"""Shared selected-root storage interface (layer L1; standard library, pc_paths and pc_records only).

Backends (the Windows root and the POSIX root) implement the abstract primitives
of RootBase on handles they hold for the whole operation; the streaming,
small-read, create and snapshot logic is written once here on top of them.
Backends never import scoped_fs. This is a cooperative boundary for a quiet
workspace, not an OS sandbox.

Records have the keys in RECORD_KEYS on every backend:
  - mode is a POSIX st_mode. Windows backends synthesise it as os.stat does:
    0o100666 for a file, 0o100444 for a file with the read-only attribute,
    0o040777 for a directory;
  - attributes are the Windows file attributes without the archive bit, which Windows sets
    on a rename, and without NORMAL, which only means that no other bit is set (0 on POSIX);
  - device and inode are non-negative integers (on Windows the volume serial
    number and the 64-bit file index), inode never 0 for a file;
  - sha256 is the content hash or None.
"""
from __future__ import annotations

import abc
from contextlib import AbstractContextManager
import hashlib
import re
import stat
from typing import Protocol
import uuid

import pc_paths
import pc_records

CHUNK_BYTES = 1 << 20
MAX_STREAM_BYTES = 1 << 40
# In-memory reads and writes are for control records only; file content streams.
MAX_CONTROL_BYTES = 1 << 25
MAX_ENTRIES = pc_records.MAX_BACKUP_ENTRIES
RECORD_KEYS = frozenset({"relative_path", "kind", "device", "inode", "mode", "size",
                         "mtime_ns", "ctime_ns", "nlink", "sha256", "attributes"})
IDENTITY_KEYS = RECORD_KEYS - {"sha256"}
# Why an entry is listed as "not included" instead of admitted.
EXCLUDED_REASONS = ("link", "special", "hard-link", "not-portable", "path-too-long", "case-collision")
# At most this many "not included" rows are kept; one final row with reason MORE_EXCLUDED counts the
# rest, so a tree full of links cannot fill memory.
MAX_EXCLUDED_ROWS = 1_000
MORE_EXCLUDED = "more"
# The only temporary names backends create and reconciliation may remove; a user's own
# ".partial-notes.docx" never matches.
PARTIAL_NAME = re.compile(r"\.partial-[0-9a-f]{32}\Z")
# The one plain-language note of a backup destination that cannot keep files private (RootBase.privacy_note).
NON_PRIVATE_NOTE = ("This drive cannot keep the backup private: anyone who can use the drive, here or on another "
                    "computer, can open the backup.")
# Destination volumes (plan RR2-4): FAT32 holds no file of 4 GiB or more, and FAT, exFAT and vfat give a file
# another id when it is renamed or listed again, so files there are bound by size and SHA-256.
FAT32_MAX_FILE_BYTES = (1 << 32) - 1
UNSTABLE_ID_KEYS = frozenset({"relative_path", "kind", "size"})
_INTEGER_KEYS = ("device", "inode", "mode", "size", "mtime_ns", "ctime_ns", "nlink", "attributes")
_HEX = frozenset("0123456789abcdef")
_WINDOWS_READ_ONLY = 0x1


class ScopedFSError(pc_records.Refusal):
    """Categorical refusal; no automatic retry or weaker fallback is implied."""

    def __init__(self, code, message=None):
        super().__init__(code, code if message is None else f"{code}: {message}")


class CapabilityHold(ScopedFSError):
    """The current platform cannot provide a required safe native primitive."""


def refuse(code, message):
    raise ScopedFSError(code, message)


def cap(value, maximum, label):
    """Return a positive integer no larger than ``maximum``."""
    if type(value) is not int or not 0 < value <= maximum:
        refuse("invalid-cap", f"{label} must be a positive integer within its documented cap")
    return value


def relative_path(value, *, allow_root=False):
    """The pc_paths grammar with scoped error codes; '' names the root when ``allow_root``."""
    if allow_root and value == "":
        return value
    try:
        return pc_paths.relative(value)
    except pc_paths.PathRefusal as exc:
        raise ScopedFSError(exc.code, str(exc)) from exc


def new_partial_name():
    """A fresh temporary file name that matches PARTIAL_NAME."""
    return ".partial-" + uuid.uuid4().hex


def partial_name(value=None):
    """The temporary name for open_new: ``value`` if it is a name made by new_partial_name() (the caller recorded it
    first, so reconciliation can remove it after a crash), a fresh name if it is None; anything else is refused."""
    if value is None:
        return new_partial_name()
    if not isinstance(value, str) or not PARTIAL_NAME.fullmatch(value):
        refuse("invalid-option", "partial must be a name made by new_partial_name()")
    return value


def destination_facts(volume, *, non_private_destination, stable_ids):
    """The admission facts a backup destination root sets, from the kind of volume its backend found.

    ``volume`` is "private" (a fixed drive whose file system keeps permissions), "non-private" (a removable
    drive, or a file system without permissions such as exFAT or vfat), "fat32" (non-private, files below
    4 GiB) or anything else (refused with destination-volume-unsupported). A non-private volume needs the
    owner's typed acknowledgment ``non_private_destination=True``; without it the CapabilityHold
    non-private-destination-acknowledgment-required carries NON_PRIVATE_NOTE. ``stable_ids`` is True only
    if the file system keeps file ids across mounts (NTFS: yes; exFAT, vfat: no); "fat32" never does, so
    its identity keys are always UNSTABLE_ID_KEYS.
    """
    if type(non_private_destination) is not bool:
        refuse("invalid-option", "non_private_destination must be boolean")
    keys = IDENTITY_KEYS if stable_ids and volume != "fat32" else UNSTABLE_ID_KEYS
    if volume == "private":
        return {"destination": True, "private": True, "privacy_note": None, "max_file_bytes": MAX_STREAM_BYTES,
                "identity_keys": keys}
    if volume not in ("non-private", "fat32"):
        refuse("destination-volume-unsupported", "Backups go to a local drive that PatchCairn can write safely")
    if not non_private_destination:
        raise CapabilityHold("non-private-destination-acknowledgment-required", NON_PRIVATE_NOTE)
    return {"destination": True, "private": False, "privacy_note": NON_PRIVATE_NOTE,
            "max_file_bytes": FAT32_MAX_FILE_BYTES if volume == "fat32" else MAX_STREAM_BYTES, "identity_keys": keys}


def name_reason(parent, name):
    """'not-portable' or 'path-too-long' when the entry ``name`` in the admitted folder ``parent`` cannot be
    admitted by name, otherwise None."""
    if not isinstance(name, str) or "/" in name or not pc_paths.portable(name):
        return "not-portable"
    return None if pc_paths.portable(f"{parent}/{name}" if parent else name) else "path-too-long"


def not_included(parent, name, reason):
    """The row for an entry left out: the admitted parent, the entry name escaped for display, the reason."""
    if reason not in EXCLUDED_REASONS:
        refuse("invalid-option", "Unknown reason for leaving an entry out")
    return {"parent": parent, "name": pc_paths.display(name), "reason": reason}


def exclude(excluded, parent, name, reason):
    """Record an entry left out in ``excluded`` (nothing when it is None); backends report through this.

    The first MAX_EXCLUDED_ROWS entries get a not_included() row; after that one final row
    {"parent": "", "name": "", "reason": MORE_EXCLUDED, "count": n} counts the rest.
    """
    row = not_included(parent, name, reason)
    if excluded is None:
        return
    if not isinstance(excluded, list):
        refuse("invalid-option", "excluded must be a list or None")
    if excluded and excluded[-1]["reason"] == MORE_EXCLUDED:
        excluded[-1]["count"] += 1
    elif len(excluded) < MAX_EXCLUDED_ROWS:
        excluded.append(row)
    else:
        excluded.append({"parent": "", "name": "", "reason": MORE_EXCLUDED, "count": 1})


def _sha256_text(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def expected_record(value, relative, *, hashed=True):
    """Validate an ordinary-file record for ``relative``; ``hashed`` requires its SHA-256."""
    relative_path(relative)
    if (not isinstance(value, dict) or set(value) != RECORD_KEYS or value["kind"] != "file"
            or value["relative_path"] != relative
            or not (_sha256_text(value["sha256"]) or (not hashed and value["sha256"] is None))):
        refuse("expected-record", "An exact ordinary-file record for this relative path is required")
    # Times before 1970 are negative and stay admissible; every other integer is non-negative.
    if (any(type(value[key]) is not int or (value[key] < 0 and key not in ("mtime_ns", "ctime_ns")) for key in _INTEGER_KEYS)
            or not stat.S_ISREG(value["mode"]) or value["inode"] == 0 or value["nlink"] != 1
            or value["size"] > MAX_STREAM_BYTES):
        refuse("expected-record", "Expected native file identity is malformed or unbounded")
    return value


def read_only(record):
    """True for a read-only file: the Windows read-only attribute, or no owner write permission in st_mode."""
    return bool(record["attributes"] & _WINDOWS_READ_ONLY or not record["mode"] & stat.S_IWUSR)


def same_identity(left, right, keys=IDENTITY_KEYS):
    """True when two records describe the same unchanged entry, compared on ``keys`` (never the hash)."""
    return all(left.get(key) == right.get(key) for key in keys)


def new_file_mode(private, original_mode):
    """Permission bits for open_new: None for a private file, otherwise ``original_mode`` (a regular-file
    st_mode or permission bits) masked to at most 0o644, so a restored file is never wider than its
    original and never executable."""
    if type(private) is not bool:
        refuse("invalid-option", "private must be boolean")
    if private:
        if original_mode is not None:
            refuse("invalid-option", "original_mode is only for a file that is not private")
        return None
    if (type(original_mode) is not int or not 0 <= original_mode < 0o200000
            or (stat.S_IFMT(original_mode) and not stat.S_ISREG(original_mode))):
        refuse("invalid-option", "A file that is not private needs the original file's recorded mode")
    return stat.S_IMODE(original_mode) & 0o644


def hash_stream(handle, size, writer=None):
    """Read exactly ``size`` bytes in CHUNK_BYTES pieces, hash each, pass it to ``writer``; return the SHA-256.

    Backends use it for every content read, including the hash taken on a delete handle, and call it
    as scoped_base.hash_stream so the contract test can observe the delete-handle hash.
    """
    if type(size) is not int or not 0 <= size <= MAX_STREAM_BYTES:
        refuse("invalid-cap", "The expected size must be a bounded non-negative integer")
    digest = hashlib.sha256()
    count = 0
    while True:
        # Ask for one byte more than expected so a file that grew is noticed.
        data = handle.read(min(CHUNK_BYTES, size - count + 1))
        if not data:
            break
        count += len(data)
        if count > size:
            refuse("read-growth", "File grew while being read")
        digest.update(data)
        if writer is not None:
            accepted = writer(data)
            if accepted is not None and accepted != len(data):
                refuse("short-write", "Consumer did not accept the complete chunk")
    if count != size:
        refuse("read-drift", "File size changed while being read")
    return digest.hexdigest()


class ReadFile(Protocol):
    """Seekable binary reader from RootBase.open_read, pinned to one file for its lifetime.

    Unbuffered: wrap it in io.BufferedReader for many small reads.
    """

    def read(self, size: int = -1) -> bytes: ...
    def seek(self, offset: int, whence: int = 0) -> int: ...
    def tell(self) -> int: ...
    def record(self) -> dict:
        """Identity of the open handle now (sha256 None), from the handle itself, never by name."""


class NewFile(Protocol):
    """Seekable binary file from RootBase.open_new, written under a PARTIAL_NAME temporary name.

    commit() syncs the file and its parent, re-checks privacy, renames without
    replacing anything, checks identity, then syncs the file and its parent again
    so the new name is on disk too. It returns the file record plus ``durable``:
    True only if both syncs, before and after the rename, succeeded. Leaving the
    ``with`` block without commit removes the temporary file. Unbuffered: wrap it in
    io.BufferedRandom for many small writes and flush that before commit().
    """

    def write(self, data: bytes) -> int: ...
    def read(self, size: int = -1) -> bytes: ...
    def seek(self, offset: int, whence: int = 0) -> int: ...
    def tell(self) -> int: ...
    def flush(self) -> None: ...
    def commit(self) -> dict: ...


class RootBase(abc.ABC):
    """One explicitly selected directory, pinned by the backend for the object's lifetime.

    Every backend refuses links and reparse points on every component and never
    follows them, and refuses an opened component whose stored name differs from
    the requested one other than by case (for example an 8.3 alias). Explicitly
    naming a link, special file, hard-linked file or unportable name is refused;
    listings report such entries as "not included". One caller thread uses a
    root at a time. Where full paths are bounded, the longest path a root can
    create is shorter than the longest it lists (open_new); callers check each
    new file with admit_new() before writing anything.
    """

    max_entries = MAX_ENTRIES
    # A root on a file system without stable file ids (FAT, exFAT) narrows this, for example to
    # {"relative_path", "kind", "size"}; the SHA-256 is still compared.
    identity_keys = IDENTITY_KEYS
    # Admission facts (plan RR2-4). A source keeps these defaults; a backup destination sets the values
    # destination_facts() returns.
    destination = False
    private = True
    privacy_note = None
    # The volume's cap on one file or MAX_STREAM_BYTES, whichever is smaller (FAT32: 4 GiB - 1).
    max_file_bytes = MAX_STREAM_BYTES

    @abc.abstractmethod
    def close(self) -> None:
        """Release every handle the root holds."""

    @abc.abstractmethod
    def inspect(self, relative: str, *, hash_file: bool = False) -> dict:
        """Record of one entry ('' is the root); with hash_file, a file record includes its SHA-256."""

    @abc.abstractmethod
    def list_directory(self, relative: str = "", *, excluded: list | None = None) -> list[dict]:
        """Records of a directory's admitted entries (ordinary files and directories), sorted by name.

        Links, special files, hard-linked files, names that are not portable,
        paths that are too long and every name of a case collision are left out
        and reported with exclude(excluded, ...), which bounds the rows kept.
        A directory with more than max_entries entries is refused with entry-cap
        while it is enumerated, before its rows are built.
        """

    @abc.abstractmethod
    def open_read(self, relative: str, *, expected: dict, uncached: bool = False) -> AbstractContextManager[ReadFile]:
        """Open a file whose identity equals ``expected``; identity is checked on entry and on a normal exit.

        ``uncached`` asks for reads that bypass the system cache where the platform allows it without
        alignment hazards (the read-back before removal); elsewhere the backend documents the limit.
        """

    @abc.abstractmethod
    def open_new(self, relative: str, *, private: bool = True, original_mode: int | None = None,
                 partial: str | None = None) -> AbstractContextManager[NewFile]:
        """Create a temporary file that commit() names ``relative`` without replacing anything.

        Its name is partial_name(partial): a name the caller made with new_partial_name() and recorded
        first, or a fresh one. A temporary name already in use is refused with destination-exists, the code
        a taken final name gets, and is never reused.

        The temporary file sits in the same folder, so where full paths are bounded the longest path that
        can be created is shorter than the longest that can be read: on Windows the folder's full path
        plus a backslash and the 41-unit temporary name must fit in 240 UTF-16 units. admit_new() checks
        this, with the name and the size, before anything is written.

        When root.private is True, the file is private before its first byte (a destination admitted as
        not private has no private files). ``private=False`` is only for restoring into an existing
        folder that an exact reviewed restore plan lists, and needs ``original_mode``, the original
        file's recorded mode (see new_file_mode): Windows validates it and creates the file with the
        folder's inherited permissions; POSIX creates it with that mode masked to at most 0o644, under
        the umask, so it is never wider than the original and never executable.
        """

    @abc.abstractmethod
    def mkdir(self, relative: str) -> dict:
        """Create one private directory; an existing or case-equivalent entry is refused."""

    @abc.abstractmethod
    def move_to(self, relative: str, *, destination: "RootBase", destination_relative: str, expected: dict) -> dict:
        """Rename a verified file onto the same volume without replacing anything; return its new record."""

    @abc.abstractmethod
    def remove_file(self, relative: str, *, expected: dict, sha256: str | None = None,
                    allow_read_only: bool = False) -> dict:
        """Delete a file only if hashing it on the delete handle gives ``sha256`` (default expected['sha256']).

        The hash is taken with hash_stream on the handle that then deletes. A
        read-only file (see read_only()) is refused unless ``allow_read_only``
        is True, which the caller passes only for entries the approved removal
        plan shows as read-only.
        """

    @abc.abstractmethod
    def free_bytes(self) -> int:
        """Bytes available to this process on the root's volume."""

    def admit_new(self, relative: str, expected_bytes: int) -> None:
        """Refuse, before anything is written, what open_new(relative) would refuse for the name or the path
        length, and an ``expected_bytes`` above max_file_bytes. A backend that bounds full paths also checks the
        temporary file's path (see open_new). A missing folder or a name in use is found only by open_new."""
        relative_path(relative)
        if type(expected_bytes) is not int or expected_bytes < 0:
            refuse("invalid-cap", "The expected size must be a non-negative integer")
        if expected_bytes > self.max_file_bytes:
            refuse("file-too-large-for-volume", "The file would exceed the largest file this drive can hold")

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def stream_to(self, relative: str, *, expected: dict, writer) -> dict:
        """Pass a reviewed file to ``writer`` in CHUNK_BYTES pieces and return its verified record.

        The handle's identity is re-checked after the last chunk and the SHA-256
        compared with ``expected``. Until this returns, everything ``writer``
        received is unverified; on a refusal the caller discards it.
        """
        expected = expected_record(expected, relative)
        if not callable(writer):
            refuse("writer", "A byte-consumer callable is required")
        with self.open_read(relative, expected=expected) as handle:
            sha256 = hash_stream(handle, expected["size"], writer)
            if not same_identity(handle.record(), expected, self.identity_keys):
                refuse("read-drift", "File changed during the read")
        if sha256 != expected["sha256"]:
            refuse("stale-content", "Content hash no longer matches the reviewed file")
        return dict(expected)

    def read_bytes(self, relative: str, *, expected: dict, max_bytes: int) -> bytes:
        """Whole content of a small control record."""
        cap(max_bytes, MAX_CONTROL_BYTES, "max_bytes for an in-memory read")
        expected = expected_record(expected, relative)
        if expected["size"] > max_bytes:
            refuse("file-byte-cap", "File exceeds its explicit byte cap")
        chunks = []
        self.stream_to(relative, expected=expected, writer=chunks.append)
        return b"".join(chunks)

    def create_file(self, relative: str, *, data: bytes) -> dict:
        """Create a small private file exclusively and return its committed record."""
        if type(data) is not bytes or len(data) > MAX_CONTROL_BYTES:
            refuse("file-byte-cap", "Bounded bytes are required for exclusive file creation")
        with self.open_new(relative) as handle:
            view = memoryview(data)
            offset = 0
            while offset < len(data):
                written = handle.write(view[offset:offset + CHUNK_BYTES])
                if not written:
                    refuse("short-write", "Exclusive file creation stopped before completion")
                offset += written
            record = handle.commit()
        if record.get("size") != len(data) or record.get("sha256") != hashlib.sha256(data).hexdigest():
            refuse("write-verification", "The committed file does not hold the written bytes")
        return record

    def _admitted(self, row, parent):
        name = row.get("relative_path") if isinstance(row, dict) else None
        if (not isinstance(name, str) or set(row) != RECORD_KEYS or row["kind"] not in ("file", "directory")
                or name.rpartition("/")[0] != parent):
            refuse("listing-contract", "A listing returned an entry that is not an admitted file or directory")
        relative_path(name)
        return row

    def snapshot(self, *, hash_files: bool = False, excluded: list | None = None) -> list[dict]:
        """Records of the whole tree, sorted by path, refused if anything changed while it was taken.

        The root and up to max_entries admitted entries (files and directories) are returned; entries
        left out are reported in ``excluded`` as by list_directory, at most MAX_EXCLUDED_ROWS rows plus
        one counting row for the whole tree.
        """
        if type(hash_files) is not bool:
            refuse("invalid-option", "hash_files must be boolean")
        if excluded is not None and not isinstance(excluded, list):
            refuse("invalid-option", "excluded must be a list or None")
        records = [self.inspect("")]
        listed = []
        pending = [""]
        while pending:
            relative = pending.pop()
            children = [self._admitted(row, relative) for row in self.list_directory(relative, excluded=excluded)]
            listed.append((relative, [row["relative_path"] for row in children]))
            for row in children:
                if len(records) > self.max_entries:
                    refuse("entry-cap", "Snapshot exceeds its total entry cap")
                if row["kind"] == "directory":
                    pending.append(row["relative_path"])
                elif hash_files:
                    row = self.inspect(row["relative_path"], hash_file=True)
                records.append(row)
        by_path = {row["relative_path"]: row for row in records}
        if not same_identity(self.inspect(""), by_path[""], self.identity_keys):
            refuse("snapshot-drift", "Root changed during snapshot")
        for relative, names in listed:
            current = self.list_directory(relative, excluded=[])
            if (names != [row["relative_path"] for row in current]
                    or not all(same_identity(row, by_path[row["relative_path"]], self.identity_keys) for row in current)):
                refuse("snapshot-drift", "Entries changed during snapshot")
        return sorted(records, key=lambda row: row["relative_path"])
