"""Contract for every scoped_base.RootBase backend, plus the shared methods written once in scoped_base.

Run from the repository root: python3 -I -S -B -m unittest discover -s tests -p "test_scoped_contract.py"
RootContract holds the behaviour every backend must show. FakeRoot, an in-memory
backend defined here, runs it; WindowsRootContractTests runs it against the Windows
backend on real folders under work/test-fixtures/, and the POSIX backend adds its own
subclass that supplies new_root() and the hooks.
"""
from __future__ import annotations

import ast
from collections import Counter
import contextlib
import ctypes
import hashlib
import io
import itertools
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
import unittest
from unittest import mock
import uuid
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_paths  # noqa: E402
import pc_records  # noqa: E402
import scoped_base  # noqa: E402
from scoped_base import CHUNK_BYTES, RECORD_KEYS, ScopedFSError  # noqa: E402

PATH_CODES = {"invalid-relative-path", "path-too-long", "invalid-path-component", "reserved-path-component"}


def pattern(size):
    return (bytes(range(256)) * (size // 256 + 1))[:size]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def without_durable(record):
    return {key: value for key, value in record.items() if key != "durable"}


def accepted(test, call, *args, **kwargs):
    """The result of a call that must succeed; a refusal makes the test fail rather than error."""
    try:
        return call(*args, **kwargs)
    except ScopedFSError as error:
        test.fail(f"unexpected refusal: {error}")


class _Node:
    MODES = {"file": 0o100600, "directory": 0o40700, "link": 0o120777, "special": 0o10600}

    def __init__(self, kind, inode, data=b"", nlink=1):
        self.kind, self.inode, self.data, self.nlink = kind, inode, bytearray(data), nlink
        self.mode = self.MODES[kind]
        self.mtime_ns = self.ctime_ns = 1_700_000_000_000_000_000 + inode
        self.attributes, self.private = 0, True


class _Reader(io.RawIOBase):
    """An open handle: it keeps its node even when the name later points elsewhere."""

    def __init__(self, root, relative, node):
        super().__init__()
        self._root, self._relative, self._node, self._position = root, relative, node, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def readinto(self, buffer):
        chunk = self._node.data[self._position:self._position + len(buffer)]
        buffer[:len(chunk)] = chunk
        self._position += len(chunk)
        return len(chunk)

    def seek(self, offset, whence=io.SEEK_SET):
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._position, io.SEEK_END: len(self._node.data)}[whence]
        self._position = max(0, base + offset)
        return self._position

    def tell(self):
        return self._position

    def record(self):
        return self._root.record_of(self._relative, self._node)


class _NewFile(io.BytesIO):
    def __init__(self, root, relative, temp):
        super().__init__()
        self._root, self._relative, self._temp, self.committed = root, relative, temp, False

    def write(self, data):
        if self.committed:
            scoped_base.refuse("commit-state", "The file is already committed")
        return super().write(data)

    def commit(self):
        root = self._root
        if self.committed:
            scoped_base.refuse("commit-state", "The file is already committed")
        root.require_absent(self._relative)
        self.flush()
        node = root.nodes.pop(self._temp)
        node.data = bytearray(self.getvalue())
        node.mtime_ns += 1
        root.nodes[self._relative] = node
        self.committed = True
        return {**root.record_of(self._relative, node, sha256(node.data)), "durable": root.durable}


class FakeRoot(scoped_base.RootBase):
    """In-memory backend: names map to nodes; handles keep their node like a descriptor."""

    def __init__(self, device=7, volume=None, non_private_destination=False):
        self.device, self.durable, self.closed = device, True, False
        self._inodes = itertools.count(2)
        if volume is not None:  # admitted as a backup destination on a volume of this kind
            kind = {"private": "private", "removable-exfat": "non-private", "fat32": "fat32"}.get(volume, volume)
            vars(self).update(scoped_base.destination_facts(kind, non_private_destination=non_private_destination,
                                                            stable_ids=volume == "private"))
        self.nodes = {"": _Node("directory", 1)}
        self.aliases = {}

    def close(self):
        self.closed = True

    def new_node(self, kind, data=b"", nlink=1):
        return _Node(kind, next(self._inodes), data, nlink)

    def record_of(self, relative, node, sha=None):
        return {"relative_path": relative, "kind": node.kind, "device": self.device, "inode": node.inode,
                "mode": node.mode, "size": len(node.data), "mtime_ns": node.mtime_ns, "ctime_ns": node.ctime_ns,
                "nlink": node.nlink, "sha256": sha, "attributes": node.attributes}

    def node(self, relative, kind=None):
        if self.closed:
            scoped_base.refuse("closed-root", "The root is closed")
        scoped_base.relative_path(relative, allow_root=True)
        if relative in self.aliases:
            scoped_base.refuse("alias", "The stored name differs from the requested one")
        found = self.nodes.get(relative)
        if found is not None and found.kind in ("link", "special"):
            scoped_base.refuse(found.kind, "Links and special files are never followed or opened")
        if found is not None and found.nlink > 1:
            scoped_base.refuse("hard-link", "Hard-linked files are not admitted")
        if found is None or (kind is not None and found.kind != kind):
            scoped_base.refuse("missing-entry", "Exact entry is missing")
        return found

    def require_absent(self, relative):
        scoped_base.relative_path(relative)
        parent = relative.rpartition("/")[0]
        self.node(parent, "directory").mtime_ns += 1
        key = pc_paths.casefold_key(relative)
        if any(pc_paths.casefold_key(name) == key for name in self.nodes):
            scoped_base.refuse("destination-exists", "Destination or case-equivalent entry already exists")

    def inspect(self, relative, *, hash_file=False):
        if type(hash_file) is not bool:
            scoped_base.refuse("invalid-option", "hash_file must be boolean")
        record = self.record_of(relative, self.node(relative))
        if hash_file and record["kind"] == "file":
            with self.open_read(relative, expected=record) as handle:
                return {**record, "sha256": scoped_base.hash_stream(handle, record["size"])}
        return record

    def list_directory(self, relative="", *, excluded=None):
        self.node(relative, "directory")
        prefix = relative + "/" if relative else ""
        names = sorted(name[len(prefix):] for name in self.nodes
                       if name.startswith(prefix) and name != relative and "/" not in name[len(prefix):])
        if len(names) > self.max_entries:
            scoped_base.refuse("entry-cap", "Directory membership exceeds its entry cap")
        keys = Counter(pc_paths.casefold_key(name) for name in names)
        rows = []
        for name in names:
            node = self.nodes[prefix + name]
            reason = (node.kind if node.kind in ("link", "special") else "hard-link" if node.nlink > 1
                      else scoped_base.name_reason(relative, name)
                      or ("case-collision" if keys[pc_paths.casefold_key(name)] > 1 else None))
            if reason is None:
                rows.append(self.record_of(prefix + name, node))
            else:
                scoped_base.exclude(excluded, relative, name, reason)
        return rows

    @contextlib.contextmanager
    def open_read(self, relative, *, expected, uncached=False):
        if type(uncached) is not bool:
            scoped_base.refuse("invalid-option", "uncached must be boolean")
        scoped_base.expected_record(expected, relative, hashed=False)
        node = self.node(relative, "file")
        if not scoped_base.same_identity(self.record_of(relative, node), expected, self.identity_keys):
            scoped_base.refuse("stale-identity", "File no longer matches the reviewed identity")
        handle = _Reader(self, relative, node)
        try:
            yield handle
            if (self.nodes.get(relative) is not node
                    or not scoped_base.same_identity(handle.record(), expected, self.identity_keys)):
                scoped_base.refuse("read-drift", "File changed while it was open")
        finally:
            handle.close()

    @contextlib.contextmanager
    def open_new(self, relative, *, private=True, original_mode=None, partial=None):
        bits = scoped_base.new_file_mode(private, original_mode)
        partial = scoped_base.partial_name(partial)
        self.require_absent(relative)
        parent = relative.rpartition("/")[0]
        temp = (parent + "/" if parent else "") + partial
        self.require_absent(temp)
        self.nodes[temp] = self.new_node("file")
        if bits is not None:
            self.nodes[temp].mode, self.nodes[temp].private = stat.S_IFREG | bits, False
        handle = _NewFile(self, relative, temp)
        try:
            yield handle
        finally:
            if not handle.committed:
                self.nodes.pop(temp, None)
            handle.close()

    def mkdir(self, relative):
        self.require_absent(relative)
        self.nodes[relative] = self.new_node("directory")
        return self.record_of(relative, self.nodes[relative])

    def move_to(self, relative, *, destination, destination_relative, expected):
        scoped_base.expected_record(expected, relative)
        if not isinstance(destination, FakeRoot) or destination.device != self.device:
            scoped_base.refuse("cross-filesystem", "Cross-filesystem copy/delete fallback is forbidden")
        node = self.node(relative, "file")
        destination.require_absent(destination_relative)
        with self.open_read(relative, expected=expected) as handle:
            if scoped_base.hash_stream(handle, expected["size"]) != expected["sha256"]:
                scoped_base.refuse("stale-content", "Content hash no longer matches the reviewed file")
        destination.nodes[destination_relative] = self.nodes.pop(relative)
        node.ctime_ns += 1
        return destination.record_of(destination_relative, node, expected["sha256"])

    def remove_file(self, relative, *, expected, sha256=None, allow_read_only=False):
        if type(allow_read_only) is not bool:
            scoped_base.refuse("invalid-option", "allow_read_only must be boolean")
        scoped_base.expected_record(expected, relative)
        target = expected["sha256"] if sha256 is None else sha256
        if not (isinstance(target, str) and len(target) == 64):
            scoped_base.refuse("expected-record", "A SHA-256 is required")
        node = self.node(relative, "file")
        if not scoped_base.same_identity(self.record_of(relative, node), expected, self.identity_keys):
            scoped_base.refuse("stale-identity", "File no longer matches the reviewed identity")
        if scoped_base.read_only(expected) and not allow_read_only:
            scoped_base.refuse("read-only", "The approved plan does not show this file as read-only")
        handle = _Reader(self, relative, node)
        observed = scoped_base.hash_stream(handle, expected["size"])
        if observed != target or not scoped_base.same_identity(handle.record(), expected, self.identity_keys):
            scoped_base.refuse("stale-content", "File content does not match the archived entry")
        if self.nodes.get(relative) is not node:
            scoped_base.refuse("remove-verification", "The name no longer refers to the hashed file")
        del self.nodes[relative]
        self.node(relative.rpartition("/")[0]).mtime_ns += 1
        return {**expected, "sha256": observed}

    def free_bytes(self):
        return 1 << 40


# Hook capabilities a backend may lack. A hook that cannot perform one returns False or None; the
# test then fails unless the backend lists that capability in absent_capabilities, and it also fails
# when a capability listed as absent is performed, so no case is skipped silently.
CAPABILITIES = frozenset({"swap", "fail-sync", "posix-mode", "case-pair", "alias", "link", "special", "hard-link",
                          "name-colon", "name-reserved", "name-trailing-dot", "long-path"})


class RootContract:
    """Behaviour every RootBase backend must show. Subclasses supply new_root() and the hooks below.

    A subclass names the hook capabilities its platform cannot provide in absent_capabilities.
    """

    absent_capabilities = frozenset()

    def new_root(self):
        raise NotImplementedError

    def grow(self, root, relative, extra):
        raise NotImplementedError

    def shrink(self, root, relative, size):
        raise NotImplementedError

    def touch(self, root, relative):
        """Change the file's identity (for example its modification time) without changing its bytes."""
        raise NotImplementedError

    def rewrite_in_place(self, root, relative, data):
        """Replace the bytes with others of the same length, keeping the identity where the platform allows."""
        raise NotImplementedError

    def swap(self, root, relative, data):
        """Put a different file holding ``data`` under ``relative``; True if the platform allowed it."""
        raise NotImplementedError

    def temp_names(self, root):
        raise NotImplementedError

    def make_read_only(self, root, relative):
        raise NotImplementedError

    def permissions(self, root, relative):
        """'private' (owner only) or 'inherited' (the folder's inherited or default permissions)."""
        raise NotImplementedError

    def restored_mode(self, root, relative):
        """POSIX permission bits of the file, or None where the platform has none."""
        raise NotImplementedError

    def fail_sync(self, root):
        """Make the next commit's sync fail; True if the platform allows forcing it."""
        raise NotImplementedError

    def add_raw_name(self, root, parent, name, kind="file", nlink=1):
        """Create an entry the grammar refuses (or a link, special file or hard link); True if created."""
        raise NotImplementedError

    def add_case_pair(self, root, parent, first, second):
        """Create the file ``first``, then try ``second``, which differs only in case. True if both now exist
        as separate entries; False if the file system is case-insensitive and holds only ``first``."""
        raise NotImplementedError

    def alias(self, root, relative):
        """Another spelling the file system resolves to ``relative`` (an 8.3 alias), or None."""
        raise NotImplementedError

    def new_destination_root(self, volume, *, non_private_destination):
        """A root admitted as a backup destination on a faked volume: "private" (fixed, keeps permissions),
        "removable-exfat", "fat32" or "unsupported" (for example a network drive)."""
        raise NotImplementedError

    def setUp(self):
        self.root = self.new_root()
        self.addCleanup(self.root.close)

    def capability(self, name, performed):
        """True if a hook performed ``name``; False only when the backend declares it absent."""
        self.assertIn(name, CAPABILITIES)
        declared = name in self.absent_capabilities
        if performed and declared:
            self.fail(f"hook capability {name!r} is declared absent but was performed")
        if not performed and not declared:
            self.fail(f"hook capability {name!r} was not performed; list it in absent_capabilities if the platform lacks it")
        return bool(performed)

    def test_absent_capabilities_are_known(self):
        self.assertIsInstance(self.absent_capabilities, frozenset)
        self.assertLessEqual(self.absent_capabilities, CAPABILITIES)

    def seed(self, relative, data):
        return without_durable(self.root.create_file(relative, data=data))

    def names(self, relative=""):
        return [row["relative_path"] for row in self.root.list_directory(relative)]

    def assertRefused(self, codes, call, *args, **kwargs):
        with self.assertRaises(ScopedFSError) as caught:
            call(*args, **kwargs)
        self.assertIn(caught.exception.code, {codes} if isinstance(codes, str) else codes)
        return caught.exception

    def test_stream_to_into_zipfile_with_zip64(self):
        big, small = pattern(2 * CHUNK_BYTES + 12345), b"line one\r\nline two\n"
        records = [self.seed("big.bin", big), self.seed("small.txt", small)]
        with self.root.open_new("archive.zip") as out:
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
                for record in records:
                    info = zipfile.ZipInfo(record["relative_path"], date_time=(2026, 1, 1, 0, 0, 0))
                    info.compress_type, info.file_size = zipfile.ZIP_DEFLATED, record["size"]
                    with archive.open(info, "w", force_zip64=True) as member:
                        self.assertEqual(self.root.stream_to(record["relative_path"], expected=record,
                                                             writer=member.write), record)
            committed = out.commit()
        with self.root.open_read("archive.zip", expected=without_durable(committed)) as handle:
            with zipfile.ZipFile(handle) as archive:
                self.assertIsNone(archive.testzip())
                infos = archive.infolist()
                self.assertEqual([info.filename for info in infos], ["big.bin", "small.txt"])
                for info, data in zip(infos, (big, small)):
                    self.assertGreaterEqual(info.extract_version, 45)
                    digest = hashlib.sha256()
                    with archive.open(info) as member:
                        while chunk := member.read(CHUNK_BYTES):
                            digest.update(chunk)
                    self.assertEqual(digest.hexdigest(), sha256(data))
                    handle.seek(info.header_offset)
                    header = handle.read(30)
                    name_length, extra_length = struct.unpack("<HH", header[26:30])
                    handle.seek(info.header_offset + 30 + name_length)
                    extra, ids = handle.read(extra_length), []
                    while len(extra) >= 4:
                        header_id, size = struct.unpack("<HH", extra[:4])
                        ids.append(header_id)
                        extra = extra[4 + size:]
                    self.assertIn(0x0001, ids)

    def test_stream_to_passes_every_byte_in_bounded_chunks(self):
        data = pattern(3 * CHUNK_BYTES + 7)
        record = self.seed("data.bin", data)
        chunks = []
        self.assertEqual(self.root.stream_to("data.bin", expected=record, writer=chunks.append), record)
        self.assertEqual(b"".join(chunks), data)
        self.assertTrue(all(0 < len(chunk) <= CHUNK_BYTES for chunk in chunks))
        empty = self.seed("empty.bin", b"")
        self.assertEqual(self.root.stream_to("empty.bin", expected=empty, writer=chunks.append), empty)

    def test_stream_to_refuses_growth(self):
        record = self.seed("grow.bin", pattern(CHUNK_BYTES + 100))

        def writer(chunk):
            if len(chunk) == CHUNK_BYTES:
                self.grow(self.root, "grow.bin", b"appended")

        self.assertRefused("read-growth", self.root.stream_to, "grow.bin", expected=record, writer=writer)

    def test_stream_to_refuses_shrinking(self):
        record = self.seed("shrink.bin", pattern(CHUNK_BYTES + 100))

        def writer(chunk):
            if len(chunk) == CHUNK_BYTES:
                self.shrink(self.root, "shrink.bin", 10)

        self.assertRefused("read-drift", self.root.stream_to, "shrink.bin", expected=record, writer=writer)

    def test_stream_to_refuses_identity_change(self):
        record = self.seed("touch.bin", pattern(CHUNK_BYTES + 100))

        def writer(chunk):
            if len(chunk) == CHUNK_BYTES:
                self.touch(self.root, "touch.bin")

        self.assertRefused("read-drift", self.root.stream_to, "touch.bin", expected=record, writer=writer)
        self.assertRefused("stale-identity", self.root.stream_to, "touch.bin", expected=record, writer=lambda chunk: None)

    def test_stream_to_refuses_changed_content(self):
        data = pattern(5000)
        record = self.seed("same.bin", data)
        self.rewrite_in_place(self.root, "same.bin", data[::-1])
        self.assertRefused({"stale-content", "stale-identity"}, self.root.stream_to, "same.bin", expected=record,
                           writer=lambda chunk: None)

    def test_stream_to_refuses_short_writes_and_bad_arguments(self):
        record = self.seed("w.bin", b"payload")
        self.assertRefused("short-write", self.root.stream_to, "w.bin", expected=record, writer=lambda chunk: 1)
        self.assertRefused("writer", self.root.stream_to, "w.bin", expected=record, writer=None)
        self.assertRefused("expected-record", self.root.stream_to, "w.bin", expected={**record, "sha256": None},
                           writer=len)
        self.assertRefused("expected-record", self.root.stream_to, "w.bin", expected={**record, "relative_path": "x"},
                           writer=len)

    def test_open_read_checks_identity_on_entry_and_exit(self):
        record = self.seed("r.bin", b"0123456789")
        with self.root.open_read("r.bin", expected=record, uncached=True) as handle:
            self.assertEqual(handle.read(4), b"0123")
            handle.seek(8)
            self.assertEqual(handle.read(), b"89")
            self.assertTrue(scoped_base.same_identity(handle.record(), record))
        with self.assertRaises(ScopedFSError) as caught:
            with self.root.open_read("r.bin", expected=record):
                self.touch(self.root, "r.bin")
        self.assertEqual(caught.exception.code, "read-drift")
        self.assertRefused("stale-identity", lambda: self.root.open_read("r.bin", expected=record).__enter__())

    def test_commit_never_overwrites(self):
        existing = self.seed("keep.txt", b"original")
        for name in ("keep.txt", "KEEP.TXT"):
            with self.subTest(name=name):
                with self.assertRaises(ScopedFSError) as caught:
                    with self.root.open_new(name) as out:
                        out.write(b"replacement")
                        out.commit()
                self.assertEqual(caught.exception.code, "destination-exists")
        self.assertEqual(self.root.read_bytes("keep.txt", expected=existing, max_bytes=100), b"original")
        with self.root.open_new("late.txt") as out:
            out.write(b"mine")
            theirs = self.seed("late.txt", b"theirs")
            self.assertRefused("destination-exists", out.commit)
        self.assertEqual(self.root.read_bytes("late.txt", expected=theirs, max_bytes=100), b"theirs")
        self.assertEqual(self.temp_names(self.root), [])

    def test_abort_removes_the_temporary_file(self):
        with self.root.open_new("draft.bin") as out:
            out.write(b"x" * 10)
            temps = self.temp_names(self.root)
            self.assertEqual(len(temps), 1)
            self.assertRegex(temps[0].rpartition("/")[2], scoped_base.PARTIAL_NAME)
        self.assertEqual(self.temp_names(self.root), [])
        self.assertNotIn("draft.bin", self.names())
        with self.assertRaises(RuntimeError):
            with self.root.open_new("draft.bin") as out:
                out.write(b"partial")
                raise RuntimeError("writer failed")
        self.assertEqual(self.temp_names(self.root), [])
        self.assertNotIn("draft.bin", self.names())

    def test_open_new_uses_caller_partial_name(self):
        # The caller records the temporary name first, so reconciliation can remove it after a crash.
        name = scoped_base.new_partial_name()
        with self.root.open_new("named.bin", partial=name) as out:
            out.write(b"x")
            self.assertEqual(self.temp_names(self.root), [name])
            out.commit()
        self.assertEqual(self.temp_names(self.root), [])
        for bad in ("notes.txt", ".partial-" + "A" * 32, 1):
            with self.subTest(partial=bad):
                self.assertRefused("invalid-option", lambda: self.root.open_new("other.bin", partial=bad).__enter__())

    def test_source_root_is_not_a_destination(self):
        # new_root() admits a source; only the separate destination admission sets destination (plan RR2-4).
        self.assertIs(self.root.destination, False)

    def test_source_root_is_private(self):
        self.assertIs(self.root.private, True)
        with self.root.open_new("p.bin") as out:
            out.write(b"p")
            out.commit()
        self.assertEqual(self.permissions(self.root, "p.bin"), "private")

    def test_privacy_note_matches_privacy(self):
        self.assertEqual(self.root.privacy_note, None if self.root.private else scoped_base.NON_PRIVATE_NOTE)

    def test_max_file_bytes_is_a_bound(self):
        cap = self.root.max_file_bytes
        self.assertTrue(type(cap) is int and 0 < cap <= scoped_base.MAX_STREAM_BYTES, cap)

    def test_admit_new_refuses_only_above_max_file_bytes(self):
        cap = self.root.max_file_bytes
        self.assertIsNone(self.root.admit_new("new.bin", 0))
        self.assertIsNone(self.root.admit_new("folder/new.bin", cap))
        self.assertRefused("file-too-large-for-volume", self.root.admit_new, "new.bin", cap + 1)
        for bad in (-1, True, 1.5, "1"):
            with self.subTest(size=bad):
                self.assertRefused("invalid-cap", self.root.admit_new, "new.bin", bad)
        for relative, code in (("", "invalid-relative-path"), ("../new.bin", "invalid-path-component"),
                               ("NUL", "reserved-path-component")):
            with self.subTest(relative=relative):
                self.assertRefused(code, self.root.admit_new, relative, 0)
                self.assertRefused(code, lambda: self.root.open_new(relative).__enter__())
        self.assertEqual(self.names(), [])

    def destination(self, volume, *, acknowledged=False):
        root = self.new_destination_root(volume, non_private_destination=acknowledged)
        self.addCleanup(root.close)
        return root

    def test_destination_without_acknowledgment_is_held(self):
        for volume in ("removable-exfat", "fat32"):
            with self.subTest(volume=volume):
                with self.assertRaises(scoped_base.CapabilityHold) as caught:
                    self.destination(volume)
                self.assertEqual(caught.exception.code, "non-private-destination-acknowledgment-required")
                self.assertIn(scoped_base.NON_PRIVATE_NOTE, str(caught.exception))
        self.assertRefused("destination-volume-unsupported", self.destination, "unsupported", acknowledged=True)

    def test_private_destination_keeps_privacy(self):
        root = self.destination("private")
        self.assertEqual((root.destination, root.private, root.privacy_note), (True, True, None))
        self.assertEqual(root.identity_keys, scoped_base.IDENTITY_KEYS)

    def test_acknowledged_destination_is_not_private(self):
        root = self.destination("removable-exfat", acknowledged=True)
        self.assertEqual((root.destination, root.private, root.privacy_note), (True, False, scoped_base.NON_PRIVATE_NOTE))
        self.assertEqual(root.identity_keys, scoped_base.UNSTABLE_ID_KEYS)
        with root.open_new("backup.zip") as out:
            out.write(b"archive")
            record = out.commit()
        self.assertEqual(root.inspect("backup.zip", hash_file=True), without_durable(record))

    def test_fat32_destination_caps_file_size(self):
        root = self.destination("fat32", acknowledged=True)
        self.assertEqual(root.max_file_bytes, scoped_base.FAT32_MAX_FILE_BYTES)
        self.assertEqual(root.identity_keys, scoped_base.UNSTABLE_ID_KEYS)
        self.assertIsNone(root.admit_new("backup.zip", scoped_base.FAT32_MAX_FILE_BYTES))
        self.assertRefused("file-too-large-for-volume", root.admit_new, "backup.zip", 1 << 32)

    def test_open_new_refuses_a_partial_name_in_use(self):
        name = scoped_base.new_partial_name()
        with self.root.open_new("first.bin", partial=name) as out:
            out.write(b"first")
            self.assertRefused("destination-exists", lambda: self.root.open_new("second.bin", partial=name).__enter__())
            record = without_durable(out.commit())
        self.assertEqual(self.root.read_bytes("first.bin", expected=record, max_bytes=10), b"first")
        self.assertNotIn("second.bin", self.names())
        self.assertEqual(self.temp_names(self.root), [])

    def test_commit_reports_durability(self):
        with self.root.open_new("d.bin") as out:
            out.write(b"abc")
            out.seek(0)
            self.assertEqual(out.read(), b"abc")
            record = out.commit()
            self.assertRefused("commit-state", out.commit)
        self.assertIs(record["durable"], True)
        self.assertEqual(set(record), RECORD_KEYS | {"durable"})
        self.assertEqual((record["size"], record["sha256"]), (3, sha256(b"abc")))
        self.assertEqual(without_durable(record), self.root.inspect("d.bin", hash_file=True))
        if self.capability("fail-sync", self.fail_sync(self.root)):
            with self.root.open_new("e.bin") as out:
                out.write(b"def")
                self.assertIs(out.commit()["durable"], False)
        self.assertEqual(self.temp_names(self.root), [])

    def test_remove_hashes_on_delete_handle(self):
        data = pattern(CHUNK_BYTES + 3)
        record = self.seed("old.bin", data)
        self.assertRefused("stale-content", self.root.remove_file, "old.bin", expected=record, sha256="0" * 64)
        self.assertIn("old.bin", self.names())
        self.rewrite_in_place(self.root, "old.bin", data[::-1])
        self.assertRefused({"stale-content", "stale-identity"}, self.root.remove_file, "old.bin", expected=record)
        self.assertIn("old.bin", self.names())
        other = self.seed("archived.bin", data)
        removed = self.root.remove_file("archived.bin", expected=other, sha256=sha256(data))
        self.assertEqual(removed["sha256"], sha256(data))
        self.assertNotIn("archived.bin", self.names())
        self.assertRefused("missing-entry", self.root.remove_file, "archived.bin", expected=other)
        # A different file put under the name after the hash must survive: the delete uses the hashed handle.
        victim = self.seed("victim.bin", data)
        original, swapped = scoped_base.hash_stream, []

        def hash_then_swap(handle, size, writer=None):
            result = original(handle, size, writer)
            swapped.append(self.swap(self.root, "victim.bin", b"swapped-in"))
            return result

        with mock.patch.object(scoped_base, "hash_stream", side_effect=hash_then_swap):
            try:
                self.root.remove_file("victim.bin", expected=victim)
                refusal = None
            except ScopedFSError as error:
                refusal = error
        self.assertEqual(len(swapped), 1)
        # A backend whose delete handle blocks the swap (Windows sharing rules) declares "swap" absent.
        if self.capability("swap", swapped[0]):
            self.assertIsNotNone(refusal)
            self.assertEqual(self.root.inspect("victim.bin", hash_file=True)["sha256"], sha256(b"swapped-in"))
        else:
            self.assertIsNone(refusal)
            self.assertNotIn("victim.bin", self.names())

    def test_read_only_refused_unless_allowed(self):
        self.seed("ro.bin", b"keep")
        self.make_read_only(self.root, "ro.bin")
        record = self.root.inspect("ro.bin", hash_file=True)
        self.assertTrue(scoped_base.read_only(record))
        self.assertRefused("read-only", self.root.remove_file, "ro.bin", expected=record)
        self.assertRefused("invalid-option", self.root.remove_file, "ro.bin", expected=record, allow_read_only=1)
        self.assertIn("ro.bin", self.names())
        self.assertEqual(self.root.remove_file("ro.bin", expected=record, allow_read_only=True)["sha256"], sha256(b"keep"))
        self.assertNotIn("ro.bin", self.names())

    def test_open_new_non_private_inherits(self):
        with self.root.open_new("private.bin") as out:
            out.write(b"p")
            out.commit()
        self.root.mkdir("existing")
        for name, original in (("restored.txt", 0o100600), ("tool.sh", 0o100755), ("shared.txt", 0o664)):
            with self.root.open_new("existing/" + name, private=False, original_mode=original) as out:
                out.write(b"restored")
                record = out.commit()
            self.assertEqual(without_durable(record), self.root.inspect("existing/" + name, hash_file=True))
            self.assertEqual(self.permissions(self.root, "existing/" + name), "inherited")
            restored = self.restored_mode(self.root, "existing/" + name)
            if self.capability("posix-mode", restored is not None):
                self.assertEqual(restored & ~0o644, 0, oct(restored))
                self.assertEqual(restored & ~stat.S_IMODE(original), 0, oct(restored))
        self.assertEqual(self.permissions(self.root, "private.bin"), "private")
        for options in ({"private": "no"}, {"private": True, "original_mode": 0o100644}, {"private": False},
                        {"private": False, "original_mode": 0o040755}, {"private": False, "original_mode": True}):
            with self.subTest(options=options):
                self.assertRefused("invalid-option", lambda: self.root.open_new("x.bin", **options).__enter__())
        self.assertRefused("missing-entry", lambda: self.root.open_new("absent/x.bin", private=False,
                                                                        original_mode=0o644).__enter__())
        self.assertEqual(self.temp_names(self.root), [])

    def test_read_bytes_is_bounded(self):
        record = self.seed("small.json", b'{"a":1}')
        self.assertEqual(self.root.read_bytes("small.json", expected=record, max_bytes=7), b'{"a":1}')
        self.assertRefused("file-byte-cap", self.root.read_bytes, "small.json", expected=record, max_bytes=6)
        self.assertRefused("invalid-cap", self.root.read_bytes, "small.json", expected=record,
                           max_bytes=scoped_base.MAX_CONTROL_BYTES + 1)
        self.assertRefused("invalid-cap", self.root.read_bytes, "small.json", expected=record, max_bytes=True)

    def test_create_file_is_exclusive_and_verified(self):
        record = self.root.create_file("dir-less.txt", data=b"hello")
        self.assertEqual(without_durable(record), self.root.inspect("dir-less.txt", hash_file=True))
        self.assertRefused("destination-exists", self.root.create_file, "dir-less.txt", data=b"again")
        self.assertRefused("file-byte-cap", self.root.create_file, "text.txt", data="text")
        self.assertRefused("file-byte-cap", self.root.create_file, "big.bin",
                           data=b"\0" * (scoped_base.MAX_CONTROL_BYTES + 1))
        self.assertNotIn("text.txt", self.names())

    def test_mkdir_and_move_to_never_replace(self):
        self.root.mkdir("folder")
        self.assertRefused("destination-exists", self.root.mkdir, "FOLDER")
        record = self.seed("a.txt", b"move me")
        moved = self.root.move_to("a.txt", destination=self.root, destination_relative="folder/a.txt", expected=record)
        self.assertEqual((moved["relative_path"], moved["sha256"], moved["inode"]), ("folder/a.txt", record["sha256"],
                                                                                     record["inode"]))
        self.assertNotIn("a.txt", self.names())
        blocker = self.seed("b.txt", b"other")
        self.seed("folder/b.txt", b"taken")
        self.assertRefused("destination-exists", self.root.move_to, "b.txt", destination=self.root,
                           destination_relative="folder/b.txt", expected=blocker)
        self.assertIn("b.txt", self.names())
        changed = self.seed("c.txt", b"original")
        self.rewrite_in_place(self.root, "c.txt", b"tampered")
        self.assertRefused({"stale-content", "stale-identity"}, self.root.move_to, "c.txt", destination=self.root,
                           destination_relative="folder/c.txt", expected=changed)
        self.assertIn("c.txt", self.names())
        self.assertNotIn("folder/c.txt", self.names("folder"))

    def test_snapshot_lists_and_hashes_the_tree(self):
        self.root.mkdir("a")
        self.root.mkdir("a/b")
        self.seed("a/x.txt", b"x")
        self.seed("a/b/y.txt", b"yy")
        self.seed("z.txt", b"")
        rows = self.root.snapshot()
        self.assertEqual([row["relative_path"] for row in rows], ["", "a", "a/b", "a/b/y.txt", "a/x.txt", "z.txt"])
        self.assertTrue(all(row["sha256"] is None for row in rows))
        hashed = {row["relative_path"]: row["sha256"] for row in self.root.snapshot(hash_files=True)}
        self.assertEqual((hashed["a/b/y.txt"], hashed["z.txt"], hashed["a"]), (sha256(b"yy"), sha256(b""), None))
        self.assertRefused("invalid-option", self.root.snapshot, hash_files=1)

    def test_snapshot_refuses_changes_while_it_runs(self):
        self.root.mkdir("a")
        self.seed("a/x.txt", b"x")
        real = self.root.list_directory
        # Call 2 lists "a" during the first pass (a new top-level entry changes the root);
        # call 3 re-lists the root in the verification pass (a new entry in "a" changes "a").
        for when, late in ((2, "late.txt"), (3, "a/new.txt")):
            calls = []

            def listing(relative="", *, excluded=None):
                calls.append(relative)
                if len(calls) == when:
                    self.seed(late, b"late")
                return real(relative, excluded=excluded)

            with self.subTest(late=late), mock.patch.object(self.root, "list_directory", side_effect=listing):
                self.assertRefused("snapshot-drift", self.root.snapshot)

    def test_snapshot_entry_cap_counts_entries_not_the_root(self):
        self.root.mkdir("d")
        for index in range(2):
            self.seed(f"d/f{index}.txt", b"")
        self.root.max_entries = 3
        self.assertEqual(len(accepted(self, self.root.snapshot)), 4)
        self.seed("extra.txt", b"")
        self.assertRefused("entry-cap", self.root.snapshot)

    def test_list_directory_refuses_an_oversized_directory(self):
        for index in range(3):
            self.seed(f"f{index}.txt", b"")
        self.root.max_entries = 3
        self.assertEqual(len(accepted(self, self.root.list_directory)), 3)
        self.seed("f3.txt", b"")
        self.assertRefused("entry-cap", self.root.list_directory)

    def test_unportable_and_link_entries_are_listed_as_not_included(self):
        self.seed("keep.txt", b"kept")
        self.root.mkdir("deep")
        raw = [("name-colon", "", "a:b", "file", 1, "not-portable"),
               ("name-reserved", "", "nul", "file", 1, "not-portable"),
               ("name-trailing-dot", "", "trailing.", "file", 1, "not-portable"),
               ("name-colon", "", "x\u202ey:z", "file", 1, "not-portable"),
               ("link", "", "link", "link", 1, "link"), ("special", "", "fifo", "special", 1, "special"),
               ("hard-link", "", "twice.txt", "file", 2, "hard-link"),
               ("long-path", "deep", "n" * 196, "file", 1, "path-too-long")]
        created = [(parent, name, reason) for capability, parent, name, kind, nlink, reason in raw
                   if self.capability(capability, self.add_raw_name(self.root, parent, name, kind, nlink))]
        # A case-insensitive file system holds only the first name of the pair, which is then ordinary.
        if self.capability("case-pair", self.add_case_pair(self.root, "", "Readme.TXT", "README.txt")):
            created += [("", "Readme.TXT", "case-collision"), ("", "README.txt", "case-collision")]
            admitted = ["deep", "keep.txt"]
        else:
            admitted = ["Readme.TXT", "deep", "keep.txt"]
        listed, snapped = [], []
        self.assertEqual(self.names(), [row["relative_path"] for row in self.root.list_directory("", excluded=listed)])
        self.assertEqual(self.names(), admitted)
        self.assertEqual(self.names("deep"), [])
        rows = self.root.snapshot(hash_files=True, excluded=snapped)
        self.assertEqual([row["relative_path"] for row in rows], sorted([""] + admitted))
        expected = Counter((parent, pc_paths.display(name), reason) for parent, name, reason in created)
        self.assertEqual(Counter((row["parent"], row["name"], row["reason"]) for row in snapped), expected)
        self.assertEqual(Counter((row["parent"], row["name"], row["reason"]) for row in listed),
                         Counter({key: count for key, count in expected.items() if key[0] == ""}))
        self.assertTrue(all(row["reason"] in scoped_base.EXCLUDED_REASONS for row in listed + snapped))
        if ("", "x\u202ey:z", "not-portable") in created:
            self.assertIn(("", "x\\u202ey:z", "not-portable"), expected)
        for name in ("a:b", "nul", "trailing."):
            with self.subTest(name=name):
                self.assertRefused(PATH_CODES, self.root.inspect, name)

    def test_not_included_rows_are_bounded(self):
        for capability, kind, nlink in (("hard-link", "file", 2), ("link", "link", 1)):
            if capability not in self.absent_capabilities:
                for index in range(5):
                    self.capability(capability, self.add_raw_name(self.root, "", f"x{index}", kind, nlink))
                break
        else:
            self.fail("bounding the not-included rows needs hard links or links on this platform")
        self.seed("keep.txt", b"kept")
        with mock.patch.object(scoped_base, "MAX_EXCLUDED_ROWS", 3):
            listed, snapped = [], []
            self.root.list_directory("", excluded=listed)
            rows = self.root.snapshot(excluded=snapped)
        for excluded in (listed, snapped):
            self.assertEqual(len(excluded), 4)
            self.assertEqual([row["name"] for row in excluded[:3]], ["x0", "x1", "x2"])
            self.assertEqual(excluded[3], {"parent": "", "name": "", "reason": scoped_base.MORE_EXCLUDED, "count": 2})
        self.assertEqual([row["relative_path"] for row in rows], ["", "keep.txt"])

    def test_links_and_aliases_are_never_followed(self):
        secret = self.seed("secret.txt", b"private")
        if self.capability("link", self.add_raw_name(self.root, "", "shortcut", "link")):
            for call in (lambda: self.root.inspect("shortcut"), lambda: self.root.list_directory("shortcut"),
                         lambda: self.root.open_read("shortcut", expected={**secret, "relative_path": "shortcut"}).__enter__()):
                self.assertRaises(ScopedFSError, call)
            self.assertNotIn("shortcut", self.names())
        alias = self.alias(self.root, "secret.txt")
        if self.capability("alias", alias is not None):
            self.assertRaises(ScopedFSError, self.root.inspect, alias)
            self.assertRaises(ScopedFSError, self.root.remove_file, alias, expected={**secret, "relative_path": alias})
        self.assertEqual(self.root.read_bytes("secret.txt", expected=secret, max_bytes=10), b"private")

    def test_paths_outside_the_grammar_are_refused(self):
        for path in ("../x", "/abs", "a\\b", "con.txt", "a:b", "x/", "x.", "COM\u00b9", "a/" * 64 + "a"):
            with self.subTest(path=path):
                self.assertRefused(PATH_CODES, self.root.inspect, path)

    def test_free_bytes_is_a_non_negative_integer(self):
        free = self.root.free_bytes()
        self.assertIs(type(free), int)
        self.assertGreaterEqual(free, 0)


class FakeRootContractTests(RootContract, unittest.TestCase):
    def new_root(self):
        return FakeRoot()

    def grow(self, root, relative, extra):
        node = root.nodes[relative]
        node.data.extend(extra)
        node.mtime_ns += 1

    def shrink(self, root, relative, size):
        node = root.nodes[relative]
        del node.data[size:]
        node.mtime_ns += 1

    def touch(self, root, relative):
        root.nodes[relative].mtime_ns += 1000

    def rewrite_in_place(self, root, relative, data):
        node = root.nodes[relative]
        self.assertEqual(len(data), len(node.data))
        node.data[:] = data

    def swap(self, root, relative, data):
        root.nodes[relative] = root.new_node("file", data)
        return True

    def temp_names(self, root):
        return [name for name in root.nodes if name.rpartition("/")[2].startswith(".partial-")]

    def make_read_only(self, root, relative):
        node = root.nodes[relative]
        node.mode, node.attributes = 0o100400, node.attributes | 0x1
        node.ctime_ns += 1

    def permissions(self, root, relative):
        return "private" if root.nodes[relative].private else "inherited"

    def restored_mode(self, root, relative):
        return stat.S_IMODE(root.nodes[relative].mode)

    def fail_sync(self, root):
        root.durable = False
        return True

    def add_raw_name(self, root, parent, name, kind="file", nlink=1):
        root.nodes[(parent + "/" if parent else "") + name] = root.new_node(kind, b"raw", nlink)
        return True

    def add_case_pair(self, root, parent, first, second):
        for name in (first, second):
            self.add_raw_name(root, parent, name)
        return True

    def alias(self, root, relative):
        root.aliases["SECRET~1.TXT"] = relative
        return "SECRET~1.TXT"

    def new_destination_root(self, volume, *, non_private_destination):
        return FakeRoot(volume=volume, non_private_destination=non_private_destination)


class _LaxRoot(FakeRoot):
    """A backend that forgets its exit check, to show the shared methods do not depend on it."""

    @contextlib.contextmanager
    def open_read(self, relative, *, expected, uncached=False):
        handle = _Reader(self, relative, self.node(relative, "file"))
        yield handle


class _UnstableIdRoot(FakeRoot):
    """A FAT-like backend whose file ids change every time a file is opened or listed."""

    def record_of(self, relative, node, sha=None):
        return {**super().record_of(relative, node, sha), "inode": next(self._inodes)}


class SharedMethodTests(unittest.TestCase):
    def test_stream_to_rechecks_identity_on_the_handle_after_the_last_chunk(self):
        root = _LaxRoot()
        record = without_durable(root.create_file("f.bin", data=pattern(CHUNK_BYTES + 5)))

        def writer(chunk):
            root.nodes["f.bin"].mtime_ns += 1

        with self.assertRaises(ScopedFSError) as caught:
            root.stream_to("f.bin", expected=record, writer=writer)
        self.assertEqual(caught.exception.code, "read-drift")

    def test_stream_to_compares_the_hash_itself(self):
        root = _LaxRoot()
        record = without_durable(root.create_file("f.bin", data=b"abcdef"))
        root.nodes["f.bin"].data[:] = b"fedcba"
        with self.assertRaises(ScopedFSError) as caught:
            root.stream_to("f.bin", expected=record, writer=len)
        self.assertEqual(caught.exception.code, "stale-content")

    def test_unstable_file_ids_need_narrowed_identity_keys(self):
        root = _UnstableIdRoot()
        record = without_durable(root.create_file("f.bin", data=b"abc"))
        with self.assertRaises(ScopedFSError) as caught:
            root.stream_to("f.bin", expected=record, writer=len)
        self.assertEqual(caught.exception.code, "stale-identity")
        root.identity_keys = frozenset({"relative_path", "kind", "size"})
        self.assertEqual(accepted(self, root.stream_to, "f.bin", expected=record, writer=len), record)
        self.assertEqual(len(accepted(self, root.snapshot, hash_files=True)), 2)
        root.nodes["f.bin"].data[:] = b"xyz"
        with self.assertRaises(ScopedFSError) as caught:
            root.stream_to("f.bin", expected=record, writer=len)
        self.assertEqual(caught.exception.code, "stale-content")

    @staticmethod
    def outcome(case_class, method):
        """(failures, errors) of one contract method run against a variant of the fake backend."""
        result = unittest.TestResult()
        case_class(method).run(result)
        return len(result.failures), len(result.errors)

    def test_not_included_contract_holds_on_a_case_insensitive_file_system(self):
        class CaseInsensitive(FakeRootContractTests):
            """Like NTFS and APFS by default: a second name that differs only in case cannot be created."""

            absent_capabilities = frozenset({"case-pair"})

            def add_raw_name(self, root, parent, name, kind="file", nlink=1):
                key = pc_paths.casefold_key((parent + "/" if parent else "") + name)
                if any(pc_paths.casefold_key(existing) == key for existing in root.nodes):
                    return False
                return super().add_raw_name(root, parent, name, kind, nlink)

            def add_case_pair(self, root, parent, first, second):
                return self.add_raw_name(root, parent, first) and self.add_raw_name(root, parent, second)

        class Undeclared(CaseInsensitive):
            absent_capabilities = frozenset()

        method = "test_unportable_and_link_entries_are_listed_as_not_included"
        self.assertEqual(self.outcome(CaseInsensitive, method), (0, 0))
        self.assertEqual(self.outcome(Undeclared, method), (1, 0))

    def test_hooks_cannot_skip_their_core_assertion(self):
        class NoSync(FakeRootContractTests):
            def fail_sync(self, root):
                return False

        class DeclaredNoSync(NoSync):
            absent_capabilities = frozenset({"fail-sync"})

        class FalselyDeclared(FakeRootContractTests):
            absent_capabilities = frozenset({"fail-sync"})

        class NoSwap(FakeRootContractTests):
            def swap(self, root, relative, data):
                return False

        class DeclaredNoSwap(NoSwap):
            absent_capabilities = frozenset({"swap"})

        class Unknown(FakeRootContractTests):
            absent_capabilities = frozenset({"teleport"})

        durability, removal = "test_commit_reports_durability", "test_remove_hashes_on_delete_handle"
        self.assertEqual(self.outcome(NoSync, durability), (1, 0))
        self.assertEqual(self.outcome(DeclaredNoSync, durability), (0, 0))
        self.assertEqual(self.outcome(FalselyDeclared, durability), (1, 0))
        self.assertEqual(self.outcome(NoSwap, removal), (1, 0))
        self.assertEqual(self.outcome(DeclaredNoSwap, removal), (0, 0))
        self.assertEqual(self.outcome(Unknown, "test_absent_capabilities_are_known"), (1, 0))

    def test_exclude_keeps_a_bounded_number_of_rows(self):
        rows = []
        with mock.patch.object(scoped_base, "MAX_EXCLUDED_ROWS", 2):
            for index in range(5):
                scoped_base.exclude(rows, "dir", f"link{index}", "link")
        self.assertEqual(rows, [{"parent": "dir", "name": "link0", "reason": "link"},
                                {"parent": "dir", "name": "link1", "reason": "link"},
                                {"parent": "", "name": "", "reason": "more", "count": 3}])
        self.assertEqual(scoped_base.MAX_EXCLUDED_ROWS, 1_000)
        self.assertIsNone(scoped_base.exclude(None, "", "x", "link"))
        for excluded, reason in (([], "too-big"), (None, "too-big"), ((), "link"), ({}, "link")):
            with self.subTest(excluded=excluded, reason=reason), self.assertRaises(ScopedFSError):
                scoped_base.exclude(excluded, "", "x", reason)
        with self.assertRaises(ScopedFSError):
            FakeRoot().snapshot(excluded=())

    def test_snapshot_refuses_rows_a_listing_must_not_return(self):
        root = FakeRoot()
        root.create_file("f.bin", data=b"x")
        good = root.list_directory()[0]
        bad_rows = [{**good, "kind": "link"}, {**good, "relative_path": "elsewhere/f.bin"}, {**good, "extra": 1},
                    "f.bin", {**good, "relative_path": "nul"}]
        for row in bad_rows:
            with self.subTest(row=repr(row)[:50]), mock.patch.object(root, "list_directory", return_value=[row]):
                with self.assertRaises(ScopedFSError) as caught:
                    root.snapshot()
                self.assertIn(caught.exception.code, {"listing-contract", "reserved-path-component"})

    def test_create_file_verifies_the_committed_record(self):
        root = FakeRoot()
        with mock.patch.object(_NewFile, "commit", lambda self: {"size": 1, "sha256": "0" * 64, "durable": True}):
            with self.assertRaises(ScopedFSError) as caught:
                root.create_file("f.bin", data=b"abc")
        self.assertEqual(caught.exception.code, "write-verification")

    def test_create_file_refuses_a_stalled_writer(self):
        root = FakeRoot()
        with mock.patch.object(_NewFile, "write", lambda self, data: 0):
            with self.assertRaises(ScopedFSError) as caught:
                root.create_file("f.bin", data=b"abc")
        self.assertEqual(caught.exception.code, "short-write")
        self.assertEqual([name for name in root.nodes if ".partial-" in name], [])

    def test_hash_stream_handles_short_reads(self):
        class Trickle(io.RawIOBase):
            def __init__(self, data):
                super().__init__()
                self.data = data

            def readable(self):
                return True

            def readinto(self, buffer):
                chunk, self.data = self.data[:7], self.data[7:]
                buffer[:len(chunk)] = chunk
                return len(chunk)

        data = pattern(100)
        self.assertEqual(scoped_base.hash_stream(Trickle(data), 100), sha256(data))
        received = []
        scoped_base.hash_stream(io.BytesIO(data), 100, received.append)
        self.assertEqual(b"".join(received), data)
        for size in (-1, True, 1.0, scoped_base.MAX_STREAM_BYTES + 1):
            with self.subTest(size=size):
                with self.assertRaises(ScopedFSError) as caught:
                    scoped_base.hash_stream(io.BytesIO(data), size)
                self.assertEqual(caught.exception.code, "invalid-cap")

    def test_expected_record_validation(self):
        posix = {"relative_path": "a/b.txt", "kind": "file", "device": 2049, "inode": 1835041, "mode": 0o100644,
                 "size": 3, "mtime_ns": 4, "ctime_ns": 5, "nlink": 1, "sha256": "a" * 64, "attributes": 0}
        windows = {**posix, "device": 0x9A3F21C4, "inode": 0x0003000000012A4F, "mode": 0o100666, "attributes": 0x20}
        before_1970 = {**windows, "mtime_ns": -315619200000000000, "ctime_ns": -11644473600000000000}
        for good in (posix, windows, before_1970):
            self.assertIs(accepted(self, scoped_base.expected_record, good, "a/b.txt"), good)
        self.assertIs(scoped_base.expected_record({**posix, "sha256": None}, "a/b.txt", hashed=False)["sha256"], None)
        bad = [{**posix, "kind": "directory"}, {**posix, "sha256": "A" * 64}, {**posix, "sha256": None},
               {**posix, "inode": 0}, {**posix, "nlink": 2}, {**posix, "size": -1}, {**posix, "size": True},
               {**posix, "size": scoped_base.MAX_STREAM_BYTES + 1}, {**posix, "mode": 0o040755},
               {**windows, "mode": 0x20}, {**windows, "inode": "0003000000012a4f"}, {**posix, "extra": 1},
               {**posix, "device": -1}, {**posix, "mtime_ns": -1.0},
               {key: value for key, value in posix.items() if key != "attributes"}, None, []]
        for value in bad:
            with self.subTest(value=repr(value)[:60]):
                with self.assertRaises(ScopedFSError) as caught:
                    scoped_base.expected_record(value, "a/b.txt")
                self.assertEqual(caught.exception.code, "expected-record")
        with self.assertRaises(ScopedFSError) as caught:
            scoped_base.expected_record(posix, "a/../b.txt")
        self.assertEqual(caught.exception.code, "invalid-path-component")

    def test_read_only_with_real_record_shapes(self):
        self.assertFalse(scoped_base.read_only({"mode": 0o100666, "attributes": 0x20}))   # ordinary Windows file
        self.assertTrue(scoped_base.read_only({"mode": 0o100444, "attributes": 0x21}))    # Windows read-only file
        self.assertFalse(scoped_base.read_only({"mode": 0o100644, "attributes": 0}))      # ordinary POSIX file
        self.assertTrue(scoped_base.read_only({"mode": 0o100444, "attributes": 0}))       # POSIX without write bits
        self.assertTrue(scoped_base.read_only({"mode": 0o100666, "attributes": 0x1}))

    def test_new_file_mode(self):
        self.assertIsNone(scoped_base.new_file_mode(True, None))
        for original, expected in ((0o100755, 0o644), (0o100600, 0o600), (0o640, 0o640), (0o4777, 0o644), (0, 0)):
            with self.subTest(original=oct(original)):
                self.assertEqual(scoped_base.new_file_mode(False, original), expected)
        for private, original in ((1, None), (True, 0o644), (False, None), (False, 0o040755), (False, -1),
                                  (False, 0o200000), (False, 1.0)):
            with self.subTest(private=private, original=original):
                with self.assertRaises(ScopedFSError) as caught:
                    scoped_base.new_file_mode(private, original)
                self.assertEqual(caught.exception.code, "invalid-option")

    def test_not_included_rows_and_reasons(self):
        self.assertIsNone(scoped_base.name_reason("", "report.docx"))
        self.assertIsNone(scoped_base.name_reason("deep", "report.docx"))
        for parent, name in (("", "a:b"), ("", "CON.txt"), ("", "x "), ("", "a/b"), ("", None), ("", "")):
            with self.subTest(name=name):
                self.assertEqual(scoped_base.name_reason(parent, name), "not-portable")
        self.assertEqual(scoped_base.name_reason("d" * 150, "n" * 60), "path-too-long")
        row = scoped_base.not_included("folder", "bad\u202eexe.pdf\n", "not-portable")
        self.assertEqual(row, {"parent": "folder", "name": "bad\\u202eexe.pdf\\u000a", "reason": "not-portable"})
        with self.assertRaises(ScopedFSError):
            scoped_base.not_included("", "x", "too-big")

    def test_admit_new_uses_max_file_bytes(self):
        root = FakeRoot()
        self.assertIsNone(root.admit_new("a.bin", scoped_base.MAX_STREAM_BYTES))
        with self.assertRaises(ScopedFSError) as caught:
            root.admit_new("a.bin", scoped_base.MAX_STREAM_BYTES + 1)  # the default cap is MAX_STREAM_BYTES
        self.assertEqual(caught.exception.code, "file-too-large-for-volume")
        root.max_file_bytes = (1 << 32) - 1
        self.assertIsNone(root.admit_new("a.bin", (1 << 32) - 1))
        with self.assertRaises(ScopedFSError) as caught:
            root.admit_new("a.bin", 1 << 32)
        self.assertEqual(caught.exception.code, "file-too-large-for-volume")

    def test_destination_identity_keys(self):
        def keys(volume, stable_ids):
            return scoped_base.destination_facts(volume, non_private_destination=True, stable_ids=stable_ids)["identity_keys"]
        self.assertEqual(keys("private", True), scoped_base.IDENTITY_KEYS)
        self.assertEqual(keys("non-private", True), scoped_base.IDENTITY_KEYS)  # a removable NTFS drive
        self.assertEqual(keys("non-private", False), scoped_base.UNSTABLE_ID_KEYS)  # exFAT, vfat
        for stable_ids in (True, False):  # FAT file ids change between mounts
            self.assertEqual(keys("fat32", stable_ids), scoped_base.UNSTABLE_ID_KEYS)
        with self.assertRaises(TypeError):  # every backend says whether its ids are stable
            scoped_base.destination_facts("private", non_private_destination=False)

    def test_partial_names(self):
        self.assertRegex(scoped_base.partial_name(), scoped_base.PARTIAL_NAME)
        given = scoped_base.new_partial_name()
        self.assertEqual(scoped_base.partial_name(given), given)
        for bad in ("notes.txt", given.upper(), given + "x", 1):
            with self.subTest(partial=bad), self.assertRaises(ScopedFSError):
                scoped_base.partial_name(bad)
        name = scoped_base.new_partial_name()
        self.assertRegex(name, scoped_base.PARTIAL_NAME)
        self.assertNotEqual(name, scoped_base.new_partial_name())
        for other in (".partial-notes.docx", ".partial-" + "A" * 32, "x.partial-" + "a" * 32, ".partial-" + "a" * 31):
            self.assertIsNone(scoped_base.PARTIAL_NAME.match(other))

    def test_errors_and_path_wrapper(self):
        error = ScopedFSError("code-x", "detail")
        self.assertIsInstance(error, pc_records.Refusal)
        self.assertIsInstance(error, ValueError)
        self.assertEqual((error.code, str(error)), ("code-x", "code-x: detail"))
        self.assertEqual(str(ScopedFSError("bare")), "bare")
        self.assertTrue(issubclass(scoped_base.CapabilityHold, ScopedFSError))
        self.assertEqual(scoped_base.relative_path("", allow_root=True), "")
        self.assertEqual(scoped_base.relative_path("a/b"), "a/b")
        for value, code in (("", "invalid-relative-path"), ("NUL", "reserved-path-component"), ("a" * 201, "path-too-long")):
            with self.subTest(value=value[:10]):
                with self.assertRaises(ScopedFSError) as caught:
                    scoped_base.relative_path(value)
                self.assertEqual(caught.exception.code, code)

    def test_cap_and_constants(self):
        self.assertEqual((CHUNK_BYTES, scoped_base.MAX_STREAM_BYTES), (1 << 20, 1 << 40))
        self.assertEqual(scoped_base.MAX_ENTRIES, pc_records.MAX_BACKUP_ENTRIES)
        self.assertEqual(FakeRoot().max_entries, pc_records.MAX_BACKUP_ENTRIES)
        self.assertEqual(scoped_base.cap(5, 10, "x"), 5)
        for value in (0, 11, True, 5.0):
            with self.subTest(value=value), self.assertRaises(ScopedFSError):
                scoped_base.cap(value, 10, "x")

    def test_root_base_is_abstract_and_a_context_manager(self):
        with self.assertRaises(TypeError):
            scoped_base.RootBase()
        with FakeRoot() as root:
            self.assertFalse(root.closed)
        self.assertTrue(root.closed)

    def test_imports_only_the_standard_library_and_layer_zero(self):
        tree = ast.parse((ROOT / "scripts" / "scoped_base.py").read_text(encoding="utf-8"))
        imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imported, {"__future__", "abc", "contextlib", "hashlib", "re", "stat", "typing", "uuid",
                                    "pc_paths", "pc_records"})


FIXTURES = ROOT / "work" / "test-fixtures"


def remove_fixture(path):
    """Remove a fixture folder, including names only the extended path form reaches and read-only files."""
    def writable_then_retry(function, name, _error):
        os.chmod(name, stat.S_IWRITE)
        function(name)
    shutil.rmtree("\\\\?\\" + str(path), onexc=writable_then_retry)


@unittest.skipUnless(os.name == "nt", "only on windows: WindowsRoot runs on Win32 file handles")
class WindowsRootContractTests(RootContract, unittest.TestCase):
    """The contract against the Windows backend, on real NTFS folders under work/test-fixtures/.

    A file this backend reads is shared for reading only and a file it removes is not shared at all,
    so no other program can grow, shrink or swap it meanwhile: grow and shrink act where the backend
    reads (win32_files.read) and swap reports that the platform refused it. Timestamps, which share
    modes do not protect, are changed for real. "secret.txt" is already a valid 8.3 name, so NTFS gives
    it no alias; test_windows_io covers 8.3 aliases with a long name.
    """

    absent_capabilities = frozenset({"swap", "posix-mode", "case-pair", "name-colon", "special", "alias"})

    def new_root(self):
        import windows_scoped
        self.case = FIXTURES / ("contract-" + uuid.uuid4().hex)
        (self.case / "root").mkdir(parents=True)
        (self.case / "outside").mkdir()
        self.addCleanup(remove_fixture, self.case)
        return windows_scoped.WindowsRoot(str(self.case / "root"))

    def path(self, relative):
        return self.case / "root" / relative

    def patch_reads(self, replacement):
        import win32_files
        real = win32_files.read
        patcher = mock.patch.object(win32_files, "read", lambda handle, address, count: replacement(real, handle, address, count))
        patcher.start()
        self.addCleanup(patcher.stop)

    def grow(self, root, relative, extra):
        pending = [extra]

        def read(real, handle, address, count):
            done = real(handle, address, count)
            if done or not pending:
                return done
            data = pending.pop()[:count]
            ctypes.memmove(address, data, len(data))
            return len(data)

        self.patch_reads(read)

    def shrink(self, root, relative, size):
        self.patch_reads(lambda real, handle, address, count: 0)

    def touch(self, root, relative):
        info = os.stat(self.path(relative))
        os.utime(self.path(relative), ns=(info.st_atime_ns, info.st_mtime_ns + 10 ** 9))

    def rewrite_in_place(self, root, relative, data):
        info = os.stat(self.path(relative))
        self.assertEqual(len(data), info.st_size)
        with open(self.path(relative), "r+b") as stream:
            stream.write(data)
        os.utime(self.path(relative), ns=(info.st_atime_ns, info.st_mtime_ns))

    def swap(self, root, relative, data):
        other = self.case / "outside" / ("swap-" + uuid.uuid4().hex)
        other.write_bytes(data)
        try:
            os.replace(other, self.path(relative))
        except PermissionError:
            other.unlink()
            return False
        return True

    def temp_names(self, root):
        found = []
        for folder, _dirs, files in os.walk(self.case / "root"):
            found += [os.path.relpath(os.path.join(folder, name), self.case / "root").replace("\\", "/")
                      for name in files if scoped_base.PARTIAL_NAME.search(name)]
        return found

    def make_read_only(self, root, relative):
        os.chmod(self.path(relative), stat.S_IREAD)

    def permissions(self, root, relative):
        import win32_files
        handle = win32_files.open_file(str(self.path(relative)), win32_files.READ_CONTROL, 7, win32_files.OPEN_EXISTING,
                                       win32_files.FILE_FLAG_OPEN_REPARSE_POINT)
        with handle:
            owner, control, aces = win32_files.security_snapshot(handle)
        if (control & 0x1000 and owner == win32_files.token_user()
                and sorted(sid for _kind, flags, _mask, sid in aces if not flags) == sorted(win32_files.private_principals())
                and len(aces) == len(win32_files.private_principals())):
            return "private"
        return "inherited" if aces and all(flags & 0x10 for _kind, flags, _mask, _sid in aces) else "other"

    def restored_mode(self, root, relative):
        return None

    def fail_sync(self, root):
        import win32_files
        real, failed = win32_files.flush, []

        def flush(handle):
            if not failed:
                failed.append(True)
                raise OSError(5, "fictional sync failure", None, 1117)
            return real(handle)

        patcher = mock.patch.object(win32_files, "flush", flush)
        patcher.start()
        self.addCleanup(patcher.stop)
        return True

    def add_raw_name(self, root, parent, name, kind="file", nlink=1):
        if kind == "special" or ":" in name:
            return False  # NTFS has no FIFOs, and a colon names a stream of another file
        target = self.path(parent) / name if parent else self.path(name)
        if kind == "link":
            import _winapi
            _winapi.CreateJunction(str(self.case / "outside"), str(target))
            return True
        # The extended form stores names such as "nul" and "trailing." literally.
        with open("\\\\?\\" + str(target), "xb") as stream:
            stream.write(b"raw")
        if nlink == 2:
            os.link("\\\\?\\" + str(target), self.case / "outside" / (uuid.uuid4().hex + ".link"))
        return True

    def add_case_pair(self, root, parent, first, second):
        self.add_raw_name(root, parent, first)
        try:
            self.add_raw_name(root, parent, second)
        except FileExistsError:
            return False
        return True

    def alias(self, root, relative):
        return None

    def new_destination_root(self, volume, *, non_private_destination):
        import windows_scoped
        filesystem, drive_type = {"private": ("NTFS", 3), "removable-exfat": ("exFAT", 2), "fat32": ("FAT32", 2),
                                  "unsupported": ("NTFS", 4)}[volume]
        folder = self.case / ("destination-" + uuid.uuid4().hex)
        folder.mkdir()
        return windows_scoped.admit_destination(str(folder), non_private_destination=non_private_destination,
                                               volumes=lambda handle, drive: {"filesystem": filesystem, "drive_type": drive_type})


if __name__ == "__main__":
    unittest.main()
