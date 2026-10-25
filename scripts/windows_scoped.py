"""Windows selected-root backend: WindowsRoot over win32_files, in this process (decision D-008).

Every native call of a root runs on the root's own I/O thread, on handles held for the whole
operation. The selected root and its ancestors stay open for the root's lifetime without delete
sharing, so none of them can be renamed or removed; each component below the root is looked up in
its parent's index before it is opened (reparse points and cloud placeholders are refused unopened)
and then opened with FILE_FLAG_OPEN_REPARSE_POINT; a file being read is shared for reading only.
Each call has a deadline: a call that does not return is cancelled with CancelSynchronousIo and the
operation is reported as unresolved; the bound is best effort (decision D-018). This is a cooperative
boundary for a quiet workspace, not an OS sandbox.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, suppress
import ctypes
import io
import ntpath
import os
from pathlib import Path
import queue
import re
import sys
import threading

import pc_paths
import pc_records
import scoped_base
from scoped_base import CHUNK_BYTES, MAX_STREAM_BYTES, CapabilityHold, ScopedFSError, refuse
import win32_files as w32

ADAPTER = "windows-handles"
MAX_ENTRIES = scoped_base.MAX_ENTRIES
# The retired helper's bound on every absolute path, in UTF-16 units: what is selected or created stays within
# MAX_PATH, so ordinary programs can open it.
MAX_PATH_CHARS = 240
# Seconds one native call may take, and the wait after CancelSynchronousIo before it counts as stuck. Flushing a
# new file also gets time per byte, at the speed of a slow USB drive.
IO_SECONDS = 120.0
CANCEL_SECONDS = 5.0
FLUSH_BYTES_PER_SECOND = 2 * 1024 * 1024
# The in-memory bound storage_ops relies on until it streams (ScopedRoot below).
LEGACY_MAX_BYTES = 64 * 1024 * 1024
_EXTENDED = "\\\\?\\"
# BACKUP_SEMANTICS only opens folders: on a file it would let an enabled SeBackupPrivilege bypass the file's DACL.
_FOLDER_FLAGS = w32.FILE_FLAG_BACKUP_SEMANTICS | w32.FILE_FLAG_OPEN_REPARSE_POINT
_FILE_FLAGS = w32.FILE_FLAG_OPEN_REPARSE_POINT
_ANCESTOR_SHARE = w32.FILE_SHARE_READ | w32.FILE_SHARE_WRITE
_ANY_SHARE = _ANCESTOR_SHARE | w32.FILE_SHARE_DELETE
_FOLDER_ACCESS = w32.FILE_READ_ATTRIBUTES | w32.FILE_LIST_DIRECTORY
_READ_ACCESS = w32.FILE_READ_DATA | w32.FILE_READ_ATTRIBUTES
# Handle metadata; 0x40000 is not here because there it means "has extended attributes" (decision D-022).
_UNSUPPORTED = w32.ATTRIBUTE_OFFLINE | w32.ATTRIBUTE_ENCRYPTED | w32.ATTRIBUTE_RECALL_ON_DATA_ACCESS
_UNSUPPORTED_ENTRY = _UNSUPPORTED | w32.ATTRIBUTE_RECALL_ON_OPEN
# Compared before and after a rename. Not ctime_ns: NTFS tunneling gives a name freed less than 15 s earlier the
# creation time of the file that had it.
_RENAMED_KEYS = frozenset({"kind", "device", "inode", "size", "mtime_ns", "nlink", "attributes"})
# Left out of records: Windows sets the archive bit when it renames a file (visible once the handle closes), and
# NORMAL only means that no other attribute is set.
_VOLATILE_ATTRIBUTES = w32.ATTRIBUTE_ARCHIVE | w32.FILE_ATTRIBUTE_NORMAL
_STUCK = []


def _platform_problem():
    if os.name != "nt":
        return "windows-required"
    if sys.version_info < (3, 12):
        return "python-312-required"
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return "windows-64bit-python-required"
    if w32.API is None:
        return "native-api-unavailable"
    return None


def _require_platform():
    problem = _platform_problem()
    if problem:
        raise CapabilityHold(problem, "The Windows file backend needs 64-bit Python 3.12 or later on Windows")


def capabilities() -> dict:
    """What this backend offers here, without touching any selected root."""
    problem = _platform_problem()
    available = problem is None
    return {"available": available, "platform": "windows", "adapter": ADAPTER, "reason": problem,
            "pinning": available, "pinning_scope": "selected-root-ancestry-for-the-root-lifetime-and-file-per-operation",
            "filesystem": "ntfs-sources", "move_noreplace": available, "remove_exact_file": available,
            "remove_file": available, "mkdir": available, "create_file": available, "read_bytes": available,
            "stream_to": available, "stream_max_bytes": MAX_STREAM_BYTES if available else 0,
            "max_read_bytes": LEGACY_MAX_BYTES if available else 0, "quiet_workspace_required": True}


def process_is_elevated() -> bool:
    """True when this process runs elevated (assessment #49; the plan's RET leaf wires the refusal of changes)."""
    _require_platform()
    try:
        return w32.token_elevated()
    except OSError:
        raise CapabilityHold("native-security-context-unavailable", "The process token could not be read") from None


def shutdown_worker() -> bool:
    """True when no file call of any root is still running past its deadline (the handoff asks before it runs)."""
    return not any(thread.busy() for thread in _STUCK)


def _ns(filetime):
    return (filetime.value - 116444736000000000) * 100


def _sorted_names(names):
    """Names in UTF-16 code unit order, the order Windows itself compares in."""
    return sorted(names, key=lambda name: name.encode("utf-16-be", "surrogatepass"))


def _native(code, function, *args):
    """Call a win32_files function; an OSError becomes a categorical refusal (a full disk keeps its own code)."""
    try:
        return function(*args)
    except OSError as error:
        if error.winerror == w32.ERROR_DISK_FULL:
            raise ScopedFSError("disk-full", "The drive is full") from None
        raise ScopedFSError(code, f"Windows error {error.winerror}") from None


def _read_into(handle, target):
    return _native("read-failed", w32.read, handle, ctypes.addressof(target), len(target))


def _open_refusal(error):
    winerror = getattr(error, "winerror", None)
    if winerror in (w32.ERROR_FILE_NOT_FOUND, w32.ERROR_PATH_NOT_FOUND):
        return ScopedFSError("missing-entry", "Exact entry is missing")
    if winerror in (w32.ERROR_SHARING_VIOLATION, w32.ERROR_LOCK_VIOLATION):
        return ScopedFSError("sharing-violation", "Another program has the entry open; nothing is retried")
    return ScopedFSError("access-sharing-or-missing", f"The entry could not be opened (Windows error {winerror})")


def _volume_facts(handle, drive):
    """Default volume-information source: file system name and drive type of the root's volume."""
    _serial, filesystem, _flags = w32.volume_information(handle)
    return {"filesystem": filesystem, "drive_type": w32.drive_type(drive)}


def _root_path(root):
    """The selected root as a plain local absolute path, refused unless it is already canonical."""
    try:
        raw = os.fspath(root)
    except TypeError:
        raw = None
    if (not isinstance(raw, str) or not re.fullmatch(r"[A-Za-z]:\\[^/]*", raw, re.S)
            or len(raw.rstrip("\\")) < 4 or w32.utf16_units(raw) > MAX_PATH_CHARS):
        refuse("local-absolute-root-required", "A local absolute folder below a drive root is required")
    trimmed = raw.rstrip("\\")
    if ntpath.normpath(trimmed) != trimmed:
        refuse("noncanonical-root", "The selected root must be written in its canonical form")
    for part in trimmed[3:].split("\\"):
        scoped_base.relative_path(part)
    return trimmed


def _refuse_impersonation():
    """CreateFileW and every later call use the calling thread's token, so a thread token is refused (M3)."""
    try:
        impersonating = w32.thread_impersonating()
    except OSError:
        raise CapabilityHold("native-security-context-unavailable", "The thread token could not be read") from None
    if impersonating:
        raise CapabilityHold("native-impersonation-unsupported", "File operations never run under impersonation")


class _Job:
    __slots__ = ("function", "args", "kwargs", "checked", "done", "value", "error")

    def __init__(self, function, args, kwargs, checked=True):
        self.function, self.args, self.kwargs, self.checked = function, args, kwargs, checked
        self.done, self.value, self.error = threading.Event(), None, None

    def run(self):
        try:
            if self.checked:
                _refuse_impersonation()
            self.value = self.function(*self.args, **self.kwargs)
        except OSError as error:
            self.error = ScopedFSError("native-call-failed", f"Windows error {error.winerror}")
        except BaseException as error:
            self.error = error
        finally:
            self.done.set()


class _IoThread:
    """The one thread that runs a root's native calls, each with a deadline (M1)."""

    def __init__(self):
        self._jobs = queue.SimpleQueue()
        self._last = None
        self.poisoned = False
        ready = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(ready,), name="patchcairn-windows-io", daemon=True)
        self._thread.start()
        ready.wait()
        if self._handle is None:
            raise CapabilityHold("native-thread-unavailable", "The file I/O thread could not be prepared")

    def _run(self, ready):
        try:
            self._handle = w32.current_thread()
        except OSError:
            self._handle = None
        ready.set()
        if self._handle is None:
            return
        with self._handle:
            while (job := self._jobs.get()) is not None:
                job.run()

    def busy(self):
        return self._last is not None and not self._last.done.is_set()

    def call(self, function, *args, check_token=True, seconds=None, **kwargs):
        if threading.current_thread() is self._thread:
            return function(*args, **kwargs)  # already on this thread: waiting for itself would never end
        if self.poisoned:
            raise CapabilityHold("io-unresolved", "An earlier file operation of this root did not finish in time")
        seconds = IO_SECONDS if seconds is None else seconds
        job = self._last = _Job(function, args, kwargs, check_token)
        self._jobs.put(job)
        try:
            finished = job.done.wait(seconds)
        except BaseException:
            # Let the call hand its new handles to their owner before the caller unwinds (M2).
            job.done.wait(seconds)
            raise
        if not finished:
            self.poisoned = True
            try:
                w32.cancel_synchronous_io(self._handle)
            except OSError:
                pass
            if not job.done.wait(CANCEL_SECONDS):
                _STUCK.append(self)
            raise CapabilityHold("io-unresolved", "A file operation did not finish before its deadline; its outcome is unknown")
        # Only a call that outlived its deadline keeps its arguments (and the caller's buffers) alive.
        job.args = job.kwargs = None
        error, job.error = job.error, None
        if error is None:
            return job.value
        try:
            raise error
        finally:
            # Its traceback holds this frame and the job's: else the job, this root and its I/O thread wait in a cycle for the
            # next collection (on Python 3.12 for Windows every lock in them holds a kernel semaphore).
            del error

    def release(self, stack):
        """Close an operation's handles. While a call is stuck they stay open: the thread closes them as soon
        as that call returns (the queue keeps the order), and never if it does not."""
        if self.busy():
            self._jobs.put(_Job(stack.close, (), {}, checked=False))
        elif self.poisoned:
            stack.close()
        else:
            self.call(stack.close, check_token=False)

    def stop(self):
        busy = self.busy()
        self._jobs.put(None)
        if not busy:
            self._thread.join(IO_SECONDS)


class _File(io.RawIOBase):
    """An open file of a WindowsRoot: unbuffered, seekable, every call on the root's I/O thread."""

    def __init__(self, root, handle, relative, *, writable=False, uncached=False, limit=MAX_STREAM_BYTES):
        super().__init__()
        self._root, self._handle, self._relative = root, handle, relative
        self._writable, self._limit, self._offset = writable, limit, 0
        self._uncached, self._block = uncached, None
        if uncached:
            # FILE_FLAG_NO_BUFFERING needs sector-aligned offsets, sizes and buffer addresses.
            # 64 KiB covers every physical sector size.
            self._buffer = ctypes.create_string_buffer(CHUNK_BYTES + 65536)
            self._aligned = ctypes.addressof(self._buffer) + (-ctypes.addressof(self._buffer)) % 65536

    def _call(self, function, *args, **options):
        self._checkClosed()
        return self._root._io.call(function, *args, **options)

    def readable(self):
        return True

    def writable(self):
        return self._writable

    def seekable(self):
        return True

    def readinto(self, buffer):
        view = memoryview(buffer).cast("B")
        if not view.nbytes:
            return 0
        if self._uncached:
            count = self._call(self._read_block, view)
        else:
            # The call owns the target until it returns, so a read that outlives its deadline never writes
            # into memory the caller has already released.
            count = self._call(_read_into, self._handle, (ctypes.c_char * min(view.nbytes, 1 << 30)).from_buffer(view))
        self._offset += count
        return count

    def _read_block(self, view):
        start = self._offset - self._offset % CHUNK_BYTES
        if self._block is None or self._block[0] != start:
            _native("seek-failed", w32.seek, self._handle, start, io.SEEK_SET)
            count = _native("read-failed", w32.read, self._handle, self._aligned, CHUNK_BYTES)
            self._block = (start, ctypes.string_at(self._aligned, count))
        data = self._block[1][self._offset - start:self._offset - start + view.nbytes]
        view[:len(data)] = data
        return len(data)

    def write(self, data):
        if not self._writable:
            raise io.UnsupportedOperation("write")
        if getattr(self, "committed", False):
            refuse("commit-state", "The file is already committed")
        view = memoryview(data).cast("B")
        if self._offset + view.nbytes > self._limit:
            refuse("file-too-large-for-volume", "The file would exceed the largest file this drive can hold")
        written = 0
        while written < view.nbytes:
            count = self._call(_native, "write-failed", w32.write, self._handle, view[written:written + CHUNK_BYTES])
            if not count:
                refuse("short-write", "The system accepted no bytes")
            written += count
            self._offset += count
        return written

    def seek(self, offset, whence=io.SEEK_SET):
        if self._uncached:
            if whence not in (io.SEEK_SET, io.SEEK_CUR, io.SEEK_END):
                refuse("invalid-option", "Unknown seek origin")
            base = (0, self._offset, None)[whence]
            base = self.record()["size"] if base is None else base
            if base + offset < 0:
                refuse("seek-failed", "A position before the start of the file was requested")
            self._offset = base + offset
        else:
            self._offset = self._call(_native, "seek-failed", w32.seek, self._handle, offset, whence)
        return self._offset

    def tell(self):
        self._checkClosed()
        return self._offset

    def record(self):
        """Identity of the open handle now (sha256 None), read from the handle, never by name."""
        return self._call(self._root._handle_record, self._handle, self._relative)


class _NewFile(_File):
    """A file being written under a temporary name in its final folder; commit() names it.

    Unbuffered like every file here: wrap it in io.BufferedRandom for many small writes and flush that before commit().
    """

    def __init__(self, root, handle, relative, parent, private):
        super().__init__(root, handle, relative, writable=True, limit=root.max_file_bytes)
        self._parent, self._private, self.committed = parent, private, False

    def commit(self) -> dict:
        """Sync the file and its folder, re-check privacy, hash this handle, rename without replacing anything, check
        the final path and identity, then sync the file and its folder again so the new name is on disk too.
        ``durable`` is True only if every one of these syncs succeeded."""
        self._checkClosed()
        if self.committed:
            refuse("commit-state", "The file is already committed")
        root = self._root
        size = self.record()["size"]
        durable = self._call(root._sync, self._handle, self._parent, seconds=IO_SECONDS + size / FLUSH_BYTES_PER_SECOND)
        if self._private:
            self._call(root._check_new_privacy, self._handle)
        before = self.record()
        self.seek(0)
        sha256 = scoped_base.hash_stream(self, before["size"])
        record = self._call(root._rename, self._handle, self._relative, before, self._parent,
                            "post-commit-verification-unresolved")
        self.committed = True
        durable = self._call(root._sync, self._handle, self._parent) and durable
        return {**record, "sha256": sha256, "durable": durable}


class WindowsRoot(scoped_base.RootBase):
    """One explicitly selected folder on a local drive, pinned with its ancestors until close().

    The constructor admits sources (NTFS, fixed drive); admit_destination() admits backup destinations. One caller
    thread uses a root at a time. Full paths stay within MAX_PATH_CHARS UTF-16 units, and a new file's temporary
    name (41 units) must fit too, so files are created only in folders whose full path has at most 198 units;
    admit_new() checks that before anything is written.
    """

    def __init__(self, root, *, max_entries=MAX_ENTRIES, expected_root=None, volumes=None, _destination=None):
        _require_platform()
        _refuse_impersonation()
        self.max_entries = scoped_base.cap(max_entries, MAX_ENTRIES, "max_entries")
        self._dos = _root_path(root)
        self._drive = self._dos[:3]
        self._volumes = _volume_facts if volumes is None else volumes
        self._closed = True
        self._pins = ExitStack()
        self._io = _IoThread()
        try:
            self._io.call(self._admit, _destination)
        except BaseException:
            self._io.release(self._pins)
            self._io.stop()
            raise
        self._closed = False
        if expected_root is not None:
            try:
                self._require_root(expected_root)
            except BaseException:
                self.close()
                raise

    # Admission ------------------------------------------------------------------------------------

    def _admit(self, destination):
        """Pin the drive root and the folders down to the root; ``destination`` is None for a source, else the acknowledgment."""
        drive = _native("access-sharing-or-missing", w32.open_file, _EXTENDED + self._drive, _FOLDER_ACCESS,
                        _ANCESTOR_SHARE, w32.OPEN_EXISTING, _FOLDER_FLAGS)
        self._pins.enter_context(drive)
        self._admit_handle(drive, self._drive, directory=True)
        try:
            facts = self._volumes(drive, self._drive)
        except OSError:
            refuse("filesystem-capability-unavailable", "The drive's file system could not be read")
        filesystem, kind = facts["filesystem"], facts["drive_type"]
        if destination is None:
            if kind != w32.DRIVE_FIXED:
                refuse("fixed-local-volume-required", "Sources must be on a fixed local drive")
            if filesystem != "NTFS":
                refuse("ntfs-required", "Sources must be on an NTFS drive")
        else:
            usable = kind in (w32.DRIVE_FIXED, w32.DRIVE_REMOVABLE) and filesystem in ("NTFS", "exFAT", "FAT32")
            volume = ("unsupported" if not usable else "fat32" if filesystem == "FAT32"
                      else "private" if kind == w32.DRIVE_FIXED and filesystem == "NTFS" else "non-private")
            vars(self).update(scoped_base.destination_facts(volume, non_private_destination=destination,
                                                           stable_ids=filesystem == "NTFS"))
        self._filesystem = filesystem
        path, handle = self._drive.rstrip("\\"), drive
        for part in self._dos[3:].split("\\"):
            path += "\\" + part
            handle, info = self._open(path, _FOLDER_ACCESS, _ANCESTOR_SHARE, directory=True)
            self._pins.enter_context(handle)
        self._root_handle = handle
        self._device = info.volume

    def _require_root(self, expected):
        if not isinstance(expected, dict) or set(expected) != scoped_base.RECORD_KEYS:
            refuse("expected-record", "An exact root record is required")
        if not scoped_base.same_identity(self.inspect(""), expected, {"kind", "device", "inode", "ctime_ns", "attributes"}):
            refuse("selected-root-changed", "The selected folder is not the one that was reviewed")

    # Paths, checks and records (I/O thread) -------------------------------------------------------

    def _path(self, relative):
        path = self._dos + ("\\" + relative.replace("/", "\\") if relative else "")
        if w32.utf16_units(path) > MAX_PATH_CHARS:
            refuse("path-too-long", "The full path would be longer than 240 characters")
        return path

    @staticmethod
    def _temp_path(parent_path, partial):
        path = parent_path + "\\" + partial
        if w32.utf16_units(path) > MAX_PATH_CHARS:
            refuse("path-too-long", "The folder leaves no room for the temporary name within 240 characters")
        return path

    def _check_final(self, handle, dos_path):
        try:
            final = w32.final_path(handle)
        except OSError:
            refuse("canonical-path-unavailable", "The opened entry's path could not be read")
        if not final.startswith(_EXTENDED) or final[:8].upper() == _EXTENDED + "UNC\\":
            refuse("unexpected-canonical-path", "The opened entry is not on a local drive")
        if not w32.same_name(final[4:].rstrip("\\"), dos_path.rstrip("\\")):
            refuse("canonical-path-mismatch", "The opened entry has another name than the one requested")

    def _admit_handle(self, handle, dos_path, *, directory=None, mutation=False, allow_read_only=False,
                      read_only_code="readonly-or-system-file"):
        self._check_final(handle, dos_path)
        info = _native("metadata-unavailable", w32.file_information, handle)
        if w32.file_type(handle) != w32.FILE_TYPE_DISK:
            refuse("non-disk-file", "Only files and folders on a disk are admitted")
        attributes = info.attributes
        if attributes & w32.ATTRIBUTE_REPARSE_POINT:
            refuse("reparse-point", "Links, junctions and other reparse points are never followed")
        if attributes & _UNSUPPORTED:
            refuse("offline-encrypted-or-recall-file", "Offline, encrypted and cloud placeholder files are not admitted")
        is_directory = bool(attributes & w32.ATTRIBUTE_DIRECTORY)
        if directory is not None and is_directory != directory:
            refuse("unexpected-type", "The entry is not of the expected kind")
        if not is_directory and info.links != 1:
            refuse("hard-link", "Files with more than one name are not admitted")
        if mutation and attributes & w32.ATTRIBUTE_SYSTEM:
            refuse("readonly-or-system-file", "System files are never changed")
        if mutation and attributes & w32.ATTRIBUTE_READONLY and not allow_read_only:
            refuse(read_only_code, "The file is read-only")
        return info

    def _check_entry(self, dos_path):
        """From the parent's index and before opening (S1), refuse a reparse point, cloud placeholder or offline entry
        and a name stored differently (an 8.3 alias); return the entry's attributes."""
        try:
            found = w32.find_entry(_EXTENDED + dos_path)
        except OSError as error:
            raise _open_refusal(error) from None
        if found is None:
            refuse("missing-entry", "Exact entry is missing")
        name, attributes = found
        if not w32.same_name(name, dos_path.rpartition("\\")[2]):
            refuse("canonical-path-mismatch", "The entry is stored under another name than the one requested")
        if attributes & w32.ATTRIBUTE_REPARSE_POINT:
            refuse("reparse-point", "Links, junctions and other reparse points are never followed")
        if attributes & _UNSUPPORTED_ENTRY:
            refuse("offline-encrypted-or-recall-file", "Offline, encrypted and cloud placeholder files are not admitted")
        return attributes

    def _open(self, dos_path, access, share, *, flags=0, **checks):
        folder = bool(self._check_entry(dos_path) & w32.ATTRIBUTE_DIRECTORY)
        flags |= _FOLDER_FLAGS if folder else _FILE_FLAGS
        try:
            handle = w32.open_file(_EXTENDED + dos_path, access, share, w32.OPEN_EXISTING, flags)
        except OSError as error:
            raise _open_refusal(error) from None
        try:
            info = self._admit_handle(handle, dos_path, **checks)
            if bool(info.attributes & w32.ATTRIBUTE_DIRECTORY) != folder:
                refuse("unexpected-type", "The entry changed between its index lookup and its opening")
            return handle, info
        except BaseException:
            handle.close()
            raise

    def _record(self, relative, info, sha256=None):
        directory = bool(info.attributes & w32.ATTRIBUTE_DIRECTORY)
        mode = 0o040777 if directory else 0o100444 if info.attributes & w32.ATTRIBUTE_READONLY else 0o100666
        return {"relative_path": relative, "kind": "directory" if directory else "file", "device": info.volume,
                "inode": info.index, "mode": mode, "size": 0 if directory else info.size,
                "mtime_ns": _ns(info.write), "ctime_ns": _ns(info.creation), "nlink": info.links,
                "sha256": sha256, "attributes": info.attributes & ~_VOLATILE_ATTRIBUTES}

    def _handle_record(self, handle, relative):
        return self._record(relative, _native("metadata-unavailable", w32.file_information, handle))

    def _ancestors(self, stack, relative):
        """Open and pin each folder between the root and the entry; returns the parent's path and handle."""
        path, handle = self._dos, self._root_handle
        for part in relative.split("/")[:-1]:
            path += "\\" + part
            handle, _info = self._open(path, _FOLDER_ACCESS, _ANCESTOR_SHARE, directory=True)
            stack.enter_context(handle)
        return path, handle

    def _open_entry(self, stack, relative, access, share, *, flags=0, **checks):
        path = self._path(relative)
        self._ancestors(stack, relative)
        handle, info = self._open(path, access, share, flags=flags, **checks)
        stack.enter_context(handle)
        return handle, self._record(relative, info)

    def _security(self, stack, *, directory):
        """SECURITY_ATTRIBUTES for a private new object (kept alive by ``stack``)."""
        try:
            w32.token_user()
        except (OSError, w32.PrivacyRefusal):
            raise CapabilityHold("new-private-creator-unavailable", "The current user could not be read") from None
        try:
            return stack.enter_context(w32.private_security(directory=directory))
        except OSError:
            raise CapabilityHold("new-private-descriptor-unavailable", "The private permissions could not be built") from None

    # Operations -----------------------------------------------------------------------------------

    @contextmanager
    def _operation(self):
        if self._closed:
            refuse("closed-root", "The selected root is closed")
        # The I/O thread checks its own token; a caller acting for another account is refused too.
        _refuse_impersonation()
        stack = ExitStack()
        try:
            yield stack
        finally:
            self._io.release(stack)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._io.release(self._pins)
        finally:
            self._io.stop()

    def inspect(self, relative, *, hash_file=False) -> dict:
        if type(hash_file) is not bool:
            refuse("invalid-option", "hash_file must be boolean")
        relative = scoped_base.relative_path(relative, allow_root=True)
        with self._operation() as stack:
            if relative == "":
                return self._io.call(self._handle_record, self._root_handle, "")
            access, share = (_READ_ACCESS, w32.FILE_SHARE_READ) if hash_file else (w32.FILE_READ_ATTRIBUTES, _ANY_SHARE)
            handle, record = self._io.call(self._open_entry, stack, relative, access, share)
            if hash_file and record["kind"] == "file":
                reader = _File(self, handle, relative)
                sha256 = scoped_base.hash_stream(reader, record["size"])
                if not scoped_base.same_identity(reader.record(), record, self.identity_keys):
                    refuse("read-drift", "File changed during the read")
                record = {**record, "sha256": sha256}
            return record

    def list_directory(self, relative="", *, excluded=None) -> list[dict]:
        relative = scoped_base.relative_path(relative, allow_root=True)
        if excluded is not None and not isinstance(excluded, list):
            refuse("invalid-option", "excluded must be a list or None")
        with self._operation() as stack:
            path, handle, entries = self._io.call(self._enumerate, stack, relative)
            names = [name for name, _attributes, _id in entries]
            keys = {}
            for name in names:
                keys.setdefault(pc_paths.casefold_key(name), []).append(name)
            attributes = {name: (value, file_id) for name, value, file_id in entries}
            rows = []
            for name in _sorted_names(names):
                reason = scoped_base.name_reason(relative, name)
                if reason is None and w32.utf16_units(path) + 1 + w32.utf16_units(name) > MAX_PATH_CHARS:
                    reason = "path-too-long"
                elif reason is None and attributes[name][0] & w32.ATTRIBUTE_REPARSE_POINT:
                    reason = "link"
                elif reason is None and attributes[name][0] & _UNSUPPORTED_ENTRY:
                    reason = "special"
                elif reason is None and len(keys[pc_paths.casefold_key(name)]) > 1:
                    reason = "case-collision"
                if reason is None:
                    child = f"{relative}/{name}" if relative else name
                    row = self._io.call(self._child_record, path, name, child, *attributes[name])
                    reason = row if isinstance(row, str) else None
                    if reason is None:
                        rows.append(row)
                if reason is not None:
                    scoped_base.exclude(excluded, relative, name, reason)
            after = self._io.call(self._entry_names, handle)
            if sorted(after) != sorted(names):
                refuse("directory-membership-changed", "Directory membership changed during listing")
            return rows

    def _enumerate(self, stack, relative):
        if relative:
            path = self._path(relative)
            self._ancestors(stack, relative)
            handle, _info = self._open(path, _FOLDER_ACCESS, _ANCESTOR_SHARE, directory=True)
            stack.enter_context(handle)
        else:
            path, handle = self._dos, self._root_handle
        entries = _native("directory-listing-unavailable", w32.directory_entries, handle, self.max_entries)
        if len(entries) > self.max_entries:
            refuse("entry-cap", "Directory membership exceeds its entry cap")
        return path, handle, entries

    def _entry_names(self, handle):
        return [name for name, _attributes, _id in
                _native("directory-listing-unavailable", w32.directory_entries, handle, self.max_entries)]

    def _child_record(self, parent_path, name, relative, attributes, file_id):
        """A listed child's record, or the reason it is left out; opened for its attributes only."""
        path = parent_path + "\\" + name
        flags = _FOLDER_FLAGS if attributes & w32.ATTRIBUTE_DIRECTORY else _FILE_FLAGS
        try:
            handle = w32.open_file(_EXTENDED + path, w32.FILE_READ_ATTRIBUTES, _ANY_SHARE, w32.OPEN_EXISTING, flags)
        except OSError as error:
            if error.winerror in (w32.ERROR_FILE_NOT_FOUND, w32.ERROR_PATH_NOT_FOUND):
                refuse("directory-membership-changed", "Directory membership changed during listing")
            raise _open_refusal(error) from None
        with handle:
            self._check_final(handle, path)
            info = _native("metadata-unavailable", w32.file_information, handle)
            if self._filesystem == "NTFS" and info.index != file_id:
                refuse("directory-membership-changed", "A listed entry was replaced before it was opened")
            if w32.file_type(handle) != w32.FILE_TYPE_DISK:
                return "special"
            if info.attributes & w32.ATTRIBUTE_REPARSE_POINT:
                return "link"
            if info.attributes & _UNSUPPORTED:
                return "special"
            if not info.attributes & w32.ATTRIBUTE_DIRECTORY and info.links != 1:
                return "hard-link"
            return self._record(relative, info)

    @contextmanager
    def open_read(self, relative, *, expected, uncached=False):
        if type(uncached) is not bool:
            refuse("invalid-option", "uncached must be boolean")
        expected = scoped_base.expected_record(expected, relative, hashed=False)
        flags = w32.FILE_FLAG_NO_BUFFERING if uncached else w32.FILE_FLAG_SEQUENTIAL_SCAN
        with self._operation() as stack:
            # Shared for reading only: no writer, delete or rename can start while the stream is open.
            handle, record = self._io.call(self._open_entry, stack, relative, _READ_ACCESS, w32.FILE_SHARE_READ,
                                           flags=flags, directory=False)
            if not scoped_base.same_identity(record, expected, self.identity_keys):
                refuse("stale-identity", "File no longer matches the reviewed identity")
            reader = _File(self, handle, relative, uncached=uncached)
            try:
                yield reader
                if not scoped_base.same_identity(reader.record(), expected, self.identity_keys):
                    refuse("read-drift", "File changed while it was open")
            finally:
                reader.close()

    @contextmanager
    def open_new(self, relative, *, private=True, original_mode=None, partial=None):
        bits = scoped_base.new_file_mode(private, original_mode)
        relative = scoped_base.relative_path(relative)
        partial = scoped_base.partial_name(partial)
        with self._operation() as stack:
            handle, parent, private = self._io.call(self._create_temp, stack, relative, bits is None, partial)
            out = _NewFile(self, handle, relative, parent, private)
            try:
                yield out
            finally:
                try:
                    if not out.committed:
                        self._io.call(_native, "delete-refused", w32.delete_on_close, handle)
                finally:
                    out.close()

    def _create_temp(self, stack, relative, private, partial):
        target = self._path(relative)
        parent_path, _ancestor = self._ancestors(stack, relative)
        if w32.find_entry(_EXTENDED + target) is not None:
            refuse("destination-exists", "Destination or case-equivalent entry already exists")
        # The parent is opened again with write access only so commit() can flush its directory entry.
        parent, _info = self._open(parent_path, _FOLDER_ACCESS | w32.FILE_ADD_FILE | w32.FILE_ADD_SUBDIRECTORY,
                                   _ANCESTOR_SHARE, directory=True)
        stack.enter_context(parent)
        temp_path = self._temp_path(parent_path, partial)
        private = private and self.private
        security = self._security(stack, directory=False) if private else None
        try:
            handle = w32.open_file(_EXTENDED + temp_path, w32.GENERIC_READ | w32.GENERIC_WRITE | w32.DELETE, 0,
                                   w32.CREATE_NEW, w32.FILE_FLAG_OPEN_REPARSE_POINT | w32.FILE_ATTRIBUTE_NORMAL,
                                   security)
        except OSError as error:
            if error.winerror == w32.ERROR_FILE_EXISTS:
                refuse("destination-exists", "The temporary name is already in use")
            refuse("create-new-refused", "The temporary file could not be created exclusively")
        stack.enter_context(handle)
        try:
            self._admit_handle(handle, temp_path, directory=False)
            if private:
                self._check_new_privacy(handle)
        except BaseException:
            # A temporary name that cannot be marked stays for reconciliation; the refusal is what counts.
            with suppress(OSError):
                w32.delete_on_close(handle)
            raise
        return handle, parent, private

    def _check_new_privacy(self, handle):
        """The private DACL is read back before the first byte and again at commit."""
        try:
            w32.validate_private(handle, directory=False, exact=True)
        except w32.PrivacyRefusal:
            refuse("new-private-file-security-unresolved", "The new file is not private")

    def _sync(self, handle, parent):
        try:
            w32.flush(handle)
            w32.flush(parent)
        except OSError:
            return False
        return True

    def _rename(self, handle, relative, before, parent, code):
        """Rename an open file to ``relative`` in this root without replacing anything; check its final path and identity."""
        target = self._path(relative)
        # The pinned target folder must still be a folder (an empty one could have been made a junction). This narrows
        # the window; a switch after this check is caught only after the rename, by _check_final.
        if _native("metadata-unavailable", w32.file_information, parent).attributes & w32.ATTRIBUTE_REPARSE_POINT:
            refuse("reparse-point", "The target folder became a link")
        try:
            w32.rename_noreplace(handle, _EXTENDED + target)
        except OSError as error:
            if error.winerror in (w32.ERROR_ALREADY_EXISTS, w32.ERROR_FILE_EXISTS):
                refuse("destination-exists", "Destination or case-equivalent entry already exists")
            refuse("rename-refused-no-overwrite", f"The file could not be renamed (Windows error {error.winerror})")
        try:
            self._check_final(handle, target)
            after = self._handle_record(handle, relative)
        except ScopedFSError:
            refuse(code, "The renamed file could not be verified")
        if not scoped_base.same_identity(after, before, _RENAMED_KEYS if self._filesystem == "NTFS" else {"kind", "size"}):
            refuse(code, "The renamed file is not the file that was checked")
        return after

    def mkdir(self, relative) -> dict:
        relative = scoped_base.relative_path(relative)
        with self._operation() as stack:
            return self._io.call(self._mkdir, stack, relative)

    def _mkdir(self, stack, relative):
        path = self._path(relative)
        self._ancestors(stack, relative)
        if w32.find_entry(_EXTENDED + path) is not None:
            refuse("destination-exists", "Destination or case-equivalent entry already exists")
        security = self._security(stack, directory=True) if self.private else None
        try:
            w32.create_directory(_EXTENDED + path, security)
        except OSError as error:
            if error.winerror in (w32.ERROR_ALREADY_EXISTS, w32.ERROR_FILE_EXISTS):
                refuse("destination-exists", "Destination or case-equivalent entry already exists")
            refuse("create-directory-refused", f"The folder could not be created (Windows error {error.winerror})")
        handle, info = self._open(path, _FOLDER_ACCESS | w32.READ_CONTROL | w32.DELETE, _ANCESTOR_SHARE, directory=True)
        with handle:
            if self.private:
                try:
                    w32.validate_private(handle, directory=True, exact=True)
                except w32.PrivacyRefusal:
                    with suppress(OSError):
                        w32.delete_on_close(handle)
                    refuse("new-private-directory-security-unresolved", "The new folder is not private")
            return self._record(relative, info)

    def move_to(self, relative, *, destination, destination_relative, expected) -> dict:
        expected = scoped_base.expected_record(expected, relative)
        destination_relative = scoped_base.relative_path(destination_relative)
        if not isinstance(destination, WindowsRoot) or destination._closed:
            refuse("destination-scope-required", "An open destination root is required")
        if destination._device != self._device or not w32.same_name(destination._drive, self._drive):
            refuse("same-volume-required", "Files are only moved within one drive; nothing is copied")
        target = destination._path(destination_relative)
        if w32.same_name(self._path(relative), target):
            refuse("same-path", "Source and destination are the same entry")
        with self._operation() as stack:
            handle, record = self._io.call(self._open_entry, stack, relative, _READ_ACCESS | w32.DELETE,
                                           w32.FILE_SHARE_READ, directory=False, mutation=True)
            if not scoped_base.same_identity(record, expected, self.identity_keys):
                refuse("stale-identity", "File no longer matches the reviewed identity")
            if scoped_base.hash_stream(_File(self, handle, relative), expected["size"]) != expected["sha256"]:
                refuse("stale-content", "Content hash no longer matches the reviewed file")
            parent = self._io.call(destination._prepare_target, stack, destination_relative)
            before = self._io.call(self._handle_record, handle, relative)
            if not scoped_base.same_identity(before, expected, self.identity_keys):
                refuse("stale-identity", "File changed immediately before the move")
            return {**self._io.call(destination._rename, handle, destination_relative, before, parent,
                                    "post-move-verification-unresolved"), "sha256": expected["sha256"]}

    def _prepare_target(self, stack, relative):
        target = self._path(relative)
        parent = self._ancestors(stack, relative)[1]
        if w32.find_entry(_EXTENDED + target) is not None:
            refuse("destination-exists", "Destination or case-equivalent entry already exists")
        return parent

    def remove_file(self, relative, *, expected, sha256=None, allow_read_only=False) -> dict:
        if type(allow_read_only) is not bool:
            refuse("invalid-option", "allow_read_only must be boolean")
        expected = scoped_base.expected_record(expected, relative)
        target = expected["sha256"] if sha256 is None else sha256
        if not isinstance(target, str) or not pc_records.SHA256.fullmatch(target):
            refuse("expected-record", "A SHA-256 is required")
        if scoped_base.read_only(expected) and not allow_read_only:
            refuse("read-only", "The approved plan does not show this file as read-only")
        if scoped_base.read_only(expected) and self._filesystem != "NTFS":
            refuse("read-only-removal-unsupported", "This drive cannot delete a read-only file without changing it")
        with self._operation() as stack:
            # No sharing: nothing else can open, change, rename or delete the file between hash and delete.
            handle, record = self._io.call(self._open_entry, stack, relative, _READ_ACCESS | w32.DELETE, 0,
                                           directory=False, mutation=True,
                                           allow_read_only=allow_read_only and self._filesystem == "NTFS",
                                           read_only_code="read-only")
            if not scoped_base.same_identity(record, expected, self.identity_keys):
                refuse("stale-identity", "File no longer matches the reviewed identity")
            observed = scoped_base.hash_stream(_File(self, handle, relative), expected["size"])
            if observed != target:
                refuse("stale-content", "File content does not match the archived entry")
            if not scoped_base.same_identity(self._io.call(self._handle_record, handle, relative), expected, self.identity_keys):
                refuse("stale-identity", "File changed immediately before removal")
            self._io.call(self._dispose, handle, allow_read_only)
        if self._io.call(w32.find_entry, _EXTENDED + self._path(relative)) is not None:
            refuse("post-purge-verification-unresolved", "The file is still present after removal")
        return {**expected, "sha256": observed}

    def _dispose(self, handle, allow_read_only):
        try:
            if self._filesystem == "NTFS":
                # POSIX semantics: the name goes when this handle closes, even if others hold attribute handles (S2).
                flags = w32.DISPOSITION_DELETE | w32.DISPOSITION_POSIX_SEMANTICS
                w32.set_disposition(handle, flags | (w32.DISPOSITION_IGNORE_READONLY if allow_read_only else 0))
            else:
                w32.delete_on_close(handle)
        except OSError:
            refuse("delete-refused", "The file could not be deleted")

    def free_bytes(self) -> int:
        if self._closed:
            refuse("closed-root", "The selected root is closed")
        return self._io.call(_native, "free-space-unavailable", w32.free_bytes, self._drive)

    def admit_new(self, relative, expected_bytes):
        super().admit_new(relative, expected_bytes)
        self._temp_path(self._path(relative).rpartition("\\")[0], scoped_base.partial_name())


def admit_destination(root, *, non_private_destination=False, volumes=None, max_entries=MAX_ENTRIES) -> WindowsRoot:
    """Admit a backup destination (separate from source admission, plan RR2-4).

    A fixed NTFS drive is admitted as private. A removable drive, or an exFAT or FAT32 drive, cannot keep
    a backup private and is admitted only with ``non_private_destination=True`` (the owner's typed
    acknowledgment of scoped_base.NON_PRIVATE_NOTE). Files on exFAT and FAT32 are bound by size and SHA-256 because
    their ids are not stable, and FAT32 refuses files of 4 GiB or more (admit_new). Other drives are refused.
    """
    if type(non_private_destination) is not bool:
        refuse("invalid-option", "non_private_destination must be boolean")
    return WindowsRoot(root, max_entries=max_entries, volumes=volumes, _destination=non_private_destination)


_LEGACY_REASONS = {"link": "reparse-point", "special": "offline-encrypted-or-recall-file", "hard-link": "hard-link",
                   "not-portable": "invalid-path-component", "path-too-long": "path-too-long", "case-collision": "case-collision"}


class ScopedRoot:
    """The selected-root calls scoped_fs and storage_ops make today, served by WindowsRoot until storage streams
    through RootBase; in-memory reads and writes keep their 64 MiB bound."""

    def __init__(self, root, *, quiet_workspace, max_entries=MAX_ENTRIES):
        if quiet_workspace is not True:
            raise CapabilityHold("quiet-workspace-required", "An owner-controlled quiet workspace must be confirmed")
        self._root = WindowsRoot(root, max_entries=max_entries)
        self.root, self.max_entries = Path(self._root._dos), max_entries

    def __enter__(self):
        if self._root._closed:
            refuse("closed-root", "The selected root is closed")
        return self

    def __exit__(self, *unused):
        self.close()

    def close(self):
        self._root.close()

    def inspect(self, relative, *, hash_file=False, max_bytes=LEGACY_MAX_BYTES):
        scoped_base.cap(max_bytes, MAX_STREAM_BYTES, "max_bytes")
        record = self._root.inspect(relative)
        if hash_file and record["kind"] == "file":
            if record["size"] > max_bytes:
                refuse("file-byte-cap", "File exceeds its explicit byte cap")
            record = self._root.inspect(relative, hash_file=True)
        return record

    def list_directory(self, relative="", *, excluded=None):
        """With ``excluded`` (a list), as WindowsRoot.list_directory; without it the first left-out entry refuses."""
        if excluded is not None:
            return self._root.list_directory(relative, excluded=excluded)
        left_out = []
        rows = self._root.list_directory(relative, excluded=left_out)
        if left_out:
            refuse(_LEGACY_REASONS.get(left_out[0]["reason"], "listing-refused"),
                   "The folder holds an entry that cannot be admitted")
        return rows

    def read_bytes(self, relative, *, expected, max_bytes):
        scoped_base.cap(max_bytes, LEGACY_MAX_BYTES, "max_bytes for an in-memory read")
        expected = scoped_base.expected_record(expected, relative)
        if expected["size"] > max_bytes:
            refuse("file-byte-cap", "File exceeds its explicit byte cap")
        chunks = []
        self._root.stream_to(relative, expected=expected, writer=chunks.append)
        return b"".join(chunks)

    def create_file(self, relative, *, data, max_bytes):
        scoped_base.cap(max_bytes, LEGACY_MAX_BYTES, "max_bytes for file creation")
        if type(data) is not bytes or len(data) > max_bytes:
            refuse("file-byte-cap", "Bounded bytes are required for exclusive file creation")
        with self._root.open_new(relative) as out:
            out.write(data)
            record = out.commit()
        return {key: value for key, value in record.items() if key != "durable"}

    def move_to(self, relative, *, destination, destination_relative, expected):
        if not isinstance(destination, ScopedRoot):
            refuse("destination-scope-required", "An open destination root is required")
        return self._root.move_to(relative, destination=destination._root, destination_relative=destination_relative, expected=expected)

    def remove_file(self, relative, *, expected):
        self._root.remove_file(relative, expected=expected)
