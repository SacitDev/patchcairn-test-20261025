"""Bounded selected-root filesystem primitives; Python 3.12+, standard library.

This is a cooperative operating boundary, not an OS sandbox. The caller must
control a quiet workspace, authenticate actual owner authority, and journal
partial outcomes. Same-user/privileged concurrent mutation is out of scope.
"""
from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_STREAM_BYTES = 1024 ** 4
MAX_ENTRIES = 20000
MAX_DEPTH = 64
_LINUX_RENAME_NOREPLACE = 1
# Apple XNU bsd/sys/stdio.h: RENAME_EXCL; renameatx_np is macOS 10.12+.
# https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stdio.h
_DARWIN_RENAME_EXCL = 0x00000004
_RECORD_KEYS = {"relative_path", "kind", "device", "inode", "mode", "size",
                "mtime_ns", "ctime_ns", "nlink", "sha256", "attributes"}


class ScopedFSError(ValueError):
    """Categorical refusal; no automatic retry or weaker fallback is implied."""
    def __init__(self, code, message=None):
        self.code = code
        super().__init__(code if message is None else f"{code}: {message}")


class CapabilityHold(ScopedFSError):
    """The current platform cannot provide a required safe native primitive."""


def _refuse(code, message):
    raise ScopedFSError(code, message)


def _cap(value, maximum, label):
    if type(value) is not int or not 0 < value <= maximum:
        _refuse("invalid-cap", f"{label} must be a positive integer within its documented cap")
    return value


def relative_path(value, *, allow_root=False):
    """Validate a literal portable relative name; never resolve links or '..'."""
    if allow_root and value == "":
        return value
    if (not isinstance(value, str) or not value or len(value) > 4096
            or "\\" in value or ":" in value or value.startswith("/")):
        _refuse("relative-path", "A literal slash-separated relative path is required")
    parts = value.split("/")
    if len(parts) > MAX_DEPTH:
        _refuse("depth-cap", "Selected path exceeds the depth cap")
    for part in parts:
        if (not part or part in {".", ".."} or part[-1] in {".", " "}
                or len(part.encode("utf-8", errors="surrogatepass")) > 255
                or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in part)
                or re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)):
            _refuse("relative-path", "Ambiguous, reserved or unsafe path component")
    return value


def _posix_capable():
    needed = (os.open, os.stat, os.unlink, os.mkdir)
    return (os.name == "posix" and sys.version_info >= (3, 12)
            and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
            and all(fn in os.supports_dir_fd for fn in needed)
            and os.stat in os.supports_follow_symlinks and os.listdir in os.supports_fd)


def _rename_function():
    if os.name != "posix":
        return None
    try:
        if sys.platform.startswith("linux"):
            function = ctypes.CDLL(None, use_errno=True).renameat2
        elif sys.platform == "darwin":
            # Use the native system library, never a caller-selected library or
            # the non-descriptor-relative renamex_np variant.
            function = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).renameatx_np
        else:
            return None
        function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        function.restype = ctypes.c_int
        return function
    except (AttributeError, OSError):
        return None


def _call_rename(function, source_fd, source_name, destination_fd, destination_name):
    """Call only the current native platform's descriptor-relative exclusive rename."""
    if os.name != "posix" or function is None:
        raise CapabilityHold("no-replace-unavailable", "Native atomic no-overwrite rename is unavailable")
    if sys.platform.startswith("linux"):
        flags = _LINUX_RENAME_NOREPLACE
    elif sys.platform == "darwin":
        flags = _DARWIN_RENAME_EXCL
    else:
        raise CapabilityHold("no-replace-unavailable", "Native atomic no-overwrite rename is unavailable")
    result = function(source_fd, os.fsencode(source_name), destination_fd, os.fsencode(destination_name), flags)
    if result != 0:
        error = ctypes.get_errno()
        unsupported = {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EXDEV,
                       getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}
        if error in unsupported:
            raise CapabilityHold("no-replace-unavailable", "Filesystem refused native no-overwrite rename")
        raise ScopedFSError("rename-refused", "Native rename failed; reconcile actual source and destination")


def capabilities():
    """Actual adapter availability, without collecting selected-root metadata."""
    if os.name == "nt":
        try:
            import windows_scoped
            return windows_scoped.capabilities()
        except ImportError:
            return {"available": False, "platform": "windows", "adapter": None,
                    "reason": "Verified Windows native selected-root adapter unavailable",
                    "pinning": False, "move_noreplace": False, "remove_file": False,
                    "create_file": False, "mkdir": False, "read_bytes": False,
                    "stream_to": False, "stream_max_bytes": 0}
    available = _posix_capable()
    return {"available": available, "platform": sys.platform,
            "adapter": "posix-dirfd-nofollow-v1" if available else None,
            "reason": None if available else "Python 3.12+ native no-follow/dir-fd support required",
            "pinning": available, "move_noreplace": available and _rename_function() is not None,
            "remove_file": available, "create_file": available, "mkdir": available,
            "read_bytes": available, "stream_to": available, "stream_max_bytes": MAX_STREAM_BYTES if available else 0,
            "quiet_workspace_required": True}


def _ordinary(info, *, directory=None):
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        _refuse("link", "Symlink or reparse entry refused")
    is_directory = stat.S_ISDIR(info.st_mode)
    if not is_directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        _refuse("file-type", "Only single-link ordinary files and ordinary directories are admitted")
    if directory is not None and is_directory != directory:
        _refuse("file-type", "Unexpected entry type")
    if info.st_ino <= 0 or info.st_dev < 0 or info.st_size < 0:
        _refuse("unknown-identity", "Stable native identity is unavailable")
    return info


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink,
            getattr(info, "st_file_attributes", 0))


def _record(relative, info, sha256=None):
    _ordinary(info)
    return {"relative_path": relative, "kind": "directory" if stat.S_ISDIR(info.st_mode) else "file",
            "device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
            "nlink": info.st_nlink, "sha256": sha256, "attributes": getattr(info, "st_file_attributes", 0)}


def _expected(value, relative):
    if (not isinstance(value, dict) or set(value) != _RECORD_KEYS or value.get("kind") != "file"
            or value.get("relative_path") != relative or not isinstance(value.get("sha256"), str)
            or not re.fullmatch("[a-f0-9]{64}", value["sha256"])):
        _refuse("expected-record", "An exact hashed ordinary-file record for this relative path is required")
    if (any(type(value[key]) is not int or value[key] < 0 for key in
            ("device", "inode", "mode", "size", "mtime_ns", "ctime_ns", "nlink", "attributes"))
            or value["inode"] == 0 or value["nlink"] != 1 or value["size"] > MAX_STREAM_BYTES):
        _refuse("expected-record", "Expected native file identity is malformed or unbounded")
    return value


class ScopedRoot:
    """Pinned ordinary ancestry for one explicitly selected absolute directory.

    Public mutation calls are low-level same-process authority. The workflow
    coordinator supplies exact plan/action approval and durable outcome records.
    """
    def __new__(cls, root, *, quiet_workspace, max_entries=MAX_ENTRIES):
        if cls is ScopedRoot and os.name == "nt":
            if quiet_workspace is not True:
                _refuse("workspace-not-quiet", "An owner-controlled quiet workspace must be confirmed")
            try:
                import windows_scoped
            except ImportError as exc:
                raise CapabilityHold("native-unavailable", "Verified Windows native adapter unavailable") from exc
            if not windows_scoped.capabilities().get("available"):
                raise CapabilityHold("native-unavailable", "Verified Windows native adapter unavailable")
            return windows_scoped.ScopedRoot(root, quiet_workspace=quiet_workspace, max_entries=max_entries)
        return super().__new__(cls)

    def __init__(self, root, *, quiet_workspace, max_entries=MAX_ENTRIES):
        self._fds = []
        self._anchors = []
        self._closed = False
        self.max_entries = _cap(max_entries, MAX_ENTRIES, "max_entries")
        if quiet_workspace is not True:
            _refuse("workspace-not-quiet", "An owner-controlled quiet workspace must be confirmed")
        if not _posix_capable():
            raise CapabilityHold("native-unavailable", "Native POSIX no-follow/dir-fd support required")
        raw = os.fspath(root)
        if (not isinstance(raw, str) or not raw.startswith("/") or raw.startswith("//")
                or raw == "/" or raw.endswith("/") or "\x00" in raw
                or any(p in {"", ".", ".."} for p in raw.split("/")[1:])):
            _refuse("root-path", "An exact absolute non-filesystem-root directory is required")
        self.root = Path(raw)
        try:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._fds.append(fd)
            for part in raw.split("/")[1:]:
                before = _ordinary(os.stat(part, dir_fd=fd, follow_symlinks=False), directory=True)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                self._fds.append(child)
                after = _ordinary(os.fstat(child), directory=True)
                if _identity(before) != _identity(after):
                    _refuse("ancestor-drift", "Directory identity changed during admission")
                self._anchors.append((fd, part, child, (after.st_dev, after.st_ino, after.st_mode)))
                fd = child
            self._fd = fd
            self._device = os.fstat(fd).st_dev
            self._validate_anchor()
        except OSError as exc:
            self.close()
            raise ScopedFSError("admission", "Selected root is missing, inaccessible or not ordinary") from exc
        except Exception:
            self.close()
            raise

    def __enter__(self):
        self._validate_anchor()
        return self

    def __exit__(self, *unused):
        self.close()

    def close(self):
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds = []
        self._closed = True

    def _validate_anchor(self):
        if self._closed:
            _refuse("closed-root", "Selected-root handles have been closed")
        try:
            for parent, name, child, identity in self._anchors:
                actual = _ordinary(os.stat(name, dir_fd=parent, follow_symlinks=False), directory=True)
                pinned = _ordinary(os.fstat(child), directory=True)
                if any((s.st_dev, s.st_ino, s.st_mode) != identity for s in (actual, pinned)):
                    _refuse("ancestor-drift", "Selected-root ancestry changed")
        except OSError as exc:
            raise ScopedFSError("ancestor-drift", "Selected-root ancestry is no longer accessible") from exc

    def _names(self, fd):
        names = os.listdir(fd)
        if len(names) > self.max_entries:
            _refuse("entry-cap", "Directory membership exceeds its entry cap")
        folded = set()
        for name in names:
            relative_path(name)
            if name.casefold() in folded:
                _refuse("case-collision", "Directory contains case-ambiguous entry names")
            folded.add(name.casefold())
        return sorted(names)

    @contextlib.contextmanager
    def _parent(self, relative):
        relative_path(relative)
        self._validate_anchor()
        fd = os.dup(self._fd)
        held = [fd]
        parts = relative.split("/")
        try:
            for part in parts[:-1]:
                if part not in self._names(fd):
                    _refuse("missing-entry", "Exact parent name is missing")
                before = _ordinary(os.stat(part, dir_fd=fd, follow_symlinks=False), directory=True)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                held.append(child)
                after = _ordinary(os.fstat(child), directory=True)
                if _identity(before) != _identity(after) or after.st_dev != self._device:
                    _refuse("parent-drift", "Parent identity changed or crossed a filesystem boundary")
                fd = child
            yield fd, parts[-1]
            self._validate_anchor()
        except OSError as exc:
            raise ScopedFSError("filesystem-access", "Scoped entry is missing, inaccessible or changed") from exc
        finally:
            for item in reversed(held):
                os.close(item)

    def _stat(self, fd, name, *, checked_names=None):
        if name not in (self._names(fd) if checked_names is None else checked_names):
            _refuse("missing-entry", "Exact selected entry name is missing")
        info = _ordinary(os.stat(name, dir_fd=fd, follow_symlinks=False))
        if info.st_dev != self._device:
            _refuse("filesystem-boundary", "Nested filesystem boundary refused")
        return info

    def inspect(self, relative, *, hash_file=False, max_bytes=DEFAULT_MAX_FILE_BYTES):
        relative_path(relative, allow_root=True)
        if type(hash_file) is not bool:
            _refuse("invalid-option", "hash_file must be boolean")
        if relative == "":
            self._validate_anchor()
            return _record("", os.fstat(self._fd))
        with self._parent(relative) as (fd, name):
            info = self._stat(fd, name)
            if hash_file and stat.S_ISREG(info.st_mode):
                return self._read(fd, name, relative, expected=None, writer=lambda _: None, max_bytes=max_bytes)
            return _record(relative, info)

    def list_directory(self, relative=""):
        relative_path(relative, allow_root=True)
        self._validate_anchor()
        with contextlib.ExitStack() as stack:
            fd = self._fd
            if relative:
                parent, name = stack.enter_context(self._parent(relative))
                before = self._stat(parent, name)
                _ordinary(before, directory=True)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                stack.callback(os.close, fd)
                if _identity(before) != _identity(os.fstat(fd)):
                    _refuse("directory-drift", "Directory changed during open")
            before = _identity(os.fstat(fd))
            names = self._names(fd)
            checked_names = set(names)
            result = [_record(f"{relative}/{name}" if relative else name,
                              self._stat(fd, name, checked_names=checked_names)) for name in names]
            if before != _identity(os.fstat(fd)) or names != self._names(fd):
                _refuse("membership-drift", "Directory membership changed during listing")
            self._validate_anchor()
            return result

    def snapshot(self, *, hash_files=False, max_file_bytes=DEFAULT_MAX_FILE_BYTES,
                 max_total_bytes=DEFAULT_MAX_TOTAL_BYTES):
        _cap(max_file_bytes, MAX_STREAM_BYTES, "max_file_bytes")
        _cap(max_total_bytes, MAX_STREAM_BYTES, "max_total_bytes")
        if type(hash_files) is not bool:
            _refuse("invalid-option", "hash_files must be boolean")
        records = [self.inspect("")]
        total = 0
        pending = [""]
        directories = []
        while pending:
            relative = pending.pop()
            children = self.list_directory(relative)
            directories.append((relative, [r["relative_path"] for r in children]))
            for row in children:
                if len(records) >= self.max_entries:
                    _refuse("entry-cap", "Snapshot exceeds its total entry cap")
                relative_path(row["relative_path"])
                if row["kind"] == "directory":
                    pending.append(row["relative_path"])
                elif hash_files:
                    total += row["size"]
                    if total > max_total_bytes:
                        _refuse("total-byte-cap", "Snapshot hashing exceeds its total byte cap")
                    row = self.inspect(row["relative_path"], hash_file=True, max_bytes=max_file_bytes)
                records.append(row)
        by_path = {row["relative_path"]: row for row in records}
        root = self.inspect("")
        if root != by_path[""]:
            _refuse("snapshot-drift", "Root changed during snapshot")
        for relative, names in directories:
            current = self.list_directory(relative)
            if names != [r["relative_path"] for r in current]:
                _refuse("snapshot-drift", "Snapshot membership changed")
            if any(any(row[key] != by_path[row["relative_path"]][key] for key in _RECORD_KEYS - {"sha256"})
                   for row in current):
                _refuse("snapshot-drift", "Entry changed during snapshot")
        return sorted(records, key=lambda row: row["relative_path"])

    def _read(self, parent, name, relative, *, expected, writer, max_bytes, chunk_size=65536):
        _cap(max_bytes, MAX_STREAM_BYTES, "max_bytes")
        _cap(chunk_size, 1024 * 1024, "chunk_size")
        if not callable(writer):
            _refuse("writer", "A trusted byte-consumer callable is required")
        before = self._stat(parent, name)
        _ordinary(before, directory=False)
        if before.st_size > max_bytes:
            _refuse("file-byte-cap", "File exceeds its explicit byte cap")
        if expected is not None:
            _expected(expected, relative)
            if _record(relative, before, expected["sha256"]) != expected:
                _refuse("stale-identity", "File no longer matches the reviewed identity")
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            opened = _ordinary(os.fstat(handle), directory=False)
            if _identity(opened) != _identity(before):
                _refuse("read-drift", "File changed before open")
            digest = hashlib.sha256()
            count = 0
            while True:
                # Read one extra byte when a file grows exactly to its cap.
                data = os.read(handle, min(chunk_size, max_bytes - count + 1))
                if not data:
                    break
                count += len(data)
                if count > max_bytes or count > opened.st_size:
                    _refuse("read-growth", "File grew while being read")
                digest.update(data)
                accepted = writer(data)
                if accepted is not None and accepted != len(data):
                    _refuse("short-write", "Consumer did not accept the complete chunk")
            after = _ordinary(os.fstat(handle), directory=False)
            named = self._stat(parent, name)
            if count != opened.st_size or _identity(after) != _identity(opened) or _identity(named) != _identity(opened):
                _refuse("read-drift", "File changed during the bounded read")
            row = _record(relative, after, digest.hexdigest())
            if expected is not None and row != expected:
                _refuse("stale-content", "Content hash no longer matches the reviewed file")
            self._validate_anchor()
            return row
        finally:
            os.close(handle)

    def stream_to(self, relative, *, expected, writer, max_bytes, chunk_size=65536):
        _expected(expected, relative)
        with self._parent(relative) as (fd, name):
            return self._read(fd, name, relative, expected=expected, writer=writer,
                              max_bytes=max_bytes, chunk_size=chunk_size)

    def read_bytes(self, relative, *, expected, max_bytes):
        _cap(max_bytes, DEFAULT_MAX_FILE_BYTES, "max_bytes for in-memory read")
        chunks = []
        self.stream_to(relative, expected=expected, writer=lambda data: chunks.append(data), max_bytes=max_bytes)
        return b"".join(chunks)

    def _absent(self, fd, name):
        if name.casefold() in {entry.casefold() for entry in self._names(fd)}:
            _refuse("destination-exists", "Destination or case-equivalent entry already exists")
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        _refuse("destination-exists", "Destination already exists")

    def mkdir(self, relative):
        with self._parent(relative) as (fd, name):
            self._absent(fd, name)
            os.mkdir(name, mode=0o700, dir_fd=fd)
            return _record(relative, self._stat(fd, name))

    def create_file(self, relative, *, data, max_bytes):
        _cap(max_bytes, DEFAULT_MAX_FILE_BYTES, "max_bytes for file creation")
        if not isinstance(data, bytes) or len(data) > max_bytes:
            _refuse("file-byte-cap", "Bounded bytes are required for exclusive file creation")
        with self._parent(relative) as (fd, name):
            self._absent(fd, name)
            handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600, dir_fd=fd)
            try:
                offset = 0
                while offset < len(data):
                    written = os.write(handle, data[offset:offset + 65536])
                    if written <= 0:
                        _refuse("short-write", "Exclusive file creation stopped before completion")
                    offset += written
                os.fsync(handle)
            finally:
                os.close(handle)
            return self._read(fd, name, relative, expected=None, writer=lambda _: None, max_bytes=max_bytes)

    def move_to(self, relative, *, destination, destination_relative, expected):
        _expected(expected, relative)
        if not isinstance(destination, ScopedRoot):
            _refuse("destination-root", "A native pinned destination ScopedRoot is required")
        if self._device != destination._device:
            _refuse("cross-filesystem", "Cross-filesystem copy/delete fallback is forbidden")
        rename = _rename_function()
        if rename is None:
            raise CapabilityHold("no-replace-unavailable", "Native atomic no-overwrite rename is unavailable")
        with self._parent(relative) as (src_fd, src_name), destination._parent(destination_relative) as (dst_fd, dst_name):
            destination._absent(dst_fd, dst_name)
            self._read(src_fd, src_name, relative, expected=expected, writer=lambda _: None,
                       max_bytes=max(expected["size"], 1))
            # Final name check still depends on the documented quiet workspace.
            if _record(relative, self._stat(src_fd, src_name), expected["sha256"]) != expected:
                _refuse("stale-identity", "Source changed immediately before rename")
            _call_rename(rename, src_fd, src_name, dst_fd, dst_name)
            actual = destination._read(dst_fd, dst_name, destination_relative, expected=None,
                                       writer=lambda _: None, max_bytes=max(expected["size"], 1))
            if any(actual[key] != expected[key] for key in {"device", "inode", "mode", "size", "mtime_ns", "nlink", "sha256", "attributes"}):
                _refuse("move-verification", "Rename occurred but its postcondition is unresolved")
            return actual

    def remove_file(self, relative, *, expected):
        _expected(expected, relative)
        with self._parent(relative) as (fd, name):
            self._read(fd, name, relative, expected=expected, writer=lambda _: None,
                       max_bytes=max(expected["size"], 1))
            if _record(relative, self._stat(fd, name), expected["sha256"]) != expected:
                _refuse("stale-identity", "File changed immediately before unlink")
            os.unlink(name, dir_fd=fd)
            if name in self._names(fd):
                _refuse("remove-verification", "Unlink occurred but destination membership is unresolved")
