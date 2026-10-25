"""Selected-root storage on POSIX (PosixRoot, scoped_base.RootBase over descriptors) and the shared storage entry
points, which delegate to windows_scoped on Windows; ScopedRoot serves the calls storage_ops and workflow_service make
today (layer L1; Python 3.12+). A cooperative boundary for a quiet workspace, not a sandbox."""
from __future__ import annotations

import contextlib
import ctypes
import errno
import io
import os
from pathlib import Path
import re
import stat
import sys
import uuid

import darwin_privacy
import linux_privacy
import pc_paths
import pc_records
import scoped_base
# The one error hierarchy of the selected-root backends, re-exported for existing callers.
from scoped_base import CapabilityHold, ScopedFSError, relative_path
from scoped_base import cap as _cap, expected_record as _expected, refuse as _refuse, same_identity as _same

try:
    import fcntl
except ImportError:  # Windows: everything below that needs fcntl runs only on Linux or macOS
    fcntl = None

ADAPTER = "posix-dirfd-nofollow"
MAX_ENTRIES = scoped_base.MAX_ENTRIES
# ScopedRoot's bound on in-memory reads and writes, which storage_ops relies on until it streams through RootBase.
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
_LINUX_RENAME_NOREPLACE = 1
# Apple XNU bsd/sys/stdio.h: RENAME_EXCL; renameatx_np is macOS 10.12+.
# https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stdio.h
_DARWIN_RENAME_EXCL = 0x00000004
# Apple XNU bsd/sys/fcntl.h: F_NOCACHE stops a descriptor's reads and writes from filling the cache; F_FULLFSYNC also
# flushes the drive's own cache, which fsync() does not do on macOS.
_F_NOCACHE, _F_FULLFSYNC = 48, 51
# Linux UAPI linux/fs.h: FS_IOC_GETFLAGS is _IOR('f', 1, long), this value in the generic ioctl encoding of 64-bit
# x86 and Arm. It is sent only there: other architectures encode direction and size differently.
_FS_IOC_GETFLAGS = 0x80086601
_GENERIC_IOCTL_MACHINES = frozenset({"x86_64", "aarch64", "arm64"})
_FS_IMMUTABLE_FL, _FS_APPEND_FL = 0x10, 0x20
# Apple bsd/sys/stat.h st_flags: immutable and append-only (user and system), and SF_DATALESS, a cloud placeholder
# whose content is downloaded when it is opened (Python 3.13 names it stat.SF_DATALESS).
_DARWIN_LOCKED = stat.UF_IMMUTABLE | stat.UF_APPEND | stat.SF_IMMUTABLE | stat.SF_APPEND
_SF_DATALESS = 0x40000000
# Compared across a rename: Linux and macOS give the renamed file a new change time.
_RENAMED_KEYS = scoped_base.IDENTITY_KEYS - {"relative_path", "ctime_ns"}
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
_FILE = os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
_NEW = os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW
_FULL = frozenset({errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)})
_TCC_MESSAGE = "permission refused (possibly macOS privacy protection or the app sandbox)"
# Names of originals moved into a removal folder (remove_original), apart from the temporary files of open_new.
REMOVAL_NAME = re.compile(r"\.removal-[0-9a-f]{32}\Z")
_INCOMPLETE = ("removal-incomplete", "The original was moved into the removal folder and not deleted; "
               "reconcile_removal finishes or reports it")


def _collisions(names):
    """Names that share a pc_paths.casefold_key (case or NFC/NFD form) with another name of the same folder."""
    groups = {}
    for name in names:
        groups.setdefault(pc_paths.casefold_key(name), []).append(name)
    return {name for group in groups.values() if len(group) > 1 for name in group}


def _left_out(info):
    """The scoped_base reason an entry of this kind is not admitted, or None for an ordinary entry."""
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        return "link"
    if getattr(info, "st_flags", 0) & _SF_DATALESS:
        return "special"  # a macOS cloud placeholder (F-206): opening it downloads it, so it is never opened
    if stat.S_ISDIR(info.st_mode):
        return None
    if not stat.S_ISREG(info.st_mode):
        return "special"
    return "hard-link" if info.st_nlink != 1 else None


def _refusal(error, code, message="The entry could not be used"):
    """The categorical refusal for an OSError of a selected root; no path or native error text is kept."""
    number = getattr(error, "errno", None)
    if number == errno.EPERM and sys.platform == "darwin":
        # privacy protection, the app sandbox or a locked folder (EACCES stays an ordinary access refusal)
        return ScopedFSError("macos-privacy-protection", _TCC_MESSAGE)
    if number in (errno.ENOENT, errno.ENOTDIR):
        return ScopedFSError("missing-entry", "Exact entry is missing")
    if number == errno.ELOOP:
        return ScopedFSError("reparse-point", "Links are never followed")
    if number in _FULL:
        return ScopedFSError("disk-full", "The drive is full")
    return ScopedFSError(code, message)


def _os(code, function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except OSError as error:
        raise _refusal(error, code) from None


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
            # The native system library only, never a caller-selected one or the path-based renamex_np.
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
        if error in (errno.EEXIST, errno.ENOTEMPTY):
            raise ScopedFSError("destination-exists", "Destination or case-equivalent entry already exists")
        if error == errno.EXDEV:  # another mount, also a bind mount of the same file system: nothing was renamed
            raise ScopedFSError("same-volume-required", "Files are only moved within one mount; nothing is copied")
        if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}:
            raise CapabilityHold("no-replace-unavailable", "Filesystem refused native no-overwrite rename")
        raise ScopedFSError("rename-refused-no-overwrite", "Native rename failed; reconcile source and destination")


def capabilities():
    """Actual adapter availability, without collecting selected-root metadata."""
    if os.name == "nt":
        try:
            import windows_scoped
            return windows_scoped.capabilities()
        except ImportError:
            return {"available": False, "platform": "windows", "adapter": None, "stream_max_bytes": 0, **dict.fromkeys(
                ("pinning", "move_noreplace", "remove_file", "create_file", "mkdir", "read_bytes", "stream_to"), False),
                "reason": "Verified Windows native adapter unavailable"}
    available = _posix_capable()
    return {"available": available, "platform": sys.platform,
            "adapter": ADAPTER if available else None,
            "reason": None if available else "Python 3.12+ native no-follow/dir-fd support required",
            "pinning": available, "move_noreplace": available and _rename_function() is not None,
            "remove_file": available, "create_file": available, "mkdir": available, "read_bytes": available,
            "stream_to": available, "stream_max_bytes": scoped_base.MAX_STREAM_BYTES if available else 0,
            "quiet_workspace_required": True}


def _ordinary(info, *, directory=None):
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        _refuse("reparse-point", "Links are never followed")
    is_directory = stat.S_ISDIR(info.st_mode)
    if not is_directory and not stat.S_ISREG(info.st_mode):
        _refuse("unexpected-type", "Only ordinary files and folders are admitted")
    if not is_directory and info.st_nlink != 1:
        _refuse("hard-link", "Files with more than one name are not admitted")
    if directory is not None and is_directory != directory:
        _refuse("unexpected-type", "The entry is not of the expected kind")
    if info.st_ino <= 0 or info.st_dev < 0 or info.st_size < 0:
        _refuse("unknown-identity", "Stable native identity is unavailable")
    return info


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink,
            getattr(info, "st_file_attributes", 0))


def _record(relative, info, sha256=None):
    _ordinary(info)
    return {"relative_path": relative, "kind": "directory" if stat.S_ISDIR(info.st_mode) else "file",
            "device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
            "nlink": info.st_nlink, "sha256": sha256, "attributes": getattr(info, "st_file_attributes", 0)}


def _locked(fd, info):
    """True when the open file has an immutable or append-only flag, so it cannot be deleted without changing one."""
    if sys.platform == "darwin":
        return bool(getattr(info, "st_flags", 0) & _DARWIN_LOCKED)
    if not sys.platform.startswith("linux") or fcntl is None or os.uname().machine not in _GENERIC_IOCTL_MACHINES:
        return False
    flags = bytearray(8)
    try:
        fcntl.ioctl(fd, _FS_IOC_GETFLAGS, flags, True)
    except OSError:
        return False  # the file system keeps no such flags; unlinkat itself refuses a file that has one
    return bool(int.from_bytes(flags[:4], sys.byteorder) & (_FS_IMMUTABLE_FL | _FS_APPEND_FL))


def _sync(*descriptors):
    """Flush each descriptor to the drive (F_FULLFSYNC on macOS); True only when every flush succeeded."""
    synced = True
    for fd in descriptors:
        try:
            if sys.platform == "darwin":
                fcntl.fcntl(fd, _F_FULLFSYNC)
            else:
                os.fsync(fd)
        except OSError:
            synced = False
            if sys.platform == "darwin":  # no F_FULLFSYNC here (for example exFAT): still flush to the drive
                with contextlib.suppress(OSError):
                    os.fsync(fd)
    return synced


def _uncache(fd):
    """Ask the system not to answer this descriptor's reads from its cache (open_read(uncached=True))."""
    try:
        if sys.platform == "darwin":
            fcntl.fcntl(fd, _F_NOCACHE, 1)
            return
        if sys.platform.startswith("linux"):
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            return
    except OSError:
        pass
    raise CapabilityHold("uncached-read-unavailable", "This system could not bypass its file cache for the read")


def _volume_facts(fd):
    """Default volume source: {"filesystem": "native", "fat", "exfat" or "other" from the privacy modules' statfs
    lists, "removable": True unless Linux sysfs proves the drive fixed or macOS does not mark it external or virtual}"""
    if sys.platform == "darwin":
        kind, removable = darwin_privacy.volume_kind(fd)
        return {"filesystem": kind, "removable": removable}
    if sys.platform.startswith("linux"):
        return {"filesystem": linux_privacy.filesystem_kind(fd),
                "removable": not linux_privacy.fixed_disk(fd)}
    return {"filesystem": "other", "removable": True}


def _destination_volume(facts):
    """(scoped_base volume kind, stable file ids) for a volume source's facts: only a native file system on a drive
    proven fixed (macOS: not marked external or virtual) is private with stable inode numbers (D-069, D-072)."""
    if (not isinstance(facts, dict) or facts.get("filesystem") not in ("native", "fat", "exfat", "other")
            or type(facts.get("removable")) is not bool):
        _refuse("filesystem-capability-unavailable", "The drive's file system could not be read")
    if facts["filesystem"] == "native":
        return ("non-private", False) if facts["removable"] else ("private", True)
    return {"fat": "fat32", "exfat": "non-private"}.get(facts["filesystem"], "unsupported"), False


class _File(io.RawIOBase):
    """An open file of a PosixRoot: unbuffered and seekable over a descriptor the root owns and closes."""

    def __init__(self, fd, relative, *, writable=False, limit=scoped_base.MAX_STREAM_BYTES):
        super().__init__()
        self._fd, self._relative, self._writable, self._limit = fd, relative, writable, limit

    def readable(self):
        return True

    seekable = readable

    def writable(self):
        return self._writable

    def readinto(self, buffer):
        self._checkClosed()
        return _os("read-failed", os.readv, self._fd, [buffer])

    def write(self, data):
        self._checkClosed()
        if not self._writable:
            raise io.UnsupportedOperation("write")
        if getattr(self, "committed", False):
            _refuse("commit-state", "The file is already committed")
        view = memoryview(data).cast("B")
        if self.tell() + view.nbytes > self._limit:
            _refuse("file-too-large-for-volume", "The file would exceed the largest file this drive can hold")
        written = 0
        while written < view.nbytes:
            count = _os("write-failed", os.write, self._fd, view[written:written + scoped_base.CHUNK_BYTES])
            if not count:
                _refuse("short-write", "The system accepted no bytes")
            written += count
        return written

    def seek(self, offset, whence=io.SEEK_SET):
        self._checkClosed()
        return _os("seek-failed", os.lseek, self._fd, offset, whence)

    def tell(self):
        return self.seek(0, io.SEEK_CUR)

    def record(self):
        """Identity of the open descriptor now (sha256 None), from the descriptor itself, never by name."""
        self._checkClosed()
        return _record(self._relative, _os("filesystem-access", os.fstat, self._fd))


class _NewFile(_File):
    """A file written under a temporary name in its final folder; commit() names it (see scoped_base.NewFile)."""

    def __init__(self, root, fd, relative, parent, partial, private):
        super().__init__(fd, relative, writable=True, limit=root.max_file_bytes)
        self._root, self._parent, self._partial, self._private, self.committed = root, parent, partial, private, False

    def commit(self) -> dict:
        """Sync the file and its folder (F_FULLFSYNC on macOS), re-check privacy, hash this descriptor, rename without
        replacing (renameat2 RENAME_NOREPLACE, renameatx_np RENAME_EXCL, else CapabilityHold no-replace-unavailable),
        check that the name leads to this file, sync both again; ``durable`` only if every sync succeeded."""
        self._checkClosed()
        if self.committed:
            _refuse("commit-state", "The file is already committed")
        root, name = self._root, self._relative.rpartition("/")[2]
        durable = _sync(self._fd, self._parent)
        if self._private:
            root._owner_only(self._fd, 0o600, "new-private-file-security-unresolved")
        before = self.record()
        self.seek(0)
        sha256 = scoped_base.hash_stream(self, before["size"])
        root._unchanged(self._fd, self._parent, self._partial, self._relative, before, root.identity_keys)
        _call_rename(_rename_function(), self._parent, self._partial, self._parent, name)
        self.committed = True
        try:
            root._unchanged(self._fd, self._parent, name, self._relative, before, root.identity_keys & _RENAMED_KEYS)
        except ScopedFSError:
            _refuse("post-commit-verification-unresolved", "The renamed file is not the file that was written")
        durable = _sync(self._fd, self._parent) and durable
        return {**self.record(), "sha256": sha256, "durable": durable}


class PosixRoot(scoped_base.RootBase):
    """One explicitly selected folder on Linux or macOS, pinned with its ancestors until close().

    The root and its ancestors stay open and are re-checked by name around every operation; every entry below it is
    looked up with fstatat without following it, then opened with O_NOFOLLOW from its parent's descriptor. The
    constructor admits a source; admit_destination() a backup destination. One caller thread uses a root at a time.
    A mount of another file system and a macOS cloud placeholder (SF_DATALESS) are listed as not included ("link",
    "special"); naming one is refused. A bind mount of the same file system is not detected (making one needs an
    administrator). No path is asked from the system (no F_GETPATH) or built from the selected root.
    """

    def __init__(self, root, *, max_entries=MAX_ENTRIES, volumes=None, _destination=None):
        self._fds, self._anchors, self._closed = [], [], True
        self.max_entries = _cap(max_entries, MAX_ENTRIES, "max_entries")
        if not _posix_capable():
            raise CapabilityHold("native-unavailable", "Native POSIX no-follow/dir-fd support required")
        try:
            raw = os.fspath(root)
        except TypeError:
            raw = None
        if (not isinstance(raw, str) or not raw.startswith("/") or raw.startswith("//")
                or raw == "/" or raw.endswith("/") or "\x00" in raw
                or any(p in {"", ".", ".."} for p in raw.split("/")[1:])):
            _refuse("root-path", "An exact absolute non-filesystem-root directory is required")
        self.root = Path(raw)
        self._volumes = _volume_facts if volumes is None else volumes
        try:
            self._admit(raw, _destination)
        except BaseException:
            self.close()
            raise
        self._closed = False

    def _admit(self, raw, destination):
        """Pin "/" and every folder down to the root; ``destination`` is None for a source, else the acknowledgment."""
        try:
            fd = os.open("/", _DIRECTORY)
            self._fds.append(fd)
            for part in raw.split("/")[1:]:
                before = _ordinary(os.stat(part, dir_fd=fd, follow_symlinks=False), directory=True)
                if getattr(before, "st_flags", 0) & _SF_DATALESS:
                    _refuse("offline-encrypted-or-recall-file", "A cloud placeholder folder is never opened")
                child = os.open(part, _DIRECTORY, dir_fd=fd)
                self._fds.append(child)
                after = _ordinary(os.fstat(child), directory=True)
                if _identity(before) != _identity(after):
                    _refuse("ancestor-drift", "Directory identity changed during admission")
                self._anchors.append((fd, part, child, (after.st_dev, after.st_ino, after.st_mode)))
                fd = child
        except OSError as error:
            refusal = _refusal(error, "admission")
            if refusal.code != "macos-privacy-protection":
                refusal = ScopedFSError("admission", "Selected root is missing, inaccessible or not ordinary")
            raise refusal from None
        self._fd, self._device = fd, after.st_dev
        if destination is not None:
            try:
                facts = self._volumes(fd)
            except (OSError, linux_privacy.LinuxPrivacyHold, darwin_privacy.DarwinPrivacyHold):
                _refuse("filesystem-capability-unavailable", "The drive's file system could not be read")
            volume, stable_ids = _destination_volume(facts)
            vars(self).update(scoped_base.destination_facts(volume, non_private_destination=destination,
                                                           stable_ids=stable_ids))

    def close(self) -> None:
        fds, self._fds, self._closed = self._fds, [], True
        for fd in reversed(fds):
            with contextlib.suppress(OSError):
                os.close(fd)

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

    @contextlib.contextmanager
    def _operation(self):
        """The descriptors one operation opens, closed when it ends; the pinned ancestry is checked before and after."""
        self._validate_anchor()
        with contextlib.ExitStack() as stack:
            yield stack
        self._validate_anchor()

    def _names(self, fd):
        names = _os("filesystem-access", os.listdir, fd)
        if len(names) > self.max_entries:
            _refuse("entry-cap", "Directory membership exceeds its entry cap")
        return sorted(names)

    def _lookup(self, fd, name):
        """The entry ``name`` of the open folder ``fd``, looked up without following or opening it."""
        info = _ordinary(_os("filesystem-access", os.stat, name, dir_fd=fd, follow_symlinks=False))
        if info.st_dev != self._device:
            _refuse("filesystem-boundary", "Nested filesystem boundary refused")
        if getattr(info, "st_flags", 0) & _SF_DATALESS:
            _refuse("offline-encrypted-or-recall-file", "A cloud placeholder is never opened: opening it downloads it")
        return info

    def _open(self, stack, fd, name, *, directory=None, code="read-drift"):
        """Open the entry ``name`` of folder ``fd`` with O_NOFOLLOW; its identity may not change from lookup to open."""
        before = self._lookup(fd, name)
        is_directory = stat.S_ISDIR(before.st_mode)
        if directory is not None and is_directory != directory:
            _refuse("unexpected-type", "The entry is not of the expected kind")
        child = _os("filesystem-access", os.open, name, _DIRECTORY if is_directory else _FILE, dir_fd=fd)
        stack.callback(os.close, child)
        if _identity(_os("filesystem-access", os.fstat, child)) != _identity(before):
            _refuse(code, "The entry changed while it was opened")
        return child, before

    def _parent(self, stack, relative):
        """Open each folder between the root and ``relative``; return the parent's descriptor and the entry's name."""
        fd, parts = self._fd, relative.split("/")
        for part in parts[:-1]:
            fd, _info = self._open(stack, fd, part, directory=True, code="parent-drift")
        return fd, parts[-1]

    def _absent(self, fd, name):
        """Refuse when ``name`` or another case or NFC/NFD form of it is taken in folder ``fd``."""
        key = pc_paths.casefold_key(name)
        if any(pc_paths.casefold_key(entry) == key for entry in self._names(fd)):
            _refuse("destination-exists", "Destination or case-equivalent entry already exists")

    def _unchanged(self, handle, parent, name, relative, expected, keys, code="stale-identity"):
        """Refuse with ``code`` unless the open file keeps ``expected``'s identity (keys) and its name leads to it."""
        info = _os("filesystem-access", os.fstat, handle)  # a file that lost its name (link count 0) has changed
        held = _record(relative, info) if info.st_nlink == 1 else {}
        named = _record(relative, self._lookup(parent, name))
        if (not held or not _same(held, expected, keys) or not _same(named, held, keys)
                or (named["device"], named["inode"]) != (held["device"], held["inode"])):
            _refuse(code, "The file changed or its name now leads to another file")
        return held

    def _verified(self, stack, relative, expected, sha256, allow_read_only):
        """Open a reviewed file, check its identity and, unless ``allow_read_only`` is None or True, that it is not
        read-only (no owner write bit, or an immutable or append-only flag), then hash it on that descriptor."""
        parent, name = self._parent(stack, relative)
        handle, info = self._open(stack, parent, name, directory=False)
        if not _same(_record(relative, info), expected, self.identity_keys):
            _refuse("stale-identity", "File no longer matches the reviewed identity")
        if allow_read_only is False and (scoped_base.read_only({"mode": info.st_mode, "attributes": 0})
                                         or _locked(handle, info)):
            _refuse("read-only", "The approved plan does not show this file as read-only")
        if scoped_base.hash_stream(_File(handle, relative), expected["size"]) != sha256:
            _refuse("stale-content", "Content hash no longer matches the reviewed file")
        return parent, name, handle

    @staticmethod
    def _owner_only(handle, mode, code):
        """Refuse with ``code`` unless the open object has permission bits ``mode`` (0600 or 0700, special bits aside),
        this process's effective user as owner, one link for a file and, on macOS, no extended ACL on the descriptor."""
        info = _os(code, os.fstat, handle)
        if info.st_uid != os.geteuid() or info.st_mode & 0o777 != mode or info.st_nlink != 1 and stat.S_ISREG(info.st_mode):
            _refuse(code, "The entry is not private")
        if sys.platform == "darwin":
            try:
                darwin_privacy.assert_no_extended_acl_fd(handle)
            except darwin_privacy.DarwinPrivacyHold:
                _refuse(code, "The entry has an access control list")

    def _discard(self, parent, partial, handle):
        """Remove an uncommitted temporary file while its name leads to it, else it stays under its recorded name."""
        with contextlib.suppress(OSError):
            named, held = os.stat(partial, dir_fd=parent, follow_symlinks=False), os.fstat(handle)
            if (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino):
                os.unlink(partial, dir_fd=parent)

    def inspect(self, relative, *, hash_file=False) -> dict:
        if type(hash_file) is not bool:
            _refuse("invalid-option", "hash_file must be boolean")
        relative = relative_path(relative, allow_root=True)
        with self._operation() as stack:
            if not relative:
                return _record("", _os("filesystem-access", os.fstat, self._fd))
            parent, name = self._parent(stack, relative)
            if not hash_file:
                return _record(relative, self._lookup(parent, name))
            handle, info = self._open(stack, parent, name)
            record = _record(relative, info)
            if record["kind"] == "file":
                reader = _File(handle, relative)
                record["sha256"] = scoped_base.hash_stream(reader, record["size"])
                if not _same(reader.record(), record, self.identity_keys):
                    _refuse("read-drift", "File changed during the read")
            return record

    def list_directory(self, relative="", *, excluded=None) -> list[dict]:
        relative = relative_path(relative, allow_root=True)
        if excluded is not None and not isinstance(excluded, list):
            _refuse("invalid-option", "excluded must be a list or None")
        with self._operation() as stack:
            fd = self._fd
            if relative:
                parent, name = self._parent(stack, relative)
                fd, _info = self._open(stack, parent, name, directory=True, code="directory-drift")
            before = _identity(_os("filesystem-access", os.fstat, fd))
            names = self._names(fd)
            colliding = _collisions(names)
            rows = []
            for name in names:
                reason = scoped_base.name_reason(relative, name) or ("case-collision" if name in colliding else None)
                if reason is None:
                    try:
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        _refuse("directory-membership-changed", "Directory membership changed during listing")
                    except OSError as error:
                        raise _refusal(error, "filesystem-access") from None
                    # Another device below the root is a nested mount: left out like a Windows mounted folder.
                    reason = _left_out(info) or ("link" if info.st_dev != self._device else None)
                if reason:
                    scoped_base.exclude(excluded, relative, name, reason)
                else:
                    rows.append(_record(f"{relative}/{name}" if relative else name, info))
            if before != _identity(_os("filesystem-access", os.fstat, fd)) or names != self._names(fd):
                _refuse("directory-membership-changed", "Directory membership changed during listing")
            return rows

    @contextlib.contextmanager
    def open_read(self, relative, *, expected, uncached=False):
        """As RootBase.open_read; the name must still lead to the file when the block is left. ``uncached``: Linux
        posix_fadvise(POSIX_FADV_DONTNEED) drops the file's clean cached pages first; macOS F_NOCACHE keeps this
        descriptor's reads out of the cache. Neither bypasses the drive's own cache, and pages another program keeps
        in use (Linux) or already cached (macOS) can still answer; elsewhere it holds (uncached-read-unavailable)."""
        if type(uncached) is not bool:
            _refuse("invalid-option", "uncached must be boolean")
        expected = _expected(expected, relative, hashed=False)
        with self._operation() as stack:
            parent, name = self._parent(stack, relative)
            handle, info = self._open(stack, parent, name, directory=False)
            if not _same(_record(relative, info), expected, self.identity_keys):
                _refuse("stale-identity", "File no longer matches the reviewed identity")
            if uncached:
                _uncache(handle)
            reader = _File(handle, relative)
            try:
                yield reader
                self._unchanged(handle, parent, name, relative, expected, self.identity_keys, "read-drift")
            finally:
                reader.close()

    @contextlib.contextmanager
    def open_new(self, relative, *, private=True, original_mode=None, partial=None):
        """As RootBase.open_new: created with O_CREAT|O_EXCL|O_NOFOLLOW under partial_name(partial) in the target
        folder, mode 0600 (private) or new_file_mode(False, original_mode) under the umask (never executable)."""
        bits = scoped_base.new_file_mode(private, original_mode)
        relative = relative_path(relative)
        partial = scoped_base.partial_name(partial)
        if _rename_function() is None:
            raise CapabilityHold("no-replace-unavailable", "Native atomic no-overwrite rename is unavailable")
        private = bits is None and self.private
        with self._operation() as stack:
            parent, name = self._parent(stack, relative)
            self._absent(parent, name)
            try:
                handle = os.open(partial, _NEW, 0o600 if bits is None else bits, dir_fd=parent)
            except FileExistsError:
                _refuse("destination-exists", "The temporary name is already in use")
            except OSError as error:
                raise _refusal(error, "create-new-refused", "The temporary file could not be created") from None
            stack.callback(os.close, handle)
            out = _NewFile(self, handle, relative, parent, partial, private)
            try:
                if private:  # owner-only before the first byte
                    self._owner_only(handle, 0o600, "new-private-file-security-unresolved")
                yield out
            finally:
                if not out.committed:
                    self._discard(parent, partial, handle)
                out.close()

    def mkdir(self, relative) -> dict:
        relative = relative_path(relative)
        with self._operation() as stack:
            parent, name = self._parent(stack, relative)
            self._absent(parent, name)
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                _refuse("destination-exists", "Destination or case-equivalent entry already exists")
            except OSError as error:
                raise _refusal(error, "create-directory-refused", "The folder could not be created") from None
            _sync(parent)  # best effort: the new folder's entry reaches the drive with its parent
            folder, info = self._open(stack, parent, name, directory=True, code="directory-drift")
            if self.private:
                try:
                    self._owner_only(folder, 0o700, "new-private-directory-security-unresolved")
                except ScopedFSError:
                    with contextlib.suppress(OSError):
                        os.rmdir(name, dir_fd=parent)
                    raise
            return _record(relative, info)

    def move_to(self, relative, *, destination, destination_relative, expected) -> dict:
        return self._move(relative, destination, destination_relative, expected)

    def _move(self, relative, destination, destination_relative, expected, *, allow_read_only=None):
        """move_to; with ``allow_read_only`` False (the removal rule) a read-only file is refused."""
        expected = _expected(expected, relative)
        destination_relative = relative_path(destination_relative)
        if not isinstance(destination, PosixRoot) or destination._closed:
            _refuse("destination-scope-required", "An open destination root is required")
        if destination._device != self._device:
            _refuse("same-volume-required", "Files are only moved within one drive; nothing is copied")
        rename = _rename_function()
        if rename is None:
            raise CapabilityHold("no-replace-unavailable", "Native atomic no-overwrite rename is unavailable")
        with self._operation() as stack, destination._operation() as target_stack:
            parent, name, handle = self._verified(stack, relative, expected, expected["sha256"], allow_read_only)
            target_parent, target_name = destination._parent(target_stack, destination_relative)
            destination._absent(target_parent, target_name)
            held = self._unchanged(handle, parent, name, relative, expected, self.identity_keys)
            _call_rename(rename, parent, name, target_parent, target_name)
            try:  # from here on the file has moved: every refusal says so
                moved = _record(destination_relative, os.stat(target_name, dir_fd=target_parent, follow_symlinks=False))
            except (OSError, ScopedFSError):
                moved = None
            if (moved is None or (moved["device"], moved["inode"]) != (held["device"], held["inode"])
                    or not _same(moved, held, self.identity_keys & _RENAMED_KEYS)):
                _refuse("post-move-verification-unresolved", "Rename occurred but its postcondition is unresolved")
            return {**moved, "sha256": expected["sha256"]}

    def remove_file(self, relative, *, expected, sha256=None, allow_read_only=False) -> dict:
        """As RootBase.remove_file, hashed with scoped_base.hash_stream on the open descriptor. POSIX deletes by name
        (#51): just before unlinkat the name's fstatat identity must equal the descriptor's, but a file renamed onto
        the name after that check would be deleted; the quiet workspace excludes that, and remove_original() first
        moves the file into a private folder. A read-only file (no owner write bit, or an immutable or append-only
        flag: Linux FS_IOC_GETFLAGS, macOS st_flags) is refused unless allowed; no mode or flag is ever changed."""
        if type(allow_read_only) is not bool:
            _refuse("invalid-option", "allow_read_only must be boolean")
        expected = _expected(expected, relative)
        target = expected["sha256"] if sha256 is None else sha256
        if not isinstance(target, str) or not pc_records.SHA256.fullmatch(target):
            _refuse("expected-record", "A SHA-256 is required")
        if scoped_base.read_only(expected) and not allow_read_only:
            _refuse("read-only", "The approved plan does not show this file as read-only")
        with self._operation() as stack:
            parent, name, handle = self._verified(stack, relative, expected, target, allow_read_only)
            self._unchanged(handle, parent, name, relative, expected, self.identity_keys)
            try:
                os.unlink(name, dir_fd=parent)
            except OSError as error:
                code = "missing-entry" if error.errno == errno.ENOENT else "delete-refused"
                raise ScopedFSError(code, "The file could not be deleted") from None
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return {**expected, "sha256": target}
            except OSError:
                pass
            _refuse("post-purge-verification-unresolved", "The name is still present after removal")

    def free_bytes(self) -> int:
        if self._closed:
            _refuse("closed-root", "The selected root is closed")
        info = _os("free-space-unavailable", os.fstatvfs, self._fd)
        return info.f_bavail * info.f_frsize


def _windows():
    try:
        import windows_scoped
    except ImportError as exc:
        raise CapabilityHold("native-unavailable", "Verified Windows native adapter unavailable") from exc
    return windows_scoped


def admit_destination(root, *, non_private_destination=False, volumes=None, max_entries=MAX_ENTRIES):
    """Admit a backup destination (separate from source admission, plan RR2-4); on Windows windows_scoped's.

    On POSIX ``volumes(fd)`` (default _volume_facts; Windows' takes (handle, drive)) decides: only a native file system
    on a drive proven fixed (macOS: not marked external or virtual) is private, with stable inode numbers; FAT holds
    files below 4 GiB; FAT, exFAT and other native drives need ``non_private_destination`` (D-069, D-072); anything else
    (tmpfs, ramfs, read-only, network, FUSE, 9p, DrvFS) is refused. Admission writes and removes one empty file in the
    folder (after a failure, by identity), so a file system without a no-replace rename holds before any backup."""
    if os.name == "nt":
        return _windows().admit_destination(root, non_private_destination=non_private_destination, volumes=volumes,
                                            max_entries=max_entries)
    if type(non_private_destination) is not bool:
        _refuse("invalid-option", "non_private_destination must be boolean")
    root = PosixRoot(root, max_entries=max_entries, volumes=volumes, _destination=non_private_destination)
    probe, record = scoped_base.new_partial_name(), None
    try:
        with root.open_new(probe) as out:  # an uncommitted probe is removed by open_new itself
            record = out.commit()
        root.remove_file(probe, expected={key: value for key, value in record.items() if key != "durable"},
                         allow_read_only=True)
    except BaseException:
        with contextlib.suppress(OSError, TypeError):
            named = os.stat(probe, dir_fd=root._fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) == (record["device"], record["inode"]):
                os.unlink(probe, dir_fd=root._fd)
        root.close()
        raise
    return root


def process_is_elevated() -> bool:
    """True when this process runs as root (POSIX) or elevated (Windows, windows_scoped)."""
    if os.name == "nt":
        return _windows().process_is_elevated()
    return os.geteuid() == 0


def new_removal_name():
    """A fresh name for an original moved into a removal folder; the caller records it before remove_original."""
    return ".removal-" + uuid.uuid4().hex


def _removal_name(removal, name):
    """``name`` (a new_removal_name()) after checking that ``removal`` is an open folder only this user can use."""
    if not isinstance(removal, PosixRoot) or removal._closed or removal.destination:
        _refuse("removal-folder", "An open private removal folder root is required")
    removal._owner_only(removal._fd, 0o700, "removal-folder")
    removal._validate_anchor()
    if not isinstance(name, str) or not REMOVAL_NAME.fullmatch(name):
        _refuse("invalid-option", "removal_name must be a new_removal_name() the caller recorded first")
    return name


def remove_original(root, relative, *, expected, sha256=None, allow_read_only=False, removal=None, removal_name=None,
                    in_place=False):
    """Delete an original after a verified backup with the removal-folder rule (D-016, D-022, plan RR2-8).

    ``removal`` is a root on the caller's work/removals/<id>/ folder (mode 0700, owned by this user, outside every
    selected root) and ``removal_name`` a new_removal_name() the caller recorded first. On POSIX, when that folder has
    the original's device, the verified original is renamed into it without replacing anything, then hashed again and
    deleted there by removal.remove_file. A refusal after the rename is removal-incomplete: the original is at
    ``removal_name`` and the caller runs reconcile_removal(). Otherwise (another device, a bind mount refusing the
    rename, and on Windows, whose delete handle closes the window) root.remove_file deletes it in place (#51). Without a
    removal folder the caller says ``in_place=True``; neither, or both, is refused.
    """
    if type(in_place) is not bool or in_place == (removal is not None):
        _refuse("invalid-option", "Give either a removal folder or in_place=True")
    if os.name != "nt" and removal is not None:
        name = _removal_name(removal, removal_name)
        if isinstance(root, PosixRoot) and removal._device == root._device:
            if type(allow_read_only) is not bool:
                _refuse("invalid-option", "allow_read_only must be boolean")
            expected = _expected(expected, relative)
            target = {**expected, "sha256": expected["sha256"] if sha256 is None else sha256}
            try:
                moved = root._move(relative, removal, name, target, allow_read_only=allow_read_only)
            except ScopedFSError as error:
                if error.code == "same-volume-required":  # EXDEV at the rename (a bind mount): nothing moved
                    return root.remove_file(relative, expected=expected, sha256=sha256, allow_read_only=allow_read_only)
                try:  # the name is fresh: if it exists in the removal folder, the original was moved
                    os.stat(name, dir_fd=removal._fd, follow_symlinks=False)
                except FileNotFoundError:
                    raise error from None  # refused before the rename: the original is where it was
                except OSError:
                    pass
                raise ScopedFSError(*_INCOMPLETE) from error
            try:
                removed = removal.remove_file(name, expected=moved, allow_read_only=allow_read_only)
            except ScopedFSError as error:
                raise ScopedFSError(*_INCOMPLETE) from error
            return {**expected, "sha256": removed["sha256"]}
    return root.remove_file(relative, expected=expected, sha256=sha256, allow_read_only=allow_read_only)


def reconcile_removal(removal, *, expected, removal_name, sha256=None, allow_read_only=False):
    """Finish or report a removal that stopped between the rename into the removal folder and the delete: "removed"
    when the entry at ``removal_name`` was the original (``expected``'s identity apart from path, change time and device
    number, which changes across a restart, then its SHA-256) and is now deleted; "absent" when nothing has that name
    (the caller checks the original's place); "kept" when an entry there differs, which is never deleted."""
    name = _removal_name(removal, removal_name)
    if not isinstance(expected, dict):
        _refuse("expected-record", "The original's exact file record is required")
    expected = _expected(expected, expected.get("relative_path"))
    target = expected["sha256"] if sha256 is None else sha256
    try:
        current = removal.inspect(name)
    except ScopedFSError as error:
        if error.code == "missing-entry":
            return "absent"
        raise
    if current["kind"] != "file" or not _same(current, expected, removal.identity_keys & _RENAMED_KEYS - {"device"}):
        return "kept"
    try:
        removal.remove_file(name, expected={**current, "sha256": target}, allow_read_only=allow_read_only)
    except ScopedFSError as error:
        if error.code in ("stale-content", "stale-identity"):
            return "kept"
        raise
    return "removed"


def disk_relation(first, second, *, sysfs=None):
    """Whether two admitted roots share a disk (D-043 item 3, F-205): "same" for one device or one parent disk,
    "different" only when Linux sysfs proves the parent disks differ, otherwise "unknown" (always on macOS, and on
    Windows until disk extents are wired in). ``sysfs(root)``: an identity of the root's physical disk or None (default
    linux_privacy.physical_disk on the root's descriptor, which never proves a disk of a virtual machine)."""
    if os.name == "nt":
        return "unknown"
    devices = first.inspect("")["device"], second.inspect("")["device"]
    if devices[0] == devices[1]:
        return "same"
    if not sys.platform.startswith("linux"):
        return "unknown"
    disks = [sysfs(root) if sysfs else linux_privacy.physical_disk(root._fd) if isinstance(root, PosixRoot) else None
             for root in (first, second)]
    if None in disks:
        return "unknown"
    return "same" if disks[0] == disks[1] else "different"


class ScopedRoot:
    """The calls storage_ops and workflow_service make today: windows_scoped.ScopedRoot on Windows, a thin adapter
    over PosixRoot here. In-memory reads and writes keep DEFAULT_MAX_FILE_BYTES; a listing without ``excluded`` is
    refused, as before, and so is an entry whose own name (the last component) is one of a case collision."""

    def __new__(cls, root, *, quiet_workspace, max_entries=MAX_ENTRIES):
        if cls is ScopedRoot and os.name == "nt":
            if quiet_workspace is not True:
                _refuse("workspace-not-quiet", "An owner-controlled quiet workspace must be confirmed")
            windows_scoped = _windows()
            if not windows_scoped.capabilities().get("available"):
                raise CapabilityHold("native-unavailable", "Verified Windows native adapter unavailable")
            return windows_scoped.ScopedRoot(root, quiet_workspace=quiet_workspace, max_entries=max_entries)
        return super().__new__(cls)

    def __init__(self, root, *, quiet_workspace, max_entries=MAX_ENTRIES):
        if quiet_workspace is not True:
            _refuse("workspace-not-quiet", "An owner-controlled quiet workspace must be confirmed")
        self._root = PosixRoot(root, max_entries=max_entries)
        self.root, self.max_entries = self._root.root, max_entries

    def __enter__(self):
        self._root._validate_anchor()
        return self

    def __exit__(self, *unused):
        self.close()

    def close(self):
        self._root.close()

    def _explicit(self, relative):
        """Refuse an explicitly named entry that shares its folder with a case-equivalent name."""
        relative, root = relative_path(relative, allow_root=True), self._root
        if relative:
            with root._operation() as stack:
                fd, name = root._parent(stack, relative)
                if name in _collisions(root._names(fd)):
                    _refuse("case-collision", "Directory contains case-ambiguous entry names")
        return relative

    def inspect(self, relative, *, hash_file=False, max_bytes=DEFAULT_MAX_FILE_BYTES):
        _cap(max_bytes, scoped_base.MAX_STREAM_BYTES, "max_bytes")
        if type(hash_file) is not bool:
            _refuse("invalid-option", "hash_file must be boolean")
        record = self._root.inspect(self._explicit(relative))
        if hash_file and record["kind"] == "file":
            if record["size"] > max_bytes:
                _refuse("file-byte-cap", "File exceeds its explicit byte cap")
            record = self._root.inspect(relative, hash_file=True)
        return record

    def list_directory(self, relative="", *, excluded=None):
        """With ``excluded`` (a list), as PosixRoot.list_directory; without it the first left-out entry refuses."""
        if excluded is not None:
            return self._root.list_directory(relative, excluded=excluded)
        left_out = []
        rows = self._root.list_directory(relative, excluded=left_out)
        if left_out:
            _refuse(left_out[0]["reason"], "The folder holds an entry that cannot be admitted")
        return rows

    def snapshot(self, *, hash_files=False, max_file_bytes=DEFAULT_MAX_FILE_BYTES, max_total_bytes=None, excluded=None):
        """As PosixRoot.snapshot, but without ``excluded`` the first entry left out refuses, as list_directory does;
        before anything is hashed no file may exceed ``max_file_bytes`` nor all files ``max_total_bytes``."""
        _cap(max_file_bytes, scoped_base.MAX_STREAM_BYTES, "max_file_bytes")
        if max_total_bytes is not None:
            _cap(max_total_bytes, scoped_base.MAX_STREAM_BYTES, "max_total_bytes")
        if type(hash_files) is not bool:
            _refuse("invalid-option", "hash_files must be boolean")
        left_out = [] if excluded is None else excluded
        rows = self._root.snapshot(excluded=left_out)
        if excluded is None and left_out:
            _refuse(left_out[0]["reason"], "The tree holds an entry that cannot be admitted")
        sizes = [row["size"] for row in rows if row["kind"] == "file"] if hash_files else []
        if any(size > max_file_bytes for size in sizes):
            _refuse("file-byte-cap", "File exceeds its explicit byte cap")
        if max_total_bytes is not None and sum(sizes) > max_total_bytes:
            _refuse("total-byte-cap", "Snapshot hashing exceeds its total byte cap")
        hashed = self._root.snapshot(hash_files=True) if hash_files else rows
        if [{**row, "sha256": None} for row in hashed] != rows:
            _refuse("snapshot-drift", "Entries changed during snapshot")
        return hashed

    def stream_to(self, relative, *, expected, writer, max_bytes, chunk_size=65536):
        """As PosixRoot.stream_to, which passes CHUNK_BYTES pieces; ``chunk_size`` is still validated."""
        _cap(max_bytes, scoped_base.MAX_STREAM_BYTES, "max_bytes")
        _cap(chunk_size, scoped_base.CHUNK_BYTES, "chunk_size")
        expected = _expected(expected, self._explicit(relative))
        if expected["size"] > max_bytes:
            _refuse("file-byte-cap", "File exceeds its explicit byte cap")
        return self._root.stream_to(relative, expected=expected, writer=writer)

    def read_bytes(self, relative, *, expected, max_bytes):
        _cap(max_bytes, DEFAULT_MAX_FILE_BYTES, "max_bytes for in-memory read")
        chunks = []
        self.stream_to(relative, expected=expected, writer=chunks.append, max_bytes=max_bytes)
        return b"".join(chunks)

    def mkdir(self, relative):
        return self._root.mkdir(relative)

    def create_file(self, relative, *, data, max_bytes):
        """Create a file exclusively through open_new; a write that could not be synced to the drive is refused."""
        _cap(max_bytes, DEFAULT_MAX_FILE_BYTES, "max_bytes for file creation")
        if not isinstance(data, bytes) or len(data) > max_bytes:
            _refuse("file-byte-cap", "Bounded bytes are required for exclusive file creation")
        with self._root.open_new(relative) as out:
            out.write(data)
            record = out.commit()
        if not record.pop("durable"):
            _refuse("sync-failed", "The new file could not be synced to the drive")
        return record

    def move_to(self, relative, *, destination, destination_relative, expected):
        if not isinstance(destination, ScopedRoot):
            _refuse("destination-root", "A native pinned destination ScopedRoot is required")
        return self._root.move_to(self._explicit(relative), destination=destination._root,
                                  destination_relative=destination_relative, expected=expected)

    def remove_file(self, relative, *, expected):
        """As before: a file the expected (approved) record shows as read-only is removed too (PD-10)."""
        expected = _expected(expected, self._explicit(relative))
        self._root.remove_file(relative, expected=expected, allow_read_only=scoped_base.read_only(expected))
