"""Read-only native Darwin volume and extended-ACL privacy admission.

The caller must pin/check ordinary ancestry and enforce current-owner 0700
directories / 0600 single-link files. Use the filesystem check on allocation
parents and actual objects as well as the separate ACL check before private
bytes; an empty ACL alone is not a privacy decision. No permission, mount or ACL
repair is performed. Same-user/privileged concurrent mutation is excluded.
"""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
import errno
import os
import stat
import sys

# Apple Libc include/sys/acl.h; these are Darwin values, not Linux ACL values.
ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0
_SYSTEM_LIBRARY = "/usr/lib/libSystem.B.dylib"
# Apple XNU bsd/sys/mount.h and cdefs.h: modern 64-bit inode layout.
# x86-64 selects the $INODE64 symbol; arm64 has only the modern ABI.
_MNT_LOCAL = 0x00001000
_MNT_RDONLY = 0x00000001
_MNT_IGNORE_OWNERSHIP = 0x00200000
_MNT_EXT_FSKIT = 0x00000002
_O_EVTONLY = 0x00008000  # Apple bsd/sys/fcntl.h; metadata-only file open.


class _StatFS64(ctypes.Structure):
    _fields_ = [("f_bsize", ctypes.c_uint32), ("f_iosize", ctypes.c_int32),
                ("f_blocks", ctypes.c_uint64), ("f_bfree", ctypes.c_uint64),
                ("f_bavail", ctypes.c_uint64), ("f_files", ctypes.c_uint64),
                ("f_ffree", ctypes.c_uint64), ("f_fsid", ctypes.c_int32 * 2),
                ("f_owner", ctypes.c_uint32), ("f_type", ctypes.c_uint32),
                ("f_flags", ctypes.c_uint32), ("f_fssubtype", ctypes.c_uint32),
                ("f_fstypename", ctypes.c_char * 16), ("f_mntonname", ctypes.c_char * 1024),
                ("f_mntfromname", ctypes.c_char * 1024), ("f_flags_ext", ctypes.c_uint32),
                ("f_reserved", ctypes.c_uint32 * 7)]


class DarwinPrivacyHold(ValueError):
    """Categorical privacy refusal; no path, ACL content or native error text."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _hold(code):
    raise DarwinPrivacyHold(code) from None


def _volume_architecture():
    if (os.name != "posix" or sys.platform != "darwin" or sys.version_info < (3, 12)
            or sys.byteorder != "little" or ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_long) != 8 or ctypes.sizeof(ctypes.c_int) != 4
            or ctypes.sizeof(_StatFS64) != 2168 or ctypes.alignment(_StatFS64) != 8
            or _StatFS64.f_flags.offset != 64 or _StatFS64.f_fstypename.offset != 72
            or _StatFS64.f_flags_ext.offset != 2136):
        _hold("darwin-fs-abi-unavailable")
    try:
        architecture = os.uname().machine
    except (AttributeError, OSError):
        _hold("darwin-fs-abi-unavailable")
    if architecture not in {"x86_64", "arm64"}:
        _hold("darwin-fs-abi-unavailable")
    return architecture


def _volume_api():
    architecture = _volume_architecture()
    if (not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
            or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks):
        _hold("darwin-fs-descriptor-unavailable")
    try:
        library = ctypes.CDLL(_SYSTEM_LIBRARY, use_errno=True)
        symbol = "fstatfs$INODE64" if architecture == "x86_64" else "fstatfs"
        query = getattr(library, symbol)
        query.argtypes, query.restype = (ctypes.c_int, ctypes.POINTER(_StatFS64)), ctypes.c_int
        return library, query
    except (OSError, AttributeError, TypeError):
        _hold("darwin-fs-api-unavailable")


def _volume_identity(info):
    if (stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)
            or info.st_ino <= 0 or info.st_dev < 0 or info.st_size < 0):
        _hold("darwin-fs-ordinary-path-required")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _volume_descriptor(raw):
    held, pins = [], []
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open("/", directory_flags)
        held.append(descriptor)
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            _hold("darwin-fs-ordinary-path-required")
        parts = raw.split("/")[1:] if raw != "/" else []
        for index, name in enumerate(parts):
            parent = descriptor
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            identity = _volume_identity(before)
            directory = stat.S_ISDIR(before.st_mode)
            if index < len(parts) - 1 and not directory:
                _hold("darwin-fs-ordinary-path-required")
            descriptor = os.open(name, directory_flags if directory else _O_EVTONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=parent)
            held.append(descriptor)
            if _volume_identity(os.fstat(descriptor)) != identity:
                _hold("darwin-fs-path-changed")
            pins.append((parent, name, descriptor, identity[:5]))
        original = _volume_identity(os.fstat(descriptor))
        yield descriptor
        if _volume_identity(os.fstat(descriptor)) != original:
            _hold("darwin-fs-path-changed")
        for parent, name, child, identity in pins:
            if (_volume_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] != identity
                    or _volume_identity(os.fstat(child))[:5] != identity):
                _hold("darwin-fs-path-changed")
        if pins and _volume_identity(os.stat(parts[-1], dir_fd=pins[-1][0], follow_symlinks=False)) != original:
            _hold("darwin-fs-path-changed")
    except OSError:
        _hold("darwin-fs-path-unavailable")
    finally:
        failed = False
        for descriptor in reversed(held):
            try:
                os.close(descriptor)
            except OSError:
                failed = True
        if failed:
            _hold("darwin-fs-close-unavailable")


def assert_private_filesystem(path):
    """Read only actual mount flags/type; never change volume ownership settings.

    Apple permits MNT_IGNORE_OWNERSHIP to grant access before ACL/BSD checks.
    Only reviewed writable local APFS/HFS+ with that flag clear and no FSKit
    adapter pass. HFS+ subtypes 0..3 are source-defined extended variants.
    No mount names, device labels, filesystem counters or raw errors are saved.
    """
    library, query = _volume_api()
    try:
        raw = os.fspath(path)
    except (TypeError, ValueError, OSError):
        _hold("darwin-fs-path-invalid")
    if (not isinstance(raw, str) or not raw.startswith("/") or raw.startswith("//") or len(raw) > 4096
            or "\x00" in raw or (raw != "/" and raw.endswith("/")) or len(raw.split("/")) > 66
            or (raw != "/" and any(part in {"", ".", ".."} for part in raw.split("/")[1:]))
            or any(0xD800 <= ord(char) <= 0xDFFF for char in raw)):
        _hold("darwin-fs-path-invalid")
    result = _StatFS64()
    with _volume_descriptor(raw) as descriptor:
        try:
            status = query(descriptor, ctypes.byref(result))
        except (OSError, ctypes.ArgumentError, TypeError):
            _hold("darwin-fs-query-unavailable")
        if status != 0:
            _hold("darwin-fs-query-unavailable")
    if result.f_flags & _MNT_IGNORE_OWNERSHIP:
        _hold("darwin-fs-ownership-ignored")
    kind = bytes(result.f_fstypename)
    if (not result.f_flags & _MNT_LOCAL or result.f_flags & _MNT_RDONLY or result.f_flags_ext & _MNT_EXT_FSKIT
            or kind not in {b"apfs", b"hfs"} or kind == b"hfs" and result.f_fssubtype not in {0, 1, 2, 3}):
        _hold("darwin-fs-unsupported-filesystem")


class _DarwinACL:
    """Only ACL retrieval, working-copy validity/iteration and memory release."""
    def __init__(self):
        if os.name != "posix" or sys.platform != "darwin" or sys.version_info < (3, 12):
            _hold("darwin-acl-platform-unavailable")
        try:
            self.library = ctypes.CDLL(_SYSTEM_LIBRARY, use_errno=True)
            self.get_file = self.library.acl_get_file
            self.valid = self.library.acl_valid
            self.get_entry = self.library.acl_get_entry
            self.free = self.library.acl_free
            self.get_file.argtypes, self.get_file.restype = (ctypes.c_char_p, ctypes.c_int), ctypes.c_void_p
            self.valid.argtypes, self.valid.restype = (ctypes.c_void_p,), ctypes.c_int
            self.get_entry.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
            self.get_entry.restype = ctypes.c_int
            self.free.argtypes, self.free.restype = (ctypes.c_void_p,), ctypes.c_int
        except (OSError, AttributeError, TypeError):
            _hold("darwin-acl-api-unavailable")


def _native(function, *arguments):
    try:
        return function(*arguments)
    except (OSError, ctypes.ArgumentError, TypeError):
        _hold("darwin-acl-call-unavailable")


def _ordinary_identity(path):
    try:
        info = os.lstat(path)
    except OSError:
        _hold("darwin-acl-path-unavailable")
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
        _hold("darwin-acl-ordinary-path-required")
    if info.st_dev < 0 or info.st_ino <= 0:
        _hold("darwin-acl-identity-unavailable")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def assert_no_extended_acl(path):
    """Pass only source-verified absence or a valid empty Darwin extended ACL.

    Apple acl_get_entry returns 0 for an entry; after acl_valid succeeds,
    FIRST_ENTRY on an empty ACL returns -1/EINVAL without setting an entry.
    Apple's acl_file/filesec/statx implementation also returns NULL/ENOENT
    for an absent ACL property. Accept only that exact absence state when the
    checked ordinary path still has the same full identity before and after.
    Missing/changed paths and every other NULL/error state remain holds.
    This function never reads file content and has no ACL/permission setter.
    """
    if os.name != "posix" or sys.platform != "darwin" or sys.version_info < (3, 12):
        _hold("darwin-acl-platform-unavailable")
    try:
        raw = os.fspath(path)
    except (TypeError, OSError, ValueError):
        _hold("darwin-acl-path-invalid")
    if (not isinstance(raw, str) or not raw.startswith("/") or raw.startswith("//")
            or raw == "/" or raw.endswith("/") or len(raw) > 4096 or "\x00" in raw
            or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
            or any(0xD800 <= ord(char) <= 0xDFFF for char in raw)):
        _hold("darwin-acl-path-invalid")
    before = _ordinary_identity(raw)
    api = _DarwinACL()
    ctypes.set_errno(0)
    acl = _native(api.get_file, os.fsencode(raw), ACL_TYPE_EXTENDED)
    read_errno = ctypes.get_errno()
    if not acl:
        # Apple Libc posix1e/acl_file.c -> gen/filesec.c FILESEC_ACL:
        # NULL/ENOENT for an absent ACL property. sys/statx_np.c deliberately
        # leaves that property unset for KAUTH_FILESEC_NOACL. A missing path
        # also returns ENOENT, so require the exact ordinary identity again.
        if read_errno == errno.ENOENT:
            if _ordinary_identity(raw) != before:
                _hold("darwin-acl-path-changed")
            return
        _hold("darwin-acl-read-unavailable")
    try:
        if _native(api.valid, acl) != 0:
            _hold("darwin-acl-invalid")
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = _native(api.get_entry, acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        entry_errno = ctypes.get_errno()
        if result == 0:
            _hold("darwin-acl-not-empty")
        if result != -1 or entry_errno != errno.EINVAL or entry.value is not None:
            _hold("darwin-acl-state-unavailable")
    finally:
        if _native(api.free, acl) != 0:
            _hold("darwin-acl-release-unavailable")
    if _ordinary_identity(raw) != before:
        _hold("darwin-acl-path-changed")
