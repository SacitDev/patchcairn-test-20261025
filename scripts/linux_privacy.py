"""Read-only admission of reviewed native Linux private-storage filesystems.

This is an extra gate, not permission repair or an OS sandbox. Callers must
still require actual effective-user ownership and 0700/0600 permissions, pin
their scope, and use a quiet workspace. Same-user/privileged mutation is excluded.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import os
import re
import stat
import sys

import pc_records

# Linux UAPI linux/magic.h. No foreign/network/emulated filesystem is admitted.
_NATIVE_TYPES = frozenset({0xEF53, 0x58465342, 0x9123683E, 0x01021994, 0x858458F6})


class LinuxPrivacyHold(pc_records.Refusal):
    """Categorical refusal without paths, filesystem IDs or native error text."""


def _hold(code):
    raise LinuxPrivacyHold(code) from None


class _StatFS(ctypes.Structure):
    """Verified glibc Linux x86-64 LP64 struct statfs, 120 bytes, alignment 8."""
    _fields_ = [("f_type", ctypes.c_int64), ("f_bsize", ctypes.c_int64),
                ("f_blocks", ctypes.c_uint64), ("f_bfree", ctypes.c_uint64),
                ("f_bavail", ctypes.c_uint64), ("f_files", ctypes.c_uint64),
                ("f_ffree", ctypes.c_uint64), ("f_fsid", ctypes.c_int32 * 2),
                ("f_namelen", ctypes.c_int64), ("f_frsize", ctypes.c_int64),
                ("f_flags", ctypes.c_int64), ("f_spare", ctypes.c_int64 * 4)]


def _supported_abi():
    if (os.name != "posix" or sys.platform != "linux" or sys.version_info < (3, 12)
            or sys.byteorder != "little" or ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_long) != 8 or ctypes.sizeof(ctypes.c_int) != 4):
        return False
    try:
        return (os.uname().machine == "x86_64" and ctypes.sizeof(_StatFS) == 120
                and ctypes.alignment(_StatFS) == 8 and _StatFS.f_fsid.offset == 56
                and _StatFS.f_namelen.offset == 64 and _StatFS.f_flags.offset == 80
                and _StatFS.f_spare.offset == 88)
    except (AttributeError, OSError):
        return False


def _descriptor_capable():
    return (all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
            and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks)


def _native_query():
    if not _supported_abi():
        _hold("linux-private-abi-unavailable")
    if not _descriptor_capable():
        _hold("linux-private-descriptor-unavailable")
    try:
        library = ctypes.CDLL("libc.so.6", use_errno=True)
        version = library.gnu_get_libc_version
        version.argtypes, version.restype = (), ctypes.c_char_p
        observed = version()
        if not isinstance(observed, bytes) or not re.fullmatch(rb"2\.[0-9]{1,3}(?:\.[0-9]{1,4})?", observed):
            _hold("linux-private-libc-unavailable")
        function = library.fstatfs
        function.argtypes, function.restype = (ctypes.c_int, ctypes.POINTER(_StatFS)), ctypes.c_int
        return library, function
    except (OSError, AttributeError, TypeError, ctypes.ArgumentError):
        _hold("linux-private-libc-unavailable")


def _ordinary(info, *, directory=None):
    is_directory = stat.S_ISDIR(info.st_mode)
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or not (is_directory or stat.S_ISREG(info.st_mode))
            or (not is_directory and info.st_nlink != 1)
            or (directory is not None and is_directory != directory)):
        _hold("linux-private-ordinary-path-required")
    if info.st_dev < 0 or info.st_ino <= 0 or info.st_size < 0:
        _hold("linux-private-identity-unavailable")
    return info


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _anchor_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


@contextmanager
def _ordinary_descriptor(raw):
    held, pins = [], []
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open("/", directory_flags)
        held.append(descriptor)
        _ordinary(os.fstat(descriptor), directory=True)
        parts = raw.split("/")[1:] if raw != "/" else []
        for index, name in enumerate(parts):
            parent = descriptor
            before = _ordinary(os.stat(name, dir_fd=parent, follow_symlinks=False),
                               directory=True if index < len(parts) - 1 else None)
            flags = directory_flags if stat.S_ISDIR(before.st_mode) else os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            descriptor = os.open(name, flags, dir_fd=parent)
            held.append(descriptor)
            after = _ordinary(os.fstat(descriptor))
            if _identity(before) != _identity(after):
                _hold("linux-private-path-changed")
            pins.append((parent, name, descriptor, _anchor_identity(after)))
        original = _identity(_ordinary(os.fstat(descriptor)))
        yield descriptor
        if _identity(_ordinary(os.fstat(descriptor))) != original:
            _hold("linux-private-path-changed")
        for parent, name, child, identity in pins:
            named = _ordinary(os.stat(name, dir_fd=parent, follow_symlinks=False))
            pinned = _ordinary(os.fstat(child))
            if _anchor_identity(named) != identity or _anchor_identity(pinned) != identity:
                _hold("linux-private-path-changed")
        if pins and _identity(_ordinary(os.stat(parts[-1], dir_fd=pins[-1][0], follow_symlinks=False))) != original:
            _hold("linux-private-path-changed")
    except OSError:
        _hold("linux-private-path-unavailable")
    finally:
        failed = False
        for item in reversed(held):
            try:
                os.close(item)
            except OSError:
                failed = True
        if failed:
            _hold("linux-private-close-unavailable")


def assert_native_private_filesystem(path):
    """Admit only reviewed native POSIX filesystem types for private storage.

    On WSL a native ext filesystem can pass; a Windows-mounted/9p/DrvFs path
    cannot pass merely because stat reports owner-only Linux mode metadata.
    Call on the existing parent before allocation and on actual paths before use.
    """
    library, query = _native_query()  # Retain the native library for the call lifetime.
    try:
        raw = os.fspath(path)
    except (TypeError, ValueError, OSError):
        _hold("linux-private-path-invalid")
    if (not isinstance(raw, str) or not raw.startswith("/") or raw.startswith("//")
            or len(raw) > 4096 or "\x00" in raw or (raw != "/" and raw.endswith("/"))
            or (raw != "/" and any(part in {"", ".", ".."} for part in raw.split("/")[1:]))
            or len(raw.split("/")) > 66 or any(0xD800 <= ord(char) <= 0xDFFF for char in raw)):
        _hold("linux-private-path-invalid")
    result = _StatFS()
    with _ordinary_descriptor(raw) as descriptor:
        ctypes.set_errno(0)
        try:
            status = query(descriptor, ctypes.byref(result))
        except (OSError, TypeError, ctypes.ArgumentError):
            _hold("linux-private-filesystem-unavailable")
        if status != 0:
            _hold("linux-private-filesystem-unavailable")
    if result.f_type not in _NATIVE_TYPES:
        _hold("linux-private-foreign-filesystem")
