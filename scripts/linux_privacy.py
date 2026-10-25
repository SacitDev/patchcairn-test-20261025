"""Read-only admission of reviewed native Linux private-storage filesystems, and the drive facts of a backup
destination (file system kind, whether its disk is proven fixed, which physical disk holds it).

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
# Backup destinations only (filesystem_kind): MSDOS_SUPER_MAGIC is FAT12/16/32 under vfat and msdos, EXFAT_SUPER_MAGIC
# the kernel's exFAT driver. Neither keeps permissions, so neither is private storage.
_FAT_TYPES = frozenset({0x4D44})
_EXFAT_TYPES = frozenset({0x2011BAB0})
# TMPFS_MAGIC and RAMFS_MAGIC: memory, emptied at unmount or restart, so never a backup destination (D-069).
_MEMORY_TYPES = frozenset({0x01021994, 0x858458F6})
_ST_RDONLY = 1  # statfs f_flags (Linux 2.6.36+): mounted read-only
# Paths of virtual-machine disks in sysfs (virtio, Hyper-V VMBus and its MSFT1000 ACPI node, Xen's /sys/devices/vbd-*),
# which may be files on one physical drive.
_VIRTUAL_DISK_MARKERS = ("virtio", "vmbus", "msft1000", "/vbd-")
# Disks reached over a network or a hot-plug bus (iSCSI sessions, FireWire sbp2), never fixed; Ceph RBD is below.
_NETWORK_DISK = re.compile(r"/session\d|/fw\d")
_TEXT_LIMIT = 1 << 20


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
    with _ordinary_descriptor(raw) as descriptor:
        result = _statfs(query, descriptor)
    if result.f_type not in _NATIVE_TYPES:
        _hold("linux-private-foreign-filesystem")


def _statfs(query, descriptor):
    result = _StatFS()
    ctypes.set_errno(0)
    try:
        status = query(descriptor, ctypes.byref(result))
    except (OSError, TypeError, ctypes.ArgumentError):
        _hold("linux-private-filesystem-unavailable")
    if status != 0:
        _hold("linux-private-filesystem-unavailable")
    return result


def filesystem_kind(descriptor):
    """The kind of file system an open descriptor is on, for backup destination admission: "native" (a disk type
    assert_native_private_filesystem admits), "fat", "exfat" or "other" (tmpfs and ramfs, which live in memory, a
    read-only mount, network, FUSE, 9p/DrvFS, unknown). Holds as assert_native_private_filesystem does when the ABI,
    libc or query is unavailable; reads no content."""
    library, query = _native_query()  # Retain the native library for the call lifetime.
    if type(descriptor) is not int or descriptor < 0:
        _hold("linux-private-path-invalid")
    result = _statfs(query, descriptor)
    kind = result.f_type
    if kind in _MEMORY_TYPES or result.f_flags & _ST_RDONLY:
        return "other"
    if kind in _NATIVE_TYPES:
        return "native"
    return "fat" if kind in _FAT_TYPES else "exfat" if kind in _EXFAT_TYPES else "other"


def _text(path):
    """A sysfs or procfs file, stripped, or None when it cannot be read; a file that fills the read limit loses its last
    line, which may be cut."""
    try:
        with open(path, encoding="ascii", errors="surrogateescape") as stream:
            data = stream.read(_TEXT_LIMIT)
    except (OSError, ValueError):
        return None
    return (data.rpartition("\n")[0] if len(data) == _TEXT_LIMIT else data).strip()


def _members(path, realpath, read, listdir, depth=0):
    """The whole-disk sysfs folders under the block device folder ``path`` (a partition's parent), following
    device-mapper (LVM, LUKS) and md through slaves/ to their members, or None when one member cannot be traced
    (loop, zram, network, an unknown path)."""
    if depth > 8 or not path.startswith("/sys/devices/"):
        return None
    whole = path.rpartition("/")[0] if read(path + "/partition") is not None else path
    if not path.startswith("/sys/devices/virtual/"):
        return [whole]
    try:  # an md partition (md0p1) has no slaves/ of its own: its array (md0) has
        slaves = sorted(listdir(whole + "/slaves"))
    except OSError:
        return None
    found = []
    for name in slaves:
        member = _members(realpath("/sys/class/block/" + name), realpath, read, listdir, depth + 1)
        if member is None:
            return None
        found += member
    return found or None


def _disks(descriptor, device, realpath, read, listdir):
    """The distinct whole disks holding the file system of the open ``descriptor`` (device number ``device``, else its
    fstat), or None when sysfs cannot trace them. A btrfs file system has anonymous device numbers that differ from
    mountinfo's, so its mount is found by the descriptor's mnt_id (/proc/self/fdinfo); its mount source and
    /sys/fs/btrfs/<fsid>/devices/ then give its member devices."""
    try:
        device = os.fstat(descriptor).st_dev if device is None else device
    except OSError:
        return None
    if os.major(device):
        found = _members(realpath(f"/sys/dev/block/{os.major(device)}:{os.minor(device)}"), realpath, read, listdir)
        return list(dict.fromkeys(found)) if found else None
    fdinfo = (read(f"/proc/self/fdinfo/{descriptor}") or "").splitlines()
    mount, found = dict(line.split(":", 1) for line in fdinfo if ":" in line).get("mnt_id", "").strip(), None
    for line in (read("/proc/self/mountinfo") or "").splitlines() if mount else ():
        fields = line.split()
        dash = fields.index("-") if "-" in fields else len(fields)
        if fields[:1] == [mount] and fields[dash + 1:dash + 2] == ["btrfs"] and len(fields) > dash + 2:
            source = re.sub(r"\\([0-7]{3})", lambda escape: chr(int(escape[1], 8)), fields[dash + 2])
            source = os.path.basename(realpath(source))
            for fsid in sorted(_listing(listdir, "/sys/fs/btrfs")):
                members = sorted(_listing(listdir, f"/sys/fs/btrfs/{fsid}/devices"))
                if source in members:
                    disks = [_members(realpath(f"/sys/class/block/{name}"), realpath, read, listdir) for name in members]
                    found = None if None in disks else [disk for group in disks for disk in group]
    return list(dict.fromkeys(found)) if found else None


def _listing(listdir, path):
    try:
        return listdir(path)
    except OSError:
        return []


def _fixed(folder, read):
    """One whole disk is proven fixed: removable flag 0, no USB bus on its path, not a card in a reader (mmc never
    sets the flag, so an mmcblk disk needs device/type "MMC", eMMC; Memory Stick disks never count), not an iSCSI,
    FireWire or Ceph RBD disk, and no device above it marked "removable" (only Thunderbolt/USB4 ports that firmware
    marks external do that; USB is caught by its path)."""
    name = folder.rpartition("/")[2]
    if (read(folder + "/removable") != "0" or "/usb" in folder or name.startswith(("mspblk", "msblk"))
            or name.startswith("mmcblk") and read(folder + "/device/type") != "MMC"
            or _NETWORK_DISK.search(folder) or folder.startswith("/sys/devices/rbd/")):
        return False
    while folder.count("/") > 3:
        folder = folder.rpartition("/")[0]
        if read(folder + "/removable") == "removable":
            return False
    return True


def fixed_disk(descriptor, *, device=None, realpath=os.path.realpath, read=_text, listdir=os.listdir):
    """True only when sysfs proves that every disk holding the file system of the open ``descriptor`` is fixed (D-069,
    D-072): device-mapper, md and btrfs are followed to their member disks. A device it cannot trace is not fixed."""
    disks = _disks(descriptor, device, realpath, read, listdir)
    return bool(disks) and all(_fixed(folder, read) for folder in disks)


def physical_disk(descriptor, *, device=None, realpath=os.path.realpath, read=_text, listdir=os.listdir):
    """An identity of the one physical disk holding the file system of the open ``descriptor``, to tell two disks
    apart, or None when sysfs cannot prove one: a device it cannot trace or that spans several disks, any disk of a
    virtual machine (a virtio, VMBus or Xen disk, or a CPU reporting a hypervisor), and any machine whose CPU flags
    line cannot be read (an arm64 guest has none). An NVMe disk is its subsystem ("nvme:" + subsysnqn), so namespaces,
    ports and controllers of one drive are one disk; an mmc disk (also its boot and gp areas) is its card device."""
    disks = _disks(descriptor, device, realpath, read, listdir)
    flags = [line.split() for line in (read("/proc/cpuinfo") or "").splitlines() if line.startswith("flags")]
    if (not disks or len(disks) > 1 or not flags or "hypervisor" in flags[0]
            or any(marker in disks[0].lower() for marker in _VIRTUAL_DISK_MARKERS)):
        return None
    head, controller, rest = disks[0].partition("/nvme/")
    if controller:
        nqn = read(head + controller + rest.split("/")[0] + "/subsysnqn")
        return "nvme:" + nqn if nqn else None
    return realpath(disks[0] + "/device") if disks[0].rpartition("/")[2].startswith("mmcblk") else disks[0]
