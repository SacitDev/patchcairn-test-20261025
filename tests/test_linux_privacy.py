"""Native-filesystem privacy gate: mocks plus owned WSL/Linux scope only."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import types
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import linux_privacy as privacy


def info(*, inode=101, directory=True, **changes):
    values = dict(st_dev=7, st_ino=inode, st_mode=(stat.S_IFDIR | 0o700) if directory else (stat.S_IFREG | 0o600),
                  st_uid=1001, st_gid=1001, st_nlink=2 if directory else 1,
                  st_size=64, st_mtime_ns=1000, st_ctime_ns=2000)
    values.update(changes)
    return types.SimpleNamespace(**values)


@contextmanager
def descriptor(_path):
    yield 41


class LinuxPrivacyTests(unittest.TestCase):
    def query(self, filesystem=0xEF53, status=0, flags=0):
        def invoke(fd, output):
            self.assertEqual(fd, 41)
            result = ctypes.cast(output, ctypes.POINTER(privacy._StatFS)).contents
            result.f_type, result.f_flags = filesystem, flags
            return status
        return mock.Mock(side_effect=invoke)

    def call_mocked(self, filesystem, *, status=0):
        query = self.query(filesystem, status)
        with mock.patch.object(privacy, "_native_query", return_value=(object(), query)), \
                mock.patch.object(privacy, "_ordinary_descriptor", side_effect=descriptor):
            return privacy.assert_native_private_filesystem("/fictional/selected")

    def test_exact_statfs_layout_and_native_call_signature(self):
        self.assertEqual(ctypes.sizeof(privacy._StatFS), 120)
        self.assertEqual(ctypes.alignment(privacy._StatFS), 8)
        self.assertEqual(privacy._StatFS.f_fsid.offset, 56)
        self.assertEqual(privacy._StatFS.f_namelen.offset, 64)
        self.assertEqual(privacy._StatFS.f_flags.offset, 80)
        self.assertEqual(privacy._StatFS.f_spare.offset, 88)
        version = mock.Mock(return_value=b"2.39")
        query = mock.Mock(return_value=0)
        with mock.patch.object(privacy, "_supported_abi", return_value=True), \
                mock.patch.object(privacy, "_descriptor_capable", return_value=True), \
                mock.patch.object(privacy.ctypes, "CDLL", return_value=types.SimpleNamespace(gnu_get_libc_version=version, fstatfs=query)) as loader:
            library, observed = privacy._native_query()
        self.assertIs(observed, query)
        loader.assert_called_once_with("libc.so.6", use_errno=True)
        self.assertEqual(version.argtypes, ())
        self.assertIs(version.restype, ctypes.c_char_p)
        self.assertEqual(query.argtypes, (ctypes.c_int, ctypes.POINTER(privacy._StatFS)))
        self.assertIs(query.restype, ctypes.c_int)

    def test_each_reviewed_native_type_is_accepted(self):
        for filesystem in (0xEF53, 0x58465342, 0x9123683E, 0x01021994, 0x858458F6):
            with self.subTest(filesystem=hex(filesystem)):
                self.assertIsNone(self.call_mocked(filesystem))

    def test_foreign_network_emulated_and_unknown_types_hold(self):
        for filesystem in (0, -1, 0x01021997, 0x65735546, 0x5346544E, 0x6969, 0xFF534D42,
                           0xFE534D42, 0x794C7630, 0x4D44, 0x2011BAB0, 0x12345678):
            with self.subTest(filesystem=hex(filesystem)):
                with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                    self.call_mocked(filesystem)
                self.assertEqual(caught.exception.code, "linux-private-foreign-filesystem")

    def test_query_error_is_not_a_foreign_filesystem_fallback(self):
        for status in (-1, 1):
            with self.subTest(status=status), self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                self.call_mocked(0xEF53, status=status)
            self.assertEqual(caught.exception.code, "linux-private-filesystem-unavailable")
        with mock.patch.object(privacy, "_native_query", return_value=(object(), mock.Mock(side_effect=OSError("sensitive native text")))), \
                mock.patch.object(privacy, "_ordinary_descriptor", side_effect=descriptor):
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.assert_native_private_filesystem("/fictional/selected")
            self.assertEqual(str(caught.exception), "linux-private-filesystem-unavailable")
            self.assertTrue(caught.exception.__suppress_context__)

    def test_unsupported_abi_or_descriptor_capability_holds_before_library_load(self):
        with mock.patch.object(privacy, "_supported_abi", return_value=False), mock.patch.object(privacy.ctypes, "CDLL") as loader:
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.assert_native_private_filesystem("/fictional/selected")
            self.assertEqual(caught.exception.code, "linux-private-abi-unavailable")
            loader.assert_not_called()
        with mock.patch.object(privacy, "_supported_abi", return_value=True), \
                mock.patch.object(privacy, "_descriptor_capable", return_value=False), mock.patch.object(privacy.ctypes, "CDLL") as loader:
            with self.assertRaises(privacy.LinuxPrivacyHold):
                privacy._native_query()
            loader.assert_not_called()

    def test_glibc_and_required_symbols_must_be_verified(self):
        libraries = (types.SimpleNamespace(), types.SimpleNamespace(gnu_get_libc_version=mock.Mock(return_value=b"musl")),
                     types.SimpleNamespace(gnu_get_libc_version=mock.Mock(return_value=None)),
                     types.SimpleNamespace(gnu_get_libc_version=mock.Mock(return_value=b"2.39")))
        with mock.patch.object(privacy, "_supported_abi", return_value=True), mock.patch.object(privacy, "_descriptor_capable", return_value=True):
            for library in libraries:
                with self.subTest(library=library), mock.patch.object(privacy.ctypes, "CDLL", return_value=library):
                    with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                        privacy._native_query()
                    self.assertEqual(caught.exception.code, "linux-private-libc-unavailable")
            with mock.patch.object(privacy.ctypes, "CDLL", side_effect=OSError("private loader details")):
                with self.assertRaises(privacy.LinuxPrivacyHold):
                    privacy._native_query()

    def test_foreign_platform_and_architecture_are_not_assumed_compatible(self):
        for name, platform in (("nt", "win32"), ("posix", "darwin"), ("posix", "freebsd")):
            with self.subTest(platform=platform), mock.patch.object(privacy.os, "name", name), \
                    mock.patch.object(privacy.sys, "platform", platform):
                self.assertFalse(privacy._supported_abi())
        with mock.patch.object(privacy.os, "name", "posix"), mock.patch.object(privacy.sys, "platform", "linux"), \
                mock.patch.object(privacy.sys, "byteorder", "big"):
            self.assertFalse(privacy._supported_abi())

    def test_only_reviewed_x86_64_lp64_abi_is_accepted(self):
        class MockLP64Long(ctypes.c_int64):
            pass
        original_sizeof = ctypes.sizeof
        def supported_sizeof(value):
            return {ctypes.c_void_p: 8, ctypes.c_long: 8, ctypes.c_int: 4}.get(value, original_sizeof(value))
        with mock.patch.object(privacy.os, "name", "posix"), mock.patch.object(privacy.sys, "platform", "linux"), \
                mock.patch.object(privacy.sys, "byteorder", "little"), mock.patch.object(privacy.sys, "version_info", (3, 12)), \
                mock.patch.object(privacy.ctypes, "c_long", MockLP64Long), \
                mock.patch.object(privacy.ctypes, "sizeof", side_effect=supported_sizeof):
            for machine in ("aarch64", "i686", "s390x", "unknown"):
                with self.subTest(machine=machine), mock.patch.object(privacy.os, "uname", return_value=types.SimpleNamespace(machine=machine), create=True):
                    self.assertFalse(privacy._supported_abi())
            with mock.patch.object(privacy.os, "uname", return_value=types.SimpleNamespace(machine="x86_64"), create=True):
                self.assertTrue(privacy._supported_abi())

    def test_invalid_paths_never_open_descriptors(self):
        with mock.patch.object(privacy, "_native_query", return_value=(object(), self.query())), \
                mock.patch.object(privacy, "_ordinary_descriptor") as opened:
            for path in ("relative", "//unknown", "/selected/../outside", "/selected/./x", "/selected/", "/selected//x", "/a\x00b", 42):
                with self.subTest(path=path), self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                    privacy.assert_native_private_filesystem(path)
                self.assertEqual(caught.exception.code, "linux-private-path-invalid")
            opened.assert_not_called()

    def descriptor_mocks(self, stack, *, leaf=None):
        leaf = info(inode=303, directory=False) if leaf is None else leaf
        observed = {10: info(inode=101), 11: info(inode=202), 12: leaf}
        stack.enter_context(mock.patch.object(privacy.os, "O_DIRECTORY", getattr(os, "O_DIRECTORY", 65536), create=True))
        stack.enter_context(mock.patch.object(privacy.os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 131072), create=True))
        stack.enter_context(mock.patch.object(privacy.os, "O_NONBLOCK", getattr(os, "O_NONBLOCK", 2048), create=True))
        opened = stack.enter_context(mock.patch.object(privacy.os, "open", side_effect=[10, 11, 12]))
        stack.enter_context(mock.patch.object(privacy.os, "fstat", side_effect=lambda fd: observed[fd]))
        def named(name, *, dir_fd, follow_symlinks):
            self.assertIs(follow_symlinks, False)
            return observed[{(10, "selected"): 11, (11, "file.txt"): 12}[dir_fd, name]]
        stack.enter_context(mock.patch.object(privacy.os, "stat", side_effect=named))
        closed = stack.enter_context(mock.patch.object(privacy.os, "close"))
        return observed, opened, closed

    def test_ordinary_descriptor_is_anchored_nofollow_pinned_and_closed_without_reads(self):
        query = self.query()
        def actual_query(fd, output):
            self.assertEqual(fd, 12)
            ctypes.cast(output, ctypes.POINTER(privacy._StatFS)).contents.f_type = 0xEF53
            return 0
        with ExitStack() as stack:
            observed, opened, closed = self.descriptor_mocks(stack)
            stack.enter_context(mock.patch.object(privacy, "_native_query", return_value=(object(), actual_query)))
            read = stack.enter_context(mock.patch.object(privacy.os, "read", side_effect=AssertionError("content read")))
            self.assertIsNone(privacy.assert_native_private_filesystem("/selected/file.txt"))
            self.assertEqual(opened.call_args_list[0].args[0], "/")
            self.assertEqual(opened.call_args_list[1].kwargs, {"dir_fd": 10})
            self.assertEqual(opened.call_args_list[2].kwargs, {"dir_fd": 11})
            for call in opened.call_args_list:
                self.assertTrue(call.args[1] & privacy.os.O_NOFOLLOW)
                self.assertTrue(call.args[1] & privacy.os.O_NONBLOCK)
            self.assertEqual(closed.call_args_list, [mock.call(12), mock.call(11), mock.call(10)])
            read.assert_not_called()

    def test_changed_open_file_identity_holds_and_closes_every_handle(self):
        with ExitStack() as stack:
            observed, opened, closed = self.descriptor_mocks(stack)
            def changed(fd, output):
                observed[12] = info(inode=304, directory=False)
                ctypes.cast(output, ctypes.POINTER(privacy._StatFS)).contents.f_type = 0xEF53
                return 0
            stack.enter_context(mock.patch.object(privacy, "_native_query", return_value=(object(), changed)))
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.assert_native_private_filesystem("/selected/file.txt")
            self.assertEqual(caught.exception.code, "linux-private-path-changed")
            self.assertEqual(closed.call_count, 3)

    def test_special_link_and_hardlink_leaf_refuse_before_open_or_query(self):
        for leaf in (info(directory=False, st_mode=stat.S_IFLNK | 0o777),
                     info(directory=False, st_nlink=2), info(directory=False, st_mode=stat.S_IFIFO | 0o600)):
            with self.subTest(mode=leaf.st_mode, links=leaf.st_nlink), ExitStack() as stack:
                observed, opened, closed = self.descriptor_mocks(stack, leaf=leaf)
                query = mock.Mock()
                stack.enter_context(mock.patch.object(privacy, "_native_query", return_value=(object(), query)))
                with self.assertRaises(privacy.LinuxPrivacyHold):
                    privacy.assert_native_private_filesystem("/selected/file.txt")
                self.assertEqual(opened.call_count, 2)
                query.assert_not_called()
                self.assertEqual(closed.call_count, 2)

    def test_query_failure_and_missing_path_close_handles_categorically(self):
        with ExitStack() as stack:
            observed, opened, closed = self.descriptor_mocks(stack)
            stack.enter_context(mock.patch.object(privacy, "_native_query", return_value=(object(), mock.Mock(return_value=-1))))
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.assert_native_private_filesystem("/selected/file.txt")
            self.assertEqual(caught.exception.code, "linux-private-filesystem-unavailable")
            self.assertEqual(closed.call_count, 3)

    def test_missing_exact_path_holds_without_a_native_query(self):
        with ExitStack() as stack:
            observed, opened, closed = self.descriptor_mocks(stack)
            stack.enter_context(mock.patch.object(privacy.os, "stat", side_effect=FileNotFoundError("sensitive fixture path")))
            query = mock.Mock()
            stack.enter_context(mock.patch.object(privacy, "_native_query", return_value=(object(), query)))
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.assert_native_private_filesystem("/selected/file.txt")
            self.assertEqual(str(caught.exception), "linux-private-path-unavailable")
            query.assert_not_called()
            self.assertEqual(closed.call_args_list, [mock.call(10)])

    def test_destination_filesystem_kind_from_an_open_descriptor(self):
        # tmpfs and ramfs live in memory and a read-only mount takes no backup: neither is a destination (D-069),
        # although tmpfs stays admitted for the private work folder.
        for filesystem, flags, kind in ((0xEF53, 0, "native"), (0x58465342, 0, "native"), (0x9123683E, 0, "native"),
                                        (0x01021994, 0, "other"), (0x858458F6, 0, "other"), (0xEF53, 1, "other"),
                                        (0x4D44, 1, "other"), (0x4D44, 0, "fat"), (0x2011BAB0, 0, "exfat"),
                                        (0x01021997, 0, "other"), (0x65735546, 0, "other"), (0xFE534D42, 0, "other"),
                                        (0, 0, "other")):
            with self.subTest(filesystem=hex(filesystem), flags=flags), \
                    mock.patch.object(privacy, "_native_query", return_value=(object(), self.query(filesystem, flags=flags))):
                self.assertEqual(privacy.filesystem_kind(41), kind)
        self.assertIsNone(self.call_mocked(0x01021994))
        with mock.patch.object(privacy, "_native_query", return_value=(object(), self.query(status=-1))):
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.filesystem_kind(41)
            self.assertEqual(caught.exception.code, "linux-private-filesystem-unavailable")
            for bad in (-1, "41", None, True):
                with self.subTest(descriptor=bad):
                    with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                        privacy.filesystem_kind(bad)
                    self.assertEqual(caught.exception.code, "linux-private-path-invalid")
        with mock.patch.object(privacy, "_supported_abi", return_value=False), mock.patch.object(privacy.ctypes, "CDLL") as loader:
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.filesystem_kind(41)
            self.assertEqual(caught.exception.code, "linux-private-abi-unavailable")
            loader.assert_not_called()

    @staticmethod
    def sysfs(links, files, folders=None):
        """Injected sysfs and procfs readers (descriptor 41) over fixed path tables; device numbers are major << 8 | minor."""
        folders = folders or {}

        def listdir(path):
            if path not in folders:
                raise FileNotFoundError(path)
            return folders[path]
        return {"realpath": lambda path: links.get(path, path), "read": files.get, "listdir": listdir}

    def numbers(self):
        stack = ExitStack()
        stack.enter_context(mock.patch.object(privacy.os, "major", lambda device: device >> 8, create=True))
        stack.enter_context(mock.patch.object(privacy.os, "minor", lambda device: device & 0xFF, create=True))
        return stack

    def test_fixed_and_physical_disks_need_sysfs_proof(self):
        pci = "/sys/devices/pci0000:00/0000:00:17.0"
        sda, nvme = pci + "/ata1/host0/target0:0:0/0:0:0:0/block/sda", pci + "/0000:3d:00.0/nvme/nvme0/nvme0n1"
        usb = "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host2/target2:0:0/2:0:0:0/block/sdb"
        thunderbolt = "/sys/devices/pci0000:00/0000:00:1c.0/0000:05:00.0/nvme/nvme1/nvme1n1"
        vda = "/sys/devices/pci0000:00/0000:00:05.0/virtio2/block/vda"
        reader = "/sys/devices/pci0000:00/0000:00:1c.4/0000:03:00.0"
        cases = {  # device: (whole-disk folder, proven fixed)
            "8:0": (sda, True), "259:2": (nvme, True), "8:16": (usb, False), "259:5": (thunderbolt, False),
            "252:0": (vda, True),
            "179:0": (reader + "/rtsx_pci_sdmmc.0/mmc_host/mmc0/mmc0:bbbb/block/mmcblk0", False),  # an SDcombo card
            "179:8": (reader + "/rtsx_pci_sdmmc.0/mmc_host/mmc0/mmc0:cccc/block/mmcblk1", False),  # no device/type
            "180:0": (reader + "/rtsx_pci_ms.0/memstick0/memstick0:0/block/mspblk0", False),  # Memory Stick
            "8:48": ("/sys/devices/platform/host3/session1/target3:0:0/3:0:0:0/block/sdd", False),  # iSCSI
            "8:64": ("/sys/devices/pci0000:00/0000:00:1e.0/0000:05:00.0/fw0/fw0.0/host4/target4:0:0/4:0:0:0/block/sde",
                     False),  # FireWire sbp2
            "251:0": ("/sys/devices/rbd/0/block/rbd0", False),  # Ceph RBD
            "202:0": ("/sys/devices/vbd-51712/block/xvda", True)}  # a Xen guest disk: fixed for the guest
        links = {"/sys/dev/block/" + text: folder for text, (folder, _fixed) in cases.items()}
        links |= {"/sys/dev/block/8:1": sda + "/sda1", "/sys/dev/block/253:0": "/sys/devices/virtual/block/dm-0"}
        files = {folder + "/removable": "0" for folder, _fixed in cases.values()}
        files |= {sda + "/sda1/partition": "1", reader + "/rtsx_pci_sdmmc.0/mmc_host/mmc0/mmc0:bbbb/block/mmcblk0/device/type":
                  "SDcombo", "/sys/devices/pci0000:00/0000:00:1c.0/0000:05:00.0/removable": "removable",
                  pci + "/0000:3d:00.0/nvme/nvme0/subsysnqn": "nqn.2014-08.org.example:drive-one",
                  "/proc/cpuinfo": "processor\t: 0\nflags\t\t: fpu vme sse2\n"}

        def device(text):
            major, minor = text.split(":")
            return int(major) << 8 | int(minor)
        with self.numbers():
            fixed = {text: privacy.fixed_disk(41, device=device(text), **self.sysfs(links, files)) for text in cases}
            self.assertEqual(fixed, {text: proven for text, (_folder, proven) in cases.items()})
            self.assertTrue(privacy.fixed_disk(41, device=device("8:1"), **self.sysfs(links, files)))  # a partition
            self.assertFalse(privacy.fixed_disk(41, device=device("253:0"), **self.sysfs(links, files)))  # no slaves/
            self.assertFalse(privacy.fixed_disk(41, device=45, **self.sysfs(links, files)))  # tmpfs, 9p: no fdinfo mnt_id
            self.assertFalse(privacy.fixed_disk(41, device=device("8:0"), **self.sysfs(links, {**files, sda + "/removable": "1"})))
            physical = {text: privacy.physical_disk(41, device=device(text), **self.sysfs(links, files))
                        for text in ("8:1", "8:0", "259:2", "252:0", "202:0", "253:0")}
            self.assertEqual(physical, {"8:1": sda, "8:0": sda, "259:2": "nvme:nqn.2014-08.org.example:drive-one",
                                        "252:0": None, "202:0": None, "253:0": None})  # virtio and Xen guests: unknown
            # No CPU flags line (an arm64 guest shows "Features"), no cpuinfo at all, or a hypervisor: never proven apart.
            for cpuinfo in ("processor\t: 0\nFeatures\t: fp asimd evtstrm\n", None, "flags\t\t: fpu sse2 hypervisor\n"):
                with self.subTest(cpuinfo=cpuinfo):
                    self.assertIsNone(privacy.physical_disk(41, device=device("8:0"),
                                                            **self.sysfs(links, {**files, "/proc/cpuinfo": cpuinfo})))
        self.assertIsNone(privacy._text(str(ROOT / "work" / ("absent-" + uuid.uuid4().hex))))

    def test_text_drops_a_line_cut_at_the_read_limit(self):
        folder = fixture_folder(self)
        (folder / "mountinfo").write_bytes(b"line one\nline two\nline three\n")
        with mock.patch.object(privacy, "_TEXT_LIMIT", 15):  # "line one\nline t" fills the limit
            self.assertEqual(privacy._text(str(folder / "mountinfo")), "line one")
        self.assertEqual(privacy._text(str(folder / "mountinfo")), "line one\nline two\nline three")

    def test_member_disks_behind_device_mapper_md_btrfs_and_nvme_heads(self):
        pci = "/sys/devices/pci0000:00/0000:00:1d.0"
        nvme, sda, sdb = pci + "/0000:3d:00.0/nvme/nvme0/nvme0n1", pci + "/ata1/host0/target0:0:0/0:0:0:0/block/sda", \
            pci + "/ata2/host1/target1:0:0/1:0:0:0/block/sdb"
        usb = "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host2/target2:0:0/2:0:0:0/block/sdc"
        md = "/sys/devices/virtual/block/md0"
        links = {"/sys/dev/block/253:0": "/sys/devices/virtual/block/dm-0", "/sys/dev/block/253:1": "/sys/devices/virtual/block/dm-1",
                 "/sys/dev/block/259:8": md + "/md0p1", "/sys/dev/block/259:0": "/sys/devices/virtual/nvme-subsystem/nvme-subsys0/nvme0n1",
                 "/sys/class/block/nvme0n1p3": nvme + "/nvme0n1p3", "/sys/class/block/sda2": sda + "/sda2",
                 "/sys/class/block/sda3": sda + "/sda3", "/sys/class/block/sda4": sda + "/sda4", "/sys/class/block/sdb1": sdb + "/sdb1", "/sys/class/block/sdc1": usb + "/sdc1",
                 "/dev/sda2": "/dev/sda2", "/dev/sdc1": "/dev/sdc1", "/dev/disk/by-label/my disk": "/dev/sdb1"}
        files = {nvme + "/nvme0n1p3/partition": "3", sda + "/sda2/partition": "2", sda + "/sda3/partition": "3",
                 sda + "/sda4/partition": "4",
                 sdb + "/sdb1/partition": "1", usb + "/sdc1/partition": "1", md + "/md0p1/partition": "1",
                 nvme + "/removable": "0", sda + "/removable": "0", sdb + "/removable": "0", usb + "/removable": "0",
                 pci + "/0000:3d:00.0/nvme/nvme0/subsysnqn": "nqn.2014-08.org.example:drive-one",
                 "/proc/cpuinfo": "flags\t: fpu\n",
                 # Field 3 is the superblock's anonymous device; a btrfs subvolume's st_dev is another one (0:52 here).
                 "/proc/self/mountinfo": "22 1 0:40 / / rw,relatime shared:1 - btrfs /dev/sda2 rw,subvol=/root\n"
                                         "23 1 0:41 / /data rw - btrfs /dev/sdc1 rw\n24 1 0:42 / /run rw - tmpfs tmpfs rw\n"
                                         "25 1 0:43 / /media rw - btrfs /dev/disk/by-label/my\\040disk rw\n"
                                         "26 1 0:44 / /home rw - btrfs /dev/sda3 rw\n"}
        folders = {"/sys/devices/virtual/block/dm-0/slaves": ["nvme0n1p3"], "/sys/devices/virtual/block/dm-1/slaves": ["sda2", "sda3"],
                   md + "/slaves": ["sda3", "sdb1"], "/sys/devices/virtual/nvme-subsystem/nvme-subsys0/nvme0n1/slaves": [],
                   "/sys/fs/btrfs": ["5f0e-two", "9a1c-usb", "c3d4-label", "e5f6-one-disk"],
                   "/sys/fs/btrfs/e5f6-one-disk/devices": ["sda4", "sda3"], "/sys/fs/btrfs/5f0e-two/devices": ["sdb1", "sda2"],
                   "/sys/fs/btrfs/9a1c-usb/devices": ["sdc1", "sda2x"], "/sys/fs/btrfs/c3d4-label/devices": ["sdb1"]}

        def mounted(mount_id):
            return {**files, "/proc/self/fdinfo/41": f"pos:\t0\nflags:\t02100000\nmnt_id:\t{mount_id}\nino:\t256\n"}
        with self.numbers():
            facts = self.sysfs(links, files, folders)
            # LUKS (device-mapper) on NVMe, LVM over two partitions of one disk, and an md partition (md0p1, which has no
            # slaves/ of its own) are fixed: every member disk is.
            self.assertTrue(privacy.fixed_disk(41, device=253 << 8, **facts))
            self.assertTrue(privacy.fixed_disk(41, device=253 << 8 | 1, **facts))
            self.assertTrue(privacy.fixed_disk(41, device=259 << 8 | 8, **facts))
            self.assertFalse(privacy.fixed_disk(41, device=253 << 8, **{**facts, "listdir": lambda path: ["nvme0n1p3", "loop0"]
                                                                         if path.endswith("slaves") else facts["listdir"](path)}))
            # An NVMe multipath head node has an empty slaves/: not proven.
            self.assertFalse(privacy.fixed_disk(41, device=259 << 8, **facts))
            self.assertIsNone(privacy.physical_disk(41, device=259 << 8, **facts))
            # btrfs is found through the descriptor's mnt_id, never through mountinfo's device field.
            self.assertTrue(privacy.fixed_disk(41, device=52, **self.sysfs(links, mounted(22), folders)))
            self.assertTrue(privacy.fixed_disk(41, device=53, **self.sysfs(links, mounted(25), folders)))  # \040 escaped
            self.assertFalse(privacy.fixed_disk(41, device=40, **self.sysfs(links, mounted(99), folders)))  # field 3 only
            self.assertFalse(privacy.fixed_disk(41, device=40, **facts))  # no fdinfo mnt_id: fails closed
            self.assertFalse(privacy.fixed_disk(41, device=54, **self.sysfs(links, mounted(23), folders)))  # a USB member
            self.assertFalse(privacy.fixed_disk(41, device=55, **self.sysfs(links, mounted(24), folders)))  # tmpfs
            # One disk under several members is one physical disk; a file system spanning two disks is none.
            self.assertEqual(privacy.physical_disk(41, device=253 << 8 | 1, **facts), sda)
            self.assertIsNone(privacy.physical_disk(41, device=52, **self.sysfs(links, mounted(22), folders)))
            self.assertEqual(privacy.physical_disk(41, device=56, **self.sysfs(links, mounted(26), folders)), sda)
            self.assertIsNone(privacy.physical_disk(41, device=259 << 8 | 8, **facts))
            self.assertEqual(privacy.physical_disk(41, device=253 << 8, **facts), "nvme:nqn.2014-08.org.example:drive-one")

    def test_nvme_subsystems_mmc_cards_and_hyper_v_disks(self):
        first = "/sys/devices/pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0"
        second = "/sys/devices/pci0000:00/0000:00:1d.0/0000:3d:00.1/nvme/nvme1"  # the drive's second port
        other = "/sys/devices/pci0000:00/0000:00:1c.0/0000:3e:00.0/nvme/nvme2"
        emmc = "/sys/devices/platform/80860F14:00/mmc_host/mmc1/mmc1:0001"
        hyperv = "/sys/devices/LNXSYSTM:00/LNXSYBUS:00/ACPI0004:00/MSFT1000:00/f1d2-guid/host0/target0:0:0/0:0:0:3/block/sdd"
        links = {"/sys/dev/block/259:1": first + "/nvme0n1", "/sys/dev/block/259:2": first + "/nvme0n2",
                 "/sys/dev/block/259:3": second + "/nvme1n1", "/sys/dev/block/259:4": other + "/nvme2n1",
                 "/sys/dev/block/179:0": emmc + "/block/mmcblk1", "/sys/dev/block/179:8": emmc + "/block/mmcblk1boot0",
                 emmc + "/block/mmcblk1/device": emmc, emmc + "/block/mmcblk1boot0/device": emmc, "/sys/dev/block/8:48": hyperv}
        files = {first + "/subsysnqn": "nqn.2014-08.org.example:drive-one", second + "/subsysnqn": "nqn.2014-08.org.example:drive-one",
                 other + "/subsysnqn": "nqn.2014-08.org.example:drive-two", "/proc/cpuinfo": "processor\t: 0\nflags\t\t: fpu sse2\n"}
        with self.numbers():
            identity = {minor: privacy.physical_disk(41, device=259 << 8 | minor, **self.sysfs(links, files)) for minor in (1, 2, 3, 4)}
            # Namespaces and controllers of one subsystem (one NQN) are one disk; another NQN is another disk.
            self.assertEqual(identity, {1: "nvme:nqn.2014-08.org.example:drive-one", 2: "nvme:nqn.2014-08.org.example:drive-one",
                                        3: "nvme:nqn.2014-08.org.example:drive-one", 4: "nvme:nqn.2014-08.org.example:drive-two"})
            unnamed = {key: value for key, value in files.items() if key != other + "/subsysnqn"}
            self.assertIsNone(privacy.physical_disk(41, device=259 << 8 | 4, **self.sysfs(links, unnamed)))
            # An eMMC card's boot area is a separate block device of the same card.
            cards = [privacy.physical_disk(41, device=179 << 8 | minor, **self.sysfs(links, files)) for minor in (0, 8)]
            self.assertEqual(cards, [emmc, emmc])
            self.assertIsNone(privacy.physical_disk(41, device=8 << 8 | 48, **self.sysfs(links, files)))  # Hyper-V (WSL)

    def test_replaced_named_leaf_cannot_hide_behind_the_pinned_descriptor(self):
        with ExitStack() as stack:
            observed, opened, closed = self.descriptor_mocks(stack)
            changed = False
            def named(name, *, dir_fd, follow_symlinks):
                if changed and (dir_fd, name) == (11, "file.txt"):
                    return info(inode=999, directory=False)
                return observed[{(10, "selected"): 11, (11, "file.txt"): 12}[dir_fd, name]]
            stack.enter_context(mock.patch.object(privacy.os, "stat", side_effect=named))
            def query(fd, output):
                nonlocal changed
                changed = True
                ctypes.cast(output, ctypes.POINTER(privacy._StatFS)).contents.f_type = 0xEF53
                return 0
            stack.enter_context(mock.patch.object(privacy, "_native_query", return_value=(object(), query)))
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.assert_native_private_filesystem("/selected/file.txt")
            self.assertEqual(caught.exception.code, "linux-private-path-changed")
            self.assertEqual(closed.call_count, 3)


# File system type names in /proc/self/mountinfo: the ones _NATIVE_TYPES admits (ext2/3/4 share one magic number),
# and the mounts WSL uses for Windows drives.
NATIVE_MOUNTS = frozenset({"ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs", "ramfs"})
WINDOWS_BACKED = frozenset({"9p", "drvfs", "v9fs", "virtiofs"})


def mount_type(path):
    """The file system type /proc/self/mountinfo gives the mount holding ``path`` (the longest mount point that
    contains it; a later line for the same mount point is the mount on top). Decided without the product."""
    target, best, kind = os.path.realpath(path), -1, None
    with open("/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape") as stream:
        for line in stream:
            fields = line.split()
            point = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
            inside = target == point or target.startswith(point.rstrip("/") + "/")
            if inside and len(point) >= best:
                best, kind = len(point), fields[fields.index("-") + 1]
    return kind


def fixture_folder(test):
    folder = ROOT / "work" / "test-fixtures" / "filesystem" / ("privacy-fs-" + uuid.uuid4().hex)
    folder.mkdir(parents=True, mode=0o700)
    test.addCleanup(shutil.rmtree, folder)
    return folder


@unittest.skipUnless(os.name == "posix" and sys.platform == "linux", "only on linux: native Linux runtime")
class NativeSelectedRootTests(unittest.TestCase):
    def test_actual_owned_selected_filesystem_is_admitted_or_explicitly_foreign(self):
        fixture = fixture_folder(self)
        if not privacy._supported_abi():
            # Outside the reviewed x86-64 LP64 ABI the gate holds instead of guessing a struct layout.
            expected = "linux-private-abi-unavailable"
        else:
            expected = None if mount_type(fixture) in NATIVE_MOUNTS else "linux-private-foreign-filesystem"
        if expected is None:
            self.assertIsNone(privacy.assert_native_private_filesystem(fixture))
        else:
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.assert_native_private_filesystem(fixture)
            self.assertEqual(caught.exception.code, expected)


@unittest.skipUnless(sys.platform.startswith("linux"), "only on linux: /proc/self/mountinfo and the Linux privacy gate")
class DrvfsHoldTests(unittest.TestCase):
    """On a Windows-backed WSL mount (9p, DrvFS, virtiofs) PatchCairn holds before writing any private data; on a
    native file system it admits. Which one the fixture folder is on comes from /proc/self/mountinfo (plan #58)."""

    def test_private_storage_holds_on_wsl_drvfs(self):
        import private_workspace
        import scoped_fs
        fixture = fixture_folder(self)
        target, kind = fixture / "private", mount_type(fixture)
        foreign = kind in WINDOWS_BACKED or kind not in NATIVE_MOUNTS
        reason = "abi-unavailable" if not privacy._supported_abi() else "foreign-filesystem" if foreign else None
        if reason is None:
            self.assertIsNone(privacy.assert_native_private_filesystem(fixture))
            self.assertEqual(private_workspace.ensure_private_directory(target, create=True), target)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            if kind in ("tmpfs", "ramfs"):  # memory: the work folder may live there, a backup never (D-069)
                with self.assertRaises(scoped_fs.ScopedFSError) as caught:
                    scoped_fs.admit_destination(str(fixture), non_private_destination=True)
                self.assertEqual(caught.exception.code, "destination-volume-unsupported")
                return
            with scoped_fs.admit_destination(str(fixture), non_private_destination=True) as root:
                self.assertEqual((root.destination, root.privacy_note is None), (True, root.private))
            return
        with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
            privacy.assert_native_private_filesystem(fixture)
        self.assertEqual(caught.exception.code, "linux-private-" + reason)
        with self.assertRaises(private_workspace.PrivateWorkspaceError) as caught:
            private_workspace.ensure_private_directory(target, create=True)
        self.assertEqual(caught.exception.code, "private-linux-" + reason)
        self.assertFalse(target.exists())
        with self.assertRaises(scoped_fs.ScopedFSError) as caught:
            scoped_fs.admit_destination(str(fixture), non_private_destination=True)
        self.assertEqual(caught.exception.code, "destination-volume-unsupported" if reason == "foreign-filesystem"
                         else "filesystem-capability-unavailable")
        self.assertEqual(os.listdir(fixture), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
