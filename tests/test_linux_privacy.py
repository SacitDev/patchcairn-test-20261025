"""Native-filesystem privacy gate: mocks plus owned WSL/Linux scope only."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
import os
from pathlib import Path
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
    def query(self, filesystem=0xEF53, status=0):
        def invoke(fd, output):
            self.assertEqual(fd, 41)
            ctypes.cast(output, ctypes.POINTER(privacy._StatFS)).contents.f_type = filesystem
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
            with self.subTest(filesystem=filesystem), self.assertRaises(privacy.LinuxPrivacyHold) as caught:
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


@unittest.skipUnless(os.name == "posix" and sys.platform == "linux", "Native Linux runtime unavailable")
class NativeSelectedRootTests(unittest.TestCase):
    def test_actual_owned_selected_filesystem_is_admitted_or_explicitly_foreign(self):
        if not privacy._supported_abi():
            self.skipTest("Actual Linux ABI is outside the reviewed x86-64 LP64 scope")
        fixture = ROOT / "work" / "upgrade_v3" / "filesystem" / "privacy_fs" / ("fixture-" + uuid.uuid4().hex)
        fixture.mkdir(parents=True, mode=0o700)
        expected_foreign = "microsoft" in os.uname().release.casefold() and str(ROOT).startswith("/mnt/")
        if expected_foreign:
            with self.assertRaises(privacy.LinuxPrivacyHold) as caught:
                privacy.assert_native_private_filesystem(fixture)
            self.assertEqual(caught.exception.code, "linux-private-foreign-filesystem")
        else:
            try:
                privacy.assert_native_private_filesystem(fixture)
            except privacy.LinuxPrivacyHold as error:
                if error.code != "linux-private-foreign-filesystem":
                    raise
                self.skipTest("Actual selected filesystem is outside the reviewed native allowlist")


if __name__ == "__main__":
    unittest.main(verbosity=2)
