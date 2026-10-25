"""Mocked Apple ACL admission; no real ACL/permission mutation or Mac claim.

Run: python -I -S -B tests/test_darwin_privacy.py
The APIs and paths are mocked. Native macOS validation remains separate.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
import errno
from pathlib import Path, PurePosixPath
import stat
import sys
import traceback
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import darwin_privacy as privacy
import private_workspace as private


def info(**changes):
    values = dict(st_dev=7, st_ino=101, st_mode=stat.S_IFDIR | 0o700,
                  st_uid=1001, st_gid=1001, st_nlink=2, st_size=64,
                  st_mtime_ns=1000, st_ctime_ns=2000)
    values.update(changes)
    return types.SimpleNamespace(**values)


class DarwinPrivacyTests(unittest.TestCase):
    path = "/fictional/private-workspace"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(privacy.os, "name", "posix"))
        self.stack.enter_context(mock.patch.object(privacy.sys, "platform", "darwin"))
        self.metadata = self.stack.enter_context(mock.patch.object(privacy.os, "lstat", return_value=info()))
        self.library = types.SimpleNamespace(acl_get_file=mock.Mock(return_value=0x12340),
                                             acl_valid=mock.Mock(return_value=0),
                                             acl_get_entry=mock.Mock(side_effect=self.empty_entry),
                                             acl_free=mock.Mock(return_value=0))
        self.loader = self.stack.enter_context(mock.patch.object(privacy.ctypes, "CDLL", return_value=self.library))

    @staticmethod
    def empty_entry(acl, entry_id, output):
        ctypes.set_errno(errno.EINVAL)
        return -1

    def assert_hold(self, code, path=None):
        with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
            privacy.assert_no_extended_acl(self.path if path is None else path)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)
        return caught.exception

    def test_valid_empty_acl_uses_exact_readonly_apple_interface(self):
        self.assertIsNone(privacy.assert_no_extended_acl(self.path))
        self.loader.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
        self.library.acl_get_file.assert_called_once_with(b"/fictional/private-workspace", 0x00000100)
        self.library.acl_valid.assert_called_once_with(0x12340)
        self.assertEqual(self.library.acl_get_entry.call_args.args[:2], (0x12340, 0))
        self.library.acl_free.assert_called_once_with(0x12340)
        self.assertEqual(self.library.acl_get_file.argtypes, (ctypes.c_char_p, ctypes.c_int))
        self.assertIs(self.library.acl_get_file.restype, ctypes.c_void_p)
        self.assertEqual(self.library.acl_valid.argtypes, (ctypes.c_void_p,))
        self.assertIs(self.library.acl_valid.restype, ctypes.c_int)
        self.assertEqual(self.library.acl_get_entry.argtypes,
                         (ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)))
        self.assertIs(self.library.acl_get_entry.restype, ctypes.c_int)
        self.assertEqual(self.library.acl_free.argtypes, (ctypes.c_void_p,))
        self.assertIs(self.library.acl_free.restype, ctypes.c_int)
        self.assertEqual(self.metadata.call_count, 2)

    def test_descriptor_acl_check_reads_the_open_object(self):
        self.library.acl_get_fd_np = mock.Mock(return_value=0x12340)
        held = info(st_mode=stat.S_IFREG | 0o600, st_nlink=1)
        with mock.patch.object(privacy.os, "fstat", return_value=held) as fstat:
            self.assertIsNone(privacy.assert_no_extended_acl_fd(17))
            self.library.acl_get_fd_np.assert_called_once_with(17, 0x00000100)
            self.assertEqual(self.library.acl_get_fd_np.argtypes, (ctypes.c_int, ctypes.c_int))
            self.assertIs(self.library.acl_get_fd_np.restype, ctypes.c_void_p)
            self.assertEqual(fstat.call_args_list, [mock.call(17), mock.call(17)])
            self.metadata.assert_not_called()  # no path is resolved
            self.library.acl_get_fd_np.side_effect = lambda *_: (ctypes.set_errno(errno.ENOENT), None)[1]
            self.assertIsNone(privacy.assert_no_extended_acl_fd(17))  # an absent ACL property
            self.library.acl_get_fd_np.side_effect = None
            self.library.acl_get_entry.side_effect = lambda acl, entry_id, output: 0
            with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
                privacy.assert_no_extended_acl_fd(17)
            self.assertEqual(caught.exception.code, "darwin-acl-not-empty")
            self.library.acl_get_entry.side_effect = self.empty_entry
            fstat.side_effect = [held, info(st_mode=held.st_mode, st_nlink=1, st_ino=999)]
            with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
                privacy.assert_no_extended_acl_fd(17)
            self.assertEqual(caught.exception.code, "darwin-acl-path-changed")
        for bad in (-1, "17", None, True):
            with self.subTest(descriptor=bad):
                with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
                    privacy.assert_no_extended_acl_fd(bad)
                self.assertEqual(caught.exception.code, "darwin-acl-path-invalid")
        del self.library.acl_get_fd_np
        with mock.patch.object(privacy.os, "fstat", return_value=held), self.assertRaises(privacy.DarwinPrivacyHold) as caught:
            privacy.assert_no_extended_acl_fd(17)
        self.assertEqual(caught.exception.code, "darwin-acl-api-unavailable")

    def test_source_verified_missing_acl_property_on_same_object_passes(self):
        def no_property(*_):
            ctypes.set_errno(errno.ENOENT)
            return None
        self.library.acl_get_file.side_effect = no_property
        self.assertIsNone(privacy.assert_no_extended_acl(self.path))
        self.assertEqual(self.metadata.call_count, 2)
        self.library.acl_valid.assert_not_called()
        self.library.acl_get_entry.assert_not_called()
        self.library.acl_free.assert_not_called()

    def test_no_property_requires_same_device_inode_owner_mode_size_change_time(self):
        self.library.acl_get_file.side_effect = lambda *_: (ctypes.set_errno(errno.ENOENT), None)[1]
        for field in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink"):
            before = info()
            after = info(**{field: getattr(before, field) + 1})
            self.metadata.side_effect = [before, after]
            with self.subTest(field=field):
                self.assert_hold("darwin-acl-path-changed")

    def test_no_property_cannot_hide_missing_or_linked_post_path(self):
        self.library.acl_get_file.side_effect = lambda *_: (ctypes.set_errno(errno.ENOENT), None)[1]
        self.metadata.side_effect = [info(), FileNotFoundError("fictional sensitive path")]
        self.assert_hold("darwin-acl-path-unavailable")
        self.metadata.side_effect = [info(), info(st_mode=stat.S_IFLNK | 0o777)]
        self.assert_hold("darwin-acl-ordinary-path-required")

    def test_other_null_states_are_holds_including_errno_zero_and_unsupported(self):
        for code in (0, errno.EACCES, errno.EINVAL, errno.ENOMEM, errno.ENOTSUP, errno.EIO):
            self.library.acl_get_file.side_effect = lambda *_, code=code: (ctypes.set_errno(code), None)[1]
            with self.subTest(code=code):
                self.assert_hold("darwin-acl-read-unavailable")
        self.library.acl_free.assert_not_called()

    def test_null_with_stale_enoent_is_not_absence(self):
        ctypes.set_errno(errno.ENOENT)
        self.library.acl_get_file.return_value = None
        self.assert_hold("darwin-acl-read-unavailable")

    def test_any_acl_entry_is_held_without_reading_principals_or_permissions(self):
        for pointer in (None, 0x23450):
            def entry(_acl, _entry_id, output, pointer=pointer):
                ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = pointer
                return 0
            self.library.acl_get_entry.side_effect = entry
            with self.subTest(pointer=pointer):
                self.assert_hold("darwin-acl-not-empty")
        self.assertEqual(self.library.acl_free.call_count, 2)

    def test_acl_must_validate_before_empty_einval_is_recognized(self):
        for result in (-1, 1):
            self.library.acl_valid.return_value = result
            with self.subTest(result=result):
                self.assert_hold("darwin-acl-invalid")
        self.library.acl_get_entry.assert_not_called()
        self.assertEqual(self.library.acl_free.call_count, 2)

    def test_unknown_entry_returns_and_errno_are_held(self):
        for result, code, pointer in ((1, 0, None), (-1, 0, None), (-1, errno.EACCES, None),
                                      (-1, errno.EINVAL, 0x23450), (-2, errno.EINVAL, None)):
            def unknown(_acl, _entry_id, output, result=result, code=code, pointer=pointer):
                ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = pointer
                ctypes.set_errno(code)
                return result
            self.library.acl_get_entry.side_effect = unknown
            with self.subTest(result=result, code=code, pointer=pointer):
                self.assert_hold("darwin-acl-state-unavailable")

    def test_stale_einval_is_cleared_before_entry_call(self):
        self.library.acl_valid.side_effect = lambda *_: (ctypes.set_errno(errno.EINVAL), 0)[1]
        self.library.acl_get_entry.side_effect = None
        self.library.acl_get_entry.return_value = -1
        self.assert_hold("darwin-acl-state-unavailable")

    def test_release_failure_is_a_hold_and_never_a_permission_change(self):
        self.library.acl_free.return_value = -1
        self.assert_hold("darwin-acl-release-unavailable")

    def test_native_call_error_frees_allocated_acl_and_hides_raw_text(self):
        self.library.acl_get_entry.side_effect = OSError("sensitive-account-path-and-acl")
        caught = self.assert_hold("darwin-acl-call-unavailable")
        self.assertTrue(caught.__suppress_context__)
        self.assertNotIn("sensitive-account-path-and-acl", "".join(traceback.format_exception(caught)))
        self.library.acl_free.assert_called_once_with(0x12340)

    def test_missing_library_and_every_required_symbol_hold(self):
        self.loader.side_effect = OSError("fictional private native loader text")
        self.assert_hold("darwin-acl-api-unavailable")
        self.loader.side_effect = None
        for missing in ("acl_get_file", "acl_valid", "acl_get_entry", "acl_free"):
            library = types.SimpleNamespace(**{name: value for name, value in vars(self.library).items() if name != missing})
            self.loader.return_value = library
            with self.subTest(missing=missing):
                self.assert_hold("darwin-acl-api-unavailable")

    def test_foreign_platform_and_old_python_hold_before_any_path_or_library_access(self):
        for os_name, platform, version in (("nt", "win32", (3, 14)), ("posix", "linux", (3, 12)),
                                          ("posix", "darwin", (3, 11))):
            self.metadata.reset_mock()
            self.loader.reset_mock()
            with self.subTest(platform=platform, version=version), mock.patch.object(privacy.os, "name", os_name), \
                    mock.patch.object(privacy.sys, "platform", platform), mock.patch.object(privacy.sys, "version_info", version):
                self.assert_hold("darwin-acl-platform-unavailable")
            self.metadata.assert_not_called()
            self.loader.assert_not_called()

    def test_invalid_literal_path_holds_before_metadata_access(self):
        for path in ("relative", "/", "//ambiguous", "/safe/../other", "/safe/./other", "/safe/", "/safe//other", "/safe\x00other", 42):
            with self.subTest(path=path):
                self.assert_hold("darwin-acl-path-invalid", path=path)
        self.metadata.assert_not_called()
        self.loader.assert_not_called()

    def test_symlink_hardlink_special_and_unknown_identity_hold_before_acl_query(self):
        for bad in (info(st_mode=stat.S_IFLNK | 0o777), info(st_mode=stat.S_IFREG | 0o600, st_nlink=2),
                    info(st_mode=stat.S_IFIFO | 0o600), info(st_ino=0)):
            self.metadata.return_value = bad
            with self.subTest(mode=bad.st_mode, inode=bad.st_ino), self.assertRaises(privacy.DarwinPrivacyHold):
                privacy.assert_no_extended_acl(self.path)
        self.loader.assert_not_called()

    def test_valid_empty_acl_also_requires_unchanged_ordinary_path(self):
        self.metadata.side_effect = [info(), info(st_ctime_ns=2001)]
        self.assert_hold("darwin-acl-path-changed")
        self.library.acl_free.assert_called_once_with(0x12340)

    def test_single_link_ordinary_file_can_be_checked_without_opening_content(self):
        self.metadata.return_value = info(st_mode=stat.S_IFREG | 0o600, st_nlink=1)
        with mock.patch.object(privacy.os, "open", side_effect=AssertionError("content opened")):
            self.assertIsNone(privacy.assert_no_extended_acl(self.path))


class DarwinConsumerContractTests(unittest.TestCase):
    """Run on every CI platform; model paths and ACL calls without host access."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(private.os, "name", "posix"))
        self.stack.enter_context(mock.patch.object(private.sys, "platform", "darwin"))
        self.stack.enter_context(mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True))
        self.stack.enter_context(mock.patch.object(private.os, "geteuid", return_value=1001, create=True))
        self.volume = self.stack.enter_context(mock.patch.object(privacy, "assert_private_filesystem"))

    def test_missing_acl_checker_holds_before_path_admission_or_allocation(self):
        with mock.patch.dict(sys.modules, {"darwin_privacy": None}), mock.patch.object(private, "_absolute") as absolute:
            with self.assertRaises(private.PrivateWorkspaceError) as caught:
                private.ensure_private_directory("/fictional/new-private", create=True)
            self.assertEqual(caught.exception.code, "private-darwin-acl-capability-unavailable")
            absolute.assert_not_called()

    def test_existing_private_object_requires_actual_acl_observation_and_categorical_refusal(self):
        metadata = info(st_mode=stat.S_IFREG | 0o600, st_nlink=1)
        path = types.SimpleNamespace(lstat=lambda: metadata)
        with mock.patch.object(privacy, "assert_no_extended_acl") as checker, mock.patch.object(private.os, "open") as opened:
            self.assertIs(private._posix_info(path, directory=False, private=True), metadata)
            checker.assert_called_once_with(path)
            opened.assert_not_called()
        for code in ("darwin-acl-not-empty", "darwin-acl-read-unavailable", "darwin-acl-path-changed"):
            with self.subTest(code=code), mock.patch.object(privacy, "assert_no_extended_acl", side_effect=privacy.DarwinPrivacyHold(code)):
                with self.assertRaises(private.PrivateWorkspaceError) as caught:
                    private._posix_info(path, directory=False, private=True)
                self.assertEqual(caught.exception.code, "private-" + code)

    def test_new_directory_acl_is_admitted_before_any_payload(self):
        created = set()
        class ModelPath(PurePosixPath):
            def lstat(value):
                if value.name == "new-private" and str(value) not in created:
                    raise FileNotFoundError()
                return info()
            def mkdir(value, *, mode):
                self.assertEqual(mode, 0o700)
                created.add(str(value))
        target = ModelPath("/fictional/new-private")
        payload = mock.Mock()
        with mock.patch.object(private, "Path", ModelPath), mock.patch.object(private, "_absolute", return_value=target), \
                mock.patch.object(privacy, "assert_no_extended_acl", side_effect=privacy.DarwinPrivacyHold("darwin-acl-not-empty")):
            with self.assertRaises(private.PrivateWorkspaceError):
                with private.private_directory(target, create=True):
                    payload()
        self.assertIn(str(target), created)
        payload.assert_not_called()
        with mock.patch.object(private, "Path", ModelPath), mock.patch.object(private, "_absolute", return_value=target), \
                mock.patch.object(privacy, "assert_no_extended_acl") as checker:
            with private.private_directory(target):
                self.assertTrue(checker.called)
                payload()
        payload.assert_called_once()

    def test_ignored_ownership_parent_holds_before_directory_allocation(self):
        allocated = mock.Mock()
        class ModelPath(PurePosixPath):
            def lstat(value):
                if value.name == "new-private":
                    raise FileNotFoundError()
                return info()
            def mkdir(value, *, mode):
                allocated()
        target = ModelPath("/fictional/new-private")
        self.volume.side_effect = privacy.DarwinPrivacyHold("darwin-fs-ownership-ignored")
        with mock.patch.object(private, "Path", ModelPath), mock.patch.object(private, "_absolute", return_value=target):
            with self.assertRaises(private.PrivateWorkspaceError) as caught:
                private.ensure_private_directory(target, create=True)
        self.assertEqual(caught.exception.code, "private-darwin-fs-ownership-ignored")
        allocated.assert_not_called()

    def test_new_file_acl_is_admitted_before_first_byte(self):
        metadata = info(st_mode=stat.S_IFREG | 0o600, st_nlink=1)
        path = types.SimpleNamespace(parent="fictional-private-parent", lstat=lambda: metadata)
        @contextmanager
        def admitted_parent(*args, **kwargs):
            yield "fictional-private-parent"
        with mock.patch.object(private, "_absolute", return_value=path), mock.patch.object(private, "private_directory", new=admitted_parent), \
                mock.patch.object(private.os, "open", return_value=19), mock.patch.object(private.os, "fstat", return_value=metadata), \
                mock.patch.object(private.os, "close") as close, mock.patch.object(private.os, "write") as writer, \
                mock.patch.object(privacy, "assert_no_extended_acl", side_effect=privacy.DarwinPrivacyHold("darwin-acl-not-empty")):
            with self.assertRaises(private.PrivateWorkspaceError):
                private.write_private_new(path, b"Fictional bytes")
            writer.assert_not_called()
            close.assert_called_once_with(19)
        with mock.patch.object(private, "_absolute", return_value=path), mock.patch.object(private, "private_directory", new=admitted_parent), \
                mock.patch.object(private.os, "open", return_value=19), mock.patch.object(private.os, "fstat", return_value=metadata), \
                mock.patch.object(private.os, "close"), mock.patch.object(private.os, "fsync"), \
                mock.patch.object(privacy, "assert_no_extended_acl") as checker:
            def accept(handle, data):
                self.assertTrue(checker.called)
                return len(data)
            with mock.patch.object(private.os, "write", side_effect=accept) as writer:
                private.write_private_new(path, b"Fictional bytes")
                writer.assert_called_once()


class DarwinFilesystemTests(unittest.TestCase):
    """Mock source-verified volume ABI; do not query any development-host mount."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.kind, self.flags, self.extended, self.subtype = b"apfs", 0x1000, 0, 0
        def query(descriptor, output):
            self.assertEqual(descriptor, 17)
            result = ctypes.cast(output, ctypes.POINTER(privacy._StatFS64)).contents
            result.f_fstypename, result.f_flags, result.f_flags_ext = self.kind, self.flags, self.extended
            result.f_fssubtype = self.subtype
            return 0
        self.query = mock.Mock(side_effect=query)
        self.api = self.stack.enter_context(mock.patch.object(privacy, "_volume_api", return_value=(object(), self.query)))
        @contextmanager
        def descriptor(path):
            self.assertEqual(path, "/fictional/private")
            yield 17
        self.descriptor = self.stack.enter_context(mock.patch.object(privacy, "_volume_descriptor", side_effect=descriptor))

    def assert_hold(self, code, path="/fictional/private"):
        with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
            privacy.assert_private_filesystem(path)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_source_verified_modern_statfs_layout_and_flags(self):
        self.assertEqual(ctypes.sizeof(privacy._StatFS64), 2168)
        self.assertEqual(ctypes.alignment(privacy._StatFS64), 8)
        self.assertEqual(privacy._StatFS64.f_flags.offset, 64)
        self.assertEqual(privacy._StatFS64.f_fstypename.offset, 72)
        self.assertEqual(privacy._StatFS64.f_flags_ext.offset, 2136)
        self.assertEqual(privacy._MNT_IGNORE_OWNERSHIP, 0x00200000)
        self.assertEqual(privacy._O_EVTONLY, 0x8000)

    def test_local_apfs_and_hfs_with_ownership_enforcement_pass(self):
        for self.kind in (b"apfs", b"hfs"):
            with self.subTest(kind=self.kind):
                self.assertIsNone(privacy.assert_private_filesystem("/fictional/private"))
        for self.subtype in (0, 1, 2, 3):
            self.assertIsNone(privacy.assert_private_filesystem("/fictional/private"))

    def test_ignored_ownership_is_held_even_for_local_apfs_or_hfs(self):
        self.flags |= 0x00200000
        for self.kind in (b"apfs", b"hfs"):
            with self.subTest(kind=self.kind):
                self.assert_hold("darwin-fs-ownership-ignored")

    def test_unknown_network_and_emulated_filesystems_are_held(self):
        for self.kind in (b"exfat", b"msdos", b"smbfs", b"nfs", b"osxfuse", b"unknown", b""):
            with self.subTest(kind=self.kind):
                self.assert_hold("darwin-fs-unsupported-filesystem")
        self.kind, self.flags = b"apfs", 0
        self.assert_hold("darwin-fs-unsupported-filesystem")
        self.flags, self.extended = 0x1000, 2
        self.assert_hold("darwin-fs-unsupported-filesystem")
        self.extended, self.flags = 0, 0x1001
        self.assert_hold("darwin-fs-unsupported-filesystem")
        self.kind, self.flags = b"hfs", 0x1000
        for self.subtype in (4, 127, 128, 0xFFFFFFFF):
            self.assert_hold("darwin-fs-unsupported-filesystem")

    def test_destination_volume_kind_from_an_open_descriptor(self):
        # removable: MNT_REMOVABLE (external drives, disk images) or "ignore ownership" (set on external drives).
        for self.kind, self.flags, self.extended, expected in (
                (b"apfs", 0x1000, 0, ("native", False)), (b"hfs", 0x1000, 0, ("native", False)),
                (b"apfs", 0x1000 | 0x00200000, 0, ("native", True)), (b"apfs", 0x1000 | 0x200, 0, ("native", True)),
                (b"hfs", 0x1000 | 0x200, 0, ("native", True)), (b"msdos", 0x1000 | 0x200, 0, ("fat", True)),
                (b"msdos", 0x1000 | 0x00200000, 0, ("fat", True)), (b"exfat", 0x1000, 2, ("exfat", False)),
                (b"apfs", 0x1000, 2, ("other", False)), (b"apfs", 0x1001, 0, ("other", False)),
                (b"msdos", 0x1001, 0, ("other", False)), (b"smbfs", 0, 0, ("other", False)),
                (b"nfs", 0, 0, ("other", False)), (b"macfuse", 0x1000, 0, ("other", False))):
            with self.subTest(kind=self.kind, flags=hex(self.flags), extended=self.extended):
                self.assertEqual(privacy.volume_kind(17), expected)
        self.descriptor.assert_not_called()  # the open descriptor is used as it is, never a path
        for bad in (-1, "17", None, True):
            with self.subTest(descriptor=bad):
                with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
                    privacy.volume_kind(bad)
                self.assertEqual(caught.exception.code, "darwin-fs-path-invalid")
        self.query.side_effect, self.query.return_value = None, -1
        with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
            privacy.volume_kind(17)
        self.assertEqual(caught.exception.code, "darwin-fs-query-unavailable")

    def test_native_failure_is_categorical_and_does_not_expose_mount_data(self):
        for result in (-1, 1):
            self.query.side_effect = None
            self.query.return_value = result
            self.assert_hold("darwin-fs-query-unavailable")
        self.query.side_effect = OSError("fictional-private-mount-name")
        self.assert_hold("darwin-fs-query-unavailable")

    def test_invalid_literal_paths_never_open_a_descriptor(self):
        for path in ("relative", "//ambiguous", "/safe/../other", "/safe/./other", "/safe//other", "/safe/", "/bad\x00path", 42):
            with self.subTest(path=path):
                self.assert_hold("darwin-fs-path-invalid", path)
        self.descriptor.assert_not_called()
        self.query.assert_not_called()

    def test_foreign_or_unreviewed_abi_holds_before_loading_native_library(self):
        for platform in ("win32", "linux"):
            with mock.patch.object(privacy.sys, "platform", platform), mock.patch.object(privacy.ctypes, "CDLL") as loader:
                with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
                    self.native_api()
                self.assertEqual(caught.exception.code, "darwin-fs-abi-unavailable")
                loader.assert_not_called()

    def test_exact_native_symbol_selection_for_reviewed_architectures(self):
        # Exercise the real loader's fixed symbol choice without host APIs.
        for architecture, symbol in (("x86_64", "fstatfs$INODE64"), ("arm64", "fstatfs")):
            native = mock.Mock(return_value=0)
            library = types.SimpleNamespace(**{symbol: native})
            with mock.patch.object(privacy, "_volume_architecture", return_value=architecture), \
                    mock.patch.object(privacy.os, "O_DIRECTORY", 0x100000, create=True), \
                    mock.patch.object(privacy.os, "O_NOFOLLOW", 0x100, create=True), \
                    mock.patch.object(privacy.os, "O_NONBLOCK", 4, create=True), \
                    mock.patch.object(privacy.os, "supports_dir_fd", {privacy.os.open, privacy.os.stat}), \
                    mock.patch.object(privacy.os, "supports_follow_symlinks", {privacy.os.stat}), \
                    mock.patch.object(privacy.ctypes, "CDLL", return_value=library) as loader:
                # setUp patched _volume_api; invoke its saved implementation.
                observed_library, observed_query = self.native_api()
            self.assertIs(observed_library, library)
            self.assertIs(observed_query, native)
            self.assertEqual(native.argtypes, (ctypes.c_int, ctypes.POINTER(privacy._StatFS64)))
            self.assertIs(native.restype, ctypes.c_int)
            loader.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)

    def test_missing_correct_abi_symbol_never_falls_back_to_another_layout(self):
        for architecture, wrong_symbol in (("x86_64", "fstatfs"), ("arm64", "fstatfs$INODE64")):
            with mock.patch.object(privacy, "_volume_architecture", return_value=architecture), \
                    mock.patch.object(privacy.os, "O_DIRECTORY", 0x100000, create=True), \
                    mock.patch.object(privacy.os, "O_NOFOLLOW", 0x100, create=True), \
                    mock.patch.object(privacy.os, "O_NONBLOCK", 4, create=True), \
                    mock.patch.object(privacy.os, "supports_dir_fd", {privacy.os.open, privacy.os.stat}), \
                    mock.patch.object(privacy.os, "supports_follow_symlinks", {privacy.os.stat}), \
                    mock.patch.object(privacy.ctypes, "CDLL", return_value=types.SimpleNamespace(**{wrong_symbol: mock.Mock()})):
                with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
                    self.native_api()
                self.assertEqual(caught.exception.code, "darwin-fs-api-unavailable")

    def test_volume_descriptor_uses_pinned_no_follow_metadata_only_file_open(self):
        directory = info(st_ino=102)
        leaf = info(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_ino=103)
        metadata = {11: info(), 12: directory, 13: leaf}
        with mock.patch.object(privacy.os, "O_DIRECTORY", 0x100000, create=True), \
                mock.patch.object(privacy.os, "O_NOFOLLOW", 0x100, create=True), \
                mock.patch.object(privacy.os, "O_NONBLOCK", 4, create=True), \
                mock.patch.object(privacy.os, "open", side_effect=[11, 12, 13]) as opened, \
                mock.patch.object(privacy.os, "stat", side_effect=lambda name, **kwargs: directory if name == "fictional" else leaf), \
                mock.patch.object(privacy.os, "fstat", side_effect=lambda descriptor: metadata[descriptor]), \
                mock.patch.object(privacy.os, "close") as closed:
            with self.native_descriptor("/fictional/record") as descriptor:
                self.assertEqual(descriptor, 13)
        self.assertEqual(opened.call_args_list[2].args, ("record", 0x8000 | 0x100 | 4))
        self.assertEqual(opened.call_args_list[2].kwargs, {"dir_fd": 12})
        self.assertEqual(closed.call_args_list, [mock.call(13), mock.call(12), mock.call(11)])

    def test_changed_descriptor_identity_is_held_and_every_handle_is_closed(self):
        directory = info(st_ino=102)
        leaf = info(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_ino=103)
        metadata = {11: info(), 12: directory, 13: info(st_mode=leaf.st_mode, st_nlink=1, st_ino=104)}
        with mock.patch.object(privacy.os, "O_DIRECTORY", 0x100000, create=True), \
                mock.patch.object(privacy.os, "O_NOFOLLOW", 0x100, create=True), \
                mock.patch.object(privacy.os, "O_NONBLOCK", 4, create=True), \
                mock.patch.object(privacy.os, "open", side_effect=[11, 12, 13]), \
                mock.patch.object(privacy.os, "stat", side_effect=lambda name, **kwargs: directory if name == "fictional" else leaf), \
                mock.patch.object(privacy.os, "fstat", side_effect=lambda descriptor: metadata[descriptor]), \
                mock.patch.object(privacy.os, "close") as closed:
            with self.assertRaises(privacy.DarwinPrivacyHold) as caught:
                with self.native_descriptor("/fictional/record"):
                    self.fail("Changed file descriptor was admitted")
        self.assertEqual(caught.exception.code, "darwin-fs-path-changed")
        self.assertEqual(closed.call_args_list, [mock.call(13), mock.call(12), mock.call(11)])

    native_api = staticmethod(privacy._volume_api)
    native_descriptor = staticmethod(privacy._volume_descriptor)


if __name__ == "__main__":
    unittest.main(verbosity=2)
