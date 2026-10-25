"""Private-copy regression fixtures only; never read or change host folder ACLs.

Fixtures live under work/test-fixtures/ and are removed after each test.
"""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import unittest
from unittest import mock
import uuid
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import private_workspace as private
import win32_files

FIXTURES = ROOT / "work" / "test-fixtures"


def remove_fixture(path):
    def writable_then_retry(function, name, _error):
        os.chmod(name, stat.S_IWRITE)
        function(name)
    shutil.rmtree(path, onexc=writable_then_retry)


@unittest.skipUnless(os.name == "nt", "only on windows: native owner and DACL fixtures")
class WindowsPrivateWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.base = FIXTURES / ("private-" + uuid.uuid4().hex)
        private.ensure_private_directory(self.base, create=True, parents=True)
        self.addCleanup(remove_fixture, self.base)

    def node_with_descriptor(self, name, descriptor_suffix, *, directory=True):
        """Creation-time ACL fixture only. Never change an existing object's ACL."""
        user = win32_files.token_user()
        descriptor = ctypes.c_void_p()
        length = ctypes.c_uint32()
        sddl = "O:" + user + descriptor_suffix.replace("CURRENT_USER", user)
        self.assertTrue(bool(win32_files.API.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), ctypes.byref(length))))
        path = self.base / name
        try:
            attributes = win32_files.SECURITY_ATTRIBUTES(ctypes.sizeof(win32_files.SECURITY_ATTRIBUTES), descriptor, False)
            if directory:
                win32_files.create_directory(str(path), attributes)
            else:
                win32_files.open_file(str(path), 0xC0020080, 0, win32_files.CREATE_NEW, 0x00200080, attributes).close()
        finally:
            win32_files.API.LocalFree(descriptor)
        return path

    def security_handle(self, path):
        return win32_files.open_file(str(path), win32_files.READ_CONTROL, 7, win32_files.OPEN_EXISTING,
                                     win32_files.FILE_FLAG_BACKUP_SEMANTICS | win32_files.FILE_FLAG_OPEN_REPARSE_POINT)

    def descriptor_bytes(self, path, *, directory=True):
        function = ctypes.WinDLL("advapi32", use_last_error=True).GetSecurityDescriptorLength
        function.argtypes, function.restype = [ctypes.c_void_p], ctypes.c_uint32
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        with self.security_handle(path) as handle:
            self.assertTrue(win32_files.API.GetSecurityInfo(handle.value, 1, 5, ctypes.byref(owner), None,
                                                            ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0)
        try:
            return ctypes.string_at(descriptor, function(descriptor))
        finally:
            win32_files.API.LocalFree(descriptor)

    def test_new_namespace_and_file_actual_owner_dacl_readback(self):
        target = self.base / "namespace"
        private.ensure_private_directory(target, create=True)
        self.assertTrue(private.ensure_private_directory(target) == target)
        private.write_private_new(target / "fictional.json", b'{"fictional":true}')
        self.assertTrue(private.ensure_private_file(target / "fictional.json") == target / "fictional.json")
        self.assertTrue((target / "fictional.json").read_bytes() == b'{"fictional":true}')

    def test_mismatched_owner_is_a_categorical_hold(self):
        with mock.patch.object(win32_files, "token_user", return_value="S-1-5-21-1-2-3-1001"):
            with self.assertRaises(private.PrivateWorkspaceError) as caught:
                private.ensure_private_directory(self.base)
        self.assertTrue(caught.exception.code == "private-owner-refused")

    def test_new_descendants_explicit_writer_and_native_owner_admission(self):
        child = self.base / "namespace" / "child"
        private.ensure_private_directory(child, create=True, parents=True)
        explicit = child / "explicit.bin"
        private.write_private_new(explicit, b"fictional explicit private file")
        self.assertTrue(private.ensure_private_file(explicit) == explicit)
        self.assertTrue(explicit.read_bytes() == b"fictional explicit private file")
        # DACL inheritance does not choose the ordinary creator's default owner.
        file = child / "inherited.bin"
        with file.open("xb") as stream:
            stream.write(b"fictional inherited file")
        before = self.descriptor_bytes(file, directory=False)
        with self.security_handle(file) as handle:
            owner, _control, aces = win32_files.security_snapshot(handle)
        owner_is_user = owner == win32_files.token_user()
        self.assertTrue(len(aces) == len(win32_files.private_principals()))
        for kind, flags, mask, _sid in aces:
            self.assertTrue(kind == 0 and flags & 0x10 and not flags & ~0x13 and mask & 0x1F01FF == 0x1F01FF)
        self.assertTrue({sid for _kind, _flags, _mask, sid in aces} == set(win32_files.private_principals()))
        if owner_is_user:
            self.assertTrue(private.ensure_private_file(file) == file)
        else:
            with self.assertRaises(private.PrivateWorkspaceError) as caught:
                private.ensure_private_file(file)
            self.assertTrue(caught.exception.code == "private-owner-refused")
        self.assertTrue(before == self.descriptor_bytes(file, directory=False))
        self.assertTrue(file.read_bytes() == b"fictional inherited file")

    def test_existing_broad_directory_refused_without_permission_repair(self):
        shared = self.node_with_descriptor("broad", "D:P(A;OICI;FA;;;CURRENT_USER)(A;OICI;FR;;;WD)")
        before = self.descriptor_bytes(shared)
        with self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.ensure_private_directory(shared)
        self.assertTrue(caught.exception.code == "private-dacl-broad-or-unknown")
        self.assertTrue(before == self.descriptor_bytes(shared))
        self.assertEqual(list(shared.iterdir()), [])

    def test_null_dacl_refused(self):
        shared = self.node_with_descriptor("null-dacl", "D:NO_ACCESS_CONTROL")
        with self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.ensure_private_directory(shared)
        self.assertTrue(caught.exception.code == "private-dacl-unavailable-or-null")

    def test_inherit_only_broad_ace_and_unsupported_ace_refuse(self):
        for name, suffix in (
            ("inherit-only", "D:P(A;OICI;FA;;;CURRENT_USER)(A;OICIIO;FR;;;WD)"),
            # Denies writing extended attributes only, so the fixture can still be listed and removed.
            ("unsupported-deny", "D:P(D;;0x00000010;;;WD)(A;OICI;FA;;;CURRENT_USER)"),
        ):
            with self.subTest(category=name):
                path = self.node_with_descriptor(name, suffix)
                with self.assertRaises(private.PrivateWorkspaceError):
                    private.ensure_private_directory(path)

    def test_noninheritable_private_directory_refuses_before_children(self):
        path = self.node_with_descriptor("no-child-protection", "D:P(A;;FA;;;CURRENT_USER)")
        with self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.ensure_private_directory(path)
        self.assertTrue(caught.exception.code == "private-dacl-inheritance-or-access-refused")

    def test_broad_existing_file_under_private_parent_refuses(self):
        path = self.node_with_descriptor("broad-file.bin", "D:P(A;;FA;;;CURRENT_USER)(A;;FR;;;WD)", directory=False)
        before = self.descriptor_bytes(path, directory=False)
        with self.assertRaises(private.PrivateWorkspaceError):
            private.ensure_private_file(path)
        self.assertTrue(before == self.descriptor_bytes(path, directory=False))

    def test_exclusive_private_writer_never_overwrites(self):
        path = self.base / "exclusive.bin"
        private.write_private_new(path, b"fictional preserved bytes")
        with self.assertRaises(private.PrivateWorkspaceError):
            private.write_private_new(path, b"fictional replacement")
        self.assertTrue(path.read_bytes() == b"fictional preserved bytes")

    def test_file_admission_failure_occurs_before_private_bytes(self):
        original = win32_files.validate_private
        def refuse_file(handle, *, directory, exact):
            if not directory:
                raise win32_files.PrivacyRefusal("fictional-file-admission-refusal")
            return original(handle, directory=directory, exact=exact)
        path = self.base / "never-populated.bin"
        with mock.patch.object(win32_files, "validate_private", new=refuse_file):
            with self.assertRaises(private.PrivateWorkspaceError):
                private.write_private_new(path, b"fictional private bytes must stay unwritten")
        self.assertTrue(path.is_file() and path.stat().st_size == 0)

    def test_hardlinked_private_file_refused(self):
        file = self.base / "hardlink-source.bin"
        private.write_private_new(file, b"fictional linked bytes")
        os.link(file, self.base / "hardlink-alias.bin")
        with self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.ensure_private_file(file)
        self.assertTrue(caught.exception.code == "private-link-or-type-refused")

    def test_boundary_escape_and_path_aliases_refuse(self):
        for value in (self.base / ".." / "escape", Path(r"C:\\fictional:stream"), Path(r"\\server\share\fictional")):
            with self.subTest(category="literal-path"), self.assertRaises(private.PrivateWorkspaceError):
                private.ensure_private_directory(value, boundary=self.base)
        with self.assertRaises(private.PrivateWorkspaceError):
            private.ensure_private_directory(self.base.parent, boundary=self.base)

    def test_backend_files_and_folders_pass_private_admission(self):
        # The selected-root backend and private_workspace share win32_files; each admits what the other creates.
        import windows_scoped
        with windows_scoped.WindowsRoot(str(self.base)) as root:
            root.mkdir("backup")
            root.create_file("backup/manifest.json", data=b"{}")
            private.write_private_new(self.base / "backup" / "README.txt", b"fictional readme")
            self.assertEqual(root.inspect("backup/README.txt", hash_file=True)["size"], 16)
        self.assertTrue(private.ensure_private_directory(self.base / "backup") == self.base / "backup")
        for name in ("manifest.json", "README.txt"):
            self.assertTrue(private.ensure_private_file(self.base / "backup" / name) == self.base / "backup" / name)
            with self.security_handle(self.base / "backup" / name) as handle:
                win32_files.validate_private(handle, directory=False, exact=True)

    @mock.patch("darwin_privacy.assert_private_filesystem")
    def test_darwin_private_namespace_is_hold_before_allocation(self, _volume_gate):
        target = self.base / "darwin-not-created"
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "darwin"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.dict(sys.modules, {"darwin_privacy": None}):
            with self.assertRaises(private.PrivateWorkspaceError) as caught:
                private.ensure_private_directory(target, create=True)
            self.assertTrue(caught.exception.code == "private-darwin-acl-capability-unavailable")
            with self.assertRaises(private.PrivateWorkspaceError):
                private.ensure_private_file(target / "fictional.bin")
        self.assertFalse(target.exists())

    @mock.patch("darwin_privacy.assert_private_filesystem")
    def test_darwin_existing_store_acl_empty_nonempty_and_error_contracts(self, _volume_gate):
        import darwin_privacy
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=17, st_nlink=1)
        path = SimpleNamespace(lstat=lambda: info)
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "darwin"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(private.os, "geteuid", return_value=17, create=True):
            with mock.patch.object(darwin_privacy, "assert_no_extended_acl") as checker:
                self.assertTrue(private._posix_info(path, directory=True, private=True) is info)
                self.assertTrue(checker.call_count == 1)
            for code in ("darwin-acl-not-empty", "darwin-acl-read-unavailable"):
                with self.subTest(category=code), mock.patch.object(darwin_privacy, "assert_no_extended_acl",
                        side_effect=darwin_privacy.DarwinPrivacyHold(code)):
                    with self.assertRaises(private.PrivateWorkspaceError) as caught:
                        private._posix_info(path, directory=True, private=True)
                    self.assertTrue(caught.exception.code == "private-" + code)

    @mock.patch("darwin_privacy.assert_private_filesystem")
    def test_darwin_new_directory_acl_is_checked_before_payload(self, _volume_gate):
        import darwin_privacy
        created = set()
        class ModelPath(PurePosixPath):
            def lstat(value):
                if value.name.startswith("new-private") and str(value) not in created:
                    raise FileNotFoundError()
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=17, st_nlink=1, st_dev=1, st_ino=2)
            def mkdir(value, *, mode):
                self.assertTrue(mode == 0o700)
                created.add(str(value))
        target = ModelPath("/fictional/new-private")
        payload = mock.Mock()
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "darwin"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(private.os, "geteuid", return_value=17, create=True), \
             mock.patch.object(private, "Path", ModelPath), mock.patch.object(private, "_absolute", return_value=target), \
             mock.patch.object(darwin_privacy, "assert_no_extended_acl",
                               side_effect=darwin_privacy.DarwinPrivacyHold("darwin-acl-not-empty")) as checker:
            with self.assertRaises(private.PrivateWorkspaceError):
                with private.private_directory(target, create=True):
                    payload()
            self.assertTrue(checker.call_count == 1)
        self.assertTrue(str(target) in created)
        self.assertFalse(payload.called)
        empty = ModelPath("/fictional/new-private-empty")
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "darwin"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(private.os, "geteuid", return_value=17, create=True), \
             mock.patch.object(private, "Path", ModelPath), mock.patch.object(private, "_absolute", return_value=empty), \
             mock.patch.object(darwin_privacy, "assert_no_extended_acl") as checker:
            with private.private_directory(empty, create=True):
                self.assertTrue(checker.called)
                payload()
        self.assertTrue(payload.call_count == 1 and str(empty) in created)

    @mock.patch("darwin_privacy.assert_private_filesystem")
    def test_darwin_new_file_acl_is_checked_before_first_write(self, _volume_gate):
        import darwin_privacy
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=17, st_nlink=1, st_dev=1, st_ino=2)
        path = SimpleNamespace(parent="fictional-private-parent", lstat=lambda: info)
        @contextmanager
        def admitted_parent(*args, **kwargs):
            yield "fictional-private-parent"
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "darwin"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(private.os, "geteuid", return_value=17, create=True), \
             mock.patch.object(private, "_absolute", return_value=path), \
             mock.patch.object(private, "private_directory", new=admitted_parent), \
             mock.patch.object(private.os, "open", return_value=19), \
             mock.patch.object(private.os, "fstat", return_value=info), \
             mock.patch.object(private.os, "close") as close, mock.patch.object(private.os, "write") as write, \
             mock.patch.object(darwin_privacy, "assert_no_extended_acl",
                               side_effect=darwin_privacy.DarwinPrivacyHold("darwin-acl-not-empty")) as checker:
            with self.assertRaises(private.PrivateWorkspaceError):
                private.write_private_new(path, b"fictional private bytes")
            self.assertTrue(checker.call_count == 1)
            self.assertFalse(write.called)
            self.assertTrue(close.call_count == 1)
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "darwin"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(private.os, "geteuid", return_value=17, create=True), \
             mock.patch.object(private, "_absolute", return_value=path), \
             mock.patch.object(private, "private_directory", new=admitted_parent), \
             mock.patch.object(private.os, "open", return_value=19), \
             mock.patch.object(private.os, "fstat", return_value=info), mock.patch.object(private.os, "close"), \
             mock.patch.object(private.os, "fsync"), \
             mock.patch.object(darwin_privacy, "assert_no_extended_acl") as checker:
            def accept(handle, data):
                self.assertTrue(checker.called)
                return len(data)
            with mock.patch.object(private.os, "write", side_effect=accept) as write:
                private.write_private_new(path, b"fictional private bytes")
                self.assertTrue(write.call_count == 1)

    def test_linux_missing_checker_and_fake_private_mode_foreign_fs_hold(self):
        import linux_privacy
        target = self.base / "linux-not-created"
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "linux"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.dict(sys.modules, {"linux_privacy": None}):
            with self.assertRaises(private.PrivateWorkspaceError) as caught:
                private.ensure_private_directory(target, create=True)
            self.assertTrue(caught.exception.code == "private-linux-filesystem-capability-unavailable")
        self.assertFalse(target.exists())
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=17, st_nlink=1)
        model = SimpleNamespace(lstat=lambda: info)
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "linux"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(private.os, "geteuid", return_value=17, create=True):
            for category in ("foreign-filesystem", "abi-unavailable"):
                with self.subTest(category=category), mock.patch.object(linux_privacy, "assert_native_private_filesystem",
                        side_effect=linux_privacy.LinuxPrivacyHold("linux-private-" + category)):
                    with self.assertRaises(private.PrivateWorkspaceError) as caught:
                        private._posix_info(model, directory=True, private=True)
                    self.assertTrue(caught.exception.code == "private-linux-" + category)
            with mock.patch.object(linux_privacy, "assert_native_private_filesystem") as checker:
                self.assertTrue(private._posix_info(model, directory=True, private=True) is info)
                self.assertTrue(checker.call_count == 1)

    def test_linux_foreign_filesystem_refuses_before_directory_allocation(self):
        import linux_privacy
        created = set()
        class ModelPath(PurePosixPath):
            def lstat(value):
                if value.name == "new-private":
                    raise FileNotFoundError()
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=17, st_nlink=1)
            def mkdir(value, *, mode):
                created.add(str(value))
        target = ModelPath("/fictional/new-private")
        payload = mock.Mock()
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "linux"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(private.os, "geteuid", return_value=17, create=True), \
             mock.patch.object(private, "Path", ModelPath), mock.patch.object(private, "_absolute", return_value=target), \
             mock.patch.object(linux_privacy, "assert_native_private_filesystem",
                               side_effect=linux_privacy.LinuxPrivacyHold("linux-private-foreign-filesystem")) as checker:
            with self.assertRaises(private.PrivateWorkspaceError):
                with private.private_directory(target, create=True):
                    payload()
            self.assertTrue(checker.call_count == 1)
        self.assertFalse(created or payload.called)

    def test_linux_foreign_new_file_is_checked_before_first_write(self):
        import linux_privacy
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=17, st_nlink=1, st_dev=1, st_ino=2)
        path = SimpleNamespace(parent="fictional-private-parent", lstat=lambda: info)
        @contextmanager
        def admitted_parent(*args, **kwargs):
            yield "fictional-private-parent"
        with mock.patch.object(private.os, "name", "posix"), mock.patch.object(private.sys, "platform", "linux"), \
             mock.patch.object(private.os, "O_NOFOLLOW", 0x20000, create=True), \
             mock.patch.object(private.os, "geteuid", return_value=17, create=True), \
             mock.patch.object(private, "_absolute", return_value=path), \
             mock.patch.object(private, "private_directory", new=admitted_parent), \
             mock.patch.object(private.os, "open", return_value=19), \
             mock.patch.object(private.os, "fstat", return_value=info), \
             mock.patch.object(private.os, "close") as close, mock.patch.object(private.os, "write") as write, \
             mock.patch.object(linux_privacy, "assert_native_private_filesystem",
                               side_effect=linux_privacy.LinuxPrivacyHold("linux-private-foreign-filesystem")) as checker:
            with self.assertRaises(private.PrivateWorkspaceError):
                private.write_private_new(path, b"fictional private bytes")
            self.assertTrue(checker.call_count == 1)
            self.assertFalse(write.called)
            self.assertTrue(close.call_count == 1)


@unittest.skipUnless(os.name == "posix", "only on posix: private mode and owner fixtures")
class PosixPrivateWorkspaceTests(unittest.TestCase):
    def test_private_modes_or_honest_non_enforcing_filesystem_hold(self):
        path = FIXTURES / ("posix-" + uuid.uuid4().hex)
        self.addCleanup(shutil.rmtree, path, True)
        try:
            private.ensure_private_directory(path, create=True, parents=True)
        except private.PrivateWorkspaceError as error:
            self.assertTrue(error.code == "private-owner-or-mode-refused" or error.code.startswith(("private-darwin-acl-", "private-linux-")))
            self.assertFalse((path / "fictional.bin").exists())
            return
        private.write_private_new(path / "fictional.bin", b"fictional POSIX private bytes")
        self.assertTrue(stat.S_IMODE(path.stat().st_mode) == 0o700)
        self.assertTrue(stat.S_IMODE((path / "fictional.bin").stat().st_mode) == 0o600)
        private.ensure_private_file(path / "fictional.bin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
