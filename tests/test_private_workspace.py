"""Private-copy regression fixtures only; never read or change host folder ACLs.

Fixtures live under work/test-fixtures/ and are removed after each test.
"""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
import errno
import os
from pathlib import Path, PurePosixPath
import ast
import re
import stat
import sys
import unittest
from unittest import mock
import uuid
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_paths
import private_workspace as private
import win32_files
from work_fixtures import PRIVATE_CAPABILITY_HOLDS, remove_tree

FIXTURES = ROOT / "work" / "test-fixtures"
NAME_RULE_MESSAGE = '" is one PatchCairn does not accept (a reserved Windows name, too long, or an unsupported character)'


@unittest.skipUnless(os.name == "nt", "only on windows: native owner and DACL fixtures")
class WindowsPrivateWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.base = FIXTURES / ("private-" + uuid.uuid4().hex)
        private.ensure_private_directory(self.base, create=True, parents=True)
        self.addCleanup(remove_tree, self.base)

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
        self.assertTrue(caught.exception.code == "private-dacl-null")
        self.assertFalse(private.capability_missing(caught.exception))  # this folder is refused, not the computer

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
        # The boundary folder itself is not below the boundary, even though it is private; nor is a sibling whose
        # name only Unicode case folding makes equal (U+212A KELVIN SIGN folds to "k", NTFS keeps it apart).
        for label, value, limit in (("boundary-itself", self.base, self.base),
                                    ("kelvin-sibling", Path("C:\\fictional\\wor\u212a\\run"), Path("C:\\fictional\\work"))):
            with self.subTest(category=label):
                with self.assertRaises(private.PrivateWorkspaceError) as caught:
                    private.ensure_private_directory(value, boundary=limit)
                self.assertTrue(caught.exception.code == "private-boundary-escape")
        # A folder below the boundary is still admitted when its spelling differs only in letter case.
        inner = private.ensure_private_directory(self.base / "inner", create=True)
        variant = self.base.parent / self.base.name.upper() / "inner"
        self.assertTrue(private.ensure_private_directory(variant, boundary=self.base) == variant)
        self.assertTrue(inner.is_dir())

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


class PathRuleTests(unittest.TestCase):
    """Path text only: nothing is created, opened or resolved."""

    def test_relative_parts_of_the_root_a_child_an_outside_path_and_a_look_alike(self):
        root = FIXTURES / "containment-root"
        self.assertEqual(private.relative_parts(root, root), ())
        self.assertEqual(private.relative_parts(root / "child" / "file.bin", root), ("child", "file.bin"))
        for outside in (root.parent, root.parent / "containment-other", root.parent / "containment-root-sibling" / "child"):
            with self.subTest(outside=outside.name):
                self.assertIsNone(private.relative_parts(outside, root))
        # Text comparison only, so a ".." part or a relative path is never taken to be inside.
        for path, limit in ((root / ".." / "containment-other", root), (root / "child", root / ".." / "containment-root"),
                            (Path("child"), Path("child")), (root / "child", Path("containment-root"))):
            with self.subTest(refused=str(path)):
                self.assertIsNone(private.relative_parts(path, limit))
        # pathlib folds U+212A KELVIN SIGN to "k" on Windows; the file system keeps the two names apart.
        anchor = Path("C:\\fictional") if os.name == "nt" else Path("/fictional")
        self.assertIsNone(private.relative_parts(anchor / "wor\u212a" / "run", anchor / "work"))
        if os.name == "nt":
            self.assertEqual(private.relative_parts(Path("C:\\FICTIONAL\\WORK\\run"), anchor / "work"), ("run",))

    @unittest.skipUnless(os.name == "nt", "only on windows: the Windows name rule applies to Windows paths only")
    def test_private_paths_refuse_exactly_the_names_pc_paths_refuses(self):
        # The path check runs before any file access, so these fictional paths are never opened.
        refused = ("CON", "con.txt", "AUX .log", "NUL", "PRN", "CONIN$", "conout$.log", "COM1", "lpt9.dat", "COM\u00b9", "LPT\u00b2",
                   "com\u00b3.txt", "name.", "name ", "a:b", "a*b", "a?b", 'a"b', "a<b", "a|b", "tab\tname", "del\x7fname",
                   "\u00e9" * 128)
        accepted = ("CONIN", "COM10", "LPT", "console", "com\u2074", "nul-file", "aux2", "conout", "fictional.txt")
        base = "C:\\fictional\\"
        for name in refused:
            with self.subTest(refused=repr(name)):
                self.assertFalse(pc_paths.portable(name))
                with self.assertRaises(private.PrivateWorkspaceError) as caught:
                    private._absolute(base + name)
                self.assertTrue(caught.exception.code == "private-path-invalid")
                # The person learns why: the code stays, the message names the rule.
                self.assertTrue(str(caught.exception).startswith('the folder name "') and str(caught.exception).endswith(NAME_RULE_MESSAGE))
        for name in ("CON", "CONIN$", "CONOUT$", "COM\u00b9", "LPT\u00b3"):
            with self.subTest(reserved=repr(name)), self.assertRaises(pc_paths.PathRefusal) as caught:
                pc_paths.relative(name)
            self.assertTrue(caught.exception.code == "reserved-path-component")
        for name in accepted:
            with self.subTest(accepted=name):
                self.assertTrue(pc_paths.portable(name))
                self.assertTrue(private._absolute(base + name) == Path(base + name))

    @unittest.skipUnless(os.name == "nt", "only on windows: Windows containment compares parts through the file system's rule")
    def test_relative_parts_on_windows_follows_the_file_system_rule(self):
        root = Path("C:\\fictional\\work")
        # Windows trims a final dot or space, so such a part could name the root itself or another folder: never inside.
        for path, limit in ((Path("C:\\fictional\\work\\..."), root), (Path("C:\\fictional\\work\\x."), root),
                            (Path("C:\\fictional\\work\\x "), root), (Path("C:\\fictional\\work.\\x"), Path("C:\\fictional\\work."))):
            with self.subTest(trimmed=str(path)):
                self.assertIsNone(private.relative_parts(path, limit))
        self.assertEqual(private.relative_parts(root / "x" / "y", root), ("x", "y"))
        # Without the Windows API there is no way to compare names as Windows does, so nothing is inside.
        with mock.patch.object(win32_files, "API", None):
            self.assertIsNone(private.relative_parts(root / "x", root))
        # The root's parts are compared through win32_files.same_name, not pathlib's lowercase folding.
        for upper, lower in (("\u03c3", "\u03c2"), ("\u03a3", "\u03c2")):
            expected = ("run",) if win32_files.same_name(upper, lower) else None
            with self.subTest(pair=(upper, lower)):
                self.assertEqual(private.relative_parts(Path("C:\\fictional") / upper / "run", Path("C:\\fictional") / lower), expected)
        # Where the file system equates two names that pathlib keeps apart, same_name's answer still decides.
        with mock.patch.object(win32_files, "same_name", lambda left, right: left.upper() == right.upper()):
            self.assertEqual(private.relative_parts(Path("C:\\fictional\\\u03c3\\run"), Path("C:\\fictional\\\u03c2")), ("run",))


@unittest.skipUnless(os.name == "posix", "only on posix: private mode and owner fixtures")
class PosixPrivateWorkspaceTests(unittest.TestCase):
    def test_private_modes_or_honest_non_enforcing_filesystem_hold(self):
        path = FIXTURES / ("posix-" + uuid.uuid4().hex)
        try:
            private.ensure_private_directory(path, create=True, parents=True)
        except private.PrivateWorkspaceError as error:
            if os.path.lexists(path):  # made, then refused
                self.addCleanup(remove_tree, path)
            self.assertTrue(error.code == "private-owner-or-mode-refused" or error.code.startswith(("private-darwin-acl-", "private-linux-")))
            self.assertFalse((path / "fictional.bin").exists())
            return
        self.addCleanup(remove_tree, path)
        private.write_private_new(path / "fictional.bin", b"fictional POSIX private bytes")
        self.assertTrue(stat.S_IMODE(path.stat().st_mode) == 0o700)
        self.assertTrue(stat.S_IMODE((path / "fictional.bin").stat().st_mode) == 0o600)
        private.ensure_private_file(path / "fictional.bin")
        # A private folder is still refused as its own boundary: the boundary admits only what is below it.
        with self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.ensure_private_directory(path, boundary=path)
        self.assertTrue(caught.exception.code == "private-boundary-escape")

    def test_boundary_itself_is_refused_before_file_access(self):
        # A path check before any file access, so it holds on file systems without private modes too.
        with self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.ensure_private_directory(FIXTURES, boundary=FIXTURES)
        self.assertTrue(caught.exception.code == "private-boundary-escape")



class PublishTests(unittest.TestCase):
    """publish_private_new: a record appears whole under its name or not at all, never over another, and the new name is synced."""

    def setUp(self):
        self.folder = FIXTURES / ("publish-" + uuid.uuid4().hex)
        try:
            private.ensure_private_directory(self.folder, create=True, parents=True)
        except private.PrivateWorkspaceError as error:
            if os.name == "posix" and error.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("only on posix: actual workspace POSIX private-storage capability unavailable: " + error.code)
            raise
        self.addCleanup(remove_tree, self.folder)
        self.path = self.folder / "record.json"

    def temporary(self):
        return sorted(item.name for item in self.folder.iterdir() if item.name.startswith(".w"))

    def test_a_record_is_published_whole_and_never_over_another(self):
        private.publish_private_new(self.path, b"first")
        with self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.publish_private_new(self.path, b"second")
        self.assertEqual((caught.exception.code, self.path.read_bytes(), self.temporary()), ("private-file-create-refused", b"first", []))
        private.ensure_private_file(self.path)

    def test_a_temporary_name_already_taken_is_left_alone(self):
        fixed = uuid.UUID(int=0xABCDEF1 << 100)  # its hex form starts "abcdef1"
        left = self.folder / (".w" + fixed.hex[:7])
        private.write_private_new(left, b"left by an earlier kill")
        with mock.patch.object(private.uuid, "uuid4", return_value=fixed), self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.publish_private_new(self.path, b"new")
        self.assertEqual((caught.exception.code, left.read_bytes(), self.path.exists()), ("private-file-create-refused", b"left by an earlier kill", False))

    def test_any_other_failure_of_the_new_name_refuses_and_leaves_no_temporary_file(self):
        primitive = "rename" if os.name == "nt" else "link"
        with mock.patch.object(private.os, primitive, side_effect=OSError(errno.EIO, "Fictional failure")), \
                self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.publish_private_new(self.path, b"never")
        self.assertEqual((caught.exception.code, self.path.exists(), self.temporary()), ("private-file-publish-unresolved", False, []))

    @unittest.skipUnless(os.name == "nt", "only on windows: a rename there is refused while another program has the file open")
    def test_a_short_refusal_of_the_rename_is_tried_again_and_a_lasting_one_refuses(self):
        real, calls, waits = os.rename, [], []

        def refused_once(source, target):
            calls.append(source)
            if len(calls) == 1:
                raise PermissionError(errno.EACCES, "Fictional scanner has the file open")
            return real(source, target)
        with mock.patch.object(private.os, "rename", side_effect=refused_once), mock.patch.object(private.time, "sleep", side_effect=waits.append):
            private.publish_private_new(self.path, b"published")
        self.assertEqual((len(calls), self.path.read_bytes(), waits, self.temporary()), (2, b"published", [private.RENAME_WAIT_SECONDS], []))
        other = self.folder / "other.json"
        with mock.patch.object(private.os, "rename", side_effect=PermissionError(errno.EACCES, "Fictional scanner")) as rename, \
                mock.patch.object(private.time, "sleep"), self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.publish_private_new(other, b"never")
        self.assertEqual((caught.exception.code, rename.call_count, other.exists(), self.temporary()),
                         ("private-file-publish-unresolved", private.RENAME_TRIES, False, []))

    def test_the_new_name_is_synced(self):
        # POSIX syncs the folder once the new name is there; Windows syncs the renamed file.
        real, synced = os.fsync, []

        def recording(descriptor):
            info = os.fstat(descriptor)
            synced.append(((info.st_dev, info.st_ino), self.path.exists()))
            return real(descriptor)
        with mock.patch.object(private.os, "fsync", side_effect=recording):
            private.publish_private_new(self.path, b"synced")
        info = os.stat(self.path if os.name == "nt" else self.folder)
        self.assertEqual(synced[-1], ((info.st_dev, info.st_ino), True))


class RefusalTypeTests(unittest.TestCase):
    def test_privacy_errors_are_shared_refusals_keeping_their_codes(self):
        import pc_records
        import win32_files
        error = private.PrivateWorkspaceError("private-path-invalid", "a folder name is not accepted")
        self.assertIsInstance(error, pc_records.Refusal)
        self.assertIsInstance(error, ValueError)
        self.assertEqual((error.code, str(error)), ("private-path-invalid", "a folder name is not accepted"))
        self.assertEqual(str(private.PrivateWorkspaceError("private-owner-or-mode-refused")), "private-owner-or-mode-refused")
        refusal = win32_files.PrivacyRefusal("private-dacl-unprotected")
        self.assertIsInstance(refusal, pc_records.Refusal)
        self.assertEqual((refusal.code, str(refusal)), ("private-dacl-unprotected", "private-dacl-unprotected"))

    def test_a_missing_capability_is_told_apart_from_a_refused_path(self):
        missing = ("private-platform-unavailable", "private-persistent-acl-unavailable", "private-linux-foreign-filesystem",
                   "private-darwin-fs-ownership-ignored", "private-fixed-local-volume-required", "private-lock-unavailable")
        # A Linux or macOS refusal this module does not recognise stops PatchCairn with its code, like a refused path.
        refused = ("private-owner-or-mode-refused", "private-dacl-broad-or-unknown", "private-dacl-unsupported", "private-dacl-null",
                   "private-darwin-acl-not-empty", "private-darwin-acl-refused", "private-linux-path-changed", "private-directory-exists",
                   "private-path-invalid", "private-lock-held", "private-linux-filesystem-refused", "private-darwin-fs-refused",
                   "private-unavailable-fictional")
        for codes, expected in ((missing, True), (refused, False)):
            for code in codes:
                with self.subTest(code=code):
                    self.assertIs(private.capability_missing(private.PrivateWorkspaceError(code, "fictional reason")), expected)
        self.assertIs(private.capability_missing(ValueError("private-platform-unavailable")), False)

    # Every other private-* code the four modules give: each refuses one path (or is a refusal nobody recognised).
    REFUSED_PATH_CODES = frozenset({
        "private-boundary-escape", "private-bytes-required", "private-canonical-path-mismatch", "private-dacl-broad-or-unknown",
        "private-dacl-inheritance-or-access-refused", "private-dacl-invalid", "private-dacl-not-exact", "private-dacl-null",
        "private-dacl-unprotected", "private-dacl-unsupported", "private-darwin-acl-invalid", "private-darwin-acl-not-empty",
        "private-darwin-acl-ordinary-path-required", "private-darwin-acl-path-changed", "private-darwin-acl-path-invalid",
        "private-darwin-acl-refused", "private-darwin-fs-ordinary-path-required", "private-darwin-fs-path-changed",
        "private-darwin-fs-path-invalid", "private-darwin-fs-refused", "private-directory-changed", "private-directory-create-refused",
        "private-directory-exists", "private-directory-missing", "private-file-changed", "private-file-create-refused",
        "private-file-flush-unresolved", "private-file-publish-unresolved", "private-file-write-unresolved", "private-link-or-type-refused",
        "private-linux-filesystem-refused", "private-linux-ordinary-path-required", "private-linux-path-changed", "private-linux-path-invalid",
        "private-local-path-required", "private-lock-held", "private-owner-or-acl-invalid", "private-owner-or-mode-refused",
        "private-owner-refused", "private-path-access-refused", "private-path-invalid", "private-root-refused",
    })

    @staticmethod
    def given_codes():
        """The private-* codes read from the source: private_workspace's own, the Windows checks' unchanged, and the Linux
        and macOS checks' renamed. The CAPABILITY_CODES assignment is left out, so the set cannot vouch for its own names."""
        def source(module):
            return (ROOT / "scripts" / (module + ".py")).read_text(encoding="utf-8")
        text = source("private_workspace")
        (node,) = [node for node in ast.parse(text).body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "CAPABILITY_CODES" for target in node.targets)]
        lines = text.splitlines()
        text = "\n".join(lines[:node.lineno - 1] + lines[node.end_lineno:])
        quoted = r'"(private-[a-z-]*[a-z])"'
        codes = set(re.findall(quoted, text)) | set(re.findall(quoted, source("win32_files")))
        codes |= {"private-" + code for code in re.findall(r'"(darwin-(?:acl|fs)-[a-z-]*[a-z])"', source("darwin_privacy"))}
        return codes | {"private-linux-" + code for code in re.findall(r'"linux-private-([a-z-]*[a-z])"', source("linux_privacy"))}

    def test_capability_codes_are_codes_this_module_gives(self):
        given = self.given_codes()
        self.assertLessEqual(private.CAPABILITY_CODES, given)  # no stale or misspelt name in the set
        self.assertFalse(private.CAPABILITY_CODES | {"private-fictional-unavailable"} <= given)  # and a name nothing gives is caught
        # The other way: every code given is sorted on purpose, as a missing capability or as one refused path.
        self.assertEqual(given - private.CAPABILITY_CODES, self.REFUSED_PATH_CODES)
        self.assertLessEqual(PRIVATE_CAPABILITY_HOLDS - {"private-owner-or-mode-refused"}, private.CAPABILITY_CODES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
