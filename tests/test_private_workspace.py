"""Private-copy regression fixtures only; never read or change host folder ACLs."""
from __future__ import annotations

import base64
import ctypes
import hashlib
from ctypes import wintypes
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import unittest
from unittest import mock
import uuid
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import private_workspace as private

FIXTURES = ROOT / "work/upgrade_v3/windows/privacy_fix"


@unittest.skipUnless(os.name == "nt", "Windows native owner/DACL fixtures")
class WindowsPrivateWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private.ensure_private_directory(FIXTURES, create=True, parents=True, exist_ok=True)

    def setUp(self):
        self.base = FIXTURES / ("case-" + uuid.uuid4().hex)
        private.ensure_private_directory(self.base, create=True)

    def node_with_descriptor(self, name, descriptor_suffix, *, directory=True):
        """Creation-time ACL fixture only. Never change an existing object's ACL."""
        api = private._WindowsSecurity()
        descriptor = ctypes.c_void_p()
        length = wintypes.DWORD()
        sddl = "O:" + api.user + descriptor_suffix.replace("CURRENT_USER", api.user)
        self.assertTrue(bool(api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), ctypes.byref(length))))
        path = self.base / name
        try:
            attributes = private._SecurityAttributes(ctypes.sizeof(private._SecurityAttributes), descriptor, False)
            if directory:
                self.assertTrue(bool(api.kernel.CreateDirectoryW(str(path), ctypes.byref(attributes))))
            else:
                handle = api.kernel.CreateFileW(str(path), 0xC0020080, 0, ctypes.byref(attributes), 1, 0x00200080, None)
                self.assertTrue(handle != ctypes.c_void_p(-1).value)
                api.close(handle)
        finally:
            api.kernel.LocalFree(descriptor)
        return path

    def descriptor_bytes(self, path, *, directory=True):
        api = private._WindowsSecurity()
        handle = api.open(path, directory=directory, security=True)
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        function = api.advapi.GetSecurityDescriptorLength
        function.argtypes, function.restype = [ctypes.c_void_p], wintypes.DWORD
        try:
            self.assertTrue(api.advapi.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None,
                              ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0)
            return ctypes.string_at(descriptor, function(descriptor))
        finally:
            if descriptor.value:
                api.kernel.LocalFree(descriptor)
            api.close(handle)

    def protected_file_dacl(self, path):
        api = private._WindowsSecurity()
        handle = api.open(path, directory=False, security=True)
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        try:
            self.assertTrue(api.advapi.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None,
                              ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0)
            control, revision = wintypes.WORD(), wintypes.DWORD()
            self.assertTrue(bool(api.advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision))))
            return bool(control.value & 0x1000)
        finally:
            if descriptor.value:
                api.kernel.LocalFree(descriptor)
            api.close(handle)

    def assert_private_compiler_directory(self, path, protected_namespace):
        """Admit inherited compiler DACLs without requiring DACL_PROTECTED.

        The enclosing request/worker namespace remains protected and pinned.
        Descendants retain ordinary metadata, exact owner, closed allow-list,
        user access/inheritance, and persistent-ACL checks. No ACL is changed.
        """
        path, protected_namespace = Path(path), Path(protected_namespace)
        relative = path.relative_to(protected_namespace)
        self.assertTrue(relative.parts and all(p not in {"", ".", ".."} for p in relative.parts),
                        "Compiler directory escaped its admitted namespace")
        api = private._WindowsSecurity()
        held = []
        with private.private_directory(protected_namespace):
            current = protected_namespace
            try:
                for part in relative.parts:
                    current /= part
                    before = current.lstat()
                    self.assertTrue(stat.S_ISDIR(before.st_mode) and not getattr(before, "st_file_attributes", 0) & 0x400,
                                    "Compiler directory is not an ordinary directory")
                    handle = api.open(current, directory=True, security=True)
                    held.append(handle)
                    info = api.info(handle, current, directory=True)
                    identity = (info.volume, info.id_high, info.id_low, info.attributes, info.links)
                    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
                    try:
                        status = api.advapi.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None,
                                                          ctypes.byref(dacl), None, ctypes.byref(descriptor))
                        self.assertTrue(status == 0 and descriptor.value and dacl.value,
                                        "Compiler directory DACL is unavailable or null")
                        control, revision = wintypes.WORD(), wintypes.DWORD()
                        self.assertTrue(bool(api.advapi.GetSecurityDescriptorControl(
                            descriptor, ctypes.byref(control), ctypes.byref(revision))), "Compiler DACL control is unavailable")
                        self.assertTrue(bool(control.value & 4), "Compiler directory DACL is absent")
                        # Deliberately no SE_DACL_PROTECTED requirement here:
                        # safe compiler subdirectories may inherit these rules.
                        self.assertTrue(api._sid_text(owner) == api.user, "Compiler directory owner differs from fixture owner")
                        self.assertTrue(bool(api.advapi.IsValidAcl(dacl)), "Compiler directory DACL is invalid")
                        acl = ctypes.cast(dacl, ctypes.POINTER(private._ACL)).contents
                        self.assertTrue(1 <= acl.count <= 256, "Compiler DACL ACE count is unsupported")
                        user_access = user_inheritance = False
                        for index in range(acl.count):
                            address = ctypes.c_void_p()
                            self.assertTrue(bool(api.advapi.GetAce(dacl, index, ctypes.byref(address))),
                                            "Compiler DACL ACE is unavailable")
                            ace = ctypes.cast(address, ctypes.POINTER(private._ACE)).contents
                            self.assertTrue(ace.kind == 0 and not ace.flags & ~0x13 and ace.size >= 16,
                                            "Compiler DACL ACE type or flags are unsupported")
                            sid = address.value + 8
                            self.assertTrue(bool(api.advapi.IsValidSid(sid)) and api.advapi.GetLengthSid(sid) <= ace.size - 8,
                                            "Compiler DACL SID is invalid")
                            principal = api._sid_text(sid)
                            self.assertTrue(principal in api.allowed, "Compiler DACL admits a broad or unknown principal")
                            if principal == api.user and (ace.mask & 0x1F01FF == 0x1F01FF or ace.mask & 0x10000000):
                                user_access = True
                                user_inheritance |= ace.flags & 3 == 3
                        self.assertTrue(user_access and user_inheritance, "Compiler directory lacks fixture-owner access or inheritance")
                        serial, maximum, flags = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
                        self.assertTrue(bool(api.kernel.GetVolumeInformationByHandleW(
                            handle, None, 0, ctypes.byref(serial), ctypes.byref(maximum), ctypes.byref(flags), None, 0))
                            and bool(flags.value & 8), "Compiler directory volume lacks persistent ACLs")
                        after = api.info(handle, current, directory=True)
                        self.assertTrue((after.volume, after.id_high, after.id_low, after.attributes, after.links) == identity,
                                        "Compiler directory metadata changed during admission")
                    finally:
                        if descriptor.value:
                            api.kernel.LocalFree(descriptor)
            finally:
                for handle in reversed(held):
                    api.close(handle)

    def test_new_namespace_and_file_actual_owner_dacl_readback(self):
        target = self.base / "namespace"
        private.ensure_private_directory(target, create=True)
        self.assertTrue(private.ensure_private_directory(target) == target)
        private.write_private_new(target / "fictional.json", b'{"fictional":true}')
        self.assertTrue(private.ensure_private_file(target / "fictional.json") == target / "fictional.json")
        self.assertTrue((target / "fictional.json").read_bytes() == b'{"fictional":true}')

    def test_mismatched_owner_is_a_categorical_hold(self):
        api = private._WindowsSecurity()
        handle = api.open(self.base, directory=True, security=True)
        try:
            with mock.patch.object(api, "_sid_text", return_value="fictional-other-owner"):
                with self.assertRaises(private.PrivateWorkspaceError) as caught:
                    api.validate(handle, directory=True)
            self.assertTrue(caught.exception.code == "private-owner-refused")
        finally:
            api.close(handle)

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
        api = private._WindowsSecurity()
        handle = api.open(file, directory=False, security=True)
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        try:
            self.assertTrue(api.advapi.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None,
                              ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0)
            owner_is_user = api._sid_text(owner) == api.user
            self.assertTrue(bool(dacl.value) and bool(api.advapi.IsValidAcl(dacl)))
            acl = ctypes.cast(dacl, ctypes.POINTER(private._ACL)).contents
            self.assertTrue(acl.count == len(api.allowed))
            inherited_principals = set()
            for index in range(acl.count):
                address = ctypes.c_void_p()
                self.assertTrue(bool(api.advapi.GetAce(dacl, index, ctypes.byref(address))))
                ace = ctypes.cast(address, ctypes.POINTER(private._ACE)).contents
                self.assertTrue(ace.kind == 0 and ace.flags & 0x10 and not ace.flags & ~0x13
                                and ace.size >= 16 and ace.mask & 0x1F01FF == 0x1F01FF)
                inherited_principals.add(api._sid_text(address.value + 8))
            self.assertTrue(inherited_principals == api.allowed)
        finally:
            if descriptor.value:
                api.kernel.LocalFree(descriptor)
            api.close(handle)
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
        self.assertFalse((shared / "request.json").exists())

    def test_null_dacl_refused(self):
        shared = self.node_with_descriptor("null-dacl", "D:NO_ACCESS_CONTROL")
        with self.assertRaises(private.PrivateWorkspaceError) as caught:
            private.ensure_private_directory(shared)
        self.assertTrue(caught.exception.code == "private-dacl-unavailable-or-null")

    def test_inherit_only_broad_ace_and_unsupported_ace_refuse(self):
        for name, suffix in (
            ("inherit-only", "D:P(A;OICI;FA;;;CURRENT_USER)(A;OICIIO;FR;;;WD)"),
            ("unsupported-deny", "D:P(D;;0x00000001;;;WD)(A;OICI;FA;;;CURRENT_USER)"),
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
        original = private._WindowsSecurity.validate
        def refuse_file(api, handle, *, directory):
            if not directory:
                raise private.PrivateWorkspaceError("fictional-file-admission-refusal")
            return original(api, handle, directory=directory)
        path = self.base / "never-populated.bin"
        with mock.patch.object(private._WindowsSecurity, "validate", new=refuse_file):
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

    def test_namespace_admission_holds_before_payload_write_or_subprocess(self):
        import windows_scoped
        shared = self.node_with_descriptor("dispatcher-shared", "D:P(A;OICI;FA;;;CURRENT_USER)(A;OICI;FR;;;WD)")
        with mock.patch.object(windows_scoped, "_WORK_ROOT", shared), \
             mock.patch.object(windows_scoped, "write_private_new") as writer, \
             mock.patch.object(windows_scoped.OwnedTransport, "start") as starter:
            with self.assertRaises(windows_scoped.CapabilityHold):
                windows_scoped._dispatch("create", data_base64="ZmljdGlvbmFsIHByaXZhdGUgYnl0ZXM=")
            self.assertFalse(writer.called)
            self.assertFalse(starter.called)
        self.assertTrue(list(shared.iterdir()) == [])

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

    def test_real_dispatch_request_response_and_temporaries_private(self):
        import windows_scoped
        self.assertTrue(windows_scoped.shutdown_worker(), "Earlier owned worker did not quiesce")
        original_runtime = windows_scoped._runtime()
        legacy = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        runtimes = [("preferred", original_runtime)]
        if Path(legacy).is_file() and legacy.casefold() != original_runtime.casefold():
            runtimes.append(("legacy", legacy))
        for category, executable in runtimes:
            with self.subTest(runtime=category):
                source = self.base / category
                private.ensure_private_directory(source, create=True)
                payload = b"fictional source content for private packet regression"
                private.write_private_new(source / "source.bin", payload)
                packets = self.base / (category + "-packets")
                with mock.patch.object(windows_scoped, "_WORK_ROOT", packets), \
                     mock.patch.object(windows_scoped, "_runtime", return_value=executable):
                    try:
                        with windows_scoped.ScopedRoot(source, quiet_workspace=True) as scope:
                            record = scope.inspect("source.bin", hash_file=True)
                            self.assertTrue(scope.read_bytes("source.bin", expected=record, max_bytes=1024) == payload)
                            scope.create_file("created.bin", data=payload, max_bytes=1024)
                        private.ensure_private_file(source / "created.bin")
                        self.assertTrue(self.protected_file_dacl(source / "created.bin"))
                        self.assertEqual((source / "created.bin").read_bytes(), payload)
                        private.ensure_private_directory(packets)
                        children = list(packets.iterdir())
                        requests = [p for p in children if p.name.startswith("request-")]
                        workers = [p for p in children if p.name.startswith("worker-")]
                        self.assertEqual(len(requests), 4)
                        self.assertEqual(len(workers), 1)
                        self.assertEqual(set(children), set(requests + workers))
                        for directory in children:
                            self.assertTrue(len(directory.name.rsplit("-", 1)[1]) == 32)
                            self.assertTrue(all(c in "0123456789abcdef" for c in directory.name.rsplit("-", 1)[1]))
                            private.ensure_private_directory(directory)
                            for entry in directory.rglob("*"):
                                if entry.is_dir():
                                    self.assert_private_compiler_directory(entry, directory)
                                else:
                                    private.ensure_private_file(entry)
                        for name in ("Windows.Scoped.Dispatch.ps1", "Windows.Scoped.cs"):
                            snapshot = workers[0] / name
                            private.ensure_private_file(snapshot)
                            self.assertEqual(hashlib.sha256(snapshot.read_bytes()).digest(),
                                             hashlib.sha256((ROOT / "scripts" / name).read_bytes()).digest())
                        content_input = content_output = False
                        operations = []
                        for request in requests:
                            q = json.loads((request / "request.json").read_text(encoding="utf-8"))
                            r = json.loads((request / "response.json").read_text(encoding="utf-8"))
                            operations.append(q.get("operation"))
                            content_input |= q.get("operation") == "create" and bool(q.get("data_base64"))
                            content_output |= q.get("operation") == "read" and bool(r.get("result", {}).get("data_base64"))
                            if q.get("operation") == "create":
                                self.assertEqual(base64.b64decode(q["data_base64"], validate=True), payload)
                            if q.get("operation") == "read":
                                self.assertEqual(base64.b64decode(r["result"]["data_base64"], validate=True), payload)
                        self.assertEqual(sorted(operations), ["create", "inspect", "inspect", "read"])
                        self.assertTrue(content_input and content_output)
                    finally:
                        # Retire and release snapshot/request pins before these
                        # patched runtime/namespace values leave their scope.
                        self.assertTrue(windows_scoped.shutdown_worker(), "Owned worker teardown was not proven")


@unittest.skipUnless(os.name == "posix", "POSIX private mode/owner fixtures")
class PosixPrivateWorkspaceTests(unittest.TestCase):
    def test_private_modes_or_honest_non_enforcing_filesystem_hold(self):
        path = FIXTURES / ("posix-" + uuid.uuid4().hex)
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
