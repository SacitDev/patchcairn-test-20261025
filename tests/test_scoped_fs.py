"""Fictional scoped-filesystem checks; every fixture stays in owned work/.

Run: python3 -I -S -B tests/test_scoped_fs.py
Native POSIX checks require real no-follow/dir-fd support; no unsafe fallback.
"""
from __future__ import annotations

import hashlib
import io
import ctypes
import errno
import os
from pathlib import Path
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
import scoped_fs as fs


class ContractTests(unittest.TestCase):
    def test_literal_relative_paths(self):
        for path in ("../escape", "a/../b", "/abs", "a\\b", "a//b", "a/./b", "x:",
                     "con.txt", "nul", "foo.", "foo ", "a/", "x\x00y", "x\ud800y", "COM¹.txt", "lpt0", "a" * 201):
            with self.subTest(path=repr(path)), self.assertRaises(fs.ScopedFSError):
                fs.relative_path(path)
        self.assertEqual(fs.relative_path("safe names/a-file.txt"), "safe names/a-file.txt")
        self.assertEqual(fs.relative_path("", allow_root=True), "")

    def test_errors_and_path_grammar_are_the_shared_ones(self):
        import pc_records
        import scoped_base
        self.assertIs(fs.ScopedFSError, scoped_base.ScopedFSError)
        self.assertIs(fs.CapabilityHold, scoped_base.CapabilityHold)
        self.assertIs(fs.relative_path, scoped_base.relative_path)
        self.assertTrue(issubclass(fs.CapabilityHold, pc_records.Refusal))
        with self.assertRaises(fs.ScopedFSError) as caught:
            fs.relative_path("/".join(["a"] * 65))
        self.assertEqual(caught.exception.code, "path-too-long")

    def test_windows_missing_native_adapter_is_hold(self):
        with mock.patch.object(fs.os, "name", "nt"), mock.patch.dict(sys.modules, {"windows_scoped": None}):
            self.assertFalse(fs.capabilities()["available"])
            with self.assertRaises(fs.CapabilityHold):
                fs.ScopedRoot("C:/fictional", quiet_workspace=True)

    def test_windows_unverified_adapter_is_hold(self):
        adapter = mock.Mock()
        adapter.capabilities.return_value = {"available": False}
        with mock.patch.object(fs.os, "name", "nt"), mock.patch.dict(sys.modules, {"windows_scoped": adapter}):
            with self.assertRaises(fs.CapabilityHold):
                fs.ScopedRoot("C:/fictional", quiet_workspace=True)
            adapter.ScopedRoot.assert_not_called()

    def test_windows_verified_adapter_dispatch(self):
        adapter = mock.Mock()
        adapter.capabilities.return_value = {"available": True, "adapter": "fictional-native"}
        with mock.patch.object(fs.os, "name", "nt"), mock.patch.dict(sys.modules, {"windows_scoped": adapter}):
            self.assertEqual(fs.capabilities()["adapter"], "fictional-native")
            result = fs.ScopedRoot("C:/fictional", quiet_workspace=True, max_entries=7)
            self.assertIs(result, adapter.ScopedRoot.return_value)
            adapter.ScopedRoot.assert_called_once_with("C:/fictional", quiet_workspace=True, max_entries=7)

    def test_quiet_workspace_required_before_windows_dispatch(self):
        with mock.patch.object(fs.os, "name", "nt"):
            with self.assertRaises(fs.ScopedFSError) as caught:
                fs.ScopedRoot("C:/fictional", quiet_workspace=False)
            self.assertEqual(caught.exception.code, "workspace-not-quiet")

    def test_incomplete_posix_capability_never_falls_back(self):
        with mock.patch.object(fs.os, "name", "posix"), mock.patch.object(fs, "_posix_capable", return_value=False):
            with self.assertRaises(fs.CapabilityHold):
                fs.ScopedRoot("/fictional", quiet_workspace=True)

    def test_mocked_special_and_reparse_types_refuse(self):
        for info in (types.SimpleNamespace(st_mode=stat.S_IFIFO, st_nlink=1),
                     types.SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=1, st_file_attributes=0x400),
                     types.SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=2)):
            with self.assertRaises(fs.ScopedFSError):
                fs._ordinary(info)

    def test_darwin_binding_and_exact_exclusive_descriptor_call(self):
        native = mock.Mock(return_value=0)
        library = types.SimpleNamespace(renameatx_np=native)
        with mock.patch.object(fs.os, "name", "posix"), mock.patch.object(fs.sys, "platform", "darwin"), \
                mock.patch.object(fs.ctypes, "CDLL", return_value=library) as loader, \
                mock.patch.object(fs.os, "rename") as weak_rename:
            function = fs._rename_function()
            self.assertIs(function, native)
            loader.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
            self.assertEqual(native.argtypes, (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint))
            self.assertIs(native.restype, ctypes.c_int)
            fs._call_rename(function, 11, "reviewed.txt", 22, "quarantine.txt")
            native.assert_called_once_with(11, b"reviewed.txt", 22, b"quarantine.txt", 0x00000004)
            weak_rename.assert_not_called()

    def test_linux_binding_and_flag_are_preserved(self):
        native = mock.Mock(return_value=0)
        with mock.patch.object(fs.os, "name", "posix"), mock.patch.object(fs.sys, "platform", "linux"), \
                mock.patch.object(fs.ctypes, "CDLL", return_value=types.SimpleNamespace(renameat2=native)) as loader:
            function = fs._rename_function()
            loader.assert_called_once_with(None, use_errno=True)
            fs._call_rename(function, 11, "reviewed.txt", 22, "quarantine.txt")
            native.assert_called_once_with(11, b"reviewed.txt", 22, b"quarantine.txt", 1)

    def test_darwin_missing_symbol_or_library_is_hold_without_fallback(self):
        with mock.patch.object(fs.os, "name", "posix"), mock.patch.object(fs.sys, "platform", "darwin"), \
                mock.patch.object(fs.os, "rename") as weak_rename:
            with mock.patch.object(fs.ctypes, "CDLL", return_value=types.SimpleNamespace()):
                self.assertIsNone(fs._rename_function())
            with mock.patch.object(fs.ctypes, "CDLL", side_effect=OSError("fictional missing library")):
                self.assertIsNone(fs._rename_function())
            with self.assertRaises(fs.CapabilityHold):
                fs._call_rename(None, 11, "source.txt", 22, "target.txt")
            weak_rename.assert_not_called()

    def test_darwin_exclusive_rename_errors_refuse_without_fallback(self):
        native = mock.Mock(return_value=-1)
        with mock.patch.object(fs.os, "name", "posix"), mock.patch.object(fs.sys, "platform", "darwin"), \
                mock.patch.object(fs.os, "rename") as weak_rename:
            for code in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
                with self.subTest(code=code), mock.patch.object(fs.ctypes, "get_errno", return_value=code):
                    with self.assertRaises(fs.CapabilityHold):
                        fs._call_rename(native, 11, "source.txt", 22, "target.txt")
            # EEXIST can occur after a checked-absent destination. Native RENAME_EXCL refuses it instead of
            # replacing that new name, with WindowsRoot's codes; EXDEV (another mount) renamed nothing.
            for code, refusal in ((errno.EEXIST, "destination-exists"), (errno.ENOTEMPTY, "destination-exists"),
                                  (errno.EXDEV, "same-volume-required"), (errno.EACCES, "rename-refused-no-overwrite"),
                                  (errno.EIO, "rename-refused-no-overwrite")):
                with self.subTest(code=code), mock.patch.object(fs.ctypes, "get_errno", return_value=code):
                    with self.assertRaises(fs.ScopedFSError) as caught:
                        fs._call_rename(native, 11, "source.txt", 22, "target.txt")
                    self.assertEqual(caught.exception.code, refusal)
                    self.assertNotIsInstance(caught.exception, fs.CapabilityHold)
            self.assertTrue(all(call.args == (11, b"source.txt", 22, b"target.txt", 4) for call in native.call_args_list))
            weak_rename.assert_not_called()

    def test_unsupported_platform_never_loads_or_calls_native_rename(self):
        for platform, os_name in (("freebsd", "posix"), ("darwin", "nt")):
            with self.subTest(platform=platform, os_name=os_name), mock.patch.object(fs.os, "name", os_name), \
                    mock.patch.object(fs.sys, "platform", platform), mock.patch.object(fs.ctypes, "CDLL") as loader:
                self.assertIsNone(fs._rename_function())
                native = mock.Mock(return_value=0)
                with self.assertRaises(fs.CapabilityHold):
                    fs._call_rename(native, 11, "source.txt", 22, "target.txt")
                loader.assert_not_called()
                native.assert_not_called()


class InjectedPlatformTests(unittest.TestCase):
    """macOS-only, Linux-only and Windows branches with injected platforms, so they run on every system."""

    def test_macos_privacy_protection_is_a_categorical_refusal_for_eperm_only(self):
        denied = PermissionError(errno.EPERM, "fictional denial of /fictional/Documents")
        with mock.patch.object(fs.sys, "platform", "darwin"):
            refusal = fs._refusal(denied, "filesystem-access")
            self.assertEqual(refusal.code, "macos-privacy-protection")
            # EPERM may also be a sandbox or a locked folder, so the message does not claim privacy protection.
            self.assertIn("permission refused (possibly macOS privacy protection or the app sandbox)", str(refusal))
            # EACCES stays an ordinary access refusal: an unreadable folder is not a privacy prompt.
            self.assertEqual(fs._refusal(PermissionError(errno.EACCES, "fictional"), "filesystem-access").code,
                             "filesystem-access")
            with self.assertRaises(fs.ScopedFSError) as caught:
                fs._os("filesystem-access", mock.Mock(side_effect=denied))
            self.assertNotIn("/fictional", str(caught.exception))
        with mock.patch.object(fs.sys, "platform", "linux"):
            self.assertEqual(fs._refusal(denied, "filesystem-access").code, "filesystem-access")
        for number, code in ((errno.ENOENT, "missing-entry"), (errno.ELOOP, "reparse-point"), (errno.ENOSPC, "disk-full"),
                             (errno.EIO, "read-failed")):
            with self.subTest(errno=number):
                self.assertEqual(fs._refusal(OSError(number, "fictional"), "read-failed").code, code)

    def test_macos_dataless_placeholder_is_left_out_as_special(self):
        def entry(mode, flags, nlink=1):
            return types.SimpleNamespace(st_mode=mode, st_nlink=nlink, st_flags=flags)
        self.assertEqual(fs._left_out(entry(stat.S_IFREG | 0o600, 0x40000000)), "special")
        self.assertEqual(fs._left_out(entry(stat.S_IFDIR | 0o700, 0x40000000, 2)), "special")
        self.assertIsNone(fs._left_out(entry(stat.S_IFREG | 0o600, stat.UF_HIDDEN)))
        self.assertEqual(fs._left_out(entry(stat.S_IFLNK | 0o777, 0x40000000)), "link")

    def test_sync_uses_full_fsync_on_macos_and_fsync_on_linux(self):
        calls = []
        native = types.SimpleNamespace(fcntl=lambda fd, operation, *args: calls.append((fd, operation, *args)))
        with mock.patch.object(fs.sys, "platform", "darwin"), mock.patch.object(fs, "fcntl", native), \
                mock.patch.object(fs.os, "fsync", side_effect=AssertionError("fsync does not reach the drive on macOS")):
            self.assertIs(fs._sync(11, 12), True)
            self.assertEqual(calls, [(11, 51), (12, 51)])
        native.fcntl = mock.Mock(side_effect=[OSError(errno.ENOTSUP, "fictional"), 0])
        with mock.patch.object(fs.sys, "platform", "darwin"), mock.patch.object(fs, "fcntl", native), \
                mock.patch.object(fs.os, "fsync") as fsync:
            # Without F_FULLFSYNC (for example exFAT) the file is still fsync'd, but not reported durable.
            self.assertIs(fs._sync(11, 12), False)
            self.assertEqual(native.fcntl.call_args_list, [mock.call(11, 51), mock.call(12, 51)])
            fsync.assert_called_once_with(11)
        with mock.patch.object(fs.sys, "platform", "linux"), mock.patch.object(fs.os, "fsync") as fsync:
            self.assertIs(fs._sync(11, 12), True)
            self.assertEqual(fsync.call_args_list, [mock.call(11), mock.call(12)])
            fsync.side_effect = [None, OSError(errno.EIO, "fictional")]
            self.assertIs(fs._sync(11, 12), False)

    def test_uncached_read_uses_nocache_on_macos_and_fadvise_on_linux(self):
        native = types.SimpleNamespace(fcntl=mock.Mock(return_value=0))
        with mock.patch.object(fs.sys, "platform", "darwin"), mock.patch.object(fs, "fcntl", native):
            fs._uncache(11)
            native.fcntl.assert_called_once_with(11, 48, 1)
            native.fcntl.side_effect = OSError(errno.EINVAL, "fictional")
            with self.assertRaises(fs.CapabilityHold) as caught:
                fs._uncache(11)
            self.assertEqual(caught.exception.code, "uncached-read-unavailable")
        with mock.patch.object(fs.sys, "platform", "linux"), \
                mock.patch.object(fs.os, "POSIX_FADV_DONTNEED", 4, create=True), \
                mock.patch.object(fs.os, "posix_fadvise", create=True) as advise:
            fs._uncache(11)
            advise.assert_called_once_with(11, 0, 0, 4)
        with mock.patch.object(fs.sys, "platform", "freebsd"), self.assertRaises(fs.CapabilityHold):
            fs._uncache(11)

    def test_immutable_and_append_only_flags_make_a_file_read_only(self):
        def flags(value):
            return types.SimpleNamespace(st_flags=value)
        with mock.patch.object(fs.sys, "platform", "darwin"):
            for value, locked in ((stat.UF_IMMUTABLE, True), (stat.UF_APPEND, True), (stat.SF_IMMUTABLE, True),
                                  (stat.SF_APPEND, True), (stat.UF_HIDDEN, False), (0, False)):
                with self.subTest(st_flags=hex(value)):
                    self.assertIs(fs._locked(11, flags(value)), locked)

        def native(value):
            def ioctl(fd, request, buffer, mutate):
                self.assertEqual((fd, request, mutate), (11, 0x80086601, True))
                buffer[:4] = value.to_bytes(4, sys.byteorder)
                return 0
            return types.SimpleNamespace(ioctl=mock.Mock(side_effect=ioctl))
        machine = types.SimpleNamespace(machine="x86_64")
        with mock.patch.object(fs.sys, "platform", "linux"), mock.patch.object(fs.os, "uname", return_value=machine, create=True):
            for value, locked in ((0x10, True), (0x20, True), (0x80000, False), (0, False)):
                with self.subTest(flags=hex(value)), mock.patch.object(fs, "fcntl", native(value)):
                    self.assertIs(fs._locked(11, flags(0)), locked)
            with mock.patch.object(fs, "fcntl", types.SimpleNamespace(ioctl=mock.Mock(side_effect=OSError(errno.ENOTTY, "x")))):
                self.assertIs(fs._locked(11, flags(0)), False)  # no such flags here; unlinkat refuses a locked file
            # On powerpc the same request number would set the flags: it is never sent there.
            machine.machine = "ppc64le"
            unused = native(0x10)
            with mock.patch.object(fs, "fcntl", unused):
                self.assertIs(fs._locked(11, flags(0)), False)
            unused.ioctl.assert_not_called()

    def test_destination_volume_kinds(self):
        # Only a native file system on a drive proven fixed is private; elsewhere ids are not stable (D-069).
        for (filesystem, removable), expected in {("native", False): ("private", True), ("native", True): ("non-private", False),
                                                  ("fat", True): ("fat32", False), ("fat", False): ("fat32", False),
                                                  ("exfat", True): ("non-private", False), ("other", False): ("unsupported", False)}.items():
            with self.subTest(filesystem=filesystem, removable=removable):
                self.assertEqual(fs._destination_volume({"filesystem": filesystem, "removable": removable}), expected)
        for facts in (None, {}, {"filesystem": "ntfs", "removable": False}, {"filesystem": "native", "removable": 1}):
            with self.subTest(facts=facts):
                with self.assertRaises(fs.ScopedFSError) as caught:
                    fs._destination_volume(facts)
                self.assertEqual(caught.exception.code, "filesystem-capability-unavailable")

    def test_default_volume_source_reads_the_privacy_modules(self):
        for fixed in (True, False):
            with self.subTest(fixed=fixed), mock.patch.object(fs.sys, "platform", "linux"), \
                    mock.patch.object(fs.linux_privacy, "filesystem_kind", return_value="native") as kind, \
                    mock.patch.object(fs.linux_privacy, "fixed_disk", return_value=fixed) as proof:
                self.assertEqual(fs._volume_facts(7), {"filesystem": "native", "removable": not fixed})
                kind.assert_called_once_with(7)
                proof.assert_called_once_with(7)  # the open descriptor: btrfs is found through its mnt_id
        with mock.patch.object(fs.sys, "platform", "darwin"), \
                mock.patch.object(fs.darwin_privacy, "volume_kind", return_value=("native", True)) as kind:
            self.assertEqual(fs._volume_facts(7), {"filesystem": "native", "removable": True})
            kind.assert_called_once_with(7)
        with mock.patch.object(fs.sys, "platform", "freebsd"):
            self.assertEqual(fs._volume_facts(7), {"filesystem": "other", "removable": True})

    def test_another_disk_only_when_sysfs_proves_it(self):
        class Root:
            def __init__(self, device):
                self.device = device

            def inspect(self, relative):
                return {"device": self.device}

        class Pinned(Root, fs.PosixRoot):
            def __init__(self, device):  # a root that holds descriptor 100 + device, without opening anything
                self.device, self._fd = device, 100 + device
        disks = {1: "/sys/devices/x/block/sda", 2: "/sys/devices/x/block/sda", 3: "nvme:nqn.2014-08.org.example:one", 4: None}

        def sysfs(root):
            return disks.get(root.device)
        with mock.patch.object(fs.os, "name", "posix"), mock.patch.object(fs.sys, "platform", "linux"):
            self.assertEqual(fs.disk_relation(Root(1), Root(1), sysfs=mock.Mock(side_effect=AssertionError)), "same")
            for first, second, relation in ((1, 2, "same"), (1, 3, "different"), (1, 4, "unknown"), (4, 4, "same")):
                with self.subTest(first=first, second=second):
                    self.assertEqual(fs.disk_relation(Root(first), Root(second), sysfs=sysfs), relation)
        with mock.patch.object(fs.os, "name", "posix"), mock.patch.object(fs.sys, "platform", "linux"), \
                mock.patch.object(fs.linux_privacy, "physical_disk", side_effect=lambda fd: disks.get(fd - 100)) as default:
            self.assertEqual(fs.disk_relation(Pinned(1), Pinned(3)), "different")  # the default: each root's descriptor
            self.assertEqual(default.call_args_list, [mock.call(101), mock.call(103)])
            self.assertEqual(fs.disk_relation(Root(1), Root(3)), "unknown")  # not a PosixRoot: no descriptor to trace
        with mock.patch.object(fs.os, "name", "posix"), mock.patch.object(fs.sys, "platform", "darwin"):
            self.assertEqual(fs.disk_relation(Root(1), Root(3), sysfs=sysfs), "unknown")
            self.assertEqual(fs.disk_relation(Root(3), Root(3)), "same")
        with mock.patch.object(fs.os, "name", "nt"):
            self.assertEqual(fs.disk_relation(Root(1), Root(1)), "unknown")

    def test_windows_entry_points_delegate_to_windows_scoped(self):
        adapter, root, removal = mock.Mock(), mock.Mock(), mock.Mock()
        with mock.patch.object(fs.os, "name", "nt"), mock.patch.dict(sys.modules, {"windows_scoped": adapter}):
            self.assertIs(fs.admit_destination("C:\\fictional", non_private_destination=True, volumes="facts", max_entries=5),
                          adapter.admit_destination.return_value)
            adapter.admit_destination.assert_called_once_with("C:\\fictional", non_private_destination=True,
                                                              volumes="facts", max_entries=5)
            self.assertIs(fs.process_is_elevated(), adapter.process_is_elevated.return_value)
            # The delete handle already closes the window: no removal folder is used on Windows.
            self.assertIs(fs.remove_original(root, "a.txt", expected={"fictional": 1}, sha256="b" * 64, allow_read_only=True,
                                             removal=removal, removal_name="unused"), root.remove_file.return_value)
            root.remove_file.assert_called_once_with("a.txt", expected={"fictional": 1}, sha256="b" * 64, allow_read_only=True)
            self.assertEqual(removal.method_calls, [])
        with mock.patch.object(fs.os, "name", "nt"), mock.patch.dict(sys.modules, {"windows_scoped": None}):
            for call in (lambda: fs.admit_destination("C:\\fictional"), fs.process_is_elevated):
                with self.assertRaises(fs.CapabilityHold) as caught:
                    call()
                self.assertEqual(caught.exception.code, "native-unavailable")

    def test_posix_elevation_is_the_effective_root_user(self):
        with mock.patch.object(fs.os, "name", "posix"):
            for uid, elevated in ((0, True), (1000, False)):
                with self.subTest(uid=uid), mock.patch.object(fs.os, "geteuid", return_value=uid, create=True):
                    self.assertIs(fs.process_is_elevated(), elevated)

    def test_removal_without_a_removal_folder_needs_in_place(self):
        root = mock.Mock()
        for os_name in ("posix", "nt"):
            with self.subTest(os_name=os_name), mock.patch.object(fs.os, "name", os_name):
                for options in ({}, {"in_place": 1}, {"in_place": True, "removal": root, "removal_name": fs.new_removal_name()}):
                    with self.assertRaises(fs.ScopedFSError) as caught:
                        fs.remove_original(root, "a.txt", expected={"fictional": 1}, **options)
                    self.assertEqual(caught.exception.code, "invalid-option")
                root.remove_file.assert_not_called()
        with mock.patch.object(fs.os, "name", "posix"):
            self.assertIs(fs.remove_original(root, "a.txt", expected={"fictional": 1}, in_place=True),
                          root.remove_file.return_value)
            root.remove_file.assert_called_once_with("a.txt", expected={"fictional": 1}, sha256=None, allow_read_only=False)
            for removal in (object(), root):
                with self.subTest(removal=removal):
                    with self.assertRaises(fs.ScopedFSError) as caught:
                        fs.remove_original(root, "a.txt", expected={"fictional": 1}, removal=removal,
                                           removal_name=fs.new_removal_name())
                    self.assertEqual(caught.exception.code, "removal-folder")


@unittest.skipUnless(fs._posix_capable(), "only on posix: native POSIX no-follow/dir-fd support is required")
class PosixTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / "work" / "test-fixtures" / "filesystem" / ("fixture-" + uuid.uuid4().hex)
        self.base.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.base)
        self.source = self.base / "selected"
        self.source.mkdir()
        self.target = self.base / "quarantine"
        self.target.mkdir()
        (self.source / "a.txt").write_bytes(b"Fictional bounded content\n")
        self.fs = fs.ScopedRoot(self.source, quiet_workspace=True)
        self.addCleanup(self.fs.close)

    def hashed(self, relative="a.txt"):
        return self.fs.inspect(relative, hash_file=True, max_bytes=1024)

    def test_metadata_then_hash_and_exact_bounded_read(self):
        metadata = self.fs.inspect("a.txt")
        self.assertIsNone(metadata["sha256"])
        row = self.hashed()
        self.assertGreater(row["inode"], 0)
        self.assertEqual(row["nlink"], 1)
        self.assertEqual(row["sha256"], hashlib.sha256(b"Fictional bounded content\n").hexdigest())
        self.assertEqual(self.fs.read_bytes("a.txt", expected=row, max_bytes=1024), b"Fictional bounded content\n")
        self.assertEqual(self.fs.inspect("")["kind"], "directory")

    def test_listing_does_not_descend_and_snapshot_has_root(self):
        (self.source / "protected").mkdir()
        (self.source / "protected" / "unopened.txt").write_bytes(b"fictional protected data")
        with mock.patch.object(fs.os, "readv", side_effect=AssertionError("content read")):
            rows = self.fs.list_directory()
            self.assertEqual([r["relative_path"] for r in rows], ["a.txt", "protected"])
            rows = self.fs.snapshot()
            self.assertEqual([r["relative_path"] for r in rows], ["", "a.txt", "protected", "protected/unopened.txt"])

    def test_hash_snapshot_file_and_total_caps(self):
        with self.assertRaises(fs.ScopedFSError):
            self.fs.snapshot(hash_files=True, max_file_bytes=2)
        (self.source / "b.txt").write_bytes(b"more fictional bytes")
        with self.assertRaises(fs.ScopedFSError):
            self.fs.snapshot(hash_files=True, max_total_bytes=30)
        self.assertTrue(all(r["sha256"] for r in self.fs.snapshot(hash_files=True) if r["kind"] == "file"))

    def test_entry_and_depth_caps(self):
        (self.source / "b.txt").write_bytes(b"second fictional entry")  # the cap counts entries, not the root
        with fs.ScopedRoot(self.source, quiet_workspace=True, max_entries=1) as tiny:
            with self.assertRaises(fs.ScopedFSError):
                tiny.snapshot()
        with self.assertRaises(fs.ScopedFSError):
            fs.relative_path("/".join(["a"] * 65))

    def test_read_needs_hash_and_valid_cap(self):
        with self.assertRaises(fs.ScopedFSError):
            self.fs.read_bytes("a.txt", expected=self.fs.inspect("a.txt"), max_bytes=1024)
        row = self.hashed()
        for cap in (0, -1, True, fs.DEFAULT_MAX_FILE_BYTES + 1):
            with self.subTest(cap=cap), self.assertRaises(fs.ScopedFSError):
                self.fs.read_bytes("a.txt", expected=row, max_bytes=cap)
        with self.assertRaises(fs.ScopedFSError):
            self.fs.read_bytes("a.txt", expected=row, max_bytes=2)

    def test_stream_uses_chunks_and_checks_consumer(self):
        row = self.hashed()
        sink = io.BytesIO()
        actual = self.fs.stream_to("a.txt", expected=row, writer=sink.write, max_bytes=1024, chunk_size=4)
        self.assertEqual(actual, row)
        self.assertEqual(sink.getvalue(), b"Fictional bounded content\n")
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.fs.stream_to("a.txt", expected=row, writer=lambda _: 0, max_bytes=1024)
        self.assertEqual(caught.exception.code, "short-write")

    def test_growth_during_read_refuses_even_if_cap_remains(self):
        row = self.hashed()
        first = True
        def append(_):
            nonlocal first
            if first:
                first = False
                with (self.source / "a.txt").open("ab") as out:
                    out.write(b"fictional growth")
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.fs.stream_to("a.txt", expected=row, writer=append, max_bytes=1024, chunk_size=4)
        self.assertIn(caught.exception.code, {"read-growth", "read-drift"})

    def test_same_size_content_change_during_read_refuses(self):
        row = self.hashed()
        first = True
        def modify(_):
            nonlocal first
            if first:
                first = False
                info = (self.source / "a.txt").stat()
                with (self.source / "a.txt").open("r+b") as out:
                    out.write(b"X")
                # An explicit time, never the clock (D-056): a write in the same clock tick keeps the old one.
                os.utime(self.source / "a.txt", ns=(info.st_atime_ns, info.st_mtime_ns + 10 ** 9))
        with self.assertRaises(fs.ScopedFSError):
            self.fs.stream_to("a.txt", expected=row, writer=modify, max_bytes=1024, chunk_size=4)

    def test_stale_replaced_identity_refuses_read_move_and_remove(self):
        row = self.hashed()
        replacement = self.source / "replacement.txt"
        replacement.write_bytes((self.source / "a.txt").read_bytes())
        os.replace(replacement, self.source / "a.txt")
        with fs.ScopedRoot(self.target, quiet_workspace=True) as target:
            for operation in (lambda: self.fs.read_bytes("a.txt", expected=row, max_bytes=1024),
                              lambda: self.fs.move_to("a.txt", destination=target, destination_relative="saved.txt", expected=row),
                              lambda: self.fs.remove_file("a.txt", expected=row)):
                with self.assertRaises(fs.ScopedFSError):
                    operation()
        self.assertTrue((self.source / "a.txt").is_file())
        self.assertFalse((self.target / "saved.txt").exists())

    def test_read_only_quarantined_file_is_purged_as_before(self):
        # storage_ops purges a quarantine whose plan lists each file's record; a 0444 file (a git object, an extracted
        # archive member) is removed as the old adapter did, because the approved record shows it read-only (PD-10).
        os.chmod(self.source / "a.txt", 0o444)
        original = self.hashed()
        with fs.ScopedRoot(self.target, quiet_workspace=True) as quarantine:
            try:
                kept = self.fs.move_to("a.txt", destination=quarantine, destination_relative="000001", expected=original)
            except fs.CapabilityHold:  # no no-replace rename here: purge the original in place instead
                kept, quarantine = original, self.fs
            self.assertTrue(fs.scoped_base.read_only(kept))
            try:
                self.assertIsNone(quarantine.remove_file(kept["relative_path"], expected=kept))
            except fs.ScopedFSError as error:
                self.fail(f"the purge refused the planned read-only file: {error}")
        self.assertEqual((os.listdir(self.target), (self.source / "a.txt").exists()), ([], False))

    def test_wrong_hash_refuses_purge_without_deleting(self):
        row = self.hashed()
        row["sha256"] = "0" * 64
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.fs.remove_file("a.txt", expected=row)
        self.assertEqual(caught.exception.code, "stale-content")
        self.assertTrue((self.source / "a.txt").exists())

    def test_exact_purge_keeps_other_files_and_directories(self):
        (self.source / "keep.txt").write_bytes(b"keep fictional file")
        (self.source / "keep-dir").mkdir()
        self.fs.remove_file("a.txt", expected=self.hashed())
        self.assertFalse((self.source / "a.txt").exists())
        self.assertTrue((self.source / "keep.txt").is_file())
        self.assertTrue((self.source / "keep-dir").is_dir())
        with self.assertRaises(fs.ScopedFSError):
            self.fs.remove_file("keep-dir", expected=self.fs.inspect("keep-dir"))

    def test_exclusive_create_and_mkdir(self):
        directory = self.fs.mkdir("owned")
        self.assertEqual(directory["kind"], "directory")
        row = self.fs.create_file("owned/new.txt", data=b"fictional new file", max_bytes=100)
        self.assertEqual(self.fs.read_bytes("owned/new.txt", expected=row, max_bytes=100), b"fictional new file")
        with self.assertRaises(fs.ScopedFSError):
            self.fs.create_file("owned/new.txt", data=b"replacement", max_bytes=100)
        with self.assertRaises(fs.ScopedFSError):
            self.fs.mkdir("owned")
        self.assertEqual((self.source / "owned" / "new.txt").read_bytes(), b"fictional new file")

    def test_quarantine_restore_no_overwrite_and_identity(self):
        original = self.hashed()
        with fs.ScopedRoot(self.target, quiet_workspace=True) as target:
            try:
                moved = self.fs.move_to("a.txt", destination=target, destination_relative="saved.txt", expected=original)
            except fs.CapabilityHold as hold:
                # Where the file system has no no-replace rename the move holds and nothing moves (never copy/delete).
                self.assertEqual(hold.code, "no-replace-unavailable")
                self.assertTrue((self.source / "a.txt").exists())
                self.assertFalse((self.target / "saved.txt").exists())
                return
            self.assertFalse((self.source / "a.txt").exists())
            self.assertEqual(moved["inode"], original["inode"])
            self.assertEqual(moved["sha256"], original["sha256"])
            restored = target.move_to("saved.txt", destination=self.fs, destination_relative="a.txt", expected=moved)
            self.assertEqual(restored["sha256"], original["sha256"])
            target.create_file("occupied.txt", data=b"preserve", max_bytes=100)
            with self.assertRaises(fs.ScopedFSError):
                self.fs.move_to("a.txt", destination=target, destination_relative="occupied.txt", expected=restored)
            self.assertEqual((self.target / "occupied.txt").read_bytes(), b"preserve")

    def test_move_verification_and_scope_with_simulated_native_rename(self):
        # Exercise the successful identity protocol without pretending that this
        # stub certifies a filesystem's native RENAME_NOREPLACE implementation.
        def simulated(src_fd, src_name, dst_fd, dst_name, flags):
            self.assertEqual(flags, 4 if sys.platform == "darwin" else 1)
            self.assertNotIn(os.fsdecode(dst_name), os.listdir(dst_fd))
            os.rename(src_name, dst_name, src_dir_fd=src_fd, dst_dir_fd=dst_fd)
            return 0
        original = self.hashed()
        with fs.ScopedRoot(self.target, quiet_workspace=True) as target, mock.patch.object(fs, "_rename_function", return_value=simulated):
            moved = self.fs.move_to("a.txt", destination=target, destination_relative="saved.txt", expected=original)
            self.assertEqual(moved["inode"], original["inode"])
            self.assertEqual(moved["sha256"], original["sha256"])
            restored = target.move_to("saved.txt", destination=self.fs, destination_relative="a.txt", expected=moved)
            self.assertEqual(restored["sha256"], original["sha256"])
            (self.target / "occupied.txt").write_bytes(b"preserve")
            with self.assertRaises(fs.ScopedFSError):
                self.fs.move_to("a.txt", destination=target, destination_relative="occupied.txt", expected=restored)
            self.assertEqual((self.target / "occupied.txt").read_bytes(), b"preserve")

    def test_mocked_case_collision_is_left_out_and_refused_explicitly(self):
        excluded = []
        with mock.patch.object(fs.os, "listdir", return_value=["Case.txt", "case.txt", "cafe\u0301.txt", "caf\u00e9.txt"]):
            self.assertEqual(self.fs.list_directory(excluded=excluded), [])
            for name in ("case.txt", "caf\u00e9.txt"):
                with self.subTest(name=name), self.assertRaises(fs.ScopedFSError) as caught:
                    self.fs.inspect(name)
                self.assertEqual(caught.exception.code, "case-collision")
        # Case and NFC/NFD forms both collide (pc_paths.casefold_key), so a restore onto APFS cannot clash.
        self.assertEqual(excluded, [{"parent": "", "name": name, "reason": "case-collision"}
                                    for name in sorted(["Case.txt", "case.txt", "cafe\u0301.txt", "caf\u00e9.txt"])])

    def test_no_native_rename_is_hold_and_never_copy_delete(self):
        with fs.ScopedRoot(self.target, quiet_workspace=True) as target, mock.patch.object(fs, "_rename_function", return_value=None):
            with self.assertRaises(fs.CapabilityHold):
                self.fs.move_to("a.txt", destination=target, destination_relative="saved.txt", expected=self.hashed())
        self.assertTrue((self.source / "a.txt").exists())
        self.assertFalse((self.target / "saved.txt").exists())

    def test_cross_device_refusal_before_native_mutation(self):
        with fs.ScopedRoot(self.target, quiet_workspace=True) as target:
            target._root._device = self.fs._root._device + 1
            with mock.patch.object(fs, "_rename_function") as rename:
                with self.assertRaises(fs.ScopedFSError) as caught:
                    self.fs.move_to("a.txt", destination=target, destination_relative="saved.txt", expected=self.hashed())
                self.assertEqual(caught.exception.code, "same-volume-required")
                rename.assert_not_called()

    def test_symlink_leaf_parent_and_admission_refuse(self):
        (self.source / "alias").symlink_to(self.target, target_is_directory=True)
        (self.base / "root-alias").symlink_to(self.source, target_is_directory=True)
        excluded = []
        self.assertEqual([row["relative_path"] for row in self.fs.list_directory(excluded=excluded)], ["a.txt"])
        self.assertEqual(excluded, [{"parent": "", "name": "alias", "reason": "link"}])
        # Without ``excluded`` (a folder PatchCairn owns) the unknown entry refuses the listing and the snapshot.
        for call in (self.fs.list_directory, self.fs.snapshot):
            with self.subTest(call=call.__name__):
                with self.assertRaises(fs.ScopedFSError) as caught:
                    call()
                self.assertEqual(caught.exception.code, "link")
        snapped = []
        self.assertEqual([row["relative_path"] for row in self.fs.snapshot(excluded=snapped)], ["", "a.txt"])
        self.assertEqual(snapped, [{"parent": "", "name": "alias", "reason": "link"}])
        for relative in ("alias", "alias/escape.txt"):
            with self.subTest(relative=relative), self.assertRaises(fs.ScopedFSError):
                self.fs.inspect(relative)
        with self.assertRaises(fs.ScopedFSError):
            fs.ScopedRoot(self.base / "root-alias", quiet_workspace=True)

    def test_hardlinks_refused_before_content_open(self):
        os.link(self.source / "a.txt", self.source / "second.txt")
        excluded = []
        with mock.patch.object(fs.os, "open", side_effect=AssertionError("file opened")):
            self.assertEqual(self.fs.list_directory(excluded=excluded), [])
        self.assertEqual(excluded, [{"parent": "", "name": name, "reason": "hard-link"} for name in ("a.txt", "second.txt")])
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.fs.inspect("second.txt", hash_file=True)
        self.assertEqual(caught.exception.code, "hard-link")

    def test_special_file_refused_without_blocking(self):
        os.mkfifo(self.source / "fictional-pipe")
        excluded = []
        self.assertEqual([row["relative_path"] for row in self.fs.list_directory(excluded=excluded)], ["a.txt"])
        self.assertEqual(excluded, [{"parent": "", "name": "fictional-pipe", "reason": "special"}])
        with self.assertRaises(fs.ScopedFSError):
            self.fs.inspect("fictional-pipe", hash_file=True)

    def test_case_collision_names_are_left_out_and_refused_explicitly(self):
        (self.source / "Case.txt").write_bytes(b"one")
        (self.source / "case.txt").write_bytes(b"two")
        names = os.listdir(self.source)
        if {"Case.txt", "case.txt"} <= set(names):
            excluded = []
            self.assertEqual([row["relative_path"] for row in self.fs.list_directory(excluded=excluded)], ["a.txt"])
            self.assertEqual(excluded, [{"parent": "", "name": name, "reason": "case-collision"} for name in ("Case.txt", "case.txt")])
            with self.assertRaises(fs.ScopedFSError) as caught:
                self.fs.inspect("case.txt")
            self.assertEqual(caught.exception.code, "case-collision")
        else:
            # A case-insensitive volume (the macOS default) keeps the first spelling as one entry, so no
            # collision can exist; the listing is in code-point order.
            self.assertIn("Case.txt", names)
            self.assertEqual([row["relative_path"] for row in self.fs.list_directory()], sorted(names))

    def test_names_other_systems_cannot_use_are_left_out_not_refused(self):
        # Legal on Linux and macOS, but not portable: listed as not included; the folder itself stays usable.
        for name in ("ok.txt", "What now?.txt", "lpt0.log"):
            (self.source / name).write_bytes(b"Fictional portable-name fixture")
        excluded = []
        self.assertEqual([row["relative_path"] for row in self.fs.list_directory(excluded=excluded)], ["a.txt", "ok.txt"])
        self.assertEqual(sorted(excluded, key=lambda row: row["name"]),
                         [{"parent": "", "name": "What now?.txt", "reason": "not-portable"}, {"parent": "", "name": "lpt0.log", "reason": "not-portable"}])
        self.assertEqual(self.fs.inspect("ok.txt")["kind"], "file")
        for name in ("What now?.txt", "lpt0.log"):
            with self.subTest(name=name), self.assertRaises(fs.ScopedFSError):
                self.fs.inspect(name)
        snapshot_excluded = []
        self.assertEqual([row["relative_path"] for row in self.fs.snapshot(excluded=snapshot_excluded)], ["", "a.txt", "ok.txt"])
        self.assertEqual(sorted(row["name"] for row in snapshot_excluded), ["What now?.txt", "lpt0.log"])

    def test_path_beyond_portable_limit_is_left_out_and_never_admitted(self):
        deep = self.source / ("d" * 120) / ("e" * 90)
        deep.mkdir(parents=True)
        (deep / "unopened.txt").write_bytes(b"fictional entry beyond the portable path limit")
        long_path = ("d" * 120) + "/" + ("e" * 90)
        listed = []
        self.assertEqual(self.fs.list_directory("d" * 120, excluded=listed), [])
        self.assertEqual(listed, [{"parent": "d" * 120, "name": "e" * 90, "reason": "path-too-long"}])
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.fs.inspect(long_path)
        self.assertEqual(caught.exception.code, "path-too-long")
        excluded = []
        rows = self.fs.snapshot(excluded=excluded)
        self.assertNotIn(long_path, [row["relative_path"] for row in rows])
        self.assertEqual(excluded, [{"parent": "d" * 120, "name": "e" * 90, "reason": "path-too-long"}])

    def test_root_replacement_invalidates_pinned_handle(self):
        self.source.rename(self.base / "old-selected")
        self.source.mkdir()
        (self.source / "a.txt").write_bytes(b"replacement scope")
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.fs.inspect("a.txt")
        self.assertEqual(caught.exception.code, "ancestor-drift")

    def test_root_spelling_closed_and_missing_states_refuse(self):
        for root in ("/", "relative", str(self.source) + "/", str(self.source) + "/../selected"):
            with self.subTest(root=root), self.assertRaises(fs.ScopedFSError):
                fs.ScopedRoot(root, quiet_workspace=True)
        with self.assertRaises(fs.ScopedFSError):
            self.fs.inspect("missing.txt")
        self.fs.close()
        with self.assertRaises(fs.ScopedFSError):
            self.fs.inspect("")


def altered(info, **changes):
    """A copy of a stat result with some fields changed (an injected nested mount or macOS placeholder)."""
    fields = {name: getattr(info, name) for name in ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid",
                                                     "st_size", "st_atime_ns", "st_mtime_ns", "st_ctime_ns")}
    return types.SimpleNamespace(**{**fields, **changes})


@unittest.skipUnless(os.name == "posix", "only on posix: PosixRoot runs on POSIX descriptors")
class PosixRootTests(unittest.TestCase):
    """PosixRoot behaviour beyond the shared contract, on real folders under work/test-fixtures/."""

    def setUp(self):
        self.base = ROOT / "work" / "test-fixtures" / "filesystem" / ("posix-root-" + uuid.uuid4().hex)
        (self.base / "selected").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.base)
        self.root = fs.PosixRoot(str(self.base / "selected"))
        self.addCleanup(self.root.close)

    def names(self):
        return sorted(os.listdir(self.base / "selected"))

    def patched_stat(self, name, **changes):
        real = os.stat

        def lookup(path, *args, **kwargs):
            info = real(path, *args, **kwargs)
            return altered(info, **{key: value(info) for key, value in changes.items()}) if path == name else info
        return mock.patch.object(fs.os, "stat", lookup)

    def test_nested_mount_is_listed_as_link_and_refused_by_name(self):
        (self.base / "selected" / "mounted").mkdir()
        (self.base / "selected" / "mounted" / "inside.txt").write_bytes(b"fictional")
        (self.base / "selected" / "kept.txt").write_bytes(b"fictional")
        with self.patched_stat("mounted", st_dev=lambda info: info.st_dev + 1):
            excluded = []
            self.assertEqual([row["relative_path"] for row in self.root.list_directory(excluded=excluded)], ["kept.txt"])
            self.assertEqual(excluded, [{"parent": "", "name": "mounted", "reason": "link"}])
            for relative in ("mounted", "mounted/inside.txt"):
                with self.subTest(relative=relative):
                    with self.assertRaises(fs.ScopedFSError) as caught:
                        self.root.inspect(relative)
                    self.assertEqual(caught.exception.code, "filesystem-boundary")

    def test_macos_placeholder_is_listed_as_special_and_never_opened(self):
        (self.base / "selected" / "placeholder.txt").write_bytes(b"fictional")
        record = self.root.inspect("placeholder.txt", hash_file=True)
        real_open = os.open

        def opener(path, *args, **kwargs):
            self.assertNotEqual(path, "placeholder.txt", "a cloud placeholder was opened")
            return real_open(path, *args, **kwargs)
        with self.patched_stat("placeholder.txt", st_flags=lambda info: 0x40000000), mock.patch.object(fs.os, "open", opener):
            excluded = []
            self.assertEqual(self.root.list_directory(excluded=excluded), [])
            self.assertEqual(excluded, [{"parent": "", "name": "placeholder.txt", "reason": "special"}])
            for call in (lambda: self.root.inspect("placeholder.txt", hash_file=True),
                         lambda: self.root.open_read("placeholder.txt", expected=record).__enter__(),
                         lambda: self.root.remove_file("placeholder.txt", expected=record)):
                with self.assertRaises(fs.ScopedFSError) as caught:
                    call()
                self.assertEqual(caught.exception.code, "offline-encrypted-or-recall-file")
        self.assertEqual(self.names(), ["placeholder.txt"])

    def test_macos_privacy_protection_and_unreadable_folders_refuse(self):
        with mock.patch.object(fs.sys, "platform", "darwin"), \
                mock.patch.object(fs.os, "listdir", side_effect=PermissionError(errno.EPERM, "fictional")):
            with self.assertRaises(fs.ScopedFSError) as caught:
                self.root.list_directory()
        self.assertEqual(caught.exception.code, "macos-privacy-protection")
        self.assertIn("permission refused (possibly macOS privacy protection or the app sandbox)", str(caught.exception))
        (self.base / "selected" / "closed").mkdir()
        os.chmod(self.base / "selected" / "closed", 0)
        self.addCleanup(os.chmod, self.base / "selected" / "closed", 0o700)
        if os.geteuid() == 0:
            self.assertEqual(self.root.list_directory("closed"), [])  # the administrator reads every folder
        else:
            with self.assertRaises(fs.ScopedFSError) as caught:
                self.root.list_directory("closed")
            self.assertEqual(caught.exception.code, "filesystem-access")

    def test_private_new_file_is_owner_only_before_its_first_byte(self):
        (self.base / "usb").mkdir()
        previous = os.umask(0o277)  # 0o600 under this umask is 0o400: not the private mode
        try:
            with self.assertRaises(fs.ScopedFSError) as caught:
                with self.root.open_new("secret.bin") as out:
                    out.write(b"never written")
            # A destination admitted as not private skips only the privacy check.
            with fs.admit_destination(str(self.base / "usb"), non_private_destination=True,
                                      volumes=lambda fd: {"filesystem": "exfat", "removable": True}) as usb:
                with usb.open_new("backup.bin") as out:
                    out.write(b"archive")
                    record = out.commit()
        finally:
            os.umask(previous)
        self.assertEqual(caught.exception.code, "new-private-file-security-unresolved")
        self.assertEqual(self.names(), [])
        self.assertEqual((stat.S_IMODE(record["mode"]), record["size"]), (0o400, 7))

    def test_macos_new_private_entries_need_no_extended_acl(self):
        # macOS only: an inherited ACL entry can grant access past the 0600/0700 mode, so new private entries are
        # checked with darwin_privacy before anything is written (injected here, as no ACL can be made portably).
        # It reads the ACL of the open descriptor, so the object checked is the object written (no path).
        refusal, held = fs.darwin_privacy.DarwinPrivacyHold("darwin-acl-not-empty"), []

        def check(descriptor):
            info = os.fstat(descriptor)
            held.append((type(descriptor), stat.S_ISDIR(info.st_mode), stat.S_IMODE(info.st_mode)))
            raise refusal
        with mock.patch.object(fs.sys, "platform", "darwin"), mock.patch.object(fs, "_rename_function", return_value=object()), \
                mock.patch.object(fs.darwin_privacy, "assert_no_extended_acl_fd", side_effect=check) as checker:
            for call, code in ((lambda: self.root.open_new("secret.bin").__enter__(), "new-private-file-security-unresolved"),
                               (lambda: self.root.mkdir("private-folder"), "new-private-directory-security-unresolved")):
                with self.assertRaises(fs.ScopedFSError) as caught:
                    call()
                self.assertEqual(caught.exception.code, code)
            self.assertEqual(self.names(), [])
            self.assertEqual(held, [(int, False, 0o600), (int, True, 0o700)])
            checker.side_effect = None
            with self.root.open_new("allowed.bin") as out:
                self.assertEqual(out.write(b"fictional"), 9)
        self.assertEqual(self.names(), [])  # left without commit: the temporary file is gone

    def test_locked_file_is_read_only_and_no_mode_or_flag_changes(self):
        (self.base / "selected" / "locked.bin").write_bytes(b"fictional")
        record = self.root.inspect("locked.bin", hash_file=True)
        with mock.patch.object(fs, "_locked", return_value=True), \
                mock.patch.object(fs.os, "chmod", side_effect=AssertionError("mode changed")), \
                mock.patch.object(fs.os, "fchmod", side_effect=AssertionError("mode changed"), create=True):
            with self.assertRaises(fs.ScopedFSError) as caught:
                self.root.remove_file("locked.bin", expected=record)
            self.assertEqual(caught.exception.code, "read-only")
            self.assertEqual(self.names(), ["locked.bin"])
            self.assertEqual(self.root.remove_file("locked.bin", expected=record, allow_read_only=True)["sha256"], record["sha256"])
        self.assertEqual(self.names(), [])

    def test_no_replace_rename_unavailable_holds_and_leaves_nothing(self):
        with mock.patch.object(fs, "_rename_function", return_value=None):
            with self.assertRaises(fs.CapabilityHold) as caught:
                self.root.open_new("a.bin").__enter__()
        self.assertEqual(caught.exception.code, "no-replace-unavailable")
        refusing = mock.Mock(return_value=-1)
        with mock.patch.object(fs, "_rename_function", return_value=refusing), \
                mock.patch.object(fs.ctypes, "get_errno", return_value=errno.EINVAL):
            with self.assertRaises(fs.CapabilityHold) as caught:
                with self.root.open_new("b.bin") as out:
                    out.write(b"fictional")
                    out.commit()
        self.assertEqual(caught.exception.code, "no-replace-unavailable")
        self.assertEqual(refusing.call_args.args[-1], 4 if sys.platform == "darwin" else 1)
        self.assertEqual(self.names(), [])

    def test_commit_syncs_file_and_folder_before_and_after_the_rename(self):
        real, calls = fs._sync, []

        def sync(*descriptors):
            calls.append((descriptors, sorted(os.listdir(self.base / "selected"))))
            return real(*descriptors)
        with mock.patch.object(fs, "_sync", side_effect=sync):
            with self.root.open_new("d.bin") as out:
                handle, parent = out._fd, out._parent
                out.write(b"durable")
                self.assertIs(out.commit()["durable"], True)
            self.root.mkdir("folder")
        self.assertEqual([descriptors for descriptors, _names in calls[:2]], [(handle, parent)] * 2)
        self.assertNotIn("d.bin", calls[0][1])  # the first sync is before the final name exists
        self.assertIn("d.bin", calls[1][1])  # the second one is after it
        self.assertEqual(calls[2][0], (self.root._fd,))  # mkdir syncs the folder that holds the new folder
        self.assertEqual(len(calls), 3)

    def test_commit_rechecks_privacy(self):
        with self.assertRaises(fs.ScopedFSError) as caught:
            with self.root.open_new("p.bin") as out:
                out.write(b"fictional")
                os.fchmod(out._fd, 0o644)  # widened between open_new and commit
                out.commit()
        self.assertEqual(caught.exception.code, "new-private-file-security-unresolved")
        self.assertEqual(self.names(), [])

    def test_move_checks_the_renamed_name_and_says_the_file_moved(self):
        (self.base / "selected" / "a.txt").write_bytes(b"fictional")
        (self.base / "selected" / "dst").mkdir()
        record = self.root.inspect("a.txt", hash_file=True)
        real = fs._call_rename

        def rename_then_swap(*arguments):
            real(*arguments)  # the move happens, then another file takes the new name
            (self.base / "other.txt").write_bytes(b"fictional")
            os.rename(self.base / "other.txt", self.base / "selected" / "dst" / "a.txt")
        with mock.patch.object(fs, "_call_rename", side_effect=rename_then_swap):
            with self.assertRaises(fs.ScopedFSError) as caught:
                self.root.move_to("a.txt", destination=self.root, destination_relative="dst/a.txt", expected=record)
        self.assertEqual(caught.exception.code, "post-move-verification-unresolved")

    def test_admission_holds_where_no_replace_rename_fails(self):
        # macOS msdos and exFAT may refuse RENAME_EXCL: a destination proves the rename before anything is written.
        (self.base / "usb").mkdir()
        refusing = mock.Mock(return_value=-1)
        with mock.patch.object(fs, "_rename_function", return_value=refusing), \
                mock.patch.object(fs.ctypes, "get_errno", return_value=errno.ENOTSUP):
            with self.assertRaises(fs.CapabilityHold) as caught:
                fs.admit_destination(str(self.base / "usb"), non_private_destination=True,
                                     volumes=lambda fd: {"filesystem": "exfat", "removable": True})
        self.assertEqual(caught.exception.code, "no-replace-unavailable")
        self.assertEqual(os.listdir(self.base / "usb"), [])
        refusing.assert_called_once()

    def test_admission_probe_is_removed_after_a_failure(self):
        (self.base / "usb").mkdir()
        with mock.patch.object(fs.PosixRoot, "remove_file", side_effect=fs.ScopedFSError("delete-refused", "fictional")):
            with self.assertRaises(fs.ScopedFSError) as caught:
                fs.admit_destination(str(self.base / "usb"), non_private_destination=True,
                                     volumes=lambda fd: {"filesystem": "exfat", "removable": True})
        self.assertEqual(caught.exception.code, "delete-refused")
        self.assertEqual(os.listdir(self.base / "usb"), [])  # the committed probe file did not stay

    def test_cloud_placeholder_root_is_refused_at_admission(self):
        (self.base / "cloud").mkdir()
        real = os.stat

        def lookup(path, *args, **kwargs):
            info = real(path, *args, **kwargs)
            return altered(info, st_flags=0x40000000) if path == "cloud" else info
        with mock.patch.object(fs, "_posix_capable", return_value=True), mock.patch.object(fs.os, "stat", lookup), \
                self.assertRaises(fs.ScopedFSError) as caught:
            fs.PosixRoot(str(self.base / "cloud"))
        self.assertEqual(caught.exception.code, "offline-encrypted-or-recall-file")

    def test_new_folder_in_a_setgid_folder_is_private(self):
        (self.base / "selected" / "shared").mkdir()
        os.chmod(self.base / "selected" / "shared", 0o2700)  # Linux gives new folders the set-group-ID bit too
        record = self.root.mkdir("shared/private")
        self.assertEqual(stat.S_IMODE(record["mode"]) & 0o777, 0o700)

    def test_free_bytes_come_from_fstatvfs_on_the_root(self):
        with mock.patch.object(fs.os, "fstatvfs", return_value=types.SimpleNamespace(f_bavail=3, f_frsize=4096)) as query:
            self.assertEqual(self.root.free_bytes(), 3 * 4096)
        query.assert_called_once_with(self.root._fd)


class Stopped(Exception):
    """Stands for a process stopped between the rename into the removal folder and the delete."""


@unittest.skipUnless(os.name == "posix", "only on posix: the removal-folder rule renames and unlinks through descriptors")
class PosixRemovalTests(unittest.TestCase):
    """remove_original() and reconcile_removal(): selected/ holds the originals, removals/r1/ stands for the private
    work/removals/<id>/ folder on the same file system."""

    def setUp(self):
        self.base = ROOT / "work" / "test-fixtures" / "filesystem" / ("removal-" + uuid.uuid4().hex)
        self.folder = self.base / "removals" / "r1"
        (self.base / "selected").mkdir(parents=True)
        self.folder.mkdir(parents=True, mode=0o700)
        self.addCleanup(shutil.rmtree, self.base)
        self.root = fs.PosixRoot(str(self.base / "selected"))
        self.addCleanup(self.root.close)
        self.removal = fs.PosixRoot(str(self.folder))
        self.addCleanup(self.removal.close)

    def original(self, name, data):
        (self.base / "selected" / name).write_bytes(data)
        return self.root.inspect(name, hash_file=True)

    def remove(self, name, record, **options):
        return fs.remove_original(self.root, name, expected=record, removal=self.removal, **options)

    def removed(self, name, record, **options):
        """remove_original() where it must succeed: a refusal fails the test instead of erroring it."""
        try:
            return self.remove(name, record, **options)
        except fs.ScopedFSError as error:
            self.fail(f"unexpected refusal: {error}")

    def test_removal_renames_into_private_folder_on_same_device(self):
        record, name, seen = self.original("report.txt", b"fictional report"), fs.new_removal_name(), []
        real = self.removal.remove_file

        def remove_there(relative, **options):
            seen.append((relative, sorted(os.listdir(self.base / "selected")), sorted(os.listdir(self.folder))))
            return real(relative, **options)
        with mock.patch.object(self.removal, "remove_file", side_effect=remove_there), \
                mock.patch.object(self.root, "remove_file", side_effect=AssertionError("deleted in place")):
            self.assertEqual(self.removed("report.txt", record, removal_name=name), record)
        self.assertEqual(seen, [(name, [], [name])])
        self.assertEqual(os.listdir(self.folder), [])
        # A changed original is refused where it is; it is never moved.
        changed = self.original("changed.txt", b"fictional before")
        (self.base / "selected" / "changed.txt").write_bytes(b"fictional AFTER!")
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.remove("changed.txt", changed, removal_name=fs.new_removal_name())
        self.assertIn(caught.exception.code, {"stale-identity", "stale-content"})
        # A read-only original is moved only when the approved plan shows it as read-only.
        os.chmod(self.base / "selected" / "changed.txt", 0o400)
        read_only = self.root.inspect("changed.txt", hash_file=True)
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.remove("changed.txt", read_only, removal_name=fs.new_removal_name())
        self.assertEqual(caught.exception.code, "read-only")
        self.assertEqual((sorted(os.listdir(self.base / "selected")), os.listdir(self.folder)), (["changed.txt"], []))
        self.removed("changed.txt", read_only, removal_name=fs.new_removal_name(), allow_read_only=True)
        self.assertEqual((os.listdir(self.base / "selected"), os.listdir(self.folder)), ([], []))
        # Moved originals have their own names, never the temporary-file names reconciliation of open_new may remove.
        for bad in (None, "notes.txt", fs.scoped_base.new_partial_name(), ".removal-" + "A" * 32):
            with self.subTest(removal_name=bad):
                with self.assertRaises(fs.ScopedFSError) as caught:
                    self.remove("missing.txt", record, removal_name=bad)
                self.assertEqual(caught.exception.code, "invalid-option")
        # The removal folder must be private: owned by this user, mode 0700 (and no ACL on macOS).
        kept = self.original("kept.txt", b"fictional kept")
        for mode in (0o755, 0o777, 0o701):
            os.chmod(self.folder, mode)
            with self.subTest(mode=oct(mode)), fs.PosixRoot(str(self.folder)) as loose:
                with self.assertRaises(fs.ScopedFSError) as caught:
                    fs.remove_original(self.root, "kept.txt", expected=kept, removal=loose, removal_name=fs.new_removal_name())
                self.assertEqual(caught.exception.code, "removal-folder")
                with self.assertRaises(fs.ScopedFSError) as caught:
                    fs.reconcile_removal(loose, expected=kept, removal_name=fs.new_removal_name())
                self.assertEqual(caught.exception.code, "removal-folder")
        os.chmod(self.folder, 0o700)
        self.assertEqual((os.listdir(self.base / "selected"), os.listdir(self.folder)), (["kept.txt"], []))

    def test_removal_unlinks_through_verified_fd_on_other_device(self):
        record = self.original("report.txt", b"fictional report")
        self.removal._device = self.root._device + 1  # no runner is sure to have a second file system
        with mock.patch.object(fs, "_call_rename", side_effect=AssertionError("renamed across devices")):
            self.assertEqual(self.removed("report.txt", record, removal_name=fs.new_removal_name()), record)
            kept = self.original("kept.txt", b"fictional kept")
            with self.assertRaises(fs.ScopedFSError) as caught:
                self.remove("kept.txt", kept, sha256="0" * 64, removal_name=fs.new_removal_name())
        self.assertEqual(caught.exception.code, "stale-content")
        self.assertEqual((os.listdir(self.base / "selected"), os.listdir(self.folder)), (["kept.txt"], []))
        # A bind mount has the same device but refuses the rename with EXDEV: nothing moved, so the verified
        # original is deleted in place instead.
        self.removal._device = self.root._device
        refusing = mock.Mock(return_value=-1)
        with mock.patch.object(fs, "_rename_function", return_value=refusing), \
                mock.patch.object(fs.ctypes, "get_errno", return_value=errno.EXDEV):
            self.assertEqual(self.removed("kept.txt", kept, removal_name=fs.new_removal_name()), kept)
        refusing.assert_called_once()
        self.assertEqual((os.listdir(self.base / "selected"), os.listdir(self.folder)), ([], []))

    def test_interrupted_removal_is_reconciled(self):
        record, name = self.original("report.txt", b"fictional report"), fs.new_removal_name()
        draft, other = self.original("draft.txt", b"fictional draft"), fs.new_removal_name()
        with mock.patch.object(self.removal, "remove_file", side_effect=Stopped):
            for original, removal_name, entry in (("report.txt", name, record), ("draft.txt", other, draft)):
                with self.assertRaises(Stopped):
                    self.remove(original, entry, removal_name=removal_name)
        self.assertEqual((os.listdir(self.base / "selected"), sorted(os.listdir(self.folder))), ([], sorted([name, other])))
        # An entry in the removal folder that is not the original is reported and kept, never deleted: one with
        # the same bytes but another modification time, then one with changed bytes and the old time.
        moved = self.folder / other
        info = moved.stat()
        os.utime(moved, ns=(info.st_atime_ns, info.st_mtime_ns + 10 ** 9))
        self.assertEqual(fs.reconcile_removal(self.removal, expected=draft, removal_name=other), "kept")
        moved.write_bytes(b"fictional DRAFT")
        os.utime(moved, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assertEqual(fs.reconcile_removal(self.removal, expected=draft, removal_name=other), "kept")
        self.assertTrue(moved.exists())
        # The interrupted original is finished, also when its device number changed with a restart (D-072);
        # afterwards nothing has its name.
        renumbered = {**record, "device": record["device"] + 1}
        self.assertEqual(fs.reconcile_removal(self.removal, expected=renumbered, removal_name=name), "removed")
        self.assertEqual(os.listdir(self.folder), [other])
        self.assertEqual(fs.reconcile_removal(self.removal, expected=record, removal_name=name), "absent")
        # A refusal after the rename has its own code: the original is in the removal folder, not where it was.
        late, last = self.original("late.txt", b"fictional late"), fs.new_removal_name()
        real = self.removal.remove_file

        def changed_after_the_move(relative, **options):
            (self.folder / last).write_bytes(b"fictional LATE")  # an app still writing through an open descriptor
            return real(relative, **options)
        with mock.patch.object(self.removal, "remove_file", side_effect=changed_after_the_move):
            with self.assertRaises(fs.ScopedFSError) as caught:
                self.remove("late.txt", late, removal_name=last)
        self.assertEqual(caught.exception.code, "removal-incomplete")
        self.assertEqual((os.listdir(self.base / "selected"), sorted(os.listdir(self.folder))), ([], sorted([other, last])))
        self.assertEqual(fs.reconcile_removal(self.removal, expected=late, removal_name=last), "kept")
        # Also when the failure comes from the move itself, after its rename: the moved file is touched, or the
        # selected folder is renamed so the re-check of its ancestry fails.
        real_rename = fs._call_rename

        def rename_then(action):
            def call(*arguments):
                real_rename(*arguments)
                action()
            return call

        def touch(moved_name):
            info = (self.folder / moved_name).stat()
            os.utime(self.folder / moved_name, ns=(info.st_atime_ns, info.st_mtime_ns + 10 ** 9))
        for original, action in (("touched.txt", touch),
                                 ("drifted.txt", lambda _name: os.rename(self.base / "selected", self.base / "moved"))):
            entry, moved_name = self.original(original, b"fictional " + original.encode()), fs.new_removal_name()
            with self.subTest(original=original), \
                    mock.patch.object(fs, "_call_rename", side_effect=rename_then(lambda: action(moved_name))):
                with self.assertRaises(fs.ScopedFSError) as caught:
                    self.remove(original, entry, removal_name=moved_name)
                self.assertEqual(caught.exception.code, "removal-incomplete")
                self.assertTrue((self.folder / moved_name).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
