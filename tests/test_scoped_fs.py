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
            for code in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EXDEV):
                with self.subTest(code=code), mock.patch.object(fs.ctypes, "get_errno", return_value=code):
                    with self.assertRaises(fs.CapabilityHold):
                        fs._call_rename(native, 11, "source.txt", 22, "target.txt")
            # EEXIST can occur after a checked-absent destination. Native
            # RENAME_EXCL must refuse it instead of replacing that new name.
            for code in (errno.EEXIST, errno.EACCES, errno.EIO):
                with self.subTest(code=code), mock.patch.object(fs.ctypes, "get_errno", return_value=code):
                    with self.assertRaises(fs.ScopedFSError) as caught:
                        fs._call_rename(native, 11, "source.txt", 22, "target.txt")
                    self.assertEqual(caught.exception.code, "rename-refused")
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


@unittest.skipUnless(fs._posix_capable(), "only on posix: native POSIX no-follow/dir-fd support is required")
class PosixTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / "work" / "test-fixtures" / "filesystem" / ("fixture-" + uuid.uuid4().hex)
        self.base.mkdir(parents=True)
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
        with mock.patch.object(self.fs, "_read", side_effect=AssertionError("content opened")):
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
                with (self.source / "a.txt").open("r+b") as out:
                    out.write(b"X")
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
        if fs._rename_function() is None:
            self.skipTest("only on posix: native atomic no-overwrite rename unavailable")
        original = self.hashed()
        with fs.ScopedRoot(self.target, quiet_workspace=True) as target:
            try:
                moved = self.fs.move_to("a.txt", destination=target, destination_relative="saved.txt", expected=original)
            except fs.CapabilityHold:
                self.assertTrue((self.source / "a.txt").exists())
                self.assertFalse((self.target / "saved.txt").exists())
                self.skipTest("only on posix: the owned filesystem refuses native atomic no-overwrite rename; source preserved")
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
            target._device = self.fs._device + 1
            with mock.patch.object(fs, "_rename_function") as rename:
                with self.assertRaises(fs.ScopedFSError) as caught:
                    self.fs.move_to("a.txt", destination=target, destination_relative="saved.txt", expected=self.hashed())
                self.assertEqual(caught.exception.code, "cross-filesystem")
                rename.assert_not_called()

    def test_symlink_leaf_parent_and_admission_refuse(self):
        try:
            (self.source / "alias").symlink_to(self.target, target_is_directory=True)
            (self.base / "root-alias").symlink_to(self.source, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"only on posix: owned filesystem symlink creation unavailable: {exc.errno}")
        excluded = []
        self.assertEqual([row["relative_path"] for row in self.fs.list_directory(excluded=excluded)], ["a.txt"])
        self.assertEqual(excluded, [{"parent": "", "name": "alias", "reason": "link"}])
        # Without ``excluded`` (a folder PatchCairn owns) the unknown entry refuses the listing.
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.fs.list_directory()
        self.assertEqual(caught.exception.code, "link")
        for relative in ("alias", "alias/escape.txt"):
            with self.subTest(relative=relative), self.assertRaises(fs.ScopedFSError):
                self.fs.inspect(relative)
        with self.assertRaises(fs.ScopedFSError):
            fs.ScopedRoot(self.base / "root-alias", quiet_workspace=True)

    def test_hardlinks_refused_before_content_open(self):
        try:
            os.link(self.source / "a.txt", self.source / "second.txt")
        except OSError as exc:
            self.skipTest(f"only on posix: owned filesystem hardlink creation unavailable: {exc.errno}")
        excluded = []
        with mock.patch.object(fs.os, "open", side_effect=AssertionError("file opened")):
            self.assertEqual(self.fs.list_directory(excluded=excluded), [])
        self.assertEqual(excluded, [{"parent": "", "name": name, "reason": "hard-link"} for name in ("a.txt", "second.txt")])
        with self.assertRaises(fs.ScopedFSError) as caught:
            self.fs.inspect("second.txt", hash_file=True)
        self.assertEqual(caught.exception.code, "file-type")

    def test_special_file_refused_without_blocking(self):
        try:
            os.mkfifo(self.source / "fictional-pipe")
        except (OSError, AttributeError) as exc:
            self.skipTest(f"only on posix: owned filesystem FIFO unavailable: {getattr(exc, 'errno', None)}")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
