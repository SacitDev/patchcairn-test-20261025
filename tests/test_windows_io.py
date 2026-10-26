"""Windows in-process file I/O (decision D-008): WindowsRoot over win32_files on real NTFS folders.

Run from the repository root: python -I -S -B -m unittest discover -s tests -p "test_windows_io.py" -v
Every fixture lives in its own folder under work/test-fixtures/ and is removed afterwards. Faked
conditions (other volumes, cloud placeholders, failing native calls) replace one win32_files function
for the duration of one call; nothing outside the fixture folders is read or changed.
"""
from __future__ import annotations

import ast
import ctypes
import gc
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import textwrap
import threading
import time
import tracemalloc
import types
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import scoped_base  # noqa: E402
from scoped_base import CHUNK_BYTES, CapabilityHold, ScopedFSError  # noqa: E402

if os.name == "nt":
    import win32_files  # noqa: E402
    import windows_scoped  # noqa: E402

FIXTURES = ROOT / "work" / "test-fixtures"
WINDOWS_ONLY = "only on windows: the Windows file backend runs on Win32 handles"
GIB = 1 << 30


def pattern(size):
    return (bytes(range(256)) * (size // 256 + 1))[:size]


def without_durable(record):
    return {key: value for key, value in record.items() if key != "durable"}


def remove_fixture(path):
    """Remove a fixture folder, including read-only files and names only the extended path form reaches."""
    def writable_then_retry(function, name, _error):
        os.chmod(name, stat.S_IWRITE)
        function(name)
    shutil.rmtree("\\\\?\\" + str(path), onexc=writable_then_retry)


def volumes(filesystem, drive_type):
    """A fake volume-information source: the real folder appears to be on another kind of drive."""
    return lambda handle, drive: {"filesystem": filesystem, "drive_type": drive_type}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.case = FIXTURES / ("io-" + uuid.uuid4().hex)
        (self.case / "root").mkdir(parents=True)
        (self.case / "outside").mkdir()
        self.addCleanup(remove_fixture, self.case)

    def path(self, relative=""):
        return self.case / "root" / relative if relative else self.case / "root"

    def open_root(self, **options):
        root = windows_scoped.WindowsRoot(str(self.path()), **options)
        self.addCleanup(root.close)
        return root

    def seed(self, root, relative, data):
        return without_durable(root.create_file(relative, data=data))

    def allowed(self, call, *args, **kwargs):
        """The result of a call that must succeed; a refusal makes the test fail rather than error."""
        try:
            return call(*args, **kwargs)
        except ScopedFSError as error:
            self.fail(f"unexpected refusal: {error}")

    def code(self, call, *args, **kwargs):
        """The refusal code of a call that must be refused with a scoped_base error."""
        try:
            call(*args, **kwargs)
        except ScopedFSError as error:
            return error.code
        self.fail("the call was not refused")

    def junction(self, link, target):
        import _winapi
        _winapi.CreateJunction(str(target), str(link))

    def patched(self, name, replacement):
        return mock.patch.object(win32_files, name, replacement)


@unittest.skipUnless(os.name == "nt", WINDOWS_ONLY)
class WindowsIoTests(Fixture):
    # G06 tests ----------------------------------------------------------------------------------------

    def test_chunked_read_bounded_memory(self):
        root = self.open_root()
        data = pattern(24 * CHUNK_BYTES + 7)
        record = self.seed(root, "big.bin", data)
        sizes = []
        tracemalloc.start()
        try:
            root.stream_to("big.bin", expected=record, writer=lambda chunk: sizes.append(len(chunk)))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(sum(sizes), len(data))
        self.assertTrue(all(0 < size <= CHUNK_BYTES for size in sizes))
        self.assertLess(peak, 4 * CHUNK_BYTES, "a 24 MiB stream must never hold more than a few chunks")

    def test_end_to_end_sha256_matches_source(self):
        root = self.open_root()
        data = pattern(3 * CHUNK_BYTES + 12345)
        source = self.path("source.bin")
        source.write_bytes(data)
        record = root.inspect("source.bin", hash_file=True)
        self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
        digest = hashlib.sha256()
        self.assertEqual(root.stream_to("source.bin", expected=record, writer=digest.update), record)
        self.assertEqual(digest.hexdigest(), hashlib.sha256(source.read_bytes()).hexdigest())

    def test_writer_blocked_while_streaming(self):
        root = self.open_root()
        record = self.seed(root, "pinned.bin", b"pinned bytes")
        with root.open_read("pinned.bin", expected=record) as reader:
            for mode in ("r+b", "ab"):
                with self.subTest(mode=mode), self.assertRaises(PermissionError):
                    open(self.path("pinned.bin"), mode).close()
            self.assertEqual(reader.read(), b"pinned bytes")
        with open(self.path("pinned.bin"), "ab"):
            pass  # released when the stream ends

    def test_delete_blocked_while_streaming(self):
        root = self.open_root()
        record = self.seed(root, "pinned.bin", b"pinned bytes")
        with root.open_read("pinned.bin", expected=record):
            with self.assertRaises(PermissionError):
                os.remove(self.path("pinned.bin"))
            with self.assertRaises(PermissionError):
                os.rename(self.path("pinned.bin"), self.path("renamed.bin"))
        self.assertTrue(self.path("pinned.bin").exists())

    def test_ancestor_rename_blocked_while_streaming(self):
        self.path("folder/inner").mkdir(parents=True)
        root = self.open_root()
        record = self.seed(root, "folder/inner/pinned.bin", b"pinned bytes")
        with root.open_read("folder/inner/pinned.bin", expected=record):
            for folder in ("folder/inner", "folder"):
                with self.subTest(folder=folder), self.assertRaises(PermissionError):
                    os.rename(self.path(folder), self.path(folder + "-moved"))
        # The selected root and its own ancestors stay pinned for the root's lifetime.
        with self.assertRaises(PermissionError):
            os.rename(self.path(), self.case / "root-moved")
        root.close()
        os.rename(self.path(), self.case / "root-moved")
        os.rename(self.case / "root-moved", self.path())

    def test_reparse_point_and_junction_refused(self):
        self.path("sub").mkdir()
        (self.case / "outside" / "secret.txt").write_bytes(b"outside the selection")
        self.junction(self.path("escape"), self.case / "outside")
        self.junction(self.path("sub/nested"), self.case / "outside")
        self.junction(self.case / "via", self.path())
        root = self.open_root()
        for call in (lambda: root.inspect("escape"), lambda: root.inspect("escape/secret.txt"),
                     lambda: root.inspect("sub/nested/secret.txt"), lambda: root.list_directory("escape"),
                     lambda: root.mkdir("escape/new"),
                     lambda: root.create_file("sub/nested/new.txt", data=b"x")):
            with self.subTest(call=call):
                self.assertEqual(self.code(call), "reparse-point")
        fake = {"relative_path": "escape", "kind": "file", "device": 1, "inode": 1, "mode": 0o100666, "size": 21,
                "mtime_ns": 1, "ctime_ns": 1, "nlink": 1, "sha256": "0" * 64, "attributes": 0x20}
        self.assertEqual(self.code(lambda: root.open_read("escape", expected=fake).__enter__()), "reparse-point")
        left_out = []
        self.assertEqual([row["relative_path"] for row in root.list_directory("", excluded=left_out)], ["sub"])
        self.assertEqual(left_out, [{"parent": "", "name": "escape", "reason": "link"}])
        self.assertNotIn("escape", [row["relative_path"] for row in root.snapshot()])
        self.assertEqual(self.code(windows_scoped.WindowsRoot, str(self.case / "via")), "reparse-point")
        self.assertEqual(self.code(windows_scoped.WindowsRoot, str(self.case / "via" / "sub")), "reparse-point")
        self.assertTrue((self.case / "outside" / "secret.txt").exists())

    def test_hard_link_refused(self):
        root = self.open_root()
        record = self.seed(root, "twice.bin", b"two names")
        os.link(self.path("twice.bin"), self.case / "outside" / "second-name.bin")
        self.assertEqual(self.code(root.inspect, "twice.bin"), "hard-link")
        self.assertEqual(self.code(lambda: root.open_read("twice.bin", expected=record).__enter__()), "hard-link")
        self.assertEqual(self.code(root.remove_file, "twice.bin", expected=record), "hard-link")
        left_out = []
        self.assertEqual(root.list_directory("", excluded=left_out), [])
        self.assertEqual(left_out, [{"parent": "", "name": "twice.bin", "reason": "hard-link"}])
        self.assertTrue(self.path("twice.bin").exists())

    def test_identity_change_refused(self):
        root = self.open_root()
        record = self.seed(root, "doc.txt", b"version one")
        os.remove(self.path("doc.txt"))
        self.path("doc.txt").write_bytes(b"version one")  # replaced: same name, size and bytes, new file
        self.assertEqual(self.code(root.stream_to, "doc.txt", expected=record, writer=len), "stale-identity")
        self.assertEqual(self.code(root.remove_file, "doc.txt", expected=record), "stale-identity")
        same = root.inspect("doc.txt", hash_file=True)
        info = os.stat(self.path("doc.txt"))
        with open(self.path("doc.txt"), "r+b") as stream:
            stream.write(b"VERSION ONE")  # same size, then the same timestamp again
        os.utime(self.path("doc.txt"), ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assertEqual(root.inspect("doc.txt"), {**same, "sha256": None})
        self.assertEqual(self.code(root.stream_to, "doc.txt", expected=same, writer=len), "stale-content")
        self.assertEqual(self.code(root.remove_file, "doc.txt", expected=same), "stale-content")
        self.assertTrue(self.path("doc.txt").exists())

    def test_final_path_mismatch_refused(self):
        root = self.open_root()
        record = self.seed(root, "a.txt", b"alpha")
        real = win32_files.final_path
        for answer, code in ((lambda path: path[:-5] + "b.txt", "canonical-path-mismatch"),
                             (lambda path: "\\\\?\\UNC\\fictional-server\\share\\a.txt", "unexpected-canonical-path")):
            def final_path(handle, answer=answer):
                path = real(handle)
                return answer(path) if path.endswith("\\a.txt") else path
            with self.subTest(code=code), self.patched("final_path", final_path):
                self.assertEqual(self.code(root.inspect, "a.txt"), code)
                self.assertEqual(self.code(root.stream_to, "a.txt", expected=record, writer=len), code)
        self.assertEqual(root.stream_to("a.txt", expected=record, writer=len), record)
        # A character above U+FFFF is two UTF-16 units; none of them may hide a difference at the end of a name.
        self.assertFalse(win32_files.same_name("x\U0001f600", "x\U0001f601"))
        self.assertFalse(win32_files.same_name("C:\\r\\\U0001f600x", "C:\\r\\\U0001f600y"))
        self.assertTrue(win32_files.same_name("A\U0001f600", "a\U0001f600"))
        emoji = self.path("\U0001f600" * 6)
        emoji.mkdir()
        (emoji / "secrets.json").write_bytes(b"{}")
        with windows_scoped.WindowsRoot(str(emoji)) as inner:
            inner.inspect("secrets.json")
            with self.patched("final_path", lambda handle: real(handle)[:-1] + "x" if real(handle).endswith(".json") else real(handle)):
                self.assertEqual(self.code(inner.inspect, "secrets.json"), "canonical-path-mismatch")
            real_find = win32_files.find_entry
            with self.patched("find_entry", lambda path: ("secrets.jsoo", real_find(path)[1]) if path.endswith(".json") else real_find(path)):
                self.assertEqual(self.code(inner.inspect, "secrets.json"), "canonical-path-mismatch")  # stored name differs
            alias = self.short_name(emoji / "secrets.json")
            if alias != "secrets.json":  # the volume makes 8.3 names: the alias is refused before it is opened
                self.assertEqual(self.code(inner.inspect, alias), "canonical-path-mismatch")
            inner.mkdir("\U0001f600")
            moved = without_durable(inner.create_file("\U0001f600/a.txt", data=b"a"))
            self.assertEqual(inner.move_to("\U0001f600/a.txt", destination=inner, destination_relative="\U0001f600/a.txu",
                                           expected=moved)["relative_path"], "\U0001f600/a.txu")

    def short_name(self, path):
        function = ctypes.WinDLL("kernel32", use_last_error=True).GetShortPathNameW
        function.argtypes, function.restype = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32], ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(1024)
        self.assertTrue(function(str(path), buffer, len(buffer)))
        return buffer.value.rpartition("\\")[2]

    def test_no_transport_files_written(self):
        before = sorted(str(path) for path in (ROOT / "work").rglob("*") if FIXTURES not in path.parents and path != FIXTURES)
        root = self.open_root()
        record = self.seed(root, "a.txt", b"alpha")
        root.stream_to("a.txt", expected=record, writer=len)
        root.mkdir("folder")
        root.move_to("a.txt", destination=root, destination_relative="folder/a.txt", expected=record)
        root.close()
        after = sorted(str(path) for path in (ROOT / "work").rglob("*") if FIXTURES not in path.parents and path != FIXTURES)
        self.assertEqual(after, before)
        self.assertFalse((ROOT / "work" / "windows-scoped").exists())
        self.assertEqual(sorted(os.listdir(self.path())), ["folder"])
        self.assertEqual(os.listdir(self.path("folder")), ["a.txt"])
        tree = ast.parse((SCRIPTS / "windows_scoped.py").read_text(encoding="utf-8"))
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imported, {"__future__", "contextlib", "ctypes", "io", "ntpath", "os", "pathlib", "queue", "re",
                                    "sys", "threading", "pc_paths", "pc_records", "scoped_base", "win32_files"})

    def test_handles_released_after_operations(self):
        # In a fresh interpreter: handles that earlier tests in this process left for Windows to close in its own time
        # (an ALPC port, an event, a thread) would otherwise move the process-wide count.
        driver = textwrap.dedent("""
            import ctypes, gc, json, sys, threading, time
            sys.path.insert(0, sys.argv[1])
            import windows_scoped
            from scoped_base import ScopedFSError

            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetCurrentProcess.restype = ctypes.c_void_p
            kernel.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]

            def handle_count():
                count = ctypes.c_uint32()
                if not kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(count)):
                    raise ctypes.WinError(ctypes.get_last_error())
                return count.value

            def io_threads():
                return [thread for thread in threading.enumerate() if thread.name.startswith("patchcairn-windows-io")]

            def seed(root, relative, data):
                return {key: value for key, value in root.create_file(relative, data=data).items() if key != "durable"}

            def refused(call, *args, **kwargs):
                try:
                    call(*args, **kwargs)
                except ScopedFSError:
                    return
                raise AssertionError("the call was not refused")

            warm = windows_scoped.WindowsRoot(sys.argv[2])
            seed(warm, "warm.bin", b"warm")  # first use binds and caches what later calls reuse
            warm.close()
            deadline = time.monotonic() + 10  # a quiet point: no file I/O thread left, garbage collected
            for thread in io_threads():
                thread.join(max(0.0, deadline - time.monotonic()))
            if io_threads():
                sys.exit(f"{len(io_threads())} file I/O thread(s) still alive 10 seconds after the warm-up root closed "
                         f"(idents {[thread.ident for thread in io_threads()]})")
            # The counts must not include roots this driver still holds: before Python 3.13, each lock in a closed root on
            # Windows (its thread's event, its queue, its last job's event) holds a kernel semaphore.
            del warm
            gc.collect()
            before = handle_count()
            gc.disable()  # a handle that only the garbage collector would release stays counted
            operations = 0
            for round_number in range(20):
                with windows_scoped.WindowsRoot(sys.argv[2]) as root:
                    operations += 1
                    for index in range(5):
                        size = 2000 + index
                        record = seed(root, f"r{round_number}-{index}.bin", (bytes(range(256)) * (size // 256 + 1))[:size])
                        root.stream_to(record["relative_path"], expected=record, writer=len)
                        refused(root.inspect, "absent.bin")
                        refused(root.stream_to, record["relative_path"], expected={**record, "inode": 1}, writer=len)
                        refused(lambda: root.open_new(record["relative_path"]).__enter__())
                        root.remove_file(record["relative_path"], expected=root.inspect(record["relative_path"], hash_file=True))
                        root.list_directory()
                        operations += 8
                    refused(windows_scoped.WindowsRoot, sys.argv[3])
                    operations += 1
            del root  # the last closed root, still named by the loop
            alive = io_threads()  # no wait: close() has already joined each root's thread
            after = handle_count()  # no wait and no collection
            print(json.dumps({"operations": operations, "before": before, "after": after, "io_threads": len(alive),
                              "idents": [thread.ident for thread in alive]}))
        """)
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", driver, str(SCRIPTS), str(self.path()),
                                 str(self.path("absent"))], capture_output=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        measured = json.loads(result.stdout)
        self.assertGreaterEqual(measured["operations"], 500)
        threads = f"{measured['io_threads']} file I/O thread(s) alive after the last root closed (idents {measured['idents']})"
        self.assertEqual(measured["after"], measured["before"],
                         f"handle count changed by {measured['after'] - measured['before']:+d}; {threads}")
        self.assertEqual(measured["io_threads"], 0, threads)

    def test_refused_call_leaves_no_reference_cycle(self):
        # A refusal raised on the root's I/O thread must not stay tied to that thread's job or to the frame that
        # re-raises it: the job, the root and its I/O thread would then wait for the garbage collector, and on
        # Python 3.12 for Windows each lock in them holds a kernel semaphore until then. Only this module's objects
        # are counted, so garbage from anything else in the process cannot fail the test.
        root = self.open_root()
        record = self.seed(root, "a.bin", b"a")
        calls = {"inspect": lambda: root.inspect("absent.bin"), "open_new": lambda: root.open_new("a.bin").__enter__(),
                 "stream_to": lambda: root.stream_to("a.bin", expected={**record, "inode": 1}, writer=len),
                 "root": lambda: windows_scoped.WindowsRoot(str(self.path("absent")))}
        owned = (ScopedFSError, windows_scoped._Job, windows_scoped._IoThread, windows_scoped.WindowsRoot)

        def ours(item):
            frame = item.tb_frame if isinstance(item, types.TracebackType) else item
            if isinstance(frame, types.FrameType):
                return frame.f_code.co_filename.endswith("windows_scoped.py") and frame.f_code.co_qualname
            return isinstance(item, owned) and type(item).__name__

        enabled, debug = gc.isenabled(), gc.get_debug()
        for name, call in calls.items():
            gc.collect()
            gc.disable()
            gc.set_debug(gc.DEBUG_SAVEALL)
            saved = list(gc.garbage)
            gc.garbage.clear()
            try:
                try:
                    call()
                except ScopedFSError:
                    refused = True
                else:
                    refused = False
                root.list_directory()  # the next call replaces the thread's last job, as in normal use
                gc.collect()  # outside the except block, where the exception is no longer being handled
                kept = sorted(label for label in map(ours, gc.garbage) if label)
            finally:
                gc.garbage[:] = saved
                gc.set_debug(debug)
                if enabled:
                    gc.enable()
            self.assertTrue(refused, f"the {name} call was not refused")
            self.assertEqual(kept, [], f"the refused {name} call left objects for the garbage collector")

    def test_private_dacl_before_first_byte(self):
        root = self.open_root()
        writes = []
        real_write = win32_files.write

        def write(handle, data):
            writes.append(len(data))
            return real_write(handle, data)

        refuse = mock.Mock(side_effect=win32_files.PrivacyRefusal("private-dacl-unprotected"))
        with self.patched("validate_private", refuse), self.patched("write", write):
            self.assertEqual(self.code(lambda: root.open_new("secret.bin").__enter__()), "new-private-file-security-unresolved")
        self.assertEqual(writes, [])
        self.assertEqual(os.listdir(self.path()), [])
        self.assertEqual(refuse.call_args.kwargs, {"directory": False, "exact": True})
        with root.open_new("secret.bin") as out:
            temp = next(self.path().iterdir())
            self.assertRegex(temp.name, scoped_base.PARTIAL_NAME)
            self.assertEqual(temp.stat().st_size, 0)
            handle = win32_files.open_file(str(temp), win32_files.READ_CONTROL, 7, win32_files.OPEN_EXISTING, 0)
            with handle:
                owner, control, aces = win32_files.security_snapshot(handle)
            self.assertEqual(owner, win32_files.token_user())
            self.assertTrue(control & 0x1000)
            self.assertEqual(sorted(sid for _kind, _flags, _mask, sid in aces), sorted(win32_files.private_principals()))
            out.write(b"private bytes")
            out.commit()

    def test_no_replace_rename(self):
        root = self.open_root()
        kept = self.seed(root, "keep.txt", b"original")
        self.assertEqual(self.code(lambda: root.open_new("KEEP.TXT").__enter__()), "destination-exists")
        with self.assertRaises(ScopedFSError) as caught:
            with root.open_new("late.txt") as out:
                out.write(b"mine")
                self.path("late.txt").write_bytes(b"theirs")
                out.commit()
        self.assertEqual(caught.exception.code, "destination-exists")
        self.assertEqual(self.path("late.txt").read_bytes(), b"theirs")
        self.seed(root, "taken.txt", b"taken")
        self.assertEqual(self.code(root.move_to, "keep.txt", destination=root, destination_relative="taken.txt",
                                   expected=root.inspect("keep.txt", hash_file=True)), "destination-exists")
        self.assertEqual(root.read_bytes("keep.txt", expected=kept, max_bytes=100), b"original")
        self.assertEqual(self.path("taken.txt").read_bytes(), b"taken")
        self.assertEqual(sorted(os.listdir(self.path())), ["keep.txt", "late.txt", "taken.txt"])

    def test_refusal_codes_match_retired_helper(self):
        # Every refusal code of the retired C# helper (scripts/Windows.Scoped.cs, listed from the file before it
        # was deleted) is reached, with the code the in-process backend gives for the same condition (RETIRED_CODES).
        # Exempt (decision D-022): attribute 0x40000 read from handle metadata, which means "has extended attributes".
        root = self.open_root()
        self.path("folder").mkdir()
        record = self.seed(root, "a.txt", b"alpha")
        hashed = root.inspect("a.txt", hash_file=True)
        outcome = {}

        def reach(old, call, *args, **kwargs):
            outcome.setdefault(old, set()).add(self.code(call, *args, **kwargs))

        def failing(name, error=OSError(5, "fictional failure", None, 5)):
            return self.patched(name, mock.Mock(side_effect=error))

        def run_after(trigger, name, answer, call, old):
            """Reach ``old`` with win32_files.<name> replaced by ``answer`` once win32_files.<trigger> has run."""
            real_trigger, real, seen = getattr(win32_files, trigger), getattr(win32_files, name), []

            def triggered(*args):
                seen.append(True)
                return real_trigger(*args)
            with self.patched(trigger, triggered), self.patched(name, lambda *args: answer(*args) if seen else real(*args)):
                reach(old, call)

        def other(**options):
            return windows_scoped.WindowsRoot(str(self.path()), **options)

        # Paths and roots.
        reach("local-absolute-root-required", windows_scoped.WindowsRoot, "relative\\path")
        reach("noncanonical-root", windows_scoped.WindowsRoot, str(self.path("folder")) + "\\..\\folder")
        reach("invalid-path-component", root.inspect, "a.txt:stream")
        reach("reserved-path-component", root.inspect, "con.txt")
        reach("invalid-relative-path", root.inspect, "a\\b")
        reach("invalid-relative-path", root.inspect, "n" * 201)  # the C# Relative() refused over 200 characters
        long_root = self.case / ("r" * (240 - len(str(self.case)) - 1))
        long_root.mkdir()
        with windows_scoped.WindowsRoot(str(long_root)) as far_root:
            reach("path-length-bound", far_root.inspect, "x.txt")  # the C# PathOf() bound on the absolute path
        reach("invalid-entry-bound", other, max_entries=0)
        reach("missing-entry", root.inspect, "absent.txt")
        reach("access-sharing-or-missing", root.inspect, "absent-folder/x.txt")  # Windows error 2 on a folder
        # Volumes and the native layer.
        reach("fixed-local-volume-required", other, volumes=volumes("NTFS", win32_files.DRIVE_REMOVABLE))
        reach("ntfs-required", other, volumes=volumes("FAT32", win32_files.DRIVE_FIXED))
        reach("filesystem-capability-unavailable", other, volumes=mock.Mock(side_effect=OSError(1, "x", None, 1)))
        with mock.patch.object(win32_files, "API", None):
            reach("native-api-unavailable", other)
        with failing("final_path"):
            reach("canonical-path-unavailable", root.inspect, "a.txt")
        real_final = win32_files.final_path
        with self.patched("final_path", lambda handle: real_final(handle).replace("a.txt", "b.txt")):
            reach("canonical-path-mismatch", root.inspect, "a.txt")
        with self.patched("final_path", lambda handle: "\\\\?\\UNC\\fictional-server\\share\\a.txt"):
            reach("unexpected-canonical-path", root.inspect, "a.txt")
        with failing("file_information"):
            reach("metadata-unavailable", root.inspect, "a.txt")
        with self.patched("file_type", lambda handle: 2):
            reach("non-disk-file", root.inspect, "a.txt")
        real_info = win32_files.file_information
        for bit in (win32_files.ATTRIBUTE_OFFLINE, win32_files.ATTRIBUTE_ENCRYPTED,
                    win32_files.ATTRIBUTE_RECALL_ON_DATA_ACCESS):
            def offline(handle, bit=bit):
                info = real_info(handle)
                info.attributes |= bit
                return info
            with self.patched("file_information", offline):
                reach("offline-encrypted-or-recall-file", root.inspect, "a.txt")
        real_find = win32_files.find_entry
        with self.patched("find_entry", lambda path: (real_find(path)[0], 0x20 | win32_files.ATTRIBUTE_RECALL_ON_OPEN)):
            reach("offline-encrypted-or-recall-file", root.inspect, "a.txt")
        # Types, links and sharing.
        reach("unexpected-type", lambda: root.open_read("folder", expected={**record, "relative_path": "folder"}).__enter__())
        self.path("ro.txt").write_bytes(b"read-only")
        os.chmod(self.path("ro.txt"), stat.S_IREAD)
        reach("readonly-or-system-file", root.move_to, "ro.txt", destination=root, destination_relative="moved.txt",
              expected=root.inspect("ro.txt", hash_file=True))
        reach("readonly-or-system-file", root.remove_file, "ro.txt", expected=root.inspect("ro.txt", hash_file=True))
        self.seed(root, "system.txt", b"system")
        ctypes.WinDLL("kernel32").SetFileAttributesW(str(self.path("system.txt")), 0x4)
        reach("readonly-or-system-file", root.remove_file, "system.txt", expected=root.inspect("system.txt", hash_file=True))
        self.seed(root, "twice.txt", b"twice")
        os.link(self.path("twice.txt"), self.case / "outside" / "twice.txt")
        reach("hardlink", root.inspect, "twice.txt")
        self.junction(self.path("escape"), self.case / "outside")
        reach("reparse-point", root.inspect, "escape/twice.txt")
        with open(self.path("a.txt"), "ab"):
            reach("access-sharing-or-missing", root.inspect, "a.txt", hash_file=True)
        self.denied_file("denied.txt")
        reach("access-sharing-or-missing", root.inspect, "denied.txt", hash_file=True)
        # Sizes and caps.
        reach("file-byte-bound", root.read_bytes, "a.txt", expected=hashed, max_bytes=2)
        reach("memory-read-bound", root.read_bytes, "a.txt", expected=hashed,
              max_bytes=scoped_base.MAX_CONTROL_BYTES + 1)
        reach("invalid-byte-bound", root.read_bytes, "a.txt", expected=hashed, max_bytes=0)
        with mock.patch.object(scoped_base, "MAX_CONTROL_BYTES", 3):
            reach("create-byte-bound", root.create_file, "big.txt", data=b"four")
        with mock.patch.object(root, "max_entries", 2):
            reach("entry-bound", root.list_directory)
        # Reads.
        with failing("read"):
            reach("read-failed", root.stream_to, "a.txt", expected=hashed, writer=len)
        with failing("seek"), root.open_read("a.txt", expected=hashed) as reader:
            reach("seek-failed", reader.seek, 2)
        real_read = win32_files.read
        grown = []

        def grow(handle, address, count):
            done = real_read(handle, address, count)
            if done or grown:
                return done
            grown.append(True)
            ctypes.memmove(address, b"more", min(4, count))
            return min(4, count)
        with self.patched("read", grow):
            reach("file-grew", root.stream_to, "a.txt", expected=hashed, writer=len)
        with self.patched("read", lambda handle, address, count: 0):
            reach("short-read", root.stream_to, "a.txt", expected=hashed, writer=len)

        def touch():
            info = os.stat(self.path("a.txt"))
            os.utime(self.path("a.txt"), ns=(info.st_atime_ns, info.st_mtime_ns + 10 ** 9))
        reach("changed-during-read", root.stream_to, "a.txt", expected=hashed, writer=lambda chunk: touch())
        reach("stale-identity-or-content", root.stream_to, "a.txt", expected=hashed, writer=len)
        hashed = root.inspect("a.txt", hash_file=True)
        reach("stale-identity-or-content", root.remove_file, "a.txt", expected=hashed, sha256="0" * 64)
        # Listing.
        real_entries, calls = win32_files.directory_entries, []

        def entries(handle, limit):
            calls.append(True)
            if len(calls) == 2:
                self.path("late.txt").write_bytes(b"late")
            return real_entries(handle, limit)
        with self.patched("directory_entries", entries):
            reach("directory-membership-changed", root.list_directory, "", excluded=[])
        # Creating.
        with self.patched("token_user", mock.Mock(side_effect=OSError(1, "x", None, 1))):
            reach("new-private-creator-unavailable", lambda: root.open_new("n.txt").__enter__())
        with failing("private_security"):
            reach("new-private-descriptor-unavailable", lambda: root.open_new("n.txt").__enter__())
        with failing("validate_private", win32_files.PrivacyRefusal("private-dacl-unprotected")):
            reach("new-private-file-security-unresolved", lambda: root.open_new("n.txt").__enter__())
        real_open = win32_files.open_file

        def no_create(path, access, share, disposition, flags, security=None):
            if disposition == win32_files.CREATE_NEW:
                raise OSError(5, "fictional failure", None, 5)
            return real_open(path, access, share, disposition, flags, security)
        with self.patched("open_file", no_create):
            reach("create-new-refused", lambda: root.open_new("n.txt").__enter__())
        with failing("create_directory"):
            reach("create-directory-refused", root.mkdir, "new-folder")
        with self.patched("write", lambda handle, data: 0), root.open_new("n.txt") as out:
            reach("partial-create-unresolved", out.write, b"bytes")
        failed_sync = []

        def flush(handle):
            failed_sync.append(True)
            raise OSError(5, "fictional failure", None, 1117)
        with self.patched("flush", flush), root.open_new("synced.txt") as out:
            out.write(b"bytes")
            self.assertIs(out.commit()["durable"], False)  # create-flush-unresolved is reported, not refused (RR2-6)
        self.assertTrue(failed_sync)
        outcome["create-flush-unresolved"] = {"durable-false"}
        # Moving and removing.
        reach("same-path", root.move_to, "synced.txt", destination=root, destination_relative="SYNCED.TXT",
              expected=root.inspect("synced.txt", hash_file=True))
        with other() as far:
            far._device += 1  # the same folder posing as another volume
            reach("same-volume-required", root.move_to, "synced.txt", destination=far, destination_relative="x.txt",
                  expected=root.inspect("synced.txt", hash_file=True))
        self.seed(root, "occupied.txt", b"occupied")
        reach("rename-refused-no-overwrite", root.move_to, "synced.txt", destination=root,
              destination_relative="occupied.txt", expected=root.inspect("synced.txt", hash_file=True))
        with failing("rename_noreplace"):
            reach("rename-refused-no-overwrite", root.move_to, "synced.txt", destination=root,
                  destination_relative="free.txt", expected=root.inspect("synced.txt", hash_file=True))
        moving = root.inspect("synced.txt", hash_file=True)
        run_after("rename_noreplace", "final_path", lambda handle: "\\\\?\\C:\\elsewhere.txt",
                  lambda: root.move_to("synced.txt", destination=root, destination_relative="folder/moved.txt",
                                       expected=moving), "post-move-verification-unresolved")
        with failing("set_disposition"):
            reach("delete-refused", root.remove_file, "occupied.txt", expected=root.inspect("occupied.txt", hash_file=True))
        doomed = root.inspect("occupied.txt", hash_file=True)
        run_after("set_disposition", "find_entry", lambda path: ("occupied.txt", 0x20),
                  lambda: root.remove_file("occupied.txt", expected=doomed), "post-purge-verification-unresolved")
        # The selected root itself.
        with other() as first:
            reviewed = first.inspect("")
        moved_root = self.case / "replaced"
        root.close()
        os.rename(self.path(), moved_root)
        self.path().mkdir()
        reach("selected-root-changed", other, expected_root=reviewed)
        os.rmdir(self.path())
        os.rename(moved_root, self.path())
        # The deliberate exemption: 0x40000 in handle metadata means "has extended attributes" and is admitted.
        def with_ea(handle):
            info = real_info(handle)
            info.attributes |= win32_files.ATTRIBUTE_RECALL_ON_OPEN
            return info
        with other() as again, self.patched("file_information", with_ea):
            self.assertTrue(again.inspect("folder")["attributes"] & win32_files.ATTRIBUTE_RECALL_ON_OPEN)
            self.assertEqual(again.inspect("ro.txt", hash_file=True)["kind"], "file")
        self.assertEqual(set(outcome), set(RETIRED_CODES))
        for old, codes in outcome.items():
            with self.subTest(old=old):
                self.assertEqual(codes, set(RETIRED_CODES[old]))

    def denied_file(self, name):
        """A file whose protected DACL lets its owner read its attributes and delete it, but not read it."""
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        descriptor, size = ctypes.c_void_p(), ctypes.c_uint32()
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
        # DELETE | READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES, and no FILE_READ_DATA.
        sddl = f"D:P(A;;0x130080;;;{win32_files.token_user()})"
        self.assertTrue(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor),
                                                                                    ctypes.byref(size)))
        try:
            attributes = win32_files.SECURITY_ATTRIBUTES(ctypes.sizeof(win32_files.SECURITY_ATTRIBUTES), descriptor, False)
            win32_files.open_file(str(self.path(name)), win32_files.FILE_READ_ATTRIBUTES, 0, win32_files.CREATE_NEW,
                                  win32_files.FILE_ATTRIBUTE_NORMAL, attributes).close()
        finally:
            ctypes.WinDLL("kernel32").LocalFree(descriptor)

    def test_blocked_io_times_out_as_unresolved(self):
        import msvcrt
        root = self.open_root()
        record = self.seed(root, "a.txt", b"alpha")
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, write_end)
        self.addCleanup(os.close, read_end)
        pipe = types.SimpleNamespace(value=msvcrt.get_osfhandle(read_end))
        real_read = win32_files.read
        # A synchronous read of an empty pipe blocks until CancelSynchronousIo cancels it.
        with mock.patch.object(windows_scoped, "IO_SECONDS", 0.5), \
             self.patched("read", lambda handle, address, count: real_read(pipe, address, count)):
            started = time.monotonic()
            self.assertEqual(self.code(root.stream_to, "a.txt", expected=record, writer=len), "io-unresolved")
            self.assertLess(time.monotonic() - started, 0.5 + windows_scoped.CANCEL_SECONDS)
        self.assertTrue(windows_scoped.shutdown_worker(), "the cancelled call returned, so nothing is stuck")
        self.assertEqual(self.code(root.inspect, "a.txt"), "io-unresolved")  # the root takes no more work
        root.close()
        # A call that ignores cancellation keeps its handles until it returns, and is reported meanwhile.
        stuck_root = windows_scoped.WindowsRoot(str(self.path()))
        gate = threading.Event()

        def ignore_cancel(handle, address, count):
            gate.wait(30)
            return 0
        with mock.patch.object(windows_scoped, "IO_SECONDS", 0.3), mock.patch.object(windows_scoped, "CANCEL_SECONDS", 0.3), \
             self.patched("read", ignore_cancel):
            self.assertEqual(self.code(stuck_root.stream_to, "a.txt", expected=record, writer=len), "io-unresolved")
            self.assertFalse(windows_scoped.shutdown_worker())
            stuck_root.close()
            with self.assertRaises(PermissionError):
                os.rename(self.path(), self.case / "root-moved")  # still pinned while the call is stuck
            gate.set()
            stuck_root._io._thread.join(10)
        self.assertFalse(stuck_root._io._thread.is_alive())
        self.assertTrue(windows_scoped.shutdown_worker())
        os.rename(self.path(), self.case / "root-moved")  # released once the call returned
        os.rename(self.case / "root-moved", self.path())

    def test_impersonated_thread_is_refused(self):
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        root = self.open_root()
        record = self.seed(root, "a.txt", b"alpha")
        self.assertTrue(root._io.call(advapi.ImpersonateSelf, 2))  # SecurityImpersonation, on the I/O thread
        try:
            self.assertEqual(self.code(root.inspect, "a.txt"), "native-impersonation-unsupported")
            self.assertEqual(self.code(root.stream_to, "a.txt", expected=record, writer=len),
                             "native-impersonation-unsupported")
        finally:
            self.assertTrue(root._io.call(advapi.RevertToSelf, check_token=False))
        self.assertEqual(root.inspect("a.txt", hash_file=True), {**record})
        self.assertTrue(advapi.ImpersonateSelf(2))  # on the calling thread
        try:
            self.assertEqual(self.code(root.inspect, "a.txt"), "native-impersonation-unsupported")
        finally:
            self.assertTrue(advapi.RevertToSelf())
        self.assertEqual(root.inspect("a.txt")["kind"], "file")

    def test_recall_on_open_file_refused(self):
        root = self.open_root()
        record = self.seed(root, "cloud.txt", b"placeholder")
        self.seed(root, "local.txt", b"local")
        real_find, real_open, real_entries = win32_files.find_entry, win32_files.open_file, win32_files.directory_entries
        opened = []

        def find(path):
            found = real_find(path)
            if path.endswith("\\cloud.txt") and found:
                return found[0], found[1] | win32_files.ATTRIBUTE_RECALL_ON_OPEN
            return found

        def open_file(path, *args):
            opened.append(path)
            return real_open(path, *args)

        def entries(handle, limit):
            return [(name, attributes | (win32_files.ATTRIBUTE_RECALL_ON_OPEN if name == "cloud.txt" else 0), file_id)
                    for name, attributes, file_id in real_entries(handle, limit)]

        with self.patched("find_entry", find), self.patched("open_file", open_file), self.patched("directory_entries", entries):
            for call in (lambda: root.inspect("cloud.txt"), lambda: root.stream_to("cloud.txt", expected=record, writer=len),
                         lambda: root.remove_file("cloud.txt", expected=record)):
                with self.subTest(call=call):
                    self.assertEqual(self.code(call), "offline-encrypted-or-recall-file")
            left_out = []
            self.assertEqual([row["relative_path"] for row in root.list_directory("", excluded=left_out)], ["local.txt"])
            self.assertEqual(left_out, [{"parent": "", "name": "cloud.txt", "reason": "special"}])
        self.assertFalse([path for path in opened if path.endswith("\\cloud.txt")], "the placeholder was opened")
        self.assertTrue(self.path("cloud.txt").exists())

    def test_errors_are_scoped_base_classes(self):
        self.assertIs(windows_scoped.ScopedFSError, scoped_base.ScopedFSError)
        self.assertIs(windows_scoped.CapabilityHold, scoped_base.CapabilityHold)
        root = self.open_root()
        record = self.seed(root, "a.txt", b"alpha")
        self.junction(self.path("escape"), self.case / "outside")
        failure = OSError(1117, "fictional device failure", None, 1117)
        calls = [lambda: root.inspect("absent.txt"), lambda: root.inspect("escape"),
                 lambda: windows_scoped.WindowsRoot("relative"), lambda: root.remove_file("a.txt", expected={}),
                 lambda: windows_scoped.admit_destination(str(self.path()), volumes=volumes("exFAT", 3))]
        for name in ("open_file", "find_entry", "file_information", "read", "directory_entries", "free_bytes"):
            def broken(name=name):
                with self.patched(name, mock.Mock(side_effect=failure)):
                    root.stream_to("a.txt", expected=record, writer=len)
                    root.list_directory()
                    root.free_bytes()
            calls.append(broken)
        for call in calls:
            with self.subTest(call=call), self.assertRaises(scoped_base.ScopedFSError) as caught:
                call()
            self.assertIn(type(caught.exception), (ScopedFSError, CapabilityHold))

    # Design tests (knowledge/research/windows-backend-design.md) ----------------------------------------

    def test_names_streams_reserved_and_lengths_refused(self):
        root = self.open_root()
        self.seed(root, "a.txt", b"alpha")
        for name, code in (("a.txt:stream", "invalid-path-component"), ("a.txt::$DATA", "invalid-path-component"),
                           ("con", "reserved-path-component"), ("COM\u00b9.txt", "reserved-path-component"),
                           ("LPT\u00b3", "reserved-path-component"), ("trailing.", "invalid-path-component"),
                           ("n" * 201, "path-too-long"), ("/".join(["d"] * 65), "path-too-long")):
            with self.subTest(name=name[:20]):
                self.assertEqual(self.code(root.inspect, name), code)
                self.assertEqual(self.code(root.mkdir, name), code)
        long_root = self.case / ("x" * 120) / ("y" * 120)
        self.assertEqual(self.code(windows_scoped.WindowsRoot, str(long_root)), "local-absolute-root-required")
        # An 8.3 alias opens the same file under another name and is refused (a fake stored name covers volumes
        # without 8.3 names in test_final_path_mismatch_refused).
        record = self.seed(root, "a long document name.txt", b"long")
        short = self.short_name(self.path(record["relative_path"]))
        if short != record["relative_path"]:  # the volume creates 8.3 names
            self.assertEqual(self.code(root.inspect, short), "canonical-path-mismatch")
            self.assertEqual(self.code(root.remove_file, short, expected={**record, "relative_path": short}),
                             "canonical-path-mismatch")
        else:
            self.assertFalse(any("~" in name for name in os.listdir(self.path())))
        self.assertTrue(self.path(record["relative_path"]).exists())

    def test_existing_writer_blocks_open_read(self):
        root = self.open_root()
        record = self.seed(root, "busy.txt", b"busy")
        with open(self.path("busy.txt"), "ab"):
            self.assertEqual(self.code(lambda: root.open_read("busy.txt", expected=record).__enter__()), "sharing-violation")
            self.assertEqual(self.code(root.remove_file, "busy.txt", expected=record), "sharing-violation")
        self.assertEqual(root.read_bytes("busy.txt", expected=record, max_bytes=10), b"busy")

    def test_selected_root_cannot_be_replaced(self):
        root = self.open_root()
        reviewed = root.inspect("")
        with self.assertRaises(PermissionError):
            os.rename(self.path(), self.case / "replaced")
        root.close()
        os.rename(self.path(), self.case / "replaced")
        self.path().mkdir()
        self.assertEqual(self.code(windows_scoped.WindowsRoot, str(self.path()), expected_root=reviewed),
                         "selected-root-changed")
        with windows_scoped.WindowsRoot(str(self.case / "replaced"), expected_root=reviewed) as original:
            self.assertEqual(original.inspect("")["inode"], reviewed["inode"])

    def test_source_volume_and_attribute_refusals(self):
        for facts, code in ((volumes("exFAT", win32_files.DRIVE_FIXED), "ntfs-required"),
                            (volumes("FAT32", win32_files.DRIVE_FIXED), "ntfs-required"),
                            (volumes("NTFS", win32_files.DRIVE_REMOVABLE), "fixed-local-volume-required"),
                            (volumes("NTFS", win32_files.DRIVE_REMOTE), "fixed-local-volume-required")):
            with self.subTest(code=code):
                self.assertEqual(self.code(windows_scoped.WindowsRoot, str(self.path()), volumes=facts), code)
        root = self.open_root()
        self.seed(root, "a.txt", b"alpha")
        real_find = win32_files.find_entry
        for bit in (win32_files.ATTRIBUTE_OFFLINE, win32_files.ATTRIBUTE_ENCRYPTED, win32_files.ATTRIBUTE_RECALL_ON_OPEN,
                    win32_files.ATTRIBUTE_RECALL_ON_DATA_ACCESS):
            with self.subTest(bit=hex(bit)), self.patched("find_entry", lambda path, bit=bit: (real_find(path)[0], bit)):
                self.assertEqual(self.code(root.inspect, "a.txt"), "offline-encrypted-or-recall-file")

    def test_read_only_and_system_files_refused_for_changes(self):
        root = self.open_root()
        self.seed(root, "ro.txt", b"read-only")
        os.chmod(self.path("ro.txt"), stat.S_IREAD)
        ro = root.inspect("ro.txt", hash_file=True)
        self.assertEqual((ro["mode"], ro["attributes"] & 1), (0o100444, 1))
        self.assertEqual(self.code(root.remove_file, "ro.txt", expected=ro), "read-only")
        self.assertEqual(self.code(root.move_to, "ro.txt", destination=root, destination_relative="m.txt", expected=ro),
                         "readonly-or-system-file")
        dispositions = []
        real = win32_files.set_disposition

        def record_flags(handle, flags):
            dispositions.append(flags)
            return real(handle, flags)
        with self.patched("set_disposition", record_flags):
            root.remove_file("ro.txt", expected=ro, allow_read_only=True)
        self.assertEqual(dispositions, [0x13])
        self.seed(root, "sys.txt", b"system")
        ctypes.WinDLL("kernel32").SetFileAttributesW(str(self.path("sys.txt")), 0x4)
        system = root.inspect("sys.txt", hash_file=True)
        for allow in (False, True):
            with self.subTest(allow=allow):
                self.assertEqual(self.code(root.remove_file, "sys.txt", expected=system, allow_read_only=allow),
                                 "readonly-or-system-file")
        self.assertTrue(self.path("sys.txt").exists())

    def test_abort_and_full_disk_remove_the_temporary_file(self):
        root = self.open_root()
        with self.assertRaises(RuntimeError):
            with root.open_new("draft.bin") as out:
                out.write(b"partial")
                raise RuntimeError("writer failed")
        self.assertEqual(os.listdir(self.path()), [])
        full = mock.Mock(side_effect=OSError(28, "fictional full disk", None, win32_files.ERROR_DISK_FULL))
        with self.assertRaises(ScopedFSError) as caught:
            with root.open_new("archive.zip") as out:
                with self.patched("write", full):
                    out.write(pattern(1000))
        self.assertEqual(caught.exception.code, "disk-full")
        self.assertEqual(os.listdir(self.path()), [])

    def test_move_stays_on_one_volume(self):
        self.path("dest").mkdir()
        root = self.open_root()
        record = self.seed(root, "a.txt", b"alpha")
        with windows_scoped.WindowsRoot(str(self.path("dest"))) as destination:
            moved = root.move_to("a.txt", destination=destination, destination_relative="a.txt", expected=record)
            self.assertEqual((moved["relative_path"], moved["inode"], moved["sha256"]), ("a.txt", record["inode"], record["sha256"]))
            self.assertEqual(destination.inspect("a.txt", hash_file=True), moved)
            destination._device += 1  # the same folder posing as another volume
            self.assertEqual(self.code(destination.move_to, "a.txt", destination=root, destination_relative="b.txt",
                                       expected=moved), "same-volume-required")
        self.assertEqual(os.listdir(self.path("dest")), ["a.txt"])
        self.assertEqual(self.code(root.move_to, "a.txt", destination=object(), destination_relative="b.txt",
                                   expected=record), "destination-scope-required")

    def test_remove_uses_posix_disposition_then_checks_absence(self):
        root = self.open_root()
        record = self.seed(root, "old.bin", pattern(CHUNK_BYTES + 3))
        flags, real = [], win32_files.set_disposition

        def record_flags(handle, value):
            flags.append(value)
            return real(handle, value)
        # Another program's attribute-only handle must not leave the name behind (POSIX semantics).
        observer = win32_files.open_file(str(self.path("old.bin")), win32_files.FILE_READ_ATTRIBUTES, 7,
                                         win32_files.OPEN_EXISTING, 0)
        with observer, self.patched("set_disposition", record_flags):
            removed = root.remove_file("old.bin", expected=record)
            self.assertFalse(self.path("old.bin").exists())
        self.assertEqual(flags, [0x3])
        self.assertEqual(removed["sha256"], record["sha256"])
        self.assertEqual(self.code(root.remove_file, "old.bin", expected=record), "missing-entry")

    def test_struct_layouts(self):
        self.assertEqual(ctypes.sizeof(ctypes.c_void_p), 8)
        self.assertEqual(ctypes.sizeof(win32_files.BY_HANDLE_FILE_INFORMATION), 52)
        self.assertEqual((win32_files.FILE_RENAME_INFO.name.offset, ctypes.sizeof(win32_files.FILE_RENAME_INFO)), (20, 24))
        self.assertEqual(win32_files.FILE_ID_BOTH_DIR_INFO.name.offset, 104)
        self.assertEqual(win32_files.LAYOUT, win32_files.EXPECTED_LAYOUT)
        root = self.open_root()
        self.seed(root, "a.txt", b"alpha")
        self.path("dest").mkdir()
        sizes, real = [], win32_files.API.SetFileInformationByHandle

        def capture(handle, information, buffer, size):
            if information == 3:
                sizes.append((size, bytes(buffer)[:size]))
            return real(handle, information, buffer, size)
        with mock.patch.object(win32_files.API, "SetFileInformationByHandle", capture):
            root.move_to("a.txt", destination=root, destination_relative="dest/a.txt",
                         expected=root.inspect("a.txt", hash_file=True))
        target = ("\\\\?\\" + str(self.path("dest/a.txt"))).encode("utf-16-le")
        self.assertEqual(len(sizes), 1)
        size, buffer = sizes[0]
        self.assertEqual(size, 24 + len(target))
        self.assertEqual(buffer[:4], b"\0\0\0\0")  # ReplaceIfExists FALSE
        self.assertEqual(int.from_bytes(buffer[16:20], "little"), len(target))
        self.assertEqual(buffer[20:20 + len(target)], target)
        self.assertEqual(buffer[20 + len(target):22 + len(target)], b"\0\0")

    # Review round 1 ------------------------------------------------------------------------------------

    def test_commit_syncs_the_folder_after_the_rename(self):
        root = self.open_root()
        calls, real_flush, real_rename = [], win32_files.flush, win32_files.rename_noreplace

        def flush(handle):
            calls.append(("flush", handle))
            return real_flush(handle)

        def rename(handle, target):
            calls.append(("rename", handle))
            return real_rename(handle, target)
        with self.patched("flush", flush), self.patched("rename_noreplace", rename), root.open_new("a.bin") as out:
            out.write(b"bytes")
            self.assertIs(out.commit()["durable"], True)
        file, parent = out._handle, out._parent
        self.assertEqual(calls, [("flush", file), ("flush", parent), ("rename", file), ("flush", file), ("flush", parent)])
        # A failed sync after the rename leaves the file committed but not durable.
        calls.clear()

        def flush_before_rename_only(handle):
            if any(kind == "rename" for kind, _handle in calls):
                raise OSError(5, "fictional failure", None, 1117)
            return flush(handle)
        with self.patched("flush", flush_before_rename_only), self.patched("rename_noreplace", rename):
            with root.open_new("b.bin") as out:
                out.write(b"bytes")
                record = out.commit()
        self.assertIs(record["durable"], False)
        self.assertEqual(root.inspect("b.bin", hash_file=True), without_durable(record))

    def test_files_dated_before_1970_stream_and_remove(self):
        root = self.open_root()
        self.path("old.txt").write_bytes(b"from 1960")
        stamp = -315619200 * 10 ** 9  # 1960-01-01T00:00:00Z
        os.utime(self.path("old.txt"), ns=(stamp, stamp))
        record = root.inspect("old.txt", hash_file=True)
        self.assertEqual(record["mtime_ns"], stamp)
        self.assertEqual(self.allowed(root.stream_to, "old.txt", expected=record, writer=len), record)
        self.assertEqual(self.allowed(root.read_bytes, "old.txt", expected=record, max_bytes=100), b"from 1960")
        self.assertEqual(self.allowed(root.remove_file, "old.txt", expected=record)["sha256"], record["sha256"])
        self.assertFalse(self.path("old.txt").exists())

    def test_full_paths_stay_within_240_characters(self):
        long_root = self.case / ("r" * (240 - len(str(self.case)) - 1))
        long_root.mkdir()
        open("\\\\?\\" + str(long_root / "x.txt"), "xb").close()
        with windows_scoped.WindowsRoot(str(long_root)) as root:
            for call in (lambda: root.inspect("x.txt"), lambda: root.create_file("y.txt", data=b"y"),
                         lambda: root.mkdir("z")):
                with self.subTest(call=call):
                    self.assertEqual(self.code(call), "path-too-long")
            left_out = []
            self.assertEqual(root.list_directory("", excluded=left_out), [])
            self.assertEqual(left_out, [{"parent": "", "name": "x.txt", "reason": "path-too-long"}])
        exact = self.case / ("s" * (240 - len(str(self.case)) - 1 - len("\\a.txt")))
        exact.mkdir()
        (exact / "a.txt").write_bytes(b"a")
        self.assertEqual(len(str(exact / "a.txt")), 240)
        with windows_scoped.WindowsRoot(str(exact)) as root:
            self.assertEqual(root.inspect("a.txt", hash_file=True)["size"], 1)  # an existing file at exactly 240
            # The temporary name (41 characters) must fit too, so a crashed partial file stays reachable.
            self.assertEqual(self.code(root.admit_new, "b.txt", 1), "path-too-long")  # said before writing
            self.assertEqual(self.code(root.create_file, "b.txt", data=b"b"), "path-too-long")
        roomy = self.case / ("t" * (240 - len(str(self.case)) - 1 - len("\\" + scoped_base.new_partial_name())))
        roomy.mkdir()
        with windows_scoped.WindowsRoot(str(roomy)) as root:
            self.assertIsNone(root.admit_new("a.txt", 1))
            self.assertEqual(self.code(root.admit_new, "a/b.txt", 1), "path-too-long")
            record = without_durable(root.create_file("a.txt", data=b"a"))  # its temporary name ended at 240
            self.assertEqual(root.inspect("a.txt", hash_file=True), record)
        self.assertEqual(os.listdir(exact), ["a.txt"])
        self.assertEqual(os.listdir(long_root), ["x.txt"])

    def test_commit_reuses_a_name_freed_just_before(self):
        # NTFS tunneling gives a name freed less than 15 s earlier the old file's creation time.
        root = self.open_root()
        first = self.seed(root, "a.txt", b"first")
        root.remove_file("a.txt", expected=first)
        second = self.allowed(self.seed, root, "a.txt", b"second")
        self.assertEqual(root.read_bytes("a.txt", expected=second, max_bytes=10), b"second")
        os.remove(self.path("a.txt"))
        third = self.allowed(self.seed, root, "a.txt", b"third")
        self.assertEqual(root.inspect("a.txt", hash_file=True), third)

    def test_commit_flush_gets_time_for_the_bytes_written(self):
        root = self.open_root()
        real, slow = win32_files.flush, []

        def flush(handle):
            if not slow:
                slow.append(True)
                time.sleep(0.6)  # longer than the patched deadline, within the time allowed for 1 MiB
            return real(handle)
        with mock.patch.object(windows_scoped, "IO_SECONDS", 0.3), \
             mock.patch.object(windows_scoped, "FLUSH_BYTES_PER_SECOND", CHUNK_BYTES), self.patched("flush", flush):
            with root.open_new("big.bin") as out:
                out.write(pattern(CHUNK_BYTES))
                self.assertIs(self.allowed(out.commit)["durable"], True)
        self.assertTrue(slow)

    def test_files_open_without_backup_semantics(self):
        self.path("folder").mkdir()
        root = self.open_root()
        record = self.seed(root, "folder/a.txt", b"alpha")
        opened, real = [], win32_files.open_file

        def open_file(path, access, share, disposition, flags, security=None):
            opened.append((path.rpartition("\\")[2], bool(flags & win32_files.FILE_FLAG_BACKUP_SEMANTICS)))
            return real(path, access, share, disposition, flags, security)
        with self.patched("open_file", open_file):
            root.inspect("folder/a.txt", hash_file=True)
            root.stream_to("folder/a.txt", expected=record, writer=len)
            root.list_directory("folder")
        self.assertTrue(opened)
        self.assertEqual({backup for name, backup in opened if name == "a.txt"}, {False})
        self.assertEqual({backup for name, backup in opened if name == "folder"}, {True})
        # An index entry that says folder for what opens as a file is refused (it was opened with BACKUP_SEMANTICS).
        real_find = win32_files.find_entry
        with self.patched("find_entry", lambda path: (real_find(path)[0], real_find(path)[1] | win32_files.ATTRIBUTE_DIRECTORY)
                          if path.endswith("a.txt") else real_find(path)):
            self.assertEqual(self.code(root.inspect, "folder/a.txt", hash_file=True), "unexpected-type")

    def test_archive_bit_changes_keep_moved_files_restorable(self):
        # NTFS sets the archive bit when it renames a file, visible once the handle closes; records leave it out,
        # so a quarantined file can be moved back and purged with the record its move returned.
        self.path("q").mkdir()
        root = self.open_root()
        for name in ("a.txt", "b.txt"):
            self.path(name).write_bytes(b"quarantined " + name.encode())
            ctypes.WinDLL("kernel32").SetFileAttributesW(str(self.path(name)), 0x80)  # archive bit cleared
        record = root.inspect("a.txt", hash_file=True)
        moved = self.allowed(root.move_to, "a.txt", destination=root, destination_relative="q/1", expected=record)
        self.assertTrue(os.stat(self.path("q/1")).st_file_attributes & win32_files.ATTRIBUTE_ARCHIVE)
        self.assertEqual(root.inspect("q/1", hash_file=True), moved)
        self.assertEqual(self.allowed(root.move_to, "q/1", destination=root, destination_relative="a.txt",
                                      expected=moved)["relative_path"], "a.txt")
        copy = self.allowed(root.move_to, "b.txt", destination=root, destination_relative="q/2",
                            expected=root.inspect("b.txt", hash_file=True))
        self.allowed(root.remove_file, "q/2", expected=copy)
        self.assertEqual(sorted(os.listdir(self.path())), ["a.txt", "q"])

    def test_rename_refuses_a_target_folder_turned_into_a_link(self):
        self.path("folder").mkdir()
        root = self.open_root()
        real = win32_files.file_information
        with self.assertRaises(ScopedFSError) as caught:
            with root.open_new("folder/a.bin") as out:
                out.write(b"x")

                def info(handle, parent=out._parent):
                    data = real(handle)
                    if handle is parent:
                        data.attributes |= win32_files.ATTRIBUTE_REPARSE_POINT
                    return data
                with self.patched("file_information", info):
                    out.commit()
        self.assertEqual(caught.exception.code, "reparse-point")
        self.assertEqual(os.listdir(self.path("folder")), [])

    def test_listing_ties_each_child_to_its_enumerated_id(self):
        root = self.open_root()
        self.seed(root, "a.txt", b"alpha")
        real = win32_files.directory_entries
        with self.patched("directory_entries", lambda handle, limit: [(name, attributes, file_id + 1)
                                                                      for name, attributes, file_id in real(handle, limit)]):
            self.assertEqual(self.code(root.list_directory), "directory-membership-changed")

    def test_scoped_root_listing_modes(self):
        import scoped_fs
        self.path("deep").mkdir()
        open("\\\\?\\" + str(self.path("deep") / ("n" * 196)), "xb").close()  # 201 characters relative
        open("\\\\?\\" + str(self.path("nul")), "xb").close()  # a Windows device name
        self.junction(self.path("link"), self.case / "outside")
        self.path("keep.txt").write_bytes(b"kept")
        with scoped_fs.ScopedRoot(str(self.path()), quiet_workspace=True) as scope:
            self.assertEqual(self.code(scope.list_directory), "reparse-point")  # without excluded: refused
            self.assertEqual(self.code(scope.list_directory, "deep"), "path-too-long")
            left_out, deep_left = [], []
            self.assertEqual([row["relative_path"] for row in scope.list_directory("", excluded=left_out)], ["deep", "keep.txt"])
            self.assertEqual(scope.list_directory("deep", excluded=deep_left), [])
        self.assertEqual(left_out, [{"parent": "", "name": "link", "reason": "link"},
                                    {"parent": "", "name": "nul", "reason": "not-portable"}])
        self.assertEqual(deep_left, [{"parent": "deep", "name": "n" * 196, "reason": "path-too-long"}])

    def test_handle_has_one_owner(self):
        self.path("a.txt").write_bytes(b"alpha")
        handle = win32_files.open_file(str(self.path("a.txt")), win32_files.GENERIC_READ, 1, win32_files.OPEN_EXISTING, 0)
        with handle:
            descriptor = handle.to_fd(os.O_RDONLY | os.O_BINARY)
            with self.assertRaises(ValueError):
                handle.to_fd(os.O_RDONLY)  # ownership moves to a descriptor only once
            self.assertEqual(os.read(descriptor, 5), b"alpha")
        self.assertTrue(handle.closed)
        with self.assertRaises(OSError):
            os.fstat(descriptor)  # the Handle closed the descriptor, and with it the Win32 handle
        handle.close()  # a second close does nothing
        with self.assertRaises(ValueError):
            handle.value

    def test_listing_sorts_by_utf16_code_units(self):
        root = self.open_root()
        for name in ("\uff21.txt", "\U0001f600.txt", "b.txt"):
            self.seed(root, name, b"x")
        # U+1F600 is stored as the surrogates D83D DE00, which sort before U+FF21 the way Windows compares names.
        self.assertEqual([row["relative_path"] for row in root.list_directory()], ["b.txt", "\U0001f600.txt", "\uff21.txt"])

    def test_crlf_bytes_round_trip(self):
        root = self.open_root()
        data = b"line one\r\nline two\nline three\r\x1a\r\n"
        record = self.seed(root, "text.txt", data)
        self.assertEqual(self.path("text.txt").read_bytes(), data)
        self.assertEqual(root.read_bytes("text.txt", expected=record, max_bytes=100), data)
        with root.open_read("text.txt", expected=record) as reader:
            self.assertEqual(reader.read(), data)
            self.assertEqual(reader.seek(10), 10)
            self.assertEqual(reader.read(3), b"lin")

    def test_killed_writer_leaves_only_the_temporary_file(self):
        driver = textwrap.dedent("""
            import sys, time
            sys.path.insert(0, sys.argv[1])
            import windows_scoped
            root = windows_scoped.WindowsRoot(sys.argv[2])
            with root.open_new("backup.zip") as out:
                out.write(b"partial archive bytes" * 1000)
                print("written", flush=True)
                time.sleep(120)
        """)
        process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", driver, str(SCRIPTS), str(self.path())],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(process.stdout.readline().strip(), b"written")
        finally:
            process.kill()
            process.communicate(timeout=60)
        names = os.listdir(self.path())
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], scoped_base.PARTIAL_NAME)
        self.assertNotIn("backup.zip", names)

    def test_one_gib_stream_stays_within_memory_bounds(self):
        size = GIB
        source = self.path("large.bin")
        digest, block = hashlib.sha256(), pattern(CHUNK_BYTES)
        with open(source, "wb") as stream:
            for _ in range(size // CHUNK_BYTES):
                stream.write(block)
                digest.update(block)
        driver = textwrap.dedent("""
            import ctypes, hashlib, json, sys, tracemalloc
            sys.path.insert(0, sys.argv[1])
            import windows_scoped

            class Counters(ctypes.Structure):
                _fields_ = [("cb", ctypes.c_uint32), ("faults", ctypes.c_uint32)] + [
                    (name, ctypes.c_size_t) for name in ("peak_working_set", "working_set", "peak_paged", "paged",
                                                         "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile")]

            root = windows_scoped.WindowsRoot(sys.argv[2])
            expected = {**root.inspect("large.bin"), "sha256": sys.argv[3]}
            digest = hashlib.sha256()
            tracemalloc.start()
            root.stream_to("large.bin", expected=expected, writer=digest.update)
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            root.close()
            kernel = ctypes.WinDLL("kernel32")
            kernel.GetCurrentProcess.restype = ctypes.c_void_p
            kernel.K32GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_uint32]
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            assert kernel.K32GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
            print(json.dumps({"sha256": digest.hexdigest(), "tracemalloc_peak": peak,
                              "peak_working_set": counters.peak_working_set}))
        """)
        try:
            result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", driver, str(SCRIPTS), str(self.path()),
                                     digest.hexdigest()], capture_output=True, timeout=600, check=True)
        finally:
            source.unlink()
        measured = json.loads(result.stdout)
        self.assertEqual(measured["sha256"], digest.hexdigest())
        self.assertLess(measured["tracemalloc_peak"], 8 * CHUNK_BYTES, measured)
        self.assertLess(measured["peak_working_set"], 128 * CHUNK_BYTES, measured)

    def test_process_elevation_is_reported(self):
        elevated = windows_scoped.process_is_elevated()
        self.assertIs(type(elevated), bool)
        self.assertEqual(elevated, bool(ctypes.WinDLL("shell32").IsUserAnAdmin()))

    def test_free_bytes_matches_the_volume(self):
        root = self.open_root()
        free = root.free_bytes()
        self.assertIs(type(free), int)
        self.assertLess(abs(free - shutil.disk_usage(self.path()).free), 256 * CHUNK_BYTES)

    def test_capabilities_and_scoped_fs_facade(self):
        import scoped_fs
        capabilities = windows_scoped.capabilities()
        self.assertTrue(capabilities["available"])
        self.assertEqual(capabilities["stream_max_bytes"], scoped_base.MAX_STREAM_BYTES)
        self.assertNotRegex(capabilities["adapter"], r"[._-]v[0-9]+$")
        self.assertEqual(scoped_fs.capabilities(), capabilities)
        with scoped_fs.ScopedRoot(str(self.path()), quiet_workspace=True) as scope:
            self.assertIsInstance(scope, windows_scoped.ScopedRoot)
            created = scope.create_file("legacy.bin", data=b"legacy", max_bytes=1024)
            self.assertNotIn("durable", created)
            record = scope.inspect("legacy.bin", hash_file=True, max_bytes=1024)
            self.assertEqual(record, created)
            self.assertEqual(scope.read_bytes("legacy.bin", expected=record, max_bytes=1024), b"legacy")
            self.assertEqual(self.code(scope.inspect, "legacy.bin", hash_file=True, max_bytes=2), "file-byte-cap")
            os.link(self.path("legacy.bin"), self.case / "outside" / "second.bin")
            self.assertEqual(self.code(scope.list_directory), "hard-link")
        with self.assertRaises(CapabilityHold):
            windows_scoped.ScopedRoot(str(self.path()), quiet_workspace=False)


# Every refusal code of the retired C# helper and the code(s) the in-process backend gives for the same condition.
# path-length-bound is the C# bound of 240 characters on the absolute path, ported as path-too-long. Three codes
# changed on purpose: a relative path over 200 characters, which the C# refused as invalid-relative-path, is
# path-too-long (pc_paths); removing a read-only file gives read-only (allowed with allow_read_only, D-022); a missing
# folder gives missing-entry. create-flush-unresolved became durable False (RR2-6).
RETIRED_CODES = {
    "access-sharing-or-missing": ("sharing-violation", "access-sharing-or-missing", "missing-entry"),
    "canonical-path-mismatch": ("canonical-path-mismatch",),
    "canonical-path-unavailable": ("canonical-path-unavailable",),
    "changed-during-read": ("read-drift",),
    "create-byte-bound": ("file-byte-cap",),
    "create-directory-refused": ("create-directory-refused",),
    "create-flush-unresolved": ("durable-false",),
    "create-new-refused": ("create-new-refused",),
    "delete-refused": ("delete-refused",),
    "directory-membership-changed": ("directory-membership-changed",),
    "entry-bound": ("entry-cap",),
    "file-byte-bound": ("file-byte-cap",),
    "file-grew": ("read-growth",),
    "filesystem-capability-unavailable": ("filesystem-capability-unavailable",),
    "fixed-local-volume-required": ("fixed-local-volume-required",),
    "hardlink": ("hard-link",),
    "invalid-byte-bound": ("invalid-cap",),
    "invalid-entry-bound": ("invalid-cap",),
    "invalid-path-component": ("invalid-path-component",),
    "invalid-relative-path": ("invalid-relative-path", "path-too-long"),
    "local-absolute-root-required": ("local-absolute-root-required",),
    "memory-read-bound": ("invalid-cap",),
    "metadata-unavailable": ("metadata-unavailable",),
    "missing-entry": ("missing-entry",),
    "native-api-unavailable": ("native-api-unavailable",),
    "new-private-creator-unavailable": ("new-private-creator-unavailable",),
    "new-private-descriptor-unavailable": ("new-private-descriptor-unavailable",),
    "new-private-file-security-unresolved": ("new-private-file-security-unresolved",),
    "non-disk-file": ("non-disk-file",),
    "noncanonical-root": ("noncanonical-root",),
    "ntfs-required": ("ntfs-required",),
    "offline-encrypted-or-recall-file": ("offline-encrypted-or-recall-file",),
    "partial-create-unresolved": ("short-write",),
    "path-length-bound": ("path-too-long",),
    "post-move-verification-unresolved": ("post-move-verification-unresolved",),
    "post-purge-verification-unresolved": ("post-purge-verification-unresolved",),
    "read-failed": ("read-failed",),
    "readonly-or-system-file": ("readonly-or-system-file", "read-only"),
    "rename-refused-no-overwrite": ("destination-exists", "rename-refused-no-overwrite"),
    "reparse-point": ("reparse-point",),
    "reserved-path-component": ("reserved-path-component",),
    "same-path": ("same-path",),
    "same-volume-required": ("same-volume-required",),
    "seek-failed": ("seek-failed",),
    "selected-root-changed": ("selected-root-changed",),
    "short-read": ("read-drift",),
    "stale-identity-or-content": ("stale-identity", "stale-content"),
    "unexpected-canonical-path": ("unexpected-canonical-path",),
    "unexpected-type": ("unexpected-type",),
}


@unittest.skipUnless(os.name == "nt", WINDOWS_ONLY)
class WindowsDestinationTests(Fixture):
    """Backup destinations on other drives (plan RR2-4), with a fake volume-information source."""

    def admit(self, filesystem, drive_type, **options):
        root = windows_scoped.admit_destination(str(self.path()), volumes=volumes(filesystem, drive_type), **options)
        self.addCleanup(root.close)
        return root

    def test_removable_or_fat_destination_needs_non_private_acknowledgment(self):
        for filesystem, drive_type in (("exFAT", win32_files.DRIVE_FIXED), ("FAT32", win32_files.DRIVE_FIXED),
                                       ("NTFS", win32_files.DRIVE_REMOVABLE), ("exFAT", win32_files.DRIVE_REMOVABLE)):
            with self.subTest(filesystem=filesystem, drive_type=drive_type):
                with self.assertRaises(CapabilityHold) as caught:
                    self.admit(filesystem, drive_type)
                self.assertEqual(caught.exception.code, "non-private-destination-acknowledgment-required")
                root = self.admit(filesystem, drive_type, non_private_destination=True)
                self.assertIs(root.private, False)
                self.assertEqual(root.privacy_note, scoped_base.NON_PRIVATE_NOTE)
                root.close()
        private = self.admit("NTFS", win32_files.DRIVE_FIXED)
        self.assertIs(private.private, True)
        self.assertIsNone(private.privacy_note)
        private.close()
        for filesystem, drive_type in (("NTFS", win32_files.DRIVE_REMOTE), ("ReFS", win32_files.DRIVE_FIXED),
                                       ("UDF", win32_files.DRIVE_CDROM)):
            with self.subTest(refused=filesystem):
                self.assertEqual(self.code(self.admit, filesystem, drive_type, non_private_destination=True),
                                 "destination-volume-unsupported")
        self.assertEqual(self.code(self.admit, "exFAT", 2, non_private_destination=1), "invalid-option")
        root = self.admit("exFAT", win32_files.DRIVE_REMOVABLE, non_private_destination=True)
        root.mkdir("backup")
        record = without_durable(root.create_file("backup/README.txt", data=b"readme"))
        self.assertEqual(root.inspect("backup/README.txt", hash_file=True), record)

    def test_fat32_refuses_archive_over_4gib_before_writing(self):
        root = self.admit("FAT32", win32_files.DRIVE_REMOVABLE, non_private_destination=True)
        self.assertEqual(root.max_file_bytes, 4 * GIB - 1)
        root.admit_new("backup.zip", 4 * GIB - 1)
        self.assertEqual(self.code(root.admit_new, "backup.zip", 4 * GIB), "file-too-large-for-volume")
        self.assertEqual(self.code(root.admit_new, "backup.zip", -1), "invalid-cap")
        writes = []
        real = win32_files.write
        with self.assertRaises(ScopedFSError) as caught, \
             self.patched("write", lambda handle, data: writes.append(len(data)) or real(handle, data)):
            with root.open_new("backup.zip") as out:
                out.write(b"header")
                out.seek(4 * GIB - 4)
                out.write(b"tail")  # would end at 4 GiB: refused before anything is written there
        self.assertEqual(caught.exception.code, "file-too-large-for-volume")
        self.assertEqual(writes, [6])
        self.assertEqual(os.listdir(self.path()), [])
        ntfs = self.admit("NTFS", win32_files.DRIVE_FIXED)
        ntfs.admit_new("backup.zip", 4 * GIB)

    def test_destination_bound_by_size_and_sha256_without_stable_ids(self):
        root = self.admit("exFAT", win32_files.DRIVE_REMOVABLE, non_private_destination=True)
        self.assertEqual(root.identity_keys, frozenset({"relative_path", "kind", "size"}))
        record = without_durable(root.create_file("backup.zip", data=b"archive bytes"))
        relisted = {**record, "inode": record["inode"] + 1, "mtime_ns": record["mtime_ns"] + 2_000_000_000}
        self.assertEqual(root.stream_to("backup.zip", expected=relisted, writer=len), relisted)
        with open(self.path("backup.zip"), "r+b") as stream:
            stream.write(b"ARCHIVE")
        self.assertEqual(self.code(root.stream_to, "backup.zip", expected=relisted, writer=len), "stale-content")
        self.assertEqual(self.code(root.stream_to, "backup.zip", expected={**relisted, "size": 12}, writer=len),
                         "stale-identity")
        self.assertEqual(self.admit("NTFS", win32_files.DRIVE_FIXED).identity_keys, scoped_base.IDENTITY_KEYS)

    def test_source_constructor_admits_sources_only(self):
        with self.assertRaises(TypeError):
            windows_scoped.WindowsRoot(str(self.path()), non_private_destination=True)
        source = windows_scoped.WindowsRoot(str(self.path()))
        self.addCleanup(source.close)
        self.assertIs(source.destination, False)
        self.assertIs(self.admit("exFAT", win32_files.DRIVE_REMOVABLE, non_private_destination=True).destination, True)
        self.assertEqual(self.code(windows_scoped.WindowsRoot, str(self.path()), volumes=volumes("FAT32", 3)), "ntfs-required")

    def test_read_only_removal_needs_ntfs(self):
        root = self.admit("FAT32", win32_files.DRIVE_REMOVABLE, non_private_destination=True)
        self.path("old.zip").write_bytes(b"old")
        os.chmod(self.path("old.zip"), stat.S_IREAD)
        record = root.inspect("old.zip", hash_file=True)
        self.assertEqual(self.code(root.remove_file, "old.zip", expected=record, allow_read_only=True),
                         "read-only-removal-unsupported")
        self.path("new.zip").write_bytes(b"new")
        fresh = root.inspect("new.zip", hash_file=True)
        os.chmod(self.path("new.zip"), stat.S_IREAD)  # read-only only after the plan was made
        self.assertEqual(self.code(root.remove_file, "new.zip", expected=fresh, allow_read_only=True), "read-only")
        self.assertTrue(self.path("old.zip").exists() and self.path("new.zip").exists())

    def test_destination_rename_never_replaces(self):
        root = self.admit("FAT32", win32_files.DRIVE_REMOVABLE, non_private_destination=True)
        self.path("backup.zip").write_bytes(b"earlier backup")
        self.assertEqual(self.code(lambda: root.open_new("backup.zip").__enter__()), "destination-exists")
        with self.assertRaises(ScopedFSError) as caught:
            with root.open_new("manifest.json") as out:
                out.write(b"{}")
                self.path("manifest.json").write_bytes(b"theirs")
                out.commit()
        self.assertEqual(caught.exception.code, "destination-exists")
        self.assertEqual(self.path("backup.zip").read_bytes(), b"earlier backup")
        self.assertEqual(self.path("manifest.json").read_bytes(), b"theirs")
        self.assertEqual(sorted(os.listdir(self.path())), ["backup.zip", "manifest.json"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
