"""Read-only runner (G09, RR2-7): a closed recipe table, listed executables only, fixed environment and bounds.

Recipes run through a fake launcher and a fake probe; no test starts a package manager. The bounded launcher itself is
exercised with the Python interpreter running this suite. Fictional paths are not user-profile paths (D-026).
Run from the repository root: python3 -I -S -B -m unittest discover -s tests -p "test_readonly_runner.py"
"""
from __future__ import annotations

import inspect
import ntpath
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import diagnostic_core  # noqa: E402
import package_routes as routes  # noqa: E402
import readonly_runner  # noqa: E402
from pc_records import Refusal  # noqa: E402

WORK = ROOT / "work" / "test-readonly-runner"
SYSTEM_DIR = "C:\\Windows\\System32"
LOCAL_APPDATA = "D:\\PatchCairnTest\\LocalData"
RUN_FOLDER = "D:\\PatchCairnTest\\work\\run-1"
UNAME = {"linux.kernel_version": (("/usr/bin/uname", "/bin/uname"), ("-r",))}


def regular(uid=0, mode=0o755):
    return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid)


def folder(uid=0, mode=0o755):
    return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid)


APP_FOLDER = "Microsoft.DesktopAppInstaller_1.12.350.0_x64__8wekyb3d8bbwe"


def appexec_buffer(strings):
    """A synthetic APPEXECLINK reparse buffer: tag, data length, reserved, version 3, NUL-separated UTF-16 strings."""
    data = (3).to_bytes(4, "little") + "".join(item + "\x00" for item in strings).encode("utf-16-le")
    return (0x8000001B).to_bytes(4, "little") + len(data).to_bytes(2, "little") + b"\x00\x00" + data


# Root-owned tools in root-owned folders that are still outside the listed system folders.
OUTSIDE = {**{path: folder() for path in ("/opt/evil", "/opt/tools", "/usr/local", "/usr/local/bin")},
           **{path: regular() for path in ("/opt/evil/uname", "/opt/tools/uname", "/usr/local/bin/uname", "/usr/local/bin/apt-config")}}


class FakeProbe:
    """Facts of a fictional computer: root-owned system folders and tools, a winget alias, a Windows system folder."""

    def __init__(self, platform="linux", files=None, links=None, elevation=None, tags=None, identity=None, aliases=None):
        self.platform, self.state, self.who, self.aliases = platform, elevation, identity, dict(aliases or {})
        self.links = {"/usr/bin/dnf": "/usr/bin/dnf5", "/bin/uname": "/usr/bin/uname", **(links or {})}
        self.tags = {routes.winget_alias_path(LOCAL_APPDATA): routes.WINGET_TAG, **(tags or {})}
        self.files = {"/": folder(), "/usr": folder(), "/usr/bin": folder(), "/usr/sbin": folder(), "/bin": folder(),
                      "/usr/bin/uname": regular(), "/usr/bin/apt-cache": regular(), "/usr/bin/apt-config": regular(),
                      "/usr/bin/dnf5": regular(), "/opt": folder(), "/opt/homebrew": folder(1000), "/opt/homebrew/bin": folder(1000),
                      "/opt/homebrew/bin/brew": regular(1000), ntpath.join(SYSTEM_DIR, "whoami.exe"): regular(), **(files or {})}

    def elevation(self):
        return self.state

    def euid(self):
        return 1000

    def identity(self):
        if isinstance(self.who, Exception):
            raise self.who
        return "/var/lib/patchcairn-test/example", "example"

    def machine(self):
        return "arm64"

    def realpath(self, path):
        return self.links.get(path, path)

    def lstat(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def environ(self):
        return {"SystemRoot": "C:\\Windows"}

    def local_appdata(self):
        return LOCAL_APPDATA

    def reparse_tag(self, path):
        return self.tags.get(path, 0)

    def system_directory(self):
        return SYSTEM_DIR

    def program_files(self):
        return "C:\\Program Files"

    def appexec_link(self, path):
        return readonly_runner.appexec_strings(self.aliases.get(path, b""))

    def private_folder(self, path):
        if path != RUN_FOLDER:
            raise Refusal("runner-run-folder", "not the private run folder")
        return path


class FakeLauncher:
    def __init__(self, data=b"", code=0):
        self.data, self.code, self.calls = data, code, []

    def __call__(self, argv, *, env, cwd, timeout, max_bytes):
        self.calls.append(SimpleNamespace(argv=argv, env=env, cwd=cwd, timeout=timeout, max_bytes=max_bytes))
        return self.code, self.data


class ReadonlyRunnerTests(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(parents=True, exist_ok=True)

    def test_runner_accepts_only_recipe_ids(self):
        table = readonly_runner.recipes()
        self.assertEqual(set(table), set(routes.READ_RECIPES) | set(diagnostic_core.RECIPES))
        self.assertFalse(set(routes.RUN_RECIPES) & set(table))
        self.assertLessEqual(set(inspect.signature(readonly_runner.run_recipe).parameters), {"recipe_id", "values", "run_folder", "launcher", "probe"})
        launcher = FakeLauncher()
        for bad in ("apt.upgrade", "winget.upgrade", "dnf.makecache", "brew.update", "apt-get", "/usr/bin/apt-get",
                    ["/usr/bin/apt-config", "dump"], ("apt.config",), None, 7, "APT.CONFIG"):
            with self.assertRaises(Refusal):
                readonly_runner.run_recipe(bad, launcher=launcher, probe=FakeProbe())
        for values in ({"package": "examplecurl;reboot"}, {"package": "-o"}, {"argv": ["/usr/bin/apt-get", "update"]},
                       {"package": "examplecurl", "extra": "1"}, {"package": ["examplecurl"]}):
            with self.assertRaises(Refusal):
                readonly_runner.run_recipe("apt.policy", values, launcher=launcher, probe=FakeProbe())
        with mock.patch.object(diagnostic_core, "ARGV", {}, create=True):
            with self.assertRaises(Refusal):
                readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=FakeProbe())
        with mock.patch.object(diagnostic_core, "ARGV", UNAME, create=True):
            with self.assertRaises(Refusal):
                readonly_runner.run_recipe("linux.kernel_version", {"flag": "-a"}, launcher=launcher, probe=FakeProbe())
        self.assertEqual(launcher.calls, [])
        readonly_runner.run_recipe("apt.policy", {"package": "examplecurl"}, launcher=launcher, probe=FakeProbe())
        self.assertEqual(launcher.calls[0].argv, ("/usr/bin/apt-cache", "policy", "examplecurl"))

    def test_runner_refuses_unlisted_executable(self):
        launcher = FakeLauncher(b"6.8.0-45-generic\n")
        with mock.patch.object(diagnostic_core, "ARGV", UNAME, create=True):
            readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=FakeProbe())
            self.assertEqual(launcher.calls[0].argv, ("/usr/bin/uname", "-r"))
            coreutils = "/usr/lib/cargo/bin/coreutils"
            rust = {**{path: folder() for path in ("/usr/lib", "/usr/lib/cargo", "/usr/lib/cargo/bin", coreutils)}, coreutils + "/uname": regular()}
            readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=FakeProbe(links={"/usr/bin/uname": coreutils + "/uname"},
                                                                                                   files=rust))
            self.assertEqual(launcher.calls[1].argv, ("/usr/bin/uname", "-r"))
            user_owned = {**OUTSIDE, "/opt/evil": folder(1000)}
            for probe in (FakeProbe(links={"/usr/bin/uname": "/opt/evil/uname", "/bin/uname": "/opt/evil/uname"}, files=user_owned),
                          FakeProbe(links={"/usr/bin/uname": coreutils + "/uname", "/bin/uname": coreutils + "/uname"},
                                    files={**rust, coreutils: folder(mode=0o777)}),
                          FakeProbe(files={"/usr/bin/uname": regular(1000)}), FakeProbe(files={"/usr/bin/uname": regular(mode=0o757)}),
                          FakeProbe(files={"/usr/bin": folder(mode=0o775)}), FakeProbe(files={"/usr": folder(1000)}),
                          FakeProbe(files={"/usr/bin/uname": regular(mode=0o644)})):
                with self.assertRaises(Refusal):
                    readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=probe)
        for command in ((("/opt/tools/uname",), ("-r",)), (("uname",), ("-r",)), (("/usr/local/bin/uname",), ("-r",)),
                        (("/usr/bin/../../opt/uname",), ("-r",)), (("/usr/bin/uname",), ("-r\x00",)), ((), ("-r",)), "uname -r",
                        (("/usr/bin/uname",), ("-r",), ("-a",))):
            with mock.patch.object(diagnostic_core, "ARGV", {"linux.kernel_version": command}, create=True):
                with self.assertRaises(Refusal):
                    readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=FakeProbe(files=OUTSIDE))
        whoami = {"linux.kernel_version": (("whoami.exe",), ("/user",))}
        with mock.patch.object(diagnostic_core, "ARGV", whoami, create=True):
            readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=FakeProbe(platform="win32"))
            self.assertEqual(launcher.calls[2].argv, (ntpath.join(SYSTEM_DIR, "whoami.exe"), "/user"))
            self.assertEqual((launcher.calls[2].env, launcher.calls[2].cwd),
                             ({"SystemRoot": "C:\\Windows", "windir": "C:\\Windows", "PATH": "C:\\Windows\\System32;C:\\Windows"}, SYSTEM_DIR))
            for probe in (FakeProbe(platform="win32", tags={ntpath.join(SYSTEM_DIR, "whoami.exe"): 0xA000000C}),
                          FakeProbe(platform="win32", files={ntpath.join(SYSTEM_DIR, "whoami.exe"): folder()})):
                with self.assertRaises(Refusal):
                    readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=probe)
        for name in ("..\\whoami.exe", "C:\\Tools\\whoami.exe", "whoami", "missing.exe"):
            with mock.patch.object(diagnostic_core, "ARGV", {"linux.kernel_version": ((name,), ())}, create=True):
                with self.assertRaises(Refusal):
                    readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=FakeProbe(platform="win32"))
        alias = routes.winget_alias_path(LOCAL_APPDATA)
        for recipe_id, probe in (("winget.version", FakeProbe(platform="win32", tags={alias: 0})),
                                 ("brew.version", FakeProbe(platform="darwin", files={"/opt/homebrew/bin/brew": regular(0)})),
                                 ("apt.config", FakeProbe(links={"/usr/bin/apt-config": "/usr/local/bin/apt-config"},
                                                          files={**OUTSIDE, "/usr/local/bin": folder(1000)})),
                                 ("apt.config", FakeProbe(identity=KeyError(12345)))):
            with self.assertRaises(Refusal):
                readonly_runner.run_recipe(recipe_id, launcher=launcher, probe=probe)
        self.assertEqual(len(launcher.calls), 3)
        with self.assertRaises(Refusal) as caught:
            readonly_runner.run_recipe("apt.config", launcher=launcher, probe=FakeProbe(identity=KeyError(12345)))
        self.assertEqual(caught.exception.code, "runner-identity")

    def test_diagnostic_recipe_runs_with_fixed_command_environment_and_bounds(self):
        launcher = FakeLauncher(b"6.8.0-45-generic\n")
        with mock.patch.object(diagnostic_core, "ARGV", {"linux.kernel_version": (("/bin/uname",), ("-r",))}, create=True):
            result = readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=FakeProbe())
        call = launcher.calls[0]
        self.assertEqual((call.argv, call.env, call.cwd, call.timeout, call.max_bytes),
                         (("/bin/uname", "-r"), readonly_runner.DIAGNOSTIC_ENV, "/", 5, 4096))
        self.assertEqual(result, {"recipe": "linux.kernel_version", "exit_code": 0, "ok": True, "stdout": b"6.8.0-45-generic\n"})
        with mock.patch.object(diagnostic_core, "ARGV", UNAME, create=True):
            with self.assertRaises(Refusal):
                readonly_runner.run_recipe("linux.kernel_version", launcher=FakeLauncher(b"x" * 4097), probe=FakeProbe())

    def test_result_is_normalised_and_bounded(self):
        failed = readonly_runner.run_recipe("apt.config", launcher=FakeLauncher(code=-1), probe=FakeProbe())
        self.assertEqual((failed["exit_code"], failed["ok"]), (0xFFFFFFFF, False))
        alias = routes.winget_alias_path(LOCAL_APPDATA)
        target = ntpath.join("C:\\Program Files", "WindowsApps", APP_FOLDER, "winget.exe")
        windows = FakeProbe(platform="win32", aliases={alias: appexec_buffer([routes.WINGET_PACKAGE, routes.WINGET_PACKAGE + "!winget", target])})
        signed = readonly_runner.run_recipe("winget.upgrades", launcher=FakeLauncher(code=routes.WINGET_NO_APPS - 2 ** 32), probe=windows)
        self.assertEqual((signed["exit_code"], signed["ok"]), (routes.WINGET_NO_APPS, True))
        outdated = readonly_runner.run_recipe("brew.outdated_one", {"kind": "--formula", "name": "examplefetch"},
                                              launcher=FakeLauncher(b"{}", code=1), probe=FakeProbe(platform="darwin"))
        self.assertEqual((outdated["exit_code"], outdated["ok"]), (1, True))
        for launcher in (FakeLauncher(code="0"), FakeLauncher(data="text"), FakeLauncher(data=b"x" * (routes.MAX_OUTPUT_BYTES + 1))):
            with self.assertRaises(Refusal):
                readonly_runner.run_recipe("apt.config", launcher=launcher, probe=FakeProbe())
        with self.assertRaises(Refusal):
            readonly_runner.package_list_time("pacman", probe=FakeProbe())

    def test_launch_runs_a_list_without_a_shell_within_time_and_output_bounds(self):
        python, env = [sys.executable, "-I", "-S", "-B", "-c"], dict(os.environ)
        code, data = readonly_runner._launch(python + ["import sys; sys.stdout.write('ok'); sys.exit(3)"], env=env, cwd=str(ROOT),
                                             timeout=60, max_bytes=100)
        self.assertEqual((code, data), (3, b"ok"))
        literal = "a && echo b | c > d"
        code, data = readonly_runner._launch(python + ["import sys; sys.stdout.write(sys.argv[1])", literal], env=env, cwd=str(ROOT),
                                             timeout=60, max_bytes=100)
        self.assertEqual((code, data), (0, literal.encode()))
        for script, timeout, expected in (("import sys; sys.stdout.write('x' * 5000); sys.stdout.flush()", 60, "runner-output-too-large"),
                                          ("import time; time.sleep(30)", 0.5, "runner-timeout")):
            with self.assertRaises(Refusal) as caught:
                readonly_runner._launch(python + [script], env=env, cwd=str(ROOT), timeout=timeout, max_bytes=100)
            self.assertEqual(caught.exception.code, expected)
        with self.assertRaises(Refusal) as caught:
            readonly_runner._launch([str(WORK / "missing-program")], env=env, cwd=str(ROOT), timeout=5, max_bytes=100)
        self.assertEqual(caught.exception.code, "runner-start")

    def test_host_probe_reads_folder_times(self):
        probe = readonly_runner.HostProbe()
        self.assertIn(probe.elevation(), (None, "root", "elevated", "system"))
        with tempfile.TemporaryDirectory(prefix="lists-", dir=WORK) as lists:
            self.assertIsNone(probe.newest_release(lists))
            entry = Path(lists, "archive.example.invalid_dists_noble_InRelease")
            entry.write_bytes(b"")
            os.utime(entry, (1760486400, 1760486400))
            Path(lists, "partial").mkdir()
            Path(lists, "lock").write_bytes(b"")
            Path(lists, "archive.example.invalid_dists_noble_main_binary-amd64_Packages").write_bytes(b"")
            self.assertEqual(probe.newest_release(lists), 1760486400)
            self.assertEqual(probe.lstat(str(entry)).st_size, 0)
            self.assertEqual(Path(probe.realpath(lists)), Path(lists).resolve())
            with mock.patch.object(readonly_runner, "APT_LISTS", lists):
                self.assertEqual(readonly_runner.package_list_time("apt", probe=probe), "2025-10-15T00:00:00Z")
        with mock.patch.object(readonly_runner, "APT_LISTS", str(WORK / "missing-lists")):
            self.assertIsNone(readonly_runner.package_list_time("apt"))
        self.assertIsInstance(probe.environ(), dict)

    def test_alias_data_must_name_app_installer(self):
        alias = routes.winget_alias_path(LOCAL_APPDATA)
        target = ntpath.join("C:\\Program Files", "WindowsApps", APP_FOLDER, "winget.exe")
        good = appexec_buffer([routes.WINGET_PACKAGE, routes.WINGET_PACKAGE + "!winget", target])
        self.assertEqual(readonly_runner.appexec_strings(good), [routes.WINGET_PACKAGE, routes.WINGET_PACKAGE + "!winget", target])
        for bad in (b"", good[:10], (0xA000000C).to_bytes(4, "little") + good[4:], good[:12] + b"\xff\xfe\x00",
                    appexec_buffer([routes.WINGET_PACKAGE, "", target])):
            self.assertIsNone(readonly_runner.appexec_strings(bad))
        self.assertEqual(readonly_runner.winget_executable(FakeProbe(platform="win32", aliases={alias: good})),
                         {"path": alias, "package": APP_FOLDER})
        other = appexec_buffer(["Contoso.Notes_abc123", "Contoso.Notes_abc123!App", target])
        for probe in (FakeProbe(platform="win32", aliases={alias: other}), FakeProbe(platform="win32"), FakeProbe(platform="win32", tags={alias: 0}),
                      FakeProbe(platform="linux")):
            with self.assertRaises(Refusal):
                readonly_runner.winget_executable(probe)

    def test_winget_output_file_goes_only_into_a_private_run_folder(self):
        alias = routes.winget_alias_path(LOCAL_APPDATA)
        target = ntpath.join("C:\\Program Files", "WindowsApps", APP_FOLDER, "winget.exe")
        probe = FakeProbe(platform="win32", aliases={alias: appexec_buffer([routes.WINGET_PACKAGE, routes.WINGET_PACKAGE + "!winget", target])})
        launcher, export = FakeLauncher(), {"export_file": RUN_FOLDER + "\\winget-export.json"}
        readonly_runner.run_recipe("winget.export", export, run_folder=RUN_FOLDER, launcher=launcher, probe=probe)
        self.assertIn(RUN_FOLDER + "\\winget-export.json", launcher.calls[0].argv)
        for folder_path in ("E:\\Shared\\Public", None):
            with self.assertRaises(Refusal) as caught:
                readonly_runner.run_recipe("winget.export", {"export_file": "E:\\Shared\\Public\\winget-export.json"}, run_folder=folder_path,
                                           launcher=launcher, probe=probe)
            self.assertEqual(caught.exception.code, "runner-run-folder")
        self.assertEqual(len(launcher.calls), 1)
        # The host check admits only an existing private folder inside the repository's work folder (private_workspace).
        host = readonly_runner.HostProbe()
        for outside in (str(ROOT.parent / "elsewhere-run"), str(ROOT / "work"), None, "relative\\run"):
            with self.assertRaises(Refusal) as caught:
                host.private_folder(outside)
            self.assertEqual(caught.exception.code, "runner-run-folder")
        inside = str(WORK / "run-1")
        with mock.patch.object(readonly_runner, "ensure_private_directory", return_value=Path(inside)) as admit:
            self.assertEqual(host.private_folder(inside), inside)
        admit.assert_called_once_with(inside, boundary=readonly_runner.WORK_FOLDER)
        self.assertEqual(Path(readonly_runner.WORK_FOLDER), ROOT / "work")

    def test_host_probe_machine_and_program_files_hold_safely(self):
        probe = readonly_runner.HostProbe()
        probe.platform = "linux"
        # sysctlbyname exists only on macOS; other systems answer from uname without touching it.
        with mock.patch.object(readonly_runner.os, "uname", create=True, return_value=SimpleNamespace(machine="aarch64")), \
                mock.patch("ctypes.CDLL", side_effect=AssertionError("sysctlbyname is called only on macOS")):
            self.assertEqual(probe.machine(), "aarch64")
        # A 32-bit process gets Program Files (x86), never App Installer's folder: winget holds with a clear message.
        with mock.patch.object(readonly_runner.struct, "calcsize", return_value=4):
            with self.assertRaises(Refusal) as caught:
                readonly_runner.HostProbe().program_files()
        self.assertEqual(caught.exception.code, "runner-32-bit")

    @unittest.skipUnless(os.name == "posix", "only on posix: process sessions and killpg")
    def test_launch_kills_descendants_that_keep_the_output_open(self):
        marker = WORK / ("descendant-" + str(os.getpid()))
        script = ("import subprocess, sys; child = subprocess.Popen([sys.executable, '-I', '-S', '-c', 'import time; time.sleep(60)']); "
                  f"open({str(marker)!r}, 'w').write(str(child.pid))")
        with self.assertRaises(Refusal) as caught:
            readonly_runner._launch([sys.executable, "-I", "-S", "-B", "-c", script], env=dict(os.environ), cwd=str(ROOT), timeout=3, max_bytes=100)
        self.assertEqual(caught.exception.code, "runner-timeout")
        pid = int(marker.read_text(encoding="utf-8"))
        marker.unlink()
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            self.fail("the descendant still runs after the timeout")

    @unittest.skipUnless(sys.platform == "win32", "only on windows: Windows token, known folder and reparse-tag calls")
    def test_windows_probe_reads_token_known_folder_and_reparse_tag(self):
        probe = readonly_runner.HostProbe()
        self.assertIn(probe.elevation(), (None, "elevated", "system"))
        system = probe.system_directory()
        self.assertTrue(ntpath.isabs(system) and ntpath.basename(system).lower() == "system32", "system folder")
        self.assertTrue(ntpath.isabs(probe.local_appdata()), "LocalAppData known folder")
        with tempfile.TemporaryDirectory(prefix="tag-", dir=WORK) as folder_path:
            plain = Path(folder_path, "plain.exe")
            plain.write_bytes(b"")
            self.assertEqual(probe.reparse_tag(str(plain)), 0)
            self.assertIsNone(probe.reparse_tag(str(Path(folder_path, "missing.exe"))))
            self.assertIsNone(probe.appexec_link(str(plain)))
            self.assertIsNone(probe.appexec_link(str(Path(folder_path, "missing.exe"))))
        self.assertTrue(ntpath.isabs(probe.program_files()), "ProgramFiles known folder")
        with mock.patch.object(diagnostic_core, "ARGV", {"linux.kernel_version": (("whoami.exe",), ())}, create=True):
            launcher = FakeLauncher()
            readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=probe)
        self.assertEqual(launcher.calls[0].argv, (ntpath.join(system, "whoami.exe"),))

    @unittest.skipUnless(os.name == "posix", "only on posix: password database, euid and root-owned system tools")
    def test_posix_probe_reads_identity_and_root_owned_tools(self):
        probe = readonly_runner.HostProbe()
        self.assertIn(probe.elevation(), (None, "root"))
        home, user = probe.identity()
        self.assertTrue(PurePosixPath(home).is_absolute() and user)
        self.assertEqual(probe.euid(), os.geteuid())
        self.assertTrue(probe.machine())
        with mock.patch.object(diagnostic_core, "ARGV", UNAME, create=True):
            launcher = FakeLauncher()
            readonly_runner.run_recipe("linux.kernel_version", launcher=launcher, probe=probe)
        self.assertIn(launcher.calls[0].argv, (("/usr/bin/uname", "-r"), ("/bin/uname", "-r")))


if __name__ == "__main__":
    unittest.main()
