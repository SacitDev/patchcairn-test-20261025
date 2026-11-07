"""The Windows diagnostic recipes (scripts/diagnostic_windows.py): the in-process OS version and drive capacity, and the
read-only start of the PowerShell helper with a fake launcher and fake host facts on every OS. No test starts
PowerShell or reads this computer; the bounded launcher itself is exercised with the Python interpreter running this
suite. Fixture folders live under work/test-fixtures/ and are removed.
Run from the repository root: python3 -I -S -B -m unittest discover -s tests -p "test_diagnostic_windows.py"
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import diagnostic_core  # noqa: E402
import diagnostic_windows as windows  # noqa: E402
import pc_records  # noqa: E402
from diagnostic_core import DiagnosticRefusal  # noqa: E402
from private_workspace import PrivateWorkspaceError, ensure_private_directory  # noqa: E402

PRIVATE_CAPABILITY_HOLDS = frozenset({
    "private-owner-or-mode-refused", "private-darwin-acl-capability-unavailable", "private-platform-unavailable",
    "private-linux-foreign-filesystem", "private-linux-abi-unavailable", "private-linux-libc-unavailable", "private-linux-descriptor-unavailable",
})
SYSTEM = r"C:\Windows\System32"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
ENVIRONMENT = {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows", "PSModulePath": r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules"}
# What Windows PowerShell 5.1 prints when the AllSigned policy refuses an unsigned script started with -File (the
# paths are fictional).
POLICY_REFUSAL = (b"File D:\\Fictional\\diagnostic_windows.ps1 cannot be loaded. The file D:\\Fictional\\diagnostic_windows.ps1 "
                  b"is not \r\ndigitally signed. You cannot run this script on the current system.\r\n"
                  b"    + CategoryInfo          : SecurityError: (:) [], ParentContainsErrorRecordException\r\n"
                  b"    + FullyQualifiedErrorId : UnauthorizedAccess\r\n")


class FakeProbe:
    """Host facts of a fictional Windows computer."""

    platform = "win32"

    def __init__(self, files=None, tags=None, usage=(1000, 400)):
        self.files = {POWERSHELL: SimpleNamespace(st_mode=stat.S_IFREG | 0o755), **(files or {})}
        self.tags, self.usage, self.measured = dict(tags or {}), usage, []

    def system_directory(self):
        return SYSTEM

    def lstat(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def reparse_tag(self, path):
        return self.tags.get(path, 0)

    def windows_version(self):
        return 10, 0, 26100

    def native_machine(self):
        return "arm64"

    def disk_usage(self, path):
        self.measured.append(path)
        return self.usage


class FakeLauncher:
    """Records each start and answers with an exit code and output, or raises."""

    def __init__(self, code=0, stdout=None, stderr=b"", error=None):
        self.code, self.stdout, self.stderr, self.error, self.calls = code, stdout, stderr, error, []

    def __call__(self, argv, *, env, cwd, timeout, max_bytes):
        request = pc_records.decode_strict(Path(argv[6]).read_bytes())
        self.calls.append(SimpleNamespace(argv=argv, env=env, cwd=cwd, timeout=timeout, max_bytes=max_bytes, request=request))
        if self.error:
            raise self.error
        stdout = self.stdout
        if stdout is None:  # the helper's result for the request it was given
            result = {key: request[key] for key in ("schema", "schema_version", "request_id", "platform", "recipe_id", "mode")}
            result.update(kind="adapter_result", status="observed", observed_utc=pc_records.utc_now(),
                          facts={"updates": [{"kb_id": "KB1234567", "installed_utc": None}]},
                          limitations=["Fictional helper output; no host collector ran."],
                          provenance=list(diagnostic_core.TABLE["windows.update_context"].sources))
            stdout = json.dumps(result).encode("ascii") + b"\r\n"
        return self.code, stdout, self.stderr


class WindowsDiagnosticTests(unittest.TestCase):
    def setUp(self):
        # The helper's request file goes into the operation's private folder, as in the service.
        self.folder = ROOT / "work" / "test-fixtures" / ("diagnostic-windows-" + uuid.uuid4().hex)
        self.addCleanup(shutil.rmtree, self.folder, ignore_errors=True)
        try:
            ensure_private_directory(self.folder, create=True, parents=True)
        except PrivateWorkspaceError as exc:
            if os.name != "posix" or exc.code not in PRIVATE_CAPABILITY_HOLDS:
                raise
            self.skipTest("only on posix: the selected filesystem cannot enforce a new private folder: " + exc.code)

    def request(self, recipe_id="windows.update_context", mode="real", scope=()):
        return {"schema": diagnostic_core.SCHEMA, "schema_version": 1, "kind": "request", "request_id": "diag-" + uuid.uuid4().hex,
                "platform": "windows", "recipe_id": recipe_id, "mode": mode, "symptom": "Fictional update error E42.",
                "scope": list(scope), "observed_utc": pc_records.utc_now()}

    def collect(self, request, launcher, probe=None, authorized=True):
        folder = ensure_private_directory(self.folder / uuid.uuid4().hex, create=True)
        return windows.collect_recipe(request, folder=folder, work=str(self.folder), coordinator_authorized=authorized,
                                      launcher=launcher, probe=probe or FakeProbe())

    def test_helper_starts_with_fixed_argv_and_only_its_three_environment_variables(self):
        launcher = FakeLauncher()
        request = self.request()
        # An inherited policy override or module path in this process must not reach the helper.
        with mock.patch.dict(os.environ, {"PSExecutionPolicyPreference": "Bypass", "PSModulePath": "D:\\Planted\\Modules"}):
            result = self.collect(request, launcher)
        self.assertEqual((result["status"], result["facts"]), ("observed", {"updates": [{"kb_id": "KB1234567", "installed_utc": None}]}))
        call, = launcher.calls
        self.assertEqual(call.argv, (POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(windows.HELPER),
                                     "-RequestPath", call.argv[6], "-CoordinatorAuthorized"))
        self.assertEqual(Path(call.argv[6]).name, "helper-request.json")
        self.assertEqual(windows.HELPER, ROOT / "scripts" / "diagnostic_windows.ps1")
        self.assertEqual(call.env, ENVIRONMENT)
        self.assertNotIn("-ExecutionPolicy", call.argv)
        self.assertEqual((call.cwd, call.timeout, call.max_bytes), (SYSTEM, windows.HELPER_TIMEOUT_SECONDS, windows.HELPER_MAX_BYTES))
        self.assertEqual((windows.HELPER_TIMEOUT_SECONDS, windows.HELPER_MAX_BYTES), (120, diagnostic_core.MAX_RECORD))
        self.assertEqual(call.request, request)
        self.assertEqual(Path(call.argv[6]).read_bytes(), pc_records.encoded(request))

    def test_policy_start_failure_timeout_and_output_holds_are_typed(self):
        utf16 = "Loading managed Windows PowerShell failed with error 8009001d.\r\n".encode("utf-16-le")
        cases = [
            (FakeLauncher(1, b"", b"diagnostic:execution-policy-override\r\nAt line:18 char:47\r\n"), "windows-script-policy"),
            (FakeLauncher(1, b"", b"diagnostic:foreign-module\r\n    + FullyQualifiedErrorId : diagnostic:foreign-module\r\n"), "windows-script-policy"),
            (FakeLauncher(1, b"", POLICY_REFUSAL), "windows-script-policy"),
            (FakeLauncher(0xFFFF0000, b"", b""), "windows-helper-start"),
            (FakeLauncher(-65536, b"", b""), "windows-helper-start"),  # 0xFFFF0000 as a signed exit status
            (FakeLauncher(1, b"", utf16), "windows-helper-start"),
            # A failed start is never the policy hold, even when its text names a policy code.
            (FakeLauncher(0xFFFF0000, b"", b"diagnostic:execution-policy-override"), "windows-helper-start"),
            (FakeLauncher(1, b"", "diagnostic:execution-policy-override".encode("utf-16-le")), "windows-helper-start"),
            (FakeLauncher(error=DiagnosticRefusal("fictional", code="windows-helper-timeout")), "windows-helper-timeout"),
            (FakeLauncher(error=DiagnosticRefusal("fictional", code="windows-helper-output")), "windows-helper-output"),
            (FakeLauncher(error=DiagnosticRefusal("fictional", code="windows-helper-start")), "windows-helper-start"),
            (FakeLauncher(0, b"x" * (windows.HELPER_MAX_BYTES + 1)), "windows-helper-output"),
        ]
        for launcher, hold in cases:
            with self.subTest(hold=hold, code=launcher.code, stderr=launcher.stderr[:40]):
                result = self.collect(self.request(), launcher)
                self.assertEqual((result["status"], result["hold"], result["facts"]), ("held", hold, {}))
                self.assertIn(windows.GUIDANCE[hold], result["limitations"])
                self.assertEqual(len(launcher.calls), 1)
        self.assertIn("Only the computer's owner may change that policy", windows.GUIDANCE["windows-script-policy"])
        self.assertNotIn("policy", windows.GUIDANCE["windows-helper-start"])
        self.assertEqual(set(windows.GUIDANCE), diagnostic_core.HOLDS)

    def test_failed_or_malformed_helper_output_keeps_no_text(self):
        secret = b"secret=FICTIONAL-STDERR D:\\Fictional\\private"
        for launcher in (FakeLauncher(1, b"", secret), FakeLauncher(0, b"not json " + secret), FakeLauncher(0, "{\"caf\u00e9\":1}".encode("utf-8")),
                         FakeLauncher(0, b'{"schema":"patchcairn.diagnostics"}'), FakeLauncher(2, None, secret)):
            with self.subTest(code=launcher.code, stdout=(launcher.stdout or b"")[:20]):
                result = self.collect(self.request(), launcher)
                self.assertEqual((result["status"], result["facts"]), ("failed", {}))
                self.assertNotIn("hold", result)
                self.assertNotIn("FICTIONAL", json.dumps(result))

    def test_helper_starts_only_for_an_approved_real_request_on_windows(self):
        cases = [(self.request(mode="fixture"), FakeProbe(), True, "Fixture requires an explicit fictional result"),
                 (self.request(), FakeProbe(), False, "approved diagnostic action are required"),
                 (self.request(), SimpleNamespace(platform="linux"), True, "approved diagnostic action are required"),
                 (self.request("windows.dism_check_health"), FakeProbe(), True, "administrator prompt"),
                 (self.request("windows.sfc_verify_only"), FakeProbe(), True, "administrator prompt")]
        for request, probe, authorized, limitation in cases:
            launcher = FakeLauncher()
            with self.subTest(recipe=request["recipe_id"], mode=request["mode"], authorized=authorized):
                result = self.collect(request, launcher, probe=probe, authorized=authorized)
                self.assertEqual((result["status"], result["facts"]), ("held", {}))
                self.assertTrue(any(limitation in item for item in result["limitations"]), result["limitations"])
                self.assertEqual(launcher.calls, [])
        with self.assertRaises(DiagnosticRefusal):
            self.collect({**self.request(), "platform": "linux", "recipe_id": "linux.kernel_version"}, FakeLauncher())

    def test_executable_must_be_a_plain_file_in_the_system_folder(self):
        missing = FakeProbe()
        del missing.files[POWERSHELL]
        for probe in (FakeProbe(tags={POWERSHELL: 0xA000000C}), FakeProbe(files={POWERSHELL: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)}), missing):
            launcher = FakeLauncher()
            with self.subTest(files=probe.files, tags=probe.tags):
                result = self.collect(self.request(), launcher, probe=probe)
                self.assertEqual((result["status"], result["hold"]), ("held", "windows-helper-start"))
                self.assertEqual(launcher.calls, [])

    def test_os_version_and_capacity_run_in_process_and_capacity_measures_the_work_drive(self):
        probe, launcher = FakeProbe(usage=(500_000_000_000, 120_000_000_000)), FakeLauncher()
        version = self.collect(self.request("windows.os_version"), launcher, probe=probe)
        self.assertEqual((version["status"], version["facts"]), ("observed", {"version": "10.0.26100", "build": "26100", "architecture": "arm64"}))
        capacity = self.collect(self.request("windows.system_capacity"), launcher, probe=probe)
        self.assertEqual((capacity["status"], capacity["facts"]), ("observed", {"total_bytes": 500_000_000_000, "available_bytes": 120_000_000_000}))
        self.assertEqual(probe.measured, [str(self.folder)])
        self.assertTrue(any("drive that holds PatchCairn's work folder" in item for item in capacity["limitations"]))
        self.assertFalse(any("emory" in item for item in capacity["limitations"]))
        self.assertEqual(launcher.calls, [])
        for recipe_id in ("windows.os_version", "windows.system_capacity"):
            with self.subTest(recipe=recipe_id), self.assertRaises(DiagnosticRefusal):
                self.collect(self.request(recipe_id, scope=["window_hours:1"]), launcher, probe=probe)
        failing = FakeProbe()
        failing.disk_usage = mock.Mock(side_effect=OSError("D:\\Fictional\\private path"))
        failed = self.collect(self.request("windows.system_capacity"), launcher, probe=failing)
        self.assertEqual((failed["status"], failed["facts"]), ("failed", {}))
        self.assertNotIn("Fictional", json.dumps(failed))

    def test_capacity_is_the_space_this_user_may_use(self):
        # A per-user quota leaves less than the drive's free space, and the service passes a Path.
        probe = windows.WindowsProbe()
        probe.platform = "win32"
        with mock.patch.object(windows.win32_files, "disk_space", return_value=(1000, 300)) as space, \
                mock.patch("shutil.disk_usage", return_value=(1000, 100, 900)):
            result = windows.collect_recipe(self.request("windows.system_capacity"), folder=self.folder, work=self.folder,
                                            coordinator_authorized=True, probe=probe)
        self.assertEqual((result["status"], result["facts"]), ("observed", {"total_bytes": 1000, "available_bytes": 300}))
        space.assert_called_once_with(str(self.folder))

    @unittest.skipUnless(sys.platform == "win32", "only on windows: the recipes make these calls only there")
    def test_host_probe_reads_version_architecture_and_capacity(self):
        probe = windows.WindowsProbe()
        major, minor, build = probe.windows_version()
        self.assertTrue(major >= 10 and build > 0)
        self.assertIn(probe.native_machine(), ("x64", "arm64", "x86", "unknown"))
        total, available = probe.disk_usage(self.folder)  # a Path, as the service passes it
        self.assertTrue(0 < total and 0 <= available <= total)

    def test_launch_reads_both_pipes_within_time_and_output_bounds(self):
        python, env = [sys.executable, "-I", "-S", "-B", "-c"], dict(os.environ)
        script = "import sys; sys.stderr.write('e' * 50000); sys.stderr.flush(); sys.stdout.write('ok'); sys.exit(3)"
        self.assertEqual(windows._launch(python + [script], env=env, cwd=str(ROOT), timeout=60, max_bytes=100000),
                         (3, b"ok", b"e" * 50000))
        for script, timeout, expected in (("import sys; sys.stdout.write('x' * 5000); sys.stdout.flush()", 60, "windows-helper-output"),
                                          ("import sys; sys.stderr.write('x' * 5000); sys.stderr.flush()", 60, "windows-helper-output"),
                                          ("import time; time.sleep(30)", 0.5, "windows-helper-timeout")):
            with self.subTest(expected=expected), self.assertRaises(DiagnosticRefusal) as caught:
                windows._launch(python + [script], env=env, cwd=str(ROOT), timeout=timeout, max_bytes=100)
            self.assertEqual(caught.exception.code, expected)
        with self.assertRaises(DiagnosticRefusal) as caught:
            windows._launch([str(self.folder / "missing-program")], env=env, cwd=str(ROOT), timeout=5, max_bytes=100)
        self.assertEqual(caught.exception.code, "windows-helper-start")


if __name__ == "__main__":
    unittest.main()
