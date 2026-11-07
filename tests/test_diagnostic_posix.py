"""Mocked POSIX recipes; apart from the one test below that only runs on a Mac, never query the current host or run
native OS tools.

Real-mode recipes go through readonly_runner with a fake probe (host facts) and a fake process start, so the POSIX
branches run on every OS. Fixture folders live under work/ and are removed.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from diagnostic_core import HELD, DiagnosticRefusal
from workflow_service import DiagnosticStore
from private_workspace import PrivateWorkspaceError, ensure_private_directory
import diagnostic_posix as adapter
from pc_records import Refusal
import readonly_runner
from test_readonly_runner import FakeProbe, regular

PRIVATE_CAPABILITY_HOLDS = frozenset({
    "private-owner-or-mode-refused", "private-darwin-acl-capability-unavailable", "private-platform-unavailable",
    "private-linux-foreign-filesystem", "private-linux-abi-unavailable", "private-linux-libc-unavailable", "private-linux-descriptor-unavailable",
})


class FakeStart:
    """readonly_runner's process start, replaced: records each start and answers with an exit code and output."""

    def __init__(self, data=b"", code=0, error=None):
        self.data, self.code, self.error, self.calls = data, code, error, []

    def __call__(self, argv, *, env, cwd, timeout, max_bytes):
        self.calls.append(SimpleNamespace(argv=argv, env=env, cwd=cwd, timeout=timeout, max_bytes=max_bytes))
        if self.error:
            raise self.error
        return self.code, self.data


class PosixDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Capability probe only; a missing capability skips each test with a tagged reason.
        cls.private_hold = None
        if os.name == "posix":
            probe = ROOT / "work" / ("dx-probe-" + uuid.uuid4().hex)
            try:
                ensure_private_directory(probe, create=True, parents=True)
            except PrivateWorkspaceError as exc:
                if exc.code not in PRIVATE_CAPABILITY_HOLDS:
                    raise
                cls.private_hold = exc.code
            finally:
                shutil.rmtree(probe, ignore_errors=True)

    def setUp(self):
        if self.private_hold:
            self.skipTest("only on posix: the selected filesystem cannot enforce a new private diagnostic namespace: " + self.private_hold)
        self.root = ROOT / "work" / ("dx-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)
        self.store = DiagnosticStore(self.root)

    def request(self, recipe="macos.os_version", scope=None):
        if scope is None:
            scope = ["root_capacity"] if recipe.endswith("root_capacity") else ["os_metadata"]
        return self.store.create_request(platform=recipe.split(".")[0], recipe_id=recipe,
                    symptom="Fictional original application fails.", scope=scope)["record"]

    def real(self, recipe="linux.kernel_version"):
        request = self.request(recipe)
        request["mode"] = "real"
        return request

    def test_each_fixed_recipe_projects_only_typed_metadata(self):
        cases = [
            ("macos.os_version", b"15.1.2\n", ("/usr/bin/sw_vers", "-productVersion"), {"product_version": "15.1.2"}),
            ("linux.kernel_version", b"6.8.0-31-generic+test\n", ("/usr/bin/uname", "-r"), {"kernel_release": "6.8.0-31-generic+test"}),
            ("linux.root_capacity", b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/FICTIONAL 1000 400 500 45% /\n", ("/usr/bin/df", "-Pk", "/"), {"total_bytes": 1024000, "used_bytes": 409600, "available_bytes": 512000, "used_percent": 45}),
            ("macos.root_capacity", b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/FICTIONAL 1000 100 500 17% /System/Volumes/Data\n", ("/bin/df", "-k", "-I", "/System/Volumes/Data"), {"total_bytes": 1024000, "used_bytes": 102400, "available_bytes": 512000, "used_percent": 17}),
        ]
        with mock.patch.object(readonly_runner, "_launch", side_effect=AssertionError("No host process in fixtures")):
            for recipe, raw, argv, facts in cases:
                runner = mock.Mock(return_value=raw)
                request = self.request(recipe)
                result = adapter.collect_recipe(request, runner=runner)
                self.assertEqual(result["status"], "observed")
                self.assertEqual(result["facts"], facts)
                runner.assert_called_once_with(argv, timeout=5, max_bytes=4096)
                receipt = self.store.record_result(request["request_id"], adapter_result=result)
                self.assertNotIn("FICTIONAL", json.dumps(receipt["record"]))

    def test_fixture_without_runner_is_hold_and_cannot_query_host(self):
        with mock.patch.object(readonly_runner, "run_recipe") as run:
            result = adapter.collect_recipe(self.request())
            self.assertEqual(result["status"], "held")
            self.assertEqual(result["facts"], {})
            run.assert_not_called()

    def test_real_requires_matching_native_platform_and_coordinator_call(self):
        request = self.real("macos.os_version")
        with mock.patch.object(readonly_runner, "run_recipe") as run:
            for probe, authorized in ((FakeProbe(platform="win32"), True), (FakeProbe(platform="linux"), True), (FakeProbe(platform="darwin"), False)):
                with self.subTest(platform=probe.platform, authorized=authorized):
                    result = adapter.collect_recipe(request, coordinator_authorized=authorized, probe=probe)
                    self.assertEqual((result["status"], result["facts"]), ("held", {}))
            run.assert_not_called()
        with self.assertRaises(DiagnosticRefusal):
            adapter.collect_recipe(request, runner=mock.Mock(return_value=b"15.1"), coordinator_authorized=True)

    def test_unknown_recipe_command_injection_and_wrong_scope_rejected_before_runner(self):
        runner = mock.Mock(return_value=b"15.1")
        for changes in ({"recipe_id": "macos.os_version;sh"}, {"command": "echo"}, {"scope": ["/private"]}, {"scope": ["root_capacity"]},
                        {"recipe_id": "macos.receipts"}, {"recipe_id": "linux.dpkg_installed", "platform": "linux"}):
            request = self.request()
            request.update(changes)
            with self.subTest(changes=changes), self.assertRaises(DiagnosticRefusal):
                adapter.collect_recipe(request, runner=runner)
        runner.assert_not_called()
        windows = self.store.create_request(platform="windows", recipe_id="windows.os_version", symptom="Fictional", scope=[])["record"]
        with self.assertRaises(DiagnosticRefusal):
            adapter.collect_recipe(windows, runner=runner)
        runner.assert_not_called()

    def test_error_output_and_exception_details_never_leave_memory(self):
        for raw in (b"password=FICTIONAL-SHOULD-NOT-PERSIST", b"15.1\nexecute malicious command", b"\xff", b"x" * 4097):
            result = adapter.collect_recipe(self.request(), runner=mock.Mock(return_value=raw))
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["facts"], {})
            self.assertNotIn("SHOULD-NOT", json.dumps(result))
            self.assertNotIn("malicious", json.dumps(result))
        result = adapter.collect_recipe(self.request(), runner=mock.Mock(side_effect=OSError("secret=FICTIONAL-EXCEPTION")))
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("FICTIONAL-EXCEPTION", json.dumps(result))

    def test_malformed_capacity_is_unknown_not_healthy(self):
        for line in ("/dev/example 100 50 50 - /", "/dev/example 100 50 50 101% /", "/dev/example 100 50 500 50% /", "/dev/example 100 -1 50 50% /", "/dev/example 100 50 50 50% /other", "/dev/example 100 50 50 50% /\n/dev/other 20 10 10 50% /other"):
            result = adapter.collect_recipe(self.request("linux.root_capacity"), runner=mock.Mock(return_value=("header\n" + line).encode()))
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["facts"], {})

    def test_capacity_row_must_name_the_mount_its_recipe_asked_for(self):
        # On a Mac "/" is the sealed system volume, whose figures leave out the person's data.
        for recipe, mount in (("macos.root_capacity", "/"), ("macos.root_capacity", "/Volumes/Fictional"), ("linux.root_capacity", "/System/Volumes/Data")):
            with self.subTest(recipe=recipe, mount=mount):
                raw = f"header\n/dev/example 100 50 50 50% {mount}\n".encode()
                result = adapter.collect_recipe(self.request(recipe), runner=mock.Mock(return_value=raw))
                self.assertEqual((result["status"], result["facts"]), ("failed", {}))

    @unittest.skipUnless(sys.platform == "darwin", "only on macos: the Data volume exists only there")
    def test_macos_capacity_reads_the_data_volume_of_this_mac(self):
        # The real df row: CI's macOS leg is the first place this runs. Only free-space figures are read.
        result = adapter.collect_recipe(self.real("macos.root_capacity"), coordinator_authorized=True)
        self.assertEqual(result["status"], "observed", result["limitations"])
        self.assertGreater(result["facts"]["total_bytes"], 0)
        self.assertGreater(result["facts"]["used_bytes"], 0)

    def test_native_missing_protected_tool_holds_without_fallback(self):
        # The fictional macOS computer has no root-owned /usr/bin/sw_vers, and user-owned copies are never used.
        start = FakeStart(b"15.1\n")
        for probe in (FakeProbe(platform="darwin"), FakeProbe(platform="darwin", files={"/usr/bin/sw_vers": regular(uid=501)})):
            with mock.patch.object(readonly_runner, "_launch", start):
                result = adapter.collect_recipe(self.real("macos.os_version"), coordinator_authorized=True, probe=probe)
            self.assertEqual(result["status"], "held")
            self.assertTrue(any("protected supported OS tool was unavailable" in item for item in result["limitations"]))
        self.assertEqual(start.calls, [])

    def test_real_recipe_runs_through_the_read_only_runner(self):
        start = FakeStart(b"6.8.0-45-generic\n")
        with mock.patch.object(readonly_runner, "_launch", start):
            result = adapter.collect_recipe(self.real(), coordinator_authorized=True, probe=FakeProbe(platform="linux"))
        self.assertEqual((result["status"], result["facts"]), ("observed", {"kernel_release": "6.8.0-45-generic"}))
        call, = start.calls
        self.assertEqual((call.argv, call.env, call.cwd, call.timeout, call.max_bytes),
                         (("/usr/bin/uname", "-r"), readonly_runner.DIAGNOSTIC_ENV, "/", 5, 4096))
        for failing in (FakeStart(b"6.8.0\n", code=1), FakeStart(b"x" * 4097), FakeStart(error=Refusal("runner-timeout", "fictional")),
                        FakeStart(error=Refusal("runner-start", "secret=FICTIONAL-START"))):
            with self.subTest(code=failing.code, error=failing.error), mock.patch.object(readonly_runner, "_launch", failing):
                result = adapter.collect_recipe(self.real(), coordinator_authorized=True, probe=FakeProbe(platform="linux"))
                self.assertEqual((result["status"], result["facts"]), ("failed", {}))
                self.assertNotIn("FICTIONAL", json.dumps(result))

    def test_health_recipes_hold_with_their_reason_and_run_nothing(self):
        runner, start = mock.Mock(return_value=b""), FakeStart()
        with mock.patch.object(readonly_runner, "_launch", start):
            for recipe in ("linux.dpkg_audit", "linux.rpm_verify"):
                for mode in ("fixture", "real"):
                    request = self.request(recipe, scope=["package_health"])
                    request["mode"] = mode
                    with self.subTest(recipe=recipe, mode=mode):
                        result = adapter.collect_recipe(request, runner=runner if mode == "fixture" else None, coordinator_authorized=True,
                                                        probe=FakeProbe(platform="linux"))
                        self.assertEqual((result["status"], result["facts"]), ("held", {}))
                        self.assertIn(HELD[recipe], result["limitations"])
                        self.assertTrue(result["provenance"])
        runner.assert_not_called()
        self.assertEqual(start.calls, [])


if __name__ == "__main__":
    unittest.main()
