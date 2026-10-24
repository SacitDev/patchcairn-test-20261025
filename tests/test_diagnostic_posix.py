"""Mocked POSIX recipes; never query the current host or run native OS tools."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from diagnostic_core import DiagnosticStore, DiagnosticRefusal, utc_now
from private_workspace import PrivateWorkspaceError, ensure_private_directory
import diagnostic_posix as adapter


class PosixDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name == "posix":
            probe = ROOT / "work" / ("dx-probe-" + uuid.uuid4().hex)
            try:
                ensure_private_directory(probe, create=True, parents=True)
            except PrivateWorkspaceError as exc:
                if exc.code not in {"private-owner-or-mode-refused", "private-darwin-acl-capability-unavailable", "private-platform-unavailable", "private-linux-foreign-filesystem", "private-linux-abi-unavailable", "private-linux-libc-unavailable", "private-linux-descriptor-unavailable"}:
                    raise
                raise unittest.SkipTest("Selected filesystem cannot enforce a new private diagnostic namespace; no recipe is run") from exc

    def setUp(self):
        self.root = ROOT / "work" / ("dx-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.store = DiagnosticStore(self.root)

    def request(self, recipe="macos.os_version"):
        return self.store.create_request(platform=recipe.split(".")[0], recipe_id=recipe,
                    symptom="Fictional original application fails.",
                    scope=["root_capacity"] if recipe.endswith("root_capacity") else ["os_metadata"])["record"]

    def test_each_fixed_recipe_projects_only_typed_metadata(self):
        cases = [
            ("macos.os_version", b"15.1.2\n", ("/usr/bin/sw_vers", "-productVersion"), {"product_version": "15.1.2"}),
            ("linux.kernel_version", b"6.8.0-31-generic+test\n", ("/usr/bin/uname", "-r"), {"kernel_release": "6.8.0-31-generic+test"}),
            ("linux.root_capacity", b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/FICTIONAL 1000 400 500 45% /\n", ("/usr/bin/df", "-Pk", "/"), {"total_bytes": 1024000, "used_bytes": 409600, "available_bytes": 512000, "used_percent": 45}),
            ("macos.root_capacity", b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/FICTIONAL 1000 100 500 17% /\n", ("/bin/df", "-k", "-I", "/"), {"total_bytes": 1024000, "used_bytes": 102400, "available_bytes": 512000, "used_percent": 17}),
        ]
        with mock.patch.object(adapter.subprocess, "Popen") as native:
            for recipe, raw, argv, facts in cases:
                runner = mock.Mock(return_value=raw)
                request = self.request(recipe)
                result = adapter.collect_recipe(request, runner=runner)
                self.assertEqual(result["status"], "observed")
                self.assertEqual(result["facts"], facts)
                runner.assert_called_once_with(argv, timeout=5, max_bytes=4096)
                receipt = self.store.record_result(request["request_id"], adapter_result=result)
                self.assertNotIn("FICTIONAL", json.dumps(receipt["record"]))
            native.assert_not_called()

    def test_fixture_without_runner_is_hold_and_cannot_query_host(self):
        with mock.patch.object(adapter, "_trusted_executable") as trusted, mock.patch.object(adapter.subprocess, "Popen") as native:
            result = adapter.collect_recipe(self.request())
            self.assertEqual(result["status"], "held")
            self.assertEqual(result["facts"], {})
            trusted.assert_not_called()
            native.assert_not_called()

    def test_real_requires_matching_native_platform_and_coordinator_call(self):
        request = self.request()
        request["mode"] = "real"
        with mock.patch.object(adapter.sys, "platform", "win32"), mock.patch.object(adapter, "_trusted_executable") as trusted, mock.patch.object(adapter.subprocess, "Popen") as native:
            result = adapter.collect_recipe(request, coordinator_authorized=True)
            self.assertEqual(result["status"], "held")
            trusted.assert_not_called()
            native.assert_not_called()
        with self.assertRaises(DiagnosticRefusal):
            adapter.collect_recipe(request, runner=mock.Mock(return_value=b"15.1"), coordinator_authorized=True)
        with mock.patch.object(adapter.sys, "platform", "darwin"), mock.patch.object(adapter, "_trusted_executable") as trusted:
            result = adapter.collect_recipe(request)
            self.assertEqual(result["status"], "held")
            trusted.assert_not_called()

    def test_unknown_recipe_command_injection_and_wrong_scope_rejected_before_runner(self):
        runner = mock.Mock(return_value=b"15.1")
        for changes in ({"recipe_id": "macos.os_version;sh"}, {"command": "echo"}, {"scope": ["/private"]}, {"scope": ["root_capacity"]}):
            request = self.request()
            request.update(changes)
            with self.assertRaises(DiagnosticRefusal):
                adapter.collect_recipe(request, runner=runner)
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

    def test_native_missing_protected_tool_holds_without_fallback(self):
        request = self.request()
        request["mode"] = "real"
        with mock.patch.object(adapter.os, "name", "posix"), mock.patch.object(adapter.sys, "platform", "darwin"), mock.patch.object(adapter, "_trusted_executable", side_effect=DiagnosticRefusal("missing")), mock.patch.object(adapter.subprocess, "Popen") as native:
            self.assertEqual(adapter.collect_recipe(request, coordinator_authorized=True)["status"], "held")
            native.assert_not_called()

    def test_native_popen_uses_fixed_arguments_clean_environment_and_no_shell(self):
        # Mock every process and pipe boundary. This validates the implementation
        # contract without invoking uname, df, sw_vers, or another host command.
        process = mock.Mock()
        process.stdout.fileno.return_value = 123
        process.wait.return_value = 0
        process.poll.return_value = 0
        selector = mock.MagicMock()
        selector.get_map.side_effect = [True, True, False]
        selector.select.return_value = [(object(), object())]
        with mock.patch.object(adapter.subprocess, "Popen", return_value=process) as popen, mock.patch.object(adapter.selectors, "DefaultSelector") as factory, mock.patch.object(adapter.os, "read", side_effect=[b"15.1\n", b""]):
            factory.return_value.__enter__.return_value = selector
            self.assertEqual(adapter._run_bounded(("/usr/bin/sw_vers", "-productVersion")), b"15.1\n")
            argv = popen.call_args.args[0]
            kwargs = popen.call_args.kwargs
            self.assertEqual(argv, ("/usr/bin/sw_vers", "-productVersion"))
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            process.stdout.close.assert_called_once()

    def test_bounded_reader_stops_on_overflow_and_timeout(self):
        for payload in (b"x" * 9, None):
            process = mock.Mock()
            process.stdout.fileno.return_value = 123
            process.poll.return_value = None
            selector = mock.MagicMock()
            selector.get_map.return_value = True
            selector.select.return_value = [(object(), object())] if payload else []
            with mock.patch.object(adapter.subprocess, "Popen", return_value=process), mock.patch.object(adapter.selectors, "DefaultSelector") as factory, mock.patch.object(adapter.os, "read", return_value=payload):
                factory.return_value.__enter__.return_value = selector
                with self.assertRaises(DiagnosticRefusal):
                    adapter._run_bounded(("/usr/bin/sw_vers", "-productVersion"), max_bytes=8)
                process.kill.assert_called_once()
                process.stdout.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
