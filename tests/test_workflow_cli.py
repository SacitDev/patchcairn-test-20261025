"""CLI tests use copied source in fictional repositories under owned engine work."""
from __future__ import annotations

import json
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
WORK = ROOT / "work" / "upgrade_v3" / "engine" / "cli-tests"
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowEngine, PrivacyCapabilityHold
from patchcairn_workflow import human_message
import patchcairn_workflow as workflow_cli


class WorkflowCliHumanMessageTests(unittest.TestCase):
    def test_default_refusal_explains_next_step_without_replacing_json_detail(self):
        result = {"ok": False, "code": "held", "message": "Work is held: fictional technical inode/DACL sentinel", "session_id": "fictional-session", "data": {}}
        before = json.dumps(result, sort_keys=True)
        message = human_message(result)
        self.assertTrue(message.startswith("I could not continue this request"))
        self.assertIn("PatchCairn: status", message)
        self.assertIn("PatchCairn: resolve", message)
        self.assertIn("does not tell us whether it finished or what effects it had", message)
        self.assertNotIn("inode/DACL sentinel", message)
        self.assertEqual(json.dumps(result, sort_keys=True), before)
        private_storage = human_message(result, storage_unavailable=True)
        self.assertTrue(private_storage.startswith("I cannot confirm that this workspace can protect private session records"))
        self.assertNotIn("inode/DACL sentinel", private_storage)
        self.assertEqual(json.dumps(result, sort_keys=True), before)


class WorkflowCliPlatformTests(unittest.TestCase):
    """Mode/OS selection uses a mocked constructor, never a real session."""
    def invoke(self, platform, arguments):
        response = {"schema_version": 3, "ok": True, "code": "created", "message": "Fictional constructor boundary only", "session_id": None, "revision": 0, "data": {}}
        with mock.patch.object(workflow_cli.sys, "platform", platform), \
             mock.patch.object(workflow_cli, "WorkflowEngine") as factory, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            factory.return_value.create_session.return_value = response
            code = workflow_cli.main(arguments)
            return code, output.getvalue(), factory

    def test_real_default_detects_each_native_platform_before_creation(self):
        for native, expected in (("win32", "windows"), ("linux", "linux"), ("darwin", "macos")):
            with self.subTest(native=native):
                code, output, factory = self.invoke(native, ["start", "security_updates", "--mode", "real"])
                self.assertEqual(code, 0)
                self.assertEqual(factory.return_value.create_session.call_args.kwargs["platform"], expected)
                self.assertEqual(factory.return_value.create_session.call_args.kwargs["mode"], "real")

    def test_real_explicit_native_matches_and_foreign_or_unknown_refuses_before_storage(self):
        code, _, factory = self.invoke("win32", ["start", "backup_recovery", "--mode", "real", "--platform", "windows"])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.create_session.call_args.kwargs["platform"], "windows")
        for selected in ("linux", "macos", "unknown"):
            with self.subTest(selected=selected):
                code, output, factory = self.invoke("win32", ["start", "backup_recovery", "--mode", "real", "--platform", selected, "--json"])
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output)["code"], "held")
                factory.assert_not_called()

    def test_unsupported_real_native_and_invalid_mode_do_not_allocate_storage(self):
        code, output, factory = self.invoke("unsupported-fixture-platform", ["start", "storage_cleanup", "--mode", "real", "--json"])
        self.assertEqual(code, 2)
        self.assertIn("unsupported", json.loads(output)["message"])
        factory.assert_not_called()
        with mock.patch.object(workflow_cli, "WorkflowEngine") as factory, \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
            workflow_cli.main(["start", "storage_cleanup", "--mode", "production"])
        self.assertEqual(stopped.exception.code, 2)
        factory.assert_not_called()

    def test_fixture_unknown_and_bare_real_menu_remain_non_collecting(self):
        code, _, factory = self.invoke("win32", ["start", "diagnosis_repair"])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.create_session.call_args.kwargs["platform"], "unknown")
        self.assertEqual(factory.return_value.create_session.call_args.kwargs["mode"], "fixture")
        code, output, factory = self.invoke("unsupported-fixture-platform", ["start", "--mode", "real"])
        self.assertEqual(code, 0)
        self.assertTrue(output.startswith("PatchCairn — Developed by Michael"))
        factory.assert_not_called()


class WorkflowCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage_available, cls.storage_reason = True, ""
        if os.name == "posix":
            probe = WORK / ("privacy-capability-" + uuid.uuid4().hex)
            probe.mkdir(parents=True)
            try:
                WorkflowEngine(probe)
            except PrivacyCapabilityHold as error:
                cls.storage_available, cls.storage_reason = False, str(error)

    def requires_storage(self):
        if not self.storage_available:
            self.skipTest("Actual workspace POSIX private-storage capability unavailable: " + self.storage_reason)

    def setUp(self):
        self.root = WORK / ("fictional-cli-" + uuid.uuid4().hex)
        (self.root / "scripts").mkdir(parents=True)
        names = ["workflow_core.py", "patchcairn_workflow.py"]
        for dependency in ("private_workspace.py", "darwin_privacy.py", "linux_privacy.py"):
            if (ROOT / "scripts" / dependency).is_file():
                names.append(dependency)
        for name in names:
            (self.root / "scripts" / name).write_bytes((ROOT / "scripts" / name).read_bytes())

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-S", "-B", str(self.root / "scripts" / "patchcairn_workflow.py"), *args], cwd=self.root, capture_output=True, text=True, encoding="utf-8", env={"PYTHONIOENCODING": "utf-8"}, timeout=30)

    def test_default_is_human_menu_without_storage_side_effects(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("PatchCairn — Developed by Michael"))
        self.assertFalse((self.root / "work").exists())
        self.assertFalse(list(self.root.rglob("__pycache__")))
        bare = self.run_cli("PatchCairn:", "start")
        self.assertEqual(bare.returncode, 0, bare.stderr)
        self.assertIn("creates no session", bare.stdout)
        self.assertNotIn("security_updates", bare.stdout)
        self.assertFalse((self.root / "work").exists())

    def test_json_is_internal_option_and_default_start_is_assessment(self):
        self.requires_storage()
        prior = self.root / "work" / "workflow-v3"
        prior.mkdir(parents=True)
        sentinel = prior / "fictional-prior-namespace.txt"
        sentinel_bytes = b"Fictional prior namespace; never adopt or migrate."
        sentinel.write_bytes(sentinel_bytes)
        result = self.run_cli("PatchCairn:", "start", "1", "--json", "--scope", "fictional-root")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["data"]["state"]["job"], "security_updates")
        self.assertEqual(data["data"]["state"]["stage"], "scope")
        self.assertFalse(data["data"]["state"]["operations"])
        self.assertIsNone(data["data"]["state"]["scope_authorization"])
        self.assertEqual(data["data"]["state"]["mode"], "fixture")
        self.assertTrue((self.root / "work" / "sessions" / "engine.json").is_file())
        self.assertTrue((self.root / "work" / "sessions" / data["session_id"] / "session.json").is_file())
        self.assertEqual(sentinel.read_bytes(), sentinel_bytes)
        self.assertEqual(list(prior.iterdir()), [sentinel])
        status = self.run_cli("status", "--session", data["session_id"])
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("Security and updates", status.stdout)

    def test_all_control_and_timing_pairs_are_independent(self):
        self.requires_storage()
        for control in ("guided", "automatic"):
            for timing in ("now", "scheduled"):
                result = self.run_cli("start", "backup_recovery", "--control", control, "--timing", timing, "--json")
                self.assertEqual(result.returncode, 0, result.stderr)
                state = json.loads(result.stdout)["data"]["state"]
                self.assertEqual(state["settings"]["control"], control)
                self.assertEqual(state["settings"]["timing"], timing)
                self.assertIsNone(state["schedule"])

    def test_unknown_slash_and_session_paths_have_clear_human_holds(self):
        for args in (("/resume",), ("start", "everything"), ("status", "--session", "../foreign")):
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 2)
            self.assertTrue(result.stdout.strip())
            self.assertNotIn("Traceback", result.stderr)

    def test_resume_command_does_not_treat_words_as_fresh_outcomes(self):
        self.requires_storage()
        result = json.loads(self.run_cli("start", "1", "--json").stdout)
        sid = result["session_id"]
        self.assertEqual(self.run_cli("pause", "--session", sid).returncode, 0)
        resume = json.loads(self.run_cli("resume", "--session", sid, "--json").stdout)
        self.assertEqual(resume["code"], "reconciliation_required")
        status = json.loads(self.run_cli("status", "--session", sid, "--json").stdout)
        self.assertEqual(status["data"]["status"], "paused")

    @unittest.skipUnless(os.name == "posix", "POSIX unsupported-mode capability hold")
    def test_unsupported_private_storage_holds_without_any_private_record(self):
        if self.storage_available:
            self.skipTest("Actual workspace supports the required POSIX privacy modes")
        result = self.run_cli("start", "1", "--json")
        self.assertEqual(result.returncode, 2, result.stderr)
        body = json.loads(result.stdout)
        self.assertFalse(body["ok"])
        self.assertIn(self.storage_reason, body["message"])
        self.assertFalse(list(self.root.rglob("engine.json")))
        self.assertFalse(list(self.root.rglob("session.json")))
        human = self.run_cli("start", "1")
        self.assertEqual(human.returncode, 2, human.stderr)
        self.assertTrue(human.stdout.startswith("I cannot confirm that this workspace can protect private session records"))
        self.assertNotIn("linux-private-foreign-filesystem", human.stdout)
        self.assertIn("what effects it had", human.stdout)


if __name__ == "__main__":
    unittest.main()
