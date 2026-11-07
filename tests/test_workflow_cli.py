"""CLI tests use copied source in fictional repositories under owned engine work."""
from __future__ import annotations

import json
import contextlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
WORK = ROOT / "work" / "test-fixtures" / "engine" / "cli-tests"
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowEngine, PrivacyCapabilityHold, initial_menu
from patchcairn_workflow import human_message
import patchcairn_workflow as workflow_cli
import patchcairn_service as service_cli
from workflow_service import ServiceRefusal
from test_packages import FakeChild, FakeTerminal, fake_route, remove_fixture_roots
from test_service_updates import harness
from work_fixtures import remove_tree


def older_folder_message(folder):
    return ("The folder " + folder + " holds records in an older PatchCairn format, which cannot be read. "
            "PatchCairn never changes or deletes them: keep that folder unchanged, move it aside to keep "
            "its records, and then start a new session.")


def make_marker_older(marker):
    older = json.loads(marker.read_bytes())
    older.update(schema_version=3, backend=f"patchcairn.workflow.python.v{3}")  # today's record layout
    marker.write_bytes(json.dumps(older, sort_keys=True, separators=(",", ":")).encode("ascii"))
    return older


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
        response = {"schema_version": 1, "ok": True, "code": "created", "message": "Fictional constructor boundary only", "session_id": None, "revision": 0, "data": {}}
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
            finally:
                remove_tree(probe)

    def requires_storage(self):
        if not self.storage_available:
            self.skipTest("only on posix: actual workspace POSIX private-storage capability unavailable: " + self.storage_reason)

    def setUp(self):
        self.root = WORK / ("fictional-cli-" + uuid.uuid4().hex)
        (self.root / "scripts").mkdir(parents=True)
        self.addCleanup(remove_tree, self.root)
        # The CLI and the engine's import closure: its L0 records and paths, the restart signals of the package routes, the
        # pure storage-payload and diagnostic validators, and the private-workspace admission with its native helpers.
        names = ["workflow_core.py", "engine_journal.py", "engine_text.py", "engine_plans.py", "engine_operations.py", "engine_restart.py",
                 "engine_updates.py", "engine_recovery.py", "engine_schedule.py", "engine_decisions.py", "patchcairn_workflow.py", "pc_records.py", "pc_paths.py",
                 "package_routes.py", "package_tokens.py", "storage_contract.py", "diagnostic_core.py", "private_workspace.py"]
        for dependency in ("win32_files.py", "darwin_privacy.py", "linux_privacy.py"):
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
        self.assertIn("Showing this menu changes nothing.", bare.stdout)
        self.assertNotIn("security_updates", bare.stdout)
        # "start assessment" names no job, so it shows the menu instead of picking one.
        assessment = self.run_cli("start", "assessment")
        self.assertEqual((assessment.returncode, assessment.stdout), (0, bare.stdout))
        self.assertFalse((self.root / "work").exists())

    def test_cli_menu_is_the_engine_menu_within_320_words(self):
        # The menu the docs check reads from the command line (PatchCairn: start --json) is the engine's menu.
        result = self.run_cli("PatchCairn:", "start", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        menu = json.loads(result.stdout)["message"]
        self.assertEqual(menu, initial_menu())
        self.assertLessEqual(max(len(re.findall(r"[A-Za-z0-9][A-Za-z0-9'’-]*", menu)), len(menu.split())), 320)
        self.assertFalse((self.root / "work").exists())

    def test_menu_reply_number_or_phrase_starts_that_job(self):
        self.requires_storage()
        for args, job in ((("3",), "diagnosis_repair"), (("free", "up", "space"), "storage_cleanup"),
                          (("PatchCairn:", "back", "up", "my", "files"), "backup_recovery")):
            with self.subTest(args=args):
                result = self.run_cli(*args, "--json")
                self.assertEqual(result.returncode, 0, result.stderr)
                state = json.loads(result.stdout)["data"]["state"]
                self.assertEqual((state["job"], state["stage"], state["operations"]), (job, "scope", {}))
                self.assertIsNone(state["scope_authorization"])

    def test_json_is_internal_option_and_default_start_is_assessment(self):
        self.requires_storage()
        prior = self.root / "work" / "workflow-previous"
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

    def test_older_format_records_are_refused_with_the_clear_message(self):
        self.requires_storage()
        sid = json.loads(self.run_cli("start", "1", "--json").stdout)["session_id"]
        marker = self.root / "work" / "sessions" / "engine.json"
        older = make_marker_older(marker)
        message = older_folder_message("work/sessions")
        human = self.run_cli("status", "--session", sid)
        self.assertEqual(human.returncode, 2, human.stderr)
        self.assertEqual(human.stdout.splitlines()[0], message)
        body = json.loads(self.run_cli("status", "--session", sid, "--json").stdout)
        self.assertEqual((body["ok"], body["code"], body["message"]), (False, "older_format", message))
        self.assertEqual(json.loads(marker.read_bytes()), older)

    def test_service_tool_shows_the_same_older_format_message(self):
        self.requires_storage()
        work = "work/cli-older-" + uuid.uuid4().hex[:12]
        engine = WorkflowEngine(work_relative=work)
        self.addCleanup(remove_tree, engine.work)
        sid = engine.create_session(checkpoints=[])["session_id"]
        older = make_marker_older(engine.work / "engine.json")
        with contextlib.redirect_stderr(io.StringIO()) as error, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(service_cli.main(["--session-work", work, "status", sid]), 2)
        self.assertEqual(error.getvalue().strip(), older_folder_message(work))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(json.loads((engine.work / "engine.json").read_bytes()), older)

    def test_resume_command_does_not_treat_words_as_fresh_outcomes(self):
        self.requires_storage()
        result = json.loads(self.run_cli("start", "1", "--json").stdout)
        sid = result["session_id"]
        self.assertEqual(self.run_cli("pause", "--session", sid).returncode, 0)
        resume = json.loads(self.run_cli("resume", "--session", sid, "--json").stdout)
        self.assertEqual(resume["code"], "reconciliation_required")
        status = json.loads(self.run_cli("status", "--session", sid, "--json").stdout)
        self.assertEqual(status["data"]["status"], "paused")

    def test_unsupported_private_storage_holds_without_any_private_record(self):
        # Every platform: the CLI turns a private-storage hold into exit 2 and the plain storage message.
        reason = "Native private storage is unavailable: private-linux-foreign-filesystem"
        with mock.patch.object(workflow_cli, "WorkflowEngine", side_effect=PrivacyCapabilityHold(reason)):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(workflow_cli.main(["start", "1", "--json"]), 2)
            body = json.loads(output.getvalue())
            self.assertFalse(body["ok"])
            self.assertIn(reason, body["message"])
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(workflow_cli.main(["start", "1"]), 2)
            self.assertTrue(output.getvalue().startswith("I cannot confirm that this workspace can protect private session records"))
            self.assertNotIn("private-linux-foreign-filesystem", output.getvalue())
            self.assertIn("what effects it had", output.getvalue())
        if not self.storage_available:
            # A POSIX workspace that really lacks the capability: the copied CLI holds before any private record.
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
            self.assertNotIn("private-linux-foreign-filesystem", human.stdout)
            self.assertIn("what effects it had", human.stdout)


class ServiceRunTextTests(unittest.TestCase):
    """patchcairn_service.py run --ticket over the real run_ticket of the package harness: every shape it returns."""

    @classmethod
    def tearDownClass(cls):
        remove_fixture_roots()

    def run_cli(self, made, ticket, *options, **keywords):
        service = mock.Mock()
        service.run_ticket.side_effect = lambda ticket_id: made.run(ticket_id, **keywords)
        with mock.patch.object(service_cli, "WorkflowEngine"), mock.patch.object(service_cli, "WorkflowService", return_value=service), \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as error:
            code = service_cli.main([*options, "run", "--ticket", ticket])
        return code, output.getvalue(), error.getvalue()

    def test_a_terminal_hold_prints_the_command_and_exits_2(self):
        made = harness()
        issued = made.issue()
        code, output, _ = self.run_cli(made, issued["ticket_id"], terminal=FakeTerminal(tty=False))
        self.assertEqual(code, 2)
        self.assertIn("This step did not start, and nothing changed (package-terminal-needed).", output)
        self.assertIn(issued["command"], output.splitlines())
        for false_success in ("handled", "None", "Updated"):
            self.assertNotIn(false_success, output)

    def test_a_restart_wait_is_not_a_success(self):
        made = harness(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"))
        code, output, _ = self.run_cli(made, made.issue()["ticket_id"])
        self.assertEqual(code, 0)
        self.assertTrue(output.startswith("This update needs a restart to finish."), output)
        self.assertIn("PatchCairn: resume", output)
        self.assertNotIn("None", output)

    def test_a_paused_session_starts_nothing_and_says_so(self):
        made = harness()
        ticket = made.issue()["ticket_id"]
        made.state["status"] = "paused"
        child = FakeChild()
        code, output, _ = self.run_cli(made, ticket, child=child)
        self.assertEqual(child.calls, [])
        self.assertEqual(output.strip(), "This step did not start, and nothing changed. Go back to the chat and say PatchCairn: status.")

    def test_a_finished_step_prints_its_result(self):
        made = harness()
        code, output, _ = self.run_cli(made, made.issue()["ticket_id"])
        self.assertEqual((code, output.strip()), (0, "Updated; the new version was checked. Go back to the chat and say done."))

    def test_json_keeps_the_result_and_the_exit_code(self):
        made = harness()
        code, output, _ = self.run_cli(made, made.issue()["ticket_id"], "--json", terminal=FakeTerminal(tty=False))
        self.assertEqual((code, json.loads(output)["hold"]), (2, "package-terminal-needed"))

    def test_a_refusal_prints_its_plain_reason_and_its_code(self):
        made = harness()
        ticket = made.issue()["ticket_id"]
        made.run(ticket)
        made.operation["outcome"] = None
        code, output, error = self.run_cli(made, ticket)
        self.assertEqual((code, output), (2, ""))
        self.assertEqual(error.strip(), "PatchCairn stopped here: This ticket was already used; inspect and reconcile the operation (package-ticket-used). "
                                        "Go back to the chat and say PatchCairn: status.")

    def failing(self, failure):
        service = mock.Mock()
        service.run_ticket.side_effect = failure
        with mock.patch.object(service_cli, "WorkflowEngine"), mock.patch.object(service_cli, "WorkflowService", return_value=service), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(service_cli.main(["run", "--ticket", "ticket-fixture"]), 2)
        return error.getvalue().strip()

    def test_a_busy_service_names_its_cause_without_recovery_steps(self):
        text = self.failing(ServiceRefusal("Service is active or interrupted; inspect before another action", code="service-busy-or-interrupted"))
        self.assertEqual(text, "PatchCairn stopped here: Service is active or interrupted; inspect before another action (service-busy-or-interrupted). "
                               "Go back to the chat and say PatchCairn: status.")
        self.assertNotIn("lock", text)

    def test_a_refusal_with_no_code_of_its_own_prints_only_the_reason(self):
        self.assertEqual(self.failing(ServiceRefusal("The ticket does not match its begun operation.")),
                         "PatchCairn stopped here: The ticket does not match its begun operation. Go back to the chat and say PatchCairn: status.")

    def test_anything_else_says_not_to_run_it_again(self):
        self.assertEqual(self.failing(OSError("fictional technical detail")),
                         "PatchCairn could not finish this step. Do not run the command again. Go back to the chat and say PatchCairn: status.")


class ServiceInspectTests(unittest.TestCase):
    """inspect-operation names the check after a restart; ticket_command is a fake until the service gains it."""
    COMMAND = "fictional-python -I -S -B patchcairn_service.py run --ticket ticket-1"

    def inspected(self, operation, *options):
        service = mock.Mock()
        service.inspect_operation.return_value = {"operation": operation}
        service.ticket_command.return_value = self.COMMAND
        with mock.patch.object(service_cli, "WorkflowEngine"), mock.patch.object(service_cli, "WorkflowService", return_value=service), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(service_cli.main([*options, "inspect-operation", "session-fixture", "operation-fixture"]), 0)
        return output.getvalue(), service

    def test_a_step_waiting_for_its_restart_gets_the_command(self):
        output, service = self.inspected({"outcome": None, "restart_pending": {"signal": "required", "source": "exit_code"}})
        self.assertIn("To check the result after the restart, run: " + self.COMMAND, output.splitlines())
        service.ticket_command.assert_called_once_with("session-fixture", operation_id="operation-fixture")

    def test_a_check_cut_short_after_the_boot_gets_it_too(self):
        output, _ = self.inspected({"outcome": None, "restart_pending": {"signal": "required", "source": "exit_code"},
                                    "restart_verification": {"boot_observed": True}})
        self.assertIn(self.COMMAND, output)

    def test_json_carries_the_command(self):
        output, _ = self.inspected({"outcome": None, "restart_pending": {"signal": "required", "source": "exit_code"}}, "--json")
        self.assertEqual(json.loads(output)["check_command"], self.COMMAND)

    def test_no_restart_or_a_closed_step_or_no_ticket_prints_no_command(self):
        for operation in ({"outcome": None}, {"outcome": "succeeded", "restart_pending": {"signal": "required", "source": "exit_code"}}):
            with self.subTest(operation=operation):
                output, service = self.inspected(operation)
                self.assertNotIn(self.COMMAND, output)
                service.ticket_command.assert_not_called()
        service = mock.Mock()
        service.inspect_operation.return_value = {"operation": {"outcome": None, "restart_pending": {"signal": "required", "source": "exit_code"}}}
        service.ticket_command.return_value = None
        with mock.patch.object(service_cli, "WorkflowEngine"), mock.patch.object(service_cli, "WorkflowService", return_value=service), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            service_cli.main(["inspect-operation", "session-fixture", "operation-fixture"])
        self.assertNotIn("To check the result", output.getvalue())


class ServiceListingTests(unittest.TestCase):
    def shown(self, *arguments, service=None):
        with mock.patch.object(service_cli, "WorkflowEngine"), mock.patch.object(service_cli, "WorkflowService", return_value=service), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(service_cli.main(list(arguments)), 0)
        return output.getvalue()

    def test_retention_uses_plain_names_and_sizes(self):
        service = mock.Mock()
        service.retention_rows.return_value = [{"name": "r", "kind": "quarantine", "session_id": "s", "location": "fictional-location", "bytes": 2048,
                                                "created_utc": "2026-10-26T12:00:00Z", "volume_identity": None, "originals_removed": None}]
        output = self.shown("retention", service=service)
        self.assertIn('Files set aside: "fictional-location" (about 2.0 KB, 2,048 bytes, kept since 2026-10-26T12:00:00Z)', output)
        self.assertNotIn("quarantine", output)

    def test_report_says_how_to_open_it(self):
        service = mock.Mock()
        service.session_report.return_value = ROOT / "work" / "fictional-report.html"
        output = self.shown("report", "session-fixture", service=service)
        self.assertIn("Your report is saved at ", output)
        self.assertIn("Open it in a web browser. It is a copy for reading, not evidence: anyone who can edit the file can change it, and PatchCairn never "
                      "reads it back.", output)

    def test_catalog_says_which_repairs_exist(self):
        output = self.shown("catalog")
        self.assertIn("Repairs run the same way: an app update, a same-version reinstall (Mac, Linux) or finishing interrupted package setup (Debian, Ubuntu). "
                      "PatchCairn does not repair Windows itself.", output)
        self.assertNotIn("stays held", output)


class WorkflowCliOutputTests(unittest.TestCase):
    """patchcairn_workflow.py's human output over a fake engine."""

    def run_main(self, *arguments, response=None, dispatch=None):
        with mock.patch.object(workflow_cli, "WorkflowEngine") as factory, contextlib.redirect_stdout(io.StringIO()) as output:
            if response is not None:
                factory.return_value.dispatch.return_value = response
            if dispatch is not None:
                factory.return_value.dispatch.side_effect = dispatch
            code = workflow_cli.main(list(arguments))
        return code, output.getvalue(), factory

    def test_an_operation_id_reaches_the_assistant_in_human_output(self):
        response = {"schema_version": 1, "ok": True, "code": "restart_check_required", "message": "Fictional check", "session_id": "session-fixture",
                    "revision": 3, "data": {"operation_id": "operation-fixture"}}
        code, output, _ = self.run_main("resume", "--session", "session-fixture", response=response)
        self.assertEqual(code, 0)
        self.assertEqual(output.splitlines(), ["Fictional check", "", "Session: session-fixture", "Operation: operation-fixture"])

    def test_no_session_says_no_job_is_open_and_touches_no_storage(self):
        for command in ("PatchCairn: resume", "settings", "status"):
            with self.subTest(command=command):
                code, output, factory = self.run_main(command)
                self.assertEqual((code, output.strip()), (2, "No job is open. PatchCairn: start shows the menu."))
                factory.assert_not_called()

    def test_a_refusal_never_tells_the_assistant_to_ask_the_coordinator(self):
        result = {"ok": False, "code": "held", "message": "Work is held: fictional", "session_id": None, "data": {}}
        for message in (human_message(result), human_message(result, storage_unavailable=True)):
            self.assertNotIn("coordinator", message)
            self.assertIn("Nothing new was started by this request.", message)
            self.assertIn("PatchCairn: start shows the jobs.", message)
        self.assertIn("PatchCairn stops here, and nothing was written.", human_message(result, storage_unavailable=True))

    def test_in_session_parsing_reaches_the_cli(self):
        code, output, factory = self.run_main("done", "thanks", "--session", "session-fixture")
        self.assertEqual(code, 2)
        self.assertIn("If it was your reply to a decision", output)


if __name__ == "__main__":
    unittest.main()
