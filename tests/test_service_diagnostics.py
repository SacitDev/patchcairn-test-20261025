"""Selected synthetic work copies only. No host inventory, update or repair.

Assessment family (scripts/service_diagnostics.py): the diagnostic action, its effect and the inventory collection.
Host processes and host facts are replaced by fakes; no test starts PowerShell or a collector's query.
"""
from __future__ import annotations
from contextlib import nullcontext
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowRefusal, encoded
import diagnostic_core
import diagnostic_windows
import pc_records
import readonly_runner
import service_state
from clock_helpers import utc_now
from workflow_service import WorkflowService, ServiceRefusal, native_platform
from diagnostic_core import DiagnosticRefusal
from test_service_state import ServiceFixtures, SessionFixtures, PROSE
from test_diagnostic_windows import FakeLauncher, FakeProbe as FakeWindowsProbe, POLICY_REFUSAL


def collector_result(platform=None, collection_mode="real", count=2):
    """A fictional collector result of the collectors' own shape."""
    return {"platform": platform or native_platform(), "collection_mode": collection_mode, "observed_utc": pc_records.utc_now(),
            "observations": [{"kind": "package", "name": "fictional-package-" + str(n), "version": "1.0"} for n in range(count)],
            "coverage": [], "errors": [], "limits": ["Fictional result; nothing was collected."]}


class WorkflowServiceTests(SessionFixtures):
    def real_session(self, *, platform=None, authorized=True):
        sid = self.engine.create_session(job="diagnosis_repair", platform=platform or native_platform(), mode="real", scope=self.scope,
                                         checkpoints=[])["session_id"]
        if authorized:
            self.engine.authorize_scope(sid, owner_quote="Read only this fictional computer's selected metadata.",
                                        owner_message_id="fictional-real-scope-" + uuid.uuid4().hex)
        return sid

    def inventory_rows(self, sid):
        return {key: row for key, row in self.state(sid)["evidence"].items() if row["kind"] == "inventory"}

    def test_diagnostic_fixed_fixture_recipe_no_native_collection_and_mode_binding(self):
        sid = self.session(job="diagnosis_repair", platform="macos")
        action = self.service.prepare_diagnostic_action(sid, action_id="read-version", recipe_id="macos.os_version", symptom="Fictional error E42", diagnostic_scope=["os_metadata"], **PROSE)
        sha = self.approve(action, sid=sid)
        runner = mock.Mock(return_value=b"15.1\n")
        with mock.patch.object(readonly_runner, "_launch", side_effect=AssertionError("No host process in a fixture session")):
            result = self.execute(action, sha, sid=sid, diagnostic_fixture_runner=runner)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(result["receipt"]["record"]["mode"], "fixture")
        self.assertEqual(result["receipt"]["record"]["facts"], {"product_version": "15.1"})
        other = self.session(job="diagnosis_repair", platform="linux")
        with self.assertRaises(DiagnosticRefusal):
            self.service.prepare_diagnostic_action(other, action_id="foreign-os", recipe_id="macos.os_version", symptom="E42", diagnostic_scope=["os_metadata"], **PROSE)

    def windows_action(self, sid, recipe_id="windows.os_version", action_id="windows-version"):
        return self.service.prepare_diagnostic_action(sid, action_id=action_id, recipe_id=recipe_id, symptom="Fictional error E42",
                                                      diagnostic_scope=[], **PROSE)

    def test_windows_fixture_session_checks_a_fictional_result_and_starts_no_process(self):
        sid = self.session(job="diagnosis_repair", platform="windows")
        action = self.windows_action(sid)
        sha = self.approve(action, sid=sid)
        request = self.service.engine.action_binding(self.state(sid), action)["request"]
        observed = {key: request[key] for key in ("schema", "schema_version", "request_id", "platform", "recipe_id", "mode")}
        observed.update(kind="adapter_result", status="observed", observed_utc=utc_now(), facts={"version": "10.0.99999", "build": "99999", "architecture": "x64"},
                        limitations=["Fictional adapter result; no host collector ran."], provenance=list(diagnostic_core.TABLE["windows.os_version"].sources))
        with mock.patch.object(diagnostic_windows, "_launch", side_effect=AssertionError("No PowerShell in a fixture session")), \
                mock.patch.object(diagnostic_windows, "WindowsProbe", side_effect=AssertionError("No host facts in a fixture session")):
            result = self.execute(action, sha, sid=sid, diagnostic_fixture_result=observed)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual((result["receipt"]["record"]["mode"], result["receipt"]["record"]["facts"]), ("fixture", observed["facts"]))
        operation = self.service._operation_dir(sid, result["operation_id"])
        self.assertFalse((operation / "handoff.json").exists())
        self.assertFalse((operation / "helper-input.json").exists())
        # The operation finished in its effect; no later callback can replace its result.
        with self.assertRaisesRegex(ServiceRefusal, "Only an active exact diagnostic handoff"):
            self.service.complete_diagnostic(sid, operation_id=result["operation_id"], adapter_result=observed, coordinator_observed=True)

    def test_windows_fixture_session_without_a_result_holds_and_takes_no_runner(self):
        sid = self.session(job="diagnosis_repair", platform="windows")
        for recipe_id in ("windows.update_context", "windows.system_capacity", "windows.dism_check_health"):
            action = self.windows_action(sid, recipe_id, action_id="held-" + recipe_id.replace("windows.", "").replace("_", "-"))
            sha = self.approve(action, sid=sid)
            with mock.patch.object(diagnostic_windows, "_launch", side_effect=AssertionError("No PowerShell in a fixture session")):
                with self.assertRaises(ServiceRefusal):  # refused before the operation begins
                    self.execute(action, sha, sid=sid, diagnostic_fixture_runner=mock.Mock(return_value=b""))
                result = self.execute(action, sha, sid=sid)
            with self.subTest(recipe=recipe_id):
                self.assertEqual((result["outcome"], result["receipt"]["record"]["status"]), ("failed", "held"))
                limitations = " ".join(result["receipt"]["record"]["limitations"])
                self.assertIn("administrator prompt" if recipe_id == "windows.dism_check_health" else "Fixture requires an explicit fictional result", limitations)
            sid = self.session(job="diagnosis_repair", platform="windows")

    def real_windows_helper(self, launcher):
        """(session id, result) of an approved real-session update-context action on a fictional Windows computer whose
        host facts and PowerShell start are fakes."""
        with mock.patch.object(service_state, "native_platform", return_value="windows"), \
                mock.patch.object(diagnostic_windows, "WindowsProbe", return_value=FakeWindowsProbe()):
            sid = self.real_session(platform="windows")
            # The service store below work/ refuses real requests; only this fictional engine's store is opened for them.
            with mock.patch.object(self.service.diagnostics, "fixture_root", False):
                action = self.windows_action(sid, "windows.update_context", action_id="windows-updates")
            sha = self.approve(action, sid=sid)
            with mock.patch.object(diagnostic_windows, "_launch", launcher):
                return sid, self.execute(action, sha, sid=sid)

    def test_real_session_starts_the_helper_with_its_fixed_start_and_records_the_result(self):
        launcher = FakeLauncher()
        sid, result = self.real_windows_helper(launcher)
        self.assertEqual(result["outcome"], "succeeded")
        record = result["receipt"]["record"]
        self.assertEqual((record["mode"], record["status"], record["facts"]), ("real", "observed", {"updates": [{"kb_id": "KB1234567", "installed_utc": None}]}))
        call, = launcher.calls
        self.assertEqual(call.argv[1:6], ("-NoProfile", "-NonInteractive", "-File", str(diagnostic_windows.HELPER), "-RequestPath"))
        self.assertEqual(call.argv[-1], "-CoordinatorAuthorized")
        self.assertEqual(set(call.env), {"SystemRoot", "WINDIR", "PSModulePath"})
        self.assertEqual(Path(call.argv[6]).parent, self.service._operation_dir(sid, result["operation_id"]))
        self.assertEqual((call.request["mode"], call.request["request_id"]), ("real", record["request_id"]))

    def test_real_session_policy_refusal_is_the_typed_script_policy_hold(self):
        _, result = self.real_windows_helper(FakeLauncher(1, b"", POLICY_REFUSAL))
        record = result["receipt"]["record"]
        self.assertEqual((result["outcome"], record["status"], record["hold"], record["facts"]), ("failed", "held", "windows-script-policy", {}))
        self.assertIn(diagnostic_windows.GUIDANCE["windows-script-policy"], record["limitations"])
        self.assertNotIn("FullyQualifiedErrorId", json.dumps(record))
        _, started = self.real_windows_helper(FakeLauncher(0xFFFF0000, b"", "Loading managed Windows PowerShell failed.".encode("utf-16-le")))
        self.assertEqual(started["receipt"]["record"]["hold"], "windows-helper-start")

    def test_fixture_inventory_refused_in_real_session(self):
        sid = self.real_session()
        before = self.state(sid)["evidence"]
        for result in (collector_result(collection_mode="fixture"), {**collector_result(), "collection_mode": None},
                       {key: value for key, value in collector_result().items() if key != "collection_mode"},
                       collector_result(platform="macos" if native_platform() != "macos" else "linux")):
            collector = mock.Mock(return_value=result)
            with self.subTest(mode=result.get("collection_mode"), platform=result["platform"]):
                with self.assertRaises(pc_records.Refusal) as caught:
                    self.service.collect_inventory(sid, collector=collector)
                self.assertEqual(caught.exception.code, "service-refusal")  # the service's own check, before the engine's
                collector.assert_called_once_with()
        self.assertEqual(self.state(sid)["evidence"], before)
        # A fixture session never collects this computer's inventory: refused before the collector runs.
        collector = mock.Mock(return_value=collector_result(collection_mode="fixture"))
        with self.assertRaises(ServiceRefusal):
            self.service.collect_inventory(self.sid, collector=collector)
        collector.assert_not_called()

    def test_collect_inventory_collects_only_after_private_storage_and_the_scope_decision(self):
        events = []
        real_admit = service_state.ensure_private_directory

        def admit(path, *args, **kwargs):
            events.append(("admit", Path(path)))
            return real_admit(path, *args, **kwargs)

        def collect():
            state = self.state(sid)
            events.append(("collect", bool(state["scope_authorization"]), self.service.work.is_dir()))
            return collector_result()

        sid = self.real_session(authorized=False)
        with mock.patch.object(service_state, "ensure_private_directory", side_effect=admit):
            with self.assertRaises(ServiceRefusal):
                self.service.collect_inventory(sid, collector=collect)
            self.assertNotIn("collect", [event[0] for event in events])
            self.engine.authorize_scope(sid, owner_quote="Read only this fictional computer's selected metadata.",
                                        owner_message_id="fictional-real-scope-" + uuid.uuid4().hex)
            events.clear()
            returned = self.service.collect_inventory(sid, collector=collect)
        self.assertEqual(events, [("admit", self.service.work), ("collect", True, True)])
        rows = self.inventory_rows(sid)
        self.assertEqual(len(rows), 1)
        row, = rows.values()
        self.assertEqual(row["sha256"], pc_records.digest(returned))
        self.assertEqual(row["facts"], {"item_count": 2})
        self.assertEqual(row["observed_utc"], returned["observed_utc"])
        self.assertEqual(pc_records.decode_strict((self.engine.work / sid / row["path"]).read_bytes()), returned)

    def test_collect_inventory_uses_the_platform_collector_and_never_takes_handed_bytes(self):
        import inspect
        self.assertEqual(list(inspect.signature(WorkflowService.collect_inventory).parameters), ["self", "session_id", "collector"])
        result = collector_result(platform="linux")
        collect_linux = mock.Mock(return_value=result)
        with mock.patch.object(service_state, "native_platform", return_value="linux"), \
                mock.patch.dict("service_diagnostics.COLLECTORS", {"linux": collect_linux}):
            sid = self.real_session(platform="linux")
            self.assertEqual(self.service.collect_inventory(sid), json.loads(encoded(result)))
        collect_linux.assert_called_once_with()
        with mock.patch.object(service_state, "native_platform", return_value="windows"):
            sid = self.real_session(platform="windows")
            with self.assertRaises(ServiceRefusal):  # Windows software is listed by winget discovery, not a collector
                self.service.collect_inventory(sid)
        for value in (None, [], "fictional", {"platform": native_platform(), "collection_mode": "real", "observations": {}}):
            with self.subTest(value=value), self.assertRaises(ServiceRefusal):
                self.service.collect_inventory(self.real_session(), collector=mock.Mock(return_value=value))


class ServicePrivacyTests(ServiceFixtures):
    def test_scheduled_collection_requires_current_activation_before_request_or_recipe(self):
        service = object.__new__(WorkflowService)
        state = {"status": "awaiting_user", "scope_authorization": {"fictional": True}}
        service.work = self.fixture_root()
        service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=state),
            require_schedule_activation=mock.Mock(side_effect=WorkflowRefusal("Current schedule is not due and activated")))
        service._lock = mock.Mock(side_effect=nullcontext)
        service.diagnostics = types.SimpleNamespace(create_request=mock.Mock())
        with mock.patch("service_state.ensure_private_directory"), self.assertRaises(WorkflowRefusal):
            service.prepare_diagnostic_action("session-fixture", action_id="scheduled-diagnostic", recipe_id="macos.os_version",
                symptom="Fictional symptom", diagnostic_scope=["os_metadata"], **PROSE)
        service.engine.require_schedule_activation.assert_called_once_with(state)
        service.diagnostics.create_request.assert_not_called()
        collector = mock.Mock()
        with mock.patch("service_state.ensure_private_directory"), self.assertRaises(WorkflowRefusal):
            service.collect_inventory("session-fixture", collector=collector)
        collector.assert_not_called()


if __name__ == "__main__":
    unittest.main()
