"""Selected synthetic work copies only. No host inventory, update or repair.

Assessment family (scripts/service_diagnostics.py): the diagnostic action and its completion.
"""
from __future__ import annotations
import copy
from contextlib import nullcontext
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowRefusal
from clock_helpers import utc_now
from workflow_service import WorkflowService, ServiceRefusal
from diagnostic_core import DiagnosticRefusal
from test_service_state import ServiceFixtures, SessionFixtures, PROSE


class WorkflowServiceTests(SessionFixtures):
    def test_diagnostic_fixed_fixture_recipe_no_native_collection_and_mode_binding(self):
        sid = self.session(job="diagnosis_repair", platform="macos")
        action = self.service.prepare_diagnostic_action(sid, action_id="read-version", recipe_id="macos.os_version", symptom="Fictional error E42", diagnostic_scope=["os_metadata"], **PROSE)
        sha = self.approve(action, sid=sid)
        runner = mock.Mock(return_value=b"15.1\n")
        with mock.patch("diagnostic_posix.subprocess.Popen") as native:
            result = self.execute(action, sha, sid=sid, diagnostic_fixture_runner=runner)
            native.assert_not_called()
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(result["receipt"]["record"]["mode"], "fixture")
        self.assertEqual(result["receipt"]["record"]["facts"], {"product_version": "15.1"})
        other = self.session(job="diagnosis_repair", platform="linux")
        with self.assertRaises(DiagnosticRefusal):
            self.service.prepare_diagnostic_action(other, action_id="foreign-os", recipe_id="macos.os_version", symptom="E42", diagnostic_scope=["os_metadata"], **PROSE)

    def test_windows_diagnostic_handoff_callback_requires_observation_and_exact_mode(self):
        sid = self.session(job="diagnosis_repair", platform="windows")
        action = self.service.prepare_diagnostic_action(sid, action_id="windows-version", recipe_id="windows.os_version", symptom="Fictional error E42", diagnostic_scope=[], **PROSE)
        handoff = self.execute(action, self.approve(action, sid=sid), sid=sid)
        request = handoff["request"]
        observed = {key: request[key] for key in ("schema", "schema_version", "request_id", "platform", "recipe_id", "mode")}
        observed.update(kind="adapter_result", status="observed", observed_utc=utc_now(), facts={"version": "10.0.99999", "build": "99999", "architecture": "x64"},
                        limitations=["Fictional adapter callback; no host collector ran."], provenance=["https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem"])
        with self.assertRaises(ServiceRefusal):
            self.service.complete_diagnostic(sid, operation_id=handoff["operation_id"], adapter_result=observed)
        wrong = copy.deepcopy(observed); wrong["mode"] = "real"
        with self.assertRaises(DiagnosticRefusal):
            self.service.complete_diagnostic(sid, operation_id=handoff["operation_id"], adapter_result=wrong, coordinator_observed=True)
        result = self.service.complete_diagnostic(sid, operation_id=handoff["operation_id"], adapter_result=observed, coordinator_observed=True)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(result["receipt"]["record"]["mode"], "fixture")


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


if __name__ == "__main__":
    unittest.main()
