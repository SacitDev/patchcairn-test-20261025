"""Selected synthetic work copies only. No host inventory, update or repair.

Reconciliation (scripts/service_reconcile.py): the storage outcome check.
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
from workflow_core import digest, encoded
from clock_helpers import utc_now
from workflow_service import WorkflowService, native_platform
from private_workspace import PrivateWorkspaceError
from test_service_state import ServiceFixtures


class ServicePrivacyTests(ServiceFixtures):
    def test_reconciliation_admits_native_outcome_privacy_before_content_read(self):
        root = self.fixture_root()
        for blocked_kind in ("native", "probe"):
            for previous_outcome in (None, "unknown"):
                for refusal in (PrivateWorkspaceError("fixture-file-private-hold"), FileNotFoundError()):
                    with self.subTest(blocked_kind=blocked_kind, previous_outcome=previous_outcome, refusal=type(refusal).__name__):
                        service = object.__new__(WorkflowService)
                        state = {"mode": "fixture", "engine_id": "engine-fixture", "platform": native_platform(),
                                 "session_id": "session-fixture", "settings_revision": 0,
                                 "settings": {"scope": {"roots": [str(root / "original-source")], "purpose": "Fictional original scope"}}}
                        service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=state))
                        service.work = root / "service"
                        operation = {"operation_id": "operation-fixture", "outcome": previous_outcome,
                                     "action_id": "action-fixture", "plan_sha256": "c" * 64, "settings_revision": 0,
                                     "started_utc": utc_now(), "adapter_id": "storage.backup_create", "mutating": True}
                        state["operations"] = {operation["operation_id"]: operation}
                        payload = {"output_root": str(root / "output"), "protected_roots": [],
                                   "operation": "storage.backup_create", "storage_plan_sha256": "a" * 64,
                                   "storage_plan": {"fictional": True}}
                        receipt = {"fictional_native_receipt": True}
                        native_path = root / "output" / ("outcome-backup-" + "a" * 64 + ".json")
                        origin_path = service.work / ("origin-" + "a" * 64 + ".json")
                        content = {native_path: encoded(receipt), origin_path: encoded({
                            "schema": "patchcairn.service", "schema_version": 1, "kind": "native_origin",
                            "operation_id": operation["operation_id"], **state})}
                        blocked_path = native_path
                        if blocked_kind == "probe":
                            payload["restore_probe_destination"] = str(root / "output" / "probe")
                            probe = {"destination": payload["restore_probe_destination"], "receipt": receipt}
                            content[root / "operation" / "restore-probe-plan.json"] = encoded(probe)
                            blocked_path = root / "output" / ("outcome-restore-" + digest(probe) + ".json")
                        service.inspect_operation = mock.Mock(return_value={"operation": operation,
                            "intent": {"payload": payload, "action": {"adapter_id": payload["operation"]},
                                "operation": copy.deepcopy(operation), "scope": state["settings"]["scope"],
                                **{key: state[key] for key in ("engine_id", "mode", "platform", "session_id", "settings_revision")}}})
                        service._lock = mock.Mock(side_effect=nullcontext)
                        service._operation_dir = mock.Mock(return_value=root / "operation")
                        service._finish = mock.Mock(side_effect=lambda state, operation, **result: result)
                        service._register_recovery = mock.Mock()
                        def admit(path):
                            if path == blocked_path:
                                raise refusal
                        with mock.patch("service_reconcile.StorageService") as storage, mock.patch("service_state.ensure_private_file", side_effect=admit) as admission, mock.patch("service_state.read_record_bytes", side_effect=lambda path, *args: content[path]) as reader:
                            result = service.reconcile_operation("session-fixture", operation_id=operation["operation_id"])
                        admission.assert_any_call(blocked_path)
                        self.assertNotIn(blocked_path, [call.args[0] for call in reader.call_args_list])
                        self.assertEqual(result["outcome"], "unknown")
                        if previous_outcome is None:
                            self.assertEqual(service._finish.call_args.kwargs["outcome"], "unknown")
                            self.assertFalse(service._finish.call_args.kwargs["receipt"]["native_outcome_verified"])
                        else:
                            service._finish.assert_not_called()
                            self.assertTrue(result["held"])
                            self.assertFalse(result["automatic_retry"])
                        self.assertEqual(storage.return_value.verify_outcome.call_count, 1 if blocked_kind == "probe" else 0)
                        service._register_recovery.assert_not_called()


if __name__ == "__main__":
    unittest.main()
