"""Selected synthetic work copies only. No host inventory, update or repair.

Cleanup family (scripts/service_cleanup.py): quarantine reservations and the backed purge.
"""
from __future__ import annotations
import copy
from contextlib import nullcontext
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowRefusal, digest
from workflow_service import WorkflowService, ServiceRefusal, native_platform
from storage_ops import StorageService, StorageRefusal
from private_workspace import PrivateWorkspaceError, ensure_private_directory
from test_service_state import ServiceFixtures, SessionFixtures, PROSE, PRIVATE_CAPABILITY_HOLDS


class WorkflowServiceTests(SessionFixtures):
    def test_purge_requires_separate_typed_exact_loss_ack_and_preserves_recovery(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses the native no-overwrite quarantine prerequisite; no fallback")
        receipt, backup, restore = self.make_recovery_and_quarantine()
        sid = self.session(job="storage_cleanup")
        recovery = self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)
        plan = self.storage().plan_purge(receipt=receipt)
        action = self.service.prepare_storage_action(sid, action_id="purge-selected", adapter_id="storage.purge", storage_plan=plan, output_root=str(self.output), recovery_evidence_ids=[recovery["evidence_id"]], **PROSE)
        sha = self.approve(action, sid=sid, purge_choice=True)
        with self.assertRaises(WorkflowRefusal):
            self.execute(action, sha, sid=sid)
        self.assertEqual(self.state(sid)["operations"], {})
        self.assertTrue((self.output / "quarantine" / "000001").exists())
        self.engine.record_irreversible_ack(sid, plan_sha256=sha, action_ids=[action["action_id"]], acknowledge_irreversible_loss=True,
                    owner_quote="I acknowledge irreversible loss for this exact synthetic purge.", owner_message_id="separate-purge-loss")
        result = self.execute(action, sha, sid=sid)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertFalse((self.output / "quarantine" / "000001").exists())
        self.assertTrue(Path(backup["archive"]).exists())
        self.assertTrue((Path(restore["destination"]) / "r001" / "example.txt").exists())


class ServicePrivacyTests(ServiceFixtures):
    def test_purge_original_recovery_and_exact_engine_binding_precede_ticket(self):
        root = self.fixture_root()
        for receipt in ({"recovery_required": False}, {"recovery_required": True},
                        {"recovery_required": True, "recovery_backup": {"unrelated": True}}):
            with self.subTest(receipt=receipt), self.assertRaises(ServiceRefusal):
                WorkflowService._purge_original_recovery({"operation": "storage.purge", "storage_plan": {"receipt": receipt}})
        service = object.__new__(WorkflowService)
        state = {"status": "active", "stage": "apply", "mode": "fixture", "settings": {"scope": {"roots": []}}}
        service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=state), pending_items=mock.Mock(return_value=False),
            verify_recovery=mock.Mock(side_effect=WorkflowRefusal("Wrong original recovery binding")), begin_operation=mock.Mock())
        service._lock = mock.Mock(side_effect=nullcontext)
        service._state = mock.Mock(return_value=state)
        service.protected_roots = mock.Mock(return_value=[])
        service._owned = mock.Mock(side_effect=lambda value, **kwargs: Path(value))
        unbacked = {"kind": "purge", "receipt": {"recovery_required": False}}
        with mock.patch("service_execute.StorageService") as lower:
            with self.assertRaises(ServiceRefusal):
                WorkflowService._storage(service, state, {"operation": "storage.purge", "mode": "fixture",
                    "output_root": str(root / "output"), "protected_roots": [], "storage_plan": unbacked,
                    "storage_plan_sha256": digest(unbacked)})
            lower.assert_not_called()
        service._storage = mock.Mock()
        action = {"action_id": "purge-fixture", "adapter_id": "storage.purge", "recovery_evidence_ids": ["unrelated-backup"]}
        plan = {"kind": "purge", "receipt": {"recovery_required": True, "recovery_backup": {}, "recovery_verification": {}}}
        service._action = mock.Mock(return_value=action)
        with self.assertRaises(WorkflowRefusal):
            service.prepare_storage_action("session-fixture", action_id=action["action_id"], adapter_id=action["adapter_id"],
                storage_plan=plan, output_root=str(root / "output"), recovery_evidence_ids=action["recovery_evidence_ids"], **PROSE)
        service.engine.verify_recovery.assert_called_once_with(state, action["recovery_evidence_ids"], action=action)
        service.engine.verify_recovery.reset_mock()
        service._binding = mock.Mock(return_value=(action, {"operation": action["adapter_id"], "storage_plan": plan, "storage_plan_sha256": digest(plan)}))
        with self.assertRaises(WorkflowRefusal):
            service.execute_action("session-fixture", action_id=action["action_id"], plan_sha256="a" * 64, precondition_evidence_ids=[])
        service.engine.verify_recovery.assert_called_once_with(state, action["recovery_evidence_ids"], action=action)
        service.engine.begin_operation.assert_not_called()

    def test_reserved_quarantine_blocks_other_sessions_and_allows_only_exact_receipt_mapping(self):
        root = self.fixture_root()
        output, source, other_output = root / "work" / "reserved", root / "work" / "source", root / "work" / "other-output"
        original = {"kind": "quarantine", "inventory": {"roots": [{"path": str(source)}]},
                    "files": [{"sha256": "b" * 64}], "quarantine_relative": "quarantine",
                    "quarantine_destination": str(output / "quarantine"), "recovery_required": False,
                    "recovery_backup": None, "recovery_verification": None}
        mapping = WorkflowService._quarantine_mapping(original)
        binding = {"output_root": str(output), "mode": "fixture", "platform": native_platform(),
                   "native_plan_sha256": digest(original), "original_plan": original, "quarantine_mapping": mapping}
        service = object.__new__(WorkflowService)
        service.root = root
        service._owned = mock.Mock(side_effect=lambda value, **kwargs: Path(value))
        service.protected_roots = mock.Mock(return_value=[str(output)])
        service._retention = mock.Mock(return_value=[{"quarantine_binding": binding}])
        state = {"mode": "fixture", "platform": native_platform(), "session_id": "another-session",
                 "settings": {"scope": {"roots": [str(source)]}}}
        receipt = {"plan_sha256": digest(original), "source_roots": original["inventory"]["roots"],
                   **{key: original[key] for key in ("quarantine_destination", "recovery_required", "recovery_backup", "recovery_verification")},
                   "records": [{"original": original["files"][0], "quarantine_record": {"relative_path": mapping[0]["quarantine_relative"]}}]}
        def payload(operation, plan, target=output):
            return {"operation": operation, "storage_plan": plan, "storage_plan_sha256": digest(plan),
                    "output_root": str(target), "mode": "fixture", "protected_roots": [str(output)]}
        restored = {"kind": "quarantine_restore", "receipt": receipt}
        with mock.patch("service_execute.StorageService") as lower:
            self.assertIs(service._storage(state, payload("storage.quarantine_restore", restored)), lower.return_value)
            lower.reset_mock()
            wrong = copy.deepcopy(restored); wrong["receipt"]["records"][0]["quarantine_record"]["relative_path"] = "quarantine/000002"
            with self.assertRaises(ServiceRefusal):
                service._storage(state, payload("storage.quarantine_restore", wrong))
            lower.assert_not_called()
            with self.assertRaises(ServiceRefusal):
                service._storage(state, payload("storage.backup_create", {"kind": "backup", "inventory": original["inventory"]}))
            lower.assert_not_called()
            selected_reserved = {"kind": "backup", "inventory": {"roots": [{"path": str(output)}]}}
            with self.assertRaises(ServiceRefusal):
                service._storage(state, payload("storage.backup_create", selected_reserved, other_output))
            lower.return_value.check_preconditions.assert_not_called()
        inventory = object.__new__(StorageService)
        inventory.output_root, inventory.protected_roots = other_output, (output,)
        inventory._scope = mock.Mock()
        for selected in (output, output / "quarantine"):
            with self.subTest(selected=selected), self.assertRaises(StorageRefusal):
                inventory.assess_storage(roots=[str(selected)])
        inventory._scope.assert_not_called()

    def test_quarantine_reservation_is_durable_before_first_adapter_effect(self):
        root = self.fixture_root()
        engine = self.fake_engine(root)
        engine.work = root / "work" / "engine"
        try:
            service = WorkflowService(engine)
        except PrivateWorkspaceError as exc:
            if os.name == "posix" and exc.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("only on posix: actual private namespace unavailable; pure reservation boundaries run separately")
            raise
        output = root / "work" / "quarantine-output"
        ensure_private_directory(output, create=True)
        plan = {"kind": "quarantine", "inventory": {"roots": [{"path": str(root / "work" / "selected")}]},
                "files": [{"sha256": "b" * 64}], "quarantine_relative": "quarantine",
                "quarantine_destination": str(output / "quarantine"), "recovery_required": False,
                "recovery_backup": None, "recovery_verification": None}
        payload = {"operation": "storage.quarantine", "storage_plan": plan,
                   "storage_plan_sha256": digest(plan), "output_root": str(output), "mode": "fixture", "protected_roots": []}
        state = {"engine_id": engine.marker["engine_id"], "session_id": "session-fixture", "mode": "fixture",
                 "platform": native_platform(), "status": "active", "stage": "apply"}
        action = {"action_id": "quarantine-fixture", "adapter_id": payload["operation"], "adapter_payload_sha256": digest(payload)}
        operation = {"operation_id": "operation-fixture", "action_id": action["action_id"], "plan_sha256": "a" * 64}
        engine.read_session, engine.pending_items = mock.Mock(return_value=state), mock.Mock(return_value=False)
        engine.begin_operation = mock.Mock(return_value={"data": operation})
        service._state, service._binding = mock.Mock(return_value=state), mock.Mock(return_value=(action, payload))
        native = mock.Mock()
        service._storage = mock.Mock(return_value=native)
        def persist_intent(*args):
            path = service._operation_dir(state["session_id"], operation["operation_id"], create=True)
            intent = {"schema": "patchcairn.service", "schema_version": 1, "kind": "operation_intent", "payload": payload,
                      "action": action, "operation": operation, "quarantine_mapping": service._quarantine_mapping(plan)}
            service._immutable(path / "intent.json", intent)
            return path, intent
        service._intent = mock.Mock(side_effect=persist_intent)
        service._finish = mock.Mock(side_effect=lambda state, operation, **result: result)
        def effect(**kwargs):
            reopened = WorkflowService(engine)
            self.assertIn(str(output), reopened.protected_roots())
            row = next(row for row in reopened._retention() if "quarantine_binding" in row)
            self.assertEqual(row["quarantine_binding"]["original_plan"], plan)
            self.assertEqual(row["quarantine_binding"]["quarantine_mapping"], service._quarantine_mapping(plan))
            self.assertIn(str(output / "quarantine" / "000001"), row["artifacts"])
            state["status"] = "stopped"
            self.assertIn(str(output), reopened.protected_roots())
            state["status"] = "active"
            return {"fictional_adapter_result": True}
        native.quarantine.side_effect = effect
        result = service.execute_action(state["session_id"], action_id=action["action_id"], plan_sha256=operation["plan_sha256"], precondition_evidence_ids=[])
        self.assertEqual(result["outcome"], "succeeded")
        native.quarantine.assert_called_once()


if __name__ == "__main__":
    unittest.main()
