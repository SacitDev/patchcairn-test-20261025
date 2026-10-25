"""Selected synthetic work copies only. No host inventory, update or repair.

One session driven through engine, service and storage: an interrupted adapter effect stays consumed
until reconciliation.
"""
from __future__ import annotations
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from storage_ops import StorageService
from test_service_state import SessionFixtures, PROSE


class LifecycleTests(SessionFixtures):
    def test_crash_after_actual_backup_keeps_consumed_ticket_until_native_reconciliation(self):
        action, native = self.backup_action()
        sha = self.approve(action)
        original = StorageService.create_backup
        def completed_then_interrupted(instance, **kwargs):
            original(instance, **kwargs)
            raise OSError("Fictional interruption; no exception detail may be persisted")
        with mock.patch.object(StorageService, "create_backup", completed_then_interrupted):
            result = self.execute(action, sha)
        self.assertEqual(result["outcome"], "unknown")
        self.assertTrue((self.output / "one.zip").exists())
        self.assertEqual(self.state()["status"], "held")
        recovered = self.service.reconcile_operation(self.sid, operation_id=result["operation_id"])
        self.assertEqual(recovered["outcome"], "succeeded")
        self.assertEqual(self.state()["status"], "paused")
        self.assertEqual(len(self.state()["operations"]), 1)

    def test_partial_move_before_step_receipt_keeps_original_mapping_and_unknown(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses native no-overwrite move; no fallback")
        storage = self.storage()
        inventory = storage.assess_storage(roots=[str(self.source)])
        native = storage.plan_cleanup(inventory=inventory, selected=["r001/example.txt"], quarantine_destination=str(self.output / "quarantine"), content_read_authorized=True, recovery_required=False)
        action = self.service.prepare_storage_action(self.sid, action_id="move-once", adapter_id="storage.quarantine", storage_plan=native, output_root=str(self.output), **PROSE)
        sha = self.approve(action)
        original = StorageService._write_json
        def interrupt_step(instance, output, relative, value):
            if relative.startswith("step-quarantine-"):
                raise OSError("fictional interrupted step receipt")
            return original(instance, output, relative, value)
        with mock.patch.object(StorageService, "_write_json", interrupt_step):
            result = self.execute(action, sha)
        self.assertEqual(result["outcome"], "unknown")
        self.assertFalse((self.source / "example.txt").exists())
        self.assertTrue((self.output / "quarantine" / "000001").exists())
        inspected = self.service.inspect_operation(self.sid, operation_id=result["operation_id"])
        self.assertEqual(inspected["intent"]["quarantine_mapping"][0]["original"], native["files"][0])
        self.assertEqual(inspected["intent"]["quarantine_mapping"][0]["quarantine_relative"], "quarantine/000001")
        reconciled = self.service.reconcile_operation(self.sid, operation_id=result["operation_id"])
        self.assertEqual(reconciled["outcome"], "unknown")
        self.assertEqual(len(self.state()["operations"]), 1)


if __name__ == "__main__":
    unittest.main()
