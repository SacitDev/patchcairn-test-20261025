"""Selected synthetic work copies only. No host inventory, update or repair.

Sessions driven through engine, service and storage: an interrupted adapter effect stays consumed until
reconciliation, and kept backups never lock out a new plan.
"""
from __future__ import annotations
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from storage_ops import StorageRefusal, StorageService
from private_workspace import ensure_private_directory, write_private_new
from workflow_service import ServiceRefusal
from test_service_state import SessionFixtures, PROSE
from test_service_retention import fixed_drive


class LifecycleTests(SessionFixtures):
    def test_crash_after_actual_backup_keeps_consumed_ticket_until_native_reconciliation(self):
        # The backup finished; the failure comes after it, before its receipt is verified, so the outcome is unknown.
        action, native = self.backup_action()
        sha = self.approve(action)
        with mock.patch.object(StorageService, "verify_outcome", side_effect=OSError("Fictional interruption; no exception detail may be persisted")):
            result = self.execute(action, sha)
        self.assertEqual(result["outcome"], "unknown")
        self.assertEqual(len(list((self.output / "one.zip").glob("*/backup.zip"))), 1)
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

    def test_more_than_30_backups_do_not_lock_out(self):
        # Each of 31 backups goes into its own folder and leaves its own kept row and protected folder; past the old cap of
        # 30 protected roots a new plan still prepares, approves and runs.
        self.service.elevation_probe = lambda: False
        for index in range(31):
            sid = self.sid if index == 0 else self.session()
            action, _plan = self.backup_action(sid=sid, suffix="b" + format(index, "02d"))
            self.assertEqual(self.execute(action, self.approve(action, sid=sid), sid=sid)["outcome"], "succeeded")
        roots = self.service.protected_roots()
        self.assertGreaterEqual(len([root for root in roots if Path(root).parent.parent == self.output]), 31)
        self.assertGreaterEqual(len(self.service.retention_rows()), 31)
        last = self.session()
        action, _plan = self.backup_action(sid=last, suffix="after")
        self.assertEqual(self.execute(action, self.approve(action, sid=last), sid=last)["outcome"], "succeeded")

    def test_fixture_source_under_work_is_admitted_next_to_protected_backups(self):
        # The protected roots name work/backups exactly, never the bare work folder, so a selected fixture copy below
        # work/ stays admissible while anything inside work/backups is refused.
        roots = self.service.protected_roots()
        self.assertIn(str(self.root / "work" / "backups"), roots)
        self.assertNotIn(str(self.root / "work"), roots)
        self.assertTrue(all(Path(root) != self.root / "work" for root in roots))
        self.service.elevation_probe = lambda: False
        action, _plan = self.backup_action()
        self.assertEqual(self.execute(action, self.approve(action))["outcome"], "succeeded")
        kept = self.root / "work" / "backups" / "20261026T120000Z-fixture"
        ensure_private_directory(kept, create=True, parents=True)
        write_private_new(kept / "backup.zip", b"Fictional kept archive")
        with self.assertRaises(StorageRefusal):
            self.storage().assess_storage(roots=[str(kept)])

    def test_chosen_destination_folder_is_protected_through_the_engine(self):
        # A backup to a chosen folder (in a fixture session, a folder of the work tree apart from the output root) protects
        # that folder before its first write, its kept row stays in it, and a later plan touching that folder is refused.
        self.service.elevation_probe = lambda: False
        chosen = self.root / "work" / "chosen-drive"
        ensure_private_directory(chosen, create=True)
        with fixed_drive():
            storage = self.storage()
            plan = storage.plan_backup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/example.txt"],
                                       destination=str(chosen), content_read_authorized=True, required_recovery=True)
            action = self.service.prepare_storage_action(self.sid, action_id="backup-chosen", adapter_id="storage.backup_create", storage_plan=plan,
                                                         output_root=str(self.output), backup_destination=str(chosen), **PROSE)
            self.assertEqual(self.execute(action, self.approve(action))["outcome"], "succeeded")
        self.assertIn(str(chosen), self.service.protected_roots())
        self.assertTrue(any(row["location"].startswith(str(chosen)) for row in self.service.retention_rows()))
        with self.assertRaises((StorageRefusal, ServiceRefusal)):
            self.storage().assess_storage(roots=[str(chosen)])


if __name__ == "__main__":
    unittest.main()
