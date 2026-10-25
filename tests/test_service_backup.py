"""Selected synthetic work copies only. No host inventory, update or repair.

Backup family (scripts/service_backup.py): the backup adapter and the storage verifier the engine re-checks
recovery through.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowRefusal
import pc_records
from workflow_service import ServiceRefusal, verify_storage_artifact
from storage_ops import StorageRefusal
from test_service_state import SessionFixtures, PROSE


class WorkflowServiceTests(SessionFixtures):
    def test_backup_probe_creates_actual_recovery_retention_and_owned_intent(self):
        action, native = self.backup_action(probe=True)
        sha = self.approve(action)
        result = self.execute(action, sha)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual((self.output / "one-probe" / "r001" / "example.txt").read_bytes(), (self.source / "example.txt").read_bytes())
        inspected = self.service.inspect_operation(self.sid, operation_id=result["operation_id"])
        self.assertEqual(inspected["intent"]["payload"]["storage_plan"], native)
        self.assertEqual(inspected["intent"]["action"]["adapter_payload_sha256"], action["adapter_payload_sha256"])
        recovery = result["receipt"]["recovery_evidence"]["evidence_id"]
        self.engine.verify_recovery(self.state(), [recovery])
        self.assertIn(str(self.output), self.service.protected_roots())
        self.assertEqual(self.state()["stage"], "apply")
        with self.assertRaises((ServiceRefusal, WorkflowRefusal, StorageRefusal)):
            self.execute(action, sha)
        self.assertEqual(len(self.state()["operations"]), 1)

    def test_begin_reverifies_recovery_artifact_from_disk(self):
        sid, action, sha, backup, _ = self.approved_purge()
        # The plan was registered and approved against these bytes; begin must read them again.
        archive = Path(backup["archive"])
        archive.rename(archive.with_name("moved-after-approval.zip"))
        self.begin(sid, action, sha, code="recovery-missing")
        self.assertEqual(self.state(sid)["operations"], {})
        self.assertTrue((self.output / "quarantine" / "000001").exists())

    def test_begin_refuses_when_recovery_bytes_changed(self):
        sid, action, sha, _, restore = self.approved_purge()
        restored = Path(restore["destination"]) / "r001" / "example.txt"
        restored.write_bytes(restored.read_bytes().upper())
        self.begin(sid, action, sha, code="recovery-changed")
        self.assertEqual(self.state(sid)["operations"], {})
        self.assertTrue((self.output / "quarantine" / "000001").exists())

    def test_begin_refuses_changed_quarantine_mapping(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses native no-overwrite move; no fallback")
        storage = self.storage()
        quarantine = storage.plan_cleanup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/example.txt"],
                                          quarantine_destination=str(self.output / "quarantine"), content_read_authorized=True,
                                          recovery_required=False)
        move = self.service.prepare_storage_action(self.sid, action_id="quarantine-unbacked", adapter_id="storage.quarantine",
                                                   storage_plan=quarantine, output_root=str(self.output), **PROSE)
        receipt = self.execute(move, self.approve(move))["receipt"]["native_receipt"]
        sid = self.session()
        action = self.service.prepare_storage_action(sid, action_id="restore-selected", adapter_id="storage.quarantine_restore",
                                                     storage_plan=self.storage().plan_quarantine_restore(receipt=receipt),
                                                     output_root=str(self.output), **PROSE)
        sha = self.approve(action, sid=sid)
        (self.output / "quarantine" / "000001").rename(self.output / "quarantine" / "000002")
        self.begin(sid, action, sha, code="recovery-changed")
        self.assertEqual(self.state(sid)["operations"], {})
        self.assertFalse((self.source / "example.txt").exists())

    def test_begin_refuses_a_changed_quarantine_attempt_record(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses native no-overwrite move; no fallback")
        storage = self.storage()
        quarantine = storage.plan_cleanup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/example.txt"],
                                          quarantine_destination=str(self.output / "quarantine"), content_read_authorized=True,
                                          recovery_required=False)
        move = self.service.prepare_storage_action(self.sid, action_id="quarantine-unbacked", adapter_id="storage.quarantine",
                                                   storage_plan=quarantine, output_root=str(self.output), **PROSE)
        receipt = self.execute(move, self.approve(move))["receipt"]["native_receipt"]
        sid = self.session()
        action = self.service.prepare_storage_action(sid, action_id="restore-selected", adapter_id="storage.quarantine_restore",
                                                     storage_plan=self.storage().plan_quarantine_restore(receipt=receipt),
                                                     output_root=str(self.output), **PROSE)
        sha = self.approve(action, sid=sid)
        # Still decodable, with the same plan file and plan digest: only the retained bytes differ.
        attempt = self.output / receipt["attempt"]
        record = json.loads(attempt.read_bytes())
        attempt.write_bytes(json.dumps({**record, "status": record["status"] + " (changed)"}, sort_keys=True, separators=(",", ":")).encode("ascii"))
        self.begin(sid, action, sha, code="recovery-changed")
        self.assertFalse((self.source / "example.txt").exists())

    def test_storage_verifier_refuses_a_backup_that_does_not_cover_the_purge(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses the native no-overwrite quarantine prerequisite; no fallback")
        receipt, backup, restore = self.make_recovery_and_quarantine()
        binding = {"kind": "backup_recovery", "output_root": str(self.output), "backup_receipt": backup, "restore_receipt": restore, "purge_receipt": receipt}
        self.assertIsNone(verify_storage_artifact(binding))
        uncovered = copy.deepcopy(receipt)
        uncovered["records"][0]["original"]["sha256"] = "0" * 64
        for changed, code in (({"purge_receipt": uncovered}, "recovery-changed"), ({"backup_receipt": {**backup, "archive": backup["archive"] + ".missing"}}, "recovery-missing"),
                              ({"kind": "fictional-unknown"}, "verifier-binding")):
            with self.subTest(code=code), self.assertRaises(pc_records.Refusal) as caught:
                verify_storage_artifact({**binding, **changed})
            self.assertEqual(caught.exception.code, code)


if __name__ == "__main__":
    unittest.main()
