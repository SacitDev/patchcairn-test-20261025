"""Selected synthetic work copies only. No host inventory, update or repair.

Restore family (scripts/service_restore.py): quarantine restoration.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import digest
import pc_records
from test_service_state import SessionFixtures, PROSE


class WorkflowServiceTests(SessionFixtures):
    def test_quarantine_restore_is_fixed_gated_and_verifies_original_bytes(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses native no-overwrite move; no fallback")
        storage = self.storage()
        inventory = storage.assess_storage(roots=[str(self.source)])
        quarantine = storage.plan_cleanup(inventory=inventory, selected=["r001/example.txt"], quarantine_destination=str(self.output / "unbacked-quarantine"), content_read_authorized=True, recovery_required=False)
        move = self.service.prepare_storage_action(self.sid, action_id="quarantine-unbacked", adapter_id="storage.quarantine", storage_plan=quarantine, output_root=str(self.output), **PROSE)
        moved = self.execute(move, self.approve(move))
        self.assertEqual(moved["outcome"], "succeeded")
        receipt = moved["receipt"]["native_receipt"]
        self.assertFalse(receipt["recovery_required"])
        sid = self.session()
        plan = self.storage().plan_quarantine_restore(receipt=receipt)
        action = self.service.prepare_storage_action(sid, action_id="restore-selected", adapter_id="storage.quarantine_restore", storage_plan=plan, output_root=str(self.output), **PROSE)
        recovery_id = action["recovery_evidence_ids"][0]
        recovery_row = self.state(sid)["evidence"][recovery_id]
        binding = json.loads((self.engine.work / sid / recovery_row["path"]).read_bytes())
        self.assertIs(pc_records.require_schema(binding, "patchcairn.quarantine.recovery"), binding)
        self.assertEqual(binding["restore_plan_sha256"], digest(plan))
        result = self.execute(action, self.approve(action, sid=sid), sid=sid)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual((self.source / "example.txt").read_text(), "Fictional selected file; no host content.\n")


if __name__ == "__main__":
    unittest.main()
