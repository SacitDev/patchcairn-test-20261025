"""Selected synthetic work copies only. No host inventory, update or repair.

Retention family (scripts/service_retention.py): recovery registration.
"""
from __future__ import annotations
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from storage_ops import StorageRefusal
from scoped_fs import ScopedFSError
from test_service_state import SessionFixtures


class WorkflowServiceTests(SessionFixtures):
    def test_recovery_boolean_or_changed_probe_cannot_supply_recovery(self):
        backup_action, native = self.backup_action(probe=True)
        result = self.execute(backup_action, self.approve(backup_action))
        backup, restore = result["receipt"]["native_receipt"], result["receipt"]["restore_probe_receipt"]
        sid = self.session()
        with self.assertRaises((StorageRefusal, KeyError, TypeError)):
            self.service.register_recovery(sid, output_root=str(self.output), backup_receipt={"verified": True}, restore_receipt={"verified": True})
        (Path(restore["destination"]) / "r001" / "example.txt").write_text("Changed probe")
        with self.assertRaises((StorageRefusal, ScopedFSError)):
            self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)


if __name__ == "__main__":
    unittest.main()
