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
from storage_ops import StorageRefusal, StorageService
from test_service_state import ServiceFixtures


class ServicePrivacyTests(ServiceFixtures):
    def interrupted(self, root, adapter_id, native_name, previous_outcome):
        """A service with one interrupted operation of ``adapter_id`` and the records reconciliation reads for it. A backup
        names a restoration probe: the shared reconciliation reads a backup's records only for that probe. Returns the
        service, the operation, the native receipt, the record contents and the paths of the native and probe outcomes."""
        service = object.__new__(WorkflowService)
        service.elevation_probe = lambda: False
        state = {"mode": "fixture", "engine_id": "engine-fixture", "platform": native_platform(),
                 "session_id": "session-fixture", "settings_revision": 0,
                 "settings": {"scope": {"roots": [str(root / "original-source")], "purpose": "Fictional original scope"}}}
        service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=state))
        service.work = root / "service"
        operation = {"operation_id": "operation-fixture", "outcome": previous_outcome,
                     "action_id": "action-fixture", "plan_sha256": "c" * 64, "settings_revision": 0,
                     "started_utc": utc_now(), "adapter_id": adapter_id, "mutating": True}
        state["operations"] = {operation["operation_id"]: operation}
        payload = {"output_root": str(root / "output"), "protected_roots": [],
                   "operation": adapter_id, "storage_plan_sha256": "a" * 64,
                   "storage_plan": {"fictional": True}}
        receipt = {"fictional_native_receipt": True, "location": str(root / "output" / "fictional-backup"),
                   "backup_bytes": 1, "volume_identity": None}
        native_path = root / "output" / ("outcome-" + native_name + "-" + "a" * 64 + ".json")
        origin_path = service.work / ("origin-" + "a" * 64 + ".json")
        content = {native_path: encoded(receipt), origin_path: encoded({
            "schema": "patchcairn.service", "schema_version": 1, "kind": "native_origin",
            "operation_id": operation["operation_id"], **state})}
        probe_path = None
        if adapter_id == "storage.backup_create":
            payload["restore_probe_destination"] = str(root / "output" / "probe")
            probe = {"destination": payload["restore_probe_destination"], "receipt": receipt}
            content[root / "operation" / "restore-probe-plan.json"] = encoded(probe)
            probe_path = root / "output" / ("outcome-restore-" + digest(probe) + ".json")
            content[probe_path] = encoded({"fictional_probe_receipt": True})
        for path in content:  # the service looks for these before it reads them; their bytes come from ``content``
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        service.inspect_operation = mock.Mock(return_value={"operation": operation,
            "intent": {"payload": payload, "action": {"adapter_id": payload["operation"]},
                "operation": copy.deepcopy(operation), "scope": state["settings"]["scope"],
                **{key: state[key] for key in ("engine_id", "mode", "platform", "session_id", "settings_revision")}}})
        service._lock = mock.Mock(side_effect=nullcontext)
        service._operation_dir = mock.Mock(return_value=root / "operation")
        service._finish = mock.Mock(side_effect=lambda state, operation, **result: result)
        service._register_recovery = mock.Mock()
        service._register_backup = mock.Mock()
        return service, operation, receipt, content, native_path, probe_path

    def test_a_probe_that_left_no_outcome_closes_partial_and_a_refused_one_holds(self):
        """The file is really gone: the backup is verified, the check did not finish. The file is there but refused, or gone
        between two looks: the shared reconciliation holds (the test above)."""
        root = self.fixture_root()
        for previous_outcome, kind in ((None, "outcome"), ("unknown", "reconciliation")):
            with self.subTest(previous_outcome=previous_outcome):
                service, operation, receipt, content, native_path, probe_path = self.interrupted(root, "storage.backup_create", "backup", previous_outcome)
                service._retain = mock.Mock()
                probe = {"destination": str(root / "output" / "probe"), "receipt": receipt, "files": [
                    {"root_id": "r001", "relative_path": "fictional.txt", "sha256": "d" * 64}]}
                content[root / "operation" / "restore-probe-plan.json"] = encoded(probe)
                (root / "output" / ("outcome-restore-" + digest(probe) + ".json")).unlink(missing_ok=True)
                with mock.patch("service_backup.StorageService") as storage, mock.patch("service_state.ensure_private_file"), \
                        mock.patch("service_state.read_record_bytes", side_effect=lambda path, *args: content[path]):
                    storage.return_value.settle_backup.return_value = {"state": "finished", "receipt": receipt, "leftover": []}
                    storage.return_value.verify_outcome.return_value = {"receipt_sha256": "b" * 64}
                    result = service.reconcile_operation("session-fixture", operation_id=operation["operation_id"])
                self.assertEqual((result["outcome"], result["kind"]), ("partial", kind))
                self.assertEqual(service._retain.call_args.args[1], {str(Path(probe["destination"]) / "r001" / "fictional.txt"): "d" * 64})
                self.assertEqual(result["receipt"]["restore_probe_files_planned"], 1)
                service._register_backup.assert_called_once()
                service._register_recovery.assert_not_called()

    def test_reconciliation_admits_native_outcome_privacy_before_content_read(self):
        """The shared _reconcile_storage reads a native outcome and a restoration probe's outcome. storage.restore goes
        straight to it; storage.backup_create reaches it only after settle_backup finished a backup that has a probe."""
        root = self.fixture_root()
        for blocked_kind, adapter_id, native_name in (("native", "storage.restore", "restore"), ("native", "storage.backup_create", "backup"),
                                                      ("probe", "storage.backup_create", "backup")):
            backup = adapter_id == "storage.backup_create"
            for previous_outcome in (None, "unknown"):
                for refusal in (PrivateWorkspaceError("fixture-file-private-hold"), FileNotFoundError()):
                    with self.subTest(blocked_kind=blocked_kind, adapter_id=adapter_id, previous_outcome=previous_outcome, refusal=type(refusal).__name__):
                        service, operation, receipt, content, native_path, probe_path = self.interrupted(root, adapter_id, native_name, previous_outcome)
                        blocked_path = probe_path if blocked_kind == "probe" else native_path
                        def admit(path):
                            if path == blocked_path:
                                raise refusal
                        with mock.patch("service_backup.StorageService") as settling, mock.patch("service_reconcile.StorageService") as storage, mock.patch("service_state.ensure_private_file", side_effect=admit) as admission, mock.patch("service_state.read_record_bytes", side_effect=lambda path, *args: content[path]) as reader:
                            settling.return_value.settle_backup.return_value = {"state": "finished", "receipt": receipt, "leftover": []}
                            settling.return_value.verify_outcome.return_value = {"receipt_sha256": "b" * 64}
                            result = service.reconcile_operation("session-fixture", operation_id=operation["operation_id"])
                        self.assertEqual(settling.return_value.settle_backup.call_count, 1 if backup else 0)
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
                        # The backup folder settle_backup verified is kept on purpose before the probe is checked
                        # (service_backup._reconcile_storage_backup_create); recovery evidence is never registered.
                        self.assertEqual(service._register_backup.call_count, 1 if backup else 0)
                        service._register_recovery.assert_not_called()

    def test_a_privacy_refusal_settling_a_backup_holds_with_nothing_finished_or_registered(self):
        """A backup's own outcome is read inside storage, by settle_backup and by verify_outcome. Their refusal is a hold
        raised to the caller: the operation keeps its outcome, and no record is read or registered."""
        root = self.fixture_root()
        refusal = StorageService._privacy_hold(PrivateWorkspaceError("fixture-file-private-hold"))
        for step in ("settle_backup", "verify_outcome"):
            for previous_outcome in (None, "unknown"):
                with self.subTest(step=step, previous_outcome=previous_outcome):
                    service, operation, receipt, *_ = self.interrupted(root, "storage.backup_create", "backup", previous_outcome)
                    with mock.patch("service_backup.StorageService") as storage, mock.patch("service_state.read_record_bytes") as reader:
                        storage.return_value.settle_backup.return_value = {"state": "finished", "receipt": receipt, "leftover": []}
                        getattr(storage.return_value, step).side_effect = refusal
                        with self.assertRaises(StorageRefusal) as caught:
                            service.reconcile_operation("session-fixture", operation_id=operation["operation_id"])
                    self.assertEqual(caught.exception.code, "fixture-file-private-hold")
                    reader.assert_not_called()
                    service._finish.assert_not_called()
                    service._register_backup.assert_not_called()
                    service._register_recovery.assert_not_called()


if __name__ == "__main__":
    unittest.main()
