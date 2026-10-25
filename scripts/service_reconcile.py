"""Reconciliation: the reconcile dispatch over every adapter id (PLAN 3.3, RR4, D-071) and the storage outcome check.

``reconcile_operation`` takes the lock and reads the operation's checked original intent, then calls the adapter's
private ``_reconcile_<id>`` method named in RECONCILE, looked up on the object. Each one is defined in its family's
module; an id whose reconciliation is not written yet holds there. The targets and ``_reconcile_storage`` rely on
reconcile_operation's steps. Absence of a native outcome stays unknown and consumed.
"""
from __future__ import annotations

from pathlib import Path

import pc_records
import service_state
from workflow_core import WorkflowRefusal, digest
from storage_ops import StorageService, StorageRefusal
from scoped_fs import ScopedFSError
from service_state import ServiceRefusal, decoded, service_record
from service_execute import STORAGE

# Every adapter id's reconcile target: the name of a private WorkflowService method defined in the module of the
# id's family (pc_records.ADAPTERS[id]["family"]). Each takes (session_id, operation, intent, payload, **arguments)
# and gets reconcile_operation's keywords unchanged.
RECONCILE = {
    pc_records.ADAPTER_STORAGE_BACKUP_CREATE: "_reconcile_storage_backup_create",
    pc_records.ADAPTER_STORAGE_RESTORE: "_reconcile_storage_restore",
    pc_records.ADAPTER_STORAGE_QUARANTINE: "_reconcile_storage_quarantine",
    pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE: "_reconcile_storage_quarantine_restore",
    pc_records.ADAPTER_STORAGE_PURGE: "_reconcile_storage_purge",
    pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS: "_reconcile_storage_remove_originals",
    pc_records.ADAPTER_STORAGE_RETENTION_RELEASE: "_reconcile_storage_retention_release",
    pc_records.ADAPTER_STORAGE_RETENTION_FORGET: "_reconcile_storage_retention_forget",
    pc_records.ADAPTER_STORAGE_SESSION_RELEASE: "_reconcile_storage_session_release",
    pc_records.ADAPTER_PACKAGE_UPGRADE: "_reconcile_package_upgrade",
    pc_records.ADAPTER_PACKAGE_REINSTALL: "_reconcile_package_reinstall",
    pc_records.ADAPTER_SYSTEM_REPAIR: "_reconcile_system_repair",
    pc_records.ADAPTER_DIAGNOSTIC_COLLECT: "_reconcile_diagnostic_collect",
    pc_records.ADAPTER_FIXTURE_ASSESSMENT: "_reconcile_fixture_assessment",
    pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL: "_reconcile_system_reviewed_external",
}


class ReconcileMixin:
    """reconcile_operation and the shared storage reconciliation."""

    def reconcile_operation(self, session_id, *, operation_id):
        """Inspect actual native outcome; absence remains unknown and consumed."""
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            payload = intent["payload"]
            return getattr(self, RECONCILE.get(intent["action"]["adapter_id"], "_reconcile_held"))(
                session_id, operation, intent, payload, operation_id=operation_id)

    def _reconcile_storage(self, session_id, operation, intent, payload, *, operation_id):
        """A storage operation's native outcome and origin, verified again, called with reconcile_operation's lock held.
        Private control files are read through service_state.private_read, which admits their privacy first."""
        if operation["outcome"] not in {None, "unknown"}:
            raise ServiceRefusal("Known operation receipt is already consumed; retain historical result")
        state = self.engine.read_session(session_id)
        self._original_authority(state, operation, intent)
        storage = StorageService(output_root=payload["output_root"], quiet_workspace=True, protected_roots=payload["protected_roots"])
        outcome_path = Path(payload["output_root"]) / ("outcome-" + STORAGE[payload["operation"]][1] + "-" + payload["storage_plan_sha256"] + ".json")
        try:
            receipt = decoded(service_state.private_read(outcome_path))
            origin = service_record(decoded(service_state.private_read(self.work / ("origin-" + payload["storage_plan_sha256"] + ".json"))),
                                    "native_origin")
            if origin["operation_id"] != operation_id or origin["mode"] != state["mode"] or origin["engine_id"] != state["engine_id"]:
                raise ServiceRefusal("Native outcome has another operation's origin")
            verification = storage.verify_outcome(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"], receipt=receipt)
            reconciled_receipt = {"native_receipt": receipt, "verification": verification}
            if "restore_probe_destination" in payload:
                probe = decoded(service_state.private_read(self._operation_dir(session_id, operation_id) / "restore-probe-plan.json"))
                if probe["destination"] != payload["restore_probe_destination"] or probe["receipt"] != receipt:
                    raise ServiceRefusal("Probe plan differs from original exact reviewed verification scope")
                probe_path = Path(payload["output_root"]) / ("outcome-restore-" + digest(probe) + ".json")
                restoration = decoded(service_state.private_read(probe_path))
                storage.verify_outcome(plan=probe, expected_plan_sha256=digest(probe), receipt=restoration)
                reconciled_receipt["restore_probe_receipt"] = restoration
                reconciled_receipt["recovery_evidence"] = self._register_recovery(session_id, payload["output_root"], receipt, restoration,
                                                                                  completing=True)
        except (OSError, StorageRefusal, ScopedFSError, WorkflowRefusal, ServiceRefusal, ValueError):
            if operation["outcome"] is None:
                return self._finish(state, operation, outcome="unknown", receipt={"possible_partial_effects": True, "native_outcome_verified": False,
                        "instruction": "Missing or inconsistent actual native outcome; no retry or success is permitted."})
            return {"operation_id": operation_id, "outcome": "unknown", "held": True, "automatic_retry": False}
        return self._finish(state, operation, outcome="succeeded", receipt=reconciled_receipt,
                            kind="reconciliation" if operation["outcome"] == "unknown" else "outcome")
