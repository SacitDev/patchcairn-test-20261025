"""Retention family: the protected retention registry, recovery registration and the retention dispatch (PLAN 3.3).

The retention release, forget and session-release adapters hold here until their family code is written.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import uuid

import pc_records
import storage_contract
from workflow_core import (encoded, digest, read_record_bytes, atomic_replace, exact_fields, record_identifier,
                           QUARANTINE_RECOVERY, RECOVERY_BINDING, RECOVERY_RETENTION)
from storage_ops import StorageService
from private_workspace import ensure_private_directory
from service_state import ServiceRefusal, decoded, private_read, service_record, service_value, within


class RetentionMixin:
    """Protected retention rows, the protected roots every storage plan must include, and recovery bindings."""

    def _retention(self):
        ensure_private_directory(self.work)
        registry = service_record(decoded(private_read(self.work / "retention.json")), "retention_registry")
        exact_fields(registry, {"schema", "schema_version", "kind", "entries"}, {"schema", "schema_version", "kind", "entries"})
        if not isinstance(registry["entries"], list) or len(registry["entries"]) > 10000:
            raise ServiceRefusal("Invalid protected retention registry")
        rows = []
        for ref in registry["entries"]:
            exact_fields(ref, {"name", "sha256"}, {"name", "sha256"})
            record_identifier(ref["name"])
            data = private_read(self.work / (ref["name"] + ".json"))
            if digest(data) != ref["sha256"]:
                raise ServiceRefusal("Protected retention record changed")
            row = service_record(decoded(data), "required_retention")
            if not isinstance(row.get("artifacts"), dict) or not row["artifacts"]:
                raise ServiceRefusal("Invalid protected retention evidence")
            protection = self._owned(row.get("protection_root"))
            for path in row["artifacts"]:
                if not within(self._owned(path), protection):
                    raise ServiceRefusal("Retention protection does not contain its exact artifacts")
            if "quarantine_binding" in row:
                self._validate_quarantine_reservation(row)
            rows.append(row)
        return rows

    def protected_roots(self):
        values = {str(self.engine.work), str(self.work)}
        for row in self._retention():
            values.add(row["protection_root"])
        if len(values) > storage_contract.MAX_PROTECTED_ROOTS:
            raise ServiceRefusal("Protection policy exceeds adapter cap; retain evidence and narrow scope")
        return sorted(values)

    def _retain(self, session_id, artifacts, *, reason, quarantine_binding=None):
        for path in artifacts:
            self._owned(path)
        row = service_value("required_retention", session_id=session_id, observed_utc=pc_records.utc_now(), reason=reason,
                            artifacts=artifacts, protection_root=os.path.commonpath([str(Path(path).parent) for path in artifacts]))
        if quarantine_binding is not None:
            row["quarantine_binding"] = copy.deepcopy(quarantine_binding)
        name = "retention-" + uuid.uuid4().hex
        ref = self._immutable(self.work / (name + ".json"), row)
        registry = service_record(decoded(private_read(self.work / "retention.json")), "retention_registry")
        registry["entries"].append({"name": name, "sha256": ref["sha256"]})
        atomic_replace(self.work / "retention.json", encoded(registry))

    def register_recovery(self, session_id, *, output_root, backup_receipt, restore_receipt):
        with self._lock():
            return self._register_recovery(session_id, output_root, backup_receipt, restore_receipt)

    def _quarantine_recovery(self, state, payload):
        plan, output = payload["storage_plan"], Path(payload["output_root"])
        receipt = plan["receipt"]
        attempt = output / receipt["attempt"]
        artifacts = {str(attempt): digest(read_record_bytes(attempt)),
                     str(output / ("outcome-quarantine-" + receipt["plan_sha256"] + ".json")): digest(receipt)}
        for row in receipt["records"]:
            artifacts[str(output / row["quarantine_record"]["relative_path"])] = row["quarantine_record"]["sha256"]
        retention = {"schema": RECOVERY_RETENTION, "schema_version": pc_records.SCHEMA_VERSION, "session_id": state["session_id"],
                     "required": True, "artifacts": artifacts}
        retention_row = self._register(state, kind="retention", value=retention)
        binding = {"schema": QUARANTINE_RECOVERY, "schema_version": pc_records.SCHEMA_VERSION, "output_root": str(output),
                   "quarantine_receipt": receipt, "restore_plan": plan, "restore_plan_sha256": digest(plan),
                   "retention_evidence_id": retention_row["evidence_id"]}
        row = self._register(state, kind="recovery", value=binding)
        self._retain(state["session_id"], artifacts,
                     reason="Exact original quarantine mapping, native bytes and immutable receipts retained for reviewed no-overwrite restoration")
        return row

    def _register_recovery(self, session_id, output_root, backup, restore, *, completing=False):
        state = self._state(session_id, collecting=not completing)
        output = self._owned(str(output_root), state=state, existing=True)
        storage = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=self.protected_roots())
        manifest = storage.verify_backup(receipt=backup)["manifest"]
        storage.verified_recovery(backup=backup, restoration=restore)
        for receipt in (backup, restore):
            origin = service_record(decoded(private_read(self.work / ("origin-" + receipt["plan_sha256"] + ".json"))), "native_origin")
            if origin.get("engine_id") != state["engine_id"] or origin.get("mode") != state["mode"] or origin.get("platform") != state["platform"]:
                raise ServiceRefusal("Recovery has no matching gated native fixture/real origin")
        if (backup.get("required_recovery") is not True
                or sorted(row["path"] for row in manifest["source_roots"]) != sorted(state["settings"]["scope"]["roots"])):
            raise ServiceRefusal("Recovery must cover this exact selected scope and remain required")
        if state["mode"] == "fixture" and any(not within(Path(row["path"]), self.root / "work") for row in manifest["source_roots"]):
            raise ServiceRefusal("Fixture recovery cannot import real source scope")
        artifacts = {backup["archive"]: backup["archive_sha256"], backup["manifest"]: backup["manifest_sha256"],
                     str(output / ("outcome-restore-" + restore["plan_sha256"] + ".json")): digest(restore)}
        for file in manifest["files"]:
            artifacts[str(Path(restore["destination"]) / file["root_id"] / file["relative_path"])] = file["sha256"]
        self._retain(session_id, artifacts, reason="Exact verified required archive, manifest and restoration probe; no automatic release")
        if state["status"] == "stopped":
            return {"registration": "preserved_in_service_retention_after_stop", "artifacts": artifacts,
                    "limitation": "Stopped session accepts only the active operation outcome; no new recovery authority was created."}
        retention = {"schema": RECOVERY_RETENTION, "schema_version": pc_records.SCHEMA_VERSION, "session_id": session_id,
                     "required": True, "artifacts": artifacts}
        retention_row = self._register(state, kind="retention", value=retention)
        binding = {"schema": RECOVERY_BINDING, "schema_version": pc_records.SCHEMA_VERSION, "output_root": str(output),
                   "backup_receipt": backup, "restore_receipt": restore, "retention_evidence_id": retention_row["evidence_id"]}
        row = self._register(state, kind="recovery", value=binding)
        self.engine.verify_recovery(self.engine.read_session(session_id), [row["evidence_id"]])
        return row

    # Dispatch targets (service_execute.EXECUTE, service_reconcile.RECONCILE; reached only through execute_action and
    # reconcile_operation): the retention adapters are not written yet.
    def _execute_storage_retention_release(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _execute_storage_retention_forget(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _execute_storage_session_release(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _reconcile_storage_retention_release(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)

    def _reconcile_storage_retention_forget(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)

    def _reconcile_storage_session_release(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)
