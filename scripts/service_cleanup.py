"""Cleanup family: quarantine reservations and mappings, the purge recovery rule and the cleanup dispatch (PLAN 3.3).

Removing originals holds here until its family code is written.
"""
from __future__ import annotations

from pathlib import Path

import pc_records
from workflow_core import digest, record_identifier
from service_state import RESERVATION_RECORD, ServiceRefusal, decoded, private_read, read_reservation, service_record, within


class CleanupMixin:
    """Quarantine reservations, their exact mappings and the backed-purge rule."""

    @staticmethod
    def _quarantine_mapping(plan):
        return [{"original": row, "quarantine_relative": plan["quarantine_relative"] + f"/{index:06d}"}
                for index, row in enumerate(plan["files"], 1)]

    @staticmethod
    def _quarantine_artifacts(output, plan):
        native_sha = digest(plan)
        artifacts = {str(output / ("attempt-quarantine-" + native_sha + ".json")): None,
                     str(output / ("outcome-quarantine-" + native_sha + ".json")): None}
        for index, row in enumerate(plan["files"], 1):
            artifacts[str(output / plan["quarantine_relative"] / f"{index:06d}")] = row["sha256"]
            artifacts[str(output / f"step-quarantine-{native_sha}-{index:06d}.json")] = None
        return artifacts

    def _validate_quarantine_reservation(self, row):
        binding = read_reservation(row["quarantine_binding"])
        for key in ("session_id", "operation_id"):
            record_identifier(binding[key])
        plan = binding["original_plan"]
        if (binding["engine_id"] != self.engine.marker["engine_id"]
                or binding["mode"] not in {"fixture", "real"} or binding["platform"] not in {"windows", "macos", "linux"}
                or row["session_id"] != binding["session_id"] or row["protection_root"] != binding["output_root"]
                or not isinstance(plan, dict) or plan.get("kind") != "quarantine"
                or digest(plan) != binding["native_plan_sha256"]
                or binding["quarantine_mapping"] != self._quarantine_mapping(plan)
                or row["artifacts"] != self._quarantine_artifacts(Path(binding["output_root"]), plan)):
            raise ServiceRefusal("Quarantine reservation differs from its exact original plan, namespace or mapping")
        intent_path = self.work / "operations" / binding["session_id"] / binding["operation_id"] / "intent.json"
        intent = service_record(decoded(private_read(intent_path)), "operation_intent")
        origin = service_record(decoded(private_read(self.work / ("origin-" + binding["native_plan_sha256"] + ".json"))), "native_origin")
        if (digest(intent) != binding["intent_sha256"] or digest(origin) != binding["native_origin_sha256"]
                or intent["payload"]["storage_plan"] != plan or intent["payload"]["output_root"] != binding["output_root"]
                or intent["quarantine_mapping"] != binding["quarantine_mapping"]
                or intent["action"]["adapter_payload_sha256"] != binding["adapter_payload_sha256"]
                or intent["operation"]["plan_sha256"] != binding["workflow_plan_sha256"]
                or any(origin.get(key) != binding[key] for key in ("engine_id", "mode", "platform", "session_id", "operation_id"))
                or origin.get("native_plan_sha256") != binding["native_plan_sha256"]
                or origin.get("workflow_plan_sha256") != binding["workflow_plan_sha256"]):
            raise ServiceRefusal("Original quarantine intent or native provenance changed; preserve the reserved output")

    def _reserve_quarantine(self, state, operation, action, payload, intent):
        plan, output = payload["storage_plan"], Path(payload["output_root"])
        origin = service_record(decoded(private_read(self.work / ("origin-" + digest(plan) + ".json"))), "native_origin")
        binding = {"schema": RESERVATION_RECORD, "schema_version": pc_records.SCHEMA_VERSION,
                   **{key: state[key] for key in ("engine_id", "mode", "platform", "session_id")},
                   "operation_id": operation["operation_id"], "workflow_plan_sha256": operation["plan_sha256"],
                   "adapter_payload_sha256": action["adapter_payload_sha256"], "native_plan_sha256": digest(plan),
                   "output_root": str(output), "original_plan": plan, "quarantine_mapping": self._quarantine_mapping(plan),
                   "intent_sha256": digest(intent), "native_origin_sha256": digest(origin)}
        artifacts = self._quarantine_artifacts(output, plan)
        self._validate_quarantine_reservation({"quarantine_binding": binding, "session_id": state["session_id"],
                                               "protection_root": str(output), "artifacts": artifacts})
        self._retain(state["session_id"], artifacts, quarantine_binding=binding,
                     reason="Exact quarantine output, original intent/native provenance and mapping reserved before the first move; no automatic release")

    def _quarantine_reservations(self, state, payload, output, plan):
        reservations = [row["quarantine_binding"] for row in self._retention() if "quarantine_binding" in row]
        for binding in reservations:
            reserved = Path(binding["output_root"])
            if not (within(output, reserved) or within(reserved, output)):
                continue
            receipt = plan.get("receipt")
            original = binding["original_plan"]
            if (payload["operation"] not in {pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE, pc_records.ADAPTER_STORAGE_PURGE}
                    or output != reserved or binding["mode"] != state["mode"] or binding["platform"] != state["platform"]
                    or not isinstance(receipt, dict) or receipt.get("plan_sha256") != binding["native_plan_sha256"]
                    or receipt.get("source_roots") != original["inventory"]["roots"]
                    or any(receipt.get(key) != original[key]
                           for key in ("quarantine_destination", "recovery_required", "recovery_backup", "recovery_verification"))
                    or [{"original": row["original"], "quarantine_relative": row["quarantine_record"]["relative_path"]}
                        for row in receipt.get("records", [])] != binding["quarantine_mapping"]):
                raise ServiceRefusal("Reserved quarantine output permits only its exact original receipt-mapped restoration or backed purge")
        return reservations

    @staticmethod
    def _purge_original_recovery(payload):
        if payload["operation"] == pc_records.ADAPTER_STORAGE_PURGE:
            receipt = payload["storage_plan"].get("receipt")
            if (not isinstance(receipt, dict) or receipt.get("recovery_required") is not True
                    or not isinstance(receipt.get("recovery_backup"), dict) or not isinstance(receipt.get("recovery_verification"), dict)):
                raise ServiceRefusal("Integrated permanent purge requires the original quarantine's exact verified backup and restoration probe")

    # Dispatch targets (service_execute.EXECUTE, service_reconcile.RECONCILE; reached only through execute_action and
    # reconcile_operation): quarantine and purge use the shared storage path; removing originals is not written yet.
    def _execute_storage_quarantine(self, session_id, state, action, payload, **arguments):
        return self._run_fixed_adapter(session_id, state, action, payload, **arguments)

    def _execute_storage_purge(self, session_id, state, action, payload, **arguments):
        return self._run_fixed_adapter(session_id, state, action, payload, **arguments)

    def _execute_storage_remove_originals(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _reconcile_storage_quarantine(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_storage(session_id, operation, intent, payload, **arguments)

    def _reconcile_storage_purge(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_storage(session_id, operation, intent, payload, **arguments)

    def _reconcile_storage_remove_originals(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)
