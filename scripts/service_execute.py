"""Execution: the service's construction, the storage action, the binding of an approved action and the execute
dispatch over every adapter id (PLAN 3.3, RR4, D-071).

``execute_action`` takes the lock, checks the session and the exact approved binding, then calls the adapter's
private ``_execute_<id>`` method named in EXECUTE, looked up on the object. Each one is defined in its family's
module; an id whose family code is not written yet holds there. The targets and ``_run_fixed_adapter`` rely on
execute_action's checks: only execute_action reaches a target and only a target calls ``_run_fixed_adapter``
(CompositionTests). G11 refuses ``service._x`` from another object, not ``self._x`` in a mixin.
"""
from __future__ import annotations

import copy
from pathlib import Path, PurePosixPath

import pc_records
import storage_contract
from workflow_core import WorkflowEngine, digest, older_folder, no_links, STORAGE_ADAPTER
from storage_ops import StorageService, StorageRefusal, plan_sha256, restorable
from scoped_fs import ScopedFSError
from diagnostic_core import DiagnosticRefusal, validate_adapter_result
from diagnostic_posix import collect_recipe
from private_workspace import ensure_private_directory
from service_state import DEFAULT_ROOT, ServiceRefusal, decoded, private_read, read_service, service_value, within, without_version
from service_backup import verify_storage_artifact
from service_diagnostics import DIAGNOSTIC_ADAPTER_ID, DiagnosticStore

# The service's storage adapters: the engine action kind and the outcome-file name of each (the storage plan
# kind is storage_contract.PLAN_KINDS).
STORAGE = {
    pc_records.ADAPTER_STORAGE_BACKUP_CREATE: ("backup_create", "backup"),
    pc_records.ADAPTER_STORAGE_RESTORE: ("backup_restore", "restore"),
    pc_records.ADAPTER_STORAGE_QUARANTINE: ("cleanup_quarantine", "quarantine"),
    pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE: ("backup_restore", "quarantine-restore"),
    pc_records.ADAPTER_STORAGE_PURGE: ("permanent_purge", "purge"),
}
# Every adapter id's execute target: the name of a private WorkflowService method defined in the module of the
# id's family (pc_records.ADAPTERS[id]["family"]). Each takes (session_id, state, action, payload, **arguments)
# and gets execute_action's keywords unchanged.
EXECUTE = {
    pc_records.ADAPTER_STORAGE_BACKUP_CREATE: "_execute_storage_backup_create",
    pc_records.ADAPTER_STORAGE_RESTORE: "_execute_storage_restore",
    pc_records.ADAPTER_STORAGE_QUARANTINE: "_execute_storage_quarantine",
    pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE: "_execute_storage_quarantine_restore",
    pc_records.ADAPTER_STORAGE_PURGE: "_execute_storage_purge",
    pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS: "_execute_storage_remove_originals",
    pc_records.ADAPTER_STORAGE_RETENTION_RELEASE: "_execute_storage_retention_release",
    pc_records.ADAPTER_STORAGE_RETENTION_FORGET: "_execute_storage_retention_forget",
    pc_records.ADAPTER_STORAGE_SESSION_RELEASE: "_execute_storage_session_release",
    pc_records.ADAPTER_PACKAGE_UPGRADE: "_execute_package_upgrade",
    pc_records.ADAPTER_PACKAGE_REINSTALL: "_execute_package_reinstall",
    pc_records.ADAPTER_SYSTEM_REPAIR: "_execute_system_repair",
    pc_records.ADAPTER_DIAGNOSTIC_COLLECT: "_execute_diagnostic_collect",
    pc_records.ADAPTER_FIXTURE_ASSESSMENT: "_execute_fixture_assessment",
    pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL: "_execute_system_reviewed_external",
}


class ExecuteMixin:
    """Construction with the storage verifier, the storage action, the approved binding and execute_action."""

    def __init__(self, engine=None, *, work_relative="work/services"):
        self.engine = engine if engine is not None else self.default_engine()
        # The begin-time re-check of recovery and artifacts is always the storage verifier (D-018, F-178).
        if self.engine.verify_artifact is None:
            self.engine.verify_artifact = verify_storage_artifact
        elif self.engine.verify_artifact is not verify_storage_artifact:
            raise ServiceRefusal("The service drives only an engine whose re-check is the storage verifier", code="verifier-contract")
        self.root = self.engine.root
        if self.root != DEFAULT_ROOT and not within(self.root, DEFAULT_ROOT / "work"):
            raise ServiceRefusal("Development root must stay below this toolkit's work tree")
        rel = PurePosixPath(work_relative)
        if (not isinstance(work_relative, str) or rel.is_absolute() or "\\" in work_relative or len(rel.parts) < 2 or rel.parts[0] != "work"
                or any(part in {".", ".."} or not part.replace("-", "").replace("_", "").isalnum() for part in rel.parts)):
            raise ServiceRefusal("Safe named work child required")
        self.work = no_links(self.root.joinpath(*rel.parts))
        ensure_private_directory(self.work, create=True, parents=True, exist_ok=True)
        marker = self.work / "service.json"
        expected = service_value("service_marker", engine_id=self.engine.marker["engine_id"], backend=self.engine.marker["backend"])
        if not marker.exists():
            if any(self.work.iterdir()):
                raise ServiceRefusal("Missing service marker in nonempty storage; no recreation")
            self._immutable(marker, expected)
            self._immutable(self.work / "retention.json", service_value("retention_registry", entries=[]))
        if without_version(older_folder(work_relative, lambda: read_service(decoded(private_read(marker))))) != without_version(expected):
            raise ServiceRefusal("Foreign service/engine binding")
        self.diagnostics = DiagnosticStore(self.root, work_relative=work_relative + "/diagnostics")
        self._retention()

    @staticmethod
    def default_engine():
        """The engine this service drives, built with the storage verifier at its begin-time re-check."""
        return WorkflowEngine(verify_artifact=verify_storage_artifact)

    def _storage(self, state, payload):
        if payload["operation"] not in STORAGE or payload["mode"] != state["mode"]:
            raise ServiceRefusal("Unsupported storage adapter or mode")
        output = self._owned(payload["output_root"], state=state, existing=True)
        protections = payload["protected_roots"]
        if not isinstance(protections, list) or len(set(protections)) != len(protections) or not set(self.protected_roots()) <= set(protections):
            raise ServiceRefusal("Exact current protected retention policy must be included in the reviewed payload")
        plan = payload["storage_plan"]
        if plan.get("kind") != storage_contract.PLAN_KINDS[payload["operation"]] or plan_sha256(plan) != payload["storage_plan_sha256"]:
            raise ServiceRefusal("Wrong native plan type or changed exact plan hash")
        self._purge_original_recovery(payload)
        reservations = self._quarantine_reservations(state, payload, output, plan)
        service = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=protections)
        if "inventory" in plan:
            roots = [item["path"] for item in plan["inventory"]["roots"]]
        elif plan["kind"] == "restore":
            roots = [item["path"] for item in service.verify_backup(receipt=plan["receipt"])["manifest"]["source_roots"]]
        else:
            roots = [item["path"] for item in plan["receipt"]["source_roots"]]
        if any(within(Path(root), Path(binding["output_root"])) or within(Path(binding["output_root"]), Path(root))
               for root in roots for binding in reservations):
            raise ServiceRefusal("Reserved quarantine evidence and originals cannot become another plan's selected source scope")
        if sorted(roots) != sorted(state["settings"]["scope"]["roots"]):
            raise ServiceRefusal("Native source roots differ from the exact authorized workflow scope")
        if state["mode"] == "fixture" and any(not within(no_links(Path(root)), self.root / "work") for root in roots):
            raise ServiceRefusal("Fixture operations are confined to explicitly selected owned work copies")
        if "restore_probe_destination" in payload:
            probe = self._owned(payload["restore_probe_destination"], state=state)
            if payload["operation"] != pc_records.ADAPTER_STORAGE_BACKUP_CREATE or not within(probe, output) or probe == output or probe.exists():
                raise ServiceRefusal("Backup verification probe requires a new exact owned output child")
            if any(within(probe, Path(root)) or within(Path(root), probe) for root in roots):
                raise ServiceRefusal("Restore probe cannot overlap original sources")
            try:
                # Refused before the backup is written, not when the probe is planned after it.
                restorable(probe.relative_to(output).as_posix(), plan["files"])
            except StorageRefusal as error:
                raise ServiceRefusal(str(error), code=error.code) from error
        return service

    def prepare_storage_action(self, session_id, *, action_id, adapter_id, storage_plan, output_root,
            target, benefit, risk, reversibility, verification, protected_roots=None,
            recovery_evidence_ids=None, requires_os_consent=False, restore_probe_destination=None):
        with self._lock():
            state = self._state(session_id, collecting=True)
            if adapter_id not in STORAGE:
                raise ServiceRefusal("Unsupported fixed storage adapter")
            protections = sorted(set(self.protected_roots()) | set(protected_roots or []))
            payload = {"schema": STORAGE_ADAPTER, "schema_version": pc_records.SCHEMA_VERSION, "operation": adapter_id,
                       "storage_plan": copy.deepcopy(storage_plan), "storage_plan_sha256": plan_sha256(storage_plan),
                       "output_root": str(output_root), "mode": state["mode"], "protected_roots": protections}
            if restore_probe_destination is not None:
                payload["restore_probe_destination"] = str(restore_probe_destination)
            service = self._storage(state, payload)
            service.check_preconditions(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"])
            if adapter_id == pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE:
                if recovery_evidence_ids:
                    raise ServiceRefusal("Quarantine restoration uses its exact typed quarantine recovery; omit unrelated recovery evidence")
                recovery = self._quarantine_recovery(state, payload)
                recovery_evidence_ids = [recovery["evidence_id"]]
                payload["protected_roots"] = sorted(set(self.protected_roots()) | set(protected_roots or []))
            inventory = storage_plan.get("inventory", storage_plan.get("records", storage_plan.get("receipt")))
            kind = STORAGE[adapter_id][0]
            required = kind in {"backup_restore", "permanent_purge"} or storage_plan.get("recovery_required") is True
            action = self._action(state, action_id=action_id, adapter_id=adapter_id, kind=kind, payload=payload,
                    inventory=inventory, target=target, benefit=benefit, risk=risk, reversibility=reversibility,
                    verification=verification, requires_recovery=required,
                    recovery_evidence_ids=recovery_evidence_ids, requires_os_consent=requires_os_consent)
            if adapter_id == pc_records.ADAPTER_STORAGE_PURGE:
                self.engine.verify_recovery(self.engine.read_session(session_id), action["recovery_evidence_ids"], action=action)
            return action

    def _binding(self, state, action_id, plan_sha256_value):
        document = self.engine.current_plan(state, plan_sha256_value)
        actions = [a for a in document["actions"] if a["action_id"] == action_id]
        if len(actions) != 1:
            raise ServiceRefusal("Exact current action required")
        action = actions[0]
        payload = self.engine.action_binding(state, action)
        if action["adapter_id"] not in STORAGE and action["adapter_id"] not in {DIAGNOSTIC_ADAPTER_ID, pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL}:
            raise ServiceRefusal("No fixed service adapter exists for this action")
        if digest(payload) != action["adapter_payload_sha256"]:
            raise ServiceRefusal("Actual payload bytes differ from approved adapter payload")
        return action, payload

    def execute_action(self, session_id, *, action_id, plan_sha256, precondition_evidence_ids,
            owner_consent_evidence_id=None, diagnostic_fixture_runner=None, diagnostic_fixture_result=None):
        with self._lock():
            state = self._state(session_id)
            if state["status"] != "active" or state["stage"] != "apply" or self.engine.pending_items(state):
                raise ServiceRefusal("New adapter work waits for the active apply stage and every selected checkpoint")
            action, payload = self._binding(state, action_id, plan_sha256)
            return getattr(self, EXECUTE.get(action["adapter_id"], "_execute_held"))(
                session_id, state, action, payload, action_id=action_id, plan_sha256=plan_sha256,
                precondition_evidence_ids=precondition_evidence_ids, owner_consent_evidence_id=owner_consent_evidence_id,
                diagnostic_fixture_runner=diagnostic_fixture_runner, diagnostic_fixture_result=diagnostic_fixture_result)

    def _run_fixed_adapter(self, session_id, state, action, payload, *, action_id, plan_sha256, precondition_evidence_ids,
                           owner_consent_evidence_id, diagnostic_fixture_runner, diagnostic_fixture_result):
        """The fixed storage, diagnostic and reviewed-handoff path, called with execute_action's lock held, after its
        session and binding checks: preconditions, begin, intent, then the adapter effect and its outcome."""
        storage = None
        if action["adapter_id"] in STORAGE:
            if diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None:
                raise ServiceRefusal("Diagnostic injection is not a storage adapter input")
            storage = self._storage(state, payload)
            storage.check_preconditions(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"])
            if action["adapter_id"] == pc_records.ADAPTER_STORAGE_PURGE:
                self.engine.verify_recovery(state, action["recovery_evidence_ids"], action=action)
        elif action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
            if action["requires_os_consent"] is not True:
                raise ServiceRefusal("Fixed local installer dispatch requires actual protected OS consent for this exact action")
            self._external_sources(payload["external_plan"])
            self._external_preflight(state, action, payload, precondition_evidence_ids)
            if diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None:
                raise ServiceRefusal("External handoff cannot accept injected adapter output")
        elif state["mode"] != "fixture" and (diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None):
            raise ServiceRefusal("Fictional diagnostic output cannot enter a real operation")
        operation = self.engine.begin_operation(session_id, action_id=action_id, plan_sha256=plan_sha256,
                    precondition_evidence_ids=precondition_evidence_ids, owner_consent_evidence_id=owner_consent_evidence_id)["data"]
        path, intent = self._intent(state, operation, action, payload)
        current = self.engine.read_session(session_id)
        if current["status"] != "active":
            return self._finish(current, operation, outcome="failed",
                                receipt={"adapter_invoked": False, "reason": "Owner pause/stop reached before the first adapter effect"})
        if action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
            handoff = {**service_value("reviewed_external_handoff"), "operation_id": operation["operation_id"],
                       "action_id": action_id, "plan_sha256": plan_sha256, "adapter_payload_sha256": action["adapter_payload_sha256"],
                       "mode": state["mode"], "external_plan": payload["external_plan"],
                       "instruction": "Trusted coordinator performs only this exact reviewed official-tool operation through normal host "
                                      "permissions; report actual evidence. This helper executes nothing."}
            self._immutable(path / "handoff.json", handoff)
            return handoff
        self._immutable(path / "entered.json", service_value("effect_boundary", observed_utc=pc_records.utc_now(),
                                                             operation_id=operation["operation_id"], adapter_id=action["adapter_id"]))
        try:
            if storage is not None:
                plan, expected = payload["storage_plan"], payload["storage_plan_sha256"]
                self._native_origin(state, operation, plan)
                if payload["operation"] == pc_records.ADAPTER_STORAGE_BACKUP_CREATE:
                    if plan["required_recovery"]:
                        self._retain(session_id, {plan["destination"]: None, plan["destination"] + ".manifest.json": None},
                                     reason="Required backup reserved before effect; incomplete/unknown artifacts remain protected")
                    receipt = storage.create_backup(plan=plan, expected_plan_sha256=expected)
                elif payload["operation"] == pc_records.ADAPTER_STORAGE_RESTORE:
                    receipt = storage.restore_backup(plan=plan, expected_plan_sha256=expected)
                elif payload["operation"] == pc_records.ADAPTER_STORAGE_QUARANTINE:
                    self._reserve_quarantine(state, operation, action, payload, intent)
                    receipt = storage.quarantine(plan=plan, expected_plan_sha256=expected)
                elif payload["operation"] == pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE:
                    receipt = storage.restore_quarantine(plan=plan, expected_plan_sha256=expected)
                else:
                    receipt = storage.purge_quarantine(plan=plan, expected_plan_sha256=expected)
                verified = storage.verify_outcome(plan=plan, expected_plan_sha256=expected, receipt=receipt)
                result = {"native_receipt": receipt, "verification": verified}
                if "restore_probe_destination" in payload:
                    probe = storage.plan_restore(receipt=receipt, destination=payload["restore_probe_destination"])
                    self._immutable(path / "restore-probe-plan.json", probe)
                    self._native_origin(state, operation, probe, substep=True)
                    self._retain(session_id, {str(Path(probe["destination"]) / f["root_id"] / f["relative_path"]): f["sha256"] for f in probe["files"]},
                                 reason="Exact restoration-probe files reserved before their reviewed verification write")
                    restoration = storage.restore_backup(plan=probe, expected_plan_sha256=digest(probe))
                    result["restore_probe_receipt"] = restoration
                    result["restore_probe_verification"] = storage.verify_outcome(plan=probe, expected_plan_sha256=digest(probe), receipt=restoration)
                    result["recovery_evidence"] = self._register_recovery(session_id, payload["output_root"], receipt, restoration, completing=True)
                return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded", receipt=result)
            request = payload["request"]
            if request["platform"] == "windows" and diagnostic_fixture_result is None:
                handoff = {**service_value("windows_diagnostic_handoff"), "operation_id": operation["operation_id"],
                           "request": request, "helper": "diagnostic_windows.ps1:Invoke-WindowsDiagnostic",
                           "instruction": "Use this fixed native helper in the matching host; return its selected actual adapter result. "
                                          "No generic command is accepted."}
                self._immutable(path / "handoff.json", handoff)
                return handoff
            observed = (validate_adapter_result(request, diagnostic_fixture_result) if diagnostic_fixture_result is not None
                        else collect_recipe(request, runner=diagnostic_fixture_runner, coordinator_authorized=state["mode"] == "real"))
            record = self.diagnostics.record_result(request["request_id"], adapter_result=observed)
            return self._finish(self.engine.read_session(session_id), operation,
                                outcome="succeeded" if observed["status"] == "observed" else "failed", receipt=record)
        except (StorageRefusal, ScopedFSError, DiagnosticRefusal, OSError, ValueError) as exc:
            # A move/write can finish before its receipt. Error text may
            # contain private paths. Preserve only a categorical failure.
            return self._finish(self.engine.read_session(session_id), operation, outcome="unknown",
                    receipt={"adapter_invoked": True, "failure_class": type(exc).__name__, "possible_partial_effects": True,
                             "failure_code": getattr(exc, "code", None),
                             "instruction": "Preserve exact intent, native attempt/mapping and outputs; inspect actual state before any new plan."})
