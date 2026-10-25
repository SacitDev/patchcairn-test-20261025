"""Execution: the service's construction, the storage action, the binding of an approved action and the execute
dispatch over every adapter id (PLAN 3.3, RR4, D-071).

``execute_action`` takes the lock, checks the session and the exact approved binding, then calls the adapter's
private ``_execute_<id>`` method named in EXECUTE, looked up on the object. Each one is defined in its family's
module, next to the adapter's ``_effect_<id>``; an id whose family code is not written yet holds there. The targets
and the shared steps defined here (``_storage_preconditions``, ``_begin_adapter``, ``_run_effect`` and
``_run_adapter``) rely on execute_action's checks: only execute_action reaches a target, only a target calls a shared
step (``_run_adapter`` calls the begin and effect steps), and each ``_effect_<id>`` is named only by its own target
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
from diagnostic_core import DiagnosticRefusal
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
                    native_plan=payload["storage_plan"], inventory=inventory, target=target, benefit=benefit, risk=risk, reversibility=reversibility,
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

    # The shared steps of the fixed adapters. Each is called with execute_action's lock held, after its session and
    # binding checks: a target runs its own preconditions, then _run_adapter (or, for the reviewed handoff,
    # _begin_adapter alone), and _run_effect runs the target's _effect_<id> after the effect boundary.
    def _storage_preconditions(self, state, action, payload, *, diagnostic_fixture_runner, diagnostic_fixture_result):
        """A storage target's preconditions before begin; returns the storage service its effect uses."""
        if diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None:
            raise ServiceRefusal("Diagnostic injection is not a storage adapter input")
        storage = self._storage(state, payload)
        storage.check_preconditions(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"])
        if action["adapter_id"] == pc_records.ADAPTER_STORAGE_PURGE:
            self.engine.verify_recovery(state, action["recovery_evidence_ids"], action=action)
        return storage

    def _begin_adapter(self, session_id, state, action, payload, *, action_id, plan_sha256, precondition_evidence_ids,
                       owner_consent_evidence_id):
        """Begin, intent, then the session re-read: (operation, path, intent, stopped). ``stopped`` is the consumed "failed"
        response when the owner paused or stopped before the first effect, otherwise None."""
        operation = self.engine.begin_operation(session_id, action_id=action_id, plan_sha256=plan_sha256,
                    precondition_evidence_ids=precondition_evidence_ids, owner_consent_evidence_id=owner_consent_evidence_id)["data"]
        path, intent = self._intent(state, operation, action, payload)
        current = self.engine.read_session(session_id)
        if current["status"] != "active":
            return operation, path, intent, self._finish(current, operation, outcome="failed",
                                receipt={"adapter_invoked": False, "reason": "Owner pause/stop reached before the first adapter effect"})
        return operation, path, intent, None

    def _run_effect(self, session_id, state, operation, action, payload, path, intent, effect, **effect_arguments):
        """Write the effect boundary (entered.json), then run ``effect``, an ``_effect_<id>`` method, with the effect
        arguments. Its listed failures finish the operation as "unknown" with a categorical receipt; others propagate."""
        self._immutable(path / "entered.json", service_value("effect_boundary", observed_utc=pc_records.utc_now(),
                                                             operation_id=operation["operation_id"], adapter_id=action["adapter_id"]))
        try:
            return effect(session_id, state, operation, action, payload, path, intent, **effect_arguments)
        except (StorageRefusal, ScopedFSError, DiagnosticRefusal, OSError, ValueError) as exc:
            # A move/write can finish before its receipt. Error text may
            # contain private paths. Preserve only a categorical failure.
            return self._finish(self.engine.read_session(session_id), operation, outcome="unknown",
                    receipt={"adapter_invoked": True, "failure_class": type(exc).__name__, "possible_partial_effects": True,
                             "failure_code": getattr(exc, "code", None),
                             "instruction": "Preserve exact intent, native attempt/mapping and outputs; inspect actual state before any new plan."})

    def _run_adapter(self, session_id, state, action, payload, effect, *, action_id, plan_sha256, precondition_evidence_ids,
                     owner_consent_evidence_id, **effect_arguments):
        """_begin_adapter, then its paused response if the owner paused, otherwise _run_effect with ``effect``."""
        operation, path, intent, stopped = self._begin_adapter(session_id, state, action, payload, action_id=action_id, plan_sha256=plan_sha256,
                                                               precondition_evidence_ids=precondition_evidence_ids,
                                                               owner_consent_evidence_id=owner_consent_evidence_id)
        if stopped is not None:
            return stopped
        return self._run_effect(session_id, state, operation, action, payload, path, intent, effect, **effect_arguments)
