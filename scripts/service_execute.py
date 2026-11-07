"""Execution: the service's construction, the storage action, the binding of an approved action and the execute
dispatch over every adapter id.

``execute_action`` takes the lock, checks the session and the exact approved binding, then calls the adapter's
private ``_execute_<id>`` method named in EXECUTE, looked up on the object. Each one is defined in its family's
module, next to the adapter's ``_effect_<id>``; an id whose family code is not written yet holds there. The targets
and the shared steps defined here (``_storage_preconditions``, ``_begin_adapter``, ``_run_effect`` and
``_run_adapter``) rely on execute_action's checks: only execute_action reaches a target, only a target calls a shared
step (``_run_adapter`` calls the begin and effect steps; the package ticket run also calls the effect step), and each
``_effect_<id>`` is named only by its own target. No change to files or software begins while this process runs
elevated (administrator or root): ``_begin_adapter`` asks ``self.elevation_probe`` first for every family but
assessment. The last step before any effect is the engine's admission (``_run_effect``): a pause or stop either stops
the effect there or arrives after it and finds active work.
"""
from __future__ import annotations

import copy
from pathlib import Path, PurePosixPath

import pc_records
import scoped_base
import scoped_fs
import storage_contract
from workflow_core import WorkflowEngine, WorkflowRefusal, digest, older_folder, no_links, STORAGE_ADAPTER
from storage_ops import StorageService, StorageRefusal, plan_sha256, restorable
from storage_policy import MAX_FILE_BYTES
from scoped_fs import ScopedFSError
from diagnostic_core import DiagnosticRefusal
from private_workspace import ensure_private_directory, relative_parts
from service_state import DEFAULT_ROOT, ServiceRefusal, apart, decoded, private_read, read_service, service_value, within, without_version
from service_backup import verify_storage_artifact
from service_diagnostics import DiagnosticStore

# The service's storage adapters: the engine action kind and the outcome-file name of each (the storage plan
# kind is storage_contract.PLAN_KINDS).
STORAGE = {
    pc_records.ADAPTER_STORAGE_BACKUP_CREATE: ("backup_create", "backup"),
    pc_records.ADAPTER_STORAGE_RESTORE: ("backup_restore", "restore"),
    pc_records.ADAPTER_STORAGE_QUARANTINE: ("cleanup_quarantine", "quarantine"),
    pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE: ("backup_restore", "quarantine-restore"),
    pc_records.ADAPTER_STORAGE_PURGE: ("permanent_purge", "purge"),
    pc_records.ADAPTER_STORAGE_DELETE_SELECTED: ("delete_selected", "deletion"),
    pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS: ("remove_originals", "removal"),
    pc_records.ADAPTER_STORAGE_RETENTION_RELEASE: ("retention_release", "retention-release"),
    pc_records.ADAPTER_STORAGE_SESSION_RELEASE: ("session_release", "session-release"),
    pc_records.ADAPTER_STORAGE_RETENTION_FORGET: ("retention_forget", "retention-forget"),
}
# The retention adapters among them: their plans name kept registry rows (service_retention), not files a storage
# family plans, so they have their own checks and no storage-layer preconditions.
RETENTION = frozenset({pc_records.ADAPTER_STORAGE_RETENTION_RELEASE, pc_records.ADAPTER_STORAGE_SESSION_RELEASE,
                       pc_records.ADAPTER_STORAGE_RETENTION_FORGET})
# The refusal of a change while this process runs elevated.
ELEVATED = ("PatchCairn does not change files or software while it runs as administrator or root. Start it again from your "
            "normal user account; nothing was changed.")
# A backup too large for its optional restore test: the test restores in memory, within the two limits that _storage checks.
RESTORE_TOO_LARGE = ("This backup is too big for PatchCairn's optional restore test. Nothing was changed. Make the plan again without the "
                     "restore test: the backup itself is still checked.")
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
    pc_records.ADAPTER_STORAGE_DELETE_SELECTED: "_execute_storage_delete_selected",
    pc_records.ADAPTER_PACKAGE_UPGRADE: "_execute_package_upgrade",
    pc_records.ADAPTER_PACKAGE_REINSTALL: "_execute_package_reinstall",
    pc_records.ADAPTER_SYSTEM_REPAIR: "_execute_system_repair",
    pc_records.ADAPTER_SYSTEM_UPDATE_HANDOFF: "_execute_system_update_handoff",
    pc_records.ADAPTER_SYSTEM_FIRMWARE_UPDATE: "_execute_system_firmware_update",
    pc_records.ADAPTER_DIAGNOSTIC_COLLECT: "_execute_diagnostic_collect",
    pc_records.ADAPTER_FIXTURE_ASSESSMENT: "_execute_fixture_assessment",
}


def _volume_identity(path):
    """The default volume lookup of a kept row's drive: scoped_fs.volume_identity, looked up when it is called."""
    return scoped_fs.volume_identity(path)


def _deletion_size(adapter_id, plan):
    """storage_contract.deletion_size, its refusal kept as the service's own (same code and text)."""
    try:
        return storage_contract.deletion_size(adapter_id, plan)
    except pc_records.Refusal as error:
        raise ServiceRefusal(str(error), code=error.code) from error


class ExecuteMixin:
    """Construction with the storage verifier, the storage action, the approved binding and execute_action."""

    def __init__(self, engine=None, *, work_relative="work/services", elevation_probe=scoped_fs.process_is_elevated,
                 volume_lookup=_volume_identity):
        """``elevation_probe()`` is True while this process runs elevated; ``volume_lookup(path)`` gives the identity of
        the volume holding an existing path, or None. Both stay public attributes so a test can replace them."""
        if not callable(elevation_probe) or not callable(volume_lookup):
            raise ServiceRefusal("The elevation probe and the volume lookup must be callables")
        self.elevation_probe, self.volume_lookup = elevation_probe, volume_lookup
        self.engine = engine if engine is not None else self.default_engine()
        # The begin-time re-check of recovery and artifacts is always the storage verifier.
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
        # The typed reply named this number and size, so they must be exactly what the reviewed plan deletes.
        if (payload.get("delete_count"), payload.get("delete_bytes")) != _deletion_size(payload["operation"], payload["storage_plan"]):
            raise ServiceRefusal("The deletion's number of items or size differs from the reviewed plan")
        output = self._owned(payload["output_root"], state=state, existing=True)
        protections = payload["protected_roots"]
        if not isinstance(protections, list) or len(set(protections)) != len(protections) or not set(self.protected_roots()) <= set(protections):
            raise ServiceRefusal("Exact current protected retention policy must be included in the reviewed payload")
        plan = payload["storage_plan"]
        if plan.get("kind") != storage_contract.PLAN_KINDS[payload["operation"]] or plan_sha256(plan) != payload["storage_plan_sha256"]:
            raise ServiceRefusal("Wrong native plan type or changed exact plan hash")
        destination = payload.get("backup_destination")
        if destination is not None:
            if payload["operation"] != pc_records.ADAPTER_STORAGE_BACKUP_CREATE or destination not in protections:
                raise ServiceRefusal("Only a backup names a chosen destination, and that folder must be one of its protected roots")
            self._destination_root(state, payload)
        if payload["operation"] in RETENTION:
            if output != self.work:
                raise ServiceRefusal("A retention action records its outcome in this service's own work folder")
            self._retention_checks(state, payload)
            return None
        self._purge_original_recovery(payload)
        reservations = self._quarantine_reservations(state, payload, output, plan)
        service = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=protections)
        if "inventory" in plan:
            roots = [item["path"] for item in plan["inventory"]["roots"]]
        elif plan["kind"] == "restore":
            roots = [item["path"] for item in service.verify_backup(receipt=plan["receipt"])["manifest"]["source_roots"]]
        else:
            roots = [item["path"] for item in plan["receipt"]["source_roots"]]
        if any(not apart(root, binding["output_root"]) for root in roots for binding in reservations):
            raise ServiceRefusal("Reserved quarantine evidence and originals cannot become another plan's selected source scope")
        if sorted(roots) != sorted(state["settings"]["scope"]["roots"]):
            raise ServiceRefusal("Native source roots differ from the exact authorized workflow scope")
        if state["mode"] == "fixture" and any(not within(no_links(Path(root)), self.root / "work") for root in roots):
            raise ServiceRefusal("Fixture operations are confined to explicitly selected owned work copies")
        if "restore_probe_destination" in payload:
            probe = self._owned(payload["restore_probe_destination"], state=state)
            if payload["operation"] != pc_records.ADAPTER_STORAGE_BACKUP_CREATE or not relative_parts(probe, output) or probe.exists():
                raise ServiceRefusal("Backup verification probe requires a new exact owned output child")
            if any(not apart(probe, root) for root in roots):
                raise ServiceRefusal("Restore probe cannot overlap original sources")
            if (plan["cost"]["archive_bytes_at_most"] > scoped_base.MAX_CONTROL_BYTES
                    or any(row["size"] > MAX_FILE_BYTES for row in plan["files"])):
                raise ServiceRefusal(RESTORE_TOO_LARGE, code="restore-size-unavailable")
            try:
                # Refused before the backup is written, not when the probe is planned after it.
                restorable(probe.relative_to(output).as_posix(), plan["files"])
            except StorageRefusal as error:
                raise ServiceRefusal(str(error), code=error.code) from error
        if destination is not None:
            # The chosen drive admitted (service_backup) in addition to the owned output root. The storage service owns that
            # root from here: whoever holds the service closes it (prepare_storage_action, _storage_preconditions, the target).
            service = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=protections,
                                     backup_destination=self._admit_backup_destination(state, payload))
        return service

    def prepare_storage_action(self, session_id, *, action_id, adapter_id, storage_plan, output_root,
            target, benefit, risk, reversibility, verification, protected_roots=None,
            recovery_evidence_ids=None, requires_os_consent=False, restore_probe_destination=None, backup_destination=None):
        """The engine action of one storage plan. A permanent deletion's payload carries the number of items and bytes
        its plan deletes (the typed reply names them); a backup to a chosen drive carries ``backup_destination``, which
        also becomes one of the protected roots."""
        with self._lock():
            state = self._state(session_id, collecting=True)
            if adapter_id not in STORAGE:
                raise ServiceRefusal("Unsupported fixed storage adapter")
            chosen = [] if backup_destination is None else [str(backup_destination)]
            protections = sorted(set(self.protected_roots()) | set(protected_roots or []) | set(chosen))
            payload = {"schema": STORAGE_ADAPTER, "schema_version": pc_records.SCHEMA_VERSION, "operation": adapter_id,
                       "storage_plan": copy.deepcopy(storage_plan), "storage_plan_sha256": plan_sha256(storage_plan),
                       "output_root": str(output_root), "mode": state["mode"], "protected_roots": protections}
            if restore_probe_destination is not None:
                payload["restore_probe_destination"] = str(restore_probe_destination)
            if chosen:
                payload["backup_destination"] = chosen[0]
            count, size = _deletion_size(adapter_id, payload["storage_plan"])
            if count is not None:
                payload.update(delete_count=count, delete_bytes=size)
            service = self._storage(state, payload)
            if adapter_id not in RETENTION:
                try:
                    service.check_preconditions(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"])
                finally:
                    service.close()
            if adapter_id == pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE:
                if recovery_evidence_ids:
                    raise ServiceRefusal("Quarantine restoration uses its exact typed quarantine recovery; omit unrelated recovery evidence")
                recovery = self._quarantine_recovery(state, payload)
                recovery_evidence_ids = [recovery["evidence_id"]]
                payload["protected_roots"] = sorted(set(self.protected_roots()) | set(protected_roots or []) | set(chosen))
            inventory = storage_plan.get("inventory", storage_plan.get("records", storage_plan.get("receipt")))
            kind = STORAGE[adapter_id][0]
            required = kind in {"backup_restore", "permanent_purge"} or storage_plan.get("recovery_required") is True
            action = self._action(state, action_id=action_id, adapter_id=adapter_id, kind=kind, payload=payload,
                    native_plan=payload["storage_plan"], inventory=inventory, target=target, benefit=benefit,
                    risk=" ".join(filter(None, (risk, storage_plan.get("privacy_note")))), reversibility=reversibility,
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
        # Every id with an execute target binds here; a family whose code is not written yet holds in its target.
        if action["adapter_id"] not in EXECUTE:
            raise ServiceRefusal("No fixed service adapter exists for this action")
        if digest(payload) != action["adapter_payload_sha256"]:
            raise ServiceRefusal("Actual payload bytes differ from approved adapter payload")
        return action, payload

    def execute_action(self, session_id, *, action_id, plan_sha256, precondition_evidence_ids,
            diagnostic_fixture_runner=None, diagnostic_fixture_result=None):
        with self._lock():
            state = self._state(session_id)
            if state["status"] != "active" or state["stage"] != "apply" or self.engine.pending_items(state):
                raise ServiceRefusal("New adapter work waits for the active apply stage and every selected checkpoint")
            action, payload = self._binding(state, action_id, plan_sha256)
            return getattr(self, EXECUTE.get(action["adapter_id"], "_execute_held"))(
                session_id, state, action, payload, action_id=action_id, plan_sha256=plan_sha256,
                precondition_evidence_ids=precondition_evidence_ids,
                diagnostic_fixture_runner=diagnostic_fixture_runner, diagnostic_fixture_result=diagnostic_fixture_result)

    def _refuse_while_elevated(self, adapter_id):
        """Refuse a change of files or software (every family but assessment) while ``self.elevation_probe()`` is not
        exactly False: an elevated process, or one whose elevation cannot be told, changes nothing. A retired adapter id,
        which an old operation may still name, counts as a change."""
        if pc_records.ADAPTERS.get(adapter_id, {}).get("family") != "assessment" and self.elevation_probe() is not False:
            raise ServiceRefusal(ELEVATED, code="process-elevated")

    # The shared steps of the fixed adapters. Each is called with execute_action's lock held, after its session and
    # binding checks: a target runs its own preconditions, then _run_adapter (or _begin_adapter alone), and _run_effect
    # runs the target's _effect_<id> after the effect boundary.
    def _storage_preconditions(self, state, action, payload, *, diagnostic_fixture_runner, diagnostic_fixture_result):
        """A storage target's preconditions before begin; returns the storage service its effect uses, which the target
        then closes (None for a retention action, whose checks are its own). A failed check closes it here."""
        if diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None:
            raise ServiceRefusal("Diagnostic injection is not a storage adapter input")
        storage = self._storage(state, payload)
        if action["adapter_id"] in RETENTION:
            return None
        try:
            storage.check_preconditions(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"])
            if action["adapter_id"] == pc_records.ADAPTER_STORAGE_PURGE:
                self.engine.verify_recovery(state, action["recovery_evidence_ids"], action=action)
        except BaseException:
            storage.close()
            raise
        return storage

    def _begin_adapter(self, session_id, state, action, payload, *, action_id, plan_sha256, precondition_evidence_ids,
                       owner_consent_evidence_id):
        """The elevation refusal, then begin, intent, the protection of a chosen backup destination, and the session
        re-read: (operation, path, intent, stopped). ``stopped`` is the consumed "failed" response when the owner paused
        or stopped before the first effect, or the chosen destination could not be protected, otherwise None."""
        self._refuse_while_elevated(action["adapter_id"])
        operation = self.engine.begin_operation(session_id, action_id=action_id, plan_sha256=plan_sha256,
                    precondition_evidence_ids=precondition_evidence_ids, owner_consent_evidence_id=owner_consent_evidence_id)["data"]
        path, intent = self._intent(state, operation, action, payload)
        if payload.get("backup_destination") is not None:
            try:
                self._register_destination(state, payload)
            except ServiceRefusal as error:
                return operation, path, intent, self._finish(self.engine.read_session(session_id), operation, outcome="failed",
                                                             receipt={"adapter_invoked": False, "reason": error.code})
        current = self.engine.read_session(session_id)
        if current["status"] != "active":
            return operation, path, intent, self._finish(current, operation, outcome="failed",
                                receipt={"adapter_invoked": False, "reason": "Owner pause/stop reached before the first adapter effect"})
        return operation, path, intent, None

    def _run_effect(self, session_id, state, operation, action, payload, path, intent, effect, *, paused_receipt=None, **effect_arguments):
        """The engine's admission, then the effect boundary (entered.json), then ``effect``, an ``_effect_<id>`` method,
        with the effect arguments. A pause or stop the admission refuses finishes the operation "failed" with no boundary
        and no effect, with ``paused_receipt`` when the caller gives one. The effect's listed failures finish it as "unknown"
        with a categorical receipt; others propagate."""
        try:
            self.engine.admit_effect(session_id, operation_id=operation["operation_id"])
        except WorkflowRefusal as error:
            if error.code != "effect-paused":
                raise
            return self._finish(self.engine.read_session(session_id), operation, outcome="failed", receipt=paused_receipt or {
                "adapter_invoked": False, "reason": "Owner pause/stop reached before the first adapter effect"})
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
                     owner_consent_evidence_id=None, **effect_arguments):
        """_begin_adapter, then its paused response if the owner paused, otherwise _run_effect with ``effect``."""
        operation, path, intent, stopped = self._begin_adapter(session_id, state, action, payload, action_id=action_id, plan_sha256=plan_sha256,
                                                               precondition_evidence_ids=precondition_evidence_ids,
                                                               owner_consent_evidence_id=owner_consent_evidence_id)
        if stopped is not None:
            return stopped
        return self._run_effect(session_id, state, operation, action, payload, path, intent, effect, **effect_arguments)
