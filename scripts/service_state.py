"""Service state: the refusal, the service record readers and helpers, and the private store, session state,
evidence, intent and outcome methods every service module builds on (PLAN 3.1, L4).

The base of the service modules: it imports no other service module.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sys
import uuid

import pc_records
from workflow_core import (encoded, digest, read_record_bytes, decode_record, no_links, exact_fields, record_identifier,
                           EVIDENCE_MAX_BYTES, EVIDENCE_MAX_NODES, SERVICE_RECORD)
from diagnostic_core import sanitize_text
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, write_private_new

RESERVATION_RECORD = "patchcairn.quarantine.reservation"
# Every service record is a kind of patchcairn.service.
SERVICE_KINDS = frozenset({"service_marker", "retention_registry", "required_retention", "operation_intent", "intent_evidence",
                           "native_origin", "service_outcome", "reviewed_external_handoff", "windows_diagnostic_handoff",
                           "effect_boundary"})
_RESERVATION_FIELDS = {"schema", "schema_version", "engine_id", "mode", "platform", "session_id", "operation_id",
                       "workflow_plan_sha256", "adapter_payload_sha256", "native_plan_sha256", "output_root",
                       "original_plan", "quarantine_mapping", "intent_sha256", "native_origin_sha256"}
DEFAULT_ROOT = Path(__file__).absolute().parent.parent


class ServiceRefusal(pc_records.Refusal):
    """Preserve a held/consumed operation; no weaker fallback or retry."""

    def __init__(self, message, *, code="service-refusal"):
        super().__init__(code, message)


def _schema(record, name):
    """``record`` checked by pc_records for the family ``name``; a refusal keeps its code."""
    try:
        return pc_records.require_schema(record, name)
    except pc_records.Refusal as error:
        raise ServiceRefusal(str(error), code=error.code) from error


def read_service(record):
    """The registered reader of patchcairn.service records: the schema check and a known kind."""
    _schema(record, SERVICE_RECORD)
    if record.get("kind") not in SERVICE_KINDS:
        raise ServiceRefusal("Unknown service record kind")
    return record


def read_reservation(record):
    """The registered reader of quarantine reservations: the schema check and the exact fields."""
    _schema(record, RESERVATION_RECORD)
    exact_fields(record, _RESERVATION_FIELDS, _RESERVATION_FIELDS)
    return record


pc_records.register_reader(SERVICE_RECORD, read_service)
pc_records.register_reader(RESERVATION_RECORD, read_reservation)


def service_record(record, kind):
    """A service record of ``kind`` (pc_records schema check, then the kind)."""
    read_service(record)
    if record["kind"] != kind:
        raise ServiceRefusal("Unexpected service record kind")
    return record


def service_value(kind, **fields):
    return {"schema": SERVICE_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": kind, **fields}


def without_version(record):
    rest = dict(record)
    rest.pop("schema_version", None)
    return rest


def native_platform():
    return "windows" if sys.platform == "win32" else "macos" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "unknown"


def within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def selected_text(value):
    clean = sanitize_text(value, limit=2000)
    if not clean or clean != value.strip():
        raise ServiceRefusal("Provide selected nonsecret text without private paths or credential-like values")
    return clean


def decoded(data):
    """A service record decoded strictly; it may hold per-file lists up to the engine's evidence bound."""
    return decode_record(data, max_bytes=EVIDENCE_MAX_BYTES, max_nodes=EVIDENCE_MAX_NODES)


def private_read(path, max_bytes=EVIDENCE_MAX_BYTES):
    ensure_private_file(path)
    return read_record_bytes(path, max_bytes)


class StateMixin:
    """The private service store, session state, evidence registration, operation intent and outcome."""

    @staticmethod
    def _immutable(path, value):
        no_links(path)
        data = encoded(value)
        if len(data) > EVIDENCE_MAX_BYTES:
            raise ServiceRefusal("Service record cap exceeded")
        write_private_new(path, data)
        return {"path": str(path), "sha256": digest(data)}

    @contextmanager
    def _lock(self):
        path = self.work / ".coordinator-lock"
        try:
            ensure_private_directory(path, create=True)
        except FileExistsError as exc:
            raise ServiceRefusal("Service is active or interrupted; inspect before another action") from exc
        except PrivateWorkspaceError as exc:
            if exc.code == "private-directory-exists":
                raise ServiceRefusal("Service is active or interrupted; inspect before another action") from None
            raise
        try:
            yield
        finally:
            path.rmdir()

    def _state(self, session_id, *, collecting=False):
        ensure_private_directory(self.work)
        state = self.engine.read_session(session_id)
        if collecting and (state["status"] not in {"active", "awaiting_user"} or not state["scope_authorization"]):
            raise ServiceRefusal("Current selected collection scope and active session required")
        if collecting:
            self.engine.require_schedule_activation(state)
        if state["mode"] == "real" and state["platform"] != native_platform():
            raise ServiceRefusal("Real service requires the actual matching native platform")
        return state

    def _owned(self, value, *, state=None, existing=False):
        if not isinstance(value, str) or not Path(value).is_absolute() or ".." in Path(value).parts:
            raise ServiceRefusal("Exact absolute owned-work path required")
        path = no_links(Path(value))
        if path == self.root / "work" or not within(path, self.root / "work"):
            raise ServiceRefusal("Output must remain below this engine's owned work root")
        if existing and not path.is_dir():
            raise ServiceRefusal("Existing positively owned output directory required")
        return path

    def _register(self, state, *, kind, value, facts=None, observed_utc=None):
        evidence_id = "service-" + uuid.uuid4().hex
        return self.engine.register_evidence(state["session_id"], evidence_id=evidence_id, content=encoded(value),
                kind=kind, scope=state["settings"]["scope"], facts=facts or {}, observed_utc=observed_utc)["data"]

    def _action(self, state, *, action_id, adapter_id, kind, payload, native_plan, inventory, target, benefit, risk,
                reversibility, verification, requires_recovery=False, recovery_evidence_ids=None, requires_os_consent=False):
        """The engine action for ``payload``; ``native_plan`` is the lower-level plan inside it that the action's
        adapter_plan_sha256 binds (each caller names its own)."""
        record_identifier(action_id)
        prose = {key: selected_text(value) for key, value in (("target", target), ("benefit", benefit), ("risk", risk),
                                                              ("reversibility", reversibility), ("verification", verification))}
        inventory_row = self._register(state, kind="inventory", value=inventory, facts={
            "complete": True, "item_count": len(inventory.get("entries", inventory.get("records", []))) if isinstance(inventory, dict) else 1})
        payload_row = self._register(state, kind="adapter_payload", value=payload)
        return {"action_id": action_id, "kind": kind, **prose, "mutating": kind != "assessment",
                "requires_os_consent": requires_os_consent, "requires_recovery": requires_recovery,
                "recovery_evidence_ids": recovery_evidence_ids or [], "adapter_id": adapter_id,
                "adapter_payload_evidence_id": payload_row["evidence_id"], "adapter_payload_sha256": payload_row["sha256"],
                "adapter_plan_sha256": digest(native_plan), "target_inventory_evidence_id": inventory_row["evidence_id"],
                "target_inventory_sha256": inventory_row["sha256"]}

    def _operation_dir(self, session_id, operation_id, *, create=False):
        record_identifier(session_id); record_identifier(operation_id)
        path = no_links(self.work / "operations" / session_id / operation_id)
        if create:
            ensure_private_directory(self.work)
            ensure_private_directory(self.work / "operations", create=True, exist_ok=True)
            ensure_private_directory(self.work / "operations" / session_id, create=True, exist_ok=True)
            ensure_private_directory(path, create=True)
        elif not path.is_dir():
            raise ServiceRefusal("Missing service operation intent; no recreation or retry")
        else:
            ensure_private_directory(self.work)
            ensure_private_directory(self.work / "operations")
            ensure_private_directory(self.work / "operations" / session_id)
            ensure_private_directory(path)
        return path

    def _intent(self, state, operation, action, payload):
        path = self._operation_dir(state["session_id"], operation["operation_id"], create=True)
        mapping = []
        if payload["operation"] == pc_records.ADAPTER_STORAGE_QUARANTINE:
            mapping = self._quarantine_mapping(payload["storage_plan"])
        value = service_value("operation_intent", session_id=state["session_id"],
                              engine_id=state["engine_id"], mode=state["mode"], platform=state["platform"],
                              settings_revision=state["settings_revision"], scope=state["settings"]["scope"],
                              operation=operation, action=action, payload=payload, quarantine_mapping=mapping,
                              observed_utc=pc_records.utc_now())
        self._immutable(path / "intent.json", value)
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        facts["outcome"] = "unknown"
        row = self._register(state, kind="outcome", value=value, facts=facts)
        self._immutable(path / "intent-evidence.json", service_value("intent_evidence", evidence_id=row["evidence_id"], sha256=row["sha256"]))
        return path, value

    def _native_origin(self, state, operation, plan, *, substep=False):
        value = service_value("native_origin", engine_id=state["engine_id"], mode=state["mode"],
                              platform=state["platform"], session_id=state["session_id"],
                              operation_id=operation["operation_id"], workflow_plan_sha256=operation["plan_sha256"],
                              native_plan_sha256=digest(plan), verification_substep=substep)
        self._immutable(self.work / ("origin-" + digest(plan) + ".json"), value)

    def _finish(self, state, operation, *, outcome, receipt, kind="outcome"):
        state = self.engine.read_session(state["session_id"])
        path = self._operation_dir(state["session_id"], operation["operation_id"])
        self._original_authority(state, operation, service_record(decoded(private_read(path / "intent.json")), "operation_intent"))
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        facts["outcome"] = outcome
        value = service_value("service_outcome", mode=state["mode"], observed_utc=pc_records.utc_now(), binding=facts, receipt=receipt)
        self._immutable(path / ("result-" + uuid.uuid4().hex + ".json"), value)
        evidence = self._register(state, kind=kind, value=value, facts=facts, observed_utc=value["observed_utc"])
        if kind == "reconciliation":
            response = self.engine.resolve(state["session_id"], pending_id="reconcile-" + operation["operation_id"], evidence_ids=[evidence["evidence_id"]])
        else:
            response = self.engine.finish_operation(state["session_id"], operation_id=operation["operation_id"], outcome=outcome,
                        evidence_ids=[evidence["evidence_id"]],
                        summary="Selected fixed adapter outcome: " + outcome + ". Original behavior/security verification remains separate.")
        return {"operation_id": operation["operation_id"], "outcome": outcome, "receipt": receipt,
                "evidence_id": evidence["evidence_id"], "workflow": response}

    @staticmethod
    def _original_authority(state, operation, intent):
        original = intent.get("operation")
        current = state.get("operations", {}).get(operation.get("operation_id"))
        fields = {"operation_id", "action_id", "plan_sha256", "settings_revision", "started_utc", "adapter_id", "mutating"}
        if (not isinstance(original, dict) or not isinstance(current, dict)
                or any(key not in original or key not in current or key not in operation
                       or original[key] != current[key] or operation[key] != current[key] for key in fields)
                or intent.get("settings_revision") != state.get("settings_revision")
                or original["settings_revision"] != state.get("settings_revision")
                or not isinstance(intent.get("scope"), dict) or intent["scope"] != state.get("settings", {}).get("scope")
                or any(intent.get(key) != state.get(key) for key in ("engine_id", "mode", "platform", "session_id"))):
            raise ServiceRefusal("Original operation scope/settings authority changed; preserve the consumed outcome without relabeling, migration or retry")

    def inspect_operation(self, session_id, *, operation_id):
        state = self._state(session_id)
        if operation_id not in state["operations"]:
            raise ServiceRefusal("Operation belongs to another session")
        path = self._operation_dir(session_id, operation_id)
        intent = service_record(decoded(private_read(path / "intent.json")), "operation_intent")
        operation = state["operations"][operation_id]
        ref = service_record(decoded(private_read(path / "intent-evidence.json")), "intent_evidence")
        row = state["evidence"].get(ref.get("evidence_id"))
        if not row or row["sha256"] != ref.get("sha256") or digest(intent) != row["sha256"]:
            raise ServiceRefusal("Original full service intent does not match its engine-owned evidence")
        data = read_record_bytes(self.engine.work / session_id / row["path"], EVIDENCE_MAX_BYTES)
        if data != encoded(intent):
            raise ServiceRefusal("Original service intent bytes changed")
        if (intent.get("engine_id") != state["engine_id"] or intent.get("mode") != state["mode"] or intent.get("session_id") != session_id
                or intent["operation"]["operation_id"] != operation_id or intent["operation"]["plan_sha256"] != operation["plan_sha256"]
                or digest(intent["payload"]) != intent["action"]["adapter_payload_sha256"]):
            raise ServiceRefusal("Service intent does not match the immutable engine operation")
        return {"operation": operation, "intent": intent, "effect_boundary_entered": (path / "entered.json").exists(),
                "handoff": read_service(decoded(private_read(path / "handoff.json"))) if (path / "handoff.json").exists() else None}

    # The typed holds of the dispatch (PLAN 3.3, D-071): an adapter whose family code is not written yet, or an id outside
    # a dispatch table, refuses with the service's existing refusal before anything is written or an operation begins.
    def _execute_held(self, session_id, state, action, payload, **arguments):
        """Hold an execute call: the refusal the service gives an action that has no fixed adapter."""
        raise ServiceRefusal("No fixed service adapter exists for this action")

    def _reconcile_held(self, session_id, operation, intent, payload, **arguments):
        """Hold a reconcile call: the outcome needs its own bounded callback evidence; nothing is changed."""
        raise ServiceRefusal("External/diagnostic outcomes require their actual bounded callback evidence")
