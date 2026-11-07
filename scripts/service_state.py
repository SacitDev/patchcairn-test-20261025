"""Service state: the refusal, the service record readers and helpers, and the private store, session state,
evidence, intent and outcome methods every service module builds on, with the session report's assembly (L4).

The base of the service modules: it imports no other service module.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from pathlib import Path
import sys
import uuid

import pc_records
import report
from workflow_core import (encoded, digest, read_record_bytes, decode_record, no_links, exact_fields, record_identifier, report_labels,
                           restart_state, EVIDENCE_MAX_BYTES, EVIDENCE_MAX_NODES, SERVICE_RECORD)
from diagnostic_core import sanitize_text
from private_workspace import (PrivateWorkspaceError, ensure_private_directory, ensure_private_file, held_lock, publish_private_new, relative_parts,
                               write_private_new)

RESERVATION_RECORD = "patchcairn.quarantine.reservation"
PLAIN_OUTCOMES = {"succeeded": "This step finished. Whether things still work as they should is checked separately.", "failed": "This step did not finish.",
                  "partial": "Only part of this step took effect.", "unknown": "PatchCairn could not confirm what this step did."}
# Every service record is a kind of patchcairn.service.
SERVICE_KINDS = frozenset({"service_marker", "retention_registry", "required_retention", "operation_intent", "intent_evidence",
                           "native_origin", "service_outcome", "effect_boundary", "release_attempt", "package_ticket"})
# The receipt keys _finish also copies into the outcome evidence facts, when the receipt has them, restart_signal from its
# "restart" record; every other receipt key stays only in the receipt.
FINISH_FACTS = ("result", "category", "group", "verified_postcondition", "actual_effects_recorded", "no_active_effects", "recovery_retained",
                "restart_signal")
# The refusal while a live process holds the service lock. A killed process never leaves it behind.
SERVICE_BUSY = ("PatchCairn is busy with another step, for example an update running in another window. Let it finish, then try again. "
                "Nothing was changed.")
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


def native_platform():
    return "windows" if sys.platform == "win32" else "macos" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "unknown"


def within(path, root):
    """True when ``path`` is ``root`` or lies below it, compared part by part through private_workspace.relative_parts
    (on Windows by the file system's own name rule, so a look-alike name is a different name). False when it lies
    outside and also when that cannot be decided, so a check that requires containment refuses; a check that refuses an
    overlap uses ``apart``."""
    return relative_parts(path, root) is not None


def apart(first, second):
    """True only when neither path contains the other and both can be compared at all. relative_parts gives None both
    for "outside" and for "cannot decide"; a path lies inside its own anchor unless it cannot be decided."""
    first, second = Path(first), Path(second)
    return (relative_parts(first, first.anchor) is not None and relative_parts(second, second.anchor) is not None
            and not within(first, second) and not within(second, first))


def retained_rows(rows):
    """The session report's kept-recovery rows (report.py's closed keys kind, location and bytes) of registry rows."""
    return [{"kind": row["retention_kind"], "location": row["location"], "bytes": row["bytes"]} for row in rows]


def _names_a_package(payload):
    return isinstance(payload, dict) and {"manager", "id"} <= set(payload)


def _package_row(payload, result, restart):
    return {"manager": payload["manager"], "package": payload["id"], "outcome": result, "restart": restart,
            "category": pc_records.UPDATE_RESULTS[result], "group": payload.get("group")}


def _latest_facts(state, operation):
    """The facts of ``operation``'s latest outcome evidence, or {} while it has none."""
    return state["evidence"].get(operation["evidence_ids"][-1], {}).get("facts", {}) if operation["evidence_ids"] else {}


def _row_restart(state, operation):
    """A package row's restart: "pending" while the step waits for its restart, else the engine's reading of it, except that
    a step with no restart recorded that closed with the signal "unknown" says "unknown", not that no restart waits."""
    reading = restart_state(operation)
    if reading == "none" and _latest_facts(state, operation).get("restart_signal") == "unknown":
        return "unknown"
    return "pending" if reading == "waiting" else reading


def _operation_result(state, operation):
    """The update result of a begun step: its latest outcome evidence's, "restart_needed" while it waits for its restart
    with none recorded, and "unknown" for anything else, such as a step still open."""
    result = _latest_facts(state, operation).get("result")
    return result if result in pc_records.UPDATE_RESULTS else "restart_needed" if restart_state(operation) == "waiting" else "unknown"


def package_rows(state, payloads):
    """The session report's package rows (report.py's closed keys manager, package, outcome, restart, category and group):
    one per update or repair item of ``state`` whose bound payload names a manager and package, whether it ran or not.
    ``payloads`` maps operation ids, and the current plan's action ids, to bound payloads. A begun step shows its result
    (_operation_result). A step of the current plan with no operation shows what follows from the plan and the approval,
    which is derived here and never stored: "excluded" when the approval leaves it out, "not_run" when it was approved (or
    a standing policy applies) but never began, and "waiting_for_you" before any approval. The category is
    pc_records.UPDATE_RESULTS[result]; restart is _row_restart's "pending", "boot_observed", "unknown" or "none"."""
    rows = [_package_row(payloads[operation["operation_id"]], _operation_result(state, operation), _row_restart(state, operation))
            for operation in state["operations"].values() if _names_a_package(payloads.get(operation["operation_id"]))]
    plan, approval = state["plan"], state["approval"]
    begun = {operation["action_id"] for operation in state["operations"].values() if plan and operation["plan_sha256"] == plan["sha256"]}
    for action in plan["document"]["actions"] if plan else ():
        if action["action_id"] not in begun and _names_a_package(payloads.get(action["action_id"])):
            result = ("excluded" if approval and action["action_id"] not in approval["action_ids"]
                      else "not_run" if approval or state["standing_policy"] else "waiting_for_you")
            rows.append(_package_row(payloads[action["action_id"]], result, "none"))
    return rows


def _finish_facts(receipt):
    """The FINISH_FACTS keys that ``receipt`` has. A restart signal that names no signal adds nothing."""
    if not isinstance(receipt, dict):
        return {}
    restart = receipt.get("restart")
    signal = restart.get("signal") if isinstance(restart, dict) else None
    named = {**receipt, **({"restart_signal": signal} if isinstance(signal, str) else {})}
    return {key: named[key] for key in FINISH_FACTS if key in named}


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
        """Publish the service record ``path``: whole or not at all, so a killed process never leaves part of one under its name,
        and never over a record already there (private_workspace.publish_private_new)."""
        no_links(path)
        data = encoded(value)
        if len(data) > EVIDENCE_MAX_BYTES:
            raise ServiceRefusal("Service record cap exceeded")
        publish_private_new(path, data)
        return {"path": str(path), "sha256": digest(data)}

    @contextmanager
    def _lock(self):
        """The one service lock, for the with block: the operating system's lock on a private file, which it frees when the
        holder dies. A live holder refuses with "service-busy"; any other failure to lock refuses as well."""
        with ExitStack() as held:
            try:
                held.enter_context(held_lock(self.work / ".coordinator-lock"))
            except PrivateWorkspaceError as exc:
                if exc.code == "private-lock-held":
                    raise ServiceRefusal(SERVICE_BUSY, code="service-busy") from None
                raise
            yield

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
        # None: outside, or it cannot be decided; (): the work folder itself.
        if not relative_parts(path, self.root / "work"):
            raise ServiceRefusal("Output must remain below this engine's owned work root")
        if existing and not path.is_dir():
            raise ServiceRefusal("Existing positively owned output directory required")
        return path

    def _register(self, state, *, kind, value, facts=None, observed_utc=None):
        evidence_id = "service-" + uuid.uuid4().hex
        return self.engine.register_evidence(state["session_id"], evidence_id=evidence_id, content=encoded(value),
                kind=kind, scope=state["settings"]["scope"], facts=facts or {}, observed_utc=observed_utc)["data"]

    def _action(self, state, *, action_id, adapter_id, kind, payload, native_plan, inventory, target, benefit, risk,
                reversibility, verification, requires_recovery=False, recovery_evidence_ids=None, requires_os_consent=False,
                rendered_command=None):
        """The engine action for ``payload``; ``native_plan`` is the lower-level plan inside it that the action's
        adapter_plan_sha256 binds (each caller names its own). A given ``rendered_command`` is passed through as the
        action's shown command: display text only, never run or parsed, bound with the plan; the engine admits it."""
        record_identifier(action_id)
        prose = {key: selected_text(value) for key, value in (("target", target), ("benefit", benefit), ("risk", risk),
                                                              ("reversibility", reversibility), ("verification", verification))}
        inventory_row = self._register(state, kind="inventory", value=inventory, facts={
            "complete": True, "item_count": len(inventory.get("entries", inventory.get("records", []))) if isinstance(inventory, dict) else 1})
        payload_row = self._register(state, kind="adapter_payload", value=payload)
        action = {"action_id": action_id, "kind": kind, **prose, "mutating": kind != "assessment",
                  "requires_os_consent": requires_os_consent, "requires_recovery": requires_recovery,
                  "recovery_evidence_ids": recovery_evidence_ids or [], "adapter_id": adapter_id,
                  "adapter_payload_evidence_id": payload_row["evidence_id"], "adapter_payload_sha256": payload_row["sha256"],
                  "adapter_plan_sha256": digest(native_plan), "target_inventory_evidence_id": inventory_row["evidence_id"],
                  "target_inventory_sha256": inventory_row["sha256"]}
        if rendered_command is not None:
            action["rendered_command"] = rendered_command
        return action

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
        binding = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        binding["outcome"] = outcome
        value = service_value("service_outcome", mode=state["mode"], observed_utc=pc_records.utc_now(), binding=binding, receipt=receipt)
        self._immutable(path / ("result-" + uuid.uuid4().hex + ".json"), value)
        evidence = self._register(state, kind=kind, value=value, facts={**binding, **_finish_facts(receipt)}, observed_utc=value["observed_utc"])
        if kind == "reconciliation":
            response = self.engine.resolve(state["session_id"], pending_id="reconcile-" + operation["operation_id"], evidence_ids=[evidence["evidence_id"]])
        else:
            response = self.engine.finish_operation(state["session_id"], operation_id=operation["operation_id"], outcome=outcome,
                        evidence_ids=[evidence["evidence_id"]],
                        summary=receipt.get("summary") if isinstance(receipt, dict) and receipt.get("summary") else PLAIN_OUTCOMES[outcome])
        return {"operation_id": operation["operation_id"], "outcome": outcome, "receipt": receipt,
                "evidence_id": evidence["evidence_id"], "workflow": response}

    def _before_intent(self, state, operation_id):
        """True for an open operation cut off before its intent was whole: both intent files come before the effect boundary,
        and no effect starts before that boundary, so nothing ran. Each file is published whole or not at all (_immutable), so
        one that is there is complete and one cut off in its write is not there."""
        path = no_links(self.work / "operations" / state["session_id"] / operation_id)
        return (state["operations"][operation_id]["outcome"] is None and not (path / "entered.json").exists()
                and not all((path / name).exists() for name in ("intent.json", "intent-evidence.json")))

    def _close_before_intent(self, session_id, operation_id):
        """Close an operation cut off before its intent was whole as "failed", with a categorical receipt, called with
        reconcile_operation's lock held. There is no whole intent to check, so _finish cannot be used and none is made up;
        the outcome goes straight to the engine, bound to the operation as usual."""
        state = self._state(session_id)
        if operation_id not in state["operations"] or not self._before_intent(state, operation_id):
            raise ServiceRefusal("Only a step cut off before it started closes this way")
        operation = state["operations"][operation_id]
        self._refuse_while_elevated(operation["adapter_id"])
        receipt = {"adapter_invoked": False, "reason": "stopped_before_intent"}
        binding = {**{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}, "outcome": "failed"}
        value = service_value("service_outcome", mode=state["mode"], observed_utc=pc_records.utc_now(), binding=binding, receipt=receipt)
        evidence = self._register(state, kind="outcome", value=value, facts=binding, observed_utc=value["observed_utc"])
        response = self.engine.finish_operation(session_id, operation_id=operation_id, outcome="failed", evidence_ids=[evidence["evidence_id"]],
                                                summary="This step was cut off before it started, so nothing ran.")
        return {"operation_id": operation_id, "outcome": "failed", "receipt": receipt, "evidence_id": evidence["evidence_id"], "workflow": response}

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
        if self._before_intent(state, operation_id):
            raise ServiceRefusal("This step was cut off before it started, so nothing ran. Checking it closes it as not run.", code="intent-incomplete")
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

    def session_report(self, session_id):
        """Write the HTML view of one session (report.render_session) as a new private file in this service's reports
        folder and return its path. The view is rebuilt from the session record each time and is never read back as
        input; anyone who can write the file can change it, so it is not evidence. The optional inputs are projected to
        report.py's closed key sets; free space has no recorded source yet and stays None. ``restarts`` carries the engine's
        reading of each step's restart record as data, because report.py cannot import the engine."""
        state = self._state(session_id)
        kept = retained_rows([row for row in self._retention() if row["session_id"] == session_id])
        restarts = {key: restart_state(operation) for key, operation in state["operations"].items()}
        try:
            page = report.render_session(state, assessment=self._assessment_summary(state), free_space=None,
                                         packages=package_rows(state, self._package_payloads(state)) or None, retained=kept or None,
                                         labels=report_labels(), restarts=restarts)
        except pc_records.Refusal as error:
            raise ServiceRefusal(str(error), code=error.code) from error
        ensure_private_directory(self.work / "reports", create=True, exist_ok=True)
        path = self.work / "reports" / (session_id + "-" + uuid.uuid4().hex[:12] + ".html")
        write_private_new(path, page)
        return path

    def _evidence_record(self, state, evidence_id, sha256):
        """The decoded evidence record ``evidence_id`` of this session, read again and checked against ``sha256``."""
        row = state["evidence"].get(evidence_id)
        data = read_record_bytes(self.engine.work / state["session_id"] / row["path"], EVIDENCE_MAX_BYTES) if row else b""
        if not row or digest(data) != row["sha256"] or row["sha256"] != sha256:
            raise ServiceRefusal("A record no longer matches its recorded evidence")
        return decoded(data)

    def _package_payloads(self, state):
        """The bound payload of each update or repair step: by operation id from its service intent, and by action id from
        the current plan's evidence. A step interrupted before its intent was written takes its action's payload, when its
        operation belongs to that same plan, so it keeps its row; nothing is added to what it recorded."""
        families, payloads = {"update", "repair"}, {}
        for operation in state["operations"].values():
            path = self.work / "operations" / state["session_id"] / operation["operation_id"] / "intent.json"
            if pc_records.ADAPTERS.get(operation["adapter_id"], {}).get("family") in families and path.exists():
                payloads[operation["operation_id"]] = service_record(decoded(private_read(path)), "operation_intent")["payload"]
        for action in state["plan"]["document"]["actions"] if state["plan"] else ():
            if pc_records.ADAPTERS.get(action["adapter_id"], {}).get("family") in families:
                payloads[action["action_id"]] = self._evidence_record(state, action["adapter_payload_evidence_id"], action["adapter_payload_sha256"])
        current = state["plan"]["sha256"] if state["plan"] else None
        for operation in state["operations"].values():
            if operation["plan_sha256"] == current and operation["action_id"] in payloads:
                payloads.setdefault(operation["operation_id"], payloads[operation["action_id"]])
        return payloads

    def _assessment_summary(self, state):
        """The decoded assessment summary the session's completed assessment names, or None when it has none."""
        finished = [item["record"] for item in state["pending"].values() if item.get("kind") == "assessment_finish"]
        return self._evidence_record(state, finished[-1]["summary_evidence_id"], finished[-1]["summary_sha256"]) if finished else None

    # The typed holds of the dispatch: an adapter whose family code is not written yet, or an id outside
    # a dispatch table, refuses with the service's existing refusal before anything is written or an operation begins.
    def _execute_held(self, session_id, state, action, payload, **arguments):
        """Hold an execute call: the refusal the service gives an action that has no fixed adapter."""
        raise ServiceRefusal("No fixed service adapter exists for this action")

    def _reconcile_held(self, session_id, operation, intent, payload, **arguments):
        """Hold a reconcile call: the outcome needs its own bounded callback evidence; nothing is changed."""
        raise ServiceRefusal("This step's outcome needs its own recorded evidence; nothing was changed")
