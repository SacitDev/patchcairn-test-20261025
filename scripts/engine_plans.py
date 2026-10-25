"""A session's creation and settings, scope, evidence, plans, reviews, owner approvals, standing policies, stages and pending
decisions.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

import copy
from datetime import timedelta
import math
from pathlib import Path
import re
import uuid

import diagnostic_core
from engine_journal import (ASSESSMENT_ACCESS, ASSESSMENT_SUMMARY, ASSESSMENT_VERIFICATION, BACKEND, CREATION_KEYS, DIAGNOSTIC_ADAPTER, EVIDENCE_MAX_BYTES,
                            EVIDENCE_MAX_NODES, FIXTURE_ADAPTER, OUTCOMES, SHA, STATE_KEYS, WorkflowRefusal, bounded_text, checked, container,
                            decode_record, exact_fields, fresh, ids, invalidate, no_links, private_directory, private_file, record_identifier, require_writable,
                            typed_record, utc_time, write_private_new)
from engine_text import CHECKPOINTS, JOBS, STAGE_LABELS, initial_menu, response
import pc_paths
import pc_records
from pc_records import SCHEMA_VERSION, digest, encoded
import storage_contract


KINDS = {"update", "cleanup_quarantine", "backup_create", "backup_restore", "repair", "permanent_purge", "restart", "firmware", "os_transition",
         "security_policy", "assessment"}
# Only the action kinds of adapters that pc_records lets a standing policy cover.
POLICY_KINDS = frozenset(kind for facts in pc_records.ADAPTERS.values() if facts["policy_coverable"] for kind in facts["kinds"])
ROLES = {"compatibility_data", "evidence_security"}
EVIDENCE_KINDS = {"scope_confirmation", "inventory", "research", "candidates", "symptom", "hypotheses", "recovery_plan", "precondition", "outcome",
                  "reconciliation", "verification", "recovery", "protected_consent", "review", "fixture"}
EVIDENCE_KINDS |= {"adapter_payload", "recovery_manifest", "restore_verification", "retention", "recovery_archive"}
# Storage adapters whose plans the storage service carries out today; the other storage ids hold.
STORAGE_ADAPTERS = frozenset({pc_records.ADAPTER_STORAGE_BACKUP_CREATE, pc_records.ADAPTER_STORAGE_RESTORE, pc_records.ADAPTER_STORAGE_QUARANTINE,
                              pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE, pc_records.ADAPTER_STORAGE_PURGE})
MAX_FACT_ITEMS = pc_records.MAX_BACKUP_ENTRIES
# Facts are copied into the journal state, so they stay small; large data belongs in the evidence content.
FACTS_MAX_BYTES = 65_536


def _facts(action):
    """The pc_records facts of an action's adapter; an action whose OS-consent flag contradicts them is refused."""
    return checked(pc_records.adapter_facts, action["adapter_id"], requires_os_consent=action["requires_os_consent"])


def acknowledgments(action):
    """Acknowledgments the owner gives separately for this action (pc_records facts)."""
    return pc_records.ADAPTERS[action["adapter_id"]]["acknowledgments"]


def _json_shape(value, depth=0):
    if depth > 12:
        raise WorkflowRefusal("Record nesting exceeds the bounded schema")
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str) and len(value) > 8000:
            raise WorkflowRefusal("Evidence text is too long")
        return
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise WorkflowRefusal("Nonfinite evidence value")
        return
    if isinstance(value, list) and len(value) <= MAX_FACT_ITEMS:
        for item in value:
            _json_shape(item, depth + 1)
        return
    if isinstance(value, dict) and len(value) <= 100:
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in {"command", "commands", "execute", "eval", "approved", "authorization"}:
                raise WorkflowRefusal("Executable or self-authorizing evidence fields are not accepted")
            _json_shape(item, depth + 1)
        return
    raise WorkflowRefusal("Evidence must be bounded JSON data")


def json_data(value):
    """Bounded JSON evidence data that the one encoder also accepts (no lone surrogates, integers within 20
    digits), checked before anything is written."""
    _json_shape(value)
    checked(pc_records.encoded, value)


def _collector_result(content):
    """The decoded result when inventory ``content`` has the collectors' own shape (a JSON object with "platform" and
    "observations" keys, as collect_linux and collect_macos return), else None. Diagnostic requests, storage inventories
    and receipts lack "observations". Only content that names both is decoded, so large storage inventories are not
    decoded a second time. This checks the trusted coordinator's own collector output for consistency; it is not an
    authority boundary: escaped keys, a wrapping object, a byte order mark or UTF-16 bytes are not recognised."""
    if b'"platform"' not in content or b'"observations"' not in content:
        return None
    try:
        value = decode_record(content, max_bytes=EVIDENCE_MAX_BYTES, max_nodes=EVIDENCE_MAX_NODES)
    except WorkflowRefusal:
        return None
    return value if isinstance(value, dict) and "platform" in value and "observations" in value else None


def _assessment_source_key(source, kind):
    """Validate recorded selectors lexically; never inspect or resolve a host path."""
    if kind == "observation":
        return record_identifier(source, "observation source")
    bounded_text(source, "literal assessment source", 2000)
    if any(ord(char) < 32 or ord(char) == 127 or char in "\\*?" for char in source):
        raise WorkflowRefusal("Assessment paths require literal forward-slash spelling")
    windows = bool(re.match(r"[A-Z]:/", source)) or source.startswith("//")
    if re.match(r"[A-Z]:/", source):
        parts = source[3:].split("/") if len(source) > 3 else []
    elif source.startswith("//"):
        parts = source[2:].split("/")
        if len(parts) < 2:
            raise WorkflowRefusal("An explicit UNC server/share is required")
    elif source.startswith("/"):
        parts = source[1:].split("/") if source != "/" else []
    else:
        raise WorkflowRefusal("An absolute literal assessment source is required")
    if any(part in {"", ".", ".."} for part in parts):
        raise WorkflowRefusal("Assessment paths cannot contain traversal or alternate spellings")
    if windows and any(not pc_paths.portable(part) for part in parts):
        raise WorkflowRefusal("Ambiguous Windows assessment path")
    return source.casefold() if windows else source


def _assessment_access(value):
    typed_record(value, ASSESSMENT_ACCESS)
    if value["target"] not in ("whole_device", "selected_paths", "specific_problem"):
        raise WorkflowRefusal("Unknown assessment access descriptor")
    operations = ids(value["operations"], "assessment operations", allow_empty=False)
    if set(operations) - {"metadata", "diagnosis", "content_read"}:
        raise WorkflowRefusal("Assessment access admits read-only operations only")
    selections = value["local_content"]
    if not isinstance(selections, list) or len(selections) > 30:
        raise WorkflowRefusal("Select at most thirty bounded local content observations")
    identifiers, identities = set(), set()
    for selection in selections:
        exact_fields(selection, {"id", "kind", "source", "selection"}, {"id", "kind", "source", "selection"})
        identifier = record_identifier(selection["id"], "assessment selection")
        if identifier in identifiers or selection["kind"] not in ("path", "observation"):
            raise WorkflowRefusal("Duplicate selection or unknown assessment source kind")
        source = _assessment_source_key(selection["source"], selection["kind"])
        bounded_text(selection["selection"], "bounded content selection", 1000)
        identity = (selection["kind"], source, selection["selection"])
        if identity in identities:
            raise WorkflowRefusal("Duplicate local content selection")
        identifiers.add(identifier)
        identities.add(identity)
    if bool(selections) != ("content_read" in operations):
        raise WorkflowRefusal("Content-read permission needs exact local content selections")
    for field in ("llm_content", "sensitive_exceptions"):
        references = ids(value[field], field)
        if len(references) > 30 or not set(references) <= identifiers:
            raise WorkflowRefusal("Disclosure and sensitive exceptions must reference exact local selections")


def _scope(scope):
    exact_fields(scope, {"roots", "purpose", "assessment"}, {"roots", "purpose"})
    if (not isinstance(scope["roots"], list) or len(scope["roots"]) > 30 or any(not isinstance(root, str) for root in scope["roots"])
            or len(set(scope["roots"])) != len(scope["roots"])):
        raise WorkflowRefusal("Select a bounded unique list of scope roots")
    for root in scope["roots"]:
        bounded_text(root, "selected scope", 1000)
    bounded_text(scope["purpose"], "scope purpose", 1000)
    if "assessment" in scope:
        _assessment_access(scope["assessment"])
    return copy.deepcopy(scope)


def _scope_selected(scope):
    return bool(scope["roots"]) or scope.get("assessment", {}).get("target") in ("whole_device", "specific_problem")


def owner_record(state, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat"):
    if source not in {"current_owner_chat", "current_owner_terminal"} or (owner_id or state["owner_id"]) != state["owner_id"]:
        raise WorkflowRefusal("Only the actual current owner instruction can authorize this decision")
    bounded_text(owner_quote, "actual owner quote")
    record_identifier(owner_message_id, "owner message identifier")
    return {"owner_id": state["owner_id"], "quote": owner_quote, "message_id": owner_message_id, "source": source, "recorded_utc": pc_records.utc_now(),
            "settings_revision": state["settings_revision"]}


def validate_state(engine, state):
    container(state, "session_state")
    exact_fields(state, STATE_KEYS, STATE_KEYS)
    if state["backend"] != BACKEND or state["engine_id"] != engine.marker["engine_id"]:
        raise WorkflowRefusal("Foreign session version, backend or creation identity")
    record_identifier(state["session_id"])
    record_identifier(state["owner_id"])
    if state["mode"] not in {"fixture", "real"} or state["platform"] not in {"unknown", "windows", "linux", "macos"}:
        raise WorkflowRefusal("Invalid immutable session mode/platform")
    if (state["job"] not in JOBS or state["stage"] not in JOBS[state["job"]]["stages"]
            or state["status"] not in {"active", "paused", "pause_pending", "held", "stopped", "completed", "awaiting_user"}):
        raise WorkflowRefusal("Invalid job, stage or status")
    for key in ("revision", "settings_revision"):
        if type(state[key]) is not int or state[key] < 0:
            raise WorkflowRefusal("Invalid revision")
    utc_time(state["created_utc"])
    utc_time(state["updated_utc"])
    settings = state["settings"]
    exact_fields(settings, {"scope", "control", "timing", "checkpoints"}, {"scope", "control", "timing", "checkpoints"})
    _scope(settings["scope"])
    if (settings["control"] not in {"guided", "automatic"} or settings["timing"] not in {"now", "scheduled"} or not isinstance(settings["checkpoints"], list)
            or set(settings["checkpoints"]) - CHECKPOINTS or len(settings["checkpoints"]) != len(set(settings["checkpoints"]))):
        raise WorkflowRefusal("Invalid session settings")
    if (not isinstance(state["evidence"], dict) or not isinstance(state["operations"], dict) or not isinstance(state["reviews"], list)
            or not isinstance(state["pending"], dict) or not isinstance(state["schedule_triggers"], list)):
        raise WorkflowRefusal("Invalid state collections")
    for evidence_id, row in state["evidence"].items():
        record_identifier(evidence_id)
        exact_fields(row, {"evidence_id", "path", "sha256", "size", "kind", "scope", "settings_revision", "observed_utc", "registered_utc", "facts"},
                     {"evidence_id", "path", "sha256", "size", "kind", "scope", "settings_revision", "observed_utc", "registered_utc", "facts"})
        if (row["evidence_id"] != evidence_id or row["path"] != "evidence/" + evidence_id + ".bin" or row["kind"] not in EVIDENCE_KINDS
                or not SHA.fullmatch(row["sha256"]) or type(row["size"]) is not int or row["size"] < 1):
            raise WorkflowRefusal("Invalid owned evidence record")
        _scope(row["scope"])
        json_data(row["facts"])
        utc_time(row["observed_utc"])
        utc_time(row["registered_utc"])
    active = []
    for operation_id, op in state["operations"].items():
        record_identifier(operation_id)
        fields = {"operation_id", "action_id", "plan_sha256", "settings_revision", "started_utc", "finished_utc", "outcome", "evidence_ids", "summary",
                  "authorization", "pause_requested", "resolution", "mutating", "adapter_id"}
        exact_fields(op, fields | {"restart_pending", "restart_decision", "restart_verification"}, fields)
        for name in ("restart_pending", "restart_decision", "restart_verification"):
            if name in op:
                if not isinstance(op[name], dict):
                    raise WorkflowRefusal("Restart lifecycle metadata must be a typed record")
                json_data(op[name])
        if op["operation_id"] != operation_id or op["outcome"] not in OUTCOMES | {None} or not SHA.fullmatch(op["plan_sha256"]):
            raise WorkflowRefusal("Invalid operation record")
        if type(op["mutating"]) is not bool or op["adapter_id"] not in pc_records.ADAPTERS:
            raise WorkflowRefusal("Operation must retain its exact adapter and mutation classification")
        record_identifier(op["action_id"])
        ids(op["evidence_ids"])
        utc_time(op["started_utc"])
        if op["finished_utc"]:
            utc_time(op["finished_utc"])
        if op["outcome"] is None:
            active.append(operation_id)
    if len(active) > 1 or state["status"] == "pause_pending" and not active:
        raise WorkflowRefusal("Invalid active-operation invariant")
    if state["plan"]:
        plan = state["plan"]
        exact_fields(plan, {"document", "sha256", "settings_revision", "registered_utc"}, {"document", "sha256", "settings_revision", "registered_utc"})
        if digest(plan["document"]) != plan["sha256"] or plan["settings_revision"] != state["settings_revision"]:
            raise WorkflowRefusal("Plan hash or settings binding changed")
        validate_plan_document(state, plan["document"])
    if (state["approval"] and (not state["plan"] or state["approval"]["plan_sha256"] != state["plan"]["sha256"]
                               or state["approval"]["settings_revision"] != state["settings_revision"])):
        raise WorkflowRefusal("Approval is not bound to the current exact plan")
    return state


def create_session(engine, *, job="security_updates", control="guided", timing="now", mode="fixture", platform="unknown", scope=None, checkpoints=None,
                   owner_id="owner"):
    if job not in JOBS:
        raise WorkflowRefusal("Choose one supported job")
    record_identifier(owner_id)
    selected = _scope(scope or {"roots": [], "purpose": "Assessment; scope still needs the owner's decision"})
    now = pc_records.utc_now()
    session_id = "session-" + uuid.uuid4().hex
    state = {"schema_version": SCHEMA_VERSION, "session_id": session_id, "engine_id": engine.marker["engine_id"], "backend": BACKEND, "mode": mode,
             "platform": platform, "created_utc": now, "updated_utc": now, "creation_scope_sha256": digest(selected), "owner_id": owner_id, "revision": 0,
             "settings_revision": 0, "job": job, "stage": "scope", "status": "active" if timing == "now" else "awaiting_user",
             "settings": {"scope": selected, "control": control, "timing": timing,
                          "checkpoints": list(checkpoints if checkpoints is not None else ["scope", "findings", "plan", "before_action", "finish"])},
             "scope_authorization": None, "evidence": {}, "plan": None, "reviews": [], "approval": None, "irreversible_ack": None, "standing_policy": None,
             "operations": {}, "pending": {}, "schedule": None, "schedule_triggers": [], "last_reconciled_utc": None, "stop_reason": None}
    validate_state(engine, state)
    private_directory(engine.work)
    private_file(engine.work / "engine.json")
    directory = engine.work / session_id
    private_directory(directory, create=True)
    private_directory(directory / "evidence", create=True)
    marker = {"schema_version": SCHEMA_VERSION, **{key: state[key] for key in CREATION_KEYS}}
    write_private_new(directory / "creation.json", encoded(marker))
    engine.journal.commit(directory, state, [], "created", {"job": job})
    return response(state, "created", initial_menu() + "\n\nYour " + JOBS[job]["label"].lower()
                    + " session is ready. Confirm the exact scope before evidence collection.", {"state": state})


def setup(engine, session_id, *, scope=None, control=None, timing=None, checkpoints=None, expected_revision=None):
    def mutate(state):
        require_writable(state)
        new = copy.deepcopy(state["settings"])
        for key, value in (("scope", scope), ("control", control), ("timing", timing), ("checkpoints", checkpoints)):
            if value is not None:
                new[key] = _scope(value) if key == "scope" else copy.deepcopy(value)
        if new != state["settings"]:
            if any(op["outcome"] in {None, "unknown"} or op["outcome"] in {"failed", "partial"}
                   and not op["resolution"] for op in state["operations"].values()):
                raise WorkflowRefusal("An operation still has active, unknown or unreconciled effects; establish its actual outcome before changing "
                                      "scope/settings")
            state["settings"] = new
            state["settings_revision"] += 1
            invalidate(state)
            state["stage"] = "scope"
            if state["status"] not in {"paused", "pause_pending", "held"}:
                state["status"] = "awaiting_user" if new["timing"] == "scheduled" else "active"
        return ({"settings": new},
                "Settings are recorded. Changed scope or control choices require a fresh scope decision and a new reviewed plan; earlier approvals cannot "
                "expand.")
    return engine.change(session_id, "settings", mutate, expected_revision)


def authorize_scope(engine, session_id, *, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat", expected_revision=None):
    def mutate(state):
        require_writable(state)
        if not _scope_selected(state["settings"]["scope"]):
            raise WorkflowRefusal("Select the exact scope before authorizing collection")
        state["scope_authorization"] = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        state["scope_authorization"]["scope_sha256"] = digest(state["settings"]["scope"])
        if state["status"] == "awaiting_user" and state["settings"]["timing"] == "now":
            state["status"] = "active"
        return {}, "Your exact scope decision is recorded. It permits only the agreed evidence collection; computer changes need a separate concrete plan."
    return engine.change(session_id, "scope_authorized", mutate, expected_revision)


def register_evidence(engine, session_id, *, evidence_id, content, kind, scope, facts=None, observed_utc=None, expected_revision=None):
    record_identifier(evidence_id, "evidence identifier")
    if not isinstance(content, bytes) or not 0 < len(content) <= EVIDENCE_MAX_BYTES or kind not in EVIDENCE_KINDS:
        raise WorkflowRefusal("Evidence must be bounded bytes with a supported kind")
    _scope(scope)
    facts = copy.deepcopy(facts or {})
    if not isinstance(facts, dict):
        raise WorkflowRefusal("Evidence facts must be a mapping")
    json_data(facts)
    if len(encoded(facts)) > FACTS_MAX_BYTES:
        raise WorkflowRefusal("Evidence facts must stay small; put large data in the evidence content", code="facts-too-large")
    observed = observed_utc or pc_records.utc_now()
    fresh(observed, seconds=86400)
    collected = _collector_result(content) if kind == "inventory" else None  # decoded before the session lock
    def mutate(state):
        if state["status"] == "stopped":
            operation = state["operations"].get(facts.get("operation_id"))
            active_receipt = operation and operation["outcome"] is None and kind == "outcome"
            late_reconciliation = (operation and operation["outcome"] in {"unknown", "partial", "failed"} and kind in {"outcome", "reconciliation"}
                                   and not operation["resolution"])
            if not active_receipt and not late_reconciliation:
                raise WorkflowRefusal("A stopped session accepts only the exact eventual receipt or bounded reconciliation of its existing unresolved "
                                      "operation")
            if facts.get("action_id") != operation["action_id"] or facts.get("plan_sha256") != operation["plan_sha256"] or facts.get("outcome") not in OUTCOMES:
                raise WorkflowRefusal("Post-stop evidence must bind the exact active operation and actual outcome")
            if operation["outcome"] in {"partial", "failed"} and facts["outcome"] != operation["outcome"]:
                raise WorkflowRefusal("Historical unsuccessful outcomes cannot be relabelled by late evidence")
            fresh(observed, after=operation["finished_utc"] or operation["started_utc"], seconds=900)
        else:
            require_writable(state)
        if evidence_id in state["evidence"]:
            raise WorkflowRefusal("Evidence identifiers are immutable and cannot be overwritten")
        if scope != state["settings"]["scope"]:
            raise WorkflowRefusal("Evidence must match the exact current selected scope")
        if kind == "fixture" and state["mode"] != "fixture":
            raise WorkflowRefusal("Fictional evidence cannot be promoted into a real session")
        if kind == "inventory" and state["mode"] == "real":
            authorization = state["scope_authorization"]
            if not authorization or authorization.get("scope_sha256") != digest(state["settings"]["scope"]):
                raise WorkflowRefusal("Inventory from this computer is recorded only after you authorize the exact current scope",
                                      code="inventory-scope-unauthorized")
            if collected is not None and collected.get("collection_mode") != "real":
                practice = collected.get("collection_mode") == "fixture"
                raise WorkflowRefusal(("This inventory is a practice (fixture) collection result" if practice else
                                       "This collector result does not state a real collection") + "; it cannot be recorded as this computer's inventory",
                                      code="inventory-fixture-result")
            if collected is not None and collected["platform"] != state["platform"]:
                raise WorkflowRefusal("This inventory was collected on a different platform than this session's computer",
                                      code="inventory-platform-mismatch")
        row = {"evidence_id": evidence_id, "path": "evidence/" + evidence_id + ".bin", "sha256": digest(content), "size": len(content), "kind": kind,
               "scope": copy.deepcopy(scope), "settings_revision": state["settings_revision"], "observed_utc": observed, "registered_utc": pc_records.utc_now(),
               "facts": facts}
        target = engine.journal.directory(session_id) / row["path"]
        if target.exists():
            raise WorkflowRefusal("An unregistered file occupies the evidence name; preserve it for inspection")
        write_private_new(engine.journal.private_path(target), content)
        state["evidence"][evidence_id] = row
        return row, "Selected evidence is saved with its exact content hash, scope and observation time."
    return engine.change(session_id, "evidence_registered", mutate, expected_revision)


def evidence_rows(state, evidence_ids, *, kinds=None, after=None, seconds=86400, allow_empty=False):
    ids(evidence_ids, "evidence identifiers", allow_empty=allow_empty)
    rows = []
    for evidence_id in evidence_ids:
        if evidence_id not in state["evidence"]:
            raise WorkflowRefusal("Referenced evidence is not owned by this session")
        row = state["evidence"][evidence_id]
        if row["settings_revision"] != state["settings_revision"] or row["scope"] != state["settings"]["scope"]:
            raise WorkflowRefusal("Evidence belongs to an earlier scope/settings revision")
        if kinds and row["kind"] not in kinds:
            raise WorkflowRefusal("Evidence kind does not support this transition")
        fresh(row["observed_utc"], after=after, seconds=seconds)
        rows.append(row)
    return rows


def validate_plan_document(state, plan):
    exact_fields(plan, {"plan_id", "summary", "evidence_ids", "actions"}, {"plan_id", "summary", "evidence_ids", "actions"})
    record_identifier(plan["plan_id"])
    bounded_text(plan["summary"], "plan explanation")
    ids(plan["evidence_ids"], allow_empty=False)
    if not isinstance(plan["actions"], list) or not 0 < len(plan["actions"]) <= 100:
        raise WorkflowRefusal("A plan needs a bounded concrete action list")
    seen = set()
    for action in plan["actions"]:
        fields = {"action_id", "kind", "target", "benefit", "risk", "reversibility", "verification", "mutating", "requires_os_consent", "requires_recovery",
                  "recovery_evidence_ids", "estimate_evidence_id", "adapter_id", "adapter_payload_evidence_id", "adapter_payload_sha256", "adapter_plan_sha256",
                  "target_inventory_evidence_id", "target_inventory_sha256"}
        required = fields - {"estimate_evidence_id"}
        exact_fields(action, fields, required)
        record_identifier(action["action_id"])
        if action["action_id"] in seen or action["kind"] not in KINDS:
            raise WorkflowRefusal("Action identifiers must be unique and kinds supported")
        seen.add(action["action_id"])
        for field in ("target", "benefit", "risk", "reversibility", "verification"):
            bounded_text(action[field], "action " + field, 2000)
        if any(type(action[key]) is not bool for key in ("mutating", "requires_os_consent", "requires_recovery")):
            raise WorkflowRefusal("Action safety flags must be explicit booleans")
        if action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL and action["requires_os_consent"] is not True:
            raise WorkflowRefusal("Every fixed local external installer requires actual owner-handled protected-system consent")
        if action["kind"] != "assessment" and not action["mutating"]:
            raise WorkflowRefusal("Change kinds cannot be disguised as read-only actions")
        if not isinstance(action["adapter_id"], str):
            raise WorkflowRefusal("Adapter identifier must name a fixed supported recipe")
        facts = _facts(action)
        if action["kind"] not in facts["kinds"] or action["adapter_id"] == pc_records.ADAPTER_FIXTURE_ASSESSMENT and state["mode"] != "fixture":
            raise WorkflowRefusal("This action has no fixed supported adapter for this kind and mode")
        if facts["backup_receipt"] == "required" and not action["requires_recovery"]:
            raise WorkflowRefusal("This adapter consumes a verified backup receipt; bind its recovery evidence")
        for field in ("adapter_payload_evidence_id", "target_inventory_evidence_id"):
            record_identifier(action[field])
        for field in ("adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256"):
            if not isinstance(action[field], str) or not SHA.fullmatch(action[field]):
                raise WorkflowRefusal("Exact adapter payload, lower-level plan and target inventory hashes are required")
        if action["kind"] in {"backup_restore", "permanent_purge", "repair", "firmware", "os_transition"} and not action["requires_recovery"]:
            raise WorkflowRefusal("This action needs verified recovery evidence or an explicit supported recovery design")
        ids(action["recovery_evidence_ids"])
        if action["requires_recovery"] and not action["recovery_evidence_ids"]:
            raise WorkflowRefusal("Required recovery has not been provided")
        if "estimate_evidence_id" in action:
            record_identifier(action["estimate_evidence_id"])


def action_binding(engine, state, action):
    payload_row = engine.evidence_rows(state, [action["adapter_payload_evidence_id"]], kinds={"adapter_payload"})[0]
    inventory_row = engine.evidence_rows(state, [action["target_inventory_evidence_id"]], kinds={"inventory"})[0]
    if payload_row["sha256"] != action["adapter_payload_sha256"] or inventory_row["sha256"] != action["target_inventory_sha256"]:
        raise WorkflowRefusal("Exact reviewed adapter payload or target inventory has changed")
    directory = engine.journal.directory(state["session_id"])
    payload, inventory = (decode_record(engine.journal.read_owned(directory / row["path"], EVIDENCE_MAX_BYTES), max_bytes=EVIDENCE_MAX_BYTES,
                                        max_nodes=EVIDENCE_MAX_NODES) for row in (payload_row, inventory_row))
    if action["adapter_id"] == pc_records.ADAPTER_FIXTURE_ASSESSMENT:
        typed_record(payload, FIXTURE_ADAPTER)
        if (payload["operation"] != action["adapter_id"] or digest(payload["fixture_plan"]) != action["adapter_plan_sha256"]
                or payload["fixture_plan_sha256"] != action["adapter_plan_sha256"] or payload["inventory_sha256"] != digest(inventory)):
            raise WorkflowRefusal("Fictional adapter payload does not bind its exact plan and inventory")
    elif action["adapter_id"] == pc_records.ADAPTER_DIAGNOSTIC_COLLECT:
        typed_record(payload, DIAGNOSTIC_ADAPTER)
        if (payload["operation"] != action["adapter_id"] or payload["request_sha256"] != action["adapter_plan_sha256"]
                or digest(payload["request"]) != action["adapter_plan_sha256"] or payload["inventory_sha256"] != digest(inventory)
                or payload["request"] != inventory):
            raise WorkflowRefusal("Diagnostic request does not match the exact reviewed selected recipe and inventory")
        json_data(payload["request"])
        try:
            request = diagnostic_core.validate_request(payload["request"])
        except diagnostic_core.DiagnosticRefusal as error:
            raise WorkflowRefusal("Diagnostic request is not a supported bounded recipe") from error
        if request["mode"] != state["mode"] or request["platform"] != state["platform"]:
            raise WorkflowRefusal("Diagnostic request belongs to a different creation mode/platform")
    elif action["adapter_id"] in pc_records.ADAPTERS and pc_records.ADAPTERS[action["adapter_id"]]["family"] in {"update", "repair"}:
        # The update and repair families bind in engine_updates, reached through the engine (no import of it here).
        engine.update_binding(state, action, payload, inventory)
    elif action["adapter_id"] in STORAGE_ADAPTERS:
        checked(storage_contract.validate_payload, payload, adapter_id=action["adapter_id"], mode=state["mode"], plan_sha256=action["adapter_plan_sha256"])
        json_data(payload["storage_plan"])
        output_value = Path(bounded_text(payload["output_root"], "owned storage output root", 2000))
        if not output_value.is_absolute():
            raise WorkflowRefusal("Storage output root must be an exact absolute owned work path")
        output = no_links(output_value)
        try:
            output.relative_to(engine.root / "work")
        except ValueError as error:
            raise WorkflowRefusal("Adapter outputs must stay inside this repository's owned work tree") from error
        probe_value = payload.get("restore_probe_destination")
        if probe_value is not None:
            if action["adapter_id"] != pc_records.ADAPTER_STORAGE_BACKUP_CREATE or not isinstance(probe_value, str) or not Path(probe_value).is_absolute():
                raise WorkflowRefusal("Only an explicitly reviewed backup action can include an exact owned restore-probe destination")
            probe = no_links(Path(probe_value))
            try:
                probe.relative_to(output)
            except ValueError as error:
                raise WorkflowRefusal("Restore probe must stay under the exact owned backup output root") from error
            if probe.exists():
                raise WorkflowRefusal("The reviewed restore-probe destination is no longer absent")
        source_inventory = payload["storage_plan"].get("inventory", payload["storage_plan"].get("records", payload["storage_plan"].get("receipt")))
        if source_inventory is None or digest(source_inventory) != digest(inventory):
            raise WorkflowRefusal("Adapter target inventory is not the exact owned inventory/receipt reviewed in the lower-level plan")
    else:
        # A registered adapter whose family code is not written yet: the facts allow it, nothing binds it.
        raise WorkflowRefusal("This adapter's payload binding is not written yet; the action is held", code="adapter-held")
    return payload


def register_plan(engine, session_id, *, plan, expected_revision=None):
    document = copy.deepcopy(plan)
    def mutate(state):
        require_writable(state)
        stages = JOBS[state["job"]]["stages"]
        if state["stage"] not in stages[:stages.index("apply")]:
            raise WorkflowRefusal("A new or replacement plan must be reviewed before the apply stage; existing action, verification and finish checkpoints "
                                  "cannot authorize another plan")
        if any(op["outcome"] is None for op in state["operations"].values()):
            raise WorkflowRefusal("Reconcile the active operation before replacing its plan")
        validate_plan_document(state, document)
        engine.evidence_rows(state, document["evidence_ids"])
        if not state["scope_authorization"]:
            raise WorkflowRefusal("The current owner has not authorized this scope")
        consumed = {op["action_id"] for op in state["operations"].values()}
        for action in document["actions"]:
            action_binding(engine, state, action)
            if action["action_id"] in consumed:
                raise WorkflowRefusal("A consumed action identifier cannot be reused or retried")
            if action["requires_recovery"] or action["recovery_evidence_ids"]:
                engine.verify_recovery(state, action["recovery_evidence_ids"], action=action)
            if action.get("estimate_evidence_id"):
                estimate = engine.evidence_rows(state, [action["estimate_evidence_id"]], kinds={"inventory"})[0]
                if estimate["facts"].get("action_id") != action["action_id"]:
                    raise WorkflowRefusal("A cost fact must identify this exact action to prevent unrelated or duplicate workload estimates")
        state["plan"] = {"document": document, "sha256": digest(document), "settings_revision": state["settings_revision"],
                         "registered_utc": pc_records.utc_now()}
        state["reviews"] = []
        state["approval"] = None
        state["irreversible_ack"] = None
        return ({"plan_sha256": state["plan"]["sha256"], "action_ids": [a["action_id"] for a in document["actions"]]},
                "The exact plan is saved. It still needs two independent reviews and your concrete action decision before any change.")
    return engine.change(session_id, "plan_registered", mutate, expected_revision)


def current_plan(state, plan_sha256):
    if not state["plan"] or state["plan"]["sha256"] != plan_sha256 or state["plan"]["settings_revision"] != state["settings_revision"]:
        raise WorkflowRefusal("The exact current plan hash is required")
    return state["plan"]["document"]


def record_review(engine, session_id, *, plan_sha256, reviewer_id, role, verdict, evidence_ids, notes, expected_revision=None):
    record_identifier(reviewer_id, "reviewer identifier")
    bounded_text(notes, "review notes")
    if role not in ROLES or verdict not in {"approved", "hold"}:
        raise WorkflowRefusal("A supported review role and approved/hold verdict are required")
    def mutate(state):
        require_writable(state)
        current_plan(state, plan_sha256)
        engine.evidence_rows(state, evidence_ids, kinds={"review"}, after=state["plan"]["registered_utc"])
        if reviewer_id == state["owner_id"] or any(row["reviewer_id"] == reviewer_id or row["role"] == role for row in state["reviews"]):
            raise WorkflowRefusal("Reviews need two distinct independent reviewers, separate from the owner")
        record = {"reviewer_id": reviewer_id, "role": role, "verdict": verdict, "evidence_ids": list(evidence_ids), "notes": notes, "plan_sha256": plan_sha256,
                  "settings_revision": state["settings_revision"], "recorded_utc": pc_records.utc_now()}
        state["reviews"].append(record)
        state["approval"] = None
        return record, "The independent review is recorded against the exact current plan. A held review prevents changes."
    return engine.change(session_id, "review_recorded", mutate, expected_revision)


def require_reviews(engine, state):
    if (not state["plan"] or len(state["reviews"]) != 2 or {row["role"] for row in state["reviews"]} != ROLES
            or len({row["reviewer_id"] for row in state["reviews"]}) != 2):
        raise WorkflowRefusal("Two independent compatibility/data and evidence/security reviews are required")
    for row in state["reviews"]:
        if row["verdict"] != "approved" or row["plan_sha256"] != state["plan"]["sha256"] or row["settings_revision"] != state["settings_revision"]:
            raise WorkflowRefusal("A review holds this plan or belongs to an earlier plan")
        engine.evidence_rows(state, row["evidence_ids"], kinds={"review"}, after=state["plan"]["registered_utc"])


def approve_plan(engine, session_id, *, plan_sha256, action_ids, owner_quote, owner_message_id, owner_id="owner", source="current_owner_chat",
                 acknowledge_permanent_loss=False, expected_revision=None):
    ids(action_ids, "approved action identifiers", allow_empty=False)
    def mutate(state):
        require_writable(state)
        document = current_plan(state, plan_sha256)
        require_reviews(engine, state)
        engine.evidence_rows(state, document["evidence_ids"])
        if set(action_ids) - {a["action_id"] for a in document["actions"]}:
            raise WorkflowRefusal("Approval cannot include actions outside the concrete plan")
        purge_ids = [a["action_id"] for a in document["actions"] if "permanent_data_loss" in acknowledgments(a) and a["action_id"] in action_ids]
        if purge_ids and acknowledge_permanent_loss is not True:
            raise WorkflowRefusal("Permanent purge needs separate actual-owner acknowledgement of irreversible loss bound to these exact purge actions")
        record = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        record.update(plan_sha256=plan_sha256, action_ids=list(action_ids), permanent_loss_action_ids=purge_ids)
        state["approval"] = record
        return ({"action_ids": list(action_ids)},
                "Your actual instruction is recorded for those exact reviewed actions. Fresh checks and protected system consent still apply.")
    return engine.change(session_id, "plan_approved", mutate, expected_revision)


def record_irreversible_ack(engine, session_id, *, plan_sha256, action_ids, acknowledge_irreversible_loss, owner_quote, owner_message_id, owner_id=None,
                            source="current_owner_chat", expected_revision=None):
    ids(action_ids, "irreversible action identifiers", allow_empty=False)
    if acknowledge_irreversible_loss is not True:
        raise WorkflowRefusal("An explicit separate acknowledgement of permanent data loss is required")
    def mutate(state):
        require_writable(state)
        plan = current_plan(state, plan_sha256)
        purge = {a["action_id"] for a in plan["actions"] if "permanent_data_loss" in acknowledgments(a)}
        if set(action_ids) - purge:
            raise WorkflowRefusal("Irreversible-loss acknowledgement binds only exact current permanent-purge actions")
        record = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        record.update(type="permanent_data_loss", plan_sha256=plan_sha256, action_ids=list(action_ids), scope_sha256=digest(state["settings"]["scope"]),
                      acknowledge_irreversible_loss=True)
        state["irreversible_ack"] = record
        return ({"action_ids": action_ids},
                "Your separate acknowledgement of irreversible loss is bound to these exact purge actions, current scope and plan. It cannot authorize another "
                "deletion.")
    return engine.change(session_id, "irreversible_loss_acknowledged", mutate, expected_revision)


def set_standing_policy(engine, session_id, *, action_kinds, max_actions, expires_utc, owner_quote, owner_message_id, targets=None, action_bindings=None,
                        owner_id="owner", source="current_owner_chat", expected_revision=None):
    if (not isinstance(action_kinds, list) or not action_kinds or set(action_kinds) - POLICY_KINDS or len(set(action_kinds)) != len(action_kinds)
            or type(max_actions) is not int or not 1 <= max_actions <= 20):
        raise WorkflowRefusal("Standing policy needs bounded supported ordinary action kinds and 1–20 actions")
    if not isinstance(targets, list) or not targets or len(targets) > 20:
        raise WorkflowRefusal("Standing policy needs exact explicitly selected targets")
    for target in targets:
        bounded_text(target, "policy target", 2000)
    if not isinstance(action_bindings, list) or not action_bindings or len(action_bindings) > 20:
        raise WorkflowRefusal("Standing policy needs exact adapter payload/plan/inventory hash bindings")
    for binding in action_bindings:
        exact_fields(binding, {"adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256"},
                     {"adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256"})
        facts = pc_records.ADAPTERS.get(binding["adapter_id"]) if isinstance(binding["adapter_id"], str) else None
        if (not facts or not facts["policy_coverable"] or not set(facts["kinds"]) & set(action_kinds)
                or any(not isinstance(binding[key], str) or not SHA.fullmatch(binding[key]) for key in binding if key != "adapter_id")):
            raise WorkflowRefusal("Standing policy binding has unsupported adapter or missing exact hashes")
    expiry = utc_time(expires_utc)
    if not utc_time(pc_records.utc_now()) < expiry <= utc_time(pc_records.utc_now()) + timedelta(days=7):
        raise WorkflowRefusal("Policy expiry must be in the next seven days")
    def mutate(state):
        require_writable(state)
        if state["settings"]["control"] != "automatic" or not state["scope_authorization"]:
            raise WorkflowRefusal("Explicit automatic control and current authorized scope are required")
        record = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        record.update(action_kinds=list(action_kinds), targets=list(targets), action_bindings=copy.deepcopy(action_bindings), max_actions=max_actions,
                      used_actions=0, expires_utc=expires_utc, scope_sha256=digest(state["settings"]["scope"]))
        state["standing_policy"] = record
        return ({}, "Your bounded standing policy is recorded. Each exact plan still needs two independent reviews, fresh checks and all selected checkpoints; "
                    "protected consent cannot be automated.")
    return engine.change(session_id, "policy_recorded", mutate, expected_revision)


def action_authorization(state, action):
    approval = state["approval"]
    if approval and action["action_id"] in approval["action_ids"] and approval["plan_sha256"] == state["plan"]["sha256"]:
        return {"kind": "exact_plan", "message_id": approval["message_id"], "plan_sha256": state["plan"]["sha256"], "action_id": action["action_id"]}
    policy = state["standing_policy"]
    if (policy and state["settings"]["control"] == "automatic" and policy["settings_revision"] == state["settings_revision"]
            and policy["scope_sha256"] == digest(state["settings"]["scope"]) and utc_time(policy["expires_utc"]) > utc_time(pc_records.utc_now())
            and policy["used_actions"] < policy["max_actions"] and action["kind"] in policy["action_kinds"] and action["target"] in policy["targets"]
            and {key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256",
                                              "target_inventory_sha256")} in policy["action_bindings"] and not action["requires_os_consent"]
            and pc_records.ADAPTERS[action["adapter_id"]]["policy_coverable"] and not pc_records.ADAPTERS[action["adapter_id"]]["irreversible"]):
        return {"kind": "standing_policy", "message_id": policy["message_id"], "plan_sha256": state["plan"]["sha256"], "action_id": action["action_id"]}
    raise WorkflowRefusal("This exact action lacks current owner authority; control style alone never authorizes a change")


def pending_items(state):
    return [item for item in state["pending"].values() if not item["resolved"]]


def add_checkpoint(state, name, action_id=None):
    if name not in state["settings"]["checkpoints"]:
        return
    token = ("checkpoint-" + name + "-" + digest({"stage": state["stage"], "action": action_id, "settings": state["settings_revision"],
                                                  "plan": state["plan"]["sha256"] if state["plan"] else None})[:20])
    if token not in state["pending"]:
        state["pending"][token] = {"pending_id": token, "kind": "checkpoint", "checkpoint": name, "action_id": action_id, "created_utc": pc_records.utc_now(),
                                   "resolved": False, "settings_revision": state["settings_revision"]}
        if state["status"] == "active":
            state["status"] = "awaiting_user"


def next_action_checkpoint(state):
    if not state["plan"] or state["stage"] != "apply":
        return
    consumed = {op["action_id"] for op in state["operations"].values()}
    for action in state["plan"]["document"]["actions"]:
        if action["action_id"] not in consumed:
            add_checkpoint(state, "before_action", action["action_id"])
            return


def resolve(engine, session_id, *, pending_id=None, evidence_ids=None, choice=None, owner_quote=None, owner_message_id=None, expected_revision=None):
    if pending_id and choice is not None:
        current = engine.read_session(session_id)
        item = current["pending"].get(pending_id)
        if item and item["kind"] == "restart" and not item["resolved"]:
            if evidence_ids:
                raise WorkflowRefusal("A restart choice uses the actual owner instruction, not imported approval evidence")
            return engine.decide_restart(session_id, operation_id=item["operation_id"], choice=choice, owner_quote=owner_quote,
                                         owner_message_id=owner_message_id, expected_revision=expected_revision)
    if choice is None and not evidence_ids:
        state = engine.read_session(session_id)
        items = pending_items(state)
        if pending_id:
            items = [p for p in items if p["pending_id"] == pending_id]
            if not items:
                raise WorkflowRefusal("No unresolved item has that identifier")
        choices = ["keep_stopped"] if state["status"] == "stopped" else ["continue", "revise_plan", "keep_held"]
        if len(items) == 1 and items[0]["kind"] == "restart":
            choices = ["defer", "authorize"]
        elif any(item["kind"] == "restart" for item in items):
            choices += ["defer", "authorize"]
        message = ("Review the specific pending decision or collect its bounded reconciliation evidence. Resolve cannot declare success or retry an action. A "
                   "stopped session remains stopped while actual results are recorded.")
        if state["status"] == "stopped" and any(item["kind"] == "restart" for item in items):
            message += (" For the retained original 3010 operation only, select its restart item to defer or authorize owner-handled restart accounting; this "
                        "cannot reopen work or create another installer attempt.")
        return response(state, "resolution_needed", message, {"pending": items, "choices": choices})
    def mutate(state):
        if not pending_id or pending_id not in state["pending"] or state["pending"][pending_id]["resolved"]:
            raise WorkflowRefusal("Choose one existing unresolved item")
        item = state["pending"][pending_id]
        was_stopped = state["status"] == "stopped"
        if not was_stopped:
            require_writable(state)
        elif item["kind"] != "reconciliation":
            raise WorkflowRefusal("Stopped sessions accept only bounded actual-outcome reconciliation; no new decision/action authority")
        if item["kind"] == "checkpoint":
            if choice != "continue" or not owner_quote or not owner_message_id:
                raise WorkflowRefusal("A checkpoint needs the owner's actual continue decision")
            item["owner_instruction"] = owner_record(state, owner_quote, owner_message_id)
            item["resolved"] = True
            if state["status"] == "awaiting_user" and not pending_items(state):
                state["status"] = "completed" if state["stage"] == "complete" else "active"
        elif item["kind"] == "reconciliation":
            operation = state["operations"][item["operation_id"]]
            if operation["outcome"] is None:
                raise WorkflowRefusal("An active operation must first reach its safe receipt checkpoint")
            if operation["outcome"] == "unknown":
                rows = engine.evidence_rows(state, evidence_ids or [], kinds={"reconciliation", "outcome"}, after=operation["finished_utc"], seconds=900)
                outcomes = {row["facts"].get("outcome") for row in rows}
                if len(outcomes) != 1 or not outcomes <= {"succeeded", "failed", "partial"}:
                    raise WorkflowRefusal("A fresh actual observed outcome is required; unknown cannot be marked resolved")
                outcome = outcomes.pop()
                engine.outcome_rows(state, operation, evidence_ids, outcome)
                operation.update(outcome=outcome, evidence_ids=list(evidence_ids), summary="Actual outcome established by fresh reconciliation evidence")
            if operation["outcome"] == "succeeded":
                item["resolved"] = True
                state["status"] = "stopped" if was_stopped else "paused"
                if not was_stopped:
                    add_checkpoint(state, "after_action", operation["action_id"])
                    next_action_checkpoint(state)
            elif choice in {"revise_plan", "keep_stopped"} and owner_quote and owner_message_id:
                if operation.get("restart_pending") and operation.get("restart_verification", {}).get("boot_observed") is not True:
                    raise WorkflowRefusal("The original restart requirement still needs actual boot accounting; generic effects flags cannot clear it")
                if was_stopped != (choice == "keep_stopped"):
                    raise WorkflowRefusal("A stopped session may account for actual effects while staying stopped; it cannot request or resume a replacement "
                                          "plan")
                rows = engine.outcome_rows(state, operation, evidence_ids or [], operation["outcome"])
                if any(row["kind"] != "reconciliation" or utc_time(row["observed_utc"]) < utc_time(operation["finished_utc"])
                       or any(row["facts"].get(flag) is not True for flag in ("actual_effects_recorded", "no_active_effects", "recovery_retained"))
                       for row in rows):
                    raise WorkflowRefusal("Replanning needs fresh actual-effects reconciliation, no ongoing operation and retained recovery; the historical "
                                          "failure remains unchanged")
                item["owner_instruction"] = owner_record(state, owner_quote, owner_message_id)
                item["resolved"] = True
                operation["resolution"] = {"kind": "effects_accounted" if was_stopped else "replan_required", "evidence_ids": list(evidence_ids),
                                           "recorded_utc": pc_records.utc_now(), "owner_message_id": owner_message_id}
                if not was_stopped:
                    state["plan"] = None
                    state["approval"] = None
                    state["reviews"] = []
                    state["stage"] = "plan"
                state["status"] = "stopped" if was_stopped else "held"
            elif choice in {"keep_held", None}:
                state["status"] = "stopped" if was_stopped else "held"
            else:
                raise WorkflowRefusal("An unsuccessful action stays held; the owner may request a separately reviewed replacement plan")
        else:
            raise WorkflowRefusal("This pending item has no general-purpose resolution")
        return ({"pending": item},
                "The identified item is reconciled only to the extent supported by actual evidence and your bounded decision. No action was retried.")
    return engine.change(session_id, "resolved", mutate, expected_revision)


def advance_stage(engine, session_id, *, evidence_ids, expected_revision=None):
    def mutate(state):
        if state["status"] != "active" or pending_items(state):
            raise WorkflowRefusal("Stage advancement waits for an active session and resolved checkpoints")
        engine.require_schedule_activation(state)
        stage = state["stage"]
        rows = engine.evidence_rows(state, evidence_ids, allow_empty=stage in {"plan", "apply"})
        required = {"scope": ("scope_confirmation", {"scope_confirmed"}), "inventory": ("inventory", {"complete"}),
                    "research": ("research", {"applicability_checked", "official_sources_checked"}),
                    "candidates": ("candidates", {"candidates_reviewed", "excluded_private"}), "symptom": ("symptom", {"symptom_recorded", "relevant_scope"}),
                    "hypotheses": ("hypotheses", {"alternatives_considered", "distinguishing_checks"}),
                    "recovery_plan": ("recovery_plan", {"contents_reviewed", "restore_check_planned", "exclusions_explicit"})}
        if stage in required:
            kind, flags = required[stage]
            matching = [row for row in rows if row["kind"] == kind and all(row["facts"].get(flag) is True for flag in flags)]
            if not matching:
                raise WorkflowRefusal("This stage needs owned evidence establishing its actual required checks")
            if stage == "scope" and (not state["scope_authorization"] or not _scope_selected(state["settings"]["scope"])):
                raise WorkflowRefusal("An actual current-owner scope decision is required before assessment")
            if stage == "inventory" and not any(type(row["facts"].get("item_count")) is int and row["facts"]["item_count"] >= 0 for row in matching):
                raise WorkflowRefusal("Inventory must record an explicit assessed item count")
        elif stage == "plan":
            require_reviews(engine, state)
            for action in state["plan"]["document"]["actions"]:
                action_authorization(state, action)
        elif stage == "apply":
            if not state["plan"]:
                raise WorkflowRefusal("No current plan can be verified")
            planned = {a["action_id"] for a in state["plan"]["document"]["actions"]}
            succeeded = {op["action_id"] for op in state["operations"].values() if op["plan_sha256"] == state["plan"]["sha256"]
                         and op["outcome"] == "succeeded"}
            if planned != succeeded:
                raise WorkflowRefusal("Every current planned action needs its own actual successful receipt before verification")
        elif stage == "verify":
            if not state["plan"]:
                raise WorkflowRefusal("Verification needs the exact current plan")
            planned = {a["action_id"] for a in state["plan"]["document"]["actions"]}
            latest = max(op["finished_utc"] for op in state["operations"].values() if op["plan_sha256"] == state["plan"]["sha256"])
            verified = [row for row in rows if row["kind"] == "verification" and row["facts"].get("verification_passed") is True
                        and row["facts"].get("plan_sha256") == state["plan"]["sha256"] and set(row["facts"].get("checked_action_ids", [])) == planned
                        and utc_time(row["observed_utc"]) >= utc_time(latest)]
            if not verified:
                raise WorkflowRefusal("Actual behavior verification for every exact planned action is required after its outcome")
        else:
            raise WorkflowRefusal("This job is already at its final stage")
        stages = JOBS[state["job"]]["stages"]
        state["stage"] = stages[stages.index(stage) + 1]
        checkpoint = "findings" if state["stage"] == "plan" else "plan" if state["stage"] == "apply" else "finish" if state["stage"] == "complete" else None
        if checkpoint:
            add_checkpoint(state, checkpoint)
        if state["stage"] == "complete" and not pending_items(state):
            state["status"] = "completed"
        if state["stage"] == "apply":
            next_action_checkpoint(state)
        return ({"stage": state["stage"]}, "The evidence supports the next step: " + STAGE_LABELS[state["stage"]].lower() + ". "
                + ("The actual checked result is complete; retained evidence and recovery files still need a separate cleanup decision."
                   if state["status"] == "completed" else "Use PatchCairn: options for the next decision and any selected checkpoint."))
    return engine.change(session_id, "stage_advanced", mutate, expected_revision)


def complete_assessment(engine, session_id, *, summary_evidence_id, verification_evidence_ids, owner_quote, owner_message_id, owner_id=None,
                        source="current_owner_chat", expected_revision=None):
    record_identifier(summary_evidence_id)
    def mutate(state):
        require_writable(state)
        if state["status"] != "active" or state["stage"] != "plan" or pending_items(state):
            raise WorkflowRefusal("Finish the assessment stages and selected checkpoints before closing an assessment")
        activation = engine.require_schedule_activation(state)
        if state["operations"] or state["plan"] is not None or state["approval"] is not None or state["reviews"] or state["standing_policy"] is not None:
            raise WorkflowRefusal("Assessment-only completion cannot close a session with any operation history, plan, approval, reviews or standing policy")
        authorization = state["scope_authorization"]
        scope_sha = digest(state["settings"]["scope"])
        if (not authorization or authorization.get("owner_id") != state["owner_id"] or authorization.get("settings_revision") != state["settings_revision"]
                or authorization.get("scope_sha256") != scope_sha):
            raise WorkflowRefusal("Assessment completion requires the actual current owner's exact authorized scope")
        after = max((authorization["recorded_utc"], activation["activated_utc"]), key=utc_time) if activation else authorization["recorded_utc"]
        summary_row = engine.evidence_rows(state, [summary_evidence_id], kinds={"research"}, after=after, seconds=900)[0]
        summary = typed_record(decode_record(engine.journal.read_owned(engine.journal.directory(session_id) / summary_row["path"])), ASSESSMENT_SUMMARY)
        if (summary["job"] != state["job"] or summary["mode"] != state["mode"] or summary["scope_sha256"] != scope_sha
                or summary["settings_revision"] != state["settings_revision"]):
            raise WorkflowRefusal("The assessment summary must bind this exact current job, mode and scope")
        bounded_text(summary["summary"], "assessment summary", 4000)
        for label in ("findings", "limitations"):
            if not isinstance(summary[label], list) or len(summary[label]) > 100:
                raise WorkflowRefusal("Assessment findings and limitations must be bounded selected text")
            for item in summary[label]:
                bounded_text(item, "assessment " + label, 2000)
        ids(summary["assessed_evidence_ids"], "assessed evidence identifiers", allow_empty=False)
        if summary_evidence_id in summary["assessed_evidence_ids"]:
            raise WorkflowRefusal("An assessment summary cannot stand in for its underlying assessment evidence")
        assessed = engine.evidence_rows(state, summary["assessed_evidence_ids"], kinds={"scope_confirmation", "inventory", "research", "candidates", "symptom",
                                                                                        "hypotheses", "recovery_plan"}, after=authorization["recorded_utc"])
        requirements = {"scope": ("scope_confirmation", {"scope_confirmed"}), "inventory": ("inventory", {"complete"}),
                        "research": ("research", {"applicability_checked", "official_sources_checked"}),
                        "candidates": ("candidates", {"candidates_reviewed", "excluded_private"}),
                        "symptom": ("symptom", {"symptom_recorded", "relevant_scope"}),
                        "hypotheses": ("hypotheses", {"alternatives_considered", "distinguishing_checks"}),
                        "recovery_plan": ("recovery_plan", {"contents_reviewed", "restore_check_planned", "exclusions_explicit"})}
        for stage in JOBS[state["job"]]["stages"][:JOBS[state["job"]]["stages"].index("plan")]:
            kind, flags = requirements[stage]
            if not any(row["kind"] == kind and all(row["facts"].get(flag) is True for flag in flags) for row in assessed):
                raise WorkflowRefusal("The summary must cover the actual current evidence for every agreed assessment step")
        rows = engine.evidence_rows(state, verification_evidence_ids, kinds={"verification"}, after=summary_row["registered_utc"], seconds=900)
        for row in rows:
            verification = typed_record(decode_record(engine.journal.read_owned(engine.journal.directory(session_id) / row["path"])), ASSESSMENT_VERIFICATION)
            if (any(verification[key] != summary[key] for key in ("job", "mode", "scope_sha256", "settings_revision", "assessed_evidence_ids"))
                    or verification["summary_evidence_id"] != summary_evidence_id or verification["summary_sha256"] != summary_row["sha256"]
                    or verification["coverage_checked"] is not True or verification["limitations_checked"] is not True
                    or verification["observed_utc"] != row["observed_utc"]):
                raise WorkflowRefusal("Assessment verification must check the exact current summary, evidence coverage and recorded limitations")
            fresh(verification["observed_utc"], after=summary_row["registered_utc"], seconds=900)
        record = {"summary_evidence_id": summary_evidence_id, "summary_sha256": summary_row["sha256"],
                  "verification_evidence_ids": list(verification_evidence_ids),
                  "owner_instruction": owner_record(state, owner_quote, owner_message_id, owner_id, source)}
        key = "assessment-finish-" + digest({"summary": summary_row["sha256"], "settings": state["settings_revision"], "message": owner_message_id})[:24]
        state["pending"][key] = {"pending_id": key, "kind": "assessment_finish", "resolved": True, "record": record}
        state["stage"] = "complete"
        add_checkpoint(state, "finish")
        if not pending_items(state):
            state["status"] = "completed"
        return (record, "The assessment and its findings are recorded, including what remains uncertain. This session recorded no maintenance action. "
                + ("Review the selected finish checkpoint before closing." if state["status"] != "completed"
                   else "The assessment session is complete; any computer change needs a separate reviewed plan."))
    return engine.change(session_id, "assessment_completed", mutate, expected_revision)
