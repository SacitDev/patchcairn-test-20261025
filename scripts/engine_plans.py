"""A session's creation and settings, scope, evidence, plans, reviews, owner approvals, standing policies, stages and pending
decisions.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there. The pure
rules they apply are in engine_decisions; every public name of this module keeps its definition here.
"""
from __future__ import annotations

import copy
from pathlib import Path
import re
import uuid

import diagnostic_core
import engine_decisions
from engine_decisions import (ATTESTATION, CONDITIONAL_FIELDS, POLICY_KINDS, REPLY_FIELDS, REVIEW, ROLES, VERDICTS, WARNING_FIELDS, approved_ids,
                              remaining_actions, reply_matches, typed)
import engine_journal
from engine_journal import (ASSESSMENT_ACCESS, ASSESSMENT_SUMMARY, ASSESSMENT_VERIFICATION, BACKEND, CREATION_KEYS, DIAGNOSTIC_ADAPTER, FIXTURE_ADAPTER,
                            OUTCOMES, RECOVERY_BINDING, SHA, STATE_KEYS, WorkflowRefusal, bounded_text, checked, container, decode_record, exact_fields,
                            fresh, ids, invalidate, no_links, private_directory, private_file, record_identifier, require_writable, restart_state,
                            typed_record, utc_time, write_private_new)
import engine_text
from engine_text import CHECKPOINTS, JOBS, STAGE_LABELS, irreversible_phrase, response
import pc_paths
import pc_records
from pc_records import SCHEMA_VERSION, TYPED_ACKNOWLEDGMENTS, digest, encoded
import private_workspace
import storage_contract


# Every action kind a registered adapter may carry (pc_records.ADAPTERS) is a plan kind, and there is no other.
KINDS = {kind for facts in pc_records.ADAPTERS.values() for kind in facts["kinds"]}
EVIDENCE_KINDS = {"scope_confirmation", "inventory", "research", "candidates", "symptom", "hypotheses", "recovery_plan", "precondition", "outcome",
                  "reconciliation", "verification", "recovery", "review", "fixture"}
EVIDENCE_KINDS |= {"adapter_payload", "recovery_manifest", "restore_verification", "retention", "recovery_archive"}
# Facts are copied into the journal state, so they stay small; large data belongs in the evidence content.
FACTS_MAX_BYTES = 65_536
# A session keeps the message ids of its owner decisions, at most this many.
MAX_USED_MESSAGE_IDS = 1000
OWNER_SOURCES = ("current_owner_chat", "current_owner_terminal")
# The evidence kind and facts each assessment stage needs (advance_stage and complete_assessment).
STAGE_REQUIREMENTS = {"scope": ("scope_confirmation", {"scope_confirmed"}), "inventory": ("inventory", {"complete"}),
                      "research": ("research", {"applicability_checked", "official_sources_checked"}),
                      "candidates": ("candidates", {"candidates_reviewed", "excluded_private"}), "symptom": ("symptom", {"symptom_recorded", "relevant_scope"}),
                      "hypotheses": ("hypotheses", {"alternatives_considered", "distinguishing_checks"}),
                      "recovery_plan": ("recovery_plan", {"contents_reviewed", "restore_check_planned", "exclusions_explicit"})}
# The one reader of assistant review records (pc_records.READERS).
read_review = pc_records.register_reader(REVIEW, engine_decisions.read_review)


def acknowledgments(action):
    """Acknowledgments the owner gives separately for this action (pc_records facts)."""
    return pc_records.ADAPTERS[action["adapter_id"]]["acknowledgments"]


def json_data(value):
    """Bounded JSON evidence data that the one encoder also accepts (no lone surrogates, integers within 20
    digits), checked before anything is written."""
    engine_decisions.json_shape(value)
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
        value = decode_record(content, max_bytes=engine_journal.EVIDENCE_MAX_BYTES, max_nodes=engine_journal.EVIDENCE_MAX_NODES)
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
    """An owner decision as the coordinator writes it from the owner's message, labelled coordinator-attested: the record
    names the message and where it was given, and does not show who wrote that message."""
    if source not in OWNER_SOURCES or (owner_id or state["owner_id"]) != state["owner_id"]:
        raise WorkflowRefusal("Only the session owner's own instruction, given in this conversation or terminal, can authorize this decision")
    bounded_text(owner_quote, "owner quote")
    record_identifier(owner_message_id, "owner message identifier")
    return {"owner_id": state["owner_id"], "quote": owner_quote, "message_id": owner_message_id, "source": source, "recorded_utc": pc_records.utc_now(),
            "settings_revision": state["settings_revision"], "attestation": ATTESTATION}


def used_message_id(engine, message_id):
    """True when a session in this engine's registry used ``message_id`` for a decision; the caller holds the registry lock.
    It reads and checks every session's state, so one decision reads as many states as the registry holds sessions."""
    return any(path.is_dir() and path.name.startswith("session-") and message_id in engine.read_session(path.name)["used_message_ids"]
               for path in engine.work.iterdir())


def claim_message(engine, state, owner_message_id):
    """Record that ``owner_message_id`` backs one decision of this session: a message already used by a decision of any
    session of this engine is refused. Called once per decision, under the registry lock (_decision)."""
    if owner_message_id in state["used_message_ids"] or used_message_id(engine, owner_message_id):
        raise WorkflowRefusal("This message was already used for a decision; ask the owner to reply again", code="message-id-used")
    if len(state["used_message_ids"]) >= MAX_USED_MESSAGE_IDS:
        raise WorkflowRefusal("This session has recorded all the decisions it can; start a new session", code="message-ids-full")
    state["used_message_ids"].append(owner_message_id)


def _decision(engine, session_id, event_type, mutate, expected_revision):
    """Commit an owner decision under the registry lock, so its message id is checked against every session."""
    with engine.journal.registry_lock():
        return engine.change(session_id, event_type, mutate, expected_revision)


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
        exact_fields(op, fields | {"restart_pending", "restart_verification"}, fields)
        for name in ("restart_pending", "restart_verification"):
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
    engine_decisions.typed_state(state, MAX_USED_MESSAGE_IDS)
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
             "operations": {}, "pending": {}, "schedule": None, "schedule_triggers": [], "last_reconciled_utc": None, "stop_reason": None,
             "irreversible_warning": None, "used_message_ids": [], "conditional_decisions": []}
    validate_state(engine, state)
    private_directory(engine.work)
    private_file(engine.work / "engine.json")
    directory = engine.work / session_id
    private_directory(directory, create=True)
    private_directory(directory / "evidence", create=True)
    marker = {"schema_version": SCHEMA_VERSION, **{key: state[key] for key in CREATION_KEYS}}
    write_private_new(directory / "creation.json", encoded(marker))
    engine.journal.commit(directory, state, [], "created", {"job": job})
    return response(state, "created", JOBS[job]["label"] + " is open. Nothing has been checked yet. What may I look at: the whole device, "
                    "selected drives or folders, or one problem? Reply in your own words.", {"state": state})


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
        claim_message(engine, state, owner_message_id)
        if state["status"] == "awaiting_user" and state["settings"]["timing"] == "now":
            state["status"] = "active"
        return {}, "Your exact scope decision is recorded. It permits only the agreed evidence collection; computer changes need a separate concrete plan."
    return _decision(engine, session_id, "scope_authorized", mutate, expected_revision)


def register_evidence(engine, session_id, *, evidence_id, content, kind, scope, facts=None, observed_utc=None, expected_revision=None):
    record_identifier(evidence_id, "evidence identifier")
    if not isinstance(content, bytes) or not 0 < len(content) <= engine_journal.EVIDENCE_MAX_BYTES or kind not in EVIDENCE_KINDS:
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
    """This session's evidence rows of the current scope and settings; ``seconds`` None sets no age limit (only a consumed
    action's original evidence, action_binding)."""
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
        if seconds is not None:
            fresh(row["observed_utc"], after=after, seconds=seconds)
        rows.append(row)
    return rows


def _evidence_value(engine, state, row):
    """The decoded content of this session's evidence ``row``, within the evidence caps engine_journal sets when it is read."""
    data = engine.journal.read_owned(engine.journal.directory(state["session_id"]) / row["path"], engine_journal.EVIDENCE_MAX_BYTES)
    return decode_record(data, max_bytes=engine_journal.EVIDENCE_MAX_BYTES, max_nodes=engine_journal.EVIDENCE_MAX_NODES)


def validate_plan_document(state, plan):
    """The plan document's fixed shape and per-action rules, and the composition rule (engine_decisions)."""
    engine_decisions.validate_plan_document(state, plan)


def action_binding(engine, state, action, *, operation_id=None):
    """The reviewed payload of ``action``, after its hashes, scope, settings and adapter rules are checked. A new launch gives no
    ``operation_id``: its payload and inventory must be fresh, and a restore probe must still be absent. ``operation_id`` names
    the action's own consumed operation (engine_decisions.require_consumed): the same original binding is checked with no age
    limit, because such a step may finish long after its plan, after a restart for example. What that step finds now needs
    fresh observations of its own."""
    limit = {}
    if operation_id is not None:
        engine_decisions.require_consumed(state, action, operation_id)
        limit["seconds"] = None
    payload_row = engine.evidence_rows(state, [action["adapter_payload_evidence_id"]], kinds={"adapter_payload"}, **limit)[0]
    inventory_row = engine.evidence_rows(state, [action["target_inventory_evidence_id"]], kinds={"inventory"}, **limit)[0]
    if payload_row["sha256"] != action["adapter_payload_sha256"] or inventory_row["sha256"] != action["target_inventory_sha256"]:
        raise WorkflowRefusal("Exact reviewed adapter payload or target inventory has changed")
    payload, inventory = (_evidence_value(engine, state, row) for row in (payload_row, inventory_row))
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
    elif action["adapter_id"] in pc_records.ADAPTERS and pc_records.ADAPTERS[action["adapter_id"]]["family"] in engine_decisions.UPDATE_FAMILIES:
        # The update and repair families bind in engine_updates, reached through the engine (no import of it here).
        engine.update_binding(state, action, payload, inventory)
    elif action["adapter_id"] in storage_contract.PLAN_KINDS:
        # Every storage adapter binds here; the service holds an id whose family code is not written yet.
        checked(storage_contract.validate_payload, payload, adapter_id=action["adapter_id"], mode=state["mode"], plan_sha256=action["adapter_plan_sha256"])
        json_data(payload["storage_plan"])
        output_value = Path(bounded_text(payload["output_root"], "owned storage output root", 2000))
        if not output_value.is_absolute():
            raise WorkflowRefusal("Storage output root must be an exact absolute owned work path")
        output = no_links(output_value)
        # Parts are compared by the file system's own rule; a path equal to the work tree passes, as before.
        if private_workspace.relative_parts(output, engine.root / "work") is None:
            raise WorkflowRefusal("Adapter outputs must stay inside this repository's owned work tree")
        if "backup_destination" in payload and (action["adapter_id"] != pc_records.ADAPTER_STORAGE_BACKUP_CREATE
                                                or payload["backup_destination"] not in payload["protected_roots"]):
            raise WorkflowRefusal("Only a reviewed backup names an outside destination, and that destination must be one of its protected roots",
                                  code="backup-destination")
        probe_value = payload.get("restore_probe_destination")
        if probe_value is not None:
            if action["adapter_id"] != pc_records.ADAPTER_STORAGE_BACKUP_CREATE or not isinstance(probe_value, str) or not Path(probe_value).is_absolute():
                raise WorkflowRefusal("Only an explicitly reviewed backup action can include an exact owned restore-probe destination")
            probe = no_links(Path(probe_value))
            if private_workspace.relative_parts(probe, output) is None:
                raise WorkflowRefusal("Restore probe must stay under the exact owned backup output root")
            if operation_id is None and probe.exists():
                raise WorkflowRefusal("The reviewed restore-probe destination is no longer absent")
        source_inventory = payload["storage_plan"].get("inventory", payload["storage_plan"].get("records", payload["storage_plan"].get("receipt")))
        if source_inventory is None or digest(source_inventory) != digest(inventory):
            raise WorkflowRefusal("Adapter target inventory is not the exact owned inventory/receipt reviewed in the lower-level plan")
    else:
        # A registered adapter whose family code is not written yet: the facts allow it, nothing binds it.
        raise WorkflowRefusal("This adapter's payload binding is not written yet; the action is held", code="adapter-held")
    return payload


def _depends(payload):
    """The depends_on list a bound payload gives (only update and repair payloads carry one), or None."""
    return payload.get("depends_on") if isinstance(payload, dict) else None


def _backup_receipts(engine, state, actions):
    """The backup receipt each recovery binding of ``actions`` names (None for a binding that names none)."""
    values = [_evidence_value(engine, state, row) for action in actions
              for row in engine.evidence_rows(state, action["recovery_evidence_ids"], kinds={"recovery"})]
    return [value.get("backup_receipt") if isinstance(value, dict) and value.get("schema") == RECOVERY_BINDING else None for value in values]


def register_plan(engine, session_id, *, plan, expected_revision=None):
    """Register an exact plan before the apply stage, or the one follow-up removal plan at the verify stage."""
    document = copy.deepcopy(plan)
    def mutate(state):
        require_writable(state)
        validate_plan_document(state, document)
        stages = JOBS[state["job"]]["stages"]
        removal = any(action["adapter_id"] == pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS for action in document["actions"])
        if state["plan"] and any(action["adapter_id"] == pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS for action in state["plan"]["document"]["actions"]):
            raise WorkflowRefusal("The follow-up removal plan is this session's last plan; start a new session for other changes", code="followup-plan")
        if not removal and state["stage"] not in stages[:stages.index("apply")]:
            raise WorkflowRefusal("A new or replacement plan must be reviewed before the apply stage; existing action, verification and finish checkpoints "
                                  "cannot authorize another plan")
        if any(op["outcome"] is None for op in state["operations"].values()):
            raise WorkflowRefusal("Reconcile the active operation before replacing its plan")
        engine.evidence_rows(state, document["evidence_ids"])
        if not state["scope_authorization"]:
            raise WorkflowRefusal("The current owner has not authorized this scope")
        consumed = {op["action_id"] for op in state["operations"].values()}
        payloads = []
        for action in document["actions"]:
            payloads.append(action_binding(engine, state, action))
            if action["action_id"] in consumed:
                raise WorkflowRefusal("A consumed action identifier cannot be reused or retried")
            if action["requires_recovery"] or action["recovery_evidence_ids"]:
                engine.verify_recovery(state, action["recovery_evidence_ids"], action=action)
            if action.get("estimate_evidence_id"):
                estimate = engine.evidence_rows(state, [action["estimate_evidence_id"]], kinds={"inventory"})[0]
                if estimate["facts"].get("action_id") != action["action_id"]:
                    raise WorkflowRefusal("A cost fact must identify this exact action to prevent unrelated or duplicate workload estimates")
        action_ids = [action["action_id"] for action in document["actions"]]
        engine_decisions.check_depends_on(action_ids, {action_id: _depends(payload) for action_id, payload in zip(action_ids, payloads)})
        data, notes = {}, []
        if removal:
            receipts = _backup_receipts(engine, state, document["actions"])
            engine_decisions.check_followup(state, document, receipts)
            notes, read_only = engine_decisions.followup_notes(receipts, [row for payload in payloads for row in payload["storage_plan"]["files"]])
            data["followup"] = {"notes": notes, "read_only_files": read_only}
            state["stage"] = "plan"
        state["plan"] = {"document": document, "sha256": digest(document), "settings_revision": state["settings_revision"],
                         "registered_utc": pc_records.utc_now()}
        engine_decisions.clear_plan_decisions(state)
        return ({"plan_sha256": state["plan"]["sha256"], "action_ids": action_ids, **data},
                " ".join(["The exact plan is saved. It still needs two assistant review passes and your decision on its exact actions before any change."]
                         + notes))
    return engine.change(session_id, "plan_registered", mutate, expected_revision)


def current_plan(state, plan_sha256):
    if not state["plan"] or state["plan"]["sha256"] != plan_sha256 or state["plan"]["settings_revision"] != state["settings_revision"]:
        raise WorkflowRefusal("The exact current plan hash is required")
    return state["plan"]["document"]


def record_review(engine, session_id, *, plan_sha256, reviewer_id, role, verdict, evidence_ids, notes, expected_revision=None):
    """Record one assistant review pass of the exact current plan; its evidence is a typed review of this plan, role, verdict
    and reviewer, used by no other review."""
    record_identifier(reviewer_id, "reviewer identifier")
    bounded_text(notes, "review notes")
    if not isinstance(role, str) or role not in ROLES or not isinstance(verdict, str) or verdict not in VERDICTS:
        raise WorkflowRefusal("A supported review role and approved/hold verdict are required")
    def mutate(state):
        require_writable(state)
        current_plan(state, plan_sha256)
        rows = engine.evidence_rows(state, evidence_ids, kinds={"review"}, after=state["plan"]["registered_utc"])
        if reviewer_id == state["owner_id"] or any(row["reviewer_id"] == reviewer_id or row["role"] == role for row in state["reviews"]):
            raise WorkflowRefusal("The two assistant review passes need different reviewers and roles, separate from the owner")
        expected = {"plan_sha256": plan_sha256, "role": role, "verdict": verdict, "reviewer_id": reviewer_id}
        reviews = (read_review(_evidence_value(engine, state, row)) for row in rows)  # each row read and checked once, after the reuse check below
        if (set(evidence_ids) & {evidence_id for row in state["reviews"] for evidence_id in row["evidence_ids"]}
                or any({key: review[key] for key in expected} != expected for review in reviews)):
            raise WorkflowRefusal("Each assistant review pass needs its own typed review evidence for this exact plan, role, verdict and reviewer",
                                  code="review-evidence")
        record = {"reviewer_id": reviewer_id, "role": role, "verdict": verdict, "evidence_ids": list(evidence_ids), "notes": notes, "plan_sha256": plan_sha256,
                  "settings_revision": state["settings_revision"], "recorded_utc": pc_records.utc_now(), "attestation": ATTESTATION}
        state["reviews"].append(record)
        state["approval"] = None
        return record, "The assistant review pass is recorded against the exact current plan. A held review prevents changes."
    return engine.change(session_id, "review_recorded", mutate, expected_revision)


def require_reviews(engine, state):
    reviews = state["reviews"]
    if (not state["plan"] or len(reviews) != 2 or {row["role"] for row in reviews} != ROLES or len({row["reviewer_id"] for row in reviews}) != 2
            or len({evidence_id for row in reviews for evidence_id in row["evidence_ids"]}) != sum(len(row["evidence_ids"]) for row in reviews)):
        raise WorkflowRefusal("Two assistant review passes are required: compatibility and data safety, and evidence and security")
    for row in reviews:
        if row["verdict"] != "approved" or row["plan_sha256"] != state["plan"]["sha256"] or row["settings_revision"] != state["settings_revision"]:
            raise WorkflowRefusal("A review holds this plan or belongs to an earlier plan")
        engine.evidence_rows(state, row["evidence_ids"], kinds={"review"}, after=state["plan"]["registered_utc"])


def _typed_reply(state, action_ids, owner_quote):
    """The approval's typed reply (all warned actions, the current warning's whole phrase), or None."""
    warned = [a for a in state["plan"]["document"]["actions"] if a["action_id"] in action_ids and typed(a)]
    if not warned:
        return None
    warning = state["irreversible_warning"] or {}
    if warning.get("plan_sha256") != state["plan"]["sha256"] or set(warning.get("action_ids", ())) != {a["action_id"] for a in warned}:
        raise WorkflowRefusal("Show this plan's warning first; the typed reply approves all warned actions together", code="typed-reply-warning")
    phrase = irreversible_phrase(warning.get("kind"), warning.get("number"))
    if not reply_matches(owner_quote, phrase):
        raise WorkflowRefusal(engine_text.WRONG_REPLY + phrase, code="typed-reply-mismatch")
    return {"type": min(TYPED_ACKNOWLEDGMENTS & set(acknowledgments(warned[0]))), "action_ids": list(warning["action_ids"]),
            "number": warning["number"], "bytes": warning["bytes"], "warning_revision": warning["revision"]}


def approve_plan(engine, session_id, *, plan_sha256, action_ids, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat",
                 expected_revision=None):
    """The owner's approval of exact reviewed actions, with every action each one depends on; a plan with a permanent deletion
    or a firmware update is approved whole, by the typed reply. One message is the approval and its typed reply."""
    ids(action_ids, "approved action identifiers", allow_empty=False)
    def mutate(state):
        require_writable(state)
        document = current_plan(state, plan_sha256)
        require_reviews(engine, state)
        engine.evidence_rows(state, document["evidence_ids"])
        plan_ids = [a["action_id"] for a in document["actions"]]
        if set(action_ids) - set(plan_ids):
            raise WorkflowRefusal("Approval cannot include actions outside the concrete plan")
        engine_decisions.check_approval(plan_ids, plan_depends_on(engine, state), action_ids, any(map(typed, document["actions"])), state["operations"])
        purge_ids = [a["action_id"] for a in document["actions"] if "permanent_data_loss" in acknowledgments(a) and a["action_id"] in action_ids]
        record = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        record.update(plan_sha256=plan_sha256, action_ids=list(action_ids), permanent_loss_action_ids=purge_ids,
                      irreversible=_typed_reply(state, action_ids, owner_quote))
        claim_message(engine, state, owner_message_id)
        state["approval"] = record
        return ({"action_ids": list(action_ids)},
                "Your approval is recorded for exactly these changes. I check again just before each one, and your computer may still ask you to confirm.")
    return _decision(engine, session_id, "plan_approved", mutate, expected_revision)


def record_irreversible_ack(engine, session_id, *, plan_sha256, action_ids, acknowledge_irreversible_loss, owner_quote, owner_message_id, owner_id=None,
                            source="current_owner_chat", expected_revision=None):
    """The owner's separate acknowledgement that no typed reply gives (today a repair without component rollback)."""
    ids(action_ids, "acknowledged action identifiers", allow_empty=False)
    if acknowledge_irreversible_loss is not True:
        raise WorkflowRefusal("An explicit separate acknowledgement is required")
    def mutate(state):
        require_writable(state)
        plan = current_plan(state, plan_sha256)
        chosen = [a for a in plan["actions"] if a["action_id"] in action_ids]
        needed = {acknowledgment for action in chosen for acknowledgment in acknowledgments(action)}
        if needed & TYPED_ACKNOWLEDGMENTS:
            raise WorkflowRefusal("A permanent deletion or a firmware update needs the typed reply to its warning", code="typed-reply-required")
        if len(chosen) != len(action_ids) or len(needed) != 1 or not all(acknowledgments(action) for action in chosen):
            raise WorkflowRefusal("A separate acknowledgement binds only exact current actions that all need the same one")
        record = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        record.update(type=needed.pop(), plan_sha256=plan_sha256, action_ids=list(action_ids), scope_sha256=digest(state["settings"]["scope"]),
                      acknowledge_irreversible_loss=True)
        claim_message(engine, state, owner_message_id)
        state["irreversible_ack"] = record
        return ({"action_ids": action_ids},
                "Your separate acknowledgement is bound to these exact actions, the current scope and plan. It cannot authorize another change.")
    return _decision(engine, session_id, "irreversible_loss_acknowledged", mutate, expected_revision)


def issue_irreversible_warning(engine, session_id, *, plan_sha256, expected_revision=None):
    """After both reviews, record the warning that the owner's typed reply answers: actions, number and bytes."""
    def mutate(state):
        require_writable(state)
        document = current_plan(state, plan_sha256)
        require_reviews(engine, state)
        warned = [a for a in document["actions"] if typed(a)]
        firmware = bool(warned) and "firmware_risk" in acknowledgments(warned[0])
        if not warned or len({a["adapter_id"] for a in warned}) != 1 or firmware and len(warned) != 1:
            raise WorkflowRefusal("A typed reply covers one kind of permanent deletion, or one firmware update, per plan", code="typed-reply-plan")
        payloads = [action_binding(engine, state, action) for action in warned]
        if firmware:
            device = payloads[0].get("device") if isinstance(payloads[0], dict) else None
            number, size = (device.get("number") if isinstance(device, dict) else None), None
        else:
            number, size = sum(payload["delete_count"] for payload in payloads), sum(payload["delete_bytes"] for payload in payloads)
        phrase = irreversible_phrase(warned[0]["kind"], number)
        state["irreversible_warning"] = warning = {"plan_sha256": plan_sha256, "kind": warned[0]["kind"], "action_ids": [a["action_id"] for a in warned],
                                                   "number": number, "bytes": size, "revision": state["revision"] + 1, "recorded_utc": pc_records.utc_now()}
        details = engine_text.release_details(warning, payloads)
        if warned[0]["adapter_id"] == pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS:
            files = [row for payload in payloads for row in payload["storage_plan"]["files"]]
            details["notes"] = engine_decisions.followup_notes(_backup_receipts(engine, state, warned), files)[0]
        return ({"phrase": phrase, "action_ids": warning["action_ids"], "number": number, "bytes": size},
                engine_text.firmware_warning(warning, platform=state["platform"], device=device.get("name"), version=device.get("target_version"),
                                             flags=payloads[0].get("flags")) if firmware else engine_text.deletion_warning(warning, **details))
    return engine.change(session_id, "irreversible_warning_recorded", mutate, expected_revision)


def set_standing_policy(engine, session_id, *, action_kinds, max_actions, expires_utc, owner_quote, owner_message_id, targets=None, action_bindings=None,
                        owner_id=None, source="current_owner_chat", expected_revision=None):
    engine_decisions.check_policy_request(action_kinds, max_actions, expires_utc, targets, action_bindings)
    def mutate(state):
        require_writable(state)
        if state["settings"]["control"] != "automatic" or not state["scope_authorization"]:
            raise WorkflowRefusal("Explicit automatic control and current authorized scope are required")
        record = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        record.update(action_kinds=list(action_kinds), targets=list(targets), action_bindings=copy.deepcopy(action_bindings), max_actions=max_actions,
                      used_actions=0, expires_utc=expires_utc, scope_sha256=digest(state["settings"]["scope"]))
        claim_message(engine, state, owner_message_id)
        state["standing_policy"] = record
        return ({}, "Your limited standing policy is recorded. Each exact plan still needs two assistant review passes, fresh checks and all selected "
                    "checkpoints. It never covers a step that needs your own reply or your own action.")
    return _decision(engine, session_id, "policy_recorded", mutate, expected_revision)


def policy_covers(state, action, payload):
    """True when the session's standing policy covers ``action`` with its bound ``payload`` (engine_decisions.policy_covers:
    pure; a None payload is never covered). In-session authorization uses it, and a scheduled run too."""
    return engine_decisions.policy_covers(state, action, payload)


def action_authorization(state, action, payload=None):
    """The owner authority for ``action``, after the conditional-decision check on the bound ``payload`` (a None payload fails
    it where it applies): the approval of the exact plan, which also ends at the actions it leaves out, or with no approval the
    standing policy when policy_covers holds."""
    engine_decisions.require_conditional(state, action, payload)
    approval = state["approval"]
    if approval:
        if action["action_id"] not in approval["action_ids"] or approval["plan_sha256"] != state["plan"]["sha256"]:
            raise WorkflowRefusal("Your approval leaves this action out, so it does not run", code="approval-left-out")
        return {"kind": "exact_plan", "message_id": approval["message_id"], "plan_sha256": state["plan"]["sha256"], "action_id": action["action_id"]}
    policy = state["standing_policy"]
    if policy_covers(state, action, payload):
        return {"kind": "standing_policy", "message_id": policy["message_id"], "plan_sha256": state["plan"]["sha256"], "action_id": action["action_id"]}
    raise WorkflowRefusal("This exact action lacks current owner authority; control style alone never authorizes a change")


def record_conditional_decision(engine, session_id, *, action_id, decision, names, owner_quote, owner_message_id, owner_id=None,
                                source="current_owner_chat", expected_revision=None):
    """The owner's own decision for one flagged action (run its install scripts, or change its runtime line), bound to the
    action id, its payload hash and the exact sorted name@version list the payload names ([] for a runtime line change)."""
    record_identifier(action_id)
    if not isinstance(decision, str) or decision not in pc_records.CONDITIONAL_DECISIONS or not engine_decisions.valid_names(decision, names):
        raise WorkflowRefusal("Choose one conditional decision with its exact name@version list (none for a runtime line change)",
                              code="conditional-decision")
    def mutate(state):
        require_writable(state)
        action = next((a for a in state["plan"]["document"]["actions"] if a["action_id"] == action_id), None) if state["plan"] else None
        if action is None or decision not in pc_records.ADAPTERS[action["adapter_id"]]["conditional_decisions"]:
            raise WorkflowRefusal("This decision applies only to an action of the current plan that can need it", code="conditional-decision")
        if (engine_decisions.needed_decisions(action_binding(engine, state, action)) or {}).get(decision) != names:
            raise WorkflowRefusal("This decision must name exactly what this action's reviewed payload asks for", code="conditional-decision")
        if (any(row["action_id"] == action_id and row["decision"] == decision for row in state["conditional_decisions"])
                or len(state["conditional_decisions"]) >= engine_decisions.MAX_CONDITIONAL_DECISIONS):
            raise WorkflowRefusal("This decision is already recorded, or the session holds all the decisions it can", code="conditional-decision")
        record = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        claim_message(engine, state, owner_message_id)
        row = {"action_id": action_id, "payload_sha256": action["adapter_payload_sha256"], "decision": decision, "names": list(names),
               "message_id": owner_message_id, "recorded_utc": record["recorded_utc"]}
        state["conditional_decisions"].append(row)
        return row, "Your decision is recorded for this one action and its exact reviewed payload. A standing policy or a schedule never uses it."
    return _decision(engine, session_id, "conditional_decision_recorded", mutate, expected_revision)


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


def plan_depends_on(engine, state):
    """depends_on of each plan action that has not run, read from its hash-bound payload: only update and repair payloads carry
    one, and a missing entry means every earlier action (remaining_actions)."""
    consumed = {op["action_id"] for op in state["operations"].values()}
    return {action["action_id"]: _depends(_evidence_value(engine, state, state["evidence"][action["adapter_payload_evidence_id"]]))
            for action in state["plan"]["document"]["actions"]
            if action["action_id"] not in consumed and pc_records.ADAPTERS[action["adapter_id"]]["family"] in engine_decisions.UPDATE_FAMILIES}


def _can_start(engine, state, action):
    """False for an action whose reviewed payload or inventory is past the evidence limit: it never starts and ends as not run,
    because a restart wait has no limit and a batch can outlast its evidence."""
    try:
        return bool(engine.evidence_rows(state, [action["adapter_payload_evidence_id"], action["target_inventory_evidence_id"]]))
    except WorkflowRefusal as error:
        if error.code == "stale-evidence":
            return False
        raise


def next_action_checkpoint(state, depends_on=None):
    """The before_action checkpoint of the first remaining action (remaining_actions); ``depends_on`` is the map
    plan_depends_on returns, and None keeps strict plan order."""
    if not state["plan"] or state["stage"] != "apply":
        return
    remaining = remaining_actions([a["action_id"] for a in state["plan"]["document"]["actions"]], depends_on or {}, approved_ids(state), state["operations"])
    if remaining:
        add_checkpoint(state, "before_action", remaining[0])


def resolve(engine, session_id, *, pending_id=None, evidence_ids=None, choice=None, owner_quote=None, owner_message_id=None, owner_id=None,
            source="current_owner_chat", expected_revision=None):
    if choice is None and not evidence_ids:
        state = engine.read_session(session_id)
        items = pending_items(state)
        if pending_id:
            items = [p for p in items if p["pending_id"] == pending_id]
            if not items:
                raise WorkflowRefusal("No unresolved item has that identifier")
        choices = ["keep_stopped"] if state["status"] == "stopped" else ["continue", "revise_plan", "keep_held"]
        return response(state, "resolution_needed", engine_text.resolve_text(state, items), {"pending": items, "choices": choices})
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
            item["owner_instruction"] = owner_record(state, owner_quote, owner_message_id, owner_id, source)
            claim_message(engine, state, owner_message_id)
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
                    next_action_checkpoint(state, plan_depends_on(engine, state) if state["plan"] else None)
            elif choice in {"revise_plan", "keep_stopped"} and owner_quote and owner_message_id:
                if restart_state(operation) == "waiting":
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
                item["owner_instruction"] = owner_record(state, owner_quote, owner_message_id, owner_id, source)
                claim_message(engine, state, owner_message_id)
                item["resolved"] = True
                operation["resolution"] = {"kind": "effects_accounted" if was_stopped else "replan_required", "evidence_ids": list(evidence_ids),
                                           "recorded_utc": pc_records.utc_now(), "owner_message_id": owner_message_id}
                if not was_stopped:
                    state["plan"] = None
                    engine_decisions.clear_plan_decisions(state)
                    state["stage"] = "plan"
                state["status"] = "stopped" if was_stopped else "held"
            elif choice in {"keep_held", None}:
                state["status"] = "stopped" if was_stopped else "held"
            else:
                raise WorkflowRefusal("An unsuccessful action stays held; the owner may request a separately reviewed replacement plan")
        else:
            raise WorkflowRefusal("This pending item has no general-purpose resolution")
        return {"pending": item}, "Recorded. No step was repeated."
    if owner_message_id is None:
        return engine.change(session_id, "resolved", mutate, expected_revision)
    return _decision(engine, session_id, "resolved", mutate, expected_revision)


def advance_stage(engine, session_id, *, evidence_ids, expected_revision=None):
    def mutate(state):
        if state["status"] != "active" or pending_items(state):
            raise WorkflowRefusal("Stage advancement waits for an active session and resolved checkpoints")
        engine.require_schedule_activation(state)
        stage = state["stage"]
        rows = engine.evidence_rows(state, evidence_ids, allow_empty=stage in {"plan", "apply"})
        finished = {}
        if stage in STAGE_REQUIREMENTS:
            kind, flags = STAGE_REQUIREMENTS[stage]
            matching = [row for row in rows if row["kind"] == kind and all(row["facts"].get(flag) is True for flag in flags)]
            if not matching:
                raise WorkflowRefusal("This stage needs owned evidence establishing its actual required checks")
            if stage == "scope" and (not state["scope_authorization"] or not _scope_selected(state["settings"]["scope"])):
                raise WorkflowRefusal("An actual current-owner scope decision is required before assessment")
            if stage == "inventory" and not any(type(row["facts"].get("item_count")) is int and row["facts"]["item_count"] >= 0 for row in matching):
                raise WorkflowRefusal("Inventory must record an explicit assessed item count")
        elif stage == "plan":
            require_reviews(engine, state)
            approved = set(approved_ids(state))
            for action in state["plan"]["document"]["actions"]:
                if action["action_id"] in approved:
                    action_authorization(state, action, action_binding(engine, state, action))
        elif stage in {"apply", "verify"}:
            if not state["plan"]:
                raise WorkflowRefusal("No current plan can be verified")
            ran = {op["action_id"]: op for op in state["operations"].values() if op["plan_sha256"] == state["plan"]["sha256"]}
            succeeded = {action_id for action_id, op in ran.items() if op["outcome"] == "succeeded"}
            if stage == "apply" and (not ran or any(op["outcome"] != "succeeded" and (op["resolution"] or {}).get("kind") != "verified_failure"
                                                    for op in ran.values())
                                     or remaining_actions([a["action_id"] for a in state["plan"]["document"]["actions"]], plan_depends_on(engine, state),
                                                          [a["action_id"] for a in state["plan"]["document"]["actions"] if a["action_id"] in approved_ids(state)
                                                           and _can_start(engine, state, a)], state["operations"])):
                raise WorkflowRefusal("Every approved action that can still run needs its own actual receipt, and every action run must have succeeded or "
                                      "have a checked failure, before verification")
            if stage == "verify":
                latest = max(op["finished_utc"] for op in ran.values())
                verified = [row for row in rows if row["kind"] == "verification" and row["facts"].get("verification_passed") is True
                            and row["facts"].get("plan_sha256") == state["plan"]["sha256"] and set(row["facts"].get("checked_action_ids", [])) == succeeded
                            and utc_time(row["observed_utc"]) >= utc_time(latest)]
                if not verified:
                    raise WorkflowRefusal("Actual behavior verification of every action that succeeded is required after its outcome")
                # The finish record lists failed, not-run and left-out actions apart from the ones that succeeded.
                approved = approved_ids(state)
                finished = {"succeeded": sorted(succeeded), "failed": sorted(set(ran) - succeeded),
                            "not_run": [action_id for action_id in approved if action_id not in ran],
                            "excluded": [a["action_id"] for a in state["plan"]["document"]["actions"] if a["action_id"] not in approved]}
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
            next_action_checkpoint(state, plan_depends_on(engine, state))
        return ({"stage": state["stage"], **finished}, "The evidence supports the next step: " + STAGE_LABELS[state["stage"]].lower() + ". "
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
        summary = typed_record(_evidence_value(engine, state, summary_row), ASSESSMENT_SUMMARY)
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
        assessed = engine.evidence_rows(state, summary["assessed_evidence_ids"], kinds={kind for kind, _ in STAGE_REQUIREMENTS.values()},
                                        after=authorization["recorded_utc"])
        for stage in JOBS[state["job"]]["stages"][:JOBS[state["job"]]["stages"].index("plan")]:
            kind, flags = STAGE_REQUIREMENTS[stage]
            if not any(row["kind"] == kind and all(row["facts"].get(flag) is True for flag in flags) for row in assessed):
                raise WorkflowRefusal("The summary must cover the actual current evidence for every agreed assessment step")
        rows = engine.evidence_rows(state, verification_evidence_ids, kinds={"verification"}, after=summary_row["registered_utc"], seconds=900)
        for row in rows:
            verification = typed_record(_evidence_value(engine, state, row), ASSESSMENT_VERIFICATION)
            if (any(verification[key] != summary[key] for key in ("job", "mode", "scope_sha256", "settings_revision", "assessed_evidence_ids"))
                    or verification["summary_evidence_id"] != summary_evidence_id or verification["summary_sha256"] != summary_row["sha256"]
                    or verification["coverage_checked"] is not True or verification["limitations_checked"] is not True
                    or verification["observed_utc"] != row["observed_utc"]):
                raise WorkflowRefusal("Assessment verification must check the exact current summary, evidence coverage and recorded limitations")
            fresh(verification["observed_utc"], after=summary_row["registered_utc"], seconds=900)
        record = {"summary_evidence_id": summary_evidence_id, "summary_sha256": summary_row["sha256"],
                  "verification_evidence_ids": list(verification_evidence_ids),
                  "owner_instruction": owner_record(state, owner_quote, owner_message_id, owner_id, source)}
        claim_message(engine, state, owner_message_id)
        key = "assessment-finish-" + digest({"summary": summary_row["sha256"], "settings": state["settings_revision"], "message": owner_message_id})[:24]
        state["pending"][key] = {"pending_id": key, "kind": "assessment_finish", "resolved": True, "record": record}
        state["stage"] = "complete"
        add_checkpoint(state, "finish")
        if not pending_items(state):
            state["status"] = "completed"
        return (record, "The assessment and its findings are recorded, including what remains uncertain. This session recorded no maintenance action. "
                + ("Review the selected finish checkpoint before closing." if state["status"] != "completed"
                   else "The assessment session is complete; any computer change needs a separate reviewed plan."))
    return _decision(engine, session_id, "assessment_completed", mutate, expected_revision)
