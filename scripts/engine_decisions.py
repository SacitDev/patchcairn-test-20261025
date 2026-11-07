"""Pure decision rules shared by the plan and operation modules: which batch actions remain, the typed reply, the shape of
plans and of the typed-reply and conditional-decision state, plan composition and dependencies, subset approval, consumed
actions, conditional decisions, the follow-up removal plan and the standing-policy check. Nothing here reads or writes a
journal: each rule reads only the data it is given, so it runs without an engine. It imports only engine_journal,
engine_text and pc_records.
"""
from __future__ import annotations

from datetime import timedelta
import math
import re

from engine_journal import SHA, WorkflowRefusal, bounded_text, checked, exact_fields, ids, record_identifier, restart_state, utc_time
import pc_records
from pc_records import ADAPTERS, TYPED_ACKNOWLEDGMENTS, digest

# The label on owner-decision and review records: the coordinator wrote them from the owner's message or from an
# assistant review pass. A record does not show who took the decision.
ATTESTATION = "coordinator-attested"
REVIEW = "patchcairn.review"
REVIEW_FIELDS = frozenset({"plan_sha256", "role", "verdict", "reviewer_id", "attestation"})
ROLES = frozenset({"compatibility_data", "evidence_security"})
VERDICTS = frozenset({"approved", "hold"})
WARNING_FIELDS = frozenset({"plan_sha256", "kind", "action_ids", "number", "bytes", "revision", "recorded_utc"})
REPLY_FIELDS = frozenset({"type", "action_ids", "number", "bytes", "warning_revision"})
CONDITIONAL_FIELDS = frozenset({"action_id", "payload_sha256", "decision", "names", "message_id", "recorded_utc"})
MAX_CONDITIONAL_DECISIONS = 100
# The conditional decision each route flag calls for; install-script names are exact name@version texts.
CONDITIONAL_FLAGS = {"install_scripts": "run_install_scripts", "runtime_line_change": "runtime_line_change"}
NAME_AT_VERSION = re.compile(r"(?:@[a-z0-9][a-z0-9._-]{0,99}/)?[A-Za-z0-9][A-Za-z0-9._-]{0,99}@[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z")
# A standing policy never covers a payload with one of these flags, and lasts at most POLICY_DAYS.
POLICY_REFUSED_FLAGS = frozenset({"adds_packages", "downgrades", "high_risk"})
POLICY_DAYS = 7
POLICY_KINDS = frozenset(kind for facts in ADAPTERS.values() if facts["policy_coverable"] for kind in facts["kinds"])
BINDING_KEYS = ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")
TYPED_KINDS = frozenset(kind for facts in ADAPTERS.values() if TYPED_ACKNOWLEDGMENTS & set(facts["acknowledgments"]) for kind in facts["kinds"])
PLAN_FIELDS = frozenset({"plan_id", "summary", "evidence_ids", "actions"})
ACTION_FIELDS = frozenset({"action_id", "kind", "target", "benefit", "risk", "reversibility", "verification", "mutating", "requires_os_consent",
                           "requires_recovery", "recovery_evidence_ids", "estimate_evidence_id", "adapter_id", "adapter_payload_evidence_id",
                           "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_evidence_id", "target_inventory_sha256", "rendered_command"})
# A shown command is display text only, never run or parsed; only the update and repair families carry it.
SHOWN_COMMAND_MAX = 500
UPDATE_FAMILIES = frozenset({"update", "repair"})
# Cloud services a backup receipt names as syncing the sources (shown in the follow-up removal plan).
SERVICE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9 ]{0,39}\Z")
# Separators a typed reply may differ in: runs of spaces, tabs and commas.
_REPLY_SEPARATORS = re.compile(r"[ \t,]+")


def remaining_actions(action_ids, depends_on, approved_ids, operations):
    """The action ids still to run, in plan order; only the first of them may start.

    action_ids is the plan's ids in plan order; depends_on maps an id to the earlier ids it needs, and a missing or None
    entry means every earlier action; approved_ids are the ids the person approved; operations are the session's
    operation records. An action whose operation succeeded is met for its dependents, even when a later approval leaves
    it out. Any other id remains when it is approved, has no operation yet, and needs only earlier ids of the plan, each
    met in the same way. A needs value that is not a list or tuple, or that names a later, unknown or the same id, blocks
    the action. Whether anything may start at all (an unknown outcome, an unresolved failure, a pending restart) is
    decided elsewhere."""
    approved = set(approved_ids)
    consumed = {operation["action_id"] for operation in operations.values()}
    unsuccessful = {operation["action_id"] for operation in operations.values() if operation["outcome"] != "succeeded"}
    blocked = set()
    remaining = []
    for index, action_id in enumerate(action_ids):
        if action_id in consumed and action_id not in unsuccessful:
            continue
        earlier = set(action_ids[:index])
        needs = depends_on.get(action_id)
        needs = action_ids[:index] if needs is None else needs
        if (action_id not in approved or action_id in unsuccessful or not isinstance(needs, (list, tuple))
                or any(not isinstance(need, str) or need not in earlier or need in blocked for need in needs)):
            blocked.add(action_id)
        elif action_id not in consumed:
            remaining.append(action_id)
    return tuple(remaining)


def _reply_text(text):
    """``text`` as typed replies are compared, or None when it has a character other than printable ASCII and tab. A host
    may end the reply with a line break, so trailing carriage returns and line feeds are dropped first."""
    text = text.rstrip("\r\n").strip(" \t")
    text = text[:-1] if text.endswith(".") else text
    if not text.isascii() or any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in text):
        return None
    return " ".join(part for part in _REPLY_SEPARATORS.split(text.lower()) if part)


def reply_matches(quote, phrase):
    """True when the owner's typed ``quote`` is ``phrase``: one final full stop, a final line break, ASCII letter case and
    runs of spaces, tabs and commas do not count; every other character must be the same, and a non-ASCII or control
    character never matches."""
    quoted = _reply_text(quote) if isinstance(quote, str) else None
    return quoted is not None and quoted == _reply_text(phrase)


def _member(value, allowed):
    return isinstance(value, str) and value in allowed


def _sha(value):
    return isinstance(value, str) and bool(SHA.fullmatch(value))


def typed(action):
    """True when ``action``'s adapter needs the owner's typed reply (a permanent deletion or a firmware update)."""
    return bool(TYPED_ACKNOWLEDGMENTS & set(ADAPTERS[action["adapter_id"]]["acknowledgments"]))


def json_shape(value, depth=0):
    """Refuse a value that is not bounded JSON data or that carries an executable or self-authorizing field."""
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
    if isinstance(value, list) and len(value) <= pc_records.MAX_BACKUP_ENTRIES:
        for item in value:
            json_shape(item, depth + 1)
        return
    if isinstance(value, dict) and len(value) <= 100:
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in {"command", "commands", "execute", "eval", "approved", "authorization"}:
                raise WorkflowRefusal("Executable or self-authorizing evidence fields are not accepted")
            json_shape(item, depth + 1)
        return
    raise WorkflowRefusal("Evidence must be bounded JSON data")


def valid_names(decision, names):
    """True when ``names`` are what a conditional ``decision`` binds: the sorted, unique, exact name@version texts of the
    install scripts, or [] for a runtime line change."""
    if decision == "runtime_line_change":
        return names == []
    return (isinstance(names, list) and 0 < len(names) <= 500 and all(isinstance(name, str) and NAME_AT_VERSION.match(name) for name in names)
            and names == sorted(set(names)))


def typed_state(state, max_used):
    """Check the typed-reply keys: the used message ids (at most ``max_used``), the warning (bound to the current plan), the
    approval's reply, and the conditional decisions (each bound to an action of the current plan, at most one per action and
    decision)."""
    used, warning, decisions = state["used_message_ids"], state["irreversible_warning"], state["conditional_decisions"]
    reply = state["approval"].get("irreversible", 0) if state["approval"] else None
    if (not isinstance(used, list) or len(used) > max_used or len(set(map(str, used))) != len(used) or reply == 0
            or not isinstance(decisions, list) or len(decisions) > MAX_CONDITIONAL_DECISIONS):
        raise WorkflowRefusal("Invalid typed-reply state")
    for message_id in used:
        record_identifier(message_id, "used message identifier")
    for record, fields, revision in ((warning, WARNING_FIELDS, "revision"), (reply, REPLY_FIELDS, "warning_revision")):
        if record is not None:
            exact_fields(record, fields, fields)
            ids(record["action_ids"], "typed-reply actions", allow_empty=False)
            if (type(record["number"]) is not int or record["number"] < 1 or type(record[revision]) is not int
                    or record["bytes"] is not None and (type(record["bytes"]) is not int or record["bytes"] < 0)):
                raise WorkflowRefusal("Invalid typed-reply record")
    if warning is not None and (not state["plan"] or warning["plan_sha256"] != state["plan"]["sha256"] or not _member(warning["kind"], TYPED_KINDS)
                                or not 0 < warning["revision"] <= state["revision"] or not utc_time(warning["recorded_utc"])):
        raise WorkflowRefusal("The irreversible-change warning is not bound to the current exact plan")
    if reply is not None and not _member(reply["type"], TYPED_ACKNOWLEDGMENTS):
        raise WorkflowRefusal("Invalid typed reply")
    plan_ids = {action["action_id"] for action in state["plan"]["document"]["actions"]} if state["plan"] else set()
    seen = set()
    for row in decisions:
        exact_fields(row, CONDITIONAL_FIELDS, CONDITIONAL_FIELDS)
        if (not _member(row["decision"], pc_records.CONDITIONAL_DECISIONS) or not _member(row["action_id"], plan_ids) or not _sha(row["payload_sha256"])
                or not valid_names(row["decision"], row["names"]) or (row["action_id"], row["decision"]) in seen):
            raise WorkflowRefusal("Invalid conditional decision")
        seen.add((row["action_id"], row["decision"]))
        record_identifier(row["message_id"], "conditional decision message identifier")
        utc_time(row["recorded_utc"])


def clear_plan_decisions(state):
    """Clear every decision bound to the current plan: its reviews, approval, acknowledgment, warning and conditional
    decisions (a new plan or a re-plan; invalidate also clears the scope, the policy and the schedule)."""
    state.update(reviews=[], approval=None, irreversible_ack=None, irreversible_warning=None, conditional_decisions=[])


def read_review(record):
    """The reader of patchcairn.review records: one assistant review pass of an exact plan, by role, verdict and reviewer,
    labelled coordinator-attested."""
    checked(pc_records.require_schema, record, REVIEW)
    exact_fields(record, REVIEW_FIELDS | {"schema", "schema_version"}, REVIEW_FIELDS | {"schema", "schema_version"})
    if (not _sha(record["plan_sha256"]) or not _member(record["role"], ROLES) or not _member(record["verdict"], VERDICTS)
            or record["attestation"] != ATTESTATION):
        raise WorkflowRefusal("A review record names one exact plan, a supported role and verdict, and the coordinator-attested label",
                              code="review-record")
    record_identifier(record["reviewer_id"], "reviewer identifier")
    return record


def validate_plan_document(state, plan):
    """The plan document: bounded fixed data, one registered adapter per action whose facts allow its kind, mode and OS-consent
    flag, exact payload, plan and inventory hashes, recovery where the action needs it, a shown command only for the update
    and repair families, and the composition rule."""
    exact_fields(plan, PLAN_FIELDS, PLAN_FIELDS)
    record_identifier(plan["plan_id"])
    bounded_text(plan["summary"], "plan explanation")
    ids(plan["evidence_ids"], allow_empty=False)
    if not isinstance(plan["actions"], list) or not 0 < len(plan["actions"]) <= 100:
        raise WorkflowRefusal("A plan needs a bounded concrete action list")
    seen = set()
    for action in plan["actions"]:
        exact_fields(action, ACTION_FIELDS, ACTION_FIELDS - {"estimate_evidence_id", "rendered_command"})
        if record_identifier(action["action_id"]) in seen:
            raise WorkflowRefusal("Action identifiers must be unique")
        seen.add(action["action_id"])
        for field in ("target", "benefit", "risk", "reversibility", "verification"):
            bounded_text(action[field], "action " + field, 2000)
        if any(type(action[key]) is not bool for key in ("mutating", "requires_os_consent", "requires_recovery")):
            raise WorkflowRefusal("Action safety flags must be explicit booleans")
        if action["kind"] != "assessment" and not action["mutating"]:
            raise WorkflowRefusal("Change kinds cannot be disguised as read-only actions")
        if not isinstance(action["adapter_id"], str):
            raise WorkflowRefusal("Adapter identifier must name a fixed supported recipe")
        facts = checked(pc_records.adapter_facts, action["adapter_id"], requires_os_consent=action["requires_os_consent"])
        if action["kind"] not in facts["kinds"] or action["adapter_id"] == pc_records.ADAPTER_FIXTURE_ASSESSMENT and state["mode"] != "fixture":
            raise WorkflowRefusal("This action has no fixed supported adapter for this kind and mode")
        if facts["backup_receipt"] == "required" and not action["requires_recovery"]:
            raise WorkflowRefusal("This adapter consumes a verified backup receipt; bind its recovery evidence")
        for field in ("adapter_payload_evidence_id", "target_inventory_evidence_id"):
            record_identifier(action[field])
        if not all(_sha(action[field]) for field in ("adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")):
            raise WorkflowRefusal("Exact adapter payload, lower-level plan and target inventory hashes are required")
        # A restore and a purge always bind recovery. A repair binds what its adapter's facts call for (no backup receipt), and a
        # system repair has its own acknowledgment at begin; no recovery evidence is made up for either.
        if action["kind"] in {"backup_restore", "permanent_purge"} and not action["requires_recovery"]:
            raise WorkflowRefusal("This action needs verified recovery evidence or an explicit supported recovery design")
        ids(action["recovery_evidence_ids"])
        if action["requires_recovery"] and not action["recovery_evidence_ids"]:
            raise WorkflowRefusal("Required recovery has not been provided")
        if "estimate_evidence_id" in action:
            record_identifier(action["estimate_evidence_id"])
        if "rendered_command" in action:
            if facts["family"] not in UPDATE_FAMILIES:
                raise WorkflowRefusal("Only an update or a repair shows a command", code="rendered-command")
            checked(pc_records.bounded_text, action["rendered_command"], "shown command", SHOWN_COMMAND_MAX)
    check_composition(plan["actions"])


def check_composition(actions):
    """Rule 1: an action that needs the typed reply shares its plan only with actions of the same adapter, and a firmware plan
    holds exactly one action."""
    warned = [action for action in actions if typed(action)]
    if warned and (len({action["adapter_id"] for action in actions}) != 1
                   or "firmware_risk" in ADAPTERS[warned[0]["adapter_id"]]["acknowledgments"] and len(actions) != 1):
        raise WorkflowRefusal("A permanent deletion shares its plan only with deletions of the same kind, and a firmware update is a plan of its "
                              "own for one device", code="plan-composition")


def needs_of(action_ids, depends_on, index):
    """The ids the action at ``index`` needs: its depends_on, or every earlier action when that is missing or None."""
    needs = depends_on.get(action_ids[index])
    return list(action_ids[:index]) if needs is None else needs


def check_depends_on(action_ids, depends_on):
    """Rule 5: each depends_on given (from the bound payload) is a list of distinct ids, each naming an earlier action of the
    same plan, so no id is unknown and there is no cycle."""
    for index, action_id in enumerate(action_ids):
        needs = depends_on.get(action_id)
        if needs is not None and (not isinstance(needs, list) or any(not isinstance(need, str) or need not in action_ids[:index] for need in needs)
                                  or len(set(needs)) != len(needs)):
            raise WorkflowRefusal("An action may depend only on earlier actions of the same plan, each named once", code="plan-depends-on")


def check_approval(action_ids, depends_on, approved_ids, whole, operations):
    """Rule 4: a plan that needs the typed reply (``whole``) is approved whole. Otherwise each approved action that has not run
    comes with every action it needs, unless that one already succeeded, so leaving an action out leaves out its dependents."""
    approved = set(approved_ids)
    if whole and approved != set(action_ids):
        raise WorkflowRefusal("A permanent deletion or a firmware update is approved as a whole plan", code="approval-whole")
    consumed = {operation["action_id"] for operation in operations.values()}
    met = approved | {operation["action_id"] for operation in operations.values() if operation["outcome"] == "succeeded"}
    for index, action_id in enumerate(action_ids):
        if action_id in approved and action_id not in consumed and set(needs_of(action_ids, depends_on, index)) - met:
            raise WorkflowRefusal("An action is approved only together with every action it depends on", code="approval-dependencies")


def approved_ids(state):
    """The ids the owner's approval names, or every plan action when there is no approval (a standing policy must then cover
    each)."""
    return list(state["approval"]["action_ids"]) if state["approval"] else [action["action_id"] for action in state["plan"]["document"]["actions"]]


def require_consumed(state, action, operation_id):
    """Refuse unless ``operation_id`` is ``action``'s own operation under the current plan and settings, and that operation can
    no longer launch: it is closed, or it carries a restart. An open operation with neither may not have started yet, so it
    stays a new launch and keeps the freshness limit."""
    record_identifier(operation_id, "operation identifier")
    operation, plan = state["operations"].get(operation_id), state["plan"]
    if (not operation or not plan or operation["plan_sha256"] != plan["sha256"] or action not in plan["document"]["actions"]
            or operation["action_id"] != action["action_id"] or operation["adapter_id"] != action["adapter_id"]
            or operation["settings_revision"] != state["settings_revision"]
            or operation["outcome"] is None and restart_state(operation) == "none"):
        raise WorkflowRefusal("Only a step that has already run reads its reviewed plan without the time limit; a new start needs fresh "
                              "evidence", code="consumed-binding")


def _flags(payload):
    flags = payload.get("flags", []) if isinstance(payload, dict) else None
    return set(flags) if isinstance(flags, list) and all(isinstance(flag, str) for flag in flags) else None


def needed_decisions(payload):
    """{decision: names} that a bound payload calls for: each flag's decision with the names its "conditional" field gives.
    None when the flags and that field do not agree or the names are not exact (fail closed)."""
    flags, conditional = _flags(payload), payload.get("conditional", {}) if isinstance(payload, dict) else None
    if flags is None or not isinstance(conditional, dict) or {CONDITIONAL_FLAGS[flag] for flag in flags & set(CONDITIONAL_FLAGS)} != set(conditional):
        return None
    return dict(conditional) if all(valid_names(decision, names) for decision, names in conditional.items()) else None


def require_conditional(state, action, payload):
    """The conditional-decision check: when the payload calls for a decision (install scripts, a runtime line change), the
    session holds a matching record for this action id, payload hash, decision and exact names, and no schedule starts the
    session. A None payload fails for an adapter that has conditional decisions."""
    allowed = ADAPTERS[action["adapter_id"]]["conditional_decisions"]
    needed = needed_decisions(payload) if payload is not None else (None if allowed else {})
    recorded = {(row["action_id"], row["payload_sha256"], row["decision"], tuple(row["names"])) for row in state["conditional_decisions"]}
    if (needed is None or set(needed) - set(allowed) or needed and state["settings"]["timing"] == "scheduled"
            or any((action["action_id"], action["adapter_payload_sha256"], decision, tuple(names)) not in recorded for decision, names in needed.items())):
        raise WorkflowRefusal("This action needs the owner's own decision about its install scripts or runtime line, given in a session timed "
                              "'now'", code="conditional-decision-required")


def reviewed(state):
    """True when two approved assistant review passes, one per role by different reviewers, are bound to the current plan."""
    rows = [row for row in state["reviews"] if row["plan_sha256"] == state["plan"]["sha256"] and row["verdict"] == "approved"
            and row["settings_revision"] == state["settings_revision"]]
    return len(rows) == 2 and {row["role"] for row in rows} == ROLES and len({row["reviewer_id"] for row in rows}) == 2


def policy_covers(state, action, payload):
    """True when the session's standing policy covers ``action`` with its bound ``payload``; pure, it writes nothing. A None
    payload is never covered; nor is an adapter that pc_records does not let a policy cover, a permanent deletion or a
    firmware update, a payload flagged adds_packages, downgrades or high_risk, or one that needs a conditional decision. The
    policy lasts at most seven days, is not expired, has actions left, and matches the scope, the action's kind and target
    and its exact adapter, payload, plan and inventory hashes; two reviews bind this plan; and the session is open, not
    paused, held or stopped, with no open operation. A scheduled run also applies scheduled_policy_coverable itself."""
    policy, plan, facts = state["standing_policy"], state["plan"], ADAPTERS.get(action.get("adapter_id"))
    flags = _flags(payload) if payload is not None else None
    if not policy or not plan or not facts or flags is None or needed_decisions(payload) != {}:
        return False
    now, expiry = utc_time(pc_records.utc_now()), utc_time(policy["expires_utc"])
    return (facts["policy_coverable"] and not facts["irreversible"] and not TYPED_ACKNOWLEDGMENTS & set(facts["acknowledgments"])
            and not flags & POLICY_REFUSED_FLAGS and not action["requires_os_consent"] and action in plan["document"]["actions"]
            and state["settings"]["control"] == "automatic" and state["status"] not in {"paused", "pause_pending", "held", "stopped", "completed"}
            and state["stage"] != "complete" and all(operation["outcome"] is not None for operation in state["operations"].values())
            and policy["settings_revision"] == state["settings_revision"] and policy["scope_sha256"] == digest(state["settings"]["scope"])
            and now < expiry <= utc_time(policy["recorded_utc"]) + timedelta(days=POLICY_DAYS) and policy["used_actions"] < policy["max_actions"]
            and action["kind"] in policy["action_kinds"] and action["target"] in policy["targets"]
            and {key: action[key] for key in BINDING_KEYS} in policy["action_bindings"] and reviewed(state))


def check_policy_request(action_kinds, max_actions, expires_utc, targets, action_bindings):
    """The bounds of a standing policy request: supported ordinary kinds, 1-20 actions, exact targets and hash bindings of
    adapters a policy may cover, and an expiry within the next seven days."""
    if (not isinstance(action_kinds, list) or not action_kinds or any(not _member(kind, POLICY_KINDS) for kind in action_kinds)
            or len(set(action_kinds)) != len(action_kinds) or type(max_actions) is not int or not 1 <= max_actions <= 20):
        raise WorkflowRefusal("Standing policy needs bounded supported ordinary action kinds and 1–20 actions")
    if not isinstance(targets, list) or not targets or len(targets) > 20:
        raise WorkflowRefusal("Standing policy needs exact explicitly selected targets")
    for target in targets:
        bounded_text(target, "policy target", 2000)
    if not isinstance(action_bindings, list) or not action_bindings or len(action_bindings) > 20:
        raise WorkflowRefusal("Standing policy needs exact adapter payload/plan/inventory hash bindings")
    for binding in action_bindings:
        exact_fields(binding, set(BINDING_KEYS), set(BINDING_KEYS))
        facts = ADAPTERS.get(binding["adapter_id"]) if isinstance(binding["adapter_id"], str) else None
        if not facts or not facts["policy_coverable"] or not set(facts["kinds"]) & set(action_kinds) or not all(_sha(binding[key]) for key in BINDING_KEYS[1:]):
            raise WorkflowRefusal("Standing policy binding has unsupported adapter or missing exact hashes")
    now = utc_time(pc_records.utc_now())
    if not now < utc_time(expires_utc) <= now + timedelta(days=POLICY_DAYS):
        raise WorkflowRefusal("Policy expiry must be in the next seven days")


def check_followup(state, document, receipts):
    """The follow-up removal plan: originals are removed only by one plan, registered at the verify stage after every backup
    of the current plan succeeded; each of its actions removes originals and consumes a receipt of one of those backups,
    whose outcome is not partial and which records durability. ``receipts`` are the backup receipts its recovery bindings
    name (None where a binding names none)."""
    plan = state["plan"]
    followed = plan["document"]["actions"] if plan else []
    backups = {action["adapter_plan_sha256"]: action["action_id"] for action in followed if action["adapter_id"] == pc_records.ADAPTER_STORAGE_BACKUP_CREATE}
    succeeded = {operation["action_id"] for operation in state["operations"].values() if plan and operation["plan_sha256"] == plan["sha256"]
                 and operation["outcome"] == "succeeded"}
    if (state["stage"] != "verify" or not backups or not set(backups.values()) <= succeeded
            or any(action["adapter_id"] == pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS for action in followed)
            or any(action["adapter_id"] != pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS for action in document["actions"])):
        raise WorkflowRefusal("Originals are removed only by one follow-up plan of removals, at the verify stage, after every backup of the current "
                              "plan succeeded", code="followup-plan")
    for receipt in receipts:
        if (not isinstance(receipt, dict) or not _member(receipt.get("plan_sha256"), backups) or receipt.get("outcome") != "succeeded"
                or receipt.get("durable") is not True):
            raise WorkflowRefusal("Each removal must use this session's checked backup; a partial backup, or one not confirmed as written to disk, "
                                  "never allows removal", code="followup-receipt")


def followup_notes(receipts, files):
    """(sentences, read-only entries) the follow-up removal plan shows: the same-disk warning unless every receipt proves a
    different disk, the synced services, and each entry's read-only state (every entry must state it)."""
    relations = {receipt.get("disk_relation") for receipt in receipts}
    services = set()
    for receipt in receipts:
        synced = receipt.get("sources_synced")
        if not isinstance(synced, list) or any(not isinstance(name, str) or not SERVICE_NAME.match(name) for name in synced):
            raise WorkflowRefusal("The backup receipt must name the services that sync its sources", code="followup-receipt")
        services.update(synced)
    if any(not isinstance(row, dict) or type(row.get("read_only")) is not bool for row in files):
        raise WorkflowRefusal("The removal plan must show whether each file is read-only", code="followup-read-only")
    notes = [] if relations == {"different"} else [
        "This backup is on the same disk as the originals; if the disk fails, both copies are lost." if "same" in relations else
        "This backup may be on the same disk as the originals; if that disk fails, both copies are lost."]
    if services:
        notes.append("This also removes them from " + " and ".join(sorted(services)) + " on all devices.")
    read_only = [{key: row.get(key) for key in ("root_id", "relative_path")} for row in files if row["read_only"]]
    if read_only:
        notes.append("%d of these files are read-only; the plan removes them too." % len(read_only))
    return notes, read_only
