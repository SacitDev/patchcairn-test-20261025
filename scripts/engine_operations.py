"""One-use operation receipts and their actual outcomes, and pausing, resuming and stopping a session.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

import uuid

from engine_decisions import approved_ids, remaining_actions
from engine_journal import (EVIDENCE_MAX_BYTES, EVIDENCE_MAX_NODES, OUTCOMES, WorkflowRefusal, bounded_text, decode_record, outstanding_effects,
                            record_identifier, require_writable, restart_state, utc_time)
from engine_plans import (acknowledgments, action_authorization, action_binding, add_checkpoint, current_plan, next_action_checkpoint, pending_items,
                          plan_depends_on, require_reviews)
import pc_records
from pc_records import TYPED_ACKNOWLEDGMENTS, digest

# The families whose actions bind a package payload (engine_updates) and whose outcomes are update results.
UPDATE_FAMILIES = frozenset({"update", "repair"})
# The outcomes each update result category may close with; a result that waits for a restart or for the owner closes none.
RESULT_OUTCOMES = {"updated_checked": {"succeeded"}, "did_not_update": {"failed", "partial"}, "needs_check": {"failed", "partial"}}
# The facts resolve reads to account for a failure's actual effects.
RESOLVE_FACTS = ("actual_effects_recorded", "no_active_effects", "recovery_retained")


def _result(facts):
    """The update result recorded in ``facts`` (pc_records.UPDATE_RESULTS), or None."""
    result = facts.get("result")
    return result if isinstance(result, str) and result in pc_records.UPDATE_RESULTS else None


def _typed_reply_covers(state, action):
    """Refuse unless the approval's typed reply covers ``action``: given after the current warning of this exact plan, for
    the warned actions, number and bytes, and of the acknowledgment the action needs."""
    reply, warning = (state["approval"] or {}).get("irreversible") or {}, state["irreversible_warning"] or {}
    if (action["action_id"] not in reply.get("action_ids", ()) or reply.get("type") not in acknowledgments(action)
            or warning.get("plan_sha256") != state["plan"]["sha256"] or reply.get("warning_revision") != warning.get("revision")
            or [reply.get(key) for key in ("action_ids", "number", "bytes")] != [warning.get(key) for key in ("action_ids", "number", "bytes")]):
        raise WorkflowRefusal("This exact action needs the owner's typed reply to its current warning", code="typed-reply-required")


def _hold(outstanding, action):
    """Refuse ``action`` while effects are outstanding anywhere in the registry (outstanding_effects). While each of them
    only waits for its restart, a backup or a read-only assessment may still start, and nothing else."""
    if not outstanding:
        return
    if all(item["restart"] for item in outstanding):
        if action["adapter_id"] == pc_records.ADAPTER_STORAGE_BACKUP_CREATE or pc_records.ADAPTERS[action["adapter_id"]]["family"] == "assessment":
            return
        raise WorkflowRefusal("An earlier update needs a restart, and a check after it, before anything else can change; until then no change can "
                              "start except a backup", code="restart-pending")
    raise WorkflowRefusal("An outstanding mutating operation in this engine registry still needs an actual receipt or effects reconciliation")


def _fired_run_refused(action, payload, authorization):
    """True for what a fired scheduled run never starts: a high_risk payload, or a standing policy's use of an adapter that
    pc_records does not let a schedule act on."""
    flags = payload.get("flags") if isinstance(payload, dict) else None
    return (isinstance(flags, list) and "high_risk" in flags
            or authorization["kind"] == "standing_policy" and not pc_records.ADAPTERS[action["adapter_id"]]["scheduled_policy_coverable"])


def _authority_holds(state, operation):
    """True while owner authority for ``operation`` still stands. A current approval decides first, however the operation began:
    it must be of the same plan and name the action. With no approval, only the standing policy that began the operation (the
    same owner message) admits it, while the plan is the operation's and the policy unexpired. A new begin's checks
    (policy_covers) are not repeated: this operation has already counted against the policy."""
    approval, policy, authorization, plan = state["approval"], state["standing_policy"], operation["authorization"], state["plan"]
    if approval:
        return approval["plan_sha256"] == operation["plan_sha256"] and operation["action_id"] in approval["action_ids"]
    return (authorization["kind"] == "standing_policy" and bool(policy) and policy["message_id"] == authorization["message_id"]
            and bool(plan) and plan["sha256"] == operation["plan_sha256"] and utc_time(pc_records.utc_now()) < utc_time(policy["expires_utc"]))


def begin_operation(engine, session_id, *, action_id, plan_sha256, precondition_evidence_ids, owner_consent_evidence_id=None, expected_revision=None):
    """The one-use receipt for the first remaining action of the exact approved plan. owner_consent_evidence_id refuses
    every value: operating-system consent is recorded after the run, from what the run observed."""
    record_identifier(action_id)
    if owner_consent_evidence_id is not None:
        raise WorkflowRefusal("Operating-system consent is recorded after the run, from what it observed; no consent record is taken before it")
    def mutate(state):
        if state["status"] != "active" or state["stage"] != "apply" or pending_items(state):
            raise WorkflowRefusal("New actions wait until the apply stage is active and every hold/checkpoint is resolved")
        activation = engine.require_schedule_activation(state)
        document = current_plan(state, plan_sha256)
        actions = [a for a in document["actions"] if a["action_id"] == action_id]
        if not actions:
            raise WorkflowRefusal("Action is absent from the exact plan")
        action = actions[0]
        _hold(outstanding_effects(engine), action)
        require_reviews(engine, state)
        engine.evidence_rows(state, document["evidence_ids"])
        payload = action_binding(engine, state, action)
        # Each update or repair payload names the earlier actions it needs (depends_on); any other action needs every earlier one.
        consumed = {op["action_id"] for op in state["operations"].values()}
        depends_on = {item["action_id"]: (payload if item is action else action_binding(engine, state, item)).get("depends_on")
                      for item in document["actions"]
                      if item["action_id"] not in consumed and pc_records.ADAPTERS[item["adapter_id"]]["family"] in UPDATE_FAMILIES}
        authorization = action_authorization(state, action, payload=payload)
        if remaining_actions([item["action_id"] for item in document["actions"]], depends_on, approved_ids(state), state["operations"])[:1] != (action_id,):
            raise WorkflowRefusal("Actions follow the exact reviewed order and their individual checkpoints")
        if any(op["action_id"] == action_id or op["outcome"] is None for op in state["operations"].values()):
            raise WorkflowRefusal("An action is already active or consumed; no automatic retry")
        if activation is not None and _fired_run_refused(action, payload, authorization):
            raise WorkflowRefusal("A scheduled run never starts this step; start it with the owner in a session timed 'now'", code="fired-run-refused")
        for acknowledgment in acknowledgments(action):
            if acknowledgment in TYPED_ACKNOWLEDGMENTS:
                if activation is not None:
                    raise WorkflowRefusal("A permanent deletion or a firmware update is never started by a schedule; start it with the owner in a "
                                          "session timed 'now'", code="typed-reply-scheduled")
                _typed_reply_covers(state, action)
                continue
            ack = state["irreversible_ack"]
            if (not ack or ack["type"] != acknowledgment or ack["plan_sha256"] != plan_sha256 or action_id not in ack["action_ids"]
                    or ack["settings_revision"] != state["settings_revision"] or ack["scope_sha256"] != digest(state["settings"]["scope"])):
                raise WorkflowRefusal("This step still needs your own separate go-ahead. PatchCairn: options shows the question.")
        after = max((state["plan"]["registered_utc"], activation["activated_utc"]), key=utc_time) if activation else state["plan"]["registered_utc"]
        rows = engine.evidence_rows(state, precondition_evidence_ids, kinds={"precondition"}, after=after, seconds=900)
        required = {"identity_matches", "scope_matches", "content_matches", "compatibility_checked", "provenance_checked"}
        if action["requires_recovery"]:
            required.add("recovery_verified")
            engine.verify_recovery(state, action["recovery_evidence_ids"], action=action)
        for row in rows:
            facts = row["facts"]
            binding = {key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")}
            if (facts.get("plan_sha256") != plan_sha256 or facts.get("action_id") != action_id or any(facts.get(key) != value for key, value in binding.items())
                    or any(facts.get(flag) is not True for flag in required)):
                raise WorkflowRefusal("Fresh preconditions must confirm this exact action's identity, scope, content, compatibility, provenance and recovery")
        operation_id = "operation-" + uuid.uuid4().hex
        operation = {"operation_id": operation_id, "action_id": action_id, "plan_sha256": plan_sha256, "settings_revision": state["settings_revision"],
                     "started_utc": pc_records.utc_now(), "finished_utc": None, "outcome": None, "evidence_ids": [],
                     "summary": "Still running, or waiting for its result", "authorization": authorization, "pause_requested": False, "resolution": None,
                     "mutating": action["mutating"], "adapter_id": action["adapter_id"]}
        state["operations"][operation_id] = operation
        if authorization["kind"] == "standing_policy":
            state["standing_policy"]["used_actions"] += 1
        return (operation,
                "The one-use operation receipt is recorded. The coordinator may now invoke only the exact supported adapter action; preserve its actual "
                "result.")
    with engine.journal.registry_lock():
        return engine.change(session_id, "operation_started", mutate, expected_revision)


def admit_effect(engine, session_id, *, operation_id):
    """The last check before an operation's effect starts, on the canonical state under the session lock: a pause or stop
    is either seen here or arrives after the admission and finds active work. Refuses ("effect-closed") an operation that
    is not this session's, is closed or has already reached its restart, ("effect-paused") any session that is not active,
    and ("effect-authority") a step whose owner authority no longer holds (_authority_holds): a ticket can wait, and a
    narrower approval, a replaced policy or an expiry may come first. Records the first admission as admitted_utc in the
    operation's authorization; a repeat for the same open operation is checked again and keeps that time."""
    record_identifier(operation_id)
    def mutate(state):
        operation = state["operations"].get(operation_id)
        if not operation or operation["outcome"] is not None or "restart_pending" in operation:
            raise WorkflowRefusal("This step is no longer open, so nothing starts for it", code="effect-closed")
        if state["status"] != "active":
            raise WorkflowRefusal("This session is paused or stopped, so this step does not start", code="effect-paused")
        if not _authority_holds(state, operation):
            raise WorkflowRefusal("The approval or policy for this step no longer covers it, so it does not start", code="effect-authority")
        admitted = operation["authorization"].setdefault("admitted_utc", pc_records.utc_now())
        return {"operation_id": operation_id, "admitted_utc": admitted}, "This step is cleared to start now."
    return engine.change(session_id, "effect_admitted", mutate)


def _bound_flags(engine, state, operation):
    """The route flags of an update or repair step's reviewed payload, read again from its hash-bound evidence without the
    freshness limit, since a step may finish long after its plan (after a restart, for example)."""
    plan, payload = state["plan"], None
    action = (next((item for item in plan["document"]["actions"] if item["action_id"] == operation["action_id"]), None)
              if plan and plan["sha256"] == operation["plan_sha256"] else None)
    row = state["evidence"].get(action["adapter_payload_evidence_id"]) if action else None
    if row and row["sha256"] == action["adapter_payload_sha256"]:
        data = engine.journal.read_owned(engine.journal.directory(state["session_id"]) / row["path"], EVIDENCE_MAX_BYTES)
        if digest(data) == row["sha256"]:
            payload = decode_record(data, max_bytes=EVIDENCE_MAX_BYTES, max_nodes=EVIDENCE_MAX_NODES)
    if not isinstance(payload, dict) or not isinstance(payload.get("flags"), list):
        raise WorkflowRefusal("This step's reviewed plan or payload is no longer the current one")
    return payload["flags"]


def outcome_rows(engine, state, operation, evidence_ids, outcome):
    """The evidence rows of ``operation``'s actual ``outcome``, refused when the outcome would claim more than was observed:
    a step that waits for its restart records only unknown; a step flagged verify_after_restart succeeds only after the
    observed boot; a recorded update result must fit the outcome; an update or repair succeeds only with its result and a
    true verified postcondition; a failure after the boot carries the facts resolve reads."""
    if outcome != "unknown" and restart_state(operation) == "waiting":
        raise WorkflowRefusal("This step waits for a restart and the check after it; record its result after that check, or record unknown",
                              code="restart-pending")
    rows = engine.evidence_rows(state, evidence_ids, kinds={"outcome", "reconciliation"}, after=operation["started_utc"], seconds=900,
                                allow_empty=outcome == "unknown")
    for row in rows:
        facts = row["facts"]
        if any(facts.get(key) != operation[key] for key in ("operation_id", "action_id", "plan_sha256")) or facts.get("outcome") != outcome:
            raise WorkflowRefusal("Outcome evidence must bind the exact operation, action, plan and observed result")
    if outcome == "unknown" or pc_records.ADAPTERS[operation["adapter_id"]]["family"] not in UPDATE_FAMILIES:
        return rows
    booted = restart_state(operation) == "boot_observed"
    if outcome == "succeeded" and not booted and "verify_after_restart" in _bound_flags(engine, state, operation):
        raise WorkflowRefusal("This update counts as done only after the check that follows the restart", code="restart-pending")
    for row in rows:
        facts = row["facts"]
        if "result" in facts and outcome not in RESULT_OUTCOMES.get(pc_records.UPDATE_RESULTS.get(_result(facts)), ()):
            raise WorkflowRefusal("The recorded update result does not fit this outcome", code="update-result")
        if outcome == "succeeded" and ("result" not in facts or facts.get("verified_postcondition") is not True):
            raise WorkflowRefusal("An update counts as done only when the check after it confirmed what is installed", code="update-postcondition")
        if booted and outcome != "succeeded" and any(type(facts.get(key)) is not bool for key in RESOLVE_FACTS):
            raise WorkflowRefusal("A result after the restart must record its actual effects, whether anything still runs and whether recovery is kept",
                                  code="resolve-facts")
    return rows


def _verified_failure(operation, outcome, rows):
    """True for a failed or partial update result whose adapter's failures stop only their dependents, when every row
    records that the step never started, or that the item did not update and the check after its run confirmed what is installed."""
    facts = pc_records.ADAPTERS[operation["adapter_id"]]
    return (outcome in {"failed", "partial"} and facts["family"] in UPDATE_FAMILIES and facts["independent_failures"] and bool(rows)
            and all(_result(row["facts"]) == "not_run"
                    or pc_records.UPDATE_RESULTS.get(_result(row["facts"])) == "did_not_update" and row["facts"].get("verified_postcondition") is True
                    for row in rows))


def finish_operation(engine, session_id, *, operation_id, outcome, evidence_ids, summary, expected_revision=None):
    record_identifier(operation_id)
    bounded_text(summary, "outcome summary")
    if outcome not in OUTCOMES:
        raise WorkflowRefusal("Choose an explicit actual operation outcome")
    def mutate(state):
        if operation_id not in state["operations"]:
            raise WorkflowRefusal("Operation is not owned by this session")
        operation = state["operations"][operation_id]
        if operation["outcome"] is not None:
            raise WorkflowRefusal("Operation receipt is already consumed; use bounded reconciliation for unknown outcomes")
        verified = _verified_failure(operation, outcome, outcome_rows(engine, state, operation, evidence_ids, outcome))
        operation.update(outcome=outcome, finished_utc=pc_records.utc_now(), evidence_ids=list(evidence_ids), summary=summary)
        was_stopped = state["status"] == "stopped"
        if verified:
            # Accounted for without a decision: only the item's dependents are left out ("not run" is derived, never stored).
            operation["resolution"] = {"kind": "verified_failure", "evidence_ids": list(evidence_ids), "recorded_utc": operation["finished_utc"],
                                       "owner_message_id": None}
        if outcome != "succeeded" and not verified:
            key = "reconcile-" + operation_id
            state["pending"][key] = {"pending_id": key, "kind": "reconciliation", "operation_id": operation_id, "created_utc": pc_records.utc_now(),
                                     "resolved": False, "settings_revision": state["settings_revision"]}
            state["status"] = "stopped" if was_stopped else "paused" if operation["pause_requested"] else "held"
        elif operation["pause_requested"] or state["status"] == "pause_pending":
            state["status"] = "stopped" if was_stopped else "paused"
        if (outcome == "succeeded" or verified) and not was_stopped:
            add_checkpoint(state, "after_action", operation["action_id"])
            next_action_checkpoint(state, plan_depends_on(engine, state) if state["plan"] else None)
        return (operation, "The actual outcome is recorded. " + (
            "Verification is still a separate step." if outcome == "succeeded"
            else "This item did not update. Items that need it will not run; the other approved items can continue." if verified
            else "Further changes are held; preserve evidence and reconcile the result before a new decision."))
    return engine.change(session_id, "operation_finished", mutate, expected_revision)


def pause(engine, session_id, *, reason="Owner requested pause", expected_revision=None):
    bounded_text(reason, "pause reason")
    def mutate(state):
        require_writable(state)
        active = [op for op in state["operations"].values() if op["outcome"] is None]
        for operation in active:
            operation["pause_requested"] = True
        state["status"] = "pause_pending" if active else "paused"
        return ({"active_operation_ids": [op["operation_id"] for op in active]},
                "New actions are paused now. " + ("The step that is running is not forced to stop: PatchCairn waits for it to finish and records what "
                                                  "it actually did." if active
                                                  else "Before carrying on, PatchCairn checks what actually happened while it was paused."))
    return engine.change(session_id, "paused", mutate, expected_revision)


def resume(engine, session_id, *, reconciliation_evidence_ids, expected_revision=None):
    def mutate(state):
        if state["status"] not in {"paused", "pause_pending", "held"}:
            raise WorkflowRefusal("Only held or paused sessions can be reconciled for resume")
        if (any(op["outcome"] in {None, "unknown"} or op["outcome"] in {"failed", "partial"} and not op["resolution"] for op in state["operations"].values())
                or any(p["kind"] == "reconciliation" for p in pending_items(state))):
            raise WorkflowRefusal("Uncertain or unsuccessful operations require an evidence-backed resolution and possibly a new plan")
        pause_time = max((e["at"] for e in engine.journal.load(session_id)["events"] if e["type"] in {"paused", "operation_finished", "resolved"}),
                         default=state["updated_utc"])
        rows = engine.evidence_rows(state, reconciliation_evidence_ids, kinds={"reconciliation"}, after=pause_time, seconds=900)
        expected_outcomes = {key: op["outcome"] for key, op in state["operations"].items()}
        for row in rows:
            facts = row["facts"]
            if (facts.get("scope_matches") is not True or facts.get("no_changes_detected") is not True or facts.get("operation_outcomes") != expected_outcomes
                    or facts.get("plan_sha256") != (state["plan"]["sha256"] if state["plan"] else None)):
                raise WorkflowRefusal("Resume needs a fresh current-scope check and actual outcomes for every operation")
        state["last_reconciled_utc"] = pc_records.utc_now()
        if state["settings"]["timing"] == "scheduled" and engine.require_schedule_activation(state, allow_waiting=True) is None:
            if state["schedule"]:
                state["schedule"]["ready_for_trigger"] = True
            state["status"] = "held"
        else:
            state["status"] = "awaiting_user" if pending_items(state) else "completed" if state["stage"] == "complete" else "active"
        return ({}, "PatchCairn checked what actually happened while it was paused, and the agreed scope is unchanged. Your earlier approvals still "
                    "apply, but only to the same plan and scope; any change to them needs a new approval.")
    return engine.change(session_id, "resumed", mutate, expected_revision)


def stop(engine, session_id, *, reason="Owner requested stop", expected_revision=None):
    bounded_text(reason, "stop reason")
    def mutate(state):
        require_writable(state)
        state["status"] = "stopped"
        state["stop_reason"] = reason
        for operation in state["operations"].values():
            if operation["outcome"] is None:
                operation["pause_requested"] = True
        running = any(op["outcome"] is None and restart_state(op) != "waiting" for op in state["operations"].values())
        return ({"unresolved": pending_items(state)},
                "Stopped. Nothing new starts in this job and nothing was undone. Its records and recovery files are kept."
                + (" The running step is not forced to stop; I record what it did when it ends." if running else ""))
    return engine.change(session_id, "stopped", mutate, expected_revision)
