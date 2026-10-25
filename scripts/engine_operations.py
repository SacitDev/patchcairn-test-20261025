"""One-use operation receipts and their actual outcomes, and pausing, resuming and stopping a session.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

import uuid

from engine_journal import OUTCOMES, WorkflowRefusal, bounded_text, outstanding_effects, record_identifier, require_writable, utc_time
from engine_plans import (acknowledgments, action_authorization, action_binding, add_checkpoint, current_plan, next_action_checkpoint, pending_items,
                          require_reviews)
import pc_records
from pc_records import digest


def begin_operation(engine, session_id, *, action_id, plan_sha256, precondition_evidence_ids, owner_consent_evidence_id=None, expected_revision=None):
    record_identifier(action_id)
    def mutate(state):
        if state["status"] != "active" or state["stage"] != "apply" or pending_items(state):
            raise WorkflowRefusal("New actions wait until the apply stage is active and every hold/checkpoint is resolved")
        activation = engine.require_schedule_activation(state)
        if outstanding_effects(engine):
            raise WorkflowRefusal("An outstanding mutating operation in this engine registry still needs an actual receipt or effects reconciliation")
        document = current_plan(state, plan_sha256)
        require_reviews(engine, state)
        engine.evidence_rows(state, document["evidence_ids"])
        actions = [a for a in document["actions"] if a["action_id"] == action_id]
        if not actions:
            raise WorkflowRefusal("Action is absent from the exact plan")
        action = actions[0]
        action_binding(engine, state, action)
        unconsumed = [a["action_id"] for a in document["actions"] if not any(op["action_id"] == a["action_id"] for op in state["operations"].values())]
        if not unconsumed or action_id != unconsumed[0]:
            raise WorkflowRefusal("Actions follow the exact reviewed order and their individual checkpoints")
        if any(op["action_id"] == action_id or op["outcome"] is None for op in state["operations"].values()):
            raise WorkflowRefusal("An action is already active or consumed; no automatic retry")
        authorization = action_authorization(state, action)
        for acknowledgment in acknowledgments(action):
            ack = state["irreversible_ack"]
            if (not ack or ack["type"] != acknowledgment or ack["plan_sha256"] != plan_sha256 or action_id not in ack["action_ids"]
                    or ack["settings_revision"] != state["settings_revision"] or ack["scope_sha256"] != digest(state["settings"]["scope"])):
                raise WorkflowRefusal("This exact action still needs the owner's separate acknowledgment: " + acknowledgment.replace("_", " "))
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
        if action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
            engine.external_preflight(state, action, rows)
        if action["requires_os_consent"]:
            record = state["pending"].get("consent-" + action_id, {}).get("record")
            if not record or record["plan_sha256"] != plan_sha256 or record["evidence_id"] != owner_consent_evidence_id:
                raise WorkflowRefusal("The actual owner must handle and record protected OS consent")
            engine.evidence_rows(state, [owner_consent_evidence_id], kinds={"protected_consent"}, after=state["plan"]["registered_utc"], seconds=900)
        operation_id = "operation-" + uuid.uuid4().hex
        operation = {"operation_id": operation_id, "action_id": action_id, "plan_sha256": plan_sha256, "settings_revision": state["settings_revision"],
                     "started_utc": pc_records.utc_now(), "finished_utc": None, "outcome": None, "evidence_ids": [],
                     "summary": "Waiting for an actual operation outcome", "authorization": authorization, "pause_requested": False, "resolution": None,
                     "mutating": action["mutating"], "adapter_id": action["adapter_id"]}
        state["operations"][operation_id] = operation
        if authorization["kind"] == "standing_policy":
            state["standing_policy"]["used_actions"] += 1
        return (operation,
                "The one-use operation receipt is recorded. The coordinator may now invoke only the exact supported adapter action; preserve its actual "
                "result.")
    with engine.journal.registry_lock():
        return engine.change(session_id, "operation_started", mutate, expected_revision)


def outcome_rows(engine, state, operation, evidence_ids, outcome):
    if (operation.get("restart_pending") and outcome in {"succeeded", "failed", "partial"}
            and operation.get("restart_verification", {}).get("boot_observed") is not True):
        raise WorkflowRefusal("The original 3010 result is still restart-dependent; preserve unknown until actual boot observations account for it")
    if outcome == "succeeded" and operation.get("restart_pending"):
        proof = operation.get("restart_verification")
        if not proof:
            raise WorkflowRefusal("The original 3010 operation still needs its owner-authorized actual restart and exact post-restart verification")
        row, all_passed = engine.validate_restart_verification(state, operation, proof["evidence_id"])
        if row["sha256"] != proof["sha256"] or not all_passed:
            raise WorkflowRefusal("The restart occurred but exact target/original behavior checks have not all passed; success cannot be recorded")
    rows = engine.evidence_rows(state, evidence_ids, kinds={"outcome", "reconciliation"}, after=operation["started_utc"], seconds=900,
                                allow_empty=outcome == "unknown")
    for row in rows:
        facts = row["facts"]
        if any(facts.get(key) != operation[key] for key in ("operation_id", "action_id", "plan_sha256")) or facts.get("outcome") != outcome:
            raise WorkflowRefusal("Outcome evidence must bind the exact operation, action, plan and observed result")
    return rows


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
        outcome_rows(engine, state, operation, evidence_ids, outcome)
        operation.update(outcome=outcome, finished_utc=pc_records.utc_now(), evidence_ids=list(evidence_ids), summary=summary)
        was_stopped = state["status"] == "stopped"
        if outcome != "succeeded":
            key = "reconcile-" + operation_id
            state["pending"][key] = {"pending_id": key, "kind": "reconciliation", "operation_id": operation_id, "created_utc": pc_records.utc_now(),
                                     "resolved": False, "settings_revision": state["settings_revision"]}
            state["status"] = "stopped" if was_stopped else "paused" if operation["pause_requested"] else "held"
        elif operation["pause_requested"] or state["status"] == "pause_pending":
            state["status"] = "stopped" if was_stopped else "paused"
        if outcome == "succeeded" and not was_stopped:
            add_checkpoint(state, "after_action", operation["action_id"])
            next_action_checkpoint(state)
        return (operation, "The actual outcome is recorded. " + ("Verification is still a separate step." if outcome == "succeeded"
                                                                 else "Further changes are held; preserve evidence and reconcile the result before a new "
                                                                      "decision."))
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
                "New actions are paused immediately. " + ("The active operation is preserved until its safe checkpoint and actual receipt; it is not killed."
                                                          if active
                                                          else "Before resuming, collect fresh evidence of the current state and any earlier outcomes."))
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
        return ({}, "Fresh evidence reconciles the current scope and actual outcomes. Existing plan/action approvals still apply only to their unchanged exact "
                    "scope.")
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
        return ({"unresolved": pending_items(state)},
                "This session is stopped. Evidence, recovery files and unfinished outcomes are preserved. An active operation still needs its actual "
                "safe-checkpoint receipt; no new action is allowed.")
    return engine.change(session_id, "stopped", mutate, expected_revision)
