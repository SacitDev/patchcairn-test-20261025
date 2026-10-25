"""Schedule proposals, their due triggers and the activation that scheduled work needs. No operating-system
schedule is created here.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

import copy
from datetime import timedelta

from engine_journal import SHA, WorkflowRefusal, bounded_text, exact_fields, ids, outstanding_effects, record_identifier, require_writable, utc_time
from engine_plans import owner_record
import pc_records
from pc_records import digest


def schedule_identity(record):
    try:
        return digest({key: record[key] for key in ("owner_id", "quote", "message_id", "source", "recorded_utc", "settings_revision", "proposal")})
    except KeyError as error:
        raise WorkflowRefusal("An incomplete schedule record cannot authorize work") from error


def require_schedule_activation(state, *, allow_waiting=False):
    if state["settings"]["timing"] != "scheduled":
        return None
    record = state["schedule"]
    if record is None and allow_waiting:
        return None
    if (not isinstance(record, dict) or record.get("settings_revision") != state["settings_revision"] or not isinstance(record.get("schedule_id"), str)
            or not SHA.fullmatch(record["schedule_id"]) or record["schedule_id"] != schedule_identity(record)):
        raise WorkflowRefusal("Scheduled work needs a current owner-bound proposal and its matching due trigger")
    activation = record.get("activation")
    if activation is None and allow_waiting:
        return None
    if not isinstance(activation, dict):
        raise WorkflowRefusal("This schedule has not been activated by its matching due trigger")
    fields = {"schedule_id", "trigger_id", "activated_utc", "settings_revision"}
    exact_fields(activation, fields, fields)
    proposal = record["proposal"]
    if (activation["schedule_id"] != record["schedule_id"] or activation["settings_revision"] != state["settings_revision"]
            or activation["trigger_id"] not in state["schedule_triggers"] or record.get("ready_for_trigger") is not False
            or not utc_time(proposal["when_utc"]) <= utc_time(activation["activated_utc"]) <= utc_time(proposal["expires_utc"])
            or utc_time(activation["activated_utc"]) - utc_time(proposal["when_utc"]) > timedelta(seconds=proposal["max_lateness_seconds"])
            or utc_time(pc_records.utc_now()) < utc_time(activation["activated_utc"])):
        raise WorkflowRefusal("The recorded activation does not authorize this exact current schedule")
    return activation


def configure_schedule(engine, session_id, *, schedule, owner_quote, owner_message_id, expected_revision=None):
    exact_fields(schedule, {"when_utc", "description", "expires_utc", "max_lateness_seconds"}, {"when_utc", "description"})
    if utc_time(schedule["when_utc"]) <= utc_time(pc_records.utc_now()):
        raise WorkflowRefusal("The proposed schedule time must be in the future")
    bounded_text(schedule["description"], "schedule explanation")
    proposal = copy.deepcopy(schedule)
    proposal.setdefault("max_lateness_seconds", 300)
    proposal.setdefault("expires_utc", (utc_time(schedule["when_utc"]) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"))
    if (type(proposal["max_lateness_seconds"]) is not int or not 0 <= proposal["max_lateness_seconds"] <= 3600
            or not utc_time(proposal["when_utc"]) <= utc_time(proposal["expires_utc"]) <= utc_time(proposal["when_utc"]) + timedelta(hours=24)):
        raise WorkflowRefusal("Schedule needs an explicit bounded catch-up window and expiry within 24 hours of its due time")
    def mutate(state):
        require_writable(state)
        if state["settings"]["timing"] != "scheduled":
            raise WorkflowRefusal("Choose scheduled timing before recording a proposal")
        if any(op["outcome"] in {None, "unknown"} and op.get("restart_verification", {}).get("boot_observed") is True for op in state["operations"].values()):
            raise WorkflowRefusal("Actual restart observations are already recorded; record that operation's final receipt before changing its schedule. This "
                                  "new proposal was not accepted; pause subsequent work while accounting for the result")
        previous = state["schedule"]
        decisions = copy.deepcopy(previous.get("decision_ids", [previous["message_id"]])) if previous else []
        ids(decisions, "schedule decision identifiers")
        if owner_message_id in decisions:
            if previous and owner_message_id == previous["message_id"] and owner_quote == previous["quote"] and proposal == previous["proposal"]:
                return previous, "This exact schedule decision is already recorded; no activation or action was changed."
            raise WorkflowRefusal("Changing a schedule needs a fresh actual-owner decision; an earlier message cannot authorize a different proposal")
        if len(decisions) >= 500:
            raise WorkflowRefusal("This session reached its bounded schedule-decision history; preserve it and choose separate scoped work")
        record = owner_record(state, owner_quote, owner_message_id)
        unresolved = any(op["outcome"] in {None, "unknown"} or op["outcome"] in {"failed", "partial"}
                         and not op["resolution"] for op in state["operations"].values())
        waiting = state["status"] == "held" and previous and previous.get("activation") is None and previous.get("ready_for_trigger") is True
        record.update(proposal=proposal, creates_os_schedule=False, settings_revision=state["settings_revision"], decision_ids=decisions + [owner_message_id],
                      activation=None, ready_for_trigger=bool((state["status"] in {"active", "awaiting_user"} or waiting) and not unresolved))
        record["schedule_id"] = schedule_identity(record)
        state["schedule"] = record
        for item in state["pending"].values():
            if item["kind"] == "checkpoint" and item.get("checkpoint") == "scheduled_start":
                item["resolved"] = True
        active = [op for op in state["operations"].values() if op["outcome"] is None]
        for operation in active:
            operation["pause_requested"] = True
        if active:
            state["status"] = "pause_pending"
        elif state["status"] not in {"paused", "held"}:
            state["status"] = "held"
        return (record, "The future schedule proposal is recorded and earlier activation cannot start new work. An existing operation still needs its safe "
                        "checkpoint and actual outcome. Paused or held work needs fresh reconciliation before the matching due trigger. No operating-system "
                        "schedule was created.")
    return engine.change(session_id, "schedule_configured", mutate, expected_revision)


def trigger_schedule(engine, session_id, *, schedule_id, trigger_id, expected_revision=None):
    record_identifier(trigger_id)
    if not isinstance(schedule_id, str) or not SHA.fullmatch(schedule_id):
        raise WorkflowRefusal("A trigger must bind the exact current schedule identifier")
    def mutate(state):
        require_writable(state)
        if not state["schedule"] or state["settings"]["timing"] != "scheduled":
            raise WorkflowRefusal("No current schedule proposal is registered")
        record = state["schedule"]
        if schedule_id != record.get("schedule_id") or schedule_id != schedule_identity(record) or record["settings_revision"] != state["settings_revision"]:
            raise WorkflowRefusal("This trigger belongs to a different or superseded schedule")
        if trigger_id in state["schedule_triggers"]:
            return ({"trigger_id": trigger_id, "duplicate": True, "starts_operation": False},
                    "This trigger was already recorded; no duplicate session or action was started.")
        if state["status"] in {"paused", "pause_pending"} or state["status"] == "held" and record.get("ready_for_trigger") is not True:
            raise WorkflowRefusal("Scheduled triggers cannot resume paused or held work")
        if record.get("activation") is not None:
            raise WorkflowRefusal("This exact schedule is already activated; a new trigger cannot restart it")
        if outstanding_effects(engine):
            raise WorkflowRefusal("An outstanding mutating operation in this engine registry blocks schedule dispatch until actual reconciliation")
        if utc_time(pc_records.utc_now()) < utc_time(state["schedule"]["proposal"]["when_utc"]):
            raise WorkflowRefusal("The proposed schedule time has not arrived")
        proposal = state["schedule"]["proposal"]
        if (utc_time(pc_records.utc_now()) > utc_time(proposal["expires_utc"])
                or utc_time(pc_records.utc_now()) - utc_time(proposal["when_utc"]) > timedelta(seconds=proposal["max_lateness_seconds"])):
            raise WorkflowRefusal("The bounded schedule catch-up window or expiry has passed; a new owner decision is required")
        for directory in engine.work.iterdir():
            if directory.is_dir() and directory.name.startswith("session-") and directory.name != session_id:
                other = engine.read_session(directory.name)
                if other["job"] == state["job"] and (other["status"] == "active" or other["status"] == "awaiting_user" and other["schedule_triggers"]):
                    raise WorkflowRefusal("Another active session already owns this job; the trigger cannot duplicate it")
        state["schedule_triggers"].append(trigger_id)
        record["activation"] = {"schedule_id": schedule_id, "trigger_id": trigger_id, "activated_utc": pc_records.utc_now(),
                                "settings_revision": state["settings_revision"]}
        record["ready_for_trigger"] = False
        if state["settings"]["control"] == "guided":
            state["status"] = "awaiting_user"
            key = "schedule-start-" + digest(trigger_id)[:24]
            state["pending"][key] = {"pending_id": key, "kind": "checkpoint", "checkpoint": "scheduled_start", "action_id": None,
                                     "created_utc": pc_records.utc_now(), "resolved": False, "settings_revision": state["settings_revision"]}
            message = "The scheduled guided session is waiting for you. Review the current scope and checkpoint before continuing."
        else:
            state["status"] = "active"
            message = ("The schedule trigger is recorded for this existing session. Exact plan, policy, review and freshness gates still apply before any "
                       "action.")
        return {"trigger_id": trigger_id, "duplicate": False, "starts_operation": False}, message
    with engine.journal.registry_lock():
        return engine.change(session_id, "schedule_triggered", mutate, expected_revision)
