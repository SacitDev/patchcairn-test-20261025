"""What the engine says: the jobs and their stages, the start menu, the command parser and the status, cost and options messages.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

import copy
import math
import re

from engine_journal import ID, WorkflowRefusal, bounded_text
from pc_records import SCHEMA_VERSION


COMMANDS = ("start", "help", "status", "options", "cost", "settings", "pause", "resume", "stop", "resolve")
JOBS = {
    "security_updates": {"label": "Security and updates", "description": "Check agreed software, relevant security concerns and suitable official updates.",
                         "stages": ["scope", "inventory", "research", "plan", "apply", "verify", "complete"]},
    "storage_cleanup": {"label": "Storage and cleanup", "description": "Inspect selected storage metadata and review exact safe cleanup choices.",
                        "stages": ["scope", "inventory", "candidates", "plan", "apply", "verify", "complete"]},
    "diagnosis_repair": {"label": "Diagnosis and repair", "description": "Investigate a stated problem, compare causes and review an evidence-backed repair.",
                         "stages": ["scope", "symptom", "hypotheses", "plan", "apply", "verify", "complete"]},
    "backup_recovery": {"label": "Backup and recovery", "description": "Review selected contents, create a verified backup or plan a checked restoration.",
                        "stages": ["scope", "inventory", "recovery_plan", "plan", "apply", "verify", "complete"]},
}
STAGE_LABELS = {"scope": "Choose and confirm the scope", "inventory": "Review the selected items", "research": "Check official guidance and relevant risks",
                "candidates": "Compare cleanup choices", "symptom": "Understand the reported problem", "hypotheses": "Compare possible causes",
                "recovery_plan": "Choose and check a recovery approach", "plan": "Review the proposed changes", "apply": "Carry out the approved work",
                "verify": "Check the actual result", "complete": "Finished checks"}
CHECKPOINT_LABELS = {"scope": "the agreed scope", "findings": "the assessment findings", "plan": "the proposed changes",
                     "before_action": "before the next action", "after_action": "after the previous action", "finish": "the final result and retained evidence",
                     "scheduled_start": "the scheduled start"}
ACTION_LABELS = {"update": "Install the selected update", "cleanup_quarantine": "Move selected files to quarantine",
                 "backup_create": "Create the reviewed backup", "backup_restore": "Restore the reviewed backup", "repair": "Apply the reviewed repair",
                 "permanent_purge": "Permanently delete the selected quarantined files", "restart": "Restart", "firmware": "Review a firmware change",
                 "os_transition": "Review a system release change", "security_policy": "Review a security setting change", "assessment": "Read-only assessment"}
CHECKPOINTS = {"scope", "findings", "plan", "before_action", "after_action", "finish"}


def decision_card(*, meaning, benefits, drawbacks, cost, reversibility, recommendation, options):
    return {"meaning": meaning, "benefits": benefits, "drawbacks": drawbacks, "cost": cost, "reversibility": reversibility, "recommendation": recommendation,
            "options": options}


def initial_menu():
    lines = ["PatchCairn — Developed by Michael", "Choose the work you want:"]
    descriptions = ["Check selected software versions and relevant security concerns before choosing suitable updates.",
                    "Understand where selected files use space and review safe cleanup choices.",
                    "Investigate a specific problem, compare possible causes and explain a proposed repair.",
                    "Protect selected files with a checked safety copy, or plan how to recover them."]
    lines += [str(number) + ". " + row["label"] + ": " + descriptions[number - 1] for number, row in enumerate(JOBS.values(), 1)]
    lines += ["I recommend guided control and a read-only assessment first: you can understand the findings before deciding about any changes. A plan is a "
              "clear list of proposed changes, their risks, recovery limits and checks.",
              "Guided control pauses at your chosen checkpoints so you can decide; it takes more of your attention. Automatic control has fewer pauses inside "
              "your agreed assessment scope. Computer changes still need an exact reviewed plan or bounded standing policy. A new material decision or OS "
              "consent still causes a hold.",
              "Checkpoints are chosen stops for your decision: scope, findings, plan, before each action, after each action and finish. Choose the stops that "
              "help you keep control.",
              "Control style (guided/automatic) is independent of timing (now/scheduled). Now is convenient when you are ready to review the work; scheduled "
              "timing proposes a later time, when fresh checks and any needed decisions still apply. No operating-system schedule is created here.",
              "Time, download size and assistant usage costs may be unknown until the selected work is assessed. I will explain the known costs and remaining "
              "uncertainty before actions; I will not invent a price or precise duration.",
              "Choose whole-device assessment, selected drives or folders, or one specific problem. Available agent tools determine actual coverage; the fixed "
              "helpers do not promise a universal scan.",
              "Metadata, selected local content reads and content shared with the assistant are separate choices. Browser history, caches, profiles and saved "
              "sessions stay excluded by default; a relevant sensitive observation needs your exact exception. Credentials and secret values are never "
              "requested. Starting does not approve computer changes or bypass OS permissions.",
              "Commands:\n" + "\n".join("- PatchCairn: " + command + " — " + explanation
                                        for command, explanation in (("start", "show this job menu; choose a job to open its assessment"),
                                                                     ("help", "explain jobs, choices, privacy and controls"),
                                                                     ("status", "explain progress, current work and what is waiting"),
                                                                     ("options", "compare the next choices, benefits, risks and recommendation"),
                                                                     ("cost", "explain known costs and what remains unknown"),
                                                                     ("settings", "review or change scope, control, timing and chosen stops"),
                                                                     ("pause", "prevent new actions while an active operation reaches a safe checkpoint"),
                                                                     ("resume", "continue only after fresh checks reconcile actual results"),
                                                                     ("stop", "end this session and preserve evidence and unfinished work"),
                                                                     ("resolve",
                                                                      "review one pending decision or uncertain result without guessing or retrying"))),
              "Next: choose job 1, 2, 3 or 4, then your control style and timing. For example, PatchCairn: start 1 selects security and updates for "
              "assessment. A bare PatchCairn: start shows this menu and creates no session."]
    return "\n\n".join(lines)


def parse_command(text):
    bounded_text(text, "conversation command", 2000)
    raw = text.strip()
    if raw.startswith("/"):
        return {"ok": False, "code": "foreign_command", "message": "Use PatchCairn: help for this toolkit; slash commands belong to the host."}
    if raw.lower().startswith("patchcairn:"):
        raw = raw[len("patchcairn:"):].strip()
    natural = {"start assessment": "start security_updates", "start security updates": "start security_updates",
               "start security and updates": "start security_updates", "start storage cleanup": "start storage_cleanup",
               "start storage and cleanup": "start storage_cleanup", "start diagnosis repair": "start diagnosis_repair",
               "start diagnosis and repair": "start diagnosis_repair", "start backup recovery": "start backup_recovery",
               "start backup and recovery": "start backup_recovery", "show status": "status", "show options": "options", "show costs": "cost",
               "pause patchcairn": "pause", "stop patchcairn": "stop", "resume patchcairn": "resume", "help patchcairn": "help"}
    raw = natural.get(raw.lower(), raw)
    bits = raw.split()
    if not bits or bits[0].lower() not in COMMANDS:
        return {"ok": False, "code": "ambiguous_command",
                "message": "I could not identify one PatchCairn command. Choose PatchCairn: help or state one specific job or command."}
    command = bits[0].lower()
    args = bits[1:]
    if command == "start":
        if len(args) == 1 and args[0] in {"1", "2", "3", "4"}:
            args = [list(JOBS)[int(args[0]) - 1]]
        if len(args) > 1 or args and args[0] not in JOBS:
            return {"ok": False, "code": "ambiguous_job",
                    "message": "Choose job 1 (security and updates), 2 (storage and cleanup), 3 (diagnosis and repair) or 4 (backup and recovery)."}
    elif command == "settings":
        if any("=" not in arg for arg in args):
            return {"ok": False, "code": "invalid_settings",
                    "message": "Use settings control=guided or control=automatic, timing=now or timing=scheduled, or checkpoints=scope,plan,before_action."}
        keys = [arg.split("=", 1)[0] for arg in args]
        if len(keys) != len(set(keys)) or set(keys) - {"control", "timing", "checkpoints"}:
            return {"ok": False, "code": "invalid_settings", "message": "Settings contain an unknown or repeated choice."}
    elif command == "resolve":
        if len(args) > 1 or args and not ID.fullmatch(args[0]):
            return {"ok": False, "code": "invalid_resolution",
                    "message": "Resolve accepts one pending item identifier; it never executes free-form instructions."}
    elif args:
        return {"ok": False, "code": "unexpected_arguments",
                "message": "This command does not accept extra instructions. Use PatchCairn: options to review the next choice."}
    return {"ok": True, "command": command, "arguments": args}


def response(state, code, message, data=None):
    if state and code not in {"created", "help", "status", "options"}:
        message = JOBS[state["job"]]["label"] + " · " + STAGE_LABELS[state["stage"]] + ". " + message
    return {"schema_version": SCHEMA_VERSION, "ok": True, "code": code, "message": message, "session_id": state["session_id"] if state else None,
            "revision": state["revision"] if state else None, "data": copy.deepcopy(data or {})}


def status(engine, session_id):
    state = engine.read_session(session_id)
    explanations = {
        "active": "Continue by reviewing the current step. Collection requires your agreed scope; changes also need the exact plan, fresh checks and the "
                  "required approval. Next: PatchCairn: options.",
        "awaiting_user": "This session is waiting for your next decision. PatchCairn: options explains the available choice.",
        "held": "Further actions are held because a decision, check or actual result needs attention. Review PatchCairn: options, then PatchCairn: resolve for "
                "the pending item. An unknown outcome must be observed before work can continue.",
        "paused": "New actions are paused. Before continuing, the coordinator must check the current scope and actual outcomes. PatchCairn: resume requests "
                  "those fresh checks; it does not retry uncertain work.",
        "pause_pending": "Pause has been requested and no new action may start. The active operation is still running or awaiting its actual safe checkpoint "
                         "receipt; it is not killed. Its outcome may still be unknown. Use PatchCairn: status to check progress and preserve its evidence.",
        "stopped": "This session is stopped and cannot resume or start another action. Keep its evidence and recovery files. Any active or uncertain earlier "
                   "work still needs its actual outcome recorded; stopping does not prove it finished or undo its effects. PatchCairn: options reviews what "
                   "remains; PatchCairn: help explains how to begin separate work.",
        "completed": "The planned work and its result checks are complete. This session is closed. Evidence and recovery files are kept until you separately "
                     "choose cleanup. Use PatchCairn: help to choose a separate job if you want more work.",
    }
    if (not state["operations"] and state["plan"] is None
            and any(item["kind"] == "assessment_finish" and item["resolved"] for item in state["pending"].values())):
        explanations["completed"] = ("The assessment and its result checks are complete. Its findings and limitations are kept with the evidence, and this "
                                     "session recorded no maintenance action. The session is closed; any computer change needs a separate reviewed plan.")
    if (state["status"] == "held" and state["settings"]["timing"] == "scheduled" and state["schedule"] and state["schedule"].get("activation") is None
            and state["schedule"].get("ready_for_trigger") is True):
        explanations["held"] = ("This session is waiting for its agreed scheduled time and matching trigger. No new collection or action may start before that "
                                "activation. Your selected checkpoints and exact plan approvals still apply. Use PatchCairn: options to review the waiting "
                                "choices.")
    restart = next((operation for operation in state["operations"].values() if operation.get("restart_pending") and not operation.get("restart_verification")
                    and operation["outcome"] in {None, "unknown"}), None)
    if restart and state["status"] not in {"stopped", "completed"}:
        decision = restart.get("restart_decision", {}).get("choice")
        lead = ("The restart is deferred. " if decision == "defer"
                else "An owner-handled restart is authorized for this exact operation, no earlier than its agreed time. " if decision == "authorize"
                else "The installer finished and reported that a restart is required. ")
        explanations[state["status"]] = (lead + "Its original 3010 receipt is retained; the restart-dependent result and original behavior are still "
                                                "unverified. No restart or installer retry happens automatically. Any existing pause remains in place for "
                                                "subsequent work. Use PatchCairn: options or PatchCairn: resolve to review the exact restart decision and "
                                                "required observations.")
    elif restart and state["status"] == "stopped":
        explanations["stopped"] += (" For this retained 3010 operation only, you may explicitly defer or authorize the owner-handled restart needed to account "
                                    "for its unfinished effect. The session stays stopped and no new job action is created.")
    mode = ("Live-work session: selecting this mode does not collect evidence or approve computer changes. " if state["mode"] == "real"
            else "Practice session: its records do not establish that your computer was checked or changed. ")
    message = JOBS[state["job"]]["label"] + " · " + STAGE_LABELS[state["stage"]] + ". " + mode + explanations[state["status"]]
    return response(state, "status", message, {"job": state["job"], "stage": state["stage"], "status": state["status"], "control": state["settings"]["control"],
                                               "timing": state["settings"]["timing"], "pending": engine.pending_items(state),
                                               "operations": list(state["operations"].values())})


def cost(engine, session_id):
    state = engine.read_session(session_id)
    totals, unknown, sources = {}, [], []
    actions = state["plan"]["document"]["actions"] if state["plan"] else []
    currencies = set()
    for metric in ("duration_minutes", "money", "bytes"):
        values = []
        for action in actions:
            evidence_id = action.get("estimate_evidence_id")
            facts = {}
            if evidence_id:
                row = engine.evidence_rows(state, [evidence_id], kinds={"inventory"})[0]
                facts = row["facts"]
                if evidence_id not in sources:
                    sources.append(evidence_id)
            value = facts.get(metric)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or not math.isfinite(value):
                break
            if metric == "money":
                currency = facts.get("currency")
                if not isinstance(currency, str) or not re.fullmatch("[A-Z]{3}", currency):
                    break
                currencies.add(currency)
            values.append(value)
        if actions and len(values) == len(actions) and (metric != "money" or len(currencies) == 1):
            totals[metric] = sum(values)
        else:
            unknown.append(metric)
    if "money" in totals:
        totals["currency"] = next(iter(currencies))
    message = "These estimates use the current assessment and proposed work. "
    if "duration_minutes" in totals:
        message += "Estimated time: " + str(totals["duration_minutes"]) + " minutes. "
    if "money" in totals:
        message += "Estimated price: " + str(totals["money"]) + " " + totals["currency"] + ". "
    if "bytes" in totals:
        message += "Recorded data workload: " + str(totals["bytes"]) + " bytes. "
    if unknown:
        labels = {"duration_minutes": "time", "money": "price", "bytes": "data workload"}
        message += "Still unknown: " + ", ".join(labels[key] for key in unknown) + ". "
    message += ("Missing numbers stay unknown. Data workload is the amount handled by the proposed steps; it does not tell you how much disk space will be "
                "freed. Assistant usage charges are not estimated here.")
    return response(state, "cost", message, {"estimates": totals, "unknown": unknown, "evidence_ids": sources})


def options(engine, session_id):
    state = engine.read_session(session_id)
    pending = engine.pending_items(state)
    checkpoint = next((item for item in pending if item["kind"] == "checkpoint"), None)
    restart = next((item for item in pending if item["kind"] == "restart"), None)
    meaning = "Current job: " + JOBS[state["job"]]["label"] + ". Current step: " + STAGE_LABELS[state["stage"]].lower() + "."
    recommendation = "Review the agreed scope and current findings before deciding about the exact proposed work."
    choices = ["Review this step with PatchCairn: status", "Review scope, control and chosen stops with PatchCairn: settings",
               "Pause new actions with PatchCairn: pause, or end the session with PatchCairn: stop"]
    if state["status"] in {"stopped", "completed"}:
        recommendation = ("This session is closed. Keep its evidence and recovery files; any uncertain earlier outcome still needs an actual observation."
                          if state["status"] == "stopped"
                          else "The result checks are complete. Keep retained evidence and recovery files until a separate cleanup decision.")
        choices = ["Review recorded results with PatchCairn: status", "Use PatchCairn: help to choose separate work"]
        if state["status"] == "stopped" and pending:
            choices.insert(1, "Use PatchCairn: resolve to inspect an existing unfinished outcome; this does not reopen the session")
            if restart:
                choices.insert(2, "Use PatchCairn: resolve to defer or authorize only the owner-handled restart needed to account for this retained operation; "
                                  "the session stays stopped")
    elif restart:
        meaning += " The installer has finished with restart required; its restart-dependent result remains unverified."
        recommendation = ("Save your work and review the restart's effect on open applications. Choose defer, or authorize only the owner-handled restart for "
                          "this exact operation; any existing pause remains for later work.")
        choices = ["Use PatchCairn: resolve to defer this exact restart", "Use PatchCairn: resolve to authorize the owner-handled restart at its agreed time",
                   "Keep the installer receipt and collect actual boot, target and original behavior checks afterward"]
    elif (state["status"] == "held" and state["settings"]["timing"] == "scheduled" and state["schedule"] and state["schedule"].get("activation") is None
            and state["schedule"].get("ready_for_trigger") is True):
        recommendation = "Keep work waiting for the agreed time and its matching trigger; a previous start cannot activate this proposal."
        choices = ["Wait for the agreed time and matching trigger", "Ask to change the proposed time with a fresh owner decision",
                   "Pause or stop the session if you no longer want the scheduled work"]
    elif state["status"] == "pause_pending":
        recommendation = "Keep new actions paused while the existing operation reaches its safe checkpoint and actual result is observed."
        choices = ["Check actual progress with PatchCairn: status", "Keep the pause in place and preserve evidence",
                   "End the session with PatchCairn: stop; the existing operation still needs its actual outcome"]
    elif any(item["kind"] == "reconciliation" for item in pending):
        recommendation = "Establish the actual result before considering further work. An unknown result cannot be treated as success or retried."
        choices = ["Inspect the unfinished result with PatchCairn: resolve", "Have the coordinator collect fresh evidence of what actually happened",
                   "Keep actions held, or end the session with PatchCairn: stop"]
    elif checkpoint:
        label = CHECKPOINT_LABELS[checkpoint["checkpoint"]]
        meaning += " Your chosen stop is " + label + "."
        recommendation = "Review " + label + ", then tell me whether to continue at this stop. Continuing a checkpoint does not approve unreviewed changes."
        choices = ["Inspect this chosen stop with PatchCairn: resolve", "After reviewing this choice, tell me whether to continue",
                   "Keep work paused or use PatchCairn: stop to end it"]
    elif state["status"] == "paused":
        recommendation = "Keep the pause until fresh checks account for the current scope and every earlier operation."
        choices = ["Review actual results with PatchCairn: status", "Request fresh outcome checks with PatchCairn: resume",
                   "Keep work paused, or end the session with PatchCairn: stop"]
    elif (state["status"] == "active" and state["stage"] == "plan" and state["plan"] is None and not state["operations"] and not state["approval"]
            and not state["reviews"] and not state["standing_policy"] and state["scope_authorization"]):
        recommendation = ("Review the assessment findings and remaining uncertainty. If you want no changes, ask to finish the assessment; its summary and "
                          "coverage checks must be recorded first.")
        choices.insert(0, "Ask to finish this assessment after reviewing its findings and limitations, without making changes")
    reversibility = ("This session is closed and cannot resume. Stopping does not undo earlier effects; retained evidence and recovery files need a separate "
                     "cleanup decision." if state["status"] in {"stopped", "completed"}
                     else "Changing scope or settings requires a fresh plan and approval. Each action explains its own recovery limits; stopping does not undo "
                          "earlier effects.")
    drawbacks = ("A restart closes applications and can lose unsaved work. Save your work and review the original plan's recovery limits first; the restart "
                 "itself cannot be undone." if restart
                 else "Changes may affect applications or data; the exact plan explains each risk. Missing evidence or permission holds the work.")
    card = decision_card(meaning=meaning, benefits="A clear next step can reduce uncertainty while preserving your control.", drawbacks=drawbacks,
                         cost=cost(engine, session_id)["message"] + (" Restart downtime is unknown until the selected work is assessed." if restart else ""),
                         reversibility=reversibility, recommendation=recommendation, options=choices)
    message = "\n\n".join(label.capitalize() + ": " + card[label] for label in ("meaning", "benefits", "drawbacks", "cost", "reversibility", "recommendation"))
    message += "\n\nChoices:\n" + "\n".join("- " + choice for choice in choices)
    actions = []
    if state["plan"]:
        for action in state["plan"]["document"]["actions"]:
            available = (["Review this recorded action and its actual result", "Keep evidence and recovery files"]
                         if state["status"] in {"stopped", "completed"} else ["Review this exact action and the required checks before an approval decision",
                                                                              "Leave this action held",
                                                                              "Ask for a separately reviewed plan if the choice changes"])
            actions.append(decision_card(meaning=ACTION_LABELS[action["kind"]] + ": " + action["target"], benefits=action["benefit"], drawbacks=action["risk"],
                                         cost="An estimate may still be unknown; see PatchCairn: cost for time, price and data workload.",
                                         reversibility=action["reversibility"],
                                         recommendation="Review this action's stated result check: " + action["verification"], options=available))
        message += "\n\n" + ("Recorded plan: " if state["status"] in {"stopped", "completed"} else "Proposed changes: ") + state["plan"]["document"]["summary"]
        for action_card in actions:
            message += ("\n\n" + "\n".join(label.capitalize() + ": " + action_card[label]
                                           for label in ("meaning", "benefits", "drawbacks", "cost", "reversibility", "recommendation")))
            message += "\nChoices:\n" + "\n".join("- " + choice for choice in action_card["options"])
    return response(state, "options", message,
                    {"decision": card, "action_decisions": actions, "pending": engine.pending_items(state), "commands": ["PatchCairn: " + c for c in COMMANDS]})


def dispatch(engine, session_id, command, *, expected_revision=None):
    parsed = parse_command(command)
    if not parsed["ok"]:
        return {"schema_version": SCHEMA_VERSION, "ok": False, "code": parsed["code"], "message": parsed["message"], "session_id": session_id, "revision": None,
                "data": {}}
    name, args = parsed["command"], parsed["arguments"]
    if name == "help":
        return response(engine.read_session(session_id) if session_id else None, "help", initial_menu())
    if name == "start":
        if session_id:
            return status(engine, session_id)
        if not args:
            return response(None, "menu", initial_menu())
        return engine.create_session(job=args[0])
    if not session_id:
        raise WorkflowRefusal("Start or select a session first")
    if name == "status":
        return status(engine, session_id)
    if name == "cost":
        return cost(engine, session_id)
    if name == "options":
        return options(engine, session_id)
    if name == "pause":
        return engine.pause(session_id, expected_revision=expected_revision)
    if name == "stop":
        return engine.stop(session_id, expected_revision=expected_revision)
    if name == "settings":
        if not args:
            state = engine.read_session(session_id)
            return response(state, "settings",
                            "Control and timing are independent. Changes invalidate old plans and approvals. Choose control=guided/automatic, "
                            "timing=now/scheduled, or checkpoints=scope,findings,plan,before_action,after_action,finish.", {"settings": state["settings"]})
        values = dict(arg.split("=", 1) for arg in args)
        if "checkpoints" in values:
            values["checkpoints"] = values["checkpoints"].split(",") if values["checkpoints"] else []
        return engine.setup(session_id, expected_revision=expected_revision, **values)
    if name == "resolve":
        return engine.resolve(session_id, pending_id=args[0] if args else None)
    # Chat text alone cannot supply real fresh observations to resume.
    state = engine.read_session(session_id)
    return response(state, "reconciliation_required",
                    "Before resuming, the coordinator must collect fresh owned current-scope and actual-operation-outcome evidence. No changes have been "
                    "resumed.", {"required": "resume(reconciliation_evidence_ids=[...])"})
