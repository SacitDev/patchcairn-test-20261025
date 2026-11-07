"""What the engine says: the jobs and their stages, the start menu and the help text, the command parser, the status,
cost and options messages, the warning, decision and hand-off texts, and the plain labels a session report shows.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
Text from outside PatchCairn (device names, update titles, vendor names, release notes) is shown only through
vendor_text(). A command is shown only as it was given (an action's rendered_command or the launcher command), never
built here.
"""
from __future__ import annotations

import copy
import math
import re
import unicodedata

from engine_journal import EVIDENCE_MAX_BYTES, EVIDENCE_MAX_NODES, ID, WorkflowRefusal, bounded_text, decode_record, restart_state
import pc_records
from pc_records import SCHEMA_VERSION


COMMANDS = ("start", "help", "status", "options", "cost", "settings", "pause", "resume", "stop", "resolve")
JOBS = {
    "security_updates": {"label": "Security and updates",
                         "description": "Find out-of-date apps, Python and Node packages, drivers, firmware and system software, and "
                                        "update what you approve.",
                         "stages": ["scope", "inventory", "research", "plan", "apply", "verify", "complete"]},
    "storage_cleanup": {"label": "Storage and cleanup",
                        "description": "See what fills your drive; delete files for good, set them aside (can be undone; frees no space) "
                                       "or back them up first (may need extra space).",
                        "stages": ["scope", "inventory", "candidates", "plan", "apply", "verify", "complete"]},
    "diagnosis_repair": {"label": "Diagnosis and repair",
                         "description": "Find out why something goes wrong and fix what I can: update an app, reinstall the same version "
                                        "(Mac, Linux) or finish a cut-off software install (Debian, Ubuntu).",
                         "stages": ["scope", "symptom", "hypotheses", "plan", "apply", "verify", "complete"]},
    "backup_recovery": {"label": "Backup and recovery", "description": "Make a checked copy of files you choose, or bring them back.",
                        "stages": ["scope", "inventory", "recovery_plan", "plan", "apply", "verify", "complete"]},
}
STAGE_LABELS = {"scope": "Choose and confirm the scope", "inventory": "Review the selected items", "research": "Check official guidance and relevant risks",
                "candidates": "Compare cleanup choices", "symptom": "Understand the reported problem", "hypotheses": "Compare possible causes",
                "recovery_plan": "Choose and check a recovery approach", "plan": "Review the proposed changes", "apply": "Carry out the approved work",
                "verify": "Check the actual result", "complete": "Finished checks"}
CHECKPOINT_LABELS = {"scope": "the agreed scope", "findings": "the assessment findings", "plan": "the proposed changes",
                     "before_action": "before the next action", "after_action": "after the previous action", "finish": "the final result and retained evidence",
                     "scheduled_start": "the scheduled start"}
ACTION_LABELS = {"update": "Install the selected update", "cleanup_quarantine": "Set the selected files aside (can be undone)",
                 "backup_create": "Create the reviewed backup", "backup_restore": "Restore the reviewed backup", "repair": "Apply the reviewed repair",
                 "permanent_purge": "Delete the selected set-aside files for good", "assessment": "Read-only assessment",
                 "remove_originals": "Delete the original files for good after a checked backup",
                 "retention_release": "Delete kept backups and recovery files for good", "retention_forget": "Forget kept backups that are already gone",
                 "session_release": "Delete a finished session's kept files for good", "delete_selected": "Delete the selected files for good",
                 "system_update": "Open the system update for you to install", "firmware_update": "Update the device's firmware"}
CHECKPOINTS = {"scope", "findings", "plan", "before_action", "after_action", "finish"}
# The exact reply that approves a permanent deletion or a firmware update, by action kind: {} is the number of files or
# backups, or the device number.
IRREVERSIBLE_REPLIES = {"permanent_purge": "delete {} files", "remove_originals": "delete {} files", "delete_selected": "delete {} files",
                        "retention_release": "delete {} backups", "session_release": "delete {} backups",
                        "firmware_update": "update firmware on device {}, I have my recovery key"}
CLOSED_STATUSES = frozenset({"stopped", "completed"})
STATUS_LABELS = {"active": "Working on the current step", "awaiting_user": "Waiting for your decision",
                 "held": "On hold until a check or a decision", "paused": "Paused", "pause_pending": "Pausing after the current step",
                 "stopped": "Stopped; it cannot continue", "completed": "Finished"}
# package_routes.RESTART_SIGNALS, copied because this module imports no route module; test_engine_text compares them.
RESTART_LABELS = {"none": "No restart reported", "recommended": "Restart recommended", "required": "Restart needed to finish",
                  "required_before_retry": "Restart needed before trying again", "initiated_by_installer": "The installer started a restart",
                  "unknown": "restart: unknown"}
# What a package row's restart says: the service writes "pending" while the step waits for its restart.
PACKAGE_RESTART_LABELS = {"none": "No restart waiting", "pending": "Waiting for a restart", "boot_observed": "Restart seen",
                          "unknown": "restart: unknown"}
# Update results only (package rows, system update hand-offs and firmware updates), for the sets in pc_records.
CATEGORY_LABELS = {"updated_checked": "Updated and checked", "need_restart": "Needs a restart to finish", "waiting_decision": "Waiting for you",
                   "did_not_update": "Did not update", "skipped_by_you": "Left out by you",
                   "update_yourself": "Update yourself", "needs_check": "Needs a check"}
GROUP_LABELS = {"system_drivers": "System and drivers", "apps": "Apps", "programming_tools": "Programming tools (Python and Node packages)",
                "update_yourself": "Update yourself", "your_decision": "Your decision, separately"}
RESULT_LABELS = {"updated": "Updated; the new version was checked", "restart_needed": "Needs a restart to finish",
                 "waiting_for_you": "Waiting for your own step", "conditional_pending": "Waiting for your separate decision",
                 "did_not_update": "Did not update; what is installed was checked", "not_installed_power": "Not installed: plug in, then choose it again",
                 "not_run": "Not run: it never started (for example after a pause, a stop, a restart still waiting, or an item it depends on)",
                 "excluded": "Left out by you",
                 "update_yourself": "Update yourself (listed only, or you chose guide me)",
                 "integrity_failure": "Needs a check: the update's files did not pass their integrity check",
                 "could_not_check": "Needs a check: the result could not be confirmed", "device_not_responding": "Needs a check: the device did not respond",
                 "differs_from_plan": "Needs a check: something other than the plan changed", "unknown": "Needs a check: no result was recorded"}
CHANGE_WORDS = {"runtime_line_change": "new line: your own decision", "major_jump": "big change: may work differently",
                "install_scripts": "wants to run its own setup program: your own decision"}
NEEDS_CHECK = ("Needs a check means PatchCairn could not confirm what happened, so it makes no other change until this is cleared up. "
               "Say PatchCairn: resolve: I look at what is really there, tell you what I found and what you can reply.")
# What PatchCairn: resolve says before the open items, and what a failed step's lines end with.
RESOLVE_MESSAGE = ("These items need your decision or a check of what actually happened. Resolving one never marks an action as done and never runs "
                   "it again. A stopped job stays stopped while its results are recorded.")
NOT_RETRIED = "Nothing else changes until you decide. Nothing is retried on its own."
# The names of kept data in the report (report.RETAINED_KINDS, compared by test_engine_text) and in the service tool's listing.
RETAINED_LABELS = {"backup": "Backup", "recovery": "Recovery copy", "quarantine": "Files set aside", "destination": "Backup folder you chose",
                   "reservation": "Reserved for an unfinished backup"}
# The restart words: PatchCairn never restarts the computer.
RESTART_NOTICE = "PatchCairn never restarts the computer; an installer may close apps or ask to restart"
RESTART_UNKNOWN = "restart: unknown"
RESTART_WAIT = "I put restarts together where I can. This update needs a restart and a check before the rest can continue."
RESTART_STEPS = ("Save your work, then restart the computer yourself when you are ready (choose Restart, not Shut down). Afterwards open your "
                 "assistant in the PatchCairn folder and say PatchCairn: resume")
RESTART_CHECK = "I check now whether the computer has restarted. If it has, I finish checking this update. Nothing else starts."
WRONG_REPLY = ("That reply is not the phrase, so nothing was approved and nothing changed. Ask the person to type it themselves; never type it for "
               "them: ")
RESTART_STOPPED = "Restart the computer when you are ready, then say PatchCairn: status so I can check the update. This job stays stopped."
JOB_CLOSED = "This job is closed, so it cannot carry on. Nothing has started."
RUN_NOT_STARTED = "This step did not start, and nothing changed"
RUN_STATUS = "Go back to the chat and say PatchCairn: status."
NO_PLAN_COST = "No costs yet: there is no plan. Assistant usage may cost money; I do not estimate it."
REPLY_RULE = 'Capital letters, extra spaces and commas, and a full stop at the end do not matter; a plain "yes" does not approve this.'
# The reply that approves a reviewed plan without a typed reply; options() offers it only when it can work.
PLAN_REPLY = ('To go ahead with the whole list, say yes. To leave something out, name it, for example "yes, but not Zoom"; '
              "anything that depends on it is left out too.")
# The decision-card headings, in order; the choices come last under "Your reply:".
CARD_HEADINGS = (("meaning", "What this does:"), ("benefits", "Good:"), ("drawbacks", "Watch out:"), ("cost", "Cost:"),
                 ("reversibility", "Can it be undone?"), ("recommendation", "I recommend:"))
# A short set of plain requests, accepted after the menu as well as the commands; "done" only checks the result (status).
PHRASES = {"free up space": "start storage_cleanup", "free up disk space": "start storage_cleanup", "clean up my disk": "start storage_cleanup",
           "my disk is full": "start storage_cleanup", "update everything": "start security_updates", "update my computer": "start security_updates",
           "update my apps": "start security_updates", "check for updates": "start security_updates", "my computer is slow": "start diagnosis_repair",
           "something is not working": "start diagnosis_repair", "back up my files": "start backup_recovery", "restore my files": "start backup_recovery",
           "start assessment": "start", "start security updates": "start security_updates", "start security and updates": "start security_updates",
           "start storage cleanup": "start storage_cleanup", "start storage and cleanup": "start storage_cleanup",
           "start diagnosis repair": "start diagnosis_repair", "start diagnosis and repair": "start diagnosis_repair",
           "start backup recovery": "start backup_recovery", "start backup and recovery": "start backup_recovery", "show status": "status",
           "show options": "options", "show costs": "cost", "pause patchcairn": "pause", "stop patchcairn": "stop", "resume patchcairn": "resume",
           "help patchcairn": "help", "done": "status", "1": "start 1", "2": "start 2", "3": "start 3", "4": "start 4"}
VENDOR_TEXT_MAX = 200
# Control, format (bidirectional, zero-width and tag characters), private-use, surrogate, unassigned and line or paragraph
# separator characters never reach a person's screen from outside text.
HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"})
FULL_DRIVE_BYTES = 10 ** 9  # below 1 GB free, the drive line first points to the Recycle Bin or Trash
KEPT_ROWS_SHOWN = 20  # a release warning names at most this many kept rows, then says how many more
_UNITS = (("TB", 10 ** 12), ("GB", 10 ** 9), ("MB", 10 ** 6), ("KB", 10 ** 3))


def irreversible_phrase(kind, number):
    """The exact reply the owner types to approve a permanent deletion or a firmware update of action ``kind``."""
    if not isinstance(kind, str) or kind not in IRREVERSIBLE_REPLIES or type(number) is not int or number < 1:
        raise WorkflowRefusal("This action has no typed reply for that number", code="typed-reply-plan")
    return IRREVERSIBLE_REPLIES[kind].format(number)


def report_labels():
    """The plain names a session report shows for each code, copied from the tables above. Keys: jobs, stages, actions,
    statuses, checkpoints, restart_signals, package_restarts, categories, groups and results (report.LABEL_KEYS)."""
    return {"jobs": {job: row["label"] for job, row in JOBS.items()}, "stages": dict(STAGE_LABELS), "actions": dict(ACTION_LABELS),
            "statuses": dict(STATUS_LABELS), "checkpoints": dict(CHECKPOINT_LABELS), "restart_signals": dict(RESTART_LABELS),
            "package_restarts": dict(PACKAGE_RESTART_LABELS), "categories": dict(CATEGORY_LABELS), "groups": dict(GROUP_LABELS),
            "results": dict(RESULT_LABELS)}


def decision_card(*, meaning, benefits, drawbacks, costs, reversibility, recommendation, choices):
    return {"meaning": meaning, "benefits": benefits, "drawbacks": drawbacks, "cost": costs, "reversibility": reversibility,
            "recommendation": recommendation, "options": choices}


def card_text(card, separator="\n\n"):
    """A decision card under its headings, the choices last under "Your reply:"."""
    return (separator.join(heading + " " + card[key] for key, heading in CARD_HEADINGS) + separator + "Your reply:\n"
            + "\n".join("- " + choice for choice in card["options"]))


def initial_menu():
    rows = [str(number) + ". " + row["label"] + ": " + row["description"][0].lower() + row["description"][1:]
            for number, row in enumerate(JOBS.values(), 1)]
    explained = (("start", "this menu"), ("help", "how a job works"), ("status", "where we are"), ("options", "next choices"),
                 ("cost", "time and costs"), ("settings", "control, timing, checkpoints"), ("pause", "finish this step, then wait"),
                 ("resume", "check, then carry on"), ("stop", "end, keep the records"), ("resolve", "decide a waiting item"))
    return "\n\n".join([
        "PatchCairn — Developed by Michael",
        "Choose a job:\n" + "\n".join(rows),
        "Nothing is checked or changed until you choose a job and agree what I may look at: the whole device, selected drives or folders, "
        "or one problem. Before any change I show a plan with its risks, whether it can be undone and how I check it.",
        "Control: guided (recommended; I wait at each checkpoint you choose) or automatic (fewer stops; changes still need your approved "
        "plan). Timing, a separate choice: now or scheduled.\n"
        "Checkpoints you can choose: scope, findings, plan, before each action, after each action and finish.",
        "Privacy: what your assistant reads, such as file and app names, goes to its company. I read file contents only if you allow it "
        "and never ask for passwords.\nCost: your time, downloads and assistant usage; I say what is known first.",
        "Commands:\n" + "\n".join("PatchCairn: " + command + " (" + words + ")" for command, words in explained),
        'Reply 1, 2, 3 or 4, or a short request such as "free up space". Showing this menu changes nothing.'])


def help_text():
    """What PatchCairn: help says: the steps of a job and the commands used most; shorter than the menu."""
    return "\n".join([
        "How a job works:",
        '1. Choose a job by replying 1, 2, 3 or 4, or a short request such as "update my computer".',
        "2. Agree what I may look at. Looking changes nothing.",
        "3. I tell you what I found.",
        "4. I propose a plan with each change, its risks, whether it can be undone and how I check it.",
        '5. You reply. Deleting files for good and firmware updates need the exact phrase I show; a plain "yes" never approves them.',
        "6. I make the approved changes, check the results and sum up.",
        "",
        "Most used:",
        'PatchCairn: status (where we are; after a step you did yourself, say "done")',
        "PatchCairn: pause (finish this step, then wait)",
        "PatchCairn: resume (check what happened, then carry on)",
        "PatchCairn: stop (end and keep the records)",
        "",
        "PatchCairn: start shows the menu again. For a page you can keep, ask for the report. For anything else, ask in your own words."])


def _is_pending_id(text):
    """True for the id of a pending item (engine_plans, engine_operations, engine_schedule); no other word goes after resolve."""
    return ID.fullmatch(text) is not None and text.startswith(("checkpoint-", "reconcile-", "schedule-start-"))


def parse_command(text, in_session=False):
    """The request ``text`` as a command with its arguments, or why it is not one. ``in_session`` is True while a job is selected,
    where a number or a word that is no command may be a reply to a decision, never a choice of job."""
    bounded_text(text, "conversation command", 2000)
    raw = text.strip()
    if raw.startswith("/"):
        return {"ok": False, "code": "foreign_command",
                "message": "Slash commands belong to your assistant, not to PatchCairn. For PatchCairn, say PatchCairn: help."}
    if raw.lower().startswith("patchcairn:"):
        raw = raw[len("patchcairn:"):].strip()
    raw = PHRASES.get(" ".join(raw.lower().split()).rstrip(".!?"), raw)
    bits = raw.split()
    if not bits or bits[0].lower() not in COMMANDS:
        return {"ok": False, "code": "ambiguous_command",
                "message": ("I did not understand that as a PatchCairn command. If it was your reply to a decision, I record it at that step. "
                            "Otherwise say PatchCairn: options." if in_session else
                            "I did not understand that as a PatchCairn request. Reply 1, 2, 3 or 4 to choose a job, or say PatchCairn: help.")}
    command = bits[0].lower()
    args = bits[1:]
    if command == "start":
        if len(args) == 1 and args[0] in {"1", "2", "3", "4"}:
            args = [list(JOBS)[int(args[0]) - 1]]
        if len(args) > 1 or args and args[0] not in JOBS:
            jobs = [f"{number} ({row['label'].lower()})" for number, row in enumerate(JOBS.values(), 1)]
            return {"ok": False, "code": "ambiguous_job", "message": "Choose job " + ", ".join(jobs[:-1]) + " or " + jobs[-1] + "."}
    elif command == "settings":
        args = [arg.rstrip(",") for arg in args]
        if any("=" not in arg for arg in args):
            return {"ok": False, "code": "invalid_settings",
                    "message": "Write each setting as name=value, for example PatchCairn: settings control=automatic timing=now. The names are "
                               "control (guided or automatic), timing (now or scheduled) and checkpoints (a list such as scope,plan,before_action)."}
        keys = [arg.split("=", 1)[0] for arg in args]
        if len(keys) != len(set(keys)) or set(keys) - {"control", "timing", "checkpoints"}:
            return {"ok": False, "code": "invalid_settings",
                    "message": "Each setting may appear once, and only control, timing and checkpoints exist. Say PatchCairn: settings to see yours."}
    elif command == "resolve":
        if len(args) > 1 or args and not _is_pending_id(args[0]):
            return {"ok": False, "code": "invalid_resolution",
                    "message": "Say PatchCairn: resolve on its own and I will show what is waiting for your decision. It takes no other words."}
    elif args:
        return {"ok": False, "code": "unexpected_arguments",
                "message": "This command takes no extra words. Say it on its own, or say PatchCairn: options to see the next choices."}
    return {"ok": True, "command": command, "arguments": args}


def response(state, code, message, data=None):
    if state and code not in {"created", "help", "status", "options", "cost", "job_open"}:
        message = JOBS[state["job"]]["label"] + " · " + STAGE_LABELS[state["stage"]] + ". " + message
    return {"schema_version": SCHEMA_VERSION, "ok": True, "code": code, "message": message, "session_id": state["session_id"] if state else None,
            "revision": state["revision"] if state else None, "data": copy.deepcopy(data or {})}


def restart_text(signal, source):
    """The restart sentence for a typed restart signal and the probe that reported it; "restart: unknown" without a source."""
    if not isinstance(signal, str) or signal not in RESTART_LABELS or signal == "unknown" or not isinstance(source, str) or not source.strip():
        return RESTART_UNKNOWN
    return RESTART_NOTICE


def _restart_operation(state):
    """The open operation that waits for a restart, by the engine's one reading of its restart record."""
    return next((operation for operation in state["operations"].values()
                 if restart_state(operation) == "waiting" and operation["outcome"] in {None, "unknown"}), None)


def _restart_sentence(operation):
    pending = operation["restart_pending"]
    text = restart_text(pending.get("signal"), pending.get("source")) if isinstance(pending, dict) else RESTART_UNKNOWN
    if text == RESTART_UNKNOWN:
        return "What asked for the restart was not recorded (" + RESTART_UNKNOWN + "). PatchCairn never restarts the computer."
    return text + "."


def _step_name(state, operation):
    """(label, target) of an operation's plan action; a step of a plan that was replaced has only its action id."""
    actions = state["plan"]["document"]["actions"] if state["plan"] else ()
    action = next((row for row in actions if row["action_id"] == operation["action_id"]), None)
    return (ACTION_LABELS[action["kind"]], action["target"]) if action else ("A step of an earlier plan", operation["action_id"])


def _failed_text(operation):
    """What a failed or partial step's record says, as whole sentences, and what follows from it."""
    summary = operation["summary"].strip()
    return summary + ("" if summary.endswith((".", "!", "?")) else ".") + " " + NOT_RETRIED


def pending_lines(state, items):
    """One line per open item: what it is and the reply that clears it. The reply goes to the assistant, who records it or checks
    what is there; nothing runs again."""
    lines = []
    for item in items:
        if item["kind"] == "checkpoint":
            lines.append("- My stop at " + CHECKPOINT_LABELS[item["checkpoint"]] + ': say "carry on" to continue.')
        elif item["kind"] == "reconciliation":
            operation = state["operations"][item["operation_id"]]
            label, target = _step_name(state, operation)
            if operation["outcome"] in {"failed", "partial"}:
                reply = ('Say "leave it stopped".' if state["status"] == "stopped" else
                         'Say "plan it again" for a new plan you approve, or "leave it on hold".')
                said = _failed_text(operation) + " " + reply
            else:
                said = 'I could not confirm the result. Say "check it" and I look at what is there now; nothing runs again.'
            lines.append("- " + label + ": " + vendor_text(target) + ": " + said)
    return lines


def resolve_text(state, items):
    """What PatchCairn: resolve says: each open item with the reply that clears it."""
    return "\n".join([RESOLVE_MESSAGE, *pending_lines(state, items)]) if items else "Nothing is waiting for your decision."


def _result_rows(state):
    """One update_summary row per step whose outcome evidence names its result, category and group; a row that does not fit
    pc_records' sets is left out, so status always answers."""
    rows = []
    for operation in state["operations"].values():
        facts = state["evidence"][operation["evidence_ids"][-1]]["facts"] if operation["evidence_ids"] else {}
        row = {"name": _step_name(state, operation)[1], **{key: facts.get(key) for key in ("result", "category", "group")}}
        try:
            check_update_row(row)
        except WorkflowRefusal:
            continue
        rows.append(row)
    return rows


def status(engine, session_id):
    state = engine.read_session(session_id)
    explanations = {
        "active": "Next: say PatchCairn: options. Looking needs your agreed scope; changes also need the plan and your approval.",
        "awaiting_user": "This job is waiting for your next decision. PatchCairn: options shows the choices.",
        "held": "Nothing else changes until a decision or a check is done. PatchCairn: options shows what comes next.",
        "paused": "Paused: nothing new starts. To carry on, say PatchCairn: resume: I first check what happened, and I never repeat a step whose result "
                  "is unclear. To end the job, say PatchCairn: stop.",
        "pause_pending": "Pausing: nothing new starts. The running step is not forced to stop, because that could leave things half done. I record what "
                         "it did when it ends.",
        "stopped": "This job is stopped: it cannot carry on, and stopping undid nothing. Its records and recovery files are kept. If a step was still "
                   "running, its result is not known yet. PatchCairn: options shows what is left; PatchCairn: start shows the menu for a new job.",
        "completed": "Finished. This job is closed. Its records and recovery files stay until you choose to delete them. PatchCairn: start shows the menu "
                     "for a new job.",
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
    items = engine.pending_items(state)
    if any(item["kind"] == "reconciliation" for item in items) or state["status"] == "held" and items:
        lines = "\n".join(pending_lines(state, items))
        if state["status"] == "stopped":
            explanations["stopped"] += " Still open:\n" + lines
        else:
            explanations[state["status"]] = "This comes first; nothing else changes until it is cleared up:\n" + lines
    restart = _restart_operation(state)
    if restart and state["status"] not in CLOSED_STATUSES:
        explanations[state["status"]] = (RESTART_WAIT + " " + _restart_sentence(restart) + " Until then no change can start except a backup. "
                                         + RESTART_STEPS + "; I then check what the restart finished."
                                         + (" The job stays paused until I have checked." if state["status"] in {"paused", "pause_pending"} else ""))
    elif restart and state["status"] == "stopped":
        explanations["stopped"] += (" One update in this job still needs a restart and a check before its result is known. PatchCairn never restarts "
                                    "the computer. " + RESTART_STOPPED)
    mode = ("This job works on your real computer. " if state["mode"] == "real"
            else "Practice session: its records do not establish that your computer was checked or changed. ")
    message = JOBS[state["job"]]["label"] + " · " + STAGE_LABELS[state["stage"]] + ". " + mode + explanations[state["status"]]
    rows = _result_rows(state)
    if rows:
        message += "\n" + update_summary(rows)
    data = {"job": state["job"], "stage": state["stage"], "status": state["status"], "control": state["settings"]["control"],
            "timing": state["settings"]["timing"], "pending": items, "operations": list(state["operations"].values())}
    return response(state, "status", message, {**data, **({"operation_id": restart["operation_id"]} if restart else {})})


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
    message += ("Missing numbers stay unknown. Data workload is the amount handled by the proposed steps; it does not tell you how much drive space will be "
                "freed. Assistant usage charges are not estimated here.")
    return response(state, "cost", message, {"estimates": totals, "unknown": unknown, "evidence_ids": sources})


def _plan_reply(state):
    """The reply that moves a plan both reviews approved forward: the typed phrase once this plan's warning stands, else
    PLAN_REPLY; None when no reply can work yet, and while a typed warning is still to come."""
    plan, warning = state["plan"], state["irreversible_warning"]
    if (not plan or state["approval"] or state["stage"] != "plan" or state["status"] not in {"active", "awaiting_user"}
            or [row["verdict"] for row in state["reviews"]] != ["approved", "approved"]):
        return None
    if warning and warning["plan_sha256"] == plan["sha256"]:
        return "To go ahead, type exactly: " + irreversible_phrase(warning["kind"], warning["number"])
    needs_typed = any(pc_records.TYPED_ACKNOWLEDGMENTS & set(pc_records.ADAPTERS[action["adapter_id"]]["acknowledgments"])
                      for action in plan["document"]["actions"])
    return None if needs_typed else PLAN_REPLY


def _separate_questions(engine, state, action):
    """The questions an action of the current plan still needs on their own, each ending with the reply that works."""
    facts, questions = pc_records.ADAPTERS[action["adapter_id"]], []
    agreed = state["irreversible_ack"] and action["action_id"] in state["irreversible_ack"]["action_ids"]
    if "no_component_rollback" in facts["acknowledgments"] and not agreed:
        questions.append(repair_ack_text())
    if facts["conditional_decisions"]:
        row = state["evidence"][action["adapter_payload_evidence_id"]]
        data = engine.journal.read_owned(engine.journal.directory(state["session_id"]) / row["path"], EVIDENCE_MAX_BYTES)
        conditional = decode_record(data, max_bytes=EVIDENCE_MAX_BYTES, max_nodes=EVIDENCE_MAX_NODES).get("conditional", {})
        recorded = {item["decision"] for item in state["conditional_decisions"] if item["action_id"] == action["action_id"]}
        if "run_install_scripts" in conditional and "run_install_scripts" not in recorded:
            questions.append(install_scripts_text(conditional["run_install_scripts"]))
        if "runtime_line_change" in conditional and "runtime_line_change" not in recorded:
            questions.append(new_line_text(action["target"]))
    return questions


def _action_choices(engine, state, action):
    """The choices of one action card: a step that began is a record, an approved one has nothing left to ask, and any other
    is still a proposal, with the questions it needs first."""
    if state["status"] in CLOSED_STATUSES or any(row["action_id"] == action["action_id"] for row in state["operations"].values()):
        return ["Review this recorded action and its actual result", "Keep evidence and recovery files"]
    if state["approval"] and action["action_id"] in state["approval"]["action_ids"]:
        return [*_separate_questions(engine, state, action), "See the result with PatchCairn: status"]
    return [*_separate_questions(engine, state, action), "Review this exact action and the required checks before an approval decision",
            "Leave this action held", "Ask for a separately reviewed plan if the choice changes"]


def options(engine, session_id):
    state = engine.read_session(session_id)
    pending = engine.pending_items(state)
    checkpoint = next((item for item in pending if item["kind"] == "checkpoint"), None)
    restart = _restart_operation(state)
    meaning = "Current job: " + JOBS[state["job"]]["label"] + ". Current step: " + STAGE_LABELS[state["stage"]].lower() + "."
    recommendation = "Review the agreed scope and current findings before deciding about the exact proposed work."
    good = "You stay in control of what happens next."
    choices = ["Review this step with PatchCairn: status", "Review scope, control and chosen stops with PatchCairn: settings",
               "Pause new actions with PatchCairn: pause, or end the job with PatchCairn: stop"]
    unfinished = [state["operations"][item["operation_id"]] for item in pending if item["kind"] == "reconciliation"]
    failed = next((operation for operation in unfinished if operation["outcome"] in {"failed", "partial"}), None)
    if state["status"] in CLOSED_STATUSES:
        recommendation = ("This job is closed. Its records and recovery files are kept; a step with an unclear result still needs a check."
                          if state["status"] == "stopped"
                          else "The result checks are complete. Its records and recovery files stay until you choose to delete them.")
        good = "Its records stay, so you can see what happened."
        choices = ["See the recorded results with PatchCairn: status", "Say PatchCairn: start to choose a new job"]
        if state["status"] == "stopped" and pending:
            choices.insert(1, "Use PatchCairn: resolve to see what is still open; this does not reopen the job")
        if state["status"] == "stopped" and restart:
            recommendation = RESTART_STOPPED
    elif restart:
        meaning += " " + RESTART_WAIT
        recommendation = RESTART_STEPS + ". " + RESTART_NOTICE + "."
        good = "This finishes the update and lets the rest continue."
        choices = ["Restart when you are ready, then say PatchCairn: resume", "See where things stand with PatchCairn: status",
                   "Pause new actions with PatchCairn: pause, or end the job with PatchCairn: stop"]
    elif (state["status"] == "held" and state["settings"]["timing"] == "scheduled" and state["schedule"] and state["schedule"].get("activation") is None
            and state["schedule"].get("ready_for_trigger") is True):
        recommendation = "Keep work waiting for the agreed time and its matching trigger; a previous start cannot activate this proposal."
        good = "Nothing starts before the agreed time."
        choices = ["Wait for the agreed time and matching trigger", "Ask to change the proposed time with a fresh owner decision",
                   "Pause or stop the job if you no longer want the scheduled work"]
    elif state["status"] == "pause_pending":
        recommendation = "Keep the pause while the running step ends. It is not forced to stop, and I record what it did."
        good = "Nothing new starts while you decide."
        choices = ["See how far it got with PatchCairn: status", "Keep the pause in place",
                   "End the job with PatchCairn: stop; the running step still ends on its own"]
    elif failed:
        recommendation = _failed_text(failed)
        good = "Nothing else changes until this is cleared up."
        choices = ["Ask me to plan it again; you approve the new plan", "Leave it as it is for now", "End this job with PatchCairn: stop"]
    elif unfinished:
        recommendation = "Find out what really happened before anything else changes. An unknown result cannot be treated as success or retried."
        good = "Nothing else changes until this is cleared up."
        choices = ["See the unfinished step with PatchCairn: resolve", "Ask me to look at what really happened",
                   "Keep work on hold, or end the job with PatchCairn: stop"]
    elif checkpoint:
        label = CHECKPOINT_LABELS[checkpoint["checkpoint"]]
        meaning += " Your chosen stop is " + label + "."
        good = "You see where things stand before anything else happens."
        recommendation = "Review " + label + ", then tell me whether to continue at this stop. Continuing a checkpoint does not approve unreviewed changes."
        choices = ["Inspect this chosen stop with PatchCairn: resolve", "After reviewing this choice, tell me whether to continue",
                   "Keep work paused or use PatchCairn: stop to end it"]
    elif state["status"] == "paused":
        recommendation = "Keep the pause until I have checked the agreed scope and every earlier step."
        good = "Nothing new starts while you decide."
        choices = ["See the results so far with PatchCairn: status", "Ask me to check and carry on with PatchCairn: resume",
                   "Keep work paused, or end the job with PatchCairn: stop"]
    elif (state["status"] == "active" and state["stage"] == "plan" and state["plan"] is None and not state["operations"] and not state["approval"]
            and not state["reviews"] and not state["standing_policy"] and state["scope_authorization"]):
        recommendation = ("Review the assessment findings and remaining uncertainty. If you want no changes, ask to finish the assessment; its summary and "
                          "coverage checks must be recorded first.")
        choices.insert(0, "Ask to finish this assessment after reviewing its findings and limitations, without making changes")
    reply = None if pending else _plan_reply(state)
    if reply:
        choices.insert(0, reply)
        recommendation = "Read the proposed changes below, then give your reply."
    reversibility = ("This job is closed and cannot carry on. Stopping undid nothing; its records and recovery files stay until you choose to delete them."
                     if state["status"] in CLOSED_STATUSES
                     else "Changing scope or settings requires a fresh plan and approval. Each action explains its own recovery limits; stopping does not undo "
                          "earlier effects.")
    drawbacks = ("A restart closes applications and can lose unsaved work. Save your work and review the original plan's recovery limits first; the restart "
                 "itself cannot be undone." if restart
                 else "Changes may affect applications or data; the exact plan explains each risk. Missing evidence or permission holds the work.")
    costs = cost(engine, session_id)["message"] if state["plan"] else NO_PLAN_COST
    card = decision_card(meaning=meaning, benefits=good, drawbacks=drawbacks, costs=costs + (" How long the restart takes is not known." if restart else ""),
                         reversibility=reversibility, recommendation=recommendation, choices=choices)
    message = card_text(card)
    actions = []
    if state["plan"]:
        for action in state["plan"]["document"]["actions"]:
            actions.append(decision_card(meaning=ACTION_LABELS[action["kind"]] + ": " + action["target"], benefits=action["benefit"], drawbacks=action["risk"],
                                         costs="An estimate may still be unknown; see PatchCairn: cost for time, price and data workload.",
                                         reversibility=action["reversibility"],
                                         recommendation="Review this action's stated result check: " + action["verification"],
                                         choices=_action_choices(engine, state, action)))
        heading = "Recorded plan: " if state["status"] in CLOSED_STATUSES else "Approved plan: " if state["approval"] else "Proposed changes: "
        message += "\n\n" + heading + state["plan"]["document"]["summary"]
        for action_card in actions:
            message += "\n\n" + card_text(action_card, "\n")
    return response(state, "options", message,
                    {"decision": card, "action_decisions": actions, "pending": engine.pending_items(state), "commands": ["PatchCairn: " + c for c in COMMANDS]})


def dispatch(engine, session_id, command, *, expected_revision=None):
    parsed = parse_command(command, in_session=bool(session_id))
    if not parsed["ok"]:
        return {"schema_version": SCHEMA_VERSION, "ok": False, "code": parsed["code"], "message": parsed["message"], "session_id": session_id, "revision": None,
                "data": {}}
    name, args = parsed["command"], parsed["arguments"]
    if name == "help":
        return response(engine.read_session(session_id) if session_id else None, "help", help_text())
    if name == "start":
        if not args:
            return response(None, "menu", initial_menu())
        if not session_id:
            return engine.create_session(job=args[0])
        state = engine.read_session(session_id)
        if state["status"] in CLOSED_STATUSES:
            return engine.create_session(job=args[0], mode=state["mode"], platform=state["platform"])
        return response(state, "job_open", "A job is already open: " + JOBS[state["job"]]["label"]
                        + ". Finish it or say PatchCairn: stop before starting another.")
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
            settings = state["settings"]
            return response(state, "settings",
                            "Your settings now: control " + settings["control"] + ", timing " + settings["timing"] + ", checkpoints "
                            + (", ".join(settings.get("checkpoints") or []) or "none") + ". Control is how often I stop: guided waits at each "
                            "checkpoint you chose, automatic stops less. Timing is now or scheduled. To change one, say PatchCairn: settings "
                            "control=automatic. In the same way: PatchCairn: settings timing=scheduled, and PatchCairn: settings "
                            "checkpoints=scope,plan,before_action. A change cancels the current plan and approvals, so they are made again.",
                            {"settings": settings})
        values = dict(arg.split("=", 1) for arg in args)
        if "checkpoints" in values:
            values["checkpoints"] = values["checkpoints"].split(",") if values["checkpoints"] else []
        return engine.setup(session_id, expected_revision=expected_revision, **values)
    if name == "resolve":
        return engine.resolve(session_id, pending_id=args[0] if args else None)
    # Chat text alone cannot supply real fresh observations to resume. The check after a restart runs through the step's ticket.
    state = engine.read_session(session_id)
    restart = _restart_operation(state)
    named = {"operation_id": restart["operation_id"]} if restart else {}
    if state["status"] in CLOSED_STATUSES:
        return response(state, "session_closed", JOB_CLOSED + " " + (RESTART_STOPPED if restart else "PatchCairn: start shows the menu for a new job."), named)
    if restart:
        return response(state, "restart_check_required", RESTART_CHECK, named)
    return response(state, "reconciliation_required",
                    "Before carrying on, I first check what actually happened while work was paused. Nothing has started again yet.",
                    {"required": "resume(reconciliation_evidence_ids=[...])"})


# --- texts for warnings, decisions and hand-offs (no engine needed) ----------------------------------------------------

def _refused(message, code="text-input"):
    return WorkflowRefusal(message, code=code)


def _count(value, name):
    if type(value) is not int or value < 0:
        raise _refused("The " + name + " must be a whole number that is not negative")
    return value


def _about(size):
    """A byte count as people read it: "about 1.2 GB" (1 GB = 1,000,000,000 bytes); under 1,000 bytes exactly."""
    size = _count(size, "size")
    if size < 1000:
        return "1 byte" if size == 1 else f"{size:,} bytes"
    unit, scale = next((unit, scale) for unit, scale in _UNITS if round(size / scale, 1) >= 1 or scale == 10 ** 3)
    return f"about {size / scale:.1f} {unit}"


def vendor_text(value):
    """Text from outside PatchCairn as it is shown: quoted, every character of the hidden categories removed (control,
    bidirectional, zero-width, tag, private-use and unassigned characters, line and paragraph separators), double quotes
    shown as single ones, then cut to at most VENDOR_TEXT_MAX characters (the last one "…" when cut)."""
    if not isinstance(value, str):
        raise _refused("Text from outside PatchCairn must be text", code="vendor-text")
    kept = []
    for char in value:
        if unicodedata.category(char) not in HIDDEN_CATEGORIES:
            kept.append("'" if char == '"' else char)
            if len(kept) > VENDOR_TEXT_MAX:
                kept[VENDOR_TEXT_MAX - 1:] = ["…"]
                break
    return '"' + "".join(kept) + '"'


def _shown_command(command, limit):
    """A command exactly as it was given, refused (never changed) when it is not one line of printable text."""
    if (not isinstance(command, str) or not command.strip() or len(command) > limit
            or any(unicodedata.category(char) in HIDDEN_CATEGORIES for char in command)):
        raise _refused("A shown command must be one line of printable text of at most " + str(limit) + " characters", code="shown-command")
    return command


def guide_steps(rendered_command, preconditions=()):
    """The "guide me" text for one item: PatchCairn's own steps to check first, then the action's rendered_command exactly as given."""
    command = _shown_command(rendered_command, 500)
    if not isinstance(preconditions, (list, tuple)) or not all(isinstance(step, str) and step.strip() for step in preconditions):
        raise _refused("Each step to check first must be text")
    lines = ["Guide me: you do this one item on your own."]
    lines += ["Before you start:", *("- " + step for step in preconditions)] if preconditions else []
    return "\n".join(lines + ["Do exactly this:", command,
                              'PatchCairn does not check the result afterwards; it lists this item under "update yourself".'])


def reinstall_hint(rendered_command):
    """How to put back the version that was installed before, with the action's rendered_command exactly as given."""
    return "\n".join(["To put back the version you had, you can run this command yourself:", _shown_command(rendered_command, 500),
                      "PatchCairn does not run it for you and does not check the result."])


def run_ticket_text(result):
    """What the person reads in their own terminal after run --ticket, from the result it returned: a hold, or a step that never
    started, says so, with the terminal steps when the hold gives the launcher command; a step waiting for a restart gets the
    restart steps; a closed step gets its recorded update result. Nothing here claims more than the result says."""
    if "hold" in result:
        held = RUN_NOT_STARTED + " (" + result["hold"] + ")."
        return (held + "\n" + terminal_handoff(result["command"], device_number=result.get("device_number")) if "command" in result
                else held + " " + RUN_STATUS)
    if result.get("outcome") is None:
        return ("This update needs a restart to finish. Save your work, restart when you are ready, then open your assistant in the PatchCairn "
                "folder and say PatchCairn: resume.")
    receipt = result.get("receipt") or {}
    if result["outcome"] != "succeeded" and receipt.get("adapter_invoked") is False:
        return RUN_NOT_STARTED + ". " + RUN_STATUS
    return RESULT_LABELS.get(receipt.get("result"), RESULT_LABELS["unknown"]) + ". Go back to the chat and say done."


def retained_text(rows):
    """The service tool's listing of kept data: each row's plain name, folder, size and date, then the total."""
    lines = []
    for row in rows:
        size = row["bytes"]
        shown = "size not recorded" if size is None else _about(size) if size < 1000 else f"{_about(size)}, {size:,} bytes"
        lines.append(f"{RETAINED_LABELS.get(row['kind'], row['kind'])}: {vendor_text(row['location'])} ({shown}, kept since {row['created_utc']})")
    total = sum(row["bytes"] for row in rows if row["bytes"] is not None)
    return "\n".join(lines + [f"Kept recovery data: {len(rows)} item(s), {total:,} bytes recorded."])


def terminal_handoff(command, *, device_number=None):
    """The step in the person's own Terminal app, with PatchCairn's launcher command exactly as given: sudo's password
    prompt, and for a firmware update the device number and the firmware tool's questions."""
    lines = ["This step runs in your own Terminal app, so you can see it and answer its questions.",
             "1. Open the Terminal app (on Ubuntu, press Ctrl+Alt+T).",
             "2. Paste this one command (Ctrl+Shift+V, or right-click and Paste), then press Enter:", _shown_command(command, 2000),
             "3. If it asks for your password (sudo), type the password you use to log in. Nothing appears while you type; that is "
             "normal. Never type it into the chat."]
    if device_number is not None:
        if type(device_number) is not int or device_number < 1:
            raise _refused("The device number must be a whole number of at least 1")
        lines.append(f"4. When it asks for the device number, type {device_number}. When the firmware tool asks you to confirm, answer y to go "
                     "ahead or n to stop. If it asks to restart now, save your work first; you can answer y, or answer n and restart later.")
    lines.append(f"{len(lines) - 1}. When the text stops, come back to the chat and say done. PatchCairn then checks the result itself.")
    return "\n".join(lines)


def modes_text(platform, *, do_it_for_me=True, reason=None):
    """The two ways for a firmware, kernel, driver or macOS restart update ("guide me", "do it for me"), with the actor rule;
    reason says why only "guide me" is offered."""
    if platform not in ("windows", "macos", "linux"):
        raise _refused("The two ways are described for Windows, macOS or Linux only")
    do_it = ("Do it for me: I check the update again just before it starts (and the power, for firmware) and open the exact Settings page; "
             "you press only the item I name. I check the result afterwards, after the restart if one is needed."
             if platform != "linux" else
             "Do it for me: I check the update again just before it starts (and the power, for firmware), then start PatchCairn's own step in a "
             "terminal you can see, or give you its one command for your Terminal app. You type your password or answer the tool's question "
             "there. I check the result afterwards, after the restart if one is needed.")
    lines = [do_it] if do_it_for_me else []
    lines.append('Guide me: I show the exact steps for this one item and you do them on your own. I do not check the result; the item is '
                 'listed under "update yourself".')
    lines.append("PatchCairn's rule for your assistant: it never presses Install, runs the update tool or answers these questions for you, "
                 "and it says no if asked.")
    if reason is not None and not (isinstance(reason, str) and reason.strip()):
        raise _refused("The reason must be text")
    lines.append('Choose "do it for me" when it is offered.' if do_it_for_me else
                 'Only "guide me" is offered for this item.' + ("" if reason is None else " " + reason))
    return "\n".join(lines)


def stale_firmware_list_text(*, max_age_days=30, rendered_command=None):
    """Why only "guide me" is offered while the Linux firmware list is old, with a refresh command only as given."""
    lines = [f"The list of firmware updates on this computer (from the Linux firmware service, LVFS) is more than {_count(max_age_days, 'age')} "
             'days old, or its age is unknown. Until it is refreshed, only "guide me" is offered for firmware.']
    if rendered_command is not None:
        lines += ["To refresh it, you can run this command yourself in the Terminal app:", _shown_command(rendered_command, 500)]
    return "\n".join(lines)


def settings_step(item, *, platform):
    """The Settings step: the one item to press (vendor text) and what to leave."""
    if platform not in ("windows", "macos"):
        raise _refused("The Settings step exists on Windows and macOS only")
    text = ("On the page I opened, press only this item: " + vendor_text(item) + ". Leave every other item, even a button that installs "
            "everything" + (" ('Download & install all')" if platform == "windows" else "") + ". When it has finished, come back to the chat "
            "and say done. If something else installs at the same time, the result needs a check, and I make no other change until you say "
            "PatchCairn: resolve.")
    if platform == "macos":
        text += " Your Mac may ask for your login password or Touch ID to install; enter it there, never in the chat."
    return text


def managed_computer_text():
    return ("This computer looks managed by an organisation, for example your work's IT team. Its updates and settings may be controlled "
            "there, and PatchCairn does not try to get around that. Ask your IT team before changing anything on it.")


def non_admin_text():
    return ("This account is not an administrator. Some updates need an administrator to approve them in the computer's own prompt. If you "
            "do not have that password, ask the person who manages this computer. PatchCairn and your assistant never ask for a password "
            "in the chat.")


def free_space_text(volume, free_bytes):
    """Free space on one drive, as observed."""
    return "Free space on " + vendor_text(volume) + ": " + _about(free_bytes) + " (observed; other programs can change it)."


def drive_line(volume, total_bytes, free_bytes, *, platform):
    """The drive line shown first in a cleanup; a nearly full drive points to the Recycle Bin or Trash step first."""
    if _count(free_bytes, "free space") > _count(total_bytes, "drive size"):
        raise _refused("Free space cannot be larger than the drive")
    line = ("Drive " + vendor_text(volume) + ": " + _about(free_bytes) + " free of " + _about(total_bytes)
            + " (observed; other programs can change it).")
    if free_bytes < FULL_DRIVE_BYTES:
        line += (" This drive is almost full. First look through the " + ("Recycle Bin" if platform == "windows" else "Trash") + ": emptying it "
                 "deletes what is in it for good. Then empty it yourself, come back to the chat and say done: PatchCairn needs some free space for "
                 "its own records before it can delete anything. If it is already empty, tell me.")
    return line


def remeasure_text(volume, before_bytes, after_bytes):
    """The difference after the person's own step (emptying the Recycle Bin or Trash, or the system's own cleanup)."""
    name = vendor_text(volume)
    if before_bytes is None or after_bytes is None:
        return "Free space on " + name + " could not be measured both before and after your step, so the difference is not known."
    change = _count(after_bytes, "free space after") - _count(before_bytes, "free space before")
    difference = ("no change" if change == 0
                  else _about(abs(change)) + (" more free space" if change > 0 else " less free space"))
    return ("Free space on " + name + " before your step: " + _about(before_bytes) + "; now: " + _about(after_bytes) + ". That is "
            + difference + " (observed; other programs can change it).")


def new_line_text(name):
    """The separate decision for moving a programming language runtime to its next line."""
    return (vendor_text(name) + " would move to a new line. A fix update (same line) is part of the normal list, but a new line can change "
            "how the programs that use it behave, so it needs its own decision from you, separate from the plan. If a program you rely on "
            'uses it, leave it out and check with that program\'s maker first. To go ahead, say "move to the new line". To keep the line you '
            'have, say "leave it out".')


def install_scripts_text(names):
    """The separate decision for an update that wants to run its own setup programs, for exactly the ``names`` given."""
    return ("This update wants to run its own setup program: " + ", ".join(vendor_text(name) for name in names) + ". A setup program can change "
            'anything your account can change, so it needs its own decision from you, separate from the plan. To allow exactly these, say '
            '"allow the setup program". To go without this update, say "leave it out".')


def repair_ack_text():
    """The separate agreement a repair needs when PatchCairn has no way to put back what it changes."""
    return ("This repair cannot be rolled back: PatchCairn has no way to put back what it changes, so it needs your own agreement, separate from "
            'the plan. To go ahead, say "go ahead without a way back". To go without this repair, say "leave it out".')


# What each kind of deletion removes: (one, many, what the reply calls one).
_DELETED = {"permanent_purge": ("set-aside file", "set-aside files", "file"), "remove_originals": ("original file", "original files", "file"),
            "delete_selected": ("file", "files", "file"),
            "retention_release": ("kept item (a backup or recovery copy)", "kept items (backups or recovery copies)", "item"),
            "session_release": ("kept item (a backup or recovery copy) of a finished session", "kept items (backups or recovery copies) of a finished session",
                                "item")}


def _warning(warning, kinds):
    if not isinstance(warning, dict) or warning.get("kind") not in kinds:
        raise _refused("This warning record is not for this kind of action", code="typed-reply-plan")
    return warning["kind"], irreversible_phrase(warning["kind"], warning.get("number"))


def _kept_rows(rows):
    """The lines naming a release plan's rows (location and size), at most KEPT_ROWS_SHOWN of them."""
    lines = [f"- {RETAINED_LABELS.get(row['kind'], row['kind'])}: {vendor_text(row['location'])} ({_about(row['size'])})" for row in rows[:KEPT_ROWS_SHOWN]]
    return lines + ([f"- and {len(rows) - KEPT_ROWS_SHOWN} more kept items"] if len(rows) > KEPT_ROWS_SHOWN else [])


def release_details(warning, payloads):
    """deletion_warning's notes and rows for a release of kept data, from its bound storage plans; nothing for another warning."""
    if warning["kind"] not in ("retention_release", "session_release"):
        return {}
    plans = [payload["storage_plan"] for payload in payloads]
    return {"notes": [note for plan in plans for note in plan.get("notes", [])], "rows": [row for plan in plans for row in plan.get("rows", [])]}


def deletion_warning(warning, *, notes=(), rows=()):
    """The warning for a permanent deletion, from the engine's irreversible_warning record: the count, the size as "about", each
    kept row of a release (``rows``), the three facts, the sharpest risks after them (``notes``, from the plan and its backup),
    and last the exact typed reply and how to decline."""
    kind, phrase = _warning(warning, _DELETED)
    size, number = warning.get("bytes"), warning["number"]
    one, many, unit = _DELETED[kind]
    they, skip, them = ("it", "skips", "it") if number == 1 else ("they", "skip", "them")
    lines = [f"What this does: deletes {number} {one if number == 1 else many} for good (" + ("size not recorded" if size is None else _about(size)) + ").",
             *_kept_rows(rows)]
    if kind == "remove_originals":
        lines.append(f"Watch out: {they} {skip} the Recycle Bin or Trash, and no other copy is kept: the checked backup becomes the only copy. "
                     "This is not secure erasure.")
    else:
        lines.append(f"Watch out: {they} {skip} the Recycle Bin or Trash, no copy is kept, and this is not secure erasure: special tools can "
                     "sometimes recover deleted files.")
    lines += notes
    if unit == "item":
        lines.append("An item can hold many files, and one backup can count as more than one item. The reply calls every item a backup.")
    lines += ["Can it be undone? No.", "Your reply: to go ahead, type exactly: " + phrase]
    if number == 1:
        lines.append(f'The reply says "{phrase.split()[-1]}" even for one {unit}.')
    return "\n".join(lines + [f"To leave {them}, say no; nothing is deleted.", REPLY_RULE])


def _flags(flags):
    """True for a list, tuple or set of the route flags pc_records names."""
    return isinstance(flags, (list, tuple, set, frozenset)) and all(isinstance(flag, str) and flag in pc_records.ROUTE_FLAGS for flag in flags)


def firmware_card(platform="unknown", *, device=None, flags=None, uefi_or_fde=None):
    """The precautions before a firmware update, or before a macOS update that needs a restart (platform "macos").
    device: the device name (vendor text); flags: the route's flags, None when unknown; uefi_or_fde: False only when the
    device is known to be neither UEFI firmware nor affecting disk encryption. Unknown facts give the longer card."""
    if platform not in ("windows", "macos", "linux", "unknown"):
        raise _refused("Unknown platform for the firmware card")
    if flags is not None and not _flags(flags):
        raise _refused("The firmware card takes the route's flags only")
    lines = [] if device is None else ["Device: " + vendor_text(device)]
    lines += ["Plug the computer into a wall socket and let the battery charge first. On battery, or if PatchCairn cannot tell how the "
              "computer is powered, the update stops and waits; PatchCairn checks the power again just before it starts.",
              "Do not switch off the computer, close the lid or unplug the device being updated. The device may stop working while it "
              "updates; the screen may go dark and the computer may restart more than once."]
    if flags is None:
        lines.append("If power is lost during the update, the computer or device may not start again.")
    elif "dual_image" in flags:
        lines.append("This device reports a second copy of its firmware, which may let it recover if the update is interrupted; that is "
                     "not a promise.")
    else:
        lines.append("This device reports no second copy of its firmware: if power is lost during the update, it may not start again.")
    lines.append("If this is a drive's own firmware, back up the files on that drive first.")
    keys = {"windows": "your BitLocker recovery key: it is usually in your Microsoft account (https://aka.ms/myrecoverykey) or with your "
                       "work's IT team",
            "macos": "your FileVault recovery key, the one you saved when FileVault was turned on",
            "linux": "your disk-encryption passphrase, the one you type when the computer starts, before the login screen"}
    shown = [keys[platform]] if platform in keys else [keys[name] for name in ("windows", "macos", "linux")]
    lines.append("Have " + "; or ".join(shown) + ". Keep it on paper or on another device, not only on this computer. If your disk is not "
                 "encrypted, there is no key to find" + ("." if platform == "macos" else ", and the reply only confirms that you looked."))
    if platform in ("linux", "unknown") and uefi_or_fde is not False:
        lines.append("If this computer can also start Windows, have the Windows BitLocker recovery key too (usually in your Microsoft account).")
    if platform == "windows":
        lines.append("Microsoft suggests suspending BitLocker before a planned firmware update; it normally turns back on after the restart. "
                     "That is your own choice and your own step: PatchCairn never does it.")
    if platform == "macos":
        lines.append("PatchCairn cannot tell whether this macOS update also updates the Mac's firmware, so these precautions apply.")
    lines.append("It counts as done only after the check that follows the restart.")
    return "\n".join(lines)


def firmware_warning(warning, *, platform="unknown", device=None, version=None, flags=None, uefi_or_fde=None):
    """The firmware card for the warned device, from the engine's irreversible_warning record, with the exact typed reply and how
    to decline. device: its name (vendor text), None when it was not reported; version: the target version (vendor text). The
    other keywords are firmware_card's; without them the card names every platform's precautions."""
    _, phrase = _warning(warning, {"firmware_update"})
    card = firmware_card(platform, flags=flags, uefi_or_fde=uefi_or_fde)
    named = "its name was not reported" if device is None else vendor_text(device)
    target = "" if version is None else " to version " + vendor_text(version)
    return "\n".join([f"What this does: updates the firmware (the built-in software) of device {warning['number']} ({named}){target}.", "Watch out:",
                      *("- " + line for line in card.split("\n")),
                      "Can it be undone? Usually not: firmware can rarely be taken back.",
                      "Your reply: to go ahead, type exactly: " + phrase, "To leave it, say no; nothing is updated.", REPLY_RULE])


def _rows(rows):
    if not isinstance(rows, (list, tuple)):
        raise _refused("Update rows must be a list", code="update-result")
    return rows


def check_update_row(row):
    """(result, category, group) of one update-result row: a result of pc_records.UPDATE_RESULTS, exactly its category and
    one of the five groups; any other row is refused."""
    if not isinstance(row, dict):
        raise _refused("An update result row must be a record", code="update-result")
    result, category, group = row.get("result"), row.get("category"), row.get("group")
    if (not isinstance(result, str) or result not in pc_records.UPDATE_RESULTS or category != pc_records.UPDATE_RESULTS[result]
            or not isinstance(group, str) or group not in pc_records.OUTCOME_GROUPS):
        raise _refused("An update result row names an unknown result, a category that is not its own, or an unknown group",
                       code="update-result")
    return result, category, group


def update_findings(rows):
    """Updates found, as the person reads them: one heading per group, in the five groups' order, each name through
    vendor_text with the words its flags call for. Update rows only; backup, cleanup and diagnosis keep their own wording."""
    grouped = {group: [] for group in pc_records.OUTCOME_GROUPS}
    for row in _rows(rows):
        group = row.get("group") if isinstance(row, dict) else None
        flags = row.get("flags", ()) if isinstance(row, dict) else None
        if not isinstance(group, str) or group not in grouped or not _flags(flags):
            raise _refused("An update finding names an unknown group or flag", code="update-result")
        words = [CHANGE_WORDS[flag] for flag in CHANGE_WORDS if flag in flags]
        grouped[group].append(vendor_text(row.get("name")) + (" (" + "; ".join(words) + ")" if words else ""))
    lines = [line for group in pc_records.OUTCOME_GROUPS if grouped[group]
             for line in (GROUP_LABELS[group] + ":", *("- " + item for item in grouped[group]))]
    return "\n".join(lines) or "Nothing to update was found in what was checked."


def update_summary(rows):
    """The summary of update results in the seven categories, in their order; a needs-a-check result is never counted as
    updated or as not updated, and adds what to do next."""
    named = {category: [] for category in pc_records.OUTCOME_CATEGORIES}
    for row in _rows(rows):
        named[check_update_row(row)[1]].append(vendor_text(row.get("name")))
    lines = [f"{CATEGORY_LABELS[category]}: {len(names)} ({', '.join(names)})"
             for category, names in named.items() if names]
    if named["needs_check"]:
        lines.append(NEEDS_CHECK)
    return "\n".join(lines) or "No update results were recorded."
