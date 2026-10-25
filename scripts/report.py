"""PatchCairn session report (layer L2; imports only the standard library, pc_records and pc_paths).

render_session(session, *, assessment=None, free_space=None, packages=None, retained=None) -> bytes renders one
session snapshot from WorkflowEngine.read_session as a UTF-8 HTML page built from templates/report.html. It is
pure: it reads only the template, writes nothing and starts no process, and the same input gives the same bytes
for the same Python version (pc_paths.display follows that version's Unicode tables). Every refusal is a
pc_records.Refusal: "report-input" for a malformed session or optional input, "report-template" for a missing or
changed template, "report-record" for a report record of the wrong layout, and the pc_records codes otherwise.

The page has a header (the session fields, two page notes and, for a fixture session, the fictional-demonstration
banner) and nine sections in this order: Scope, Findings, Plan, Assistant reviews of the plan, Approvals,
Outcomes, Free space, Package results and Recovery copies kept. Values are shown as recorded. A record the session
does not hold shows "not recorded"; an empty list inside a recorded record shows "None listed". Every owner
decision (scope, approvals, standing policy, checkpoint, reconciliation, protected-consent, assessment-completion,
schedule and restart decisions) and every review shows how it was recorded: "coordinator-attested" in words, "Not
stated" when the record carries no label, and any other label as "Unrecognised label: <label>". The full plan
fingerprint appears only under Plan; elsewhere a record is "Same as the plan above" or names an earlier plan by its
first eight characters. Each step shows who authorized it, and a step whose installer asked for a restart (code 3010)
shows that it is waiting for one until a boot is checked. The session's created_utc must be a UTC time (it dates the
page title) and its settings_revision must not be negative.

Optional inputs, each a closed key set (None or an empty list shows "not recorded"; malformed input is refused):
  assessment  the decoded patchcairn.assessment.summary record with exactly ASSESSMENT_KEYS. Its job, mode and
              scope_sha256 must equal the session's job, mode and pc_records.digest(settings.scope); its
              assessed_evidence_ids must be a non-empty list of evidence ids the session holds; its
              settings_revision may be lower than the session's (shown as such) but never higher.
  free_space  a list of rows {"volume": text, "before_bytes": int|None, "after_bytes": int|None,
              "expected_net_bytes": int|None}: free space measured on each drive before and after the work (never
              negative) and PatchCairn's computed net change, shown as the estimate; the measured change is after
              minus before and is "not recorded" unless both measurements are.
  packages    a list of rows {"manager": text, "package": text, "outcome": text, "restart": text}.
  retained    a list of rows {"kind": text, "location": text, "bytes": int|None} (bytes never negative).

Every shown value goes through pc_paths.display. Path values (scope roots, content sources, location and volume)
are split first, on backslash and slash for a Windows session and on slash otherwise, so a Windows path stays
readable while a control or bidirectional-control character inside a name is still escaped. Integers of 10**20
or more in magnitude are refused (pc_records' 20-digit bound). Sizes use decimal units (1 GB = 1,000,000,000
bytes) next to the exact byte count. The page data is one patchcairn.report record, passed through its registered
reader and embedded as pc_records.encoded bytes with <, > and & escaped, under a Content-Security-Policy that
admits only the template's one script and one style by their SHA-256 hashes.

The record holds schema, schema_version, generated_utc, title, banner (text or None), header and one key per
section. The header and each section are non-empty lists of blocks: ["heading", text], ["note", text] or
["fields", [[label, value], ...]]. Labels are fixed text; values, headings and notes are shown as they are.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re

import pc_paths
import pc_records

SCHEMA = "patchcairn.report"
SUMMARY = "patchcairn.assessment.summary"
TEMPLATE = Path(__file__).absolute().parent.parent / "templates" / "report.html"
# Each placeholder occurs once in the template; the data goes in last, so session text is never substituted.
SCRIPT_HASH, STYLE_HASH, DATA = "@@SCRIPT_SHA256@@", "@@STYLE_SHA256@@", "@@REPORT_DATA@@"
DATA_ELEMENT = '<script type="application/json" id="report-data">' + DATA + "</script>"
SECTIONS = ("scope", "findings", "plan", "reviews", "approvals", "outcomes", "free_space", "packages", "retained")
RECORD_KEYS = frozenset({"schema", "schema_version", "generated_utc", "title", "banner", "header", *SECTIONS})
# The engine's patchcairn.assessment.summary fields (workflow_core.RECORD_FIELDS), copied because this L2 module
# cannot import the engine; test_report.ReportTests.test_assessment_keys_match_engine_reader catches any drift.
ASSESSMENT_KEYS = frozenset({"schema", "schema_version", "job", "mode", "scope_sha256", "settings_revision", "summary",
                             "findings", "limitations", "assessed_evidence_ids"})
FREE_SPACE_KEYS = ("volume", "before_bytes", "after_bytes", "expected_net_bytes")
PACKAGE_KEYS = ("manager", "package", "outcome", "restart")
RETAINED_KEYS = ("kind", "location", "bytes")
MAX_INTEGER = 10 ** 20  # pc_records refuses integers of more than 20 digits
NOT_RECORDED = "not recorded"
NONE_LISTED = "None listed"
BANNER = ("FICTIONAL DEMONSTRATION. This is a practice session with made-up data. Its records do not establish that any "
          "computer was checked or changed.")
PAGE_NOTE = "This page lists only what was given to it. 'Not recorded' means no record of that item was available when this report was made."
TIME_NOTE = "All times are in UTC (Coordinated Universal Time), not your local clock time."
DECISIONS_NOTE = ("The AI assistant wrote these entries, quoting the owner's messages in the chat or terminal. This page cannot "
                  "show who typed those messages. To confirm a decision, find the quoted words in the conversation history.")
SCOPE_NOTE = "Written by the AI assistant from the owner's message; see the note under Approvals."
REVIEWS_NOTE = ("Reviews are checks of the plan made by AI assistant passes, not by a person or an outside company. "
                "'Approved' here means that pass found no reason to stop. It is not the owner's approval.")
ATTESTED = "coordinator-attested"
OWNER_ATTESTED = "Written by the assistant from the owner's message (coordinator-attested)"
REVIEW_ATTESTED = "Written by the assistant from an AI review pass (coordinator-attested)"
UNLABELLED = "Not stated: this record does not say how it was made."
UNRECOGNISED = "Unrecognised label: "
NO_FINDINGS = ("No problems are listed because none were recorded. That does not mean the computer has none: only what "
               "was checked could be found.")
EVIDENCE_HEADING = "Technical records (evidence)"
EVIDENCE_NOTE = ("Evidence records (technical detail): what the assistant saved while it worked, copied as written. This "
                 "page does not check them.")
PLAN_NOTE = ("The plan fingerprint changes if anything in the plan changes; the reviews and the approval refer to this "
             "exact plan.")
SAME_PLAN = "Same as the plan above"
NO_RESULT = ("No result recorded: this step started, but no result had been recorded when this report was made. It may "
             "still be running or may have stopped part-way. Ask the assistant (PatchCairn: status) before starting anything "
             "else on this computer.")
RESTART_WAITING = ("Waiting for a restart: the installer reported that the computer must restart to finish this step (code "
                   "3010). The step stays unfinished until the computer has restarted and the result is checked.")
RESTART_UNDECIDED = "Not decided yet. Tell the assistant whether to restart now or later (PatchCairn: resolve)."
OUTCOMES_NOTE = ("Results are shown as recorded. 'failed' means the step did not complete, 'partial' means only part of it "
                 "took effect, and 'unknown' means its effect could not be confirmed. After any of these, PatchCairn holds "
                 "further changes in this session until the result is reconciled: ask the assistant what changed and what "
                 "was kept (PatchCairn: status, then PatchCairn: resolve).")
EARLIER_PLAN_NOTE = ("Some steps belong to an earlier plan in this session. That plan, its reviews and its approval were "
                     "replaced by the plan above, so this page does not show them; each step still shows who authorized it.")
FREE_SPACE_NOTES = ("Free space was measured on each drive before and after the work. The measured change includes anything else "
                    "that used or freed space at the same time, such as downloads or system updates.",
                    "The expected change is PatchCairn's estimate: the size of the files removed minus the size of any backup "
                    "written to the same drive. Quarantine keeps files on the same drive so they can be put back, so it frees no "
                    "space there.",
                    "1 GB here is 1,000,000,000 bytes.")
EXPLORER_NOTE = " Windows File Explorer counts 1,073,741,824 bytes per GB, so it shows a slightly smaller number."
LLM_CONTENT_NONE = ("None listed. File names, folder names, sizes and other details from the allowed checks can still appear "
                    "in the chat with the assistant.")
RETAINED_NOTE = ("PatchCairn keeps these so a change can be undone or files restored. They use disk space until you decide "
                 "to release them. Ask your assistant before deleting any of them, because afterwards the change cannot be "
                 "undone.")
MODES = {"fixture": "practice with made-up data", "real": "a real computer"}
PLATFORMS = {"windows": "Windows", "macos": "macOS", "linux": "Linux", "unknown": "not stated"}
SOURCES = {"current_owner_chat": "the chat", "current_owner_terminal": "the terminal"}
ROLES = {"compatibility_data": "Compatibility and data safety", "evidence_security": "Evidence and security"}
VERDICTS = {"approved": "no reason to stop found", "hold": "a reason to stop was found"}
TARGETS = {"whole_device": "the whole computer", "selected_paths": "selected folders or files",
           "specific_problem": "one specific problem"}
OPERATIONS = {"metadata": "file and system details", "diagnosis": "problem diagnosis", "content_read": "reading selected file contents"}
RESTART_CHOICES = {"defer": "Restart later", "authorize": "Restart allowed; you restart the computer yourself"}
RESOLUTIONS = {"replan_required": "A new plan is needed before anything else changes",
               "effects_accounted": "What changed was accounted for after the session stopped"}
UNSETTLED = frozenset({"failed", "partial", "unknown"})
UNITS = (("PB", 10 ** 15), ("TB", 10 ** 12), ("GB", 10 ** 9), ("MB", 10 ** 6), ("KB", 10 ** 3))
EVIDENCE = (("Evidence", "evidence_id"), ("Kind", "kind"), ("Observed (UTC)", "observed_utc"))
ACTION_NAME = (("Action", "action_id"), ("Kind", "kind"))
ACTION_TEXT = (("Benefit", "benefit"), ("Risk", "risk"), ("How it can be undone", "reversibility"),
               ("How the result will be checked", "verification"))
# Owner decisions kept in pending items: the kind's name and where its owner record is (D-007 labels every one).
PENDING = {"checkpoint": "Go-ahead at a checkpoint", "reconciliation": "Choice after an unfinished step (reconciliation)",
           "protected_consent": "Operating-system permission prompt handled (protected consent)",
           "assessment_finish": "Assessment closed (assessment completion)"}


def _refused(message):
    return pc_records.Refusal("report-input", message)


def _value(record, key, kind, where, *, nullable=False):
    """``record[key]`` when it has the type ``kind`` (int means a true integer, never bool), else a typed refusal."""
    if not isinstance(record, dict) or key not in record:
        raise _refused(f"The {where} has no {key} field")
    value = record[key]
    if value is None and nullable:
        return None
    if (type(value) is not int) if kind is int else not isinstance(value, kind):
        raise _refused(f"The {where} field {key} has the wrong type")
    if kind is int and abs(value) >= MAX_INTEGER:
        raise _refused(f"The {where} field {key} is outside the 20-digit range")
    return value


def _optional(record, key, kind, where):
    """``record[key]`` checked as in _value when the field is present, else None."""
    if not isinstance(record, dict):
        raise _refused(f"The {where} must be a record")
    return _value(record, key, kind, where) if key in record else None


def _texts(record, key, where):
    values = _value(record, key, list, where)
    if not all(isinstance(value, str) for value in values):
        raise _refused(f"The {where} field {key} must be a list of text")
    return values


def _count(record, key, where):
    value = _value(record, key, int, where, nullable=True)
    if value is not None and value < 0:
        raise _refused(f"The {where} field {key} cannot be negative")
    return value


def _shown(text):
    """Text as the owner sees it: escaped, or "not recorded" when it is absent or blank."""
    return NOT_RECORDED if text is None or not text.strip() else pc_paths.display(text)


def _worded(text, words):
    """A recorded code in plain words with the code kept in brackets; an unknown code is shown as it is."""
    return f"{words[text]} ({pc_paths.display(text)})" if text in words else _shown(text)


def _path(text, windows):
    """A path shown part by part: the separators stay, each name between them is escaped."""
    if not text.strip():
        return NOT_RECORDED
    parts = re.split(r"([\\/])" if windows else r"(/)", text)
    return "".join(part if index % 2 else pc_paths.display(part) for index, part in enumerate(parts))


def _joined(values):
    return ", ".join(pc_paths.display(value) for value in values) if values else NONE_LISTED


def _joined_paths(values, windows):
    return ", ".join(_path(value, windows) for value in values) if values else NONE_LISTED


def _bytes(count):
    return "1 byte" if count == 1 else f"{count:,} bytes"


def _amount(size):
    """A non-negative byte count of at least 1,000 in decimal units, such as "about 11.8 GB"."""
    unit, scale = next((unit, scale) for unit, scale in UNITS if round(size / scale, 1) >= 1 or scale == 10 ** 3)
    return f"about {size / scale:.1f} {unit}"


def _size(size):
    if size is None:
        return NOT_RECORDED
    return _bytes(size) if size < 1000 else f"{_amount(size)} ({size:,} bytes)"


def _change(change):
    if change is None:
        return NOT_RECORDED
    if change == 0:
        return "No change"
    size, direction = abs(change), "more" if change > 0 else "less"
    return f"{_bytes(size)} {direction} free space" if size < 1000 else f"{_amount(size)} {direction} free space ({size:,} bytes)"


def _fact(key, value):
    text = value if isinstance(value, str) else pc_records.encoded(value).decode("ascii")
    return pc_paths.display(key) + ": " + pc_paths.display(text)


def _rows(record, where, labels):
    return [[label, _shown(_value(record, key, str, where))] for label, key in labels]


def _note(text):
    return ["note", text]


def _fields(pairs):
    return ["fields", pairs]


def _attestation(record, meaning, where):
    label = _optional(record, "attestation", str, where)
    if label is None:
        return UNLABELLED
    return meaning if label == ATTESTED else UNRECOGNISED + (pc_paths.display(label) if label.strip() else "(blank)")


def _decision(record, name, where, extra=()):
    """One owner decision: the quoted instruction, its message, where it was given, when, and how it was recorded."""
    return _fields([["Decision", name], ["Quoted instruction", _shown(_value(record, "quote", str, where))],
                    ["Message id", _shown(_value(record, "message_id", str, where))],
                    ["Given in", _worded(_value(record, "source", str, where), SOURCES)],
                    ["Recorded (UTC)", _shown(_value(record, "recorded_utc", str, where))], *extra,
                    ["How this was recorded", _attestation(record, OWNER_ATTESTED, where)]])


def _plan_hash(record, where, current):
    """The plan a record is bound to, compared with the current plan: the full fingerprint is shown only under Plan."""
    value = _value(record, "plan_sha256", str, where)
    if not value.strip():
        return ["Plan fingerprint", NOT_RECORDED]
    return ["Plan fingerprint", SAME_PLAN if value == current else "An earlier plan (fingerprint begins " + pc_paths.display(value[:8]) + ")"]


def _optional_rows(rows, keys, name):
    """The rows of an optional input; None and an empty list give no rows, and each row has exactly ``keys``."""
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(row, dict) and set(row) == set(keys) for row in rows):
        raise _refused(f"{name} must be a list of rows with exactly the keys " + ", ".join(keys))
    return rows


def _assessment(session, assessment, scope):
    """The checked assessment summary and the session's settings revision, or None without a summary."""
    if assessment is None:
        return None
    pc_records.require_schema(assessment, SUMMARY)
    if set(assessment) != ASSESSMENT_KEYS:
        raise _refused("The assessment summary has unexpected or missing fields")
    if (assessment["job"] != session["job"] or assessment["mode"] != session["mode"]
            or assessment["scope_sha256"] != pc_records.digest(scope)):
        raise _refused("The assessment summary belongs to another job, mode or scope")
    assessed, evidence = _texts(assessment, "assessed_evidence_ids", "assessment summary"), _value(session, "evidence", dict, "session")
    if not assessed or any(evidence_id not in evidence for evidence_id in assessed):
        raise _refused("The assessment summary must name evidence that this session holds")
    revision, current = _revision(assessment, "assessment summary"), _revision(session, "session")
    if revision > current:
        raise _refused("The assessment summary cannot come from a later settings revision than the session")
    return assessment, current


def _revision(record, where):
    value = _value(record, "settings_revision", int, where)
    if value < 0:
        raise _refused(f"The {where} field settings_revision cannot be negative")
    return value


def _access(access, windows):
    """The assessment access descriptor: what it covers, the allowed checks and each content selection."""
    where = "assessment access"
    rows = [["Assessment covers", _worded(_value(access, "target", str, where), TARGETS)],
            ["Allowed checks", ", ".join(_worded(name, OPERATIONS) for name in _texts(access, "operations", where)) or NONE_LISTED]]
    for selection in _value(access, "local_content", list, where):
        source = _value(selection, "source", str, "content selection")
        shown = _path(source, windows) if _value(selection, "kind", str, "content selection") == "path" else _shown(source)
        rows.append(["Content to read", _shown(_value(selection, "id", str, "content selection")) + ": " + shown + " ("
                     + _shown(_value(selection, "selection", str, "content selection")) + ")"])
    shared = _texts(access, "llm_content", where)
    return rows + [["Selected file contents the assistant may see", _joined(shared) if shared else LLM_CONTENT_NONE],
                   ["Selected files that may be read although they are normally private (sensitive exceptions)",
                    _joined(_texts(access, "sensitive_exceptions", where))]]


def _scope(session, scope, windows):
    roots = _texts(scope, "roots", "scope")
    selection = [["Purpose", _shown(_value(scope, "purpose", str, "scope"))]]
    selection += [["Selected folder or drive", _path(root, windows)] for root in roots] or [["Selected folders or drives", NONE_LISTED]]
    selection += _access(_value(scope, "assessment", dict, "scope"), windows) if "assessment" in scope else [["Assessment covers", NOT_RECORDED]]
    decision = _value(session, "scope_authorization", dict, "session", nullable=True)
    if decision is None:
        return [_fields(selection), _note("Scope decision: " + NOT_RECORDED + "."), _note(SCOPE_NOTE)]
    fingerprint = [["Scope fingerprint", _shown(_value(decision, "scope_sha256", str, "scope decision"))]]
    return [_fields(selection), _decision(decision, "Scope decision", "scope decision", fingerprint), _note(SCOPE_NOTE)]


def _findings(session, checked):
    blocks, findings = [["heading", "What was found"]], []
    if checked is None:
        blocks.append(_note("Assessment summary: " + NOT_RECORDED + "."))
    else:
        assessment, current = checked
        findings = _texts(assessment, "findings", "assessment summary")
        limitations = _texts(assessment, "limitations", "assessment summary")
        pairs = [["Summary", _shown(_value(assessment, "summary", str, "assessment summary"))],
                 *([["Problem found", _shown(text)] for text in findings] or [["Problems found", NONE_LISTED]]),
                 *([["Limitation", _shown(text)] for text in limitations] or [["Limitations", NONE_LISTED]])]
        if assessment["settings_revision"] < current:
            pairs.append(["Settings revision", f"Settings changed after this assessment (assessed at settings revision "
                                               f"{assessment['settings_revision']}, now revision {current}). The findings may "
                                               f"not match the current settings."])
        blocks.append(_fields(pairs))
    if not findings:
        blocks.append(_note(NO_FINDINGS))
    blocks += [["heading", EVIDENCE_HEADING], _note(EVIDENCE_NOTE)]
    rows = []
    for row in _value(session, "evidence", dict, "session").values():
        facts = _value(row, "facts", dict, "evidence row")
        if not all(isinstance(key, str) for key in facts):
            raise _refused("Evidence facts must have text keys")
        pairs = _rows(row, "evidence row", EVIDENCE) + ([["Recorded value", _fact(key, value)] for key, value in facts.items()]
                                                       or [["Recorded values", NONE_LISTED]])
        rows.append((pc_records.parse_utc(row["observed_utc"]), row["evidence_id"], pairs))
    blocks += [_fields(pairs) for _, _, pairs in sorted(rows, key=lambda entry: entry[:2])]
    return blocks if rows else blocks + [_note("Evidence: " + NOT_RECORDED + ".")]


def _plan(session, windows):
    plan = _value(session, "plan", dict, "session", nullable=True)
    if plan is None:
        return [_note("Not recorded.")]
    document = _value(plan, "document", dict, "plan")
    overview = (_rows(document, "plan", (("Plan", "plan_id"), ("Summary", "summary")))
                + _rows(plan, "plan", (("Plan fingerprint (SHA-256)", "sha256"), ("Registered (UTC)", "registered_utc"))))
    actions = [_fields(_rows(action, "plan action", ACTION_NAME) + [["Target", _path(_value(action, "target", str, "plan action"), windows)]]
                       + _rows(action, "plan action", ACTION_TEXT)) for action in _value(document, "actions", list, "plan")]
    return [_fields(overview), _note(PLAN_NOTE)] + actions


def _reviews(session, current):
    blocks = []
    for review in _value(session, "reviews", list, "session"):
        blocks.append(_fields([["Role", _worded(_value(review, "role", str, "review"), ROLES)],
                               ["Reviewer", _shown(_value(review, "reviewer_id", str, "review"))],
                               ["Review result", _worded(_value(review, "verdict", str, "review"), VERDICTS)],
                               _plan_hash(review, "review", current),
                               ["Recorded (UTC)", _shown(_value(review, "recorded_utc", str, "review"))],
                               ["How this was recorded", _attestation(review, REVIEW_ATTESTED, "review")]]))
    return ([_note(REVIEWS_NOTE)] + blocks) if blocks else [_note("Not recorded.")]


def _pending_decision(item, current):
    """(owner record, decision name, extra rows) of a pending item that holds an owner decision, else None."""
    kind = _value(item, "kind", str, "pending item")
    if kind == "checkpoint":
        # A checkpoint or reconciliation item carries the owner's record only once the owner has decided.
        action = _value(item, "action_id", str, "pending item", nullable=True)
        extra = [["Checkpoint", _shown(_value(item, "checkpoint", str, "pending item"))],
                 ["Action", "none (whole session)" if action is None else _shown(action)]]
        return _optional(item, "owner_instruction", dict, "pending item"), PENDING[kind], extra
    if kind == "reconciliation":
        extra = [["Operation", _shown(_value(item, "operation_id", str, "pending item"))]]
        return _optional(item, "owner_instruction", dict, "pending item"), PENDING[kind], extra
    if kind == "protected_consent":
        record = _value(item, "record", dict, "pending item")
        return record, PENDING[kind], [["Action", _shown(_value(record, "action_id", str, "protected consent"))],
                                       _plan_hash(record, "protected consent", current)]
    if kind == "assessment_finish":
        finish = _value(item, "record", dict, "pending item")
        extra = [["Summary evidence", _shown(_value(finish, "summary_evidence_id", str, "assessment completion"))]]
        return _value(finish, "owner_instruction", dict, "assessment completion"), PENDING[kind], extra
    record = _optional(item, "owner_instruction", dict, "pending item")
    if record is None:
        record = _optional(item, "record", dict, "pending item")
    return record, "Other owner decision (" + _shown(kind) + ")", []


def _other_decisions(session, current):
    """Owner decisions outside the three main records: pending items and restart decisions, each sorted by the
    recorded time text and then the key, and the schedule decision."""
    pending = []
    for key, item in _value(session, "pending", dict, "session").items():
        record, name, extra = _pending_decision(item, current)
        if record is not None:
            when = _value(record, "recorded_utc", str, name.lower())
            pending.append((when, key, _decision(record, name, name.lower(), extra)))
    blocks = [block for _, _, block in sorted(pending, key=lambda entry: entry[:2])]
    schedule = _value(session, "schedule", dict, "session", nullable=True)
    if schedule is not None:
        when = _value(_value(schedule, "proposal", dict, "schedule decision"), "when_utc", str, "schedule proposal")
        blocks.append(_decision(schedule, "Schedule decision", "schedule decision", [["Scheduled for (UTC)", _shown(when)]]))
    restarts = []
    for key, operation in _value(session, "operations", dict, "session").items():
        restart = _optional(operation, "restart_decision", dict, "operation")
        if restart is not None:
            where = "restart decision"
            restarts.append((_value(restart, "recorded_utc", str, where), key, _decision(restart, "Restart decision", where, [
                ["Choice", _worded(_value(restart, "choice", str, where), RESTART_CHOICES)],
                ["Operation", _shown(_value(restart, "operation_id", str, where))],
                ["Not before (UTC)", _shown(_value(restart, "not_before_utc", str, where))], _plan_hash(restart, where, current)])))
    return blocks + [block for _, _, block in sorted(restarts, key=lambda entry: entry[:2])]


def _approval_rows(record, where, current, windows):
    return [["Approved actions", _joined(_texts(record, "action_ids", where))], _plan_hash(record, where, current)]


def _ack_rows(record, where, current, windows):
    return [["Actions it covers", _joined(_texts(record, "action_ids", where))], _plan_hash(record, where, current)]


def _policy_rows(record, where, current, windows):
    return [["Kinds of step allowed", _joined(_texts(record, "action_kinds", where))],
            ["Targets", _joined_paths(_texts(record, "targets", where), windows)],
            ["Steps allowed", str(_value(record, "max_actions", int, where))], ["Steps used", str(_value(record, "used_actions", int, where))],
            ["Expires (UTC)", _shown(_value(record, "expires_utc", str, where))]]


def _approvals(session, current, windows):
    """The plan approval, the irreversible-loss acknowledgment and the standing policy, each in its place, then the
    other owner decisions."""
    blocks = [_note(DECISIONS_NOTE)]
    for key, name, where, rows in (
            ("approval", "Plan approval", "plan approval", _approval_rows),
            ("irreversible_ack", "Agreement to a permanent deletion (irreversible-loss acknowledgment)", "irreversible-loss acknowledgment", _ack_rows),
            ("standing_policy", "Standing permission for routine steps (standing policy)", "standing policy", _policy_rows)):
        record = _value(session, key, dict, "session", nullable=True)
        blocks.append(_note(name + ": " + NOT_RECORDED + ".") if record is None
                      else _decision(record, name, where, rows(record, where, current, windows)))
    return blocks + _other_decisions(session, current)


def _authorized(operation):
    """Who authorized a step, from the operation's authorization record."""
    authorization = _value(operation, "authorization", dict, "operation")
    if not authorization:
        return NOT_RECORDED
    kind = _value(authorization, "kind", str, "authorization")
    if kind not in ("exact_plan", "standing_policy"):
        return _shown(kind)
    message = _shown(_value(authorization, "message_id", str, "authorization"))
    return ("the plan approval" if kind == "exact_plan" else "the standing permission") + f" (message {message})"


def _restart(operation):
    """(result text or None, restart rows) for a step whose installer asked for a restart (code 3010)."""
    pending = _optional(operation, "restart_pending", dict, "operation")
    if not pending:
        return None, []
    verification = _optional(operation, "restart_verification", dict, "operation")
    decision = _optional(operation, "restart_decision", dict, "operation")
    choice = RESTART_UNDECIDED if decision is None else _worded(_value(decision, "choice", str, "restart decision"), RESTART_CHOICES)
    checked = verification is not None and verification.get("boot_observed") is True
    return (None if checked else RESTART_WAITING), [["Restart decision", choice]]


def _outcomes(session, current):
    rows, unsettled, earlier = [], False, False
    for operation in _value(session, "operations", dict, "session").values():
        outcome = _value(operation, "outcome", str, "operation", nullable=True)
        waiting, restart = _restart(operation)
        resolution = _value(operation, "resolution", dict, "operation", nullable=True)
        resolved = [["Resolution", NOT_RECORDED]] if resolution is None else [
            ["Resolution", _worded(_value(resolution, "kind", str, "resolution"), RESOLUTIONS)],
            ["Resolution recorded (UTC)", _shown(_value(resolution, "recorded_utc", str, "resolution"))]]
        fingerprint = _plan_hash(operation, "operation", current)
        pairs = (_rows(operation, "operation", (("Action", "action_id"),)) + [fingerprint, ["Authorized by", _authorized(operation)]]
                 + _rows(operation, "operation", (("Started (UTC)", "started_utc"),))
                 + [["Finished (UTC)", _shown(_value(operation, "finished_utc", str, "operation", nullable=True))],
                    ["Result", waiting or (NO_RESULT if outcome is None else _shown(outcome))], *restart,
                    ["Summary", _shown(_value(operation, "summary", str, "operation"))], *resolved])
        unsettled = unsettled or outcome is None or outcome in UNSETTLED or waiting is not None
        earlier = earlier or fingerprint[1] != SAME_PLAN
        rows.append((pc_records.parse_utc(operation["started_utc"]), _value(operation, "operation_id", str, "operation"), pairs))
    blocks = ([_note(OUTCOMES_NOTE)] if unsettled else []) + ([_note(EARLIER_PLAN_NOTE)] if earlier else [])
    blocks += [_fields(pairs) for _, _, pairs in sorted(rows, key=lambda entry: entry[:2])] or [_note("Not recorded.")]
    plan = _value(session, "plan", dict, "session", nullable=True)
    if plan is not None:
        done = {operation["action_id"] for operation in session["operations"].values()}  # each checked above
        planned = [_value(action, "action_id", str, "plan action") for action in _value(_value(plan, "document", dict, "plan"), "actions", list, "plan")]
        missing = [action_id for action_id in planned if action_id not in done]
        if missing:
            blocks.append(_note("Planned steps not started: " + _joined(missing) + ". They may still be waiting to run, or may have been skipped."))
    return blocks


def _free_space(rows, windows):
    blocks = []
    for row in _optional_rows(rows, FREE_SPACE_KEYS, "free_space"):
        volume = _path(_value(row, "volume", str, "free_space row"), windows)
        before, after = _count(row, "before_bytes", "free_space row"), _count(row, "after_bytes", "free_space row")
        expected = _value(row, "expected_net_bytes", int, "free_space row", nullable=True)
        blocks.append(_fields([["Drive", volume], ["Free space before", _size(before)], ["Free space after", _size(after)],
                               ["Measured change", _change(None if before is None or after is None else after - before)],
                               ["Expected change (estimate)", _change(expected)]]))
    if not blocks:
        return [_note("Not recorded.")]
    measured, estimate, units = FREE_SPACE_NOTES
    return [_note(measured), _note(estimate), _note(units + (EXPLORER_NOTE if windows else ""))] + blocks


def _packages(rows):
    labels = (("Manager", "manager"), ("Package", "package"), ("Result", "outcome"), ("Restart", "restart"))
    blocks = [_fields(_rows(row, "packages row", labels)) for row in _optional_rows(rows, PACKAGE_KEYS, "packages")]
    return blocks or [_note("Not recorded.")]


def _retained(rows, windows):
    blocks = [_fields([["Kind", _shown(_value(row, "kind", str, "retained row"))],
                       ["Location", _path(_value(row, "location", str, "retained row"), windows)],
                       ["Size", _size(_count(row, "bytes", "retained row"))]])
              for row in _optional_rows(rows, RETAINED_KEYS, "retained")]
    return ([_note(RETAINED_NOTE)] + blocks) if blocks else [_note("Not recorded.")]


def _laid_out(blocks):
    """True for a non-empty list of ["heading", text], ["note", text] or ["fields", [[label, value], ...]] blocks."""
    if not isinstance(blocks, list) or not blocks:
        return False
    for block in blocks:
        if not (isinstance(block, list) and len(block) == 2 and isinstance(block[0], str)):
            return False
        kind, content = block
        if kind in ("heading", "note"):
            if not (isinstance(content, str) and content.strip()):
                return False
        elif kind != "fields" or not (isinstance(content, list) and content and all(
                isinstance(pair, list) and len(pair) == 2 and all(isinstance(text, str) for text in pair) for pair in content)):
            return False
    return True


def read_report(record):
    """The registered reader of patchcairn.report records: the schema checks first, then the exact layout."""
    pc_records.require_schema(record, SCHEMA)
    if set(record) != RECORD_KEYS:
        raise pc_records.Refusal("report-record", "A report record has exactly its title, banner, header and nine section fields")
    pc_records.parse_utc(record["generated_utc"])
    if (not isinstance(record["title"], str) or not record["title"].strip()
            or not (record["banner"] is None or isinstance(record["banner"], str) and record["banner"].strip())
            or not all(_laid_out(record[key]) for key in ("header", *SECTIONS))):
        raise pc_records.Refusal("report-record", "A report title, banner, header or section is malformed or empty")
    return record


pc_records.register_reader(SCHEMA, read_report)


def _sha256(text):
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _template():
    try:
        # Text mode reads every line ending as LF, the form a browser hashes the inline program and style in.
        return TEMPLATE.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise pc_records.Refusal("report-template", "The report template cannot be read") from error


def _page(template, data):
    """The template with both CSP hashes filled in, then the escaped record data, as UTF-8 bytes."""
    programs = re.findall(r"<script>(.*?)</script>", template, re.S)
    styles = re.findall(r"<style>(.*?)</style>", template, re.S)
    if (len(programs) != 1 or len(styles) != 1 or template.count(DATA_ELEMENT) != 1
            or any(template.count(mark) != 1 for mark in (SCRIPT_HASH, STYLE_HASH, DATA)) or "@@" in programs[0] + styles[0]):
        raise pc_records.Refusal("report-template", "The report template does not have its expected layout")
    before, after = template.replace(SCRIPT_HASH, _sha256(programs[0])).replace(STYLE_HASH, _sha256(styles[0])).split(DATA)
    return (before + data + after).encode("utf-8")


def render_session(session, *, assessment=None, free_space=None, packages=None, retained=None):
    """The session report as UTF-8 HTML bytes (see the module docstring for the inputs); malformed input is refused."""
    pc_records.require_container(session, "session_state")
    scope = _value(_value(session, "settings", dict, "session"), "scope", dict, "settings")
    labels = (("Session", "session_id"), ("Job", "job"), ("Stage", "stage"), ("Status", "status"))
    header = _rows(session, "session", labels) + [
        ["Mode", _worded(_value(session, "mode", str, "session"), MODES)],
        ["Platform", _worded(_value(session, "platform", str, "session"), PLATFORMS)]]
    created = _value(session, "created_utc", str, "session")
    try:
        day = pc_records.parse_utc(created).date().isoformat()
    except pc_records.Refusal as error:
        raise _refused("The session field created_utc is not a UTC time") from error
    header += _rows(session, "session", (("Created (UTC)", "created_utc"), ("Last updated (UTC)", "updated_utc")))
    _revision(session, "session")
    windows = session["platform"] == "windows"
    plan = _value(session, "plan", dict, "session", nullable=True)
    current = None if plan is None else _value(plan, "sha256", str, "plan")
    generated = pc_records.utc_now()
    record = {"schema": SCHEMA, "schema_version": pc_records.SCHEMA_VERSION, "generated_utc": generated,
              "title": "PatchCairn session report: " + _shown(session["job"]) + ", created " + day,
              "banner": BANNER if session["mode"] == "fixture" else None,
              "header": [_fields(header + [["Report made (UTC)", _shown(generated)]]), _note(PAGE_NOTE), _note(TIME_NOTE)],
              "scope": _scope(session, scope, windows), "findings": _findings(session, _assessment(session, assessment, scope)),
              "plan": _plan(session, windows), "reviews": _reviews(session, current), "approvals": _approvals(session, current, windows),
              "outcomes": _outcomes(session, current), "free_space": _free_space(free_space, windows), "packages": _packages(packages),
              "retained": _retained(retained, windows)}
    data = pc_records.encoded(read_report(record)).decode("ascii")
    for char, escape in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026")):
        data = data.replace(char, escape)
    return _page(_template(), data)
