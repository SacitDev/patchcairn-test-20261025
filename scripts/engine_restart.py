"""Restart accounting for an update or repair step: the restart signal its route reported, which keeps the step open in
the restart class, and the observed boot after it, which releases it. PatchCairn never restarts the computer.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

from engine_journal import BOOT_OBSERVATION, WorkflowRefusal, decode_record, record_identifier, require_writable, typed_record, utc_time
from package_routes import RESTART_SIGNALS
import pc_records
from pc_records import digest

# Where a route can read its restart signal again: the reboot-required file, a manager's restart check or the Windows
# reboot-pending keys. A signal from any other source, such as an installer's exit code, is released only by a boot.
REREAD_SOURCES = frozenset({"linux.reboot_required", "apt.needrestart", "dnf.needs_restarting", "windows.reboot_pending"})


def _operation(state, operation_id, outcomes):
    """The unresolved operation ``operation_id`` whose outcome is in ``outcomes``; a stopped session still accounts for it."""
    if state["status"] != "stopped":
        require_writable(state)
    operation = state["operations"].get(operation_id)
    if not operation or operation["outcome"] not in outcomes or operation["resolution"]:
        raise WorkflowRefusal("Only this session's unfinished step can record its restart")
    return operation


def _boot(engine, state, row):
    """The checked boot observation in evidence ``row``."""
    data = engine.journal.read_owned(engine.journal.directory(state["session_id"]) / row["path"])
    if digest(data) != row["sha256"]:
        raise WorkflowRefusal("The boot observation bytes changed")
    boot = typed_record(decode_record(data), BOOT_OBSERVATION)
    if boot["observed_utc"] != row["observed_utc"] or utc_time(boot["last_boot_utc"]) > utc_time(boot["observed_utc"]):
        raise WorkflowRefusal("A boot observation must be one consistent reading", code="boot-inconsistent")
    record_identifier(boot["source"], "boot source")
    if boot["boot_id"] is not None:
        record_identifier(boot["boot_id"], "boot identifier")
    return boot


def _read_since(state, evidence_id, row):
    """True when another outcome row of the same step read the same place at the time of ``row`` or later."""
    observed, facts = utc_time(row["observed_utc"]), row["facts"]
    return any(key != evidence_id and item["kind"] == "outcome" and item["facts"].get("operation_id") == facts["operation_id"]
               and item["facts"].get("restart_source") == facts["restart_source"] and utc_time(item["observed_utc"]) >= observed
               for key, item in state["evidence"].items())


def _signal_rows(state, operation_id):
    """The outcome rows that read a restart signal as still set for this step. A reading names the place it was read from; a
    closing row's restart_signal only reports what its receipt said."""
    return [row for row in state["evidence"].values() if row["kind"] == "outcome" and row["facts"].get("operation_id") == operation_id
            and row["facts"].get("restart_signal", "none") != "none" and "restart_source" in row["facts"]]


def record_restart_pending(engine, session_id, *, operation_id, evidence_id, expected_revision=None):
    """Keep an open step open in the restart class. An outcome row of this step whose facts carry restart_signal (a
    package_routes.RESTART_SIGNALS value) and restart_source (where the route read it) becomes restart_pending =
    {"signal", "source"}. A later row read again from the same source in REREAD_SOURCES replaces it, and "none" there means
    the signal is gone; a reading older than another from that place changes nothing, so an old "none" never clears a newer
    requirement, and a signal from any other source is released only by record_boot_observation. The row carries
    boot_id, the boot this reading was taken in, where the computer has one: that binds the boot record_boot_observation
    must differ from."""
    record_identifier(operation_id)
    record_identifier(evidence_id)
    def mutate(state):
        operation = _operation(state, operation_id, {None})
        if operation.get("restart_verification"):
            raise WorkflowRefusal("The restart after this step is already observed; record the result of the check after it")
        row = engine.evidence_rows(state, [evidence_id], kinds={"outcome"}, after=operation["started_utc"], seconds=900)[0]
        facts = row["facts"]
        if any(facts.get(key) != operation[key] for key in ("operation_id", "action_id", "plan_sha256")):
            raise WorkflowRefusal("A restart signal must name this exact step, action and plan")
        record = {"signal": facts.get("restart_signal"), "source": facts.get("restart_source")}
        if record["signal"] not in RESTART_SIGNALS:
            raise WorkflowRefusal("A restart signal must be one that the update routes report")
        record_identifier(record["source"], "restart source")
        if facts.get("boot_id") is not None:
            record_identifier(facts["boot_id"], "boot identifier")
        existing = operation.get("restart_pending")
        if existing == record:
            return existing, "This restart signal is already recorded; nothing changed."
        if existing and (existing.get("source") != record["source"] or record["source"] not in REREAD_SOURCES):
            raise WorkflowRefusal("A recorded restart signal changes only when it is read again from the same place; a signal from an installer's exit "
                                  "code ends only with a restart", code="restart-signal-kept")
        if existing and _read_since(state, evidence_id, row):
            raise WorkflowRefusal("A newer reading of this restart signal already exists, so this older one changes nothing; read it again",
                                  code="restart-signal-kept")
        if not existing and record["signal"] == "none":
            raise WorkflowRefusal("No restart is waiting for this step; record its result instead")
        operation["restart_pending"] = record
        if record["signal"] == "none":
            return record, "The restart signal is gone when read again from the same place, so this step's result can now be checked."
        return record, ("This update needs a restart, and a check after it, before the rest can continue. PatchCairn never restarts the computer. "
                        "Until then this step stays open and is not run again, and only a backup can start.")
    return engine.change(session_id, "restart_pending", mutate, expected_revision)


def record_boot_observation(engine, session_id, *, operation_id, evidence_id, expected_revision=None):
    """Release a step's restart. An outcome row that names this exact step, action and plan and holds a
    patchcairn.boot.observation record (last_boot_utc, boot_id, observed_utc, source) whose boot is later than the step's
    start and every reading of its signal as set, with a boot_id none of those readings was taken in, sets restart_verification = {"boot_observed": True, "evidence_id", "sha256", "recorded_utc"}. A known
    boot_id is refused whatever time the record claims, and a reading without one where the step has one is held.
    finish_operation then records the step's result once. Once recorded, the same boot read again is a replay and changes
    nothing, and any other boot is refused."""
    record_identifier(operation_id)
    record_identifier(evidence_id)
    def mutate(state):
        operation = _operation(state, operation_id, {None, "unknown"})
        if not operation.get("restart_pending"):
            raise WorkflowRefusal("Only a step that waits for a restart takes a boot observation")
        existing = operation.get("restart_verification")
        replay = "This restart is already recorded; nothing changed."
        if existing and existing["evidence_id"] == evidence_id:
            return existing, replay
        row = engine.evidence_rows(state, [evidence_id], kinds={"outcome"}, after=operation["started_utc"], seconds=900)[0]
        if any(row["facts"].get(key) != operation[key] for key in ("operation_id", "action_id", "plan_sha256")):
            raise WorkflowRefusal("A boot observation must name this exact step, action and plan")
        boot = _boot(engine, state, row)
        last = utc_time(boot["last_boot_utc"])
        if existing:
            recorded = _boot(engine, state, state["evidence"][existing["evidence_id"]])
            if (utc_time(recorded["last_boot_utc"]), recorded["boot_id"]) != (last, boot["boot_id"]):
                raise WorkflowRefusal("A different restart is already recorded for this step", code="boot-conflict")
            return existing, replay
        signals = _signal_rows(state, operation_id)
        known = {item["facts"]["boot_id"] for item in signals if isinstance(item["facts"].get("boot_id"), str)}
        if (last <= utc_time(operation["started_utc"]) or boot["boot_id"] in known
                or any(last <= utc_time(item["observed_utc"]) for item in signals)):
            raise WorkflowRefusal("No restart after this step is observed yet: the computer has not started again since the step ran", code="no-later-boot")
        if known and boot["boot_id"] is None:
            raise WorkflowRefusal("This boot reading cannot be compared with the one taken when the step ran, so the restart stays unconfirmed",
                                  code="boot-inconsistent")
        record = {"boot_observed": True, "evidence_id": evidence_id, "sha256": row["sha256"], "recorded_utc": pc_records.utc_now()}
        operation["restart_verification"] = record
        return record, "The restart after this step is recorded. PatchCairn now checks what the restart finished and records the step's result."
    return engine.change(session_id, "boot_observed", mutate, expected_revision)
