"""Deterministic PatchCairn conversation-session records. This module never executes a plan.

The caller is the trusted coordinator, not an untrusted JSON authority. An owner
quote records the actual human instruction supplied by that coordinator; it is
not cryptographic proof of a human and these helpers are not an OS sandbox.

WorkflowEngine is the facade over the engine modules. It owns the session Journal (engine_journal) and is the context
the other modules' functions receive: engine_text (the menu, the commands and the messages), engine_plans (scope,
evidence, plans, reviews and approvals), engine_operations, engine_restart, engine_updates, engine_recovery and
engine_schedule. Those functions reach the journal, the three seams (_change, which they call through change,
evidence_rows and read_session) and the families they do not import only through the engine's public attributes. Each
method here looks its engine function up when it is called and forwards its arguments unchanged, so a patch on the
engine module reaches it; replaced on an instance, only the three seams reach the engine's own calls. A patch
replacement must not call the facade method of the same name. Public names
such as journal, change, validate_state and outcome_rows are the engine modules' internal context, not an interface
for the coordinator, the service or the command-line tools. This module also keeps the names that the command-line
tools and the service import.
"""
from __future__ import annotations

import functools
import sys

sys.dont_write_bytecode = True  # before the engine modules load, as the command-line tools do

import engine_journal
import engine_operations
import engine_plans
import engine_recovery
import engine_restart
import engine_schedule
import engine_text
import engine_updates
from engine_journal import (BACKEND, DIAGNOSTIC_ADAPTER, EVIDENCE_MAX_BYTES, EVIDENCE_MAX_NODES, EXTERNAL_ADAPTER, EXTERNAL_PREFLIGHT,
                            EXTERNAL_RECEIPT, INSTALLER_METADATA, JOURNAL_MAX_BYTES, PUBLISHER_SIGNATURE, QUARANTINE_RECOVERY, RECORD_FIELDS,
                            RECOVERY_BINDING, RECOVERY_RETENTION, RESTART_PENDING, RESTART_VERIFICATION, SERVICE_RECORD, STORAGE_ADAPTER,
                            WINDOWS_BOOT, Journal, PrivacyCapabilityHold, WorkflowRefusal, atomic_replace, decode_record, exact_fields, no_links,
                            older_folder, older_format_message, read_record_bytes, record_identifier, typed_record, utc_time)
from engine_text import CHECKPOINTS, COMMANDS, JOBS, initial_menu, parse_command
from pc_records import SCHEMA_VERSION, digest, encoded


def _forward(function):
    """A method that calls the engine function of this name with this engine, looked up when it runs, and forwards its
    arguments unchanged (PD-17). If the method itself was assigned onto its module, it calls the original function."""
    module, name = function.__module__, function.__name__

    @functools.wraps(function)
    def method(self, *args, **kwargs):
        target = getattr(sys.modules[module], name)
        if getattr(target, "__func__", target) is method:
            target = function
        return target(self, *args, **kwargs)
    return method


def _static(function):
    """Like _forward, for an engine function that does not take the engine."""
    module, name = function.__module__, function.__name__

    @functools.wraps(function)
    def call(*args, **kwargs):
        target = getattr(sys.modules[module], name)
        if getattr(target, "__func__", target) is call:
            target = function
        return target(*args, **kwargs)
    return staticmethod(call)


class WorkflowEngine:
    """The conversation-session engine. Its sessions live under the repository's private ``work/`` folder."""

    def __init__(self, root=None, *, work_relative="work/sessions", backend=BACKEND, verify_artifact=None):
        """``verify_artifact(binding) -> None`` re-reads recovery and artifact bytes from disk and raises
        pc_records.Refusal when they changed or are missing. Only WorkflowService builds it (from storage); an
        engine without it holds every action that depends on recovery or artifact bytes."""
        engine_journal.admit_engine(backend, verify_artifact)
        self.verify_artifact = verify_artifact
        self.journal = Journal(root, work_relative, self.validate_state)

    @property
    def root(self):
        return self.journal.root

    @property
    def work(self):
        return self.journal.work

    @property
    def marker(self):
        return self.journal.marker

    def _change(self, session_id, event_type, mutate, expected_revision=None):
        """The one seam through which every session change is written."""
        state, message, data = self.journal.change(session_id, event_type, mutate, expected_revision)
        return engine_text.response(state, event_type, message, data)

    def change(self, session_id, event_type, mutate, expected_revision=None):
        """The engine modules' way into the _change seam, always with four positional arguments."""
        return self._change(session_id, event_type, mutate, expected_revision)

    def read_session(self, session_id):
        return self.journal.read(session_id)

    def _lock(self, session_id):
        return self.journal.lock(session_id)

    def _registry_lock(self):
        return self.journal.registry_lock()

    _outstanding_effects = _forward(engine_journal.outstanding_effects)

    # engine_text
    status = _forward(engine_text.status)
    cost = _forward(engine_text.cost)
    options = _forward(engine_text.options)
    dispatch = _forward(engine_text.dispatch)

    # engine_plans
    validate_state = _forward(engine_plans.validate_state)
    create_session = _forward(engine_plans.create_session)
    setup = _forward(engine_plans.setup)
    authorize_scope = _forward(engine_plans.authorize_scope)
    register_evidence = _forward(engine_plans.register_evidence)
    evidence_rows = _static(engine_plans.evidence_rows)
    _validate_plan_document = _static(engine_plans.validate_plan_document)
    action_binding = _forward(engine_plans.action_binding)
    register_plan = _forward(engine_plans.register_plan)
    current_plan = _static(engine_plans.current_plan)
    record_review = _forward(engine_plans.record_review)
    approve_plan = _forward(engine_plans.approve_plan)
    record_irreversible_ack = _forward(engine_plans.record_irreversible_ack)
    set_standing_policy = _forward(engine_plans.set_standing_policy)
    pending_items = _static(engine_plans.pending_items)
    advance_stage = _forward(engine_plans.advance_stage)
    resolve = _forward(engine_plans.resolve)
    complete_assessment = _forward(engine_plans.complete_assessment)

    # engine_operations
    begin_operation = _forward(engine_operations.begin_operation)
    outcome_rows = _forward(engine_operations.outcome_rows)
    finish_operation = _forward(engine_operations.finish_operation)
    pause = _forward(engine_operations.pause)
    resume = _forward(engine_operations.resume)
    stop = _forward(engine_operations.stop)

    # engine_restart
    record_restart_pending = _forward(engine_restart.record_restart_pending)
    decide_restart = _forward(engine_restart.decide_restart)
    validate_restart_verification = _forward(engine_restart.validate_restart_verification)
    record_restart_verification = _forward(engine_restart.record_restart_verification)

    # engine_updates
    validate_external_plan = _forward(engine_updates.validate_external_plan)
    external_preflight = _external_preflight = _forward(engine_updates.external_preflight)
    record_protected_consent = _forward(engine_updates.record_protected_consent)

    # engine_recovery
    reverify = _forward(engine_recovery.reverify)
    work_artifact = _forward(engine_recovery.work_artifact)
    verify_recovery = _forward(engine_recovery.verify_recovery)

    # engine_schedule
    schedule_identity = _static(engine_schedule.schedule_identity)
    require_schedule_activation = _static(engine_schedule.require_schedule_activation)
    configure_schedule = _forward(engine_schedule.configure_schedule)
    trigger_schedule = _forward(engine_schedule.trigger_schedule)
