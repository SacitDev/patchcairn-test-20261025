"""Fixed adapter coordination; never executes a command from a payload.

The engine owns authority and canonical state. This service owns immutable
adapter intents and recovery retention, and calls only named library methods.
External official-tool actions remain a trusted assistant/host handoff.
"""
from __future__ import annotations

from diagnostic_core import DiagnosticRefusal
from service_state import ServiceRefusal, StateMixin, native_platform
from service_retention import RetentionMixin
from service_backup import BackupMixin, verify_storage_artifact
from service_restore import RestoreMixin
from service_cleanup import CleanupMixin
from service_diagnostics import DIAGNOSTIC_ADAPTER_ID, DiagnosticStore, DiagnosticsMixin
from service_updates import ARTIFACT_EXTENSIONS, OFFICIAL_DOMAINS, UpdatesMixin
from service_execute import STORAGE, ExecuteMixin
from service_reconcile import ReconcileMixin

__all__ = ["ARTIFACT_EXTENSIONS", "DIAGNOSTIC_ADAPTER_ID", "OFFICIAL_DOMAINS", "STORAGE", "DiagnosticRefusal", "DiagnosticStore",
           "ServiceRefusal", "WorkflowService", "native_platform", "verify_storage_artifact"]


class WorkflowService(ExecuteMixin, ReconcileMixin, StateMixin, RetentionMixin, BackupMixin, RestoreMixin, CleanupMixin,
                      DiagnosticsMixin, UpdatesMixin):
    """The one service class: each service module adds its methods as a mixin, and no two mixins define the same
    name. Construction is ExecuteMixin.__init__ (the engine, its storage verifier and the private service store)."""
