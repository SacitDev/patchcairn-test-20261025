"""Restore family: the dispatch of backup restoration and quarantine restoration (PLAN 3.3).

Both adapters run through the shared storage path of service_execute and service_reconcile; B-RST replaces these
bodies.
"""
from __future__ import annotations


class RestoreMixin:
    """The restore adapters' dispatch targets (service_execute.EXECUTE, service_reconcile.RECONCILE), reached only
    through execute_action and reconcile_operation after their lock, session and binding checks."""

    def _execute_storage_restore(self, session_id, state, action, payload, **arguments):
        return self._run_fixed_adapter(session_id, state, action, payload, **arguments)

    def _execute_storage_quarantine_restore(self, session_id, state, action, payload, **arguments):
        return self._run_fixed_adapter(session_id, state, action, payload, **arguments)

    def _reconcile_storage_restore(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_storage(session_id, operation, intent, payload, **arguments)

    def _reconcile_storage_quarantine_restore(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_storage(session_id, operation, intent, payload, **arguments)
