"""Restore family: the dispatch and the effects of backup restoration and quarantine restoration (PLAN 3.3).

Both adapters run through the shared steps of service_execute and the shared storage reconciliation of
service_reconcile; B-RST replaces these bodies.
"""
from __future__ import annotations


class RestoreMixin:
    """The restore adapters' dispatch targets (service_execute.EXECUTE, service_reconcile.RECONCILE), reached only
    through execute_action and reconcile_operation after their lock, session and binding checks, and their effects."""

    def _execute_storage_restore(self, session_id, state, action, payload, **arguments):
        storage = self._storage_preconditions(state, action, payload, diagnostic_fixture_runner=arguments.pop("diagnostic_fixture_runner"),
                                              diagnostic_fixture_result=arguments.pop("diagnostic_fixture_result"))
        return self._run_adapter(session_id, state, action, payload, self._effect_storage_restore, storage=storage, **arguments)

    def _execute_storage_quarantine_restore(self, session_id, state, action, payload, **arguments):
        storage = self._storage_preconditions(state, action, payload, diagnostic_fixture_runner=arguments.pop("diagnostic_fixture_runner"),
                                              diagnostic_fixture_result=arguments.pop("diagnostic_fixture_result"))
        return self._run_adapter(session_id, state, action, payload, self._effect_storage_quarantine_restore, storage=storage, **arguments)

    def _effect_storage_restore(self, session_id, state, operation, action, payload, path, intent, *, storage):
        """The backup restoration, after the effect boundary (service_execute._run_effect)."""
        plan, expected = payload["storage_plan"], payload["storage_plan_sha256"]
        self._native_origin(state, operation, plan)
        receipt = storage.restore_backup(plan=plan, expected_plan_sha256=expected)
        verified = storage.verify_outcome(plan=plan, expected_plan_sha256=expected, receipt=receipt)
        result = {"native_receipt": receipt, "verification": verified}
        return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded", receipt=result)

    def _effect_storage_quarantine_restore(self, session_id, state, operation, action, payload, path, intent, *, storage):
        """The quarantine restoration, after the effect boundary (service_execute._run_effect)."""
        plan, expected = payload["storage_plan"], payload["storage_plan_sha256"]
        self._native_origin(state, operation, plan)
        receipt = storage.restore_quarantine(plan=plan, expected_plan_sha256=expected)
        verified = storage.verify_outcome(plan=plan, expected_plan_sha256=expected, receipt=receipt)
        result = {"native_receipt": receipt, "verification": verified}
        return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded", receipt=result)

    def _reconcile_storage_restore(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_storage(session_id, operation, intent, payload, **arguments)

    def _reconcile_storage_quarantine_restore(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_storage(session_id, operation, intent, payload, **arguments)
