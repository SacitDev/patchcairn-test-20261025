"""Selected synthetic work copies only. No host inventory, update or repair.

Service execution (scripts/service_execute.py): construction, the storage action, the approved binding,
execute_action, the dispatch tables over every adapter id and the composition of WorkflowService.
"""
from __future__ import annotations
import ast
import copy
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowEngine, WorkflowRefusal, digest
import diagnostic_core
import pc_records
from workflow_service import WorkflowService, ServiceRefusal, verify_storage_artifact
from storage_ops import StorageRefusal, StorageService
from scoped_fs import ScopedFSError
from private_workspace import PrivateWorkspaceError, ensure_private_directory, write_private_new
import scoped_base
import storage_contract
from storage_policy import MAX_FILE_BYTES
from service_execute import EXECUTE, STORAGE
from service_reconcile import RECONCILE
from test_service_state import ServiceFixtures, SessionFixtures, PROSE, PRIVATE_CAPABILITY_HOLDS, broad_namespace_fixture


class PauseBeforeEffectTests(ServiceFixtures):
    """Fictional service ordering only; no files, child process or adapter effect."""
    def test_pause_or_stop_after_intent_finishes_failed_before_any_storage_or_diagnostic_effect(self):
        # An owner pause or stop that lands between begin and the first effect finishes the consumed operation "failed":
        # _begin_adapter's stop response, never None, is what _run_adapter returns, with no effect boundary and no effect.
        # STORAGE ids whose family is not written yet hold in their target before anything begins (DispatchTests).
        written = [adapter_id for adapter_id in STORAGE if getattr(WorkflowService, EXECUTE[adapter_id]).__code__.co_names != ("_execute_held",)]
        for adapter_id in [*written, pc_records.ADAPTER_DIAGNOSTIC_COLLECT]:
            for status in ("paused", "stopped"):
                with self.subTest(adapter_id=adapter_id, status=status):
                    service, state, operation, events, written, arguments = self.prepared()
                    service.elevation_probe = lambda: False
                    arguments.pop("owner_consent_evidence_id")
                    action, payload = service._binding.return_value
                    action["adapter_id"] = adapter_id
                    payload.clear()
                    payload.update(operation=adapter_id, fictional=True)
                    storage = mock.MagicMock(name="storage")  # a backup target holds its storage service in a with statement
                    storage.__enter__.return_value = storage
                    service._storage_preconditions = mock.Mock(return_value=storage)
                    effect_name = "_effect_" + EXECUTE[adapter_id].removeprefix("_execute_")
                    effect = mock.Mock(name=effect_name)
                    setattr(service, effect_name, effect)
                    responses, begin = [], service._begin_adapter
                    def recorded_begin(*args, **kwargs):
                        responses.append(begin(*args, **kwargs))
                        return responses[-1]
                    service._begin_adapter = recorded_begin
                    def reread(*args, status=status):
                        events.append("status-" + str(service.engine.read_session.call_count))
                        state["status"] = status
                        return state
                    service.engine.read_session.side_effect = reread
                    result = service.execute_action(state["session_id"], **arguments)
                    self.assertEqual(events, ["begin-operation", "engine-preflight", "intent", "status-1", "finish"])
                    self.assertEqual(result, {"operation_id": operation["operation_id"], "outcome": "failed", "receipt": {
                        "adapter_invoked": False, "reason": "Owner pause/stop reached before the first adapter effect"}})
                    self.assertEqual(len(responses), 1)
                    self.assertIsNotNone(responses[0][3])
                    self.assertIs(result, responses[0][3])
                    effect.assert_not_called()
                    self.assertEqual(storage.method_calls, [])
                    self.assertEqual(set(written), {"intent.json"})
                    self.assertEqual(operation["outcome"], "failed")
                    if adapter_id in STORAGE:
                        service._storage_preconditions.assert_called_once_with(state, action, payload, diagnostic_fixture_runner=None,
                                                                               diagnostic_fixture_result=None)
                    else:
                        service._storage_preconditions.assert_not_called()


class BindingTests(ServiceFixtures):
    """Fictional service objects only; no files, engine or adapter effect."""
    HELD = ("service-refusal", "No fixed service adapter exists for this action")

    def test_binding_reaches_every_dispatch_target(self):
        # Every adapter id with an execute target passes the service's binding, and execute_action reaches the target with
        # the bound payload and its own arguments unchanged; an id outside EXECUTE keeps the refusal. Nothing begins here.
        service = object.__new__(WorkflowService)
        service._lock = mock.Mock(side_effect=nullcontext)
        state = {"status": "active", "stage": "apply"}
        service._state = mock.Mock(return_value=state)
        arguments = dict(action_id="dispatched", plan_sha256="a" * 64, precondition_evidence_ids=["proof"],
                         diagnostic_fixture_runner=None, diagnostic_fixture_result=None)
        for adapter_id in [*EXECUTE, "fixture.unlisted"]:
            payload = {"fictional_payload": adapter_id}
            action = {"action_id": "dispatched", "adapter_id": adapter_id, "adapter_payload_sha256": digest(payload)}
            service.engine = types.SimpleNamespace(pending_items=mock.Mock(return_value=[]), begin_operation=mock.Mock(),
                                                   current_plan=mock.Mock(return_value={"actions": [action]}),
                                                   action_binding=mock.Mock(return_value=payload))
            with self.subTest(adapter_id=adapter_id):
                if adapter_id in EXECUTE:
                    with mock.patch.object(service, EXECUTE[adapter_id], return_value="reached") as target:
                        try:
                            self.assertEqual(service.execute_action("session-fixture", **arguments), "reached")
                        except ServiceRefusal as error:
                            self.fail("the binding refused an id that has an execute target: " + str(error))
                    target.assert_called_once_with("session-fixture", state, action, payload, **arguments)
                else:
                    with self.assertRaises(ServiceRefusal) as caught:
                        service.execute_action("session-fixture", **arguments)
                    self.assertEqual((caught.exception.code, str(caught.exception)), self.HELD)
                service.engine.current_plan.assert_called_once_with(state, "a" * 64)
                service.engine.action_binding.assert_called_once_with(state, action)
                service.engine.begin_operation.assert_not_called()

    def test_run_effect_order_and_unknown_mapping(self):
        # _run_adapter: begin, intent, the session re-read, the engine's admission, the effect boundary (entered.json), then
        # the effect. A pause before the admission, or one the admission refuses, finishes "failed" with no boundary and no
        # effect; a listed failure after the boundary finishes "unknown" with a categorical receipt (no error text); any other
        # error propagates and records nothing.
        start = ["begin-operation", "engine-preflight", "intent", "status-1"]
        admitted = start + ["admit", "entered.json", "effect"]
        cases = (("succeeds", None, admitted),
                 ("refusal", pc_records.Refusal("fictional-code", "Fictional private detail"), admitted + ["status-2", "finish"]),
                 ("os-error", OSError(5, "Fictional private detail"), admitted + ["status-2", "finish"]),
                 ("other-error", KeyError("Fictional private detail"), admitted),
                 ("paused", None, start + ["finish"]),
                 ("admission-refused", None, start + ["admit", "status-2", "finish"]))
        for label, error, expected in cases:
            with self.subTest(case=label):
                service, state, operation, events, written, arguments = self.prepared()
                service.elevation_probe = lambda: False
                action, payload = service._binding.return_value

                def admit(session_id, *, operation_id):
                    events.append("admit")
                    self.assertEqual((session_id, operation_id), (state["session_id"], operation["operation_id"]))
                    if label == "admission-refused":
                        raise WorkflowRefusal("Fictional pause", code="effect-paused")
                service.engine.admit_effect = admit
                if label == "paused":
                    def reread(*args):
                        events.append("status-" + str(service.engine.read_session.call_count))
                        state["status"] = "paused"
                        return state
                    service.engine.read_session.side_effect = reread

                def effect(session_id, current, selected, bound_action, bound_payload, path, intent, **effect_arguments):
                    events.append("effect")
                    self.assertEqual((session_id, selected, bound_action, bound_payload, effect_arguments),
                                     (state["session_id"], operation, action, payload, {"fictional_argument": True}))
                    if error is not None:
                        raise error
                    return "effect-result"
                run = lambda: service._run_adapter(state["session_id"], state, action, payload, effect, fictional_argument=True, **arguments)
                if label == "other-error":
                    with self.assertRaises(KeyError):
                        run()
                else:
                    result = run()
                self.assertEqual(events, expected)
                if label in ("paused", "admission-refused"):
                    self.assertEqual((result["outcome"], result["receipt"]["adapter_invoked"]), ("failed", False))
                    self.assertNotIn("entered.json", written)
                    continue
                self.assertEqual(written["entered.json"]["kind"], "effect_boundary")
                self.assertEqual((written["entered.json"]["operation_id"], written["entered.json"]["adapter_id"]),
                                 (operation["operation_id"], action["adapter_id"]))
                if label == "succeeds":
                    self.assertEqual(result, "effect-result")
                elif label in ("refusal", "os-error"):
                    self.assertEqual(result["outcome"], "unknown")
                    self.assertEqual(result["receipt"], {
                        "adapter_invoked": True, "failure_class": type(error).__name__, "possible_partial_effects": True,
                        "failure_code": "fictional-code" if label == "refusal" else None,
                        "instruction": "Preserve exact intent, native attempt/mapping and outputs; inspect actual state before any new plan."})
                    self.assertNotIn("private", str(result))

    def test_a_paused_effect_finishes_with_the_caller_s_receipt_when_it_gives_one(self):
        for given, expected in (({"fictional_receipt": True}, {"fictional_receipt": True}),
                                (None, {"adapter_invoked": False, "reason": "Owner pause/stop reached before the first adapter effect"})):
            with self.subTest(given=given):
                service, state, operation, _events, written, _arguments = self.prepared()
                service.engine.admit_effect = mock.Mock(side_effect=WorkflowRefusal("Fictional pause", code="effect-paused"))
                effect = mock.Mock()
                result = service._run_effect("session-drain", state, operation, *service._binding.return_value, self.fixture_root(), {}, effect,
                                             paused_receipt=given, fictional_argument=True)
                self.assertEqual((result["outcome"], result["receipt"]), ("failed", expected))
                effect.assert_not_called()
                self.assertEqual(written, {})

    def test_an_admission_refused_for_any_other_reason_starts_nothing_and_finishes_nothing(self):
        # A closed step, or another writer holding the session lock: the refusal propagates, because no pause happened.
        for code in ("effect-closed", "workflow-refusal"):
            with self.subTest(code=code):
                service, state, _operation, events, written, arguments = self.prepared()
                service.elevation_probe = lambda: False
                action, payload = service._binding.return_value
                service.engine.admit_effect = mock.Mock(side_effect=WorkflowRefusal("Fictional refusal", code=code))
                effect = mock.Mock()
                with self.assertRaises(WorkflowRefusal) as caught:
                    service._run_adapter(state["session_id"], state, action, payload, effect, **arguments)
                self.assertEqual(caught.exception.code, code)
                effect.assert_not_called()
                self.assertNotIn("entered.json", written)
                self.assertNotIn("finish", events)


class AdmissionTests(SessionFixtures):
    """The engine's admission, driven through the real engine and service: nothing fakes the session it reads."""

    def requested_after_begin(self, request):
        """Run an approved backup with the owner's ``request`` landing after _begin_adapter read the session as active, so
        that only the admission can see it: nothing starts, and the operation finishes failed with no effect boundary."""
        action, _native = self.backup_action()
        sha = self.approve(action)
        begin = self.service._begin_adapter

        def requested(*args, **kwargs):
            begun = begin(*args, **kwargs)
            request(self.sid)
            return begun
        with mock.patch.object(self.service, "_begin_adapter", side_effect=requested), mock.patch.object(StorageService, "create_backup") as create:
            result = self.execute(action, sha)
        create.assert_not_called()
        self.assertEqual((result["outcome"], result["receipt"]["adapter_invoked"]), ("failed", False))
        (operation,) = self.state()["operations"].values()
        self.assertEqual(operation["outcome"], "failed")
        self.assertFalse((self.service._operation_dir(self.sid, operation["operation_id"]) / "entered.json").exists())

    def test_a_pause_after_begin_stops_the_effect_at_the_admission(self):
        self.requested_after_begin(self.engine.pause)
        self.assertEqual(self.state()["status"], "paused")

    def test_a_stop_after_begin_stops_the_effect_at_the_admission(self):
        self.requested_after_begin(self.engine.stop)
        self.assertEqual(self.state()["status"], "stopped")

    def test_an_admitted_effect_records_the_admission_before_its_boundary(self):
        action, _native = self.backup_action()
        sha = self.approve(action)
        seen = []
        immutable = self.service._immutable

        def boundary(path, value):
            if path.name == "entered.json":
                (operation,) = self.state()["operations"].values()
                seen.append(operation["authorization"].get("admitted_utc"))
            return immutable(path, value)
        with mock.patch.object(self.service, "_immutable", side_effect=boundary):
            self.assertEqual(self.execute(action, sha)["outcome"], "succeeded")
        self.assertEqual(len(seen), 1)
        self.assertIsNotNone(seen[0])

    def test_a_clock_step_back_after_begin_is_refused_as_a_clock_step(self):
        # The computer's clock moves back just after the backup begins, so the outcome PatchCairn stamps is earlier than
        # the start it stamped: the refusal names the clock step, and the step stays open to be checked.
        action, _native = self.backup_action()
        sha = self.approve(action)
        clock, begin, readings = pc_records.utc_now, self.engine.begin_operation, []

        def stepped_clock():
            if not readings:
                return clock()
            readings.append(readings[-1] + timedelta(microseconds=1))
            return readings[-1].isoformat(timespec="microseconds").replace("+00:00", "Z")

        def begin_then_step(*args, **kwargs):
            begun = begin(*args, **kwargs)
            # From here the clock reads 1 second before that start and moves on 1 microsecond a reading, however long the backup takes.
            readings.append(pc_records.parse_utc(begun["data"]["started_utc"]) - timedelta(seconds=1))
            return begun
        with mock.patch("pc_records.utc_now", side_effect=stepped_clock), mock.patch.object(self.engine, "begin_operation", side_effect=begin_then_step):
            with self.assertRaises(WorkflowRefusal) as caught:
                self.execute(action, sha)
        self.assertEqual((caught.exception.code, str(caught.exception)), ("clock-step", diagnostic_core.CLOCK_STEP_MESSAGE))
        (operation,) = self.state()["operations"].values()
        self.assertIsNone(operation["outcome"])
        # Observing again, with the clock right, settles the step from what the backup actually wrote.
        self.assertEqual(self.service.reconcile_operation(self.sid, operation_id=operation["operation_id"])["outcome"], "succeeded")


class PrepareTests(ServiceFixtures):
    """Fictional service objects: the payload prepare_storage_action builds; no files, engine or storage."""

    def prepared(self, adapter_id, plan):
        """(service, payload or None): prepare_storage_action with every dependency replaced by a mock."""
        service = object.__new__(WorkflowService)
        state = {"mode": "fixture"}
        service._lock, service._state = mock.Mock(side_effect=nullcontext), mock.Mock(return_value=state)
        service.protected_roots, service._storage = mock.Mock(return_value=[]), mock.Mock()
        service._action = mock.Mock(return_value={"action_id": "prepared", "recovery_evidence_ids": []})
        service.engine = types.SimpleNamespace(verify_recovery=mock.Mock(), read_session=mock.Mock(return_value=state))
        service.prepare_storage_action("session-fixture", action_id="prepared", adapter_id=adapter_id, storage_plan=plan,
                                       output_root=str(ROOT / "work" / "fictional-output"), **PROSE)
        return service._action.call_args.kwargs["payload"]

    def test_prepare_storage_action_fills_count_and_bytes_from_plan_rows(self):
        purge = {"kind": "purge", "receipt": {"records": [{"original": {"size": 5}}, {"original": {"size": 7}}]}}
        selected = {"kind": "delete_selected", "rows_file": {"row_count": 3, "row_bytes": 4096}}
        originals = {"kind": "remove_originals", "files": [{"size": 0}, {"size": 9}, {"size": 1}]}
        for adapter_id, plan, expected in ((pc_records.ADAPTER_STORAGE_PURGE, purge, (2, 12)), (pc_records.ADAPTER_STORAGE_DELETE_SELECTED, selected, (3, 4096)),
                                           (pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS, originals, (3, 10))):
            with self.subTest(adapter_id=adapter_id):
                payload = self.prepared(adapter_id, plan)
                self.assertEqual((payload["delete_count"], payload["delete_bytes"]), expected)
        self.assertFalse(storage_contract.DELETION_FIELDS & set(self.prepared(pc_records.ADAPTER_STORAGE_BACKUP_CREATE, {"kind": "backup", "files": [{"size": 5}]})))
        # A plan that lists nothing to delete, or no size for each item, is refused before anything is recorded.
        for plan in ({"kind": "purge", "receipt": {"records": []}}, {"kind": "purge", "receipt": {}}, {"kind": "remove_originals", "files": [{"name": "x"}]},
                     {"kind": "remove_originals", "files": [{"size": 1.5}]}, {"kind": "delete_selected", "rows_file": {"row_count": 0, "row_bytes": 0}},
                     {"kind": "delete_selected", "rows_file": {"row_count": 2, "row_bytes": -1}}, {"kind": "delete_selected", "rows_file": []}):
            with self.subTest(refused=plan), self.assertRaises(ServiceRefusal):
                self.prepared(pc_records.ADAPTER_STORAGE_PURGE if plan["kind"] == "purge" else
                              pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS if plan["kind"] == "remove_originals" else pc_records.ADAPTER_STORAGE_DELETE_SELECTED, plan)
        # At execution the payload's count and size must still be exactly the plan's.
        service = object.__new__(WorkflowService)
        for changes in ({"delete_count": 2, "delete_bytes": 0}, {"delete_count": 3, "delete_bytes": 12}, {}):
            payload = {"operation": pc_records.ADAPTER_STORAGE_PURGE, "mode": "fixture", "storage_plan": purge, **changes}
            with self.subTest(executed=changes), self.assertRaises(ServiceRefusal):
                WorkflowService._storage(service, {"mode": "fixture"}, payload)

    def test_chosen_destination_is_copied_into_the_payload_and_the_protected_roots(self):
        chosen = str(self.fixture_root() / "chosen-drive")
        backup = {"kind": "backup", "files": [{"size": 5}]}
        service = object.__new__(WorkflowService)
        state = {"mode": "fixture"}
        service._lock, service._state = mock.Mock(side_effect=nullcontext), mock.Mock(return_value=state)
        service.protected_roots, service._storage = mock.Mock(return_value=["fixture-root"]), mock.Mock()
        service._action = mock.Mock(return_value={"action_id": "prepared", "recovery_evidence_ids": []})
        service.prepare_storage_action("session-fixture", action_id="prepared", adapter_id=pc_records.ADAPTER_STORAGE_BACKUP_CREATE,
                                       storage_plan=backup, output_root=str(ROOT / "work" / "fictional-output"), backup_destination=chosen, **PROSE)
        payload = service._action.call_args.kwargs["payload"]
        self.assertEqual(payload["backup_destination"], chosen)
        self.assertEqual(payload["protected_roots"], sorted(["fixture-root", chosen]))
        self.assertNotIn("backup_destination", self.prepared(pc_records.ADAPTER_STORAGE_BACKUP_CREATE, backup))

    def test_storage_admits_the_chosen_destination_in_addition_to_the_owned_output(self):
        root = self.fixture_root()
        chosen, source = str(root / "work" / "chosen-drive"), str(root / "work" / "selected")
        service = object.__new__(WorkflowService)
        service.root = root
        service._owned = mock.Mock(side_effect=lambda value, **kwargs: Path(value))
        service.protected_roots, service._retention = mock.Mock(return_value=[]), mock.Mock(return_value=[])
        service._admit_backup_destination = mock.Mock(return_value="admitted-root")
        state = {"mode": "fixture", "platform": "windows", "settings": {"scope": {"roots": [source]}}}
        plan = {"kind": "backup", "inventory": {"roots": [{"path": source}]}}

        def payload(operation=pc_records.ADAPTER_STORAGE_BACKUP_CREATE, destination=chosen, protected=(chosen,)):
            return {"operation": operation, "storage_plan": plan, "storage_plan_sha256": digest(plan), "output_root": str(root / "work" / "output"),
                    "mode": "fixture", "protected_roots": list(protected), "backup_destination": destination}
        with mock.patch("service_execute.StorageService") as lower:
            self.assertIs(service._storage(state, payload()), lower.return_value)
            self.assertEqual(lower.call_args.kwargs["backup_destination"], "admitted-root")
            service._admit_backup_destination.assert_called_once_with(state, payload())
            service._owned.assert_any_call(str(root / "work" / "output"), state=state, existing=True)
            outside, inside = str(root / "chosen-drive"), str(root / "work" / "output" / "inside")
            for refused in (payload(protected=()), payload(destination=outside, protected=(outside,)), payload(destination=inside, protected=(inside,))):
                with self.subTest(refused=refused["backup_destination"]), self.assertRaises(ServiceRefusal):
                    service._storage(state, refused)
        self.assertEqual(service._admit_backup_destination.call_count, 1)

    def test_a_chosen_destination_is_told_apart_from_the_output_root_and_confined_in_a_fixture(self):
        # The one rule for a fixture's "other drive": below the work folder, apart from the output root. A real session's
        # is outside the work folder, on a drive with an identity.
        root = self.fixture_root()
        work, output = root / "work", root / "work" / "output"
        service = object.__new__(WorkflowService)
        service.root, service.volume_lookup = root, mock.Mock(return_value="fixture-volume")

        def payload(path):
            return {"backup_destination": str(path), "output_root": str(output)}
        self.assertIsNone(service._destination_root({"mode": "fixture"}, payload(work / "chosen-drive")))
        service.volume_lookup.assert_not_called()
        for refused in (root / "chosen-drive", output, output / "inside", work, work / "x" / ".." / "y"):
            with self.subTest(fixture=refused), self.assertRaises(ServiceRefusal):
                service._destination_root({"mode": "fixture"}, payload(refused))
        self.assertEqual(service._destination_root({"mode": "real"}, payload(root / "chosen-drive")), "fixture-volume")
        for refused in (work / "chosen-drive", output / "inside"):
            with self.subTest(real=refused), self.assertRaises(ServiceRefusal):
                service._destination_root({"mode": "real"}, payload(refused))

    def test_each_admitted_root_has_one_owner_that_closes_it(self):
        # prepare_storage_action closes the service it asked for on every path; _storage_preconditions closes it only when a
        # check fails, because otherwise the target that receives it does.
        backup = {"kind": "backup", "files": [{"size": 5}]}
        for failure in (None, StorageRefusal("Fictional precondition")):
            with self.subTest(prepare=failure):
                storage = mock.Mock(name="storage")
                storage.check_preconditions.side_effect = failure
                with mock.patch.object(WorkflowService, "_storage", return_value=storage), \
                        mock.patch.object(WorkflowService, "_action", return_value={"action_id": "prepared", "recovery_evidence_ids": []}):
                    service = object.__new__(WorkflowService)
                    state = {"mode": "fixture"}
                    service._lock, service._state = mock.Mock(side_effect=nullcontext), mock.Mock(return_value=state)
                    service.protected_roots = mock.Mock(return_value=[])
                    run = lambda: service.prepare_storage_action("session-fixture", action_id="prepared", adapter_id=pc_records.ADAPTER_STORAGE_BACKUP_CREATE,
                                                                 storage_plan=backup, output_root=str(ROOT / "work" / "fictional-output"), **PROSE)
                    if failure is None:
                        run()
                    else:
                        with self.assertRaises(StorageRefusal):
                            run()
                storage.close.assert_called_once_with()
            with self.subTest(preconditions=failure):
                storage = mock.Mock(name="storage")
                storage.check_preconditions.side_effect = failure
                service = object.__new__(WorkflowService)
                service._storage = mock.Mock(return_value=storage)
                action = {"adapter_id": pc_records.ADAPTER_STORAGE_BACKUP_CREATE}
                run = lambda: service._storage_preconditions({}, action, {"storage_plan": backup, "storage_plan_sha256": "a" * 64},
                                                             diagnostic_fixture_runner=None, diagnostic_fixture_result=None)
                if failure is None:
                    self.assertIs(run(), storage)
                    storage.close.assert_not_called()
                else:
                    with self.assertRaises(StorageRefusal):
                        run()
                    storage.close.assert_called_once_with()


class RestoreLimitTests(SessionFixtures):
    """The optional restore test restores in memory, so a backup above its limits is refused before anything begins, and
    never runs into the limit after the backup is written. Bounded: fictional files of at most 42 MiB, mostly zeros."""

    def planned(self, names, suffix):
        storage = self.storage()
        plan = storage.plan_backup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=names,
                                   destination=str(self.output / (suffix + ".zip")), content_read_authorized=True, required_recovery=True)
        return dict(action_id="backup-" + suffix, adapter_id="storage.backup_create", storage_plan=plan, output_root=str(self.output), **PROSE)

    def assert_refused_with_a_test_and_planned_without(self, names):
        with self.assertRaises(ServiceRefusal) as caught:
            self.service.prepare_storage_action(self.sid, restore_probe_destination=str(self.output / "large-probe"), **self.planned(names, "large"))
        self.assertEqual(caught.exception.code, "restore-size-unavailable")
        self.assertIn("without the restore test", str(caught.exception))
        self.assertEqual(self.state()["operations"], {})
        self.assertEqual(self.service.prepare_storage_action(self.sid, **self.planned(names, "no-test"))["action_id"], "backup-no-test")

    def test_one_file_above_the_restore_limit_is_refused_before_the_backup(self):
        write_private_new(self.source / "large.bin", bytes(MAX_FILE_BYTES + 1))
        self.assert_refused_with_a_test_and_planned_without(["r001/large.bin"])

    def test_an_archive_that_can_pass_the_restore_limit_is_refused_before_the_backup(self):
        size = 14 * 1024 * 1024
        for index in range(3):
            write_private_new(self.source / f"part-{index}.bin", bytes(size))
        self.assertLessEqual(size, MAX_FILE_BYTES)
        self.assertGreater(3 * size, scoped_base.MAX_CONTROL_BYTES)
        self.assert_refused_with_a_test_and_planned_without([f"r001/part-{index}.bin" for index in range(3)])

    def test_a_backup_within_the_limits_keeps_its_restore_test(self):
        action, _plan = self.backup_action(probe=True)
        self.assertEqual(action["action_id"], "backup-one")


class WorkflowServiceTests(SessionFixtures):
    def test_plan_A_cannot_execute_plan_B_wrong_roots_output_type_or_hash(self):
        action, native = self.backup_action()
        sha = self.approve(action)
        with self.assertRaises(WorkflowRefusal):
            self.service.execute_action(self.sid, action_id=action["action_id"], plan_sha256="f" * 64, precondition_evidence_ids=[])
        other = self.root / "work" / "other-output"
        other.mkdir()
        for adapter, plan, output in (("storage.purge", native, self.output),
                                      ("storage.backup_create", native, other)):
            with self.assertRaises((ServiceRefusal, StorageRefusal, ScopedFSError)):
                self.service.prepare_storage_action(self.sid, action_id="wrong-target", adapter_id=adapter,
                            storage_plan=plan, output_root=str(output), **PROSE)
        altered = copy.deepcopy(native)
        altered["inventory"]["roots"][0]["path"] = str(self.root / "work" / "other-source")
        with self.assertRaises((ServiceRefusal, StorageRefusal)):
            self.service.prepare_storage_action(self.sid, action_id="wrong-root", adapter_id="storage.backup_create", storage_plan=altered, output_root=str(self.output), **PROSE)
        self.assertEqual(self.state()["operations"], {})
        self.assertFalse((self.output / "one.zip").exists())

    def test_stale_content_stale_precondition_pause_settings_and_stop_block_new_effect(self):
        action, native = self.backup_action()
        sha = self.approve(action)
        stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        eid = self.precondition(action, sha, observed_utc=stale)
        with self.assertRaises(WorkflowRefusal):
            self.service.execute_action(self.sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[eid])
        self.engine.pause(self.sid)
        with self.assertRaises(ServiceRefusal):
            self.execute(action, sha)
        self.engine.setup(self.sid, control="automatic")
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.execute(action, sha)
        self.engine.stop(self.sid)
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.service.execute_action(self.sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[])
        self.assertEqual(self.state()["operations"], {})
        self.assertFalse((self.output / "one.zip").exists())

    def test_native_content_changes_hold_before_consuming_ticket(self):
        action, native = self.backup_action()
        sha = self.approve(action)
        (self.source / "example.txt").write_text("Changed after review", encoding="utf-8")
        with self.assertRaises((ServiceRefusal, StorageRefusal, ScopedFSError)):
            self.execute(action, sha)
        self.assertEqual(self.state()["operations"], {})

    def test_checkpoint_blocks_adapter_even_when_exact_plan_is_approved(self):
        self.engine.setup(self.sid, checkpoints=["before_action"])
        self.engine.authorize_scope(self.sid, owner_quote="Use this synthetic scope after checkpoint setting.", owner_message_id="scope-again")
        action, native = self.backup_action()
        sha = self.approve(action)
        self.assertEqual(self.state()["status"], "awaiting_user")
        with self.assertRaises(ServiceRefusal):
            self.execute(action, sha)
        self.assertFalse((self.output / "one.zip").exists())

    def test_backup_probe_whose_restore_paths_exceed_the_portable_limit_is_refused_before_the_backup(self):
        name = "n" * 96 + ".txt"
        write_private_new(self.source / name, b"Fictional long-named file.\n")
        storage = self.storage()
        plan = storage.plan_backup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/" + name],
                                   destination=str(self.output / "long.zip"), content_read_authorized=True, required_recovery=True)
        with self.assertRaises(ServiceRefusal) as caught:
            self.service.prepare_storage_action(self.sid, action_id="backup-long", adapter_id="storage.backup_create", storage_plan=plan,
                                                output_root=str(self.output), restore_probe_destination=str(self.output / ("probe-" + "x" * 92)), **PROSE)
        self.assertEqual(caught.exception.code, "path-too-long")
        self.assertFalse((self.output / "long.zip").exists())
        action = self.service.prepare_storage_action(self.sid, action_id="backup-long", adapter_id="storage.backup_create", storage_plan=plan,
                                                     output_root=str(self.output), restore_probe_destination=str(self.output / "p"), **PROSE)
        self.assertEqual(action["adapter_id"], "storage.backup_create")

    def test_service_supplies_storage_verifier(self):
        with mock.patch("service_execute.WorkflowEngine") as built:
            self.assertIs(WorkflowService.default_engine(), built.return_value)
        built.assert_called_once_with(verify_artifact=verify_storage_artifact)
        # A service built without an engine uses that default.
        with mock.patch.object(WorkflowService, "default_engine", return_value=self.engine) as default:
            self.assertIs(WorkflowService().engine, self.engine)
        default.assert_called_once_with()
        # An engine built elsewhere without a verifier gets the storage verifier; any other verifier is refused.
        bare = WorkflowEngine(self.root)
        self.assertIsNone(bare.verify_artifact)
        self.assertIs(WorkflowService(bare).engine.verify_artifact, verify_storage_artifact)
        with self.assertRaises(ServiceRefusal) as caught:
            WorkflowService(WorkflowEngine(self.root, verify_artifact=lambda binding: None))
        self.assertEqual(caught.exception.code, "verifier-contract")


class ServicePrivacyTests(ServiceFixtures):
    def test_namespace_refusal_precedes_marker_or_retention_write(self):
        root = self.fixture_root()
        with mock.patch("service_execute.ensure_private_directory", side_effect=PrivateWorkspaceError("fixture-private-hold")), mock.patch("service_state.publish_private_new") as writer:
            with self.assertRaises(PrivateWorkspaceError):
                WorkflowService(self.fake_engine(root))
            writer.assert_not_called()
        self.assertFalse(list(root.glob("**/*.json")))

    def test_existing_broad_service_namespace_refuses_without_acl_repair(self):
        root = self.fixture_root()
        namespace = root / "work" / "services"
        namespace.mkdir(parents=True)
        try:
            ensure_private_directory(namespace)
        except PrivateWorkspaceError as exc:
            if exc.code in PRIVATE_CAPABILITY_HOLDS - {"private-owner-or-mode-refused", "private-linux-foreign-filesystem"}:
                self.skipTest("only on posix: native private-ACL admission unavailable; refusal is covered separately")
            if exc.code not in {"private-owner-or-mode-refused", "private-dacl-unprotected", "private-dacl-broad-or-unknown", "private-linux-foreign-filesystem"}:
                raise
        else:
            broad_namespace_fixture(namespace)
        before = namespace.stat().st_mode
        with self.assertRaises(PrivateWorkspaceError):
            WorkflowService(self.fake_engine(root))
        self.assertEqual(namespace.stat().st_mode, before)
        self.assertFalse(list(root.glob("**/*.json")))

    def test_neutral_default_and_explicit_service_namespaces_do_not_adopt_old_records(self):
        root = self.fixture_root()
        try:
            old = WorkflowService(self.fake_engine(root), work_relative="work/service-previous")
        except PrivateWorkspaceError as exc:
            if os.name == "posix" and exc.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("only on posix: private namespace unavailable; native refusal covered separately")
            raise
        old_marker = (old.work / "service.json").read_bytes()
        current = WorkflowService(self.fake_engine(root))
        explicit = WorkflowService(self.fake_engine(root), work_relative="work/selected-service")
        self.assertEqual(current.work, root / "work/services")
        self.assertEqual(current.diagnostics.base, root / "work/services/diagnostics")
        self.assertEqual(explicit.work, root / "work/selected-service")
        self.assertEqual(WorkflowService(self.fake_engine(root), work_relative="work/service-previous").work, old.work)
        self.assertEqual((old.work / "service.json").read_bytes(), old_marker)
        self.assertNotEqual(current.work, old.work)

    def test_a_marker_without_the_integer_schema_version_or_with_another_binding_is_refused(self):
        root = self.fixture_root()
        try:
            marker = WorkflowService(self.fake_engine(root)).work / "service.json"
        except PrivateWorkspaceError as exc:
            if os.name == "posix" and exc.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("only on posix: private namespace unavailable; native refusal covered separately")
            raise
        good = json.loads(marker.read_bytes())
        WorkflowService(self.fake_engine(root))  # the marker as written is admitted again
        # True == 1 and 1.0 == 1 in Python, so these must be refused by the schema check, not by the comparison.
        cases = {"no schema_version": ({key: value for key, value in good.items() if key != "schema_version"}, "schema-version"),
                 "true": ({**good, "schema_version": True}, "schema-version"), "1.0": ({**good, "schema_version": 1.0}, "schema-version"),
                 "text": ({**good, "schema_version": "1"}, "schema-version"), "a later version": ({**good, "schema_version": 2}, "schema-version"),
                 "another schema": ({**good, "schema": "patchcairn.storage"}, "schema-name"),
                 "another kind": ({**good, "kind": "retention_registry"}, "service-refusal"),
                 "another engine": ({**good, "engine_id": "fictional-other-engine"}, "service-refusal")}
        for name, (value, code) in cases.items():
            with self.subTest(name):
                marker.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
                with self.assertRaises(ServiceRefusal) as caught:
                    WorkflowService(self.fake_engine(root))
                self.assertEqual(caught.exception.code, code)

    def test_read_only_cli_defaults_and_explicit_paths_bind_selected_namespaces(self):
        import patchcairn_service as cli
        for options, session_work, service_work in (
            ([], "work/sessions", "work/services"),
            (["--session-work", "work/selected-sessions", "--service-work", "work/selected-services"], "work/selected-sessions", "work/selected-services"),
        ):
            engine, service = mock.Mock(), mock.Mock()
            service.inspect_operation.return_value = {"operation": {"outcome": "unknown"}}
            with mock.patch.object(cli, "WorkflowEngine", return_value=engine) as engine_type, mock.patch.object(cli, "WorkflowService", return_value=service) as service_type, mock.patch("builtins.print"):
                self.assertEqual(cli.main(options + ["inspect-operation", "session-fixture", "operation-fixture"]), 0)
            engine_type.assert_called_once_with(work_relative=session_work)
            service_type.assert_called_once_with(engine, work_relative=service_work)
            service.inspect_operation.assert_called_once_with("session-fixture", operation_id="operation-fixture")
        with mock.patch.object(cli, "WorkflowEngine") as engine_type, mock.patch.object(cli, "WorkflowService") as service_type, mock.patch("builtins.print"):
            self.assertEqual(cli.main(["catalog"]), 0)
        engine_type.assert_not_called()
        service_type.assert_not_called()


class DispatchTests(SessionFixtures):
    def test_every_adapter_has_execute_and_reconcile(self):
        # Both tables name every adapter id; each target is a private WorkflowService method defined in
        # its family's module and looked up on the object; a target whose whole body is the held refusal holds before
        # anything is written or begun. The held set is read from the code, so a family leaf that writes a body drops out.
        modules = {"backup": "service_backup", "restore": "service_restore", "cleanup": "service_cleanup", "retention": "service_retention",
                   "update": "service_updates", "repair": "service_updates", "assessment": "service_diagnostics"}
        self.assertEqual(set(EXECUTE), set(pc_records.ADAPTERS))
        self.assertEqual(set(RECONCILE), set(pc_records.ADAPTERS))
        held = {}
        for table, kind in ((EXECUTE, "execute"), (RECONCILE, "reconcile")):
            methods = {adapter_id: getattr(WorkflowService, name) for adapter_id, name in table.items()}
            self.assertEqual(len({str(inspect.signature(method)) for method in methods.values()}), 1, kind + " signatures differ")
            for adapter_id, method in methods.items():
                with self.subTest(table=kind, adapter_id=adapter_id):
                    self.assertEqual(table[adapter_id], f"_{kind}_" + adapter_id.replace(".", "_"))
                    self.assertEqual(method.__name__, table[adapter_id])
                    self.assertEqual(method.__module__, modules[pc_records.ADAPTERS[adapter_id]["family"]])
            held[kind] = sorted(adapter_id for adapter_id, method in methods.items() if method.__code__.co_names == (f"_{kind}_held",))
        refusals = {"execute": "No fixed service adapter exists for this action",
                    "reconcile": "This step's outcome needs its own recorded evidence; nothing was changed"}
        state = self.state()
        files = sorted((path, path.stat().st_size) for path in self.root.rglob("*"))
        operation = {"operation_id": "held-operation", "action_id": "held-action", "plan_sha256": "a" * 64, "outcome": None}
        with mock.patch.object(self.engine, "begin_operation") as begin:
            for kind, call in (("execute", lambda adapter_id: getattr(self.service, EXECUTE[adapter_id])(
                                    self.sid, state, {"action_id": "held-action", "adapter_id": adapter_id}, {},
                                    action_id="held-action", plan_sha256="a" * 64, precondition_evidence_ids=[],
                                    owner_consent_evidence_id=None, diagnostic_fixture_runner=None, diagnostic_fixture_result=None)),
                               ("reconcile", lambda adapter_id: getattr(self.service, RECONCILE[adapter_id])(
                                    self.sid, operation, {"action": {"adapter_id": adapter_id}, "payload": {}}, {},
                                    operation_id=operation["operation_id"]))):
                for adapter_id in held[kind]:
                    with self.subTest(held=kind, adapter_id=adapter_id):
                        with self.assertRaises(ServiceRefusal) as caught:
                            call(adapter_id)
                        self.assertEqual((caught.exception.code, str(caught.exception)), ("service-refusal", refusals[kind]))
        begin.assert_not_called()
        self.assertEqual(self.state()["revision"], state["revision"])
        self.assertEqual(sorted((path, path.stat().st_size) for path in self.root.rglob("*")), files)
        # Dispatch looks the target up on the object, so a patch on the method intercepts it with the arguments forwarded
        # unchanged; an id outside a table keeps the same refusal, and no KeyError escapes either dispatch.
        service = object.__new__(WorkflowService)
        service.elevation_probe = lambda: False
        service._lock = mock.Mock(side_effect=nullcontext)
        service._state = mock.Mock(return_value={"status": "active", "stage": "apply"})
        service.engine = types.SimpleNamespace(pending_items=mock.Mock(return_value=False), begin_operation=mock.Mock())
        arguments = dict(action_id="dispatched", plan_sha256="a" * 64, precondition_evidence_ids=["proof"],
                         diagnostic_fixture_runner=None, diagnostic_fixture_result=None)
        # Ids that name a method of the service if a dispatch ever built names from ids instead of reading its table.
        for adapter_id in (pc_records.ADAPTER_STORAGE_BACKUP_CREATE, "fixture.unlisted", "_binding", "__init__", "storage"):
            action, payload = {"action_id": "dispatched", "adapter_id": adapter_id}, {"fictional": True}
            intent = {"action": action, "payload": payload}
            service._binding = mock.Mock(return_value=(action, payload))
            service.inspect_operation = mock.Mock(return_value={"operation": operation, "intent": intent})
            if adapter_id in EXECUTE:
                with mock.patch.object(service, EXECUTE[adapter_id], return_value="patched-execute") as target:
                    self.assertEqual(service.execute_action("session-fixture", **arguments), "patched-execute")
                target.assert_called_once_with("session-fixture", service._state.return_value, action, payload, **arguments)
                with mock.patch.object(service, RECONCILE[adapter_id], return_value="patched-reconcile") as target:
                    self.assertEqual(service.reconcile_operation("session-fixture", operation_id="dispatched"), "patched-reconcile")
                target.assert_called_once_with("session-fixture", operation, intent, payload, operation_id="dispatched")
                continue
            for kind, call in (("execute", lambda: service.execute_action("session-fixture", **arguments)),
                               ("reconcile", lambda: service.reconcile_operation("session-fixture", operation_id="dispatched"))):
                with self.subTest(unlisted=kind):
                    with self.assertRaises(ServiceRefusal) as caught:
                        call()
                    self.assertEqual(str(caught.exception), refusals[kind])
        service.engine.begin_operation.assert_not_called()

    def held_execution(self, action, sha):
        """Execute an approved action whose family is not written yet: the target's refusal, no begin, no file written."""
        proof = self.precondition(action, sha)
        with self.service._lock():  # the lock's own private file stays once it exists; it is no change of this action's
            pass

        def listing():
            return sorted((path, path.stat().st_size if path.is_file() else None) for path in self.root.rglob("*"))
        files, revision = listing(), self.state()["revision"]
        with mock.patch.object(self.engine, "begin_operation") as begin, self.assertRaises(ServiceRefusal) as caught:
            self.service.execute_action(self.sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[proof])
        self.assertEqual((caught.exception.code, str(caught.exception)), BindingTests.HELD)
        begin.assert_not_called()
        self.assertEqual(self.state()["revision"], revision)
        self.assertEqual(listing(), files)

    def test_unwritten_family_still_holds(self):
        # A real fixture.assessment action binds in the engine and in the service, then holds in its own target.
        inventory = {"fixture": True, "entries": [{"name": "fictional.data"}]}
        fixture_plan = {"fictional_assessment": True}
        payload = {"schema": "patchcairn.fixture.adapter", "schema_version": 1, "operation": pc_records.ADAPTER_FIXTURE_ASSESSMENT,
                   "fixture_plan": fixture_plan, "fixture_plan_sha256": digest(fixture_plan), "inventory_sha256": digest(inventory)}
        action = self.service._action(self.state(), action_id="fixture-assessment", adapter_id=payload["operation"], kind="assessment",
                                      payload=payload, native_plan=fixture_plan, inventory=inventory, **PROSE)
        self.held_execution(action, self.approve(action))

    def test_every_storage_plan_kind_binds_generically(self):
        # Every storage plan kind binds through the engine's one storage branch: a retention-forget plan registers and is
        # approved, and executing it is refused by the retention checks before anything begins, because the rows it
        # names are not the registry's. A release plan that lists no released rows cannot even be planned: its count
        # has no source to come from.
        records = {"fixture": True, "entries": [{"name": "fictional-kept-backup"}]}
        def action_for(adapter_id, kind, **deletion):
            plan = {"schema": "patchcairn.storage", "schema_version": 1, "kind": kind, "records": records, "fixture": True}
            payload = {"schema": "patchcairn.storage.adapter", "schema_version": 1, "operation": adapter_id, "storage_plan": plan,
                       "storage_plan_sha256": digest(plan), "output_root": str(self.service.work), "mode": "fixture",
                       "protected_roots": self.service.protected_roots(), **deletion}
            return self.service._action(self.state(), action_id="kept-" + kind.replace("_", "-"), adapter_id=adapter_id, kind=kind,
                                        payload=payload, native_plan=plan, inventory=records, **PROSE)
        release = action_for(pc_records.ADAPTER_STORAGE_RETENTION_RELEASE, "retention_release", delete_count=1, delete_bytes=0)
        with self.assertRaises(WorkflowRefusal) as caught:
            self.approve(release)
        self.assertEqual(caught.exception.code, "storage-payload")
        action = action_for(pc_records.ADAPTER_STORAGE_RETENTION_FORGET, "retention_forget")
        try:
            sha = self.approve(action)
        except WorkflowRefusal as error:
            self.fail("the retention-forget plan did not register: " + error.code)
        proof = self.precondition(action, sha)
        with mock.patch.object(self.engine, "begin_operation") as begin, self.assertRaises(ServiceRefusal) as caught:
            self.service.execute_action(self.sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[proof])
        self.assertEqual(caught.exception.code, "kept-rows-changed")
        begin.assert_not_called()
        self.assertEqual(self.state()["operations"], {})

    def test_storage_table_names_delete_selected_and_remove_originals(self):
        # Both permanent deletions have their storage rows (engine action kind, outcome-file name), so their family code
        # needs no edit here; until it is written, each target holds before anything begins.
        self.assertEqual(STORAGE.get(pc_records.ADAPTER_STORAGE_DELETE_SELECTED), ("delete_selected", "deletion"))
        self.assertEqual(STORAGE.get(pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS), ("remove_originals", "removal"))
        for adapter_id, (kind, _outcome) in STORAGE.items():
            with self.subTest(adapter_id=adapter_id):
                self.assertEqual(pc_records.ADAPTERS[adapter_id]["kinds"], (kind,))
                self.assertIn(adapter_id, storage_contract.PLAN_KINDS)
        self.assertEqual(len({outcome for _kind, outcome in STORAGE.values()}), len(STORAGE))
        state = self.state()
        for adapter_id in (pc_records.ADAPTER_STORAGE_DELETE_SELECTED, pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS):
            with self.subTest(held=adapter_id), mock.patch.object(self.engine, "begin_operation") as begin:
                with self.assertRaises(ServiceRefusal) as caught:
                    getattr(self.service, EXECUTE[adapter_id])(self.sid, state, {"action_id": "held", "adapter_id": adapter_id}, {}, action_id="held",
                                                               plan_sha256="a" * 64, precondition_evidence_ids=[], owner_consent_evidence_id=None,
                                                               diagnostic_fixture_runner=None, diagnostic_fixture_result=None)
                self.assertEqual((caught.exception.code, str(caught.exception)), BindingTests.HELD)
                begin.assert_not_called()


class OverlapTests(ServiceFixtures):
    """An overlap check in _storage: a path equal to a reserved quarantine output overlaps it (within is inclusive)."""

    def test_a_source_equal_to_a_reserved_quarantine_output_overlaps_it(self):
        root = self.fixture_root()
        reserved = root / "work" / "reserved"
        service = object.__new__(WorkflowService)
        service.root = root
        service._owned = mock.Mock(side_effect=lambda value, **kwargs: Path(value))
        service.protected_roots = mock.Mock(return_value=[])
        service._retention = mock.Mock(return_value=[{"quarantine_binding": {"output_root": str(root / "work" / "elsewhere")}}])
        state = {"mode": "fixture", "platform": "windows", "settings": {"scope": {"roots": [str(reserved)]}}}
        plan = {"kind": "backup", "inventory": {"roots": [{"path": str(reserved)}]}}
        payload = {"operation": pc_records.ADAPTER_STORAGE_BACKUP_CREATE, "storage_plan": plan, "storage_plan_sha256": digest(plan),
                   "output_root": str(root / "work" / "output"), "mode": "fixture", "protected_roots": []}
        with mock.patch("service_execute.StorageService") as lower:
            self.assertIs(service._storage(state, payload), lower.return_value)
            for output in (str(reserved), str(reserved / "inner")):
                service._retention.return_value = [{"quarantine_binding": {"output_root": output}}]
                with self.subTest(reserved=output), self.assertRaisesRegex(ServiceRefusal, "Reserved quarantine evidence"):
                    service._storage(state, payload)


class ElevationTests(SessionFixtures):
    """The elevation refusal with an injected probe, so it runs the same on every operating system."""

    def test_every_change_is_refused_while_elevated_and_assessment_is_not(self):
        service = object.__new__(WorkflowService)
        for answer in (True, None, 1):
            service.elevation_probe = mock.Mock(return_value=answer)
            for adapter_id, facts in pc_records.ADAPTERS.items():
                with self.subTest(answer=answer, adapter_id=adapter_id):
                    if facts["family"] == "assessment":
                        self.assertIsNone(service._refuse_while_elevated(adapter_id))
                    else:
                        with self.assertRaises(ServiceRefusal) as caught:
                            service._refuse_while_elevated(adapter_id)
                        self.assertEqual(caught.exception.code, "process-elevated")
        service.elevation_probe = mock.Mock(return_value=False)
        for adapter_id in pc_records.ADAPTERS:
            self.assertIsNone(service._refuse_while_elevated(adapter_id))

    def test_elevated_backup_is_refused_before_anything_begins(self):
        action, _native = self.backup_action()
        sha = self.approve(action)
        self.service.elevation_probe = mock.Mock(return_value=True)
        with mock.patch.object(self.engine, "begin_operation") as begin, self.assertRaises(ServiceRefusal) as caught:
            self.execute(action, sha)
        self.assertEqual(caught.exception.code, "process-elevated")
        begin.assert_not_called()
        self.assertEqual(self.state()["operations"], {})
        self.assertFalse((self.output / "one.zip").exists())
        self.service.elevation_probe = lambda: False
        self.assertEqual(self.execute(action, sha)["outcome"], "succeeded")

    def test_elevated_reconcile_of_a_retention_action_is_refused_before_it_reads_anything(self):
        service = object.__new__(WorkflowService)
        service.elevation_probe = mock.Mock(return_value=True)
        service.engine = types.SimpleNamespace(read_session=mock.Mock(side_effect=AssertionError("nothing is read while elevated")))
        for adapter_id in (pc_records.ADAPTER_STORAGE_RETENTION_RELEASE, pc_records.ADAPTER_STORAGE_SESSION_RELEASE,
                           pc_records.ADAPTER_STORAGE_RETENTION_FORGET):
            with self.subTest(adapter_id=adapter_id), self.assertRaises(ServiceRefusal) as caught:
                getattr(service, RECONCILE[adapter_id])("session-fixture", {"outcome": None}, {}, {"operation": adapter_id},
                                                        operation_id="operation-fixture")
            self.assertEqual(caught.exception.code, "process-elevated")

    def test_every_reconcile_target_that_can_change_anything_is_refused_while_elevated(self):
        # The shared reconcile path refuses before it enters any target but assessment's, on what the operation's own intent names.
        for adapter_id, name in RECONCILE.items():
            with self.subTest(adapter_id=adapter_id):
                service = object.__new__(WorkflowService)
                service.elevation_probe = mock.Mock(return_value=True)
                service._lock = lambda: nullcontext()
                intent = {"action": {"adapter_id": adapter_id}, "payload": {"operation": adapter_id}}
                service.inspect_operation = mock.Mock(return_value={"operation": {"outcome": None}, "intent": intent})
                target = mock.Mock(return_value="reconciled")
                setattr(service, name, target)
                if pc_records.ADAPTERS[adapter_id]["family"] == "assessment":
                    self.assertEqual(service.reconcile_operation("session-fixture", operation_id="operation-fixture"), "reconciled")
                else:
                    with self.assertRaises(ServiceRefusal) as caught:
                        service.reconcile_operation("session-fixture", operation_id="operation-fixture")
                    self.assertEqual(caught.exception.code, "process-elevated")
                    target.assert_not_called()

    def test_only_a_package_step_takes_a_tests_reconcile_fakes(self):
        # probe and reader reach the three package targets, as given; any other step refuses them before its target runs.
        package = {pc_records.ADAPTER_PACKAGE_UPGRADE, pc_records.ADAPTER_PACKAGE_REINSTALL, pc_records.ADAPTER_SYSTEM_REPAIR}
        fake_probe, fake_reader = object(), object()
        for adapter_id, name in RECONCILE.items():
            with self.subTest(adapter_id=adapter_id):
                service = object.__new__(WorkflowService)
                service.elevation_probe = mock.Mock(return_value=False)
                service._lock = lambda: nullcontext()
                intent = {"action": {"adapter_id": adapter_id}, "payload": {"operation": adapter_id}}
                service.inspect_operation = mock.Mock(return_value={"operation": {"outcome": None}, "intent": intent})
                target = mock.Mock(return_value="reconciled")
                setattr(service, name, target)
                if adapter_id in package:
                    self.assertEqual(service.reconcile_operation("session-fixture", operation_id="operation-fixture", probe=fake_probe,
                                                                 reader=fake_reader), "reconciled")
                    self.assertEqual(target.call_args.kwargs, {"operation_id": "operation-fixture", "probe": fake_probe, "reader": fake_reader})
                    continue
                for fakes in ({"probe": fake_probe}, {"reader": fake_reader}):
                    with self.assertRaises(ServiceRefusal) as caught:
                        service.reconcile_operation("session-fixture", operation_id="operation-fixture", **fakes)
                    self.assertEqual(caught.exception.code, "reconcile-fakes")
                target.assert_not_called()
                self.assertEqual(service.reconcile_operation("session-fixture", operation_id="operation-fixture"), "reconciled")

    def test_an_elevated_process_can_still_inspect_a_backup_it_may_not_settle(self):
        class Stopped(BaseException):
            pass
        action, _native = self.backup_action()
        sha = self.approve(action)
        with mock.patch.object(StorageService, "create_backup", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute(action, sha)
        (operation,) = self.state()["operations"].values()
        self.service.elevation_probe = mock.Mock(return_value=True)
        with mock.patch.object(StorageService, "settle_backup") as settle, self.assertRaises(ServiceRefusal) as caught:
            self.service.reconcile_operation(self.sid, operation_id=operation["operation_id"])
        self.assertEqual(caught.exception.code, "process-elevated")
        settle.assert_not_called()
        inspected = self.service.inspect_operation(self.sid, operation_id=operation["operation_id"])
        self.assertEqual(inspected["operation"]["operation_id"], operation["operation_id"])
        self.service.elevation_probe = lambda: False
        self.assertEqual(self.service.reconcile_operation(self.sid, operation_id=operation["operation_id"])["outcome"], "failed")

    def test_a_retired_adapter_id_counts_as_a_change(self):
        service = object.__new__(WorkflowService)
        service.elevation_probe = mock.Mock(return_value=True)
        with self.assertRaises(ServiceRefusal) as caught:
            service._refuse_while_elevated("system.fictional_retired_route")
        self.assertEqual(caught.exception.code, "process-elevated")

    def test_probe_is_a_constructor_keyword_kept_as_a_public_attribute(self):
        import scoped_fs
        probe = mock.Mock(return_value=False)
        self.assertIs(WorkflowService(self.engine, elevation_probe=probe).elevation_probe, probe)
        self.assertIs(WorkflowService(self.engine).elevation_probe, scoped_fs.process_is_elevated)
        with self.assertRaises(ServiceRefusal):
            WorkflowService(self.engine, elevation_probe=False)


class CliStartTests(ServiceFixtures):
    """patchcairn_service.py: the start check, the ticket line, the catalog and the read-only views."""

    def test_service_cli_refuses_without_isolated_flags(self):
        cli = str(ROOT / "scripts" / "patchcairn_service.py")
        # Bytes, not text: a child's console encoding is its own (the catalog's dash is not ASCII).
        for flags in ([], ["-I"], ["-S"]):
            with self.subTest(flags=flags):
                refused = subprocess.run([sys.executable, *flags, "-B", cli, "catalog"], capture_output=True, timeout=120, cwd=str(ROOT))
                self.assertEqual(refused.returncode, 2)
                self.assertEqual(refused.stdout, b"")
                self.assertIn(b"-I -S -B", refused.stderr)
        started = subprocess.run([sys.executable, "-I", "-S", "-B", cli, "catalog"], capture_output=True, timeout=120, cwd=str(ROOT))
        self.assertEqual((started.returncode, started.stderr), (0, b""))
        self.assertIn(b"Developed by Michael", started.stdout)
        source = (ROOT / "scripts" / "patchcairn_service.py").read_text(encoding="utf-8")
        main = ast.parse(source).body[-1]
        self.assertEqual(ast.unparse(main.test), "__name__ == '__main__'")
        self.assertEqual(ast.unparse(main.body[0].test), "not (sys.flags.isolated and sys.flags.no_site)")

    def test_run_ticket_line_calls_run_ticket_with_the_ticket(self):
        import patchcairn_service as cli
        with mock.patch.object(cli, "WorkflowEngine") as engine_type, mock.patch.object(WorkflowService, "__init__", return_value=None) as built, \
                mock.patch.object(WorkflowService, "run_ticket", create=True, return_value={"outcome": "succeeded", "receipt": {"result": "updated"}}) as run, \
                mock.patch("builtins.print") as shown:
            self.assertEqual(cli.main(["--service-work", "work/selected-services", "run", "--ticket", "ticket-fixture"]), 0)
        built.assert_called_once_with(engine_type.return_value, work_relative="work/selected-services")
        run.assert_called_once_with(ticket_id="ticket-fixture")
        self.assertIn("Updated; the new version was checked", shown.call_args.args[0])
        with mock.patch("builtins.print"), mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            cli.main(["run"])

    def test_catalog_names_the_ticket_launcher_and_no_installer_handoffs(self):
        import patchcairn_service as cli
        with mock.patch("builtins.print") as shown:
            self.assertEqual(cli.main(["--json", "catalog"]), 0)
        data = json.loads(shown.call_args.args[0])
        self.assertEqual(data["ticket_launcher"], "run --ticket")
        self.assertFalse({"external_handoff_catalog", "held_external_catalog", "external_execution"} & set(data))
        with mock.patch("builtins.print") as shown:
            cli.main(["catalog"])
        text = shown.call_args.args[0]
        self.assertIn("ticket-bound launcher", text)
        self.assertNotIn("handoff", text.lower())
        self.assertNotIn("assistant", text.lower())
        tree = ast.parse((ROOT / "scripts" / "patchcairn_service.py").read_text(encoding="utf-8"))
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(imported & {path.stem for path in (ROOT / "scripts").glob("*.py")}, {"workflow_core", "workflow_service", "storage_ops"})

    def test_report_and_retention_subcommands_are_views(self):
        import patchcairn_service as cli
        service = mock.Mock()
        service.session_report.return_value = ROOT / "work" / "services" / "reports" / "session-fixture-view.html"
        service.retention_rows.return_value = [{"name": "retention-fixture", "kind": "backup", "session_id": "session-fixture",
                                                "location": "fixture-location", "bytes": 2048, "created_utc": "2026-10-26T12:00:00Z",
                                                "volume_identity": None, "originals_removed": None},
                                               {"name": "retention-other", "kind": "reservation", "session_id": "session-fixture",
                                                "location": "other-location", "bytes": None, "created_utc": "2026-10-26T12:00:01Z",
                                                "volume_identity": None, "originals_removed": None}]
        with mock.patch.object(cli, "WorkflowEngine"), mock.patch.object(cli, "WorkflowService", return_value=service), \
                mock.patch("builtins.print") as shown:
            self.assertEqual(cli.main(["report", "session-fixture"]), 0)
            report = shown.call_args.args[0]
            self.assertEqual(cli.main(["retention"]), 0)
            listing = shown.call_args.args[0]
        service.session_report.assert_called_once_with("session-fixture")
        self.assertIn("a copy for reading, not evidence", report)
        self.assertIn("anyone who can edit the file can change it", report)
        self.assertIn("2,048 bytes", listing)
        self.assertIn("size not recorded", listing)
        self.assertIn("2 item(s), 2,048 bytes", listing)


class CompositionTests(ServiceFixtures):
    # The shared bodies a dispatch target may call; any other target is exactly the held refusal.
    SHARED = {"_run_adapter", "_begin_adapter", "_run_effect", "_reconcile_storage", "_reconcile_retention", "_reconcile_package"}

    def test_each_target_is_held_or_calls_a_shared_body(self):
        found = []
        for table, held in ((EXECUTE, "_execute_held"), (RECONCILE, "_reconcile_held")):
            for adapter_id, name in table.items():
                names = getattr(WorkflowService, name).__code__.co_names
                if names != (held,) and not self.SHARED & set(names):
                    found.append((adapter_id, name))
        self.assertEqual(found, [])

    def test_instance_attributes_and_mixins_do_not_shadow_methods(self):
        mixins = WorkflowService.__mro__[1:-1]
        for mixin in mixins:
            self.assertFalse({"__getattr__", "__getattribute__"} & set(vars(mixin)), mixin.__name__)
        root = self.fixture_root()
        try:
            service = WorkflowService(self.fake_engine(root))
        except PrivateWorkspaceError as exc:
            if os.name == "posix" and exc.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("only on posix: private namespace unavailable; native refusal covered separately")
            raise
        names = {name for mixin in mixins for name in vars(mixin)}
        self.assertTrue({"engine", "root", "work", "diagnostics", "elevation_probe", "volume_lookup"} <= set(vars(service)))
        self.assertEqual(set(vars(service)) & names, set())

    def test_mixins_define_disjoint_names_and_one_init(self):
        # WorkflowService is one class built from mixins, and a name defined twice resolves silently by
        # method order; so no two mixins share a non-dunder name, the composed class adds none of its own, and only
        # ExecuteMixin, which builds the service's state, defines __init__.
        mixins = WorkflowService.__mro__[1:-1]
        self.assertIs(WorkflowService.__mro__[-1], object)
        owners = {}
        for mixin in mixins:
            for name in vars(mixin):
                if not (name.startswith("__") and name.endswith("__")):
                    owners.setdefault(name, []).append(mixin.__name__)
        self.assertEqual({name: classes for name, classes in owners.items() if len(classes) > 1}, {})
        self.assertEqual([name for name in vars(WorkflowService) if not (name.startswith("__") and name.endswith("__"))], [])
        self.assertEqual([mixin.__name__ for mixin in mixins if "__init__" in vars(mixin)], ["ExecuteMixin"])

    def test_only_the_dispatch_reaches_the_targets(self):
        # The architecture check refuses service._x, not self._x inside a mixin. So no function names a target except through
        # the tables, only a target calls the shared steps that rely on execute_action's and reconcile_operation's checks
        # (_run_adapter is the begin step followed by the effect step), and each adapter's _effect_<id> is named only by its
        # own target.
        targets = set(EXECUTE.values()) | set(RECONCILE.values())
        execute = set(EXECUTE.values())
        # The package ticket run (UpdatesMixin.run_ticket) is the one other caller of _run_effect and of the effects of the
        # three adapters it starts: the two package adapters and the system repair.
        callers = {"_storage_preconditions": execute, "_run_adapter": execute, "_begin_adapter": execute | {"_run_adapter"},
                   "_run_effect": execute | {"_run_adapter", "run_ticket"}, "_reconcile_storage": set(RECONCILE.values()),
                   "_reconcile_retention": {RECONCILE[adapter_id] for adapter_id, facts in pc_records.ADAPTERS.items()
                                            if facts["family"] == "retention"}}
        ticketed = {EXECUTE[pc_records.ADAPTER_PACKAGE_UPGRADE], EXECUTE[pc_records.ADAPTER_PACKAGE_REINSTALL], EXECUTE[pc_records.ADAPTER_SYSTEM_REPAIR]}
        callers.update({"_effect_" + name.removeprefix("_execute_"): {name} | ({"run_ticket"} if name in ticketed else set()) for name in execute})
        found = []
        for path in sorted((ROOT / "scripts").glob("*.py")):
            for function in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # run_ticket counts only as UpdatesMixin's, in service_updates.py.
                    caller = function.name if function.name != "run_ticket" or path.name == "service_updates.py" else path.name + ":run_ticket"
                    for node in ast.walk(function):
                        if isinstance(node, ast.Attribute) and (node.attr in targets or caller not in callers.get(node.attr, {caller})):
                            found.append((path.name, node.lineno, function.name, node.attr))
                        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
                              and (node.value in targets or caller not in callers.get(node.value, {caller}))):
                            found.append((path.name, node.lineno, function.name, node.value))
        self.assertEqual(found, [])

    def test_storage_targets_run_their_preconditions_before_they_begin(self):
        # Each STORAGE target calls the storage preconditions itself (the exact storage binding, its live native content and a
        # purge's recovery), so a target that begins an operation, through _run_adapter or _begin_adapter, must first call
        # _storage_preconditions unconditionally: as the value of a statement of its own body, or the context of a with statement
        # there (which then closes the storage service it returns), before any statement that begins.
        names = {EXECUTE[adapter_id] for adapter_id in STORAGE}
        definitions = {}
        for path in sorted((ROOT / "scripts").glob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
                    definitions.setdefault(node.name, []).append(node)
        self.assertEqual({name: len(nodes) for name, nodes in definitions.items()}, dict.fromkeys(names, 1))

        def calls(node, name):
            return any(isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr == name for item in ast.walk(node))

        def flattened(body):
            for statement in body:
                if isinstance(statement, ast.With):
                    yield from (item.context_expr for item in statement.items)
                    yield from flattened(statement.body)
                else:
                    yield statement.value if isinstance(statement, (ast.Assign, ast.Expr)) else statement
        missing = []
        for name, (target,) in sorted(definitions.items()):
            statements = list(flattened(target.body))
            begins = [index for index, statement in enumerate(statements) if calls(statement, "_run_adapter") or calls(statement, "_begin_adapter")]
            checked = [index for index, statement in enumerate(statements) if isinstance(statement, ast.Call)
                       and isinstance(statement.func, ast.Attribute) and statement.func.attr == "_storage_preconditions"]
            if begins and not (checked and checked[0] < begins[0]):
                missing.append(name)
        self.assertEqual(missing, [])

    def test_effects_are_only_passed_to_the_shared_steps(self):
        # An effect runs only inside _run_effect, after the effect boundary (entered.json) and inside its failure mapping. So,
        # apart from its definition, an _effect_<id> appears only as the effect argument of a _run_adapter or _run_effect call:
        # never called directly, aliased or named by a string.
        found = []
        for path in sorted((ROOT / "scripts").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            passed = {id(argument) for node in ast.walk(tree)
                      if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"_run_adapter", "_run_effect"}
                      for argument in [*node.args, *(keyword.value for keyword in node.keywords if keyword.arg == "effect")]}
            for node in ast.walk(tree):
                name = (node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name)
                        else node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else "")
                if name.startswith("_effect_") and id(node) not in passed:
                    found.append((path.name, node.lineno, name))
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
