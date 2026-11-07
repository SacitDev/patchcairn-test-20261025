"""Selected synthetic work copies only. No host inventory, update or repair.

Service state (scripts/service_state.py): the private store, intent, outcome and original authority.
Also the shared fixtures of every service test module: ServiceFixtures and SessionFixtures.
"""
from __future__ import annotations
import copy
from contextlib import nullcontext
import functools
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_records
from workflow_core import WorkflowEngine, WorkflowRefusal, PrivacyCapabilityHold, digest, encoded, report_labels
from clock_helpers import start_forward_only_clock, utc_now
from workflow_service import WorkflowService, ServiceRefusal, native_platform, verify_storage_artifact
from storage_ops import StorageService
from scoped_fs import ScopedFSError, ScopedRoot
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, write_private_new
from work_fixtures import PRIVATE_CAPABILITY_HOLDS, remove_tree

def broad_namespace_fixture(namespace):
    """Make a new fixture folder broad when this host created it private: POSIX mode 0755 (an attack fixture, never
    runtime remediation). A Windows folder that inherits a private DACL cannot be made broad without changing an ACL."""
    if os.name != "posix":
        raise AssertionError("The fixture parent already inherits a private DACL; no ACL is broadened for the test")
    namespace.chmod(0o755)
    try:
        ensure_private_directory(namespace)
    except PrivateWorkspaceError as exc:
        if exc.code != "private-owner-or-mode-refused":
            raise
    else:
        raise AssertionError("A 0755 folder was admitted as private")


PROSE = dict(target="Selected fictional file", benefit="Preserve selected example contents", risk="A synthetic file can change",
             reversibility="Keep exact required recovery and reviewed restore options", verification="Read the exact selected output and verify its content")


@functools.cache
def capability_probe():
    """(native_move_supported, private_hold) of this host, probed once per process for every SessionFixtures class.
    Capability probes only; a missing capability skips each test with a tagged reason."""
    native_move_supported, private_hold = True, None
    if os.name == "posix":
        probe = ROOT / "work" / ("sv-probe-" + uuid.uuid4().hex[:16])
        probe.mkdir(parents=True)
        try:
            WorkflowEngine(probe)
        except PrivacyCapabilityHold as exc:
            if exc.code not in PRIVATE_CAPABILITY_HOLDS:
                raise
            private_hold = str(exc)
            return native_move_supported, private_hold
        finally:
            remove_tree(probe)
        base = ROOT / "work" / ("sv-move-" + uuid.uuid4().hex)
        source, output = base / "source", base / "output"
        source.mkdir(parents=True); output.mkdir()
        try:
            (source / "fictional.txt").write_bytes(b"Fictional native capability probe only")
            with ScopedRoot(source, quiet_workspace=True) as src, ScopedRoot(output, quiet_workspace=True) as dst:
                expected = src.inspect("fictional.txt", hash_file=True, max_bytes=1024)
                src.move_to("fictional.txt", destination=dst, destination_relative="fictional.txt", expected=expected)
        except ScopedFSError as exc:
            if exc.code != "no-replace-unavailable":
                raise
            native_move_supported = False
        finally:
            remove_tree(base)
    return native_move_supported, private_hold


class ServiceFixtures(unittest.TestCase):
    """Shared helpers of the tests that build their own fictional service object; it defines no test."""
    def prepared(self, *, mode="fixture", platform="windows"):
        events, written = [], {}
        state = {"session_id": "session-drain", "mode": mode, "platform": platform,
                 "status": "active", "stage": "apply", "operations": {}}
        operation = {"operation_id": "operation-drain", "action_id": "action-drain",
                     "plan_sha256": "a" * 64, "outcome": None}
        action = {"action_id": operation["action_id"], "adapter_id": "system.repair",
                  "adapter_payload_sha256": "b" * 64, "requires_os_consent": True}
        payload = {"mode": mode, "platform": platform, "fictional": True}
        engine = types.SimpleNamespace(pending_items=mock.Mock(return_value=False))
        def begin(*args, **kwargs):
            events.extend(("begin-operation", "engine-preflight"))
            state["operations"][operation["operation_id"]] = operation
            return {"data": operation}
        engine.begin_operation = mock.Mock(side_effect=begin)
        def read(*args):
            events.append("status-" + str(engine.read_session.call_count))
            return state
        engine.read_session = mock.Mock(side_effect=read)
        service = object.__new__(WorkflowService)
        service.engine = engine
        service._lock = lambda: nullcontext()
        service._state = mock.Mock(return_value=state)
        service._binding = mock.Mock(return_value=(action, payload))
        directory = ROOT / "work" / "fictional-drain" / operation["operation_id"]
        def intent(*args):
            events.append("intent")
            value = copy.deepcopy({"operation": operation, "action": action, "payload": payload})
            written["intent.json"] = value
            return directory, value
        service._intent = mock.Mock(side_effect=intent)
        def immutable(path, value):
            events.append(path.name)
            self.assertNotIn(path.name, written)
            written[path.name] = copy.deepcopy(value)
        service._immutable = mock.Mock(side_effect=immutable)
        def finish(current, selected, *, outcome, receipt):
            events.append("finish")
            selected["outcome"] = outcome
            if current["status"] == "active":
                current["status"] = "held"
            return {"operation_id": selected["operation_id"], "outcome": outcome, "receipt": receipt}
        service._finish = mock.Mock(side_effect=finish)
        arguments = dict(action_id=action["action_id"], plan_sha256=operation["plan_sha256"],
                         precondition_evidence_ids=["fictional-proof"], owner_consent_evidence_id="fictional-consent")
        return service, state, operation, events, written, arguments

    def fixture_root(self):
        root = ROOT / "work" / ("sv-private-" + uuid.uuid4().hex[:16])
        root.mkdir(parents=True)
        self.addCleanup(remove_tree, root)
        return root

    @staticmethod
    def fake_engine(root):
        return types.SimpleNamespace(root=root, marker={"engine_id": "fictional-private-test", "backend": "patchcairn.workflow.python"}, verify_artifact=verify_storage_artifact)


class SessionFixtures(ServiceFixtures):
    """A fictional engine, service and authorized session for each test; it defines no test."""
    @classmethod
    def setUpClass(cls):
        cls.native_move_supported, cls.private_hold = capability_probe()

    def setUp(self):
        if self.private_hold:
            self.skipTest("only on posix: the selected filesystem cannot enforce new private engine namespaces: " + self.private_hold)
        self.root = ROOT / "work" / ("sv-" + uuid.uuid4().hex[:16])
        self.source = self.root / "work" / "selected"
        self.output = self.root / "work" / "artifacts"
        ensure_private_directory(self.source, create=True, parents=True)
        self.addCleanup(remove_tree, self.root)
        ensure_private_directory(self.output, create=True)
        write_private_new(self.source / "example.txt", b"Fictional selected file; no host content.\n")
        start_forward_only_clock(self)
        self.engine = WorkflowEngine(self.root, verify_artifact=verify_storage_artifact)
        self.service = WorkflowService(self.engine, elevation_probe=lambda: False)
        self.scope = {"roots": [str(self.source)], "purpose": "Selected synthetic fixture only"}
        self.sid = self.session()
        self.counter = 0

    def session(self, job="backup_recovery", platform=None):
        sid = self.engine.create_session(job=job, platform=platform or native_platform(), mode="fixture", scope=self.scope, checkpoints=[])["session_id"]
        self.engine.authorize_scope(sid, owner_quote="Use only this selected synthetic folder.", owner_message_id="fictional-scope-" + uuid.uuid4().hex)
        return sid

    def state(self, sid=None):
        return self.engine.read_session(sid or self.sid)

    def evidence(self, kind, facts=None, *, sid=None, content=None, observed_utc=None):
        self.counter += 1
        return self.engine.register_evidence(sid or self.sid, evidence_id="fixture-evidence-" + str(self.counter),
                    content=content or encoded({"fictional": True, "facts": facts or {}}), kind=kind,
                    scope=self.scope, facts=facts or {}, observed_utc=observed_utc)["data"]["evidence_id"]

    def storage(self):
        return StorageService(output_root=str(self.output), quiet_workspace=True, protected_roots=self.service.protected_roots())

    def backup_action(self, *, sid=None, probe=False, suffix="one"):
        storage = self.storage()
        inventory = storage.assess_storage(roots=[str(self.source)])
        plan = storage.plan_backup(inventory=inventory, selected=["r001/example.txt"],
                    destination=str(self.output / (suffix + ".zip")), content_read_authorized=True, required_recovery=True)
        return self.service.prepare_storage_action(sid or self.sid, action_id="backup-" + suffix,
                    adapter_id="storage.backup_create", storage_plan=plan, output_root=str(self.output),
                    restore_probe_destination=str(self.output / (suffix + "-probe")) if probe else None, **PROSE), plan

    def approve(self, action, *, sid=None, purge_choice=False, ack=False):
        sid = sid or self.sid
        required = {"scope": ("scope_confirmation", {"scope_confirmed": True}),
                    "inventory": ("inventory", {"complete": True, "item_count": 1}),
                    "research": ("research", {"applicability_checked": True, "official_sources_checked": True}),
                    "candidates": ("candidates", {"candidates_reviewed": True, "excluded_private": True}),
                    "symptom": ("symptom", {"symptom_recorded": True, "relevant_scope": True}),
                    "hypotheses": ("hypotheses", {"alternatives_considered": True, "distinguishing_checks": True}),
                    "recovery_plan": ("recovery_plan", {"contents_reviewed": True, "restore_check_planned": True, "exclusions_explicit": True})}
        while self.state(sid)["stage"] != "plan":
            kind, facts = required[self.state(sid)["stage"]]
            self.engine.advance_stage(sid, evidence_ids=[self.evidence(kind, facts, sid=sid)])
        plan = {"plan_id": "plan-" + uuid.uuid4().hex, "summary": "Exact synthetic reviewed adapter plan",
                "evidence_ids": [action["target_inventory_evidence_id"]], "actions": [action]}
        sha = self.engine.register_plan(sid, plan=plan)["data"]["plan_sha256"]
        for reviewer, role in (("fixture-reviewer-data", "compatibility_data"), ("fixture-reviewer-security", "evidence_security")):
            review = {"schema": "patchcairn.review", "schema_version": 1, "plan_sha256": sha, "role": role, "verdict": "approved",
                      "reviewer_id": reviewer, "attestation": "coordinator-attested"}
            self.engine.record_review(sid, plan_sha256=sha, reviewer_id=reviewer, role=role, verdict="approved",
                        evidence_ids=[self.evidence("review", {"reviewed": True}, sid=sid, content=encoded(review))], notes="Independent synthetic review of this exact bounded plan")
        quote, message_id = "Apply only this exact synthetic action.", "fixture-plan-choice-" + uuid.uuid4().hex
        if purge_choice:
            # A permanent deletion is approved by the owner's typed reply to the engine's warning, in a message never used before.
            quote, message_id = self.engine.issue_irreversible_warning(sid, plan_sha256=sha)["data"]["phrase"], "fixture-typed-reply-" + uuid.uuid4().hex
        self.engine.approve_plan(sid, plan_sha256=sha, action_ids=[action["action_id"]], owner_quote=quote, owner_message_id=message_id)
        if ack:
            self.engine.record_irreversible_ack(sid, plan_sha256=sha, action_ids=[action["action_id"]],
                        acknowledge_irreversible_loss=True, owner_quote="I acknowledge the separate risk of these exact fictional actions.", owner_message_id="fixture-loss-ack-" + uuid.uuid4().hex)
        self.engine.advance_stage(sid, evidence_ids=[])
        return sha

    def precondition(self, action, sha, *, sid=None, observed_utc=None):
        facts = {"action_id": action["action_id"], "plan_sha256": sha,
                 "identity_matches": True, "scope_matches": True, "content_matches": True,
                 "compatibility_checked": True, "provenance_checked": True, "recovery_verified": True}
        facts.update({key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")})
        return self.evidence("precondition", facts, sid=sid, observed_utc=observed_utc)

    def execute(self, action, sha, *, sid=None, **kwargs):
        return self.service.execute_action(sid or self.sid, action_id=action["action_id"], plan_sha256=sha,
                    precondition_evidence_ids=[self.precondition(action, sha, sid=sid)], **kwargs)

    def make_recovery_and_quarantine(self):
        backup_action, native = self.backup_action(probe=True)
        backup_result = self.execute(backup_action, self.approve(backup_action))
        self.assertEqual(backup_result["outcome"], "succeeded")
        backup = backup_result["receipt"]["native_receipt"]
        restore = backup_result["receipt"]["restore_probe_receipt"]
        sid = self.session(job="storage_cleanup")
        recovery = self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)
        storage = self.storage()
        inventory = storage.assess_storage(roots=[str(self.source)])
        plan = storage.plan_cleanup(inventory=inventory, selected=["r001/example.txt"], quarantine_destination=str(self.output / "quarantine"), content_read_authorized=True, recovery_backup=backup, recovery_verification=restore)
        action = self.service.prepare_storage_action(sid, action_id="quarantine-selected", adapter_id="storage.quarantine", storage_plan=plan, output_root=str(self.output), recovery_evidence_ids=[recovery["evidence_id"]], **PROSE)
        result = self.execute(action, self.approve(action, sid=sid), sid=sid)
        self.assertEqual(result["outcome"], "succeeded")
        return result["receipt"]["native_receipt"], backup, restore

    def approved_purge(self):
        """A purge approved by the typed reply whose recovery is a real verified backup and restoration probe."""
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses the native no-overwrite quarantine prerequisite; no fallback")
        receipt, backup, restore = self.make_recovery_and_quarantine()
        sid = self.session(job="storage_cleanup")
        recovery = self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)
        action = self.service.prepare_storage_action(sid, action_id="purge-selected", adapter_id="storage.purge",
                    storage_plan=self.storage().plan_purge(receipt=receipt), output_root=str(self.output),
                    recovery_evidence_ids=[recovery["evidence_id"]], **PROSE)
        sha = self.approve(action, sid=sid, purge_choice=True)
        return sid, action, sha, backup, restore

    def begin(self, sid, action, sha, *, code=None):
        """The engine's own begin, so its re-check of recovery from disk is exercised without the service preflight;
        with ``code`` the begin must be refused with exactly that code and start no operation."""
        evidence = [self.precondition(action, sha, sid=sid)]
        if code is None:
            return self.engine.begin_operation(sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=evidence)
        with self.assertRaises(WorkflowRefusal) as caught:
            self.engine.begin_operation(sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=evidence)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.state(sid)["operations"], {})


class WorkflowServiceTests(SessionFixtures):
    def test_action_binds_the_lower_level_plan_each_caller_names(self):
        # Each caller names the plan inside its payload that the action's adapter_plan_sha256 binds: the storage plan and the
        # diagnostic request, whose hashes the engine's binding compares with it. The package route's half is in test_packages,
        # PackageEngineTests.test_action_binds_the_reviewed_transaction_of_its_preflight.
        storage, _native = self.backup_action()
        diagnostic_sid = self.session(job="diagnosis_repair", platform="macos")
        diagnostic = self.service.prepare_diagnostic_action(diagnostic_sid, action_id="read-version", recipe_id="macos.os_version",
                                                            symptom="Fictional error E42", diagnostic_scope=["os_metadata"], **PROSE)
        for sid, action, field, bound in ((self.sid, storage, "storage_plan", "storage_plan_sha256"),
                                          (diagnostic_sid, diagnostic, "request", "request_sha256")):
            with self.subTest(field=field):
                row = self.state(sid)["evidence"][action["adapter_payload_evidence_id"]]
                payload = json.loads((self.engine.work / sid / row["path"]).read_bytes())
                self.assertEqual(action["adapter_plan_sha256"], digest(payload[field]))
                self.assertEqual(action["adapter_plan_sha256"], payload[bound])

    def test_service_intent_tamper_missing_marker_and_foreign_ids_refuse(self):
        action, native = self.backup_action()
        result = self.execute(action, self.approve(action))
        path = self.service.work / "operations" / self.sid / result["operation_id"] / "intent.json"
        intent = json.loads(path.read_bytes()); intent["payload"]["mode"] = "real"; path.write_bytes(encoded(intent))
        with self.assertRaises(ServiceRefusal):
            self.service.inspect_operation(self.sid, operation_id=result["operation_id"])
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.service.inspect_operation(self.sid, operation_id="../escape")
        (self.service.work / "service.json").rename(self.service.work / "preserved-marker.json")
        with self.assertRaises(ServiceRefusal):
            WorkflowService(self.engine)


class ServicePrivacyTests(ServiceFixtures):
    def test_immutable_writer_never_bypasses_private_file_guard(self):
        root = self.fixture_root()
        target = root / "fictional-control.json"
        # The record is published through a private temporary file beside it: that file goes through the same guard.
        with mock.patch("private_workspace.write_private_new", side_effect=PrivateWorkspaceError("fixture-file-private-hold")) as writer:
            with self.assertRaises(PrivateWorkspaceError):
                WorkflowService._immutable(target, {"fictional": True})
            (written, data), = (call.args for call in writer.call_args_list)
            self.assertEqual((written.parent, data), (target.parent, encoded({"fictional": True})))
        self.assertFalse(target.exists())

    def test_control_file_privacy_admission_precedes_content_read(self):
        from service_state import private_read
        target = self.fixture_root() / "fictional-control.json"
        with mock.patch("service_state.ensure_private_file", side_effect=PrivateWorkspaceError("fixture-file-private-hold")), mock.patch("service_state.read_record_bytes") as reader:
            with self.assertRaises(PrivateWorkspaceError):
                private_read(target)
            reader.assert_not_called()
        self.assertFalse(target.exists())

    def test_original_authority_cannot_be_retagged_after_scope_or_settings_change(self):
        root = self.fixture_root()
        operation = {"operation_id": "operation-fixture", "action_id": "action-fixture", "plan_sha256": "c" * 64,
                     "settings_revision": 0, "started_utc": utc_now(), "adapter_id": "storage.backup_create",
                     "mutating": True, "outcome": "unknown"}
        scope = {"roots": [str(root / "original-source")], "purpose": "Original fictional scope"}
        state = {"session_id": "session-fixture", "engine_id": "engine-fixture", "mode": "fixture", "platform": native_platform(),
                 "settings_revision": 0, "settings": {"scope": scope}, "operations": {operation["operation_id"]: copy.deepcopy(operation)}}
        intent = {"schema": "patchcairn.service", "schema_version": 1, "kind": "operation_intent",
                  **{key: state[key] for key in ("session_id", "engine_id", "mode", "platform", "settings_revision")},
                  "scope": copy.deepcopy(scope), "operation": copy.deepcopy(operation),
                  "action": {"adapter_id": operation["adapter_id"]}, "payload": {}}
        for status in ("active", "paused", "stopped"):
            current = copy.deepcopy(state); current.update(status=status, revision=99)
            current["operations"][operation["operation_id"]]["pause_requested"] = True
            with self.subTest(allowed_status=status):
                self.assertIsNone(WorkflowService._original_authority(current, operation, intent))
        variants = []
        changed = copy.deepcopy(state); changed["settings_revision"] = 1; variants.append(changed)
        changed = copy.deepcopy(state); changed["settings"]["scope"]["roots"] = [str(root / "other-source")]; variants.append(changed)
        for key, value in (("settings_revision", 1), ("action_id", "other-action"), ("plan_sha256", "d" * 64)):
            changed = copy.deepcopy(state); changed["operations"][operation["operation_id"]][key] = value; variants.append(changed)
        for current in variants:
            with self.subTest(refused_state=current):
                service = object.__new__(WorkflowService)
                service.elevation_probe = lambda: False
                service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=current), finish_operation=mock.Mock())
                service._lock = mock.Mock(side_effect=nullcontext)
                service.inspect_operation = mock.Mock(return_value={"operation": operation, "intent": intent})
                service._register, service._immutable = mock.Mock(), mock.Mock()
                service._operation_dir = mock.Mock(return_value=root / "operation")
                before = copy.deepcopy(current)
                with mock.patch("service_reconcile.StorageService") as storage, mock.patch("service_state.private_read", return_value=encoded(intent)) as reader:
                    with self.assertRaises(ServiceRefusal):
                        service.reconcile_operation(state["session_id"], operation_id=operation["operation_id"])
                    storage.assert_not_called()
                    reader.assert_not_called()
                    with self.assertRaises(ServiceRefusal):
                        service._finish(state, operation, outcome="succeeded", receipt={"unaccepted": True})
                    reader.assert_called_once_with(root / "operation" / "intent.json")
                    with self.assertRaisesRegex(ServiceRefusal, "scope/settings authority"):
                        service.complete_diagnostic(state["session_id"], operation_id=operation["operation_id"], adapter_result={}, coordinator_observed=True)
                    # The package route: the same check refuses before any of its reads of the installed version.
                    service.inspect_operation.return_value = {"operation": operation, "intent": {**intent, "action": {"adapter_id": pc_records.ADAPTER_PACKAGE_UPGRADE}}}
                    with self.assertRaisesRegex(ServiceRefusal, "scope/settings authority"):
                        service.reconcile_operation(state["session_id"], operation_id=operation["operation_id"])
                    reader.assert_called_once()
                service._register.assert_not_called()
                service._immutable.assert_not_called()
                service.engine.finish_operation.assert_not_called()
                self.assertEqual(current, before)

    def test_native_service_controls_private_or_hold_before_private_bytes(self):
        root = self.fixture_root()
        try:
            service = WorkflowService(self.fake_engine(root))
        except PrivateWorkspaceError as exc:
            if os.name != "posix" or exc.code not in PRIVATE_CAPABILITY_HOLDS:
                raise
            self.assertFalse(list(root.glob("**/*.json")))
            return
        ensure_private_directory(service.work)
        ensure_private_file(service.work / "service.json")
        ensure_private_file(service.work / "retention.json")
        operation = service._operation_dir("session-fixture", "operation-fixture", create=True)
        ensure_private_directory(operation)
        service._immutable(operation / "intent.json", {"fictional": True})
        ensure_private_file(operation / "intent.json")
        ensure_private_directory(service.diagnostics.base)
        with service._lock():
            with self.assertRaises(ServiceRefusal):
                with service._lock():
                    self.fail("An existing coordinator lock must not be adopted")
            self.assertTrue((service.work / ".coordinator-lock").is_file())
        with service._lock():  # the lock is free again; its private file stays
            pass


class ContainmentTests(ServiceFixtures):
    """service_state.within (inclusive) and apart, compared through private_workspace.relative_parts."""

    def test_within_is_inclusive_and_a_look_alike_part_is_another_name(self):
        from service_state import apart, within
        root = self.fixture_root()
        self.assertTrue(within(root, root))
        self.assertTrue(within(root / "kept" / "file.txt", root / "kept"))
        self.assertFalse(within(root / "kept-other", root / "kept"))
        # U+212A (Kelvin sign) folds to "k" in Unicode, but the file system keeps it a different name.
        self.assertFalse(within(root / "Kept" / "file.txt", root / "kept"))
        self.assertFalse(within(root / "kept", root / "Kept"))
        self.assertFalse(apart(root, root))
        self.assertFalse(apart(root / "kept", root / "kept" / "child"))
        self.assertFalse(apart(root / "kept" / "child", root / "kept"))
        self.assertTrue(apart(root / "kept", root / "kept-other"))
        self.assertTrue(apart(root / "Kept", root / "kept"))
        self.assertFalse(apart("relative-name", root))

    def test_a_comparison_that_cannot_be_decided_is_never_apart(self):
        from service_state import apart, within
        root = self.fixture_root()
        if os.name != "nt":
            self.skipTest("only on windows: a trailing dot or space is a name Windows would trim, so the comparison cannot be decided")
        for name in ("kept.", "kept "):
            with self.subTest(name=name):
                self.assertFalse(within(root / name / "file.txt", root / name))
                self.assertFalse(apart(root / name, root / "other"))
        with mock.patch("private_workspace.w32.API", None):
            self.assertFalse(within(root / "kept", root))
            self.assertFalse(apart(root / "kept", root / "other"))

    def test_owned_refuses_the_work_folder_itself_and_paths_outside_it(self):
        root = self.fixture_root()
        service = object.__new__(WorkflowService)
        service.root = root
        self.assertEqual(service._owned(str(root / "work" / "kept")), root / "work" / "kept")
        # "worK" folds to "work" in Unicode, but it is another folder to the file system.
        for value in (str(root / "work"), str(root / "elsewhere"), str(root / "worK" / "kept")):
            with self.subTest(value=value), self.assertRaises(ServiceRefusal):
                service._owned(value)


class FinishFactsTests(ServiceFixtures):
    def test_finish_copies_the_result_keys_into_the_evidence_facts(self):
        # The golden facts layout: the binding, the outcome and exactly the FINISH_FACTS keys, when present, the restart signal
        # from the receipt's restart record.
        state = {"session_id": "session-fixture", "mode": "fixture", "settings": {"scope": {"roots": [], "purpose": "Fictional"}}}
        operation = {"operation_id": "operation-fixture", "action_id": "action-fixture", "plan_sha256": "a" * 64}
        service = object.__new__(WorkflowService)
        service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=state), finish_operation=mock.Mock(return_value="finished"),
                                               register_evidence=mock.Mock(return_value={"data": {"evidence_id": "evidence-fixture", "sha256": "b" * 64}}))
        service._operation_dir, service._original_authority, service._immutable = mock.Mock(return_value=self.fixture_root()), mock.Mock(), mock.Mock()
        receipt = {"result": "did_not_update", "category": "did_not_update", "group": "apps", "verified_postcondition": True, "actual_effects_recorded": True,
                   "no_active_effects": True, "recovery_retained": False, "installed_version": "1.0", "facts": {"fictional": True},
                   "restart": {"signal": "unknown", "source": "apt.needrestart"}}
        intent = encoded({"schema": "patchcairn.service", "schema_version": 1, "kind": "operation_intent"})
        with mock.patch("service_state.private_read", return_value=intent):
            service._finish(state, operation, outcome="failed", receipt=receipt)
            service._finish(state, operation, outcome="succeeded", receipt={"native_receipt": {"fictional": True}, "restart": {"signal": None, "source": None}})
        first, second = (call.kwargs["facts"] for call in service.engine.register_evidence.call_args_list)
        self.assertEqual(encoded(first), b'{"action_id":"action-fixture","actual_effects_recorded":true,"category":"did_not_update","group":"apps",'
                                         b'"no_active_effects":true,"operation_id":"operation-fixture","outcome":"failed","plan_sha256":"' + b"a" * 64 +
                                         b'","recovery_retained":false,"restart_signal":"unknown","result":"did_not_update","verified_postcondition":true}')
        self.assertEqual(second, {"operation_id": "operation-fixture", "action_id": "action-fixture", "plan_sha256": "a" * 64, "outcome": "succeeded"})
        self.assertNotIn("result", service._immutable.call_args_list[0].args[1]["binding"])


class RenderedCommandTests(ServiceFixtures):
    def test_action_passes_the_shown_command_through_only_when_given(self):
        service = object.__new__(WorkflowService)
        service._register = mock.Mock(return_value={"evidence_id": "evidence-fixture", "sha256": "c" * 64})
        arguments = dict(action_id="update-fixture", adapter_id="package.upgrade", kind="update", payload={"fictional": True},
                         native_plan={"fictional": True}, inventory={"entries": []}, **PROSE)
        shown = "winget upgrade --id Example.Editor --exact"
        self.assertEqual(service._action({}, rendered_command=shown, **arguments)["rendered_command"], shown)
        self.assertNotIn("rendered_command", service._action({}, **arguments))


class ReportProjectionTests(SessionFixtures):
    """The session report's assembly in service_state: inputs projected to report.py's closed key sets."""

    def update_state(self):
        evidence = {"evidence-updated": {"facts": {"result": "updated"}}, "evidence-restart": {"facts": {"result": "restart_needed"}},
                    "evidence-plain": {"facts": {"outcome": "succeeded"}}}
        operations = {"operation-updated": {"operation_id": "operation-updated", "evidence_ids": ["evidence-updated"]},
                      "operation-restart": {"operation_id": "operation-restart", "evidence_ids": ["evidence-restart"],
                                            "restart_pending": {"signal": "fictional-signal", "source": "fictional-source"}},
                      "operation-plain": {"operation_id": "operation-plain", "evidence_ids": ["evidence-plain"]},
                      "operation-open": {"operation_id": "operation-open", "evidence_ids": []}}
        for key, operation in operations.items():
            operation.update(action_id=key.replace("operation", "action"), plan_sha256="a" * 64)
        payloads = {"operation-updated": {"manager": "winget", "id": "Example.Editor", "group": "apps", "version": "2.0"},
                    "operation-restart": {"manager": "apt", "id": "example-driver", "group": "system_drivers"},
                    "operation-plain": {"manager": "brew", "id": "example-tool", "group": "programming_tools"},
                    "operation-open": {"manager": "npm", "id": "example-cli", "group": "programming_tools"}}
        return {"operations": operations, "evidence": evidence, "plan": None, "approval": None, "standing_policy": None}, payloads

    def test_package_rows_carry_category_and_group(self):
        from service_state import package_rows
        import report
        state, payloads = self.update_state()
        rows = package_rows(state, payloads)
        self.assertEqual(rows[:2], [{"manager": "winget", "package": "Example.Editor", "outcome": "updated", "restart": "none",
                                     "category": "updated_checked", "group": "apps"},
                                    {"manager": "apt", "package": "example-driver", "outcome": "restart_needed", "restart": "pending",
                                     "category": "need_restart", "group": "system_drivers"}])
        # A step with no update result is never left out: it shows as unknown, which needs a check.
        self.assertEqual([(row["package"], row["outcome"], row["category"]) for row in rows[2:]],
                         [("example-tool", "unknown", "needs_check"), ("example-cli", "unknown", "needs_check")])
        for row in rows:
            self.assertEqual(set(row), {"manager", "package", "outcome", "restart", "category", "group"})
            self.assertEqual(row["category"], pc_records.UPDATE_RESULTS[row["outcome"]])
            self.assertIn(row["group"], pc_records.OUTCOME_GROUPS)
        # report.py takes the two keys and the labels input.
        page = report.render_session(self.state(), packages=rows, labels=report_labels()).decode("utf-8")
        self.assertIn("Example.Editor", page)

    def test_package_rows_cover_items_left_out_not_run_and_waiting_for_a_restart(self):
        # Excluded and blocked items have no operation, and a recorded restart adds no outcome evidence, so the rows come from
        # the plan, the approval, the operations and the restart record. "Not run" is derived here and stored nowhere.
        from service_state import package_rows
        state, payloads = self.update_state()
        waiting = {"operation_id": "operation-waiting", "action_id": "action-waiting", "plan_sha256": "a" * 64, "evidence_ids": [],
                   "restart_pending": {"signal": "required", "source": "fictional-source"}}
        released = {"operation_id": "operation-released", "action_id": "action-released", "plan_sha256": "a" * 64, "evidence_ids": [],
                    "restart_pending": {"signal": "none", "source": "fictional-source"}}
        booted = {"operation_id": "operation-booted", "action_id": "action-booted", "plan_sha256": "a" * 64, "evidence_ids": [],
                  "restart_pending": {"signal": "required", "source": "fictional-source"}, "restart_verification": {"boot_observed": True}}
        state["operations"] = {"operation-waiting": waiting, "operation-released": released, "operation-booted": booted}
        identifiers = ("left-out", "blocked", "waiting", "released", "booted")
        state["plan"] = {"sha256": "a" * 64, "document": {"actions": [{"action_id": "action-" + name} for name in identifiers]}}
        state["approval"] = {"action_ids": ["action-blocked", "action-waiting", "action-released", "action-booted"]}
        for name in identifiers:
            payloads["action-" + name] = payloads["operation-" + name] = {"manager": "apt", "id": name, "group": "apps"}
        self.assertEqual({row["package"]: (row["outcome"], row["category"], row["restart"]) for row in package_rows(state, payloads)},
                         {"left-out": ("excluded", "skipped_by_you", "none"), "blocked": ("not_run", "did_not_update", "none"),
                          "waiting": ("restart_needed", "need_restart", "pending"), "released": ("unknown", "needs_check", "none"),
                          "booted": ("unknown", "needs_check", "boot_observed")})
        # Before any approval a planned item waits for the person, unless a standing policy covers it.
        state["approval"] = None
        self.assertEqual({row["package"]: row["outcome"] for row in package_rows(state, payloads) if row["package"] in {"left-out", "blocked"}},
                         {"left-out": "waiting_for_you", "blocked": "waiting_for_you"})
        state["standing_policy"] = {"fictional": True}
        self.assertEqual({row["outcome"] for row in package_rows(state, payloads) if row["package"] in {"left-out", "blocked"}}, {"not_run"})
        # An operation of an earlier plan does not count as this plan's item having run.
        state["operations"]["operation-waiting"]["plan_sha256"] = "b" * 64
        self.assertEqual([row["outcome"] for row in package_rows(state, payloads) if row["package"] == "waiting"], ["restart_needed", "not_run"])

    def test_a_closed_step_whose_restart_signal_is_unknown_says_so(self):
        from service_state import package_rows
        state, payloads = self.update_state()
        state["evidence"]["evidence-updated"]["facts"]["restart_signal"] = "unknown"
        state["evidence"]["evidence-restart"]["facts"]["restart_signal"] = "unknown"
        state["evidence"]["evidence-plain"]["facts"]["restart_signal"] = "none"
        self.assertEqual({row["package"]: row["restart"] for row in package_rows(state, payloads)},
                         {"Example.Editor": "unknown", "example-driver": "pending", "example-tool": "none", "example-cli": "none"})

    def test_a_step_with_no_intent_takes_its_payload_only_from_its_own_plan(self):
        payload = {"manager": "apt", "id": "example-tool", "group": "apps"}
        evidence = self.evidence("adapter_payload", content=encoded(payload))
        action = {"action_id": "action-fixture", "adapter_id": pc_records.ADAPTER_PACKAGE_UPGRADE, "adapter_payload_evidence_id": evidence,
                  "adapter_payload_sha256": self.state()["evidence"][evidence]["sha256"]}
        operation = {"operation_id": "operation-fixture", "action_id": "action-fixture", "adapter_id": pc_records.ADAPTER_PACKAGE_UPGRADE, "plan_sha256": "a" * 64}
        state = {**self.state(), "plan": {"sha256": "a" * 64, "document": {"actions": [action]}}, "operations": {"operation-fixture": operation}}
        self.assertEqual(self.service._package_payloads(state), {"action-fixture": payload, "operation-fixture": payload})
        earlier = {**state, "operations": {"operation-fixture": {**operation, "plan_sha256": "b" * 64}}}
        self.assertEqual(self.service._package_payloads(earlier), {"action-fixture": payload})
        other = {**state, "operations": {"operation-fixture": {**operation, "action_id": "action-other"}}}
        self.assertEqual(self.service._package_payloads(other), {"action-fixture": payload})

    def test_package_payloads_come_from_the_intents_and_the_plan_s_evidence(self):
        payload = {"manager": "apt", "id": "example-tool", "group": "apps"}
        evidence = self.evidence("adapter_payload", content=encoded(payload))
        sha = self.state()["evidence"][evidence]["sha256"]
        action = {"action_id": "action-fixture", "adapter_id": pc_records.ADAPTER_PACKAGE_UPGRADE, "adapter_payload_evidence_id": evidence,
                  "adapter_payload_sha256": sha}
        backup = {**action, "action_id": "action-backup", "adapter_id": pc_records.ADAPTER_STORAGE_BACKUP_CREATE}
        state = {**self.state(), "plan": {"sha256": "a" * 64, "document": {"actions": [action, backup]}}}
        self.assertEqual(self.service._package_payloads(state), {"action-fixture": payload})
        changed = {**state, "plan": {"sha256": "a" * 64, "document": {"actions": [{**action, "adapter_payload_sha256": "0" * 64}]}}}
        with self.assertRaisesRegex(ServiceRefusal, "no longer matches"):
            self.service._package_payloads(changed)

    def test_retained_rows_and_the_other_inputs_use_the_closed_key_sets(self):
        from service_state import retained_rows
        rows = [{"retention_kind": "backup", "location": "fixture-location", "bytes": 2048, "artifacts": {"x": None}, "session_id": "s"}]
        self.assertEqual(retained_rows(rows), [{"kind": "backup", "location": "fixture-location", "bytes": 2048}])
        action, _native = self.backup_action()
        self.service.elevation_probe = lambda: False
        self.execute(action, self.approve(action))
        with mock.patch("report.render_session", return_value=b"<html>fictional view</html>") as render:
            path = self.service.session_report(self.sid)
        kwargs = render.call_args.kwargs
        self.assertEqual(render.call_args.args, (self.state(),))
        self.assertEqual(set(kwargs), {"assessment", "free_space", "packages", "retained", "labels", "restarts"})
        self.assertEqual(kwargs["restarts"], dict.fromkeys(self.state()["operations"], "none"))
        self.assertIsNone(kwargs["assessment"])
        self.assertIsNone(kwargs["free_space"])
        self.assertIsNone(kwargs["packages"])
        self.assertEqual(kwargs["labels"], report_labels())
        self.assertTrue(kwargs["retained"] and all(set(row) == {"kind", "location", "bytes"} for row in kwargs["retained"]))
        self.assertEqual(path.parent, self.service.work / "reports")
        self.assertEqual(path.read_bytes(), b"<html>fictional view</html>")
        ensure_private_file(path)

    def test_session_report_renders_through_report_py(self):
        # report.py takes the labels input.
        path = self.service.session_report(self.sid)
        self.assertIn(b"PatchCairn session report", path.read_bytes())


if __name__ == "__main__":
    unittest.main()
