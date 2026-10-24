"""Selected synthetic work copies only. No host inventory, update or repair."""
from __future__ import annotations
import copy
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
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
from workflow_core import WorkflowEngine, WorkflowRefusal, PrivacyCapabilityHold, digest, encoded, utc_now
from workflow_service import WorkflowService, ServiceRefusal, native_platform
from storage_ops import StorageService, StorageRefusal
from diagnostic_core import DiagnosticRefusal
from scoped_fs import ScopedFSError, ScopedRoot
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, write_private_new

PRIVATE_CAPABILITY_HOLDS = frozenset({
    "private-owner-or-mode-refused", "private-darwin-acl-capability-unavailable", "private-platform-unavailable",
    "private-linux-foreign-filesystem", "private-linux-abi-unavailable", "private-linux-libc-unavailable", "private-linux-descriptor-unavailable",
})

if os.name == "nt":
    import windows_scoped
    windows_scoped._WORK_ROOT = ROOT / "work" / "sv-rpc"


PROSE = dict(target="Selected fictional file", benefit="Preserve selected example contents", risk="A synthetic file can change",
             reversibility="Keep exact required recovery and reviewed restore options", verification="Read the exact selected output and verify its content")
INSTALLER_BYTES = b"Fictional immutable installer artifact; never execute."


class ExternalHandoffDrainTests(unittest.TestCase):
    """Fictional service ordering only; no files, child process or installer."""
    def prepared(self, *, mode="fixture", platform="windows"):
        events, written = [], {}
        state = {"session_id": "session-drain", "mode": mode, "platform": platform,
                 "status": "active", "stage": "apply", "operations": {}}
        operation = {"operation_id": "operation-drain", "action_id": "action-drain",
                     "plan_sha256": "a" * 64, "outcome": None}
        action = {"action_id": operation["action_id"], "adapter_id": "system.reviewed_external.v3",
                  "adapter_payload_sha256": "b" * 64, "requires_os_consent": True}
        payload = {"external_plan": {"mode": mode, "platform": platform, "fictional": True}}
        engine = types.SimpleNamespace(_pending=mock.Mock(return_value=False))
        engine._external_preflight = mock.Mock(side_effect=lambda: events.append("engine-preflight"))
        def begin(*args, **kwargs):
            events.append("begin-operation")
            engine._external_preflight()
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
        service._external_sources = mock.Mock(side_effect=lambda unused: events.append("sources"))
        service._external_preflight = mock.Mock(side_effect=lambda *args: events.append("service-preflight"))
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

    def test_owned_windows_drain_follows_both_preflights_intent_and_status(self):
        for mode, claimed in (("fixture", "linux"), ("real", "windows")):
            with self.subTest(mode=mode):
                service, state, operation, events, written, arguments = self.prepared(mode=mode, platform=claimed)
                def drain():
                    self.assertIn(operation["operation_id"], state["operations"])
                    self.assertIn("intent.json", written)
                    self.assertEqual(events[-1], "status-1")
                    events.append("drain")
                    return True
                owned = types.SimpleNamespace(shutdown_worker=mock.Mock(side_effect=drain))
                with mock.patch("workflow_service.native_platform", return_value="windows"), mock.patch.dict(sys.modules, {"windows_scoped": owned}):
                    result = service.execute_action(state["session_id"], **arguments)
                self.assertEqual(events, ["sources", "service-preflight", "begin-operation", "engine-preflight", "intent", "status-1", "drain", "status-2", "handoff.json"])
                owned.shutdown_worker.assert_called_once_with()
                self.assertEqual(result, written["handoff.json"])
                self.assertEqual(result["kind"], "reviewed_external_handoff")
                self.assertEqual(result["mode"], mode)
                self.assertIsNone(operation["outcome"])
                service._finish.assert_not_called()

    def test_drain_false_or_ordinary_failure_preserves_consumed_intent_and_no_handoff(self):
        for case, answer in (("false", False), ("none", None), ("truthy", 1),
                             ("os-error", OSError("fictional-private-detail")),
                             ("runtime-error", RuntimeError("fictional-private-detail")), ("missing-api", None)):
            with self.subTest(case=case):
                service, state, operation, events, written, arguments = self.prepared()
                owned = types.SimpleNamespace()
                if case != "missing-api":
                    owned.shutdown_worker = mock.Mock(side_effect=answer) if isinstance(answer, Exception) else mock.Mock(return_value=answer)
                with mock.patch("workflow_service.native_platform", return_value="windows"), mock.patch.dict(sys.modules, {"windows_scoped": owned}):
                    result = service.execute_action(state["session_id"], **arguments)
                    with self.assertRaises(ServiceRefusal):
                        service.execute_action(state["session_id"], **arguments)
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["receipt"], {"adapter_invoked": False, "external_handoff_created": False,
                                 "automatic_retry": False, "reason": "owned-windows-worker-drain-failed"})
                self.assertEqual(operation["outcome"], "failed")
                self.assertEqual(len(state["operations"]), 1)
                self.assertEqual(set(written), {"intent.json"})
                self.assertIsNone(written["intent.json"]["operation"]["outcome"])
                self.assertNotIn("fictional-private-detail", json.dumps(result))
                service.engine.begin_operation.assert_called_once()
                service.engine.read_session.assert_called_once()
                service._finish.assert_called_once()
                if case != "missing-api":
                    owned.shutdown_worker.assert_called_once_with()

    def test_pause_or_stop_during_drain_blocks_handoff_after_second_status_read(self):
        for status in ("pause_pending", "stopped"):
            with self.subTest(status=status):
                service, state, operation, events, written, arguments = self.prepared()
                def drain():
                    events.append("drain")
                    state["status"] = status
                    return True
                owned = types.SimpleNamespace(shutdown_worker=mock.Mock(side_effect=drain))
                with mock.patch("workflow_service.native_platform", return_value="windows"), mock.patch.dict(sys.modules, {"windows_scoped": owned}):
                    result = service.execute_action(state["session_id"], **arguments)
                self.assertEqual(events[-3:], ["drain", "status-2", "finish"])
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["receipt"], {"adapter_invoked": False, "external_handoff_created": False,
                                 "automatic_retry": False, "reason": "owner-state-changed-during-worker-drain"})
                self.assertEqual(set(written), {"intent.json"})
                self.assertIsNone(written["intent.json"]["operation"]["outcome"])
                owned.shutdown_worker.assert_called_once_with()

    def test_nonwindows_native_platform_never_imports_or_drains_windows_helper(self):
        ordinary_import = __import__
        def guarded_import(name, *args, **kwargs):
            if name == "windows_scoped":
                raise AssertionError("POSIX handoff must not import the Windows helper")
            return ordinary_import(name, *args, **kwargs)
        for actual, mode, claimed in (("linux", "fixture", "windows"), ("macos", "real", "macos")):
            with self.subTest(actual=actual, mode=mode):
                service, state, operation, events, written, arguments = self.prepared(mode=mode, platform=claimed)
                with mock.patch("workflow_service.native_platform", return_value=actual), mock.patch("builtins.__import__", side_effect=guarded_import):
                    result = service.execute_action(state["session_id"], **arguments)
                self.assertEqual(events, ["sources", "service-preflight", "begin-operation", "engine-preflight", "intent", "status-1", "handoff.json"])
                self.assertEqual(result["kind"], "reviewed_external_handoff")
                self.assertIsNone(operation["outcome"])
                service._finish.assert_not_called()

    def test_nonordinary_interruption_keeps_intent_and_creates_no_handoff(self):
        service, state, operation, events, written, arguments = self.prepared()
        owned = types.SimpleNamespace(shutdown_worker=mock.Mock(side_effect=KeyboardInterrupt))
        with mock.patch("workflow_service.native_platform", return_value="windows"), mock.patch.dict(sys.modules, {"windows_scoped": owned}), self.assertRaises(KeyboardInterrupt):
            service.execute_action(state["session_id"], **arguments)
        self.assertEqual(set(written), {"intent.json"})
        self.assertIsNone(operation["outcome"])
        service._finish.assert_not_called()
        service.engine.begin_operation.assert_called_once()


class WorkflowServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native_move_supported = True
        if os.name == "posix":
            probe = ROOT / "work" / ("sv-probe-" + uuid.uuid4().hex[:16])
            probe.mkdir(parents=True)
            try:
                WorkflowEngine(probe)
            except PrivacyCapabilityHold as exc:
                raise unittest.SkipTest("Selected filesystem cannot enforce new private engine namespaces; service actions are held") from exc
            base = ROOT / "work" / ("sv-move-" + uuid.uuid4().hex)
            source, output = base / "source", base / "output"
            source.mkdir(parents=True); output.mkdir()
            (source / "fictional.txt").write_bytes(b"Fictional native capability probe only")
            try:
                with ScopedRoot(source, quiet_workspace=True) as src, ScopedRoot(output, quiet_workspace=True) as dst:
                    expected = src.inspect("fictional.txt", hash_file=True, max_bytes=1024)
                    src.move_to("fictional.txt", destination=dst, destination_relative="fictional.txt", expected=expected)
            except ScopedFSError as exc:
                if exc.code != "no-replace-unavailable":
                    raise
                cls.native_move_supported = False

    def setUp(self):
        self.root = ROOT / "work" / ("sv-" + uuid.uuid4().hex[:16])
        self.source = self.root / "work" / "selected"
        self.output = self.root / "work" / "artifacts"
        ensure_private_directory(self.source, create=True, parents=True)
        ensure_private_directory(self.output, create=True)
        write_private_new(self.source / "example.txt", b"Fictional selected file; no host content.\n")
        self.engine = WorkflowEngine(self.root)
        self.service = WorkflowService(self.engine)
        self.scope = {"roots": [str(self.source)], "purpose": "Selected synthetic fixture only"}
        self.sid = self.session()
        self.counter = 0

    def session(self, job="backup_recovery", platform=None):
        sid = self.engine.create_session(job=job, platform=platform or native_platform(), mode="fixture", scope=self.scope, checkpoints=[])["session_id"]
        self.engine.authorize_scope(sid, owner_quote="Use only this selected synthetic folder.", owner_message_id="fictional-scope")
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
                    adapter_id="storage.backup_create.v3", storage_plan=plan, output_root=str(self.output),
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
            self.engine.record_review(sid, plan_sha256=sha, reviewer_id=reviewer, role=role, verdict="approved",
                        evidence_ids=[self.evidence("review", {"reviewed": True}, sid=sid)], notes="Independent synthetic review of this exact bounded plan")
        self.engine.approve_plan(sid, plan_sha256=sha, action_ids=[action["action_id"]], owner_quote="Apply only this exact synthetic action.",
                    owner_message_id="fixture-plan-choice", acknowledge_permanent_loss=purge_choice)
        if ack:
            self.engine.record_irreversible_ack(sid, plan_sha256=sha, action_ids=[action["action_id"]],
                        acknowledge_irreversible_loss=True, owner_quote="I acknowledge permanent irreversible loss of these exact fictional quarantined files.", owner_message_id="fixture-loss-ack")
        self.engine.advance_stage(sid, evidence_ids=[])
        return sha

    def precondition(self, action, sha, *, sid=None, observed_utc=None):
        if action["adapter_id"] == "system.reviewed_external.v3":
            sid = sid or self.sid
            observed = utc_now()
            signature = {"schema_version": "patchcairn.publisher.signature.v3", "mode": "fixture", "platform": "windows",
                         "artifact_sha256": digest(INSTALLER_BYTES), "publisher": "Fictional Example Publisher", "status": "verified",
                         "source_id": "publisher_download", "method": "windows.authenticode", "observed_utc": observed}
            signature_id = self.evidence("research", sid=sid, content=encoded(signature), observed_utc=observed)
            observed_metadata = utc_now()
            metadata = {"schema_version": "patchcairn.installer.metadata.v3", "mode": "fixture", "platform": "windows",
                        "target_id": "Example.Editor",
                        "artifact_sha256": digest(INSTALLER_BYTES), "publisher": "Fictional Example Publisher", "source_id": "publisher_download",
                        "version": "2.0", "channel": "stable", "architecture": "x64", "installation_scope": "machine", "observed_utc": observed_metadata}
            metadata_id = self.evidence("research", sid=sid, content=encoded(metadata), observed_utc=observed_metadata)
            row = self.service.record_external_preflight(sid, action_id=action["action_id"], plan_sha256=sha,
                        artifact_paths={"Example.Editor": str(self.output / "fictional-installer.msi")},
                        signature_evidence_ids={"Example.Editor": signature_id}, metadata_evidence_ids={"Example.Editor": metadata_id}, coordinator_verified=True)
            return row["evidence_id"]
        facts = {"action_id": action["action_id"], "plan_sha256": sha,
                 "identity_matches": True, "scope_matches": True, "content_matches": True,
                 "compatibility_checked": True, "provenance_checked": True, "recovery_verified": True}
        facts.update({key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")})
        return self.evidence("precondition", facts, sid=sid, observed_utc=observed_utc)

    def execute(self, action, sha, *, sid=None, **kwargs):
        if action["requires_os_consent"] and "owner_consent_evidence_id" not in kwargs:
            selected_sid = sid or self.sid
            consent = self.evidence("protected_consent", {"action_id": action["action_id"], "plan_sha256": sha, "actual_os_consent": True}, sid=selected_sid)
            self.engine.record_protected_consent(selected_sid, action_id=action["action_id"], plan_sha256=sha, evidence_id=consent,
                        owner_quote="Synthetic owner handled the selected fixture consent step; no OS installer runs.", owner_message_id="fixture-native-consent")
            kwargs["owner_consent_evidence_id"] = consent
        return self.service.execute_action(sid or self.sid, action_id=action["action_id"], plan_sha256=sha,
                    precondition_evidence_ids=[self.precondition(action, sha, sid=sid)], **kwargs)

    def test_backup_probe_creates_actual_recovery_retention_and_owned_intent(self):
        action, native = self.backup_action(probe=True)
        sha = self.approve(action)
        result = self.execute(action, sha)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual((self.output / "one-probe" / "r001" / "example.txt").read_bytes(), (self.source / "example.txt").read_bytes())
        inspected = self.service.inspect_operation(self.sid, operation_id=result["operation_id"])
        self.assertEqual(inspected["intent"]["payload"]["storage_plan"], native)
        self.assertEqual(inspected["intent"]["action"]["adapter_payload_sha256"], action["adapter_payload_sha256"])
        recovery = result["receipt"]["recovery_evidence"]["evidence_id"]
        self.engine._recovery(self.state(), [recovery])
        self.assertIn(str(self.output), self.service.protected_roots())
        self.assertEqual(self.state()["stage"], "apply")
        with self.assertRaises((ServiceRefusal, WorkflowRefusal, StorageRefusal)):
            self.execute(action, sha)
        self.assertEqual(len(self.state()["operations"]), 1)

    def test_plan_A_cannot_execute_plan_B_wrong_roots_output_type_or_hash(self):
        action, native = self.backup_action()
        sha = self.approve(action)
        with self.assertRaises(WorkflowRefusal):
            self.service.execute_action(self.sid, action_id=action["action_id"], plan_sha256="f" * 64, precondition_evidence_ids=[])
        other = self.root / "work" / "other-output"
        other.mkdir()
        for adapter, plan, output in (("storage.permanent_purge.v3", native, self.output),
                                      ("storage.backup_create.v3", native, other)):
            with self.assertRaises((ServiceRefusal, StorageRefusal, ScopedFSError)):
                self.service.prepare_storage_action(self.sid, action_id="wrong-target", adapter_id=adapter,
                            storage_plan=plan, output_root=str(output), **PROSE)
        altered = copy.deepcopy(native)
        altered["inventory"]["roots"][0]["path"] = str(self.root / "work" / "other-source")
        with self.assertRaises((ServiceRefusal, StorageRefusal)):
            self.service.prepare_storage_action(self.sid, action_id="wrong-root", adapter_id="storage.backup_create.v3", storage_plan=altered, output_root=str(self.output), **PROSE)
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

    def test_crash_after_actual_backup_keeps_consumed_ticket_until_native_reconciliation(self):
        action, native = self.backup_action()
        sha = self.approve(action)
        original = StorageService.create_backup
        def completed_then_interrupted(instance, **kwargs):
            original(instance, **kwargs)
            raise OSError("Fictional interruption; no exception detail may be persisted")
        with mock.patch.object(StorageService, "create_backup", completed_then_interrupted):
            result = self.execute(action, sha)
        self.assertEqual(result["outcome"], "unknown")
        self.assertTrue((self.output / "one.zip").exists())
        self.assertEqual(self.state()["status"], "held")
        recovered = self.service.reconcile_operation(self.sid, operation_id=result["operation_id"])
        self.assertEqual(recovered["outcome"], "succeeded")
        self.assertEqual(self.state()["status"], "paused")
        self.assertEqual(len(self.state()["operations"]), 1)

    def test_partial_move_before_step_receipt_keeps_original_mapping_and_unknown(self):
        if not self.native_move_supported:
            self.skipTest("Selected mounted filesystem refuses native no-overwrite move; no fallback")
        storage = self.storage()
        inventory = storage.assess_storage(roots=[str(self.source)])
        native = storage.plan_cleanup(inventory=inventory, selected=["r001/example.txt"], quarantine_destination=str(self.output / "quarantine"), content_read_authorized=True, recovery_required=False)
        action = self.service.prepare_storage_action(self.sid, action_id="move-once", adapter_id="storage.cleanup_quarantine.v3", storage_plan=native, output_root=str(self.output), **PROSE)
        sha = self.approve(action)
        original = StorageService._write_json
        def interrupt_step(instance, output, relative, value):
            if relative.startswith("step-quarantine-"):
                raise OSError("fictional interrupted step receipt")
            return original(instance, output, relative, value)
        with mock.patch.object(StorageService, "_write_json", interrupt_step):
            result = self.execute(action, sha)
        self.assertEqual(result["outcome"], "unknown")
        self.assertFalse((self.source / "example.txt").exists())
        self.assertTrue((self.output / "quarantine" / "000001").exists())
        inspected = self.service.inspect_operation(self.sid, operation_id=result["operation_id"])
        self.assertEqual(inspected["intent"]["quarantine_mapping"][0]["original"], native["files"][0])
        self.assertEqual(inspected["intent"]["quarantine_mapping"][0]["quarantine_relative"], "quarantine/000001")
        reconciled = self.service.reconcile_operation(self.sid, operation_id=result["operation_id"])
        self.assertEqual(reconciled["outcome"], "unknown")
        self.assertEqual(len(self.state()["operations"]), 1)

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
        action = self.service.prepare_storage_action(sid, action_id="quarantine-selected", adapter_id="storage.cleanup_quarantine.v3", storage_plan=plan, output_root=str(self.output), recovery_evidence_ids=[recovery["evidence_id"]], **PROSE)
        result = self.execute(action, self.approve(action, sid=sid), sid=sid)
        self.assertEqual(result["outcome"], "succeeded")
        return result["receipt"]["native_receipt"], backup, restore

    def test_purge_requires_separate_typed_exact_loss_ack_and_preserves_recovery(self):
        if not self.native_move_supported:
            self.skipTest("Selected mounted filesystem refuses native no-overwrite quarantine prerequisite; no fallback")
        receipt, backup, restore = self.make_recovery_and_quarantine()
        sid = self.session(job="storage_cleanup")
        recovery = self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)
        plan = self.storage().plan_purge(receipt=receipt)
        action = self.service.prepare_storage_action(sid, action_id="purge-selected", adapter_id="storage.permanent_purge.v3", storage_plan=plan, output_root=str(self.output), recovery_evidence_ids=[recovery["evidence_id"]], **PROSE)
        sha = self.approve(action, sid=sid, purge_choice=True)
        with self.assertRaises(WorkflowRefusal):
            self.execute(action, sha, sid=sid)
        self.assertEqual(self.state(sid)["operations"], {})
        self.assertTrue((self.output / "quarantine" / "000001").exists())
        self.engine.record_irreversible_ack(sid, plan_sha256=sha, action_ids=[action["action_id"]], acknowledge_irreversible_loss=True,
                    owner_quote="I acknowledge irreversible loss for this exact synthetic purge.", owner_message_id="separate-purge-loss")
        result = self.execute(action, sha, sid=sid)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertFalse((self.output / "quarantine" / "000001").exists())
        self.assertTrue(Path(backup["archive"]).exists())
        self.assertTrue((Path(restore["destination"]) / "r001" / "example.txt").exists())

    def test_quarantine_restore_is_fixed_gated_and_verifies_original_bytes(self):
        if not self.native_move_supported:
            self.skipTest("Selected mounted filesystem refuses native no-overwrite move; no fallback")
        storage = self.storage()
        inventory = storage.assess_storage(roots=[str(self.source)])
        quarantine = storage.plan_cleanup(inventory=inventory, selected=["r001/example.txt"], quarantine_destination=str(self.output / "unbacked-quarantine"), content_read_authorized=True, recovery_required=False)
        move = self.service.prepare_storage_action(self.sid, action_id="quarantine-unbacked", adapter_id="storage.cleanup_quarantine.v3", storage_plan=quarantine, output_root=str(self.output), **PROSE)
        moved = self.execute(move, self.approve(move))
        self.assertEqual(moved["outcome"], "succeeded")
        receipt = moved["receipt"]["native_receipt"]
        self.assertFalse(receipt["recovery_required"])
        sid = self.session()
        plan = self.storage().plan_quarantine_restore(receipt=receipt)
        action = self.service.prepare_storage_action(sid, action_id="restore-selected", adapter_id="storage.quarantine_restore.v3", storage_plan=plan, output_root=str(self.output), **PROSE)
        recovery_id = action["recovery_evidence_ids"][0]
        recovery_row = self.state(sid)["evidence"][recovery_id]
        binding = json.loads((self.engine.work / sid / recovery_row["path"]).read_bytes())
        self.assertEqual(binding["schema_version"], "patchcairn.quarantine.recovery.v3")
        self.assertEqual(binding["restore_plan_sha256"], digest(plan))
        result = self.execute(action, self.approve(action, sid=sid), sid=sid)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual((self.source / "example.txt").read_text(), "Fictional selected file; no host content.\n")

    def test_recovery_boolean_or_changed_probe_cannot_supply_recovery(self):
        backup_action, native = self.backup_action(probe=True)
        result = self.execute(backup_action, self.approve(backup_action))
        backup, restore = result["receipt"]["native_receipt"], result["receipt"]["restore_probe_receipt"]
        sid = self.session()
        with self.assertRaises((StorageRefusal, KeyError, TypeError)):
            self.service.register_recovery(sid, output_root=str(self.output), backup_receipt={"verified": True}, restore_receipt={"verified": True})
        (Path(restore["destination"]) / "r001" / "example.txt").write_text("Changed probe")
        with self.assertRaises((StorageRefusal, ScopedFSError)):
            self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)

    def test_diagnostic_fixed_fixture_recipe_no_native_collection_and_mode_binding(self):
        sid = self.session(job="diagnosis_repair", platform="macos")
        action = self.service.prepare_diagnostic_action(sid, action_id="read-version", recipe_id="macos.os_version", symptom="Fictional error E42", diagnostic_scope=["os_metadata"], **PROSE)
        sha = self.approve(action, sid=sid)
        runner = mock.Mock(return_value=b"15.1\n")
        with mock.patch("diagnostic_posix.subprocess.Popen") as native:
            result = self.execute(action, sha, sid=sid, diagnostic_fixture_runner=runner)
            native.assert_not_called()
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(result["receipt"]["record"]["mode"], "fixture")
        self.assertEqual(result["receipt"]["record"]["facts"], {"product_version": "15.1"})
        other = self.session(job="diagnosis_repair", platform="linux")
        with self.assertRaises(DiagnosticRefusal):
            self.service.prepare_diagnostic_action(other, action_id="foreign-os", recipe_id="macos.os_version", symptom="E42", diagnostic_scope=["os_metadata"], **PROSE)

    def test_windows_diagnostic_handoff_callback_requires_observation_and_exact_mode(self):
        sid = self.session(job="diagnosis_repair", platform="windows")
        action = self.service.prepare_diagnostic_action(sid, action_id="windows-version", recipe_id="windows.os_version", symptom="Fictional error E42", diagnostic_scope=[], **PROSE)
        handoff = self.execute(action, self.approve(action, sid=sid), sid=sid)
        request = handoff["request"]
        observed = {key: request[key] for key in ("schema_version", "request_id", "platform", "recipe_id", "mode")}
        observed.update(kind="adapter_result", status="observed", observed_utc=utc_now(), facts={"version": "10.0.99999", "build": "99999", "architecture": "x64"},
                        limitations=["Fictional adapter callback; no host collector ran."], provenance=["https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem"])
        with self.assertRaises(ServiceRefusal):
            self.service.complete_diagnostic(sid, operation_id=handoff["operation_id"], adapter_result=observed)
        wrong = copy.deepcopy(observed); wrong["mode"] = "real"
        with self.assertRaises(DiagnosticRefusal):
            self.service.complete_diagnostic(sid, operation_id=handoff["operation_id"], adapter_result=wrong, coordinator_observed=True)
        result = self.service.complete_diagnostic(sid, operation_id=handoff["operation_id"], adapter_result=observed, coordinator_observed=True)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(result["receipt"]["record"]["mode"], "fixture")

    def external(self, *, sid=None):
        sid = sid or self.session(job="security_updates", platform="windows")
        provenance = self.evidence("research", {"official_sources_checked": True, "applicability_checked": True}, sid=sid)
        recovery = {"schema_version": "patchcairn.external.recovery.v3", "strategy": "no_verified_rollback", "evidence_ids": [], "limits": "No verified rollback is claimed for this synthetic handoff."}
        verification = {"schema_version": "patchcairn.external.verification.v3", "original_success_condition": "Selected fictional application reports the reviewed version and opens the example.", "checks": [{"check_id": "selected-behavior", "description": "Observe the selected fictional version and original behavior", "expected_result": "Reviewed version and successful original example operation"}]}
        plan = {"schema_version": "patchcairn.external.plan.v3", "kind": "update", "platform": "windows", "mode": "fixture", "catalog_id": "windows.msiexec.install", "official_tool": "msiexec.exe", "targets": ["Example.Editor"],
                "target_versions": {"Example.Editor": "2.0"},
                "target_identities": {"Example.Editor": {"channel": "stable", "architecture": "x64", "publisher": "Fictional Example Publisher", "content_sha256": digest(INSTALLER_BYTES), "source_id": "publisher_download", "installation_scope": "machine"}},
                "argv": ["/i", str(self.output / "fictional-installer.msi"), "/passive", "/norestart"],
                "sources": ["https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options"], "provenance_evidence_ids": [provenance], "compatibility_evidence_ids": [provenance],
                "recovery_plan": recovery, "recovery_plan_sha256": digest(recovery), "verification_plan": verification, "verification_plan_sha256": digest(verification), "scope": self.scope}
        (self.output / "fictional-installer.msi").write_bytes(INSTALLER_BYTES)
        action = self.service.prepare_external_action(sid, action_id="external-update", external_plan=plan, inventory={"fixture": True, "selected_version": "1.0"}, **PROSE)
        return sid, action, plan

    def external_receipt(self, sid, handoff):
        operation = self.state(sid)["operations"][handoff["operation_id"]]
        evidence = self.evidence("outcome", {**{k: operation[k] for k in ("operation_id", "action_id", "plan_sha256")}, "outcome": "succeeded"}, sid=sid,
                    content=encoded({"fictional_actual_target": "2.0", "original_behavior": "passed"}))
        return {"schema_version": "patchcairn.external.receipt.v3", "operation_id": operation["operation_id"], "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"],
                "adapter_payload_sha256": handoff["adapter_payload_sha256"], "mode": "fixture", "platform": "windows", "catalog_id": "windows.msiexec.install", "observed_utc": utc_now(), "outcome": "succeeded", "tool_exit_code": 0, "postcondition_state": "verified", "evidence_ids": [evidence], "observed_effects": ["Fictional selected application changed to the reviewed version."], "limitations": ["Synthetic callback; no real application was updated."]}

    @unittest.skipUnless(os.name == "nt", "Windows owned-worker external handoff drain")
    def test_failed_owned_worker_drain_records_consumed_failure_without_handoff(self):
        import windows_scoped
        self.addCleanup(lambda: self.assertIs(windows_scoped.shutdown_worker(), True))
        sid, action, plan = self.external()
        sha = self.approve(action, sid=sid)
        with mock.patch("windows_scoped.shutdown_worker", return_value=False) as drain:
            result = self.execute(action, sha, sid=sid)
            self.assertEqual(result["outcome"], "failed")
            self.assertEqual(result["receipt"], {"adapter_invoked": False, "external_handoff_created": False,
                             "automatic_retry": False, "reason": "owned-windows-worker-drain-failed"})
            operation = self.state(sid)["operations"][result["operation_id"]]
            self.assertEqual(operation["outcome"], "failed")
            self.assertEqual(self.state(sid)["status"], "held")
            directory = self.service._operation_dir(sid, result["operation_id"])
            intent = (directory / "intent.json").read_bytes()
            self.assertFalse((directory / "handoff.json").exists())
            self.assertFalse((directory / "entered.json").exists())
            with self.assertRaises(ServiceRefusal):
                self.service.execute_action(sid, action_id=action["action_id"], plan_sha256=sha,
                            precondition_evidence_ids=[])
            self.assertEqual((directory / "intent.json").read_bytes(), intent)
            self.assertEqual(len(self.state(sid)["operations"]), 1)
            drain.assert_called_once_with()


    def test_external_handoff_keeps_active_until_actual_callback_and_pause_stop_are_preserved(self):
        for command in ("pause", "stop"):
            sid, action, plan = self.external()
            sha = self.approve(action, sid=sid)
            handoff = self.execute(action, sha, sid=sid)
            self.assertEqual(handoff["kind"], "reviewed_external_handoff")
            self.assertIsNone(self.state(sid)["operations"][handoff["operation_id"]]["outcome"])
            with self.assertRaises(WorkflowRefusal):
                self.engine.setup(sid, control="automatic")
            getattr(self.engine, command)(sid)
            receipt = self.external_receipt(sid, handoff)
            wrong = copy.deepcopy(receipt); wrong["adapter_payload_sha256"] = "f" * 64
            with self.assertRaises(ServiceRefusal):
                self.service.complete_external(sid, operation_id=handoff["operation_id"], actual_receipt=wrong, coordinator_observed=True)
            result = self.service.complete_external(sid, operation_id=handoff["operation_id"], actual_receipt=receipt, coordinator_observed=True)
            self.assertEqual(result["outcome"], "succeeded")
            self.assertEqual(self.state(sid)["status"], "paused" if command == "pause" else "stopped")
            with self.assertRaises(ServiceRefusal):
                self.service.complete_external(sid, operation_id=handoff["operation_id"], actual_receipt=receipt, coordinator_observed=True)

    def test_msi_3010_keeps_same_consumed_operation_until_owner_restart_and_actual_verification(self):
        for control in getattr(self, "restart_controls", ("pause", "stop", "partial", "unknown", "stop_before_decision", "defer_stop")):
            sid, action, plan = self.external()
            sha = self.approve(action, sid=sid)
            handoff = self.execute(action, sha, sid=sid)
            operation_id = handoff["operation_id"]
            operation = self.state(sid)["operations"][operation_id]
            receipt = self.external_receipt(sid, handoff)
            receipt.update(tool_exit_code=3010, outcome="installed_restart_pending", postcondition_state="not_verified")
            if control == "unknown":
                self.engine.finish_operation(sid, operation_id=operation_id, outcome="unknown", evidence_ids=[],
                    summary="Fictional callback interruption; do not retry the consumed installer action.")
            old_boot = (datetime.fromisoformat(operation["started_utc"].replace("Z", "+00:00")) - timedelta(days=1)).isoformat(timespec="microseconds").replace("+00:00", "Z")
            def boot_record(last_boot):
                observed = utc_now()
                return self.evidence("outcome", sid=sid, observed_utc=observed, content=encoded({
                    "schema_version": "patchcairn.windows.boot.observation.v3", "mode": "fixture", "platform": "windows",
                    "observed_utc": observed, "last_boot_utc": last_boot, "source": "windows.cim_last_boot_up_time"}),
                    facts={**{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}, "outcome": "unknown"})
            before = boot_record(old_boot)
            pending = self.service.complete_external(sid, operation_id=operation_id, actual_receipt=receipt,
                restart_boot_evidence_id=before, coordinator_observed=True)
            self.assertEqual(pending["outcome"], "installed_restart_pending")
            self.assertEqual(self.state(sid)["operations"][operation_id]["outcome"], "unknown" if control == "unknown" else None)
            self.assertEqual(len(self.state(sid)["operations"]), 1)
            wrong = self.external_receipt(sid, handoff)
            with self.assertRaises(ServiceRefusal):
                self.service.complete_external(sid, operation_id=operation_id, actual_receipt=wrong, coordinator_observed=True)
            if control == "pause":
                self.engine.pause(sid)
            if control == "stop_before_decision":
                self.engine.stop(sid)
            else:
                self.engine.decide_restart(sid, operation_id=operation_id, choice="defer", owner_quote="Defer this exact fixture restart; no host action runs.", owner_message_id="fixture-restart-defer")
            if control == "defer_stop":
                self.engine.stop(sid)
            self.engine.decide_restart(sid, operation_id=operation_id, choice="authorize", owner_quote="Authorize only this exact fictional owner-handled restart; the test performs none.", owner_message_id="fixture-restart-authorize")
            if control in {"stop_before_decision", "defer_stop"}:
                self.assertEqual(self.state(sid)["status"], "stopped")
                self.assertEqual(len(self.state(sid)["operations"]), 1)
            if control == "stop":
                self.engine.stop(sid)
            after = boot_record(utc_now())
            observed = utc_now()
            proof = {"schema_version": "patchcairn.restart.verification.v3", "session_id": sid,
                     **{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256", "settings_revision")},
                     "scope_sha256": digest(self.scope), "external_plan_sha256": digest(plan), "mode": "fixture", "platform": "windows",
                     "catalog_id": "windows.msiexec.install", "original_exit_code": 3010, "pending_evidence_id": pending["evidence_id"],
                     "restart_decision_message_id": "fixture-restart-authorize", "observed_utc": observed,
                     "before_boot_evidence_id": before, "after_boot_evidence_id": after,
                     "targets": {"Example.Editor": {"version": "2.0", "architecture": "x64", "installation_scope": "machine", "publisher": "Fictional Example Publisher"}},
                     "checks": [{"check_id": row["check_id"], "outcome": "passed", "observation": "Fictional exact target and original example behavior were observed after the simulated boot."} for row in plan["verification_plan"]["checks"]]}
            proof_id = self.evidence("outcome", sid=sid, observed_utc=observed, content=encoded(proof),
                facts={**{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}, "outcome": "succeeded"})
            bad_proofs = []
            changed = copy.deepcopy(proof); changed["targets"]["Example.Editor"]["version"] = "9.9"; bad_proofs.append(changed)
            changed = copy.deepcopy(proof); changed["checks"][0]["outcome"] = "failed"; bad_proofs.append(changed)
            changed = copy.deepcopy(proof); changed["after_boot_evidence_id"] = before; bad_proofs.append(changed)
            changed = copy.deepcopy(proof); changed["restart_decision_message_id"] = "other-owner-message"; bad_proofs.append(changed)
            changed = copy.deepcopy(proof); changed["scope_sha256"] = "f" * 64; bad_proofs.append(changed)
            for bad in bad_proofs if control == "pause" else []:
                bad["observed_utc"] = utc_now()
                bad_id = self.evidence("outcome", sid=sid, observed_utc=bad["observed_utc"], content=encoded(bad),
                    facts={**{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}, "outcome": "succeeded"})
                candidate = self.external_receipt(sid, handoff); candidate["tool_exit_code"] = 3010
                with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
                    self.service.complete_external_after_restart(sid, operation_id=operation_id, actual_receipt=candidate,
                        verification_evidence_id=bad_id, coordinator_observed=True)
                self.assertIsNone(self.state(sid)["operations"][operation_id]["outcome"])
                self.assertEqual(len(self.state(sid)["operations"]), 1)
            final = self.external_receipt(sid, handoff); final["tool_exit_code"] = 3010
            if control == "partial":
                partial_proof = copy.deepcopy(proof)
                partial_proof["checks"][0].update(outcome="failed", observation="Fictional original application behavior still fails after the simulated restart.")
                partial_proof["observed_utc"] = utc_now()
                proof_id = self.evidence("outcome", sid=sid, observed_utc=partial_proof["observed_utc"], content=encoded(partial_proof),
                    facts={**{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}, "outcome": "partial"})
                final = self.external_receipt(sid, handoff)
                final.update(tool_exit_code=3010, outcome="partial", postcondition_state="not_verified", evidence_ids=[proof_id])
            result = self.service.complete_external_after_restart(sid, operation_id=operation_id, actual_receipt=final,
                verification_evidence_id=proof_id, coordinator_observed=True)
            self.assertEqual(result["outcome"], "partial" if control == "partial" else "succeeded")
            self.assertEqual(result["receipt"]["external_receipt"]["tool_exit_code"], 3010)
            self.assertEqual(self.state(sid)["status"], "held" if control == "partial" else "stopped" if control in {"stop", "stop_before_decision", "defer_stop"} else "paused")
            self.assertEqual(len(self.state(sid)["operations"]), 1)
            with self.assertRaises(ServiceRefusal):
                self.service.complete_external_after_restart(sid, operation_id=operation_id, actual_receipt=final,
                    verification_evidence_id=proof_id, coordinator_observed=True)
            if control == "partial":
                effects = self.evidence("reconciliation", sid=sid, facts={
                    **{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}, "outcome": "partial",
                    "actual_effects_recorded": True, "no_active_effects": True, "recovery_retained": True})
                self.engine.resolve(sid, pending_id="reconcile-" + operation_id, evidence_ids=[effects], choice="revise_plan",
                    owner_quote="The fictional effects are accounted for; review a new plan without retrying this consumed installer action.", owner_message_id="fixture-after-restart-replan")
                self.assertIsNone(self.state(sid)["plan"])
                self.assertTrue(self.state(sid)["pending"]["restart-" + operation_id]["resolved"])
                self.engine.setup(sid, control="automatic")

    def test_external_injection_sources_credentials_exit_status_and_no_observation_refused(self):
        sid, action, plan = self.external()
        repair = copy.deepcopy(plan)
        repair.update(kind="repair", catalog_id="windows.dism.restorehealth", official_tool="Dism.exe", targets=["windows.component_store"], target_versions={}, target_identities={}, argv=["/Online", "/Cleanup-Image", "/RestoreHealth"])
        with self.assertRaisesRegex(ServiceRefusal, "component recovery"):
            self.service.prepare_external_action(sid, action_id="unsupported-os-repair", external_plan=repair, inventory={"fixture": True}, requires_os_consent=False, **PROSE)
        for change in ({"argv": ["uninstall", "--all"]}, {"sources": ["https://example.invalid/repair"]}, {"sources": ["https://learn.microsoft.com/?secret=example"]}, {"targets": ["Example.Token"], "argv": ["upgrade", "--id", "Example.Token", "--exact", "--source", "winget", "--disable-interactivity"]}):
            bad = copy.deepcopy(plan); bad.update(change)
            with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
                self.service.prepare_external_action(sid, action_id="bad-external", external_plan=bad, inventory={"fixture": True}, **PROSE)
        manager = copy.deepcopy(plan); manager.update(catalog_id="windows.winget.upgrade", official_tool="winget")
        with self.assertRaisesRegex(ServiceRefusal, "Manager handoff held"):
            self.service.prepare_external_action(sid, action_id="unbound-manager-content", external_plan=manager, inventory={"fixture": True}, **PROSE)
        handoff = self.execute(action, self.approve(action, sid=sid), sid=sid)
        receipt = self.external_receipt(sid, handoff)
        with self.assertRaises(ServiceRefusal):
            self.service.complete_external(sid, operation_id=handoff["operation_id"], actual_receipt=receipt)
        receipt["tool_exit_code"] = 42
        with self.assertRaises(ServiceRefusal):
            self.service.complete_external(sid, operation_id=handoff["operation_id"], actual_receipt=receipt, coordinator_observed=True)
        self.assertIsNone(self.state(sid)["operations"][handoff["operation_id"]]["outcome"])

    def test_external_payload_and_variant_proof_are_checked_before_ticket(self):
        sid, action, plan = self.external()
        sha = self.approve(action, sid=sid)
        weakened = {**action, "requires_os_consent": False}
        payload = self.engine._action_binding(self.state(sid), action)
        with mock.patch.object(self.service, "_binding", return_value=(weakened, payload)), mock.patch.object(self.service, "_external_preflight") as check, mock.patch.object(self.engine, "begin_operation") as begin:
            with self.assertRaisesRegex(ServiceRefusal, "protected OS consent"):
                self.service.execute_action(sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[])
            check.assert_not_called()
            begin.assert_not_called()
        raw = self.evidence("precondition", {"action_id": action["action_id"], "plan_sha256": sha}, sid=sid)
        with self.assertRaises(ServiceRefusal):
            self.service.execute_action(sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[raw])
        proof = self.precondition(action, sha, sid=sid)
        row = self.state(sid)["evidence"][proof]
        proof_data = json.loads((self.engine.work / sid / row["path"]).read_bytes())
        proof_target = proof_data["targets"]["Example.Editor"]
        metadata_row = self.state(sid)["evidence"][proof_target["metadata_evidence_id"]]
        wrong_product = json.loads((self.engine.work / sid / metadata_row["path"]).read_bytes())
        wrong_product.update(target_id="Another.Product", observed_utc=utc_now())
        wrong_product_id = self.evidence("research", sid=sid, content=encoded(wrong_product), observed_utc=wrong_product["observed_utc"])
        with self.assertRaisesRegex(ServiceRefusal, "package metadata"):
            self.service.record_external_preflight(sid, action_id=action["action_id"], plan_sha256=sha,
                        artifact_paths={"Example.Editor": str(self.output / "fictional-installer.msi")},
                        signature_evidence_ids={"Example.Editor": proof_target["signature_evidence_id"]},
                        metadata_evidence_ids={"Example.Editor": wrong_product_id}, coordinator_verified=True)
        self.assertEqual(self.state(sid)["operations"], {})
        installer = self.output / "fictional-installer.msi"
        installer.write_bytes(b"Changed after the exact publisher/payload check")
        with self.assertRaises((ServiceRefusal, WorkflowRefusal, ScopedFSError)):
            self.service.execute_action(sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[proof])
        self.assertEqual(self.state(sid)["operations"], {})
        with mock.patch("workflow_service.ScopedRoot") as native_open:
            with self.assertRaises(ServiceRefusal):
                self.service.record_external_preflight(sid, action_id=action["action_id"], plan_sha256=sha,
                            artifact_paths={"Example.Editor": str(self.output / ".ssh" / "id_rsa")},
                            signature_evidence_ids={"Example.Editor": "untrusted-claim"}, metadata_evidence_ids={"Example.Editor": "untrusted-metadata"}, coordinator_verified=True)
            native_open.assert_not_called()

    def test_local_pkg_and_deb_catalogs_are_fixed_literal_nonexecuting_plans(self):
        unused_sid, unused_action, base = self.external()
        guid = "{11111111-2222-3333-4444-555555555555}"
        exact_msi = copy.deepcopy(base)
        exact_msi["targets"] = [guid]
        exact_msi["target_versions"] = {guid: "2.0"}
        exact_msi["target_identities"] = {guid: exact_msi["target_identities"]["Example.Editor"]}
        self.service.prepare_external_action(unused_sid, action_id="stable-msi-family", external_plan=exact_msi,
                    inventory={"fixture": True, "selected_version": "1.0"}, **PROSE)
        cases = [("macos", "macos.installer.pkg", "/usr/sbin/installer", ".pkg", "arm64", "https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web"),
                 ("linux", "linux.dpkg.install_local", "/usr/bin/dpkg", ".deb", "all", "https://manpages.debian.org/stable/dpkg/dpkg.1.en.html")]
        for platform, catalog, tool, suffix, architecture, source in cases:
            sid = self.session(job="security_updates", platform=platform)
            provenance = self.evidence("research", {"official_sources_checked": True, "compatibility_checked": True}, sid=sid)
            artifact = self.output / ("fictional-local" + suffix)
            artifact.write_bytes(INSTALLER_BYTES)
            plan = copy.deepcopy(base)
            plan.update(platform=platform, catalog_id=catalog, official_tool=tool, sources=[source],
                        provenance_evidence_ids=[provenance], compatibility_evidence_ids=[provenance])
            plan["target_identities"]["Example.Editor"].update(architecture=architecture, installation_scope="system")
            plan["argv"] = ["-pkg", str(artifact), "-target", "/"] if platform == "macos" else ["--install", str(artifact)]
            action = self.service.prepare_external_action(sid, action_id="local-" + platform, external_plan=plan,
                        inventory={"fixture": True, "selected_version": "1.0"}, **PROSE)
            self.assertTrue(action["requires_os_consent"])
            self.assertEqual(self.state(sid)["operations"], {})
            altered = copy.deepcopy(plan); altered["argv"].append("--unreviewed-extra")
            with self.assertRaises(WorkflowRefusal):
                self.service.prepare_external_action(sid, action_id="invalid-local", external_plan=altered,
                            inventory={"fixture": True}, **PROSE)

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


class ServicePrivacyTests(unittest.TestCase):
    def fixture_root(self):
        root = ROOT / "work" / ("sv-private-" + uuid.uuid4().hex[:16])
        root.mkdir(parents=True)
        return root

    @staticmethod
    def fake_engine(root):
        return types.SimpleNamespace(root=root, marker={"engine_id": "fictional-private-test", "backend": "patchcairn.workflow.python.v3"})

    def test_namespace_refusal_precedes_marker_or_retention_write(self):
        root = self.fixture_root()
        with mock.patch("workflow_service.ensure_private_directory", side_effect=PrivateWorkspaceError("fixture-private-hold")), mock.patch("workflow_service.write_private_new") as writer:
            with self.assertRaises(PrivateWorkspaceError):
                WorkflowService(self.fake_engine(root))
            writer.assert_not_called()
        self.assertFalse(list(root.glob("**/*.json")))

    def test_immutable_writer_never_bypasses_private_file_guard(self):
        root = self.fixture_root()
        target = root / "fictional-control.json"
        with mock.patch("workflow_service.write_private_new", side_effect=PrivateWorkspaceError("fixture-file-private-hold")) as writer:
            with self.assertRaises(PrivateWorkspaceError):
                WorkflowService._immutable(target, {"fictional": True})
            writer.assert_called_once_with(target, encoded({"fictional": True}))
        self.assertFalse(target.exists())

    def test_control_file_privacy_admission_precedes_content_read(self):
        from workflow_service import _private_read
        target = self.fixture_root() / "fictional-control.json"
        with mock.patch("workflow_service.ensure_private_file", side_effect=PrivateWorkspaceError("fixture-file-private-hold")), mock.patch("workflow_service._read") as reader:
            with self.assertRaises(PrivateWorkspaceError):
                _private_read(target)
            reader.assert_not_called()
        self.assertFalse(target.exists())

    def test_scheduled_collection_requires_current_activation_before_request_or_recipe(self):
        service = object.__new__(WorkflowService)
        state = {"status": "awaiting_user", "scope_authorization": {"fictional": True}}
        service.work = self.fixture_root()
        service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=state),
            _require_schedule_activation=mock.Mock(side_effect=WorkflowRefusal("Current schedule is not due and activated")))
        service._lock = mock.Mock(side_effect=nullcontext)
        service.diagnostics = types.SimpleNamespace(create_request=mock.Mock())
        with mock.patch("workflow_service.ensure_private_directory"), self.assertRaises(WorkflowRefusal):
            service.prepare_diagnostic_action("session-fixture", action_id="scheduled-diagnostic", recipe_id="macos.os_version",
                symptom="Fictional symptom", diagnostic_scope=["os_metadata"], **PROSE)
        service.engine._require_schedule_activation.assert_called_once_with(state)
        service.diagnostics.create_request.assert_not_called()

    def test_msi_restart_status_is_catalog_specific_and_never_translated_to_zero(self):
        service = object.__new__(WorkflowService)
        service.engine = types.SimpleNamespace(_evidence=mock.Mock(return_value=[{}]))
        operation = {"operation_id": "fixture-operation", "action_id": "fixture-action", "plan_sha256": "a" * 64, "started_utc": utc_now()}
        intent = {"mode": "fixture", "platform": "windows", "action": {"adapter_payload_sha256": "b" * 64},
                  "payload": {"external_plan": {"catalog_id": "windows.msiexec.install"}}}
        receipt = {"schema_version": "patchcairn.external.receipt.v3", "operation_id": operation["operation_id"],
                   "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"], "adapter_payload_sha256": "b" * 64,
                   "mode": "fixture", "platform": "windows", "catalog_id": "windows.msiexec.install", "observed_utc": utc_now(),
                   "outcome": "installed_restart_pending", "tool_exit_code": 3010, "postcondition_state": "not_verified",
                   "evidence_ids": ["fixture-observation"], "observed_effects": ["Fictional MSI installation completed."],
                   "limitations": ["Owner restart and actual behavior verification remain pending."]}
        self.assertEqual(service._external_receipt({}, operation, intent, receipt)["tool_exit_code"], 3010)
        success = {**receipt, "outcome": "succeeded", "postcondition_state": "verified"}
        with self.assertRaises(ServiceRefusal):
            service._external_receipt({}, operation, intent, success)
        self.assertEqual(service._external_receipt({}, operation, intent, success, after_restart=True)["tool_exit_code"], 3010)
        with self.assertRaises(ServiceRefusal):
            service._external_receipt({}, operation, intent, {**success, "tool_exit_code": 0}, after_restart=True)
        with self.assertRaises(ServiceRefusal):
            service._external_receipt({}, operation, intent, {**success, "tool_exit_code": 1641})
        self.assertEqual(service._external_receipt({}, operation, intent, {**receipt, "tool_exit_code": 1641, "outcome": "unknown"})["outcome"], "unknown")
        foreign = copy.deepcopy(intent); foreign["platform"] = "macos"; foreign["payload"]["external_plan"]["catalog_id"] = "macos.installer.pkg"
        with self.assertRaises(ServiceRefusal):
            service._external_receipt({}, operation, foreign, {**receipt, "platform": "macos", "catalog_id": "macos.installer.pkg"})

    def test_msi_pending_refuses_an_intervening_boot_before_receipt_or_engine_write(self):
        service = object.__new__(WorkflowService)
        now = datetime.now(timezone.utc)
        stamp = lambda value: value.isoformat(timespec="microseconds").replace("+00:00", "Z")
        service._restart_boot = mock.Mock(return_value={"last_boot_utc": stamp(now), "observed_utc": stamp(now)})
        service._operation_dir, service._immutable, service._register = mock.Mock(), mock.Mock(), mock.Mock()
        with self.assertRaises(ServiceRefusal):
            service._record_restart_pending({}, {}, {}, {"observed_utc": stamp(now - timedelta(seconds=1))}, "before-boot")
        service._operation_dir.assert_not_called()
        service._immutable.assert_not_called()
        service._register.assert_not_called()

    def test_generic_finish_cannot_consume_restart_operation_before_actual_boot(self):
        engine = object.__new__(WorkflowEngine)
        operation = {"operation_id": "operation-fixture", "action_id": "action-fixture", "plan_sha256": "a" * 64,
                     "started_utc": utc_now(), "outcome": None, "pause_requested": False,
                     "restart_pending": {"evidence_id": "pending-fixture", "original_exit_code": 3010}}
        state = {"status": "active", "operations": {operation["operation_id"]: operation}, "pending": {}}
        engine._change = lambda session_id, event, mutate, expected_revision: mutate(copy.deepcopy(state))
        engine._evidence = mock.Mock(return_value=[])
        for outcome in ("succeeded", "failed", "partial"):
            with self.subTest(outcome=outcome), self.assertRaises(WorkflowRefusal):
                engine.finish_operation("session-fixture", operation_id=operation["operation_id"], outcome=outcome,
                    evidence_ids=["generic-true-facts"], summary="Fictional generic effects flags must not retire the boot requirement.")
            self.assertIsNone(state["operations"][operation["operation_id"]]["outcome"])
        engine._evidence.assert_not_called()

    def test_restart_verification_cannot_replace_original_private_receipt_hash(self):
        root = self.fixture_root()
        service = object.__new__(WorkflowService)
        service.root = root
        operation = {"operation_id": "operation-fixture", "started_utc": utc_now(), "outcome": None}
        intent = {"action": {"adapter_id": "system.reviewed_external.v3"}}
        state = {"session_id": "session-fixture"}
        service.engine = types.SimpleNamespace(work=root / "engine", read_session=mock.Mock(return_value=state),
            _evidence=mock.Mock(side_effect=[[{"path": "proof.json"}], [{"path": "pending.json"}]]), record_restart_verification=mock.Mock())
        service._lock, service._original_authority = mock.Mock(side_effect=nullcontext), mock.Mock()
        service.inspect_operation = mock.Mock(return_value={"operation": operation, "intent": intent})
        service._external_receipt = mock.Mock(return_value={"observed_utc": utc_now()})
        service._operation_dir = mock.Mock(return_value=root / "operation")
        service._finish = mock.Mock()
        original_path = root / "operation" / "external-restart-pending.json"
        content = {root / "engine" / state["session_id"] / "proof.json": encoded({
                       "schema_version": "patchcairn.restart.verification.v3", "pending_evidence_id": "pending"}),
                   root / "engine" / state["session_id"] / "pending.json": encoded({
                       "schema_version": "patchcairn.restart.pending.v3", "native_receipt_relative_path": original_path.relative_to(root).as_posix(), "native_receipt_sha256": "f" * 64}),
                   original_path: encoded({"tool_exit_code": 3010, "outcome": "installed_restart_pending"})}
        with mock.patch("workflow_service._private_read", side_effect=lambda path: content[path]), self.assertRaises(ServiceRefusal):
            service.complete_external_after_restart(state["session_id"], operation_id=operation["operation_id"], actual_receipt={},
                verification_evidence_id="proof", coordinator_observed=True)
        service.engine.record_restart_verification.assert_not_called()
        service._finish.assert_not_called()

    def test_reconciliation_admits_native_outcome_privacy_before_content_read(self):
        root = self.fixture_root()
        for blocked_kind in ("native", "probe"):
            for previous_outcome in (None, "unknown"):
                for refusal in (PrivateWorkspaceError("fixture-file-private-hold"), FileNotFoundError()):
                    with self.subTest(blocked_kind=blocked_kind, previous_outcome=previous_outcome, refusal=type(refusal).__name__):
                        service = object.__new__(WorkflowService)
                        state = {"mode": "fixture", "engine_id": "engine-fixture", "platform": native_platform(),
                                 "session_id": "session-fixture", "settings_revision": 0,
                                 "settings": {"scope": {"roots": [str(root / "original-source")], "purpose": "Fictional original scope"}}}
                        service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=state))
                        service.work = root / "service"
                        operation = {"operation_id": "operation-fixture", "outcome": previous_outcome,
                                     "action_id": "action-fixture", "plan_sha256": "c" * 64, "settings_revision": 0,
                                     "started_utc": utc_now(), "adapter_id": "storage.backup_create.v3", "mutating": True}
                        state["operations"] = {operation["operation_id"]: operation}
                        payload = {"output_root": str(root / "output"), "protected_roots": [],
                                   "operation": "storage.backup_create.v3", "storage_plan_sha256": "a" * 64,
                                   "storage_plan": {"fictional": True}}
                        receipt = {"fictional_native_receipt": True}
                        native_path = root / "output" / ("outcome-backup-" + "a" * 64 + ".json")
                        origin_path = service.work / ("origin-" + "a" * 64 + ".json")
                        content = {native_path: encoded(receipt), origin_path: encoded({
                            "operation_id": operation["operation_id"], **state})}
                        blocked_path = native_path
                        if blocked_kind == "probe":
                            payload["restore_probe_destination"] = str(root / "output" / "probe")
                            probe = {"destination": payload["restore_probe_destination"], "receipt": receipt}
                            content[root / "operation" / "restore-probe-plan.json"] = encoded(probe)
                            blocked_path = root / "output" / ("outcome-restore-" + digest(probe) + ".json")
                        service.inspect_operation = mock.Mock(return_value={"operation": operation,
                            "intent": {"payload": payload, "action": {"adapter_id": payload["operation"]},
                                "operation": copy.deepcopy(operation), "scope": state["settings"]["scope"],
                                **{key: state[key] for key in ("engine_id", "mode", "platform", "session_id", "settings_revision")}}})
                        service._lock = mock.Mock(side_effect=nullcontext)
                        service._operation_dir = mock.Mock(return_value=root / "operation")
                        service._finish = mock.Mock(side_effect=lambda state, operation, **result: result)
                        service._register_recovery = mock.Mock()
                        def admit(path):
                            if path == blocked_path:
                                raise refusal
                        with mock.patch("workflow_service.StorageService") as storage, mock.patch("workflow_service.ensure_private_file", side_effect=admit) as admission, mock.patch("workflow_service._read", side_effect=lambda path, *args: content[path]) as reader:
                            result = service.reconcile_operation("session-fixture", operation_id=operation["operation_id"])
                        admission.assert_any_call(blocked_path)
                        self.assertNotIn(blocked_path, [call.args[0] for call in reader.call_args_list])
                        self.assertEqual(result["outcome"], "unknown")
                        if previous_outcome is None:
                            self.assertEqual(service._finish.call_args.kwargs["outcome"], "unknown")
                            self.assertFalse(service._finish.call_args.kwargs["receipt"]["native_outcome_verified"])
                        else:
                            service._finish.assert_not_called()
                            self.assertTrue(result["held"])
                            self.assertFalse(result["automatic_retry"])
                        self.assertEqual(storage.return_value.verify_outcome.call_count, 1 if blocked_kind == "probe" else 0)
                        service._register_recovery.assert_not_called()

    def test_original_authority_cannot_be_retagged_after_scope_or_settings_change(self):
        root = self.fixture_root()
        operation = {"operation_id": "operation-fixture", "action_id": "action-fixture", "plan_sha256": "c" * 64,
                     "settings_revision": 0, "started_utc": utc_now(), "adapter_id": "storage.backup_create.v3",
                     "mutating": True, "outcome": "unknown"}
        scope = {"roots": [str(root / "original-source")], "purpose": "Original fictional scope"}
        state = {"session_id": "session-fixture", "engine_id": "engine-fixture", "mode": "fixture", "platform": native_platform(),
                 "settings_revision": 0, "settings": {"scope": scope}, "operations": {operation["operation_id"]: copy.deepcopy(operation)}}
        intent = {**{key: state[key] for key in ("session_id", "engine_id", "mode", "platform", "settings_revision")},
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
                service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=current), finish_operation=mock.Mock())
                service._lock = mock.Mock(side_effect=nullcontext)
                service.inspect_operation = mock.Mock(return_value={"operation": operation, "intent": intent})
                service._register, service._immutable = mock.Mock(), mock.Mock()
                service._operation_dir = mock.Mock(return_value=root / "operation")
                before = copy.deepcopy(current)
                with mock.patch("workflow_service.StorageService") as storage, mock.patch("workflow_service._private_read", return_value=encoded(intent)) as reader:
                    with self.assertRaises(ServiceRefusal):
                        service.reconcile_operation(state["session_id"], operation_id=operation["operation_id"])
                    storage.assert_not_called()
                    reader.assert_not_called()
                    with self.assertRaises(ServiceRefusal):
                        service._finish(state, operation, outcome="succeeded", receipt={"unaccepted": True})
                    reader.assert_called_once_with(root / "operation" / "intent.json")
                    with self.assertRaisesRegex(ServiceRefusal, "scope/settings authority"):
                        service.complete_diagnostic(state["session_id"], operation_id=operation["operation_id"], adapter_result={}, coordinator_observed=True)
                    with self.assertRaisesRegex(ServiceRefusal, "scope/settings authority"):
                        service.complete_external(state["session_id"], operation_id=operation["operation_id"], actual_receipt={}, coordinator_observed=True)
                    reader.assert_called_once()
                service._register.assert_not_called()
                service._immutable.assert_not_called()
                service.engine.finish_operation.assert_not_called()
                self.assertEqual(current, before)

    def test_purge_original_recovery_and_exact_engine_binding_precede_ticket(self):
        root = self.fixture_root()
        for receipt in ({"recovery_required": False}, {"recovery_required": True},
                        {"recovery_required": True, "recovery_backup": {"unrelated": True}}):
            with self.subTest(receipt=receipt), self.assertRaises(ServiceRefusal):
                WorkflowService._purge_original_recovery({"operation": "storage.permanent_purge.v3", "storage_plan": {"receipt": receipt}})
        service = object.__new__(WorkflowService)
        state = {"status": "active", "stage": "apply", "mode": "fixture", "settings": {"scope": {"roots": []}}}
        service.engine = types.SimpleNamespace(read_session=mock.Mock(return_value=state), _pending=mock.Mock(return_value=False),
            _recovery=mock.Mock(side_effect=WorkflowRefusal("Wrong original recovery binding")), begin_operation=mock.Mock())
        service._lock = mock.Mock(side_effect=nullcontext)
        service._state = mock.Mock(return_value=state)
        service.protected_roots = mock.Mock(return_value=[])
        service._owned = mock.Mock(side_effect=lambda value, **kwargs: Path(value))
        unbacked = {"kind": "purge", "receipt": {"recovery_required": False}}
        with mock.patch("workflow_service.StorageService") as lower:
            with self.assertRaises(ServiceRefusal):
                WorkflowService._storage(service, state, {"operation": "storage.permanent_purge.v3", "mode": "fixture",
                    "output_root": str(root / "output"), "protected_roots": [], "storage_plan": unbacked,
                    "storage_plan_sha256": digest(unbacked)})
            lower.assert_not_called()
        service._storage = mock.Mock()
        action = {"action_id": "purge-fixture", "adapter_id": "storage.permanent_purge.v3", "recovery_evidence_ids": ["unrelated-backup"]}
        plan = {"kind": "purge", "receipt": {"recovery_required": True, "recovery_backup": {}, "recovery_verification": {}}}
        service._action = mock.Mock(return_value=action)
        with self.assertRaises(WorkflowRefusal):
            service.prepare_storage_action("session-fixture", action_id=action["action_id"], adapter_id=action["adapter_id"],
                storage_plan=plan, output_root=str(root / "output"), recovery_evidence_ids=action["recovery_evidence_ids"], **PROSE)
        service.engine._recovery.assert_called_once_with(state, action["recovery_evidence_ids"], action=action)
        service.engine._recovery.reset_mock()
        service._binding = mock.Mock(return_value=(action, {"operation": action["adapter_id"], "storage_plan": plan, "storage_plan_sha256": digest(plan)}))
        with self.assertRaises(WorkflowRefusal):
            service.execute_action("session-fixture", action_id=action["action_id"], plan_sha256="a" * 64, precondition_evidence_ids=[])
        service.engine._recovery.assert_called_once_with(state, action["recovery_evidence_ids"], action=action)
        service.engine.begin_operation.assert_not_called()

    def test_reserved_quarantine_blocks_other_sessions_and_allows_only_exact_receipt_mapping(self):
        root = self.fixture_root()
        output, source, other_output = root / "work" / "reserved", root / "work" / "source", root / "work" / "other-output"
        original = {"kind": "quarantine", "inventory": {"roots": [{"path": str(source)}]},
                    "files": [{"sha256": "b" * 64}], "quarantine_relative": "quarantine",
                    "quarantine_destination": str(output / "quarantine"), "recovery_required": False,
                    "recovery_backup": None, "recovery_verification": None}
        mapping = WorkflowService._quarantine_mapping(original)
        binding = {"output_root": str(output), "mode": "fixture", "platform": native_platform(),
                   "native_plan_sha256": digest(original), "original_plan": original, "quarantine_mapping": mapping}
        service = object.__new__(WorkflowService)
        service.root = root
        service._owned = mock.Mock(side_effect=lambda value, **kwargs: Path(value))
        service.protected_roots = mock.Mock(return_value=[str(output)])
        service._retention = mock.Mock(return_value=[{"quarantine_binding": binding}])
        state = {"mode": "fixture", "platform": native_platform(), "session_id": "another-session",
                 "settings": {"scope": {"roots": [str(source)]}}}
        receipt = {"plan_sha256": digest(original), "source_roots": original["inventory"]["roots"],
                   **{key: original[key] for key in ("quarantine_destination", "recovery_required", "recovery_backup", "recovery_verification")},
                   "records": [{"original": original["files"][0], "quarantine_record": {"relative_path": mapping[0]["quarantine_relative"]}}]}
        def payload(operation, plan, target=output):
            return {"operation": operation, "storage_plan": plan, "storage_plan_sha256": digest(plan),
                    "output_root": str(target), "mode": "fixture", "protected_roots": [str(output)]}
        restored = {"kind": "quarantine_restore", "receipt": receipt}
        with mock.patch("workflow_service.StorageService") as lower:
            self.assertIs(service._storage(state, payload("storage.quarantine_restore.v3", restored)), lower.return_value)
            lower.reset_mock()
            wrong = copy.deepcopy(restored); wrong["receipt"]["records"][0]["quarantine_record"]["relative_path"] = "quarantine/000002"
            with self.assertRaises(ServiceRefusal):
                service._storage(state, payload("storage.quarantine_restore.v3", wrong))
            lower.assert_not_called()
            with self.assertRaises(ServiceRefusal):
                service._storage(state, payload("storage.backup_create.v3", {"kind": "backup", "inventory": original["inventory"]}))
            lower.assert_not_called()
            selected_reserved = {"kind": "backup", "inventory": {"roots": [{"path": str(output)}]}}
            with self.assertRaises(ServiceRefusal):
                service._storage(state, payload("storage.backup_create.v3", selected_reserved, other_output))
            lower.return_value.check_preconditions.assert_not_called()
        inventory = object.__new__(StorageService)
        inventory.output_root, inventory.protected_roots = other_output, (output,)
        inventory._scope = mock.Mock()
        for selected in (output, output / "quarantine"):
            with self.subTest(selected=selected), self.assertRaises(StorageRefusal):
                inventory.assess_storage(roots=[str(selected)])
        inventory._scope.assert_not_called()

    def test_quarantine_reservation_is_durable_before_first_adapter_effect(self):
        root = self.fixture_root()
        engine = self.fake_engine(root)
        engine.work = root / "work" / "engine"
        try:
            service = WorkflowService(engine)
        except PrivateWorkspaceError as exc:
            if os.name == "posix" and exc.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("Actual private namespace unavailable; pure reservation boundaries run separately")
            raise
        output = root / "work" / "quarantine-output"
        ensure_private_directory(output, create=True)
        plan = {"kind": "quarantine", "inventory": {"roots": [{"path": str(root / "work" / "selected")}]},
                "files": [{"sha256": "b" * 64}], "quarantine_relative": "quarantine",
                "quarantine_destination": str(output / "quarantine"), "recovery_required": False,
                "recovery_backup": None, "recovery_verification": None}
        payload = {"operation": "storage.cleanup_quarantine.v3", "storage_plan": plan,
                   "storage_plan_sha256": digest(plan), "output_root": str(output), "mode": "fixture", "protected_roots": []}
        state = {"engine_id": engine.marker["engine_id"], "session_id": "session-fixture", "mode": "fixture",
                 "platform": native_platform(), "status": "active", "stage": "apply"}
        action = {"action_id": "quarantine-fixture", "adapter_id": payload["operation"], "adapter_payload_sha256": digest(payload)}
        operation = {"operation_id": "operation-fixture", "action_id": action["action_id"], "plan_sha256": "a" * 64}
        engine.read_session, engine._pending = mock.Mock(return_value=state), mock.Mock(return_value=False)
        engine.begin_operation = mock.Mock(return_value={"data": operation})
        service._state, service._binding = mock.Mock(return_value=state), mock.Mock(return_value=(action, payload))
        native = mock.Mock()
        service._storage = mock.Mock(return_value=native)
        def persist_intent(*args):
            path = service._operation_dir(state["session_id"], operation["operation_id"], create=True)
            intent = {"payload": payload, "action": action, "operation": operation, "quarantine_mapping": service._quarantine_mapping(plan)}
            service._immutable(path / "intent.json", intent)
            return path, intent
        service._intent = mock.Mock(side_effect=persist_intent)
        service._finish = mock.Mock(side_effect=lambda state, operation, **result: result)
        def effect(**kwargs):
            reopened = WorkflowService(engine)
            self.assertIn(str(output), reopened.protected_roots())
            row = next(row for row in reopened._retention() if "quarantine_binding" in row)
            self.assertEqual(row["quarantine_binding"]["original_plan"], plan)
            self.assertEqual(row["quarantine_binding"]["quarantine_mapping"], service._quarantine_mapping(plan))
            self.assertIn(str(output / "quarantine" / "000001"), row["artifacts"])
            state["status"] = "stopped"
            self.assertIn(str(output), reopened.protected_roots())
            state["status"] = "active"
            return {"fictional_adapter_result": True}
        native.quarantine.side_effect = effect
        result = service.execute_action(state["session_id"], action_id=action["action_id"], plan_sha256=operation["plan_sha256"], precondition_evidence_ids=[])
        self.assertEqual(result["outcome"], "succeeded")
        native.quarantine.assert_called_once()

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
            self.assertTrue((service.work / ".coordinator-lock").is_dir())
        self.assertFalse((service.work / ".coordinator-lock").exists())

    def test_existing_broad_service_namespace_refuses_without_acl_repair(self):
        root = self.fixture_root()
        namespace = root / "work" / "services"
        namespace.mkdir(parents=True)
        before = namespace.stat().st_mode
        try:
            ensure_private_directory(namespace)
        except PrivateWorkspaceError as exc:
            if exc.code in PRIVATE_CAPABILITY_HOLDS - {"private-owner-or-mode-refused", "private-linux-foreign-filesystem"}:
                self.skipTest("Native private-ACL admission unavailable; refusal is covered separately")
            if exc.code not in {"private-owner-or-mode-refused", "private-dacl-unprotected", "private-dacl-broad-or-unknown", "private-linux-foreign-filesystem"}:
                raise
        else:
            self.skipTest("This parent already gives the fixture private permissions")
        with self.assertRaises(PrivateWorkspaceError):
            WorkflowService(self.fake_engine(root))
        self.assertEqual(namespace.stat().st_mode, before)
        self.assertFalse(list(root.glob("**/*.json")))

    def test_neutral_default_and_explicit_service_namespaces_do_not_adopt_old_records(self):
        root = self.fixture_root()
        try:
            old = WorkflowService(self.fake_engine(root), work_relative="work/service-v3")
        except PrivateWorkspaceError as exc:
            if os.name == "posix" and exc.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("Private namespace unavailable; native refusal covered separately")
            raise
        old_marker = (old.work / "service.json").read_bytes()
        current = WorkflowService(self.fake_engine(root))
        explicit = WorkflowService(self.fake_engine(root), work_relative="work/selected-service")
        self.assertEqual(current.work, root / "work/services")
        self.assertEqual(current.diagnostics.base, root / "work/services/diagnostics")
        self.assertEqual(explicit.work, root / "work/selected-service")
        self.assertEqual(WorkflowService(self.fake_engine(root), work_relative="work/service-v3").work, old.work)
        self.assertEqual((old.work / "service.json").read_bytes(), old_marker)
        self.assertNotEqual(current.work, old.work)

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


if __name__ == "__main__":
    unittest.main()
