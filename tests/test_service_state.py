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
from workflow_core import WorkflowEngine, WorkflowRefusal, PrivacyCapabilityHold, digest, encoded
from clock_helpers import start_forward_only_clock, utc_now
from workflow_service import WorkflowService, ServiceRefusal, native_platform, verify_storage_artifact
from storage_ops import StorageService
from scoped_fs import ScopedFSError, ScopedRoot
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, write_private_new

PRIVATE_CAPABILITY_HOLDS = frozenset({
    "private-owner-or-mode-refused", "private-darwin-acl-capability-unavailable", "private-platform-unavailable",
    "private-linux-foreign-filesystem", "private-linux-abi-unavailable", "private-linux-libc-unavailable", "private-linux-descriptor-unavailable",
})

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
INSTALLER_BYTES = b"Fictional immutable installer artifact; never execute."


@functools.cache
def capability_probe():
    """(native_move_supported, private_hold) of this host, probed once per process for every SessionFixtures class.
    Capability probes only; a missing capability skips each test with a tagged reason (D-023)."""
    native_move_supported, private_hold = True, None
    if os.name == "posix":
        probe = ROOT / "work" / ("sv-probe-" + uuid.uuid4().hex[:16])
        probe.mkdir(parents=True)
        try:
            WorkflowEngine(probe)
        except PrivacyCapabilityHold as exc:
            private_hold = str(exc)
            return native_move_supported, private_hold
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
            native_move_supported = False
    return native_move_supported, private_hold


class ServiceFixtures(unittest.TestCase):
    """Shared helpers of the tests that build their own fictional service object; it defines no test."""
    def prepared(self, *, mode="fixture", platform="windows"):
        events, written = [], {}
        state = {"session_id": "session-drain", "mode": mode, "platform": platform,
                 "status": "active", "stage": "apply", "operations": {}}
        operation = {"operation_id": "operation-drain", "action_id": "action-drain",
                     "plan_sha256": "a" * 64, "outcome": None}
        action = {"action_id": operation["action_id"], "adapter_id": "system.reviewed_external",
                  "adapter_payload_sha256": "b" * 64, "requires_os_consent": True}
        payload = {"external_plan": {"mode": mode, "platform": platform, "fictional": True}}
        engine = types.SimpleNamespace(pending_items=mock.Mock(return_value=False))
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

    def fixture_root(self):
        root = ROOT / "work" / ("sv-private-" + uuid.uuid4().hex[:16])
        root.mkdir(parents=True)
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
        ensure_private_directory(self.output, create=True)
        write_private_new(self.source / "example.txt", b"Fictional selected file; no host content.\n")
        start_forward_only_clock(self)
        self.engine = WorkflowEngine(self.root, verify_artifact=verify_storage_artifact)
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
        if action["adapter_id"] == "system.reviewed_external":
            sid = sid or self.sid
            observed = utc_now()
            signature = {"schema": "patchcairn.publisher.signature", "schema_version": 1, "mode": "fixture", "platform": "windows",
                         "artifact_sha256": digest(INSTALLER_BYTES), "publisher": "Fictional Example Publisher", "status": "verified",
                         "source_id": "publisher_download", "method": "windows.authenticode", "observed_utc": observed}
            signature_id = self.evidence("research", sid=sid, content=encoded(signature), observed_utc=observed)
            observed_metadata = utc_now()
            metadata = {"schema": "patchcairn.installer.metadata", "schema_version": 1, "mode": "fixture", "platform": "windows",
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
        """An approved, acknowledged purge whose recovery is a real verified backup and restoration probe."""
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses the native no-overwrite quarantine prerequisite; no fallback")
        receipt, backup, restore = self.make_recovery_and_quarantine()
        sid = self.session(job="storage_cleanup")
        recovery = self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)
        action = self.service.prepare_storage_action(sid, action_id="purge-selected", adapter_id="storage.purge",
                    storage_plan=self.storage().plan_purge(receipt=receipt), output_root=str(self.output),
                    recovery_evidence_ids=[recovery["evidence_id"]], **PROSE)
        sha = self.approve(action, sid=sid, purge_choice=True, ack=True)
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

    def external(self, *, sid=None):
        sid = sid or self.session(job="security_updates", platform="windows")
        provenance = self.evidence("research", {"official_sources_checked": True, "applicability_checked": True}, sid=sid)
        recovery = {"schema": "patchcairn.external.recovery", "schema_version": 1, "strategy": "no_verified_rollback", "evidence_ids": [], "limits": "No verified rollback is claimed for this synthetic handoff."}
        verification = {"schema": "patchcairn.external.verification", "schema_version": 1, "original_success_condition": "Selected fictional application reports the reviewed version and opens the example.", "checks": [{"check_id": "selected-behavior", "description": "Observe the selected fictional version and original behavior", "expected_result": "Reviewed version and successful original example operation"}]}
        plan = {"schema": "patchcairn.external.plan", "schema_version": 1, "kind": "update", "platform": "windows", "mode": "fixture", "catalog_id": "windows.msiexec.install", "official_tool": "msiexec.exe", "targets": ["Example.Editor"],
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
        return {"schema": "patchcairn.external.receipt", "schema_version": 1, "operation_id": operation["operation_id"], "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"],
                "adapter_payload_sha256": handoff["adapter_payload_sha256"], "mode": "fixture", "platform": "windows", "catalog_id": "windows.msiexec.install", "observed_utc": utc_now(), "outcome": "succeeded", "tool_exit_code": 0, "postcondition_state": "verified", "evidence_ids": [evidence], "observed_effects": ["Fictional selected application changed to the reviewed version."], "limitations": ["Synthetic callback; no real application was updated."]}


class WorkflowServiceTests(SessionFixtures):
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
        with mock.patch("service_state.write_private_new", side_effect=PrivateWorkspaceError("fixture-file-private-hold")) as writer:
            with self.assertRaises(PrivateWorkspaceError):
                WorkflowService._immutable(target, {"fictional": True})
            writer.assert_called_once_with(target, encoded({"fictional": True}))
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
                    with self.assertRaisesRegex(ServiceRefusal, "scope/settings authority"):
                        service.complete_external(state["session_id"], operation_id=operation["operation_id"], actual_receipt={}, coordinator_observed=True)
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
            self.assertTrue((service.work / ".coordinator-lock").is_dir())
        self.assertFalse((service.work / ".coordinator-lock").exists())


if __name__ == "__main__":
    unittest.main()
