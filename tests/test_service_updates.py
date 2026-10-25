"""Selected synthetic work copies only. No host inventory, update or repair.

Update and repair family (scripts/service_updates.py): the reviewed local-installer handoff, its receipt
and MSI restart accounting.
"""
from __future__ import annotations
import copy
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowEngine, WorkflowRefusal, digest, encoded
import pc_records
from clock_helpers import utc_now
from workflow_service import WorkflowService, ServiceRefusal
import diagnostic_core
from scoped_fs import ScopedFSError
from test_service_state import ServiceFixtures, SessionFixtures, PROSE, INSTALLER_BYTES


class ExternalHandoffOrderTests(ServiceFixtures):
    """Fictional service ordering only; no files, child process or installer."""
    def test_handoff_follows_both_preflights_intent_and_status_without_any_worker(self):
        ordinary_import = __import__
        def guarded_import(name, *args, **kwargs):
            if name == "windows_scoped":
                raise AssertionError("The reviewed handoff must not import or drain a Windows helper")
            return ordinary_import(name, *args, **kwargs)
        for actual, mode, claimed in (("windows", "fixture", "linux"), ("windows", "real", "windows"), ("linux", "fixture", "windows"), ("macos", "real", "macos")):
            with self.subTest(actual=actual, mode=mode):
                service, state, operation, events, written, arguments = self.prepared(mode=mode, platform=claimed)
                with mock.patch("service_state.native_platform", return_value=actual), mock.patch("builtins.__import__", side_effect=guarded_import):
                    result = service.execute_action(state["session_id"], **arguments)
                self.assertEqual(events, ["sources", "service-preflight", "begin-operation", "engine-preflight", "intent", "status-1", "handoff.json"])
                self.assertEqual(result["kind"], "reviewed_external_handoff")
                self.assertEqual(written["handoff.json"], result)
                self.assertIsNone(operation["outcome"])
                service._finish.assert_not_called()


class ReviewedExternalHandoffOrderTests(ServiceFixtures):
    """Fictional service ordering only; no files, child process or installer."""
    def test_owner_pause_after_intent_records_consumed_failure_without_handoff(self):
        service, state, operation, events, written, arguments = self.prepared()
        def paused(*args):
            events.append("status-" + str(service.engine.read_session.call_count))
            state["status"] = "paused"
            return state
        service.engine.read_session.side_effect = paused
        result = service.execute_action(state["session_id"], **arguments)
        self.assertEqual(events, ["sources", "service-preflight", "begin-operation", "engine-preflight", "intent", "status-1", "finish"])
        self.assertEqual(result["outcome"], "failed")
        self.assertFalse(result["receipt"]["adapter_invoked"])
        self.assertEqual(set(written), {"intent.json"})

    def test_nonordinary_interruption_keeps_intent_and_creates_no_handoff(self):
        service, state, operation, events, written, arguments = self.prepared()
        service.engine.read_session.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            service.execute_action(state["session_id"], **arguments)
        self.assertEqual(set(written), {"intent.json"})
        self.assertIsNone(operation["outcome"])
        service._finish.assert_not_called()
        service.engine.begin_operation.assert_called_once()


class WorkflowServiceTests(SessionFixtures):
    def test_external_receipt_before_the_start_is_a_clock_step_or_stale(self):
        # D-056: ordering keeps no tolerance; a gap within pc_records' future-skew bound is reported as a clock step.
        sid, action, plan = self.external()
        handoff = self.execute(action, self.approve(action, sid=sid), sid=sid)
        started = datetime.fromisoformat(self.state(sid)["operations"][handoff["operation_id"]]["started_utc"].replace("Z", "+00:00"))
        for seconds, code in ((1, "clock-step"), (pc_records.FUTURE_SKEW_SECONDS + 5, "service-refusal")):
            receipt = self.external_receipt(sid, handoff)
            receipt["observed_utc"] = (started - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            with self.subTest(seconds=seconds), self.assertRaises(ServiceRefusal) as caught:
                self.service.complete_external(sid, operation_id=handoff["operation_id"], actual_receipt=receipt, coordinator_observed=True)
            self.assertEqual(caught.exception.code, code)
        self.assertIn("clock moved back", diagnostic_core.CLOCK_STEP_MESSAGE)
        self.assertIsNone(self.state(sid)["operations"][handoff["operation_id"]]["outcome"])

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
                    "schema": "patchcairn.windows.boot.observation", "schema_version": 1, "mode": "fixture", "platform": "windows",
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
            proof = {"schema": "patchcairn.restart.verification", "schema_version": 1, "session_id": sid,
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
        payload = self.engine.action_binding(self.state(sid), action)
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
        with mock.patch("service_updates.ScopedRoot") as native_open:
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


class ServicePrivacyTests(ServiceFixtures):
    def test_msi_restart_status_is_catalog_specific_and_never_translated_to_zero(self):
        service = object.__new__(WorkflowService)
        service.engine = types.SimpleNamespace(evidence_rows=mock.Mock(return_value=[{}]))
        operation = {"operation_id": "fixture-operation", "action_id": "fixture-action", "plan_sha256": "a" * 64, "started_utc": utc_now()}
        intent = {"mode": "fixture", "platform": "windows", "action": {"adapter_payload_sha256": "b" * 64},
                  "payload": {"external_plan": {"catalog_id": "windows.msiexec.install"}}}
        receipt = {"schema": "patchcairn.external.receipt", "schema_version": 1, "operation_id": operation["operation_id"],
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
        engine.evidence_rows = mock.Mock(return_value=[])
        for outcome in ("succeeded", "failed", "partial"):
            with self.subTest(outcome=outcome), self.assertRaises(WorkflowRefusal):
                engine.finish_operation("session-fixture", operation_id=operation["operation_id"], outcome=outcome,
                    evidence_ids=["generic-true-facts"], summary="Fictional generic effects flags must not retire the boot requirement.")
            self.assertIsNone(state["operations"][operation["operation_id"]]["outcome"])
        engine.evidence_rows.assert_not_called()

    def test_restart_verification_cannot_replace_original_private_receipt_hash(self):
        root = self.fixture_root()
        service = object.__new__(WorkflowService)
        service.root = root
        operation = {"operation_id": "operation-fixture", "started_utc": utc_now(), "outcome": None}
        intent = {"action": {"adapter_id": "system.reviewed_external"}}
        state = {"session_id": "session-fixture"}
        service.engine = types.SimpleNamespace(work=root / "engine", read_session=mock.Mock(return_value=state),
            evidence_rows=mock.Mock(side_effect=[[{"path": "proof.json"}], [{"path": "pending.json"}]]), record_restart_verification=mock.Mock())
        service._lock, service._original_authority = mock.Mock(side_effect=nullcontext), mock.Mock()
        service.inspect_operation = mock.Mock(return_value={"operation": operation, "intent": intent})
        service._external_receipt = mock.Mock(return_value={"observed_utc": utc_now()})
        service._operation_dir = mock.Mock(return_value=root / "operation")
        service._finish = mock.Mock()
        original_path = root / "operation" / "external-restart-pending.json"
        content = {root / "engine" / state["session_id"] / "proof.json": encoded({
                       "schema": "patchcairn.restart.verification", "schema_version": 1, "pending_evidence_id": "pending"}),
                   root / "engine" / state["session_id"] / "pending.json": encoded({
                       "schema": "patchcairn.restart.pending", "schema_version": 1, "native_receipt_relative_path": original_path.relative_to(root).as_posix(), "native_receipt_sha256": "f" * 64}),
                   original_path: encoded({"tool_exit_code": 3010, "outcome": "installed_restart_pending"})}
        with mock.patch("service_updates.private_read", side_effect=lambda path: content[path]), self.assertRaises(ServiceRefusal):
            service.complete_external_after_restart(state["session_id"], operation_id=operation["operation_id"], actual_receipt={},
                verification_evidence_id="proof", coordinator_observed=True)
        service.engine.record_restart_verification.assert_not_called()
        service._finish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
