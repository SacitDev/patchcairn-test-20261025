"""Update and repair family: today's reviewed local-installer handoff (D-014, PD-19), its preflight, receipt and
restart accounting, and the update and repair dispatch (PLAN 3.3).

The package upgrade, package reinstall and system repair adapters hold here until their family code is written.
"""
from __future__ import annotations

import copy
import re
from urllib.parse import urlsplit

import pc_paths
import pc_records
from workflow_core import (typed_record, read_record_bytes, exact_fields, utc_time, encoded, digest, EVIDENCE_MAX_BYTES,
                           EXTERNAL_ADAPTER, EXTERNAL_PREFLIGHT, EXTERNAL_RECEIPT, INSTALLER_METADATA, PUBLISHER_SIGNATURE,
                           RESTART_PENDING, RESTART_VERIFICATION, WINDOWS_BOOT)
from scoped_fs import ScopedRoot
from diagnostic_core import CLOCK_STEP_MESSAGE, after_now, stepped_back, SENSITIVE, sanitize_text
from service_state import ServiceRefusal, decoded, private_read, selected_text, service_value, without_version

OFFICIAL_DOMAINS = {
    "windows.msiexec.install": {"learn.microsoft.com", "support.microsoft.com"},
    "macos.installer.pkg": {"support.apple.com", "developer.apple.com"},
    "linux.dpkg.install_local": {"manpages.debian.org", "www.debian.org", "debian.org"},
    "windows.winget.upgrade": {"learn.microsoft.com", "support.microsoft.com"},
    "windows.dism.restorehealth": {"learn.microsoft.com", "support.microsoft.com"},
    "macos.softwareupdate.install": {"support.apple.com", "developer.apple.com"},
    "linux.apt.upgrade_selected": {"manpages.debian.org", "www.debian.org", "debian.org", "ubuntu.com"},
    "linux.dnf.upgrade_selected": {"dnf.readthedocs.io", "dnf5.readthedocs.io", "docs.fedoraproject.org"},
    "linux.dpkg.configure_selected": {"manpages.debian.org", "www.debian.org", "debian.org"},
}
ARTIFACT_EXTENSIONS = {"windows.msiexec.install": {".msi"}, "macos.installer.pkg": {".pkg"},
                       "linux.dpkg.install_local": {".deb"}}


def _named(record, name, message):
    """``record`` through the engine's registered reader for ``name``. An older record keeps the clear
    older-format message; any other refusal is explained by ``message`` and keeps its own code."""
    try:
        return typed_record(record, name)
    except pc_records.Refusal as error:
        raise ServiceRefusal(str(error) if error.code == "older-format" else message, code=error.code) from error


class UpdatesMixin:
    """The reviewed local-installer handoff: plan, preflight proof, receipt and MSI restart accounting."""

    def prepare_external_action(self, session_id, *, action_id, external_plan, inventory,
            target, benefit, risk, reversibility, verification, requires_recovery=False,
            recovery_evidence_ids=None, requires_os_consent=True):
        with self._lock():
            state = self._state(session_id, collecting=True)
            if isinstance(external_plan, dict) and external_plan.get("kind") == "repair":
                raise ServiceRefusal("OS/app repair is held: file-content ZIP recovery cannot establish exact component recovery")
            if external_plan.get("catalog_id") not in ARTIFACT_EXTENSIONS:
                raise ServiceRefusal("Manager handoff held: the current argv cannot enforce exact reviewed content; "
                                     "use a supported fixed local-artifact update")
            if requires_os_consent is not True:
                raise ServiceRefusal("Fixed local installer handoffs require actual coordinator-recorded protected OS consent")
            self.engine.validate_external_plan(state, external_plan, inventory)
            self._external_sources(external_plan)
            payload = {"schema": EXTERNAL_ADAPTER, "schema_version": pc_records.SCHEMA_VERSION, "operation": pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL,
                       "external_plan": copy.deepcopy(external_plan), "external_plan_sha256": digest(external_plan),
                       "inventory_sha256": digest(inventory)}
            return self._action(state, action_id=action_id, adapter_id=payload["operation"], kind=external_plan["kind"],
                    payload=payload, native_plan=payload["external_plan"], inventory=inventory, target=target, benefit=benefit, risk=risk,
                    reversibility=reversibility, verification=verification,
                    requires_recovery=requires_recovery or external_plan["kind"] == "repair",
                    recovery_evidence_ids=recovery_evidence_ids, requires_os_consent=requires_os_consent)

    @staticmethod
    def _external_sources(plan):
        for url in plan["sources"]:
            parsed = urlsplit(url)
            if parsed.hostname not in OFFICIAL_DOMAINS.get(plan["catalog_id"], set()) or parsed.query or parsed.fragment or any(ord(c) <= 32 for c in url):
                raise ServiceRefusal("Selected catalog requires a reviewed primary official source without credential-bearing URL data")
        for value in plan["targets"]:
            if plan["catalog_id"] == "windows.msiexec.install" and re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}", value):
                continue
            if SENSITIVE.search(value):
                raise ServiceRefusal("Potential credential value in external plan refused before persistence")
        for value in [plan["recovery_plan"]["limits"], plan["verification_plan"]["original_success_condition"]]:
            if SENSITIVE.search(value):
                raise ServiceRefusal("Potential credential value in external plan refused before persistence")
        for check in plan["verification_plan"]["checks"]:
            selected_text(check["description"])
            selected_text(check["expected_result"])
        for identity in plan["target_identities"].values():
            for key in ("publisher", "channel", "source_id"):
                selected_text(identity[key])

    def _artifact(self, state, plan, path, expected_sha256):
        value = self._owned(path, state=state)
        if (value.suffix.casefold() not in ARTIFACT_EXTENSIONS.get(plan["catalog_id"], set())
                or pc_paths.protected(value.relative_to(self.root / "work").as_posix())):
            raise ServiceRefusal("Only the selected owned noncredential installer artifact format may be opened")
        with ScopedRoot(value.parent, quiet_workspace=True) as source:
            observed = source.inspect(value.name, hash_file=True, max_bytes=64 * 1024 * 1024)
        if observed["kind"] != "file" or observed["nlink"] != 1 or observed["sha256"] != expected_sha256:
            raise ServiceRefusal("Actual selected installer bytes differ from the reviewed exact content identity")
        return observed

    def _external_preflight(self, state, action, payload, evidence_ids):
        plan = payload["external_plan"]
        rows = self.engine.evidence_rows(state, evidence_ids, kinds={"precondition"}, after=state["plan"]["registered_utc"], seconds=900)
        admitted = False
        for row in rows:
            value = decoded(read_record_bytes(self.engine.work / state["session_id"] / row["path"], EVIDENCE_MAX_BYTES))
            if not isinstance(value, dict) or value.get("schema") != EXTERNAL_PREFLIGHT:
                continue
            typed_record(value, EXTERNAL_PREFLIGHT)
            if (value["action_id"] != action["action_id"] or value["plan_sha256"] != state["plan"]["sha256"]
                    or value["external_plan_sha256"] != digest(plan) or value["mode"] != state["mode"] or value["platform"] != state["platform"]
                    or value["observed_utc"] != row["observed_utc"] or not isinstance(value["targets"], dict)
                    or set(value["targets"]) != set(plan["targets"])):
                raise ServiceRefusal("Preexecution proof must bind this exact reviewed action, target variants and observed time")
            for target, observed in value["targets"].items():
                expected = {**plan["target_identities"][target], "version": plan["target_versions"][target]}
                extras = {"artifact_path", "artifact_record", "signature_evidence_id", "metadata_evidence_id"}
                exact_fields(observed, set(expected) | extras, set(expected) | extras)
                if any(observed[key] != item for key, item in expected.items()):
                    raise ServiceRefusal("Preexecution selected variant differs from the reviewed version/channel/architecture/scope/publisher/content")
                if (observed["artifact_path"] != plan["argv"][1]
                        or self._artifact(state, plan, observed["artifact_path"], expected["content_sha256"]) != observed["artifact_record"]):
                    raise ServiceRefusal("Actual local installer path/native identity differs from the exact approved argv and preflight record")
                signature_row = self.engine.evidence_rows(state, [observed["signature_evidence_id"]], kinds={"research", "precondition"},
                                                          after=state["plan"]["registered_utc"], seconds=900)[0]
                signature = typed_record(decoded(read_record_bytes(self.engine.work / state["session_id"] / signature_row["path"],
                                                                   EVIDENCE_MAX_BYTES)), PUBLISHER_SIGNATURE)
                method = ("windows.authenticode" if state["platform"] == "windows"
                          else "apple.pkgutil_check_signature" if state["platform"] == "macos" else "distribution.signed_metadata")
                required = {"schema": PUBLISHER_SIGNATURE, "mode": state["mode"], "platform": state["platform"],
                            "artifact_sha256": expected["content_sha256"], "publisher": expected["publisher"], "status": "verified",
                            "source_id": expected["source_id"], "method": method, "observed_utc": signature_row["observed_utc"]}
                if without_version(signature) != required:
                    raise ServiceRefusal("Actual selected publisher/signature observation does not match this reviewed artifact and source")
                metadata_row = self.engine.evidence_rows(state, [observed["metadata_evidence_id"]], kinds={"research", "precondition"},
                                                         after=state["plan"]["registered_utc"], seconds=900)[0]
                metadata = typed_record(decoded(read_record_bytes(self.engine.work / state["session_id"] / metadata_row["path"],
                                                                  EVIDENCE_MAX_BYTES)), INSTALLER_METADATA)
                required_metadata = {"schema": INSTALLER_METADATA, "mode": state["mode"], "platform": state["platform"],
                                     "artifact_sha256": expected["content_sha256"], "target_id": target, "version": expected["version"],
                                     **{key: expected[key] for key in ("channel", "architecture", "installation_scope", "publisher", "source_id")},
                                     "observed_utc": metadata_row["observed_utc"]}
                if without_version(metadata) != required_metadata:
                    raise ServiceRefusal("Actual selected package metadata does not match the exact reviewed version/variant/publisher")
            admitted = True
        if not admitted:
            raise ServiceRefusal("Actual selected artifact and publisher/signature preexecution proof is required before a handoff")

    def record_external_preflight(self, session_id, *, action_id, plan_sha256, artifact_paths,
                                  signature_evidence_ids, metadata_evidence_ids, coordinator_verified=False):
        """Record actual selected downloaded bytes and coordinator-verified signature evidence.

        This method verifies hashes; signature trust is attributed to the
        coordinator's actual supported official-tool observation, never inferred
        from a downloaded page or imported approved/signature boolean.
        """
        with self._lock():
            if coordinator_verified is not True:
                raise ServiceRefusal("Current trusted-coordinator payload/signature verification is required")
            state = self._state(session_id, collecting=True)
            action, payload = self._binding(state, action_id, plan_sha256)
            if action["adapter_id"] != pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
                raise ServiceRefusal("External preflight belongs only to an exact reviewed official-tool handoff")
            plan = payload["external_plan"]
            if (not isinstance(artifact_paths, dict) or not isinstance(signature_evidence_ids, dict) or not isinstance(metadata_evidence_ids, dict)
                    or set(artifact_paths) != set(plan["targets"]) or set(signature_evidence_ids) != set(plan["targets"])
                    or set(metadata_evidence_ids) != set(plan["targets"])):
                raise ServiceRefusal("Every exact selected update target needs actual payload and publisher evidence")
            value = {"schema": EXTERNAL_PREFLIGHT, "schema_version": pc_records.SCHEMA_VERSION, "action_id": action_id, "plan_sha256": plan_sha256,
                     "external_plan_sha256": digest(plan), "mode": state["mode"], "platform": state["platform"],
                     "observed_utc": pc_records.utc_now(), "targets": {}}
            for target in plan["targets"]:
                if artifact_paths[target] != plan["argv"][1]:
                    raise ServiceRefusal("Local artifact path must be the exact reviewed fixed argv path")
                artifact_record = self._artifact(state, plan, artifact_paths[target], plan["target_identities"][target]["content_sha256"])
                value["targets"][target] = {**plan["target_identities"][target], "version": plan["target_versions"][target],
                                            "artifact_path": artifact_paths[target], "artifact_record": artifact_record,
                                            "signature_evidence_id": signature_evidence_ids[target], "metadata_evidence_id": metadata_evidence_ids[target]}
            facts = {"action_id": action_id, "plan_sha256": plan_sha256, "identity_matches": True, "scope_matches": True,
                     "content_matches": True, "compatibility_checked": True, "provenance_checked": True}
            facts.update({key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")})
            row = self._register(state, kind="precondition", value=value, facts=facts, observed_utc=value["observed_utc"])
            self._external_preflight(self.engine.read_session(session_id), action, payload, [row["evidence_id"]])
            return row

    def _external_receipt(self, state, operation, intent, actual_receipt, *, after_restart=False):
        typed_record(actual_receipt, EXTERNAL_RECEIPT)
        plan = intent["payload"]["external_plan"]
        expected = {"operation_id": operation["operation_id"],
                    "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"],
                    "adapter_payload_sha256": intent["action"]["adapter_payload_sha256"], "mode": intent["mode"],
                    "platform": intent["platform"], "catalog_id": plan["catalog_id"]}
        if (any(actual_receipt[key] != value for key, value in expected.items()) or not isinstance(actual_receipt["outcome"], str)
                or actual_receipt["outcome"] not in {"succeeded", "failed", "partial", "unknown", "installed_restart_pending"}):
            raise ServiceRefusal("External result differs from the consumed exact handoff")
        observed, started = utc_time(actual_receipt["observed_utc"]), utc_time(operation["started_utc"])
        if stepped_back(observed, started):
            raise ServiceRefusal(CLOCK_STEP_MESSAGE, code="clock-step")
        if not started <= observed or after_now(observed):
            raise ServiceRefusal("External result requires fresh post-start observation")
        code = actual_receipt["tool_exit_code"]
        if code is not None and (type(code) is not int or not -(1 << 31) <= code < (1 << 31)):
            raise ServiceRefusal("Typed actual tool status required")
        if actual_receipt["postcondition_state"] not in {"verified", "not_verified", "unknown"}:
            raise ServiceRefusal("Explicit observed target postcondition state required")
        msi = plan["catalog_id"] == "windows.msiexec.install" and intent["platform"] == "windows"
        if actual_receipt["outcome"] == "installed_restart_pending" and (
                not msi or code != 3010 or actual_receipt["postcondition_state"] == "verified" or after_restart):
            raise ServiceRefusal("Only actual MSI3010 may record installed with restart and behavior verification still pending")
        if msi and code == 3010 and actual_receipt["outcome"] not in ({"succeeded", "failed", "partial"} if after_restart else {"installed_restart_pending"}):
            raise ServiceRefusal("Preserve MSI3010 as restart-pending until its exact later boot and behavior verification")
        if msi and code == 1641 and actual_receipt["outcome"] != "unknown":
            raise ServiceRefusal("Unexpected MSI restart initiation under no-restart arguments requires unknown reconciliation")
        self.engine.evidence_rows(state, actual_receipt["evidence_ids"], after=operation["started_utc"], seconds=900,
                              allow_empty=actual_receipt["outcome"] == "unknown")
        successful_code = code == 0 or after_restart and msi and code == 3010
        if actual_receipt["outcome"] == "succeeded" and (not successful_code or actual_receipt["postcondition_state"] != "verified"):
            raise ServiceRefusal("Success requires actual successful tool status and observed exact target state")
        if after_restart and (not msi or code != 3010 or actual_receipt["outcome"] not in {"succeeded", "failed", "partial"}):
            raise ServiceRefusal("Post-restart completion preserves the original exact MSI3010 status")
        clean = copy.deepcopy(actual_receipt)
        for key in ("observed_effects", "limitations"):
            if not isinstance(clean[key], list) or not 1 <= len(clean[key]) <= 20:
                raise ServiceRefusal("Selected bounded effect and limitation explanations required")
            clean[key] = [sanitize_text(text, limit=2000) for text in clean[key]]
        return clean

    def _restart_boot(self, state, operation, evidence_id):
        row = self.engine.evidence_rows(state, [evidence_id], kinds={"precondition", "outcome"}, after=operation["started_utc"], seconds=900)[0]
        value = typed_record(decoded(private_read(self.engine.work / state["session_id"] / row["path"])), WINDOWS_BOOT)
        if (value["mode"] != state["mode"]
                or value["platform"] != "windows" or value["source"] != "windows.cim_last_boot_up_time"
                or value["observed_utc"] != row["observed_utc"] or utc_time(value["last_boot_utc"]) > utc_time(value["observed_utc"])):
            raise ServiceRefusal("Restart accounting needs an actual selected typed Windows boot observation")
        return value

    def _record_restart_pending(self, state, operation, intent, receipt, boot_evidence_id):
        boot = self._restart_boot(state, operation, boot_evidence_id)
        if not utc_time(boot["last_boot_utc"]) <= utc_time(receipt["observed_utc"]) <= utc_time(boot["observed_utc"]):
            raise ServiceRefusal("Intervening or unaccounted restart cannot become a new assumed restart baseline")
        path = self._operation_dir(state["session_id"], operation["operation_id"]) / "external-restart-pending.json"
        if path.exists():
            if private_read(path) != encoded(receipt):
                raise ServiceRefusal("Original MSI3010 receipt is immutable; no replacement or installer retry")
        else:
            self._immutable(path, receipt)
        pending = {"schema": RESTART_PENDING, "schema_version": pc_records.SCHEMA_VERSION, "session_id": state["session_id"],
                   **{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256", "settings_revision")},
                   "scope_sha256": digest(intent["scope"]), "adapter_payload_sha256": intent["action"]["adapter_payload_sha256"],
                   "external_plan_sha256": digest(intent["payload"]["external_plan"]), "mode": state["mode"], "platform": "windows",
                   "catalog_id": "windows.msiexec.install", "original_exit_code": 3010, "observed_utc": pc_records.utc_now(),
                   "native_receipt_relative_path": path.relative_to(self.root).as_posix(), "native_receipt_sha256": digest(receipt),
                   "before_boot_evidence_id": boot_evidence_id}
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        facts["outcome"] = "unknown"
        row = self._register(state, kind="outcome", value=pending, facts=facts, observed_utc=pending["observed_utc"])
        response = self.engine.record_restart_pending(state["session_id"], operation_id=operation["operation_id"], evidence_id=row["evidence_id"])
        return {"operation_id": operation["operation_id"], "outcome": "installed_restart_pending", "operation_active": True,
                "automatic_retry": False, "restart_executor": False, "receipt": receipt, "evidence_id": row["evidence_id"],
                "instruction": "Installation reported MSI3010. Keep this consumed operation, obtain its separate owner restart decision, "
                               "then verify the actual boot transition and original behavior. Do not rerun the installer.",
                "workflow": response}

    def complete_external(self, session_id, *, operation_id, actual_receipt, coordinator_observed=False, restart_boot_evidence_id=None):
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            state = self.engine.read_session(session_id)
            self._original_authority(state, operation, intent)
            if (coordinator_observed is not True or operation["outcome"] not in {None, "unknown"}
                    or intent["action"]["adapter_id"] != pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL):
                raise ServiceRefusal("Actual trusted-coordinator observation for an active exact external operation is required")
            clean = self._external_receipt(state, operation, intent, actual_receipt)
            if clean["outcome"] == "installed_restart_pending":
                if not isinstance(restart_boot_evidence_id, str):
                    raise ServiceRefusal("MSI3010 requires its fresh owned pre-restart boot observation")
                return self._record_restart_pending(state, operation, intent, clean, restart_boot_evidence_id)
            if operation["outcome"] == "unknown":
                raise ServiceRefusal("Only the exact late MSI3010 receipt can enter restart accounting for this unknown consumed operation")
            if restart_boot_evidence_id is not None or (self._operation_dir(session_id, operation_id) / "external-restart-pending.json").exists():
                raise ServiceRefusal("Use the exact original restart-pending verification path; never translate its exit status to zero")
            return self._finish(state, operation, outcome=clean["outcome"], receipt=clean)

    def complete_external_after_restart(self, session_id, *, operation_id, actual_receipt, verification_evidence_id, coordinator_observed=False):
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            state = self.engine.read_session(session_id)
            self._original_authority(state, operation, intent)
            if (coordinator_observed is not True or operation["outcome"] not in {None, "unknown"}
                    or intent["action"]["adapter_id"] != pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL):
                raise ServiceRefusal("Only the active consumed external operation accepts actual post-restart evidence")
            clean = self._external_receipt(state, operation, intent, actual_receipt, after_restart=True)
            row = self.engine.evidence_rows(state, [verification_evidence_id], kinds={"outcome"}, after=operation["started_utc"], seconds=900)[0]
            proof = _named(decoded(private_read(self.engine.work / session_id / row["path"])), RESTART_VERIFICATION,
                           "Exact typed post-restart verification is required")
            pending_row = self.engine.evidence_rows(state, [proof.get("pending_evidence_id")], kinds={"outcome"}, after=operation["started_utc"])[0]
            pending = _named(decoded(private_read(self.engine.work / session_id / pending_row["path"])), RESTART_PENDING,
                             "The final verification must reference the exact typed restart-pending record")
            original_path = self._operation_dir(session_id, operation_id) / "external-restart-pending.json"
            original_data = private_read(original_path)
            preserved = "Post-restart outcome must preserve the exact original MSI3010 receipt and later verification"
            if (pending.get("native_receipt_relative_path") != original_path.relative_to(self.root).as_posix()
                    or pending.get("native_receipt_sha256") != digest(original_data)):
                raise ServiceRefusal(preserved)
            original = _named(decoded(original_data), EXTERNAL_RECEIPT, preserved)
            if (original.get("tool_exit_code") != 3010 or original.get("outcome") != "installed_restart_pending"
                    or utc_time(clean["observed_utc"]) < utc_time(proof.get("observed_utc"))):
                raise ServiceRefusal(preserved)
            verification = self.engine.record_restart_verification(session_id, operation_id=operation_id, evidence_id=verification_evidence_id)
            if clean["outcome"] == "succeeded" and verification["data"].get("behavior_passed") is not True:
                raise ServiceRefusal("Actual post-restart target or original behavior did not pass; "
                                     "preserve failed or partial effects without claiming success")
            return self._finish(self.engine.read_session(session_id), operation, outcome=clean["outcome"],
                receipt={"external_receipt": clean, "original_restart_pending_receipt": original,
                         "restart_verification_evidence_id": verification_evidence_id},
                kind="reconciliation" if operation["outcome"] == "unknown" else "outcome")

    # Dispatch targets (service_execute.EXECUTE, service_reconcile.RECONCILE; reached only through execute_action and
    # reconcile_operation): the reviewed handoff keeps its own preconditions, begins through service_execute's shared
    # begin step, writes its handoff without an effect boundary and completes through complete_external; the package and
    # repair adapters are not written yet.
    def _execute_package_upgrade(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _execute_package_reinstall(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _execute_system_repair(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _execute_system_reviewed_external(self, session_id, state, action, payload, **arguments):
        if action["requires_os_consent"] is not True:
            raise ServiceRefusal("Fixed local installer dispatch requires actual protected OS consent for this exact action")
        self._external_sources(payload["external_plan"])
        self._external_preflight(state, action, payload, arguments["precondition_evidence_ids"])
        if arguments["diagnostic_fixture_runner"] is not None or arguments["diagnostic_fixture_result"] is not None:
            raise ServiceRefusal("External handoff cannot accept injected adapter output")
        operation, path, intent, stopped = self._begin_adapter(session_id, state, action, payload, action_id=arguments["action_id"],
                                                               plan_sha256=arguments["plan_sha256"],
                                                               precondition_evidence_ids=arguments["precondition_evidence_ids"],
                                                               owner_consent_evidence_id=arguments["owner_consent_evidence_id"])
        if stopped is not None:
            return stopped
        handoff = {**service_value("reviewed_external_handoff"), "operation_id": operation["operation_id"],
                   "action_id": arguments["action_id"], "plan_sha256": arguments["plan_sha256"],
                   "adapter_payload_sha256": action["adapter_payload_sha256"], "mode": state["mode"], "external_plan": payload["external_plan"],
                   "instruction": "Trusted coordinator performs only this exact reviewed official-tool operation through normal host "
                                  "permissions; report actual evidence. This helper executes nothing."}
        self._immutable(path / "handoff.json", handoff)
        return handoff

    def _reconcile_package_upgrade(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)

    def _reconcile_package_reinstall(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)

    def _reconcile_system_repair(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)

    def _reconcile_system_reviewed_external(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)
