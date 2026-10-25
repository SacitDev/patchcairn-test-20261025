"""The reviewed local-installer handoff: its exact plan, its artifact and signature preflight, and the recorded
protected-system consent. Nothing is installed here.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlsplit

from engine_journal import (EXTERNAL_PLAN, EXTERNAL_PREFLIGHT, EXTERNAL_RECOVERY, EXTERNAL_VERIFICATION, INSTALLER_METADATA, PUBLISHER_SIGNATURE, SHA,
                            WorkflowRefusal, bounded_text, decode_record, exact_fields, fresh, record_identifier, require_writable, typed_record)
from engine_plans import action_binding, current_plan, owner_record
import pc_paths
from pc_records import digest


def validate_external_plan(engine, state, plan, inventory):
    typed_record(plan, EXTERNAL_PLAN)
    if (plan["kind"] not in {"update", "repair"} or plan["platform"] != state["platform"] or plan["mode"] != state["mode"]
            or plan["scope"] != state["settings"]["scope"]):
        raise WorkflowRefusal("External plan must bind this exact session's kind, platform, mode and scope")
    if plan["kind"] == "repair":
        raise WorkflowRefusal("This component repair is held: no supported component-specific rollback verifier or separately authorized no-recovery-risk "
                              "policy exists. An ordinary file ZIP and restore probe cannot establish operating-system or application rollback")
    targets = plan["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 20 or any(not isinstance(t, str) for t in targets) or len(set(targets)) != len(targets):
        raise WorkflowRefusal("External plan needs explicit unique bounded targets")
    versions = plan["target_versions"]
    if (not isinstance(versions, dict) or set(versions) != (set(targets) if plan["kind"] == "update" else set())
            or any(not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~:^-]{0,127}", version) for version in versions.values())):
        raise WorkflowRefusal("Update handoffs require an exact reviewed version for every target; repair version map must be empty")
    identities = plan["target_identities"]
    if not isinstance(identities, dict) or set(identities) != (set(targets) if plan["kind"] == "update" else set()):
        raise WorkflowRefusal("Every update target requires exact channel, architecture, publisher, content and source identities")
    for identity in identities.values():
        fields = {"channel", "architecture", "publisher", "content_sha256", "source_id", "installation_scope"}
        exact_fields(identity, fields, fields)
        if (any(not isinstance(identity[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", identity[key])
                or identity[key].lower() in {"unknown", "latest", "any"} for key in ("channel", "source_id"))
                or identity["architecture"] not in {"x86", "x64", "arm64", "universal", "all"} or not isinstance(identity["content_sha256"], str)
                or not SHA.fullmatch(identity["content_sha256"])):
            raise WorkflowRefusal("Update artifact/channel/architecture/source identities must be exact and known")
        publisher = bounded_text(identity["publisher"], "verified publisher", 200)
        if publisher.lower() in {"unknown", "latest", "any"} or any(ord(char) < 32 for char in publisher):
            raise WorkflowRefusal("An exact reviewed nonsecret publisher identity is required")
    catalog = plan["catalog_id"]
    mapping = {"windows.msiexec.install": ("windows", "update", "msiexec.exe"), "macos.installer.pkg": ("macos", "update", "/usr/sbin/installer"),
               "linux.dpkg.install_local": ("linux", "update", "/usr/bin/dpkg")}
    if catalog not in mapping or (plan["platform"], plan["kind"], plan["official_tool"]) != mapping[catalog]:
        raise WorkflowRefusal("Manager or unknown handoffs that cannot consume the exact reviewed artifact stay held; only the fixed local MSI, PKG and DEB "
                              "catalogs are supported")
    target_pattern = r"(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}|\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})"
    if (len(targets) != 1 or not re.fullmatch(target_pattern, targets[0]) or not isinstance(plan["argv"], list) or not 2 <= len(plan["argv"]) <= 5
            or any(not isinstance(arg, str) or len(arg) > 2000 or any(ord(char) < 32 for char in arg) for arg in plan["argv"])):
        raise WorkflowRefusal("A local installer handoff needs one exact target and bounded fixed literal arguments")
    artifact = Path(plan["argv"][1])
    if not artifact.is_absolute() or ".." in artifact.parts:
        raise WorkflowRefusal("The local installer must consume an exact absolute owned artifact path")
    try:
        artifact.relative_to(engine.root / "work")
    except ValueError as error:
        raise WorkflowRefusal("The approved local installer artifact must be under owned repository work") from error
    suffix = {"windows.msiexec.install": ".msi", "macos.installer.pkg": ".pkg", "linux.dpkg.install_local": ".deb"}[catalog]
    if artifact.suffix.casefold() != suffix:
        raise WorkflowRefusal("This fixed local installer catalog cannot consume that artifact format")
    argv = (["/i", str(artifact), "/passive", "/norestart"] if catalog == "windows.msiexec.install" else ["-pkg", str(artifact), "-target", "/"]
            if catalog == "macos.installer.pkg" else ["--install", str(artifact)])
    identity = identities[targets[0]]
    allowed_scopes = {"user", "machine"} if plan["platform"] == "windows" else {"system"}
    allowed_architectures = {"windows": {"x86", "x64", "arm64"}, "macos": {"x64", "arm64", "universal"},
                             "linux": {"x86", "x64", "arm64", "all"}}[plan["platform"]]
    if identity["installation_scope"] not in allowed_scopes or identity["architecture"] not in allowed_architectures or identity["channel"] != "stable":
        raise WorkflowRefusal("This fixed local installer route requires the reviewed stable package and supported installation scope")
    if plan["argv"] != argv:
        raise WorkflowRefusal("External argv differs from the fixed catalog grammar; no free-form command handoff")
    sources = plan["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 20:
        raise WorkflowRefusal("Exact reviewed official HTTPS sources are required")
    for source in sources:
        bounded_text(source, "official source URL", 2000)
        parsed = urlsplit(source)
        if (parsed.scheme != "https" or not parsed.hostname or "." not in parsed.hostname or parsed.username or parsed.password
                or parsed.port not in {None, 443}):
            raise WorkflowRefusal("External source must be an explicit ordinary HTTPS URL without credentials")
    engine.evidence_rows(state, plan["provenance_evidence_ids"], kinds={"research", "review", "inventory"})
    engine.evidence_rows(state, plan["compatibility_evidence_ids"], kinds={"research", "review", "inventory"})
    recovery = typed_record(plan["recovery_plan"], EXTERNAL_RECOVERY)
    if recovery["strategy"] not in {"verified_backup", "publisher_rollback", "no_verified_rollback"} or digest(recovery) != plan["recovery_plan_sha256"]:
        raise WorkflowRefusal("External recovery plan and exact limits must be reviewed and hash-bound")
    bounded_text(recovery["limits"], "recovery limits", 2000)
    engine.evidence_rows(state, recovery["evidence_ids"], allow_empty=recovery["strategy"] == "no_verified_rollback")
    if recovery["strategy"] == "verified_backup":
        engine.verify_recovery(state, recovery["evidence_ids"])
    verification = typed_record(plan["verification_plan"], EXTERNAL_VERIFICATION)
    if digest(verification) != plan["verification_plan_sha256"] or not isinstance(verification["checks"], list) or not 1 <= len(verification["checks"]) <= 20:
        raise WorkflowRefusal("An exact behavior verification plan is required for the external handoff")
    bounded_text(verification["original_success_condition"], "original success condition", 2000)
    seen = set()
    for check in verification["checks"]:
        exact_fields(check, {"check_id", "description", "expected_result"}, {"check_id", "description", "expected_result"})
        record_identifier(check["check_id"])
        if check["check_id"] in seen:
            raise WorkflowRefusal("Verification check IDs must be unique")
        seen.add(check["check_id"])
        bounded_text(check["description"], "verification check", 2000)
        bounded_text(check["expected_result"], "expected verification result", 2000)


def external_preflight(engine, state, action, rows):
    payload = action_binding(engine, state, action)
    external = payload["external_plan"]
    for row in rows:
        proof = typed_record(decode_record(engine.journal.read_owned(engine.journal.directory(state["session_id"]) / row["path"])), EXTERNAL_PREFLIGHT)
        if (proof["action_id"] != action["action_id"] or proof["plan_sha256"] != state["plan"]["sha256"]
                or proof["external_plan_sha256"] != action["adapter_plan_sha256"] or proof["mode"] != state["mode"] or proof["platform"] != state["platform"]
                or not isinstance(proof["targets"], dict) or set(proof["targets"]) != set(external["targets"])):
            raise WorkflowRefusal("An external handoff requires an actual exact current artifact/provenance preflight before the mutation ticket")
        fresh(proof["observed_utc"], after=state["plan"]["registered_utc"], seconds=900)
        for target, observed in proof["targets"].items():
            identity = external["target_identities"][target]
            expected = {**identity, "version": external["target_versions"][target]}
            additional = {"artifact_path", "artifact_record", "signature_evidence_id", "metadata_evidence_id"}
            exact_fields(observed, set(expected) | additional, set(expected) | additional)
            if any(observed[key] != value for key, value in expected.items()):
                raise WorkflowRefusal("Actual selected artifact version, variant, publisher or source differs from the reviewed offer")
            if observed["artifact_path"] != external["argv"][1]:
                raise WorkflowRefusal("The fixed installer arguments must consume the exact artifact whose actual identity and content were verified")
            artifact = Path(bounded_text(observed["artifact_path"], "selected official artifact", 2000))
            if not artifact.is_absolute() or ".." in artifact.parts:
                raise WorkflowRefusal("Select the exact owned work artifact before content verification")
            try:
                relative = artifact.relative_to(engine.root / "work").as_posix()
            except ValueError as error:
                raise WorkflowRefusal("External preflight artifacts must remain in owned repository work") from error
            if pc_paths.protected(relative) or artifact.suffix.casefold() not in {".msi", ".pkg", ".deb"}:
                raise WorkflowRefusal("Known private-store names and unsupported external artifact formats stay unopened")
            engine.reverify({"kind": "installer_artifact", "path": str(artifact), "record": observed["artifact_record"],
                          "sha256": identity["content_sha256"]})
            signature_row = engine.evidence_rows(state, [observed["signature_evidence_id"]], kinds={"research", "precondition"},
                                                 after=state["plan"]["registered_utc"], seconds=900)[0]
            signature = typed_record(decode_record(engine.journal.read_owned(engine.journal.directory(state["session_id"]) / signature_row["path"])),
                                     PUBLISHER_SIGNATURE)
            method = {"windows": "windows.authenticode", "macos": "apple.pkgutil_check_signature", "linux": "distribution.signed_metadata"}[state["platform"]]
            if (signature["mode"] != state["mode"] or signature["platform"] != state["platform"] or signature["artifact_sha256"] != identity["content_sha256"]
                    or signature["publisher"] != identity["publisher"] or signature["source_id"] != identity["source_id"] or signature["method"] != method
                    or signature["status"] != "verified"):
                raise WorkflowRefusal("A current actual publisher/signature verification receipt for the exact artifact and source is required")
            fresh(signature["observed_utc"], after=state["plan"]["registered_utc"], seconds=900)
            metadata_row = engine.evidence_rows(state, [observed["metadata_evidence_id"]], kinds={"research", "precondition"},
                                                after=state["plan"]["registered_utc"], seconds=900)[0]
            metadata = typed_record(decode_record(engine.journal.read_owned(engine.journal.directory(state["session_id"]) / metadata_row["path"])),
                                    INSTALLER_METADATA)
            if (metadata["mode"] != state["mode"] or metadata["platform"] != state["platform"] or metadata["artifact_sha256"] != identity["content_sha256"]
                    or metadata["target_id"] != target or any(metadata[key] != value for key, value in expected.items() if key != "content_sha256")):
                raise WorkflowRefusal("Actual package metadata does not establish the approved version, variant, publisher and source for this exact artifact")
            fresh(metadata["observed_utc"], after=state["plan"]["registered_utc"], seconds=900)


def record_protected_consent(engine, session_id, *, action_id, plan_sha256, evidence_id, owner_quote, owner_message_id, owner_id=None,
                             source="current_owner_chat", expected_revision=None):
    def mutate(state):
        require_writable(state)
        document = current_plan(state, plan_sha256)
        if action_id not in {a["action_id"] for a in document["actions"] if a["requires_os_consent"]}:
            raise WorkflowRefusal("This is not a protected-consent action in the current plan")
        rows = engine.evidence_rows(state, [evidence_id], kinds={"protected_consent"}, after=state["plan"]["registered_utc"], seconds=900)
        facts = rows[0]["facts"]
        if facts.get("plan_sha256") != plan_sha256 or facts.get("action_id") != action_id or facts.get("actual_os_consent") is not True:
            raise WorkflowRefusal("Record the actual protected consent result for this exact action")
        record = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        record.update(plan_sha256=plan_sha256, action_id=action_id, evidence_id=evidence_id)
        key = "consent-" + action_id
        state["pending"][key] = {"pending_id": key, "kind": "protected_consent", "resolved": True, "record": record}
        return {}, "The owner's actual protected-system consent result is recorded; the helper does not bypass or click that prompt."
    return engine.change(session_id, "protected_consent_recorded", mutate, expected_revision)
