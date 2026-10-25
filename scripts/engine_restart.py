"""Accounting for an installer that reported a needed restart (exit code 3010): its receipts, the owner's restart
decision and the post-restart checks. No restart is performed here.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

from pathlib import PurePosixPath

from engine_journal import (BACKEND, EXTERNAL_RECEIPT, RESTART_PENDING, RESTART_VERIFICATION, SERVICE_RECORD, WINDOWS_BOOT, WorkflowRefusal, bounded_text,
                            checked, decode_record, exact_fields, fresh, outstanding_effects, read_record_bytes, record_identifier, require_writable,
                            typed_record, utc_time)
from engine_plans import owner_record
import pc_records
from pc_records import digest


def _without_version(record):
    """A copy of a validated record without its schema_version, for comparing the remaining fields."""
    rest = dict(record)
    rest.pop("schema_version", None)
    return rest


def _restart_evidence(engine, state, evidence_id, kinds):
    record_identifier(evidence_id)
    row = state["evidence"].get(evidence_id)
    if not row or row["kind"] not in kinds or row["scope"] != state["settings"]["scope"] or row["settings_revision"] != state["settings_revision"]:
        raise WorkflowRefusal("Restart evidence must retain this operation's original current scope and settings")
    data = engine.journal.read_owned(engine.journal.directory(state["session_id"]) / row["path"])
    if digest(data) != row["sha256"] or len(data) != row["size"]:
        raise WorkflowRefusal("Original restart evidence bytes changed")
    return row, decode_record(data)


def _restart_context(engine, state, operation):
    if (operation["adapter_id"] != pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL or operation["settings_revision"] != state["settings_revision"]
            or not state["plan"] or operation["plan_sha256"] != state["plan"]["sha256"] or state["platform"] != "windows"):
        raise WorkflowRefusal("A restart continuation must retain the exact original Windows MSI operation, plan and scope")
    action = next((item for item in state["plan"]["document"]["actions"] if item["action_id"] == operation["action_id"]), None)
    if not action or action["adapter_id"] != operation["adapter_id"]:
        raise WorkflowRefusal("The restart action is not the original consumed handoff")
    row, payload = _restart_evidence(engine, state, action["adapter_payload_evidence_id"], {"adapter_payload"})
    if (row["sha256"] != action["adapter_payload_sha256"] or payload.get("operation") != operation["adapter_id"]
            or digest(payload.get("external_plan")) != action["adapter_plan_sha256"] or payload.get("external_plan_sha256") != action["adapter_plan_sha256"]):
        raise WorkflowRefusal("Original MSI payload bytes or plan binding changed")
    external = payload["external_plan"]
    if (external.get("catalog_id") != "windows.msiexec.install" or external.get("kind") != "update" or external.get("mode") != state["mode"]
            or external.get("platform") != "windows" or external.get("scope") != state["settings"]["scope"]):
        raise WorkflowRefusal("Only the exact fixed MSI local-install recipe supports this restart continuation")
    return action, external


def _restart_boot(engine, state, evidence_id):
    row, boot = _restart_evidence(engine, state, evidence_id, {"precondition", "outcome"})
    typed_record(boot, WINDOWS_BOOT)
    if (boot["mode"] != state["mode"] or boot["platform"] != "windows" or boot["source"] != "windows.cim_last_boot_up_time"
            or boot["observed_utc"] != row["observed_utc"] or utc_time(boot["last_boot_utc"]) > utc_time(boot["observed_utc"])):
        raise WorkflowRefusal("Restart checks require an exact owned actual Windows boot observation")
    return row, boot


def _restart_pending(engine, state, operation, evidence_id):
    action, external = _restart_context(engine, state, operation)
    row, proof = _restart_evidence(engine, state, evidence_id, {"outcome"})
    typed_record(proof, RESTART_PENDING)
    expected = {"session_id": state["session_id"], "operation_id": operation["operation_id"], "action_id": operation["action_id"],
                "plan_sha256": operation["plan_sha256"], "settings_revision": state["settings_revision"], "scope_sha256": digest(state["settings"]["scope"]),
                "adapter_payload_sha256": action["adapter_payload_sha256"], "external_plan_sha256": action["adapter_plan_sha256"], "mode": state["mode"],
                "platform": "windows", "catalog_id": "windows.msiexec.install", "original_exit_code": 3010}
    if (any(proof[key] != value for key, value in expected.items()) or type(proof["original_exit_code"]) is not int
            or proof["observed_utc"] != row["observed_utc"]):
        raise WorkflowRefusal("The restart-pending receipt must bind the exact original 3010 operation")
    relative = PurePosixPath(bounded_text(proof["native_receipt_relative_path"], "owned original MSI receipt", 2000))
    tail = ("operations", state["session_id"], operation["operation_id"], "external-restart-pending.json")
    if (relative.is_absolute() or "\\" in str(relative) or any(part in {".", ".."} or ":" in part for part in relative.parts) or len(relative.parts) < 6
            or relative.parts[0] != "work" or tuple(relative.parts[-4:]) != tail):
        raise WorkflowRefusal("The original restart receipt must stay in its exact private service operation")
    service_root = engine.root.joinpath(*relative.parts[:-4])
    marker = checked(pc_records.require_schema, decode_record(read_record_bytes(service_root / "service.json", 10000, private=True)), SERVICE_RECORD)
    if _without_version(marker) != {"schema": SERVICE_RECORD, "kind": "service_marker", "engine_id": state["engine_id"], "backend": BACKEND}:
        raise WorkflowRefusal("The restart receipt belongs to a foreign service or engine")
    native = typed_record(decode_record(engine.work_artifact(str(engine.root.joinpath(*relative.parts)), proof["native_receipt_sha256"],
                                                             output_root=service_root, max_bytes=8_000_000)), EXTERNAL_RECEIPT)
    if (any(native[key] != expected[key] for key in ("operation_id", "action_id", "plan_sha256", "adapter_payload_sha256", "mode", "platform", "catalog_id"))
            or type(native["tool_exit_code"]) is not int or native["tool_exit_code"] != 3010 or native["outcome"] != "installed_restart_pending"
            or native["postcondition_state"] not in {"not_verified", "unknown"}
            or not utc_time(operation["started_utc"]) <= utc_time(native["observed_utc"]) <= utc_time(proof["observed_utc"])):
        raise WorkflowRefusal("An actual original MSI 3010 receipt is required; another exit code cannot be translated into success")
    before_row, before = _restart_boot(engine, state, proof["before_boot_evidence_id"])
    if (not utc_time(native["observed_utc"]) <= utc_time(before["observed_utc"]) <= utc_time(proof["observed_utc"])
            or utc_time(before["last_boot_utc"]) > utc_time(native["observed_utc"])):
        raise WorkflowRefusal("The actual pre-restart boot observation does not bind the original tool receipt")
    return row, proof, before_row, before, action, external


def record_restart_pending(engine, session_id, *, operation_id, evidence_id, expected_revision=None):
    record_identifier(operation_id)
    def mutate(state):
        if state["status"] != "stopped":
            require_writable(state)
        operation = state["operations"].get(operation_id)
        if not operation or operation["outcome"] not in {None, "unknown"} or operation["resolution"]:
            raise WorkflowRefusal("Only the exact active or unresolved-unknown consumed operation accepts a restart-pending receipt")
        row, proof, before_row, before, _, _ = _restart_pending(engine, state, operation, evidence_id)
        fresh(proof["observed_utc"], after=operation["started_utc"], seconds=900)
        fresh(before["observed_utc"], after=operation["started_utc"], seconds=900)
        existing = operation.get("restart_pending")
        if existing:
            if existing["evidence_id"] != evidence_id or existing["sha256"] != row["sha256"]:
                raise WorkflowRefusal("The original restart-pending receipt cannot be replaced")
            return existing, "The exact restart-pending receipt is already retained; no action was retried."
        record = {"evidence_id": evidence_id, "sha256": row["sha256"], "before_boot_evidence_id": proof["before_boot_evidence_id"],
                  "before_boot_sha256": before_row["sha256"], "original_exit_code": 3010, "recorded_utc": pc_records.utc_now(), "decision_ids": []}
        operation["restart_pending"] = record
        key = "restart-" + operation_id
        state["pending"][key] = {"pending_id": key, "kind": "restart", "operation_id": operation_id, "resolved": False, "created_utc": pc_records.utc_now()}
        return (record, "The installer reported that a restart is needed. Its original 3010 receipt is retained and this same operation is unfinished. Choose "
                        "whether to defer or authorize an owner-handled restart; no restart or installer retry was performed.")
    return engine.change(session_id, "restart_pending", mutate, expected_revision)


def decide_restart(engine, session_id, *, operation_id, choice, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat",
                   expected_revision=None):
    if choice not in {"defer", "authorize"}:
        raise WorkflowRefusal("Choose defer or authorize for this exact pending restart")
    def mutate(state):
        if state["status"] != "stopped":
            require_writable(state)
        owner = owner_record(state, owner_quote, owner_message_id, owner_id, source)
        operation = state["operations"].get(operation_id)
        if not operation or operation["outcome"] not in {None, "unknown"} or operation["resolution"] or not operation.get("restart_pending"):
            raise WorkflowRefusal("A restart decision requires the exact unfinished operation and actual 3010 safe-checkpoint receipt")
        pending = operation["restart_pending"]
        if operation.get("restart_verification"):
            raise WorkflowRefusal("This restart is already verified; record its actual outcome rather than authorizing another restart")
        _restart_pending(engine, state, operation, pending["evidence_id"])
        proposal = state["schedule"] if state["settings"]["timing"] == "scheduled" else None
        if state["settings"]["timing"] == "scheduled" and (not proposal or proposal.get("schedule_id") != engine.schedule_identity(proposal)):
            raise WorkflowRefusal("Scheduled restart continuation needs a current actual owner proposal")
        if choice == "authorize" and any(item["operation_id"] != operation_id or item["session_id"] != session_id for item in outstanding_effects(engine)):
            raise WorkflowRefusal("Unrelated uncertain work must be reconciled before an owner-handled restart")
        if owner_message_id in pending["decision_ids"]:
            existing = operation.get("restart_decision")
            if (existing and existing["message_id"] == owner_message_id and existing["choice"] == choice and existing["quote"] == owner_quote
                    and existing["schedule_id"] == (proposal["schedule_id"] if proposal else None)):
                return existing, "This exact restart decision is already recorded; no restart was performed."
            raise WorkflowRefusal("A different restart choice needs a fresh actual owner decision")
        if len(pending["decision_ids"]) >= 100:
            raise WorkflowRefusal("The bounded restart-decision history is full; preserve this held operation")
        record = owner
        not_before = max((record["recorded_utc"], proposal["proposal"]["when_utc"]), key=utc_time) if proposal else record["recorded_utc"]
        record.update(choice=choice, operation_id=operation_id, action_id=operation["action_id"], plan_sha256=operation["plan_sha256"],
                      scope_sha256=digest(state["settings"]["scope"]), pending_evidence_id=pending["evidence_id"],
                      schedule_id=proposal["schedule_id"] if proposal else None, not_before_utc=not_before)
        pending["decision_ids"].append(owner_message_id)
        operation["restart_decision"] = record
        operation.pop("restart_verification", None)
        message = ("The restart is deferred and the same consumed operation remains unfinished. No installer retry or other change is authorized."
                   if choice == "defer"
                   else "Your decision authorizes only the owner-handled restart for this exact operation, no earlier than its agreed time. No restart was "
                        "performed here. Any existing pause remains in place for subsequent work, and actual post-restart verification is still required.")
        if state["status"] == "stopped":
            message += (" This is accounting for the retained unfinished effect only: the session stays stopped, with no new job action, plan or operation "
                        "ticket.")
        return record, message
    with engine.journal.registry_lock():
        return engine.change(session_id, "restart_decision", mutate, expected_revision)


def validate_restart_verification(engine, state, operation, evidence_id):
    pending = operation.get("restart_pending")
    decision = operation.get("restart_decision")
    if not pending or not decision or decision["choice"] != "authorize":
        raise WorkflowRefusal("Actual post-restart verification needs the prior exact owner authorization")
    pending_row, pending_proof, before_row, before, action, external = _restart_pending(engine, state, operation, pending["evidence_id"])
    if (pending_row["sha256"] != pending["sha256"] or before_row["sha256"] != pending["before_boot_sha256"]
            or decision["settings_revision"] != state["settings_revision"] or decision["scope_sha256"] != digest(state["settings"]["scope"])
            or decision["plan_sha256"] != operation["plan_sha256"]):
        raise WorkflowRefusal("Restart authorization or its original proof changed")
    current_schedule = state["schedule"] if state["settings"]["timing"] == "scheduled" else None
    if decision["schedule_id"] != (current_schedule["schedule_id"] if current_schedule else None):
        raise WorkflowRefusal("The restart choice belongs to an earlier schedule; obtain a fresh owner decision")
    row, proof = _restart_evidence(engine, state, evidence_id, {"outcome"})
    typed_record(proof, RESTART_VERIFICATION)
    expected = {"session_id": state["session_id"], "operation_id": operation["operation_id"], "action_id": operation["action_id"],
                "plan_sha256": operation["plan_sha256"], "settings_revision": state["settings_revision"], "scope_sha256": digest(state["settings"]["scope"]),
                "external_plan_sha256": action["adapter_plan_sha256"], "mode": state["mode"], "platform": "windows", "catalog_id": "windows.msiexec.install",
                "original_exit_code": 3010, "pending_evidence_id": pending["evidence_id"], "restart_decision_message_id": decision["message_id"],
                "before_boot_evidence_id": pending["before_boot_evidence_id"]}
    if (any(proof[key] != value for key, value in expected.items()) or type(proof["original_exit_code"]) is not int
            or proof["observed_utc"] != row["observed_utc"]):
        raise WorkflowRefusal("Post-restart verification must bind the exact original 3010 receipt and owner decision")
    fresh(proof["observed_utc"], after=decision["recorded_utc"], seconds=900)
    _, after = _restart_boot(engine, state, proof["after_boot_evidence_id"])
    fresh(after["observed_utc"], after=decision["recorded_utc"], seconds=900)
    if (not utc_time(before["last_boot_utc"]) < utc_time(after["last_boot_utc"])
            or not utc_time(pending_proof["observed_utc"]) <= utc_time(decision["recorded_utc"]) < utc_time(after["last_boot_utc"])
            <= utc_time(after["observed_utc"]) <= utc_time(proof["observed_utc"]) or utc_time(after["last_boot_utc"]) < utc_time(decision["not_before_utc"])):
        raise WorkflowRefusal("An actual boot transition after the owner decision and agreed time is required")
    if not isinstance(proof["targets"], dict) or set(proof["targets"]) != set(external["targets"]):
        raise WorkflowRefusal("Post-restart checks must account for every exact selected target")
    all_passed = True
    for target in external["targets"]:
        expected_target = {key: external["target_identities"][target][key] for key in ("architecture", "installation_scope", "publisher")}
        expected_target["version"] = external["target_versions"][target]
        actual_target = proof["targets"][target]
        exact_fields(actual_target, set(expected_target), set(expected_target))
        for value in actual_target.values():
            bounded_text(value, "selected actual target observation", 512)
        if actual_target != expected_target:
            all_passed = False
    checks = external["verification_plan"]["checks"]
    if not isinstance(proof["checks"], list) or len(proof["checks"]) != len(checks):
        raise WorkflowRefusal("Post-restart behavior must cover the original verification plan")
    for actual, expected_check in zip(proof["checks"], checks):
        exact_fields(actual, {"check_id", "outcome", "observation"}, {"check_id", "outcome", "observation"})
        if actual["check_id"] != expected_check["check_id"] or actual["outcome"] not in {"passed", "failed", "unknown"}:
            raise WorkflowRefusal("The observations must identify every original behavior check and its actual result")
        if actual["outcome"] != "passed":
            all_passed = False
        bounded_text(actual["observation"], "selected actual post-restart observation", 2000)
    return row, all_passed


def record_restart_verification(engine, session_id, *, operation_id, evidence_id, expected_revision=None):
    def mutate(state):
        if state["status"] != "stopped":
            require_writable(state)
        operation = state["operations"].get(operation_id)
        if not operation or operation["outcome"] not in {None, "unknown"}:
            raise WorkflowRefusal("Only the exact unfinished restart operation accepts this observation")
        row, all_passed = validate_restart_verification(engine, state, operation, evidence_id)
        record = {"evidence_id": evidence_id, "sha256": row["sha256"], "recorded_utc": pc_records.utc_now(), "boot_observed": True,
                  "behavior_passed": all_passed}
        operation["restart_verification"] = record
        state["pending"]["restart-" + operation_id]["resolved"] = True
        return (record, "Actual boot, target and original behavior observations are recorded for the same operation. "
                + ("The exact target and original behavior checks passed. " if all_passed
                   else "Some target or behavior results failed or remain unknown; record the actual failed/partial result and review recovery. ")
                + "The original 3010 code is preserved; this record does not itself finish or retry the installer.")
    return engine.change(session_id, "restart_verified", mutate, expected_revision)
