"""Recovery checks: the backup, restore and quarantine receipts that a dependent action needs, with their bytes
re-read from disk by the verifier the service injects.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

import copy
from pathlib import Path

from engine_journal import (EVIDENCE_MAX_BYTES, EVIDENCE_MAX_NODES, QUARANTINE_RECOVERY, RECOVERY_BINDING, RECOVERY_RETENTION, SHA, WorkflowRefusal,
                            bounded_text, checked, decode_record, no_links, private_directory, read_record_bytes, typed_record)
import pc_records
from pc_records import digest
import storage_contract


SERVICE_RECORD_MAX_BYTES = 8_000_000


def _storage_record(value, kind, message):
    """Return a typed storage record of ``kind``; ``message`` explains a missing or different kind."""
    if not isinstance(value, dict) or value.get("kind") != kind:
        raise WorkflowRefusal(message)
    return checked(storage_contract.read_storage, value)


def reverify(engine, binding):
    """Re-read recovery or artifact bytes from disk through the injected verifier (D-018, PD-3)."""
    if engine.verify_artifact is None:
        raise WorkflowRefusal("Recovery and artifact bytes cannot be re-checked without the service's storage verifier; the action is held",
                              code="verifier-missing")
    try:
        result = engine.verify_artifact(copy.deepcopy(binding))
    except WorkflowRefusal:
        raise
    except pc_records.Refusal as error:
        raise WorkflowRefusal(str(error), code=error.code) from error
    if result is not None:
        raise WorkflowRefusal("The artifact verifier must return nothing and refuse by raising", code="verifier-contract")


def _owned_output(engine, value):
    root = Path(bounded_text(value, "recovery output root", 2000))
    if not root.is_absolute():
        raise WorkflowRefusal("Recovery output root must be an exact absolute owned work path")
    root = no_links(root)
    try:
        root.relative_to(engine.root / "work")
    except ValueError as error:
        raise WorkflowRefusal("Recovery artifacts must remain in the exact owned work output root") from error
    return root


def work_artifact(engine, path, expected_sha256, *, output_root, max_bytes=SERVICE_RECORD_MAX_BYTES):
    """Bytes of a private record under an owned work root (a service receipt), admitted before they are read."""
    value = Path(bounded_text(path, "owned record path", 2000))
    if not value.is_absolute() or output_root is None or not Path(output_root).is_absolute():
        raise WorkflowRefusal("Owned records need exact absolute owned work paths")
    value, output_root = no_links(value), _owned_output(engine, str(output_root))
    try:
        relative = value.relative_to(output_root)
    except ValueError as error:
        raise WorkflowRefusal("Owned records must remain in the exact owned work root") from error
    current = private_directory(output_root)
    for part in relative.parts[:-1]:
        current = private_directory(current / part)
    data = read_record_bytes(value, max_bytes, private=True)
    if not isinstance(expected_sha256, str) or digest(data) != expected_sha256:
        raise WorkflowRefusal("Required owned record bytes changed")
    return data


def _retention(engine, state, evidence_id):
    row = engine.evidence_rows(state, [evidence_id], kinds={"retention"})[0]
    data = engine.journal.read_owned(engine.journal.directory(state["session_id"]) / row["path"], EVIDENCE_MAX_BYTES)
    retention = typed_record(decode_record(data, max_bytes=EVIDENCE_MAX_BYTES, max_nodes=EVIDENCE_MAX_NODES), RECOVERY_RETENTION)
    if retention["session_id"] != state["session_id"] or retention["required"] is not True or not isinstance(retention["artifacts"], dict):
        raise WorkflowRefusal("A current exact retention record must protect every actual required recovery artifact")
    return retention["artifacts"]


def _quarantine_recovery(engine, state, binding, action):
    typed_record(binding, QUARANTINE_RECOVERY)
    if (not action or action["adapter_id"] != pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE or binding["restore_plan_sha256"] != action["adapter_plan_sha256"]
            or digest(binding["restore_plan"]) != action["adapter_plan_sha256"]):
        raise WorkflowRefusal("Quarantine recovery applies only to its exact reviewed quarantine-restore action, never to a generic repair or purge")
    payload = engine.action_binding(state, action)
    if (payload["output_root"] != binding["output_root"] or payload["storage_plan"] != binding["restore_plan"]
            or payload["storage_plan"].get("receipt") != binding["quarantine_receipt"]):
        raise WorkflowRefusal("Quarantine recovery differs from the exact approved native restore mapping")
    output, receipt = _owned_output(engine, binding["output_root"]), binding["quarantine_receipt"]
    try:
        attempt_path = output / receipt["attempt"]
        retained = {str(output / ("outcome-quarantine-" + receipt["plan_sha256"] + ".json")): digest(receipt)}
        retained.update({str(output / row["quarantine_record"]["relative_path"]): row["quarantine_record"]["sha256"] for row in receipt["records"]})
    except (KeyError, TypeError) as error:
        raise WorkflowRefusal("Quarantine recovery needs the exact typed original quarantine receipt") from error
    artifacts = _retention(engine, state, binding["retention_evidence_id"])
    # The attempt record's digest is checked against its bytes by the verifier.
    retained[str(attempt_path)] = artifacts.get(str(attempt_path))
    if not isinstance(retained[str(attempt_path)], str) or artifacts != retained:
        raise WorkflowRefusal("A current exact retention record must protect every actual required recovery artifact")
    reverify(engine, {"kind": "quarantine_recovery", "output_root": str(output), "protected_roots": payload["protected_roots"],
                  "restore_plan": binding["restore_plan"], "restore_plan_sha256": action["adapter_plan_sha256"],
                  "attempt": receipt["attempt"], "attempt_sha256": retained[str(attempt_path)]})


def verify_recovery(engine, state, evidence_ids, *, action=None):
    purge_payload = original = None
    if action and action["adapter_id"] == pc_records.ADAPTER_STORAGE_PURGE:
        purge_payload = engine.action_binding(state, action)
        original = _storage_record(purge_payload["storage_plan"].get("receipt"), "quarantine_receipt",
                                   "Purge recovery requires the exact original typed quarantine receipt")
        if (original.get("recovery_required") is not True or not isinstance(original.get("recovery_backup"), dict)
                or not isinstance(original.get("recovery_verification"), dict)):
            raise WorkflowRefusal("Integrated purge of originally unbacked quarantine is held; an unrelated backup cannot supply its recovery proof")
    for row in engine.evidence_rows(state, evidence_ids, kinds={"recovery"}):
        binding = decode_record(engine.journal.read_owned(engine.journal.directory(state["session_id"]) / row["path"], EVIDENCE_MAX_BYTES),
                                max_bytes=EVIDENCE_MAX_BYTES, max_nodes=EVIDENCE_MAX_NODES)
        if isinstance(binding, dict) and binding.get("schema") == QUARANTINE_RECOVERY:
            _quarantine_recovery(engine, state, binding, action)
            continue
        typed_record(binding, RECOVERY_BINDING)
        backup, restore = binding["backup_receipt"], binding["restore_receipt"]
        if (purge_payload and (binding["output_root"] != purge_payload["output_root"] or backup != original["recovery_backup"]
                               or restore != original["recovery_verification"])):
            raise WorkflowRefusal("Purge recovery must match the exact original quarantine backup, restore verification and output root")
        message = "Required recovery needs actual typed backup and completed restoration receipts"
        _storage_record(backup, "backup_receipt", message)
        _storage_record(restore, "restore_receipt", message)
        if backup.get("required_recovery") is not True:
            raise WorkflowRefusal(message)
        output_root = _owned_output(engine, binding["output_root"])
        if (restore.get("backup_plan_sha256") != backup.get("plan_sha256") or restore.get("backup_archive_sha256") != backup.get("archive_sha256")
                or restore.get("backup_manifest_sha256") != backup.get("manifest_sha256") or not SHA.fullmatch(str(restore.get("plan_sha256", "")))):
            raise WorkflowRefusal("Restoration receipt does not bind this exact verified backup")
        files = restore.get("files")
        if not isinstance(files, list) or not 0 < len(files) <= pc_records.MAX_BACKUP_ENTRIES:
            raise WorkflowRefusal("Restoration must account for every bounded archived file")
        outcome_path = output_root / ("outcome-restore-" + restore["plan_sha256"] + ".json")
        retained = {backup.get("archive"): backup.get("archive_sha256"), backup.get("manifest"): backup.get("manifest_sha256"),
                    str(outcome_path): digest(restore)}
        for file in files:
            try:
                expected = Path(restore["destination"]) / file["root_id"] / file["relative_path"]
                expected.relative_to(output_root)
            except (KeyError, TypeError, ValueError) as error:
                raise WorkflowRefusal("Restoration probe escapes its owned work output root") from error
            retained[str(expected)] = file.get("sha256")
        if _retention(engine, state, binding["retention_evidence_id"]) != retained:
            raise WorkflowRefusal("A current exact retention record must protect every actual required recovery artifact")
        # The archive, manifest, restored files and outcome receipt are re-read from disk by the verifier,
        # which also checks that the backup covers every quarantined original of a purge.
        reverify(engine, {"kind": "backup_recovery", "output_root": str(output_root), "backup_receipt": backup,
                      "restore_receipt": restore, "purge_receipt": original})
