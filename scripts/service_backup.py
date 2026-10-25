"""Backup family: the storage verifier the service injects into the engine (D-018, RR2-7), the backup dispatch and
the backup effect.

B-BAK delivers the receipts the engine re-checks through ``verify_storage_artifact``.
"""
from __future__ import annotations

from pathlib import Path

import pc_records
from workflow_core import digest
from storage_ops import StorageService
from scoped_fs import ScopedRoot

# Error codes that mean a recovery or artifact file is gone rather than changed.
_MISSING_CODES = frozenset({"missing-entry", "filesystem-access", "private-path-access-refused", "private-directory-missing"})
INSTALLER_MAX_BYTES = 64 * 1024 * 1024


def _changed(message):
    return pc_records.Refusal("recovery-changed", message)


def _covers_purge(manifest, receipt):
    """The backup manifest covers every quarantined original of the purge receipt by source, path, content and size."""
    originals, backed_files = receipt.get("records"), manifest.get("files")
    if (not isinstance(manifest.get("source_roots"), list) or not manifest["source_roots"] or manifest["source_roots"] != receipt.get("source_roots")
            or not isinstance(originals, list) or not originals or not isinstance(backed_files, list) or not backed_files):
        raise _changed("Recovery must cover the exact quarantined originals and selected source roots")

    def covered_key(file):
        if (not isinstance(file, dict) or any(not isinstance(file.get(key), str) or not file[key] for key in ("root_id", "relative_path", "sha256"))
                or not pc_records.SHA256.match(file["sha256"]) or type(file.get("size")) is not int or file["size"] < 0):
            raise _changed("Purge recovery requires exact bounded original/manifest content mappings")
        return file["root_id"], file["relative_path"], file["sha256"], file["size"]
    backed = {covered_key(file) for file in backed_files}
    if any(not isinstance(record, dict) or covered_key(record.get("original")) not in backed for record in originals):
        raise _changed("Recovery must cover the exact quarantined originals by source, path, content and size")


def _verify_binding(binding):
    kind = binding["kind"]
    if kind == "installer_artifact":
        artifact = Path(binding["path"])
        with ScopedRoot(str(artifact.parent), quiet_workspace=True) as pinned:
            actual = pinned.inspect(artifact.name, hash_file=True, max_bytes=INSTALLER_MAX_BYTES)
        if actual.get("kind") != "file" or actual.get("sha256") != binding["sha256"] or actual != binding["record"]:
            raise _changed("The actual selected official artifact bytes differ from the approved content hash")
        return
    storage = StorageService(output_root=binding["output_root"], quiet_workspace=True, protected_roots=binding.get("protected_roots"))
    if kind == "backup_recovery":
        backup = binding["backup_receipt"]
        manifest = storage.verified_recovery(backup=backup, restoration=binding["restore_receipt"])
        if manifest.get("required_recovery") is not True or manifest.get("plan_sha256") != backup.get("plan_sha256"):
            raise _changed("Recovery manifest does not bind the actual archive and original backup plan")
        if binding.get("purge_receipt") is not None:
            _covers_purge(manifest, binding["purge_receipt"])
    elif kind == "quarantine_recovery":
        storage.check_preconditions(plan=binding["restore_plan"], expected_plan_sha256=binding["restore_plan_sha256"])
        if storage.artifact_sha256(binding["attempt"]) != binding["attempt_sha256"]:
            raise _changed("The original quarantine attempt record changed")
    else:
        raise pc_records.Refusal("verifier-binding", "The artifact verifier does not know this binding")


def verify_storage_artifact(binding):
    """The engine's ``verify_artifact`` that only WorkflowService builds in (D-018, F-178): re-read from disk, through
    the storage code, the recovery or artifact bytes a binding names. Returns None; raises pc_records.Refusal with
    code recovery-missing or recovery-changed (and the reason) when they are not exactly as reviewed."""
    try:
        _verify_binding(binding)
    except pc_records.Refusal as error:
        if error.code in {"recovery-missing", "recovery-changed", "verifier-binding"}:
            raise
        code = "recovery-missing" if error.code in _MISSING_CODES else "recovery-changed"
        raise pc_records.Refusal(code, str(error)) from error
    except (KeyError, TypeError, AttributeError) as error:
        raise pc_records.Refusal("verifier-binding", "The artifact binding is incomplete") from error
    except OSError as error:
        raise pc_records.Refusal("recovery-missing" if isinstance(error, FileNotFoundError) else "recovery-changed",
                                 "Recovery or artifact bytes could not be read again") from error


class BackupMixin:
    """The backup adapter's dispatch targets (service_execute.EXECUTE, service_reconcile.RECONCILE), reached only
    through execute_action and reconcile_operation after their lock, session and binding checks, and its effect."""

    def _execute_storage_backup_create(self, session_id, state, action, payload, **arguments):
        storage = self._storage_preconditions(state, action, payload, diagnostic_fixture_runner=arguments.pop("diagnostic_fixture_runner"),
                                              diagnostic_fixture_result=arguments.pop("diagnostic_fixture_result"))
        return self._run_adapter(session_id, state, action, payload, self._effect_storage_backup_create, storage=storage, **arguments)

    def _effect_storage_backup_create(self, session_id, state, operation, action, payload, path, intent, *, storage):
        """The backup and its optional restoration probe, after the effect boundary (service_execute._run_effect)."""
        plan, expected = payload["storage_plan"], payload["storage_plan_sha256"]
        self._native_origin(state, operation, plan)
        if plan["required_recovery"]:
            self._retain(session_id, {plan["destination"]: None, plan["destination"] + ".manifest.json": None},
                         reason="Required backup reserved before effect; incomplete/unknown artifacts remain protected")
        receipt = storage.create_backup(plan=plan, expected_plan_sha256=expected)
        verified = storage.verify_outcome(plan=plan, expected_plan_sha256=expected, receipt=receipt)
        result = {"native_receipt": receipt, "verification": verified}
        if "restore_probe_destination" in payload:
            probe = storage.plan_restore(receipt=receipt, destination=payload["restore_probe_destination"])
            self._immutable(path / "restore-probe-plan.json", probe)
            self._native_origin(state, operation, probe, substep=True)
            self._retain(session_id, {str(Path(probe["destination"]) / f["root_id"] / f["relative_path"]): f["sha256"] for f in probe["files"]},
                         reason="Exact restoration-probe files reserved before their reviewed verification write")
            restoration = storage.restore_backup(plan=probe, expected_plan_sha256=digest(probe))
            result["restore_probe_receipt"] = restoration
            result["restore_probe_verification"] = storage.verify_outcome(plan=probe, expected_plan_sha256=digest(probe), receipt=restoration)
            result["recovery_evidence"] = self._register_recovery(session_id, payload["output_root"], receipt, restoration, completing=True)
        return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded", receipt=result)

    def _reconcile_storage_backup_create(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_storage(session_id, operation, intent, payload, **arguments)
