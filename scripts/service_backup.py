"""Backup family: the storage verifier the service injects into the engine, the admission of a backup destination on
another drive, and the backup adapter's dispatch, effect and reconciliation.
"""
from __future__ import annotations

import os
from pathlib import Path

import pc_records
from workflow_core import digest
from storage_ops import StorageRefusal, StorageService
from storage_policy import admitted_destination, shown_path
import scoped_fs
from service_state import PLAIN_OUTCOMES, ServiceRefusal, apart, decoded, private_read, within

# Error codes that mean a recovery or artifact file is gone rather than changed.
_MISSING_CODES = frozenset({"missing-entry", "filesystem-access", "private-path-access-refused", "private-directory-missing"})
# What a failed backup leaves: its effects are all recorded, nothing still runs, and the originals were never touched.
_RESOLVE_FACTS = {"actual_effects_recorded": True, "no_active_effects": True, "recovery_retained": True}
# Why a backup did not finish, in the person's words; a fixed list, so no path from a refusal reaches the receipt.
_FAILURE_REASONS = {"disk-full": "the drive ran out of space; free some space or choose another drive",
                    "file-in-use": "a selected file was in use by another program; close that program",
                    "file-too-large-for-volume": "this drive cannot hold a file that big; choose another drive or fewer files"}
_PROBE_UNFINISHED = ("The backup is verified, but its restoration check did not finish, so it cannot count as a tested recovery yet. "
                     "The original files were not touched. To test it, say so and I make a new plan for you to approve.")
# Files a settlement keeps at a temporary name of the backup because the drive cannot tell the backup's own temporary file from
# one made later under that name: their names, then the folder. Nothing here says where they came from. A folder path longer
# than _SHOWN_FOLDER_MAX is shown by its own name, so the summary stays bounded.
_LEFTOVER = {1: (" A file named {} is in {}, where this backup kept a temporary file. PatchCairn cannot tell whether it is that file, "
                 "so it did not delete it. If you did not put it there, you may delete it. Its name starts with a dot, so it may stay "
                 "hidden until you choose to show hidden files."),
             2: (" Files named {} are in {}, where this backup kept its temporary files. PatchCairn cannot tell whether they are those "
                 "files, so it did not delete them. If you did not put them there, you may delete them. Their names start with a dot, "
                 "so they may stay hidden until you choose to show hidden files.")}
_SHOWN_FOLDER_MAX = 1000


def _leftover_note(settled):
    """The plain words for the files settlement kept in "leftover" (all in the backup's own folder), or "" when there are none."""
    leftover = settled["leftover"]
    if not leftover:
        return ""
    folder = shown_path(Path(leftover[0]).parent)
    return _LEFTOVER[min(len(leftover), 2)].format(", ".join(Path(path).name for path in leftover),
                                                   folder if len(folder) <= _SHOWN_FOLDER_MAX else settled["folder"])


def _changed(message):
    return pc_records.Refusal("recovery-changed", message)


def _absent(path):
    """True only when ``path`` is not there; a drive that cannot be read is not proof of that, so its error propagates."""
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return True
    return False


def _probe_targets(probe):
    """{path: SHA-256} of every file the restoration probe ``probe`` writes."""
    return {str(Path(probe["destination"]) / row["root_id"] / row["relative_path"]): row["sha256"] for row in probe["files"]}


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
    storage = StorageService(output_root=binding["output_root"], quiet_workspace=True, protected_roots=binding.get("protected_roots"))
    if kind == "backup_recovery":
        backup = binding["backup_receipt"]
        # Originals are about to go: the read must come from the drive, not from what the system still holds in memory.
        manifest = storage.verified_recovery(backup=backup, restoration=binding["restore_receipt"], uncached=binding.get("remove_originals") is True)
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
    """The engine's ``verify_artifact`` that only WorkflowService builds in: re-read from disk, through the storage code,
    the recovery bytes a binding names. Returns None; raises pc_records.Refusal with code recovery-missing or
    recovery-changed (and the reason) when they are not exactly as reviewed."""
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

    def _admit_backup_destination(self, state, payload):
        """The folder on another drive that a backup payload names (``backup_destination``), admitted as a backup
        destination by scoped_fs.admit_destination with the hash-bound plan's ``non_private_destination``
        acknowledgment; None when the payload names none. It must be the reviewed plan's own destination, apart from the
        native output root, and in fixture mode a folder below this engine's work tree. The caller hands the returned
        root to one StorageService, which owns it from then on; whoever holds that service closes it (a context
        manager) when the action ends, also when it fails."""
        if "backup_destination" not in payload:
            return None
        plan, destination = payload["storage_plan"], payload["backup_destination"]
        if (payload["operation"] != pc_records.ADAPTER_STORAGE_BACKUP_CREATE or plan.get("external") is not True
                or destination != plan.get("destination") or not apart(Path(destination), Path(payload["output_root"]))
                or state["mode"] == "fixture" and not within(Path(destination), self.root / "work")):
            raise ServiceRefusal("A backup destination is only the reviewed backup's own folder on another drive")
        try:
            return admitted_destination(destination, plan["non_private_destination"])
        except (scoped_fs.ScopedFSError, StorageRefusal) as error:
            raise ServiceRefusal(str(error), code=error.code) from error

    def _execute_storage_backup_create(self, session_id, state, action, payload, **arguments):
        with self._storage_preconditions(state, action, payload, diagnostic_fixture_runner=arguments.pop("diagnostic_fixture_runner"),
                                         diagnostic_fixture_result=arguments.pop("diagnostic_fixture_result")) as storage:
            return self._run_adapter(session_id, state, action, payload, self._effect_storage_backup_create, storage=storage, **arguments)

    def _effect_storage_backup_create(self, session_id, state, operation, action, payload, path, intent, *, storage):
        """The backup and its optional restoration probe, after the effect boundary (service_execute._run_effect). A
        refusal the backup knows (a full drive, a file in use, a drive that cannot hold the archive, a chosen folder that
        was not reserved) finishes the operation here as failed, after its temporary files are removed; it never becomes
        "unknown"."""
        plan, expected = payload["storage_plan"], payload["storage_plan_sha256"]
        self._native_origin(state, operation, plan)
        names = storage.backup_names(plan=plan)
        if plan["required_recovery"] and not plan["external"]:
            # The folder this backup will create, reserved before it exists; a destination on another drive is
            # reserved by the service's registration before the effect.
            self._retain(session_id, {str(Path(plan["destination"]) / names["folder"]): None},
                         reason="Required backup reserved before effect; incomplete/unknown artifacts remain protected")
        try:
            if plan["external"] and not self._destination_reserved(state, plan["destination"]):
                raise StorageRefusal("The chosen backup folder was not protected before the backup", code="destination-not-reserved")
            receipt = storage.create_backup(plan=plan, expected_plan_sha256=expected, names=names)
        except (pc_records.Refusal, OSError) as error:
            settled = storage.settle_backup(plan=plan, expected_plan_sha256=expected, volume_identity=self._reserved_volume(state, plan))
            return self._finish(self.engine.read_session(session_id), operation, outcome="failed",
                                receipt=self._backup_failed(settled, getattr(error, "code", type(error).__name__)))
        verified = storage.verify_outcome(plan=plan, expected_plan_sha256=expected, receipt=receipt, recheck_content=False)
        result = {"native_receipt": receipt, "verification": verified}
        if "restore_probe_destination" in payload:
            probe = storage.plan_restore(receipt=receipt, destination=payload["restore_probe_destination"])
            self._immutable(path / "restore-probe-plan.json", probe)
            self._native_origin(state, operation, probe, substep=True)
            self._retain(session_id, _probe_targets(probe), reason="Exact restoration-probe files reserved before their reviewed verification write")
            restoration = storage.restore_backup(plan=probe, expected_plan_sha256=digest(probe))
            result["restore_probe_receipt"] = restoration
            result["restore_probe_verification"] = storage.verify_outcome(plan=probe, expected_plan_sha256=digest(probe), receipt=restoration)
            result["recovery_evidence"] = self._register_recovery(session_id, payload["output_root"], receipt, restoration, completing=True)
        # Once per verified backup folder: a probe that fails leaves the operation unknown, and its reconciliation registers it
        # and closes the operation (_unfinished_probe).
        self._register_backup(state, location=receipt["location"], size_bytes=receipt["backup_bytes"],
                              receipt_sha256=verified["receipt_sha256"], volume_identity=receipt["volume_identity"])
        return self._finish(self.engine.read_session(session_id), operation, outcome=receipt["outcome"], receipt=result)

    def _destination_reserved(self, state, destination):
        """True when this session's retention row protects the chosen folder (_begin_adapter wrote it before the effect)."""
        return any(row["retention_kind"] == "destination" and row["session_id"] == state["session_id"]
                   and row["protection_root"] == destination for row in self._retention())

    def _reserved_volume(self, state, plan):
        """The volume identity this session recorded for the chosen drive of ``plan``: its row keeps it from before the first
        write, and the backup's row after that. None for a plan in the work folder, and when no row names it."""
        if plan.get("external") is not True:
            return None
        return next((row["volume_identity"] for row in self._retention() if row["session_id"] == state["session_id"]
                     and row["protection_root"] == plan["destination"] and row["volume_identity"] is not None), None)

    @staticmethod
    def _backup_failed(settled, code):
        """The receipt of a backup that did not finish: why, what was removed, which kept files the person may judge
        (_leftover_note), what stays protected, what to do next, and the facts a replan needs."""
        return {"adapter_invoked": True, "backup_finished": False, "failure_code": code, "folder": settled["folder"],
                "removed_temporary_files": settled["removed"], "kept": settled["kept"], **_RESOLVE_FACTS,
                "summary": f"The backup did not finish: {_FAILURE_REASONS.get(code, 'something stopped it')}. The original files were "
                           "not touched. To try again, say so and I make a new plan for you to approve." + _leftover_note(settled)
                           + (" Some files could not be removed and stay protected." if len(settled["kept"]) > len(settled["leftover"]) else "")}

    def _unfinished_probe(self, session_id, operation_id, payload, receipt):
        """None when the optional restoration probe of a verified backup has its saved plan and its outcome receipt, for the
        shared storage reconciliation to check. Otherwise the probe never finished and never will: its files stay protected
        (from its saved plan, if it got that far), and this returns the receipt's facts about them. No probe write is
        repeated and no recovery evidence is made. A saved plan that is not this backup's is left to the same check."""
        path = self._operation_dir(session_id, operation_id) / "restore-probe-plan.json"
        if _absent(path):
            return {"restore_probe_finished": False, "restore_probe_files_planned": 0, "restore_probe_files_found": 0}
        probe = decoded(private_read(path))
        if (probe.get("destination") != payload["restore_probe_destination"] or probe.get("receipt") != receipt
                or not _absent(Path(payload["output_root"]) / ("outcome-restore-" + digest(probe) + ".json"))):
            return None
        targets = _probe_targets(probe)
        self._retain(session_id, targets, reason="Files of a restoration check that did not finish; never read as recovery evidence")
        return {"restore_probe_finished": False, "restore_probe_files_planned": len(targets),
                "restore_probe_files_found": sum(not _absent(target) for target in targets)}

    def _reconcile_storage_backup_create(self, session_id, operation, intent, payload, **arguments):
        """A backup's outcome after an interruption, from its attempt record: never started or stopped before its
        archive got its final name → failed, after removing the recorded temporary names it can prove are its own; a
        final archive without a receipt → verified and finished, or kept and reported; a receipt → the backup is checked
        and kept, then its optional restoration probe: finished → the shared storage reconciliation, not finished →
        "partial". Never "unknown" for a backup that was killed, unless its own records or drive refuse. Settling removes
        files and writes records: reconcile_operation refuses it while this process runs elevated, like the backup itself."""
        if operation["outcome"] not in {None, "unknown"}:
            return self._reconcile_storage(session_id, operation, intent, payload, **arguments)
        state = self.engine.read_session(session_id)
        self._original_authority(state, operation, intent)
        storage = StorageService(output_root=payload["output_root"], quiet_workspace=True, protected_roots=payload["protected_roots"])
        settled = storage.settle_backup(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"], finish=True,
                                        volume_identity=self._reserved_volume(state, payload["storage_plan"]))
        kind = "reconciliation" if operation["outcome"] == "unknown" else "outcome"
        if settled["state"] == "finished":
            # The backup folder is verified: it is registered whether or not a restore probe still has to be checked.
            receipt = settled["receipt"]
            verified = storage.verify_outcome(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"],
                                              receipt=receipt)
            self._register_backup(state, location=receipt["location"], size_bytes=receipt["backup_bytes"],
                                  receipt_sha256=verified["receipt_sha256"], volume_identity=receipt["volume_identity"])
            result, note = {"native_receipt": receipt, "verification": verified}, _leftover_note(settled)
            if "restore_probe_destination" in payload:
                unfinished = self._unfinished_probe(session_id, operation["operation_id"], payload, receipt)
                if unfinished is None:
                    return self._reconcile_storage(session_id, operation, intent, payload, **arguments)
                return self._finish(state, operation, outcome="partial", kind=kind,
                                    receipt={**result, "adapter_invoked": True, "backup_finished": True, **unfinished, **_RESOLVE_FACTS,
                                             "summary": _PROBE_UNFINISHED + note})
            return self._finish(state, operation, outcome=receipt["outcome"], kind=kind,
                                receipt={**result, "summary": PLAIN_OUTCOMES[receipt["outcome"]] + note} if note else result)
        return self._finish(state, operation, outcome="failed", receipt=self._backup_failed(settled, "interrupted"), kind=kind)
