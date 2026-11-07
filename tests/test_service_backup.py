"""Selected synthetic work copies only. No host inventory, update or repair.

Backup family (scripts/service_backup.py): the backup adapter and the storage verifier the engine re-checks
recovery through.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import tracemalloc
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowRefusal
import pc_records
from workflow_service import ServiceRefusal, WorkflowService, verify_storage_artifact
from storage_ops import StorageRefusal, StorageService, plan_sha256
from private_workspace import ensure_private_directory
import scoped_base
import scoped_fs
import storage_backup
import win32_files
from test_service_state import SessionFixtures, PROSE
from test_storage_policy import ROOT_CLASS

SCRIPTS = ROOT / "scripts"
# Whether settlement can prove a killed backup's temporary file its own: an NTFS file id carries a sequence number, while a
# POSIX inode number can be given to a later file, so on POSIX the file stays and is named for the person to judge.
LASTING_IDS = os.name == "nt"


def leftover_text(names, folder):
    """The receipt's words for files kept at this backup's temporary names, written out here: they never say where the files
    came from."""
    if len(names) == 1:
        return (f" A file named {names[0]} is in {folder}, where this backup kept a temporary file. PatchCairn cannot tell whether it "
                "is that file, so it did not delete it. If you did not put it there, you may delete it. Its name starts with a dot, so "
                "it may stay hidden until you choose to show hidden files.")
    return (f" Files named {', '.join(names)} are in {folder}, where this backup kept its temporary files. PatchCairn cannot tell "
            "whether they are those files, so it did not delete them. If you did not put them there, you may delete them. Their names "
            "start with a dot, so they may stay hidden until you choose to show hidden files.")


def assert_settled(test, receipt, partial):
    """The killed backup's temporary file ``partial`` is removed where its file id lasts; elsewhere it is kept and named in
    plain words that leave it to the person, without saying where it came from."""
    if LASTING_IDS:
        test.assertEqual((receipt["removed_temporary_files"], receipt["kept"]), ([partial.name], []))
        test.assertFalse(partial.exists())
        test.assertNotIn("temporary file", receipt["summary"])
    else:
        test.assertEqual((receipt["removed_temporary_files"], receipt["kept"]), ([], [partial.name]))
        test.assertTrue(partial.is_file())
        test.assertIn(leftover_text([partial.name], partial.parent), receipt["summary"])
        test.assertNotIn("stay protected", receipt["summary"])


class Stopped(BaseException):
    """Ends a call where a crash would, without being one of the failures the service handles."""


class WorkflowServiceTests(SessionFixtures):
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
        self.engine.verify_recovery(self.state(), [recovery])
        self.assertIn(str(self.output), self.service.protected_roots())
        self.assertEqual(self.state()["stage"], "apply")
        with self.assertRaises((ServiceRefusal, WorkflowRefusal, StorageRefusal)):
            self.execute(action, sha)
        self.assertEqual(len(self.state()["operations"]), 1)

    def test_begin_reverifies_recovery_artifact_from_disk(self):
        sid, action, sha, backup, _ = self.approved_purge()
        # The plan was registered and approved against these bytes; begin must read them again.
        archive = Path(backup["archive"])
        archive.rename(archive.with_name("moved-after-approval.zip"))
        self.begin(sid, action, sha, code="recovery-missing")
        self.assertEqual(self.state(sid)["operations"], {})
        self.assertTrue((self.output / "quarantine" / "000001").exists())

    def test_begin_refuses_when_recovery_bytes_changed(self):
        sid, action, sha, _, restore = self.approved_purge()
        restored = Path(restore["destination"]) / "r001" / "example.txt"
        restored.write_bytes(restored.read_bytes().upper())
        self.begin(sid, action, sha, code="recovery-changed")
        self.assertEqual(self.state(sid)["operations"], {})
        self.assertTrue((self.output / "quarantine" / "000001").exists())

    def test_begin_refuses_changed_quarantine_mapping(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses native no-overwrite move; no fallback")
        storage = self.storage()
        quarantine = storage.plan_cleanup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/example.txt"],
                                          quarantine_destination=str(self.output / "quarantine"), content_read_authorized=True,
                                          recovery_required=False)
        move = self.service.prepare_storage_action(self.sid, action_id="quarantine-unbacked", adapter_id="storage.quarantine",
                                                   storage_plan=quarantine, output_root=str(self.output), **PROSE)
        receipt = self.execute(move, self.approve(move))["receipt"]["native_receipt"]
        sid = self.session()
        action = self.service.prepare_storage_action(sid, action_id="restore-selected", adapter_id="storage.quarantine_restore",
                                                     storage_plan=self.storage().plan_quarantine_restore(receipt=receipt),
                                                     output_root=str(self.output), **PROSE)
        sha = self.approve(action, sid=sid)
        (self.output / "quarantine" / "000001").rename(self.output / "quarantine" / "000002")
        self.begin(sid, action, sha, code="recovery-changed")
        self.assertEqual(self.state(sid)["operations"], {})
        self.assertFalse((self.source / "example.txt").exists())

    def test_begin_refuses_a_changed_quarantine_attempt_record(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses native no-overwrite move; no fallback")
        storage = self.storage()
        quarantine = storage.plan_cleanup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/example.txt"],
                                          quarantine_destination=str(self.output / "quarantine"), content_read_authorized=True,
                                          recovery_required=False)
        move = self.service.prepare_storage_action(self.sid, action_id="quarantine-unbacked", adapter_id="storage.quarantine",
                                                   storage_plan=quarantine, output_root=str(self.output), **PROSE)
        receipt = self.execute(move, self.approve(move))["receipt"]["native_receipt"]
        sid = self.session()
        action = self.service.prepare_storage_action(sid, action_id="restore-selected", adapter_id="storage.quarantine_restore",
                                                     storage_plan=self.storage().plan_quarantine_restore(receipt=receipt),
                                                     output_root=str(self.output), **PROSE)
        sha = self.approve(action, sid=sid)
        # Still decodable, with the same plan file and plan digest: only the retained bytes differ.
        attempt = self.output / receipt["attempt"]
        record = json.loads(attempt.read_bytes())
        attempt.write_bytes(json.dumps({**record, "status": record["status"] + " (changed)"}, sort_keys=True, separators=(",", ":")).encode("ascii"))
        self.begin(sid, action, sha, code="recovery-changed")
        self.assertFalse((self.source / "example.txt").exists())

    def test_storage_verifier_refuses_a_backup_that_does_not_cover_the_purge(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses the native no-overwrite quarantine prerequisite; no fallback")
        receipt, backup, restore = self.make_recovery_and_quarantine()
        binding = {"kind": "backup_recovery", "output_root": str(self.output), "backup_receipt": backup, "restore_receipt": restore, "purge_receipt": receipt}
        self.assertIsNone(verify_storage_artifact(binding))
        uncovered = copy.deepcopy(receipt)
        uncovered["records"][0]["original"]["sha256"] = "0" * 64
        # A receipt that names another path is a changed receipt; the receipt's own archive gone from the disk is a missing one.
        for changed, code in (({"purge_receipt": uncovered}, "recovery-changed"), ({"backup_receipt": {**backup, "archive": backup["archive"] + ".moved"}}, "recovery-changed"),
                              ({"kind": "fictional-unknown"}, "verifier-binding")):
            with self.subTest(code=code), self.assertRaises(pc_records.Refusal) as caught:
                verify_storage_artifact({**binding, **changed})
            self.assertEqual(caught.exception.code, code)
        archive = Path(backup["archive"])
        archive.rename(archive.with_name("moved-after-approval.zip"))
        with self.assertRaises(pc_records.Refusal) as caught:
            verify_storage_artifact(binding)
        self.assertEqual(caught.exception.code, "recovery-missing")



# The child process of the kill test: it runs the reviewed backup through engine -> service -> storage and stops for
# good right after the first bytes reached the archive's temporary file, which the parent then kills.
KILLED_CHILD = """
import sys, time
from pathlib import Path
sys.dont_write_bytecode = True
root, scripts, marker, sid, action_id, sha, evidence = sys.argv[1:8]
sys.path.insert(0, scripts)
import storage_backup
from workflow_core import WorkflowEngine
from workflow_service import WorkflowService, verify_storage_artifact
real = storage_backup._Member.write
def stop_after_a_recorded_write(member, data):
    written = real(member, data)
    member.stream.flush()
    Path(marker).write_text("written", encoding="utf-8")
    time.sleep(600)
    return written
storage_backup._Member.write = stop_after_a_recorded_write
service = WorkflowService(WorkflowEngine(Path(root), verify_artifact=verify_storage_artifact))
service.elevation_probe = lambda: False
service.execute_action(sid, action_id=action_id, plan_sha256=sha, precondition_evidence_ids=[evidence])
"""


class BackupReconcileTests(SessionFixtures):
    """A backup that failed or was killed: never "unknown", only the recorded temporary names are removed, and the
    three facts a replan needs are in its receipt."""

    def approved_backup(self, **options):
        action, plan = self.backup_action(**options)
        sha = self.approve(action)
        return action, plan, sha

    def operation(self, sid=None):
        operations = self.state(sid)["operations"]
        self.assertEqual(len(operations), 1)
        return next(iter(operations.values()))

    def assert_failed_with_resolve_facts(self, result):
        self.assertEqual(result["outcome"], "failed")
        for fact in ("actual_effects_recorded", "no_active_effects", "recovery_retained"):
            self.assertIs(result["receipt"][fact], True)
        self.assertEqual(self.operation()["outcome"], "failed")
        self.assertEqual((self.source / "example.txt").read_bytes(), b"Fictional selected file; no host content.\n")

    def attempt(self, plan):
        return json.loads((self.output / f"attempt-backup-{plan_sha256(plan)}.json").read_bytes())

    def assert_partial_with_probe_unfinished(self, result, planned, found):
        """A verified backup whose restoration check did not finish: known, kept, resolvable, and no recovery evidence."""
        receipt = result["receipt"]
        self.assertEqual(result["outcome"], "partial")
        self.assertEqual(self.operation()["outcome"], "partial")
        self.assertIn("The backup is verified, but its restoration check did not finish", receipt["summary"])
        self.assertEqual((receipt["backup_finished"], receipt["restore_probe_finished"]), (True, False))
        self.assertEqual((receipt["restore_probe_files_planned"], receipt["restore_probe_files_found"]), (planned, found))
        for fact in ("actual_effects_recorded", "no_active_effects", "recovery_retained"):
            self.assertIs(receipt[fact], True)
        self.assertTrue(receipt["verification"]["verification_passed"])
        self.assertNotIn("recovery_evidence", receipt)
        self.assertEqual([row["location"] for row in self.service.retention_rows() if row["kind"] == "backup"],
                         [receipt["native_receipt"]["location"]])
        self.assertFalse([row for row in self.state()["evidence"].values() if row["kind"] == "recovery"])
        with self.assertRaises(ServiceRefusal):  # consumed: nothing repeats it
            self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])

    def probe_files(self):
        return [path for row in self.service._retention() if row["retention_kind"] == "recovery" for path in row["artifacts"]]

    def test_backup_stopped_before_its_restore_probe_was_planned_is_partial(self):
        action, plan, sha = self.approved_backup(probe=True)
        with mock.patch.object(StorageService, "plan_restore", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute(action, sha)
        self.assertIsNone(self.operation()["outcome"])
        self.assert_partial_with_probe_unfinished(self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"]), 0, 0)
        self.assertEqual(self.probe_files(), [])

    def test_backup_stopped_during_its_restore_probe_is_partial_and_keeps_what_the_probe_wrote(self):
        action, plan, sha = self.approved_backup(probe=True)
        real = StorageService._write_json

        def stopped_after_the_first_restored_file(storage, output, relative, value):
            if relative.startswith("step-restore-"):
                raise Stopped()
            return real(storage, output, relative, value)
        with mock.patch.object(StorageService, "_write_json", stopped_after_the_first_restored_file), self.assertRaises(Stopped):
            self.execute(action, sha)
        restored = self.output / "one-probe" / "r001" / "example.txt"
        self.assertTrue(restored.is_file())
        written = restored.read_bytes()
        result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        self.assert_partial_with_probe_unfinished(result, 1, 1)
        self.assertEqual(restored.read_bytes(), written)  # nothing written again, nothing removed
        self.assertEqual(self.probe_files(), [str(restored)])

    def test_files_of_a_probe_stopped_before_it_protected_them_get_protected(self):
        action, plan, sha = self.approved_backup(probe=True)
        real = WorkflowService._native_origin

        def stopped_at_the_probe(service, state, operation, native, *, substep=False):
            if substep:
                raise Stopped()
            return real(service, state, operation, native, substep=substep)
        with mock.patch.object(WorkflowService, "_native_origin", stopped_at_the_probe), self.assertRaises(Stopped):
            self.execute(action, sha)
        self.assertEqual(self.probe_files(), [])
        self.assert_partial_with_probe_unfinished(self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"]), 1, 0)
        self.assertEqual(self.probe_files(), [str(self.output / "one-probe" / "r001" / "example.txt")])

    def test_backup_stopped_before_its_restore_probe_wrote_a_file_counts_none_found(self):
        action, plan, sha = self.approved_backup(probe=True)
        with mock.patch.object(StorageService, "_create_private_file", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute(action, sha)
        self.assert_partial_with_probe_unfinished(self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"]), 1, 0)

    def test_a_restore_probe_that_is_refused_closes_partial_and_blocks_no_other_session(self):
        """The restoration check is refused after the backup is written, a failure the effect catches: the operation is unknown,
        its reconciliation closes it as partial, and the person's choice frees other sessions. (A probe too big to run is refused
        before begin; a process killed at this point is test_backup_stopped_before_its_restore_probe_was_planned_is_partial.)"""
        action, plan, sha = self.approved_backup(probe=True)
        refused = StorageRefusal("Fictional refusal of the restoration check", code="fictional-probe-refusal")
        with mock.patch.object(StorageService, "plan_restore", side_effect=refused):
            result = self.execute(action, sha)
        self.assertEqual((result["outcome"], result["receipt"]["failure_code"]), ("unknown", "fictional-probe-refusal"))
        operation_id = self.operation()["operation_id"]
        result = self.service.reconcile_operation(self.sid, operation_id=operation_id)
        self.assert_partial_with_probe_unfinished(result, 0, 0)
        self.engine.resolve(self.sid, pending_id="reconcile-" + operation_id, choice="revise_plan", evidence_ids=[result["evidence_id"]],
                            owner_quote="Prepare a new plan.", owner_message_id="fictional-replan-" + uuid.uuid4().hex)
        other = self.session()
        action, _plan = self.backup_action(sid=other, suffix="two")
        self.assertEqual(self.execute(action, self.approve(action, sid=other), sid=other)["outcome"], "succeeded")

    def test_a_finished_probe_still_goes_through_the_shared_check(self):
        action, plan, sha = self.approved_backup(probe=True)
        with mock.patch.object(WorkflowService, "_register_recovery", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute(action, sha)
        result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        self.assertEqual(result["outcome"], "succeeded")
        self.assertIn("recovery_evidence", result["receipt"])

    def test_a_saved_probe_plan_of_another_backup_is_not_trusted(self):
        action, plan, sha = self.approved_backup(probe=True)
        with mock.patch.object(StorageService, "restore_backup", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute(action, sha)
        operation = self.operation()
        saved = self.service._operation_dir(self.sid, operation["operation_id"]) / "restore-probe-plan.json"
        probe = json.loads(saved.read_bytes())
        saved.unlink()
        self.service._immutable(saved, {**probe, "destination": str(self.output / "another-probe")})
        result = self.service.reconcile_operation(self.sid, operation_id=operation["operation_id"])
        self.assertEqual(result["outcome"], "unknown")
        self.assertNotIn("restore_probe_finished", result["receipt"])

    def test_failed_backup_says_why_and_what_to_do_next_without_a_path(self):
        reasons = {"disk-full": "the drive ran out of space; free some space or choose another drive",
                   "file-in-use": "a selected file was in use by another program; close that program",
                   "file-too-large-for-volume": "this drive cannot hold a file that big; choose another drive or fewer files",
                   "interrupted": "something stopped it", "write-failed": "something stopped it", "OSError": "something stopped it"}
        failed = sys.modules["service_backup"].BackupMixin._backup_failed
        for code, reason in reasons.items():
            with self.subTest(code=code):
                receipt = failed({"folder": None, "removed": [], "kept": [], "leftover": []}, code)
                self.assertEqual(receipt["failure_code"], code)
                self.assertEqual(receipt["summary"], f"The backup did not finish: {reason}. The original files were not touched. To try again, "
                                                     "say so and I make a new plan for you to approve.")
        kept = failed({"folder": None, "removed": [], "kept": ["x"], "leftover": []}, "disk-full")
        self.assertTrue(kept["summary"].endswith(" Some files could not be removed and stay protected."))

    def test_a_leftover_temporary_file_is_named_with_what_the_person_may_do(self):
        failed = sys.modules["service_backup"].BackupMixin._backup_failed
        folder = self.output / "20260101T000000Z-backup"
        one, two = ".partial-" + "a" * 32, ".partial-" + "b" * 32
        receipt = failed({"folder": folder.name, "removed": [], "kept": [one], "leftover": [str(folder / one)]}, "interrupted")
        self.assertTrue(receipt["summary"].endswith(leftover_text([one], folder)))
        receipt = failed({"folder": folder.name, "removed": [], "kept": [one, two, "backup.zip"], "leftover": [str(folder / one), str(folder / two)]},
                         "interrupted")
        self.assertIn(leftover_text([one, two], folder), receipt["summary"])
        self.assertTrue(receipt["summary"].endswith(" Some files could not be removed and stay protected."))  # backup.zip: not a leftover
        for claim in ("usable backup", "left a temporary file", "the backup made"):  # nothing says where the file came from
            self.assertNotIn(claim, receipt["summary"])
        # A folder path too long to show keeps the summary within what the engine records: the backup folder's own name.
        deep = Path(self.output, *["fictional-deep-folder"] * 60, folder.name)
        receipt = failed({"folder": folder.name, "removed": [], "kept": [one], "leftover": [str(deep / one)]}, "interrupted")
        self.assertIn(f"A file named {one} is in {folder.name}, where", receipt["summary"])
        self.assertLess(len(receipt["summary"]), 4000)

    def test_a_temporary_file_the_drive_cannot_prove_its_own_is_kept_and_named_through_the_service(self):
        """A killed backup on a drive whose file ids do not last (FAT, exFAT; and every POSIX drive, whose inode numbers can be used
        again): reconciliation keeps the file at the temporary name and names it and its folder for the person."""
        action, plan, sha = self.approved_backup()

        def killed(member, data):
            member.archive.fp.committed = True  # as a killed process: nothing removes the temporary file any more
            raise Stopped()
        with mock.patch.object(ROOT_CLASS, "identity_keys", scoped_base.UNSTABLE_ID_KEYS):
            with mock.patch.object(storage_backup._Member, "write", killed), self.assertRaises(Stopped):
                self.execute(action, sha)
            result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        attempt = self.attempt(plan)
        partial = Path(plan["destination"]) / attempt["folder"] / attempt["partials"]["archive"]
        self.assert_failed_with_resolve_facts(result)
        self.assertEqual((result["receipt"]["removed_temporary_files"], result["receipt"]["kept"]), ([], [partial.name]))
        self.assertIn(leftover_text([partial.name], partial.parent), result["receipt"]["summary"])
        self.assertTrue(partial.is_file())

    def test_a_backup_killed_in_its_note_on_a_drive_that_cannot_prove_the_note_still_finishes(self):
        """backup.zip and manifest.json were final when the process died writing README.txt, on a drive whose file ids do not
        last (FAT, exFAT; and every POSIX drive): reconciliation writes the note afresh, the backup finishes and is registered,
        and the file at the note's temporary name is named for the person."""
        action, plan, sha = self.approved_backup()
        real = storage_backup.StorageBackup._write_lines

        def killed_in_the_note(destination, relative, partial, chunks, *, created=None):
            if not relative.endswith("/README.txt"):
                return real(destination, relative, partial, chunks, created=created)
            with destination.open_new(relative, partial=partial) as out:
                created(out)
                out.write(b"cut off")
                out.committed = True  # as a killed process: nothing removes it
                raise Stopped()
        with mock.patch.object(ROOT_CLASS, "identity_keys", scoped_base.UNSTABLE_ID_KEYS):
            with mock.patch.object(storage_backup.StorageBackup, "_write_lines", staticmethod(killed_in_the_note)), self.assertRaises(Stopped):
                self.execute(action, sha)
            result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        attempt = self.attempt(plan)
        folder, name = Path(plan["destination"]) / attempt["folder"], attempt["partials"]["readme"]
        self.assertEqual((result["outcome"], self.operation()["outcome"]), ("succeeded", "succeeded"))
        self.assertEqual(result["receipt"]["summary"], "This step finished. Whether things still work as they should is checked separately."
                         + leftover_text([name], folder))
        self.assertEqual([row["location"] for row in self.service.retention_rows() if row["kind"] == "backup"],
                         [result["receipt"]["native_receipt"]["location"]])
        self.assertIn("files backed up", (folder / "README.txt").read_text(encoding="utf-8"))
        self.assertEqual((folder / name).read_bytes(), b"cut off")

    def test_full_drive_during_backup_finishes_failed_not_unknown(self):
        action, plan, sha = self.approved_backup()
        full = scoped_base.ScopedFSError("disk-full", "The drive is full")
        with mock.patch.object(storage_backup._Member, "write", side_effect=full):
            result = self.execute(action, sha)
        self.assert_failed_with_resolve_facts(result)
        self.assertEqual(result["receipt"]["failure_code"], "disk-full")
        self.assertIn("did not finish: the drive ran out of space", result["receipt"]["summary"])
        attempt = self.attempt(plan)
        folder = Path(plan["destination"]) / attempt["folder"]
        self.assertEqual(os.listdir(folder), [])  # the temporary archive was removed; nothing has a final name
        self.assertEqual(result["receipt"]["kept"], [])

    def test_backup_that_never_wrote_its_attempt_record_reconciles_failed(self):
        action, plan, sha = self.approved_backup()
        with mock.patch.object(StorageService, "create_backup", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute(action, sha)
        self.assertIsNone(self.operation()["outcome"])
        result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        self.assert_failed_with_resolve_facts(result)
        self.assertIsNone(result["receipt"]["folder"])

    def test_backup_stopped_before_its_archive_reconciles_failed(self):
        action, plan, sha = self.approved_backup()
        with mock.patch.object(StorageService, "_write_archive", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute(action, sha)
        attempt = self.attempt(plan)
        self.assertEqual(os.listdir(Path(plan["destination"]) / attempt["folder"]), [])
        result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        self.assert_failed_with_resolve_facts(result)
        self.assertEqual((result["receipt"]["removed_temporary_files"], result["receipt"]["kept"]), ([], []))

    def test_settlement_refuses_while_elevated_and_changes_nothing(self):
        action, plan, sha = self.approved_backup()
        self.kill_backup_in_child(action, sha)
        attempt = self.attempt(plan)
        partial = Path(plan["destination"]) / attempt["folder"] / attempt["partials"]["archive"]
        written = partial.read_bytes()
        operation_id = self.operation()["operation_id"]
        for probe in (lambda: True, lambda: None):  # elevated, or it cannot be told
            self.service.elevation_probe = probe
            with self.assertRaises(ServiceRefusal) as caught:
                self.service.reconcile_operation(self.sid, operation_id=operation_id)
            self.assertEqual(caught.exception.code, "process-elevated")
            self.assertEqual(partial.read_bytes(), written)
            self.assertIsNone(self.operation()["outcome"])
        self.service.elevation_probe = lambda: False
        result = self.service.reconcile_operation(self.sid, operation_id=operation_id)
        self.assert_failed_with_resolve_facts(result)
        assert_settled(self, result["receipt"], partial)

    def test_a_temporary_name_this_backup_never_created_stays(self):
        """The process stopped before it created anything, and a file has that name now: the name alone proves nothing."""
        action, plan, sha = self.approved_backup()
        with mock.patch.object(StorageService, "_write_archive", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute(action, sha)
        attempt = self.attempt(plan)
        partial = Path(plan["destination"]) / attempt["folder"] / attempt["partials"]["archive"]
        partial.write_bytes(b"fictional file with that name")
        result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        self.assert_failed_with_resolve_facts(result)
        self.assertEqual((result["receipt"]["removed_temporary_files"], result["receipt"]["kept"]), ([], [partial.name]))
        self.assertEqual(partial.read_bytes(), b"fictional file with that name")

    def test_a_replaced_temporary_file_survives_the_reconciliation_of_a_killed_backup(self):
        action, plan, sha = self.approved_backup()
        self.kill_backup_in_child(action, sha)
        attempt = self.attempt(plan)
        partial = Path(plan["destination"]) / attempt["folder"] / attempt["partials"]["archive"]
        replacement = partial.with_name("fictional-replacement")
        replacement.write_bytes(b"fictional file that took this name")
        os.replace(replacement, partial)
        result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        self.assert_failed_with_resolve_facts(result)
        self.assertEqual((result["receipt"]["removed_temporary_files"], result["receipt"]["kept"]), ([], [partial.name]))
        self.assertEqual(partial.read_bytes(), b"fictional file that took this name")
        # Where file ids last the other file is told apart and stays protected; on POSIX nothing tells them apart, and the words
        # leave it to the person without saying it is the backup's.
        self.assertIn("stay protected" if LASTING_IDS else leftover_text([partial.name], partial.parent), result["receipt"]["summary"])

    def kill_backup_in_child(self, action, sha):
        """Run the backup in a child process (sys.executable -I -S -B, inside the cap) and kill it right after its first
        recorded write to the archive's temporary file; then remove the stale coordinator lock it left, as the
        coordinator's inspected step."""
        marker = self.root / ("killed-" + uuid.uuid4().hex)
        evidence = self.precondition(action, sha)
        log = self.root / "child.log"
        with open(log, "wb") as output:
            child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", KILLED_CHILD, str(self.root), str(SCRIPTS), str(marker),
                                      self.sid, action["action_id"], sha, evidence], stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 300
            while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertTrue(marker.exists(), "the child stopped before its first write: " + log.read_text(encoding="utf-8", errors="replace"))
        finally:
            child.kill()
            child.wait(60)

    def test_backup_killed_reconciles_failed_and_removes_only_recorded_partials(self):
        action, plan, sha = self.approved_backup()
        self.kill_backup_in_child(action, sha)
        self.assertIsNone(self.operation()["outcome"])
        attempt = self.attempt(plan)
        folder = Path(plan["destination"]) / attempt["folder"]
        recorded = folder / attempt["partials"]["archive"]
        self.assertTrue(recorded.is_file() and recorded.stat().st_size > 0)
        stranger = folder / scoped_base.new_partial_name()  # a temporary-looking name this backup never recorded
        stranger.write_bytes(b"not this backup's")
        result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        self.assert_failed_with_resolve_facts(result)
        assert_settled(self, result["receipt"], recorded)
        self.assertEqual(stranger.read_bytes(), b"not this backup's")
        self.assertFalse((folder / "backup.zip").exists())
        self.assertIn("The backup did not finish: something stopped it. The original files were not touched.", result["receipt"]["summary"])

    def test_backup_killed_during_pending_restart_reconciles_failed_not_unknown(self):
        """A backup may run while an operation of another session waits for a restart (the restart class); killed, it
        still reconciles to failed. A session runs one step at a time, so the waiting step is in its own session."""
        action, plan, sha = self.approved_backup()
        waiting = self.session(job="security_updates")

        def restart_pending(state):
            # A package operation in the restart class: open, with its typed restart marker (the engine's own fields).
            state["operations"]["fictional-restart"] = {
                "operation_id": "fictional-restart", "action_id": "fictional-update", "plan_sha256": sha,
                "settings_revision": state["settings_revision"], "started_utc": pc_records.utc_now(), "finished_utc": None, "outcome": None,
                "evidence_ids": [], "summary": "Waiting for the restart", "authorization": None, "pause_requested": False,
                "resolution": None, "mutating": True, "adapter_id": pc_records.ADAPTER_PACKAGE_UPGRADE,
                "restart_pending": {"signal": "fictional", "source": "fictional"}}
            return None, "Fictional pending restart for this test"
        self.engine.change(waiting, "restart_pending", restart_pending)
        self.kill_backup_in_child(action, sha)
        result = self.service.reconcile_operation(self.sid, operation_id=self.operation()["operation_id"])
        self.assert_failed_with_resolve_facts(result)


class DestinationAdmissionTests(SessionFixtures):
    """_admit_backup_destination: the reviewed plan's own folder on another drive, admitted with its acknowledgment. In
    fixture mode "another drive" is a folder outside the native output root, still below the owned work tree."""

    def payload(self, folder, **plan):
        return {"operation": "storage.backup_create", "backup_destination": str(folder), "output_root": str(self.output),
                "storage_plan": {"external": True, "destination": str(folder), "non_private_destination": False, **plan}}

    def chosen(self):
        folder = self.root / "work" / "external-drive"
        ensure_private_directory(folder, create=True)
        return folder

    @staticmethod
    def fixed_drive():
        """Destinations admitted from now on appear to be on a fixed private drive, whatever disk the test runs on."""
        if os.name == "nt":
            facts = {"filesystem": "NTFS", "removable": False, "drive_type": win32_files.DRIVE_FIXED}
            volumes = lambda handle, drive: facts  # noqa: E731
        else:
            facts = {"filesystem": "native", "removable": False}
            volumes = lambda fd: facts  # noqa: E731
        real = scoped_fs.admit_destination
        return mock.patch.object(scoped_fs, "admit_destination", lambda root, **options: real(root, volumes=volumes, **options))

    def external_plan(self, destination):
        storage = self.storage()
        return storage.plan_backup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/example.txt"],
                                   destination=str(destination), content_read_authorized=True)

    def external_action(self, destination):
        plan = self.external_plan(destination)
        return self.service.prepare_storage_action(self.sid, action_id="backup-external", adapter_id="storage.backup_create",
                                                   storage_plan=plan, output_root=str(self.output), backup_destination=str(destination), **PROSE)

    def attempts(self):
        return [name for name in os.listdir(self.output) if name.startswith("attempt-backup-")]

    def test_admits_only_the_reviewed_destination(self):
        state = self.state()
        destination = self.chosen()
        self.assertIsNone(self.service._admit_backup_destination(state, {"operation": "storage.backup_create", "storage_plan": {}}))
        with self.fixed_drive(), self.service._admit_backup_destination(state, self.payload(destination)) as root:
            self.assertIs(root.destination, True)
        inside = self.output / "inside-the-output-root"
        inside.mkdir()
        for payload in (self.payload(destination, destination=str(destination) + "-other"), self.payload(destination, external=False),
                        {**self.payload(destination), "operation": "storage.restore"},
                        self.payload(inside), self.payload(self.output),  # not another drive: the plan's own output
                        self.payload(ROOT.parent / "outside-the-work-tree")):
            with self.subTest(payload=payload), self.assertRaises(ServiceRefusal):
                self.service._admit_backup_destination(state, payload)

    def test_a_missing_folder_is_named_in_plain_words(self):
        missing = self.root / "work" / "unplugged-drive"
        with self.assertRaises(ServiceRefusal) as caught:
            self.service._admit_backup_destination(self.state(), self.payload(missing))
        self.assertEqual(caught.exception.code, "destination-not-found")
        self.assertEqual(str(caught.exception), f"The backup drive or folder cannot be found: {missing}. Plug the drive in, check that it "
                                                "shows in File Explorer or Finder, then ask me to try again. Nothing was changed.")

    def killed_backup_on_a_reserved_drive(self, stop):
        """An external backup whose drive was reserved as "fictional-reserved-drive", stopped by the patch ``stop``."""
        destination = self.chosen()
        with mock.patch.object(WorkflowService, "_destination_root", return_value="fictional-reserved-drive"), \
                mock.patch.object(scoped_fs, "volume_identity", return_value="fictional-reserved-drive"), stop, self.assertRaises(Stopped):
            action = self.external_action(destination)
            self.execute(action, self.approve(action))

    def killed_at_the_first_write(self):
        def killed(member, data):
            member.archive.fp.committed = True  # as a killed process: nothing removes the temporary file
            raise Stopped()
        return mock.patch.object(storage_backup._Member, "write", killed)

    def attempt_of(self, destination):
        (name,) = self.attempts()
        attempt = json.loads((self.output / name).read_bytes())
        return attempt, destination / attempt["folder"] / attempt["partials"]["archive"]

    def test_a_killed_backup_on_the_wrong_drive_changes_nothing_there(self):
        with self.fixed_drive():
            self.killed_backup_on_a_reserved_drive(self.killed_at_the_first_write())
            attempt, partial = self.attempt_of(self.root / "work" / "external-drive")
            (operation,) = self.state()["operations"].values()
            before = sorted(os.listdir(partial.parent.parent))
            with mock.patch.object(scoped_fs, "volume_identity", return_value="fictional-other-drive"):
                result = self.service.reconcile_operation(self.sid, operation_id=operation["operation_id"])
        self.assertEqual((result["outcome"], result["receipt"]["removed_temporary_files"]), ("failed", []))
        self.assertIn(partial.name, result["receipt"]["kept"])
        self.assertTrue(partial.is_file())
        self.assertEqual(sorted(os.listdir(partial.parent.parent)), before)

    def test_a_killed_backup_on_its_own_drive_is_settled(self):
        with self.fixed_drive():
            self.killed_backup_on_a_reserved_drive(self.killed_at_the_first_write())
            attempt, partial = self.attempt_of(self.root / "work" / "external-drive")
            (operation,) = self.state()["operations"].values()
            with mock.patch.object(scoped_fs, "volume_identity", return_value="fictional-reserved-drive"):
                result = self.service.reconcile_operation(self.sid, operation_id=operation["operation_id"])
        self.assertEqual(result["outcome"], "failed")
        assert_settled(self, result["receipt"], partial)

    def test_a_failed_backup_settles_with_the_reserved_identity_too(self):
        destination = self.chosen()
        with self.fixed_drive(), mock.patch.object(WorkflowService, "_destination_root", return_value="fictional-reserved-drive"), \
                mock.patch.object(scoped_fs, "volume_identity", return_value="fictional-reserved-drive"), \
                mock.patch.object(StorageService, "settle_backup", return_value={"state": "removed", "folder": None, "removed": [], "kept": [],
                                                                                 "leftover": []}) as settle, \
                mock.patch.object(storage_backup._Member, "write", side_effect=scoped_base.ScopedFSError("disk-full", "The drive is full")):
            action = self.external_action(destination)
            result = self.execute(action, self.approve(action))
        self.assertEqual((result["outcome"], result["receipt"]["failure_code"]), ("failed", "disk-full"))
        self.assertEqual(settle.call_args.kwargs["volume_identity"], "fictional-reserved-drive")

    def test_a_receipt_on_the_wrong_drive_stays_unknown_until_the_right_drive_is_back(self):
        with self.fixed_drive():
            self.killed_backup_on_a_reserved_drive(mock.patch.object(StorageService, "verify_outcome", side_effect=Stopped()))
            (operation,) = self.state()["operations"].values()
            with mock.patch.object(scoped_fs, "volume_identity", return_value="fictional-other-drive"), self.assertRaises(StorageRefusal) as caught:
                self.service.reconcile_operation(self.sid, operation_id=operation["operation_id"])
            self.assertEqual(caught.exception.code, "drive-not-connected")
            self.assertIsNone(self.state()["operations"][operation["operation_id"]]["outcome"])
            with mock.patch.object(scoped_fs, "volume_identity", return_value="fictional-reserved-drive"):
                result = self.service.reconcile_operation(self.sid, operation_id=operation["operation_id"])
        self.assertEqual(result["outcome"], "succeeded")

    def test_a_removal_binding_reads_the_archive_past_the_system_cache(self):
        action, _plan = self.backup_action(probe=True)
        result = self.execute(action, self.approve(action))
        binding = {"kind": "backup_recovery", "output_root": str(self.output), "backup_receipt": result["receipt"]["native_receipt"],
                   "restore_receipt": result["receipt"]["restore_probe_receipt"], "purge_receipt": None}
        with scoped_fs.open_root(str(self.output)) as root:  # closed at once: an open root keeps its folder in use
            root_class = type(root)
        real, modes = root_class.open_read, []

        def spy(root, relative, **options):
            if relative.endswith("/backup.zip"):
                modes.append(options["uncached"])
            return real(root, relative, **options)
        with mock.patch.object(root_class, "open_read", spy):
            self.assertIsNone(verify_storage_artifact(binding))
            self.assertIsNone(verify_storage_artifact({**binding, "remove_originals": True}))
        self.assertEqual(modes, [False, True])

    def test_installer_artifact_binding_is_gone(self):
        with self.assertRaises(pc_records.Refusal) as caught:
            verify_storage_artifact({"kind": "installer_artifact", "output_root": str(self.output), "path": str(self.output / "x.msi")})
        self.assertEqual(caught.exception.code, "verifier-binding")
        self.assertFalse(hasattr(sys.modules["service_backup"], "INSTALLER_MAX_BYTES"))

    def test_external_destination_end_to_end(self):
        """engine -> service -> storage into a folder outside the output root."""
        destination = self.chosen()
        with self.fixed_drive():
            action = self.external_action(destination)
            result = self.execute(action, self.approve(action))
        self.assertEqual(result["outcome"], "succeeded")
        receipt = result["receipt"]["native_receipt"]
        self.assertIs(receipt["external"], True)
        self.assertTrue((destination / receipt["folder"] / "backup.zip").is_file())
        location = Path(receipt["location"])
        self.assertTrue(any(root == location or root in location.parents for root in map(Path, self.service.protected_roots())))
        self.assertEqual([row["location"] for row in self.service.retention_rows() if row["kind"] == "backup"], [str(location)])

    def test_external_plan_without_its_wrapper_destination_never_starts(self):
        """The folder is reserved through the wrapper, so an external plan without it stops at preparation, and a payload
        built by hand stops at the engine's binding; nothing reaches the folder."""
        destination = self.chosen()
        with self.fixed_drive():
            plan = self.external_plan(destination)
            with self.assertRaises(StorageRefusal) as caught:
                self.service.prepare_storage_action(self.sid, action_id="backup-unreserved", adapter_id="storage.backup_create",
                                                    storage_plan=plan, output_root=str(self.output), **PROSE)
            self.assertEqual(caught.exception.code, "destination-not-admitted")
            payload = {"schema": "patchcairn.storage.adapter", "schema_version": 1, "operation": "storage.backup_create", "storage_plan": plan,
                       "storage_plan_sha256": plan_sha256(plan), "output_root": str(self.output), "mode": "fixture",
                       "protected_roots": self.service.protected_roots()}
            action = self.service._action(self.state(), action_id="backup-unreserved", adapter_id="storage.backup_create", kind="backup_create",
                                          payload=payload, native_plan=plan, inventory=plan["inventory"], **PROSE)
            with self.assertRaises(WorkflowRefusal) as caught:
                self.approve(action)
            self.assertEqual(caught.exception.code, "storage-payload")
        self.assertEqual(self.state()["operations"], {})
        self.assertEqual(os.listdir(destination), [])

    def test_external_backup_without_its_reservation_finishes_failed_and_writes_nothing(self):
        destination = self.chosen()
        with self.fixed_drive():
            action = self.external_action(destination)
            sha = self.approve(action)
            with mock.patch.object(WorkflowService, "_register_destination"):
                result = self.execute(action, sha)
        self.assertEqual((result["outcome"], result["receipt"]["failure_code"]), ("failed", "destination-not-reserved"))
        self.assertIs(result["receipt"]["no_active_effects"], True)
        self.assertEqual(os.listdir(destination), [])
        self.assertEqual(self.attempts(), [])

    def execute_recording_roots(self):
        """The approved external backup executed: every root admitted while it ran is checked closed afterwards."""
        with self.fixed_drive():
            action = self.external_action(self.chosen())
            sha = self.approve(action)
            roots, admit = [], scoped_fs.admit_destination

            def recording(root, **options):
                roots.append(admit(root, **options))
                return roots[-1]
            with mock.patch.object(scoped_fs, "admit_destination", recording):
                self.addCleanup(lambda: self.assertEqual([root._closed for root in roots], [True] * len(roots)))
                self.addCleanup(lambda: self.assertTrue(roots))
                return self.execute(action, sha)

    def test_admitted_destination_is_closed_when_the_backup_finishes(self):
        self.assertEqual(self.execute_recording_roots()["outcome"], "succeeded")

    def test_admitted_destination_is_closed_when_the_backup_is_refused(self):
        with mock.patch.object(StorageService, "create_backup", side_effect=StorageRefusal("Fictional full drive", code="disk-full")):
            self.assertEqual(self.execute_recording_roots()["outcome"], "failed")

    def test_admitted_destination_is_closed_when_the_backup_stops(self):
        with mock.patch.object(StorageService, "create_backup", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute_recording_roots()


class ServiceBackupTests(SessionFixtures):
    def test_engine_job_with_50000_files_has_bounded_peak_memory(self):
        """A fixture-mode engine -> service -> storage backup of 50,000 files; tracemalloc's peak stays within the
        engine-path bound, 256 MiB plus 2 KiB per file. Every file is one byte, so the test bounds memory, not disk."""
        count = 50_000
        for folder in range(50):
            directory = self.source / f"d{folder:02d}"
            directory.mkdir()
            for index in range(count // 50):
                with open(directory / f"f{index:04d}.txt", "xb") as stream:
                    stream.write(bytes([index % 251]))
        self.service.elevation_probe = lambda: False
        tracemalloc.start()
        try:
            storage = self.storage()
            inventory = storage.assess_storage(roots=[str(self.source)])
            selected = [row["key"] for row in inventory["entries"] if row["kind"] == "file"]
            plan = storage.plan_backup(inventory=inventory, selected=selected, destination=str(self.output),
                                       content_read_authorized=True, required_recovery=False)
            del inventory, selected
            action = self.service.prepare_storage_action(self.sid, action_id="backup-many", adapter_id="storage.backup_create",
                                                         storage_plan=plan, output_root=str(self.output), **PROSE)
            del plan, storage
            result = self.execute(action, self.approve(action))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(result["receipt"]["native_receipt"]["entry_count"], count + 1)
        self.assertLessEqual(peak, (256 << 20) + 2048 * count)


if __name__ == "__main__":
    unittest.main()
