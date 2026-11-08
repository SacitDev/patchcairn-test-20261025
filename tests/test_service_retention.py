"""Selected synthetic work copies only. No host inventory, update or repair.

Retention family (scripts/service_retention.py): recovery registration, the registry of kept recovery data, and the
retention release, session release and forget adapters, each driven through engine, service and storage.
"""
from __future__ import annotations
import ast
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap
import threading
import time
import types
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_records
from workflow_core import WorkflowRefusal, digest, encoded
from storage_ops import StorageRefusal, StorageService
import scoped_fs
from scoped_fs import ScopedFSError
import service_retention
import service_state
import storage_backup
import storage_cleanup
from private_workspace import ensure_private_directory, write_private_new
from workflow_service import WorkflowService, ServiceRefusal
from test_service_state import SessionFixtures, PROSE

RELEASE, SESSION_RELEASE, FORGET = (pc_records.ADAPTER_STORAGE_RETENTION_RELEASE, pc_records.ADAPTER_STORAGE_SESSION_RELEASE,
                                    pc_records.ADAPTER_STORAGE_RETENTION_FORGET)
RETENTION_PROSE = dict(target="Selected fictional kept backups", benefit="Free the space the selected fictional kept backups use",
                       risk="The selected fictional kept backups are deleted permanently",
                       reversibility="None; a permanent deletion cannot be undone",
                       verification="Each kept file is checked against its recorded fingerprint right before deletion")


class Stopped(BaseException):
    """The process stops here: no except clause of the service catches it, so what follows it never runs."""


@contextmanager
def fixed_drive():
    """Destination admission as on a fixed native drive, whatever file system the test folder is on (tmpfs is refused)."""
    if os.name == "nt":
        import win32_files
        volumes = lambda handle, drive: {"filesystem": "NTFS", "removable": False, "drive_type": win32_files.DRIVE_FIXED}  # noqa: E731
    else:
        volumes = lambda fd: {"filesystem": "native", "removable": False}  # noqa: E731
    real = scoped_fs.admit_destination

    def admitted(root, **options):
        return real(root, volumes=volumes, **options)
    with mock.patch.object(scoped_fs, "admit_destination", admitted), mock.patch.object(storage_cleanup, "admit_destination", admitted):
        yield


class WorkflowServiceTests(SessionFixtures):
    def test_recovery_boolean_or_changed_probe_cannot_supply_recovery(self):
        backup_action, native = self.backup_action(probe=True)
        result = self.execute(backup_action, self.approve(backup_action))
        backup, restore = result["receipt"]["native_receipt"], result["receipt"]["restore_probe_receipt"]
        sid = self.session()
        with self.assertRaises((StorageRefusal, KeyError, TypeError)):
            self.service.register_recovery(sid, output_root=str(self.output), backup_receipt={"verified": True}, restore_receipt={"verified": True})
        (Path(restore["destination"]) / "r001" / "example.txt").write_text("Changed probe", encoding="utf-8")
        with self.assertRaises((StorageRefusal, ScopedFSError)):
            self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)


class RetentionFixtures(SessionFixtures):
    """SessionFixtures plus kept backups, retention plans and their approval; it defines no test. The service it
    executes with is told that this process is not elevated (hosted Windows runners are)."""

    def setUp(self):
        super().setUp()
        self.service.elevation_probe = lambda: False

    def kept_backup(self, *, sid=None, suffix="one"):
        """A verified backup with its restoration probe, run in session ``sid`` (a new one by default): (session, the
        names of the kept rows it left, its receipt)."""
        sid = sid or self.session()
        action, _plan = self.backup_action(sid=sid, probe=True, suffix=suffix)
        result = self.execute(action, self.approve(action, sid=sid), sid=sid)
        self.assertEqual(result["outcome"], "succeeded")
        return sid, [row["name"] for row in self.service.retention_rows() if row["session_id"] == sid], result["receipt"]

    def kept_files(self, names):
        """Every file the named kept rows list."""
        return sorted({path for ref, row in self.service._registry() if ref["name"] in names for path in row["artifacts"]})

    def retention_action(self, sid, plan, adapter_id=RELEASE, action_id="kept-release"):
        return self.service.prepare_storage_action(sid, action_id=action_id, adapter_id=adapter_id, storage_plan=plan,
                                                   output_root=str(self.service.work), **RETENTION_PROSE)

    def payload(self, sid, action):
        row = self.state(sid)["evidence"][action["adapter_payload_evidence_id"]]
        return json.loads((self.engine.work / sid / row["path"]).read_bytes())

    def released(self, names, *, adapter_id=RELEASE, session_id=None):
        """Release (or session-release) through engine, service and storage with the typed reply: (session, result)."""
        sid = self.session(job="storage_cleanup")
        plan = self.service.retention_plan(adapter_id, names=None if session_id else names, session_id=session_id)
        action = self.retention_action(sid, plan, adapter_id)
        return sid, self.execute(action, self.approve(action, sid=sid, purge_choice=True), sid=sid)

    def external_row(self, *, identity, folder_exists=False, under_work=False):
        """Write one kept backup row by hand: on a fictional chosen drive outside this engine's work folder, or below it;
        the folder exists only with ``folder_exists``. Returns (row name, folder, its file)."""
        drive = (self.output if under_work else self.root / "chosen-drive")
        ensure_private_directory(drive, create=True, exist_ok=True)
        folder = drive / ("20261026T120000Z-kept-" + uuid.uuid4().hex[:8])
        target = folder / "backup.zip"
        if folder_exists:
            ensure_private_directory(folder, create=True)
            write_private_new(target, b"Fictional kept archive")
        row = self.service._row(self.sid, "backup", location=str(folder), protection_root=str(folder if under_work else drive),
                                artifacts={str(target): hashlib.sha256(b"Fictional kept archive").hexdigest()}, reason="Fictional kept backup",
                                bytes_=22, receipt_sha256="d" * 64, volume_identity=identity)
        before = {ref["name"] for ref, _row in self.service._registry()}
        self.service._write_rows([row])
        return next(ref["name"] for ref, _row in self.service._registry() if ref["name"] not in before), folder, target

    def forget(self, name):
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, self.service.retention_plan(FORGET, names=[name]), FORGET, action_id="kept-forget")
        return self.execute(action, self.approve(action, sid=sid), sid=sid)

    def held(self, name, code):
        with self.assertRaises(ServiceRefusal) as caught:
            self.service.retention_plan(FORGET, names=[name])
        self.assertEqual(caught.exception.code, code)
        self.assertIn(name, {row["name"] for row in self.service.retention_rows()})
        return str(caught.exception)


class RetentionReleaseTests(RetentionFixtures):
    def test_retention_release_needs_owner_approval(self):
        # Two reviews, the engine's warning and the owner's typed reply "delete <N> backups"; an ordinary approval, a
        # wrong reply or no approval at all deletes nothing and begins nothing.
        _sid, names, _receipt = self.kept_backup(sid=self.sid)
        files = self.kept_files(names)
        self.assertTrue(files and all(os.path.exists(path) for path in files))
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, self.service.retention_plan(RELEASE, names=names))
        with self.assertRaises(WorkflowRefusal) as caught:
            self.approve(action, sid=sid)  # the reviews are recorded, then the ordinary approval quote is refused
        self.assertEqual(caught.exception.code, "typed-reply-warning")
        sha = self.state(sid)["plan"]["sha256"]
        warning = self.engine.issue_irreversible_warning(sid, plan_sha256=sha)["data"]
        self.assertEqual(warning["phrase"], f"delete {len(names)} backups")
        for quote, code in (("Apply only this exact synthetic action.", "typed-reply-mismatch"), (f"delete {len(names) + 1} backups", "typed-reply-mismatch")):
            with self.subTest(quote=quote), self.assertRaises(WorkflowRefusal) as caught:
                self.engine.approve_plan(sid, plan_sha256=sha, action_ids=[action["action_id"]], owner_quote=quote,
                                         owner_message_id="fixture-reply-" + uuid.uuid4().hex)
            self.assertEqual(caught.exception.code, code)
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.service.execute_action(sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[])
        self.assertEqual(self.state(sid)["operations"], {})
        self.assertTrue(all(os.path.exists(path) for path in files))
        self.engine.approve_plan(sid, plan_sha256=sha, action_ids=[action["action_id"]], owner_quote=warning["phrase"],
                                 owner_message_id="fixture-typed-reply-" + uuid.uuid4().hex)
        self.engine.advance_stage(sid, evidence_ids=[])
        result = self.execute(action, sha, sid=sid)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(sorted(result["receipt"]["removed"]), files)
        self.assertFalse(any(os.path.exists(path) for path in files))
        self.assertEqual([row for row in self.service.retention_rows() if row["name"] in names], [])
        # Files only: the folders that held them stay.
        self.assertTrue(self.output.is_dir() and (self.output / "one-probe").is_dir())

    def test_retention_release_respects_dependencies(self):
        # A backup that an open quarantine still needs cannot be released: refused when planned, and an earlier
        # approved release is refused again before it begins once the quarantine exists.
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses the native no-overwrite quarantine prerequisite; no fallback")
        _sid, names, receipt = self.kept_backup(sid=self.sid)
        early_sid = self.session(job="storage_cleanup")
        early = self.retention_action(early_sid, self.service.retention_plan(RELEASE, names=names))
        early_sha = self.approve(early, sid=early_sid, purge_choice=True)
        backup, restore = receipt["native_receipt"], receipt["restore_probe_receipt"]
        cleanup_sid = self.session(job="storage_cleanup")
        recovery = self.service.register_recovery(cleanup_sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)
        storage = self.storage()
        plan = storage.plan_cleanup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/example.txt"],
                                    quarantine_destination=str(self.output / "quarantine"), content_read_authorized=True,
                                    recovery_backup=backup, recovery_verification=restore)
        quarantine = self.service.prepare_storage_action(cleanup_sid, action_id="quarantine-selected", adapter_id="storage.quarantine",
                                                         storage_plan=plan, output_root=str(self.output),
                                                         recovery_evidence_ids=[recovery["evidence_id"]], **PROSE)
        self.assertEqual(self.execute(quarantine, self.approve(quarantine, sid=cleanup_sid), sid=cleanup_sid)["outcome"], "succeeded")
        needed = {name for row in self.service._retention() if row["retention_kind"] == "quarantine" for name in row["depends_on"]}
        self.assertTrue(set(names) & needed)
        files = self.kept_files(names)
        with self.assertRaises(ServiceRefusal) as caught:
            self.retention_action(self.session(job="storage_cleanup"), self.service.retention_plan(RELEASE, names=names), action_id="late-release")
        self.assertEqual(caught.exception.code, "kept-row-needed")
        with self.assertRaises(ServiceRefusal) as caught:
            self.execute(early, early_sha, sid=early_sid)
        self.assertEqual(caught.exception.code, "kept-row-needed")
        self.assertEqual(self.state(early_sid)["operations"], {})
        self.assertTrue(all(os.path.exists(path) for path in files))
        self.assertTrue(set(names) <= {row["name"] for row in self.service.retention_rows()})

    def test_release_plan_carries_count_and_bytes(self):
        # The plan lists one row per kept item with the bytes it frees; the payload's delete_count (the N of the typed
        # reply) is the number of those rows and delete_bytes their sum, which is what is on disk.
        _first, first, _receipt = self.kept_backup(sid=self.sid, suffix="one")
        _second, second, _receipt = self.kept_backup(suffix="two")
        names = first + second
        plan = self.service.retention_plan(RELEASE, names=names)
        on_disk = sum(os.path.getsize(path) for path in self.kept_files(names))
        self.assertEqual([row["name"] for row in plan["rows"]], names)
        self.assertEqual(sum(row["size"] for row in plan["rows"]), on_disk)
        self.assertGreater(on_disk, 0)
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, plan)
        payload = self.payload(sid, action)
        self.assertEqual((payload["delete_count"], payload["delete_bytes"]), (len(names), on_disk))
        with self.assertRaises(WorkflowRefusal):
            self.approve(action, sid=sid)
        warning = self.engine.issue_irreversible_warning(sid, plan_sha256=self.state(sid)["plan"]["sha256"])["data"]
        self.assertEqual((warning["number"], warning["bytes"], warning["phrase"]), (len(names), on_disk, f"delete {len(names)} backups"))

    def test_release_plan_says_this_backup_is_the_only_copy(self):
        folder = self.output / "20261026T120000Z-only-copy"
        ensure_private_directory(folder, create=True)
        write_private_new(folder / "backup.zip", b"Fictional archive of removed originals")
        self.service._register_backup(self.state(), location=str(folder), size_bytes=38, receipt_sha256="e" * 64, volume_identity=None)
        self.service.record_originals_removed(str(folder), removed_utc="2026-10-26T09:30:00Z", file_count=12)
        name = next(row["name"] for row in self.service.retention_rows() if row["location"] == str(folder))
        plan = self.service.retention_plan(RELEASE, names=[name])
        self.assertEqual(plan["notes"], ["This backup is the only copy of 12 files: their originals were removed on 2026-10-26."])
        self.assertEqual(plan["rows"][0]["only_copy_files"], 12)
        other = self.output / "20261026T120000Z-other"
        ensure_private_directory(other, create=True)
        write_private_new(other / "backup.zip", b"Fictional archive")
        self.service._register_backup(self.state(), location=str(other), size_bytes=17, receipt_sha256="f" * 64, volume_identity=None)
        other_name = next(row["name"] for row in self.service.retention_rows() if row["location"] == str(other))
        self.assertEqual(self.service.retention_plan(RELEASE, names=[other_name])["notes"], [])
        self.service.record_originals_removed(str(folder), removed_utc="2026-10-26T09:30:00Z", file_count=1)
        name = next(row["name"] for row in self.service.retention_rows() if row["location"] == str(folder))
        self.assertEqual(self.service.retention_plan(RELEASE, names=[name])["notes"],
                         ["This backup is the only copy of 1 file: its original was removed on 2026-10-26."])

    def test_the_bound_plan_carries_the_notes_and_the_rows_the_warning_shows(self):
        # The warning reads storage_plan["notes"] and each row's location and size from the action's bound payload.
        folder = self.output / "20261026T120000Z-only-copy"
        ensure_private_directory(folder, create=True)
        write_private_new(folder / "backup.zip", b"Fictional archive of removed originals")
        self.service._register_backup(self.state(), location=str(folder), size_bytes=38, receipt_sha256="e" * 64, volume_identity=None)
        self.service.record_originals_removed(str(folder), removed_utc="2026-10-26T09:30:00Z", file_count=12)
        name = next(row["name"] for row in self.service.retention_rows() if row["location"] == str(folder))
        self.engine.stop(self.sid)
        for adapter_id, arguments in ((RELEASE, {"names": [name]}), (SESSION_RELEASE, {"session_id": self.sid})):
            with self.subTest(adapter_id=adapter_id):
                sid = self.session(job="storage_cleanup")
                action = self.retention_action(sid, self.service.retention_plan(adapter_id, **arguments), adapter_id)
                bound = self.engine.action_binding(self.state(sid), action)["storage_plan"]
                self.assertEqual(bound["notes"], ["This backup is the only copy of 12 files: their originals were removed on 2026-10-26."])
                self.assertEqual([(row["location"], row["size"], row["only_copy_files"]) for row in bound["rows"]], [(str(folder), 38, 12)])

    def test_every_kept_row_reports_bytes_and_the_rows_add_up_to_what_is_on_disk(self):
        _sid, names, receipt = self.kept_backup(sid=self.sid)
        rows = self.service.retention_rows()
        self.assertEqual(sorted(row["kind"] for row in rows), ["backup", "recovery"])  # the restore test's reservation was replaced
        self.assertTrue(all(type(row["bytes"]) is int for row in rows), rows)
        files = self.kept_files(names)
        self.assertEqual(sum(row["bytes"] for row in rows), sum(os.path.getsize(path) for path in files))
        # Another job that relies on the same backup keeps it safe too, and adds no bytes.
        sid = self.session(job="storage_cleanup")
        self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=receipt["native_receipt"], restore_receipt=receipt["restore_probe_receipt"])
        self.assertEqual([row["bytes"] for row in self.service.retention_rows() if row["session_id"] == sid], [0])

    def test_a_planned_size_that_is_not_there_never_stops_a_quarantine(self):
        self.assertEqual(service_retention._planned({"files": [{"size": 3}, {"size": 4}]}), 7)
        for files in ([{"size": 3}, {}], [{"size": True}], [{"size": -1}], [{"size": "3"}]):
            with self.subTest(files=files):
                self.assertIsNone(service_retention._planned({"files": files}))

    def test_a_size_that_cannot_be_read_never_stops_a_registration(self):
        name = "fictional-kept.bin"
        write_private_new(self.output / name, b"Fictional kept bytes")
        with mock.patch("service_retention._lstat", side_effect=ServiceRefusal("Fictional", code="kept-file-unreadable")):
            self.service._retain(self.sid, {str(self.output / name): "a" * 64}, reason="Fictional")
        self.assertEqual([row["bytes"] for row in self.service.retention_rows()], [None])

    def test_retention_refusals_use_the_person_s_words(self):
        # Every refusal text of the module: these are record and engine words, and the person may read any of them.
        tree = ast.parse((ROOT / "scripts" / "service_retention.py").read_text(encoding="utf-8"))
        constants = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign) for target in node.targets if isinstance(target, ast.Name)}
        texts = [constants["DRIVE_NOT_CONNECTED"], constants["DRIVE_NOT_IDENTIFIED"], constants["LIST_STOPPED"], constants["KEPT_LIST_CHANGED"]]
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "ServiceRefusal":
                texts.append(node.args[0])
        words = [part.value for text in texts for part in ast.walk(text) if isinstance(part, ast.Constant) and isinstance(part.value, str)]
        self.assertGreater(len(words), 20)
        for text in words:
            with self.subTest(text=text):
                self.assertIsNone(re.search(r"\b(rows?|reconcile\w*|settle\w*|released?|quarantine\w*)\b", text, re.I))

    def test_a_changed_kept_file_is_kept_and_its_row_stays(self):
        _sid, names, receipt = self.kept_backup(sid=self.sid)
        archive = receipt["native_receipt"]["archive"]
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, self.service.retention_plan(RELEASE, names=names))
        sha = self.approve(action, sid=sid, purge_choice=True)
        with open(archive, "r+b") as handle:  # same size, other bytes: only the recorded fingerprint can tell
            first = handle.read(1)
            handle.seek(0)
            handle.write(bytes([first[0] ^ 0xFF]))
        result = self.execute(action, sha, sid=sid)
        self.assertEqual(result["outcome"], "partial")
        self.assertIn({"path": archive, "reason": "stale-content"}, result["receipt"]["kept"])
        self.assertTrue(os.path.exists(archive))
        kept = {row["name"] for row in self.service.retention_rows()}
        self.assertTrue(any(name in kept for name in names))
        self.assertTrue(all(os.path.exists(path) is False for path in result["receipt"]["removed"]))

    def test_release_rows_must_match_the_chosen_entries_one_to_one(self):
        # The typed reply counts the plan's rows and the execution deletes its entries' files, so the two must be one list:
        # a plan with one row fewer than it has entries would delete more than the person was told.
        _first, first, _receipt = self.kept_backup(sid=self.sid, suffix="one")
        _second, second, _receipt = self.kept_backup(suffix="two")
        names, sid = first + second, self.session(job="storage_cleanup")
        plan, files = self.service.retention_plan(RELEASE, names=names), self.kept_files(names)
        rows = plan["rows"]
        self.assertGreater(len(rows), 1)
        changed = {"a row left out": {"rows": rows[:-1]}, "a row added": {"rows": rows + rows[:1]}, "another order": {"rows": rows[::-1]},
                   "fewer bytes": {"rows": [{**rows[0], "size": rows[0]["size"] + 1}, *rows[1:]]},
                   "another row's identity": {"rows": [{**rows[0], "sha256": "0" * 64}, *rows[1:]]},
                   "another location": {"rows": [{**rows[0], "location": rows[0]["location"] + "-other"}, *rows[1:]]},
                   "no only-copy note": {"notes": ["This backup is the only copy of 3 files."]}}
        for label, change in changed.items():
            with self.subTest(label), self.assertRaises(ServiceRefusal) as caught:
                self.retention_action(sid, {**plan, **change})
            self.assertEqual(caught.exception.code, "kept-rows-changed")
        self.assertTrue(all(os.path.exists(path) for path in files))
        self.assertEqual(self.retention_action(sid, plan)["adapter_id"], RELEASE)

    def test_bytes_that_change_after_the_approval_stop_the_release_before_any_deletion(self):
        # The reviewed bytes are checked before begin and again inside the effect, right before the first deletion.
        _sid, names, receipt = self.kept_backup(sid=self.sid)
        archive, files = receipt["native_receipt"]["archive"], self.kept_files(names)
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, self.service.retention_plan(RELEASE, names=names))
        sha = self.approve(action, sid=sid, purge_choice=True)
        size = os.path.getsize(archive)
        with open(archive, "ab") as handle:
            handle.write(b"Fictional added bytes")
        with self.assertRaises(ServiceRefusal) as caught:
            self.execute(action, sha, sid=sid)
        self.assertEqual(caught.exception.code, "kept-rows-changed")
        self.assertEqual(self.state(sid)["operations"], {})
        os.truncate(archive, size)
        begin = self.service._begin_adapter

        def changed_after_begin(*args, **kwargs):
            begun = begin(*args, **kwargs)
            with open(archive, "ab") as handle:
                handle.write(b"Fictional added bytes")
            return begun
        with mock.patch.object(self.service, "_begin_adapter", side_effect=changed_after_begin):
            result = self.execute(action, sha, sid=sid)
        self.assertEqual((result["outcome"], result["receipt"]), ("failed", {"changed": False, "reason": "kept-rows-changed"}))
        self.assertTrue(all(os.path.exists(path) for path in files))


class SessionReleaseTests(RetentionFixtures):
    def test_session_release_needs_owner_approval(self):
        # A finished session's kept rows are released only by an owner-approved plan with the typed reply; the
        # engine's own session folder stays.
        sid, names, _receipt = self.kept_backup(sid=self.sid)
        files = self.kept_files(names)
        self.engine.stop(sid)
        release_sid = self.session(job="storage_cleanup")
        plan = self.service.retention_plan(SESSION_RELEASE, session_id=sid)
        self.assertEqual(sorted(entry["name"] for entry in plan["records"]["entries"]), sorted(names))
        action = self.retention_action(release_sid, plan, SESSION_RELEASE)
        with self.assertRaises(WorkflowRefusal) as caught:
            self.approve(action, sid=release_sid)
        self.assertEqual(caught.exception.code, "typed-reply-warning")
        sha = self.state(release_sid)["plan"]["sha256"]
        phrase = self.engine.issue_irreversible_warning(release_sid, plan_sha256=sha)["data"]["phrase"]
        self.engine.approve_plan(release_sid, plan_sha256=sha, action_ids=[action["action_id"]], owner_quote=phrase,
                                 owner_message_id="fixture-typed-reply-" + uuid.uuid4().hex)
        self.engine.advance_stage(release_sid, evidence_ids=[])
        result = self.execute(action, sha, sid=release_sid)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertFalse(any(os.path.exists(path) for path in files))
        self.assertEqual([row for row in self.service.retention_rows() if row["session_id"] == sid], [])
        self.assertTrue((self.engine.work / sid).is_dir())
        self.assertEqual(self.state(sid)["status"], "stopped")

    def test_session_release_is_refused_while_an_operation_is_unknown(self):
        action, _plan = self.backup_action()
        sha = self.approve(action)
        with mock.patch.object(StorageService, "verify_outcome", side_effect=OSError("Fictional interruption")):
            self.assertEqual(self.execute(action, sha)["outcome"], "unknown")
        self.engine.stop(self.sid)
        for refused in (lambda: self.service.retention_plan(SESSION_RELEASE, session_id=self.sid),
                        lambda: self.service.retention_plan(SESSION_RELEASE, session_id=self.session())):
            with self.subTest(), self.assertRaises(ServiceRefusal) as caught:
                refused()
            self.assertIn(caught.exception.code, {"session-not-settled", "service-refusal"})
        self.assertTrue((self.output / "one.zip").exists())

    def test_session_release_reads_the_engine_s_one_restart_state(self):
        # A signal that reads "none" and a recorded boot release the session; a standing signal holds it.
        closed = {"operation_id": "operation-fixture", "outcome": "succeeded", "resolution": None}
        pending = {"restart_pending": {"signal": "required", "source": "fictional-source"}}
        verification = {"restart_verification": {"boot_observed": True, "evidence_id": "e", "sha256": "a" * 64, "recorded_utc": "2026-10-26T12:00:00Z"}}
        for label, extra, refused in (("no marker", {}, False), ("signal gone", {"restart_pending": {"signal": "none", "source": "fictional-source"}}, False),
                                      ("boot seen", {**pending, **verification}, False), ("waiting", pending, True)):
            state = {"status": "stopped", "operations": {"operation-fixture": {**closed, **extra}}}
            with self.subTest(label), mock.patch.object(self.engine, "read_session", return_value=state):
                if refused:
                    with self.assertRaises(ServiceRefusal) as caught:
                        self.service._finished_session("session-fixture")
                    self.assertEqual(caught.exception.code, "session-not-settled")
                else:
                    self.assertIsNone(self.service._finished_session("session-fixture"))

    def test_a_message_id_used_in_a_released_session_stays_used(self):
        # The session release never deletes the engine's session folder, whose typed-reply message ids the engine scans.
        _a, first, _receipt = self.kept_backup(sid=self.sid, suffix="one")
        _b, second, receipt = self.kept_backup(suffix="two")
        used_sid = self.session(job="storage_cleanup")
        self.service.register_recovery(used_sid, output_root=str(self.output), backup_receipt=receipt["native_receipt"],
                                       restore_receipt=receipt["restore_probe_receipt"])
        action = self.retention_action(used_sid, self.service.retention_plan(RELEASE, names=first))
        with self.assertRaises(WorkflowRefusal):
            self.approve(action, sid=used_sid)
        sha = self.state(used_sid)["plan"]["sha256"]
        phrase = self.engine.issue_irreversible_warning(used_sid, plan_sha256=sha)["data"]["phrase"]
        used = "fixture-typed-reply-" + uuid.uuid4().hex
        self.engine.approve_plan(used_sid, plan_sha256=sha, action_ids=[action["action_id"]], owner_quote=phrase, owner_message_id=used)
        self.engine.advance_stage(used_sid, evidence_ids=[])
        self.assertEqual(self.execute(action, sha, sid=used_sid)["outcome"], "succeeded")
        self.engine.stop(used_sid)
        _release_sid, result = self.released(None, adapter_id=SESSION_RELEASE, session_id=used_sid)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual([row for row in self.service.retention_rows() if row["session_id"] == used_sid], [])
        later_sid = self.session(job="storage_cleanup")
        later = self.retention_action(later_sid, self.service.retention_plan(RELEASE, names=second), action_id="later-release")
        with self.assertRaises(WorkflowRefusal):
            self.approve(later, sid=later_sid)
        later_sha = self.state(later_sid)["plan"]["sha256"]
        later_phrase = self.engine.issue_irreversible_warning(later_sid, plan_sha256=later_sha)["data"]["phrase"]
        with self.assertRaises(WorkflowRefusal) as caught:
            self.engine.approve_plan(later_sid, plan_sha256=later_sha, action_ids=[later["action_id"]], owner_quote=later_phrase, owner_message_id=used)
        self.assertEqual(caught.exception.code, "message-id-used")


class QuarantineRowTests(RetentionFixtures):
    """A quarantine's kept row is settled by the files it moved; its own records stay behind as history."""

    def quarantine_row(self):
        return next(row["name"] for row in self.service.retention_rows() if row["kind"] == "quarantine")

    def test_a_purged_quarantine_is_forgotten_and_its_backup_can_then_be_deleted(self):
        sid, action, sha, backup, _restore = self.approved_purge()
        name = self.quarantine_row()
        self.assertEqual(self.execute(action, sha, sid=sid)["outcome"], "succeeded")
        kept = [row["name"] for row in self.service.retention_rows() if row["name"] != name]
        with self.assertRaises(ServiceRefusal) as caught:
            self.service._retention_checks(self.state(sid), {"operation": RELEASE, "storage_plan": self.service.retention_plan(RELEASE, names=kept)})
        self.assertEqual(caught.exception.code, "kept-row-needed")  # the kept row still protects the backup
        try:
            self.assertEqual(self.forget(name)["outcome"], "succeeded")
        except ServiceRefusal as error:
            self.fail(f"A purged quarantine's row must be forgotten: {error.code}")
        self.assertNotIn(name, {row["name"] for row in self.service.retention_rows()})
        _sid, result = self.released(kept)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertFalse(os.path.exists(backup["archive"]))

    def test_a_quarantine_that_still_holds_its_files_is_not_forgotten(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses the native no-overwrite quarantine prerequisite; no fallback")
        self.make_recovery_and_quarantine()
        self.held(self.quarantine_row(), "kept-item-exists")

    def test_a_quarantine_row_reports_the_size_of_what_it_keeps(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses the native no-overwrite quarantine prerequisite; no fallback")
        size = (self.source / "example.txt").stat().st_size
        self.make_recovery_and_quarantine()
        self.assertEqual(next(row["bytes"] for row in self.service.retention_rows() if row["kind"] == "quarantine"), size)


class ForgetTests(RetentionFixtures):
    """storage.retention_forget: no typed reply; it refuses while any item still exists and holds while the recorded
    drive is not connected. The volume lookup is injected."""

    def test_absent_drive_holds(self):
        name, _folder, _file = self.external_row(identity="fixture-volume")
        self.service.volume_lookup = lambda path: "another-fixture-volume"
        message = self.held(name, "drive-not-connected")
        self.assertIn("not connected", message)
        self.assertIn("until that drive is connected again", message)
        self.assertIn("uses no space on this computer", message)

    def test_the_refusal_names_the_folder_and_a_list_says_what_one_drive_stopped(self):
        lost, folder, _file = self.external_row(identity="fixture-volume")
        near, _near, _near_file = self.external_row(identity=None, under_work=True, folder_exists=True)
        self.service.volume_lookup = lambda path: "another-fixture-volume"
        self.engine.stop(self.sid)
        alone = self.held(lost, "drive-not-connected")
        self.assertIn("(" + str(folder) + ")", alone)
        self.assertNotIn("one at a time", alone)
        for arguments in ({"names": [near, lost]}, {"session_id": self.sid}):
            adapter_id = SESSION_RELEASE if "session_id" in arguments else RELEASE
            with self.subTest(adapter_id=adapter_id), self.assertRaises(ServiceRefusal) as caught:
                self.service.retention_plan(adapter_id, **arguments)
            self.assertEqual(caught.exception.code, "drive-not-connected")
            self.assertIn(str(folder), str(caught.exception))
            self.assertIn("can still be deleted one at a time", str(caught.exception))

    def test_present_drive_and_missing_folder_forgets(self):
        name, folder, _file = self.external_row(identity="fixture-volume")
        self.service.volume_lookup = mock.Mock(return_value="fixture-volume")
        result = self.forget(name)
        self.assertEqual((result["outcome"], result["receipt"]["forgotten_rows"]), ("succeeded", [name]))
        self.assertNotIn(name, {row["name"] for row in self.service.retention_rows()})
        self.assertNotIn(str(folder.parent), self.service.protected_roots())
        self.assertEqual(self.service.volume_lookup.call_args.args, (str(folder.parent),))

    def test_present_drive_and_existing_folder_refuses(self):
        name, _folder, target = self.external_row(identity="fixture-volume", folder_exists=True)
        self.service.volume_lookup = lambda path: "fixture-volume"
        self.held(name, "kept-item-exists")
        self.assertTrue(target.exists())

    def test_no_recorded_identity_outside_work_holds(self):
        name, _folder, _file = self.external_row(identity=None)
        self.service.volume_lookup = lambda path: "fixture-volume"
        self.held(name, "drive-not-connected")

    def test_no_recorded_identity_below_work_and_missing_folder_forgets(self):
        name, _folder, _file = self.external_row(identity=None, under_work=True)
        self.service.volume_lookup = mock.Mock(side_effect=AssertionError("the repository's own drive needs no lookup"))
        self.assertEqual(self.forget(name)["outcome"], "succeeded")
        self.service.volume_lookup.assert_not_called()

    def test_a_target_that_cannot_be_checked_holds(self):
        # Only FileNotFoundError and NotADirectoryError mean "gone"; a permission or input/output error holds.
        name, folder, target = self.external_row(identity=None, under_work=True)
        for error in (PermissionError(errno.EACCES, "Fictional permission refusal"), OSError(errno.EIO, "Fictional input/output error")):
            def lstat(path, *args, error=error, **kwargs):
                if str(path) in {str(folder), str(target)}:
                    raise error
                return os.lstat(path, *args, **kwargs)
            # Only the retention module's view of os changes, so the fake error reaches exactly its existence check.
            with self.subTest(error=type(error).__name__), mock.patch("service_retention.os", types.SimpleNamespace(lstat=lstat, path=os.path)):
                self.held(name, "kept-file-unreadable")

    def test_default_volume_lookup_is_scoped_fs_volume_identity(self):
        # scoped_fs.volume_identity gives the drive's identity here.
        service = WorkflowService(self.engine)
        identity = service.volume_lookup(str(self.root))
        self.assertTrue(identity is None or isinstance(identity, str))
        name, _folder, _file = self.external_row(identity=identity or "fixture-volume")
        self.service.volume_lookup = service.volume_lookup
        if identity is None:
            self.held(name, "drive-not-connected")
        else:
            self.assertEqual(self.forget(name)["outcome"], "succeeded")


CHILD = textwrap.dedent('''
    import sys
    from pathlib import Path
    root, scripts, session_id, action_id, plan_sha256, evidence_id, point = sys.argv[1:8]
    sys.path.insert(0, scripts)
    import service_retention
    import storage_cleanup
    from workflow_core import WorkflowEngine
    from workflow_service import WorkflowService, verify_storage_artifact

    def stop():
        print("KILL-POINT", flush=True)
        sys.stdin.read()
        raise SystemExit("the parent did not kill this process")

    if point == "after-first-delete":
        real_root = storage_cleanup.ScopedRoot

        class Folder:
            def __init__(self, *args, **kwargs):
                self.inner = real_root(*args, **kwargs)

            def __enter__(self):
                self.inner.__enter__()
                return self

            def __exit__(self, *exc):
                return self.inner.__exit__(*exc)

            def inspect(self, *args, **kwargs):
                return self.inner.inspect(*args, **kwargs)

            def remove_file(self, *args, **kwargs):
                self.inner.remove_file(*args, **kwargs)
                stop()
        storage_cleanup.ScopedRoot = Folder
    else:
        real_replace = service_retention.atomic_replace

        def replace(*args, **kwargs):
            real_replace(*args, **kwargs)
            stop()
        service_retention.atomic_replace = replace
    engine = WorkflowEngine(Path(root), verify_artifact=verify_storage_artifact)
    WorkflowService(engine, elevation_probe=lambda: False).execute_action(
        session_id, action_id=action_id, plan_sha256=plan_sha256, precondition_evidence_ids=[evidence_id])
    raise SystemExit("finished without reaching the kill point")
''')


class RetentionKillTests(RetentionFixtures):
    """A real process kill (not an exception) at a fixed point after a recorded write, then reconciliation."""

    def killed(self, sid, action, sha, point):
        """Run the approved action in a child started with sys.executable -I -S -B, kill it at ``point`` and return the open
        operation's id. The operating system frees the service lock the killed child held, so nothing is cleaned here."""
        evidence = self.precondition(action, sha, sid=sid)
        child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", CHILD, str(self.root), str(ROOT / "scripts"), sid,
                                  action["action_id"], sha, evidence, point], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, encoding="utf-8")
        watchdog = threading.Timer(300, child.kill)
        watchdog.start()
        try:
            line = child.stdout.readline()
            child.kill()
            child.wait(timeout=60)
        finally:
            watchdog.cancel()
            stderr = child.stderr.read()
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()
        self.assertEqual(line.strip(), "KILL-POINT", stderr)
        (operation,) = [op for op in self.state(sid)["operations"].values() if op["outcome"] is None]
        # The operation's start was stamped by the child, outside this test's forward-only clock, so a backward step of the
        # host clock (seen in WSL) can leave this process behind it. Ordering checks keep no tolerance, so wait it out, bounded.
        started, deadline = pc_records.parse_utc(operation["started_utc"]), time.monotonic() + 30
        while pc_records.parse_utc(pc_records.utc_now()) <= started and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreater(pc_records.parse_utc(pc_records.utc_now()), started, "the host clock stayed behind the operation's start")
        return operation["operation_id"]

    def test_release_killed_after_the_first_deletion_reconciles(self):
        _sid, names, _receipt = self.kept_backup(sid=self.sid)
        files = self.kept_files(names)
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, self.service.retention_plan(RELEASE, names=names))
        operation_id = self.killed(sid, action, self.approve(action, sid=sid, purge_choice=True), "after-first-delete")
        gone = [path for path in files if not os.path.exists(path)]
        self.assertEqual(len(gone), 1)
        result = self.service.reconcile_operation(sid, operation_id=operation_id)
        self.assertEqual((result["outcome"], result["receipt"]["removed"]), ("partial", gone))
        self.assertEqual(sorted(result["receipt"]["kept"]), sorted(set(files) - set(gone)))
        self.assertEqual(result["receipt"]["absent"], [])
        # Every file still on disk is still listed by a kept row; only a row whose files are all gone left the registry.
        listed = {path for row in self.service._retention() for path in row["artifacts"]}
        self.assertTrue(set(files) - set(gone) <= listed)
        self.assertTrue(set(result["receipt"]["released_rows"]) < set(names))

    def test_session_release_killed_after_the_first_deletion_reconciles(self):
        released_sid, names, _receipt = self.kept_backup(sid=self.sid)
        self.engine.stop(released_sid)
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, self.service.retention_plan(SESSION_RELEASE, session_id=released_sid), SESSION_RELEASE)
        operation_id = self.killed(sid, action, self.approve(action, sid=sid, purge_choice=True), "after-first-delete")
        result = self.service.reconcile_operation(sid, operation_id=operation_id)
        self.assertEqual((result["outcome"], len(result["receipt"]["removed"])), ("partial", 1))
        self.assertTrue((self.engine.work / released_sid).is_dir())

    def test_forget_killed_after_the_registry_write_reconciles(self):
        name, _folder, _file = self.external_row(identity=None, under_work=True)
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, self.service.retention_plan(FORGET, names=[name]), FORGET, action_id="kept-forget")
        operation_id = self.killed(sid, action, self.approve(action, sid=sid), "after-registry-write")
        self.assertNotIn(name, {row["name"] for row in self.service.retention_rows()})
        result = self.service.reconcile_operation(sid, operation_id=operation_id)
        self.assertEqual((result["outcome"], result["receipt"]["forgotten_rows"]), ("succeeded", [name]))


class DriveLeftTests(RetentionFixtures):
    """A kept row on a chosen drive: nothing on a drive that cannot be identified counts as removed or absent."""

    def interrupted(self, names):
        """A release of ``names`` through engine and service that stops right after its attempt record, with nothing deleted:
        (its session, its open operation)."""
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, self.service.retention_plan(RELEASE, names=names))
        sha = self.approve(action, sid=sid, purge_choice=True)

        def stopped(targets, *, attempt, **options):
            attempt(sorted(targets), [], [])
            raise Stopped()
        with mock.patch("service_retention.release_set", side_effect=stopped), self.assertRaises(Stopped):
            self.execute(action, sha, sid=sid)
        (operation,) = self.state(sid)["operations"].values()
        return sid, operation["operation_id"]

    def test_an_unplugged_drive_never_counts_as_removed(self):
        name, folder, target = self.external_row(identity="fixture-volume", folder_exists=True)
        near, _near_folder, near_file = self.external_row(identity=None, under_work=True, folder_exists=True)
        self.service.volume_lookup = lambda path: "fixture-volume"
        sid, operation_id = self.interrupted([name, near])
        os.remove(near_file)
        drive, away = folder.parent, folder.parent.with_name("drive-while-unplugged")
        drive.rename(away)
        self.service.volume_lookup = lambda path: "the-volume-of-this-computer"
        result = self.service.reconcile_operation(sid, operation_id=operation_id)
        self.assertEqual((result["outcome"], result["receipt"]["reason"], result["receipt"]["held_rows"]), ("unknown", "drive-not-connected", [name]))
        self.assertNotIn("removed", result["receipt"])
        kept = {row["name"] for row in self.service.retention_rows()}
        self.assertTrue({name, near} <= kept)  # nothing is dropped, not even the row on the drive that is here
        self.assertIn(str(drive), self.service.protected_roots())
        self.assertEqual(self.state(sid)["operations"][operation_id]["outcome"], "unknown")
        again = self.service.reconcile_operation(sid, operation_id=operation_id)
        self.assertEqual((again["outcome"], again["held"], again["automatic_retry"]), ("unknown", True, False))
        # The drive is back, with its file: only now is each path classified, and the known result closes the unknown.
        away.rename(drive)
        self.service.volume_lookup = lambda path: "fixture-volume"
        settled = self.service.reconcile_operation(sid, operation_id=operation_id)
        self.assertEqual((settled["outcome"], settled["receipt"]["removed"], settled["receipt"]["kept"]), ("partial", [str(near_file)], [str(target)]))
        self.assertEqual((settled["receipt"]["released_rows"], settled["receipt"]["kept_rows"]), ([near], [name]))
        self.assertEqual({key: settled["receipt"][key] for key in ("actual_effects_recorded", "no_active_effects", "recovery_retained")},
                         dict.fromkeys(("actual_effects_recorded", "no_active_effects", "recovery_retained"), True))
        self.assertEqual(self.state(sid)["operations"][operation_id]["outcome"], "partial")
        self.assertIn(name, {row["name"] for row in self.service.retention_rows()})
        self.assertTrue(target.exists())

    def test_a_file_gone_from_a_connected_drive_counts_as_removed(self):
        name, _folder, target = self.external_row(identity="fixture-volume", folder_exists=True)
        self.service.volume_lookup = lambda path: "fixture-volume"
        sid, operation_id = self.interrupted([name])
        os.remove(target)
        result = self.service.reconcile_operation(sid, operation_id=operation_id)
        self.assertEqual((result["outcome"], result["receipt"]["removed"]), ("succeeded", [str(target)]))
        self.assertNotIn(name, {row["name"] for row in self.service.retention_rows()})

    def attempted_absent(self, name):
        """A release of ``name`` stopped right after an attempt record that found its file absent: (session, operation id)."""
        sid = self.session(job="storage_cleanup")
        action = self.retention_action(sid, self.service.retention_plan(RELEASE, names=[name]))
        sha = self.approve(action, sid=sid, purge_choice=True)

        def stopped(targets, *, attempt, **options):
            attempt([], sorted(targets), [])
            raise Stopped()
        with mock.patch("service_retention.release_set", side_effect=stopped), self.assertRaises(Stopped):
            self.execute(action, sha, sid=sid)
        (operation,) = self.state(sid)["operations"].values()
        return sid, operation["operation_id"]

    def test_a_file_the_attempt_found_absent_counts_only_while_it_stays_absent(self):
        name, _folder, target = self.external_row(identity="fixture-volume", folder_exists=True)
        self.service.volume_lookup = lambda path: "fixture-volume"
        sid, operation_id = self.attempted_absent(name)
        result = self.service.reconcile_operation(sid, operation_id=operation_id)
        self.assertEqual((result["outcome"], result["receipt"]["absent"], result["receipt"]["kept"], result["receipt"]["kept_rows"]),
                         ("failed", [], [str(target)], [name]))
        self.assertIn(name, {row["name"] for row in self.service.retention_rows()})
        self.assertTrue(target.exists())

    def test_a_file_the_attempt_found_absent_and_still_absent_lets_its_row_go(self):
        name, _folder, target = self.external_row(identity="fixture-volume", folder_exists=True)
        self.service.volume_lookup = lambda path: "fixture-volume"
        sid, operation_id = self.attempted_absent(name)
        os.remove(target)
        result = self.service.reconcile_operation(sid, operation_id=operation_id)
        self.assertEqual((result["outcome"], result["receipt"]["absent"], result["receipt"]["kept"]), ("succeeded", [str(target)], []))
        self.assertNotIn(name, {row["name"] for row in self.service.retention_rows()})

    def test_a_drive_that_leaves_during_the_release_keeps_its_row(self):
        name, _folder, target = self.external_row(identity="fixture-volume", folder_exists=True)
        self.service.volume_lookup = lambda path: "fixture-volume"

        def left(targets, *, attempt, **options):
            attempt([], sorted(targets), [])
            self.service.volume_lookup = lambda path: "the-volume-of-this-computer"
            return {"removed": [], "absent": sorted(targets), "kept": []}
        with mock.patch("service_retention.release_set", side_effect=left):
            _sid, result = self.released([name])
        self.assertEqual(result["outcome"], "partial")
        self.assertEqual((result["receipt"]["absent"], result["receipt"]["kept"]), ([], [{"path": str(target), "reason": "drive-not-connected"}]))
        self.assertIn(name, {row["name"] for row in self.service.retention_rows()})


class ChosenDriveFixtures(RetentionFixtures):
    """Backups to a chosen folder: in a fixture session a folder of the work tree, apart from the output root."""

    def setUp(self):
        super().setUp()
        self.chosen = self.root / "work" / "chosen-drive"
        ensure_private_directory(self.chosen, create=True)

    def chosen_action(self, *, probe=False):
        storage = self.storage()
        plan = storage.plan_backup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/example.txt"],
                                   destination=str(self.chosen), content_read_authorized=True, required_recovery=True)
        return self.service.prepare_storage_action(self.sid, action_id="backup-chosen", adapter_id="storage.backup_create", storage_plan=plan,
                                                   output_root=str(self.output), backup_destination=str(self.chosen),
                                                   restore_probe_destination=str(self.output / "probe") if probe else None, **PROSE)

    def stopped_before_finish(self, action, sha):
        """Run the approved backup and stop the process right after its registration, before its outcome is recorded."""
        with mock.patch.object(self.service, "_finish", side_effect=Stopped()), self.assertRaises(Stopped):
            self.execute(action, sha)
        (operation,) = self.state()["operations"].values()
        return operation["operation_id"]

    def accounted(self, operation):
        """Resolve a failed backup with the owner's choice of a new plan, so the session no longer blocks other work."""
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        evidence = self.evidence("reconciliation", {**facts, "outcome": "failed", "actual_effects_recorded": True, "no_active_effects": True,
                                                    "recovery_retained": True})
        self.engine.resolve(self.sid, pending_id="reconcile-" + operation["operation_id"], choice="revise_plan", evidence_ids=[evidence],
                            owner_quote="Prepare a new plan.", owner_message_id="fixture-replan-" + uuid.uuid4().hex)

    def failed_backup(self, action, sha):
        """Run the approved backup into a full drive; its temporary file is removed and the operation finishes failed.
        Returns (its receipt, the operation, resolved)."""
        full = ScopedFSError("disk-full", "The drive is full")
        with mock.patch.object(storage_backup._Member, "write", side_effect=full):
            result = self.execute(action, sha)
        self.assertEqual(result["outcome"], "failed")
        (operation,) = self.state()["operations"].values()
        self.accounted(operation)
        return result["receipt"]

    def row_name(self, kind):
        (name,) = [row["name"] for row in self.service.retention_rows() if row["kind"] == kind]
        return name


class ChosenDriveTests(ChosenDriveFixtures):
    def test_a_chosen_drive_and_a_local_probe_keep_one_row_per_volume(self):
        # The archive goes to the chosen drive and the restoration probe stays in the work folder. Two Windows drives have no
        # common path, so the fake refuses one across them (a POSIX common path would be the bare root or work folder).
        real, chosen = os.path.commonpath, self.chosen

        def one_volume(paths):
            paths = list(paths)
            if len({Path(path).is_relative_to(chosen) for path in paths}) > 1:
                raise ValueError("Paths don't have the same drive")
            return real(paths)
        with fixed_drive():
            action = self.chosen_action(probe=True)
            sha = self.approve(action)
            with mock.patch("os.path.commonpath", side_effect=one_volume):
                result = self.execute(action, sha)
        self.assertEqual(result["outcome"], "succeeded")
        receipt = result["receipt"]["native_receipt"]
        rows = self.service._retention()
        self.assertEqual({row["retention_kind"] for row in rows if Path(row["protection_root"]) == chosen}, {"backup", "recovery"})
        for row in rows:
            within_chosen = {Path(path).is_relative_to(chosen) for path in row["artifacts"]}
            self.assertEqual(len(within_chosen), 1, row["artifacts"])
            self.assertEqual(within_chosen, {Path(row["protection_root"]).is_relative_to(chosen)})
        # One recovery binding across the two groups: every file of the recovery is on a row with its backup receipt's SHA-256.
        bound = [row for row in rows if row["retention_kind"] == "recovery" and row["receipt_sha256"] == digest(receipt)]
        self.assertEqual(len(bound), 2)
        files = {path for row in bound for path in row["artifacts"]}
        self.assertLessEqual({receipt["archive"], receipt["manifest"], str(self.output / "probe" / "r001" / "example.txt")}, files)
        self.assertNotIn(str(self.root / "work"), self.service.protected_roots())

    def test_a_quarantine_needs_every_row_of_its_recovery(self):
        if not self.native_move_supported:
            self.skipTest("only on posix: the selected mounted filesystem refuses the native no-overwrite quarantine prerequisite; no fallback")
        with fixed_drive():
            action = self.chosen_action(probe=True)
            result = self.execute(action, self.approve(action))
            backup, restore = result["receipt"]["native_receipt"], result["receipt"]["restore_probe_receipt"]
            sid = self.session(job="storage_cleanup")
            recovery = self.service.register_recovery(sid, output_root=str(self.output), backup_receipt=backup, restore_receipt=restore)
            storage = self.storage()
            plan = storage.plan_cleanup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/example.txt"],
                                        quarantine_destination=str(self.output / "quarantine"), content_read_authorized=True,
                                        recovery_backup=backup, recovery_verification=restore)
            quarantine = self.service.prepare_storage_action(sid, action_id="quarantine-selected", adapter_id="storage.quarantine", storage_plan=plan,
                                                             output_root=str(self.output), recovery_evidence_ids=[recovery["evidence_id"]], **PROSE)
            self.assertEqual(self.execute(quarantine, self.approve(quarantine, sid=sid), sid=sid)["outcome"], "succeeded")
        needed = {name for row in self.service._retention() if row["retention_kind"] == "quarantine" for name in row["depends_on"]}
        bound = {ref["name"] for ref, row in self.service._registry() if row["receipt_sha256"] == digest(backup)}
        self.assertGreaterEqual(len(bound), 3)
        self.assertEqual(needed, bound)

    def test_a_backup_interrupted_after_its_registration_registers_once(self):
        action, _plan = self.backup_action(probe=True)
        operation_id = self.stopped_before_finish(action, self.approve(action))
        rows = self.service._registry()
        self.assertEqual(self.service.reconcile_operation(self.sid, operation_id=operation_id)["outcome"], "succeeded")
        self.assertEqual(self.service._registry(), rows)

    def test_a_backup_to_a_chosen_folder_interrupted_after_its_registration_registers_once(self):
        with fixed_drive():
            action = self.chosen_action()
            operation_id = self.stopped_before_finish(action, self.approve(action))
            self.assertEqual([row["kind"] for row in self.service.retention_rows()], ["backup"])  # it replaced the reservation
            rows = self.service._registry()
            self.assertEqual(self.service.reconcile_operation(self.sid, operation_id=operation_id)["outcome"], "succeeded")
        self.assertEqual(self.service._registry(), rows)


class ReservationTests(ChosenDriveFixtures):
    """A reservation that its backup never replaced: it records the drive, and a forget or a release settles it."""

    def reservation(self, identity):
        """A chosen destination's reservation written by hand, on a fictional drive outside the work folder: (its name, the folder)."""
        drive = self.root / "chosen-outside"
        ensure_private_directory(drive, create=True)
        self.service._write_rows([self.service._row(self.sid, "destination", location=str(drive), protection_root=str(drive), artifacts={},
                                                    reason="Fictional reservation", volume_identity=identity)])
        return self.row_name("destination"), drive

    def test_a_reservation_records_the_drive_it_was_admitted_on(self):
        drive = self.root / "chosen-outside"
        state, payload = {**self.state(), "mode": "real"}, {"backup_destination": str(drive), "output_root": str(self.output)}
        self.service.volume_lookup = mock.Mock(return_value="fixture-volume")
        self.service._register_destination(state, payload)
        (row,) = self.service._retention()
        self.assertEqual((row["retention_kind"], row["volume_identity"], row["protection_root"]), ("destination", "fixture-volume", str(drive)))
        self.service.volume_lookup.assert_called_once_with(str(drive))

    def test_a_drive_that_cannot_be_identified_refuses_before_any_effect(self):
        state, payload = {**self.state(), "mode": "real"}, {"backup_destination": str(self.root / "chosen-outside"), "output_root": str(self.output)}
        for lookup in (mock.Mock(return_value=None), mock.Mock(side_effect=OSError("Fictional")), mock.Mock(side_effect=pc_records.Refusal("fixture", "Fictional"))):
            self.service.volume_lookup = lookup
            with self.subTest(lookup=lookup), self.assertRaises(ServiceRefusal) as caught:
                self.service._destination_root(state, payload)
            self.assertEqual(caught.exception.code, "drive-not-identified")
        self.assertEqual(self.service._retention(), [])

    def test_a_reservation_that_fails_after_begin_finishes_failed_with_no_effect(self):
        with fixed_drive():
            action = self.chosen_action()
            sha = self.approve(action)
            with mock.patch.object(self.service, "_register_destination", side_effect=ServiceRefusal("Fictional", code="drive-not-identified")), \
                    mock.patch.object(StorageService, "create_backup") as create:
                result = self.execute(action, sha)
        create.assert_not_called()
        self.assertEqual((result["outcome"], result["receipt"]), ("failed", {"adapter_invoked": False, "reason": "drive-not-identified"}))
        (operation,) = self.state()["operations"].values()
        self.assertFalse((self.service._operation_dir(self.sid, operation["operation_id"]) / "entered.json").exists())

    def test_forget_settles_a_reservation_on_its_identified_drive(self):
        name, drive = self.reservation("fixture-volume")
        self.service.volume_lookup = mock.Mock(return_value="fixture-volume")
        self.assertEqual(self.forget(name)["outcome"], "succeeded")
        self.assertNotIn(name, {row["name"] for row in self.service.retention_rows()})
        self.assertNotIn(str(drive), self.service.protected_roots())
        self.assertTrue(drive.is_dir())  # the chosen folder is the person's; it stays

    def test_a_reservation_holds_while_its_drive_is_not_the_recorded_one(self):
        name, _drive = self.reservation("fixture-volume")
        self.service.volume_lookup = lambda path: "the-volume-of-this-computer"
        self.held(name, "drive-not-connected")

    def test_a_reservation_without_an_identity_outside_work_holds(self):
        name, _drive = self.reservation(None)
        self.service.volume_lookup = mock.Mock(return_value="fixture-volume")
        self.held(name, "drive-not-connected")
        self.service.volume_lookup.assert_not_called()

    def test_a_release_settles_a_reservation_and_deletes_nothing(self):
        name, drive = self.reservation("fixture-volume")
        self.service.volume_lookup = lambda path: "fixture-volume"
        _sid, result = self.released([name])
        self.assertEqual((result["outcome"], result["receipt"]["removed"], result["receipt"]["released_rows"]), ("succeeded", [], [name]))
        self.assertTrue(drive.is_dir())

    def test_a_reservation_whose_drive_leaves_during_the_release_stays(self):
        # A reservation lists no files, so nothing but the drive's identity can keep it: the check runs again after release_set.
        name, drive = self.reservation("fixture-volume")
        self.service.volume_lookup = lambda path: "fixture-volume"

        def left(targets, *, attempt, **options):
            attempt([], [], [])
            self.service.volume_lookup = lambda path: "the-volume-of-this-computer"
            return {"removed": [], "absent": [], "kept": []}
        with mock.patch("service_retention.release_set", side_effect=left):
            _sid, result = self.released([name])
        self.assertEqual((result["outcome"], result["receipt"]["kept_rows"]), ("partial", [name]))
        self.assertIn(name, {row["name"] for row in self.service.retention_rows()})
        self.assertIn(str(drive), self.service.protected_roots())

    def test_a_failed_backup_s_reservation_is_settled_once_its_folder_holds_no_files(self):
        with fixed_drive():
            action = self.chosen_action()
            receipt = self.failed_backup(action, self.approve(action))
        name, folder = self.row_name("destination"), self.chosen / receipt["folder"]
        self.assertEqual(os.listdir(folder), [])
        write_private_new(folder / "backup.zip", b"Fictional file left by the backup")
        message = self.held(name, "kept-item-exists")
        self.assertIn("still holds files", message)
        self.assertIn(str(folder), message)
        self.assertIn(str(self.chosen), self.service.protected_roots())
        os.remove(folder / "backup.zip")
        self.assertEqual(self.forget(name)["outcome"], "succeeded")
        self.assertNotIn(str(self.chosen), self.service.protected_roots())

    def test_a_backup_folder_reserved_in_the_output_folder_is_settled_the_same_way(self):
        action, _plan = self.backup_action()
        receipt = self.failed_backup(action, self.approve(action))
        name, folder = self.row_name("reservation"), self.output / "one.zip" / receipt["folder"]
        write_private_new(folder / "backup.zip", b"Fictional file left by the backup")
        self.held(name, "kept-item-exists")
        os.remove(folder / "backup.zip")
        self.assertEqual(self.forget(name)["outcome"], "succeeded")

    def test_a_release_refuses_a_reservation_whose_folder_holds_files(self):
        action, _plan = self.backup_action()
        receipt = self.failed_backup(action, self.approve(action))
        name, folder = self.row_name("reservation"), self.output / "one.zip" / receipt["folder"]
        write_private_new(folder / "backup.zip", b"Fictional file left by the backup")
        with self.assertRaises(ServiceRefusal) as caught:
            self.service.retention_plan(RELEASE, names=[name])
        self.assertEqual(caught.exception.code, "kept-item-exists")
        os.remove(folder / "backup.zip")
        _sid, result = self.released([name])
        self.assertEqual((result["outcome"], result["receipt"]["removed"], result["receipt"]["released_rows"]), ("succeeded", [], [name]))
        self.assertTrue(folder.is_dir())

    def test_a_reservation_stays_while_its_backup_is_open(self):
        with fixed_drive():
            action = self.chosen_action()
            sha = self.approve(action)
            with mock.patch.object(StorageService, "create_backup", side_effect=Stopped()), self.assertRaises(Stopped):
                self.execute(action, sha)
        self.held(self.row_name("destination"), "kept-row-needed")


class RetentionRegistryTests(RetentionFixtures):
    def test_registry_row_layout_is_golden(self):
        with mock.patch("pc_records.utc_now", return_value="2026-10-26T12:00:00.000000Z"):
            row = self.service._row("session-fixture", "backup", location="/fictional/kept/20261026T120000Z-fixture",
                                    protection_root="/fictional/kept", reason="Verified backup folder; no automatic release",
                                    artifacts={"/fictional/kept/20261026T120000Z-fixture/backup.zip": "b" * 64}, bytes_=4096,
                                    receipt_sha256="a" * 64, volume_identity="fictional-volume-1")
        self.assertEqual(encoded(row), (
            b'{"artifacts":{"/fictional/kept/20261026T120000Z-fixture/backup.zip":"' + b"b" * 64 + b'"},"bytes":4096,'
            b'"created_utc":"2026-10-26T12:00:00.000000Z","depends_on":[],"kind":"required_retention",'
            b'"location":"/fictional/kept/20261026T120000Z-fixture","originals_removed":null,"protection_root":"/fictional/kept",'
            b'"reason":"Verified backup folder; no automatic release","receipt_sha256":"' + b"a" * 64 + b'","retention_kind":"backup",'
            b'"schema":"patchcairn.service","schema_version":1,"session_id":"session-fixture","volume_identity":"fictional-volume-1"}'))
        self.assertEqual(json.loads((self.service.work / "retention.json").read_bytes()),
                         {"entries": [], "kind": "retention_registry", "schema": "patchcairn.service", "schema_version": 1})

    def test_register_backup_writes_one_row_per_folder_and_replaces_its_reservations(self):
        folder = self.output / "20261026T120000Z-fixture"
        ensure_private_directory(folder, create=True)
        write_private_new(folder / "backup.zip", b"Fictional archive")
        write_private_new(folder / "manifest.json", b"Fictional manifest")
        self.service._retain(self.sid, {str(folder / "backup.zip"): None, str(folder / "manifest.json"): None}, reason="Reserved before effect")
        with mock.patch("pc_records.utc_now", return_value="2026-10-26T12:00:00.000000Z"):
            self.service._register_backup(self.state(), location=str(folder), size_bytes=35, receipt_sha256="a" * 64,
                                          volume_identity="fictional-volume-1")
        rows = self.service._retention()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], {**self.service._row(self.sid, "backup", location=str(folder), protection_root=str(folder),
                                                       artifacts={str(folder / "backup.zip"): hashlib.sha256(b"Fictional archive").hexdigest(),
                                                                  str(folder / "manifest.json"): hashlib.sha256(b"Fictional manifest").hexdigest()},
                                                       reason="Verified backup folder; no automatic release", bytes_=35,
                                                       receipt_sha256="a" * 64, volume_identity="fictional-volume-1"),
                                   "created_utc": "2026-10-26T12:00:00.000000Z"})
        self.assertIn(str(folder), self.service.protected_roots())

    def test_registering_a_backup_again_changes_nothing_and_a_conflict_refuses(self):
        folder = self.output / "20261026T120000Z-fixture"
        ensure_private_directory(folder, create=True)
        write_private_new(folder / "backup.zip", b"Fictional archive")
        details = dict(location=str(folder), size_bytes=17, receipt_sha256="a" * 64, volume_identity=None)
        self.service._register_backup(self.state(), **details)
        registry = (self.service.work / "retention.json").read_bytes()
        self.service._register_backup(self.state(), **details)
        self.assertEqual((self.service.work / "retention.json").read_bytes(), registry)
        for state, changed in ((self.state(), {**details, "receipt_sha256": "b" * 64}), (self.state(self.session()), details),
                               (self.state(), {**details, "location": str(folder).replace("fixture", "FIXTURE")})):
            with self.subTest(changed=changed), self.assertRaises(ServiceRefusal) as caught:
                self.service._register_backup(state, **changed)
            self.assertEqual(caught.exception.code, "backup-row-conflict")
        self.assertEqual((self.service.work / "retention.json").read_bytes(), registry)

    def test_external_row_on_an_absent_drive_still_constructs_and_is_protected(self):
        # Rows outside the work folder are checked by text only: building a service never opens the chosen drive.
        name, folder, _file = self.external_row(identity="fixture-volume")

        def guarded(real):
            def call(path, *args, **kwargs):
                if str(path).startswith(str(folder.parent)):
                    raise AssertionError("the chosen drive was opened while the service was built")
                return real(path, *args, **kwargs)
            return call
        lstat, stat_call = guarded(os.lstat), guarded(os.stat)
        # POSIX code asks whether os.stat takes dir_fd by looking it up in these sets, so the fake must stand in there too.
        with mock.patch.object(os, "lstat", lstat), mock.patch.object(os, "stat", stat_call), \
                mock.patch.object(os, "supports_dir_fd", os.supports_dir_fd | {stat_call}), \
                mock.patch.object(os, "supports_follow_symlinks", os.supports_follow_symlinks | {stat_call}):
            service = WorkflowService(self.engine)
            roots = service.protected_roots()
        self.assertIn(str(folder.parent), roots)
        self.assertIn(name, {row["name"] for row in service.retention_rows()})

    def test_reading_a_row_checks_its_files_by_text_and_looks_for_links_only_at_its_root_and_location(self):
        folder = self.output / "kept-many"
        artifacts = {str(folder / f"{index:05d}.bin"): "a" * 64 for index in range(200)}
        row = self.service._row(self.sid, "backup", location=str(folder), protection_root=str(folder), reason="Fictional", artifacts=artifacts)
        real = service_state.no_links
        with mock.patch("service_state.no_links", side_effect=real) as checked:
            self.assertIs(self.service._checked_row(row), row)
        self.assertLessEqual(checked.call_count, 2)
        outside = {**artifacts, str(self.output / "kept-other" / "backup.zip"): "a" * 64}
        with self.assertRaisesRegex(ServiceRefusal, "does not contain"):
            self.service._checked_row({**row, "artifacts": outside})
        for path in ("relative/backup.zip", str(folder) + "/../elsewhere/backup.zip"):
            with self.subTest(path=path), self.assertRaises(ServiceRefusal):
                self.service._checked_row({**row, "artifacts": {path: "a" * 64}})

    def test_equal_path_is_inside_its_protection_root_and_a_look_alike_is_not(self):
        folder = self.output / "kept-equal"
        row = self.service._row(self.sid, "backup", location=str(folder), protection_root=str(folder), reason="Fictional",
                                artifacts={str(folder / "backup.zip"): "a" * 64})
        self.assertIs(self.service._checked_row(row), row)
        outside = [self.output / "kept-equal-other"]
        if sys.platform != "darwin":  # U+212A (KELVIN SIGN) for "k": another name on Windows and Linux, the same on macOS (private_workspace.relative_parts).
            outside.append(self.output / "\u212aept-equal")
        for path in outside:
            with self.subTest(path.name.encode("unicode_escape").decode()), self.assertRaisesRegex(ServiceRefusal, "does not contain"):
                self.service._checked_row({**row, "location": str(path)})

    def test_registry_lists_kept_rows_without_file_lists(self):
        _sid, names, _receipt = self.kept_backup(sid=self.sid)
        rows = self.service.retention_rows()
        self.assertEqual(sorted(row["name"] for row in rows), sorted(names))
        for row in rows:
            self.assertEqual(set(row), {"name", "kind", "session_id", "location", "bytes", "created_utc", "volume_identity", "originals_removed"})


if __name__ == "__main__":
    unittest.main()
