"""Backup plans and streamed, verified backup creation, mixed into storage_ops.StorageService (see its trust model).

A backup is one folder, <UTC yyyymmddTHHMMSSZ>-<label>, created exclusively below the plan's destination (an owned
work folder, or a folder on a drive the person chose): backup.zip (ZIP64, DEFLATE, each entry named "<root id>/<relative
path>" with the UTF-8 flag), manifest.json (JSON Lines) and README.txt, written last. Every selected file is streamed
from its pinned source in CHUNK_BYTES pieces and hashed as it is read; the archive keeps a temporary .partial-* name
until storage_verify has read every entry back from the drive, and only a no-replace rename gives it its final name.
On a chosen drive manifest.json names no file that was left out; the private plan file keeps that list.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import os
import re
import stat
import time
import zipfile
from contextlib import ExitStack
from pathlib import Path

import pc_paths
import pc_records
import scoped_base
import scoped_fs
import win32_files
from storage_policy import (StorageRefusal, about_size, admitted_destination, archive_bound, attempt_record, bound_plan,
                            canonical, checked_absolute, content_permission, new_plan, selection, shown_path, storage_value,
                            synced_folder, within)
from storage_verify import READ_BACK_NOTE, ManifestLines, plan_row, verify_archive

LABEL = re.compile(r"[a-z0-9-]{1,32}\Z")
FOLDER = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-z0-9-]{1,32}\Z")
ARCHIVE, MANIFEST, README = "backup.zip", "manifest.json", "README.txt"
# Plain reasons for entries an assessment lists as not included (scoped_base.EXCLUDED_REASONS).
NOT_INCLUDED = {"link": "a link; not included", "special": "a special file; not included",
                "hard-link": "a file with more than one hard link; not included",
                "not-portable": "a name that cannot be used on every system; not included",
                "path-too-long": "path longer than the portable limit; not included",
                "case-collision": "a name that differs from another only by case or form; not included",
                "online-only": "kept online only by a cloud service; never downloaded and not included",
                scoped_base.MORE_EXCLUDED: "more entries not included"}
_NOT_SELECTED = "not selected; not backed up"
_FOLDER_NOT_BACKED_UP = "directory metadata and empty-directory preservation are not backed up; selected child contents may be included"
# The reasons a left-out row may keep on a chosen drive: a reason given with the plan may name the file.
_FIXED_REASONS = frozenset({*NOT_INCLUDED.values(), _NOT_SELECTED, _FOLDER_NOT_BACKED_UP})
# A source that fails one of these while it is read changed during the backup: recorded as changed, never as backed up.
CHANGED_CODES = frozenset({"stale-identity", "stale-content", "read-drift", "read-growth", "missing-entry", "expected-record"})
# Fields a manifest entry adds to the plan's row.
MANIFEST_FIELDS = frozenset({"crc32", "read_only", "dacl_protected", "changed", "archived", "archived_size", "archived_sha256"})
_RECEIPT_BYTES_AT_MOST = 16_384
# One record per temporary file of a backup, named by its key in the attempt record.
_PARTIAL_KEYS = frozenset({"archive", "manifest", "readme"})
_PARTIAL_RECORD_BYTES = 1024
_OTHER_DRIVE = ("The drive at {} is not the one this backup was written to. Nothing was changed. Connect the right drive, then ask "
                "me to check again.")
_POSIX_CHECK_NOTE = "Checking this drive writes one empty temporary file in the chosen folder and removes it again."
MEMORY_NOTE = ("Files are streamed in 1 MiB pieces; memory grows only with the number of files (their list and the "
               "archive's directory), not with their size.")
README_TEXT = """PatchCairn backup
=================

What is inside
- backup.zip: copies of the files you chose. Each one is stored as <folder number>/<path inside that folder>; the
  folder numbers (r001, r002, ...) and the original folders they stand for are listed below.
- manifest.json: one line per file with its size, SHA-256 and CRC-32 checksums, permissions and whether it changed
  while it was copied (a file that changed is marked "changed" and is not a usable copy).
- README.txt: this note.

The archive is NOT encrypted. Anyone who can open this folder can read the files in it.

How to restore
- With PatchCairn: ask it to restore this backup. It checks the archive against its receipt first, and never
  overwrites a file.
- By hand: open backup.zip with any ZIP tool (File Explorer, Finder, unzip) and copy out the files you need.

Keep a second copy: a backup on the same disk as the originals is lost together with them if that disk fails.
Copy this folder to another drive or to cloud storage you trust.

Folders in this backup
"""


class _EntryInfo(zipfile.ZipInfo):
    """A member whose name is always stored as UTF-8 with the UTF-8 flag set (zipfile sets the flag only for names
    outside ASCII)."""

    __slots__ = ()

    def _encodeFilenameFlags(self):
        return self.filename.encode("utf-8"), self.flag_bits | 0x800


def entry_info(name, mtime_ns):
    """The ZIP member of one regular file: DEFLATE, mode 0600, its modification time in UTC (clamped to ZIP's range)."""
    info = _EntryInfo(name, time.gmtime(min(max(mtime_ns // 1_000_000_000, 315532800), 4354819198))[:6])
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


class _Member:
    """The writer stream_to feeds for one file: opens the archive member at the first piece (an empty file at close),
    hashes what it passes on, and keeps a destination failure apart from a changed source."""

    def __init__(self, archive, info):
        self.archive, self.info, self.stream, self.digest, self.size, self.failure = archive, info, None, hashlib.sha256(), 0, None

    def write(self, data):
        try:
            if self.stream is None:
                self.stream = self.archive.open(self.info, "w", force_zip64=True)
            self.stream.write(data)
        except BaseException as error:
            self.failure = error
            raise
        self.digest.update(data)
        self.size += len(data)
        return len(data)

    def close(self):
        """Finish the member (an empty one for a file that gave no bytes); its CRC-32 is then in self.info.CRC."""
        if self.stream is None:
            self.write(b"")
        self.stream.close()


def _in_use(error, relative):
    """A source that another program holds open or has locked: a typed refusal that names it, never retried."""
    if isinstance(error, scoped_base.ScopedFSError) and error.code == "sharing-violation":
        return StorageRefusal(f"A selected file ({pc_paths.display(relative)}) is in use by another program, so the backup stopped and "
                              "no backup was made. Close that program, then ask me to plan the backup again.", code="file-in-use")
    return error


class StorageBackup:
    """StorageService's backup plan and archive creation."""

    def plan_backup(self, *, inventory, selected, destination, content_read_authorized, required_recovery=True,
                    exclusions=None, label="backup", size_budget_bytes=None, non_private_destination=False):
        """A hash-bound backup plan. ``destination`` is the folder that will hold the backup folder: the owned output
        root or a folder below it, or a folder on another drive (admitted as a backup destination now; a drive that
        cannot keep files private needs ``non_private_destination=True``, the person's acknowledgment of the plan's
        privacy note). ``size_budget_bytes`` is the person's optional limit on the selected files' total size."""
        content_permission(content_read_authorized)
        if type(required_recovery) is not bool or type(non_private_destination) is not bool:
            raise StorageRefusal("Required recovery and the non-private acknowledgment must be explicit booleans")
        if not isinstance(label, str) or not LABEL.fullmatch(label):
            raise StorageRefusal("A backup label is 1 to 32 lowercase letters, digits or hyphens")
        if size_budget_bytes is not None and (type(size_budget_bytes) is not int or size_budget_bytes < 0):
            raise StorageRefusal("A size budget is a whole number of bytes")
        if exclusions is not None and (not isinstance(exclusions, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) or not v.strip() or len(v) > 400 for k, v in exclusions.items())):
            raise StorageRefusal("Exclusions require exact keys and bounded human-readable reasons")
        destination = checked_absolute(destination)
        external = not within(destination, self.output_root)
        if external and within(self.output_root, destination):
            raise StorageRefusal("Choose the output folder itself, a folder below it, or a separate folder for the backup")
        self._apart_from_sources(destination, inventory["roots"])
        selected_rows = selection(inventory, selected)
        if len(selected_rows) > pc_records.MAX_BACKUP_ENTRIES:
            raise StorageRefusal("A backup holds at most " + str(pc_records.MAX_BACKUP_ENTRIES) + " files", code="entry-cap")
        total = sum(row["size"] for row in selected_rows)
        if size_budget_bytes is not None and total > size_budget_bytes:
            raise StorageRefusal(f"The selected files total {about_size(total)}, more than your size budget of "
                                 f"{about_size(size_budget_bytes)}. Select fewer files or raise the budget.", code="size-budget")
        self._fresh_inventory(inventory)
        privacy = {"external": external, "non_private_destination": non_private_destination, "private": True,
                   "privacy_note": None, "destination_check_note": None}
        rows = []
        with ExitStack() as stack:
            if external:
                self._require_unsynced(destination)
                root = self.backup_destination or stack.enter_context(admitted_destination(destination, non_private_destination))
                privacy.update(private=root.private, privacy_note=root.privacy_note,
                               destination_check_note=None if os.name == "nt" else _POSIX_CHECK_NOTE)
            sources = self._source_roots(stack, inventory["roots"])
            for item in selected_rows:
                try:
                    hashed = sources[item["root_id"]].inspect(item["relative_path"], hash_file=True)
                except scoped_base.ScopedFSError as error:
                    raise _in_use(error, item["relative_path"]) from error
                original = {key: value for key, value in item.items() if key not in {"root_id", "key"}}
                if {**hashed, "sha256": None} != {**original, "sha256": None}:
                    raise StorageRefusal("Selected file identity or metadata changed")
                rows.append({"entry": item["root_id"] + "/" + item["relative_path"], "root_id": item["root_id"],
                             "key": item["key"], **hashed})
        skipped = []
        selected_set = set(selected)
        for item in inventory["entries"]:
            if item["key"] not in selected_set:
                default_reason = _FOLDER_NOT_BACKED_UP if item["kind"] == "directory" else _NOT_SELECTED
                skipped.append({"key": item["key"], "kind": item["kind"],
                                "reason": item.get("reason") or (exclusions or {}).get(item["key"], default_reason)})
        for row in inventory["not_included"]:
            skipped.append({"key": "/".join(part for part in (row["root_id"], row["parent"], row["name"]) if part),
                            "kind": "not_included", "reason": NOT_INCLUDED[row["reason"]], **({"count": row["count"]} if "count" in row else {})})
        if exclusions and any(key not in {item["key"] for item in skipped} for key in exclusions):
            raise StorageRefusal("Exclusion reasons may refer only to exact skipped inventory entries")
        synced = sorted({service for service in (synced_folder(item["path"]) for item in inventory["roots"]) if service})
        plan = new_plan("backup", inventory=inventory, files=rows, skipped=skipped, destination=str(destination),
                        label=label, size_budget_bytes=size_budget_bytes, sources_synced=synced, **privacy,
                        required_recovery=required_recovery, compression="deflate", encryption=False,
                        layout={"folder": "<UTC yyyymmddTHHMMSSZ>-" + label, "archive": ARCHIVE, "manifest": MANIFEST,
                                "readme": README})
        manifest_most = 2 * len(canonical(rows)) + 512 * (len(rows) + 4) + len(canonical(skipped)) + len(canonical(inventory["roots"]))
        plan["cost"] = {"source_logical_bytes": total, "archive_bytes_at_most": archive_bound(rows),
                        "manifest_bytes_at_most": manifest_most, "control_record_bytes": 0,
                        "stream_chunk_bytes": scoped_base.CHUNK_BYTES, "peak_process_memory": MEMORY_NOTE,
                        "duration_seconds": None, "money": None, "net_free_space_change_bytes": None}
        # The plan file, the attempt record, the records of the temporary files and the receipt, measured: the plan's own
        # size is in its cost, so the figure counts its own digits (the 0 in the plan now is one of them).
        attempt = len(canonical(attempt_record("backup", "0" * 64, f"plan-backup-{'0' * 64}.json", plan, **_names(label))))
        measured = (len(canonical(plan)) + attempt + len(_PARTIAL_KEYS) * _PARTIAL_RECORD_BYTES + _RECEIPT_BYTES_AT_MOST
                    + 4 * len(str(destination)) - 1)
        digits = len(str(measured))
        plan["cost"]["control_record_bytes"] = measured + len(str(measured + digits))
        return plan

    def backup_names(self, *, plan):
        """The run-time names of a backup of ``plan``: its folder (<UTC yyyymmddTHHMMSSZ>-<label>) and the temporary names
        of backup.zip, manifest.json and README.txt. A caller may take them first (to reserve the folder) and pass them
        to create_backup."""
        now = pc_records.utc_now()  # 2026-10-26T12:34:56.123456Z
        stamp = now[0:4] + now[5:7] + now[8:10] + "T" + now[11:13] + now[14:16] + now[17:19] + "Z"
        return _names(plan["label"], folder=stamp + "-" + plan["label"])

    def create_backup(self, *, plan, expected_plan_sha256, names=None):
        """Create the reviewed backup and return its receipt. The attempt record, with the run-time folder name and the
        temporary names, is written exclusively before the folder or any of its files exists, and each temporary file's
        identity is recorded before its first byte. A refusal leaves at most those records, the empty folder and the
        recorded temporary names, which settle_backup removes."""
        bound_plan(plan, expected_plan_sha256, "backup")
        names = names or self.backup_names(plan=plan)
        if (not isinstance(names, dict) or set(names) != {"folder", "partials"} or not FOLDER.fullmatch(str(names["folder"]))
                or not names["folder"].endswith("-" + plan["label"]) or not isinstance(names["partials"], dict)
                or set(names["partials"]) != {"archive", "manifest", "readme"}
                or any(not isinstance(name, str) or not scoped_base.PARTIAL_NAME.fullmatch(name) for name in names["partials"].values())):
            raise StorageRefusal("Backup names must come from backup_names()")
        self._backup_preconditions(plan)
        with ExitStack() as stack:
            output = stack.enter_context(scoped_fs.open_root(str(self.output_root)))
            destination = self._backup_destination_root(stack, plan, create=True)
            sources = self._source_roots(stack, plan["inventory"]["roots"])
            self._backup_preflight(plan, destination, output)
            attempt = f"attempt-backup-{expected_plan_sha256}.json"
            plan_file = f"plan-backup-{expected_plan_sha256}.json"
            self._write_record(output, attempt, attempt_record("backup", expected_plan_sha256, plan_file, plan, **names))
            self._write_record(output, plan_file, plan)
            folder = names["folder"]
            destination.mkdir(folder)

            def created(key):
                return lambda out: self._note_partial(output, destination, expected_plan_sha256, key, names["partials"][key], out)
            rows, archive_record = self._write_archive(destination, folder, names["partials"]["archive"], plan, sources,
                                                       created=created("archive"))
            manifest_record = self._write_lines(destination, folder + "/" + MANIFEST, names["partials"]["manifest"],
                                                self._manifest_lines(plan, expected_plan_sha256, rows), created=created("manifest"))
            readme_record = self._write_lines(destination, folder + "/" + README, names["partials"]["readme"],
                                              [self._readme(plan, rows).encode("utf-8")], created=created("readme"))
            receipt = self._receipt(plan, expected_plan_sha256, folder, destination, sources, rows,
                                    (archive_record, manifest_record, readme_record), _control_bytes(output, expected_plan_sha256))
            self._write_record(output, f"outcome-backup-{expected_plan_sha256}.json", receipt)
            return receipt

    @staticmethod
    def _receipt(plan, plan_digest, folder, destination, sources, rows, records, control_bytes):
        """The backup receipt: where the backup is, what it holds, how it was checked, and the facts the follow-up plans
        and the retention registry read (outcome, durable, changed_count, not_included_count, volume_identity,
        sources_synced, disk_relation)."""
        archive, manifest, readme = ({key: value for key, value in record.items() if key != "durable"} for record in records)
        changed, root = sum(row["changed"] for row in rows), Path(plan["destination"])
        return {**storage_value("backup_receipt"), "plan_sha256": plan_digest,
                "outcome": "partial" if changed else "succeeded", "destination": plan["destination"], "folder": folder,
                "location": str(root / folder), "external": plan["external"], "private": destination.private,
                "archive": str(root / folder / ARCHIVE), "archive_record": archive, "archive_sha256": archive["sha256"],
                "manifest": str(root / folder / MANIFEST), "manifest_record": manifest, "manifest_sha256": manifest["sha256"],
                "readme": str(root / folder / README), "readme_sha256": readme["sha256"],
                "durable": all(record.get("durable") is True for record in records),
                "entry_count": len(rows), "changed_count": changed,
                "not_included_count": sum(row.get("count", 1) for row in plan["skipped"] if row["kind"] == "not_included"),
                "required_recovery": plan["required_recovery"], "verified": True, "verification": READ_BACK_NOTE,
                "encryption": False, "volume_identity": scoped_fs.volume_identity(plan["destination"]),
                "sources_synced": plan["sources_synced"], "disk_relation": _disk_relation(sources, destination),
                "attempt": f"attempt-backup-{plan_digest}.json",
                "actual_archive_bytes": archive["size"], "archive_and_manifest_bytes": archive["size"] + manifest["size"],
                "backup_bytes": archive["size"] + manifest["size"] + readme["size"], "control_record_bytes": control_bytes,
                "source_logical_bytes": sum(row["size"] for row in rows if not row["changed"]),
                "finished_utc": pc_records.utc_now()}

    def settle_backup(self, *, plan, expected_plan_sha256, finish=False, volume_identity=None):
        """Put in order what a backup that failed or was interrupted left, from its attempt record alone (the destination
        folder is never listed), and say what is there:
          - no attempt record: {"state": "not-started"};
          - its outcome receipt exists: {"state": "finished", "receipt": ...};
          - a final backup.zip without a receipt: with ``finish``, the archive is read back and verified against the
            final manifest.json, README.txt is written if it is missing (under a fresh temporary name when a file this
            drive cannot prove the backup's has the recorded one: that file stays, in "leftover") and the receipt is written
            ("finished"); otherwise, or when that fails, the files stay ({"state": "kept"});
          - else each recorded .partial-* name is removed, by name, inside the backup folder, when it is the file this
            backup created (_remove_partial), after its bytes are hashed on the delete handle ({"state": "removed"}).
        ``volume_identity`` is the identity reserved for a chosen drive: nothing is written or removed there, admission's
        check included, unless the folder is on that volume ({"state": "kept"}); a receipt on another drive is not read
        back (refused drive-not-connected). "removed" and "kept" list the names; a name that could not be removed or
        proven this backup's (in use, an absent or other drive, a replaced file, a drive whose file ids do not last or can
        be used again) is in "kept", never reported as removed. "leftover" gives the full path of each file found at a
        recorded temporary name that the drive's file ids cannot tell from a file made later under that name (POSIX, FAT,
        exFAT): it may be the backup's temporary file or another, so it stays for the person to judge. A POSIX device number
        is never compared: it changes across a restart."""
        bound_plan(plan, expected_plan_sha256, "backup")
        result = {"state": "not-started", "folder": None, "removed": [], "kept": [], "leftover": []}
        with ExitStack() as stack:
            output = stack.enter_context(scoped_fs.open_root(str(self.output_root)))
            try:
                attempt = self._read_record(output, f"attempt-backup-{expected_plan_sha256}.json", "attempt",
                                            "The backup's attempt record is unreadable")
            except scoped_base.ScopedFSError as error:
                if error.code != "missing-entry":
                    raise
                return result
            names = {key: attempt.get(key) for key in ("folder", "partials")}
            if (attempt.get("plan_sha256") != expected_plan_sha256 or not isinstance(names["folder"], str)
                    or not FOLDER.fullmatch(names["folder"]) or not isinstance(names["partials"], dict)
                    or set(names["partials"]) != _PARTIAL_KEYS
                    or any(not isinstance(name, str) or not scoped_base.PARTIAL_NAME.fullmatch(name) for name in names["partials"].values())):
                raise StorageRefusal("The backup's attempt record is not this plan's")
            folder = result["folder"] = names["folder"]
            try:
                receipt = self._read_record(output, f"outcome-backup-{expected_plan_sha256}.json", "backup_receipt",
                                            "The backup's receipt is unreadable")
                if volume_identity is not None and not _on_reserved_volume(plan, volume_identity):
                    raise StorageRefusal(_OTHER_DRIVE.format(shown_path(plan["destination"])), code="drive-not-connected")
                return {**result, "state": "finished", "receipt": receipt}
            except scoped_base.ScopedFSError as error:
                if error.code != "missing-entry":
                    raise
            kept = {**result, "state": "kept", "kept": [*names["partials"].values(), ARCHIVE, MANIFEST, README]}
            if not _on_reserved_volume(plan, volume_identity):
                return kept
            try:
                destination = self._backup_destination_root(stack, plan)
            except (StorageRefusal, scoped_base.ScopedFSError):
                return kept
            if not _on_reserved_volume(plan, volume_identity):  # the folder is pinned now: this is the drive every step below uses
                return kept
            final = _present(destination, folder + "/" + ARCHIVE)
            if final and finish:
                with contextlib.suppress(StorageRefusal, scoped_base.ScopedFSError):
                    receipt, leftover = self._finish_backup(stack, plan, expected_plan_sha256, folder, names, destination, output)
                    return {**result, "state": "finished", "receipt": receipt, "leftover": leftover}
            for key, name in names["partials"].items():
                try:
                    if _present(destination, folder + "/" + name):
                        removed = self._remove_partial(output, destination, expected_plan_sha256, key, folder, name)
                        result["removed" if removed else "kept"].append(name)
                        if removed is None:
                            result["leftover"].append(str(Path(plan["destination"]) / folder / name))
                except scoped_base.ScopedFSError:
                    result["kept"].append(name)
            if final:
                result["kept"] += [name for name in (ARCHIVE, MANIFEST, README) if _present(destination, folder + "/" + name)]
            return {**result, "state": "kept" if final else "removed"}

    def _note_partial(self, output, destination, plan_digest, key, name, out):
        """Record the identity of the temporary file ``out`` before its first byte, so that a later settlement can tell it
        from whatever takes its name afterwards. A file killed before this ran has no record and stays, as does every
        temporary file on a drive whose file ids do not last or can be used again, which records nothing."""
        identity = destination.created_identity(out.record())
        if identity is not None:
            self._write_record(output, _partial_record(plan_digest, key),
                               {**storage_value("attempt"), "operation": "backup-temporary-file", "plan_sha256": plan_digest,
                                "name": name, "identity": identity})

    def _remove_partial(self, output, destination, plan_digest, key, folder, name):
        """Remove the recorded temporary file ``name`` when it is the object this backup created: its identity now equals the
        identity recorded when it was created, on the very record the delete handle then compares. True when it was removed;
        None when it stays because this drive's file ids do not last or can be used again, so no record can tell it from a
        file made later under its name; False when it stays because ownership cannot be established: a name, or a hash taken
        now, proves nothing."""
        relative = folder + "/" + name
        if destination.created_identity(destination.inspect(relative)) is None:
            return None
        saved = _partial_record(plan_digest, key)
        if not _present(output, saved):
            return False
        noted = self._read_record(output, saved, "attempt", "The record of a backup's temporary file is unreadable")
        record = destination.inspect(relative, hash_file=True)
        if (noted.get("plan_sha256") != plan_digest or noted.get("name") != name or not noted.get("identity")
                or noted["identity"] != destination.created_identity(record)):
            return False
        destination.remove_file(relative, expected=record, allow_read_only=scoped_base.read_only(record))
        return True

    def _finish_backup(self, stack, plan, plan_digest, folder, names, destination, output):
        """Finish a backup whose archive got its final name before the process stopped: verify it against its final
        manifest, write README.txt if missing, then the receipt (durable is False: the old syncs cannot be confirmed).
        Returns (receipt, leftover paths). A file at the note's recorded temporary name that this drive cannot prove the
        backup's stays where it is and is returned as leftover; the note is then written under a fresh temporary name."""
        lines = ManifestLines()
        manifest_record = destination.inspect(folder + "/" + MANIFEST, hash_file=True)
        destination.stream_to(folder + "/" + MANIFEST, expected=manifest_record, writer=lines)
        manifest = lines.manifest()
        if manifest["plan_sha256"] != plan_digest or [plan_row(row) for row in manifest["entries"]] != plan["files"]:
            raise StorageRefusal("The finished archive's manifest is not this plan's")
        archive_record = destination.inspect(folder + "/" + ARCHIVE, hash_file=True)
        with destination.open_read(folder + "/" + ARCHIVE, expected=archive_record) as handle:
            verify_archive(handle, manifest["entries"])
        leftover = []
        if not _present(destination, folder + "/" + README):
            partial = names["partials"]["readme"]
            removed = True  # nothing has the recorded name
            if _present(destination, folder + "/" + partial):
                removed = self._remove_partial(output, destination, plan_digest, "readme", folder, partial)
            if removed is False:
                raise StorageRefusal("Another file has taken the temporary name of this backup's note")
            if removed is None:
                leftover.append(str(Path(plan["destination"]) / folder / partial))
                partial = None
            self._write_lines(destination, folder + "/" + README, partial, [self._readme(plan, manifest["entries"]).encode("utf-8")])
        readme_record = destination.inspect(folder + "/" + README, hash_file=True)
        try:
            sources = self._source_roots(stack, plan["inventory"]["roots"])
        except (StorageRefusal, scoped_base.ScopedFSError):
            sources = {}
        receipt = self._receipt(plan, plan_digest, folder, destination, sources, manifest["entries"],
                                (archive_record, manifest_record, readme_record), _control_bytes(output, plan_digest))
        receipt["durable"] = False
        self._write_record(output, f"outcome-backup-{plan_digest}.json", receipt)
        return receipt, leftover

    def _write_archive(self, destination, folder, partial, plan, sources, *, created=None):
        """backup.zip under its recorded temporary name: ``created`` is told of the new file before its first byte, every
        file is streamed into its own member, then the whole archive is read back and verified, then committed (no-replace
        rename, synced). Returns the manifest rows and the archive's committed record."""
        relative = folder + "/" + ARCHIVE
        destination.admit_new(relative, archive_bound(plan["files"]))
        rows = []
        with destination.open_new(relative, partial=partial) as out:
            if created is not None:
                created(out)
            archive = zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True)
            try:
                for row in plan["files"]:
                    rows.append(self._archive_entry(archive, sources[row["root_id"]], row))
                archive.close()
            except BaseException:
                archive.fp = None  # the temporary file is discarded: nothing more is written to it, not even at collection
                raise
            verify_archive(out, rows)
            record = out.commit()
        return rows, record

    @staticmethod
    def _archive_entry(archive, source, row):
        """One file streamed into the archive. A source that changes while it is read gives a "changed" row (its bytes
        stay in the archive, marked); a file in use and a destination failure refuse the whole backup."""
        expected = {key: value for key, value in row.items() if key not in {"entry", "root_id", "key"}}
        member = _Member(archive, entry_info(row["entry"], row["mtime_ns"]))
        try:
            source.stream_to(row["relative_path"], expected=expected, writer=member.write)
        except scoped_base.ScopedFSError as error:
            if member.failure is not None or error.code not in CHANGED_CODES:
                raise _in_use(error, row["relative_path"]) from error
            if member.stream is not None:
                member.close()
            return {**row, "changed": True, "archived": member.stream is not None, "archived_size": member.size,
                    "archived_sha256": member.digest.hexdigest(), "crc32": member.info.CRC if member.stream else None}
        member.close()
        return {**row, "crc32": member.info.CRC, "read_only": scoped_base.read_only(row),
                "dacl_protected": win32_files.dacl_protected(str(source.root / row["relative_path"])) if os.name == "nt" else None,
                "changed": False}

    @staticmethod
    def _manifest_lines(plan, plan_digest, rows):
        """manifest.json, one JSON object per line: the header (a backup_manifest record), one line per entry, one line
        per left-out entry (on a chosen drive without its name, see _nameless)."""
        header = {**storage_value("backup_manifest"), "format": "json-lines", "created_utc": pc_records.utc_now(),
                  "plan_sha256": plan_digest, "required_recovery": plan["required_recovery"],
                  "source_roots": plan["inventory"]["roots"], "entry_count": len(rows),
                  "changed_count": sum(row["changed"] for row in rows), "skipped_count": len(plan["skipped"]),
                  "source_logical_bytes": sum(row["size"] for row in rows if not row["changed"]),
                  "compression_is_not_encryption": True, "archive": ARCHIVE}
        yield canonical(header) + b"\n"
        for row in rows:
            yield canonical(row) + b"\n"
        for row in plan["skipped"]:
            yield canonical({"skipped": _nameless(row) if plan["external"] else row}) + b"\n"

    @staticmethod
    def _write_lines(destination, relative, partial, chunks, *, created=None):
        """A small file streamed under its recorded temporary name (``created`` as in _write_archive), then committed."""
        with destination.open_new(relative, partial=partial) as out:
            if created is not None:
                created(out)
            for chunk in chunks:
                for start in range(0, len(chunk), scoped_base.CHUNK_BYTES):
                    out.write(chunk[start:start + scoped_base.CHUNK_BYTES])
            return out.commit()

    @staticmethod
    def _readme(plan, rows):
        lines = [README_TEXT]
        for root in plan["inventory"]["roots"]:
            lines.append(f"- {root['root_id']}: {shown_path(root['path'])}\n")
        changed = sum(row["changed"] for row in rows)
        lines.append(f"\n{len(rows) - changed} files backed up" + (f"; {changed} changed while they were copied and are "
                                                                     "marked in manifest.json" if changed else "") + ".\n")
        return "".join(lines)


def _names(label, folder=None):
    """The run-time folder name and the temporary names a backup records before it creates any of them."""
    return {"folder": folder or "00000000T000000Z-" + label,
            "partials": {"archive": scoped_base.new_partial_name(), "manifest": scoped_base.new_partial_name(),
                         "readme": scoped_base.new_partial_name()}}


def _partial_record(plan_digest, key):
    """The control record holding the identity of one temporary file, in the output folder."""
    return f"partial-{key}-{plan_digest}.json"


def _control_bytes(output, plan_digest):
    """The bytes of a backup's control records so far: its attempt and plan records and those of its temporary files."""
    names = [f"attempt-backup-{plan_digest}.json", f"plan-backup-{plan_digest}.json",
             *(_partial_record(plan_digest, key) for key in sorted(_PARTIAL_KEYS))]
    return sum(output.inspect(name)["size"] for name in names if _present(output, name))


def _nameless(row):
    """A left-out row as a chosen drive holds it: whoever has the drive reads manifest.json, so no name, and no reason
    written for this plan, which may hold one. The private plan file keeps the full row."""
    reason = row["reason"] if row["reason"] in _FIXED_REASONS else "left out on purpose"
    return {"kind": row["kind"], "reason": reason, **({"count": row["count"]} if "count" in row else {})}


def _on_reserved_volume(plan, volume_identity):
    """True for a backup in the owned work folder, and for one on a chosen drive when ``volume_identity``, the identity
    reserved for that drive, is known and is what the destination folder's volume has now."""
    return plan["external"] is False or (volume_identity is not None and scoped_fs.volume_identity(plan["destination"]) == volume_identity)


def _present(root, relative):
    """True when ``relative`` names an entry of ``root``; False when it is missing (any other refusal propagates)."""
    try:
        root.inspect(relative)
    except scoped_base.ScopedFSError as error:
        if error.code == "missing-entry":
            return False
        raise
    return True


def _disk_relation(sources, destination):
    """"same" when any source shares the destination's disk, "different" when every one is proven on another disk."""
    relations = set()
    for source in sources.values():
        try:
            relations.add(scoped_fs.disk_relation(source, destination))
        except (scoped_base.ScopedFSError, OSError):
            relations.add("unknown")
    return "same" if "same" in relations else "different" if relations == {"different"} else "unknown"
