"""Retention family: the registry of kept recovery data, the protected roots every storage plan must include, recovery
registration, and the retention release, session release and forget adapters.

The registry (retention.json, a retention_registry service record) names one required_retention record by name and
SHA-256 for each kept backup folder, quarantine set, recovery binding or chosen backup destination. A record keeps
digests and counts only: its kind, location and protection root, bytes, the receipt SHA-256, the destination volume
identity (or null), its creation time (UTC), the exact files it keeps with their SHA-256 (or null while not yet
written), the kept rows it depends on, and when the originals it backs up were removed. Bytes count each file for one
row only, so the rows add up to what is kept; a reservation has none. A row outside this engine's
work folder (a backup on a drive the person chose) is checked by text only, so a service is built even while that
drive is not connected. Kept files are deleted only through storage_cleanup.release_set; there is no automatic expiry.

One row covers one volume: a recovery kept on two drives is two rows that share its backup receipt's SHA-256. A
reservation (a chosen destination protected before a backup's first write, or a backup folder reserved before it exists)
holds no verified files; it is settled by a forget or a release once its backup is no longer open or unknown and the
backup folders it covers hold no files. The chosen folder itself stays: it is the person's.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import stat
import uuid

import pc_paths
import pc_records
import storage_contract
from workflow_core import (encoded, digest, read_record_bytes, atomic_replace, exact_fields, record_identifier, restart_state,
                           WorkflowRefusal, QUARANTINE_RECOVERY, RECOVERY_BINDING, RECOVERY_RETENTION)
from storage_ops import StorageService
from storage_cleanup import release_set
import scoped_fs
from scoped_fs import ScopedRoot
from scoped_base import MAX_STREAM_BYTES
from private_workspace import ensure_private_directory, relative_parts
from service_state import ServiceRefusal, apart, decoded, private_read, service_record, service_value, within

ROW_FIELDS = frozenset({"schema", "schema_version", "kind", "session_id", "created_utc", "reason", "retention_kind", "location",
                        "protection_root", "bytes", "receipt_sha256", "volume_identity", "artifacts", "depends_on", "originals_removed"})
RETENTION_KINDS = ("backup", "destination", "quarantine", "recovery", "reservation")
# The rows that only reserve what a backup may write: no verified files, nothing for a release to delete.
RESERVED_KINDS = frozenset({"destination", "reservation"})
RELEASE, SESSION_RELEASE, FORGET = (pc_records.ADAPTER_STORAGE_RETENTION_RELEASE, pc_records.ADAPTER_STORAGE_SESSION_RELEASE,
                                    pc_records.ADAPTER_STORAGE_RETENTION_FORGET)
DRIVE_NOT_CONNECTED = ("The drive that holds this kept backup ({folder}) is not connected, so PatchCairn cannot check it. The record stays "
                       "until that drive is connected again. If the drive will never come back (lost or reformatted), only this record "
                       "remains; it uses no space on this computer.")
# Added when that drive stopped a list of kept items, such as all of one job's.
LIST_STOPPED = " Because of this nothing on the list was deleted, but the other kept items can still be deleted one at a time."
KEPT_LIST_CHANGED = "The list of kept items changed after you reviewed it. Nothing was deleted. I make a new list for you to check."
DRIVE_NOT_IDENTIFIED = ("PatchCairn cannot identify the drive of this backup folder, so it could not tell later whether the drive is "
                        "connected. Nothing was changed. Choose a folder on another drive.")
# What a reconciliation that observed every effect records: the facts a replacement plan needs.
ACCOUNTED = {"actual_effects_recorded": True, "no_active_effects": True, "recovery_retained": True}


def _exact(value):
    """``value`` as a Path when it is exact absolute path text: normalised, no "." or ".." part, comparable by name."""
    path = Path(value) if isinstance(value, str) and 0 < len(value) <= storage_contract.MAX_PATH_TEXT and "\x00" not in value else None
    if (path is None or not path.is_absolute() or str(path) != value or {".", ".."} & set(path.parts)
            or relative_parts(path, path.anchor) is None):
        raise ServiceRefusal("Kept items are named by exact absolute paths")
    return path


def _folded(path):
    return tuple(part.casefold() for part in Path(path).parts)


def _lstat(path):
    """os.lstat of ``path``, or None only for FileNotFoundError or NotADirectoryError; any other error holds, because a
    drive that cannot be read is not proof that a file is gone."""
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as error:
        raise ServiceRefusal("A kept file could not be checked; nothing was changed", code="kept-file-unreadable") from error


def _present(path):
    return _lstat(path) is not None


def _holds_files(folder):
    """False only when the reserved backup folder ``folder`` is absent or empty; a folder that cannot be read holds."""
    info = _lstat(folder)
    if info is None:
        return False
    if not stat.S_ISDIR(info.st_mode):
        return True
    try:
        with os.scandir(folder) as entries:
            return next(entries, None) is not None
    except OSError as error:
        raise ServiceRefusal("A kept file could not be checked; nothing was changed", code="kept-file-unreadable") from error


def _measured(paths):
    """The bytes of those of ``paths`` that are ordinary files now. None when none is, or when one cannot be read: the size
    is a report, so it never stops a registration."""
    try:
        found = [info for info in map(_lstat, paths) if info is not None and stat.S_ISREG(info.st_mode)]
    except ServiceRefusal:
        return None
    return sum(info.st_size for info in found) if found else None


def _planned(plan):
    """The bytes a quarantine plan will move, or None when a row does not say: as with _measured, the size never stops the work."""
    sizes = [row.get("size") for row in plan["files"]]
    return sum(sizes) if all(type(size) is int and size >= 0 for size in sizes) else None


def _shown(path):
    """A folder as the person reads it: names made safe to show, the separators kept."""
    return pc_paths.display(path).replace(chr(92) + "u005c", chr(92))


def _targets(row):
    """What must be gone before a row is forgotten: its files, and its own folder for a backup. A quarantine set counts only
    the files it moved, which have a SHA-256; its attempt, outcome and step records stay as the history of that move."""
    if row["retention_kind"] == "quarantine":
        return [path for path, sha in row["artifacts"].items() if sha is not None]
    return [*row["artifacts"], *([row["location"]] if row["retention_kind"] == "backup" else [])]


def _merged(chosen):
    """The files of the chosen rows, each with the SHA-256 any of them records for it (None when none does). A reservation
    lists no file to delete."""
    targets = {}
    for _ref, row in chosen:
        if row["retention_kind"] not in RESERVED_KINDS:
            for path, sha in row["artifacts"].items():
                targets[path] = targets.get(path) or sha
    return targets


def _only_copy_notes(chosen):
    """The release plan's sentence for each chosen backup whose originals were removed."""
    notes = []
    for _ref, row in chosen:
        if row["originals_removed"]:
            count, day = row["originals_removed"]["file_count"], row["originals_removed"]["removed_utc"][:10]
            notes.append(f"This backup is the only copy of 1 file: its original was removed on {day}." if count == 1
                         else f"This backup is the only copy of {count} files: their originals were removed on {day}.")
    return notes


class RetentionMixin:
    """The kept-recovery registry, the protected roots, recovery bindings and the three retention adapters."""

    def _registry(self):
        """(entry, row) of every kept row, each record checked against its entry's SHA-256 and its own layout."""
        ensure_private_directory(self.work)
        registry = service_record(decoded(private_read(self.work / "retention.json")), "retention_registry")
        exact_fields(registry, {"schema", "schema_version", "kind", "entries"}, {"schema", "schema_version", "kind", "entries"})
        if not isinstance(registry["entries"], list) or len(registry["entries"]) > 10000:
            raise ServiceRefusal("Invalid protected retention registry")
        rows = []
        for ref in registry["entries"]:
            exact_fields(ref, {"name", "sha256"}, {"name", "sha256"})
            record_identifier(ref["name"])
            data = private_read(self.work / (ref["name"] + ".json"))
            if digest(data) != ref["sha256"]:
                raise ServiceRefusal("Protected retention record changed")
            rows.append((ref, self._checked_row(service_record(decoded(data), "required_retention"))))
        return rows

    def _retention(self):
        return [row for _ref, row in self._registry()]

    def _kept_path(self, value, destinations):
        """The one rule for every kept path: below this engine's work folder it must be owned and free of links
        (_owned); anywhere else it is checked by text only, never opened, and must lie inside one of ``destinations``
        (chosen backup destination folders)."""
        path = _exact(value)
        if within(path, self.root / "work"):
            return self._owned(value)
        if not any(within(path, Path(root)) for root in destinations):
            raise ServiceRefusal("Kept files stay below the work folder or inside a chosen backup destination")
        return path

    def _checked_row(self, row):
        exact_fields(row, ROW_FIELDS | {"quarantine_binding"}, ROW_FIELDS)
        record_identifier(row["session_id"])
        pc_records.parse_utc(row["created_utc"])
        removed, identity = row["originals_removed"], row["volume_identity"]
        if (row["retention_kind"] not in RETENTION_KINDS or not isinstance(row["reason"], str) or not isinstance(row["artifacts"], dict)
                or (row["retention_kind"] == "destination") != (not row["artifacts"])
                or any(sha is not None and not (isinstance(sha, str) and pc_records.SHA256.fullmatch(sha)) for sha in row["artifacts"].values())
                or row["bytes"] is not None and (type(row["bytes"]) is not int or row["bytes"] < 0)
                or row["receipt_sha256"] is not None and not (isinstance(row["receipt_sha256"], str) and pc_records.SHA256.fullmatch(row["receipt_sha256"]))
                or identity is not None and not (isinstance(identity, str) and 0 < len(identity) <= 512 and identity.isprintable())
                or not isinstance(row["depends_on"], list) or any(not isinstance(name, str) for name in row["depends_on"])
                or removed is not None and (not isinstance(removed, dict) or set(removed) != {"removed_utc", "file_count"}
                                            or type(removed["file_count"]) is not int or removed["file_count"] < 1)):
            raise ServiceRefusal("Invalid protected retention evidence")
        if removed is not None:
            pc_records.parse_utc(removed["removed_utc"])
        root = row["protection_root"]
        protection = self._kept_path(root, [root])
        # The root and location once; the files by text, because this runs on every read of the registry, and a row can list
        # very many. release_set refuses links when it uses a path.
        if not within(self._kept_path(row["location"], [root]), protection) or not all(within(_exact(path), protection) for path in row["artifacts"]):
            raise ServiceRefusal("Retention protection does not contain its exact artifacts")
        if "quarantine_binding" in row:
            self._validate_quarantine_reservation(row)
        return row

    def _external(self, row):
        return not within(Path(row["protection_root"]), self.root / "work")

    def _chosen_roots(self, rows):
        """{folder: recorded volume identity} of the chosen backup destinations that the kept ``rows`` protect: a destination
        row's folder, and the root of a row that keeps files below it. A fixture's chosen folder lies below the work folder."""
        return {row["protection_root"]: row["volume_identity"] for row in rows
                if row["retention_kind"] == "destination" or row["protection_root"] != row["location"] or self._external(row)}

    def protected_roots(self):
        """The folders every storage plan must keep out of reach, named exactly: the engine's work folder, this service's
        work folder, work/backups, and each kept row's protection root (a kept output folder, or a chosen backup
        destination). A folder inside another listed one adds nothing, so the list grows with destinations, not with
        backups. The bare work folder is never listed: selected fixture copies below it stay admissible."""
        candidates = {str(self.engine.work), str(self.work), str(self.root / "work" / "backups")}
        candidates |= {row["protection_root"] for row in self._retention()}
        roots = []
        for root in sorted(candidates, key=lambda value: (len(Path(value).parts), value)):
            if not any(within(Path(root), Path(kept)) for kept in roots):
                roots.append(root)
        if len(roots) > storage_contract.MAX_PROTECTED_ROOTS:
            raise ServiceRefusal("Protection policy exceeds the payload bound; retain evidence and narrow scope")
        return sorted(roots)

    def _write_rows(self, rows, *, drop=(), registry=None):
        """Write each new row record, then the registry with ``drop`` (entry names) removed and the new rows added.
        ``registry`` is the caller's _registry() result when nothing has changed the registry since it was read."""
        current = [ref for ref, _row in (self._registry() if registry is None else registry) if ref["name"] not in set(drop)]
        for row in rows:
            self._checked_row(row)
            name = "retention-" + uuid.uuid4().hex
            current.append({"name": name, "sha256": self._immutable(self.work / (name + ".json"), row)["sha256"]})
        if len(current) > 10000:
            raise ServiceRefusal("PatchCairn's list of kept items is full. Delete some kept backups first.")
        atomic_replace(self.work / "retention.json", encoded(service_value("retention_registry", entries=current)))

    def _row(self, session_id, kind, *, location, protection_root, artifacts, reason, bytes_=None, receipt_sha256=None,
             volume_identity=None, depends_on=()):
        return service_value("required_retention", session_id=session_id, created_utc=pc_records.utc_now(), reason=reason,
                             retention_kind=kind, location=location, protection_root=protection_root, bytes=bytes_,
                             receipt_sha256=receipt_sha256, volume_identity=volume_identity, artifacts=artifacts,
                             depends_on=list(depends_on), originals_removed=None)

    def _retain(self, session_id, artifacts, *, reason, quarantine_binding=None, receipt_sha256=None, backup_files=()):
        """Keep ``artifacts`` as one row per volume: the files inside a chosen destination below that folder, with its
        recorded volume identity, and the rest below their common folder in work. The rows of one recovery share
        ``receipt_sha256``, the SHA-256 of its backup receipt, and what needs one of them needs them all. A group this
        session already keeps identically is not added again, because a reconciliation repeats the registration, and a
        group replaces this session's earlier recovery row of part of it (the restore test's files, reserved before they
        were written). A row's bytes are its files as they stand now, leaving out ``backup_files``, which the backup's own
        row reports, and files another row already reports; a quarantine reserved before its first move takes the planned
        size, and a reservation has none."""
        registry = self._registry()
        chosen = self._chosen_roots(row for _ref, row in registry)
        groups = {}
        for path, sha in artifacts.items():
            kept = self._kept_path(path, chosen)
            groups.setdefault(max((root for root in chosen if within(kept, Path(root))), key=len, default=None), {})[path] = sha
        needs = []
        if quarantine_binding is not None:
            backup = quarantine_binding["original_plan"].get("recovery_backup")
            if isinstance(backup, dict):
                needs = [ref["name"] for ref, row in registry if backup.get("archive") in row["artifacts"] or row["receipt_sha256"] == digest(backup)]
        reported = {_folded(path) for path in backup_files} | {_folded(path) for _ref, row in registry if row["bytes"] is not None for path in row["artifacts"]}
        rows, replaced = [], []
        for root, group in groups.items():
            kind = "quarantine" if quarantine_binding is not None else "reservation" if all(v is None for v in group.values()) else "recovery"
            if quarantine_binding is None and any(row["session_id"] == session_id and row["retention_kind"] == kind and row["artifacts"] == group
                                                  for _ref, row in registry):
                continue
            own = [path for path in group if _folded(path) not in reported]
            size = (_planned(quarantine_binding["original_plan"]) if quarantine_binding is not None
                    else None if kind == "reservation" else _measured(own) if own else 0)
            location = os.path.commonpath([str(Path(path).parent) for path in group])
            rows.append(self._row(session_id, kind, location=location, protection_root=root or location, artifacts=group, reason=reason, bytes_=size,
                                  receipt_sha256=receipt_sha256, volume_identity=chosen.get(root), depends_on=needs))
            if quarantine_binding is not None:
                rows[-1]["quarantine_binding"] = copy.deepcopy(quarantine_binding)
            elif kind == "recovery":
                replaced += [ref["name"] for ref, row in registry if row["session_id"] == session_id and row["retention_kind"] == kind
                             and row["artifacts"].keys() < group.keys()]
        if rows:
            self._write_rows(rows, drop=replaced, registry=registry)

    def _destination_root(self, state, payload):
        """The checks of a payload's chosen backup destination folder, before begin and again when it is registered: exact
        absolute path text outside this engine's work folder (a backup inside it goes to work/backups without one), on a
        drive with a volume identity to record. A fixture session never leaves that work folder: its "other drive" is a
        folder there, apart from the output root. Returns the identity, None for a folder below work."""
        destination, work = payload["backup_destination"], self.root / "work"
        path = _exact(destination)
        if state["mode"] == "fixture":
            if not within(path, work) or not apart(path, payload["output_root"]):
                raise ServiceRefusal("A fixture's chosen backup destination stays below the work folder, apart from the output folder")
            return None
        if within(path, work):
            raise ServiceRefusal("A chosen backup destination must lie outside the work folder")
        try:
            identity = self.volume_lookup(destination)
        except (OSError, pc_records.Refusal):
            identity = None
        if identity is None:
            raise ServiceRefusal(DRIVE_NOT_IDENTIFIED, code="drive-not-identified")
        return identity

    def _register_destination(self, state, payload):
        """Protect a chosen backup destination folder before the backup's first write: a row with no files whose protection
        root is that folder, with its volume identity, replaced by the backup's own row when the backup is registered. A
        backup that never gets there leaves it as a reservation (_require_settled)."""
        identity, destination = self._destination_root(state, payload), payload["backup_destination"]
        self._write_rows([self._row(state["session_id"], "destination", location=destination, protection_root=destination, artifacts={},
                                    reason="Chosen backup destination protected before the first write", volume_identity=identity)])

    def _register_backup(self, state, *, location, size_bytes, receipt_sha256, volume_identity):
        """Register one verified backup folder: its files are listed with their SHA-256 (read now, while the drive is
        connected; subfolders are not kept files) with the folder's bytes, receipt SHA-256, destination volume identity
        (or None) and creation time (UTC). This session's earlier reservations of that folder, and the destination row
        that protected it before the write, are replaced. Called once per verified backup folder, inside its operation or
        its reconciliation: a repeat with the same session, location and receipt changes nothing, and any other row for
        that folder refuses."""
        path = _exact(location)
        if (type(size_bytes) is not int or size_bytes < 0 or not isinstance(receipt_sha256, str) or not pc_records.SHA256.fullmatch(receipt_sha256)
                or volume_identity is not None and not (isinstance(volume_identity, str) and 0 < len(volume_identity) <= 512)):
            raise ServiceRefusal("A verified backup needs its folder, size, receipt SHA-256 and volume identity")
        registry = self._registry()
        session, external = state["session_id"], not within(path, self.root / "work")
        same = [row for _ref, row in registry if row["retention_kind"] == "backup" and _folded(row["location"]) == _folded(location)]
        if same:
            if [(row["session_id"], row["location"], row["receipt_sha256"]) for row in same] == [(session, location, receipt_sha256)]:
                return
            raise ServiceRefusal("Another kept backup already names this folder; nothing was changed", code="backup-row-conflict")
        reserved = [row for _ref, row in registry if row["retention_kind"] == "destination" and row["session_id"] == session
                    and within(path, Path(row["protection_root"])) and path != Path(row["protection_root"])]
        if external and not reserved:
            raise ServiceRefusal("The chosen backup destination was not protected before the backup")
        if reserved:
            root, recorded = reserved[0]["protection_root"], reserved[0]["volume_identity"]
            if external and volume_identity not in {None, recorded}:
                raise ServiceRefusal("This backup is not on the drive that was reserved for it; nothing was changed", code="backup-row-conflict")
            volume_identity, opened = volume_identity or recorded, scoped_fs.admit_destination(location, non_private_destination=True)
        else:
            root, opened = str(self._owned(location, existing=True)), ScopedRoot(location, quiet_workspace=True)
        artifacts = {}
        with opened as folder:
            left_out = []
            for entry in folder.list_directory("", excluded=left_out):
                if entry["kind"] == "file":
                    record = folder.inspect(entry["relative_path"], hash_file=True, **({} if reserved else {"max_bytes": MAX_STREAM_BYTES}))
                    artifacts[str(path / entry["relative_path"])] = record["sha256"]
        if left_out or not artifacts:
            raise ServiceRefusal("A verified backup folder holds only its own ordinary files")
        replaced = [ref["name"] for ref, row in registry if row["session_id"] == session and "quarantine_binding" not in row
                    and (row["retention_kind"] == "reservation" and all(within(Path(item), path) for item in row["artifacts"])
                         or row["retention_kind"] == "destination" and row["protection_root"] == root)]
        self._write_rows([self._row(session, "backup", location=location, protection_root=root, artifacts=artifacts,
                                    reason="Verified backup folder; no automatic release", bytes_=size_bytes,
                                    receipt_sha256=receipt_sha256, volume_identity=volume_identity)], drop=replaced, registry=registry)

    def record_originals_removed(self, location, *, removed_utc, file_count):
        """Mark the kept backup folder ``location`` as the only copy of ``file_count`` files whose originals were removed at
        ``removed_utc``; a later release plan says so. Takes the service lock (use _record_originals_removed inside an
        operation)."""
        with self._lock():
            return self._record_originals_removed(location, removed_utc=removed_utc, file_count=file_count)

    def _record_originals_removed(self, location, *, removed_utc, file_count):
        pc_records.parse_utc(removed_utc)
        if type(file_count) is not int or file_count < 1:
            raise ServiceRefusal("The number of removed originals is required")
        registry = self._registry()
        rows = [(ref, row) for ref, row in registry if row["retention_kind"] == "backup" and row["location"] == location]
        if len(rows) != 1:
            raise ServiceRefusal("Exactly one kept backup folder must match")
        ref, row = rows[0]
        changed = {**copy.deepcopy(row), "originals_removed": {"removed_utc": removed_utc, "file_count": file_count}}
        self._write_rows([changed], drop=[ref["name"]], registry=registry)

    def retention_rows(self):
        """Every kept row for the read-only listing: name, kind, session, location, bytes, creation time, volume identity
        and removed originals (no file lists)."""
        return [{"name": ref["name"], "kind": row["retention_kind"], "session_id": row["session_id"], "location": row["location"],
                 "bytes": row["bytes"], "created_utc": row["created_utc"], "volume_identity": row["volume_identity"],
                 "originals_removed": row["originals_removed"]} for ref, row in self._registry()]

    def register_recovery(self, session_id, *, output_root, backup_receipt, restore_receipt):
        with self._lock():
            return self._register_recovery(session_id, output_root, backup_receipt, restore_receipt)

    def _quarantine_recovery(self, state, payload):
        plan, output = payload["storage_plan"], Path(payload["output_root"])
        receipt = plan["receipt"]
        attempt = output / receipt["attempt"]
        artifacts = {str(attempt): digest(read_record_bytes(attempt)),
                     str(output / ("outcome-quarantine-" + receipt["plan_sha256"] + ".json")): digest(receipt)}
        for row in receipt["records"]:
            artifacts[str(output / row["quarantine_record"]["relative_path"])] = row["quarantine_record"]["sha256"]
        retention = {"schema": RECOVERY_RETENTION, "schema_version": pc_records.SCHEMA_VERSION, "session_id": state["session_id"],
                     "required": True, "artifacts": artifacts}
        retention_row = self._register(state, kind="retention", value=retention)
        binding = {"schema": QUARANTINE_RECOVERY, "schema_version": pc_records.SCHEMA_VERSION, "output_root": str(output),
                   "quarantine_receipt": receipt, "restore_plan": plan, "restore_plan_sha256": digest(plan),
                   "retention_evidence_id": retention_row["evidence_id"]}
        row = self._register(state, kind="recovery", value=binding)
        self._retain(state["session_id"], artifacts,
                     reason="Exact original quarantine mapping, native bytes and immutable receipts retained for reviewed no-overwrite restoration")
        return row

    def _register_recovery(self, session_id, output_root, backup, restore, *, completing=False):
        state = self._state(session_id, collecting=not completing)
        output = self._owned(str(output_root), state=state, existing=True)
        storage = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=self.protected_roots())
        manifest = storage.verify_backup(receipt=backup)["manifest"]
        storage.verified_recovery(backup=backup, restoration=restore)
        for receipt in (backup, restore):
            origin = service_record(decoded(private_read(self.work / ("origin-" + receipt["plan_sha256"] + ".json"))), "native_origin")
            if origin.get("engine_id") != state["engine_id"] or origin.get("mode") != state["mode"] or origin.get("platform") != state["platform"]:
                raise ServiceRefusal("Recovery has no matching gated native fixture/real origin")
        if (backup.get("required_recovery") is not True
                or sorted(row["path"] for row in manifest["source_roots"]) != sorted(state["settings"]["scope"]["roots"])):
            raise ServiceRefusal("Recovery must cover this exact selected scope and remain required")
        if state["mode"] == "fixture" and any(not within(Path(row["path"]), self.root / "work") for row in manifest["source_roots"]):
            raise ServiceRefusal("Fixture recovery cannot import real source scope")
        artifacts = {backup["archive"]: backup["archive_sha256"], backup["manifest"]: backup["manifest_sha256"],
                     str(output / ("outcome-restore-" + restore["plan_sha256"] + ".json")): digest(restore)}
        for file in manifest["files"]:
            artifacts[str(Path(restore["destination"]) / file["root_id"] / file["relative_path"])] = file["sha256"]
        self._retain(session_id, artifacts, reason="Exact verified required archive, manifest and restoration probe; no automatic release",
                     receipt_sha256=digest(backup), backup_files=(backup["archive"], backup["manifest"]))
        if state["status"] == "stopped":
            return {"registration": "preserved_in_service_retention_after_stop", "artifacts": artifacts,
                    "limitation": "Stopped session accepts only the active operation outcome; no new recovery authority was created."}
        retention = {"schema": RECOVERY_RETENTION, "schema_version": pc_records.SCHEMA_VERSION, "session_id": session_id,
                     "required": True, "artifacts": artifacts}
        retention_row = self._register(state, kind="retention", value=retention)
        binding = {"schema": RECOVERY_BINDING, "schema_version": pc_records.SCHEMA_VERSION, "output_root": str(output),
                   "backup_receipt": backup, "restore_receipt": restore, "retention_evidence_id": retention_row["evidence_id"]}
        row = self._register(state, kind="recovery", value=binding)
        self.engine.verify_recovery(self.engine.read_session(session_id), [row["evidence_id"]])
        return row

    # Release, session release and forget: the plan, the checks repeated before begin and in the effect, the effects
    # and the reconciliation.
    def retention_plan(self, adapter_id, *, names=None, session_id=None):
        """The storage plan of a retention release or forget of the kept rows ``names`` (registry names), or of a session
        release of every kept row of the finished session ``session_id``. Pass it to prepare_storage_action with this
        service's work folder as the output root. A release plan lists one row per kept item with the bytes it frees, and
        says when a backup is the only copy of files whose originals were removed."""
        if adapter_id not in {RELEASE, SESSION_RELEASE, FORGET} or (adapter_id == SESSION_RELEASE) != (session_id is not None) \
                or (names is None) == (session_id is None):
            raise ServiceRefusal("Name the kept items to delete or forget, or a finished job whose kept items should be deleted.")
        registry = self._registry()
        if session_id is not None:
            record_identifier(session_id)
            self._finished_session(session_id)
            chosen = [(ref, row) for ref, row in registry if row["session_id"] == session_id]
        else:
            by_name = {ref["name"]: (ref, row) for ref, row in registry}
            if not isinstance(names, list) or len(set(names)) != len(names) or any(not isinstance(name, str) or name not in by_name for name in names):
                raise ServiceRefusal("Name each kept item once, exactly as the list of kept items shows it.")
            chosen = [by_name[name] for name in names]
        if not chosen:
            raise ServiceRefusal("There are no kept items to change.")
        plan = {"schema": storage_contract.PLAN, "schema_version": pc_records.SCHEMA_VERSION, "kind": storage_contract.PLAN_KINDS[adapter_id],
                "created_utc": pc_records.utc_now(), "session_id": session_id,
                "records": {"entries": [{"name": ref["name"], "sha256": ref["sha256"]} for ref, _row in chosen]}}
        if adapter_id == FORGET:
            self._forget_ready(chosen)
            plan["explanation"] = "Forget the records of kept items that are already gone. Nothing is deleted."
            return plan
        plan["rows"] = self._release_rows(registry, chosen)
        plan["notes"] = _only_copy_notes(chosen)
        plan["explanation"] = "Permanently delete the files of these kept backups and recovery records. This cannot be undone."
        return plan

    def _release_rows(self, registry, chosen):
        """One plan row per chosen kept row with the bytes its release frees now: its present files that no remaining
        row lists, each counted once. A present file without a recorded SHA-256, or one that is not an ordinary file,
        refuses the plan, because the release would have to keep it. A reservation must be settled, and frees nothing."""
        names = {ref["name"] for ref, _row in chosen}
        remaining = {_folded(path) for ref, row in registry if ref["name"] not in names for path in row["artifacts"]}
        hashes, counted, rows = _merged(chosen), set(), []
        for ref, row in chosen:
            self._require_volume(row, others=len(chosen) > 1)
            size = 0
            if row["retention_kind"] in RESERVED_KINDS:
                self._require_settled(row)
            for path in sorted(_merged([(ref, row)])):
                info = None if _folded(path) in remaining or _folded(path) in counted else _lstat(path)
                if info is None:
                    continue
                counted.add(_folded(path))
                if hashes[path] is None or not stat.S_ISREG(info.st_mode):
                    raise ServiceRefusal("PatchCairn cannot confirm that a file in this kept item is the one it saved, so it will not delete "
                                         "it. Nothing was changed.", code="kept-file-unverifiable")
                size += info.st_size
            removed = row["originals_removed"]
            rows.append({"name": ref["name"], "sha256": ref["sha256"], "kind": row["retention_kind"], "location": row["location"],
                         "size": size, "only_copy_files": removed["file_count"] if removed else None})
        return rows

    def _require_volume(self, row, *, others=False):
        """Hold while a kept row's drive is not connected. A row below the work folder is on this repository's own drive.
        Elsewhere the drive is connected only when the volume lookup of the nearest existing folder on the row's path
        gives the recorded volume identity; a row without one, or a failed lookup, holds. The refusal names the folder and,
        with ``others``, says that this one drive stopped a whole list."""
        path = Path(row["location"])
        if within(path, self.root / "work"):
            return
        try:
            ancestor = next((candidate for candidate in (path, *path.parents) if _present(candidate)), None)
            observed = self.volume_lookup(str(ancestor)) if ancestor is not None and row["volume_identity"] is not None else None
        except (OSError, pc_records.Refusal):
            observed = None
        if observed is None or observed != row["volume_identity"]:
            raise ServiceRefusal(DRIVE_NOT_CONNECTED.format(folder=_shown(row["location"])) + (LIST_STOPPED if others else ""), code="drive-not-connected")

    def _unidentified(self, chosen):
        """The names of the chosen rows whose recorded drive cannot be identified now. Nothing on such a drive counts as gone."""
        held = set()
        for ref, row in chosen:
            try:
                self._require_volume(row)
            except ServiceRefusal:
                held.add(ref["name"])
        return held

    def _forget_ready(self, chosen):
        for _ref, row in chosen:
            self._require_volume(row)
            if row["retention_kind"] in RESERVED_KINDS:
                self._require_settled(row)
            elif any(_present(path) for path in _targets(row)):
                raise ServiceRefusal("A kept file or folder still exists. Forgetting a record is only for kept items that are already gone; "
                                     "to remove the files, ask me to delete this kept item. Nothing was changed.", code="kept-item-exists")

    def _require_settled(self, row):
        """Refuse unless the reservation ``row`` is settled: no backup of its session is open or unknown, and the backup
        folders it covers hold no files. A reservation row names its folder; a destination row covers the folder each
        unfinished backup of that session recorded in its attempt record before making it (no attempt record, nothing
        written there). An empty folder is what a settled backup leaves, and it is not removed."""
        try:
            operations = self.engine.read_session(row["session_id"])["operations"]
        except WorkflowRefusal as error:
            raise ServiceRefusal("PatchCairn could not read the job this kept item belongs to. Nothing was changed.") from error
        backups = [operation for operation in operations.values() if operation["adapter_id"] == pc_records.ADAPTER_STORAGE_BACKUP_CREATE]
        if any(operation["outcome"] in {None, "unknown"} for operation in backups):
            raise ServiceRefusal("The backup this was reserved for has not finished. Say PatchCairn: status in that job first. Nothing was changed.",
                                 code="kept-row-needed")
        folders = list(row["artifacts"])
        for operation in backups if row["retention_kind"] == "destination" else ():
            intent = self.work / "operations" / row["session_id"] / operation["operation_id"] / "intent.json"
            payload = service_record(decoded(private_read(intent)), "operation_intent")["payload"] if _present(intent) else {}
            attempt = (Path(payload["output_root"]) / ("attempt-backup-" + payload["storage_plan_sha256"] + ".json")
                       if operation["outcome"] != "succeeded" and payload.get("backup_destination") == row["location"] else None)
            if attempt is not None and _present(attempt):
                name = decoded(private_read(attempt)).get("folder")
                if not isinstance(name, str) or Path(name).name != name:
                    raise ServiceRefusal("A backup's attempt record could not be read; nothing was changed")
                folders.append(str(Path(row["location"]) / name))
        occupied = next((folder for folder in folders if _holds_files(folder)), None)
        if occupied is not None:
            raise ServiceRefusal(f"The folder of an unfinished backup still holds files: {_shown(occupied)}. They stay protected until you have "
                                 "looked at them and removed them yourself. Nothing was changed.", code="kept-item-exists")

    def _finished_session(self, session_id):
        try:
            state = self.engine.read_session(session_id)
        except WorkflowRefusal as error:
            raise ServiceRefusal("PatchCairn could not read that job's records, so its kept files stay. Nothing was changed.") from error
        if state["status"] not in {"stopped", "completed"}:
            raise ServiceRefusal("That job is still open, so its kept files stay. Finish it, or say PatchCairn: stop in that job, then try again. "
                                 "Nothing was changed.")
        for operation in state["operations"].values():
            if (operation["outcome"] in {None, "unknown"} or operation["outcome"] in {"failed", "partial"} and not operation["resolution"]
                    or restart_state(operation) == "waiting"):
                raise ServiceRefusal("That job still has a step with no confirmed result, or one waiting for a restart. Clear that first: "
                                     "PatchCairn: status in that job shows how. Its kept files stay until then.", code="session-not-settled")

    def _retention_checks(self, state, payload):
        """The checks of a retention action, before begin and again inside the effect: the planned rows are exactly the
        current ones, not needed by a remaining row and on a connected drive; a release's rows and notes are, one to one
        and in order, what those registry entries give now (name, SHA-256, kind, location and bytes), so the typed reply's
        number and size, which are read from those rows, are what the execution deletes; a session release names another
        finished, settled session and every one of its rows; a forget's items are all gone. Returns (registry, chosen rows)."""
        plan, adapter_id = payload["storage_plan"], payload["operation"]
        entries = plan.get("records", {}).get("entries") if isinstance(plan.get("records"), dict) else None
        registry = self._registry()
        by_name = {ref["name"]: (ref, row) for ref, row in registry}
        if not isinstance(entries, list) or not entries or any(not isinstance(entry, dict) or by_name.get(entry.get("name"), ({},))[0] != entry
                                                                for entry in entries) or len({entry["name"] for entry in entries}) != len(entries):
            raise ServiceRefusal(KEPT_LIST_CHANGED, code="kept-rows-changed")
        chosen = [by_name[entry["name"]] for entry in entries]
        if adapter_id == SESSION_RELEASE:
            target = plan.get("session_id")
            record_identifier(target)
            current = sorted(ref["name"] for ref, row in registry if row["session_id"] == target)
            if target == state["session_id"] or sorted(entry["name"] for entry in entries) != current:
                raise ServiceRefusal("A job's kept files are deleted together, from another job, after that job has ended. Nothing was deleted. "
                                     "I make a new list for you to check.", code="kept-rows-changed")
            self._finished_session(target)
        elif plan.get("session_id") is not None:
            raise ServiceRefusal("This list names a whole job, but it is not a deletion of that job's kept files. Nothing was deleted.")
        if adapter_id == FORGET:
            self._forget_ready(chosen)
            return registry, chosen
        names = {entry["name"] for entry in entries}
        if any(names & set(row["depends_on"]) for ref, row in registry if ref["name"] not in names):
            raise ServiceRefusal("Another job still relies on this backup. Finish or delete that first. Nothing was deleted.", code="kept-row-needed")
        if plan.get("rows") != self._release_rows(registry, chosen) or plan.get("notes") != _only_copy_notes(chosen):
            raise ServiceRefusal(KEPT_LIST_CHANGED, code="kept-rows-changed")
        return registry, chosen

    def _drop_gone(self, chosen, gone, held):
        """Remove from the registry each chosen row whose files are all gone (or still kept by a remaining row) and each
        reservation, unless ``held`` names it (its drive cannot be identified); returns the names removed."""
        registry = self._registry()
        current = {ref["name"] for ref, _row in registry}
        names = [ref["name"] for ref, row in chosen if ref["name"] in current and ref["name"] not in held
                 and (row["retention_kind"] in RESERVED_KINDS or all(_folded(path) in gone for path in row["artifacts"]))]
        if names:
            self._write_rows([], drop=names, registry=registry)
        return names

    def _release(self, session_id, state, operation, payload, path):
        """Delete the chosen rows' files through release_set (the attempt record with the exact paths first), then drop
        the rows whose files are gone; rows with kept files stay, and so does a row whose drive left during the release."""
        try:
            registry, chosen = self._retention_checks(state, payload)
        except ServiceRefusal as error:
            return self._finish(self.engine.read_session(session_id), operation, outcome="failed",
                                receipt={"changed": False, "reason": error.code})
        names = {ref["name"] for ref, _row in chosen}
        remaining = [row for ref, row in registry if ref["name"] not in names]

        def attempt(delete, absent, kept):
            self._immutable(path / "release-attempt.json", service_value(
                "release_attempt", operation_id=operation["operation_id"], observed_utc=pc_records.utc_now(), rows=sorted(names),
                delete=delete, absent=absent, kept=kept))
        result = release_set(_merged(chosen), keep=[item for row in remaining for item in row["artifacts"]],
                             never=[str(self.engine.work), str(self.work)], attempt=attempt,
                             destinations=list(self._chosen_roots(row for _ref, row in chosen)))
        held = self._unidentified(chosen)
        unseen = {_folded(item) for ref, row in chosen if ref["name"] in held for item in row["artifacts"]}
        result["kept"] += [{"path": item, "reason": "drive-not-connected"} for item in result["absent"] if _folded(item) in unseen]
        result["absent"] = [item for item in result["absent"] if _folded(item) not in unseen]
        gone = {_folded(item) for item in result["removed"] + result["absent"]}
        gone |= {_folded(row["path"]) for row in result["kept"] if row["reason"] == "still-listed"}
        released = self._drop_gone(chosen, gone, held)
        return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded" if len(released) == len(chosen) else "partial",
                            receipt={**result, "released_rows": sorted(released), "kept_rows": sorted(names - set(released))})

    def _forget(self, session_id, state, operation, payload):
        try:
            registry, chosen = self._retention_checks(state, payload)
        except ServiceRefusal as error:
            return self._finish(self.engine.read_session(session_id), operation, outcome="failed",
                                receipt={"changed": False, "reason": error.code})
        self._write_rows([], drop=[ref["name"] for ref, _row in chosen], registry=registry)
        return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded",
                            receipt={"forgotten_rows": sorted(ref["name"] for ref, _row in chosen), "deleted": []})

    def _reconcile_retention(self, session_id, operation, intent, payload, *, operation_id):
        """Reconcile a release, session release or forget after an interruption, with the service lock held: classify
        each planned file as removed (listed for deletion in the attempt record and now gone), absent (already gone at the
        attempt) or kept, drop the planned rows whose files are all gone (a forget's rows only while their drive is
        connected and every item is gone), and record what was observed. Nothing is deleted here. While a planned row's
        drive cannot be identified after an attempt, a missing file proves nothing: nothing is classified or dropped, the
        rows stay protected and the operation stays unknown until that drive is back."""
        self._refuse_while_elevated(payload["operation"])
        if operation["outcome"] not in {None, "unknown"}:
            raise ServiceRefusal("Known operation receipt is already consumed; retain historical result")
        state = self.engine.read_session(session_id)
        self._original_authority(state, operation, intent)
        entries = payload["storage_plan"]["records"]["entries"]
        planned = {entry["name"] for entry in entries}
        registry = self._registry()
        chosen = [(ref, row) for ref, row in registry if ref["name"] in planned]
        if payload["operation"] == FORGET:
            ready = []
            for ref, row in chosen:
                try:
                    self._forget_ready([(ref, row)])
                except ServiceRefusal:
                    continue
                ready.append(ref["name"])
            if ready:
                self._write_rows([], drop=ready, registry=registry)
            left = planned - {ref["name"] for ref, _row in chosen} | set(ready)
            receipt = {"forgotten_rows": sorted(left), "kept_rows": sorted(planned - left), "deleted": [], **ACCOUNTED}
        else:
            attempt_path = self._operation_dir(session_id, operation_id) / "release-attempt.json"
            recorded = _present(attempt_path)
            attempt = (service_record(decoded(private_read(attempt_path)), "release_attempt") if recorded
                       else {"delete": [], "absent": [], "kept": []})
            held = self._unidentified(chosen) if recorded else set()
            if held:
                observed = {"possible_partial_effects": True, "reason": "drive-not-connected", "held_rows": sorted(held),
                            "instruction": "Connect the drive that holds these kept items, then ask PatchCairn to check again."}
                if operation["outcome"] is None:
                    return self._finish(state, operation, outcome="unknown", receipt=observed)
                return {"operation_id": operation_id, "outcome": "unknown", "held": True, "automatic_retry": False, "observed": observed}
            removed = [item for item in attempt["delete"] if not _present(item)]
            # A file the attempt found absent counts only while it is still absent: its drive may have come back since.
            returned = [item for item in attempt["absent"] if _present(item)]
            absent = [item for item in attempt["absent"] if item not in returned]
            kept = [item for item in attempt["delete"] if item not in removed] + [row["path"] for row in attempt["kept"]] + returned
            names = {ref["name"] for ref, _row in chosen}
            listed = {_folded(item) for ref, row in registry if ref["name"] not in planned for item in row["artifacts"]}
            gone = {_folded(item) for item in removed + absent} | {_folded(item) for item in kept if _folded(item) in listed}
            released = self._drop_gone(chosen, gone, held) if recorded else []
            left = planned - names | set(released)
            receipt = {"removed": removed, "absent": absent, "kept": kept, "released_rows": sorted(left),
                       "kept_rows": sorted(planned - left), "attempt_recorded": recorded, **ACCOUNTED}
        outcome = "succeeded" if not receipt["kept_rows"] else "partial" if receipt.get("removed") or len(receipt["kept_rows"]) < len(planned) else "failed"
        return self._finish(state, operation, outcome=outcome, receipt=receipt,
                            kind="reconciliation" if operation["outcome"] == "unknown" else "outcome")

    # Dispatch targets (service_execute.EXECUTE, service_reconcile.RECONCILE; reached only through execute_action and
    # reconcile_operation): each runs its checks, then the shared begin and effect steps of service_execute.
    def _execute_storage_retention_release(self, session_id, state, action, payload, **arguments):
        self._storage_preconditions(state, action, payload, diagnostic_fixture_runner=arguments.pop("diagnostic_fixture_runner"),
                                    diagnostic_fixture_result=arguments.pop("diagnostic_fixture_result"))
        return self._run_adapter(session_id, state, action, payload, self._effect_storage_retention_release, **arguments)

    def _execute_storage_retention_forget(self, session_id, state, action, payload, **arguments):
        self._storage_preconditions(state, action, payload, diagnostic_fixture_runner=arguments.pop("diagnostic_fixture_runner"),
                                    diagnostic_fixture_result=arguments.pop("diagnostic_fixture_result"))
        return self._run_adapter(session_id, state, action, payload, self._effect_storage_retention_forget, **arguments)

    def _execute_storage_session_release(self, session_id, state, action, payload, **arguments):
        self._storage_preconditions(state, action, payload, diagnostic_fixture_runner=arguments.pop("diagnostic_fixture_runner"),
                                    diagnostic_fixture_result=arguments.pop("diagnostic_fixture_result"))
        return self._run_adapter(session_id, state, action, payload, self._effect_storage_session_release, **arguments)

    def _effect_storage_retention_release(self, session_id, state, operation, action, payload, path, intent):
        return self._release(session_id, state, operation, payload, path)

    def _effect_storage_session_release(self, session_id, state, operation, action, payload, path, intent):
        return self._release(session_id, state, operation, payload, path)

    def _effect_storage_retention_forget(self, session_id, state, operation, action, payload, path, intent):
        return self._forget(session_id, state, operation, payload)

    def _reconcile_storage_retention_release(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_retention(session_id, operation, intent, payload, **arguments)

    def _reconcile_storage_retention_forget(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_retention(session_id, operation, intent, payload, **arguments)

    def _reconcile_storage_session_release(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_retention(session_id, operation, intent, payload, **arguments)
