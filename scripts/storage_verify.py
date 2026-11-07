"""Backup, required-recovery and outcome verification, mixed into storage_ops.StorageService (see its trust model).

verify_archive is the one verification of a backup archive, for all three moments: after the archive is written and
before it gets its final name, before a restore (after its SHA-256 matched the receipt), and before originals are
removed (read back uncached where the platform allows it)."""
from __future__ import annotations

import hashlib
import io
import re
import stat
import struct
import zipfile
import zlib
from contextlib import ExitStack
from pathlib import Path

import pc_paths
import pc_records
import scoped_base
import scoped_fs
from storage_policy import (CONTROL_RECORD_MAX_BYTES, HASH_RE, MAX_FILE_BYTES, StorageRefusal, bound_plan, canonical,
                            checked_record, checked_relative, decode_storage, sha256, storage_value)

READ_BACK_NOTE = ("Every entry was read back from the disk through the file system and checked (CRC-32 and SHA-256) before "
                  "the archive got its final name. The system may answer a read of recently written data from its memory, so "
                  "this does not test the drive itself.")
# DEFLATE cannot pack more than about 1032 bytes into one; a higher ratio means a crafted archive.
MAX_COMPRESSION_RATIO = 1100
MAX_LINE_BYTES = 1 << 20
ROOT_ID = re.compile(r"r[0-9]{3}\Z")
FOLDER = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-z0-9-]{1,32}\Z")
_LOCAL = struct.Struct("<4sHHHHHIIIHH")
_MANIFEST_FIELDS = frozenset({"crc32", "read_only", "dacl_protected", "changed", "archived", "archived_size", "archived_sha256"})


def _broken(message="ZIP structure, CRC or bounded content verification failed"):
    return StorageRefusal(message, code="archive-verification-failed")


def entry_name(row):
    """The ZIP name of a manifest row, "<root id>/<relative path>", after checking that it is exactly that: the relative
    path in pc_paths' one grammar (no "..", drive letter, absolute path, backslash, stream or reserved name) and not a
    protected name."""
    if not isinstance(row, dict) or not isinstance(row.get("root_id"), str) or not ROOT_ID.fullmatch(row["root_id"]):
        raise _broken("Invalid backup entry")
    relative = checked_relative(row.get("relative_path"))
    if pc_paths.protected(relative):
        raise _broken("Protected or invalid restore target")
    name = row["root_id"] + "/" + relative
    if row.get("entry") != name:
        raise _broken("A ZIP entry name differs from the manifest's validated path")
    return name


def _expected(row):
    """(size, SHA-256) the archive member of ``row`` holds: the reviewed file's, or what was read of a changed one."""
    size, digest = (row.get("archived_size"), row.get("archived_sha256")) if row.get("changed") else (row.get("size"), row.get("sha256"))
    if type(size) is not int or not 0 <= size <= scoped_base.MAX_STREAM_BYTES or not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
        raise _broken("Invalid bounded archive member")
    return size, digest


def _local_header(reader, info, start):
    """Check the local header of ``info`` against its central directory entry; return where its data ends."""
    if info.header_offset != start:
        raise _broken("ZIP members overlap, leave gaps or are out of order")
    reader.seek(info.header_offset)
    raw = reader.read(_LOCAL.size)
    if len(raw) != _LOCAL.size:
        raise _broken()
    signature, _version, flags, method, _time, _date, crc, compressed, size, name_length, extra_length = _LOCAL.unpack(raw)
    name, extra = reader.read(name_length), reader.read(extra_length)
    if (signature != b"PK\x03\x04" or flags != info.flag_bits or method != info.compress_type or crc != info.CRC
            or name != info.filename.encode("utf-8") or len(extra) != extra_length):
        raise _broken("A ZIP local header differs from the central directory")
    if (compressed, size) == (0xFFFFFFFF, 0xFFFFFFFF):
        sizes = None
        while len(extra) >= 4 and sizes is None:
            tag, length = struct.unpack("<HH", extra[:4])
            sizes = struct.unpack("<QQ", extra[4:20]) if tag == 1 and length >= 16 else None
            extra = extra[4 + length:]
        compressed, size = (sizes[1], sizes[0]) if sizes else (None, None)
    if (size, compressed) != (info.file_size, info.compress_size):
        raise _broken("A ZIP local header differs from the central directory")
    return info.header_offset + _LOCAL.size + name_length + extra_length + info.compress_size


def verify_archive(handle, rows):
    """The one verification of a backup archive. ``handle`` is the archive opened for reading (seekable, positioned
    anywhere) and ``rows`` the manifest's entry rows in order. Checks the structure (one member per archived row, in
    order, each local header equal to its central directory entry, members back to back from offset 0 up to the
    central directory, no encryption, data descriptor or compression ratio above MAX_COMPRESSION_RATIO), that every
    name is exactly the manifest's validated path with no case duplicate, and streams every member back in CHUNK_BYTES
    pieces, checking its CRC-32 (zipfile) and SHA-256. Returns the number of members; raises StorageRefusal."""
    if not isinstance(rows, list) or len(rows) > pc_records.MAX_BACKUP_ENTRIES:
        raise _broken("Invalid manifest entry list")
    names = [entry_name(row) for row in rows]
    if len({pc_paths.casefold_key(name) for name in names}) != len(names):
        raise _broken("Case-ambiguous or duplicate restore destinations")
    members = [row for row in rows if not row.get("changed") or row.get("archived") is True]
    reader = io.BufferedReader(handle, buffer_size=scoped_base.CHUNK_BYTES)
    try:
        reader.seek(0)
        archive = zipfile.ZipFile(reader)
        infos = archive.infolist()
        if len(infos) != len(members) or [info.filename for info in infos] != [row["entry"] for row in members]:
            raise _broken("ZIP entries differ from the exact reviewed list")
        end = 0
        for info, row in zip(infos, members):
            size, digest = _expected(row)
            if (info.is_dir() or info.flag_bits & 0x9 or not info.flag_bits & 0x800 or info.compress_type != zipfile.ZIP_DEFLATED
                    or not stat.S_ISREG(info.external_attr >> 16) or info.file_size != size
                    or info.file_size > MAX_COMPRESSION_RATIO * max(info.compress_size, 1)):
                raise _broken("Unsupported, encrypted, oversized or nonordinary ZIP member")
            end = _local_header(reader, info, end)
            hashed, count = hashlib.sha256(), 0
            with archive.open(info) as stream:
                while chunk := stream.read(scoped_base.CHUNK_BYTES):
                    count += len(chunk)
                    if count > size:
                        raise _broken("ZIP member content/hash mismatch")
                    hashed.update(chunk)
            if count != size or hashed.hexdigest() != digest:
                raise _broken("ZIP member content/hash mismatch")
        if end != archive.start_dir:
            raise _broken("ZIP data overlaps or is apart from the central directory")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, EOFError, NotImplementedError, struct.error, zlib.error,
            UnicodeError, OverflowError) as exc:
        raise _broken() from exc
    finally:
        reader.detach()
    return len(members)


class ManifestLines:
    """A stream_to writer that splits manifest.json into strictly decoded lines: the header (a backup_manifest record),
    then one row per entry, then one {"skipped": row} per left-out entry."""

    def __init__(self):
        self.pending, self.header, self.entries, self.skipped = b"", None, [], []

    def __call__(self, data):
        lines = (self.pending + data).split(b"\n")
        self.pending = lines.pop()
        if len(self.pending) > MAX_LINE_BYTES:
            raise StorageRefusal("A manifest line exceeds its bound")
        for line in lines:
            value = decode_storage(line, "Invalid bounded backup manifest line")
            if self.header is None:
                self.header = checked_record(value, "backup_manifest", "Foreign backup manifest")
            elif isinstance(value, dict) and set(value) == {"skipped"} and isinstance(value["skipped"], dict):
                self.skipped.append(value["skipped"])
            elif isinstance(value, dict) and "entry" in value and not self.skipped and len(self.entries) < pc_records.MAX_BACKUP_ENTRIES:
                self.entries.append(value)
            else:
                raise StorageRefusal("Invalid backup manifest line")
        return len(data)

    def manifest(self):
        if self.pending or self.header is None or self.header.get("format") != "json-lines":
            raise StorageRefusal("Invalid or incomplete backup manifest")
        header = self.header
        if (header.get("entry_count") != len(self.entries) or header.get("skipped_count") != len(self.skipped)
                or header.get("changed_count") != sum(row.get("changed") is True for row in self.entries)):
            raise StorageRefusal("The backup manifest's counts differ from its lines")
        return {**header, "entries": self.entries, "files": [row for row in self.entries if not row.get("changed")],
                "changed": [row for row in self.entries if row.get("changed")], "skipped": self.skipped}


def plan_row(row):
    """A manifest entry without the fields the manifest adds: the reviewed plan's row."""
    return {key: value for key, value in row.items() if key not in _MANIFEST_FIELDS}


class StorageVerification:
    """StorageService's backup, recovery and outcome verification."""

    def _receipt_folder(self, stack, receipt):
        """The backup folder a receipt names, as (destination root, folder name): the paths must be exactly the
        receipt's folder below its destination; an external destination is admitted with its hash-bound plan's
        acknowledgment (the plan file in the output root)."""
        folder, destination = receipt.get("folder"), receipt.get("destination")
        if (not isinstance(folder, str) or not FOLDER.fullmatch(folder) or not isinstance(destination, str)
                or receipt.get("archive") != str(Path(destination) / folder / "backup.zip")
                or receipt.get("manifest") != str(Path(destination) / folder / "manifest.json")
                or type(receipt.get("external")) is not bool):
            raise StorageRefusal("An exact backup receipt is required")
        plan = {"destination": destination, "external": receipt["external"]}
        if receipt["external"] and self.backup_destination is None:
            with scoped_fs.open_root(str(self.output_root)) as output:
                plan = self._read_record(output, f"plan-backup-{receipt['plan_sha256']}.json", "backup",
                                         "The backup's reviewed plan is missing or changed", expected_sha256=receipt["plan_sha256"])
            if plan["destination"] != destination or plan["external"] is not True:
                raise StorageRefusal("Backup receipt binding changed")
        return self._backup_destination_root(stack, plan), folder

    def verify_backup(self, *, receipt, archive_data=True, uncached=False):
        """The receipt's backup read back from disk: the manifest (its SHA-256 the receipt's), the archive's SHA-256 (the
        receipt's), then verify_archive against the manifest. ``uncached`` asks the backend to bypass its cache (before
        originals are removed). Returns {"manifest": header plus "entries" (all rows, in order), "files" (the rows of
        unchanged files), "changed" and "skipped"; "verified": True} and, with ``archive_data``, "archive_data": the
        archive's bytes for the in-memory restore, which holds an archive above scoped_base.MAX_CONTROL_BYTES."""
        checked_record(receipt, "backup_receipt", "An exact backup receipt is required")
        with ExitStack() as stack:
            root, folder = self._receipt_folder(stack, receipt)
            lines = ManifestLines()
            root.stream_to(folder + "/manifest.json", expected={**receipt["manifest_record"], "sha256": receipt["manifest_sha256"]},
                           writer=lines)
            manifest = lines.manifest()
            if manifest["plan_sha256"] != receipt["plan_sha256"] or manifest["required_recovery"] != receipt["required_recovery"]:
                raise StorageRefusal("Backup receipt binding changed")
            expected = {**receipt["archive_record"], "sha256": receipt["archive_sha256"]}
            with root.open_read(folder + "/backup.zip", expected=expected, uncached=uncached) as handle:
                if scoped_base.hash_stream(handle, expected["size"]) != receipt["archive_sha256"]:
                    raise StorageRefusal("Stored backup or manifest changed")
                verify_archive(handle, manifest["entries"])
            result = {"manifest": manifest, "verified": True}
            if archive_data:
                if expected["size"] > scoped_base.MAX_CONTROL_BYTES:
                    raise StorageRefusal("Restoring an archive this large is not available yet; the backup itself is verified",
                                         code="restore-size-unavailable")
                result["archive_data"] = root.read_bytes(folder + "/backup.zip", expected=expected, max_bytes=scoped_base.MAX_CONTROL_BYTES)
        return result

    def verified_recovery(self, *, backup, restoration, uncached=False):
        """The backup and its restoration probe, read back from disk; ``uncached`` as in verify_backup. Returns the manifest."""
        manifest = self.verify_backup(receipt=backup, archive_data=False, uncached=uncached)["manifest"]
        required = "Required recovery needs a completed exact restoration probe and its immutable outcome"
        checked_record(restoration, "restore_receipt", required)
        if (restoration.get("verified") is not True
                or restoration.get("backup_plan_sha256") != backup["plan_sha256"]
                or restoration.get("backup_archive_sha256") != backup["archive_sha256"]
                or restoration.get("backup_manifest_sha256") != backup["manifest_sha256"]
                or not isinstance(restoration.get("plan_sha256"), str)
                or not HASH_RE.fullmatch(restoration["plan_sha256"])
                or restoration.get("files") != manifest["files"]
                or len(restoration.get("records", [])) != len(manifest["files"])):
            raise StorageRefusal(required)
        destination = self._output_relative(restoration["destination"])
        if self._outcome_bytes("outcome-restore-" + restoration["plan_sha256"] + ".json")[0] != canonical(restoration):
            raise StorageRefusal("Restoration outcome artifact differs from the exact recovery record")
        with self._scope(self.output_root) as output:
            for row, record in zip(manifest["files"], restoration["records"]):
                expected_path = destination + "/" + row["root_id"] + "/" + row["relative_path"]
                if record["relative_path"] != expected_path or record["sha256"] != row["sha256"]:
                    raise StorageRefusal("Recovery probe does not map the exact backed-up contents")
                self._private_created_file(expected_path)
                data = output.read_bytes(expected_path, expected=record, max_bytes=MAX_FILE_BYTES)
                if len(data) != row["size"] or sha256(data) != row["sha256"]:
                    raise StorageRefusal("Required restored recovery bytes changed")
        return manifest

    def verify_outcome(self, *, plan, expected_plan_sha256, receipt, recheck_content=True):
        """Read-only actual postconditions for a known immutable outcome.

        Missing/partial outcome evidence is a hold. This method does not retry,
        recreate a receipt or turn an unknown interrupted action into success.
        A backup's archive and manifest are read back and verified again unless
        ``recheck_content`` is False (right after create_backup verified them);
        then only their committed identity is checked.
        """
        operations = {"backup": ("backup", "backup_receipt"), "restore": ("restore", "restore_receipt"),
                      "quarantine": ("quarantine", "quarantine_receipt"),
                      "quarantine_restore": ("quarantine-restore", "quarantine_restore_receipt"),
                      "purge": ("purge", "purge_receipt")}
        kind = plan.get("kind")
        if kind not in operations:
            raise StorageRefusal("Unknown fixed storage outcome kind")
        bound_plan(plan, expected_plan_sha256, kind)
        operation, receipt_kind = operations[kind]
        checked_record(receipt, receipt_kind, "An exact bound immutable operation receipt is required")
        if receipt.get("plan_sha256") != expected_plan_sha256:
            raise StorageRefusal("An exact bound immutable operation receipt is required")
        outcome_name = f"outcome-{operation}-{expected_plan_sha256}.json"
        outcome_data, outcome_record = self._outcome_bytes(outcome_name)
        if outcome_data != canonical(receipt):
            raise StorageRefusal("Outcome receipt differs from the exact immutable artifact")
        if kind == "backup":
            self._backup_outcome(plan, receipt, recheck_content)
        else:
            self._legacy_outcome(kind, plan, receipt)
        return {**storage_value("storage_outcome_verification"), "observed_utc": pc_records.utc_now(),
                "storage_plan_sha256": expected_plan_sha256, "operation_kind": kind,
                "outcome": receipt.get("outcome", "succeeded"), "verification_passed": True, "mutation_performed": False,
                "receipt_sha256": sha256(outcome_data), "outcome_artifact_relative": outcome_name,
                "outcome_artifact_record": outcome_record}

    def _outcome_bytes(self, name):
        """(bytes, record) of a private outcome receipt in the output root, read through a pinned RootBase."""
        self._private_created_file(name)
        with scoped_fs.open_root(str(self.output_root)) as records:
            record = records.inspect(name, hash_file=True)
            if record["kind"] != "file" or record["size"] > CONTROL_RECORD_MAX_BYTES:
                raise StorageRefusal("Outcome receipt differs from the exact immutable artifact")
            chunks = []
            records.stream_to(name, expected=record, writer=chunks.append)
        return b"".join(chunks), record

    def _backup_outcome(self, plan, receipt, recheck_content):
        if receipt.get("destination") != plan["destination"] or receipt.get("external") is not plan["external"]:
            raise StorageRefusal("Backup outcome differs from the exact reviewed content/output")
        if recheck_content:
            rows = self.verify_backup(receipt=receipt, archive_data=False)["manifest"]["entries"]
            if [plan_row(row) for row in rows] != plan["files"]:
                raise StorageRefusal("Backup outcome differs from the exact reviewed content/output")
            return
        with ExitStack() as stack:
            root, folder = self._receipt_folder(stack, receipt)
            for name, record in (("backup.zip", receipt["archive_record"]), ("manifest.json", receipt["manifest_record"])):
                if not scoped_base.same_identity(root.inspect(folder + "/" + name), record, root.identity_keys):
                    raise StorageRefusal("Stored backup or manifest changed")

    def _legacy_outcome(self, kind, plan, receipt):
        """The outcome checks of the kinds that still use the in-memory scope (restore, quarantine, purge)."""
        with self._scope(self.output_root) as output:
            if kind == "restore":
                self.verified_recovery(backup=plan["receipt"], restoration=receipt)
                if receipt["destination"] != plan["destination"] or receipt["files"] != plan["files"]:
                    raise StorageRefusal("Restore outcome differs from the exact reviewed destination/content")
            elif kind == "quarantine":
                self._quarantine_current(receipt)
                if [row["original"] for row in receipt["records"]] != plan["files"]:
                    raise StorageRefusal("Quarantine outcome differs from the exact reviewed targets")
                with ExitStack() as stack:
                    sources = self._open_sources(stack, plan["inventory"]["roots"])
                    for row in plan["files"]:
                        self._require_absent(sources[row["root_id"]], row["relative_path"])
                if plan["recovery_required"]:
                    self.verified_recovery(backup=plan["recovery_backup"], restoration=plan["recovery_verification"])
            elif kind == "quarantine_restore":
                original_receipt = plan["receipt"]
                self._quarantine_provenance(original_receipt, output)
                if len(receipt["records"]) != len(original_receipt["records"]):
                    raise StorageRefusal("Restoration outcome target count changed")
                with ExitStack() as stack:
                    sources = self._open_sources(stack, original_receipt["source_roots"])
                    for original_row, observed in zip(original_receipt["records"], receipt["records"]):
                        original = original_row["original"]
                        if observed["relative_path"] != original["relative_path"] or observed["sha256"] != original["sha256"]:
                            raise StorageRefusal("Restored quarantine mapping/content differs from the original")
                        source_root = next(root["path"] for root in original_receipt["source_roots"] if root["root_id"] == original["root_id"])
                        self._private_windows_quarantine_file(Path(source_root) / original["relative_path"])
                        data = sources[original["root_id"]].read_bytes(original["relative_path"], expected=observed, max_bytes=MAX_FILE_BYTES)
                        if len(data) != original["size"] or sha256(data) != original["sha256"]:
                            raise StorageRefusal("Restored original bytes changed")
                        self._require_absent(output, original_row["quarantine_record"]["relative_path"])
            else:
                original_receipt = plan["receipt"]
                self._quarantine_provenance(original_receipt, output)
                expected_removed = [row["quarantine_record"]["relative_path"] for row in original_receipt["records"]]
                if receipt["removed"] != expected_removed:
                    raise StorageRefusal("Purge outcome differs from the exact reviewed target list")
                for relative in expected_removed:
                    self._require_absent(output, relative)
                if original_receipt["recovery_required"]:
                    self.verified_recovery(backup=original_receipt["recovery_backup"], restoration=original_receipt["recovery_verification"])
