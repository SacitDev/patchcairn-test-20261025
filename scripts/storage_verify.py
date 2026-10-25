"""Backup, required-recovery and outcome verification, mixed into storage_ops.StorageService (see its trust model)."""
from __future__ import annotations

import io
import re
import stat
import zipfile
from contextlib import ExitStack
from pathlib import Path

import pc_paths
import pc_records
from storage_policy import (HASH_RE, MAX_ARCHIVE_BYTES, MAX_ENTRIES, MAX_FILE_BYTES, StorageRefusal, bound_plan, canonical,
                            checked_limits, checked_record, checked_relative, decode_storage, sha256, storage_value)


class StorageVerification:
    """StorageService's backup, recovery and outcome verification."""

    @staticmethod
    def _verify_zip(data, manifest):
        checked_record(manifest, "backup_manifest", "Foreign backup manifest")
        if len(data) > MAX_ARCHIVE_BYTES or sha256(data) != manifest["archive_sha256"] or len(data) != manifest["archive_bytes"]:
            raise StorageRefusal("Archive byte/hash mismatch")
        rows = manifest["files"]
        if not rows or len(rows) > MAX_ENTRIES or len({row["entry"] for row in rows}) != len(rows):
            raise StorageRefusal("Invalid manifest entry list")
        if len({(row["root_id"], pc_paths.casefold_key(row["relative_path"])) for row in rows}) != len(rows):
            raise StorageRefusal("Case-ambiguous or duplicate restore destinations")
        limit = checked_limits(manifest["limits"])
        if sum(row["size"] for row in rows) > limit["max_total_bytes"]:
            raise StorageRefusal("Archive expanded byte cap exceeded")
        for row in rows:
            if not re.fullmatch(r"payload/[0-9]{6}", row["entry"]):
                raise StorageRefusal("Unsafe ZIP entry name")
            checked_relative(row["relative_path"])
            if pc_paths.protected(row["relative_path"]) or not re.fullmatch(r"r[0-9]{3}", row["root_id"]):
                raise StorageRefusal("Protected or invalid restore target")
            if type(row["size"]) is not int or not 0 <= row["size"] <= limit["max_file_bytes"] or not HASH_RE.fullmatch(row["sha256"]):
                raise StorageRefusal("Invalid bounded archive member")
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
                infos = archive.infolist()
                if len(infos) != len(rows) or [info.filename for info in infos] != [row["entry"] for row in rows]:
                    raise StorageRefusal("ZIP entries differ from the exact reviewed list")
                for info, row in zip(infos, rows):
                    if (info.is_dir() or info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                            or not stat.S_ISREG(info.external_attr >> 16) or info.file_size != row["size"]):
                        raise StorageRefusal("Unsupported, encrypted or nonordinary ZIP member")
                    with archive.open(info) as stream:
                        content = stream.read(limit["max_file_bytes"] + 1)
                    if len(content) != row["size"] or sha256(content) != row["sha256"]:
                        raise StorageRefusal("ZIP member content/hash mismatch")
                    # Reading every member also performs zipfile's CRC verification.
        except (zipfile.BadZipFile, RuntimeError, EOFError, NotImplementedError) as exc:
            raise StorageRefusal("ZIP structure, CRC or bounded content verification failed") from exc
        return True

    def verify_backup(self, *, receipt):
        checked_record(receipt, "backup_receipt", "An exact backup receipt is required")
        archive_rel = self._output_relative(receipt["archive"])
        manifest_rel = self._output_relative(receipt["manifest"])
        with self._scope(self.output_root) as output:
            self._private_created_file(archive_rel)
            self._private_created_file(manifest_rel)
            manifest_data = output.read_bytes(manifest_rel, expected=receipt["manifest_record"], max_bytes=MAX_ARCHIVE_BYTES)
            archive_data = output.read_bytes(archive_rel, expected=receipt["archive_record"], max_bytes=MAX_ARCHIVE_BYTES)
        if sha256(manifest_data) != receipt["manifest_sha256"] or sha256(archive_data) != receipt["archive_sha256"]:
            raise StorageRefusal("Stored backup or manifest changed")
        manifest = checked_record(decode_storage(manifest_data, "Invalid bounded backup manifest"), "backup_manifest", "Foreign backup manifest")
        if manifest["plan_sha256"] != receipt["plan_sha256"] or manifest["required_recovery"] != receipt["required_recovery"]:
            raise StorageRefusal("Backup receipt binding changed")
        self._verify_zip(archive_data, manifest)
        return {"manifest": manifest, "archive_data": archive_data, "verified": True}

    def verified_recovery(self, *, backup, restoration):
        manifest = self.verify_backup(receipt=backup)["manifest"]
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
        outcome = "outcome-restore-" + restoration["plan_sha256"] + ".json"
        with self._scope(self.output_root) as output:
            self._private_created_file(outcome)
            outcome_record = output.inspect(outcome, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)
            if output.read_bytes(outcome, expected=outcome_record, max_bytes=MAX_ARCHIVE_BYTES) != canonical(restoration):
                raise StorageRefusal("Restoration outcome artifact differs from the exact recovery record")
            for row, record in zip(manifest["files"], restoration["records"]):
                expected_path = destination + "/" + row["root_id"] + "/" + row["relative_path"]
                if record["relative_path"] != expected_path or record["sha256"] != row["sha256"]:
                    raise StorageRefusal("Recovery probe does not map the exact backed-up contents")
                self._private_created_file(expected_path)
                data = output.read_bytes(expected_path, expected=record, max_bytes=MAX_FILE_BYTES)
                if len(data) != row["size"] or sha256(data) != row["sha256"]:
                    raise StorageRefusal("Required restored recovery bytes changed")
        return manifest

    def verify_outcome(self, *, plan, expected_plan_sha256, receipt):
        """Read-only actual postconditions for a known immutable outcome.

        Missing/partial outcome evidence is a hold. This method does not retry,
        recreate a receipt or turn an unknown interrupted action into success.
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
        with self._scope(self.output_root) as output:
            self._private_created_file(outcome_name)
            outcome_record = output.inspect(outcome_name, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)
            outcome_data = output.read_bytes(outcome_name, expected=outcome_record, max_bytes=MAX_ARCHIVE_BYTES)
            if outcome_data != canonical(receipt):
                raise StorageRefusal("Outcome receipt differs from the exact immutable artifact")
            if kind == "backup":
                verified = self.verify_backup(receipt=receipt)
                if verified["manifest"]["files"] != plan["files"] or receipt["archive"] != plan["destination"]:
                    raise StorageRefusal("Backup outcome differs from the exact reviewed content/output")
            elif kind == "restore":
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
        return {**storage_value("storage_outcome_verification"), "observed_utc": pc_records.utc_now(),
                "storage_plan_sha256": expected_plan_sha256, "operation_kind": kind,
                "outcome": "succeeded", "verification_passed": True, "mutation_performed": False,
                "receipt_sha256": sha256(outcome_data), "outcome_artifact_relative": outcome_name,
                "outcome_artifact_record": outcome_record}
