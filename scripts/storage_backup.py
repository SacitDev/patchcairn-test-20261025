"""Backup plans and verified archive creation, mixed into storage_ops.StorageService (see its trust model)."""
from __future__ import annotations

import io
import stat
import zipfile
from contextlib import ExitStack
from pathlib import Path

import pc_records
import scoped_base
from storage_policy import (MAX_ARCHIVE_BYTES, MAX_FILE_BYTES, StorageRefusal, bound_plan, canonical, checked_absolute,
                            content_permission, new_plan, selection, sha256, storage_value)

# Plain reasons for entries an assessment lists as not included (scoped_base.EXCLUDED_REASONS, D-025).
NOT_INCLUDED = {"link": "a link; not included", "special": "a special file; not included",
                "hard-link": "a file with more than one hard link; not included",
                "not-portable": "a name that cannot be used on every system; not included",
                "path-too-long": "path longer than the portable limit; not included",
                "case-collision": "a name that differs from another only by case or form; not included",
                scoped_base.MORE_EXCLUDED: "more entries not included"}


class StorageBackup:
    """StorageService's backup plan and archive creation."""

    def plan_backup(self, *, inventory, selected, destination, content_read_authorized, required_recovery=True, exclusions=None):
        content_permission(content_read_authorized)
        if type(required_recovery) is not bool:
            raise StorageRefusal("Required recovery must be an explicit boolean")
        if exclusions is not None and (not isinstance(exclusions, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) or not v.strip() or len(v) > 400 for k, v in exclusions.items())):
            raise StorageRefusal("Exclusions require exact keys and bounded human-readable reasons")
        destination_rel = self._outside_sources(destination, inventory["roots"])
        if Path(destination_rel).suffix.casefold() != ".zip":
            raise StorageRefusal("An explicit .zip output filename is required")
        selected_rows = selection(inventory, selected)
        self._content_budget(selected_rows, inventory["limits"])
        self._fresh_inventory(inventory)
        rows = []
        with ExitStack() as stack:
            sources = self._open_sources(stack, inventory["roots"])
            for index, item in enumerate(selected_rows, 1):
                hashed = self._hashed(sources[item["root_id"]], item, inventory["limits"])
                rows.append({"entry": f"payload/{index:06d}", **hashed})
        skipped = []
        selected_set = set(selected)
        for item in inventory["entries"]:
            if item["key"] not in selected_set:
                default_reason = ("directory metadata and empty-directory preservation are not backed up; selected child contents may be included"
                                  if item["kind"] == "directory" else "not selected; not backed up")
                skipped.append({"key": item["key"], "kind": item["kind"],
                                "reason": item.get("reason") or (exclusions or {}).get(item["key"], default_reason)})
        for row in inventory["not_included"]:
            skipped.append({"key": "/".join(part for part in (row["root_id"], row["parent"], row["name"]) if part),
                            "kind": "not_included", "reason": NOT_INCLUDED[row["reason"]], **({"count": row["count"]} if "count" in row else {})})
        if exclusions and any(key not in {item["key"] for item in skipped} for key in exclusions):
            raise StorageRefusal("Exclusion reasons may refer only to exact skipped inventory entries")
        return new_plan("backup", inventory=inventory, files=rows, skipped=skipped,
                         destination=str(checked_absolute(destination)), destination_relative=destination_rel,
                         required_recovery=required_recovery, compression="deflate", encryption=False,
                         cost={"source_logical_bytes": sum(row["size"] for row in rows),
                               "archive_bytes": None, "peak_additional_disk_bytes": None,
                               "peak_process_memory_bytes": None,
                               "bounded_payload_buffer_bytes": MAX_ARCHIVE_BYTES + MAX_FILE_BYTES,
                               "duration_seconds": None, "money": None,
                               "net_free_space_change_bytes": None})

    def create_backup(self, *, plan, expected_plan_sha256):
        bound_plan(plan, expected_plan_sha256, "backup")
        self._reviewed_files(plan)
        self._content_budget(plan["files"], plan["inventory"]["limits"])
        self._fresh_inventory(plan["inventory"])
        destination_rel = self._outside_sources(plan["destination"], plan["inventory"]["roots"])
        if destination_rel != plan["destination_relative"]:
            raise StorageRefusal("Output scope changed")
        with ExitStack() as stack:
            output = stack.enter_context(self._scope(self.output_root))
            sources = self._open_sources(stack, plan["inventory"]["roots"])
            attempt = self._attempt(output, expected_plan_sha256, "backup", plan)
            buffer = io.BytesIO()
            total = 0
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for row in plan["files"]:
                    total += row["size"]
                    if total > plan["inventory"]["limits"]["max_total_bytes"]:
                        raise StorageRefusal("Backup source byte cap exceeded")
                    record = {key: value for key, value in row.items() if key not in {"entry", "root_id", "key"}}
                    data = sources[row["root_id"]].read_bytes(row["relative_path"], expected=record,
                                                              max_bytes=plan["inventory"]["limits"]["max_file_bytes"])
                    if sha256(data) != row["sha256"] or len(data) != row["size"]:
                        raise StorageRefusal("Backup source content changed")
                    info = zipfile.ZipInfo(row["entry"], (1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    archive.writestr(info, data)
                    if buffer.tell() > MAX_ARCHIVE_BYTES:
                        raise StorageRefusal("Backup archive byte cap exceeded")
            archive_data = buffer.getvalue()
            if len(archive_data) > MAX_ARCHIVE_BYTES:
                raise StorageRefusal("Backup archive byte cap exceeded")
            manifest = {**storage_value("backup_manifest"), "created_utc": pc_records.utc_now(),
                        "plan_sha256": expected_plan_sha256, "archive_sha256": sha256(archive_data),
                        "archive_bytes": len(archive_data), "files": plan["files"], "skipped": plan["skipped"],
                        "source_roots": plan["inventory"]["roots"], "required_recovery": plan["required_recovery"],
                        "source_logical_bytes": total, "compression_is_not_encryption": True, "limits": plan["inventory"]["limits"]}
            self._verify_zip(archive_data, manifest)
            archive_record = self._create_private_file(output, destination_rel, data=archive_data, max_bytes=MAX_ARCHIVE_BYTES)
            manifest_rel = destination_rel + ".manifest.json"
            manifest_data = canonical(manifest)
            manifest_record = self._create_private_file(output, manifest_rel, data=manifest_data, max_bytes=MAX_ARCHIVE_BYTES)
            receipt = {**storage_value("backup_receipt"), "plan_sha256": expected_plan_sha256,
                       "archive": str(self.output_root / destination_rel), "archive_record": archive_record,
                       "archive_sha256": sha256(archive_data), "manifest": str(self.output_root / manifest_rel),
                       "manifest_record": manifest_record, "manifest_sha256": sha256(manifest_data),
                       "required_recovery": plan["required_recovery"], "attempt": attempt,
                       "verified": True, "encryption": False, "actual_archive_bytes": len(archive_data),
                       "archive_and_manifest_bytes": len(archive_data) + len(manifest_data),
                       "additional_control_record_bytes": None,
                       "source_logical_bytes": total, "finished_utc": pc_records.utc_now()}
            # Verify bytes from disk, not just the buffer used to create them.
            self.verify_backup(receipt=receipt)
            self._write_json(output, f"outcome-backup-{expected_plan_sha256}.json", receipt)
            return receipt
