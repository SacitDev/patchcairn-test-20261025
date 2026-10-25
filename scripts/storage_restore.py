"""Restore plans and restore from a verified backup, mixed into storage_ops.StorageService (see its trust model)."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pc_paths
import pc_records
from scoped_fs import ScopedFSError
from storage_policy import MAX_FILE_BYTES, StorageRefusal, bound_plan, checked_absolute, new_plan, sha256, storage_value


def restorable(destination_relative, files):
    """Refuse, before any attempt record or output, a restore whose target path would exceed the portable limit."""
    if any(not pc_paths.portable(f"{destination_relative}/{row['root_id']}/{row['relative_path']}") for row in files):
        raise StorageRefusal("A restored path would be longer than the portable limit; choose a shorter destination folder",
                             code="path-too-long")


class StorageRestore:
    """StorageService's restore plan and restore from a verified backup."""

    def plan_restore(self, *, receipt, destination):
        verified = self.verify_backup(receipt=receipt)
        manifest = verified["manifest"]
        relative = self._outside_sources(destination, manifest["source_roots"])
        with self._scope(self.output_root) as output:
            parent = Path(relative).parent.as_posix()
            if parent != ".":
                output.inspect(parent)
            try:
                output.inspect(relative)
            except (FileNotFoundError, ScopedFSError) as exc:
                # Do not treat access, symlink or capability failures as absence.
                if isinstance(exc, ScopedFSError) and getattr(exc, "code", "") != "missing-entry":
                    raise
            else:
                raise StorageRefusal("Restore requires a new destination; overwrite is refused")
        restorable(relative, manifest["files"])
        return new_plan("restore", receipt=receipt, destination=str(checked_absolute(destination)),
                         destination_relative=relative, files=manifest["files"], skipped=manifest["skipped"],
                         cost={"logical_bytes_to_write": manifest["source_logical_bytes"], "duration_seconds": None,
                               "physical_bytes_to_write": None, "net_free_space_change_bytes": None})

    def _mkdir_parents(self, output, relative, made):
        parts = relative.split("/")[:-1]
        for count in range(1, len(parts) + 1):
            parent = "/".join(parts[:count])
            if parent not in made:
                self._mkdir_private(output, parent)
                made.add(parent)

    def restore_backup(self, *, plan, expected_plan_sha256):
        bound_plan(plan, expected_plan_sha256, "restore")
        verified = self.verify_backup(receipt=plan["receipt"])
        if plan["files"] != verified["manifest"]["files"]:
            raise StorageRefusal("Restore file list differs from verified backup")
        relative = self._outside_sources(plan["destination"], verified["manifest"]["source_roots"])
        if relative != plan["destination_relative"]:
            raise StorageRefusal("Restore scope changed")
        restorable(relative, plan["files"])
        records = []
        with self._scope(self.output_root) as output:
            attempt = self._attempt(output, expected_plan_sha256, "restore", plan)
            self._mkdir_private(output, relative)
            made = {"/".join(relative.split("/")[:depth]) for depth in range(1, len(relative.split("/")) + 1)}
            with zipfile.ZipFile(io.BytesIO(verified["archive_data"]), "r") as archive:
                for index, row in enumerate(plan["files"], 1):
                    target = relative + "/" + row["root_id"] + "/" + row["relative_path"]
                    self._mkdir_parents(output, target, made)
                    data = archive.read(row["entry"])
                    if sha256(data) != row["sha256"]:
                        raise StorageRefusal("Restore content changed")
                    record = self._create_private_file(output, target, data=data, max_bytes=MAX_FILE_BYTES)
                    observed = output.read_bytes(target, expected=record, max_bytes=MAX_FILE_BYTES)
                    if sha256(observed) != row["sha256"]:
                        raise StorageRefusal("Restored file verification failed")
                    records.append(record)
                    self._write_json(output, f"step-restore-{expected_plan_sha256}-{index:06d}.json", record)
            receipt = {**storage_value("restore_receipt"), "plan_sha256": expected_plan_sha256,
                       "destination": plan["destination"], "records": records, "verified": True,
                       "backup_plan_sha256": plan["receipt"]["plan_sha256"],
                       "backup_archive_sha256": plan["receipt"]["archive_sha256"],
                       "backup_manifest_sha256": plan["receipt"]["manifest_sha256"],
                       "files": plan["files"],
                       "skipped": plan["skipped"], "attempt": attempt, "finished_utc": pc_records.utc_now()}
            self._write_json(output, f"outcome-restore-{expected_plan_sha256}.json", receipt)
            return receipt
