"""Quarantine, quarantine restore and purge of exact files, mixed into storage_ops.StorageService (see its trust model)."""
from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path

import pc_records
from scoped_fs import capabilities
from private_workspace import PrivateWorkspaceError, ensure_private_file
from storage_policy import (HASH_RE, MAX_ARCHIVE_BYTES, MAX_FILE_BYTES, StorageRefusal, bound_plan, canonical,
                            checked_absolute, checked_record, content_permission, decode_storage, new_plan, selection,
                            storage_value, within)


class StorageCleanup:
    """StorageService's quarantine, quarantine restore and purge."""

    def _private_windows_quarantine_file(self, path):
        # Same-volume Windows rename preserves the original file DACL. Directory
        # privacy alone cannot counter SeChangeNotify traversal privileges.
        # POSIX mode 0644 files remain protected by their private 0700 parent and
        # retain their original permissions; do not chmod ordinary source files.
        if os.name == "nt":
            try:
                ensure_private_file(path)
            except PrivateWorkspaceError as exc:
                raise self._privacy_hold(exc) from exc

    def _quarantine_source_privacy(self, roots, rows):
        if os.name == "nt":
            paths = {row["root_id"]: Path(row["path"]) for row in roots}
            for row in rows:
                self._private_windows_quarantine_file(paths[row["root_id"]] / row["relative_path"])

    def plan_cleanup(self, *, inventory, selected, quarantine_destination, content_read_authorized,
                     recovery_required=True, recovery_backup=None, recovery_verification=None, protected=None):
        content_permission(content_read_authorized)
        if type(recovery_required) is not bool:
            raise StorageRefusal("Recovery requirement must be an explicit boolean")
        protected = protected or []
        if not isinstance(protected, list) or any(not isinstance(key, str) for key in protected):
            raise StorageRefusal("Exact protected file keys are required")
        selected_rows = selection(inventory, selected)
        self._content_budget(selected_rows, inventory["limits"])
        self._cleanup_targets(inventory, selected_rows, protected)
        self._quarantine_source_privacy(inventory["roots"], selected_rows)
        relative = self._outside_sources(quarantine_destination, inventory["roots"])
        self._fresh_inventory(inventory)
        rows = []
        with ExitStack() as stack:
            sources = self._open_sources(stack, inventory["roots"])
            for item in selected_rows:
                rows.append(self._hashed(sources[item["root_id"]], item, inventory["limits"]))
        if recovery_required:
            if recovery_backup is None:
                raise StorageRefusal("Required recovery has not been verified; create and verify the exact backup first")
            manifest = self.verified_recovery(backup=recovery_backup, restoration=recovery_verification)
            backed = {(row["root_id"], row["relative_path"], row["sha256"], row["size"]) for row in manifest["files"]}
            if manifest["source_roots"] != inventory["roots"] or any(
                    (row["root_id"], row["relative_path"], row["sha256"], row["size"]) not in backed for row in rows):
                raise StorageRefusal("Required backup does not cover the exact selected identities/content/scope")
        return new_plan("quarantine", inventory=inventory, files=rows, protected=sorted(protected),
                         quarantine_destination=str(checked_absolute(quarantine_destination)), quarantine_relative=relative,
                         recovery_required=recovery_required, recovery_backup=recovery_backup,
                         recovery_verification=recovery_verification,
                         cost={"selected_logical_bytes": sum(row["size"] for row in rows),
                               "expected_free_space_gain_bytes": 0, "physical_bytes": None,
                               "duration_seconds": None, "money": None},
                         explanation="Quarantine moves exact ordinary files on the same volume. It normally frees no disk space.")

    def _cleanup_targets(self, inventory, rows, protected):
        if {row["key"] for row in rows} & set(protected):
            raise StorageRefusal("Required recovery/protected artifacts cannot be cleanup targets")
        roots_by_id = {row["root_id"]: checked_absolute(row["path"]) for row in inventory["roots"]}
        if any(within(roots_by_id[row["root_id"]] / row["relative_path"], self.output_root) for row in rows):
            raise StorageRefusal("This service's backup, evidence and recovery output artifacts stay protected from host cleanup")

    def quarantine(self, *, plan, expected_plan_sha256):
        bound_plan(plan, expected_plan_sha256, "quarantine")
        self._reviewed_files(plan)
        self._content_budget(plan["files"], plan["inventory"]["limits"])
        self._quarantine_source_privacy(plan["inventory"]["roots"], plan["files"])
        if capabilities().get("move_noreplace") is not True:
            raise StorageRefusal("Checked native no-overwrite move is unavailable; quarantine is held with no fallback")
        self._fresh_inventory(plan["inventory"])
        self._cleanup_targets(plan["inventory"], plan["files"], plan["protected"])
        if plan["recovery_required"]:
            self.verified_recovery(backup=plan["recovery_backup"], restoration=plan["recovery_verification"])
        relative = self._outside_sources(plan["quarantine_destination"], plan["inventory"]["roots"])
        if relative != plan["quarantine_relative"] or any(row["key"] in plan["protected"] for row in plan["files"]):
            raise StorageRefusal("Quarantine scope or protected files changed")
        records = []
        with ExitStack() as stack:
            output = stack.enter_context(self._scope(self.output_root))
            sources = self._open_sources(stack, plan["inventory"]["roots"])
            destination_device = output.inspect("")["device"]
            if any(row["device"] != destination_device for row in plan["files"]):
                raise StorageRefusal("Cross-volume quarantine is refused; no copy/delete fallback")
            attempt = self._attempt(output, expected_plan_sha256, "quarantine", plan)
            self._mkdir_private(output, relative)
            for index, row in enumerate(plan["files"], 1):
                target = relative + f"/{index:06d}"
                expected = {key: value for key, value in row.items() if key not in {"root_id", "key"}}
                moved = sources[row["root_id"]].move_to(row["relative_path"], destination=output,
                                                       destination_relative=target, expected=expected)
                self._private_windows_quarantine_file(self.output_root / target)
                record = {"original": row, "quarantine_record": moved}
                records.append(record)
                self._write_json(output, f"step-quarantine-{expected_plan_sha256}-{index:06d}.json", record)
            receipt = {**storage_value("quarantine_receipt"), "plan_sha256": expected_plan_sha256,
                       "source_roots": plan["inventory"]["roots"], "quarantine_destination": plan["quarantine_destination"],
                       "records": records, "recovery_required": plan["recovery_required"], "recovery_backup": plan["recovery_backup"],
                       "recovery_verification": plan["recovery_verification"],
                       "attempt": attempt, "expected_free_space_gain_bytes": 0, "finished_utc": pc_records.utc_now()}
            self._write_json(output, f"outcome-quarantine-{expected_plan_sha256}.json", receipt)
            return receipt

    def _quarantine_provenance(self, receipt, output):
        checked_record(receipt, "quarantine_receipt", "Exact quarantine receipt required")
        if not isinstance(receipt.get("plan_sha256"), str) or not HASH_RE.fullmatch(receipt["plan_sha256"]):
            raise StorageRefusal("Exact original quarantine plan binding required")
        relative = self._output_relative(receipt["quarantine_destination"])
        outcome_name = "outcome-quarantine-" + receipt["plan_sha256"] + ".json"
        self._private_created_file(outcome_name)
        outcome_record = output.inspect(outcome_name, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)
        if output.read_bytes(outcome_name, expected=outcome_record, max_bytes=MAX_ARCHIVE_BYTES) != canonical(receipt):
            raise StorageRefusal("Quarantine receipt differs from the immutable original outcome")
        attempt_name = "attempt-quarantine-" + receipt["plan_sha256"] + ".json"
        if receipt.get("attempt") != attempt_name:
            raise StorageRefusal("Original quarantine attempt reference changed")
        self._private_created_file(attempt_name)
        attempt_record = output.inspect(attempt_name, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)
        attempt = checked_record(decode_storage(output.read_bytes(attempt_name, expected=attempt_record, max_bytes=MAX_ARCHIVE_BYTES),
                                   "Invalid original quarantine attempt"), "attempt", "Invalid original quarantine attempt")
        plan_file = "plan-quarantine-" + receipt["plan_sha256"] + ".json"
        if attempt.get("plan_file") != plan_file or attempt.get("plan_sha256") != receipt["plan_sha256"]:
            raise StorageRefusal("Original exact quarantine plan is unavailable; reconcile the incomplete operation")
        self._private_created_file(plan_file)
        plan_record = output.inspect(plan_file, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)
        original_plan = decode_storage(output.read_bytes(plan_file, expected=plan_record, max_bytes=MAX_ARCHIVE_BYTES), "Invalid original quarantine plan")
        bound_plan(original_plan, receipt["plan_sha256"], "quarantine")
        if (original_plan["quarantine_relative"] != relative
                or original_plan["quarantine_destination"] != receipt["quarantine_destination"]):
            raise StorageRefusal("Original quarantine destination changed")
        if (original_plan["inventory"]["roots"] != receipt["source_roots"]
                or original_plan["files"] != [row["original"] for row in receipt["records"]]
                or original_plan["recovery_required"] != receipt["recovery_required"]
                or original_plan["recovery_backup"] != receipt["recovery_backup"]
                or original_plan["recovery_verification"] != receipt["recovery_verification"]):
            raise StorageRefusal("Quarantine source mapping or recovery retention differs from the original plan")
        if any(row["quarantine_record"]["relative_path"] != relative + f"/{index:06d}"
               for index, row in enumerate(receipt["records"], 1)):
            raise StorageRefusal("Quarantine target mapping differs from the original numbered plan")
        return relative

    def _quarantine_current(self, receipt):
        with self._scope(self.output_root) as output:
            relative = self._quarantine_provenance(receipt, output)
            self._private_directory(relative)
            left_out = []
            actual = sorted(output.list_directory(relative, excluded=left_out), key=lambda row: row["relative_path"])
            if left_out:
                # PatchCairn's own quarantine folder: an unknown link, special file or name is never "not included".
                raise StorageRefusal("Unknown, missing or changed quarantine files; recovery review is required")
            expected = sorted([row["quarantine_record"] for row in receipt["records"]], key=lambda row: row["relative_path"])
            if ([{**row, "sha256": None} for row in actual]
                    != [{**row, "sha256": None} for row in expected]):
                raise StorageRefusal("Unknown, missing or changed quarantine files; recovery review is required")
            for row in receipt["records"]:
                self._private_windows_quarantine_file(self.output_root / row["quarantine_record"]["relative_path"])
                observed = output.inspect(row["quarantine_record"]["relative_path"], hash_file=True, max_bytes=MAX_FILE_BYTES)
                if observed != row["quarantine_record"]:
                    raise StorageRefusal("Quarantine content changed")
        return relative

    def plan_quarantine_restore(self, *, receipt):
        self._quarantine_current(receipt)
        return new_plan("quarantine_restore", receipt=receipt,
                         explanation="Restore the exact quarantined files to their original selected roots; existing files are never overwritten.")

    def restore_quarantine(self, *, plan, expected_plan_sha256):
        bound_plan(plan, expected_plan_sha256, "quarantine_restore")
        if capabilities().get("move_noreplace") is not True:
            raise StorageRefusal("Checked native no-overwrite move is unavailable; restore is held with no fallback")
        receipt = plan["receipt"]
        self._quarantine_current(receipt)
        result = []
        with ExitStack() as stack:
            output = stack.enter_context(self._scope(self.output_root))
            sources = self._open_sources(stack, receipt["source_roots"])
            attempt = self._attempt(output, expected_plan_sha256, "quarantine-restore", plan)
            for index, row in enumerate(receipt["records"], 1):
                original = row["original"]
                observed = output.move_to(row["quarantine_record"]["relative_path"], destination=sources[original["root_id"]],
                                          destination_relative=original["relative_path"], expected=row["quarantine_record"])
                source_root = next(root["path"] for root in receipt["source_roots"] if root["root_id"] == original["root_id"])
                self._private_windows_quarantine_file(Path(source_root) / original["relative_path"])
                result.append(observed)
                self._write_json(output, f"step-quarantine-restore-{expected_plan_sha256}-{index:06d}.json", observed)
            outcome = {**storage_value("quarantine_restore_receipt"), "plan_sha256": expected_plan_sha256,
                       "records": result, "attempt": attempt, "finished_utc": pc_records.utc_now()}
            self._write_json(output, f"outcome-quarantine-restore-{expected_plan_sha256}.json", outcome)
            return outcome

    def plan_purge(self, *, receipt):
        self._quarantine_current(receipt)
        if receipt["recovery_required"]:
            self.verified_recovery(backup=receipt["recovery_backup"], restoration=receipt["recovery_verification"])
        return new_plan("purge", receipt=receipt, irreversible=True,
                         requires_separate_owner_approval=True, requires_loss_acknowledgment=True,
                         cost={"selected_logical_bytes": sum(row["original"]["size"] for row in receipt["records"]),
                               "physical_free_space_gain_bytes": None, "duration_seconds": None, "money": None},
                         explanation="Permanently remove only the exact quarantined files. Logical size is not a promise of physical free space.")

    def purge_quarantine(self, *, plan, expected_plan_sha256):
        """Low-level removal; coordinator MUST separately gate irreversible loss.

        There is deliberately no `approved=True` or quotation parameter. Such a
        parameter would not authenticate the current owner's decision.
        """
        bound_plan(plan, expected_plan_sha256, "purge")
        if capabilities().get("remove_file") is not True:
            raise StorageRefusal("Checked native file removal is unavailable; purge is held with no fallback")
        receipt = plan["receipt"]
        self._quarantine_current(receipt)
        if receipt["recovery_required"]:
            self.verified_recovery(backup=receipt["recovery_backup"], restoration=receipt["recovery_verification"])
        removed = []
        with self._scope(self.output_root) as output:
            attempt = self._attempt(output, expected_plan_sha256, "purge", plan)
            for index, row in enumerate(receipt["records"], 1):
                target = row["quarantine_record"]
                output.remove_file(target["relative_path"], expected=target)
                removed.append(target["relative_path"])
                self._write_json(output, f"step-purge-{expected_plan_sha256}-{index:06d}.json", {"removed": target})
            outcome = {**storage_value("purge_receipt"), "plan_sha256": expected_plan_sha256,
                       "removed": removed, "irreversible": True, "attempt": attempt, "finished_utc": pc_records.utc_now(),
                       "physical_free_space_gain_bytes": None}
            self._write_json(output, f"outcome-purge-{expected_plan_sha256}.json", outcome)
            return outcome
