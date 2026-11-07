"""The storage adapter payload contract (scripts/storage_contract.py): pure data checks, no files."""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_records
import storage_contract

OUTPUT = str(ROOT / "work" / "test-fixtures" / "storage-contract" / "output")


# Where each built permanent deletion's plan lists what it deletes: two items of 3 and 4 bytes.
ROWS = {pc_records.ADAPTER_STORAGE_PURGE: {"receipt": {"records": [{"original": {"size": 3}}, {"original": {"size": 4}}]}},
        pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS: {"files": [{"size": 3}, {"size": 4}]},
        pc_records.ADAPTER_STORAGE_DELETE_SELECTED: {"rows_file": {"row_count": 2, "row_bytes": 7}},
        pc_records.ADAPTER_STORAGE_RETENTION_RELEASE: {"rows": [{"size": 3}, {"size": 4}]},
        pc_records.ADAPTER_STORAGE_SESSION_RELEASE: {"rows": [{"size": 3}, {"size": 4}]}}


def payload(adapter_id=pc_records.ADAPTER_STORAGE_BACKUP_CREATE, rows=None, **changes):
    """A storage payload whose plan lists rows (by default the adapter's ROWS) and, for a permanent deletion, their
    count and bytes."""
    plan = {"schema": storage_contract.PLAN, "schema_version": 1, "kind": storage_contract.plan_kind(adapter_id), "fixture": True,
            **(ROWS.get(adapter_id, {}) if rows is None else rows)}
    value = {"schema": storage_contract.PAYLOAD, "schema_version": 1, "operation": adapter_id, "storage_plan": plan,
             "storage_plan_sha256": pc_records.digest(plan), "output_root": OUTPUT, "mode": "fixture", "protected_roots": [OUTPUT]}
    if adapter_id in ROWS:
        value.update(delete_count=2, delete_bytes=7)
    value.update(changes)
    return value


class StorageContractTests(unittest.TestCase):
    def refused(self, call, code="storage-payload"):
        with self.assertRaises(pc_records.Refusal) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def check(self, value, adapter_id=pc_records.ADAPTER_STORAGE_BACKUP_CREATE, mode="fixture"):
        return storage_contract.validate_payload(value, adapter_id=adapter_id, mode=mode, plan_sha256=pc_records.digest(value["storage_plan"]))

    def test_kind_map_covers_every_storage_adapter_and_nothing_else(self):
        storage_ids = {adapter_id for adapter_id in pc_records.ADAPTERS if adapter_id.startswith("storage.")}
        self.assertEqual(set(storage_contract.PLAN_KINDS), storage_ids)
        for adapter_id in storage_ids:
            self.assertEqual(storage_contract.plan_kind(adapter_id), storage_contract.PLAN_KINDS[adapter_id])
        for other in ("package.upgrade", "system.repair", "storage.unknown", None, 3):
            with self.subTest(adapter_id=other):
                self.refused(lambda: storage_contract.plan_kind(other), "unknown-adapter")

    def test_exact_payload_is_accepted_for_each_written_storage_adapter(self):
        for adapter_id in (pc_records.ADAPTER_STORAGE_BACKUP_CREATE, pc_records.ADAPTER_STORAGE_RESTORE, pc_records.ADAPTER_STORAGE_QUARANTINE,
                           pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE, pc_records.ADAPTER_STORAGE_PURGE):
            with self.subTest(adapter_id=adapter_id):
                value = payload(adapter_id)
                self.assertIs(self.check(value, adapter_id), value)
        probe = payload(restore_probe_destination=OUTPUT + "-probe")
        self.assertIs(self.check(probe), probe)

    def test_payload_that_differs_from_the_review_is_refused(self):
        plan = payload()["storage_plan"]
        other_kind = dict(plan, kind="purge")
        cases = {
            "extra field": payload(unexpected=True),
            "missing field": {key: value for key, value in payload().items() if key != "protected_roots"},
            "other operation": payload(operation=pc_records.ADAPTER_STORAGE_QUARANTINE),
            "other mode": payload(mode="real"),
            "plan digest": payload(storage_plan_sha256="0" * 64),
            "plan kind": payload(storage_plan=other_kind, storage_plan_sha256=pc_records.digest(other_kind)),
            "relative output": payload(output_root="work/output"),
            "traversal output": payload(output_root=OUTPUT + "/../elsewhere"),
            "relative protected root": payload(protected_roots=["work"]),
            "repeated protected root": payload(protected_roots=[OUTPUT, OUTPUT]),
            "too many protected roots": payload(protected_roots=[OUTPUT + "/r" + str(n) for n in range(storage_contract.MAX_PROTECTED_ROOTS + 1)]),
            "probe on a purge": payload(pc_records.ADAPTER_STORAGE_PURGE, restore_probe_destination=OUTPUT + "-probe"),
        }
        for reason, value in cases.items():
            adapter_id = pc_records.ADAPTER_STORAGE_PURGE if reason == "probe on a purge" else pc_records.ADAPTER_STORAGE_BACKUP_CREATE
            with self.subTest(reason=reason):
                self.refused(lambda: self.check(value, adapter_id))
        self.refused(lambda: self.check(payload(), pc_records.ADAPTER_STORAGE_BACKUP_CREATE, mode="real"))
        renamed = dict(payload(), schema="patchcairn.storage.payload")
        self.refused(lambda: self.check(renamed), "schema-name")
        self.refused(lambda: self.check(copy.deepcopy(payload()) | {"schema_version": True}), "schema-version")

    def test_storage_reader_is_registered_here_and_checks_the_kind(self):
        self.assertIs(pc_records.READERS[storage_contract.PLAN], storage_contract.read_storage)
        record = {"schema": storage_contract.PLAN, "schema_version": 1, "kind": "backup_receipt"}
        self.assertIs(storage_contract.read_storage(record), record)
        self.refused(lambda: storage_contract.read_storage(dict(record, kind="fictional")), "storage-refusal")
        self.refused(lambda: storage_contract.read_storage(dict(record, schema_version=2)), "schema-version")

    def test_payload_reader_is_registered_here_and_checks_exact_fields(self):
        self.assertIs(pc_records.READERS[storage_contract.PAYLOAD], storage_contract.read_payload)
        value = payload(pc_records.ADAPTER_STORAGE_PURGE)
        self.assertIs(storage_contract.read_payload(value), value)
        self.refused(lambda: storage_contract.read_payload(payload(unexpected=True)))
        self.refused(lambda: storage_contract.read_payload({key: item for key, item in payload().items() if key != "mode"}))
        self.refused(lambda: storage_contract.read_payload(dict(payload(), schema_version=2)), "schema-version")
        self.refused(lambda: storage_contract.read_payload(dict(payload(), schema=storage_contract.PLAN)), "schema-name")
        # validate_payload reads the payload through this one reader before anything else.
        with mock.patch.object(storage_contract, "read_payload", side_effect=pc_records.Refusal("fictional-reader")) as read:
            self.refused(lambda: self.check(payload()), "fictional-reader")
        read.assert_called_once()

    def test_storage_record_kinds_cover_plan_kinds(self):
        # The record kinds come from the plan kinds, so a storage plan of every adapter reads back as a storage record.
        self.assertLessEqual(set(storage_contract.PLAN_KINDS.values()), storage_contract.KINDS)
        for adapter_id, kind in storage_contract.PLAN_KINDS.items():
            record = {"schema": storage_contract.PLAN, "schema_version": 1, "kind": kind}
            with self.subTest(adapter_id=adapter_id):
                self.assertIs(storage_contract.read_storage(record), record)

    def test_module_imports_only_layer_zero_and_the_standard_library(self):
        tree = ast.parse((ROOT / "scripts" / "storage_contract.py").read_text(encoding="utf-8"))
        names = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        names |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        products = {path.stem for path in (ROOT / "scripts").glob("*.py")}
        self.assertEqual(names & products, {"pc_records"})
        self.assertTrue(names - products <= set(sys.stdlib_module_names) | {"__future__"}, names - products)


class ContractTests(unittest.TestCase):
    """The deletion count and size that the owner's typed reply names (pure data checks)."""

    def check(self, value):
        return storage_contract.validate_payload(value, adapter_id=value["operation"], mode="fixture",
                                                 plan_sha256=pc_records.digest(value["storage_plan"]))

    def refused(self, value):
        with self.assertRaises(pc_records.Refusal) as caught:
            self.check(value)
        self.assertEqual(caught.exception.code, "storage-payload")

    def test_permanent_loss_kinds_require_count_and_bytes(self):
        loss = {adapter_id for adapter_id in storage_contract.PLAN_KINDS
                if "permanent_data_loss" in pc_records.ADAPTERS[adapter_id]["acknowledgments"]}
        self.assertEqual(loss, set(ROWS))
        self.assertEqual(set(storage_contract.DELETION_SOURCES), set(ROWS))
        for adapter_id in sorted(ROWS):
            base = {key: value for key, value in payload(adapter_id).items() if key not in storage_contract.DELETION_FIELDS}
            with self.subTest(adapter_id=adapter_id):
                accepted = dict(base, delete_count=2, delete_bytes=7)
                self.assertIs(self.check(accepted), accepted)
                for changes in ({}, {"delete_count": 2}, {"delete_bytes": 7}, {"delete_count": 0, "delete_bytes": 7},
                                {"delete_count": True, "delete_bytes": 7}, {"delete_count": "2", "delete_bytes": 7},
                                {"delete_count": 2.0, "delete_bytes": 7}, {"delete_count": None, "delete_bytes": 7},
                                {"delete_count": 2, "delete_bytes": -1}, {"delete_count": 2, "delete_bytes": 7.0},
                                {"delete_count": 2, "delete_bytes": None}):
                    with self.subTest(adapter_id=adapter_id, changes=changes):
                        self.refused(dict(base, **changes))
        # A release reads its own rows: another deletion's list counts for nothing.
        for adapter_id in (pc_records.ADAPTER_STORAGE_RETENTION_RELEASE, pc_records.ADAPTER_STORAGE_SESSION_RELEASE):
            with self.subTest(other_list=adapter_id):
                self.refused(payload(adapter_id, rows={"files": [{"size": 3}]}, delete_count=1, delete_bytes=3))
        # Every other storage kind carries neither field.
        for adapter_id in sorted(set(storage_contract.PLAN_KINDS) - loss):
            value = payload(adapter_id)
            self.assertIs(self.check(value), value)
            for changes in ({"delete_count": 1, "delete_bytes": 0}, {"delete_count": 1}, {"delete_bytes": 0}):
                with self.subTest(adapter_id=adapter_id, changes=changes):
                    self.refused(dict(value, **changes))

    def test_count_and_bytes_must_equal_the_plan_rows(self):
        for adapter_id in sorted(ROWS):
            for count, size in ((1, 7), (3, 7), (2, 6), (2, 8), (500, 0)):
                with self.subTest(adapter_id=adapter_id, count=count, size=size):
                    self.refused(payload(adapter_id, delete_count=count, delete_bytes=size))
        self.assertEqual(storage_contract.deletion_size(pc_records.ADAPTER_STORAGE_PURGE, payload(pc_records.ADAPTER_STORAGE_PURGE)["storage_plan"]), (2, 7))
        self.assertEqual(storage_contract.deletion_size(pc_records.ADAPTER_STORAGE_BACKUP_CREATE, {"files": [{"size": 3}]}), (None, None))

    def test_a_deletion_plan_lists_its_items_in_one_place(self):
        # The count comes from the adapter's own source; a plan that also carries another deletion's source is refused.
        for adapter_id, extra in ((pc_records.ADAPTER_STORAGE_PURGE, {"rows_file": {"row_count": 1, "row_bytes": 0}}),
                                  (pc_records.ADAPTER_STORAGE_PURGE, {"files": [{"size": 0}]}),
                                  (pc_records.ADAPTER_STORAGE_DELETE_SELECTED, {"files": [{"size": 3}, {"size": 4}]}),
                                  (pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS, {"rows_file": {"row_count": 2, "row_bytes": 7}}),
                                  (pc_records.ADAPTER_STORAGE_RETENTION_RELEASE, {"files": [{"size": 3}, {"size": 4}]})):
            with self.subTest(adapter_id=adapter_id, extra=sorted(extra)):
                self.refused(payload(adapter_id, rows={**ROWS[adapter_id], **extra}))

    def test_row_sizes_are_integers_of_zero_or_more(self):
        # Sizes whose sum still equals the payload's bytes: only the per-row check can refuse them.
        for adapter_id, rows, total in ((pc_records.ADAPTER_STORAGE_PURGE, {"receipt": {"records": [{"original": {"size": 8}}, {"original": {"size": -1}}]}}, 7),
                                        (pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS, {"files": [{"size": 8}, {"size": -1}]}, 7),
                                        (pc_records.ADAPTER_STORAGE_RETENTION_RELEASE, {"rows": [{"size": 8}, {"size": -1}]}, 7),
                                        (pc_records.ADAPTER_STORAGE_DELETE_SELECTED, {"rows_file": {"row_count": 2, "row_bytes": -1}}, -1)):
            with self.subTest(adapter_id=adapter_id, sizes="8 and -1"):
                self.refused(payload(adapter_id, rows=rows, delete_count=2, delete_bytes=total))
        for size in (True, False, 1.5, "3", None):
            for adapter_id, rows in ((pc_records.ADAPTER_STORAGE_PURGE, {"receipt": {"records": [{"original": {"size": 7}}, {"original": {"size": size}}]}}),
                                     (pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS, {"files": [{"size": 7}, {"size": size}]}),
                                     (pc_records.ADAPTER_STORAGE_SESSION_RELEASE, {"rows": [{"size": 7}, {"size": size}]}),
                                     (pc_records.ADAPTER_STORAGE_DELETE_SELECTED, {"rows_file": {"row_count": 2, "row_bytes": size}})):
                with self.subTest(adapter_id=adapter_id, size=size):
                    self.refused(payload(adapter_id, rows=rows, delete_count=2, delete_bytes=7))
        zero = payload(pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS, rows={"files": [{"size": 0}]}, delete_count=1, delete_bytes=0)
        self.assertIs(self.check(zero), zero)
        for rows in ({"files": []}, {"files": {"size": 3}}, {}):
            with self.subTest(rows=rows):
                self.refused(payload(pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS, rows=rows, delete_count=1, delete_bytes=0))



class BackupPayloadTests(unittest.TestCase):
    """The backup payload fields: an optional folder on another drive, only for a backup, exactly the plan's own."""

    def check(self, value):
        return storage_contract.validate_payload(value, adapter_id=value["operation"], mode="fixture",
                                                 plan_sha256=pc_records.digest(value["storage_plan"]))

    def test_backup_destination_is_there_exactly_when_the_plan_is_external(self):
        elsewhere = str(ROOT / "work" / "test-fixtures" / "storage-contract" / "elsewhere")
        rows = {"external": True, "destination": elsewhere}
        value = payload(rows=rows, backup_destination=elsewhere)
        self.assertIs(self.check(value), value)
        # A backup in the owned output folder carries none; a plan without the fact is such a backup.
        for plain in (payload(), payload(rows={"external": False, "destination": OUTPUT})):
            self.assertIs(self.check(plain), plain)
        self.assertLessEqual({"backup_destination", "restore_probe_destination"}, storage_contract.PAYLOAD_OPTIONAL)
        self.assertNotIn("backup_destination", storage_contract.PAYLOAD_REQUIRED)
        for changed in (payload(rows=rows),  # external, so its folder would be written without being reserved
                        payload(rows={**rows, "external": 1}), payload(rows={**rows, "external": "true"}),
                        payload(rows={**rows, "external": None}),
                        payload(rows={**rows, "external": 1}, backup_destination=elsewhere),
                        payload(rows={"external": False, "destination": elsewhere}, backup_destination=elsewhere),
                        payload(backup_destination=elsewhere),
                        payload(rows=rows, backup_destination=elsewhere + "-other"),
                        payload(rows=rows, backup_destination="relative/folder"),
                        payload(pc_records.ADAPTER_STORAGE_RESTORE, backup_destination=elsewhere),
                        payload(pc_records.ADAPTER_STORAGE_PURGE, backup_destination=elsewhere)):
            with self.subTest(changed=changed), self.assertRaises(pc_records.Refusal) as caught:
                self.check(changed)
            self.assertEqual(caught.exception.code, "storage-payload")


if __name__ == "__main__":
    unittest.main()
