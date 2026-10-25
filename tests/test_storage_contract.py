"""The storage adapter payload contract (scripts/storage_contract.py): pure data checks, no files."""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_records
import storage_contract

OUTPUT = str(ROOT / "work" / "test-fixtures" / "storage-contract" / "output")


def payload(adapter_id=pc_records.ADAPTER_STORAGE_BACKUP_CREATE, **changes):
    plan = {"schema": storage_contract.PLAN, "schema_version": 1, "kind": storage_contract.plan_kind(adapter_id), "fixture": True}
    value = {"schema": storage_contract.PAYLOAD, "schema_version": 1, "operation": adapter_id, "storage_plan": plan,
             "storage_plan_sha256": pc_records.digest(plan), "output_root": OUTPUT, "mode": "fixture", "protected_roots": [OUTPUT]}
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
        for other in ("package.upgrade", "system.reviewed_external", "storage.unknown", None, 3):
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

    def test_module_imports_only_layer_zero_and_the_standard_library(self):
        tree = ast.parse((ROOT / "scripts" / "storage_contract.py").read_text(encoding="utf-8"))
        names = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        names |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        products = {path.stem for path in (ROOT / "scripts").glob("*.py")}
        self.assertEqual(names & products, {"pc_records"})
        self.assertTrue(names - products <= set(sys.stdlib_module_names) | {"__future__"}, names - products)


if __name__ == "__main__":
    unittest.main()
