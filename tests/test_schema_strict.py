"""Strict record schemas (gate G04), driven by the pc_records registry.

Every family with a registered reader refuses a schema_version that is not the integer 1 and a schema name that
is wrong, versioned or missing; containers need the integer version; records in an older PatchCairn format are
refused with the clear message. The readers are the ones the product modules register when they are imported.
The golden-layout tests pin the exact bytes or hashes of the engine marker, creation marker, session state and
journal, service marker and retention registry, diagnostic request, storage attempt record and storage capabilities
(F-011); the storage inventory rows and fingerprint fields are pinned in test_storage_ops. Fixtures stay under
work/test-fixtures/ss-<id>/.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_records
import diagnostic_core
import storage_contract
import storage_ops
import workflow_core
import workflow_service

# Short fixture names keep the deepest record path within the Windows private-path cap from a long checkout path.
WORK = ROOT / "work" / "test-fixtures"
# A family's reader lives in the lowest module that reads it, named by its layer (D-036 item 2).
OWNER_PREFIXES = ("workflow_core", "engine_", "workflow_service", "service_", "storage_", "diagnostic_")
# The kind a sample record carries in the families whose records are told apart by "kind".
SAMPLE_KINDS = {"patchcairn.storage": "backup_receipt", "patchcairn.diagnostics": "result", "patchcairn.service": "service_marker"}
MISSING = object()
BAD_VERSIONS = (True, 1.0, "1", 0, 2, MISSING)
CLOCK = "2026-01-02T03:04:05.000006Z"


def versioned(name, number):
    """An older-style name, built at run time so no version label sits in the source."""
    return f"{name}.v{number}"


def sample(name, version=1):
    """A record of the family ``name``; the schema checks run before any other field check."""
    record = {"schema": name, "schema_version": version}
    if version is MISSING:
        del record["schema_version"]
    if name in SAMPLE_KINDS:
        record["kind"] = SAMPLE_KINDS[name]
    return record


def readers():
    return sorted((name, reader) for name, reader in pc_records.READERS.items())


def fixture_root():
    root = WORK / ("ss-" + uuid.uuid4().hex[:16])
    root.mkdir(parents=True)
    return root


class StrictSchemaTests(unittest.TestCase):
    def refused(self, call, code):
        with self.assertRaises(pc_records.Refusal) as caught:
            call()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_every_python_family_refuses_bad_schema_version(self):
        for name, reader in readers():
            for version in BAD_VERSIONS:
                with self.subTest(family=name, version=version if version is not MISSING else "missing"):
                    self.refused(lambda: reader(sample(name, version)), "schema-version")

    def test_every_python_family_refuses_bad_schema_name(self):
        names = [name for name, _ in readers()]
        for name, reader in readers():
            other = next(candidate for candidate in names if candidate != name)
            wrong = dict(sample(name), schema=other)
            unknown = dict(sample(name), schema="patchcairn.unknown")
            missing = sample(name)
            del missing["schema"]
            with self.subTest(family=name):
                self.refused(lambda: reader(wrong), "schema-name")
                self.refused(lambda: reader(unknown), "schema-name")
                self.refused(lambda: reader(missing), "schema-name")
                older = self.refused(lambda: reader(dict(sample(name), schema=versioned(name, 3))), "older-format")
                self.assertEqual(str(older), pc_records.OLDER_FORMAT_MESSAGE)

    def test_container_records_need_integer_version(self):
        for kind in sorted(pc_records.CONTAINERS):
            with self.subTest(container=kind):
                self.assertEqual(pc_records.require_container({"schema_version": 1}, kind), {"schema_version": 1})
                for version in BAD_VERSIONS:
                    record = {} if version is MISSING else {"schema_version": version}
                    self.refused(lambda: pc_records.require_container(record, kind), "schema-version")
                self.refused(lambda: pc_records.require_container({"schema": "patchcairn.storage", "schema_version": 1}, kind), "schema-name")
        for relative, kind in (("templates/workflows.json", "workflows_template"), ("templates/tool-catalog.json", "tool_catalog"),
                               ("toolkit.json", "toolkit_marker")):
            with self.subTest(file=relative):
                record = pc_records.decode_strict((ROOT / relative).read_bytes())
                self.assertIs(pc_records.require_container(record, kind), record)
        root = fixture_root()
        marker = workflow_core.WorkflowEngine(root).work / "engine.json"
        original = pc_records.decode_strict(marker.read_bytes())
        for version in BAD_VERSIONS:
            changed = dict(original)
            if version is MISSING:
                del changed["schema_version"]
            else:
                changed["schema_version"] = version
            marker.write_bytes(pc_records.encoded(changed))
            with self.subTest(engine_marker=version if version is not MISSING else "missing"):
                self.refused(lambda: workflow_core.WorkflowEngine(root), "schema-version")

    def test_stored_session_state_and_creation_need_integer_version(self):
        engine = workflow_core.WorkflowEngine(fixture_root())
        sid = engine.create_session(checkpoints=[])["session_id"]
        for name in ("session.json", "creation.json"):
            path = engine.work / sid / name
            original = path.read_bytes()
            for version in BAD_VERSIONS:
                record = pc_records.decode_strict(original, max_bytes=workflow_core.JOURNAL_MAX_BYTES)
                target = record["state"] if name == "session.json" else record
                if version is MISSING:
                    del target["schema_version"]
                else:
                    target["schema_version"] = version
                path.write_bytes(pc_records.encoded(record))
                with self.subTest(record=name, version=version if version is not MISSING else "missing"):
                    self.refused(lambda: engine.read_session(sid), "schema-version")
            path.write_bytes(original)
        self.assertEqual(engine.read_session(sid)["session_id"], sid)

    def test_registry_fully_covered(self):
        self.assertEqual(set(pc_records.READERS), pc_records.SCHEMAS - pc_records.PLANNED_SCHEMAS)
        self.assertFalse(set(pc_records.READERS) & pc_records.PLANNED_SCHEMAS)
        names = [name for name, _ in readers()]
        for name, reader in readers():
            with self.subTest(family=name):
                self.assertTrue(callable(reader), name + " has no registered reader")
                self.assertTrue(reader.__module__.startswith(OWNER_PREFIXES), reader.__module__)
                for other in names:
                    if other != name:
                        self.refused(lambda: reader(sample(other)), "schema-name")
        engine_families = {name for name, reader in readers() if reader.__module__.startswith(("workflow_core", "engine_"))}
        self.assertEqual(engine_families, set(workflow_core.RECORD_FIELDS))
        self.assertIs(pc_records.READERS["patchcairn.storage"], storage_contract.read_storage)
        for name in sorted(engine_families):
            # The engine's typed_record and the registry give one answer for each family.
            for record in (sample(name), dict(sample(name), unexpected=True)):
                with self.subTest(engine_family=name, fields=sorted(record)):
                    outcomes = []
                    for read in (lambda: workflow_core.typed_record(record, name), lambda: pc_records.READERS[name](record)):
                        try:
                            outcomes.append(("accepted", read()))
                        except pc_records.Refusal as error:
                            outcomes.append(("refused", error.code))
                    self.assertEqual(outcomes[0], outcomes[1])
        kind_codes = {"patchcairn.storage": "storage-refusal", "patchcairn.diagnostics": "diagnostic-refusal",
                      "patchcairn.service": "service-refusal"}
        for name in SAMPLE_KINDS:
            with self.subTest(kinded_family=name):
                record = sample(name)
                self.assertIs(pc_records.READERS[name](record), record)
                self.refused(lambda: pc_records.READERS[name](dict(record, kind="unknown-kind")), kind_codes[name])

    def test_older_record_refused_with_clear_message(self):
        for name, reader in readers():
            older = {"schema_version": versioned(name, 3), "kind": SAMPLE_KINDS.get(name, "older")}
            with self.subTest(family=name):
                error = self.refused(lambda: reader(older), "older-format")
                self.assertEqual(str(error), pc_records.OLDER_FORMAT_MESSAGE)
        for kind in sorted(pc_records.CONTAINERS):
            with self.subTest(container=kind):
                error = self.refused(lambda: pc_records.require_container({"schema_version": "1.0"}, kind), "older-format")
                self.assertEqual(str(error), pc_records.OLDER_FORMAT_MESSAGE)
        root = fixture_root()
        marker = workflow_core.WorkflowEngine(root).work / "engine.json"
        older = dict(pc_records.decode_strict(marker.read_bytes()), schema_version=3, backend=versioned("patchcairn.workflow.python", 3))
        marker.write_bytes(pc_records.encoded(older))
        # The engine marker is read before every command, so its message names the folder and the next step.
        error = self.refused(lambda: workflow_core.WorkflowEngine(root), "older-format")
        self.assertEqual(str(error), "The folder " + "work/sessions" + " holds records in an older PatchCairn format, which cannot be read. "
                             "PatchCairn never changes or deletes them: keep that folder unchanged, move it aside to keep "
                             "its records, and then start a new session.")
        request = {"schema_version": versioned("patchcairn.diagnostics", 3), "kind": "request", "request_id": "diag-" + "0" * 32,
                   "platform": "macos", "recipe_id": "macos.os_version", "mode": "fixture", "symptom": "Fictional E42",
                   "scope": ["os_metadata"], "observed_utc": CLOCK}
        error = self.refused(lambda: diagnostic_core.validate_request(request), "older-format")
        self.assertEqual(str(error), pc_records.OLDER_FORMAT_MESSAGE)
        request = dict(request, schema=versioned("patchcairn.diagnostics", 3), schema_version=1)
        error = self.refused(lambda: diagnostic_core.validate_request(request), "older-format")
        self.assertEqual(str(error), pc_records.OLDER_FORMAT_MESSAGE)


class RefusalBaseTests(unittest.TestCase):
    def test_product_refusals_share_one_base_with_categorical_codes(self):
        import darwin_privacy
        import linux_privacy
        import scoped_base
        import scoped_fs
        cases = ((workflow_core.WorkflowRefusal, "workflow-refusal"), (workflow_core.PrivacyCapabilityHold, "private-storage-unavailable"),
                 (workflow_service.ServiceRefusal, "service-refusal"), (storage_ops.StorageRefusal, "storage-refusal"),
                 (diagnostic_core.DiagnosticRefusal, "diagnostic-refusal"))
        for cls, code in cases:
            with self.subTest(refusal=cls.__name__):
                error = cls("Fictional refusal text")
                self.assertIsInstance(error, pc_records.Refusal)
                self.assertIsInstance(error, ValueError)
                self.assertEqual((error.code, str(error)), (code, "Fictional refusal text"))
                self.assertEqual(cls("Fictional refusal text", code="fictional-code").code, "fictional-code")
        for cls in (linux_privacy.LinuxPrivacyHold, darwin_privacy.DarwinPrivacyHold):
            with self.subTest(refusal=cls.__name__):
                error = cls("fictional-hold-code")
                self.assertIsInstance(error, pc_records.Refusal)
                self.assertEqual((error.code, str(error)), ("fictional-hold-code", "fictional-hold-code"))
        self.assertIs(scoped_fs.ScopedFSError, scoped_base.ScopedFSError)
        self.assertIs(scoped_fs.CapabilityHold, scoped_base.CapabilityHold)
        self.assertTrue(issubclass(scoped_fs.ScopedFSError, pc_records.Refusal))

    def test_shared_check_refusals_keep_their_code_through_each_module(self):
        request = {"schema": "patchcairn.diagnostics", "schema_version": 1, "kind": "request", "request_id": "diag-" + "0" * 32,
                   "platform": "macos", "recipe_id": "macos.os_version", "mode": "fixture", "symptom": "Fictional E42",
                   "scope": ["os_metadata"], "observed_utc": "yesterday"}
        cases = ((lambda: workflow_core.typed_record({"schema": "patchcairn.external.plan", "schema_version": "1"}, "patchcairn.external.plan"),
                  workflow_core.WorkflowRefusal, "schema-version"),
                 (lambda: storage_ops.canonical({"text": "\ud800"}), storage_ops.StorageRefusal, "invalid-record"),
                 (lambda: diagnostic_core.validate_request(request), diagnostic_core.DiagnosticRefusal, "utc-time"))
        for call, cls, code in cases:
            with self.subTest(refusal=cls.__name__), self.assertRaises(cls) as caught:
                call()
            self.assertEqual(caught.exception.code, code)


class RecordLayoutTests(unittest.TestCase):
    """Golden bytes of the record layouts introduced here: "schema" names a registered family and
    "schema_version" is the integer 1 (containers carry only the integer), encoded by pc_records.encoded."""

    def engine(self):
        root, ids, real = fixture_root(), iter([uuid.UUID(int=0x1111), uuid.UUID(int=0x2222)]), uuid.uuid4
        with mock.patch("pc_records.utc_now", return_value=CLOCK), mock.patch("uuid.uuid4", side_effect=lambda: next(ids, None) or real()):
            engine = workflow_core.WorkflowEngine(root)
            session_id = engine.create_session(scope={"roots": ["fictional-root"], "purpose": "Fictional golden layout"}, checkpoints=[])["session_id"]
        return engine, session_id

    def test_engine_marker_creation_marker_and_session_state_layouts(self):
        engine, session_id = self.engine()
        self.assertEqual((engine.work / "engine.json").read_bytes(),
                         b'{"backend":"patchcairn.workflow.python","engine_id":"00000000000000000000000000001111","schema_version":1}')
        self.assertEqual((engine.work / session_id / "creation.json").read_bytes(),
                         b'{"backend":"patchcairn.workflow.python","created_utc":"2026-01-02T03:04:05.000006Z",'
                         b'"creation_scope_sha256":"e0d6f92dd37e983c0f1922a6ed8637ca225d64bb923ca76f270900a1dc157729",'
                         b'"engine_id":"00000000000000000000000000001111","job":"security_updates","mode":"fixture","owner_id":"owner",'
                         b'"platform":"unknown","schema_version":1,"session_id":"session-00000000000000000000000000002222"}')
        self.assertEqual(workflow_core.digest(engine.read_session(session_id)), "6309a1085c6eb83a9e1a9fea0c63c6d11e918a0200066e9716a048a26d704f42")

    def test_journal_events_keep_digests_of_changes(self):
        # D-017: a journal event names each changed field with the digest of its new value, never the value.
        engine, session_id = self.engine()
        with mock.patch("pc_records.utc_now", return_value=CLOCK):
            engine.pause(session_id)
        data = (engine.work / session_id / "session.json").read_bytes()
        self.assertIn(b'"details":{"changes":{"status":"d2f88d9c865e0709761ef96771df45593cc185ac902cfe3ecbb9578129edcf1c"},'
                      b'"settings_revision":0}', data)
        self.assertEqual(workflow_core.digest("paused"), "d2f88d9c865e0709761ef96771df45593cc185ac902cfe3ecbb9578129edcf1c")
        self.assertEqual(hashlib.sha256(data).hexdigest(), "281da1b6ce86e7d3e006ae4e1e7b071d6f771740640bd82fb4fa145247ca56fb")

    def test_storage_attempt_record_keeps_digest_plan_file_and_count(self):
        # D-017: the exact plan is a separate hash-bound file; the attempt record keeps its digest and entry count.
        with mock.patch("pc_records.utc_now", return_value=CLOCK):
            record = storage_ops.attempt_record("backup", "a" * 64, "plan-backup-" + "a" * 64 + ".json", {"files": [{}, {}, {}]})
        self.assertEqual(pc_records.encoded(record),
                         b'{"automatic_retry":false,"entry_count":3,"kind":"attempt","operation":"backup","plan_file":"plan-backup-' + b"a" * 64
                         + b'.json","plan_sha256":"' + b"a" * 64 + b'","schema":"patchcairn.storage","schema_version":1,'
                         b'"started_utc":"2026-01-02T03:04:05.000006Z","status":"attempted; inspect immutable step and outcome receipts before recovery"}')

    def test_service_marker_and_retention_registry_layouts(self):
        engine, _ = self.engine()
        with mock.patch("pc_records.utc_now", return_value=CLOCK):
            service = workflow_service.WorkflowService(engine)
        self.assertEqual((service.work / "service.json").read_bytes(),
                         b'{"backend":"patchcairn.workflow.python","engine_id":"00000000000000000000000000001111",'
                         b'"kind":"service_marker","schema":"patchcairn.service","schema_version":1}')
        self.assertEqual((service.work / "retention.json").read_bytes(),
                         b'{"entries":[],"kind":"retention_registry","schema":"patchcairn.service","schema_version":1}')

    def test_diagnostic_request_layout_has_no_trailing_newline(self):
        store = workflow_service.DiagnosticStore(fixture_root(), work_relative="work/d")
        with mock.patch("pc_records.utc_now", return_value=CLOCK), mock.patch("uuid.uuid4", return_value=uuid.UUID(int=0x3333)):
            receipt = store.create_request(platform="macos", recipe_id="macos.os_version", symptom="Fictional error E42", scope=["os_metadata"])
        data = (store.root / receipt["evidence"]["path"]).read_bytes()
        self.assertEqual(data, b'{"kind":"request","mode":"fixture","observed_utc":"2026-01-02T03:04:05.000006Z","platform":"macos",'
                               b'"recipe_id":"macos.os_version","request_id":"diag-00000000000000000000000000003333",'
                               b'"schema":"patchcairn.diagnostics","schema_version":1,"scope":["os_metadata"],"symptom":"Fictional error E42"}')
        self.assertEqual(receipt["record_id"], "request-337912fae0e90e8fae3a8eacbe3b4b26572ee272f922f6c4c5292d1923bc4dfe")
        self.assertEqual(hashlib.sha256(data).hexdigest(), receipt["record_id"].split("-", 1)[1])

    def test_storage_record_layout(self):
        with mock.patch("storage_ops.capabilities", return_value={"available": True, "adapter": "fictional-adapter"}):
            capabilities = storage_ops.storage_capabilities()
        self.assertEqual(storage_ops.canonical(capabilities),
                         b'{"cli_mutation_enabled":false,"filesystem":{"adapter":"fictional-adapter","available":true},"kind":"capabilities",'
                         b'"not_an_os_sandbox":true,"quiet_exclusive_workspace_required":true,"requires_workflow_engine_gate":true,'
                         b'"schema":"patchcairn.storage","schema_version":1,"zip_encryption":false}')
        self.assertIs(pc_records.READERS["patchcairn.storage"](capabilities), capabilities)


if __name__ == "__main__":
    unittest.main()
