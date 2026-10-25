"""pc_records: canonical JSON, strict decoding, schema registry, UTC clock, validators and adapter facts.

Run from the repository root: python3 -I -S -B -m unittest discover -s tests -p "test_records.py"
"""
from __future__ import annotations

import ast
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_records  # noqa: E402
from pc_records import Refusal  # noqa: E402


def versioned(name, number):
    """An older-style name, built at run time so no version label sits in the source."""
    return f"{name}.v{number}"


def legacy_encoded(value):
    """Frozen copy of workflow_core.encoded at 3512771 (scripts/workflow_core.py:81-82)."""
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


GOLDEN_SAMPLE = [
    None, True, False, 0, -1, 2 ** 63, -(2 ** 63), 10 ** 20 - 1, 1.5, -0.0, 1e-300, 1e300, 0.1, 3.0, 12345678901234567890.0,
    "", "plain", "quote \" backslash \\ slash /", "tab\tnewline\ncarriage\r", "\x00\x1f\x7f",
    "caf\u00e9", "\u65e5\u672c", "\U0001f600", "\u2028\u2029",
    [], {}, [1, [2, [3, []]]], ("tuple", "as", "list"),
    {"b": 1, "a": 2, "A": 3, "\u00e9": 4, "10": 5, "9": 6, "": 7, "\U0001f600": 8},
    {"schema": "patchcairn.storage", "schema_version": 1,
     "entries": [{"relative_path": "a/b.txt", "size": 12, "sha256": "0" * 64}, {"relative_path": "c", "size": 0}]},
    {"nested": {"z": [True, None, 1.25], "y": {"x": "\u00fc"}}},
]
# SHA-256 of b"\n".join(encoded(v) for v in GOLDEN_SAMPLE) (654 bytes), computed at 3512771 with
# workflow_core.encoded; storage_ops.canonical and diagnostic_core's encoder (without its newline) agree.
# The sample holds only values decode_strict reads back; the others are refused (see the next class).
GOLDEN_SHA256 = "6482d409e1a94b9ff4c8c769b3965a01d973faec61b947921984160fbd8d0ea2"


class CanonicalEncodingTests(unittest.TestCase):
    def test_encoded_matches_legacy_encoder_on_varied_sample(self):
        for value in GOLDEN_SAMPLE:
            with self.subTest(value=repr(value)[:40]):
                self.assertEqual(pc_records.encoded(value), legacy_encoded(value))

    def test_golden_bytes_are_pinned(self):
        joined = b"\n".join(pc_records.encoded(value) for value in GOLDEN_SAMPLE)
        self.assertEqual(hashlib.sha256(joined).hexdigest(), GOLDEN_SHA256)
        self.assertEqual(pc_records.encoded({"b": 1, "a": [True, None, 1.5]}), b'{"a":[true,null,1.5],"b":1}')
        self.assertEqual(pc_records.encoded("caf\u00e9 \U0001f600"), b'"caf\\u00e9 \\ud83d\\ude00"')

    def test_digest_hashes_bytes_directly_and_values_canonically(self):
        self.assertEqual(pc_records.digest(b"abc"), hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(pc_records.digest({"b": 1, "a": 2}), hashlib.sha256(b'{"a":2,"b":1}').hexdigest())

    def test_encoded_refuses_values_that_are_not_json(self):
        circular = []
        circular.append(circular)
        lone = chr(0xD800)
        for value in (float("nan"), float("inf"), {1, 2}, object(), circular, {"a": 1, 2: "b"}, {1: "x"}, {None: 1},
                      {True: 1}, lone, {lone: 1}, ["ok", {"k": "a" + lone}], 10 ** 20, [-(10 ** 20)]):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(Refusal) as caught:
                    pc_records.encoded(value)
                self.assertEqual(caught.exception.code, "invalid-record")


class StrictDecoderTests(unittest.TestCase):
    def refused(self, data, code, **limits):
        with self.assertRaises(Refusal) as caught:
            pc_records.decode_strict(data, **limits)
        self.assertEqual(caught.exception.code, code)

    def test_round_trip_of_canonical_bytes(self):
        value = GOLDEN_SAMPLE[-2]
        self.assertEqual(pc_records.decode_strict(pc_records.encoded(value)), value)
        self.assertEqual(pc_records.decode_strict(bytearray(b' {"a": [1, 2.5, "x"]} ')), {"a": [1, 2.5, "x"]})

    def test_default_limits(self):
        self.assertEqual(pc_records.DEFAULT_MAX_BYTES, 16_000_000)
        self.assertEqual(pc_records.DEFAULT_MAX_DEPTH, 64)
        self.assertEqual(pc_records.DEFAULT_MAX_ITEMS, pc_records.MAX_BACKUP_ENTRIES)

    def test_published_backup_entry_bound(self):
        bound = pc_records.MAX_BACKUP_ENTRIES
        self.assertIs(type(bound), int)
        self.assertTrue(50_000 <= bound <= 100_000)

    def test_refuses_byte_order_mark(self):
        self.refused(b"\xef\xbb\xbf{}", "json-bom")

    def test_refuses_duplicate_keys_at_any_depth(self):
        self.refused(b'{"a":1,"a":2}', "json-duplicate-key")
        self.refused(b'{"x":[{"k":1,"k":1}]}', "json-duplicate-key")
        self.assertEqual(pc_records.decode_strict(b'{"a":1,"A":2}'), {"a": 1, "A": 2})

    def test_refuses_nan_and_infinity(self):
        for text in (b"NaN", b"[Infinity]", b'{"a":-Infinity}', b"1e400", b"[-1e999]"):
            with self.subTest(text=text):
                self.refused(text, "json-nonfinite")

    def test_refuses_text_that_is_not_utf8(self):
        for data in (b'"\xff"', '{"a":1}'.encode("utf-16"), '{"a":1}'.encode("utf-16-le"), b'"\xed\xa0\x80"'):
            with self.subTest(data=data):
                with self.assertRaises(Refusal) as caught:
                    pc_records.decode_strict(data)
                self.assertIn(caught.exception.code, {"json-encoding", "json-invalid"})
        self.refused(b'"\xff"', "json-encoding")
        self.refused(b'"\\ud800"', "json-encoding")
        self.refused(b'{"\\udfff":1}', "json-encoding")
        self.assertEqual(pc_records.decode_strict(b'"\\ud83d\\ude00"'), "\U0001f600")

    def test_refuses_str_input(self):
        self.refused('{"a":1}', "json-type")

    def test_refuses_over_large_input(self):
        self.refused(b"[" + b"1," * 10 + b"1]", "json-too-large", max_bytes=10)
        self.assertEqual(pc_records.decode_strict(b"[1,2]", max_bytes=5), [1, 2])

    def test_refuses_over_deep_input(self):
        depth = pc_records.DEFAULT_MAX_DEPTH
        self.assertEqual(pc_records.decode_strict(b"[" * depth + b"]" * depth), json.loads("[" * depth + "]" * depth))
        self.refused(b"[" * (depth + 1) + b"]" * (depth + 1), "json-too-deep")
        self.refused(b'{"a":' * 3 + b"1" + b"}" * 3, "json-too-deep", max_depth=2)
        self.refused(b"[" * 200_000 + b"]" * 200_000, "json-too-deep", max_bytes=1_000_000)

    def test_refuses_too_many_entries_in_one_list_or_object(self):
        self.refused(b"[1,2,3]", "json-too-large", max_items=2)
        self.refused(b'{"a":1,"b":2,"c":3}', "json-too-large", max_items=2)
        self.assertEqual(pc_records.decode_strict(b"[[1,2],[3,4]]", max_items=2), [[1, 2], [3, 4]])

    def test_refuses_malformed_json(self):
        for data in (b"", b"{", b"{'a':1}", b"[1,]", b"1 2"):
            with self.subTest(data=data[:10]):
                self.refused(data, "json-invalid")

    def test_integers_are_bounded_to_twenty_digits(self):
        for text in (b"9" * 21, b"-" + b"1" * 21, b"[" + b"1" * 5000 + b"]"):
            with self.subTest(text=text[:12]):
                self.refused(text, "json-number")
        self.assertEqual(pc_records.decode_strict(b"9" * 20), 10 ** 20 - 1)
        self.assertEqual(pc_records.decode_strict(b"-" + b"9" * 20), -(10 ** 20 - 1))

    def test_total_values_are_bounded(self):
        self.assertEqual(pc_records.DEFAULT_MAX_NODES, 1_000_000)
        self.refused(b"[" + b",".join([b"{}"] * 50) + b"]", "json-too-large", max_nodes=40)
        self.refused(b"[" + b",".join([b"[]"] * 50) + b"]", "json-too-large", max_nodes=40)
        self.refused(b"[" + b",".join([b"1"] * 50) + b"]", "json-too-large", max_nodes=40)
        self.refused(b'{"a":[' + b",".join([b'"x"'] * 50) + b"]}", "json-too-large", max_nodes=40)
        self.assertEqual(len(pc_records.decode_strict(b"[" + b",".join([b"1"] * 39) + b"]", max_nodes=40)), 39)

    def test_limits_must_be_positive_integers(self):
        for limits in ({"max_bytes": 0}, {"max_depth": True}, {"max_items": 1.0}, {"max_nodes": -1}):
            with self.subTest(limits=limits):
                self.refused(b"{}", "invalid-limit", **limits)


def typed(name, **fields):
    return {"schema": name, "schema_version": 1, **fields}


class SchemaTests(unittest.TestCase):
    BAD_VERSIONS = (True, False, 1.0, "1", 0, 2, -1, None, [1], {"v": 1})

    def refused(self, call, code):
        with self.assertRaises(Refusal) as caught:
            call()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_schema_version_constant_is_the_integer_one(self):
        self.assertIs(type(pc_records.SCHEMA_VERSION), int)
        self.assertEqual(pc_records.SCHEMA_VERSION, 1)

    def test_every_registered_name_accepts_its_exact_record(self):
        for name in sorted(pc_records.SCHEMAS):
            with self.subTest(name=name):
                record = typed(name, kind="example")
                self.assertIs(pc_records.require_schema(record, name), record)

    def test_bad_schema_version_refused(self):
        for value in self.BAD_VERSIONS:
            with self.subTest(value=repr(value)):
                self.refused(lambda: pc_records.require_schema({"schema": "patchcairn.storage", "schema_version": value},
                                                               "patchcairn.storage"), "schema-version")
        self.refused(lambda: pc_records.require_schema({"schema": "patchcairn.storage"}, "patchcairn.storage"),
                     "schema-version")
        error = self.refused(lambda: pc_records.require_schema(typed("patchcairn.storage") | {"schema_version": 2},
                                                               "patchcairn.storage"), "schema-version")
        self.assertEqual(str(error), pc_records.UNSUPPORTED_VERSION_MESSAGE)

    def test_bad_schema_name_refused(self):
        for value in ("patchcairn.service", "PatchCairn.Storage", "patchcairn.storage ", 1, None, True, ["patchcairn.storage"]):
            with self.subTest(value=repr(value)):
                self.refused(lambda: pc_records.require_schema({"schema": value, "schema_version": 1}, "patchcairn.storage"),
                             "schema-name")
        self.refused(lambda: pc_records.require_schema({"schema_version": 1}, "patchcairn.storage"), "schema-name")

    def test_versioned_schema_name_refused_as_older_format(self):
        for value in (versioned("patchcairn.storage", 3), versioned("patchcairn.storage", 1), f"windows-powershell-v{2}",
                      f"posix-python_V{2}"):
            with self.subTest(value=value):
                self.refused(lambda: pc_records.require_schema({"schema": value, "schema_version": 1}, "patchcairn.storage"),
                             "older-format")

    def test_older_record_refused_with_clear_message(self):
        older = [
            {"schema": versioned("patchcairn.diagnostics", 3), "schema_version": 1},
            {"schema_version": versioned("patchcairn.storage", 3), "kind": "backup_receipt"},
            {"schema_version": versioned("patchcairn.assessment.access", 1), "target": "whole_device"},
            {"schema_version": "1.0", "run_id": "run-x"},
            # Today's engine marker (engine.json) and session state carry an integer 3 and a versioned backend.
            {"schema_version": 3, "backend": versioned("patchcairn.workflow.python", 3), "engine_id": "0" * 32},
            {"schema_version": 3, "session_id": "session-1", "backend": versioned("patchcairn.workflow.python", 3),
             "job": "storage_cleanup", "revision": 4},
        ]
        for record in older:
            with self.subTest(record=record):
                error = self.refused(lambda: pc_records.require_schema(record, "patchcairn.storage"), "older-format")
                self.assertEqual(str(error), pc_records.OLDER_FORMAT_MESSAGE)
                error = self.refused(lambda: pc_records.require_container(record, "session_state"), "older-format")
                self.assertEqual(str(error), pc_records.OLDER_FORMAT_MESSAGE)
        self.assertEqual(pc_records.OLDER_FORMAT_MESSAGE,
                         "This record uses an older PatchCairn format and cannot be read; start a new session.")

    def test_container_records_need_integer_version(self):
        record = {"schema_version": 1, "engine_id": "e1", "backend": "patchcairn.workflow.python"}
        self.assertIs(pc_records.require_container(record, "engine_marker"), record)
        for value in self.BAD_VERSIONS:
            with self.subTest(value=repr(value)):
                self.refused(lambda: pc_records.require_container({"schema_version": value}, "engine_marker"),
                             "schema-version")
        self.refused(lambda: pc_records.require_container({"engine_id": "e1"}, "engine_marker"), "schema-version")
        self.refused(lambda: pc_records.require_container({"schema": "patchcairn.service", "schema_version": 1},
                                                          "engine_marker"), "schema-name")
        for kind in ("engine.json", "patchcairn.service", "", None):
            with self.subTest(kind=kind):
                self.refused(lambda: pc_records.require_container(record, kind), "schema-unregistered")

    def test_unregistered_name_and_non_object_records_refused(self):
        for name in ("patchcairn.unknown", versioned("patchcairn.storage", 3), "patchcairn.public-site",
                     "patchcairn.storage.backup.receipt"):
            with self.subTest(name=name):
                self.refused(lambda: pc_records.require_schema(typed(name), name), "schema-unregistered")
        for value in ([], "record", None, 1):
            with self.subTest(value=repr(value)):
                self.refused(lambda: pc_records.require_schema(value, "patchcairn.storage"), "record-shape")
                self.refused(lambda: pc_records.require_container(value, "session_state"), "record-shape")

    def test_registry_names_are_unversioned_and_namespaced(self):
        label = re.compile(r"[._-]v[0-9]+\b|\bv[0-9]+\b", re.IGNORECASE)
        for name in pc_records.SCHEMAS:
            with self.subTest(name=name):
                self.assertRegex(name, r"\Apatchcairn\.[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*\Z")
                self.assertIsNone(label.search(name))
        for name in pc_records.CONTAINERS:
            self.assertRegex(name, r"\A[a-z][a-z_]*\Z")
        self.assertFalse(pc_records.SCHEMAS & pc_records.CONTAINERS)

    def test_todays_records_and_planned_families_are_registered(self):
        today = {"patchcairn.storage", "patchcairn.storage.adapter", "patchcairn.service", "patchcairn.diagnostics",
                 "patchcairn.diagnostic.adapter", "patchcairn.fixture.adapter", "patchcairn.quarantine.reservation",
                 "patchcairn.quarantine.recovery", "patchcairn.recovery.retention", "patchcairn.recovery.binding",
                 "patchcairn.assessment.access", "patchcairn.assessment.summary", "patchcairn.assessment.verification",
                 "patchcairn.restart.pending", "patchcairn.restart.verification", "patchcairn.windows.boot.observation"}
        self.assertLessEqual(today, pc_records.SCHEMAS - pc_records.PLANNED_SCHEMAS)
        self.assertEqual(pc_records.PLANNED_SCHEMAS, {"patchcairn.package", "patchcairn.schedule", "patchcairn.report"})
        self.assertEqual(pc_records.CONTAINERS, {"engine_marker", "session_state", "session_creation",
                                                 "response_envelope", "workflows_template", "tool_catalog", "toolkit_marker"})
        # One name per family: new storage records are kinds of patchcairn.storage, so no second name may
        # describe the same receipt; there is no schedule-policy record; the site manifest is not a product record.
        self.assertEqual([name for name in pc_records.SCHEMAS if name.startswith("patchcairn.storage.")],
                         ["patchcairn.storage.adapter"])
        self.assertFalse([name for name in pc_records.SCHEMAS if "polic" in name or "site" in name])

    def test_registry_fully_covered(self):
        self.assertLessEqual(pc_records.PLANNED_SCHEMAS, pc_records.SCHEMAS)
        self.assertEqual(set(pc_records.READERS), pc_records.SCHEMAS - pc_records.PLANNED_SCHEMAS)
        self.assertTrue(all(reader is None or callable(reader) for reader in pc_records.READERS.values()))

    def test_readers_register_once_and_never_for_planned_names(self):
        def reader(record):
            return pc_records.require_schema(record, "patchcairn.storage")

        with mock.patch.dict(pc_records.READERS):
            self.assertIs(pc_records.register_reader("patchcairn.storage", reader), reader)
            self.assertIs(pc_records.register_reader("patchcairn.storage", reader), reader)
            self.assertIs(pc_records.READERS["patchcairn.storage"], reader)
            for name, candidate, code in (("patchcairn.storage", len, "reader-registered"),
                                          ("patchcairn.report", len, "schema-planned"),
                                          ("patchcairn.unknown", len, "schema-unregistered"),
                                          ("patchcairn.service", "not callable", "invalid-reader")):
                with self.subTest(name=name):
                    self.refused(lambda: pc_records.register_reader(name, candidate), code)
            self.assertNotIn("patchcairn.report", pc_records.READERS)


class TimeTests(unittest.TestCase):
    def test_utc_now_has_microseconds_and_z(self):
        now = pc_records.utc_now()
        self.assertRegex(now, r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z\Z")
        self.assertEqual(pc_records.parse_utc(now).utcoffset(), timedelta(0))

    def test_parse_utc_refuses_anything_but_explicit_utc(self):
        for text in ("2026-10-25T00:00:00", "2026-10-25T00:00:00+00:00", "2026-10-25T00:00:00+01:00Z",
                     "2026-10-25Z", "yesterdayZ", "Z", "", None, 1, "2026-10-25T00:00:00." + "0" * 60 + "Z",
                     "2026-W43-7T00:00:00Z", "20261025T000000Z", "2026-10-25 00:00:00Z", "2026-10-25T00Z",
                     "2026-10-25T00:00:00,123Z", "2026-10-25T00:00:00.1234567Z", "2026-02-30T12:34:56Z",
                     "2026-10-25T24:00:00Z", "2026-10-25t00:00:00z"):
            with self.subTest(text=text):
                with self.assertRaises(Refusal) as caught:
                    pc_records.parse_utc(text)
                self.assertEqual(caught.exception.code, "utc-time")
        self.assertEqual(pc_records.parse_utc("2026-10-25T01:02:03Z").hour, 1)
        self.assertEqual(pc_records.parse_utc("2026-10-25T01:02:03.5Z").microsecond, 500000)
        self.assertEqual(pc_records.parse_utc("2026-10-25T01:02:03.000123Z").microsecond, 123)

    def at(self, base, seconds):
        return (pc_records.parse_utc(base) + timedelta(seconds=seconds)).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def accepted(self, observed, **limits):
        try:
            return pc_records.fresh(observed, **limits)
        except Refusal as error:
            self.fail("fresh evidence was refused: " + str(error))

    def test_small_backward_clock_step_is_not_refused(self):
        observed = pc_records.utc_now()
        # The clock steps back 1.5 s after the evidence was recorded.
        with mock.patch.object(pc_records, "utc_now", return_value=self.at(observed, -1.5)):
            self.assertEqual(self.accepted(observed, seconds=900), pc_records.parse_utc(observed))
        with mock.patch.object(pc_records, "utc_now", return_value=self.at(observed, -2.5)):
            with self.assertRaises(Refusal) as caught:
                pc_records.fresh(observed, seconds=900)
            self.assertEqual(caught.exception.code, "stale-evidence")
            self.assertEqual(self.accepted(observed, seconds=900, future_skew=3), pc_records.parse_utc(observed))
        self.assertEqual(pc_records.FUTURE_SKEW_SECONDS, 2.0)

    def test_ordering_against_a_decision_keeps_no_tolerance(self):
        decision = pc_records.utc_now()
        with mock.patch.object(pc_records, "utc_now", return_value=self.at(decision, 5)):
            self.accepted(decision, after=decision, seconds=900)
            self.accepted(self.at(decision, 0.000001), after=decision, seconds=900)
            for earlier in (-0.000001, -1.0):
                with self.subTest(earlier=earlier):
                    with self.assertRaises(Refusal) as caught:
                        pc_records.fresh(self.at(decision, earlier), after=decision, seconds=900)
                    self.assertEqual(caught.exception.code, "evidence-order")

    def test_stale_evidence_refused(self):
        observed = pc_records.utc_now()
        with mock.patch.object(pc_records, "utc_now", return_value=self.at(observed, 901)):
            with self.assertRaises(Refusal) as caught:
                pc_records.fresh(observed, seconds=900)
            self.assertEqual(caught.exception.code, "stale-evidence")
            pc_records.fresh(observed, seconds=902)

    def test_freshness_limits_are_validated(self):
        now = pc_records.utc_now()
        for limits in ({"seconds": 0}, {"seconds": True}, {"seconds": -1}, {"seconds": float("nan")},
                       {"seconds": "900"}, {"seconds": 1e300}, {"seconds": 900, "future_skew": -1},
                       {"seconds": 900, "future_skew": None}):
            with self.subTest(limits=limits):
                with self.assertRaises(Refusal) as caught:
                    pc_records.fresh(now, **limits)
                self.assertEqual(caught.exception.code, "invalid-limit")
        with self.assertRaises(Refusal):
            pc_records.fresh(now, after="", seconds=900)


class ValidatorTests(unittest.TestCase):
    def test_identifier(self):
        for value in ("a", "A.b-c_9", "x" * 96, "session-0f3a"):
            self.assertEqual(pc_records.identifier(value), value)
        for value in ("", ".hidden", "-x", "a/b", "a\\b", "a b", "x" * 97, "caf\u00e9", None, 7, "a\n"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(Refusal) as caught:
                    pc_records.identifier(value, "session identifier")
                self.assertEqual(caught.exception.code, "invalid-identifier")
                self.assertIn("session identifier", str(caught.exception))

    def test_sha256_hex(self):
        self.assertEqual(pc_records.sha256_hex("a" * 64), "a" * 64)
        for value in ("A" * 64, "a" * 63, "a" * 65, "g" * 64, None, "a" * 64 + "\n"):
            with self.subTest(value=repr(value)), self.assertRaises(Refusal):
                pc_records.sha256_hex(value)

    def test_bounded_text(self):
        self.assertEqual(pc_records.bounded_text("line\n\ttab"), "line\n\ttab")
        self.assertEqual(pc_records.bounded_text("x" * 10, limit=10), "x" * 10)
        for value, limit in (("", 10), ("   \n", 10), ("x" * 11, 10), ("bell\x07", 10), ("cr\r", 10), (None, 10)):
            with self.subTest(value=repr(value)):
                with self.assertRaises(Refusal) as caught:
                    pc_records.bounded_text(value, "owner quote", limit)
                self.assertEqual(caught.exception.code, "invalid-text")

    def test_refusal_is_a_categorical_value_error(self):
        error = Refusal("older-format", "message text")
        self.assertIsInstance(error, ValueError)
        self.assertEqual((error.code, str(error)), ("older-format", "message text"))
        self.assertEqual(str(Refusal("bare-code")), "bare-code")


TODAY_ADAPTER_KINDS = {
    # workflow_core.ADAPTERS at 3512771 (scripts/workflow_core.py:44), each id under its new name.
    "storage.backup_create": ("backup_create",), "storage.restore": ("backup_restore",),
    "storage.quarantine": ("cleanup_quarantine",), "storage.quarantine_restore": ("backup_restore",),
    "storage.purge": ("permanent_purge",), "fixture.assessment": ("assessment",),
    "diagnostic.collect": ("assessment",), "system.reviewed_external": ("update", "repair"),
}
FACT_KEYS = {"family", "kinds", "acknowledgments", "conditional_acknowledgments", "backup_receipt",
             "policy_coverable", "scheduled_policy_coverable", "os_consent", "irreversible", "transitional"}
BOOLEAN_FACTS = {"policy_coverable", "scheduled_policy_coverable", "irreversible", "transitional"}


def with_fact(name, value=True):
    return {key for key, facts in pc_records.ADAPTERS.items() if facts[name] == value}


class AdapterFactsTests(unittest.TestCase):
    def test_closed_adapter_set(self):
        ids = {"storage.backup_create", "storage.restore", "storage.quarantine", "storage.quarantine_restore",
               "storage.purge", "storage.remove_originals", "storage.retention_release", "storage.retention_forget",
               "storage.session_release", "package.upgrade", "package.reinstall", "system.repair", "diagnostic.collect",
               "fixture.assessment", "system.reviewed_external"}
        self.assertEqual(set(pc_records.ADAPTERS), ids)
        self.assertEqual(with_fact("transitional"), {"system.reviewed_external"})

    def test_todays_adapters_keep_their_kinds(self):
        for adapter_id, kinds in TODAY_ADAPTER_KINDS.items():
            with self.subTest(adapter_id=adapter_id):
                self.assertEqual(pc_records.ADAPTERS[adapter_id]["kinds"], kinds)

    def test_ids_and_families(self):
        families = {"storage.backup_create": "backup", "storage.restore": "restore", "storage.quarantine": "cleanup",
                    "storage.quarantine_restore": "restore", "storage.purge": "cleanup", "storage.remove_originals": "cleanup",
                    "storage.retention_release": "retention", "storage.retention_forget": "retention",
                    "storage.session_release": "retention", "package.upgrade": "update", "package.reinstall": "repair",
                    "system.repair": "repair", "diagnostic.collect": "assessment", "fixture.assessment": "assessment",
                    "system.reviewed_external": "update"}
        self.assertEqual({key: facts["family"] for key, facts in pc_records.ADAPTERS.items()}, families)
        self.assertLessEqual(set(families.values()), pc_records.FAMILIES)
        for adapter_id in pc_records.ADAPTERS:
            with self.subTest(adapter_id=adapter_id):
                self.assertRegex(adapter_id, r"\A[a-z]+(?:\.[a-z_]+)+\Z")

    def test_every_facts_record_is_complete_and_typed(self):
        for adapter_id, facts in pc_records.ADAPTERS.items():
            with self.subTest(adapter_id=adapter_id):
                self.assertEqual(set(facts), FACT_KEYS)
                self.assertTrue(facts["kinds"] and all(type(kind) is str for kind in facts["kinds"]))
                for key in ("kinds", "acknowledgments", "conditional_acknowledgments"):
                    self.assertIs(type(facts[key]), tuple)
                for key in ("acknowledgments", "conditional_acknowledgments"):
                    self.assertLessEqual(set(facts[key]), pc_records.ACKNOWLEDGMENTS)
                self.assertFalse(set(facts["acknowledgments"]) & set(facts["conditional_acknowledgments"]))
                for key in BOOLEAN_FACTS:
                    self.assertIs(type(facts[key]), bool)
                self.assertIn(facts["os_consent"], pc_records.OS_CONSENT)
                self.assertIn(facts["backup_receipt"], pc_records.BACKUP_RECEIPT)

    def test_facts_cannot_be_changed_at_run_time(self):
        with self.assertRaises(TypeError):
            pc_records.ADAPTERS["storage.purge"]["irreversible"] = False
        with self.assertRaises(TypeError):
            pc_records.ADAPTERS["storage.extra"] = {}
        self.assertTrue(pc_records.ADAPTERS["storage.purge"]["irreversible"])

    def test_acknowledgments_match_the_plan(self):
        acknowledgments = {key: facts["acknowledgments"] for key, facts in pc_records.ADAPTERS.items() if facts["acknowledgments"]}
        self.assertEqual(acknowledgments, {"storage.purge": ("permanent_data_loss",),
                                           "storage.remove_originals": ("permanent_data_loss",),
                                           "storage.retention_release": ("permanent_data_loss",),
                                           "storage.session_release": ("permanent_data_loss",),
                                           "system.repair": ("no_component_rollback",)})
        conditional = {key: facts["conditional_acknowledgments"] for key, facts in pc_records.ADAPTERS.items()
                       if facts["conditional_acknowledgments"]}
        self.assertEqual(conditional, {"storage.backup_create": ("non_private_destination",)})

    def test_irreversible_actions_need_an_acknowledgment_and_no_policy_covers_them(self):
        self.assertEqual(with_fact("irreversible"), {"storage.purge", "storage.remove_originals", "storage.retention_release",
                                                     "storage.session_release", "system.repair"})
        for adapter_id in with_fact("irreversible"):
            with self.subTest(adapter_id=adapter_id):
                facts = pc_records.ADAPTERS[adapter_id]
                self.assertTrue(facts["acknowledgments"])
                self.assertFalse(facts["policy_coverable"] or facts["scheduled_policy_coverable"])
        forget = pc_records.ADAPTERS["storage.retention_forget"]
        self.assertEqual((forget["acknowledgments"], forget["irreversible"], forget["policy_coverable"]), ((), False, False))

    def test_policy_coverage_follows_todays_policy_kinds(self):
        policy_kinds = {"update", "cleanup_quarantine", "backup_create"}  # workflow_core.POLICY_KINDS at 3512771
        self.assertEqual(with_fact("policy_coverable"), {"storage.backup_create", "storage.quarantine", "package.upgrade"})
        for adapter_id in with_fact("policy_coverable"):
            self.assertLessEqual(set(pc_records.ADAPTERS[adapter_id]["kinds"]), policy_kinds)
        # A fired scheduled run never acts on an update; it stops at before_action.
        self.assertEqual(with_fact("scheduled_policy_coverable"), {"storage.backup_create", "storage.quarantine"})
        self.assertLessEqual(with_fact("scheduled_policy_coverable"), with_fact("policy_coverable"))

    def test_backup_receipts_and_os_consent(self):
        self.assertEqual(with_fact("backup_receipt", "required"), {"storage.restore", "storage.remove_originals"})
        self.assertEqual(with_fact("backup_receipt", "optional"), {"storage.quarantine", "storage.purge"})
        self.assertEqual(with_fact("os_consent", "always"), {"system.repair", "system.reviewed_external"})
        self.assertEqual(with_fact("os_consent", "per_route"), {"package.upgrade", "package.reinstall"})

    def test_actions_must_match_the_os_consent_fact(self):
        for adapter_id, facts in pc_records.ADAPTERS.items():
            with self.subTest(adapter_id=adapter_id):
                allowed = {"always": {True}, "per_route": {True, False}, "never": {False}}[facts["os_consent"]]
                for flag in (True, False):
                    if flag in allowed:
                        self.assertIs(pc_records.adapter_facts(adapter_id, requires_os_consent=flag), facts)
                    else:
                        with self.assertRaises(Refusal) as caught:
                            pc_records.adapter_facts(adapter_id, requires_os_consent=flag)
                        self.assertEqual(caught.exception.code, "os-consent")
        for adapter_id, flag, code in (("storage.unknown", False, "unknown-adapter"), (None, False, "unknown-adapter"),
                                       ("package.upgrade", 1, "os-consent"), ("package.upgrade", None, "os-consent")):
            with self.subTest(adapter_id=adapter_id, flag=flag):
                with self.assertRaises(Refusal) as caught:
                    pc_records.adapter_facts(adapter_id, requires_os_consent=flag)
                self.assertEqual(caught.exception.code, code)

    def test_named_constants_cover_the_registry(self):
        constants = {value for name, value in vars(pc_records).items() if name.startswith("ADAPTER_")}
        self.assertEqual(constants, set(pc_records.ADAPTERS))


class ModuleLayerTests(unittest.TestCase):
    def test_imports_standard_library_only(self):
        tree = ast.parse((ROOT / "scripts" / "pc_records.py").read_text(encoding="utf-8"))
        imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertLessEqual(imported, {"__future__", "datetime", "hashlib", "json", "math", "re", "types"})


if __name__ == "__main__":
    unittest.main()
