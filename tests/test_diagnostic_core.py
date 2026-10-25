"""Fictional diagnostic records only; all fixtures remain in owned work/."""
from __future__ import annotations
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from diagnostic_core import DiagnosticRefusal, sanitize_text, validate_adapter_result
from workflow_service import DiagnosticStore
import pc_records
from clock_helpers import start_forward_only_clock, utc_now
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, write_private_new

PRIVATE_CAPABILITY_HOLDS = frozenset({
    "private-owner-or-mode-refused", "private-darwin-acl-capability-unavailable", "private-platform-unavailable",
    "private-linux-foreign-filesystem", "private-linux-abi-unavailable", "private-linux-libc-unavailable", "private-linux-descriptor-unavailable",
})


class DiagnosticCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Capability probe only; a missing capability skips each test with a tagged reason (D-023).
        cls.private_hold = None
        if os.name == "posix":
            probe = ROOT / "work" / ("dc-probe-" + uuid.uuid4().hex)
            try:
                ensure_private_directory(probe, create=True, parents=True)
            except PrivateWorkspaceError as exc:
                if exc.code not in PRIVATE_CAPABILITY_HOLDS:
                    raise
                cls.private_hold = exc.code

    def setUp(self):
        if self.private_hold:
            self.skipTest("only on posix: the selected filesystem cannot enforce new owner-only private namespaces: " + self.private_hold)
        start_forward_only_clock(self)
        self.root = ROOT / "work" / ("dc-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.store = DiagnosticStore(self.root)
        self.receipt = self.store.create_request(platform="macos", recipe_id="macos.os_version",
                    symptom="Fictional application could not start.", scope=["os_metadata"])
        self.request = self.receipt["record"]
        self.id = self.request["request_id"]

    def adapter(self, **changes):
        result = {key: self.request[key] for key in ("schema", "schema_version", "request_id", "platform", "recipe_id", "mode")}
        result.update(kind="adapter_result", status="observed", observed_utc=utc_now(), facts={"product_version": "15.1"},
                      limitations=["Fictional version evidence; application behavior unknown."],
                      provenance=["https://support.apple.com/en-us/109033"])
        result.update(changes)
        return result

    def result(self):
        return self.store.record_result(self.id, adapter_result=self.adapter())

    def test_receipt_binds_exact_owned_bytes_and_deep_copy(self):
        ref = self.receipt["evidence"]
        data = (self.root / ref["path"]).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), ref["sha256"])
        self.assertEqual(self.store.evidence_bytes(self.id, self.receipt["record_id"]), data)
        self.assertEqual(self.store.evidence_ref(self.id, self.receipt["record_id"]), ref)
        self.request["symptom"] = "Altered caller data"
        self.assertEqual(self.store.read_request(self.id)["symptom"], "Fictional application could not start.")

    def test_immutable_record_cannot_be_replaced(self):
        record = self.result()
        with self.assertRaises(DiagnosticRefusal):
            self.store._write(record["record"], "result")
        path = self.root / record["evidence"]["path"]
        pretty = json.dumps(record["record"], indent=2).encode()
        noncanonical = path.with_name("result-" + hashlib.sha256(pretty).hexdigest() + ".json")
        write_private_new(noncanonical, pretty)
        with self.assertRaisesRegex(DiagnosticRefusal, "Noncanonical"):
            self.store.read_record(self.id, noncanonical.stem)
        path.write_bytes(path.read_bytes().replace(b"15.1", b"99.9"))
        with self.assertRaisesRegex(DiagnosticRefusal, "hash mismatch"):
            self.store.read_record(self.id, record["record_id"])

    def test_no_recreate_missing_or_ambiguous_request(self):
        with self.assertRaises(FileNotFoundError):
            self.store.read_request("diag-" + "0" * 32)
        first = self.root / self.receipt["evidence"]["path"]
        duplicate = first.with_name("request-" + "0" * 64 + ".json")
        duplicate.write_bytes(first.read_bytes())
        with self.assertRaisesRegex(DiagnosticRefusal, "ambiguous"):
            self.store.read_request(self.id)

    def test_untrusted_identifiers_and_traversal_refused_before_read(self):
        for value in ("../outside", "diag-" + "0" * 32 + "/secret", "$(malicious)", "C:\\private"):
            with self.subTest(value=value), mock.patch("service_diagnostics.os.open") as opened:
                with self.assertRaises(DiagnosticRefusal):
                    self.store.read_request(value)
                opened.assert_not_called()
        with self.assertRaises(DiagnosticRefusal):
            self.store.read_record(self.id, "../request")
        for path in ("work/../escape", "work\\escape", "work/con", "/work/escape"):
            with self.assertRaises(DiagnosticRefusal):
                DiagnosticStore(self.root, work_relative=path)
        with self.assertRaises(DiagnosticRefusal):
            DiagnosticStore(self.root / ".." / ".." / ".." / ".." / "..")
        with self.assertRaises(DiagnosticRefusal):
            DiagnosticStore(ROOT.parent)

    def test_fixture_cannot_promote_to_real_or_change_recipe_platform(self):
        with self.assertRaises(DiagnosticRefusal):
            self.store.create_request(platform="macos", recipe_id="macos.os_version", symptom="Example", scope=["os_metadata"], mode="real")
        with self.assertRaises(DiagnosticRefusal):
            self.store.create_request(platform="linux", recipe_id="macos.os_version", symptom="Example", scope=[])
        for changes in ({"mode": "real"}, {"request_id": "diag-" + "0" * 32}, {"recipe_id": "sh"}, {"command": "malicious"}):
            with self.assertRaises(DiagnosticRefusal):
                self.store.record_result(self.id, adapter_result=self.adapter(**changes))

    def test_credential_input_never_persisted(self):
        samples = ["error password: fictional-value", "Authorization: Basic fictional-encoded-value", "Bearer example-value",
                   "api_key=fictional-value", "-----BEGIN PRIVATE KEY-----\nexample-body\n-----END PRIVATE KEY-----",
                   "https://example.invalid/error?key=fictional-value", "a" * 48, "session_id: example", "_auth=fictional-value", "AKIA" + "X" * 16]
        for text in samples:
            with self.subTest(text=text):
                receipt = self.store.record_excerpt(self.id, excerpt=text)
                persisted = self.store.evidence_bytes(self.id, receipt["record_id"]).decode()
                self.assertNotIn(text, persisted)
                self.assertIn("REDACTED", persisted)
                self.assertNotIn("fictional-value", persisted)

    def test_selected_error_survives_and_paths_addresses_are_suppressed(self):
        result = self.store.record_excerpt(self.id, excerpt="Error E42 while opening C:\\Users\\Example\\doc and /Users/example/doc for person@example.invalid")
        text = result["record"]["text"]
        self.assertIn("Error E42", text)
        for value in ("C:\\Users", "/Users/example", "person@example.invalid"):
            self.assertNotIn(value, text)
        self.assertFalse(hasattr(self.store, "read_log"))
        self.assertFalse(hasattr(self.store, "record_log_file"))

    def test_bounded_input_control_characters_and_command_keys(self):
        for text in ("x" * 4097, "line\n" * 34, "E42\x1b[31m", "E42\u202ehidden"):
            with self.assertRaises(DiagnosticRefusal):
                self.store.record_excerpt(self.id, excerpt=text)
        for scope in (["../escape"], ["x;echo"], ["os_metadata", "os_metadata"], ["x"] * 17):
            with self.assertRaises(DiagnosticRefusal):
                self.store.create_request(platform="macos", recipe_id="macos.os_version", symptom="E42", scope=scope)
        with self.assertRaises(DiagnosticRefusal):
            self.store.record_result(self.id, adapter_result=self.adapter(facts={"product_version": "15.1", "command": "echo"}))

    def test_typed_facts_and_unavailable_state(self):
        for facts in ({"product_version": "15.1;echo"}, {"product_version": 15}, {"hostname": "example"}):
            with self.assertRaises(DiagnosticRefusal):
                self.store.record_result(self.id, adapter_result=self.adapter(facts=facts))
        with self.assertRaises(DiagnosticRefusal):
            self.store.record_result(self.id, adapter_result=self.adapter(status="held"))
        held = self.store.record_result(self.id, adapter_result=self.adapter(status="held", facts={}))
        self.assertEqual(held["record"]["status"], "held")
        for changes in ({"provenance": ["https://example.invalid/run"]}, {"provenance": ["https://support.apple.com/?secret=value"]}, {"limitations": []}, {"observed_utc": "2099-01-01T00:00:00Z"}):
            with self.assertRaises(DiagnosticRefusal):
                self.store.record_result(self.id, adapter_result=self.adapter(**changes))

    def test_windows_fact_projection_contract(self):
        cases = [
            ("windows.os_version", {"version": "10.0.12345", "build": "12345", "architecture": "arm64"}),
            ("windows.system_capacity", {"total_bytes": 1000, "available_bytes": 200}),
            ("windows.update_context", {"updates": [{"kb_id": "KB12345", "installed_utc": None}]}),
            ("windows.system_event_metadata", {"events": [{"event_id": 41, "provider": "Microsoft-Windows-Kernel-Power", "level": 1, "observed_utc": "2026-01-01T00:00:00Z"}]}),
            ("windows.update_event_metadata", {"events": []}),
        ]
        for recipe, facts in cases:
            request = self.store.create_request(platform="windows", recipe_id=recipe, symptom="Fictional error", scope=[])["record"]
            result = self.adapter()
            for key in ("request_id", "platform", "recipe_id"):
                result[key] = request[key]
            result.update(facts=facts, observed_utc=utc_now(), provenance=["https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent"])
            self.assertEqual(validate_adapter_result(request, result)["facts"], facts)
            bad = copy.deepcopy(result)
            bad["facts"]["Message"] = "Potential private payload"
            with self.assertRaises(DiagnosticRefusal):
                validate_adapter_result(request, bad)

    def test_result_time_tolerates_a_small_clock_step_but_not_a_future_date(self):
        # WSL2 and NTP can step the clock back between two reads (#80); pc_records' tolerance applies.
        request = self.store.create_request(platform="windows", recipe_id="windows.update_event_metadata", symptom="Fictional error", scope=[])["record"]
        result = self.adapter()
        for key in ("request_id", "platform", "recipe_id"):
            result[key] = request[key]
        now = datetime.now(timezone.utc)
        result.update(facts={"events": []}, provenance=["https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent"])
        clock = (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        for ahead, accepted in ((0.5, True), (5, False)):
            result["observed_utc"] = (now + timedelta(seconds=ahead)).isoformat().replace("+00:00", "Z")
            with self.subTest(ahead=ahead), mock.patch("pc_records.utc_now", return_value=clock):
                if accepted:
                    self.assertEqual(validate_adapter_result(request, result)["facts"], {"events": []})
                else:
                    with self.assertRaises(DiagnosticRefusal):
                        validate_adapter_result(request, result)

    def test_result_before_its_request_is_a_clock_step_or_refused(self):
        # D-056: ordering keeps no tolerance; a gap within pc_records' future-skew bound is reported as a clock step.
        request = self.store.create_request(platform="windows", recipe_id="windows.update_event_metadata", symptom="Fictional error", scope=[])["record"]
        result = self.adapter()
        for key in ("request_id", "platform", "recipe_id"):
            result[key] = request[key]
        result.update(facts={"events": []}, provenance=["https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent"])
        requested = datetime.fromisoformat(request["observed_utc"].replace("Z", "+00:00"))
        for seconds, code in ((1, "clock-step"), (pc_records.FUTURE_SKEW_SECONDS + 5, "diagnostic-refusal")):
            result["observed_utc"] = (requested - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            with self.subTest(seconds=seconds), self.assertRaises(DiagnosticRefusal) as caught:
                validate_adapter_result(request, result)
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), "Result must fall between request and current UTC")

    def hypothesis(self, evidence_ids=None):
        return {"hypothesis_id": "version-context", "statement": "Version mismatch may explain the error.",
                "mechanism": "Unknown until behavior is checked.", "original_cause": "Unknown.",
                "confidence": "low", "outcome": "unknown", "evidence_ids": evidence_ids or [],
                "counterevidence_ids": [], "next_check": "Compare the original behavior with official support guidance."}

    def test_hypotheses_keep_unknown_and_counterevidence_bound(self):
        observed = self.result()
        hypothesis = self.hypothesis([observed["record_id"]])
        hypothesis["counterevidence_ids"] = [observed["record_id"]]
        saved = self.store.record_hypotheses(self.id, hypotheses=[hypothesis], unknowns=["Original cause remains unknown."])
        self.assertEqual(saved["record"]["hypotheses"][0]["original_cause"], "Unknown.")
        with self.assertRaises(DiagnosticRefusal):
            self.store.record_hypotheses(self.id, hypotheses=[self.hypothesis()], unknowns=[])
        hypothesis = self.hypothesis()
        hypothesis["outcome"] = "supported"
        with self.assertRaises(DiagnosticRefusal):
            self.store.record_hypotheses(self.id, hypotheses=[hypothesis], unknowns=["Cause unknown"])
        hypothesis = self.hypothesis([self.receipt["record_id"]])
        with self.assertRaises(DiagnosticRefusal):
            self.store.record_hypotheses(self.id, hypotheses=[hypothesis], unknowns=["Cause unknown"])

    def test_verification_freshness_binding_and_actual_observation(self):
        before = self.result()
        completed = utc_now()
        fields = dict(action_id="repair-example", plan_sha256="a" * 64, action_completed_utc=completed,
                      original_success_condition="Original application opens the selected example file.", outcome="passed",
                      observation="Owner reports the original example operation succeeded.")
        with self.assertRaises(DiagnosticRefusal):
            self.store.record_verification(self.id, result_ids=[before["record_id"]], **fields)
        with self.assertRaises(DiagnosticRefusal):
            self.store.record_verification(self.id, result_ids=[], **fields)
        after = self.store.record_excerpt(self.id, excerpt="The fictional original operation now succeeds.")
        receipt = self.store.record_verification(self.id, result_ids=[after["record_id"]], **fields)
        self.assertEqual(receipt["record"]["plan_sha256"], fields["plan_sha256"])
        self.assertIn("original cause", receipt["record"]["limitation"])
        held = self.store.record_result(self.id, adapter_result=self.adapter(status="held", facts={}))
        with self.assertRaises(DiagnosticRefusal):
            self.store.record_verification(self.id, result_ids=[held["record_id"]], **fields)

    def test_hardlinks_refused_before_open(self):
        path = self.root / self.receipt["evidence"]["path"]
        extra = path.with_name("fictional-hardlink.json")
        os.link(path, extra)
        # Keep native namespace admission's descriptor capability checks intact.
        with mock.patch("service_diagnostics.os", wraps=os) as diagnostic_os:
            with self.assertRaisesRegex(DiagnosticRefusal, "Single-link ordinary file required"):
                self.store.read_record(self.id, self.receipt["record_id"])
            diagnostic_os.open.assert_not_called()

    def test_symlink_fixture_root_refused_without_reading_target(self):
        target = self.root / "ordinary-target"
        target.mkdir()
        link = self.root / "fictional-link"
        if os.name == "nt":
            import _winapi  # A junction needs no symbolic-link privilege, so the refusal also runs on Windows.
            _winapi.CreateJunction(str(target), str(link))
        else:
            link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(DiagnosticRefusal):
            DiagnosticStore(link)


class DiagnosticPrivacyTests(unittest.TestCase):
    def fixture_root(self):
        root = ROOT / "work" / ("dp-" + uuid.uuid4().hex[:16])
        root.mkdir(parents=True)
        return root

    def test_namespace_refusal_precedes_private_record_writer(self):
        root = self.fixture_root()
        with mock.patch("service_diagnostics.ensure_private_directory", side_effect=PrivateWorkspaceError("fixture-private-hold")), mock.patch("service_diagnostics.write_private_new") as writer:
            with self.assertRaises(PrivateWorkspaceError):
                DiagnosticStore(root)
            writer.assert_not_called()
        self.assertFalse(list(root.glob("**/*.json")))

    def test_actual_native_namespace_is_private_or_holds_before_records(self):
        root = self.fixture_root()
        try:
            store = DiagnosticStore(root)
        except PrivateWorkspaceError as exc:
            if os.name != "posix" or exc.code not in PRIVATE_CAPABILITY_HOLDS:
                raise
            self.assertFalse(list(root.glob("**/*.json")))
            return
        request = store.create_request(platform="macos", recipe_id="macos.os_version", symptom="Fictional E42", scope=["os_metadata"])
        ensure_private_directory(store.base)
        ensure_private_directory(store.base / request["record"]["request_id"])
        ensure_private_file(root / request["evidence"]["path"])

    def test_existing_broad_namespace_refuses_without_permission_repair(self):
        root = self.fixture_root()
        namespace = root / "work" / "diagnostics"
        namespace.mkdir(parents=True)
        before = namespace.stat().st_mode
        try:
            ensure_private_directory(namespace)
        except PrivateWorkspaceError as exc:
            if exc.code in PRIVATE_CAPABILITY_HOLDS - {"private-owner-or-mode-refused", "private-linux-foreign-filesystem"}:
                self.skipTest("only on posix: native private-ACL admission unavailable; refusal is covered separately")
            if exc.code not in {"private-owner-or-mode-refused", "private-dacl-unprotected", "private-dacl-broad-or-unknown", "private-linux-foreign-filesystem"}:
                raise
        else:
            # This host created the folder private (umask 077); make the attack fixture broad on POSIX.
            if os.name != "posix":
                self.fail("The fixture parent already inherits a private DACL; no ACL is broadened for the test")
            namespace.chmod(0o755)
            before = namespace.stat().st_mode
        with self.assertRaises(PrivateWorkspaceError):
            DiagnosticStore(root)
        self.assertEqual(namespace.stat().st_mode, before)
        self.assertFalse(list(root.glob("**/*.json")))

    def test_neutral_default_is_separate_from_explicit_old_diagnostic_store(self):
        root = self.fixture_root()
        try:
            old = DiagnosticStore(root, work_relative="work/diagnostics-previous")
        except PrivateWorkspaceError as exc:
            if os.name == "posix" and exc.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("only on posix: private namespace unavailable; native refusal covered separately")
            raise
        receipt = old.create_request(platform="macos", recipe_id="macos.os_version", symptom="Fictional E42", scope=["os_metadata"])
        original = old.evidence_bytes(receipt["record"]["request_id"], receipt["record_id"])
        current = DiagnosticStore(root)
        self.assertEqual(current.base, root / "work/diagnostics")
        self.assertFalse(list(current.base.iterdir()))
        with self.assertRaises(FileNotFoundError):
            current.read_request(receipt["record"]["request_id"])
        reopened = DiagnosticStore(root, work_relative="work/diagnostics-previous")
        self.assertEqual(reopened.evidence_bytes(receipt["record"]["request_id"], receipt["record_id"]), original)

    def test_file_privacy_admission_precedes_content_open(self):
        root = self.fixture_root()
        try:
            store = DiagnosticStore(root)
        except PrivateWorkspaceError as exc:
            if os.name == "posix" and exc.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("only on posix: private namespace unavailable; native refusal covered separately")
            raise
        receipt = store.create_request(platform="macos", recipe_id="macos.os_version", symptom="Fictional E42", scope=["os_metadata"])
        with mock.patch("service_diagnostics.ensure_private_file", side_effect=PrivateWorkspaceError("fixture-file-private-hold")), mock.patch("service_diagnostics.os.open") as opened:
            with self.assertRaises(PrivateWorkspaceError):
                store.read_record(receipt["record"]["request_id"], receipt["record_id"])
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
