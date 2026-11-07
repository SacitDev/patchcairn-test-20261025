"""Fictional macOS metadata tests; never query the development computer.

Real queries go through readonly_runner, replaced here by fakes. Fixture folders live under work/test-fixtures/ and
are removed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collect_macos as mac
import pc_records
import readonly_runner
from pc_records import Refusal
from test_linux_collector import assert_inventory_needs_the_scope_decision, inventory_session


WORK = Path(__file__).resolve().parents[1] / "work" / "test-fixtures" / "macos"


def fake_runner(responses=None):
    values = {
        ("/usr/bin/sw_vers",): "ProductName:\tmacOS\nProductVersion:\t15.5.2\nBuildVersion:\t24F123\n",
        ("/usr/bin/uname", "-m"): "x86_64\n",
        ("/usr/sbin/sysctl", "-n", "hw.optional.arm64"): "1\n",
        ("/usr/sbin/sysctl", "-in", "sysctl.proc_translated"): "1\n",
        ("/usr/bin/xcode-select", "--print-path"): "/Applications/ExampleTools.app/Contents/Developer\n",
        ("/usr/sbin/pkgutil", "--pkgs"): "org.example.alpha\norg.example.beta\n",
    }
    if responses:
        values.update(responses)
    calls = []

    def run(command, timeout):
        key = tuple(command)
        calls.append(key)
        if key not in values:
            raise AssertionError("Unexpected metadata query")
        value = values[key]
        return value if isinstance(value, mac.CommandResult) else mac.CommandResult(0, value)

    run.calls = calls
    return run


def make_app(root, name="Example.app", metadata=None, binary=None):
    app = root / name
    (app / "Contents" / "MacOS").mkdir(parents=True)
    fields = {"CFBundleName": "Example App", "CFBundleShortVersionString": "2.4.1",
              "CFBundleVersion": "2410", "CFBundleIdentifier": "org.example.application",
              "CFBundleExecutable": "Example", "LSMinimumSystemVersion": "14.0",
              "UnselectedPrivateField": "fictional data must not be copied"}
    if metadata:
        fields.update(metadata)
    (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps(fields))
    if binary is None:
        binary = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
    (app / "Contents" / "MacOS" / "Example").write_bytes(binary)
    return app


class MacCollectorTests(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="fictional-", dir=WORK)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def collect_fixture(self, roots=(), candidates=(), runner=None, **kwargs):
        return mac.collect(fixture=True, runner=runner or fake_runner(),
                           application_roots=roots, homebrew_candidates=candidates, **kwargs)

    def test_collector_feeds_inventory_evidence(self):
        """Real-mode facts (Darwin and its commands simulated, no live reads) become exact inventory evidence."""
        engine, scope, session_id = inventory_session(self, "macos")  # the authorized real session that receives the evidence
        runner = fake_runner()
        observed = pc_records.utc_now()
        with patch.object(mac.platform, "system", return_value="Darwin"), \
                patch.object(mac, "_default_runner", side_effect=runner), \
                patch.object(mac.Path, "home", return_value=self.root / "fictional-home"), \
                patch.object(mac, "_no_links", return_value=False), \
                patch.object(mac.os.path, "lexists", return_value=False), \
                patch.object(mac.os, "scandir", side_effect=AssertionError("No live application traversal")) as scan, \
                patch.object(mac, "inspect_app", side_effect=AssertionError("No live application metadata")) as inspect, \
                patch.object(mac.pc_records, "utc_now", return_value=observed):
            facts = mac.collect()
        self.assertEqual(set(runner.calls), mac.ALLOWED_COMMANDS)
        scan.assert_not_called()
        inspect.assert_not_called()
        self.assertEqual((facts["platform"], facts["collection_mode"], facts["observed_utc"]), ("macos", "real", observed))
        self.assertEqual([item["kind"] for item in facts["observations"]],
                         ["operating_system", "developer_tool_selection", "package_receipt", "package_receipt"])
        content = pc_records.encoded(facts)
        engine.register_evidence(session_id, evidence_id="fictional-macos-inventory", content=content, kind="inventory",
                                 scope=scope, observed_utc=facts["observed_utc"],
                                 facts={"item_count": len(facts["observations"])})
        row = engine.read_session(session_id)["evidence"]["fictional-macos-inventory"]
        self.assertEqual((row["kind"], row["sha256"], row["observed_utc"]), ("inventory", pc_records.digest(content), observed))
        saved = pc_records.decode_strict((engine.work / session_id / row["path"]).read_bytes())
        self.assertEqual(saved, facts)
        self.assertEqual((saved["observations"][0]["version"], saved["observations"][0]["build"]), ("15.5.2", "24F123"))
        # A fixture result never enters a real session: the engine refuses it as kind "fixture", and as inventory it
        # reads the result's collection_mode and refuses it (inventory-fixture-result).
        import workflow_core
        fixture = self.collect_fixture()
        self.assertEqual(fixture["collection_mode"], "fixture")
        with self.assertRaisesRegex(workflow_core.WorkflowRefusal, "cannot be promoted into a real session"):
            engine.register_evidence(session_id, evidence_id="fictional-macos-fixture", content=pc_records.encoded(fixture),
                                     kind="fixture", scope=scope, observed_utc=fixture["observed_utc"])
        with self.assertRaises(workflow_core.WorkflowRefusal) as caught:
            engine.register_evidence(session_id, evidence_id="fictional-macos-fixture-inventory", content=pc_records.encoded(fixture),
                                     kind="inventory", scope=scope, observed_utc=fixture["observed_utc"])
        self.assertEqual(caught.exception.code, "inventory-fixture-result")
        self.assertEqual(set(engine.read_session(session_id)["evidence"]), {"fictional-macos-inventory"})
        # Negative control: the real result is refused while the owner has not authorized the scope.
        assert_inventory_needs_the_scope_decision(self, "macos", content)

    def test_wrong_platform_stops_before_commands_or_files(self):
        with patch.object(mac.platform, "system", return_value="Windows"), patch.object(mac.os, "scandir", side_effect=AssertionError("Must not inspect")), patch.object(mac.readonly_runner, "run_recipe", side_effect=AssertionError("Must not execute")):
            with self.assertRaises(mac.UnsupportedPlatform):
                mac.collect()
            with self.assertRaises(mac.UnsupportedPlatform):
                mac._default_runner(("/usr/sbin/pkgutil", "--pkgs"), 5.0)

    def test_default_runner_runs_each_fixed_query_as_its_read_only_recipe(self):
        self.assertEqual(mac.ALLOWED_COMMANDS, {("/usr/bin/sw_vers",), ("/usr/bin/uname", "-m"), ("/usr/sbin/sysctl", "-n", "hw.optional.arm64"),
                                                ("/usr/sbin/sysctl", "-in", "sysctl.proc_translated"), ("/usr/bin/xcode-select", "--print-path"),
                                                ("/usr/sbin/pkgutil", "--pkgs")})
        answers = {"macos.receipts": {"ok": True, "exit_code": 0, "stdout": b"org.example.alpha\n"},
                   "macos.sw_vers": {"ok": False, "exit_code": 3, "stdout": b"fictional private output"},
                   "macos.machine": Refusal("runner-timeout", "fictional"), "macos.developer_dir": Refusal("runner-output-too-large", "fictional"),
                   "macos.translated": Refusal("runner-executable", "fictional")}
        calls = []

        def run_recipe(recipe_id):
            calls.append(recipe_id)
            if isinstance(answers[recipe_id], Exception):
                raise answers[recipe_id]
            return {"recipe": recipe_id, **answers[recipe_id]}

        with patch.object(mac.platform, "system", return_value="Darwin"), patch.object(mac.readonly_runner, "run_recipe", side_effect=run_recipe):
            results = {command: mac._default_runner(command, 5.0) for command in (
                ("/usr/sbin/pkgutil", "--pkgs"), ("/usr/bin/sw_vers",), ("/usr/bin/uname", "-m"), ("/usr/bin/xcode-select", "--print-path"),
                ("/usr/sbin/sysctl", "-in", "sysctl.proc_translated"))}
            with self.assertRaises(ValueError):
                mac._default_runner(("/usr/sbin/pkgutil", "--files", "org.example.alpha"), 5.0)
        self.assertEqual(calls, ["macos.receipts", "macos.sw_vers", "macos.machine", "macos.developer_dir", "macos.translated"])
        self.assertEqual(list(results.values()), [mac.CommandResult(0, "org.example.alpha\n"), mac.CommandResult(3, error="nonzero exit"),
                                                  mac.CommandResult(None, error="timeout"), mac.CommandResult(None, error="output limit exceeded"),
                                                  mac.CommandResult(None, error="unavailable")])

    def test_default_runner_uses_the_read_only_runner_environment_and_root_owned_tools(self):
        from test_readonly_runner import FakeLauncher, FakeProbe, regular
        probe = FakeProbe(platform="darwin", files={"/usr/sbin/pkgutil": regular()})
        launcher = FakeLauncher(b"org.example.alpha\n")
        with patch.object(mac.platform, "system", return_value="Darwin"), patch.object(readonly_runner, "HostProbe", return_value=probe), \
                patch.object(readonly_runner, "_launch", launcher):
            self.assertEqual(mac._default_runner(("/usr/sbin/pkgutil", "--pkgs"), 5.0), mac.CommandResult(0, "org.example.alpha\n"))
            self.assertEqual(mac._default_runner(("/usr/bin/xcode-select", "--print-path"), 5.0), mac.CommandResult(None, error="unavailable"))
        call, = launcher.calls
        self.assertEqual((call.argv, call.env, call.cwd, call.timeout, call.max_bytes),
                         (("/usr/sbin/pkgutil", "--pkgs"), readonly_runner.INVENTORY_ENV, "/", readonly_runner.INVENTORY_TIMEOUT_SECONDS,
                          readonly_runner.INVENTORY_MAX_BYTES))

    def test_fixture_requires_every_injected_boundary(self):
        with self.assertRaises(ValueError):
            mac.collect(fixture=True)
        with self.assertRaises(ValueError):
            mac.collect(fixture=True, runner=fake_runner(), application_roots=())

    def test_explicit_fixture_calls_only_fixed_queries(self):
        runner = fake_runner()
        with patch.object(mac.readonly_runner, "run_recipe", side_effect=AssertionError("No native command in fixtures")), patch.object(mac.Path, "home", side_effect=AssertionError("No home lookup in fixtures")):
            data = self.collect_fixture(runner=runner)
        self.assertEqual(set(runner.calls), mac.ALLOWED_COMMANDS)
        self.assertEqual(len(runner.calls), 6)
        self.assertEqual(data["collection_mode"], "fixture")
        self.assertTrue(data["observed_utc"].endswith("Z"))

    def test_apple_silicon_translated_process_is_distinct(self):
        data = self.collect_fixture()
        os_record = data["observations"][0]
        self.assertEqual(os_record["version"], "15.5.2")
        self.assertEqual(os_record["build"], "24F123")
        self.assertEqual(os_record["architecture"], "arm64")
        self.assertEqual(os_record["process_architecture"], "x86_64")
        self.assertTrue(os_record["process_translated"])

    def test_missing_architecture_key_is_unknown(self):
        data = self.collect_fixture(runner=fake_runner({("/usr/sbin/sysctl", "-n", "hw.optional.arm64"): mac.CommandResult(1, error="unsupported")}))
        self.assertIsNone(data["observations"][0]["architecture"])
        self.assertTrue(any("unavailable or failed" in value for value in data["limits"]))

    def test_receipts_are_identifiers_not_current_version_claims(self):
        data = self.collect_fixture(max_receipts=1)
        receipts = [item for item in data["observations"] if item["kind"] == "package_receipt"]
        self.assertEqual(len(receipts), 1)
        self.assertIsNone(receipts[0]["version"])
        self.assertTrue(data["coverage"]["receipt_identifiers_truncated"])

    def test_receipt_parser_rejects_controls_and_invalid_values(self):
        values, truncated = mac.parse_receipt_ids("org.example.valid\n<script>bad</script>\norg.example.valid\norg.example.\x1b[31m\n")
        self.assertEqual(values, ["org.example.valid"])
        self.assertFalse(truncated)

    def test_selected_app_fields_only_and_header_never_executed(self):
        make_app(self.root)
        with patch.object(mac.readonly_runner, "run_recipe", side_effect=AssertionError("Never launch application")):
            data = self.collect_fixture(roots=(self.root,))
        apps = [item for item in data["observations"] if item["kind"] == "application"]
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["architecture"], "arm64")
        self.assertEqual(apps[0]["version"], "2.4.1")
        self.assertEqual(apps[0]["build"], "2410")
        self.assertNotIn("UnselectedPrivateField", json.dumps(data))
        self.assertNotIn(str(self.root), json.dumps(data))
        self.assertIn("not signature/integrity", apps[0]["architecture_evidence"])

    def test_app_limit_is_explicit(self):
        make_app(self.root, "First.app")
        make_app(self.root, "Second.app")
        data = self.collect_fixture(roots=(self.root,), max_apps=1)
        self.assertEqual(data["coverage"]["application_records"], 1)
        self.assertTrue(data["coverage"]["application_truncated"])

    def test_no_nested_project_or_profile_traversal(self):
        make_app(self.root / "UnrelatedProject", "Hidden.app")
        (self.root / "BrowserProfile").mkdir()
        (self.root / "BrowserProfile" / "History").write_text("fictional private data", encoding="utf-8")
        data = self.collect_fixture(roots=(self.root,))
        self.assertEqual(data["coverage"]["application_records"], 0)

    def test_executable_traversal_is_not_read(self):
        app = make_app(self.root, metadata={"CFBundleExecutable": "../../outside"})
        with patch.object(mac, "parse_macho_architectures", side_effect=AssertionError("Must not read escaped binary")):
            record = mac.inspect_app(app, "fictional")
        self.assertIsNone(record["architecture"])

    def test_malformed_or_oversized_plists_are_skipped(self):
        app = make_app(self.root)
        plist_path = app / "Contents" / "Info.plist"
        for payload in (b"not a plist", b'<?xml version="1.0"?><plist><dict><key>broken', b"x" * (mac.MAX_PLIST_BYTES + 1)):
            plist_path.write_bytes(payload)
            self.assertIsNone(mac.inspect_app(app, "fictional"))

    def test_nonregular_leaf_is_rejected_before_open(self):
        with patch.object(mac.os, "open", side_effect=AssertionError("A nonregular leaf must never be opened")):
            self.assertIsNone(mac._read_regular(self.root, mac.MAX_PLIST_BYTES))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "only on posix: os.mkfifo creates the fictional FIFO")
    def test_native_fifo_is_rejected_without_opening(self):
        fifo = self.root / "fictional-metadata.fifo"
        os.mkfifo(fifo, 0o600)
        with patch.object(mac.os, "open", side_effect=AssertionError("A FIFO must never be opened for metadata")):
            self.assertIsNone(mac._read_regular(fifo, mac.MAX_PLIST_BYTES))

    def test_symlinked_app_or_plist_is_never_followed(self):
        source = make_app(self.root / "source")
        approved = self.root / "approved"
        approved.mkdir()
        link = approved / "Alias.app"
        try:
            link.symlink_to(source, target_is_directory=True)
        except OSError as error:
            if os.name != "nt" or getattr(error, "winerror", None) != 1314:
                raise
            self.skipTest("only on posix: Windows refused the symbolic link because the symbolic-link privilege is not held")
        self.assertIsNone(mac.inspect_app(link, "fictional"))
        real = make_app(approved, "Real.app")
        (real / "Contents" / "Info.plist").unlink()
        (real / "Contents" / "Info.plist").symlink_to(source / "Contents" / "Info.plist")
        self.assertIsNone(mac.inspect_app(real, "fictional"))

    def test_homebrew_candidate_is_never_executed_or_opened(self):
        candidate = self.root / "brew"
        candidate.write_text("fictional program; do not execute", encoding="utf-8")
        runner = fake_runner()
        data = self.collect_fixture(candidates=(candidate,), runner=runner)
        found = [item for item in data["observations"] if item["kind"] == "package_manager_candidate"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["status"], "hold")
        self.assertFalse(data["coverage"]["homebrew_packages_inventoried"])
        self.assertTrue(all(command[0] != str(candidate) for command in runner.calls))

    def test_custom_developer_path_is_not_retained(self):
        private_path = "/Users/example/private/Tools.app/Contents/Developer"
        data = self.collect_fixture(runner=fake_runner({("/usr/bin/xcode-select", "--print-path"): private_path}))
        self.assertNotIn(private_path, json.dumps(data))
        self.assertNotIn("/Users/example", json.dumps(data))

    def test_raw_errors_and_oversized_command_output_are_not_retained(self):
        sentinel = "fictional-private-error-value"
        data = self.collect_fixture(runner=fake_runner({("/usr/bin/sw_vers",): mac.CommandResult(1, sentinel, sentinel),
                                                        ("/usr/sbin/pkgutil", "--pkgs"): "x" * (mac.MAX_COMMAND_BYTES + 1)}))
        self.assertNotIn(sentinel, json.dumps(data))
        self.assertIsNone(data["observations"][0]["version"])
        self.assertEqual(data["coverage"]["receipt_identifiers"], 0)

    def test_macho_thin_universal_and_invalid_headers(self):
        thin = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 0, 2, 0, 0, 0, 0)
        universal = struct.pack(">II", 0xCAFEBABE, 2) + struct.pack(">IIIII", 0x01000007, 0, 4096, 100, 12) + struct.pack(">IIIII", 0x0100000C, 0, 8192, 100, 12)
        self.assertEqual(mac.parse_macho_architectures(thin), ["x86_64"])
        self.assertEqual(mac.parse_macho_architectures(universal), ["arm64", "x86_64"])
        self.assertEqual(mac.parse_macho_architectures(universal[:20]), [])
        self.assertEqual(mac.parse_macho_architectures(struct.pack(">II", 0xCAFEBABE, 9999)), [])
        self.assertEqual(mac.parse_macho_architectures(b"#!/bin/sh\n"), [])

    def test_bounds_cannot_be_silently_disabled(self):
        for values in ({"timeout": 0}, {"max_apps": 501}, {"max_receipts": 0}):
            with self.assertRaises(ValueError):
                self.collect_fixture(**values)


if __name__ == "__main__":
    unittest.main()
