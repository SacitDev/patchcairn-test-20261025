"""Fictional macOS metadata tests; never query the development computer."""

from __future__ import annotations

import json
import errno
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
import posix_core as core


WORK = Path(__file__).resolve().parents[1] / "work" / "v2" / "macos"


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

    def isolated_toolkit(self):
        """Build fictional controls only; never use another run's authority."""
        toolkit_root = self.root / "fictional-toolkit"
        (toolkit_root / "templates").mkdir(parents=True)
        source_root = Path(__file__).resolve().parents[1]
        for name in ("toolkit.json", "templates/ledger-contract.json"):
            (toolkit_root / name).write_bytes((source_root / name).read_bytes())
        try:
            return core.Toolkit(toolkit_root)
        except core.Refusal as error:
            if str(error) in {
                "Private storage refused: private-linux-foreign-filesystem",
                "Private storage refused: private-linux-abi-unavailable",
                "Private storage refused: private-linux-libc-unavailable",
                "Private storage refused: private-darwin-acl-api-unavailable",
                "Private storage refused: private-darwin-acl-not-empty",
            }:
                self.skipTest("Actual private-workspace capability hold: " + str(error))
            raise

    def test_nonfixture_macos_producer_integrates_with_real_core_contract(self):
        """Exercise the actual producer/consumer handoff, with no live OS reads."""
        toolkit = self.isolated_toolkit()
        runner = fake_runner()
        # Only the native capability boundary is simulated. The core's mode,
        # platform, evidence and ledger checks remain in the exercised path.
        with patch.object(core.Toolkit, "assert_native_platform") as platform_gate:
            run_id = toolkit.new_run(mode="real", platform="macos",
                                     purpose="Fictional mocked producer/consumer contract test")["run_id"]
            with patch.object(mac.platform, "system", return_value="Darwin"), \
                    patch.object(mac, "_default_runner", side_effect=runner), \
                    patch.object(mac.Path, "home", return_value=self.root / "fictional-home"), \
                    patch.object(mac, "_no_links", return_value=False), \
                    patch.object(mac.os.path, "lexists", return_value=False), \
                    patch.object(mac.os, "scandir", side_effect=AssertionError("No live application traversal")) as scan, \
                    patch.object(mac, "inspect_app", side_effect=AssertionError("No live application metadata")) as inspect:
                result = toolkit.collect_baseline(run_id)
            self.assertEqual(platform_gate.call_args_list, [unittest.mock.call("macos"), unittest.mock.call("macos")])
        self.assertEqual(set(runner.calls), mac.ALLOWED_COMMANDS)
        scan.assert_not_called()
        inspect.assert_not_called()
        ledger = toolkit.read_ledger(run_id)
        self.assertEqual(ledger["run"]["mode"], "real")
        self.assertEqual(ledger["run"]["platform"], "macos")
        self.assertEqual(result["observation_count"], 4)
        self.assertEqual(ledger["components"][0]["name"], "macOS")
        self.assertEqual(ledger["components"][0]["installed_version"], "15.5.2")
        self.assertTrue(all(item["security_state"] == "not_assessed" for item in ledger["components"]))
        evidence = ledger["evidence"][0]
        saved = core.decode(core.safe_read(toolkit.work / run_id, evidence["relative_path"]))
        self.assertEqual(saved["collection_mode"], "real")
        self.assertEqual(saved["observations"][0]["build"], "24F123")

    def test_fixture_macos_producer_is_refused_by_real_core_contract(self):
        toolkit = self.isolated_toolkit()
        fixture_result = self.collect_fixture()
        self.assertEqual(fixture_result["collection_mode"], "fixture")
        with patch.object(core.Toolkit, "assert_native_platform"):
            run_id = toolkit.new_run(mode="real", platform="macos",
                                     purpose="Fictional fixture-rejection contract test")["run_id"]
            before = core.safe_read(toolkit.work / run_id, "ledger.json")
            with patch.object(mac, "collect", return_value=fixture_result) as producer:
                with self.assertRaisesRegex(core.Refusal, "real/fixture mode mismatch"):
                    toolkit.collect_baseline(run_id)
            producer.assert_called_once_with()
        self.assertEqual(before, core.safe_read(toolkit.work / run_id, "ledger.json"))
        self.assertEqual(toolkit.read_ledger(run_id)["evidence"], [])

    def test_wrong_platform_stops_before_commands_or_files(self):
        with patch.object(mac.platform, "system", return_value="Windows"), patch.object(mac.os, "scandir", side_effect=AssertionError("Must not inspect")), patch.object(mac.subprocess, "Popen", side_effect=AssertionError("Must not execute")):
            with self.assertRaises(mac.UnsupportedPlatform):
                mac.collect()

    def test_fixture_requires_every_injected_boundary(self):
        with self.assertRaises(ValueError):
            mac.collect(fixture=True)
        with self.assertRaises(ValueError):
            mac.collect(fixture=True, runner=fake_runner(), application_roots=())

    def test_explicit_fixture_calls_only_fixed_queries(self):
        runner = fake_runner()
        with patch.object(mac.subprocess, "Popen", side_effect=AssertionError("No native command in fixtures")), patch.object(mac.Path, "home", side_effect=AssertionError("No home lookup in fixtures")):
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
        with patch.object(mac.subprocess, "Popen", side_effect=AssertionError("Never launch application")):
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

    def test_native_fifo_is_rejected_without_opening(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("This host does not support creating fictional POSIX FIFOs")
        fifo = self.root / "fictional-metadata.fifo"
        try:
            os.mkfifo(fifo, 0o600)
        except OSError as error:
            unsupported = {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EPERM, errno.EACCES}
            if error.errno in unsupported:
                self.skipTest("This owned fixture filesystem does not support POSIX FIFO creation")
            raise
        with patch.object(mac.os, "open", side_effect=AssertionError("A FIFO must never be opened for metadata")):
            self.assertIsNone(mac._read_regular(fifo, mac.MAX_PLIST_BYTES))

    def test_symlinked_app_or_plist_is_never_followed(self):
        source = make_app(self.root / "source")
        approved = self.root / "approved"
        approved.mkdir()
        link = approved / "Alias.app"
        try:
            link.symlink_to(source, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("OS does not permit creating a fictional symlink")
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
        private_path = "/Users/FictionalUser/private/Tools.app/Contents/Developer"
        data = self.collect_fixture(runner=fake_runner({("/usr/bin/xcode-select", "--print-path"): private_path}))
        self.assertNotIn(private_path, json.dumps(data))
        self.assertNotIn("FictionalUser", json.dumps(data))

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
