"""Fictional Linux metadata fixtures; never collect the current host inventory.

Package queries go through readonly_runner, replaced here by fakes (its recipe call, or its host facts and process
start), so every test runs on every OS. Fixture folders live under work/test-fixtures/ and are removed.
"""

import importlib.util
from pathlib import Path, PurePosixPath
import stat
import sys
import uuid
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


_MODULE = Path(__file__).resolve().parents[1] / "scripts" / "collect_linux.py"
sys.path.insert(0, str(_MODULE.parent))
import pc_records
import readonly_runner
from pc_records import Refusal
from work_fixtures import remove_tree
_SPEC = importlib.util.spec_from_file_location("fixture_linux_collector", _MODULE)
linux = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(linux)
WORK = _MODULE.parents[1] / "work" / "test-fixtures" / "linux-collector"
DPKG_ROW = b"example\t1.0-2vendor\tamd64\tii \texample-source\n"


def inventory_session(test, platform, *, authorized=True):
    """A fresh engine session in its own fixture folder (removed after the test) whose whole-device,
    metadata-only scope the fictional owner authorizes before evidence is registered (unless authorized=False).
    The one helper of both collector test modules."""
    # The engine core does not check the host platform (the CLI and the service refuse a non-native
    # real session), so this real session simulates a native host of the given platform.
    import workflow_core
    root = WORK / ("fictional-engine-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    test.addCleanup(remove_tree, root)
    engine = workflow_core.WorkflowEngine(root)
    access = {"schema": "patchcairn.assessment.access", "schema_version": 1, "target": "whole_device",
              "operations": ["metadata"], "local_content": [], "llm_content": [], "sensitive_exceptions": []}
    scope = {"roots": [], "purpose": "Fictional installed-software inventory", "assessment": access}
    session_id = engine.create_session(mode="real", platform=platform, scope=scope)["session_id"]
    if authorized:
        engine.authorize_scope(session_id, owner_quote="Read only installed-software metadata on this fictional device.",
                               owner_message_id="fictional-owner-scope-" + uuid.uuid4().hex)
        test.assertEqual(engine.read_session(session_id)["scope_authorization"]["scope_sha256"], pc_records.digest(scope))
    return engine, scope, session_id


def assert_inventory_needs_the_scope_decision(test, platform, content):
    """Registering inventory before authorize_scope is refused (the engine's inventory-scope-unauthorized refusal,
    test_engine_plans.InventoryEvidenceTests.test_real_inventory_needs_current_scope_authorization)."""
    import workflow_core
    engine, scope, session_id = inventory_session(test, platform, authorized=False)
    before = engine.read_session(session_id)
    with test.assertRaises(workflow_core.WorkflowRefusal) as caught:
        engine.register_evidence(session_id, evidence_id="fictional-unauthorized-inventory", content=content, kind="inventory", scope=scope)
    test.assertEqual(caught.exception.code, "inventory-scope-unauthorized")
    test.assertEqual(engine.read_session(session_id), before)


def recipes(outputs):
    """A fake readonly_runner.run_recipe answering each recipe id from ``outputs`` (bytes, an exception, or absent:
    no listed root-owned tool)."""
    calls = []

    def run_recipe(recipe_id):
        calls.append(recipe_id)
        value = outputs.get(recipe_id, Refusal("runner-executable", "No listed system tool owned by root was found"))
        if isinstance(value, Exception):
            raise value
        code, data = value if isinstance(value, tuple) else (0, value)
        return {"recipe": recipe_id, "exit_code": code, "ok": code == 0, "stdout": data}

    run_recipe.calls = calls
    return run_recipe


def native(run_recipe, uname=None, os_release=None):
    """Patches simulating a native Linux host: platform, os-release, kernel and the package queries."""
    return (patch.object(linux.sys, "platform", "linux"),
            patch.object(linux, "_read_os_release", side_effect=os_release) if isinstance(os_release, Exception)
            else patch.object(linux, "_read_os_release", return_value=os_release or {"ID": "example", "VERSION_ID": "12", "PRETTY_NAME": "Example Linux 12"}),
            patch.object(linux.os, "uname", return_value=uname or MagicMock(release="6.1.0-example", machine="x86_64"), create=True),
            patch.object(linux.readonly_runner, "run_recipe", side_effect=run_recipe))


def collect(run_recipe, **host):
    patches = native(run_recipe, **host)
    for item in patches:
        item.start()
    try:
        return linux.collect()
    finally:
        for item in reversed(patches):
            item.stop()


class LinuxParserTests(unittest.TestCase):
    def test_os_release_selected_literal_fields_only(self):
        result = linux.parse_os_release(
            'ID=example\nVERSION_ID="12.5"\nID_LIKE="debian linux"\n'
            'PRETTY_NAME="Example Linux 12"\nHOME_URL="https://example.invalid/"\n'
            'SECRET_FIELD="must not be retained"\n')
        self.assertEqual(result, {"ID": "example", "VERSION_ID": "12.5",
                                  "ID_LIKE": "debian linux", "PRETTY_NAME": "Example Linux 12"})

    def test_os_release_never_interpolates_shell_input(self):
        result = linux.parse_os_release('ID=example\nPRETTY_NAME="$(touch unwanted)"\n')
        self.assertEqual(result, {"ID": "example"})

    def test_os_release_duplicate_or_missing_id_is_not_valid_evidence(self):
        for text in ('ID=example\nID=other\n', 'PRETTY_NAME="Example Linux"\n'):
            with self.assertRaises(linux.CollectionError):
                linux.parse_os_release(text)

    def test_dpkg_filters_removed_and_incomplete_preserves_epoch_and_hold(self):
        rows, rejected = linux.parse_dpkg(
            "example:amd64\t2:1.0-3vendor1\tamd64\thi \texample-source\n"
            "old\t1.0\tall\trc \told\n"
            "incomplete\t1.0\tall\tiU \tincomplete\n")
        self.assertEqual(rejected, 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["version"], "2:1.0-3vendor1")
        self.assertTrue(rows[0]["desired_hold"])
        self.assertEqual(rows[0]["source_package"], "example-source")
        self.assertEqual(rows[0]["update_offer"], "not_checked")

    def test_dpkg_reinstall_flag_is_not_marked_healthy(self):
        rows, _ = linux.parse_dpkg("example\t1.0\tall\tiiR\texample\n")
        self.assertEqual(rows[0]["package_health"], "reinstallation_required")

    def test_untrusted_rows_are_rejected_without_echo(self):
        for parser, text in (
            (linux.parse_dpkg, "bad name\t1\tall\tii \tsource\n"),
            (linux.parse_rpm, "example\t1\tx86_64\tunsafe\x1bvalue\n"),
            (linux.parse_flatpak, "bad id\t1\tx86_64\tstable\n"),
        ):
            rows, rejected = parser(text)
            self.assertEqual(rows, [])
            self.assertEqual(rejected, 1)

    def test_rpm_preserves_epoch_release_and_source(self):
        rows, rejected = linux.parse_rpm("example\t0:1.2-3.vendor\tx86_64\texample-1.2-3.src.rpm\n")
        self.assertEqual(rejected, 0)
        self.assertEqual(rows[0]["version"], "0:1.2-3.vendor")
        self.assertEqual(rows[0]["source_package"], "example-1.2-3.src.rpm")

    def test_snap_uses_revision_and_channel_without_publisher_prose(self):
        rows, rejected = linux.parse_snap(
            "Name Version Rev Tracking Publisher Notes\n"
            "example 1.2 456 latest/stable fictional-publisher held,classic\n")
        self.assertEqual(rejected, 0)
        self.assertEqual(rows[0]["revision"], "456")
        self.assertEqual(rows[0]["channel"], "latest/stable")
        self.assertTrue(rows[0]["desired_hold"])
        self.assertNotIn("publisher", rows[0])
        self.assertEqual(linux.parse_snap("unexpected output"), ([], 1))

    def test_snap_with_nothing_installed_is_complete_coverage(self):
        # snap list prints nothing on stdout when no snaps are installed.
        for output in (b"", b"\n"):
            with self.subTest(output=output):
                facts = collect(recipes({"linux.snap_list": output}))
                scope = next(row for row in facts["coverage"] if row["scope"] == "snap")
                self.assertEqual((scope["state"], scope["records"], scope["rejected_rows"]), ("observed", 0, 0))

    def test_rpm_signing_keys_are_not_packages_and_do_not_lower_coverage(self):
        facts = collect(recipes({"linux.rpm_installed": b"example\t0:1.2-3.vendor\tx86_64\texample-1.2-3.src.rpm\n"
                                                        b"gpg-pubkey\t0:abcdef12-5f000000\t(none)\t(none)\n"}))
        scope = next(row for row in facts["coverage"] if row["scope"] == "rpm")
        self.assertEqual((scope["state"], scope["records"], scope["rejected_rows"]), ("observed", 1, 0))
        self.assertEqual([row["name"] for row in facts["observations"] if row["kind"] == "package"], ["example"])
        # Only a key row's exact shape is passed over: the name alone hides nothing from the inventory.
        self.assertEqual(linux.parse_rpm("gpg-pubkey\t0:abcdef12-5f000000\t(none)\n"), ([], 1))
        rows, rejected = linux.parse_rpm("gpg-pubkey\t0:1.0-1\tx86_64\tgpg-pubkey-1.0-1.src.rpm\n")
        self.assertEqual(([row["name"] for row in rows], rejected), (["gpg-pubkey"], 0))

    def test_flatpak_empty_version_is_unknown_not_latest(self):
        rows, rejected = linux.parse_flatpak("org.example.Runtime\t\tx86_64\t24.08\n")
        self.assertEqual(rejected, 0)
        self.assertIsNone(rows[0]["version"])
        self.assertEqual(rows[0]["scope"], "system")

    def test_collector_feeds_inventory_evidence(self):
        """Simulated native collection becomes exact inventory evidence in a fresh engine session."""
        engine, scope, session_id = inventory_session(self, "linux")  # the authorized real session that receives the evidence
        observed = pc_records.utc_now()
        run_recipe = recipes({"linux.dpkg_installed": DPKG_ROW})
        with patch.object(linux.pc_records, "utc_now", return_value=observed):
            facts = collect(run_recipe)
        self.assertEqual(run_recipe.calls, ["linux.dpkg_installed", "linux.rpm_installed", "linux.snap_list", "linux.flatpak_system"])
        self.assertEqual((facts["platform"], facts["collection_mode"], facts["observed_utc"], facts["errors"]),
                         ("linux", "real", observed, []))
        self.assertEqual([item["kind"] for item in facts["observations"]], ["operating_system", "kernel", "package"])
        package = facts["observations"][2]
        self.assertEqual((package["update_offer"], package["security_applicability"]), ("not_checked", "not_assessed"))
        content = pc_records.encoded(facts)
        engine.register_evidence(session_id, evidence_id="fictional-linux-inventory", content=content, kind="inventory",
                                 scope=scope, observed_utc=facts["observed_utc"],
                                 facts={"item_count": len(facts["observations"])})
        row = engine.read_session(session_id)["evidence"]["fictional-linux-inventory"]
        self.assertEqual((row["kind"], row["sha256"], row["observed_utc"]), ("inventory", pc_records.digest(content), observed))
        self.assertEqual(pc_records.decode_strict((engine.work / session_id / row["path"]).read_bytes()), facts)
        # Negative control: the same evidence is refused while the owner has not authorized the scope.
        assert_inventory_needs_the_scope_decision(self, "linux", content)


class LinuxSafetyTests(unittest.TestCase):
    def test_queries_run_through_the_read_only_runner_with_its_fixed_environment(self):
        from test_readonly_runner import FakeLauncher, FakeProbe, regular
        probe = FakeProbe(files={"/usr/bin/dpkg-query": regular(), "/usr/bin/snap": regular(uid=1000)})
        launcher = FakeLauncher(DPKG_ROW)
        with patch.object(readonly_runner, "HostProbe", return_value=probe), patch.object(readonly_runner, "_launch", launcher):
            facts = collect(readonly_runner.run_recipe)
        call, = launcher.calls  # rpm and flatpak are absent and snap is not owned by root: none of them starts
        self.assertEqual(call.argv, ("/usr/bin/dpkg-query", "--show",
                                     "--showformat=${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\t${source:Package}\\n"))
        self.assertEqual((call.env, call.cwd, call.timeout, call.max_bytes),
                         (readonly_runner.INVENTORY_ENV, "/", readonly_runner.INVENTORY_TIMEOUT_SECONDS, readonly_runner.INVENTORY_MAX_BYTES))
        self.assertEqual(call.env["HOME"], "/dev/null")
        self.assertEqual([row["state"] for row in facts["coverage"] if row["scope"] != "os_release"],
                         ["observed", "unavailable_or_untrusted", "unavailable_or_untrusted", "unavailable_or_untrusted"])
        self.assertEqual(facts["observations"][2]["name"], "example")

    def test_runner_refusals_and_failures_become_categorical_errors(self):
        run_recipe = recipes({"linux.dpkg_installed": Refusal("runner-timeout", "fictional"),
                              "linux.rpm_installed": Refusal("runner-output-too-large", "fictional"),
                              "linux.snap_list": (7, b"fictional private text"),
                              "linux.flatpak_system": b"\xff\xfe not UTF-8"})
        result = collect(run_recipe)
        self.assertEqual(result["errors"], [{"scope": "dpkg-query", "code": "query_timeout"}, {"scope": "rpm", "code": "query_output_limit"},
                                            {"scope": "snap", "code": "query_exit_nonzero"}, {"scope": "flatpak", "code": "query_encoding"}])
        self.assertNotIn("fictional private text", str(result))
        started = collect(recipes({"linux.dpkg_installed": Refusal("runner-start", "secret D:\\Fictional\\path")}))
        self.assertEqual(started["errors"][0], {"scope": "dpkg-query", "code": "query_unavailable"})
        self.assertNotIn("Fictional", str(started))

    def test_non_linux_rejected_before_any_host_read(self):
        with patch.object(linux.sys, "platform", "win32"), \
             patch.object(linux, "_read_os_release") as read, \
             patch.object(linux.readonly_runner, "run_recipe") as run:
            with self.assertRaisesRegex(linux.CollectionError, "native_linux_required"):
                linux.collect()
        read.assert_not_called()
        run.assert_not_called()

    def test_os_release_file_must_be_root_owned_and_not_writable_by_others(self):
        metadata = {}
        class FixturePath(PurePosixPath):
            def resolve(self, strict=True):
                return self
            def stat(self):
                return metadata.get(str(self), SimpleNamespace(
                    st_mode=(stat.S_IFREG | 0o644) if self.name == "os-release" else (stat.S_IFDIR | 0o755),
                    st_uid=0))
        with patch.object(linux, "Path", FixturePath):
            self.assertTrue(linux._trusted_system_path("/etc/os-release"))
            metadata["/etc/os-release"] = SimpleNamespace(st_mode=stat.S_IFREG | 0o666, st_uid=0)
            self.assertFalse(linux._trusted_system_path("/etc/os-release"))
            metadata["/etc/os-release"] = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=1000)
            self.assertFalse(linux._trusted_system_path("/etc/os-release"))
            metadata.clear()
            metadata["/etc"] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0)
            self.assertFalse(linux._trusted_system_path("/etc/os-release"))
            metadata.clear()
            metadata["/etc/os-release"] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
            self.assertFalse(linux._trusted_system_path("/etc/os-release"))
            self.assertFalse(linux._trusted_system_path("/var/tmp/os-release"))

    def test_collect_wsl_metadata_and_partial_coverage_are_not_security_clearance(self):
        uname = MagicMock(release="5.15.0-example-microsoft-standard-WSL2", machine="x86_64")
        run_recipe = recipes({"linux.dpkg_installed": b"example\t1.0-2vendor\tamd64\tii \texample\nmalformed\n"})
        result = collect(run_recipe, uname=uname, os_release={"ID": "example", "VERSION_ID": "12"})
        self.assertEqual(result["platform"], "linux")
        self.assertTrue(result["observed_utc"].endswith("Z"))
        self.assertEqual(result["observations"][1]["environment"], "wsl_guest")
        scope = next(row for row in result["coverage"] if row["scope"] == "dpkg-query")
        self.assertEqual(scope["state"], "partial")
        self.assertEqual(scope["rejected_rows"], 1)
        self.assertEqual(result["observations"][2]["security_applicability"], "not_assessed")

    def test_collector_error_does_not_echo_private_error_details(self):
        run_recipe = recipes({recipe_id: (2, b"fictional private stderr-like text") for recipe_id in
                              ("linux.dpkg_installed", "linux.rpm_installed", "linux.snap_list", "linux.flatpak_system")})
        result = collect(run_recipe, uname=MagicMock(release="6.0.0-example", machine="x86_64"),
                         os_release=linux.CollectionError("os_release_unavailable"))
        self.assertEqual(len(result["errors"]), 5)
        self.assertTrue(all(set(item) == {"scope", "code"} for item in result["errors"]))
        self.assertNotIn("private", str(result["errors"]))


if __name__ == "__main__":
    unittest.main()
