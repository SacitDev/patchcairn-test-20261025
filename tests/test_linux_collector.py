"""Fictional Linux metadata fixtures; never collect the current host inventory."""

import importlib.util
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import uuid
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


_MODULE = Path(__file__).resolve().parents[1] / "scripts" / "collect_linux.py"
_SPEC = importlib.util.spec_from_file_location("fixture_linux_collector", _MODULE)
linux = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(linux)


def _run_controlled_pipe_fixture(program, *, timeout=linux.QUERY_TIMEOUT, byte_limit=linux.MAX_BYTES):
    """Exercise pipe behavior with only the currently running test interpreter.

    Hosted CI can install that interpreter outside production's system-tool roots.
    Its admission is mocked locally; the production policy remains independently
    tested and is restored even when the fixture times out or exceeds its cap.
    """
    interpreter = sys.executable
    def admit_fixture(candidate, executable=False):
        return executable is True and candidate == interpreter
    with patch.object(linux, "_trusted_system_path", side_effect=admit_fixture):
        return linux._run_query(
            [interpreter, "-I", "-S", "-B", "-c", program],
            timeout=timeout, byte_limit=byte_limit,
        )


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

    def test_flatpak_empty_version_is_unknown_not_latest(self):
        rows, rejected = linux.parse_flatpak("org.example.Runtime\t\tx86_64\t24.08\n")
        self.assertEqual(rejected, 0)
        self.assertIsNone(rows[0]["version"])
        self.assertEqual(rows[0]["scope"], "system")


class LinuxSafetyTests(unittest.TestCase):
    def test_legacy_store_privacy_hold_precedes_mocked_collector(self):
        source_root = _MODULE.parent.parent
        fixture = source_root / "work" / "upgrade_v3" / "filesystem" / "legacy_privacy" / ("linux-collector-" + uuid.uuid4().hex)
        fixture.mkdir(parents=True)
        (fixture / "toolkit.json").write_bytes((source_root / "toolkit.json").read_bytes())
        specification = importlib.util.spec_from_file_location("fictional_linux_legacy_core", _MODULE.with_name("posix_core.py"))
        core = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(core)
        with patch.object(core, "_private_directory", side_effect=core.Refusal("Private storage refused: private-linux-foreign-filesystem")), \
                patch.object(linux, "collect") as collector:
            with self.assertRaisesRegex(core.Refusal, "private-linux-foreign-filesystem"):
                core.Toolkit(fixture).collect_baseline("run-" + "a" * 32)
        collector.assert_not_called()
        self.assertFalse((fixture / "work").exists())

    def test_pipe_fixture_admits_only_controlled_non_system_interpreter_and_restores_policy(self):
        interpreter = "/opt/hostedtoolcache/Python/3.12.9/x64/bin/python3"
        original_admission = linux._trusted_system_path
        class LiteralSystemPath(PurePosixPath):
            def resolve(self, strict=True):
                return self
            def stat(self):
                raise AssertionError("This fictional non-system path must be rejected before stat")
        with patch.object(linux, "Path", LiteralSystemPath):
            self.assertFalse(original_admission(interpreter, executable=True))
        def inspect_fixture(argv, **bounds):
            self.assertEqual(argv, [interpreter, "-I", "-S", "-B", "-c", "print('fictional')"])
            self.assertTrue(linux._trusted_system_path(interpreter, executable=True))
            self.assertFalse(linux._trusted_system_path(interpreter, executable=False))
            self.assertFalse(linux._trusted_system_path(interpreter + "-other", executable=True))
            self.assertFalse(linux._trusted_system_path("/usr/bin/other", executable=True))
            self.assertEqual(bounds, {"timeout": linux.QUERY_TIMEOUT, "byte_limit": linux.MAX_BYTES})
            return "fictional\n"
        with patch.object(sys, "executable", interpreter), \
             patch.object(linux, "_run_query", side_effect=inspect_fixture):
            self.assertEqual(_run_controlled_pipe_fixture("print('fictional')"), "fictional\n")
        self.assertIs(linux._trusted_system_path, original_admission)
        with patch.object(sys, "executable", interpreter), \
             patch.object(linux, "_run_query", side_effect=linux.CollectionError("query_timeout")):
            with self.assertRaisesRegex(linux.CollectionError, "query_timeout"):
                _run_controlled_pipe_fixture("print('fictional')")
        self.assertIs(linux._trusted_system_path, original_admission)

    def test_non_linux_rejected_before_any_host_read(self):
        with patch.object(linux.sys, "platform", "win32"), \
             patch.object(linux, "_read_os_release") as read, \
             patch.object(linux, "_find_program") as find:
            with self.assertRaisesRegex(linux.CollectionError, "native_linux_required"):
                linux.collect()
        read.assert_not_called()
        find.assert_not_called()

    def test_program_resolution_never_searches_user_path(self):
        with patch.object(linux, "_trusted_system_path", return_value=False) as trusted:
            self.assertIsNone(linux._find_program("dpkg-query"))
            self.assertIsNone(linux._find_program("unapproved-tool"))
        self.assertEqual([call.args[0].as_posix() for call in trusted.call_args_list],
                         ["/usr/bin/dpkg-query", "/bin/dpkg-query", "/usr/sbin/dpkg-query"])

    def test_trusted_program_rejects_world_writable_and_wrong_owner(self):
        metadata = {}
        class FixturePath(PurePosixPath):
            def resolve(self, strict=True):
                return self
            def stat(self):
                return metadata.get(str(self), SimpleNamespace(
                    st_mode=(stat.S_IFREG | 0o755) if self.name == "example" else (stat.S_IFDIR | 0o755),
                    st_uid=0))
        with patch.object(linux, "Path", FixturePath):
            self.assertTrue(linux._trusted_system_path("/usr/bin/example", executable=True))
            metadata["/usr/bin/example"] = SimpleNamespace(st_mode=stat.S_IFREG | 0o777, st_uid=0)
            self.assertFalse(linux._trusted_system_path("/usr/bin/example", executable=True))
            metadata["/usr/bin/example"] = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=1000)
            self.assertFalse(linux._trusted_system_path("/usr/bin/example", executable=True))
            metadata.clear()
            metadata["/usr"] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0)
            self.assertFalse(linux._trusted_system_path("/usr/bin/example", executable=True))
            self.assertFalse(linux._trusted_system_path("/unapproved/example", executable=True))

    def _fake_query(self, chunks, exit_code=0):
        process = MagicMock()
        process.poll.return_value = exit_code
        process.wait.return_value = exit_code
        key = MagicMock()
        key.fileobj = process.stdout
        selector = MagicMock()
        selector.get_map.side_effect = [True] * len(chunks) + [False]
        selector.select.return_value = [(key, linux.selectors.EVENT_READ)]
        return process, selector

    def test_query_has_hard_cap_and_no_raw_stderr_or_inherited_environment(self):
        process, selector = self._fake_query([b"12345"])
        with patch.object(linux, "_trusted_system_path", return_value=True), \
             patch.object(linux.subprocess, "Popen", return_value=process) as popen, \
             patch.object(linux.selectors, "DefaultSelector", return_value=selector), \
             patch.object(linux.os, "read", return_value=b"12345"):
            with self.assertRaisesRegex(linux.CollectionError, "query_output_limit"):
                linux._run_query(["/usr/bin/dpkg-query", "--show"], byte_limit=4)
        options = popen.call_args.kwargs
        self.assertFalse(options["shell"])
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertEqual(options["env"]["HOME"], "/dev/null")
        self.assertNotIn("LD_PRELOAD", options["env"])
        self.assertNotIn("HTTP_PROXY", options["env"])

    def test_query_nonzero_is_categorical_and_stdout_not_returned(self):
        process, selector = self._fake_query([b"sensitive-like fictional output", b""], exit_code=7)
        with patch.object(linux, "_trusted_system_path", return_value=True), \
             patch.object(linux.subprocess, "Popen", return_value=process), \
             patch.object(linux.selectors, "DefaultSelector", return_value=selector), \
             patch.object(linux.os, "read", side_effect=[b"fictional private text", b""]):
            with self.assertRaisesRegex(linux.CollectionError, "query_exit_nonzero") as caught:
                linux._run_query(["/usr/bin/example"])
        self.assertEqual(str(caught.exception), "query_exit_nonzero")

    def test_query_timeout_kills_only_its_own_spawned_process(self):
        process, selector = self._fake_query([b"unused"])
        process.poll.return_value = None
        with patch.object(linux, "_trusted_system_path", return_value=True), \
             patch.object(linux.subprocess, "Popen", return_value=process), \
             patch.object(linux.selectors, "DefaultSelector", return_value=selector), \
             patch.object(linux.time, "monotonic", side_effect=[0.0, 9.0]):
            with self.assertRaisesRegex(linux.CollectionError, "query_timeout"):
                linux._run_query(["/usr/bin/example"])
        process.kill.assert_called_once_with()

    def test_collect_wsl_metadata_and_partial_coverage_are_not_security_clearance(self):
        uname = MagicMock(release="5.15.0-example-microsoft-standard-WSL2", machine="x86_64")
        def query(argv):
            if "dpkg-query" in argv[0]:
                return "example\t1.0-2vendor\tamd64\tii \texample\nmalformed\n"
            raise AssertionError("Unexpected fixture command")
        with patch.object(linux.sys, "platform", "linux"), \
             patch.object(linux, "_read_os_release", return_value={"ID": "example", "VERSION_ID": "12"}), \
             patch.object(linux.os, "uname", return_value=uname, create=True), \
             patch.object(linux, "_find_program", side_effect=lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None), \
             patch.object(linux, "_run_query", side_effect=query):
            result = linux.collect()
        self.assertEqual(result["platform"], "linux")
        self.assertTrue(result["observed_utc"].endswith("Z"))
        self.assertEqual(result["observations"][1]["environment"], "wsl_guest")
        scope = next(row for row in result["coverage"] if row["scope"] == "dpkg-query")
        self.assertEqual(scope["state"], "partial")
        self.assertEqual(scope["rejected_rows"], 1)
        self.assertEqual(result["observations"][2]["security_applicability"], "not_assessed")

    def test_collector_error_does_not_echo_private_error_details(self):
        uname = MagicMock(release="6.0.0-example", machine="x86_64")
        with patch.object(linux.sys, "platform", "linux"), \
             patch.object(linux, "_read_os_release", side_effect=linux.CollectionError("os_release_unavailable")), \
             patch.object(linux.os, "uname", return_value=uname, create=True), \
             patch.object(linux, "_find_program", return_value="/usr/bin/example"), \
             patch.object(linux, "_run_query", side_effect=linux.CollectionError("query_exit_nonzero")):
            result = linux.collect()
        self.assertEqual(len(result["errors"]), 5)
        self.assertTrue(all(set(item) == {"scope", "code"} for item in result["errors"]))


@unittest.skipUnless(sys.platform.startswith("linux"), "Native Linux pipe fixture only; no host inventory")
class LinuxPipeFixtureTests(unittest.TestCase):
    """Only spawn this test interpreter with fixed fictional-output programs."""

    def test_native_pipe_reads_fictional_output(self):
        result = _run_controlled_pipe_fixture("print('fictional-package 1.0')")
        self.assertEqual(result, "fictional-package 1.0\n")

    def test_native_pipe_enforces_cap(self):
        with self.assertRaisesRegex(linux.CollectionError, "query_output_limit"):
            _run_controlled_pipe_fixture("print('x' * 100000)", byte_limit=100)

    def test_native_pipe_timeout_terminates_only_fixture_process(self):
        with self.assertRaisesRegex(linux.CollectionError, "query_timeout"):
            _run_controlled_pipe_fixture("import time; time.sleep(2)", timeout=0.05)


if __name__ == "__main__":
    unittest.main()
