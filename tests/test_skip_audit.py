#!/usr/bin/env python3
"""Fictional checks for tests/run_tests.py: the skip audit, the report and unittest-identical output.

Synthetic suites are built inside each test (never at module level, so discovery cannot pick them up) and run with
a simulated platform, so every rule is exercised on every operating system. Colour settings (FORCE_COLOR, NO_COLOR,
PYTHON_COLORS) are neutralised for every compared run, in process and in subprocesses. Fixture folders live under
work/test-fixtures/ and each test removes only its own. None of these tests skips.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import textwrap
import types
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
TESTS = Path(__file__).absolute().parent
ROOT = TESTS.parent
sys.path.insert(0, str(TESTS))
import run_tests  # noqa: E402

PLATFORMS = ("windows", "linux", "macos")
HERE = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
VERSION = "%d.%d.%d" % sys.version_info[:3]


def case(name, module="synthetic", **methods):
    """A synthetic TestCase class in a fictional module (absent from sys.modules unless a test adds it: no fixtures)."""
    return type(name, (unittest.TestCase,), {"__module__": module, "__qualname__": name, **methods})


def skipper(reason):
    return lambda self: self.skipTest(reason)


COLOUR_FORCING = ("FORCE_COLOR", "PYTHON_COLORS", "CLICOLOR_FORCE")


def plain_env():
    """This process's environment with colour forcing removed and NO_COLOR set (it wins even under -I)."""
    env = {name: value for name, value in os.environ.items() if name not in COLOUR_FORCING}
    env["NO_COLOR"] = "1"
    return env


@contextlib.contextmanager
def no_colour():
    with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):  # restores the whole environment afterwards
        for name in COLOUR_FORCING:
            os.environ.pop(name, None)
        yield


def suite_of(*cases):
    return unittest.TestSuite(unittest.TestLoader().loadTestsFromTestCase(c) for c in cases)


def run(*cases):
    stream = io.StringIO()
    with no_colour():
        result = run_tests.run_suite(suite_of(*cases), stream)
    return result, stream.getvalue()


def fixture_dir(test):
    """A new folder under work/test-fixtures/ that only this test owns, removed when the test ends."""
    path = ROOT / "work" / "test-fixtures" / f"skip-audit-{uuid.uuid4().hex}"
    path.mkdir(parents=True)
    test.addCleanup(shutil.rmtree, path)
    return path


def report(result, platform):
    return run_tests.build_report(result, platform, "3.99.0", None, None)


def timeless(text):
    return re.sub(r"(?m)^(Ran \d+ tests?) in [\d.]+s$", r"\1", text)


class PlatformTests(unittest.TestCase):
    def test_platform_names_come_from_sys_platform(self):
        self.assertEqual(run_tests.platform_name("win32"), "windows")
        self.assertEqual(run_tests.platform_name("linux"), "linux")
        self.assertEqual(run_tests.platform_name("darwin"), "macos")
        self.assertEqual(run_tests.platform_name(), HERE)
        for other in ("cygwin", "freebsd14", "emscripten", ""):
            with self.subTest(other=other), self.assertRaisesRegex(ValueError, "unsupported platform"):
                run_tests.platform_name(other)

    def test_unsupported_platform_exits_2_before_running_anything(self):
        stderr = io.StringIO()
        before = sys.platform
        with mock.patch.object(run_tests.unittest.TestLoader, "discover", side_effect=AssertionError("ran")), \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(run_tests.main([], sys_platform="cygwin"), 2)  # injected: sys.platform is untouched
        self.assertIn("unsupported platform 'cygwin'", stderr.getvalue())
        self.assertEqual(sys.platform, before)


class SkipRuleTests(unittest.TestCase):
    def test_untagged_skip_is_a_violation_on_every_platform(self):
        for platform in PLATFORMS:
            for reason in ("Native symlink capability unavailable", "", "windows only", "only windows: x"):
                with self.subTest(platform=platform, reason=reason):
                    self.assertEqual(run_tests.skip_problem(reason, platform), "untagged skip")

    def test_tag_naming_other_platforms_is_allowed(self):
        self.assertIsNone(run_tests.skip_problem("only on windows: NTFS junctions", "linux"))
        self.assertIsNone(run_tests.skip_problem("only on windows: NTFS junctions", "macos"))
        self.assertIsNone(run_tests.skip_problem("only on linux, macos: FIFOs", "windows"))
        self.assertIsNone(run_tests.skip_problem("only on windows,linux : x", "macos"))

    def test_tag_naming_the_running_platform_is_a_violation(self):
        for reason, platform in (("only on windows: x", "windows"), ("only on linux: x", "linux"),
                                 ("only on macos: x", "macos"), ("only on windows, linux: x", "linux")):
            with self.subTest(reason=reason, platform=platform):
                self.assertEqual(run_tests.skip_problem(reason, platform),
                                 f"skipped on {platform}, which its tag names")

    def test_posix_means_linux_and_macos(self):
        self.assertEqual(run_tests.tag_platforms("only on posix: x"), {"linux", "macos"})
        self.assertEqual(run_tests.tag_platforms("only on windows, posix: x"), {"windows", "linux", "macos"})
        self.assertIsNone(run_tests.skip_problem("only on posix: x", "windows"))
        self.assertIsNotNone(run_tests.skip_problem("only on posix: x", "linux"))
        self.assertIsNotNone(run_tests.skip_problem("only on posix: x", "macos"))

    def test_malformed_tags_are_violations(self):
        for reason in ("only on windows", "only on win32: x", "only on : x", "only on windows,: x",
                       "only on windows linux: x", "only on posix;linux: x", "only on Windows: x",
                       "only onwindows: x", "only on darwin: x"):
            for platform in PLATFORMS:
                with self.subTest(reason=reason, platform=platform):
                    self.assertEqual(run_tests.skip_problem(reason, platform), "malformed platform tag")
        for reason in ("Only on windows: x", " only on windows: x"):
            with self.subTest(reason=reason):
                self.assertEqual(run_tests.skip_problem(reason, "linux"), "untagged skip")


class SyntheticSuiteTests(unittest.TestCase):
    def test_untagged_skip_fails_the_run(self):
        result, _ = run(case("Untagged", test_ok=lambda self: None,
                             test_skip=skipper("Native capability unavailable")))
        for platform in PLATFORMS:
            with self.subTest(platform=platform):
                audit = report(result, platform)
                self.assertEqual(audit["violations"], [{"test": "synthetic.Untagged.test_skip",
                                                        "reason": "Native capability unavailable",
                                                        "problem": "untagged skip"}])
                self.assertEqual(run_tests.exit_status(audit), 1)

    def test_tagged_skip_passes_elsewhere_and_fails_where_it_is_named(self):
        result, _ = run(case("Tagged", test_ok=lambda self: None, test_skip=skipper("only on windows: junctions")))
        for platform, expected in (("linux", 0), ("macos", 0), ("windows", 1)):
            with self.subTest(platform=platform):
                audit = report(result, platform)
                self.assertEqual(audit["counts"]["violations"], expected)
                self.assertEqual(run_tests.exit_status(audit), expected)

    def test_posix_tagged_skip_runs_on_linux_and_macos(self):
        result, _ = run(case("Posix", test_skip=skipper("only on posix: FIFOs")))
        self.assertEqual(report(result, "windows")["counts"]["violations"], 0)
        self.assertEqual(report(result, "linux")["counts"]["violations"], 1)
        self.assertEqual(report(result, "macos")["counts"]["violations"], 1)

    def test_malformed_tag_fails_the_run(self):
        result, _ = run(case("Malformed", test_skip=skipper("only on win32: x")))
        audit = report(result, "linux")
        self.assertEqual([v["problem"] for v in audit["violations"]], ["malformed platform tag"])
        self.assertEqual(run_tests.exit_status(audit), 1)

    def test_class_level_skip_is_a_violation_whatever_its_tag_and_its_tests_are_listed(self):
        def class_skip(cls):
            raise unittest.SkipTest("only on linux: fictional private folders")

        result, _ = run(case("ClassSkip", setUpClass=classmethod(class_skip), test_a=lambda self: None,
                             test_b=lambda self: None), case("Runs", test_ok=lambda self: None))
        for platform in PLATFORMS:  # the tag would allow the skip on windows and macos; a fixture skip never is
            with self.subTest(platform=platform):
                audit = report(result, platform)
                self.assertEqual(audit["violations"], [{"test": "setUpClass (synthetic.ClassSkip)",
                                                        "reason": "only on linux: fictional private folders",
                                                        "problem": run_tests.FIXTURE_SKIP}])
                self.assertEqual(audit["tests"], [
                    {"id": "synthetic.ClassSkip.test_a", "outcome": "skipped",
                     "reason": "only on linux: fictional private folders"},
                    {"id": "synthetic.ClassSkip.test_b", "outcome": "skipped",
                     "reason": "only on linux: fictional private folders"},
                    {"id": "synthetic.Runs.test_ok", "outcome": "ok"},
                    {"id": "setUpClass (synthetic.ClassSkip)", "outcome": "skipped",
                     "reason": "only on linux: fictional private folders"}])
                self.assertEqual(audit["counts"], {"ran": 1, "passed": 1, "failed": 0, "errors": 0, "skipped": 3,
                                                   "violations": 1})
                self.assertEqual(run_tests.exit_status(audit), 1)

    def test_module_level_skip_is_a_violation_whatever_its_tag(self):
        def module_skip():
            raise unittest.SkipTest("only on macos: fictional module fixture")

        fixture_module = types.ModuleType("synthetic_skipped")
        fixture_module.setUpModule = module_skip
        with mock.patch.dict(sys.modules, {"synthetic_skipped": fixture_module}):
            result, _ = run(case("InSkipped", module="synthetic_skipped", test_x=lambda self: None),
                            case("Runs", test_ok=lambda self: None))
        audit = report(result, "windows")
        self.assertEqual([(v["test"], v["problem"]) for v in audit["violations"]],
                         [("setUpModule (synthetic_skipped)", run_tests.FIXTURE_SKIP)])
        self.assertEqual({t["id"]: (t["outcome"], t.get("reason")) for t in audit["tests"]}, {
            "synthetic_skipped.InSkipped.test_x": ("skipped", "only on macos: fictional module fixture"),
            "synthetic.Runs.test_ok": ("ok", None),
            "setUpModule (synthetic_skipped)": ("skipped", "only on macos: fictional module fixture")})

    def test_tests_that_never_ran_for_another_reason_are_errors(self):
        def broken(cls):
            raise RuntimeError("fictional class fixture failure")

        result, _ = run(case("Broken", setUpClass=classmethod(broken), test_a=lambda self: None,
                             test_b=lambda self: None), case("Runs", test_ok=lambda self: None))
        audit = report(result, HERE)
        self.assertEqual({t["id"]: (t["outcome"], t.get("reason")) for t in audit["tests"]}, {
            "synthetic.Broken.test_a": ("error", "never ran"), "synthetic.Broken.test_b": ("error", "never ran"),
            "synthetic.Runs.test_ok": ("ok", None), "setUpClass (synthetic.Broken)": ("error", None)})
        self.assertEqual(audit["counts"], {"ran": 1, "passed": 1, "failed": 0, "errors": 3, "skipped": 0,
                                           "violations": 0})
        self.assertEqual(run_tests.exit_status(audit), 1)

    def test_subtest_skips_and_apostrophe_reasons_are_audited(self):
        def subtest_skip(self):
            for value in (1, 2):
                with self.subTest(value=value):
                    if value == 2:
                        self.skipTest("only on macos: can't run here")

        result, output = run(case("Quoted", test_sub=subtest_skip,
                                  test_tagged=skipper("only on posix: Windows can't make FIFOs"),
                                  test_untagged=skipper("can't make FIFOs")))
        self.assertIn("test_tagged (synthetic.Quoted.test_tagged) ... skipped \"only on posix: Windows can't make "
                      "FIFOs\"\n", output)
        self.assertIn("  test_sub (synthetic.Quoted.test_sub) (value=2) ... skipped \"only on macos: can't run here\"",
                      output)
        expected = {"windows": [("synthetic.Quoted.test_untagged", "untagged skip")],
                    "linux": [("synthetic.Quoted.test_tagged", "skipped on linux, which its tag names"),
                              ("synthetic.Quoted.test_untagged", "untagged skip")],
                    "macos": [("synthetic.Quoted.test_sub (value=2)", "skipped on macos, which its tag names"),
                              ("synthetic.Quoted.test_tagged", "skipped on macos, which its tag names"),
                              ("synthetic.Quoted.test_untagged", "untagged skip")]}
        for platform, problems in expected.items():
            with self.subTest(platform=platform):
                audit = report(result, platform)
                self.assertEqual(sorted((v["test"], v["problem"]) for v in audit["violations"]), problems)
                self.assertIn({"id": "synthetic.Quoted.test_sub", "outcome": "skipped",
                               "reason": "only on macos: can't run here"}, audit["tests"])

    def test_expected_failure_is_a_violation_and_unexpected_success_a_failure(self):
        expected = case("Expected", test_hidden=unittest.expectedFailure(lambda self: self.fail("known")))
        audit = report(run(expected)[0], HERE)
        self.assertEqual(audit["violations"], [{"test": "synthetic.Expected.test_hidden", "reason": None,
                                                "problem": "expected failure hides a failing test"}])
        self.assertEqual(audit["counts"], {"ran": 1, "passed": 0, "failed": 1, "errors": 0, "skipped": 0,
                                           "violations": 1})
        self.assertEqual(run_tests.exit_status(audit), 1)
        unexpected = case("Unexpected", test_fixed=unittest.expectedFailure(lambda self: None))
        audit = report(run(unexpected)[0], HERE)
        self.assertEqual((audit["counts"]["passed"], audit["counts"]["failed"], audit["violations"]), (0, 1, []))
        self.assertEqual(run_tests.exit_status(audit), 1)

    def test_ids_come_from_the_class_when_a_test_assigns_self_id(self):
        # tests/test_diagnostic_core.py assigns self.id in setUp; unittest itself never calls id() while reporting.
        def setup(self):
            self.id = "fictional-request-id"

        def sub_fail(self):
            with self.subTest(part=1):
                self.fail("fictional")

        result, _ = run(case("Shadowed", setUp=setup, test_a=lambda self: None, test_b=sub_fail,
                             test_c=skipper("untagged")))
        audit = report(result, HERE)
        self.assertEqual([(t["id"], t["outcome"]) for t in audit["tests"]],
                         [("synthetic.Shadowed.test_a", "ok"), ("synthetic.Shadowed.test_b", "fail"),
                          ("synthetic.Shadowed.test_c", "skipped")])
        self.assertEqual([v["test"] for v in audit["violations"]], ["synthetic.Shadowed.test_c"])

    def test_class_id_constant_or_method_neither_crashes_nor_renames(self):
        result, output = run(case("Constant", id="fictional-id", test_a=lambda self: None),
                             case("Method", id=lambda self: "custom", test_b=skipper("untagged")))
        audit = report(result, HERE)
        self.assertEqual([(t["id"], t["outcome"]) for t in audit["tests"]],
                         [("synthetic.Constant.test_a", "ok"), ("synthetic.Method.test_b", "skipped")])
        self.assertEqual([v["test"] for v in audit["violations"]], ["synthetic.Method.test_b"])
        self.assertIn("test_b (synthetic.Method.test_b) ... skipped 'untagged'", output)  # the id the log shows

    def test_report_counts_outcomes_and_summary(self):
        def subtest_fail(self):
            for value in (1, 2):
                with self.subTest(value=value):
                    self.assertEqual(value, 2)

        def raises(self):
            raise RuntimeError("fictional")

        mixed = case("Mixed", test_a_ok=lambda self: None, test_b_fail=lambda self: self.fail("fictional"),
                     test_c_error=raises, test_d_tagged=skipper("only on linux: fictional"),
                     test_e_untagged=skipper("fictional capability missing"),
                     test_f_expected=unittest.expectedFailure(lambda self: self.fail("known")),
                     test_g_unexpected=unittest.expectedFailure(lambda self: None),
                     test_h_subtests=subtest_fail)
        result, _ = run(mixed)
        audit = report(result, "windows")
        self.assertEqual(json.loads(json.dumps(audit)), audit)
        self.assertEqual((audit["platform"], audit["python"], audit["commit"], audit["dirty"]),
                         ("windows", "3.99.0", None, None))
        self.assertEqual(audit["counts"], {"ran": 8, "passed": 1, "failed": 4, "errors": 1, "skipped": 2,
                                           "violations": 2})
        self.assertEqual(audit["tests"], [
            {"id": "synthetic.Mixed.test_a_ok", "outcome": "ok"},
            {"id": "synthetic.Mixed.test_b_fail", "outcome": "fail"},
            {"id": "synthetic.Mixed.test_c_error", "outcome": "error"},
            {"id": "synthetic.Mixed.test_d_tagged", "outcome": "skipped", "reason": "only on linux: fictional"},
            {"id": "synthetic.Mixed.test_e_untagged", "outcome": "skipped", "reason": "fictional capability missing"},
            {"id": "synthetic.Mixed.test_f_expected", "outcome": "expected failure"},
            {"id": "synthetic.Mixed.test_g_unexpected", "outcome": "unexpected success"},
            {"id": "synthetic.Mixed.test_h_subtests", "outcome": "fail"},
        ])
        self.assertEqual(audit["violations"], [
            {"test": "synthetic.Mixed.test_e_untagged", "reason": "fictional capability missing",
             "problem": "untagged skip"},
            {"test": "synthetic.Mixed.test_f_expected", "reason": None,
             "problem": "expected failure hides a failing test"}])
        self.assertEqual(run_tests.summary_line(audit),
                         "PLATFORM windows PY 3.99.0: ran=8 passed=1 failed=4 errors=1 skipped=2 violations=2")

    def test_failures_and_errors_fail_the_run_without_skips(self):
        def raises(self):
            raise RuntimeError("fictional")

        for name, method, expected in (("Passing", lambda self: None, 0), ("Failing", lambda self: self.fail("x"), 1),
                                       ("Erroring", raises, 1)):
            with self.subTest(name=name):
                result, _ = run(case(name, test_one=method))
                audit = report(result, HERE)
                self.assertEqual(audit["counts"]["violations"], 0)
                self.assertEqual(run_tests.exit_status(audit), expected)

    def test_empty_run_is_a_violation(self):
        result, _ = run()
        audit = report(result, HERE)
        self.assertEqual(audit["violations"], [{"test": None, "reason": None, "problem": "no tests ran"}])
        self.assertEqual(run_tests.exit_status(audit), 1)

    def test_verbose_output_is_unittests_own(self):
        def documented(self):
            """A docstring's first line is shown under the test name."""

        cases = (case("Lines", test_a=documented, test_b=lambda self: self.fail("fictional"),
                      test_c=skipper("untagged 'quoted' reason")),)
        _, audited = run(*cases)
        plain = io.StringIO()
        with no_colour():
            unittest.TextTestRunner(stream=plain, verbosity=2).run(suite_of(*cases))
        self.assertEqual(timeless(audited), timeless(plain.getvalue()))
        self.assertIn("test_c (synthetic.Lines.test_c) ... skipped \"untagged 'quoted' reason\"\n", audited)
        self.assertRegex(audited, r"(?m)^Ran 3 tests in [\d.]+s\n\nFAILED \(failures=1, skipped=1\)$")

    def test_colour_settings_cannot_change_the_audited_text(self):
        cases = (case("Colour", test_a=lambda self: None, test_b=skipper("only on posix: fictional")),)
        with mock.patch.dict(os.environ, {"FORCE_COLOR": "1"}):
            os.environ.pop("NO_COLOR", None)
            forced = io.StringIO()
            unittest.TextTestRunner(stream=forced, verbosity=2).run(suite_of(*cases))
            _, audited = run(*cases)
        if sys.version_info >= (3, 14):  # unittest colours its output from 3.14 on: the premise must hold there
            self.assertIn("\x1b[", forced.getvalue())
        self.assertNotIn("\x1b[", audited)
        self.assertIn("test_b (synthetic.Colour.test_b) ... skipped 'only on posix: fictional'\n", audited)


class GitStateTests(unittest.TestCase):
    SHA = "0123456789abcdef" * 2 + "01234567"

    def state(self, which="git", top=None, head=(0, SHA + "\n"), status=(0, "")):
        top = (0, str(ROOT) + "\n") if top is None else top
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            answer = top if "--show-toplevel" in args else head if "HEAD" in args else status
            if isinstance(answer, Exception):
                raise answer
            return subprocess.CompletedProcess(args, answer[0], answer[1], "")

        with mock.patch.object(run_tests.shutil, "which", return_value=which), \
                mock.patch.object(run_tests.subprocess, "run", side_effect=fake_run):
            return run_tests.git_state(), calls

    def test_commit_and_dirty_come_from_git_without_index_writes(self):
        self.assertEqual(self.state()[0], (self.SHA, False))
        state, calls = self.state(status=(0, " M tests/run_tests.py\n?? new.txt\n"))
        self.assertEqual(state, (self.SHA, True))
        self.assertEqual(calls, [["git", "--no-optional-locks", "rev-parse", "--show-toplevel"],
                                 ["git", "--no-optional-locks", "rev-parse", "HEAD"],
                                 ["git", "--no-optional-locks", "status", "--porcelain"]])

    def test_another_checkouts_commit_is_never_reported(self):
        for top in ((0, str(ROOT.parent) + "\n"), (0, str(ROOT / "missing-fictional-folder") + "\n"), (128, ""),
                    (0, "\n"), OSError("fictional")):
            with self.subTest(top=top):
                state, calls = self.state(top=top)
                self.assertEqual(state, (None, None))
                self.assertEqual(len(calls), 1)  # HEAD and status are never asked

    def test_unknown_answers_stay_unknown(self):
        self.assertEqual(self.state(which=None)[0], (None, None))
        self.assertEqual(self.state(head=(128, ""))[0], (None, None))
        self.assertEqual(self.state(head=(0, "not a commit\n"))[0], (None, None))
        self.assertEqual(self.state(head=OSError("fictional"))[0], (None, None))
        self.assertEqual(self.state(status=(128, ""))[0], (self.SHA, None))
        self.assertEqual(self.state(status=subprocess.TimeoutExpired("git", 60))[0], (self.SHA, None))

    def test_this_checkout_matches_what_git_itself_says(self):
        git, expected = shutil.which("git"), (None, None)
        if git:
            def ask(*args):
                return subprocess.run([git, "--no-optional-locks", "-C", str(ROOT), *args], capture_output=True,
                                      encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL, timeout=60)

            top, head = ask("rev-parse", "--show-toplevel"), ask("rev-parse", "HEAD")
            status = ask("status", "--porcelain")
            if top.returncode == 0 and head.returncode == 0 and os.path.samefile(top.stdout.strip(), ROOT):
                expected = (head.stdout.strip(), None if status.returncode else bool(status.stdout.strip()))
        self.assertEqual(run_tests.git_state(), expected)


class MainTests(unittest.TestCase):
    """run_tests.main in process, with a small synthetic suite in place of discovery."""

    SUMMARY = f"PLATFORM {HERE} PY {VERSION}: ran=2 passed=1 failed=0 errors=0 skipped=1 violations=1"

    def call(self, *argv, write_error=None, git=(None, None)):
        def discover(*args, **kwargs):
            return suite_of(case("Main", test_ok=lambda self: None, test_skip=skipper("untagged")))

        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(run_tests.unittest.TestLoader, "discover", side_effect=discover))
            stack.enter_context(mock.patch.object(run_tests, "git_state", return_value=git))
            if write_error is not None:
                stack.enter_context(mock.patch.object(run_tests.Path, "write_text", side_effect=write_error))
            stack.enter_context(no_colour())
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            code = run_tests.main(list(argv))
        return code, out.getvalue().splitlines(), err.getvalue()

    def test_summary_is_the_last_line_after_the_report_is_written(self):
        target = fixture_dir(self) / "report.json"
        code, lines, err = self.call("--report", str(target), git=(GitStateTests.SHA, True))
        self.assertEqual((code, lines), (1, ["VIOLATION synthetic.Main.test_skip: untagged skip: 'untagged'",
                                             f"REPORT {target}", self.SUMMARY]))
        self.assertIn("Ran 2 tests", err)
        saved = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual((saved["commit"], saved["dirty"], saved["counts"]["violations"]), (GitStateTests.SHA, True, 1))

    def test_failed_report_write_exits_2_and_still_prints_the_summary_last(self):
        target = fixture_dir(self) / "report.json"
        code, lines, _ = self.call("--report", str(target), write_error=OSError(13, "fictional denial"))
        self.assertEqual(code, 2)
        self.assertEqual(lines[-2:], [f"REPORT NOT WRITTEN {target}: fictional denial", self.SUMMARY])
        self.assertFalse(target.exists())

    def test_report_that_cannot_be_replaced_stops_before_any_test(self):
        folder = fixture_dir(self)  # an existing folder where the report file would go
        code, lines, err = self.call("--report", str(folder))
        self.assertEqual((code, lines), (2, []))
        self.assertIn("cannot replace the report", err)
        self.assertNotIn("Ran ", err)
        self.assertTrue(folder.is_dir())


class CommandLineTests(unittest.TestCase):
    """Runs a copy of the runner on a fictional tests folder inside an owned folder under work/test-fixtures/."""

    FIXTURE = textwrap.dedent('''\
        import sys
        import unittest

        HERE = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
        OTHER = "posix" if HERE == "windows" else "windows"


        class Fixture(unittest.TestCase):
            def test_passes(self):
                """A docstring's first line is shown too."""

            def test_other_platform(self):
                self.skipTest(f"only on {OTHER}: fictional native fixture")
        ''')

    def setUp(self):
        self.root = fixture_dir(self)
        (self.root / "tests").mkdir()
        shutil.copyfile(TESTS / "run_tests.py", self.root / "tests" / "run_tests.py")

    def write(self, extra=""):
        (self.root / "tests" / "test_fixture.py").write_text(self.FIXTURE + textwrap.dedent(extra), encoding="utf-8")

    def python(self, *args):
        return subprocess.run([sys.executable, "-I", "-S", "-B", *args], cwd=self.root, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, errors="replace", timeout=120, env=plain_env())

    def test_fixture_folder_is_under_work_test_fixtures_and_removed_afterwards(self):
        self.assertEqual(self.root.parent, ROOT / "work" / "test-fixtures")
        self.assertRegex(self.root.name, r"^skip-audit-[0-9a-f]{32}$")
        self.doCleanups()
        self.assertFalse(self.root.exists())
        self.assertTrue(self.root.parent.is_dir())  # the shared parent stays for other tests

    def test_clean_suite_exits_0_and_writes_the_default_report(self):
        self.write()
        done = self.python("tests/run_tests.py")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        name = f"work/test-results/{HERE}-py{sys.version_info[0]}{sys.version_info[1]}.json"
        self.assertEqual(done.stdout.splitlines(), [
            f"REPORT {name}",
            f"PLATFORM {HERE} PY {VERSION}: ran=2 passed=1 failed=0 errors=0 skipped=1 violations=0"])
        saved = json.loads((self.root / name).read_text(encoding="utf-8"))
        self.assertEqual((saved["platform"], saved["python"], saved["violations"]), (HERE, VERSION, []))
        self.assertEqual(saved["counts"], {"ran": 2, "passed": 1, "failed": 0, "errors": 0, "skipped": 1,
                                           "violations": 0})
        self.assertEqual([t["outcome"] for t in saved["tests"]], ["skipped", "ok"])
        self.assertEqual((saved["commit"], saved["dirty"]), (None, None))  # the copy is not git's top level

    def test_colour_settings_do_not_reach_the_compared_subprocess_output(self):
        self.write()
        with mock.patch.dict(os.environ, {"FORCE_COLOR": "1"}):
            os.environ.pop("NO_COLOR", None)
            done = self.python("tests/run_tests.py")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertNotIn("\x1b[", done.stdout + done.stderr)
        self.assertIn("test_passes (test_fixture.Fixture.test_passes)\nA docstring's first line is shown too. ... ok\n",
                      done.stderr)

    def test_relative_report_path_is_fixed_at_start_and_an_old_report_is_removed_first(self):
        self.write('''
            import os

            START = os.getcwd()


            class Moves(unittest.TestCase):
                def test_old_report_is_gone_during_the_run(self):
                    self.assertFalse(os.path.exists(os.path.join(START, "out", "custom.json")))

                def test_z_leaks_a_folder_change(self):
                    os.chdir(os.path.join(START, "tests"))
            ''')
        (self.root / "out").mkdir()
        (self.root / "out" / "custom.json").write_text("stale report from an earlier run", encoding="utf-8")
        done = self.python("tests/run_tests.py", "--report", "out/custom.json")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        saved = json.loads((self.root / "out" / "custom.json").read_text(encoding="utf-8"))
        self.assertEqual((saved["counts"]["ran"], saved["counts"]["passed"]), (4, 3))
        self.assertFalse((self.root / "tests" / "out").exists())

    def test_module_skipped_at_import_is_a_violation_whatever_its_tag(self):
        self.write()
        (self.root / "tests" / "test_skipped_module.py").write_text(textwrap.dedent('''\
            import sys
            import unittest

            OTHER = "posix" if sys.platform == "win32" else "windows"
            raise unittest.SkipTest(f"only on {OTHER}: fictional module")
            '''), encoding="utf-8")
        plain = self.python("-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v")
        audited = self.python("tests/run_tests.py")
        self.assertEqual((plain.returncode, audited.returncode), (0, 1), audited.stdout + audited.stderr)
        self.assertEqual(timeless(audited.stderr), timeless(plain.stderr))
        self.assertIn("VIOLATION unittest.loader.ModuleSkipped.test_skipped_module: " + run_tests.FIXTURE_SKIP,
                      audited.stdout)
        self.assertIn(": ran=3 passed=1 failed=0 errors=0 skipped=2 violations=1", audited.stdout)

    def test_untagged_skip_alone_exits_1(self):
        self.write('''
            class Untagged(unittest.TestCase):
                def test_capability(self):
                    self.skipTest("fictional capability unavailable")
            ''')
        done = self.python("tests/run_tests.py")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("VIOLATION test_fixture.Untagged.test_capability: untagged skip: "
                      "'fictional capability unavailable'", done.stdout)
        self.assertIn(": ran=3 passed=1 failed=0 errors=0 skipped=2 violations=1", done.stdout)

    def test_output_matches_unittest_discover_and_report_path_is_honoured(self):
        self.write('''
            class Mixed(unittest.TestCase):
                def test_fails(self):
                    self.assertEqual(1, 2)

                def test_raises(self):
                    raise RuntimeError("fictional")

                def test_named_platform(self):
                    self.skipTest(f"only on {HERE}: fictional")

                def test_warns(self):
                    import warnings
                    warnings.warn("fictional deprecation", DeprecationWarning)
            ''')
        plain = self.python("-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v")
        audited = self.python("tests/run_tests.py", "--report", "out/custom.json")
        self.assertEqual((plain.returncode, audited.returncode), (1, 1), audited.stdout + audited.stderr)
        self.assertEqual(timeless(audited.stderr), timeless(plain.stderr))
        self.assertIn("test_named_platform (test_fixture.Mixed.test_named_platform) ... skipped", audited.stderr)
        self.assertIn("DeprecationWarning: fictional deprecation", audited.stderr)  # unittest's warning filter
        self.assertIn("REPORT out/custom.json", audited.stdout)
        saved = json.loads((self.root / "out" / "custom.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["counts"], {"ran": 6, "passed": 2, "failed": 1, "errors": 1, "skipped": 2,
                                           "violations": 1})
        self.assertFalse((self.root / "work").exists())


if __name__ == "__main__":
    unittest.main()
