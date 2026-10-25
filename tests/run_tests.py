#!/usr/bin/env python3
"""Run every tests/test_*.py like `python -m unittest discover -s tests -p "test_*.py" -v` and audit skips.

Usage, from the repository root:  python -I -S -B tests/run_tests.py [--report <path>]

The verbose unittest lines and the final "Ran N tests" / "OK" / "FAILED" lines are unchanged. Violations:
- a skip whose reason does not start with "only on <platforms>:" (a comma-separated subset of windows, linux, macos,
  posix, where posix means linux and macos), or whose list names the running platform;
- any skip raised by a class- or module-level fixture (setUpClass, setUpModule, tearDownClass, tearDownModule) or at
  module import (unittest.loader.ModuleSkipped), whatever its tag: tag the test methods or use a class decorator, so
  every test reports for itself;
- an expected failure, which hides a failing test;
- a run in which no test ran.
A JSON report goes to work/test-results/<platform>-py<major><minor>.json unless --report names another path (resolved
at start-up; an earlier report there is removed before the run). The summary line is always printed last. The exit
code is 0 only when nothing failed, nothing raised an error and there are no violations; it is 2 when the platform is
not supported or the report cannot be replaced or written. Standard library only.

Counts: "ran" equals unittest's testsRun (the "Ran N tests" line). The other counts are per report entry: one entry
per discovered test id, with its subtests folded into it (the worst outcome wins), plus one separate entry for each
class- or module-level fixture outcome (for example "setUpClass (module.Class)"). A test that never ran because such a
fixture skipped is "skipped" with the fixture's reason; a test that never ran for any other reason is an error,
"never ran". Expected failures and unexpected successes count as failed. So passed + failed + errors + skipped equals
the number of entries, and it can differ from "ran" and from unittest's own footer.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
from unittest.case import _SubTest  # the class TextTestResult itself uses to recognise subtests

TESTS = Path(os.path.abspath(os.path.dirname(__file__)))
ROOT = TESTS.parent
TAG = re.compile(r"^only on ((?:windows|linux|macos|posix)(?:\s*,\s*(?:windows|linux|macos|posix))*)\s*:")
FIXTURE = re.compile(r"^(setUpClass|setUpModule) \((.+)\)$")
MODULE_SKIPPED = "unittest.loader.ModuleSkipped."
FIXTURE_SKIP = "class- or module-level skip; tag the test methods or use a class decorator instead"
EXPECTED_FAILURE = "expected failure hides a failing test"
# Worst outcome wins when one test reports several times (for example through subtests).
RANK = {"ok": 0, "skipped": 1, "expected failure": 2, "unexpected success": 3, "fail": 4, "error": 5}


def platform_name(value: str | None = None) -> str:
    value = sys.platform if value is None else value
    if value == "win32":
        return "windows"
    if value.startswith("linux"):
        return "linux"
    if value == "darwin":
        return "macos"
    raise ValueError(f"unsupported platform {value!r}; the skip audit knows windows, linux and macos")


def tag_platforms(reason: str) -> set[str] | None:
    """Platforms named by the reason's "only on ...:" tag, or None when the reason has no valid tag."""
    match = TAG.match(reason)
    if not match:
        return None
    names = set()
    for name in re.split(r"\s*,\s*", match[1]):
        names |= {"linux", "macos"} if name == "posix" else {name}
    return names


def skip_problem(reason: str, platform: str) -> str | None:
    """Why a test-level skip with this reason is not allowed on this platform, or None when it is allowed."""
    names = tag_platforms(reason)
    if names is None:
        if reason.startswith("only on"):
            return "malformed platform tag"
        return "untagged skip"
    if platform in names:
        return f"skipped on {platform}, which its tag names"
    return None


def case_id(test) -> str:
    """module.Class.method (plus the subtest parameters) as the verbose line shows it, from unittest's own TestCase.id:
    a test may assign self.id, and a class may define an id constant or method."""
    if isinstance(test, _SubTest):
        return f"{case_id(test.test_case)} {test._subDescription()}"
    return unittest.TestCase.id(test) if isinstance(test, unittest.TestCase) else test.id()


def leaf_tests(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from leaf_tests(item)
        else:
            yield item


class AuditResult(unittest.TextTestResult):
    """The standard verbose result, also recording one outcome per test id, every skip and every expected failure."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes: dict[str, dict] = {}
        self.skips: list[tuple[str, str, bool]] = []  # (id, reason, raised by a class/module fixture or import)
        self.fixture_skips: dict[tuple[str, str], str] = {}  # ("setUpClass", module.Class) -> reason
        self.expected_failures: list[str] = []
        self.planned: list[tuple[str, str, str]] = []  # (id, module.Class, module) of every discovered test

    def _record(self, test, outcome, reason=None):
        owner = case_id(test.test_case if isinstance(test, _SubTest) else test)  # a subtest reports under its test
        entry = self.outcomes.setdefault(owner, {"id": owner, "outcome": None})
        if entry["outcome"] is None or RANK[outcome] > RANK[entry["outcome"]]:
            entry["outcome"] = outcome
            entry.pop("reason", None)
            if reason is not None:
                entry["reason"] = reason

    def startTest(self, test):
        super().startTest(test)
        self.outcomes.setdefault(case_id(test), {"id": case_id(test), "outcome": None})

    def addSuccess(self, test):
        super().addSuccess(test)
        self._record(test, "ok")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._record(test, "fail")

    def addError(self, test, err):
        super().addError(test, err)
        self._record(test, "error")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        reason, key = str(reason), case_id(test)
        fixture = not isinstance(test, unittest.TestCase)  # unittest's holder for a class/module fixture outcome
        if fixture and (match := FIXTURE.match(key)):
            self.fixture_skips[(match[1], match[2])] = reason
        self.skips.append((key, reason, fixture or key.startswith(MODULE_SKIPPED)))
        self._record(test, "skipped", reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.expected_failures.append(case_id(test))
        self._record(test, "expected failure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._record(test, "unexpected success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._record(test, "fail" if issubclass(err[0], subtest.failureException) else "error")


def run_suite(suite: unittest.TestSuite, stream) -> AuditResult:
    """Run the suite with the settings `python -m unittest -v` uses, after listing its tests (running empties it)."""
    planned = [(case_id(t), f"{type(t).__module__}.{type(t).__qualname__}", type(t).__module__)
               for t in leaf_tests(suite)]
    runner = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=AuditResult,
                                     warnings=None if sys.warnoptions else "default")
    result = runner.run(suite)
    result.planned = planned
    return result


def git_state() -> tuple[str | None, bool | None]:
    """HEAD and whether the working tree differs from it, only when this repository is git's top level (a copy
    unpacked inside another checkout must not report that checkout); None for whatever git cannot tell (git is never
    required)."""
    git = shutil.which("git")
    if not git:
        return None, None

    def ask(*args):
        try:
            done = subprocess.run([git, "--no-optional-locks", *args], cwd=ROOT, stdin=subprocess.DEVNULL,
                                  capture_output=True, encoding="utf-8", errors="replace", timeout=60)
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout if done.returncode == 0 else None

    top = (ask("rev-parse", "--show-toplevel") or "").strip()
    try:
        own = bool(top) and os.path.samefile(top, ROOT)
    except OSError:
        own = False
    commit = (ask("rev-parse", "HEAD") or "").strip() if own else ""
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        return None, None
    status = ask("status", "--porcelain")
    return commit, None if status is None else bool(status.strip())


def build_report(result: AuditResult, platform: str, python: str, commit: str | None, dirty: bool | None) -> dict:
    remaining = dict(result.outcomes)
    tests = []
    for key, cls, module in dict.fromkeys(result.planned):
        entry = remaining.pop(key, None)
        if entry is None:
            reason = result.fixture_skips.get(("setUpClass", cls), result.fixture_skips.get(("setUpModule", module)))
            entry = ({"id": key, "outcome": "skipped", "reason": reason} if reason is not None
                     else {"id": key, "outcome": "error", "reason": "never ran"})
        tests.append(entry)
    tests.extend(remaining.values())  # class- and module-level fixture outcomes
    tests = [dict(entry) if entry["outcome"] is not None  # started but never reported: count it, never pass it
             else {"id": entry["id"], "outcome": "error", "reason": "no outcome recorded"} for entry in tests]
    violations = []
    for key, reason, fixture in result.skips:
        if problem := (FIXTURE_SKIP if fixture else skip_problem(reason, platform)):
            violations.append({"test": key, "reason": reason, "problem": problem})
    violations += [{"test": key, "reason": None, "problem": EXPECTED_FAILURE} for key in result.expected_failures]
    if result.testsRun == 0:
        violations.append({"test": None, "reason": None, "problem": "no tests ran"})
    tally = Counter(test["outcome"] for test in tests)
    return {
        "platform": platform,
        "python": python,
        "commit": commit,
        "dirty": dirty,
        "counts": {
            "ran": result.testsRun,
            "passed": tally["ok"],
            "failed": tally["fail"] + tally["expected failure"] + tally["unexpected success"],
            "errors": tally["error"],
            "skipped": tally["skipped"],
            "violations": len(violations),
        },
        "tests": tests,
        "violations": violations,
    }


def summary_line(report: dict) -> str:
    c = report["counts"]
    return (f"PLATFORM {report['platform']} PY {report['python']}: ran={c['ran']} passed={c['passed']} "
            f"failed={c['failed']} errors={c['errors']} skipped={c['skipped']} violations={c['violations']}")


def exit_status(report: dict) -> int:
    c = report["counts"]
    return 0 if c["failed"] == 0 and c["errors"] == 0 and c["violations"] == 0 else 1


def main(argv: list[str] | None = None, *, sys_platform: str | None = None) -> int:
    """Exit 0, 1 (failures, errors or violations) or 2 (the run or its report was not possible)."""
    parser = argparse.ArgumentParser(description="Run the PatchCairn unit tests and audit their skips.",
                                     allow_abbrev=False)
    parser.add_argument("--report", help="JSON report path (default work/test-results/<platform>-py<version>.json)")
    args = parser.parse_args(argv)
    try:
        platform = platform_name(sys_platform)
    except ValueError as error:
        print(f"run_tests: {error}", file=sys.stderr)
        return 2
    major, minor, micro = sys.version_info[:3]
    shown = args.report or f"work/test-results/{platform}-py{major}{minor}.json"
    path = Path(args.report).absolute() if args.report else ROOT / shown  # fixed before a test can change folder
    try:
        path.unlink(missing_ok=True)  # an interrupted run must not leave an earlier report looking current
    except OSError as error:
        print(f"run_tests: cannot replace the report {shown}: {error.strerror or error}", file=sys.stderr)
        return 2
    commit, dirty = git_state()  # the tree as tested, before any test writes a file

    suite = unittest.TestLoader().discover(str(TESTS), pattern="test_*.py")
    result = run_suite(suite, sys.stderr)
    report = build_report(result, platform, f"{major}.{minor}.{micro}", commit, dirty)
    line, status = summary_line(report), exit_status(report)

    if hasattr(sys.stdout, "reconfigure"):  # a skip reason must never crash the summary
        sys.stdout.reconfigure(errors="backslashreplace")
    for item in report["violations"]:
        reason = "" if item["reason"] is None else f": {item['reason']!r}"
        print(f"VIOLATION {item['test'] or '(run)'}: {item['problem']}{reason}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"REPORT {shown}")
    except OSError as error:
        print(f"REPORT NOT WRITTEN {shown}: {error.strerror or error}")
        status = 2
    print(line, flush=True)  # always the last line
    return status


if __name__ == "__main__":
    sys.exit(main())
