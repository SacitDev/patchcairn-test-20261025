"""A real process kill (never an in-process exception) at a fixed point of a package run, then reconciliation. Selected synthetic
work copies only: each child is this interpreter (sys.executable -I -S -B) running a fictional fixture, the product's run_ticket
with a fake package route and a fake child. No package manager, installer or other program ever starts here. The operating system
frees a killed process's locks, so reconciliation follows the kill with no cleaning step. Also the locks themselves: a live holder
refuses a second process, and a lock is never handed on to a child.
"""
from __future__ import annotations
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import engine_text
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, held_lock, write_private_new
from service_state import package_rows
from workflow_core import PrivacyCapabilityHold, WorkflowRefusal
from workflow_service import ServiceRefusal
import test_packages
from test_packages import REINSTALL, REPAIR, UPGRADE, fake_payload, fake_route, refusals_fail, registered, remove_fixture_roots
from test_service_state import SessionFixtures
from test_service_updates import Harness, OPERATION

# The child: at spec["point"] it writes a marker, after the effect boundary ("child": while its fake child runs; "exit": right after
# the child's exit was recorded), and then waits, so the parent kills it at that exact point.
KILL_CHILD = """
import json, os, sys, time
spec = json.loads(os.environ["PC_KILL_SPEC"])
sys.path[:0] = [spec["scripts"], spec["tests"]]
import test_service_kill as t
made = t.Harness.load(spec["root"], t.kill_route(), t.kill_payload(spec["adapter_id"]), spec["adapter_id"])
def stop_here(*args, **keywords):
    with open(spec["marker"], "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))
    time.sleep(60)
def child(argv, **keywords):
    if spec["point"] == "child":
        stop_here()
    return 0, b""
if spec["point"] == "exit":
    made.service._complete = stop_here
made.run(spec["ticket"], child=child, routes=(t.kill_route(),))
"""
# The same run through the real engine and service: the child process shares only the records on disk with the test.
REAL_ENGINE_CHILD = """
import json, os, sys, time
from pathlib import Path
spec = json.loads(os.environ["PC_KILL_SPEC"])
sys.path[:0] = [spec["scripts"], spec["tests"]]
import test_packages as packages
from workflow_core import WorkflowEngine
from workflow_service import WorkflowService, verify_storage_artifact
def stop_here(*args, **keywords):
    with open(spec["marker"], "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))
    time.sleep(60)
def child(argv, **keywords):
    if spec["point"] == "child":
        stop_here()
    return 0, b""
service = WorkflowService(WorkflowEngine(Path(spec["root"]), verify_artifact=verify_storage_artifact), elevation_probe=lambda: False)
if spec["point"] == "exit":
    service._complete = stop_here
with packages.registered(packages.fake_route(result="updated")):
    service.run_ticket(ticket_id=spec["ticket"], launcher=child, probe=packages.RunProbe(), reader=packages.FakeLauncher(), terminal=packages.FakeTerminal())
"""
# Holds one of the three locks until it is killed.
LOCK_CHILD = """
import json, os, sys, time
from pathlib import Path
spec = json.loads(os.environ["PC_KILL_SPEC"])
sys.path.insert(0, spec["scripts"])
from workflow_core import WorkflowEngine
from workflow_service import WorkflowService, verify_storage_artifact
engine = WorkflowEngine(Path(spec["root"]), verify_artifact=verify_storage_artifact)
service = WorkflowService(engine, elevation_probe=lambda: False)
with {"service": service._lock, "session": lambda: engine.journal.lock(spec["session"]), "registry": engine.journal.registry_lock}[spec["lock"]]():
    print("HELD", flush=True)
    time.sleep(60)
"""
# Holds a lock file, starts a process that outlives it, passing on every handle the system would pass on, and then waits.
HANDED_ON_CHILD = """
import json, os, subprocess, sys, time
spec = json.loads(os.environ["PC_KILL_SPEC"])
sys.path.insert(0, spec["scripts"])
from private_workspace import held_lock
with held_lock(spec["lock"]):
    later = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", "import time; time.sleep(60)"], close_fds=False,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(later.pid, flush=True)
    time.sleep(60)
"""


def started(code, spec):
    """A child (this interpreter, -I -S -B) running ``code``, with a pipe for the one line it prints."""
    return subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", "import os;exec(os.environ['PC_KILL_CODE'])"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            env={**os.environ, "PC_KILL_SPEC": json.dumps(spec), "PC_KILL_CODE": code})


class Stopped(BaseException):
    """The process stops here: no except clause of the service catches it, so what follows it never runs."""


def first_line(child, test):
    """The first line ``child`` prints; a watchdog kills a child that never gets there, so the read always ends."""
    watchdog = threading.Timer(120, child.kill)
    watchdog.start()
    try:
        line = child.stdout.readline().strip()
    finally:
        watchdog.cancel()
    test.assertTrue(line, "the child stopped early: " + ("" if child.poll() is None else child.stderr.read()))
    return line


def stopped(process_id):
    """End a process this test does not hold a handle to; one that has already gone needs nothing."""
    try:
        os.kill(process_id, signal.SIGTERM)
    except OSError:
        pass


def ended(child):
    """Kill ``child`` and close its pipes; a second call changes nothing."""
    if child.stdout.closed:
        return
    child.kill()
    child.wait(timeout=60)
    for stream in (child.stdout, child.stderr):
        stream.close()


def kill_route():
    return fake_route(manager="pip")


def kill_payload(adapter_id):
    return fake_payload(kill_route(), adapter_id=adapter_id)


@refusals_fail
class ProcessKillTests(unittest.TestCase):
    """Each written action killed mid-run: while its child runs it stays unknown, after its exit was recorded it reconciles."""

    def killed(self, adapter_id, point):
        payload = kill_payload(adapter_id)
        made = Harness(kill_route(), payload, adapter_id=adapter_id)
        with registered(kill_route()):
            ticket = made.issue()["ticket_id"]
        marker, errors = made.root / "child-started.txt", made.root / "child-errors.txt"
        spec = {"root": str(made.root), "adapter_id": adapter_id, "ticket": ticket, "marker": str(marker), "scripts": str(ROOT / "scripts"),
                "tests": str(ROOT / "tests"), "point": point}
        environment = {**os.environ, "PC_KILL_SPEC": json.dumps(spec), "PC_KILL_CODE": KILL_CHILD}
        with open(errors, "wb") as sink:
            child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", "import os;exec(os.environ['PC_KILL_CODE'])"], stdin=subprocess.DEVNULL,
                                     stdout=sink, stderr=sink, env=environment)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and child.poll() is None and not (marker.exists() and marker.read_text(encoding="utf-8").isdigit()):
                time.sleep(0.05)
            self.assertTrue(marker.exists(), "the child never reached its run: " + errors.read_text(encoding="utf-8", errors="replace"))
            self.assertTrue(made.entered(), "the effect boundary was written before the kill")
        finally:
            child.kill()
            child.wait(timeout=60)
        made.state["operations"][OPERATION] = made.operation
        made.reconcile()
        return made

    def assert_child_may_still_run(self, made):
        # The kill came while the child ran: its exit is unknown, so the operation stays unknown although the target reads as installed.
        self.assertFalse(made.exit_recorded())
        self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["result"]), ("unknown", "unknown"))

    def test_package_upgrade_killed_then_reconciled(self):
        self.assert_child_may_still_run(self.killed(UPGRADE, "child"))

    def test_package_reinstall_killed_then_reconciled(self):
        self.assert_child_may_still_run(self.killed(REINSTALL, "child"))

    def test_system_repair_killed_then_reconciled(self):
        self.assert_child_may_still_run(self.killed(REPAIR, "child"))

    def test_killed_after_the_exit_was_recorded_reconciles_to_the_result(self):
        for adapter_id in (UPGRADE, REINSTALL, REPAIR):
            with self.subTest(adapter_id=adapter_id):
                made = self.killed(adapter_id, "exit")
                self.assertTrue(made.exit_recorded())
                self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["result"]), ("succeeded", "updated"))


@refusals_fail
class RealEngineKillTests(SessionFixtures):
    """A real kill of a run through the real engine and service: the journal holds only what the killed process wrote."""

    prepared, registered_plan, approved, ticket, ticketed, operation, reconciled, launched = (
        getattr(test_packages.PackageEngineTests, name)
        for name in ("prepared", "registered_plan", "approved", "ticket", "ticketed", "operation", "reconciled", "launched"))

    def killed_run(self, route, point):
        """A ticketed step run in a child that is killed at ``point``: (session id, the ticket response)."""
        sid, issued = self.ticketed(route)
        marker = self.root / "child-started.txt"
        child = started(REAL_ENGINE_CHILD, {"root": str(self.root), "ticket": issued["ticket_id"], "marker": str(marker), "point": point,
                                            "scripts": str(ROOT / "scripts"), "tests": str(ROOT / "tests")})
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and child.poll() is None and not (marker.exists() and marker.read_text(encoding="utf-8").isdigit()):
                time.sleep(0.05)
            self.assertTrue(marker.exists(), "the child never reached its run: " + ("" if child.poll() is None else child.stderr.read()))
        finally:
            ended(child)
        return sid, issued

    def another_step(self, route):
        """An approved step of another session, with its plan hash: (session id, its action, the hash)."""
        sid, actions = self.prepared(route, [{"action_id": "update-other", "manager": "pip", "id": "example-tool"}])
        return sid, actions[0], self.approved(sid, actions, self.registered_plan(sid, actions))

    def test_killed_run_holds_every_ticket_until_reconciled(self):
        route = fake_route(result="updated")
        sid, issued = self.killed_run(route, "exit")
        other, action, sha = self.another_step(route)
        self.assertIsNone(self.operation(sid, issued)["outcome"])
        with self.assertRaisesRegex(WorkflowRefusal, "outstanding mutating operation"):
            self.ticket(other, action, sha)
        self.assertEqual(self.state(other)["operations"], {})
        result = self.reconciled(route, sid, issued)
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("succeeded", "updated"))
        self.assertEqual(self.operation(sid, issued)["outcome"], "succeeded")
        self.assertIn("ticket_id", self.ticket(other, action, sha))

    def test_a_kill_with_no_recorded_exit_stays_unknown_and_holds(self):
        route = fake_route(result="updated")
        sid, issued = self.killed_run(route, "child")
        result = self.reconciled(route, sid, issued)
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("unknown", "unknown"))
        self.assertEqual((self.operation(sid, issued)["outcome"], self.state(sid)["status"]), ("unknown", "held"))
        self.assertTrue(self.reconciled(route, sid, issued)["held"])
        other, action, sha = self.another_step(route)
        with self.assertRaisesRegex(WorkflowRefusal, "outstanding mutating operation"):
            self.ticket(other, action, sha)


    def cut_off(self, stop):
        """A step whose begin is recorded and whose ticket stops at ``stop`` (a mock.patch target): (session id, the operation)."""
        sid, step, sha = self.another_step(fake_route(result="updated"))
        with stop, self.assertRaises(Stopped):
            self.ticket(sid, step, sha)
        (operation,) = self.state(sid)["operations"].values()
        return sid, operation

    def test_a_step_cut_off_before_its_intent_stays_in_the_report_as_unknown(self):
        sid, operation = self.cut_off(mock.patch.object(self.service, "_intent", side_effect=Stopped))
        state = self.state(sid)
        rows = package_rows(state, self.service._package_payloads(state))
        self.assertEqual([(row["package"], row["outcome"], row["category"], row["restart"]) for row in rows],
                         [("example-tool", "unknown", "needs_check", "none")])
        self.assertFalse((self.service.work / "operations" / sid / operation["operation_id"]).exists())  # no intent is made up
        self.assertIn("example-tool", self.service.session_report(sid).read_text(encoding="utf-8"))

    def test_a_step_cut_off_before_its_intent_was_whole_closes_as_not_run(self):
        real = self.service._immutable

        def stop_at_the_second_intent_file(path, value):
            if path.name == "intent-evidence.json":
                raise Stopped()
            return real(path, value)
        for label, stop in (("no intent", mock.patch.object(self.service, "_intent", side_effect=Stopped)),
                            ("half an intent", mock.patch.object(self.service, "_immutable", side_effect=stop_at_the_second_intent_file))):
            with self.subTest(label):
                sid, operation = self.cut_off(stop)
                operation_id = operation["operation_id"]
                with self.assertRaises(ServiceRefusal) as caught:
                    self.service.inspect_operation(sid, operation_id=operation_id)
                self.assertEqual(caught.exception.code, "intent-incomplete")
                self.service.elevation_probe = lambda: True
                with self.assertRaises(ServiceRefusal) as caught:
                    self.service._close_before_intent(sid, operation_id)
                self.assertEqual(caught.exception.code, "process-elevated")
                self.service.elevation_probe = lambda: False
                self.assertIsNone(self.state(sid)["operations"][operation_id]["outcome"])
                closed = self.service._close_before_intent(sid, operation_id)
                self.assertEqual((closed["outcome"], closed["receipt"]), ("failed", {"adapter_invoked": False, "reason": "stopped_before_intent"}))
                state = self.state(sid)
                self.assertEqual((state["operations"][operation_id]["outcome"], state["status"]), ("failed", "held"))
                self.assertIn("reconcile-" + operation_id, state["pending"])
                self.assertEqual(state["evidence"][closed["evidence_id"]]["facts"]["outcome"], "failed")
                with self.assertRaises(ServiceRefusal):  # once only
                    self.service._close_before_intent(sid, operation_id)
                self.close_out(sid, operation_id)

    def test_a_kill_during_either_intent_write_leaves_none_of_it_and_closes_as_not_run(self):
        """The process dies while the bytes of intent.json, or of intent-evidence.json, are being written: half of them have reached
        the disk. Nothing stands under the record's own name, so the step is one cut off before its intent was whole: the report
        keeps its row, from the plan's hash-checked payload or from the whole intent, and reconciliation closes it as not run."""
        real = os.write
        for kind, name in (("operation_intent", "intent.json"), ("intent_evidence", "intent-evidence.json")):
            with self.subTest(record=name):
                cut = []

                def dies_half_way(descriptor, data, marker=b'"kind":"' + kind.encode("ascii") + b'"'):
                    if not cut and marker in bytes(data):
                        cut.append(real(descriptor, bytes(data)[:len(data) // 2]))
                        raise Stopped()
                    return real(descriptor, data)
                sid, operation = self.cut_off(mock.patch.object(os, "write", dies_half_way))
                self.assertTrue(cut, "the write was cut off half way")
                folder = self.service.work / "operations" / sid / operation["operation_id"]
                self.assertFalse((folder / name).exists())
                self.assertEqual([path.stat().st_size for path in folder.iterdir() if path.name.startswith(".w")], cut)  # what the kill left
                state = self.state(sid)
                rows = package_rows(state, self.service._package_payloads(state))
                self.assertEqual([(row["package"], row["outcome"]) for row in rows], [("example-tool", "unknown")])
                self.assertIn("example-tool", self.service.session_report(sid).read_text(encoding="utf-8"))
                closed = self.service.reconcile_operation(sid, operation_id=operation["operation_id"])
                self.assertEqual((closed["outcome"], closed["receipt"]), ("failed", {"adapter_invoked": False, "reason": "stopped_before_intent"}))
                self.close_out(sid, operation["operation_id"])

    def test_a_service_record_is_never_published_over_another(self):
        path = self.service.work / "fictional-record.json"
        self.service._immutable(path, {"fictional": 1})
        before = path.read_bytes()
        with self.assertRaises(PrivateWorkspaceError) as caught:
            self.service._immutable(path, {"fictional": 2})
        self.assertEqual((caught.exception.code, path.read_bytes()), ("private-file-create-refused", before))
        self.assertEqual([item.name for item in path.parent.iterdir() if item.name.startswith(".w")], [])  # a refusal leaves no temporary file

    def test_reconcile_closes_a_step_cut_off_before_its_intent(self):
        sid, operation = self.cut_off(mock.patch.object(self.service, "_intent", side_effect=Stopped))
        closed = self.service.reconcile_operation(sid, operation_id=operation["operation_id"])
        self.assertEqual((closed["outcome"], closed["receipt"]), ("failed", {"adapter_invoked": False, "reason": "stopped_before_intent"}))
        self.assertEqual(self.state(sid)["operations"][operation["operation_id"]]["outcome"], "failed")
        with self.assertRaises(ServiceRefusal):  # consumed: the step never runs again, and nothing is made up for it
            self.service.reconcile_operation(sid, operation_id=operation["operation_id"])

    def close_out(self, sid, operation_id):
        """Account for a failed step, as the person's replan does, so that the next step of a test can begin."""
        operation = self.state(sid)["operations"][operation_id]
        row = self.evidence("reconciliation", {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
                            | {"outcome": "failed", "actual_effects_recorded": True, "no_active_effects": True, "recovery_retained": True}, sid=sid)
        self.engine.resolve(sid, pending_id="reconcile-" + operation_id, evidence_ids=[row], choice="revise_plan",
                            owner_quote="Account for this fictional step and plan again.", owner_message_id="fictional-replan-" + operation_id)

    def test_a_whole_intent_or_a_passed_boundary_is_not_closed_this_way(self):
        sid, operation = self.cut_off(mock.patch.object(self.service, "_write_ticket", side_effect=Stopped))
        operation_id = operation["operation_id"]
        folder = self.service.work / "operations" / sid / operation_id
        self.assertTrue((folder / "intent.json").exists())
        with self.assertRaisesRegex(ServiceRefusal, "cut off before it started"):  # a whole intent keeps its own reconciliation
            self.service._close_before_intent(sid, operation_id)
        write_private_new(folder / "entered.json", b"{}")
        os.remove(folder / "intent-evidence.json")
        with self.assertRaisesRegex(ServiceRefusal, "cut off before it started"):  # past the boundary an effect may have started
            self.service._close_before_intent(sid, operation_id)
        self.assertIsNone(self.state(sid)["operations"][operation_id]["outcome"])

    def test_a_finished_step_leaves_what_the_status_text_reads_in_its_outcome_row(self):
        route = fake_route(result="updated")
        sid, issued = self.ticketed(route)
        self.assertEqual(self.launched(route, issued)["outcome"], "succeeded")
        operation = self.operation(sid, issued)
        facts = self.state(sid)["evidence"][operation["evidence_ids"][-1]]["facts"]
        self.assertEqual((facts["result"], facts["category"], facts["group"]), ("updated", "updated_checked", "apps"))
        self.assertIn("example-tool", engine_text.update_summary([{"name": "example-tool", **facts}]))


class LockTests(SessionFixtures):
    """private_workspace.held_lock and the three locks built on it."""

    def lock_path(self):
        return self.service.work / "fictional.lock"

    def holder(self, lock):
        child = started(LOCK_CHILD, {"root": str(self.root), "scripts": str(ROOT / "scripts"), "session": self.sid, "lock": lock})
        self.addCleanup(ended, child)
        self.assertEqual(first_line(child, self), "HELD")
        return child

    def test_a_second_process_is_refused_while_the_first_lives_and_nothing_stays_when_it_dies(self):
        journal = self.engine.journal
        for lock, take, refusal, code in (("service", self.service._lock, ServiceRefusal, "service-busy"),
                                          ("session", lambda: journal.lock(self.sid), WorkflowRefusal, "workflow-refusal"),
                                          ("registry", journal.registry_lock, WorkflowRefusal, "workflow-refusal")):
            with self.subTest(lock=lock):
                child = self.holder(lock)
                with self.assertRaises(refusal) as caught:
                    with take():
                        self.fail("A lock another process holds must not be taken")
                self.assertEqual(caught.exception.code, code)
                ended(child)
                with take():  # no folder to remove, no step in between
                    pass

    def test_the_service_refusal_says_what_is_happening_and_what_to_do(self):
        with self.service._lock():
            with self.assertRaises(ServiceRefusal) as caught:
                with self.service._lock():
                    self.fail("A held lock must not be taken again")
        self.assertEqual(caught.exception.code, "service-busy")
        message = str(caught.exception)
        self.assertIn("Let it finish, then try again", message)
        self.assertIn("Nothing was changed", message)
        self.assertNotIn(str(self.root), message)

    def test_a_lock_is_not_handed_on_to_a_child_that_outlives_the_holder(self):
        path = self.lock_path()
        child = started(HANDED_ON_CHILD, {"lock": str(path), "scripts": str(ROOT / "scripts")})
        self.addCleanup(ended, child)
        later = int(first_line(child, self))
        self.addCleanup(stopped, later)
        with self.assertRaises(PrivateWorkspaceError) as caught:
            with held_lock(path):
                self.fail("A lock another process holds must not be taken")
        self.assertEqual(caught.exception.code, "private-lock-held")
        ended(child)
        with held_lock(path):
            pass

    def test_the_file_is_private_stays_and_can_be_taken_again(self):
        path = self.lock_path()
        with held_lock(path):
            self.assertEqual(ensure_private_file(path), path)
            self.assertEqual(path.stat().st_size, 0)
        self.assertEqual(ensure_private_file(path), path)
        with held_lock(path):
            pass

    def test_an_error_from_the_operating_system_refuses_and_runs_nothing(self):
        # A failure that says nothing about a holder: the block must not run, whichever lock it is.
        with mock.patch("msvcrt.locking" if os.name == "nt" else "fcntl.flock", side_effect=OSError(errno.EINVAL, "Fictional lock failure")):
            with self.assertRaises(PrivateWorkspaceError) as caught:
                with held_lock(self.lock_path()):
                    self.fail("The block ran without the lock")
            self.assertEqual(caught.exception.code, "private-lock-unavailable")
            with self.assertRaises(PrivateWorkspaceError) as caught:
                with self.service._lock():
                    self.fail("The service went on without its lock")
            self.assertEqual(caught.exception.code, "private-lock-unavailable")
            for take in (lambda: self.engine.journal.lock(self.sid), self.engine.journal.registry_lock):
                with self.assertRaises(PrivacyCapabilityHold):
                    with take():
                        self.fail("The engine went on without its lock")

    def test_something_else_at_the_lock_path_refuses(self):
        path = self.lock_path()
        ensure_private_directory(path, create=True)
        with self.assertRaises(PrivateWorkspaceError):
            with held_lock(path):
                self.fail("A folder is not a lock")

    def test_a_failure_inside_the_block_frees_the_lock_and_keeps_its_own_type(self):
        for take in (self.service._lock, self.engine.journal.registry_lock):
            with self.subTest(lock=take.__qualname__):
                with self.assertRaises(PrivateWorkspaceError) as caught:
                    with take():
                        raise PrivateWorkspaceError("private-lock-held", "Fictional failure of the work inside the lock")
                self.assertEqual(str(caught.exception), "Fictional failure of the work inside the lock")
                with take():
                    pass


def tearDownModule():
    remove_fixture_roots()


if __name__ == "__main__":
    unittest.main()
