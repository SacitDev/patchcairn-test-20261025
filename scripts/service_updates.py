"""Update and repair family: package discovery, the package actions, the one-use ticket and the
ticket-bound launcher, its receipts, the check after a restart, reconciliation, and the update and repair dispatch.

A package change runs in two steps. The execute target (step 1, reached through execute_action) begins the operation
and writes the one-use ticket that binds the run folder and its run files. run_ticket (step 2, in its own process:
``patchcairn_service.py run --ticket <id>``) checks everything again and starts exactly the bound executable with the
bound argv and environment, without a shell, and records the child's exit as soon as it is known. Every completion, after
the run, after a restart and in reconciliation, goes through _complete and package_registry.route_result. Every route is
looked up in package_registry; this module has no per-manager code. It never restarts the computer, never kills a child
it started and never runs a command it is handed. A practice session never starts a real program or reads this computer.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
import uuid

import package_registry
import package_routes
import pc_records
import readonly_runner
from private_workspace import ensure_private_directory, publish_private_new, write_private_new
from workflow_core import (SERVICE_RECORD, digest, exact_fields, read_record_bytes, record_identifier, restart_state, update_findings,
                           EVIDENCE_MAX_BYTES)
from service_state import ServiceRefusal, decoded, private_read, service_record, service_value

# The operation each written adapter binds; the other update ids hold until their routes are written.
OPERATIONS = {pc_records.ADAPTER_PACKAGE_UPGRADE: "upgrade", pc_records.ADAPTER_PACKAGE_REINSTALL: "reinstall",
              pc_records.ADAPTER_SYSTEM_REPAIR: "repair"}
RUN_NAMESPACE = "package-runs"  # every package run folder: <work>/package-runs/<fresh name>
TICKET_KIND = "package_ticket"
EXIT_RECORD = "exit.json"  # in the operation folder: what the run recorded when its child ended; without it the child may still run
BEFORE_RECORD = "before.json"  # in the operation folder: each read taken right before the run with its status, and the restart files then
TICKET_RECORD = "ticket-id.txt"  # in the operation folder: the id of its ticket
TICKET_FIELDS = frozenset({"schema", "schema_version", "kind", "ticket_id", "session_id", "operation_id", "action_id", "plan_sha256",
                           "adapter_payload_sha256", "run_folder", "run_files", "issued_utc"})
TAIL_BYTES = 65536
PIPE_WAIT_SECONDS = 2  # after a process child ends: how long a descendant that kept its output open can delay the exit record
TEXT_MAX = 2000  # the engine's bound on an action's target and risk
PRACTICE = "A practice session never starts a real program or reads this computer; nothing was changed"
# The terminal's interrupt keys and hang-up, where this system has them.
INTERRUPTS = tuple(getattr(signal, name) for name in ("SIGINT", "SIGQUIT", "SIGHUP", "SIGBREAK") if hasattr(signal, name))
DISCOVERY_WORDING = "changes no installed software; the manager may refresh its own lists and logs"
# Apps outside the four managers: each collector manager label and the official update path the person uses.
OUTSIDE_UPDATE_PATHS = {"snap": "snap_store", "flatpak": "flatpak_remote", "unknown": "app_store_or_vendor",
                        "apple-installer-receipt": "vendor_installer", "homebrew-unverified": "homebrew_unverified"}
ROUTED_COLLECTOR_MANAGERS = frozenset({"dpkg", "rpm", "winget", "homebrew"})
MAX_LISTED_APPS, MAX_SHOWN_TEXT = 500, 200
RUN_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}(?:\.[A-Za-z0-9]{1,15}){0,2}")


class _Reads:
    """The run function package hooks get: read-only recipes through readonly_runner in one fresh private run folder,
    plus bounded reads of configuration files the routes check (never written, never followed through a link). A probe
    with its own read_file and list_names (a test's fake computer) answers those instead of this computer."""

    def __init__(self, folder, probe, launcher):
        self.folder, self.probe, self.launcher = str(folder), probe, launcher

    def __call__(self, recipe_id, values=None):
        return readonly_runner.run_recipe(recipe_id, values, run_folder=self.folder, launcher=self.launcher, probe=self.probe)

    def read_file(self, path):
        """The bytes of a regular file (at most the route output bound), or None when it is missing, a link or unreadable."""
        if callable(getattr(self.probe, "read_file", None)):
            return self.probe.read_file(path)
        try:
            if Path(path).is_symlink():
                return None
            with open(path, "rb") as handle:
                data = handle.read(package_routes.MAX_OUTPUT_BYTES + 1)
        except OSError:
            return None
        return data if len(data) <= package_routes.MAX_OUTPUT_BYTES else None

    def discard(self, path):
        """Remove a file of this run folder; one that is gone or cannot be removed stays a private file of that folder."""
        try:
            if path.startswith(self.folder):
                os.unlink(path)
        except OSError:
            pass

    def list_names(self, folder):
        if callable(getattr(self.probe, "list_names", None)):
            return self.probe.list_names(folder)
        try:
            return sorted(os.listdir(folder))
        except OSError:
            return None


class _Console:
    """The terminal run_ticket runs in: a TTY on stdin and stdout, and the device-number line of a firmware update."""

    @staticmethod
    def isatty():
        return os.isatty(0) and os.isatty(1)

    @staticmethod
    def ask(prompt):
        print(prompt, end="", flush=True)
        return sys.stdin.readline(64)


@contextmanager
def _interrupts_ignored():
    """While a child runs this process ignores the terminal's interrupt keys and hang-up, as system(3) does, so the child's exit
    is always recorded; the child, started before this, keeps default handling. Only the main thread can change a handler."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    saved = [(number, signal.signal(number, signal.SIG_IGN)) for number in INTERRUPTS]
    try:
        yield
    finally:
        for number, handler in saved:
            signal.signal(number, signal.SIG_DFL if handler is None else handler)


def _start_child(argv, *, env, cwd, terminal):
    """Start the bound argv (a list, never a shell) and wait until it ends; (exit code, last output bytes). A terminal
    child inherits stdin, stdout and stderr, so sudo's or the tool's own prompt reaches the person; a process child gets
    the null device as stdin and its combined output is kept to the last 64 KiB. The exit counts when the child ends, not when
    its output closes: a descendant that keeps the pipe open costs at most PIPE_WAIT_SECONDS. There is no timeout and no kill: a
    child that runs on keeps its operation open for reconciliation."""
    if terminal:
        process = subprocess.Popen(list(argv), env=env, cwd=cwd, shell=False)
        with _interrupts_ignored():
            return process.wait(), b""
    process = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=cwd,
                               shell=False)
    tail = [b""]

    def read():
        for chunk in iter(lambda: process.stdout.read1(TAIL_BYTES), b""):
            tail[0] = (tail[0] + chunk)[-TAIL_BYTES:]

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    with _interrupts_ignored():
        code = process.wait()
        reader.join(PIPE_WAIT_SECONDS)
    if not reader.is_alive():  # a descendant still holding the pipe would block close(); the daemon reader is left
        process.stdout.close()
    return code, tail[0]


def launcher_command(ticket_id):
    """The one command for the person's own terminal when PatchCairn has none: the launcher, never a recipe's argv, every
    argument quoted for the shell it is pasted into."""
    record_identifier(ticket_id)
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patchcairn_service.py")
    return package_registry.shell_line((sys.executable, "-I", "-S", "-B", script, "run", "--ticket", ticket_id))


def _hold(error):
    return ServiceRefusal(str(error), code=error.code)


def _shown(value):
    """Collector text for the assistant and the evidence: no hidden or format characters, cut to MAX_SHOWN_TEXT."""
    return package_registry.visible(value)[:MAX_SHOWN_TEXT] if isinstance(value, str) else None


def _fitted(facts, extra):
    """``facts``, which come first and cannot be replaced, then the assistant's own words, within the engine's bound."""
    text = facts + " " + extra
    return text if len(text) <= TEXT_MAX else text[:TEXT_MAX - 1] + "\u2026"


def _bound_target(body, extra):
    """An action's target from its bound payload: what the person approves is what the plan binds."""
    return _fitted(f"{body['manager']}: {body['id']} version {body['version']} from {body['source']}.", extra)


def _bound_risk(body, extra):
    """An action's risk with its fixed sentences from the bound payload: each agreement, and what else the manager said changes."""
    agreements = {"package": "Approving this accepts the package's licence agreement for exactly this package.",
                  "source": "Approving this accepts the source's agreement for exactly this package."}
    others = (f"It also changes {len(body['dependencies'])} other package(s): {', '.join(body['dependencies'])}." if body["dependencies"]
              else "The package manager lists no other package that changes." if "depends_on" in body
              else "The package manager does not say whether other packages change.")
    return _fitted(" ".join([*(agreements[name] for name in body["agreements"]), others]), extra)


def _needs_os_consent(adapter_id, route):
    """The action flag of this adapter on this route: the operating system asks the person, or the elevating step may."""
    return pc_records.ADAPTERS[adapter_id]["os_consent"] == "always" or route["run"]["os_consent"] == "exit_observed"


def _shown_command(route, payload, folder):
    """The command the action shows: the run's own argv for this payload, as one line."""
    values = route["run"]["values"](payload, payload["recipe"], str(folder))
    return package_registry.render(payload["recipe"], values, executable=payload["executable"]["path"], run_folder=str(folder),
                                   prefix=readonly_runner.executable_prefix(payload["executable"]["kind"]))


class UpdatesMixin:
    """Package discovery, package actions, the ticket-bound launcher, receipts and the update and repair dispatch targets."""

    # --- discovery and planning (public; the service command-line tool calls them) ------------------------------------
    def discover_packages(self, session_id, *, manager, launcher=None, probe=None, other_apps=False, collector=None):
        """Read-only discovery of one manager's updates (it changes no installed software; the manager may refresh its own
        lists and logs) in a fresh private run folder, with the age of the package lists, recorded as session evidence.
        With other_apps, the collector inventory adds the apps outside the four managers and their official update path."""
        with self._lock():
            state = self._state(session_id, collecting=True)
            self._refuse_practice(state, probe, launcher)
            route = self._route({"manager": manager})
            probe = probe or readonly_runner.HostProbe()
            try:
                found = route["discover"](probe, _Reads(self._run_folder(), probe, launcher))
            except pc_records.Refusal as error:
                found = {"candidates": [], "left_out": [], "holds": [{"code": error.code, "message": str(error)}]}
            age = (package_routes.list_age(manager, readonly_runner.package_list_time(manager, probe=probe))
                   if manager in package_routes.MANAGERS else None)
            findings = {"manager": manager, "wording": DISCOVERY_WORDING, "list_age": age, "candidates": found["candidates"],
                        "left_out": found["left_out"], "holds": found["holds"]}
            if other_apps:
                findings["outside_managers"] = self._apps_outside_managers(session_id, collector)
            row = self._register(state, kind="inventory", value=findings,
                                 facts={"complete": not found["holds"], "item_count": len(found["candidates"])})
            rows = [{"name": item["id"], "group": route["group"], "flags": item.get("flags") or []} for item in found["candidates"]]
            return {**findings, "evidence_id": row["evidence_id"], "findings_text": update_findings(rows)}

    @staticmethod
    def _refuse_practice(state, *injected):
        """Refuse a practice session on its way to the real computer: it goes on only with a test's fakes (each of ``injected``)."""
        if state["mode"] != "real" and any(fake is None for fake in injected):
            raise ServiceRefusal(PRACTICE, code="package-fixture-session")

    def _apps_outside_managers(self, session_id, collector):
        """Collector observations not owned by a routed manager, each with its official update path; no automated route."""
        inventory = self.collect_inventory(session_id, collector=collector)
        rows = []
        for item in inventory.get("observations", []) if isinstance(inventory, dict) else []:
            if not isinstance(item, dict) or item.get("kind") not in ("application", "package") or len(rows) >= MAX_LISTED_APPS:
                continue
            manager = _shown(item.get("manager"))
            if manager not in ROUTED_COLLECTOR_MANAGERS:
                rows.append({"name": _shown(item.get("name")), "version": _shown(item.get("version")), "manager": manager,
                             "update_path": OUTSIDE_UPDATE_PATHS.get(manager, "vendor")})
        return rows

    def prepare_package_action(self, session_id, *, adapter_id, items, target, benefit, risk, reversibility, verification,
                               launcher=None, probe=None):
        """One plan action per selected package (items: {"action_id", "manager", "id", optional "kind" for Homebrew,
        "agreements" the person accepted for winget}), each read fresh and bound to its exact id, version, source, preflight result
        and executable, sorted in one dependency-preserving order before the plan is hashed. What an item needs comes from the
        manager's own data (package_registry.dependency_edges), never from the caller. The action's target and risk state what the
        payload binds; ``target`` and ``risk`` only follow those facts. Returns the actions in that order; the coordinator registers
        them as one plan."""
        with self._lock():
            state = self._state(session_id, collecting=True)
            self._refuse_practice(state, probe, launcher)
            if adapter_id not in OPERATIONS or not isinstance(items, list) or not 0 < len(items) <= package_routes.MAX_ITEMS:
                raise ServiceRefusal("A package action needs a written update or repair adapter and one to 500 selected packages")
            probe, planned = probe or readonly_runner.HostProbe(), []
            for item in items:
                planned.append(self._planned(adapter_id, item, probe, launcher))
            edges = package_registry.dependency_edges([{**fragment, "action_id": item["action_id"]} for item, *_rest, fragment, _env in planned])
            for item, *_rest, fragment, _env in planned:
                if "depends_on" in fragment:
                    fragment["depends_on"] = edges[item["action_id"]]
            order = package_registry.plan_order([{**fragment, "action_id": item["action_id"]} for item, *_rest, fragment, _env in planned])
            by_id = {entry[0]["action_id"]: entry for entry in planned}
            facts = pc_records.ADAPTERS[adapter_id]
            actions = []
            for entry in order:
                item, route, folder, texts, fragment, environment = by_id[entry["action_id"]]
                body = package_registry.payload(fragment, environment=environment)
                inventory = {"manager": body["manager"], "id": body["id"], "run_folder": folder.name, "run_files": texts}
                action = self._action(state, action_id=item["action_id"], adapter_id=adapter_id, kind=facts["kinds"][0], payload=body,
                                      native_plan=body["preflight"], inventory=inventory, target=target, benefit=benefit, risk=risk, reversibility=reversibility,
                                      verification=verification, rendered_command=_shown_command(route, body, folder),
                                      requires_os_consent=_needs_os_consent(adapter_id, route))
                # After _action, which checks the assistant's words: a text filter must not refuse a package that is named passwd.
                actions.append({**action, "target": _bound_target(body, target), "risk": _bound_risk(body, risk)})
            return actions

    def _planned(self, adapter_id, item, probe, launcher):
        """(item, route, run folder, run file texts, payload fragment, environment) of one selected package."""
        if not isinstance(item, dict) or set(item) - {"action_id", "manager", "id", "kind", "agreements"}:
            raise ServiceRefusal("A selected package names only its action id, manager, id, kind and agreements; what it needs comes from its manager")
        record_identifier(item.get("action_id"))
        route = self._route(item)
        folder = self._run_folder()
        try:
            candidate = route["run"]["preflight"](probe, _Reads(folder, probe, launcher), {"id": item.get("id"), "kind": item.get("kind")},
                                                  OPERATIONS[adapter_id])
            spec = route["run"]["executable"](probe, None)
            executable = {"kind": spec["kind"], "path": spec["path"],
                          "identity": readonly_runner.executable_identity(spec["kind"], spec["path"], program=spec.get("program"), probe=probe)}
            texts = dict(candidate.pop("run_files", None) or {})
            fragment = route["plan"](candidate, {"operation": OPERATIONS[adapter_id], "executable": executable,
                                                 "agreements": list(item.get("agreements") or ())})
            environment = route["run"]["environment"](probe)
        except pc_records.Refusal as error:
            raise _hold(error) from error
        if "hold" in fragment:
            raise ServiceRefusal(fragment["message"], code=fragment["hold"])
        self._selected(route, fragment)
        if fragment.get("run_kind") not in pc_records.ADAPTERS[adapter_id]["run_kinds"]:
            raise ServiceRefusal("The route planned a recipe or run kind this adapter does not run", code="package-recipe")
        for name, text in texts.items():
            if not isinstance(name, str) or not RUN_FILE_NAME.fullmatch(name) or not isinstance(text, str):
                raise ServiceRefusal("A run file needs a plain name and text", code="package-run-file")
            write_private_new(folder / name, text.encode("utf-8"))
        fragment["run_files"] = {name: digest(text.encode("utf-8")) for name, text in sorted(texts.items())}
        return item, route, folder, texts, fragment, environment

    def _run_folder(self):
        """A fresh private run folder in the one package-run namespace below the work folder."""
        namespace = self.root / "work" / RUN_NAMESPACE
        ensure_private_directory(namespace, create=True, parents=True, exist_ok=True)
        return ensure_private_directory(namespace / ("run-" + uuid.uuid4().hex), create=True)

    # --- step 1: the execute targets write the one-use ticket ----------------------------------------------------------
    def _execute_package_upgrade(self, session_id, state, action, payload, **arguments):
        folder, files = self._ticket_preconditions(state, action, payload, **arguments)
        operation, path, intent, stopped = self._begin_adapter(session_id, state, action, payload, action_id=arguments["action_id"],
                                                               plan_sha256=arguments["plan_sha256"],
                                                               precondition_evidence_ids=arguments["precondition_evidence_ids"],
                                                               owner_consent_evidence_id=None)
        return stopped if stopped is not None else self._write_ticket(state, operation, action, folder, files)

    def _execute_package_reinstall(self, session_id, state, action, payload, **arguments):
        folder, files = self._ticket_preconditions(state, action, payload, **arguments)
        operation, path, intent, stopped = self._begin_adapter(session_id, state, action, payload, action_id=arguments["action_id"],
                                                               plan_sha256=arguments["plan_sha256"],
                                                               precondition_evidence_ids=arguments["precondition_evidence_ids"],
                                                               owner_consent_evidence_id=None)
        return stopped if stopped is not None else self._write_ticket(state, operation, action, folder, files)

    def _execute_system_repair(self, session_id, state, action, payload, **arguments):
        folder, files = self._ticket_preconditions(state, action, payload, **arguments)
        operation, path, intent, stopped = self._begin_adapter(session_id, state, action, payload, action_id=arguments["action_id"],
                                                               plan_sha256=arguments["plan_sha256"],
                                                               precondition_evidence_ids=arguments["precondition_evidence_ids"],
                                                               owner_consent_evidence_id=None)
        return stopped if stopped is not None else self._write_ticket(state, operation, action, folder, files)

    def _execute_system_update_handoff(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _execute_system_firmware_update(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _ticket_preconditions(self, state, action, payload, *, diagnostic_fixture_runner=None, diagnostic_fixture_result=None, **unused):
        """Before begin: the route is known and built, the payload names the recipe and run kind the route selects for it, the
        launcher command can be shown (a checkout path no shell line can carry refuses here, before an action is consumed), the
        action's shown command and consent flag are what this payload runs, and the bound run folder holds exactly the planned run
        files. Returns (run folder, {name: sha256})."""
        if diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None:
            raise ServiceRefusal("Diagnostic injection is not a package adapter input")
        route = self._route(payload)
        if payload.get("operation") != OPERATIONS.get(action["adapter_id"]):
            raise ServiceRefusal("The payload's operation or recipe is not this adapter's", code="package-recipe")
        self._selected(route, payload)
        launcher_command("ticket-" + "0" * 32)
        inventory = self._inventory(state, action)
        folder = self.root / "work" / RUN_NAMESPACE / inventory.get("run_folder", "")
        if not isinstance(inventory.get("run_folder"), str) or not inventory["run_folder"].startswith("run-") or folder.parent.name != RUN_NAMESPACE:
            raise ServiceRefusal("The action's run folder is not in the package-run namespace", code="package-run-folder")
        if (action.get("rendered_command") != _shown_command(route, payload, folder)
                or action["requires_os_consent"] is not _needs_os_consent(action["adapter_id"], route)):
            raise ServiceRefusal("The action's shown command or consent flag is not what its payload runs", code="package-action-mismatch")
        return folder, self._run_files(folder, payload)

    @staticmethod
    def _selected(route, record):
        """Refuse a payload or fragment that does not name what the route selects for its operation and package kind."""
        try:
            package_registry.check_selection(route, record)
        except pc_records.Refusal as error:
            raise _hold(error) from error

    def _inventory(self, state, action):
        """The action's inventory record, read from the engine's evidence and checked against the hash the plan binds."""
        row = state["evidence"].get(action["target_inventory_evidence_id"])
        data = read_record_bytes(self.engine.work / state["session_id"] / row["path"], EVIDENCE_MAX_BYTES) if row else b""
        if not row or digest(data) != row["sha256"] or row["sha256"] != action["target_inventory_sha256"]:
            raise ServiceRefusal("The action's inventory differs from the one the plan binds")
        return decoded(data)

    @staticmethod
    def _run_files(folder, payload):
        """{name: sha256} of the run folder's planned files, each hashed again; a missing, changed or extra file holds."""
        ensure_private_directory(folder)
        if set(os.listdir(folder)) != set(payload["run_files"]):
            raise ServiceRefusal("The run folder holds files the plan did not bind", code="package-run-file-changed")
        found = {}
        for name in payload["run_files"]:
            data = read_record_bytes(folder / name, package_routes.MAX_OUTPUT_BYTES)
            found[name] = digest(data)
        if found != payload["run_files"]:
            raise ServiceRefusal("A bound run file changed after the plan; build and approve a new plan", code="package-run-file-changed")
        return found

    def _write_ticket(self, state, operation, action, folder, files):
        """The one-use ticket of a begun operation, written below the service's tickets folder."""
        ticket_id = "ticket-" + uuid.uuid4().hex
        tickets = self.work / "tickets"
        ensure_private_directory(tickets, create=True, exist_ok=True)
        ticket = service_value(TICKET_KIND, ticket_id=ticket_id, session_id=state["session_id"], operation_id=operation["operation_id"],
                               action_id=operation["action_id"], plan_sha256=operation["plan_sha256"],
                               adapter_payload_sha256=action["adapter_payload_sha256"], run_folder=str(folder), run_files=files,
                               issued_utc=pc_records.utc_now())
        self._immutable(tickets / (ticket_id + ".json"), ticket)
        publish_private_new(self._operation_dir(state["session_id"], operation["operation_id"]) / TICKET_RECORD, ticket_id.encode("ascii"))
        return {"operation_id": operation["operation_id"], "ticket_id": ticket_id, "command": launcher_command(ticket_id),
                "shell": "powershell" if os.name == "nt" else "posix"}

    def ticket_command(self, session_id, *, operation_id):
        """The launcher command of this operation's ticket, which the check after a restart runs again; None when it has no ticket."""
        path = self._operation_dir(session_id, operation_id) / TICKET_RECORD
        if not path.exists():
            return None
        ticket = self._ticket(private_read(path).decode("ascii"))
        if ticket["session_id"] != session_id or ticket["operation_id"] != operation_id:
            raise ServiceRefusal("The ticket does not match its begun operation")
        return launcher_command(ticket["ticket_id"])

    def _ticket(self, ticket_id):
        record_identifier(ticket_id)
        path = self.work / "tickets" / (ticket_id + ".json")
        if not path.is_file():
            raise ServiceRefusal("There is no package ticket with this id", code="package-ticket-unknown")
        ticket = decoded(private_read(path))
        pc_records.require_schema(ticket, SERVICE_RECORD)
        exact_fields(ticket, TICKET_FIELDS, TICKET_FIELDS)
        if (ticket["kind"] != TICKET_KIND or ticket["ticket_id"] != ticket_id
                or Path(ticket["run_folder"]).parent != self.root / "work" / RUN_NAMESPACE):
            raise ServiceRefusal("Not a package ticket")
        return ticket

    @staticmethod
    def _route(payload):
        try:
            return package_registry.descriptor(payload.get("manager"))
        except pc_records.Refusal as error:
            raise _hold(error) from error

    # --- step 2: the launcher ------------------------------------------------------------------------------------------
    def run_ticket(self, *, ticket_id, launcher=None, probe=None, reader=None, terminal=None):
        """Run one ticket, once. Refuses unless PatchCairn surely runs without elevation; under the lock refuses a practice session that
        would reach the real launcher, probe or read-only launcher (a test gives all three fakes), then, after the session and the operation's
        checked intent are read again, refuses an operation that is no longer open or already started. An operation waiting for
        its restart gets only the check after the restart: the consumed action's original binding with no age limit, because the
        wait for a restart has none, then fresh observations of what stands now.
        Otherwise, after the exact approved binding is read again with its freshness limit: the run files hashed again, the
        executable checked again through readonly_runner, a terminal run only with a TTY on stdin and stdout (else nothing
        starts and the launcher command is returned), a firmware item's device number typed in that terminal, the route's
        drift() right before the argv is built, and as the last step _run_effect's admission by the engine, which refuses a pause or
        stop that arrived meanwhile and closes the ticket as not run. An item the manager no longer offers because an earlier step
        brought it to its approved target starts nothing and closes on the route's own read. ``launcher``, ``probe``, ``reader`` (the
        read-only launcher) and ``terminal`` are injected by tests; the child is never killed."""
        if self.elevation_probe() is not False:
            raise ServiceRefusal("PatchCairn is running with administrator rights, or that cannot be told; package changes run only without them",
                                 code="package-elevated")
        ticket = self._ticket(ticket_id)
        session_id, terminal = ticket["session_id"], terminal or _Console()
        with self._lock():
            state = self._state(session_id)
            self._refuse_practice(state, launcher, probe, reader)
            probe = probe or readonly_runner.HostProbe()
            inspected = self.inspect_operation(session_id, operation_id=ticket["operation_id"])
            operation, intent = inspected["operation"], inspected["intent"]
            action, payload = intent["action"], intent["payload"]
            if (operation["action_id"] != ticket["action_id"] or operation["plan_sha256"] != ticket["plan_sha256"]
                    or action["adapter_payload_sha256"] != ticket["adapter_payload_sha256"] or action["adapter_id"] not in OPERATIONS):
                raise ServiceRefusal("The ticket does not match its begun operation")
            if operation["outcome"] is not None:
                raise ServiceRefusal("This operation is closed; its ticket runs nothing", code="package-ticket-closed")
            route, reads = self._route(payload), _Reads(ticket["run_folder"], probe, reader)
            path = self._operation_dir(session_id, ticket["operation_id"])
            restart = restart_state(operation)
            if restart != "none":
                self._original_authority(state, operation, intent)
                if self.engine.action_binding(state, action, operation_id=operation["operation_id"]) != payload:
                    raise ServiceRefusal("The ticket does not match its begun operation")
                return self._after_restart(state, operation, action, payload, route, reads, path, restart)
            if (path / "entered.json").exists():
                raise ServiceRefusal("This ticket was already used; inspect and reconcile the operation", code="package-ticket-used")
            if self._binding(state, ticket["action_id"], ticket["plan_sha256"]) != (action, payload):
                raise ServiceRefusal("The ticket does not match its begun operation")
            if state["status"] != "active":
                return self._finish(state, operation, outcome="failed", receipt=self._not_run(payload, "owner_paused_or_stopped"))
            launch = self._launch_plan(state, action, payload, route, reads, ticket, probe, terminal)
            if "hold" in launch:
                return launch
            if "already_at_target" in launch:
                return self._close_at_target(state, operation, action, payload, route, reads, path, launch)
            started = {"paused_receipt": self._not_run(payload, "owner_paused_or_stopped"), "launch": launch, "route": route, "reads": reads,
                       "launcher": launcher or _start_child}
            if action["adapter_id"] == pc_records.ADAPTER_PACKAGE_UPGRADE:
                return self._run_effect(session_id, state, operation, action, payload, path, intent, self._effect_package_upgrade, **started)
            if action["adapter_id"] == pc_records.ADAPTER_PACKAGE_REINSTALL:
                return self._run_effect(session_id, state, operation, action, payload, path, intent, self._effect_package_reinstall, **started)
            if action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REPAIR:
                return self._run_effect(session_id, state, operation, action, payload, path, intent, self._effect_system_repair, **started)
            raise ServiceRefusal("No effect is written for this kind of step, so nothing started", code="package-no-effect")

    def _launch_plan(self, state, action, payload, route, reads, ticket, probe, terminal):
        """Everything checked right before the start, in order: the recipe the route selects, run files, executable, terminal and
        device number, the before reads and restart files, drift(), then the argv. It writes nothing, so a ticket that holds here
        or is refused admission can be run again. A Settings item gets drift() and then its fixed page. A typed hold
        ({"hold", ...}) starts nothing, and an item already at its target ({"already_at_target": True, ...}) needs no start."""
        self._selected(route, payload)
        if payload["run_kind"] == "settings":
            self._drift(route, probe, reads, payload)
            return self._open_settings(payload["settings_page"])
        folder = Path(ticket["run_folder"])
        if self._run_files(folder, payload) != ticket["run_files"]:
            raise ServiceRefusal("A bound run file changed after the ticket", code="package-run-file-changed")
        bound, spec = payload["executable"], route["run"]["executable"](probe, payload["recipe"])
        try:
            readonly_runner.recheck_executable(bound["kind"], bound["path"], bound["identity"], program=spec.get("program"), probe=probe)
            environment = route["run"]["environment"](probe)
        except pc_records.Refusal as error:
            raise _hold(error) from error
        if spec["kind"] != bound["kind"] or digest(environment) != payload["environment_sha256"]:
            raise ServiceRefusal("The executable or environment is not the one the plan bound", code="package-drift")
        tty, device = payload["run_kind"] == "terminal", "not_applicable"
        if tty and not terminal.isatty():
            return {"hold": "package-terminal-needed", "operation_id": ticket["operation_id"], "ticket_id": ticket["ticket_id"],
                    "command": launcher_command(ticket["ticket_id"]), "device_number": payload["device"]["number"] if "device" in payload else None}
        if "firmware_risk" in pc_records.ADAPTERS[action["adapter_id"]]["acknowledgments"]:
            number = str(payload["device"]["number"]) if tty and isinstance(payload.get("device"), dict) else None
            typed = terminal.ask(f"device {number}: ") if number else None
            if not isinstance(typed, str) or typed.strip() != number:
                raise ServiceRefusal("The device number typed in the terminal is not this update's device", code="package-device-number")
            device = "matched"
        checked = {"before": self._read_all(reads, route, payload), "restart_files": self._restart_files(route, probe), "device_number": device}
        if self._drift(route, probe, reads, payload, checked["before"]):
            return {"already_at_target": True, **checked}
        values = route["run"]["values"](payload, payload["recipe"], str(folder))
        argv = package_registry.argv(payload["recipe"], values, executable=bound["path"], run_folder=str(folder),
                                     prefix=readonly_runner.executable_prefix(bound["kind"]))
        return {"argv": argv, "env": environment, "cwd": str(folder), "terminal": tty, **checked}

    @staticmethod
    def _drift(route, probe, reads, payload, before=None):
        """The route's drift(): any change since the plan (a removal, an extra package, power for firmware) holds. An item the
        manager no longer offers does not hold when the route's own verification finds it at its approved target in ``before``,
        the reads taken right now: an earlier item of the plan brought it there, and True says so."""
        held = route["drift"](probe, reads, payload)
        if held is None:
            return False
        if before is not None and held.get("not_offered"):
            found = route["verify"](payload, {"before": before, "after": before, "files": {}})
            if found.get("result") == "updated" and found.get("verified_postcondition") is True:
                return True
        raise ServiceRefusal(held.get("message", "The item changed since the plan"), code=held.get("hold", "package-drift"))

    @staticmethod
    def _open_settings(page_id):
        """Open one fixed Settings page for the person's own step: a typed hold until the Settings route is written."""
        return {"hold": "package-settings-not-built", "settings_page": page_id}

    @staticmethod
    def _read_all(reads, route, payload):
        """{recipe id: result} of the route's verification recipes (and restart probe), each with its own status; a read that
        holds is left out."""
        found = {}
        for recipe_id in (*route["verify_recipes"], *((route["restart_probe"],) if route["restart_probe"] else ())):
            try:
                found[recipe_id] = reads(recipe_id, route["run"]["values"](payload, recipe_id, reads.folder) or None)
            except pc_records.Refusal:
                continue
        return found

    # The effects: run only by run_ticket, through _run_effect, after the effect boundary is written.
    def _effect_package_upgrade(self, session_id, state, operation, action, payload, path, intent, **launched):
        return self._package_run(state, operation, action, payload, path, **launched)

    def _effect_package_reinstall(self, session_id, state, operation, action, payload, path, intent, **launched):
        return self._package_run(state, operation, action, payload, path, **launched)

    def _effect_system_repair(self, session_id, state, operation, action, payload, path, intent, **launched):
        return self._package_run(state, operation, action, payload, path, **launched)

    def _package_run(self, state, operation, action, payload, path, *, launch, route, reads, launcher):
        """Save the reads taken right before the run, start the child and wait for it, record its exit before anything else is
        read, then complete."""
        self._save_before(state, operation, path, launch)
        started, clock, invoked = pc_records.utc_now(), time.monotonic(), True
        try:
            code, tail = launcher(launch["argv"], env=launch["env"], cwd=launch["cwd"], terminal=launch["terminal"])
        except OSError:
            code, tail, invoked = None, b"", False
        finished = pc_records.utc_now()
        code = code if type(code) is int else None
        text, exit_restart = package_routes.text_of(tail if isinstance(tail, bytes) else b""), route["run"].get("exit_restart")
        ran = {"adapter_invoked": invoked, "terminal": "tty_observed" if launch["terminal"] else "not_applicable",
               "device_number": launch["device_number"], "os_consent": self._os_consent(action, route, code),
               "exit": {"code": None if code is None else code & 0xFFFFFFFF, "source": "process", "class": route["classify_exit"](code, text),
                        **({"restart": exit_restart(code, text)} if exit_restart else {}),
                        "signal": -code if code is not None and -64 <= code < 0 else None, "started_utc": started, "finished_utc": finished,
                        "seconds": round(time.monotonic() - clock, 3)}}
        self._immutable(path / EXIT_RECORD, service_value("service_outcome", mode=state["mode"], observed_utc=finished,
                                                          binding=self._bound(operation), receipt=ran))
        return self._complete(state["session_id"], operation, action, payload, route, reads, path, ran)

    def _close_at_target(self, state, operation, action, payload, route, reads, path, launch):
        """An earlier step of the plan brought this item to its approved target: no child starts, and the one completion closes the
        ticket on the route's own read."""
        self._save_before(state, operation, path, launch)
        now = pc_records.utc_now()
        ran = {"adapter_invoked": False, "terminal": "not_applicable", "device_number": launch["device_number"], "os_consent": "not_applicable",
               "exit": {"code": None, "source": "not_started", "class": "nothing_to_do", "signal": None, "started_utc": now, "finished_utc": now, "seconds": 0}}
        return self._complete(state["session_id"], operation, action, payload, route, reads, path, ran, reason="already_at_target")

    @staticmethod
    def _bound(operation):
        return {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}

    def _save_before(self, state, operation, path, launch):
        """Keep the reads taken right before the run with their status, and the restart files that stood then, for every later
        completion: a replay must see a failed read as failed."""
        for recipe_id, found in launch["before"].items():
            write_private_new(path / ("before-" + recipe_id + ".out"), found["stdout"])
        self._immutable(path / BEFORE_RECORD, service_value("service_outcome", mode=state["mode"], observed_utc=pc_records.utc_now(), binding=self._bound(operation),
                                                            receipt={"reads": {recipe_id: {"ok": found.get("ok") is True, "exit_code": found.get("exit_code")}
                                                                               for recipe_id, found in launch["before"].items()},
                                                                     "restart_files": launch["restart_files"]}))

    def _recorded(self, path, name, operation):
        """The receipt of this operation's record ``name`` in its folder, or None when it was never written."""
        if not (path / name).exists():
            return None
        record = service_record(decoded(private_read(path / name)), "service_outcome")
        if record["binding"] != self._bound(operation):
            raise ServiceRefusal("This record belongs to another operation")
        return record["receipt"]

    def _recorded_exit(self, path, operation):
        """What the run recorded when its child ended, or None: without it the child may still be running."""
        return self._recorded(path, EXIT_RECORD, operation)

    def _complete(self, session_id, operation, action, payload, route, reads, path, ran, *, restart="none", **extra):
        """The one completion of a run whose exit is recorded (``ran``), after the run, after the restart and in reconciliation:
        the route's verification, the one result of package_registry.route_result, then the operation closes, once, or waits in
        the restart class. An operation whose restart is accounted for (``restart`` "boot_observed") or whose child never started
        takes no new restart signal; one that closed as unknown and reads a restart signal stays unknown, since no boot was seen.
        ``extra`` adds receipt keys."""
        saved = self._recorded(path, BEFORE_RECORD, operation) or {"reads": {}, "restart_files": {}}
        found = {"before": self._saved_before(path, saved["reads"]), "files_before": saved["restart_files"],
                 "after": self._read_all(reads, route, payload), "files": self._restart_files(route, reads.probe)}
        verification = route["verify"](payload, found)
        marker = operation.get("restart_pending") or {}
        signal, source = marker.get("signal"), marker.get("source")
        waits = ran["adapter_invoked"] and restart != "boot_observed"
        if waits:
            signal, source = package_registry.restart_signal(route, found)
            told = ran["exit"].get("restart")  # the exit's own restart value, on a route that has one
            if ran["exit"]["class"] == "restart" or told == "required_before_retry":
                signal, source = told or "required", "exit_code"
            if "verify_after_restart" in payload["flags"] and signal not in package_registry.RESTART_CLASS_SIGNALS:
                signal, source = "required", "verify_after_restart"
        settled = package_registry.route_result(payload, ran["exit"], verification, signal=signal if waits else None)
        receipt = {**ran, "manager": payload["manager"], "operation": payload["operation"], "id": payload["id"], "version": payload["version"],
                   "already_pending": any(present and saved["restart_files"].get(path_name) for path_name, present in found["files"].items()),
                   "run_kind": payload["run_kind"], "restart": {"signal": signal, "source": source}, "installed_version": verification.get("installed_version"),
                   "changed_outside_plan": verification.get("facts", {}).get("changed_outside_plan"), **extra,
                   **self._result(payload, settled["result"], settled["verified_postcondition"])}
        if settled["result"] == "restart_needed":
            if operation["outcome"] == "unknown":
                return self._still_unknown(operation)
            return self._restart_pending(session_id, operation, receipt, reads.probe)
        outcome = package_registry.CLOSING[settled["result"]]
        if outcome == "unknown" and operation["outcome"] == "unknown":
            return self._still_unknown(operation)
        if settled["result"] != "updated":
            # The facts resolve reads: the read after the run finished, the child's exit is recorded, and an update that binds no
            # recovery has nothing left to retain.
            receipt.update(actual_effects_recorded=settled["verified_postcondition"], no_active_effects=True,
                           recovery_retained=action["requires_recovery"] is False)
        return self._finish(self.engine.read_session(session_id), operation, outcome=outcome, receipt=receipt,
                            kind="reconciliation" if operation["outcome"] == "unknown" else "outcome")

    def _no_exit(self, state, operation, payload):
        """A started run with no recorded exit: route_result's unknown, whatever is installed, because the child may still run."""
        if operation["outcome"] == "unknown":
            return self._still_unknown(operation)
        settled = package_registry.route_result(payload, None, {})
        return self._finish(state, operation, outcome="unknown", receipt={"adapter_invoked": True, "possible_partial_effects": True,
                                                                          **self._result(payload, settled["result"], settled["verified_postcondition"])})

    @staticmethod
    def _still_unknown(operation):
        return {"operation_id": operation["operation_id"], "outcome": "unknown", "held": True, "automatic_retry": False}

    @staticmethod
    def _result(payload, result, verified):
        """The update-result keys every update record carries."""
        return {"result": result, "category": pc_records.UPDATE_RESULTS[result], "group": payload["group"], "verified_postcondition": verified}

    @staticmethod
    def _os_consent(action, route, code):
        """Whether the operating system's consent step was observed: never for an adapter that needs none; "observed" only for
        exit 0 of an elevating executable, which means it ran the command, not that a person typed a password (sudo may ask
        nothing, from its cached credentials or NOPASSWD); otherwise not observed (a refused password, an installer's prompt)."""
        if pc_records.ADAPTERS[action["adapter_id"]]["os_consent"] == "never" or route["run"]["os_consent"] == "not_applicable":
            return "not_applicable"
        return "observed" if route["run"]["os_consent"] == "exit_observed" and code == 0 else "not_observed"

    @staticmethod
    def _restart_files(route, probe):
        """{path: present, or None when that could not be told} of the route's restart files, read through the probe."""
        found = {}
        for path in route["run"].get("restart_files", {}):
            try:
                found[path] = probe.lstat(path) is not None
            except (FileNotFoundError, NotADirectoryError):
                found[path] = False
            except (OSError, ValueError):
                found[path] = None
        return found

    def _not_run(self, payload, reason):
        """A step that never started: a known state, with nothing read, so nothing about what is installed is claimed."""
        return {"adapter_invoked": False, "reason": reason, **self._result(payload, "not_run", False)}

    def _restart_pending(self, session_id, operation, receipt, probe):
        """Record the typed restart signal instead of finishing: the operation stays open in the restart class. The row names
        the boot the step ran in, where the computer has a boot id, so that a later reading of the same boot is not a restart."""
        state = self.engine.read_session(session_id)
        facts = {**self._bound(operation), "outcome": "unknown", "restart_signal": receipt["restart"]["signal"],
                 "restart_source": receipt["restart"]["source"], "result": "restart_needed", "verified_postcondition": False}
        boot_id = self._boot_identity(probe).get("boot_id")
        if isinstance(boot_id, str):
            facts["boot_id"] = boot_id
        value = service_value("service_outcome", mode=state["mode"], observed_utc=pc_records.utc_now(), binding=facts, receipt=receipt)
        self._immutable(self._operation_dir(session_id, operation["operation_id"]) / ("restart-" + uuid.uuid4().hex + ".json"), value)
        row = self._register(state, kind="outcome", value=value, facts=facts, observed_utc=value["observed_utc"])
        response = self.engine.record_restart_pending(session_id, operation_id=operation["operation_id"], evidence_id=row["evidence_id"])
        return {"operation_id": operation["operation_id"], "outcome": None, "receipt": receipt, "evidence_id": row["evidence_id"],
                "workflow": response}

    @staticmethod
    def _boot_identity(probe):
        """The computer's boot reading from a probe that can give one, else {}."""
        boot = getattr(probe, "boot_identity", None)
        return boot() if callable(boot) else {}

    def _boot_evidence(self, state, operation, probe):
        """Read the boot now and register it as a patchcairn.boot.observation; the id of its evidence row."""
        seen = self._boot_identity(probe)
        if not seen:
            raise ServiceRefusal("The check after the restart needs the computer's boot time, which this probe cannot read",
                                 code="package-boot-unavailable")
        observed = pc_records.utc_now()
        record = {"schema": "patchcairn.boot.observation", "schema_version": pc_records.SCHEMA_VERSION, "last_boot_utc": seen.get("last_boot_utc"),
                  "boot_id": seen.get("boot_id"), "observed_utc": observed, "source": seen.get("source", "host_probe")}
        pc_records.parse_utc(record["last_boot_utc"])
        return self._register(state, kind="outcome", value=record, facts={**self._bound(operation), "outcome": "unknown"}, observed_utc=observed)["evidence_id"]

    def _after_restart(self, state, operation, action, payload, route, reads, path, restart):
        """The second run of a ticket in the restart class: the boot observation (a boot already recorded is reused, so an
        interrupted check resumes), then the one completion. It never starts the recipe again."""
        boot = (operation["restart_verification"]["evidence_id"] if restart == "boot_observed"
                else self._boot_evidence(state, operation, reads.probe))
        self.engine.record_boot_observation(state["session_id"], operation_id=operation["operation_id"], evidence_id=boot)
        ran = self._recorded_exit(path, operation)
        if ran is None:
            return self._no_exit(state, operation, payload)
        return self._complete(state["session_id"], operation, action, payload, route, reads, path, ran, restart="boot_observed",
                              after_restart=True, boot_evidence_id=boot)

    @staticmethod
    def _saved_before(path, reads):
        """The verification reads taken right before the run ({recipe id: result}), each with the status ``reads`` recorded for it."""
        return {recipe_id: {**status, "stdout": private_read(path / ("before-" + recipe_id + ".out"), package_routes.MAX_OUTPUT_BYTES)}
                for recipe_id, status in reads.items()}

    # --- reconciliation ------------------------------------------------------------------------------------------------
    def _reconcile_package_upgrade(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_package(session_id, operation, intent, payload, **arguments)

    def _reconcile_package_reinstall(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_package(session_id, operation, intent, payload, **arguments)

    def _reconcile_system_repair(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_package(session_id, operation, intent, payload, **arguments)

    def _reconcile_system_update_handoff(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)

    def _reconcile_system_firmware_update(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)

    def _reconcile_package(self, session_id, operation, intent, payload, *, operation_id, probe=None, reader=None):
        """The actual outcome of an interrupted package run (called with reconcile_operation's lock held). A ticket never
        started closes as not run. A started run without a recorded exit stays unknown, whatever is installed, because the child
        may still be running and is never killed. With the exit recorded, the one completion finishes the job, also for an
        operation whose restart is accounted for or whose signal is gone; one still waiting for its restart waits. Its reads go
        through ``probe`` and ``reader`` when a test gives them; a practice session without both is refused before any read."""
        if operation["outcome"] not in (None, "unknown"):
            raise ServiceRefusal("Known operation receipt is already consumed; retain historical result")
        restart = restart_state(operation)
        if restart == "waiting":
            raise ServiceRefusal("This operation waits for the restart; run its ticket again after the restart", code="package-restart-class")
        state = self.engine.read_session(session_id)
        self._original_authority(state, operation, intent)
        path = self._operation_dir(session_id, operation["operation_id"])
        if not (path / "entered.json").exists() and operation["outcome"] is None:
            return self._finish(state, operation, outcome="failed", receipt=self._not_run(payload, "ticket_never_started"))
        ran = self._recorded_exit(path, operation)
        if ran is None:
            return self._no_exit(state, operation, payload)
        self._refuse_practice(state, probe, reader)
        reads = _Reads(self._run_folder(), probe or readonly_runner.HostProbe(), reader)
        return self._complete(session_id, operation, intent["action"], payload, self._route(payload), reads, path, ran, restart=restart)
