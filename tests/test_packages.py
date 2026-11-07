"""Package routes (G09): the winget, Homebrew, apt and dnf5 route classes, on synthetic fixtures and fakes only.

No test starts a package manager. Parsers read tests/fixtures/packages (fictional package ids); executable resolution
and the read-only runner use FakeProbe and FakeLauncher below. The fictional Windows folders and the fictional home
folder are not user-profile paths.
Run from the repository root: python3 -I -S -B -m unittest discover -s tests -p "test_packages.py"
"""
from __future__ import annotations

import ast
from datetime import datetime, timedelta
import functools
import json
import ntpath
import os
import re
import shlex
from pathlib import Path, PurePosixPath
import stat
import sys
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import urlsplit
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import package_apt as apt  # noqa: E402
import package_registry  # noqa: E402
import package_routes as routes  # noqa: E402
import package_tokens  # noqa: E402
import pc_records  # noqa: E402
import readonly_runner  # noqa: E402
import service_updates  # noqa: E402
from pc_records import Refusal  # noqa: E402
from clock_helpers import utc_now  # noqa: E402
from test_service_state import PROSE, SessionFixtures  # noqa: E402
from workflow_core import WorkflowRefusal  # noqa: E402
from workflow_service import ServiceRefusal  # noqa: E402
from work_fixtures import remove_tree  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "packages"
LOCAL_APPDATA = "D:\\PatchCairnTest\\LocalData"
SYSTEM_DIR = "C:\\Windows\\System32"
PROGRAM_FILES = "C:\\Program Files"
WINGET = routes.winget_alias_path(LOCAL_APPDATA)
APP_FOLDER = "Microsoft.DesktopAppInstaller_1.12.350.0_x64__8wekyb3d8bbwe"
WINGET_EXE = {"path": WINGET, "package": APP_FOLDER}
RUN_FOLDER = "D:\\PatchCairnTest\\run folder"
RUN_LOG = RUN_FOLDER + "\\winget-1.log"
EXPORT_FILE = RUN_FOLDER + "\\winget-export.json"
BREW = "/opt/homebrew/bin/brew"
HOME = "/var/lib/patchcairn-test/example"
NOW = "2026-10-25T12:00:00Z"
ORIGIN = "Example:24.04/example-updates"
SHELLS = {"cmd", "cmd.exe", "sh", "bash", "zsh", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "/bin/sh", "/bin/bash"}
# The documentation allowlist per manager: host and path prefix.
DOC_HOSTS = {"winget": [("learn.microsoft.com", ()), ("github.com", ("microsoft", "winget-cli"))], "brew": [("docs.brew.sh", ())],
             "apt": [("manpages.debian.org", ()), ("manpages.ubuntu.com", ())],
             "dnf": [("dnf.readthedocs.io", ()), ("dnf5.readthedocs.io", ()), ("rpm-software-management.github.io", ())],
             "repair": [("learn.microsoft.com", ()), ("manpages.debian.org", ())]}
# Forbidden rows per manager: one per token of the design's section 3 (patterns such as globs, `<name>/<release>` or
# dpkg `--force-*` are refused by the grammar instead, and winget --name, apt -o and apt-get -s are allowed rows).
# brew has one row fewer than section 3: the legacy JSON format flag is not listed literally, because the frozen G03
# label rule refuses that spelling; render() emits only --json=v2.
FORBIDDEN_ROWS = {"winget": 64, "brew": 47, "apt": 29, "dnf": 44, "repair": 5}


def fixture(name):
    return (FIXTURES / name).read_bytes()


# winget --version prints a leading v; the version-label rule refuses that literal in the source, so tests compose it.
WINGET_V = "v"


def winget_version(text):
    return WINGET_V + text


WINGET_CLIENT = winget_version("1.12.350")
WINGET_OUTPUT = (WINGET_CLIENT + "\n").encode()


def refusals_fail(cls):
    """A hold (Refusal) that a test did not expect is reported as a failure, not an error."""
    def wrap(test):
        @functools.wraps(test)
        def wrapper(self, *args, **kwargs):
            try:
                return test(self, *args, **kwargs)
            except Refusal as error:
                raise self.failureException(f"unexpected hold {error.code}: {error}") from error
        return wrapper
    for name, value in list(vars(cls).items()):
        if name.startswith("test") and callable(value):
            setattr(cls, name, wrap(value))
    return cls


def holds(case, code, function, *args, **kwargs):
    """function(...) must hold with exactly this refusal code, so the intended check is the one that fired."""
    with case.assertRaises(Refusal) as caught:
        function(*args, **kwargs)
    case.assertEqual(caught.exception.code, code)


def regular(uid=0, mode=0o755):
    return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid)


def folder(uid=0, mode=0o755, gid=0):
    return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid, st_gid=gid)


def symlink(uid=0):
    return SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=uid)


class FakeProbe:
    """Executable and environment facts of a fictional computer; nothing on this computer is read."""

    TOOLS = ("/usr/bin/apt-get", "/usr/bin/apt-cache", "/usr/bin/apt-config", "/usr/bin/dpkg-query", "/usr/bin/dpkg",
             "/usr/sbin/needrestart", "/usr/bin/dnf5", "/usr/bin/rpm")
    LINK = [routes.WINGET_PACKAGE, routes.WINGET_PACKAGE + "!winget", ntpath.join(PROGRAM_FILES, "WindowsApps", APP_FOLDER, "winget.exe")]

    def __init__(self, platform="linux", files=None, links=None, uid=1000, machine="arm64", elevation=None,
                 tag=routes.WINGET_TAG, environ=None, newest=None, link=LINK):
        self.platform, self.uid, self.machine_name, self.state, self.tag, self.link = platform, uid, machine, elevation, tag, link
        self.links = {"/usr/bin/dnf": "/usr/bin/dnf5", **(links or {})}
        self.env, self.newest = dict(environ or {"SystemRoot": "C:\\Windows"}), newest
        self.files = {"/": folder(), "/usr": folder(), "/usr/bin": folder(), "/usr/sbin": folder(), "/bin": folder(),
                      "/opt": folder(), "/opt/homebrew": folder(uid), "/opt/homebrew/bin": folder(uid), BREW: regular(uid),
                      **{tool: regular() for tool in self.TOOLS}, **(files or {})}

    def elevation(self):
        return self.state

    def euid(self):
        return self.uid

    def identity(self):
        return HOME, "example"

    def machine(self):
        return self.machine_name

    def realpath(self, path):
        return self.links.get(path, path)

    def lstat(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def environ(self):
        return dict(self.env)

    def local_appdata(self):
        return LOCAL_APPDATA

    def program_files(self):
        return PROGRAM_FILES

    def reparse_tag(self, path):
        return self.tag if path == WINGET else 0

    def appexec_link(self, path):
        return self.link if path == WINGET else None

    def system_directory(self):
        return SYSTEM_DIR

    def newest_release(self, path):
        if isinstance(self.newest, Exception):
            raise self.newest
        return self.newest


class FakeLauncher:
    """Records what the runner would start and returns a fixed exit code and output."""

    def __init__(self, data=b"", code=0):
        self.data, self.code, self.calls = data, code, []

    def __call__(self, argv, *, env, cwd, timeout, max_bytes):
        self.calls.append(SimpleNamespace(argv=argv, env=env, cwd=cwd, timeout=timeout, max_bytes=max_bytes))
        return self.code, self.data


SUDO = "/usr/bin/sudo"
FIXTURE_ROOTS = []


def fixture_root():
    """A new fictional root under work/test-fixtures; tearDownModule removes every one."""
    root = ROOT / "work" / "test-fixtures" / ("pkg-" + uuid.uuid4().hex[:16])
    FIXTURE_ROOTS.append(root)
    return root


def remove_fixture_roots():
    while FIXTURE_ROOTS:
        root = FIXTURE_ROOTS.pop()
        if os.path.lexists(root):  # a test may have used none of its root
            remove_tree(root)


def tearDownModule():
    remove_fixture_roots()

FAKE_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
UPGRADE, REINSTALL, REPAIR = pc_records.ADAPTER_PACKAGE_UPGRADE, pc_records.ADAPTER_PACKAGE_REINSTALL, pc_records.ADAPTER_SYSTEM_REPAIR
FIRMWARE, HANDOFF = pc_records.ADAPTER_SYSTEM_FIRMWARE_UPDATE, pc_records.ADAPTER_SYSTEM_UPDATE_HANDOFF
OPERATION_OF = {UPGRADE: "upgrade", REINSTALL: "reinstall", REPAIR: "repair", FIRMWARE: "firmware_update", HANDOFF: "system_update"}


class FakeChild:
    """The run launcher: records each start (argv, environment, folder, terminal) and returns a fixed exit code and output.
    It has kill and terminate only so a test can prove nothing ever asks for them."""

    def __init__(self, code=0, tail=b"", events=None, error=None):
        self.code, self.tail, self.events, self.error, self.calls, self.killed = code, tail, events, error, [], []

    def __call__(self, argv, **keywords):
        self.calls.append(SimpleNamespace(argv=argv, **keywords))
        if self.events is not None:
            self.events.append("start")
        if self.error:
            raise self.error
        return self.code, self.tail

    def kill(self):
        self.killed.append("kill")

    def terminate(self):
        self.killed.append("terminate")


class FakeTerminal:
    """The terminal run_ticket runs in: whether stdin and stdout are a TTY, and what the person types at the device line."""

    def __init__(self, tty=True, answer=None, events=None):
        self.tty, self.answer, self.events, self.prompts = tty, answer, events, []

    def isatty(self):
        return self.tty

    def ask(self, prompt):
        self.prompts.append(prompt)
        if self.events is not None:
            self.events.append("ask")
        return self.answer


class RunProbe(FakeProbe):
    """FakeProbe plus the run-folder admission, configuration files and (only when given) the boot time of the fictional
    computer; nothing on this computer is read."""

    def __init__(self, *args, text_files=None, folders=None, boot=None, **kwargs):
        kwargs.setdefault("files", {SUDO: regular()})
        super().__init__(*args, **kwargs)
        self.text_files, self.folders, self.admitted = dict(text_files or {}), dict(folders or {}), []
        if boot is not None:
            self.boot_identity = lambda: dict(boot)

    def private_folder(self, path):
        self.admitted.append(path)
        return str(path)

    def read_file(self, path):
        return self.text_files.get(path)

    def list_names(self, folder):
        return self.folders.get(folder)


def sudo_identity():
    return readonly_runner.executable_identity("system", SUDO, program=SUDO, probe=RunProbe())


def fake_route(events=None, *, manager="pip", recipe="apt.configure", run_kind="terminal", drift=None, result="updated", verified=True,
               os_consent="not_observed", restart_probe=None, restart=None, classify=None, self_ids=(), item_flags=None, scripts=None,
               results=None, restart_files=None, dependencies=None):
    """A built route the service has never seen (a manager the core registry does not build), made only of the descriptor fields;
    it runs an existing recipe through sudo, reads apt.audit as its verification and records its hooks in ``events``.
    item_flags, scripts and results map an item id to its flags, install-script names and verification result; dependencies,
    when given, makes the route list what each item id brings with it (a missing id: nothing)."""
    events = [] if events is None else events

    def drift_hook(probe, run, payload):
        events.append("drift")
        return drift

    def verify(payload, reads):
        events.append("verify")
        found = (results or {}).get(payload["id"], result)
        return {"result": found, "verified_postcondition": verified, "installed_version": payload["version"] if found == "updated" else None,
                "facts": {"changed_outside_plan": []}}

    def preflight(probe, run, item, operation):
        events.append("preflight")
        return {"operation": operation, "id": item["id"], "version": "1.0.0", "source": "fictional", "flags": list((item_flags or {}).get(item["id"], ())),
                "script_names": list((scripts or {}).get(item["id"], ())), "preflight": {"version": "1.0.0", "item": item["id"]},
                **({} if dependencies is None else {"dependencies": list(dependencies.get(item["id"], ()))})}

    def plan(candidate, facts):
        fragment = {"manager": manager, "operation": facts["operation"], "id": candidate["id"], "version": candidate["version"],
                    "source": candidate["source"], "group": "apps", "flags": sorted(candidate.get("flags") or ()), "preflight": candidate["preflight"],
                    "dependencies": list(candidate.get("dependencies") or ()), "agreements": sorted(facts.get("agreements") or ()), "run_kind": run_kind,
                    "recipe": recipe, "run_files": {}, "executable": facts["executable"], **({"depends_on": []} if "dependencies" in candidate else {})}
        conditional = package_registry.conditional_of(fragment["flags"], candidate.get("script_names") or ())
        return fragment if conditional is None else {**fragment, "conditional": conditional}

    plan.selection = lambda record: (None if run_kind == "settings" else recipe, run_kind)
    return MappingProxyType({
        "manager": manager, "platforms": ("linux",), "group": "apps", "state": "built", "run_kind": run_kind, "flags": tuple(pc_records.ROUTE_FLAGS),
        "discover": lambda probe, run: {"candidates": [], "left_out": [], "holds": []}, "plan": plan, "drift": drift_hook,
        "verify_recipes": ("apt.audit",), "verify": verify, "restart_probe": restart_probe, "self_ids": self_ids,
        "classify_exit": classify or (lambda code, tail: "success" if code == 0 else "not_observed" if code is None else "failed"),
        "run": MappingProxyType({"recipes": (recipe,), "preflight": preflight, "values": lambda payload, recipe_id, folder: {},
                                 "executable": lambda probe, recipe_id: {"kind": "system", "path": SUDO, "program": SUDO},
                                 "environment": lambda probe: dict(FAKE_ENV), "os_consent": os_consent,
                                 **({"restart": restart} if restart else {}), **({"restart_files": restart_files} if restart_files else {})}),
    })


def fake_payload(route, *, adapter_id=UPGRADE, run_files=None, flags=(), device=None, run_kind=None, settings_page=None):
    fields = {"manager": route["manager"], "operation": OPERATION_OF[adapter_id], "id": "example-tool", "version": "1.0.0", "source": "fictional",
              "group": "apps", "flags": sorted(flags), "preflight": {"version": "1.0.0", "item": "example-tool"}, "run_kind": run_kind or route["run_kind"]}
    if fields["run_kind"] == "settings":
        return package_registry.payload({**fields, "settings_page": settings_page or "windowsupdate"})
    fields.update(dependencies=[], agreements=[], recipe=route["run"]["recipes"][0], executable={"kind": "system", "path": SUDO, "identity": sudo_identity()},
                  run_files={name: pc_records.digest(text.encode("utf-8")) for name, text in sorted((run_files or {}).items())})
    if device is not None:
        fields["device"] = device
    return package_registry.payload(fields, environment=FAKE_ENV)


def registered(*routes):
    """The registry with these routes added (a route for a manager the core does not build plugs in this way)."""
    return mock.patch.object(package_registry, "DESCRIPTORS", MappingProxyType({**package_registry.DESCRIPTORS,
                                                                                **{route["manager"]: route for route in routes}}))


class ManagerRun:
    """The run function a route's hooks get, over fictional output {recipe id: bytes}. A recipe in ``failed`` exits with a code its
    recipe does not expect and prints its output all the same."""

    folder = "fictional-run-folder"

    def __init__(self, outputs, *, failed=(), files=None, folders=None):
        self.outputs, self.failed, self.read_file, self.list_names = outputs, failed, dict(files or {}).get, dict(folders or {}).get

    def __call__(self, recipe_id, values=None):
        ok = recipe_id not in self.failed
        return {"recipe": recipe_id, "ok": ok, "exit_code": 0 if ok else 3, "stdout": self.outputs[recipe_id]}


SETTLED_APT = {"apt.config": fixture("apt-config.txt"), "apt.policy": fixture("apt-policy.txt"), "apt.newer": b""}


def documented(row):
    parts = urlsplit(row.url)
    path = tuple(parts.path.split("/")[1:])
    return (parts.scheme == "https" and not (parts.username or parts.password or parts.port)
            and any(parts.hostname == host and path[:len(prefix)] == prefix for host, prefix in DOC_HOSTS[row.manager]))


def table_problems(managers):
    """Rows of these managers whose page is not on the manager's allowlist, and tokens both allowed and forbidden."""
    rows = [row for row in package_tokens.TOKENS if row.manager in managers]
    overlap = {(r.manager, r.token) for r in rows if r.allowed} & {(r.manager, r.token) for r in rows if not r.allowed}
    counts = [f"{m}: {sum(1 for r in rows if r.manager == m and not r.allowed)} forbidden rows, the design has {FORBIDDEN_ROWS[m]}"
              for m in sorted(managers) if sum(1 for r in rows if r.manager == m and not r.allowed) != FORBIDDEN_ROWS[m]]
    return [row for row in rows if not documented(row)] + sorted(overlap) + counts + ([] if rows else ["no rows"])


def token_problems(manager, argv, values=(), paths=(), shell=True):
    """Literals of argv that are not allowed rows of this manager, are forbidden, or, in a line rendered for a shell,
    would need quoting (product paths excepted). Read-only argv never meets a shell: the runner starts it as a list."""
    found = []
    for token in argv:
        if token in paths:
            continue
        if (shell and routes.needs_quoting(token)) or (manager, token) in package_tokens.FORBIDDEN or token.lower() in SHELLS:
            found.append(token)
        elif token not in values and (manager, token) not in package_tokens.ALLOWED:
            found.append(token)
    return found


def read_recipes(manager):
    return {rid: found for rid, found in routes.READ_RECIPES.items() if found.manager == manager}


def result_of(classification, verification, *, signal=None):
    """The one result function over a parsed exit and a route module's own verification facts."""
    reported = "differs_from_plan" if verification.get("changed_outside_plan") else "updated" if verification["target_installed"] else "did_not_update"
    return package_registry.route_result({"run_kind": "process"}, classification, {"result": reported, "verified_postcondition": verification.get("diff_complete") is not False},
                                         signal=signal)["result"]


def stored(state):
    """A parsed installed state after a round trip through the canonical record encoder, as PKG-INT stores it."""
    return pc_records.decode_strict(pc_records.encoded(state))


@refusals_fail
class WingetRouteTests(unittest.TestCase):
    def entry(self, d5="winget-installed-before.txt", client=None, source=None, agreements=None, executable=None):
        candidates, _ = routes.winget_candidates(fixture("winget-upgrades.txt"), fixture("winget-export.json"), exit_code=0)
        candidate = next((c for c in candidates if c["id"] == "Contoso.NoteTaker"), None)
        if candidate is None:
            self.fail("discovery did not offer Contoso.NoteTaker")
        confirm = routes.winget_installed(fixture(d5) if isinstance(d5, str) else d5, "Contoso.NoteTaker")
        return routes.plan_winget(candidate, confirm, client=routes.winget_client(client or WINGET_OUTPUT),
                                  source=routes.winget_source(source or fixture("winget-source.json")),
                                  agreements=agreements or {"source": True, "package": False}, executable=executable or WINGET_EXE)

    def test_discovery_argv_is_read_only(self):
        values = {"winget.export": {"export_file": EXPORT_FILE}, "winget.installed": {"id": "Contoso.NoteTaker"}}
        argvs = {rid: routes.render(rid, values.get(rid), executable=WINGET, run_folder=RUN_FOLDER) for rid in read_recipes("winget")}
        self.assertEqual(set(argvs), {"winget.version", "winget.source", "winget.export", "winget.upgrades", "winget.installed"})
        self.assertEqual(argvs["winget.upgrades"], (WINGET, "list", "--upgrade-available", "--source", "winget", "--disable-interactivity"))
        self.assertEqual(argvs["winget.source"], (WINGET, "source", "export", "--name", "winget", "--disable-interactivity"))
        self.assertEqual(argvs["winget.export"], (WINGET, "export", "--output", EXPORT_FILE, "--source", "winget", "--include-versions",
                                                  "--disable-interactivity"))
        self.assertEqual(argvs["winget.installed"][1:5], ("list", "--id", "Contoso.NoteTaker", "--exact"))
        consent = routes.render("winget.upgrades", {"source_agreements": True}, executable=WINGET)
        self.assertEqual(consent[-1], "--accept-source-agreements")
        changing = {"upgrade", "install", "uninstall", "import", "configure", "download", "repair", "pin", "settings", "update",
                    "--accept-package-agreements", "--silent"}
        for argv in argvs.values():
            self.assertFalse(changing & set(argv), argv)
            self.assertEqual(token_problems("winget", argv, values=("Contoso.NoteTaker",), paths=(WINGET, EXPORT_FILE), shell=False), [])
        for outside in ("D:\\Shared\\winget-export.json", "C:\\ProgramData\\Startup\\winget-export.json"):
            holds(self, "package-recipe-values", routes.render, "winget.export", {"export_file": outside}, executable=WINGET, run_folder=RUN_FOLDER)
        holds(self, "package-recipe-values", routes.render, "winget.export", {"export_file": EXPORT_FILE}, executable=WINGET)
        self.assertLessEqual(set(argvs), set(readonly_runner.recipes()))
        self.assertNotIn("winget.upgrade", readonly_runner.recipes())

    def test_plan_binds_exact_id_version_and_source(self):
        candidates, held = routes.winget_candidates(fixture("winget-upgrades.txt"), fixture("winget-export.json"), exit_code=0)
        self.assertEqual([c["id"] for c in candidates], ["Contoso.NoteTaker", "Fabrikam.PhotoViewerPro"])
        self.assertEqual(sorted(h["reason"] for h in held), ["explicit_or_pinned", "id-unresolved", "id-unresolved", "version-unknown"])
        self.assertIn({"id": "Adatum.SyncPlus", "reason": "explicit_or_pinned"}, held)
        self.assertNotIn(b"Source", fixture("winget-upgrades.txt"))  # --source winget: winget prints no Source column
        entry = self.entry()
        self.assertEqual({key: entry[key] for key in ("manager", "id", "installed_version", "target_version", "source")},
                         {"manager": "winget", "id": "Contoso.NoteTaker", "installed_version": "3.4.0", "target_version": "3.4.1",
                          "source": "winget"})
        self.assertEqual(entry["preflight"]["source_identity"], dict(routes.WINGET_SOURCE))
        self.assertEqual(entry["executable"], {"kind": "winget_alias", "path": WINGET, "package": APP_FOLDER, "reparse_tag": 0x8000001B})
        self.assertEqual(entry["agreements"], {"source": True, "package": False})
        for bad in ("Contoso", "Contoso Notes", "Contoso.Note$Taker", "Contoso.NoteTaker;calc", "Contoso.Note\u2026"):
            holds(self, "package-token", routes.variable, "id", bad)
        store = dict(json.loads(fixture("winget-source.json")), Arg="https://storeedgefd.dsx.mp.microsoft.com",
                     Identifier="StoreEdgeFD", Type="Microsoft.Rest")
        holds(self, "winget-source", routes.winget_source, json.dumps(store).encode())
        confirm = routes.winget_installed(fixture("winget-installed-before.txt"), "Contoso.NoteTaker")
        holds(self, "winget-agreements", routes.plan_winget, candidates[0], confirm, client=WINGET_CLIENT, source=dict(routes.WINGET_SOURCE),
              agreements={"source": True}, executable=WINGET_EXE)
        for executable in ({"path": "D:\\Tools\\winget.exe", "package": APP_FOLDER}, {"path": WINGET, "package": "Contoso.Fake_1.0_x64__abc"}, None):
            holds(self, "winget-alias", routes.plan_winget, candidates[0], confirm, client=WINGET_CLIENT, source=dict(routes.WINGET_SOURCE),
                  agreements={"source": True, "package": True}, executable=executable)

    def test_run_argv_is_fixed_and_refuses_forbidden_flags(self):
        argv = routes.run_argv(self.entry(), log_file=RUN_LOG, run_folder=RUN_FOLDER)
        self.assertEqual(argv, (WINGET, "upgrade", "--id", "Contoso.NoteTaker", "--exact", "--version", "3.4.1", "--source", "winget",
                                "--silent", "--disable-interactivity", "--accept-source-agreements", "--log", RUN_LOG))
        both = routes.run_argv(self.entry(agreements={"source": True, "package": True}), log_file=RUN_LOG, run_folder=RUN_FOLDER)
        self.assertEqual(both[11:13], ("--accept-package-agreements", "--accept-source-agreements"))
        neither = routes.run_argv(self.entry(agreements={"source": False, "package": False}), log_file=RUN_LOG, run_folder=RUN_FOLDER)
        self.assertFalse({"--accept-package-agreements", "--accept-source-agreements"} & set(neither))
        self.assertEqual(token_problems("winget", argv, values=("Contoso.NoteTaker", "3.4.1"), paths=(WINGET, RUN_LOG)), [])
        self.assertEqual(routes.run_argv(self.entry(), executable=WINGET, log_file=RUN_LOG, run_folder=RUN_FOLDER), argv)
        for other in ("D:\\attacker\\Microsoft\\WindowsApps\\winget.exe", "C:\\Microsoft\\WindowsApps\\winget.exe"):
            holds(self, "package-executable", routes.run_argv, self.entry(), executable=other, log_file=RUN_LOG, run_folder=RUN_FOLDER)
        for flag in ("--force", "--ignore-security-hash", "--override", "--custom", "-m", "--manifest", "--allow-reboot",
                     "--ignore-local-archive-malware-scan"):
            self.assertIn(("winget", flag), package_tokens.FORBIDDEN)
        good = {"id": "Contoso.NoteTaker", "version": "3.4.1", "log_file": RUN_LOG}
        for change, code in (({"id": "--force"}, "package-token"), ({"version": "--override"}, "package-token"),
                             ({"override": "x"}, "package-recipe-values"), ({"log_file": "D:\\run\\other.log"}, "package-recipe-values"),
                             ({"log_file": "winget-1.log"}, "package-recipe-values"), ({"log_file": "D:\\elsewhere\\winget-1.log"}, "package-recipe-values"),
                             ({"package_agreements": "yes"}, "package-recipe-values")):
            holds(self, code, routes.render, "winget.upgrade", {**good, **change}, executable=WINGET, run_folder=RUN_FOLDER)
        for executable in ("winget.exe", "D:\\Tools\\winget.exe", None):
            holds(self, "winget-alias", routes.render, "winget.upgrade", good, executable=executable, run_folder=RUN_FOLDER)
        self.assertEqual(table_problems({"winget", "repair"}), [])

    def test_verification_requires_planned_version(self):
        entry = self.entry()
        after = routes.verify_winget(entry, fixture("winget-installed-after.txt"))
        self.assertTrue(after["target_installed"])
        self.assertEqual((after["changed"], after["changed_outside_plan"]), (None, None))
        self.assertEqual(result_of(routes.classify_exit("winget", 0), after), "updated")
        unchanged = routes.verify_winget(entry, fixture("winget-installed-before.txt"))
        self.assertEqual((unchanged["target_installed"], unchanged["reason"]), (False, "version_differs"))
        self.assertEqual(result_of(routes.classify_exit("winget", 0), unchanged), "did_not_update")
        newer = fixture("winget-installed-after.txt").replace(b"3.4.1", b"3.5.0")
        self.assertFalse(routes.verify_winget(entry, newer)["target_installed"])
        for gone in (b"No installed package found matching input criteria.\n", fixture("winget-installed-after.txt") * 2):
            self.assertEqual(routes.verify_winget(entry, gone), {"target_installed": False, "reason": "winget-confirm", "changed": None,
                                                                 "changed_outside_plan": None, "diff_complete": None})
        truncated_name = b"Name                 Id                 Version\n" + b"-" * 50 + b"\nContoso Contoso\xe2\x80\xa6  Contoso.NoteTaker  3.4.1\n"
        self.assertTrue(routes.verify_winget(entry, truncated_name)["target_installed"])
        self.assertEqual(routes.render("winget.installed", {"id": entry["id"]}, executable=WINGET)[1:4], ("list", "--id", entry["id"]))

    def test_executable_is_absolute_and_no_shell(self):
        self.assertTrue(ntpath.isabs(WINGET))
        self.assertTrue(WINGET.endswith("\\Microsoft\\WindowsApps\\winget.exe"))
        for local in ("LocalData", "\\\\server\\share\\LocalData", "D:\\a\\..\\b", "D:\\a\"b", None):
            holds(self, "winget-alias", routes.winget_alias_path, local)
        launcher = FakeLauncher(WINGET_OUTPUT)
        result = readonly_runner.run_recipe("winget.version", launcher=launcher, probe=FakeProbe(platform="win32"))
        self.assertEqual(launcher.calls[0].argv, (WINGET, "--version"))
        self.assertIsInstance(launcher.calls[0].argv, tuple)
        self.assertEqual(launcher.calls[0].cwd, SYSTEM_DIR)
        self.assertFalse(SHELLS & {token.lower() for token in launcher.calls[0].argv})
        self.assertEqual(routes.winget_client(result["stdout"]), WINGET_CLIENT)
        self.assertEqual(readonly_runner.winget_executable(FakeProbe(platform="win32")), WINGET_EXE)
        lookalike = [routes.WINGET_PACKAGE, routes.WINGET_PACKAGE + "!winget", "D:\\Elsewhere\\" + APP_FOLDER + "\\winget.exe"]
        for probe in (FakeProbe(platform="win32", tag=0), FakeProbe(platform="linux"), FakeProbe(platform="win32", link=None),
                      FakeProbe(platform="win32", link=["Contoso.Fake_abc", "Contoso.Fake_abc!app", FakeProbe.LINK[2]]),
                      FakeProbe(platform="win32", link=lookalike)):
            holds(self, "runner-executable", readonly_runner.run_recipe, "winget.version", launcher=launcher, probe=probe)
        self.assertEqual(len(launcher.calls), 1)

    def test_restart_signal_is_reported_not_triggered(self):
        cases = {0x8A150109: ("restart", "required"), 0x8A150109 - 2 ** 32: ("restart", "required"),
                 0x8A15010B: ("restart", "initiated_by_installer"), 0x8A15010A: ("failed", "required_before_retry"),
                 3010: ("restart", "required"), 0: ("success", "unknown"), 0x8A150123: ("failed", "unknown")}
        for code, expected in cases.items():
            result = routes.classify_exit("winget", code)
            self.assertEqual((result["class"], result["restart"]), expected, hex(code))
            self.assertEqual((result["exit_code"], result["from_probes"]), (code & 0xFFFFFFFF, False))
        pending = routes.classify_exit("winget", 0x8A150109)
        self.assertEqual(result_of(pending, {"target_installed": False}, signal=pending["restart"]), "restart_needed")
        shell = routes.classify_exit("winget", 9, source="shell")
        self.assertEqual((shell["class"], shell["exit_code"]), ("not_observed", None))
        self.assertNotIn("--allow-reboot", routes.run_argv(self.entry(), log_file=RUN_LOG, run_folder=RUN_FOLDER))
        self.assertIn(("winget", "--allow-reboot"), package_tokens.FORBIDDEN)

    def test_environment_is_fixed(self):
        hostile = {"systemroot": "D:\\Evil", "windir": "D:\\Evil", "TEMP": "D:\\Temp", "Path": "D:\\Evil", "PYTHONPATH": "D:\\Evil",
                   "WINGET_SETTINGS": "1", "PSModulePath": "D:\\Evil", "ComSpec": "D:\\Evil\\cmd.exe", "ProgramFiles": "C:\\Program Files\x00"}
        env = routes.environment("winget", windows=hostile, system_dir=SYSTEM_DIR)
        folders = [SYSTEM_DIR, "C:\\Windows", SYSTEM_DIR + "\\Wbem", ntpath.join(SYSTEM_DIR, r"WindowsPowerShell\v1.0"), SYSTEM_DIR + "\\OpenSSH"]
        self.assertEqual(env, {"TEMP": "D:\\Temp", "SystemRoot": "C:\\Windows", "windir": "C:\\Windows", "ComSpec": SYSTEM_DIR + "\\cmd.exe",
                               "PATH": ";".join(folders)})
        self.assertEqual(routes.environment("winget", windows={}, system_dir=SYSTEM_DIR)["SystemRoot"], "C:\\Windows")
        launcher = FakeLauncher(WINGET_OUTPUT)
        readonly_runner.run_recipe("winget.version", launcher=launcher, probe=FakeProbe(platform="win32", environ=hostile))
        self.assertEqual(launcher.calls[0].env, env)
        self.assertEqual((launcher.calls[0].timeout, launcher.calls[0].max_bytes), (600, 32 * 1024 * 1024))
        for system_dir in ("System32", "C:\\Windows;D:\\Evil", None):
            holds(self, "package-environment", routes.environment, "winget", windows=hostile, system_dir=system_dir)

    def test_provenance_preflight_holds_on_drift(self):
        planned = self.entry()
        self.assertEqual(routes.drift(planned, self.entry()), [])
        self.assertEqual(routes.drift(planned, self.entry(client=winget_version("1.12.400\n").encode())), ["preflight.client_version"])
        moved = {"path": "E:\\Profile\\Microsoft\\WindowsApps\\winget.exe", "package": APP_FOLDER}
        self.assertEqual(routes.drift(planned, self.entry(executable=moved)), ["executable"])
        replaced = {"path": WINGET, "package": "Microsoft.DesktopAppInstaller_1.12.351.0_x64__8wekyb3d8bbwe"}
        self.assertEqual(routes.drift(planned, self.entry(executable=replaced)), ["executable"])
        holds(self, "winget-source", routes.winget_source, json.dumps(dict(json.loads(fixture("winget-source.json")),
                                                                           Arg="https://cdn.example.invalid/cache")).encode())
        candidate = routes.winget_candidates(fixture("winget-upgrades.txt"), fixture("winget-export.json"), exit_code=0)[0][0]
        confirm = routes.winget_installed(fixture("winget-installed-before.txt"), candidate["id"])
        for identity in (dict(routes.WINGET_SOURCE, Arg="https://cdn.example.invalid/cache"), {}):
            holds(self, "winget-source", routes.plan_winget, candidate, confirm, client=WINGET_CLIENT, source=identity,
                  agreements={"source": True, "package": True}, executable=WINGET_EXE)
        for state in ("elevated", "system"):
            holds(self, "package-elevated", routes.refuse_elevated, state)
            holds(self, "package-elevated", readonly_runner.run_recipe, "winget.version", launcher=FakeLauncher(),
                  probe=FakeProbe(platform="win32", elevation=state))
        self.assertIsNone(routes.refuse_elevated(None))

    def test_transaction_drift_holds(self):
        planned = self.entry()
        newer = fixture("winget-installed-before.txt").replace(b"3.4.1", b"3.4.2")
        self.assertEqual(routes.drift(planned, self.entry(d5=newer)), ["target_version", "transaction.available_version"])
        holds(self, "winget-confirm", self.entry, d5="winget-installed-after.txt")
        holds(self, "winget-confirm", self.entry, d5=fixture("winget-installed-after.txt").replace(b"3.4.1", b"3.4.0"))
        holds(self, "winget-confirm", self.entry, d5=fixture("winget-installed-before.txt").replace(b"3.4.0 ", b"3.3.9 "))

    def test_stale_package_lists_reported_not_up_to_date(self):
        stale = routes.list_age("winget", "2026-10-18T11:59:59Z", now_utc=NOW)
        self.assertEqual((stale["status"], stale["message"]), ("stale", "stale; refresh needed"))
        week = routes.list_age("winget", "2026-10-18T12:00:00Z", now_utc=NOW)
        self.assertEqual((week["status"], week["age_days"]), ("recent", 7))
        unknown = routes.list_age("winget", None, now_utc=NOW)
        self.assertEqual(unknown["status"], "unknown")
        self.assertIn("winget maintains its own source cache", unknown["message"])
        future = routes.list_age("winget", "2026-10-26T00:00:00Z", now_utc=NOW)
        self.assertEqual(future["status"], "unknown")
        for result in (stale, week, unknown, future):
            self.assertNotIn("up to date", result["message"].lower())
        self.assertIsNone(readonly_runner.package_list_time("winget", probe=FakeProbe(platform="win32")))

    def test_leading_dash_id_refused(self):
        for bad in ("-Northwind.Shell", "--force", "-m"):
            holds(self, "package-token", routes.variable, "id", bad)
            holds(self, "package-token", routes.render, "winget.installed", {"id": bad}, executable=WINGET)
            holds(self, "package-token", routes.render, "winget.upgrade", {"id": bad, "version": "1.0", "log_file": RUN_LOG},
                  executable=WINGET, run_folder=RUN_FOLDER)
            holds(self, "package-token", routes.winget_installed, fixture("winget-installed-before.txt"), bad)
        candidates, held = routes.winget_candidates(fixture("winget-upgrades.txt"), fixture("winget-export.json"), exit_code=0)
        self.assertNotIn("-Northwind.Shell", [c["id"] for c in candidates] + [h["id"] for h in held])
        self.assertNotIn("-Northwind.Shell", routes.winget_export(fixture("winget-export.json")))
        holds(self, "package-token", routes.plan_winget, {"id": "-Northwind.Shell", "installed_version": "1.0"},
              {"installed_version": "1.0", "available_version": "1.1"}, client=WINGET_CLIENT, source=dict(routes.WINGET_SOURCE),
              agreements={"source": True, "package": True}, executable=WINGET_EXE)

    def test_no_updates_is_reported_only_for_known_empty_output(self):
        empty, export = fixture("winget-no-upgrades.txt"), fixture("winget-export.json")
        for code in (0, routes.WINGET_NO_APPS):
            self.assertEqual(routes.winget_candidates(empty, export, exit_code=code), ([], []))
        # winget always prints a message for an empty list, so empty output, or a row without its table, is not "no updates".
        for data, code in ((empty, 1), (empty, 0x8A150046), (b"Contoso Notes Contoso.NoteTaker 3.4.0 3.4.1\n", 0), (b"", 0),
                           (b"  \r\n\r\n", 0), (b"Contoso Notes Contoso.NoteTaker 3.4.0 3.4.1\n", routes.WINGET_NO_APPS)):
            holds(self, "winget-table", routes.winget_candidates, data, export, exit_code=code)
        # The explicit-targeting table is never the main table, even when it is the only table winget prints.
        # Spinner fragments alone are not winget's "no package found" message.
        holds(self, "winget-table", routes.winget_candidates, b"   - \r   \\ \r", export, exit_code=0)
        # A row this parser cannot read ends its table; discovery holds instead of dropping it and the rows after it.
        head = b"Name                  Id                 Version Available\n" + b"-" * 58 + b"\n"
        notes, viewer = b"Contoso Notes         Contoso.NoteTaker  3.4.0   3.4.1\n", b"Fabrikam Photo Viewer Fabrikam.PhotoViewerPro 8.7.0 8.7.1\n"
        for odd in (b"1.1 Beta", b"1.1~rc2", b"2024.1(3)"):
            row = b"Example App           Example.App        1.0     " + odd + b"\n"
            for data in (head + row + notes, head + notes + row + viewer, head + viewer + notes + row):
                holds(self, "winget-table", routes.winget_candidates, data + b"3 upgrades available.\n", export, exit_code=0)
        source = (b"Name                  Id                 Version Available Source\n" + b"-" * 64 + b"\n"
                  b"Contoso Notes         Contoso.NoteTaker  3.4.0   3.4.1     winget\n1 upgrades available.\n")
        holds(self, "winget-table", routes.winget_candidates, source, export, exit_code=0)
        # A summary line with a number (some languages) is not a row.
        for summary in (b"Es gibt 2 Upgrades.\n", b"2 mises a niveau disponibles.\n"):
            self.assertEqual([c["id"] for c in routes.winget_candidates(head + notes + viewer + summary, export, exit_code=0)[0]],
                             ["Contoso.NoteTaker", "Fabrikam.PhotoViewerPro"])
        for explicit in (fixture("winget-explicit-only.txt"), fixture("winget-explicit-only.txt").replace(b"\n", b"\r\n")):
            self.assertEqual(routes.winget_candidates(explicit, export, exit_code=0), ([], [{"id": "Adatum.SyncPlus", "reason": "explicit_or_pinned"}]))
        holds(self, "winget-exit", routes.winget_candidates, fixture("winget-upgrades.txt"), export, exit_code=routes.WINGET_NO_APPS)
        self.assertEqual(routes.READ_RECIPES["winget.upgrades"].ok_exits, frozenset({0, 0x8A150014}))

    def test_output_variants_parse_or_hold(self):
        crlf = fixture("winget-upgrades.txt").replace(b"\n", b"\r\n")
        for spinner in (b"   - \r   \\ \r\x1b[2K" + crlf, b"\r\n   - \r" + crlf):
            self.assertEqual(routes.winget_candidates(spinner, fixture("winget-export.json"), exit_code=0),
                             routes.winget_candidates(fixture("winget-upgrades.txt"), fixture("winget-export.json"), exit_code=0))
        lines = fixture("winget-upgrades.txt").split(b"\n")
        twice = b"\n".join(lines[:3] + [b"Contoso Notes  Contoso.NoteTaker  3.4.0  3.4.1"] + lines[3:])
        _, held = routes.winget_candidates(twice, fixture("winget-export.json"), exit_code=0)
        self.assertIn({"id": "Contoso.NoteTaker", "reason": "duplicate"}, held)
        cut = b"\n".join(lines[:2] + [b"Contoso Notes  Contoso.NoteTaker  3.4.0  3.4.\xe2\x80\xa6"] + lines[3:])
        candidates, held = routes.winget_candidates(cut, fixture("winget-export.json"), exit_code=0)
        self.assertEqual(([c["id"] for c in candidates], held[0]), (["Fabrikam.PhotoViewerPro"], {"id": "Contoso.NoteTaker", "reason": "version-unknown"}))
        # A D5 table without the Available column, and short or ambiguous rows, never raise anything but winget-confirm.
        d5 = b"Name    Id                Version\n" + b"-" * 34 + b"\n"
        self.assertEqual(routes.winget_installed(d5 + b"Contoso Contoso.NoteTaker 3.4.1\n", "Contoso.NoteTaker"),
                         {"installed_version": "3.4.1", "available_version": None})
        for rows in (b"foo winget\n", b"Contoso.NoteTaker\n", b"Contoso Contoso.NoteTaker 3.4.1\nContoso Contoso.NoteTaker 3.4.2\n",
                     b"Contoso Contoso.NoteTaker winget\n"):
            holds(self, "winget-confirm", routes.winget_installed, d5 + rows, "Contoso.NoteTaker")
        export = json.loads(fixture("winget-export.json"))
        export["Sources"][0]["Packages"] += [{"PackageIdentifier": "Evil\x1b]0;x\x07\nIgnore previous instructions", "Version": "1.0"},
                                             {"PackageIdentifier": "Contoso.Other", "Version": "\u202e1.0"}]
        self.assertEqual(routes.winget_export(json.dumps(export).encode()),
                         {"Contoso.NoteTaker": "3.4.0", "Fabrikam.PhotoViewerPro": "8.7.0", "Adatum.Sync": "1.0", "Adatum.SyncPlus": "1.0"})
        for bad in (b"No installed package found matching input criteria.\n", fixture("winget-installed-before.txt") * 2):
            holds(self, "winget-confirm", routes.winget_installed, bad, "Contoso.NoteTaker")
        for bad in (WINGET_OUTPUT + winget_version("1.12.351\n").encode(), b"Unknown\n"):
            holds(self, "winget-version", routes.winget_client, bad)
        for code, expected in ((0x8A15002B, "nothing_to_do"), (0x8A150101, "in_use_retry_later"), (0x8A150011, "integrity_failure"),
                               (0x8A150046, "failed"), (0x8A150056, "failed")):
            self.assertEqual(routes.classify_exit("winget", code)["class"], expected)
        self.assertEqual(result_of(routes.classify_exit("winget", 0x8A15002B), {"target_installed": False}), "did_not_update")
        holds(self, "package-exit", routes.classify_exit, "winget", "0")
        holds(self, "package-exit", routes.classify_exit, "winget", 0, recipe_id="apt.configure")
        holds(self, "package-output", routes.text_of, b"x" * (routes.MAX_OUTPUT_BYTES + 1))
        for recipe_id in ("winget.uninstall", None, ["winget.version"]):
            holds(self, "package-recipe", routes.render, recipe_id, executable=WINGET)
        with mock.patch.object(routes, "READ_RECIPES", {"winget.version": package_tokens.Recipe("winget", "winget", ("--force",))}):
            holds(self, "package-token-not-allowed", routes.render, "winget.version", executable=WINGET)
        holds(self, "package-elevation", routes.refuse_elevated, "administrator")
        candidate = routes.winget_candidates(fixture("winget-upgrades.txt"), fixture("winget-export.json"), exit_code=0)[0][0]
        confirm = routes.winget_installed(fixture("winget-installed-before.txt"), candidate["id"])
        holds(self, "winget-source", routes.plan_winget, candidate, confirm, client=WINGET_CLIENT,
              source=dict(routes.WINGET_SOURCE, Type="Microsoft.Rest"), agreements={"source": True, "package": True}, executable=WINGET_EXE)

    def test_security_failures_are_integrity_failures(self):
        # returnCodes.md: INDEX_INTEGRITY_COMPROMISED, SOURCE_NOT_SECURE, PINNED_CERTIFICATE_MISMATCH, ARCHIVE_SCAN_FAILED.
        for code in (0x8A15000A, 0x8A15001A, 0x8A15005E, 0x8A150060):
            with self.subTest(code=hex(code)):
                found = routes.classify_exit("winget", code)
                self.assertEqual((found["class"], found["reason"], found["restart"]), ("integrity_failure", "", "none"))
                exited = {"class": package_registry.WINGET["classify_exit"](code, "")}
                self.assertEqual(package_registry.route_result({"run_kind": "process"}, exited, {"result": "did_not_update", "verified_postcondition": True}),
                                 {"result": "integrity_failure", "verified_postcondition": False})

    def test_exit_zero_with_the_restart_sentence_needs_a_restart(self):
        printed = "Successfully installed\nRestart your PC to finish installation.\n"
        for output in (printed, printed.encode(), b"\x1b[33mRestart your PC to finish installation.\x1b[0m\r\n"):
            with self.subTest(output=output):
                found = routes.classify_exit("winget", 0, output=output)
                self.assertEqual((found["exit_code"], found["class"], found["restart"]), (0, "restart", "required"))
        self.assertEqual(package_registry.WINGET["classify_exit"](0, printed), "restart")
        self.assertEqual(package_registry.WINGET["run"]["exit_restart"](0, printed), "required")
        # Without the sentence exit 0 says nothing about a restart: another display language stays unknown, never "none".
        for output in ("", "Successfully installed\n", "Starten Sie den PC neu, um die Installation abzuschliessen.\n"):
            found = routes.classify_exit("winget", 0, output=output)
            self.assertEqual((found["class"], found["restart"]), ("success", "unknown"), output)
        # The sentence changes only exit 0.
        self.assertEqual(routes.classify_exit("winget", 0x8A150101, output=printed)["class"], "in_use_retry_later")
        self.assertEqual(routes.classify_exit("winget", 9, output=printed, source="shell")["class"], "not_observed")

    def test_a_dash_word_with_a_dot_is_quoted_for_powershell(self):
        self.assertEqual(package_registry.shell_line((WINGET, "-name.ext", "--name.ext", "-m", "plain.word")),
                         f"& '{WINGET}' '-name.ext' --name.ext -m plain.word")

    def test_the_export_is_removed_once_it_was_read(self):
        def computer(error=None):
            events = []
            def run(recipe_id, values=None):
                events.append(recipe_id)
                if error and recipe_id == "winget.upgrades":
                    raise error
                return {"ok": True, "exit_code": 0, "stdout": b""}
            run.folder = RUN_FOLDER
            run.read_file = lambda path: events.append("read") or b""
            run.discard = lambda path: events.append(path)
            return run, events
        run, events = computer()
        with mock.patch.object(routes, "winget_candidates", return_value=([{"id": "Contoso.NoteTaker"}], [])):
            self.assertEqual(package_registry._winget_listing(None, run), ([{"id": "Contoso.NoteTaker"}], []))
        self.assertEqual(events, ["winget.export", "winget.upgrades", "read", EXPORT_FILE])
        # A listing that holds leaves no inventory behind either.
        run, events = computer(Refusal("runner-timeout", "fictional"))
        holds(self, "runner-timeout", package_registry._winget_listing, None, run)
        self.assertEqual(events[-1], EXPORT_FILE)
        run, events = computer()
        with mock.patch.object(routes, "winget_candidates", side_effect=Refusal("winget-table", "fictional")):
            holds(self, "winget-table", package_registry._winget_listing, None, run)
        self.assertEqual(events[-1], EXPORT_FILE)


def brew_one(name, source):
    """A fixture narrowed to one package, as `brew outdated` and `brew info` print it for a named package."""
    document = json.loads(fixture(source))
    return {part: [item for item in document[part] if name in (item.get("name"), item.get("token"))] for part in ("formulae", "casks")}


def brew_run(outputs=None, files=None):
    """A run function over fictional Homebrew output (recipe id -> bytes), for the registry's Homebrew hooks; brew.env files by path."""
    table = {"brew.version": fixture("brew-version.txt"), "brew.outdated_one": json.dumps(brew_one("examplefetch", "brew-outdated.json")).encode(),
             "brew.info_one": json.dumps(brew_one("examplefetch", "brew-info.json")).encode(), "brew.dry_run": fixture("brew-dry-run.txt"), **(outputs or {})}
    def run(recipe_id, values=None):
        return {"recipe": recipe_id, "ok": True, "exit_code": 0, "stdout": table[recipe_id]}
    run.read_file = (files or {}).get
    return run


MAC = "darwin"
FETCH = {"id": "examplefetch", "kind": "formula"}
BREW_PREFLIGHT = package_registry.BREW["run"]["preflight"]


@refusals_fail
class HomebrewRouteTests(unittest.TestCase):
    def env_check(self, **files):
        return routes.check_brew_env({"system": None, "prefix": None, "user": None, **files})

    def candidates(self, outdated=None, info=None):
        return routes.brew_candidates(outdated or fixture("brew-outdated.json"), info or fixture("brew-info.json"))

    def entry(self, kind="formula", name="examplefetch", version=None, env=None, outdated=None, info=None, machine="arm64", dry_run=None):
        candidate = next((c for c in self.candidates(outdated, info)[0] if (c["kind"], c["name"]) == (kind, name)), None)
        if candidate is None:
            self.fail(f"{kind} {name} is not an eligible candidate")
        dependencies = routes.brew_dependencies(dry_run or fixture("brew-dry-run.txt"), name, candidate["target_version"]) \
            if name == "examplefetch" else []
        return routes.plan_brew(candidate, version=routes.brew_version(version or fixture("brew-version.txt")),
                                path=routes.BREW_PATHS[machine], machine=machine, env=env or self.env_check(), dependencies=dependencies)

    def info_with(self, **versions):
        """brew-info-after.json with other installed versions; a value is a formula version or a (cask) string."""
        info = json.loads(fixture("brew-info-after.json"))
        for item in info["formulae"]:
            if item["name"] in versions:
                item["installed"], item["linked_keg"] = [{"version": versions[item["name"]]}], versions[item["name"]]
        for item in info["casks"]:
            item["installed"] = versions.get(item["token"], item["installed"])
        return json.dumps(info).encode()

    def test_discovery_argv_is_read_only(self):
        values = {"brew.outdated_one": {"kind": "--formula", "name": "examplefetch"}, "brew.info_one": {"kind": "--cask", "name": "exampleviewer"},
                  "brew.dry_run": {"kind": "--formula", "name": "examplefetch"}}
        argvs = {rid: routes.render(rid, values.get(rid), executable=BREW) for rid in read_recipes("brew")}
        self.assertEqual(argvs["brew.version"], (BREW, "--version"))
        self.assertEqual(argvs["brew.outdated"], (BREW, "outdated", "--json=v2"))
        self.assertEqual(argvs["brew.info"], (BREW, "info", "--json=v2", "--installed"))
        self.assertEqual(argvs["brew.outdated_one"], (BREW, "outdated", "--json=v2", "--formula", "examplefetch"))
        self.assertEqual(argvs["brew.info_one"], (BREW, "info", "--json=v2", "--cask", "exampleviewer"))
        self.assertEqual(argvs["brew.dry_run"], (BREW, "upgrade", "--dry-run", "--formula", "examplefetch"))
        self.assertIn(1, routes.READ_RECIPES["brew.outdated_one"].ok_exits)
        for argv in argvs.values():
            self.assertFalse({"update", "install", "reinstall", "cleanup", "uninstall", "tap"} & set(argv), argv)
            self.assertTrue("upgrade" not in argv or "--dry-run" in argv, argv)
            self.assertEqual(token_problems("brew", argv, values=("examplefetch", "exampleviewer"), paths=(BREW,), shell=False), [])
        self.assertLessEqual(set(argvs), set(readonly_runner.recipes()))

    def test_plan_binds_exact_id_version_and_source(self):
        candidates, reported = self.candidates()
        self.assertEqual([(c["kind"], c["name"]) for c in candidates], [("cask", "exampleviewer"), ("formula", "exampledep"),
                                                                        ("formula", "examplefetch")])
        self.assertIsNone(candidates[0]["eligibility"]["auto_updates"] or None)
        self.assertEqual({(r["kind"], r["name"]): r["reason"] for r in reported if r["name"]},
                         {("cask", "exampleinstaller"): "needs_administrator", ("cask", "examplenocheck"): "no_checksum",
                          ("cask", "exampleupdater"): "self_updating", ("formula", "examplepin"): "pinned_or_disabled"})
        self.assertEqual(sum(1 for r in reported if r["name"] is None), 2)
        entry = self.entry()
        self.assertEqual({key: entry[key] for key in ("manager", "kind", "name", "source", "target_version", "installed_versions")},
                         {"manager": "brew", "kind": "formula", "name": "examplefetch", "source": "homebrew/core",
                          "target_version": "1.25.0_2", "installed_versions": ["1.24.5"]})
        self.assertEqual(entry["dependencies"], [{"name": "exampledep", "installed_versions": ["3.3.0"], "target_version": "3.3.1"},
                                                 {"name": "examplenew", "installed_versions": [], "target_version": "2.0"}])
        self.assertEqual((entry["preflight"]["brew_version"], entry["preflight"]["brew_path"], entry["preflight"]["prefix"]),
                         ("7.0.10", BREW, "/opt/homebrew"))
        # Several old versions are comma-separated; packages joined on one line hold instead of hiding a dependency.
        self.assertEqual(routes.brew_dependencies(b"==> Would upgrade 1 outdated package:\nexamplefetch 1.24.4, 1.24.5 -> 1.25.0_2\n",
                                                  "examplefetch", "1.25.0_2"), [])
        for dry_run in (b"==> Would upgrade\nexamplefetch 1.24.5 -> 1.25.0_2\nsomething else here\n", b"examplefetch 1.24.5 -> 1.25.0_2\n",
                        fixture("brew-dry-run.txt").replace(b"1.25.0_2", b"1.25.1"), b"==> Would upgrade 1 outdated package:\n",
                        fixture("brew-dry-run-joined.txt")):
            self.assertIsNone(routes.brew_dependencies(dry_run, "examplefetch", "1.25.0_2"))
            holds(self, "brew-dependencies", self.entry, dry_run=dry_run)
        bare = json.loads(fixture("brew-outdated.json"))
        bare["formulae"][3]["name"] = "examplecli"
        self.assertIn({"kind": "formula", "name": "examplecli", "reason": "third_party_tap"}, self.candidates(outdated=json.dumps(bare).encode())[1])
        holds(self, "brew-source", routes.plan_brew, dict(candidates[2], tap="fabrikam/tools"), version="7.0.10", path=BREW, machine="arm64",
              env=self.env_check(), dependencies=[])
        holds(self, "brew-prefix", routes.plan_brew, candidates[2], version="7.0.10", path="/usr/local/bin/brew", machine="arm64",
              env=self.env_check(), dependencies=[])
        for bad in ("fabrikam/tools/examplecli", "Example", "example fetch", "evil.rb", "evil.RB", "evil.json", "evil-1.0.arm64_sonoma.bottle.tar.gz"):
            holds(self, "package-token", routes.variable, "name", bad)
        holds(self, "brew-too-old", routes.brew_version, b"Homebrew 6.9.2\n")
        holds(self, "brew-version", routes.brew_version, b"Homebrew\n")

    def test_casks_follow_the_real_json_shape(self):
        info = json.loads(fixture("brew-info.json"))
        for value, eligible in ((None, True), (False, True), (True, False), ("yes", False)):
            info["casks"][0]["auto_updates"] = value
            names = [c["name"] for c in self.candidates(info=json.dumps(info).encode())[0]]
            self.assertEqual("exampleviewer" in names, eligible, value)
        del info["casks"][0]["auto_updates"]
        self.assertIn("exampleviewer", [c["name"] for c in self.candidates(info=json.dumps(info).encode())[0]])
        outdated = json.loads(fixture("brew-outdated.json"))
        del outdated["casks"][0]["pinned"]
        self.assertIn("exampleviewer", [c["name"] for c in self.candidates(outdated=json.dumps(outdated).encode())[0]])
        del outdated["formulae"][0]["pinned"]
        self.assertNotIn("examplefetch", [c["name"] for c in self.candidates(outdated=json.dumps(outdated).encode())[0]])

    def test_run_argv_is_fixed_and_refuses_forbidden_flags(self):
        formula = routes.run_argv(self.entry())
        self.assertEqual(formula, (BREW, "upgrade", "--formula", "examplefetch"))
        cask = routes.run_argv(self.entry("cask", "exampleviewer"))
        self.assertEqual(cask, (BREW, "upgrade", "--cask", "--require-sha", "exampleviewer"))
        self.assertNotIn("1.25.0_2", formula)
        self.assertEqual(routes.run_argv(self.entry(), executable=BREW), formula)
        holds(self, "package-executable", routes.run_argv, self.entry(), executable="/usr/local/bin/brew")
        for argv, name in ((formula, "examplefetch"), (cask, "exampleviewer")):
            self.assertEqual(token_problems("brew", argv, values=(name,), paths=(BREW,)), [])
        for flag in ("--force", "--no-quarantine", "HOMEBREW_BOTTLE_DOMAIN", "HOMEBREW_NO_INSTALL_FROM_API"):
            self.assertIn(("brew", flag), package_tokens.FORBIDDEN)
        for bad, code in (({"name": "--force"}, "package-token"), ({"name": "-f"}, "package-token"), ({"name": "fabrikam/tools/x"}, "package-token"),
                          ({"name": "examplefetch", "force": True}, "package-recipe-values")):
            holds(self, code, routes.render, "brew.upgrade_formula", bad, executable=BREW)
        holds(self, "package-executable", routes.render, "brew.upgrade_formula", {"name": "examplefetch"}, executable="/usr/local/Cellar/brew")
        self.assertEqual(table_problems({"brew"}), [])

    def test_verification_requires_planned_version(self):
        entry, before = self.entry(), stored(routes.brew_info(fixture("brew-info.json")))
        ok = routes.verify_brew(entry, before, fixture("brew-info-after.json"))
        self.assertEqual(ok, {"target_installed": True, "changed": ["formula:exampledep"], "changed_outside_plan": [], "diff_complete": True})
        self.assertEqual(ok, routes.verify_brew(entry, routes.brew_info(fixture("brew-info.json")), fixture("brew-info-after.json")))
        self.assertEqual(result_of(routes.classify_exit("brew", 0), ok), "updated")
        wrong = routes.verify_brew(entry, before, self.info_with(examplefetch="1.25.0_1"))
        self.assertFalse(wrong["target_installed"])
        self.assertEqual(result_of(routes.classify_exit("brew", 0), wrong), "did_not_update")
        unlinked = json.loads(fixture("brew-info-after.json"))
        unlinked["formulae"][0]["linked_keg"] = "1.24.5"
        self.assertFalse(routes.verify_brew(entry, before, json.dumps(unlinked).encode())["target_installed"])
        kept_unlinked = dict(entry, transaction=dict(entry["transaction"], eligibility=dict(entry["transaction"]["eligibility"], linked_keg=None)))
        unlinked["formulae"][0]["linked_keg"] = None
        self.assertTrue(routes.verify_brew(kept_unlinked, before, json.dumps(unlinked).encode())["target_installed"])
        self.assertFalse(routes.verify_brew(entry, before, json.dumps(unlinked).encode())["target_installed"])
        cask = self.entry("cask", "exampleviewer")
        self.assertTrue(routes.verify_brew(cask, before, self.info_with(exampleviewer="132.0"))["target_installed"])
        self.assertFalse(routes.verify_brew(cask, before, fixture("brew-info-after.json"))["target_installed"])
        outside = routes.verify_brew(entry, before, self.info_with(exampleother="4.1"))
        self.assertEqual(outside["changed_outside_plan"], ["formula:exampleother"])
        self.assertEqual(result_of(routes.classify_exit("brew", 0), outside), "differs_from_plan")

    def test_executable_is_absolute_and_no_shell(self):
        launcher = FakeLauncher(fixture("brew-version.txt"))
        readonly_runner.run_recipe("brew.version", launcher=launcher, probe=FakeProbe(platform="darwin"))
        self.assertEqual(launcher.calls[0].argv, (BREW, "--version"))
        self.assertTrue(PurePosixPath(launcher.calls[0].argv[0]).is_absolute())
        intel_real = "/usr/local/Homebrew/bin/brew"
        intel = {"/usr/local": folder(), "/usr/local/Homebrew": folder(1000), "/usr/local/Homebrew/bin": folder(1000),
                 intel_real: regular(1000), "/usr/local/Cellar/brew": regular(1000), "/usr/local/bin": folder(1000),
                 "/usr/local/bin/brew": symlink(1000)}
        readonly_runner.run_recipe("brew.version", launcher=launcher, probe=FakeProbe(
            platform="darwin", machine="x86_64", files=intel, links={"/usr/local/bin/brew": intel_real}))
        self.assertEqual(launcher.calls[1].argv, ("/usr/local/bin/brew", "--version"))
        for probe in (FakeProbe(platform="darwin", machine="x86_64", files=intel, links={"/usr/local/bin/brew": "/usr/local/Cellar/brew"}),
                      FakeProbe(platform="darwin", files={BREW: regular(501)}), FakeProbe(platform="darwin", files={BREW: regular(1000, 0o775)}),
                      FakeProbe(platform="darwin", uid=0, files={BREW: regular(0)}), FakeProbe(platform="linux"),
                      FakeProbe(platform="darwin", machine="ppc"), FakeProbe(platform="darwin", files={"/opt/homebrew/bin": folder(1000, 0o777)}),
                      FakeProbe(platform="darwin", files={"/opt/homebrew": folder(501)}), FakeProbe(platform="darwin", files={"/opt": folder(0, 0o777)}),
                      FakeProbe(platform="darwin", files={"/": folder(501)}),
                      # Intel: the link and every folder on its way are checked too, not only the Homebrew repository.
                      FakeProbe(platform="darwin", machine="x86_64", files={**intel, "/usr/local/bin": folder(1000, 0o777)},
                                links={"/usr/local/bin/brew": intel_real}),
                      FakeProbe(platform="darwin", machine="x86_64", files={**intel, "/usr/local/bin/brew": symlink(501)},
                                links={"/usr/local/bin/brew": intel_real}),
                      FakeProbe(platform="darwin", machine="x86_64", files={**intel, "/usr/local": folder(501)}, links={"/usr/local/bin/brew": intel_real})):
            holds(self, "runner-executable", readonly_runner.run_recipe, "brew.version", launcher=launcher, probe=probe)
        with self.assertRaises(Refusal) as caught:
            readonly_runner.run_recipe("brew.version", launcher=launcher, probe=FakeProbe(platform="darwin", machine="x86_64-rosetta"))
        self.assertIn("Rosetta", str(caught.exception))
        self.assertEqual(len(launcher.calls), 2)
        self.assertFalse(SHELLS & set(launcher.calls[0].argv))

    def test_restart_signal_is_reported_not_triggered(self):
        for code in (0, 1, 130, 7):
            self.assertEqual(routes.classify_exit("brew", code)["restart"], "none")
        self.assertEqual(result_of(routes.classify_exit("brew", 0), {"target_installed": True}), "updated")
        self.assertEqual(routes.BREW_FIXED["HOMEBREW_NO_UPGRADE_QUIT_CASKS"], "1")
        self.assertEqual(routes.classify_exit("brew", 1, output="Error: SHA256 mismatch")["class"], "integrity_failure")
        self.assertEqual(routes.classify_exit("brew", 1, output="Error: This cask requires sudo")["reason"], "needs_sudo")
        self.assertEqual(routes.classify_exit("brew", 130)["reason"], "interrupted")
        self.assertEqual(result_of(routes.classify_exit("brew", 1), {"target_installed": True}), "differs_from_plan")

    def test_environment_is_fixed(self):
        env = routes.environment("brew", home=HOME, user="example")
        self.assertEqual(env, {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": HOME, "USER": "example", "LOGNAME": "example",
                               "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ASK": "1", "HOMEBREW_NO_INSTALL_CLEANUP": "1",
                               "HOMEBREW_NO_UPGRADE_QUIT_CASKS": "1", "HOMEBREW_NO_SUDO": "1", "HOMEBREW_NO_ENV_HINTS": "1",
                               "HOMEBREW_NO_ANALYTICS": "1"})
        self.assertFalse({row.token for row in package_tokens.TOKENS if row.manager == "brew" and not row.allowed} & set(env))
        launcher = FakeLauncher(fixture("brew-version.txt"))
        readonly_runner.run_recipe("brew.version", launcher=launcher, probe=FakeProbe(platform="darwin"))
        self.assertEqual((launcher.calls[0].env, launcher.calls[0].cwd), (env, "/"))
        for home, user in (("relative", "example"), (HOME, "bad user"), (HOME + "\n", "example"), (None, "example")):
            holds(self, "package-environment", routes.environment, "brew", home=home, user=user)
        holds(self, "package-environment", routes.environment, "macports", home=HOME)

    def test_provenance_preflight_holds_on_drift(self):
        planned = self.entry()
        self.assertEqual(routes.drift(planned, self.entry()), [])
        allowed = self.env_check(user=b"# owner settings\nHOMEBREW_NO_ENV_HINTS=1\n")
        self.assertEqual(allowed["problems"], [])
        self.assertEqual(routes.drift(planned, self.entry(env=allowed)), ["preflight.brew_env_sha256"])
        self.assertEqual(routes.drift(planned, self.entry(version=b"Homebrew 7.0.11\n")), ["preflight.brew_version"])
        redirects = ("HOMEBREW_BOTTLE_DOMAIN=https://mirror.example.invalid", "HOMEBREW_BREW_GIT_REMOTE=https://git.example.invalid/brew",
                     "HOMEBREW_CORE_GIT_REMOTE=https://git.example.invalid/core", "HOMEBREW_CURL_PATH=/tmp/curl", "HOMEBREW_GIT_PATH=/tmp/git",
                     "HOMEBREW_NO_VERIFY_ATTESTATIONS=1", "HOMEBREW_PIP_INDEX_URL=https://pip.example.invalid",
                     "HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY=1", "HOMEBREW_XDG_CONFIG_HOME=/elsewhere", "HOMEBREW_NO_AUTO_UPDATE=0",
                     "SUDO_ASKPASS=/usr/local/bin/askpass", "export X", "OTHER=1")
        for text in redirects:
            check = self.env_check(prefix=f"{text}\n".encode())
            self.assertTrue(check["problems"], text)
            holds(self, "brew-env", self.entry, env=check)
        self.assertEqual(self.env_check(system=b"HOMEBREW_CASK_OPTS=--appdir=/Applications\n")["reported"], ["system:HOMEBREW_CASK_OPTS"])
        hidden = b"HOMEBREW_NO_ENV_HINTS=1\x1b]\nHOMEBREW_BOTTLE_DOMAIN=https://mirror.example.invalid\n\x07\n"
        holds(self, "package-config-bytes", self.env_check, prefix=hidden)
        first, second = (self.env_check(prefix=b"HOMEBREW_NO_ENV_HINTS=1\n# " + byte + b"\n")["sha256"]["prefix"] for byte in (b"\xff", b"\xfe"))
        self.assertNotEqual(first, second)
        holds(self, "package-elevated", readonly_runner.run_recipe, "brew.version", launcher=FakeLauncher(),
              probe=FakeProbe(platform="darwin", elevation="root"))

    def test_transaction_drift_holds(self):
        planned = self.entry()
        moved = json.loads(fixture("brew-outdated.json"))
        moved["formulae"][0]["current_version"] = "1.25.1"
        dry_run = fixture("brew-dry-run.txt").replace(b"1.25.0_2", b"1.25.1")
        self.assertEqual(routes.drift(planned, self.entry(outdated=json.dumps(moved).encode(), dry_run=dry_run)),
                         ["target_version", "transaction.current_version"])
        gone = dict(moved, formulae=moved["formulae"][1:])
        self.assertNotIn("examplefetch", [c["name"] for c in self.candidates(outdated=json.dumps(gone).encode())[0]])
        pinned = json.loads(fixture("brew-info.json"))
        pinned["formulae"][0]["pinned"] = True
        self.assertNotIn("examplefetch", [c["name"] for c in self.candidates(info=json.dumps(pinned).encode())[0]])
        broken = json.loads(fixture("brew-info.json"))
        broken["formulae"][0]["disabled"] = "yes"
        self.assertNotIn("examplefetch", [c["name"] for c in self.candidates(info=json.dumps(broken).encode())[0]])

    def test_stale_package_lists_reported_not_up_to_date(self):
        stale = routes.list_age("brew", "2026-10-10T00:00:00Z", now_utc=NOW)
        self.assertEqual((stale["status"], stale["message"], stale["age_days"]), ("stale", "stale; refresh needed", 15))
        unknown = routes.list_age("brew", None, now_utc=NOW)
        self.assertEqual((unknown["status"], unknown["message"]), ("unknown", "package list age unknown; refresh needed"))
        self.assertIsNone(readonly_runner.package_list_time("brew", probe=FakeProbe(platform="darwin")))
        self.assertNotIn("up to date", (stale["message"] + unknown["message"]).lower())
        holds(self, "package-manager", routes.list_age, "macports", None)

    def test_leading_dash_id_refused(self):
        for bad in ("-examplebad", "--force", "-f"):
            holds(self, "package-token", routes.variable, "name", bad)
            holds(self, "package-token", routes.render, "brew.upgrade_formula", {"name": bad}, executable=BREW)
            holds(self, "package-token", routes.render, "brew.info_one", {"kind": "--formula", "name": bad}, executable=BREW)
        candidates, reported = self.candidates()
        self.assertNotIn("-examplebad", [c["name"] for c in candidates] + [r["name"] for r in reported])
        holds(self, "package-recipe-values", routes.render, "brew.info_one", {"kind": "--force", "name": "examplefetch"}, executable=BREW)

    def test_a_tampered_download_is_an_integrity_failure(self):
        # Homebrew's download queue prints these two lines and no "mismatch"; ChecksumMismatchError prints "SHA-256 mismatch".
        queue = ("Error: Bottle examplefetch (1.25.0_2) reports different checksum: " + "a" * 64 + "\n"
                 "       SHA-256 checksum of downloaded file:                        " + "b" * 64 + "\n")
        for output in (queue, queue.splitlines()[0], queue.splitlines()[1], "Error: SHA-256 mismatch\nExpected: a\n"):
            with self.subTest(output=output):
                self.assertEqual(routes.classify_exit("brew", 1, output=output)["class"], "integrity_failure")
                self.assertEqual(package_registry.BREW["classify_exit"](1, output), "integrity_failure")
        self.assertEqual(routes.classify_exit("brew", 1, output="Error: Download failed\n")["class"], "failed")

    def test_dry_run_sections_hold_with_their_own_reason(self):
        rows = "==> Would upgrade 1 requested outdated package\nexamplefetch 1.24.5 -> 1.25.0_2\n"
        for section, code in (("==> 1 homebrew/core formula that would build from source\nexamplefetch\n", "brew-would-build-from-source"),
                              ("==> 2 homebrew/core formulae that would build from source\nexamplefetch\nexampledep\n", "brew-would-build-from-source"),
                              ("==> 1 Deprecated or disabled package\nexampledep (deprecated)\n", "brew-deprecated"),
                              ("==> 2 Deprecated or disabled packages\nexampledep (deprecated)\nexampleother (disabled)\n", "brew-deprecated"),
                              ("==> 1 Pinned formula\nexamplepin 2.0 -> 2.1\n", "brew-pinned-dependent"),
                              ("==> 2 Pinned formulae\nexamplepin 2.0 -> 2.1\nexampleother 4.0 -> 4.1\n", "brew-pinned-dependent"),
                              ("==> 1 Pinned cask\nexampleviewer 131.0 -> 132.0\n", "brew-pinned-dependent")):
            with self.subTest(section=section):
                holds(self, code, routes.brew_dependencies, (rows + section).encode(), "examplefetch", "1.25.0_2")
                holds(self, code, BREW_PREFLIGHT, FakeProbe(platform=MAC), brew_run({"brew.dry_run": (rows + section).encode()}), FETCH, "upgrade")
        self.assertNotIn("warnings", self.entry(machine="x86_64"))

    def test_a_deprecated_package_is_not_offered(self):
        info = json.loads(fixture("brew-info.json"))
        info["formulae"][0]["deprecated"] = False
        self.assertIn("examplefetch", [c["name"] for c in self.candidates(info=json.dumps(info).encode())[0]])
        for value in (True, "yes"):
            info["formulae"][0]["deprecated"] = info["casks"][0]["deprecated"] = value
            candidates, reported = self.candidates(info=json.dumps(info).encode())
            self.assertFalse({"examplefetch", "exampleviewer"} & {c["name"] for c in candidates}, value)
            self.assertIn({"kind": "formula", "name": "examplefetch", "reason": "deprecated"}, reported)
            self.assertIn({"kind": "cask", "name": "exampleviewer", "reason": "deprecated"}, reported)

    def test_a_brew_env_file_left_unread_holds(self):
        user = HOME + "/.homebrew/brew.env"
        found = BREW_PREFLIGHT(FakeProbe(platform=MAC), brew_run(), FETCH, "upgrade")
        self.assertEqual(found["preflight"]["brew_env_sha256"], {"system": "absent", "prefix": "absent", "user": "absent"})

        class Refused(FakeProbe):
            error = OSError

            def lstat(self, path):
                if path == user:
                    raise self.error(path)
                return super().lstat(path)

        Refused.error = NotADirectoryError  # ~/.homebrew is a file: the setting file cannot exist
        self.assertEqual(BREW_PREFLIGHT(Refused(platform=MAC), brew_run(), FETCH, "upgrade")["preflight"]["brew_env_sha256"]["user"], "absent")
        for probe in (FakeProbe(platform=MAC, files={user: symlink(1000)}), FakeProbe(platform=MAC, files={user: regular(1000, 0o600)})):
            holds(self, "brew-env", BREW_PREFLIGHT, probe, brew_run(), FETCH, "upgrade")
        for error in (PermissionError, OSError, ValueError):
            Refused.error = error
            holds(self, "brew-env", BREW_PREFLIGHT, Refused(platform=MAC), brew_run(), FETCH, "upgrade")
        # The service's own reader leaves an oversize file unread, and the real lstat finds it.
        root = fixture_root()
        root.mkdir(parents=True)
        path = root / "brew.env"
        with open(path, "wb") as handle:
            handle.truncate(routes.MAX_OUTPUT_BYTES + 1)
        reads = service_updates._Reads(root, SimpleNamespace(), None)
        self.assertIsNone(reads.read_file(str(path)))
        holds(self, "brew-env", package_registry._brew_env_file, SimpleNamespace(lstat=os.lstat), reads, str(path))
        self.assertIsNone(package_registry._brew_env_file(SimpleNamespace(lstat=os.lstat), reads, str(root / "missing.env")))

    def test_cask_options_hold_the_cask_only(self):
        options = {"/etc/homebrew/brew.env": b"HOMEBREW_CASK_OPTS=--appdir=/Applications\n"}
        info = brew_one("exampleviewer", "brew-info.json")
        info["casks"][0]["auto_updates"] = False
        outputs = {"brew.outdated_one": json.dumps(brew_one("exampleviewer", "brew-outdated.json")).encode(), "brew.info_one": json.dumps(info).encode(),
                   "brew.dry_run": b"==> Would upgrade 1 outdated package:\nexampleviewer 131.0 -> 132.0\n"}
        cask = {"id": "exampleviewer", "kind": "cask"}
        self.assertEqual(BREW_PREFLIGHT(FakeProbe(platform=MAC), brew_run(outputs), cask, "upgrade")["version"], "132.0")
        holds(self, "brew-cask-options", BREW_PREFLIGHT, FakeProbe(platform=MAC), brew_run(outputs, options), cask, "upgrade")
        holds(self, "brew-cask-options", BREW_PREFLIGHT, FakeProbe(platform=MAC), brew_run(outputs, options), cask, "reinstall")
        self.assertEqual(BREW_PREFLIGHT(FakeProbe(platform=MAC), brew_run(files=options), FETCH, "upgrade")["id"], "examplefetch")

    def test_a_package_the_update_adds_is_flagged(self):
        found = BREW_PREFLIGHT(FakeProbe(platform=MAC), brew_run(), FETCH, "upgrade")
        self.assertEqual((found["flags"], found["dependencies"]), (["adds_packages"], ["exampledep@3.3.1", "examplenew@2.0"]))
        fragment = package_registry.BREW["plan"](found, {"operation": "upgrade", "executable": {"kind": "brew", "path": BREW}})
        self.assertEqual(fragment["flags"], ["adds_packages"])
        self.assertLessEqual(set(fragment["flags"]), set(package_registry.BREW["flags"]))
        upgrades = b"==> Would upgrade 2 outdated packages:\nexampledep 3.3.0 -> 3.3.1\nexamplefetch 1.24.5 -> 1.25.0_2\n"
        self.assertEqual(BREW_PREFLIGHT(FakeProbe(platform=MAC), brew_run({"brew.dry_run": upgrades}), FETCH, "upgrade")["flags"], [])

    def test_reinstall_holds_while_an_outdated_formula_depends_on_it(self):
        none = json.dumps({"formulae": [], "casks": []}).encode()
        def computer(dependencies, outdated="exampledep"):
            info = json.loads(fixture("brew-info.json"))
            for item in info["formulae"]:
                item["installed"][0]["runtime_dependencies"] = dependencies if item["name"] in ("exampledep", "examplecli") else []
            listed = brew_one(outdated, "brew-outdated.json")
            return brew_run({"brew.outdated_one": none, "brew.outdated": json.dumps(listed).encode(), "brew.info": json.dumps(info).encode()})
        uses_it, other = [{"full_name": "examplefetch", "version": "1.24.5"}], [{"full_name": "exampleother", "version": "4.0"}]
        found = BREW_PREFLIGHT(FakeProbe(platform=MAC), computer(other), FETCH, "reinstall")
        self.assertEqual((found["operation"], found["version"]), ("reinstall", "1.24.5"))
        # Nothing outdated needs it: a dependent that is up to date stays as it is.
        self.assertEqual(BREW_PREFLIGHT(FakeProbe(platform=MAC), computer(uses_it, outdated="nothing"), FETCH, "reinstall")["id"], "examplefetch")
        for dependencies, outdated in ((uses_it, "exampledep"), (None, "exampledep"), (["not a row"], "exampledep"), (uses_it, "fabrikam/tools/examplecli")):
            with self.subTest(dependencies=dependencies, outdated=outdated):
                holds(self, "brew-reinstall", BREW_PREFLIGHT, FakeProbe(platform=MAC), computer(dependencies, outdated), FETCH, "reinstall")
        # A dependent that goes out of date between the plan and the run holds at the drift check.
        payload = {"id": "examplefetch", "operation": "reinstall", "version": found["version"], "source": found["source"], "preflight": found["preflight"],
                   "transaction_sha256": pc_records.digest(found["preflight"])}
        self.assertIsNone(package_registry.BREW["drift"](FakeProbe(platform=MAC), computer(other), payload))
        self.assertEqual((package_registry.BREW["drift"](FakeProbe(platform=MAC), computer(uses_it), payload) or {}).get("hold"), "brew-reinstall")
        # brew reinstall looks for dependents of formulae only: a cask reads neither list.
        info = brew_one("exampleviewer", "brew-info.json")
        info["casks"][0].update(auto_updates=False, installed="131.0")
        outputs = {"brew.outdated_one": none, "brew.info_one": json.dumps(info).encode()}
        self.assertEqual(BREW_PREFLIGHT(FakeProbe(platform=MAC), brew_run(outputs), {"id": "exampleviewer", "kind": "cask"}, "reinstall")["version"], "131.0")

    def test_a_group_may_write_a_homebrew_folder_only_as_admin(self):
        launcher = FakeLauncher(fixture("brew-version.txt"))
        for path in ("/opt/homebrew", "/opt/homebrew/bin"):
            with self.subTest(path=path):
                readonly_runner.run_recipe("brew.version", launcher=launcher, probe=FakeProbe(platform=MAC, files={path: folder(1000, 0o775, gid=80)}))
                holds(self, "runner-executable", readonly_runner.run_recipe, "brew.version", launcher=launcher,
                      probe=FakeProbe(platform=MAC, files={path: folder(1000, 0o775, gid=20)}))
        self.assertEqual(len(launcher.calls), 2)

    def test_the_linked_keg_rule_reads_what_the_plan_bound(self):
        info = lambda **fields: {"stdout": json.dumps({"formulae": [{"name": "example-tool", "tap": "homebrew/core", "installed": [{"version": "2.0"}], **fields}],
                                                       "casks": []}).encode(), "ok": True, "exit_code": 0}
        def verified(bound, after):
            payload = {"id": "example-tool", "version": "2.0", "operation": "reinstall", "dependencies": [], "preflight": {"kind": "formula", **bound}}
            return package_registry.BREW["verify"](payload, {"before": {"brew.info": info(linked_keg="2.0")}, "after": {"brew.info": info(**after)}})["result"]
        linked, unlinked = {"linked_keg": "2.0"}, {"linked_keg": None}
        for bound, after, result in (({"snapshot": linked}, linked, "updated"), ({"snapshot": linked}, unlinked, "did_not_update"),
                                     ({"snapshot": unlinked}, unlinked, "updated"), ({"snapshot": linked}, {"linked_keg": "1.0"}, "did_not_update"),
                                     ({"transaction": {"eligibility": unlinked}}, unlinked, "updated"),
                                     ({"transaction": {"eligibility": linked}}, unlinked, "did_not_update"),
                                     ({"snapshot": linked}, {"linked_keg": None, "keg_only": True}, "updated")):
            with self.subTest(bound=bound, after=after):
                self.assertEqual(verified(bound, after), result)


@refusals_fail
class AptRouteTests(unittest.TestCase):
    SOURCES = {"sources.list": b"deb [arch=amd64 signed-by=/usr/share/keyrings/example.gpg] http://archive.example.invalid/ubuntu noble main\n"
                               b"# deb [trusted=yes] http://old.example.invalid/ubuntu noble main\n",
               "sources.list.d/example.sources": b"Types: deb\nURIs: http://archive.example.invalid/ubuntu\nSuites: noble\nComponents: main\n"
                                  b"Signed-By: /usr/share/keyrings/example.gpg\n"}

    def rows(self, selected=("examplecurl", "libexample1:i386")):
        return [row for row in apt.apt_simulation(fixture("apt-upgrades.txt"), exit_code=0)["upgrade"] if row["package"] in selected]

    def entry(self, selected=("examplecurl", "libexample1:i386"), simulation=None, installed=None, policy=None, newer=None, config=None,
              sources=None, rows=None):
        rows = rows or self.rows(selected)
        return apt.plan_apt(rows, simulation=apt.apt_simulation(simulation or fixture("apt-simulate.txt"), exit_code=0),
                            installed=apt.dpkg_installed(installed or fixture("dpkg-installed.txt")),
                            policy=policy or {row["package"]: fixture("apt-policy.txt") for row in rows},
                            newer={row["package"]: 0 for row in rows} if newer is None else newer,
                            config=apt.apt_config(config or fixture("apt-config.txt")), sources=apt.apt_sources(sources or self.SOURCES))

    def test_discovery_argv_is_read_only(self):
        specs = apt.apt_specs(self.rows(("examplecurl",)))
        values = {"apt.policy": {"package": "libexample1:i386"}, "apt.newer": {"target": "8.5.0-2example2", "installed": "8.5.0-2example1"},
                  "apt.simulate": {"spec": specs}, "apt.simulate_reinstall": {"spec": ["examplecurl=8.5.0-2example1"]}}
        argvs = {rid: routes.render(rid, values.get(rid)) for rid in read_recipes("apt")}
        self.assertEqual(argvs["apt.upgrades"], ("/usr/bin/apt-get", "-s", "-q", "upgrade"))
        self.assertEqual(argvs["apt.config"], ("/usr/bin/apt-config", "dump"))
        self.assertEqual(argvs["apt.installed"], ("/usr/bin/dpkg-query", "-W", package_tokens.SHOWFORMAT))
        self.assertEqual(argvs["apt.policy"], ("/usr/bin/apt-cache", "policy", "libexample1:i386"))
        self.assertEqual(argvs["apt.newer"], ("/usr/bin/dpkg", "--compare-versions", "8.5.0-2example2", "gt", "8.5.0-2example1"))
        self.assertEqual(argvs["apt.needrestart"], ("/usr/sbin/needrestart", "-b", "-r", "l"))
        run = routes.render("apt.upgrade", {"spec": specs})
        self.assertEqual(argvs["apt.simulate"], ("/usr/bin/apt-get", "-s") + run[run.index("/usr/bin/apt-get") + 1:])
        self.assertEqual(specs, ["examplecurl=8.5.0-2example2"])
        for argv in argvs.values():
            self.assertNotIn("/usr/bin/sudo", argv)
            self.assertTrue(not {"install", "upgrade"} & set(argv) or argv[:2] == ("/usr/bin/apt-get", "-s"), argv)
            self.assertEqual(token_problems("apt", argv, values=sum((list(v) if isinstance(v, list) else [v] for d in values.values()
                                                                     for v in d.values()), []), shell=False), [])
        self.assertLessEqual(set(argvs), set(readonly_runner.recipes()))

    def test_plan_binds_exact_id_version_and_source(self):
        entry = self.entry()
        self.assertEqual(entry["items"], [
            {"name": "examplecurl", "arch": "amd64", "installed_version": "8.5.0-2example1", "origin": ORIGIN,
             "target_version": "8.5.0-2example2", "spec": "examplecurl=8.5.0-2example2"},
            {"name": "libexample1", "arch": "i386", "installed_version": "2.1-1", "origin": ORIGIN, "target_version": "2.1-2",
             "spec": "libexample1:i386=2.1-2"}])
        self.assertEqual(entry["collateral"], ["libexample1=2.1-2", "libexampledep=1.0-1"])
        self.assertRegex(entry["transaction"]["sim_sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(apt.apt_simulation(fixture("apt-upgrades.txt"), exit_code=0)["kept_back"], ["examplekernel"])
        held = {"kind": "upgrade", "package": "exampleheld", "name": "exampleheld", "arch": "amd64", "installed_version": "1.0-1",
                "target_version": "1.0-2", "origin": ORIGIN}
        with_held = fixture("apt-simulate.txt") + f"Inst exampleheld [1.0-1] (1.0-2 {ORIGIN} [amd64])\n".encode()
        holds(self, "apt-dpkg-hold", self.entry, rows=[held], simulation=with_held)
        phased = fixture("apt-policy.txt").replace(b"8.5.0-2example2 500\n", b"8.5.0-2example2 500 (phased 10%)\n")
        installed_phased = fixture("apt-policy.txt").replace(b"8.5.0-2example1 100\n", b"8.5.0-2example1 100 (phased 50%)\n")
        self.assertEqual(self.entry(selected=("examplecurl",), policy={"examplecurl": installed_phased})["items"][0]["name"], "examplecurl")
        for change, code in (({"policy": {"examplecurl": phased}}, "apt-phased"), ({"policy": {"examplecurl": b"examplecurl:\n"}}, "apt-phased"),
                             ({"newer": {"examplecurl": 1}}, "apt-not-newer"), ({"policy": {"other": b""}}, "apt-phased")):
            holds(self, code, self.entry, selected=("examplecurl",), **change)
        for good in ("1:2.0-1", "2.0", "2.0~rc1-0ubuntu1+b1"):
            self.assertEqual(routes.variable("target", good), good)
        for bad in ("2.0:1", "1.0-", "1.0=~2", "1:~2", "a1.0", "examplecurl/noble"):
            holds(self, "package-token", routes.variable, "target", bad)

    def test_run_argv_is_fixed_and_refuses_forbidden_flags(self):
        argv = routes.run_argv(self.entry())
        self.assertEqual(argv, ("/usr/bin/sudo", "/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "/usr/bin/apt-get",
                                "install", "--only-upgrade", "--no-remove", "-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o",
                                "Dpkg::Options::=--force-confold", "examplecurl=8.5.0-2example2", "libexample1:i386=2.1-2"))
        self.assertEqual([argv[n + 1] for n, token in enumerate(argv) if token == "-o"], [package_tokens.CONFDEF, package_tokens.CONFOLD])
        self.assertEqual(token_problems("apt", argv, values=("examplecurl=8.5.0-2example2", "libexample1:i386=2.1-2")), [])
        for flag in ("--allow-unauthenticated", "--allow-downgrades", "--force-yes", "--allow-remove-essential", "--allow-change-held-packages",
                     "-qq", "-S", "-A"):
            self.assertIn(("apt", flag), package_tokens.FORBIDDEN)
        for spec in ("--allow-downgrades", "examplecurl", "examplecurl=8.5;rm", "examplecurl/noble=1.0", "examplecurl=8.5 x"):
            holds(self, "package-token", routes.render, "apt.upgrade", {"spec": [spec]})
        for bad in ({"spec": []}, {"spec": "examplecurl=1.0"}, {"spec": ["examplecurl=1.0"] * 501}):
            holds(self, "package-recipe-values", routes.render, "apt.upgrade", bad)
        holds(self, "package-executable", routes.render, "apt.upgrade", {"spec": ["examplecurl=1.0"]}, executable="/usr/local/bin/sudo")
        with mock.patch.object(routes, "RUN_RECIPES", {"apt.upgrade": package_tokens.Recipe("dnf", "/usr/bin/pkexec", ("/usr/bin/dnf5",))}):
            holds(self, "package-executable", routes.render, "apt.upgrade")
        self.assertEqual(table_problems({"apt"}), [])

    def test_verification_requires_planned_version(self):
        entry, before = self.entry(), stored(apt.dpkg_installed(fixture("dpkg-installed.txt")))
        ok = apt.verify_apt(entry, before, fixture("dpkg-installed-after.txt"))
        self.assertEqual((ok["target_installed"], ok["changed_outside_plan"], ok["diff_complete"]), (True, [], True))
        self.assertEqual(ok, apt.verify_apt(entry, apt.dpkg_installed(fixture("dpkg-installed.txt")), fixture("dpkg-installed-after.txt")))
        self.assertEqual(result_of(routes.classify_exit("apt", 0), ok, signal="none"), "updated")
        for old, new in ((b"8.5.0-2example2\tii ", b"8.5.0-2example3\tii "), (b"8.5.0-2example2\tii ", b"8.5.0-2example2\tiU ")):
            other = apt.verify_apt(entry, before, fixture("dpkg-installed-after.txt").replace(old, new))
            self.assertFalse(other["target_installed"], new)
        outside = apt.verify_apt(entry, before, fixture("dpkg-installed-after.txt").replace(b"6.8.0-45.45", b"6.8.0-47.47"))
        self.assertEqual(outside["changed_outside_plan"], ["examplekernel:amd64"])
        self.assertEqual(result_of(routes.classify_exit("apt", 0), outside, signal="none"), "differs_from_plan")
        unread = apt.verify_apt(entry, before, fixture("dpkg-installed-after.txt") + b"strange line\n")
        self.assertFalse(unread["diff_complete"])
        self.assertEqual(result_of(routes.classify_exit("apt", 0), unread, signal="none"), "could_not_check")

    def test_executable_is_absolute_and_no_shell(self):
        launcher = FakeLauncher(fixture("apt-config.txt"))
        readonly_runner.run_recipe("apt.config", launcher=launcher, probe=FakeProbe())
        self.assertEqual(launcher.calls[0].argv, ("/usr/bin/apt-config", "dump"))
        for found in read_recipes("apt").values():
            self.assertTrue(PurePosixPath(found.executable).is_absolute() and ("apt", found.executable) in package_tokens.ALLOWED)
        self.assertEqual(routes.recipe("apt.upgrade").executable, "/usr/bin/sudo")
        for probe in (FakeProbe(files={"/usr/bin/apt-config": regular(mode=0o775)}), FakeProbe(files={"/usr/bin/apt-config": regular(1000)}),
                      FakeProbe(files={"/usr/bin": folder(mode=0o777)}),
                      FakeProbe(links={"/usr/bin/apt-config": "/opt/evil/apt-config"}, files={"/opt/evil": folder(1000), "/opt/evil/apt-config": regular()}),
                      FakeProbe(files={"/usr/bin/apt-config": folder()}), FakeProbe(files={"/usr/bin/apt-config": regular(mode=0o644)})):
            holds(self, "runner-executable", readonly_runner.run_recipe, "apt.config", launcher=launcher, probe=probe)
        self.assertEqual(len(launcher.calls), 1)
        self.assertFalse(SHELLS & set(routes.run_argv(self.entry())))

    def test_restart_signal_is_reported_not_triggered(self):
        self.assertEqual(apt.apt_restart(before=False, after=True), {"signal": "required", "already_pending": False, "services": []})
        self.assertEqual(apt.apt_restart(before=True, after=True)["already_pending"], True)
        facts = apt.needrestart_facts(b"NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.8.0-45\nNEEDRESTART-KSTA: 2\nNEEDRESTART-SVC: ssh.service\n"
                                      b"NEEDRESTART-SVC: bad unit name\n")
        self.assertEqual(facts, {"ksta": 2, "services": ["ssh.service"]})
        self.assertEqual(apt.apt_restart(before=False, after=False, ksta=facts["ksta"])["signal"], "required")
        self.assertEqual(apt.apt_restart(before=False, after=False, ksta=3)["signal"], "required")
        self.assertEqual(apt.apt_restart(before=False, after=False, ksta=1, services=facts["services"]),
                         {"signal": "recommended", "already_pending": False, "services": ["ssh.service"]})
        self.assertEqual(apt.apt_restart(before=None, after=None)["signal"], "unknown")
        self.assertEqual(apt.apt_restart(before=None, after=None, ksta=0)["signal"], "unknown")
        self.assertEqual(apt.apt_restart(before=False, after=False, ksta=1)["signal"], "unknown")
        user = apt.needrestart_facts(b"NEEDRESTART-VER: 3.6\nNEEDRESTART-PID: example-editor=4242\n")
        self.assertEqual(apt.apt_restart(before=False, after=False, **user), {"signal": "unknown", "already_pending": False, "services": []})
        self.assertEqual(apt.needrestart_facts(b""), {"ksta": None, "services": []})
        self.assertEqual(result_of(routes.classify_exit("apt", 0), {"target_installed": True}, signal="required"), "restart_needed")
        self.assertEqual(routes.classify_exit("apt", 0)["restart"], "unknown")
        self.assertTrue(routes.classify_exit("apt", 0)["from_probes"])
        argv = routes.run_argv(self.entry())
        self.assertIn("NEEDRESTART_MODE=l", argv)
        self.assertFalse({"reboot", "shutdown", "--reboot"} & set(argv))

    def test_environment_is_fixed(self):
        env = routes.environment("apt", home=HOME)
        self.assertEqual(env, {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": HOME, "LC_ALL": "C"})
        self.assertIn(("apt", "APT_CONFIG"), package_tokens.FORBIDDEN)
        launcher = FakeLauncher(fixture("dpkg-installed.txt"))
        readonly_runner.run_recipe("apt.installed", launcher=launcher, probe=FakeProbe())
        self.assertEqual(launcher.calls[0].env, env)
        argv = routes.run_argv(self.entry())
        self.assertEqual(argv[1:4], ("/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l"))
        holds(self, "package-environment", routes.environment, "apt", home="home/example")

    def test_provenance_preflight_holds_on_drift(self):
        planned = self.entry()
        self.assertEqual(routes.drift(planned, self.entry()), [])
        for name, text in (("sources.list", b"deb [trusted=yes] http://archive.example.invalid/ubuntu noble main\n"),
                           ("sources.list.d/extra.list", b"deb [ allow-insecure=yes ] http://archive.example.invalid/ubuntu noble main\n"),
                           ("sources.list.d/example.sources", b"Types: deb\nURIs: http://a.example.invalid\nSuites: noble\nTrusted: yes\n"),
                           ("sources.list.d/example.sources", b"Types: deb\nURIs: http://a.example.invalid\nSuites: noble\nAllow-Weak: no\n yes\n"),
                           ("sources.list.d/extra.list", b"deb [check-valid-until=no] http://a.example.invalid noble main\n"),
                           ("sources.list.d/extra.list", b"deb [valid-until-min=864000] http://a.example.invalid noble main\n"),
                           ("sources.list.d/example.sources", b"Types: deb\nURIs: http://a.example.invalid\nSuites: noble\nCheck-Date: off\n"),
                           # apt's StringToBool reads an empty value or "00" as false through strtol.
                           ("sources.list.d/example.sources", b"Types: deb\nURIs: http://a.example.invalid\nSuites: noble\nCheck-Valid-Until:\n"),
                           ("sources.list.d/extra.list", b"deb [check-date=00] http://a.example.invalid noble main\n")):
            holds(self, "apt-trust", self.entry, sources={**self.SOURCES, name: text})
        # The three ways round 3 found to hide a trusted source (apt reads lines up to LF, keeps a "#" inside "[...]", and
        # reads deb822 by fields): each now shows the trusted source or holds the file.
        evil = b"http://evil.example.invalid noble main\n"
        holds(self, "apt-trust", self.entry, sources={**self.SOURCES, "sources.list.d/extra.list": b"deb [x-note=#a trusted=yes] " + evil})
        for text in (b"deb [x-note=a\rtrusted=yes] " + evil, b"deb [x-note=a\xc2\x85trusted=yes] " + evil, b"deb [x-note=a\xe2\x80\xa8trusted=yes] " + evil,
                     b"deb [x-note=a\xe2\x80\xa9trusted=yes] " + evil, b"deb [x-note=a\xfftrusted=yes] " + evil):
            holds(self, "apt-sources-line-break", apt.apt_sources, {**self.SOURCES, "sources.list.d/extra.list": text})
        stanza = b"Types: deb\nURIs: http://evil.example.invalid\nSuites: noble\nTrusted: yes\nX-Note: a"
        for separator in (b"\r", b"\xe2\x80\xa8"):
            holds(self, "apt-sources-line-break", apt.apt_sources, {**self.SOURCES, "sources.list.d/extra.sources": stanza + separator + b"Enabled: no\n"})
        # apt's ParseQuoteWord dequotes and decodes words, takes "]" inside a word, and refuses a broken option block.
        for line in (b'"deb" [trusted=yes] ', b"d%65b [trusted=yes] ", b"deb [x=a]b trusted=yes] ", b"deb [trusted=%79es] ", b"deb\t[ trusted=yes ] ",
                     b"deb [enabled=no trusted=yes] "):
            holds(self, "apt-trust", self.entry, sources={**self.SOURCES, "sources.list.d/extra.list": line + evil})
        for line in (b"deb [trusted=yes ", b"deb [trusted=yes%5d ", b"deb [check-valid-until=] ", b"deb [x] ", b"rpm [trusted=yes] ",
                     b'deb [x="a trusted=yes] ', b'"deb [trusted=yes] '):
            holds(self, "apt-sources-entry", apt.apt_sources, {**self.SOURCES, "sources.list.d/extra.list": line + evil})
        # deb822: a "#" continuation line is part of the value, so "Enabled: no" continued is no longer false.
        head = b"Types: deb\nURIs: http://evil.example.invalid\nSuites: noble\nComponents: main\n"
        # U+00A0 and U+3000 are no space to apt, so these first-line values are not empty and their continuation is kept.
        for fields in (b"Trusted: yes\nEnabled: no\n #note\n", b"Trusted: yes\n", b"Enabled: no\n x\nTrusted: yes\n", b"Enabled-: no\nTrusted: yes\n",
                       b"Enabled: \xc2\xa0\n no\nTrusted: yes\n", b"Check-Valid-Until: \xe3\x80\x80\n yes\n"):
            holds(self, "apt-trust", self.entry, sources={**self.SOURCES, "sources.list.d/extra.sources": head + fields})
        # Every deb822 shape apt could read differently holds (round 4): a line of only spaces or tabs (apt continues the field
        # across it), a tab-indented continuation, a trust field continued from an empty value (apt keeps a leading line break
        # before a tab), a repeated field, a continuation opening a stanza, a spaced or suffixed name, a line without a colon.
        for fields in (b"Trusted: yes\nEnabled: no\n \n x\n", b"Trusted: yes\nEnabled: no\n \nEnabled: yes\n", b"Enabled: yes\n \nTrusted: yes\nEnabled: no\n",
                       b"Trusted: yes\nEnabled: no\n\t\n", b"Trusted: yes\nEnabled:\n\tno\n", b"Check-Valid-Until:\n\tyes\n", b"Check-Date:\n\tyes\n",
                       b"Trusted: yes\nEnabled:\n no\n", b"Signed-By: /usr/share/keyrings/example.gpg\n\tx\n", b"Enabled: yes\nEnabled: no\nTrusted: yes\n",
                       b"Trusted: yes\nenabled: no\nEnabled: no\n", b"Trusted : yes\n", b"Enabled+: no\nTrusted: yes\n", b"Trusted yes\n",
                       b"Trusted: yes\n\n \n"):
            holds(self, "apt-sources-entry", apt.apt_sources, {**self.SOURCES, "sources.list.d/extra.sources": head + fields})
        holds(self, "apt-sources-entry", apt.apt_sources, {**self.SOURCES, "sources.list.d/extra.sources": b" Trusted: yes\n" + head})
        for name, text in (("sources.list.d/extra.sources", head + b"Trusted : yes\n"), ("sources.list.d/extra.list", b"deb [x] " + evil),
                           ("sources.list.d/extra.list", b"deb [x=a\rtrusted=yes] " + evil), ("sources.list.d/extra.list", None)):
            with self.assertRaises(Refusal) as caught:  # the hold names the file the owner has to look at
                apt.apt_sources({**self.SOURCES, name: text})
            self.assertIn(name + ":", str(caught.exception))
        # Ordinary shapes pass: Ubuntu 24.04's stock ubuntu.sources, an embedded Signed-By key block (sources.list(5); the
        # key text here is a placeholder) and a URI list continued from a non-empty value.
        stock = (b"## See the sources.list(5) manual page for further settings.\nTypes: deb\nURIs: http://archive.ubuntu.com/ubuntu/\n"
                 b"Suites: noble noble-updates noble-backports\nComponents: main restricted universe multiverse\n"
                 b"Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n## Ubuntu security updates. Aside from URIs and Suites,\n"
                 b"## this should mirror your choices in the previous section.\nTypes: deb\nURIs: http://security.ubuntu.com/ubuntu/\n"
                 b"Suites: noble-security\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n")
        keyed = (b"Types: deb\nURIs: https://ppa.example.invalid/example/tools/ubuntu/\n  https://mirror.example.invalid/tools/ubuntu/\n"
                 b"Suites: noble\nComponents: main\nSigned-By: \n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n PLACEHOLDERKEYTEXTNOTAKEY0000000000\n"
                 b" =abcd\n -----END PGP PUBLIC KEY BLOCK-----\n")
        self.assertEqual(apt.apt_sources({"sources.list.d/ubuntu.sources": stock, "sources.list.d/example-tools.sources": keyed})["problems"], [])
        quiet = {"sources.list": b"deb [arch=amd64 signed-by=/usr/share/keyrings/example.gpg] http://archive.example.invalid/ubuntu noble main"
                                 b" # [trusted=yes]\r\n# deb [trusted=yes] http://old.example.invalid noble main\r\n",
                 "sources.list.d/example.sources": b"Types: deb\r\nURIs: http://archive.example.invalid\r\nSuites: noble\r\n\r\n"
                                                   b"Types: deb\nURIs: http://evil.example.invalid\nEnabled: no\nTrusted: yes\n"}
        self.assertEqual(apt.apt_sources(quiet)["problems"], [])
        # Every name apt itself reads (apt GetListOfFilesInDir: any length, letters, digits, _ - : .) goes through the check.
        trusted = b"deb [trusted=yes] http://a.example.invalid noble main\n"
        for name in ("a" * 101 + ".list", "archive_uri-https_ppa.example.invalid_example_" + "x" * 60 + "-noble.list", "vendor:stable.list",
                     "example:repo.list", "sources.list", "ex.ample_1-2.list"):
            holds(self, "apt-trust", self.entry, sources={**self.SOURCES, "sources.list.d/" + name: trusted})
        holds(self, "apt-trust", self.entry, sources={**self.SOURCES, "sources.list.d/example:repo.sources":
                                                      b"Types: deb\nURIs: http://a.example.invalid\nSuites: noble\nTrusted: yes\n"})
        # apt's isalpha follows the locale, so non-ASCII names (also undecodable ones) are read too; they show as a placeholder.
        for name in ("caf\u00e9.list", "vendor\udce9.list"):
            found = apt.apt_sources({**self.SOURCES, "sources.list.d/" + name: trusted})
            self.assertEqual(found["problems"], ["(unprintable or long name):trusted"])
            self.assertEqual(stored(found), found)
        self.assertEqual(apt.apt_sources({"sources.list.d/" + "a" * 130 + ".list": trusted})["problems"], ["(unprintable or long name):trusted"])
        disabled = {**self.SOURCES, "sources.list.d/old.sources": b"# kept for reference\nTypes: deb\nURIs: http://a.example.invalid\n # note\n\n"
                                                                  b"Types: deb\nURIs: http://old.example.invalid\nEnabled: no\nTrusted: yes\n"}
        self.assertEqual(routes.drift(planned, self.entry(sources=disabled)), ["preflight.sources_sha256"])
        # Names apt skips are listed and hashed (adding one is drift), never read: a hidden name, other extensions or characters.
        skipped = ("sources.list.d/.hidden.list", "sources.list.d/ubuntu.sources.curtin.orig", "sources.list.d/example list.list",
                   "sources.list.d/example+1.list", "sources.list.d/" + "b" * 130 + ".save")
        ignored = {**self.SOURCES, **dict.fromkeys(skipped, trusted)}
        self.assertEqual(apt.apt_sources(ignored)["problems"], [])
        self.assertEqual(apt.apt_sources(ignored)["ignored"], ["sources.list.d/.hidden.list"] + ["(unprintable or long name)"] * 2
                         + ["sources.list.d/example+1.list", "sources.list.d/ubuntu.sources.curtin.orig"])
        self.assertEqual(routes.drift(planned, self.entry(sources=ignored)), ["preflight.sources_sha256"])
        holds(self, "apt-sources-unreadable", apt.apt_sources, {**self.SOURCES, "sources.list.d/extra.list": None})
        # The route itself: a sources file that cannot be read holds it, so no hidden source escapes the trust check.
        unreadable = ManagerRun(SETTLED_APT, folders={"/etc/apt": ["sources.list.d"], "/etc/apt/sources.list.d": ["example.sources"]})
        holds(self, "apt-sources-unreadable", package_registry.APT["run"]["preflight"], FakeProbe(), unreadable, {"id": "examplecurl"}, "upgrade")

        def changed(line):
            """The config fixture with this line instead of a line of the same key (a Dir line appears once in a dump)."""
            return b"".join(old for old in fixture("apt-config.txt").splitlines(True) if old.split(b" ")[0] != line.split(b" ")[0]) + line

        for line in (b'APT::Get::AllowUnauthenticated "true";\n', b'Acquire::AllowInsecureRepositories "1";\n',
                     b'DPkg::Options:: "--force-overwrite";\n', b"garbage\n", b'Binary::apt-get::APT::Get::AllowUnauthenticated "true";\n',
                     b'Binary::apt-get::DPkg::Options:: "--force-overwrite";\n', b'Dir::Etc::sourceparts "/opt/example/sources.d";\n',
                     b'APT::Sources::With:: "/opt/example/extra.sources";\n', b'Dir "/srv/example/";\n', b'Dir::Etc "etc/example/";\n',
                     b'Binary::apt-get::Dir::Etc::sourcelist "other.list";\n', b'Acquire::Check-Valid-Until "false";\n',
                     b'Acquire::Check-Date "0";\n', b'Acquire::Min-ValidTime "864000";\n', b'Acquire::Min-ValidTime::Example "1";\n',
                     b'Acquire::Check-Valid-Until::Example "no";\n', b'Acquire::Check-Valid-Until "00";\n', b'Acquire::Check-Date "0x0";\n',
                     b'Dir::Etc "etc/apt-other";\n', b'Dir::Etc "/etc/apt";\n', b'Dir::Etc "";\n', b'Dir::Etc::sourceparts "sources.list.d.example/";\n',
                     b'Dir "//";\n', b'Dir::Etc::sourcelist "sources.list/";\n', b'Dir::Etc "etc/apt ";\n', b'Dir::Etc::sourceparts " sources.list.d";\n',
                     # apt's FindFile puts RootDir in front of every path, sources included.
                     b'RootDir "/srv/example/";\n', b'Binary::apt-get::RootDir "/srv/example";\n', b'Dir::RootDir "/srv/example";\n', b'RootDir "//";\n'):
            holds(self, "apt-trust", self.entry, config=changed(line))
        # apt's FindDir appends "/" to a folder: the modern dump form (fixture), the old form and a trailing "/" are one folder.
        self.assertIn(b'Dir::Etc "etc/apt";\n', fixture("apt-config.txt"))
        for line in (b'Dir::Etc "etc/apt/";\n', b'Dir::Etc::sourceparts "sources.list.d/";\n', b'RootDir "/";\n', b'RootDir "";\n'):
            self.assertEqual(apt.apt_config(changed(line))["problems"], [])
        # The Dir lines `apt-config dump` prints on Ubuntu 24.04 (captured unchanged) pass.
        self.assertEqual(apt.apt_config(fixture("apt-config-dir-ubuntu.txt"))["problems"], [])
        self.assertEqual(apt.apt_config(fixture("apt-config.txt"))["problems"], [])
        # An empty or cut dump proves nothing, and apt-config's own switches or Binary::apt-config settings could mask it.
        self.assertEqual(apt.apt_config(b"")["problems"], ["dir::etc::sourcelist:missing", "dir::etc::sourceparts:missing", "dir::etc:missing",
                                                           "dir:missing"])
        cut = fixture("apt-config.txt").replace(b'Dir::Etc "etc/apt";\n', b"")
        self.assertEqual(apt.apt_config(cut)["problems"], ["dir::etc:missing"])
        defaults = b'Dir "/";\nDir::Etc "etc/apt";\nDir::Etc::sourcelist "sources.list";\nDir::Etc::sourceparts "sources.list.d";\n'
        self.assertEqual(apt.apt_config(defaults)["problems"], [])
        self.assertEqual(apt.apt_config(defaults * 3)["problems"], ["dir::etc::sourcelist:repeated", "dir::etc::sourceparts:repeated",
                                                                    "dir::etc:repeated", "dir:repeated"])
        holds(self, "apt-trust", self.entry, config=defaults * 3)
        masked = fixture("apt-config.txt") + b'APT::Get::AllowUnauthenticated "false";\nRootDir "/";\nbinary::apt-config "";\n'
        for config in (cut, fixture("apt-config.txt") + b'binary::apt-config "";\n', fixture("apt-config.txt") + b'APT::Config::Dump::EmptyValue "false";\n',
                       fixture("apt-config.txt") + b'APT::Config::Dump::Format "x";\n', masked,
                       fixture("apt-config.txt") + b'Binary::apt-config::RootDir "/";\n',
                       fixture("apt-config.txt").replace(b"Dir::", b"Binary::apt-get::Dir::")):
            holds(self, "apt-trust", self.entry, config=config)
        self.assertEqual(apt.apt_config(fixture("apt-config.txt") + b'Acquire::Check-Valid-Until "true";\nAcquire::Max-ValidTime "1";\n'
                                        b'APT::Sources::With "";\nAcquire::Check-Date "";\n')["problems"], [])
        checked = b"Types: deb\nURIs: http://a.example.invalid\nSuites: noble\nCheck-Valid-Until: yes\nCheck-Date: on\n"
        self.assertEqual(apt.apt_sources({**self.SOURCES, "sources.list.d/checked.sources": checked})["problems"], [])
        self.assertEqual(apt.apt_config(fixture("apt-config.txt") + b'Binary::apt-get::APT::Get::AllowUnauthenticated "true";\n')["problems"],
                         ["apt::get::allowunauthenticated"])
        self.assertEqual(apt.apt_config(fixture("apt-config.txt") + b'Binary::apt-get::DPkg::Options:: "--force-overwrite";\n')["problems"],
                         ["dpkg::options"])
        other = fixture("apt-config.txt").replace(b'"amd64"', b'"arm64"')
        self.assertEqual(routes.drift(planned, self.entry(config=other)), ["preflight.apt_config_sha256"])
        holds(self, "package-config-bytes", apt.apt_config, fixture("apt-config.txt") + b'X "\x1b]0;y\x07";\n')
        holds(self, "package-config-bytes", apt.apt_sources,
              {"sources.list.d/x.list": b"# note\x1b]\ndeb [trusted=yes] http://a.example.invalid noble main\n#\x07\n"})
        for name in ("../sources.list", "x.list", "sources.list.d/x/y.list", "sources.list.d\\x.list", "sources.list.d/", "sources.list.d/..",
                     "", "trusted.gpg", "/etc/apt/sources.list", 7):
            holds(self, "apt-sources", apt.apt_sources, {name: b""})
        holds(self, "apt-sources", apt.apt_sources, {**self.SOURCES, 7: b""})

    def test_transaction_drift_holds(self):
        planned = self.entry()
        extra = fixture("apt-simulate.txt") + f"Inst libexampleextra (1.0-1 {ORIGIN} [amd64])\n".encode()
        self.assertEqual(routes.drift(planned, self.entry(simulation=extra)), ["collateral", "transaction.sim_sha256"])
        conf = fixture("apt-simulate.txt") + f"Conf libexampleextra (1.0-1 {ORIGIN} [amd64])\n".encode()
        self.assertEqual(routes.drift(planned, self.entry(simulation=conf)), ["transaction.sim_sha256"])
        broken = fixture("apt-simulate.txt").replace(b"[i386])\nConf libexampledep", b"[i386]) [examplecurl:amd64 ]\nConf libexampledep")
        self.assertEqual(routes.drift(planned, self.entry(simulation=broken)), ["transaction.sim_sha256"])
        holds(self, "apt-removal", self.entry, simulation=fixture("apt-simulate.txt") + b"Remv exampleold [1.0-1]\n")
        holds(self, "apt-removal", self.entry, simulation=fixture("apt-simulate.txt") + b"Purg exampleold [1.0-1]\n")
        missing = b"".join(line for line in fixture("apt-simulate.txt").splitlines(True) if not line.startswith(b"Inst examplecurl "))
        holds(self, "apt-simulation", self.entry, simulation=missing)
        holds(self, "apt-not-installed", self.entry, installed=fixture("dpkg-installed.txt").replace(b"8.5.0-2example1", b"8.5.0-2example0"))
        for line in (f"Inst examplecurl [8.5.0-2example1] (8.5.0-2example2 {ORIGIN} [amd64]) [Curl:amd64 ]\n", "Inst examplecurl\n",
                     f"Inst examplecurl [8.5.0-2example1] (8.5.0-2example2 {ORIGIN} [amd_64])\n", "Conf examplecurl broken\n",
                     f"Inst examplecurl [8.5.0-2example1] (8.5.0-2example2 {ORIGIN} [amd64]) [libx on liby]\n"):
            holds(self, "apt-simulation", apt.apt_simulation, fixture("apt-simulate.txt") + line.encode(), exit_code=0)
        holds(self, "apt-simulation-failed", apt.apt_simulation, b"E: Unable to locate package examplecurl\n", exit_code=100)

    def test_stale_package_lists_reported_not_up_to_date(self):
        refreshed = readonly_runner.package_list_time("apt", probe=FakeProbe(newest=1760486400))  # 2025-10-15T00:00:00Z
        self.assertEqual(refreshed, "2025-10-15T00:00:00Z")
        stale = routes.list_age("apt", refreshed, now_utc=NOW)
        self.assertEqual((stale["status"], stale["message"]), ("stale", "stale; refresh needed"))
        recent = routes.list_age("apt", "2026-10-24T00:00:00Z", now_utc=NOW)
        self.assertEqual((recent["status"], recent["message"]), ("recent", "the newest package list is 1 day(s) old"))
        for probe in (FakeProbe(newest=None), FakeProbe(newest=OSError("not readable"))):
            self.assertIsNone(readonly_runner.package_list_time("apt", probe=probe))
        self.assertEqual(routes.list_age("apt", None, now_utc=NOW)["status"], "unknown")
        self.assertNotIn("up to date", (stale["message"] + recent["message"]).lower())

    def test_exit_codes_follow_the_documented_meanings(self):
        cases = {(0, ""): ("success", ""), (100, "E: Could not get lock /var/lib/dpkg/lock-frontend"): ("in_use_retry_later", ""),
                 (100, "E: Hash Sum mismatch"): ("integrity_failure", ""), (100, "W: cannot be authenticated"): ("integrity_failure", ""),
                 (100, "E: Unable to locate package"): ("failed", ""), (1, ""): ("failed", "elevation_not_completed")}
        for (code, output), expected in cases.items():
            result = routes.classify_exit("apt", code, output=output)
            self.assertEqual((result["class"], result["reason"]), expected, output)
        # sudo also exits 1 when the owner's authentication fails, so exit 1 cannot prove the elevated step ran.
        for code, reason in ((1, "dpkg_or_elevation_error"), (2, "dpkg_error")):
            self.assertEqual(routes.classify_exit("apt", code, recipe_id="apt.configure")["reason"], reason)
        for result, code, output in (("differs_from_plan", 100, "Could not get lock"), ("integrity_failure", 100, "Hash Sum mismatch")):
            self.assertEqual(result_of(routes.classify_exit("apt", code, output=output), {"target_installed": True}), result)
        self.assertEqual(result_of(routes.classify_exit("apt", None), {"target_installed": True}, signal="required"), "restart_needed")
        holds(self, "package-exit", routes.classify_exit, "apt", 0, source="clipboard")
        holds(self, "package-exit", routes.classify_exit, "apt", 0, recipe_id="apt.unknown")
        holds(self, "package-plan", self.entry, rows=[], selected=())

    def test_leading_dash_id_refused(self):
        for bad in ("-examplecurl", "--allow-downgrades", "-o"):
            for slot in ("package", "spec", "target"):
                holds(self, "package-token", routes.variable, slot, bad)
            holds(self, "package-token", routes.render, "apt.policy", {"package": bad})
            holds(self, "package-token", routes.render, "apt.upgrade", {"spec": [f"{bad}=1.0-1"]})
        holds(self, "apt-simulation", apt.apt_simulation, f"Inst -examplecurl [1.0-1] (1.0-2 {ORIGIN} [amd64])\n".encode(), exit_code=0)
        holds(self, "package-token", routes.render, "apt.newer", {"target": "-1", "installed": "1.0"})
        self.assertNotIn("-examplecurl:amd64", apt.dpkg_installed(b"-examplecurl\tamd64\t1.0-1\tii \n")["packages"])


@refusals_fail
class DnfRouteTests(unittest.TestCase):
    def rows(self, selected=("exampletool", "examplelib")):
        return [row for row in routes.dnf_upgrades(fixture("dnf-upgrades.txt"), exit_code=0)[0] if row["name"] in selected]

    def entry(self, selected=("exampletool", "examplelib"), realpath="/usr/bin/dnf5", version=None, installed=None, configs=None, preview=None):
        return routes.plan_dnf(self.rows(selected), realpath=realpath, version=version or fixture("dnf-version.txt"),
                               installed=routes.rpm_installed(installed or fixture("rpm-installed.txt")),
                               repo_configs=configs or {"updates": fixture("dnf-repo-config.txt")},
                               preview=routes.dnf_preview(preview or fixture("dnf-preview.txt")))

    def test_discovery_argv_is_read_only(self):
        nevra = "exampletool-0:8.9.1-3.fc41.x86_64"
        values = {"dnf.installed": {"rpm_name": ["exampletool", "examplelib"]}, "dnf.repo_config": {"repoid": "updates"},
                  "dnf.preview": {"nevra": [nevra]}, "dnf.preview_reinstall": {"nevra": nevra}}
        argvs = {rid: routes.render(rid, values.get(rid)) for rid in read_recipes("dnf")}
        # No -C: a normal user's dnf5 refreshes its per-user cache copy from root's cache only when the copy has expired.
        self.assertEqual(argvs["dnf.upgrades"], ("/usr/bin/dnf5", "repoquery", "--upgrades", "--latest-limit=1", package_tokens.QUERYFORMAT))
        self.assertEqual(argvs["dnf.installed"], ("/usr/bin/rpm", "-q", "--qf", package_tokens.RPMFORMAT, "exampletool", "examplelib"))
        self.assertEqual(argvs["dnf.all_installed"], ("/usr/bin/rpm", "-q", "-a", "--qf", package_tokens.RPMFORMAT))
        self.assertEqual(argvs["dnf.repo_config"], ("/usr/bin/dnf5", "--dump-repo-config=updates"))
        self.assertEqual(argvs["dnf.preview"], ("/usr/bin/dnf5", "upgrade", "--assumeno", "--no-allow-downgrade", nevra))
        self.assertEqual(argvs["dnf.preview_reinstall"], ("/usr/bin/dnf5", "reinstall", "--assumeno", "--no-allow-downgrade", nevra))
        self.assertFalse(any("-C" in argv for argv in argvs.values()))
        self.assertEqual(argvs["dnf.needs_restarting"], ("/usr/bin/dnf5", "needs-restarting"))
        for argv in argvs.values():
            self.assertNotIn("/usr/bin/sudo", argv)
            self.assertFalse({"makecache", "install", "remove", "-y"} & set(argv), argv)
            self.assertTrue(not {"upgrade", "reinstall"} & set(argv) or "--assumeno" in argv, argv)
            self.assertEqual(token_problems("dnf", argv, values=(nevra, "exampletool", "examplelib", "--dump-repo-config=updates"),
                                            shell=False), [])
        self.assertLessEqual(set(argvs), set(readonly_runner.recipes()))

    def test_plan_binds_exact_id_version_and_source(self):
        entry = self.entry()
        self.assertEqual(entry["items"], [
            {"name": "exampletool", "arch": "x86_64", "installed_nevras": ["exampletool-0:8.9.1-2.fc41.x86_64"],
             "target_nevra": "exampletool-0:8.9.1-3.fc41.x86_64", "repoid": "updates", "gpgcheck": True},
            {"name": "examplelib", "arch": "x86_64", "installed_nevras": ["examplelib-1:2.1-1.fc41.x86_64"],
             "target_nevra": "examplelib-1:2.1-2.fc41.x86_64", "repoid": "updates", "gpgcheck": True}])
        self.assertEqual((entry["flavor"], entry["collateral"], "preview" in entry), ("dnf5", ["exampledep"], False))
        # An install-only package (a kernel) is listed under "Installing:" and routes like an upgrade.
        kernel = routes.dnf_upgrades(b"examplekernel-0:6.11.6-300.fc41.x86_64 updates\n", exit_code=0)[0]
        planned = routes.plan_dnf(kernel, realpath="/usr/bin/dnf5", version=fixture("dnf-version.txt"),
                                  installed=routes.rpm_installed(b"examplekernel 0:6.11.5-300.fc41.x86_64\n"),
                                  repo_configs={"updates": fixture("dnf-repo-config.txt")}, preview=routes.dnf_preview(
                                      b"Package Arch Version Repository Size\nInstalling:\n examplekernel x86_64 6.11.6-300.fc41 updates 1 KiB\n"))
        self.assertEqual(planned["transaction"]["upgrades"], ["examplekernel-0:6.11.6-300.fc41.x86_64 updates"])
        holds(self, "package-config-bytes", routes.dnf_gpgcheck, b"[updates]\nname = x\x1b]\npkg_gpgcheck = 0\nusername = \x07\ngpgcheck = 1\n")
        for bad in ("exampletool-8.9.1-3.fc41.x86_64", "exampletool*", "@group", "exampletool-0:8.9.1-3.fc41.x86_64;x", "exampletool^",
                    "exampletool-0:1-1.fc41.rpm", "exampletool-0:1-1.fc41.RPM"):
            holds(self, "package-token", routes.variable, "nevra", bad)
        holds(self, "package-token", routes.variable, "rpm_name", "exampletool.rpm")
        for text in (b"exampletool-0:8.9.1-3.fc41.x86_64 updates extra\n", b"exampletool-8.9.1-3.fc41.x86_64 updates\n",
                     b"exampletool-0:8.9.1-3.fc41.x86_64\tupdates\n"):
            holds(self, "dnf-repoquery", routes.dnf_upgrades, text, exit_code=0)
        caret = fixture("dnf-upgrades.txt") + b"examplego-0:0^20240101git1234567-1.fc41.x86_64 updates\n"
        rows, held = routes.dnf_upgrades(caret, exit_code=0)
        self.assertEqual((len(rows), held), (2, [{"repoid": "updates", "reason": "nevra-not-routable"}]))
        holds(self, "dnf-metadata", routes.dnf_upgrades, b"", exit_code=1)
        for realpath in ("/usr/bin/dnf-3", "/usr/bin/dnf4", None):
            holds(self, "dnf-held", self.entry, realpath=realpath)
        installs = routes.rpm_installed(b"examplekernel 0:6.11.4-301.fc41.x86_64\nexamplekernel 0:6.11.5-300.fc41.x86_64\nbad line here\n")
        self.assertEqual((len(installs["packages"]["examplekernel.x86_64"]), len(installs["unrecognised"])), (2, 1))

    def test_run_argv_is_fixed_and_refuses_forbidden_flags(self):
        argv = routes.run_argv(self.entry())
        self.assertEqual(argv, ("/usr/bin/sudo", "/usr/bin/dnf5", "upgrade", "-y", "--no-allow-downgrade", "exampletool-0:8.9.1-3.fc41.x86_64",
                                "examplelib-1:2.1-2.fc41.x86_64"))
        self.assertEqual(token_problems("dnf", argv, values=argv[5:]), [])
        self.assertIn(("dnf", "/usr/bin/sudo"), package_tokens.ALLOWED)
        for flag in ("--nogpgcheck", "--no-gpgchecks", "--setopt", "--repofrompath", "--allowerasing", "--from-vendor", "--allow-downgrade"):
            self.assertIn(("dnf", flag), package_tokens.FORBIDDEN)
            self.assertNotIn(flag, argv)
        for nevra in ("--allowerasing", "exampletool", "exampletool-0:1-1.fc41.x86_64 extra", "exampletool-0:1-1.fc41.rpm"):
            holds(self, "package-token", routes.render, "dnf.upgrade", {"nevra": [nevra]})
        holds(self, "package-manager", routes.run_argv, {"manager": "pacman"})
        self.assertEqual(table_problems({"dnf"}), [])

    def test_verification_requires_planned_version(self):
        target, before, after = "exampletool-0:8.9.1-3.fc41.x86_64", fixture("rpm-all-before.txt"), fixture("rpm-all-after.txt")
        def verified(before, after):
            payload = {"id": "exampletool", "version": target, "operation": "upgrade", "preflight": {},
                       "dependencies": ["examplelib.x86_64@1:2.1-2.fc41/updates", "exampledep.x86_64@1:1.0-1.fc41/updates"]}
            return package_registry.DNF["verify"](payload, {when: {"dnf.all_installed": {"stdout": data, "ok": True, "exit_code": 0}}
                                                            for when, data in (("before", before), ("after", after))})
        def settled(code, verification):
            return package_registry.route_result({"run_kind": "terminal"}, routes.classify_exit("dnf", code), verification)["result"]
        ok = verified(before, after)
        self.assertEqual((ok["result"], ok["verified_postcondition"], ok["installed_version"], ok["facts"]["changed_outside_plan"]), ("updated", True, target, []))
        self.assertEqual(settled(0, ok), "updated")
        wrong = verified(before, after.replace(b"8.9.1-3", b"8.9.1-4"))
        self.assertEqual((wrong["result"], wrong["installed_version"]), ("did_not_update", None))
        self.assertEqual(settled(0, wrong), "did_not_update")
        outside = verified(before, after.replace(b"4.0-1.fc41", b"4.0-2.fc41"))
        self.assertEqual(outside["facts"]["changed_outside_plan"], ["exampleother.noarch"])
        # A package that disappears is never a planned change, even when its name is planned collateral (an obsoleted package).
        gone = verified(before + b"exampledep 0:0.9-1.fc41.x86_64\n", after.replace(b"exampledep 1:1.0-1.fc41.x86_64\n", b""))
        self.assertEqual((gone["installed_version"], gone["facts"]["changed_outside_plan"]), (target, ["exampledep.x86_64"]))
        self.assertEqual(settled(0, gone), "differs_from_plan")
        key = verified(before, after.replace(b"e99d6ad1-64d2612c", b"0badc0de-65000000"))
        self.assertEqual((key["result"], key["verified_postcondition"]), ("updated", False))
        self.assertEqual(settled(0, key), "could_not_check")
        self.assertEqual(settled(None, wrong), "did_not_update")

    def test_executable_is_absolute_and_no_shell(self):
        launcher = FakeLauncher(fixture("dnf-version.txt"))
        readonly_runner.run_recipe("dnf.version", launcher=launcher, probe=FakeProbe())
        self.assertEqual(launcher.calls[0].argv, ("/usr/bin/dnf5", "--version"))
        for recipe_id, probe, code in (("dnf.version", FakeProbe(links={"/usr/bin/dnf": "/usr/bin/dnf-3"}), "dnf-held"),
                                       ("dnf.all_installed", FakeProbe(files={"/usr/bin/rpm": regular(1000)}), "runner-executable"),
                                       ("dnf.version", FakeProbe(files={"/": folder(mode=0o777)}), "runner-executable")):
            holds(self, code, readonly_runner.run_recipe, recipe_id, launcher=launcher, probe=probe)
        self.assertEqual(len(launcher.calls), 1)
        self.assertEqual(routes.run_argv(self.entry())[:2], ("/usr/bin/sudo", "/usr/bin/dnf5"))

    def test_restart_signal_is_reported_not_triggered(self):
        self.assertEqual([routes.dnf_restart(code) for code in (1, 0, 2, None, "1")], ["recommended", "none", "unknown", "unknown", "unknown"])
        self.assertEqual(routes.READ_RECIPES["dnf.needs_restarting"].ok_exits, frozenset({0, 1}))
        self.assertEqual(result_of(routes.classify_exit("dnf", 0), {"target_installed": True}, signal="recommended"), "updated")
        self.assertEqual(routes.classify_exit("dnf", 2)["reason"], "route_defect")
        self.assertEqual(routes.classify_exit("dnf", 1)["class"], "failed")
        self.assertFalse({"reboot", "--reboot", "needs-restarting"} & set(routes.run_argv(self.entry())))
        holds(self, "package-restart", result_of, routes.classify_exit("dnf", 0), {"target_installed": True}, signal="soon")

    def test_environment_is_fixed(self):
        env = routes.environment("dnf", home=HOME, user="ignored")
        self.assertEqual(env, {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": HOME, "LC_ALL": "C"})
        launcher = FakeLauncher(fixture("dnf-upgrades.txt"))
        readonly_runner.run_recipe("dnf.upgrades", launcher=launcher, probe=FakeProbe())
        self.assertEqual((launcher.calls[0].env, launcher.calls[0].cwd), (env, "/"))

    def test_provenance_preflight_holds_on_drift(self):
        planned = self.entry()
        self.assertEqual(routes.drift(planned, self.entry()), [])
        for config in (b"[updates]\npkg_gpgcheck = 0\n", b"[updates]\nname = x\n", b"[updates]\npkg_gpgcheck = 1\ngpgcheck = 0\n"):
            holds(self, "dnf-gpgcheck", self.entry, configs={"updates": config})
        holds(self, "dnf-gpgcheck", self.entry, configs={"other": fixture("dnf-repo-config.txt")})
        other_repo = fixture("dnf-preview.txt").replace(b"1:1.0-1.fc41     updates", b"1:1.0-1.fc41     extras ")
        holds(self, "dnf-gpgcheck", self.entry, preview=other_repo)
        newer = fixture("dnf-version.txt").replace(b"5.2.8.1", b"5.2.9.0")
        self.assertEqual(routes.drift(planned, self.entry(version=newer)), ["preflight.dnf5_version_sha256"])
        holds(self, "package-elevated", readonly_runner.run_recipe, "dnf.version", launcher=FakeLauncher(), probe=FakeProbe(elevation="root"))

    def test_transaction_drift_holds(self):
        planned = self.entry()
        holds(self, "dnf-removal", self.entry, preview=fixture("dnf-preview.txt").replace(b"Installing dependencies:\n", b"Removing dependent packages:\n"))
        extra = fixture("dnf-preview.txt").replace(b"\n\nTransaction Summary", b"\n exampleextra  x86_64  1.0-1.fc41  updates  1 KiB\n\nTransaction Summary")
        self.assertEqual(routes.drift(planned, self.entry(preview=extra)), ["collateral", "transaction.preview_sha256"])
        # Output without a transaction table always holds; there is no "preview unavailable" plan.
        for failure in (b"Failed to resolve the transaction:\nProblem: conflicting requests\n", b"No match for argument: exampletool\n", b"",
                        b"This command has to be run with superuser privileges (under the root user on most systems).\n"):
            holds(self, "dnf-preview", routes.dnf_preview, failure)
        # dnf removes an obsoleted package without --allowerasing: a "replacing" row of another name or architecture is a removal.
        obsoletes = fixture("dnf-preview.txt").replace(b"   replacing examplelib ", b"   replacing exampleold ")
        self.assertTrue(routes.dnf_preview(obsoletes)["removals"])
        holds(self, "dnf-removal", self.entry, preview=obsoletes)
        holds(self, "dnf-removal", self.entry, preview=fixture("dnf-preview.txt").replace(b"replacing examplelib   x86_64", b"replacing examplelib   i686  "))
        self.assertFalse(routes.dnf_preview(fixture("dnf-preview.txt"))["removals"])
        # A "replacing" row belongs to the package row above it in the same section.
        moved = fixture("dnf-preview.txt").replace(b"   replacing examplelib ", b"Installing:\n   replacing examplelib ")
        self.assertTrue(routes.dnf_preview(moved)["removals"])
        holds(self, "dnf-removal", routes.plan_dnf, [], realpath="/usr/bin/dnf5", version=b"", installed={}, repo_configs={},
              preview=routes.dnf_preview(b"Package Arch Version\nUpgrading:\n   replacing exampleold x86_64 1.0-1.fc41 updates 1 KiB\n"))
        moved = fixture("rpm-installed.txt").replace(b"8.9.1-2", b"8.9.1-2.1")
        self.assertEqual(routes.drift(planned, self.entry(installed=moved)), ["items", "transaction.installed"])
        holds(self, "dnf-not-installed", self.entry, installed=b"examplelib 1:2.1-1.fc41.x86_64\n")
        no_item = fixture("dnf-preview.txt").replace(b" examplelib               x86_64  1:2.1-2.fc41     updates     10.0 KiB\n", b"")
        no_item = no_item.replace(b"   replacing examplelib   x86_64  1:2.1-1.fc41     updates     10.0 KiB\n", b"")
        holds(self, "dnf-preview-item", self.entry, preview=no_item)
        for text in (b"Package Arch Version\nUpgrading:\nnot-indented x86_64 1 updates\n", b"Package Arch Version\n orphan x86_64 1 updates\n"):
            holds(self, "dnf-preview", routes.dnf_preview, text)

    def test_stale_package_lists_reported_not_up_to_date(self):
        stale = routes.list_age("dnf", "2026-10-01T00:00:00Z", now_utc=NOW)
        self.assertEqual((stale["status"], stale["message"]), ("stale", "stale; refresh needed"))
        self.assertEqual(routes.list_age("dnf", None, now_utc=NOW)["status"], "unknown")
        self.assertIsNone(readonly_runner.package_list_time("dnf", probe=FakeProbe()))
        self.assertNotIn("up to date", stale["message"])
        holds(self, "package-manager", readonly_runner.package_list_time, "pacman", probe=FakeProbe())

    def test_leading_dash_id_refused(self):
        for slot, bad in (("nevra", "-exampletool-0:1-1.fc41.x86_64"), ("rpm_name", "-q"), ("repoid", "--setopt"), ("rpm_name", "--nogpgcheck")):
            holds(self, "package-token", routes.variable, slot, bad)
        for recipe_id, values in (("dnf.repo_config", {"repoid": "-x"}), ("dnf.installed", {"rpm_name": ["-a"]}),
                                  ("dnf.preview", {"nevra": ["-exampletool-0:1-1.fc41.x86_64"]})):
            holds(self, "package-token", routes.render, recipe_id, values)
        self.assertEqual(routes.dnf_upgrades(b"-exampletool-0:1.0-1.fc41.x86_64 updates\n", exit_code=0),
                         ([], [{"repoid": "updates", "reason": "nevra-not-routable"}]))
        holds(self, "dnf-repoquery", routes.dnf_upgrades, b"-exampletool-0:1.0-1.fc41.x86_64 --setopt\n", exit_code=0)



def winget_run(installed=b"", client=WINGET_OUTPUT):
    """A run function over fictional winget output (recipe id -> result), for the registry's winget hooks."""
    outputs = {"winget.version": client, "winget.source": fixture("winget-source.json"), "winget.installed": installed}
    return lambda recipe_id, values=None: {"recipe": recipe_id, "ok": True, "exit_code": 0, "stdout": outputs[recipe_id]}


@refusals_fail
class RegistryTests(unittest.TestCase):
    def test_validate_descriptor_refuses_bad_shapes(self):
        for manager, route in package_registry.DESCRIPTORS.items():
            self.assertIs(package_registry.validate_descriptor(route), route)
            self.assertEqual(route["manager"], manager)
        good = dict(fake_route())
        self.assertIs(package_registry.validate_descriptor(good), good)
        stub = {"manager": "fwupd", "platforms": ("linux",), "group": "system_drivers", "state": "not built", "run_kind": "terminal", "flags": ()}
        self.assertIs(package_registry.validate_descriptor(stub), stub)
        run = dict(good["run"])
        bad = {"unknown manager": {**good, "manager": "chocolatey"}, "unknown state": {**good, "state": "half built"},
               "platform": {**good, "platforms": ("linux", "beos")}, "platform list": {**good, "platforms": ["linux"]},
               "no platform": {**good, "platforms": ()}, "repeated platform": {**good, "platforms": ("linux", "linux")},
               "group": {**good, "group": "games"}, "run kind": {**good, "run_kind": "shell"}, "flag": {**good, "flags": ("restart_whenever",)},
               "missing hook": {k: v for k, v in good.items() if k != "drift"}, "hook not callable": {**good, "verify": "verify"},
               "extra field": {**good, "command": "anything"}, "missing field": {k: v for k, v in good.items() if k != "group"},
               "verify recipes": {**good, "verify_recipes": "apt.audit"}, "restart probe": {**good, "restart_probe": 3},
               "run spec": {**good, "run": None}, "run hook": {**good, "run": {**run, "values": None}},
               "os consent": {**good, "run": {**run, "os_consent": "observed"}}, "no recipes": {**good, "run": {**run, "recipes": ()}},
               "restart files": {**good, "run": {**run, "restart_files": ["/run/reboot-required"]}},
               "restart source": {**good, "run": {**run, "restart_files": {"/run/reboot-required": None}}},
               "restart source path": {**good, "run": {**run, "restart_files": {"/run/reboot-required": "/run/reboot-required"}}},
               "self ids": {**good, "self_ids": ["pip"]}, "plan without its selection": {**good, "plan": lambda candidate, facts: {}},
               "not a mapping": [("manager", "pip")]}
        for name, descriptor in bad.items():
            with self.subTest(name=name):
                holds(self, "package-descriptor", package_registry.validate_descriptor, descriptor)
        one, both = SimpleNamespace(DESCRIPTOR=stub), SimpleNamespace(DESCRIPTOR=stub, DESCRIPTORS=(stub,))
        self.assertEqual(package_registry.descriptors_of(one), (stub,))
        self.assertEqual(package_registry.descriptors_of(SimpleNamespace(DESCRIPTORS=(stub, stub))), (stub, stub))
        for module in (both, SimpleNamespace(), SimpleNamespace(DESCRIPTORS=[stub]), SimpleNamespace(DESCRIPTORS=())):
            holds(self, "package-descriptor", package_registry.descriptors_of, module)
        holds(self, "package-manager-unknown", package_registry.descriptor, "pip")
        with mock.patch.object(package_registry, "DESCRIPTORS", MappingProxyType({**package_registry.DESCRIPTORS, "fwupd": stub})):
            holds(self, "package-manager-unknown", package_registry.descriptor, "fwupd")

    def test_registry_is_pure_and_shows_only_the_launchers_argv(self):
        # The registry imports no process module and writes no option of its own; render() shows the argv the launcher runs.
        tree = ast.parse((ROOT / "scripts" / "package_registry.py").read_text(encoding="utf-8"))
        imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        self.assertFalse(imported & {"subprocess", "asyncio", "multiprocessing", "pty", "os", "readonly_runner"})
        names = {target.id for node in tree.body if isinstance(node, ast.Assign) for target in node.targets if isinstance(target, ast.Name)}
        self.assertFalse([name for name in names if "TOKENS" in name])
        literals = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and node.value.startswith("-")]
        self.assertEqual(literals, [])
        argv = package_registry.argv("apt.upgrade", {"spec": ["example-tool=1.0-1"]}, executable=SUDO, prefix=("prefix",))
        self.assertEqual(argv[:2], (SUDO, "prefix"))
        self.assertEqual(package_registry.render("apt.upgrade", {"spec": ["example-tool=1.0-1"]}, executable=SUDO), " ".join(argv[:1] + argv[2:]))
        shown = package_registry.render("winget.export", {"export_file": EXPORT_FILE}, executable=WINGET, run_folder=RUN_FOLDER)
        self.assertIn("'" + EXPORT_FILE + "'", shown)
        self.assertNotIn("--accept-source-agreements", shown)
        self.assertEqual(set(package_registry.read_recipes()), set(routes.READ_RECIPES))
        self.assertEqual(set(package_registry.run_recipes()), set(routes.RUN_RECIPES))
        self.assertEqual(package_registry.allowed(), package_tokens.ALLOWED)

    def test_shown_lines_keep_every_argument_literal_in_their_shell(self):
        # POSIX: what a shell splits back is exactly the argv.
        hostile = ["/usr/bin/sudo", "/srv/a b/$(touch x)", "`id`;&|<>*?[]{}", "it's", "~", "a=b", "--flag"]
        # Single quotes, literally: double quotes would split back the same and still let a shell run the substitution.
        self.assertEqual(package_registry.shell_line(hostile), "/usr/bin/sudo '/srv/a b/$(touch x)' '`id`;&|<>*?[]{}' 'it'\"'\"'s' '~' a=b --flag")
        self.assertEqual(shlex.split(package_registry.shell_line(hostile)), hostile)
        argv = package_registry.argv("apt.upgrade", {"spec": ["example-tool=1.2~rc1-1"]}, executable=SUDO)
        self.assertEqual(shlex.split(package_registry.render("apt.upgrade", {"spec": ["example-tool=1.2~rc1-1"]}, executable=SUDO)), list(argv))
        # PowerShell: the call operator for a quoted program; plain words stay; everything else is in single quotes with each
        # quote doubled, the curly ones PowerShell also reads as quotes among them.
        self.assertEqual(package_registry.shell_line(["C:\\Tools\\tool.exe", "--id", "-I", "Contoso.NoteTaker", "3.4.1", "$(calc)", "`n", "it's", "a\u2018b\u2019c\u201ad\u201be",
                                                      "D:\\run folder\\x.log", "a;b", "@file", "a=b"]),
                         "& 'C:\\Tools\\tool.exe' --id -I Contoso.NoteTaker '3.4.1' '$(calc)' '`n' 'it''s' 'a\u2018\u2018b\u2019\u2019c\u201a\u201ad\u201b\u201be' "
                         "'D:\\run folder\\x.log' 'a;b' '@file' 'a=b'")
        self.assertTrue(package_registry.shell_line(["\\\\server\\share\\tool.exe"]).startswith("& '"))
        # A token no line can carry holds on both shells; a double quote only where PowerShell cannot pass it on.
        for program in ("/usr/bin/sudo", "C:\\Tools\\tool.exe"):
            for token in ("new\nline", "carriage\rreturn", "tab\tbed", "esc\x1b[0m", "nul\x00", "bidi\u202eright", "line\u2028sep", "zero\u200bwidth", ""):
                with self.subTest(program=program, token=token):
                    holds(self, "package-shown-command", package_registry.shell_line, [program, token])
        holds(self, "package-shown-command", package_registry.shell_line, ["C:\\Tools\\tool.exe", 'say"hi'])
        self.assertEqual(shlex.split(package_registry.shell_line(["/usr/bin/sudo", 'say"hi'])), ["/usr/bin/sudo", 'say"hi'])
        holds(self, "package-shown-command", package_registry.shell_line, [])

    def test_route_module_tables_reach_the_renderer(self):
        # A further route module brings its recipes, tokens and slot grammar; the registry's argv and render use exactly those.
        rows = tuple(package_tokens.Token(token=token, allowed=allowed, manager="pip", url="https://docs.python.org/3/")
                     for token, allowed in (("/opt/example/bin/tool", True), ("install", True), ("--force", False)))
        recipes = {"example.install": package_tokens.Recipe("pip", "/opt/example/bin/tool", ("install", package_tokens.Slot("example_spec"))),
                   "example.forced": package_tokens.Recipe("pip", "/opt/example/bin/tool", ("install", "--force"))}
        module = SimpleNamespace(RUN_RECIPES=recipes, EXAMPLE_TOKENS=rows, SLOTS={"example_spec": re.compile(r"[a-z]+==[0-9.]+").fullmatch})
        values = {"example_spec": "tool==1.0"}
        holds(self, "package-recipe", package_registry.argv, "example.install", values, executable="/opt/example/bin/tool")
        with mock.patch.object(package_registry, "ROUTE_MODULES", (module,)):
            self.assertEqual(package_registry.argv("example.install", values, executable="/opt/example/bin/tool", prefix=("p",)),
                             ("/opt/example/bin/tool", "p", "install", "tool==1.0"))
            self.assertEqual(package_registry.render("example.install", values, executable="/opt/example/bin/tool"), "/opt/example/bin/tool install tool==1.0")
            # The tables stay checked: a forbidden row, a value outside the grammar and a value the slot does not know all hold.
            holds(self, "package-token-not-allowed", package_registry.argv, "example.forced", executable="/opt/example/bin/tool")
            holds(self, "package-token", package_registry.argv, "example.install", {"example_spec": "tool>=1.0"}, executable="/opt/example/bin/tool")
            holds(self, "package-executable", package_registry.argv, "example.install", values, executable="/opt/other/tool")
            self.assertEqual(package_registry.argv("apt.configure", {}, executable=SUDO)[0], SUDO)
        holds(self, "package-recipe", routes.render, "example.install", values, executable="/opt/example/bin/tool")

    def test_one_result_function_selects_every_result(self):
        process, terminal = {"run_kind": "process"}, {"run_kind": "terminal"}
        def result(payload, kind, reported, verified=True, signal=None):
            exited = None if kind is None else {"class": kind}
            return package_registry.route_result(payload, exited, {"result": reported, "verified_postcondition": verified}, signal=signal)
        table = ((process, "success", "updated", True, None, ("updated", True)),
                 (process, "restart", "updated", True, None, ("updated", True)),
                 (process, "nothing_to_do", "updated", True, None, ("updated", True)),
                 # No recorded exit: unknown, even when the target reads as installed.
                 (process, None, "updated", True, None, ("unknown", False)),
                 # A missing or false postcondition never claims what is installed.
                 (process, "success", "updated", False, None, ("could_not_check", False)),
                 (process, "success", "updated", None, None, ("could_not_check", False)),
                 (process, "success", "updated", "yes", None, ("could_not_check", False)),
                 (process, "success", "did_not_update", False, None, ("could_not_check", False)),
                 (process, "success", "not_installed_power", False, None, ("could_not_check", False)),
                 (process, "success", "did_not_update", True, None, ("did_not_update", True)),
                 (process, "success", "not_installed_power", True, None, ("not_installed_power", True)),
                 # A failed or unobserved child is never updated.
                 (process, "failed", "updated", True, None, ("differs_from_plan", False)),
                 (process, "in_use_retry_later", "updated", True, None, ("differs_from_plan", False)),
                 (process, "not_observed", "updated", True, None, ("could_not_check", False)),
                 (process, "failed", "did_not_update", True, None, ("did_not_update", True)),
                 # The elevation refused, so the command never ran: it did not update where the read confirms that, and nothing else.
                 (terminal, "not_started", "did_not_update", True, None, ("did_not_update", True)),
                 (terminal, "not_started", "did_not_update", True, "required", ("did_not_update", True)),
                 (terminal, "not_started", "did_not_update", False, None, ("could_not_check", False)),
                 (terminal, "not_started", "updated", True, None, ("could_not_check", False)),
                 (terminal, "not_started", "differs_from_plan", True, None, ("could_not_check", False)),
                 ({**terminal, "operation": "repair"}, "not_started", "did_not_update", True, None, ("could_not_check", False)),
                 # Integrity beats a restart; a failed terminal run holds, also before a restart signal.
                 (process, "integrity_failure", "updated", True, "required", ("integrity_failure", False)),
                 (terminal, "integrity_failure", "did_not_update", True, None, ("integrity_failure", False)),
                 (terminal, "failed", "did_not_update", True, None, ("could_not_check", False)),
                 (terminal, "failed", "did_not_update", True, "required", ("could_not_check", False)),
                 (terminal, "in_use_retry_later", "did_not_update", True, None, ("could_not_check", False)),
                 (terminal, "not_observed", "did_not_update", True, None, ("did_not_update", True)),
                 (terminal, "success", "did_not_update", True, None, ("did_not_update", True)),
                 # Only a signal of the restart class keeps the operation open.
                 (process, "success", "updated", True, "required", ("restart_needed", False)),
                 (process, "success", "updated", True, "initiated_by_installer", ("restart_needed", False)),
                 (process, "success", "updated", True, "recommended", ("updated", True)),
                 (process, "success", "updated", True, "none", ("updated", True)),
                 # What a route reports stands only within the closing results.
                 (process, "success", "differs_from_plan", True, None, ("differs_from_plan", False)),
                 (process, "success", "device_not_responding", False, None, ("device_not_responding", False)),
                 (process, "success", "unknown", False, None, ("unknown", False)),
                 (process, "success", "restart_needed", True, None, ("could_not_check", False)),
                 (process, "success", "not a result", True, None, ("could_not_check", False)),
                 (process, "success", ["updated"], True, None, ("could_not_check", False)),
                 (process, "success", None, True, None, ("could_not_check", False)))
        for payload, kind, reported, verified, signal, expected in table:
            with self.subTest(kind=kind, reported=reported, verified=verified, signal=signal, run_kind=payload["run_kind"]):
                self.assertEqual(result(payload, kind, reported, verified, signal), {"result": expected[0], "verified_postcondition": expected[1]})
        holds(self, "package-restart", result, process, "success", "updated", True, "soon")

    def apt_reads(self, before, after):
        return {"before": {"apt.installed": {"ok": True, "stdout": before.encode()}}, "after": {"apt.installed": {"ok": True, "stdout": after.encode()}}}

    def test_apt_postcondition_needs_the_complete_state_of_every_planned_package(self):
        verify = package_registry.APT["verify"]
        payload = {"id": "example-tool", "version": "1.2.3-1", "operation": "upgrade", "dependencies": ["libexample:amd64@2.0-1"], "preflight": {"arch": "amd64"}}
        old = "example-tool\tamd64\t1.2.2-1\tii \nlibexample\tamd64\t1.9-1\tii \n"
        new = "example-tool\tamd64\t1.2.3-1\tii \nlibexample\tamd64\t2.0-1\tii \n"
        cases = (("every planned package installed", old, new, "updated", True),
                 ("nothing changed", old, old, "did_not_update", True),
                 ("the error flag on the item", old, new.replace("1.2.3-1\tii ", "1.2.3-1\tiiR"), "did_not_update", False),
                 ("the error flag on a collateral package", old, new.replace("2.0-1\tii ", "2.0-1\tiiR"), "updated", False),
                 ("half configured collateral package", old, new.replace("2.0-1\tii ", "2.0-1\tiF "), "updated", False),
                 ("unpacked item", old, new.replace("1.2.3-1\tii ", "1.2.3-1\tiU "), "did_not_update", False),
                 ("the item gone", old, "libexample\tamd64\t2.0-1\tii \n", None, False),
                 ("only another architecture of the item", "example-tool\ti386\t1.2.2-1\tii \nlibexample\tamd64\t1.9-1\tii \n",
                  "example-tool\ti386\t1.2.2-1\tii \nlibexample\tamd64\t1.9-1\tii \n", "did_not_update", False),
                 ("the item never there", "libexample\tamd64\t1.9-1\tii \n", "libexample\tamd64\t1.9-1\tii \n", "did_not_update", False),
                 ("the item listed but not installed", "example-tool\tamd64\t\tun \n", "example-tool\tamd64\t\tun \n", "did_not_update", False),
                 ("collateral missing with the item at its target", "example-tool\tamd64\t1.2.2-1\tii \n", "example-tool\tamd64\t1.2.3-1\tii \n", "updated", False),
                 ("collateral short of its bound target", old, new.replace("2.0-1\tii ", "1.9-1\tii "), "updated", False),
                 ("collateral past its bound target", old, new.replace("2.0-1\tii ", "2.0-2\tii "), "updated", False),
                 # Another architecture of the same name changing is outside the plan, even though the name is planned.
                 ("another architecture of the collateral moved", old + "libexample\ti386\t1.9-1\tii \n", new + "libexample\ti386\t2.0-1\tii \n", "differs_from_plan", True),
                 ("an empty read", old, "", None, False))
        for name, before, after, result, verified in cases:
            with self.subTest(case=name):
                found = verify(payload, self.apt_reads(before, after))
                self.assertEqual((result or found["result"], found["verified_postcondition"]), (found["result"], verified))
                if not verified:
                    self.assertNotEqual(package_registry.route_result({"run_kind": "terminal"}, {"class": "success"}, found)["result"], "updated")
        # A dependency the plan would have added stays absent after a run that changed nothing: nothing is half done.
        added = {**payload, "dependencies": ["libnew:amd64@1.0-1"]}
        same = "example-tool\tamd64\t1.2.2-1\tii \n"
        found = verify(added, self.apt_reads(same, same))
        self.assertEqual((found["result"], found["verified_postcondition"]), ("did_not_update", True))
        # The planned package of another architecture is missing: a healthy row of the same name is not it.
        foreign = {**payload, "dependencies": ["libexample:arm64@2.0-1"]}
        found = verify(foreign, self.apt_reads(old, "example-tool\tamd64\t1.2.3-1\tii \nlibexample\tamd64\t1.9-1\tii \n"))
        self.assertEqual((found["result"], found["verified_postcondition"]), ("updated", False))
        self.assertEqual(package_registry.route_result({"run_kind": "terminal"}, {"class": "success"}, found)["result"], "could_not_check")
        found = verify(foreign, self.apt_reads(old + "libexample\tarm64\t1.9-1\tii \n", new.replace("2.0-1", "1.9-1") + "libexample\tarm64\t2.0-1\tii \n"))
        self.assertEqual((found["result"], found["verified_postcondition"]), ("updated", True))
        # Rows of a foreign architecture, or a removed package's config files, are no reason to doubt a good update.
        for extra in ("example-tool\ti386\t\trc \n", "example-tool\ti386\t1.0\thi \n", "libexample\ti386\t1.0\trc \n"):
            with self.subTest(extra=extra):
                found = verify(payload, self.apt_reads(old + extra, new + extra))
                self.assertEqual((found["result"], found["verified_postcondition"]), ("updated", True))
        # A planned package left as config files only, while nothing moved, is not half done either.
        found = verify(payload, self.apt_reads("example-tool\tamd64\t1.2.2-1\tii \nlibexample\tamd64\t1.9-1\trc \n", "example-tool\tamd64\t1.2.2-1\tii \nlibexample\tamd64\t1.9-1\trc \n"))
        self.assertEqual((found["result"], found["verified_postcondition"]), ("did_not_update", True))
        # A foreign architecture of the same name is not the item.
        both = "example-tool\tamd64\t{}\tii \nexample-tool\ti386\t1.2.2-1\tii \nlibexample\tamd64\t{}\tii \n"
        found = verify(payload, self.apt_reads(both.format("1.2.2-1", "1.9-1"), both.format("1.2.3-1", "2.0-1")))
        self.assertEqual((found["result"], found["verified_postcondition"], found["installed_version"]), ("updated", True, "1.2.3-1"))

    def test_apt_repair_needs_a_settled_package_database(self):
        verify = package_registry.APT["verify"]
        payload = {"id": "dpkg", "version": "1.22.6", "operation": "repair", "dependencies": [], "preflight": {}}
        before = "dpkg\tamd64\t1.22.6\tii \nexample-tool\tamd64\t1.0\tiF \n"
        settled = "dpkg\tamd64\t1.22.6\tii \nexample-tool\tamd64\t1.0\tii \nold-tool\tamd64\t0.9\trc \ngone-tool\tamd64\t\tun \nheld-tool\tamd64\t2.0\thi \n"
        found = verify(payload, self.apt_reads(before, settled))
        self.assertEqual((found["result"], found["verified_postcondition"], found["installed_version"]), ("updated", True, "1.22.6"))
        for name, after in (("the error flag", settled.replace("1.0\tii ", "1.0\tiiR")), ("half configured", settled.replace("1.0\tii ", "1.0\tiF ")),
                            ("trigger pending", settled.replace("1.0\tii ", "1.0\tit ")), ("unpacked", settled.replace("1.0\tii ", "1.0\tiU ")),
                            ("an unread line", settled + "strange line\n"), ("dpkg missing", settled.replace("dpkg\tamd64\t1.22.6\tii \n", "")),
                            ("an empty read", ""), ("dpkg itself broken", settled.replace("1.22.6\tii ", "1.22.6\tiF "))):
            with self.subTest(case=name):
                found = verify(payload, self.apt_reads(before, after))
                self.assertEqual((found["result"], found["verified_postcondition"]), ("did_not_update", False))
                self.assertEqual(package_registry.route_result({"run_kind": "terminal"}, {"class": "success"}, found),
                                 {"result": "could_not_check", "verified_postcondition": False})

    def test_brew_and_dnf_postconditions_need_a_known_installed_version(self):
        info = lambda **versions: json.dumps({"formulae": [{"name": name, "tap": "homebrew/core", "installed": [{"version": version}] if version else []}
                                                           for name, version in versions.items()], "casks": []}).encode()
        brew = lambda after, deps=(): package_registry.BREW["verify"](
            {"id": "example-tool", "version": "2.0", "operation": "upgrade", "dependencies": list(deps), "preflight": {"kind": "formula"}},
            {"before": {"brew.info": {"ok": True, "stdout": info(**{"example-tool": "1.0", "example-dep": "1.0"})}}, "after": {"brew.info": {"ok": True, "stdout": after}}})
        for name, after, deps, result, verified in (("at the target", {"example-tool": "2.0", "example-dep": "1.0"}, (), "updated", True),
                                                    ("not moved", {"example-tool": "1.0", "example-dep": "1.0"}, (), "did_not_update", True),
                                                    ("no installed version", {"example-tool": None, "example-dep": "1.0"}, (), "did_not_update", False),
                                                    ("a planned package without one", {"example-tool": "2.0", "example-dep": None}, ("example-dep@2.0",), "updated", False)):
            with self.subTest(route="brew", case=name):
                found = brew(info(**after), deps)
                self.assertEqual((found["result"], found["verified_postcondition"]), (result, verified))
        # A versioned formula is one name: "python@3.12" at 3.12.4 is the dependency "python@3.12@3.12.4".
        versioned = package_registry.BREW["verify"](
            {"id": "example-tool", "version": "2.0", "operation": "upgrade", "dependencies": ["python@3.12@3.12.4"], "preflight": {"kind": "formula"}},
            {"before": {"brew.info": {"ok": True, "stdout": info(**{"example-tool": "1.0", "python@3.12": "3.12.3"})}},
             "after": {"brew.info": {"ok": True, "stdout": info(**{"example-tool": "2.0", "python@3.12": "3.12.4"})}}})
        self.assertEqual((versioned["result"], versioned["verified_postcondition"]), ("updated", True))
        rpm = lambda *rows: "".join(f"{name} 0:{version}.x86_64\n" for name, version in rows).encode()
        target = "example-tool-0:2.0-1.fc41.x86_64"
        dnf = lambda after, deps=(): package_registry.DNF["verify"](
            {"id": "example-tool", "version": target, "operation": "upgrade", "dependencies": list(deps), "preflight": {}},
            {"before": {"dnf.all_installed": {"ok": True, "stdout": rpm(("example-tool", "1.0-1.fc41"))}}, "after": {"dnf.all_installed": {"ok": True, "stdout": after}}})
        for name, after, deps, result, verified in (("at the target", rpm(("example-tool", "2.0-1.fc41")), (), "updated", True),
                                                    ("not moved", rpm(("example-tool", "1.0-1.fc41")), (), "did_not_update", True),
                                                    ("a planned package missing", rpm(("example-tool", "2.0-1.fc41")), ("example-dep.x86_64@1.0-1/updates",),
                                                     "updated", False),
                                                    ("a planned package there", rpm(("example-tool", "2.0-1.fc41"), ("example-dep", "1.0-1")),
                                                     ("example-dep.x86_64@1.0-1/updates",), "updated", True),
                                                    ("a planned package at another version", rpm(("example-tool", "2.0-1.fc41"), ("example-dep", "1.0-2")),
                                                     ("example-dep.x86_64@1.0-1/updates",), "updated", False)):
            with self.subTest(route="dnf", case=name):
                found = dnf(after, deps)
                self.assertEqual((found["result"], found["verified_postcondition"]), (result, verified))

    def test_the_reboot_file_is_named_by_its_source_id(self):
        probe = {"files": {"/run/reboot-required": True}}
        self.assertEqual(package_registry.restart_signal(package_registry.APT, probe), ("required", "linux.reboot_required"))
        self.assertEqual(pc_records.identifier("linux.reboot_required"), "linux.reboot_required")
        self.assertEqual(package_registry.restart_signal(package_registry.APT, {"files": {"/run/reboot-required": False}}), ("unknown", None))
        # A file that stood before the run was pending already, so this step does not wait for it; one that came with the run does.
        now, reboot = {"/run/reboot-required": True}, "/run/reboot-required"
        self.assertEqual(package_registry.restart_signal(package_registry.APT, {"files": now, "files_before": {reboot: True}}), ("unknown", None))
        self.assertEqual(package_registry.restart_signal(package_registry.APT, {"files": now, "files_before": {reboot: False}}), ("required", "linux.reboot_required"))
        self.assertEqual(package_registry.restart_signal(package_registry.APT, {"files": now, "files_before": {reboot: None}}), ("required", "linux.reboot_required"))
        # A file that could not be read is no "absent": only a required restart stands beside it.
        probe = fake_route(restart_files={reboot: "linux.reboot_required"}, restart_probe="apt.needrestart", restart=lambda found: "none")
        self.assertEqual(package_registry.restart_signal(probe, {"files": {reboot: None}, "after": {"apt.needrestart": {}}}), ("unknown", None))
        self.assertEqual(package_registry.restart_signal(probe, {"files": {reboot: False}, "after": {"apt.needrestart": {}}}), ("none", "apt.needrestart"))
        required = fake_route(restart_files={reboot: "linux.reboot_required"}, restart_probe="apt.needrestart", restart=lambda found: "required")
        self.assertEqual(package_registry.restart_signal(required, {"files": {reboot: None}, "after": {"apt.needrestart": {}}}), ("required", "apt.needrestart"))
        for route in package_registry.DESCRIPTORS.values():
            for source in route["run"].get("restart_files", {}).values():
                pc_records.identifier(source)

    def test_held_repairs_name_their_reason(self):
        for name, code in (("dism", "repair-held-dism"), ("sfc", "repair-guidance-only"), ("winget_repair", "repair-guidance-only")):
            with self.subTest(route=name):
                holds(self, code, package_registry.descriptor, name)
        self.assertFalse(set(package_registry.HELD) & set(package_registry.DESCRIPTORS))

    def test_core_verification_requires_the_planned_version(self):
        payload = {"id": "Contoso.NoteTaker", "version": "3.4.1", "operation": "upgrade", "dependencies": [], "preflight": {}}
        winget = package_registry.WINGET["verify"]
        after = {"after": {"winget.installed": {"ok": True, "stdout": fixture("winget-installed-after.txt")}}}
        self.assertEqual(winget(payload, after)["result"], "updated")
        for installed in (fixture("winget-installed-before.txt"), fixture("winget-installed-after.txt").replace(b"3.4.1", b"3.5.0")):
            found = winget(payload, {"after": {"winget.installed": {"ok": True, "stdout": installed}}})
            self.assertEqual((found["result"], found["verified_postcondition"]), ("did_not_update", True))
        self.assertEqual(winget(payload, {"after": {}})["result"], "could_not_check")
        line = "example-tool\tamd64\t{}\tii \n"
        apt_payload = {"id": "example-tool", "version": "1.2.3-1", "operation": "upgrade", "dependencies": [], "preflight": {}}
        reads = lambda before, after: {"before": {"apt.installed": {"ok": True, "stdout": line.format(before).encode()}},
                                       "after": {"apt.installed": {"ok": True, "stdout": line.format(after).encode()}}}
        self.assertEqual(package_registry.APT["verify"](apt_payload, reads("1.2.2-1", "1.2.3-1"))["result"], "updated")
        self.assertEqual(package_registry.APT["verify"](apt_payload, reads("1.2.2-1", "1.2.4-1"))["result"], "did_not_update")
        half = {"before": reads("1.2.2-1", "1.2.3-1")["before"], "after": {"apt.installed": {"ok": True, "stdout": b"example-tool\tamd64\t1.2.3-1\tiF \n"}}}
        self.assertEqual(package_registry.APT["verify"](apt_payload, half)["verified_postcondition"], False)
        other = {"before": reads("1.2.2-1", "1.2.3-1")["before"], "after": {"apt.installed": {"ok": True, "stdout": (line.format("1.2.3-1") + "other-tool\tamd64\t2.0\tii \n").encode()}}}
        self.assertEqual(package_registry.APT["verify"](apt_payload, other)["result"], "differs_from_plan")

    def test_apt_sources_read_into_exact_keys(self):
        # sources.list (when present) and sources.list.d/<name>, each the bytes or None when unreadable: exactly what
        # package_apt.apt_sources reads.
        files = {"/etc/apt/sources.list": b"deb http://deb.example.invalid/ stable main\n", "/etc/apt/sources.list.d/a.list": b"",
                 "/etc/apt/sources.list.d/b.sources": None}
        folders = {"/etc/apt": ["apt.conf.d", "sources.list", "sources.list.d"], "/etc/apt/sources.list.d": ["b.sources", "a.list", "README"]}
        run = SimpleNamespace(read_file=files.get, list_names=folders.get)
        found = package_registry.apt_source_files(run)
        self.assertEqual(found, {"sources.list": files["/etc/apt/sources.list"], "sources.list.d/a.list": b"", "sources.list.d/README": None,
                                 "sources.list.d/b.sources": None})
        folders["/etc/apt"] = ["sources.list.d"]
        self.assertNotIn("sources.list", package_registry.apt_source_files(run))
        for gone in ("/etc/apt", "/etc/apt/sources.list.d"):
            with self.subTest(gone=gone):
                broken = dict(folders, **{gone: None}, **({"/etc/apt": ["sources.list.d"]} if gone != "/etc/apt" else {}))
                holds(self, "apt-sources-unreadable", package_registry.apt_source_files, SimpleNamespace(read_file=files.get, list_names=broken.get))

    def test_tool_catalog_matches_route_table(self):
        catalog = pc_records.decode_strict((ROOT / "templates" / "tool-catalog.json").read_bytes())
        self.assertIs(pc_records.require_container(catalog, "tool_catalog"), catalog)
        self.assertEqual([key for key in catalog if "version" in key], ["schema_version"])
        self.assertNotIn("ledger", json.dumps(catalog).lower())
        tools = {tool["id"]: tool for tool in catalog["tools"]}
        routes_of = {"winget": "winget", "homebrew": "brew", "linux-apt": "apt", "linux-dnf": "dnf"}
        self.assertEqual(sorted(routes_of.values()), sorted(routes.MANAGERS))
        platforms = {"windows": "windows", "darwin": "macos", "linux": "linux"}
        for tool_id, manager in routes_of.items():
            with self.subTest(manager=manager):
                route = package_registry.descriptor(manager)
                self.assertLessEqual({platforms[name] for name in route["platforms"]}, set(tools[tool_id]["supported_os"]))
                self.assertNotIn("handoff", json.dumps(tools[tool_id]))
        self.assertFalse({"windows-msiexec-local", "macos-installer-local", "linux-dpkg-local"} & set(tools))
        self.assertFalse(any(word in json.dumps(catalog) for word in ("msiexec.install", "installer.pkg", "install_local")))
        cited = {source for tool in catalog["tools"] for source in tool["source_ids"]}
        self.assertEqual({source["id"] for source in catalog["sources"]}, cited)


class PackageEngineFixture(SessionFixtures):
    """Package actions through the real engine and service: the steps every engine test here and in test_service_updates shares.
    It defines no test."""

    def prepared(self, route, items, *, sid=None, adapter_id=None):
        sid = sid or self.session(job="security_updates", platform="linux")
        self.service.elevation_probe = lambda: False
        self.route = route
        with registered(route):
            actions = self.service.prepare_package_action(sid, adapter_id=adapter_id or UPGRADE, items=items, probe=RunProbe(), launcher=FakeLauncher(),
                                                          **PROSE)
        return sid, actions

    def registered_plan(self, sid, actions):
        required = {"scope": ("scope_confirmation", {"scope_confirmed": True}), "inventory": ("inventory", {"complete": True, "item_count": 1}),
                    "research": ("research", {"applicability_checked": True, "official_sources_checked": True}),
                    "candidates": ("candidates", {"candidates_reviewed": True, "excluded_private": True})}
        while self.state(sid)["stage"] != "plan":
            kind, facts = required[self.state(sid)["stage"]]
            self.engine.advance_stage(sid, evidence_ids=[self.evidence(kind, facts, sid=sid)])
        plan = {"plan_id": "plan-" + uuid.uuid4().hex, "summary": "Exact synthetic package plan",
                "evidence_ids": [actions[0]["target_inventory_evidence_id"]], "actions": actions}
        return self.engine.register_plan(sid, plan=plan)["data"]["plan_sha256"]

    def approved(self, sid, actions, sha, *, advance=True):
        for reviewer, role in (("fixture-reviewer-data", "compatibility_data"), ("fixture-reviewer-security", "evidence_security")):
            review = {"schema": "patchcairn.review", "schema_version": 1, "plan_sha256": sha, "role": role, "verdict": "approved",
                      "reviewer_id": reviewer, "attestation": "coordinator-attested"}
            self.engine.record_review(sid, plan_sha256=sha, reviewer_id=reviewer, role=role, verdict="approved",
                                      evidence_ids=[self.evidence("review", {"reviewed": True}, sid=sid, content=pc_records.encoded(review))],
                                      notes="Independent synthetic review of this exact bounded plan")
        self.engine.approve_plan(sid, plan_sha256=sha, action_ids=[action["action_id"] for action in actions],
                                 owner_quote="Apply only these exact synthetic package actions.", owner_message_id="fixture-package-" + uuid.uuid4().hex)
        if advance:
            self.engine.advance_stage(sid, evidence_ids=[])
        return sha

    def ticket(self, sid, action, sha):
        with registered(self.route):
            return self.service.execute_action(sid, action_id=action["action_id"], plan_sha256=sha,
                                               precondition_evidence_ids=[self.precondition(action, sha, sid=sid)])

    def launched(self, route, issued, child=None, probe=None, reader=None):
        with registered(route):
            return self.service.run_ticket(ticket_id=issued["ticket_id"], launcher=child or FakeChild(), probe=probe or RunProbe(), reader=reader or FakeLauncher(),
                                           terminal=FakeTerminal())

    def ticketed(self, route):
        """One approved action of ``route`` with its ticket: (session id, the ticket response)."""
        sid, actions = self.prepared(route, [{"action_id": "update-tool", "manager": "pip", "id": "example-tool"}])
        return sid, self.ticket(sid, actions[0], self.approved(sid, actions, self.registered_plan(sid, actions)))

    def operation(self, sid, issued):
        return self.state(sid)["operations"][issued["operation_id"]]

    def reconciled(self, route, sid, issued):
        """reconcile_operation with a practice session's fakes: a fictional computer, and every read a fake that prints nothing."""
        with registered(route), mock.patch.object(readonly_runner, "run_recipe", return_value={"ok": True, "stdout": b"", "exit_code": 0}):
            return self.service.reconcile_operation(sid, operation_id=issued["operation_id"], probe=RunProbe(), reader=FakeLauncher())

    @staticmethod
    def boot():
        return RunProbe(boot={"last_boot_utc": utc_now(), "boot_id": "boot-after", "source": "fictional_probe"})

    def needing_restart(self):
        """An approved action whose run left a required restart: (route, session id, ticket response)."""
        route = fake_route(restart_probe="apt.needrestart", restart=lambda found: "required")
        sid, issued = self.ticketed(route)
        self.assertIsNone(self.launched(route, issued)["outcome"])
        return route, sid, issued

    def payload_of(self, sid, action):
        row = self.state(sid)["evidence"][action["adapter_payload_evidence_id"]]
        return json.loads((self.engine.work / sid / row["path"]).read_bytes())


@refusals_fail
class PackageEngineTests(PackageEngineFixture):
    """Package actions through the real engine and service: the package payload binding, the batch rule, the conditional
    decisions, the shown-command field of the plan validator and the action builder, and the service's elevation probe."""

    def test_payload_builder_matches_golden_contract(self):
        golden = json.loads((ROOT / "tests" / "fixtures" / "package-payload.json").read_text(encoding="utf-8"))
        self.assertEqual(len(golden["variants"]), 4)
        derived = ("schema", "schema_version", "transaction_sha256", "environment_sha256")
        for variant in golden["variants"]:
            with self.subTest(variant=variant["name"]):
                fields = {key: value for key, value in variant["payload"].items() if key not in derived}
                built = package_registry.payload(fields, environment=variant.get("inputs", {}).get("environment"))
                self.assertEqual(pc_records.encoded(built).decode("ascii"), variant["encoded"])
                self.assertEqual(pc_records.digest(built), variant["sha256"])
                self.assertEqual(built["transaction_sha256"], pc_records.digest(fields["preflight"]))
        process = {key: value for key, value in golden["variants"][0]["payload"].items() if key not in derived}
        settings = {key: value for key, value in golden["variants"][2]["payload"].items() if key not in derived}
        environment = golden["variants"][0]["inputs"]["environment"]
        for name, fields, keywords in (("unknown key", {**process, "command": "anything"}, {"environment": environment}),
                                       ("settings with recipe", {**settings, "recipe": "winget.upgrade"}, {}),
                                       ("settings with environment", settings, {"environment": environment}),
                                       ("process with settings_page", {**process, "settings_page": "windowsupdate"}, {"environment": environment}),
                                       ("process without environment", process, {}),
                                       ("process without executable", {k: v for k, v in process.items() if k != "executable"}, {"environment": environment}),
                                       ("manager outside the registry", {**process, "manager": "chocolatey"}, {"environment": environment}),
                                       ("operation", {**process, "operation": "uninstall"}, {"environment": environment})):
            with self.subTest(refused=name):
                holds(self, "package-payload", package_registry.payload, fields, **keywords)

    def test_local_installer_handoffs_removed(self):
        # The service half, the engine half and the registry entries together.
        import service_execute
        import service_reconcile
        import service_updates
        import workflow_core
        from workflow_service import WorkflowService
        for name in ("prepare_external_action", "record_external_preflight", "complete_external", "complete_external_after_restart",
                     "_external_sources", "_external_preflight", "_artifact", "_external_receipt", "_record_restart_pending", "_restart_boot",
                     "ARTIFACT_EXTENSIONS", "OFFICIAL_DOMAINS"):
            self.assertFalse(hasattr(service_updates, name) or hasattr(WorkflowService, name), name)
        for name in ("validate_external_plan", "external_preflight", "record_protected_consent", "decide_restart", "record_restart_verification"):
            self.assertFalse(hasattr(workflow_core.WorkflowEngine, name), name)
        self.assertNotIn("system.reviewed_external", pc_records.ADAPTERS)
        self.assertNotIn("system.reviewed_external", service_execute.EXECUTE)
        self.assertNotIn("system.reviewed_external", service_reconcile.RECONCILE)
        retired = {name for name in pc_records.SCHEMAS if name.startswith("patchcairn.external.")}
        retired |= {"patchcairn.installer.metadata", "patchcairn.publisher.signature", "patchcairn.windows.boot.observation"} & pc_records.SCHEMAS
        self.assertEqual(retired, set())
        catalog = (ROOT / "templates" / "tool-catalog.json").read_text(encoding="utf-8")
        self.assertNotIn("msiexec.install", catalog)

    def test_action_binds_the_reviewed_transaction_of_its_preflight(self):
        # The package route's half of test_action_binds_the_lower_level_plan_each_caller_names: the action's adapter_plan_sha256
        # is the hash of the preflight inside its payload, which the engine's binding compares with transaction_sha256.
        sid, actions = self.prepared(fake_route(), [{"action_id": "update-tool", "manager": "pip", "id": "example-tool"}])
        row = self.state(sid)["evidence"][actions[0]["adapter_payload_evidence_id"]]
        payload = json.loads((self.engine.work / sid / row["path"]).read_bytes())
        self.assertEqual(actions[0]["adapter_plan_sha256"], pc_records.digest(payload["preflight"]))
        self.assertEqual(actions[0]["adapter_plan_sha256"], payload["transaction_sha256"])

    def test_update_runs_only_after_reviews_approval_and_ticket(self):
        route = fake_route()
        sid, actions = self.prepared(route, [{"action_id": "update-tool", "manager": "pip", "id": "example-tool"}])
        sha = self.registered_plan(sid, actions)
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.ticket(sid, actions[0], sha)
        self.assertEqual(self.state(sid)["operations"], {})
        with self.assertRaises((ServiceRefusal, WorkflowRefusal, OSError)):
            self.service.run_ticket(ticket_id="ticket-" + "0" * 32, launcher=FakeChild(), probe=RunProbe(), reader=FakeLauncher(), terminal=FakeTerminal())
        self.approved(sid, actions, sha)
        issued = self.ticket(sid, actions[0], sha)
        self.assertIsNone(self.state(sid)["operations"][issued["operation_id"]]["outcome"])
        child = FakeChild()
        result = self.launched(route, issued, child)
        self.assertEqual((result["outcome"], result["receipt"]["result"], len(child.calls)), ("succeeded", "updated", 1))
        self.assertEqual(child.calls[0].argv[0], SUDO)
        with self.assertRaises(ServiceRefusal):
            self.launched(route, issued, child)
        self.assertEqual(len(child.calls), 1)

    def test_drift_between_plan_and_run_holds(self):
        # The winget route reads the item again right before the run; any change of the bound preflight holds.
        route = package_registry.WINGET
        candidate = route["run"]["preflight"](None, winget_run(fixture("winget-installed-before.txt")), {"id": "Contoso.NoteTaker"}, "upgrade")
        fragment = route["plan"](candidate, {"operation": "upgrade", "executable": {"kind": "winget", "path": WINGET, "identity": {"package": APP_FOLDER}},
                                             "agreements": []})
        payload = package_registry.payload(fragment, environment={"fictional": True})
        self.assertIsNone(route["drift"](None, winget_run(fixture("winget-installed-before.txt")), payload))
        newer = fixture("winget-installed-before.txt").replace(b"3.4.1", b"3.4.2")
        changed = {"newer offer": winget_run(newer), "client": winget_run(fixture("winget-installed-before.txt"), client=winget_version("1.12.400\n").encode()),
                   "no longer offered": winget_run(fixture("winget-installed-after.txt"))}
        for name, run in changed.items():
            with self.subTest(change=name):
                held = route["drift"](None, run, payload)
                self.assertIsInstance(held, dict)
                self.assertIn(held["hold"], ("package-drift", "winget-confirm"))
        # Through the launcher: a drift starts nothing and writes no effect boundary.
        from test_service_updates import harness
        made = harness(fake_route(drift={"hold": "package-drift", "message": "The item changed"}))
        ticket = made.issue()["ticket_id"]
        child = FakeChild()
        with self.assertRaises(ServiceRefusal):
            made.run(ticket, child=child)
        self.assertEqual((child.calls, made.entered(), made.finished), ([], False, []))

    def test_failed_item_stops_only_its_dependents(self):
        route = fake_route(results={"tool-a": "did_not_update"}, dependencies={"tool-b": ["tool-a@1.0.0"]})
        sid, actions = self.prepared(route, [{"action_id": "a", "manager": "pip", "id": "tool-a"}, {"action_id": "b", "manager": "pip", "id": "tool-b"},
                                             {"action_id": "c", "manager": "pip", "id": "tool-c"}])
        sha = self.approved(sid, actions, self.registered_plan(sid, actions))
        by_id = {action["action_id"]: action for action in actions}
        first = self.launched(route, self.ticket(sid, by_id["a"], sha))
        self.assertEqual((first["outcome"], first["receipt"]["result"], first["receipt"]["verified_postcondition"]), ("failed", "did_not_update", True))
        self.assertEqual(self.state(sid)["status"], "active")
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.ticket(sid, by_id["b"], sha)
        third = self.launched(route, self.ticket(sid, by_id["c"], sha))
        self.assertEqual(third["outcome"], "succeeded")

    def test_unknown_outcome_stops_the_batch(self):
        route = fake_route(results={"tool-a": "unknown"}, dependencies={})
        sid, actions = self.prepared(route, [{"action_id": "a", "manager": "pip", "id": "tool-a"}, {"action_id": "c", "manager": "pip", "id": "tool-c"}])
        sha = self.approved(sid, actions, self.registered_plan(sid, actions))
        first = self.launched(route, self.ticket(sid, actions[0], sha))
        self.assertEqual(first["outcome"], "unknown")
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.ticket(sid, actions[1], sha)
        self.assertEqual(len(self.state(sid)["operations"]), 1)

    def test_runtime_line_change_needs_its_own_decision(self):
        route = fake_route(item_flags={"runtime": ["runtime_line_change"]})
        sid, actions = self.prepared(route, [{"action_id": "runtime", "manager": "pip", "id": "runtime"}])
        self.assertEqual(self.payload_of(sid, actions[0])["conditional"], {"runtime_line_change": []})
        sha = self.approved(sid, actions, self.registered_plan(sid, actions), advance=False)
        # The plan's approval does not cover it: the apply stage waits for the decision of its own.
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.engine.advance_stage(sid, evidence_ids=[])
        self.engine.record_conditional_decision(sid, action_id="runtime", decision="runtime_line_change", names=[],
                                                owner_quote="Move this fictional runtime to its new line.", owner_message_id="fixture-line-" + uuid.uuid4().hex)
        self.engine.advance_stage(sid, evidence_ids=[])
        self.assertEqual(self.launched(route, self.ticket(sid, actions[0], sha))["outcome"], "succeeded")

    def test_install_scripts_need_their_own_decision(self):
        route = fake_route(item_flags={"tool": ["install_scripts"]}, scripts={"tool": ["example-tool@1.0.0"]})
        sid, actions = self.prepared(route, [{"action_id": "tool", "manager": "pip", "id": "tool"}])
        self.assertEqual(self.payload_of(sid, actions[0])["conditional"], {"run_install_scripts": ["example-tool@1.0.0"]})
        sha = self.approved(sid, actions, self.registered_plan(sid, actions), advance=False)
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.engine.record_conditional_decision(sid, action_id="tool", decision="run_install_scripts", names=["other-tool@1.0.0"],
                                                    owner_quote="Let these fictional scripts run.", owner_message_id="fixture-scripts-" + uuid.uuid4().hex)
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.engine.advance_stage(sid, evidence_ids=[])
        self.engine.record_conditional_decision(sid, action_id="tool", decision="run_install_scripts", names=["example-tool@1.0.0"],
                                                owner_quote="Let these fictional scripts run.", owner_message_id="fixture-scripts-" + uuid.uuid4().hex)
        self.engine.advance_stage(sid, evidence_ids=[])
        self.assertEqual(self.launched(route, self.ticket(sid, actions[0], sha))["outcome"], "succeeded")

    def assert_held_for_a_check(self, route):
        sid, issued = self.ticketed(route)
        result = self.launched(route, issued)
        self.assertEqual((result["outcome"], result["receipt"]["result"], result["receipt"]["verified_postcondition"]), ("failed", "could_not_check", False))
        self.assertEqual((self.state(sid)["status"], self.operation(sid, issued)["resolution"]), ("held", None))
        self.assertEqual(self.state(sid)["evidence"][result["evidence_id"]]["facts"]["result"], "could_not_check")

    def test_a_false_postcondition_is_held_through_the_engine(self):
        self.assert_held_for_a_check(fake_route(verified=False))

    def test_an_unverified_failure_is_no_verified_failure_through_the_engine(self):
        self.assert_held_for_a_check(fake_route(verified=False, result="did_not_update"))

    def test_a_terminal_failure_holds_the_session_through_the_engine(self):
        # apt exit 100 in a terminal: the text that would show an integrity failure went to the person, so nothing may continue.
        route = fake_route(classify=package_registry.APT["classify_exit"], result="did_not_update", restart_probe="apt.needrestart", restart=lambda found: "required")
        sid, issued = self.ticketed(route)
        result = self.launched(route, issued, FakeChild(code=100))
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("failed", "could_not_check"))
        operation = self.operation(sid, issued)
        self.assertEqual((self.state(sid)["status"], operation["resolution"], operation.get("restart_pending")), ("held", None, None))

    def test_an_interrupted_run_stays_unknown_through_the_engine(self):
        route = fake_route(result="updated")
        sid, issued = self.ticketed(route)
        with self.assertRaises(KeyboardInterrupt):
            self.launched(route, issued, FakeChild(error=KeyboardInterrupt()))
        result = self.reconciled(route, sid, issued)
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("unknown", "unknown"))
        self.assertEqual((self.operation(sid, issued)["outcome"], self.state(sid)["status"]), ("unknown", "held"))
        self.assertEqual(self.reconciled(route, sid, issued)["held"], True)
        self.assertEqual(self.operation(sid, issued)["outcome"], "unknown")

    def test_a_recorded_exit_reconciles_through_the_engine(self):
        route = fake_route(result="updated")
        sid, issued = self.ticketed(route)
        with mock.patch.object(self.service, "_complete", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.launched(route, issued)
        result = self.reconciled(route, sid, issued)
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("succeeded", "updated"))
        self.assertEqual(self.operation(sid, issued)["outcome"], "succeeded")
        # The unknown of a run cut off after its exit closes in reconciliation too.
        sid, issued = self.ticketed(fake_route(result="updated"))
        with mock.patch.object(self.service, "_complete", side_effect=ValueError("cut off")):
            self.assertEqual(self.launched(route, issued)["outcome"], "unknown")
        self.reconciled(route, sid, issued)
        self.assertEqual(self.operation(sid, issued)["outcome"], "succeeded")

    def test_a_pause_during_the_checks_starts_nothing_through_the_engine(self):
        route = fake_route()
        sid, issued = self.ticketed(route)
        pausing = MappingProxyType({**route, "drift": lambda probe, run, payload: self.engine.pause(sid) and None})
        child = FakeChild()
        result = self.launched(pausing, issued, child)
        self.assertEqual((child.calls, result["outcome"], result["receipt"]["adapter_invoked"]), ([], "failed", False))
        self.assertEqual(self.state(sid)["status"], "paused")
        self.assertEqual((result["receipt"]["result"], result["receipt"]["reason"]), ("not_run", "owner_paused_or_stopped"))

    def test_the_reboot_file_enters_the_restart_class_through_the_engine(self):
        route = fake_route(restart_files=dict(package_registry.APT["run"]["restart_files"]))
        sid, issued = self.ticketed(route)
        probe = RunProbe()
        def child(argv, **keywords):
            probe.files["/run/reboot-required"] = regular()
            return 0, b""
        result = self.launched(route, issued, child, probe=probe)
        self.assertEqual((result["outcome"], result["receipt"]["result"]), (None, "restart_needed"))
        self.assertEqual(self.operation(sid, issued)["restart_pending"], {"signal": "required", "source": "linux.reboot_required"})
        self.assertIsNone(self.operation(sid, issued)["outcome"])

    def test_a_boot_recorded_before_an_interruption_is_reused_through_the_engine(self):
        route, sid, issued = self.needing_restart()
        with mock.patch.object(self.service, "_complete", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.launched(route, issued, probe=self.boot())
        recorded = self.operation(sid, issued)["restart_verification"]
        self.assertIs(recorded["boot_observed"], True)
        self.assertIsNone(self.operation(sid, issued)["outcome"])
        # The probe of the next run cannot read a boot at all: the recorded one carries it.
        child = FakeChild()
        result = self.launched(route, issued, child, probe=RunProbe())
        self.assertEqual((child.calls, result["outcome"], result["receipt"]["boot_evidence_id"]), ([], "succeeded", recorded["evidence_id"]))
        self.assertEqual(self.operation(sid, issued)["restart_verification"], recorded)

    def test_reconciliation_recognises_a_recorded_boot_through_the_engine(self):
        route, sid, issued = self.needing_restart()
        with self.assertRaises(ServiceRefusal) as caught:
            self.reconciled(route, sid, issued)
        self.assertEqual(caught.exception.code, "package-restart-class")
        with mock.patch.object(self.service, "_complete", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.launched(route, issued, probe=self.boot())
        result = self.reconciled(route, sid, issued)
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("succeeded", "updated"))
        self.assertEqual(self.operation(sid, issued)["outcome"], "succeeded")

    def test_the_check_after_a_restart_has_no_time_limit_but_a_new_launch_has(self):
        def later(hours):
            real = pc_records.utc_now
            def shifted():
                value = datetime.fromisoformat(real().replace("Z", "+00:00")) + timedelta(hours=hours)
                return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            return mock.patch("pc_records.utc_now", side_effect=shifted)
        route, sid, issued = self.needing_restart()
        with later(30):
            child = FakeChild()
            result = self.launched(route, issued, child, probe=self.boot())
        self.assertEqual((child.calls, result["outcome"], result["receipt"]["after_restart"]), ([], "succeeded", True))
        # A ticket that never ran keeps the freshness limit of a new launch.
        route = fake_route()
        sid, issued = self.ticketed(route)
        child = FakeChild()
        with later(30), self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.launched(route, issued, child)
        self.assertEqual(child.calls, [])

    def test_a_pending_restart_records_the_boot_it_ran_in_through_the_engine(self):
        route = fake_route(restart_probe="apt.needrestart", restart=lambda found: "required")
        sid, issued = self.ticketed(route)
        same = {"last_boot_utc": "2026-01-01T00:00:00Z", "boot_id": "boot-before", "source": "fictional_probe"}
        result = self.launched(route, issued, probe=RunProbe(boot=same))
        self.assertEqual(self.state(sid)["evidence"][result["evidence_id"]]["facts"]["boot_id"], "boot-before")
        # The same boot read again is no restart.
        with self.assertRaises(WorkflowRefusal) as caught:
            self.launched(route, issued, probe=RunProbe(boot=same))
        self.assertEqual(caught.exception.code, "no-later-boot")
        self.assertIsNone(self.operation(sid, issued)["outcome"])



def winget_exits(route):
    """``route`` with winget's own exit hooks, so the real classification goes through the real service and engine."""
    return MappingProxyType({**route, "classify_exit": package_registry.WINGET["classify_exit"],
                             "run": MappingProxyType({**route["run"], "exit_restart": package_registry.WINGET["run"]["exit_restart"]})})


class BrewComputer:
    """A fictional Mac: read-only Homebrew commands answer from what is installed, and the run replaces it with ``after``."""

    def __init__(self, after, info=None):
        self.info, self.after, self.started = info or json.loads(fixture("brew-info.json")), after, []

    def __call__(self, argv, *, env, cwd, timeout, max_bytes):
        command = argv[1:]
        if command[0] == "--version":
            return 0, fixture("brew-version.txt")
        if command[0] == "outdated":
            return 0, json.dumps(brew_one("examplefetch", "brew-outdated.json")).encode()
        if command[0] == "upgrade":
            return 0, fixture("brew-dry-run.txt")
        current = self.after if self.started else self.info
        return 0, json.dumps(current if "--installed" in command else
                             {"formulae": [item for item in current["formulae"] if item["name"] == "examplefetch"], "casks": []}).encode()

    def child(self, argv, **keywords):
        self.started.append(argv)
        return 0, b""


@refusals_fail
class RouteThroughTheEngineTests(SessionFixtures):
    """The Homebrew route and winget's exit hooks in a real run: the real service, engine and completion, on a fictional computer."""
    prepared, registered_plan, approved, ticket = PackageEngineTests.prepared, PackageEngineTests.registered_plan, PackageEngineTests.approved, PackageEngineTests.ticket
    launched, ticketed, operation = PackageEngineTests.launched, PackageEngineTests.ticketed, PackageEngineTests.operation
    reconciled, payload_of = PackageEngineTests.reconciled, PackageEngineTests.payload_of

    def brew_run(self, computer):
        """One approved Homebrew update, run to its end: (session id, approved action, the run's result)."""
        sid, probe = self.session(job="security_updates", platform="macos"), RunProbe(platform=MAC)
        self.service.elevation_probe, self.route = lambda: False, package_registry.BREW
        actions = self.service.prepare_package_action(sid, adapter_id=UPGRADE, items=[{"action_id": "update-fetch", "manager": "brew", **FETCH}],
                                                      probe=probe, launcher=computer, **PROSE)
        issued = self.ticket(sid, actions[0], self.approved(sid, actions, self.registered_plan(sid, actions)))
        return sid, actions[0], self.service.run_ticket(ticket_id=issued["ticket_id"], launcher=computer.child, probe=probe, reader=computer, terminal=FakeTerminal())

    @staticmethod
    def after_run(**fetch):
        """What brew info prints after the update: the new versions, the added package, and examplefetch with ``fetch`` on top."""
        after = json.loads(fixture("brew-info-after.json"))
        after["formulae"][0].update(fetch)
        after["formulae"].append({"name": "examplenew", "full_name": "examplenew", "tap": "homebrew/core", "pinned": False, "disabled": False,
                                  "keg_only": False, "linked_keg": "2.0", "installed": [{"version": "2.0", "installed_on_request": False}]})
        return after

    def test_an_old_version_left_linked_is_no_update(self):
        sid, action, result = self.brew_run(BrewComputer(self.after_run()))
        self.assertEqual((result["outcome"], result["receipt"]["result"], result["receipt"]["installed_version"]), ("succeeded", "updated", "1.25.0_2"))
        self.assertIs(result["receipt"]["verified_postcondition"], True)
        self.assertEqual(self.payload_of(sid, action)["flags"], ["adds_packages"])
        for fetch in ({"linked_keg": "1.24.5"}, {"linked_keg": None}):
            with self.subTest(fetch=fetch):
                _sid, _action, result = self.brew_run(BrewComputer(self.after_run(**fetch)))
                self.assertEqual((result["outcome"], result["receipt"]["result"], result["receipt"]["installed_version"]), ("failed", "did_not_update", None))

    def test_an_unlinked_keg_stands_where_the_plan_allows_it(self):
        _sid, _action, result = self.brew_run(BrewComputer(self.after_run(linked_keg=None, keg_only=True)))
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("succeeded", "updated"))
        info = json.loads(fixture("brew-info.json"))
        info["formulae"][0]["linked_keg"] = None
        _sid, _action, result = self.brew_run(BrewComputer(self.after_run(linked_keg=None), info))
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("succeeded", "updated"))

    def waits_for(self, signal, code, tail=b""):
        route = winget_exits(fake_route(run_kind="process"))
        sid, issued = self.ticketed(route)
        result = self.launched(route, issued, FakeChild(code=code, tail=tail))
        self.assertEqual((result["outcome"], result["receipt"]["result"], result["receipt"]["exit"]["restart"]), (None, "restart_needed", signal))
        self.assertEqual(self.operation(sid, issued)["restart_pending"], {"signal": signal, "source": "exit_code"})

    def test_a_restart_the_installer_started_keeps_its_name(self):
        self.waits_for("initiated_by_installer", 0x8A15010B)

    def test_a_restart_from_the_msi_code_keeps_its_name(self):
        self.waits_for("initiated_by_installer", 1641)

    def test_the_restart_sentence_at_exit_zero_waits_for_the_restart(self):
        self.waits_for("required", 0, b"Successfully installed\r\nRestart your PC to finish installation.\r\n")

    def test_a_failed_install_that_needs_a_restart_first_says_so(self):
        route = winget_exits(fake_route(run_kind="process", result="did_not_update"))
        sid, issued = self.ticketed(route)
        result = self.launched(route, issued, FakeChild(code=0x8A15010A))
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("failed", "did_not_update"))
        self.assertEqual(result["receipt"]["restart"], {"signal": "required_before_retry", "source": "exit_code"})
        self.assertFalse(self.operation(sid, issued).get("restart_pending"))

    def test_an_exit_without_a_restart_sentence_leaves_the_restart_unknown(self):
        route = winget_exits(fake_route(run_kind="process"))
        _sid, issued = self.ticketed(route)
        result = self.launched(route, issued, FakeChild(code=0, tail=b"Successfully installed\r\n"))
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("succeeded", "updated"))
        self.assertEqual(result["receipt"]["restart"], {"signal": "unknown", "source": None})

    def record_lost(self, route, child, *, boot_fails=False):
        """A run whose restart signal could not be recorded: the engine refused the record, or the boot could not be read. The
        step closes as unknown; (session id, ticket response)."""
        sid, issued = self.ticketed(route)
        probe = RunProbe()
        if boot_fails:
            probe.boot_identity = mock.Mock(side_effect=OSError("the boot time cannot be read"))
        refusal = None if boot_fails else WorkflowRefusal("Session is locked by another writer")
        with mock.patch.object(self.engine, "record_restart_pending", side_effect=refusal):
            self.assertEqual(self.launched(route, issued, child, probe=probe)["outcome"], "unknown")
        return sid, issued

    def stays_unknown(self, route, child, **keywords):
        sid, issued = self.record_lost(route, child, **keywords)
        result = self.reconciled(route, sid, issued)
        self.assertEqual((result["outcome"], result.get("held")), ("unknown", True))
        self.assertNotIn("receipt", result)
        self.assertEqual(self.operation(sid, issued)["outcome"], "unknown")

    def test_a_probed_restart_survives_a_refused_record(self):
        self.stays_unknown(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"), FakeChild())

    def test_a_probed_restart_survives_an_unreadable_boot(self):
        self.stays_unknown(fake_route(restart_probe="apt.needrestart", restart=lambda found: "required"), FakeChild(), boot_fails=True)

    def test_the_exit_code_restart_survives_a_refused_record(self):
        self.stays_unknown(winget_exits(fake_route(run_kind="process")), FakeChild(code=0x8A15010B))

    def test_the_exit_code_restart_survives_an_unreadable_boot(self):
        self.stays_unknown(winget_exits(fake_route(run_kind="process")), FakeChild(code=0x8A15010B), boot_fails=True)

    def test_a_signal_gone_after_a_failed_record_closes_the_step(self):
        signals = ["required"]
        route = fake_route(restart_probe="apt.needrestart", restart=lambda found: signals[-1])
        sid, issued = self.record_lost(route, FakeChild())
        signals.append("none")
        result = self.reconciled(route, sid, issued)
        self.assertEqual((result["outcome"], result["receipt"]["result"]), ("succeeded", "updated"))

    def test_the_ticket_names_the_shell_of_its_command(self):
        _sid, issued = self.ticketed(fake_route())
        self.assertEqual(issued.get("shell"), "powershell" if os.name == "nt" else "posix")
        self.assertEqual(issued["command"].startswith("& "), issued.get("shell") == "powershell")


if __name__ == "__main__":
    unittest.main()
