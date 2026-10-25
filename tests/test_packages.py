"""Package routes (G09): the winget, Homebrew, apt and dnf5 route classes, on synthetic fixtures and fakes only.

No test starts a package manager. Parsers read tests/fixtures/packages (fictional package ids); executable resolution
and the read-only runner use FakeProbe and FakeLauncher below. The fictional Windows folders and the fictional home
folder are not user-profile paths (D-026).
Run from the repository root: python3 -I -S -B -m unittest discover -s tests -p "test_packages.py"
"""
from __future__ import annotations

import functools
import json
import ntpath
from pathlib import Path, PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import package_apt as apt  # noqa: E402
import package_routes as routes  # noqa: E402
import package_tokens  # noqa: E402
import pc_records  # noqa: E402
import readonly_runner  # noqa: E402
from pc_records import Refusal  # noqa: E402

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
# The documentation allowlist per manager: host and path prefix (assessment #27).
DOC_HOSTS = {"winget": [("learn.microsoft.com", ()), ("github.com", ("microsoft", "winget-cli"))], "brew": [("docs.brew.sh", ())],
             "apt": [("manpages.debian.org", ()), ("manpages.ubuntu.com", ())],
             "dnf": [("dnf.readthedocs.io", ()), ("dnf5.readthedocs.io", ()), ("rpm-software-management.github.io", ())],
             "repair": [("learn.microsoft.com", ()), ("manpages.debian.org", ())]}
# Forbidden rows per manager: one per token of the design's section 3 (patterns such as globs, `<name>/<release>` or
# dpkg `--force-*` are refused by the grammar instead, and winget --name, apt -o and apt-get -s are allowed rows).
# brew has one row fewer than section 3: the legacy JSON format flag is not listed literally, because the frozen G03
# label rule refuses that spelling; render() emits only --json=v2 (D-035).
FORBIDDEN_ROWS = {"winget": 64, "brew": 47, "apt": 27, "dnf": 44, "repair": 5}


def fixture(name):
    return (FIXTURES / name).read_bytes()


# winget --version prints a leading v; the frozen G03 label rule refuses that literal, so tests compose it (D-035).
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


def folder(uid=0, mode=0o755):
    return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid)


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
        done = routes.typed_outcome(routes.classify_exit("winget", 0), after)
        self.assertEqual((done["outcome"], done["other_changes"]), ("succeeded", "not_observed"))
        unchanged = routes.verify_winget(entry, fixture("winget-installed-before.txt"))
        self.assertEqual((unchanged["target_installed"], unchanged["reason"]), (False, "version_differs"))
        outcome = routes.typed_outcome(routes.classify_exit("winget", 0), unchanged)
        self.assertEqual((outcome["outcome"], outcome["reason"]), ("failed", "verification_mismatch"))
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
                 3010: ("restart", "required"), 0: ("success", "none"), 0x8A150123: ("failed", "unknown")}
        for code, expected in cases.items():
            result = routes.classify_exit("winget", code)
            self.assertEqual((result["class"], result["restart"]), expected, hex(code))
            self.assertEqual((result["exit_code"], result["from_probes"]), (code & 0xFFFFFFFF, False))
        pending = routes.typed_outcome(routes.classify_exit("winget", 0x8A150109), {"target_installed": False})
        self.assertEqual((pending["outcome"], pending["verification"], pending["restart"]),
                         ("succeeded_restart_required", "pending_restart", "required"))
        self.assertIn("never restarts the computer", pending["notice"])
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
        nothing = routes.typed_outcome(routes.classify_exit("winget", 0x8A15002B), {"target_installed": False})
        self.assertEqual((nothing["outcome"], nothing["reason"]), ("failed", "not_applicable"))
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
        # Several old versions are comma-separated; packages joined on one line hold instead of hiding a dependency (PD-13).
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
        self.assertEqual(routes.typed_outcome(routes.classify_exit("brew", 0), ok)["outcome"], "succeeded")
        wrong = routes.verify_brew(entry, before, self.info_with(examplefetch="1.25.0_1"))
        self.assertFalse(wrong["target_installed"])
        self.assertEqual(routes.typed_outcome(routes.classify_exit("brew", 0), wrong)["reason"], "verification_mismatch")
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
        result = routes.typed_outcome(routes.classify_exit("brew", 0), outside)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "changed_outside_plan"))

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
        done = routes.typed_outcome(routes.classify_exit("brew", 0), {"target_installed": True})
        self.assertEqual((done["outcome"], done["restart"]), ("succeeded", "none"))
        self.assertEqual(routes.BREW_FIXED["HOMEBREW_NO_UPGRADE_QUIT_CASKS"], "1")
        self.assertEqual(routes.classify_exit("brew", 1, output="Error: SHA256 mismatch")["class"], "integrity_failure")
        self.assertEqual(routes.classify_exit("brew", 1, output="Error: This cask requires sudo")["reason"], "needs_sudo")
        self.assertEqual(routes.classify_exit("brew", 130)["reason"], "interrupted")
        failed = routes.typed_outcome(routes.classify_exit("brew", 1), {"target_installed": True})
        self.assertEqual((failed["outcome"], failed["reason"]), ("failed", "manager_error_target_present"))

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
        self.assertEqual(routes.typed_outcome(routes.classify_exit("apt", 0), ok, restart="none")["outcome"], "succeeded")
        for old, new in ((b"8.5.0-2example2\tii ", b"8.5.0-2example3\tii "), (b"8.5.0-2example2\tii ", b"8.5.0-2example2\tiU ")):
            other = apt.verify_apt(entry, before, fixture("dpkg-installed-after.txt").replace(old, new))
            self.assertFalse(other["target_installed"], new)
        outside = apt.verify_apt(entry, before, fixture("dpkg-installed-after.txt").replace(b"6.8.0-45.45", b"6.8.0-47.47"))
        self.assertEqual(outside["changed_outside_plan"], ["examplekernel:amd64"])
        self.assertEqual(routes.typed_outcome(routes.classify_exit("apt", 0), outside, restart="none")["outcome"], "failed")
        unread = apt.verify_apt(entry, before, fixture("dpkg-installed-after.txt") + b"strange line\n")
        self.assertFalse(unread["diff_complete"])
        self.assertEqual(routes.typed_outcome(routes.classify_exit("apt", 0), unread, restart="none")["other_changes"], "incomplete")

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
        result = routes.typed_outcome(routes.classify_exit("apt", 0), {"target_installed": True}, restart="required")
        self.assertEqual(result["outcome"], "succeeded_restart_required")
        self.assertEqual(routes.typed_outcome(routes.classify_exit("apt", 0), {"target_installed": True})["restart"], "unknown")
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
        for kind, code, output in (("in_use_retry_later", 100, "Could not get lock"), ("integrity_failure", 100, "Hash Sum mismatch")):
            outcome = routes.typed_outcome(routes.classify_exit("apt", code, output=output), {"target_installed": True})
            self.assertEqual(outcome["outcome"], kind)
        unseen = routes.typed_outcome(routes.classify_exit("apt", None), {"target_installed": True}, restart="required")
        self.assertEqual((unseen["outcome"], unseen["restart"]), ("succeeded_restart_required", "required"))
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
                  "dnf.preview": {"nevra": [nevra]}}
        argvs = {rid: routes.render(rid, values.get(rid)) for rid in read_recipes("dnf")}
        # No -C: a normal user's dnf5 refreshes its per-user cache copy from root's cache only when the copy has expired.
        self.assertEqual(argvs["dnf.upgrades"], ("/usr/bin/dnf5", "repoquery", "--upgrades", "--latest-limit=1", package_tokens.QUERYFORMAT))
        self.assertEqual(argvs["dnf.installed"], ("/usr/bin/rpm", "-q", "--qf", package_tokens.RPMFORMAT, "exampletool", "examplelib"))
        self.assertEqual(argvs["dnf.all_installed"], ("/usr/bin/rpm", "-q", "-a", "--qf", package_tokens.RPMFORMAT))
        self.assertEqual(argvs["dnf.repo_config"], ("/usr/bin/dnf5", "--dump-repo-config=updates"))
        self.assertEqual(argvs["dnf.preview"], ("/usr/bin/dnf5", "upgrade", "--assumeno", "--no-allow-downgrade", nevra))
        self.assertFalse(any("-C" in argv for argv in argvs.values()))
        self.assertEqual(argvs["dnf.needs_restarting"], ("/usr/bin/dnf5", "needs-restarting"))
        for argv in argvs.values():
            self.assertNotIn("/usr/bin/sudo", argv)
            self.assertFalse({"makecache", "install", "remove", "reinstall", "-y"} & set(argv), argv)
            self.assertTrue("upgrade" not in argv or "--assumeno" in argv, argv)
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
        entry, before = self.entry(), stored(routes.rpm_installed(fixture("rpm-all-before.txt")))
        ok = routes.verify_dnf(entry, before, fixture("rpm-all-after.txt"))
        self.assertEqual(ok, {"target_installed": True, "changed": ["exampledep.x86_64", "examplelib.x86_64", "exampletool.x86_64"],
                              "changed_outside_plan": [], "diff_complete": True})
        self.assertEqual(ok, routes.verify_dnf(entry, routes.rpm_installed(fixture("rpm-all-before.txt")), fixture("rpm-all-after.txt")))
        wrong = routes.verify_dnf(entry, before, fixture("rpm-all-after.txt").replace(b"8.9.1-3", b"8.9.1-4"))
        self.assertFalse(wrong["target_installed"])
        self.assertEqual(routes.typed_outcome(routes.classify_exit("dnf", 0), wrong)["reason"], "verification_mismatch")
        outside = routes.verify_dnf(entry, before, fixture("rpm-all-after.txt").replace(b"4.0-1.fc41", b"4.0-2.fc41"))
        self.assertEqual(outside["changed_outside_plan"], ["exampleother.noarch"])
        # A package that disappears is never a planned change, even when its name is planned collateral (an obsoleted package).
        with_dep = stored(routes.rpm_installed(fixture("rpm-all-before.txt") + b"exampledep 0:0.9-1.fc41.x86_64\n"))
        gone = routes.verify_dnf(entry, with_dep, fixture("rpm-all-after.txt").replace(b"exampledep 0:1.0-1.fc41.x86_64\n", b""))
        self.assertEqual((gone["target_installed"], gone["changed_outside_plan"]), (True, ["exampledep.x86_64"]))
        result = routes.typed_outcome(routes.classify_exit("dnf", 0), gone)
        self.assertEqual((result["outcome"], result["reason"]), ("failed", "changed_outside_plan"))
        key = routes.verify_dnf(entry, before, fixture("rpm-all-after.txt").replace(b"e99d6ad1-64d2612c", b"0badc0de-65000000"))
        self.assertEqual((key["target_installed"], key["diff_complete"]), (True, False))
        self.assertEqual(routes.typed_outcome(routes.classify_exit("dnf", 0), key)["other_changes"], "incomplete")
        missing = routes.typed_outcome(routes.classify_exit("dnf", None), wrong)
        self.assertEqual((missing["outcome"], missing["reason"]), ("failed", "not_completed"))

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
        result = routes.typed_outcome(routes.classify_exit("dnf", 0), {"target_installed": True}, restart="recommended")
        self.assertEqual((result["outcome"], result["restart"]), ("succeeded", "recommended"))
        self.assertEqual(routes.classify_exit("dnf", 2)["reason"], "route_defect")
        self.assertEqual(routes.classify_exit("dnf", 1)["class"], "failed")
        self.assertFalse({"reboot", "--reboot", "needs-restarting"} & set(routes.run_argv(self.entry())))
        holds(self, "package-restart", routes.typed_outcome, routes.classify_exit("dnf", 0), {"target_installed": True}, restart="soon")

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
        other_repo = fixture("dnf-preview.txt").replace(b"1.0-1.fc41       updates", b"1.0-1.fc41       extras ")
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


if __name__ == "__main__":
    unittest.main()
