"""Package routes for winget, Homebrew, apt and dnf5 (layer L2-pure: standard library, pc_records, package_tokens).

This module starts no process. It holds the closed read-only recipes the read-only runner may run, the run argv
rendered for the coordinator after the ticket (only tokens on an allowed row of package_tokens.TOKENS), parsers that
turn manager output into validated fields (raw manager text never leaves a parser), plan binding, drift,
verification, exit and restart classification and package-list age; the apt parsers, plan and verification are in
package_apt (D-057). A pc_records.Refusal is a hold.
"""
from __future__ import annotations

from datetime import timedelta
import ntpath
from pathlib import PurePosixPath
import re
from types import MappingProxyType

from package_tokens import (ALLOWED, BREW_PATHS, BREW_PREFIXES, DNF5, READ_RECIPES, RUN_FILES, RUN_RECIPES, Slot,
                            WINGET_NO_APPS)
import pc_records
from pc_records import Refusal

MANAGERS = ("winget", "brew", "apt", "dnf")
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
READ_TIMEOUT_SECONDS = 600
STALE_DAYS = 7
MAX_ITEMS = 500
WINGET_TAG = 0x8000001B
WINGET_PACKAGE = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"

# --- grammar of variable tokens (ids, names, versions, specs, NEVRAs, repoids) ----------------------------------------
W_ID = re.compile(r"(?=.{1,128}\Z)[A-Za-z0-9_+][A-Za-z0-9_+-]{0,31}(?:\.[A-Za-z0-9_+-]{1,32}){1,7}")
W_VER = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,127}")
B_NAME = re.compile(r"[a-z0-9][a-z0-9+_.@-]{0,99}")
B_TAP = re.compile(r"homebrew/(?:core|cask)")
B_VER = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+,:~-]{0,127}")
A_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{1,99}(?::[a-z0-9][a-z0-9-]{0,31})?")
A_ARCH = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
A_VER = re.compile(r"(?:[0-9]{1,9}:)?[0-9][A-Za-z0-9.+~:-]{0,126}")
F_NEVRA = re.compile(r"([A-Za-z0-9_+][A-Za-z0-9._+-]*)-([0-9]{1,9}):([A-Za-z0-9._+~]+)-([A-Za-z0-9._+~]+)\.([a-z0-9_]+)")
F_NAME = re.compile(r"[A-Za-z0-9_+][A-Za-z0-9._+-]{0,199}")
F_REPO = re.compile(r"[A-Za-z0-9._:-]{1,100}")
# Characters and sequences that would need quoting in bash, PowerShell or cmd (and in zsh without EXTENDED_GLOB).
_UNSAFE = re.compile(r"[\s'\"`$;&|<>()*?\[\]{}^,%!#\\]|=~|:~")
_ESCAPES = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
# A spec ending in .rpm is a package file to dnf5 (libdnf5 Goal::add_spec); a name ending in .rb, .json or .tar.gz (a bottle) a file to brew.
_FILE_SPECS = MappingProxyType({"nevra": (".rpm",), "rpm_name": (".rpm",), "name": (".rb", ".json", ".tar.gz")})


def apt_version(value):
    """A-VER plus Debian Policy 5.6.12: ':' only after an epoch, '-' only before a non-empty revision."""
    epoch = re.match(r"[0-9]{1,9}:", value)
    upstream, dash, revision = value[epoch.end() if epoch else 0:].rpartition("-")
    return (bool(A_VER.fullmatch(value)) and (epoch is not None or ":" not in value)
            and (not dash or (bool(upstream) and bool(re.fullmatch(r"[A-Za-z0-9+.~]+", revision)))))


def _apt_spec(value):
    package, _, version = value.partition("=")
    return bool(A_PACKAGE.fullmatch(package)) and apt_version(version)


_SLOTS = MappingProxyType({"id": W_ID.fullmatch, "version": W_VER.fullmatch, "name": B_NAME.fullmatch, "package": A_PACKAGE.fullmatch,
                           "target": apt_version, "installed": apt_version, "spec": _apt_spec, "nevra": F_NEVRA.fullmatch,
                           "rpm_name": F_NAME.fullmatch, "repoid": F_REPO.fullmatch})


def needs_quoting(value):
    """True when a token would need quoting in bash, PowerShell or cmd (zsh with EXTENDED_GLOB also treats ~ as a pattern)."""
    return not isinstance(value, str) or not value or not value.isascii() or bool(_UNSAFE.search(value))


def variable(slot, value):
    """A variable token matching its grammar: no leading '-', nothing needing shell quoting, no name a manager reads as a file."""
    check = _SLOTS.get(slot)
    if (check is None or needs_quoting(value) or len(value) > 256 or value.startswith("-") or not check(value)
            or value.lower().endswith(_FILE_SPECS.get(slot, ("\x00",)))):
        raise Refusal("package-token", f"Refused {slot}: the value does not match the route grammar")
    return value


def _valid(slot, value):
    try:
        return variable(slot, value) == value
    except Refusal:
        return False


def _windows_path(value):
    """An absolute local Windows path without control characters, quotes, wildcards, ';' or '..' parts."""
    return (isinstance(value, str) and len(value) <= 1024 and bool(re.fullmatch(r"[A-Za-z]:\\[^\x00-\x1f\"<>|?*;]*", value))
            and ".." not in re.split(r"[\\/]", value))


def _alias_path(path):
    """True for <absolute local folder>\\Microsoft\\WindowsApps\\winget.exe."""
    local = ntpath.dirname(ntpath.dirname(ntpath.dirname(path))) if isinstance(path, str) else None
    return _windows_path(local) and winget_alias_path(local).lower() == path.lower()


def recipe(recipe_id):
    """The read-only or run recipe with this id; anything else is refused."""
    found = (READ_RECIPES.get(recipe_id) or RUN_RECIPES.get(recipe_id)) if isinstance(recipe_id, str) else None
    if found is None:
        raise Refusal("package-recipe", "Not a PatchCairn package recipe")
    return found


def _literal(manager, token):
    if (manager, token) not in ALLOWED:
        raise Refusal("package-token-not-allowed", f"The {manager} route may not emit this token")
    return token


def winget_alias_path(local_appdata):
    """<LocalAppData known folder>\\Microsoft\\WindowsApps\\winget.exe: the App Execution Alias PatchCairn runs."""
    if not _windows_path(local_appdata):
        raise Refusal("winget-alias", "The LocalAppData known folder must be an absolute local path")
    return ntpath.join(local_appdata, "Microsoft", "WindowsApps", "winget.exe")


def _executable(found, executable):
    """argv[0]: the winget alias path, or a fixed path that is an allowed row of the recipe's manager."""
    if found.executable == "winget":
        if not _alias_path(executable):
            raise Refusal("winget-alias", "winget runs only through its App Execution Alias path")
        return executable
    choices = tuple(BREW_PATHS.values()) if found.executable == "brew" else (found.executable,)
    path = executable if executable is not None or found.executable == "brew" else found.executable
    if path not in choices or (found.manager, path) not in ALLOWED:
        raise Refusal("package-executable", "This recipe runs only its fixed executable from the token table")
    return path


def _value(manager, element, value, run_folder):
    if element.flag and (value is None or type(value) is bool):
        return [_literal(manager, element.flag)] if value else []
    if element.choices and value in element.choices:
        return [_literal(manager, value)]
    if (element.name in RUN_FILES and _windows_path(value) and _windows_path(run_folder) and RUN_FILES[element.name].fullmatch(ntpath.basename(value))
            and ntpath.normcase(ntpath.dirname(value)) == ntpath.normcase(ntpath.normpath(run_folder))):
        return [value]
    if element.many and isinstance(value, (list, tuple)) and 0 < len(value) <= MAX_ITEMS:
        return [variable(element.name, item) for item in value]
    if not (element.flag or element.choices or element.many or element.name in RUN_FILES):
        return [f"{_literal(manager, element.joined)}={variable(element.name, value)}" if element.joined else variable(element.name, value)]
    raise Refusal("package-recipe-values", f"Refused {element.name}: not a value this recipe accepts (winget files stay in the run folder)")


def render(recipe_id, values=None, *, executable=None, run_folder=None):
    """argv (a tuple, never a shell string) of a recipe; values are checked, winget's output and log files sit in run_folder."""
    found, values = recipe(recipe_id), dict(values or {})
    if set(values) - {element.name for element in found.template if isinstance(element, Slot)}:
        raise Refusal("package-recipe-values", "This recipe has no such value")
    argv = [_executable(found, executable)]
    for element in found.template:
        argv += [_literal(found.manager, element)] if isinstance(element, str) else _value(found.manager, element, values.get(element.name), run_folder)
    return tuple(argv)


def run_argv(entry, *, executable=None, log_file=None, run_folder=None):
    """The changing argv of a plan entry, using only the executable bound in the plan; winget --accept-* tokens only with consent."""
    manager = entry.get("manager")
    bound = entry["executable"]["path"] if manager == "winget" else entry["preflight"]["brew_path"] if manager == "brew" else None
    if executable is not None and executable != bound:
        raise Refusal("package-executable", "The run uses the executable bound in the plan; the drift check compares it")
    if manager == "winget":
        return render("winget.upgrade", {"id": entry["id"], "version": entry["target_version"], "log_file": log_file,
                                         "package_agreements": entry["agreements"]["package"],
                                         "source_agreements": entry["agreements"]["source"]}, executable=bound, run_folder=run_folder)
    if manager == "brew":
        return render(f"brew.upgrade_{entry['kind']}", {"name": entry["name"]}, executable=bound)
    if manager in ("apt", "dnf"):
        key = "spec" if manager == "apt" else "nevra"
        return render(f"{manager}.upgrade", {key: [item["spec" if manager == "apt" else "target_nevra"] for item in entry["items"]]})
    raise Refusal("package-manager", "Not a package manager PatchCairn routes")


# --- environment, privilege and list age -----------------------------------------------------------------------------
BREW_FIXED = MappingProxyType(dict.fromkeys(("HOMEBREW_NO_AUTO_UPDATE", "HOMEBREW_NO_ASK", "HOMEBREW_NO_INSTALL_CLEANUP",
                                             "HOMEBREW_NO_UPGRADE_QUIT_CASKS", "HOMEBREW_NO_SUDO", "HOMEBREW_NO_ENV_HINTS",
                                             "HOMEBREW_NO_ANALYTICS"), "1"))
POSIX_PATH = MappingProxyType({"brew": "/usr/bin:/bin:/usr/sbin:/sbin", "apt": "/usr/sbin:/usr/bin:/sbin:/bin", "dnf": "/usr/sbin:/usr/bin:/sbin:/bin"})
# winget documents no environment variable. Its commands get the variables Windows programs and installers rely on,
# copied from the interactive user's environment; SystemRoot, windir, ComSpec and PATH come from the system folder.
WINDOWS_NAMES = ("SystemDrive", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramFiles(Arm)", "ProgramW6432", "CommonProgramFiles",
                 "CommonProgramFiles(x86)", "CommonProgramFiles(Arm)", "CommonProgramW6432", "ALLUSERSPROFILE", "PUBLIC", "USERPROFILE",
                 "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "USERNAME", "USERDOMAIN", "COMPUTERNAME",
                 "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS", "PATHEXT")


def environment(manager, *, home=None, user=None, windows=None, system_dir=None):
    """The whole environment of a manager's commands: PATH, HOME (USER, LOGNAME) from the password database, LC_ALL=C
    for apt and dnf, the fixed HOMEBREW_* switches; for winget the WINDOWS_NAMES of ``windows`` plus SystemRoot, windir,
    ComSpec and PATH (the default Windows folders) built from the system folder."""
    if manager == "winget":
        source = {str(key).upper(): value for key, value in (windows or {}).items()}
        if not _windows_path(system_dir):
            raise Refusal("package-environment", "The system folder must be an absolute local path")
        env = {name: source[name.upper()] for name in WINDOWS_NAMES if isinstance(source.get(name.upper()), str) and "\x00" not in source[name.upper()]}
        windows_dir = ntpath.dirname(system_dir.rstrip(ntpath.sep))
        folders = (system_dir, windows_dir, ntpath.join(system_dir, "Wbem"), ntpath.join(system_dir, r"WindowsPowerShell\v1.0"),
                   ntpath.join(system_dir, "OpenSSH"))
        return {**env, "SystemRoot": windows_dir, "windir": windows_dir, "ComSpec": ntpath.join(system_dir, "cmd.exe"), "PATH": ";".join(folders)}
    if manager not in POSIX_PATH or not isinstance(home, str) or not PurePosixPath(home).is_absolute() or any(ord(c) < 32 for c in home):
        raise Refusal("package-environment", "HOME must be the absolute home folder from the password database")
    if manager != "brew":
        return {"PATH": POSIX_PATH[manager], "HOME": home, "LC_ALL": "C"}
    if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", user):
        raise Refusal("package-environment", "USER must be the account name from the password database")
    return {"PATH": POSIX_PATH[manager], "HOME": home, "USER": user, "LOGNAME": user, **BREW_FIXED}


def refuse_elevated(state):
    """Hold every package route while PatchCairn itself runs elevated, as root or as SYSTEM (assessment #49)."""
    if state not in (None, "root", "elevated", "system"):
        raise Refusal("package-elevation", "Unknown elevation state")
    if state is not None:
        raise Refusal("package-elevated", f"PatchCairn is running {state}; package routes run only without elevation, and the "
                      "operating system asks the owner for the one command that needs it")


def list_age(manager, refreshed_utc, *, now_utc=None):
    """Age of the package lists: older than 7 days is "stale; refresh needed"; an unknown age is never current."""
    if manager not in MANAGERS:
        raise Refusal("package-manager", "Not a package manager PatchCairn routes")
    now = pc_records.parse_utc(now_utc if now_utc is not None else pc_records.utc_now())
    refreshed = pc_records.parse_utc(refreshed_utc) if refreshed_utc is not None else None
    if refreshed is None or refreshed > now:
        note = "winget maintains its own source cache" if manager == "winget" else "refresh needed"
        return {"manager": manager, "age_days": None, "status": "unknown", "message": f"package list age unknown; {note}"}
    age = now - refreshed
    if age > timedelta(days=STALE_DAYS):
        return {"manager": manager, "age_days": age.days, "status": "stale", "message": "stale; refresh needed"}
    return {"manager": manager, "age_days": age.days, "status": "recent", "message": f"the newest package list is {age.days} day(s) old"}


# --- shared parsing --------------------------------------------------------------------------------------------------
def text_of(data):
    """Manager output as text: UTF-8 with replacement, terminal escape sequences removed, at most 32 MiB."""
    if isinstance(data, (bytes, bytearray)) and len(data) <= MAX_OUTPUT_BYTES:
        data = bytes(data).decode("utf-8", "replace")
    if not isinstance(data, str) or len(data) > MAX_OUTPUT_BYTES:
        raise Refusal("package-output", "Manager output must be bounded text or bytes")
    return _ESCAPES.sub("", data)


def file_text(data):
    """A config file (or apt-config dump) as text plus the SHA-256 of its raw bytes; control bytes other than tab, CR, LF hold."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_OUTPUT_BYTES or re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", raw):
        raise Refusal("package-config-bytes", "A configuration file holds control characters or is too large; it holds")
    return bytes(raw).decode("utf-8", "replace"), pc_records.digest(bytes(raw))


def _json(data):
    text = text_of(data).strip()
    return pc_records.decode_strict(text[max(text.find("{"), 0):].encode("utf-8"), max_bytes=MAX_OUTPUT_BYTES, max_nodes=4_000_000)


def _list(record, key):
    value = record.get(key) if isinstance(record, dict) else None
    return value if isinstance(value, list) else []


def selected_items(selected):
    if not isinstance(selected, (list, tuple)) or not 0 < len(selected) <= MAX_ITEMS:
        raise Refusal("package-plan", "A plan needs one to 500 selected packages")
    return list(selected)


def installed_state(packages, unrecognised):
    """A storable installed-state snapshot: text keys, and the SHA-256 of each line or entry that could not be read."""
    return {"packages": packages, "unrecognised": sorted(unrecognised)}


def state_changes(before, after, planned, name, skip=(), value=lambda state: state):
    """Changed packages, those outside the plan and collateral (PD-13) or gone, and whether the diff is complete (unread lines equal)."""
    keys = set(before["packages"]) | set(after["packages"])
    changed = sorted(k for k in keys if k not in skip and value(before["packages"].get(k) or {}) != value(after["packages"].get(k) or {}))
    return {"changed": changed, "changed_outside_plan": [k for k in changed if name(k) not in planned or k not in after["packages"]],
            "diff_complete": before["unrecognised"] == after["unrecognised"]}


def drift(planned, observed):
    """Every fact that differs between a plan entry and the same entry rebuilt right before the run; any one holds."""
    changed = []
    for key in sorted(set(planned) | set(observed)):
        before, after = planned.get(key), observed.get(key)
        if key in ("preflight", "transaction") and isinstance(before, dict) and isinstance(after, dict):
            changed += [f"{key}.{name}" for name in sorted(set(before) | set(after)) if before.get(name) != after.get(name)]
        elif before != after:
            changed.append(key)
    return changed


# --- winget ----------------------------------------------------------------------------------------------------------
WINGET_SOURCE = MappingProxyType({"Arg": "https://cdn.winget.microsoft.com/cache", "Identifier": "Microsoft.Winget.Source_8wekyb3d8bbwe",
                                  "Type": "Microsoft.PreIndexed.Package"})
WINGET_FOLDER = re.compile(r"Microsoft\.DesktopAppInstaller_[0-9.]{1,32}_(?:x64|x86|arm64|neutral)__8wekyb3d8bbwe")


def _winget_version(value):
    """W-VER with at least one digit: "Unknown", "< 1.2" and other text hold the row."""
    return _valid("version", value) and any(char.isdigit() for char in value)


def _dash_line(line):
    return len(line.strip()) >= 10 and set(line.strip()) == {"-"}


def _row_like(parts):
    """A line that looks like a winget row: an Id (or a truncated one) followed by a version, or two versions at its end."""
    return (any((first.endswith("\u2026") or _valid("id", first)) and _winget_version(second) for first, second in zip(parts, parts[1:]))
            or (len(parts) >= 4 and _winget_version(parts[-1]) and _winget_version(parts[-2])))


def _winget_table(data):
    """(rows of the main table, rows of every other table, whether a row may have been dropped), or None without a table.
    winget prints no Source column with --source winget (empty columns are not printed). Rows run from an all-dash line to
    the first line whose last token is not a version; a table whose header follows one text line after a blank line
    (explicit targeting or pins) is never main. A table without rows (winget prints no empty table), or a row-like line
    between a table's end and the next blank line, means a row this parser cannot read was dropped."""
    lines, main, later, seen, dropped = text_of(data).splitlines(), None, [], False, False
    for n, line in enumerate(lines):
        if not _dash_line(line):
            continue
        seen, rows, end = True, [], len(lines)
        for m in range(n + 1, len(lines)):
            parts = lines[m].split()
            if not parts or not (_winget_version(parts[-1]) or parts[-1].endswith("\u2026")):  # a truncated value is a row
                end = m
                break
            rows.append(parts)
        tail = []
        for rest in lines[end:]:
            if not rest.strip() or _dash_line(rest):
                break
            tail.append(rest.split())
        dropped |= not rows or any(_row_like(parts) for parts in tail)
        explicit = n >= 3 and any(char.isalpha() for char in lines[n - 2]) and not lines[n - 3].strip()  # not a spinner fragment
        if main is None and not explicit:
            main = rows
        else:
            later += rows
    return (main or [], later, dropped) if seen else None


def winget_client(data):
    """D1: the client version (one token)."""
    words = text_of(data).split()
    if len(words) != 1 or not _winget_version(words[0]):
        raise Refusal("winget-version", "winget did not print one client version")
    return words[0]


def winget_source(data):
    """D2: only the winget community source with its documented Arg, Identifier and Type is allowed."""
    record = _json(data)
    identity = {key: record.get(key) for key in WINGET_SOURCE} if isinstance(record, dict) else {}
    if identity != dict(WINGET_SOURCE):
        raise Refusal("winget-source", "Only the winget community source with its documented identity is allowed")
    return identity


def _export_ids(data):
    """Every PackageIdentifier of D3 with its Version, unvalidated: used only to count truncated-id matches."""
    return {package["PackageIdentifier"]: package.get("Version") for source in _list(_json(data), "Sources")
            for package in _list(source, "Packages") if isinstance(package, dict) and isinstance(package.get("PackageIdentifier"), str)}


def winget_export(data):
    """D3: {PackageIdentifier: Version} for the identifiers and versions that pass the route grammar."""
    return {key: value for key, value in _export_ids(data).items() if _valid("id", key) and _winget_version(value)}


def _winget_id(token, ids):
    if token.endswith("\u2026"):
        matches = [known for known in ids if len(token) > 1 and known.startswith(token[:-1])]
        token = matches[0] if len(matches) == 1 else None
    return token if token in ids and _valid("id", token) else None


def winget_candidates(list_data, export_data, *, exit_code):
    """D4 rows read from the right (Available, Version, Id), the Id resolved against D3; the rest are held, and rows of
    another table (packages that require explicit targeting or are pinned) are held. Output without a table means "no
    updates" only for exit 0 or NO_APPLICATIONS_FOUND, with a word and no row-like line; a dropped row and anything else hold."""
    table, text = _winget_table(list_data), text_of(list_data)
    if table is None:
        if exit_code in (0, WINGET_NO_APPS) and any(char.isalpha() for char in text) and not any(_row_like(line.split()) for line in text.splitlines()):
            return [], []
        raise Refusal("winget-table", "winget printed no package table")
    if table[2]:
        raise Refusal("winget-table", "winget printed a package row PatchCairn cannot read; discovery holds")
    if exit_code != 0:
        raise Refusal("winget-exit", "winget printed a table but reported an error; discovery holds")
    ids, candidates, held = _export_ids(export_data), [], []
    for parts in table[0]:
        package = _winget_id(parts[-3], ids) if len(parts) >= 4 else None
        if package is None:
            held.append({"id": None, "reason": "id-unresolved"})
        elif not (_winget_version(parts[-2]) and _winget_version(parts[-1])):
            held.append({"id": package, "reason": "version-unknown"})
        elif any(candidate["id"] == package for candidate in candidates):
            held.append({"id": package, "reason": "duplicate"})
        else:
            candidates.append({"id": package, "installed_version": parts[-2], "available_version": parts[-1]})
    held += [{"id": _winget_id(parts[-3], ids) if len(parts) >= 4 else None, "reason": "explicit_or_pinned"} for parts in table[1]]
    return candidates, held


def winget_installed(data, package_id):
    """D5 for one id: installed version and, when offered, the available version; an exact Id beats a truncated (...) one."""
    package_id, exact, prefix = variable("id", package_id), [], []
    table = _winget_table(data)
    for parts in table[0] + table[1] if table else []:
        for width, available in ((3, True), (2, False)):
            if len(parts) <= width:
                continue
            token, found = parts[-width], (parts[1 - width], parts[-1] if available else None)
            if token == package_id:
                exact.append(found)
            elif len(token) > 1 and token.endswith("\u2026") and package_id.startswith(token[:-1]):
                prefix.append(found)
    found = exact or prefix
    if len(found) != 1 or not _winget_version(found[0][0]) or not (found[0][1] is None or _winget_version(found[0][1])):
        raise Refusal("winget-confirm", "winget did not show exactly one matching installed package")
    return {"installed_version": found[0][0], "available_version": found[0][1]}


def plan_winget(candidate, confirm, *, client, source, agreements, executable):
    """One winget entry: id, installed and target (D5 Available), source, consent and executable {path, package} from the runner."""
    package = variable("id", candidate.get("id"))
    if confirm.get("installed_version") != candidate.get("installed_version") or confirm.get("available_version") is None:
        raise Refusal("winget-confirm", "winget no longer offers this upgrade; discovery must run again")
    if dict(source) != dict(WINGET_SOURCE) or not _winget_version(client):
        raise Refusal("winget-source", "Only the winget community source with its documented identity is allowed")
    if not isinstance(agreements, dict) or set(agreements) != {"source", "package"} or {type(v) for v in agreements.values()} != {bool}:
        raise Refusal("winget-agreements", "The plan records each agreement as accepted or not")
    path, folder = (executable.get("path"), executable.get("package")) if isinstance(executable, dict) else (None, None)
    if not _alias_path(path) or not (isinstance(folder, str) and WINGET_FOLDER.fullmatch(folder)):
        raise Refusal("winget-alias", "The plan binds the resolved winget alias path and its App Installer package")
    installed, target = variable("version", confirm["installed_version"]), variable("version", confirm["available_version"])
    return {"manager": "winget", "id": package, "installed_version": installed, "target_version": target, "source": "winget",
            "agreements": dict(agreements), "executable": {"kind": "winget_alias", "path": path, "package": folder, "reparse_tag": WINGET_TAG},
            "preflight": {"client_version": client, "source_identity": dict(source)},
            "transaction": {"installed_version": installed, "available_version": target}}


def verify_winget(entry, data):
    """D5 after the run: Version == target. winget may install dependencies this route cannot see: change lists are None."""
    try:
        installed = winget_installed(data, entry["id"])["installed_version"] == entry["target_version"]
        reason = "" if installed else "version_differs"
    except Refusal as error:
        installed, reason = False, error.code
    return {"target_installed": installed, "reason": reason, "changed": None, "changed_outside_plan": None, "diff_complete": None}


# --- Homebrew --------------------------------------------------------------------------------------------------------
def brew_version(data):
    """D1 line 1, "Homebrew <version>"; versions before 7.0.0 hold ("refresh Homebrew first")."""
    match = re.match(r"Homebrew (([0-9]+)\.[0-9]+\.[0-9]+[0-9A-Za-z._+-]{0,64})[ \t]*(?:\r?\n|\Z)", text_of(data).strip())
    if not match:
        raise Refusal("brew-version", "Homebrew did not print its version")
    if int(match[2]) < 7:
        raise Refusal("brew-too-old", "Homebrew 7.0.0 or later is needed; refresh Homebrew first")
    return match[1]


def _brew_versions(values):
    return isinstance(values, list) and 0 < len(values) <= 64 and all(isinstance(v, str) and B_VER.fullmatch(v) for v in values)


def _flag(item, key):
    """A JSON boolean, False when absent, None (never eligible) when anything else."""
    value = item.get(key, False)
    return value if type(value) is bool else None


def _auto_updates(item):
    """auto_updates: null or absent means not self-updating, true self-updating, anything else never eligible."""
    value = item.get("auto_updates")
    return False if value is None else value if type(value) is bool else None


def _brew_items(data):
    record = _json(data)
    return [(kind, item, item.get("name" if kind == "formula" else "token")) for kind, key in (("formula", "formulae"), ("cask", "casks"))
            for item in _list(record, key) if isinstance(item, dict)]


def brew_outdated(data):
    """outdated --json=v2: ({"<kind>:<name>": entry} of valid entries, count of others); a cask without pinned is not pinned."""
    found, unrecognised = {}, 0
    for kind, item, _ in _brew_items(data):
        name, installed, current = item.get("name"), item.get("installed_versions"), item.get("current_version")
        pinned = item.get("pinned", False if kind == "cask" else None)
        if _valid("name", name) and _brew_versions(installed) and _brew_versions([current]) and type(pinned) is bool:
            found[f"{kind}:{name}"] = {"name": name, "installed_versions": installed, "current_version": current, "pinned": pinned}
        else:
            unrecognised += 1
    return found, unrecognised


def _brew_snapshot(kind, item):
    tap = item["tap"] if isinstance(item.get("tap"), str) and B_TAP.fullmatch(item["tap"]) else "other"
    snap = {"tap": tap, "pinned": _flag(item, "pinned"), "disabled": _flag(item, "disabled")}
    if kind == "formula":
        installed, linked = [entry.get("version") for entry in _list(item, "installed") if isinstance(entry, dict)], item.get("linked_keg")
        return {**snap, "full_name": item.get("full_name") == item.get("name"), "installed": installed if _brew_versions(installed) else [],
                "linked_keg": linked if _brew_versions([linked]) else None, "keg_only": item.get("keg_only") is True}
    installed = item.get("installed")
    return {**snap, "installed": installed if _brew_versions([installed]) else None, "auto_updates": _auto_updates(item),
            "checksum": item.get("sha256") != "no_check", "latest": item.get("version") == "latest",
            "administrator": any(isinstance(a, dict) and bool({"pkg", "installer"} & set(a)) for a in _list(item, "artifacts"))}


def brew_info(data):
    """info --json=v2: a storable state {"packages": {"formula:<name>"|"cask:<token>": snapshot}, "unrecognised": [...]}."""
    packages, unrecognised = {}, []
    for kind, item, name in _brew_items(data):
        if _valid("name", name):
            packages[f"{kind}:{name}"] = _brew_snapshot(kind, item)
        else:
            unrecognised.append(pc_records.digest(item))
    return installed_state(packages, unrecognised)


def _brew_ineligible(kind, snap):
    if snap["tap"] != ("homebrew/core" if kind == "formula" else "homebrew/cask") or not snap.get("full_name", True):
        return "third_party_tap"
    if snap["pinned"] is not False or snap["disabled"] is not False:
        return "pinned_or_disabled"
    if kind == "cask" and (snap["auto_updates"] is not False or snap["latest"]):
        return "self_updating"
    if kind == "cask" and snap["administrator"]:
        return "needs_administrator"
    return "no_checksum" if kind == "cask" and not snap["checksum"] else None


def brew_candidates(outdated_data, info_data):
    """Eligible homebrew/core formulae and homebrew/cask casks, and the reported rest (all from cached metadata)."""
    (outdated, unrecognised), info = brew_outdated(outdated_data), brew_info(info_data)["packages"]
    candidates, reported = [], [{"kind": None, "name": None, "reason": "unrecognised"} for _ in range(unrecognised)]
    for key, entry in sorted(outdated.items()):
        kind, name, snap = *key.split(":", 1), info.get(key)
        reason = "not_in_info" if snap is None else _brew_ineligible(kind, snap) or ("pinned_or_disabled" if entry["pinned"] else None)
        if reason:
            reported.append({"kind": kind, "name": name, "reason": reason})
        else:
            candidates.append({"kind": kind, "name": name, "tap": snap["tap"], "installed_versions": entry["installed_versions"],
                               "target_version": entry["current_version"], "eligibility": snap})
    return candidates, reported


def brew_dependencies(data, name, target):
    """The other packages `brew upgrade --dry-run` lists under its "Would upgrade"/"Would install" headings (PD-13):
    "<name> <old>[, <old>] -> <new>" or "<name> <new>", columns padded, an optional "(<size>)" at the end. None (the plan
    holds) when a line is not recognised, or the target is missing or has another version."""
    rows, heading = [], False
    for line in (line.strip() for line in text_of(data).splitlines()):
        body = re.sub(r"\s*\([^()]*\)\Z", "", line)
        if re.match(r"(?:==> )?Would (?:upgrade|install)\b", line) or not body:
            heading = heading or bool(body)
            continue
        found = re.fullmatch(r"(\S+)\s+(\S+(?:,\s*\S+)*)\s+->\s+(\S+)", body) or re.fullmatch(r"(\S+)\s+()(\S+)", body)
        old = [part.strip() for part in found[2].split(",")] if found and found[2] else []
        if not (heading and found and _valid("name", found[1]) and (not found[2] or _brew_versions(old)) and _brew_versions([found[3]])):
            return None
        rows.append({"name": found[1], "installed_versions": old, "target_version": found[3]})
    own = [row["target_version"] for row in rows if row["name"] == name]
    return [row for row in rows if row["name"] != name] if own == [target] else None


def check_brew_env(files):
    """The brew.env files ({"system"|"prefix"|"user": bytes or None}), read and never changed, bound by the SHA-256 of
    their bytes. An allowlist: only the BREW_FIXED keys set to 1 may appear and HOMEBREW_CASK_OPTS is reported; any
    other key (another HOMEBREW_* variable such as a remote, a curl or git path, SUDO_ASKPASS) or unread line holds."""
    digests, problems, reported = {}, [], []
    for label in ("system", "prefix", "user"):
        if files.get(label) is None:
            digests[label] = "absent"
            continue
        text, digests[label] = file_text(files[label])
        for key, sep, value in (line.strip().partition("=") for line in text.splitlines()):
            if not key or key.startswith("#"):
                continue
            if key == "HOMEBREW_CASK_OPTS" and sep:
                reported.append(f"{label}:{key}")
            elif not (sep and key in BREW_FIXED and value.strip().strip("\"'") == "1"):
                problems.append(f"{label}:{key}" if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", key) else f"{label}:unrecognised-line")
    return {"sha256": digests, "problems": problems, "reported": reported}


def plan_brew(candidate, *, version, path, machine, env, dependencies):
    """One Homebrew entry. Homebrew has no version argument: the drift check right before the run binds the target."""
    kind, name = candidate.get("kind"), variable("name", candidate.get("name"))
    if kind not in ("formula", "cask") or candidate.get("tap") != ("homebrew/core" if kind == "formula" else "homebrew/cask"):
        raise Refusal("brew-source", "Only homebrew/core formulae and homebrew/cask casks are routed")
    if path != BREW_PATHS.get(machine) or not (isinstance(version, str) and B_VER.fullmatch(version)):
        raise Refusal("brew-prefix", "Homebrew runs only from the documented prefix for this machine, with its version recorded")
    if env["problems"]:
        raise Refusal("brew-env", "A brew.env file sets a variable PatchCairn does not allow")
    if not isinstance(dependencies, list):
        raise Refusal("brew-dependencies", "The dry run gave no recognisable dependency list (PD-13); the plan holds")
    return {"manager": "brew", "kind": kind, "name": name, "source": candidate["tap"], "target_version": candidate["target_version"],
            "installed_versions": list(candidate["installed_versions"]), "dependencies": dependencies,
            "warnings": ["intel_tier3_may_build_from_source"] if machine == "x86_64" and kind == "formula" else [],
            "preflight": {"brew_version": version, "brew_path": path, "prefix": BREW_PREFIXES[machine], "machine": machine,
                          "brew_env_sha256": dict(env["sha256"])},
            "transaction": {"installed_versions": list(candidate["installed_versions"]), "current_version": candidate["target_version"],
                            "eligibility": dict(candidate["eligibility"])}}


def verify_brew(entry, before, after_data):
    """before: brew_info() before the run. Target installed and linked (or unlinked as at plan time); other changes listed."""
    after = brew_info(after_data)
    key, target = f"{entry['kind']}:{entry['name']}", entry["target_version"]
    snap = after["packages"].get(key) or {}
    if entry["kind"] == "formula":
        unlinked = entry["transaction"]["eligibility"].get("linked_keg") is None
        linked = snap.get("linked_keg") == target or (snap.get("linked_keg") is None and (snap.get("keg_only") is True or unlinked))
        installed = target in (snap.get("installed") or []) and linked
    else:
        installed = snap.get("installed") == target
    planned = {row["name"] for row in entry.get("dependencies") or []}
    return {"target_installed": installed,
            **state_changes(before, after, planned, lambda k: k.split(":", 1)[1], skip={key}, value=lambda state: state.get("installed"))}


# --- dnf5 ------------------------------------------------------------------------------------------------------------
_NEVRA_SHAPE = re.compile(r"\S+-[0-9]{1,9}:\S+-\S+\.\S+")


def dnf_flavor(realpath):
    """realpath(/usr/bin/dnf) must be /usr/bin/dnf5; dnf4 and anything else hold."""
    if realpath != DNF5:
        raise Refusal("dnf-held", "Only dnf5 (Fedora 41 or later) is routed; dnf4 and other targets hold")
    return "dnf5"


def dnf_upgrades(data, *, exit_code):
    """D2 (rows, held): NEVRA plus repoid per line; a non-routable NEVRA (^ versions) is held; other lines or a failed exit hold."""
    if exit_code != 0:
        raise Refusal("dnf-metadata", "dnf5 could not load repository metadata; check the network or refresh (sudo dnf5 makecache)")
    rows, held = [], []
    for parts in (line.split(" ") for line in text_of(data).splitlines() if line.strip()):
        if len(parts) == 2 and _valid("repoid", parts[1]) and _valid("nevra", parts[0]):
            match = F_NEVRA.fullmatch(parts[0])
            rows.append({"name": match[1], "arch": match[5], "target_nevra": parts[0], "repoid": parts[1]})
        elif len(parts) == 2 and _valid("repoid", parts[1]) and _NEVRA_SHAPE.fullmatch(parts[0]):
            held.append({"repoid": parts[1], "reason": "nevra-not-routable"})
        else:
            raise Refusal("dnf-repoquery", "dnf5 printed a line PatchCairn does not recognise; discovery holds")
    return rows, held


def rpm_installed(data):
    """rpm lines "NAME E:V-R.A" as a storable state {"<name>.<arch>": [NEVRA, ...]}; unread lines (gpg-pubkey) by hash."""
    found, unrecognised = {}, []
    for line in (line for line in text_of(data).splitlines() if line.strip()):
        parts = line.split(" ")
        match = F_NEVRA.fullmatch(f"{parts[0]}-{parts[1]}") if len(parts) == 2 else None
        if match and match[1] == parts[0] and _valid("nevra", match[0]):
            found.setdefault(f"{match[1]}.{match[5]}", []).append(match[0])
        else:
            unrecognised.append(pc_records.digest(line.encode("utf-8")))
    return installed_state({key: sorted(value) for key, value in found.items()}, unrecognised)


def dnf_gpgcheck(data):
    """D4 --dump-repo-config: pkg_gpgcheck or gpgcheck is 1/true, and none of them is off."""
    values = [m[1].lower() for m in re.finditer(r"(?m)^\s*(?:pkg_gpgcheck|gpgcheck)\s*=\s*(\S*)\s*$", file_text(data)[0])]
    return bool(values) and all(value in ("1", "true", "yes") for value in values)


def dnf_preview(data):
    """upgrade --assumeno rows, removals and hash; output without a transaction table holds. A "replacing" row of another
    name or architecture (an obsoleted package) is a removal: dnf removes obsoleted packages without --allowerasing."""
    rows, section, removals, started, current = [], None, False, False, None
    for line in text_of(data).splitlines():
        header, parts = None if line.startswith(" ") else re.fullmatch(r"([A-Z][a-z]+(?: [a-z]+)*):", line.strip()), line.split()
        if line.startswith("Transaction Summary"):
            break
        if not started:
            started = parts[:3] == ["Package", "Arch", "Version"]
        elif header:
            section, current = header[1], None
            removals |= section not in ("Upgrading", "Installing", "Installing dependencies", "Installing weak dependencies")
        elif parts:
            replacing = parts[0] == "replacing"
            parts = parts[1:] if replacing else parts
            if (section is None or not line.startswith(" ") or len(parts) < 4 or not F_NAME.fullmatch(parts[0])
                    or not re.fullmatch(r"[a-z0-9_]{1,32}", parts[1])
                    or not re.fullmatch(r"[A-Za-z0-9._+~:-]{1,128}", parts[2]) or not re.fullmatch(r"@?[A-Za-z0-9._:-]{1,100}", parts[3])):
                raise Refusal("dnf-preview", "dnf5 printed a transaction PatchCairn does not recognise; it holds")
            removals |= replacing and parts[:2] != current
            current = current if replacing else parts[:2]
            rows.append([section, replacing] + parts[:4])
    if not rows:
        raise Refusal("dnf-preview", "dnf5 printed no transaction table (for example a resolver problem); it holds")
    rows.sort()
    return {"removals": removals, "rows": rows, "sha256": pc_records.digest(rows)}


def _nevra_versions(nevra):
    match = F_NEVRA.fullmatch(nevra)
    return {f"{match[2]}:{match[3]}-{match[4]}"} | ({f"{match[3]}-{match[4]}"} if match[2] == "0" else set())


def plan_dnf(selected, *, realpath, version, installed, repo_configs, preview):
    """One dnf5 entry: target NEVRAs, repoids with gpgcheck (every preview repository too), installed NEVRAs, preview item check."""
    flavor, items = dnf_flavor(realpath), []
    if preview["removals"]:
        raise Refusal("dnf-removal", "The preview removes a package (also one replaced as obsolete) or downgrades one; it holds")
    for row in selected_items(selected):
        current = installed["packages"].get(f"{row['name']}.{row['arch']}")
        if not current:
            raise Refusal("dnf-not-installed", f"{row['name']}: no installed package of this architecture")
        if not dnf_gpgcheck(repo_configs.get(row["repoid"], "")):
            raise Refusal("dnf-gpgcheck", f"{row['name']}: its repository does not enable gpgcheck")
        target = variable("nevra", row["target_nevra"])
        if not any(r[0] in ("Upgrading", "Installing") and not r[1] and r[2:4] == [row["name"], row["arch"]] and r[5] == row["repoid"]
                   and r[4] in _nevra_versions(target) for r in preview["rows"]):
            raise Refusal("dnf-preview-item", f"{row['name']}: the preview does not upgrade it to this version from this repository")
        items.append({"name": row["name"], "arch": row["arch"], "installed_nevras": list(current or ()), "target_nevra": target,
                      "repoid": row["repoid"], "gpgcheck": True})
    unchecked = sorted({r[5] for r in preview["rows"] if not r[1] and not dnf_gpgcheck(repo_configs.get(r[5], ""))})
    if unchecked:
        raise Refusal("dnf-gpgcheck", "A repository the preview installs from does not enable gpgcheck")
    names = {item["name"] for item in items}
    return {"manager": "dnf", "flavor": flavor, "items": items, "collateral": sorted({row[2] for row in preview["rows"] if not row[1] and row[2] not in names}),
            "preflight": {"executable": realpath, "dnf5_version_sha256": pc_records.digest(text_of(version).encode("utf-8")),
                          "gpgcheck": {repo: True for repo in sorted({item["repoid"] for item in items} | {r[5] for r in preview["rows"] if not r[1]})}},
            "transaction": {"upgrades": [f"{i['target_nevra']} {i['repoid']}" for i in items], "preview_sha256": preview["sha256"],
                            "installed": {f"{i['name']}.{i['arch']}": i["installed_nevras"] for i in items}}}


def verify_dnf(entry, before, after_data):
    """before: rpm_installed() of rpm -qa before the run. Every target NEVRA installed; changes outside the preview listed."""
    after = rpm_installed(after_data)
    installed = all(i["target_nevra"] in after["packages"].get(f"{i['name']}.{i['arch']}", []) for i in entry["items"])
    planned = {i["name"] for i in entry["items"]} | set(entry["collateral"])
    return {"target_installed": installed, **state_changes(before, after, planned, lambda k: k.rsplit(".", 1)[0])}


def dnf_restart(code):
    """`dnf5 needs-restarting`: exit 1 recommended, 0 none, anything else unknown."""
    return {1: "recommended", 0: "none"}.get(code, "unknown") if type(code) is int else "unknown"


# --- exit classification and typed outcome ---------------------------------------------------------------------------
RESTART_SIGNALS = ("none", "recommended", "required", "required_before_retry", "initiated_by_installer", "unknown")
_WINGET_EXITS = {0: ("success", "", "none"), 0x8A150109: ("restart", "", "required"), 0x8A15010B: ("restart", "", "initiated_by_installer"),
                 0x8A15010A: ("failed", "", "required_before_retry"), 0x8A15010C: ("failed", "cancelled", "none"),
                 0x8A150068: ("failed", "pinned", "none"), 0x8A150105: ("failed", "disk_full", "none"),
                 0x8A150002: ("failed", "route_held_update_app_installer", "none"),
                 3010: ("restart", "msi_mapping_unverified", "required"), 1641: ("restart", "msi_mapping_unverified", "initiated_by_installer"),
                 **dict.fromkeys((0x8A15002B, 0x8A15004F), ("nothing_to_do", "", "none")),
                 **dict.fromkeys((0x8A150101, 0x8A150102, 0x8A150103, 0x8A150111), ("in_use_retry_later", "", "none")),
                 **dict.fromkeys((0x8A150011, 0x8A15002D, 0x8A15002E, 0x8A15003F), ("integrity_failure", "", "none")),
                 **dict.fromkeys((0x8A150041, 0x8A150046), ("failed", "agreements", "none")),
                 **dict.fromkeys((0x8A15003A, 0x8A15010F), ("failed", "policy", "none")),
                 **dict.fromkeys((0x8A150056, 0x8A15007D), ("failed", "elevated_context", "none"))}
_POSIX_EXITS = {"brew": {0: ("success", "", "none"), 130: ("failed", "interrupted", "none")},
                "apt": {0: ("success", "", "unknown"), 1: ("failed", "elevation_not_completed", "unknown")},
                "dnf": {0: ("success", "", "unknown"), 2: ("failed", "route_defect", "unknown")},
                "apt.configure": {0: ("success", "", "unknown"), 1: ("failed", "dpkg_or_elevation_error", "unknown"), 2: ("failed", "dpkg_error", "unknown")}}


def classify_exit(manager, code, *, output="", source="process", recipe_id=None):
    """Exit class, reason and restart signal; code & 0xFFFFFFFF, its source ("process", or an 8-bit "shell" status that
    winget counts as not observed) recorded; None: not observed. output is matched against fixed phrases only. For apt
    and dnf the restart signal comes from the probes (from_probes). dpkg --configure -a exits 1 or 2 on its own errors."""
    if (manager not in MANAGERS or source not in ("process", "shell") or (code is not None and type(code) is not int)
            or recipe_id not in (None, *RUN_RECIPES) or (recipe_id is not None and RUN_RECIPES[recipe_id].manager != manager)):
        raise Refusal("package-exit", "Unknown manager, exit code, exit source or recipe")
    probes = manager in ("apt", "dnf")
    if code is None or (manager == "winget" and source == "shell"):
        return {"exit_code": None, "source": source, "class": "not_observed", "reason": "", "restart": "unknown", "from_probes": probes}
    code, text = code & 0xFFFFFFFF, text_of(output)
    if manager == "winget":
        kind, reason, restart = _WINGET_EXITS.get(code, ("failed", "", "unknown"))
    else:
        table = _POSIX_EXITS["apt.configure" if recipe_id == "apt.configure" else manager]
        kind, reason, restart = table.get(code, ("failed", "", "none" if manager == "brew" else "unknown"))
    if (manager, code) == ("brew", 1) and re.search(r"SHA-?256 mismatch", text):
        kind = "integrity_failure"
    elif (manager, code) == ("brew", 1) and "requires sudo" in text:
        reason = "needs_sudo"
    elif (manager, code) == ("apt", 100) and "Could not get lock" in text:
        kind = "in_use_retry_later"
    elif (manager, code) == ("apt", 100) and ("Hash Sum mismatch" in text or "cannot be authenticated" in text):
        kind = "integrity_failure"
    return {"exit_code": code, "source": source, "class": kind, "reason": reason, "restart": restart, "from_probes": probes}


def typed_outcome(classification, verification, *, restart=None):
    """Exit class combined with verification. A failure is never upgraded to success, and a change outside the plan is
    never reported as succeeded (PD-13). restart: the probes' typed signal; by default the exit code's. other_changes:
    "observed", "not_observed" (the route cannot see them) or "incomplete" (an unreadable line changed)."""
    restart = classification["restart"] if restart is None else restart
    if restart not in RESTART_SIGNALS:
        raise Refusal("package-restart", "Unknown restart signal")
    kind, present = classification["class"], verification["target_installed"] is True
    outcome, reason, check = "failed", "", "target_installed" if present else "target_missing"
    if kind in ("integrity_failure", "in_use_retry_later"):
        outcome = kind
    elif kind == "failed":
        reason = classification["reason"] or ("manager_error_target_present" if present else "manager_error")
    elif kind == "nothing_to_do":
        outcome, reason = ("nothing_to_do", "") if present else ("failed", "not_applicable")
    elif kind == "restart" or present:
        restarting = kind == "restart" or restart in ("required", "initiated_by_installer")
        outcome, check = ("succeeded_restart_required" if restarting else "succeeded"), (check if present else "pending_restart")
    else:
        reason = "not_completed" if kind == "not_observed" else "verification_mismatch"
    outside = verification.get("changed_outside_plan")
    other = "not_observed" if outside is None else "incomplete" if verification.get("diff_complete") is False else "observed"
    if outcome.startswith("succeeded") and outside:
        outcome, reason = "failed", "changed_outside_plan"
    return {"outcome": outcome, "reason": reason, "verification": check, "restart": restart, "other_changes": other,
            "notice": "PatchCairn never restarts the computer; an installer may close apps or ask to restart"}
