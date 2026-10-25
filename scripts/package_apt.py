"""The apt route (layer L2-pure: standard library, pc_records, package_routes; D-057 moved it out of package_routes).

It starts no process. Parsers for apt-config dump, the sources files, apt-get -s, dpkg-query, apt-cache policy and
needrestart -b turn manager output into validated fields (raw manager text never leaves a parser); plan binding,
verification and the restart signal of the apt route. The read-only recipes and the run argv stay in package_tokens and
package_routes. A pc_records.Refusal is a hold.
"""
from __future__ import annotations

import posixpath
import re
from types import MappingProxyType

from package_routes import A_ARCH, A_PACKAGE, apt_version, file_text, installed_state, selected_items, state_changes, text_of, variable
import pc_records
from pc_records import Refusal

_FORCE = re.compile(r"\A--force-")
_APT_TRUST_KEYS = frozenset({"apt::get::allowunauthenticated", "apt::get::allow-downgrades", "apt::get::allow-remove-essential",
                             "apt::get::allow-change-held-packages", "apt::get::force-yes", "acquire::allowinsecurerepositories",
                             "acquire::allowweakrepositories", "acquire::allowdowngradetoinsecurerepositories"})
# apt StringToBool's words; its strtol step also reads "00" or "0x0" (and "" in a sources option) as false: a check counts as on only for a true word.
_NO = frozenset({"false", "no", "0", "off", "without", "disable"})
_OFF, _YES = _NO | {""}, frozenset({"true", "yes", "1", "on", "with", "enable"})
_SOURCE_OPTIONS = ("trusted", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure")
# apt reads its sources from these locations (sourcelist.cc ReadMainList); any other value would hide sources unchecked.
# Defaults as `apt-config dump` prints them on Ubuntu 24.04 (apt-pkg/init.cc). FindDir appends "/" to a folder, so a trailing
# "/" on the two folders names the same folder. posixpath.sep is "/": a "/" literal would be read by G09 as a token.
_APT_DIRS = MappingProxyType({"dir": posixpath.sep, "dir::etc": "etc/apt", "dir::etc::sourcelist": "sources.list", "dir::etc::sourceparts": "sources.list.d"})
_APT_FOLDERS = ("dir::etc", "dir::etc::sourceparts")
_C_SPACE = " \t\n\v\f\r"  # isspace() in the C locale, which apt's ParseQuoteWord uses
# apt reads a sources file line by line up to LF; a CR without LF, U+0085, U+2028, U+2029 or undecodable bytes (U+FFFD) could
# split a line or a field differently for apt and for this parser, so such a file holds.
_ODD_BREAK = re.compile("\r(?!\n)|[\x85\u2028\u2029\ufffd]")
_FIELD = re.compile(r"([A-Za-z][A-Za-z0-9-]*):(.*)")  # a deb822 field line "Name: value"
_TRUST_FIELDS = _SOURCE_OPTIONS + ("enabled", "check-valid-until", "check-date", "valid-until-min")
# apt-get(8) -s: "Square brackets indicate broken packages, and empty square brackets indicate breaks that are of no
# consequence" (pkgSimulate::ShortBreaks writes " [name:arch ...]"); the bracket stays in the hashed line.
_BREAKS = r"(?: \[((?:[a-z0-9][a-z0-9+.-]*:[a-z0-9][a-z0-9-]* )*)\])?"
_APT_LINES = (("upgrade", re.compile(r"Inst (\S+) \[(\S+)\] \((\S+) (.+?) \[(\S+)\]\)" + _BREAKS), ("installed_version", "target_version", "origin", "arch")),
              ("new", re.compile(r"Inst (\S+) \((\S+) (.+?) \[(\S+)\]\)" + _BREAKS), ("target_version", "origin", "arch")),
              ("conf", re.compile(r"Conf (\S+) \((\S+) (.+?) \[(\S+)\]\)" + _BREAKS), ("target_version", "origin", "arch")),
              ("remove", re.compile(r"Remv (\S+) \[(\S+)\]" + _BREAKS), ("installed_version",)),
              ("remove", re.compile(r"Purg (\S+) \[(\S+)\]" + _BREAKS), ("installed_version",)))
_ORIGIN = re.compile(r"[A-Za-z0-9.:/_+~ ,-]{1,200}")


def apt_config(data):
    """D1 apt-config dump: no trust switch is true, DPkg::Options holds no --force-* but the two constants, the sources
    locations are present (unscoped) and apt's defaults, replay protection is on; a Binary::<program>:: scope is removed
    before comparing. apt-config's own dump switches (APT::Config::Dump::*) and Binary::apt-config settings, which apt-config
    applies over the dumped values without printing them, hold: the dump could then hide what apt-get uses."""
    text, sha256 = file_text(data)
    problems, seen = set(), set()
    for line in (line.strip() for line in text.splitlines() if line.strip()):
        match = re.fullmatch(r'([^\s"]+) "([^"]*)";', line)
        key, value = (re.sub(r"\Abinary::[^:]+::", "", match[1].lower()), match[2].strip()) if match else ("unrecognised-line", "true")
        if match and match[1].lower() in _APT_DIRS and match[1].lower() in seen:  # a repeated Dir line: which one apt uses is unclear
            problems.add(f"{match[1].lower()}:repeated")
        seen.add(match[1].lower() if match else "")
        if match and match[1].lower().startswith(("apt::config::dump", "binary::apt-config")):
            problems.add(match[1].lower())
        elif (key in _APT_TRUST_KEYS or not match) and value.lower() not in _OFF:
            problems.add(key)
        elif key.startswith("dpkg::options") and _FORCE.match(value) and value not in ("--force-confdef", "--force-confold"):
            problems.add("dpkg::options")
        elif ((key in _APT_DIRS and (match[2].rstrip(posixpath.sep) if key in _APT_FOLDERS else match[2]) != _APT_DIRS[key])  # unstripped
              or (key.startswith("apt::sources::with") and value)):
            problems.add(key if key in _APT_DIRS else "apt::sources::with")
        elif key in ("rootdir", "dir::rootdir") and match[2] not in ("", posixpath.sep):  # FindFile puts RootDir before every path
            problems.add(key)
        elif ((re.fullmatch(r"acquire::check-(?:valid-until|date)(?:::.*)?", key) and value and value.lower() not in _YES)
              or key.startswith("acquire::min-validtime")):
            problems.add(key)
    problems |= {f"{key}:missing" for key in _APT_DIRS if key not in seen}  # an empty or cut dump proves nothing
    return {"sha256": sha256, "problems": sorted(problems)}


def _quote_word(text, at):
    """apt's ParseQuoteWord from index at (callers pass the index of a non-space character): (the word with %XX decoded
    and quotes removed, the index after it and its spaces), or None where apt fails (a quote or bracket left open)."""
    start = at
    while at < len(text) and text[at] not in _C_SPACE:
        if text[at] in "\"[":
            at = text.find("\"" if text[at] == "\"" else "]", at + 1)
            if at < 0:
                return None
        at += 1
    word = re.sub(r'%([0-9A-Fa-f]{2})|"', lambda m: chr(int(m[1], 16)) if m[1] else "", text[start:at])
    while at < len(text) and text[at] in _C_SPACE:
        at += 1
    return word, at


def _list_entry(line):
    """The [key=value] options of one sources.list line as apt's ParseFileOldStyle and ParseLine read them: "#" starts a
    comment only where no "[" is still open before it; [] for a blank, comment or option-less line; None where apt refuses
    the line (which then holds the file)."""
    cut, opened, closed = len(line), 0, 0
    for n, char in enumerate(line):  # apt counts the "[" and "]" before each "#"; one pass keeps the same rule linear
        if char == "#" and opened <= closed:
            cut = n
            break
        opened, closed = opened + (char == "["), closed + (char == "]")
    line, pairs = line[:cut].strip(_C_SPACE), []
    found = _quote_word(line, 0) if line else ("", 0)
    if found is None or found[0] not in ("", "deb", "deb-src"):
        return None
    at = found[1]
    if not found[0] or at >= len(line) or line[at] != "[":
        return pairs
    at += 1
    while at < len(line) and line[at] in _C_SPACE:
        at += 1
    while at < len(line) and line[at] != "]":
        found = _quote_word(line, at)
        if found is None or len(found[0]) < 3:
            return None
        option, at = found
        if option.endswith("]"):  # apt accepts the last option without a space before "]" and walks back to that "]"
            option, at = option[:-1], line.rfind("]", 0, at)
            if at < 0:  # the "]" came from %5d: apt would walk back past the line
                return None
        key, equals, value = option.partition("=")
        if not (key and equals and value):
            return None
        pairs.append((key.lower(), value.lower()))
    return pairs if at < len(line) else None


def _stanzas(text, label):
    """deb822 stanzas as (field name, value) lists. Only shapes that apt's tag parser and this one read alike are accepted:
    "Name: value" field lines, comment lines starting with "#", empty lines between stanzas, and continuation lines that
    start with a space and follow a field (an empty first-line value only for fields that do not decide trust, such as a
    Signed-By key block). Every other shape holds: a line of only spaces or tabs (apt continues the field across it), a
    continuation starting with a tab or opening a stanza, a trust field continued from an empty value (apt may keep a
    leading line break), a field repeated in a stanza, and any other line."""
    stanzas, fields, seen = [], [], set()  # a value is kept as its parts and the names in a set, so large files stay linear
    for raw in text.split("\n") + [""]:
        field = _FIELD.fullmatch(raw)
        if not raw:
            stanzas += [[(name, " ".join(parts)) for name, parts in fields]] if fields else []
            fields, seen = [], set()
        elif raw.startswith("#"):
            continue
        elif field and field[1].lower() not in seen:
            seen.add(field[1].lower())
            fields.append((field[1].lower(), [field[2].strip(_C_SPACE).lower()] if field[2].strip(_C_SPACE) else []))
        elif raw[0] == " " and raw.strip(_C_SPACE) and fields and (fields[-1][1] or fields[-1][0] not in _TRUST_FIELDS):
            fields[-1][1].append(raw.strip(_C_SPACE).lower())
        else:
            raise Refusal("apt-sources-entry", f"{label}: a sources stanza has a shape apt could read differently (a blank-looking line, "
                                               "a tab-indented or empty-value continuation, a repeated field); the apt route holds")
    return stanzas


def _source_problems(label, fields, deb822):
    """Problems of one source from its (name, value) pairs. Every value of a repeated one-line option counts, a one-line key
    with a "+"/"-" suffix still counts for the trust checks, and only a deb822 stanza whose Enabled field is false is
    skipped (apt reads Enabled in deb822 files only; _stanzas already held repeated or oddly spelled fields)."""
    if fields is None:
        raise Refusal("apt-sources-entry", f"{label}: a sources line cannot be read the way apt reads it; the apt route holds")
    values = {option: [v.strip(_C_SPACE) for k, v in fields if k.strip(_C_SPACE).rstrip("+-") == option]
              for option in _SOURCE_OPTIONS + ("check-valid-until", "check-date", "valid-until-min")}
    enabled = [(k, v.strip(_C_SPACE)) for k, v in fields if k.strip(_C_SPACE).rstrip("+-") == "enabled"]
    if deb822 and enabled and all(k == "enabled" and v in _NO for k, v in enabled):
        return []
    return ([f"{label}:{option}" for option in _SOURCE_OPTIONS if any(value not in _NO for value in values[option])]
            + [f"{label}:{option}" for option in ("check-valid-until", "check-date") if any(value not in _YES for value in values[option])]
            + ([f"{label}:valid-until-min"] if values["valid-until-min"] else []))


def apt_sources(files):
    """{"sources.list" | "sources.list.d/<name>": bytes}, names and bytes hashed: no enabled source is trusted, insecure or without
    replay protection, an unreadable file holds. sources.list.d names are read as apt's GetListOfFilesInDir reads them (no leading
    ".", extension list/sources, any length, ASCII A-Z a-z 0-9 _ - : . and, as isalpha follows the locale, any non-ASCII)."""
    problems, digests, ignored = [], [], []
    for key in sorted(files, key=str):
        match = re.fullmatch(r"(sources\.list\.d/)?([^\\/]+)", key) if isinstance(key, str) else None
        if not match or (not match[1] and key != "sources.list") or match[2] in (".", ".."):
            raise Refusal("apt-sources", "Sources files are sources.list and sources.list.d/<name>")
        label = key if re.fullmatch(r"[A-Za-z0-9_:./+~-]{1,120}", key) else "(unprintable or long name)"
        name = pc_records.digest(key.encode("utf-8", "surrogatepass"))
        if match[1] and (match[2].startswith(".") or not re.fullmatch(r"(?:[A-Za-z0-9_:.-]|[^\x00-\x7f])+\.(?:list|sources)", match[2])):
            ignored, digests = ignored + [label], digests + [[name, None]]
            continue
        if not isinstance(files[key], (bytes, bytearray, str)):
            raise Refusal("apt-sources-unreadable", f"{label}: a sources file apt reads could not be read; the apt route holds")
        text, sha256 = file_text(files[key])
        if _ODD_BREAK.search(text):
            raise Refusal("apt-sources-line-break", f"{label}: a sources file holds a line break apt does not use (CR without LF, U+0085, "
                                                    "U+2028, U+2029) or bytes that are not UTF-8; the apt route holds")
        digests.append([name, sha256])
        lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]  # apt reads up to LF
        for fields in [_list_entry(line) for line in lines] if key.endswith(".list") else _stanzas("\n".join(lines), label):
            problems += _source_problems(label, fields, not key.endswith(".list"))
    return {"sha256": pc_records.digest(digests), "problems": problems, "ignored": ignored}


def apt_simulation(data, *, exit_code):
    """apt-get -s rows (upgrade, new, remove), kept back, sim_sha256 of sorted Inst/Conf/Remv lines; a non-zero exit holds."""
    if exit_code != 0:
        raise Refusal("apt-simulation-failed", "apt-get could not simulate; refresh the package lists or change the selection")
    rows, lines, kept, in_kept = [], [], [], False
    for raw in text_of(data).splitlines():
        line = raw.rstrip()
        if in_kept and raw[:1] in (" ", "\t"):
            kept += [name for name in line.split() if A_PACKAGE.fullmatch(name)]
            continue
        in_kept = line == "The following packages have been kept back:"
        if not line.startswith(("Inst ", "Conf ", "Remv ", "Purg ")):
            continue
        lines.append(line)
        kind, match, fields = next(((k, m, f) for k, pattern, f in _APT_LINES if (m := pattern.fullmatch(line))), (None, None, ()))
        row = {"kind": kind, "arch": "", "package": match[1] if match else "", **dict(zip(fields, match.groups()[1:] if match else ()))}
        if not (match and A_PACKAGE.fullmatch(row["package"]) and _ORIGIN.fullmatch(row.get("origin", "-"))
                and all(apt_version(row[k]) for k in ("installed_version", "target_version") if k in row)
                and (kind == "remove" or A_ARCH.fullmatch(row["arch"])) and all(A_PACKAGE.fullmatch(n) for n in (match[match.re.groups] or "").split())):
            raise Refusal("apt-simulation", "apt-get printed a transaction line PatchCairn does not recognise; discovery holds")
        rows.append({**row, "name": row["package"].split(":")[0]})
    return {**{kind: [row for row in rows if row["kind"] == kind] for kind in ("upgrade", "new", "remove")}, "kept_back": kept,
            "sim_sha256": pc_records.digest("\n".join(sorted(lines)).encode("utf-8"))}


def dpkg_installed(data):
    """D3 dpkg-query: a storable state {"packages": {"<name>:<arch>": {"version", "status"}}, "unrecognised": [...]}."""
    packages, unrecognised = {}, []
    for line in (line for line in text_of(data).splitlines() if line.strip()):
        parts = line.split("\t")
        if (len(parts) == 4 and A_PACKAGE.fullmatch(parts[0]) and ":" not in parts[0] and A_ARCH.fullmatch(parts[1])
                and (parts[2] == "" or apt_version(parts[2])) and re.fullmatch(r"[uihrp][ncHUFWti][ R]", parts[3])):
            packages[f"{parts[0]}:{parts[1]}"] = {"version": parts[2], "status": parts[3]}
        else:
            unrecognised.append(pc_records.digest(line.encode("utf-8")))
    return installed_state(packages, unrecognised)


def apt_specs(rows):
    """Exact specs <name>=<target>, or <name>:<arch>=<target> for a foreign architecture; the simulation and the run share them."""
    return [variable("spec", f"{row['package']}={row['target_version']}") for row in selected_items(rows)]


def _phased(policy):
    """apt-cache policy: the Candidate's own version-table line carries "(phased N%)"; output without a Candidate holds."""
    text = text_of(policy)
    candidate = re.search(r"(?m)^\s*Candidate:\s*(\S+)\s*$", text)
    return candidate is None or any("(phased" in line for line in text.splitlines()
                                    if candidate[1] in line.split()[:2] and not line.strip().startswith("Candidate:"))


def plan_apt(selected, *, simulation, installed, policy, newer, config, sources):
    """One apt entry from chosen D2 rows, the -s simulation of apt_specs, D3, {package: D4}, {package: D5 exit} and the preflight."""
    if config["problems"] or sources["problems"]:
        raise Refusal("apt-trust", "A trusted or insecure source or a permissive apt setting holds the whole apt route")
    if simulation["remove"]:
        raise Refusal("apt-removal", "The simulated transaction removes a package; it holds")
    items = []
    for row, spec in zip(selected_items(selected), apt_specs(selected)):
        package, name, state = row["package"], row["name"], installed["packages"].get(f"{row['name']}:{row['arch']}")
        if state is None or state["version"] != row["installed_version"]:
            raise Refusal("apt-not-installed", f"{name}: not installed as listed")
        if state["status"][0] == "h":
            raise Refusal("apt-dpkg-hold", f"{name}: the owner holds this package (dpkg hold)")
        if package not in policy or _phased(policy[package]):
            raise Refusal("apt-phased", f"{name}: a phased update, or apt-cache policy shows no candidate")
        if newer.get(package) != 0:
            raise Refusal("apt-not-newer", f"{name}: the target is not newer than the installed version")
        if [(r["installed_version"], r["target_version"]) for r in simulation["upgrade"] if r["package"] == package] != [
                (row["installed_version"], row["target_version"])]:
            raise Refusal("apt-simulation", f"{name}: the simulated transaction does not upgrade exactly this version")
        items.append({"name": name, "arch": row["arch"], "installed_version": row["installed_version"], "origin": row["origin"],
                      "target_version": row["target_version"], "spec": spec})
    planned = {row["package"] for row in selected}
    collateral = sorted(f"{r['package']}={r['target_version']}" for r in simulation["upgrade"] + simulation["new"] if r["package"] not in planned)
    return {"manager": "apt", "items": items, "collateral": collateral,
            "preflight": {"apt_config_sha256": config["sha256"], "sources_sha256": sources["sha256"]},
            "transaction": {"sim_sha256": simulation["sim_sha256"],
                            "installed": {f"{i['name']}:{i['arch']}": installed["packages"][f"{i['name']}:{i['arch']}"] for i in items}}}


def verify_apt(entry, before, after_data):
    """before: dpkg_installed() before the run. Each item at its target with status "ii "; changes outside collateral listed."""
    after = dpkg_installed(after_data)
    installed = all(after["packages"].get(f"{i['name']}:{i['arch']}") == {"version": i["target_version"], "status": "ii "}
                    for i in entry["items"])
    planned = {i["name"] for i in entry["items"]} | {c.split("=")[0].split(":")[0] for c in entry["collateral"]}
    return {"target_installed": installed, **state_changes(before, after, planned, lambda k: k.split(":")[0])}


def needrestart_facts(data):
    """needrestart -b: KSTA (0 unknown, 1 none, 2 ABI upgrade pending, 3 version upgrade pending) and NEEDRESTART-SVC units."""
    text = text_of(data)
    ksta = re.search(r"(?m)^NEEDRESTART-KSTA: ([0-3])\s*$", text)
    services = re.findall(r"(?m)^NEEDRESTART-SVC: ([A-Za-z0-9@._:\\-]{1,255})\s*$", text)
    return {"ksta": int(ksta[1]) if ksta else None, "services": sorted(set(services))}


def apt_restart(*, before, after, ksta=None, services=()):
    """reboot-required before/after (None: unreadable), kernel status 2 or 3 (required), services on old code (recommended),
    else unknown: needrestart run without root reports neither the kernel nor services, so apt never claims "none"."""
    services = sorted(services)
    if after is True or ksta in (2, 3):
        return {"signal": "required", "already_pending": before is True, "services": services}
    return {"signal": "recommended" if services else "unknown", "already_pending": False, "services": services}
