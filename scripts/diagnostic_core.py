"""Pure diagnostic record rules and the read-only recipe table (layer L2-pure): validators and data, no files and no
executor.

The trusted coordinator owns collection authority and sequential persistence.
These controls are an operational boundary in a quiet, exclusively controlled
workspace, not a sandbox against another process running as the same user.
"""
from __future__ import annotations

from collections import namedtuple
import copy
from datetime import timedelta
import re
from types import MappingProxyType
import unicodedata
from urllib.parse import urlsplit

import pc_records

SCHEMA = "patchcairn.diagnostics"
KINDS = frozenset({"request", "adapter_result", "result", "excerpt", "hypotheses", "verification"})
MAX_RECORD = 128 * 1024
REQUEST_RE = re.compile(r"diag-[a-f0-9]{32}\Z")
RECORD_RE = re.compile(r"(request|result|excerpt|hypotheses|verification)-([a-f0-9]{64})\Z")
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,95}\Z")

# Every read-only recipe: its platform, how it runs, its official sources, its fixed command (executable candidates,
# then arguments) and, for a recipe that does not run, why it holds. How it runs: "runner" (the command, through
# readonly_runner), "in_process" (the standard library), "helper" (the Windows PowerShell helper, which a scheduled run
# skips) or "inventory" (a collector's query: only that collector runs it, and no diagnostic request names it).
Recipe = namedtuple("Recipe", "platform run sources command held", defaults=((), None, None))
_MS = "https://learn.microsoft.com/en-us/"
_GNU = "https://www.gnu.org/software/coreutils/manual/html_node/"
_ADMIN = ("This check needs an administrator prompt, which PatchCairn never opens; an administrator can run {} "
          "themselves and share what it reports.")
_UNVERIFIED = ("How {} behaves without administrator rights is not verified yet, so this check holds and nothing is run.")
TABLE = MappingProxyType({
    "macos.os_version": Recipe("macos", "runner", (
        "https://developer.apple.com/documentation/technologyoverviews/building-your-macos-game-remotely-from-your-pc",),
        (("/usr/bin/sw_vers",), ("-productVersion",))),
    "macos.root_capacity": Recipe("macos", "runner", (
        "https://raw.githubusercontent.com/apple-oss-distributions/file_cmds/main/df/df.1",),
        # "/" is the sealed system volume, whose figures leave out the person's data; the Data volume holds them.
        (("/bin/df",), ("-k", "-I", "/System/Volumes/Data"))),
    "linux.kernel_version": Recipe("linux", "runner", (_GNU + "uname-invocation.html",), (("/usr/bin/uname", "/bin/uname"), ("-r",))),
    "linux.root_capacity": Recipe("linux", "runner", (_GNU + "df-invocation.html",), (("/usr/bin/df", "/bin/df"), ("-Pk", "/"))),
    "linux.dpkg_audit": Recipe("linux", "runner", ("https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html",),
                               held=_UNVERIFIED.format("the package database audit of dpkg")),
    "linux.rpm_verify": Recipe("linux", "runner", ("https://rpm-software-management.github.io/rpm/man/rpm.8.html",),
                               held=_UNVERIFIED.format("the package verification of rpm")),
    "windows.os_version": Recipe("windows", "in_process", (
        "https://docs.python.org/3/library/sys.html",
        _MS + "windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2")),
    "windows.system_capacity": Recipe("windows", "in_process", (
        _MS + "windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw",)),
    "windows.update_context": Recipe("windows", "helper", (
        _MS + "powershell/module/microsoft.powershell.management/get-hotfix",)),
    "windows.system_event_metadata": Recipe("windows", "helper", (
        _MS + "powershell/module/microsoft.powershell.diagnostics/get-winevent",)),
    "windows.update_event_metadata": Recipe("windows", "helper", (
        _MS + "powershell/module/microsoft.powershell.diagnostics/get-winevent",)),
    "windows.dism_check_health": Recipe("windows", "runner", (
        _MS + "windows-hardware/manufacture/desktop/repair-a-windows-image",),
        held=_ADMIN.format("the Windows image health check (DISM with CheckHealth)")),
    "windows.sfc_verify_only": Recipe("windows", "runner", (
        _MS + "windows-server/administration/windows-commands/sfc",),
        held=_ADMIN.format("the System File Checker in its verify-only mode")),
    # The collectors' queries; the Linux ones keep the collector's own search order of system folders.
    "linux.dpkg_installed": Recipe("linux", "inventory", command=(
        ("/usr/bin/dpkg-query", "/bin/dpkg-query", "/usr/sbin/dpkg-query"),
        ("--show", "--showformat=${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\t${source:Package}\\n"))),
    "linux.rpm_installed": Recipe("linux", "inventory", command=(
        ("/usr/bin/rpm", "/bin/rpm", "/usr/sbin/rpm"),
        ("--noplugins", "--rcfile", "/dev/null", "--macros", "/dev/null", "--dbpath", "/var/lib/rpm", "-qa", "--qf",
         "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n"))),
    "linux.snap_list": Recipe("linux", "inventory", command=(("/usr/bin/snap", "/bin/snap", "/usr/sbin/snap"), ("list",))),
    "linux.flatpak_system": Recipe("linux", "inventory", command=(
        ("/usr/bin/flatpak", "/bin/flatpak", "/usr/sbin/flatpak"), ("list", "--system", "--columns=application,version,arch,branch"))),
    "macos.sw_vers": Recipe("macos", "inventory", command=(("/usr/bin/sw_vers",), ())),
    "macos.machine": Recipe("macos", "inventory", command=(("/usr/bin/uname",), ("-m",))),
    "macos.arm64_capable": Recipe("macos", "inventory", command=(("/usr/sbin/sysctl",), ("-n", "hw.optional.arm64"))),
    "macos.translated": Recipe("macos", "inventory", command=(("/usr/sbin/sysctl",), ("-in", "sysctl.proc_translated"))),
    "macos.developer_dir": Recipe("macos", "inventory", command=(("/usr/bin/xcode-select",), ("--print-path",))),
    "macos.receipts": Recipe("macos", "inventory", command=(("/usr/sbin/pkgutil",), ("--pkgs",))),
})
# {recipe id: platform} for every recipe (readonly_runner's closed table takes its ids from here).
RECIPES = {recipe_id: row.platform for recipe_id, row in TABLE.items()}
# The fixed command of each recipe that runs through readonly_runner; a held recipe has none, so it holds there too.
ARGV = MappingProxyType({recipe_id: row.command for recipe_id, row in TABLE.items() if row.command and not row.held})
HELD = MappingProxyType({recipe_id: row.held for recipe_id, row in TABLE.items() if row.held})
HELPER_RECIPES = frozenset(recipe_id for recipe_id, row in TABLE.items() if row.run == "helper")
INVENTORY_RECIPES = frozenset(recipe_id for recipe_id, row in TABLE.items() if row.run == "inventory")
# Why a result holds when the Windows PowerShell helper could not answer: the script policy refused it, Windows
# PowerShell did not start, it ran past its time limit, or it printed more than its output bound.
HOLDS = frozenset({"windows-script-policy", "windows-helper-start", "windows-helper-timeout", "windows-helper-output"})
SENSITIVE = re.compile(
    r"(?i)password|passwd|\bpwd\b|token|secret|api[ _-]?key|(?:[_-]?auth(?:entication|orization)?\b)|bearer|"
    r"cookie|credential|private[ _-]?key|session[ _-]?(?:id|key)|access[ _-]?key|"
    r"connection[ _-]?string|BEGIN[^\r\n]*PRIVATE KEY|(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"(?:[A-Za-z0-9_+/=-]{32,})|(?:https?://[^\s]*[?@#])")
SOURCES = {"developer.apple.com", "support.apple.com", "www.gnu.org", "gnu.org",
           "learn.microsoft.com", "www.freedesktop.org", "freedesktop.org",
           "www.kernel.org", "kernel.org", "man7.org", "www.man7.org", "docs.python.org", "manpages.debian.org",
           "rpm-software-management.github.io"}


class DiagnosticRefusal(pc_records.Refusal):
    """A refused bounded operation; the caller preserves existing evidence."""

    def __init__(self, message, *, code="diagnostic-refusal"):
        super().__init__(code, message)


def _shared(check, *args, **kwargs):
    """Run a shared pc_records check; its refusal becomes a DiagnosticRefusal with the same code."""
    try:
        return check(*args, **kwargs)
    except pc_records.Refusal as exc:
        if isinstance(exc, DiagnosticRefusal):
            raise
        raise DiagnosticRefusal(str(exc), code=exc.code) from exc


def parse_time(value):
    """A strict UTC timestamp, refused as a DiagnosticRefusal."""
    return _shared(pc_records.parse_utc, value)


# A time just before the one it must follow (stepped_back). It names the gap, not a cause: a small step back of the
# computer's clock gives one, and so does a time given that really comes first.
CLOCK_STEP_MESSAGE = (f"This time is up to {pc_records.FUTURE_SKEW_SECONDS:g} seconds before the step it must follow, as happens "
                      "when the computer's clock is set back; observe again.")


def stepped_back(observed, after):
    """True when ``observed`` precedes ``after`` by no more than pc_records' future-skew bound: ordering keeps no
    tolerance, but such a small backward gap is refused as a clock step, not as stale evidence."""
    return after - timedelta(seconds=pc_records.FUTURE_SKEW_SECONDS) <= observed < after


def after_now(observed):
    """True when the time ``observed`` lies beyond now plus pc_records' tolerance for clock steps."""
    return observed > parse_time(pc_records.utc_now()) + timedelta(seconds=pc_records.FUTURE_SKEW_SECONDS)


def read_diagnostic(record):
    """The registered reader of patchcairn.diagnostics records: the schema check and a known kind."""
    _shared(pc_records.require_schema, record, SCHEMA)
    if record.get("kind") not in KINDS:
        raise DiagnosticRefusal("Unknown diagnostic record kind")
    return record


pc_records.register_reader(SCHEMA, read_diagnostic)


def sanitize_text(value, *, limit=4096):
    """Conservatively suppress a potentially credential-bearing entire excerpt.

    This is defense in depth, not a secret detector. The caller supplies a
    reviewed nonsecret excerpt; this module never opens a log/credential path.
    """
    if not isinstance(value, str) or len(value) > limit or len(value.splitlines()) > 32:
        raise DiagnosticRefusal("Selected text exceeds the bounded excerpt limit")
    if any(unicodedata.category(char).startswith("C") and char not in "\n\r\t" for char in value):
        raise DiagnosticRefusal("Control characters refused")
    if SENSITIVE.search(value):
        return "[REDACTED: potentially sensitive excerpt]"
    value = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED: address]", value)
    value = re.sub(r"(?i)(?:[A-Z]:[\\/]|\\\\)[^\s\"<>]*", "[REDACTED: path]", value)
    value = re.sub(r"(?<![\w:])/(?:[^\s\"<>]+)", "[REDACTED: path]", value)
    return value.strip()


def scope_tokens(scope):
    if not isinstance(scope, list) or not 0 <= len(scope) <= 16:
        raise DiagnosticRefusal("At most sixteen categorical scope tokens required")
    if any(not isinstance(s, str) or not TOKEN_RE.fullmatch(s) for s in scope) or len(set(scope)) != len(scope):
        raise DiagnosticRefusal("Unsafe or duplicate scope token")
    return list(scope)


def exact_keys(data, required, optional=()):
    if not isinstance(data, dict) or set(data) - set(required) - set(optional) or set(required) - set(data):
        raise DiagnosticRefusal("Unexpected or missing fields")


def _number(value, *, maximum=(1 << 63) - 1):
    if type(value) is not int or value < 0 or value > maximum:
        raise DiagnosticRefusal("Bounded nonnegative integer required")


def _version(value, pattern=r"[0-9][A-Za-z0-9._+~^-]{0,95}"):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise DiagnosticRefusal("Unexpected version metadata")


def validate_request(request):
    read_diagnostic(request)
    exact_keys(request, {"schema", "schema_version", "kind", "request_id", "platform", "recipe_id", "mode", "symptom", "scope", "observed_utc"})
    if request["kind"] != "request" or not REQUEST_RE.fullmatch(str(request["request_id"])):
        raise DiagnosticRefusal("Foreign diagnostic request")
    if (not isinstance(request["recipe_id"], str) or not isinstance(request["platform"], str) or not isinstance(request["mode"], str)
            or RECIPES.get(request["recipe_id"]) != request["platform"] or request["recipe_id"] in INVENTORY_RECIPES
            or request["mode"] not in {"fixture", "real"}):
        raise DiagnosticRefusal("Unknown or foreign-platform recipe")
    scope_tokens(request["scope"])
    parse_time(request["observed_utc"])
    if sanitize_text(request["symptom"]) != request["symptom"] or not request["symptom"]:
        raise DiagnosticRefusal("Request symptom must already be sanitized")
    return copy.deepcopy(request)


def _facts(recipe, facts):
    if recipe.endswith("root_capacity"):
        exact_keys(facts, {"total_bytes", "used_bytes", "available_bytes", "used_percent"})
        for key in ("total_bytes", "used_bytes", "available_bytes"):
            _number(facts[key])
        _number(facts["used_percent"], maximum=100)
        if facts["used_bytes"] > facts["total_bytes"] or facts["available_bytes"] > facts["total_bytes"]:
            raise DiagnosticRefusal("Inconsistent capacity metadata")
    elif recipe == "macos.os_version":
        exact_keys(facts, {"product_version"})
        _version(facts["product_version"], r"[0-9]+(?:\.[0-9]+){1,3}")
    elif recipe == "linux.kernel_version":
        exact_keys(facts, {"kernel_release"})
        _version(facts["kernel_release"])
    elif recipe == "windows.os_version":
        exact_keys(facts, {"version", "build", "architecture"})
        _version(facts["version"], r"[0-9]+(?:\.[0-9]+){1,3}")
        _version(facts["build"], r"[0-9]{1,12}")
        if not isinstance(facts["architecture"], str) or facts["architecture"] not in {"x86", "x64", "arm64", "unknown"}:
            raise DiagnosticRefusal("Unknown architecture label")
    elif recipe == "windows.system_capacity":
        exact_keys(facts, {"total_bytes", "available_bytes"})
        for value in facts.values():
            _number(value)
        if facts["available_bytes"] > facts["total_bytes"]:
            raise DiagnosticRefusal("Inconsistent capacity metadata")
    elif recipe == "windows.update_context":
        exact_keys(facts, {"updates"})
        if not isinstance(facts["updates"], list) or len(facts["updates"]) > 50:
            raise DiagnosticRefusal("Update metadata cap exceeded")
        for item in facts["updates"]:
            exact_keys(item, {"kb_id", "installed_utc"})
            if not isinstance(item["kb_id"], str) or not re.fullmatch(r"KB[0-9]{1,12}", item["kb_id"]):
                raise DiagnosticRefusal("Unexpected update identifier")
            if item["installed_utc"] is not None:
                parse_time(item["installed_utc"])
    elif recipe in ("windows.system_event_metadata", "windows.update_event_metadata"):
        exact_keys(facts, {"events"})
        if not isinstance(facts["events"], list) or len(facts["events"]) > 50:
            raise DiagnosticRefusal("Event metadata cap exceeded")
        for item in facts["events"]:
            exact_keys(item, {"event_id", "provider", "level", "observed_utc"})
            _number(item["event_id"], maximum=65535)
            _number(item["level"], maximum=5)
            if item["event_id"] == 0 or item["level"] == 0:
                raise DiagnosticRefusal("Event identifier and level must be nonzero")
            if not isinstance(item["provider"], str) or item["provider"] not in {"Microsoft-Windows-WindowsUpdateClient", "Microsoft-Windows-Kernel-Power", "EventLog", "Microsoft-Windows-WHEA-Logger", "disk", "Ntfs", "Microsoft-Windows-Ntfs", "volmgr"}:
                raise DiagnosticRefusal("Unreviewed event provider")
            parse_time(item["observed_utc"])
    else:
        raise DiagnosticRefusal("This recipe holds; it has no observed facts")
    return copy.deepcopy(facts)


def validate_adapter_result(request, result):
    """A recipe's result for ``request``, checked and copied. An optional ``hold`` names why a held result holds (HOLDS)."""
    validate_request(request)
    read_diagnostic(result)
    exact_keys(result, {"schema", "schema_version", "kind", "request_id", "platform", "recipe_id", "mode", "status", "observed_utc", "facts",
                        "limitations", "provenance"}, {"hold"})
    for key in ("request_id", "platform", "recipe_id", "mode"):
        if result[key] != request[key]:
            raise DiagnosticRefusal("Result/request identity mismatch")
    if result["kind"] != "adapter_result" or not isinstance(result["status"], str) or result["status"] not in {"observed", "held", "failed"}:
        raise DiagnosticRefusal("Unknown adapter result")
    if "hold" in result and (result["status"] != "held" or not isinstance(result["hold"], str) or result["hold"] not in HOLDS):
        raise DiagnosticRefusal("Unknown hold reason")
    observed, requested = parse_time(result["observed_utc"]), parse_time(request["observed_utc"])
    if stepped_back(observed, requested):
        raise DiagnosticRefusal(CLOCK_STEP_MESSAGE, code="clock-step")
    if observed < requested or after_now(observed):
        raise DiagnosticRefusal("Result must fall between request and current UTC")
    result = copy.deepcopy(result)
    if result["status"] == "observed":
        result["facts"] = _facts(request["recipe_id"], result["facts"])
    elif result["facts"] != {}:
        raise DiagnosticRefusal("Held/failed observations cannot carry success facts")
    if not isinstance(result["limitations"], list) or not 1 <= len(result["limitations"]) <= 16:
        raise DiagnosticRefusal("Explicit bounded limitations required")
    result["limitations"] = [sanitize_text(item, limit=1024) for item in result["limitations"]]
    if not isinstance(result["provenance"], list) or not 1 <= len(result["provenance"]) <= 8:
        raise DiagnosticRefusal("Official provenance required")
    for url in result["provenance"]:
        if not isinstance(url, str) or len(url) > 512 or any(ord(char) <= 32 or char == "\\" for char in url):
            raise DiagnosticRefusal("Bounded source URL required")
        try:
            parsed = urlsplit(url)
            apple_oss = parsed.hostname == "raw.githubusercontent.com" and parsed.path == "/apple-oss-distributions/file_cmds/main/df/df.1"
            invalid = parsed.scheme != "https" or (parsed.hostname not in SOURCES and not apple_oss) or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port
        except ValueError as exc:
            raise DiagnosticRefusal("Malformed diagnostic source URL") from exc
        if invalid:
            raise DiagnosticRefusal("Unreviewed diagnostic source URL")
    return result
