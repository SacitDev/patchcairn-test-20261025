"""Pure diagnostic record rules (layer L2-pure, PD-12): validators, no files and no executor.

The trusted coordinator owns collection authority and sequential persistence.
These controls are an operational boundary in a quiet, exclusively controlled
workspace, not a sandbox against another process running as the same user.
"""
from __future__ import annotations

import copy
from datetime import timedelta
import re
import unicodedata
from urllib.parse import urlsplit

import pc_records

SCHEMA = "patchcairn.diagnostics"
KINDS = frozenset({"request", "adapter_result", "result", "excerpt", "hypotheses", "verification"})
MAX_RECORD = 128 * 1024
REQUEST_RE = re.compile(r"diag-[a-f0-9]{32}\Z")
RECORD_RE = re.compile(r"(request|result|excerpt|hypotheses|verification)-([a-f0-9]{64})\Z")
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,95}\Z")
RECIPES = {
    "macos.os_version": "macos", "macos.root_capacity": "macos",
    "linux.kernel_version": "linux", "linux.root_capacity": "linux",
    "windows.os_version": "windows", "windows.system_capacity": "windows",
    "windows.update_context": "windows", "windows.system_event_metadata": "windows",
    "windows.update_event_metadata": "windows",
}
SENSITIVE = re.compile(
    r"(?i)password|passwd|\bpwd\b|token|secret|api[ _-]?key|(?:[_-]?auth(?:entication|orization)?\b)|bearer|"
    r"cookie|credential|private[ _-]?key|session[ _-]?(?:id|key)|access[ _-]?key|"
    r"connection[ _-]?string|BEGIN[^\r\n]*PRIVATE KEY|(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"(?:[A-Za-z0-9_+/=-]{32,})|(?:https?://[^\s]*[?@#])")
SOURCES = {"developer.apple.com", "support.apple.com", "www.gnu.org", "gnu.org",
           "learn.microsoft.com", "www.freedesktop.org", "freedesktop.org",
           "www.kernel.org", "kernel.org", "man7.org", "www.man7.org"}


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


# D-056: a backward step of the computer's clock between two times PatchCairn stamped in one flow.
CLOCK_STEP_MESSAGE = "The computer's clock moved back while PatchCairn was working; observe again."


def stepped_back(observed, after):
    """True when ``observed`` precedes ``after`` by no more than pc_records' future-skew bound (D-056): ordering keeps
    no tolerance, but such a small backward gap is refused as a clock step, not as stale evidence."""
    return after - timedelta(seconds=pc_records.FUTURE_SKEW_SECONDS) <= observed < after


def after_now(observed):
    """True when the time ``observed`` lies beyond now plus pc_records' tolerance for clock steps (#80)."""
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
    if not isinstance(request["recipe_id"], str) or not isinstance(request["platform"], str) or not isinstance(request["mode"], str) or RECIPES.get(request["recipe_id"]) != request["platform"] or request["mode"] not in {"fixture", "real"}:
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
    else:
        exact_keys(facts, {"events"})
        if not isinstance(facts["events"], list) or len(facts["events"]) > 50:
            raise DiagnosticRefusal("Event metadata cap exceeded")
        for item in facts["events"]:
            exact_keys(item, {"event_id", "provider", "level", "observed_utc"})
            _number(item["event_id"], maximum=65535)
            _number(item["level"], maximum=5)
            if item["event_id"] == 0 or item["level"] == 0:
                raise DiagnosticRefusal("Event identifier and level must be nonzero")
            if not isinstance(item["provider"], str) or item["provider"] not in {"Microsoft-Windows-WindowsUpdateClient", "Microsoft-Windows-Kernel-Power", "EventLog", "Microsoft-Windows-WHEA-Logger", "disk", "Ntfs", "volmgr"}:
                raise DiagnosticRefusal("Unreviewed event provider")
            parse_time(item["observed_utc"])
    return copy.deepcopy(facts)


def validate_adapter_result(request, result):
    validate_request(request)
    read_diagnostic(result)
    exact_keys(result, {"schema", "schema_version", "kind", "request_id", "platform", "recipe_id", "mode", "status", "observed_utc", "facts", "limitations", "provenance"})
    for key in ("request_id", "platform", "recipe_id", "mode"):
        if result[key] != request[key]:
            raise DiagnosticRefusal("Result/request identity mismatch")
    if result["kind"] != "adapter_result" or not isinstance(result["status"], str) or result["status"] not in {"observed", "held", "failed"}:
        raise DiagnosticRefusal("Unknown adapter result")
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
