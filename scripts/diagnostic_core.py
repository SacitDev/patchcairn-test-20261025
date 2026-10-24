"""Bounded diagnostic evidence, with no repair or command-from-data executor.

The trusted coordinator owns collection authority and sequential persistence.
These controls are an operational boundary in a quiet, exclusively controlled
workspace, not a sandbox against another process running as the same user.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, write_private_new

SCHEMA = "patchcairn.diagnostics.v3"
DEFAULT_ROOT = Path(__file__).absolute().parent.parent
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


class DiagnosticRefusal(ValueError):
    """A refused bounded operation; the caller preserves existing evidence."""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", value):
        raise DiagnosticRefusal("UTC-Z timestamp required")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DiagnosticRefusal("Invalid UTC timestamp") from exc


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


def _tokens(scope):
    if not isinstance(scope, list) or not 0 <= len(scope) <= 16:
        raise DiagnosticRefusal("At most sixteen categorical scope tokens required")
    if any(not isinstance(s, str) or not TOKEN_RE.fullmatch(s) for s in scope) or len(set(scope)) != len(scope):
        raise DiagnosticRefusal("Unsafe or duplicate scope token")
    return list(scope)


def _exact(data, required, optional=()):
    if not isinstance(data, dict) or set(data) - set(required) - set(optional) or set(required) - set(data):
        raise DiagnosticRefusal("Unexpected or missing fields")


def _number(value, *, maximum=(1 << 63) - 1):
    if type(value) is not int or value < 0 or value > maximum:
        raise DiagnosticRefusal("Bounded nonnegative integer required")


def _version(value, pattern=r"[0-9][A-Za-z0-9._+~^-]{0,95}"):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise DiagnosticRefusal("Unexpected version metadata")


def validate_request(request):
    _exact(request, {"schema_version", "kind", "request_id", "platform", "recipe_id", "mode", "symptom", "scope", "observed_utc"})
    if request["schema_version"] != SCHEMA or request["kind"] != "request" or not REQUEST_RE.fullmatch(str(request["request_id"])):
        raise DiagnosticRefusal("Foreign diagnostic request")
    if not isinstance(request["recipe_id"], str) or not isinstance(request["platform"], str) or not isinstance(request["mode"], str) or RECIPES.get(request["recipe_id"]) != request["platform"] or request["mode"] not in {"fixture", "real"}:
        raise DiagnosticRefusal("Unknown or foreign-platform recipe")
    _tokens(request["scope"])
    _utc(request["observed_utc"])
    if sanitize_text(request["symptom"]) != request["symptom"] or not request["symptom"]:
        raise DiagnosticRefusal("Request symptom must already be sanitized")
    return copy.deepcopy(request)


def _facts(recipe, facts):
    if recipe.endswith("root_capacity"):
        _exact(facts, {"total_bytes", "used_bytes", "available_bytes", "used_percent"})
        for key in ("total_bytes", "used_bytes", "available_bytes"):
            _number(facts[key])
        _number(facts["used_percent"], maximum=100)
        if facts["used_bytes"] > facts["total_bytes"] or facts["available_bytes"] > facts["total_bytes"]:
            raise DiagnosticRefusal("Inconsistent capacity metadata")
    elif recipe == "macos.os_version":
        _exact(facts, {"product_version"})
        _version(facts["product_version"], r"[0-9]+(?:\.[0-9]+){1,3}")
    elif recipe == "linux.kernel_version":
        _exact(facts, {"kernel_release"})
        _version(facts["kernel_release"])
    elif recipe == "windows.os_version":
        _exact(facts, {"version", "build", "architecture"})
        _version(facts["version"], r"[0-9]+(?:\.[0-9]+){1,3}")
        _version(facts["build"], r"[0-9]{1,12}")
        if not isinstance(facts["architecture"], str) or facts["architecture"] not in {"x86", "x64", "arm64", "unknown"}:
            raise DiagnosticRefusal("Unknown architecture label")
    elif recipe == "windows.system_capacity":
        _exact(facts, {"total_bytes", "available_bytes"})
        for value in facts.values():
            _number(value)
        if facts["available_bytes"] > facts["total_bytes"]:
            raise DiagnosticRefusal("Inconsistent capacity metadata")
    elif recipe == "windows.update_context":
        _exact(facts, {"updates"})
        if not isinstance(facts["updates"], list) or len(facts["updates"]) > 50:
            raise DiagnosticRefusal("Update metadata cap exceeded")
        for item in facts["updates"]:
            _exact(item, {"kb_id", "installed_utc"})
            if not isinstance(item["kb_id"], str) or not re.fullmatch(r"KB[0-9]{1,12}", item["kb_id"]):
                raise DiagnosticRefusal("Unexpected update identifier")
            if item["installed_utc"] is not None:
                _utc(item["installed_utc"])
    else:
        _exact(facts, {"events"})
        if not isinstance(facts["events"], list) or len(facts["events"]) > 50:
            raise DiagnosticRefusal("Event metadata cap exceeded")
        for item in facts["events"]:
            _exact(item, {"event_id", "provider", "level", "observed_utc"})
            _number(item["event_id"], maximum=65535)
            _number(item["level"], maximum=5)
            if item["event_id"] == 0 or item["level"] == 0:
                raise DiagnosticRefusal("Event identifier and level must be nonzero")
            if not isinstance(item["provider"], str) or item["provider"] not in {"Microsoft-Windows-WindowsUpdateClient", "Microsoft-Windows-Kernel-Power", "EventLog", "Microsoft-Windows-WHEA-Logger", "disk", "Ntfs", "volmgr"}:
                raise DiagnosticRefusal("Unreviewed event provider")
            _utc(item["observed_utc"])
    return copy.deepcopy(facts)


def validate_adapter_result(request, result):
    validate_request(request)
    _exact(result, {"schema_version", "kind", "request_id", "platform", "recipe_id", "mode", "status", "observed_utc", "facts", "limitations", "provenance"})
    for key in ("schema_version", "request_id", "platform", "recipe_id", "mode"):
        if result[key] != request[key]:
            raise DiagnosticRefusal("Result/request identity mismatch")
    if result["kind"] != "adapter_result" or not isinstance(result["status"], str) or result["status"] not in {"observed", "held", "failed"}:
        raise DiagnosticRefusal("Unknown adapter result")
    observed = _utc(result["observed_utc"])
    if observed < _utc(request["observed_utc"]) or observed > _utc(utc_now()):
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


def _encoded(value):
    try:
        data = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    except (ValueError, TypeError, RecursionError) as exc:
        raise DiagnosticRefusal("Invalid bounded record") from exc
    if len(data) > MAX_RECORD:
        raise DiagnosticRefusal("Record size cap exceeded")
    return data


def _ordinary(path, *, directory=False):
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise DiagnosticRefusal("Link or reparse point refused")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise DiagnosticRefusal("Ordinary directory required")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise DiagnosticRefusal("Single-link ordinary file required")
    return info


def _ancestors(path):
    for item in reversed([path, *path.parents]):
        _ordinary(item, directory=True)


class DiagnosticStore:
    """Append-only, content-hashed records below this toolkit's work directory."""

    def __init__(self, root=None, *, work_relative="work/diagnostics"):
        self.root = Path(root).absolute() if root is not None else DEFAULT_ROOT
        if ".." in self.root.parts:
            raise DiagnosticRefusal("Traversal in fixture root refused")
        self.fixture_root = root is not None and self.root != DEFAULT_ROOT
        _ancestors(self.root)
        if self.fixture_root:
            try:
                self.root.relative_to(DEFAULT_ROOT / "work")
            except ValueError as exc:
                raise DiagnosticRefusal("Fixture root must stay below toolkit work") from exc
        parts = work_relative.split("/") if isinstance(work_relative, str) else []
        if len(parts) < 2 or parts[0] != "work" or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", part) or re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])", part) for part in parts):
            raise DiagnosticRefusal("Safe work-relative directory required")
        self.base = self.root.joinpath(*parts)
        ensure_private_directory(self.base, create=True, parents=True, exist_ok=True)

    def _directory(self, request_id):
        if not isinstance(request_id, str) or not REQUEST_RE.fullmatch(request_id):
            raise DiagnosticRefusal("Invalid diagnostic request identifier")
        path = self.base / request_id
        _ancestors(path)
        ensure_private_directory(self.base)
        ensure_private_directory(path)
        return path

    def _write(self, record, prefix):
        path = self._directory(record["request_id"])
        data = _encoded(record)
        sha256 = hashlib.sha256(data).hexdigest()
        record_id = prefix + "-" + sha256
        target = path / (record_id + ".json")
        try:
            write_private_new(target, data)
        except FileExistsError as exc:
            raise DiagnosticRefusal("Immutable record already exists") from exc
        except PrivateWorkspaceError as exc:
            if exc.code == "private-file-create-refused" and target.exists():
                raise DiagnosticRefusal("Immutable record already exists") from exc
            raise
        return {"record_id": record_id, "record": copy.deepcopy(record), "evidence": {
            "path": target.relative_to(self.root).as_posix(), "sha256": sha256,
            "scope": copy.deepcopy(record["scope"]), "observed_utc": record["observed_utc"], "kind": record["kind"]}}

    def create_request(self, *, platform, recipe_id, symptom, scope, mode="fixture"):
        if self.fixture_root and mode != "fixture":
            raise DiagnosticRefusal("Fixture roots cannot create real requests")
        request = {"schema_version": SCHEMA, "kind": "request", "request_id": "diag-" + uuid.uuid4().hex,
                   "platform": platform, "recipe_id": recipe_id, "mode": mode,
                   "symptom": sanitize_text(symptom), "scope": _tokens(scope), "observed_utc": utc_now()}
        validate_request(request)
        ensure_private_directory(self.base)
        ensure_private_directory(self.base / request["request_id"], create=True)
        return self._write(request, "request")

    def read_record(self, request_id, record_id):
        if not isinstance(record_id, str) or not (match := RECORD_RE.fullmatch(record_id)):
            raise DiagnosticRefusal("Invalid record identifier")
        path = self._directory(request_id) / (record_id + ".json")
        before = _ordinary(path)
        ensure_private_file(path)
        if before.st_size > MAX_RECORD:
            raise DiagnosticRefusal("Record size cap exceeded")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_nlink) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink):
                raise DiagnosticRefusal("Record identity changed")
            data = stream.read(MAX_RECORD + 1)
            after = os.fstat(stream.fileno())
        if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns) or len(data) > MAX_RECORD or hashlib.sha256(data).hexdigest() != match[2]:
            raise DiagnosticRefusal("Immutable record hash mismatch")
        try:
            record = json.loads(data)
        except (ValueError, RecursionError, UnicodeError) as exc:
            raise DiagnosticRefusal("Invalid immutable record encoding") from exc
        if not isinstance(record, dict) or record.get("request_id") != request_id or record.get("schema_version") != SCHEMA or record.get("kind") != match[1]:
            raise DiagnosticRefusal("Foreign record identity")
        if _encoded(record) != data:
            raise DiagnosticRefusal("Noncanonical immutable record bytes")
        return record

    def read_request(self, request_id):
        names = [p.stem for p in self._directory(request_id).iterdir() if p.name.startswith("request-") and p.name.endswith(".json")]
        if len(names) != 1:
            raise DiagnosticRefusal("Missing or ambiguous immutable request")
        return validate_request(self.read_record(request_id, names[0]))

    def record_result(self, request_id, *, adapter_result):
        request = self.read_request(request_id)
        result = validate_adapter_result(request, adapter_result)
        result["kind"] = "result"
        result["scope"] = request["scope"]
        return self._write(result, "result")

    def record_excerpt(self, request_id, *, excerpt, observed_utc=None):
        request = self.read_request(request_id)
        observed = observed_utc or utc_now()
        if _utc(observed) > _utc(utc_now()):
            raise DiagnosticRefusal("Future excerpt observation refused")
        return self._write({"schema_version": SCHEMA, "kind": "excerpt", "request_id": request_id,
                            "mode": request["mode"], "scope": request["scope"], "observed_utc": observed,
                            "source": "owner_selected_nonsecret_excerpt", "text": sanitize_text(excerpt),
                            "limitation": "Owner-reported excerpt; not independently reproduced or a complete log."}, "excerpt")

    def _evidence_ids(self, request_id, ids):
        if not isinstance(ids, list) or len(ids) > 24 or any(not isinstance(s, str) for s in ids) or len(set(ids)) != len(ids):
            raise DiagnosticRefusal("Bounded unique evidence identifiers required")
        for record_id in ids:
            if self.read_record(request_id, record_id)["kind"] not in {"result", "excerpt"}:
                raise DiagnosticRefusal("Observation evidence required")
        return list(ids)

    def record_hypotheses(self, request_id, *, hypotheses, unknowns):
        request = self.read_request(request_id)
        if not isinstance(hypotheses, list) or not 1 <= len(hypotheses) <= 12 or not isinstance(unknowns, list) or not 1 <= len(unknowns) <= 16:
            raise DiagnosticRefusal("Bounded hypotheses and explicit unknowns required")
        clean = []
        used = set()
        for item in hypotheses:
            _exact(item, {"hypothesis_id", "statement", "mechanism", "original_cause", "confidence", "outcome", "evidence_ids", "counterevidence_ids", "next_check"})
            if not isinstance(item["hypothesis_id"], str) or not TOKEN_RE.fullmatch(item["hypothesis_id"]) or item["hypothesis_id"] in used:
                raise DiagnosticRefusal("Unique hypothesis token required")
            used.add(item["hypothesis_id"])
            if not isinstance(item["confidence"], str) or not isinstance(item["outcome"], str) or item["confidence"] not in {"unknown", "low", "medium", "high"} or item["outcome"] not in {"supported", "disproved", "unknown"}:
                raise DiagnosticRefusal("Explicit hypothesis confidence/outcome required")
            value = copy.deepcopy(item)
            for key in ("statement", "mechanism", "original_cause", "next_check"):
                value[key] = sanitize_text(item[key], limit=1024)
                if not value[key]:
                    raise DiagnosticRefusal("Nonempty hypothesis explanations required")
            for key in ("evidence_ids", "counterevidence_ids"):
                value[key] = self._evidence_ids(request_id, item[key])
            if item["outcome"] != "unknown" and not value["evidence_ids"]:
                raise DiagnosticRefusal("Supported or disproved hypothesis needs evidence")
            clean.append(value)
        return self._write({"schema_version": SCHEMA, "kind": "hypotheses", "request_id": request_id,
                            "scope": request["scope"], "mode": request["mode"], "observed_utc": utc_now(),
                            "hypotheses": clean, "unknowns": [sanitize_text(s, limit=1024) for s in unknowns]}, "hypotheses")

    def record_verification(self, request_id, *, action_id, plan_sha256, action_completed_utc,
                            original_success_condition, result_ids, outcome, observation):
        request = self.read_request(request_id)
        if not isinstance(action_id, str) or not TOKEN_RE.fullmatch(action_id) or not isinstance(plan_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", plan_sha256):
            raise DiagnosticRefusal("Exact action and plan binding required")
        completed = _utc(action_completed_utc)
        if completed > _utc(utc_now()) or not isinstance(outcome, str) or outcome not in {"passed", "failed", "unknown"}:
            raise DiagnosticRefusal("Invalid verification time or outcome")
        ids = self._evidence_ids(request_id, result_ids)
        if outcome in {"passed", "failed"} and not ids:
            raise DiagnosticRefusal("Verification outcome requires fresh evidence")
        for record_id in ids:
            evidence = self.read_record(request_id, record_id)
            if _utc(evidence["observed_utc"]) < completed:
                raise DiagnosticRefusal("Pre-repair evidence cannot verify a repair")
            if outcome == "passed" and evidence["kind"] == "result" and evidence["status"] != "observed":
                raise DiagnosticRefusal("Unavailable observation cannot verify success")
        condition = sanitize_text(original_success_condition, limit=1024)
        detail = sanitize_text(observation, limit=1024)
        if not condition or not detail:
            raise DiagnosticRefusal("Original success condition and actual observation required")
        return self._write({"schema_version": SCHEMA, "kind": "verification", "request_id": request_id,
                            "scope": request["scope"], "mode": request["mode"], "observed_utc": utc_now(),
                            "action_id": action_id, "plan_sha256": plan_sha256, "action_completed_utc": action_completed_utc,
                            "original_success_condition": condition, "result_ids": ids, "outcome": outcome,
                            "observation": detail, "limitation": "Coordinator-attributed behavior check; does not establish original cause or all-system integrity."}, "verification")

    def evidence_bytes(self, request_id, record_id):
        """Validated exact bytes for the engine/v2 coordinator to register itself."""
        record = self.read_record(request_id, record_id)
        return _encoded(record)

    def evidence_ref(self, request_id, record_id):
        record = self.read_record(request_id, record_id)
        return {"path": (self._directory(request_id) / (record_id + ".json")).relative_to(self.root).as_posix(),
                "sha256": record_id.rsplit("-", 1)[1], "scope": copy.deepcopy(record["scope"]),
                "observed_utc": record["observed_utc"], "kind": record["kind"]}
