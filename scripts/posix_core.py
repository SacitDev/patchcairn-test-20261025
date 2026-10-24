"""PatchCairn's supported Python 3.12+ ledger/report and POSIX ownership backend.

This is an operational boundary, not a sandbox. Use an exclusively controlled
workspace: a privileged or same-user adversary can defeat cooperative locks.
There is deliberately no command-from-ledger or update executor.
"""
from __future__ import annotations

import collections
import base64
import contextlib
import csv
import hashlib
import html
import io
import json
import math
import os
import re
import stat
import sys
import uuid
import unicodedata
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

BACKEND = "posix-python-v2"
DEFAULT_ROOT = Path(__file__).absolute().parent.parent
RUN_RE = re.compile(r"run-[a-f0-9]{32}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
HASH_RE = re.compile(r"[a-f0-9]{64}\Z")
MAX_BYTES = 16 * 1024 * 1024
CONTROLS = {"run-marker.json", "ledger.json", "owned-files.json", "actions.jsonl"}
ROLE_ROOTS = {"temporary": "temporary", "evidence": "evidence", "report": "reports", "backup": "backups"}
MUTATIONS = {"update", "repair", "cleanup", "retire"}


class Refusal(ValueError):
    """A failed precondition. Preserve evidence; do not automatically retry."""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    bounded_json_tree(value)
    return json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False, separators=(",", ":")).encode("utf-8")


def bounded_json_tree(value):
    pending = [(value, 0, frozenset())]
    nodes = 0
    while pending:
        item, depth, parents = pending.pop()
        nodes += 1
        if depth > 60 or nodes > 200000:
            raise Refusal("JSON depth/node cap exceeded")
        if isinstance(item, float) and not math.isfinite(item):
            raise Refusal("Nonfinite JSON number")
        if isinstance(item, (dict, list)):
            if id(item) in parents:
                raise Refusal("Cyclic JSON data refused")
            parent_ids = parents | {id(item)}
            if isinstance(item, dict):
                if any(not isinstance(key, str) for key in item):
                    raise Refusal("JSON object keys must be strings")
                if len(item) != len({key.casefold() for key in item}):
                    raise Refusal("Case-ambiguous JSON object keys")
                children = item.values()
            else:
                children = item
            pending.extend((child, depth + 1, parent_ids) for child in children)


def decode(data):
    if len(data) > MAX_BYTES:
        raise Refusal("JSON size cap exceeded")
    def unique(pairs):
        result = {}
        folded = set()
        for key, value in pairs:
            if key.casefold() in folded:
                raise Refusal("Duplicate/case-ambiguous JSON key")
            result[key] = value
            folded.add(key.casefold())
        return result
    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise Refusal("Nonfinite JSON number")
        return result
    try:
        result = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique,
                            parse_float=finite_float,
                            parse_constant=lambda _: (_ for _ in ()).throw(Refusal("Nonfinite JSON number")))
        bounded_json_tree(result)
        return result
    except RecursionError as exc:
        raise Refusal("JSON nesting cap exceeded") from exc


def relative(value):
    if not isinstance(value, str) or not value or len(value) > 240 or "\\" in value:
        raise Refusal("Bounded slash-separated relative path required")
    for part in value.split("/"):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", part) or part in {".", ".."} or part.endswith("."):
            raise Refusal("Unsafe relative path")
        if re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part):
            raise Refusal("Reserved path")
    return value


def ordinary(path, directory=False):
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise Refusal("Symlink/reparse point refused")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise Refusal("Ordinary directory required")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Refusal("Single-link regular file required")
    return info


def ancestors(path):
    current = Path(path)
    if not current.is_absolute():
        raise Refusal("Absolute anchor required")
    for item in reversed([current, *current.parents]):
        ordinary(item, True)


def native_capable():
    """Fail closed, including Windows and incomplete POSIX Python builds."""
    functions = (os.open, os.stat, os.unlink, os.rmdir, os.mkdir, os.rename)
    return (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NONBLOCK")
            and all(fn in os.supports_dir_fd for fn in functions)
            and os.stat in os.supports_follow_symlinks and os.listdir in os.supports_fd)


@contextlib.contextmanager
def anchor_fd(path):
    if not native_capable():
        raise Refusal("Native POSIX no-follow/dir-fd capabilities required; no fallback")
    path = Path(path)
    if not path.is_absolute():
        raise Refusal("Absolute POSIX anchor required")
    handle = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handle)
            os.close(handle)
            handle = nxt
        yield handle
    finally:
        os.close(handle)


@contextlib.contextmanager
def parent_fd(root_fd, path):
    relative(path)
    handle = os.dup(root_fd)
    parts = path.split("/")
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handle)
            os.close(handle)
            handle = nxt
        yield handle, parts[-1]
    finally:
        os.close(handle)


def _private_api():
    try:
        import private_workspace
    except ImportError:
        raise Refusal("Private storage refused: private-helper-unavailable") from None
    return private_workspace


def _privacy_refusal(error):
    code = getattr(error, "code", "")
    if not isinstance(code, str) or not re.fullmatch(r"private-[a-z-]{1,100}", code):
        code = "private-capability-refused"
    raise Refusal("Private storage refused: " + code) from None


def _private_directory(path, *, create=False, parents=False, exist_ok=False):
    api = _private_api()
    try:
        return api.ensure_private_directory(path, create=create, parents=parents, exist_ok=exist_ok)
    except api.PrivateWorkspaceError as error:
        _privacy_refusal(error)


def _private_file(path):
    api = _private_api()
    try:
        return api.ensure_private_file(path)
    except api.PrivateWorkspaceError as error:
        _privacy_refusal(error)


def _private_parents(root, rel):
    current = Path(root)
    _private_directory(current)
    for component in rel.split("/")[:-1]:
        current /= component
        _private_directory(current)


@contextlib.contextmanager
def _private_existing_stream(path, mode):
    """Open an admitted existing private object; never create/truncate/adopt it."""
    if mode not in {"rb", "r+b"}:
        raise Refusal("Fixed private stream mode required")
    path = Path(path)
    _private_directory(path.parent)
    _private_file(path)
    before = ordinary(path)
    flags = (os.O_RDONLY if mode == "rb" else os.O_RDWR) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    handle = os.open(path, flags)
    with os.fdopen(handle, mode) as stream:
        opened = os.fstat(stream.fileno())
        if identity(before) != identity(opened):
            raise Refusal("Private stream identity changed before open")
        _private_file(path)
        if identity(ordinary(path)) != identity(opened):
            raise Refusal("Private stream named identity changed before bytes")
        yield stream
        stream.flush()
        if mode != "rb":
            os.fsync(stream.fileno())
        _private_file(path)
        named, pinned = ordinary(path), os.fstat(stream.fileno())
        if any((item.st_dev, item.st_ino, item.st_mode, item.st_nlink) !=
               (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink) for item in (named, pinned)):
            raise Refusal("Private stream identity changed during use")


def _read_file(root, rel, max_bytes, *, private):
    relative(rel)
    if private:
        _private_parents(root, rel)
    if os.name == "posix":
        with anchor_fd(root) as root_fd, parent_fd(root_fd, rel) as (fd, name):
            before_open = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(before_open.st_mode) or before_open.st_nlink != 1 or before_open.st_size > max_bytes:
                raise Refusal("Read refused before open: nonregular, hardlinked or oversized file")
            handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(handle, "rb") as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > max_bytes
                        or identity(before_open) != identity(before)):
                    raise Refusal("Read refused: nonregular, hardlinked or oversized file")
                if private:
                    _private_file(Path(root) / rel)
                    if identity(ordinary(Path(root) / rel)) != identity(before):
                        raise Refusal("Private read named identity changed before bytes")
                data = stream.read(max_bytes + 1)
                after = os.fstat(stream.fileno())
                if identity(before) != identity(after) or len(data) > max_bytes:
                    raise Refusal("File changed during read")
                if private:
                    _private_file(Path(root) / rel)
                    if identity(ordinary(Path(root) / rel)) != identity(after):
                        raise Refusal("Private read named identity changed during read")
                return data
    ancestors(Path(root) / Path(rel).parent)
    path = Path(root) / rel
    before = ordinary(path)
    if before.st_size > max_bytes:
        raise Refusal("Read size cap exceeded")
    if private:
        with _private_existing_stream(path, "rb") as stream:
            opened = os.fstat(stream.fileno())
            data = stream.read(max_bytes + 1)
            if identity(opened) != identity(os.fstat(stream.fileno())) or len(data) > max_bytes:
                raise Refusal("File changed during private fixture read")
            return data
    data = path.read_bytes()
    if identity(before) != identity(ordinary(path)) or len(data) > max_bytes:
        raise Refusal("File changed during portable fixture read")
    return data


def safe_read(root, rel, max_bytes=MAX_BYTES):
    """Bounded ordinary public/source read; does not adopt a private store."""
    return _read_file(root, rel, max_bytes, private=False)


def private_read(root, rel, max_bytes=MAX_BYTES):
    """Private run/control read with actual namespace and file admission."""
    return _read_file(root, rel, max_bytes, private=True)


def identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns, "nlink": info.st_nlink}


def create_file(path, data):
    path = Path(path)
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise Refusal("Artifact size cap exceeded")
    _private_directory(path.parent)
    if os.path.lexists(path):
        raise FileExistsError("Private exclusive target already exists")
    api = _private_api()
    try:
        api.write_private_new(path, data)
    except api.PrivateWorkspaceError as error:
        _privacy_refusal(error)


def replace_control(path, data):
    _private_directory(Path(path).parent)
    _private_file(path)
    tmp = Path(path).parent / ("control-write-" + uuid.uuid4().hex + ".tmp")
    create_file(tmp, data)
    # No truncation fallback; failed replacement leaves a visible recovery file.
    _private_file(path)
    _private_file(tmp)
    os.replace(tmp, path)
    _private_file(path)


def timestamp(value, nullable=False):
    if value is None and nullable:
        return
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z", value):
        raise Refusal("UTC ISO-8601 timestamp ending Z required")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refusal("Invalid UTC timestamp") from exc


def text(value, nullable=False):
    if value is None and nullable:
        return
    if not isinstance(value, str) or len(value) > 16384:
        raise Refusal("Bounded string required")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise Refusal("Unpaired Unicode surrogate refused") from exc


def markdown_text(value):
    """Make imported one-line prose inert in a Markdown viewer too."""
    value = html.escape(str(value)).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value)


def unresolved_actions(ledger):
    """A verified recovery checkpoint preserves, rather than erases, failures.

    The validator separately constrains these references and requires evidence.
    This does not resolve a security finding or imply an installer succeeded.
    """
    resolved = {target for action in ledger["actions"]
                if action["kind"] == "verify" and action["state"] == "completed" and action["evidence_ids"]
                for target in action.get("resolves_action_ids", [])}
    return [action for action in ledger["actions"] if action["state"] not in {"completed", "cancelled"}
            and not (action["state"] in {"failed", "partial"} and action["id"] in resolved)]


class Toolkit:
    def __init__(self, root=None):
        if sys.version_info < (3, 12):
            raise Refusal("Supported Python 3.12+ required; do not auto-install a prerequisite")
        supplied_root = Path(root or DEFAULT_ROOT)
        if not supplied_root.is_absolute() or ".." in supplied_root.parts:
            raise Refusal("Absolute root without traversal segments required")
        self.root = supplied_root.absolute()
        if self.root != DEFAULT_ROOT and DEFAULT_ROOT / "work" not in self.root.parents:
            raise Refusal("Root override must be inside this toolkit work area")
        ancestors(self.root)
        marker = decode(safe_read(self.root, "toolkit.json"))
        self.marker = marker
        try:
            self.toolkit_id = str(uuid.UUID(marker["toolkit_id"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise Refusal("Toolkit identity missing") from exc
        self.work = self.root / "work"
        _private_directory(self.work, create=not os.path.lexists(self.work))

    def area(self, name):
        if not re.fullmatch(r"_[a-z]+", name):
            raise Refusal("Unknown work area")
        _private_directory(self.work)
        path = self.work / name
        _private_directory(path, create=not os.path.lexists(path))
        return path

    @contextlib.contextmanager
    def lock(self, run_id):
        if not RUN_RE.fullmatch(run_id):
            raise Refusal("Invalid run ID")
        # A foreign/missing backend must be rejected before even a lock file is
        # created. Mode/platform rechecks still run inside the acquired lease.
        self.run(run_id)
        path = self.area("_locks") / (run_id + ".lock")
        try:
            create_file(path, encoded({"run_id": run_id, "created_utc": utc_now()}))
        except FileExistsError as exc:
            raise Refusal("Active/unresolved lock; do not automatically retry") from exc
        try:
            yield
        finally:
            _private_file(path)
            path.unlink()

    def run(self, run_id):
        if not isinstance(run_id, str) or not RUN_RE.fullmatch(run_id):
            raise Refusal("Invalid run ID")
        path = self.work / run_id
        ancestors(path)
        _private_directory(self.work)
        _private_directory(path)
        marker_bytes = private_read(path, "run-marker.json")
        marker = decode(marker_bytes)
        owned = decode(private_read(path, "owned-files.json"))
        if (marker.get("backend") != BACKEND or marker.get("toolkit_id") != self.toolkit_id
                or marker.get("run_id") != run_id or marker.get("created_by") != "portable-toolkit"
                or marker.get("creation_mode") not in {"fixture", "real"}
                or marker.get("creation_platform") not in {"windows", "linux", "macos", "unknown"}
                or marker.get("creation_nonce") != owned.get("creation_nonce")
                or digest(marker_bytes) != owned.get("marker_sha256")):
            raise Refusal("Immutable backend/mode/platform/ownership marker mismatch; no migration")
        private_read(path, "actions.jsonl")
        private_read(path, "ledger.json")
        return path, marker, owned

    def contract(self):
        result = decode(safe_read(self.root, "templates/ledger-contract.json"))
        if result.get("schema_version") != "1.0":
            raise Refusal("Unsupported shared ledger contract")
        return result

    def validate_value(self, ledger, run_id):
        contract = self.contract()
        required = contract["required_fields"]
        enums = contract["enums"]
        def record(value, section):
            if not isinstance(value, dict) or any(k not in value for k in required[section]):
                raise Refusal("Missing required fields: " + section)
            for key in contract.get("array_fields", {}).get(section, []):
                if not isinstance(value[key], list):
                    raise Refusal("JSON array required: " + section + "." + key)
            for key in contract.get("boolean_fields", {}).get(section, []):
                if not isinstance(value[key], bool):
                    raise Refusal("Boolean required: " + section + "." + key)
            for key in contract.get("utc_fields", {}).get(section, []):
                timestamp(value[key], key in contract.get("nullable_fields", {}).get(section, []))
        def enum(value, field):
            if value not in enums[field]:
                raise Refusal("Invalid enum: " + field)
        record(ledger, "root")
        if ledger["schema_version"] != "1.0" or ledger["toolkit_id"] != self.toolkit_id:
            raise Refusal("Ledger toolkit/schema mismatch")
        run = ledger["run"]
        record(run, "run")
        if run["id"] != run_id:
            raise Refusal("Ledger run mismatch")
        for field in ("mode", "platform", "phase", "status"):
            enum(run[field], "run." + field)
        for key in ("created_utc", "updated_utc"):
            timestamp(run[key])
        text(run["purpose"])
        if not isinstance(run["pending_restart"], bool):
            raise Refusal("Explicit boolean restart checkpoint required")
        sets = ("coverage", "components", "findings", "sources", "evidence", "actions", "approvals")
        sections = {"coverage": "coverage", "components": "component", "findings": "finding",
                    "sources": "source", "evidence": "evidence", "actions": "action", "approvals": "approval"}
        ids = {}
        for group in sets:
            if not isinstance(ledger[group], list) or len(ledger[group]) > 10000:
                raise Refusal("Bounded JSON array required: " + group)
            ids[group] = set()
            for item in ledger[group]:
                record(item, sections[group])
                if not isinstance(item["id"], str) or not ID_RE.fullmatch(item["id"]) or item["id"] in ids[group]:
                    raise Refusal("Missing/duplicate/unsafe record ID")
                ids[group].add(item["id"])
        def refs(item, field, group):
            value = item[field]
            if not isinstance(value, list) or any(not isinstance(v, str) or v not in ids[group] for v in value):
                raise Refusal("Unknown reference: " + field)
        for c in ledger["components"]:
            for field in ("update_state", "security_state", "compatibility_state", "owner_scope"):
                enum(c[field], "component." + field)
            for field in ("name", "kind", "next_step"):
                text(c[field])
            for field in ("installed_version", "reviewed_target", "available_release", "agent_id"):
                text(c[field], True)
            for field in ("architecture", "manager", "channel", "default_resolution", "owner_component_id"):
                if field in c:
                    text(c[field], True)
            owner_id = c.get("owner_component_id")
            if owner_id is not None and owner_id not in ids["components"]:
                raise Refusal("Unknown exact owning-component reference")
            refs(c, "evidence_ids", "evidence")
            refs(c, "finding_ids", "findings")
        for c in ledger["coverage"]:
            enum(c["state"], "coverage.state")
            text(c["scope"]); text(c["limits"])
        for s in ledger["sources"]:
            enum(s["authority"], "source.authority")
            timestamp(s["retrieved_utc"], True); text(s["title"])
            if not isinstance(s["provenance_verified"], bool) or not isinstance(s["checks"], list):
                raise Refusal("Explicit provenance/checks required")
            for check in s["checks"]:
                text(check)
            if s["provenance_verified"] and not s["checks"]:
                raise Refusal("Provenance claim lacks ownership checks")
            if s["url"] is None:
                if s["authority"] not in {"installed_metadata", "owner_report"}:
                    raise Refusal("Web source URL required")
            else:
                text(s["url"])
                parsed = urlsplit(s["url"])
                if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                        or parsed.password is not None or parsed.query or parsed.fragment):
                    raise Refusal("Canonical public HTTPS URL without credentials/query/fragment required")
        for e in ledger["evidence"]:
            relative(e["relative_path"])
            if not e["relative_path"].startswith("evidence/") or not HASH_RE.fullmatch(e["sha256"]):
                raise Refusal("Evidence path/hash invalid")
            timestamp(e["observed_utc"])
            for key in ("kind", "scope", "limits"):
                text(e[key])
        for f in ledger["findings"]:
            enum(f["state"], "finding.state")
            text(f["kind"]); text(f["claim"])
            if f["component_id"] is not None and f["component_id"] not in ids["components"]:
                raise Refusal("Unknown finding component")
            refs(f, "evidence_ids", "evidence"); refs(f, "source_ids", "sources")
            if not isinstance(f["conditions"], list):
                raise Refusal("Finding conditions array required")
            for value in f["conditions"]:
                text(value)
        for a in ledger["approvals"]:
            enum(a["decision"], "approval.decision")
            timestamp(a["recorded_utc"])
            refs(a, "action_ids", "actions")
            text(a["scope"]); text(a["authorization_quote"])
            if a["decision"] == "approved" and (not a["authorization_quote"].strip()
                    or not a["action_ids"] or not isinstance(a["plan_sha256"], str)
                    or not HASH_RE.fullmatch(a["plan_sha256"])):
                raise Refusal("Exact actions/hash/actual owner quotation required")
        approvals = {a["id"]: a for a in ledger["approvals"]}
        actions = {a["id"]: a for a in ledger["actions"]}
        for a in ledger["actions"]:
            enum(a["kind"], "action.kind"); enum(a["state"], "action.state")
            refs(a, "component_ids", "components"); refs(a, "evidence_ids", "evidence")
            if a["automatic_retry"] is not False:
                raise Refusal("Automatic retry must be false")
            timestamp(a["started_utc"], True); timestamp(a["finished_utc"], True)
            text(a["outcome"], True)
            if "group_id" in a and a["group_id"] is not None:
                text(a["group_id"])
                if a["group_id"] != a["group_id"].strip():
                    raise Refusal("Group ID cannot have leading/trailing whitespace")
            if "resolves_action_ids" in a:
                targets = a["resolves_action_ids"]
                if not isinstance(targets, list) or any(not isinstance(v, str) for v in targets) or len(targets) != len(set(targets)):
                    raise Refusal("Resolution IDs must be a unique array of exact references")
                if targets and (a["kind"] != "verify" or any(target == a["id"] or target not in actions
                        or actions[target]["state"] not in {"failed", "partial"} for target in targets)):
                    raise Refusal("Only a new verification action can resolve failed/partial history")
                if targets and a["state"] == "completed" and not a["evidence_ids"]:
                    raise Refusal("Completed recovery checkpoint requires evidence receipts")
            if a["state"] == "completed" and a["finished_utc"] is None:
                raise Refusal("Completed action needs finish time")
            if a["kind"] in MUTATIONS and a["state"] in {"approved", "running", "completed"}:
                approval = approvals.get(a["approval_id"], {})
                if approval.get("decision") != "approved" or a["id"] not in approval.get("action_ids", []):
                    raise Refusal("Mutating action lacks exact approved plan/action binding")
                if a["state"] == "completed" and not a["evidence_ids"]:
                    raise Refusal("Completed mutation needs evidence receipts")
        diagnosis = ledger["diagnosis"]
        record(diagnosis, "diagnosis")
        enum(diagnosis["status"], "diagnosis.status")
        if not isinstance(diagnosis["hypotheses"], list) or not isinstance(diagnosis["repair_approved"], bool):
            raise Refusal("Diagnosis arrays/boolean required")
        for key in ("original_cause", "least_disruptive_fix"):
            text(diagnosis[key], True)
        text(diagnosis["uncertainty"])
        hypothesis_ids = set()
        for h in diagnosis["hypotheses"]:
            record(h, "hypothesis"); text(h["claim"])
            if not isinstance(h["id"], str) or not ID_RE.fullmatch(h["id"]) or h["id"] in hypothesis_ids:
                raise Refusal("Missing/duplicate/unsafe hypothesis ID")
            hypothesis_ids.add(h["id"])
            enum(h["state"], "hypothesis.state"); refs(h, "evidence_ids", "evidence")
            if not isinstance(h["alternatives"], list):
                raise Refusal("Diagnosis alternatives array required")
            for alt in h["alternatives"]:
                record(alt, "alternative"); text(alt["claim"])
                enum(alt["state"], "alternative.state"); refs(alt, "evidence_ids", "evidence")
        if diagnosis["status"] == "cause_supported" and (not diagnosis["original_cause"] or not diagnosis["original_cause"].strip() or not any(
                h["state"] == "supported" and h["evidence_ids"] for h in diagnosis["hypotheses"])):
            raise Refusal("Original cause needs supported evidence-linked hypothesis")
        if run["status"] == "completed" and (run["phase"] != "closed" or run["pending_restart"] or unresolved_actions(ledger)):
            raise Refusal("Completed run cannot contain unfinished work or restart")
        return True

    def new_run(self, mode="fixture", platform="unknown", purpose="Assessment record"):
        if mode not in {"fixture", "real"} or platform not in {"windows", "linux", "macos", "unknown"}:
            raise Refusal("Invalid mode/platform")
        text(purpose)
        if mode == "real":
            self.assert_native_platform(platform)
        run_id = "run-" + uuid.uuid4().hex
        path = self.work / run_id
        now = utc_now()
        marker = {"schema_version": "1.0", "toolkit_id": self.toolkit_id, "run_id": run_id,
                  "created_by": "portable-toolkit", "creation_nonce": uuid.uuid4().hex,
                  "creation_mode": mode, "creation_platform": platform, "backend": BACKEND, "created_utc": now}
        marker_bytes = encoded(marker)
        owned = {"schema_version": "1.0", "creation_nonce": marker["creation_nonce"],
                 "marker_sha256": digest(marker_bytes), "directories": [], "files": []}
        ledger = {"schema_version": "1.0", "toolkit_id": self.toolkit_id,
                  "run": {"id": run_id, "mode": mode, "platform": platform, "phase": "assessment", "status": "draft",
                          "created_utc": now, "updated_utc": now, "purpose": purpose, "pending_restart": False},
                  "coverage": [], "components": [], "findings": [], "sources": [], "evidence": [],
                  "actions": [], "approvals": [], "diagnosis": {"status": "not_started", "hypotheses": [],
                  "original_cause": None, "uncertainty": "Not investigated", "least_disruptive_fix": None, "repair_approved": False}}
        self.validate_value(ledger, run_id)
        _private_directory(self.work)
        _private_directory(path, create=True)
        for name, data in (("run-marker.json", marker_bytes), ("ledger.json", encoded(ledger)),
                           ("owned-files.json", encoded(owned)), ("actions.jsonl", b"")):
            create_file(path / name, data)
        self._artifact(path, owned, "PLANS.md", "plan", b"# Run plan\n\nNo mutation approved.\n", False)
        self._audit(path, run_id, "NewRun", {"collection_performed": False})
        return {"run_id": run_id, "mode": mode, "platform": platform, "backend": BACKEND}

    @staticmethod
    def assert_native_platform(platform):
        host = "linux" if sys.platform.startswith("linux") else "macos" if sys.platform == "darwin" else "unknown"
        if not native_capable() or platform != host or host == "unknown":
            raise Refusal("Real operation requires matching native Linux/macOS and POSIX capabilities")

    def _audit(self, path, run_id, operation, details):
        target = path / "actions.jsonl"
        data = encoded({"time_utc": utc_now(), "run_id": run_id, "operation": operation,
                        "details": details}) + b"\n"
        # Preserve JSONL history through a newly verified private file and atomic
        # replacement; raw append must not bypass actual permission admission.
        replace_control(target, private_read(path, "actions.jsonl") + data)

    def _validate_bound(self, path, marker, owned, ledger):
        self.validate_value(ledger, marker["run_id"])
        if ledger["run"]["mode"] != marker["creation_mode"] or ledger["run"]["platform"] != marker["creation_platform"]:
            raise Refusal("Immutable creation mode/platform changed; no fixture promotion")
        rows = {f["relative_path"]: f for f in owned["files"]}
        if len(rows) != len(owned["files"]):
            raise Refusal("Duplicate ownership record")
        for ev in ledger["evidence"]:
            row = rows.get(ev["relative_path"])
            data = private_read(path, ev["relative_path"])
            if not row or row["sha256"] != ev["sha256"] or digest(data) != ev["sha256"]:
                raise Refusal("Evidence lacks unchanged positive ownership/hash")
        active = [a for a in ledger["actions"] if a["kind"] in MUTATIONS and a["state"] in {"approved", "running"}]
        if active:
            plan_sha = digest(private_read(path, "PLANS.md"))
            if rows.get("PLANS.md", {}).get("sha256") != plan_sha:
                raise Refusal("Current plan ownership/hash changed")
            approvals = {a["id"]: a for a in ledger["approvals"]}
            if any(approvals[a["approval_id"]]["plan_sha256"] != plan_sha for a in active):
                raise Refusal("Active approval does not match exact current plan")

    def read_ledger(self, run_id):
        path, marker, owned = self.run(run_id)
        data = private_read(path, "ledger.json")
        ledger = decode(data)
        self._validate_bound(path, marker, owned, ledger)
        return ledger

    def validate(self, run_id):
        ledger = self.read_ledger(run_id)
        return {"valid": True, "run_id": run_id, "mode": ledger["run"]["mode"], "backend": BACKEND}

    def set_ledger(self, run_id, ledger):
        with self.lock(run_id):
            path, marker, owned = self.run(run_id)
            before = self.read_ledger(run_id)
            old = {a["id"]: a for a in before["actions"]}
            new = {a["id"]: a for a in ledger.get("actions", [])}
            for action_id, action in old.items():
                if action["state"] in {"failed", "partial"} and new.get(action_id) != action:
                    raise Refusal("Failed/partial action is immutable; new reviewed recovery action required")
            self._validate_bound(path, marker, owned, ledger)
            replace_control(path / "ledger.json", encoded(ledger))
            self._audit(path, run_id, "SetLedger", {"maintenance_executed": False})
        return self.validate(run_id)

    def _artifact(self, path, owned, rel, role, data, rollback=False):
        relative(rel)
        if role == "plan":
            if rel != "PLANS.md":
                raise Refusal("Plan target mismatch")
        elif role not in ROLE_ROOTS or rel.split("/")[0] != ROLE_ROOTS[role]:
            raise Refusal("Artifact role/path mismatch")
        if not isinstance(rollback, bool):
            raise Refusal("Rollback flag must be boolean")
        if rollback and role != "backup":
            raise Refusal("Needed recovery material must use the backup role and backups/ path")
        path_key = os.path.normcase(rel)
        rows = [f for f in owned["files"] if os.path.normcase(f["relative_path"]) == path_key]
        if rows and (len(rows) != 1 or rows[0]["relative_path"] != rel):
            raise Refusal("Ambiguous ownership or nonexact registered path spelling")
        full = path / rel
        if full.exists() or full.is_symlink():
            if len(rows) != 1 or rows[0]["sha256"] != digest(data) or private_read(path, rel) != data:
                raise Refusal("Unknown/changed artifact; immutable no-overwrite rule")
            if rows[0]["role"] != role or rows[0]["rollback_needed"] is not rollback or rows[0]["bytes"] != len(data):
                raise Refusal("Existing artifact protection/classification differs; no silent metadata change")
            return rows[0]
        if rows:
            raise Refusal("Registered artifact is missing; no silent recreation or duplicate ownership")
        parent = Path(rel).parent
        so_far = Path()
        registered_dirs = {os.path.normcase(value): value for value in owned["directories"]}
        if len(registered_dirs) != len(owned["directories"]):
            raise Refusal("Duplicate or ambiguous directory ownership")
        pending_dirs = []
        for part in parent.parts:
            so_far = so_far / part
            subrel = so_far.as_posix()
            target = path / so_far
            registered = registered_dirs.get(os.path.normcase(subrel))
            if registered is not None and registered != subrel:
                raise Refusal("Nonexact registered directory spelling")
            if target.exists() or target.is_symlink():
                _private_directory(target)
                if registered is None:
                    raise Refusal("Unknown existing directory")
            else:
                if registered is not None:
                    raise Refusal("Registered artifact parent is missing; no silent recreation")
                pending_dirs.append((target, subrel))
        # Complete the refusal checks before creating any new parent or bytes.
        for target, subrel in pending_dirs:
            _private_directory(target, create=True)
            owned["directories"].append(subrel)
        create_file(full, data)
        row = {"relative_path": rel, "role": role, "bytes": len(data), "sha256": digest(data), "rollback_needed": rollback}
        owned["files"].append(row)
        replace_control(path / "owned-files.json", encoded(owned))
        return row

    def write_artifact(self, run_id, rel, role, data, rollback=False):
        if role == "report" or role == "plan":
            raise Refusal("Use structured report/plan operations")
        if not isinstance(data, bytes):
            raise Refusal("Artifact bytes required")
        with self.lock(run_id):
            path, _, owned = self.run(run_id)
            row = self._artifact(path, owned, rel, role, data, rollback)
            self._audit(path, run_id, "WriteArtifact", {"relative_path": rel, "role": role})
            return row

    def release_recovery(self, run_id, rel, expected_sha256, evidence_ids, authorization_quote, reason):
        """Record an owner-reviewed retirement of ONE no-longer-needed backup.

        The caller must establish actual current-owner consent. This is not a
        generic metadata editor and never deletes or changes artifact bytes.
        """
        relative(rel)
        if not isinstance(expected_sha256, str) or not HASH_RE.fullmatch(expected_sha256):
            raise Refusal("Exact artifact SHA-256 required")
        for value in (authorization_quote, reason):
            text(value)
            if not value.strip():
                raise Refusal("Actual owner quotation and recovery-release reason required")
        if (not isinstance(evidence_ids, list) or not evidence_ids
                or any(not isinstance(value, str) for value in evidence_ids)
                or len(evidence_ids) != len(set(evidence_ids))):
            raise Refusal("Nonempty unique evidence IDs required")
        with self.lock(run_id):
            path, _, owned = self.run(run_id)
            ledger = self.read_ledger(run_id)
            if (ledger["run"]["status"] != "completed" or ledger["run"]["phase"] != "closed"
                    or ledger["run"]["pending_restart"] or unresolved_actions(ledger)):
                raise Refusal("Recovery release requires a closed completed run without pending work/restart")
            receipts = {value for action in ledger["actions"] if action["kind"] == "verify" and action["state"] == "completed"
                        for value in action["evidence_ids"]}
            evidence = {item["id"] for item in ledger["evidence"]}
            if any(value not in evidence or value not in receipts for value in evidence_ids):
                raise Refusal("Recovery release evidence must be unchanged owned completed-verification receipts")
            rows = [item for item in owned["files"] if item["relative_path"] == rel]
            if len(rows) != 1 or rows[0]["role"] != "backup" or rows[0]["rollback_needed"] is not True:
                raise Refusal("Exactly one positively owned protected backup artifact required")
            row = rows[0]
            data = private_read(path, rel)
            if row["sha256"] != expected_sha256 or digest(data) != expected_sha256 or row["bytes"] != len(data):
                raise Refusal("Recovery artifact changed; protection retained")
            details = {"relative_path": rel, "sha256": expected_sha256, "before_rollback_needed": True,
                       "after_rollback_needed": False, "evidence_ids": evidence_ids, "reason": reason,
                       "authorization_quote": authorization_quote, "deletion_performed": False}
            self._audit(path, run_id, "ReleaseRecoveryIntent", details)
            row["rollback_needed"] = False
            replace_control(path / "owned-files.json", encoded(owned))
            self._audit(path, run_id, "ReleaseRecoveryCompleted", details)
            return {"run_id": run_id, "relative_path": rel, "sha256": expected_sha256,
                    "rollback_needed": False, "deletion_performed": False, "fresh_cleanup_preview_required": True}

    def set_plan(self, run_id, content):
        text(content)
        with self.lock(run_id):
            path, _, owned = self.run(run_id)
            ledger = self.read_ledger(run_id)
            if any(a["kind"] in MUTATIONS and a["state"] in {"approved", "running"} for a in ledger["actions"]):
                raise Refusal("Hold active approvals before changing their plan")
            row = next(f for f in owned["files"] if f["relative_path"] == "PLANS.md")
            if digest(private_read(path, "PLANS.md")) != row["sha256"]:
                raise Refusal("Existing plan changed")
            data = content.encode("utf-8")
            replace_control(path / "PLANS.md", data)
            row.update(sha256=digest(data), bytes=len(data))
            replace_control(path / "owned-files.json", encoded(owned))
            self._audit(path, run_id, "SetPlan", {"plan_sha256": row["sha256"], "maintenance_executed": False})
            return {"plan_sha256": row["sha256"]}

    def build_report(self, run_id):
        with self.lock(run_id):
            path, marker, owned = self.run(run_id)
            data = private_read(path, "ledger.json")
            ledger = decode(data)
            self._validate_bound(path, marker, owned, ledger)
            template_bytes = safe_read(self.root, "templates/report.html")
            template = template_bytes.decode("utf-8-sig")
            # Branding is local, positive-allowlisted PNG data, never markup
            # obtained from a ledger/source or an arbitrary image URL.
            branding = self.marker.get("branding", {})
            logo = branding.get("report_logo")
            markup = ""
            if logo:
                relative(logo)
                listing = decode(safe_read(self.root, "templates/export-allowlist.json"))["files"]
                if not logo.startswith("assets/") or not logo.endswith(".png") or logo not in listing:
                    raise Refusal("Brand PNG must be a positive-allowlisted assets file")
                image = safe_read(self.root, logo, 2_000_000)
                if len(image) < 33 or image[:8] != b"\x89PNG\r\n\x1a\n" or image[12:16] != b"IHDR":
                    raise Refusal("Invalid bounded PNG header")
                width, height = int.from_bytes(image[16:20], "big"), int.from_bytes(image[20:24], "big")
                if not 0 < width <= 4096 or not 0 < height <= 4096:
                    raise Refusal("Brand PNG dimensions refused")
                markup = '<img class="brand-logo" alt="PatchCairn" src="data:image/png;base64,' + base64.b64encode(image).decode("ascii") + '">'
            if "@@BRAND_LOGO@@" in template:
                if template.count("@@BRAND_LOGO@@") != 1:
                    raise Refusal("Brand template token contract changed")
                template = template.replace("@@BRAND_LOGO@@", markup)
            if template.count("@@LEDGER_SHA@@") != 1 or template.count("@@DATA@@") != 1:
                raise Refusal("Report template token contract changed")
            sha, template_sha = digest(data), digest(template.encode("utf-8"))
            prefix = "reports/" + sha[:16] + "-" + template_sha[:12]
            completed = [a for a in ledger["actions"] if a["state"] == "completed"]
            summary = {"schema_version": "1.0", "run_id": run_id, "mode": ledger["run"]["mode"],
                       "ledger_sha256": sha, "component_records": len(ledger["components"]),
                       "completed_action_records": len(completed),
                       "completed_action_groups": len({a.get("group_id") or a["id"] for a in completed}),
                       "open_finding_records": sum(f["state"] in {"open", "conditional", "held", "unknown"} for f in ledger["findings"]),
                       "counts_are_not_security_clearance": True, "generated_from_one_ledger_snapshot": True}
            for output, field in (("update_states", "update_state"), ("security_states", "security_state"), ("compatibility_states", "compatibility_state")):
                summary[output] = dict(collections.Counter(c[field] for c in ledger["components"]))
            payload = encoded({"ledger": ledger, "summary": summary}).decode("ascii").replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            rendered = template.replace("@@LEDGER_SHA@@", sha).replace("@@DATA@@", payload).encode("utf-8")
            fields = ["id", "name", "installed_version", "reviewed_target", "available_release", "update_state", "security_state", "compatibility_state", "owner_scope", "agent_id", "next_step", "ledger_sha256"]
            buffer = io.StringIO(newline="")
            writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
            writer.writerow(fields)
            for c in ledger["components"]:
                values = []
                for field in fields:
                    value = sha if field == "ledger_sha256" else c.get(field)
                    value = "" if value is None else str(value)
                    stripped = value
                    while stripped and (stripped[0].isspace() or unicodedata.category(stripped[0])[0] in {"Z", "C"}):
                        stripped = stripped[1:]
                    if value and (value[0].isspace() or unicodedata.category(value[0])[0] == "C" or stripped.startswith(("=", "+", "-", "@"))):
                        value = "'" + value
                    values.append(value)
                writer.writerow(values)
            notice = "FICTIONAL DEMONSTRATION - not this computer; no real audit or update performed." if ledger["run"]["mode"] == "fixture" else (
                "Assessment has not started: zero components is not a clean-computer result." if not ledger["components"] else "Scoped saved evidence; uninspected areas remain unknown.")
            human = ["# PatchCairn run summary", "", notice, "Run phase: " + ledger["run"]["phase"] + "; state: " + ledger["run"]["status"],
                     "Component records: " + str(summary["component_records"]) + "; completed action records: " + str(len(completed)) + "; completed action groups: " + str(summary["completed_action_groups"]),
                     "Version, security and compatibility counts are independent dimensions, not an all-secure percentage.",
                     "Diagnosis: " + ledger["diagnosis"]["status"] + "; original cause: " + markdown_text(ledger["diagnosis"]["original_cause"] or "Not established"),
                     "Uncertainty: " + markdown_text(ledger["diagnosis"]["uncertainty"])]
            for c in ledger["components"]:
                human.append("- " + markdown_text(c["name"]) + " | update: " + c["update_state"] + " | security: " + c["security_state"] + " | compatibility: " + c["compatibility_state"] + " | next: " + markdown_text(c["next_step"]))
            human += ["", "Canonical ledger SHA-256: " + sha]
            outputs = {"ledger.snapshot.json": data, "summary.json": encoded(summary), "components.csv": buffer.getvalue().encode("utf-8"),
                       "report.html": rendered, "summary.md": "\n".join(human).encode("utf-8")}
            for name, value in outputs.items():
                self._artifact(path, owned, prefix + "/" + name, "report", value)
            self._audit(path, run_id, "BuildReport", {"ledger_sha256": sha, "template_sha256": template_sha})
            return {"run_id": run_id, "ledger_sha256": sha, "template_sha256": template_sha,
                    "report": str(path / prefix / "report.html"), "summary": str(path / prefix / "summary.json")}

    @staticmethod
    def _assert_fresh_baseline(ledger, owned):
        if ledger["run"]["mode"] != "real":
            raise Refusal("Fixtures never collect host inventory")
        if ledger["run"]["phase"] != "assessment" or ledger["run"]["status"] not in {"draft", "active"}:
            raise Refusal("Baseline collection requires a fresh assessment run")
        prior_baseline = any(row["relative_path"].startswith("evidence/baseline-") and row["relative_path"].endswith(".json")
                             for row in owned["files"])
        if ledger["components"] or prior_baseline:
            raise Refusal("Existing inventory or baseline attempt requires a fresh run; no implicit reconciliation")

    def collect_baseline(self, run_id):
        # Refuse repeat/manual inventory before even creating a cooperative lock.
        _, _, owned = self.run(run_id)
        self._assert_fresh_baseline(self.read_ledger(run_id), owned)
        # One cooperative lease covers observation and canonical reconciliation;
        # a concurrent helper cannot silently overwrite a newer ledger snapshot.
        with self.lock(run_id):
            path, marker, owned = self.run(run_id)
            ledger = self.read_ledger(run_id)
            self._assert_fresh_baseline(ledger, owned)
            self.assert_native_platform(ledger["run"]["platform"])
            module_name = "collect_linux" if ledger["run"]["platform"] == "linux" else "collect_macos"
            module = __import__(module_name)
            result = module.collect()
            if result.get("platform") != ledger["run"]["platform"] or result.get("collection_mode", "real") != "real":
                raise Refusal("Collector platform or real/fixture mode mismatch")
            timestamp(result["observed_utc"])
            if not isinstance(result.get("observations"), list) or not isinstance(result.get("limits"), list):
                raise Refusal("Collector observations and limits arrays required")
            for limit in result["limits"]:
                text(limit)
            suffix = uuid.uuid4().hex
            rel = "evidence/baseline-" + suffix + ".json"
            row = self._artifact(path, owned, rel, "evidence", encoded(result))
            evidence_id = "baseline-" + suffix
            ledger["evidence"].append({"id": evidence_id, "relative_path": rel, "sha256": row["sha256"], "kind": "installed_metadata",
                "observed_utc": result["observed_utc"], "scope": "Selected native OS and software metadata",
                "limits": "; ".join(result["limits"])[:16384]})
            ledger["coverage"].append({"id": "coverage-" + suffix, "scope": "Selected native baseline collector",
                "state": "partial", "limits": "Bounded installed metadata only; no complete dependency, security or compatibility assessment. " + "; ".join(result["limits"])[:15000]})
            for index, observation in enumerate(result["observations"]):
                if not isinstance(observation.get("name"), str):
                    continue
                ledger["components"].append({"id": "component-" + suffix + "-" + str(index), "name": observation["name"],
                    "kind": observation.get("kind", "software"), "installed_version": observation.get("version"),
                    "reviewed_target": None, "available_release": None, "update_state": "observed", "security_state": "not_assessed",
                    "compatibility_state": "not_tested", "owner_scope": observation.get("scope") if observation.get("scope") in {"system", "machine", "user", "vendor_bundle", "project", "portable"} else "unknown",
                    "evidence_ids": [evidence_id], "finding_ids": [], "agent_id": "native-baseline", "next_step": "Research official support, advisories and compatible target; inventory is not security clearance."})
            ledger["run"]["updated_utc"] = utc_now()
            self._validate_bound(path, marker, owned, ledger)
            replace_control(path / "ledger.json", encoded(ledger))
            self._audit(path, run_id, "CollectBaseline", {"evidence_id": evidence_id, "mutation_performed": False})
            return {"run_id": run_id, "evidence_id": evidence_id, "observation_count": len(result["observations"])}

    def _cleanup_state(self, ledger, owned, scope):
        if scope not in {"Temporary", "CompletedRun"}:
            raise Refusal("Unknown cleanup scope")
        if ledger["run"]["pending_restart"] or unresolved_actions(ledger):
            raise Refusal("Active, unresolved or restart work prevents cleanup")
        if any(f["rollback_needed"] for f in owned["files"]):
            raise Refusal("Required rollback artifact prevents cleanup")
        if scope == "CompletedRun" and (ledger["run"]["phase"] != "closed" or ledger["run"]["status"] != "completed"):
            raise Refusal("Full purge requires a closed completed run")

    def _inventory(self, path, owned):
        """Capture ONLY positive inventory; refuse any unknown entry, no recursion fallback."""
        files = set(CONTROLS) | {f["relative_path"] for f in owned["files"]}
        dirs = set(owned["directories"])
        if len(files) != len(CONTROLS) + len(owned["files"]) or len(dirs) != len(owned["directories"]):
            raise Refusal("Duplicate/control-colliding ownership path")
        for rel in files | dirs:
            relative(rel)
        inventory = []
        with anchor_fd(path) as root_fd:
            for rel in sorted(dirs | {""}):
                _private_directory(path / rel)
                if rel:
                    with parent_fd(root_fd, rel) as (parent, name):
                        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                else:
                    fd = os.dup(root_fd)
                try:
                    expected = {p[len(rel) + 1:] if rel else p for p in files | dirs if (p.rsplit("/", 1)[0] if "/" in p else "") == rel}
                    if set(os.listdir(fd)) != expected:
                        raise Refusal("Unknown/missing run entry; cleanup refused")
                    inventory.append({"relative_path": rel, "kind": "directory", **identity(os.fstat(fd)), "sha256": None})
                finally:
                    os.close(fd)
            for rel in sorted(files):
                _private_parents(path, rel)
                with parent_fd(root_fd, rel) as (parent, name):
                    before_open = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if not stat.S_ISREG(before_open.st_mode) or before_open.st_nlink != 1 or before_open.st_size > MAX_BYTES:
                        raise Refusal("Nonregular/hardlinked/oversized cleanup entry refused before open")
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    with os.fdopen(fd, "rb") as stream:
                        info = os.fstat(stream.fileno())
                        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES
                                or identity(before_open) != identity(info)):
                            raise Refusal("Nonregular/hardlinked/oversized cleanup entry")
                        _private_file(path / rel)
                        if identity(ordinary(path / rel)) != identity(info):
                            raise Refusal("Private cleanup entry identity changed before bytes")
                        sha = digest(stream.read(MAX_BYTES + 1))
                        if identity(info) != identity(os.fstat(stream.fileno())):
                            raise Refusal("Cleanup entry changed during capture")
                        _private_file(path / rel)
                        inventory.append({"relative_path": rel, "kind": "file", **identity(info), "sha256": sha})
        rows = {f["relative_path"]: f for f in owned["files"]}
        for item in inventory:
            row = rows.get(item["relative_path"])
            if row and (item["sha256"] != row["sha256"] or item["size"] != row["bytes"]):
                raise Refusal("Owned artifact changed")
        return sorted(inventory, key=lambda item: item["relative_path"])

    @staticmethod
    def _targets(owned, scope, inventory):
        if scope == "CompletedRun":
            return sorted(item["relative_path"] for item in inventory)
        targets = {f["relative_path"] for f in owned["files"] if f["role"] == "temporary"}
        for directory in owned["directories"]:
            if directory == "temporary" or directory.startswith("temporary/"):
                if not any(f["relative_path"].startswith(directory + "/") and f["relative_path"] not in targets for f in owned["files"]):
                    targets.add(directory)
        return sorted(targets)

    def plan_cleanup(self, run_id, scope="Temporary"):
        if not native_capable():
            raise Refusal("Native POSIX cleanup cannot run on this host; no fallback")
        with self.lock(run_id):
            path, marker, owned = self.run(run_id)
            ledger = self.read_ledger(run_id)
            if ledger["run"]["mode"] == "real":
                self.assert_native_platform(ledger["run"]["platform"])
            self._cleanup_state(ledger, owned, scope)
            self._audit(path, run_id, "PlanCleanup", {"scope": scope, "deletion_performed": False})
            inventory = self._inventory(path, owned)
            targets = self._targets(owned, scope, inventory)
            plan_id = "plan-" + uuid.uuid4().hex
            directory = self.area("_plans") / plan_id
            _private_directory(directory, create=True)
            now = datetime.now(timezone.utc)
            plan = {"schema_version": "1.0", "backend": BACKEND, "toolkit_id": self.toolkit_id, "plan_id": plan_id,
                    "run_id": run_id, "scope": scope, "action_id": "cleanup-" + uuid.uuid4().hex,
                    "created_utc": utc_now(), "expires_utc": (now + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
                    "ledger_sha256": digest(private_read(path, "ledger.json")), "run_creation_nonce": marker["creation_nonce"],
                    "inventory": inventory, "targets": targets, "preview_only": True, "owner_approval_created": False,
                    "selected_logical_bytes": sum(i["size"] for i in inventory if i["kind"] == "file" and i["relative_path"] in targets),
                    "no_follow": True, "exclusive_workspace_required": True, "not_an_os_sandbox": True}
            data = encoded(plan)
            create_file(directory / "plan.json", data)
            return {"plan_id": plan_id, "plan_sha256": digest(data), "scope": scope, "targets": targets,
                    "logical_bytes": plan["selected_logical_bytes"], "deletion_performed": False}

    def _load_cleanup_plan(self, plan_id, expected_hash):
        if not re.fullmatch(r"plan-[a-f0-9]{32}", plan_id) or not HASH_RE.fullmatch(expected_hash):
            raise Refusal("Exact cleanup plan ID/hash required")
        directory = self.area("_plans") / plan_id
        ancestors(directory)
        data = private_read(directory, "plan.json")
        if digest(data) != expected_hash:
            raise Refusal("Cleanup plan hash changed")
        plan = decode(data)
        timestamp(plan["expires_utc"])
        if plan.get("backend") != BACKEND or plan.get("toolkit_id") != self.toolkit_id or plan.get("plan_id") != plan_id:
            raise Refusal("Cleanup plan identity/backend mismatch")
        if datetime.fromisoformat(plan["expires_utc"].replace("Z", "+00:00")) < datetime.now(timezone.utc):
            raise Refusal("Cleanup plan expired")
        _, marker, _ = self.run(plan["run_id"])
        if marker["creation_nonce"] != plan["run_creation_nonce"]:
            raise Refusal("Cleanup run identity changed")
        return directory, plan

    def record_cleanup_approval(self, plan_id, expected_hash, authorization_quote, acknowledge=False):
        """Caller must establish actual current-owner consent; imported fields cannot."""
        text(authorization_quote)
        if not authorization_quote.strip() or not isinstance(acknowledge, bool):
            raise Refusal("Actual owner quotation and boolean acknowledgment required")
        _, plan = self._load_cleanup_plan(plan_id, expected_hash)
        if plan["scope"] == "CompletedRun" and not acknowledge:
            raise Refusal("Explicit acknowledgment of losing records and backups required")
        approval_id = "approval-" + uuid.uuid4().hex
        approval = {"schema_version": "1.0", "backend": BACKEND, "actor": "owner", "decision": "approved",
                    "toolkit_id": self.toolkit_id, "run_id": plan["run_id"], "plan_id": plan_id, "plan_sha256": expected_hash,
                    "action_ids": [plan["action_id"]], "scope": plan["scope"], "authorization_quote": authorization_quote,
                    "recorded_utc": utc_now(), "acknowledge_records_and_backups_deletion": acknowledge}
        create_file(self.area("_approvals") / (approval_id + ".json"), encoded(approval))
        return {"approval_id": approval_id, "not_independent_proof_of_human_consent": True}

    def apply_cleanup(self, plan_id, expected_hash, approval_id):
        if not native_capable():
            raise Refusal("Native POSIX cleanup cannot run on this host; no fallback")
        directory, plan = self._load_cleanup_plan(plan_id, expected_hash)
        if not re.fullmatch(r"approval-[a-f0-9]{32}", approval_id):
            raise Refusal("Exact approval ID required")
        approval = decode(private_read(self.area("_approvals"), approval_id + ".json"))
        if (approval.get("backend") != BACKEND or approval.get("actor") != "owner" or approval.get("decision") != "approved"
                or approval.get("toolkit_id") != self.toolkit_id or approval.get("run_id") != plan["run_id"]
                or approval.get("plan_id") != plan_id or approval.get("plan_sha256") != expected_hash
                or approval.get("action_ids") != [plan["action_id"]] or approval.get("scope") != plan["scope"]
                or not isinstance(approval.get("authorization_quote"), str) or not approval["authorization_quote"].strip()
                or (plan["scope"] == "CompletedRun" and approval.get("acknowledge_records_and_backups_deletion") is not True)):
            raise Refusal("Exact owner-recorded approval binding required")
        timestamp(approval["recorded_utc"])
        age = datetime.now(timezone.utc) - datetime.fromisoformat(approval["recorded_utc"].replace("Z", "+00:00"))
        if age < timedelta(minutes=-1) or age > timedelta(hours=24):
            raise Refusal("Stale approval")
        with self.lock(plan["run_id"]):
            receipt_path = directory / "attempt.json"
            if receipt_path.exists():
                raise Refusal("Consumed cleanup plan; no automatic retry")
            receipt = {"plan_id": plan_id, "plan_sha256": expected_hash, "approval_id": approval_id,
                       "run_id": plan["run_id"], "status": "running", "started_utc": utc_now(),
                       "finished_utc": None, "files": 0, "directories": 0, "logical_bytes": 0,
                       "automatic_retry": False, "partial_deletion_possible": False}
            create_file(receipt_path, encoded(receipt))
            try:
                path, marker, owned = self.run(plan["run_id"])
                ledger = self.read_ledger(plan["run_id"])
                self._cleanup_state(ledger, owned, plan["scope"])
                if ledger["run"]["mode"] == "real":
                    self.assert_native_platform(ledger["run"]["platform"])
                if marker["creation_nonce"] != plan["run_creation_nonce"] or digest(private_read(path, "ledger.json")) != plan["ledger_sha256"]:
                    raise Refusal("Run checkpoint changed after preview")
                inventory = self._inventory(path, owned)
                if inventory != plan["inventory"] or self._targets(owned, plan["scope"], inventory) != plan["targets"]:
                    raise Refusal("Owned inventory/identity/hash changed after preview")
                with anchor_fd(path) as root_fd:
                    records = {i["relative_path"]: i for i in inventory}
                    for rel in sorted((p for p in plan["targets"] if p), key=lambda p: (p.count("/"), p), reverse=True):
                        item = records[rel]
                        with parent_fd(root_fd, rel) as (parent, name):
                            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                            # Directory timestamps change as owned children are removed.
                            if (info.st_dev, info.st_ino, info.st_mode) != (item["device"], item["inode"], item["mode"]):
                                raise Refusal("Cleanup identity changed during operation")
                            if item["kind"] == "file":
                                if info.st_nlink != 1 or digest(private_read(path, rel)) != item["sha256"]:
                                    raise Refusal("Cleanup file changed during operation")
                                os.unlink(name, dir_fd=parent)
                                receipt["files"] += 1; receipt["logical_bytes"] += item["size"]
                            else:
                                os.rmdir(name, dir_fd=parent)
                                receipt["directories"] += 1
                    if "" in plan["targets"]:
                        with anchor_fd(self.work) as work_fd:
                            info = os.stat(plan["run_id"], dir_fd=work_fd, follow_symlinks=False)
                            root_item = records[""]
                            if (info.st_dev, info.st_ino) != (root_item["device"], root_item["inode"]):
                                raise Refusal("Run root identity changed")
                            os.rmdir(plan["run_id"], dir_fd=work_fd)
                            receipt["directories"] += 1
                if plan["scope"] == "Temporary":
                    owned["files"] = [f for f in owned["files"] if f["relative_path"] not in plan["targets"]]
                    owned["directories"] = [d for d in owned["directories"] if d not in plan["targets"]]
                    replace_control(path / "owned-files.json", encoded(owned))
                    self._audit(path, plan["run_id"], "ApplyCleanup", {"plan_id": plan_id, "files": receipt["files"]})
                receipt["status"] = "completed"
            except Exception:
                receipt["status"] = "failed_or_partial"
                receipt["partial_deletion_possible"] = bool(receipt["files"] or receipt["directories"])
                receipt["error"] = "Stopped. Preserve this receipt and exact plan; do not automatically retry."
                raise
            finally:
                receipt["finished_utc"] = utc_now()
                replace_control(receipt_path, encoded(receipt))
            return receipt

    def export_toolkit(self):
        listing = decode(safe_read(self.root, "templates/export-allowlist.json"))["files"]
        if not isinstance(listing, list) or not listing or any(not isinstance(p, str) for p in listing) or len(listing) != len({p.casefold() for p in listing}):
            raise Refusal("Exact nonempty public allowlist required")
        payloads = []
        for rel in sorted(listing):
            relative(rel)
            if any(part.lower() in {"work", ".git"} for part in rel.split("/")):
                raise Refusal("Private work/history excluded")
            extension = Path(rel).suffix.lower()
            if extension not in {".md", ".json", ".ps1", ".psm1", ".cs", ".py", ".html", ".css", ".js", ".cjs", ".png", ".yml", ".yaml"} and rel not in {".gitattributes", ".gitignore", "LICENSE"}:
                raise Refusal("Unreviewed public export type")
            data = safe_read(self.root, rel, 4_000_000)
            if extension == ".png":
                if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
                    raise Refusal("Public PNG signature/header invalid")
                width, height = int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
                if not 0 < width <= 4096 or not 0 < height <= 4096:
                    raise Refusal("Public PNG dimensions refused")
            else:
                try:
                    data.decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise Refusal("Public text is not valid UTF-8") from exc
                if b"\0" in data:
                    raise Refusal("Binary NUL in public text")
            payloads.append((rel, data))
        directory = self.area("_exports") / ("export-" + uuid.uuid4().hex)
        _private_directory(directory, create=True)
        archive = directory / "toolkit.zip"
        create_file(archive, b"")
        with _private_existing_stream(archive, "r+b") as stream, zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
            for rel, data in payloads:
                info = zipfile.ZipInfo(rel, (1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                zipped.writestr(info, data)
        manifest = {"schema_version": "1.0", "toolkit_id": self.toolkit_id, "archive_sha256": digest(private_read(directory, "toolkit.zip")),
                    "files": [{"relative_path": rel, "sha256": digest(data)} for rel, data in payloads],
                    "work_or_git_included": False, "publication_performed": False}
        create_file(directory / "export-manifest.json", encoded(manifest))
        return {"archive": str(archive), "manifest": str(directory / "export-manifest.json"), "files": len(payloads), "publication_performed": False}
