"""Fixed adapter coordination; never executes a command from a payload.

The engine owns authority and canonical state. This service owns immutable
adapter intents and recovery retention, and calls only named library methods.
External official-tool actions remain a trusted assistant/host handoff.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import uuid
from urllib.parse import urlsplit

import pc_paths
import pc_records
import storage_contract
from workflow_core import (WorkflowEngine, WorkflowRefusal, encoded, digest, typed_record, older_folder, read_record_bytes, decode_record, no_links, atomic_replace,
                           exact_fields, record_identifier, utc_time, EVIDENCE_MAX_BYTES, EVIDENCE_MAX_NODES,
                           DIAGNOSTIC_ADAPTER, EXTERNAL_ADAPTER, EXTERNAL_PREFLIGHT, EXTERNAL_RECEIPT,
                           INSTALLER_METADATA, PUBLISHER_SIGNATURE, QUARANTINE_RECOVERY, RECOVERY_BINDING, RECOVERY_RETENTION,
                           RESTART_PENDING, RESTART_VERIFICATION, SERVICE_RECORD, STORAGE_ADAPTER, WINDOWS_BOOT)
from storage_ops import StorageService, StorageRefusal, plan_sha256, restorable
from scoped_fs import ScopedFSError, ScopedRoot
from diagnostic_core import (CLOCK_STEP_MESSAGE, DiagnosticRefusal, MAX_RECORD, after_now, stepped_back, RECORD_RE, REQUEST_RE, SCHEMA as DIAGNOSTIC_RECORD, SENSITIVE, TOKEN_RE,
                             exact_keys, parse_time, read_diagnostic, sanitize_text, scope_tokens, validate_adapter_result,
                             validate_request)
from diagnostic_posix import collect_recipe
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, write_private_new

RESERVATION_RECORD = "patchcairn.quarantine.reservation"
# Every service record is a kind of patchcairn.service.
SERVICE_KINDS = frozenset({"service_marker", "retention_registry", "required_retention", "operation_intent", "intent_evidence",
                           "native_origin", "service_outcome", "reviewed_external_handoff", "windows_diagnostic_handoff",
                           "effect_boundary"})
_RESERVATION_FIELDS = {"schema", "schema_version", "engine_id", "mode", "platform", "session_id", "operation_id",
                       "workflow_plan_sha256", "adapter_payload_sha256", "native_plan_sha256", "output_root",
                       "original_plan", "quarantine_mapping", "intent_sha256", "native_origin_sha256"}
DEFAULT_ROOT = Path(__file__).absolute().parent.parent
DIAGNOSTIC_ADAPTER_ID = pc_records.ADAPTER_DIAGNOSTIC_COLLECT
# The service's storage adapters: the engine action kind and the outcome-file name of each (the storage plan
# kind is storage_contract.PLAN_KINDS).
STORAGE = {
    pc_records.ADAPTER_STORAGE_BACKUP_CREATE: ("backup_create", "backup"),
    pc_records.ADAPTER_STORAGE_RESTORE: ("backup_restore", "restore"),
    pc_records.ADAPTER_STORAGE_QUARANTINE: ("cleanup_quarantine", "quarantine"),
    pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE: ("backup_restore", "quarantine-restore"),
    pc_records.ADAPTER_STORAGE_PURGE: ("permanent_purge", "purge"),
}
OFFICIAL_DOMAINS = {
    "windows.msiexec.install": {"learn.microsoft.com", "support.microsoft.com"},
    "macos.installer.pkg": {"support.apple.com", "developer.apple.com"},
    "linux.dpkg.install_local": {"manpages.debian.org", "www.debian.org", "debian.org"},
    "windows.winget.upgrade": {"learn.microsoft.com", "support.microsoft.com"},
    "windows.dism.restorehealth": {"learn.microsoft.com", "support.microsoft.com"},
    "macos.softwareupdate.install": {"support.apple.com", "developer.apple.com"},
    "linux.apt.upgrade_selected": {"manpages.debian.org", "www.debian.org", "debian.org", "ubuntu.com"},
    "linux.dnf.upgrade_selected": {"dnf.readthedocs.io", "dnf5.readthedocs.io", "docs.fedoraproject.org"},
    "linux.dpkg.configure_selected": {"manpages.debian.org", "www.debian.org", "debian.org"},
}
ARTIFACT_EXTENSIONS = {"windows.msiexec.install": {".msi"}, "macos.installer.pkg": {".pkg"},
                       "linux.dpkg.install_local": {".deb"}}


class ServiceRefusal(pc_records.Refusal):
    """Preserve a held/consumed operation; no weaker fallback or retry."""

    def __init__(self, message, *, code="service-refusal"):
        super().__init__(code, message)


def _schema(record, name):
    """``record`` checked by pc_records for the family ``name``; a refusal keeps its code."""
    try:
        return pc_records.require_schema(record, name)
    except pc_records.Refusal as error:
        raise ServiceRefusal(str(error), code=error.code) from error


def _read_service(record):
    """The registered reader of patchcairn.service records: the schema check and a known kind."""
    _schema(record, SERVICE_RECORD)
    if record.get("kind") not in SERVICE_KINDS:
        raise ServiceRefusal("Unknown service record kind")
    return record


def _read_reservation(record):
    """The registered reader of quarantine reservations: the schema check and the exact fields."""
    _schema(record, RESERVATION_RECORD)
    exact_fields(record, _RESERVATION_FIELDS, _RESERVATION_FIELDS)
    return record


pc_records.register_reader(SERVICE_RECORD, _read_service)
pc_records.register_reader(RESERVATION_RECORD, _read_reservation)


def _service_record(record, kind):
    """A service record of ``kind`` (pc_records schema check, then the kind)."""
    _read_service(record)
    if record["kind"] != kind:
        raise ServiceRefusal("Unexpected service record kind")
    return record


def _named(record, name, message):
    """``record`` through the engine's registered reader for ``name``. An older record keeps the clear
    older-format message; any other refusal is explained by ``message`` and keeps its own code."""
    try:
        return typed_record(record, name)
    except pc_records.Refusal as error:
        raise ServiceRefusal(str(error) if error.code == "older-format" else message, code=error.code) from error


def _service_value(kind, **fields):
    return {"schema": SERVICE_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": kind, **fields}


def _without_version(record):
    rest = dict(record)
    rest.pop("schema_version", None)
    return rest


def native_platform():
    return "windows" if sys.platform == "win32" else "macos" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "unknown"


def _within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _selected_text(value):
    clean = sanitize_text(value, limit=2000)
    if not clean or clean != value.strip():
        raise ServiceRefusal("Provide selected nonsecret text without private paths or credential-like values")
    return clean


# Error codes that mean a recovery or artifact file is gone rather than changed.
_MISSING_CODES = frozenset({"missing-entry", "filesystem-access", "private-path-access-refused", "private-directory-missing"})
INSTALLER_MAX_BYTES = 64 * 1024 * 1024


def _decoded(data):
    """A service record decoded strictly; it may hold per-file lists up to the engine's evidence bound."""
    return decode_record(data, max_bytes=EVIDENCE_MAX_BYTES, max_nodes=EVIDENCE_MAX_NODES)


def _changed(message):
    return pc_records.Refusal("recovery-changed", message)


def _covers_purge(manifest, receipt):
    """The backup manifest covers every quarantined original of the purge receipt by source, path, content and size."""
    originals, backed_files = receipt.get("records"), manifest.get("files")
    if (not isinstance(manifest.get("source_roots"), list) or not manifest["source_roots"] or manifest["source_roots"] != receipt.get("source_roots")
            or not isinstance(originals, list) or not originals or not isinstance(backed_files, list) or not backed_files):
        raise _changed("Recovery must cover the exact quarantined originals and selected source roots")

    def covered_key(file):
        if (not isinstance(file, dict) or any(not isinstance(file.get(key), str) or not file[key] for key in ("root_id", "relative_path", "sha256"))
                or not pc_records.SHA256.match(file["sha256"]) or type(file.get("size")) is not int or file["size"] < 0):
            raise _changed("Purge recovery requires exact bounded original/manifest content mappings")
        return file["root_id"], file["relative_path"], file["sha256"], file["size"]
    backed = {covered_key(file) for file in backed_files}
    if any(not isinstance(record, dict) or covered_key(record.get("original")) not in backed for record in originals):
        raise _changed("Recovery must cover the exact quarantined originals by source, path, content and size")


def _verify_binding(binding):
    kind = binding["kind"]
    if kind == "installer_artifact":
        artifact = Path(binding["path"])
        with ScopedRoot(str(artifact.parent), quiet_workspace=True) as pinned:
            actual = pinned.inspect(artifact.name, hash_file=True, max_bytes=INSTALLER_MAX_BYTES)
        if actual.get("kind") != "file" or actual.get("sha256") != binding["sha256"] or actual != binding["record"]:
            raise _changed("The actual selected official artifact bytes differ from the approved content hash")
        return
    storage = StorageService(output_root=binding["output_root"], quiet_workspace=True, protected_roots=binding.get("protected_roots"))
    if kind == "backup_recovery":
        backup = binding["backup_receipt"]
        manifest = storage.verified_recovery(backup=backup, restoration=binding["restore_receipt"])
        if manifest.get("required_recovery") is not True or manifest.get("plan_sha256") != backup.get("plan_sha256"):
            raise _changed("Recovery manifest does not bind the actual archive and original backup plan")
        if binding.get("purge_receipt") is not None:
            _covers_purge(manifest, binding["purge_receipt"])
    elif kind == "quarantine_recovery":
        storage.check_preconditions(plan=binding["restore_plan"], expected_plan_sha256=binding["restore_plan_sha256"])
        if storage.artifact_sha256(binding["attempt"]) != binding["attempt_sha256"]:
            raise _changed("The original quarantine attempt record changed")
    else:
        raise pc_records.Refusal("verifier-binding", "The artifact verifier does not know this binding")


def verify_storage_artifact(binding):
    """The engine's ``verify_artifact`` that only WorkflowService builds in (D-018, F-178): re-read from disk, through
    the storage code, the recovery or artifact bytes a binding names. Returns None; raises pc_records.Refusal with
    code recovery-missing or recovery-changed (and the reason) when they are not exactly as reviewed."""
    try:
        _verify_binding(binding)
    except pc_records.Refusal as error:
        if error.code in {"recovery-missing", "recovery-changed", "verifier-binding"}:
            raise
        code = "recovery-missing" if error.code in _MISSING_CODES else "recovery-changed"
        raise pc_records.Refusal(code, str(error)) from error
    except (KeyError, TypeError, AttributeError) as error:
        raise pc_records.Refusal("verifier-binding", "The artifact binding is incomplete") from error
    except OSError as error:
        raise pc_records.Refusal("recovery-missing" if isinstance(error, FileNotFoundError) else "recovery-changed",
                                 "Recovery or artifact bytes could not be read again") from error


def _private_read(path, max_bytes=EVIDENCE_MAX_BYTES):
    ensure_private_file(path)
    return read_record_bytes(path, max_bytes)


# The diagnostic record store (PD-12: moved from diagnostic_core so the engine's validator stays pure).

def _diagnostic_encoded(value):
    try:
        data = pc_records.encoded(value)
    except pc_records.Refusal as exc:
        raise DiagnosticRefusal("Invalid bounded record", code=exc.code) from exc
    if len(data) > MAX_RECORD:
        raise DiagnosticRefusal("Record size cap exceeded")
    return data


def _diagnostic_ordinary(path, *, directory=False):
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise DiagnosticRefusal("Link or reparse point refused")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise DiagnosticRefusal("Ordinary directory required")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise DiagnosticRefusal("Single-link ordinary file required")
    return info


def _diagnostic_ancestors(path):
    for item in reversed([path, *path.parents]):
        _diagnostic_ordinary(item, directory=True)


class DiagnosticStore:
    """Append-only, content-hashed records below this toolkit's work directory."""

    def __init__(self, root=None, *, work_relative="work/diagnostics"):
        self.root = Path(root).absolute() if root is not None else DEFAULT_ROOT
        if ".." in self.root.parts:
            raise DiagnosticRefusal("Traversal in fixture root refused")
        self.fixture_root = root is not None and self.root != DEFAULT_ROOT
        _diagnostic_ancestors(self.root)
        if self.fixture_root:
            try:
                self.root.relative_to(DEFAULT_ROOT / "work")
            except ValueError as exc:
                raise DiagnosticRefusal("Fixture root must stay below toolkit work") from exc
        parts = work_relative.split("/") if isinstance(work_relative, str) else []
        if len(parts) < 2 or parts[0] != "work" or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", part) or not pc_paths.portable(part) for part in parts):
            raise DiagnosticRefusal("Safe work-relative directory required")
        self.base = self.root.joinpath(*parts)
        ensure_private_directory(self.base, create=True, parents=True, exist_ok=True)

    def _directory(self, request_id):
        if not isinstance(request_id, str) or not REQUEST_RE.fullmatch(request_id):
            raise DiagnosticRefusal("Invalid diagnostic request identifier")
        path = self.base / request_id
        _diagnostic_ancestors(path)
        ensure_private_directory(self.base)
        ensure_private_directory(path)
        return path

    def _write(self, record, prefix):
        path = self._directory(record["request_id"])
        data = _diagnostic_encoded(record)
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
        request = {"schema": DIAGNOSTIC_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": "request",
                   "request_id": "diag-" + uuid.uuid4().hex, "platform": platform, "recipe_id": recipe_id, "mode": mode,
                   "symptom": sanitize_text(symptom), "scope": scope_tokens(scope), "observed_utc": pc_records.utc_now()}
        validate_request(request)
        ensure_private_directory(self.base)
        ensure_private_directory(self.base / request["request_id"], create=True)
        return self._write(request, "request")

    def read_record(self, request_id, record_id):
        if not isinstance(record_id, str) or not (match := RECORD_RE.fullmatch(record_id)):
            raise DiagnosticRefusal("Invalid record identifier")
        path = self._directory(request_id) / (record_id + ".json")
        before = _diagnostic_ordinary(path)
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
            record = pc_records.decode_strict(data, max_bytes=MAX_RECORD)
        except pc_records.Refusal as exc:
            raise DiagnosticRefusal("Invalid immutable record encoding", code=exc.code) from exc
        if not isinstance(record, dict) or record.get("request_id") != request_id or record.get("kind") != match[1]:
            raise DiagnosticRefusal("Foreign record identity")
        read_diagnostic(record)
        if _diagnostic_encoded(record) != data:
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
        observed = observed_utc or pc_records.utc_now()
        if after_now(parse_time(observed)):
            raise DiagnosticRefusal("Future excerpt observation refused")
        return self._write({"schema": DIAGNOSTIC_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": "excerpt", "request_id": request_id,
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
            exact_keys(item, {"hypothesis_id", "statement", "mechanism", "original_cause", "confidence", "outcome", "evidence_ids", "counterevidence_ids", "next_check"})
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
        return self._write({"schema": DIAGNOSTIC_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": "hypotheses", "request_id": request_id,
                            "scope": request["scope"], "mode": request["mode"], "observed_utc": pc_records.utc_now(),
                            "hypotheses": clean, "unknowns": [sanitize_text(s, limit=1024) for s in unknowns]}, "hypotheses")

    def record_verification(self, request_id, *, action_id, plan_sha256, action_completed_utc,
                            original_success_condition, result_ids, outcome, observation):
        request = self.read_request(request_id)
        if not isinstance(action_id, str) or not TOKEN_RE.fullmatch(action_id) or not isinstance(plan_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", plan_sha256):
            raise DiagnosticRefusal("Exact action and plan binding required")
        completed = parse_time(action_completed_utc)
        if after_now(completed) or not isinstance(outcome, str) or outcome not in {"passed", "failed", "unknown"}:
            raise DiagnosticRefusal("Invalid verification time or outcome")
        ids = self._evidence_ids(request_id, result_ids)
        if outcome in {"passed", "failed"} and not ids:
            raise DiagnosticRefusal("Verification outcome requires fresh evidence")
        for record_id in ids:
            evidence = self.read_record(request_id, record_id)
            if parse_time(evidence["observed_utc"]) < completed:
                raise DiagnosticRefusal("Pre-repair evidence cannot verify a repair")
            if outcome == "passed" and evidence["kind"] == "result" and evidence["status"] != "observed":
                raise DiagnosticRefusal("Unavailable observation cannot verify success")
        condition = sanitize_text(original_success_condition, limit=1024)
        detail = sanitize_text(observation, limit=1024)
        if not condition or not detail:
            raise DiagnosticRefusal("Original success condition and actual observation required")
        return self._write({"schema": DIAGNOSTIC_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": "verification", "request_id": request_id,
                            "scope": request["scope"], "mode": request["mode"], "observed_utc": pc_records.utc_now(),
                            "action_id": action_id, "plan_sha256": plan_sha256, "action_completed_utc": action_completed_utc,
                            "original_success_condition": condition, "result_ids": ids, "outcome": outcome,
                            "observation": detail, "limitation": "Coordinator-attributed behavior check; does not establish original cause or all-system integrity."}, "verification")

    def evidence_bytes(self, request_id, record_id):
        """Validated exact bytes for the engine coordinator to register itself."""
        record = self.read_record(request_id, record_id)
        return _diagnostic_encoded(record)

    def evidence_ref(self, request_id, record_id):
        record = self.read_record(request_id, record_id)
        return {"path": (self._directory(request_id) / (record_id + ".json")).relative_to(self.root).as_posix(),
                "sha256": record_id.rsplit("-", 1)[1], "scope": copy.deepcopy(record["scope"]),
                "observed_utc": record["observed_utc"], "kind": record["kind"]}


class WorkflowService:
    def __init__(self, engine=None, *, work_relative="work/services"):
        self.engine = engine if engine is not None else self.default_engine()
        # The begin-time re-check of recovery and artifacts is always the storage verifier (D-018, F-178).
        if self.engine.verify_artifact is None:
            self.engine.verify_artifact = verify_storage_artifact
        elif self.engine.verify_artifact is not verify_storage_artifact:
            raise ServiceRefusal("The service drives only an engine whose re-check is the storage verifier", code="verifier-contract")
        self.root = self.engine.root
        if self.root != DEFAULT_ROOT and not _within(self.root, DEFAULT_ROOT / "work"):
            raise ServiceRefusal("Development root must stay below this toolkit's work tree")
        rel = PurePosixPath(work_relative)
        if not isinstance(work_relative, str) or rel.is_absolute() or "\\" in work_relative or len(rel.parts) < 2 or rel.parts[0] != "work" or any(part in {".", ".."} or not part.replace("-", "").replace("_", "").isalnum() for part in rel.parts):
            raise ServiceRefusal("Safe named work child required")
        self.work = no_links(self.root.joinpath(*rel.parts))
        ensure_private_directory(self.work, create=True, parents=True, exist_ok=True)
        marker = self.work / "service.json"
        expected = _service_value("service_marker", engine_id=self.engine.marker["engine_id"], backend=self.engine.marker["backend"])
        if not marker.exists():
            if any(self.work.iterdir()):
                raise ServiceRefusal("Missing service marker in nonempty storage; no recreation")
            self._immutable(marker, expected)
            self._immutable(self.work / "retention.json", _service_value("retention_registry", entries=[]))
        if _without_version(older_folder(work_relative, lambda: _read_service(_decoded(_private_read(marker))))) != _without_version(expected):
            raise ServiceRefusal("Foreign service/engine binding")
        self.diagnostics = DiagnosticStore(self.root, work_relative=work_relative + "/diagnostics")
        self._retention()

    @staticmethod
    def default_engine():
        """The engine this service drives, built with the storage verifier at its begin-time re-check."""
        return WorkflowEngine(verify_artifact=verify_storage_artifact)

    @staticmethod
    def _immutable(path, value):
        no_links(path)
        data = encoded(value)
        if len(data) > EVIDENCE_MAX_BYTES:
            raise ServiceRefusal("Service record cap exceeded")
        write_private_new(path, data)
        return {"path": str(path), "sha256": digest(data)}

    @contextmanager
    def _lock(self):
        path = self.work / ".coordinator-lock"
        try:
            ensure_private_directory(path, create=True)
        except FileExistsError as exc:
            raise ServiceRefusal("Service is active or interrupted; inspect before another action") from exc
        except PrivateWorkspaceError as exc:
            if exc.code == "private-directory-exists":
                raise ServiceRefusal("Service is active or interrupted; inspect before another action") from None
            raise
        try:
            yield
        finally:
            path.rmdir()

    def _state(self, session_id, *, collecting=False):
        ensure_private_directory(self.work)
        state = self.engine.read_session(session_id)
        if collecting and (state["status"] not in {"active", "awaiting_user"} or not state["scope_authorization"]):
            raise ServiceRefusal("Current selected collection scope and active session required")
        if collecting:
            self.engine.require_schedule_activation(state)
        if state["mode"] == "real" and state["platform"] != native_platform():
            raise ServiceRefusal("Real service requires the actual matching native platform")
        return state

    def _owned(self, value, *, state=None, existing=False):
        if not isinstance(value, str) or not Path(value).is_absolute() or ".." in Path(value).parts:
            raise ServiceRefusal("Exact absolute owned-work path required")
        path = no_links(Path(value))
        if path == self.root / "work" or not _within(path, self.root / "work"):
            raise ServiceRefusal("Output must remain below this engine's owned work root")
        if existing and not path.is_dir():
            raise ServiceRefusal("Existing positively owned output directory required")
        return path

    def _retention(self):
        ensure_private_directory(self.work)
        registry = _service_record(_decoded(_private_read(self.work / "retention.json")), "retention_registry")
        exact_fields(registry, {"schema", "schema_version", "kind", "entries"}, {"schema", "schema_version", "kind", "entries"})
        if not isinstance(registry["entries"], list) or len(registry["entries"]) > 10000:
            raise ServiceRefusal("Invalid protected retention registry")
        rows = []
        for ref in registry["entries"]:
            exact_fields(ref, {"name", "sha256"}, {"name", "sha256"})
            record_identifier(ref["name"])
            data = _private_read(self.work / (ref["name"] + ".json"))
            if digest(data) != ref["sha256"]:
                raise ServiceRefusal("Protected retention record changed")
            row = _service_record(_decoded(data), "required_retention")
            if not isinstance(row.get("artifacts"), dict) or not row["artifacts"]:
                raise ServiceRefusal("Invalid protected retention evidence")
            protection = self._owned(row.get("protection_root"))
            for path in row["artifacts"]:
                if not _within(self._owned(path), protection):
                    raise ServiceRefusal("Retention protection does not contain its exact artifacts")
            if "quarantine_binding" in row:
                self._validate_quarantine_reservation(row)
            rows.append(row)
        return rows

    def protected_roots(self):
        values = {str(self.engine.work), str(self.work)}
        for row in self._retention():
            values.add(row["protection_root"])
        if len(values) > storage_contract.MAX_PROTECTED_ROOTS:
            raise ServiceRefusal("Protection policy exceeds adapter cap; retain evidence and narrow scope")
        return sorted(values)

    def _retain(self, session_id, artifacts, *, reason, quarantine_binding=None):
        for path in artifacts:
            self._owned(path)
        row = _service_value("required_retention", session_id=session_id, observed_utc=pc_records.utc_now(), reason=reason,
                             artifacts=artifacts, protection_root=os.path.commonpath([str(Path(path).parent) for path in artifacts]))
        if quarantine_binding is not None:
            row["quarantine_binding"] = copy.deepcopy(quarantine_binding)
        name = "retention-" + uuid.uuid4().hex
        ref = self._immutable(self.work / (name + ".json"), row)
        registry = _service_record(_decoded(_private_read(self.work / "retention.json")), "retention_registry")
        registry["entries"].append({"name": name, "sha256": ref["sha256"]})
        atomic_replace(self.work / "retention.json", encoded(registry))

    @staticmethod
    def _quarantine_mapping(plan):
        return [{"original": row, "quarantine_relative": plan["quarantine_relative"] + f"/{index:06d}"}
                for index, row in enumerate(plan["files"], 1)]

    @staticmethod
    def _quarantine_artifacts(output, plan):
        native_sha = digest(plan)
        artifacts = {str(output / ("attempt-quarantine-" + native_sha + ".json")): None,
                     str(output / ("outcome-quarantine-" + native_sha + ".json")): None}
        for index, row in enumerate(plan["files"], 1):
            artifacts[str(output / plan["quarantine_relative"] / f"{index:06d}")] = row["sha256"]
            artifacts[str(output / f"step-quarantine-{native_sha}-{index:06d}.json")] = None
        return artifacts

    def _validate_quarantine_reservation(self, row):
        binding = _read_reservation(row["quarantine_binding"])
        for key in ("session_id", "operation_id"):
            record_identifier(binding[key])
        plan = binding["original_plan"]
        if (binding["engine_id"] != self.engine.marker["engine_id"]
                or binding["mode"] not in {"fixture", "real"} or binding["platform"] not in {"windows", "macos", "linux"}
                or row["session_id"] != binding["session_id"] or row["protection_root"] != binding["output_root"]
                or not isinstance(plan, dict) or plan.get("kind") != "quarantine"
                or digest(plan) != binding["native_plan_sha256"]
                or binding["quarantine_mapping"] != self._quarantine_mapping(plan)
                or row["artifacts"] != self._quarantine_artifacts(Path(binding["output_root"]), plan)):
            raise ServiceRefusal("Quarantine reservation differs from its exact original plan, namespace or mapping")
        intent_path = self.work / "operations" / binding["session_id"] / binding["operation_id"] / "intent.json"
        intent = _service_record(_decoded(_private_read(intent_path)), "operation_intent")
        origin = _service_record(_decoded(_private_read(self.work / ("origin-" + binding["native_plan_sha256"] + ".json"))), "native_origin")
        if (digest(intent) != binding["intent_sha256"] or digest(origin) != binding["native_origin_sha256"]
                or intent["payload"]["storage_plan"] != plan or intent["payload"]["output_root"] != binding["output_root"]
                or intent["quarantine_mapping"] != binding["quarantine_mapping"]
                or intent["action"]["adapter_payload_sha256"] != binding["adapter_payload_sha256"]
                or intent["operation"]["plan_sha256"] != binding["workflow_plan_sha256"]
                or any(origin.get(key) != binding[key] for key in ("engine_id", "mode", "platform", "session_id", "operation_id"))
                or origin.get("native_plan_sha256") != binding["native_plan_sha256"]
                or origin.get("workflow_plan_sha256") != binding["workflow_plan_sha256"]):
            raise ServiceRefusal("Original quarantine intent or native provenance changed; preserve the reserved output")

    def _reserve_quarantine(self, state, operation, action, payload, intent):
        plan, output = payload["storage_plan"], Path(payload["output_root"])
        origin = _service_record(_decoded(_private_read(self.work / ("origin-" + digest(plan) + ".json"))), "native_origin")
        binding = {"schema": RESERVATION_RECORD, "schema_version": pc_records.SCHEMA_VERSION,
                   **{key: state[key] for key in ("engine_id", "mode", "platform", "session_id")},
                   "operation_id": operation["operation_id"], "workflow_plan_sha256": operation["plan_sha256"],
                   "adapter_payload_sha256": action["adapter_payload_sha256"], "native_plan_sha256": digest(plan),
                   "output_root": str(output), "original_plan": plan, "quarantine_mapping": self._quarantine_mapping(plan),
                   "intent_sha256": digest(intent), "native_origin_sha256": digest(origin)}
        artifacts = self._quarantine_artifacts(output, plan)
        self._validate_quarantine_reservation({"quarantine_binding": binding, "session_id": state["session_id"],
                                               "protection_root": str(output), "artifacts": artifacts})
        self._retain(state["session_id"], artifacts, quarantine_binding=binding,
                     reason="Exact quarantine output, original intent/native provenance and mapping reserved before the first move; no automatic release")

    def _quarantine_reservations(self, state, payload, output, plan):
        reservations = [row["quarantine_binding"] for row in self._retention() if "quarantine_binding" in row]
        for binding in reservations:
            reserved = Path(binding["output_root"])
            if not (_within(output, reserved) or _within(reserved, output)):
                continue
            receipt = plan.get("receipt")
            original = binding["original_plan"]
            if (payload["operation"] not in {pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE, pc_records.ADAPTER_STORAGE_PURGE}
                    or output != reserved or binding["mode"] != state["mode"] or binding["platform"] != state["platform"]
                    or not isinstance(receipt, dict) or receipt.get("plan_sha256") != binding["native_plan_sha256"]
                    or receipt.get("source_roots") != original["inventory"]["roots"]
                    or any(receipt.get(key) != original[key] for key in ("quarantine_destination", "recovery_required", "recovery_backup", "recovery_verification"))
                    or [{"original": row["original"], "quarantine_relative": row["quarantine_record"]["relative_path"]}
                        for row in receipt.get("records", [])] != binding["quarantine_mapping"]):
                raise ServiceRefusal("Reserved quarantine output permits only its exact original receipt-mapped restoration or backed purge")
        return reservations

    @staticmethod
    def _purge_original_recovery(payload):
        if payload["operation"] == pc_records.ADAPTER_STORAGE_PURGE:
            receipt = payload["storage_plan"].get("receipt")
            if (not isinstance(receipt, dict) or receipt.get("recovery_required") is not True
                    or not isinstance(receipt.get("recovery_backup"), dict) or not isinstance(receipt.get("recovery_verification"), dict)):
                raise ServiceRefusal("Integrated permanent purge requires the original quarantine's exact verified backup and restoration probe")

    def _register(self, state, *, kind, value, facts=None, observed_utc=None):
        evidence_id = "service-" + uuid.uuid4().hex
        return self.engine.register_evidence(state["session_id"], evidence_id=evidence_id, content=encoded(value),
                kind=kind, scope=state["settings"]["scope"], facts=facts or {}, observed_utc=observed_utc)["data"]

    def _action(self, state, *, action_id, adapter_id, kind, payload, inventory, target, benefit, risk,
                reversibility, verification, requires_recovery=False, recovery_evidence_ids=None, requires_os_consent=False):
        record_identifier(action_id)
        prose = {key: _selected_text(value) for key, value in (("target", target), ("benefit", benefit), ("risk", risk), ("reversibility", reversibility), ("verification", verification))}
        inventory_row = self._register(state, kind="inventory", value=inventory, facts={"complete": True, "item_count": len(inventory.get("entries", inventory.get("records", []))) if isinstance(inventory, dict) else 1})
        payload_row = self._register(state, kind="adapter_payload", value=payload)
        native_plan = payload.get("storage_plan", payload.get("request", payload.get("external_plan")))
        return {"action_id": action_id, "kind": kind, **prose, "mutating": kind != "assessment",
                "requires_os_consent": requires_os_consent, "requires_recovery": requires_recovery,
                "recovery_evidence_ids": recovery_evidence_ids or [], "adapter_id": adapter_id,
                "adapter_payload_evidence_id": payload_row["evidence_id"], "adapter_payload_sha256": payload_row["sha256"],
                "adapter_plan_sha256": digest(native_plan), "target_inventory_evidence_id": inventory_row["evidence_id"],
                "target_inventory_sha256": inventory_row["sha256"]}

    def _storage(self, state, payload):
        if payload["operation"] not in STORAGE or payload["mode"] != state["mode"]:
            raise ServiceRefusal("Unsupported storage adapter or mode")
        output = self._owned(payload["output_root"], state=state, existing=True)
        protections = payload["protected_roots"]
        if not isinstance(protections, list) or len(set(protections)) != len(protections) or not set(self.protected_roots()) <= set(protections):
            raise ServiceRefusal("Exact current protected retention policy must be included in the reviewed payload")
        plan = payload["storage_plan"]
        if plan.get("kind") != storage_contract.PLAN_KINDS[payload["operation"]] or plan_sha256(plan) != payload["storage_plan_sha256"]:
            raise ServiceRefusal("Wrong native plan type or changed exact plan hash")
        self._purge_original_recovery(payload)
        reservations = self._quarantine_reservations(state, payload, output, plan)
        service = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=protections)
        if "inventory" in plan:
            roots = [item["path"] for item in plan["inventory"]["roots"]]
        elif plan["kind"] == "restore":
            roots = [item["path"] for item in service.verify_backup(receipt=plan["receipt"])["manifest"]["source_roots"]]
        else:
            roots = [item["path"] for item in plan["receipt"]["source_roots"]]
        if any(_within(Path(root), Path(binding["output_root"])) or _within(Path(binding["output_root"]), Path(root))
               for root in roots for binding in reservations):
            raise ServiceRefusal("Reserved quarantine evidence and originals cannot become another plan's selected source scope")
        if sorted(roots) != sorted(state["settings"]["scope"]["roots"]):
            raise ServiceRefusal("Native source roots differ from the exact authorized workflow scope")
        if state["mode"] == "fixture" and any(not _within(no_links(Path(root)), self.root / "work") for root in roots):
            raise ServiceRefusal("Fixture operations are confined to explicitly selected owned work copies")
        if "restore_probe_destination" in payload:
            probe = self._owned(payload["restore_probe_destination"], state=state)
            if payload["operation"] != pc_records.ADAPTER_STORAGE_BACKUP_CREATE or not _within(probe, output) or probe == output or probe.exists():
                raise ServiceRefusal("Backup verification probe requires a new exact owned output child")
            if any(_within(probe, Path(root)) or _within(Path(root), probe) for root in roots):
                raise ServiceRefusal("Restore probe cannot overlap original sources")
            try:
                # Refused before the backup is written, not when the probe is planned after it.
                restorable(probe.relative_to(output).as_posix(), plan["files"])
            except StorageRefusal as error:
                raise ServiceRefusal(str(error), code=error.code) from error
        return service

    def prepare_storage_action(self, session_id, *, action_id, adapter_id, storage_plan, output_root,
            target, benefit, risk, reversibility, verification, protected_roots=None,
            recovery_evidence_ids=None, requires_os_consent=False, restore_probe_destination=None):
        with self._lock():
            state = self._state(session_id, collecting=True)
            if adapter_id not in STORAGE:
                raise ServiceRefusal("Unsupported fixed storage adapter")
            protections = sorted(set(self.protected_roots()) | set(protected_roots or []))
            payload = {"schema": STORAGE_ADAPTER, "schema_version": pc_records.SCHEMA_VERSION, "operation": adapter_id,
                       "storage_plan": copy.deepcopy(storage_plan), "storage_plan_sha256": plan_sha256(storage_plan),
                       "output_root": str(output_root), "mode": state["mode"], "protected_roots": protections}
            if restore_probe_destination is not None:
                payload["restore_probe_destination"] = str(restore_probe_destination)
            service = self._storage(state, payload)
            service.check_preconditions(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"])
            if adapter_id == pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE:
                if recovery_evidence_ids:
                    raise ServiceRefusal("Quarantine restoration uses its exact typed quarantine recovery; omit unrelated recovery evidence")
                recovery = self._quarantine_recovery(state, payload)
                recovery_evidence_ids = [recovery["evidence_id"]]
                payload["protected_roots"] = sorted(set(self.protected_roots()) | set(protected_roots or []))
            inventory = storage_plan.get("inventory", storage_plan.get("records", storage_plan.get("receipt")))
            kind = STORAGE[adapter_id][0]
            required = kind in {"backup_restore", "permanent_purge"} or storage_plan.get("recovery_required") is True
            action = self._action(state, action_id=action_id, adapter_id=adapter_id, kind=kind, payload=payload,
                    inventory=inventory, target=target, benefit=benefit, risk=risk, reversibility=reversibility,
                    verification=verification, requires_recovery=required,
                    recovery_evidence_ids=recovery_evidence_ids, requires_os_consent=requires_os_consent)
            if adapter_id == pc_records.ADAPTER_STORAGE_PURGE:
                self.engine.verify_recovery(self.engine.read_session(session_id), action["recovery_evidence_ids"], action=action)
            return action

    def prepare_diagnostic_action(self, session_id, *, action_id, recipe_id, symptom, diagnostic_scope,
            target, benefit, risk, reversibility, verification):
        with self._lock():
            state = self._state(session_id, collecting=True)
            receipt = self.diagnostics.create_request(platform=state["platform"], recipe_id=recipe_id,
                        symptom=symptom, scope=diagnostic_scope, mode=state["mode"])
            request = receipt["record"]
            payload = {"schema": DIAGNOSTIC_ADAPTER, "schema_version": pc_records.SCHEMA_VERSION, "operation": DIAGNOSTIC_ADAPTER_ID,
                       "request": request, "request_sha256": digest(request), "inventory_sha256": digest(request)}
            return self._action(state, action_id=action_id, adapter_id=payload["operation"], kind="assessment", payload=payload,
                    inventory=request, target=target, benefit=benefit, risk=risk, reversibility=reversibility, verification=verification)

    def prepare_external_action(self, session_id, *, action_id, external_plan, inventory,
            target, benefit, risk, reversibility, verification, requires_recovery=False,
            recovery_evidence_ids=None, requires_os_consent=True):
        with self._lock():
            state = self._state(session_id, collecting=True)
            if isinstance(external_plan, dict) and external_plan.get("kind") == "repair":
                raise ServiceRefusal("OS/app repair is held: file-content ZIP recovery cannot establish exact component recovery")
            if external_plan.get("catalog_id") not in ARTIFACT_EXTENSIONS:
                raise ServiceRefusal("Manager handoff held: the current argv cannot enforce exact reviewed content; use a supported fixed local-artifact update")
            if requires_os_consent is not True:
                raise ServiceRefusal("Fixed local installer handoffs require actual coordinator-recorded protected OS consent")
            self.engine.validate_external_plan(state, external_plan, inventory)
            self._external_sources(external_plan)
            payload = {"schema": EXTERNAL_ADAPTER, "schema_version": pc_records.SCHEMA_VERSION, "operation": pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL,
                       "external_plan": copy.deepcopy(external_plan), "external_plan_sha256": digest(external_plan),
                       "inventory_sha256": digest(inventory)}
            return self._action(state, action_id=action_id, adapter_id=payload["operation"], kind=external_plan["kind"],
                    payload=payload, inventory=inventory, target=target, benefit=benefit, risk=risk,
                    reversibility=reversibility, verification=verification,
                    requires_recovery=requires_recovery or external_plan["kind"] == "repair",
                    recovery_evidence_ids=recovery_evidence_ids, requires_os_consent=requires_os_consent)

    @staticmethod
    def _external_sources(plan):
        for url in plan["sources"]:
            parsed = urlsplit(url)
            if parsed.hostname not in OFFICIAL_DOMAINS.get(plan["catalog_id"], set()) or parsed.query or parsed.fragment or any(ord(c) <= 32 for c in url):
                raise ServiceRefusal("Selected catalog requires a reviewed primary official source without credential-bearing URL data")
        for value in plan["targets"]:
            if plan["catalog_id"] == "windows.msiexec.install" and re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}", value):
                continue
            if SENSITIVE.search(value):
                raise ServiceRefusal("Potential credential value in external plan refused before persistence")
        for value in [plan["recovery_plan"]["limits"], plan["verification_plan"]["original_success_condition"]]:
            if SENSITIVE.search(value):
                raise ServiceRefusal("Potential credential value in external plan refused before persistence")
        for check in plan["verification_plan"]["checks"]:
            _selected_text(check["description"])
            _selected_text(check["expected_result"])
        for identity in plan["target_identities"].values():
            for key in ("publisher", "channel", "source_id"):
                _selected_text(identity[key])

    def register_recovery(self, session_id, *, output_root, backup_receipt, restore_receipt):
        with self._lock():
            return self._register_recovery(session_id, output_root, backup_receipt, restore_receipt)

    def _quarantine_recovery(self, state, payload):
        plan, output = payload["storage_plan"], Path(payload["output_root"])
        receipt = plan["receipt"]
        attempt = output / receipt["attempt"]
        artifacts = {str(attempt): digest(read_record_bytes(attempt)),
                     str(output / ("outcome-quarantine-" + receipt["plan_sha256"] + ".json")): digest(receipt)}
        for row in receipt["records"]:
            artifacts[str(output / row["quarantine_record"]["relative_path"])] = row["quarantine_record"]["sha256"]
        retention = {"schema": RECOVERY_RETENTION, "schema_version": pc_records.SCHEMA_VERSION, "session_id": state["session_id"],
                     "required": True, "artifacts": artifacts}
        retention_row = self._register(state, kind="retention", value=retention)
        binding = {"schema": QUARANTINE_RECOVERY, "schema_version": pc_records.SCHEMA_VERSION, "output_root": str(output),
                   "quarantine_receipt": receipt, "restore_plan": plan, "restore_plan_sha256": digest(plan),
                   "retention_evidence_id": retention_row["evidence_id"]}
        row = self._register(state, kind="recovery", value=binding)
        self._retain(state["session_id"], artifacts, reason="Exact original quarantine mapping, native bytes and immutable receipts retained for reviewed no-overwrite restoration")
        return row

    def _register_recovery(self, session_id, output_root, backup, restore, *, completing=False):
        state = self._state(session_id, collecting=not completing)
        output = self._owned(str(output_root), state=state, existing=True)
        storage = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=self.protected_roots())
        manifest = storage.verify_backup(receipt=backup)["manifest"]
        storage.verified_recovery(backup=backup, restoration=restore)
        for receipt in (backup, restore):
            origin = _service_record(_decoded(_private_read(self.work / ("origin-" + receipt["plan_sha256"] + ".json"))), "native_origin")
            if origin.get("engine_id") != state["engine_id"] or origin.get("mode") != state["mode"] or origin.get("platform") != state["platform"]:
                raise ServiceRefusal("Recovery has no matching gated native fixture/real origin")
        if backup.get("required_recovery") is not True or sorted(row["path"] for row in manifest["source_roots"]) != sorted(state["settings"]["scope"]["roots"]):
            raise ServiceRefusal("Recovery must cover this exact selected scope and remain required")
        if state["mode"] == "fixture" and any(not _within(Path(row["path"]), self.root / "work") for row in manifest["source_roots"]):
            raise ServiceRefusal("Fixture recovery cannot import real source scope")
        artifacts = {backup["archive"]: backup["archive_sha256"], backup["manifest"]: backup["manifest_sha256"],
                     str(output / ("outcome-restore-" + restore["plan_sha256"] + ".json")): digest(restore)}
        for file in manifest["files"]:
            artifacts[str(Path(restore["destination"]) / file["root_id"] / file["relative_path"])] = file["sha256"]
        self._retain(session_id, artifacts, reason="Exact verified required archive, manifest and restoration probe; no automatic release")
        if state["status"] == "stopped":
            return {"registration": "preserved_in_service_retention_after_stop", "artifacts": artifacts,
                    "limitation": "Stopped session accepts only the active operation outcome; no new recovery authority was created."}
        retention = {"schema": RECOVERY_RETENTION, "schema_version": pc_records.SCHEMA_VERSION, "session_id": session_id,
                     "required": True, "artifacts": artifacts}
        retention_row = self._register(state, kind="retention", value=retention)
        binding = {"schema": RECOVERY_BINDING, "schema_version": pc_records.SCHEMA_VERSION, "output_root": str(output),
                   "backup_receipt": backup, "restore_receipt": restore, "retention_evidence_id": retention_row["evidence_id"]}
        row = self._register(state, kind="recovery", value=binding)
        self.engine.verify_recovery(self.engine.read_session(session_id), [row["evidence_id"]])
        return row

    def _binding(self, state, action_id, plan_sha256_value):
        document = self.engine.current_plan(state, plan_sha256_value)
        actions = [a for a in document["actions"] if a["action_id"] == action_id]
        if len(actions) != 1:
            raise ServiceRefusal("Exact current action required")
        action = actions[0]
        payload = self.engine.action_binding(state, action)
        if action["adapter_id"] not in STORAGE and action["adapter_id"] not in {DIAGNOSTIC_ADAPTER_ID, pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL}:
            raise ServiceRefusal("No fixed service adapter exists for this action")
        if digest(payload) != action["adapter_payload_sha256"]:
            raise ServiceRefusal("Actual payload bytes differ from approved adapter payload")
        return action, payload

    def _artifact(self, state, plan, path, expected_sha256):
        value = self._owned(path, state=state)
        if value.suffix.casefold() not in ARTIFACT_EXTENSIONS.get(plan["catalog_id"], set()) or pc_paths.protected(value.relative_to(self.root / "work").as_posix()):
            raise ServiceRefusal("Only the selected owned noncredential installer artifact format may be opened")
        with ScopedRoot(value.parent, quiet_workspace=True) as source:
            observed = source.inspect(value.name, hash_file=True, max_bytes=64 * 1024 * 1024)
        if observed["kind"] != "file" or observed["nlink"] != 1 or observed["sha256"] != expected_sha256:
            raise ServiceRefusal("Actual selected installer bytes differ from the reviewed exact content identity")
        return observed

    def _external_preflight(self, state, action, payload, evidence_ids):
        plan = payload["external_plan"]
        rows = self.engine.evidence_rows(state, evidence_ids, kinds={"precondition"}, after=state["plan"]["registered_utc"], seconds=900)
        admitted = False
        for row in rows:
            value = _decoded(read_record_bytes(self.engine.work / state["session_id"] / row["path"], EVIDENCE_MAX_BYTES))
            if not isinstance(value, dict) or value.get("schema") != EXTERNAL_PREFLIGHT:
                continue
            typed_record(value, EXTERNAL_PREFLIGHT)
            if value["action_id"] != action["action_id"] or value["plan_sha256"] != state["plan"]["sha256"] or value["external_plan_sha256"] != digest(plan) or value["mode"] != state["mode"] or value["platform"] != state["platform"] or value["observed_utc"] != row["observed_utc"] or not isinstance(value["targets"], dict) or set(value["targets"]) != set(plan["targets"]):
                raise ServiceRefusal("Preexecution proof must bind this exact reviewed action, target variants and observed time")
            for target, observed in value["targets"].items():
                expected = {**plan["target_identities"][target], "version": plan["target_versions"][target]}
                extras = {"artifact_path", "artifact_record", "signature_evidence_id", "metadata_evidence_id"}
                exact_fields(observed, set(expected) | extras, set(expected) | extras)
                if any(observed[key] != item for key, item in expected.items()):
                    raise ServiceRefusal("Preexecution selected variant differs from the reviewed version/channel/architecture/scope/publisher/content")
                if observed["artifact_path"] != plan["argv"][1] or self._artifact(state, plan, observed["artifact_path"], expected["content_sha256"]) != observed["artifact_record"]:
                    raise ServiceRefusal("Actual local installer path/native identity differs from the exact approved argv and preflight record")
                signature_row = self.engine.evidence_rows(state, [observed["signature_evidence_id"]], kinds={"research", "precondition"}, after=state["plan"]["registered_utc"], seconds=900)[0]
                signature = typed_record(_decoded(read_record_bytes(self.engine.work / state["session_id"] / signature_row["path"], EVIDENCE_MAX_BYTES)), PUBLISHER_SIGNATURE)
                method = "windows.authenticode" if state["platform"] == "windows" else "apple.pkgutil_check_signature" if state["platform"] == "macos" else "distribution.signed_metadata"
                required = {"schema": PUBLISHER_SIGNATURE, "mode": state["mode"], "platform": state["platform"],
                            "artifact_sha256": expected["content_sha256"], "publisher": expected["publisher"], "status": "verified",
                            "source_id": expected["source_id"], "method": method, "observed_utc": signature_row["observed_utc"]}
                if _without_version(signature) != required:
                    raise ServiceRefusal("Actual selected publisher/signature observation does not match this reviewed artifact and source")
                metadata_row = self.engine.evidence_rows(state, [observed["metadata_evidence_id"]], kinds={"research", "precondition"}, after=state["plan"]["registered_utc"], seconds=900)[0]
                metadata = typed_record(_decoded(read_record_bytes(self.engine.work / state["session_id"] / metadata_row["path"], EVIDENCE_MAX_BYTES)), INSTALLER_METADATA)
                required_metadata = {"schema": INSTALLER_METADATA, "mode": state["mode"], "platform": state["platform"],
                                     "artifact_sha256": expected["content_sha256"], "target_id": target, "version": expected["version"],
                                     **{key: expected[key] for key in ("channel", "architecture", "installation_scope", "publisher", "source_id")},
                                     "observed_utc": metadata_row["observed_utc"]}
                if _without_version(metadata) != required_metadata:
                    raise ServiceRefusal("Actual selected package metadata does not match the exact reviewed version/variant/publisher")
            admitted = True
        if not admitted:
            raise ServiceRefusal("Actual selected artifact and publisher/signature preexecution proof is required before a handoff")

    def record_external_preflight(self, session_id, *, action_id, plan_sha256, artifact_paths,
                                  signature_evidence_ids, metadata_evidence_ids, coordinator_verified=False):
        """Record actual selected downloaded bytes and coordinator-verified signature evidence.

        This method verifies hashes; signature trust is attributed to the
        coordinator's actual supported official-tool observation, never inferred
        from a downloaded page or imported approved/signature boolean.
        """
        with self._lock():
            if coordinator_verified is not True:
                raise ServiceRefusal("Current trusted-coordinator payload/signature verification is required")
            state = self._state(session_id, collecting=True)
            action, payload = self._binding(state, action_id, plan_sha256)
            if action["adapter_id"] != pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
                raise ServiceRefusal("External preflight belongs only to an exact reviewed official-tool handoff")
            plan = payload["external_plan"]
            if not isinstance(artifact_paths, dict) or not isinstance(signature_evidence_ids, dict) or not isinstance(metadata_evidence_ids, dict) or set(artifact_paths) != set(plan["targets"]) or set(signature_evidence_ids) != set(plan["targets"]) or set(metadata_evidence_ids) != set(plan["targets"]):
                raise ServiceRefusal("Every exact selected update target needs actual payload and publisher evidence")
            value = {"schema": EXTERNAL_PREFLIGHT, "schema_version": pc_records.SCHEMA_VERSION, "action_id": action_id, "plan_sha256": plan_sha256,
                     "external_plan_sha256": digest(plan), "mode": state["mode"], "platform": state["platform"],
                     "observed_utc": pc_records.utc_now(), "targets": {}}
            for target in plan["targets"]:
                if artifact_paths[target] != plan["argv"][1]:
                    raise ServiceRefusal("Local artifact path must be the exact reviewed fixed argv path")
                artifact_record = self._artifact(state, plan, artifact_paths[target], plan["target_identities"][target]["content_sha256"])
                value["targets"][target] = {**plan["target_identities"][target], "version": plan["target_versions"][target],
                                            "artifact_path": artifact_paths[target], "artifact_record": artifact_record,
                                            "signature_evidence_id": signature_evidence_ids[target], "metadata_evidence_id": metadata_evidence_ids[target]}
            facts = {"action_id": action_id, "plan_sha256": plan_sha256, "identity_matches": True, "scope_matches": True,
                     "content_matches": True, "compatibility_checked": True, "provenance_checked": True}
            facts.update({key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")})
            row = self._register(state, kind="precondition", value=value, facts=facts, observed_utc=value["observed_utc"])
            self._external_preflight(self.engine.read_session(session_id), action, payload, [row["evidence_id"]])
            return row

    def _operation_dir(self, session_id, operation_id, *, create=False):
        record_identifier(session_id); record_identifier(operation_id)
        path = no_links(self.work / "operations" / session_id / operation_id)
        if create:
            ensure_private_directory(self.work)
            ensure_private_directory(self.work / "operations", create=True, exist_ok=True)
            ensure_private_directory(self.work / "operations" / session_id, create=True, exist_ok=True)
            ensure_private_directory(path, create=True)
        elif not path.is_dir():
            raise ServiceRefusal("Missing service operation intent; no recreation or retry")
        else:
            ensure_private_directory(self.work)
            ensure_private_directory(self.work / "operations")
            ensure_private_directory(self.work / "operations" / session_id)
            ensure_private_directory(path)
        return path

    def _intent(self, state, operation, action, payload):
        path = self._operation_dir(state["session_id"], operation["operation_id"], create=True)
        mapping = []
        if payload["operation"] == pc_records.ADAPTER_STORAGE_QUARANTINE:
            mapping = self._quarantine_mapping(payload["storage_plan"])
        value = _service_value("operation_intent", session_id=state["session_id"],
                               engine_id=state["engine_id"], mode=state["mode"], platform=state["platform"],
                               settings_revision=state["settings_revision"], scope=state["settings"]["scope"],
                               operation=operation, action=action, payload=payload, quarantine_mapping=mapping,
                               observed_utc=pc_records.utc_now())
        self._immutable(path / "intent.json", value)
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        facts["outcome"] = "unknown"
        row = self._register(state, kind="outcome", value=value, facts=facts)
        self._immutable(path / "intent-evidence.json", _service_value("intent_evidence", evidence_id=row["evidence_id"], sha256=row["sha256"]))
        return path, value

    def _native_origin(self, state, operation, plan, *, substep=False):
        value = _service_value("native_origin", engine_id=state["engine_id"], mode=state["mode"],
                               platform=state["platform"], session_id=state["session_id"],
                               operation_id=operation["operation_id"], workflow_plan_sha256=operation["plan_sha256"],
                               native_plan_sha256=digest(plan), verification_substep=substep)
        self._immutable(self.work / ("origin-" + digest(plan) + ".json"), value)

    def _finish(self, state, operation, *, outcome, receipt, kind="outcome"):
        state = self.engine.read_session(state["session_id"])
        path = self._operation_dir(state["session_id"], operation["operation_id"])
        self._original_authority(state, operation, _service_record(_decoded(_private_read(path / "intent.json")), "operation_intent"))
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        facts["outcome"] = outcome
        value = _service_value("service_outcome", mode=state["mode"], observed_utc=pc_records.utc_now(), binding=facts, receipt=receipt)
        self._immutable(path / ("result-" + uuid.uuid4().hex + ".json"), value)
        evidence = self._register(state, kind=kind, value=value, facts=facts, observed_utc=value["observed_utc"])
        if kind == "reconciliation":
            response = self.engine.resolve(state["session_id"], pending_id="reconcile-" + operation["operation_id"], evidence_ids=[evidence["evidence_id"]])
        else:
            response = self.engine.finish_operation(state["session_id"], operation_id=operation["operation_id"], outcome=outcome,
                        evidence_ids=[evidence["evidence_id"]], summary="Selected fixed adapter outcome: " + outcome + ". Original behavior/security verification remains separate.")
        return {"operation_id": operation["operation_id"], "outcome": outcome, "receipt": receipt,
                "evidence_id": evidence["evidence_id"], "workflow": response}

    def execute_action(self, session_id, *, action_id, plan_sha256, precondition_evidence_ids,
            owner_consent_evidence_id=None, diagnostic_fixture_runner=None, diagnostic_fixture_result=None):
        with self._lock():
            state = self._state(session_id)
            if state["status"] != "active" or state["stage"] != "apply" or self.engine.pending_items(state):
                raise ServiceRefusal("New adapter work waits for the active apply stage and every selected checkpoint")
            action, payload = self._binding(state, action_id, plan_sha256)
            storage = None
            if action["adapter_id"] in STORAGE:
                if diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None:
                    raise ServiceRefusal("Diagnostic injection is not a storage adapter input")
                storage = self._storage(state, payload)
                storage.check_preconditions(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"])
                if action["adapter_id"] == pc_records.ADAPTER_STORAGE_PURGE:
                    self.engine.verify_recovery(state, action["recovery_evidence_ids"], action=action)
            elif action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
                if action["requires_os_consent"] is not True:
                    raise ServiceRefusal("Fixed local installer dispatch requires actual protected OS consent for this exact action")
                self._external_sources(payload["external_plan"])
                self._external_preflight(state, action, payload, precondition_evidence_ids)
                if diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None:
                    raise ServiceRefusal("External handoff cannot accept injected adapter output")
            elif state["mode"] != "fixture" and (diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None):
                raise ServiceRefusal("Fictional diagnostic output cannot enter a real operation")
            operation = self.engine.begin_operation(session_id, action_id=action_id, plan_sha256=plan_sha256,
                        precondition_evidence_ids=precondition_evidence_ids, owner_consent_evidence_id=owner_consent_evidence_id)["data"]
            path, intent = self._intent(state, operation, action, payload)
            current = self.engine.read_session(session_id)
            if current["status"] != "active":
                return self._finish(current, operation, outcome="failed", receipt={"adapter_invoked": False, "reason": "Owner pause/stop reached before the first adapter effect"})
            if action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
                handoff = {**_service_value("reviewed_external_handoff"), "operation_id": operation["operation_id"],
                           "action_id": action_id, "plan_sha256": plan_sha256, "adapter_payload_sha256": action["adapter_payload_sha256"],
                           "mode": state["mode"], "external_plan": payload["external_plan"],
                           "instruction": "Trusted coordinator performs only this exact reviewed official-tool operation through normal host permissions; report actual evidence. This helper executes nothing."}
                self._immutable(path / "handoff.json", handoff)
                return handoff
            self._immutable(path / "entered.json", _service_value("effect_boundary", observed_utc=pc_records.utc_now(), operation_id=operation["operation_id"], adapter_id=action["adapter_id"]))
            try:
                if storage is not None:
                    plan, expected = payload["storage_plan"], payload["storage_plan_sha256"]
                    self._native_origin(state, operation, plan)
                    if payload["operation"] == pc_records.ADAPTER_STORAGE_BACKUP_CREATE:
                        if plan["required_recovery"]:
                            self._retain(session_id, {plan["destination"]: None, plan["destination"] + ".manifest.json": None}, reason="Required backup reserved before effect; incomplete/unknown artifacts remain protected")
                        receipt = storage.create_backup(plan=plan, expected_plan_sha256=expected)
                    elif payload["operation"] == pc_records.ADAPTER_STORAGE_RESTORE:
                        receipt = storage.restore_backup(plan=plan, expected_plan_sha256=expected)
                    elif payload["operation"] == pc_records.ADAPTER_STORAGE_QUARANTINE:
                        self._reserve_quarantine(state, operation, action, payload, intent)
                        receipt = storage.quarantine(plan=plan, expected_plan_sha256=expected)
                    elif payload["operation"] == pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE:
                        receipt = storage.restore_quarantine(plan=plan, expected_plan_sha256=expected)
                    else:
                        receipt = storage.purge_quarantine(plan=plan, expected_plan_sha256=expected)
                    verified = storage.verify_outcome(plan=plan, expected_plan_sha256=expected, receipt=receipt)
                    result = {"native_receipt": receipt, "verification": verified}
                    if "restore_probe_destination" in payload:
                        probe = storage.plan_restore(receipt=receipt, destination=payload["restore_probe_destination"])
                        self._immutable(path / "restore-probe-plan.json", probe)
                        self._native_origin(state, operation, probe, substep=True)
                        self._retain(session_id, {str(Path(probe["destination"]) / f["root_id"] / f["relative_path"]): f["sha256"] for f in probe["files"]},
                                     reason="Exact restoration-probe files reserved before their reviewed verification write")
                        restoration = storage.restore_backup(plan=probe, expected_plan_sha256=digest(probe))
                        result["restore_probe_receipt"] = restoration
                        result["restore_probe_verification"] = storage.verify_outcome(plan=probe, expected_plan_sha256=digest(probe), receipt=restoration)
                        result["recovery_evidence"] = self._register_recovery(session_id, payload["output_root"], receipt, restoration, completing=True)
                    return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded", receipt=result)
                request = payload["request"]
                if request["platform"] == "windows" and diagnostic_fixture_result is None:
                    handoff = {**_service_value("windows_diagnostic_handoff"), "operation_id": operation["operation_id"],
                               "request": request, "helper": "diagnostic_windows.ps1:Invoke-WindowsDiagnostic",
                               "instruction": "Use this fixed native helper in the matching host; return its selected actual adapter result. No generic command is accepted."}
                    self._immutable(path / "handoff.json", handoff)
                    return handoff
                observed = validate_adapter_result(request, diagnostic_fixture_result) if diagnostic_fixture_result is not None else collect_recipe(request, runner=diagnostic_fixture_runner, coordinator_authorized=state["mode"] == "real")
                record = self.diagnostics.record_result(request["request_id"], adapter_result=observed)
                return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded" if observed["status"] == "observed" else "failed", receipt=record)
            except (StorageRefusal, ScopedFSError, DiagnosticRefusal, OSError, ValueError) as exc:
                # A move/write can finish before its receipt. Error text may
                # contain private paths. Preserve only a categorical failure.
                return self._finish(self.engine.read_session(session_id), operation, outcome="unknown",
                        receipt={"adapter_invoked": True, "failure_class": type(exc).__name__, "possible_partial_effects": True,
                                 "failure_code": getattr(exc, "code", None),
                                 "instruction": "Preserve exact intent, native attempt/mapping and outputs; inspect actual state before any new plan."})

    @staticmethod
    def _original_authority(state, operation, intent):
        original = intent.get("operation")
        current = state.get("operations", {}).get(operation.get("operation_id"))
        fields = {"operation_id", "action_id", "plan_sha256", "settings_revision", "started_utc", "adapter_id", "mutating"}
        if (not isinstance(original, dict) or not isinstance(current, dict)
                or any(key not in original or key not in current or key not in operation
                       or original[key] != current[key] or operation[key] != current[key] for key in fields)
                or intent.get("settings_revision") != state.get("settings_revision")
                or original["settings_revision"] != state.get("settings_revision")
                or not isinstance(intent.get("scope"), dict) or intent["scope"] != state.get("settings", {}).get("scope")
                or any(intent.get(key) != state.get(key) for key in ("engine_id", "mode", "platform", "session_id"))):
            raise ServiceRefusal("Original operation scope/settings authority changed; preserve the consumed outcome without relabeling, migration or retry")

    def inspect_operation(self, session_id, *, operation_id):
        state = self._state(session_id)
        if operation_id not in state["operations"]:
            raise ServiceRefusal("Operation belongs to another session")
        path = self._operation_dir(session_id, operation_id)
        intent = _service_record(_decoded(_private_read(path / "intent.json")), "operation_intent")
        operation = state["operations"][operation_id]
        ref = _service_record(_decoded(_private_read(path / "intent-evidence.json")), "intent_evidence")
        row = state["evidence"].get(ref.get("evidence_id"))
        if not row or row["sha256"] != ref.get("sha256") or digest(intent) != row["sha256"]:
            raise ServiceRefusal("Original full service intent does not match its engine-owned evidence")
        data = read_record_bytes(self.engine.work / session_id / row["path"], EVIDENCE_MAX_BYTES)
        if data != encoded(intent):
            raise ServiceRefusal("Original service intent bytes changed")
        if intent.get("engine_id") != state["engine_id"] or intent.get("mode") != state["mode"] or intent.get("session_id") != session_id or intent["operation"]["operation_id"] != operation_id or intent["operation"]["plan_sha256"] != operation["plan_sha256"] or digest(intent["payload"]) != intent["action"]["adapter_payload_sha256"]:
            raise ServiceRefusal("Service intent does not match the immutable engine operation")
        return {"operation": operation, "intent": intent, "effect_boundary_entered": (path / "entered.json").exists(),
                "handoff": _read_service(_decoded(_private_read(path / "handoff.json"))) if (path / "handoff.json").exists() else None}

    def complete_diagnostic(self, session_id, *, operation_id, adapter_result, coordinator_observed=False):
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            self._original_authority(self.engine.read_session(session_id), operation, intent)
            if coordinator_observed is not True or operation["outcome"] is not None or intent["action"]["adapter_id"] != DIAGNOSTIC_ADAPTER_ID:
                raise ServiceRefusal("Only an active exact diagnostic handoff accepts this result")
            request = intent["payload"]["request"]
            observed = validate_adapter_result(request, adapter_result)
            record = self.diagnostics.record_result(request["request_id"], adapter_result=observed)
            return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded" if observed["status"] == "observed" else "failed", receipt=record)

    def _external_receipt(self, state, operation, intent, actual_receipt, *, after_restart=False):
        typed_record(actual_receipt, EXTERNAL_RECEIPT)
        plan = intent["payload"]["external_plan"]
        expected = {"operation_id": operation["operation_id"],
                    "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"],
                    "adapter_payload_sha256": intent["action"]["adapter_payload_sha256"], "mode": intent["mode"],
                    "platform": intent["platform"], "catalog_id": plan["catalog_id"]}
        if any(actual_receipt[key] != value for key, value in expected.items()) or not isinstance(actual_receipt["outcome"], str) or actual_receipt["outcome"] not in {"succeeded", "failed", "partial", "unknown", "installed_restart_pending"}:
            raise ServiceRefusal("External result differs from the consumed exact handoff")
        observed, started = utc_time(actual_receipt["observed_utc"]), utc_time(operation["started_utc"])
        if stepped_back(observed, started):
            raise ServiceRefusal(CLOCK_STEP_MESSAGE, code="clock-step")
        if not started <= observed or after_now(observed):
            raise ServiceRefusal("External result requires fresh post-start observation")
        code = actual_receipt["tool_exit_code"]
        if code is not None and (type(code) is not int or not -(1 << 31) <= code < (1 << 31)):
            raise ServiceRefusal("Typed actual tool status required")
        if actual_receipt["postcondition_state"] not in {"verified", "not_verified", "unknown"}:
            raise ServiceRefusal("Explicit observed target postcondition state required")
        msi = plan["catalog_id"] == "windows.msiexec.install" and intent["platform"] == "windows"
        if actual_receipt["outcome"] == "installed_restart_pending" and (not msi or code != 3010 or actual_receipt["postcondition_state"] == "verified" or after_restart):
            raise ServiceRefusal("Only actual MSI3010 may record installed with restart and behavior verification still pending")
        if msi and code == 3010 and actual_receipt["outcome"] not in ({"succeeded", "failed", "partial"} if after_restart else {"installed_restart_pending"}):
            raise ServiceRefusal("Preserve MSI3010 as restart-pending until its exact later boot and behavior verification")
        if msi and code == 1641 and actual_receipt["outcome"] != "unknown":
            raise ServiceRefusal("Unexpected MSI restart initiation under no-restart arguments requires unknown reconciliation")
        self.engine.evidence_rows(state, actual_receipt["evidence_ids"], after=operation["started_utc"], seconds=900,
                              allow_empty=actual_receipt["outcome"] == "unknown")
        successful_code = code == 0 or after_restart and msi and code == 3010
        if actual_receipt["outcome"] == "succeeded" and (not successful_code or actual_receipt["postcondition_state"] != "verified"):
            raise ServiceRefusal("Success requires actual successful tool status and observed exact target state")
        if after_restart and (not msi or code != 3010 or actual_receipt["outcome"] not in {"succeeded", "failed", "partial"}):
            raise ServiceRefusal("Post-restart completion preserves the original exact MSI3010 status")
        clean = copy.deepcopy(actual_receipt)
        for key in ("observed_effects", "limitations"):
            if not isinstance(clean[key], list) or not 1 <= len(clean[key]) <= 20:
                raise ServiceRefusal("Selected bounded effect and limitation explanations required")
            clean[key] = [sanitize_text(text, limit=2000) for text in clean[key]]
        return clean

    def _restart_boot(self, state, operation, evidence_id):
        row = self.engine.evidence_rows(state, [evidence_id], kinds={"precondition", "outcome"}, after=operation["started_utc"], seconds=900)[0]
        value = typed_record(_decoded(_private_read(self.engine.work / state["session_id"] / row["path"])), WINDOWS_BOOT)
        if (value["mode"] != state["mode"]
                or value["platform"] != "windows" or value["source"] != "windows.cim_last_boot_up_time"
                or value["observed_utc"] != row["observed_utc"] or utc_time(value["last_boot_utc"]) > utc_time(value["observed_utc"])):
            raise ServiceRefusal("Restart accounting needs an actual selected typed Windows boot observation")
        return value

    def _record_restart_pending(self, state, operation, intent, receipt, boot_evidence_id):
        boot = self._restart_boot(state, operation, boot_evidence_id)
        if not utc_time(boot["last_boot_utc"]) <= utc_time(receipt["observed_utc"]) <= utc_time(boot["observed_utc"]):
            raise ServiceRefusal("Intervening or unaccounted restart cannot become a new assumed restart baseline")
        path = self._operation_dir(state["session_id"], operation["operation_id"]) / "external-restart-pending.json"
        if path.exists():
            if _private_read(path) != encoded(receipt):
                raise ServiceRefusal("Original MSI3010 receipt is immutable; no replacement or installer retry")
        else:
            self._immutable(path, receipt)
        pending = {"schema": RESTART_PENDING, "schema_version": pc_records.SCHEMA_VERSION, "session_id": state["session_id"],
                   **{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256", "settings_revision")},
                   "scope_sha256": digest(intent["scope"]), "adapter_payload_sha256": intent["action"]["adapter_payload_sha256"],
                   "external_plan_sha256": digest(intent["payload"]["external_plan"]), "mode": state["mode"], "platform": "windows",
                   "catalog_id": "windows.msiexec.install", "original_exit_code": 3010, "observed_utc": pc_records.utc_now(),
                   "native_receipt_relative_path": path.relative_to(self.root).as_posix(), "native_receipt_sha256": digest(receipt),
                   "before_boot_evidence_id": boot_evidence_id}
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        facts["outcome"] = "unknown"
        row = self._register(state, kind="outcome", value=pending, facts=facts, observed_utc=pending["observed_utc"])
        response = self.engine.record_restart_pending(state["session_id"], operation_id=operation["operation_id"], evidence_id=row["evidence_id"])
        return {"operation_id": operation["operation_id"], "outcome": "installed_restart_pending", "operation_active": True,
                "automatic_retry": False, "restart_executor": False, "receipt": receipt, "evidence_id": row["evidence_id"],
                "instruction": "Installation reported MSI3010. Keep this consumed operation, obtain its separate owner restart decision, then verify the actual boot transition and original behavior. Do not rerun the installer.",
                "workflow": response}

    def complete_external(self, session_id, *, operation_id, actual_receipt, coordinator_observed=False, restart_boot_evidence_id=None):
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            state = self.engine.read_session(session_id)
            self._original_authority(state, operation, intent)
            if coordinator_observed is not True or operation["outcome"] not in {None, "unknown"} or intent["action"]["adapter_id"] != pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
                raise ServiceRefusal("Actual trusted-coordinator observation for an active exact external operation is required")
            clean = self._external_receipt(state, operation, intent, actual_receipt)
            if clean["outcome"] == "installed_restart_pending":
                if not isinstance(restart_boot_evidence_id, str):
                    raise ServiceRefusal("MSI3010 requires its fresh owned pre-restart boot observation")
                return self._record_restart_pending(state, operation, intent, clean, restart_boot_evidence_id)
            if operation["outcome"] == "unknown":
                raise ServiceRefusal("Only the exact late MSI3010 receipt can enter restart accounting for this unknown consumed operation")
            if restart_boot_evidence_id is not None or (self._operation_dir(session_id, operation_id) / "external-restart-pending.json").exists():
                raise ServiceRefusal("Use the exact original restart-pending verification path; never translate its exit status to zero")
            return self._finish(state, operation, outcome=clean["outcome"], receipt=clean)

    def complete_external_after_restart(self, session_id, *, operation_id, actual_receipt, verification_evidence_id, coordinator_observed=False):
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            state = self.engine.read_session(session_id)
            self._original_authority(state, operation, intent)
            if coordinator_observed is not True or operation["outcome"] not in {None, "unknown"} or intent["action"]["adapter_id"] != pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
                raise ServiceRefusal("Only the active consumed external operation accepts actual post-restart evidence")
            clean = self._external_receipt(state, operation, intent, actual_receipt, after_restart=True)
            row = self.engine.evidence_rows(state, [verification_evidence_id], kinds={"outcome"}, after=operation["started_utc"], seconds=900)[0]
            proof = _named(_decoded(_private_read(self.engine.work / session_id / row["path"])), RESTART_VERIFICATION,
                           "Exact typed post-restart verification is required")
            pending_row = self.engine.evidence_rows(state, [proof.get("pending_evidence_id")], kinds={"outcome"}, after=operation["started_utc"])[0]
            pending = _named(_decoded(_private_read(self.engine.work / session_id / pending_row["path"])), RESTART_PENDING,
                             "The final verification must reference the exact typed restart-pending record")
            original_path = self._operation_dir(session_id, operation_id) / "external-restart-pending.json"
            original_data = _private_read(original_path)
            preserved = "Post-restart outcome must preserve the exact original MSI3010 receipt and later verification"
            if (pending.get("native_receipt_relative_path") != original_path.relative_to(self.root).as_posix()
                    or pending.get("native_receipt_sha256") != digest(original_data)):
                raise ServiceRefusal(preserved)
            original = _named(_decoded(original_data), EXTERNAL_RECEIPT, preserved)
            if (original.get("tool_exit_code") != 3010 or original.get("outcome") != "installed_restart_pending"
                    or utc_time(clean["observed_utc"]) < utc_time(proof.get("observed_utc"))):
                raise ServiceRefusal(preserved)
            verification = self.engine.record_restart_verification(session_id, operation_id=operation_id, evidence_id=verification_evidence_id)
            if clean["outcome"] == "succeeded" and verification["data"].get("behavior_passed") is not True:
                raise ServiceRefusal("Actual post-restart target or original behavior did not pass; preserve failed or partial effects without claiming success")
            return self._finish(self.engine.read_session(session_id), operation, outcome=clean["outcome"],
                receipt={"external_receipt": clean, "original_restart_pending_receipt": original,
                         "restart_verification_evidence_id": verification_evidence_id},
                kind="reconciliation" if operation["outcome"] == "unknown" else "outcome")

    def reconcile_operation(self, session_id, *, operation_id):
        """Inspect actual native outcome; absence remains unknown and consumed."""
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            payload = intent["payload"]
            if intent["action"]["adapter_id"] not in STORAGE:
                raise ServiceRefusal("External/diagnostic outcomes require their actual bounded callback evidence")
            if operation["outcome"] not in {None, "unknown"}:
                raise ServiceRefusal("Known operation receipt is already consumed; retain historical result")
            state = self.engine.read_session(session_id)
            self._original_authority(state, operation, intent)
            storage = StorageService(output_root=payload["output_root"], quiet_workspace=True, protected_roots=payload["protected_roots"])
            outcome_path = Path(payload["output_root"]) / ("outcome-" + STORAGE[payload["operation"]][1] + "-" + payload["storage_plan_sha256"] + ".json")
            try:
                receipt = _decoded(_private_read(outcome_path))
                origin = _service_record(_decoded(_private_read(self.work / ("origin-" + payload["storage_plan_sha256"] + ".json"))), "native_origin")
                if origin["operation_id"] != operation_id or origin["mode"] != state["mode"] or origin["engine_id"] != state["engine_id"]:
                    raise ServiceRefusal("Native outcome has another operation's origin")
                verification = storage.verify_outcome(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"], receipt=receipt)
                reconciled_receipt = {"native_receipt": receipt, "verification": verification}
                if "restore_probe_destination" in payload:
                    probe = _decoded(_private_read(self._operation_dir(session_id, operation_id) / "restore-probe-plan.json"))
                    if probe["destination"] != payload["restore_probe_destination"] or probe["receipt"] != receipt:
                        raise ServiceRefusal("Probe plan differs from original exact reviewed verification scope")
                    probe_path = Path(payload["output_root"]) / ("outcome-restore-" + digest(probe) + ".json")
                    restoration = _decoded(_private_read(probe_path))
                    storage.verify_outcome(plan=probe, expected_plan_sha256=digest(probe), receipt=restoration)
                    reconciled_receipt["restore_probe_receipt"] = restoration
                    reconciled_receipt["recovery_evidence"] = self._register_recovery(session_id, payload["output_root"], receipt, restoration, completing=True)
            except (OSError, StorageRefusal, ScopedFSError, WorkflowRefusal, ServiceRefusal, ValueError):
                if operation["outcome"] is None:
                    return self._finish(state, operation, outcome="unknown", receipt={"possible_partial_effects": True, "native_outcome_verified": False,
                            "instruction": "Missing or inconsistent actual native outcome; no retry or success is permitted."})
                return {"operation_id": operation_id, "outcome": "unknown", "held": True, "automatic_retry": False}
            return self._finish(state, operation, outcome="succeeded", receipt=reconciled_receipt,
                                kind="reconciliation" if operation["outcome"] == "unknown" else "outcome")
