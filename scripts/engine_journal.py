"""Engine storage and shared checks: the Journal (the private session folders, the locks and the chained session journal,
owned by workflow_core.WorkflowEngine), the record names and size caps, and the typed readers of the engine's record families.
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

import pc_records
from pc_records import SCHEMA_VERSION, digest, encoded
import private_workspace
import storage_contract


BACKEND = "patchcairn.workflow.python"
OUTCOMES = {"succeeded", "failed", "partial", "unknown"}
ID = pc_records.ID
SHA = pc_records.SHA256
SERVICE_RECORD = "patchcairn.service"
ASSESSMENT_ACCESS, ASSESSMENT_SUMMARY, ASSESSMENT_VERIFICATION = ("patchcairn.assessment.access", "patchcairn.assessment.summary",
                                                                  "patchcairn.assessment.verification")
FIXTURE_ADAPTER, DIAGNOSTIC_ADAPTER, EXTERNAL_ADAPTER, STORAGE_ADAPTER = ("patchcairn.fixture.adapter", "patchcairn.diagnostic.adapter",
                                                                          "patchcairn.external.adapter", "patchcairn.storage.adapter")
EXTERNAL_PLAN, EXTERNAL_RECOVERY, EXTERNAL_VERIFICATION = "patchcairn.external.plan", "patchcairn.external.recovery", "patchcairn.external.verification"
EXTERNAL_PREFLIGHT, EXTERNAL_RECEIPT = "patchcairn.external.preflight", "patchcairn.external.receipt"
PUBLISHER_SIGNATURE, INSTALLER_METADATA = "patchcairn.publisher.signature", "patchcairn.installer.metadata"
RECOVERY_RETENTION, RECOVERY_BINDING, QUARANTINE_RECOVERY = "patchcairn.recovery.retention", "patchcairn.recovery.binding", "patchcairn.quarantine.recovery"
WINDOWS_BOOT, RESTART_PENDING, RESTART_VERIFICATION = "patchcairn.windows.boot.observation", "patchcairn.restart.pending", "patchcairn.restart.verification"
_EXTERNAL_RECEIPT_FIELDS = {"operation_id", "action_id", "plan_sha256", "adapter_payload_sha256", "mode", "platform", "catalog_id", "observed_utc", "outcome",
                            "tool_exit_code", "postcondition_state", "evidence_ids", "observed_effects", "limitations"}
_ASSESSMENT_COMMON = {"job", "mode", "scope_sha256", "settings_revision"}
# Exact fields of each typed record family the engine reads, besides "schema" and "schema_version":
# (required, optional).
RECORD_FIELDS = {
    ASSESSMENT_ACCESS: ({"target", "operations", "local_content", "llm_content", "sensitive_exceptions"}, set()),
    ASSESSMENT_SUMMARY: (_ASSESSMENT_COMMON | {"summary", "findings", "limitations", "assessed_evidence_ids"}, set()),
    ASSESSMENT_VERIFICATION: (_ASSESSMENT_COMMON | {"summary_evidence_id", "summary_sha256", "assessed_evidence_ids", "coverage_checked", "limitations_checked",
                                                    "observed_utc"}, set()),
    FIXTURE_ADAPTER: ({"operation", "fixture_plan", "fixture_plan_sha256", "inventory_sha256"}, set()),
    DIAGNOSTIC_ADAPTER: ({"operation", "request", "request_sha256", "inventory_sha256"}, set()),
    EXTERNAL_ADAPTER: ({"operation", "external_plan", "external_plan_sha256", "inventory_sha256"}, set()),
    STORAGE_ADAPTER: (set(storage_contract.PAYLOAD_REQUIRED), set(storage_contract.PAYLOAD_OPTIONAL)),
    EXTERNAL_PLAN: ({"kind", "platform", "mode", "catalog_id", "official_tool", "argv", "targets", "target_versions", "target_identities", "sources",
                     "provenance_evidence_ids", "compatibility_evidence_ids", "recovery_plan", "recovery_plan_sha256", "verification_plan",
                     "verification_plan_sha256", "scope"}, set()),
    EXTERNAL_RECOVERY: ({"strategy", "evidence_ids", "limits"}, set()),
    EXTERNAL_VERIFICATION: ({"original_success_condition", "checks"}, set()),
    EXTERNAL_PREFLIGHT: ({"action_id", "plan_sha256", "external_plan_sha256", "mode", "platform", "observed_utc", "targets"}, set()),
    EXTERNAL_RECEIPT: (_EXTERNAL_RECEIPT_FIELDS, set()),
    PUBLISHER_SIGNATURE: ({"mode", "platform", "artifact_sha256", "publisher", "status", "source_id", "method", "observed_utc"}, set()),
    INSTALLER_METADATA: ({"mode", "platform", "artifact_sha256", "target_id", "version", "channel", "architecture", "installation_scope", "publisher",
                          "source_id", "observed_utc"}, set()),
    RECOVERY_RETENTION: ({"session_id", "required", "artifacts"}, set()),
    RECOVERY_BINDING: ({"output_root", "backup_receipt", "restore_receipt", "retention_evidence_id"}, set()),
    QUARANTINE_RECOVERY: ({"output_root", "quarantine_receipt", "restore_plan", "restore_plan_sha256", "retention_evidence_id"}, set()),
    WINDOWS_BOOT: ({"mode", "platform", "observed_utc", "last_boot_utc", "source"}, set()),
    RESTART_PENDING: ({"session_id", "operation_id", "action_id", "plan_sha256", "settings_revision", "scope_sha256", "adapter_payload_sha256",
                       "external_plan_sha256", "mode", "platform", "catalog_id", "original_exit_code", "observed_utc", "native_receipt_relative_path",
                       "native_receipt_sha256", "before_boot_evidence_id"}, set()),
    RESTART_VERIFICATION: ({"session_id", "operation_id", "action_id", "plan_sha256", "settings_revision", "scope_sha256", "external_plan_sha256", "mode",
                            "platform", "catalog_id", "original_exit_code", "pending_evidence_id", "restart_decision_message_id", "observed_utc",
                            "before_boot_evidence_id", "after_boot_evidence_id", "targets", "checks"}, set()),
}
# Caps (D-017, D-040) scale with the published entry bound. Every JSON value, and every bracket the strict
# decoder counts (also inside strings), takes at least one byte, so node caps equal to the byte caps never
# refuse a record that the byte cap admitted when it was written. Journal events keep digests of what
# changed, never per-file lists, so the journal grows with events and evidence rows, not with file counts.
JOURNAL_MAX_BYTES = 64_000_000
JOURNAL_MAX_NODES = JOURNAL_MAX_BYTES
# Evidence content may be a storage plan with three per-file lists (inventory, files, skipped). The cap allows
# MAX_BACKUP_ENTRIES rows averaging 512 bytes, about 90-character ASCII paths; rows reach about 700 bytes at
# 200-unit ASCII paths and more for escaped non-ASCII names, so such plans are refused at registration, before
# any effect. Measuring the real bound is G18's (B-BAK, MEAS).
EVIDENCE_MAX_BYTES = 3 * 512 * pc_records.MAX_BACKUP_ENTRIES
EVIDENCE_MAX_NODES = EVIDENCE_MAX_BYTES
CREATION_KEYS = ("session_id", "engine_id", "backend", "mode", "platform", "created_utc", "creation_scope_sha256", "owner_id", "job")
STATE_KEYS = {"schema_version", "session_id", "engine_id", "backend", "mode", "platform", "created_utc", "updated_utc", "creation_scope_sha256", "owner_id",
              "revision", "settings_revision", "job", "stage", "status", "settings", "scope_authorization", "evidence", "plan", "reviews", "approval",
              "irreversible_ack", "standing_policy", "operations", "pending", "schedule", "schedule_triggers", "last_reconciled_utc", "stop_reason"}


class WorkflowRefusal(pc_records.Refusal):
    """A hold or invalid request; no operation was authorized."""

    def __init__(self, message, *, code="workflow-refusal"):
        super().__init__(code, message)


class PrivacyCapabilityHold(WorkflowRefusal):
    """The filesystem could not establish the required POSIX private storage."""

    def __init__(self, message, *, code="private-storage-unavailable"):
        super().__init__(message, code=code)


def checked(check, *args, **kwargs):
    """Run a shared pc_records check; its refusal becomes a WorkflowRefusal with the same code."""
    try:
        return check(*args, **kwargs)
    except WorkflowRefusal:
        raise
    except pc_records.Refusal as error:
        raise WorkflowRefusal(str(error), code=error.code) from error


def utc_time(value):
    return checked(pc_records.parse_utc, value)


def fresh(value, *, after=None, seconds=900):
    checked(pc_records.fresh, value, after=after, seconds=seconds)


def bounded_text(value, name="text", limit=4000):
    return checked(pc_records.bounded_text, value, name, limit)


def record_identifier(value, name="identifier"):
    return checked(pc_records.identifier, value, name)


def _reader(name):
    required, optional = RECORD_FIELDS[name]

    def read(record):
        checked(pc_records.require_schema, record, name)
        exact_fields(record, required | optional | {"schema", "schema_version"}, required | {"schema", "schema_version"})
        return record
    return read


# One registered reader per typed record family the engine owns (pc_records.READERS).
_READERS = {name: pc_records.register_reader(name, _reader(name)) for name in RECORD_FIELDS}


def typed_record(value, name):
    """Return ``value`` if it is a record of the engine family ``name`` with exactly its fields."""
    return _READERS[name](value)


def ids(value, name="identifiers", *, allow_empty=True):
    if not isinstance(value, list) or len(value) > 500 or (not allow_empty and not value):
        raise WorkflowRefusal("Invalid " + name)
    for item in value:
        record_identifier(item, name)
    if len(set(value)) != len(value):
        raise WorkflowRefusal("Duplicate " + name)
    return value


def exact_fields(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise WorkflowRefusal("Unexpected or missing record fields")


def no_links(path):
    path = Path(path)
    if ".." in path.parts:
        raise WorkflowRefusal("Parent path traversal is not admitted")
    path = path.absolute()
    for part in [path, *path.parents]:
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise WorkflowRefusal("Link or reparse paths are not admitted")
    return path


def _admitted(admission, *args, **kwargs):
    """Run a private_workspace admission. A platform or filesystem that cannot provide owner-only storage is a
    PrivacyCapabilityHold; any other refusal (unsafe existing permissions, an existing name) a WorkflowRefusal."""
    try:
        return admission(*args, **kwargs)
    except private_workspace.PrivateWorkspaceError as error:
        if re.search(r"unavailable|foreign-filesystem|unsupported", error.code):
            raise PrivacyCapabilityHold("Native private storage is unavailable: " + error.code, code=error.code) from error
        raise WorkflowRefusal("Native private engine storage admission held: " + error.code, code=error.code) from error


def private_directory(path, *, create=False, parents=False, exist_ok=False):
    return _admitted(private_workspace.ensure_private_directory, no_links(path), create=create, parents=parents, exist_ok=exist_ok)


def private_file(path):
    return _admitted(private_workspace.ensure_private_file, no_links(path))


def write_private_new(path, data):
    path = no_links(path)
    private_directory(path.parent)
    _admitted(private_workspace.write_private_new, path, data)


def _open_private(path):
    """An owner-only regular file opened without following links; checked again on the open handle."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    private_directory(path.parent)
    private_file(path)
    handle = os.fdopen(os.open(path, flags), "rb")
    try:
        info = os.fstat(handle.fileno())
        named = path.lstat()
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise WorkflowRefusal("The admitted private path no longer identifies the opened file")
        if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise WorkflowRefusal("Private engine records must stay current-owner single-link files 0600")
        private_file(path)
    except BaseException:
        handle.close()
        raise
    return handle, info


def read_record_bytes(path, max_bytes=16_000_000, *, private=False):
    no_links(path)
    if private:
        handle, info = _open_private(path)
    else:
        # Separately scoped records have their own native admission contract;
        # engine-private modes must not be imposed on them.
        handle = path.open("rb")
        info = os.fstat(handle.fileno())
    with handle:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
            raise WorkflowRefusal("Owned file is not a bounded ordinary single-link file")
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise WorkflowRefusal("Owned record exceeds size limit")
    return data


def _private_digest(path, max_bytes):
    """SHA-256 and size of a private owned file, hashed in 1 MiB chunks so large evidence is never held whole."""
    handle, info = _open_private(no_links(path))
    with handle:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
            raise WorkflowRefusal("Owned file is not a bounded ordinary single-link file")
        hasher, size = hashlib.sha256(), 0
        while chunk := handle.read(1 << 20):
            size += len(chunk)
            if size > max_bytes:
                raise WorkflowRefusal("Owned record exceeds size limit")
            hasher.update(chunk)
    return hasher.hexdigest(), size


def decode_record(data, *, max_bytes=pc_records.DEFAULT_MAX_BYTES, max_nodes=pc_records.DEFAULT_MAX_NODES):
    return checked(pc_records.decode_strict, data, max_bytes=max_bytes, max_nodes=max_nodes)


def container(value, kind):
    return checked(pc_records.require_container, value, kind)


def older_folder(folder, check, *args):
    """Run a marker ``check``; an older-format marker means the whole folder is older, so the refusal names that
    folder (relative to the repository) and the owner's next step. Records are never migrated or deleted."""
    try:
        return check(*args)
    except pc_records.Refusal as error:
        if error.code != "older-format":
            raise
        raise WorkflowRefusal("The folder " + folder + " holds records in an older PatchCairn format, which cannot be read. "
                              "PatchCairn never changes or deletes them: keep that folder unchanged, move it aside to keep "
                              "its records, and then start a new session.", code="older-format") from error


def older_format_message(error):
    """The plain reason and next step when ``error`` refuses a record in an older format, otherwise None
    (both command-line tools show it as it is; older records are never migrated)."""
    return str(error) if isinstance(error, pc_records.Refusal) and error.code == "older-format" else None


def atomic_replace(path, data):
    no_links(path)
    private_directory(path.parent)
    if path.exists():
        private_file(path)
    temp = path.parent / (".write-" + uuid.uuid4().hex)
    try:
        write_private_new(temp, data)
        private_directory(path.parent)
        if path.exists():
            private_file(path)
        os.replace(temp, path)
        private_file(path)
    finally:
        if temp.exists():
            temp.unlink()


def admit_engine(backend, verify_artifact):
    """The engine's own preconditions, refused before any storage is touched."""
    if sys.version_info < (3, 12):
        raise WorkflowRefusal("Python 3.12 or newer is required")
    if backend != BACKEND:
        raise WorkflowRefusal("Foreign backend is not supported")
    if verify_artifact is not None and not callable(verify_artifact):
        raise WorkflowRefusal("The artifact verifier must be callable")


class Journal:
    """The engine's private session store: its folders, locks and chained session journal. The engine owns it and
    passes ``validate(state)``, its full session check, which the journal runs on every state it reads or writes."""

    def __init__(self, root, work_relative, validate):
        self._validate = validate
        self.root = no_links(Path(root) if root else Path(__file__).absolute().parent.parent)
        rel = PurePosixPath(work_relative)
        if (rel.is_absolute() or "\\" in work_relative or not rel.parts or rel.parts[0] != "work" or any(p in {".", ".."} or ":" in p for p in rel.parts)
                or len(rel.parts) < 2):
            raise WorkflowRefusal("Session storage must be a named child of repository work/")
        self.work = no_links(self.root.joinpath(*rel.parts))
        private_directory(self.work, create=True, parents=True, exist_ok=True)
        marker = self.work / "engine.json"
        if not marker.exists():
            if any(self.work.iterdir()):
                raise WorkflowRefusal("Engine creation marker is missing from nonempty storage; do not recreate or migrate it")
            try:
                write_private_new(marker, encoded({"schema_version": SCHEMA_VERSION, "backend": BACKEND, "engine_id": uuid.uuid4().hex}))
            except WorkflowRefusal:
                if not marker.exists():
                    raise
        self.marker = older_folder(rel.as_posix(), lambda: container(decode_record(self.read_owned(marker)), "engine_marker"))
        exact_fields(self.marker, {"schema_version", "backend", "engine_id"}, {"schema_version", "backend", "engine_id"})
        if self.marker["backend"] != BACKEND:
            raise WorkflowRefusal("Missing or foreign engine marker; migration is not permitted")
        record_identifier(self.marker["engine_id"])

    def private_path(self, path):
        path = no_links(path)
        try:
            relative = path.relative_to(self.work)
        except ValueError as error:
            raise WorkflowRefusal("Private engine records must stay inside the exact engine namespace") from error
        current = private_directory(self.work)
        private_file(self.work / "engine.json")
        for part in relative.parts[:-1]:
            current = private_directory(current / part)
        return path

    def read_owned(self, path, max_bytes=16_000_000):
        return read_record_bytes(self.private_path(path), max_bytes, private=True)

    def directory(self, session_id):
        record_identifier(session_id, "session identifier")
        private_directory(self.work)
        private_file(self.work / "engine.json")
        path = no_links(self.work / session_id)
        if not path.is_dir():
            raise WorkflowRefusal("Session is not registered; it will not be recreated")
        private_directory(path)
        private_directory(path / "evidence")
        return path

    @contextmanager
    def lock(self, session_id):
        path = self.directory(session_id) / ".lock"
        try:
            private_directory(path, create=True)
        except WorkflowRefusal as error:
            if error.code != "private-directory-exists":
                raise
            raise WorkflowRefusal("Session is locked by another writer or interrupted write; inspect it before recovery") from error
        try:
            yield
        finally:
            path.rmdir()

    @contextmanager
    def registry_lock(self):
        private_directory(self.work)
        private_file(self.work / "engine.json")
        path = self.work / ".registry-lock"
        try:
            private_directory(path, create=True)
        except WorkflowRefusal as error:
            if error.code != "private-directory-exists":
                raise
            raise WorkflowRefusal("Another registry action is being coordinated; no concurrent mutation ticket is issued") from error
        try:
            yield
        finally:
            path.rmdir()

    def load(self, session_id):
        directory = self.directory(session_id)
        try:
            marker = decode_record(self.read_owned(directory / "creation.json"))
            bundle = decode_record(self.read_owned(directory / "session.json", JOURNAL_MAX_BYTES), max_bytes=JOURNAL_MAX_BYTES, max_nodes=JOURNAL_MAX_NODES)
        except FileNotFoundError as error:
            raise WorkflowRefusal("Registered session state is missing; no silent reconstruction") from error
        exact_fields(bundle, {"state", "events"}, {"state", "events"})
        state = self._validate(bundle["state"])
        container(marker, "session_creation")
        exact_fields(marker, {"schema_version", *CREATION_KEYS}, {"schema_version", *CREATION_KEYS})
        if any(marker[key] != state[key] for key in CREATION_KEYS) or state["session_id"] != session_id:
            raise WorkflowRefusal("Immutable session creation binding changed")
        if not isinstance(bundle["events"], list) or len(bundle["events"]) != state["revision"] + 1:
            raise WorkflowRefusal("Session event sequence is incomplete")
        previous = None
        for revision, event in enumerate(bundle["events"]):
            exact_fields(event, {"revision", "at", "type", "details", "state_sha256", "previous", "sha256"},
                         {"revision", "at", "type", "details", "state_sha256", "previous", "sha256"})
            bare = {key: value for key, value in event.items() if key != "sha256"}
            if event["revision"] != revision or event["previous"] != previous or event["sha256"] != digest(bare):
                raise WorkflowRefusal("Session event chain changed")
            utc_time(event["at"])
            previous = event["sha256"]
        if bundle["events"][-1]["state_sha256"] != digest(state):
            raise WorkflowRefusal("State does not match its committed event")
        for row in state["evidence"].values():
            if _private_digest(self.private_path(directory / row["path"]), EVIDENCE_MAX_BYTES) != (row["sha256"], row["size"]):
                raise WorkflowRefusal("Owned evidence has changed")
        return bundle

    def commit(self, directory, state, events, event_type, details):
        self._validate(state)
        event = {"revision": state["revision"], "at": state["updated_utc"], "type": event_type, "details": details, "state_sha256": digest(state),
                 "previous": events[-1]["sha256"] if events else None}
        event["sha256"] = digest(event)
        # State and its entire chained event journal share one atomic transaction.
        data = encoded({"state": state, "events": events + [event]})
        if len(data) > JOURNAL_MAX_BYTES:
            raise WorkflowRefusal("Session journal reached its bounded size; preserve it and start a separately scoped session")
        atomic_replace(self.private_path(directory / "session.json"), data)

    def change(self, session_id, event_type, mutate, expected_revision=None):
        """Apply ``mutate(state) -> (data, message)`` under the session lock and commit it; returns (state, message, data)."""
        with self.lock(session_id):
            bundle = self.load(session_id)
            current = bundle["state"]
            if expected_revision is not None and (type(expected_revision) is not int or expected_revision != current["revision"]):
                raise WorkflowRefusal("Session changed; read the current revision before writing")
            candidate = copy.deepcopy(current)
            data, message = mutate(candidate)
            candidate["revision"] += 1
            candidate["updated_utc"] = pc_records.utc_now()
            # The event keeps the digest of each changed value; the state itself is bound by state_sha256.
            changes = {key: digest(value) for key, value in candidate.items() if key not in {"revision", "updated_utc"} and value != current[key]}
            self.commit(self.directory(session_id), candidate, bundle["events"], event_type,
                        {"settings_revision": candidate["settings_revision"], "changes": changes})
        return candidate, message, data

    def read(self, session_id):
        return copy.deepcopy(self.load(session_id)["state"])


def outstanding_effects(engine):
    """Mutating operations anywhere in this engine's registry that still need an actual receipt or reconciliation."""
    private_directory(engine.work)
    private_file(engine.work / "engine.json")
    outstanding = []
    for directory in engine.work.iterdir():
        if directory.is_dir() and directory.name.startswith("session-"):
            state = engine.read_session(directory.name)
            for operation in state["operations"].values():
                restart_unresolved = operation.get("restart_pending") and operation.get("restart_verification", {}).get("boot_observed") is not True
                if (operation["mutating"] and (restart_unresolved or operation["outcome"] in {None, "unknown"} or operation["outcome"] in {"partial", "failed"}
                                               and not operation["resolution"])):
                    outstanding.append({"session_id": state["session_id"], "operation_id": operation["operation_id"], "outcome": operation["outcome"]})
    return outstanding


def require_writable(state):
    if state["status"] in {"stopped", "completed"}:
        raise WorkflowRefusal("This session is closed; evidence is preserved")


def invalidate(state):
    state["plan"] = None
    state["approval"] = None
    state["irreversible_ack"] = None
    state["reviews"] = []
    state["standing_policy"] = None
    state["scope_authorization"] = None
    state["schedule"] = None
    for item in state["pending"].values():
        if item["kind"] == "checkpoint":
            item["resolved"] = True
