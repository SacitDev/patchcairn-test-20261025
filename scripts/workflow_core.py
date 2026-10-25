"""Deterministic PatchCairn conversation-session records. This module never executes a plan.

The caller is the trusted coordinator, not an untrusted JSON authority. An owner
quote records the actual human instruction supplied by that coordinator; it is
not cryptographic proof of a human and these helpers are not an OS sandbox.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import timedelta
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import uuid
from urllib.parse import urlsplit

import diagnostic_core
import pc_paths
import pc_records
from pc_records import SCHEMA_VERSION, digest, encoded
import private_workspace
import storage_contract

sys.dont_write_bytecode = True
BACKEND = "patchcairn.workflow.python"
COMMANDS = ("start", "help", "status", "options", "cost", "settings", "pause", "resume", "stop", "resolve")
JOBS = {
    "security_updates": {"label": "Security and updates", "description": "Check agreed software, relevant security concerns and suitable official updates.", "stages": ["scope", "inventory", "research", "plan", "apply", "verify", "complete"]},
    "storage_cleanup": {"label": "Storage and cleanup", "description": "Inspect selected storage metadata and review exact safe cleanup choices.", "stages": ["scope", "inventory", "candidates", "plan", "apply", "verify", "complete"]},
    "diagnosis_repair": {"label": "Diagnosis and repair", "description": "Investigate a stated problem, compare causes and review an evidence-backed repair.", "stages": ["scope", "symptom", "hypotheses", "plan", "apply", "verify", "complete"]},
    "backup_recovery": {"label": "Backup and recovery", "description": "Review selected contents, create a verified backup or plan a checked restoration.", "stages": ["scope", "inventory", "recovery_plan", "plan", "apply", "verify", "complete"]},
}
STAGE_LABELS = {"scope": "Choose and confirm the scope", "inventory": "Review the selected items", "research": "Check official guidance and relevant risks", "candidates": "Compare cleanup choices", "symptom": "Understand the reported problem", "hypotheses": "Compare possible causes", "recovery_plan": "Choose and check a recovery approach", "plan": "Review the proposed changes", "apply": "Carry out the approved work", "verify": "Check the actual result", "complete": "Finished checks"}
CHECKPOINT_LABELS = {"scope": "the agreed scope", "findings": "the assessment findings", "plan": "the proposed changes", "before_action": "before the next action", "after_action": "after the previous action", "finish": "the final result and retained evidence", "scheduled_start": "the scheduled start"}
ACTION_LABELS = {"update": "Install the selected update", "cleanup_quarantine": "Move selected files to quarantine", "backup_create": "Create the reviewed backup", "backup_restore": "Restore the reviewed backup", "repair": "Apply the reviewed repair", "permanent_purge": "Permanently delete the selected quarantined files", "restart": "Restart", "firmware": "Review a firmware change", "os_transition": "Review a system release change", "security_policy": "Review a security setting change", "assessment": "Read-only assessment"}
KINDS = {"update", "cleanup_quarantine", "backup_create", "backup_restore", "repair", "permanent_purge", "restart", "firmware", "os_transition", "security_policy", "assessment"}
# Only the action kinds of adapters that pc_records lets a standing policy cover.
POLICY_KINDS = frozenset(kind for facts in pc_records.ADAPTERS.values() if facts["policy_coverable"] for kind in facts["kinds"])
ROLES = {"compatibility_data", "evidence_security"}
OUTCOMES = {"succeeded", "failed", "partial", "unknown"}
EVIDENCE_KINDS = {"scope_confirmation", "inventory", "research", "candidates", "symptom", "hypotheses", "recovery_plan", "precondition", "outcome", "reconciliation", "verification", "recovery", "protected_consent", "review", "fixture"}
EVIDENCE_KINDS |= {"adapter_payload", "recovery_manifest", "restore_verification", "retention", "recovery_archive"}
# Storage adapters whose plans the storage service carries out today; the other storage ids hold.
STORAGE_ADAPTERS = frozenset({pc_records.ADAPTER_STORAGE_BACKUP_CREATE, pc_records.ADAPTER_STORAGE_RESTORE, pc_records.ADAPTER_STORAGE_QUARANTINE,
                              pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE, pc_records.ADAPTER_STORAGE_PURGE})
ID = pc_records.ID
SHA = pc_records.SHA256
SERVICE_RECORD = "patchcairn.service"
ASSESSMENT_ACCESS, ASSESSMENT_SUMMARY, ASSESSMENT_VERIFICATION = "patchcairn.assessment.access", "patchcairn.assessment.summary", "patchcairn.assessment.verification"
FIXTURE_ADAPTER, DIAGNOSTIC_ADAPTER, EXTERNAL_ADAPTER, STORAGE_ADAPTER = "patchcairn.fixture.adapter", "patchcairn.diagnostic.adapter", "patchcairn.external.adapter", "patchcairn.storage.adapter"
EXTERNAL_PLAN, EXTERNAL_RECOVERY, EXTERNAL_VERIFICATION = "patchcairn.external.plan", "patchcairn.external.recovery", "patchcairn.external.verification"
EXTERNAL_PREFLIGHT, EXTERNAL_RECEIPT = "patchcairn.external.preflight", "patchcairn.external.receipt"
PUBLISHER_SIGNATURE, INSTALLER_METADATA = "patchcairn.publisher.signature", "patchcairn.installer.metadata"
RECOVERY_RETENTION, RECOVERY_BINDING, QUARANTINE_RECOVERY = "patchcairn.recovery.retention", "patchcairn.recovery.binding", "patchcairn.quarantine.recovery"
WINDOWS_BOOT, RESTART_PENDING, RESTART_VERIFICATION = "patchcairn.windows.boot.observation", "patchcairn.restart.pending", "patchcairn.restart.verification"
_EXTERNAL_RECEIPT_FIELDS = {"operation_id", "action_id", "plan_sha256", "adapter_payload_sha256", "mode", "platform", "catalog_id", "observed_utc", "outcome", "tool_exit_code", "postcondition_state", "evidence_ids", "observed_effects", "limitations"}
_ASSESSMENT_COMMON = {"job", "mode", "scope_sha256", "settings_revision"}
# Exact fields of each typed record family the engine reads, besides "schema" and "schema_version":
# (required, optional).
RECORD_FIELDS = {
    ASSESSMENT_ACCESS: ({"target", "operations", "local_content", "llm_content", "sensitive_exceptions"}, set()),
    ASSESSMENT_SUMMARY: (_ASSESSMENT_COMMON | {"summary", "findings", "limitations", "assessed_evidence_ids"}, set()),
    ASSESSMENT_VERIFICATION: (_ASSESSMENT_COMMON | {"summary_evidence_id", "summary_sha256", "assessed_evidence_ids", "coverage_checked", "limitations_checked", "observed_utc"}, set()),
    FIXTURE_ADAPTER: ({"operation", "fixture_plan", "fixture_plan_sha256", "inventory_sha256"}, set()),
    DIAGNOSTIC_ADAPTER: ({"operation", "request", "request_sha256", "inventory_sha256"}, set()),
    EXTERNAL_ADAPTER: ({"operation", "external_plan", "external_plan_sha256", "inventory_sha256"}, set()),
    STORAGE_ADAPTER: (set(storage_contract.PAYLOAD_REQUIRED), set(storage_contract.PAYLOAD_OPTIONAL)),
    EXTERNAL_PLAN: ({"kind", "platform", "mode", "catalog_id", "official_tool", "argv", "targets", "target_versions", "target_identities", "sources", "provenance_evidence_ids", "compatibility_evidence_ids", "recovery_plan", "recovery_plan_sha256", "verification_plan", "verification_plan_sha256", "scope"}, set()),
    EXTERNAL_RECOVERY: ({"strategy", "evidence_ids", "limits"}, set()),
    EXTERNAL_VERIFICATION: ({"original_success_condition", "checks"}, set()),
    EXTERNAL_PREFLIGHT: ({"action_id", "plan_sha256", "external_plan_sha256", "mode", "platform", "observed_utc", "targets"}, set()),
    EXTERNAL_RECEIPT: (_EXTERNAL_RECEIPT_FIELDS, set()),
    PUBLISHER_SIGNATURE: ({"mode", "platform", "artifact_sha256", "publisher", "status", "source_id", "method", "observed_utc"}, set()),
    INSTALLER_METADATA: ({"mode", "platform", "artifact_sha256", "target_id", "version", "channel", "architecture", "installation_scope", "publisher", "source_id", "observed_utc"}, set()),
    RECOVERY_RETENTION: ({"session_id", "required", "artifacts"}, set()),
    RECOVERY_BINDING: ({"output_root", "backup_receipt", "restore_receipt", "retention_evidence_id"}, set()),
    QUARANTINE_RECOVERY: ({"output_root", "quarantine_receipt", "restore_plan", "restore_plan_sha256", "retention_evidence_id"}, set()),
    WINDOWS_BOOT: ({"mode", "platform", "observed_utc", "last_boot_utc", "source"}, set()),
    RESTART_PENDING: ({"session_id", "operation_id", "action_id", "plan_sha256", "settings_revision", "scope_sha256", "adapter_payload_sha256", "external_plan_sha256", "mode", "platform", "catalog_id", "original_exit_code", "observed_utc", "native_receipt_relative_path", "native_receipt_sha256", "before_boot_evidence_id"}, set()),
    RESTART_VERIFICATION: ({"session_id", "operation_id", "action_id", "plan_sha256", "settings_revision", "scope_sha256", "external_plan_sha256", "mode", "platform", "catalog_id", "original_exit_code", "pending_evidence_id", "restart_decision_message_id", "observed_utc", "before_boot_evidence_id", "after_boot_evidence_id", "targets", "checks"}, set()),
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
MAX_FACT_ITEMS = pc_records.MAX_BACKUP_ENTRIES
# Facts are copied into the journal state, so they stay small; large data belongs in the evidence content.
FACTS_MAX_BYTES = 65_536
SERVICE_RECORD_MAX_BYTES = 8_000_000
CREATION_KEYS = ("session_id", "engine_id", "backend", "mode", "platform", "created_utc", "creation_scope_sha256", "owner_id", "job")
CHECKPOINTS = {"scope", "findings", "plan", "before_action", "after_action", "finish"}
STATE_KEYS = {"schema_version", "session_id", "engine_id", "backend", "mode", "platform", "created_utc", "updated_utc", "creation_scope_sha256", "owner_id", "revision", "settings_revision", "job", "stage", "status", "settings", "scope_authorization", "evidence", "plan", "reviews", "approval", "irreversible_ack", "standing_policy", "operations", "pending", "schedule", "schedule_triggers", "last_reconciled_utc", "stop_reason"}


class WorkflowRefusal(pc_records.Refusal):
    """A hold or invalid request; no operation was authorized."""

    def __init__(self, message, *, code="workflow-refusal"):
        super().__init__(code, message)


class PrivacyCapabilityHold(WorkflowRefusal):
    """The filesystem could not establish the required POSIX private storage."""

    def __init__(self, message, *, code="private-storage-unavailable"):
        super().__init__(message, code=code)


def _checked(check, *args, **kwargs):
    """Run a shared pc_records check; its refusal becomes a WorkflowRefusal with the same code."""
    try:
        return check(*args, **kwargs)
    except WorkflowRefusal:
        raise
    except pc_records.Refusal as error:
        raise WorkflowRefusal(str(error), code=error.code) from error


def utc_time(value):
    return _checked(pc_records.parse_utc, value)


def _fresh(value, *, after=None, seconds=900):
    _checked(pc_records.fresh, value, after=after, seconds=seconds)


def _text(value, name="text", limit=4000):
    return _checked(pc_records.bounded_text, value, name, limit)


def record_identifier(value, name="identifier"):
    return _checked(pc_records.identifier, value, name)


def _reader(name):
    required, optional = RECORD_FIELDS[name]

    def read(record):
        _checked(pc_records.require_schema, record, name)
        exact_fields(record, required | optional | {"schema", "schema_version"}, required | {"schema", "schema_version"})
        return record
    return read


# One registered reader per typed record family the engine owns (pc_records.READERS).
_READERS = {name: pc_records.register_reader(name, _reader(name)) for name in RECORD_FIELDS}


def typed_record(value, name):
    """Return ``value`` if it is a record of the engine family ``name`` with exactly its fields."""
    return _READERS[name](value)


def _storage_record(value, kind, message):
    """Return a typed storage record of ``kind``; ``message`` explains a missing or different kind."""
    if not isinstance(value, dict) or value.get("kind") != kind:
        raise WorkflowRefusal(message)
    return _checked(storage_contract.read_storage, value)


def _facts(action):
    """The pc_records facts of an action's adapter; an action whose OS-consent flag contradicts them is refused."""
    return _checked(pc_records.adapter_facts, action["adapter_id"], requires_os_consent=action["requires_os_consent"])


def _acknowledgments(action):
    """Acknowledgments the owner gives separately for this action (pc_records facts)."""
    return pc_records.ADAPTERS[action["adapter_id"]]["acknowledgments"]


def _without_version(record):
    """A copy of a validated record without its schema_version, for comparing the remaining fields."""
    rest = dict(record)
    rest.pop("schema_version", None)
    return rest


def _ids(value, name="identifiers", *, allow_empty=True):
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


def _json_shape(value, depth=0):
    if depth > 12:
        raise WorkflowRefusal("Record nesting exceeds the bounded schema")
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str) and len(value) > 8000:
            raise WorkflowRefusal("Evidence text is too long")
        return
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise WorkflowRefusal("Nonfinite evidence value")
        return
    if isinstance(value, list) and len(value) <= MAX_FACT_ITEMS:
        for item in value:
            _json_shape(item, depth + 1)
        return
    if isinstance(value, dict) and len(value) <= 100:
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in {"command", "commands", "execute", "eval", "approved", "authorization"}:
                raise WorkflowRefusal("Executable or self-authorizing evidence fields are not accepted")
            _json_shape(item, depth + 1)
        return
    raise WorkflowRefusal("Evidence must be bounded JSON data")


def _json_data(value):
    """Bounded JSON evidence data that the one encoder also accepts (no lone surrogates, integers within 20
    digits), checked before anything is written."""
    _json_shape(value)
    _checked(pc_records.encoded, value)


def _assessment_source_key(source, kind):
    """Validate recorded selectors lexically; never inspect or resolve a host path."""
    if kind == "observation":
        return record_identifier(source, "observation source")
    _text(source, "literal assessment source", 2000)
    if any(ord(char) < 32 or ord(char) == 127 or char in "\\*?" for char in source):
        raise WorkflowRefusal("Assessment paths require literal forward-slash spelling")
    windows = bool(re.match(r"[A-Z]:/", source)) or source.startswith("//")
    if re.match(r"[A-Z]:/", source):
        parts = source[3:].split("/") if len(source) > 3 else []
    elif source.startswith("//"):
        parts = source[2:].split("/")
        if len(parts) < 2:
            raise WorkflowRefusal("An explicit UNC server/share is required")
    elif source.startswith("/"):
        parts = source[1:].split("/") if source != "/" else []
    else:
        raise WorkflowRefusal("An absolute literal assessment source is required")
    if any(part in {"", ".", ".."} for part in parts):
        raise WorkflowRefusal("Assessment paths cannot contain traversal or alternate spellings")
    if windows and any(not pc_paths.portable(part) for part in parts):
        raise WorkflowRefusal("Ambiguous Windows assessment path")
    return source.casefold() if windows else source


def _assessment_access(value):
    typed_record(value, ASSESSMENT_ACCESS)
    if value["target"] not in ("whole_device", "selected_paths", "specific_problem"):
        raise WorkflowRefusal("Unknown assessment access descriptor")
    operations = _ids(value["operations"], "assessment operations", allow_empty=False)
    if set(operations) - {"metadata", "diagnosis", "content_read"}:
        raise WorkflowRefusal("Assessment access admits read-only operations only")
    selections = value["local_content"]
    if not isinstance(selections, list) or len(selections) > 30:
        raise WorkflowRefusal("Select at most thirty bounded local content observations")
    identifiers, identities = set(), set()
    for selection in selections:
        exact_fields(selection, {"id", "kind", "source", "selection"}, {"id", "kind", "source", "selection"})
        identifier = record_identifier(selection["id"], "assessment selection")
        if identifier in identifiers or selection["kind"] not in ("path", "observation"):
            raise WorkflowRefusal("Duplicate selection or unknown assessment source kind")
        source = _assessment_source_key(selection["source"], selection["kind"])
        _text(selection["selection"], "bounded content selection", 1000)
        identity = (selection["kind"], source, selection["selection"])
        if identity in identities:
            raise WorkflowRefusal("Duplicate local content selection")
        identifiers.add(identifier)
        identities.add(identity)
    if bool(selections) != ("content_read" in operations):
        raise WorkflowRefusal("Content-read permission needs exact local content selections")
    for field in ("llm_content", "sensitive_exceptions"):
        references = _ids(value[field], field)
        if len(references) > 30 or not set(references) <= identifiers:
            raise WorkflowRefusal("Disclosure and sensitive exceptions must reference exact local selections")


def _scope(scope):
    exact_fields(scope, {"roots", "purpose", "assessment"}, {"roots", "purpose"})
    if not isinstance(scope["roots"], list) or len(scope["roots"]) > 30 or any(not isinstance(root, str) for root in scope["roots"]) or len(set(scope["roots"])) != len(scope["roots"]):
        raise WorkflowRefusal("Select a bounded unique list of scope roots")
    for root in scope["roots"]:
        _text(root, "selected scope", 1000)
    _text(scope["purpose"], "scope purpose", 1000)
    if "assessment" in scope:
        _assessment_access(scope["assessment"])
    return copy.deepcopy(scope)


def _scope_selected(scope):
    return bool(scope["roots"]) or scope.get("assessment", {}).get("target") in ("whole_device", "specific_problem")


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


def _private_directory(path, *, create=False, parents=False, exist_ok=False):
    return _admitted(private_workspace.ensure_private_directory, no_links(path), create=create, parents=parents, exist_ok=exist_ok)


def _private_file(path):
    return _admitted(private_workspace.ensure_private_file, no_links(path))


def _write_private_new(path, data):
    path = no_links(path)
    _private_directory(path.parent)
    _admitted(private_workspace.write_private_new, path, data)


def _open_private(path):
    """An owner-only regular file opened without following links; checked again on the open handle."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    _private_directory(path.parent)
    _private_file(path)
    handle = os.fdopen(os.open(path, flags), "rb")
    try:
        info = os.fstat(handle.fileno())
        named = path.lstat()
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise WorkflowRefusal("The admitted private path no longer identifies the opened file")
        if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise WorkflowRefusal("Private engine records must stay current-owner single-link files 0600")
        _private_file(path)
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
    return _checked(pc_records.decode_strict, data, max_bytes=max_bytes, max_nodes=max_nodes)


def _container(value, kind):
    return _checked(pc_records.require_container, value, kind)


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
    _private_directory(path.parent)
    if path.exists():
        _private_file(path)
    temp = path.parent / (".write-" + uuid.uuid4().hex)
    try:
        _write_private_new(temp, data)
        _private_directory(path.parent)
        if path.exists():
            _private_file(path)
        os.replace(temp, path)
        _private_file(path)
    finally:
        if temp.exists():
            temp.unlink()


def _owner(state, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat"):
    if source not in {"current_owner_chat", "current_owner_terminal"} or (owner_id or state["owner_id"]) != state["owner_id"]:
        raise WorkflowRefusal("Only the actual current owner instruction can authorize this decision")
    _text(owner_quote, "actual owner quote")
    record_identifier(owner_message_id, "owner message identifier")
    return {"owner_id": state["owner_id"], "quote": owner_quote, "message_id": owner_message_id, "source": source, "recorded_utc": pc_records.utc_now(), "settings_revision": state["settings_revision"]}


def decision_card(*, meaning, benefits, drawbacks, cost, reversibility, recommendation, options):
    return {"meaning": meaning, "benefits": benefits, "drawbacks": drawbacks, "cost": cost, "reversibility": reversibility, "recommendation": recommendation, "options": options}


def initial_menu():
    lines = ["PatchCairn — Developed by Michael", "Choose the work you want:"]
    descriptions = ["Check selected software versions and relevant security concerns before choosing suitable updates.", "Understand where selected files use space and review safe cleanup choices.", "Investigate a specific problem, compare possible causes and explain a proposed repair.", "Protect selected files with a checked safety copy, or plan how to recover them."]
    lines += [str(number) + ". " + row["label"] + ": " + descriptions[number - 1] for number, row in enumerate(JOBS.values(), 1)]
    lines += ["I recommend guided control and a read-only assessment first: you can understand the findings before deciding about any changes. A plan is a clear list of proposed changes, their risks, recovery limits and checks.",
              "Guided control pauses at your chosen checkpoints so you can decide; it takes more of your attention. Automatic control has fewer pauses inside your agreed assessment scope. Computer changes still need an exact reviewed plan or bounded standing policy. A new material decision or OS consent still causes a hold.",
              "Checkpoints are chosen stops for your decision: scope, findings, plan, before each action, after each action and finish. Choose the stops that help you keep control.",
              "Control style (guided/automatic) is independent of timing (now/scheduled). Now is convenient when you are ready to review the work; scheduled timing proposes a later time, when fresh checks and any needed decisions still apply. No operating-system schedule is created here.",
              "Time, download size and assistant usage costs may be unknown until the selected work is assessed. I will explain the known costs and remaining uncertainty before actions; I will not invent a price or precise duration.",
              "Choose whole-device assessment, selected drives or folders, or one specific problem. Available agent tools determine actual coverage; the fixed helpers do not promise a universal scan.",
              "Metadata, selected local content reads and content shared with the assistant are separate choices. Browser history, caches, profiles and saved sessions stay excluded by default; a relevant sensitive observation needs your exact exception. Credentials and secret values are never requested. Starting does not approve computer changes or bypass OS permissions.",
              "Commands:\n" + "\n".join("- PatchCairn: " + command + " — " + explanation for command, explanation in (("start", "show this job menu; choose a job to open its assessment"), ("help", "explain jobs, choices, privacy and controls"), ("status", "explain progress, current work and what is waiting"), ("options", "compare the next choices, benefits, risks and recommendation"), ("cost", "explain known costs and what remains unknown"), ("settings", "review or change scope, control, timing and chosen stops"), ("pause", "prevent new actions while an active operation reaches a safe checkpoint"), ("resume", "continue only after fresh checks reconcile actual results"), ("stop", "end this session and preserve evidence and unfinished work"), ("resolve", "review one pending decision or uncertain result without guessing or retrying"))),
              "Next: choose job 1, 2, 3 or 4, then your control style and timing. For example, PatchCairn: start 1 selects security and updates for assessment. A bare PatchCairn: start shows this menu and creates no session."]
    return "\n\n".join(lines)


def parse_command(text):
    _text(text, "conversation command", 2000)
    raw = text.strip()
    if raw.startswith("/"):
        return {"ok": False, "code": "foreign_command", "message": "Use PatchCairn: help for this toolkit; slash commands belong to the host."}
    if raw.lower().startswith("patchcairn:"):
        raw = raw[len("patchcairn:"):].strip()
    natural = {"start assessment": "start security_updates", "start security updates": "start security_updates", "start security and updates": "start security_updates", "start storage cleanup": "start storage_cleanup", "start storage and cleanup": "start storage_cleanup", "start diagnosis repair": "start diagnosis_repair", "start diagnosis and repair": "start diagnosis_repair", "start backup recovery": "start backup_recovery", "start backup and recovery": "start backup_recovery", "show status": "status", "show options": "options", "show costs": "cost", "pause patchcairn": "pause", "stop patchcairn": "stop", "resume patchcairn": "resume", "help patchcairn": "help"}
    raw = natural.get(raw.lower(), raw)
    bits = raw.split()
    if not bits or bits[0].lower() not in COMMANDS:
        return {"ok": False, "code": "ambiguous_command", "message": "I could not identify one PatchCairn command. Choose PatchCairn: help or state one specific job or command."}
    command = bits[0].lower()
    args = bits[1:]
    if command == "start":
        if len(args) == 1 and args[0] in {"1", "2", "3", "4"}:
            args = [list(JOBS)[int(args[0]) - 1]]
        if len(args) > 1 or args and args[0] not in JOBS:
            return {"ok": False, "code": "ambiguous_job", "message": "Choose job 1 (security and updates), 2 (storage and cleanup), 3 (diagnosis and repair) or 4 (backup and recovery)."}
    elif command == "settings":
        if any("=" not in arg for arg in args):
            return {"ok": False, "code": "invalid_settings", "message": "Use settings control=guided or control=automatic, timing=now or timing=scheduled, or checkpoints=scope,plan,before_action."}
        keys = [arg.split("=", 1)[0] for arg in args]
        if len(keys) != len(set(keys)) or set(keys) - {"control", "timing", "checkpoints"}:
            return {"ok": False, "code": "invalid_settings", "message": "Settings contain an unknown or repeated choice."}
    elif command == "resolve":
        if len(args) > 1 or args and not ID.fullmatch(args[0]):
            return {"ok": False, "code": "invalid_resolution", "message": "Resolve accepts one pending item identifier; it never executes free-form instructions."}
    elif args:
        return {"ok": False, "code": "unexpected_arguments", "message": "This command does not accept extra instructions. Use PatchCairn: options to review the next choice."}
    return {"ok": True, "command": command, "arguments": args}


class WorkflowEngine:
    def __init__(self, root=None, *, work_relative="work/sessions", backend=BACKEND, verify_artifact=None):
        """``verify_artifact(binding) -> None`` re-reads recovery and artifact bytes from disk and raises
        pc_records.Refusal when they changed or are missing. Only WorkflowService builds it (from storage); an
        engine without it holds every action that depends on recovery or artifact bytes."""
        if sys.version_info < (3, 12):
            raise WorkflowRefusal("Python 3.12 or newer is required")
        if backend != BACKEND:
            raise WorkflowRefusal("Foreign backend is not supported")
        if verify_artifact is not None and not callable(verify_artifact):
            raise WorkflowRefusal("The artifact verifier must be callable")
        self.verify_artifact = verify_artifact
        self.root = no_links(Path(root) if root else Path(__file__).absolute().parent.parent)
        rel = PurePosixPath(work_relative)
        if rel.is_absolute() or "\\" in work_relative or not rel.parts or rel.parts[0] != "work" or any(p in {".", ".."} or ":" in p for p in rel.parts) or len(rel.parts) < 2:
            raise WorkflowRefusal("Session storage must be a named child of repository work/")
        self.work = no_links(self.root.joinpath(*rel.parts))
        _private_directory(self.work, create=True, parents=True, exist_ok=True)
        marker = self.work / "engine.json"
        if not marker.exists():
            if any(self.work.iterdir()):
                raise WorkflowRefusal("Engine creation marker is missing from nonempty storage; do not recreate or migrate it")
            try:
                _write_private_new(marker, encoded({"schema_version": SCHEMA_VERSION, "backend": BACKEND, "engine_id": uuid.uuid4().hex}))
            except WorkflowRefusal:
                if not marker.exists():
                    raise
        self.marker = older_folder(rel.as_posix(), lambda: _container(decode_record(self._read_owned(marker)), "engine_marker"))
        exact_fields(self.marker, {"schema_version", "backend", "engine_id"}, {"schema_version", "backend", "engine_id"})
        if self.marker["backend"] != BACKEND:
            raise WorkflowRefusal("Missing or foreign engine marker; migration is not permitted")
        record_identifier(self.marker["engine_id"])

    def _private_path(self, path):
        path = no_links(path)
        try:
            relative = path.relative_to(self.work)
        except ValueError as error:
            raise WorkflowRefusal("Private engine records must stay inside the exact engine namespace") from error
        current = _private_directory(self.work)
        _private_file(self.work / "engine.json")
        for part in relative.parts[:-1]:
            current = _private_directory(current / part)
        return path

    def _read_owned(self, path, max_bytes=16_000_000):
        return read_record_bytes(self._private_path(path), max_bytes, private=True)

    def _directory(self, session_id):
        record_identifier(session_id, "session identifier")
        _private_directory(self.work)
        _private_file(self.work / "engine.json")
        path = no_links(self.work / session_id)
        if not path.is_dir():
            raise WorkflowRefusal("Session is not registered; it will not be recreated")
        _private_directory(path)
        _private_directory(path / "evidence")
        return path

    @contextmanager
    def _lock(self, session_id):
        path = self._directory(session_id) / ".lock"
        try:
            _private_directory(path, create=True)
        except WorkflowRefusal as error:
            if error.code != "private-directory-exists":
                raise
            raise WorkflowRefusal("Session is locked by another writer or interrupted write; inspect it before recovery") from error
        try:
            yield
        finally:
            path.rmdir()

    @contextmanager
    def _registry_lock(self):
        _private_directory(self.work)
        _private_file(self.work / "engine.json")
        path = self.work / ".registry-lock"
        try:
            _private_directory(path, create=True)
        except WorkflowRefusal as error:
            if error.code != "private-directory-exists":
                raise
            raise WorkflowRefusal("Another registry action is being coordinated; no concurrent mutation ticket is issued") from error
        try:
            yield
        finally:
            path.rmdir()

    def _outstanding_effects(self):
        _private_directory(self.work)
        _private_file(self.work / "engine.json")
        outstanding = []
        for directory in self.work.iterdir():
            if directory.is_dir() and directory.name.startswith("session-"):
                state = self.read_session(directory.name)
                for operation in state["operations"].values():
                    restart_unresolved = operation.get("restart_pending") and operation.get("restart_verification", {}).get("boot_observed") is not True
                    if operation["mutating"] and (restart_unresolved or operation["outcome"] in {None, "unknown"} or operation["outcome"] in {"partial", "failed"} and not operation["resolution"]):
                        outstanding.append({"session_id": state["session_id"], "operation_id": operation["operation_id"], "outcome": operation["outcome"]})
        return outstanding

    def _validate(self, state):
        _container(state, "session_state")
        exact_fields(state, STATE_KEYS, STATE_KEYS)
        if state["backend"] != BACKEND or state["engine_id"] != self.marker["engine_id"]:
            raise WorkflowRefusal("Foreign session version, backend or creation identity")
        record_identifier(state["session_id"])
        record_identifier(state["owner_id"])
        if state["mode"] not in {"fixture", "real"} or state["platform"] not in {"unknown", "windows", "linux", "macos"}:
            raise WorkflowRefusal("Invalid immutable session mode/platform")
        if state["job"] not in JOBS or state["stage"] not in JOBS[state["job"]]["stages"] or state["status"] not in {"active", "paused", "pause_pending", "held", "stopped", "completed", "awaiting_user"}:
            raise WorkflowRefusal("Invalid job, stage or status")
        for key in ("revision", "settings_revision"):
            if type(state[key]) is not int or state[key] < 0:
                raise WorkflowRefusal("Invalid revision")
        utc_time(state["created_utc"])
        utc_time(state["updated_utc"])
        settings = state["settings"]
        exact_fields(settings, {"scope", "control", "timing", "checkpoints"}, {"scope", "control", "timing", "checkpoints"})
        _scope(settings["scope"])
        if settings["control"] not in {"guided", "automatic"} or settings["timing"] not in {"now", "scheduled"} or not isinstance(settings["checkpoints"], list) or set(settings["checkpoints"]) - CHECKPOINTS or len(settings["checkpoints"]) != len(set(settings["checkpoints"])):
            raise WorkflowRefusal("Invalid session settings")
        if not isinstance(state["evidence"], dict) or not isinstance(state["operations"], dict) or not isinstance(state["reviews"], list) or not isinstance(state["pending"], dict) or not isinstance(state["schedule_triggers"], list):
            raise WorkflowRefusal("Invalid state collections")
        for evidence_id, row in state["evidence"].items():
            record_identifier(evidence_id)
            exact_fields(row, {"evidence_id", "path", "sha256", "size", "kind", "scope", "settings_revision", "observed_utc", "registered_utc", "facts"}, {"evidence_id", "path", "sha256", "size", "kind", "scope", "settings_revision", "observed_utc", "registered_utc", "facts"})
            if row["evidence_id"] != evidence_id or row["path"] != "evidence/" + evidence_id + ".bin" or row["kind"] not in EVIDENCE_KINDS or not SHA.fullmatch(row["sha256"]) or type(row["size"]) is not int or row["size"] < 1:
                raise WorkflowRefusal("Invalid owned evidence record")
            _scope(row["scope"])
            _json_data(row["facts"])
            utc_time(row["observed_utc"])
            utc_time(row["registered_utc"])
        active = []
        for operation_id, op in state["operations"].items():
            record_identifier(operation_id)
            fields = {"operation_id", "action_id", "plan_sha256", "settings_revision", "started_utc", "finished_utc", "outcome", "evidence_ids", "summary", "authorization", "pause_requested", "resolution", "mutating", "adapter_id"}
            exact_fields(op, fields | {"restart_pending", "restart_decision", "restart_verification"}, fields)
            for name in ("restart_pending", "restart_decision", "restart_verification"):
                if name in op:
                    if not isinstance(op[name], dict):
                        raise WorkflowRefusal("Restart lifecycle metadata must be a typed record")
                    _json_data(op[name])
            if op["operation_id"] != operation_id or op["outcome"] not in OUTCOMES | {None} or not SHA.fullmatch(op["plan_sha256"]):
                raise WorkflowRefusal("Invalid operation record")
            if type(op["mutating"]) is not bool or op["adapter_id"] not in pc_records.ADAPTERS:
                raise WorkflowRefusal("Operation must retain its exact adapter and mutation classification")
            record_identifier(op["action_id"])
            _ids(op["evidence_ids"])
            utc_time(op["started_utc"])
            if op["finished_utc"]:
                utc_time(op["finished_utc"])
            if op["outcome"] is None:
                active.append(operation_id)
        if len(active) > 1 or state["status"] == "pause_pending" and not active:
            raise WorkflowRefusal("Invalid active-operation invariant")
        if state["plan"]:
            plan = state["plan"]
            exact_fields(plan, {"document", "sha256", "settings_revision", "registered_utc"}, {"document", "sha256", "settings_revision", "registered_utc"})
            if digest(plan["document"]) != plan["sha256"] or plan["settings_revision"] != state["settings_revision"]:
                raise WorkflowRefusal("Plan hash or settings binding changed")
            self._validate_plan_document(state, plan["document"])
        if state["approval"] and (not state["plan"] or state["approval"]["plan_sha256"] != state["plan"]["sha256"] or state["approval"]["settings_revision"] != state["settings_revision"]):
            raise WorkflowRefusal("Approval is not bound to the current exact plan")
        return state

    def _load(self, session_id):
        directory = self._directory(session_id)
        try:
            marker = decode_record(self._read_owned(directory / "creation.json"))
            bundle = decode_record(self._read_owned(directory / "session.json", JOURNAL_MAX_BYTES), max_bytes=JOURNAL_MAX_BYTES, max_nodes=JOURNAL_MAX_NODES)
        except FileNotFoundError as error:
            raise WorkflowRefusal("Registered session state is missing; no silent reconstruction") from error
        exact_fields(bundle, {"state", "events"}, {"state", "events"})
        state = self._validate(bundle["state"])
        _container(marker, "session_creation")
        exact_fields(marker, {"schema_version", *CREATION_KEYS}, {"schema_version", *CREATION_KEYS})
        if any(marker[key] != state[key] for key in CREATION_KEYS) or state["session_id"] != session_id:
            raise WorkflowRefusal("Immutable session creation binding changed")
        if not isinstance(bundle["events"], list) or len(bundle["events"]) != state["revision"] + 1:
            raise WorkflowRefusal("Session event sequence is incomplete")
        previous = None
        for revision, event in enumerate(bundle["events"]):
            exact_fields(event, {"revision", "at", "type", "details", "state_sha256", "previous", "sha256"}, {"revision", "at", "type", "details", "state_sha256", "previous", "sha256"})
            bare = {key: value for key, value in event.items() if key != "sha256"}
            if event["revision"] != revision or event["previous"] != previous or event["sha256"] != digest(bare):
                raise WorkflowRefusal("Session event chain changed")
            utc_time(event["at"])
            previous = event["sha256"]
        if bundle["events"][-1]["state_sha256"] != digest(state):
            raise WorkflowRefusal("State does not match its committed event")
        for row in state["evidence"].values():
            if _private_digest(self._private_path(directory / row["path"]), EVIDENCE_MAX_BYTES) != (row["sha256"], row["size"]):
                raise WorkflowRefusal("Owned evidence has changed")
        return bundle

    def _commit(self, directory, state, events, event_type, details):
        self._validate(state)
        event = {"revision": state["revision"], "at": state["updated_utc"], "type": event_type, "details": details, "state_sha256": digest(state), "previous": events[-1]["sha256"] if events else None}
        event["sha256"] = digest(event)
        # State and its entire chained event journal share one atomic transaction.
        data = encoded({"state": state, "events": events + [event]})
        if len(data) > JOURNAL_MAX_BYTES:
            raise WorkflowRefusal("Session journal reached its bounded size; preserve it and start a separately scoped session")
        atomic_replace(self._private_path(directory / "session.json"), data)

    def _change(self, session_id, event_type, mutate, expected_revision=None):
        with self._lock(session_id):
            bundle = self._load(session_id)
            current = bundle["state"]
            if expected_revision is not None and (type(expected_revision) is not int or expected_revision != current["revision"]):
                raise WorkflowRefusal("Session changed; read the current revision before writing")
            candidate = copy.deepcopy(current)
            data, message = mutate(candidate)
            candidate["revision"] += 1
            candidate["updated_utc"] = pc_records.utc_now()
            # The event keeps the digest of each changed value; the state itself is bound by state_sha256.
            changes = {key: digest(value) for key, value in candidate.items() if key not in {"revision", "updated_utc"} and value != current[key]}
            self._commit(self._directory(session_id), candidate, bundle["events"], event_type, {"settings_revision": candidate["settings_revision"], "changes": changes})
        return self._response(candidate, event_type, message, data)

    @staticmethod
    def _response(state, code, message, data=None):
        if state and code not in {"created", "help", "status", "options"}:
            message = JOBS[state["job"]]["label"] + " · " + STAGE_LABELS[state["stage"]] + ". " + message
        return {"schema_version": SCHEMA_VERSION, "ok": True, "code": code, "message": message, "session_id": state["session_id"] if state else None, "revision": state["revision"] if state else None, "data": copy.deepcopy(data or {})}

    def create_session(self, *, job="security_updates", control="guided", timing="now", mode="fixture", platform="unknown", scope=None, checkpoints=None, owner_id="owner"):
        if job not in JOBS:
            raise WorkflowRefusal("Choose one supported job")
        record_identifier(owner_id)
        selected = _scope(scope or {"roots": [], "purpose": "Assessment; scope still needs the owner's decision"})
        now = pc_records.utc_now()
        session_id = "session-" + uuid.uuid4().hex
        state = {"schema_version": SCHEMA_VERSION, "session_id": session_id, "engine_id": self.marker["engine_id"], "backend": BACKEND, "mode": mode, "platform": platform, "created_utc": now, "updated_utc": now, "creation_scope_sha256": digest(selected), "owner_id": owner_id, "revision": 0, "settings_revision": 0, "job": job, "stage": "scope", "status": "active" if timing == "now" else "awaiting_user", "settings": {"scope": selected, "control": control, "timing": timing, "checkpoints": list(checkpoints if checkpoints is not None else ["scope", "findings", "plan", "before_action", "finish"])}, "scope_authorization": None, "evidence": {}, "plan": None, "reviews": [], "approval": None, "irreversible_ack": None, "standing_policy": None, "operations": {}, "pending": {}, "schedule": None, "schedule_triggers": [], "last_reconciled_utc": None, "stop_reason": None}
        self._validate(state)
        _private_directory(self.work)
        _private_file(self.work / "engine.json")
        directory = self.work / session_id
        _private_directory(directory, create=True)
        _private_directory(directory / "evidence", create=True)
        marker = {"schema_version": SCHEMA_VERSION, **{key: state[key] for key in CREATION_KEYS}}
        _write_private_new(directory / "creation.json", encoded(marker))
        self._commit(directory, state, [], "created", {"job": job})
        return self._response(state, "created", initial_menu() + "\n\nYour " + JOBS[job]["label"].lower() + " session is ready. Confirm the exact scope before evidence collection.", {"state": state})

    def read_session(self, session_id):
        return copy.deepcopy(self._load(session_id)["state"])

    @staticmethod
    def _writable(state):
        if state["status"] in {"stopped", "completed"}:
            raise WorkflowRefusal("This session is closed; evidence is preserved")

    @staticmethod
    def _invalidate(state):
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

    def setup(self, session_id, *, scope=None, control=None, timing=None, checkpoints=None, expected_revision=None):
        def mutate(state):
            self._writable(state)
            new = copy.deepcopy(state["settings"])
            for key, value in (("scope", scope), ("control", control), ("timing", timing), ("checkpoints", checkpoints)):
                if value is not None:
                    new[key] = _scope(value) if key == "scope" else copy.deepcopy(value)
            if new != state["settings"]:
                if any(op["outcome"] in {None, "unknown"} or op["outcome"] in {"failed", "partial"} and not op["resolution"] for op in state["operations"].values()):
                    raise WorkflowRefusal("An operation still has active, unknown or unreconciled effects; establish its actual outcome before changing scope/settings")
                state["settings"] = new
                state["settings_revision"] += 1
                self._invalidate(state)
                state["stage"] = "scope"
                if state["status"] not in {"paused", "pause_pending", "held"}:
                    state["status"] = "awaiting_user" if new["timing"] == "scheduled" else "active"
            return {"settings": new}, "Settings are recorded. Changed scope or control choices require a fresh scope decision and a new reviewed plan; earlier approvals cannot expand."
        return self._change(session_id, "settings", mutate, expected_revision)

    def authorize_scope(self, session_id, *, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat", expected_revision=None):
        def mutate(state):
            self._writable(state)
            if not _scope_selected(state["settings"]["scope"]):
                raise WorkflowRefusal("Select the exact scope before authorizing collection")
            state["scope_authorization"] = _owner(state, owner_quote, owner_message_id, owner_id, source)
            state["scope_authorization"]["scope_sha256"] = digest(state["settings"]["scope"])
            if state["status"] == "awaiting_user" and state["settings"]["timing"] == "now":
                state["status"] = "active"
            return {}, "Your exact scope decision is recorded. It permits only the agreed evidence collection; computer changes need a separate concrete plan."
        return self._change(session_id, "scope_authorized", mutate, expected_revision)

    def register_evidence(self, session_id, *, evidence_id, content, kind, scope, facts=None, observed_utc=None, expected_revision=None):
        record_identifier(evidence_id, "evidence identifier")
        if not isinstance(content, bytes) or not 0 < len(content) <= EVIDENCE_MAX_BYTES or kind not in EVIDENCE_KINDS:
            raise WorkflowRefusal("Evidence must be bounded bytes with a supported kind")
        _scope(scope)
        facts = copy.deepcopy(facts or {})
        if not isinstance(facts, dict):
            raise WorkflowRefusal("Evidence facts must be a mapping")
        _json_data(facts)
        if len(encoded(facts)) > FACTS_MAX_BYTES:
            raise WorkflowRefusal("Evidence facts must stay small; put large data in the evidence content", code="facts-too-large")
        observed = observed_utc or pc_records.utc_now()
        _fresh(observed, seconds=86400)
        def mutate(state):
            if state["status"] == "stopped":
                operation = state["operations"].get(facts.get("operation_id"))
                active_receipt = operation and operation["outcome"] is None and kind == "outcome"
                late_reconciliation = operation and operation["outcome"] in {"unknown", "partial", "failed"} and kind in {"outcome", "reconciliation"} and not operation["resolution"]
                if not active_receipt and not late_reconciliation:
                    raise WorkflowRefusal("A stopped session accepts only the exact eventual receipt or bounded reconciliation of its existing unresolved operation")
                if facts.get("action_id") != operation["action_id"] or facts.get("plan_sha256") != operation["plan_sha256"] or facts.get("outcome") not in OUTCOMES:
                    raise WorkflowRefusal("Post-stop evidence must bind the exact active operation and actual outcome")
                if operation["outcome"] in {"partial", "failed"} and facts["outcome"] != operation["outcome"]:
                    raise WorkflowRefusal("Historical unsuccessful outcomes cannot be relabelled by late evidence")
                _fresh(observed, after=operation["finished_utc"] or operation["started_utc"], seconds=900)
            else:
                self._writable(state)
            if evidence_id in state["evidence"]:
                raise WorkflowRefusal("Evidence identifiers are immutable and cannot be overwritten")
            if scope != state["settings"]["scope"]:
                raise WorkflowRefusal("Evidence must match the exact current selected scope")
            if kind == "fixture" and state["mode"] != "fixture":
                raise WorkflowRefusal("Fictional evidence cannot be promoted into a real session")
            row = {"evidence_id": evidence_id, "path": "evidence/" + evidence_id + ".bin", "sha256": digest(content), "size": len(content), "kind": kind, "scope": copy.deepcopy(scope), "settings_revision": state["settings_revision"], "observed_utc": observed, "registered_utc": pc_records.utc_now(), "facts": facts}
            target = self._directory(session_id) / row["path"]
            if target.exists():
                raise WorkflowRefusal("An unregistered file occupies the evidence name; preserve it for inspection")
            _write_private_new(self._private_path(target), content)
            state["evidence"][evidence_id] = row
            return row, "Selected evidence is saved with its exact content hash, scope and observation time."
        return self._change(session_id, "evidence_registered", mutate, expected_revision)

    def evidence_rows(self, state, evidence_ids, *, kinds=None, after=None, seconds=86400, allow_empty=False):
        _ids(evidence_ids, "evidence identifiers", allow_empty=allow_empty)
        rows = []
        for evidence_id in evidence_ids:
            if evidence_id not in state["evidence"]:
                raise WorkflowRefusal("Referenced evidence is not owned by this session")
            row = state["evidence"][evidence_id]
            if row["settings_revision"] != state["settings_revision"] or row["scope"] != state["settings"]["scope"]:
                raise WorkflowRefusal("Evidence belongs to an earlier scope/settings revision")
            if kinds and row["kind"] not in kinds:
                raise WorkflowRefusal("Evidence kind does not support this transition")
            _fresh(row["observed_utc"], after=after, seconds=seconds)
            rows.append(row)
        return rows

    def _validate_plan_document(self, state, plan):
        exact_fields(plan, {"plan_id", "summary", "evidence_ids", "actions"}, {"plan_id", "summary", "evidence_ids", "actions"})
        record_identifier(plan["plan_id"])
        _text(plan["summary"], "plan explanation")
        _ids(plan["evidence_ids"], allow_empty=False)
        if not isinstance(plan["actions"], list) or not 0 < len(plan["actions"]) <= 100:
            raise WorkflowRefusal("A plan needs a bounded concrete action list")
        seen = set()
        for action in plan["actions"]:
            fields = {"action_id", "kind", "target", "benefit", "risk", "reversibility", "verification", "mutating", "requires_os_consent", "requires_recovery", "recovery_evidence_ids", "estimate_evidence_id", "adapter_id", "adapter_payload_evidence_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_evidence_id", "target_inventory_sha256"}
            required = fields - {"estimate_evidence_id"}
            exact_fields(action, fields, required)
            record_identifier(action["action_id"])
            if action["action_id"] in seen or action["kind"] not in KINDS:
                raise WorkflowRefusal("Action identifiers must be unique and kinds supported")
            seen.add(action["action_id"])
            for field in ("target", "benefit", "risk", "reversibility", "verification"):
                _text(action[field], "action " + field, 2000)
            if any(type(action[key]) is not bool for key in ("mutating", "requires_os_consent", "requires_recovery")):
                raise WorkflowRefusal("Action safety flags must be explicit booleans")
            if action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL and action["requires_os_consent"] is not True:
                raise WorkflowRefusal("Every fixed local external installer requires actual owner-handled protected-system consent")
            if action["kind"] != "assessment" and not action["mutating"]:
                raise WorkflowRefusal("Change kinds cannot be disguised as read-only actions")
            if not isinstance(action["adapter_id"], str):
                raise WorkflowRefusal("Adapter identifier must name a fixed supported recipe")
            facts = _facts(action)
            if action["kind"] not in facts["kinds"] or action["adapter_id"] == pc_records.ADAPTER_FIXTURE_ASSESSMENT and state["mode"] != "fixture":
                raise WorkflowRefusal("This action has no fixed supported adapter for this kind and mode")
            if facts["backup_receipt"] == "required" and not action["requires_recovery"]:
                raise WorkflowRefusal("This adapter consumes a verified backup receipt; bind its recovery evidence")
            for field in ("adapter_payload_evidence_id", "target_inventory_evidence_id"):
                record_identifier(action[field])
            for field in ("adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256"):
                if not isinstance(action[field], str) or not SHA.fullmatch(action[field]):
                    raise WorkflowRefusal("Exact adapter payload, lower-level plan and target inventory hashes are required")
            if action["kind"] in {"backup_restore", "permanent_purge", "repair", "firmware", "os_transition"} and not action["requires_recovery"]:
                raise WorkflowRefusal("This action needs verified recovery evidence or an explicit supported recovery design")
            _ids(action["recovery_evidence_ids"])
            if action["requires_recovery"] and not action["recovery_evidence_ids"]:
                raise WorkflowRefusal("Required recovery has not been provided")
            if "estimate_evidence_id" in action:
                record_identifier(action["estimate_evidence_id"])

    def action_binding(self, state, action):
        payload_row = self.evidence_rows(state, [action["adapter_payload_evidence_id"]], kinds={"adapter_payload"})[0]
        inventory_row = self.evidence_rows(state, [action["target_inventory_evidence_id"]], kinds={"inventory"})[0]
        if payload_row["sha256"] != action["adapter_payload_sha256"] or inventory_row["sha256"] != action["target_inventory_sha256"]:
            raise WorkflowRefusal("Exact reviewed adapter payload or target inventory has changed")
        directory = self._directory(state["session_id"])
        payload, inventory = (decode_record(self._read_owned(directory / row["path"], EVIDENCE_MAX_BYTES), max_bytes=EVIDENCE_MAX_BYTES,
                                            max_nodes=EVIDENCE_MAX_NODES) for row in (payload_row, inventory_row))
        if action["adapter_id"] == pc_records.ADAPTER_FIXTURE_ASSESSMENT:
            typed_record(payload, FIXTURE_ADAPTER)
            if payload["operation"] != action["adapter_id"] or digest(payload["fixture_plan"]) != action["adapter_plan_sha256"] or payload["fixture_plan_sha256"] != action["adapter_plan_sha256"] or payload["inventory_sha256"] != digest(inventory):
                raise WorkflowRefusal("Fictional adapter payload does not bind its exact plan and inventory")
        elif action["adapter_id"] == pc_records.ADAPTER_DIAGNOSTIC_COLLECT:
            typed_record(payload, DIAGNOSTIC_ADAPTER)
            if payload["operation"] != action["adapter_id"] or payload["request_sha256"] != action["adapter_plan_sha256"] or digest(payload["request"]) != action["adapter_plan_sha256"] or payload["inventory_sha256"] != digest(inventory) or payload["request"] != inventory:
                raise WorkflowRefusal("Diagnostic request does not match the exact reviewed selected recipe and inventory")
            _json_data(payload["request"])
            try:
                request = diagnostic_core.validate_request(payload["request"])
            except diagnostic_core.DiagnosticRefusal as error:
                raise WorkflowRefusal("Diagnostic request is not a supported bounded recipe") from error
            if request["mode"] != state["mode"] or request["platform"] != state["platform"]:
                raise WorkflowRefusal("Diagnostic request belongs to a different creation mode/platform")
        elif action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
            typed_record(payload, EXTERNAL_ADAPTER)
            if payload["operation"] != action["adapter_id"] or payload["external_plan_sha256"] != action["adapter_plan_sha256"] or digest(payload["external_plan"]) != action["adapter_plan_sha256"] or payload["inventory_sha256"] != digest(inventory):
                raise WorkflowRefusal("External handoff does not match its exact reviewed plan and inventory")
            self.validate_external_plan(state, payload["external_plan"], inventory)
            if payload["external_plan"]["kind"] != action["kind"]:
                raise WorkflowRefusal("External handoff kind differs from the exact engine action")
            if action["requires_os_consent"] is not True:
                raise WorkflowRefusal("A local installer handoff requires actual owner-handled protected-system consent")
        elif action["adapter_id"] in STORAGE_ADAPTERS:
            _checked(storage_contract.validate_payload, payload, adapter_id=action["adapter_id"], mode=state["mode"], plan_sha256=action["adapter_plan_sha256"])
            _json_data(payload["storage_plan"])
            output_value = Path(_text(payload["output_root"], "owned storage output root", 2000))
            if not output_value.is_absolute():
                raise WorkflowRefusal("Storage output root must be an exact absolute owned work path")
            output = no_links(output_value)
            try:
                output.relative_to(self.root / "work")
            except ValueError as error:
                raise WorkflowRefusal("Adapter outputs must stay inside this repository's owned work tree") from error
            probe_value = payload.get("restore_probe_destination")
            if probe_value is not None:
                if action["adapter_id"] != pc_records.ADAPTER_STORAGE_BACKUP_CREATE or not isinstance(probe_value, str) or not Path(probe_value).is_absolute():
                    raise WorkflowRefusal("Only an explicitly reviewed backup action can include an exact owned restore-probe destination")
                probe = no_links(Path(probe_value))
                try:
                    probe.relative_to(output)
                except ValueError as error:
                    raise WorkflowRefusal("Restore probe must stay under the exact owned backup output root") from error
                if probe.exists():
                    raise WorkflowRefusal("The reviewed restore-probe destination is no longer absent")
            source_inventory = payload["storage_plan"].get("inventory", payload["storage_plan"].get("records", payload["storage_plan"].get("receipt")))
            if source_inventory is None or digest(source_inventory) != digest(inventory):
                raise WorkflowRefusal("Adapter target inventory is not the exact owned inventory/receipt reviewed in the lower-level plan")
        else:
            # A registered adapter whose family code is not written yet: the facts allow it, nothing binds it.
            raise WorkflowRefusal("This adapter's payload binding is not written yet; the action is held", code="adapter-held")
        return payload

    def validate_external_plan(self, state, plan, inventory):
        typed_record(plan, EXTERNAL_PLAN)
        if plan["kind"] not in {"update", "repair"} or plan["platform"] != state["platform"] or plan["mode"] != state["mode"] or plan["scope"] != state["settings"]["scope"]:
            raise WorkflowRefusal("External plan must bind this exact session's kind, platform, mode and scope")
        if plan["kind"] == "repair":
            raise WorkflowRefusal("This component repair is held: no supported component-specific rollback verifier or separately authorized no-recovery-risk policy exists. An ordinary file ZIP and restore probe cannot establish operating-system or application rollback")
        targets = plan["targets"]
        if not isinstance(targets, list) or not 1 <= len(targets) <= 20 or any(not isinstance(t, str) for t in targets) or len(set(targets)) != len(targets):
            raise WorkflowRefusal("External plan needs explicit unique bounded targets")
        versions = plan["target_versions"]
        if not isinstance(versions, dict) or set(versions) != (set(targets) if plan["kind"] == "update" else set()) or any(not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~:^-]{0,127}", version) for version in versions.values()):
            raise WorkflowRefusal("Update handoffs require an exact reviewed version for every target; repair version map must be empty")
        identities = plan["target_identities"]
        if not isinstance(identities, dict) or set(identities) != (set(targets) if plan["kind"] == "update" else set()):
            raise WorkflowRefusal("Every update target requires exact channel, architecture, publisher, content and source identities")
        for identity in identities.values():
            fields = {"channel", "architecture", "publisher", "content_sha256", "source_id", "installation_scope"}
            exact_fields(identity, fields, fields)
            if any(not isinstance(identity[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", identity[key]) or identity[key].lower() in {"unknown", "latest", "any"} for key in ("channel", "source_id")) or identity["architecture"] not in {"x86", "x64", "arm64", "universal", "all"} or not isinstance(identity["content_sha256"], str) or not SHA.fullmatch(identity["content_sha256"]):
                raise WorkflowRefusal("Update artifact/channel/architecture/source identities must be exact and known")
            publisher = _text(identity["publisher"], "verified publisher", 200)
            if publisher.lower() in {"unknown", "latest", "any"} or any(ord(char) < 32 for char in publisher):
                raise WorkflowRefusal("An exact reviewed nonsecret publisher identity is required")
        catalog = plan["catalog_id"]
        mapping = {"windows.msiexec.install": ("windows", "update", "msiexec.exe"), "macos.installer.pkg": ("macos", "update", "/usr/sbin/installer"), "linux.dpkg.install_local": ("linux", "update", "/usr/bin/dpkg")}
        if catalog not in mapping or (plan["platform"], plan["kind"], plan["official_tool"]) != mapping[catalog]:
            raise WorkflowRefusal("Manager or unknown handoffs that cannot consume the exact reviewed artifact stay held; only the fixed local MSI, PKG and DEB catalogs are supported")
        target_pattern = r"(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}|\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})"
        if len(targets) != 1 or not re.fullmatch(target_pattern, targets[0]) or not isinstance(plan["argv"], list) or not 2 <= len(plan["argv"]) <= 5 or any(not isinstance(arg, str) or len(arg) > 2000 or any(ord(char) < 32 for char in arg) for arg in plan["argv"]):
            raise WorkflowRefusal("A local installer handoff needs one exact target and bounded fixed literal arguments")
        artifact = Path(plan["argv"][1])
        if not artifact.is_absolute() or ".." in artifact.parts:
            raise WorkflowRefusal("The local installer must consume an exact absolute owned artifact path")
        try:
            artifact.relative_to(self.root / "work")
        except ValueError as error:
            raise WorkflowRefusal("The approved local installer artifact must be under owned repository work") from error
        suffix = {"windows.msiexec.install": ".msi", "macos.installer.pkg": ".pkg", "linux.dpkg.install_local": ".deb"}[catalog]
        if artifact.suffix.casefold() != suffix:
            raise WorkflowRefusal("This fixed local installer catalog cannot consume that artifact format")
        argv = ["/i", str(artifact), "/passive", "/norestart"] if catalog == "windows.msiexec.install" else ["-pkg", str(artifact), "-target", "/"] if catalog == "macos.installer.pkg" else ["--install", str(artifact)]
        identity = identities[targets[0]]
        allowed_scopes = {"user", "machine"} if plan["platform"] == "windows" else {"system"}
        allowed_architectures = {"windows": {"x86", "x64", "arm64"}, "macos": {"x64", "arm64", "universal"}, "linux": {"x86", "x64", "arm64", "all"}}[plan["platform"]]
        if identity["installation_scope"] not in allowed_scopes or identity["architecture"] not in allowed_architectures or identity["channel"] != "stable":
            raise WorkflowRefusal("This fixed local installer route requires the reviewed stable package and supported installation scope")
        if plan["argv"] != argv:
            raise WorkflowRefusal("External argv differs from the fixed catalog grammar; no free-form command handoff")
        sources = plan["sources"]
        if not isinstance(sources, list) or not 1 <= len(sources) <= 20:
            raise WorkflowRefusal("Exact reviewed official HTTPS sources are required")
        for source in sources:
            _text(source, "official source URL", 2000)
            parsed = urlsplit(source)
            if parsed.scheme != "https" or not parsed.hostname or "." not in parsed.hostname or parsed.username or parsed.password or parsed.port not in {None, 443}:
                raise WorkflowRefusal("External source must be an explicit ordinary HTTPS URL without credentials")
        self.evidence_rows(state, plan["provenance_evidence_ids"], kinds={"research", "review", "inventory"})
        self.evidence_rows(state, plan["compatibility_evidence_ids"], kinds={"research", "review", "inventory"})
        recovery = typed_record(plan["recovery_plan"], EXTERNAL_RECOVERY)
        if recovery["strategy"] not in {"verified_backup", "publisher_rollback", "no_verified_rollback"} or digest(recovery) != plan["recovery_plan_sha256"]:
            raise WorkflowRefusal("External recovery plan and exact limits must be reviewed and hash-bound")
        _text(recovery["limits"], "recovery limits", 2000)
        self.evidence_rows(state, recovery["evidence_ids"], allow_empty=recovery["strategy"] == "no_verified_rollback")
        if recovery["strategy"] == "verified_backup":
            self.verify_recovery(state, recovery["evidence_ids"])
        verification = typed_record(plan["verification_plan"], EXTERNAL_VERIFICATION)
        if digest(verification) != plan["verification_plan_sha256"] or not isinstance(verification["checks"], list) or not 1 <= len(verification["checks"]) <= 20:
            raise WorkflowRefusal("An exact behavior verification plan is required for the external handoff")
        _text(verification["original_success_condition"], "original success condition", 2000)
        seen = set()
        for check in verification["checks"]:
            exact_fields(check, {"check_id", "description", "expected_result"}, {"check_id", "description", "expected_result"})
            record_identifier(check["check_id"])
            if check["check_id"] in seen:
                raise WorkflowRefusal("Verification check IDs must be unique")
            seen.add(check["check_id"])
            _text(check["description"], "verification check", 2000)
            _text(check["expected_result"], "expected verification result", 2000)

    def _external_preflight(self, state, action, rows):
        payload = self.action_binding(state, action)
        external = payload["external_plan"]
        for row in rows:
            proof = typed_record(decode_record(self._read_owned(self._directory(state["session_id"]) / row["path"])), EXTERNAL_PREFLIGHT)
            if proof["action_id"] != action["action_id"] or proof["plan_sha256"] != state["plan"]["sha256"] or proof["external_plan_sha256"] != action["adapter_plan_sha256"] or proof["mode"] != state["mode"] or proof["platform"] != state["platform"] or not isinstance(proof["targets"], dict) or set(proof["targets"]) != set(external["targets"]):
                raise WorkflowRefusal("An external handoff requires an actual exact current artifact/provenance preflight before the mutation ticket")
            _fresh(proof["observed_utc"], after=state["plan"]["registered_utc"], seconds=900)
            for target, observed in proof["targets"].items():
                identity = external["target_identities"][target]
                expected = {**identity, "version": external["target_versions"][target]}
                additional = {"artifact_path", "artifact_record", "signature_evidence_id", "metadata_evidence_id"}
                exact_fields(observed, set(expected) | additional, set(expected) | additional)
                if any(observed[key] != value for key, value in expected.items()):
                    raise WorkflowRefusal("Actual selected artifact version, variant, publisher or source differs from the reviewed offer")
                if observed["artifact_path"] != external["argv"][1]:
                    raise WorkflowRefusal("The fixed installer arguments must consume the exact artifact whose actual identity and content were verified")
                artifact = Path(_text(observed["artifact_path"], "selected official artifact", 2000))
                if not artifact.is_absolute() or ".." in artifact.parts:
                    raise WorkflowRefusal("Select the exact owned work artifact before content verification")
                try:
                    relative = artifact.relative_to(self.root / "work").as_posix()
                except ValueError as error:
                    raise WorkflowRefusal("External preflight artifacts must remain in owned repository work") from error
                if pc_paths.protected(relative) or artifact.suffix.casefold() not in {".msi", ".pkg", ".deb"}:
                    raise WorkflowRefusal("Known private-store names and unsupported external artifact formats stay unopened")
                self._verify({"kind": "installer_artifact", "path": str(artifact), "record": observed["artifact_record"],
                              "sha256": identity["content_sha256"]})
                signature_row = self.evidence_rows(state, [observed["signature_evidence_id"]], kinds={"research", "precondition"}, after=state["plan"]["registered_utc"], seconds=900)[0]
                signature = typed_record(decode_record(self._read_owned(self._directory(state["session_id"]) / signature_row["path"])), PUBLISHER_SIGNATURE)
                method = {"windows": "windows.authenticode", "macos": "apple.pkgutil_check_signature", "linux": "distribution.signed_metadata"}[state["platform"]]
                if signature["mode"] != state["mode"] or signature["platform"] != state["platform"] or signature["artifact_sha256"] != identity["content_sha256"] or signature["publisher"] != identity["publisher"] or signature["source_id"] != identity["source_id"] or signature["method"] != method or signature["status"] != "verified":
                    raise WorkflowRefusal("A current actual publisher/signature verification receipt for the exact artifact and source is required")
                _fresh(signature["observed_utc"], after=state["plan"]["registered_utc"], seconds=900)
                metadata_row = self.evidence_rows(state, [observed["metadata_evidence_id"]], kinds={"research", "precondition"}, after=state["plan"]["registered_utc"], seconds=900)[0]
                metadata = typed_record(decode_record(self._read_owned(self._directory(state["session_id"]) / metadata_row["path"])), INSTALLER_METADATA)
                if metadata["mode"] != state["mode"] or metadata["platform"] != state["platform"] or metadata["artifact_sha256"] != identity["content_sha256"] or metadata["target_id"] != target or any(metadata[key] != value for key, value in expected.items() if key != "content_sha256"):
                    raise WorkflowRefusal("Actual package metadata does not establish the approved version, variant, publisher and source for this exact artifact")
                _fresh(metadata["observed_utc"], after=state["plan"]["registered_utc"], seconds=900)

    def _verify(self, binding):
        """Re-read recovery or artifact bytes from disk through the injected verifier (D-018, PD-3)."""
        if self.verify_artifact is None:
            raise WorkflowRefusal("Recovery and artifact bytes cannot be re-checked without the service's storage verifier; the action is held", code="verifier-missing")
        try:
            result = self.verify_artifact(copy.deepcopy(binding))
        except WorkflowRefusal:
            raise
        except pc_records.Refusal as error:
            raise WorkflowRefusal(str(error), code=error.code) from error
        if result is not None:
            raise WorkflowRefusal("The artifact verifier must return nothing and refuse by raising", code="verifier-contract")

    def _owned_output(self, value):
        root = Path(_text(value, "recovery output root", 2000))
        if not root.is_absolute():
            raise WorkflowRefusal("Recovery output root must be an exact absolute owned work path")
        root = no_links(root)
        try:
            root.relative_to(self.root / "work")
        except ValueError as error:
            raise WorkflowRefusal("Recovery artifacts must remain in the exact owned work output root") from error
        return root

    def _work_artifact(self, path, expected_sha256, *, output_root, max_bytes=SERVICE_RECORD_MAX_BYTES):
        """Bytes of a private record under an owned work root (a service receipt), admitted before they are read."""
        value = Path(_text(path, "owned record path", 2000))
        if not value.is_absolute() or output_root is None or not Path(output_root).is_absolute():
            raise WorkflowRefusal("Owned records need exact absolute owned work paths")
        value, output_root = no_links(value), self._owned_output(str(output_root))
        try:
            relative = value.relative_to(output_root)
        except ValueError as error:
            raise WorkflowRefusal("Owned records must remain in the exact owned work root") from error
        current = _private_directory(output_root)
        for part in relative.parts[:-1]:
            current = _private_directory(current / part)
        data = read_record_bytes(value, max_bytes, private=True)
        if not isinstance(expected_sha256, str) or digest(data) != expected_sha256:
            raise WorkflowRefusal("Required owned record bytes changed")
        return data

    def _retention(self, state, evidence_id):
        row = self.evidence_rows(state, [evidence_id], kinds={"retention"})[0]
        data = self._read_owned(self._directory(state["session_id"]) / row["path"], EVIDENCE_MAX_BYTES)
        retention = typed_record(decode_record(data, max_bytes=EVIDENCE_MAX_BYTES, max_nodes=EVIDENCE_MAX_NODES), RECOVERY_RETENTION)
        if retention["session_id"] != state["session_id"] or retention["required"] is not True or not isinstance(retention["artifacts"], dict):
            raise WorkflowRefusal("A current exact retention record must protect every actual required recovery artifact")
        return retention["artifacts"]

    def _quarantine_recovery(self, state, binding, action):
        typed_record(binding, QUARANTINE_RECOVERY)
        if not action or action["adapter_id"] != pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE or binding["restore_plan_sha256"] != action["adapter_plan_sha256"] or digest(binding["restore_plan"]) != action["adapter_plan_sha256"]:
            raise WorkflowRefusal("Quarantine recovery applies only to its exact reviewed quarantine-restore action, never to a generic repair or purge")
        payload = self.action_binding(state, action)
        if payload["output_root"] != binding["output_root"] or payload["storage_plan"] != binding["restore_plan"] or payload["storage_plan"].get("receipt") != binding["quarantine_receipt"]:
            raise WorkflowRefusal("Quarantine recovery differs from the exact approved native restore mapping")
        output, receipt = self._owned_output(binding["output_root"]), binding["quarantine_receipt"]
        try:
            attempt_path = output / receipt["attempt"]
            retained = {str(output / ("outcome-quarantine-" + receipt["plan_sha256"] + ".json")): digest(receipt)}
            retained.update({str(output / row["quarantine_record"]["relative_path"]): row["quarantine_record"]["sha256"] for row in receipt["records"]})
        except (KeyError, TypeError) as error:
            raise WorkflowRefusal("Quarantine recovery needs the exact typed original quarantine receipt") from error
        artifacts = self._retention(state, binding["retention_evidence_id"])
        # The attempt record's digest is checked against its bytes by the verifier.
        retained[str(attempt_path)] = artifacts.get(str(attempt_path))
        if not isinstance(retained[str(attempt_path)], str) or artifacts != retained:
            raise WorkflowRefusal("A current exact retention record must protect every actual required recovery artifact")
        self._verify({"kind": "quarantine_recovery", "output_root": str(output), "protected_roots": payload["protected_roots"],
                      "restore_plan": binding["restore_plan"], "restore_plan_sha256": action["adapter_plan_sha256"],
                      "attempt": receipt["attempt"], "attempt_sha256": retained[str(attempt_path)]})

    def verify_recovery(self, state, evidence_ids, *, action=None):
        purge_payload = original = None
        if action and action["adapter_id"] == pc_records.ADAPTER_STORAGE_PURGE:
            purge_payload = self.action_binding(state, action)
            original = _storage_record(purge_payload["storage_plan"].get("receipt"), "quarantine_receipt", "Purge recovery requires the exact original typed quarantine receipt")
            if original.get("recovery_required") is not True or not isinstance(original.get("recovery_backup"), dict) or not isinstance(original.get("recovery_verification"), dict):
                raise WorkflowRefusal("Integrated purge of originally unbacked quarantine is held; an unrelated backup cannot supply its recovery proof")
        for row in self.evidence_rows(state, evidence_ids, kinds={"recovery"}):
            binding = decode_record(self._read_owned(self._directory(state["session_id"]) / row["path"], EVIDENCE_MAX_BYTES), max_bytes=EVIDENCE_MAX_BYTES, max_nodes=EVIDENCE_MAX_NODES)
            if isinstance(binding, dict) and binding.get("schema") == QUARANTINE_RECOVERY:
                self._quarantine_recovery(state, binding, action)
                continue
            typed_record(binding, RECOVERY_BINDING)
            backup, restore = binding["backup_receipt"], binding["restore_receipt"]
            if purge_payload and (binding["output_root"] != purge_payload["output_root"] or backup != original["recovery_backup"] or restore != original["recovery_verification"]):
                raise WorkflowRefusal("Purge recovery must match the exact original quarantine backup, restore verification and output root")
            message = "Required recovery needs actual typed backup and completed restoration receipts"
            _storage_record(backup, "backup_receipt", message)
            _storage_record(restore, "restore_receipt", message)
            if backup.get("required_recovery") is not True:
                raise WorkflowRefusal(message)
            output_root = self._owned_output(binding["output_root"])
            if restore.get("backup_plan_sha256") != backup.get("plan_sha256") or restore.get("backup_archive_sha256") != backup.get("archive_sha256") or restore.get("backup_manifest_sha256") != backup.get("manifest_sha256") or not SHA.fullmatch(str(restore.get("plan_sha256", ""))):
                raise WorkflowRefusal("Restoration receipt does not bind this exact verified backup")
            files = restore.get("files")
            if not isinstance(files, list) or not 0 < len(files) <= pc_records.MAX_BACKUP_ENTRIES:
                raise WorkflowRefusal("Restoration must account for every bounded archived file")
            outcome_path = output_root / ("outcome-restore-" + restore["plan_sha256"] + ".json")
            retained = {backup.get("archive"): backup.get("archive_sha256"), backup.get("manifest"): backup.get("manifest_sha256"), str(outcome_path): digest(restore)}
            for file in files:
                try:
                    expected = Path(restore["destination"]) / file["root_id"] / file["relative_path"]
                    expected.relative_to(output_root)
                except (KeyError, TypeError, ValueError) as error:
                    raise WorkflowRefusal("Restoration probe escapes its owned work output root") from error
                retained[str(expected)] = file.get("sha256")
            if self._retention(state, binding["retention_evidence_id"]) != retained:
                raise WorkflowRefusal("A current exact retention record must protect every actual required recovery artifact")
            # The archive, manifest, restored files and outcome receipt are re-read from disk by the verifier,
            # which also checks that the backup covers every quarantined original of a purge.
            self._verify({"kind": "backup_recovery", "output_root": str(output_root), "backup_receipt": backup,
                          "restore_receipt": restore, "purge_receipt": original})

    def register_plan(self, session_id, *, plan, expected_revision=None):
        document = copy.deepcopy(plan)
        def mutate(state):
            self._writable(state)
            stages = JOBS[state["job"]]["stages"]
            if state["stage"] not in stages[:stages.index("apply")]:
                raise WorkflowRefusal("A new or replacement plan must be reviewed before the apply stage; existing action, verification and finish checkpoints cannot authorize another plan")
            if any(op["outcome"] is None for op in state["operations"].values()):
                raise WorkflowRefusal("Reconcile the active operation before replacing its plan")
            self._validate_plan_document(state, document)
            self.evidence_rows(state, document["evidence_ids"])
            if not state["scope_authorization"]:
                raise WorkflowRefusal("The current owner has not authorized this scope")
            consumed = {op["action_id"] for op in state["operations"].values()}
            for action in document["actions"]:
                self.action_binding(state, action)
                if action["action_id"] in consumed:
                    raise WorkflowRefusal("A consumed action identifier cannot be reused or retried")
                if action["requires_recovery"] or action["recovery_evidence_ids"]:
                    self.verify_recovery(state, action["recovery_evidence_ids"], action=action)
                if action.get("estimate_evidence_id"):
                    estimate = self.evidence_rows(state, [action["estimate_evidence_id"]], kinds={"inventory"})[0]
                    if estimate["facts"].get("action_id") != action["action_id"]:
                        raise WorkflowRefusal("A cost fact must identify this exact action to prevent unrelated or duplicate workload estimates")
            state["plan"] = {"document": document, "sha256": digest(document), "settings_revision": state["settings_revision"], "registered_utc": pc_records.utc_now()}
            state["reviews"] = []
            state["approval"] = None
            state["irreversible_ack"] = None
            return {"plan_sha256": state["plan"]["sha256"], "action_ids": [a["action_id"] for a in document["actions"]]}, "The exact plan is saved. It still needs two independent reviews and your concrete action decision before any change."
        return self._change(session_id, "plan_registered", mutate, expected_revision)

    @staticmethod
    def current_plan(state, plan_sha256):
        if not state["plan"] or state["plan"]["sha256"] != plan_sha256 or state["plan"]["settings_revision"] != state["settings_revision"]:
            raise WorkflowRefusal("The exact current plan hash is required")
        return state["plan"]["document"]

    def record_review(self, session_id, *, plan_sha256, reviewer_id, role, verdict, evidence_ids, notes, expected_revision=None):
        record_identifier(reviewer_id, "reviewer identifier")
        _text(notes, "review notes")
        if role not in ROLES or verdict not in {"approved", "hold"}:
            raise WorkflowRefusal("A supported review role and approved/hold verdict are required")
        def mutate(state):
            self._writable(state)
            self.current_plan(state, plan_sha256)
            self.evidence_rows(state, evidence_ids, kinds={"review"}, after=state["plan"]["registered_utc"])
            if reviewer_id == state["owner_id"] or any(row["reviewer_id"] == reviewer_id or row["role"] == role for row in state["reviews"]):
                raise WorkflowRefusal("Reviews need two distinct independent reviewers, separate from the owner")
            record = {"reviewer_id": reviewer_id, "role": role, "verdict": verdict, "evidence_ids": list(evidence_ids), "notes": notes, "plan_sha256": plan_sha256, "settings_revision": state["settings_revision"], "recorded_utc": pc_records.utc_now()}
            state["reviews"].append(record)
            state["approval"] = None
            return record, "The independent review is recorded against the exact current plan. A held review prevents changes."
        return self._change(session_id, "review_recorded", mutate, expected_revision)

    def _reviewed(self, state):
        if not state["plan"] or len(state["reviews"]) != 2 or {row["role"] for row in state["reviews"]} != ROLES or len({row["reviewer_id"] for row in state["reviews"]}) != 2:
            raise WorkflowRefusal("Two independent compatibility/data and evidence/security reviews are required")
        for row in state["reviews"]:
            if row["verdict"] != "approved" or row["plan_sha256"] != state["plan"]["sha256"] or row["settings_revision"] != state["settings_revision"]:
                raise WorkflowRefusal("A review holds this plan or belongs to an earlier plan")
            self.evidence_rows(state, row["evidence_ids"], kinds={"review"}, after=state["plan"]["registered_utc"])

    def approve_plan(self, session_id, *, plan_sha256, action_ids, owner_quote, owner_message_id, owner_id="owner", source="current_owner_chat", acknowledge_permanent_loss=False, expected_revision=None):
        _ids(action_ids, "approved action identifiers", allow_empty=False)
        def mutate(state):
            self._writable(state)
            document = self.current_plan(state, plan_sha256)
            self._reviewed(state)
            self.evidence_rows(state, document["evidence_ids"])
            if set(action_ids) - {a["action_id"] for a in document["actions"]}:
                raise WorkflowRefusal("Approval cannot include actions outside the concrete plan")
            purge_ids = [a["action_id"] for a in document["actions"] if "permanent_data_loss" in _acknowledgments(a) and a["action_id"] in action_ids]
            if purge_ids and acknowledge_permanent_loss is not True:
                raise WorkflowRefusal("Permanent purge needs separate actual-owner acknowledgement of irreversible loss bound to these exact purge actions")
            record = _owner(state, owner_quote, owner_message_id, owner_id, source)
            record.update(plan_sha256=plan_sha256, action_ids=list(action_ids), permanent_loss_action_ids=purge_ids)
            state["approval"] = record
            return {"action_ids": list(action_ids)}, "Your actual instruction is recorded for those exact reviewed actions. Fresh checks and protected system consent still apply."
        return self._change(session_id, "plan_approved", mutate, expected_revision)

    def record_irreversible_ack(self, session_id, *, plan_sha256, action_ids, acknowledge_irreversible_loss, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat", expected_revision=None):
        _ids(action_ids, "irreversible action identifiers", allow_empty=False)
        if acknowledge_irreversible_loss is not True:
            raise WorkflowRefusal("An explicit separate acknowledgement of permanent data loss is required")
        def mutate(state):
            self._writable(state)
            plan = self.current_plan(state, plan_sha256)
            purge = {a["action_id"] for a in plan["actions"] if "permanent_data_loss" in _acknowledgments(a)}
            if set(action_ids) - purge:
                raise WorkflowRefusal("Irreversible-loss acknowledgement binds only exact current permanent-purge actions")
            record = _owner(state, owner_quote, owner_message_id, owner_id, source)
            record.update(type="permanent_data_loss", plan_sha256=plan_sha256, action_ids=list(action_ids), scope_sha256=digest(state["settings"]["scope"]), acknowledge_irreversible_loss=True)
            state["irreversible_ack"] = record
            return {"action_ids": action_ids}, "Your separate acknowledgement of irreversible loss is bound to these exact purge actions, current scope and plan. It cannot authorize another deletion."
        return self._change(session_id, "irreversible_loss_acknowledged", mutate, expected_revision)

    def set_standing_policy(self, session_id, *, action_kinds, max_actions, expires_utc, owner_quote, owner_message_id, targets=None, action_bindings=None, owner_id="owner", source="current_owner_chat", expected_revision=None):
        if not isinstance(action_kinds, list) or not action_kinds or set(action_kinds) - POLICY_KINDS or len(set(action_kinds)) != len(action_kinds) or type(max_actions) is not int or not 1 <= max_actions <= 20:
            raise WorkflowRefusal("Standing policy needs bounded supported ordinary action kinds and 1–20 actions")
        if not isinstance(targets, list) or not targets or len(targets) > 20:
            raise WorkflowRefusal("Standing policy needs exact explicitly selected targets")
        for target in targets:
            _text(target, "policy target", 2000)
        if not isinstance(action_bindings, list) or not action_bindings or len(action_bindings) > 20:
            raise WorkflowRefusal("Standing policy needs exact adapter payload/plan/inventory hash bindings")
        for binding in action_bindings:
            exact_fields(binding, {"adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256"}, {"adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256"})
            facts = pc_records.ADAPTERS.get(binding["adapter_id"]) if isinstance(binding["adapter_id"], str) else None
            if not facts or not facts["policy_coverable"] or not set(facts["kinds"]) & set(action_kinds) or any(not isinstance(binding[key], str) or not SHA.fullmatch(binding[key]) for key in binding if key != "adapter_id"):
                raise WorkflowRefusal("Standing policy binding has unsupported adapter or missing exact hashes")
        expiry = utc_time(expires_utc)
        if not utc_time(pc_records.utc_now()) < expiry <= utc_time(pc_records.utc_now()) + timedelta(days=7):
            raise WorkflowRefusal("Policy expiry must be in the next seven days")
        def mutate(state):
            self._writable(state)
            if state["settings"]["control"] != "automatic" or not state["scope_authorization"]:
                raise WorkflowRefusal("Explicit automatic control and current authorized scope are required")
            record = _owner(state, owner_quote, owner_message_id, owner_id, source)
            record.update(action_kinds=list(action_kinds), targets=list(targets), action_bindings=copy.deepcopy(action_bindings), max_actions=max_actions, used_actions=0, expires_utc=expires_utc, scope_sha256=digest(state["settings"]["scope"]))
            state["standing_policy"] = record
            return {}, "Your bounded standing policy is recorded. Each exact plan still needs two independent reviews, fresh checks and all selected checkpoints; protected consent cannot be automated."
        return self._change(session_id, "policy_recorded", mutate, expected_revision)

    def _authorization(self, state, action):
        approval = state["approval"]
        if approval and action["action_id"] in approval["action_ids"] and approval["plan_sha256"] == state["plan"]["sha256"]:
            return {"kind": "exact_plan", "message_id": approval["message_id"], "plan_sha256": state["plan"]["sha256"], "action_id": action["action_id"]}
        policy = state["standing_policy"]
        if policy and state["settings"]["control"] == "automatic" and policy["settings_revision"] == state["settings_revision"] and policy["scope_sha256"] == digest(state["settings"]["scope"]) and utc_time(policy["expires_utc"]) > utc_time(pc_records.utc_now()) and policy["used_actions"] < policy["max_actions"] and action["kind"] in policy["action_kinds"] and action["target"] in policy["targets"] and {key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")} in policy["action_bindings"] and not action["requires_os_consent"] and pc_records.ADAPTERS[action["adapter_id"]]["policy_coverable"] and not pc_records.ADAPTERS[action["adapter_id"]]["irreversible"]:
            return {"kind": "standing_policy", "message_id": policy["message_id"], "plan_sha256": state["plan"]["sha256"], "action_id": action["action_id"]}
        raise WorkflowRefusal("This exact action lacks current owner authority; control style alone never authorizes a change")

    @staticmethod
    def pending_items(state):
        return [item for item in state["pending"].values() if not item["resolved"]]

    def _checkpoint(self, state, name, action_id=None):
        if name not in state["settings"]["checkpoints"]:
            return
        token = "checkpoint-" + name + "-" + digest({"stage": state["stage"], "action": action_id, "settings": state["settings_revision"], "plan": state["plan"]["sha256"] if state["plan"] else None})[:20]
        if token not in state["pending"]:
            state["pending"][token] = {"pending_id": token, "kind": "checkpoint", "checkpoint": name, "action_id": action_id, "created_utc": pc_records.utc_now(), "resolved": False, "settings_revision": state["settings_revision"]}
            if state["status"] == "active":
                state["status"] = "awaiting_user"

    def _next_action_checkpoint(self, state):
        if not state["plan"] or state["stage"] != "apply":
            return
        consumed = {op["action_id"] for op in state["operations"].values()}
        for action in state["plan"]["document"]["actions"]:
            if action["action_id"] not in consumed:
                self._checkpoint(state, "before_action", action["action_id"])
                return

    def record_protected_consent(self, session_id, *, action_id, plan_sha256, evidence_id, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat", expected_revision=None):
        def mutate(state):
            self._writable(state)
            document = self.current_plan(state, plan_sha256)
            if action_id not in {a["action_id"] for a in document["actions"] if a["requires_os_consent"]}:
                raise WorkflowRefusal("This is not a protected-consent action in the current plan")
            rows = self.evidence_rows(state, [evidence_id], kinds={"protected_consent"}, after=state["plan"]["registered_utc"], seconds=900)
            facts = rows[0]["facts"]
            if facts.get("plan_sha256") != plan_sha256 or facts.get("action_id") != action_id or facts.get("actual_os_consent") is not True:
                raise WorkflowRefusal("Record the actual protected consent result for this exact action")
            record = _owner(state, owner_quote, owner_message_id, owner_id, source)
            record.update(plan_sha256=plan_sha256, action_id=action_id, evidence_id=evidence_id)
            key = "consent-" + action_id
            state["pending"][key] = {"pending_id": key, "kind": "protected_consent", "resolved": True, "record": record}
            return {}, "The owner's actual protected-system consent result is recorded; the helper does not bypass or click that prompt."
        return self._change(session_id, "protected_consent_recorded", mutate, expected_revision)

    def begin_operation(self, session_id, *, action_id, plan_sha256, precondition_evidence_ids, owner_consent_evidence_id=None, expected_revision=None):
        record_identifier(action_id)
        def mutate(state):
            if state["status"] != "active" or state["stage"] != "apply" or self.pending_items(state):
                raise WorkflowRefusal("New actions wait until the apply stage is active and every hold/checkpoint is resolved")
            activation = self.require_schedule_activation(state)
            if self._outstanding_effects():
                raise WorkflowRefusal("An outstanding mutating operation in this engine registry still needs an actual receipt or effects reconciliation")
            document = self.current_plan(state, plan_sha256)
            self._reviewed(state)
            self.evidence_rows(state, document["evidence_ids"])
            actions = [a for a in document["actions"] if a["action_id"] == action_id]
            if not actions:
                raise WorkflowRefusal("Action is absent from the exact plan")
            action = actions[0]
            self.action_binding(state, action)
            unconsumed = [a["action_id"] for a in document["actions"] if not any(op["action_id"] == a["action_id"] for op in state["operations"].values())]
            if not unconsumed or action_id != unconsumed[0]:
                raise WorkflowRefusal("Actions follow the exact reviewed order and their individual checkpoints")
            if any(op["action_id"] == action_id or op["outcome"] is None for op in state["operations"].values()):
                raise WorkflowRefusal("An action is already active or consumed; no automatic retry")
            authorization = self._authorization(state, action)
            for acknowledgment in _acknowledgments(action):
                ack = state["irreversible_ack"]
                if not ack or ack["type"] != acknowledgment or ack["plan_sha256"] != plan_sha256 or action_id not in ack["action_ids"] or ack["settings_revision"] != state["settings_revision"] or ack["scope_sha256"] != digest(state["settings"]["scope"]):
                    raise WorkflowRefusal("This exact action still needs the owner's separate acknowledgment: " + acknowledgment.replace("_", " "))
            after = max((state["plan"]["registered_utc"], activation["activated_utc"]), key=utc_time) if activation else state["plan"]["registered_utc"]
            rows = self.evidence_rows(state, precondition_evidence_ids, kinds={"precondition"}, after=after, seconds=900)
            required = {"identity_matches", "scope_matches", "content_matches", "compatibility_checked", "provenance_checked"}
            if action["requires_recovery"]:
                required.add("recovery_verified")
                self.verify_recovery(state, action["recovery_evidence_ids"], action=action)
            for row in rows:
                facts = row["facts"]
                binding = {key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")}
                if facts.get("plan_sha256") != plan_sha256 or facts.get("action_id") != action_id or any(facts.get(key) != value for key, value in binding.items()) or any(facts.get(flag) is not True for flag in required):
                    raise WorkflowRefusal("Fresh preconditions must confirm this exact action's identity, scope, content, compatibility, provenance and recovery")
            if action["adapter_id"] == pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL:
                self._external_preflight(state, action, rows)
            if action["requires_os_consent"]:
                record = state["pending"].get("consent-" + action_id, {}).get("record")
                if not record or record["plan_sha256"] != plan_sha256 or record["evidence_id"] != owner_consent_evidence_id:
                    raise WorkflowRefusal("The actual owner must handle and record protected OS consent")
                self.evidence_rows(state, [owner_consent_evidence_id], kinds={"protected_consent"}, after=state["plan"]["registered_utc"], seconds=900)
            operation_id = "operation-" + uuid.uuid4().hex
            operation = {"operation_id": operation_id, "action_id": action_id, "plan_sha256": plan_sha256, "settings_revision": state["settings_revision"], "started_utc": pc_records.utc_now(), "finished_utc": None, "outcome": None, "evidence_ids": [], "summary": "Waiting for an actual operation outcome", "authorization": authorization, "pause_requested": False, "resolution": None, "mutating": action["mutating"], "adapter_id": action["adapter_id"]}
            state["operations"][operation_id] = operation
            if authorization["kind"] == "standing_policy":
                state["standing_policy"]["used_actions"] += 1
            return operation, "The one-use operation receipt is recorded. The coordinator may now invoke only the exact supported adapter action; preserve its actual result."
        with self._registry_lock():
            return self._change(session_id, "operation_started", mutate, expected_revision)

    def _restart_evidence(self, state, evidence_id, kinds):
        record_identifier(evidence_id)
        row = state["evidence"].get(evidence_id)
        if not row or row["kind"] not in kinds or row["scope"] != state["settings"]["scope"] or row["settings_revision"] != state["settings_revision"]:
            raise WorkflowRefusal("Restart evidence must retain this operation's original current scope and settings")
        data = self._read_owned(self._directory(state["session_id"]) / row["path"])
        if digest(data) != row["sha256"] or len(data) != row["size"]:
            raise WorkflowRefusal("Original restart evidence bytes changed")
        return row, decode_record(data)

    def _restart_context(self, state, operation):
        if operation["adapter_id"] != pc_records.ADAPTER_SYSTEM_REVIEWED_EXTERNAL or operation["settings_revision"] != state["settings_revision"] or not state["plan"] or operation["plan_sha256"] != state["plan"]["sha256"] or state["platform"] != "windows":
            raise WorkflowRefusal("A restart continuation must retain the exact original Windows MSI operation, plan and scope")
        action = next((item for item in state["plan"]["document"]["actions"] if item["action_id"] == operation["action_id"]), None)
        if not action or action["adapter_id"] != operation["adapter_id"]:
            raise WorkflowRefusal("The restart action is not the original consumed handoff")
        row, payload = self._restart_evidence(state, action["adapter_payload_evidence_id"], {"adapter_payload"})
        if row["sha256"] != action["adapter_payload_sha256"] or payload.get("operation") != operation["adapter_id"] or digest(payload.get("external_plan")) != action["adapter_plan_sha256"] or payload.get("external_plan_sha256") != action["adapter_plan_sha256"]:
            raise WorkflowRefusal("Original MSI payload bytes or plan binding changed")
        external = payload["external_plan"]
        if external.get("catalog_id") != "windows.msiexec.install" or external.get("kind") != "update" or external.get("mode") != state["mode"] or external.get("platform") != "windows" or external.get("scope") != state["settings"]["scope"]:
            raise WorkflowRefusal("Only the exact fixed MSI local-install recipe supports this restart continuation")
        return action, external

    def _restart_boot(self, state, evidence_id):
        row, boot = self._restart_evidence(state, evidence_id, {"precondition", "outcome"})
        typed_record(boot, WINDOWS_BOOT)
        if boot["mode"] != state["mode"] or boot["platform"] != "windows" or boot["source"] != "windows.cim_last_boot_up_time" or boot["observed_utc"] != row["observed_utc"] or utc_time(boot["last_boot_utc"]) > utc_time(boot["observed_utc"]):
            raise WorkflowRefusal("Restart checks require an exact owned actual Windows boot observation")
        return row, boot

    def _restart_pending(self, state, operation, evidence_id):
        action, external = self._restart_context(state, operation)
        row, proof = self._restart_evidence(state, evidence_id, {"outcome"})
        typed_record(proof, RESTART_PENDING)
        expected = {"session_id": state["session_id"], "operation_id": operation["operation_id"], "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"], "settings_revision": state["settings_revision"], "scope_sha256": digest(state["settings"]["scope"]), "adapter_payload_sha256": action["adapter_payload_sha256"], "external_plan_sha256": action["adapter_plan_sha256"], "mode": state["mode"], "platform": "windows", "catalog_id": "windows.msiexec.install", "original_exit_code": 3010}
        if any(proof[key] != value for key, value in expected.items()) or type(proof["original_exit_code"]) is not int or proof["observed_utc"] != row["observed_utc"]:
            raise WorkflowRefusal("The restart-pending receipt must bind the exact original 3010 operation")
        relative = PurePosixPath(_text(proof["native_receipt_relative_path"], "owned original MSI receipt", 2000))
        tail = ("operations", state["session_id"], operation["operation_id"], "external-restart-pending.json")
        if relative.is_absolute() or "\\" in str(relative) or any(part in {".", ".."} or ":" in part for part in relative.parts) or len(relative.parts) < 6 or relative.parts[0] != "work" or tuple(relative.parts[-4:]) != tail:
            raise WorkflowRefusal("The original restart receipt must stay in its exact private service operation")
        service_root = self.root.joinpath(*relative.parts[:-4])
        marker = _checked(pc_records.require_schema, decode_record(read_record_bytes(service_root / "service.json", 10000, private=True)), SERVICE_RECORD)
        if _without_version(marker) != {"schema": SERVICE_RECORD, "kind": "service_marker", "engine_id": state["engine_id"], "backend": BACKEND}:
            raise WorkflowRefusal("The restart receipt belongs to a foreign service or engine")
        native = typed_record(decode_record(self._work_artifact(str(self.root.joinpath(*relative.parts)), proof["native_receipt_sha256"], output_root=service_root, max_bytes=8_000_000)), EXTERNAL_RECEIPT)
        if any(native[key] != expected[key] for key in ("operation_id", "action_id", "plan_sha256", "adapter_payload_sha256", "mode", "platform", "catalog_id")) or type(native["tool_exit_code"]) is not int or native["tool_exit_code"] != 3010 or native["outcome"] != "installed_restart_pending" or native["postcondition_state"] not in {"not_verified", "unknown"} or not utc_time(operation["started_utc"]) <= utc_time(native["observed_utc"]) <= utc_time(proof["observed_utc"]):
            raise WorkflowRefusal("An actual original MSI 3010 receipt is required; another exit code cannot be translated into success")
        before_row, before = self._restart_boot(state, proof["before_boot_evidence_id"])
        if not utc_time(native["observed_utc"]) <= utc_time(before["observed_utc"]) <= utc_time(proof["observed_utc"]) or utc_time(before["last_boot_utc"]) > utc_time(native["observed_utc"]):
            raise WorkflowRefusal("The actual pre-restart boot observation does not bind the original tool receipt")
        return row, proof, before_row, before, action, external

    def record_restart_pending(self, session_id, *, operation_id, evidence_id, expected_revision=None):
        record_identifier(operation_id)
        def mutate(state):
            if state["status"] != "stopped":
                self._writable(state)
            operation = state["operations"].get(operation_id)
            if not operation or operation["outcome"] not in {None, "unknown"} or operation["resolution"]:
                raise WorkflowRefusal("Only the exact active or unresolved-unknown consumed operation accepts a restart-pending receipt")
            row, proof, before_row, before, _, _ = self._restart_pending(state, operation, evidence_id)
            _fresh(proof["observed_utc"], after=operation["started_utc"], seconds=900)
            _fresh(before["observed_utc"], after=operation["started_utc"], seconds=900)
            existing = operation.get("restart_pending")
            if existing:
                if existing["evidence_id"] != evidence_id or existing["sha256"] != row["sha256"]:
                    raise WorkflowRefusal("The original restart-pending receipt cannot be replaced")
                return existing, "The exact restart-pending receipt is already retained; no action was retried."
            record = {"evidence_id": evidence_id, "sha256": row["sha256"], "before_boot_evidence_id": proof["before_boot_evidence_id"], "before_boot_sha256": before_row["sha256"], "original_exit_code": 3010, "recorded_utc": pc_records.utc_now(), "decision_ids": []}
            operation["restart_pending"] = record
            key = "restart-" + operation_id
            state["pending"][key] = {"pending_id": key, "kind": "restart", "operation_id": operation_id, "resolved": False, "created_utc": pc_records.utc_now()}
            return record, "The installer reported that a restart is needed. Its original 3010 receipt is retained and this same operation is unfinished. Choose whether to defer or authorize an owner-handled restart; no restart or installer retry was performed."
        return self._change(session_id, "restart_pending", mutate, expected_revision)

    def decide_restart(self, session_id, *, operation_id, choice, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat", expected_revision=None):
        if choice not in {"defer", "authorize"}:
            raise WorkflowRefusal("Choose defer or authorize for this exact pending restart")
        def mutate(state):
            if state["status"] != "stopped":
                self._writable(state)
            owner = _owner(state, owner_quote, owner_message_id, owner_id, source)
            operation = state["operations"].get(operation_id)
            if not operation or operation["outcome"] not in {None, "unknown"} or operation["resolution"] or not operation.get("restart_pending"):
                raise WorkflowRefusal("A restart decision requires the exact unfinished operation and actual 3010 safe-checkpoint receipt")
            pending = operation["restart_pending"]
            if operation.get("restart_verification"):
                raise WorkflowRefusal("This restart is already verified; record its actual outcome rather than authorizing another restart")
            self._restart_pending(state, operation, pending["evidence_id"])
            proposal = state["schedule"] if state["settings"]["timing"] == "scheduled" else None
            if state["settings"]["timing"] == "scheduled" and (not proposal or proposal.get("schedule_id") != self._schedule_identity(proposal)):
                raise WorkflowRefusal("Scheduled restart continuation needs a current actual owner proposal")
            if choice == "authorize" and any(item["operation_id"] != operation_id or item["session_id"] != session_id for item in self._outstanding_effects()):
                raise WorkflowRefusal("Unrelated uncertain work must be reconciled before an owner-handled restart")
            if owner_message_id in pending["decision_ids"]:
                existing = operation.get("restart_decision")
                if existing and existing["message_id"] == owner_message_id and existing["choice"] == choice and existing["quote"] == owner_quote and existing["schedule_id"] == (proposal["schedule_id"] if proposal else None):
                    return existing, "This exact restart decision is already recorded; no restart was performed."
                raise WorkflowRefusal("A different restart choice needs a fresh actual owner decision")
            if len(pending["decision_ids"]) >= 100:
                raise WorkflowRefusal("The bounded restart-decision history is full; preserve this held operation")
            record = owner
            not_before = max((record["recorded_utc"], proposal["proposal"]["when_utc"]), key=utc_time) if proposal else record["recorded_utc"]
            record.update(choice=choice, operation_id=operation_id, action_id=operation["action_id"], plan_sha256=operation["plan_sha256"], scope_sha256=digest(state["settings"]["scope"]), pending_evidence_id=pending["evidence_id"], schedule_id=proposal["schedule_id"] if proposal else None, not_before_utc=not_before)
            pending["decision_ids"].append(owner_message_id)
            operation["restart_decision"] = record
            operation.pop("restart_verification", None)
            message = "The restart is deferred and the same consumed operation remains unfinished. No installer retry or other change is authorized." if choice == "defer" else "Your decision authorizes only the owner-handled restart for this exact operation, no earlier than its agreed time. No restart was performed here. Any existing pause remains in place for subsequent work, and actual post-restart verification is still required."
            if state["status"] == "stopped":
                message += " This is accounting for the retained unfinished effect only: the session stays stopped, with no new job action, plan or operation ticket."
            return record, message
        with self._registry_lock():
            return self._change(session_id, "restart_decision", mutate, expected_revision)

    def _validate_restart_verification(self, state, operation, evidence_id):
        pending = operation.get("restart_pending")
        decision = operation.get("restart_decision")
        if not pending or not decision or decision["choice"] != "authorize":
            raise WorkflowRefusal("Actual post-restart verification needs the prior exact owner authorization")
        pending_row, pending_proof, before_row, before, action, external = self._restart_pending(state, operation, pending["evidence_id"])
        if pending_row["sha256"] != pending["sha256"] or before_row["sha256"] != pending["before_boot_sha256"] or decision["settings_revision"] != state["settings_revision"] or decision["scope_sha256"] != digest(state["settings"]["scope"]) or decision["plan_sha256"] != operation["plan_sha256"]:
            raise WorkflowRefusal("Restart authorization or its original proof changed")
        current_schedule = state["schedule"] if state["settings"]["timing"] == "scheduled" else None
        if decision["schedule_id"] != (current_schedule["schedule_id"] if current_schedule else None):
            raise WorkflowRefusal("The restart choice belongs to an earlier schedule; obtain a fresh owner decision")
        row, proof = self._restart_evidence(state, evidence_id, {"outcome"})
        typed_record(proof, RESTART_VERIFICATION)
        expected = {"session_id": state["session_id"], "operation_id": operation["operation_id"], "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"], "settings_revision": state["settings_revision"], "scope_sha256": digest(state["settings"]["scope"]), "external_plan_sha256": action["adapter_plan_sha256"], "mode": state["mode"], "platform": "windows", "catalog_id": "windows.msiexec.install", "original_exit_code": 3010, "pending_evidence_id": pending["evidence_id"], "restart_decision_message_id": decision["message_id"], "before_boot_evidence_id": pending["before_boot_evidence_id"]}
        if any(proof[key] != value for key, value in expected.items()) or type(proof["original_exit_code"]) is not int or proof["observed_utc"] != row["observed_utc"]:
            raise WorkflowRefusal("Post-restart verification must bind the exact original 3010 receipt and owner decision")
        _fresh(proof["observed_utc"], after=decision["recorded_utc"], seconds=900)
        _, after = self._restart_boot(state, proof["after_boot_evidence_id"])
        _fresh(after["observed_utc"], after=decision["recorded_utc"], seconds=900)
        if not utc_time(before["last_boot_utc"]) < utc_time(after["last_boot_utc"]) or not utc_time(pending_proof["observed_utc"]) <= utc_time(decision["recorded_utc"]) < utc_time(after["last_boot_utc"]) <= utc_time(after["observed_utc"]) <= utc_time(proof["observed_utc"]) or utc_time(after["last_boot_utc"]) < utc_time(decision["not_before_utc"]):
            raise WorkflowRefusal("An actual boot transition after the owner decision and agreed time is required")
        if not isinstance(proof["targets"], dict) or set(proof["targets"]) != set(external["targets"]):
            raise WorkflowRefusal("Post-restart checks must account for every exact selected target")
        all_passed = True
        for target in external["targets"]:
            expected_target = {key: external["target_identities"][target][key] for key in ("architecture", "installation_scope", "publisher")}
            expected_target["version"] = external["target_versions"][target]
            actual_target = proof["targets"][target]
            exact_fields(actual_target, set(expected_target), set(expected_target))
            for value in actual_target.values():
                _text(value, "selected actual target observation", 512)
            if actual_target != expected_target:
                all_passed = False
        checks = external["verification_plan"]["checks"]
        if not isinstance(proof["checks"], list) or len(proof["checks"]) != len(checks):
            raise WorkflowRefusal("Post-restart behavior must cover the original verification plan")
        for actual, expected_check in zip(proof["checks"], checks):
            exact_fields(actual, {"check_id", "outcome", "observation"}, {"check_id", "outcome", "observation"})
            if actual["check_id"] != expected_check["check_id"] or actual["outcome"] not in {"passed", "failed", "unknown"}:
                raise WorkflowRefusal("The observations must identify every original behavior check and its actual result")
            if actual["outcome"] != "passed":
                all_passed = False
            _text(actual["observation"], "selected actual post-restart observation", 2000)
        return row, all_passed

    def record_restart_verification(self, session_id, *, operation_id, evidence_id, expected_revision=None):
        def mutate(state):
            if state["status"] != "stopped":
                self._writable(state)
            operation = state["operations"].get(operation_id)
            if not operation or operation["outcome"] not in {None, "unknown"}:
                raise WorkflowRefusal("Only the exact unfinished restart operation accepts this observation")
            row, all_passed = self._validate_restart_verification(state, operation, evidence_id)
            record = {"evidence_id": evidence_id, "sha256": row["sha256"], "recorded_utc": pc_records.utc_now(), "boot_observed": True, "behavior_passed": all_passed}
            operation["restart_verification"] = record
            state["pending"]["restart-" + operation_id]["resolved"] = True
            return record, "Actual boot, target and original behavior observations are recorded for the same operation. " + ("The exact target and original behavior checks passed. " if all_passed else "Some target or behavior results failed or remain unknown; record the actual failed/partial result and review recovery. ") + "The original 3010 code is preserved; this record does not itself finish or retry the installer."
        return self._change(session_id, "restart_verified", mutate, expected_revision)

    def _outcome_rows(self, state, operation, evidence_ids, outcome):
        if operation.get("restart_pending") and outcome in {"succeeded", "failed", "partial"} and operation.get("restart_verification", {}).get("boot_observed") is not True:
            raise WorkflowRefusal("The original 3010 result is still restart-dependent; preserve unknown until actual boot observations account for it")
        if outcome == "succeeded" and operation.get("restart_pending"):
            proof = operation.get("restart_verification")
            if not proof:
                raise WorkflowRefusal("The original 3010 operation still needs its owner-authorized actual restart and exact post-restart verification")
            row, all_passed = self._validate_restart_verification(state, operation, proof["evidence_id"])
            if row["sha256"] != proof["sha256"] or not all_passed:
                raise WorkflowRefusal("The restart occurred but exact target/original behavior checks have not all passed; success cannot be recorded")
        rows = self.evidence_rows(state, evidence_ids, kinds={"outcome", "reconciliation"}, after=operation["started_utc"], seconds=900, allow_empty=outcome == "unknown")
        for row in rows:
            facts = row["facts"]
            if any(facts.get(key) != operation[key] for key in ("operation_id", "action_id", "plan_sha256")) or facts.get("outcome") != outcome:
                raise WorkflowRefusal("Outcome evidence must bind the exact operation, action, plan and observed result")
        return rows

    def finish_operation(self, session_id, *, operation_id, outcome, evidence_ids, summary, expected_revision=None):
        record_identifier(operation_id)
        _text(summary, "outcome summary")
        if outcome not in OUTCOMES:
            raise WorkflowRefusal("Choose an explicit actual operation outcome")
        def mutate(state):
            if operation_id not in state["operations"]:
                raise WorkflowRefusal("Operation is not owned by this session")
            operation = state["operations"][operation_id]
            if operation["outcome"] is not None:
                raise WorkflowRefusal("Operation receipt is already consumed; use bounded reconciliation for unknown outcomes")
            self._outcome_rows(state, operation, evidence_ids, outcome)
            operation.update(outcome=outcome, finished_utc=pc_records.utc_now(), evidence_ids=list(evidence_ids), summary=summary)
            was_stopped = state["status"] == "stopped"
            if outcome != "succeeded":
                key = "reconcile-" + operation_id
                state["pending"][key] = {"pending_id": key, "kind": "reconciliation", "operation_id": operation_id, "created_utc": pc_records.utc_now(), "resolved": False, "settings_revision": state["settings_revision"]}
                state["status"] = "stopped" if was_stopped else "paused" if operation["pause_requested"] else "held"
            elif operation["pause_requested"] or state["status"] == "pause_pending":
                state["status"] = "stopped" if was_stopped else "paused"
            if outcome == "succeeded" and not was_stopped:
                self._checkpoint(state, "after_action", operation["action_id"])
                self._next_action_checkpoint(state)
            return operation, "The actual outcome is recorded. " + ("Verification is still a separate step." if outcome == "succeeded" else "Further changes are held; preserve evidence and reconcile the result before a new decision.")
        return self._change(session_id, "operation_finished", mutate, expected_revision)

    def pause(self, session_id, *, reason="Owner requested pause", expected_revision=None):
        _text(reason, "pause reason")
        def mutate(state):
            self._writable(state)
            active = [op for op in state["operations"].values() if op["outcome"] is None]
            for operation in active:
                operation["pause_requested"] = True
            state["status"] = "pause_pending" if active else "paused"
            return {"active_operation_ids": [op["operation_id"] for op in active]}, "New actions are paused immediately. " + ("The active operation is preserved until its safe checkpoint and actual receipt; it is not killed." if active else "Before resuming, collect fresh evidence of the current state and any earlier outcomes.")
        return self._change(session_id, "paused", mutate, expected_revision)

    def resume(self, session_id, *, reconciliation_evidence_ids, expected_revision=None):
        def mutate(state):
            if state["status"] not in {"paused", "pause_pending", "held"}:
                raise WorkflowRefusal("Only held or paused sessions can be reconciled for resume")
            if any(op["outcome"] in {None, "unknown"} or op["outcome"] in {"failed", "partial"} and not op["resolution"] for op in state["operations"].values()) or any(p["kind"] == "reconciliation" for p in self.pending_items(state)):
                raise WorkflowRefusal("Uncertain or unsuccessful operations require an evidence-backed resolution and possibly a new plan")
            pause_time = max((e["at"] for e in self._load(session_id)["events"] if e["type"] in {"paused", "operation_finished", "resolved"}), default=state["updated_utc"])
            rows = self.evidence_rows(state, reconciliation_evidence_ids, kinds={"reconciliation"}, after=pause_time, seconds=900)
            expected_outcomes = {key: op["outcome"] for key, op in state["operations"].items()}
            for row in rows:
                facts = row["facts"]
                if facts.get("scope_matches") is not True or facts.get("no_changes_detected") is not True or facts.get("operation_outcomes") != expected_outcomes or facts.get("plan_sha256") != (state["plan"]["sha256"] if state["plan"] else None):
                    raise WorkflowRefusal("Resume needs a fresh current-scope check and actual outcomes for every operation")
            state["last_reconciled_utc"] = pc_records.utc_now()
            if state["settings"]["timing"] == "scheduled" and self.require_schedule_activation(state, allow_waiting=True) is None:
                if state["schedule"]:
                    state["schedule"]["ready_for_trigger"] = True
                state["status"] = "held"
            else:
                state["status"] = "awaiting_user" if self.pending_items(state) else "completed" if state["stage"] == "complete" else "active"
            return {}, "Fresh evidence reconciles the current scope and actual outcomes. Existing plan/action approvals still apply only to their unchanged exact scope."
        return self._change(session_id, "resumed", mutate, expected_revision)

    def resolve(self, session_id, *, pending_id=None, evidence_ids=None, choice=None, owner_quote=None, owner_message_id=None, expected_revision=None):
        if pending_id and choice is not None:
            current = self.read_session(session_id)
            item = current["pending"].get(pending_id)
            if item and item["kind"] == "restart" and not item["resolved"]:
                if evidence_ids:
                    raise WorkflowRefusal("A restart choice uses the actual owner instruction, not imported approval evidence")
                return self.decide_restart(session_id, operation_id=item["operation_id"], choice=choice, owner_quote=owner_quote, owner_message_id=owner_message_id, expected_revision=expected_revision)
        if choice is None and not evidence_ids:
            state = self.read_session(session_id)
            items = self.pending_items(state)
            if pending_id:
                items = [p for p in items if p["pending_id"] == pending_id]
                if not items:
                    raise WorkflowRefusal("No unresolved item has that identifier")
            choices = ["keep_stopped"] if state["status"] == "stopped" else ["continue", "revise_plan", "keep_held"]
            if len(items) == 1 and items[0]["kind"] == "restart":
                choices = ["defer", "authorize"]
            elif any(item["kind"] == "restart" for item in items):
                choices += ["defer", "authorize"]
            message = "Review the specific pending decision or collect its bounded reconciliation evidence. Resolve cannot declare success or retry an action. A stopped session remains stopped while actual results are recorded."
            if state["status"] == "stopped" and any(item["kind"] == "restart" for item in items):
                message += " For the retained original 3010 operation only, select its restart item to defer or authorize owner-handled restart accounting; this cannot reopen work or create another installer attempt."
            return self._response(state, "resolution_needed", message, {"pending": items, "choices": choices})
        def mutate(state):
            if not pending_id or pending_id not in state["pending"] or state["pending"][pending_id]["resolved"]:
                raise WorkflowRefusal("Choose one existing unresolved item")
            item = state["pending"][pending_id]
            was_stopped = state["status"] == "stopped"
            if not was_stopped:
                self._writable(state)
            elif item["kind"] != "reconciliation":
                raise WorkflowRefusal("Stopped sessions accept only bounded actual-outcome reconciliation; no new decision/action authority")
            if item["kind"] == "checkpoint":
                if choice != "continue" or not owner_quote or not owner_message_id:
                    raise WorkflowRefusal("A checkpoint needs the owner's actual continue decision")
                item["owner_instruction"] = _owner(state, owner_quote, owner_message_id)
                item["resolved"] = True
                if state["status"] == "awaiting_user" and not self.pending_items(state):
                    state["status"] = "completed" if state["stage"] == "complete" else "active"
            elif item["kind"] == "reconciliation":
                operation = state["operations"][item["operation_id"]]
                if operation["outcome"] is None:
                    raise WorkflowRefusal("An active operation must first reach its safe receipt checkpoint")
                if operation["outcome"] == "unknown":
                    rows = self.evidence_rows(state, evidence_ids or [], kinds={"reconciliation", "outcome"}, after=operation["finished_utc"], seconds=900)
                    outcomes = {row["facts"].get("outcome") for row in rows}
                    if len(outcomes) != 1 or not outcomes <= {"succeeded", "failed", "partial"}:
                        raise WorkflowRefusal("A fresh actual observed outcome is required; unknown cannot be marked resolved")
                    outcome = outcomes.pop()
                    self._outcome_rows(state, operation, evidence_ids, outcome)
                    operation.update(outcome=outcome, evidence_ids=list(evidence_ids), summary="Actual outcome established by fresh reconciliation evidence")
                if operation["outcome"] == "succeeded":
                    item["resolved"] = True
                    state["status"] = "stopped" if was_stopped else "paused"
                    if not was_stopped:
                        self._checkpoint(state, "after_action", operation["action_id"])
                        self._next_action_checkpoint(state)
                elif choice in {"revise_plan", "keep_stopped"} and owner_quote and owner_message_id:
                    if operation.get("restart_pending") and operation.get("restart_verification", {}).get("boot_observed") is not True:
                        raise WorkflowRefusal("The original restart requirement still needs actual boot accounting; generic effects flags cannot clear it")
                    if was_stopped != (choice == "keep_stopped"):
                        raise WorkflowRefusal("A stopped session may account for actual effects while staying stopped; it cannot request or resume a replacement plan")
                    rows = self._outcome_rows(state, operation, evidence_ids or [], operation["outcome"])
                    if any(row["kind"] != "reconciliation" or utc_time(row["observed_utc"]) < utc_time(operation["finished_utc"]) or any(row["facts"].get(flag) is not True for flag in ("actual_effects_recorded", "no_active_effects", "recovery_retained")) for row in rows):
                        raise WorkflowRefusal("Replanning needs fresh actual-effects reconciliation, no ongoing operation and retained recovery; the historical failure remains unchanged")
                    item["owner_instruction"] = _owner(state, owner_quote, owner_message_id)
                    item["resolved"] = True
                    operation["resolution"] = {"kind": "effects_accounted" if was_stopped else "replan_required", "evidence_ids": list(evidence_ids), "recorded_utc": pc_records.utc_now(), "owner_message_id": owner_message_id}
                    if not was_stopped:
                        state["plan"] = None
                        state["approval"] = None
                        state["reviews"] = []
                        state["stage"] = "plan"
                    state["status"] = "stopped" if was_stopped else "held"
                elif choice in {"keep_held", None}:
                    state["status"] = "stopped" if was_stopped else "held"
                else:
                    raise WorkflowRefusal("An unsuccessful action stays held; the owner may request a separately reviewed replacement plan")
            else:
                raise WorkflowRefusal("This pending item has no general-purpose resolution")
            return {"pending": item}, "The identified item is reconciled only to the extent supported by actual evidence and your bounded decision. No action was retried."
        return self._change(session_id, "resolved", mutate, expected_revision)

    def advance_stage(self, session_id, *, evidence_ids, expected_revision=None):
        def mutate(state):
            if state["status"] != "active" or self.pending_items(state):
                raise WorkflowRefusal("Stage advancement waits for an active session and resolved checkpoints")
            self.require_schedule_activation(state)
            stage = state["stage"]
            rows = self.evidence_rows(state, evidence_ids, allow_empty=stage in {"plan", "apply"})
            required = {"scope": ("scope_confirmation", {"scope_confirmed"}), "inventory": ("inventory", {"complete"}), "research": ("research", {"applicability_checked", "official_sources_checked"}), "candidates": ("candidates", {"candidates_reviewed", "excluded_private"}), "symptom": ("symptom", {"symptom_recorded", "relevant_scope"}), "hypotheses": ("hypotheses", {"alternatives_considered", "distinguishing_checks"}), "recovery_plan": ("recovery_plan", {"contents_reviewed", "restore_check_planned", "exclusions_explicit"})}
            if stage in required:
                kind, flags = required[stage]
                matching = [row for row in rows if row["kind"] == kind and all(row["facts"].get(flag) is True for flag in flags)]
                if not matching:
                    raise WorkflowRefusal("This stage needs owned evidence establishing its actual required checks")
                if stage == "scope" and (not state["scope_authorization"] or not _scope_selected(state["settings"]["scope"])):
                    raise WorkflowRefusal("An actual current-owner scope decision is required before assessment")
                if stage == "inventory" and not any(type(row["facts"].get("item_count")) is int and row["facts"]["item_count"] >= 0 for row in matching):
                    raise WorkflowRefusal("Inventory must record an explicit assessed item count")
            elif stage == "plan":
                self._reviewed(state)
                for action in state["plan"]["document"]["actions"]:
                    self._authorization(state, action)
            elif stage == "apply":
                if not state["plan"]:
                    raise WorkflowRefusal("No current plan can be verified")
                planned = {a["action_id"] for a in state["plan"]["document"]["actions"]}
                succeeded = {op["action_id"] for op in state["operations"].values() if op["plan_sha256"] == state["plan"]["sha256"] and op["outcome"] == "succeeded"}
                if planned != succeeded:
                    raise WorkflowRefusal("Every current planned action needs its own actual successful receipt before verification")
            elif stage == "verify":
                if not state["plan"]:
                    raise WorkflowRefusal("Verification needs the exact current plan")
                planned = {a["action_id"] for a in state["plan"]["document"]["actions"]}
                latest = max(op["finished_utc"] for op in state["operations"].values() if op["plan_sha256"] == state["plan"]["sha256"])
                verified = [row for row in rows if row["kind"] == "verification" and row["facts"].get("verification_passed") is True and row["facts"].get("plan_sha256") == state["plan"]["sha256"] and set(row["facts"].get("checked_action_ids", [])) == planned and utc_time(row["observed_utc"]) >= utc_time(latest)]
                if not verified:
                    raise WorkflowRefusal("Actual behavior verification for every exact planned action is required after its outcome")
            else:
                raise WorkflowRefusal("This job is already at its final stage")
            stages = JOBS[state["job"]]["stages"]
            state["stage"] = stages[stages.index(stage) + 1]
            checkpoint = "findings" if state["stage"] == "plan" else "plan" if state["stage"] == "apply" else "finish" if state["stage"] == "complete" else None
            if checkpoint:
                self._checkpoint(state, checkpoint)
            if state["stage"] == "complete" and not self.pending_items(state):
                state["status"] = "completed"
            if state["stage"] == "apply":
                self._next_action_checkpoint(state)
            return {"stage": state["stage"]}, "The evidence supports the next step: " + STAGE_LABELS[state["stage"]].lower() + ". " + ("The actual checked result is complete; retained evidence and recovery files still need a separate cleanup decision." if state["status"] == "completed" else "Use PatchCairn: options for the next decision and any selected checkpoint.")
        return self._change(session_id, "stage_advanced", mutate, expected_revision)

    def complete_assessment(self, session_id, *, summary_evidence_id, verification_evidence_ids, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat", expected_revision=None):
        record_identifier(summary_evidence_id)
        def mutate(state):
            self._writable(state)
            if state["status"] != "active" or state["stage"] != "plan" or self.pending_items(state):
                raise WorkflowRefusal("Finish the assessment stages and selected checkpoints before closing an assessment")
            activation = self.require_schedule_activation(state)
            if state["operations"] or state["plan"] is not None or state["approval"] is not None or state["reviews"] or state["standing_policy"] is not None:
                raise WorkflowRefusal("Assessment-only completion cannot close a session with any operation history, plan, approval, reviews or standing policy")
            authorization = state["scope_authorization"]
            scope_sha = digest(state["settings"]["scope"])
            if not authorization or authorization.get("owner_id") != state["owner_id"] or authorization.get("settings_revision") != state["settings_revision"] or authorization.get("scope_sha256") != scope_sha:
                raise WorkflowRefusal("Assessment completion requires the actual current owner's exact authorized scope")
            after = max((authorization["recorded_utc"], activation["activated_utc"]), key=utc_time) if activation else authorization["recorded_utc"]
            summary_row = self.evidence_rows(state, [summary_evidence_id], kinds={"research"}, after=after, seconds=900)[0]
            summary = typed_record(decode_record(self._read_owned(self._directory(session_id) / summary_row["path"])), ASSESSMENT_SUMMARY)
            if summary["job"] != state["job"] or summary["mode"] != state["mode"] or summary["scope_sha256"] != scope_sha or summary["settings_revision"] != state["settings_revision"]:
                raise WorkflowRefusal("The assessment summary must bind this exact current job, mode and scope")
            _text(summary["summary"], "assessment summary", 4000)
            for label in ("findings", "limitations"):
                if not isinstance(summary[label], list) or len(summary[label]) > 100:
                    raise WorkflowRefusal("Assessment findings and limitations must be bounded selected text")
                for item in summary[label]:
                    _text(item, "assessment " + label, 2000)
            _ids(summary["assessed_evidence_ids"], "assessed evidence identifiers", allow_empty=False)
            if summary_evidence_id in summary["assessed_evidence_ids"]:
                raise WorkflowRefusal("An assessment summary cannot stand in for its underlying assessment evidence")
            assessed = self.evidence_rows(state, summary["assessed_evidence_ids"], kinds={"scope_confirmation", "inventory", "research", "candidates", "symptom", "hypotheses", "recovery_plan"}, after=authorization["recorded_utc"])
            requirements = {"scope": ("scope_confirmation", {"scope_confirmed"}), "inventory": ("inventory", {"complete"}), "research": ("research", {"applicability_checked", "official_sources_checked"}), "candidates": ("candidates", {"candidates_reviewed", "excluded_private"}), "symptom": ("symptom", {"symptom_recorded", "relevant_scope"}), "hypotheses": ("hypotheses", {"alternatives_considered", "distinguishing_checks"}), "recovery_plan": ("recovery_plan", {"contents_reviewed", "restore_check_planned", "exclusions_explicit"})}
            for stage in JOBS[state["job"]]["stages"][:JOBS[state["job"]]["stages"].index("plan")]:
                kind, flags = requirements[stage]
                if not any(row["kind"] == kind and all(row["facts"].get(flag) is True for flag in flags) for row in assessed):
                    raise WorkflowRefusal("The summary must cover the actual current evidence for every agreed assessment step")
            rows = self.evidence_rows(state, verification_evidence_ids, kinds={"verification"}, after=summary_row["registered_utc"], seconds=900)
            for row in rows:
                verification = typed_record(decode_record(self._read_owned(self._directory(session_id) / row["path"])), ASSESSMENT_VERIFICATION)
                if any(verification[key] != summary[key] for key in ("job", "mode", "scope_sha256", "settings_revision", "assessed_evidence_ids")) or verification["summary_evidence_id"] != summary_evidence_id or verification["summary_sha256"] != summary_row["sha256"] or verification["coverage_checked"] is not True or verification["limitations_checked"] is not True or verification["observed_utc"] != row["observed_utc"]:
                    raise WorkflowRefusal("Assessment verification must check the exact current summary, evidence coverage and recorded limitations")
                _fresh(verification["observed_utc"], after=summary_row["registered_utc"], seconds=900)
            record = {"summary_evidence_id": summary_evidence_id, "summary_sha256": summary_row["sha256"], "verification_evidence_ids": list(verification_evidence_ids), "owner_instruction": _owner(state, owner_quote, owner_message_id, owner_id, source)}
            key = "assessment-finish-" + digest({"summary": summary_row["sha256"], "settings": state["settings_revision"], "message": owner_message_id})[:24]
            state["pending"][key] = {"pending_id": key, "kind": "assessment_finish", "resolved": True, "record": record}
            state["stage"] = "complete"
            self._checkpoint(state, "finish")
            if not self.pending_items(state):
                state["status"] = "completed"
            return record, "The assessment and its findings are recorded, including what remains uncertain. This session recorded no maintenance action. " + ("Review the selected finish checkpoint before closing." if state["status"] != "completed" else "The assessment session is complete; any computer change needs a separate reviewed plan.")
        return self._change(session_id, "assessment_completed", mutate, expected_revision)

    @staticmethod
    def _schedule_identity(record):
        try:
            return digest({key: record[key] for key in ("owner_id", "quote", "message_id", "source", "recorded_utc", "settings_revision", "proposal")})
        except KeyError as error:
            raise WorkflowRefusal("An incomplete schedule record cannot authorize work") from error

    def require_schedule_activation(self, state, *, allow_waiting=False):
        if state["settings"]["timing"] != "scheduled":
            return None
        record = state["schedule"]
        if record is None and allow_waiting:
            return None
        if not isinstance(record, dict) or record.get("settings_revision") != state["settings_revision"] or not isinstance(record.get("schedule_id"), str) or not SHA.fullmatch(record["schedule_id"]) or record["schedule_id"] != self._schedule_identity(record):
            raise WorkflowRefusal("Scheduled work needs a current owner-bound proposal and its matching due trigger")
        activation = record.get("activation")
        if activation is None and allow_waiting:
            return None
        if not isinstance(activation, dict):
            raise WorkflowRefusal("This schedule has not been activated by its matching due trigger")
        fields = {"schedule_id", "trigger_id", "activated_utc", "settings_revision"}
        exact_fields(activation, fields, fields)
        proposal = record["proposal"]
        if activation["schedule_id"] != record["schedule_id"] or activation["settings_revision"] != state["settings_revision"] or activation["trigger_id"] not in state["schedule_triggers"] or record.get("ready_for_trigger") is not False or not utc_time(proposal["when_utc"]) <= utc_time(activation["activated_utc"]) <= utc_time(proposal["expires_utc"]) or utc_time(activation["activated_utc"]) - utc_time(proposal["when_utc"]) > timedelta(seconds=proposal["max_lateness_seconds"]) or utc_time(pc_records.utc_now()) < utc_time(activation["activated_utc"]):
            raise WorkflowRefusal("The recorded activation does not authorize this exact current schedule")
        return activation

    def configure_schedule(self, session_id, *, schedule, owner_quote, owner_message_id, expected_revision=None):
        exact_fields(schedule, {"when_utc", "description", "expires_utc", "max_lateness_seconds"}, {"when_utc", "description"})
        if utc_time(schedule["when_utc"]) <= utc_time(pc_records.utc_now()):
            raise WorkflowRefusal("The proposed schedule time must be in the future")
        _text(schedule["description"], "schedule explanation")
        proposal = copy.deepcopy(schedule)
        proposal.setdefault("max_lateness_seconds", 300)
        proposal.setdefault("expires_utc", (utc_time(schedule["when_utc"]) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"))
        if type(proposal["max_lateness_seconds"]) is not int or not 0 <= proposal["max_lateness_seconds"] <= 3600 or not utc_time(proposal["when_utc"]) <= utc_time(proposal["expires_utc"]) <= utc_time(proposal["when_utc"]) + timedelta(hours=24):
            raise WorkflowRefusal("Schedule needs an explicit bounded catch-up window and expiry within 24 hours of its due time")
        def mutate(state):
            self._writable(state)
            if state["settings"]["timing"] != "scheduled":
                raise WorkflowRefusal("Choose scheduled timing before recording a proposal")
            if any(op["outcome"] in {None, "unknown"} and op.get("restart_verification", {}).get("boot_observed") is True for op in state["operations"].values()):
                raise WorkflowRefusal("Actual restart observations are already recorded; record that operation's final receipt before changing its schedule. This new proposal was not accepted; pause subsequent work while accounting for the result")
            previous = state["schedule"]
            decisions = copy.deepcopy(previous.get("decision_ids", [previous["message_id"]])) if previous else []
            _ids(decisions, "schedule decision identifiers")
            if owner_message_id in decisions:
                if previous and owner_message_id == previous["message_id"] and owner_quote == previous["quote"] and proposal == previous["proposal"]:
                    return previous, "This exact schedule decision is already recorded; no activation or action was changed."
                raise WorkflowRefusal("Changing a schedule needs a fresh actual-owner decision; an earlier message cannot authorize a different proposal")
            if len(decisions) >= 500:
                raise WorkflowRefusal("This session reached its bounded schedule-decision history; preserve it and choose separate scoped work")
            record = _owner(state, owner_quote, owner_message_id)
            unresolved = any(op["outcome"] in {None, "unknown"} or op["outcome"] in {"failed", "partial"} and not op["resolution"] for op in state["operations"].values())
            waiting = state["status"] == "held" and previous and previous.get("activation") is None and previous.get("ready_for_trigger") is True
            record.update(proposal=proposal, creates_os_schedule=False, settings_revision=state["settings_revision"], decision_ids=decisions + [owner_message_id], activation=None, ready_for_trigger=bool((state["status"] in {"active", "awaiting_user"} or waiting) and not unresolved))
            record["schedule_id"] = self._schedule_identity(record)
            state["schedule"] = record
            for item in state["pending"].values():
                if item["kind"] == "checkpoint" and item.get("checkpoint") == "scheduled_start":
                    item["resolved"] = True
            active = [op for op in state["operations"].values() if op["outcome"] is None]
            for operation in active:
                operation["pause_requested"] = True
            if active:
                state["status"] = "pause_pending"
            elif state["status"] not in {"paused", "held"}:
                state["status"] = "held"
            return record, "The future schedule proposal is recorded and earlier activation cannot start new work. An existing operation still needs its safe checkpoint and actual outcome. Paused or held work needs fresh reconciliation before the matching due trigger. No operating-system schedule was created."
        return self._change(session_id, "schedule_configured", mutate, expected_revision)

    def trigger_schedule(self, session_id, *, schedule_id, trigger_id, expected_revision=None):
        record_identifier(trigger_id)
        if not isinstance(schedule_id, str) or not SHA.fullmatch(schedule_id):
            raise WorkflowRefusal("A trigger must bind the exact current schedule identifier")
        def mutate(state):
            self._writable(state)
            if not state["schedule"] or state["settings"]["timing"] != "scheduled":
                raise WorkflowRefusal("No current schedule proposal is registered")
            record = state["schedule"]
            if schedule_id != record.get("schedule_id") or schedule_id != self._schedule_identity(record) or record["settings_revision"] != state["settings_revision"]:
                raise WorkflowRefusal("This trigger belongs to a different or superseded schedule")
            if trigger_id in state["schedule_triggers"]:
                return {"trigger_id": trigger_id, "duplicate": True, "starts_operation": False}, "This trigger was already recorded; no duplicate session or action was started."
            if state["status"] in {"paused", "pause_pending"} or state["status"] == "held" and record.get("ready_for_trigger") is not True:
                raise WorkflowRefusal("Scheduled triggers cannot resume paused or held work")
            if record.get("activation") is not None:
                raise WorkflowRefusal("This exact schedule is already activated; a new trigger cannot restart it")
            if self._outstanding_effects():
                raise WorkflowRefusal("An outstanding mutating operation in this engine registry blocks schedule dispatch until actual reconciliation")
            if utc_time(pc_records.utc_now()) < utc_time(state["schedule"]["proposal"]["when_utc"]):
                raise WorkflowRefusal("The proposed schedule time has not arrived")
            proposal = state["schedule"]["proposal"]
            if utc_time(pc_records.utc_now()) > utc_time(proposal["expires_utc"]) or utc_time(pc_records.utc_now()) - utc_time(proposal["when_utc"]) > timedelta(seconds=proposal["max_lateness_seconds"]):
                raise WorkflowRefusal("The bounded schedule catch-up window or expiry has passed; a new owner decision is required")
            for directory in self.work.iterdir():
                if directory.is_dir() and directory.name.startswith("session-") and directory.name != session_id:
                    other = self.read_session(directory.name)
                    if other["job"] == state["job"] and (other["status"] == "active" or other["status"] == "awaiting_user" and other["schedule_triggers"]):
                        raise WorkflowRefusal("Another active session already owns this job; the trigger cannot duplicate it")
            state["schedule_triggers"].append(trigger_id)
            record["activation"] = {"schedule_id": schedule_id, "trigger_id": trigger_id, "activated_utc": pc_records.utc_now(), "settings_revision": state["settings_revision"]}
            record["ready_for_trigger"] = False
            if state["settings"]["control"] == "guided":
                state["status"] = "awaiting_user"
                key = "schedule-start-" + digest(trigger_id)[:24]
                state["pending"][key] = {"pending_id": key, "kind": "checkpoint", "checkpoint": "scheduled_start", "action_id": None, "created_utc": pc_records.utc_now(), "resolved": False, "settings_revision": state["settings_revision"]}
                message = "The scheduled guided session is waiting for you. Review the current scope and checkpoint before continuing."
            else:
                state["status"] = "active"
                message = "The schedule trigger is recorded for this existing session. Exact plan, policy, review and freshness gates still apply before any action."
            return {"trigger_id": trigger_id, "duplicate": False, "starts_operation": False}, message
        with self._registry_lock():
            return self._change(session_id, "schedule_triggered", mutate, expected_revision)

    def stop(self, session_id, *, reason="Owner requested stop", expected_revision=None):
        _text(reason, "stop reason")
        def mutate(state):
            self._writable(state)
            state["status"] = "stopped"
            state["stop_reason"] = reason
            for operation in state["operations"].values():
                if operation["outcome"] is None:
                    operation["pause_requested"] = True
            return {"unresolved": self.pending_items(state)}, "This session is stopped. Evidence, recovery files and unfinished outcomes are preserved. An active operation still needs its actual safe-checkpoint receipt; no new action is allowed."
        return self._change(session_id, "stopped", mutate, expected_revision)

    def status(self, session_id):
        state = self.read_session(session_id)
        explanations = {
            "active": "Continue by reviewing the current step. Collection requires your agreed scope; changes also need the exact plan, fresh checks and the required approval. Next: PatchCairn: options.",
            "awaiting_user": "This session is waiting for your next decision. PatchCairn: options explains the available choice.",
            "held": "Further actions are held because a decision, check or actual result needs attention. Review PatchCairn: options, then PatchCairn: resolve for the pending item. An unknown outcome must be observed before work can continue.",
            "paused": "New actions are paused. Before continuing, the coordinator must check the current scope and actual outcomes. PatchCairn: resume requests those fresh checks; it does not retry uncertain work.",
            "pause_pending": "Pause has been requested and no new action may start. The active operation is still running or awaiting its actual safe checkpoint receipt; it is not killed. Its outcome may still be unknown. Use PatchCairn: status to check progress and preserve its evidence.",
            "stopped": "This session is stopped and cannot resume or start another action. Keep its evidence and recovery files. Any active or uncertain earlier work still needs its actual outcome recorded; stopping does not prove it finished or undo its effects. PatchCairn: options reviews what remains; PatchCairn: help explains how to begin separate work.",
            "completed": "The planned work and its result checks are complete. This session is closed. Evidence and recovery files are kept until you separately choose cleanup. Use PatchCairn: help to choose a separate job if you want more work.",
        }
        if not state["operations"] and state["plan"] is None and any(item["kind"] == "assessment_finish" and item["resolved"] for item in state["pending"].values()):
            explanations["completed"] = "The assessment and its result checks are complete. Its findings and limitations are kept with the evidence, and this session recorded no maintenance action. The session is closed; any computer change needs a separate reviewed plan."
        if state["status"] == "held" and state["settings"]["timing"] == "scheduled" and state["schedule"] and state["schedule"].get("activation") is None and state["schedule"].get("ready_for_trigger") is True:
            explanations["held"] = "This session is waiting for its agreed scheduled time and matching trigger. No new collection or action may start before that activation. Your selected checkpoints and exact plan approvals still apply. Use PatchCairn: options to review the waiting choices."
        restart = next((operation for operation in state["operations"].values() if operation.get("restart_pending") and not operation.get("restart_verification") and operation["outcome"] in {None, "unknown"}), None)
        if restart and state["status"] not in {"stopped", "completed"}:
            decision = restart.get("restart_decision", {}).get("choice")
            lead = "The restart is deferred. " if decision == "defer" else "An owner-handled restart is authorized for this exact operation, no earlier than its agreed time. " if decision == "authorize" else "The installer finished and reported that a restart is required. "
            explanations[state["status"]] = lead + "Its original 3010 receipt is retained; the restart-dependent result and original behavior are still unverified. No restart or installer retry happens automatically. Any existing pause remains in place for subsequent work. Use PatchCairn: options or PatchCairn: resolve to review the exact restart decision and required observations."
        elif restart and state["status"] == "stopped":
            explanations["stopped"] += " For this retained 3010 operation only, you may explicitly defer or authorize the owner-handled restart needed to account for its unfinished effect. The session stays stopped and no new job action is created."
        mode = "Live-work session: selecting this mode does not collect evidence or approve computer changes. " if state["mode"] == "real" else "Practice session: its records do not establish that your computer was checked or changed. "
        message = JOBS[state["job"]]["label"] + " · " + STAGE_LABELS[state["stage"]] + ". " + mode + explanations[state["status"]]
        return self._response(state, "status", message, {"job": state["job"], "stage": state["stage"], "status": state["status"], "control": state["settings"]["control"], "timing": state["settings"]["timing"], "pending": self.pending_items(state), "operations": list(state["operations"].values())})

    def cost(self, session_id):
        state = self.read_session(session_id)
        totals, unknown, sources = {}, [], []
        actions = state["plan"]["document"]["actions"] if state["plan"] else []
        currencies = set()
        for metric in ("duration_minutes", "money", "bytes"):
            values = []
            for action in actions:
                evidence_id = action.get("estimate_evidence_id")
                facts = {}
                if evidence_id:
                    row = self.evidence_rows(state, [evidence_id], kinds={"inventory"})[0]
                    facts = row["facts"]
                    if evidence_id not in sources:
                        sources.append(evidence_id)
                value = facts.get(metric)
                if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or not math.isfinite(value):
                    break
                if metric == "money":
                    currency = facts.get("currency")
                    if not isinstance(currency, str) or not re.fullmatch("[A-Z]{3}", currency):
                        break
                    currencies.add(currency)
                values.append(value)
            if actions and len(values) == len(actions) and (metric != "money" or len(currencies) == 1):
                totals[metric] = sum(values)
            else:
                unknown.append(metric)
        if "money" in totals:
            totals["currency"] = next(iter(currencies))
        message = "These estimates use the current assessment and proposed work. "
        if "duration_minutes" in totals:
            message += "Estimated time: " + str(totals["duration_minutes"]) + " minutes. "
        if "money" in totals:
            message += "Estimated price: " + str(totals["money"]) + " " + totals["currency"] + ". "
        if "bytes" in totals:
            message += "Recorded data workload: " + str(totals["bytes"]) + " bytes. "
        if unknown:
            labels = {"duration_minutes": "time", "money": "price", "bytes": "data workload"}
            message += "Still unknown: " + ", ".join(labels[key] for key in unknown) + ". "
        message += "Missing numbers stay unknown. Data workload is the amount handled by the proposed steps; it does not tell you how much disk space will be freed. Assistant usage charges are not estimated here."
        return self._response(state, "cost", message, {"estimates": totals, "unknown": unknown, "evidence_ids": sources})

    def options(self, session_id):
        state = self.read_session(session_id)
        pending = self.pending_items(state)
        checkpoint = next((item for item in pending if item["kind"] == "checkpoint"), None)
        restart = next((item for item in pending if item["kind"] == "restart"), None)
        meaning = "Current job: " + JOBS[state["job"]]["label"] + ". Current step: " + STAGE_LABELS[state["stage"]].lower() + "."
        recommendation = "Review the agreed scope and current findings before deciding about the exact proposed work."
        choices = ["Review this step with PatchCairn: status", "Review scope, control and chosen stops with PatchCairn: settings", "Pause new actions with PatchCairn: pause, or end the session with PatchCairn: stop"]
        if state["status"] in {"stopped", "completed"}:
            recommendation = "This session is closed. Keep its evidence and recovery files; any uncertain earlier outcome still needs an actual observation." if state["status"] == "stopped" else "The result checks are complete. Keep retained evidence and recovery files until a separate cleanup decision."
            choices = ["Review recorded results with PatchCairn: status", "Use PatchCairn: help to choose separate work"]
            if state["status"] == "stopped" and pending:
                choices.insert(1, "Use PatchCairn: resolve to inspect an existing unfinished outcome; this does not reopen the session")
                if restart:
                    choices.insert(2, "Use PatchCairn: resolve to defer or authorize only the owner-handled restart needed to account for this retained operation; the session stays stopped")
        elif restart:
            meaning += " The installer has finished with restart required; its restart-dependent result remains unverified."
            recommendation = "Save your work and review the restart's effect on open applications. Choose defer, or authorize only the owner-handled restart for this exact operation; any existing pause remains for later work."
            choices = ["Use PatchCairn: resolve to defer this exact restart", "Use PatchCairn: resolve to authorize the owner-handled restart at its agreed time", "Keep the installer receipt and collect actual boot, target and original behavior checks afterward"]
        elif state["status"] == "held" and state["settings"]["timing"] == "scheduled" and state["schedule"] and state["schedule"].get("activation") is None and state["schedule"].get("ready_for_trigger") is True:
            recommendation = "Keep work waiting for the agreed time and its matching trigger; a previous start cannot activate this proposal."
            choices = ["Wait for the agreed time and matching trigger", "Ask to change the proposed time with a fresh owner decision", "Pause or stop the session if you no longer want the scheduled work"]
        elif state["status"] == "pause_pending":
            recommendation = "Keep new actions paused while the existing operation reaches its safe checkpoint and actual result is observed."
            choices = ["Check actual progress with PatchCairn: status", "Keep the pause in place and preserve evidence", "End the session with PatchCairn: stop; the existing operation still needs its actual outcome"]
        elif any(item["kind"] == "reconciliation" for item in pending):
            recommendation = "Establish the actual result before considering further work. An unknown result cannot be treated as success or retried."
            choices = ["Inspect the unfinished result with PatchCairn: resolve", "Have the coordinator collect fresh evidence of what actually happened", "Keep actions held, or end the session with PatchCairn: stop"]
        elif checkpoint:
            label = CHECKPOINT_LABELS[checkpoint["checkpoint"]]
            meaning += " Your chosen stop is " + label + "."
            recommendation = "Review " + label + ", then tell me whether to continue at this stop. Continuing a checkpoint does not approve unreviewed changes."
            choices = ["Inspect this chosen stop with PatchCairn: resolve", "After reviewing this choice, tell me whether to continue", "Keep work paused or use PatchCairn: stop to end it"]
        elif state["status"] == "paused":
            recommendation = "Keep the pause until fresh checks account for the current scope and every earlier operation."
            choices = ["Review actual results with PatchCairn: status", "Request fresh outcome checks with PatchCairn: resume", "Keep work paused, or end the session with PatchCairn: stop"]
        elif state["status"] == "active" and state["stage"] == "plan" and state["plan"] is None and not state["operations"] and not state["approval"] and not state["reviews"] and not state["standing_policy"] and state["scope_authorization"]:
            recommendation = "Review the assessment findings and remaining uncertainty. If you want no changes, ask to finish the assessment; its summary and coverage checks must be recorded first."
            choices.insert(0, "Ask to finish this assessment after reviewing its findings and limitations, without making changes")
        reversibility = "This session is closed and cannot resume. Stopping does not undo earlier effects; retained evidence and recovery files need a separate cleanup decision." if state["status"] in {"stopped", "completed"} else "Changing scope or settings requires a fresh plan and approval. Each action explains its own recovery limits; stopping does not undo earlier effects."
        drawbacks = "A restart closes applications and can lose unsaved work. Save your work and review the original plan's recovery limits first; the restart itself cannot be undone." if restart else "Changes may affect applications or data; the exact plan explains each risk. Missing evidence or permission holds the work."
        card = decision_card(meaning=meaning, benefits="A clear next step can reduce uncertainty while preserving your control.", drawbacks=drawbacks, cost=self.cost(session_id)["message"] + (" Restart downtime is unknown until the selected work is assessed." if restart else ""), reversibility=reversibility, recommendation=recommendation, options=choices)
        message = "\n\n".join(label.capitalize() + ": " + card[label] for label in ("meaning", "benefits", "drawbacks", "cost", "reversibility", "recommendation"))
        message += "\n\nChoices:\n" + "\n".join("- " + choice for choice in choices)
        actions = []
        if state["plan"]:
            for action in state["plan"]["document"]["actions"]:
                available = ["Review this recorded action and its actual result", "Keep evidence and recovery files"] if state["status"] in {"stopped", "completed"} else ["Review this exact action and the required checks before an approval decision", "Leave this action held", "Ask for a separately reviewed plan if the choice changes"]
                actions.append(decision_card(meaning=ACTION_LABELS[action["kind"]] + ": " + action["target"], benefits=action["benefit"], drawbacks=action["risk"], cost="An estimate may still be unknown; see PatchCairn: cost for time, price and data workload.", reversibility=action["reversibility"], recommendation="Review this action's stated result check: " + action["verification"], options=available))
            message += "\n\n" + ("Recorded plan: " if state["status"] in {"stopped", "completed"} else "Proposed changes: ") + state["plan"]["document"]["summary"]
            for action_card in actions:
                message += "\n\n" + "\n".join(label.capitalize() + ": " + action_card[label] for label in ("meaning", "benefits", "drawbacks", "cost", "reversibility", "recommendation"))
                message += "\nChoices:\n" + "\n".join("- " + choice for choice in action_card["options"])
        return self._response(state, "options", message, {"decision": card, "action_decisions": actions, "pending": self.pending_items(state), "commands": ["PatchCairn: " + c for c in COMMANDS]})

    def dispatch(self, session_id, command, *, expected_revision=None):
        parsed = parse_command(command)
        if not parsed["ok"]:
            return {"schema_version": SCHEMA_VERSION, "ok": False, "code": parsed["code"], "message": parsed["message"], "session_id": session_id, "revision": None, "data": {}}
        name, args = parsed["command"], parsed["arguments"]
        if name == "help":
            return self._response(self.read_session(session_id) if session_id else None, "help", initial_menu())
        if name == "start":
            if session_id:
                return self.status(session_id)
            if not args:
                return self._response(None, "menu", initial_menu())
            return self.create_session(job=args[0])
        if not session_id:
            raise WorkflowRefusal("Start or select a session first")
        if name == "status":
            return self.status(session_id)
        if name == "cost":
            return self.cost(session_id)
        if name == "options":
            return self.options(session_id)
        if name == "pause":
            return self.pause(session_id, expected_revision=expected_revision)
        if name == "stop":
            return self.stop(session_id, expected_revision=expected_revision)
        if name == "settings":
            if not args:
                state = self.read_session(session_id)
                return self._response(state, "settings", "Control and timing are independent. Changes invalidate old plans and approvals. Choose control=guided/automatic, timing=now/scheduled, or checkpoints=scope,findings,plan,before_action,after_action,finish.", {"settings": state["settings"]})
            values = dict(arg.split("=", 1) for arg in args)
            if "checkpoints" in values:
                values["checkpoints"] = values["checkpoints"].split(",") if values["checkpoints"] else []
            return self.setup(session_id, expected_revision=expected_revision, **values)
        if name == "resolve":
            return self.resolve(session_id, pending_id=args[0] if args else None)
        # Chat text alone cannot supply real fresh observations to resume.
        state = self.read_session(session_id)
        return self._response(state, "reconciliation_required", "Before resuming, the coordinator must collect fresh owned current-scope and actual-operation-outcome evidence. No changes have been resumed.", {"required": "resume(reconciliation_evidence_ids=[...])"})
