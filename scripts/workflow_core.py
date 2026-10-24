"""Deterministic PatchCairn conversation-session records. This module never executes a plan.

The caller is the trusted coordinator, not an untrusted JSON authority. An owner
quote records the actual human instruction supplied by that coordinator; it is
not cryptographic proof of a human and these helpers are not an OS sandbox.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import uuid
import zipfile
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
VERSION = 3
BACKEND = "patchcairn.workflow.python.v3"
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
POLICY_KINDS = {"update", "cleanup_quarantine", "backup_create"}
ROLES = {"compatibility_data", "evidence_security"}
OUTCOMES = {"succeeded", "failed", "partial", "unknown"}
EVIDENCE_KINDS = {"scope_confirmation", "inventory", "research", "candidates", "symptom", "hypotheses", "recovery_plan", "precondition", "outcome", "reconciliation", "verification", "recovery", "protected_consent", "review", "fixture"}
EVIDENCE_KINDS |= {"adapter_payload", "recovery_manifest", "restore_verification", "retention", "recovery_archive"}
ADAPTERS = {"storage.backup_create.v3": "backup_create", "storage.backup_restore.v3": "backup_restore", "storage.cleanup_quarantine.v3": "cleanup_quarantine", "storage.quarantine_restore.v3": "backup_restore", "storage.permanent_purge.v3": "permanent_purge", "fixture.assessment.v3": "assessment", "diagnostic.read_recipe.v3": "assessment", "system.reviewed_external.v3": ("update", "repair")}
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
CHECKPOINTS = {"scope", "findings", "plan", "before_action", "after_action", "finish"}
STATE_KEYS = {"schema_version", "session_id", "engine_id", "backend", "mode", "platform", "created_utc", "updated_utc", "creation_scope_sha256", "owner_id", "revision", "settings_revision", "job", "stage", "status", "settings", "scope_authorization", "evidence", "plan", "reviews", "approval", "irreversible_ack", "standing_policy", "operations", "pending", "schedule", "schedule_triggers", "last_reconciled_utc", "stop_reason"}


class WorkflowRefusal(ValueError):
    """A hold or invalid request; no operation was authorized."""


class PrivacyCapabilityHold(WorkflowRefusal):
    """The filesystem could not establish the required POSIX private storage."""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _time(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WorkflowRefusal("A UTC timestamp ending in Z is required")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise WorkflowRefusal("Invalid UTC timestamp") from error
    if result.utcoffset() != timedelta(0):
        raise WorkflowRefusal("Timestamp must be UTC")
    return result


def _fresh(value, *, after=None, seconds=900):
    observed, now = _time(value), _time(utc_now())
    if observed > now or now - observed > timedelta(seconds=seconds):
        raise WorkflowRefusal("Evidence is future-dated or stale; collect a fresh observation")
    if after and observed < _time(after):
        raise WorkflowRefusal("Evidence predates the operation or decision it must reconcile")


def encoded(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else encoded(value)).hexdigest()


def _text(value, name="text", limit=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise WorkflowRefusal("Invalid " + name)
    return value


def _id(value, name="identifier"):
    if not isinstance(value, str) or not ID.fullmatch(value) or value in {".", ".."}:
        raise WorkflowRefusal("Invalid " + name + "; paths are not accepted")
    return value


def _ids(value, name="identifiers", *, allow_empty=True):
    if not isinstance(value, list) or len(value) > 500 or (not allow_empty and not value):
        raise WorkflowRefusal("Invalid " + name)
    for item in value:
        _id(item, name)
    if len(set(value)) != len(value):
        raise WorkflowRefusal("Duplicate " + name)
    return value


def _fields(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise WorkflowRefusal("Unexpected or missing record fields")


def _json_data(value, depth=0):
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
    if isinstance(value, list) and len(value) <= 1000:
        for item in value:
            _json_data(item, depth + 1)
        return
    if isinstance(value, dict) and len(value) <= 100:
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in {"command", "commands", "execute", "eval", "approved", "authorization"}:
                raise WorkflowRefusal("Executable or self-authorizing evidence fields are not accepted")
            _json_data(item, depth + 1)
        return
    raise WorkflowRefusal("Evidence must be bounded JSON data")


def _assessment_source_key(source, kind):
    """Validate recorded selectors lexically; never inspect or resolve a host path."""
    if kind == "observation":
        return _id(source, "observation source")
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
    if windows and any(any(char in part for char in ':<>"|') or part.endswith((".", " ")) or re.fullmatch(r"(?i:con|prn|aux|nul|conin\$|conout\$|com[0-9]|lpt[0-9])(?:\..*)?", part) for part in parts):
        raise WorkflowRefusal("Ambiguous Windows assessment path")
    return source.casefold() if windows else source


def _assessment_access(value):
    fields = {"schema_version", "target", "operations", "local_content", "llm_content", "sensitive_exceptions"}
    _fields(value, fields, fields)
    if value["schema_version"] != "patchcairn.assessment.access.v1" or value["target"] not in ("whole_device", "selected_paths", "specific_problem"):
        raise WorkflowRefusal("Unknown assessment access descriptor")
    operations = _ids(value["operations"], "assessment operations", allow_empty=False)
    if set(operations) - {"metadata", "diagnosis", "content_read"}:
        raise WorkflowRefusal("Assessment access admits read-only operations only")
    selections = value["local_content"]
    if not isinstance(selections, list) or len(selections) > 30:
        raise WorkflowRefusal("Select at most thirty bounded local content observations")
    identifiers, identities = set(), set()
    for selection in selections:
        _fields(selection, {"id", "kind", "source", "selection"}, {"id", "kind", "source", "selection"})
        identifier = _id(selection["id"], "assessment selection")
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
    _fields(scope, {"roots", "purpose", "assessment"}, {"roots", "purpose"})
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


def _no_links(path):
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


def _posix_private_capability():
    if sys.platform != "darwin" and not sys.platform.startswith("linux"):
        raise PrivacyCapabilityHold("Native privacy admission for this POSIX platform is unavailable")
    if not hasattr(os, "geteuid") or not hasattr(os, "O_NOFOLLOW"):
        raise PrivacyCapabilityHold("POSIX private storage requires effective-owner and no-follow file support")


def _linux_private_filesystem(path):
    if os.name != "posix" or not sys.platform.startswith("linux"):
        return
    try:
        from linux_privacy import assert_native_private_filesystem, LinuxPrivacyHold
    except ImportError as error:
        raise PrivacyCapabilityHold("Native Linux private-filesystem admission is unavailable") from error
    try:
        assert_native_private_filesystem(path)
    except LinuxPrivacyHold as error:
        raise PrivacyCapabilityHold("Native Linux private storage is unavailable: " + error.code) from error


def _private_info(info, *, directory, created=False, native_acl_checked=False, path=None):
    if os.name != "posix":
        return
    _posix_private_capability()
    if sys.platform == "darwin" and not native_acl_checked:
        raise PrivacyCapabilityHold("Actual native macOS ACL admission is required; mode bits alone cannot authorize private engine storage")
    if sys.platform.startswith("linux"):
        if path is None:
            raise PrivacyCapabilityHold("Actual native Linux filesystem admission is required for private engine storage")
        _linux_private_filesystem(path)
        named = Path(path).lstat()
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise WorkflowRefusal("The admitted private path no longer identifies the opened inode")
    expected = 0o700 if directory else 0o600
    ordinary = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if not ordinary or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != expected:
        if created:
            raise PrivacyCapabilityHold("POSIX private storage is unavailable: the actual filesystem/umask did not establish current-owner " + oct(expected) + " permissions; no private record was authorized")
        raise WorkflowRefusal("Existing private engine storage must be current-owner ordinary " + ("directory 0700" if directory else "single-link file 0600") + "; unsafe permissions or ownership are held without adoption or chmod")


def _private_directory(path, *, create=False, parents=False, exist_ok=False):
    path = _no_links(path)
    if os.name == "nt" or sys.platform == "darwin":
        try:
            from private_workspace import ensure_private_directory, PrivateWorkspaceError
        except ImportError as error:
            raise PrivacyCapabilityHold("The supported native private namespace adapter is unavailable") from error
        try:
            return ensure_private_directory(path, create=create, parents=parents, exist_ok=exist_ok)
        except PrivateWorkspaceError as error:
            if sys.platform == "darwin" and "unavailable" in error.code:
                raise PrivacyCapabilityHold("Native macOS ACL private storage is unavailable: " + error.code) from error
            raise WorkflowRefusal("Native private engine namespace admission held: " + error.code) from error
    if os.name == "posix":
        _posix_private_capability()
        # Missing ordinary ancestors contain no private data. Check the exact
        # existing allocation filesystem before creating even the namespace.
        existing = next(item for item in (path, *path.parents) if item.exists())
        _linux_private_filesystem(existing)
    created = False
    if create:
        if parents:
            # Ancestors contain no private records and need not be owner-only.
            path.parent.mkdir(parents=True, exist_ok=True)
        _linux_private_filesystem(path.parent)
        try:
            os.mkdir(path, 0o700 if os.name == "posix" else 0o777)
            created = True
        except FileExistsError:
            if not exist_ok:
                raise
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise WorkflowRefusal("A private engine directory is missing; it will not be silently recreated") from error
    if not stat.S_ISDIR(info.st_mode):
        raise WorkflowRefusal("A private engine directory must be ordinary")
    _private_info(info, directory=True, created=created, path=path)
    return path


def _private_file(path):
    path = _no_links(path)
    if os.name == "nt" or sys.platform == "darwin":
        try:
            from private_workspace import ensure_private_file, PrivateWorkspaceError
        except ImportError as error:
            raise PrivacyCapabilityHold("The supported native private namespace adapter is unavailable") from error
        try:
            return ensure_private_file(path)
        except PrivateWorkspaceError as error:
            if sys.platform == "darwin" and "unavailable" in error.code:
                raise PrivacyCapabilityHold("Native macOS ACL private storage is unavailable: " + error.code) from error
            raise WorkflowRefusal("Native private engine record admission held: " + error.code) from error
    _private_info(path.lstat(), directory=False, path=path)


def _private_flags(access):
    if os.name == "posix":
        _posix_private_capability()
    return access | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)


def _write_private_new(path, data):
    path = _no_links(path)
    _private_directory(path.parent)
    if os.name == "nt" or sys.platform == "darwin":
        try:
            from private_workspace import write_private_new, PrivateWorkspaceError
        except ImportError as error:
            raise PrivacyCapabilityHold("The supported native private namespace adapter is unavailable") from error
        try:
            return write_private_new(path, data)
        except PrivateWorkspaceError as error:
            if sys.platform == "darwin" and "unavailable" in error.code:
                raise PrivacyCapabilityHold("Native macOS ACL private storage is unavailable: " + error.code) from error
            raise WorkflowRefusal("Native private engine record creation held: " + error.code) from error
    flags = _private_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as handle:
        _private_info(os.fstat(handle.fileno()), directory=False, created=True, path=path)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
        _private_info(os.fstat(handle.fileno()), directory=False, path=path)


def _read(path, max_bytes=16_000_000, *, private=False):
    _no_links(path)
    if private:
        _private_directory(path.parent)
        _private_file(path)
        handle = os.fdopen(os.open(path, _private_flags(os.O_RDONLY)), "rb")
    else:
        # Separately scoped recovery/installer artifacts have their own native
        # admission contract; engine-private modes must not be imposed on them.
        handle = path.open("rb")
    with handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
            raise WorkflowRefusal("Owned file is not a bounded ordinary single-link file")
        if private:
            if os.name == "nt" or sys.platform == "darwin":
                _private_file(path)
            _private_info(info, directory=False, native_acl_checked=sys.platform == "darwin", path=path)
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise WorkflowRefusal("Owned record exceeds size limit")
    return data


def _decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise WorkflowRefusal("Duplicate JSON keys are not accepted")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(WorkflowRefusal("Nonfinite JSON")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise WorkflowRefusal("Invalid owned JSON record") from error


def _atomic(path, data):
    _no_links(path)
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
    _id(owner_message_id, "owner message identifier")
    return {"owner_id": state["owner_id"], "quote": owner_quote, "message_id": owner_message_id, "source": source, "recorded_utc": utc_now(), "settings_revision": state["settings_revision"]}


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
    def __init__(self, root=None, *, work_relative="work/sessions", backend=BACKEND):
        if sys.version_info < (3, 12):
            raise WorkflowRefusal("Python 3.12 or newer is required")
        if backend != BACKEND:
            raise WorkflowRefusal("Foreign backend is not supported")
        self.root = _no_links(Path(root) if root else Path(__file__).absolute().parent.parent)
        rel = PurePosixPath(work_relative)
        if rel.is_absolute() or "\\" in work_relative or not rel.parts or rel.parts[0] != "work" or any(p in {".", ".."} or ":" in p for p in rel.parts) or len(rel.parts) < 2:
            raise WorkflowRefusal("Session storage must be a named child of repository work/")
        self.work = _no_links(self.root.joinpath(*rel.parts))
        _private_directory(self.work, create=True, parents=True, exist_ok=True)
        marker = self.work / "engine.json"
        if not marker.exists():
            if any(self.work.iterdir()):
                raise WorkflowRefusal("Engine creation marker is missing from nonempty storage; do not recreate or migrate it")
            try:
                _write_private_new(marker, encoded({"schema_version": VERSION, "backend": BACKEND, "engine_id": uuid.uuid4().hex}))
            except FileExistsError:
                pass
        self.marker = _decode(self._read_owned(marker))
        _fields(self.marker, {"schema_version", "backend", "engine_id"}, {"schema_version", "backend", "engine_id"})
        if self.marker["schema_version"] != VERSION or self.marker["backend"] != BACKEND:
            raise WorkflowRefusal("Missing or foreign engine marker; migration is not permitted")
        _id(self.marker["engine_id"])

    def _private_path(self, path):
        path = _no_links(path)
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
        return _read(self._private_path(path), max_bytes, private=True)

    def _directory(self, session_id):
        _id(session_id, "session identifier")
        _private_directory(self.work)
        _private_file(self.work / "engine.json")
        path = _no_links(self.work / session_id)
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
        except FileExistsError as error:
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
        except FileExistsError as error:
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
        _fields(state, STATE_KEYS, STATE_KEYS)
        if state["schema_version"] != VERSION or state["backend"] != BACKEND or state["engine_id"] != self.marker["engine_id"]:
            raise WorkflowRefusal("Foreign session version, backend or creation identity")
        _id(state["session_id"])
        _id(state["owner_id"])
        if state["mode"] not in {"fixture", "real"} or state["platform"] not in {"unknown", "windows", "linux", "macos"}:
            raise WorkflowRefusal("Invalid immutable session mode/platform")
        if state["job"] not in JOBS or state["stage"] not in JOBS[state["job"]]["stages"] or state["status"] not in {"active", "paused", "pause_pending", "held", "stopped", "completed", "awaiting_user"}:
            raise WorkflowRefusal("Invalid job, stage or status")
        for key in ("revision", "settings_revision"):
            if type(state[key]) is not int or state[key] < 0:
                raise WorkflowRefusal("Invalid revision")
        _time(state["created_utc"])
        _time(state["updated_utc"])
        settings = state["settings"]
        _fields(settings, {"scope", "control", "timing", "checkpoints"}, {"scope", "control", "timing", "checkpoints"})
        _scope(settings["scope"])
        if settings["control"] not in {"guided", "automatic"} or settings["timing"] not in {"now", "scheduled"} or not isinstance(settings["checkpoints"], list) or set(settings["checkpoints"]) - CHECKPOINTS or len(settings["checkpoints"]) != len(set(settings["checkpoints"])):
            raise WorkflowRefusal("Invalid session settings")
        if not isinstance(state["evidence"], dict) or not isinstance(state["operations"], dict) or not isinstance(state["reviews"], list) or not isinstance(state["pending"], dict) or not isinstance(state["schedule_triggers"], list):
            raise WorkflowRefusal("Invalid state collections")
        for evidence_id, row in state["evidence"].items():
            _id(evidence_id)
            _fields(row, {"evidence_id", "path", "sha256", "size", "kind", "scope", "settings_revision", "observed_utc", "registered_utc", "facts"}, {"evidence_id", "path", "sha256", "size", "kind", "scope", "settings_revision", "observed_utc", "registered_utc", "facts"})
            if row["evidence_id"] != evidence_id or row["path"] != "evidence/" + evidence_id + ".bin" or row["kind"] not in EVIDENCE_KINDS or not SHA.fullmatch(row["sha256"]) or type(row["size"]) is not int or row["size"] < 1:
                raise WorkflowRefusal("Invalid owned evidence record")
            _scope(row["scope"])
            _json_data(row["facts"])
            _time(row["observed_utc"])
            _time(row["registered_utc"])
        active = []
        for operation_id, op in state["operations"].items():
            _id(operation_id)
            fields = {"operation_id", "action_id", "plan_sha256", "settings_revision", "started_utc", "finished_utc", "outcome", "evidence_ids", "summary", "authorization", "pause_requested", "resolution", "mutating", "adapter_id"}
            _fields(op, fields | {"restart_pending", "restart_decision", "restart_verification"}, fields)
            for name in ("restart_pending", "restart_decision", "restart_verification"):
                if name in op:
                    if not isinstance(op[name], dict):
                        raise WorkflowRefusal("Restart lifecycle metadata must be a typed record")
                    _json_data(op[name])
            if op["operation_id"] != operation_id or op["outcome"] not in OUTCOMES | {None} or not SHA.fullmatch(op["plan_sha256"]):
                raise WorkflowRefusal("Invalid operation record")
            if type(op["mutating"]) is not bool or op["adapter_id"] not in ADAPTERS:
                raise WorkflowRefusal("Operation must retain its exact adapter and mutation classification")
            _id(op["action_id"])
            _ids(op["evidence_ids"])
            _time(op["started_utc"])
            if op["finished_utc"]:
                _time(op["finished_utc"])
            if op["outcome"] is None:
                active.append(operation_id)
        if len(active) > 1 or state["status"] == "pause_pending" and not active:
            raise WorkflowRefusal("Invalid active-operation invariant")
        if state["plan"]:
            plan = state["plan"]
            _fields(plan, {"document", "sha256", "settings_revision", "registered_utc"}, {"document", "sha256", "settings_revision", "registered_utc"})
            if digest(plan["document"]) != plan["sha256"] or plan["settings_revision"] != state["settings_revision"]:
                raise WorkflowRefusal("Plan hash or settings binding changed")
            self._validate_plan_document(state, plan["document"])
        if state["approval"] and (not state["plan"] or state["approval"]["plan_sha256"] != state["plan"]["sha256"] or state["approval"]["settings_revision"] != state["settings_revision"]):
            raise WorkflowRefusal("Approval is not bound to the current exact plan")
        return state

    def _load(self, session_id):
        directory = self._directory(session_id)
        try:
            marker = _decode(self._read_owned(directory / "creation.json"))
            bundle = _decode(self._read_owned(directory / "session.json"))
        except FileNotFoundError as error:
            raise WorkflowRefusal("Registered session state is missing; no silent reconstruction") from error
        _fields(bundle, {"state", "events"}, {"state", "events"})
        state = self._validate(bundle["state"])
        expected = {key: state[key] for key in ("session_id", "engine_id", "backend", "mode", "platform", "created_utc", "creation_scope_sha256", "owner_id", "job")}
        if marker != expected or state["session_id"] != session_id:
            raise WorkflowRefusal("Immutable session creation binding changed")
        if not isinstance(bundle["events"], list) or len(bundle["events"]) != state["revision"] + 1:
            raise WorkflowRefusal("Session event sequence is incomplete")
        previous = None
        for revision, event in enumerate(bundle["events"]):
            _fields(event, {"revision", "at", "type", "details", "state_sha256", "previous", "sha256"}, {"revision", "at", "type", "details", "state_sha256", "previous", "sha256"})
            bare = {key: value for key, value in event.items() if key != "sha256"}
            if event["revision"] != revision or event["previous"] != previous or event["sha256"] != digest(bare):
                raise WorkflowRefusal("Session event chain changed")
            _time(event["at"])
            previous = event["sha256"]
        if bundle["events"][-1]["state_sha256"] != digest(state):
            raise WorkflowRefusal("State does not match its committed event")
        for row in state["evidence"].values():
            content = self._read_owned(directory / row["path"])
            if len(content) != row["size"] or digest(content) != row["sha256"]:
                raise WorkflowRefusal("Owned evidence has changed")
        return bundle

    def _commit(self, directory, state, events, event_type, details):
        self._validate(state)
        event = {"revision": state["revision"], "at": state["updated_utc"], "type": event_type, "details": details, "state_sha256": digest(state), "previous": events[-1]["sha256"] if events else None}
        event["sha256"] = digest(event)
        # State and its entire chained event journal share one atomic transaction.
        data = encoded({"state": state, "events": events + [event]})
        if len(data) > 16_000_000:
            raise WorkflowRefusal("Session journal reached its bounded size; preserve it and start a separately scoped session")
        _atomic(self._private_path(directory / "session.json"), data)

    def _change(self, session_id, event_type, mutate, expected_revision=None):
        with self._lock(session_id):
            bundle = self._load(session_id)
            current = bundle["state"]
            if expected_revision is not None and (type(expected_revision) is not int or expected_revision != current["revision"]):
                raise WorkflowRefusal("Session changed; read the current revision before writing")
            candidate = copy.deepcopy(current)
            data, message = mutate(candidate)
            candidate["revision"] += 1
            candidate["updated_utc"] = utc_now()
            changes = {key: value for key, value in candidate.items() if key not in {"revision", "updated_utc"} and value != current[key]}
            self._commit(self._directory(session_id), candidate, bundle["events"], event_type, {"settings_revision": candidate["settings_revision"], "changes": changes})
        return self._response(candidate, event_type, message, data)

    @staticmethod
    def _response(state, code, message, data=None):
        if state and code not in {"created", "help", "status", "options"}:
            message = JOBS[state["job"]]["label"] + " · " + STAGE_LABELS[state["stage"]] + ". " + message
        return {"schema_version": VERSION, "ok": True, "code": code, "message": message, "session_id": state["session_id"] if state else None, "revision": state["revision"] if state else None, "data": copy.deepcopy(data or {})}

    def create_session(self, *, job="security_updates", control="guided", timing="now", mode="fixture", platform="unknown", scope=None, checkpoints=None, owner_id="owner"):
        if job not in JOBS:
            raise WorkflowRefusal("Choose one supported job")
        _id(owner_id)
        selected = _scope(scope or {"roots": [], "purpose": "Assessment; scope still needs the owner's decision"})
        now = utc_now()
        session_id = "session-" + uuid.uuid4().hex
        state = {"schema_version": VERSION, "session_id": session_id, "engine_id": self.marker["engine_id"], "backend": BACKEND, "mode": mode, "platform": platform, "created_utc": now, "updated_utc": now, "creation_scope_sha256": digest(selected), "owner_id": owner_id, "revision": 0, "settings_revision": 0, "job": job, "stage": "scope", "status": "active" if timing == "now" else "awaiting_user", "settings": {"scope": selected, "control": control, "timing": timing, "checkpoints": list(checkpoints if checkpoints is not None else ["scope", "findings", "plan", "before_action", "finish"])}, "scope_authorization": None, "evidence": {}, "plan": None, "reviews": [], "approval": None, "irreversible_ack": None, "standing_policy": None, "operations": {}, "pending": {}, "schedule": None, "schedule_triggers": [], "last_reconciled_utc": None, "stop_reason": None}
        self._validate(state)
        _private_directory(self.work)
        _private_file(self.work / "engine.json")
        directory = self.work / session_id
        _private_directory(directory, create=True)
        _private_directory(directory / "evidence", create=True)
        marker = {key: state[key] for key in ("session_id", "engine_id", "backend", "mode", "platform", "created_utc", "creation_scope_sha256", "owner_id", "job")}
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
        _id(evidence_id, "evidence identifier")
        if not isinstance(content, bytes) or not 0 < len(content) <= 8_000_000 or kind not in EVIDENCE_KINDS:
            raise WorkflowRefusal("Evidence must be bounded bytes with a supported kind")
        _scope(scope)
        facts = copy.deepcopy(facts or {})
        if not isinstance(facts, dict):
            raise WorkflowRefusal("Evidence facts must be a mapping")
        _json_data(facts)
        observed = observed_utc or utc_now()
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
            row = {"evidence_id": evidence_id, "path": "evidence/" + evidence_id + ".bin", "sha256": digest(content), "size": len(content), "kind": kind, "scope": copy.deepcopy(scope), "settings_revision": state["settings_revision"], "observed_utc": observed, "registered_utc": utc_now(), "facts": facts}
            target = self._directory(session_id) / row["path"]
            if target.exists():
                raise WorkflowRefusal("An unregistered file occupies the evidence name; preserve it for inspection")
            _write_private_new(self._private_path(target), content)
            state["evidence"][evidence_id] = row
            return row, "Selected evidence is saved with its exact content hash, scope and observation time."
        return self._change(session_id, "evidence_registered", mutate, expected_revision)

    def _evidence(self, state, evidence_ids, *, kinds=None, after=None, seconds=86400, allow_empty=False):
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
        _fields(plan, {"plan_id", "summary", "evidence_ids", "actions"}, {"plan_id", "summary", "evidence_ids", "actions"})
        _id(plan["plan_id"])
        _text(plan["summary"], "plan explanation")
        _ids(plan["evidence_ids"], allow_empty=False)
        if not isinstance(plan["actions"], list) or not 0 < len(plan["actions"]) <= 100:
            raise WorkflowRefusal("A plan needs a bounded concrete action list")
        seen = set()
        for action in plan["actions"]:
            fields = {"action_id", "kind", "target", "benefit", "risk", "reversibility", "verification", "mutating", "requires_os_consent", "requires_recovery", "recovery_evidence_ids", "estimate_evidence_id", "adapter_id", "adapter_payload_evidence_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_evidence_id", "target_inventory_sha256"}
            required = fields - {"estimate_evidence_id"}
            _fields(action, fields, required)
            _id(action["action_id"])
            if action["action_id"] in seen or action["kind"] not in KINDS:
                raise WorkflowRefusal("Action identifiers must be unique and kinds supported")
            seen.add(action["action_id"])
            for field in ("target", "benefit", "risk", "reversibility", "verification"):
                _text(action[field], "action " + field, 2000)
            if any(type(action[key]) is not bool for key in ("mutating", "requires_os_consent", "requires_recovery")):
                raise WorkflowRefusal("Action safety flags must be explicit booleans")
            if action["adapter_id"] == "system.reviewed_external.v3" and action["requires_os_consent"] is not True:
                raise WorkflowRefusal("Every fixed local external installer requires actual owner-handled protected-system consent")
            if action["kind"] != "assessment" and not action["mutating"]:
                raise WorkflowRefusal("Change kinds cannot be disguised as read-only actions")
            if not isinstance(action["adapter_id"], str):
                raise WorkflowRefusal("Adapter identifier must name a fixed supported recipe")
            supported = ADAPTERS.get(action["adapter_id"], ())
            if isinstance(supported, str):
                supported = (supported,)
            if action["kind"] not in supported or action["adapter_id"].startswith("fixture.") and state["mode"] != "fixture":
                raise WorkflowRefusal("This action has no fixed supported adapter for this kind and mode")
            for field in ("adapter_payload_evidence_id", "target_inventory_evidence_id"):
                _id(action[field])
            for field in ("adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256"):
                if not isinstance(action[field], str) or not SHA.fullmatch(action[field]):
                    raise WorkflowRefusal("Exact adapter payload, lower-level plan and target inventory hashes are required")
            if action["kind"] in {"backup_restore", "permanent_purge", "repair", "firmware", "os_transition"} and not action["requires_recovery"]:
                raise WorkflowRefusal("This action needs verified recovery evidence or an explicit supported recovery design")
            _ids(action["recovery_evidence_ids"])
            if action["requires_recovery"] and not action["recovery_evidence_ids"]:
                raise WorkflowRefusal("Required recovery has not been provided")
            if "estimate_evidence_id" in action:
                _id(action["estimate_evidence_id"])

    def _action_binding(self, state, action):
        payload_row = self._evidence(state, [action["adapter_payload_evidence_id"]], kinds={"adapter_payload"})[0]
        inventory_row = self._evidence(state, [action["target_inventory_evidence_id"]], kinds={"inventory"})[0]
        if payload_row["sha256"] != action["adapter_payload_sha256"] or inventory_row["sha256"] != action["target_inventory_sha256"]:
            raise WorkflowRefusal("Exact reviewed adapter payload or target inventory has changed")
        directory = self._directory(state["session_id"])
        payload = _decode(self._read_owned(directory / payload_row["path"]))
        inventory = _decode(self._read_owned(directory / inventory_row["path"]))
        if action["adapter_id"] == "fixture.assessment.v3":
            _fields(payload, {"schema_version", "operation", "fixture_plan", "fixture_plan_sha256", "inventory_sha256"}, {"schema_version", "operation", "fixture_plan", "fixture_plan_sha256", "inventory_sha256"})
            if payload["schema_version"] != "patchcairn.fixture.adapter.v3" or payload["operation"] != action["adapter_id"] or digest(payload["fixture_plan"]) != action["adapter_plan_sha256"] or payload["fixture_plan_sha256"] != action["adapter_plan_sha256"] or payload["inventory_sha256"] != digest(inventory):
                raise WorkflowRefusal("Fictional adapter payload does not bind its exact plan and inventory")
        elif action["adapter_id"] == "diagnostic.read_recipe.v3":
            _fields(payload, {"schema_version", "operation", "request", "request_sha256", "inventory_sha256"}, {"schema_version", "operation", "request", "request_sha256", "inventory_sha256"})
            if payload["schema_version"] != "patchcairn.diagnostic.adapter.v3" or payload["operation"] != action["adapter_id"] or payload["request_sha256"] != action["adapter_plan_sha256"] or digest(payload["request"]) != action["adapter_plan_sha256"] or payload["inventory_sha256"] != digest(inventory) or payload["request"] != inventory:
                raise WorkflowRefusal("Diagnostic request does not match the exact reviewed selected recipe and inventory")
            _json_data(payload["request"])
            try:
                from diagnostic_core import validate_request, DiagnosticRefusal
                request = validate_request(payload["request"])
            except ImportError as error:
                raise WorkflowRefusal("The supported diagnostic validator is unavailable") from error
            except DiagnosticRefusal as error:
                raise WorkflowRefusal("Diagnostic request is not a supported bounded recipe") from error
            if request["mode"] != state["mode"] or request["platform"] != state["platform"]:
                raise WorkflowRefusal("Diagnostic request belongs to a different creation mode/platform")
        elif action["adapter_id"] == "system.reviewed_external.v3":
            _fields(payload, {"schema_version", "operation", "external_plan", "external_plan_sha256", "inventory_sha256"}, {"schema_version", "operation", "external_plan", "external_plan_sha256", "inventory_sha256"})
            if payload["schema_version"] != "patchcairn.external.adapter.v3" or payload["operation"] != action["adapter_id"] or payload["external_plan_sha256"] != action["adapter_plan_sha256"] or digest(payload["external_plan"]) != action["adapter_plan_sha256"] or payload["inventory_sha256"] != digest(inventory):
                raise WorkflowRefusal("External handoff does not match its exact reviewed plan and inventory")
            self._external_plan(state, payload["external_plan"], inventory)
            if payload["external_plan"]["kind"] != action["kind"]:
                raise WorkflowRefusal("External handoff kind differs from the exact engine action")
            if action["requires_os_consent"] is not True:
                raise WorkflowRefusal("A local installer handoff requires actual owner-handled protected-system consent")
        else:
            fields = {"schema_version", "operation", "storage_plan", "storage_plan_sha256", "output_root", "mode", "protected_roots"}
            _fields(payload, fields | {"restore_probe_destination"}, fields)
            if payload["schema_version"] != "patchcairn.storage.adapter.v3" or payload["operation"] != action["adapter_id"] or payload["mode"] != state["mode"] or not isinstance(payload["storage_plan"], dict) or digest(payload["storage_plan"]) != action["adapter_plan_sha256"] or payload["storage_plan_sha256"] != action["adapter_plan_sha256"]:
                raise WorkflowRefusal("Storage adapter payload does not match the exact reviewed lower-level plan")
            if not isinstance(payload["protected_roots"], list) or len(payload["protected_roots"]) > 30:
                raise WorkflowRefusal("Storage adapter needs bounded explicit protected roots")
            for protected in payload["protected_roots"]:
                if not isinstance(protected, str) or not Path(protected).is_absolute() or ".." in Path(protected).parts:
                    raise WorkflowRefusal("Protected roots must be exact absolute paths")
            _json_data(payload["storage_plan"])
            expected_kind = {"storage.backup_create.v3": "backup", "storage.backup_restore.v3": "restore", "storage.cleanup_quarantine.v3": "quarantine", "storage.quarantine_restore.v3": "quarantine_restore", "storage.permanent_purge.v3": "purge"}[action["adapter_id"]]
            if payload["storage_plan"].get("schema_version") != "patchcairn.storage.v3" or payload["storage_plan"].get("kind") != expected_kind:
                raise WorkflowRefusal("Storage plan kind/version differs from the fixed reviewed adapter")
            output_value = Path(_text(payload["output_root"], "owned storage output root", 2000))
            if not output_value.is_absolute():
                raise WorkflowRefusal("Storage output root must be an exact absolute owned work path")
            output = _no_links(output_value)
            try:
                output.relative_to(self.root / "work")
            except ValueError as error:
                raise WorkflowRefusal("Adapter outputs must stay inside this repository's owned work tree") from error
            probe_value = payload.get("restore_probe_destination")
            if probe_value is not None:
                if action["adapter_id"] != "storage.backup_create.v3" or not isinstance(probe_value, str) or not Path(probe_value).is_absolute():
                    raise WorkflowRefusal("Only an explicitly reviewed backup action can include an exact owned restore-probe destination")
                probe = _no_links(Path(probe_value))
                try:
                    probe.relative_to(output)
                except ValueError as error:
                    raise WorkflowRefusal("Restore probe must stay under the exact owned backup output root") from error
                if probe.exists():
                    raise WorkflowRefusal("The reviewed restore-probe destination is no longer absent")
            source_inventory = payload["storage_plan"].get("inventory", payload["storage_plan"].get("records", payload["storage_plan"].get("receipt")))
            if source_inventory is None or digest(source_inventory) != digest(inventory):
                raise WorkflowRefusal("Adapter target inventory is not the exact owned inventory/receipt reviewed in the lower-level plan")
        return payload

    def _external_plan(self, state, plan, inventory):
        fields = {"schema_version", "kind", "platform", "mode", "catalog_id", "official_tool", "argv", "targets", "target_versions", "target_identities", "sources", "provenance_evidence_ids", "compatibility_evidence_ids", "recovery_plan", "recovery_plan_sha256", "verification_plan", "verification_plan_sha256", "scope"}
        _fields(plan, fields, fields)
        if plan["schema_version"] != "patchcairn.external.plan.v3" or plan["kind"] not in {"update", "repair"} or plan["platform"] != state["platform"] or plan["mode"] != state["mode"] or plan["scope"] != state["settings"]["scope"]:
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
            _fields(identity, fields, fields)
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
        self._evidence(state, plan["provenance_evidence_ids"], kinds={"research", "review", "inventory"})
        self._evidence(state, plan["compatibility_evidence_ids"], kinds={"research", "review", "inventory"})
        recovery = plan["recovery_plan"]
        _fields(recovery, {"schema_version", "strategy", "evidence_ids", "limits"}, {"schema_version", "strategy", "evidence_ids", "limits"})
        if recovery["schema_version"] != "patchcairn.external.recovery.v3" or recovery["strategy"] not in {"verified_backup", "publisher_rollback", "no_verified_rollback"} or digest(recovery) != plan["recovery_plan_sha256"]:
            raise WorkflowRefusal("External recovery plan and exact limits must be reviewed and hash-bound")
        _text(recovery["limits"], "recovery limits", 2000)
        self._evidence(state, recovery["evidence_ids"], allow_empty=recovery["strategy"] == "no_verified_rollback")
        if recovery["strategy"] == "verified_backup":
            self._recovery(state, recovery["evidence_ids"])
        verification = plan["verification_plan"]
        _fields(verification, {"schema_version", "original_success_condition", "checks"}, {"schema_version", "original_success_condition", "checks"})
        if verification["schema_version"] != "patchcairn.external.verification.v3" or digest(verification) != plan["verification_plan_sha256"] or not isinstance(verification["checks"], list) or not 1 <= len(verification["checks"]) <= 20:
            raise WorkflowRefusal("An exact behavior verification plan is required for the external handoff")
        _text(verification["original_success_condition"], "original success condition", 2000)
        seen = set()
        for check in verification["checks"]:
            _fields(check, {"check_id", "description", "expected_result"}, {"check_id", "description", "expected_result"})
            _id(check["check_id"])
            if check["check_id"] in seen:
                raise WorkflowRefusal("Verification check IDs must be unique")
            seen.add(check["check_id"])
            _text(check["description"], "verification check", 2000)
            _text(check["expected_result"], "expected verification result", 2000)

    def _external_preflight(self, state, action, rows):
        payload = self._action_binding(state, action)
        external = payload["external_plan"]
        fields = {"schema_version", "action_id", "plan_sha256", "external_plan_sha256", "mode", "platform", "observed_utc", "targets"}
        for row in rows:
            proof = _decode(self._read_owned(self._directory(state["session_id"]) / row["path"]))
            _fields(proof, fields, fields)
            if proof["schema_version"] != "patchcairn.external.preflight.v3" or proof["action_id"] != action["action_id"] or proof["plan_sha256"] != state["plan"]["sha256"] or proof["external_plan_sha256"] != action["adapter_plan_sha256"] or proof["mode"] != state["mode"] or proof["platform"] != state["platform"] or not isinstance(proof["targets"], dict) or set(proof["targets"]) != set(external["targets"]):
                raise WorkflowRefusal("An external handoff requires an actual exact current artifact/provenance preflight before the mutation ticket")
            _fresh(proof["observed_utc"], after=state["plan"]["registered_utc"], seconds=900)
            for target, observed in proof["targets"].items():
                identity = external["target_identities"][target]
                expected = {**identity, "version": external["target_versions"][target]}
                additional = {"artifact_path", "artifact_record", "signature_evidence_id", "metadata_evidence_id"}
                _fields(observed, set(expected) | additional, set(expected) | additional)
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
                try:
                    from storage_ops import _protected
                    from scoped_fs import ScopedRoot, ScopedFSError
                    if _protected(relative) or artifact.suffix.casefold() not in {".msi", ".pkg", ".deb"}:
                        raise WorkflowRefusal("Known private-store names and unsupported external artifact formats stay unopened")
                    with ScopedRoot(str(artifact.parent), quiet_workspace=True) as pinned:
                        actual = pinned.inspect(artifact.name, hash_file=True, max_bytes=64 * 1024 * 1024)
                    if actual.get("kind") != "file" or actual.get("sha256") != identity["content_sha256"] or actual != observed["artifact_record"]:
                        raise WorkflowRefusal("The actual selected official artifact bytes differ from the approved content hash")
                except ImportError as error:
                    raise WorkflowRefusal("The supported bounded native artifact verifier is unavailable") from error
                except ScopedFSError as error:
                    raise WorkflowRefusal("Actual native external artifact verification refused; no weaker fallback") from error
                signature_row = self._evidence(state, [observed["signature_evidence_id"]], kinds={"research", "precondition"}, after=state["plan"]["registered_utc"], seconds=900)[0]
                signature = _decode(self._read_owned(self._directory(state["session_id"]) / signature_row["path"]))
                signature_fields = {"schema_version", "mode", "platform", "artifact_sha256", "publisher", "status", "source_id", "method", "observed_utc"}
                _fields(signature, signature_fields, signature_fields)
                method = {"windows": "windows.authenticode", "macos": "apple.pkgutil_check_signature", "linux": "distribution.signed_metadata"}[state["platform"]]
                if signature["schema_version"] != "patchcairn.publisher.signature.v3" or signature["mode"] != state["mode"] or signature["platform"] != state["platform"] or signature["artifact_sha256"] != identity["content_sha256"] or signature["publisher"] != identity["publisher"] or signature["source_id"] != identity["source_id"] or signature["method"] != method or signature["status"] != "verified":
                    raise WorkflowRefusal("A current actual publisher/signature verification receipt for the exact artifact and source is required")
                _fresh(signature["observed_utc"], after=state["plan"]["registered_utc"], seconds=900)
                metadata_row = self._evidence(state, [observed["metadata_evidence_id"]], kinds={"research", "precondition"}, after=state["plan"]["registered_utc"], seconds=900)[0]
                metadata = _decode(self._read_owned(self._directory(state["session_id"]) / metadata_row["path"]))
                metadata_fields = {"schema_version", "mode", "platform", "artifact_sha256", "target_id", "version", "channel", "architecture", "installation_scope", "publisher", "source_id", "observed_utc"}
                _fields(metadata, metadata_fields, metadata_fields)
                if metadata["schema_version"] != "patchcairn.installer.metadata.v3" or metadata["mode"] != state["mode"] or metadata["platform"] != state["platform"] or metadata["artifact_sha256"] != identity["content_sha256"] or metadata["target_id"] != target or any(metadata[key] != value for key, value in expected.items() if key != "content_sha256"):
                    raise WorkflowRefusal("Actual package metadata does not establish the approved version, variant, publisher and source for this exact artifact")
                _fresh(metadata["observed_utc"], after=state["plan"]["registered_utc"], seconds=900)

    def _work_artifact(self, path, expected_sha256, *, output_root=None, record=None, quarantined_source=False, max_bytes=64 * 1024 * 1024):
        if type(max_bytes) is not int or not 0 < max_bytes <= 64 * 1024 * 1024:
            raise WorkflowRefusal("Owned artifact read limits cannot exceed the existing recovery cap")
        value = Path(_text(path, "owned recovery artifact path", 2000))
        if not value.is_absolute():
            raise WorkflowRefusal("Recovery artifact paths must be exact absolute owned work paths")
        value = _no_links(value)
        if output_root is None or not Path(output_root).is_absolute():
            raise WorkflowRefusal("Recovery bytes require their exact owned private output root")
        output_root = _no_links(Path(output_root))
        try:
            output_root.relative_to(self.root / "work")
            relative = value.relative_to(output_root)
        except ValueError as error:
            raise WorkflowRefusal("Recovery artifacts must remain in the exact owned work output root") from error
        current = _private_directory(output_root)
        for part in relative.parts[:-1]:
            current = _private_directory(current / part)
        # Quarantine preserves POSIX source modes; its checked private parents
        # protect those source bytes. Native Windows files still require DACL
        # admission. All created recovery records/probes require private files.
        private_file = os.name != "posix" or not quarantined_source
        if private_file:
            _private_file(value)
        else:
            _linux_private_filesystem(value)
        data = _read(value, max_bytes, private=private_file)
        if not isinstance(expected_sha256, str) or digest(data) != expected_sha256:
            raise WorkflowRefusal("Required recovery artifact bytes changed")
        if record is not None:
            if not isinstance(record, dict) or record.get("kind") != "file" or record.get("sha256") != expected_sha256 or output_root is not None and record.get("relative_path") != value.relative_to(output_root).as_posix():
                raise WorkflowRefusal("Recovery native identity record is missing or mismatched")
            if output_root is None:
                raise WorkflowRefusal("Native recovery records require an exact owned output root")
            try:
                from scoped_fs import ScopedRoot, ScopedFSError
                with ScopedRoot(str(output_root), quiet_workspace=True) as pinned:
                    observed = pinned.inspect(record["relative_path"], hash_file=True, max_bytes=max_bytes)
                    if observed != record:
                        raise WorkflowRefusal("Required recovery artifact native identity or freshness changed")
                    observed_data = pinned.read_bytes(record["relative_path"], expected=record, max_bytes=max_bytes)
                if observed_data != data or digest(observed_data) != expected_sha256:
                    raise WorkflowRefusal("Recovery content changed between native admission and read")
            except ImportError as error:
                raise WorkflowRefusal("The supported native recovery identity adapter is unavailable") from error
            except ScopedFSError as error:
                raise WorkflowRefusal("Native recovery identity or content reinspection refused; no weaker fallback") from error
        return data

    def _retention(self, state, evidence_id, artifacts):
        row = self._evidence(state, [evidence_id], kinds={"retention"})[0]
        retention = _decode(self._read_owned(self._directory(state["session_id"]) / row["path"]))
        _fields(retention, {"schema_version", "session_id", "required", "artifacts"}, {"schema_version", "session_id", "required", "artifacts"})
        if retention["schema_version"] != "patchcairn.recovery.retention.v3" or retention["session_id"] != state["session_id"] or retention["required"] is not True or retention["artifacts"] != artifacts:
            raise WorkflowRefusal("A current exact retention record must protect every actual required recovery artifact")

    def _quarantine_recovery(self, state, binding, action):
        fields = {"schema_version", "output_root", "quarantine_receipt", "restore_plan", "restore_plan_sha256", "retention_evidence_id"}
        _fields(binding, fields, fields)
        if not action or action["adapter_id"] != "storage.quarantine_restore.v3" or binding["restore_plan_sha256"] != action["adapter_plan_sha256"] or digest(binding["restore_plan"]) != action["adapter_plan_sha256"]:
            raise WorkflowRefusal("Quarantine recovery applies only to its exact reviewed quarantine-restore action, never to a generic repair or purge")
        payload = self._action_binding(state, action)
        if payload["output_root"] != binding["output_root"] or payload["storage_plan"] != binding["restore_plan"] or payload["storage_plan"].get("receipt") != binding["quarantine_receipt"]:
            raise WorkflowRefusal("Quarantine recovery differs from the exact approved native restore mapping")
        output = _no_links(Path(binding["output_root"]))
        try:
            from storage_ops import StorageService, StorageRefusal
            from scoped_fs import ScopedFSError
            storage = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=payload["protected_roots"])
            storage.check_preconditions(plan=binding["restore_plan"], expected_plan_sha256=action["adapter_plan_sha256"])
        except ImportError as error:
            raise WorkflowRefusal("The supported native quarantine-restore verifier is unavailable") from error
        except (StorageRefusal, ScopedFSError) as error:
            raise WorkflowRefusal("Native quarantine recovery identity, provenance, original mapping or no-overwrite preconditions refused") from error
        receipt = binding["quarantine_receipt"]
        attempt_path = output / receipt["attempt"]
        outcome_path = output / ("outcome-quarantine-" + receipt["plan_sha256"] + ".json")
        attempt_bytes = _read(attempt_path, 64 * 1024 * 1024, private=True)
        retained = {str(attempt_path): digest(attempt_bytes), str(outcome_path): digest(receipt)}
        self._work_artifact(str(outcome_path), digest(receipt), output_root=output)
        for row in receipt["records"]:
            record = row["quarantine_record"]
            target = output / record["relative_path"]
            self._work_artifact(str(target), record["sha256"], output_root=output, record=record, quarantined_source=True)
            retained[str(target)] = record["sha256"]
        self._retention(state, binding["retention_evidence_id"], retained)

    def _recovery(self, state, evidence_ids, *, action=None):
        purge_payload = None
        if action and action["adapter_id"] == "storage.permanent_purge.v3":
            purge_payload = self._action_binding(state, action)
            original = purge_payload["storage_plan"].get("receipt")
            if not isinstance(original, dict) or original.get("schema_version") != "patchcairn.storage.v3" or original.get("kind") != "quarantine_receipt":
                raise WorkflowRefusal("Purge recovery requires the exact original typed quarantine receipt")
            if original.get("recovery_required") is not True or not isinstance(original.get("recovery_backup"), dict) or not isinstance(original.get("recovery_verification"), dict):
                raise WorkflowRefusal("Integrated purge of originally unbacked quarantine is held; an unrelated backup cannot supply its recovery proof")
        for row in self._evidence(state, evidence_ids, kinds={"recovery"}):
            binding = _decode(self._read_owned(self._directory(state["session_id"]) / row["path"]))
            if isinstance(binding, dict) and binding.get("schema_version") == "patchcairn.quarantine.recovery.v3":
                self._quarantine_recovery(state, binding, action)
                continue
            _fields(binding, {"schema_version", "output_root", "backup_receipt", "restore_receipt", "retention_evidence_id"}, {"schema_version", "output_root", "backup_receipt", "restore_receipt", "retention_evidence_id"})
            if binding["schema_version"] != "patchcairn.recovery.binding.v3":
                raise WorkflowRefusal("An exact backup/restore/retention recovery binding is required")
            backup, restore = binding["backup_receipt"], binding["restore_receipt"]
            if purge_payload and (binding["output_root"] != purge_payload["output_root"] or backup != original["recovery_backup"] or restore != original["recovery_verification"]):
                raise WorkflowRefusal("Purge recovery must match the exact original quarantine backup, restore verification and output root")
            if not isinstance(backup, dict) or not isinstance(restore, dict) or backup.get("schema_version") != "patchcairn.storage.v3" or backup.get("kind") != "backup_receipt" or backup.get("required_recovery") is not True or restore.get("kind") != "restore_receipt" or restore.get("schema_version") != "patchcairn.storage.v3":
                raise WorkflowRefusal("Required recovery needs actual typed backup and completed restoration receipts")
            root_value = Path(_text(binding["output_root"], "recovery output root", 2000))
            if not root_value.is_absolute():
                raise WorkflowRefusal("Recovery output root must be an exact absolute owned work path")
            output_root = _no_links(root_value)
            archive = self._work_artifact(backup.get("archive"), backup.get("archive_sha256"), output_root=output_root, record=backup.get("archive_record"))
            manifest_data = self._work_artifact(backup.get("manifest"), backup.get("manifest_sha256"), output_root=output_root, record=backup.get("manifest_record"))
            manifest = _decode(manifest_data)
            if manifest.get("schema_version") != "patchcairn.storage.v3" or manifest.get("kind") != "backup_manifest" or manifest.get("required_recovery") is not True or manifest.get("archive_sha256") != digest(archive) or manifest.get("archive_bytes") != len(archive) or manifest.get("plan_sha256") != backup.get("plan_sha256"):
                raise WorkflowRefusal("Recovery manifest does not bind the actual archive and original backup plan")
            if purge_payload:
                originals, backed_files = original.get("records"), manifest.get("files")
                if not isinstance(manifest.get("source_roots"), list) or not manifest["source_roots"] or manifest["source_roots"] != original.get("source_roots") or not isinstance(originals, list) or not originals or not isinstance(backed_files, list) or not backed_files:
                    raise WorkflowRefusal("Recovery must cover the exact quarantined originals and selected source roots")
                def covered_key(file):
                    if not isinstance(file, dict) or any(not isinstance(file.get(key), str) or not file[key] for key in ("root_id", "relative_path", "sha256")) or not SHA.fullmatch(file["sha256"]) or type(file.get("size")) is not int or file["size"] < 0:
                        raise WorkflowRefusal("Purge recovery requires exact bounded original/manifest content mappings")
                    return file["root_id"], file["relative_path"], file["sha256"], file["size"]
                backed = {covered_key(file) for file in backed_files}
                if any(not isinstance(record, dict) or covered_key(record.get("original")) not in backed for record in originals):
                    raise WorkflowRefusal("Recovery must cover the exact quarantined originals by source, path, content and size")
            if restore.get("backup_plan_sha256") != backup.get("plan_sha256") or restore.get("backup_archive_sha256") != digest(archive) or restore.get("backup_manifest_sha256") != digest(manifest_data) or restore.get("files") != manifest.get("files") or not SHA.fullmatch(str(restore.get("plan_sha256", ""))):
                raise WorkflowRefusal("Restoration receipt does not bind this exact verified backup")
            outcome_path = output_root / ("outcome-restore-" + restore["plan_sha256"] + ".json")
            self._work_artifact(str(outcome_path), digest(restore), output_root=output_root)
            files, records = manifest.get("files"), restore.get("records")
            if not isinstance(files, list) or not isinstance(records, list) or len(files) != len(records) or not 0 < len(files) <= 10000:
                raise WorkflowRefusal("Restoration must account for every bounded archived file")
            total, retained = 0, {backup["archive"]: digest(archive), backup["manifest"]: digest(manifest_data), str(outcome_path): digest(restore)}
            try:
                with zipfile.ZipFile(io.BytesIO(archive), "r") as zipped:
                    if zipped.namelist() != [file["entry"] for file in files] or len(set(zipped.namelist())) != len(files):
                        raise WorkflowRefusal("Recovery ZIP entry mapping differs from the exact manifest")
                    for file, record in zip(files, records):
                        info = zipped.getinfo(file["entry"])
                        entry_type = stat.S_IFMT(info.external_attr >> 16)
                        if info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED} or entry_type not in {0, stat.S_IFREG}:
                            raise WorkflowRefusal("Required recovery entries must be ordinary unencrypted files in the supported ZIP formats")
                        if type(file.get("size")) is not int or not 0 <= file["size"] <= 16 * 1024 * 1024 or info.file_size != file["size"]:
                            raise WorkflowRefusal("Recovery entry size exceeds the verified bounded contents")
                        total += file["size"]
                        if total > 48 * 1024 * 1024:
                            raise WorkflowRefusal("Recovery total byte cap exceeded")
                        if digest(zipped.read(file["entry"])) != file.get("sha256"):
                            raise WorkflowRefusal("Recovery ZIP entry hash differs from its manifest")
                        expected = Path(restore["destination"]) / file["root_id"] / file["relative_path"]
                        try:
                            relative = expected.relative_to(output_root).as_posix()
                        except ValueError as error:
                            raise WorkflowRefusal("Restoration probe escapes its owned work output root") from error
                        if record.get("relative_path") != relative:
                            raise WorkflowRefusal("Restoration native record does not map the exact original entry")
                        self._work_artifact(str(expected), file["sha256"], output_root=output_root, record=record)
                        retained[str(expected)] = file["sha256"]
            except (zipfile.BadZipFile, KeyError, RuntimeError) as error:
                raise WorkflowRefusal("Required recovery ZIP or restoration mapping is invalid") from error
            self._retention(state, binding["retention_evidence_id"], retained)

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
            self._evidence(state, document["evidence_ids"])
            if not state["scope_authorization"]:
                raise WorkflowRefusal("The current owner has not authorized this scope")
            consumed = {op["action_id"] for op in state["operations"].values()}
            for action in document["actions"]:
                self._action_binding(state, action)
                if action["action_id"] in consumed:
                    raise WorkflowRefusal("A consumed action identifier cannot be reused or retried")
                if action["requires_recovery"] or action["recovery_evidence_ids"]:
                    self._recovery(state, action["recovery_evidence_ids"], action=action)
                if action.get("estimate_evidence_id"):
                    estimate = self._evidence(state, [action["estimate_evidence_id"]], kinds={"inventory"})[0]
                    if estimate["facts"].get("action_id") != action["action_id"]:
                        raise WorkflowRefusal("A cost fact must identify this exact action to prevent unrelated or duplicate workload estimates")
            state["plan"] = {"document": document, "sha256": digest(document), "settings_revision": state["settings_revision"], "registered_utc": utc_now()}
            state["reviews"] = []
            state["approval"] = None
            state["irreversible_ack"] = None
            return {"plan_sha256": state["plan"]["sha256"], "action_ids": [a["action_id"] for a in document["actions"]]}, "The exact plan is saved. It still needs two independent reviews and your concrete action decision before any change."
        return self._change(session_id, "plan_registered", mutate, expected_revision)

    @staticmethod
    def _plan(state, plan_sha256):
        if not state["plan"] or state["plan"]["sha256"] != plan_sha256 or state["plan"]["settings_revision"] != state["settings_revision"]:
            raise WorkflowRefusal("The exact current plan hash is required")
        return state["plan"]["document"]

    def record_review(self, session_id, *, plan_sha256, reviewer_id, role, verdict, evidence_ids, notes, expected_revision=None):
        _id(reviewer_id, "reviewer identifier")
        _text(notes, "review notes")
        if role not in ROLES or verdict not in {"approved", "hold"}:
            raise WorkflowRefusal("A supported review role and approved/hold verdict are required")
        def mutate(state):
            self._writable(state)
            self._plan(state, plan_sha256)
            self._evidence(state, evidence_ids, kinds={"review"}, after=state["plan"]["registered_utc"])
            if reviewer_id == state["owner_id"] or any(row["reviewer_id"] == reviewer_id or row["role"] == role for row in state["reviews"]):
                raise WorkflowRefusal("Reviews need two distinct independent reviewers, separate from the owner")
            record = {"reviewer_id": reviewer_id, "role": role, "verdict": verdict, "evidence_ids": list(evidence_ids), "notes": notes, "plan_sha256": plan_sha256, "settings_revision": state["settings_revision"], "recorded_utc": utc_now()}
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
            self._evidence(state, row["evidence_ids"], kinds={"review"}, after=state["plan"]["registered_utc"])

    def approve_plan(self, session_id, *, plan_sha256, action_ids, owner_quote, owner_message_id, owner_id="owner", source="current_owner_chat", acknowledge_permanent_loss=False, expected_revision=None):
        _ids(action_ids, "approved action identifiers", allow_empty=False)
        def mutate(state):
            self._writable(state)
            document = self._plan(state, plan_sha256)
            self._reviewed(state)
            self._evidence(state, document["evidence_ids"])
            if set(action_ids) - {a["action_id"] for a in document["actions"]}:
                raise WorkflowRefusal("Approval cannot include actions outside the concrete plan")
            purge_ids = [a["action_id"] for a in document["actions"] if a["kind"] == "permanent_purge" and a["action_id"] in action_ids]
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
            plan = self._plan(state, plan_sha256)
            purge = {a["action_id"] for a in plan["actions"] if a["kind"] == "permanent_purge"}
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
            _fields(binding, {"adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256"}, {"adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256"})
            supported = ADAPTERS.get(binding["adapter_id"])
            allowed = set(supported) & POLICY_KINDS if isinstance(supported, tuple) else {supported} & POLICY_KINDS
            if not allowed or any(not isinstance(binding[key], str) or not SHA.fullmatch(binding[key]) for key in binding if key != "adapter_id"):
                raise WorkflowRefusal("Standing policy binding has unsupported adapter or missing exact hashes")
        expiry = _time(expires_utc)
        if not _time(utc_now()) < expiry <= _time(utc_now()) + timedelta(days=7):
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
        if policy and state["settings"]["control"] == "automatic" and policy["settings_revision"] == state["settings_revision"] and policy["scope_sha256"] == digest(state["settings"]["scope"]) and _time(policy["expires_utc"]) > _time(utc_now()) and policy["used_actions"] < policy["max_actions"] and action["kind"] in policy["action_kinds"] and action["target"] in policy["targets"] and {key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")} in policy["action_bindings"] and not action["requires_os_consent"]:
            return {"kind": "standing_policy", "message_id": policy["message_id"], "plan_sha256": state["plan"]["sha256"], "action_id": action["action_id"]}
        raise WorkflowRefusal("This exact action lacks current owner authority; control style alone never authorizes a change")

    @staticmethod
    def _pending(state):
        return [item for item in state["pending"].values() if not item["resolved"]]

    def _checkpoint(self, state, name, action_id=None):
        if name not in state["settings"]["checkpoints"]:
            return
        token = "checkpoint-" + name + "-" + digest({"stage": state["stage"], "action": action_id, "settings": state["settings_revision"], "plan": state["plan"]["sha256"] if state["plan"] else None})[:20]
        if token not in state["pending"]:
            state["pending"][token] = {"pending_id": token, "kind": "checkpoint", "checkpoint": name, "action_id": action_id, "created_utc": utc_now(), "resolved": False, "settings_revision": state["settings_revision"]}
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
            document = self._plan(state, plan_sha256)
            if action_id not in {a["action_id"] for a in document["actions"] if a["requires_os_consent"]}:
                raise WorkflowRefusal("This is not a protected-consent action in the current plan")
            rows = self._evidence(state, [evidence_id], kinds={"protected_consent"}, after=state["plan"]["registered_utc"], seconds=900)
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
        _id(action_id)
        def mutate(state):
            if state["status"] != "active" or state["stage"] != "apply" or self._pending(state):
                raise WorkflowRefusal("New actions wait until the apply stage is active and every hold/checkpoint is resolved")
            activation = self._require_schedule_activation(state)
            if self._outstanding_effects():
                raise WorkflowRefusal("An outstanding mutating operation in this engine registry still needs an actual receipt or effects reconciliation")
            document = self._plan(state, plan_sha256)
            self._reviewed(state)
            self._evidence(state, document["evidence_ids"])
            actions = [a for a in document["actions"] if a["action_id"] == action_id]
            if not actions:
                raise WorkflowRefusal("Action is absent from the exact plan")
            action = actions[0]
            self._action_binding(state, action)
            unconsumed = [a["action_id"] for a in document["actions"] if not any(op["action_id"] == a["action_id"] for op in state["operations"].values())]
            if not unconsumed or action_id != unconsumed[0]:
                raise WorkflowRefusal("Actions follow the exact reviewed order and their individual checkpoints")
            if any(op["action_id"] == action_id or op["outcome"] is None for op in state["operations"].values()):
                raise WorkflowRefusal("An action is already active or consumed; no automatic retry")
            authorization = self._authorization(state, action)
            if action["kind"] == "permanent_purge":
                ack = state["irreversible_ack"]
                if not ack or ack["type"] != "permanent_data_loss" or ack["plan_sha256"] != plan_sha256 or action_id not in ack["action_ids"] or ack["settings_revision"] != state["settings_revision"] or ack["scope_sha256"] != digest(state["settings"]["scope"]):
                    raise WorkflowRefusal("This exact purge still needs a separate actual-owner acknowledgement of irreversible data loss")
            after = max((state["plan"]["registered_utc"], activation["activated_utc"]), key=_time) if activation else state["plan"]["registered_utc"]
            rows = self._evidence(state, precondition_evidence_ids, kinds={"precondition"}, after=after, seconds=900)
            required = {"identity_matches", "scope_matches", "content_matches", "compatibility_checked", "provenance_checked"}
            if action["requires_recovery"]:
                required.add("recovery_verified")
                self._recovery(state, action["recovery_evidence_ids"], action=action)
            for row in rows:
                facts = row["facts"]
                binding = {key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")}
                if facts.get("plan_sha256") != plan_sha256 or facts.get("action_id") != action_id or any(facts.get(key) != value for key, value in binding.items()) or any(facts.get(flag) is not True for flag in required):
                    raise WorkflowRefusal("Fresh preconditions must confirm this exact action's identity, scope, content, compatibility, provenance and recovery")
            if action["adapter_id"] == "system.reviewed_external.v3":
                self._external_preflight(state, action, rows)
            if action["requires_os_consent"]:
                record = state["pending"].get("consent-" + action_id, {}).get("record")
                if not record or record["plan_sha256"] != plan_sha256 or record["evidence_id"] != owner_consent_evidence_id:
                    raise WorkflowRefusal("The actual owner must handle and record protected OS consent")
                self._evidence(state, [owner_consent_evidence_id], kinds={"protected_consent"}, after=state["plan"]["registered_utc"], seconds=900)
            operation_id = "operation-" + uuid.uuid4().hex
            operation = {"operation_id": operation_id, "action_id": action_id, "plan_sha256": plan_sha256, "settings_revision": state["settings_revision"], "started_utc": utc_now(), "finished_utc": None, "outcome": None, "evidence_ids": [], "summary": "Waiting for an actual operation outcome", "authorization": authorization, "pause_requested": False, "resolution": None, "mutating": action["mutating"], "adapter_id": action["adapter_id"]}
            state["operations"][operation_id] = operation
            if authorization["kind"] == "standing_policy":
                state["standing_policy"]["used_actions"] += 1
            return operation, "The one-use operation receipt is recorded. The coordinator may now invoke only the exact supported adapter action; preserve its actual result."
        with self._registry_lock():
            return self._change(session_id, "operation_started", mutate, expected_revision)

    def _restart_evidence(self, state, evidence_id, kinds):
        _id(evidence_id)
        row = state["evidence"].get(evidence_id)
        if not row or row["kind"] not in kinds or row["scope"] != state["settings"]["scope"] or row["settings_revision"] != state["settings_revision"]:
            raise WorkflowRefusal("Restart evidence must retain this operation's original current scope and settings")
        data = self._read_owned(self._directory(state["session_id"]) / row["path"])
        if digest(data) != row["sha256"] or len(data) != row["size"]:
            raise WorkflowRefusal("Original restart evidence bytes changed")
        return row, _decode(data)

    def _restart_context(self, state, operation):
        if operation["adapter_id"] != "system.reviewed_external.v3" or operation["settings_revision"] != state["settings_revision"] or not state["plan"] or operation["plan_sha256"] != state["plan"]["sha256"] or state["platform"] != "windows":
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
        fields = {"schema_version", "mode", "platform", "observed_utc", "last_boot_utc", "source"}
        _fields(boot, fields, fields)
        if boot["schema_version"] != "patchcairn.windows.boot.observation.v3" or boot["mode"] != state["mode"] or boot["platform"] != "windows" or boot["source"] != "windows.cim_last_boot_up_time" or boot["observed_utc"] != row["observed_utc"] or _time(boot["last_boot_utc"]) > _time(boot["observed_utc"]):
            raise WorkflowRefusal("Restart checks require an exact owned actual Windows boot observation")
        return row, boot

    def _restart_pending(self, state, operation, evidence_id):
        action, external = self._restart_context(state, operation)
        row, proof = self._restart_evidence(state, evidence_id, {"outcome"})
        fields = {"schema_version", "session_id", "operation_id", "action_id", "plan_sha256", "settings_revision", "scope_sha256", "adapter_payload_sha256", "external_plan_sha256", "mode", "platform", "catalog_id", "original_exit_code", "observed_utc", "native_receipt_relative_path", "native_receipt_sha256", "before_boot_evidence_id"}
        _fields(proof, fields, fields)
        expected = {"schema_version": "patchcairn.restart.pending.v3", "session_id": state["session_id"], "operation_id": operation["operation_id"], "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"], "settings_revision": state["settings_revision"], "scope_sha256": digest(state["settings"]["scope"]), "adapter_payload_sha256": action["adapter_payload_sha256"], "external_plan_sha256": action["adapter_plan_sha256"], "mode": state["mode"], "platform": "windows", "catalog_id": "windows.msiexec.install", "original_exit_code": 3010}
        if any(proof[key] != value for key, value in expected.items()) or type(proof["original_exit_code"]) is not int or proof["observed_utc"] != row["observed_utc"]:
            raise WorkflowRefusal("The restart-pending receipt must bind the exact original 3010 operation")
        relative = PurePosixPath(_text(proof["native_receipt_relative_path"], "owned original MSI receipt", 2000))
        tail = ("operations", state["session_id"], operation["operation_id"], "external-restart-pending.json")
        if relative.is_absolute() or "\\" in str(relative) or any(part in {".", ".."} or ":" in part for part in relative.parts) or len(relative.parts) < 6 or relative.parts[0] != "work" or tuple(relative.parts[-4:]) != tail:
            raise WorkflowRefusal("The original restart receipt must stay in its exact private service operation")
        service_root = self.root.joinpath(*relative.parts[:-4])
        marker = _decode(_read(service_root / "service.json", 10000, private=True))
        if marker != {"schema_version": "patchcairn.service.v3", "engine_id": state["engine_id"], "backend": BACKEND}:
            raise WorkflowRefusal("The restart receipt belongs to a foreign service or engine")
        native = _decode(self._work_artifact(str(self.root.joinpath(*relative.parts)), proof["native_receipt_sha256"], output_root=service_root, max_bytes=8_000_000))
        native_fields = {"schema_version", "operation_id", "action_id", "plan_sha256", "adapter_payload_sha256", "mode", "platform", "catalog_id", "observed_utc", "outcome", "tool_exit_code", "postcondition_state", "evidence_ids", "observed_effects", "limitations"}
        _fields(native, native_fields, native_fields)
        if native["schema_version"] != "patchcairn.external.receipt.v3" or any(native[key] != expected[key] for key in ("operation_id", "action_id", "plan_sha256", "adapter_payload_sha256", "mode", "platform", "catalog_id")) or type(native["tool_exit_code"]) is not int or native["tool_exit_code"] != 3010 or native["outcome"] != "installed_restart_pending" or native["postcondition_state"] not in {"not_verified", "unknown"} or not _time(operation["started_utc"]) <= _time(native["observed_utc"]) <= _time(proof["observed_utc"]):
            raise WorkflowRefusal("An actual original MSI 3010 receipt is required; another exit code cannot be translated into success")
        before_row, before = self._restart_boot(state, proof["before_boot_evidence_id"])
        if not _time(native["observed_utc"]) <= _time(before["observed_utc"]) <= _time(proof["observed_utc"]) or _time(before["last_boot_utc"]) > _time(native["observed_utc"]):
            raise WorkflowRefusal("The actual pre-restart boot observation does not bind the original tool receipt")
        return row, proof, before_row, before, action, external

    def record_restart_pending(self, session_id, *, operation_id, evidence_id, expected_revision=None):
        _id(operation_id)
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
            record = {"evidence_id": evidence_id, "sha256": row["sha256"], "before_boot_evidence_id": proof["before_boot_evidence_id"], "before_boot_sha256": before_row["sha256"], "original_exit_code": 3010, "recorded_utc": utc_now(), "decision_ids": []}
            operation["restart_pending"] = record
            key = "restart-" + operation_id
            state["pending"][key] = {"pending_id": key, "kind": "restart", "operation_id": operation_id, "resolved": False, "created_utc": utc_now()}
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
            not_before = max((record["recorded_utc"], proposal["proposal"]["when_utc"]), key=_time) if proposal else record["recorded_utc"]
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
        fields = {"schema_version", "session_id", "operation_id", "action_id", "plan_sha256", "settings_revision", "scope_sha256", "external_plan_sha256", "mode", "platform", "catalog_id", "original_exit_code", "pending_evidence_id", "restart_decision_message_id", "observed_utc", "before_boot_evidence_id", "after_boot_evidence_id", "targets", "checks"}
        _fields(proof, fields, fields)
        expected = {"schema_version": "patchcairn.restart.verification.v3", "session_id": state["session_id"], "operation_id": operation["operation_id"], "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"], "settings_revision": state["settings_revision"], "scope_sha256": digest(state["settings"]["scope"]), "external_plan_sha256": action["adapter_plan_sha256"], "mode": state["mode"], "platform": "windows", "catalog_id": "windows.msiexec.install", "original_exit_code": 3010, "pending_evidence_id": pending["evidence_id"], "restart_decision_message_id": decision["message_id"], "before_boot_evidence_id": pending["before_boot_evidence_id"]}
        if any(proof[key] != value for key, value in expected.items()) or type(proof["original_exit_code"]) is not int or proof["observed_utc"] != row["observed_utc"]:
            raise WorkflowRefusal("Post-restart verification must bind the exact original 3010 receipt and owner decision")
        _fresh(proof["observed_utc"], after=decision["recorded_utc"], seconds=900)
        _, after = self._restart_boot(state, proof["after_boot_evidence_id"])
        _fresh(after["observed_utc"], after=decision["recorded_utc"], seconds=900)
        if not _time(before["last_boot_utc"]) < _time(after["last_boot_utc"]) or not _time(pending_proof["observed_utc"]) <= _time(decision["recorded_utc"]) < _time(after["last_boot_utc"]) <= _time(after["observed_utc"]) <= _time(proof["observed_utc"]) or _time(after["last_boot_utc"]) < _time(decision["not_before_utc"]):
            raise WorkflowRefusal("An actual boot transition after the owner decision and agreed time is required")
        if not isinstance(proof["targets"], dict) or set(proof["targets"]) != set(external["targets"]):
            raise WorkflowRefusal("Post-restart checks must account for every exact selected target")
        all_passed = True
        for target in external["targets"]:
            expected_target = {key: external["target_identities"][target][key] for key in ("architecture", "installation_scope", "publisher")}
            expected_target["version"] = external["target_versions"][target]
            actual_target = proof["targets"][target]
            _fields(actual_target, set(expected_target), set(expected_target))
            for value in actual_target.values():
                _text(value, "selected actual target observation", 512)
            if actual_target != expected_target:
                all_passed = False
        checks = external["verification_plan"]["checks"]
        if not isinstance(proof["checks"], list) or len(proof["checks"]) != len(checks):
            raise WorkflowRefusal("Post-restart behavior must cover the original verification plan")
        for actual, expected_check in zip(proof["checks"], checks):
            _fields(actual, {"check_id", "outcome", "observation"}, {"check_id", "outcome", "observation"})
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
            record = {"evidence_id": evidence_id, "sha256": row["sha256"], "recorded_utc": utc_now(), "boot_observed": True, "behavior_passed": all_passed}
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
        rows = self._evidence(state, evidence_ids, kinds={"outcome", "reconciliation"}, after=operation["started_utc"], seconds=900, allow_empty=outcome == "unknown")
        for row in rows:
            facts = row["facts"]
            if any(facts.get(key) != operation[key] for key in ("operation_id", "action_id", "plan_sha256")) or facts.get("outcome") != outcome:
                raise WorkflowRefusal("Outcome evidence must bind the exact operation, action, plan and observed result")
        return rows

    def finish_operation(self, session_id, *, operation_id, outcome, evidence_ids, summary, expected_revision=None):
        _id(operation_id)
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
            operation.update(outcome=outcome, finished_utc=utc_now(), evidence_ids=list(evidence_ids), summary=summary)
            was_stopped = state["status"] == "stopped"
            if outcome != "succeeded":
                key = "reconcile-" + operation_id
                state["pending"][key] = {"pending_id": key, "kind": "reconciliation", "operation_id": operation_id, "created_utc": utc_now(), "resolved": False, "settings_revision": state["settings_revision"]}
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
            if any(op["outcome"] in {None, "unknown"} or op["outcome"] in {"failed", "partial"} and not op["resolution"] for op in state["operations"].values()) or any(p["kind"] == "reconciliation" for p in self._pending(state)):
                raise WorkflowRefusal("Uncertain or unsuccessful operations require an evidence-backed resolution and possibly a new plan")
            pause_time = max((e["at"] for e in self._load(session_id)["events"] if e["type"] in {"paused", "operation_finished", "resolved"}), default=state["updated_utc"])
            rows = self._evidence(state, reconciliation_evidence_ids, kinds={"reconciliation"}, after=pause_time, seconds=900)
            expected_outcomes = {key: op["outcome"] for key, op in state["operations"].items()}
            for row in rows:
                facts = row["facts"]
                if facts.get("scope_matches") is not True or facts.get("no_changes_detected") is not True or facts.get("operation_outcomes") != expected_outcomes or facts.get("plan_sha256") != (state["plan"]["sha256"] if state["plan"] else None):
                    raise WorkflowRefusal("Resume needs a fresh current-scope check and actual outcomes for every operation")
            state["last_reconciled_utc"] = utc_now()
            if state["settings"]["timing"] == "scheduled" and self._require_schedule_activation(state, allow_waiting=True) is None:
                if state["schedule"]:
                    state["schedule"]["ready_for_trigger"] = True
                state["status"] = "held"
            else:
                state["status"] = "awaiting_user" if self._pending(state) else "completed" if state["stage"] == "complete" else "active"
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
            items = self._pending(state)
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
                if state["status"] == "awaiting_user" and not self._pending(state):
                    state["status"] = "completed" if state["stage"] == "complete" else "active"
            elif item["kind"] == "reconciliation":
                operation = state["operations"][item["operation_id"]]
                if operation["outcome"] is None:
                    raise WorkflowRefusal("An active operation must first reach its safe receipt checkpoint")
                if operation["outcome"] == "unknown":
                    rows = self._evidence(state, evidence_ids or [], kinds={"reconciliation", "outcome"}, after=operation["finished_utc"], seconds=900)
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
                    if any(row["kind"] != "reconciliation" or _time(row["observed_utc"]) < _time(operation["finished_utc"]) or any(row["facts"].get(flag) is not True for flag in ("actual_effects_recorded", "no_active_effects", "recovery_retained")) for row in rows):
                        raise WorkflowRefusal("Replanning needs fresh actual-effects reconciliation, no ongoing operation and retained recovery; the historical failure remains unchanged")
                    item["owner_instruction"] = _owner(state, owner_quote, owner_message_id)
                    item["resolved"] = True
                    operation["resolution"] = {"kind": "effects_accounted" if was_stopped else "replan_required", "evidence_ids": list(evidence_ids), "recorded_utc": utc_now(), "owner_message_id": owner_message_id}
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
            if state["status"] != "active" or self._pending(state):
                raise WorkflowRefusal("Stage advancement waits for an active session and resolved checkpoints")
            self._require_schedule_activation(state)
            stage = state["stage"]
            rows = self._evidence(state, evidence_ids, allow_empty=stage in {"plan", "apply"})
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
                verified = [row for row in rows if row["kind"] == "verification" and row["facts"].get("verification_passed") is True and row["facts"].get("plan_sha256") == state["plan"]["sha256"] and set(row["facts"].get("checked_action_ids", [])) == planned and _time(row["observed_utc"]) >= _time(latest)]
                if not verified:
                    raise WorkflowRefusal("Actual behavior verification for every exact planned action is required after its outcome")
            else:
                raise WorkflowRefusal("This job is already at its final stage")
            stages = JOBS[state["job"]]["stages"]
            state["stage"] = stages[stages.index(stage) + 1]
            checkpoint = "findings" if state["stage"] == "plan" else "plan" if state["stage"] == "apply" else "finish" if state["stage"] == "complete" else None
            if checkpoint:
                self._checkpoint(state, checkpoint)
            if state["stage"] == "complete" and not self._pending(state):
                state["status"] = "completed"
            if state["stage"] == "apply":
                self._next_action_checkpoint(state)
            return {"stage": state["stage"]}, "The evidence supports the next step: " + STAGE_LABELS[state["stage"]].lower() + ". " + ("The actual checked result is complete; retained evidence and recovery files still need a separate cleanup decision." if state["status"] == "completed" else "Use PatchCairn: options for the next decision and any selected checkpoint.")
        return self._change(session_id, "stage_advanced", mutate, expected_revision)

    def complete_assessment(self, session_id, *, summary_evidence_id, verification_evidence_ids, owner_quote, owner_message_id, owner_id=None, source="current_owner_chat", expected_revision=None):
        _id(summary_evidence_id)
        def mutate(state):
            self._writable(state)
            if state["status"] != "active" or state["stage"] != "plan" or self._pending(state):
                raise WorkflowRefusal("Finish the assessment stages and selected checkpoints before closing an assessment")
            activation = self._require_schedule_activation(state)
            if state["operations"] or state["plan"] is not None or state["approval"] is not None or state["reviews"] or state["standing_policy"] is not None:
                raise WorkflowRefusal("Assessment-only completion cannot close a session with any operation history, plan, approval, reviews or standing policy")
            authorization = state["scope_authorization"]
            scope_sha = digest(state["settings"]["scope"])
            if not authorization or authorization.get("owner_id") != state["owner_id"] or authorization.get("settings_revision") != state["settings_revision"] or authorization.get("scope_sha256") != scope_sha:
                raise WorkflowRefusal("Assessment completion requires the actual current owner's exact authorized scope")
            after = max((authorization["recorded_utc"], activation["activated_utc"]), key=_time) if activation else authorization["recorded_utc"]
            summary_row = self._evidence(state, [summary_evidence_id], kinds={"research"}, after=after, seconds=900)[0]
            summary = _decode(self._read_owned(self._directory(session_id) / summary_row["path"]))
            common = {"schema_version", "job", "mode", "scope_sha256", "settings_revision"}
            summary_fields = common | {"summary", "findings", "limitations", "assessed_evidence_ids"}
            _fields(summary, summary_fields, summary_fields)
            if summary["schema_version"] != "patchcairn.assessment.summary.v3" or summary["job"] != state["job"] or summary["mode"] != state["mode"] or summary["scope_sha256"] != scope_sha or summary["settings_revision"] != state["settings_revision"]:
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
            assessed = self._evidence(state, summary["assessed_evidence_ids"], kinds={"scope_confirmation", "inventory", "research", "candidates", "symptom", "hypotheses", "recovery_plan"}, after=authorization["recorded_utc"])
            requirements = {"scope": ("scope_confirmation", {"scope_confirmed"}), "inventory": ("inventory", {"complete"}), "research": ("research", {"applicability_checked", "official_sources_checked"}), "candidates": ("candidates", {"candidates_reviewed", "excluded_private"}), "symptom": ("symptom", {"symptom_recorded", "relevant_scope"}), "hypotheses": ("hypotheses", {"alternatives_considered", "distinguishing_checks"}), "recovery_plan": ("recovery_plan", {"contents_reviewed", "restore_check_planned", "exclusions_explicit"})}
            for stage in JOBS[state["job"]]["stages"][:JOBS[state["job"]]["stages"].index("plan")]:
                kind, flags = requirements[stage]
                if not any(row["kind"] == kind and all(row["facts"].get(flag) is True for flag in flags) for row in assessed):
                    raise WorkflowRefusal("The summary must cover the actual current evidence for every agreed assessment step")
            rows = self._evidence(state, verification_evidence_ids, kinds={"verification"}, after=summary_row["registered_utc"], seconds=900)
            for row in rows:
                verification = _decode(self._read_owned(self._directory(session_id) / row["path"]))
                fields = common | {"summary_evidence_id", "summary_sha256", "assessed_evidence_ids", "coverage_checked", "limitations_checked", "observed_utc"}
                _fields(verification, fields, fields)
                if verification["schema_version"] != "patchcairn.assessment.verification.v3" or any(verification[key] != summary[key] for key in ("job", "mode", "scope_sha256", "settings_revision", "assessed_evidence_ids")) or verification["summary_evidence_id"] != summary_evidence_id or verification["summary_sha256"] != summary_row["sha256"] or verification["coverage_checked"] is not True or verification["limitations_checked"] is not True or verification["observed_utc"] != row["observed_utc"]:
                    raise WorkflowRefusal("Assessment verification must check the exact current summary, evidence coverage and recorded limitations")
                _fresh(verification["observed_utc"], after=summary_row["registered_utc"], seconds=900)
            record = {"summary_evidence_id": summary_evidence_id, "summary_sha256": summary_row["sha256"], "verification_evidence_ids": list(verification_evidence_ids), "owner_instruction": _owner(state, owner_quote, owner_message_id, owner_id, source)}
            key = "assessment-finish-" + digest({"summary": summary_row["sha256"], "settings": state["settings_revision"], "message": owner_message_id})[:24]
            state["pending"][key] = {"pending_id": key, "kind": "assessment_finish", "resolved": True, "record": record}
            state["stage"] = "complete"
            self._checkpoint(state, "finish")
            if not self._pending(state):
                state["status"] = "completed"
            return record, "The assessment and its findings are recorded, including what remains uncertain. This session recorded no maintenance action. " + ("Review the selected finish checkpoint before closing." if state["status"] != "completed" else "The assessment session is complete; any computer change needs a separate reviewed plan.")
        return self._change(session_id, "assessment_completed", mutate, expected_revision)

    @staticmethod
    def _schedule_identity(record):
        try:
            return digest({key: record[key] for key in ("owner_id", "quote", "message_id", "source", "recorded_utc", "settings_revision", "proposal")})
        except KeyError as error:
            raise WorkflowRefusal("An incomplete schedule record cannot authorize work") from error

    def _require_schedule_activation(self, state, *, allow_waiting=False):
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
        _fields(activation, fields, fields)
        proposal = record["proposal"]
        if activation["schedule_id"] != record["schedule_id"] or activation["settings_revision"] != state["settings_revision"] or activation["trigger_id"] not in state["schedule_triggers"] or record.get("ready_for_trigger") is not False or not _time(proposal["when_utc"]) <= _time(activation["activated_utc"]) <= _time(proposal["expires_utc"]) or _time(activation["activated_utc"]) - _time(proposal["when_utc"]) > timedelta(seconds=proposal["max_lateness_seconds"]) or _time(utc_now()) < _time(activation["activated_utc"]):
            raise WorkflowRefusal("The recorded activation does not authorize this exact current schedule")
        return activation

    def configure_schedule(self, session_id, *, schedule, owner_quote, owner_message_id, expected_revision=None):
        _fields(schedule, {"when_utc", "description", "expires_utc", "max_lateness_seconds"}, {"when_utc", "description"})
        if _time(schedule["when_utc"]) <= _time(utc_now()):
            raise WorkflowRefusal("The proposed schedule time must be in the future")
        _text(schedule["description"], "schedule explanation")
        proposal = copy.deepcopy(schedule)
        proposal.setdefault("max_lateness_seconds", 300)
        proposal.setdefault("expires_utc", (_time(schedule["when_utc"]) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"))
        if type(proposal["max_lateness_seconds"]) is not int or not 0 <= proposal["max_lateness_seconds"] <= 3600 or not _time(proposal["when_utc"]) <= _time(proposal["expires_utc"]) <= _time(proposal["when_utc"]) + timedelta(hours=24):
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
        _id(trigger_id)
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
            if _time(utc_now()) < _time(state["schedule"]["proposal"]["when_utc"]):
                raise WorkflowRefusal("The proposed schedule time has not arrived")
            proposal = state["schedule"]["proposal"]
            if _time(utc_now()) > _time(proposal["expires_utc"]) or _time(utc_now()) - _time(proposal["when_utc"]) > timedelta(seconds=proposal["max_lateness_seconds"]):
                raise WorkflowRefusal("The bounded schedule catch-up window or expiry has passed; a new owner decision is required")
            for directory in self.work.iterdir():
                if directory.is_dir() and directory.name.startswith("session-") and directory.name != session_id:
                    other = self.read_session(directory.name)
                    if other["job"] == state["job"] and (other["status"] == "active" or other["status"] == "awaiting_user" and other["schedule_triggers"]):
                        raise WorkflowRefusal("Another active session already owns this job; the trigger cannot duplicate it")
            state["schedule_triggers"].append(trigger_id)
            record["activation"] = {"schedule_id": schedule_id, "trigger_id": trigger_id, "activated_utc": utc_now(), "settings_revision": state["settings_revision"]}
            record["ready_for_trigger"] = False
            if state["settings"]["control"] == "guided":
                state["status"] = "awaiting_user"
                key = "schedule-start-" + digest(trigger_id)[:24]
                state["pending"][key] = {"pending_id": key, "kind": "checkpoint", "checkpoint": "scheduled_start", "action_id": None, "created_utc": utc_now(), "resolved": False, "settings_revision": state["settings_revision"]}
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
            return {"unresolved": self._pending(state)}, "This session is stopped. Evidence, recovery files and unfinished outcomes are preserved. An active operation still needs its actual safe-checkpoint receipt; no new action is allowed."
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
        return self._response(state, "status", message, {"job": state["job"], "stage": state["stage"], "status": state["status"], "control": state["settings"]["control"], "timing": state["settings"]["timing"], "pending": self._pending(state), "operations": list(state["operations"].values())})

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
                    row = self._evidence(state, [evidence_id], kinds={"inventory"})[0]
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
        pending = self._pending(state)
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
        return self._response(state, "options", message, {"decision": card, "action_decisions": actions, "pending": self._pending(state), "commands": ["PatchCairn: " + c for c in COMMANDS]})

    def dispatch(self, session_id, command, *, expected_revision=None):
        parsed = parse_command(command)
        if not parsed["ok"]:
            return {"schema_version": VERSION, "ok": False, "code": parsed["code"], "message": parsed["message"], "session_id": session_id, "revision": None, "data": {}}
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
