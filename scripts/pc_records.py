"""PatchCairn record foundation (layer L0, standard library only).

One home for canonical JSON, the strict decoder, the schema registry, the UTC
clock, identifier and text validators, the refusal base and the closed table of
adapter facts. Other modules call ``pc_records.utc_now()`` through the module so
tests can patch the one clock.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import re
from types import MappingProxyType

SCHEMA_VERSION = 1
OLDER_FORMAT_MESSAGE = "This record uses an older PatchCairn format and cannot be read; start a new session."
UNSUPPORTED_VERSION_MESSAGE = "This record uses a PatchCairn format version this release cannot read; start a new session."
# The published backup entry bound; the storage measurements confirm it or lower it to the count
# measured through the engine.
MAX_BACKUP_ENTRIES = 100_000
# The engine reads owned records with a 16,000,000-byte cap today. The depth limit is far above every
# record PatchCairn writes, and one list or object may hold as many entries as the largest backup.
# Parsing can briefly need about 25 times max_bytes of memory, so readers of a single small record pass
# a smaller max_bytes, and readers of large hash-bound files pass larger max_nodes explicitly.
DEFAULT_MAX_BYTES = 16_000_000
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_ITEMS = MAX_BACKUP_ENTRIES
DEFAULT_MAX_NODES = 1_000_000
# 20 digits hold every 64-bit identity and nanosecond time; longer integers are refused before parsing.
_MAX_INTEGER_DIGITS = 20
# A small backward clock step (NTP or a WSL re-sync) must not make fresh evidence look future-dated.
# Ordering against a plan or a decision keeps no tolerance.
FUTURE_SKEW_SECONDS = 2.0
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# Hours stop at 23: Python also reads 24:00:00 as the next midnight, a second spelling of one instant. A fraction
# has exactly the six digits utc_now writes, so .5 and .500000 cannot both name one instant. Whole seconds keep two
# valid spellings, 03:04:05Z (written by seconds-precision collectors) and 03:04:05.000000Z (the one utc_now writes);
# they parse to the same instant but hash and sort as different text.
_UTC_TEXT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{6})?Z\Z")
_VERSIONED_NAME = re.compile(r".*[._-]v[0-9]+\Z", re.IGNORECASE)
_DECIMAL_VERSION = re.compile(r"[0-9]+\.[0-9]+\Z")

# Every typed record name. A family has one name and tells its records apart by "kind" (the storage
# family's receipts, manifests and README facts are kinds of patchcairn.storage; release receipts are
# kinds of patchcairn.service).
SCHEMAS = frozenset({
    "patchcairn.assessment.access", "patchcairn.assessment.summary", "patchcairn.assessment.verification",
    "patchcairn.diagnostic.adapter", "patchcairn.diagnostics", "patchcairn.fixture.adapter",
    "patchcairn.external.adapter", "patchcairn.external.plan", "patchcairn.external.preflight",
    "patchcairn.external.receipt", "patchcairn.external.recovery", "patchcairn.external.verification",
    "patchcairn.installer.metadata", "patchcairn.publisher.signature", "patchcairn.quarantine.recovery",
    "patchcairn.quarantine.reservation", "patchcairn.recovery.binding", "patchcairn.recovery.retention",
    "patchcairn.restart.pending", "patchcairn.restart.verification", "patchcairn.service", "patchcairn.storage",
    "patchcairn.storage.adapter", "patchcairn.windows.boot.observation",
    "patchcairn.package", "patchcairn.schedule", "patchcairn.report",
})
# Names whose family is not written yet. They may not have a reader; each leaves this set when its
# family's reader is registered, and the set is empty in a finished release.
PLANNED_SCHEMAS = frozenset({"patchcairn.package", "patchcairn.schedule", "patchcairn.report"})
CONTAINERS = frozenset({
    "engine_marker", "session_state", "session_creation", "response_envelope",
    "workflows_template", "tool_catalog", "toolkit_marker",
})


class Refusal(ValueError):
    """A categorical refusal: nothing was authorized and nothing is retried.

    It stays a ValueError because every product refusal is one today and
    callers catch ValueError.
    """

    def __init__(self, code, message=None):
        self.code = code
        super().__init__(code if message is None else message)


# The single validator of each unplanned name. Modules whose readers predate this registry are listed
# by name (None) until they call register_reader; a complete release has a callable for every name.
READERS = dict.fromkeys(SCHEMAS - PLANNED_SCHEMAS)


def register_reader(name, reader):
    """Record ``reader`` (record -> record) as the one validator of the record name ``name``; return it."""
    if name not in SCHEMAS:
        raise Refusal("schema-unregistered", "Not a registered PatchCairn record name: " + repr(name))
    if name in PLANNED_SCHEMAS:
        raise Refusal("schema-planned", "This record family is not written yet: " + repr(name))
    if not callable(reader):
        raise Refusal("invalid-reader", "A record reader must be callable")
    if READERS.get(name) is not None and READERS[name] is not reader:
        raise Refusal("reader-registered", "Each record name has exactly one reader: " + repr(name))
    READERS[name] = reader
    return reader


def _check_text(value, code):
    if not value.isascii():
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise Refusal(code, "Text with unpaired surrogates is not accepted") from error


def _check_encodable(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise Refusal("invalid-record", "Record keys must be text")
                _check_text(key, "invalid-record")
                pending.append(child)
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
        elif isinstance(item, str):
            _check_text(item, "invalid-record")
        elif isinstance(item, int) and abs(item) >= 10 ** _MAX_INTEGER_DIGITS:
            raise Refusal("invalid-record", "Integers longer than 20 digits are not accepted")


def encoded(value):
    """Canonical JSON bytes: sorted keys, ASCII, no NaN, no whitespace; only data decode_strict reads back."""
    try:
        data = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise Refusal("invalid-record", "A record must be bounded JSON data") from error
    # json.dumps turns 1 and "1" keys into the same text, and writes lone surrogates and long integers
    # that the decoder refuses.
    _check_encodable(value)
    return data


def digest(value):
    """SHA-256 hex of raw bytes, or of the canonical encoding of any other value."""
    return hashlib.sha256(value if isinstance(value, bytes) else encoded(value)).hexdigest()


def _limit(value, name):
    if type(value) is not int or value < 1:
        raise Refusal("invalid-limit", name + " must be a positive integer")
    return value


def _nonfinite(_text):
    raise Refusal("json-nonfinite", "NaN and Infinity are not accepted")


def _finite(text):
    value = float(text)
    if not math.isfinite(value):
        raise Refusal("json-nonfinite", "Numbers outside the finite range are not accepted")
    return value


def _integer(text):
    if len(text.lstrip("-")) > _MAX_INTEGER_DIGITS:
        raise Refusal("json-number", "Integers longer than 20 digits are not accepted")
    return int(text)


def _check_tree(value, max_depth, max_items, max_nodes):
    pending, count = [(value, 1)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > max_nodes:
            raise Refusal("json-too-large", "The record has too many values")
        if isinstance(item, (dict, list)):
            if depth > max_depth:
                raise Refusal("json-too-deep", "The record is nested too deeply")
            if len(item) > max_items:
                raise Refusal("json-too-large", "A record list or object has too many entries")
            if isinstance(item, dict):
                for key in item:
                    _check_text(key, "json-encoding")
                children = item.values()
            else:
                children = item
            pending.extend((child, depth + 1) for child in children)
        elif isinstance(item, str):
            _check_text(item, "json-encoding")


def decode_strict(data, *, max_bytes=DEFAULT_MAX_BYTES, max_depth=DEFAULT_MAX_DEPTH, max_items=DEFAULT_MAX_ITEMS,
                  max_nodes=DEFAULT_MAX_NODES):
    """Decode UTF-8 JSON bytes, refusing a BOM, duplicate keys, NaN or Infinity and over-deep or over-large input."""
    _limit(max_bytes, "max_bytes")
    _limit(max_depth, "max_depth")
    _limit(max_items, "max_items")
    _limit(max_nodes, "max_nodes")
    if not isinstance(data, (bytes, bytearray)):
        raise Refusal("json-type", "Records are read as bytes")
    if len(data) > max_bytes:
        raise Refusal("json-too-large", "The record exceeds its size limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise Refusal("json-bom", "A byte order mark is not accepted")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal("json-encoding", "Records must be UTF-8") from error
    # Lists cannot be counted while json parses them, so a flood of lists is stopped by counting
    # brackets first (brackets inside strings count too, which errs on the side of refusing).
    if text.count("[") > max_nodes:
        raise Refusal("json-too-large", "The record has too many values")
    objects = [0]

    def unique(pairs):
        objects[0] += len(pairs) + 1
        if len(pairs) > max_items or objects[0] > max_nodes:
            raise Refusal("json-too-large", "A record object has too many entries")
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refusal("json-duplicate-key", "Duplicate JSON keys are not accepted")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=unique, parse_constant=_nonfinite, parse_float=_finite,
                           parse_int=_integer)
    except Refusal:
        raise
    except RecursionError as error:
        raise Refusal("json-too-deep", "The record is nested too deeply") from error
    except ValueError as error:
        raise Refusal("json-invalid", "Invalid JSON record") from error
    _check_tree(value, max_depth, max_items, max_nodes)
    return value


def _older(record):
    schema, version, backend = record.get("schema"), record.get("schema_version"), record.get("backend")
    # Today's engine marker and session state are containers whose backend name carries a version.
    if type(backend) is str and _VERSIONED_NAME.match(backend):
        return True
    if type(schema) is str:
        return bool(_VERSIONED_NAME.match(schema))
    # Older records kept a versioned name or "1.0" in schema_version and had no schema field.
    return "schema" not in record and type(version) is str and bool(_VERSIONED_NAME.match(version) or _DECIMAL_VERSION.match(version))


def _require_version(record):
    if "schema_version" not in record:
        raise Refusal("schema-version", "The record has no schema_version")
    version = record["schema_version"]
    # The one strict comparison of schema_version in the product: bool, float and text never pass.
    if type(version) is not int or version < SCHEMA_VERSION:
        raise Refusal("schema-version", "schema_version must be the integer 1")
    if version != SCHEMA_VERSION:
        raise Refusal("schema-version", UNSUPPORTED_VERSION_MESSAGE)


def require_schema(record, name):
    """Return a typed record whose schema is exactly ``name`` and whose schema_version is the integer 1."""
    if name not in SCHEMAS:
        raise Refusal("schema-unregistered", "Not a registered PatchCairn record name: " + repr(name))
    if not isinstance(record, dict):
        raise Refusal("record-shape", "A JSON object record is required")
    if _older(record):
        raise Refusal("older-format", OLDER_FORMAT_MESSAGE)
    if type(record.get("schema")) is not str or record["schema"] != name:
        raise Refusal("schema-name", "Expected a " + name + " record")
    _require_version(record)
    return record


def require_container(record, kind):
    """Return a container record of the registered ``kind``: the integer schema_version 1 and no schema name."""
    if kind not in CONTAINERS:
        raise Refusal("schema-unregistered", "Not a registered PatchCairn container kind: " + repr(kind))
    if not isinstance(record, dict):
        raise Refusal("record-shape", "A JSON object record is required")
    if _older(record):
        raise Refusal("older-format", OLDER_FORMAT_MESSAGE)
    if "schema" in record:
        raise Refusal("schema-name", "A container record carries only schema_version")
    _require_version(record)
    return record


def utc_now():
    """Current UTC time with exactly six fraction digits (microseconds, .000000 too), in the 'Z' form records use."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_utc(text):
    """Parse a record timestamp: YYYY-MM-DDTHH:MM:SS, no fraction or a fraction of exactly 6 digits, then 'Z'.

    A fixed-width fraction gives an instant with a fraction one spelling, which keeps record hashes and the
    text ordering of utc_now() timestamps consistent.
    """
    if not isinstance(text, str) or not _UTC_TEXT.match(text):
        raise Refusal("utc-time", "A UTC timestamp such as 2026-01-02T03:04:05Z or 2026-01-02T03:04:05.123456Z is"
                                  " required: no fraction, or a fraction of exactly six digits")
    try:
        return datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise Refusal("utc-time", "Invalid UTC timestamp") from error


def _seconds(value, name, *, positive):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise Refusal("invalid-limit", name + " must be a finite number of seconds")
    try:
        return timedelta(seconds=value)
    except OverflowError as error:
        raise Refusal("invalid-limit", name + " is out of range") from error


def fresh(observed, *, after=None, seconds, future_skew=FUTURE_SKEW_SECONDS):
    """Refuse evidence older than ``seconds`` or dated more than ``future_skew`` seconds ahead; return its time.

    ``after`` is the operation or decision the evidence must follow, with no
    tolerance: evidence from before the decision never counts.
    """
    window = _seconds(seconds, "seconds", positive=True)
    skew = _seconds(future_skew, "future_skew", positive=False)
    moment, now = parse_utc(observed), parse_utc(utc_now())
    if moment > now + skew or now - moment > window:
        raise Refusal("stale-evidence", "Evidence is future-dated or stale; collect a fresh observation")
    if after is not None and moment < parse_utc(after):
        raise Refusal("evidence-order", "Evidence predates the operation or decision it must reconcile")
    return moment


def identifier(value, name="identifier"):
    """Return a bounded record identifier; paths and separators are refused."""
    if not isinstance(value, str) or not ID.match(value):
        raise Refusal("invalid-identifier", "Invalid " + name + "; paths are not accepted")
    return value


def sha256_hex(value, name="SHA-256"):
    """Return a lowercase 64-digit SHA-256 hex string."""
    if not isinstance(value, str) or not SHA256.match(value):
        raise Refusal("invalid-sha256", "Invalid " + name)
    return value


def bounded_text(value, name="text", limit=4000):
    """Return non-blank text of at most ``limit`` characters without control characters other than tab and newline."""
    if (not isinstance(value, str) or not value.strip() or len(value) > limit
            or any(ord(char) < 32 and char not in "\n\t" for char in value)):
        raise Refusal("invalid-text", "Invalid " + name)
    return value


ACKNOWLEDGMENTS = frozenset({"permanent_data_loss", "no_component_rollback", "non_private_destination"})
FAMILIES = frozenset({"backup", "restore", "cleanup", "retention", "update", "repair", "assessment"})
OS_CONSENT = ("never", "per_route", "always")
BACKUP_RECEIPT = ("none", "optional", "required")


def _facts(family, kinds, *, acknowledgments=(), conditional=(), backup_receipt="none", policy_coverable=False,
           scheduled_policy_coverable=False, os_consent="never", irreversible=False, transitional=False):
    return MappingProxyType({
        "family": family, "kinds": kinds, "acknowledgments": acknowledgments, "conditional_acknowledgments": conditional,
        "backup_receipt": backup_receipt, "policy_coverable": policy_coverable,
        "scheduled_policy_coverable": scheduled_policy_coverable, "os_consent": os_consent,
        "irreversible": irreversible, "transitional": transitional})


ADAPTER_STORAGE_BACKUP_CREATE = "storage.backup_create"
ADAPTER_STORAGE_RESTORE = "storage.restore"
ADAPTER_STORAGE_QUARANTINE = "storage.quarantine"
ADAPTER_STORAGE_QUARANTINE_RESTORE = "storage.quarantine_restore"
ADAPTER_STORAGE_PURGE = "storage.purge"
ADAPTER_STORAGE_REMOVE_ORIGINALS = "storage.remove_originals"
ADAPTER_STORAGE_RETENTION_RELEASE = "storage.retention_release"
ADAPTER_STORAGE_RETENTION_FORGET = "storage.retention_forget"
ADAPTER_STORAGE_SESSION_RELEASE = "storage.session_release"
ADAPTER_PACKAGE_UPGRADE = "package.upgrade"
ADAPTER_PACKAGE_REINSTALL = "package.reinstall"
ADAPTER_SYSTEM_REPAIR = "system.repair"
ADAPTER_DIAGNOSTIC_COLLECT = "diagnostic.collect"
ADAPTER_FIXTURE_ASSESSMENT = "fixture.assessment"
ADAPTER_SYSTEM_REVIEWED_EXTERNAL = "system.reviewed_external"

# The closed adapter set and its facts, read-only for the whole process.
# - "kinds": the engine action kinds an id may carry (today's mapping for the ids that exist today).
# - "backup_receipt": "required" (a verified receipt must be bound), "optional" (bound only when the plan
#   requires recovery) or "none".
# - "policy_coverable": a standing policy may authorize it inside a session; "scheduled_policy_coverable":
#   a fired scheduled run may act on it under that policy (package updates stop at before_action).
# - "os_consent": "never", "per_route" (depends on the manager and install scope, recorded after the run)
#   or "always" (the operating system asks the owner every time).
# - storage.retention_forget forgets folders that were deleted outside PatchCairn; its executor refuses
#   if any target still exists, so it needs no loss acknowledgment.
# - "transitional": today's local-installer route, kept only until the package routes replace it.
ADAPTERS = MappingProxyType({
    ADAPTER_STORAGE_BACKUP_CREATE: _facts("backup", ("backup_create",), conditional=("non_private_destination",),
                                          policy_coverable=True, scheduled_policy_coverable=True),
    ADAPTER_STORAGE_RESTORE: _facts("restore", ("backup_restore",), backup_receipt="required"),
    ADAPTER_STORAGE_QUARANTINE: _facts("cleanup", ("cleanup_quarantine",), backup_receipt="optional",
                                       policy_coverable=True, scheduled_policy_coverable=True),
    ADAPTER_STORAGE_QUARANTINE_RESTORE: _facts("restore", ("backup_restore",)),
    ADAPTER_STORAGE_PURGE: _facts("cleanup", ("permanent_purge",), acknowledgments=("permanent_data_loss",),
                                  backup_receipt="optional", irreversible=True),
    ADAPTER_STORAGE_REMOVE_ORIGINALS: _facts("cleanup", ("remove_originals",), acknowledgments=("permanent_data_loss",),
                                             backup_receipt="required", irreversible=True),
    ADAPTER_STORAGE_RETENTION_RELEASE: _facts("retention", ("retention_release",),
                                              acknowledgments=("permanent_data_loss",), irreversible=True),
    ADAPTER_STORAGE_RETENTION_FORGET: _facts("retention", ("retention_forget",)),
    ADAPTER_STORAGE_SESSION_RELEASE: _facts("retention", ("session_release",), acknowledgments=("permanent_data_loss",),
                                            irreversible=True),
    ADAPTER_PACKAGE_UPGRADE: _facts("update", ("update",), policy_coverable=True, os_consent="per_route"),
    ADAPTER_PACKAGE_REINSTALL: _facts("repair", ("repair",), os_consent="per_route"),
    ADAPTER_SYSTEM_REPAIR: _facts("repair", ("repair",), acknowledgments=("no_component_rollback",), os_consent="always",
                                  irreversible=True),
    ADAPTER_DIAGNOSTIC_COLLECT: _facts("assessment", ("assessment",)),
    ADAPTER_FIXTURE_ASSESSMENT: _facts("assessment", ("assessment",)),
    ADAPTER_SYSTEM_REVIEWED_EXTERNAL: _facts("update", ("update", "repair"), os_consent="always", transitional=True),
})


def adapter_facts(adapter_id, *, requires_os_consent):
    """Facts of a registered adapter, refusing an action whose OS-consent flag contradicts them."""
    facts = ADAPTERS.get(adapter_id) if isinstance(adapter_id, str) else None
    if facts is None:
        raise Refusal("unknown-adapter", "This action has no registered adapter")
    if type(requires_os_consent) is not bool:
        raise Refusal("os-consent", "requires_os_consent must be true or false")
    if facts["os_consent"] == "always" and not requires_os_consent:
        raise Refusal("os-consent", "This adapter always needs the operating system to ask the owner")
    if facts["os_consent"] == "never" and requires_os_consent:
        raise Refusal("os-consent", "This adapter never involves an operating-system consent prompt")
    return facts
