"""The storage adapter payload contract (layer L2-pure: the standard library and L0 modules only).

One home, shared by the engine, the service and the storage code, for the storage plan kind each storage
adapter binds and for the payload wrapper a reviewed storage action carries (PD-18). It reads only the data
it is given; the engine adds its own work-tree confinement and the storage code its native checks.
"""
from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import pc_records

PAYLOAD = "patchcairn.storage.adapter"
PLAN = "patchcairn.storage"
# The storage plan kind of every storage adapter id in pc_records.ADAPTERS.
PLAN_KINDS = MappingProxyType({
    pc_records.ADAPTER_STORAGE_BACKUP_CREATE: "backup",
    pc_records.ADAPTER_STORAGE_RESTORE: "restore",
    pc_records.ADAPTER_STORAGE_QUARANTINE: "quarantine",
    pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE: "quarantine_restore",
    pc_records.ADAPTER_STORAGE_PURGE: "purge",
    pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS: "remove_originals",
    pc_records.ADAPTER_STORAGE_RETENTION_RELEASE: "retention_release",
    pc_records.ADAPTER_STORAGE_RETENTION_FORGET: "retention_forget",
    pc_records.ADAPTER_STORAGE_SESSION_RELEASE: "session_release",
    pc_records.ADAPTER_STORAGE_DELETE_SELECTED: "delete_selected",
})
# Every storage record is a kind of patchcairn.storage: each plan kind above, and the records around the plans.
KINDS = frozenset(PLAN_KINDS.values()) | frozenset({
    "inventory", "storage_preconditions", "duplicates", "attempt", "backup_manifest", "backup_receipt", "restore_receipt",
    "quarantine_receipt", "quarantine_restore_receipt", "purge_receipt", "storage_outcome_verification", "capabilities"})
PAYLOAD_REQUIRED = frozenset({"operation", "storage_plan", "storage_plan_sha256", "output_root", "mode", "protected_roots"})
# The number of files or backups and their bytes that the owner's typed reply names: required for, and only for, an
# adapter whose facts list permanent data loss.
DELETION_FIELDS = frozenset({"delete_count", "delete_bytes"})
PAYLOAD_OPTIONAL = frozenset({"restore_probe_destination"}) | DELETION_FIELDS
# Where each built permanent deletion's plan lists what it deletes: a purge its quarantine receipt's records (each
# record's original), removing originals its selected files (the plan builders' "files" rows), deleting selected files
# its rows file's totals. Retention and session release are not built yet and are refused.
DELETION_SOURCES = MappingProxyType({
    pc_records.ADAPTER_STORAGE_PURGE: "receipt",
    pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS: "files",
    pc_records.ADAPTER_STORAGE_DELETE_SELECTED: "rows_file",
})
# Above the service's 10,000 retention rows plus its own namespaces, so retained recovery never locks a
# new plan out (#1); D-015 later narrows the roots to one per destination.
MAX_PROTECTED_ROOTS = 16_384
MAX_PATH_TEXT = 2000


def _refuse(message):
    raise pc_records.Refusal("storage-payload", message)


def read_storage(record):
    """The registered reader of patchcairn.storage records, shared by the engine and the storage code:
    the schema check and a known kind; the fields of each kind are checked where it is used."""
    pc_records.require_schema(record, PLAN)
    if record.get("kind") not in KINDS:
        raise pc_records.Refusal("storage-refusal", "Unknown storage record kind")
    return record


pc_records.register_reader(PLAN, read_storage)


def plan_kind(adapter_id):
    """The storage plan kind the storage adapter ``adapter_id`` binds."""
    kind = PLAN_KINDS.get(adapter_id) if isinstance(adapter_id, str) else None
    if kind is None:
        raise pc_records.Refusal("unknown-adapter", "This action has no registered storage adapter")
    return kind


def absolute_path(value, name):
    """Exact absolute path text without traversal; nothing is opened or resolved."""
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_TEXT or "\x00" in value:
        _refuse(name + " must be bounded path text")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        _refuse(name + " must be an exact absolute path without traversal")
    return value


def deletion_size(adapter_id, plan):
    """(number of items, bytes) that the permanent deletion ``adapter_id`` removes, read from its plan where
    DELETION_SOURCES says (never from whichever key happens to be present); (None, None) for an adapter whose facts list
    no permanent data loss. A plan that also carries another deletion's source, or a row size that is not an integer of
    0 or more, is refused."""
    if "permanent_data_loss" not in pc_records.ADAPTERS[adapter_id]["acknowledgments"]:
        return None, None
    source = DELETION_SOURCES.get(adapter_id)
    if source is None:
        _refuse("This permanent deletion is not built yet")
    if not isinstance(plan, dict) or (set(DELETION_SOURCES.values()) - {source}) & set(plan):
        _refuse("A permanent deletion's plan lists what it deletes in exactly one place")
    try:
        if source == "rows_file":
            sizes, count = [plan["rows_file"]["row_bytes"]], plan["rows_file"]["row_count"]
        else:
            rows = plan["files"] if source == "files" else [record["original"] for record in plan["receipt"]["records"]]
            sizes, count = [row["size"] for row in rows], len(rows)
    except (KeyError, TypeError) as error:
        raise pc_records.Refusal("storage-payload", "A permanent deletion's plan must list the items it deletes and their sizes") from error
    if type(count) is not int or count < 1 or any(type(size) is not int or size < 0 for size in sizes):
        _refuse("A permanent deletion's plan must list at least one item, each with a size of 0 or more bytes")
    return count, sum(sizes)


def validate_payload(payload, *, adapter_id, mode, plan_sha256):
    """Return the storage ``payload`` of a reviewed action if it binds exactly ``adapter_id``, ``mode`` and the
    storage plan whose digest is ``plan_sha256``; raise pc_records.Refusal otherwise."""
    pc_records.require_schema(payload, PAYLOAD)
    fields = {"schema", "schema_version"}
    if set(payload) - (PAYLOAD_REQUIRED | PAYLOAD_OPTIONAL | fields) or (PAYLOAD_REQUIRED | fields) - set(payload):
        _refuse("Unexpected or missing storage payload fields")
    kind = plan_kind(adapter_id)
    plan = payload["storage_plan"]
    if (payload["operation"] != adapter_id or payload["mode"] != mode or not isinstance(plan, dict)
            or not isinstance(plan_sha256, str) or pc_records.digest(plan) != plan_sha256
            or payload["storage_plan_sha256"] != plan_sha256):
        _refuse("Storage adapter payload does not match the exact reviewed lower-level plan")
    pc_records.require_schema(plan, PLAN)
    if plan.get("kind") != kind:
        _refuse("Storage plan kind differs from the fixed reviewed adapter")
    roots = payload["protected_roots"]
    if not isinstance(roots, list) or len(roots) > MAX_PROTECTED_ROOTS or len(set(map(str, roots))) != len(roots):
        _refuse("Storage adapter needs bounded unique explicit protected roots")
    for root in roots:
        absolute_path(root, "A protected root")
    absolute_path(payload["output_root"], "The storage output root")
    if "restore_probe_destination" in payload:
        if adapter_id != pc_records.ADAPTER_STORAGE_BACKUP_CREATE:
            _refuse("Only a reviewed backup can include a restore-probe destination")
        absolute_path(payload["restore_probe_destination"], "The restore-probe destination")
    # The typed reply names this count and size, so they must be exactly what the plan deletes.
    expected = deletion_size(adapter_id, plan)
    if expected == (None, None):
        if DELETION_FIELDS & set(payload):
            _refuse("Only a permanent deletion carries a deletion count and size")
    elif (not DELETION_FIELDS <= set(payload) or type(payload["delete_count"]) is not int or type(payload["delete_bytes"]) is not int
          or (payload["delete_count"], payload["delete_bytes"]) != expected):
        _refuse("A permanent deletion's count and size must be exactly the items and bytes its plan deletes")
    return payload
