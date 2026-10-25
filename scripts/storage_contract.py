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
})
# Every storage record is a kind of patchcairn.storage.
KINDS = frozenset({"inventory", "backup", "restore", "quarantine", "quarantine_restore", "purge", "storage_preconditions",
                   "duplicates", "attempt", "backup_manifest", "backup_receipt", "restore_receipt", "quarantine_receipt",
                   "quarantine_restore_receipt", "purge_receipt", "storage_outcome_verification", "capabilities"})
PAYLOAD_REQUIRED = frozenset({"operation", "storage_plan", "storage_plan_sha256", "output_root", "mode", "protected_roots"})
PAYLOAD_OPTIONAL = frozenset({"restore_probe_destination"})
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
    return payload
