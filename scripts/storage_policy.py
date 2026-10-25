"""Shared storage plumbing mixed into storage_ops.StorageService (see its trust model): the caps, strict storage
records, paths, limits and selections, the selected-root scope, owner-private output and its records, content hashing."""
from __future__ import annotations

import hashlib
import re
from contextlib import ExitStack
from pathlib import Path

import pc_paths
import pc_records
import storage_contract
from scoped_fs import ScopedRoot, ScopedFSError, capabilities
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file

SCHEMA = "patchcairn.storage"
REPOSITORY_ROOT = Path(__file__).absolute().parent.parent
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 48 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_DEPTH = 48
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")


class StorageRefusal(pc_records.Refusal):
    """An explicit hold; preserve evidence and do not use a weaker fallback."""

    def __init__(self, message, *, code="storage-refusal"):
        super().__init__(code, message)


def _shared(check, *args, **kwargs):
    """Run a shared pc_records/pc_paths check; its refusal becomes a StorageRefusal with the same code."""
    try:
        return check(*args, **kwargs)
    except (pc_records.Refusal, pc_paths.PathRefusal) as exc:
        if isinstance(exc, StorageRefusal):
            raise
        raise StorageRefusal(str(exc), code=exc.code) from exc


def checked_record(value, kind, message):
    """A storage record of ``kind``; ``message`` explains a missing or different record."""
    if not isinstance(value, dict) or value.get("kind") != kind:
        raise StorageRefusal(message)
    return _shared(storage_contract.read_storage, value)


def decode_storage(data, message):
    """Strictly decoded hash-bound storage bytes; ``message`` explains a refusal. Every value and every bracket
    takes at least one byte, so a node cap equal to the byte cap accepts every record its writer produced."""
    try:
        return pc_records.decode_strict(data, max_bytes=MAX_ARCHIVE_BYTES, max_nodes=MAX_ARCHIVE_BYTES)
    except pc_records.Refusal as exc:
        raise StorageRefusal(message, code=exc.code) from exc


def canonical(value):
    """The canonical record bytes of pc_records.encoded, with a storage refusal."""
    try:
        return pc_records.encoded(value)
    except pc_records.Refusal as exc:
        raise StorageRefusal("Bounded JSON-compatible data required", code=exc.code) from exc


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def plan_sha256(plan):
    return sha256(canonical(plan))


def checked_relative(value):
    """A relative path in the one pc_paths grammar."""
    return _shared(pc_paths.relative, value)


def checked_absolute(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise StorageRefusal("An explicit absolute path without traversal is required")
    return path


def within(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def checked_limits(value=None):
    result = {"max_entries": MAX_ENTRIES, "max_depth": MAX_DEPTH,
              "max_file_bytes": MAX_FILE_BYTES, "max_total_bytes": MAX_TOTAL_BYTES}
    if value is not None:
        if not isinstance(value, dict) or set(value) - set(result):
            raise StorageRefusal("Unknown limits field")
        for key, limit in value.items():
            if type(limit) is not int or not 0 < limit <= result[key]:
                raise StorageRefusal("Limits must be positive and within the compiled safety caps")
            result[key] = limit
    return result


def content_permission(value):
    if value is not True:
        raise StorageRefusal("Explicit permission to read selected ordinary-file contents is required")


def inventory_files(inventory):
    return {item["key"]: item for item in inventory["entries"] if item["kind"] == "file"}


def fingerprint(inventory):
    try:
        return sha256(canonical({key: inventory[key] for key in ("schema", "schema_version", "roots", "entries", "not_included", "limits")}))
    except (KeyError, TypeError) as exc:
        raise StorageRefusal("Inventory binding is missing or changed") from exc


def bound_plan(plan, expected, kind):
    if not isinstance(expected, str) or not HASH_RE.fullmatch(expected) or plan_sha256(plan) != expected:
        raise StorageRefusal("The exact reviewed plan hash is required; this is not proof of owner consent")
    checked_record(plan, kind, "Foreign or wrong-kind storage plan")


def storage_value(kind, **fields):
    return {"schema": SCHEMA, "schema_version": pc_records.SCHEMA_VERSION, "kind": kind, **fields}


def attempt_record(operation, plan_sha256, plan_file, plan):
    """The attempt record of one storage operation: the plan's digest, its hash-bound file and its entry count."""
    entries = plan.get("files", plan.get("receipt", {}).get("records", []))
    return {**storage_value("attempt"), "operation": operation, "plan_sha256": plan_sha256, "plan_file": plan_file,
            "entry_count": len(entries), "started_utc": pc_records.utc_now(),
            "status": "attempted; inspect immutable step and outcome receipts before recovery", "automatic_retry": False}


def new_plan(kind, **fields):
    return {**storage_value(kind), "created_utc": pc_records.utc_now(),
            "exclusive_workspace_required": True, "not_an_os_sandbox": True, **fields}


def selection(inventory, selected):
    if not isinstance(selected, (list, tuple)) or not selected or len(selected) != len(set(selected)):
        raise StorageRefusal("An exact, nonempty, unique selected file list is required")
    files = inventory_files(inventory)
    if any(not isinstance(key, str) or key not in files for key in selected):
        raise StorageRefusal("A target is unknown, excluded or not an ordinary inventoried file")
    return [files[key] for key in sorted(selected)]


class StoragePolicy:
    """StorageService state and the checks every family shares: output root, scopes, privacy, bindings, preconditions."""

    def __init__(self, *, output_root, quiet_workspace, protected_roots=None):
        if quiet_workspace is not True:
            raise StorageRefusal("A quiet, exclusively controlled workspace is required")
        self.output_root = checked_absolute(output_root)
        work = REPOSITORY_ROOT / "work"
        if not within(self.output_root, work) or self.output_root == work:
            raise StorageRefusal("Output must be an existing owned child of this toolkit's work directory")
        self._require_private_output()
        self.quiet_workspace = True
        if protected_roots is not None and (not isinstance(protected_roots, (list, tuple)) or len(protected_roots) > storage_contract.MAX_PROTECTED_ROOTS):
            raise StorageRefusal("Protected roots require a bounded explicit path list")
        self.protected_roots = tuple(checked_absolute(path) for path in (protected_roots or []))

    def _protected_root(self, path):
        """A selected source root that must be refused: pc_paths' absolute-path floor or a retained root."""
        return pc_paths.protected_root(str(path)) or any(within(path, root) for root in self.protected_roots)

    def _protected_entry(self, root, relative):
        return pc_paths.protected(relative, root=str(root)) or any(within(root / relative, item) for item in self.protected_roots)

    def _scope(self, path):
        self._require_private_output()
        return ScopedRoot(path, quiet_workspace=True, max_entries=MAX_ENTRIES)

    @staticmethod
    def _privacy_hold(exc):
        return StorageRefusal("Owner-private storage namespace or file could not be verified (" + exc.code
                              + "); existing permissions will not be changed. Preserve any attempted outputs and receipts", code=exc.code)

    def _require_private_output(self):
        try:
            ensure_private_directory(self.output_root, boundary=REPOSITORY_ROOT / "work")
        except PrivateWorkspaceError as exc:
            raise self._privacy_hold(exc) from exc

    def _private_directory(self, relative, *, create=False):
        self._require_private_output()
        path = self.output_root / checked_relative(relative)
        try:
            return ensure_private_directory(path, create=create, boundary=self.output_root)
        except PrivateWorkspaceError as exc:
            raise self._privacy_hold(exc) from exc

    def _private_created_file(self, relative):
        try:
            ensure_private_file(self.output_root / checked_relative(relative))
        except PrivateWorkspaceError as exc:
            raise self._privacy_hold(exc) from exc

    def _create_private_file(self, output, relative, *, data, max_bytes):
        relative = checked_relative(relative)
        self._require_private_output()
        if "/" in relative:
            self._private_directory(relative.rsplit("/", 1)[0])
        # The checked native creator inherits the verified private Windows DACL,
        # or creates POSIX mode 0600. No bytes enter a broadly readable namespace.
        record = output.create_file(relative, data=data, max_bytes=max_bytes)
        self._private_created_file(relative)
        return record

    def _mkdir_private(self, output, relative):
        self._private_directory(relative, create=True)
        return output.inspect(relative)

    def _output_relative(self, path):
        absolute = checked_absolute(path)
        if not within(absolute, self.output_root) or absolute == self.output_root:
            raise StorageRefusal("Output must remain below the exact owned output root")
        return checked_relative(absolute.relative_to(self.output_root).as_posix())

    def _outside_sources(self, destination, roots):
        path = checked_absolute(destination)
        relative = self._output_relative(path)
        for item in roots:
            source = checked_absolute(item["path"])
            if within(path, source) or within(source, path):
                raise StorageRefusal("Backup/quarantine output must be outside every selected source root")
        return relative

    def _open_sources(self, stack, roots):
        result = {}
        for item in roots:
            source = stack.enter_context(self._scope(item["path"]))
            current = source.inspect("")
            if any(current[key] != item["record"][key] for key in ("device", "inode", "mode")):
                raise StorageRefusal("Selected source root identity changed")
            result[item["root_id"]] = source
        return result

    def _fresh_inventory(self, inventory):
        checked_record(inventory, "inventory", "Inventory binding is missing or changed")
        if fingerprint(inventory) != inventory.get("inventory_sha256"):
            raise StorageRefusal("Inventory binding is missing or changed")
        current = self.assess_storage(roots=[item["path"] for item in inventory["roots"]], limits=inventory["limits"])
        if current["inventory_sha256"] != inventory["inventory_sha256"]:
            raise StorageRefusal("Selected inventory changed, including unknown files; review a fresh plan")
        derived = ("kind", "summary", "extensions", "tree", "size_buckets", "content_read")
        if canonical({key: inventory[key] for key in derived}) != canonical({key: current[key] for key in derived}):
            raise StorageRefusal("Inventory derived report facts changed; use the actual source-backed assessment")

    @staticmethod
    def _content_budget(rows, limit):
        if any(row["size"] > limit["max_file_bytes"] for row in rows):
            raise StorageRefusal("A selected file exceeds the ordinary-file content read cap; select smaller files or review a supported backup route")
        if sum(row["size"] for row in rows) > limit["max_total_bytes"]:
            raise StorageRefusal("Selected contents exceed the total read budget; narrow the content selection")

    @staticmethod
    def _reviewed_files(plan):
        """Enforce ordinary admitted scope even for a direct low-level caller."""
        rows = plan["files"]
        originals = selection(plan["inventory"], [row["key"] for row in rows])
        for index, (original, reviewed) in enumerate(zip(originals, rows), 1):
            plain = {key: value for key, value in reviewed.items() if key != "entry"}
            if {**plain, "sha256": None} != {**original, "sha256": None}:
                raise StorageRefusal("Selected file mapping differs from its exact admitted ordinary-file inventory")
            if plan["kind"] == "backup" and reviewed.get("entry") != f"payload/{index:06d}":
                raise StorageRefusal("ZIP mapping differs from the exact admitted selected order")
        return originals

    @staticmethod
    def _require_absent(output, relative):
        checked_relative(relative)
        if "/" in relative:
            parent = output.inspect(relative.rsplit("/", 1)[0])
            if parent["kind"] != "directory":
                raise StorageRefusal("Reviewed output parent must be an existing ordinary directory")
        try:
            output.inspect(relative)
        except ScopedFSError as exc:
            if getattr(exc, "code", "") != "missing-entry":
                raise
        else:
            raise StorageRefusal("A reviewed new destination is required; overwrite is refused")

    def check_preconditions(self, *, plan, expected_plan_sha256):
        """Read-only native freshness evidence before the engine begins an action.

        This consumes no plan and grants no authority. The operation still
        repeats its native checks immediately before the first side effect.
        """
        kind = plan.get("kind")
        if kind not in {"backup", "restore", "quarantine", "quarantine_restore", "purge"}:
            raise StorageRefusal("Unknown fixed storage operation")
        bound_plan(plan, expected_plan_sha256, kind)
        snapshot = {**storage_value("storage_preconditions"), "storage_plan_sha256": expected_plan_sha256,
                    "operation_kind": kind, "observed_utc": pc_records.utc_now(), "output_root": str(self.output_root),
                    "protected_roots": [str(path) for path in self.protected_roots], "mutation_performed": False}
        with self._scope(self.output_root) as output:
            snapshot["output_root_record"] = output.inspect("")
            if kind in {"backup", "quarantine"}:
                inventory = plan["inventory"]
                self._fresh_inventory(inventory)
                selected = selection(inventory, [row["key"] for row in plan["files"]])
                self._content_budget(selected, inventory["limits"])
                if kind == "quarantine":
                    self._quarantine_source_privacy(inventory["roots"], selected)
                with ExitStack() as stack:
                    sources = self._open_sources(stack, inventory["roots"])
                    for index, (original, reviewed) in enumerate(zip(selected, plan["files"]), 1):
                        hashed = self._hashed(sources[original["root_id"]], original, inventory["limits"])
                        if hashed != {key: value for key, value in reviewed.items() if key != "entry"}:
                            raise StorageRefusal("Exact selected content differs from the reviewed storage plan")
                        if kind == "backup" and reviewed["entry"] != f"payload/{index:06d}":
                            raise StorageRefusal("ZIP member mapping differs from the fixed reviewed order")
                snapshot["inventory_sha256"] = inventory["inventory_sha256"]
                if kind == "backup":
                    relative = self._outside_sources(plan["destination"], inventory["roots"])
                    if relative != plan["destination_relative"]:
                        raise StorageRefusal("Backup output scope changed")
                    self._require_absent(output, relative)
                    self._require_absent(output, relative + ".manifest.json")
                else:
                    relative = self._outside_sources(plan["quarantine_destination"], inventory["roots"])
                    if relative != plan["quarantine_relative"]:
                        raise StorageRefusal("Quarantine scope changed")
                    self._cleanup_targets(inventory, plan["files"], plan["protected"])
                    self._require_absent(output, relative)
                    if capabilities().get("move_noreplace") is not True:
                        raise StorageRefusal("Checked native no-overwrite moves are unavailable; no fallback")
                    if any(row["device"] != snapshot["output_root_record"]["device"] for row in plan["files"]):
                        raise StorageRefusal("Cross-volume quarantine is refused; no copy/delete fallback")
                    if plan["recovery_required"]:
                        self.verified_recovery(backup=plan["recovery_backup"], restoration=plan["recovery_verification"])
            elif kind == "restore":
                verified = self.verify_backup(receipt=plan["receipt"])
                if plan["files"] != verified["manifest"]["files"]:
                    raise StorageRefusal("Restore mapping differs from the verified archive")
                relative = self._outside_sources(plan["destination"], verified["manifest"]["source_roots"])
                if relative != plan["destination_relative"]:
                    raise StorageRefusal("Restore output scope changed")
                self._require_absent(output, relative)
                snapshot["receipt_sha256"] = sha256(canonical(plan["receipt"]))
            else:
                capability = "remove_file" if kind == "purge" else "move_noreplace"
                if capabilities().get(capability) is not True:
                    raise StorageRefusal("Required checked native operation is unavailable; no fallback")
                self._quarantine_current(plan["receipt"])
                snapshot["receipt_sha256"] = sha256(canonical(plan["receipt"]))
                if kind == "purge" and plan["receipt"]["recovery_required"]:
                    self.verified_recovery(backup=plan["receipt"]["recovery_backup"], restoration=plan["receipt"]["recovery_verification"])
                if kind == "quarantine_restore":
                    with ExitStack() as stack:
                        sources = self._open_sources(stack, plan["receipt"]["source_roots"])
                        for row in plan["receipt"]["records"]:
                            original = row["original"]
                            self._require_absent(sources[original["root_id"]], original["relative_path"])
        return snapshot

    @staticmethod
    def _hashed(source, item, limit):
        before = source.inspect(item["relative_path"], hash_file=True, max_bytes=limit["max_file_bytes"])
        original = {key: value for key, value in item.items() if key not in {"root_id", "key"}}
        if {**before, "sha256": None} != {**original, "sha256": None}:
            raise StorageRefusal("Selected file identity or metadata changed")
        return {"root_id": item["root_id"], "key": item["key"], **before}

    def _write_json(self, output, relative, value):
        return self._create_private_file(output, relative, data=canonical(value), max_bytes=MAX_ARCHIVE_BYTES)

    def _attempt(self, output, expected, operation, plan):
        # Exclusive creation consumes a plan even when later validation fails; the exact plan follows in its
        # own hash-bound file, so the attempt record keeps only digests and counts (D-017).
        name = f"attempt-{operation}-{expected}.json"
        plan_file = f"plan-{operation}-{expected}.json"
        self._write_json(output, name, attempt_record(operation, expected, plan_file, plan))
        self._write_json(output, plan_file, plan)
        return name

    def artifact_sha256(self, relative):
        """SHA-256 of a private record below the output root, read through the pinned root after privacy admission."""
        relative = checked_relative(relative)
        self._private_created_file(relative)
        with self._scope(self.output_root) as output:
            return output.inspect(relative, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)["sha256"]
