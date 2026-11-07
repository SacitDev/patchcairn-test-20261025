"""Shared storage plumbing mixed into storage_ops.StorageService (see its trust model): the limits, strict storage
records, paths, containment and selections, the selected-root scopes, owner-private output and its records, the
cloud-sync and free-space checks of a backup, and content hashing."""
from __future__ import annotations

import contextlib
import hashlib
import os
import re
import sys
from contextlib import ExitStack
from pathlib import Path

import pc_paths
import pc_records
import scoped_base
import scoped_fs
import storage_contract
import win32_files
from scoped_fs import ScopedRoot, ScopedFSError, capabilities
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, relative_parts

SCHEMA = "patchcairn.storage"
REPOSITORY_ROOT = Path(__file__).absolute().parent.parent
# The in-memory bounds of the code that still reads whole files: restoring, the assessment's limits (checked_limits) and
# the quarantine records. Backups stream and use none of them; each name goes when its last reader streams.
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 48 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
# The published entry bound; the backup checks pc_records.MAX_BACKUP_ENTRIES itself when it runs.
MAX_ENTRIES = pc_records.MAX_BACKUP_ENTRIES
MAX_DEPTH = 48
# A storage control record (plan, attempt, receipt) is read whole: about 1.5 KB per entry at the entry bound.
CONTROL_RECORD_MAX_BYTES = 3 * 512 * pc_records.MAX_BACKUP_ENTRIES
# Kept free on each drive a backup writes to, besides the archive's worst-case size and the control records.
FREE_SPACE_MARGIN_BYTES = 256 << 20
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
# Folder names sync clients create (best effort: a client can be told to sync any folder).
_SYNC_FOLDERS = {"dropbox": "Dropbox", "google drive": "Google Drive", "my drive": "Google Drive",
                 "icloud drive": "iCloud Drive", "icloud drive (archive)": "iCloud Drive"}
_CLOUD_PROVIDERS = {"onedrive": "OneDrive", "googledrive": "Google Drive", "dropbox": "Dropbox", "box": "Box",
                    "icloud": "iCloud Drive"}
# Windows cloud-file attributes (pinned, unpinned, recall on open, recall on data access, offline) and macOS SF_DATALESS.
_CLOUD_ATTRIBUTES = 0x80000 | 0x100000 | 0x40000 | 0x400000 | 0x1000
_SF_DATALESS = 0x40000000
# A selected root keeps this identity across a restart; a POSIX device number does not (scoped_fs.PosixRoot).
_ROOT_KEYS = ("device", "inode", "mode") if os.name == "nt" else ("inode", "mode")
_SIZE_UNITS = (("TB", 10 ** 12), ("GB", 10 ** 9), ("MB", 10 ** 6), ("KB", 10 ** 3))
# The refusals of a chosen folder that is not there or cannot be reached.
_DESTINATION_MISSING = frozenset({"missing-entry", "access-sharing-or-missing", "admission"})
_DESTINATION_NOT_FOUND = ("The backup drive or folder cannot be found: {}. Plug the drive in, check that it shows in File Explorer or "
                          "Finder, then ask me to try again. Nothing was changed.")
_SYNCED_DESTINATION = ("The backup destination is synced by {}, which would copy the backup to the cloud as it is written; choose a "
                       "folder that is not synced")
_SYNCED_WORK_FOLDER = ("The PatchCairn folder is inside {}, which would copy the backup to the cloud as it is written. Move the "
                       "PatchCairn folder to a folder that is not synced, then start again. Nothing was changed.")
_TOO_BIG_FOR_DRIVE = ("This drive cannot hold one file of {} or more, and this backup can reach that size. Choose another drive or "
                      "fewer files. Nothing was changed.")
# What a work folder that cannot be used means to a person, by refusal code.
_ANOTHER_ACCOUNT = "another account can reach this folder"
_WORK_FOLDER_REASONS = {"private-owner-or-mode-refused": _ANOTHER_ACCOUNT, "private-dacl-unprotected": _ANOTHER_ACCOUNT,
                        "private-dacl-broad-or-unknown": _ANOTHER_ACCOUNT, "private-link-or-type-refused": "a folder on this path is a link",
                        "private-local-path-required": "it is on a network path or the path is longer than 240 characters"}


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
        return pc_records.decode_strict(data, max_bytes=CONTROL_RECORD_MAX_BYTES, max_nodes=CONTROL_RECORD_MAX_BYTES)
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
    """True when ``path`` is ``parent`` or below it, compared part by part by private_workspace.relative_parts (on
    Windows by the file system's own rule, so a look-alike such as U+212A is not "k"). A pair it cannot decide (a part
    Windows would trim, no Windows API) is refused, never read as "outside"."""
    if relative_parts(path, parent) is not None:
        return True
    if relative_parts(path, path) is None or relative_parts(parent, parent) is None:
        raise StorageRefusal("These folders cannot be compared safely", code="containment-undecidable")
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


def attempt_record(operation, plan_sha256, plan_file, plan, **names):
    """The attempt record of one storage operation: the plan's digest, its hash-bound file and its entry count, plus
    ``names`` (a backup's folder and temporary file names, recorded before any of them exists)."""
    entries = plan.get("files", plan.get("receipt", {}).get("records", []))
    return {**storage_value("attempt"), "operation": operation, "plan_sha256": plan_sha256, "plan_file": plan_file,
            "entry_count": len(entries), "started_utc": pc_records.utc_now(), **names,
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


def about_size(size):
    """A byte count as people read it: "about 52.4 GB" (1 GB = 1,000,000,000 bytes); under 1,000 bytes exactly."""
    if size < 1000:
        return "1 byte" if size == 1 else f"{size:,} bytes"
    unit, scale = next((unit, scale) for unit, scale in _SIZE_UNITS if round(size / scale, 1) >= 1 or scale == 10 ** 3)
    return f"about {size / scale:.1f} {unit}"


def shown_path(path):
    """A path as a person reads it: control and format characters are escaped, so a name cannot hide text; backslashes stay."""
    return pc_paths.display(str(path)).replace(chr(92) + "u005c", chr(92))


def admitted_destination(folder, non_private_destination):
    """The chosen backup folder admitted as a destination; a folder that is not there says so in plain words, with its path
    (StorageRefusal destination-not-found)."""
    try:
        return scoped_fs.admit_destination(str(folder), non_private_destination=non_private_destination)
    except ScopedFSError as error:
        if error.code not in _DESTINATION_MISSING:
            raise
        raise StorageRefusal(_DESTINATION_NOT_FOUND.format(shown_path(folder)), code="destination-not-found") from error


def _lstat(path):
    return os.stat(path, follow_symlinks=False)


def synced_folder(path, *, probe=None):
    """The cloud service that syncs the folder ``path``, best effort, or None: a OneDrive folder named by the OneDrive,
    OneDriveConsumer or OneDriveCommercial environment variables; a Dropbox, Google Drive or iCloud Drive folder by
    name; macOS ~/Library/CloudStorage/<provider> and ~/Library/Mobile Documents (iCloud); and a folder or ancestor with
    cloud placeholder attributes (Windows cloud files, macOS dataless). Nothing is opened or recalled.

    ``probe`` replaces the system facts: a mapping with any of "platform" (sys.platform), "home" (the home folder),
    "environ" (the environment) and "stat" (os.stat without following links), so every branch runs on every system."""
    facts = {"platform": sys.platform, "home": os.path.expanduser("~"), "environ": os.environ, "stat": _lstat, **(probe or {})}
    path = Path(path)
    if not path.is_absolute():
        raise StorageRefusal("An absolute folder is required")
    for name in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        folder = facts["environ"].get(name)
        if folder and Path(folder).is_absolute() and relative_parts(path, folder) is not None:
            return "OneDrive"
    home = Path(facts["home"])
    if facts["platform"] == "darwin" and home.is_absolute():
        provider = relative_parts(path, home / "Library" / "CloudStorage")
        if provider:
            name = provider[0].split("-", 1)[0]
            return _CLOUD_PROVIDERS.get(name.casefold(), name[:40])
        if relative_parts(path, home / "Library" / "Mobile Documents") is not None:
            return "iCloud Drive"
    for part in path.parts[1:]:
        key = part.casefold()
        if key in _SYNC_FOLDERS or key.startswith("dropbox ("):
            return _SYNC_FOLDERS.get(key, "Dropbox")
    for folder in (path, *path.parents):
        try:
            info = facts["stat"](folder)
        except (OSError, ValueError):
            continue
        if getattr(info, "st_file_attributes", 0) & _CLOUD_ATTRIBUTES or getattr(info, "st_flags", 0) & _SF_DATALESS:
            return "a cloud storage service"
    return None


def archive_bound(rows):
    """The most bytes backup.zip can take for ``rows`` (each with "entry" and "size"): DEFLATE's worst case (stored
    blocks, as zlib's deflateBound) plus the local header, ZIP64 extras, central directory entry and data descriptor of
    each entry, and the end records."""
    total = 22 + 56 + 20
    for row in rows:
        size, name = row["size"], len(row["entry"].encode("utf-8"))
        total += size + (size >> 12) + (size >> 14) + (size >> 25) + 13 + 2 * (30 + 46 + name + 32) + 24
    return total


class StoragePolicy:
    """StorageService state and the checks every family shares: output root, scopes, privacy, bindings, preconditions.

    The only mixin that holds state: the output root, the protected roots, an admitted backup destination and, during
    one service call that may exempt the user's Temp folder, the folder win32_files.user_temp_folder() named. A service
    given an admitted destination owns that root: closing the service (it is a context manager) closes it."""

    def __init__(self, *, output_root, quiet_workspace, protected_roots=None, backup_destination=None):
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
        if backup_destination is not None and (not isinstance(backup_destination, scoped_base.RootBase)
                                               or backup_destination.destination is not True):
            raise StorageRefusal("A backup destination must be a folder admitted as a backup destination")
        self.backup_destination = backup_destination
        self._junk_roots = None
        self._protected_near = {}

    def close(self):
        """Release the admitted backup destination, if this service was given one. Closing twice changes nothing."""
        if self.backup_destination is not None:
            self.backup_destination.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    @contextlib.contextmanager
    def _junk_call(self):
        """One service call that may exempt the user's Temp folder: win32_files.user_temp_folder() is read once, here,
        and never taken from a plan; None (no exemption) where Windows cannot confirm the folder."""
        if self._junk_roots is not None:
            raise StorageRefusal("Service calls do not nest", code="junk-scope")
        self._junk_roots = [win32_files.user_temp_folder()]
        try:
            yield
        finally:
            self._junk_roots = None

    def _junk_root(self, junk):
        if not junk:
            return None
        if self._junk_roots is None:
            raise StorageRefusal("The Temp exemption is read once per service call", code="junk-scope")
        return self._junk_roots[0]

    def _protected_root(self, path, *, junk=False):
        """A source root that must be refused: pc_paths' absolute-path floor or a retained root. ``junk`` (never for a
        root the person selected) exempts the user's Temp folder of this service call; every other rule stays."""
        return (pc_paths.protected_root(str(path), junk_root=self._junk_root(junk))
                or any(within(path, root) for root in self.protected_roots))

    def _protected_entry(self, root, relative, *, junk=False):
        return (pc_paths.protected(relative, root=str(root), junk_root=self._junk_root(junk))
                or self._inside_protected(root, root / relative))

    def _inside_protected(self, root, path):
        """True when ``path``, an entry below the selected ``root``, lies in a protected root. This runs for every entry of
        an assessment, so a protected root apart from ``root``, which no entry below it can lie in, is ruled out once per
        selected root; the first ``within`` still refuses a path that cannot be compared."""
        if not self.protected_roots:
            return False
        near = self._protected_near.get(root)
        if near is None:
            near = self._protected_near[root] = [item for item in self.protected_roots if within(root, item) or within(item, root)]
        return within(path, path) and any(within(path, item) for item in near)

    def _scope(self, path):
        self._require_private_output()
        return ScopedRoot(path, quiet_workspace=True, max_entries=MAX_ENTRIES)

    @staticmethod
    def _privacy_hold(exc):
        detail = exc.code + ("" if str(exc) == exc.code else ": " + str(exc))
        return StorageRefusal("Owner-private storage namespace or file could not be verified (" + detail
                              + "); existing permissions will not be changed. Preserve any attempted outputs and receipts", code=exc.code)

    @staticmethod
    def _work_hold(exc):
        """_privacy_hold for PatchCairn's own work folder: what is wrong in plain words, and what the person can do."""
        reason = _WORK_FOLDER_REASONS.get(exc.code) or ("its permissions could not be confirmed" if str(exc) == exc.code else str(exc))
        return StorageRefusal(f"PatchCairn cannot use its work folder here: {reason}. Nothing was changed. Move the PatchCairn folder "
                              "to a plain local folder that only you use, then start again.", code=exc.code)

    def _require_private_output(self):
        try:
            ensure_private_directory(self.output_root, boundary=REPOSITORY_ROOT / "work")
        except PrivateWorkspaceError as exc:
            raise self._work_hold(exc) from exc

    def _private_directory(self, relative, *, create=False):
        self._require_private_output()
        path = self.output_root / checked_relative(relative)
        try:
            return ensure_private_directory(path, create=create, boundary=self.output_root)
        except PrivateWorkspaceError as exc:
            raise self._work_hold(exc) from exc

    def _private_created_file(self, relative):
        try:
            ensure_private_file(self.output_root / checked_relative(relative))
        except PrivateWorkspaceError as exc:
            raise self._work_hold(exc) from exc

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
        return checked_relative("/".join(relative_parts(absolute, self.output_root)))

    def _outside_sources(self, destination, roots):
        path = checked_absolute(destination)
        relative = self._output_relative(path)
        self._apart_from_sources(path, roots)
        return relative

    @staticmethod
    def _apart_from_sources(path, roots):
        for item in roots:
            source = checked_absolute(item["path"])
            if within(path, source) or within(source, path):
                raise StorageRefusal("Backup/quarantine output must be outside every selected source root")

    def _open_sources(self, stack, roots):
        result = {}
        for item in roots:
            source = stack.enter_context(self._scope(item["path"]))
            current = source.inspect("")
            if any(current[key] != item["record"][key] for key in _ROOT_KEYS):
                raise StorageRefusal("Selected source root identity changed")
            result[item["root_id"]] = source
        return result

    def _source_roots(self, stack, roots):
        """Each selected source root as a RootBase (scoped_fs.open_root), with its reviewed identity; a root admitted as
        a backup destination is refused as a source."""
        self._require_private_output()
        result = {}
        for item in roots:
            source = stack.enter_context(scoped_fs.open_root(item["path"], max_entries=MAX_ENTRIES))
            if source.destination is not False:
                raise StorageRefusal("A folder admitted as a backup destination is never a backup source", code="destination-as-source")
            current = source.inspect("")
            if any(current[key] != item["record"][key] for key in _ROOT_KEYS):
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
        for original, reviewed in zip(originals, rows):
            plain = {key: value for key, value in reviewed.items() if key != "entry"}
            if {**plain, "sha256": None} != {**original, "sha256": None}:
                raise StorageRefusal("Selected file mapping differs from its exact admitted ordinary-file inventory")
            if plan["kind"] == "backup" and reviewed.get("entry") != original["root_id"] + "/" + original["relative_path"]:
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

    # Backups ----------------------------------------------------------------------------------------------------------

    @staticmethod
    def _require_unsynced(path, refusal=_SYNCED_DESTINATION):
        service = synced_folder(path)
        if service is not None:
            raise StorageRefusal(refusal.format(service), code="synced-folder")

    def _backup_destination_root(self, stack, plan, *, create=False):
        """The folder that holds backup folders, as a RootBase: the admitted destination this service was given, else
        derived from the hash-bound plan (a private folder in the owned output root, or an external folder admitted again
        here). The plan's ``external`` fact must agree with its path. A missing output folder is created privately only
        with ``create``; before that its parent stands in."""
        destination = checked_absolute(plan["destination"])
        external = not within(destination, self.output_root)
        if plan["external"] is not external:
            raise StorageRefusal("The reviewed backup's destination is not where its plan says it is")
        if external:
            root = self.backup_destination
            if root is None:
                root = stack.enter_context(scoped_fs.admit_destination(str(destination), non_private_destination=plan["non_private_destination"]))
            elif not same_folder(root.root, destination):
                raise StorageRefusal("The admitted backup destination is not the reviewed one")
            return root
        if self.backup_destination is not None:
            raise StorageRefusal("The reviewed backup stays in the owned output folder")
        self._require_private_output()
        if destination != self.output_root:
            try:
                ensure_private_directory(destination, create=create, parents=create, exist_ok=True, boundary=self.output_root)
            except PrivateWorkspaceError as exc:
                if create or exc.code != "private-directory-missing":
                    raise self._work_hold(exc) from exc
                return self._backup_destination_root(stack, {**plan, "destination": str(destination.parent)})
        return stack.enter_context(scoped_fs.open_root(str(destination), max_entries=MAX_ENTRIES))

    def _backup_preflight(self, plan, destination_root, output_root):
        """Before any write: the worst-case archive (backup.zip) fits the destination drive (FAT32 refuses an archive of 4
        GiB or more through admit_new), and free space covers it, the control records and a margin, on the destination
        and on the drive of the owned work folder (one sum when they share a drive)."""
        archive = archive_bound(plan["files"])
        folder = "00000000T000000Z-" + plan["label"]  # as long as the run-time folder name
        try:
            destination_root.admit_new(folder + "/backup.zip", archive)
        except ScopedFSError as error:
            if error.code != "file-too-large-for-volume":
                raise
            limit = destination_root.max_file_bytes
            raise StorageRefusal(_TOO_BIG_FOR_DRIVE.format("4 GB" if limit == scoped_base.FAT32_MAX_FILE_BYTES else about_size(limit)),
                                 code=error.code) from error
        destination_root.admit_new(folder + "/manifest.json", plan["cost"]["manifest_bytes_at_most"])
        destination_root.admit_new(folder + "/README.txt", 1 << 20)
        records = plan["cost"]["control_record_bytes"]
        destination_need = archive + plan["cost"]["manifest_bytes_at_most"] + FREE_SPACE_MARGIN_BYTES
        output_need = records + FREE_SPACE_MARGIN_BYTES
        same = destination_root.inspect("")["device"] == output_root.inspect("")["device"]
        checks = [(destination_root, destination_need + (records if same else 0), "the backup drive")]
        if not same:
            checks.append((output_root, output_need, "the drive of PatchCairn's work folder"))
        for root, need, name in checks:
            free = root.free_bytes()
            if free < need:
                raise StorageRefusal(f"Not enough free space on {name}: {about_size(need)} needed, {about_size(free)} free. "
                                     "Free some space or choose another drive.", code="disk-full")

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
        if kind == "backup":
            return {**snapshot, **self._backup_preconditions(plan)}
        with self._scope(self.output_root) as output:
            snapshot["output_root_record"] = output.inspect("")
            if kind == "quarantine":
                inventory = plan["inventory"]
                self._fresh_inventory(inventory)
                selected = selection(inventory, [row["key"] for row in plan["files"]])
                self._content_budget(selected, inventory["limits"])
                self._quarantine_source_privacy(inventory["roots"], selected)
                with ExitStack() as stack:
                    sources = self._open_sources(stack, inventory["roots"])
                    for original, reviewed in zip(selected, plan["files"]):
                        hashed = self._hashed(sources[original["root_id"]], original, inventory["limits"])
                        if hashed != {key: value for key, value in reviewed.items() if key != "entry"}:
                            raise StorageRefusal("Exact selected content differs from the reviewed storage plan")
                snapshot["inventory_sha256"] = inventory["inventory_sha256"]
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
                verified = self.verify_backup(receipt=plan["receipt"], archive_data=False)
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

    def _backup_preconditions(self, plan):
        """A backup's checks before begin, without reading file contents (the backup re-hashes every file as it reads
        it): an external destination admitted by the caller, which reserves it first (verification and reconciliation
        alone derive it from the plan), the plan's scope, the unchanged inventory and selection, the entry bound, no
        cloud-synced work folder or destination, and the free-space preflight on every drive the backup writes to."""
        inventory = plan["inventory"]
        if plan["external"] and self.backup_destination is None:
            raise StorageRefusal("A backup to another drive runs only with that folder admitted and reserved first",
                                 code="destination-not-admitted")
        self._reviewed_files(plan)
        if len(plan["files"]) > pc_records.MAX_BACKUP_ENTRIES:
            raise StorageRefusal("A backup holds at most " + str(pc_records.MAX_BACKUP_ENTRIES) + " files", code="entry-cap")
        self._fresh_inventory(inventory)
        self._apart_from_sources(checked_absolute(plan["destination"]), inventory["roots"])
        self._require_unsynced(self.output_root, _SYNCED_WORK_FOLDER)
        self._require_unsynced(checked_absolute(plan["destination"]))
        with ExitStack() as stack:
            output = stack.enter_context(scoped_fs.open_root(str(self.output_root), max_entries=MAX_ENTRIES))
            destination = self._backup_destination_root(stack, plan)
            self._backup_preflight(plan, destination, output)
            return {"output_root_record": output.inspect(""), "inventory_sha256": inventory["inventory_sha256"],
                    "destination_record": destination.inspect("")}

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
        # own hash-bound file, so the attempt record keeps only digests and counts.
        name = f"attempt-{operation}-{expected}.json"
        plan_file = f"plan-{operation}-{expected}.json"
        self._write_json(output, name, attempt_record(operation, expected, plan_file, plan))
        self._write_json(output, plan_file, plan)
        return name

    def _write_record(self, root, relative, value):
        """A control record created exclusively and privately through the RootBase ``root`` (streamed, so a large plan
        is never capped by the small in-memory writer); its committed record, which must be durable."""
        data = canonical(value)
        if len(data) > CONTROL_RECORD_MAX_BYTES:
            raise StorageRefusal("A storage control record exceeds its bound")
        with root.open_new(checked_relative(relative)) as out:
            for start in range(0, len(data), scoped_base.CHUNK_BYTES):
                out.write(data[start:start + scoped_base.CHUNK_BYTES])
            record = out.commit()
        if record.pop("durable") is not True or record["sha256"] != sha256(data):
            raise StorageRefusal("A storage control record could not be written to the drive", code="sync-failed")
        return record

    def _read_record(self, root, relative, kind, message, *, expected_sha256=None):
        """A strict storage record of ``kind`` read through ``root``, the RootBase of the output folder, after the file's
        privacy is admitted (no byte of a refused record is read); with ``expected_sha256`` its bytes must have that digest.
        A record that does not exist raises missing-entry."""
        root.inspect(checked_relative(relative))
        self._private_created_file(relative)
        record = root.inspect(relative, hash_file=True)
        if record["kind"] != "file" or record["size"] > CONTROL_RECORD_MAX_BYTES:
            raise StorageRefusal(message)
        chunks = []
        root.stream_to(relative, expected=record, writer=chunks.append)
        data = b"".join(chunks)
        if expected_sha256 is not None and sha256(data) != expected_sha256:
            raise StorageRefusal(message)
        return checked_record(decode_storage(data, message), kind, message)

    def artifact_sha256(self, relative):
        """SHA-256 of a private record below the output root, read through the pinned root after privacy admission."""
        relative = checked_relative(relative)
        self._private_created_file(relative)
        with scoped_fs.open_root(str(self.output_root), max_entries=MAX_ENTRIES) as output:
            return output.inspect(relative, hash_file=True)["sha256"]


def same_folder(left, right):
    """True when two absolute folder paths name the same folder, compared as within() does."""
    return within(Path(left), Path(right)) and within(Path(right), Path(left))
