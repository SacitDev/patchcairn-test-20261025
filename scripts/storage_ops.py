"""Bounded selected-root storage, verified recovery and quarantine primitives.

This is a library with its caller's privileges, not an authorization mechanism or
an OS sandbox. The trusted coordinator must pass the workflow engine's exact
action/plan/scope/review gate before calling mutation methods. No quote, JSON
field or digest in this module authenticates current human consent. A quiet,
exclusively controlled workspace is a required operational assumption.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import zipfile
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

from scoped_fs import ScopedRoot, ScopedFSError, capabilities
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file

VERSION = "patchcairn.storage.v3"
REPOSITORY_ROOT = Path(__file__).absolute().parent.parent
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 48 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_DEPTH = 48
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
PROTECTED_COMPONENTS = frozenset({
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".git",
    "appdata", "keychains", "keychain", "credentials", "credential",
    "passwords", "password", "secrets", "secret", "vault", "wallets",
    "google-chrome", "chromium", "chrome", "firefox", "mozilla", "edge",
    "brave", "brave-browser", "safari", "opera", "vivaldi", "tor browser",
    "chatgpt", "chats", "chat", "sessions", "session", "conversation",
    "conversations", ".codex", ".claude", ".gemini", "signal", "telegram",
    "discord", "slack", "teams", "whatsapp", "keyrings", "keyring", "kwalletd", "kwallet",
    "keepass", "keepassxc", "1password", "bitwarden", "lastpass", "enpass", "dashlane",
    "gnome-keyring", "gcloud", "gh", "git-credential-manager", "git", "rclone",
    "identityservice", "identitycache", "microsoft.aad.brokerplugin", "microsoftaccounts",
    "globalstorage", "workspacestorage", "chatsessions",
    "windows", "system32", "syswow64", "programdata", "$recycle.bin",
    "system volume information", "proc", "sys", "dev", "etc", "boot",
})
PROTECTED_FILES = frozenset({
    ".env", ".npmrc", ".pypirc", ".netrc", "_netrc", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts", "cookies",
    "cookies.sqlite", "history", "history.db", "login data", "web data",
    "key4.db", "logins.json", "cert9.db", "credential.json", "credentials.json",
    "token.json", "tokens.json", "auth.json", "secrets.json", "passwords.json",
    ".git-credentials", ".gitconfig", ".bash_history", ".zsh_history", ".python_history",
    ".psql_history", "consolehost_history.txt", "state.vscdb", "access_tokens.db",
    "credentials.db", "application_default_credentials.json",
})
PROTECTED_SUFFIXES = frozenset({".pem", ".key", ".pfx", ".p12", ".kdbx", ".kdb", ".keyring", ".wallet",
                                ".jks", ".keystore", ".keychain", ".keychain-db"})
BROWSER_PREFIXES = ("google-chrome", "microsoft-edge", "edge", "chrome", "chromium",
                    "firefox", "mozilla", "brave", "brave-browser", "safari", "opera", "vivaldi")


class StorageRefusal(ValueError):
    """An explicit hold; preserve evidence and do not use a weaker fallback."""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise StorageRefusal("Bounded JSON-compatible data required") from exc


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def plan_sha256(plan):
    return sha256(canonical(plan))


def _relative(value):
    if (not isinstance(value, str) or not value or len(value) > 1024 or "\\" in value
            or "\x00" in value or value.startswith("/") or ":" in value):
        raise StorageRefusal("A bounded ordinary relative path is required")
    for part in value.split("/"):
        if (not part or part in {".", ".."} or part.endswith((".", " "))
                or any(ord(char) < 32 or ord(char) == 127 for char in part)
                or re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)):
            raise StorageRefusal("Unsafe or ambiguous relative path")
    return value


def _absolute(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise StorageRefusal("An explicit absolute path without traversal is required")
    return path


def _within(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _protected(relative):
    parts = [part.casefold() for part in relative.replace("\\", "/").split("/")]
    return (any(part in PROTECTED_COMPONENTS for part in parts)
            or any(part.replace(" ", "-") == prefix or part.replace(" ", "-").startswith(prefix + "-")
                   for part in parts for prefix in BROWSER_PREFIXES)
            or any(part in PROTECTED_FILES or part.startswith(".env.") for part in parts)
            or Path(parts[-1]).suffix in PROTECTED_SUFFIXES)


def _limits(value=None):
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


def _content_permission(value):
    if value is not True:
        raise StorageRefusal("Explicit permission to read selected ordinary-file contents is required")


def _files(inventory):
    return {item["key"]: item for item in inventory["entries"] if item["kind"] == "file"}


def _fingerprint(inventory):
    return sha256(canonical({key: inventory[key] for key in ("schema_version", "roots", "entries", "limits")}))


def _bound_plan(plan, expected, kind):
    if not isinstance(expected, str) or not HASH_RE.fullmatch(expected) or plan_sha256(plan) != expected:
        raise StorageRefusal("The exact reviewed plan hash is required; this is not proof of owner consent")
    if plan.get("schema_version") != VERSION or plan.get("kind") != kind:
        raise StorageRefusal("Foreign or wrong-kind storage plan")


def _new_plan(kind, **fields):
    return {"schema_version": VERSION, "kind": kind, "created_utc": _now(),
            "exclusive_workspace_required": True, "not_an_os_sandbox": True, **fields}


def _selection(inventory, selected):
    if not isinstance(selected, (list, tuple)) or not selected or len(selected) != len(set(selected)):
        raise StorageRefusal("An exact, nonempty, unique selected file list is required")
    files = _files(inventory)
    if any(not isinstance(key, str) or key not in files for key in selected):
        raise StorageRefusal("A target is unknown, excluded or not an ordinary inventoried file")
    return [files[key] for key in sorted(selected)]


def _display(value):
    """Prevent filenames from injecting terminal controls or table delimiters."""
    return str(value).encode("unicode_escape").decode("ascii").replace("|", "\\|")


def format_bytes(value):
    if value < 1024:
        return f"{value} B"
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        value /= 1024
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"


def render_storage(inventory, *, width=20):
    """Deterministic chat/terminal table from metadata; no content reads."""
    if type(width) is not int or not 1 <= width <= 60:
        raise StorageRefusal("Bar width must be from 1 to 60")
    summary = inventory["summary"]
    lines = ["Selected storage assessment", "", f"{summary['files']} ordinary files; {format_bytes(summary['logical_bytes'])} logical size.",
             "Physical allocation and reclaimable free space are unknown.", "", "Extension | Files | Logical size | Share", "--- | ---: | ---: | ---"]
    total = summary["logical_bytes"]
    for item in inventory["extensions"]:
        count = round(width * item["logical_bytes"] / total) if total else 0
        lines.append(f"{_display(item['extension'])} | {item['files']} | {format_bytes(item['logical_bytes'])} | {'#' * count}")
    lines.extend(["", "Selected tree | Files | Logical size", "--- | ---: | ---:"])
    for item in inventory["tree"]:
        lines.append(f"{_display(item['key'])} | {item['files']} | {format_bytes(item['logical_bytes'])}")
    lines.extend(["", "File size | Files", "--- | ---:"])
    for item in inventory["size_buckets"]:
        lines.append(f"{_display(item['bucket'])} | {item['files']}")
    lines.extend(["", f"{summary['excluded']} protected entries were excluded before descent or content reads.",
                  "Next: choose exact files for an optional content comparison or a reviewed backup.",
                  "Equal file bytes do not establish that either file can be removed."])
    return "\n".join(lines)


class StorageService:
    """Pure plans plus checked native primitives, with no standalone consent API.

    `output_root` must be an existing, positively owned and owner-private
    directory below this executing repository's work/. The coordinator creates
    its dedicated private namespace; existing permissions are never repaired.
    No external output destination or broad filesystem discovery is supported.
    """

    def __init__(self, *, output_root, quiet_workspace, protected_roots=None):
        if quiet_workspace is not True:
            raise StorageRefusal("A quiet, exclusively controlled workspace is required")
        self.output_root = _absolute(output_root)
        work = REPOSITORY_ROOT / "work"
        if not _within(self.output_root, work) or self.output_root == work:
            raise StorageRefusal("Output must be an existing owned child of this toolkit's work directory")
        self._require_private_output()
        self.quiet_workspace = True
        if protected_roots is not None and (not isinstance(protected_roots, (list, tuple)) or len(protected_roots) > 128):
            raise StorageRefusal("Protected roots require a bounded explicit path list")
        self.protected_roots = tuple(_absolute(path) for path in (protected_roots or []))

    def _protected_path(self, path):
        return _protected(path.as_posix()) or any(_within(path, root) for root in self.protected_roots)

    def _scope(self, path):
        self._require_private_output()
        return ScopedRoot(path, quiet_workspace=True, max_entries=MAX_ENTRIES)

    @staticmethod
    def _privacy_hold(exc):
        return StorageRefusal("Owner-private storage namespace or file could not be verified (" + exc.code
                              + "); existing permissions will not be changed. Preserve any attempted outputs and receipts")

    def _require_private_output(self):
        try:
            ensure_private_directory(self.output_root, boundary=REPOSITORY_ROOT / "work")
        except PrivateWorkspaceError as exc:
            raise self._privacy_hold(exc) from exc

    def _private_directory(self, relative, *, create=False):
        self._require_private_output()
        path = self.output_root / _relative(relative)
        try:
            return ensure_private_directory(path, create=create, boundary=self.output_root)
        except PrivateWorkspaceError as exc:
            raise self._privacy_hold(exc) from exc

    def _private_created_file(self, relative):
        try:
            ensure_private_file(self.output_root / _relative(relative))
        except PrivateWorkspaceError as exc:
            raise self._privacy_hold(exc) from exc

    def _create_private_file(self, output, relative, *, data, max_bytes):
        relative = _relative(relative)
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

    def _private_windows_quarantine_file(self, path):
        # Same-volume Windows rename preserves the original file DACL. Directory
        # privacy alone cannot counter SeChangeNotify traversal privileges.
        # POSIX mode 0644 files remain protected by their private 0700 parent and
        # retain their original permissions; do not chmod ordinary source files.
        if os.name == "nt":
            try:
                ensure_private_file(path)
            except PrivateWorkspaceError as exc:
                raise self._privacy_hold(exc) from exc

    def _quarantine_source_privacy(self, roots, rows):
        if os.name == "nt":
            paths = {row["root_id"]: Path(row["path"]) for row in roots}
            for row in rows:
                self._private_windows_quarantine_file(paths[row["root_id"]] / row["relative_path"])

    def _output_relative(self, path):
        absolute = _absolute(path)
        if not _within(absolute, self.output_root) or absolute == self.output_root:
            raise StorageRefusal("Output must remain below the exact owned output root")
        return _relative(absolute.relative_to(self.output_root).as_posix())

    def _outside_sources(self, destination, roots):
        path = _absolute(destination)
        relative = self._output_relative(path)
        for item in roots:
            source = _absolute(item["path"])
            if _within(path, source) or _within(source, path):
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

    def assess_storage(self, *, roots, limits=None):
        """Read metadata only, pruning protected names before descending."""
        limit = _limits(limits)
        if not isinstance(roots, (list, tuple)) or not roots or len(roots) > 32:
            raise StorageRefusal("Select between one and 32 explicit directory roots")
        paths = sorted((_absolute(root) for root in roots), key=lambda path: os.path.normcase(str(path)))
        for index, path in enumerate(paths):
            if path == Path(path.anchor) or self._protected_path(path):
                raise StorageRefusal("Protected or whole-volume source roots are excluded")
            for earlier in paths[:index]:
                if _within(path, earlier) or _within(earlier, path):
                    raise StorageRefusal("Overlapping or duplicate source roots are refused")
        root_rows, entries, identities = [], [], set()
        total = 0
        for number, path in enumerate(paths, 1):
            root_id = f"r{number:03d}"
            with self._scope(path) as source:
                root_record = source.inspect("")
                identity = (root_record["device"], root_record["inode"])
                if identity in identities:
                    raise StorageRefusal("Aliased selected roots are refused")
                identities.add(identity)
                root_rows.append({"root_id": root_id, "path": str(path), "record": root_record})
                pending = [""]
                while pending:
                    current = pending.pop()
                    for record in sorted(source.list_directory(current), key=lambda item: item["relative_path"]):
                        rel = _relative(record["relative_path"])
                        if len(entries) >= limit["max_entries"] or rel.count("/") >= limit["max_depth"]:
                            raise StorageRefusal("Selected metadata traversal exceeds entry/depth cap; select narrower roots")
                        item = {"root_id": root_id, "key": f"{root_id}/{rel}", **record}
                        if self._protected_path(path / rel):
                            item["kind"] = "excluded"
                            item["reason"] = "protected browser, session, credential or system boundary"
                        elif record["kind"] == "directory":
                            pending.append(rel)
                        elif record["kind"] == "file":
                            file_identity = (record["device"], record["inode"])
                            if record["nlink"] != 1 or file_identity in identities:
                                raise StorageRefusal("Hardlink or repeated file identity is excluded; narrow the selected scope")
                            identities.add(file_identity)
                            total += record["size"]
                        else:
                            raise StorageRefusal("Nonordinary metadata entry; no traversal fallback")
                        entries.append(item)
        entries.sort(key=lambda item: item["key"])
        extensions, tree = {}, {}
        buckets = {"0 B": 0, "1 B–1 KiB": 0, "1 KiB–1 MiB": 0, "1 MiB–16 MiB": 0, "over 16 MiB": 0}
        for item in entries:
            if item["kind"] != "file":
                continue
            size = item["size"]
            extension = Path(item["relative_path"]).suffix.casefold() or "(no extension)"
            group = extensions.setdefault(extension, {"extension": extension, "files": 0, "logical_bytes": 0})
            group["files"] += 1
            group["logical_bytes"] += size
            parts = item["relative_path"].split("/")[:-1]
            for depth in range(len(parts) + 1):
                key = item["root_id"] + ("/" + "/".join(parts[:depth]) if depth else "")
                group = tree.setdefault(key, {"key": key, "files": 0, "logical_bytes": 0})
                group["files"] += 1
                group["logical_bytes"] += size
            bucket = "0 B" if size == 0 else "1 B–1 KiB" if size <= 1024 else "1 KiB–1 MiB" if size <= 1024**2 else "1 MiB–16 MiB" if size <= 16*1024**2 else "over 16 MiB"
            buckets[bucket] += 1
        inventory = {"schema_version": VERSION, "kind": "inventory", "observed_utc": _now(),
                     "roots": root_rows, "entries": entries, "limits": limit,
                     "summary": {"files": sum(item["kind"] == "file" for item in entries),
                                 "directories": sum(item["kind"] == "directory" for item in entries),
                                 "excluded": sum(item["kind"] == "excluded" for item in entries),
                                 "logical_bytes": total, "physical_bytes": None, "reclaimable_bytes": None},
                     "extensions": sorted(extensions.values(), key=lambda row: (-row["logical_bytes"], row["extension"])),
                     "tree": sorted(tree.values(), key=lambda row: row["key"]),
                     "size_buckets": [{"bucket": key, "files": value} for key, value in buckets.items()],
                     "content_read": False, "exclusive_workspace_required": True, "not_an_os_sandbox": True}
        inventory["inventory_sha256"] = _fingerprint(inventory)
        return inventory

    def _fresh_inventory(self, inventory):
        if inventory.get("schema_version") != VERSION or _fingerprint(inventory) != inventory.get("inventory_sha256"):
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
        originals = _selection(plan["inventory"], [row["key"] for row in rows])
        for index, (original, reviewed) in enumerate(zip(originals, rows), 1):
            plain = {key: value for key, value in reviewed.items() if key != "entry"}
            if {**plain, "sha256": None} != {**original, "sha256": None}:
                raise StorageRefusal("Selected file mapping differs from its exact admitted ordinary-file inventory")
            if plan["kind"] == "backup" and reviewed.get("entry") != f"payload/{index:06d}":
                raise StorageRefusal("ZIP mapping differs from the exact admitted selected order")
        return originals

    @staticmethod
    def _require_absent(output, relative):
        _relative(relative)
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
        _bound_plan(plan, expected_plan_sha256, kind)
        snapshot = {"schema_version": VERSION, "kind": "storage_preconditions", "storage_plan_sha256": expected_plan_sha256,
                    "operation_kind": kind, "observed_utc": _now(), "output_root": str(self.output_root),
                    "protected_roots": [str(path) for path in self.protected_roots], "mutation_performed": False}
        with self._scope(self.output_root) as output:
            snapshot["output_root_record"] = output.inspect("")
            if kind in {"backup", "quarantine"}:
                inventory = plan["inventory"]
                self._fresh_inventory(inventory)
                selected = _selection(inventory, [row["key"] for row in plan["files"]])
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
                        self._verified_recovery(backup=plan["recovery_backup"], restoration=plan["recovery_verification"])
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
                    self._verified_recovery(backup=plan["receipt"]["recovery_backup"], restoration=plan["receipt"]["recovery_verification"])
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

    def find_duplicates(self, *, inventory, content_read_authorized, limits=None):
        _content_permission(content_read_authorized)
        limit = _limits(limits or inventory["limits"])
        self._fresh_inventory(inventory)
        candidates = {}
        for item in _files(inventory).values():
            candidates.setdefault(item["size"], []).append(item)
        groups, read_bytes = [], 0
        compared = []
        with ExitStack() as stack:
            sources = self._open_sources(stack, inventory["roots"])
            for size in sorted(candidates):
                if len(candidates[size]) < 2:
                    continue
                hashes = {}
                for item in candidates[size]:
                    read_bytes += size
                    if read_bytes > limit["max_total_bytes"]:
                        raise StorageRefusal("Duplicate content-read byte cap exceeded")
                    hashed = self._hashed(sources[item["root_id"]], item, limit)
                    compared.append(hashed)
                    hashes.setdefault(hashed["sha256"], []).append(hashed)
                for digest, rows in sorted(hashes.items()):
                    if len(rows) > 1:
                        identities = {(row["device"], row["inode"]) for row in rows}
                        if len(identities) != len(rows) or any(row["nlink"] != 1 for row in rows):
                            raise StorageRefusal("Hardlinked aliases cannot be counted as reclaimable duplicates")
                        groups.append({"sha256": digest, "size": size, "files": rows,
                                       "logical_byte_opportunity": size * (len(rows) - 1), "removal_authorized": False})
            for item in compared:
                current = sources[item["root_id"]].inspect(item["relative_path"])
                expected = {key: value for key, value in item.items() if key not in {"root_id", "key"}}
                if {**current, "sha256": None} != {**expected, "sha256": None}:
                    raise StorageRefusal("A duplicate candidate changed before comparison completed")
        return {"schema_version": VERSION, "kind": "duplicates", "inventory_sha256": inventory["inventory_sha256"],
                "groups": groups, "content_bytes_read": read_bytes,
                "logical_byte_opportunity": sum(row["logical_byte_opportunity"] for row in groups),
                "reclaimable_bytes": None, "removal_authorized": False,
                "message": "Equal SHA-256 and size identify byte duplicates; ownership and removability still require review."}

    def plan_backup(self, *, inventory, selected, destination, content_read_authorized, required_recovery=True, exclusions=None):
        _content_permission(content_read_authorized)
        if type(required_recovery) is not bool:
            raise StorageRefusal("Required recovery must be an explicit boolean")
        if exclusions is not None and (not isinstance(exclusions, dict) or any(not isinstance(k, str) or not isinstance(v, str) or not v.strip() or len(v) > 400 for k, v in exclusions.items())):
            raise StorageRefusal("Exclusions require exact keys and bounded human-readable reasons")
        destination_rel = self._outside_sources(destination, inventory["roots"])
        if Path(destination_rel).suffix.casefold() != ".zip":
            raise StorageRefusal("An explicit .zip output filename is required")
        selected_rows = _selection(inventory, selected)
        self._content_budget(selected_rows, inventory["limits"])
        self._fresh_inventory(inventory)
        rows = []
        with ExitStack() as stack:
            sources = self._open_sources(stack, inventory["roots"])
            for index, item in enumerate(selected_rows, 1):
                hashed = self._hashed(sources[item["root_id"]], item, inventory["limits"])
                rows.append({"entry": f"payload/{index:06d}", **hashed})
        skipped = []
        selected_set = set(selected)
        for item in inventory["entries"]:
            if item["key"] not in selected_set:
                default_reason = ("directory metadata and empty-directory preservation are not backed up; selected child contents may be included"
                                  if item["kind"] == "directory" else "not selected; not backed up")
                skipped.append({"key": item["key"], "kind": item["kind"],
                                "reason": item.get("reason") or (exclusions or {}).get(item["key"], default_reason)})
        if exclusions and any(key not in {item["key"] for item in skipped} for key in exclusions):
            raise StorageRefusal("Exclusion reasons may refer only to exact skipped inventory entries")
        return _new_plan("backup", inventory=inventory, files=rows, skipped=skipped,
                         destination=str(_absolute(destination)), destination_relative=destination_rel,
                         required_recovery=required_recovery, compression="deflate", encryption=False,
                         cost={"source_logical_bytes": sum(row["size"] for row in rows),
                               "archive_bytes": None, "peak_additional_disk_bytes": None,
                               "peak_process_memory_bytes": None,
                               "bounded_payload_buffer_bytes": MAX_ARCHIVE_BYTES + MAX_FILE_BYTES,
                               "duration_seconds": None, "money": None,
                               "net_free_space_change_bytes": None})

    def _write_json(self, output, relative, value):
        return self._create_private_file(output, relative, data=canonical(value), max_bytes=MAX_ARCHIVE_BYTES)

    def _attempt(self, output, expected, operation, plan):
        # Exclusive creation consumes a plan even when later validation fails.
        name = f"attempt-{operation}-{expected}.json"
        self._write_json(output, name, {"schema_version": VERSION, "operation": operation,
                                     "plan_sha256": expected, "started_utc": _now(),
                                     "exact_plan": plan,
                                     "status": "attempted; inspect immutable step and outcome receipts before recovery",
                                     "automatic_retry": False})
        return name

    def create_backup(self, *, plan, expected_plan_sha256):
        _bound_plan(plan, expected_plan_sha256, "backup")
        self._reviewed_files(plan)
        self._content_budget(plan["files"], plan["inventory"]["limits"])
        self._fresh_inventory(plan["inventory"])
        destination_rel = self._outside_sources(plan["destination"], plan["inventory"]["roots"])
        if destination_rel != plan["destination_relative"]:
            raise StorageRefusal("Output scope changed")
        with ExitStack() as stack:
            output = stack.enter_context(self._scope(self.output_root))
            sources = self._open_sources(stack, plan["inventory"]["roots"])
            attempt = self._attempt(output, expected_plan_sha256, "backup", plan)
            buffer = io.BytesIO()
            total = 0
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for row in plan["files"]:
                    total += row["size"]
                    if total > plan["inventory"]["limits"]["max_total_bytes"]:
                        raise StorageRefusal("Backup source byte cap exceeded")
                    record = {key: value for key, value in row.items() if key not in {"entry", "root_id", "key"}}
                    data = sources[row["root_id"]].read_bytes(row["relative_path"], expected=record,
                                                              max_bytes=plan["inventory"]["limits"]["max_file_bytes"])
                    if sha256(data) != row["sha256"] or len(data) != row["size"]:
                        raise StorageRefusal("Backup source content changed")
                    info = zipfile.ZipInfo(row["entry"], (1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    archive.writestr(info, data)
                    if buffer.tell() > MAX_ARCHIVE_BYTES:
                        raise StorageRefusal("Backup archive byte cap exceeded")
            archive_data = buffer.getvalue()
            if len(archive_data) > MAX_ARCHIVE_BYTES:
                raise StorageRefusal("Backup archive byte cap exceeded")
            manifest = {"schema_version": VERSION, "kind": "backup_manifest", "created_utc": _now(),
                        "plan_sha256": expected_plan_sha256, "archive_sha256": sha256(archive_data),
                        "archive_bytes": len(archive_data), "files": plan["files"], "skipped": plan["skipped"],
                        "source_roots": plan["inventory"]["roots"], "required_recovery": plan["required_recovery"],
                        "source_logical_bytes": total, "compression_is_not_encryption": True, "limits": plan["inventory"]["limits"]}
            self._verify_zip(archive_data, manifest)
            archive_record = self._create_private_file(output, destination_rel, data=archive_data, max_bytes=MAX_ARCHIVE_BYTES)
            manifest_rel = destination_rel + ".manifest.json"
            manifest_data = canonical(manifest)
            manifest_record = self._create_private_file(output, manifest_rel, data=manifest_data, max_bytes=MAX_ARCHIVE_BYTES)
            receipt = {"schema_version": VERSION, "kind": "backup_receipt", "plan_sha256": expected_plan_sha256,
                       "archive": str(self.output_root / destination_rel), "archive_record": archive_record,
                       "archive_sha256": sha256(archive_data), "manifest": str(self.output_root / manifest_rel),
                       "manifest_record": manifest_record, "manifest_sha256": sha256(manifest_data),
                       "required_recovery": plan["required_recovery"], "attempt": attempt,
                       "verified": True, "encryption": False, "actual_archive_bytes": len(archive_data),
                       "archive_and_manifest_bytes": len(archive_data) + len(manifest_data),
                       "additional_control_record_bytes": None,
                       "source_logical_bytes": total, "finished_utc": _now()}
            # Verify bytes from disk, not just the buffer used to create them.
            self.verify_backup(receipt=receipt)
            self._write_json(output, f"outcome-backup-{expected_plan_sha256}.json", receipt)
            return receipt

    @staticmethod
    def _verify_zip(data, manifest):
        if manifest.get("schema_version") != VERSION or manifest.get("kind") != "backup_manifest":
            raise StorageRefusal("Foreign backup manifest")
        if len(data) > MAX_ARCHIVE_BYTES or sha256(data) != manifest["archive_sha256"] or len(data) != manifest["archive_bytes"]:
            raise StorageRefusal("Archive byte/hash mismatch")
        rows = manifest["files"]
        if not rows or len(rows) > MAX_ENTRIES or len({row["entry"] for row in rows}) != len(rows):
            raise StorageRefusal("Invalid manifest entry list")
        if len({(row["root_id"], row["relative_path"].casefold()) for row in rows}) != len(rows):
            raise StorageRefusal("Case-ambiguous or duplicate restore destinations")
        limit = _limits(manifest["limits"])
        if sum(row["size"] for row in rows) > limit["max_total_bytes"]:
            raise StorageRefusal("Archive expanded byte cap exceeded")
        for row in rows:
            if not re.fullmatch(r"payload/[0-9]{6}", row["entry"]):
                raise StorageRefusal("Unsafe ZIP entry name")
            _relative(row["relative_path"])
            if _protected(row["relative_path"]) or not re.fullmatch(r"r[0-9]{3}", row["root_id"]):
                raise StorageRefusal("Protected or invalid restore target")
            if type(row["size"]) is not int or not 0 <= row["size"] <= limit["max_file_bytes"] or not HASH_RE.fullmatch(row["sha256"]):
                raise StorageRefusal("Invalid bounded archive member")
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
                infos = archive.infolist()
                if len(infos) != len(rows) or [info.filename for info in infos] != [row["entry"] for row in rows]:
                    raise StorageRefusal("ZIP entries differ from the exact reviewed list")
                for info, row in zip(infos, rows):
                    if (info.is_dir() or info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                            or not stat.S_ISREG(info.external_attr >> 16) or info.file_size != row["size"]):
                        raise StorageRefusal("Unsupported, encrypted or nonordinary ZIP member")
                    with archive.open(info) as stream:
                        content = stream.read(limit["max_file_bytes"] + 1)
                    if len(content) != row["size"] or sha256(content) != row["sha256"]:
                        raise StorageRefusal("ZIP member content/hash mismatch")
                    # Reading every member also performs zipfile's CRC verification.
        except (zipfile.BadZipFile, RuntimeError, EOFError, NotImplementedError) as exc:
            raise StorageRefusal("ZIP structure, CRC or bounded content verification failed") from exc
        return True

    def verify_backup(self, *, receipt):
        if receipt.get("schema_version") != VERSION or receipt.get("kind") != "backup_receipt":
            raise StorageRefusal("An exact backup receipt is required")
        archive_rel = self._output_relative(receipt["archive"])
        manifest_rel = self._output_relative(receipt["manifest"])
        with self._scope(self.output_root) as output:
            self._private_created_file(archive_rel)
            self._private_created_file(manifest_rel)
            manifest_data = output.read_bytes(manifest_rel, expected=receipt["manifest_record"], max_bytes=MAX_ARCHIVE_BYTES)
            archive_data = output.read_bytes(archive_rel, expected=receipt["archive_record"], max_bytes=MAX_ARCHIVE_BYTES)
        if sha256(manifest_data) != receipt["manifest_sha256"] or sha256(archive_data) != receipt["archive_sha256"]:
            raise StorageRefusal("Stored backup or manifest changed")
        try:
            manifest = json.loads(manifest_data)
        except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
            raise StorageRefusal("Invalid bounded backup manifest") from exc
        if manifest["plan_sha256"] != receipt["plan_sha256"] or manifest["required_recovery"] != receipt["required_recovery"]:
            raise StorageRefusal("Backup receipt binding changed")
        self._verify_zip(archive_data, manifest)
        return {"manifest": manifest, "archive_data": archive_data, "verified": True}

    def plan_restore(self, *, receipt, destination):
        verified = self.verify_backup(receipt=receipt)
        manifest = verified["manifest"]
        relative = self._outside_sources(destination, manifest["source_roots"])
        with self._scope(self.output_root) as output:
            parent = Path(relative).parent.as_posix()
            if parent != ".":
                output.inspect(parent)
            try:
                output.inspect(relative)
            except (FileNotFoundError, ScopedFSError) as exc:
                # Do not treat access, symlink or capability failures as absence.
                if isinstance(exc, ScopedFSError) and getattr(exc, "code", "") != "missing-entry":
                    raise
            else:
                raise StorageRefusal("Restore requires a new destination; overwrite is refused")
        return _new_plan("restore", receipt=receipt, destination=str(_absolute(destination)),
                         destination_relative=relative, files=manifest["files"], skipped=manifest["skipped"],
                         cost={"logical_bytes_to_write": manifest["source_logical_bytes"], "duration_seconds": None,
                               "physical_bytes_to_write": None, "net_free_space_change_bytes": None})

    def _mkdir_parents(self, output, relative, made):
        parts = relative.split("/")[:-1]
        for count in range(1, len(parts) + 1):
            parent = "/".join(parts[:count])
            if parent not in made:
                self._mkdir_private(output, parent)
                made.add(parent)

    def restore_backup(self, *, plan, expected_plan_sha256):
        _bound_plan(plan, expected_plan_sha256, "restore")
        verified = self.verify_backup(receipt=plan["receipt"])
        if plan["files"] != verified["manifest"]["files"]:
            raise StorageRefusal("Restore file list differs from verified backup")
        relative = self._outside_sources(plan["destination"], verified["manifest"]["source_roots"])
        if relative != plan["destination_relative"]:
            raise StorageRefusal("Restore scope changed")
        records = []
        with self._scope(self.output_root) as output:
            attempt = self._attempt(output, expected_plan_sha256, "restore", plan)
            self._mkdir_private(output, relative)
            made = {"/".join(relative.split("/")[:depth]) for depth in range(1, len(relative.split("/")) + 1)}
            with zipfile.ZipFile(io.BytesIO(verified["archive_data"]), "r") as archive:
                for index, row in enumerate(plan["files"], 1):
                    target = relative + "/" + row["root_id"] + "/" + row["relative_path"]
                    self._mkdir_parents(output, target, made)
                    data = archive.read(row["entry"])
                    if sha256(data) != row["sha256"]:
                        raise StorageRefusal("Restore content changed")
                    record = self._create_private_file(output, target, data=data, max_bytes=MAX_FILE_BYTES)
                    observed = output.read_bytes(target, expected=record, max_bytes=MAX_FILE_BYTES)
                    if sha256(observed) != row["sha256"]:
                        raise StorageRefusal("Restored file verification failed")
                    records.append(record)
                    self._write_json(output, f"step-restore-{expected_plan_sha256}-{index:06d}.json", record)
            receipt = {"schema_version": VERSION, "kind": "restore_receipt", "plan_sha256": expected_plan_sha256,
                       "destination": plan["destination"], "records": records, "verified": True,
                       "backup_plan_sha256": plan["receipt"]["plan_sha256"],
                       "backup_archive_sha256": plan["receipt"]["archive_sha256"],
                       "backup_manifest_sha256": plan["receipt"]["manifest_sha256"],
                       "files": plan["files"],
                       "skipped": plan["skipped"], "attempt": attempt, "finished_utc": _now()}
            self._write_json(output, f"outcome-restore-{expected_plan_sha256}.json", receipt)
            return receipt

    def _verified_recovery(self, *, backup, restoration):
        manifest = self.verify_backup(receipt=backup)["manifest"]
        if (not isinstance(restoration, dict) or restoration.get("schema_version") != VERSION
                or restoration.get("kind") != "restore_receipt" or restoration.get("verified") is not True
                or restoration.get("backup_plan_sha256") != backup["plan_sha256"]
                or restoration.get("backup_archive_sha256") != backup["archive_sha256"]
                or restoration.get("backup_manifest_sha256") != backup["manifest_sha256"]
                or not isinstance(restoration.get("plan_sha256"), str)
                or not HASH_RE.fullmatch(restoration["plan_sha256"])
                or restoration.get("files") != manifest["files"]
                or len(restoration.get("records", [])) != len(manifest["files"])):
            raise StorageRefusal("Required recovery needs a completed exact restoration probe and its immutable outcome")
        destination = self._output_relative(restoration["destination"])
        outcome = "outcome-restore-" + restoration["plan_sha256"] + ".json"
        with self._scope(self.output_root) as output:
            self._private_created_file(outcome)
            outcome_record = output.inspect(outcome, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)
            if output.read_bytes(outcome, expected=outcome_record, max_bytes=MAX_ARCHIVE_BYTES) != canonical(restoration):
                raise StorageRefusal("Restoration outcome artifact differs from the exact recovery record")
            for row, record in zip(manifest["files"], restoration["records"]):
                expected_path = destination + "/" + row["root_id"] + "/" + row["relative_path"]
                if record["relative_path"] != expected_path or record["sha256"] != row["sha256"]:
                    raise StorageRefusal("Recovery probe does not map the exact backed-up contents")
                self._private_created_file(expected_path)
                data = output.read_bytes(expected_path, expected=record, max_bytes=MAX_FILE_BYTES)
                if len(data) != row["size"] or sha256(data) != row["sha256"]:
                    raise StorageRefusal("Required restored recovery bytes changed")
        return manifest

    def plan_cleanup(self, *, inventory, selected, quarantine_destination, content_read_authorized,
                     recovery_required=True, recovery_backup=None, recovery_verification=None, protected=None):
        _content_permission(content_read_authorized)
        if type(recovery_required) is not bool:
            raise StorageRefusal("Recovery requirement must be an explicit boolean")
        protected = protected or []
        if not isinstance(protected, list) or any(not isinstance(key, str) for key in protected):
            raise StorageRefusal("Exact protected file keys are required")
        selected_rows = _selection(inventory, selected)
        self._content_budget(selected_rows, inventory["limits"])
        self._cleanup_targets(inventory, selected_rows, protected)
        self._quarantine_source_privacy(inventory["roots"], selected_rows)
        relative = self._outside_sources(quarantine_destination, inventory["roots"])
        self._fresh_inventory(inventory)
        rows = []
        with ExitStack() as stack:
            sources = self._open_sources(stack, inventory["roots"])
            for item in selected_rows:
                rows.append(self._hashed(sources[item["root_id"]], item, inventory["limits"]))
        if recovery_required:
            if recovery_backup is None:
                raise StorageRefusal("Required recovery has not been verified; create and verify the exact backup first")
            manifest = self._verified_recovery(backup=recovery_backup, restoration=recovery_verification)
            backed = {(row["root_id"], row["relative_path"], row["sha256"], row["size"]) for row in manifest["files"]}
            if manifest["source_roots"] != inventory["roots"] or any((row["root_id"], row["relative_path"], row["sha256"], row["size"]) not in backed for row in rows):
                raise StorageRefusal("Required backup does not cover the exact selected identities/content/scope")
        return _new_plan("quarantine", inventory=inventory, files=rows, protected=sorted(protected),
                         quarantine_destination=str(_absolute(quarantine_destination)), quarantine_relative=relative,
                         recovery_required=recovery_required, recovery_backup=recovery_backup,
                         recovery_verification=recovery_verification,
                         cost={"selected_logical_bytes": sum(row["size"] for row in rows),
                               "expected_free_space_gain_bytes": 0, "physical_bytes": None,
                               "duration_seconds": None, "money": None},
                         explanation="Quarantine moves exact ordinary files on the same volume. It normally frees no disk space.")

    def _cleanup_targets(self, inventory, rows, protected):
        if {row["key"] for row in rows} & set(protected):
            raise StorageRefusal("Required recovery/protected artifacts cannot be cleanup targets")
        roots_by_id = {row["root_id"]: _absolute(row["path"]) for row in inventory["roots"]}
        if any(_within(roots_by_id[row["root_id"]] / row["relative_path"], self.output_root) for row in rows):
            raise StorageRefusal("This service's backup, evidence and recovery output artifacts stay protected from host cleanup")

    def quarantine(self, *, plan, expected_plan_sha256):
        _bound_plan(plan, expected_plan_sha256, "quarantine")
        self._reviewed_files(plan)
        self._content_budget(plan["files"], plan["inventory"]["limits"])
        self._quarantine_source_privacy(plan["inventory"]["roots"], plan["files"])
        if capabilities().get("move_noreplace") is not True:
            raise StorageRefusal("Checked native no-overwrite move is unavailable; quarantine is held with no fallback")
        self._fresh_inventory(plan["inventory"])
        self._cleanup_targets(plan["inventory"], plan["files"], plan["protected"])
        if plan["recovery_required"]:
            self._verified_recovery(backup=plan["recovery_backup"], restoration=plan["recovery_verification"])
        relative = self._outside_sources(plan["quarantine_destination"], plan["inventory"]["roots"])
        if relative != plan["quarantine_relative"] or any(row["key"] in plan["protected"] for row in plan["files"]):
            raise StorageRefusal("Quarantine scope or protected files changed")
        records = []
        with ExitStack() as stack:
            output = stack.enter_context(self._scope(self.output_root))
            sources = self._open_sources(stack, plan["inventory"]["roots"])
            destination_device = output.inspect("")["device"]
            if any(row["device"] != destination_device for row in plan["files"]):
                raise StorageRefusal("Cross-volume quarantine is refused; no copy/delete fallback")
            attempt = self._attempt(output, expected_plan_sha256, "quarantine", plan)
            self._mkdir_private(output, relative)
            for index, row in enumerate(plan["files"], 1):
                target = relative + f"/{index:06d}"
                expected = {key: value for key, value in row.items() if key not in {"root_id", "key"}}
                moved = sources[row["root_id"]].move_to(row["relative_path"], destination=output,
                                                       destination_relative=target, expected=expected)
                self._private_windows_quarantine_file(self.output_root / target)
                record = {"original": row, "quarantine_record": moved}
                records.append(record)
                self._write_json(output, f"step-quarantine-{expected_plan_sha256}-{index:06d}.json", record)
            receipt = {"schema_version": VERSION, "kind": "quarantine_receipt", "plan_sha256": expected_plan_sha256,
                       "source_roots": plan["inventory"]["roots"], "quarantine_destination": plan["quarantine_destination"],
                       "records": records, "recovery_required": plan["recovery_required"], "recovery_backup": plan["recovery_backup"],
                       "recovery_verification": plan["recovery_verification"],
                       "attempt": attempt, "expected_free_space_gain_bytes": 0, "finished_utc": _now()}
            self._write_json(output, f"outcome-quarantine-{expected_plan_sha256}.json", receipt)
            return receipt

    def _quarantine_provenance(self, receipt, output):
        if receipt.get("schema_version") != VERSION or receipt.get("kind") != "quarantine_receipt":
            raise StorageRefusal("Exact quarantine receipt required")
        if not isinstance(receipt.get("plan_sha256"), str) or not HASH_RE.fullmatch(receipt["plan_sha256"]):
            raise StorageRefusal("Exact original quarantine plan binding required")
        relative = self._output_relative(receipt["quarantine_destination"])
        outcome_name = "outcome-quarantine-" + receipt["plan_sha256"] + ".json"
        self._private_created_file(outcome_name)
        outcome_record = output.inspect(outcome_name, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)
        if output.read_bytes(outcome_name, expected=outcome_record, max_bytes=MAX_ARCHIVE_BYTES) != canonical(receipt):
            raise StorageRefusal("Quarantine receipt differs from the immutable original outcome")
        attempt_name = "attempt-quarantine-" + receipt["plan_sha256"] + ".json"
        if receipt.get("attempt") != attempt_name:
            raise StorageRefusal("Original quarantine attempt reference changed")
        self._private_created_file(attempt_name)
        attempt_record = output.inspect(attempt_name, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)
        try:
            attempt = json.loads(output.read_bytes(attempt_name, expected=attempt_record, max_bytes=MAX_ARCHIVE_BYTES))
        except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
            raise StorageRefusal("Invalid original quarantine attempt") from exc
        original_plan = attempt.get("exact_plan")
        if not isinstance(original_plan, dict):
            raise StorageRefusal("Original exact quarantine plan is unavailable; reconcile the incomplete operation")
        _bound_plan(original_plan, receipt["plan_sha256"], "quarantine")
        if (original_plan["quarantine_relative"] != relative
                or original_plan["quarantine_destination"] != receipt["quarantine_destination"]):
            raise StorageRefusal("Original quarantine destination changed")
        if (original_plan["inventory"]["roots"] != receipt["source_roots"]
                or original_plan["files"] != [row["original"] for row in receipt["records"]]
                or original_plan["recovery_required"] != receipt["recovery_required"]
                or original_plan["recovery_backup"] != receipt["recovery_backup"]
                or original_plan["recovery_verification"] != receipt["recovery_verification"]):
            raise StorageRefusal("Quarantine source mapping or recovery retention differs from the original plan")
        if any(row["quarantine_record"]["relative_path"] != relative + f"/{index:06d}"
               for index, row in enumerate(receipt["records"], 1)):
            raise StorageRefusal("Quarantine target mapping differs from the original numbered plan")
        return relative

    def _quarantine_current(self, receipt):
        with self._scope(self.output_root) as output:
            relative = self._quarantine_provenance(receipt, output)
            self._private_directory(relative)
            actual = sorted(output.list_directory(relative), key=lambda row: row["relative_path"])
            expected = sorted([row["quarantine_record"] for row in receipt["records"]], key=lambda row: row["relative_path"])
            if ([{**row, "sha256": None} for row in actual]
                    != [{**row, "sha256": None} for row in expected]):
                raise StorageRefusal("Unknown, missing or changed quarantine files; recovery review is required")
            for row in receipt["records"]:
                self._private_windows_quarantine_file(self.output_root / row["quarantine_record"]["relative_path"])
                observed = output.inspect(row["quarantine_record"]["relative_path"], hash_file=True, max_bytes=MAX_FILE_BYTES)
                if observed != row["quarantine_record"]:
                    raise StorageRefusal("Quarantine content changed")
        return relative

    def plan_quarantine_restore(self, *, receipt):
        self._quarantine_current(receipt)
        return _new_plan("quarantine_restore", receipt=receipt,
                         explanation="Restore the exact quarantined files to their original selected roots; existing files are never overwritten.")

    def restore_quarantine(self, *, plan, expected_plan_sha256):
        _bound_plan(plan, expected_plan_sha256, "quarantine_restore")
        if capabilities().get("move_noreplace") is not True:
            raise StorageRefusal("Checked native no-overwrite move is unavailable; restore is held with no fallback")
        receipt = plan["receipt"]
        self._quarantine_current(receipt)
        result = []
        with ExitStack() as stack:
            output = stack.enter_context(self._scope(self.output_root))
            sources = self._open_sources(stack, receipt["source_roots"])
            attempt = self._attempt(output, expected_plan_sha256, "quarantine-restore", plan)
            for index, row in enumerate(receipt["records"], 1):
                original = row["original"]
                observed = output.move_to(row["quarantine_record"]["relative_path"], destination=sources[original["root_id"]],
                                          destination_relative=original["relative_path"], expected=row["quarantine_record"])
                source_root = next(root["path"] for root in receipt["source_roots"] if root["root_id"] == original["root_id"])
                self._private_windows_quarantine_file(Path(source_root) / original["relative_path"])
                result.append(observed)
                self._write_json(output, f"step-quarantine-restore-{expected_plan_sha256}-{index:06d}.json", observed)
            outcome = {"schema_version": VERSION, "kind": "quarantine_restore_receipt", "plan_sha256": expected_plan_sha256,
                       "records": result, "attempt": attempt, "finished_utc": _now()}
            self._write_json(output, f"outcome-quarantine-restore-{expected_plan_sha256}.json", outcome)
            return outcome

    def plan_purge(self, *, receipt):
        self._quarantine_current(receipt)
        if receipt["recovery_required"]:
            self._verified_recovery(backup=receipt["recovery_backup"], restoration=receipt["recovery_verification"])
        return _new_plan("purge", receipt=receipt, irreversible=True,
                         requires_separate_owner_approval=True, requires_loss_acknowledgment=True,
                         cost={"selected_logical_bytes": sum(row["original"]["size"] for row in receipt["records"]),
                               "physical_free_space_gain_bytes": None, "duration_seconds": None, "money": None},
                         explanation="Permanently remove only the exact quarantined files. Logical size is not a promise of physical free space.")

    def purge_quarantine(self, *, plan, expected_plan_sha256):
        """Low-level removal; coordinator MUST separately gate irreversible loss.

        There is deliberately no `approved=True` or quotation parameter. Such a
        parameter would not authenticate the current owner's decision.
        """
        _bound_plan(plan, expected_plan_sha256, "purge")
        if capabilities().get("remove_file") is not True:
            raise StorageRefusal("Checked native file removal is unavailable; purge is held with no fallback")
        receipt = plan["receipt"]
        self._quarantine_current(receipt)
        if receipt["recovery_required"]:
            self._verified_recovery(backup=receipt["recovery_backup"], restoration=receipt["recovery_verification"])
        removed = []
        with self._scope(self.output_root) as output:
            attempt = self._attempt(output, expected_plan_sha256, "purge", plan)
            for index, row in enumerate(receipt["records"], 1):
                target = row["quarantine_record"]
                output.remove_file(target["relative_path"], expected=target)
                removed.append(target["relative_path"])
                self._write_json(output, f"step-purge-{expected_plan_sha256}-{index:06d}.json", {"removed": target})
            outcome = {"schema_version": VERSION, "kind": "purge_receipt", "plan_sha256": expected_plan_sha256,
                       "removed": removed, "irreversible": True, "attempt": attempt, "finished_utc": _now(),
                       "physical_free_space_gain_bytes": None}
            self._write_json(output, f"outcome-purge-{expected_plan_sha256}.json", outcome)
            return outcome

    def verify_outcome(self, *, plan, expected_plan_sha256, receipt):
        """Read-only actual postconditions for a known immutable outcome.

        Missing/partial outcome evidence is a hold. This method does not retry,
        recreate a receipt or turn an unknown interrupted action into success.
        """
        operations = {"backup": ("backup", "backup_receipt"), "restore": ("restore", "restore_receipt"),
                      "quarantine": ("quarantine", "quarantine_receipt"),
                      "quarantine_restore": ("quarantine-restore", "quarantine_restore_receipt"),
                      "purge": ("purge", "purge_receipt")}
        kind = plan.get("kind")
        if kind not in operations:
            raise StorageRefusal("Unknown fixed storage outcome kind")
        _bound_plan(plan, expected_plan_sha256, kind)
        operation, receipt_kind = operations[kind]
        if (not isinstance(receipt, dict) or receipt.get("schema_version") != VERSION
                or receipt.get("kind") != receipt_kind or receipt.get("plan_sha256") != expected_plan_sha256):
            raise StorageRefusal("An exact bound immutable operation receipt is required")
        outcome_name = f"outcome-{operation}-{expected_plan_sha256}.json"
        with self._scope(self.output_root) as output:
            self._private_created_file(outcome_name)
            outcome_record = output.inspect(outcome_name, hash_file=True, max_bytes=MAX_ARCHIVE_BYTES)
            outcome_data = output.read_bytes(outcome_name, expected=outcome_record, max_bytes=MAX_ARCHIVE_BYTES)
            if outcome_data != canonical(receipt):
                raise StorageRefusal("Outcome receipt differs from the exact immutable artifact")
            if kind == "backup":
                verified = self.verify_backup(receipt=receipt)
                if verified["manifest"]["files"] != plan["files"] or receipt["archive"] != plan["destination"]:
                    raise StorageRefusal("Backup outcome differs from the exact reviewed content/output")
            elif kind == "restore":
                self._verified_recovery(backup=plan["receipt"], restoration=receipt)
                if receipt["destination"] != plan["destination"] or receipt["files"] != plan["files"]:
                    raise StorageRefusal("Restore outcome differs from the exact reviewed destination/content")
            elif kind == "quarantine":
                self._quarantine_current(receipt)
                if [row["original"] for row in receipt["records"]] != plan["files"]:
                    raise StorageRefusal("Quarantine outcome differs from the exact reviewed targets")
                with ExitStack() as stack:
                    sources = self._open_sources(stack, plan["inventory"]["roots"])
                    for row in plan["files"]:
                        self._require_absent(sources[row["root_id"]], row["relative_path"])
                if plan["recovery_required"]:
                    self._verified_recovery(backup=plan["recovery_backup"], restoration=plan["recovery_verification"])
            elif kind == "quarantine_restore":
                original_receipt = plan["receipt"]
                self._quarantine_provenance(original_receipt, output)
                if len(receipt["records"]) != len(original_receipt["records"]):
                    raise StorageRefusal("Restoration outcome target count changed")
                with ExitStack() as stack:
                    sources = self._open_sources(stack, original_receipt["source_roots"])
                    for original_row, observed in zip(original_receipt["records"], receipt["records"]):
                        original = original_row["original"]
                        if observed["relative_path"] != original["relative_path"] or observed["sha256"] != original["sha256"]:
                            raise StorageRefusal("Restored quarantine mapping/content differs from the original")
                        source_root = next(root["path"] for root in original_receipt["source_roots"] if root["root_id"] == original["root_id"])
                        self._private_windows_quarantine_file(Path(source_root) / original["relative_path"])
                        data = sources[original["root_id"]].read_bytes(original["relative_path"], expected=observed, max_bytes=MAX_FILE_BYTES)
                        if len(data) != original["size"] or sha256(data) != original["sha256"]:
                            raise StorageRefusal("Restored original bytes changed")
                        self._require_absent(output, original_row["quarantine_record"]["relative_path"])
            else:
                original_receipt = plan["receipt"]
                self._quarantine_provenance(original_receipt, output)
                expected_removed = [row["quarantine_record"]["relative_path"] for row in original_receipt["records"]]
                if receipt["removed"] != expected_removed:
                    raise StorageRefusal("Purge outcome differs from the exact reviewed target list")
                for relative in expected_removed:
                    self._require_absent(output, relative)
                if original_receipt["recovery_required"]:
                    self._verified_recovery(backup=original_receipt["recovery_backup"], restoration=original_receipt["recovery_verification"])
        return {"schema_version": VERSION, "kind": "storage_outcome_verification", "observed_utc": _now(),
                "storage_plan_sha256": expected_plan_sha256, "operation_kind": kind,
                "outcome": "succeeded", "verification_passed": True, "mutation_performed": False,
                "receipt_sha256": sha256(outcome_data), "outcome_artifact_relative": outcome_name,
                "outcome_artifact_record": outcome_record}


def storage_capabilities():
    return {"schema_version": VERSION, "filesystem": capabilities(), "cli_mutation_enabled": False,
            "requires_workflow_engine_gate": True, "quiet_exclusive_workspace_required": True,
            "not_an_os_sandbox": True, "zip_encryption": False}
