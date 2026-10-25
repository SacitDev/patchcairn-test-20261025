"""Metadata-only assessment, duplicate comparison and the chat table, mixed into storage_ops.StorageService (see its trust model)."""
from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path

import pc_paths
import pc_records
import scoped_base
from storage_policy import (StorageRefusal, checked_absolute, checked_limits, checked_relative, content_permission,
                            fingerprint, inventory_files, storage_value, within)


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
    lines.extend(["", f"{summary['excluded']} protected entries were excluded before descent or content reads."])
    if summary["not_included"]:
        lines.append(f"{summary['not_included']} entries were not included: links, special files, or names and paths that cannot be "
                     "used on every system. They are listed in the assessment, never opened, and not backed up.")
    lines.extend([
                  "Next: choose exact files for an optional content comparison or a reviewed backup.",
                  "Equal file bytes do not establish that either file can be removed."])
    return "\n".join(lines)


class StorageAssessment:
    """StorageService's metadata assessment and duplicate comparison."""

    def assess_storage(self, *, roots, limits=None):
        """Read metadata only, pruning protected names before descending."""
        limit = checked_limits(limits)
        if not isinstance(roots, (list, tuple)) or not roots or len(roots) > 32:
            raise StorageRefusal("Select between one and 32 explicit directory roots")
        paths = sorted((checked_absolute(root) for root in roots), key=lambda path: os.path.normcase(str(path)))
        for index, path in enumerate(paths):
            if path == Path(path.anchor) or self._protected_root(path):
                raise StorageRefusal("Protected or whole-volume source roots are excluded")
            for earlier in paths[:index]:
                if within(path, earlier) or within(earlier, path):
                    raise StorageRefusal("Overlapping or duplicate source roots are refused")
        root_rows, entries, not_included, identities = [], [], [], set()
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
                # D-025: entries the root does not admit are listed as not included (scoped_base rows, names
                # escaped for display), never opened, and never refuse the whole selection.
                left_out = []
                pending = [""]
                while pending:
                    current = pending.pop()
                    for record in sorted(source.list_directory(current, excluded=left_out), key=lambda item: item["relative_path"]):
                        rel = checked_relative(record["relative_path"])
                        parent, _, name = rel.rpartition("/")
                        if not pc_paths.portable(f"{root_id}/{rel}"):
                            # Restores write <destination>/<root id>/<path>; keep that headroom.
                            scoped_base.exclude(left_out, parent, name, "path-too-long")
                            continue
                        if len(entries) >= limit["max_entries"] or rel.count("/") >= limit["max_depth"]:
                            raise StorageRefusal("Selected metadata traversal exceeds entry/depth cap; select narrower roots")
                        item = {"root_id": root_id, "key": f"{root_id}/{rel}", **record}
                        if self._protected_entry(path, rel):
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
                not_included.extend({"root_id": root_id, **row} for row in left_out)
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
            bucket = ("0 B" if size == 0 else "1 B–1 KiB" if size <= 1024 else "1 KiB–1 MiB" if size <= 1024**2
                      else "1 MiB–16 MiB" if size <= 16*1024**2 else "over 16 MiB")
            buckets[bucket] += 1
        inventory = {**storage_value("inventory"), "observed_utc": pc_records.utc_now(),
                     "roots": root_rows, "entries": entries, "not_included": not_included, "limits": limit,
                     "summary": {"files": sum(item["kind"] == "file" for item in entries),
                                 "directories": sum(item["kind"] == "directory" for item in entries),
                                 "excluded": sum(item["kind"] == "excluded" for item in entries),
                                 "not_included": sum(row.get("count", 1) for row in not_included),
                                 "logical_bytes": total, "physical_bytes": None, "reclaimable_bytes": None},
                     "extensions": sorted(extensions.values(), key=lambda row: (-row["logical_bytes"], row["extension"])),
                     "tree": sorted(tree.values(), key=lambda row: row["key"]),
                     "size_buckets": [{"bucket": key, "files": value} for key, value in buckets.items()],
                     "content_read": False, "exclusive_workspace_required": True, "not_an_os_sandbox": True}
        inventory["inventory_sha256"] = fingerprint(inventory)
        return inventory

    def find_duplicates(self, *, inventory, content_read_authorized, limits=None):
        content_permission(content_read_authorized)
        limit = checked_limits(limits or inventory["limits"])
        self._fresh_inventory(inventory)
        candidates = {}
        for item in inventory_files(inventory).values():
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
        return {**storage_value("duplicates"), "inventory_sha256": inventory["inventory_sha256"],
                "groups": groups, "content_bytes_read": read_bytes,
                "logical_byte_opportunity": sum(row["logical_byte_opportunity"] for row in groups),
                "reclaimable_bytes": None, "removal_authorized": False,
                "message": "Equal SHA-256 and size identify byte duplicates; ownership and removability still require review."}
