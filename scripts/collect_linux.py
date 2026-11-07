"""Bounded native Linux installed-metadata adapter. No writes or update commands.

A read-only inventory provider: collect() returns validated facts, which the coordinator
registers as inventory evidence in an engine session whose owner authorized this collection.
Create the engine session first; it admits private storage before any collection.
Every package query is a recipe of readonly_runner (fixed root-owned tool, fixed arguments and
environment, a timeout and an output bound); this module starts no process itself.
This module deliberately does not discover projects, user profiles or repositories.
"""

import os
from pathlib import Path
import re
import shlex
import stat
import sys

import pc_records
import readonly_runner


MAX_ROWS = 10000
OS_RELEASE_LIMIT = 16384
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:@~^!/-]{0,199}\Z")
_PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()\[\]/:+-]{0,159}\Z")
_OS_KEYS = frozenset({"ID", "ID_LIKE", "VERSION_ID", "PRETTY_NAME"})
# readonly_runner's refusal codes as this collector's categorical error codes.
_RUNNER_ERRORS = {"runner-timeout": "query_timeout", "runner-output-too-large": "query_output_limit"}


class CollectionError(Exception):
    """Safe categorical error; never includes raw command stderr or file contents."""


def _token(value):
    return isinstance(value, str) and bool(_TOKEN.fullmatch(value))


def _trusted_system_path(path):
    """Accept only a root-owned non-writable system file below /etc or /usr/lib, and its root-owned ancestors.

    This is an ownership boundary, not a signature or package-integrity proof.
    A compromised root/OS is outside the guarantee of an in-process collector.
    """
    try:
        resolved = Path(path).resolve(strict=True)
        if not any(resolved == root or root in resolved.parents for root in (Path("/etc"), Path("/usr/lib"))):
            return False
        if not stat.S_ISREG(resolved.stat().st_mode):
            return False
        for entry in (resolved,) + tuple(resolved.parents):
            item = entry.stat()
            if item.st_uid != 0 or item.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        return True
    except (OSError, RuntimeError):
        return False


def _read_os_release():
    for path in (Path("/etc/os-release"), Path("/usr/lib/os-release")):
        if not _trusted_system_path(path):
            continue
        try:
            # Revalidate the opened descriptor; do not follow an unchecked new link.
            resolved = path.resolve(strict=True)
            before = resolved.stat()
            with resolved.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise CollectionError("metadata_changed")
                if not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_mode & 0o022:
                    raise CollectionError("metadata_ownership")
                raw = stream.read(OS_RELEASE_LIMIT + 1)
            if len(raw) > OS_RELEASE_LIMIT:
                raise CollectionError("metadata_size_limit")
            return parse_os_release(raw.decode("utf-8", errors="strict"))
        except (OSError, UnicodeError):
            raise CollectionError("os_release_unavailable") from None
    raise CollectionError("os_release_untrusted_or_missing")


def parse_os_release(text):
    """Parse selected literal fields; never source, evaluate or interpolate them."""
    selected = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key not in _OS_KEYS:
            continue
        try:
            parts = shlex.split(value, comments=False, posix=True)
        except ValueError:
            continue
        if len(parts) != 1 or not _PLAIN.fullmatch(parts[0]):
            continue
        if key in selected:  # Ambiguous duplicate identity fields are not evidence.
            raise CollectionError("duplicate_os_identity_field")
        selected[key] = parts[0]
    if not _token(selected.get("ID")):
        raise CollectionError("os_identity_missing")
    return selected


def _query(recipe_id):
    """The text a package query printed, through readonly_runner; None when no listed root-owned tool exists. dpkg-query,
    rpm, snap and flatpak print UTF-8; other bytes are refused. A refusal, a failure status or undecodable output raises
    CollectionError with a categorical code (never the tool's text)."""
    try:
        found = readonly_runner.run_recipe(recipe_id)
    except pc_records.Refusal as error:
        if error.code == "runner-executable":
            return None
        raise CollectionError(_RUNNER_ERRORS.get(error.code, "query_unavailable")) from None
    if not found["ok"]:
        raise CollectionError("query_exit_nonzero")
    try:
        return found["stdout"].decode("utf-8", errors="strict")
    except UnicodeError:
        raise CollectionError("query_encoding") from None


def _package(name, version, architecture, manager, **extras):
    record = {
        "name": name, "version": version or None, "architecture": architecture or None,
        "manager": manager, "scope": "system", "kind": "package",
        "status": "observed", "metadata_source": "installed_package_database",
        "update_offer": "not_checked", "security_applicability": "not_assessed",
    }
    record.update(extras)
    return record


def parse_dpkg(text):
    rows, rejected = [], 0
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            rejected += 1
            continue
        name, version, architecture, state, source = fields
        if len(state) != 3 or state[0] not in "uihrp" or state[1] not in "ncHUFWti" or state[2] not in " R":
            rejected += 1
            continue
        if state[1] != "i":
            continue  # Removed/config-only/incomplete records are not installed software.
        if not all(_token(value) for value in (name, version, architecture, source)):
            rejected += 1
            continue
        rows.append(_package(name, version, architecture, "dpkg", source_package=source,
                             desired_hold=state[0] == "h", package_state=state,
                             package_health="reinstallation_required" if state[2] == "R" else "not_tested"))
    return rows, rejected


def parse_rpm(text):
    rows, rejected = [], 0
    for line in text.splitlines():
        fields = line.split("\t")
        if fields[0] == "gpg-pubkey" and fields[2:] == ["(none)", "(none)"]:
            continue  # An imported signing key, which rpm lists like a package; it is not installed software.
        if len(fields) != 4 or not all(_token(value) for value in fields):
            rejected += 1
            continue
        name, version, architecture, source = fields
        rows.append(_package(name, version, architecture, "rpm", source_package=source))
    return rows, rejected


def parse_snap(text):
    rows, rejected = [], 0
    if not text.strip():
        return [], 0  # With no snaps installed, snap list prints nothing on stdout.
    lines = text.splitlines()
    if lines[0].split() != ["Name", "Version", "Rev", "Tracking", "Publisher", "Notes"]:
        return [], 1
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != 6:
            rejected += 1
            continue
        name, version, revision, channel, _publisher, notes = fields
        if not all(_token(value) for value in (name, version, channel)) or not revision.isdigit():
            rejected += 1
            continue
        # Publisher and notes are not retained as arbitrary imported prose.
        rows.append(_package(name, version, None, "snap", revision=revision,
                             channel=channel, desired_hold="held" in notes.split(",")))
    return rows, rejected


def parse_flatpak(text):
    rows, rejected = [], 0
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            rejected += 1
            continue
        name, version, architecture, branch = fields
        if not all(_token(value) for value in (name, architecture, branch)) or (version and not _token(version)):
            rejected += 1
            continue
        rows.append(_package(name, version, architecture, "flatpak", channel=branch))
    return rows, rejected


def collect():
    """Return metadata, coverage and safe errors; caller owns consent and all writes.

    Direct calls still collect native metadata: this guard prevents the wrong OS,
    not unauthorized calling code. Call it only for a session's authorized scope.
    """
    if not sys.platform.startswith("linux"):
        raise CollectionError("native_linux_required")
    observed = pc_records.utc_now()
    result = {
        "platform": "linux", "collection_mode": "real", "observed_utc": observed, "observations": [],
        "coverage": [], "errors": [], "limits": [
            "Selected installed metadata only; no update offers or security conclusions.",
            "No user profiles, project environments, repositories, browser data or private logs inspected.",
            "System Flatpak only; per-user and additional named installations excluded.",
            "Kernel observation does not establish available kernel updates or reboot requirements.",
            "Installed package metadata can omit portable, bundled, container or manually installed copies.",
            "Native package tools/daemons may maintain operational logs outside toolkit work.",
        ],
    }
    try:
        identity = _read_os_release()
        result["observations"].append({
            "name": identity.get("PRETTY_NAME", identity["ID"]),
            "version": identity.get("VERSION_ID"), "kind": "operating_system",
            "manager": "os-release", "scope": "system", "status": "observed",
            "distribution_id": identity["ID"], "distribution_like": identity.get("ID_LIKE"),
        })
        result["coverage"].append({"scope": "os_release", "state": "observed"})
    except CollectionError as error:
        result["errors"].append({"scope": "os_release", "code": str(error)})
    kernel = os.uname()
    if _token(kernel.release) and _token(kernel.machine):
        wsl = "microsoft" in kernel.release.lower() or "wsl" in kernel.release.lower()
        result["observations"].append({
            "name": "Running Linux kernel", "version": kernel.release,
            "architecture": kernel.machine, "kind": "kernel", "manager": "uname",
            "scope": "system", "status": "observed",
            "environment": "wsl_guest" if wsl else "native_vm_or_container_unresolved",
        })
        if wsl:
            result["limits"].append("WSL guest: Windows host, WSL package and guest distribution updates are separate and unassessed here.")
    specs = (
        ("dpkg-query", "linux.dpkg_installed", parse_dpkg),
        ("rpm", "linux.rpm_installed", parse_rpm),
        ("snap", "linux.snap_list", parse_snap),
        ("flatpak", "linux.flatpak_system", parse_flatpak),
    )
    for manager, recipe_id, parser in specs:
        try:
            text = _query(recipe_id)
            if text is None:
                result["coverage"].append({"scope": manager, "state": "unavailable_or_untrusted"})
                continue
            rows, rejected = parser(text)
            allowance = max(0, MAX_ROWS - len(result["observations"]))
            truncated = len(rows) > allowance
            result["observations"].extend(rows[:allowance])
            result["coverage"].append({
                "scope": manager, "state": "partial" if rejected or truncated else "observed",
                "records": min(len(rows), allowance), "rejected_rows": rejected,
                "truncated": truncated, "freshness": "installed_metadata_not_update_offer",
            })
        except CollectionError as error:
            result["coverage"].append({"scope": manager, "state": "unavailable"})
            result["errors"].append({"scope": manager, "code": str(error)})
    result["limits"].append("RPM query isolates user macro/rc configuration and uses /var/lib/rpm; nonstandard databases or required distro macro configuration can remain unavailable.")
    return result
