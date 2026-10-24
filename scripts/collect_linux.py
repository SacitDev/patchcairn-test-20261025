"""Bounded native Linux installed-metadata adapter. No writes or update commands.

The coordinator establishes assessment authorization and registers returned evidence.
This module deliberately does not discover projects, user profiles or repositories.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import selectors
import shlex
import stat
import subprocess
import sys
import time


MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 10000
QUERY_TIMEOUT = 8.0
OS_RELEASE_LIMIT = 16384
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:@~^!/-]{0,199}\Z")
_PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()\[\]/:+-]{0,159}\Z")
_OS_KEYS = frozenset({"ID", "ID_LIKE", "VERSION_ID", "PRETTY_NAME"})
_TOOLS = ("dpkg-query", "rpm", "snap", "flatpak")
# No inherited HOME, proxy, loader, Python or authentication configuration.
# /dev/null cannot become a per-user configuration/cache directory.
_QUERY_ENV = {
    "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
    "HOME": "/dev/null", "XDG_CONFIG_HOME": "/dev/null",
    "XDG_CACHE_HOME": "/dev/null", "XDG_DATA_HOME": "/dev/null",
    "GIO_USE_VFS": "local", "PAGER": "cat", "DPKG_PAGER": "cat",
}


class CollectionError(Exception):
    """Safe categorical error; never includes raw command stderr or file contents."""


def _token(value):
    return isinstance(value, str) and bool(_TOKEN.fullmatch(value))


def _trusted_system_path(path, executable=False):
    """Accept only root-owned non-writable system files and their ancestors.

    This is an ownership boundary, not a signature or package-integrity proof.
    A compromised root/OS is outside the guarantee of an in-process collector.
    """
    try:
        resolved = Path(path).resolve(strict=True)
        allowed_roots = (Path("/usr/bin"), Path("/usr/sbin")) if executable else (
            Path("/etc"), Path("/usr/lib"))
        if not any(resolved == root or root in resolved.parents for root in allowed_roots):
            return False
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode) or (executable and not info.st_mode & 0o111):
            return False
        for entry in (resolved,) + tuple(resolved.parents):
            item = entry.stat()
            if item.st_uid != 0 or item.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        return True
    except (OSError, RuntimeError):
        return False


def _find_program(name):
    if name not in _TOOLS:
        return None
    for directory in ("/usr/bin", "/bin", "/usr/sbin"):
        candidate = Path(directory) / name
        if _trusted_system_path(candidate, executable=True):
            return str(candidate.resolve(strict=True))
    return None


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


def _run_query(argv, timeout=QUERY_TIMEOUT, byte_limit=MAX_BYTES):
    """Read a capped pipe, not an unbounded capture_output buffer (Linux only)."""
    if not (0 < timeout <= 30 and 0 < byte_limit <= MAX_BYTES):
        raise CollectionError("invalid_query_bounds")
    if not argv or not _trusted_system_path(argv[0], executable=True):
        raise CollectionError("untrusted_program")
    process = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(
            list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=dict(_QUERY_ENV), cwd="/",
            close_fds=True, shell=False,
        )
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        collected = bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CollectionError("query_timeout")
            for key, _ in selector.select(min(remaining, 0.2)):
                chunk = os.read(key.fileobj.fileno(), min(65536, byte_limit - len(collected) + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    collected.extend(chunk)
                    if len(collected) > byte_limit:
                        raise CollectionError("query_output_limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CollectionError("query_timeout")
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise CollectionError("query_timeout") from None
        if code != 0:
            raise CollectionError("query_exit_nonzero")
        try:
            return collected.decode("utf-8", errors="strict")
        except UnicodeError:
            raise CollectionError("query_encoding") from None
    except OSError:
        raise CollectionError("query_unavailable") from None
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                process.kill()  # Only the exact process created above; never a host updater.
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            if process.stdout is not None:
                process.stdout.close()


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
        if len(fields) != 4 or not all(_token(value) for value in fields):
            rejected += 1
            continue
        name, version, architecture, source = fields
        rows.append(_package(name, version, architecture, "rpm", source_package=source))
    return rows, rejected


def parse_snap(text):
    rows, rejected = [], 0
    lines = text.splitlines()
    if not lines or lines[0].split() != ["Name", "Version", "Rev", "Tracking", "Publisher", "Notes"]:
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
    not unauthorized calling code. Use the coordinator's real-run authorization.
    """
    if not sys.platform.startswith("linux"):
        raise CollectionError("native_linux_required")
    observed = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    result = {
        "platform": "linux", "observed_utc": observed, "observations": [],
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
        ("dpkg-query", ["--show", "--showformat=${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\t${source:Package}\\n"], parse_dpkg),
        ("rpm", ["--noplugins", "--rcfile", "/dev/null", "--macros", "/dev/null", "--dbpath", "/var/lib/rpm", "-qa", "--qf", "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n"], parse_rpm),
        ("snap", ["list"], parse_snap),
        ("flatpak", ["list", "--system", "--columns=application,version,arch,branch"], parse_flatpak),
    )
    for manager, args, parser in specs:
        program = _find_program(manager)
        if program is None:
            result["coverage"].append({"scope": manager, "state": "unavailable_or_untrusted"})
            continue
        try:
            rows, rejected = parser(_run_query([program] + args))
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
