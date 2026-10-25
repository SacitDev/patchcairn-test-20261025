"""Bounded macOS metadata collection; no updates, elevation, cleanup, or writes.

A read-only inventory provider: collect() returns validated facts, which the coordinator
registers as inventory evidence in an engine session whose owner authorized this collection.
Create the engine session first; it admits private storage before any collection.
The real entry point is Darwin-only. Tests must explicitly opt into fixtures and
provide their own command runner, application roots, and Homebrew candidates;
fixture results report collection_mode "fixture".
Never pass imported report values as collector options or executable commands.
"""

from __future__ import annotations

import itertools
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import struct
import subprocess
import threading
import unicodedata
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence
from xml.parsers.expat import ExpatError

import pc_records


MAX_COMMAND_BYTES = 256 * 1024
MAX_PLIST_BYTES = 256 * 1024
MAX_HEADER_BYTES = 4096
MAX_ENTRIES_PER_ROOT = 1000
MAX_ROOTS = 6
MAX_TEXT = 256
ALLOWED_COMMANDS = frozenset(
    {
        ("/usr/bin/sw_vers",),
        ("/usr/bin/uname", "-m"),
        ("/usr/sbin/sysctl", "-n", "hw.optional.arm64"),
        ("/usr/sbin/sysctl", "-in", "sysctl.proc_translated"),
        ("/usr/bin/xcode-select", "--print-path"),
        ("/usr/sbin/pkgutil", "--pkgs"),
    }
)
CPU_NAMES = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 18: "ppc"}


class UnsupportedPlatform(RuntimeError):
    """A native collector must never run on a different operating system."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: str = ""
    error: str | None = None


CommandRunner = Callable[[Sequence[str], float], CommandResult]


def _clean(value: object, limit: int = MAX_TEXT) -> str | None:
    """Retain selected metadata, suppress control characters and long fields."""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    text = str(value)
    if any(unicodedata.category(char).startswith("C") for char in text):
        return None
    return text[:limit] or None


def parse_sw_vers(text: str) -> dict[str, str | None]:
    """Parse only selected keys; ignore all other command output."""
    result: dict[str, str | None] = {"version": None, "build": None, "version_extra": None}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        value = value.strip()
        if key.strip() == "ProductVersion" and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){1,3}", value):
            result["version"] = value
        elif key.strip() == "BuildVersion" and re.fullmatch(r"[A-Za-z0-9]{3,32}", value):
            result["build"] = value
        elif key.strip() == "ProductVersionExtra" and re.fullmatch(r"\([a-z]\)", value):
            result["version_extra"] = value
    return result


def parse_receipt_ids(text: str, limit: int = 200) -> tuple[list[str], bool]:
    """Receipt identifiers only: no file lists, scripts, or receipt values."""
    found: list[str] = []
    seen: set[str] = set()
    truncated = False
    for line in text.splitlines():
        value = line.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", value) or value in seen:
            continue
        seen.add(value)
        if len(found) >= limit:
            truncated = True
            break
        found.append(value)
    return sorted(found), truncated


def parse_macho_architectures(header: bytes) -> list[str]:
    """Read header architecture labels only; not a binary integrity validator."""
    data = header[:MAX_HEADER_BYTES]
    if len(data) < 8:
        return []
    magic = data[:4]
    thin = {b"\xce\xfa\xed\xfe": "<", b"\xcf\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xce": ">", b"\xfe\xed\xfa\xcf": ">"}
    if magic in thin:
        minimum = 32 if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 28
        if len(data) < minimum:
            return []
        cpu = struct.unpack_from(thin[magic] + "I", data, 4)[0]
        return [CPU_NAMES[cpu]] if cpu in CPU_NAMES else []
    fat = {b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20), b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32)}
    if magic not in fat:
        return []
    endian, entry_size = fat[magic]
    count = struct.unpack_from(endian + "I", data, 4)[0]
    if not 1 <= count <= 32 or 8 + count * entry_size > len(data):
        return []
    labels: set[str] = set()
    for index in range(count):
        cpu = struct.unpack_from(endian + "I", data, 8 + index * entry_size)[0]
        if cpu in CPU_NAMES:
            labels.add(CPU_NAMES[cpu])
    return sorted(labels)


def _is_link_or_reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _no_links(path: Path) -> bool:
    """Refuse links/reparses in every existing component, including parents."""
    try:
        for part in reversed((path,) + tuple(path.parents)):
            if _is_link_or_reparse(part):
                return False
        return True
    except (OSError, ValueError):
        return False


def _read_regular(path: Path, max_bytes: int, *, header_only: bool = False) -> bytes | None:
    """Open a known metadata path without following a final symlink."""
    try:
        selected = path.lstat()
        if not stat.S_ISREG(selected.st_mode) or selected.st_nlink != 1:
            return None
        if getattr(selected, "st_file_attributes", 0) & 0x400:
            return None
        if not header_only and selected.st_size > max_bytes:
            return None
        if not _no_links(path):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        if os.open in getattr(os, "supports_dir_fd", ()) and hasattr(os, "O_NOFOLLOW"):
            # Native macOS/POSIX: open each directory relative to its predecessor.
            # Renaming a parent or replacing it with a link cannot redirect reads.
            if not path.is_absolute() or ".." in path.parts:
                return None
            directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for component in path.parts[1:-1]:
                    next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    os.close(directory)
                    directory = next_directory
                descriptor = os.open(path.name, flags, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            # Windows is fixture-only for this adapter; no native Mac claims.
            descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                return None
            if (selected.st_dev, selected.st_ino, selected.st_size, selected.st_mtime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                return None
            if not header_only and before.st_size > max_bytes:
                return None
            data = stream.read(max_bytes if header_only else max_bytes + 1)
            after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                return None
            if not _no_links(path) or (not header_only and len(data) > max_bytes):
                return None
            current = path.lstat()
            if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                return None
            return data
    except (OSError, ValueError):
        return None


def inspect_app(app: Path, root_label: str) -> dict[str, object] | None:
    """Read one app's selected plist fields and at most 4096 executable bytes."""
    if not app.name.endswith(".app") or not _no_links(app):
        return None
    raw = _read_regular(app / "Contents" / "Info.plist", MAX_PLIST_BYTES)
    if raw is None:
        return None
    try:
        metadata = plistlib.loads(raw)
    except (ValueError, TypeError, OverflowError, RecursionError, ExpatError, plistlib.InvalidFileException):
        return None
    if not isinstance(metadata, dict):
        return None
    name = _clean(metadata.get("CFBundleDisplayName")) or _clean(metadata.get("CFBundleName")) or _clean(app.stem)
    if not name:
        return None
    architectures: list[str] = []
    executable = metadata.get("CFBundleExecutable")
    if isinstance(executable, str) and re.fullmatch(r"[A-Za-z0-9_. +()-]{1,128}", executable) and executable not in (".", ".."):
        header = _read_regular(app / "Contents" / "MacOS" / executable, MAX_HEADER_BYTES, header_only=True)
        if header is not None:
            architectures = parse_macho_architectures(header)
    return {
        "kind": "application", "name": name,
        "version": _clean(metadata.get("CFBundleShortVersionString")),
        "build": _clean(metadata.get("CFBundleVersion")),
        "bundle_id": _clean(metadata.get("CFBundleIdentifier")),
        "minimum_macos": _clean(metadata.get("LSMinimumSystemVersion")),
        "architecture": ",".join(architectures) if architectures else None,
        "architecture_evidence": "bounded Mach-O header; not signature/integrity verification" if architectures else "not established",
        "manager": "unknown", "scope": root_label,
        "source": "selected app Info.plist and optional Mach-O header",
        "version_state": "bundle metadata; publisher/channel and actual behavior unverified",
    }


def _default_runner(command: Sequence[str], timeout: float) -> CommandResult:
    if platform.system() != "Darwin":
        raise UnsupportedPlatform("Native macOS commands are unavailable on this platform")
    if tuple(command) not in ALLOWED_COMMANDS:
        raise ValueError("Command is not in the fixed macOS metadata allowlist")
    # No inherited credential environment, shell, PATH resolution, or stderr dump.
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    try:
        process = subprocess.Popen(list(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment, shell=False)
    except OSError:
        return CommandResult(None, error="unavailable")
    output: list[bytes] = []
    exceeded = threading.Event()

    def read_bounded() -> None:
        try:
            assert process.stdout is not None
            data = process.stdout.read(MAX_COMMAND_BYTES + 1)
            output.append(data)
            if len(data) > MAX_COMMAND_BYTES:
                exceeded.set()
                process.kill()
        except (OSError, ValueError):
            output.append(b"")

    reader = threading.Thread(target=read_bounded, daemon=True)
    reader.start()
    error = None
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        error = "timeout"
        process.kill()
        process.wait(timeout=2)
    finally:
        reader.join(timeout=2)
        if process.stdout is not None:
            process.stdout.close()
    if exceeded.is_set():
        return CommandResult(process.returncode, error="output limit exceeded")
    if error or reader.is_alive():
        return CommandResult(process.returncode, error=error or "output incomplete")
    if process.returncode:
        return CommandResult(process.returncode, error="nonzero exit")
    raw = output[0] if output else b""
    return CommandResult(process.returncode, raw.decode("utf-8", errors="replace"))


def collect(*, runner: CommandRunner | None = None, fixture: bool = False,
            application_roots: Iterable[Path] | None = None,
            homebrew_candidates: Iterable[Path] | None = None,
            timeout: float = 5.0, max_apps: int = 200,
            max_receipts: int = 200) -> dict[str, object]:
    """Return bounded metadata; the caller owns authorization and persistence.

    Fixture mode requires an injected runner and explicit fixture-only filesystem
    roots, ensuring Windows/Linux tests never query native application paths.
    """
    if fixture:
        if runner is None or application_roots is None or homebrew_candidates is None:
            raise ValueError("Fixture mode requires a fake runner and explicit fixture roots/candidates")
    elif platform.system() != "Darwin":
        raise UnsupportedPlatform("macOS collection requires a native Darwin host")
    elif runner is not None or application_roots is not None or homebrew_candidates is not None:
        raise ValueError("Injected commands or roots require explicit fixture mode")
    if not 0.1 <= timeout <= 15 or not 1 <= max_apps <= 500 or not 1 <= max_receipts <= 500:
        raise ValueError("Collector bounds are outside the supported range")
    execute = runner or _default_runner
    limits = [
        "Selected metadata only; no exhaustive installed-software or vulnerability assessment.",
        "No update availability check, authentication, app launch, configuration change, or cleanup performed.",
        "Private projects, environments, browser data, account/configuration files, keychains and system logs excluded.",
        "Apple Installer receipt identifiers do not prove files are present or current; receipt versions were not collected.",
        "Homebrew detection only; no third-party executable or package metadata was queried.",
        "Bundle versions and bounded Mach-O labels do not establish signing, notarization, publisher ownership or secure status.",
    ]
    observations: list[dict[str, object]] = []
    command_status: dict[str, str] = {}

    def query(command: tuple[str, ...]) -> str:
        if command not in ALLOWED_COMMANDS:
            raise ValueError("Not a fixed metadata query")
        result = execute(command, timeout)
        if not isinstance(result, CommandResult):
            raise TypeError("Injected runner must return CommandResult")
        label = " ".join(command)
        if result.error or result.returncode != 0:
            command_status[label] = "unavailable or failed"
            limits.append("Selected query unavailable or failed: " + label + "; raw error suppressed.")
            return ""
        if len(result.stdout.encode("utf-8")) > MAX_COMMAND_BYTES:
            command_status[label] = "output limit exceeded"
            limits.append("Selected query exceeded output limit: " + label)
            return ""
        command_status[label] = "completed"
        return result.stdout

    os_values = parse_sw_vers(query(("/usr/bin/sw_vers",)))
    process_arch = query(("/usr/bin/uname", "-m")).strip()
    process_arch = process_arch if process_arch in ("arm64", "x86_64", "i386") else None
    arm64 = query(("/usr/sbin/sysctl", "-n", "hw.optional.arm64")).strip()
    translated = query(("/usr/sbin/sysctl", "-in", "sysctl.proc_translated")).strip()
    hardware_arch = "arm64" if arm64 == "1" else process_arch if arm64 == "0" else None
    observations.append({"kind": "operating_system", "name": "macOS", **os_values, "architecture": hardware_arch,
                         "process_architecture": process_arch,
                         "process_translated": translated == "1" if translated in ("0", "1") else None,
                         "manager": "apple-software-update", "scope": "system", "source": "fixed Apple version/architecture queries"})
    developer = query(("/usr/bin/xcode-select", "--print-path")).strip()
    if developer:
        if developer == "/Library/Developer/CommandLineTools":
            selection = "Command Line Tools"
        elif re.fullmatch(r"/Applications/[^/\r\n]{1,100}\.app/Contents/Developer", developer):
            selection = "Xcode app in system Applications"
        else:
            selection = "custom developer directory; actual path suppressed"
        observations.append({"kind": "developer_tool_selection", "name": "Active Apple developer tools", "version": None,
                             "selection": selection, "manager": "apple-developer-tools", "scope": "system",
                             "source": "xcode-select --print-path; path not retained"})
    receipts, receipt_truncated = parse_receipt_ids(query(("/usr/sbin/pkgutil", "--pkgs")), max_receipts)
    for receipt in receipts:
        observations.append({"kind": "package_receipt", "name": receipt, "version": None, "manager": "apple-installer-receipt",
                             "scope": "system", "source": "pkgutil --pkgs", "version_state": "receipt identifier only"})
    if receipt_truncated:
        limits.append("Receipt identifier limit reached; remaining identifiers were not retained.")

    roots = list(itertools.islice(application_roots if application_roots is not None else
                                 (Path("/Applications"), Path("/Applications/Utilities"), Path("/System/Applications"),
                                  Path("/System/Applications/Utilities"), Path.home() / "Applications"), MAX_ROOTS + 1))
    if len(roots) > MAX_ROOTS:
        raise ValueError("Too many application roots")
    app_count = 0
    roots_accessible = 0
    app_skipped = 0
    app_truncated = False
    for root_index, root_value in enumerate(roots):
        root = Path(root_value)
        if not root.is_absolute() or not _no_links(root) or not root.is_dir():
            limits.append("Application root " + str(root_index + 1) + " unavailable or linked; not traversed.")
            continue
        try:
            with os.scandir(root) as entries:
                bounded = list(itertools.islice(entries, MAX_ENTRIES_PER_ROOT + 1))
            roots_accessible += 1
        except OSError:
            limits.append("Application root " + str(root_index + 1) + " inaccessible; not traversed.")
            continue
        if len(bounded) > MAX_ENTRIES_PER_ROOT:
            bounded = bounded[:MAX_ENTRIES_PER_ROOT]
            app_truncated = True
        for entry in sorted(bounded, key=lambda item: item.name.casefold()):
            if not entry.name.endswith(".app"):
                continue
            if app_count >= max_apps:
                app_truncated = True
                break
            app = inspect_app(Path(entry.path), "approved application root " + str(root_index + 1))
            if app is None:
                app_skipped += 1
                continue
            observations.append(app)
            app_count += 1
    if app_truncated:
        limits.append("Application entry/record limit reached; coverage is partial.")
    if app_skipped:
        limits.append("Some application metadata was unreadable, linked, malformed, oversized or outside the safe field rules.")
    candidates = list(itertools.islice(homebrew_candidates if homebrew_candidates is not None else
                                      (Path("/opt/homebrew/bin/brew"), Path("/usr/local/bin/brew")), 3))
    if len(candidates) > 2:
        raise ValueError("Too many Homebrew candidate paths")
    detected_brew = 0
    for index, candidate in enumerate(candidates):
        if os.path.lexists(candidate):
            detected_brew += 1
            observations.append({"kind": "package_manager_candidate", "name": "Homebrew candidate " + str(index + 1),
                                 "version": None, "manager": "homebrew-unverified", "scope": "known prefix candidate",
                                 "source": "path presence only; executable not read or run", "status": "hold",
                                 "reason": "Verify provenance and package ownership separately before invoking an existing manager."})
    return {"platform": "macos", "collection_mode": "fixture" if fixture else "real",
            "observed_utc": pc_records.utc_now(),
            "observations": observations, "limits": limits,
            "coverage": {"commands": command_status, "application_roots_accessible": roots_accessible,
                         "application_records": app_count, "application_skipped": app_skipped,
                         "application_truncated": app_truncated, "receipt_identifiers": len(receipts),
                         "receipt_identifiers_truncated": receipt_truncated, "homebrew_candidates": detected_brew,
                         "homebrew_packages_inventoried": False, "native_macos_validation": "pending"}}
