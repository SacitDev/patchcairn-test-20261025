r"""Windows diagnostic recipes (layer L2): the OS version and the work drive's capacity in-process, and the update and
event recipes in diagnostic_windows.ps1, which this module starts as a read-only process.

The helper starts only as <GetSystemDirectoryW>\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive
-File <scripts>\diagnostic_windows.ps1 -RequestPath <request file> -CoordinatorAuthorized: no shell and no window,
stdin from the null device, an environment built from scratch (SystemRoot, WINDIR and PSModulePath, the shell's own
module folder; never PSExecutionPolicyPreference), a time limit and an output bound. -ExecutionPolicy is never passed
and the policy is never changed: when the policy refuses the script, the result holds, and only the computer's owner
may change the policy. The service starts the helper only for an approved real-session diagnostic action.
"""
from __future__ import annotations

import ntpath
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time

import pc_records
import readonly_runner
import win32_files
from diagnostic_core import HELD, MAX_RECORD, TABLE, DiagnosticRefusal, validate_adapter_result, validate_request
from private_workspace import write_private_new

HELPER = Path(__file__).absolute().with_name("diagnostic_windows.ps1")
HELPER_TIMEOUT_SECONDS, HELPER_MAX_BYTES = 120, MAX_RECORD
# Exit status 0xFFFF0000: Windows PowerShell itself did not load (for example without SystemRoot).
START_FAILURE = 0xFFFF0000
# What stops the script under the script policy: the helper's own codes, and the invariant error id Windows PowerShell
# prints when the policy refuses to load a script ("+ FullyQualifiedErrorId : UnauthorizedAccess").
_POLICY = re.compile(r"diagnostic:(?:foreign-module|execution-policy-override)\b"
                     r"|^[ \t]*\+[ \t]*FullyQualifiedErrorId[ \t]*:[ \t]*UnauthorizedAccess[ \t]*\r?$", re.MULTILINE)
# The plain words of each typed hold (the result's "hold").
GUIDANCE = {
    "windows-script-policy": "Windows did not let PatchCairn's read-only PowerShell script run under this computer's script "
                             "policy. Only the computer's owner may change that policy; PatchCairn never changes or bypasses it.",
    "windows-helper-start": "Windows PowerShell could not start for this read-only check; nothing was collected.",
    "windows-helper-timeout": "The read-only PowerShell check did not finish in time and was stopped; nothing was kept.",
    "windows-helper-output": "The read-only PowerShell check printed more than its output limit and was stopped; nothing was kept.",
}
_MACHINES = {0x8664: "x64", 0xAA64: "arm64", 0x014C: "x86"}  # IMAGE_FILE_MACHINE_AMD64, _ARM64, _I386


class WindowsProbe(readonly_runner.HostProbe):
    """readonly_runner's host facts plus those of the in-process recipes; tests pass a fake with the same methods."""

    def windows_version(self):
        """(major, minor, build) of the running Windows, not a version a compatibility layer reports."""
        return sys.getwindowsversion().platform_version

    def native_machine(self):
        """The hardware architecture (x64, arm64 or x86) from IsWow64Process2, also under emulation; else "unknown"."""
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        query = getattr(kernel, "IsWow64Process2", None)
        if query is None:
            return "unknown"
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        query.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
        process, native = wintypes.USHORT(), wintypes.USHORT()
        if not query(kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(native)):
            return "unknown"
        return _MACHINES.get(native.value, "unknown")

    def disk_usage(self, path):
        """(total bytes, bytes this user may use: a per-user quota counts) of the drive that holds ``path``."""
        return win32_files.disk_space(str(path))


def helper_start(system_directory, request_path):
    """(argv, environment) of the one helper start, from the Windows system folder (GetSystemDirectoryW)."""
    shell = ntpath.join(system_directory, r"WindowsPowerShell\v1.0")
    windows = ntpath.dirname(system_directory.rstrip("\\"))
    argv = (ntpath.join(shell, "powershell.exe"), "-NoProfile", "-NonInteractive", "-File", str(HELPER),
            "-RequestPath", str(request_path), "-CoordinatorAuthorized")
    return argv, {"SystemRoot": windows, "WINDIR": windows, "PSModulePath": ntpath.join(shell, "Modules")}


def hold_of(exit_code, stderr):
    """The typed hold of a finished helper, or None. A failed start (exit 0xFFFF0000, or native error text in UTF-16,
    whose NUL bytes PowerShell's own text never has) is windows-helper-start, never the policy hold."""
    if exit_code & 0xFFFFFFFF == START_FAILURE or b"\x00" in stderr:
        return "windows-helper-start"
    if _POLICY.search(stderr.decode("ascii", errors="replace")):
        return "windows-script-policy"
    return None


def _launch(argv, *, env, cwd, timeout, max_bytes):
    """Start argv (a list, no shell, no window) with stdin from the null device and read stdout and stderr up to
    max_bytes each; returns (exit code, stdout, stderr). A process past its timeout or bound is killed, and a
    DiagnosticRefusal with the hold code is raised (windows-helper-timeout or windows-helper-output); a failed start
    raises windows-helper-start."""
    try:
        process = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                   cwd=cwd, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as error:
        raise DiagnosticRefusal("Windows PowerShell could not be started", code="windows-helper-start") from error
    over, outputs = threading.Event(), ([], [])

    def read(stream, chunks):
        size = 0
        while chunk := stream.read1(65536):
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                over.set()
                return

    readers = [threading.Thread(target=read, args=pair, daemon=True) for pair in zip((process.stdout, process.stderr), outputs)]
    deadline, finished = time.monotonic() + timeout, False
    try:
        for reader in readers:
            reader.start()
        while not over.is_set() and any(reader.is_alive() for reader in readers) and time.monotonic() < deadline:
            over.wait(min(0.1, max(deadline - time.monotonic(), 0)))
        if over.is_set():
            raise DiagnosticRefusal("The helper printed more than its output bound", code="windows-helper-output")
        try:
            if any(reader.is_alive() for reader in readers):
                raise subprocess.TimeoutExpired(argv, timeout)
            code, finished = process.wait(timeout=max(deadline - time.monotonic(), 0.1)), True
        except subprocess.TimeoutExpired:
            raise DiagnosticRefusal("The helper did not finish in time", code="windows-helper-timeout") from None
        return code, b"".join(outputs[0]), b"".join(outputs[1])
    finally:
        if not finished:
            try:
                process.kill()
                process.wait(timeout=readonly_runner.KILL_WAIT_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for reader, stream in zip(readers, (process.stdout, process.stderr)):
            reader.join(readonly_runner.KILL_WAIT_SECONDS)
            if not reader.is_alive():  # a pipe a reader still blocks on is left to the daemon thread
                stream.close()


def _helper(request, result, folder, probe, launcher):
    """Start the helper for ``request``: its checked result, or ``result`` held with a typed hold or failed."""
    def held(code):
        result.update(hold=code, observed_utc=pc_records.utc_now())
        result["limitations"].append(GUIDANCE[code])
        return validate_adapter_result(request, result)

    system = probe.system_directory()
    request_path = Path(folder) / "helper-input.json"
    argv, env = helper_start(system, request_path)
    try:
        if not stat.S_ISREG(probe.lstat(argv[0]).st_mode) or probe.reparse_tag(argv[0]) != 0:
            return held("windows-helper-start")
    except OSError:
        return held("windows-helper-start")
    write_private_new(request_path, pc_records.encoded(request))
    try:
        code, stdout, stderr = (launcher or _launch)(argv, env=env, cwd=system, timeout=HELPER_TIMEOUT_SECONDS, max_bytes=HELPER_MAX_BYTES)
    except DiagnosticRefusal as error:
        if error.code not in GUIDANCE:
            raise
        return held(error.code)
    if type(code) is not int or not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise DiagnosticRefusal("The process result is not an exit code and output bytes")
    if max(len(stdout), len(stderr)) > HELPER_MAX_BYTES:
        return held("windows-helper-output")
    hold = hold_of(code, stderr)
    if hold:
        return held(hold)
    try:
        # The helper prints one ASCII JSON line; its stderr text and any other output are never kept.
        if code != 0 or not stdout.isascii():
            raise DiagnosticRefusal("The helper printed no result")
        return validate_adapter_result(request, pc_records.decode_strict(stdout, max_bytes=HELPER_MAX_BYTES))
    except (ValueError, TypeError):
        result.update(status="failed", observed_utc=pc_records.utc_now())
        result["limitations"].append("The read-only PowerShell check failed or printed no valid result; no cause is established.")
        return validate_adapter_result(request, result)


def _in_process(recipe_id, probe, work):
    """(facts, limitation) of an in-process recipe."""
    if recipe_id == "windows.os_version":
        major, minor, build = probe.windows_version()
        return ({"version": f"{major}.{minor}.{build}", "build": str(build), "architecture": probe.native_machine()},
                "Version context does not establish support, update completeness or security remediation.")
    total, available = probe.disk_usage(work)
    return ({"total_bytes": total, "available_bytes": available},
            "Free space of the drive that holds PatchCairn's work folder, at one moment; other drives were not measured.")


def collect_recipe(request, *, folder, work, coordinator_authorized=False, launcher=None, probe=None):
    """Run one Windows recipe for ``request``, or return an explicit hold. ``folder`` is the operation's private folder
    (the helper's request file goes there); ``work`` is PatchCairn's work folder, whose drive the capacity recipe measures.
    Only a real request with ``coordinator_authorized`` True (an approved real-session action), on Windows, reads this
    computer; a fixture request never does (the caller checks its fictional result). A held recipe always holds.
    ``launcher`` and ``probe`` replace the process start and the host facts in tests."""
    request = validate_request(request)
    recipe_id = request["recipe_id"]
    row = TABLE[recipe_id]
    if row.platform != "windows":
        raise DiagnosticRefusal("Windows adapter cannot handle this recipe")
    result = {key: request[key] for key in ("schema", "schema_version", "request_id", "platform", "recipe_id", "mode")}
    result.update(kind="adapter_result", status="held", observed_utc=pc_records.utc_now(), facts={},
                  limitations=["Metadata observation cannot establish the original cause or verify application behavior."],
                  provenance=list(row.sources))
    probe = probe or WindowsProbe()
    if recipe_id in HELD:
        result["limitations"].append(HELD[recipe_id])
    elif request["mode"] != "real":
        result["limitations"].append("Fixture requires an explicit fictional result; no host query occurred.")
    elif coordinator_authorized is not True or probe.platform != "win32":
        result["limitations"].append("Native Windows and an approved diagnostic action are required; no query occurred.")
    elif row.run == "helper":
        return _helper(request, result, folder, probe, launcher)
    elif request["scope"] != []:
        raise DiagnosticRefusal("Recipe requires its exact selected metadata scope")
    else:
        try:
            facts, limitation = _in_process(recipe_id, probe, work)
            result.update(status="observed", facts=facts, observed_utc=pc_records.utc_now())
            result["limitations"].append(limitation)
            return validate_adapter_result(request, result)
        except (OSError, ValueError, TypeError):
            # The exception text may hold a private path; only a categorical failure is kept.
            result.update(status="failed", facts={}, observed_utc=pc_records.utc_now())
            result["limitations"][1:] = ["Selected metadata was unavailable or malformed; no cause is established."]
    return validate_adapter_result(request, result)
