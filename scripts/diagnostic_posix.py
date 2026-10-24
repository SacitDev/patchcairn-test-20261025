"""Fixed, bounded macOS/Linux diagnostic metadata recipes (Python 3.12+).

No journal, Console, keychain, browser/profile, environment, process argument,
private project or credential-store reader is provided. No repair is executed.
"""
from __future__ import annotations

import os
import re
import selectors
import stat
import subprocess
import sys
import time
from pathlib import Path

from diagnostic_core import DiagnosticRefusal, SCHEMA, utc_now, validate_request, validate_adapter_result

MAX_OUTPUT = 4096
TIMEOUT = 5
PROVENANCE = {
    "macos.os_version": ["https://developer.apple.com/documentation/technologyoverviews/building-your-macos-game-remotely-from-your-pc"],
    "macos.root_capacity": ["https://raw.githubusercontent.com/apple-oss-distributions/file_cmds/main/df/df.1"],
    "linux.kernel_version": ["https://www.gnu.org/software/coreutils/manual/html_node/uname-invocation.html"],
    "linux.root_capacity": ["https://www.gnu.org/software/coreutils/manual/html_node/df-invocation.html"],
}
ARGV = {
    "macos.os_version": (("/usr/bin/sw_vers",), ("-productVersion",)),
    "macos.root_capacity": (("/bin/df",), ("-k", "-I", "/")),
    "linux.kernel_version": (("/usr/bin/uname", "/bin/uname"), ("-r",)),
    "linux.root_capacity": (("/usr/bin/df", "/bin/df"), ("-Pk", "/")),
}


def _trusted_executable(candidates):
    """Resolve only fixed OS-tool candidates; reject writable/non-root tools."""
    for candidate in candidates:
        try:
            path = Path(candidate).resolve(strict=True)
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111:
                continue
            for ancestor in path.parents:
                parent = ancestor.stat()
                if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
                    raise DiagnosticRefusal("Untrusted system-tool ancestry")
            return str(path)
        except (OSError, DiagnosticRefusal):
            continue
    raise DiagnosticRefusal("Supported protected system tool unavailable")


def _run_bounded(argv, *, timeout=TIMEOUT, max_bytes=MAX_OUTPUT):
    """Read at most cap+1 bytes in memory and discard stderr without persisting it."""
    process = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, cwd="/", close_fds=True,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DiagnosticRefusal("Diagnostic recipe timed out")
                ready = selector.select(remaining)
                if not ready:
                    raise DiagnosticRefusal("Diagnostic recipe timed out")
                chunk = os.read(process.stdout.fileno(), min(1024, max_bytes + 1 - len(output)))
                if not chunk:
                    selector.unregister(process.stdout)
                else:
                    output.extend(chunk)
                    if len(output) > max_bytes:
                        raise DiagnosticRefusal("Diagnostic output cap exceeded")
        status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if status != 0:
            raise DiagnosticRefusal("Diagnostic recipe returned a failure status")
        return bytes(output)
    finally:
        try:
            if process.poll() is None:
                process.kill()
            # A process stuck inside a kernel operation may not exit promptly.
            # Do not turn a diagnostic timeout into an unbounded helper wait.
            process.wait(timeout=1)
        finally:
            process.stdout.close()


def _parse(recipe_id, raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_OUTPUT:
        raise DiagnosticRefusal("Bounded byte output required")
    try:
        text = raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise DiagnosticRefusal("Unexpected noncategorical metadata") from exc
    if recipe_id == "macos.os_version":
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", text):
            raise DiagnosticRefusal("Unexpected macOS version output")
        return {"product_version": text}
    if recipe_id == "linux.kernel_version":
        if not re.fullmatch(r"[0-9][A-Za-z0-9._+~^-]{0,95}", text):
            raise DiagnosticRefusal("Unexpected kernel release output")
        return {"kernel_release": text}
    lines = text.splitlines()
    if len(lines) != 2:
        raise DiagnosticRefusal("Unexpected capacity output shape")
    columns = lines[1].split()
    if len(columns) != 6 or columns[5] != "/" or not all(re.fullmatch(r"[0-9]{1,20}", s) for s in columns[1:4]) or not re.fullmatch(r"[0-9]{1,3}%", columns[4]):
        raise DiagnosticRefusal("Unexpected numeric capacity metadata")
    # Filesystem source and mount labels are deliberately discarded.
    return {"total_bytes": int(columns[1]) * 1024, "used_bytes": int(columns[2]) * 1024,
            "available_bytes": int(columns[3]) * 1024, "used_percent": int(columns[4][:-1])}


def collect_recipe(request, *, runner=None, coordinator_authorized=False):
    """Run one enumerated recipe or return an explicit capability hold.

    Fixture mode REQUIRES an injected runner and never invokes the host. Real
    mode forbids a runner, requires matching POSIX/native platform and explicit
    trusted-coordinator call authority. A JSON boolean is not user consent.
    """
    request = validate_request(request)
    recipe_id = request["recipe_id"]
    if recipe_id not in ARGV:
        raise DiagnosticRefusal("POSIX adapter cannot handle this recipe")
    expected_scope = ["root_capacity"] if recipe_id.endswith("root_capacity") else ["os_metadata"]
    if request["scope"] != expected_scope:
        raise DiagnosticRefusal("Recipe requires its exact selected metadata scope")
    result = {key: request[key] for key in ("schema_version", "request_id", "platform", "recipe_id", "mode")}
    result.update(kind="adapter_result", status="held", observed_utc=utc_now(), facts={},
                  limitations=["Metadata observation cannot establish the original cause or verify application behavior."],
                  provenance=PROVENANCE[recipe_id])
    if request["mode"] == "fixture":
        if runner is None:
            result["limitations"].append("Fixture requires an explicit fictional runner; no host query occurred.")
            return validate_adapter_result(request, result)
        executable = ARGV[recipe_id][0][0]
        result["limitations"].append("Fictional injected recipe output; native behavior remains unverified.")
    else:
        if runner is not None:
            raise DiagnosticRefusal("Injected output cannot become a real observation")
        native = "macos" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "unsupported"
        if coordinator_authorized is not True or os.name != "posix" or native != request["platform"] or sys.version_info < (3, 12):
            result["limitations"].append("Native platform, supported Python and current coordinator collection authority are required; no query occurred.")
            return validate_adapter_result(request, result)
        try:
            executable = _trusted_executable(ARGV[recipe_id][0])
        except DiagnosticRefusal:
            result["limitations"].append("A protected supported OS tool was unavailable; no query occurred.")
            return validate_adapter_result(request, result)
        runner = _run_bounded
    argv = (executable, *ARGV[recipe_id][1])
    try:
        facts = _parse(recipe_id, runner(argv, timeout=TIMEOUT, max_bytes=MAX_OUTPUT))
        result.update(status="observed", facts=facts, observed_utc=utc_now())
        return validate_adapter_result(request, result)
    except (DiagnosticRefusal, OSError, subprocess.SubprocessError, ValueError, TypeError):
        # Never retain exception text, stderr or malformed stdout: they may hold
        # private paths or secrets even when a selected command failed.
        result.update(status="failed", facts={}, observed_utc=utc_now())
        result["limitations"].append("Selected metadata was unavailable, malformed, oversized or timed out; no cause is established.")
        return validate_adapter_result(request, result)
