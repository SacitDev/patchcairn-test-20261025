"""Fixed, bounded macOS/Linux diagnostic metadata recipes (Python 3.12+), run through readonly_runner.

No journal, Console, keychain, browser/profile, environment, process argument,
private project or credential-store reader is provided. No repair is executed.
"""
from __future__ import annotations

import re
import sys

import pc_records
import readonly_runner
from diagnostic_core import ARGV, HELD, RECIPES, TABLE, DiagnosticRefusal, validate_request, validate_adapter_result

MAX_OUTPUT = readonly_runner.DIAGNOSTIC_MAX_BYTES
TIMEOUT = readonly_runner.DIAGNOSTIC_TIMEOUT_SECONDS


def _parse(recipe_id, raw):
    """The typed facts of a recipe's stdout. uname, df and sw_vers print ASCII; any other byte is refused."""
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
    if len(columns) != 6 or columns[5] != ARGV[recipe_id][1][-1] or not all(re.fullmatch(r"[0-9]{1,20}", s) for s in columns[1:4]) or not re.fullmatch(r"[0-9]{1,3}%", columns[4]):
        raise DiagnosticRefusal("Unexpected numeric capacity metadata")
    # Filesystem source and mount labels are deliberately discarded.
    return {"total_bytes": int(columns[1]) * 1024, "used_bytes": int(columns[2]) * 1024,
            "available_bytes": int(columns[3]) * 1024, "used_percent": int(columns[4][:-1])}


def collect_recipe(request, *, runner=None, coordinator_authorized=False, probe=None):
    """Run one enumerated recipe or return an explicit capability hold.

    Fixture mode REQUIRES an injected runner and never invokes the host. Real
    mode forbids a runner, requires matching POSIX/native platform and explicit
    trusted-coordinator call authority, and runs the recipe through readonly_runner
    (``probe`` answers its host lookups; tests pass a fake). A JSON boolean is not
    user consent. A held recipe holds in both modes and nothing runs.
    """
    request = validate_request(request)
    recipe_id = request["recipe_id"]
    if RECIPES[recipe_id] not in ("macos", "linux"):
        raise DiagnosticRefusal("POSIX adapter cannot handle this recipe")
    result = {key: request[key] for key in ("schema", "schema_version", "request_id", "platform", "recipe_id", "mode")}
    result.update(kind="adapter_result", status="held", observed_utc=pc_records.utc_now(), facts={},
                  limitations=["Metadata observation cannot establish the original cause or verify application behavior."],
                  provenance=list(TABLE[recipe_id].sources))
    if recipe_id in HELD:
        result["limitations"].append(HELD[recipe_id])
        return validate_adapter_result(request, result)
    expected_scope = ["root_capacity"] if recipe_id.endswith("root_capacity") else ["os_metadata"]
    if request["scope"] != expected_scope:
        raise DiagnosticRefusal("Recipe requires its exact selected metadata scope")
    candidates, arguments = ARGV[recipe_id]
    # Never retain exception text, stderr or malformed stdout: they may hold
    # private paths or secrets even when a selected command failed.
    if request["mode"] == "fixture":
        if runner is None:
            result["limitations"].append("Fixture requires an explicit fictional runner; no host query occurred.")
            return validate_adapter_result(request, result)
        result["limitations"].append("Fictional injected recipe output; native behavior remains unverified.")
        try:
            raw = runner((candidates[0], *arguments), timeout=TIMEOUT, max_bytes=MAX_OUTPUT)
        except (OSError, ValueError, TypeError):
            return _failed(request, result)
    else:
        if runner is not None:
            raise DiagnosticRefusal("Injected output cannot become a real observation")
        probe = probe or readonly_runner.HostProbe()
        native = "macos" if probe.platform == "darwin" else "linux" if probe.platform.startswith("linux") else "unsupported"
        if coordinator_authorized is not True or native != request["platform"] or sys.version_info < (3, 12):
            result["limitations"].append("Native platform, supported Python and current coordinator collection authority are required; no query occurred.")
            return validate_adapter_result(request, result)
        try:
            found = readonly_runner.run_recipe(recipe_id, probe=probe)
        except pc_records.Refusal as error:
            if error.code != "runner-executable":
                return _failed(request, result)
            result["limitations"].append("A protected supported OS tool was unavailable; no query occurred.")
            return validate_adapter_result(request, result)
        if not found["ok"]:
            return _failed(request, result)
        raw = found["stdout"]
    try:
        result.update(status="observed", facts=_parse(recipe_id, raw), observed_utc=pc_records.utc_now())
        return validate_adapter_result(request, result)
    except (OSError, ValueError, TypeError):
        return _failed(request, result)


def _failed(request, result):
    """``result`` as a categorical failure: no facts, no exception text and no output kept."""
    result.update(status="failed", facts={}, observed_utc=pc_records.utc_now())
    result["limitations"].append("Selected metadata was unavailable, malformed, oversized or timed out; no cause is established.")
    return validate_adapter_result(request, result)
