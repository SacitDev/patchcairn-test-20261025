"""The update and repair families' payload binding: the one reader of the package payload (patchcairn.package) and the
binding of that payload to its reviewed action. Nothing is installed here; the service runs the bound payload.
Functions that need the engine take it as ``engine`` (workflow_core.WorkflowEngine), the context described there.
"""
from __future__ import annotations

import re

from engine_journal import PACKAGE, PACKAGE_RUN, RECORD_FIELDS, SHA, WorkflowRefusal, checked
from engine_plans import json_data
import pc_records

# The payload operation of each update and repair adapter.
OPERATIONS = {pc_records.ADAPTER_PACKAGE_UPGRADE: "upgrade", pc_records.ADAPTER_PACKAGE_REINSTALL: "reinstall",
              pc_records.ADAPTER_SYSTEM_REPAIR: "repair", pc_records.ADAPTER_SYSTEM_UPDATE_HANDOFF: "system_update",
              pc_records.ADAPTER_SYSTEM_FIRMWARE_UPDATE: "firmware_update"}
# The decision a flag calls for, which the owner gives in a message of its own (pc_records.CONDITIONAL_DECISIONS).
CONDITIONAL_FLAGS = {"install_scripts": "run_install_scripts", "runtime_line_change": "runtime_line_change"}
# A value from a manager (an id, version, source or name@version): no leading "-", nothing a shell would need quoted but the
# comma of a cask version, which package_routes.variable still refuses in anything that enters an argv.
_TOKEN = re.compile(r"(?!-)(?!.*:~)[A-Za-z0-9_.+:@~/,-]{1,256}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_RECIPE = re.compile(r"[a-z0-9_]{1,32}(?:\.[a-z0-9_]{1,32}){1,3}\Z")
_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
_PAGE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")


def _refuse(rule, message):
    raise WorkflowRefusal(message, code="package-payload-" + rule)


def _matches(pattern, value):
    return isinstance(value, str) and bool(pattern.match(value))


def _tokens(value, limit=500):
    """A list of distinct manager values."""
    return isinstance(value, list) and len(value) <= limit and all(_matches(_TOKEN, item) for item in value) and len(set(value)) == len(value)


def _path(value):
    return isinstance(value, str) and 0 < len(value) <= 1024 and not any(ord(char) < 32 or ord(char) == 127 for char in value)


def read_package(record):
    """The one reader of the package payload (patchcairn.package): its exact fields, how they combine and each field's
    shape, with one refusal code per rule. update_binding adds the rules that depend on the adapter."""
    checked(pc_records.require_schema, record, PACKAGE)
    fields = set(record) - {"schema", "schema_version"}
    required, optional = RECORD_FIELDS[PACKAGE]
    if fields - required - optional or required - fields:
        _refuse("unknown-key", "A package payload has exactly the fields of its contract")
    if record["run_kind"] not in pc_records.RUN_KINDS:
        _refuse("run-kind", "A package payload runs as a process, in a terminal or as a Settings step")
    settings = record["run_kind"] == "settings"
    if settings and (PACKAGE_RUN & fields or "settings_page" not in fields):
        _refuse("settings", "A Settings step names its page and carries no recipe, executable or run files")
    if not settings and ("settings_page" in fields or PACKAGE_RUN - fields):
        _refuse("settings-page", "A run that PatchCairn starts carries its recipe, executable and run files, and no Settings page")
    flags = record["flags"]
    if not isinstance(flags, list) or not all(isinstance(flag, str) and flag in pc_records.ROUTE_FLAGS for flag in flags) or len(set(flags)) != len(flags):
        _refuse("flags", "Route flags must be distinct known flags")
    expected = {CONDITIONAL_FLAGS[flag] for flag in flags if flag in CONDITIONAL_FLAGS}
    if "conditional" in fields or expected:
        conditional = record.get("conditional")
        names = conditional.get("run_install_scripts") if isinstance(conditional, dict) else None
        if (not isinstance(conditional, dict) or set(conditional) != expected or conditional.get("runtime_line_change", []) != []
                or "run_install_scripts" in expected and (not names or not _tokens(names) or names != sorted(names) or any("@" not in name for name in names))):
            _refuse("conditional", "A payload carries exactly the separate decisions its flags call for")
    device = record.get("device")
    if "device" in fields and (not isinstance(device, dict) or set(device) != {"id", "number", "target_version"} or not _matches(_TOKEN, device["id"])
                               or type(device["number"]) is not int or not 1 <= device["number"] <= 999 or not _matches(_TOKEN, device["target_version"])):
        _refuse("device", "A firmware update names exactly one device: its id, number and target version")
    update = record.get("update")
    if (not _matches(_NAME, record["manager"]) or record["operation"] not in OPERATIONS.values() or not _matches(_TOKEN, record["id"])
            or not (_matches(_TOKEN, record["version"]) or record["version"] is None and "update" in fields) or not _matches(_TOKEN, record["source"])
            or record["group"] not in pc_records.OUTCOME_GROUPS or not isinstance(record["preflight"], dict)
            or not _matches(SHA, record["transaction_sha256"]) or record["transaction_sha256"] != checked(pc_records.digest, record["preflight"])
            or "depends_on" in fields and not (isinstance(record["depends_on"], list) and len(record["depends_on"]) <= 100
                                               and all(_matches(pc_records.ID, item) for item in record["depends_on"])
                                               and len(set(record["depends_on"])) == len(record["depends_on"]))
            or "update" in fields and (not settings or not isinstance(update, dict) or set(update) != {"update_id", "revision"}
                                       or not _matches(_GUID, update["update_id"]) or type(update["revision"]) is not int
                                       or not 0 <= update["revision"] < 2 ** 31)
            or settings and not _matches(_PAGE, record["settings_page"])):
        _refuse("field", "A package payload field does not have its contract's shape")
    if not settings:
        executable, files = record["executable"], record["run_files"]
        if (not _tokens(record["dependencies"]) or not isinstance(record["agreements"], list) or not _matches(_RECIPE, record["recipe"])
                or not isinstance(files, dict) or len(files) > 20 or any(not _matches(_FILE, name) or not _matches(SHA, value) for name, value in files.items())
                or not isinstance(executable, dict) or set(executable) != {"kind", "path", "identity"} or not _matches(_NAME, executable["kind"])
                or not _path(executable["path"]) or not isinstance(executable["identity"], dict) or not _matches(SHA, record["environment_sha256"])):
            _refuse("field", "A package payload's run fields do not have their contract's shape")
    return record


pc_records.register_reader(PACKAGE, read_package)


def update_binding(engine, state, action, payload, inventory):
    """The payload binding of an update or repair family action (pc_records.ADAPTERS), reached from
    engine_plans.action_binding through the engine after its payload and inventory hash checks. Every adapter in
    OPERATIONS takes the package payload the same way, whatever its manager: the payload's own contract (read_package),
    then the rules that depend on the adapter (its operation, run kinds and separate decisions; a firmware update's one
    device and flags), then the reviewed transaction, which the action's adapter_plan_sha256 binds. The service checks the
    manager against its registry."""
    adapter = action["adapter_id"]
    read_package(payload)
    json_data(payload)
    facts, firmware = pc_records.ADAPTERS[adapter], adapter == pc_records.ADAPTER_SYSTEM_FIRMWARE_UPDATE
    if payload["operation"] != OPERATIONS[adapter]:
        _refuse("operation", "The payload's operation is not its adapter's")
    if payload["run_kind"] not in facts["run_kinds"]:
        _refuse("run-kind", "This adapter does not run that way")
    if ("device" in payload) != firmware:
        _refuse("device", "Only a firmware update names a device, and it names exactly one")
    if firmware and not {"firmware", "high_risk"} <= set(payload["flags"]):
        _refuse("firmware-flags", "A firmware update is flagged as firmware and high risk")
    if set(payload.get("conditional", ())) - set(facts["conditional_decisions"]):
        _refuse("conditional", "This adapter takes no such separate decision")
    if payload["transaction_sha256"] != action["adapter_plan_sha256"]:
        raise WorkflowRefusal("The package payload does not bind the exact reviewed transaction")
