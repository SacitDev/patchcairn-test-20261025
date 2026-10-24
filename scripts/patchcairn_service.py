"""Read-only inspection of gated workflow services; no mutation/import CLI."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
from workflow_core import WorkflowEngine, WorkflowRefusal
from workflow_service import WorkflowService, ServiceRefusal, STORAGE, OFFICIAL_DOMAINS, ARTIFACT_EXTENSIONS
from diagnostic_core import DiagnosticRefusal


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect PatchCairn service state and fixed supported adapters. No imported plan execution or maintenance mutation command is exposed.")
    parser.add_argument("--session-work", default="work/sessions")
    parser.add_argument("--service-work", default="work/services")
    parser.add_argument("--json", action="store_true", help="Internal structured evidence")
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("catalog", help="List fixed service capabilities without collecting host evidence")
    status = sub.add_parser("status")
    status.add_argument("session_id")
    inspect = sub.add_parser("inspect-operation")
    inspect.add_argument("session_id")
    inspect.add_argument("operation_id")
    args = parser.parse_args(argv)
    try:
        if args.operation == "catalog":
            data = {"storage_adapters": list(STORAGE), "diagnostic_adapter": "diagnostic.read_recipe.v3",
                    "external_handoff_catalog": list(ARTIFACT_EXTENSIONS), "held_external_catalog": sorted(set(OFFICIAL_DOMAINS) - set(ARTIFACT_EXTENSIONS)),
                    "external_execution": False, "external_repair_enabled": False}
            print(json.dumps(data, sort_keys=True) if args.json else "PatchCairn — Developed by Michael\n\nFixed storage and selected diagnostic adapters are available through the reviewed workflow. Official update operations are exact assistant handoffs; this service does not execute them. OS/app repair stays held while required component recovery is unsupported. Use chat to establish scope, review the plan and record your decision.")
            return 0
        engine = WorkflowEngine(work_relative=args.session_work)
        if args.operation == "status":
            result = engine.status(args.session_id)
            print(json.dumps(result, sort_keys=True) if args.json else result["message"])
        else:
            result = WorkflowService(engine, work_relative=args.service_work).inspect_operation(args.session_id, operation_id=args.operation_id)
            print(json.dumps(result, sort_keys=True) if args.json else "Operation outcome: " + str(result["operation"]["outcome"] or "awaiting actual evidence") + ". Preserve the reviewed intent and existing native receipts. A missing receipt does not permit retry or establish success.")
        return 0
    except (WorkflowRefusal, ServiceRefusal, DiagnosticRefusal, OSError, ValueError):
        print("Service hold: the exact owned state, selected scope or supported capability could not be verified. Preserve the operation and review its bounded evidence; no new host action was started.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
