"""PatchCairn service command line: read-only inspection, the session report view, the kept-recovery listing, and the
ticket-bound launcher that runs exactly one approved, reviewed package step. Start it only as
"<python>" -I -S -B patchcairn_service.py ...; any other start is refused before anything is written."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
from workflow_core import WorkflowEngine, WorkflowRefusal, older_format_message, restart_state, retained_text, run_ticket_text
from workflow_service import WorkflowService, ServiceRefusal, DiagnosticRefusal, STORAGE, DIAGNOSTIC_ADAPTER_ID
from storage_ops import ScopedFSError, StorageRefusal

ISOLATION_REFUSAL = ("PatchCairn starts this tool only as \"<python>\" -I -S -B patchcairn_service.py ..., so no other Python "
                     "files or settings can change what it runs. Nothing was written or changed.")
CATALOG = ("PatchCairn — Developed by Michael\n\nFixed storage and selected diagnostic adapters are available through the reviewed "
           "workflow. An approved package update runs only through the ticket-bound launcher (patchcairn_service.py run --ticket "
           "<ticket>), which runs exactly one approved, reviewed step. Repairs run the same way: an app update, a same-version reinstall "
           "(Mac, Linux) or finishing interrupted package setup (Debian, Ubuntu). PatchCairn does not repair Windows itself. Use chat to "
           "establish scope, review the plan and record your decision.")
REPORT_NOTE = ("Open it in a web browser. It is a copy for reading, not evidence: anyone who can edit the file can change it, and "
               "PatchCairn never reads it back.")
GENERAL_CODES = frozenset({"workflow-refusal", "service-refusal"})
GO_BACK = "Go back to the chat and say PatchCairn: status."


def _hold_text(error):
    """What the person reads when the tool stops: a refusal's plain reason, and any code more specific than the general ones,
    which names the cause; anything else says only what to do next."""
    code = getattr(error, "code", None)
    named = f" ({code})" if code and code not in GENERAL_CODES else ""
    if isinstance(error, (WorkflowRefusal, ServiceRefusal)):
        return "PatchCairn stopped here: " + str(error).rstrip(". ") + named + ". " + GO_BACK
    return "PatchCairn could not finish this step" + named + ". Do not run the command again. " + GO_BACK


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")  # a printed command may hold any character of a folder's name
    parser = argparse.ArgumentParser(description="Inspect PatchCairn service state, write a session report view, list kept recovery "
                                                 "data, or run one approved ticket. No imported plan is ever executed.")
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
    report = sub.add_parser("report", help="Write an HTML view of one session under the private work folder")
    report.add_argument("session_id")
    sub.add_parser("retention", help="List kept backups and recovery data with their sizes")
    run = sub.add_parser("run", help="Run exactly one approved, reviewed package step")
    run.add_argument("--ticket", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "catalog":
            data = {"storage_adapters": list(STORAGE), "diagnostic_adapter": DIAGNOSTIC_ADAPTER_ID, "ticket_launcher": "run --ticket"}
            print(json.dumps(data, sort_keys=True) if args.json else CATALOG)
            return 0
        engine = WorkflowEngine(work_relative=args.session_work)
        if args.operation == "status":
            result = engine.status(args.session_id)
            print(json.dumps(result, sort_keys=True) if args.json else result["message"])
            return 0
        service = WorkflowService(engine, work_relative=args.service_work)
        if args.operation == "inspect-operation":
            result = service.inspect_operation(args.session_id, operation_id=args.operation_id)
            operation = result["operation"]
            restarting = operation["outcome"] is None and restart_state(operation) != "none"
            command = service.ticket_command(args.session_id, operation_id=args.operation_id) if restarting else None
            print(json.dumps({**result, "check_command": command} if command else result, sort_keys=True) if args.json else "Operation outcome: " + str(operation["outcome"] or "awaiting actual evidence") + ". Preserve the reviewed intent and existing native receipts. A missing receipt does not permit retry or establish success." + ("\nTo check the result after the restart, run: " + command if command else ""))
        elif args.operation == "report":
            path = service.session_report(args.session_id)
            print(json.dumps({"report_path": str(path), "view_not_evidence": True}, sort_keys=True) if args.json
                  else "Your report is saved at " + str(path) + ".\n" + REPORT_NOTE)
        elif args.operation == "retention":
            rows = service.retention_rows()
            total = sum(row["bytes"] for row in rows if row["bytes"] is not None)
            print(json.dumps({"rows": rows, "total_bytes": total}, sort_keys=True) if args.json else retained_text(rows))
        else:
            result = service.run_ticket(ticket_id=args.ticket)
            print(json.dumps(result, sort_keys=True) if args.json else run_ticket_text(result))
            return 2 if "hold" in result else 0
        return 0
    except (WorkflowRefusal, ServiceRefusal, DiagnosticRefusal, StorageRefusal, ScopedFSError, OSError, ValueError) as error:
        # Records in an older format are never migrated; the person reads the plain reason and next step.
        print(older_format_message(error) or _hold_text(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    if not (sys.flags.isolated and sys.flags.no_site):
        print(ISOLATION_REFUSAL, file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
