#!/usr/bin/env python3
"""Structured PatchCairn operations. No arbitrary command execution."""
import argparse
import json
import sys
from pathlib import Path
sys.dont_write_bytecode = True
# Isolated (-I) Python deliberately omits the script directory. Add only the
# trusted sibling directory derived from this entry point, never the CWD/PATH.
sys.path.insert(0, str(Path(__file__).absolute().parent))
from posix_core import Toolkit, Refusal, decode, private_read, relative


def main():
    parser = argparse.ArgumentParser(description="PatchCairn: use python3 -B; Start means assessment, never updates.")
    parser.add_argument("operation", choices=["new-run", "read-ledger", "validate", "set-ledger", "set-plan", "write-artifact",
                        "build-report", "collect-baseline", "release-recovery", "plan-cleanup", "approve-cleanup", "apply-cleanup", "export"])
    parser.add_argument("--run-id")
    parser.add_argument("--mode", default="fixture", choices=["fixture", "real"])
    parser.add_argument("--platform", default="unknown", choices=["unknown", "windows", "linux", "macos"])
    parser.add_argument("--purpose", default="Assessment record")
    parser.add_argument("--input", help="Relative input under this toolkit's work directory only")
    parser.add_argument("--path", help="Owned run-relative output path")
    parser.add_argument("--role", choices=["evidence", "temporary", "backup"], default="evidence")
    parser.add_argument("--scope", choices=["Temporary", "CompletedRun"], default="Temporary")
    parser.add_argument("--plan-id")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--approval-id")
    parser.add_argument("--owner-quote", help="Actual current-owner consent; a string is not independent proof of consent")
    parser.add_argument("--artifact-sha256", help="Exact current protected artifact SHA-256")
    parser.add_argument("--evidence-id", action="append", default=[], help="Completed verification receipt ID; repeat for multiple receipts")
    parser.add_argument("--reason", help="Why this one recovery artifact is no longer needed")
    parser.add_argument("--acknowledge-records-and-backups-deletion", action="store_true")
    parser.add_argument("--rollback-needed", action="store_true")
    args = parser.parse_args()
    toolkit = Toolkit()
    payload = None
    if args.input:
        relative(args.input)
        payload = private_read(toolkit.work, args.input)
    op = args.operation
    if op == "new-run": result = toolkit.new_run(args.mode, args.platform, args.purpose)
    elif op == "read-ledger": result = toolkit.read_ledger(args.run_id)
    elif op == "validate": result = toolkit.validate(args.run_id)
    elif op == "set-ledger": result = toolkit.set_ledger(args.run_id, decode(payload))
    elif op == "set-plan": result = toolkit.set_plan(args.run_id, payload.decode("utf-8"))
    elif op == "write-artifact": result = toolkit.write_artifact(args.run_id, args.path, args.role, payload, args.rollback_needed)
    elif op == "build-report": result = toolkit.build_report(args.run_id)
    elif op == "collect-baseline": result = toolkit.collect_baseline(args.run_id)
    elif op == "release-recovery": result = toolkit.release_recovery(args.run_id, args.path, args.artifact_sha256,
            args.evidence_id, args.owner_quote, args.reason)
    elif op == "plan-cleanup": result = toolkit.plan_cleanup(args.run_id, args.scope)
    elif op == "approve-cleanup": result = toolkit.record_cleanup_approval(args.plan_id, args.plan_sha256, args.owner_quote, args.acknowledge_records_and_backups_deletion)
    elif op == "apply-cleanup": result = toolkit.apply_cleanup(args.plan_id, args.plan_sha256, args.approval_id)
    else: result = toolkit.export_toolkit()
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (Refusal, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print("Stopped: " + str(error) + ". Preserve evidence; no automatic retry.", file=sys.stderr)
        sys.exit(2)
