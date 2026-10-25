#!/usr/bin/env python3
"""Human-first, fixed-command PatchCairn workflow interface; no OS executor."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
# Isolated Python omits this directory; admit only the trusted sibling location.
sys.path.insert(0, str(Path(__file__).absolute().parent))
from workflow_core import JOBS, SCHEMA_VERSION, WorkflowEngine, WorkflowRefusal, PrivacyCapabilityHold, initial_menu, older_format_message, parse_command


def creation_platform(mode, requested):
    """Resolve immutable real-session platform without collecting host metadata."""
    if mode != "real":
        return requested or "unknown"
    detected = "windows" if sys.platform == "win32" else "macos" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "unknown"
    if detected == "unknown":
        raise WorkflowRefusal("This native platform is unsupported for a real session; no private session storage was allocated")
    if requested is not None and requested != detected:
        raise WorkflowRefusal("A real session must use this computer's actual native platform; no private session storage was allocated")
    return detected


def human_message(result, *, storage_unavailable=False):
    if result["ok"] or result["code"] != "held":
        return result["message"]
    lead = "I cannot confirm that this workspace can protect private session records. Ask the coordinator about supported private storage. " if storage_unavailable else "I could not continue this request because a required check needs attention. "
    return (lead +
            "Keep the existing evidence and ask the coordinator to explain the failed check. "
            "If earlier work was already running, its actual outcome still needs to be checked; this refusal does not tell us whether it finished or what effects it had. "
            "Next: use PatchCairn: status to review the selected session, then PatchCairn: options or PatchCairn: resolve for the next decision. "
            "If no session has been selected, PatchCairn: help shows the available jobs. Do not retry an uncertain action.")


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="PatchCairn — Developed by Michael. Start shows the job menu; choosing a job does not authorize computer changes.")
    parser.add_argument("command", nargs="*", help="PatchCairn: help, start, status, options, cost, settings, pause, resume, stop or resolve")
    parser.add_argument("--session", help="Existing session identifier; paths are refused")
    parser.add_argument("--job", choices=list(JOBS), help="Explicit job selection; bare start only displays the menu")
    parser.add_argument("--control", choices=["guided", "automatic"], default="guided")
    parser.add_argument("--timing", choices=["now", "scheduled"], default="now")
    parser.add_argument("--mode", choices=["fixture", "real"], default="fixture")
    parser.add_argument("--platform", choices=["unknown", "windows", "linux", "macos"], help="Real session defaults to the detected native platform; fixtures default to unknown")
    parser.add_argument("--scope", action="append", default=[], help="Exact selected scope label; repeat for each root. This is not collection authority.")
    parser.add_argument("--checkpoint", choices=["scope", "findings", "plan", "before_action", "after_action", "finish"], action="append")
    parser.add_argument("--expected-revision", type=int)
    parser.add_argument("--json", action="store_true", help="Structured response for internal callers; human text is the default")
    args = parser.parse_args(argv)
    command = " ".join(args.command) if args.command else "PatchCairn: help"
    storage_unavailable = False
    try:
        parsed = parse_command(command)
        if not parsed["ok"]:
            result = {"schema_version": SCHEMA_VERSION, "ok": False, "code": parsed["code"], "message": parsed["message"], "session_id": args.session, "revision": None, "data": {}}
        elif not args.session and (parsed["command"] == "help" or parsed["command"] == "start" and not (parsed["arguments"] or args.job)):
            # Help needs neither a storage directory nor a registered session.
            result = {"schema_version": SCHEMA_VERSION, "ok": True, "code": "help", "message": initial_menu(), "session_id": None, "revision": None, "data": {}}
        else:
            selected_platform = creation_platform(args.mode, args.platform) if parsed["command"] == "start" and not args.session else args.platform
            engine = WorkflowEngine()
            if parsed["command"] == "start" and not args.session:
                job = parsed["arguments"][0] if parsed["arguments"] else args.job
                result = engine.create_session(job=job, control=args.control, timing=args.timing, mode=args.mode, platform=selected_platform, scope={"roots": args.scope, "purpose": "Selected " + JOBS[job]["label"].lower() + " scope; collection needs current-owner authorization"}, checkpoints=args.checkpoint)
            else:
                result = engine.dispatch(args.session, command, expected_revision=args.expected_revision)
    except (WorkflowRefusal, OSError, ValueError, TypeError, KeyError) as error:
        storage_unavailable = isinstance(error, PrivacyCapabilityHold)
        if older_format_message(error):
            # Records in an older format are never migrated; the person reads the plain reason and next step.
            result = {"schema_version": SCHEMA_VERSION, "ok": False, "code": "older_format", "message": older_format_message(error), "session_id": args.session, "revision": None, "data": {}}
        else:
            result = {"schema_version": SCHEMA_VERSION, "ok": False, "code": "held", "message": "Work is held: " + str(error) + ". Preserve evidence and review the specific next step; no automatic retry.", "session_id": args.session, "revision": None, "data": {}}
    if args.json:
        print(json.dumps(result, ensure_ascii=True, allow_nan=False, sort_keys=True))
    else:
        print(human_message(result, storage_unavailable=storage_unavailable))
        if result["session_id"]:
            print("\nSession: " + result["session_id"])
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
