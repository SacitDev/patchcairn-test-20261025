"""Read-only storage entry point; real operations use the gated coordinator."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    # Before anything else is imported or written: an interpreter that may load other code is refused.
    print("Storage hold (interpreter-not-isolated): start this tool with python -I -S -B so no other code is loaded "
          "into it; nothing was read or written.", file=sys.stderr)
    raise SystemExit(2)

# Explicit sibling import supports isolated -I -S -B without ambient PYTHONPATH.
sys.path.insert(0, str(Path(__file__).absolute().parent))
from storage_ops import ScopedFSError, StorageRefusal, StorageService, render_storage, storage_capabilities


def main(argv=None):
    parser = argparse.ArgumentParser(description="PatchCairn selected storage metadata and native capability checks. No cleanup or backup mutation command is exposed.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    capability_parser = subparsers.add_parser("capabilities", help="Show supported checked filesystem capabilities")
    capability_parser.add_argument("--json", action="store_true", help="Internal structured result")
    assess = subparsers.add_parser("assess", help="Metadata only for explicitly selected ordinary roots")
    assess.add_argument("--root", action="append", required=True, help="Exact authorized source root; repeat for each selected root")
    assess.add_argument("--owned-output-root", required=True, help="Existing owner-private work child; broad existing permissions cause a hold, without repair")
    assess.add_argument("--quiet-workspace", action="store_true", required=True, help="Confirm the scope is quiet and exclusively controlled")
    args = parser.parse_args(argv)
    try:
        if args.command == "capabilities":
            result = storage_capabilities()
            if args.json:
                print(json.dumps(result, ensure_ascii=True, sort_keys=True))
            else:
                print("PatchCairn storage capabilities\n")
                print("Checked filesystem: " + json.dumps(result["filesystem"], ensure_ascii=True, sort_keys=True))
                print("Actual backup, restore and cleanup require the coordinator's exact reviewed workflow gate.")
                print("ZIP compression provides no encryption. A quiet, exclusively controlled workspace is required.")
            return 0
        service = StorageService(output_root=args.owned_output_root, quiet_workspace=args.quiet_workspace)
        print(render_storage(service.assess_storage(roots=args.root)))
        return 0
    except (StorageRefusal, ScopedFSError, OSError) as exc:
        # No traceback, environment dump or private payload on a routine hold.
        code = getattr(exc, "code", type(exc).__name__)
        detail = str(exc) if isinstance(exc, StorageRefusal) else "The selected scope or safe native capability could not be verified"
        print(f"Storage hold ({code}): {detail}. Preserve existing artifacts and review a narrower scope or supported private workspace.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
