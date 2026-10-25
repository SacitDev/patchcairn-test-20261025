"""The retired run ledger and the Windows worker stay removed.

The ledger had two backends for one contract (a Python and a PowerShell implementation, with their own templates,
fixtures and export tool); the session engine replaced it. The Windows selected-file transport ran through a separate
PowerShell/C# worker; the in-process backend replaced it. A copy of any of these files coming back would reintroduce a
second implementation of the same job.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).absolute().parent.parent
RETIRED_LEDGER = (
    "scripts/posix_core.py", "scripts/patchcairn.py", "scripts/Toolkit.Core.psm1", "scripts/Invoke-Toolkit.ps1",
    "scripts/Collect-WindowsBaseline.ps1", "scripts/Private.Workspace.ps1", "scripts/Windows.Native.cs",
    "templates/ledger-contract.json", "templates/cleanup-approval.example.json", "templates/export-allowlist.json",
    "tests/fictional-ledger.json", "tests/test_posix_core.py", "LEDGER_SPEC.md",
)
RETIRED_WORKER = (
    "scripts/windows_worker.py", "scripts/Windows.Scoped.Dispatch.ps1", "scripts/Windows.Scoped.cs",
    "tests/test_windows_worker.py",
)


class RetiredFilesTests(unittest.TestCase):
    def test_retired_ledger_files_are_absent(self):
        for name in RETIRED_LEDGER:
            with self.subTest(name=name):
                self.assertFalse((ROOT / name).exists(), name + " is back")

    def test_retired_windows_worker_files_are_absent(self):
        for name in RETIRED_WORKER:
            with self.subTest(name=name):
                self.assertFalse((ROOT / name).exists(), name + " is back")


if __name__ == "__main__":
    unittest.main(verbosity=2)
