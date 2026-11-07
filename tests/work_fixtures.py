"""Fixture folders of the tests below work/: the one remover a test registers with addCleanup right after it creates its
folder, and the POSIX probe for new private folders. Standard library and scripts/ only (callers put scripts/ on sys.path).

Nothing here ignores an error: a fixture folder that cannot be removed fails the test's cleanup, so work/ cannot grow
unnoticed.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import uuid

from private_workspace import PrivateWorkspaceError, ensure_private_directory

ROOT = Path(__file__).absolute().parent.parent
# The refusals with which a POSIX computer says it cannot give a new folder owner-only access: a missing capability that
# skips a test with its reason, never a failure of the code under test.
PRIVATE_CAPABILITY_HOLDS = frozenset({
    "private-owner-or-mode-refused", "private-darwin-acl-capability-unavailable", "private-platform-unavailable",
    "private-linux-foreign-filesystem", "private-linux-abi-unavailable", "private-linux-libc-unavailable", "private-linux-descriptor-unavailable",
})


def _extended(path):
    """The Windows extended form of ``path``, which also reaches names past the classic 260-character limit."""
    text = os.path.abspath(path)
    if text.startswith("\\\\?\\"):
        return text
    return "\\\\?\\UNC\\" + text[2:] if text.startswith("\\\\") else "\\\\?\\" + text


def remove_tree(path):
    """Remove the fixture folder ``path`` and everything in it. A read-only file or folder (Windows) is made writable and
    removed again; a link is never followed to make its target writable. Every other failure, a missing ``path``
    included, is raised."""
    def writable_then_retry(function, name, error):
        if function not in (os.unlink, os.remove, os.rmdir) or os.path.islink(name) or os.path.isjunction(name):
            raise error
        os.chmod(name, stat.S_IWRITE)
        function(name)
    shutil.rmtree(_extended(path) if os.name == "nt" else path, onexc=writable_then_retry)


def private_hold():
    """None when a new owner-only folder can be made below work/ (always on Windows), else the capability code POSIX
    refused it with. A probe only: any other refusal is raised, never turned into a skip; the probe folder is removed."""
    if os.name != "posix":
        return None
    probe = ROOT / "work" / ("private-probe-" + uuid.uuid4().hex)
    try:
        ensure_private_directory(probe, create=True, parents=True)
    except PrivateWorkspaceError as exc:
        if exc.code not in PRIVATE_CAPABILITY_HOLDS:
            raise
        return exc.code
    finally:
        if os.path.lexists(probe):
            remove_tree(probe)
    return None
