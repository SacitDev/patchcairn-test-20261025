"""Bounded selected-root storage, verified recovery and quarantine primitives.

This is a library with its caller's privileges, not an authorization mechanism or
an OS sandbox. The trusted coordinator must pass the workflow engine's exact
action/plan/scope/review gate before calling mutation methods. No quote, JSON
field or digest in this module authenticates current human consent. A quiet,
exclusively controlled workspace is a required operational assumption.
"""
from __future__ import annotations

from scoped_fs import ScopedFSError, capabilities
from storage_assess import StorageAssessment, render_storage
from storage_backup import StorageBackup
from storage_cleanup import StorageCleanup
from storage_policy import StoragePolicy, StorageRefusal, attempt_record, canonical, plan_sha256, storage_value
from storage_restore import StorageRestore, restorable
from storage_verify import StorageVerification

# The public storage API; product callers import it from this facade, not from the family modules.
__all__ = ["ScopedFSError", "StorageRefusal", "StorageService", "attempt_record", "canonical", "plan_sha256",
           "render_storage", "restorable", "storage_capabilities"]


# One mixin per family module. StorageService defines no method of its own: every call reaches the family code
# through method resolution, so callers and tests see one whole class.
class StorageService(StoragePolicy, StorageAssessment, StorageBackup, StorageVerification, StorageRestore, StorageCleanup):
    """Pure plans plus checked native primitives, with no standalone consent API.

    `output_root` must be an existing, positively owned and owner-private
    directory below this executing repository's work/. The coordinator creates
    its dedicated private namespace; existing permissions are never repaired.
    No external output destination or broad filesystem discovery is supported.
    """


def storage_capabilities():
    return {**storage_value("capabilities"), "filesystem": capabilities(), "cli_mutation_enabled": False,
            "requires_workflow_engine_gate": True, "quiet_exclusive_workspace_required": True,
            "not_an_os_sandbox": True, "zip_encryption": False}
