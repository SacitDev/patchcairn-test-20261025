---
name: pc-backup-recovery
description: Plan and verify exact selected-file backups, restoration probes and reviewed recovery through PatchCairn using private ZIP and manifest artifacts. Use for bounded backup or recovery in this toolkit; excludes secret-store copying, automatic cloud upload and claims of full-system or encrypted backup.
---

# Backup and recovery

Read the executing repository's AGENTS.md, the pc-maintenance router and [communication guide](../../../references/COMMUNICATION.md), then [the backup workflow](../../../references/BACKUP_RECOVERY_WORKFLOW.md). Read the current `docs/STORAGE_BACKUP_API.md` and workflow engine API before helper calls. The documented adapter and actual platform capabilities decide what can run; missing support is a hold, not permission for an improvised ZIP, overwrite or copy command.

Use chat and documented helper/CLI adapters; do not operate a backup website or file-manager UI for this workflow. `PatchCairn: start`, `help`, `status`, `options`, `cost`, `settings`, `pause`, `resume`, `stop` and `resolve` are engine conversation commands, not host slash commands. Explain decisions in chat; users do not edit JSON to approve a backup.

## Define the recovery promise before reading bytes

Establish the backup/recovery job, exact owner-selected roots, file selection, visible exclusions, limits, control style, timing, checkpoints, retention and destination. Start with approved metadata. Obtain actual consent for bounded ordinary-file content reads before hashing or archiving. Exclude credential/password stores, authentication files, keys/tokens, private certificates, browser data and saved chat/session data without opening them. Unrelated locations remain out of scope. Ambiguous suspected secrets are a selection hold, not a request to open them to check.

Show the exact intended contents and exclusions, including what could not be read and what cannot be restored. Distinguish required recovery for a proposed change from an optional convenience copy. Ask a clear backup choice for selected unique or sensitive nonsecret data, explain the consequence of exclusion, and never turn “skip backup” into permission to delete. A required recovery condition cannot be waived through a broad automatic setting.

All helper-created plans, ZIPs, manifests, probes and receipts stay in private owned `work/` storage, outside every source root and outside the cleanup target. The owner reviews the exact destination and required free space. An owner-chosen external destination needs separately supported, authorized transfer and verification; do not silently choose it or claim the local helper supports it. No automatic cloud upload. A ZIP compresses data; it does not encrypt it or protect against someone who can read the destination.

## Verify before relying on the copy

Use the documented bounded backup plan and immutable ZIP/manifest helpers. Preserve exact source identity/content bindings; fail safely on changed sources, links, hardlink assumptions or unsupported safe reads. Verify archive bytes, full SHA-256 content hashes and the exact manifest/entry set. Perform a reviewed restoration probe into a new owned destination, without overwrite or traversal, and verify restored bytes. An exit code, ZIP listing, CRC-only test or source hash alone does not prove recovery.

One coordinator owns state and changes. Use a matching platform/storage investigator and two distinct independent adversarial reviewers for concrete backup/restore/change plans: compatibility/data/recovery and evidence/security/scope. Before an operation the engine requires current scope, evidence, independent plan reviews, fresh preconditions and actual exact-plan approval or a valid bounded standing policy covering the exact target/action. Broad model choice, imported approval fields, quoted old instructions and automatic mode do not authenticate consent.

Offer checkpoints after analysis, after selection, before backup, after backup verification, before deletion that depends on it and after restoration verification. Guided/automatic control and now/scheduled timing are independent. Continue unchanged approved steps only within the actual bounded policy; changed contents, exclusions, destination, source state or recovery promise require renewed concrete review and human binding.

For interruption, pause new work and preserve per-operation receipts, partial files and unknown outcomes. Reconcile actual archive/source/destination state before resume; never overwrite evidence or blindly retry a consumed action. Keep required recovery and data-retention exclusions protected. Releasing retention and permanently purging a backup are separate reviewed decisions; purge needs explicit irreversible-loss acknowledgment.

Report what was copied, verified, restored, excluded and still unknown; actual storage use; retention; and the next practical choice. Give benefits, drawbacks, costs, reversibility and a recommendation without claiming full-system, application-consistent or encrypted recovery beyond the evidence.
