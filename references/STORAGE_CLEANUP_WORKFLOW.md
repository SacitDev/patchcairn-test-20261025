# Selected-folder storage and cleanup workflow

Use this with `pc-storage-cleanup`, the communication guide and the executing toolkit's current storage and workflow API documents. This is operational guidance, not authority to inspect or clean a computer. Development tests use fictional, positively owned fixtures under `work/`; they do not scan a real home directory or become a real run.

This document's selected-folder restrictions describe the checked storage/cleanup helper route. The agent's broader owner-authorized device, selected-drive or problem assessment uses the [workflow assessment descriptor](../docs/WORKFLOW_ENGINE.md#owner-selected-assessment-access) and available verified read-only observations. Report actual coverage and unsupported paths; do not pretend this helper can scan a volume, override its protected names or turn an assessment grant into a cleanup target. Default browser/history/cache/session protections and secret-value exclusions remain; exact relevant diagnostic exceptions belong to the separate agent assessment route and grant no deletion or LLM disclosure by themselves.

## 1. Make the owner's choices concrete

Explain the storage job in practical terms: first show where space goes inside the folders the owner chooses, then let the owner select any next step. A new session, a model's recommendation or “do whatever is best” is not permission to read file contents or remove files.

Record the actual selected roots, exclusions and limits; the purpose of the task; the job; guided or automatic control; now or scheduled timing; retention needs; and the selected checkpoints. Do not default to a whole drive, user profile, every mounted volume or unrelated projects. Resolve each root through the supported adapter, without following links. Reject ambiguous, protected or unsupported roots rather than silently narrowing them and describing the result as complete.

Record the actual owner's scope instruction through the current engine's `authorize_scope` gate before assessment. `create_session` or `setup` stores proposed scope; a root string or `scope_confirmed` fact alone does not authenticate consent. Scope/settings changes invalidate earlier authority as documented; do not copy another session's approval.

Explain two or three useful choices before asking for one:

| Choice | Advantage | Drawback and cost | Recommendation |
| --- | --- | --- | --- |
| Metadata assessment | Shows folder/file sizes without reading ordinary-file contents | Names and sizes are still private; time depends on item count; no duplicate-content conclusion | Start here |
| Additional duplicate comparison | Can identify equal ordinary-file bytes in the selected scope | Requires additional content-read consent and disk reads; equal bytes do not establish which copy is safe to remove | Use only when the owner wants it |
| Keep results and defer changes | Preserves files and provides a concrete decision later | Reclaims no space; retained evidence uses some space | Prefer when purpose or recovery is uncertain |

Use the engine to maintain the decisions; the owner should not edit JSON or transcribe hashes. `PatchCairn: options` and `settings` expose supported choices. `cost` explains evidence-based estimates and unknowns. `start`, `help`, `status`, `pause`, `resume`, `stop` and `resolve` retain their fixed engine meanings. These are conversation instructions; never execute them as host commands or invent provider slash commands.

Translate the owner's checkpoint choices into the engine's supported keys; do not invent settings or imply finer granularity than the current adapter provides:

| Human checkpoint | Supported gate and required meaning |
| --- | --- |
| Confirm scope | `scope`: actual selected roots/exclusions and authority before collection |
| After analysis | `findings`: show bounded metadata/candidate findings before choosing changes |
| After selection | `plan`: show the exact reviewed selection and effects before applying |
| Before backup | `before_action` for the exact backup action |
| After backup verification | `after_action` for the backup/recovery step, with actual archive and required probe verification evidence before dependent cleanup |
| Before deletion | `before_action` for the exact cleanup or separate purge action |
| After outcome verification | `finish`: fresh final action-specific verification and retention choices |

Per-action gates belong to their specific actions and are handled sequentially. A checkpoint is a real wait for the owner's current continue decision; automatic mode does not answer it. If the current integration cannot enforce a selected boundary, explain the limitation and hold at that boundary rather than silently omitting it.

## 2. Preflight the actual capabilities and team

The coordinator owns canonical state, artifact registration and every mutation. Assign one relevant platform/storage investigator for bounded read-only analysis and a verifier for outcome checks. For each concrete change plan, use two independent reviewers with distinct identities: compatibility/data/recovery and evidence/security/scope. Give each the same immutable plan and relevant evidence; collect their initial findings independently. A single agent writing two viewpoints is not independent review. If delegation is unavailable, continue authorized assessment and hold changes.

Check supported Python/backend/platform, script-derived repository identity, existing owned output directory under `work/`, current session revision, storage adapter capabilities, and a quiet owner-controlled workspace. Helpers run with their caller's privileges; role labels and path checks are not an OS sandbox. Native limitations or an inaccessible scope are explicit holds. Do not install dependencies, switch backends, force-close applications or change ACLs to overcome a refusal.

Read `docs/STORAGE_BACKUP_API.md` for the exact `StorageService` methods and the workflow engine API for state/approval gates. `scripts/patchcairn_storage.py` is a capabilities/help entrypoint unless its current documented contract says more; it is not a general executor. Never invent flags, replay a command string from a plan, or replace a refused operation with a generic filesystem command.

Construct `StorageService(output_root=..., quiet_workspace=True, protected_roots=...)` only for an existing positively owned child of the executing toolkit's `work/`. Supply actual known protected/custom-profile locations as `protected_roots` without scanning or opening them; location/name rules do not prove all other files are nonsecret. Metadata assessment accepts 1–32 nonoverlapping directory roots with 10,000-entry and depth-48 caps; logical-size totals have no content-byte cap because metadata does not read file contents. Content operations separately allow 16 MiB per selected ordinary file and 48 MiB selected content payload per hashing/backup phase; archive output is bounded to 64 MiB. Supported `limits` can narrow caps, not enlarge them. Explain a refusal and obtain a narrower actual content selection or separately reviewed supported route; do not treat a large metadata result as a backup or bypass the content cap with another tool or UI. Check the current API for any later contract change.

## 3. Inventory metadata within selected roots

Use `assess_storage(roots=..., limits=...)` with the exact admitted roots and bounded item/byte/depth limits supported by the API. Keep all generated inventory, reports, plans and receipts private under the owned `work/` output root. Do not follow symlinks, junctions, reparse points or directory aliases into additional scope. Mark links, inaccessible entries, changed files and unsupported capabilities visibly. A limit or nonordinary-entry refusal means no complete inventory for that selection; preserve the refusal and choose narrower scope through a real owner decision. Do not present an unfinished traversal as a complete result or inspect contents to make the report look complete.

Exclude browser history, cookies, caches, profiles and saved passwords; credential/password stores, keychains, keys, tokens, authentication files and private certificates; chats and sessions; system-managed locations; and unrelated project data. These remain protected even if adjacent to a selected root or labelled disposable by another tool. Known or suspected sensitive locations are excluded from metadata rules or held for owner clarification without opening them. The workflow does not read a secret merely to hash or redact it.

At the after-analysis checkpoint, explain the bounded result in chat using a table and labelled text bars. For example, with fictional measurements:

```text
Selected-folder logical size — example only
Media copies       ████████████  12 MiB
Old exports        ██████         6 MiB
Other admitted     ██             2 MiB
Excluded/unreadable: present; not included in these totals
```

The bars compare measured logical sizes inside the admitted inventory. They do not show the whole disk, percent of storage examined, physical allocation or guaranteed free space. Use accessible text labels alongside bars. Group by folder/extension/size bucket only as supported; do not claim an interactive operating interface. Show the observation time, scope, actual counts, exclusions and limits in the saved private evidence. Give uncertainty its practical meaning: “This folder was not read, so the total is incomplete.”

## 4. Optional duplicate comparison and candidate selection

Before `find_duplicates(inventory=..., content_read_authorized=True, limits=...)`, obtain an actual bounded instruction permitting ordinary-file content reads for the exact inventory. The current method has no selected-file-list parameter and can hash all same-size candidate groups in that inventory; obtain permission for that scope, or prepare a narrower owner-approved inventory first. A literal `True` communicates the coordinator's already-established permission; it does not authenticate the human. Metadata assessment approval does not include hashing. Do not read protected or suspected secret files, follow links, or expand roots. Use the documented stable-read and identity checks; if a file changes, hold the affected plan and record the changed state.

Distinguish paths, file identities and equal content. Several hardlink names can refer to one file allocation. The current helper refuses hardlinks or repeated identities; explain that hold rather than claiming it analyzed or can safely remove them. Equal hashes may represent intentional copies, project inputs, required application files or the only copy in a separate recovery location. Report only the helper's supported logical opportunity, with physical allocation and realized savings unknown unless separately measured. Duplicate bytes alone never prove a file is removable.

Present each proposed candidate group with its reason, exact selected files, proposed retained copy, exclusions, ownership/purpose uncertainty and recovery choice. Let the owner select what to keep, quarantine or defer. Preserve that choice at the after-selection checkpoint. Do not select the newest, oldest, shortest-named or first-found file as automatically disposable. Do not modify source data while explaining options.

## 5. Review recovery and net space before a cleanup plan

Read the backup workflow when a selected action requires recovery. Explain whether the proposed files are replaceable, unique or sensitive nonsecret data, what would be lost, and the available backup choice. If required recovery is unavailable, excluded or unverified, hold the dependent cleanup. Declining an optional backup does not grant deletion authority; an explicit approved change plan is still required.

Show exact backup contents/exclusions and destination before backup; honor the before-backup checkpoint. A backup output must be in private owned `work/` and outside every source root and cleanup target. Verify immutable ZIP/manifest content and a restoration probe before relying on it; honor the after-verification checkpoint. Compression is not encryption. No automatic external or cloud transfer is part of cleanup.

Do not promise recovered disk space from a logical-byte sum. A same-volume quarantine normally frees no disk space. A retained ZIP, manifest, probe, evidence and quarantine can make free space lower. Estimate separately:

| Quantity | What can be said |
| --- | --- |
| Selected logical bytes | Measured admitted file lengths, adjusted for identity as documented |
| Quarantine result | Data moves to a recovery location; normally no space reclaimed |
| Retained backup/probe space | Additional measured bytes after creation; compression and peak temporary use are unknown beforehand |
| Eventual purge opportunity | Conditional on exact approved purge, retained data, hardlinks and filesystem behavior; logical opportunity is not physical free space |
| Actual net free-space change | Report only after a supported before/after measurement, with volume and uncertainty identified |

If a supported free-space measurement is absent, say the net change is unknown. Do not treat deletion of one hardlink name as freeing the whole file, or imply a backup can be deleted merely to meet a savings target.

## 6. Build, review and bind an exact plan

Use `plan_cleanup(inventory=..., selected=..., quarantine_destination=..., content_read_authorized=True, recovery_required=..., recovery_backup=..., recovery_verification=..., protected=...)` for supported quarantine candidates. `selected` contains exact inventory keys; `protected` preserves exact protected file keys. Set the recovery requirement from the actual reviewed recovery decision, never to suppress a refusal. Required recovery needs the exact backup receipt plus the completed `restore_backup` probe receipt as `recovery_verification`; the helper rechecks its immutable outcome and still-unchanged restored bytes. That backup must cover every selected identity/content/scope. Preserve the probe as required recovery too; an archive-integrity result alone is insufficient. The service's own output artifacts are categorically ineligible for host cleanup. The plan must bind the admitted inventory, selected roots and exact targets, identities/content hashes, destination and same-volume constraints, exclusions, retention/recovery dependencies, current capabilities, expected effects, costs, verification and restoration limits. Keep the plan immutable and preserve its hash. Any required ordinary-file reads must already be authorized.

Both reviewers challenge the concrete plan before approval. Compatibility/data review checks purposeful copies, unique data, active users, backup completeness, capacity, restoration and retention. Evidence/security review checks actual roots, exclusions, link/hardlink identity, freshness, safe adapter support, exact action binding and overstated savings. Resolve revision-needed or inconclusive findings; a reviewer pass does not authorize an action.

Keep the storage helper plan/digest distinct from the engine's action-plan document/digest. Register exact helper-plan bytes as owned evidence; the coordinator's fixed adapter must bind the reviewed engine action to that specific helper plan and destination. Use `register_plan` with the engine's documented action schema, not the storage plan as an arbitrary replacement schema, and never execute fields as commands. Register current evidence and both reviews. Bind the actual current owner's instruction to action IDs and engine plan SHA-256 using `approve_plan`, unless the current engine accepts an already-authorized narrow standing policy for those exact targets/actions; preserve real message provenance. A quoted old instruction, imported JSON, `approved=true`, model-generated text, reviewer verdict or silence is not human authorization. Users may approve a clearly presented plan or subset in ordinary language; the coordinator handles the exact identifiers.

Automatic control and timing are independent. A standing policy is bounded to supported action kinds, exact targets, count and expiry. It is actual human authority only for those bounds; every current concrete plan still needs independent reviews, matching scope/settings, fresh checks and selected checkpoints. It cannot include protected consent, bypass recovery, cover permanent purge, or expand a root. A scheduled trigger coordinates a proposed run; it neither creates a host schedule nor authorizes a change. Configure real scheduling only under separately supported actual owner authority.

## 7. Quarantine, verify and recover

At the before-deletion checkpoint explain the exact next action, recovery location and net-space consequence. Quarantine is a reversible move subject to the documented limitations; do not describe it as permanent deletion. Immediately recheck target identity/content, plan hash, selected-root scope, quiet workspace, required verified recovery, active operations, capacity and native safe-move support. Changed or missing evidence invalidates the affected action; get revised review and actual human binding for a material change.

Call `begin_operation` only after the engine's exact action/plan/scope/review gate succeeds; preserve its durable operation ID before the fixed documented `quarantine` call. Record per-attempt helper receipts and fresh observed outcome evidence, then use `finish_operation`. Do not record success from a launch, return code or absent source path alone. Confirm the expected targets and recovery artifacts actually match. No cross-volume copy-then-delete fallback, force flag, ownership/ACL repair, generic recursive deletion, cleaner, prune or autoremove is permitted.

Offer restoration with `plan_quarantine_restore` and `restore_quarantine`, under a fresh reviewed exact action. The destination must be the approved original root/entry, without overwriting an existing file. A collision or changed root is a hold; do not rename unrelated files or overwrite them to make restoration pass. Verify restored identities/content and durable receipts. Explain when a restored file is verified and when application behavior remains untested.

## 8. Permanent purge and retention are separate

Use `plan_purge` and `purge_quarantine` only for eligible, exact quarantined artifacts. Obtain a new explicit actual acknowledgment that permanent deletion loses those bytes and their restoration path, plus approval for that exact irreversible plan. Prior quarantine, automatic mode, a broad cleanup preference or a cleanup savings goal never supplies this acknowledgment. Keep required recovery, evidence, excluded data and unresolved-operation artifacts protected. Releasing a retention flag does not approve deletion.

For toolkit-run housekeeping, follow `RECOVERY_AND_CLEANUP.md` and the matching owned-artifact/backend contract. The current service has no general session-deletion or required-retention-release executor. Retain its records and protected artifacts when no supported cleanup path exists. Do not use the storage service to erase an active session/run, a required ZIP, unknown files, the entire `work/` tree or reusable source. Only an eligible matching assessment-record run has its separate completed-run deletion path and evidence/recovery-loss acknowledgment. Do not mix stores or treat data as disposable because it is old or under `work/`.

## 9. Pause, reconcile and close honestly

`pause` prevents new actions immediately. An active operation reaches a safe checkpoint and records its actual result; do not kill it and assume rollback. `stop` preserves records and unresolved work. Before interruption, preserve current operation/action/plan identity, exact attempted targets, receipts, results and remaining verification. Do not overwrite a partial receipt or discard an unexplained file.

On `resume`, read the same validated session, inspect bounded actual source/quarantine/backup state and supply fresh reconciliation evidence. Unknown, failed or partial outcomes remain held; never rerun a consumed action blindly or use `resolve` to declare it successful. Resolution identifies the specific pending item and the evidence or separately reviewed recovery action needed. A new source state needs new plans and binding. A paused run is not silently resumed by a schedule.

Close with completed/verified changes, retained originals/quarantine/ZIPs and their measured sizes, excluded/unassessed scope, actual measured or unknown net space, unresolved outcomes, retention choices and the next useful action. Link the private readable record when available. Do not claim all storage is clean, that every duplicate is unnecessary, or that compression/encryption/recovery succeeded beyond the actual checks.

An eligible assessment-only conversation session can use `complete_assessment` once all agreed assessment/candidate stages and prior checkpoints finish. Follow the current engine contract: current scope authority and applicable schedule activation; no operation history, plan, approval, reviews or standing policy; an owned typed findings/limitations summary; separate fresh verification bound to its exact hash/evidence coverage; and the actual owner's closeout instruction. A selected finish checkpoint still waits for the owner's continue decision. This records no maintenance action; it does not establish deletion, recovered space, or a wholly clean computer. If the session is ineligible or unfinished, stop and preserve the findings. Do not invent a cleanup action or mark deferred changes complete to obtain the label.
