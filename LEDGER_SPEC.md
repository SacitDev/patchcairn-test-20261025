# State and evidence contracts

PatchCairn has one public product version, recorded in `toolkit.json`, and one four-job conversation entrypoint. Its internal components use separate session, service, diagnostic, storage and assessment-ledger records. The assessment ledger uses internal contract format 1.0; numeric suffixes in backend/schema identifiers also describe internal formats, not alternate product versions. These records share evidence and consent principles but are not interchangeable databases. The coordinator matches the actual creating component and preserves its lifecycle; it never edits markers, imports approvals as authority or reconstructs an executable action from a JSON record.

| Contract | Canonical record | Machine/API reference |
| --- | --- | --- |
| Current conversation engine | One `session.json` bundle containing validated `state` and chained `events`, plus immutable creation/evidence records | [Session contract](templates/session-contract.json), [workflow definitions](templates/workflows.json), [engine API](docs/WORKFLOW_ENGINE.md) |
| Current fixed-adapter service | Engine operation plus immutable service intent/result/native-origin evidence, storage receipts and protected-retention registry | [Service integration](docs/SERVICE_INTEGRATION.md), [storage API](docs/STORAGE_BACKUP_API.md) |
| Assessment-record and report helpers | One run's `ledger.json`, with `actions.jsonl` audit history and separate ownership bookkeeping | [Assessment ledger contract](templates/ledger-contract.json), [record helper reference](references/HELPER_API.md), assessment-record sections below |

All generated records stay private under the executing toolkit's owned `work/` children. Public source, fixtures and website content contain no real session/ledger data. Human chat and reports explain records; they do not become input authority. Users do not edit JSON to grant permission or fix a hold.

## Conversation identity and canonical state

The engine backend is `patchcairn.workflow.python.v3`. The engine's named work child contains `engine.json`; each bounded session ID identifies its own directory with `creation.json`, `session.json` and immutable `evidence/` bytes. Session IDs are identifiers, never caller-supplied paths. A missing marker/state in registered or nonempty storage, foreign version/backend, changed evidence or inconsistent event chain is a hold; no silent recreation, migration or promotion is supported.

The immutable creation marker binds `session_id`, `engine_id`, `backend`, `mode`, `platform`, `created_utc`, initial `creation_scope_sha256`, `owner_id` and `job`. Fixture and real modes remain distinct. Changing platform, job or backend requires a new correctly scoped session; it cannot make fictional facts or another computer's records authoritative.

| Conversation state group | Meaning and invariant |
| --- | --- |
| Identity, UTC and revisions | Schema/backend/engine/session identity, creation/current UTCZ timestamps, monotonic `revision` and `settings_revision`. |
| Job, stage and status | One supported job and its allowed stage; status is `active`, `awaiting_user`, `held`, `pause_pending`, `paused`, `stopped` or `completed`. A state label alone does not establish a successful operation or verified computer. |
| `settings` and `scope_authorization` | Exact selected scope, independent guided/automatic control and now/scheduled timing, supported checkpoints, and the actual current owner's scope instruction. Session creation/settings do not authorize collection. |
| `evidence` | Immutable owned byte references, exact hashes/sizes, supported kinds, current scope/settings binding, observed/registered UTCZ and bounded typed facts. Facts do not substitute for the evidence bytes or current human authority. |
| `plan`, `reviews`, `approval`, `irreversible_ack` | Exact current engine action plan/hash, two independent role-specific review records, actual selected-action approval and separately typed purge-loss acknowledgment. |
| `standing_policy` | Actual explicitly bounded authority for supported ordinary kinds, exact targets, exact adapter/payload/native-plan/inventory hashes, count, expiry and current scope/settings. Automatic mode alone supplies none of it. |
| `operations` and `pending` | Durable one-use action tickets, actual receipts/outcomes and bounded checkpoint/reconciliation decisions. At most one operation is active. |
| Schedule and lifecycle fields | Proposed timing/trigger IDs, last reconciliation and terminal stop reason. No OS scheduler is created by these records. |

The canonical file contains exactly the state plus its event journal. Each event has revision, UTCZ observation, fixed type, recorded changes, state hash, previous event hash and event hash. A validated candidate state and its next event are replaced together atomically under an exclusive writer-directory lock. The current engine bounds the bundle to 16,000,000 bytes. These are local consistency and coordination controls, not an OS sandbox or a guarantee against a hostile process with equivalent filesystem permissions. A leftover writer lock requires inspection; it is not automatically presumed stale. Use `expected_revision` when coordinating writes; never race another writer or hand-edit the journal.

## Conversation evidence, exact plans and authority

`register_evidence` owns bounded immutable bytes and records an ID, relative `evidence/<id>.bin` path, SHA-256, size, kind, exact scope, settings revision and UTC times. IDs cannot be overwritten. Missing/changed registered bytes, an unregistered file occupying a proposed output name, observed links/reparses, hardlinked evidence, scope mismatch and future observations are holds. The engine does not claim a general scan for every unrelated extra file. A digest proves a byte binding, not factual correctness, publisher identity, independent review or consent. Do not persist secrets, broad personal logs or unapproved file contents.

The engine plan has exactly `plan_id`, `summary`, `evidence_ids` and `actions`. Each action describes benefit, risk, recovery and verification and binds a fixed `adapter_id`, owned adapter payload bytes/hash, lower adapter-plan hash and exact owned target inventory/hash. The complete required field list and adapter schemas are maintained in [the engine API](docs/WORKFLOW_ENGINE.md) and [session contract](templates/session-contract.json). Do not pass a lower storage plan as an engine plan or put a shell command in a payload. A service preparation method registers exact evidence and returns an action specification; it does not approve the action.

Two distinct independent reviewers, separate from the owner, record current exact-plan verdicts for `compatibility_data` and `evidence_security`. The coordinator must ensure actual independence; two IDs or two self-written viewpoints are insufficient. Both approved reviews, fresh relevant evidence, current scope and an actual authorization path are required before the engine issues a ticket. A material settings change invalidates earlier plan, reviews, authority and timing as documented.

The coordinator records the actual current owner's quote and original message ID using `current_owner_chat` or `current_owner_terminal`. Imported approvals, a model's claim, `approved=true`, a broad model-choice request or a stored quotation cannot authenticate consent. Exact-plan approval binds selected action IDs and plan hash. A standing policy is a different narrow actual decision; it still needs matching exact payload/inventory bindings, independent plan reviews, fresh checks, selected checkpoints, count and expiry. It does not cover protected OS consent, restoration or permanent purge outside the current supported kinds.

Permanent purge additionally needs explicit actual acknowledgment of irreversible loss for its exact action IDs, plan hash, current settings revision and scope. Current plan approval requires its documented permanent-loss acknowledgment, and beginning the operation separately requires the `record_irreversible_ack` record. A prior quarantine approval or retention-release decision is insufficient. Typed `permanent_data_loss` evidence is not a generic reusable “delete anything” permission. Keep the actual instruction and provenance without making the owner transcribe technical hashes.

Preconditions bind the action/engine plan, adapter ID, payload hash, native-plan hash and target inventory hash, with actual identity, scope, content, compatibility, provenance and required-recovery checks. Outcome evidence binds operation/action/plan and the observed outcome. The current engine requires preconditions, outcomes and reconciliation within 15 minutes and after the relevant plan/operation/hold; other evidence has its documented 24-hour limit. A timestamp or Boolean cannot make stale or unobserved data current.

## Operation truth, pause, terminal stop and reconciliation

`begin_operation` durably consumes the exact action ID before the fixed supported adapter can act. The service records an immutable exact intent and the lower native origin/attempt/mapping/outcome evidence. It does not evaluate a stored command or choose a method from free text. A reviewed external-tool handoff leaves the engine operation active until the trusted coordinator supplies the real bounded outcome. Issuing a handoff or receiving exit code zero alone does not establish success.

| Outcome/lifecycle | Record meaning |
| --- | --- |
| Outcome absent | This ticket is active and consumed. Effects may already have occurred; an absent final receipt is not proof of no change. |
| `succeeded` | The exact operation's observed postcondition is evidenced. Fresh original behavior/security verification remains separate. |
| `failed` or `partial` | Preserve the historical result. Further changes stay held until supported evidence-backed resolution and, if needed, a distinct new reviewed plan. |
| `unknown` | Preserve possible partial effects and the consumed ticket. Only fresh actual outcome evidence can establish a later observed result through the supported reconciliation path. |
| `pause_pending` / `paused` | New actions are blocked immediately; already-active work reaches a safe receipt. Resume requires fresh scope/plan/outcome reconciliation. |
| `stopped` | Terminal session. New plans, changes and resume are refused. The eventual exact receipt of an already-active operation or bounded actual-outcome reconciliation of an existing unresolved unknown/failed/partial operation can still be recorded. Scope/approval bindings are preserved and the session remains stopped. |

Never reuse an action ID, repeat a native plan because its result is absent, relabel a failure as success or reconstruct a missing operation intent. Service inspection/reconciliation checks actual receipts and resulting bytes; missing or inconsistent native evidence remains unknown. For nonstopped work, a failed/partial replacement decision records fresh actual effects, no ongoing effects and retained recovery, preserves the original failure, clears stale plan authority and needs new action IDs/reviews/approval. It does not authorize a retry from an old ledger. A stopped session can resolve an unknown to its actual observed result or record `effects_accounted` for failed/partial work using fresh exact-operation evidence of actual effects, no active effects and retained recovery plus the owner's `keep_stopped` instruction. This preserves historical failed/partial outcomes, scope/approval bindings and stopped status; it cannot reopen the session, replace the plan, resume, retry or grant new authority. Unestablished consumed outcomes remain unresolved and visible.

`resume` applies only to paused/held work after every active/unknown/unresolved failed or partial operation is addressed. It needs a fresh exact current-scope/no-change observation and the actual outcomes of all operations, bound to the current plan. Selected checkpoints require the owner's actual continue instruction. `resolve` can inspect a named pending decision or record its supported bounded resolution; it cannot invent success or retry. A scheduled trigger never duplicates an active operation, bypasses a hold or silently resumes stopped/paused work. See [recovery and cleanup](RECOVERY_AND_CLEANUP.md) for the operational procedure.

An unfinished MSI3010 operation additionally retains its original receipt, before-boot evidence and exact action/plan/scope bindings. The owner's separate defer/authorize decision covers only its exact owner-handled restart and timing; it can be recorded after stop solely as retained-effect accounting while stopped status and the consumed action remain. Actual authorized later boot, selected target and ordered original-behavior observations precede final accounting. All required target/check results must pass for success; failed or unknown behavior supports only failed/partial results, never fabricated passed evidence. Original code3010 is preserved. Replanning after failed/partial effects still needs fresh actual-effects/no-active-work/retained-recovery evidence and an actual owner decision; no installer retry, new stopped-session ticket or automatic restart is created.

## Recovery evidence and retention are independent of completion

Required recovery binds actual source coverage and usable restored bytes. Its typed binding names an exact owned output root, actual storage backup receipt, actual completed restore receipt and owned retention evidence. The engine reopens the archive/manifest and their hashes/native identities, the immutable restoration outcome, every mapped restored probe file, and both plan bindings. `restore_verified=true` or `protected=true` alone cannot pass this gate.

Typed required-retention evidence identifies the owning session and each exact archive, manifest, restoration outcome and restored probe path with its actual hash. The service also maintains its own immutable retention entries and protected-root registry, including protective reservations made before a required backup/probe effect. An interrupted or stopped operation can leave required/unknown artifacts protected. The registry's existence is not deletion authority, and releasing an assessment-record flag does not release fixed-adapter service retention.

The built-in ZIP helper is bounded selected-file-content recovery: 16 MiB per content-read file, 48 MiB selected content total and 64 MiB archive. Metadata assessment still has entry/depth bounds but no logical-byte content cap; a multi-gigabyte metadata inventory does not establish that its contents can be backed up by this route. ZIP compression is not encryption, external/cloud output is unsupported here, and ACL/ownership/extended-attribute/application/system-image recovery is not promised. Larger recovery needs a separately reviewed supported route; no generic large-backup executor is implied.

Do not delete live records, unknown/partial outputs, required ZIPs/manifests/probes, current service evidence or protected/excluded locations. The current service has no general session-delete or required-retention-release API. Its storage purge is only for exact eligible quarantine files and needs a new explicit irreversible-loss decision. Missing support is a hold, never permission to use an assessment-record helper, generic recursive deletion, ACL repair or another backend.

## Assessment ledger fields (internal format 1.0)

The remaining fields describe the assessment-record and reporting component only. Windows PowerShell and portable POSIX Python helpers share this ledger schema while retaining their separate native markers and filesystem guarantees. JSON reports/ledgers, other host adapters and conversation sessions do not acquire each other's schema or authority. No cross-backend state mixing or automatic migration is supported.

ledger.json is the canonical current maintenance record for ONE run. actions.jsonl is chronological audit history, not a second independent current state. Reports are output only. Do not import another machine's ledger as verified facts or authorizations. templates/ledger-contract.json supplies the shared machine-readable field/enum/summary contract; both backends enforce it plus their native filesystem invariants.

## Assessment-record helpers: root fields

| Field | Meaning |
|---|---|
| schema_version | Contract version; reject unsupported values. |
| toolkit_id | Toolkit identity matching toolkit.json; not a hardware/account identifier. |
| run | ID, fixture/real mode, platform, phase/status, UTC timestamps and purpose. |
| coverage | Authorized areas, observation state and explicit access/coverage limits. |
| components | Distinct installed or reviewed delivery records, with ownership and independent update/security/compatibility states. |
| findings | Scoped security, compatibility or diagnostic claims, conditions and evidence/source references. |
| sources | Public authority/provenance records and retrieval times. |
| evidence | Relative owned evidence paths, SHA-256, UTC observation time, scope and limits. |
| actions | Planned/attempted/verified work linked to exact components, approvals and receipts. |
| approvals | Actual owner decisions, their scope, action IDs and exact plan hash. |
| diagnosis | Hypotheses, evidence, supported mechanism/cause, uncertainty and proposed repair. |

IDs must be unique in their collection; references must resolve. Evidence paths must remain relative to the owned run and pass containment/reparse checks. Dates use UTC ISO-8601 with Z. Versions remain strings; use the appropriate version scheme, not a generic lexical comparison.

## Assessment-record helpers: run and coverage

run contains id, mode, platform, phase, status, created_utc, updated_utc, purpose and pending_restart. The last field is a Boolean workflow checkpoint; its initial false value is not a query proving the operating system has no pending restart.

- mode: fixture or real.
- platform: windows, linux, macos or unknown.
- phase: assessment, diagnosis, planning, approval, execution, verification or closed.
- status: draft, active, held, partial, failed or completed.

Each coverage item has id, scope, state and limits. State is not_checked, observed, partial, verified or excluded. "Verified coverage" is limited to the named collection/check; it is not exhaustive whole-device discovery.

A completed assessment can retain explicit holds and unknowns. It must not contain an active operation or unresolved claimed-success verification. An empty/unassessed run cannot be presented as a clean computer.

Creation backend, mode and platform are bound in the run marker and must match the selected helper and ledger. A fixture cannot be promoted or relabeled as a real assessment. Platform/backend changes require a fresh run. A foreign or missing backend marker is refused before a writer mutates run state; there is no automatic migration. Hand-editing the marker is unsupported and does not establish consent or real evidence.

## Assessment-record helpers: component records

Required identity/state fields: id, name, kind, installed_version, reviewed_target, available_release, update_state, security_state, compatibility_state, owner_scope, evidence_ids, finding_ids, next_step and agent_id. Unknown installed_version, reviewed_target, available_release and agent_id use null rather than invented values.

Preserve nullable installed/target versions as unknown when not established. Helpful optional context includes architecture, manager, channel, default_resolution and owner_component_id. Newest available_release and suitable reviewed_target are different concepts.

Optional component-context fields use strings or null. A non-null owner_component_id must resolve to the exact ID of an existing component, with matching case. An absent or invalid owning-application reference cannot be treated as a validated relationship.

- owner_scope: system, machine, user, vendor_bundle, project, portable or unknown.
- update_state: unknown, observed, update_available, held, staged, installed_unverified, verified or retired.
- security_state: not_assessed, no_applicable_finding_established, conditional, outstanding, partial, verified_scoped or vendor_hold.
- compatibility_state: not_tested, conditional, held, passed_scoped or failed.

Update "verified" means the scoped installation postcondition is evidenced. It never implies security_state verified_scoped. A publisher-owned bundle can remain vendor_hold while the standalone installation is updated.

Do not count different architectures, scopes, bundles or project environments as accidental duplicates without evidence. Do not count two coupled package changes as two applications. Retired records remain historical; they are not active installed-target tasks.

## Assessment-record helpers: findings and sources

A finding has id, component_id, kind, state, claim, conditions, evidence_ids and source_ids.

Finding state: open, conditional, held, resolved_scoped, not_applicable or unknown. Describe advisory identity, exact affected delivery/platform/architecture, version/backport evaluation, trigger prerequisites and uncertainty in the claim/conditions. Do not equate a version match with demonstrated exploitation.

A source has id, url, title, retrieved_utc, authority, provenance_verified and checks. Authority is official_vendor, official_os, package_registry, installed_metadata, secondary or owner_report. Canonical web-source URLs require HTTPS without credentials, query strings or fragments; null URLs are reserved for installed_metadata and owner_report. Reference the stable publisher page rather than a sensitive signed download URL. A true provenance flag needs recorded ownership checks; syntax-valid URLs and hashes alone do not establish authority.

Use relevant primary records to confirm a vulnerability claim or remediation. Secondary news supplies context/leads. A failed source fetch is recorded as a limitation; do not label unseen content verified.

## Assessment-record helpers: evidence and action history

Evidence has id, relative_path, sha256, kind, observed_utc, scope and limits. Do not store secrets or broad personal diagnostic dumps. A matching hash proves unchanged bytes, not applicability, publisher authenticity or owner consent.

An action has id, kind, state, component_ids, evidence_ids, approval_id, started_utc, finished_utc, outcome and automatic_retry=false.

- kind: observe, diagnose, prepare, update, repair, verify, cleanup or retire.
- state: planned, awaiting_approval, approved, running, partial, failed, completed or cancelled.

Distinguish observed owner changes, observations and executed mutations. Failed/partial action records are immutable history. A successful recovery is a distinct reviewed action; do not erase the failed attempt, relabel it completed, or repeat it automatically.

An optional resolves_action_ids array is allowed on a new verify action. Its unique targets must be existing failed/partial action IDs, never itself. A completed resolver requires nonempty owned evidence receipts establishing the operation/recovery checkpoint and what remains. A closed completed run may retain failed/partial history only when each is explicitly covered by such a completed verification record. This resolves the operation's housekeeping checkpoint, not its security finding; unresolved findings/holds remain visible. An unresolved partial operation still prevents completed-run cleanup.

Update actions need appropriate installed-state/behavior receipts; claimed security fixes need a separate scoped verification. Report application events, component outcomes, OS repair events, observations and vulnerability assessments with explicit units, not one misleading percentage.

## Assessment-record helpers: approvals

An approval includes id, scope, decision, recorded_utc, authorization_quote, action_ids and plan_sha256. Decision is pending, approved or rejected. Preserve the actual human instruction and its scope; do not fabricate a quotation.

Before mutation, freeze the concrete plan and bind its hash, exact actions/targets, data effects and restart policy to authorization. Imported approval records cannot authorize themselves. The assistant must establish that consent came from the current owner in this run.

For CompletedRun deletion, additionally record acknowledge_records_and_backups_deletion=true with the exact cleanup plan hash and scope. Approval to update software does not imply permission to delete reports/backups.

## Assessment-record helpers: diagnosis

diagnosis contains status, hypotheses, original_cause, uncertainty, least_disruptive_fix and repair_approved.

- status: not_started, investigating, mechanism_supported, cause_supported or uncertain.
- Hypothesis fields: id, claim, state, evidence_ids and alternatives.
- Hypothesis/alternative state: proposed, supported, disproved or unknown.
- Alternatives contain claim, state and evidence_ids.

Mechanism supported does not imply original cause supported. repair_approved defaults false. A proposal becomes executable only through the actual approved action plan, not this Boolean.

## Assessment-record helpers: derived outputs and bookkeeping

BuildReport reads canonical ledger bytes once, saves reports/<ledger-prefix>-<template-prefix>/ledger.snapshot.json, and derives HTML, CSV and summaries from that snapshot. Each output identifies its full source hash. Template changes produce a new snapshot directory. Do not manually repair counts in the HTML or silently update an old snapshot.

owned-files.json tracks positively owned artifact paths/hashes and cleanup classifications; it is not maintenance truth. Cleanup plans/receipts under the helper's work subdirectories are generated artifacts too. Their existence does not authorize unrelated deletion.

Do not retain personal data in reusable fixtures. Any fixture run/report is prominently marked fictional and cannot supply a real run's conclusions or approvals.
