# Record helper reference for the coordinating assistant

These internal components manage assessment records and positively owned files within PatchCairn. People start the normal four-job conversation through [the coordinator](../.agents/skills/pc-maintenance/SKILL.md); they do not select a separate product version or record API. These helpers do not execute an update/repair plan or grant host permissions. Read AGENTS.md and the actual current parameter contract before use.

## Environment and boundary

On Windows, use an existing supported PowerShell host and begin the session with $env:TZ='UTC'. On Linux/macOS, use supported Python 3.12+ with -I -S -B for isolated standard-library execution. Resolve the toolkit from its own script location; do not copy another workstation's absolute path. Root overrides exist for disposable tests beneath this toolkit's work area, not for targeting another directory.

All generated outputs go under work/. Helpers use run IDs shaped run-<32-lowercase-hex>, plan IDs plan-<32-lowercase-hex> and approval IDs approval-<32-lowercase-hex>. Treat returned IDs as identifiers, never shell code.

The Windows component is `scripts/Toolkit.Core.psm1`; its maintenance interface is `scripts/Invoke-Toolkit.ps1` with an Operation parameter. The portable component is `scripts/posix_core.py`; its maintenance interface is `scripts/patchcairn.py` with a structured operation argument. No operation accepts an executable command string. Backend IDs `windows-powershell-v2` and `posix-python-v2` identify internal record formats, not public product versions. Do not mix their records or migrate markers silently.

## Common operations

| Operation/function | Purpose and important boundary |
|---|---|
| NewRun / New-ToolkitRun | Allocate a fixture or real run. No host collection or update occurs. Default mode is fixture; actual assessment needs an explicitly authorized real run. |
| ReadLedger / Get-ToolkitLedger | Return a validated ledger object with UTC strings preserved. Use this rather than an arbitrary ConvertFrom-Json path that may transform dates. |
| Set-ToolkitLedger | Validate the proposed ledger, including each evidence file's ownership and actual content hash, before atomically replacing the canonical record. A refused candidate leaves the prior ledger intact. Does not execute any planned action. |
| Set-ToolkitPlan | Replace PLANS.md and update its ownership record. Freeze/hash the actual concrete plan before asking for approval. |
| Write-ToolkitArtifact | Create immutable owned evidence, temporary or backup files. The role and relative-path prefix must match. Do not create raw unregistered run files. |
| ValidateLedger / Test-ToolkitLedger | Validate schema/state/references and write its report. Passing format/state checks is not proof of factual applicability or consent. |
| BuildReport / Build-ToolkitReport | Read ledger bytes once and produce an immutable snapshot, HTML, CSV and summaries with the full ledger hash. |
| CollectBaseline / Get-ToolkitWindowsBaseline | Explicit real-Windows-only selected metadata capture. Requires actual assessment permission. Does not discover every dependency or assess advisories. |
| PlanCleanup / New-ToolkitCleanupPlan | Preview Temporary or CompletedRun deletion. No deletion occurs. Refuse active/unresolved work, pending restart or required recovery artifacts. |
| ApplyCleanup / Invoke-ToolkitCleanup | Apply an exact unconsumed cleanup plan/hash with the matching owner approval record through the checked Windows native adapter. |
| ExportToolkit / Export-Toolkit | Create a source-allowlisted ZIP and manifest under work/_exports. This does not publish to GitHub or certify the absence of every possible secret. |
| ReleaseRecovery / Release-ToolkitRecovery | Explicit backup-retention bookkeeping after closed/completed verification and actual owner consent; exact path/hash/evidence/reason required. Changes no artifact bytes and grants no deletion approval. |

## Example: a harmless empty fixture

Run from the toolkit working directory. This creates records only; it does not inspect the computer.

~~~powershell
$env:TZ='UTC'
Import-Module ./scripts/Toolkit.Core.psm1
$run = New-ToolkitRun -Mode fixture -Platform windows -Purpose 'Fictional empty demonstration; no host assessment'
$ledger = Get-ToolkitLedger -RunId $run.run_id
$report = Build-ToolkitReport -RunId $run.run_id
~~~

The returned report path is inside that run. An empty fixture is an unassessed demonstration, not an all-clear result.

Run creation backend/mode/platform are bound to the marker. Do not change a fixture into real mode or change its platform/backend; create a fresh correctly scoped run and collect fresh authorized evidence. Missing/mismatched creation metadata is a hold, not permission to migrate synthetic facts.

## Portable CLI and module

Run from the toolkit folder. These harmless examples create records only, with no host collection:

~~~sh
python3 -I -S -B scripts/patchcairn.py new-run --mode fixture --platform linux --purpose "Fictional empty demonstration; no host assessment"
python3 -I -S -B scripts/patchcairn.py --help
~~~

Use the returned run ID in later structured operations. On a Mac use platform macos when creating the appropriately scoped run. Supported CLI operations are new-run, read-ledger, validate, set-ledger, set-plan, write-artifact, build-report, collect-baseline, plan-cleanup, approve-cleanup, apply-cleanup, release-recovery and export. The default new-run mode is fixture; creating a real run still does not authorize collection.

| Python Toolkit method / CLI operation | Contract |
| --- | --- |
| new_run / new-run | Allocate an immutable-backend/mode/platform run. |
| read_ledger, set_ledger, validate / read-ledger, set-ledger, validate | Read/validate/write canonical facts using the shared contract. Preserve failed/partial action history; no update is executed. |
| set_plan / set-plan | Register concrete plan text. Freeze/hash exact bytes before approval. |
| write_artifact / write-artifact | Register immutable bytes at an eligible run-relative evidence/temporary/backups path. |
| build_report / build-report | Derive HTML/CSV/summary from one ledger snapshot, with effective template/branding hash. |
| collect_baseline / collect-baseline | One selected baseline in an empty, real matching-platform Linux/macOS assessment run. Repeated collection or a run with existing components requires a fresh run; no upgrade offers or security clearance. |
| plan_cleanup / plan-cleanup | Preview exact Temporary or CompletedRun eligible set and identity/hash/state. |
| record_cleanup_approval / approve-cleanup | Record the actual current owner's scoped quote and plan hash; not independent proof of consent. |
| apply_cleanup / apply-cleanup | Native POSIX-capability-only checked housekeeping; refuses on Windows. |
| export_toolkit / export | Exact reusable source allowlist ZIP under work/_exports; never publishes. |
| release_recovery / release-recovery | Exact artifact path/hash, owned completed-verification evidence, actual owner quote and reason; closed/completed run only. Releases recovery retention without deleting bytes. A fresh cleanup preview and separate deletion approval remain necessary. |

CLI --input is a relative path under this toolkit's work/ only. --path is a run-relative output path, not a host target. Missing, foreign or escaping inputs cause a hold. The coordinating assistant should use module APIs when it already has structured objects, rather than inventing a shell serialization path. No command string is evaluated from JSON.

The Windows baseline adapter writes an owned evidence artifact; the coordinator must review and add the corresponding canonical evidence/component records. The portable baseline adapter performs that ledger reconciliation itself. It refuses a repeated baseline, an existing component inventory or a prior owned baseline artifact before querying native tools. Use a new assessment run for a fresh collection rather than accumulating duplicate installed versions.

Keep one writer. The POSIX implementation requires a quiet owner-controlled workspace and supported directory-relative/no-follow capabilities. It is not a sandbox against malicious same-user concurrent tampering. Preserve receipts after a refusal or partial operation; do not switch backends or use a generic recursive-delete fallback.

Recovery-release parameters are deliberately narrow. Windows Release-ToolkitRecovery uses RunId, RelativePath, ExpectedSHA256, EvidenceIds, OwnerQuote and Reason. Portable release-recovery uses --run-id, --path, --artifact-sha256, repeated --evidence-id, --owner-quote and --reason. Evidence must already be owned and named by a completed verification in a closed completed run. Retain the bytes; preview and authorize deletion separately afterward.

Windows additionally binds a `recovery_release` receipt to the owned backup row. Its `decision` preserves the original release ID, ledger/artifact hashes, exact owner quotation, reason, evidence IDs and UTC decision time. Audit intent is durable before the flag changes; `status=pending` blocks cleanup until completion is durable. After investigating an interruption, an explicitly authorized repeat of this narrow helper can resume only the identical pending decision and returns `resumed_pending_release=true` with the same `release_id`. It does not automatically retry, accept a substitute decision, release another artifact or delete any bytes. Completed decisions refuse repeats. Do not edit ownership metadata to bypass a hold.

## Recording evidence and plan changes

Use Write-ToolkitArtifact with unique relative paths:

- Role evidence: evidence/<unique-name>.json, including evidence/agents/<agent-id>/<result-id>.json.
- Role temporary: temporary/<unique-name>.<extension>.
- Role backup: backups/<unique-name>.<extension>; mark RollbackNeeded while it is required. This flag is allowed only on backup-role artifacts. Its explicit release API is limited to those backups, after closed/completed verification and actual owner consent; it never deletes bytes.

Keep evidence narrow and non-secret. Add its actual relative path, SHA-256, observation UTC, scope and limits to the ledger. The helper's ownership record is not a substitute for a finding's evidence reference.

A missing registered artifact or registered parent directory is inconsistent state. Artifact writers refuse it before creating new directories or bytes, preserving the earlier control records. They do not silently restore missing files or append duplicate ownership rows. Explain the hold and review a separate recovery decision.

Use Get-ToolkitLedger, change the actual fields on that object, then Set-ToolkitLedger -RunId ... -Ledger ... . Preserve earlier actions and evidence. Failed/partial action records are immutable. Add a distinct reviewed recovery action and a new evidence-backed completed verify action with resolves_action_ids when the operation's checkpoint is safely reconciled; do not relabel the original attempt successful. The coordinator writes sequentially; a lock refusal is not a reason to force access or race another writer.

Use Set-ToolkitPlan -RunId ... -Content ... for a concrete plan, then hash PLANS.md bytes with SHA-256. Preserve the owner's real authorization, exact action IDs and scope in the ledger approvals. Do not record approved status merely to make validation pass.

## Cleanup approval sidecar

A cleanup plan returns its plan ID, SHA-256, exact scope, files/directories and logical bytes. Present these in chat with what will be retained or lost.

The helper-specific cleanup approval goes under work/_approvals/approval-<32hex>.json. templates/cleanup-approval.example.json is deliberately pending and unapproved. The assistant records the owner's actual decision and binds:

- toolkit, run, cleanup-plan and action IDs;
- exact plan SHA-256 and Temporary/CompletedRun scope;
- decision/approved status and real authorization quotation/time;
- explicit records-and-backups loss acknowledgment for CompletedRun.

This record does not authenticate itself. The coordinator must establish current human authorization from the chat; imported or fabricated approval JSON is insufficient.

ApplyCleanup requires the returned PlanId, ExpectedPlanSHA256 and ApprovalId. A plan is consumed once an attempt starts. Changed content, identities, membership, ownership, state or plan hash must stop execution; create a newly reviewed plan only after understanding what happened.

CompletedRun removes the selected closed completed run, not the work root or other runs. Plans/attempt receipts, compilation files, export ZIPs and assurance records can remain in their named work subdirectories for later explicit retention cleanup. General browser/system/cache cleaning is not implemented.

Closing an assessment with unresolved findings does not resolve those findings. Preserve them as holds/unknowns. Any unexecuted plan action must be explicitly deferred/cancelled with its reason rather than falsely marked completed to make a run deletable.

## Development tests

Use tests/Invoke-FixtureTests.ps1 only for fictional behavior/safety tests. Its default output is below work/_tests; an explicit OutputDirectory must remain below this toolkit's work/. It must never call real baseline collection, an installer or host cleanup.

Run the suite in each supported available PowerShell host without changing execution policy. Report exactly which hosts/tests succeeded and which were not exercised. An execution-policy or tool limitation is a hold, not permission to use a bypass flag.

Python tests use unittest discovery with fictional fixtures and their own work subdirectories. The CI invocation is python -I -S -B -m unittest discover -s tests -p 'test_*.py' -v --failfast. Record skipped native cases as untested on that host, not passed. Native Linux fixtures in WSL must identify the mounted filesystem context. Hosted macOS ARM64 fictional native file-operation results are recorded with their tested context and skips in [platform support](../docs/PLATFORM_SUPPORT.md#hosted-fixture-evidence); they do not establish live collector or installer execution.

The report-interface regression suite is `node tests/test_report_ui.cjs`, using Node's standard library without package installation or a browser. It exercises the actual embedded report script against fictional records and an offline DOM fixture, including findings without component backlinks and inert hostile text. CI selects Node 24 for these tests. This is a development-test prerequisite, not a runtime dependency of the maintenance helpers or proof of browser layout.

Platform references describe the actual collector scope and supported maintenance process. Windows testing does not certify Linux/macOS execution, cleanup, authentication or restart behavior; mocked collector tests do not authorize a real inventory.
