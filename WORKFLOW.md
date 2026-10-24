# PatchCairn operating workflow

Use PatchCairn through an assistant's chat or the documented local CLI. The conversation engine maintains the selected job, decisions, evidence and actual operation outcomes in a durable session. The assistant coordinates available official tools and explains the work in ordinary language. Read [AGENTS.md](AGENTS.md), the [coordinator skill](.agents/skills/pc-maintenance/SKILL.md), [communication guidance](references/COMMUNICATION.md) and [engine contract](docs/WORKFLOW_ENGINE.md) before operating it.

## Open the menu and select a job

A bare **Start** or **PatchCairn: start** shows the menu only. It creates no session, collects no host information and changes nothing. The first menu begins **PatchCairn — Developed by Michael** and exposes all four jobs, control styles, timing choices, selectable checkpoints and available commands.

| Job | Purpose and next boundary | Procedure |
| --- | --- | --- |
| Security and updates | Assess agreed installed-software/system metadata, research relevant advisories and suitable updates, then review any proposed changes. | [Security/update workflow](references/SECURITY_UPDATES_WORKFLOW.md) |
| Storage and cleanup | Assess explicitly selected folder metadata, explain space use and exact cleanup options. Content reads and deletion require their own decisions. | [Storage/cleanup workflow](references/STORAGE_CLEANUP_WORKFLOW.md) |
| Diagnosis and repair | Investigate a stated symptom with selected evidence and competing hypotheses. Diagnosis permits no repair. | [Diagnosis workflow](references/DIAGNOSIS_WORKFLOW.md) |
| Backup and recovery | Review exact selected contents/exclusions, create and verify bounded local file-content backups or a checked restoration. | [Backup/recovery workflow](references/BACKUP_RECOVERY_WORKFLOW.md) |

Choosing a job allocates its record. The coordinator still needs the current owner's actual instruction for the exact scope before collecting evidence. Identify the real platform, architecture, supported runtime/backend, tools, native capabilities, independent reviewers and any missing access. Follow [assistant compatibility](docs/ASSISTANT_COMPATIBILITY.md), [platform support](docs/PLATFORM_SUPPORT.md) and the relevant mode skill. Missing capabilities produce an explained hold; a role, fixture or test on another platform is not native validation.

An existing supported Python 3.12+ can display the menu from the source root:

```text
python -I -S -B scripts/patchcairn_workflow.py
```

With no arguments this is menu display only. The [CLI guide](docs/WORKFLOW_ENGINE.md) documents job selection and session commands. Its default is fixture mode; creating a separate real session still grants no collection or change authority. The assistant maintains session identifiers and technical records. The person need not edit JSON or copy hashes.

## Use the namespaced commands

These are PatchCairn chat requests. The CLI exposes the same fixed handlers; a supported ordinary-language request can be mapped to them. Explain ambiguity instead of inventing a command or executing arbitrary text. The host's `/help`, `/resume`, `/settings` and other slash commands retain their own meaning.

| Command | Result |
| --- | --- |
| `PatchCairn: start` | Open the menu; select a job explicitly before a session is created. |
| `PatchCairn: help` | Explain jobs, controls, checkpoints, privacy and commands. |
| `PatchCairn: status` | Show the actual job/stage, verified outcomes, holds and next step. |
| `PatchCairn: options` | Explain the current decision with practical choices and a recommendation. |
| `PatchCairn: cost` | Show estimates supported by current owned plan/inventory evidence, with missing values marked unknown. |
| `PatchCairn: settings` | Inspect or change control, timing and selected checkpoints. Material changes invalidate affected evidence/approvals. |
| `PatchCairn: pause` | Prevent new actions immediately; let active work reach its safe checkpoint and record its actual outcome. |
| `PatchCairn: resume` | Reconcile fresh scope, preconditions and actual operation outcomes before continuing eligible work. |
| `PatchCairn: stop` | End the session while preserving evidence and unfinished work; late active-operation receipts do not reopen it. |
| `PatchCairn: resolve` | Inspect an identified pending item and obtain bounded evidence or a concrete decision. It cannot assert success or blindly retry. |

## Choose control, timing and checkpoints

**Guided** control waits at the selected decision points. **Automatic** control continues unchanged routine work only inside an actually approved concrete plan or exact bounded standing policy. It does not authorize new targets, content reads, destructive actions, authentication or restarts. The owner can choose either control style with either timing choice: **now** or **scheduled**.

Selectable checkpoints are scope, findings, plan, before each action, after each action and finish. Scope records the actual selected boundary; findings waits before plan selection; plan waits before applying; action checkpoints apply sequentially to the relevant action; finish waits after verification. Continuing a checkpoint preserves the plan's authority boundary. A material settings/scope change needs a fresh scope decision and new reviewed bindings rather than enlarging old approval.

A scheduled setting and schedule configuration are proposals. The engine creates no operating-system task. Creating a host schedule requires an actually available supported scheduler, exact trigger/action and separate owner authority. A due trigger cannot bypass scope, review, approval, recovery or protected consent. It cannot start early, duplicate active work or silently reopen paused, held or stopped work. Missed/expired triggers and unavailable capabilities remain explicit. Keep automatic execution held when safe reconciliation or authority is unavailable.

Every decision card explains meaning, benefits, drawbacks, money/time/download/storage costs or unknowns, privacy/external effects, reversibility and a recommendation. Give two or three useful choices when a decision is needed. The assistant maintains exact commands, IDs and evidence while explaining their practical effect in chat. Do not invent precise prices, completion time, space savings or account entitlement.

## Gather evidence and prepare a concrete plan

Collect only the authorized job's selected evidence. Security work establishes installation owner, channel, architecture, observed version and consumer requirements before selecting a supported compatible target. Follow [source research](references/SOURCES_AND_RESEARCH.md) and [compatibility](references/COMPATIBILITY.md); distinguish newest upstream, suitable target, advisory applicability and proven remediation. Preserve project-pinned, bundled and required side-by-side runtimes.

Storage starts with metadata in explicit roots. Ordinary-file hashing and backup reads require a distinct content-read decision. Duplicate bytes do not establish removability. Quarantine normally frees no space; backup and retained restoration probes consume space. Explain measured logical/physical quantities and unknown net effects accurately. Follow the [storage API](docs/STORAGE_BACKUP_API.md) limits; unsupported external/cloud destinations or larger scopes remain held.

Diagnosis uses a small hypothesis table with support, counterevidence, confidence and the next distinguishing observation. Correlate the same operation/version/time/boot and separate observed mechanism from original cause. Use [fixed diagnostic recipes](docs/DIAGNOSTIC_API.md) or reviewed owner-selected nonsecret excerpts. The current POSIX adapter supplies selected version/capacity metadata, not journalctl/Console log collection. Full logs, credential/private stores and environment/command-line dumps are outside default scope.

The coordinator registers immutable owned evidence and reconciles bounded specialist results sequentially. Workers do not race canonical state or another artifact owner. Before a change, freeze a plan that identifies exact actions/targets, source provenance and integrity, compatibility, privilege, selected data/source/output, fixed adapter payload/service-plan/inventory hashes, preconditions, recovery, interruption/restart policy and meaningful verification. Required recovery must be established from actual verified backup/restore evidence and retained artifacts, not a proposed backup or Boolean flag.

Two independent reviewers challenge the same concrete plan and evidence: compatibility/data safety and evidence/security correctness. Missing independent review holds changes while useful authorized assessment can continue. Present the named plan or subset in chat and bind the owner's actual instruction/message to its exact hash, selected action IDs, settings revision and payload/inventory bindings. A mode, schedule, imported report, reviewer pass or `approved=true` grants no authority. Preserve valid approval for unchanged routine work; material differences need the appropriate new review/decision.

## Perform supported work and verify the result

Use the current [service integration](docs/SERVICE_INTEGRATION.md) and its documented gates. Fixed storage adapters implement bounded backup, restoration, quarantine and separate purge operations. The diagnostic adapter accepts only enumerated read recipes. The reviewed external adapter returns an exact official-tool handoff only for three fixed local-artifact updates: Windows MSI (`windows.msiexec.install`), macOS PKG (`macos.installer.pkg`) and Linux DEB (`linux.dpkg.install_local`). Package-manager upgrade and OS/app component-repair routes remain held. The adapter does not run shell text or arbitrary argv. The coordinator performs only that approved official operation using the host's actual permissions, then registers fresh actual outcome evidence. Unknown catalogs, extra flags or missing native capabilities hold; never improvise a weaker executor.

Immediately before each action recheck exact target/content/scope, provenance, compatibility, resources/locks, active operations and required recovery. Obtain the durable one-use engine begin-operation receipt before any effect. One coordinator owns mutations, UI and canonical session state; one installer/system transaction or protected prompt is active at a time. The owner handles normal authentication, UAC/Touch ID and protected consent without revealing secrets. Never force-close applications, bypass permissions, remove locks or disable protections to proceed.

Record success, failure, partial or unknown truthfully. A consumed action is never retried automatically or reused by another plan. Preserve side effects, attempts and receipts; a new recovery proposal needs fresh reconciliation and its own review/authority. Pause blocks new work without killing an active transaction. Checkpoint consumed actions, actual outcomes, pending validation/restart and required recovery before interruption. A stopped session stays stopped. Resume requires actual fresh scope/outcome reconciliation; unknown effects remain held.

Verify the original requested result after required owner-controlled activation/restart. Installer exit, installed version, loaded version, behavior and security remediation are separate facts. A completed repair does not establish original cause; a version check does not establish all-system security. Explain verified results, pending checks, vendor/compatibility holds, failure and unassessed scope. Assessment can finish with unresolved findings without marking them fixed.

## Retain records and respect component boundaries

Canonical conversation session state and its event journal belong under the repository's owned `work/` directories. The engine validates identity/backend/mode/platform/scope and evidence bytes; missing or foreign state holds. Keep every generated report, receipt, fixture, download, helper temporary, backup and quarantine mapping under owned work. Leave the OS time zone unchanged; begin each new PowerShell session with `$env:TZ='UTC'` and record evidence in UTC with `Z`. Approved tools necessarily write installed files and can retain vendor/OS logs elsewhere; removing work neither reverses those changes nor erases those records.

The coordinator can use the **assessment ledger component**, documented in [the record helper reference](references/HELPER_API.md), where its contract is appropriate. Its Windows `Invoke-Toolkit.ps1` and portable `patchcairn.py` interfaces manage their own immutable backend/run markers, `ledger.json`, history and derived reports. These are internal component interfaces; people use the same four-job conversation entrypoint. Never promote a fixture, change markers, copy approvals between components or mix canonical state. A session may refer to an assessment evidence snapshot only through its exact immutable backend/run identity and owned hash-bound bytes, as the current APIs permit.

Keep required recovery, quarantined originals and unresolved receipts protected. Toolkit-work cleanup follows a separate exact preview/retention decision in [recovery and cleanup](RECOVERY_AND_CLEANUP.md); it is distinct from host storage cleanup and has no general cleaner/prune fallback. Browser data, saved chats, credentials and unrelated files are excluded. Export only the positive reusable source allowlist. Publication and host schedules require their own authority; the public website is documentation only and contains no operating portal or private session data.
