# Requests you can use with PatchCairn

Open the PatchCairn source folder in a capable assistant and ask it to read [AGENTS.md](AGENTS.md) and the [coordinator skill](.agents/skills/pc-maintenance/SKILL.md). These examples are chat requests. The assistant maps them to the deterministic engine, keeps the technical records and explains meaningful choices in ordinary language. You do not edit JSON, type hashes or supply passwords.

## Begin with the menu

> Read this project's instructions and show the current PatchCairn menu. Explain the four jobs, guided or automatic control, now or scheduled timing, selectable checkpoints and all available commands. Do not collect computer information until I select and authorize the scope.

You can also type `PatchCairn: start` or simply **Start**. Both show the menu only: no session, scan, installation or cleanup. The menu begins **PatchCairn — Developed by Michael**. Selecting a job creates its record; the assistant then confirms the actual selected scope before evidence collection.

If you use a terminal, an existing supported Python 3.12+ can show the same menu from the source root:

```text
python -I -S -B scripts/patchcairn_workflow.py
```

The [engine/CLI guide](docs/WORKFLOW_ENGINE.md) documents further arguments and handlers. CLI fixture mode is the default. A real session is a separate record, not collection or change permission. If a required runtime or host capability is missing, the assistant explains the available choices instead of installing it silently. See [assistant compatibility](docs/ASSISTANT_COMPATIBILITY.md).

## Choose one of the four jobs

**Security and updates** — choose this to understand the agreed software and system update needs.

> Start the security and updates job. Assess only the system and installed-software metadata we agree on. Research applicable official advisories, vendor news and compatible supported updates. Explain what matters and show a concrete plan before any installation, removal, repair or restart. Keep private files, browser data and unrelated projects outside scope.

The assistant identifies the actual installation owner, architecture, channel and required runtimes. A newer release is not automatically suitable, and an installed version check is separate from proving a security issue resolved. [Security/update procedure](references/SECURITY_UPDATES_WORKFLOW.md).

**Storage and cleanup** — choose this to understand space use in folders you explicitly select.

> Start the storage and cleanup job for the folders I select. Begin with file metadata only. Show the largest categories and the exclusions, and explain which space figures are measured or unknown. Ask separately before reading file contents for duplicate checks or backups. Show an exact cleanup plan and recovery limits before moving or deleting anything.

Equal file bytes do not prove either copy can be removed. Quarantine usually frees no space, and a backup plus restoration probe needs extra storage. Browser profiles, saved chats, credentials and unrelated files stay excluded. [Storage/cleanup procedure](references/STORAGE_CLEANUP_WORKFLOW.md).

**Diagnosis and repair** — choose this for a stated failure or unexpected behavior.

> Start diagnosis for this problem: [describe what failed, what you expected and when it occurred; include only a short nonsecret error]. Compare plausible explanations and counterevidence using the smallest relevant checks. Explain the supported failure mechanism, confidence, unknown original cause and next useful observation. Present a supported repair and its effects before making changes.

Do not paste passwords, tokens, keys, raw logs or private configuration. Diagnosis permits bounded evidence collection only. A documented repair can be reasonable while the original cause remains unknown; it still needs a concrete reviewed plan and approval. [Diagnosis procedure](references/DIAGNOSIS_WORKFLOW.md).

**Backup and recovery** — choose this for selected local file-content protection or a checked restoration.

> Start backup and recovery for the ordinary files I select. Show the exact contents, exclusions, destination, extra space needed and privacy/recovery limits before reading their contents or writing a backup. After approval, verify the archive and a checked restoration. Explain what this local file-content backup can recover and what it does not preserve.

The current bounded helper keeps output under owned toolkit work and does not support external/cloud destinations or an entire-system image. Compression is not encryption, and a backup on the same drive is not off-device disaster protection. Restoration uses a new reviewed destination and does not overwrite originals. [Backup/recovery procedure](references/BACKUP_RECOVERY_WORKFLOW.md).

## Set how and when the work proceeds

> Explain guided and automatic control for this job. I want to choose my checkpoints separately from whether the work happens now or is scheduled. Show the benefit, drawback, money/time/storage cost or unknowns, privacy effects and reversibility of each useful choice, with your recommendation.

Guided control waits at your selected checkpoints: scope, findings, plan, before an action, after an action and finish. Automatic control can continue only unchanged routine actions inside your exact approved plan or a bounded standing policy. It cannot supply missing authority, bypass protected consent or make unknown outcomes successful.

> Prepare a schedule proposal for this selected job and time. Explain the exact scope, trigger, control style, checkpoints, limits, failure/pause handling and any additional host scheduler authority needed. Do not create a host schedule until its concrete action is approved.

Scheduling is independent of guided/automatic control. The engine stores proposals and coordinates due triggers; it does not create an operating-system schedule. A trigger cannot start early, duplicate active work or silently restart a paused, held or stopped session. Missing safe scheduling capability leaves a proposal you can start later.

## Use any command from the beginning

| Chat command | Ask it to do this |
| --- | --- |
| `PatchCairn: start` | Open the job/control/checkpoint menu without collecting information. |
| `PatchCairn: help` | Explain the jobs, settings, privacy and available commands. |
| `PatchCairn: status` | Explain what is verified, current, waiting or unfinished and the next step. |
| `PatchCairn: options` | Show useful current choices and a recommendation with consequences. |
| `PatchCairn: cost` | Explain supported estimates and unknown money, time and storage costs. |
| `PatchCairn: settings` | Review or change control, timing and selected checkpoints. |
| `PatchCairn: pause` | Prevent new actions and checkpoint active work safely. |
| `PatchCairn: resume` | Reconcile actual outcomes and current scope before eligible work continues. |
| `PatchCairn: stop` | End the session and preserve evidence and unresolved work. |
| `PatchCairn: resolve` | Inspect a specific pending decision or reconcile a bounded uncertain outcome. |

These are PatchCairn requests, not provider slash commands. Your host's `/help`, `/resume` and `/settings` keep their normal meaning. The assistant identifies the current session; when more than one is possible, it asks one clear question. A command gets its actual handler result or an explained capability hold, not a guessed status.

## Approve a concrete plan or continue after an interruption

After the assistant has presented one clearly named reviewed plan:

> Apply the plan you just explained, limited to [name the plan or selected actions]. Continue its unchanged approved routine steps, keep me informed and verify the actual results. Explain material changes or separately required decisions before proceeding.

This refers to the actual plan in the conversation. The assistant binds your instruction to exact action IDs, plan/payload/inventory hashes and settings revision; you do not copy those values yourself. Two independent reviewers assess compatibility/data safety and evidence/security correctness before changes. Approval does not add private-file access, an unapproved restart/removal or protected consent. Changed settings invalidate affected approvals rather than enlarging them.

After a restart or interruption:

> Check what actually completed in the previous PatchCairn session. Explain what changed and what remains. Reconcile current evidence before resuming only eligible approved work; do not repeat a failed, interrupted or unknown action.

A host conversation resume is different from PatchCairn outcome reconciliation. Pause blocks new actions without killing an active installation. Stop remains terminal even if a late receipt arrives. Failed/partial/unknown attempts stay historical; a new recovery proposal needs its own appropriate review and decision. An installer exit, version string or repaired symptom does not prove all security fixed or establish the original cause.

## Retain or share the result

> Explain the final result, remaining uncertainty and anything I need to do. Show which toolkit-owned working files could be cleaned separately, with exact sizes and what evidence or recovery would be retained or lost. Wait for my decision on that exact preview.

This is toolkit-work housekeeping, distinct from the storage job. Required recovery, quarantined originals, active work and unresolved receipts remain protected. The current service has no general session-deletion or required-retention-release executor; if no exact supported cleanup path exists, retain the files. Any supported record deletion needs the specific loss decision and component checks in [recovery and cleanup](RECOVERY_AND_CLEANUP.md). Approved tools and the OS can keep records outside work; deleting work does not erase those records or reverse installed changes.

> Prepare a reusable source-only package for another computer. Verify its exact allowlisted contents and exclude work, private sessions, inventories, logs, backups, credentials and Git history. Do not upload or publish it.

The next computer needs fresh scope, facts and authority. Public-site documentation does not operate your computer. See [publication guidance](PUBLICATION.md) for a separately authorized publication.

The assistant selects suitable internal record helpers as part of this same workflow; you do not choose another product version or startup route. The [record helper reference](references/HELPER_API.md) documents component markers, record IDs and reports for maintainers. Records remain bound to their creating component: no fixture promotion, marker changes, imported approvals or automatic migration. Any permitted cross-reference stays tied to the exact immutable backend identity and hash-bound evidence.
