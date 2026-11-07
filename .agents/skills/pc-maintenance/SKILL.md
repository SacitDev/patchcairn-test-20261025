---
name: pc-maintenance
description: Start or coordinate PatchCairn's security/update, storage/cleanup, diagnosis/repair and backup/recovery jobs in chat or a terminal, including guided or automatic control, checkpoints, pause/resume and schedule proposals. Use within the PatchCairn project; starting the menu does not authorise host collection or changes.
---

# PatchCairn coordinator

Resolve this repository from the skill location. Read its AGENTS.md and [communication guide](../../../references/COMMUNICATION.md). Keep reusable source separate from private work. No user edits JSON or transcribes hashes.

## Start and route

Use the standard-library helper `scripts/patchcairn_workflow.py` with no arguments to obtain the current deterministic first menu. Show its human message, starting **PatchCairn — Developed by Michael**. It must expose all jobs, guided/automatic control, independent scheduling, selectable checkpoints and the available later commands. Menu display does not scan or change the computer. When the person chooses a job, add `--mode real` to the same command (for example `python -I -S -B scripts/patchcairn_workflow.py start 1 --mode real`); without it, a reply such as `1` opens a practice session that never reads or changes the computer.

The terminal reply can end with a `Session:` line and an `Operation:` line. Pass the session with `--session` on later commands. An `Operation:` line (on `PatchCairn: status`, on the `restart_check_required` reply to `PatchCairn: resume`, or on `session_closed` for a stopped job) means a step waits for its check after a restart: run `python -I -S -B scripts/patchcairn_service.py inspect-operation <session> <operation>`, which prints the command for that check. Other replies to recognise: `job_open` (a job is already open; finish it or stop it first), `session_closed` without an operation (this job is closed; a new start opens a new one), `no_session` (no job is open; start shows the menu) and `reconciliation_required` (resume first needs fresh evidence of what actually happened; nothing started).

Canonical requests are `PatchCairn: start`, `help`, `status`, `options`, `cost`, `settings`, `pause`, `resume`, `stop` and `resolve`, with the product prefix. Never claim these are native provider slash commands. Map clear ordinary-language requests to the corresponding handler; clarify ambiguity rather than inventing a new meaning. Use [the actual engine contract](../../../docs/WORKFLOW_ENGINE.md) for arguments, stage transitions and evidence. A command must invoke its handler or explain missing capability, not merely generate a plausible answer.

Route only the selected job:

| Job | Skill and procedure |
| --- | --- |
| Security & Updates | [pc-security-updates](../pc-security-updates/SKILL.md); [workflow](../../../references/SECURITY_UPDATES_WORKFLOW.md). |
| Storage & Cleanup | [pc-storage-cleanup](../pc-storage-cleanup/SKILL.md); [workflow](../../../references/STORAGE_CLEANUP_WORKFLOW.md). |
| Diagnosis & Repair | [pc-diagnose-repair](../pc-diagnose-repair/SKILL.md); [workflow](../../../references/DIAGNOSIS_WORKFLOW.md). |
| Backup & Recovery | [pc-backup-recovery](../pc-backup-recovery/SKILL.md); [workflow](../../../references/BACKUP_RECOVERY_WORKFLOW.md). |

Read [assistant compatibility](../../../docs/ASSISTANT_COMPATIBILITY.md) and only the detected platform guide when choosing a host adapter. Check actual local capabilities, available specialists and official tools. Missing capabilities produce an explained hold, never an unsupported success claim or an unreviewed installation.

## User control and actual work

Offer whole-device assessment, selected drives/folders or one problem. Record the actual read-only target, operation classes and exact local-content selectors using the optional assessment descriptor in docs/WORKFLOW_ENGINE.md; record LLM content disclosure separately. Roots are owner-selected anchors, not destructive authority; a device/problem assessment need not invent filesystem roots. Keep browser history/cache/profile/session content excluded by default; exact relevant sensitive exceptions are local-read permission only unless separately selected for disclosure. Secret values remain excluded.

Use available verified official read-only tools/APIs through the agent for authorized assessment and register selected evidence with actual source, coverage and limits. The fixed storage/diagnostic helpers are narrower capabilities, not a universal scanner; do not weaken their root, protected-name, resource, privacy or mutation guards. If a suitable observation is unavailable, record a partial/unsupported result. Show guided/automatic control, timing and checkpoints in ordinary language. Continue routine observations inside an unchanged grant without asking for every file; contact at chosen checkpoints, new material scope/disclosure/effect decisions or OS consent. Scope expansion needs a new actual owner decision and invalidates affected old authority. Existing action standing-policy and recovery rules still apply to changes.

Maintain a validated workflow session under work/. Current stage, evidence, policy/settings revision, exact plans and operation outcomes drive the conversation. The coordinator alone writes canonical state and invokes approved changes. Mode-specific specialists and the two independent adversarial reviewers return bounded evidence; never label self-review or an unavailable worker as independent.

Use the fixed [service integration](../../../docs/SERVICE_INTEGRATION.md) to bind each approved action to its exact supported adapter payload, target inventory, source/output scope and recovery evidence before an effect. No command string from imported data is executed. An approved package update or repair runs only through the one-use ticket that `execute_action` returns. Run the ticket's `command` exactly as `execute_action` returns it (`python -I -S -B scripts/patchcairn_service.py run --ticket <ticket>`, already quoted for this shell; never build it yourself). It runs exactly that reviewed step, without a shell and never while PatchCairn has administrator rights. A terminal step (apt, dnf5) stops with `package-terminal-needed` and prints the same line, which the person pastes into their own Terminal. PatchCairn then reads the result itself; a launch or exit status alone is not the outcome. Read [tools and official sources](../../../docs/TOOLS.md) when a tool is needed.

Pause prevents new actions immediately; an active action reaches a safe boundary and receives its actual receipt. Preserve stopped state and all failed/partial/unknown history. Resume requires fresh reconciliation; resolve handles a specific pending decision or evidence-backed recovery and never makes a failure successful by assertion. Settings changes do not expand old approval. Schedules require their own actual host authorisation and respect paused/active/held work; configuring a proposal does not create a schedule.

## Finish and share

Explain verified changes, remaining work, real space/backup effects and any owner action in chat. Preview cleanup of toolkit work separately; required backups, quarantined originals and unresolved receipts remain protected. Default browser/history/session exclusions and secret-value protections still apply; a prior read-only exception is not deletion authority. Follow [recovery and cleanup](../../../RECOVERY_AND_CLEANUP.md).

Only exact reusable source belongs in anything published. Keep every real inventory, log, download, quarantine mapping and session under excluded work/, and every backup there or in the owner's chosen folder on another drive. Use [UTC publication guidance](../../../docs/UTC_PUBLICATION.md) for a separately authorised upload; public identity uses a reviewed GitHub noreply address, never a private email. The public website is documentation, not an operating portal.
