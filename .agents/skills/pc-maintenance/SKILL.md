---
name: pc-maintenance
description: Start or coordinate PatchCairn's security/update, storage/cleanup, diagnosis/repair and backup/recovery jobs in chat or a terminal, including guided or automatic control, checkpoints, pause/resume and schedule proposals. Use within the PatchCairn project; starting the menu does not authorise host collection or changes.
---

# PatchCairn coordinator

Resolve this repository from the skill location. Read its AGENTS.md and [communication guide](../../../references/COMMUNICATION.md). Keep reusable source separate from private work. No user edits JSON or transcribes hashes.

## Start and route

Use the standard-library helper `scripts/patchcairn_workflow.py` with no arguments to obtain the current deterministic first menu. Show its human message, starting **PatchCairn — Developed by Michael**. It must expose all jobs, guided/automatic control, independent scheduling, selectable checkpoints and the available later commands. Menu display does not scan or change the computer.

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

Use the fixed [service integration](../../../docs/SERVICE_INTEGRATION.md) to bind each approved action to its exact supported adapter payload, target inventory, source/output scope and recovery evidence before an effect. No command string from imported data is executed. Official system updates/repairs are reviewed coordinator operations using actual host permissions and protected human consent; record their actual outcome and verification, not a launch or exit status alone. Read [tools and official sources](../../../docs/TOOLS.md) when a tool is needed.

Pause prevents new actions immediately; an active action reaches a safe boundary and receives its actual receipt. Preserve stopped state and all failed/partial/unknown history. Resume requires fresh reconciliation; resolve handles a specific pending decision or evidence-backed recovery and never makes a failure successful by assertion. Settings changes do not expand old approval. Schedules require their own actual host authorisation and respect paused/active/held work; configuring a proposal does not create a schedule.

## Finish and share

Explain verified changes, remaining work, real space/backup effects and any owner action in chat. Preview cleanup of toolkit work separately; required backups, quarantined originals and unresolved receipts remain protected. Default browser/history/session exclusions and secret-value protections still apply; a prior read-only exception is not deletion authority. Follow [recovery and cleanup](../../../RECOVERY_AND_CLEANUP.md).

Only exact reusable source belongs in a public export. Keep every real inventory, log, backup, download, quarantine mapping and session under excluded work/. Use [UTC publication guidance](../../../docs/UTC_PUBLICATION.md) for a separately authorised upload; public identity uses a reviewed GitHub noreply address, never a private email. The public website is documentation, not an operating portal.
