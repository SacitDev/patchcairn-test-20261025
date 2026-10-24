# Your first PatchCairn session

PatchCairn gives an AI assistant a careful maintenance workflow. You describe what you need in chat, the assistant explains evidence and choices, and local tools keep the records. **Developed by Michael.**

## 1. Download and extract the source

Get the complete source ZIP from the publishing repository or the reviewed release that provided this guide. On GitHub, the repository's **Code → Download ZIP** control downloads its source; a release may also offer a separately reviewed source package. A documentation website is a guide, not an installed maintenance app.

Extract the whole package into a local folder you control, then find the folder containing `README.md`, `AGENTS.md`, `scripts`, and `.agents`. Open that inner source folder if the archive added an outer folder. Keep `.agents` even if your file manager hides names beginning with a dot. A source-only package must not include another person's `work/` folder, reports, backups, or approvals.

| Your computer | Extract and choose a location |
| --- | --- |
| Windows | In File Explorer, select the ZIP and use **Extract All**. Choose an owner-controlled local folder with a short name and little nesting. The checked selected-file route requires a supported fixed local NTFS volume; protected system folders, shared folders, and synchronized folders are unsuitable starting points. |
| Linux | Open the ZIP in your archive manager and extract it into an owner-controlled local folder. Private records require a supported native Linux filesystem; network, FUSE, and Windows-mounted filesystems can be refused. In WSL, a native Linux filesystem and a Windows-mounted folder have different capabilities. |
| macOS | Open the ZIP in Finder and use its extracted folder in an owner-controlled local location. Private storage and native operations still require capability checks. The Mac adapters have hosted native fictional file-operation evidence; see [platform support](PLATFORM_SUPPORT.md#hosted-fixture-evidence) for the tested runner context and limits. |

Avoid shared or synchronizing locations while maintenance is in progress. Do not change permissions, remount storage, or disable a security control to make a refused location pass. See [platform notes](PLATFORM_SUPPORT.md) for the exact private-storage and native-operation limits.

On Windows, checked private/native paths have a conservative **240-character full-path limit**, including generated record names. A deeply nested source folder can therefore open the menu but hold when a session first needs records. Prefer a short source location from the start; an existing session must not be silently moved or adopted to bypass its identity checks. See the [Windows adapter](WINDOWS_ADAPTER.md).

Downloaded PowerShell scripts can also retain an Internet-origin mark. Under Windows `RemoteSigned` policy, an unsigned marked script can be blocked even after extraction. The assistant should explain the block and hold that dependent step. Do not change or bypass execution policy. After checking the actual source and code, you can separately review a trusted Git-clone acquisition or an exact owner-approved provenance-unblocking step when a documented capability requires it. Neither is automatic permission to run scripts or override a managed policy. [Microsoft explains downloaded-script policy and review before unblocking](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing).

## 2. Open the folder in a local assistant

Use an already installed assistant that can read this source folder and run supported local tools on the computer you intend to maintain. In a desktop assistant, open or add the extracted source folder as its project. With a local coding CLI, start the assistant at that folder using its publisher's normal instructions. A terminal running an assistant is different from an ordinary shell prompt: type PatchCairn requests into the assistant conversation.

If you do not yet have a suitable local assistant, use the [assistant guide](ASSISTANT_COMPATIBILITY.md#choose-the-available-host) to choose one and follow its publisher's setup instructions. Assistant installation, sign-in, subscription costs, and any Python setup are separate owner choices. PatchCairn does not install them or change their account settings for you.

Codex is the primary workflow. Claude Code, OpenCode, and other hosts need [adapter capability checks](ASSISTANT_COMPATIBILITY.md). The assistant checks actual file access, a suitable shell, web research, permission controls, and any needed independent reviewers or scheduling support. Opening a folder does not establish those capabilities. An ordinary browser chat or remote workspace cannot be assumed to reach this computer.

The portable helpers require an existing supported Python 3.12+; Windows's existing record helpers use PowerShell. A missing prerequisite is explained before dependent work. Nothing should be installed silently to make a check pass. See [platform notes](PLATFORM_SUPPORT.md) for implementation and actual validation limits.

## 3. Open the menu

Copy this into the assistant's chat:

> Read AGENTS.md and .agents/skills/pc-maintenance/SKILL.md from this project. PatchCairn: start. Show the menu and explain my choices in plain language. Wait until I select a job and authorize its scope before collecting information.

This is a **chat prompt**. Do not paste `PatchCairn: start` into PowerShell, Bash, or macOS Terminal at an ordinary shell prompt. You do not need to install a separate PatchCairn desktop app, paste a script from the internet, or edit JSON to open the menu.

The opening begins with **“PatchCairn — Developed by Michael”** and introduces these jobs:

| Job | Start here when… | First useful result |
| --- | --- | --- |
| Security updates | You want to understand updates or a reported security weakness. | A scoped assessment, official-source research, and compatibility questions. |
| Storage cleanup | You need space or want to understand selected folders. | A metadata-first picture of those folders and candidates to review. |
| Diagnosis and repair | Something failed or behaves unexpectedly. | An evidence-backed explanation, uncertainty, and the next distinguishing check. |
| Backup and recovery | You want to protect files or restore a reviewed backup. | Exact contents, exclusions, destination, verification, and recovery limits. |

A bare “Start” or `PatchCairn: start` shows the menu only. It creates no session and collects no host information. Choosing a job creates that job's record; the assistant then explains the exact scope and waits for your authorization before assessment. This does not approve installations, deletion, repairs, restores, or restarts. Natural language is welcome; ambiguous requests need clarification.

## 4. Choose how work proceeds and when it starts

**Guided** work returns to you at selected checkpoints. This gives you more opportunities to review and is a good first choice. **Automatic** work can continue routine actions within a concrete approved policy, but needs clear scope, limits, and stop conditions. Missing authority, changed facts, protected consent, or unverified required recovery still cause a hold.

Separately, choose **now** or discuss a **schedule**. A proposed time is not a created schedule. The host must support scheduling and the actual schedule needs your authorization. A trigger cannot silently resume a paused session or duplicate active work.

Checkpoints cover scope, findings, the plan, before and after actions, and the finish. A necessary restart has its own explained decision. Review these choices with `PatchCairn: settings`; changes do not widen an old approval.

## 5. Review a decision you can understand

Before asking you to choose, the assistant explains:

- **Meaning:** what the option does to the named files, software, or system item.
- **Benefits and drawbacks:** what improves and what may be affected or interrupted.
- **Cost:** known assistant usage, downloads, storage, paid tools, time, and unknowns.
- **Reversibility:** what can be undone, which recovery checks passed, and uncertain rollback.
- **Recommendation:** a practical choice supported by the evidence.

A change plan also records exact targets, official sources, compatibility, recovery requirements, verification, and restart policy. Approve a clearly identified plan or named part in ordinary language. The assistant handles the identifiers; you do not need to edit JSON or transcribe a hash.

Unchanged routine steps in that scope can continue. A new target, destructive choice, wider private access, or another material change needs a fresh explanation and the necessary decision. You handle normal sign-in and operating-system consent. Never paste a password or token into chat.

## 6. Stay informed and use the commands

| Say this in chat | Use it to… |
| --- | --- |
| `PatchCairn: help` | Understand the workflow and commands. |
| `PatchCairn: status` | See what completed, what is happening, and what needs attention. |
| `PatchCairn: options` | Review choices at this stage. |
| `PatchCairn: cost` | Request the supported estimate and its unknowns. |
| `PatchCairn: settings` | Review scope, checkpoints, control style, and timing. |
| `PatchCairn: pause` | Prevent new actions and reach a safe checkpoint for active work. |
| `PatchCairn: resume` | Reconcile actual outcomes and check freshness before continuing. |
| `PatchCairn: stop` | End further work while keeping evidence and unresolved items. |
| `PatchCairn: resolve` | Inspect a pending item and explain its required choice or evidence. |

Pause cannot safely kill every operation immediately. An installer may need to reach a safe checkpoint. Resume checks what happened; it does not blindly repeat an action. Resolve cannot declare an unknown failure fixed.

For a restart, save your work and choose timing through the normal workflow. An expected version being installed and a verified security fix are separate findings. The assistant should explain what it checked and what remains.

## 7. Finish and choose what to keep

Expect a clear separation between completed work, verified results, remaining security concerns, pending decisions, and unfinished checks. Private records and reports live under your source copy's `work/` directory. They must never appear on the public site.

If assessment answered your question and you choose no changes, ask the assistant to finish assessment only and keep the findings. An eligible session can reach assessment-only completion after all agreed assessment steps, a findings-and-limitations summary, separate evidence-coverage verification, and your actual closeout decision. Any selected finish checkpoint still needs your continue decision. This records no maintenance action in that session; it does not mean the whole computer is secure or prove that nothing else changed.

The assistant checks eligibility rather than creating a pretend action. A session with existing action-plan or operation history follows its actual closure rules. You can always ask to stop further work and preserve the findings; unfinished or deferred changes must stay explicit.

Keep the evidence and required recovery material. The current service has no general session-deletion or required-retention-release executor. The assistant checks the exact component contract before proposing housekeeping; a record helper cannot supply missing session-deletion support. If a supported cleanup path is unavailable, retain the files and explain the hold. Any supported deletion needs exact targets, sizes, and an explanation of what would be lost. Removing toolkit files does not undo updates or erase vendor/operating-system logs elsewhere. See [recovery and cleanup](../RECOVERY_AND_CLEANUP.md).

## A good first request for each job

> **Security updates:** Check the agreed installed-software metadata and official security sources. Explain what needs attention. Do not update anything before showing me the plan.

> **Storage cleanup:** Help me understand space used by folders I select. Start with metadata. Show exact candidates and recovery choices before moving or deleting anything.

> **Diagnosis and repair:** Diagnose this problem before proposing a repair: [describe what failed, what you expected, and the nonsecret error].

> **Backup and recovery:** Help me choose files for a backup. Explain contents, exclusions, destination, verification, storage cost, and restoration limits first.

See [common questions](FAQ.md), the [official tool catalog](TOOLS.md), [workflow engine](WORKFLOW_ENGINE.md), and [security contract](../SECURITY.md).

## Check the route before approving changes

The job names describe the goal; actual execution depends on the current adapters, available tools, and your exact authorization. The built-in file-content backup is capped at **16 MiB per file, 48 MiB total selected content, and 64 MiB per archive**. Current integrated update handoffs accept one exact reviewed local **MSI, PKG, or DEB** artifact up to **64 MiB**. They prepare a checked handoff for the coordinator's actual official-tool call; creating the handoff does not install anything.

Package-manager updates and OS/application repair routes remain held in the current integration. The assistant can investigate, explain a vendor-supported procedure, and describe a concrete owner-performed step. It cannot claim that guidance supplies a missing adapter, bypass the held route with an arbitrary command, or mark an unobserved change complete. Larger backups need a separately reviewed supported recovery approach. Read [the first-run boundaries](YOUR_FIRST_RUN.md#know-the-current-boundaries-before-committing) before relying on a proposed backup, cleanup, update, or repair.
