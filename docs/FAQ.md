# Frequently asked questions

## What is PatchCairn?

PatchCairn is a skillset and local working project for an AI assistant. It combines instructions, deterministic session helpers, and bounded platform tools. Operate it through chat or its local CLI; the public website explains the project. **Developed by Michael.**

## Do I need to know commands or edit JSON?

No. Use ordinary language or the `PatchCairn:` requests in your local assistant's chat, including an assistant conversation running inside a terminal. They are not PowerShell, Bash, or macOS Terminal commands at an ordinary shell prompt. The assistant explains meaning, benefits, drawbacks, cost, recovery limits, and its recommendation. It keeps technical records internally. Ask for more detail whenever it helps.

## How do I install it on Windows, Linux, or macOS?

Download and extract the complete source ZIP, then open its source folder in an already installed capable local assistant. Keep `.agents`, `AGENTS.md`, and `scripts` together. There is no separate PatchCairn desktop installer. Copy the opening prompt from [getting started](GETTING_STARTED.md#1-download-and-extract-the-source) into the assistant's chat; it opens the menu before any host collection.

The source includes platform-specific implementations for Windows, Linux, and macOS, but implementation and tested native behavior differ. Existing supported Python 3.12+ is required for PatchCairn's helpers; on Windows, the event and update-history diagnostic checks also use the built-in Windows PowerShell. The assistant checks your actual tools, permissions, and private-storage/native capabilities. Missing prerequisites are an explained setup choice, and unsupported routes remain held. See [platform support](PLATFORM_SUPPORT.md) for actual evidence rather than assuming every platform passed the same tests.

## Does Start immediately check my computer?

No. A bare “Start” or `PatchCairn: start` shows the menu only, without creating a session or collecting host information. Choosing a job creates its record. The assistant explains the selected scope and needs your actual authorization before assessment. Changes such as an update, cleanup, repair, or restore require their own concrete plan and authority.

## Which assistant should I use?

Codex is the primary workflow. Claude Code and OpenCode need adapter capability checks. Their tools, permission prompts, delegation, scheduling, and resume behavior differ. A first-message check does not prove a whole maintenance job works. Missing capabilities are explained holds. See [platform support](PLATFORM_SUPPORT.md).

## What is the difference between guided, automatic, and scheduled?

Guided work returns to you at selected checkpoints. Automatic work continues routine steps only inside a concrete approved policy. Scheduling is a separate timing choice: either style can be discussed for now or later. A schedule proposal does not create a host schedule or authorize maintenance.

For a first session, start with guided assessment now. You gain information without approving changes. Later, consider automatic work when you understand scope, stop conditions, and recovery requirements.

## Can I choose when it asks me?

Yes. Review scope, findings, plan, before-action, after-action, and finish checkpoints with `PatchCairn: settings`. The assistant still holds for changed facts, missing authority, authentication, protected consent, or unverified required recovery. A necessary restart needs its own explained decision. Removing a checkpoint cannot expand an old approval.

## Does pause immediately stop an installation?

It immediately prevents new actions. An active operation must be recorded and brought to a safe checkpoint rather than killed during a write. `PatchCairn: status` explains what remains active. `PatchCairn: resume` reconciles observed outcomes and freshness before continuing. `PatchCairn: stop` preserves evidence and unresolved work.

## What does resolve do?

`PatchCairn: resolve` examines an identified pending decision or operation and explains the evidence or bounded choice needed. It cannot turn an unknown failure into success, bypass a hold, or blindly retry a consumed action. A recovery or repair needs reviewed scope and actual verification.

## Why can an update be installed but still unfinished?

An update can be installed and still need a restart to finish. PatchCairn never restarts the computer itself, but an installer may close apps or start a restart on its own, so save your work before you approve an update. When a restart is needed, PatchCairn keeps the step open and does not run it again; until then only a backup or a read-only check can start. When you are ready, save your work, choose Restart (not Shut down), then open your assistant in the PatchCairn folder and say `PatchCairn: resume` (after `PatchCairn: stop`, say `PatchCairn: status`). PatchCairn then confirms that the computer really started again and reads the result from the package manager.

A failed check supports only a failed or partial result, with actual effects and retained recovery reviewed before a new plan. An elapsed wait or a new version string cannot replace the check after the restart. Any pause still applies to later work. After stop, that check still runs for the same open step; the session stays stopped, with no new job action. Without a later restart the step stays open, and security remediation is a separate finding.

## What if I only want findings and no changes?

Ask for the findings, remaining uncertainty, and assessment-only closeout. A successful investigation can answer your question without an update, move, deletion, or repair. For an eligible session, the assistant completes the agreed assessment stages, records a current scope-bound summary and separate verification of coverage and limitations, and records your actual closeout decision. A selected finish checkpoint still waits for you.

Completed assessment means no maintenance action was recorded in that session; it does not certify the whole computer or prove nothing else changed. Existing plan or operation history can prevent assessment-only completion. The assistant follows the actual closure rules, or you can stop further work and preserve the evidence. It must not invent an action or mark deferred changes complete to obtain the label.

## What will it cost?

Assistant usage, downloads, storage, paid products, time, and interruptions can matter. `PatchCairn: cost` uses facts available for the current plan. It states unknown prices, usage, or durations instead of inventing estimates. The project does not choose a subscription or buy a product for you.

## Will it update everything automatically?

Only concrete authorized actions proceed. “Latest” does not permit replacing an application-owned runtime, removing required versions, changing security policy, restarting without authority, or bypassing consent. The owning publisher's current tools and channel still need review. The [official tool catalog](TOOLS.md) supports investigation; it is not an installer bundle or permission grant.

Updates run through the package manager that owns the software: **winget** on Windows, **Homebrew** on macOS, and **apt** or **dnf5** (Fedora 41 or later) on Linux; a system with only dnf 4, such as RHEL 9 and its rebuilds, holds. PatchCairn reads what the manager offers, puts the exact package, version, source and command into the plan, and after your approval runs only that step, once; it is never run a second time. It does not run while PatchCairn has administrator rights: if you opened your assistant with Run as administrator or with sudo, close it and open it normally. On Linux the step runs in your own Terminal, where sudo may ask for your password. Windows Update, macOS system updates, firmware, and Python and Node packages are not updated in this version.

## Can it repair my operating system or guide me through another official tool?

It can diagnose selected symptoms, compare evidence, research official procedures, and explain a proposed repair with its risks and recovery requirements. The repairs it can run are an app update, a same-version reinstall (Homebrew on macOS, apt or dnf on Linux) and finishing an interrupted package setup on Debian and Ubuntu. It does not repair Windows itself: a DISM repair is held, and System File Checker and winget repair are guidance only. An ordinary-file ZIP is not Windows component-store, operating-system, application, or package-state rollback.

The assistant may explain a concrete official owner-performed procedure within the agreed scope. That guidance does not create a missing integrated adapter, allow an arbitrary-command fallback around a hold, or establish that a repair succeeded. Any supported coordinator action still needs its actual contract, exact plan, independent reviews, current authority, normal protected consent, and outcome verification. When the route is unavailable, expect a clear recommendation and remaining hold.

## Is an application being current the same as being safe?

No. An expected installed version is one observation. Support, advisory applicability, backported fixes, publisher-owned dependencies, and behavior need separate checks. Current software can still await a publisher's dependency fix. Unknown or unassessed scope must remain explicit.

## Why can storage assessment find duplicates without offering deletion?

Equal bytes do not prove a file is unnecessary. Applications may require separate copies, links may share storage, and selected folders may omit context. Assessment starts with metadata. Ordinary-file hashing needs appropriate scope; cleanup needs exact candidates, freshness and identity checks, authority, and a supported safe operation. In this version one cleanup handles files of at most 16 MiB each and 48 MiB in total, and frees less than 32 MiB (about 33.6 MB). See the [storage and backup reference](STORAGE_BACKUP_API.md).

## Does cleanup remove browser caches, chats, or system stores?

No. Browser history, cookies, caches, profiles, saved passwords, and chat sessions are protected. Credential stores, unrelated projects, and broad system locations are excluded. Host cleanup uses selected reviewed targets. Deleting PatchCairn's own kept backups is a separate reviewed plan that you approve by typing its exact phrase. Neither route implies a global cleaner, package autoremove, ACL bypass, or recursive-delete workaround.

## Is a ZIP backup encrypted? Does a successful backup prove I can recover?

A normal ZIP is not encrypted. Choose contents, destination, storage, and handling accordingly. Hash and entry checks establish specific archive facts. Restoration checks address whether reviewed data can be restored as intended. No backup promises every application, permission, or system setting is recoverable. Required recovery stays protected until release is explicitly justified.

A backup holds up to **100,000 selected files** and streams them into the archive. It goes to PatchCairn's private work folder or to a folder you choose on another drive. PatchCairn refuses a folder it recognises as synced by OneDrive, iCloud Drive, Dropbox or Google Drive, but that check is best effort, so do not choose a synced folder yourself. Network drives and NAS shares are refused. A USB drive, or a drive formatted exFAT or FAT32, cannot keep the backup private, so PatchCairn asks you to accept that first. PatchCairn's own restore handles archives up to **32 MiB** (about 33.6 MB) and files up to **16 MiB**; a larger backup is still written and checked, but PatchCairn cannot restore it for you or use it as the safety copy for deleting files. A larger recovery need requires a narrower selection or a separately reviewed supported approach. It does not silently exclude files, split them into automatic chunks, choose a destination for you, or label a partial archive complete.

## Does diagnosis always find the original cause?

No. It separates symptom, observed failure mechanism, possible causes, confidence, and unknowns. The mechanism may be supported while the earlier cause remains unknown. A proportionate repair can be proposed with uncertainty explained. The [diagnostic reference](DIAGNOSTIC_API.md) defines selected evidence and fixed recipes; it is not a generic command executor.

## Does it read passwords or private projects?

These are excluded from ordinary assessment, along with credential files, keychains, private browser stores, broad authentication/environment dumps, and unrelated projects. If specific private evidence is needed, the assistant explains a narrow extension before access. It must not read secrets simply to redact them afterward.

## What are the records for? Can I share them?

Private state, event history, evidence, and reports support resume and verification. They can contain computer-specific information. Share a reviewed minimal example when seeking help, not a whole session. Published source and the documentation site exclude `work/` and Git history; the site builder uses an exact list of public files. An ignore file or secret scan alone cannot prove privacy.

## Can I delete everything after a session?

PatchCairn can delete its kept backups and recovery data, for items you choose or for one finished job, through a reviewed plan that you approve by typing the exact phrase it shows, such as "delete 2 backups". The session records themselves stay; no command deletes a whole session. Do not remove the work root while operations, unresolved outcomes, or needed recovery remain. Any supported cleanup needs reviewed exact targets and consequences. Deleting records does not undo updates or erase external logs. See [recovery and cleanup](../RECOVERY_AND_CLEANUP.md).

## Does this replace security software or professional support?

It coordinates bounded assessment and approved maintenance. It is not an antivirus engine, sandbox, complete vulnerability discovery, or guarantee of risk-free repair. Permissions, platform capabilities, official tools, and current evidence matter. [Security guidance](../SECURITY.md) and [platform support](PLATFORM_SUPPORT.md) preserve exact limits.

## Can I host the documentation with GitHub Pages?

Yes. Build the allowlisted site with `scripts/build_site.py` and review the output. The included Pages workflow runs manually from the default branch and publishes only generated `work/site/github-pages` contents. The site needs no API key, external fonts, trackers, or live session. Its fixed self-hosted JavaScript is limited to visual effects and interaction cues, and its guides remain readable without it. Its optional repository link comes from the chosen repository during publication. See [GitHub setup](GITHUB_SETUP.md) and [UTC publication](UTC_PUBLICATION.md) before uploading or changing Git metadata.
