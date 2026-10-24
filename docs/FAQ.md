# Frequently asked questions

## What is PatchCairn?

PatchCairn is a skillset and local working project for an AI assistant. It combines instructions, deterministic session helpers, and bounded platform tools. Operate it through chat or its local CLI; the public website explains the project. **Developed by Michael.**

## Do I need to know commands or edit JSON?

No. Use ordinary language or the `PatchCairn:` requests in your local assistant's chat, including an assistant conversation running inside a terminal. They are not PowerShell, Bash, or macOS Terminal commands at an ordinary shell prompt. The assistant explains meaning, benefits, drawbacks, cost, recovery limits, and its recommendation. It keeps technical records internally. Ask for more detail whenever it helps.

## How do I install it on Windows, Linux, or macOS?

Download and extract the complete source ZIP, then open its source folder in an already installed capable local assistant. Keep `.agents`, `AGENTS.md`, and `scripts` together. There is no separate PatchCairn desktop installer. Copy the opening prompt from [getting started](GETTING_STARTED.md#1-download-and-extract-the-source) into the assistant's chat; it opens the menu before any host collection.

The source includes platform-specific implementations for Windows, Linux, and macOS, but implementation and tested native behavior differ. Existing supported Python 3.12+ is required for portable helpers; Windows's assessment-record helpers use PowerShell. The assistant checks your actual tools, permissions, and private-storage/native capabilities. Missing prerequisites are an explained setup choice, and unsupported routes remain held. See [platform support](PLATFORM_SUPPORT.md) for actual evidence rather than assuming every platform passed the same tests.

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

## Why can a Windows update be installed but still unfinished?

The supported MSI installer can return code 3010: installation completed and a restart is still needed. PatchCairn preserves that original result and the same unfinished operation. You choose whether to defer or separately authorize the exact owner-handled restart after saving your work. It does not restart Windows or run the installer again automatically.

Afterward, the assistant needs actual evidence of the boot transition, selected installation, and original behavior. Success requires the reviewed target and all behavior checks to pass. A failed check supports only a failed or partial result, with actual effects and retained recovery reviewed before a new plan. Update approval, an elapsed wait, or a new version string cannot replace those checks. Any pause still applies to later work. After stop, you may still defer or authorize only the owner-handled restart needed to account for that same retained unfinished operation; the session stays stopped, with no new job action. Missing decision or boot evidence leaves it unfinished, and security remediation is a separate finding.

## What if I only want findings and no changes?

Ask for the findings, remaining uncertainty, and assessment-only closeout. A successful investigation can answer your question without an update, move, deletion, or repair. For an eligible session, the assistant completes the agreed assessment stages, records a current scope-bound summary and separate verification of coverage and limitations, and records your actual closeout decision. A selected finish checkpoint still waits for you.

Completed assessment means no maintenance action was recorded in that session; it does not certify the whole computer or prove nothing else changed. Existing plan or operation history can prevent assessment-only completion. The assistant follows the actual closure rules, or you can stop further work and preserve the evidence. It must not invent an action or mark deferred changes complete to obtain the label.

## What will it cost?

Assistant usage, downloads, storage, paid products, time, and interruptions can matter. `PatchCairn: cost` uses facts available for the current plan. It states unknown prices, usage, or durations instead of inventing estimates. The project does not choose a subscription or buy a product for you.

## Will it update everything automatically?

Only concrete authorized actions proceed. “Latest” does not permit replacing an application-owned runtime, removing required versions, changing security policy, restarting without authority, or bypassing consent. The owning publisher's current tools and channel still need review. The [official tool catalog](TOOLS.md) supports investigation; it is not an installer bundle or permission grant.

Current integrated updates are exact reviewed local MSI, PKG, or DEB handoffs, each limited to a **64 MiB artifact** and the documented fixed arguments. Package-manager update routes remain held because their current integration cannot force the transaction to consume the exact reviewed bytes. A handoff records the approved action for the coordinator's actual official-tool call; it does not itself install a package.

## Can it repair my operating system or guide me through another official tool?

It can diagnose selected symptoms, compare evidence, research official procedures, and explain a proposed repair with its risks and recovery requirements. The current integrated OS/application repair routes remain held until component-specific recovery is supported. An ordinary-file ZIP is not Windows component-store, operating-system, application, or package-state rollback.

The assistant may explain a concrete official owner-performed procedure within the agreed scope. That guidance does not create a missing integrated adapter, allow an arbitrary-command fallback around a hold, or establish that a repair succeeded. Any supported coordinator action still needs its actual contract, exact plan, independent reviews, current authority, normal protected consent, and outcome verification. When the route is unavailable, expect a clear recommendation and remaining hold.

## Is an application being current the same as being safe?

No. An expected installed version is one observation. Support, advisory applicability, backported fixes, publisher-owned dependencies, and behavior need separate checks. Current software can still await a publisher's dependency fix. Unknown or unassessed scope must remain explicit.

## Why can storage assessment find duplicates without offering deletion?

Equal bytes do not prove a file is unnecessary. Applications may require separate copies, links may share storage, and selected folders may omit context. Assessment starts with metadata. Ordinary-file hashing needs appropriate scope; cleanup needs exact candidates, freshness and identity checks, authority, and a supported safe operation. See the [storage and backup reference](STORAGE_BACKUP_API.md).

## Does cleanup remove browser caches, chats, or system stores?

No. Browser history, cookies, caches, profiles, saved passwords, and chat sessions are protected. Credential stores, unrelated projects, and broad system locations are excluded. Host cleanup uses selected reviewed targets. Toolkit housekeeping follows the matching record-family contract; assessment-record run-cleanup helpers cannot delete conversation sessions. Neither route implies a global cleaner, package autoremove, ACL bypass, or recursive-delete workaround.

## Is a ZIP backup encrypted? Does a successful backup prove I can recover?

A normal ZIP is not encrypted. Choose contents, destination, storage, and handling accordingly. Hash and entry checks establish specific archive facts. Restoration checks address whether reviewed data can be restored as intended. No backup promises every application, permission, or system setting is recoverable. Required recovery stays protected until release is explicitly justified.

The built-in route supports selected ordinary-file contents up to **16 MiB per file, 48 MiB total selected content, and 64 MiB per archive**. A larger recovery need requires a narrower selection or a separately reviewed supported approach. It does not silently exclude oversized files, split them into automatic chunks, choose an external destination, or label a partial archive complete.

## Does diagnosis always find the original cause?

No. It separates symptom, observed failure mechanism, possible causes, confidence, and unknowns. The mechanism may be supported while the earlier cause remains unknown. A proportionate repair can be proposed with uncertainty explained. The [diagnostic reference](DIAGNOSTIC_API.md) defines selected evidence and fixed recipes; it is not a generic command executor.

## Does it read passwords or private projects?

These are excluded from ordinary assessment, along with credential files, keychains, private browser stores, broad authentication/environment dumps, and unrelated projects. If specific private evidence is needed, the assistant explains a narrow extension before access. It must not read secrets simply to redact them afterward.

## What are the records for? Can I share them?

Private state, event history, evidence, and reports support resume and verification. They can contain computer-specific information. Share a reviewed minimal example when seeking help, not a whole run. Source export and the documentation site use exact public file lists and exclude `work/` and Git history. An ignore file or secret scan alone cannot prove privacy.

## Can I delete everything after a session?

The current service has no general session-deletion or required-retention-release executor. Keep its records and required recovery material when no supported cleanup path exists. The assistant matches housekeeping to the exact component that created the files; another helper's cleanup route cannot authorize deleting a conversation session. Do not remove the work root while operations, unresolved outcomes, or needed recovery remain. Any supported cleanup needs reviewed exact targets and consequences. Deleting records does not undo updates or erase external logs. See [recovery and cleanup](../RECOVERY_AND_CLEANUP.md).

## Does this replace security software or professional support?

It coordinates bounded assessment and approved maintenance. It is not an antivirus engine, sandbox, complete vulnerability discovery, or guarantee of risk-free repair. Permissions, platform capabilities, official tools, and current evidence matter. [Security guidance](../SECURITY.md) and [platform support](PLATFORM_SUPPORT.md) preserve exact limits.

## Can I host the documentation with GitHub Pages?

Yes. Build the allowlisted site with `scripts/build_site.py` and review the output. The included Pages workflow runs manually from the default branch and publishes only generated `work/site/github-pages` contents. The site needs no API key, external fonts, trackers, or live session. Its fixed self-hosted JavaScript is limited to visual effects and interaction cues, and its guides remain readable without it. Its optional repository link comes from the chosen repository during publication. See [GitHub setup](GITHUB_SETUP.md) and [UTC publication](UTC_PUBLICATION.md) before uploading or changing Git metadata.
