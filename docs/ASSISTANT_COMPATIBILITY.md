# Use PatchCairn with an AI assistant

PatchCairn runs through a capable local assistant's chat and documented local helper interfaces. Download and extract a source copy into a folder you control, open it as the assistant's project, load the project instructions, and begin with the menu. The [setup guide](GETTING_STARTED.md#1-download-and-extract-the-source) covers Windows, Linux, and macOS extraction and folder selection. The public website explains the toolkit; it does not control a computer or hold private session records.

The assistant supplies the conversation and coordinates available tools. PatchCairn supplies the shared rules, job skills, deterministic conversation helpers, and operation gates. An instruction file cannot grant OS privileges, add missing tools, guarantee a model's behavior, or make a cloud session able to reach a local computer.

The portable startup route is to read the included project files explicitly, beginning with `AGENTS.md` and `.agents/skills/pc-maintenance/SKILL.md`. Codex's native automatic skill discovery is a useful optional integration; the explicit-read route does not depend on a selector entry. You do not need to copy skills into global configuration, install an API SDK, or obtain an API key to use this toolkit's local helpers. Your chosen assistant can still have its own normal sign-in, access, and usage requirements.

## Begin with the menu

Use this prompt in a new chat opened at the source folder:

> Read AGENTS.md and .agents/skills/pc-maintenance/SKILL.md from this project. Use the current workflow engine to show the PatchCairn first menu. Explain the four jobs, guided or automatic control, now or scheduled timing, selectable checkpoints, costs and privacy limits in plain language. Show every PatchCairn command. Do not collect host information or make changes until I select and authorize the scope.

The menu begins **PatchCairn — Developed by Michael**. Choose security and updates, storage assessment and cleanup, diagnosis and repair, or backup and recovery. Guided/automatic control and now/scheduled timing are independent choices. An automatic setting can continue only under actual bounded authorization; a scheduled setting is a proposal until an available scheduler and its exact action are approved.

If the host cannot load the menu, an existing supported Python 3.12+ installation can display it from the source root:

```text
python -I -S -B scripts/patchcairn_workflow.py
```

With no arguments this displays the public menu without creating a session or collecting host information. It gives the person a useful starting point; further operations still need a capable coordinator and actual scope approval. If Python is missing, read the public choices in chat and leave helper calls held. See the [workflow engine guide](WORKFLOW_ENGINE.md) before using session commands.

Use `PatchCairn: start`, `PatchCairn: help`, `PatchCairn: status`, `PatchCairn: options`, `PatchCairn: cost`, `PatchCairn: settings`, `PatchCairn: pause`, `PatchCairn: resume`, `PatchCairn: stop`, and `PatchCairn: resolve`. The host's `/help`, `/resume`, and other slash commands keep their normal meaning. A host resume command reopens a conversation; `PatchCairn: resume` reconciles PatchCairn's recorded work and freshness before more actions. Neither creates approval.

Type these requests into the assistant conversation. An assistant CLI can display that conversation inside a terminal, but an ordinary PowerShell, Bash, or macOS Terminal shell prompt cannot interpret `PatchCairn: start`. The Python command above is a real shell command for the menu only; later workflow actions use their documented interfaces and gates.

## Choose the available host

Install or update an assistant only if you choose to, using its publisher's current instructions. Sign in through that assistant's normal interface. PatchCairn does not install hosts, alter account settings, obtain keys, inspect saved credentials, or copy private configuration as setup.

| Host | Load the public instructions | Practical fallback |
| --- | --- | --- |
| Codex desktop | Open the extracted source as the project. Ask it to read AGENTS.md and use the pc-maintenance skill. Repository skills live in `.agents/skills`. | If the skill is absent from the selector, name its exact project file in chat. Check local file/command and web tools before assessment. A cloud workspace cannot be assumed to access this computer. |
| Codex CLI | Start Codex at the source root, then use the same opening prompt. Codex documents project AGENTS.md discovery and repository `.agents/skills` discovery. | Read the installed CLI help before choosing permission, sandbox, or noninteractive flags. An ephemeral CLI session concerns host conversation storage, not PatchCairn's durable records under `work/`. |
| Claude Code | Start at the source root. `CLAUDE.md` imports `@AGENTS.md` and routes requests to the canonical `.agents/skills` files. | Ask it to read the selected skill by exact path. Claude documents `.claude/skills` discovery; this package does not require a copied skill tree, global setting, hook, or plugin. |
| OpenCode | Start at the source root and load AGENTS.md. Inspect the installed release and its matching rules, skills, and permission documentation. | The publisher's release-specific documentation describes `.agents/skills` compatibility; permission schemas differ between releases. If discovery fails, explicitly load the router and selected job files. Do not paste a configuration example for a different installed release. |
| Grok Build CLI | First check that the installed `grok` help identifies the intended product. Load the public rules and selected skill explicitly unless that version's documentation establishes discovery. | Use chat guidance only when tools or controls are missing. A product name containing “Build” is not an instruction to run a build, install software, or start a coding workflow. |
| Other coding or chat hosts | Supply AGENTS.md, the router, and only the relevant public job skill using the host's supported attachment or file mechanism. | The assistant can explain the menu and prepare a plan. If it cannot run the documented backend, keep actions held and transfer the reviewed task to a supported local host. Do not pretend a chat attachment grants local execution. |

Codex's official documentation describes [project instructions](https://learn.chatgpt.com/docs/agent-configuration/agents-md) and [local skill discovery](https://learn.chatgpt.com/docs/build-skills). See the publisher's [CLI reference](https://learn.chatgpt.com/docs/developer-commands?surface=cli) for installed-version checks before choosing flags.

Claude Code documents [CLAUDE.md and AGENTS.md loading](https://code.claude.com/docs/en/memory), including the `@AGENTS.md` import, and its [skill locations](https://code.claude.com/docs/en/skills). A project CLAUDE.md can change automatic AGENTS.md loading, which is why this adapter imports the shared agreement directly.

OpenCode's [rules documentation](https://docs.opencode.ai/docs/rules/), [skill documentation](https://docs.opencode.ai/docs/skills/), and [additional release's skill documentation](https://opencode.ai/v2/docs/skills) describe host-specific discovery. Match the installed release to its [corresponding permission documentation](https://docs.opencode.ai/docs/permissions/) or [additional release's permission documentation](https://opencode.ai/v2/docs/permissions). These are the assistant publisher's release differences, not PatchCairn product choices. Grok's publisher describes its TUI and headless interfaces in the [Grok Build overview](https://docs.x.ai/build/overview).

## Check capabilities before work

PatchCairn ships no host adapter descriptor, and nothing it saves is a launcher, a saved approval, an executable command list, or evidence that a host is installed. Detect capabilities again in each actual session without reading credentials or dumping configuration.

| Capability | Required check and fallback |
| --- | --- |
| Public instruction access | Confirm the source copy, shared agreement, router, selected job, and current helper API can be read. If not, supply the needed public files through a supported interface and keep operations held. |
| Local helpers | Verify the executing platform, documented backend, supported PowerShell or Python 3.12+, selected filesystem/native capabilities, and write access to owned `work/`. Missing prerequisites are an owner setup choice; never install them silently. |
| Web research | Use available official-source search/fetch tools for current vendor facts. Without research access, preserve uncertainty and defer source-dependent recommendations or changes. |
| Independent reviewers | Confirm two distinct independent reviewers can assess the concrete plan's compatibility/data safety and evidence/security correctness. If unavailable, finish useful authorized assessment and hold changes. A host's ability to create a second conversation is not proof of independent review. |
| Native UI | Use a current host computer-use skill and a supported native UI tool only when necessary and available. Otherwise explain the exact owner-performed step or hold. CLI access alone does not provide a GUI. |
| Scheduling | Confirm a supported scheduler, user scope, exact trigger/action, duplicate prevention, authority, pause handling and durable receipts. Without them, retain a schedule proposal and let the person start the task later. No host is promised universal unattended maintenance. |
| Cost and limits | Report known plan costs and host-reported usage separately. Subscription access does not establish remaining quota, token count, a future price, or a precise run estimate. Unknown values stay unknown. |
| Authentication or protected consent | The person handles the host's normal sign-in and OS consent. A missing login, quota failure, inaccessible path, or denied tool is a hold, not a reason to bypass a boundary. |

Keep generated sessions, reports, fixtures and probe receipts under owned `work/` paths. Hosts and operating systems can also keep their own caches, telemetry or account records outside that directory; deleting PatchCairn work does not erase those records or reverse completed changes. Source sharing excludes `work/` and private host state.

## What compatibility checks establish

Startup checks compare a first synthetic response with the public menu contract. They do not establish safe execution of a maintenance job, OS isolation, independent review quality, successful recovery, or universal provider compatibility.

For an explicitly authorized check, use only a small fixture containing the current public menu and necessary public skills. Use fictional references and no installed-software inventory, private source, credentials, real logs, or past chats. Require documented tool-disable, one-turn, no-session-persistence and output-token or spending-limit controls before sending a prompt. Disable external tools and customizations through supported controls. Never use a permission-bypass flag. If a required control is absent or uncertain, record a skipped check. Stop on missing login or quota; do not retry through another account or API key.

At most two startup prompts per tested CLI are allowed in this build, with one preferred when sufficient. Preserve the configured model unless the owner requests another. Capture output privately, sanitize accounts, emails, machine paths and credential-like content before reporting, and record exact invocation controls, prompt/context hashes, completion category, reported usage and unknowns. A client spending limit may be an estimate and can overshoot one request; it is not a promise of an exact bill. Claude documents that limitation alongside its [print, tools, persistence, turns and budget controls](https://code.claude.com/docs/en/cli-reference), and documents a process-local output-token cap in its [environment-variable reference](https://code.claude.com/docs/en/env-vars).

The build's actual discovered versions, presence/absence results and sanitized receipts remain private under `work/upgrade_v3/host_compatibility`; this public guide makes no claim that any named host is installed on the reader's computer or that an unexecuted check passed.
