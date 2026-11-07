# Security and update workflow

This procedure serves `pc-security-updates`. It is reusable guidance, not a live inventory, advisory verdict or authorization. Use [communication](COMMUNICATION.md), [sources](SOURCES_AND_RESEARCH.md), [compatibility](COMPATIBILITY.md) and the [service contract](../docs/SERVICE_INTEGRATION.md) for their detailed contracts.

## Start and define the boundary

Use the current conversation engine interface and `security_updates` job. The engine owns the first menu and the commands `PatchCairn: start`, `help`, `status`, `options`, `cost`, `settings`, `pause`, `resume`, `stop`, and `resolve`; present their full names as `PatchCairn: <command>`, without replacing host slash commands. Natural language can select a known command; resolve ambiguous scope before acting. A bare Start opens only the menu, without session creation or host collection. An explicit assessment permits only its agreed read-only scope; session creation alone permits no collection.

Record the agreed computer/scope, exclusions, control style, timing and selectable checkpoints. Automatic control can continue only a concrete authorized scope with required gates; scheduling stores a proposal until separate authority creates a host schedule. Settings changes cannot broaden an earlier approval. Keep JSON and action bookkeeping with the assistant, not the owner.

Establish the real platform, architecture, supported backend/runtime and available research, shell/API, file, review and UI capabilities. Read the [current engine documentation](../docs/WORKFLOW_ENGINE.md) and [service contract](../docs/SERVICE_INTEGRATION.md). A missing native adapter, package route, supported runtime, independent review or OS permission is a capability hold. Do not imply a fixture or role name certifies host support. Begin each new PowerShell session with `$env:TZ='UTC'`; leave the OS time zone unchanged.

Create fresh appropriately scoped real records only for actual authorized work. Preserve session identity; never promote fixtures or import another owner's inventory/approval. Register evidence through the engine evidence API, with actual hash, observation UTC-Z, scope and limits. Reports are derived views, not another authority.

## Build a usable installation map

For each selected component establish product/publisher, observed version/build, architecture, package identity, installation scope, actual owner/updater, channel/support branch and observation time. Separate machine, user, portable, project and application-bundled installations; record unresolved ownership rather than guessing from a name, PATH entry or catalogue match. Inventory adapters cover selected metadata, not every dependency. Do not use `Win32_Product`, execute unknown launchers, crawl private projects or dump environment/authentication files.

Map consumer requirements when relevant within approved scope. Preserve required Python/Node/Java/.NET/VC++ families, virtual environments, manager prefixes and side-by-side architectures. For an application bundle, propose its publisher's update; a global runtime update does not fix its private runtime. A project pin is a compatibility constraint, not permission to open private lockfiles or rewrite the project. Unknown consumers can justify a hold or separate scoped check; they do not justify deleting the older copy.

## Research applicability and choose a target

Use current primary publisher release notes, lifecycle policy, security advisories and distribution notices. Check relevant vendor security news and official exploitation/incident alerts as well as advisory databases; third-party reporting is a discovery lead. Public queries contain public product/error identifiers, never raw logs, local paths, hostnames, account data or private package names.

For each advisory candidate record affected product/branch/range, fixed build or vendor backport, architecture/platform, required feature/exposure, support status, exploitation claim/source/date and the local facts that establish or prevent applicability. Use applicable, not applicable with reason, conditional/unknown, or not assessed. An old upstream version in a distro package may contain backported fixes; no update offer or published CVE does not prove safety. Keep availability, support, compatibility, applicability and actual remediation separate.

Record source ID, title, requested/final URL, publisher ownership, accessed UTC-Z, publication/revision date if available, claim supported and access limitation. News receipts distinguish publication date from event date. An inaccessible advisory leaves an explicit gap; a landing page is not its contents. Revalidate changing facts before action.

Choose a supported compatible stable/LTS target in the correct owner/channel/architecture, not the numerically newest release. Check OS requirements, dependencies, plug-ins, data/configuration migration, licensing/entitlement, known issues and restart needs. OS release transitions, firmware/BIOS, removal, new paid entitlement or channel migration require explicit scoped decisions.

## Make changes concrete and reviewable

Create immutable plan bytes through the documented API. Every action needs:

| Plan element | Required detail |
| --- | --- |
| Identity and intent | Action ID; exact installed copy/owner/scope/current version; chosen target/channel/architecture; reason and supported advisory claim where relevant. |
| Provenance and operation | Official HTTPS source and ownership/redirect chain; exact package/installer identity; staged artifact hash; expected publisher/signature or documented signed-integrity procedure; precise documented command/API/UI steps and privilege. Bind the fixed adapter, canonical payload, lower-level service plan and target inventory hashes required by the current engine contract. The approval for one plan must not gate a different service action. Never evaluate a command field from data. |
| Preconditions and effects | Fresh identity/version/locks/active transactions; dependencies; available resources; running-app/data effects; app closure; expected OS/vendor writes; source/integrity checks immediately before use. |
| Recovery and interruption | Verified recovery when required, its actual location/identity and limits; owner work-saving decision; restart policy; safe checkpoints; failure stop conditions. A proposed backup or restore point is not verified recovery. |
| Evidence and success | Baseline/evidence IDs; installed and loaded/active result; behavior check; specific fixed-build/backport/security criterion; remaining unknowns and postrestart checks. |

Use official signed distribution where supplied. Windows verification distinguishes embedded/catalog signatures and the expected signer; other platforms follow the vendor's signed package/checksum/provenance procedure. A self-calculated hash identifies bytes, not authorship. HTTPS, a catalogue match, notarization or a valid unrelated signer is insufficient. Unavailable or failed required verification holds the action; never bypass it. Stage toolkit-requested downloads under `work/`; do not download/install tools merely to complete an assessment.

For integrated updates, use the service's built package routes: winget on Windows, Homebrew on macOS, and apt or dnf on Linux. `discover_packages` reads what the manager offers through fixed read-only commands; `prepare_package_action` binds the exact package, version, source, dependencies and command into the action. After approval, `execute_action` returns a one-use ticket, and only `scripts/patchcairn_service.py run --ticket <ticket>` runs that step: it checks the binding and the offer again, starts exactly the bound command without a shell, and refuses to run while PatchCairn has administrator rights. A terminal step (apt, dnf) is pasted by the owner into their own Terminal, where sudo may ask for a password. No extra flags, force or substitute packages. See [tool/source pairs and access limits](../docs/TOOLS.md).

A changed offer, an unknown manager or a route that is not built holds without a weaker executor; Windows Update, macOS system updates, firmware, Python and Node packages hold in this version. A package's scripts, dependency/state effects and restart needs still need review and actual verification. Ordinary-file ZIP recovery does not establish OS/package-state rollback.

The coordinator selects bounded work for these roles:

| Role | Security/update contribution |
| --- | --- |
| Matching platform specialist | Installation ownership, channel, architecture, native constraints and dependency map. |
| Security/release researcher | Primary advisories, relevant vendor news, support/fixed-branch evidence, provenance and uncertainty. |
| Independent adversarial reviewer A | Challenge compatible target, pinned/bundled consumers, data continuity, closure/restart and recovery. |
| Independent adversarial reviewer B | Challenge applicability, signed source, exact action/scope, privacy, injection and unsupported security claims. |
| Verifier/evidence curator | Fresh result evidence, receipt limits and parity of session records and the report view. |

One coordinator owns mutations, UI and canonical writes. Specialists return uniquely identified bounded results; the coordinator records originals sequentially. Use the engine evidence-registration API with actual result bytes, scope and UTC observation, and the service/diagnostic methods for their separately bound records. Do not insert unregistered files or mix these stores. Both adversarial reviewers independently inspect the same immutable plan/evidence before seeing each other's verdict. Missing review is a hold; two self-written perspectives are not independent. Resolve material blockers and retain dissent.

Explain the named plan or subset in chat: practical purpose, recommendation and alternatives, benefits, drawbacks, known/unknown money, download/storage needs and time/downtime, privacy/external effects, reversibility and unfinished risks. Use measured facts for estimates; say unknown when unavailable. Record the actual owner's instruction and message reference against exact action IDs and plan SHA-256 through the current engine approval interface. A review pass, `approved=true`, mode selection, schedule trigger or silence grants no authority. Preserve already-valid consent for unchanged routine actions.

## Execute, pause and verify

Immediately before mutation, refresh material preconditions and the approved artifact/target. Obtain the engine's durable begin-operation receipt for that exact action/plan/evidence; only then run the step through its ticket. Engine records are not an arbitrary executor or OS sandbox. One active installer, servicing transaction or protected prompt at a time. Do not use blanket upgrade-all, pin/hash overrides, force, undocumented switches, manual bundle swaps or security-policy changes.

Explain normal authentication/UAC/Touch ID and let the owner complete it without collecting secrets. Give a concrete handoff if UI/elevation is unavailable. Stop on source drift, mismatch, refusal, lock, cleanup warning, unexpected restart/preservation behavior or partial/unknown result. Keep safe selected output, side effects and receipts. A consumed action is not retried automatically; a new supported recovery proposal needs reconciled evidence and its own appropriate review/consent.

`PatchCairn: pause` blocks new work immediately. Bring an active operation to its safe receipt/checkpoint without killing it. Before restart/process interruption record completed/consumed actions, active-operation identity, actual result, pending verification, required recovery and next owner step. Restarts and forced application closure are never inferred. On resume reconcile the same session against fresh installation/boot/receipt evidence; unknown outcomes remain held. `resolve` addresses a named pending item with evidence or a bounded decision, never asserts an unobserved fix. Stop preserves unresolved state and evidence.

When a step's route reports that a restart is needed (a reboot-required file, a manager's restart check, the Windows reboot-pending keys or an installer's exit code), the engine keeps that step open and does not run it again; only a backup can start meanwhile. PatchCairn never restarts the computer or schedules a restart: the owner restarts when ready. A signal read again from the same place can clear it; a signal from an exit code ends only with a restart. After the restart, run the check after the restart, the same launcher command, which `scripts/patchcairn_service.py inspect-operation <session> <operation>` prints: it records a boot later than the step and then reads the result. A stopped session keeps this check for its open step and gains no new plan, action or ticket. Do not rerun the step or clear pause/stop.

Finish operation records truthfully, then verify actual installation identity/version and active/loaded state, relevant behavior and the specific security criterion separately after required restarts. An installer exit, download, version string or empty update queue alone is insufficient. Report verified updates, already-current installations, pending activation/restart, failed/partial actions, vendor-managed dependencies, compatibility holds and unknown/unassessed scope. Close an assessment with holds honestly; do not mark deferred actions completed for cleanup. Offer only separate approved owned-artifact cleanup under [recovery and cleanup](../RECOVERY_AND_CLEANUP.md).

For an eligible assessment-only conversation session, use the engine's `complete_assessment` contract after every agreed assessment stage and prior checkpoint has finished. It requires current scope authority, current schedule activation when applicable, no operation history/plan/approval/reviews/standing policy, an owned typed findings-and-limitations summary, separate fresh verification of its exact hash/evidence coverage, and the actual owner's closeout instruction. A selected finish checkpoint still waits for the owner's continue decision. This records no maintenance action in that session; it is not an all-secure or computer-unchanged finding. An ineligible or unfinished session can be stopped with findings preserved. Never manufacture a plan or action to obtain completed status.
