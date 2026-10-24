# Compatibility and safe change decisions

This guide explains how to choose and verify a maintenance action; it is not a prescription to replace every older-looking component.
Use current primary sources in [SOURCES_AND_RESEARCH.md](SOURCES_AND_RESEARCH.md), and retain the owner's approved scope and exclusions.
No current target versions, real host inventory, or private diagnostic records belong in this public document.

## 1. Identify the installation before touching it

Record product, publisher, architecture, package type, installation scope, update channel, owner, support branch, and observed version.
Distinguish system-wide software, per-user software, portable tools, project environments, and application-bundled components.
Use approved helpers and selected metadata; do not run arbitrary programs found on PATH or crawl application/user folders to discover more.
Do not query Win32_Product: Microsoft documents that inventory queries can trigger MSI consistency checks and repair. [Inventory reference](https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations)
Registry inventory, Store package metadata, WinGet matches, and executable versions each cover different subsets; none alone proves a complete inventory.
When two records disagree, preserve both observations with timestamps and determine which installation each describes.

## 2. Choose the supported channel

Prefer the existing supported stable or LTS channel unless the owner explicitly chooses a different channel for a documented reason.
The newest feature release, preview, alpha, or beta is not automatically the safest replacement for a supported production release.
Check OS support, architecture, license eligibility, device model when relevant, and the application's compatibility requirements.
Do not silently convert a paid installation, remove an older runtime, change a vendor, or migrate an application to another packaging channel.
Existing authorization can cover routine updates within the agreed plan; a materially different migration, license, restart, firmware change, or data-loss risk needs a new owner decision.
Vendor support ending is a maintenance problem to report; it does not authorize breaking the dependent application.

## 3. Treat multiple runtimes as dependencies

| Family | Why several copies can be legitimate | Safe maintenance decision |
| --- | --- | --- |
| Python | Different projects, interpreter branches, free-threaded builds, managers, and bundled distributions. | Identify the owner and project requirement. Update that installation through its supported manager; test a replacement environment before retiring a required interpreter. |
| Python environments | Each environment has its own interpreter relationship and packages. | A global Python or pip update does not update every environment. Recreate an approved environment from reviewed requirements/lock data and test it; do not copy interpreter files into it. |
| uv-managed Python | uv can select its own managed interpreter or use an external one. | Use uv's documented management model after confirming ownership and pinning. Updating uv itself does not prove all interpreters or projects were migrated. |
| Node.js and npm | Machine MSI, user managers, portable tools, and app bundles can select different copies. | Check the supported Node channel and npm compatibility. Verify the intended executable and ordinary-shell resolution after updating; do not hand-edit MSI-owned shims or flatten all prefixes. |
| Java | A JDK, application JRE, IDE bundle, and multiple vendors/majors can coexist. | Select a supported compatible vendor/channel and check licensing. Validate dependent applications and effective JAVA_HOME/PATH behavior before removing an older installation. |
| Modern .NET | SDKs and Runtime, Desktop, or ASP.NET runtimes can coexist by major family and architecture. | Patch the required families. Adding a newer major does not guarantee that an application targeting an older major will use it. |
| Self-contained .NET | An application may ship a private runtime. | Update through the application publisher; a system runtime update does not patch the private copy. |
| .NET Framework | Windows and older applications depend on Framework components under different servicing rules from modern .NET. | Use the documented Windows/Framework servicing route; do not remove a Windows component as if it were an obsolete standalone .NET SDK. |
| Visual C++ runtimes | Applications target particular runtime families and architectures. | Match the application's architecture, including x86 applications on x64 Windows. Keep older required families unless their dependents have been addressed. |
| PowerShell | Windows PowerShell and newer PowerShell can coexist and have different module compatibility. | Update each through its supported channel. Do not replace Windows PowerShell files or assume every script/module supports the newer host. |
| App/IDE/agent bundles | Vendors may pin Python, Node, Java, Git, Electron, or other dependencies internally. | Update the owning application. Record unresolved vendor dependency exposure; never hot-swap files inside its signed distribution. |
| WSL and containers | Windows integration, Linux distribution packages, container images, and persistent data are distinct. | Follow the relevant platform guide and owner decisions. Updating the host does not update every image or distribution; never use reset/unregister as an update shortcut. |

Python's documentation describes environment isolation and recreation, and uv documents managed versus external interpreters. [Python Windows](https://docs.python.org/3/using/windows.html), [venv](https://docs.python.org/3/library/venv.html), [uv versions](https://docs.astral.sh/uv/concepts/python-versions/)
For Node.js, choose the supported production channel from the live release policy rather than assuming the largest major is preferable. [Node.js releases](https://nodejs.org/en/about/previous-releases)
Java support and licensing depend on vendor, release, use, and entitlement; verify the intended distribution before proposing replacement. [Oracle roadmap](https://www.oracle.com/java/technologies/java-se-support-roadmap.html)
Modern .NET selection and self-contained deployment have distinct rules. [Installation](https://learn.microsoft.com/en-us/dotnet/core/install/windows), [version selection](https://learn.microsoft.com/en-us/dotnet/core/versions/selection), [Framework](https://learn.microsoft.com/en-us/dotnet/framework/install/versions-and-dependencies)
Use the application vendor's instructions for VC++ remediation and preserve required families/architectures. [Microsoft VC++ reference](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)
Windows PowerShell remains alongside PowerShell; module compatibility must be checked. [Microsoft PowerShell installation](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows)

## 4. Make an action reviewable

Before changing an item, document the expected benefit, exact installation, authoritative source, target channel, expected app impact, restart behavior, verification, and recovery limits.
For a routine authorized update, stage and verify the actual installer before execution; source research alone does not verify the downloaded bytes.
Use exact product/package identity and the intended source, scope, and architecture. A WinGet match is useful evidence, not automatic proof that the chosen package is the correct variant.
Avoid blanket upgrade-all operations, unknown-version upgrades, pin overrides, uninstall-previous, force flags, hash bypasses, or undocumented installer switches.
Read [WinGet upgrade semantics](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade) for the available options; this toolkit deliberately takes the narrower action justified by its approved plan.

Prefer a supported in-place patch to an unnecessary uninstall/reinstall.
If side-by-side installation is supported and helps preserve compatibility, test the new copy before deciding whether the older copy is removable.
Never claim rollback is guaranteed: some installers, OS repairs, databases, and configuration migrations cannot be safely downgraded.
Have a verified recovery route appropriate to the change; a restore point alone is not a backup of all personal files or application data.

## 5. Respect running work and restart boundaries

Keep one coordinated writer for a shared package manager, runtime prefix, or Windows servicing operation.
Research and evidence review can run in parallel; conflicting installations, repairs, and cleanup cannot.
Do not force-close applications, terminate servicing, suppress security controls, or bypass locked-file protections to accelerate an update.
If an installer needs applications closed, let the owner save work and close them normally, or hold that update for maintenance.
Use only documented no-restart behavior; do not assume an arbitrary silent flag prevents reboot or application termination.
Keep owner-controlled restarts explicit and last, and record when activation still depends on a browser/application restart versus a Windows restart.
An MSI result can distinguish success, restart required, and restart already initiated; interpret the actual installer and wrapper correctly. [MSI return codes](https://learn.microsoft.com/en-us/windows/win32/msi/error-codes)
A wrapper's zero exit code is insufficient if its own result receipt records a hold or child-process failure.

## 6. Diagnose before escalating a Windows repair

Identify the exact failed update, OS release/build/edition/architecture, timestamp, error, boot, and related servicing session.
Use current official guidance, form bounded hypotheses, and collect only the nonmutating evidence that distinguishes them.
Explain the supported failure mechanism separately from the unproven original cause; do not attribute damage to another maintenance action without evidence.
Do not interpret a registry number or a shared base-file version as proof of the complete installation state or a downgrade.
Different display labels, enablement packages, shared servicing bases, or staged content require context and independent target evidence.
If an active repair is already running, monitor it without concurrent DISM/SFC operations, component cleanup, update-cache resets, or manual package installs.
The [current-version repair](https://support.microsoft.com/en-us/windows/deployment/install-upgrade/fix-issues-by-reinstalling-the-current-version-of-windows) is a specific supported option with preservation and eligibility conditions; Reset this PC is a different operation.
An unexpected target, preservation choice, or repair mode is a stop-and-explain condition before the next consequential step.
After the owner restarts, verify the intended update/build and original failure condition; do not infer success merely from reaching the desktop.

## 7. Keep cleanup separate from patching

Browser data is always outside this toolkit's cleanup scope: no browser caches, history, cookies, sessions, profiles, downloads, or activity records are deleted.
Do not open browser storage or account data to calculate possible savings.
Application or AI activity-history deletion needs its own supported owner-directed workflow; do not guess where screenshots or databases are stored.
Never treat system component stores, Windows Installer caches, driver stores, active setup downloads, recovery/rollback files, project environments, or application bundles as generic junk.
Do not clean anything being used by the active update or repair, even if its name contains Temp or Cache.
For other candidate cleanup, inventory only approved metadata first, distinguish reproducible cache from unique data, and present exact targets and measured savings.
Preserve scope exclusions, verified backups, application state, and coding tools; uncertain or locked items stay held.
Deleting a Recycle Bin entry is permanent through that interface and requires a specifically approved scope; it is not implied by permission to patch software.

## 8. Verify the result and describe the remaining risk

Verify the installation identity and observed version using trusted metadata and, when approved, a reviewed executable's benign version query.
Verify the intended default in a fresh shell without changing PATH merely to make the report appear correct.
Check that the supported application starts and performs the relevant normal operation when that verification is within scope; do not open private content to test it.
For a security fix, confirm the vendor's fixed-build or backport evidence and remaining preconditions; a larger version number is insufficient.
Do not launch invasive tests, exploitation attempts, paid operations, firmware updates, or broad scanners as routine version verification.

Use distinct outcomes: verified update; pending application restart; pending Windows restart; held for owner decision; vendor-managed dependency unresolved; unsupported dependency retained; or verification incomplete.
State the exact evidence and limitation for each result.
Count software installations, update actions, advisory candidates, and verified vulnerabilities separately; a percentage across mixed records is misleading.
Do not promise that all vulnerabilities are eliminated, that no hidden software exists, or that an unsupported bundle is fixed by updating the global runtime.

## Before declaring an item complete

- Correct installation, owner, source, channel, architecture, and license verified.
- Artifact authenticity checked without suppressing failed safeguards.
- Action stayed within existing approval; required owner decisions were resolved.
- Actual installer result and receipt checked; no concurrent servicing conflict.
- Required activation/restart completed or clearly listed as pending.
- Intended behavior verified with proportionate, privacy-preserving checks.
- Remaining vendor gaps, unsupported dependencies, and uncertain applicability retained in the report.
