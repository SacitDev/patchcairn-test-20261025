# Prepare a clear GitHub project

This guide prepares publication. It does not authorize a remote, upload, public repository, release or account change.

## Suggested presentation

The root README.md is the page visitors will see on GitHub. Keep it at the top of the uploaded source tree, alongside AGENTS.md, toolkit.json and the scripts/docs folders. There is no separate GitHub-only README to maintain. GitHub formats the Markdown into the project introduction automatically. [GitHub's README documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes)

When preparing the source ZIP and clean delivery folder, use the exact source allowlist and verify folder/ZIP membership and hashes. Keep the private work/ directory, development `.git/` metadata/history, run records, test outputs and export copies out of both. The ZIP is a transport package; the root README and project files inside it are the source to publish. Any later authorized publication starts a fresh repository from that reviewed source and creates a separately authorized initial UTC commit. A `.gitignore` does not inspect history or prove that an export is private.

Name: **PatchCairn**. A cairn is a stack of stones marking a safe route; the name fits a workflow that leaves an evidence trail through maintenance decisions. Repository names belong to an account namespace. Recheck availability and naming/trademark concerns when publishing; a dated search is not a reservation.

Suggested description:

> A maintenance skillset for AI assistants: plan security updates, assess selected storage, verify backups and diagnose problems with clear explanations and owner-approved changes.

Suggested topics:

`maintenance`, `diagnostics`, `security`, `system-administration`, `windows`, `linux`, `macos`, `ai-workflow`, `codex`, `software-updates`, `compatibility`, `privacy`, `powershell`, `python`, `incident-diagnosis`

The canonical GitHub landing page is the root `README.md`. Keep one README authoritative; avoid a second copied “GitHub README” that drifts. It displays the selected PatchCairn wordmark from `assets/patchcairn-logo.png`: black geometric lettering with an orange connection between h and C. Design exploration and generation receipts remain private work and are not included in the source export.

The landing page introduces the skillset, explains the user's journey and links to guides. Keep test matrices and implementation details in [platform notes](PLATFORM_SUPPORT.md) and the technical references, with accurate operating limits preserved there. Do not replace them with unsupported claims of universal validation. [Communication guidance](../references/COMMUNICATION.md) governs how the assistant explains actual findings and decisions to users.

The public attribution is **PatchCairn — Developed by Michael**. Before a future publication, review the intended Git author and committer name as Michael and use only the owner's reviewed GitHub noreply address. Do not infer a private email, copy a local workstation identity or invent the account-specific noreply address. Account settings and existing Git configuration are not changed by this guide.

## Validate before uploading

1. Preserve the owner's selected [MIT License](../LICENSE), copyright 2026 Michael, in the source package and any later publication. This license decision is complete; it does not authorize a repository, upload, or account change. Keep the license notice with distributions as its terms require. See [GitHub's licensing guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository).
2. Run fictional tests on available platforms and record actual versions, source hashes, failures and coverage. A future macOS CI job does not establish that macOS has passed today.
3. Resolve blockers from two independent adversarial reviews. Preserve scoped limits rather than promise zero errors on every computer.
4. Export through the exact source allowlist. Inspect the actual ZIP entry list, folder/ZIP parity, included text, PNG metadata and privacy results. Exclude every real inventory, log, screenshot, secret, approval and local user identifier. Private test/review evidence stays under work; only the reviewed public source and documentation site can be published.
5. Use the clean source-only delivery for a fresh publication repository. Do not publish the development repository or copy its Git directory/history. Unexpected existing Git metadata in the intended clean destination is a stop-and-review condition; do not silently adopt it.
6. Review repository owner/name, visibility, files and intended command with the owner. Upload only after actual publication authorization. No account or remote is hardcoded here.

## Future CI and publication metadata

Before creating a publication commit or annotated tag, follow [UTC publication guidance](UTC_PUBLICATION.md). It covers explicit UTC author/committer dates and annotated-tag dates, public identity review and reachable metadata verification before pushing. Git dates must carry `+0000`; evidence timestamps use UTC-Z. Keep the operating system's time zone unchanged. Review unexpected existing identities, history or non-UTC objects before choosing a publication path; do not force-push, rewrite history, skip hooks or silently repair configuration. These checks do not authorize an upload.

`.github/workflows/ci.yml` is configured to discover all Python `test_*.py` unit/integration fixtures on hosted Windows, Ubuntu and macOS with Python 3.12 and 3.15. Its Windows job includes the assessment-record, native selected-file and private-namespace PowerShell suites under PowerShell 7 and Windows PowerShell 5.1, and it retains the offline JavaScript report-interface fixtures. Portable Windows jobs retain a 90-minute bound; the separate Windows PowerShell job allows 60 minutes, and Ubuntu/macOS portable jobs allow 15 minutes. The worker reuses interpreter/type startup while native operations and safety checks remain fresh per request. Local Windows fixture completion, focused native checks and worker memory observations are described in [Windows evidence](WINDOWS_ADAPTER.md#evidence-and-test-limits); they do not establish hosted timing or a new hosted pass. Match the published snapshot to completed results in the [fixture-safety workflow](https://github.com/SacitDev/PatchCairn/actions/workflows/ci.yml). All native test files are fictional files inside owned work directories. Capability skips remain visible and do not establish a native operation passed. The workflow has read-only repository permissions, no persisted checkout credentials, no package publishing and no live inventory/update/repair steps. Actions are pinned to full commit IDs; review and reverify them before future updates.

The checked-in pins were resolved against the official action repositories on 2026-10-23: [checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), [setup-python v7.1.0](https://github.com/actions/setup-python/releases/tag/v7.1.0) and [setup-node v7.1.0](https://github.com/actions/setup-node/releases/tag/v7.1.0). The Node step runs offline report-interface fixtures; it is not an additional requirement for the maintenance helpers. Pinning prevents silent tag movement; it does not eliminate the need to review updates and hosted-runner behavior.

Use [GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use) for CI itself. For operating-system and product claims, follow the actual vendor's documentation, such as Microsoft Learn/Support/MSRC for Microsoft products.

## Public documentation site

The public site is documentation only. It does not operate the toolkit, collect diagnostics, upload run records, provide a control portal or expose local drive links. Its Night Circuit design uses self-hosted CSS, the approved wordmark, a local illustrative hero image, and one fixed local `enhancements.js` for visual effects and interaction cues. The guides remain visible and readable without JavaScript. The visual script does not access sessions, browser storage, the clipboard, or the network. It is not permission to add arbitrary scripts or operating controls.

The site builder uses an explicit public-source selection and writes its generated output below `work/site/`. Build a local preview from the source root with an existing Python 3.12+:

```text
python -I -S -B scripts/build_site.py --output work/site/preview
```

Open the generated `index.html` in a browser and review its guides, links, narrow-screen layout, keyboard access, and reduced-motion behavior. These are documentation checks, not a host-maintenance test. Upload only the reviewed generated site artifact; never select the repository root or work tree as the Pages artifact.

The separate `.github/workflows/pages.yml` provides a manual publication path from the repository's default branch. After actual authorization, configure GitHub Pages for Actions, review the target branch/environment and exact source snapshot, and manually dispatch that workflow. Keep deployment permissions confined to the deployment job and official actions pinned to reviewed commits. A manual trigger is a control point; it does not replace the owner's publication instruction or the content/privacy review. [GitHub documents the custom-workflow and deployment requirements](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

A local preview, a checked-in Pages workflow, or successful fictional CI does not mean a public repository or site has been created. Publication remains a separate owner decision. The source package includes the owner's selected MIT License; no repository owner, remote, or account-specific identity is implied.
