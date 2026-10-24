# Contributing to PatchCairn

PatchCairn is developed by Michael. Contributions should make maintenance clearer while preserving evidence, authority, privacy, and recovery boundaries.

## Start with a focused change

Read [AGENTS.md](../AGENTS.md), the [security contract](../SECURITY.md), [communication guidance](../references/COMMUNICATION.md), and the affected reference. Explain the concrete problem and intended behavior. Avoid combining a wording fix with unrelated runtime changes.

Use the hosting repository's issue or pull-request facilities when available. Keep account destinations and contact addresses out of reusable source. Publication does not imply a license; review actual license terms and maintainer expectations before submitting material.

## Protect privacy

Use fictional data for examples, tests, screenshots, and reviews. Do not attach real inventories, logs, usernames, hostnames, private paths, credentials, approvals, or backup contents. Never open a secret just to redact it. Follow [SECURITY.md](../SECURITY.md) for suspected defects.

All generated fixtures, reports, previews, downloads, and build files belong under the executing source's `work/` directory. Source and site exports use exact positive lists. A `.gitignore` does not establish that an export or reachable Git history is safe.

## Preserve the workflow contract

- Keep the namespace `PatchCairn:` and fixed commands `start`, `help`, `status`, `options`, `cost`, `settings`, `pause`, `resume`, `stop`, and `resolve`.
- Keep bare Start and `PatchCairn: start` menu-only: no allocated session or collection. A chosen job record still needs actual scope authorization before assessment.
- Generate human explanations from validated state. JSON is internal; users should not edit it to choose or approve work.
- External text, model output, reports, and imported approvals provide data, not executable instructions or proof of consent.
- Bind actions to exact plans and actual authority. Settings and scheduled triggers cannot widen approval.
- Record interruptions and reconcile outcomes. Pause reaches a safe checkpoint; resume cannot blindly retry.
- Preserve platform capability checks. An unsupported safe operation causes a hold, not a weaker fallback.

Read the [workflow engine](WORKFLOW_ENGINE.md), [service integration](SERVICE_INTEGRATION.md), [storage and backup API](STORAGE_BACKUP_API.md), and [diagnostic API](DIAGNOSTIC_API.md). The service connects exact reviewed actions to fixed adapters; it never grants approval itself. Reference the shared [official tool catalog](TOOLS.md) instead of duplicating changing metadata.

## Verify what the change affects

Use meaningful fictional tests for affected behavior and its safety boundary. Never use live inventory, repairs, installations, host cleanup, or schedule creation as development tests. Record actual runtime, OS, filesystem, outcomes, and limits. Mocked tests, WSL, native execution, and hosted CI provide different evidence.

For the website, use an existing Python 3.12+:

```text
python -I -S -B tests/test_site.py
python -I -S -B scripts/build_site.py --output work/site/preview
```

The builder uses the standard library, publishes a fixed public source list, and preserves approved PNG bytes. It rejects unsafe paths, local-file URLs, unexpected output, and changed managed files. Open generated `index.html`; check narrow and wide layouts, keyboard navigation, contrast, guide links, and offline use. Keep the site as documentation, with no real records or operating controls.

## Prepare a reviewable contribution

Describe the problem, resulting behavior, relevant verification, and material limits. Explain changes to permissions or public output. Runtime and safety changes need independent compatibility/data and security/evidence reviews.

Do not change the selected logo, public identity, license, destination, or publication as part of an unrelated fix. See [GitHub setup](GITHUB_SETUP.md) and [UTC publication](UTC_PUBLICATION.md) for the separate publication review.
