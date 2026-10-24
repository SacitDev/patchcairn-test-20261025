# Publishing source with UTC metadata

This guide applies to an explicitly authorized publication. It does not create a commit, tag, remote, release or repository by itself. Review the destination, visibility, exact files and intended public identity with the owner first.

The delivery route is a clean source-only folder without the development `.git/` directory or history. A later authorized publication starts a fresh repository and makes its initial commit from that reviewed source with the UTC metadata below. Do not copy development history into the delivery or silently adopt an unexpected repository in the destination.

## What to keep in UTC

| Record | Required representation |
| --- | --- |
| Toolkit evidence and session records | UTC ISO-8601 strings ending in Z. |
| Git commit author and committer dates | Explicit zero offset, stored by Git as +0000. |
| An authorized annotated tag's tagger date | Explicit zero offset, verified before pushing. |
| Local file timestamps | Filesystem metadata; copying files does not set Git commit dates. |

Source tests deliberately include invalid/non-UTC input examples so they can check that validators refuse them. These are fictional test data, not actual publication or maintenance timestamps. Keep those negative tests intact.

Repository files do not control every clock displayed by GitHub or a viewer. Verify the underlying commit/tag metadata. Keep the operating system's time zone unchanged.

## Before a publication commit

1. Confirm actual authorization and the reviewed source snapshot. Exclude work/, credentials, local reports and history from another computer.
2. Review the intended public author and committer identity. Use the account's reviewed public or noreply email where appropriate; do not silently inherit a private email, Windows account name or hostname.
3. Check the repository, branch and hooks. Never skip hooks, force-push or rewrite history to repair a timezone mistake without a separate reviewed plan.
4. Start PowerShell with `$env:TZ='UTC'` and set both Git date variables explicitly for the approved commit. Do not rely only on a machine timezone or a browser-generated commit.

The following pattern sets dates; it is not an instruction or authorization to publish. The coordinating assistant inserts only the separately approved commit action and restores process variables afterward.

~~~powershell
$env:TZ='UTC'
$previousAuthorDate=$env:GIT_AUTHOR_DATE
$previousCommitterDate=$env:GIT_COMMITTER_DATE
$utcGitStamp='@'+[DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString([Globalization.CultureInfo]::InvariantCulture)+' +0000'
try {
    $env:GIT_AUTHOR_DATE=$utcGitStamp
    $env:GIT_COMMITTER_DATE=$utcGitStamp
    # Only the separately authorized commit action belongs here.
} finally {
    if($null -eq $previousAuthorDate){Remove-Item Env:GIT_AUTHOR_DATE -ErrorAction SilentlyContinue}else{$env:GIT_AUTHOR_DATE=$previousAuthorDate}
    if($null -eq $previousCommitterDate){Remove-Item Env:GIT_COMMITTER_DATE -ErrorAction SilentlyContinue}else{$env:GIT_COMMITTER_DATE=$previousCommitterDate}
}
~~~

Git documents the [author/committer variables](https://git-scm.com/docs/git-commit#_commit_information) and [raw timestamp-plus-offset format](https://git-scm.com/docs/git-commit#_date_formats). Check the actual annotated-tag operation against [git-tag](https://git-scm.com/docs/git-tag); uploading source does not require creating a tag.

## Verify before pushing

Check every reachable commit's author and committer offsets, for example with `git log --all --format="%H %ai | %ci"`. Actual author and committer dates must end in +0000. If publishing an annotated tag, inspect its tagger date too. Verify the actual objects and intended identities before upload.

An existing non-UTC commit, unexpected identity, hook refusal or changed remote is a stop-and-explain condition. A UTC shell variable does not fix an old commit. Check newly created browser or merge commits rather than assuming their metadata is suitable.

The user receives the plain-language result. Exact commands, identities and hashes stay in the review records unless requested. Approval remains bound to the concrete reviewed action.
