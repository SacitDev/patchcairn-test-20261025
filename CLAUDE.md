@AGENTS.md

# PatchCairn in Claude Code

This is a small host adapter. The imported AGENTS.md is the shared working agreement; do not replace it with a second set of rules here.

For a PatchCairn request, read `.agents/skills/pc-maintenance/SKILL.md` from this repository, then load only the job skill selected by the person:

- Security and updates: `.agents/skills/pc-security-updates/SKILL.md`.
- Storage assessment and cleanup: `.agents/skills/pc-storage-cleanup/SKILL.md`.
- Diagnosis and repair: `.agents/skills/pc-diagnose-repair/SKILL.md`.
- Backup and recovery: `.agents/skills/pc-backup-recovery/SKILL.md`.

These are the canonical skill files. Explicit file loading is the fallback when this Claude Code session does not discover `.agents/skills`; do not silently copy them into user settings or install a plugin. Use their referenced documentation and the current workflow engine interface before invoking a helper. If the engine or a required capability is unavailable, explain the hold and the concrete owner-controlled fallback described in `docs/ASSISTANT_COMPATIBILITY.md`.

Keep conversation commands in the `PatchCairn: <command>` namespace. Preserve Claude Code commands such as `/help`, `/resume`, `/config`, and `/memory` for their host purpose. On the first PatchCairn interaction, render the current engine menu with `PatchCairn — Developed by Michael`, the four jobs, control styles, timing choices, checkpoints, privacy boundary, and every available PatchCairn command. Loading this adapter or opening the project grants no host investigation or change authority.
