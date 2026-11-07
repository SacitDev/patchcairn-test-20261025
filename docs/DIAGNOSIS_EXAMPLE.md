# A fictional diagnosis, step by step

This example contains invented software and observations. It is not evidence about any real device, product, vulnerability or update.

## Symptom

The owner says that “Example Editor” still reports version 4 after its version 5 update succeeded. The goal is to find the installation being used, preserve settings and verify the intended update. A diagnosis request authorizes bounded observations, not uninstallation or a PATH edit.

## Hypotheses and distinguishing checks

| Hypothesis | Safe distinguishing check | Fictional observation | Conclusion |
| --- | --- | --- | --- |
| The updater failed before installing version 5. | Read the selected installer receipt and installed metadata for the intended scope. | Receipt names a per-user version 5 installation; metadata agrees. | The evidence contradicts failure for that installation, but says nothing about what is running. |
| The running application needs a normal restart. | Compare the reported process image location/version with the installed target, without collecting command-line arguments. | The running image is a different machine installation. | A restart of the same shortcut may reopen the other copy; this is not yet an adequate fix. |
| A shortcut launches a second installation. | Inspect only the owner-approved shortcut target and the selected public version metadata. | The shortcut targets machine version 4. | Wrong launch target is the supported immediate mechanism. |
| The second installation is safe to remove. | Establish its owner/dependents and supported removal behavior. | Dependents have not been checked. | Unknown; no removal is justified. |

## Bounded conclusion

The update installed the intended per-user copy, while the shortcut selects the machine copy. That explains the symptom. The evidence does not establish who created the shortcut or whether the machine copy is unnecessary.

The assistant says in chat: “The new copy is installed, but the shortcut opens a different copy. I recommend testing the verified new application directly and, if it works with your settings, reviewing a change to that one shortcut. Keeping both copies temporarily avoids an unreviewed uninstall. Removing the old copy needs a dependency check.”

## Plan and approval

No PatchCairn adapter edits a shortcut, so the assistant explains an owner-performed change. It names the exact shortcut and verified target, no unrelated PATH/profile changes, settings preservation, no app force-close, and normal behavior checks. If the owner wants a copy of the shortcut first, that is a separate reviewed backup plan: two reviewers challenge its target and data/recovery assumptions, and the owner's approval is bound to that plan's hash and action IDs.

## Verification

After the owner changes the shortcut and restarts the application normally, the selected launch opens the intended copy and the scoped behavior check succeeds. The session records the verified result. Any security finding is separately evaluated against the exact vendor build and advisory conditions. Version 5 alone does not establish a security fix.

If verification fails, the known side effects and any backup remain recorded, and the hypothesis table is reopened. Nothing is retried automatically. A later reviewed recovery and evidence-backed verification keep the original failure and any unresolved security finding on record.
