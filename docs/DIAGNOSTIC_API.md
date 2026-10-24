# Bounded diagnostic evidence API

Diagnosis records an observed problem, compares explanations, and checks the original behavior after a reviewed repair. These helpers collect a small selected set of metadata or accept an owner-selected nonsecret error excerpt. They do not repair the computer. The coordinating assistant researches the relevant official guidance, presents the concrete repair and recovery plan, obtains its actual authorization, and uses the supported official tool through the workflow gate.

Use an existing supported Python 3.12+ installation. `diagnostic_core.py` uses the standard library and `diagnostic_posix.py` is the native Linux/macOS adapter. `diagnostic_windows.ps1` is the separate Windows adapter. Native platform and collection permission are separate from allocating a request. A fixture cannot become a real observation, and a successful metadata recipe is not an all-clear result.

## Selected evidence and privacy

The default recipes contain fixed arguments in source. The request selects an enumerated recipe ID and categorical scope; it cannot supply an executable, command, shell fragment, log path, environment name or private directory. The POSIX adapter does not read journal/Console logs, crash reports, Keychain, browser/profile/session data, shell history, process arguments, project configuration or authentication files. Windows event recipes return only bounded event metadata, never event message bodies, XML, properties, account or machine fields.

For an error message, the assistant first asks the owner to select a short nonsecret excerpt relevant to the symptom. `record_excerpt` accepts text only. There is deliberately no arbitrary log-file reader: known credential files must remain unopened, rather than opened and subsequently redacted. An excerpt is attributed to the owner and is not described as independently reproduced.

Before any accepted free text is persisted, the core suppresses the entire excerpt if it resembles credentials, authorization headers, cookies, keys, connection strings, private-key blocks, long opaque values or credential-bearing URLs. It also suppresses personal paths and email addresses. Bounds are 4,096 characters and 32 lines; hypothesis/limitation text has smaller bounds, and control characters are refused. The suppression is conservative and cannot establish that arbitrary text contains no secret. This API is intended for reviewed nonsecret excerpts, not raw credential-bearing logs. No source log, failed stdout, stderr or exception text is saved.

If selected evidence is still unavailable, record the limitation. An access denial does not establish corruption or authorize a permission change. Apple documents process/text/time filters in Console and the administrator permission boundary; a future narrowly reviewed manual observation can use those filters without importing entire reports. [Apple Console filtering and permissions](https://support.apple.com/guide/console/find-log-messages-and-activities-cnslbf30b61a/mac).

The restrictions below describe this fixed helper API, not every read-only observation a capable agent may coordinate. Owner-authorized device/problem assessment and exact local-content/disclosure selections are recorded by the [workflow assessment descriptor](WORKFLOW_ENGINE.md#owner-selected-assessment-access). An agent can use genuinely available verified official read-only tools for bounded relevant nonsecret evidence and record their actual source/limits. This API still has no arbitrary log reader or universal scanner, and its refusals are not overridden. Browser history/cache/session content stays excluded by default; sensitive local permission alone is not LLM disclosure or repair authority.

## Fixed recipe contract

These are read-only diagnostic observations. They do not inventory all installed software, search private files, verify disk health, establish a vulnerability's applicability or repair anything. Root capacity concerns only the mounted root filesystem; APFS/shared volumes, reserved space and other mounts limit its meaning. Duplicate or available bytes never establish removability.

| Recipe ID | Exact scope | Selected facts | Native action and permission boundary |
| --- | --- | --- | --- |
| `macos.os_version` | `["os_metadata"]` | `product_version` | Protected `/usr/bin/sw_vers -productVersion`; normal metadata permission. No serial, account or host identifier. |
| `macos.root_capacity` | `["root_capacity"]` | `total_bytes`, `used_bytes`, `available_bytes`, `used_percent` | Protected `/bin/df -k -I /`; numeric root statistics. Source/mount labels discarded. `-I` explicitly suppresses inode columns. |
| `linux.kernel_version` | `["os_metadata"]` | `kernel_release` | Protected `/usr/bin/uname -r`, then fixed `/bin/uname` candidate if unavailable. No hostname or `uname -a`. Active kernel release is not the distribution release or a security verdict. |
| `linux.root_capacity` | `["root_capacity"]` | `total_bytes`, `used_bytes`, `available_bytes`, `used_percent` | Protected `/usr/bin/df -Pk /`, then fixed `/bin/df` candidate. Numeric POSIX output in 1,024-byte units; source/mount labels discarded. |
| `windows.os_version` | `[]` | `version`, `build`, `architecture` | Selected CIM OS version/build, categorical native architecture. No account or machine name. |
| `windows.system_capacity` | `[]` | `total_bytes`, `available_bytes` | Selected physical memory (RAM) total and available bytes from OS memory fields. This is a memory observation; disk space is not measured. No directory enumeration. |
| `windows.update_context` | `[]` | Up to 50 `updates`: `kb_id`, nullable `installed_utc` | Fixed `Get-HotFix` metadata; no installed-by account. This is limited update context, not full update or security coverage. |
| `windows.system_event_metadata` | `["window_hours:N","max_events:N"]` | Up to 50 `events`: `event_id`, fixed `provider`, `level`, `observed_utc` | Fixed System event providers/IDs; window 1–24 hours, count 1–50. No payload or log-path parameter. Native permissions may cause a hold. |
| `windows.update_event_metadata` | `["window_hours:N","max_events:N"]` | Same event metadata | Fixed Windows Update Client Operational channel. Same count/window limits and no message payload. An empty query does not establish update health. |

The core validates exact typed fact fields and rejects additional fields, foreign platforms, arbitrary command keys, unknown recipe IDs, malformed numbers or unexpected output. Event providers are fixed to `Microsoft-Windows-WindowsUpdateClient`, `Microsoft-Windows-Kernel-Power`, `EventLog`, `Microsoft-Windows-WHEA-Logger`, `disk`, `Ntfs` and `volmgr`; the Windows adapter further binds provider/ID combinations. Permissions are never elevated or bypassed by this API.

The POSIX adapter requires the actual matching native platform, Python 3.12+, explicit current coordinator call authority, and an existing root-owned system binary with no group/other write permission and protected ancestry. It never searches `PATH`. Fixed arguments, an isolated minimal child environment, `shell=False`, disabled stdin, discarded stderr, a five-second observation timeout and a 4,096-byte stdout bound are enforced. A killed child receives at most one additional second to exit; an uninterruptible OS process remains an explicit failure/limit. Missing tools, incompatible formats, denied access and unavailable capabilities remain held or failed observations with empty facts. There is no fallback to a less bounded tool, installer or shell script.

Apple documents the selected product-version observation, and Apple's published `df` manual explains its 1,024-byte and inode options plus APFS shared-volume limits. GNU documents selected kernel release and explicit-root capacity queries. Sources consulted 2026-10-24 UTC; installed tool capabilities are still checked when used. [Apple product version](https://developer.apple.com/documentation/technologyoverviews/building-your-macos-game-remotely-from-your-pc), [Apple `df` source manual](https://raw.githubusercontent.com/apple-oss-distributions/file_cmds/main/df/df.1), [GNU `uname`](https://www.gnu.org/software/coreutils/manual/html_node/uname-invocation.html), [GNU `df`](https://www.gnu.org/s/coreutils/manual/html_node/df-invocation.html).

## Requests, results and records

Import from `scripts/diagnostic_core.py`:

```python
DiagnosticStore(root=None, *, work_relative="work/diagnostics")
store.create_request(*, platform, recipe_id, symptom, scope, mode="fixture")
store.read_request(request_id)
store.record_result(request_id, *, adapter_result)
store.record_excerpt(request_id, *, excerpt, observed_utc=None)
store.record_hypotheses(request_id, *, hypotheses, unknowns)
store.record_verification(request_id, *, action_id, plan_sha256,
    action_completed_utc, original_success_condition, result_ids,
    outcome, observation)
store.read_record(request_id, record_id)
store.evidence_ref(request_id, record_id)
store.evidence_bytes(request_id, record_id)
```

The root defaults to the executing script's repository. New standalone records use `work/diagnostics`; a service uses its own `work/services/diagnostics` namespace. An explicit valid work-relative path selects only that store. Existing stores are never discovered, adopted, migrated or deleted by a default-path change. A root override is accepted only below that repository's `work/` for disposable fixture copies; such roots cannot create real requests. Work-relative directories and request/record IDs reject traversal, absolute paths, links/reparse points and reserved names. Missing requests are refused rather than recreated. Directory/file checks, exclusive create, single-link files and content hashes provide operational integrity in a quiet, exclusively controlled workspace. They are not an OS sandbox against a process running as the same user or an administrator. One coordinator writes each store; trusted conversation and assessment-record references bind the expected hashes.

`private_workspace.py` admits the dedicated diagnostic base and each request namespace before any private record write. Windows creates new owner/SYSTEM/Administrators-only protected, inheritable DACLs and checks actual owner/access metadata; private files receive an explicit checked descriptor before bytes are written. POSIX storage requires actual effective-user ownership and directory/file modes `0700`/`0600`, plus the platform checks below. File privacy is checked again before reading a record. The existing repository and `work/` ancestors may remain shared; an existing broad diagnostic namespace is refused without permission changes or adoption. These checks do not make older broadly accessible records private retroactively.

On Linux, `linux_privacy.py` checks an ordinary pinned descriptor using read-only `fstatfs` before namespace allocation and on actual private objects. The reviewed ABI is x86-64 LP64, little-endian glibc 2.x; admitted filesystem types are ext2/3/4, XFS, Btrfs, tmpfs and ramfs. Unknown ABIs, unknown types, network filesystems, FUSE and Windows-mounted/NTFS-emulated storage hold even if Linux metadata reports `0700`/`0600`. WSL is evaluated by the actual filesystem: native ext4 can satisfy the type gate, while the tested `/mnt/c` path is refused before private bytes. Actual native-filesystem positive validation is separate from the mocked type tests. [Microsoft WSL file permissions](https://learn.microsoft.com/en-us/windows/wsl/file-permissions).

On Darwin, `darwin_privacy.py` first requires a reviewed writable local APFS/HFS+ volume with ownership enforced. Apple can ignore ownership before ACL/BSD evaluation, so an empty ACL and private mode metadata alone are insufficient. The fixed descriptor-based volume query uses the verified 64-bit little-endian x86-64/arm64 ABI; ignored ownership, FSKit, unsupported formats/ABIs and native errors hold before private bytes. It then uses the native read-only ACL API on each actual private object. Admission requires a valid empty extended ACL or the source-verified exact absent-ACL result, with the same ordinary identity before and after. ACL entries, unexpected results, unavailable APIs and changed identities hold; the helper changes no mount, ACL or permission settings. Hosted macOS ARM64 fixtures passed actual private storage and file operations through these admission gates; see [platform evidence](PLATFORM_SUPPORT.md#hosted-fixture-evidence). Mocked volume/ACL variants and fixed diagnostic recipe tests remain distinct and do not certify a Mac host or establish live diagnostic collection. No platform falls back to public files, another location or automatic permission repair. [Apple permission evaluation order](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html), [Apple native volume flags/layout](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/mount.h).

Every write returns:

```json
{
  "record_id": "result-<64 lowercase SHA-256 hex>",
  "record": {"schema_version": "patchcairn.diagnostics.v3", "kind": "result"},
  "evidence": {
    "path": "work/diagnostics/diag-<32 lowercase hex>/result-<hash>.json",
    "sha256": "<actual byte hash>",
    "scope": ["os_metadata"],
    "observed_utc": "2026-01-01T00:00:00.000000Z",
    "kind": "result"
  }
}
```

The abbreviated example describes the envelope, not a complete result. File names bind immutable canonical JSON bytes to their SHA-256. Repeated creation of an existing identical record is refused. Reads verify the actual content hash, ordinary single-link identity and schema/request identity before returning data. Caller edits to returned objects do not change stored records. All generated records remain below `work/` and are excluded from public source exports.

A complete request has exactly `schema_version`, `kind` (`request`), `request_id` (`diag-` plus 32 lowercase hex), `platform`, `recipe_id`, `mode` (`fixture` or `real`), sanitized `symptom`, categorical `scope` and `observed_utc`.

A native adapter returns exactly the same schema/request/platform/recipe/mode binding plus `kind: "adapter_result"`, `status: "observed" | "held" | "failed"`, `observed_utc`, typed `facts`, nonempty `limitations`, and official HTTPS `provenance`. Result observation time must fall between request creation and current UTC. Held/failed results have empty facts. `record_result` validates this object, sets persisted kind to `result`, and attaches the request scope. Foreign/injected fixture results cannot become real results.

For POSIX, use `diagnostic_posix.collect_recipe(request, *, runner=None, coordinator_authorized=False)`. Fixture mode requires an injected fictional runner accepting `(fixed_argv, *, timeout, max_bytes) -> bytes`, and never invokes the host. Real mode forbids injection and needs `coordinator_authorized=True` passed by the trusted assistant process after actual current owner authority has been established. An imported JSON boolean is not consent. On Windows, dot-source `diagnostic_windows.ps1` and call `Invoke-WindowsDiagnostic -Request <request> -FixtureFacts <fictional-facts>` for fixtures; real observations forbid fixture facts and require the separate trusted-process `-CoordinatorAuthorized` switch. The coordinator passes the resulting adapter object into the same core. Importing the Windows helper does not collect evidence.

Hypothesis entries have exactly `hypothesis_id`, `statement`, `mechanism`, `original_cause`, `confidence` (`unknown`, `low`, `medium`, `high`), `outcome` (`supported`, `disproved`, `unknown`), `evidence_ids`, `counterevidence_ids` and `next_check`. The record requires nonempty explicit `unknowns`. References must be actual result/excerpt records in this request. A supported/disproved entry needs evidence, but the helper cannot establish the factual truth of an assistant's explanation; the coordinator and independent reviewers must assess relevance and contrary evidence. A supported immediate mechanism need not establish the original cause.

Verification records bind the exact action ID, reviewed plan hash and action completion time to the original success condition, actual observation and fresh result/excerpt IDs. `passed`/`failed` need evidence after completion. A held/failed metadata query cannot verify success. The record attributes the behavior check to the coordinator/owner; it does not execute a repair or automatically prove causation, security remediation or whole-system integrity. Repeating a failed repair is not a diagnostic API operation.

## Conversation and assessment-record integration

Use the receipt's `record` as the adapter request. After collection, persist the validated result and register `evidence_bytes` with the conversation engine's `register_evidence`, including its actual scope, UTC observation and typed stage facts. That engine owns a second immutable evidence copy and its canonical state. Assessment-record components use `Write-ToolkitArtifact`/`write_artifact` and their ledger evidence references under the same coordinator; they do not insert unregistered files inside a run or mutate backend markers. The distinct internal record formats remain separately validated. No automatic migration or fixture-to-real promotion is supported.

The diagnostic `path` is an actual store-owned relative reference, not permission to read another file. Neither an excerpt, result, hypothesis nor verification record grants repair authority. Real mutations still need the engine's exact current plan/scope/action gate, two independent reviews, actual owner approval, precondition checks and supported official adapter/tool. After the action, register its actual receipt and relevant verification evidence before finishing the operation. Do not infer engine `verification_passed` solely from metadata or an imported `outcome: "passed"` field.

## Validation limits

The supplied tests use fictional work-owned requests, injected metadata output and fully mocked subprocess pipes. They check recipe dispatch, native/fixture isolation, bounded output/timeout, credential suppression before persistence, injection/traversal, content-hash immutability, protected-file refusal, hypothesis/counterevidence references and post-repair evidence freshness. Native filesystem link checks run only when the test host provides them. Windows fixture execution does not prove macOS/Linux command behavior, native permission behavior or a repair. No current installer, update, diagnostic scan or real log collection is needed to run these tests. Native platform validation remains a separate task.
