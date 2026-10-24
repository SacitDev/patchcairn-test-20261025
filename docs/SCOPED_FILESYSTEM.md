# Selected-root filesystem boundary

`scripts/scoped_fs.py` provides bounded operations for an explicitly selected
ordinary directory. Storage assessment can list one directory at a time and
stop before descending into a protected location. Content reads, quarantine,
restore and permanent file removal require the exact identity and SHA-256
captured for the reviewed file. A changed or inaccessible file causes a hold.

The workflow coordinator must establish the owner's authority, apply the exact
action/plan/scope gate, protect required recovery data, and record outcomes.
These library functions have their calling process's authority. They are not
an OS sandbox and do not authenticate consent from a hash, an imported record,
or a `quiet_workspace=True` argument.

## Operating assumptions

Use a quiet workspace controlled by its owner. A same-user or privileged
process that deliberately changes names between the last check and a native
operation is outside this boundary. Do not use this helper against an actively
changing application tree. The helper does not bypass sharing locks, access
controls, permissions or OS consent.

Each selected root must already exist at an exact absolute path. Admission
checks ordinary, non-reparse ancestry. A filesystem root, traversal component,
missing ancestor, symlink or reparse ancestor is refused. Relative paths are
literal slash-separated names: absolute paths, `..`, empty/dot components,
backslashes, alternate-stream colons, controls, reserved device names,
trailing dots/spaces and case collisions are refused. A file must be regular
and have exactly one hard link. Special files are refused before content open.
Unknown identity and nested filesystem boundaries are holds.

On POSIX, the adapter retains the actual ancestor and selected-root directory
descriptors. It checks the named ancestry against those pinned descriptors
before and after operations. Parent traversal and file operations use
descriptor-relative paths, `O_NOFOLLOW`, and `O_NONBLOCK`; directories also
use `O_DIRECTORY`. This requires Python 3.12+ and the native descriptor APIs.
There is no ordinary-path read/delete fallback when these are unavailable.

On Windows, `scoped_fs` delegates only to the checked
`windows_scoped`/`windows_worker`/`Windows.Scoped.cs` route. The supported worker
requires Windows 10+/Server 2016+, 64-bit Python 3.12+ and 64-bit PowerShell 5.1
or 7 in `FullLanguage`, plus the required job/handle-list and native filesystem
capabilities. Missing support is a hold. A process-owned serial worker reuses
its interpreter and compiled C# type; each request runs in a fresh function scope, and selected-file operations
create fresh C# `Scope` objects and pin current ordinary ancestry and exact
selected handles. Those selected handles do not remain locked between operations.
Worker process/source/private-namespace pins are a distinct lifetime boundary,
not an authority cache or a persistent selected-root OS lock.

Each logical request retains private request/response packets; fixed source
snapshots and compiler files belong to a separate private worker-generation
child under `work/windows-scoped/`. Caller serialization has a separate wait
of up to 120 seconds. After admission, one 120-second cold-startup/exchange
budget has a separate five-second failure-teardown grace; file preparation
and response persistence are byte-bounded rather than a hard total-return
promise. Possible-send ambiguity is never replayed. Replacement waits for
proved job-empty and completed I/O disposal; unresolved teardown holds with
required pins retained. Explicit idle `windows_scoped.shutdown_worker()`
proves only a point-in-time owned-helper drain, deletes no packets and closes
no user applications. A later native call can create a new generation.
An embedding process must prove shutdown completed before changing its selected
PowerShell runtime or toolkit PS/C# sources, then keep toolkit native calls quiet
throughout that update or an external-installer interval. Later native preflight
requires another successful drain before proceeding. See the
[worker lifecycle](WINDOWS_ADAPTER.md#owned-serial-worker-lifecycle) for exact
limits and shutdown results. POSIX keeps its current in-process descriptor
adapter. Imports and the bare menu start no worker. The quiet-workspace
assumption still applies on both platforms; see
[platform support](PLATFORM_SUPPORT.md) for the wider toolkit limits.

## Private artifact namespaces on Linux

Private storage on Linux also requires a native-filesystem admission check
before allocation and again on existing or newly created namespaces/files
before private bytes are used. `linux_privacy.assert_native_private_filesystem(path)`
queries an existing ordinary object through a pinned no-follow descriptor;
it does not infer privacy from reported mode bits on a foreign filesystem.
The current verified ABI is little-endian Linux x86-64 LP64 with glibc 2.x.
Unknown ABIs, unavailable APIs, native errors and unreviewed filesystem types
hold. The allowlist is ext2/3/4, XFS, Btrfs, tmpfs and ramfs. Actual owner and
`0700`/`0600` checks remain mandatory; this check grants no broader authority.

WSL itself is not rejected. Native Linux filesystems within WSL can pass the
same check. Windows-mounted/DrvFs, 9p, FUSE, NTFS emulation and network or
unknown filesystems hold for private storage even if they report restrictive
Linux mode metadata. Microsoft documents that Windows-file access still
uses Windows permissions. The gate reads no mount table or file contents and
changes no mount, ACL or permission. See the Linux [filesystem type constants](https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h),
[native statfs layout](https://github.com/bminor/glibc/blob/master/sysdeps/unix/sysv/linux/bits/statfs.h),
[fstatfs interface](https://man7.org/linux/man-pages/man2/statfs.2.html)
and Microsoft's [WSL permission rules](https://learn.microsoft.com/en-us/windows/wsl/file-permissions).

## Private artifact namespaces on macOS

Private session and artifact storage requires current-owner ordinary ancestry,
`0700` directories and single-link `0600` files, plus a native ACL check before
private bytes are written. `darwin_privacy.assert_no_extended_acl(path)` uses
only fixed libSystem read-only ACL APIs. It refuses every extended ACL entry,
including inherited or deny entries, without inspecting principals or trying
to repair permissions. Existing namespaces and newly created empty paths are
checked before use; mode bits alone do not establish privacy on macOS.

The separate `darwin_privacy.assert_private_filesystem(path)` gate also runs
before private allocation and on the actual private objects before bytes.
It uses a pinned ordinary descriptor and the source-verified 64-bit
little-endian `arm64`/`x86_64` filesystem ABI. Only writable local APFS or
reviewed HFS+ subtypes 0–3 with ownership enforcement enabled are admitted.
Ignore-ownership, FSKit, read-only, network or unknown filesystems and
ambiguous ABI/API results hold. The file observation is metadata-only; the
gate does not alter ownership, ACLs, mounts or permissions. Filesystem
admission does not replace the independent ACL and owner/mode checks.

The checker accepts a valid empty ACL only after `acl_valid` succeeds and
Apple's first-entry query confirms no entry. It also recognizes Apple's
source-verified missing-ACL-property result, `NULL` with `ENOENT`, only when
ordinary `lstat` observations before and after identify the same unchanged
object. A missing or changed path, another native error, invalid ACL or missing
primitive causes a hold. See Apple's [ACL declarations](https://github.com/apple-oss-distributions/Libc/blob/main/include/sys/acl.h),
[ACL retrieval implementation](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_file.c),
[file-security property implementation](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c)
and [stat/security implementation](https://github.com/apple-oss-distributions/Libc/blob/main/sys/statx_np.c).
This remains a quiet owner-controlled workspace boundary, with same-user and
privileged concurrent mutation excluded. Native call/error variants retain mocked
verification. Hosted macOS ARM64 private-storage and file-operation fixtures
also passed; see [hosted fixture evidence](PLATFORM_SUPPORT.md#hosted-fixture-evidence).
That runner context does not certify every filesystem, ABI or ACL state.

## Public API

All mutation and content arguments after the relative path are keyword-only.
`ScopedRoot` is a context manager and also has `close()`.

```python
capabilities() -> dict
relative_path(value: str, *, allow_root=False) -> str

ScopedRoot(root, *, quiet_workspace: bool, max_entries=20000)
scope.inspect(relative, *, hash_file=False, max_bytes=67108864) -> dict
scope.list_directory(relative="") -> list[dict]
scope.snapshot(*, hash_files=False, max_file_bytes=67108864,
               max_total_bytes=268435456) -> list[dict]
scope.read_bytes(relative, *, expected: dict, max_bytes: int) -> bytes
scope.stream_to(relative, *, expected: dict, writer, max_bytes: int,
                chunk_size=65536) -> dict
scope.mkdir(relative) -> dict
scope.create_file(relative, *, data: bytes, max_bytes: int) -> dict
scope.move_to(relative, *, destination: ScopedRoot,
              destination_relative: str, expected: dict) -> dict
scope.remove_file(relative, *, expected: dict) -> None
```

An entry record has exactly these keys:

| Field | Meaning |
| --- | --- |
| `relative_path` | Literal name within this selected root; `""` denotes the root. |
| `kind` | `file` or `directory`. |
| `device`, `inode` | Native filesystem/volume and object identity, not a portable cross-machine identifier. Windows uses its volume serial and file ID. |
| `mode`, `attributes` | Native type/permission or attribute observations. Their representation is adapter-specific. |
| `size` | Native logical size; it is not physical allocation or reclaimable space. |
| `mtime_ns`, `ctime_ns` | Native write and change observations. Windows uses its available native timestamps, with creation time in `ctime_ns`. |
| `nlink` | Native hard-link count; admitted files have one link. |
| `sha256` | Lowercase content hash, or `None` for metadata-only records and directories. |

`inspect("")` returns the root record. `list_directory()` returns only immediate
children and opens no child content. It refuses the listing if an entry is
unsupported; it does not silently omit a link or an unknown entry.
`snapshot()` includes the root and all ordinary descendants, checks bounded
membership and freshness, and optionally hashes files. The storage service
uses `list_directory()` to apply its protected-name policy before descent;
the general filesystem primitive cannot infer which private locations an
owner intended to select.

The `expected` argument for reading, moving or removing must be the exact
hashed file record returned for that relative path. The native device, object
identity, type, size, timestamps, link count, attributes and content hash are
checked again. A metadata-only record does not permit a content operation.
`ScopedFSError` is a refusal with a categorical `.code`; `CapabilityHold` is
its unsupported-capability subclass. `missing-entry` means an exact POSIX
leaf name is absent. Inaccessible or missing parents are a different hold;
callers must not treat all errors as an empty destination.

## Bounds and read outcomes

The POSIX defaults are 20,000 total snapshot entries, 64 path components,
64 MiB per hashed file and 256 MiB total hashed content. Metadata-only
snapshots do not reject a large ordinary file merely because its contents
would exceed the hashing cap. Callers can supply smaller positive bounds.
The native Windows adapter may impose tighter documented bounds.

In-memory reads and exclusive creation accept at most 64 MiB. POSIX streaming
accepts an explicit positive cap up to 1 TiB and chunks from 1 byte to 1 MiB.
The initial size must fit that cap; growth beyond the initial size, truncation,
changed content/identity and incomplete consumers cause a refusal. The current
Windows streaming adapter holds above 64 MiB; it does not claim streaming a
large file through an unbounded memory buffer. A ZIP builder must choose caps
within its actual adapter and verify the completed archive separately.

`stream_to()` calls a trusted byte-consumer, such as a ZIP entry writer, and
returns the verified source record only after the complete read succeeds.
The consumer may already have received bytes if a later check fails. A writer
return value must be `None` or the whole chunk length. The caller must keep
partial output untrusted, retain a failure record, and avoid publishing it as
a verified backup. A write failure is not permission for an automatic retry.

## Quarantine, restore and permanent removal

`move_to()` checks an admitted destination root on the same filesystem and
refuses an existing destination, including a case-equivalent name. Linux uses
native descriptor-relative `renameat2(RENAME_NOREPLACE)` for atomic
no-overwrite rename. Symbol availability does not establish support on every
filesystem: `ENOSYS`, unsupported flags/filesystem behavior or a cross-device
result cause a capability hold.

On native macOS, the adapter binds the system library's descriptor-relative
`renameatx_np` and supplies only `RENAME_EXCL` (`0x00000004`). Apple's header
declares this interface for macOS 10.12 and later; the native symbol and the
required POSIX descriptor capabilities must actually be available. Apple's
manual defines an existing destination as `EEXIST` under `RENAME_EXCL`, and
unsupported filesystem flags as `ENOTSUP`. The adapter passes admitted parent
descriptors and literal leaf names, preserving the same checked ancestry,
identity, same-filesystem and quiet-workspace boundary as Linux. This macOS
binding has both mocked call/error verification and successful native
no-overwrite move/restoration fixtures on the hosted macOS ARM64 workspace;
see [the hosted fixture evidence](PLATFORM_SUPPORT.md#hosted-fixture-evidence). See Apple's [interface and constant declarations](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stdio.h)
and [rename manual source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/rename.2).

Missing native symbols/libraries and unsupported POSIX platforms hold this
operation. There is no weaker rename, cross-volume copy/delete or overwrite
fallback.

The source is rehashed and checked immediately before the rename; the
destination identity and content are verified afterward. Rename can update
change time, so the returned destination record is the new exact record to
use for a later restore or purge. Restore is the same checked move in the
opposite direction and refuses an occupied original name.

`remove_file()` rechecks the exact hashed ordinary file before one native
unlink. It cannot delete a directory, recurse through a tree or select
unlisted neighbors. Permanent purge needs its own explicit owner decision
and an exact storage plan. No helper force flag, recursive remove, global
prune or ACL repair exists here.

These are individual operations, not a transaction. If a native operation
succeeds and a later check or journal write fails, the caller must reconcile
actual source/destination state and preserve evidence. The code does not
promise power-loss durability, atomic multi-file cleanup, or automatic
rollback. A failed create can leave a partial ordinary file for reconciliation.

## Larger backup selections

The storage service's content operations currently set narrower compiled
bounds than the general POSIX streaming primitive: 16 MiB per selected file,
48 MiB total selected content and a 64 MiB archive. Metadata assessment has
separate root, entry and depth limits; logical file sizes do not consume its
content-read budget. This permits a size summary for a larger selected tree
without authorizing its contents to be opened. The service checks the selected
content budget before hashing backup/quarantine plans or beginning those
native operations.

Current ZIP creation and verification use bounded in-memory buffers. A
multi-gigabyte content selection therefore needs a different reviewed
workflow; increasing the compiled constants alone would not establish safe
bounded memory or recovery verification.

Keep the existing bounds until a streaming archive writer, bounded archive
reader, immutable output protocol and restoration verification have been
implemented and tested together for each native adapter. For present larger
content selections, the coordinator can propose an appropriate official
backup tool, a separately reviewed
destination and exact contents/exclusions, with actual tool capabilities,
owner authority, recovery checks and failure handling. The present helper
must report an unsupported selection size honestly and keep required recovery
protected. It must not silently trim the selection or treat several partial
backups as complete recovery coverage.

## Fixture verification

`tests/test_scoped_fs.py` writes fictional fixtures only under
`work/upgrade_v3/filesystem`. It covers admission and relative boundaries,
root replacement, symlink/reparse/hardlink/special-file refusal, read growth,
same-size mutation, stale identity/hash, caps, exclusive creation, exact purge,
destination preservation, and move/restore identity checks. It also checks
Windows adapter dispatch and capability holds with mocks.
Mocked macOS checks verify the exact system-library symbol, C argument types,
parent descriptors, literal leaf-name bytes, `RENAME_EXCL` flag and refusal
of existing destinations, unsupported operations and other native errors.

The native WSL Ubuntu checks execute against the owned Windows-mounted work
directory. That filesystem cannot create a case collision or FIFO in these
fixtures and rejects atomic `RENAME_NOREPLACE`; those native success cases
are explicit skips. The safe rename refusal preserves the source, and a
separate explicitly simulated rename exercises the successful identity
protocol. Mocked dispatch or a simulated rename is not native-platform
certification. No fixture scan or write uses a real private source tree,
`/tmp`, a home directory or a global cleanup target.

`tests/test_windows_worker.py` separates strict codec and fictional
transport/lifecycle fixtures from actual PowerShell/C# integration. Local
Windows Python fixture discovery completed with actual skips; focused native
checks also created, inspected and read 64 MiB under both PowerShell 7 and
5.1, verified bytes/hashes and completed owned-worker teardown. The
[Windows evidence](WINDOWS_ADAPTER.md#evidence-and-test-limits) records the
counts, observed worker lifetime peaks and limits; neither suite completion
nor these focused checks establish general workload speed.
