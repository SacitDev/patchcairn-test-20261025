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

On Windows, `scoped_fs` delegates to `windows_scoped`, which calls Windows
through `win32_files` (Python `ctypes`) inside the Python process. It needs
64-bit Python 3.12+ on Windows; missing support is a hold. Each open root has
its own I/O thread, which holds the selected root and its ancestors open for
the root's lifetime and opens each selected file per operation. A native call
that does not return within its deadline (120 seconds, plus flush time for a
new file) is cancelled and reported as unresolved, and that root refuses later
calls; nothing is retried. There is no worker process, request packet or
compiled helper. See the [I/O thread lifecycle](WINDOWS_ADAPTER.md#io-thread-lifecycle)
for the exact limits. POSIX keeps its in-process descriptor adapter. Imports and
the bare menu open no root. The quiet-workspace assumption still applies on both
platforms; see [platform support](PLATFORM_SUPPORT.md) for the wider toolkit limits.

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
verification, and the hosted macOS CI job runs the private-storage and
file-operation fixtures; see [hosted fixture evidence](PLATFORM_SUPPORT.md#hosted-fixture-evidence).
That runner context does not certify every filesystem, ABI or ACL state.

## Public API

All mutation and content arguments after the relative path are keyword-only.
`ScopedRoot` is a context manager and also has `close()`.

```python
capabilities() -> dict
relative_path(value: str, *, allow_root=False) -> str

ScopedRoot(root, *, quiet_workspace: bool, max_entries=100000)
scope.inspect(relative, *, hash_file=False, max_bytes=67108864) -> dict
scope.list_directory(relative="", *, excluded=None) -> list[dict]
scope.read_bytes(relative, *, expected: dict, max_bytes: int) -> bytes
scope.mkdir(relative) -> dict
scope.create_file(relative, *, data: bytes, max_bytes: int) -> dict
scope.move_to(relative, *, destination: ScopedRoot,
              destination_relative: str, expected: dict) -> dict
scope.remove_file(relative, *, expected: dict) -> None
```

Streaming reads, snapshots and the new files that a backup writes go through
the backends' shared interface instead: `scoped_fs.open_root`, then
`open_read`, `open_new`, `stream_to` and `snapshot` of `scoped_base.RootBase`. `admit_destination` admits a backup destination
separately from a source root.

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
children and opens no child content. Without an `excluded` list it refuses the
listing if an entry is unsupported; with one, each such entry (link, special
file, online-only placeholder, hard link, non-portable name, path too long or
case collision) is reported there as not included and never read.
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

A listing holds at most 100,000 entries and at most 1,000 "not included"
rows, with one final row counting the rest; paths have at most 64 components
and 200 UTF-16 units. Metadata-only records do not reject a large ordinary
file merely because its contents would exceed a hashing cap. Callers can
supply smaller positive bounds.

In-memory reads and exclusive creation through `ScopedRoot` accept at most
64 MiB. Streaming through the backend interface reads 1 MiB pieces, up to
1 TiB per stream. The initial size must fit the cap; growth beyond the initial
size, truncation, changed content/identity and incomplete consumers cause a
refusal. A ZIP builder must choose caps within its actual adapter and verify
the completed archive separately.

A streaming consumer, such as a ZIP entry writer, may already have received
bytes if a later check fails. The caller must keep partial output untrusted,
retain a failure record, and avoid publishing it as a verified backup. A
write failure is not permission for an automatic retry.

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
binding has mocked call/error verification, and the hosted macOS CI job runs
its native no-overwrite move/restoration fixtures;
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

The storage service sets its own bounds on top of the backends. Metadata
assessment has separate root, entry and depth limits; logical file sizes do
not consume a content-read budget, so a size summary of a larger selected
tree does not authorize opening its contents. Duplicate comparison and
quarantine read at most 16 MiB per file and 48 MiB in total, checked before
hashing or moving.

A backup streams each selected file into the archive and holds at most
100,000 files. It writes to the owned work folder or to a folder on another
drive that the owner chose, which must have free space for the backup's
worst-case size plus a 256 MiB margin; a FAT32 drive refuses a backup that
can reach 4 GiB. The archive keeps a temporary name until every entry has
been read back from the drive.

PatchCairn's own restore still reads the archive in memory: it accepts an
archive of at most 32 MiB and files of at most 16 MiB. A larger backup is
verified but cannot be restored, or used as required recovery, by PatchCairn.
For such a selection the coordinator can propose an appropriate official
backup tool, a separately reviewed destination and exact
contents/exclusions, with actual tool capabilities, owner authority, recovery
checks and failure handling. The helper must report an unsupported selection
size honestly and keep required recovery protected. It must not silently trim
the selection or treat several partial backups as complete recovery coverage.

## Fixture verification

`tests/test_scoped_fs.py` writes fictional fixtures only under
`work/test-fixtures/`. It covers admission and relative boundaries,
root replacement, symlink/reparse/hardlink/special-file refusal, read growth,
same-size mutation, stale identity/hash, caps, exclusive creation, exact purge,
destination preservation, and move/restore identity checks. It also checks
Windows adapter dispatch and capability holds with mocks.
Mocked macOS checks verify the exact system-library symbol, C argument types,
parent descriptors, literal leaf-name bytes, `RENAME_EXCL` flag and refusal
of existing destinations, unsupported operations and other native errors.

A Windows-mounted WSL folder (9p) cannot create a case collision or FIFO,
rejects atomic `RENAME_NOREPLACE` and is refused for private storage, so the
tests that need those capabilities do not pass there; the supported Linux
evidence is a native Linux filesystem. A separate explicitly simulated rename
exercises the successful identity protocol. Mocked dispatch or a simulated
rename is not native-platform certification. No fixture scan or write uses a real private source tree,
`/tmp`, a home directory or a global cleanup target.

`tests/test_windows_io.py` exercises the Windows adapter on fictional NTFS
folders; the [Windows evidence](WINDOWS_ADAPTER.md#evidence-and-test-limits)
describes what it covers and its limits. Suite completion does not establish
general workload speed.
