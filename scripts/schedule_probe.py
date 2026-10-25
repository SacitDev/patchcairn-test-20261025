"""Host facts and path rules for schedules (layer L2-pure: standard library and pc_records only).

schedule_hosts renders and registers schedules; this module reads the computer they are made on. It gives:
- check_path(): the spelling rules every rendered path must meet, so each renderer can quote it safely;
- host_facts(): on Windows the system folder, the user's SID (an elevated token is refused) and the console, OEM and
  ANSI code pages; elsewhere the uid, the home folder, a root-owned systemctl, and whether systemd and cron run;
- system_offset(): the computer's own time zone, which the operating-system schedulers use, never the process TZ;
- interpreter_path(): the interpreter recorded in a new schedule;
- check_writable() and check_placement(): who besides this user, root (and on macOS the admin group) could change
  what the schedule runs, as listed in check_writable; launchd never runs from a folder macOS protects; Windows paths
  stay within the 260-character limit;
- LocalFiles: the real file object for the home-folder plist and unit files (the engine constructs it at L4).
Production passes host_facts(record, ...) and system_offset() to schedule_hosts; tests replace each source with a fake.
"""
from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import errno
import io
import ntpath
import os
import posixpath
import re
import shlex
import stat
import sys
import unicodedata
import zoneinfo

from pc_records import Refusal

SYSTEMCTLS = ("/usr/bin/systemctl", "/bin/systemctl")
# Without long paths (off by default) a path holds at most 259 UTF-16 units, and a folder an API creates at most
# 247 (MAX_PATH minus 12; https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation).
# private_workspace, which writes task.xml, takes at most 240 (D-050). The longest rendered file is
# <root>\work\schedules\<id16>\task.xml (41 more units) and the folder the engine creates is
# <root>\work\schedules\<id16> (32 more), so the root may hold min(259 - 41, 247 - 32, 240 - 41) units.
WINDOWS_ROOT_LIMIT = min(259 - 41, 247 - 32, 240 - 41)
_SID = re.compile(r"S-1-(?:5-21|12-1)(?:-[0-9]{1,10}){4}\Z")
_SYSTEM_DIR = re.compile(r"[A-Za-z]:\\[^\\]+\\system32\Z", re.IGNORECASE)
_FACT_KEYS = {"windows": {"platform", "system_dir", "user_sid", "code_pages"}, "macos": {"platform", "uid", "home"},
              "linux": {"platform", "uid", "home", "systemctl", "systemd_running", "cron_running"}}
# File systems whose owners and permission bits cannot show who else can write. WSL's Windows drives copy the
# Windows user's own access, and chmod changes nothing (https://learn.microsoft.com/en-us/windows/wsl/file-permissions);
# mount.drvfs mounts them as drvfs, plan9, virtio-plan9 or virtiofs (https://wsl.dev/technical-documentation/drvfs/),
# and 9p is the kernel's name for plan9. cifs and smb3 shares (mount.cifs(8): uid=, file_mode=) and VirtualBox
# shared folders (vboxsf) show owners and bits taken from mount options.
_SHARED_TYPES = frozenset({"9p", "drvfs", "plan9", "virtio-plan9", "virtiofs", "cifs", "smb3", "vboxsf"})
# A Windows path the access check can answer for: a drive letter, or a network share.
_WINDOWS_PLAIN = re.compile(r"[A-Za-z]:\\|\\\\(?![?.]\\)[^\\]+\\[^\\]+(?:\\|\Z)")
# Folders whose contents macOS shows only to apps the person allowed (https://support.apple.com/guide/security/secddd1d86a6),
# and the cloud-storage folder beside them; a launchd job runs python with nobody's consent, so it could not read there.
MACOS_PROTECTED = ("Desktop", "Documents", "Downloads", "Library/Mobile Documents", "Library/CloudStorage")
MACOS_ADMIN_GID = 80  # decision D-045: on macOS the admin group counts like root
_PYTHON = {"windows": re.compile(r"python(?:3(?:\.[0-9]{1,2}t?)?)?\.exe\Z", re.IGNORECASE),
           "posix": re.compile(r"python(?:3(?:\.[0-9]{1,2}t?)?)?\Z")}
# Windows: quotes and % break the task's command line; POSIX: these characters are quoting, escapes or specifiers
# in systemd, cron's shell or the prompt.
_UNSAFE = {"windows": frozenset('"%*?<>|/:'), "posix": frozenset("%$\\\"';`*?")}
_HIDDEN = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})  # control, format (bidirectional overrides), surrogates, separators
_CRON_PIDFILES = ("/run/crond.pid", "/var/run/crond.pid")  # Debian cron and cronie (not verified on every distribution)
_MAX_BYTES = 1_000_000


def check_path(value, platform, what, *, python=False):
    """Return ``value`` when it is a plain absolute path that every renderer can quote safely; otherwise refuse."""
    windows = platform == "windows"
    if (not isinstance(value, str) or not 0 < len(value) <= (259 if windows else 1024)
            or any(unicodedata.category(char) in _HIDDEN for char in value)):
        raise Refusal("schedule-path", f"The {what} must be an absolute path without control characters")
    if windows:
        absolute = value[:1].isascii() and value[:1].isalpha() and value[1:3] == ":\\"
        rest, parts, unsafe = value[3:], value[3:].split("\\"), _UNSAFE["windows"]
    else:
        absolute, rest, parts, unsafe = value.startswith("/"), value[1:], value[1:].split("/"), _UNSAFE["posix"]
    if (not absolute or any(char in unsafe for char in rest) or any(part in ("", ".", "..") for part in parts)
            or (windows and any(part != part.rstrip(" .") for part in parts))):
        raise Refusal("schedule-path", f"The {what} must be a plain absolute path: no '..', no empty parts and none of "
                                       + " ".join(sorted(unsafe)))
    if python and not _PYTHON["windows" if windows else "posix"].match(parts[-1]):
        raise Refusal("schedule-path", f"The {what} must be a python executable given by its absolute path")
    return value


def check_facts(facts, platform):
    """Return the computer facts (host_facts) when they are complete and valid for ``platform``."""
    if not isinstance(facts, dict) or facts.get("platform") != platform or set(facts) != _FACT_KEYS.get(platform):
        raise Refusal("schedule-facts", "The computer facts do not describe this schedule's platform")
    if platform == "windows":
        check_path(facts["system_dir"], platform, "Windows system folder")
        if not _SYSTEM_DIR.match(facts["system_dir"]):
            raise Refusal("schedule-facts", "The Windows system folder must be <drive>:\\<Windows folder>\\System32")
        if not isinstance(facts["user_sid"], str) or not _SID.match(facts["user_sid"]):
            raise Refusal("schedule-facts", "Windows did not report a user account PatchCairn can schedule for")
        pages = facts["code_pages"]
        if not isinstance(pages, list) or not pages or any(type(page) is not int or not 0 < page < 65536 for page in pages):
            raise Refusal("schedule-facts", "Windows did not report its code pages")
        return facts
    if type(facts["uid"]) is not int or not 0 < facts["uid"] < 2 ** 32 - 1:
        raise Refusal("schedule-facts", "PatchCairn schedules only for an ordinary user account, never for root")
    check_path(facts["home"], platform, "home folder")
    if platform == "linux" and (facts["systemctl"] not in (None, *SYSTEMCTLS) or type(facts["systemd_running"]) is not bool
                                or type(facts["cron_running"]) is not bool):
        raise Refusal("schedule-facts", "The Linux facts need systemctl (or None) and whether systemd and cron run")
    return facts


def native_platform():
    """This computer's platform name ("windows", "macos" or "linux"), or None when PatchCairn does not support it."""
    if os.name == "nt":
        return "windows"
    return "macos" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else None


def interpreter_path():
    """The absolute path of this interpreter, recorded in a new schedule: Python 3.12 or later, 64-bit on Windows."""
    platform = native_platform()
    if platform is None or sys.version_info < (3, 12) or (platform == "windows" and sys.maxsize <= 2 ** 32):
        raise Refusal("schedule-interpreter", "Scheduling needs Python 3.12 or later, 64-bit on Windows")
    if not os.path.isabs(sys.executable) or not os.path.isfile(sys.executable):
        raise Refusal("schedule-interpreter", "This Python does not report its own absolute path")
    return sys.executable


def system_offset(platform=None, *, zone_file=None, convert=None):
    """``offset_of(timestamp)``: seconds east of UTC at that instant in this computer's own time zone.

    The process TZ variable never counts: PatchCairn's own instructions set TZ=UTC, while Task Scheduler, launchd,
    cron and the desktop apps keep the computer's zone. Windows reads the dynamic time zone from kernel32
    (GetDynamicTimeZoneInformation and SystemTimeToTzSpecificLocalTimeEx); macOS and Linux read /etc/localtime with
    zoneinfo. Tests pass ``zone_file`` (a binary file object holding TZif data) or ``convert`` (a UTC
    (year, month, day, hour, minute, second) tuple to the local one) instead of the system source.
    """
    if (platform or native_platform()) == "windows":
        convert = convert or _windows_converter()

        def offset_of(timestamp):
            utc = datetime.fromtimestamp(timestamp, timezone.utc).replace(tzinfo=None, microsecond=0)  # SYSTEMTIME: whole seconds
            return int((datetime(*convert(utc.timetuple()[:6])) - utc).total_seconds())
        return offset_of
    try:
        with zone_file or open("/etc/localtime", "rb") as handle:
            data = handle.read(1 << 16)  # a TZif file holds a few KB; 3.12's byte loop is slow on far more
        zone = zoneinfo.ZoneInfo.from_file(_ZoneData(data))
    except Exception as error:  # OSError, or ValueError, struct.error, AssertionError and others from a damaged file
        raise Refusal("schedule-time", "This computer's time zone could not be read from /etc/localtime; set the time zone "
                                       "in the system settings, then make the schedule again") from error
    return lambda timestamp: int(datetime.fromtimestamp(timestamp, zone).utcoffset().total_seconds())


class _ZoneData(io.BytesIO):
    """TZif bytes whose reads past the end raise. zoneinfo in Python 3.12 (Ubuntu 24.04's default) reads the last
    line of a version 2 or later file one byte at a time until a newline, so a file cut anywhere in that line,
    even just after its opening newline, would never finish."""

    def read(self, size=-1):
        data = super().read(size)
        if size is not None and size > 0 and not data:
            raise EOFError("the time zone file ends early")
        return data


def host_facts(record, *, writable_by_others=None, purpose="register"):
    """Facts of this computer for a record that schedule_hosts.check_record() accepted.

    For "register" it first refuses a missing interpreter or folder, a folder macOS protects or a Windows path that is
    too long, and files someone else can change (check_writable; on Windows that needs ``writable_by_others`` from
    the caller, or the schedule is refused). For "remove" it skips those checks: the removal flows prove ownership
    themselves, and a schedule whose Python has gone or become unsafe must still be removable.
    """
    platform = native_platform()
    if purpose not in ("register", "remove"):
        raise Refusal("schedule-facts", "host_facts is asked for registration or removal only")
    if record.get("platform") != platform:
        raise Refusal("not-supported", "A schedule is rendered only on the computer it was made for")
    if purpose == "register" and (not os.path.isfile(record["interpreter"]) or not os.path.isdir(record["root"])):
        raise Refusal("schedule-path", "The recorded Python interpreter or PatchCairn folder no longer exists")
    if platform == "windows":
        facts = {"platform": platform, **_windows_identity()}
    else:
        import pwd
        uid = os.getuid()
        try:
            home = pwd.getpwuid(uid).pw_dir
        except KeyError as error:
            raise Refusal("schedule-facts", "This user account has no home folder entry") from error
        facts = {"platform": platform, "uid": uid, "home": home}
        if platform == "linux":
            facts.update(systemctl=next((path for path in SYSTEMCTLS if _root_owned(path)), None),
                         systemd_running=os.path.isdir("/run/systemd/system"), cron_running=_cron_running())
    if purpose == "register":
        check_placement(record, facts.get("home"))
        check_writable(record, writable_by_others=writable_by_others)
    return facts


def check_placement(record, home, *, realpath=os.path.realpath):
    """Refuse a PatchCairn folder too long for Windows, a macOS schedule on another drive (any route), or a launchd
    schedule in a folder macOS protects."""
    if record["platform"] == "windows" and len(record["root"].encode("utf-16-le")) // 2 > WINDOWS_ROOT_LIMIT:
        raise Refusal("schedule-path", f"The PatchCairn folder path is longer than {WINDOWS_ROOT_LIMIT} characters, so files "
                                       "under it would pass the Windows path limit. Move PatchCairn to a shorter path, "
                                       "then make the schedule again.")
    if record["platform"] != "macos":
        return

    def folded(path):  # one spelling: decomposed Unicode, case-folded, and without the data-volume firmlink prefix
        path = unicodedata.normalize("NFD", path).casefold()
        return path[len("/system/volumes/data"):] if path.startswith("/system/volumes/data/") else path
    resolved = {folded(realpath(record["interpreter"])), folded(realpath(record["root"]))}
    paths = resolved | {folded(record["interpreter"]), folded(record["root"])}
    # Resolved forms only: /Volumes/Macintosh HD is a link to this Mac's own disk.
    if any(path == "/volumes" or path.startswith("/volumes/") for path in resolved):
        # A drive with "Ignore ownership" shows every file as the viewer's own, so ownership proves nothing there.
        raise Refusal("schedule-path", "PatchCairn and its Python must be on this Mac's own disk: on another drive macOS may "
                                       "ignore who owns the files, so PatchCairn cannot tell who can change them. Move "
                                       "the PatchCairn folder into your home folder, use a Python on this Mac's own disk, "
                                       "then make the schedule again.")
    if record["route"] != "launchd":
        return
    protected = [folded(home + "/" + name) for name in MACOS_PROTECTED]
    for path in paths:
        if any(path == folder or path.startswith(folder + "/") for folder in protected):
            raise Refusal("schedule-path", "macOS protects Desktop, Documents, Downloads, iCloud Drive and cloud-storage "
                                           "folders, so a schedule started by launchd could not read PatchCairn there. "
                                           "Move the PatchCairn folder elsewhere in your home folder, use a Python "
                                           "that is not in those folders either, then make the schedule again.")


def check_writable(record, *, writable_by_others=None, stat_of=os.stat, list_dir=os.listdir, realpath=os.path.realpath,
                   account=None, runtime=None, list_xattr=None, readlink=os.readlink, mountinfo=None):
    """Refuse when someone other than this user or root could change what the schedule runs.

    The recorded interpreter must be the Python this check runs under (``runtime``: its executable, base prefix and
    standard-library folders, from sys and sysconfig unless a test passes them). Objects checked: the interpreter
    after resolving links; its folder and the recorded path's folder, and the parents of both (where Python reads
    pyvenv.cfg), with any pyvenv.cfg there (a broken link counts); the base prefix (the real Python a venv runs) with
    its top-level files (every top-level entry on Windows, DLLs included); the stdlib and platstdlib folders with
    their top-level entries; the PatchCairn folder; its scripts folder, every entry in it, and scripts/__pycache__
    with its entries (Python reads cached code even with -B); the resolved target of each; and every path a link
    leads through, at any of these or at any folder above them, again for the paths those links lead through (a
    relative target counts from the link's real folder, as the system resolves it). Then every folder above those
    objects up to the filesystem root (on Windows: the drive or share root).
    POSIX: every object and folder above belongs to this user or root and has no group or other write bit, sticky or
    not (a sticky folder still lets anyone create a name that has gone, such as a PatchCairn folder in /tmp after a
    reboot). A group bit is allowed for the macOS admin group (D-045) and for this user's own private group on Linux
    (its name is the user's, it is the user's primary group, nobody else belongs to it, and the path carries no POSIX
    access-control list, whose named entries the group bits would hide). On Linux an object on a mount whose bits do
    not show who else can write (_SHARED_TYPES: WSL's Windows drives, cifs and smb3 shares, VirtualBox folders) is
    refused; the mount comes from /proc/self/mountinfo (``mountinfo`` in tests).
    Windows: a link target's \\\\?\\ or \\??\\ prefix is dropped, and a path not on a drive letter or a network share
    (for example \\\\?\\Volume{...}) is refused without asking.
    ``writable_by_others(path, ancestor)`` must answer False for every object (ancestor False) and every
    folder above and pyvenv.cfg parent (ancestor True). It answers True when the effective DACL grants another SID
    than the owner (this user), SYSTEM (S-1-5-18), Administrators (S-1-5-32-544) or TrustedInstaller any of
    FILE_WRITE_DATA, FILE_APPEND_DATA, WRITE_DAC, WRITE_OWNER, DELETE, GENERIC_WRITE or GENERIC_ALL; inherited entries
    count, inherit-only entries do not apply to the object itself, and a NULL DACL grants everything. It also answers
    True when an account other than this user, SYSTEM, Administrators or TrustedInstaller owns the object, and it may
    answer None or raise when the lookup fails. For ancestor True only FILE_ADD_FILE, FILE_DELETE_CHILD, DELETE,
    WRITE_DAC, WRITE_OWNER, GENERIC_WRITE and GENERIC_ALL count (the add-subfolder right that standard users hold on
    C:\\ does not). Without it the check fails closed. macOS, NFSv4 and SMB access-control lists are not read.
    """
    windows = record["platform"] == "windows"
    if windows and writable_by_others is None:
        raise Refusal("schedule-path", "The check of who can change the Python and PatchCairn files is not available here, "
                                       "so PatchCairn cannot make this schedule safely")
    runtime = runtime or _runtime()
    if realpath(runtime["executable"]) != realpath(record["interpreter"]):
        raise Refusal("schedule-path", "Make the schedule with the Python it will run: PatchCairn is running under another "
                                       "Python than the one this schedule records")
    separator = "\\" if windows else "/"
    interpreter, scripts = realpath(record["interpreter"]), record["root"] + separator + "scripts"
    folders = [_parent(interpreter, separator), _parent(record["interpreter"], separator)]
    venv_parents = list(dict.fromkeys(_parent(folder, separator) for folder in folders))
    cache = scripts + separator + "__pycache__"
    optional = [folder.rstrip(separator) + separator + "pyvenv.cfg" for folder in folders + venv_parents]
    optional += [cache] + [cache + separator + name for name in _entries(list_dir, cache)]
    base = runtime["base_prefix"]
    python = [base, *(path for path in _children(list_dir, base, separator) if windows or _is_file(stat_of, path))]
    optional += [base.rstrip(separator) + separator + "DLLs"] if windows else []
    for folder in dict.fromkeys(path for path in (runtime["stdlib"], runtime["platstdlib"]) if path):
        python += [folder, *_children(list_dir, folder, separator)]
    objects = [interpreter, *folders, record["root"], scripts,
               *(scripts + separator + name for name in _entries(list_dir, scripts, required=True)), *python,
               *(path for path in optional if _present(stat_of, readlink, path))]
    objects = list(dict.fromkeys(objects + [realpath(path) for path in objects]))
    objects += [step for step in _links_on_the_way([record["interpreter"], *objects, *venv_parents], readlink, realpath,
                                                   separator) if step not in objects]
    strict = set(objects) | set(venv_parents)
    above = [folder for path in objects + venv_parents for folder in _ancestors(path, separator) if folder not in strict]
    checks = [(path, False) for path in objects] + [(path, True) for path in dict.fromkeys(venv_parents + above)]
    if windows:
        for path, ancestor in checks:
            if not _WINDOWS_PLAIN.match(path):  # for example \\?\Volume{...}: the check could answer for the wrong object
                raise Refusal("schedule-path", _unsafe_message(path, "unchecked"))
            try:
                answer = writable_by_others(path, ancestor)
            except Exception as error:  # a lookup that fails cannot confirm the path is safe
                raise Refusal("schedule-path", _unsafe_message(path, "unconfirmed")) from error
            if answer is not False:
                raise Refusal("schedule-path", _unsafe_message(path, "write" if answer is True else "unconfirmed"))
        return
    if record["platform"] == "linux":
        _refuse_shared_mounts(objects, mountinfo)
    uid, name, primary, members_of = account or _account()
    groups = {}  # members_of once per group in this check

    def members(gid):
        if gid not in groups:
            groups[gid] = members_of(gid)
        return groups[gid]
    account_facts = (record["platform"], primary, name, members, list_xattr or getattr(os, "listxattr", None))
    for path, _ancestor in checks:
        try:
            info = stat_of(path)
        except OSError as error:
            raise Refusal("schedule-path", f"{path} could not be checked, so nothing was scheduled") from error
        if info.st_uid not in (uid, 0):
            raise Refusal("schedule-path", _unsafe_message(path, "owner"))
        if info.st_mode & 0o002 or (info.st_mode & 0o020 and not _group_ok(path, info.st_gid, *account_facts)):
            raise Refusal("schedule-path", _unsafe_message(path, "write", owned=info.st_uid == uid))


def _refuse_shared_mounts(paths, mountinfo):
    """Refuse a path on a mount of a _SHARED_TYPES file system, from /proc/self/mountinfo (proc(5): mount id, parent
    id, ..., field 5 the mount point; the first field after " - " the type). The mount that covers a path is found as
    the kernel finds it: from the top, the mount on each next folder of the path whose parent is the mount reached so
    far, so a later mount over a parent folder hides the mounts below it, and the last of mounts stacked on one folder
    wins."""
    if mountinfo is None:
        try:
            with open("/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape") as handle:
                mountinfo = handle.read()
        except OSError as error:
            raise Refusal("schedule-path", "PatchCairn could not read /proc/self/mountinfo, so it cannot tell which drive "
                                           "the Python and PatchCairn files are on") from error
    mounts, on = {}, {}
    for line in mountinfo.splitlines():
        left, dash, right = line.partition(" - ")
        fields = left.split()
        if dash and len(fields) >= 5 and right.split():
            point = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
            mounts[fields[0]] = (fields[1], point.rstrip("/") or "/", right.split()[0])
    for ident, (parent, point, _kind) in mounts.items():
        on[(parent if parent in mounts and parent != ident else None, point)] = ident  # None: a top mount
    for path in paths:
        names, current = [name for name in path.split("/") if name], None
        for prefix in ["/"] + ["/" + "/".join(names[:end]) for end in range(1, len(names) + 1)]:
            for _ in range(len(mounts)):  # mounts stacked on one folder; bounded, in case the list is damaged
                if (current, prefix) not in on:
                    break
                current = on[(current, prefix)]
        if current is not None and mounts[current][2] in _SHARED_TYPES:
            raise Refusal("schedule-path", f"{path} is on a Windows drive or a shared folder, where Linux cannot check who "
                                           "can change files. Copy PatchCairn into your Linux home folder (for example "
                                           "~/PatchCairn), use a Python installed inside Linux, then make the schedule again.")


def _group_ok(path, gid, platform, primary, name, members_of, list_xattr):
    """A group-write bit is harmless for the macOS admin group (D-045) or this user's own private group on Linux,
    unless a POSIX access-control list on the path grants others write access behind the group bits."""
    if platform == "macos":
        return gid == MACOS_ADMIN_GID
    if gid != primary:
        return False
    group, members = members_of(gid)
    if group != name or not members <= {name} or list_xattr is None:
        return False
    try:
        return "system.posix_acl_access" not in list_xattr(path)  # follows links, as stat does
    except OSError as error:
        if error.errno in {getattr(errno, code, None) for code in ("ENOTSUP", "EOPNOTSUPP")} - {None}:
            return True  # the file system keeps no access-control lists
        raise Refusal("schedule-path", f"{path} could not be checked, so nothing was scheduled") from error


def _unsafe_message(path, reason, *, owned=False):
    """The refusal: "owner" (another account owns the path), "write" (others can write it), "unconfirmed" or
    "unchecked" (a Windows path on no drive letter or share)."""
    shown = path if path.isprintable() else repr(path)
    if reason == "unchecked":
        return (f"PatchCairn cannot check who can change {shown}, because it is not on a drive letter or a network share, "
                "so it made no schedule. Use a PatchCairn folder and a Python on a drive with a letter, such as C:, then "
                "make the schedule again.")
    if reason == "unconfirmed":
        return (f"PatchCairn could not confirm that only you and the system can change {shown}, so it made no schedule. "
                "Try again; if it happens again, use a PatchCairn folder and a Python in your own folders.")
    remedy = f" You can remove that access with: chmod go-w {shlex.quote(path)}." if owned and path.isprintable() else ""
    first = f"{shown} belongs to another account" if reason == "owner" else f"Other accounts on this computer can change {shown}"
    return (f"{first}, and a schedule would run their changes as you.{remedy} Use a PatchCairn folder and a Python that "
            "belong to you or to the system (for example a Python installed in your home folder), or ask this computer's "
            "administrator to fix that; then make the schedule again.")


def _links_on_the_way(paths, readlink, realpath, separator):
    """Every path a link leads through, at ``paths`` or at any folder above them, and again at the paths those links
    lead through and their folders, until nothing new appears."""
    found, seen, waiting = [], set(), list(paths)
    while waiting:
        path = waiting.pop()
        if path in seen:
            continue
        seen.add(path)
        if len(seen) > 100_000:  # only a damaged or hostile tree gets here: refuse rather than stop looking
            raise Refusal("schedule-path", "There are too many links on the way to the Python and PatchCairn files to "
                                           "check them, so nothing was scheduled")
        steps = _chain(path, readlink, realpath, separator)
        found += steps
        waiting += [*_ancestors(path, separator), *steps]
    return list(dict.fromkeys(found))


def _chain(path, readlink, realpath, separator):
    """Every path a link at ``path`` leads through, in order (at most 40 steps); [] when it is not a link. A relative
    target counts from the real folder of the link, as the system resolves it."""
    join = ntpath if separator == "\\" else posixpath
    found = []
    while len(found) < 40:
        try:
            target = readlink(path)
        except (OSError, ValueError):
            break
        path = join.normpath(join.join(realpath(_parent(path, separator)), _plain(target) if join is ntpath else target))
        if path in found:
            break
        found.append(path)
    return found


def _plain(target):
    """A Windows link target without the \\\\?\\ or \\??\\ prefix that readlink returns before a drive letter or UNC\\
    (https://docs.python.org/3/library/os.html#os.readlink); any other prefixed form stays, and is refused later."""
    for prefix in ("\\\\?\\", "\\??\\"):
        rest = target[len(prefix):] if target.startswith(prefix) else ""
        if rest[:4].upper() == "UNC\\":
            return "\\\\" + rest[4:]
        if re.match(r"[A-Za-z]:\\", rest):
            return rest
    return target


def _parent(path, separator):
    if separator == "\\":
        return ntpath.dirname(path)  # a drive root or a share root is its own parent
    return path.rsplit("/", 1)[0] or "/"


def _ancestors(path, separator):
    found, parent = [], _parent(path, separator)
    while parent != path:
        found.append(parent)
        path, parent = parent, _parent(parent, separator)
    return found


def _children(list_dir, folder, separator):
    return [folder.rstrip(separator) + separator + name for name in _entries(list_dir, folder)]


def _is_file(stat_of, path):
    try:
        return stat.S_ISREG(stat_of(path).st_mode)
    except FileNotFoundError:
        return False
    except OSError:
        return True  # it exists but cannot be read: the check of that path refuses it


def _runtime():
    """The running Python: executable, base prefix (the real Python behind a venv) and standard-library folders."""
    import sysconfig
    return {"executable": sys.executable, "base_prefix": sys.base_prefix, "stdlib": sysconfig.get_path("stdlib"),
            "platstdlib": sysconfig.get_path("platstdlib")}


def _entries(list_dir, folder, *, required=False):
    """The names in ``folder``; a missing folder has none unless it is required."""
    try:
        return sorted(list_dir(folder))
    except FileNotFoundError:
        if required:
            raise Refusal("schedule-path", f"{folder} is missing, so nothing was scheduled") from None
        return []
    except OSError as error:
        raise Refusal("schedule-path", f"{folder} could not be listed, so nothing was scheduled") from error


def _present(stat_of, readlink, path):
    """Whether something is at ``path``: a broken link counts, so its check refuses it (anyone may create its target)."""
    try:
        stat_of(path)
    except FileNotFoundError:
        try:
            readlink(path)
        except (OSError, ValueError):
            return False
        return True
    except OSError:
        return True  # it exists but cannot be read: the check of that path refuses it
    return True


def _account():
    """(uid, user name, primary gid, members_of(gid) -> (group name, member names)) of this POSIX account.

    The members are the group's listed members plus every account whose primary group it is.
    """
    import grp
    import pwd
    uid = os.getuid()
    entry = pwd.getpwuid(uid)

    def members_of(gid):
        try:
            group = grp.getgrgid(gid)
        except KeyError:
            return None, set()
        return group.gr_name, set(group.gr_mem) | {other.pw_name for other in pwd.getpwall() if other.pw_gid == gid}
    return uid, entry.pw_name, entry.pw_gid, members_of


class LocalFiles:
    """The real file system for registration. Tests pass an object with the same methods; each raises OSError."""

    @staticmethod
    def read(path):
        """The bytes of a plain file of at most 1 MB, or None when nothing is there; a link or other entry is refused."""
        try:
            if stat.S_ISLNK(os.lstat(path).st_mode):
                raise OSError(errno.ELOOP, "PatchCairn does not follow a link here", path)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_BYTES:
                raise OSError(errno.EINVAL, "This is not a plain file of at most 1 MB", path)
            return handle.read(_MAX_BYTES + 1)

    @staticmethod
    def exists(path):
        """Whether anything (a file, folder or link) is at ``path``."""
        return os.path.lexists(path)

    @staticmethod
    def write_new(path, data, mode):
        """Create ``path`` with exactly ``mode`` and write ``data``; an existing entry or a link is never replaced."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, mode)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                if hasattr(os, "fchmod"):
                    os.fchmod(handle.fileno(), mode)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(path)
            raise

    @staticmethod
    def remove(path):
        """Delete a plain file; a link or a folder is refused."""
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise OSError(errno.EINVAL, "PatchCairn deletes only a plain file here", path)
        os.unlink(path)

    @staticmethod
    def ensure_dir(path, base):
        """Create the missing folders of the POSIX ``path`` below ``base`` (mode 0700); a link below ``base`` is refused."""
        if not path.startswith(base + "/"):
            raise OSError(errno.EINVAL, "PatchCairn creates folders only inside the home folder", path)
        current = base
        for part in path[len(base):].strip("/").split("/"):
            current = current + "/" + part
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                os.mkdir(current, 0o700)
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise OSError(errno.ENOTDIR, "This is a link or not a folder; PatchCairn does not write there", current)


def _root_owned(path):
    try:
        info = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022


def _cron_running():
    """Whether a cron daemon's pid file names a live process (WSL without an init system starts none)."""
    for path in _CRON_PIDFILES:
        try:
            with open(path, "rb") as handle:
                pid = int(handle.read(32).strip())
        except (OSError, ValueError):
            continue
        if pid > 0 and os.path.isdir(f"/proc/{pid}"):
            return True
    return False


def _windows_identity():
    """The system folder (GetSystemDirectoryW, never PATH), this process's user SID and the code pages.

    An elevated token is refused: what it creates belongs to Administrators, and its user may be another account.
    """
    import ctypes
    from ctypes import wintypes
    kernel32, advapi32 = ctypes.WinDLL("kernel32"), ctypes.WinDLL("advapi32")
    kernel32.GetSystemDirectoryW.argtypes = (wintypes.LPWSTR, wintypes.UINT)
    kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.LocalFree.argtypes, kernel32.LocalFree.restype = (ctypes.c_void_p,), ctypes.c_void_p
    kernel32.GetConsoleOutputCP.restype = kernel32.GetOEMCP.restype = kernel32.GetACP.restype = wintypes.UINT
    advapi32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    advapi32.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD))
    advapi32.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    folder, token, size, text = ctypes.create_unicode_buffer(261), wintypes.HANDLE(), wintypes.DWORD(), ctypes.c_void_p()
    length = kernel32.GetSystemDirectoryW(folder, 261)
    if not 0 < length < 261 or not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise Refusal("schedule-facts", "Windows did not report its system folder or this user account")
    try:
        elevated = wintypes.DWORD()
        if not advapi32.GetTokenInformation(token, 20, ctypes.byref(elevated), 4, ctypes.byref(size)):  # TokenElevation
            raise Refusal("schedule-facts", "Windows did not say whether this session has administrator rights")
        if elevated.value:
            raise Refusal("schedule-facts", "Make the schedule from a session without administrator rights")
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser; this first call gives the size
        if not 8 <= size.value <= 65536:
            raise Refusal("schedule-facts", "Windows did not report this user account")
        user = ctypes.create_string_buffer(size.value)
        if (not advapi32.GetTokenInformation(token, 1, user, size, ctypes.byref(size))
                or not advapi32.ConvertSidToStringSidW(ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.byref(text))):
            raise Refusal("schedule-facts", "Windows did not report this user account")
        try:
            sid = ctypes.wstring_at(text.value)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.CloseHandle(token)
    # Microsoft documents no encoding for schtasks output, and it depends on how the runner starts schtasks, so
    # schedule_hosts tries each of these code pages (console, OEM, ANSI).
    pages = [page for page in (kernel32.GetConsoleOutputCP(), kernel32.GetOEMCP(), kernel32.GetACP()) if page]
    return {"system_dir": folder.value, "user_sid": sid, "code_pages": list(dict.fromkeys(pages))}


def _windows_converter():
    """UTC to local time with this computer's dynamic time zone (kernel32), independent of the process TZ."""
    import ctypes
    from ctypes import wintypes

    class SystemTime(ctypes.Structure):
        _fields_ = [(name, wintypes.WORD) for name in ("year", "month", "weekday", "day", "hour", "minute", "second", "ms")]

    class DynamicZone(ctypes.Structure):  # DYNAMIC_TIME_ZONE_INFORMATION
        _fields_ = [("Bias", wintypes.LONG), ("StandardName", wintypes.WCHAR * 32), ("StandardDate", SystemTime),
                    ("StandardBias", wintypes.LONG), ("DaylightName", wintypes.WCHAR * 32), ("DaylightDate", SystemTime),
                    ("DaylightBias", wintypes.LONG), ("TimeZoneKeyName", wintypes.WCHAR * 128),
                    ("DynamicDaylightTimeDisabled", wintypes.BOOLEAN)]

    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.GetDynamicTimeZoneInformation.argtypes = (ctypes.POINTER(DynamicZone),)
    kernel32.GetDynamicTimeZoneInformation.restype = wintypes.DWORD
    kernel32.SystemTimeToTzSpecificLocalTimeEx.argtypes = (ctypes.POINTER(DynamicZone), ctypes.POINTER(SystemTime),
                                                          ctypes.POINTER(SystemTime))
    kernel32.SystemTimeToTzSpecificLocalTimeEx.restype = wintypes.BOOL
    zone = DynamicZone()
    if kernel32.GetDynamicTimeZoneInformation(ctypes.byref(zone)) == 0xFFFFFFFF:  # TIME_ZONE_ID_INVALID
        raise Refusal("schedule-time", "Windows did not report this computer's time zone")

    def convert(fields):
        year, month, day, hour, minute, second = fields
        utc, local = SystemTime(year, month, 0, day, hour, minute, second, 0), SystemTime()
        if not kernel32.SystemTimeToTzSpecificLocalTimeEx(ctypes.byref(zone), ctypes.byref(utc), ctypes.byref(local)):
            raise Refusal("schedule-time", "Windows could not convert a time to this computer's time zone")
        return local.year, local.month, local.day, local.hour, local.minute, local.second
    return convert
