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
import os
import re
import shlex
import stat
import sys
import unicodedata
import zoneinfo

from pc_records import Refusal

SYSTEMCTLS = ("/usr/bin/systemctl", "/bin/systemctl")
# The PatchCairn folder's longest rendered path is <root>\work\schedules\<id16>\task.xml (41 more characters);
# MAX_PATH is 260 including the terminating NUL unless long paths are enabled, which they are not by default
# (https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation).
WINDOWS_ROOT_LIMIT = 259 - 41
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
            zone = zoneinfo.ZoneInfo.from_file(handle)
    except (OSError, ValueError) as error:
        raise Refusal("schedule-time", "This computer's time zone could not be read from /etc/localtime; set the time zone "
                                       "in the system settings, then make the schedule again") from error
    return lambda timestamp: int(datetime.fromtimestamp(timestamp, zone).utcoffset().total_seconds())


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
    """Refuse a PatchCairn folder that is too long for Windows, or a launchd schedule in a folder macOS protects."""
    if record["platform"] == "windows" and len(record["root"]) > WINDOWS_ROOT_LIMIT:
        raise Refusal("schedule-path", f"The PatchCairn folder path is longer than {WINDOWS_ROOT_LIMIT} characters, so files "
                                       "under it would pass the Windows path limit. Move PatchCairn to a shorter path, "
                                       "then make the schedule again.")
    if record["platform"] != "macos" or record["route"] != "launchd":
        return

    def folded(path):  # one spelling: decomposed Unicode, case-folded, and without the data-volume firmlink prefix
        path = unicodedata.normalize("NFD", path).casefold()
        return path[len("/system/volumes/data"):] if path.startswith("/system/volumes/data/") else path
    protected = [folded(home + "/" + name) for name in MACOS_PROTECTED] + ["/volumes"]
    for path in {record["interpreter"], record["root"], realpath(record["interpreter"]), realpath(record["root"])}:
        if any(folded(path) == folder or folded(path).startswith(folder + "/") for folder in protected):
            raise Refusal("schedule-path", "macOS protects Desktop, Documents, Downloads, iCloud Drive, cloud-storage folders "
                                           "and other drives, so a schedule started by launchd could not read PatchCairn "
                                           "there. Move the PatchCairn folder elsewhere in your home folder, use a Python "
                                           "that is not in those folders either, then make the schedule again.")


def check_writable(record, *, writable_by_others=None, stat_of=os.stat, list_dir=os.listdir, realpath=os.path.realpath,
                   account=None, runtime=None, list_xattr=None):
    """Refuse when someone other than this user or root could change what the schedule runs.

    The recorded interpreter must be the Python this check runs under (``runtime``: its executable, base prefix and
    standard-library folders, from sys and sysconfig unless a test passes them). Objects checked: the interpreter
    after resolving links; its folder and the recorded path's folder, and the parents of both (where Python reads
    pyvenv.cfg), with any pyvenv.cfg there; the base prefix (the real Python a venv runs) with its top-level files
    (every top-level entry on Windows, DLLs included); the stdlib and platstdlib folders with their top-level entries;
    the PatchCairn folder; its scripts folder, every entry in it, and scripts/__pycache__ with its entries (Python
    reads cached code even with -B); and each of these again after resolving links. Then every folder above those
    objects up to the filesystem root (on Windows: the volume root).
    POSIX: an object's owner is this user or root, with no group or other write bit; a group bit is allowed for the
    macOS admin group (D-045) and for this user's own private group on Linux (its name is the user's, it is the
    user's primary group, nobody else belongs to it, and the path carries no POSIX access-control list, whose named
    entries the group bits would hide). A folder above may also be writable when its sticky bit is set, except the
    pyvenv.cfg parents, where anyone with write access could add the file.
    Windows: ``writable_by_others(path, ancestor)`` must answer False for every object (ancestor False) and every
    folder above and pyvenv.cfg parent (ancestor True). It answers True when the effective DACL grants another SID
    than the owner (this user), SYSTEM (S-1-5-18), Administrators (S-1-5-32-544) or TrustedInstaller any of
    FILE_WRITE_DATA, FILE_APPEND_DATA, WRITE_DAC, WRITE_OWNER, DELETE, GENERIC_WRITE or GENERIC_ALL; inherited entries
    count, inherit-only entries do not apply to the object itself, and a NULL DACL grants everything. It also answers
    True when another account owns the object or the lookup fails. For ancestor True only FILE_ADD_FILE,
    FILE_DELETE_CHILD, DELETE, WRITE_DAC and WRITE_OWNER count (the add-subfolder right that standard users hold on
    C:\\ does not). Without it the check fails closed. macOS access-control lists are not read.
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
               *(path for path in optional if _present(stat_of, path))]
    objects = list(dict.fromkeys(objects + [realpath(path) for path in objects]))  # a link's target is checked too
    strict = set(objects) | set(venv_parents)
    above = [folder for path in objects + venv_parents for folder in _ancestors(path, separator) if folder not in strict]
    checks = [(path, False) for path in objects] + [(path, True) for path in dict.fromkeys(venv_parents + above)]
    if windows:
        for path, ancestor in checks:
            if writable_by_others(path, ancestor) is not False:
                raise Refusal("schedule-path", _unsafe_message(path, None))
        return
    uid, name, primary, members_of = account or _account()
    account_facts = (record["platform"], primary, name, members_of, list_xattr or getattr(os, "listxattr", None))
    for path, ancestor in checks:
        try:
            info = stat_of(path)
        except OSError as error:
            raise Refusal("schedule-path", f"{path} could not be checked, so nothing was scheduled") from error
        mode, sticky = info.st_mode, ancestor and path not in venv_parents and info.st_mode & stat.S_ISVTX
        if info.st_uid not in (uid, 0) or (not sticky and (mode & 0o002 or (
                mode & 0o020 and not _group_ok(path, info.st_gid, *account_facts)))):
            raise Refusal("schedule-path", _unsafe_message(path, info.st_uid == uid))


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


def _unsafe_message(path, owned):
    remedy = f" You can remove that access with: chmod go-w {shlex.quote(path)}." if owned and path.isprintable() else ""
    path = path if path.isprintable() else repr(path)
    return (f"Other accounts on this computer can change {path}, and a schedule would run their changes as you.{remedy} "
            "Use a PatchCairn folder and a Python that only you or the administrator can change (for example a Python "
            "installed in your home folder), or ask this computer's administrator to remove that access; then make the "
            "schedule again.")


def _parent(path, separator):
    head = path.rsplit(separator, 1)[0]
    if separator == "/":
        return head or "/"
    return head + "\\" if len(head) == 2 and head[1] == ":" else head


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


def _present(stat_of, path):
    try:
        stat_of(path)
    except FileNotFoundError:
        return False
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
