"""Read-only process runner (layer L2): a closed recipe table, fixed executables and environment, a timeout and an
output bound.

The table is built from package_routes.READ_RECIPES and diagnostic_core.RECIPES; this module defines no command
itself. Callers pass a recipe id and grammar-checked values, never a command line. Executables come from a fixed
allowlist: system tools listed in a POSIX system folder whose resolved file has root-owned ancestry, tools in the
Windows system folder, Homebrew at its documented prefix owned by the current user, and the winget App Execution
Alias (reparse tag 0x8000001B, pointing to App Installer) under the LocalAppData known folder. No shell is used and
nothing that changes software runs here: changing commands are rendered for the coordinator. The stdout bytes
returned are raw manager output for a package_routes or diagnostic parser, never text for a person.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ntpath
import os
from pathlib import PurePosixPath
import signal
import stat
import struct
import subprocess
import sys
import threading
import time

import diagnostic_core
import package_routes
from package_tokens import BREW_PATHS, BREW_REAL_ROOTS, DNF_LINK, RUN_FILES, Slot
from pc_records import Refusal
from private_workspace import PrivateWorkspaceError, ensure_private_directory

POSIX_TOOL_DIRS = frozenset({"/usr/bin", "/bin", "/usr/sbin", "/sbin"})
APT_LISTS = "/var/lib/apt/lists"
# Diagnostic recipes keep the limits and environment of today's diagnostic runner.
DIAGNOSTIC_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
DIAGNOSTIC_TIMEOUT_SECONDS, DIAGNOSTIC_MAX_BYTES = 5, 4096
# A process that ignores the kill is left after this wait rather than turning a hold into an endless wait.
KILL_WAIT_SECONDS = 5
_LOCAL_APPDATA = "F1B32785-6FBA-4FCF-9D55-7B8E7F157091"  # FOLDERID_LocalAppData
_PROGRAM_FILES = "905E63B6-C1BF-494E-B29C-65B732D3D21A"  # FOLDERID_ProgramFiles
WORK_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "work")


def recipes():
    """The closed table {recipe id: "package" or "diagnostic"}."""
    return {**dict.fromkeys(package_routes.READ_RECIPES, "package"), **dict.fromkeys(diagnostic_core.RECIPES, "diagnostic")}


def _diagnostic_command(recipe_id):
    """(executable candidates, fixed arguments) that diagnostic_core publishes for a recipe (its ARGV table, moved
    there from diagnostic_posix by the DIAG leaf); a recipe without one holds."""
    command = getattr(diagnostic_core, "ARGV", {}).get(recipe_id)
    if (not isinstance(command, tuple) or len(command) != 2 or not command[0]
            or not all(isinstance(part, str) and part and "\x00" not in part for part in command[0] + command[1])):
        raise Refusal("runner-recipe-unavailable", "This diagnostic recipe has no fixed command yet; it holds")
    return command


def appexec_strings(buffer):
    """The package id, app id and target path of an APPEXECLINK reparse buffer (layout from public research, not
    documented: tag, data length, reserved, version, then NUL-separated UTF-16 strings); None when it does not parse."""
    if len(buffer) < 12 or int.from_bytes(buffer[:4], "little") != package_routes.WINGET_TAG:
        return None
    try:
        strings = bytes(buffer[12:8 + int.from_bytes(buffer[4:6], "little")]).decode("utf-16-le").split("\x00")
    except UnicodeDecodeError:
        return None
    return strings[:3] if len(strings) >= 3 and all(strings[:3]) else None


class HostProbe:
    """The facts executable resolution and the environment read from this computer; tests pass a fake with the same
    methods, so no test starts a package manager."""

    platform = sys.platform

    def elevation(self):
        """None, or "root", "elevated" or "system" for the running process."""
        if os.name != "nt":
            return "root" if os.geteuid() == 0 else None
        import ctypes
        from ctypes import wintypes
        advapi, kernel = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.POINTER(wintypes.DWORD)]
        advapi.IsWellKnownSid.argtypes = [ctypes.c_void_p, ctypes.c_int]
        token, elevated, size, user = wintypes.HANDLE(), wintypes.DWORD(), wintypes.DWORD(), ctypes.create_string_buffer(256)
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
            raise Refusal("runner-elevation-unknown", "The process token could not be read; package routes hold")
        try:
            # TokenElevation (20) and TokenUser (1), whose first field is the user's SID.
            if (not advapi.GetTokenInformation(token, 20, ctypes.byref(elevated), 4, ctypes.byref(size))
                    or not advapi.GetTokenInformation(token, 1, user, len(user), ctypes.byref(size))):
                raise Refusal("runner-elevation-unknown", "The process token could not be read; package routes hold")
            if advapi.IsWellKnownSid(ctypes.c_void_p.from_buffer(user).value, 22):  # WinLocalSystemSid
                return "system"
            return "elevated" if elevated.value else None
        finally:
            kernel.CloseHandle(token)

    def euid(self):
        return os.geteuid()

    def identity(self):
        """(home folder, account name) from the password database."""
        import pwd
        entry = pwd.getpwuid(os.geteuid())
        return entry.pw_dir, entry.pw_name

    def machine(self):
        """os.uname().machine, or on macOS "x86_64-rosetta" for an Intel process translated by Rosetta (sysctl.proc_translated)."""
        if self.platform != "darwin":
            return os.uname().machine
        import ctypes
        machine, value, size = os.uname().machine, ctypes.c_int(0), ctypes.c_size_t(4)
        translated = ctypes.CDLL(None).sysctlbyname(b"sysctl.proc_translated", ctypes.byref(value), ctypes.byref(size), None, 0) == 0
        return "x86_64-rosetta" if machine == "x86_64" and translated and value.value == 1 else machine

    def realpath(self, path):
        return os.path.realpath(path)

    def lstat(self, path):
        return os.lstat(path)

    def environ(self):
        return dict(os.environ)

    def known_folder(self, guid):
        """A known folder through SHGetKnownFolderPath, never from the environment."""
        import ctypes
        import uuid
        from ctypes import wintypes
        shell32, ole32 = ctypes.WinDLL("shell32"), ctypes.WinDLL("ole32")
        folder_id = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID(guid).bytes_le)
        shell32.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
        shell32.SHGetKnownFolderPath.restype = ctypes.c_long
        ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        pointer = ctypes.c_void_p()
        try:
            if shell32.SHGetKnownFolderPath(ctypes.addressof(folder_id), 0, None, ctypes.byref(pointer)) != 0 or not pointer.value:
                raise Refusal("runner-known-folder", "A Windows known folder is not available")
            return ctypes.wstring_at(pointer.value)
        finally:
            ole32.CoTaskMemFree(pointer)

    def local_appdata(self):
        return self.known_folder(_LOCAL_APPDATA)

    def program_files(self):
        """FOLDERID_ProgramFiles; a 32-bit process would get Program Files (x86), not App Installer's folder, so it holds."""
        if struct.calcsize("P") < 8:
            raise Refusal("runner-32-bit", "PatchCairn needs a 64-bit Python to check winget; start it with a 64-bit Python")
        return self.known_folder(_PROGRAM_FILES)

    def private_folder(self, path):
        """path as an existing private folder inside PatchCairn's work folder (private_workspace), else a hold."""
        try:
            return str(ensure_private_directory(path, boundary=WORK_FOLDER))
        except PrivateWorkspaceError as error:
            raise Refusal("runner-run-folder", "winget's output folder must be a private folder inside PatchCairn's work folder") from error

    def _reparse(self, path, query):
        """Open path itself (FILE_FLAG_OPEN_REPARSE_POINT) and return query(kernel, handle), or None when it cannot open."""
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                       wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        # FILE_READ_ATTRIBUTES, share all, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS.
        handle = kernel.CreateFileW(path, 0x80, 7, None, 3, 0x00200000 | 0x02000000, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            return None
        try:
            return query(ctypes, wintypes, kernel, handle)
        finally:
            kernel.CloseHandle(handle)

    def reparse_tag(self, path):
        """The reparse tag of path itself, 0 when it is not a reparse point, None when it cannot be read."""
        def query(ctypes, wintypes, kernel, handle):
            kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            info = (wintypes.DWORD * 2)()  # FILE_ATTRIBUTE_TAG_INFO: FileAttributes, ReparseTag
            if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):  # FileAttributeTagInfo
                return None
            return info[1] if info[0] & 0x400 else 0  # FILE_ATTRIBUTE_REPARSE_POINT
        return self._reparse(path, query)

    def appexec_link(self, path):
        """The strings of an App Execution Alias (FSCTL_GET_REPARSE_POINT on the alias itself), or None."""
        def query(ctypes, wintypes, kernel, handle):
            kernel.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                               wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
            buffer, size = ctypes.create_string_buffer(16384), wintypes.DWORD()
            if not kernel.DeviceIoControl(handle, 0x000900A8, None, 0, buffer, len(buffer), ctypes.byref(size), None):
                return None
            return appexec_strings(buffer.raw[:size.value])
        return self._reparse(path, query)

    def system_directory(self):
        """The Windows system folder from GetSystemDirectoryW."""
        import ctypes
        buffer = ctypes.create_unicode_buffer(260)
        length = ctypes.WinDLL("kernel32").GetSystemDirectoryW(buffer, len(buffer))
        if not 0 < length < len(buffer):
            raise Refusal("runner-system-folder", "The Windows system folder is not available")
        return buffer.value

    def newest_release(self, folder):
        """The newest modification time of the regular *_InRelease and *_Release files in folder (apt stamps them with
        the archive's Last-Modified time, which errs on the stale side), or None."""
        with os.scandir(folder) as entries:
            return max((entry.stat(follow_symlinks=False).st_mtime for entry in entries
                        if entry.is_file(follow_symlinks=False) and entry.name.endswith(("_InRelease", "_Release"))), default=None)


def _root_owned(path, probe):
    """A regular executable file that only root can change, in folders that only root can change, up to /."""
    info = probe.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111:
        return False
    for folder in PurePosixPath(path).parents:
        parent = probe.lstat(str(folder))
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            return False
    return True


def _system_tool(candidates, probe):
    """The first candidate that is a system tool: in the Windows system folder (a plain file, not a reparse point), or
    listed in a POSIX system folder with a resolved file of root-owned ancestry (such as /usr/lib/cargo/bin/coreutils)."""
    for candidate in candidates:
        try:
            if probe.platform == "win32":
                path = ntpath.join(probe.system_directory(), candidate)
                if (ntpath.basename(candidate) == candidate and candidate.lower().endswith(".exe")
                        and stat.S_ISREG(probe.lstat(path).st_mode) and probe.reparse_tag(path) == 0):
                    return path
                continue
            listed = PurePosixPath(candidate).is_absolute() and str(PurePosixPath(candidate).parent) in POSIX_TOOL_DIRS
            if listed and _root_owned(probe.realpath(candidate), probe):
                return candidate
        except (OSError, ValueError, TypeError):
            continue
    raise Refusal("runner-executable", "No listed system tool owned by root was found; the recipe holds")


def _brew(probe):
    """brew at the documented prefix for this machine: a file owned by this account and not writable by others, its link
    owned by this account or root, and every folder from / to both owned by this account or root, not writable by others."""
    machine = probe.machine() if probe.platform == "darwin" else None
    path, root = BREW_PATHS.get(machine), BREW_REAL_ROOTS.get(machine)
    try:
        real, euid = probe.realpath(path), probe.euid()
        info, link = probe.lstat(real), probe.lstat(path)
        folders = [probe.lstat(folder) for folder in sorted({str(f) for name in (path, real) for f in PurePosixPath(name).parents})]
    except (OSError, TypeError, ValueError):
        path = None
    if (path is None or euid == 0 or not PurePosixPath(real).is_relative_to(root) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != euid or info.st_mode & 0o022 or link.st_uid not in (euid, 0)
            or any(not stat.S_ISDIR(f.st_mode) or f.st_uid not in (euid, 0) or f.st_mode & 0o002 for f in folders)):
        raise Refusal("runner-executable", "PatchCairn runs under Rosetta; start it with a native arm64 Python" if "rosetta" in str(machine)
                      else "Homebrew is not at its documented prefix, owned by this account and protected from others "
                           "(Homebrew on Linux and other prefixes hold)")
    return path


def winget_executable(probe=None):
    """The winget alias {"path", "package"}: reparse tag 0x8000001B and an alias of App Installer's winget
    (Microsoft.DesktopAppInstaller_8wekyb3d8bbwe, target <ProgramFiles>\\WindowsApps\\<package folder>\\winget.exe)."""
    probe = probe or HostProbe()
    if probe.platform != "win32":
        raise Refusal("runner-executable", "winget runs only on Windows")
    path = package_routes.winget_alias_path(probe.local_appdata())
    link = probe.appexec_link(path) if probe.reparse_tag(path) == package_routes.WINGET_TAG else None
    folder = ntpath.basename(ntpath.dirname(link[2])) if link else ""
    if (not link or link[0] != package_routes.WINGET_PACKAGE or not package_routes.WINGET_FOLDER.fullmatch(folder)
            or link[2].lower() != ntpath.join(probe.program_files(), "WindowsApps", folder, "winget.exe").lower()):
        raise Refusal("runner-executable", "The winget alias is missing or does not point to App Installer's winget")
    return {"path": path, "package": folder}


def _prepare(recipe_id, values, probe, run_folder):
    """(argv, environment, timeout, output bound, expected exit codes, working folder) for one table entry."""
    kind = recipes().get(recipe_id) if isinstance(recipe_id, str) else None
    if kind is None:
        raise Refusal("runner-unknown-recipe", "Only recipe ids from the closed table are run")
    if kind == "diagnostic":
        if values:
            raise Refusal("runner-recipe-values", "Diagnostic recipes take no values")
        candidates, arguments = _diagnostic_command(recipe_id)
        executable, env, folder = _system_tool(candidates, probe), dict(DIAGNOSTIC_ENV), "/"
        if probe.platform == "win32":
            folder = probe.system_directory()
            windows = ntpath.dirname(folder.rstrip(ntpath.sep))
            env = {"SystemRoot": windows, "windir": windows, "PATH": f"{folder};{windows}"}
        return (executable,) + tuple(arguments), env, DIAGNOSTIC_TIMEOUT_SECONDS, DIAGNOSTIC_MAX_BYTES, frozenset({0}), folder
    found = package_routes.READ_RECIPES[recipe_id]
    package_routes.refuse_elevated(probe.elevation())
    if any(isinstance(element, Slot) and element.name in RUN_FILES for element in found.template):
        run_folder = probe.private_folder(run_folder)
    if found.executable == "winget":
        executable, folder = winget_executable(probe)["path"], probe.system_directory()
        env = package_routes.environment("winget", windows=probe.environ(), system_dir=folder)
    else:
        if found.manager == "dnf":
            package_routes.dnf_flavor(probe.realpath(DNF_LINK))
        executable = _brew(probe) if found.executable == "brew" else _system_tool((found.executable,), probe)
        try:
            home, user = probe.identity()
        except (KeyError, OSError) as error:
            raise Refusal("runner-identity", "This account has no password-database entry; package routes hold") from error
        env, folder = package_routes.environment(found.manager, home=home, user=user), "/"
    argv = package_routes.render(recipe_id, values, executable=executable, run_folder=run_folder)
    return argv, env, package_routes.READ_TIMEOUT_SECONDS, package_routes.MAX_OUTPUT_BYTES, found.ok_exits, folder


def run_recipe(recipe_id, values=None, *, run_folder=None, launcher=None, probe=None):
    """Run one read-only recipe from the closed table with grammar-checked values (winget's output file goes into
    run_folder, a private folder inside PatchCairn's work folder). Returns {"recipe", "exit_code" (code & 0xFFFFFFFF),
    "ok" (an expected exit code), "stdout" (bounded bytes)}. A refused recipe, executable, value, folder or elevation, a
    timeout and an output over the bound raise Refusal."""
    argv, env, timeout, limit, ok_exits, folder = _prepare(recipe_id, values, probe or HostProbe(), run_folder)
    code, data = (launcher or _launch)(argv, env=env, cwd=folder, timeout=timeout, max_bytes=limit)
    if type(code) is not int or not isinstance(data, bytes) or len(data) > limit:
        raise Refusal("runner-result", "The process result is not an exit code and bounded output")
    return {"recipe": recipe_id, "exit_code": code & 0xFFFFFFFF, "ok": code & 0xFFFFFFFF in ok_exits, "stdout": data}


def package_list_time(manager, *, probe=None):
    """When the manager's package lists last changed (UTC text), where that is observable: apt's newest *_InRelease or
    *_Release file in /var/lib/apt/lists. Other managers return None: their age is reported as unknown, never current."""
    if manager not in package_routes.MANAGERS:
        raise Refusal("package-manager", "Not a package manager PatchCairn routes")
    try:
        newest = (probe or HostProbe()).newest_release(APT_LISTS) if manager == "apt" else None
    except OSError:
        newest = None
    if newest is None:
        return None
    return datetime.fromtimestamp(newest, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _launch(argv, *, env, cwd, timeout, max_bytes):
    """Start argv (a list, no shell) with stdin from the null device, stderr discarded and stdout read up to max_bytes;
    a process past its timeout or bound is killed (on POSIX its whole session, also when only a descendant still holds
    stdout) and the recipe holds."""
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
    try:
        process = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=env, cwd=cwd, shell=False, **options)
    except OSError as error:
        raise Refusal("runner-start", "The read-only command could not be started; it holds") from error
    chunks, size = [], [0]

    def read():
        while size[0] <= max_bytes:
            chunk = process.stdout.read1(65536)
            if not chunk:
                return
            chunks.append(chunk)
            size[0] += len(chunk)

    reader, deadline, held = threading.Thread(target=read, daemon=True), time.monotonic() + timeout, True
    try:
        reader.start()
        reader.join(timeout)
        if size[0] > max_bytes:
            raise Refusal("runner-output-too-large", "The read-only command printed more than its output bound; it holds")
        try:
            if reader.is_alive():
                raise subprocess.TimeoutExpired(argv, timeout)
            code, held = process.wait(timeout=max(deadline - time.monotonic(), 0.1)), False
            return code, b"".join(chunks)
        except subprocess.TimeoutExpired:
            raise Refusal("runner-timeout", "The read-only command did not finish in time; it holds") from None
    finally:
        if held or process.poll() is None:
            try:
                if os.name == "nt":
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=KILL_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        reader.join(KILL_WAIT_SECONDS)
        if not reader.is_alive():  # a descendant still holding the pipe would block close(); the daemon reader is left
            process.stdout.close()
