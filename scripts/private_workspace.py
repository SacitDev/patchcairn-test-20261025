"""Create/admit private artifact namespaces without repairing existing permissions.

Windows uses the current process token and native protected security descriptors;
POSIX requires actual effective-user ownership and 0700/0600 modes, plus a native
filesystem gate on Linux and absent/empty extended-ACL admission on Darwin. No SID, ACL,
account name, native error text or supplied path is included in refusal messages.
This cooperative boundary excludes the same user and privileged administrators.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import stat
import sys


class PrivateWorkspaceError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _hold(code):
    raise PrivateWorkspaceError(code)


def _absolute(path, boundary=None):
    try:
        raw = os.fspath(path)
    except (TypeError, OSError):
        _hold("private-path-invalid")
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        _hold("private-path-invalid")
    value = Path(raw)
    if not value.is_absolute() or ".." in value.parts:
        _hold("private-path-invalid")
    if os.name == "nt":
        if not re.match(r"\A[A-Za-z]:\\", raw) or raw.startswith("\\\\") or len(raw) > 240:
            _hold("private-local-path-required")
        for part in value.parts[1:]:
            if (not part or part in {".", ".."} or part[-1:] in {".", " "}
                    or re.search(r'[/:*?<>|"\x00-\x1f]', part)
                    or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?", part)):
                _hold("private-path-invalid")
    value = value.absolute()
    if value == value.parent:
        _hold("private-root-refused")
    if boundary is not None:
        limit = _absolute(boundary)
        try:
            value.relative_to(limit)
        except ValueError:
            _hold("private-boundary-escape")
    return value


class _Info(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
                ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
                ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                ("id_high", wintypes.DWORD), ("id_low", wintypes.DWORD)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                ("inherit_handle", wintypes.BOOL)]


class _ACL(ctypes.Structure):
    _fields_ = [("revision", ctypes.c_ubyte), ("reserved", ctypes.c_ubyte),
                ("size", wintypes.WORD), ("count", wintypes.WORD), ("reserved2", wintypes.WORD)]


class _ACE(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_ubyte), ("flags", ctypes.c_ubyte),
                ("size", wintypes.WORD), ("mask", wintypes.DWORD)]


class _WindowsSecurity:
    """Narrow Win32 bindings; deliberately no permission-editing API."""
    def __init__(self):
        if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
            _hold("private-windows-api-unavailable")
        try:
            self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        except OSError:
            _hold("private-windows-api-unavailable")
        pointer = ctypes.c_void_p
        self._bind(self.kernel, "GetCurrentProcess", [], wintypes.HANDLE)
        self._bind(self.kernel, "CloseHandle", [wintypes.HANDLE], wintypes.BOOL)
        self._bind(self.kernel, "LocalFree", [pointer], pointer)
        self._bind(self.kernel, "CreateFileW", [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                   pointer, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE)
        self._bind(self.kernel, "CreateDirectoryW", [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)], wintypes.BOOL)
        self._bind(self.kernel, "GetFileInformationByHandle", [wintypes.HANDLE, ctypes.POINTER(_Info)], wintypes.BOOL)
        self._bind(self.kernel, "GetFinalPathNameByHandleW", [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD], wintypes.DWORD)
        self._bind(self.kernel, "GetFileType", [wintypes.HANDLE], wintypes.DWORD)
        self._bind(self.kernel, "GetDriveTypeW", [wintypes.LPCWSTR], wintypes.UINT)
        self._bind(self.kernel, "GetVolumeInformationByHandleW", [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD,
                   ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                   wintypes.LPWSTR, wintypes.DWORD], wintypes.BOOL)
        self._bind(self.kernel, "WriteFile", [wintypes.HANDLE, pointer, wintypes.DWORD,
                   ctypes.POINTER(wintypes.DWORD), pointer], wintypes.BOOL)
        self._bind(self.kernel, "FlushFileBuffers", [wintypes.HANDLE], wintypes.BOOL)
        self._bind(self.advapi, "OpenProcessToken", [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL)
        self._bind(self.advapi, "GetTokenInformation", [wintypes.HANDLE, ctypes.c_int, pointer,
                   wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
        self._bind(self.advapi, "ConvertSidToStringSidW", [pointer, ctypes.POINTER(pointer)], wintypes.BOOL)
        self._bind(self.advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [wintypes.LPCWSTR,
                   wintypes.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
        self._bind(self.advapi, "GetSecurityInfo", [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                   ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer)], wintypes.DWORD)
        self._bind(self.advapi, "GetSecurityDescriptorControl", [pointer, ctypes.POINTER(wintypes.WORD),
                   ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
        self._bind(self.advapi, "IsValidAcl", [pointer], wintypes.BOOL)
        self._bind(self.advapi, "GetAce", [pointer, wintypes.DWORD, ctypes.POINTER(pointer)], wintypes.BOOL)
        self._bind(self.advapi, "IsValidSid", [pointer], wintypes.BOOL)
        self._bind(self.advapi, "GetLengthSid", [pointer], wintypes.DWORD)
        self.user = self._token_user()
        self.allowed = {self.user, "S-1-5-18", "S-1-5-32-544"}

    @staticmethod
    def _bind(library, name, arguments, result):
        try:
            function = getattr(library, name)
        except AttributeError:
            _hold("private-windows-api-unavailable")
        function.argtypes, function.restype = arguments, result

    def close(self, handle):
        if handle not in (None, 0, ctypes.c_void_p(-1).value):
            self.kernel.CloseHandle(handle)

    def _sid_text(self, sid):
        if not sid or not self.advapi.IsValidSid(sid):
            _hold("private-owner-or-acl-invalid")
        text = ctypes.c_void_p()
        if not self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            _hold("private-owner-or-acl-unavailable")
        try:
            return ctypes.wstring_at(text)
        finally:
            self.kernel.LocalFree(text)

    def _token_user(self):
        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            _hold("private-token-unavailable")
        try:
            size = wintypes.DWORD()
            self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not 8 <= size.value <= 65536:
                _hold("private-token-unavailable")
            buffer = ctypes.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                _hold("private-token-unavailable")
            return self._sid_text(ctypes.c_void_p.from_buffer(buffer).value)
        finally:
            self.close(token)

    @contextmanager
    def descriptor(self, *, directory):
        inherit = "OICI" if directory else ""
        # This text remains in memory. Never include it or its identities in errors/evidence.
        principals = list(dict.fromkeys((self.user, "S-1-5-18", "S-1-5-32-544")))
        sddl = "O:" + self.user + "D:P" + "".join("(A;" + inherit + ";FA;;;" + sid + ")" for sid in principals)
        descriptor = ctypes.c_void_p()
        size = wintypes.DWORD()
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)):
            _hold("private-descriptor-unavailable")
        try:
            yield _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        finally:
            self.kernel.LocalFree(descriptor)

    def info(self, handle, path, *, directory):
        info = _Info()
        if not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)) or self.kernel.GetFileType(handle) != 1:
            _hold("private-file-metadata-unavailable")
        if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory or (not directory and info.links != 1):
            _hold("private-link-or-type-refused")
        buffer = ctypes.create_unicode_buffer(32768)
        count = self.kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not 0 < count < len(buffer) or not buffer.value.startswith("\\\\?\\"):
            _hold("private-canonical-path-unavailable")
        if buffer.value[4:].rstrip("\\").casefold() != str(path).rstrip("\\").casefold():
            _hold("private-canonical-path-mismatch")
        return info

    def open(self, path, *, directory, security=False, missing=False):
        handle = self.kernel.CreateFileW(str(path), 0x80 | (0x20000 if security else 0),
                                        3, None, 3, 0x02200000, None)
        if handle == ctypes.c_void_p(-1).value:
            error = ctypes.get_last_error()
            if missing and error in (2, 3):
                return None
            _hold("private-path-access-refused")
        try:
            self.info(handle, path, directory=directory)
            return handle
        except BaseException:
            self.close(handle)
            raise

    def validate(self, handle, *, directory):
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        result = self.advapi.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None,
                                             ctypes.byref(dacl), None, ctypes.byref(descriptor))
        try:
            if result or not descriptor.value or not dacl.value:
                _hold("private-dacl-unavailable-or-null")
            control, revision = wintypes.WORD(), wintypes.DWORD()
            if not self.advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
                _hold("private-dacl-unavailable")
            if not control.value & 4 or (directory and not control.value & 0x1000):
                _hold("private-dacl-unprotected")
            if self._sid_text(owner) != self.user:
                _hold("private-owner-refused")
            if not self.advapi.IsValidAcl(dacl):
                _hold("private-dacl-invalid")
            acl = ctypes.cast(dacl, ctypes.POINTER(_ACL)).contents
            if not 1 <= acl.count <= 256:
                _hold("private-dacl-unsupported")
            user_access = False
            user_inheritance = not directory
            for index in range(acl.count):
                address = ctypes.c_void_p()
                if not self.advapi.GetAce(dacl, index, ctypes.byref(address)):
                    _hold("private-dacl-unavailable")
                ace = ctypes.cast(address, ctypes.POINTER(_ACE)).contents
                if ace.kind != 0 or ace.flags & ~0x13 or ace.size < 16:
                    _hold("private-dacl-unsupported")
                sid = address.value + 8
                if not self.advapi.IsValidSid(sid) or self.advapi.GetLengthSid(sid) > ace.size - 8:
                    _hold("private-dacl-invalid")
                principal = self._sid_text(sid)
                if principal not in self.allowed:
                    _hold("private-dacl-broad-or-unknown")
                if principal == self.user and (ace.mask & 0x1F01FF == 0x1F01FF or ace.mask & 0x10000000):
                    user_access = True
                    if ace.flags & 3 == 3:
                        user_inheritance = True
            if not user_access or not user_inheritance:
                _hold("private-dacl-inheritance-or-access-refused")
            serial, maximum, flags = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
            if not self.kernel.GetVolumeInformationByHandleW(handle, None, 0, ctypes.byref(serial),
                        ctypes.byref(maximum), ctypes.byref(flags), None, 0) or not flags.value & 8:
                _hold("private-persistent-acl-unavailable")
        finally:
            if descriptor.value:
                self.kernel.LocalFree(descriptor)

    def create_directory(self, path):
        with self.descriptor(directory=True) as attributes:
            if not self.kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
                _hold("private-directory-create-refused")


@contextmanager
def _windows_directory(path, *, create, parents, exist_ok):
    api = _WindowsSecurity()
    if api.kernel.GetDriveTypeW(path.anchor) != 3:
        _hold("private-fixed-local-volume-required")
    held = []
    try:
        current = Path(path.anchor)
        held.append(api.open(current, directory=True))
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            current /= part
            target = index == len(parts) - 1
            handle = api.open(current, directory=True, security=target, missing=True)
            if handle is None:
                if not create or (not target and not parents):
                    _hold("private-directory-missing")
                api.create_directory(current)
                handle = api.open(current, directory=True, security=True)
                held.append(handle)
                api.validate(handle, directory=True)
            else:
                held.append(handle)
                if target:
                    if create and not exist_ok:
                        _hold("private-directory-exists")
                    api.validate(handle, directory=True)
        yield path
        api.info(held[-1], path, directory=True)
        api.validate(held[-1], directory=True)
    finally:
        for handle in reversed(held):
            api.close(handle)


def _posix_info(path, *, directory, private):
    _posix_capability()
    try:
        info = path.lstat()
    except OSError:
        _hold("private-path-access-refused")
    if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) or (not directory and info.st_nlink != 1):
        _hold("private-link-or-type-refused")
    if private and (not hasattr(os, "geteuid") or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)):
        _hold("private-owner-or-mode-refused")
    if private and sys.platform.startswith("linux"):
        _linux_filesystem(path)
    if private and sys.platform == "darwin":
        _darwin_filesystem(path)
        checker, refusal = _darwin_checker()
        try:
            checker(path)
        except refusal as error:
            code = getattr(error, "code", "")
            _hold("private-" + code if isinstance(code, str) and re.fullmatch(r"darwin-acl-[a-z-]{1,60}", code) else "private-darwin-acl-refused")
    return info


def _darwin_checker():
    try:
        from darwin_privacy import assert_no_extended_acl, DarwinPrivacyHold
    except ImportError:
        _hold("private-darwin-acl-capability-unavailable")
    return assert_no_extended_acl, DarwinPrivacyHold


def _darwin_filesystem(path):
    try:
        from darwin_privacy import assert_private_filesystem, DarwinPrivacyHold
    except ImportError:
        _hold("private-darwin-fs-capability-unavailable")
    try:
        assert_private_filesystem(path)
    except DarwinPrivacyHold as error:
        code = getattr(error, "code", "")
        _hold("private-" + code if isinstance(code, str) and re.fullmatch(r"darwin-fs-[a-z-]{1,60}", code) else "private-darwin-fs-refused")


def _linux_checker():
    try:
        from linux_privacy import assert_native_private_filesystem, LinuxPrivacyHold
    except ImportError:
        _hold("private-linux-filesystem-capability-unavailable")
    return assert_native_private_filesystem, LinuxPrivacyHold


def _linux_filesystem(path):
    checker, refusal = _linux_checker()
    try:
        checker(path)
    except refusal as error:
        code = getattr(error, "code", "")
        _hold("private-linux-" + code[len("linux-private-"):] if isinstance(code, str) and re.fullmatch(r"linux-private-[a-z-]{1,60}", code) else "private-linux-filesystem-refused")


def _posix_capability():
    # Darwin ACLs can grant access before BSD mode checks. Require the fixed
    # read-only checker, and call it on each actual private object before bytes.
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        _hold("private-platform-unavailable")
    if sys.platform == "darwin":
        _darwin_checker()
        return
    if sys.platform.startswith("linux"):
        _linux_checker()
        return
    _hold("private-platform-unavailable")


@contextmanager
def private_directory(path, *, create=False, parents=False, exist_ok=False, boundary=None):
    """Admit a private target and hold Windows ordinary ancestry during use.

    `boundary` confines the target; existing ordinary repository/work ancestors
    may be shared. Existing target permissions are validated, never changed.
    """
    if os.name != "nt":
        _posix_capability()
    path = _absolute(path, boundary)
    if os.name == "nt":
        with _windows_directory(path, create=create, parents=parents, exist_ok=exist_ok) as value:
            yield value
        return
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:]):
        current /= part
        target = current == path
        try:
            current.lstat()
        except FileNotFoundError:
            if not create or (not target and not parents):
                _hold("private-directory-missing")
            if sys.platform.startswith("linux"):
                _linux_filesystem(current.parent)
            if sys.platform == "darwin":
                _darwin_filesystem(current.parent)
            try:
                current.mkdir(mode=0o700)
            except OSError:
                _hold("private-directory-create-refused")
            _posix_info(current, directory=True, private=True)
        except OSError:
            _hold("private-path-access-refused")
        else:
            if target and create and not exist_ok:
                _hold("private-directory-exists")
            _posix_info(current, directory=True, private=target)
    before = _posix_info(path, directory=True, private=True)
    yield path
    after = _posix_info(path, directory=True, private=True)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        _hold("private-directory-changed")


def ensure_private_directory(path, *, create=False, parents=False, exist_ok=False, boundary=None):
    with private_directory(path, create=create, parents=parents, exist_ok=exist_ok, boundary=boundary) as value:
        return value


def ensure_private_file(path):
    if os.name != "nt":
        _posix_capability()
    path = _absolute(path)
    if os.name == "nt":
        api = _WindowsSecurity()
        held = []
        try:
            current = Path(path.anchor)
            held.append(api.open(current, directory=True))
            for part in path.parent.parts[1:]:
                current /= part
                held.append(api.open(current, directory=True))
            handle = api.open(path, directory=False, security=True)
            try:
                api.validate(handle, directory=False)
            finally:
                api.close(handle)
        finally:
            for handle in reversed(held):
                api.close(handle)
    else:
        if os.name != "posix":
            _hold("private-platform-unavailable")
        for ancestor in reversed(path.parents):
            _posix_info(ancestor, directory=True, private=False)
        _posix_info(path, directory=False, private=True)
    return path


def write_private_new(path, data):
    """Exclusive private file creation; verify its real permissions before bytes."""
    path = _absolute(path)
    if not isinstance(data, bytes):
        _hold("private-bytes-required")
    with private_directory(path.parent):
        if os.name == "nt":
            api = _WindowsSecurity()
            with api.descriptor(directory=False) as attributes:
                handle = api.kernel.CreateFileW(str(path), 0xC0020080, 0, ctypes.byref(attributes), 1, 0x00200080, None)
            if handle == ctypes.c_void_p(-1).value:
                _hold("private-file-create-refused")
            try:
                api.info(handle, path, directory=False)
                api.validate(handle, directory=False)
                for start in range(0, len(data), 1024 * 1024):
                    chunk = data[start:start + 1024 * 1024]
                    buffer = ctypes.create_string_buffer(chunk)
                    count = wintypes.DWORD()
                    if not api.kernel.WriteFile(handle, buffer, len(chunk), ctypes.byref(count), None) or count.value != len(chunk):
                        _hold("private-file-write-unresolved")
                if not api.kernel.FlushFileBuffers(handle):
                    _hold("private-file-flush-unresolved")
                api.info(handle, path, directory=False)
                api.validate(handle, directory=False)
            finally:
                api.close(handle)
        else:
            try:
                handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except OSError:
                _hold("private-file-create-refused")
            try:
                before = os.fstat(handle)
                if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or not stat.S_ISREG(before.st_mode):
                    _hold("private-owner-or-mode-refused")
                named = _posix_info(path, directory=False, private=True)
                if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
                    _hold("private-file-changed")
                offset = 0
                while offset < len(data):
                    count = os.write(handle, data[offset:offset + 1024 * 1024])
                    if count <= 0:
                        _hold("private-file-write-unresolved")
                    offset += count
                os.fsync(handle)
                after = _posix_info(path, directory=False, private=True)
                if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                    _hold("private-file-changed")
            except OSError:
                _hold("private-file-write-unresolved")
            finally:
                os.close(handle)
