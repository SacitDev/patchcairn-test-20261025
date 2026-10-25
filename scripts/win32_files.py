"""Win32 file, directory, token and security calls through ctypes (layer L1, standard library only).

Bindings, not policy: windows_scoped (selected roots) and private_workspace (owned work folders)
decide what is allowed. Every bound function has argtypes and restype, and a failed call raises
OSError carrying the Windows error code in ``winerror``. 64-bit Python on Windows is required; the
structure layouts are asserted for it. On any other platform nothing is bound and ``API`` is None.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import os
import threading

DWORD, BOOL, WORD, HANDLE, LPCWSTR = ctypes.c_uint32, ctypes.c_int, ctypes.c_uint16, ctypes.c_void_p, ctypes.c_wchar_p
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# CreateFileW access rights, share modes, dispositions and flags.
GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
DELETE, READ_CONTROL = 0x00010000, 0x00020000
FILE_READ_DATA = FILE_LIST_DIRECTORY = 0x1
FILE_WRITE_DATA = FILE_ADD_FILE = 0x2
FILE_APPEND_DATA = FILE_ADD_SUBDIRECTORY = 0x4
FILE_READ_ATTRIBUTES = 0x80
FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE = 0x1, 0x2, 0x4
CREATE_NEW, OPEN_EXISTING = 1, 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS = 0x00200000, 0x02000000
FILE_FLAG_SEQUENTIAL_SCAN, FILE_FLAG_NO_BUFFERING = 0x08000000, 0x20000000
# File attributes.
ATTRIBUTE_READONLY, ATTRIBUTE_SYSTEM, ATTRIBUTE_DIRECTORY, ATTRIBUTE_ARCHIVE = 0x1, 0x4, 0x10, 0x20
ATTRIBUTE_REPARSE_POINT, ATTRIBUTE_OFFLINE, ATTRIBUTE_ENCRYPTED = 0x400, 0x1000, 0x4000
# RECALL_ON_OPEN appears only in directory listings; in handle metadata the same bit means "has extended attributes".
ATTRIBUTE_RECALL_ON_OPEN, ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x40000, 0x400000
FILE_TYPE_DISK = 1
DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_REMOTE, DRIVE_CDROM = 2, 3, 4, 5
FILE_PERSISTENT_ACLS = 0x8
# FileDispositionInfoEx flags.
DISPOSITION_DELETE, DISPOSITION_POSIX_SEMANTICS, DISPOSITION_IGNORE_READONLY = 0x1, 0x2, 0x10
# Windows error codes the callers classify.
ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED = 2, 3, 5
ERROR_NO_MORE_FILES, ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION = 18, 32, 33
ERROR_HANDLE_EOF, ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS = 38, 80, 183
ERROR_DISK_FULL, ERROR_INSUFFICIENT_BUFFER, ERROR_OPERATION_ABORTED = 112, 122, 995
ERROR_NO_TOKEN, ERROR_NOT_FOUND = 1008, 1168
SYSTEM_SID, ADMINISTRATORS_SID = "S-1-5-18", "S-1-5-32-544"

_TOKEN_QUERY, _THREAD_TERMINATE = 0x8, 0x1
_TOKEN_USER, _TOKEN_ELEVATION = 1, 20
_FILE_RENAME_INFO, _FILE_DISPOSITION_INFO, _FILE_DISPOSITION_INFO_EX = 3, 4, 21
_FILE_ID_BOTH_DIRECTORY_INFO, _FILE_ID_BOTH_DIRECTORY_RESTART_INFO = 10, 11
_SE_FILE_OBJECT, _OWNER_AND_DACL = 1, 0x1 | 0x4
_SE_DACL_PRESENT, _SE_DACL_PROTECTED = 0x4, 0x1000
_FULL_ACCESS, _GENERIC_ALL = 0x1F01FF, 0x10000000
_INHERIT_OBJECT_AND_CONTAINER = 0x3


class FILETIME(ctypes.Structure):
    _fields_ = [("low", DWORD), ("high", DWORD)]

    @property
    def value(self):
        return (self.high << 32) | self.low


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [("attributes", DWORD), ("creation", FILETIME), ("access", FILETIME), ("write", FILETIME),
                ("volume", DWORD), ("size_high", DWORD), ("size_low", DWORD), ("links", DWORD),
                ("index_high", DWORD), ("index_low", DWORD)]

    @property
    def size(self):
        return (self.size_high << 32) | self.size_low

    @property
    def index(self):
        return (self.index_high << 32) | self.index_low


class FILE_RENAME_INFO(ctypes.Structure):
    # The first member is the union {BOOLEAN ReplaceIfExists; DWORD Flags}; it stays 0 (never replace).
    _fields_ = [("flags", DWORD), ("root", HANDLE), ("length", DWORD), ("name", ctypes.c_wchar * 1)]


class FILE_ID_BOTH_DIR_INFO(ctypes.Structure):
    _fields_ = [("next", DWORD), ("index", DWORD), ("creation", ctypes.c_int64), ("access", ctypes.c_int64),
                ("write", ctypes.c_int64), ("change", ctypes.c_int64), ("end_of_file", ctypes.c_int64),
                ("allocation", ctypes.c_int64), ("attributes", DWORD), ("name_length", DWORD), ("ea_size", DWORD),
                ("short_length", ctypes.c_byte), ("short_name", ctypes.c_wchar * 12), ("file_id", ctypes.c_int64),
                ("name", ctypes.c_wchar * 1)]


class WIN32_FIND_DATAW(ctypes.Structure):
    _fields_ = [("attributes", DWORD), ("creation", FILETIME), ("access", FILETIME), ("write", FILETIME),
                ("size_high", DWORD), ("size_low", DWORD), ("reserved0", DWORD), ("reserved1", DWORD),
                ("name", ctypes.c_wchar * 260), ("alternate", ctypes.c_wchar * 14)]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("length", DWORD), ("descriptor", ctypes.c_void_p), ("inherit", BOOL)]


class _ACL(ctypes.Structure):
    _fields_ = [("revision", ctypes.c_ubyte), ("reserved", ctypes.c_ubyte), ("size", WORD), ("count", WORD),
                ("reserved2", WORD)]


class _ACE(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_ubyte), ("flags", ctypes.c_ubyte), ("size", WORD), ("mask", DWORD)]


# 64-bit layouts. FILE_RENAME_INFO and SECURITY_ATTRIBUTES were measured on AMD64 with Python 3.14 and 3.15
# (knowledge/research/windows-inprocess.md); the others follow from the Windows SDK declarations.
LAYOUT = {"BY_HANDLE_FILE_INFORMATION": ctypes.sizeof(BY_HANDLE_FILE_INFORMATION),
          "FILE_RENAME_INFO": ctypes.sizeof(FILE_RENAME_INFO), "FILE_RENAME_INFO.name": FILE_RENAME_INFO.name.offset,
          "FILE_ID_BOTH_DIR_INFO.name": FILE_ID_BOTH_DIR_INFO.name.offset,
          "WIN32_FIND_DATAW": ctypes.sizeof(WIN32_FIND_DATAW), "SECURITY_ATTRIBUTES": ctypes.sizeof(SECURITY_ATTRIBUTES)}
EXPECTED_LAYOUT = {"BY_HANDLE_FILE_INFORMATION": 52, "FILE_RENAME_INFO": 24, "FILE_RENAME_INFO.name": 20,
                   "FILE_ID_BOTH_DIR_INFO.name": 104, "WIN32_FIND_DATAW": 592, "SECURITY_ATTRIBUTES": 24}


class PrivacyRefusal(ValueError):
    """An object's owner or DACL is not the private shape; ``code`` names the first difference found."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Handle:
    """The one owner of a Win32 handle. After to_fd() it owns the C runtime descriptor that wraps it.

    Use it in a with block or an ExitStack; close() is idempotent and every use after close raises.
    """

    __slots__ = ("_value", "_fd")

    def __init__(self, value):
        if value in (None, 0, INVALID_HANDLE_VALUE):
            raise ValueError("not an open handle")
        self._value, self._fd = value, None

    @property
    def value(self):
        if self._value is None:
            raise ValueError("the handle is closed")
        return self._value

    @property
    def closed(self):
        return self._value is None

    def to_fd(self, flags):
        """Transfer the handle to a C runtime descriptor once; this object then owns and closes the descriptor."""
        import msvcrt
        if self._fd is not None:
            raise ValueError("the handle already belongs to a descriptor")
        self._fd = msvcrt.open_osfhandle(self.value, flags)
        return self._fd

    def close(self):
        value, fd = self._value, self._fd
        self._value = self._fd = None
        if fd is not None:
            os.close(fd)
        elif value is not None and not API.CloseHandle(value):
            raise _error()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


class _Api:
    """The bound kernel32 and advapi32 functions."""


def _load():
    if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8 or LAYOUT != EXPECTED_LAYOUT:
        return None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer, dword_out, handle_out = ctypes.c_void_p, ctypes.POINTER(DWORD), ctypes.POINTER(HANDLE)
    api = _Api()
    for library, name, restype, argtypes in (
        (kernel, "CreateFileW", HANDLE, (LPCWSTR, DWORD, DWORD, pointer, DWORD, DWORD, HANDLE)),
        (kernel, "CloseHandle", BOOL, (HANDLE,)),
        (kernel, "GetFileInformationByHandle", BOOL, (HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION))),
        (kernel, "GetFileInformationByHandleEx", BOOL, (HANDLE, ctypes.c_int, pointer, DWORD)),
        (kernel, "SetFileInformationByHandle", BOOL, (HANDLE, ctypes.c_int, pointer, DWORD)),
        (kernel, "GetFileType", DWORD, (HANDLE,)),
        (kernel, "GetFinalPathNameByHandleW", DWORD, (HANDLE, ctypes.c_wchar_p, DWORD, DWORD)),
        (kernel, "GetVolumeInformationByHandleW", BOOL, (HANDLE, ctypes.c_wchar_p, DWORD, dword_out, dword_out,
                                                         dword_out, ctypes.c_wchar_p, DWORD)),
        (kernel, "GetDriveTypeW", ctypes.c_uint, (LPCWSTR,)),
        (kernel, "GetDiskFreeSpaceExW", BOOL, (LPCWSTR, ctypes.POINTER(ctypes.c_uint64), pointer, pointer)),
        (kernel, "ReadFile", BOOL, (HANDLE, pointer, DWORD, dword_out, pointer)),
        (kernel, "WriteFile", BOOL, (HANDLE, pointer, DWORD, dword_out, pointer)),
        (kernel, "SetFilePointerEx", BOOL, (HANDLE, ctypes.c_int64, ctypes.POINTER(ctypes.c_int64), DWORD)),
        (kernel, "FlushFileBuffers", BOOL, (HANDLE,)),
        (kernel, "CreateDirectoryW", BOOL, (LPCWSTR, pointer)),
        (kernel, "FindFirstFileExW", HANDLE, (LPCWSTR, ctypes.c_int, pointer, ctypes.c_int, pointer, DWORD)),
        (kernel, "FindClose", BOOL, (HANDLE,)),
        (kernel, "GetCurrentProcess", HANDLE, ()),
        (kernel, "GetCurrentThread", HANDLE, ()),
        (kernel, "GetCurrentThreadId", DWORD, ()),
        (kernel, "OpenThread", HANDLE, (DWORD, BOOL, DWORD)),
        (kernel, "CancelSynchronousIo", BOOL, (HANDLE,)),
        (kernel, "CompareStringOrdinal", ctypes.c_int, (LPCWSTR, ctypes.c_int, LPCWSTR, ctypes.c_int, BOOL)),
        (kernel, "LocalFree", pointer, (pointer,)),
        (advapi, "OpenProcessToken", BOOL, (HANDLE, DWORD, handle_out)),
        (advapi, "OpenThreadToken", BOOL, (HANDLE, DWORD, BOOL, handle_out)),
        (advapi, "GetTokenInformation", BOOL, (HANDLE, ctypes.c_int, pointer, DWORD, dword_out)),
        (advapi, "ConvertSidToStringSidW", BOOL, (pointer, ctypes.POINTER(pointer))),
        (advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", BOOL,
         (LPCWSTR, DWORD, ctypes.POINTER(pointer), dword_out)),
        (advapi, "GetSecurityInfo", DWORD, (HANDLE, ctypes.c_int, DWORD, ctypes.POINTER(pointer), pointer,
                                            ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer))),
        (advapi, "GetSecurityDescriptorControl", BOOL, (pointer, ctypes.POINTER(WORD), dword_out)),
        (advapi, "IsValidAcl", BOOL, (pointer,)),
        (advapi, "GetAce", BOOL, (pointer, DWORD, ctypes.POINTER(pointer))),
        (advapi, "IsValidSid", BOOL, (pointer,)),
        (advapi, "GetLengthSid", DWORD, (pointer,)),
    ):
        function = getattr(library, name)
        function.restype, function.argtypes = restype, argtypes
        setattr(api, name, function)
    return api


try:
    API = _load()
except (OSError, AttributeError):
    API = None


def _error(code=None):
    return ctypes.WinError(ctypes.get_last_error() if code is None else code)


def open_file(path, access, share, disposition, flags, security=None):
    """CreateFileW; the returned Handle owns the new handle from this statement on."""
    raw = API.CreateFileW(path, access, share, None if security is None else ctypes.byref(security),
                          disposition, flags, None)
    if raw in (None, INVALID_HANDLE_VALUE):
        raise _error()
    return Handle(raw)


def file_information(handle):
    info = BY_HANDLE_FILE_INFORMATION()
    if not API.GetFileInformationByHandle(handle.value, ctypes.byref(info)):
        raise _error()
    return info


def file_type(handle):
    return API.GetFileType(handle.value)


def final_path(handle):
    """GetFinalPathNameByHandleW, normalized DOS form (flags 0)."""
    buffer = ctypes.create_unicode_buffer(32768)
    count = API.GetFinalPathNameByHandleW(handle.value, buffer, len(buffer), 0)
    if not count:
        raise _error()
    if count >= len(buffer):
        raise _error(ERROR_INSUFFICIENT_BUFFER)
    return buffer.value


def volume_information(handle):
    """(volume serial, file system name, file system flags) of the volume holding the handle."""
    serial, length, flags = DWORD(), DWORD(), DWORD()
    name = ctypes.create_unicode_buffer(261)
    if not API.GetVolumeInformationByHandleW(handle.value, None, 0, ctypes.byref(serial), ctypes.byref(length),
                                             ctypes.byref(flags), name, len(name)):
        raise _error()
    return serial.value, name.value, flags.value


def drive_type(root):
    """GetDriveTypeW of a drive root such as 'C:\\'."""
    return API.GetDriveTypeW(root)


def free_bytes(directory):
    """GetDiskFreeSpaceExW lpFreeBytesAvailableToCaller: free space this user may use (quotas included)."""
    available = ctypes.c_uint64()
    if not API.GetDiskFreeSpaceExW(directory, ctypes.byref(available), None, None):
        raise _error()
    return available.value


def read(handle, address, count):
    """ReadFile into memory at ``address``; returns the byte count, 0 at end of file (either EOF form)."""
    done = DWORD()
    if not API.ReadFile(handle.value, address, count, ctypes.byref(done), None):
        error = ctypes.get_last_error()
        if error == ERROR_HANDLE_EOF:
            return 0
        raise _error(error)
    return done.value


def write(handle, data):
    """WriteFile; returns the byte count the system accepted."""
    data = data if isinstance(data, bytes) else bytes(data)
    done = DWORD()
    if not API.WriteFile(handle.value, data, len(data), ctypes.byref(done), None):
        raise _error()
    return done.value


def seek(handle, offset, whence):
    position = ctypes.c_int64()
    if not API.SetFilePointerEx(handle.value, offset, ctypes.byref(position), whence):
        raise _error()
    return position.value


def flush(handle):
    if not API.FlushFileBuffers(handle.value):
        raise _error()


def rename_noreplace(handle, target):
    """SetFileInformationByHandle FileRenameInfo with ReplaceIfExists FALSE and RootDirectory NULL.

    ``target`` must be a full path: a bare name is resolved against the process's current directory,
    and RootDirectory is refused by the system (both measured). The buffer is 24 bytes plus the name,
    zero-filled, so the name stays NUL-terminated.
    """
    name = target.encode("utf-16-le", "surrogatepass")
    buffer = ctypes.create_string_buffer(ctypes.sizeof(FILE_RENAME_INFO) + len(name))
    FILE_RENAME_INFO.from_buffer(buffer).length = len(name)
    ctypes.memmove(ctypes.addressof(buffer) + FILE_RENAME_INFO.name.offset, name, len(name))
    if not API.SetFileInformationByHandle(handle.value, _FILE_RENAME_INFO, buffer, len(buffer)):
        raise _error()


def set_disposition(handle, flags):
    """FileDispositionInfoEx; with POSIX semantics the name disappears when this handle closes."""
    value = DWORD(flags)
    if not API.SetFileInformationByHandle(handle.value, _FILE_DISPOSITION_INFO_EX, ctypes.byref(value), 4):
        raise _error()


def delete_on_close(handle):
    """FileDispositionInfo DeleteFile TRUE: the file goes when its last handle closes (every file system)."""
    value = ctypes.c_ubyte(1)
    if not API.SetFileInformationByHandle(handle.value, _FILE_DISPOSITION_INFO, ctypes.byref(value), 1):
        raise _error()


def create_directory(path, security=None):
    if not API.CreateDirectoryW(path, None if security is None else ctypes.byref(security)):
        raise _error()


def directory_entries(handle, limit):
    """[(name, attributes, file id)] of the open directory, from FileIdBothDirectoryInfo; '.' and '..' left out.

    Stops after ``limit`` + 1 entries, so a caller can refuse an oversized directory without reading it all.
    """
    buffer = ctypes.create_string_buffer(64 * 1024)
    base = ctypes.addressof(buffer)
    name_offset = FILE_ID_BOTH_DIR_INFO.name.offset
    entries, information = [], _FILE_ID_BOTH_DIRECTORY_RESTART_INFO
    while len(entries) <= limit:
        if not API.GetFileInformationByHandleEx(handle.value, information, buffer, len(buffer)):
            error = ctypes.get_last_error()
            if error == ERROR_NO_MORE_FILES:
                break
            raise _error(error)
        information, offset = _FILE_ID_BOTH_DIRECTORY_INFO, 0
        while True:
            entry = FILE_ID_BOTH_DIR_INFO.from_buffer(buffer, offset)
            name = ctypes.wstring_at(base + offset + name_offset, entry.name_length // 2)
            if name not in (".", ".."):
                entries.append((name, entry.attributes, entry.file_id & 0xFFFFFFFFFFFFFFFF))
            if not entry.next:
                break
            offset += entry.next
    return entries


def find_entry(path):
    """(stored name, attributes) of one directory entry from its parent's index, without opening it; None if absent."""
    data = WIN32_FIND_DATAW()
    # FindExInfoBasic (1), FindExSearchNameMatch (0): the names this module receives hold no wildcards.
    found = API.FindFirstFileExW(path, 1, ctypes.byref(data), 0, None, 0)
    if found in (None, INVALID_HANDLE_VALUE):
        error = ctypes.get_last_error()
        if error in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
            return None
        raise _error(error)
    API.FindClose(found)
    return data.name, data.attributes


def utf16_units(text):
    """Length in UTF-16 units, the unit Windows counts names and paths in."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def same_name(left, right):
    """CompareStringOrdinal ignoring case (the file system's own rule, not Unicode case folding).

    The lengths are UTF-16 units: a character above U+FFFF is two of them, and counting it as one would leave the
    end of the string uncompared.
    """
    result = API.CompareStringOrdinal(left, utf16_units(left), right, utf16_units(right), True)
    if not result:
        raise _error()
    return result == 2


def thread_impersonating():
    """True when the calling thread has an impersonation token (CreateFileW would use it)."""
    token = HANDLE()
    if API.OpenThreadToken(API.GetCurrentThread(), _TOKEN_QUERY, True, ctypes.byref(token)):
        Handle(token.value).close()
        return True
    error = ctypes.get_last_error()
    if error == ERROR_NO_TOKEN:
        return False
    raise _error(error)


def current_thread():
    """A Handle to the calling thread with the right CancelSynchronousIo needs."""
    raw = API.OpenThread(_THREAD_TERMINATE, False, API.GetCurrentThreadId())
    if not raw:
        raise _error()
    return Handle(raw)


def cancel_synchronous_io(thread):
    """Ask the system to cancel the thread's pending synchronous I/O; False if nothing was pending."""
    if API.CancelSynchronousIo(thread.value):
        return True
    error = ctypes.get_last_error()
    if error == ERROR_NOT_FOUND:
        return False
    raise _error(error)


@contextmanager
def _process_token():
    token = HANDLE()
    if not API.OpenProcessToken(API.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise _error()
    with Handle(token.value) as owned:
        yield owned


def _sid_text(sid):
    if not sid or not API.IsValidSid(sid):
        raise PrivacyRefusal("private-owner-or-acl-invalid")
    text = ctypes.c_void_p()
    if not API.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise PrivacyRefusal("private-owner-or-acl-unavailable")
    try:
        return ctypes.wstring_at(text)
    finally:
        API.LocalFree(text)


_USER = []
_USER_LOCK = threading.Lock()


def token_user():
    """The process token's user SID as text (cached: a process token's user never changes)."""
    with _USER_LOCK:
        if not _USER:
            with _process_token() as token:
                size = DWORD()
                API.GetTokenInformation(token.value, _TOKEN_USER, None, 0, ctypes.byref(size))
                if not 8 <= size.value <= 65536:
                    raise _error()
                buffer = ctypes.create_string_buffer(size.value)
                if not API.GetTokenInformation(token.value, _TOKEN_USER, buffer, size, ctypes.byref(size)):
                    raise _error()
                _USER.append(_sid_text(ctypes.c_void_p.from_buffer(buffer).value))
        return _USER[0]


def token_elevated():
    """True when the process token is elevated (TokenElevation)."""
    with _process_token() as token:
        value, size = DWORD(), DWORD()
        if not API.GetTokenInformation(token.value, _TOKEN_ELEVATION, ctypes.byref(value), 4, ctypes.byref(size)):
            raise _error()
        return bool(value.value)


def private_principals():
    """The current user, SYSTEM and Administrators, without duplicates (a process may run as SYSTEM)."""
    return tuple(dict.fromkeys((token_user(), SYSTEM_SID, ADMINISTRATORS_SID)))


@contextmanager
def private_security(*, directory):
    """SECURITY_ATTRIBUTES for a new object: owner the current user, protected DACL granting full access to
    the private principals only (inherited by children of a directory). The text never leaves memory."""
    user = token_user()
    inherit = "OICI" if directory else ""
    sddl = "O:" + user + "D:P" + "".join(f"(A;{inherit};FA;;;{sid})" for sid in private_principals())
    descriptor, size = ctypes.c_void_p(), DWORD()
    if not API.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor),
                                                                    ctypes.byref(size)):
        raise _error()
    try:
        yield SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
    finally:
        API.LocalFree(descriptor)


def security_snapshot(handle):
    """(owner SID, descriptor control, [(ACE type, flags, mask, SID)]) of an object opened with READ_CONTROL."""
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    if API.GetSecurityInfo(handle.value, _SE_FILE_OBJECT, _OWNER_AND_DACL, ctypes.byref(owner), None,
                           ctypes.byref(dacl), None, ctypes.byref(descriptor)):
        raise PrivacyRefusal("private-dacl-unavailable-or-null")
    try:
        if not descriptor.value or not dacl.value:
            raise PrivacyRefusal("private-dacl-unavailable-or-null")
        control, revision = WORD(), DWORD()
        if not API.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise PrivacyRefusal("private-dacl-unavailable")
        owner_sid = _sid_text(owner.value)
        if not API.IsValidAcl(dacl):
            raise PrivacyRefusal("private-dacl-invalid")
        acl = ctypes.cast(dacl, ctypes.POINTER(_ACL)).contents
        if not 1 <= acl.count <= 256:
            raise PrivacyRefusal("private-dacl-unsupported")
        aces = []
        for index in range(acl.count):
            address = ctypes.c_void_p()
            if not API.GetAce(dacl, index, ctypes.byref(address)):
                raise PrivacyRefusal("private-dacl-unavailable")
            ace = ctypes.cast(address, ctypes.POINTER(_ACE)).contents
            sid = address.value + 8
            if ace.size < 16 or not API.IsValidSid(sid) or API.GetLengthSid(sid) > ace.size - 8:
                raise PrivacyRefusal("private-dacl-invalid")
            aces.append((ace.kind, ace.flags, ace.mask, _sid_text(sid)))
        return owner_sid, control.value, aces
    finally:
        API.LocalFree(descriptor)


def validate_private(handle, *, directory, exact):
    """Refuse (PrivacyRefusal) unless the object is private: owned by the current user, DACL present,
    only allowed ACEs from the private principals and persistent ACLs on the volume.

    ``exact`` is the shape private_security() creates: protected DACL, exactly one full-access ACE per
    principal, inherited to children only for a directory. Otherwise (admitting an existing object) the
    DACL may hold fewer or inherited ACEs, but a directory's must be protected and give the user
    inheritable full access.
    """
    owner, control, aces = security_snapshot(handle)
    principals = private_principals()
    if not control & _SE_DACL_PRESENT or ((directory or exact) and not control & _SE_DACL_PROTECTED):
        raise PrivacyRefusal("private-dacl-unprotected")
    if owner != principals[0]:
        raise PrivacyRefusal("private-owner-refused")
    if exact and sorted(sid for _kind, _flags, _mask, sid in aces) != sorted(principals):
        raise PrivacyRefusal("private-dacl-not-exact")
    user_access, user_inheritance = False, not directory
    for kind, flags, mask, sid in aces:
        if kind != 0 or flags & ~0x13 or (exact and (flags != (_INHERIT_OBJECT_AND_CONTAINER if directory else 0)
                                                    or mask != _FULL_ACCESS)):
            raise PrivacyRefusal("private-dacl-unsupported")
        if sid not in principals:
            raise PrivacyRefusal("private-dacl-broad-or-unknown")
        if sid == principals[0] and (mask & _FULL_ACCESS == _FULL_ACCESS or mask & _GENERIC_ALL):
            user_access = True
            user_inheritance |= flags & _INHERIT_OBJECT_AND_CONTAINER == _INHERIT_OBJECT_AND_CONTAINER
    if not user_access or not user_inheritance:
        raise PrivacyRefusal("private-dacl-inheritance-or-access-refused")
    try:
        flags = volume_information(handle)[2]
    except OSError:
        raise PrivacyRefusal("private-persistent-acl-unavailable") from None
    if not flags & FILE_PERSISTENT_ACLS:
        raise PrivacyRefusal("private-persistent-acl-unavailable")
