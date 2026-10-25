"""Create/admit private artifact namespaces without repairing existing permissions.

Windows uses the current process token and native protected security descriptors;
POSIX requires actual effective-user ownership and 0700/0600 modes, plus a native
filesystem gate on Linux and absent/empty extended-ACL admission on Darwin. No SID, ACL,
account name, native error text or supplied path is included in refusal messages.
This cooperative boundary excludes the same user and privileged administrators.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import re
import stat
import sys

import win32_files as w32


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


def _windows_api():
    if os.name != "nt" or w32.API is None:
        _hold("private-windows-api-unavailable")
    try:
        w32.token_user()
    except (OSError, w32.PrivacyRefusal):
        _hold("private-token-unavailable")


def _windows_info(handle, path, *, directory):
    try:
        info = w32.file_information(handle)
    except OSError:
        _hold("private-file-metadata-unavailable")
    if w32.file_type(handle) != w32.FILE_TYPE_DISK:
        _hold("private-file-metadata-unavailable")
    if (info.attributes & w32.ATTRIBUTE_REPARSE_POINT or bool(info.attributes & w32.ATTRIBUTE_DIRECTORY) != directory
            or (not directory and info.links != 1)):
        _hold("private-link-or-type-refused")
    try:
        final = w32.final_path(handle)
    except OSError:
        _hold("private-canonical-path-unavailable")
    if not final.startswith("\\\\?\\"):
        _hold("private-canonical-path-unavailable")
    if not w32.same_name(final[4:].rstrip("\\"), str(path).rstrip("\\")):
        _hold("private-canonical-path-mismatch")
    return info


def _windows_open(path, *, directory, security=False, missing=False):
    access = w32.FILE_READ_ATTRIBUTES | (w32.READ_CONTROL if security else 0)
    # BACKUP_SEMANTICS only for folders: on a file an enabled SeBackupPrivilege would bypass the file's DACL.
    flags = w32.FILE_FLAG_OPEN_REPARSE_POINT | (w32.FILE_FLAG_BACKUP_SEMANTICS if directory else 0)
    try:
        handle = w32.open_file(str(path), access, w32.FILE_SHARE_READ | w32.FILE_SHARE_WRITE, w32.OPEN_EXISTING, flags)
    except OSError as error:
        if missing and error.winerror in (w32.ERROR_FILE_NOT_FOUND, w32.ERROR_PATH_NOT_FOUND):
            return None
        _hold("private-path-access-refused")
    try:
        _windows_info(handle, path, directory=directory)
        return handle
    except BaseException:
        handle.close()
        raise


def _windows_validate(handle, *, directory):
    try:
        w32.validate_private(handle, directory=directory, exact=False)
    except w32.PrivacyRefusal as error:
        _hold(error.code)


def _windows_create_directory(path):
    try:
        with w32.private_security(directory=True) as attributes:
            try:
                w32.create_directory(str(path), attributes)
            except OSError:
                _hold("private-directory-create-refused")
    except OSError:
        _hold("private-descriptor-unavailable")


@contextmanager
def _windows_directory(path, *, create, parents, exist_ok):
    _windows_api()
    if w32.drive_type(path.anchor) != w32.DRIVE_FIXED:
        _hold("private-fixed-local-volume-required")
    with ExitStack() as held:
        current = Path(path.anchor)
        last = held.enter_context(_windows_open(current, directory=True))
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            current /= part
            target = index == len(parts) - 1
            handle = _windows_open(current, directory=True, security=target, missing=True)
            if handle is None:
                if not create or (not target and not parents):
                    _hold("private-directory-missing")
                _windows_create_directory(current)
                last = held.enter_context(_windows_open(current, directory=True, security=True))
                _windows_validate(last, directory=True)
            else:
                last = held.enter_context(handle)
                if target:
                    if create and not exist_ok:
                        _hold("private-directory-exists")
                    _windows_validate(last, directory=True)
        yield path
        _windows_info(last, path, directory=True)
        _windows_validate(last, directory=True)


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
        _windows_api()
        with ExitStack() as held:
            current = Path(path.anchor)
            held.enter_context(_windows_open(current, directory=True))
            for part in path.parent.parts[1:]:
                current /= part
                held.enter_context(_windows_open(current, directory=True))
            with _windows_open(path, directory=False, security=True) as handle:
                _windows_validate(handle, directory=False)
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
            _windows_api()
            try:
                with w32.private_security(directory=False) as attributes:
                    try:
                        handle = w32.open_file(str(path), w32.GENERIC_READ | w32.GENERIC_WRITE | w32.READ_CONTROL, 0,
                                               w32.CREATE_NEW,
                                               w32.FILE_FLAG_OPEN_REPARSE_POINT | w32.FILE_ATTRIBUTE_NORMAL, attributes)
                    except OSError:
                        _hold("private-file-create-refused")
            except OSError:
                _hold("private-descriptor-unavailable")
            with handle:
                _windows_info(handle, path, directory=False)
                _windows_validate(handle, directory=False)
                # The C runtime descriptor gives the standard os.write and os.fsync (FlushFileBuffers).
                descriptor = handle.to_fd(os.O_WRONLY | os.O_BINARY)
                for start in range(0, len(data), 1024 * 1024):
                    chunk = data[start:start + 1024 * 1024]
                    try:
                        count = os.write(descriptor, chunk)
                    except OSError:
                        count = -1
                    if count != len(chunk):
                        _hold("private-file-write-unresolved")
                try:
                    os.fsync(descriptor)
                except OSError:
                    _hold("private-file-flush-unresolved")
                _windows_info(handle, path, directory=False)
                _windows_validate(handle, directory=False)
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
