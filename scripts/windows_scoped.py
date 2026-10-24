"""Windows selected ordinary-file adapter; fixed PowerShell dispatcher, no shell evaluation.

Authority belongs to the coordinator/OS. A quiet owner-controlled workspace is required.
Every native operation pins ordinary ancestors and exact file handles; context lifetime
is a root identity binding, not a persistent OS lock between subprocess calls.
"""
from __future__ import annotations

import base64
import atexit
from contextlib import ExitStack
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import uuid
from scoped_fs import ScopedFSError, CapabilityHold
from private_workspace import PrivateWorkspaceError, private_directory, write_private_new, _WindowsSecurity, _Info
from windows_worker import OwnedTransport, TransportFailure, PROTOCOL, MAX_SEQUENCE, all_quiescent

DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_REPO = Path(__file__).resolve().parent.parent
_WORK_ROOT = _REPO / "work" / "windows-scoped"
_FIELDS = {"relative_path", "kind", "device", "inode", "mode", "size", "mtime_ns", "ctime_ns", "nlink", "sha256", "attributes"}
_OPERATIONS = frozenset(("probe", "inspect", "list", "read", "move", "remove", "mkdir", "create"))
_IDLE_SECONDS = 60.0
_MAX_AGE_SECONDS = 900.0
_EXCHANGE_SECONDS = 120.0
_TEARDOWN_SECONDS = 5.0


class _Luid(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_int32)]


class _TokenStatistics(ctypes.Structure):
    _fields_ = [("token_id", _Luid), ("authentication_id", _Luid),
        ("expiration", ctypes.c_int64), ("kind", ctypes.c_int32),
        ("impersonation", ctypes.c_int32), ("dynamic_charged", ctypes.c_uint32),
        ("dynamic_available", ctypes.c_uint32), ("groups", ctypes.c_uint32),
        ("privileges", ctypes.c_uint32), ("modified_id", _Luid)]


def _security_binding():
    """Bind only this process's security context; never persist identities."""
    api = _WindowsSecurity()
    api._bind(api.kernel, "GetCurrentThread", [], wintypes.HANDLE)
    api._bind(api.advapi, "OpenThreadToken", [wintypes.HANDLE, wintypes.DWORD,
        wintypes.BOOL, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL)
    thread_token = wintypes.HANDLE()
    if api.advapi.OpenThreadToken(api.kernel.GetCurrentThread(), 8, True, ctypes.byref(thread_token)):
        api.close(thread_token)
        raise CapabilityHold("native-impersonation-unsupported")
    if ctypes.get_last_error() != 1008:  # ERROR_NO_TOKEN is the sole ordinary case.
        raise CapabilityHold("native-security-context-unavailable")
    token = wintypes.HANDLE()
    if not api.advapi.OpenProcessToken(api.kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise CapabilityHold("native-security-context-unavailable")
    try:
        info, length = _TokenStatistics(), wintypes.DWORD()
        if (ctypes.sizeof(info) != 56 or not api.advapi.GetTokenInformation(token, 10,
                ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(length))
                or length.value != ctypes.sizeof(info) or info.kind != 1):
            raise CapabilityHold("native-security-context-unavailable")
        return (api.user, info.token_id.low, info.token_id.high,
            info.authentication_id.low, info.authentication_id.high,
            info.modified_id.low, info.modified_id.high)
    finally:
        api.close(token)


class _ReadPin:
    """Read the admitted handle; deny write/delete sharing until close."""
    def __init__(self, path, *, private, maximum=1024 * 1024, read=True, runtime=False):
        self.path, self.handle = Path(path), None
        self.runtime = runtime
        self.api = _WindowsSecurity()
        try:
            self.handle = self.api.kernel.CreateFileW(str(self.path), 0x80020080,
                1, None, 3, 0x02200000, None)
            if self.handle == ctypes.c_void_p(-1).value:
                self.handle = None
                raise PrivateWorkspaceError("private-path-access-refused")
            before = self.info()
            if private:
                self.api.validate(self.handle, directory=False)
            self.identity = (before.volume, before.id_high, before.id_low,
                before.size_high, before.size_low, before.write.dwHighDateTime,
                before.write.dwLowDateTime)
            self.data = None
            if read:
                size = (before.size_high << 32) | before.size_low
                if size > maximum:
                    raise PrivateWorkspaceError("private-file-byte-bound")
                self.api._bind(self.api.kernel, "ReadFile", [wintypes.HANDLE,
                    ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                    ctypes.c_void_p], wintypes.BOOL)
                chunks, remaining = [], size
                while remaining:
                    buffer = ctypes.create_string_buffer(min(remaining, 65536))
                    count = wintypes.DWORD()
                    if (not self.api.kernel.ReadFile(self.handle, buffer, len(buffer),
                            ctypes.byref(count), None) or not 0 < count.value <= len(buffer)):
                        raise PrivateWorkspaceError("private-file-read-refused")
                    chunks.append(buffer.raw[:count.value])
                    remaining -= count.value
                self.data = b"".join(chunks)
                after = self.info()
                if (after.volume, after.id_high, after.id_low, after.size_high,
                        after.size_low, after.write.dwHighDateTime,
                        after.write.dwLowDateTime) != self.identity:
                    raise PrivateWorkspaceError("private-file-changed")
        except BaseException:
            self.close()
            raise

    def info(self):
        if not self.runtime:
            return self.api.info(self.handle, self.path, directory=False)
        # Windows servicing may hardlink its approved executable into WinSxS.
        # This identity pin is distinct from single-link payload/source admission.
        info = _Info()
        if (not self.api.kernel.GetFileInformationByHandle(self.handle, ctypes.byref(info))
                or self.api.kernel.GetFileType(self.handle) != 1
                or info.attributes & (0x400 | 0x10) or info.links < 1):
            raise PrivateWorkspaceError("native-runtime-type-refused")
        buffer = ctypes.create_unicode_buffer(32768)
        count = self.api.kernel.GetFinalPathNameByHandleW(self.handle, buffer, len(buffer), 0)
        if (not 0 < count < len(buffer) or not buffer.value.startswith("\\\\?\\")
                or buffer.value[4:].casefold() != str(self.path).casefold()):
            raise PrivateWorkspaceError("native-runtime-path-mismatch")
        return info

    def close(self):
        self.api.close(self.handle)
        self.handle = None


def _pin(stack, path, **kwargs):
    value = _ReadPin(path, **kwargs)
    stack.callback(value.close)
    return value


def _capture_inputs(executable, stack):
    """Capture fixed source/runtime identities; no caller selects worker code."""
    api = _WindowsSecurity()
    seen = set()
    for file in (Path(executable), _REPO / "scripts" / "Windows.Scoped.Dispatch.ps1",
                 _REPO / "scripts" / "Windows.Scoped.cs"):
        for directory in reversed(file.parents):
            key = str(directory).casefold()
            if key not in seen:
                handle = api.open(directory, directory=True)
                stack.callback(api.close, handle)
                seen.add(key)
    runtime = _pin(stack, executable, private=False, read=False, runtime=True)
    sources = {}
    for name in ("Windows.Scoped.Dispatch.ps1", "Windows.Scoped.cs"):
        source = _pin(stack, _REPO / "scripts" / name, private=False)
        sources[name] = source.data
    hashes = tuple(hashlib.sha256(sources[name]).hexdigest() for name in sources)
    key = (os.getpid(), str(_REPO).casefold(), str(_WORK_ROOT).casefold(),
           str(Path(executable)).casefold(), runtime.identity, _security_binding(), *hashes)
    return key, sources, hashes


def _record_shape(record):
    if type(record) is not dict or set(record) != _FIELDS:
        return False
    if record["kind"] not in ("file", "directory"):
        return False
    try:
        _relative(record["relative_path"], root=True)
    except ScopedFSError:
        return False
    if not isinstance(record["inode"], str) or not re.fullmatch(r"[a-f0-9]{16}", record["inode"]):
        return False
    if any(type(record[name]) is not int or not -(2**63) <= record[name] < 2**63
           for name in ("device", "mode", "size", "mtime_ns", "ctime_ns", "nlink", "attributes")):
        return False
    if (not 0 <= record["device"] <= 0xffffffff or not 0 <= record["attributes"] <= 0xffffffff
            or record["mode"] != record["attributes"] or record["attributes"] & 0x400):
        return False
    if record["kind"] == "directory":
        return (bool(record["attributes"] & 0x10) and record["size"] == 0
                and record["sha256"] is None and record["nlink"] >= 1)
    return (not record["attributes"] & 0x10 and record["size"] >= 0 and record["nlink"] == 1
            and (record["sha256"] is None or isinstance(record["sha256"], str)
                and re.fullmatch(r"[a-f0-9]{64}", record["sha256"]) is not None))


def _response_shape(response, operation, values):
    """Validate bodies before acknowledgment; malformed replies poison reuse."""
    if type(response) is not dict or type(response.get("ok")) is not bool:
        return False
    if response["ok"] is False:
        return (set(response) == {"ok", "code"} and isinstance(response["code"], str)
                and re.fullmatch(r"[a-z0-9-]{1,80}", response["code"]) is not None)
    if set(response) != {"ok", "result"}:
        return False
    result = response["result"]
    if operation in ("inspect", "move", "mkdir", "create"):
        expected_relative = values.get("destination_relative") if operation == "move" else values.get("relative")
        if not _record_shape(result) or result["relative_path"] != expected_relative:
            return False
        if operation == "mkdir":
            return result["kind"] == "directory" and result["sha256"] is None
        if operation == "create":
            data = base64.b64decode(values["data_base64"], validate=True)
            return (result["kind"] == "file" and result["size"] == len(data)
                    and result["sha256"] == hashlib.sha256(data).hexdigest())
        if operation == "move":
            expected = values["expected"]
            return result["kind"] == "file" and all(result[k] == expected[k]
                for k in ("device", "inode", "size", "sha256"))
        return ((expected_relative != "" or result["kind"] == "directory")
                and (result["kind"] != "file" or (result["sha256"] is not None) == bool(values.get("hash_file"))))
    if operation == "list":
        prefix = values.get("relative", "")
        prefix = prefix + "/" if prefix else ""
        return (type(result) is list and len(result) <= values.get("max_entries", 20000)
                and all(_record_shape(record) for record in result)
                and all(record["relative_path"].startswith(prefix)
                    and "/" not in record["relative_path"][len(prefix):]
                    and len(record["relative_path"]) > len(prefix)
                    and record["sha256"] is None for record in result)
                and len({record["relative_path"] for record in result}) == len(result))
    if operation == "remove":
        return type(result) is dict and set(result) == {"removed"} and result["removed"] is True
    if operation == "read":
        if type(result) is not dict or set(result) != {"data_base64"} or not isinstance(result["data_base64"], str):
            return False
        encoded = result["data_base64"]
        if len(encoded) > 4 * ((values.get("max_bytes", 0) + 2) // 3):
            return False
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            return False
        return (len(data) <= values.get("max_bytes", 0)
                and len(data) == values["expected"]["size"]
                and hashlib.sha256(data).hexdigest() == values["expected"]["sha256"])
    if operation == "probe":
        expected = {"available": True, "reason": None, "adapter": "windows-scoped-handles-v3",
            "platform": "windows", "pinning": True,
            "pinning_scope": "ordinary-ancestors-and-file-per-operation", "filesystem": "ntfs-only",
            "move_noreplace": True, "remove_exact_file": True, "remove_file": True, "mkdir": True,
            "create_file": True, "read_bytes": True, "stream_to": True, "stream_max_bytes": 67108864,
            "max_read_bytes": 67108864, "quiet_workspace_required": True}
        return type(result) is dict and result == expected and all(type(result[k]) is type(v) for k, v in expected.items())
    return False


class _Generation:
    def __init__(self, key, stack, hashes):
        self.key, self.pins, self.hashes = key, stack, hashes
        self.security_context = key[5]
        self.identifier = uuid.uuid4().hex
        self.sequence = 0
        self.created = self.acknowledged = time.monotonic()
        self.state = "STARTING"
        self.transport = None
        self.pending_pins = None
        self.artifact_unresolved = False


class _WorkerManager:
    """One serial generation, one active caller and at most one waiter."""
    def __init__(self):
        self.condition = threading.Condition()
        self.slots = threading.BoundedSemaphore(2)
        self.call_lock = threading.Lock()
        self.local = threading.local()
        self.generation = None
        self.reaper = None

    def _retire(self, generation, deadline, *, force):
        with self.condition:
            generation.state = "DRAINING"
        transport = generation.transport
        done = False
        try:
            disposed = transport is None or transport.quiescent or transport.close(deadline, force=force)
            if disposed and not generation.artifact_unresolved:
                # Only completed I/O/job teardown releases retained request/source pins.
                try:
                    if generation.pending_pins is not None:
                        generation.pending_pins.close()
                        generation.pending_pins = None
                    generation.pins.close()
                except BaseException:
                    # ExitStack consumes callbacks even on failure. Never let a
                    # later empty-stack close erase an unresolved artifact check.
                    generation.artifact_unresolved = True
                    raise
                done = True
        except Exception:
            # A failed final admission/disposal must not leave an eternal DRAINING wait.
            # Keep the generation interlock until an explicit reviewed resolution.
            done = False
        finally:
            # Also publish the hold before propagating interruption/system exit.
            with self.condition:
                generation.state = "CLOSED" if done else "TEARDOWN_UNRESOLVED"
                if done and self.generation is generation:
                    self.generation = None
                self.condition.notify_all()
        return done

    def _reap(self):
        while True:
            with self.condition:
                current = self.generation
                if current is None:
                    self.reaper = None
                    return
                if current.state != "IDLE":
                    self.condition.wait(1.0)
                    continue
                delay = min(current.acknowledged + _IDLE_SECONDS,
                            current.created + _MAX_AGE_SECONDS) - time.monotonic()
                if delay > 0:
                    self.condition.wait(delay)
                    continue
                current.state = "DRAINING"
            # Atomic retirement competes with reservation under the same condition.
            self._retire(current, time.monotonic() + _TEARDOWN_SECONDS, force=False)
            with self.condition:
                if current.state == "TEARDOWN_UNRESOLVED":
                    self.reaper = None
                    return

    def _ready(self, envelope, generation):
        body = envelope.get("response") if type(envelope) is dict else None
        result = body.get("result") if type(body) is dict else None
        return (type(body) is dict and set(body) == {"ok", "result"} and body["ok"] is True
            and type(result) is dict and set(result) == {"state", "dispatcher_sha256", "native_sha256",
                "powershell_version", "powershell_edition", "bitness", "language_mode", "adapter"}
            and result["state"] == "ready" and result["dispatcher_sha256"] == generation.hashes[0]
            and result["native_sha256"] == generation.hashes[1]
            and isinstance(result["powershell_version"], str)
            and re.fullmatch(r"\d+\.\d+(?:\.\d+){0,2}", result["powershell_version"]) is not None
            and result["powershell_edition"] in ("Core", "Desktop")
            and type(result["bitness"]) is int and result["bitness"] == 64
            and result["language_mode"] == "FullLanguage" and result["adapter"] == "windows-scoped-handles-v3")

    def _reserve(self, executable, deadline):
        inputs = ExitStack()
        try:
            key, sources, hashes = _capture_inputs(executable, inputs)
            while True:
                with self.condition:
                    old = self.generation
                    if old is not None and old.state in ("DRAINING", "STARTING"):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise CapabilityHold("native-dispatch-unavailable")
                        self.condition.wait(remaining)
                        continue
                    if old is not None and old.state == "TEARDOWN_UNRESOLVED":
                        raise CapabilityHold("native-dispatch-teardown-unresolved")
                    if old is not None and old.state != "IDLE":
                        raise CapabilityHold("native-dispatch-unavailable")
                    if old is not None and (old.key != key or old.sequence >= MAX_SEQUENCE
                            or old.transport is None or not old.transport.usable
                            or time.monotonic() - old.created >= _MAX_AGE_SECONDS
                            or time.monotonic() - old.acknowledged >= _IDLE_SECONDS):
                        old.state = "DRAINING"
                    elif old is not None:
                        old.state = "RESERVED"
                        return old
                    else:
                        # Originals remain pinned through launch/validated ready;
                        # generation lifetime owns only its immutable private copies.
                        generation = _Generation(key, ExitStack(), hashes)
                        self.generation = generation
                        break
                if not self._retire(old, min(deadline, time.monotonic() + _TEARDOWN_SECONDS), force=False):
                    raise CapabilityHold("native-dispatch-teardown-unresolved")
            directory = _WORK_ROOT / ("worker-" + generation.identifier)
            generation.pins.enter_context(private_directory(_WORK_ROOT, create=True,
                parents=True, exist_ok=True, boundary=_REPO / "work"))
            generation.pins.enter_context(private_directory(directory, create=True, boundary=_WORK_ROOT))
            for name, data in sources.items():
                write_private_new(directory / name, data)
                actual = _pin(generation.pins, directory / name, private=True)
                if actual.data != data:
                    raise PrivateWorkspaceError("private-file-changed")
            env = os.environ.copy()
            env.update(TZ="UTC", TEMP=str(directory), TMP=str(directory), POWERSHELL_TELEMETRY_OPTOUT="1")
            argv = [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                str(directory / "Windows.Scoped.Dispatch.ps1"), "-Serve", "-RepositoryRoot", str(_REPO),
                "-RequestRoot", str(_WORK_ROOT), "-WorkerDirectory", str(directory),
                "-Generation", generation.identifier, "-ExpectedDispatcherSha256", hashes[0],
                "-ExpectedNativeSha256", hashes[1]]
            try:
                OwnedTransport.start(argv, env, str(directory), generation.identifier, deadline,
                    on_created=lambda owner: setattr(generation, "transport", owner))
                if not self._ready(generation.transport.receive_ready(deadline), generation):
                    raise CapabilityHold("native-dispatch-unavailable")
            except TransportFailure as error:
                generation.transport = error.transport or generation.transport
                self._retire(generation, time.monotonic(), force=True)
                raise CapabilityHold(error.code) from None
            with self.condition:
                generation.state = "RESERVED"
                if self.reaper is None:
                    self.reaper = threading.Thread(target=self._reap, name="patchcairn-worker-idle", daemon=True)
                    self.reaper.start()
            return generation
        except BaseException:
            with self.condition:
                current = self.generation
            if current is not None and current.state == "STARTING":
                self._retire(current, time.monotonic() + _TEARDOWN_SECONDS, force=True)
            raise
        finally:
            inputs.close()

    def dispatch(self, operation, values):
        if operation not in _OPERATIONS:
            raise ScopedFSError("unknown-operation")
        if getattr(self.local, "active", False) or not self.slots.acquire(blocking=False):
            raise CapabilityHold("native-dispatch-busy")
        wait_deadline = time.monotonic() + _EXCHANGE_SECONDS
        locked = False
        pending = ExitStack()
        generation = None
        possible_send = False
        try:
            locked = self.call_lock.acquire(timeout=max(0.0, wait_deadline - time.monotonic()))
            if not locked:
                raise CapabilityHold("native-dispatch-busy")
            self.local.active = True
            # Bounded caller waiting is separate from the single cold-inclusive
            # exchange budget; a queued caller does not inherit an expired budget.
            deadline = time.monotonic() + _EXCHANGE_SECONDS
            executable = _runtime()
            pending.enter_context(private_directory(_WORK_ROOT, create=True, parents=True,
                exist_ok=True, boundary=_REPO / "work"))
            generation = self._reserve(executable, deadline)
            identifier = uuid.uuid4().hex
            directory = _WORK_ROOT / ("request-" + identifier)
            pending.enter_context(private_directory(directory, create=True, boundary=_WORK_ROOT))
            request = directory / "request.json"
            payload = {"schema": "patchcairn.windows-scoped.v3", "operation": operation,
                "quiet_workspace": True, "root_record": None, **values}
            raw = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
            if len(raw) > 100_000_000:
                raise ScopedFSError("request-byte-bound")
            write_private_new(request, raw)
            admitted = _pin(pending, request, private=True, maximum=100_000_000)
            if admitted.data != raw:
                raise PrivateWorkspaceError("private-file-changed")
            if _security_binding() != generation.security_context:
                raise CapabilityHold("native-security-context-changed")
            if time.monotonic() >= deadline:
                raise CapabilityHold("native-dispatch-unavailable")
            with self.condition:
                generation.sequence += 1
                generation.state = "INFLIGHT"
            envelope = {"protocol": PROTOCOL, "generation": generation.identifier,
                "sequence": generation.sequence, "request_id": identifier, "request_path": str(request),
                "request_sha256": hashlib.sha256(raw).hexdigest(), "operation": operation}
            possible_send = True
            outer = generation.transport.exchange(envelope, deadline)
            response = outer["response"]
            if not _response_shape(response, operation, values):
                raise CapabilityHold("native-dispatch-interrupted-reconcile-required")
            if _security_binding() != generation.security_context:
                raise CapabilityHold("native-security-context-changed-reconcile-required")
            write_private_new(directory / "response.json",
                json.dumps(response, ensure_ascii=True, allow_nan=False).encode("utf-8"))
            # Exit-time namespace checks are part of acknowledgment, too.
            try:
                pending.close()
            except BaseException:
                # ExitStack may already have consumed the failing callback.
                # A later retirement must retain this acknowledgment anomaly.
                generation.artifact_unresolved = True
                raise
            with self.condition:
                generation.acknowledged = time.monotonic()
                generation.state = "IDLE"
                self.condition.notify_all()
            if response["ok"] is not True:
                raise ScopedFSError(response["code"])
            return response["result"]
        except BaseException as error:
            if generation is not None and generation.state in ("RESERVED", "INFLIGHT"):
                generation.pending_pins = pending.pop_all()
                # The transport already used its finite failure grace. Do not add another.
                until = time.monotonic() if isinstance(error, TransportFailure) else time.monotonic() + _TEARDOWN_SECONDS
                self._retire(generation, until, force=True)
            if isinstance(error, TransportFailure):
                raise CapabilityHold(error.code) from None
            if isinstance(error, PrivateWorkspaceError):
                raise CapabilityHold("native-private-artifact-reconcile-required" if possible_send else error.code) from None
            if isinstance(error, (KeyError, TypeError, ValueError)) and not isinstance(error, ScopedFSError):
                raise CapabilityHold("native-dispatch-interrupted-reconcile-required" if possible_send else "native-dispatch-unavailable") from None
            raise
        finally:
            try:
                pending.close()
            except BaseException as error:
                if generation is not None:
                    generation.artifact_unresolved = True
                if isinstance(error, PrivateWorkspaceError):
                    raise CapabilityHold(error.code) from None
                raise
            finally:
                if locked:
                    self.local.active = False
                    self.call_lock.release()
                self.slots.release()

    def shutdown(self):
        deadline = time.monotonic() + _TEARDOWN_SECONDS
        if not self.call_lock.acquire(timeout=_TEARDOWN_SECONDS):
            return False
        try:
            with self.condition:
                current = self.generation
                if current is None:
                    return all_quiescent()
                while current.state == "DRAINING":
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self.condition.wait(remaining)
                    current = self.generation
                    if current is None:
                        return all_quiescent()
                current.state = "DRAINING"
            return self._retire(current, deadline, force=True) and all_quiescent()
        finally:
            self.call_lock.release()


_MANAGER = _WorkerManager()


def shutdown_worker():
    """Retire the exact owned helper; never deletes files or searches host PIDs."""
    return _MANAGER.shutdown()


atexit.register(shutdown_worker)


def _relative(value: str, *, root: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 200 or len(value.split("/")) > 64 or (not value and not root):
        raise ScopedFSError("invalid-relative-path")
    if value and any(not p or p in {".", ".."} or p[-1:] in {".", " "} or re.search(r'[\\:*?<>|"\x00-\x1f]', p) or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?", p) for p in value.split("/")):
        raise ScopedFSError("invalid-relative-path")
    return value


def _bound(value: int, maximum: int, code: str) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise ScopedFSError(code)
    return value


def _runtime() -> str:
    if os.name != "nt":
        raise CapabilityHold("windows-required")
    if sys.version_info < (3, 12):
        raise CapabilityHold("python-312-required")
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise CapabilityHold("windows-64bit-python-required")
    # Select installed native executables only; never command strings from records.
    executable = None
    # Unlike Windows shutil.which, do not prepend/search the working directory.
    # Keep installed absolute local PATH order; no registry or network discovery.
    for directory in os.get_exec_path():
        if not re.match(r"^[A-Za-z]:[\\/]", directory) or ".." in Path(directory).parts:
            continue
        candidate = Path(directory) / "pwsh.exe"
        if candidate.is_file():
            executable = str(candidate)
            break
    if executable is None:
        executable = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    if not re.match(r"^[A-Za-z]:[\\/]", executable) or not Path(executable).is_file():
        raise CapabilityHold("powershell-unavailable")
    return executable


def _dispatch(operation: str, **values):
    return _MANAGER.dispatch(operation, values)


def capabilities() -> dict:
    try:
        return _dispatch("probe")
    except (ScopedFSError, OSError, subprocess.SubprocessError) as error:
        return {"available": False, "platform": "windows", "adapter": "windows-scoped-handles-v3", "reason": getattr(error, "code", "native-dispatch-unavailable"), "pinning": False, "move_noreplace": False, "remove_file": False, "create_file": False, "mkdir": False, "read_bytes": False, "stream_to": False, "stream_max_bytes": 0}


class ScopedRoot:
    def __init__(self, root, *, quiet_workspace: bool, max_entries: int = 20000):
        if quiet_workspace is not True:
            raise CapabilityHold("quiet-workspace-required")
        _bound(max_entries, 20000, "invalid-entry-bound")
        if max_entries == 0:
            raise ScopedFSError("invalid-entry-bound")
        raw = os.fspath(root)
        if not isinstance(raw, str) or not re.match(r"^[A-Za-z]:\\", raw) or not 4 <= len(raw.rstrip("\\")) <= 240:
            raise ScopedFSError("local-absolute-root-required")
        self.root = Path(raw.rstrip("\\"))
        self.max_entries = max_entries
        self._closed = False
        self._root_record = None
        self._root_record = self.inspect("", hash_file=False)

    def __enter__(self):
        if self._closed:
            raise ScopedFSError("scope-closed")
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self._closed = True

    def _call(self, operation, **values):
        if self._closed:
            raise ScopedFSError("scope-closed")
        if len(str(self.root)) > 240:
            raise ScopedFSError("local-absolute-root-required")
        return _dispatch(operation, root=str(self.root), root_record=self._root_record, **values)

    def inspect(self, relative, *, hash_file=False, max_bytes=DEFAULT_MAX_FILE_BYTES):
        _relative(relative, root=True)
        _bound(max_bytes, 64 * 1024**3, "invalid-byte-bound")
        return self._call("inspect", relative=relative, hash_file=bool(hash_file), max_bytes=max_bytes)

    def list_directory(self, relative=""):
        _relative(relative, root=True)
        records = self._call("list", relative=relative, max_entries=self.max_entries)
        return records if isinstance(records, list) else [records]

    def snapshot(self, *, hash_files=False, max_file_bytes=DEFAULT_MAX_FILE_BYTES, max_total_bytes=DEFAULT_MAX_TOTAL_BYTES):
        _bound(max_total_bytes, 1024**4, "invalid-total-bound")
        _bound(max_file_bytes, 64 * 1024**3, "invalid-byte-bound")
        result = [self.inspect("")]
        queue = [""]
        total = 0
        directories = []
        while queue:
            directory = queue.pop()
            if directory.count("/") >= 64:
                raise ScopedFSError("depth-bound")
            children = self.list_directory(directory)
            directories.append((directory, [record["relative_path"] for record in children]))
            for record in children:
                if len(result) >= self.max_entries:
                    raise ScopedFSError("entry-bound")
                if record["kind"] == "directory":
                    queue.append(record["relative_path"])
                elif hash_files:
                    total += record["size"]
                    if total > max_total_bytes or record["size"] > max_file_bytes:
                        raise ScopedFSError("snapshot-byte-bound")
                    record = self.inspect(record["relative_path"], hash_file=True, max_bytes=max_file_bytes)
                result.append(record)
        by_path = {record["relative_path"]: record for record in result}
        if self.inspect("") != by_path[""]:
            raise ScopedFSError("snapshot-drift")
        for directory, names in directories:
            current = self.list_directory(directory)
            if names != [record["relative_path"] for record in current] or any(any(record[key] != by_path[record["relative_path"]][key] for key in _FIELDS - {"sha256"}) for record in current):
                raise ScopedFSError("snapshot-drift")
        return sorted(result, key=lambda record: record["relative_path"])

    @staticmethod
    def _expected(expected):
        if not _record_shape(expected) or expected.get("kind") != "file" or not re.fullmatch(r"[a-f0-9]{64}", expected.get("sha256") or ""):
            raise ScopedFSError("expected-hashed-file-required")
        return expected

    def read_bytes(self, relative, *, expected, max_bytes):
        _relative(relative)
        _bound(max_bytes, DEFAULT_MAX_FILE_BYTES, "memory-read-bound")
        reply = self._call("read", relative=relative, expected=self._expected(expected), max_bytes=max_bytes)
        data = base64.b64decode(reply["data_base64"], validate=True)
        if len(data) > max_bytes:
            raise ScopedFSError("response-byte-bound")
        return data

    def stream_to(self, relative, *, expected, writer, max_bytes, chunk_size=65536):
        _bound(chunk_size, 1024 * 1024, "invalid-chunk-bound")
        if chunk_size == 0 or not callable(writer):
            raise ScopedFSError("invalid-writer-or-chunk")
        if max_bytes > DEFAULT_MAX_FILE_BYTES:
            raise CapabilityHold("windows-stream-over-64mib-unavailable")
        data = self.read_bytes(relative, expected=expected, max_bytes=max_bytes)
        for start in range(0, len(data), chunk_size):
            chunk = data[start:start + chunk_size]
            accepted = writer(chunk)
            if accepted is not None and accepted != len(chunk):
                raise ScopedFSError("short-write")
        return dict(expected)

    def mkdir(self, relative):
        return self._call("mkdir", relative=_relative(relative))

    def create_file(self, relative, *, data, max_bytes):
        _bound(max_bytes, DEFAULT_MAX_FILE_BYTES, "create-byte-bound")
        if not isinstance(data, bytes) or len(data) > max_bytes:
            raise ScopedFSError("create-byte-bound")
        return self._call("create", relative=_relative(relative), data_base64=base64.b64encode(data).decode("ascii"), max_bytes=max_bytes)

    def move_to(self, relative, *, destination, destination_relative, expected):
        if not isinstance(destination, ScopedRoot) or destination._closed:
            raise ScopedFSError("destination-scope-required")
        if len(str(destination.root)) > 240:
            raise ScopedFSError("local-absolute-root-required")
        return self._call("move", relative=_relative(relative), destination_root=str(destination.root), destination_relative=_relative(destination_relative), expected=self._expected(expected), destination_root_record=destination._root_record)

    def remove_file(self, relative, *, expected):
        self._call("remove", relative=_relative(relative), expected=self._expected(expected))
