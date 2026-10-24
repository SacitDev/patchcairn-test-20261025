"""Private Windows worker transport; importing this module launches nothing.

The adapter owns source/private-file admission and all native-result semantics.
This module owns only an atomic job-bound child, bounded wire I/O, and teardown.
It never replays an operation or reopens a process or thread by numeric ID.
"""
from __future__ import annotations

import ctypes
import json
import math
import os
import re
import struct
import subprocess
import threading
import time

PROTOCOL = "patchcairn.windows-worker.v1"
MAGIC = b"PCW1"
MAX_REQUEST_BYTES = 8192
MAX_RESPONSE_BYTES = 100_000_000
MAX_SEQUENCE = 256
MAX_JSON_DEPTH = 32
MAX_COLLECTION_ITEMS = 20_000
MAX_JSON_TOKENS = 1_000_000
_READY_ID = "0" * 32
_HEX32 = re.compile(r"[a-f0-9]{32}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_CODE = re.compile(r"[a-z0-9-]{1,80}\Z")
_PRIMITIVE = re.compile(r'[^\s,\[\]{}:"\\]+')
_OPERATIONS = frozenset(("probe", "inspect", "list", "read", "move",
                         "remove", "mkdir", "create"))
_REQUEST_KEYS = frozenset(("protocol", "generation", "sequence", "request_id",
                           "request_path", "request_sha256", "operation"))
_RESPONSE_KEYS = frozenset(("protocol", "generation", "sequence", "request_id",
                            "response"))
_UNAVAILABLE = "native-dispatch-unavailable"
_INTERRUPTED = "native-dispatch-interrupted-reconcile-required"
_UNRESOLVED = "native-dispatch-teardown-unresolved"
_OWNER_LOCK = threading.Lock()
_LIVE_OWNERS = set()


def all_quiescent():
    """Read-only ownership check; never closes another owner's resources."""
    with _OWNER_LOCK:
        return all(owner.quiescent for owner in _LIVE_OWNERS)


class TransportFailure(ValueError):
    """Categorical failure; no private argv, paths, payloads or native text."""
    def __init__(self, code, may_have_sent=False):
        self.code = code if isinstance(code, str) and _CODE.fullmatch(code) else _UNAVAILABLE
        self.may_have_sent = bool(may_have_sent)
        # A failed start can still own an unresolved child. Never lose that owner.
        self.transport = None
        super().__init__(self.code)


class _Stopped(Exception):
    pass


class _PipeEOF(Exception):
    pass


def _valid_deadline(deadline):
    return (type(deadline) in (int, float) and math.isfinite(deadline)
            and deadline > time.monotonic())


def _scan_json(text):
    """Bound structure before the JSON decoder allocates containers.

    Quoted spans are skipped with str.find so large Base64 strings are not
    traversed one Python character at a time. Syntax is still checked by json.
    """
    stack = []
    tokens = 0
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char == '"':
            tokens += 1
            end = index + 1
            while True:
                end = text.find('"', end)
                if end < 0:
                    raise ValueError("invalid-json")
                cursor = end - 1
                while cursor > index and text[cursor] == "\\":
                    cursor -= 1
                if (end - cursor - 1) % 2 == 0:
                    break
                end += 1
            index = end + 1
        elif char in "[{":
            tokens += 1
            stack.append([char, 0])
            if len(stack) > MAX_JSON_DEPTH:
                raise ValueError("json-depth-bound")
            index += 1
        elif char in "]}":
            if not stack or (stack[-1][0], char) not in (("[", "]"), ("{", "}")):
                raise ValueError("invalid-json")
            stack.pop()
            index += 1
        elif char == ",":
            if not stack:
                raise ValueError("invalid-json")
            stack[-1][1] += 1
            if stack[-1][1] >= MAX_COLLECTION_ITEMS:
                raise ValueError("json-collection-bound")
            index += 1
        elif char == ":":
            index += 1
        else:
            match = _PRIMITIVE.match(text, index)
            if match is None:
                raise ValueError("invalid-json")
            tokens += 1
            index = match.end()
        if tokens > MAX_JSON_TOKENS:
            raise ValueError("json-token-bound")
    if stack:
        raise ValueError("invalid-json")


def _strict_json(payload):
    if not isinstance(payload, (bytes, bytearray)) or not 0 < len(payload) <= MAX_RESPONSE_BYTES:
        raise ValueError("json-byte-bound")
    if payload[:3] == b"\xef\xbb\xbf":
        raise ValueError("json-bom")
    text = payload.decode("utf-8", errors="strict")
    _scan_json(text)

    def pairs(items):
        result = {}
        if len(items) > MAX_COLLECTION_ITEMS:
            raise ValueError("json-collection-bound")
        for key, value in items:
            if key in result:
                raise ValueError("duplicate-json-key")
            result[key] = value
        return result

    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite-json")
        return result

    def constant(_):
        raise ValueError("nonfinite-json")

    return json.loads(text, object_pairs_hook=pairs, parse_float=number,
                      parse_constant=constant)


def _frame_length(header):
    """Validate a complete response header before a body buffer is allocated."""
    if not isinstance(header, (bytes, bytearray)) or len(header) != 8 or header[:4] != MAGIC:
        raise TransportFailure(_UNAVAILABLE)
    size = struct.unpack_from("<I", header, 4)[0]
    if not 0 < size <= MAX_RESPONSE_BYTES:
        raise TransportFailure(_UNAVAILABLE)
    return size


def _encode_request(envelope, generation, expected_sequence):
    """Return one PCW1 frame, or refuse it before any transport write."""
    try:
        if (not isinstance(generation, str) or not _HEX32.fullmatch(generation)
                or type(expected_sequence) is not int
                or not 1 <= expected_sequence <= MAX_SEQUENCE
                or type(envelope) is not dict or set(envelope) != _REQUEST_KEYS
                or envelope["protocol"] != PROTOCOL
                or envelope["generation"] != generation
                or type(envelope["sequence"]) is not int
                or envelope["sequence"] != expected_sequence
                or not isinstance(envelope["request_id"], str)
                or not _HEX32.fullmatch(envelope["request_id"])
                or not isinstance(envelope["request_sha256"], str)
                or not _HEX64.fullmatch(envelope["request_sha256"])
                or not isinstance(envelope["request_path"], str)
                or not envelope["request_path"] or "\x00" in envelope["request_path"]
                or envelope["operation"] not in _OPERATIONS):
            raise ValueError("request-contract")
        encoded = json.dumps(envelope, ensure_ascii=True, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
        if not 0 < len(encoded) <= MAX_REQUEST_BYTES:
            raise ValueError("request-byte-bound")
        return MAGIC + struct.pack("<I", len(encoded)) + encoded
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise TransportFailure(_UNAVAILABLE) from None


def _decode_response(payload, generation, sequence, request_id):
    """Decode and validate only the outer contract; the adapter owns its body."""
    try:
        value = _strict_json(payload)
        if (type(value) is not dict or set(value) != _RESPONSE_KEYS
                or value["protocol"] != PROTOCOL
                or value["generation"] != generation
                or not isinstance(generation, str) or not _HEX32.fullmatch(generation)
                or type(value["sequence"]) is not int
                or value["sequence"] != sequence
                or type(sequence) is not int or not 0 <= sequence <= MAX_SEQUENCE
                or value["request_id"] != request_id
                or not isinstance(request_id, str) or not _HEX32.fullmatch(request_id)
                or (sequence == 0 and request_id != _READY_ID)
                or type(value["response"]) is not dict):
            raise ValueError("response-contract")
        return value
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, UnicodeError):
        raise TransportFailure(_UNAVAILABLE) from None


# Structures are data declarations only. No Windows DLL is loaded at import.
_DWORD = ctypes.c_uint32
_WORD = ctypes.c_uint16
_BOOL = ctypes.c_int32
_HANDLE = ctypes.c_void_p
_SIZE_T = ctypes.c_size_t
_LARGE_INTEGER = ctypes.c_int64


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", _DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", _BOOL)]


class _STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", _DWORD), ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p), ("lpTitle", ctypes.c_wchar_p),
        ("dwX", _DWORD), ("dwY", _DWORD), ("dwXSize", _DWORD),
        ("dwYSize", _DWORD), ("dwXCountChars", _DWORD),
        ("dwYCountChars", _DWORD), ("dwFillAttribute", _DWORD),
        ("dwFlags", _DWORD), ("wShowWindow", _WORD),
        ("cbReserved2", _WORD), ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", _HANDLE), ("hStdOutput", _HANDLE),
        ("hStdError", _HANDLE),
    ]


class _STARTUPINFOEX(ctypes.Structure):
    _fields_ = [("StartupInfo", _STARTUPINFO),
                ("lpAttributeList", ctypes.c_void_p)]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", _HANDLE), ("hThread", _HANDLE),
                ("dwProcessId", _DWORD), ("dwThreadId", _DWORD)]


class _JOB_BASIC_LIMIT(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", _LARGE_INTEGER),
        ("PerJobUserTimeLimit", _LARGE_INTEGER), ("LimitFlags", _DWORD),
        ("MinimumWorkingSetSize", _SIZE_T), ("MaximumWorkingSetSize", _SIZE_T),
        ("ActiveProcessLimit", _DWORD), ("Affinity", _SIZE_T),
        ("PriorityClass", _DWORD), ("SchedulingClass", _DWORD),
    ]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _JOB_EXTENDED_LIMIT(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _JOB_BASIC_LIMIT),
                ("IoInfo", _IO_COUNTERS), ("ProcessMemoryLimit", _SIZE_T),
                ("JobMemoryLimit", _SIZE_T), ("PeakProcessMemoryUsed", _SIZE_T),
                ("PeakJobMemoryUsed", _SIZE_T)]


class _JOB_ACCOUNTING(ctypes.Structure):
    _fields_ = [(name, _LARGE_INTEGER) for name in (
        "TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime",
        "ThisPeriodTotalKernelTime")] + [(name, _DWORD) for name in (
            "TotalPageFaultCount", "TotalProcesses", "ActiveProcesses",
            "TotalTerminatedProcesses")]


class _WinAPI:
    def __init__(self):
        if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
            raise TransportFailure(_UNAVAILABLE)
        widths = ctypes.sizeof(_HANDLE)
        expected = {
            _SECURITY_ATTRIBUTES: 24 if widths == 8 else 12,
            _STARTUPINFO: 104 if widths == 8 else 68,
            _STARTUPINFOEX: 112 if widths == 8 else 72,
            _PROCESS_INFORMATION: 24 if widths == 8 else 16,
            _JOB_BASIC_LIMIT: 64 if widths == 8 else 48,
            _IO_COUNTERS: 48,
            _JOB_EXTENDED_LIMIT: 144 if widths == 8 else 112,
            _JOB_ACCOUNTING: 48,
        }
        if (widths not in (4, 8) or ctypes.sizeof(ctypes.c_wchar) != 2
                or any(ctypes.sizeof(kind) != size for kind, size in expected.items())):
            raise TransportFailure(_UNAVAILABLE)
        self.dll = ctypes.WinDLL("kernel32", use_last_error=True)
        pointer = ctypes.c_void_p
        phandle = ctypes.POINTER(_HANDLE)
        self._bind("CreateJobObjectW", [pointer, ctypes.c_wchar_p], _HANDLE)
        self._bind("SetInformationJobObject", [_HANDLE, ctypes.c_int, pointer, _DWORD], _BOOL)
        self._bind("QueryInformationJobObject", [_HANDLE, ctypes.c_int, pointer, _DWORD,
                                                ctypes.POINTER(_DWORD)], _BOOL)
        self._bind("TerminateJobObject", [_HANDLE, _DWORD], _BOOL)
        self._bind("CreatePipe", [phandle, phandle, ctypes.POINTER(_SECURITY_ATTRIBUTES), _DWORD], _BOOL)
        self._bind("SetHandleInformation", [_HANDLE, _DWORD, _DWORD], _BOOL)
        self._bind("CreateFileW", [ctypes.c_wchar_p, _DWORD, _DWORD, pointer,
                                   _DWORD, _DWORD, _HANDLE], _HANDLE)
        self._bind("InitializeProcThreadAttributeList",
                   [pointer, _DWORD, _DWORD, ctypes.POINTER(_SIZE_T)], _BOOL)
        self._bind("UpdateProcThreadAttribute",
                   [pointer, _DWORD, _SIZE_T, pointer, _SIZE_T, pointer, pointer], _BOOL)
        self._bind("DeleteProcThreadAttributeList", [pointer], None)
        self._bind("CreateProcessW",
                   [ctypes.c_wchar_p, pointer, pointer, pointer, _BOOL, _DWORD,
                    pointer, ctypes.c_wchar_p, ctypes.POINTER(_STARTUPINFOEX),
                    ctypes.POINTER(_PROCESS_INFORMATION)], _BOOL)
        self._bind("ReadFile", [_HANDLE, pointer, _DWORD, ctypes.POINTER(_DWORD), pointer], _BOOL)
        self._bind("WriteFile", [_HANDLE, pointer, _DWORD, ctypes.POINTER(_DWORD), pointer], _BOOL)
        self._bind("CancelSynchronousIo", [_HANDLE], _BOOL)
        self._bind("WaitForSingleObject", [_HANDLE, _DWORD], _DWORD)
        self._bind("GetExitCodeProcess", [_HANDLE, ctypes.POINTER(_DWORD)], _BOOL)
        self._bind("CloseHandle", [_HANDLE], _BOOL)
        self._bind("GetCurrentProcess", [], _HANDLE)
        self._bind("GetCurrentThread", [], _HANDLE)
        self._bind("DuplicateHandle",
                   [_HANDLE, _HANDLE, _HANDLE, phandle, _DWORD, _BOOL, _DWORD], _BOOL)

    def _bind(self, name, arguments, result):
        function = getattr(self.dll, name)
        function.argtypes, function.restype = arguments, result
        setattr(self, name, function)


class OwnedTransport:
    """One exact child/job generation. Construct with start(), never directly."""
    def __init__(self, generation):
        self._generation = generation
        self._owner_pid = os.getpid()
        self._api = None
        self._native = {}
        self._acquiring = set()
        self._acquisition_outputs = {}
        self._creation_information = None
        self._creation_result = None
        self._process_id = None
        self._condition = threading.Condition()
        self._api_gate = threading.Lock()
        self._close_gate = threading.Lock()
        self._stop = threading.Event()
        self._quiescent = threading.Event()
        self._threads = {}
        self._thread_handles = {}
        self._fatal = None
        self._expected = (0, _READY_ID)
        self._reply = None
        self._write_slot = None
        self._write_done = True
        self._sent = False
        self._ready_received = False
        self._next_sequence = 1
        self._closing = False
        self._peer_eof = False

    @property
    def quiescent(self):
        """True only after job-zero, joined I/O and disposal of owned handles."""
        return self._quiescent.is_set()

    @property
    def usable(self):
        """An idle live protocol boundary, not a cached file/authority result."""
        with self._condition:
            return (self._owner_pid == os.getpid() and self._ready_received
                and not self._closing and not self._stop.is_set()
                and self._fatal is None and not self._peer_eof
                and self._expected is None and self._reply is None
                and self._write_slot is None and self._write_done
                and not self.quiescent)

    @property
    def process_id(self):
        """Diagnostic ID only; never used for lookup, authority or termination."""
        return self._process_id

    @classmethod
    def start(cls, argv, env, cwd, generation, deadline, *, on_created=None):
        if (os.name != "nt" or not _valid_deadline(deadline)
                or not isinstance(generation, str) or not _HEX32.fullmatch(generation)
                or on_created is not None and not callable(on_created)):
            raise TransportFailure(_UNAVAILABLE)
        transport = cls(generation)
        with _OWNER_LOCK:
            if any(not owner.quiescent for owner in _LIVE_OWNERS):
                raise TransportFailure(_UNRESOLVED)
            _LIVE_OWNERS.add(transport)
        try:
            # Publish ownership to the adapter BEFORE any child can be created.
            # An interruption after returning from start must not lose its owner.
            if on_created is not None:
                on_created(transport)
            transport._launch(argv, env, cwd, deadline)
            transport._start_io(deadline)
            return transport
        except BaseException:
            failure = TransportFailure(_UNAVAILABLE, transport._sent)
            failure.transport = transport
            transport.close(time.monotonic() + 5.0, force=True)
            raise failure from None

    def _launch(self, argv, env, cwd, deadline):
        if (type(argv) is not list or not argv
                or any(not isinstance(item, str) or "\x00" in item for item in argv)
                or not os.path.isabs(argv[0]) or not isinstance(cwd, str)
                or not os.path.isabs(cwd) or "\x00" in cwd
                or type(env) is not dict):
            raise TransportFailure(_UNAVAILABLE)
        if len(env) > 4096 or sum(len(item) + 1 for item in argv) > 32767:
            raise TransportFailure(_UNAVAILABLE)
        pairs, names = [], set()
        environment_characters = 2
        for key, value in env.items():
            if (not isinstance(key, str) or not key or "=" in key or "\x00" in key
                    or not isinstance(value, str) or "\x00" in value
                    or key.casefold() in names):
                raise TransportFailure(_UNAVAILABLE)
            environment_characters += len(key) + len(value) + 2
            if environment_characters > 1024 * 1024:
                raise TransportFailure(_UNAVAILABLE)
            names.add(key.casefold())
            pairs.append((key, value))
        command = subprocess.list2cmdline(argv)
        if len(command.encode("utf-16-le")) // 2 + 1 > 32767:
            raise TransportFailure(_UNAVAILABLE)
        environment = "\x00".join(key + "=" + value for key, value in
                                    sorted(pairs, key=lambda item: item[0].casefold())) + "\x00\x00"
        # Explicit finite preparation bound; no environment data enters errors.
        if len(pairs) > 4096 or len(environment.encode("utf-16-le")) > 2 * 1024 * 1024:
            raise TransportFailure(_UNAVAILABLE)
        command_buffer = ctypes.create_unicode_buffer(command)
        environment_buffer = ctypes.create_unicode_buffer(environment)
        self._api = api = _WinAPI()
        self._acquiring.add("job")
        job = api.CreateJobObjectW(None, None)
        if job:
            self._native["job"] = job
        self._acquiring.discard("job")
        if not job:
            raise TransportFailure(_UNAVAILABLE)
        limit = _JOB_EXTENDED_LIMIT()
        limit.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE only.
        if not api.SetInformationJobObject(job, 9, ctypes.byref(limit), ctypes.sizeof(limit)):
            raise TransportFailure(_UNAVAILABLE)
        if not api.SetHandleInformation(job, 1, 0):
            raise TransportFailure(_UNAVAILABLE)

        security = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), None, True)
        for read_name, write_name in (("child_stdin", "stdin"),
                                      ("stdout", "child_stdout")):
            reader, writer = _HANDLE(), _HANDLE()
            self._acquiring.add("pipe-" + read_name)
            self._acquisition_outputs["pipe-" + read_name] = (reader, writer)
            made = api.CreatePipe(ctypes.byref(reader), ctypes.byref(writer),
                                  ctypes.byref(security), 0)
            if made:
                self._native[read_name] = reader.value
                self._native[write_name] = writer.value
            self._acquiring.discard("pipe-" + read_name)
            del self._acquisition_outputs["pipe-" + read_name]
            if not made:
                raise TransportFailure(_UNAVAILABLE)
        for name in ("stdin", "stdout"):
            if not api.SetHandleInformation(self._native[name], 1, 0):
                raise TransportFailure(_UNAVAILABLE)
        self._acquiring.add("stderr")
        stderr = api.CreateFileW("NUL", 0x40000000, 3, ctypes.byref(security),
                                 3, 0x80, None)
        valid_stderr = stderr not in (None, ctypes.c_void_p(-1).value)
        if valid_stderr:
            self._native["stderr"] = stderr
        self._acquiring.discard("stderr")
        if not valid_stderr:
            raise TransportFailure(_UNAVAILABLE)

        size = _SIZE_T()
        ctypes.set_last_error(0)
        sized = api.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
        if sized or ctypes.get_last_error() != 122 or not 0 < size.value <= 1024 * 1024:
            raise TransportFailure(_UNAVAILABLE)
        attributes = ctypes.create_string_buffer(size.value)
        initialized = False
        try:
            if not api.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)):
                raise TransportFailure(_UNAVAILABLE)
            initialized = True
            jobs = (_HANDLE * 1)(job)
            handles = (_HANDLE * 3)(self._native["child_stdin"],
                                    self._native["child_stdout"], stderr)
            if not api.UpdateProcThreadAttribute(attributes, 0, 0x0002000D, jobs,
                                                  ctypes.sizeof(jobs), None, None):
                raise TransportFailure(_UNAVAILABLE)
            if not api.UpdateProcThreadAttribute(attributes, 0, 0x00020002, handles,
                                                  ctypes.sizeof(handles), None, None):
                raise TransportFailure(_UNAVAILABLE)
            startup = _STARTUPINFOEX()
            startup.StartupInfo.cb = ctypes.sizeof(startup)
            startup.StartupInfo.dwFlags = 0x00000100  # STARTF_USESTDHANDLES.
            startup.StartupInfo.hStdInput = self._native["child_stdin"]
            startup.StartupInfo.hStdOutput = self._native["child_stdout"]
            startup.StartupInfo.hStdError = stderr
            startup.lpAttributeList = ctypes.addressof(attributes)
            information = _PROCESS_INFORMATION()
            if not _valid_deadline(deadline):
                raise TransportFailure(_UNAVAILABLE)
            flags = 0x00080000 | 0x00000400 | 0x08000000
            self._creation_information = information
            self._acquiring.add("process")
            self._creation_result = api.CreateProcessW(
                argv[0], command_buffer, None, None, True, flags,
                environment_buffer, cwd, ctypes.byref(startup),
                ctypes.byref(information))
            if self._creation_result:
                self._adopt_process()
            else:
                self._creation_information = None
            self._acquiring.discard("process")
            if not self._creation_result:
                raise TransportFailure(_UNAVAILABLE)
        finally:
            if initialized:
                api.DeleteProcThreadAttributeList(attributes)
        for name in ("primary_thread", "child_stdin", "child_stdout", "stderr"):
            if not self._close_native(name):
                raise TransportFailure(_UNAVAILABLE)

    def _adopt_process(self):
        information = self._creation_information
        if self._creation_result and information is not None:
            self._native["process"] = information.hProcess
            self._native["primary_thread"] = information.hThread
            self._process_id = int(information.dwProcessId)
            self._creation_information = None
            self._acquiring.discard("process")

    def _close_native(self, name):
        handle = self._native.get(name)
        if handle is None:
            return True
        if self._api.CloseHandle(handle):
            del self._native[name]
            return True
        return False

    def _capture_thread(self, name):
        api = self._api
        handle = _HANDLE()
        current = api.GetCurrentProcess()
        label = "io-thread-" + name
        with self._condition:
            self._acquiring.add(label)
            self._acquisition_outputs[label] = handle
        made = api.DuplicateHandle(current, api.GetCurrentThread(), current,
                                   ctypes.byref(handle), 0x00100001, False, 0)
        with self._condition:
            if made:
                self._thread_handles[name] = handle.value
            self._acquiring.discard(label)
            del self._acquisition_outputs[label]
            self._condition.notify_all()
        if not made:
            raise TransportFailure(_UNAVAILABLE)

    def _start_io(self, deadline):
        for name, target in (("reader", self._reader_main), ("writer", self._writer_main)):
            thread = threading.Thread(target=target, name="PatchCairn worker " + name,
                                      daemon=True)
            self._threads[name] = thread
            try:
                thread.start()
            except BaseException:
                if thread.ident is None and not thread.is_alive():
                    del self._threads[name]
                raise
        with self._condition:
            while len(self._thread_handles) != 2:
                if self._fatal is not None:
                    raise self._fatal
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportFailure(_UNAVAILABLE)
                self._condition.wait(remaining)

    def _set_fatal(self):
        with self._condition:
            # Freeze delivery atomically with writer check/mark. A categorical
            # unsent failure must never be followed by a late native write.
            self._stop.set()
            if self._fatal is None:
                self._fatal = TransportFailure(_INTERRUPTED if self._sent else _UNAVAILABLE,
                                                self._sent)
                self._fatal.transport = self
            self._condition.notify_all()

    def _read_exact(self, count, *, header=False):
        result = bytearray()
        correlation = None
        while len(result) < count:
            if self._stop.is_set():
                raise _Stopped()
            chunk = ctypes.create_string_buffer(min(65536, count - len(result)))
            read = _DWORD()
            if not self._api.ReadFile(self._native["stdout"], chunk, len(chunk),
                                      ctypes.byref(read), None) or read.value == 0:
                if self._stop.is_set():
                    raise _Stopped()
                if header and not result:
                    raise _PipeEOF()
                raise _Stopped()
            if read.value > len(chunk):
                raise _Stopped()
            if header and not result:
                with self._condition:
                    correlation = self._expected
                    if correlation is None or self._reply is not None:
                        raise _Stopped()
            result.extend(chunk.raw[:read.value])
        return (result, correlation) if header else result

    def _reader_main(self):
        try:
            self._capture_thread("reader")
            while not self._stop.is_set():
                header, correlation = self._read_exact(8, header=True)
                size = _frame_length(header)
                payload = self._read_exact(size)
                value = _decode_response(payload, self._generation, *correlation)
                with self._condition:
                    if (self._stop.is_set() or self._expected != correlation
                            or self._reply is not None):
                        raise _Stopped()
                    self._reply = value
                    self._expected = None
                    self._condition.notify_all()
                # Do not retain a prior body while waiting for the next header.
                del value, payload, header, correlation
        except _PipeEOF:
            with self._condition:
                boundary = self._expected is None
                if boundary:
                    self._peer_eof = True
                    self._condition.notify_all()
            if not boundary and not self._stop.is_set():
                self._set_fatal()
        except BaseException:
            if not self._stop.is_set():
                self._set_fatal()
        finally:
            with self._condition:
                self._condition.notify_all()

    def _writer_main(self):
        try:
            self._capture_thread("writer")
            while True:
                with self._condition:
                    while self._write_slot is None and not self._stop.is_set():
                        self._condition.wait()
                    if self._stop.is_set():
                        return
                    wire = self._write_slot
                    self._write_slot = None
                offset = 0
                while offset < len(wire):
                    if self._stop.is_set():
                        raise _Stopped()
                    chunk = wire[offset:offset + 65536]
                    buffer = ctypes.create_string_buffer(chunk)
                    written = _DWORD()
                    with self._condition:
                        if self._stop.is_set():
                            raise _Stopped()
                        self._sent = True  # Any write attempt is uncertain delivery.
                    if not self._api.WriteFile(self._native["stdin"], buffer, len(chunk),
                                               ctypes.byref(written), None):
                        raise _Stopped()
                    if not 0 < written.value <= len(chunk):
                        raise _Stopped()
                    offset += written.value
                with self._condition:
                    self._write_done = True
                    self._condition.notify_all()
                del wire, chunk, buffer
        except BaseException:
            if not self._stop.is_set():
                self._set_fatal()
        finally:
            with self._condition:
                self._condition.notify_all()

    def _await_reply(self, deadline):
        with self._condition:
            while True:
                if self._fatal is not None:
                    raise self._fatal
                if self._closing:
                    raise TransportFailure(_INTERRUPTED if self._sent else _UNAVAILABLE,
                                            self._sent)
                if self._reply is not None and self._write_done:
                    value = self._reply
                    self._reply = None
                    self._sent = False
                    return value
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportFailure(_INTERRUPTED if self._sent else _UNAVAILABLE,
                                            self._sent)
                self._condition.wait(remaining)

    def _operation_failed(self):
        self._set_fatal()
        with self._condition:
            failure = self._fatal
        self.close(time.monotonic() + 5.0, force=True)
        return failure

    def receive_ready(self, deadline):
        if not self._api_gate.acquire(blocking=False):
            raise TransportFailure(_UNAVAILABLE)
        try:
            if self._owner_pid != os.getpid() or not _valid_deadline(deadline):
                raise TransportFailure(_UNAVAILABLE)
            with self._condition:
                if self._ready_received:
                    raise TransportFailure(_UNAVAILABLE)
            value = self._await_reply(deadline)
            with self._condition:
                self._ready_received = True
            return value
        except BaseException:
            raise self._operation_failed() from None
        finally:
            self._api_gate.release()

    def exchange(self, envelope, deadline):
        if not self._api_gate.acquire(blocking=False):
            raise TransportFailure(_UNAVAILABLE)
        try:
            if self._owner_pid != os.getpid() or not _valid_deadline(deadline):
                raise TransportFailure(_UNAVAILABLE)
            with self._condition:
                sequence = self._next_sequence
            wire = _encode_request(envelope, self._generation, sequence)
            with self._condition:
                if (not self._ready_received or self._closing or self._fatal is not None
                        or self._expected is not None or self._reply is not None
                        or self._write_slot is not None or not self._write_done
                        or self._peer_eof):
                    raise TransportFailure(_UNAVAILABLE)
                self._expected = (sequence, envelope["request_id"])
                self._sent = False
                self._write_done = False
                self._next_sequence += 1
                self._write_slot = wire
                self._condition.notify_all()
            return self._await_reply(deadline)
        except BaseException:
            raise self._operation_failed() from None
        finally:
            self._api_gate.release()

    def _cancel_io(self):
        with self._condition:
            handles = tuple(self._thread_handles.values())
        for handle in handles:
            # Success/not-found only requests cancellation. Completion is separate.
            self._api.CancelSynchronousIo(handle)

    def _joined_io(self):
        complete = True
        for name, thread in tuple(self._threads.items()):
            try:
                thread.join(timeout=0)
            except RuntimeError:
                complete = False
                continue
            if thread.is_alive():
                complete = False
                continue
            with self._condition:
                handle = self._thread_handles.get(name)
            if handle is not None:
                if self._api.WaitForSingleObject(handle, 0) != 0:
                    complete = False
                    continue
                if not self._api.CloseHandle(handle):
                    complete = False
                    continue
                with self._condition:
                    del self._thread_handles[name]
        return complete

    def _process_exited(self):
        handle = self._native.get("process")
        if handle is None:
            return True
        if self._api.WaitForSingleObject(handle, 0) != 0:
            return False
        code = _DWORD()
        if not self._api.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        # Release the exited process reference BEFORE querying job-zero.
        return self._close_native("process")

    def _job_empty(self):
        job = self._native.get("job")
        if job is None:
            return True
        accounting = _JOB_ACCOUNTING()
        if not self._api.QueryInformationJobObject(job, 1, ctypes.byref(accounting),
                                                   ctypes.sizeof(accounting), None):
            return False
        return accounting.ActiveProcesses == 0

    def close(self, deadline, force=False):
        """Return true only with positive job-zero + joined-I/O disposal proof.

        A false result deliberately retains all still-needed handles and keeps
        the module's live-owner interlock latched. The adapter must retain pins.
        """
        if self.quiescent:
            return True
        if not self._close_gate.acquire(blocking=False):
            return self.quiescent
        try:
            if type(deadline) not in (int, float) or not math.isfinite(deadline):
                return False
            with self._condition:
                self._closing = True
                self._stop.set()
                self._write_slot = None
                self._reply = None
                if self._fatal is None:
                    self._fatal = TransportFailure(_INTERRUPTED if self._sent else _UNAVAILABLE,
                                                    self._sent)
                    self._fatal.transport = self
                self._condition.notify_all()
            normal_until = min(deadline, time.monotonic() + 1.0)
            if self._creation_result:
                self._adopt_process()
            while True:
                api = self._api
                job = self._native.get("job")
                if api is not None:
                    if job is not None and (force or time.monotonic() >= normal_until):
                        # Retain the job handle so termination can be verified.
                        api.TerminateJobObject(job, 2)
                    self._cancel_io()
                    joined = self._joined_io()
                    # No stream/native handle is closed while its I/O user lives.
                    if joined:
                        self._close_native("stdin")
                        self._close_native("stdout")
                    # Child-side copies/initial thread are never I/O-thread users.
                    for name in ("primary_thread", "child_stdin", "child_stdout", "stderr"):
                        self._close_native(name)
                    exited = self._process_exited()
                    empty = self._job_empty() if exited else False
                else:
                    joined, exited, empty = not self._threads, True, not self._native
                with self._condition:
                    acquired = not self._acquiring
                if joined and exited and empty and acquired:
                    if api is not None:
                        for name in tuple(self._native):
                            if name != "job":
                                self._close_native(name)
                        if set(self._native) <= {"job"}:
                            self._close_native("job")
                    if not self._native and not self._thread_handles:
                        self._quiescent.set()
                        with _OWNER_LOCK:
                            _LIVE_OWNERS.discard(self)
                        return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                # Reissue cancellation: the first request can precede entry into
                # ReadFile/WriteFile. Stop prevents any further I/O iterations.
                time.sleep(min(0.01, remaining))
        except BaseException:
            return False
        finally:
            self._close_gate.release()
