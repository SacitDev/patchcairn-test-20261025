"""Strict wire and real owned-process fixtures; no user data or live maintenance.

Python echo children exercise the actual Windows Job/anonymous-pipe transport.
Their synthetic response bodies prove transport only, never C# filesystem success.
All generated scripts/packets remain in a newly admitted private source/work tree.
"""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import queue
import struct
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import private_workspace as private
import windows_worker as worker

PROTOCOL = "patchcairn.windows-worker.v1"
GENERATION = "1" * 32
ZERO_ID = "0" * 32
SAFE_CODES = {
    "native-dispatch-unavailable",
    "native-dispatch-interrupted-reconcile-required",
    "native-dispatch-teardown-unresolved",
}


def envelope(sequence=1, request_id="2" * 32, request_path="C:/fictional/request.json"):
    return {"protocol": PROTOCOL, "generation": GENERATION, "sequence": sequence,
            "request_id": request_id, "request_path": request_path,
            "request_sha256": "3" * 64, "operation": "probe"}


def response(sequence=1, request_id="2" * 32, body=None):
    return {"protocol": PROTOCOL, "generation": GENERATION, "sequence": sequence,
            "request_id": request_id,
            "response": {"transport_fixture_sequence": sequence} if body is None else body}


def encoded(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")


class WorkerCodecTests(unittest.TestCase):
    def refuses(self, call):
        with self.assertRaises(worker.TransportFailure) as caught:
            call()
        self.assertIn(caught.exception.code, SAFE_CODES)
        self.assertIs(type(caught.exception.may_have_sent), bool)

    def decode(self, payload):
        return worker._decode_response(payload, GENERATION, 1, "2" * 32)

    def test_frozen_wire_constants(self):
        self.assertEqual(worker.PROTOCOL, PROTOCOL)
        self.assertEqual(worker.MAGIC, b"PCW1")
        self.assertEqual(worker.MAX_REQUEST_BYTES, 8192)
        self.assertEqual(worker.MAX_RESPONSE_BYTES, 100_000_000)
        self.assertEqual(worker.MAX_SEQUENCE, 256)
        self.assertEqual(worker.MAX_JSON_DEPTH, 32)
        self.assertEqual(worker.MAX_COLLECTION_ITEMS, 20_000)
        self.assertEqual(worker.MAX_JSON_TOKENS, 1_000_000)

    def test_transport_failure_default_is_explicitly_unsent(self):
        error = worker.TransportFailure("native-dispatch-unavailable")
        self.assertEqual(error.code, "native-dispatch-unavailable")
        self.assertFalse(error.may_have_sent)

    def test_request_round_trip_is_exact_little_endian_frame(self):
        request = envelope()
        frame = worker._encode_request(request, GENERATION, 1)
        self.assertIs(type(frame), bytes)
        self.assertEqual(frame[:4], b"PCW1")
        self.assertEqual(struct.unpack("<I", frame[4:8])[0], len(frame) - 8)
        self.assertEqual(json.loads(frame[8:].decode("utf-8")), request)

    def test_response_preserves_exact_64_bit_integer_values(self):
        body = {"positive": 2**64 - 1, "signed": -(2**63), "bool": True}
        self.assertEqual(self.decode(encoded(response(body=body)))["response"], body)

    def test_frame_header_bounds_do_not_allocate_declared_body(self):
        for length in (1, 8192, 100_000_000):
            self.assertEqual(worker._frame_length(b"PCW1" + struct.pack("<I", length)), length)
        for header in (b"", b"PCW1", b"PCW1\x01\0\0", b"PCW1\x01\0\0\0x",
                       b"BAD!\x01\0\0\0", b"PCW1" + struct.pack("<I", 0),
                       b"PCW1" + struct.pack("<I", 100_000_001),
                       b"PCW1" + struct.pack("<I", 0xffffffff)):
            with self.subTest(header_size=len(header)):
                self.refuses(lambda header=header: worker._frame_length(header))

    def test_sequence_requires_strict_integer_and_generation_bound(self):
        for value in (True, False, 0, -1, 257, 1.0, "1", None, 2**100):
            with self.subTest(value_type=type(value).__name__):
                self.refuses(lambda value=value: worker._encode_request(envelope(sequence=value), GENERATION, 1))
                bad = response(sequence=value)
                self.refuses(lambda bad=bad: self.decode(encoded(bad)))
        for sequence in (1, 256):
            frame = worker._encode_request(envelope(sequence=sequence), GENERATION, sequence)
            self.assertEqual(json.loads(frame[8:])["sequence"], sequence)

    def test_response_correlation_exact_keys_and_types(self):
        for key, value in (("protocol", "fictional.other"), ("generation", "4" * 32),
                           ("sequence", 2), ("request_id", "5" * 32),
                           ("response", []), ("response", None)):
            bad = response()
            bad[key] = value
            with self.subTest(field=key):
                self.refuses(lambda bad=bad: self.decode(encoded(bad)))
        bad = response()
        bad["unexpected"] = 1
        self.refuses(lambda: self.decode(encoded(bad)))
        for key in response():
            bad = response()
            del bad[key]
            self.refuses(lambda bad=bad: self.decode(encoded(bad)))

    def test_ready_uses_only_sequence_zero_and_zero_request_id(self):
        ready = response(sequence=0, request_id=ZERO_ID)
        self.assertEqual(worker._decode_response(encoded(ready), GENERATION, 0, ZERO_ID), ready)
        self.refuses(lambda: worker._decode_response(encoded(ready), GENERATION, 1, "2" * 32))
        self.refuses(lambda: worker._decode_response(encoded(response()), GENERATION, 0, ZERO_ID))

    def test_request_exact_keys_correlation_and_bounded_encoding(self):
        for key in envelope():
            bad = envelope()
            del bad[key]
            self.refuses(lambda bad=bad: worker._encode_request(bad, GENERATION, 1))
        for key, value in (("extra", 1), ("generation", "4" * 32),
                           ("request_id", "A" * 32), ("request_id", "z" * 32),
                           ("request_sha256", "z" * 64), ("operation", "fictional-shell"),
                           ("request_path", None), ("protocol", "other")):
            bad = envelope()
            bad[key] = value
            self.refuses(lambda bad=bad: worker._encode_request(bad, GENERATION, 1))
        self.refuses(lambda: worker._encode_request(envelope(request_path="x" * 8192), GENERATION, 1))

    def test_request_cap_accepts_exact_boundary_and_rejects_one_more_byte(self):
        short = len(worker._encode_request(envelope(request_path="x"), GENERATION, 1)) - 8
        request = envelope(request_path="x" * (8192 - short + 1))
        frame = worker._encode_request(request, GENERATION, 1)
        self.assertEqual(len(frame) - 8, 8192)
        request["request_path"] += "x"
        self.refuses(lambda: worker._encode_request(request, GENERATION, 1))

    def test_strict_utf8_bom_trailing_and_root_types(self):
        payload = encoded(response())
        for bad in (b"\xef\xbb\xbf" + payload, b"\xff", payload + b"{}", b"[]", b"null", b"1", b'"text"', b"{", payload[:-1]):
            self.refuses(lambda bad=bad: self.decode(bad))

    def test_duplicate_keys_at_outer_and_nested_levels_refuse(self):
        payload = encoded(response())
        duplicate_outer = payload[:-1] + b',"protocol":"patchcairn.windows-worker.v1"}'
        duplicate_inner = encoded(response(body={"x": 1})).replace(b'"x":1', b'"x":1,"x":2')
        for bad in (duplicate_outer, duplicate_inner):
            self.refuses(lambda bad=bad: self.decode(bad))

    def test_nonfinite_numbers_refuse(self):
        for token in (b"NaN", b"Infinity", b"-Infinity", b"1e999999"):
            bad = encoded(response(body={"x": 0})).replace(b'"x":0', b'"x":' + token)
            self.refuses(lambda bad=bad: self.decode(bad))

    def test_excessive_depth_and_per_collection_bound_refuse(self):
        nested = b"[" * 33 + b"0" + b"]" * 33
        bad = encoded(response(body={"x": 0})).replace(b'"x":0', b'"x":' + nested)
        self.refuses(lambda: self.decode(bad))
        self.refuses(lambda: self.decode(encoded(response(body={"x": [0] * 20_001}))))
        self.refuses(lambda: self.decode(encoded(response(body={str(n): 0 for n in range(20_001)}))))

    def test_valid_collection_boundary_remains_available(self):
        body = {"x": [0] * 20_000}
        self.assertEqual(len(self.decode(encoded(response(body=body)))["response"]["x"]), 20_000)

    def test_aggregate_token_budget_is_distinct_from_collection_bound(self):
        # Every inner array has only 20,000 items, but aggregate tokens exceed 1M.
        body = {"rows": [[0] * 20_000 for _ in range(51)]}
        self.refuses(lambda: self.decode(encoded(response(body=body))))


# This generated child is a protocol fixture, not a native-operation simulator.
# It never imports the C# adapter or invokes PowerShell, installers or collectors.
CHILD = r'''from __future__ import annotations
import hashlib,json,os,struct,subprocess,sys,time
from pathlib import Path
P='patchcairn.windows-worker.v1'
def data(v): return json.dumps(v,separators=(',',':'),allow_nan=False).encode('utf-8')
def send_raw(v):
 sys.stdout.buffer.write(v);sys.stdout.buffer.flush()
def send(v):
 b=data(v);send_raw(b'PCW1'+struct.pack('<I',len(b))+b)
def exact(n):
 out=b''
 while len(out)<n:
  part=sys.stdin.buffer.read(n-len(out))
  if not part: raise EOFError()
  out+=part
 return out
def get():
 h=exact(8)
 if h[:4]!=b'PCW1': raise ValueError()
 n=struct.unpack('<I',h[4:])[0]
 if not 0<n<=8192: raise ValueError()
 return json.loads(exact(n))
def outer(g,s,r,b): return dict(protocol=P,generation=g,sequence=s,request_id=r,response=b)
def worker(mode,g):
 if mode=='exit_before_ready': os._exit(17)
 if mode=='no_ready': time.sleep(60);return
 ready=outer(g,0,'0'*32,{'transport_fixture_ready':True,'worker_pid':os.getpid()})
 if mode=='bad_ready': ready['generation']='f'*32
 send(ready)
 if mode=='block_write': time.sleep(60);return
 descendant=None
 while True:
  try: request=get()
  except EOFError: return
  if mode in {'effect_exit','effect_no_reply'}:
   sys.path.insert(0,sys.argv[4])
   import private_workspace as private
   marker=Path(__file__).with_name(mode+'.marker')
   if marker.exists():
    private.ensure_private_file(marker)
    with marker.open('ab') as output:
     output.write(b'fictional-effect-once\n');output.flush();os.fsync(output.fileno())
   else: private.write_private_new(marker,b'fictional-effect-once\n')
   if mode=='effect_exit': os._exit(23)
   continue
  if mode=='exit_after_request': os._exit(19)
  if mode=='no_reply': time.sleep(60);return
  if mode=='gated_reply' and request['sequence']==1:
   sys.path.insert(0,sys.argv[4])
   import private_workspace as private
   received=Path(__file__).with_name('received')
   release=Path(__file__).with_name('release')
   private.write_private_new(received,b'1')
   until=time.monotonic()+5
   while not release.exists():
    if time.monotonic()>=until: raise RuntimeError('fixture-gate-timeout')
    time.sleep(.005)
   private.ensure_private_file(release)
  reply=outer(g,request['sequence'],request['request_id'],{'transport_fixture_sequence':request['sequence']})
  if mode=='descendant':
   descendant=subprocess.Popen([sys.executable,'-I','-S','-B',__file__,'hold'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
   reply['response']['descendant_pid']=descendant.pid
  if mode=='wrong_generation': reply['generation']='f'*32
  if mode=='wrong_sequence': reply['sequence']+=1
  if mode=='wrong_request': reply['request_id']='f'*32
  if mode=='extra_key': reply['extra']=1
  b=data(reply)
  if mode=='bad_magic': send_raw(b'NOPE'+struct.pack('<I',len(b))+b);return
  if mode=='zero_length': send_raw(b'PCW1'+struct.pack('<I',0));return
  if mode=='oversized': send_raw(b'PCW1'+struct.pack('<I',100000001));return
  if mode=='truncated_header': send_raw(b'PCW1\x20\0');return
  if mode=='truncated_body': send_raw(b'PCW1'+struct.pack('<I',len(b))+b[:-2]);return
  if mode=='invalid_utf8': send_raw(b'PCW1'+struct.pack('<I',1)+b'\xff');return
  if mode=='duplicate_json':
   b=b[:-1]+b',"sequence":1}';send_raw(b'PCW1'+struct.pack('<I',len(b))+b);return
  send(reply)
  if mode=='duplicate_response': send(reply)
def parent(g,scripts,packet):
 sys.path.insert(0,scripts)
 import windows_worker as w
 import private_workspace as private
 t=w.OwnedTransport.start(argv=[sys.executable,'-I','-S','-B',__file__,'worker','descendant',g],env=dict(os.environ),cwd=os.path.dirname(__file__),generation=g,deadline=time.monotonic()+10)
 t.receive_ready(time.monotonic()+10)
 private.ensure_private_file(packet)
 raw=Path(packet).read_bytes()
 r=dict(protocol=P,generation=g,sequence=1,request_id=os.path.basename(os.path.dirname(packet))[8:],request_path=packet,request_sha256=hashlib.sha256(raw).hexdigest(),operation='probe')
 answer=t.exchange(r,time.monotonic()+10)
 sys.stdout.write(json.dumps([t.process_id,answer['response']['descendant_pid']])+'\n');sys.stdout.flush()
 sys.stdin.buffer.read(1)
 if not t.close(time.monotonic()+5,force=True): raise RuntimeError('fixture-owned-close-held')
if sys.argv[1]=='hold': time.sleep(60)
elif sys.argv[1]=='worker': worker(sys.argv[2],sys.argv[3])
elif sys.argv[1]=='parent': parent(sys.argv[2],sys.argv[3],sys.argv[4])
'''


@unittest.skipUnless(os.name == "nt", "Windows owned Job/anonymous-pipe transport")
class WindowsOwnedTransportTests(unittest.TestCase):
    def setUp(self):
        import windows_scoped
        self.assertTrue(windows_scoped.shutdown_worker(), "Earlier manager helper did not quiesce")
        self.base = ROOT / "work" / "tw" / ("c" + uuid.uuid4().hex[:8])
        self.assertLess(len(str(self.base / ("request-" + "a" * 32) / "request.json")), 240)
        private.ensure_private_directory(self.base, create=True, parents=True, boundary=ROOT / "work")
        self.temp = self.base / "t"
        private.ensure_private_directory(self.temp, create=True, boundary=self.base)
        self.script = self.base / "child.py"
        private.write_private_new(self.script, CHILD.encode("utf-8"))
        private.ensure_private_file(self.script)
        self.transports = []
        self.next_sequence = 1

    def tearDown(self):
        for transport in reversed(self.transports):
            closed = transport.close(time.monotonic() + 5, force=True)
            self.assertTrue(closed, "Owned transport teardown was not proven")
            self.assertTrue(transport.quiescent, "Quiescence requires job and I/O completion")

    def child_env(self):
        names = ("SystemRoot", "WINDIR", "COMSPEC", "PATH", "PATHEXT")
        env = {name: os.environ[name] for name in names if name in os.environ}
        env.update(TZ="UTC", TEMP=str(self.temp), TMP=str(self.temp))
        return env

    def start(self, mode="good", receive_ready=True):
        private.ensure_private_directory(self.base)
        private.ensure_private_directory(self.temp)
        private.ensure_private_file(self.script)
        try:
            transport = worker.OwnedTransport.start(
                argv=[sys.executable, "-I", "-S", "-B", str(self.script), "worker", mode, GENERATION, str(ROOT / "scripts")],
                env=self.child_env(), cwd=str(self.base), generation=GENERATION,
                deadline=time.monotonic() + 10)
        except worker.TransportFailure as error:
            if getattr(error, "transport", None) is not None:
                self.transports.append(error.transport)
            raise  # Missing supported-host launch capability must fail this test.
        self.transports.append(transport)
        if receive_ready:
            ready = transport.receive_ready(time.monotonic() + 10)
            self.assertEqual(ready["sequence"], 0)
            self.assertEqual(ready["request_id"], ZERO_ID)
            self.assertTrue(ready["response"]["transport_fixture_ready"])
            self.assertEqual(ready["response"]["worker_pid"], transport.process_id)
        return transport

    def request(self, sequence=None):
        if sequence is None:
            sequence = self.next_sequence
            self.next_sequence += 1
        request_id = uuid.uuid4().hex
        folder = self.base / ("request-" + request_id)
        private.ensure_private_directory(folder, create=True, boundary=self.base)
        path = folder / "request.json"
        payload = encoded({"fictional_transport_packet": True, "sequence": sequence})
        private.write_private_new(path, payload)
        private.ensure_private_file(path)
        result = envelope(sequence, request_id, str(path))
        result["request_sha256"] = hashlib.sha256(payload).hexdigest()
        return result

    @contextmanager
    def process_wait_handle(self, process_id):
        # Only exact IDs returned by this fixture's owned launch/frame are used.
        # This never searches processes or terminates a process by PID.
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        api.OpenProcess.restype = ctypes.c_void_p
        api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        api.WaitForSingleObject.restype = ctypes.c_uint32
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        api.CloseHandle.restype = ctypes.c_int
        handle = api.OpenProcess(0x00100000, False, process_id)
        self.assertTrue(handle, "Could not retain exact owned process wait handle")
        try:
            yield lambda milliseconds: api.WaitForSingleObject(handle, milliseconds)
        finally:
            self.assertTrue(api.CloseHandle(handle))

    def fault(self, mode, timeout=3, transport=None):
        transport = self.start(mode) if transport is None else transport
        request = self.request()
        results = queue.Queue(maxsize=1)

        def exchange_fault():
            try:
                results.put(("ok", transport.exchange(request, time.monotonic() + timeout)))
            except Exception as error:
                results.put(("error", error))

        caller = threading.Thread(target=exchange_fault, name="fixture-observed-fault")
        try:
            with self.process_wait_handle(transport.process_id) as wait:
                caller.start()
                self.assertEqual(wait(int((timeout + 6) * 1000)), 0, "Exact owned process did not terminate after the fault")
            # Release this extra process-object reference before requiring the
            # transport's job-zero teardown completion; observer handles must
            # not create an accounting dependency on their own later release.
            caller.join(timeout=6)
            self.assertFalse(caller.is_alive(), "Fault exchange did not finish after observer release")
            outcome, value = results.get_nowait()
            self.assertEqual(outcome, "error", "Faulting child unexpectedly produced a valid reply")
            self.assertIsInstance(value, worker.TransportFailure)
            self.assertEqual(value.code, "native-dispatch-interrupted-reconcile-required")
            self.assertTrue(value.may_have_sent)
            self.assertTrue(transport.close(time.monotonic() + 5, force=True))
            self.assertTrue(transport.quiescent)
            return transport
        finally:
            if caller.is_alive():
                transport.close(time.monotonic() + 5, force=True)
                caller.join(timeout=6)
            self.assertFalse(caller.is_alive(), "Fault fixture caller did not complete")

    def test_real_ready_and_serial_round_trips_keep_one_owned_process(self):
        transport = self.start()
        process_id = transport.process_id
        self.assertIs(type(process_id), int)
        self.assertGreater(process_id, 0)
        self.assertFalse(transport.quiescent)
        for sequence in range(1, 4):
            request = self.request(sequence)
            answer = transport.exchange(request, time.monotonic() + 3)
            self.assertEqual(answer, response(sequence, request["request_id"]))
            self.assertEqual(transport.process_id, process_id)
        self.assertTrue(transport.close(time.monotonic() + 5))
        self.assertTrue(transport.quiescent)

    def test_malformed_truncated_and_correlation_faults_poison_real_transport(self):
        for mode in ("bad_magic", "zero_length", "oversized", "truncated_header", "truncated_body",
                     "invalid_utf8", "duplicate_json", "wrong_generation", "wrong_sequence", "wrong_request", "extra_key"):
            with self.subTest(mode=mode):
                self.next_sequence = 1
                self.fault(mode)

    def test_process_death_after_request_is_possibly_sent(self):
        self.fault("exit_after_request")

    def test_actual_private_marker_effect_before_lost_reply_is_never_replayed(self):
        original_launch = worker.OwnedTransport._launch
        for mode in ("effect_exit", "effect_no_reply"):
            with self.subTest(mode=mode):
                transport = self.start(mode)
                attempts = []

                def observe_launch(instance, *args, **kwargs):
                    # Forward the real native launch unchanged. Record attempts
                    # without argv/env/payload values or fabricated outcomes.
                    attempts.append(1)
                    if instance not in self.transports:
                        self.transports.append(instance)
                    return original_launch(instance, *args, **kwargs)

                self.next_sequence = 1
                with mock.patch.object(worker.OwnedTransport, "_launch", new=observe_launch):
                    self.fault(mode, timeout=5, transport=transport)
                self.assertEqual(attempts, [], "Exchange attempted a replacement native launch")
                marker = self.base / (mode + ".marker")
                private.ensure_private_file(marker)
                self.assertEqual(marker.read_bytes().splitlines(), [b"fictional-effect-once"])

    def test_read_deadline_finishes_actual_owned_teardown(self):
        start = time.monotonic()
        self.fault("no_reply", timeout=.3)
        self.assertLess(time.monotonic() - start, 17, "Read fault exceeded launch plus finite teardown allowance")

    def test_nonreading_child_deadline_closes_actual_writer_and_reader(self):
        transport = self.start("block_write")
        request = self.request()
        # This is a transport-only wire-pressure reference, never dereferenced by
        # the helper. Its prefix remains in our fresh private fixture namespace;
        # no oversized filesystem path or native operation is created/executed.
        prefix = str(self.base) + "/"
        request["request_path"] = prefix
        short = len(worker._encode_request(request, GENERATION, 1)) - 8
        request["request_path"] += "x" * (8192 - short)
        self.assertEqual(len(worker._encode_request(request, GENERATION, 1)) - 8, 8192)
        results = queue.Queue(maxsize=1)

        def exchange_unread():
            try:
                results.put(("ok", transport.exchange(request, time.monotonic() + 1)))
            except Exception as error:
                results.put(("error", error))

        caller = threading.Thread(target=exchange_unread, name="fixture-unread-exchange")
        caller.start()
        observed_sent = observed_pending = False
        try:
            until = time.monotonic() + 2
            while caller.is_alive() and time.monotonic() < until:
                # Existing read-only state, not a fake creator or production
                # backdoor: pending proves an unfinished WriteFile attempt only.
                with transport._condition:
                    observed_sent |= transport._sent
                    observed_pending |= transport._sent and not transport._write_done
                time.sleep(.001)
            outcome, value = results.get(timeout=5)
            self.assertTrue(observed_sent, "Real writer never attempted the frame")
            self.assertEqual(outcome, "error", "Nonreading child unexpectedly produced a response")
            self.assertIsInstance(value, worker.TransportFailure)
            self.assertTrue(value.may_have_sent)
            self.assertEqual(value.code, "native-dispatch-interrupted-reconcile-required")
            self.assertTrue(transport.close(time.monotonic() + 5, force=True))
            self.assertTrue(transport.quiescent)
            # Do not turn a pending attempt or suggested pipe size into a claim
            # that the kernel write was blocked. That proof remains separate.
            self.nonreading_pipe_observation = "pending-write-attempt" if observed_pending else "frame-buffered-or-observation-race"
        finally:
            if caller.is_alive():
                transport.close(time.monotonic() + 5, force=True)
            caller.join(timeout=5)
            self.assertFalse(caller.is_alive(), "Nonreading fixture caller did not finish")

    def test_startup_eof_and_wrong_ready_are_unsent(self):
        for mode in ("exit_before_ready", "bad_ready"):
            with self.subTest(mode=mode):
                transport = self.start(mode, receive_ready=False)
                with self.assertRaises(worker.TransportFailure) as caught:
                    transport.receive_ready(time.monotonic() + 3)
                self.assertFalse(caught.exception.may_have_sent)
                self.assertTrue(transport.close(time.monotonic() + 5, force=True))
                self.assertTrue(transport.quiescent)

    def test_startup_deadline_is_unsent_and_finitely_closed(self):
        transport = self.start("no_ready", receive_ready=False)
        with self.assertRaises(worker.TransportFailure) as caught:
            transport.receive_ready(time.monotonic() + .3)
        self.assertFalse(caught.exception.may_have_sent)
        self.assertTrue(transport.close(time.monotonic() + 5, force=True))
        self.assertTrue(transport.quiescent)

    def test_duplicate_response_never_becomes_next_request_reply(self):
        transport = self.start("duplicate_response")
        request = self.request()
        try:
            first = transport.exchange(request, time.monotonic() + 3)
        except worker.TransportFailure as error:
            # Immediate unsolicited-frame detection is also a refusal, provided
            # it records the actual possibly-sent delivery state.
            self.assertEqual(error.code, "native-dispatch-interrupted-reconcile-required")
            self.assertTrue(error.may_have_sent)
        else:
            self.assertEqual(first["sequence"], 1)
            with self.assertRaises(worker.TransportFailure):
                transport.exchange(self.request(), time.monotonic() + 3)
        self.assertTrue(transport.close(time.monotonic() + 5, force=True))
        self.assertTrue(transport.quiescent)

    def test_direct_overlap_refuses_unsent_without_closing_active_caller(self):
        transport = self.start("gated_reply")
        first, second = self.request(1), self.request(2)
        results = queue.Queue(maxsize=1)

        def exchange_first():
            try:
                results.put(("ok", transport.exchange(first, time.monotonic() + 8)))
            except Exception as error:
                results.put(("error", error))

        caller = threading.Thread(target=exchange_first, name="fixture-active-exchange")
        caller.start()
        try:
            # A private marker from the real child proves request1 was received;
            # its reply waits for our separate private release marker.
            received, release = self.base / "received", self.base / "release"
            until = time.monotonic() + 5
            while not received.exists() and time.monotonic() < until:
                time.sleep(.005)
            self.assertTrue(received.exists(), "Real child never reached the reply barrier")
            private.ensure_private_file(received)
            with self.assertRaises(worker.TransportFailure) as caught:
                transport.exchange(second, time.monotonic() + 1)
            self.assertEqual(caught.exception.code, "native-dispatch-unavailable")
            self.assertFalse(caught.exception.may_have_sent)
            private.write_private_new(release, b"1")
            outcome, value = results.get(timeout=5)
            self.assertEqual(outcome, "ok", "The overlapping caller disrupted the active request")
            self.assertEqual(value["sequence"], 1)
            answer = transport.exchange(second, time.monotonic() + 3)
            self.assertEqual(answer["sequence"], 2)
        finally:
            if caller.is_alive():
                transport.close(time.monotonic() + 5, force=True)
            caller.join(timeout=5)
            self.assertFalse(caller.is_alive(), "Active fixture caller did not finish")

    def test_live_owner_interlock_refuses_replacement_without_harming_owner(self):
        transport = self.start()
        process_id = transport.process_id
        with self.assertRaises(worker.TransportFailure) as caught:
            self.start()
        self.assertFalse(caught.exception.may_have_sent)
        self.assertEqual(transport.process_id, process_id)
        answer = transport.exchange(self.request(), time.monotonic() + 3)
        self.assertEqual(answer["sequence"], 1)

    def test_expired_exchange_deadline_refuses_before_send(self):
        transport = self.start()
        with self.assertRaises(worker.TransportFailure) as caught:
            transport.exchange(self.request(), time.monotonic() - 1)
        self.assertFalse(caught.exception.may_have_sent)

    def test_sequence_reuse_and_257th_request_refuse_before_send(self):
        transport = self.start()
        first = self.request(1)
        transport.exchange(first, time.monotonic() + 3)
        with self.assertRaises(worker.TransportFailure) as caught:
            transport.exchange(first, time.monotonic() + 3)
        self.assertFalse(caught.exception.may_have_sent)
        # A fresh generation is required after a local invalid-envelope refusal.
        self.assertTrue(transport.close(time.monotonic() + 5, force=True))
        transport = self.start()
        with self.assertRaises(worker.TransportFailure) as caught:
            transport.exchange(self.request(257), time.monotonic() + 3)
        self.assertFalse(caught.exception.may_have_sent)

    def test_close_is_idempotent_and_proves_descendant_exit(self):
        transport = self.start("descendant")
        answer = transport.exchange(self.request(), time.monotonic() + 3)
        descendant = answer["response"]["descendant_pid"]
        self.assertIs(type(descendant), int)
        result = queue.Queue(maxsize=1)
        closer = threading.Thread(target=lambda: result.put(transport.close(time.monotonic() + 5, force=True)),
                                  name="fixture-observed-close")
        try:
            with self.process_wait_handle(transport.process_id) as wait_worker, self.process_wait_handle(descendant) as wait_child:
                closer.start()
                self.assertEqual(wait_worker(5000), 0)
                self.assertEqual(wait_child(5000), 0)
            # Both synchronization handles are now closed. Job-zero can finish
            # without any observer-held process reference, on either accounting
            # behavior permitted by the platform's documented lifetime rules.
        finally:
            if closer.ident is not None:
                closer.join(timeout=6)
                self.assertFalse(closer.is_alive(), "Observed close did not finish after observer release")
        self.assertTrue(result.get_nowait(), "Actual owned close did not prove job/I/O quiescence")
        self.assertTrue(transport.quiescent)
        self.assertTrue(transport.close(time.monotonic() + 1, force=True))

    def test_abrupt_owner_death_closes_job_and_terminates_owned_descendant(self):
        request = self.request(1)
        packet = request["request_path"]
        command = [sys.executable, "-I", "-S", "-B", str(self.script), "parent", GENERATION, str(ROOT / "scripts"), packet]
        parent = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  cwd=self.base, env=self.child_env(), close_fds=True)
        result = queue.Queue(maxsize=1)
        reader = threading.Thread(target=lambda: result.put(parent.stdout.readline(256)), name="fixture-parent-control-reader")
        reader.start()
        try:
            raw = result.get(timeout=15)
            ids = json.loads(raw)
            self.assertIs(type(ids), list)
            self.assertEqual(len(ids), 2)
            self.assertTrue(all(type(value) is int and 0 < value <= 0xffffffff for value in ids))
            with self.process_wait_handle(ids[0]) as wait_worker, self.process_wait_handle(ids[1]) as wait_child:
                parent.terminate()  # Exact test-owned Popen handle; never a PID kill.
                parent.wait(timeout=5)
                self.assertEqual(wait_worker(5000), 0, "Worker survived abrupt job-owner death")
                self.assertEqual(wait_child(5000), 0, "Descendant survived abrupt job-owner death")
        finally:
            if parent.poll() is None:
                parent.terminate()
                parent.wait(timeout=5)
            parent.stdin.close()
            parent.stdout.close()
            reader.join(timeout=5)
            self.assertFalse(reader.is_alive(), "Fixture control reader did not complete")


@unittest.skipIf(os.name == "nt", "POSIX inert-import contract")
class PosixWorkerImportTests(unittest.TestCase):
    def test_fresh_import_has_no_process_network_or_write_side_effect(self):
        # A new interpreter proves the actual import path, without patching a fake
        # Windows creator. Its audit hook denies effects before they can happen.
        code = r'''import os,sys
sys.dont_write_bytecode=True
sys.path.insert(0,sys.argv[1])
def audit(event,args):
 if event in {'subprocess.Popen','os.system','os.fork','os.posix_spawn','os.exec','os.mkdir','os.remove','os.rename','socket.connect','socket.bind'}:
  raise AssertionError('worker-import-effect-refused')
 if event=='open' and len(args)>2 and isinstance(args[2],int) and args[2]&(os.O_CREAT|os.O_TRUNC|os.O_WRONLY|os.O_RDWR):
  raise AssertionError('worker-import-write-refused')
sys.addaudithook(audit)
import windows_worker
assert windows_worker.PROTOCOL=='patchcairn.windows-worker.v1'
sys.stdout.write('inert')
'''
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code, str(ROOT / "scripts")],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=ROOT, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, "Fresh POSIX worker import attempted an effect or failed")
        self.assertEqual(result.stdout, b"inert")


"""Proposed isolated manager tests; merge into test_windows_worker after review."""
import base64
from contextlib import ExitStack, contextmanager
import hashlib
import json
from pathlib import Path
import threading
import time
import types
import unittest
from unittest import mock

import windows_scoped as adapter
from windows_worker import TransportFailure


class ManagerContractTests(unittest.TestCase):
    def setUp(self):
        self.manager = adapter._WorkerManager()
        self.events = []
        self.files = {}
        self.generation = adapter._Generation(('fictional',)*8, ExitStack(), ('a'*64, 'b'*64))
        self.generation.state = 'RESERVED'
        self.generation.pins.callback(lambda: self.events.append('generation-pins-closed'))
        self.transport = types.SimpleNamespace(quiescent=False, exchange=self.reply, close=self.close)
        self.generation.transport = self.transport
        self.manager.generation = self.generation

    def close(self, deadline, force=False):
        self.events.append('owned-job-and-io-closed')
        self.transport.quiescent = True
        return True

    def reply(self, envelope, deadline):
        self.events.append('exchange')
        return {'response': {'ok': True, 'result': {'removed': True}}}

    @contextmanager
    def directory(self, *args, **kwargs):
        self.events.append('directory-admitted')
        try:
            yield args[0]
        finally:
            self.events.append('directory-rechecked')

    def write(self, path, data):
        self.events.append('persist-response' if path.name == 'response.json' else 'persist-request')
        self.assertEqual(self.generation.state, 'INFLIGHT' if path.name == 'response.json' else 'RESERVED')
        self.files[path] = data

    def pin(self, stack, path, **kwargs):
        self.events.append('request-pinned')
        stack.callback(lambda: self.events.append('request-pin-closed'))
        return types.SimpleNamespace(data=self.files[path])

    @contextmanager
    def patches(self):
        with mock.patch.object(adapter, '_runtime', return_value='fictional-runtime'), \
             mock.patch.object(adapter, '_security_binding', return_value='fictional'), \
             mock.patch.object(self.manager, '_reserve', return_value=self.generation), \
             mock.patch.object(adapter, 'private_directory', side_effect=self.directory), \
             mock.patch.object(adapter, 'write_private_new', side_effect=self.write), \
             mock.patch.object(adapter, '_pin', side_effect=self.pin):
            yield

    def test_idle_requires_persisted_response_and_namespace_exit_checks(self):
        with self.patches():
            self.assertEqual(self.manager.dispatch('remove', {}), {'removed': True})
        self.assertEqual(self.generation.state, 'IDLE')
        self.assertLess(self.events.index('persist-response'), self.events.index('request-pin-closed'))
        self.assertEqual(self.events[-1], 'directory-rechecked')
        self.assertNotIn('owned-job-and-io-closed', self.events)

    def test_persistence_failure_tears_down_before_releasing_pins(self):
        original = self.write
        def fail(path, data):
            if path.name == 'response.json':
                raise adapter.PrivateWorkspaceError('private-file-flush-unresolved')
            original(path, data)
        with self.patches(), mock.patch.object(adapter, 'write_private_new', side_effect=fail):
            with self.assertRaises(adapter.CapabilityHold) as caught:
                self.manager.dispatch('remove', {})
        self.assertEqual(caught.exception.code, 'native-private-artifact-reconcile-required')
        self.assertLess(self.events.index('owned-job-and-io-closed'), self.events.index('request-pin-closed'))
        self.assertIsNone(self.manager.generation)

    def test_unresolved_teardown_retains_request_and_source_pins(self):
        self.transport.close = lambda *args, **kwargs: False
        self.transport.exchange = mock.Mock(side_effect=TransportFailure('native-dispatch-interrupted-reconcile-required', True))
        with self.patches(), self.assertRaises(adapter.CapabilityHold):
            self.manager.dispatch('remove', {})
        self.assertEqual(self.generation.state, 'TEARDOWN_UNRESOLVED')
        self.assertIsNotNone(self.generation.pending_pins)
        self.assertNotIn('request-pin-closed', self.events)
        self.assertNotIn('generation-pins-closed', self.events)
        self.transport.exchange.assert_called_once()
        # Explicit fixture-only cleanup, after the retained-state assertions.
        self.generation.pending_pins.close()
        self.generation.pins.close()

    def test_malformed_success_cannot_become_idle_or_trigger_replay(self):
        self.transport.exchange = mock.Mock(return_value={'response': {'ok': True, 'result': {'removed': 'true'}}})
        with self.patches(), self.assertRaises(adapter.CapabilityHold) as caught:
            self.manager.dispatch('remove', {})
        self.assertEqual(caught.exception.code, 'native-dispatch-interrupted-reconcile-required')
        self.transport.exchange.assert_called_once()
        self.assertEqual(self.generation.state, 'CLOSED')

    def test_reentrant_call_refuses_before_namespace_or_exchange(self):
        self.manager.local.active = True
        with self.patches(), self.assertRaises(adapter.CapabilityHold) as caught:
            self.manager.dispatch('remove', {})
        self.assertEqual(caught.exception.code, 'native-dispatch-busy')
        self.assertEqual(self.events, [])

    def test_full_caller_slots_refuse_without_hidden_queue(self):
        self.assertTrue(self.manager.slots.acquire(blocking=False))
        self.assertTrue(self.manager.slots.acquire(blocking=False))
        try:
            with self.patches(), self.assertRaises(adapter.CapabilityHold) as caught:
                self.manager.dispatch('remove', {})
            self.assertEqual(caught.exception.code, 'native-dispatch-busy')
            self.assertEqual(self.events, [])
        finally:
            self.manager.slots.release()
            self.manager.slots.release()

    def record(self, **changes):
        record = dict(relative_path='fictional.bin', kind='file', device=1,
            inode='a'*16, mode=32, size=3, mtime_ns=123, ctime_ns=122,
            nlink=1, sha256=hashlib.sha256(b'abc').hexdigest(), attributes=32)
        record.update(changes)
        return record

    def test_operation_specific_record_shapes_refuse_incompatible_success(self):
        expected = self.record()
        probes = [
            ('create', {'relative':'fictional.bin','data_base64':base64.b64encode(b'abc').decode()}, self.record(kind='directory')),
            ('create', {'relative':'fictional.bin','data_base64':base64.b64encode(b'abc').decode()}, self.record(size=4)),
            ('mkdir', {'relative':'fictional.bin'}, expected),
            ('move', {'destination_relative':'fictional.bin','expected':expected}, self.record(inode='b'*16)),
            ('inspect', {'relative':'fictional.bin','hash_file':True}, self.record(sha256=None)),
            ('list', {'relative':'folder','max_entries':3}, [self.record(relative_path='elsewhere/file',sha256=None)]),
            ('list', {'relative':'folder','max_entries':3}, [self.record(relative_path='folder/deep/file',sha256=None)]),
            ('list', {'relative':'folder','max_entries':3}, [self.record(relative_path='folder/file')]),
            ('read', {'max_bytes':3,'expected':expected}, {'data_base64':base64.b64encode(b'abd').decode()}),
        ]
        for operation, values, result in probes:
            with self.subTest(operation=operation):
                self.assertFalse(adapter._response_shape({'ok':True,'result':result}, operation, values))

    def test_categorical_native_refusal_is_persisted_without_poison_or_retry(self):
        self.transport.exchange = mock.Mock(return_value={'response': {'ok': False, 'code': 'expected-file-changed'}})
        with self.patches(), self.assertRaises(adapter.ScopedFSError) as caught:
            self.manager.dispatch('remove', {})
        self.assertEqual(caught.exception.code, 'expected-file-changed')
        self.assertEqual(self.generation.state, 'IDLE')
        self.transport.exchange.assert_called_once()
        self.assertIn('persist-response', self.events)

    def test_valid_native_result_shapes_remain_available(self):
        record = self.record()
        directory = self.record(kind='directory',relative_path='folder',mode=16,attributes=16,size=0,sha256=None)
        probes = [
            ('create', {'relative':'fictional.bin','data_base64':'YWJj'}, record),
            ('mkdir', {'relative':'folder'}, directory),
            ('move', {'destination_relative':'fictional.bin','expected':record}, record),
            ('inspect', {'relative':'fictional.bin','hash_file':True}, record),
            ('inspect', {'relative':'fictional.bin','hash_file':False}, self.record(sha256=None)),
            ('inspect', {'relative':'','hash_file':False}, dict(directory,relative_path='')),
            ('list', {'relative':'folder','max_entries':3}, [self.record(relative_path='folder/file',sha256=None)]),
            ('list', {'relative':'folder','max_entries':3}, []),
            ('read', {'max_bytes':3,'expected':record}, {'data_base64':'YWJj'}),
        ]
        for operation, values, result in probes:
            with self.subTest(operation=operation):
                self.assertTrue(adapter._response_shape({'ok':True,'result':result},operation,values))

    def test_security_context_drift_closes_without_acknowledgment(self):
        with self.patches(), mock.patch.object(adapter,'_security_binding',side_effect=['fictional','changed']), \
             self.assertRaises(adapter.CapabilityHold) as caught:
            self.manager.dispatch('remove',{})
        self.assertEqual(caught.exception.code,'native-security-context-changed-reconcile-required')
        self.assertNotIn('persist-response',self.events)
        self.assertEqual(self.generation.state,'CLOSED')

    def test_security_drift_during_preparation_refuses_before_send(self):
        self.transport.exchange=mock.Mock(side_effect=AssertionError('Old-context operation must not be sent'))
        with self.patches(), mock.patch.object(adapter,'_security_binding',return_value='changed'), \
             self.assertRaises(adapter.CapabilityHold) as caught:
            self.manager.dispatch('remove',{})
        self.assertEqual(caught.exception.code,'native-security-context-changed')
        self.transport.exchange.assert_not_called()
        self.assertEqual(self.generation.state,'CLOSED')

    def test_early_namespace_exit_failure_releases_all_caller_synchronization(self):
        @contextmanager
        def failing_exit(*args,**kwargs):
            yield args[0]
            raise adapter.PrivateWorkspaceError('private-owner-refused')
        self.manager.generation = None
        with self.patches(), mock.patch.object(adapter,'private_directory',side_effect=failing_exit), \
             mock.patch.object(self.manager,'_reserve',side_effect=adapter.CapabilityHold('native-dispatch-unavailable')), \
             self.assertRaises(adapter.CapabilityHold):
            self.manager.dispatch('remove',{})
        self.assertFalse(self.manager.local.active)
        self.assertTrue(self.manager.call_lock.acquire(blocking=False))
        self.manager.call_lock.release()
        self.assertTrue(self.manager.slots.acquire(blocking=False))
        self.assertTrue(self.manager.slots.acquire(blocking=False))
        self.assertFalse(self.manager.slots.acquire(blocking=False))
        self.manager.slots.release();self.manager.slots.release()

    def test_teardown_exception_publishes_unresolved_and_retains_pins(self):
        self.transport.close = mock.Mock(side_effect=AttributeError('fictional transport disposal failure'))
        self.assertFalse(self.manager._retire(self.generation,time.monotonic()+1,force=True))
        self.assertEqual(self.generation.state,'TEARDOWN_UNRESOLVED')
        self.assertNotIn('generation-pins-closed',self.events)
        self.generation.pins.close()

    def test_teardown_interruption_publishes_hold_before_propagation(self):
        self.transport.quiescent = True
        self.generation.pins.callback(mock.Mock(side_effect=KeyboardInterrupt))
        with self.assertRaises(KeyboardInterrupt):
            self.manager._retire(self.generation,time.monotonic()+1,force=True)
        self.assertEqual(self.generation.state,'TEARDOWN_UNRESOLVED')



"""Append-only regressions for repaired worker races; no production test seam.

Logic classes use explicitly fake I/O/owners and real bounded Python threads.
The Windows class alone launches an actual owned PowerShell worker. No logic
fixture result is presented as native filesystem/job success.
"""
from types import SimpleNamespace as _OpusNS
from pathlib import PureWindowsPath as _OpusWindowsPath
import shutil as _opus_shutil
import windows_scoped as opus_adapter


class OpusTransportLogicRegressionTests(unittest.TestCase):
    def _writer(self, write_file):
        owner = worker.OwnedTransport("1" * 32)  # Python state only; never launched.
        owner._api = _OpusNS(WriteFile=write_file)
        owner._native["stdin"] = 1  # Fake value, consumed only by fake WriteFile.
        owner._write_slot = b"fictional-frame"
        owner._write_done = False
        owner._capture_thread = lambda name: None  # No native thread handle exists.
        return owner

    def test_fatal_wins_before_atomic_send_mark_no_late_write(self):
        before_mark, release = threading.Event(), threading.Event()
        writes = []
        owner = self._writer(lambda *args: writes.append(1))
        real_buffer = ctypes.create_string_buffer

        def paused_buffer(value):
            buffer = real_buffer(value)
            before_mark.set()
            if not release.wait(5):
                raise AssertionError("fixture-send-barrier-timeout")
            return buffer

        proxy = _OpusNS(create_string_buffer=paused_buffer, byref=ctypes.byref)
        caller = threading.Thread(target=owner._writer_main, name="fixture-fatal-wins")
        try:
            with mock.patch.object(worker, "ctypes", proxy):
                caller.start()
                self.assertTrue(before_mark.wait(5))
                owner._set_fatal()
                self.assertTrue(owner._stop.is_set())
                self.assertFalse(owner._fatal.may_have_sent)
                release.set()
                caller.join(timeout=5)
            self.assertFalse(caller.is_alive())
            self.assertEqual(writes, [])
            self.assertFalse(owner._sent)
            self.assertEqual(owner._fatal.code, "native-dispatch-unavailable")
        finally:
            release.set()
            owner._stop.set()
            with owner._condition:
                owner._condition.notify_all()
            if caller.ident is not None:
                caller.join(timeout=5)
            self.assertFalse(caller.is_alive())

    def test_writer_wins_mark_then_fatal_keeps_possible_delivery(self):
        attempted, release = threading.Event(), threading.Event()
        writes = []

        def fake_write(handle, buffer, count, written, overlapped):
            writes.append(1)
            attempted.set()
            if not release.wait(5):
                raise AssertionError("fixture-write-barrier-timeout")
            ctypes.cast(written, ctypes.POINTER(worker._DWORD))[0] = count
            return True

        owner = self._writer(fake_write)
        caller = threading.Thread(target=owner._writer_main, name="fixture-writer-wins")
        try:
            caller.start()
            self.assertTrue(attempted.wait(5))
            owner._set_fatal()
            self.assertTrue(owner._sent)
            self.assertTrue(owner._stop.is_set())
            self.assertTrue(owner._fatal.may_have_sent)
            self.assertEqual(owner._fatal.code, "native-dispatch-interrupted-reconcile-required")
            release.set()
            caller.join(timeout=5)
            self.assertFalse(caller.is_alive())
            self.assertEqual(writes, [1])
        finally:
            release.set()
            owner._stop.set()
            with owner._condition:
                owner._condition.notify_all()
            if caller.ident is not None:
                caller.join(timeout=5)
            self.assertFalse(caller.is_alive())

    def test_created_callback_precedes_launch_and_runs_outside_owner_lock(self):
        events, owners = [], []

        def created(owner):
            owners.append(owner)
            acquired = worker._OWNER_LOCK.acquire(blocking=False)
            self.assertTrue(acquired, "Ownership callback ran inside the owner lock")
            if acquired:
                worker._OWNER_LOCK.release()
            self.assertIsNone(owner._api)
            self.assertEqual(owner._native, {})
            events.append("created")

        def fake_launch(owner, *args):
            self.assertIs(owner, owners[0])
            events.append("launch")

        def fake_io(owner, deadline):
            events.append("io")

        owner = None
        with mock.patch.object(worker, "os", _OpusNS(name="nt", getpid=os.getpid)), \
             mock.patch.object(worker, "_LIVE_OWNERS", set()), \
             mock.patch.object(worker, "_OWNER_LOCK", threading.Lock()), \
             mock.patch.object(worker.OwnedTransport, "_launch", new=fake_launch), \
             mock.patch.object(worker.OwnedTransport, "_start_io", new=fake_io):
            try:
                owner = worker.OwnedTransport.start(["fictional"], {}, "fictional", "1" * 32,
                                                    time.monotonic() + 5, on_created=created)
                self.assertEqual(events, ["created", "launch", "io"])
                self.assertFalse(worker.all_quiescent())
            finally:
                if owner is not None:
                    self.assertTrue(owner.close(time.monotonic() + 1, force=True))
            self.assertTrue(worker.all_quiescent())

    def test_callback_failure_never_launches_and_real_empty_cleanup_keeps_owner(self):
        owners, close_calls = [], []
        original_close = worker.OwnedTransport.close

        def created(owner):
            owners.append(owner)
            raise RuntimeError("fictional-callback-failure")

        def observe_close(owner, deadline, force=False):
            close_calls.append(force)
            return original_close(owner, deadline, force=force)

        with mock.patch.object(worker, "os", _OpusNS(name="nt", getpid=os.getpid)), \
             mock.patch.object(worker, "_LIVE_OWNERS", set()), \
             mock.patch.object(worker, "_OWNER_LOCK", threading.Lock()), \
             mock.patch.object(worker.OwnedTransport, "_launch") as launch, \
             mock.patch.object(worker.OwnedTransport, "_start_io") as start_io, \
             mock.patch.object(worker.OwnedTransport, "close", new=observe_close):
            with self.assertRaises(worker.TransportFailure) as caught:
                worker.OwnedTransport.start(["fictional"], {}, "fictional", "1" * 32,
                                            time.monotonic() + 5, on_created=created)
            self.assertIs(caught.exception.transport, owners[0])
            self.assertFalse(caught.exception.may_have_sent)
            self.assertTrue(owners[0].quiescent)
            self.assertEqual(close_calls, [True])
            self.assertTrue(worker.all_quiescent())
            launch.assert_not_called()
            start_io.assert_not_called()


class OpusManagerRegressionTests(unittest.TestCase):
    def setUp(self):
        # Composition reuses the existing fixture without rediscovering its14 tests.
        self.fixture = ManagerContractTests("test_idle_requires_persisted_response_and_namespace_exit_checks")
        self.fixture.setUp()

    def tearDown(self):
        generation = self.fixture.generation
        if generation.pending_pins is not None:
            generation.pending_pins.close()
        generation.pins.close()  # Fictional ExitStack callbacks only.

    def test_artifact_exit_failure_is_sticky_even_after_empty_stack_retry(self):
        fixture = self.fixture
        fixture.transport.quiescent = True
        attempts = []

        def fail_artifact():
            attempts.append(1)
            raise opus_adapter.PrivateWorkspaceError("fictional-private-exit-refusal")

        fixture.generation.pins.callback(fail_artifact)
        self.assertFalse(fixture.manager._retire(fixture.generation, time.monotonic() + 1, force=True))
        self.assertTrue(fixture.generation.artifact_unresolved)
        self.assertEqual(fixture.generation.state, "TEARDOWN_UNRESOLVED")
        self.assertFalse(fixture.manager._retire(fixture.generation, time.monotonic() + 1, force=True))
        self.assertTrue(fixture.generation.artifact_unresolved)
        self.assertEqual(fixture.generation.state, "TEARDOWN_UNRESOLVED")
        self.assertIs(fixture.manager.generation, fixture.generation)
        self.assertEqual(attempts, [1])

    def test_transient_transport_teardown_can_resolve_without_artifact_failure(self):
        fixture = self.fixture
        attempts = []

        def close(deadline, force=False):
            attempts.append(1)
            if len(attempts) == 1:
                return False
            fixture.transport.quiescent = True
            return True

        fixture.transport.close = close
        self.assertFalse(fixture.manager._retire(fixture.generation, time.monotonic() + 1, force=True))
        self.assertFalse(fixture.generation.artifact_unresolved)
        self.assertNotIn("generation-pins-closed", fixture.events)
        self.assertTrue(fixture.manager._retire(fixture.generation, time.monotonic() + 1, force=True))
        self.assertEqual(attempts, [1, 1])
        self.assertEqual(fixture.generation.state, "CLOSED")
        self.assertIsNone(fixture.manager.generation)
        self.assertFalse(fixture.generation.artifact_unresolved)

    def test_artifact_keyboard_interrupt_latches_hold_across_shutdown(self):
        fixture = self.fixture
        fixture.transport.quiescent = True

        def interrupt():
            raise KeyboardInterrupt()

        fixture.generation.pins.callback(interrupt)
        with self.assertRaises(KeyboardInterrupt):
            fixture.manager._retire(fixture.generation, time.monotonic() + 1, force=True)
        self.assertTrue(fixture.generation.artifact_unresolved)
        self.assertEqual(fixture.generation.state, "TEARDOWN_UNRESOLVED")
        with mock.patch.object(opus_adapter, "all_quiescent", return_value=True):
            self.assertFalse(fixture.manager.shutdown())
        self.assertIs(fixture.manager.generation, fixture.generation)

    def test_one_shot_acknowledgment_namespace_failure_stays_unresolved_after_retry(self):
        fixture = self.fixture
        acknowledged = fixture.generation.acknowledged
        failed = []

        @contextmanager
        def fail_once_after_persistence(*args, **kwargs):
            yield args[0]
            if "persist-response" in fixture.events and not failed:
                failed.append(1)
                raise opus_adapter.PrivateWorkspaceError("fictional-acknowledgment-namespace-refusal")

        with fixture.patches(), mock.patch.object(opus_adapter, "private_directory", side_effect=fail_once_after_persistence):
            with self.assertRaises(opus_adapter.CapabilityHold) as caught:
                fixture.manager.dispatch("remove", {})
        self.assertEqual(caught.exception.code, "native-private-artifact-reconcile-required")
        self.assertEqual(failed, [1])
        self.assertIn("persist-response", fixture.events)
        self.assertTrue(fixture.generation.artifact_unresolved)
        self.assertEqual(fixture.generation.acknowledged, acknowledged)
        self.assertEqual(fixture.generation.state, "TEARDOWN_UNRESOLVED")
        self.assertNotIn("generation-pins-closed", fixture.events)
        with mock.patch.object(opus_adapter, "all_quiescent", return_value=True):
            self.assertFalse(fixture.manager.shutdown())
            self.assertFalse(fixture.manager.shutdown())
        self.assertEqual(fixture.generation.state, "TEARDOWN_UNRESOLVED")
        self.assertIs(fixture.manager.generation, fixture.generation)
        with mock.patch.object(opus_adapter, "_capture_inputs", return_value=(fixture.generation.key, {}, fixture.generation.hashes)), \
             mock.patch.object(opus_adapter.OwnedTransport, "start", side_effect=AssertionError("Unresolved artifact was replaced")) as starter:
            with self.assertRaises(opus_adapter.CapabilityHold) as held:
                fixture.manager._reserve("fictional-runtime", time.monotonic() + 1)
            self.assertEqual(held.exception.code, "native-dispatch-teardown-unresolved")
            starter.assert_not_called()

    def test_shutdown_waits_for_pending_reaper_and_then_reports_completion(self):
        fixture = self.fixture
        fixture.generation.state = "DRAINING"
        waiting, done = threading.Event(), threading.Event()
        result = queue.Queue(maxsize=1)
        original_wait = fixture.manager.condition.wait

        def observe_wait(timeout=None):
            waiting.set()
            return original_wait(timeout)

        def shutdown():
            try:
                result.put(fixture.manager.shutdown())
            finally:
                done.set()

        caller = threading.Thread(target=shutdown, name="fixture-draining-shutdown")
        try:
            with mock.patch.object(fixture.manager.condition, "wait", new=observe_wait), \
                 mock.patch.object(opus_adapter, "all_quiescent", return_value=True):
                caller.start()
                self.assertTrue(waiting.wait(2), "Shutdown did not wait on the draining generation")
                self.assertFalse(done.is_set())
                self.assertTrue(fixture.manager._retire(fixture.generation, time.monotonic() + 1, force=False))
                caller.join(timeout=5)
            self.assertFalse(caller.is_alive())
            self.assertIs(result.get_nowait(), True)
        finally:
            with fixture.manager.condition:
                fixture.manager.generation = None  # Fictional test-thread release only.
                fixture.manager.condition.notify_all()
            if caller.ident is not None:
                caller.join(timeout=5)
            self.assertFalse(caller.is_alive())

    def test_none_manager_still_refuses_nonquiescent_global_owner(self):
        self.fixture.manager.generation = None
        owner = type("FictionalOwner", (), {"quiescent": False})()
        with mock.patch.object(worker, "_LIVE_OWNERS", {owner}), \
             mock.patch.object(worker, "_OWNER_LOCK", threading.Lock()):
            self.assertFalse(worker.all_quiescent())
            self.assertFalse(self.fixture.manager.shutdown())
            owner.quiescent = True
            self.assertTrue(self.fixture.manager.shutdown())

    def test_manager_publishes_start_owner_even_when_error_has_no_owner(self):
        fixture = self.fixture
        fixture.manager.generation = None
        generations = []

        def inputs(executable, stack):
            stack.callback(lambda: fixture.events.append("startup-source-pins-closed"))
            return (("fictional",) * 8,
                    {"Windows.Scoped.Dispatch.ps1": b"fictional-ps", "Windows.Scoped.cs": b"fictional-cs"},
                    ("a" * 64, "b" * 64))

        def start(argv, env, cwd, generation, deadline, *, on_created):
            current = fixture.manager.generation
            generations.append(current)
            self.assertIsNone(current.transport)
            on_created(fixture.transport)
            self.assertIs(current.transport, fixture.transport)
            fixture.events.append("owner-published")
            # The callback is the sole publication source in this failure path.
            raise worker.TransportFailure("native-dispatch-unavailable")

        with mock.patch.object(opus_adapter, "_capture_inputs", side_effect=inputs), \
             mock.patch.object(opus_adapter, "private_directory", side_effect=fixture.directory), \
             mock.patch.object(opus_adapter, "write_private_new", side_effect=lambda p, b: fixture.files.__setitem__(p, b)), \
             mock.patch.object(opus_adapter, "_pin", side_effect=fixture.pin), \
             mock.patch.object(opus_adapter.OwnedTransport, "start", side_effect=start) as starter:
            with self.assertRaises(opus_adapter.CapabilityHold) as caught:
                fixture.manager._reserve("fictional-runtime", time.monotonic() + 5)
        self.assertEqual(caught.exception.code, "native-dispatch-unavailable")
        starter.assert_called_once()
        self.assertEqual(generations[0].state, "CLOSED")
        self.assertTrue(fixture.transport.quiescent)
        self.assertIsNone(fixture.manager.generation)
        self.assertLess(fixture.events.index("owner-published"), fixture.events.index("owned-job-and-io-closed"))
        self.assertLess(fixture.events.index("owned-job-and-io-closed"), fixture.events.index("startup-source-pins-closed"))

    def test_queued_caller_gets_fresh_exchange_budget_after_lock_acquisition(self):
        fixture = self.fixture
        real_lock = fixture.manager.call_lock
        self.assertTrue(real_lock.acquire(blocking=False))
        waiting = threading.Event()
        result = queue.Queue(maxsize=1)
        deadlines = []

        def acquire(*args, **kwargs):
            waiting.set()
            return real_lock.acquire(*args, **kwargs)

        fixture.manager.call_lock = _OpusNS(acquire=acquire, release=real_lock.release)

        def reserve(executable, deadline):
            deadlines.append(deadline)
            return fixture.generation

        def dispatch():
            try:
                result.put(("ok", fixture.manager.dispatch("remove", {})))
            except Exception as error:
                result.put(("error", error))

        caller = threading.Thread(target=dispatch, name="fixture-queued-budget")
        held = True
        try:
            with fixture.patches(), mock.patch.object(fixture.manager, "_reserve", side_effect=reserve):
                caller.start()
                self.assertTrue(waiting.wait(2))
                released_at = time.monotonic()
                real_lock.release()
                held = False
                caller.join(timeout=5)
            self.assertFalse(caller.is_alive())
            self.assertEqual(result.get_nowait()[0], "ok")
            self.assertEqual(len(deadlines), 1)
            self.assertGreaterEqual(deadlines[0], released_at + opus_adapter._EXCHANGE_SECONDS)
        finally:
            if held:
                real_lock.release()
            if caller.ident is not None:
                caller.join(timeout=5)
            fixture.manager.call_lock = real_lock
            self.assertFalse(caller.is_alive())


class OpusFrontendRegressionTests(unittest.TestCase):
    def _scope(self, root=r"C:\fictional"):
        scope = object.__new__(opus_adapter.ScopedRoot)
        scope.root, scope._root_record, scope._closed, scope.max_entries = Path(root), None, False, 16
        return scope

    def test_invalid_expected_records_refuse_before_dispatch(self):
        fixture = ManagerContractTests("test_idle_requires_persisted_response_and_namespace_exit_checks")
        fixture.setUp()
        valid = fixture.record()
        invalid = [None, [], dict(valid, nlink=True), dict(valid, nlink=0), dict(valid, device=2**32),
                   dict(valid, size=-1), dict(valid, size=True), dict(valid, attributes=16),
                   dict(valid, mode=33), dict(valid, relative_path="../escape"), dict(valid, inode="z" * 16),
                   dict(valid, sha256="A" * 64), dict(valid, extra=1)]
        source, destination = self._scope(), self._scope(r"C:\fictional-destination")
        try:
            with mock.patch.object(opus_adapter, "_dispatch", side_effect=AssertionError("Invalid frontend record was dispatched")) as dispatch:
                for record in invalid:
                    for operation in (lambda: source.read_bytes("fictional.bin", expected=record, max_bytes=3),
                                      lambda: source.remove_file("fictional.bin", expected=record),
                                      lambda: source.move_to("fictional.bin", destination=destination,
                                                             destination_relative="fictional.bin", expected=record)):
                        with self.assertRaises(opus_adapter.ScopedFSError) as caught:
                            operation()
                        self.assertEqual(caught.exception.code, "expected-hashed-file-required")
                dispatch.assert_not_called()
        finally:
            fixture.generation.pins.close()

    def test_root241_constructor_and_changed_source_destination_refuse_before_dispatch(self):
        long_root = "C:\\" + "x" * 238
        self.assertEqual(len(long_root), 241)
        source, destination = self._scope(), self._scope(long_root)
        fixture = ManagerContractTests("test_idle_requires_persisted_response_and_namespace_exit_checks")
        fixture.setUp()
        try:
            with mock.patch.object(opus_adapter, "_dispatch", side_effect=AssertionError("Root241 was dispatched")) as dispatch:
                with self.assertRaises(opus_adapter.ScopedFSError):
                    opus_adapter.ScopedRoot(long_root, quiet_workspace=True)
                source.root = Path(long_root)
                with self.assertRaises(opus_adapter.ScopedFSError):
                    source.inspect("")
                with self.assertRaises(opus_adapter.ScopedFSError):
                    self._scope().move_to("fictional.bin", destination=destination,
                                          destination_relative="fictional.bin", expected=fixture.record())
                dispatch.assert_not_called()
        finally:
            fixture.generation.pins.close()

    def test_runtime_search_uses_only_explicit_absolute_local_path_entries(self):
        target = str(_OpusWindowsPath("C:/installed/PS") / "pwsh.exe")
        queried = []
        env = _OpusNS(name="nt", get_exec_path=lambda: ["", ".", "relative", r"\\fixture\share", "C:/safe/../escape", "C:/installed/PS", "D:/later/PS"],
                      environ={"SystemRoot": "C:/Windows"})

        class FixtureWindowsPath(_OpusWindowsPath):
            # Lexical Windows paths on every host; no filesystem lookup.
            def is_file(path):
                queried.append(str(path))
                return str(path) == target

        with mock.patch.object(opus_adapter, "os", env), \
             mock.patch.object(opus_adapter, "sys", _OpusNS(version_info=(3, 12))), \
             mock.patch.object(opus_adapter, "ctypes", _OpusNS(sizeof=lambda kind: 8, c_void_p=ctypes.c_void_p)), \
             mock.patch.object(opus_adapter, "Path", FixtureWindowsPath), \
             mock.patch.object(_opus_shutil, "which", side_effect=AssertionError("Implicit working-directory runtime search")):
            self.assertEqual(opus_adapter._runtime(), target)
        self.assertEqual(queried, [target, target])  # Candidate and final exact-path check.


@unittest.skipUnless(os.name == "nt", "Actual Windows dead-idle owned worker")
class WindowsDeadIdleWorkerRegressionTests(unittest.TestCase):
    def test_actual_dead_idle_generation_is_retired_before_fresh_probe_without_replay(self):
        self.assertTrue(opus_adapter.shutdown_worker())
        base = ROOT / "work" / "od" / ("c" + uuid.uuid4().hex[:8])
        self.assertLessEqual(len(str(base / "p" / ("worker-" + "a" * 32) / "Windows.Scoped.Dispatch.ps1")), 240)
        private.ensure_private_directory(base, create=True, parents=True, boundary=ROOT / "work")
        packets = base / "p"
        owners = []
        original_start = worker.OwnedTransport.start

        def observe_start(*args, **kwargs):
            owner = original_start(*args, **kwargs)
            owners.append(owner)
            return owner

        with mock.patch.object(opus_adapter, "_WORK_ROOT", packets), \
             mock.patch.object(worker.OwnedTransport, "start", side_effect=observe_start):
            try:
                self.assertIs(opus_adapter._dispatch("probe")["available"], True)
                old = opus_adapter._MANAGER.generation
                self.assertEqual(old.sequence, 1)
                self.assertTrue(old.transport.usable)
                with opus_adapter._MANAGER.condition:
                    self.assertEqual(old.state, "IDLE")
                    # Terminate only the exact already-owned job, with no active
                    # request and no PID search/reopen/kill or selected user data.
                    self.assertTrue(old.transport._api.TerminateJobObject(old.transport._native["job"], 23))
                    self.assertEqual(old.transport._api.WaitForSingleObject(old.transport._native["process"], 5000), 0)
                until = time.monotonic() + 5
                while old.transport.usable and time.monotonic() < until:
                    time.sleep(.005)
                self.assertFalse(old.transport.usable)
                self.assertIs(opus_adapter._dispatch("probe")["available"], True)
                new = opus_adapter._MANAGER.generation
                self.assertIsNot(new, old)
                self.assertNotEqual(new.identifier, old.identifier)
                self.assertEqual(new.sequence, 1)
                self.assertEqual(old.sequence, 1)
                self.assertEqual(old.state, "CLOSED")
                self.assertTrue(old.transport.quiescent)
                self.assertEqual(len(owners), 2)
                requests = list(packets.glob("request-*/request.json"))
                self.assertEqual(len(requests), 2)
                for request in requests:
                    private.ensure_private_file(request)
                    self.assertEqual(json.loads(request.read_bytes())["operation"], "probe")
                    private.ensure_private_file(request.parent / "response.json")
            finally:
                self.assertTrue(opus_adapter.shutdown_worker())
        self.assertTrue(worker.all_quiescent())


"""Append before unittest.main in test_windows_worker; actual PS/C# fixtures.

This fragment adds no production seam and changes no existing tests. Protocol
faults are private generated probe/inspect packets sent to a real generation
admitted by the actual adapter manager. No native success is fabricated.
"""
from contextlib import ExitStack as _PsExitStack, contextmanager as _ps_contextmanager
import shutil as _ps_shutil
import stat as _ps_stat
import windows_scoped as ps_adapter


@unittest.skipUnless(os.name == "nt", "Windows actual PowerShell worker boundary")
class WindowsPowerShellWorkerContractTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(ps_adapter.shutdown_worker(), "Prior process-owned worker did not quiesce")
        self.base = ROOT / "work" / "pw" / ("c" + uuid.uuid4().hex[:8])
        self.assertLessEqual(len(str(self.base / "d00" / "p" / ("request-" + "a" * 32) / "request.json")), 240)
        private.ensure_private_directory(self.base, create=True, parents=True, boundary=ROOT / "work")
        self.case_number = 0

    def tearDown(self):
        self.assertTrue(ps_adapter.shutdown_worker(), "Actual worker job/I/O/pins did not quiesce")
        self._assert_artifact_budget()

    def _editions(self):
        preferred = _ps_shutil.which("pwsh.exe")
        legacy = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        self.assertTrue(preferred is not None and Path(preferred).is_file(), "PowerShell7 is required for the supported Windows fixture host")
        self.assertTrue(legacy.is_file(), "Windows PowerShell5.1 is required for the supported Windows fixture host")
        return (("Core", str(preferred)), ("Desktop", str(legacy)))

    def _mkdir(self, path, *, parents=False):
        self.assertLessEqual(len(str(path)), 240)
        return private.ensure_private_directory(path, create=True, parents=parents, boundary=self.base)

    def _write(self, path, data):
        self.assertLessEqual(len(str(path)), 240)
        private.write_private_new(path, data)
        private.ensure_private_file(path)

    @_ps_contextmanager
    def _edition(self, edition, executable):
        self.assertTrue(ps_adapter.shutdown_worker())
        self.case_number += 1
        directory = self._mkdir(self.base / ("d" + str(self.case_number).zfill(2)))
        selected = self._mkdir(directory / "s")
        packets = directory / "p"
        observed_ready = []
        original_ready = worker.OwnedTransport.receive_ready

        def record_real_ready(instance, deadline):
            outer = original_ready(instance, deadline)
            observed_ready.append(outer["response"]["result"])
            return outer  # The actual transport reply, unchanged.

        with mock.patch.object(ps_adapter, "_WORK_ROOT", packets), \
             mock.patch.object(ps_adapter, "_runtime", return_value=executable), \
             mock.patch.object(worker.OwnedTransport, "receive_ready", new=record_real_ready):
            try:
                yield {"selected": selected, "packets": packets, "ready": observed_ready}
            finally:
                # Retire while the exact runtime/work key is still installed.
                self.assertTrue(ps_adapter.shutdown_worker(), "Actual edition teardown was not proven")
                for ready in observed_ready:
                    self.assertEqual(ready["powershell_edition"], edition)
                    major_minor = tuple(int(p) for p in ready["powershell_version"].split(".")[:2])
                    self.assertTrue(major_minor[0] >= 7 if edition == "Core" else major_minor == (5, 1))
                    self.assertEqual(ready["bitness"], 64)
                    self.assertEqual(ready["language_mode"], "FullLanguage")

    def _probe(self):
        result = ps_adapter._dispatch("probe")
        self.assertIs(result["available"], True)
        self.assertEqual(result["adapter"], "windows-scoped-handles-v3")
        generation = ps_adapter._MANAGER.generation
        self.assertIsNotNone(generation)
        self.assertIsInstance(generation.transport, worker.OwnedTransport)
        return generation

    def _assert_artifact_budget(self):
        # Metadata only, confined to this fresh test tree; inherited compiler
        # directories are not incorrectly required to have protected DACLs.
        pending = [(self.base, 0)]
        size = nodes = 0
        while pending:
            directory, depth = pending.pop()
            self.assertLessEqual(depth, 12)
            for entry in os.scandir(directory):
                nodes += 1
                self.assertLessEqual(nodes, 4096)
                info = Path(entry.path).lstat()
                self.assertFalse(getattr(info, "st_file_attributes", 0) & 0x400)
                if _ps_stat.S_ISDIR(info.st_mode):
                    pending.append((Path(entry.path), depth + 1))
                else:
                    self.assertTrue(_ps_stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                    size += info.st_size
                    self.assertLessEqual(size, 64 * 1024 * 1024)

    def _write_open(self, path, *, permitted):
        private.ensure_private_file(path)
        api = private._WindowsSecurity()
        ctypes.set_last_error(0)
        handle = api.kernel.CreateFileW(str(path), 0x40000000, 7, None,
                                       3, 0x00200080, None)  # OPEN_EXISTING; no write.
        error = ctypes.get_last_error()
        if handle == ctypes.c_void_p(-1).value:
            if permitted:
                self.fail("Private fixture remained write-pinned after the required release")
            self.assertEqual(error, 32, "Expected the actual deny-write sharing pin")
        else:
            self.assertTrue(bool(api.kernel.CloseHandle(handle)), "Fixture write-probe handle did not close")
            self.assertTrue(permitted, "Private fixture was writable while its immutable pin was required")

    def test_actual_empty_single_multi_list_and_legal_date_like_name_both_editions(self):
        for edition, executable in self._editions():
            with self.subTest(edition=edition), self._edition(edition, executable) as case:
                with ps_adapter.ScopedRoot(case["selected"], quiet_workspace=True) as scope:
                    self.assertEqual(scope.list_directory(), [])
                    self._write(case["selected"] / "2026-10-24", b"fictional date-like filename")
                    one = scope.list_directory()
                    self.assertIs(type(one), list)
                    self.assertEqual([r["relative_path"] for r in one], ["2026-10-24"])
                    self.assertIs(type(one[0]["relative_path"]), str)
                    dated = scope.inspect("2026-10-24", hash_file=True, max_bytes=1024)
                    self.assertIs(type(dated["relative_path"]), str)
                    self.assertEqual(scope.read_bytes("2026-10-24", expected=dated, max_bytes=1024), b"fictional date-like filename")
                    self._write(case["selected"] / "second.bin", b"second fictional entry")
                    many = scope.list_directory()
                    self.assertIs(type(many), list)
                    self.assertEqual({r["relative_path"] for r in many}, {"2026-10-24", "second.bin"})
                    self.assertTrue(all(r["kind"] == "file" and r["sha256"] is None for r in many))
                self.assertEqual(len(case["ready"]), 1)

    def test_actual_timestamp_above_2pow53_roundtrips_as_exact_int64_both_editions(self):
        target = 1_700_000_000_123_456_700  # NTFS100ns precision; not exactly a Double.
        self.assertGreater(target, 2**53)
        self.assertNotEqual(int(float(target)), target)
        for edition, executable in self._editions():
            with self.subTest(edition=edition), self._edition(edition, executable) as case:
                path = case["selected"] / "timestamp.bin"
                payload = b"fictional exact timestamp packet roundtrip"
                self._write(path, payload)
                os.utime(path, ns=(target, target))
                private.ensure_private_file(path)
                self.assertEqual(path.stat().st_mtime_ns, target)
                with ps_adapter.ScopedRoot(case["selected"], quiet_workspace=True) as scope:
                    record = scope.inspect("timestamp.bin", hash_file=True, max_bytes=1024)
                    self.assertIs(type(record["mtime_ns"]), int)
                    self.assertEqual(record["mtime_ns"], target)
                    self.assertEqual(scope.read_bytes("timestamp.bin", expected=record, max_bytes=1024), payload)
                request_files = list(case["packets"].glob("request-*/request.json"))
                reads = []
                for retained in request_files:
                    private.ensure_private_file(retained)
                    reads.append(json.loads(retained.read_bytes()))
                reads = [q for q in reads if q["operation"] == "read"]
                self.assertEqual(len(reads), 1)
                self.assertIs(type(reads[0]["expected"]["mtime_ns"]), int)
                self.assertEqual(reads[0]["expected"]["mtime_ns"], target)

    def test_private_snapshot_and_request_pins_release_without_retaining_selected_file_handles(self):
        for edition, executable in self._editions():
            with self.subTest(edition=edition), self._edition(edition, executable) as case:
                source_hashes = {name: hashlib.sha256((ROOT / "scripts" / name).read_bytes()).digest()
                                 for name in ("Windows.Scoped.Dispatch.ps1", "Windows.Scoped.cs")}
                observed_packets = []
                original_exchange = worker.OwnedTransport.exchange

                def observe_real_exchange(instance, request, deadline):
                    packet = Path(request["request_path"])
                    self._write_open(packet, permitted=False)
                    observed_packets.append(packet)
                    return original_exchange(instance, request, deadline)

                with mock.patch.object(worker.OwnedTransport, "exchange", new=observe_real_exchange):
                    generation = self._probe()
                directory = case["packets"] / ("worker-" + generation.identifier)
                snapshots = [directory / name for name in source_hashes]
                for snapshot in snapshots:
                    self._write_open(snapshot, permitted=False)
                    self.assertEqual(hashlib.sha256(snapshot.read_bytes()).digest(), source_hashes[snapshot.name])
                self.assertEqual(len(observed_packets), 1)
                self._write_open(observed_packets[0], permitted=True)
                selected_file = case["selected"] / "selected.bin"
                self._write(selected_file, b"fictional selected handle lifetime")
                with ps_adapter.ScopedRoot(case["selected"], quiet_workspace=True) as scope:
                    record = scope.inspect("selected.bin", hash_file=True, max_bytes=1024)
                    self._write_open(selected_file, permitted=True)
                    self.assertEqual(scope.read_bytes("selected.bin", expected=record, max_bytes=1024), b"fictional selected handle lifetime")
                    self._write_open(selected_file, permitted=True)
                self.assertTrue(ps_adapter.shutdown_worker())
                self.assertTrue(generation.transport.quiescent)
                self.assertEqual(generation.state, "CLOSED")
                for snapshot in snapshots:
                    self._write_open(snapshot, permitted=True)
                    self.assertEqual(hashlib.sha256(snapshot.read_bytes()).digest(), source_hashes[snapshot.name])
                for name, expected in source_hashes.items():
                    self.assertEqual(hashlib.sha256((ROOT / "scripts" / name).read_bytes()).digest(), expected)

    def _exact_directory(self, parent, length):
        remaining = length - len(str(parent)) - 1
        self.assertTrue(1 <= remaining <= 255)
        result = parent / ("r" + "x" * (remaining - 1))
        self.assertEqual(len(str(result)), length)
        return self._mkdir(result)

    def test_actual_selected_root_239_and_240_characters_are_accepted_both_editions(self):
        for edition, executable in self._editions():
            with self.subTest(edition=edition), self._edition(edition, executable) as case:
                for length in (239, 240):
                    with self.subTest(path_length=length):
                        selected = self._exact_directory(case["selected"], length)
                        with ps_adapter.ScopedRoot(selected, quiet_workspace=True) as scope:
                            record = scope.inspect("")
                            self.assertEqual(record["kind"], "directory")
                            self.assertEqual(scope.list_directory(), [])

    def _inspect_packet(self, selected):
        root_record = ps_adapter._dispatch("inspect", root=str(selected), root_record=None,
                                          relative="", hash_file=False, max_bytes=1024)
        return {"schema": "patchcairn.windows-scoped.v3", "operation": "inspect", "quiet_workspace": True,
                "root_record": root_record, "root": str(selected), "relative": "", "hash_file": False, "max_bytes": 1024}

    def _fault_bytes(self, name, selected):
        probe = {"schema": "patchcairn.windows-scoped.v3", "operation": "probe", "quiet_workspace": True, "root_record": None}
        if name in {"float", "exponent", "nonfinite", "bool_integer", "int64_high", "int64_low", "record_float",
                    "nested_duplicate", "nested_unknown", "root241", "relative201"}:
            packet = self._inspect_packet(selected)
        else:
            packet = probe
        raw = json.dumps(packet, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if name == "duplicate":
            raw = raw[:-1] + b',"operation":"probe"}'
        elif name == "case_duplicate":
            raw = raw[:-1] + b',"Operation":"probe"}'
        elif name == "case_key":
            raw = raw.replace(b'"schema":', b'"Schema":', 1)
        elif name == "unknown":
            raw = raw[:-1] + b',"unexpected":true}'
        elif name in {"float", "exponent", "nonfinite", "bool_integer"}:
            value = {"float": b"1.0", "exponent": b"1e0", "nonfinite": b"NaN", "bool_integer": b"true"}[name]
            raw = raw.replace(b'"max_bytes":1024', b'"max_bytes":' + value)
        elif name in {"int64_high", "int64_low", "record_float"}:
            packet["root_record"]["mtime_ns"] = {"int64_high": 2**63, "int64_low": -(2**63) - 1, "record_float": 1.0}[name]
            raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
        elif name == "nested_duplicate":
            token = b'"mtime_ns":' + str(packet["root_record"]["mtime_ns"]).encode("ascii")
            raw = raw.replace(token, token + b"," + token, 1)
        elif name == "nested_unknown":
            packet["root_record"]["unexpected"] = 1
            raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
        elif name == "root241":
            prefix = str(selected) + os.sep
            packet["root"] = prefix + "x" * (241 - len(prefix))
            self.assertEqual(len(packet["root"]), 241)  # Text only; never create a241 path.
            raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
        elif name == "relative201":
            packet["relative"] = "x" * 201
            raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
        elif name == "operation_case":
            raw = raw.replace(b'"operation":"probe"', b'"operation":"Probe"', 1)
        elif name == "invalid_utf8":
            raw = b"\xff"
        elif name == "array":
            raw = raw[:-1] + b',"unexpected":[]}'
        elif name not in {"hash", "path_alias", "wrong_path"}:
            self.fail("Unknown static packet-fault fixture")
        return packet["operation"], raw

    def _send_packet_fault(self, case, name):
        self._probe()
        operation, raw = self._fault_bytes(name, case["selected"])
        # Payload operation_case deliberately disagrees with the fixed envelope.
        if name == "operation_case":
            operation = "probe"
        manager = ps_adapter._MANAGER
        self.assertTrue(manager.call_lock.acquire(timeout=5), "Fixture manager reservation was not available")
        pending = _PsExitStack()
        generation = None
        try:
            with manager.condition:
                generation = manager.generation
                self.assertIsNotNone(generation)
                self.assertEqual(generation.state, "IDLE")
                generation.state = "RESERVED"
            pending.enter_context(private.private_directory(case["packets"]))
            request_id = uuid.uuid4().hex
            directory = case["packets"] / ("request-" + request_id)
            pending.enter_context(private.private_directory(directory, create=True, boundary=case["packets"]))
            packet = directory / "request.json"
            self._write(packet, raw)
            pin = ps_adapter._ReadPin(packet, private=True, maximum=100_000_000)
            pending.callback(pin.close)
            self.assertEqual(pin.data, raw)
            path = str(packet)
            sha = hashlib.sha256(raw).hexdigest()
            if name == "hash":
                sha = "0" * 64
            elif name == "path_alias":
                path = str(packet.parent) + os.sep + "." + os.sep + packet.name
            elif name == "wrong_path":
                other = self._mkdir(case["packets"] / "other") / "request.json"
                self._write(other, raw)
                path = str(other)
            with manager.condition:
                generation.sequence += 1
                sequence = generation.sequence
                generation.state = "INFLIGHT"
            request = {"protocol": worker.PROTOCOL, "generation": generation.identifier, "sequence": sequence,
                       "request_id": request_id, "request_path": path, "request_sha256": sha, "operation": operation}
            # Establish that the parent codec accepts the envelope: the actual
            # child must reject the generated packet, not a fake transport seam.
            worker._encode_request(request, generation.identifier, sequence)
            with self.assertRaises(worker.TransportFailure) as caught:
                generation.transport.exchange(request, time.monotonic() + 10)
            self.assertEqual(caught.exception.code, "native-dispatch-interrupted-reconcile-required")
            self.assertTrue(caught.exception.may_have_sent)
            self.assertFalse((directory / "response.json").exists())
        finally:
            try:
                if generation is not None:
                    done = generation.transport.close(time.monotonic() + 5, force=True)
                    if not done:
                        generation.pending_pins = pending.pop_all()
                    self.assertTrue(done, "Malformed-packet generation teardown was not proven")
                    self.assertTrue(generation.transport.quiescent)
            finally:
                try:
                    pending.close()
                finally:
                    manager.call_lock.release()

    def test_actual_child_strict_packet_faults_both_editions(self):
        faults = ("duplicate", "case_duplicate", "case_key", "unknown", "float", "exponent", "nonfinite", "bool_integer",
                  "int64_high", "int64_low", "record_float", "nested_duplicate", "nested_unknown", "root241", "relative201",
                  "operation_case", "invalid_utf8", "array", "hash", "path_alias", "wrong_path")
        for edition, executable in self._editions():
            for name in faults:
                with self.subTest(edition=edition, fault=name), self._edition(edition, executable) as case:
                    self._send_packet_fault(case, name)
                    self._assert_artifact_budget()

    def test_actual_256_acknowledgements_retire_before_request257_both_editions(self):
        self.assertEqual(worker.MAX_SEQUENCE, 256)
        for edition, executable in self._editions():
            with self.subTest(edition=edition), self._edition(edition, executable) as case:
                old = self._probe()
                for index in range(255):
                    self.assertIs(self._probe(), old)
                    if index % 16 == 0:
                        self._assert_artifact_budget()
                self.assertEqual(old.sequence, 256)
                new = self._probe()
                self.assertIsNot(new, old)
                self.assertNotEqual(new.identifier, old.identifier)
                self.assertEqual(new.sequence, 1)
                self.assertEqual(old.state, "CLOSED")
                self.assertTrue(old.transport.quiescent)
                self.assertEqual(len(case["ready"]), 2)

    def test_actual_age_retirement_with_only_fixture_created_time_advanced_both_editions(self):
        for edition, executable in self._editions():
            with self.subTest(edition=edition), self._edition(edition, executable) as case:
                old = self._probe()
                with ps_adapter._MANAGER.condition:
                    self.assertEqual(old.state, "IDLE")
                    old.created = time.monotonic() - ps_adapter._MAX_AGE_SECONDS - 1
                    ps_adapter._MANAGER.condition.notify_all()
                new = self._probe()
                self.assertIsNot(new, old)
                self.assertNotEqual(new.identifier, old.identifier)
                self.assertEqual(old.state, "CLOSED")
                self.assertTrue(old.transport.quiescent)
                self.assertEqual(len(case["ready"]), 2)

    def test_actual_default_60_second_idle_retirement_preferred_edition(self):
        edition, executable = self._editions()[0]
        self.assertEqual(edition, "Core")
        self.assertEqual(ps_adapter._IDLE_SECONDS, 60.0)
        with self._edition(edition, executable) as case:
            old = self._probe()
            snapshot = case["packets"] / ("worker-" + old.identifier) / "Windows.Scoped.cs"
            self._write_open(snapshot, permitted=False)
            start = time.monotonic()
            deadline = start + 80
            with ps_adapter._MANAGER.condition:
                while old.state != "CLOSED" and time.monotonic() < deadline:
                    ps_adapter._MANAGER.condition.wait(min(.25, max(0, deadline - time.monotonic())))
                self.assertEqual(old.state, "CLOSED", "Actual default idle timer did not finitely retire the generation")
                self.assertIsNone(ps_adapter._MANAGER.generation)
            self.assertLess(time.monotonic() - start, 80)
            self.assertTrue(old.transport.quiescent)
            self._write_open(snapshot, permitted=True)
            self.assertEqual(len(case["ready"]), 1)  # No later call triggered retirement.


"""Append one actual advertised-cap regression; no inherited test discovery."""
import shutil as _cap_shutil
import stat as _cap_stat


@unittest.skipUnless(os.name == "nt", "Actual Windows64MiB advertised native cap")
class WindowsNativeAdvertisedCapTests(unittest.TestCase):
    def _artifacts(self, root, maximum, max_nodes):
        pending, total, nodes = [(root, 0)], 0, 0
        while pending:
            directory, depth = pending.pop()
            self.assertLessEqual(depth, 12)
            for entry in os.scandir(directory):
                self.assertLessEqual(depth + 1, 12)
                path = Path(entry.path)
                info = path.lstat()
                nodes += 1
                self.assertLessEqual(nodes, max_nodes)
                self.assertFalse(getattr(info, "st_file_attributes", 0) & 0x400)
                if _cap_stat.S_ISDIR(info.st_mode):
                    pending.append((path, depth + 1))
                else:
                    self.assertTrue(_cap_stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                    private.ensure_private_file(path)
                    total += info.st_size
                    self.assertLessEqual(total, maximum)
        return total

    def test_actual_67108864_create_inspect_read_both_editions(self):
        helper = WindowsPowerShellWorkerContractTests("test_actual_empty_single_multi_list_and_legal_date_like_name_both_editions")
        helper.setUp()  # Composition creates a fresh admitted short source/work root.
        cap, per_edition, aggregate = 67_108_864, 512 * 1024**2, 1024**3
        try:
            self.assertTrue(_cap_shutil.disk_usage(helper.base).free >= 4 * 1024**3,
                            "Advertised-cap fixture requires4GiB available at its private test volume")
            payload = b"F" * cap
            expected = hashlib.sha256(payload).hexdigest()
            for edition, executable in helper._editions():
                with self.subTest(edition=edition):
                    with helper._edition(edition, executable) as case:
                        with ps_adapter.ScopedRoot(case["selected"], quiet_workspace=True) as scope:
                            created = scope.create_file("cap.bin", data=payload, max_bytes=cap)
                            self.assertTrue(ps_adapter._record_shape(created))
                            self.assertEqual((created["relative_path"], created["kind"], created["size"], created["nlink"], created["sha256"]),
                                             ("cap.bin", "file", cap, 1, expected))
                            self._artifacts(case["selected"].parent, per_edition, 4096)
                            inspected = scope.inspect("cap.bin", hash_file=True, max_bytes=cap)
                            self.assertEqual(inspected, created)
                            self._artifacts(case["selected"].parent, per_edition, 4096)
                            restored = scope.read_bytes("cap.bin", expected=inspected, max_bytes=cap)
                            self.assertEqual(len(restored), cap)
                            self.assertTrue(restored == payload, "Native64MiB read differs from the generated fixture")
                            self.assertEqual(hashlib.sha256(restored).hexdigest(), expected)
                            del restored
                        generation = ps_adapter._MANAGER.generation
                        self.assertEqual(generation.sequence, 4)
                        requests = list(case["packets"].glob("request-*"))
                        self.assertEqual(len(requests), 4)
                        private.ensure_private_directory(case["packets"])
                        for directory in case["packets"].iterdir():
                            private.ensure_private_directory(directory)
                        request_sizes = [(r / "request.json").stat().st_size for r in requests]
                        response_sizes = [(r / "response.json").stat().st_size for r in requests]
                        self.assertLessEqual(max(request_sizes + response_sizes), 100_000_000)
                        self.assertEqual(sum(n >= 89_478_488 for n in request_sizes), 1)
                        self.assertEqual(sum(n >= 89_478_488 for n in response_sizes), 1)
                        self._artifacts(case["selected"].parent, per_edition, 4096)
                        self.assertEqual(len(case["ready"]), 1)
                    self.assertEqual(generation.state, "CLOSED")
                    self.assertTrue(generation.transport.quiescent)
                    self.assertTrue(worker.all_quiescent())
                    self._artifacts(helper.base, aggregate, 8192)
        finally:
            self.assertTrue(ps_adapter.shutdown_worker())
            self._artifacts(helper.base, aggregate, 8192)
            # helper.tearDown's64MiB artifact budget belongs to its small tests;
            # this test keeps its explicit512MiB/1GiB budgets instead.

if __name__ == "__main__":
    unittest.main()
