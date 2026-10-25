"""Assessment family: the diagnostic record store (PD-12), the diagnostic action and its completion, and the
assessment dispatch (PLAN 3.3). The fictional fixture assessment holds here until its family code is written.
"""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import re
import stat
import uuid

import pc_paths
import pc_records
from workflow_core import digest, DIAGNOSTIC_ADAPTER
from diagnostic_core import (DiagnosticRefusal, MAX_RECORD, after_now, RECORD_RE, REQUEST_RE, SCHEMA as DIAGNOSTIC_RECORD, TOKEN_RE,
                             exact_keys, parse_time, read_diagnostic, sanitize_text, scope_tokens, validate_adapter_result,
                             validate_request)
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, write_private_new
from service_state import DEFAULT_ROOT, ServiceRefusal

DIAGNOSTIC_ADAPTER_ID = pc_records.ADAPTER_DIAGNOSTIC_COLLECT


# The diagnostic record store (PD-12: moved from diagnostic_core so the engine's validator stays pure).

def _diagnostic_encoded(value):
    try:
        data = pc_records.encoded(value)
    except pc_records.Refusal as exc:
        raise DiagnosticRefusal("Invalid bounded record", code=exc.code) from exc
    if len(data) > MAX_RECORD:
        raise DiagnosticRefusal("Record size cap exceeded")
    return data


def _diagnostic_ordinary(path, *, directory=False):
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise DiagnosticRefusal("Link or reparse point refused")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise DiagnosticRefusal("Ordinary directory required")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise DiagnosticRefusal("Single-link ordinary file required")
    return info


def _diagnostic_ancestors(path):
    for item in reversed([path, *path.parents]):
        _diagnostic_ordinary(item, directory=True)


class DiagnosticStore:
    """Append-only, content-hashed records below this toolkit's work directory."""

    def __init__(self, root=None, *, work_relative="work/diagnostics"):
        self.root = Path(root).absolute() if root is not None else DEFAULT_ROOT
        if ".." in self.root.parts:
            raise DiagnosticRefusal("Traversal in fixture root refused")
        self.fixture_root = root is not None and self.root != DEFAULT_ROOT
        _diagnostic_ancestors(self.root)
        if self.fixture_root:
            try:
                self.root.relative_to(DEFAULT_ROOT / "work")
            except ValueError as exc:
                raise DiagnosticRefusal("Fixture root must stay below toolkit work") from exc
        parts = work_relative.split("/") if isinstance(work_relative, str) else []
        if len(parts) < 2 or parts[0] != "work" or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", part) or not pc_paths.portable(part) for part in parts):
            raise DiagnosticRefusal("Safe work-relative directory required")
        self.base = self.root.joinpath(*parts)
        ensure_private_directory(self.base, create=True, parents=True, exist_ok=True)

    def _directory(self, request_id):
        if not isinstance(request_id, str) or not REQUEST_RE.fullmatch(request_id):
            raise DiagnosticRefusal("Invalid diagnostic request identifier")
        path = self.base / request_id
        _diagnostic_ancestors(path)
        ensure_private_directory(self.base)
        ensure_private_directory(path)
        return path

    def _write(self, record, prefix):
        path = self._directory(record["request_id"])
        data = _diagnostic_encoded(record)
        sha256 = hashlib.sha256(data).hexdigest()
        record_id = prefix + "-" + sha256
        target = path / (record_id + ".json")
        try:
            write_private_new(target, data)
        except FileExistsError as exc:
            raise DiagnosticRefusal("Immutable record already exists") from exc
        except PrivateWorkspaceError as exc:
            if exc.code == "private-file-create-refused" and target.exists():
                raise DiagnosticRefusal("Immutable record already exists") from exc
            raise
        return {"record_id": record_id, "record": copy.deepcopy(record), "evidence": {
            "path": target.relative_to(self.root).as_posix(), "sha256": sha256,
            "scope": copy.deepcopy(record["scope"]), "observed_utc": record["observed_utc"], "kind": record["kind"]}}

    def create_request(self, *, platform, recipe_id, symptom, scope, mode="fixture"):
        if self.fixture_root and mode != "fixture":
            raise DiagnosticRefusal("Fixture roots cannot create real requests")
        request = {"schema": DIAGNOSTIC_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": "request",
                   "request_id": "diag-" + uuid.uuid4().hex, "platform": platform, "recipe_id": recipe_id, "mode": mode,
                   "symptom": sanitize_text(symptom), "scope": scope_tokens(scope), "observed_utc": pc_records.utc_now()}
        validate_request(request)
        ensure_private_directory(self.base)
        ensure_private_directory(self.base / request["request_id"], create=True)
        return self._write(request, "request")

    def read_record(self, request_id, record_id):
        if not isinstance(record_id, str) or not (match := RECORD_RE.fullmatch(record_id)):
            raise DiagnosticRefusal("Invalid record identifier")
        path = self._directory(request_id) / (record_id + ".json")
        before = _diagnostic_ordinary(path)
        ensure_private_file(path)
        if before.st_size > MAX_RECORD:
            raise DiagnosticRefusal("Record size cap exceeded")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_nlink)
                    != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)):
                raise DiagnosticRefusal("Record identity changed")
            data = stream.read(MAX_RECORD + 1)
            after = os.fstat(stream.fileno())
        if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns) or len(data) > MAX_RECORD or hashlib.sha256(data).hexdigest() != match[2]:
            raise DiagnosticRefusal("Immutable record hash mismatch")
        try:
            record = pc_records.decode_strict(data, max_bytes=MAX_RECORD)
        except pc_records.Refusal as exc:
            raise DiagnosticRefusal("Invalid immutable record encoding", code=exc.code) from exc
        if not isinstance(record, dict) or record.get("request_id") != request_id or record.get("kind") != match[1]:
            raise DiagnosticRefusal("Foreign record identity")
        read_diagnostic(record)
        if _diagnostic_encoded(record) != data:
            raise DiagnosticRefusal("Noncanonical immutable record bytes")
        return record

    def read_request(self, request_id):
        names = [p.stem for p in self._directory(request_id).iterdir() if p.name.startswith("request-") and p.name.endswith(".json")]
        if len(names) != 1:
            raise DiagnosticRefusal("Missing or ambiguous immutable request")
        return validate_request(self.read_record(request_id, names[0]))

    def record_result(self, request_id, *, adapter_result):
        request = self.read_request(request_id)
        result = validate_adapter_result(request, adapter_result)
        result["kind"] = "result"
        result["scope"] = request["scope"]
        return self._write(result, "result")

    def record_excerpt(self, request_id, *, excerpt, observed_utc=None):
        request = self.read_request(request_id)
        observed = observed_utc or pc_records.utc_now()
        if after_now(parse_time(observed)):
            raise DiagnosticRefusal("Future excerpt observation refused")
        return self._write({"schema": DIAGNOSTIC_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": "excerpt", "request_id": request_id,
                            "mode": request["mode"], "scope": request["scope"], "observed_utc": observed,
                            "source": "owner_selected_nonsecret_excerpt", "text": sanitize_text(excerpt),
                            "limitation": "Owner-reported excerpt; not independently reproduced or a complete log."}, "excerpt")

    def _evidence_ids(self, request_id, ids):
        if not isinstance(ids, list) or len(ids) > 24 or any(not isinstance(s, str) for s in ids) or len(set(ids)) != len(ids):
            raise DiagnosticRefusal("Bounded unique evidence identifiers required")
        for record_id in ids:
            if self.read_record(request_id, record_id)["kind"] not in {"result", "excerpt"}:
                raise DiagnosticRefusal("Observation evidence required")
        return list(ids)

    def record_hypotheses(self, request_id, *, hypotheses, unknowns):
        request = self.read_request(request_id)
        if not isinstance(hypotheses, list) or not 1 <= len(hypotheses) <= 12 or not isinstance(unknowns, list) or not 1 <= len(unknowns) <= 16:
            raise DiagnosticRefusal("Bounded hypotheses and explicit unknowns required")
        clean = []
        used = set()
        for item in hypotheses:
            exact_keys(item, {"hypothesis_id", "statement", "mechanism", "original_cause", "confidence", "outcome", "evidence_ids",
                              "counterevidence_ids", "next_check"})
            if not isinstance(item["hypothesis_id"], str) or not TOKEN_RE.fullmatch(item["hypothesis_id"]) or item["hypothesis_id"] in used:
                raise DiagnosticRefusal("Unique hypothesis token required")
            used.add(item["hypothesis_id"])
            if (not isinstance(item["confidence"], str) or not isinstance(item["outcome"], str)
                    or item["confidence"] not in {"unknown", "low", "medium", "high"} or item["outcome"] not in {"supported", "disproved", "unknown"}):
                raise DiagnosticRefusal("Explicit hypothesis confidence/outcome required")
            value = copy.deepcopy(item)
            for key in ("statement", "mechanism", "original_cause", "next_check"):
                value[key] = sanitize_text(item[key], limit=1024)
                if not value[key]:
                    raise DiagnosticRefusal("Nonempty hypothesis explanations required")
            for key in ("evidence_ids", "counterevidence_ids"):
                value[key] = self._evidence_ids(request_id, item[key])
            if item["outcome"] != "unknown" and not value["evidence_ids"]:
                raise DiagnosticRefusal("Supported or disproved hypothesis needs evidence")
            clean.append(value)
        return self._write({"schema": DIAGNOSTIC_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": "hypotheses", "request_id": request_id,
                            "scope": request["scope"], "mode": request["mode"], "observed_utc": pc_records.utc_now(),
                            "hypotheses": clean, "unknowns": [sanitize_text(s, limit=1024) for s in unknowns]}, "hypotheses")

    def record_verification(self, request_id, *, action_id, plan_sha256, action_completed_utc,
                            original_success_condition, result_ids, outcome, observation):
        request = self.read_request(request_id)
        if (not isinstance(action_id, str) or not TOKEN_RE.fullmatch(action_id)
                or not isinstance(plan_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", plan_sha256)):
            raise DiagnosticRefusal("Exact action and plan binding required")
        completed = parse_time(action_completed_utc)
        if after_now(completed) or not isinstance(outcome, str) or outcome not in {"passed", "failed", "unknown"}:
            raise DiagnosticRefusal("Invalid verification time or outcome")
        ids = self._evidence_ids(request_id, result_ids)
        if outcome in {"passed", "failed"} and not ids:
            raise DiagnosticRefusal("Verification outcome requires fresh evidence")
        for record_id in ids:
            evidence = self.read_record(request_id, record_id)
            if parse_time(evidence["observed_utc"]) < completed:
                raise DiagnosticRefusal("Pre-repair evidence cannot verify a repair")
            if outcome == "passed" and evidence["kind"] == "result" and evidence["status"] != "observed":
                raise DiagnosticRefusal("Unavailable observation cannot verify success")
        condition = sanitize_text(original_success_condition, limit=1024)
        detail = sanitize_text(observation, limit=1024)
        if not condition or not detail:
            raise DiagnosticRefusal("Original success condition and actual observation required")
        return self._write({"schema": DIAGNOSTIC_RECORD, "schema_version": pc_records.SCHEMA_VERSION, "kind": "verification", "request_id": request_id,
                            "scope": request["scope"], "mode": request["mode"], "observed_utc": pc_records.utc_now(),
                            "action_id": action_id, "plan_sha256": plan_sha256, "action_completed_utc": action_completed_utc,
                            "original_success_condition": condition, "result_ids": ids, "outcome": outcome,
                            "observation": detail,
                            "limitation": "Coordinator-attributed behavior check; does not establish original cause or all-system integrity."},
                           "verification")

    def evidence_bytes(self, request_id, record_id):
        """Validated exact bytes for the engine coordinator to register itself."""
        record = self.read_record(request_id, record_id)
        return _diagnostic_encoded(record)

    def evidence_ref(self, request_id, record_id):
        record = self.read_record(request_id, record_id)
        return {"path": (self._directory(request_id) / (record_id + ".json")).relative_to(self.root).as_posix(),
                "sha256": record_id.rsplit("-", 1)[1], "scope": copy.deepcopy(record["scope"]),
                "observed_utc": record["observed_utc"], "kind": record["kind"]}


class DiagnosticsMixin:
    """The diagnostic action: a fixed recipe request, and the coordinator's observed result for a handoff."""

    def prepare_diagnostic_action(self, session_id, *, action_id, recipe_id, symptom, diagnostic_scope,
            target, benefit, risk, reversibility, verification):
        with self._lock():
            state = self._state(session_id, collecting=True)
            receipt = self.diagnostics.create_request(platform=state["platform"], recipe_id=recipe_id,
                        symptom=symptom, scope=diagnostic_scope, mode=state["mode"])
            request = receipt["record"]
            payload = {"schema": DIAGNOSTIC_ADAPTER, "schema_version": pc_records.SCHEMA_VERSION, "operation": DIAGNOSTIC_ADAPTER_ID,
                       "request": request, "request_sha256": digest(request), "inventory_sha256": digest(request)}
            return self._action(state, action_id=action_id, adapter_id=payload["operation"], kind="assessment", payload=payload,
                    inventory=request, target=target, benefit=benefit, risk=risk, reversibility=reversibility, verification=verification)

    def complete_diagnostic(self, session_id, *, operation_id, adapter_result, coordinator_observed=False):
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            self._original_authority(self.engine.read_session(session_id), operation, intent)
            if coordinator_observed is not True or operation["outcome"] is not None or intent["action"]["adapter_id"] != DIAGNOSTIC_ADAPTER_ID:
                raise ServiceRefusal("Only an active exact diagnostic handoff accepts this result")
            request = intent["payload"]["request"]
            observed = validate_adapter_result(request, adapter_result)
            record = self.diagnostics.record_result(request["request_id"], adapter_result=observed)
            return self._finish(self.engine.read_session(session_id), operation,
                                outcome="succeeded" if observed["status"] == "observed" else "failed", receipt=record)

    # Dispatch targets (service_execute.EXECUTE, service_reconcile.RECONCILE; reached only through execute_action and
    # reconcile_operation): a diagnostic completes through its own callback, so neither assessment adapter reconciles;
    # the fictional fixture assessment is not written yet.
    def _execute_diagnostic_collect(self, session_id, state, action, payload, **arguments):
        return self._run_fixed_adapter(session_id, state, action, payload, **arguments)

    def _execute_fixture_assessment(self, session_id, state, action, payload, **arguments):
        return self._execute_held(session_id, state, action, payload, **arguments)

    def _reconcile_diagnostic_collect(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)

    def _reconcile_fixture_assessment(self, session_id, operation, intent, payload, **arguments):
        return self._reconcile_held(session_id, operation, intent, payload, **arguments)
