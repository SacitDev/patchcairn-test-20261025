"""Fixed v3 adapter coordination; never executes a command from a payload.

The engine owns authority and canonical state. This service owns immutable
adapter intents and recovery retention, and calls only named library methods.
External official-tool actions remain a trusted assistant/host handoff.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import re
import sys
import uuid
from urllib.parse import urlsplit

from workflow_core import WorkflowEngine, WorkflowRefusal, encoded, digest, utc_now, _read, _decode, _no_links, _atomic, _fields, _id, _time
from storage_ops import StorageService, StorageRefusal, plan_sha256, _protected
from scoped_fs import ScopedFSError, ScopedRoot
from diagnostic_core import DiagnosticStore, DiagnosticRefusal, validate_request, validate_adapter_result, sanitize_text, SENSITIVE
from diagnostic_posix import collect_recipe
from private_workspace import PrivateWorkspaceError, ensure_private_directory, ensure_private_file, write_private_new

SCHEMA = "patchcairn.service.v3"
DEFAULT_ROOT = Path(__file__).absolute().parent.parent
STORAGE = {
    "storage.backup_create.v3": ("backup_create", "backup", "backup"),
    "storage.backup_restore.v3": ("backup_restore", "restore", "restore"),
    "storage.cleanup_quarantine.v3": ("cleanup_quarantine", "quarantine", "quarantine"),
    "storage.quarantine_restore.v3": ("backup_restore", "quarantine_restore", "quarantine-restore"),
    "storage.permanent_purge.v3": ("permanent_purge", "purge", "purge"),
}
OFFICIAL_DOMAINS = {
    "windows.msiexec.install": {"learn.microsoft.com", "support.microsoft.com"},
    "macos.installer.pkg": {"support.apple.com", "developer.apple.com"},
    "linux.dpkg.install_local": {"manpages.debian.org", "www.debian.org", "debian.org"},
    "windows.winget.upgrade": {"learn.microsoft.com", "support.microsoft.com"},
    "windows.dism.restorehealth": {"learn.microsoft.com", "support.microsoft.com"},
    "macos.softwareupdate.install": {"support.apple.com", "developer.apple.com"},
    "linux.apt.upgrade_selected": {"manpages.debian.org", "www.debian.org", "debian.org", "ubuntu.com"},
    "linux.dnf.upgrade_selected": {"dnf.readthedocs.io", "dnf5.readthedocs.io", "docs.fedoraproject.org"},
    "linux.dpkg.configure_selected": {"manpages.debian.org", "www.debian.org", "debian.org"},
}
ARTIFACT_EXTENSIONS = {"windows.msiexec.install": {".msi"}, "macos.installer.pkg": {".pkg"},
                       "linux.dpkg.install_local": {".deb"}}


class ServiceRefusal(ValueError):
    """Preserve a held/consumed operation; no weaker fallback or retry."""


def native_platform():
    return "windows" if sys.platform == "win32" else "macos" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "unknown"


def _within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _selected_text(value):
    clean = sanitize_text(value, limit=2000)
    if not clean or clean != value.strip():
        raise ServiceRefusal("Provide selected nonsecret text without private paths or credential-like values")
    return clean


def _private_read(path, max_bytes=16_000_000):
    ensure_private_file(path)
    return _read(path, max_bytes)


class WorkflowService:
    def __init__(self, engine=None, *, work_relative="work/services"):
        self.engine = engine if engine is not None else WorkflowEngine()
        self.root = self.engine.root
        if self.root != DEFAULT_ROOT and not _within(self.root, DEFAULT_ROOT / "work"):
            raise ServiceRefusal("Development root must stay below this toolkit's work tree")
        rel = PurePosixPath(work_relative)
        if not isinstance(work_relative, str) or rel.is_absolute() or "\\" in work_relative or len(rel.parts) < 2 or rel.parts[0] != "work" or any(part in {".", ".."} or not part.replace("-", "").replace("_", "").isalnum() for part in rel.parts):
            raise ServiceRefusal("Safe named work child required")
        self.work = _no_links(self.root.joinpath(*rel.parts))
        ensure_private_directory(self.work, create=True, parents=True, exist_ok=True)
        marker = self.work / "service.json"
        expected = {"schema_version": SCHEMA, "engine_id": self.engine.marker["engine_id"], "backend": self.engine.marker["backend"]}
        if not marker.exists():
            if any(self.work.iterdir()):
                raise ServiceRefusal("Missing service marker in nonempty storage; no recreation")
            self._immutable(marker, expected)
            self._immutable(self.work / "retention.json", {"schema_version": SCHEMA, "entries": []})
        if _decode(_private_read(marker)) != expected:
            raise ServiceRefusal("Foreign service/engine binding")
        self.diagnostics = DiagnosticStore(self.root, work_relative=work_relative + "/diagnostics")
        self._retention()

    @staticmethod
    def _immutable(path, value):
        _no_links(path)
        data = encoded(value)
        if len(data) > 8_000_000:
            raise ServiceRefusal("Service record cap exceeded")
        write_private_new(path, data)
        return {"path": str(path), "sha256": digest(data)}

    @contextmanager
    def _lock(self):
        path = self.work / ".coordinator-lock"
        try:
            ensure_private_directory(path, create=True)
        except FileExistsError as exc:
            raise ServiceRefusal("Service is active or interrupted; inspect before another action") from exc
        except PrivateWorkspaceError as exc:
            if exc.code == "private-directory-exists":
                raise ServiceRefusal("Service is active or interrupted; inspect before another action") from None
            raise
        try:
            yield
        finally:
            path.rmdir()

    def _state(self, session_id, *, collecting=False):
        ensure_private_directory(self.work)
        state = self.engine.read_session(session_id)
        if collecting and (state["status"] not in {"active", "awaiting_user"} or not state["scope_authorization"]):
            raise ServiceRefusal("Current selected collection scope and active session required")
        if collecting:
            self.engine._require_schedule_activation(state)
        if state["mode"] == "real" and state["platform"] != native_platform():
            raise ServiceRefusal("Real service requires the actual matching native platform")
        return state

    def _owned(self, value, *, state=None, existing=False):
        if not isinstance(value, str) or not Path(value).is_absolute() or ".." in Path(value).parts:
            raise ServiceRefusal("Exact absolute owned-work path required")
        path = _no_links(Path(value))
        if path == self.root / "work" or not _within(path, self.root / "work"):
            raise ServiceRefusal("Output must remain below this engine's owned work root")
        if existing and not path.is_dir():
            raise ServiceRefusal("Existing positively owned output directory required")
        return path

    def _retention(self):
        ensure_private_directory(self.work)
        registry = _decode(_private_read(self.work / "retention.json"))
        _fields(registry, {"schema_version", "entries"}, {"schema_version", "entries"})
        if registry["schema_version"] != SCHEMA or not isinstance(registry["entries"], list) or len(registry["entries"]) > 10000:
            raise ServiceRefusal("Invalid protected retention registry")
        rows = []
        for ref in registry["entries"]:
            _fields(ref, {"name", "sha256"}, {"name", "sha256"})
            _id(ref["name"])
            data = _private_read(self.work / (ref["name"] + ".json"))
            if digest(data) != ref["sha256"]:
                raise ServiceRefusal("Protected retention record changed")
            row = _decode(data)
            if row.get("schema_version") != SCHEMA or row.get("kind") != "required_retention" or not isinstance(row.get("artifacts"), dict) or not row["artifacts"]:
                raise ServiceRefusal("Invalid protected retention evidence")
            protection = self._owned(row.get("protection_root"))
            for path in row["artifacts"]:
                if not _within(self._owned(path), protection):
                    raise ServiceRefusal("Retention protection does not contain its exact artifacts")
            if "quarantine_binding" in row:
                self._validate_quarantine_reservation(row)
            rows.append(row)
        return rows

    def protected_roots(self):
        values = {str(self.engine.work), str(self.work)}
        for row in self._retention():
            values.add(row["protection_root"])
        if len(values) > 30:
            raise ServiceRefusal("Protection policy exceeds adapter cap; retain evidence and narrow scope")
        return sorted(values)

    def _retain(self, session_id, artifacts, *, reason, quarantine_binding=None):
        for path in artifacts:
            self._owned(path)
        row = {"schema_version": SCHEMA, "kind": "required_retention", "session_id": session_id,
               "observed_utc": utc_now(), "reason": reason, "artifacts": artifacts,
               "protection_root": os.path.commonpath([str(Path(path).parent) for path in artifacts])}
        if quarantine_binding is not None:
            row["quarantine_binding"] = copy.deepcopy(quarantine_binding)
        name = "retention-" + uuid.uuid4().hex
        ref = self._immutable(self.work / (name + ".json"), row)
        registry = _decode(_private_read(self.work / "retention.json"))
        registry["entries"].append({"name": name, "sha256": ref["sha256"]})
        _atomic(self.work / "retention.json", encoded(registry))

    @staticmethod
    def _quarantine_mapping(plan):
        return [{"original": row, "quarantine_relative": plan["quarantine_relative"] + f"/{index:06d}"}
                for index, row in enumerate(plan["files"], 1)]

    @staticmethod
    def _quarantine_artifacts(output, plan):
        native_sha = digest(plan)
        artifacts = {str(output / ("attempt-quarantine-" + native_sha + ".json")): None,
                     str(output / ("outcome-quarantine-" + native_sha + ".json")): None}
        for index, row in enumerate(plan["files"], 1):
            artifacts[str(output / plan["quarantine_relative"] / f"{index:06d}")] = row["sha256"]
            artifacts[str(output / f"step-quarantine-{native_sha}-{index:06d}.json")] = None
        return artifacts

    def _validate_quarantine_reservation(self, row):
        binding = row["quarantine_binding"]
        fields = {"schema_version", "engine_id", "mode", "platform", "session_id", "operation_id",
                  "workflow_plan_sha256", "adapter_payload_sha256", "native_plan_sha256", "output_root",
                  "original_plan", "quarantine_mapping", "intent_sha256", "native_origin_sha256"}
        _fields(binding, fields, fields)
        for key in ("session_id", "operation_id"):
            _id(binding[key])
        plan = binding["original_plan"]
        if (binding["schema_version"] != "patchcairn.quarantine.reservation.v3"
                or binding["engine_id"] != self.engine.marker["engine_id"]
                or binding["mode"] not in {"fixture", "real"} or binding["platform"] not in {"windows", "macos", "linux"}
                or row["session_id"] != binding["session_id"] or row["protection_root"] != binding["output_root"]
                or not isinstance(plan, dict) or plan.get("kind") != "quarantine"
                or digest(plan) != binding["native_plan_sha256"]
                or binding["quarantine_mapping"] != self._quarantine_mapping(plan)
                or row["artifacts"] != self._quarantine_artifacts(Path(binding["output_root"]), plan)):
            raise ServiceRefusal("Quarantine reservation differs from its exact original plan, namespace or mapping")
        intent_path = self.work / "operations" / binding["session_id"] / binding["operation_id"] / "intent.json"
        intent = _decode(_private_read(intent_path))
        origin = _decode(_private_read(self.work / ("origin-" + binding["native_plan_sha256"] + ".json")))
        if (digest(intent) != binding["intent_sha256"] or digest(origin) != binding["native_origin_sha256"]
                or intent["payload"]["storage_plan"] != plan or intent["payload"]["output_root"] != binding["output_root"]
                or intent["quarantine_mapping"] != binding["quarantine_mapping"]
                or intent["action"]["adapter_payload_sha256"] != binding["adapter_payload_sha256"]
                or intent["operation"]["plan_sha256"] != binding["workflow_plan_sha256"]
                or any(origin.get(key) != binding[key] for key in ("engine_id", "mode", "platform", "session_id", "operation_id"))
                or origin.get("native_plan_sha256") != binding["native_plan_sha256"]
                or origin.get("workflow_plan_sha256") != binding["workflow_plan_sha256"]):
            raise ServiceRefusal("Original quarantine intent or native provenance changed; preserve the reserved output")

    def _reserve_quarantine(self, state, operation, action, payload, intent):
        plan, output = payload["storage_plan"], Path(payload["output_root"])
        origin = _decode(_private_read(self.work / ("origin-" + digest(plan) + ".json")))
        binding = {"schema_version": "patchcairn.quarantine.reservation.v3",
                   **{key: state[key] for key in ("engine_id", "mode", "platform", "session_id")},
                   "operation_id": operation["operation_id"], "workflow_plan_sha256": operation["plan_sha256"],
                   "adapter_payload_sha256": action["adapter_payload_sha256"], "native_plan_sha256": digest(plan),
                   "output_root": str(output), "original_plan": plan, "quarantine_mapping": self._quarantine_mapping(plan),
                   "intent_sha256": digest(intent), "native_origin_sha256": digest(origin)}
        artifacts = self._quarantine_artifacts(output, plan)
        self._validate_quarantine_reservation({"quarantine_binding": binding, "session_id": state["session_id"],
                                               "protection_root": str(output), "artifacts": artifacts})
        self._retain(state["session_id"], artifacts, quarantine_binding=binding,
                     reason="Exact quarantine output, original intent/native provenance and mapping reserved before the first move; no automatic release")

    def _quarantine_reservations(self, state, payload, output, plan):
        reservations = [row["quarantine_binding"] for row in self._retention() if "quarantine_binding" in row]
        for binding in reservations:
            reserved = Path(binding["output_root"])
            if not (_within(output, reserved) or _within(reserved, output)):
                continue
            receipt = plan.get("receipt")
            original = binding["original_plan"]
            if (payload["operation"] not in {"storage.quarantine_restore.v3", "storage.permanent_purge.v3"}
                    or output != reserved or binding["mode"] != state["mode"] or binding["platform"] != state["platform"]
                    or not isinstance(receipt, dict) or receipt.get("plan_sha256") != binding["native_plan_sha256"]
                    or receipt.get("source_roots") != original["inventory"]["roots"]
                    or any(receipt.get(key) != original[key] for key in ("quarantine_destination", "recovery_required", "recovery_backup", "recovery_verification"))
                    or [{"original": row["original"], "quarantine_relative": row["quarantine_record"]["relative_path"]}
                        for row in receipt.get("records", [])] != binding["quarantine_mapping"]):
                raise ServiceRefusal("Reserved quarantine output permits only its exact original receipt-mapped restoration or backed purge")
        return reservations

    @staticmethod
    def _purge_original_recovery(payload):
        if payload["operation"] == "storage.permanent_purge.v3":
            receipt = payload["storage_plan"].get("receipt")
            if (not isinstance(receipt, dict) or receipt.get("recovery_required") is not True
                    or not isinstance(receipt.get("recovery_backup"), dict) or not isinstance(receipt.get("recovery_verification"), dict)):
                raise ServiceRefusal("Integrated permanent purge requires the original quarantine's exact verified backup and restoration probe")

    def _register(self, state, *, kind, value, facts=None, observed_utc=None):
        evidence_id = "service-" + uuid.uuid4().hex
        return self.engine.register_evidence(state["session_id"], evidence_id=evidence_id, content=encoded(value),
                kind=kind, scope=state["settings"]["scope"], facts=facts or {}, observed_utc=observed_utc)["data"]

    def _action(self, state, *, action_id, adapter_id, kind, payload, inventory, target, benefit, risk,
                reversibility, verification, requires_recovery=False, recovery_evidence_ids=None, requires_os_consent=False):
        _id(action_id)
        prose = {key: _selected_text(value) for key, value in (("target", target), ("benefit", benefit), ("risk", risk), ("reversibility", reversibility), ("verification", verification))}
        inventory_row = self._register(state, kind="inventory", value=inventory, facts={"complete": True, "item_count": len(inventory.get("entries", inventory.get("records", []))) if isinstance(inventory, dict) else 1})
        payload_row = self._register(state, kind="adapter_payload", value=payload)
        native_plan = payload.get("storage_plan", payload.get("request", payload.get("external_plan")))
        return {"action_id": action_id, "kind": kind, **prose, "mutating": kind != "assessment",
                "requires_os_consent": requires_os_consent, "requires_recovery": requires_recovery,
                "recovery_evidence_ids": recovery_evidence_ids or [], "adapter_id": adapter_id,
                "adapter_payload_evidence_id": payload_row["evidence_id"], "adapter_payload_sha256": payload_row["sha256"],
                "adapter_plan_sha256": digest(native_plan), "target_inventory_evidence_id": inventory_row["evidence_id"],
                "target_inventory_sha256": inventory_row["sha256"]}

    def _storage(self, state, payload):
        if payload["operation"] not in STORAGE or payload["mode"] != state["mode"]:
            raise ServiceRefusal("Unsupported storage adapter or mode")
        output = self._owned(payload["output_root"], state=state, existing=True)
        protections = payload["protected_roots"]
        if not isinstance(protections, list) or len(set(protections)) != len(protections) or not set(self.protected_roots()) <= set(protections):
            raise ServiceRefusal("Exact current protected retention policy must be included in the reviewed payload")
        plan = payload["storage_plan"]
        if plan.get("kind") != STORAGE[payload["operation"]][1] or plan_sha256(plan) != payload["storage_plan_sha256"]:
            raise ServiceRefusal("Wrong native plan type or changed exact plan hash")
        self._purge_original_recovery(payload)
        reservations = self._quarantine_reservations(state, payload, output, plan)
        service = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=protections)
        if "inventory" in plan:
            roots = [item["path"] for item in plan["inventory"]["roots"]]
        elif plan["kind"] == "restore":
            roots = [item["path"] for item in service.verify_backup(receipt=plan["receipt"])["manifest"]["source_roots"]]
        else:
            roots = [item["path"] for item in plan["receipt"]["source_roots"]]
        if any(_within(Path(root), Path(binding["output_root"])) or _within(Path(binding["output_root"]), Path(root))
               for root in roots for binding in reservations):
            raise ServiceRefusal("Reserved quarantine evidence and originals cannot become another plan's selected source scope")
        if sorted(roots) != sorted(state["settings"]["scope"]["roots"]):
            raise ServiceRefusal("Native source roots differ from the exact authorized workflow scope")
        if state["mode"] == "fixture" and any(not _within(_no_links(Path(root)), self.root / "work") for root in roots):
            raise ServiceRefusal("Fixture operations are confined to explicitly selected owned work copies")
        if "restore_probe_destination" in payload:
            probe = self._owned(payload["restore_probe_destination"], state=state)
            if payload["operation"] != "storage.backup_create.v3" or not _within(probe, output) or probe == output or probe.exists():
                raise ServiceRefusal("Backup verification probe requires a new exact owned output child")
            if any(_within(probe, Path(root)) or _within(Path(root), probe) for root in roots):
                raise ServiceRefusal("Restore probe cannot overlap original sources")
        return service

    def prepare_storage_action(self, session_id, *, action_id, adapter_id, storage_plan, output_root,
            target, benefit, risk, reversibility, verification, protected_roots=None,
            recovery_evidence_ids=None, requires_os_consent=False, restore_probe_destination=None):
        with self._lock():
            state = self._state(session_id, collecting=True)
            if adapter_id not in STORAGE:
                raise ServiceRefusal("Unsupported fixed storage adapter")
            protections = sorted(set(self.protected_roots()) | set(protected_roots or []))
            payload = {"schema_version": "patchcairn.storage.adapter.v3", "operation": adapter_id,
                       "storage_plan": copy.deepcopy(storage_plan), "storage_plan_sha256": plan_sha256(storage_plan),
                       "output_root": str(output_root), "mode": state["mode"], "protected_roots": protections}
            if restore_probe_destination is not None:
                payload["restore_probe_destination"] = str(restore_probe_destination)
            service = self._storage(state, payload)
            service.check_preconditions(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"])
            if adapter_id == "storage.quarantine_restore.v3":
                if recovery_evidence_ids:
                    raise ServiceRefusal("Quarantine restoration uses its exact typed quarantine recovery; omit unrelated recovery evidence")
                recovery = self._quarantine_recovery(state, payload)
                recovery_evidence_ids = [recovery["evidence_id"]]
                payload["protected_roots"] = sorted(set(self.protected_roots()) | set(protected_roots or []))
            inventory = storage_plan.get("inventory", storage_plan.get("records", storage_plan.get("receipt")))
            kind = STORAGE[adapter_id][0]
            required = kind in {"backup_restore", "permanent_purge"} or storage_plan.get("recovery_required") is True
            action = self._action(state, action_id=action_id, adapter_id=adapter_id, kind=kind, payload=payload,
                    inventory=inventory, target=target, benefit=benefit, risk=risk, reversibility=reversibility,
                    verification=verification, requires_recovery=required,
                    recovery_evidence_ids=recovery_evidence_ids, requires_os_consent=requires_os_consent)
            if adapter_id == "storage.permanent_purge.v3":
                self.engine._recovery(self.engine.read_session(session_id), action["recovery_evidence_ids"], action=action)
            return action

    def prepare_diagnostic_action(self, session_id, *, action_id, recipe_id, symptom, diagnostic_scope,
            target, benefit, risk, reversibility, verification):
        with self._lock():
            state = self._state(session_id, collecting=True)
            receipt = self.diagnostics.create_request(platform=state["platform"], recipe_id=recipe_id,
                        symptom=symptom, scope=diagnostic_scope, mode=state["mode"])
            request = receipt["record"]
            payload = {"schema_version": "patchcairn.diagnostic.adapter.v3", "operation": "diagnostic.read_recipe.v3",
                       "request": request, "request_sha256": digest(request), "inventory_sha256": digest(request)}
            return self._action(state, action_id=action_id, adapter_id=payload["operation"], kind="assessment", payload=payload,
                    inventory=request, target=target, benefit=benefit, risk=risk, reversibility=reversibility, verification=verification)

    def prepare_external_action(self, session_id, *, action_id, external_plan, inventory,
            target, benefit, risk, reversibility, verification, requires_recovery=False,
            recovery_evidence_ids=None, requires_os_consent=True):
        with self._lock():
            state = self._state(session_id, collecting=True)
            if isinstance(external_plan, dict) and external_plan.get("kind") == "repair":
                raise ServiceRefusal("OS/app repair is held: file-content ZIP recovery cannot establish exact component recovery")
            if external_plan.get("catalog_id") not in ARTIFACT_EXTENSIONS:
                raise ServiceRefusal("Manager handoff held: the current argv cannot enforce exact reviewed content; use a supported fixed local-artifact update")
            if requires_os_consent is not True:
                raise ServiceRefusal("Fixed local installer handoffs require actual coordinator-recorded protected OS consent")
            self.engine._external_plan(state, external_plan, inventory)
            self._external_sources(external_plan)
            payload = {"schema_version": "patchcairn.external.adapter.v3", "operation": "system.reviewed_external.v3",
                       "external_plan": copy.deepcopy(external_plan), "external_plan_sha256": digest(external_plan),
                       "inventory_sha256": digest(inventory)}
            return self._action(state, action_id=action_id, adapter_id=payload["operation"], kind=external_plan["kind"],
                    payload=payload, inventory=inventory, target=target, benefit=benefit, risk=risk,
                    reversibility=reversibility, verification=verification,
                    requires_recovery=requires_recovery or external_plan["kind"] == "repair",
                    recovery_evidence_ids=recovery_evidence_ids, requires_os_consent=requires_os_consent)

    @staticmethod
    def _external_sources(plan):
        for url in plan["sources"]:
            parsed = urlsplit(url)
            if parsed.hostname not in OFFICIAL_DOMAINS.get(plan["catalog_id"], set()) or parsed.query or parsed.fragment or any(ord(c) <= 32 for c in url):
                raise ServiceRefusal("Selected catalog requires a reviewed primary official source without credential-bearing URL data")
        for value in plan["targets"]:
            if plan["catalog_id"] == "windows.msiexec.install" and re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}", value):
                continue
            if SENSITIVE.search(value):
                raise ServiceRefusal("Potential credential value in external plan refused before persistence")
        for value in [plan["recovery_plan"]["limits"], plan["verification_plan"]["original_success_condition"]]:
            if SENSITIVE.search(value):
                raise ServiceRefusal("Potential credential value in external plan refused before persistence")
        for check in plan["verification_plan"]["checks"]:
            _selected_text(check["description"])
            _selected_text(check["expected_result"])
        for identity in plan["target_identities"].values():
            for key in ("publisher", "channel", "source_id"):
                _selected_text(identity[key])

    def register_recovery(self, session_id, *, output_root, backup_receipt, restore_receipt):
        with self._lock():
            return self._register_recovery(session_id, output_root, backup_receipt, restore_receipt)

    def _quarantine_recovery(self, state, payload):
        plan, output = payload["storage_plan"], Path(payload["output_root"])
        receipt = plan["receipt"]
        attempt = output / receipt["attempt"]
        artifacts = {str(attempt): digest(_read(attempt)),
                     str(output / ("outcome-quarantine-" + receipt["plan_sha256"] + ".json")): digest(receipt)}
        for row in receipt["records"]:
            artifacts[str(output / row["quarantine_record"]["relative_path"])] = row["quarantine_record"]["sha256"]
        retention = {"schema_version": "patchcairn.recovery.retention.v3", "session_id": state["session_id"],
                     "required": True, "artifacts": artifacts}
        retention_row = self._register(state, kind="retention", value=retention)
        binding = {"schema_version": "patchcairn.quarantine.recovery.v3", "output_root": str(output),
                   "quarantine_receipt": receipt, "restore_plan": plan, "restore_plan_sha256": digest(plan),
                   "retention_evidence_id": retention_row["evidence_id"]}
        row = self._register(state, kind="recovery", value=binding)
        self._retain(state["session_id"], artifacts, reason="Exact original quarantine mapping, native bytes and immutable receipts retained for reviewed no-overwrite restoration")
        return row

    def _register_recovery(self, session_id, output_root, backup, restore, *, completing=False):
        state = self._state(session_id, collecting=not completing)
        output = self._owned(str(output_root), state=state, existing=True)
        storage = StorageService(output_root=str(output), quiet_workspace=True, protected_roots=self.protected_roots())
        manifest = storage.verify_backup(receipt=backup)["manifest"]
        storage._verified_recovery(backup=backup, restoration=restore)
        for receipt in (backup, restore):
            origin = _decode(_private_read(self.work / ("origin-" + receipt["plan_sha256"] + ".json")))
            if origin.get("engine_id") != state["engine_id"] or origin.get("mode") != state["mode"] or origin.get("platform") != state["platform"]:
                raise ServiceRefusal("Recovery has no matching gated native fixture/real origin")
        if backup.get("required_recovery") is not True or sorted(row["path"] for row in manifest["source_roots"]) != sorted(state["settings"]["scope"]["roots"]):
            raise ServiceRefusal("Recovery must cover this exact selected scope and remain required")
        if state["mode"] == "fixture" and any(not _within(Path(row["path"]), self.root / "work") for row in manifest["source_roots"]):
            raise ServiceRefusal("Fixture recovery cannot import real source scope")
        artifacts = {backup["archive"]: backup["archive_sha256"], backup["manifest"]: backup["manifest_sha256"],
                     str(output / ("outcome-restore-" + restore["plan_sha256"] + ".json")): digest(restore)}
        for file in manifest["files"]:
            artifacts[str(Path(restore["destination"]) / file["root_id"] / file["relative_path"])] = file["sha256"]
        self._retain(session_id, artifacts, reason="Exact verified required archive, manifest and restoration probe; no automatic release")
        if state["status"] == "stopped":
            return {"registration": "preserved_in_service_retention_after_stop", "artifacts": artifacts,
                    "limitation": "Stopped session accepts only the active operation outcome; no new recovery authority was created."}
        retention = {"schema_version": "patchcairn.recovery.retention.v3", "session_id": session_id,
                     "required": True, "artifacts": artifacts}
        retention_row = self._register(state, kind="retention", value=retention)
        binding = {"schema_version": "patchcairn.recovery.binding.v3", "output_root": str(output),
                   "backup_receipt": backup, "restore_receipt": restore, "retention_evidence_id": retention_row["evidence_id"]}
        row = self._register(state, kind="recovery", value=binding)
        self.engine._recovery(self.engine.read_session(session_id), [row["evidence_id"]])
        return row

    def _binding(self, state, action_id, plan_sha256_value):
        document = self.engine._plan(state, plan_sha256_value)
        actions = [a for a in document["actions"] if a["action_id"] == action_id]
        if len(actions) != 1:
            raise ServiceRefusal("Exact current action required")
        action = actions[0]
        payload = self.engine._action_binding(state, action)
        if action["adapter_id"] not in STORAGE and action["adapter_id"] not in {"diagnostic.read_recipe.v3", "system.reviewed_external.v3"}:
            raise ServiceRefusal("No fixed service adapter exists for this action")
        if digest(payload) != action["adapter_payload_sha256"]:
            raise ServiceRefusal("Actual payload bytes differ from approved adapter payload")
        return action, payload

    def _artifact(self, state, plan, path, expected_sha256):
        value = self._owned(path, state=state)
        if value.suffix.casefold() not in ARTIFACT_EXTENSIONS.get(plan["catalog_id"], set()) or _protected(value.as_posix()):
            raise ServiceRefusal("Only the selected owned noncredential installer artifact format may be opened")
        with ScopedRoot(value.parent, quiet_workspace=True) as source:
            observed = source.inspect(value.name, hash_file=True, max_bytes=64 * 1024 * 1024)
        if observed["kind"] != "file" or observed["nlink"] != 1 or observed["sha256"] != expected_sha256:
            raise ServiceRefusal("Actual selected installer bytes differ from the reviewed exact content identity")
        return observed

    def _external_preflight(self, state, action, payload, evidence_ids):
        plan = payload["external_plan"]
        rows = self.engine._evidence(state, evidence_ids, kinds={"precondition"}, after=state["plan"]["registered_utc"], seconds=900)
        admitted = False
        for row in rows:
            value = _decode(_read(self.engine.work / state["session_id"] / row["path"]))
            if not isinstance(value, dict) or value.get("schema_version") != "patchcairn.external.preflight.v3":
                continue
            fields = {"schema_version", "action_id", "plan_sha256", "external_plan_sha256", "mode", "platform", "observed_utc", "targets"}
            _fields(value, fields, fields)
            if value["action_id"] != action["action_id"] or value["plan_sha256"] != state["plan"]["sha256"] or value["external_plan_sha256"] != digest(plan) or value["mode"] != state["mode"] or value["platform"] != state["platform"] or value["observed_utc"] != row["observed_utc"] or not isinstance(value["targets"], dict) or set(value["targets"]) != set(plan["targets"]):
                raise ServiceRefusal("Preexecution proof must bind this exact reviewed action, target variants and observed time")
            for target, observed in value["targets"].items():
                expected = {**plan["target_identities"][target], "version": plan["target_versions"][target]}
                extras = {"artifact_path", "artifact_record", "signature_evidence_id", "metadata_evidence_id"}
                _fields(observed, set(expected) | extras, set(expected) | extras)
                if any(observed[key] != item for key, item in expected.items()):
                    raise ServiceRefusal("Preexecution selected variant differs from the reviewed version/channel/architecture/scope/publisher/content")
                if observed["artifact_path"] != plan["argv"][1] or self._artifact(state, plan, observed["artifact_path"], expected["content_sha256"]) != observed["artifact_record"]:
                    raise ServiceRefusal("Actual local installer path/native identity differs from the exact approved argv and preflight record")
                signature_row = self.engine._evidence(state, [observed["signature_evidence_id"]], kinds={"research", "precondition"}, after=state["plan"]["registered_utc"], seconds=900)[0]
                signature = _decode(_read(self.engine.work / state["session_id"] / signature_row["path"]))
                signature_fields = {"schema_version", "mode", "platform", "artifact_sha256", "publisher", "status", "source_id", "method", "observed_utc"}
                _fields(signature, signature_fields, signature_fields)
                method = "windows.authenticode" if state["platform"] == "windows" else "apple.pkgutil_check_signature" if state["platform"] == "macos" else "distribution.signed_metadata"
                required = {"schema_version": "patchcairn.publisher.signature.v3", "mode": state["mode"], "platform": state["platform"],
                            "artifact_sha256": expected["content_sha256"], "publisher": expected["publisher"], "status": "verified",
                            "source_id": expected["source_id"], "method": method, "observed_utc": signature_row["observed_utc"]}
                if signature != required:
                    raise ServiceRefusal("Actual selected publisher/signature observation does not match this reviewed artifact and source")
                metadata_row = self.engine._evidence(state, [observed["metadata_evidence_id"]], kinds={"research", "precondition"}, after=state["plan"]["registered_utc"], seconds=900)[0]
                metadata = _decode(_read(self.engine.work / state["session_id"] / metadata_row["path"]))
                required_metadata = {"schema_version": "patchcairn.installer.metadata.v3", "mode": state["mode"], "platform": state["platform"],
                                     "artifact_sha256": expected["content_sha256"], "target_id": target, "version": expected["version"],
                                     **{key: expected[key] for key in ("channel", "architecture", "installation_scope", "publisher", "source_id")},
                                     "observed_utc": metadata_row["observed_utc"]}
                if metadata != required_metadata:
                    raise ServiceRefusal("Actual selected package metadata does not match the exact reviewed version/variant/publisher")
            admitted = True
        if not admitted:
            raise ServiceRefusal("Actual selected artifact and publisher/signature preexecution proof is required before a handoff")

    def record_external_preflight(self, session_id, *, action_id, plan_sha256, artifact_paths,
                                  signature_evidence_ids, metadata_evidence_ids, coordinator_verified=False):
        """Record actual selected downloaded bytes and coordinator-verified signature evidence.

        This method verifies hashes; signature trust is attributed to the
        coordinator's actual supported official-tool observation, never inferred
        from a downloaded page or imported approved/signature boolean.
        """
        with self._lock():
            if coordinator_verified is not True:
                raise ServiceRefusal("Current trusted-coordinator payload/signature verification is required")
            state = self._state(session_id, collecting=True)
            action, payload = self._binding(state, action_id, plan_sha256)
            if action["adapter_id"] != "system.reviewed_external.v3":
                raise ServiceRefusal("External preflight belongs only to an exact reviewed official-tool handoff")
            plan = payload["external_plan"]
            if not isinstance(artifact_paths, dict) or not isinstance(signature_evidence_ids, dict) or not isinstance(metadata_evidence_ids, dict) or set(artifact_paths) != set(plan["targets"]) or set(signature_evidence_ids) != set(plan["targets"]) or set(metadata_evidence_ids) != set(plan["targets"]):
                raise ServiceRefusal("Every exact selected update target needs actual payload and publisher evidence")
            value = {"schema_version": "patchcairn.external.preflight.v3", "action_id": action_id, "plan_sha256": plan_sha256,
                     "external_plan_sha256": digest(plan), "mode": state["mode"], "platform": state["platform"],
                     "observed_utc": utc_now(), "targets": {}}
            for target in plan["targets"]:
                if artifact_paths[target] != plan["argv"][1]:
                    raise ServiceRefusal("Local artifact path must be the exact reviewed fixed argv path")
                artifact_record = self._artifact(state, plan, artifact_paths[target], plan["target_identities"][target]["content_sha256"])
                value["targets"][target] = {**plan["target_identities"][target], "version": plan["target_versions"][target],
                                            "artifact_path": artifact_paths[target], "artifact_record": artifact_record,
                                            "signature_evidence_id": signature_evidence_ids[target], "metadata_evidence_id": metadata_evidence_ids[target]}
            facts = {"action_id": action_id, "plan_sha256": plan_sha256, "identity_matches": True, "scope_matches": True,
                     "content_matches": True, "compatibility_checked": True, "provenance_checked": True}
            facts.update({key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")})
            row = self._register(state, kind="precondition", value=value, facts=facts, observed_utc=value["observed_utc"])
            self._external_preflight(self.engine.read_session(session_id), action, payload, [row["evidence_id"]])
            return row

    def _operation_dir(self, session_id, operation_id, *, create=False):
        _id(session_id); _id(operation_id)
        path = _no_links(self.work / "operations" / session_id / operation_id)
        if create:
            ensure_private_directory(self.work)
            ensure_private_directory(self.work / "operations", create=True, exist_ok=True)
            ensure_private_directory(self.work / "operations" / session_id, create=True, exist_ok=True)
            ensure_private_directory(path, create=True)
        elif not path.is_dir():
            raise ServiceRefusal("Missing service operation intent; no recreation or retry")
        else:
            ensure_private_directory(self.work)
            ensure_private_directory(self.work / "operations")
            ensure_private_directory(self.work / "operations" / session_id)
            ensure_private_directory(path)
        return path

    def _intent(self, state, operation, action, payload):
        path = self._operation_dir(state["session_id"], operation["operation_id"], create=True)
        mapping = []
        if payload["operation"] == "storage.cleanup_quarantine.v3":
            mapping = self._quarantine_mapping(payload["storage_plan"])
        value = {"schema_version": SCHEMA, "kind": "operation_intent", "session_id": state["session_id"],
                 "engine_id": state["engine_id"], "mode": state["mode"], "platform": state["platform"],
                 "settings_revision": state["settings_revision"], "scope": state["settings"]["scope"],
                 "operation": operation, "action": action, "payload": payload, "quarantine_mapping": mapping,
                 "observed_utc": utc_now()}
        self._immutable(path / "intent.json", value)
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        facts["outcome"] = "unknown"
        row = self._register(state, kind="outcome", value=value, facts=facts)
        self._immutable(path / "intent-evidence.json", {"evidence_id": row["evidence_id"], "sha256": row["sha256"]})
        return path, value

    def _native_origin(self, state, operation, plan, *, substep=False):
        value = {"schema_version": SCHEMA, "engine_id": state["engine_id"], "mode": state["mode"],
                 "platform": state["platform"], "session_id": state["session_id"],
                 "operation_id": operation["operation_id"], "workflow_plan_sha256": operation["plan_sha256"],
                 "native_plan_sha256": digest(plan), "verification_substep": substep}
        self._immutable(self.work / ("origin-" + digest(plan) + ".json"), value)

    def _finish(self, state, operation, *, outcome, receipt, kind="outcome"):
        state = self.engine.read_session(state["session_id"])
        path = self._operation_dir(state["session_id"], operation["operation_id"])
        self._original_authority(state, operation, _decode(_private_read(path / "intent.json")))
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        facts["outcome"] = outcome
        value = {"schema_version": SCHEMA, "kind": "service_outcome", "mode": state["mode"],
                 "observed_utc": utc_now(), "binding": facts, "receipt": receipt}
        self._immutable(path / ("result-" + uuid.uuid4().hex + ".json"), value)
        evidence = self._register(state, kind=kind, value=value, facts=facts, observed_utc=value["observed_utc"])
        if kind == "reconciliation":
            response = self.engine.resolve(state["session_id"], pending_id="reconcile-" + operation["operation_id"], evidence_ids=[evidence["evidence_id"]])
        else:
            response = self.engine.finish_operation(state["session_id"], operation_id=operation["operation_id"], outcome=outcome,
                        evidence_ids=[evidence["evidence_id"]], summary="Selected fixed adapter outcome: " + outcome + ". Original behavior/security verification remains separate.")
        return {"operation_id": operation["operation_id"], "outcome": outcome, "receipt": receipt,
                "evidence_id": evidence["evidence_id"], "workflow": response}

    def execute_action(self, session_id, *, action_id, plan_sha256, precondition_evidence_ids,
            owner_consent_evidence_id=None, diagnostic_fixture_runner=None, diagnostic_fixture_result=None):
        with self._lock():
            state = self._state(session_id)
            if state["status"] != "active" or state["stage"] != "apply" or self.engine._pending(state):
                raise ServiceRefusal("New adapter work waits for the active apply stage and every selected checkpoint")
            action, payload = self._binding(state, action_id, plan_sha256)
            storage = None
            if action["adapter_id"] in STORAGE:
                if diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None:
                    raise ServiceRefusal("Diagnostic injection is not a storage adapter input")
                storage = self._storage(state, payload)
                storage.check_preconditions(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"])
                if action["adapter_id"] == "storage.permanent_purge.v3":
                    self.engine._recovery(state, action["recovery_evidence_ids"], action=action)
            elif action["adapter_id"] == "system.reviewed_external.v3":
                if action["requires_os_consent"] is not True:
                    raise ServiceRefusal("Fixed local installer dispatch requires actual protected OS consent for this exact action")
                self._external_sources(payload["external_plan"])
                self._external_preflight(state, action, payload, precondition_evidence_ids)
                if diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None:
                    raise ServiceRefusal("External handoff cannot accept injected adapter output")
            elif state["mode"] != "fixture" and (diagnostic_fixture_runner is not None or diagnostic_fixture_result is not None):
                raise ServiceRefusal("Fictional diagnostic output cannot enter a real operation")
            operation = self.engine.begin_operation(session_id, action_id=action_id, plan_sha256=plan_sha256,
                        precondition_evidence_ids=precondition_evidence_ids, owner_consent_evidence_id=owner_consent_evidence_id)["data"]
            path, intent = self._intent(state, operation, action, payload)
            current = self.engine.read_session(session_id)
            if current["status"] != "active":
                return self._finish(current, operation, outcome="failed", receipt={"adapter_invoked": False, "reason": "Owner pause/stop reached before the first adapter effect"})
            if action["adapter_id"] == "system.reviewed_external.v3":
                if native_platform() == "windows":
                    # Both service and engine preflight can warm this process's
                    # owned helper. Retire it only after the consumed intent.
                    try:
                        from windows_scoped import shutdown_worker
                        drained = shutdown_worker()
                    except Exception:
                        drained = False
                    if drained is not True:
                        return self._finish(current, operation, outcome="failed", receipt={
                            "adapter_invoked": False, "external_handoff_created": False,
                            "automatic_retry": False, "reason": "owned-windows-worker-drain-failed"})
                    current = self.engine.read_session(session_id)
                    if current["status"] != "active":
                        return self._finish(current, operation, outcome="failed", receipt={
                            "adapter_invoked": False, "external_handoff_created": False,
                            "automatic_retry": False, "reason": "owner-state-changed-during-worker-drain"})
                handoff = {"schema_version": SCHEMA, "kind": "reviewed_external_handoff", "operation_id": operation["operation_id"],
                           "action_id": action_id, "plan_sha256": plan_sha256, "adapter_payload_sha256": action["adapter_payload_sha256"],
                           "mode": state["mode"], "external_plan": payload["external_plan"],
                           "instruction": "Trusted coordinator performs only this exact reviewed official-tool operation through normal host permissions; report actual evidence. This helper executes nothing."}
                self._immutable(path / "handoff.json", handoff)
                return handoff
            self._immutable(path / "entered.json", {"schema_version": SCHEMA, "observed_utc": utc_now(), "operation_id": operation["operation_id"], "adapter_id": action["adapter_id"]})
            try:
                if storage is not None:
                    plan, expected = payload["storage_plan"], payload["storage_plan_sha256"]
                    self._native_origin(state, operation, plan)
                    if payload["operation"] == "storage.backup_create.v3":
                        if plan["required_recovery"]:
                            self._retain(session_id, {plan["destination"]: None, plan["destination"] + ".manifest.json": None}, reason="Required backup reserved before effect; incomplete/unknown artifacts remain protected")
                        receipt = storage.create_backup(plan=plan, expected_plan_sha256=expected)
                    elif payload["operation"] == "storage.backup_restore.v3":
                        receipt = storage.restore_backup(plan=plan, expected_plan_sha256=expected)
                    elif payload["operation"] == "storage.cleanup_quarantine.v3":
                        self._reserve_quarantine(state, operation, action, payload, intent)
                        receipt = storage.quarantine(plan=plan, expected_plan_sha256=expected)
                    elif payload["operation"] == "storage.quarantine_restore.v3":
                        receipt = storage.restore_quarantine(plan=plan, expected_plan_sha256=expected)
                    else:
                        receipt = storage.purge_quarantine(plan=plan, expected_plan_sha256=expected)
                    verified = storage.verify_outcome(plan=plan, expected_plan_sha256=expected, receipt=receipt)
                    result = {"native_receipt": receipt, "verification": verified}
                    if "restore_probe_destination" in payload:
                        probe = storage.plan_restore(receipt=receipt, destination=payload["restore_probe_destination"])
                        self._immutable(path / "restore-probe-plan.json", probe)
                        self._native_origin(state, operation, probe, substep=True)
                        self._retain(session_id, {str(Path(probe["destination"]) / f["root_id"] / f["relative_path"]): f["sha256"] for f in probe["files"]},
                                     reason="Exact restoration-probe files reserved before their reviewed verification write")
                        restoration = storage.restore_backup(plan=probe, expected_plan_sha256=digest(probe))
                        result["restore_probe_receipt"] = restoration
                        result["restore_probe_verification"] = storage.verify_outcome(plan=probe, expected_plan_sha256=digest(probe), receipt=restoration)
                        result["recovery_evidence"] = self._register_recovery(session_id, payload["output_root"], receipt, restoration, completing=True)
                    return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded", receipt=result)
                request = payload["request"]
                if request["platform"] == "windows" and diagnostic_fixture_result is None:
                    handoff = {"schema_version": SCHEMA, "kind": "windows_diagnostic_handoff", "operation_id": operation["operation_id"],
                               "request": request, "helper": "diagnostic_windows.ps1:Invoke-WindowsDiagnostic",
                               "instruction": "Use this fixed native helper in the matching host; return its selected actual adapter result. No generic command is accepted."}
                    self._immutable(path / "handoff.json", handoff)
                    return handoff
                observed = validate_adapter_result(request, diagnostic_fixture_result) if diagnostic_fixture_result is not None else collect_recipe(request, runner=diagnostic_fixture_runner, coordinator_authorized=state["mode"] == "real")
                record = self.diagnostics.record_result(request["request_id"], adapter_result=observed)
                return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded" if observed["status"] == "observed" else "failed", receipt=record)
            except (StorageRefusal, ScopedFSError, DiagnosticRefusal, OSError, ValueError) as exc:
                # A move/write can finish before its receipt. Error text may
                # contain private paths. Preserve only a categorical failure.
                return self._finish(self.engine.read_session(session_id), operation, outcome="unknown",
                        receipt={"adapter_invoked": True, "failure_class": type(exc).__name__, "possible_partial_effects": True,
                                 "failure_code": getattr(exc, "code", None),
                                 "instruction": "Preserve exact intent, native attempt/mapping and outputs; inspect actual state before any new plan."})

    @staticmethod
    def _original_authority(state, operation, intent):
        original = intent.get("operation")
        current = state.get("operations", {}).get(operation.get("operation_id"))
        fields = {"operation_id", "action_id", "plan_sha256", "settings_revision", "started_utc", "adapter_id", "mutating"}
        if (not isinstance(original, dict) or not isinstance(current, dict)
                or any(key not in original or key not in current or key not in operation
                       or original[key] != current[key] or operation[key] != current[key] for key in fields)
                or intent.get("settings_revision") != state.get("settings_revision")
                or original["settings_revision"] != state.get("settings_revision")
                or not isinstance(intent.get("scope"), dict) or intent["scope"] != state.get("settings", {}).get("scope")
                or any(intent.get(key) != state.get(key) for key in ("engine_id", "mode", "platform", "session_id"))):
            raise ServiceRefusal("Original operation scope/settings authority changed; preserve the consumed outcome without relabeling, migration or retry")

    def inspect_operation(self, session_id, *, operation_id):
        state = self._state(session_id)
        if operation_id not in state["operations"]:
            raise ServiceRefusal("Operation belongs to another session")
        path = self._operation_dir(session_id, operation_id)
        intent = _decode(_private_read(path / "intent.json"))
        operation = state["operations"][operation_id]
        ref = _decode(_private_read(path / "intent-evidence.json"))
        row = state["evidence"].get(ref.get("evidence_id"))
        if not row or row["sha256"] != ref.get("sha256") or digest(intent) != row["sha256"]:
            raise ServiceRefusal("Original full service intent does not match its engine-owned evidence")
        data = _read(self.engine.work / session_id / row["path"])
        if data != encoded(intent):
            raise ServiceRefusal("Original service intent bytes changed")
        if intent.get("schema_version") != SCHEMA or intent.get("engine_id") != state["engine_id"] or intent.get("mode") != state["mode"] or intent.get("session_id") != session_id or intent["operation"]["operation_id"] != operation_id or intent["operation"]["plan_sha256"] != operation["plan_sha256"] or digest(intent["payload"]) != intent["action"]["adapter_payload_sha256"]:
            raise ServiceRefusal("Service intent does not match the immutable engine operation")
        return {"operation": operation, "intent": intent, "effect_boundary_entered": (path / "entered.json").exists(),
                "handoff": _decode(_private_read(path / "handoff.json")) if (path / "handoff.json").exists() else None}

    def complete_diagnostic(self, session_id, *, operation_id, adapter_result, coordinator_observed=False):
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            self._original_authority(self.engine.read_session(session_id), operation, intent)
            if coordinator_observed is not True or operation["outcome"] is not None or intent["action"]["adapter_id"] != "diagnostic.read_recipe.v3":
                raise ServiceRefusal("Only an active exact diagnostic handoff accepts this result")
            request = intent["payload"]["request"]
            observed = validate_adapter_result(request, adapter_result)
            record = self.diagnostics.record_result(request["request_id"], adapter_result=observed)
            return self._finish(self.engine.read_session(session_id), operation, outcome="succeeded" if observed["status"] == "observed" else "failed", receipt=record)

    def _external_receipt(self, state, operation, intent, actual_receipt, *, after_restart=False):
        fields = {"schema_version", "operation_id", "action_id", "plan_sha256", "adapter_payload_sha256", "mode", "platform", "catalog_id", "observed_utc", "outcome", "tool_exit_code", "postcondition_state", "evidence_ids", "observed_effects", "limitations"}
        _fields(actual_receipt, fields, fields)
        plan = intent["payload"]["external_plan"]
        expected = {"schema_version": "patchcairn.external.receipt.v3", "operation_id": operation["operation_id"],
                    "action_id": operation["action_id"], "plan_sha256": operation["plan_sha256"],
                    "adapter_payload_sha256": intent["action"]["adapter_payload_sha256"], "mode": intent["mode"],
                    "platform": intent["platform"], "catalog_id": plan["catalog_id"]}
        if any(actual_receipt[key] != value for key, value in expected.items()) or not isinstance(actual_receipt["outcome"], str) or actual_receipt["outcome"] not in {"succeeded", "failed", "partial", "unknown", "installed_restart_pending"}:
            raise ServiceRefusal("External result differs from the consumed exact handoff")
        if not _time(operation["started_utc"]) <= _time(actual_receipt["observed_utc"]) <= _time(utc_now()):
            raise ServiceRefusal("External result requires fresh post-start observation")
        code = actual_receipt["tool_exit_code"]
        if code is not None and (type(code) is not int or not -(1 << 31) <= code < (1 << 31)):
            raise ServiceRefusal("Typed actual tool status required")
        if actual_receipt["postcondition_state"] not in {"verified", "not_verified", "unknown"}:
            raise ServiceRefusal("Explicit observed target postcondition state required")
        msi = plan["catalog_id"] == "windows.msiexec.install" and intent["platform"] == "windows"
        if actual_receipt["outcome"] == "installed_restart_pending" and (not msi or code != 3010 or actual_receipt["postcondition_state"] == "verified" or after_restart):
            raise ServiceRefusal("Only actual MSI3010 may record installed with restart and behavior verification still pending")
        if msi and code == 3010 and actual_receipt["outcome"] not in ({"succeeded", "failed", "partial"} if after_restart else {"installed_restart_pending"}):
            raise ServiceRefusal("Preserve MSI3010 as restart-pending until its exact later boot and behavior verification")
        if msi and code == 1641 and actual_receipt["outcome"] != "unknown":
            raise ServiceRefusal("Unexpected MSI restart initiation under no-restart arguments requires unknown reconciliation")
        self.engine._evidence(state, actual_receipt["evidence_ids"], after=operation["started_utc"], seconds=900,
                              allow_empty=actual_receipt["outcome"] == "unknown")
        successful_code = code == 0 or after_restart and msi and code == 3010
        if actual_receipt["outcome"] == "succeeded" and (not successful_code or actual_receipt["postcondition_state"] != "verified"):
            raise ServiceRefusal("Success requires actual successful tool status and observed exact target state")
        if after_restart and (not msi or code != 3010 or actual_receipt["outcome"] not in {"succeeded", "failed", "partial"}):
            raise ServiceRefusal("Post-restart completion preserves the original exact MSI3010 status")
        clean = copy.deepcopy(actual_receipt)
        for key in ("observed_effects", "limitations"):
            if not isinstance(clean[key], list) or not 1 <= len(clean[key]) <= 20:
                raise ServiceRefusal("Selected bounded effect and limitation explanations required")
            clean[key] = [sanitize_text(text, limit=2000) for text in clean[key]]
        return clean

    def _restart_boot(self, state, operation, evidence_id):
        row = self.engine._evidence(state, [evidence_id], kinds={"precondition", "outcome"}, after=operation["started_utc"], seconds=900)[0]
        value = _decode(_private_read(self.engine.work / state["session_id"] / row["path"]))
        fields = {"schema_version", "mode", "platform", "observed_utc", "last_boot_utc", "source"}
        _fields(value, fields, fields)
        if (value["schema_version"] != "patchcairn.windows.boot.observation.v3" or value["mode"] != state["mode"]
                or value["platform"] != "windows" or value["source"] != "windows.cim_last_boot_up_time"
                or value["observed_utc"] != row["observed_utc"] or _time(value["last_boot_utc"]) > _time(value["observed_utc"])):
            raise ServiceRefusal("Restart accounting needs an actual selected typed Windows boot observation")
        return value

    def _record_restart_pending(self, state, operation, intent, receipt, boot_evidence_id):
        boot = self._restart_boot(state, operation, boot_evidence_id)
        if not _time(boot["last_boot_utc"]) <= _time(receipt["observed_utc"]) <= _time(boot["observed_utc"]):
            raise ServiceRefusal("Intervening or unaccounted restart cannot become a new assumed restart baseline")
        path = self._operation_dir(state["session_id"], operation["operation_id"]) / "external-restart-pending.json"
        if path.exists():
            if _private_read(path) != encoded(receipt):
                raise ServiceRefusal("Original MSI3010 receipt is immutable; no replacement or installer retry")
        else:
            self._immutable(path, receipt)
        pending = {"schema_version": "patchcairn.restart.pending.v3", "session_id": state["session_id"],
                   **{key: operation[key] for key in ("operation_id", "action_id", "plan_sha256", "settings_revision")},
                   "scope_sha256": digest(intent["scope"]), "adapter_payload_sha256": intent["action"]["adapter_payload_sha256"],
                   "external_plan_sha256": digest(intent["payload"]["external_plan"]), "mode": state["mode"], "platform": "windows",
                   "catalog_id": "windows.msiexec.install", "original_exit_code": 3010, "observed_utc": utc_now(),
                   "native_receipt_relative_path": path.relative_to(self.root).as_posix(), "native_receipt_sha256": digest(receipt),
                   "before_boot_evidence_id": boot_evidence_id}
        facts = {key: operation[key] for key in ("operation_id", "action_id", "plan_sha256")}
        facts["outcome"] = "unknown"
        row = self._register(state, kind="outcome", value=pending, facts=facts, observed_utc=pending["observed_utc"])
        response = self.engine.record_restart_pending(state["session_id"], operation_id=operation["operation_id"], evidence_id=row["evidence_id"])
        return {"operation_id": operation["operation_id"], "outcome": "installed_restart_pending", "operation_active": True,
                "automatic_retry": False, "restart_executor": False, "receipt": receipt, "evidence_id": row["evidence_id"],
                "instruction": "Installation reported MSI3010. Keep this consumed operation, obtain its separate owner restart decision, then verify the actual boot transition and original behavior. Do not rerun the installer.",
                "workflow": response}

    def complete_external(self, session_id, *, operation_id, actual_receipt, coordinator_observed=False, restart_boot_evidence_id=None):
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            state = self.engine.read_session(session_id)
            self._original_authority(state, operation, intent)
            if coordinator_observed is not True or operation["outcome"] not in {None, "unknown"} or intent["action"]["adapter_id"] != "system.reviewed_external.v3":
                raise ServiceRefusal("Actual trusted-coordinator observation for an active exact external operation is required")
            clean = self._external_receipt(state, operation, intent, actual_receipt)
            if clean["outcome"] == "installed_restart_pending":
                if not isinstance(restart_boot_evidence_id, str):
                    raise ServiceRefusal("MSI3010 requires its fresh owned pre-restart boot observation")
                return self._record_restart_pending(state, operation, intent, clean, restart_boot_evidence_id)
            if operation["outcome"] == "unknown":
                raise ServiceRefusal("Only the exact late MSI3010 receipt can enter restart accounting for this unknown consumed operation")
            if restart_boot_evidence_id is not None or (self._operation_dir(session_id, operation_id) / "external-restart-pending.json").exists():
                raise ServiceRefusal("Use the exact original restart-pending verification path; never translate its exit status to zero")
            return self._finish(state, operation, outcome=clean["outcome"], receipt=clean)

    def complete_external_after_restart(self, session_id, *, operation_id, actual_receipt, verification_evidence_id, coordinator_observed=False):
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            state = self.engine.read_session(session_id)
            self._original_authority(state, operation, intent)
            if coordinator_observed is not True or operation["outcome"] not in {None, "unknown"} or intent["action"]["adapter_id"] != "system.reviewed_external.v3":
                raise ServiceRefusal("Only the active consumed external operation accepts actual post-restart evidence")
            clean = self._external_receipt(state, operation, intent, actual_receipt, after_restart=True)
            row = self.engine._evidence(state, [verification_evidence_id], kinds={"outcome"}, after=operation["started_utc"], seconds=900)[0]
            proof = _decode(_private_read(self.engine.work / session_id / row["path"]))
            if not isinstance(proof, dict) or proof.get("schema_version") != "patchcairn.restart.verification.v3":
                raise ServiceRefusal("Exact typed post-restart verification is required")
            pending_row = self.engine._evidence(state, [proof.get("pending_evidence_id")], kinds={"outcome"}, after=operation["started_utc"])[0]
            pending = _decode(_private_read(self.engine.work / session_id / pending_row["path"]))
            if not isinstance(pending, dict) or pending.get("schema_version") != "patchcairn.restart.pending.v3":
                raise ServiceRefusal("The final verification must reference the exact typed restart-pending record")
            original_path = self._operation_dir(session_id, operation_id) / "external-restart-pending.json"
            original_data = _private_read(original_path)
            original = _decode(original_data)
            if (pending.get("native_receipt_relative_path") != original_path.relative_to(self.root).as_posix()
                    or pending.get("native_receipt_sha256") != digest(original_data)
                    or original.get("tool_exit_code") != 3010 or original.get("outcome") != "installed_restart_pending"
                    or _time(clean["observed_utc"]) < _time(proof.get("observed_utc"))):
                raise ServiceRefusal("Post-restart outcome must preserve the exact original MSI3010 receipt and later verification")
            verification = self.engine.record_restart_verification(session_id, operation_id=operation_id, evidence_id=verification_evidence_id)
            if clean["outcome"] == "succeeded" and verification["data"].get("behavior_passed") is not True:
                raise ServiceRefusal("Actual post-restart target or original behavior did not pass; preserve failed or partial effects without claiming success")
            return self._finish(self.engine.read_session(session_id), operation, outcome=clean["outcome"],
                receipt={"external_receipt": clean, "original_restart_pending_receipt": original,
                         "restart_verification_evidence_id": verification_evidence_id},
                kind="reconciliation" if operation["outcome"] == "unknown" else "outcome")

    def reconcile_operation(self, session_id, *, operation_id):
        """Inspect actual native outcome; absence remains unknown and consumed."""
        with self._lock():
            inspected = self.inspect_operation(session_id, operation_id=operation_id)
            operation, intent = inspected["operation"], inspected["intent"]
            payload = intent["payload"]
            if intent["action"]["adapter_id"] not in STORAGE:
                raise ServiceRefusal("External/diagnostic outcomes require their actual bounded callback evidence")
            if operation["outcome"] not in {None, "unknown"}:
                raise ServiceRefusal("Known operation receipt is already consumed; retain historical result")
            state = self.engine.read_session(session_id)
            self._original_authority(state, operation, intent)
            storage = StorageService(output_root=payload["output_root"], quiet_workspace=True, protected_roots=payload["protected_roots"])
            outcome_path = Path(payload["output_root"]) / ("outcome-" + STORAGE[payload["operation"]][2] + "-" + payload["storage_plan_sha256"] + ".json")
            try:
                receipt = _decode(_private_read(outcome_path))
                origin = _decode(_private_read(self.work / ("origin-" + payload["storage_plan_sha256"] + ".json")))
                if origin["operation_id"] != operation_id or origin["mode"] != state["mode"] or origin["engine_id"] != state["engine_id"]:
                    raise ServiceRefusal("Native outcome has another operation's origin")
                verification = storage.verify_outcome(plan=payload["storage_plan"], expected_plan_sha256=payload["storage_plan_sha256"], receipt=receipt)
                reconciled_receipt = {"native_receipt": receipt, "verification": verification}
                if "restore_probe_destination" in payload:
                    probe = _decode(_private_read(self._operation_dir(session_id, operation_id) / "restore-probe-plan.json"))
                    if probe["destination"] != payload["restore_probe_destination"] or probe["receipt"] != receipt:
                        raise ServiceRefusal("Probe plan differs from original exact reviewed verification scope")
                    probe_path = Path(payload["output_root"]) / ("outcome-restore-" + digest(probe) + ".json")
                    restoration = _decode(_private_read(probe_path))
                    storage.verify_outcome(plan=probe, expected_plan_sha256=digest(probe), receipt=restoration)
                    reconciled_receipt["restore_probe_receipt"] = restoration
                    reconciled_receipt["recovery_evidence"] = self._register_recovery(session_id, payload["output_root"], receipt, restoration, completing=True)
            except (OSError, StorageRefusal, ScopedFSError, WorkflowRefusal, ServiceRefusal, ValueError):
                if operation["outcome"] is None:
                    return self._finish(state, operation, outcome="unknown", receipt={"possible_partial_effects": True, "native_outcome_verified": False,
                            "instruction": "Missing or inconsistent actual native outcome; no retry or success is permitted."})
                return {"operation_id": operation_id, "outcome": "unknown", "held": True, "automatic_retry": False}
            return self._finish(state, operation, outcome="succeeded", receipt=reconciled_receipt,
                                kind="reconciliation" if operation["outcome"] == "unknown" else "outcome")
