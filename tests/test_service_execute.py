"""Selected synthetic work copies only. No host inventory, update or repair.

Service execution (scripts/service_execute.py): construction, the storage action, the approved binding,
execute_action, the dispatch tables over every adapter id and the composition of WorkflowService.
"""
from __future__ import annotations
import ast
import copy
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import inspect
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_core import WorkflowEngine, WorkflowRefusal
import pc_records
from workflow_service import WorkflowService, ServiceRefusal, verify_storage_artifact
from storage_ops import StorageRefusal
from scoped_fs import ScopedFSError
from private_workspace import PrivateWorkspaceError, ensure_private_directory, write_private_new
from service_execute import EXECUTE
from service_reconcile import RECONCILE
from test_service_state import ServiceFixtures, SessionFixtures, PROSE, PRIVATE_CAPABILITY_HOLDS, broad_namespace_fixture


class ExternalHandoffOrderTests(ServiceFixtures):
    """Fictional service ordering only; no files, child process or installer."""
    def test_owner_pause_after_intent_records_consumed_failure_without_handoff(self):
        service, state, operation, events, written, arguments = self.prepared()
        def paused(*args):
            events.append("status-" + str(service.engine.read_session.call_count))
            state["status"] = "paused"
            return state
        service.engine.read_session.side_effect = paused
        result = service.execute_action(state["session_id"], **arguments)
        self.assertEqual(events, ["sources", "service-preflight", "begin-operation", "engine-preflight", "intent", "status-1", "finish"])
        self.assertEqual(result["outcome"], "failed")
        self.assertFalse(result["receipt"]["adapter_invoked"])
        self.assertEqual(set(written), {"intent.json"})

    def test_nonordinary_interruption_keeps_intent_and_creates_no_handoff(self):
        service, state, operation, events, written, arguments = self.prepared()
        service.engine.read_session.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            service.execute_action(state["session_id"], **arguments)
        self.assertEqual(set(written), {"intent.json"})
        self.assertIsNone(operation["outcome"])
        service._finish.assert_not_called()
        service.engine.begin_operation.assert_called_once()


class WorkflowServiceTests(SessionFixtures):
    def test_plan_A_cannot_execute_plan_B_wrong_roots_output_type_or_hash(self):
        action, native = self.backup_action()
        sha = self.approve(action)
        with self.assertRaises(WorkflowRefusal):
            self.service.execute_action(self.sid, action_id=action["action_id"], plan_sha256="f" * 64, precondition_evidence_ids=[])
        other = self.root / "work" / "other-output"
        other.mkdir()
        for adapter, plan, output in (("storage.purge", native, self.output),
                                      ("storage.backup_create", native, other)):
            with self.assertRaises((ServiceRefusal, StorageRefusal, ScopedFSError)):
                self.service.prepare_storage_action(self.sid, action_id="wrong-target", adapter_id=adapter,
                            storage_plan=plan, output_root=str(output), **PROSE)
        altered = copy.deepcopy(native)
        altered["inventory"]["roots"][0]["path"] = str(self.root / "work" / "other-source")
        with self.assertRaises((ServiceRefusal, StorageRefusal)):
            self.service.prepare_storage_action(self.sid, action_id="wrong-root", adapter_id="storage.backup_create", storage_plan=altered, output_root=str(self.output), **PROSE)
        self.assertEqual(self.state()["operations"], {})
        self.assertFalse((self.output / "one.zip").exists())

    def test_stale_content_stale_precondition_pause_settings_and_stop_block_new_effect(self):
        action, native = self.backup_action()
        sha = self.approve(action)
        stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        eid = self.precondition(action, sha, observed_utc=stale)
        with self.assertRaises(WorkflowRefusal):
            self.service.execute_action(self.sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[eid])
        self.engine.pause(self.sid)
        with self.assertRaises(ServiceRefusal):
            self.execute(action, sha)
        self.engine.setup(self.sid, control="automatic")
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.execute(action, sha)
        self.engine.stop(self.sid)
        with self.assertRaises((ServiceRefusal, WorkflowRefusal)):
            self.service.execute_action(self.sid, action_id=action["action_id"], plan_sha256=sha, precondition_evidence_ids=[])
        self.assertEqual(self.state()["operations"], {})
        self.assertFalse((self.output / "one.zip").exists())

    def test_native_content_changes_hold_before_consuming_ticket(self):
        action, native = self.backup_action()
        sha = self.approve(action)
        (self.source / "example.txt").write_text("Changed after review", encoding="utf-8")
        with self.assertRaises((ServiceRefusal, StorageRefusal, ScopedFSError)):
            self.execute(action, sha)
        self.assertEqual(self.state()["operations"], {})

    def test_checkpoint_blocks_adapter_even_when_exact_plan_is_approved(self):
        self.engine.setup(self.sid, checkpoints=["before_action"])
        self.engine.authorize_scope(self.sid, owner_quote="Use this synthetic scope after checkpoint setting.", owner_message_id="scope-again")
        action, native = self.backup_action()
        sha = self.approve(action)
        self.assertEqual(self.state()["status"], "awaiting_user")
        with self.assertRaises(ServiceRefusal):
            self.execute(action, sha)
        self.assertFalse((self.output / "one.zip").exists())

    def test_backup_probe_whose_restore_paths_exceed_the_portable_limit_is_refused_before_the_backup(self):
        name = "n" * 96 + ".txt"
        write_private_new(self.source / name, b"Fictional long-named file.\n")
        storage = self.storage()
        plan = storage.plan_backup(inventory=storage.assess_storage(roots=[str(self.source)]), selected=["r001/" + name],
                                   destination=str(self.output / "long.zip"), content_read_authorized=True, required_recovery=True)
        with self.assertRaises(ServiceRefusal) as caught:
            self.service.prepare_storage_action(self.sid, action_id="backup-long", adapter_id="storage.backup_create", storage_plan=plan,
                                                output_root=str(self.output), restore_probe_destination=str(self.output / ("probe-" + "x" * 92)), **PROSE)
        self.assertEqual(caught.exception.code, "path-too-long")
        self.assertFalse((self.output / "long.zip").exists())
        action = self.service.prepare_storage_action(self.sid, action_id="backup-long", adapter_id="storage.backup_create", storage_plan=plan,
                                                     output_root=str(self.output), restore_probe_destination=str(self.output / "p"), **PROSE)
        self.assertEqual(action["adapter_id"], "storage.backup_create")

    def test_service_supplies_storage_verifier(self):
        with mock.patch("service_execute.WorkflowEngine") as built:
            self.assertIs(WorkflowService.default_engine(), built.return_value)
        built.assert_called_once_with(verify_artifact=verify_storage_artifact)
        # A service built without an engine uses that default.
        with mock.patch.object(WorkflowService, "default_engine", return_value=self.engine) as default:
            self.assertIs(WorkflowService().engine, self.engine)
        default.assert_called_once_with()
        # An engine built elsewhere without a verifier gets the storage verifier; any other verifier is refused.
        bare = WorkflowEngine(self.root)
        self.assertIsNone(bare.verify_artifact)
        self.assertIs(WorkflowService(bare).engine.verify_artifact, verify_storage_artifact)
        with self.assertRaises(ServiceRefusal) as caught:
            WorkflowService(WorkflowEngine(self.root, verify_artifact=lambda binding: None))
        self.assertEqual(caught.exception.code, "verifier-contract")


class ServicePrivacyTests(ServiceFixtures):
    def test_namespace_refusal_precedes_marker_or_retention_write(self):
        root = self.fixture_root()
        with mock.patch("service_execute.ensure_private_directory", side_effect=PrivateWorkspaceError("fixture-private-hold")), mock.patch("service_state.write_private_new") as writer:
            with self.assertRaises(PrivateWorkspaceError):
                WorkflowService(self.fake_engine(root))
            writer.assert_not_called()
        self.assertFalse(list(root.glob("**/*.json")))

    def test_existing_broad_service_namespace_refuses_without_acl_repair(self):
        root = self.fixture_root()
        namespace = root / "work" / "services"
        namespace.mkdir(parents=True)
        try:
            ensure_private_directory(namespace)
        except PrivateWorkspaceError as exc:
            if exc.code in PRIVATE_CAPABILITY_HOLDS - {"private-owner-or-mode-refused", "private-linux-foreign-filesystem"}:
                self.skipTest("only on posix: native private-ACL admission unavailable; refusal is covered separately")
            if exc.code not in {"private-owner-or-mode-refused", "private-dacl-unprotected", "private-dacl-broad-or-unknown", "private-linux-foreign-filesystem"}:
                raise
        else:
            broad_namespace_fixture(namespace)
        before = namespace.stat().st_mode
        with self.assertRaises(PrivateWorkspaceError):
            WorkflowService(self.fake_engine(root))
        self.assertEqual(namespace.stat().st_mode, before)
        self.assertFalse(list(root.glob("**/*.json")))

    def test_neutral_default_and_explicit_service_namespaces_do_not_adopt_old_records(self):
        root = self.fixture_root()
        try:
            old = WorkflowService(self.fake_engine(root), work_relative="work/service-previous")
        except PrivateWorkspaceError as exc:
            if os.name == "posix" and exc.code in PRIVATE_CAPABILITY_HOLDS:
                self.skipTest("only on posix: private namespace unavailable; native refusal covered separately")
            raise
        old_marker = (old.work / "service.json").read_bytes()
        current = WorkflowService(self.fake_engine(root))
        explicit = WorkflowService(self.fake_engine(root), work_relative="work/selected-service")
        self.assertEqual(current.work, root / "work/services")
        self.assertEqual(current.diagnostics.base, root / "work/services/diagnostics")
        self.assertEqual(explicit.work, root / "work/selected-service")
        self.assertEqual(WorkflowService(self.fake_engine(root), work_relative="work/service-previous").work, old.work)
        self.assertEqual((old.work / "service.json").read_bytes(), old_marker)
        self.assertNotEqual(current.work, old.work)

    def test_read_only_cli_defaults_and_explicit_paths_bind_selected_namespaces(self):
        import patchcairn_service as cli
        for options, session_work, service_work in (
            ([], "work/sessions", "work/services"),
            (["--session-work", "work/selected-sessions", "--service-work", "work/selected-services"], "work/selected-sessions", "work/selected-services"),
        ):
            engine, service = mock.Mock(), mock.Mock()
            service.inspect_operation.return_value = {"operation": {"outcome": "unknown"}}
            with mock.patch.object(cli, "WorkflowEngine", return_value=engine) as engine_type, mock.patch.object(cli, "WorkflowService", return_value=service) as service_type, mock.patch("builtins.print"):
                self.assertEqual(cli.main(options + ["inspect-operation", "session-fixture", "operation-fixture"]), 0)
            engine_type.assert_called_once_with(work_relative=session_work)
            service_type.assert_called_once_with(engine, work_relative=service_work)
            service.inspect_operation.assert_called_once_with("session-fixture", operation_id="operation-fixture")
        with mock.patch.object(cli, "WorkflowEngine") as engine_type, mock.patch.object(cli, "WorkflowService") as service_type, mock.patch("builtins.print"):
            self.assertEqual(cli.main(["catalog"]), 0)
        engine_type.assert_not_called()
        service_type.assert_not_called()


class DispatchTests(SessionFixtures):
    def test_every_adapter_has_execute_and_reconcile(self):
        # PLAN 3.3, D-071: both tables name every adapter id; each target is a private WorkflowService method defined in
        # its family's module and looked up on the object; a target whose whole body is the held refusal holds before
        # anything is written or begun. The held set is read from the code, so a family leaf that writes a body drops out.
        modules = {"backup": "service_backup", "restore": "service_restore", "cleanup": "service_cleanup", "retention": "service_retention",
                   "update": "service_updates", "repair": "service_updates", "assessment": "service_diagnostics"}
        self.assertEqual(set(EXECUTE), set(pc_records.ADAPTERS))
        self.assertEqual(set(RECONCILE), set(pc_records.ADAPTERS))
        held = {}
        for table, kind in ((EXECUTE, "execute"), (RECONCILE, "reconcile")):
            methods = {adapter_id: getattr(WorkflowService, name) for adapter_id, name in table.items()}
            self.assertEqual(len({str(inspect.signature(method)) for method in methods.values()}), 1, kind + " signatures differ")
            for adapter_id, method in methods.items():
                with self.subTest(table=kind, adapter_id=adapter_id):
                    self.assertEqual(table[adapter_id], f"_{kind}_" + adapter_id.replace(".", "_"))
                    self.assertEqual(method.__name__, table[adapter_id])
                    self.assertEqual(method.__module__, modules[pc_records.ADAPTERS[adapter_id]["family"]])
            held[kind] = sorted(adapter_id for adapter_id, method in methods.items() if method.__code__.co_names == (f"_{kind}_held",))
        refusals = {"execute": "No fixed service adapter exists for this action",
                    "reconcile": "External/diagnostic outcomes require their actual bounded callback evidence"}
        state = self.state()
        files = sorted((path, path.stat().st_size) for path in self.root.rglob("*"))
        operation = {"operation_id": "held-operation", "action_id": "held-action", "plan_sha256": "a" * 64, "outcome": None}
        with mock.patch.object(self.engine, "begin_operation") as begin:
            for kind, call in (("execute", lambda adapter_id: getattr(self.service, EXECUTE[adapter_id])(
                                    self.sid, state, {"action_id": "held-action", "adapter_id": adapter_id}, {},
                                    action_id="held-action", plan_sha256="a" * 64, precondition_evidence_ids=[],
                                    owner_consent_evidence_id=None, diagnostic_fixture_runner=None, diagnostic_fixture_result=None)),
                               ("reconcile", lambda adapter_id: getattr(self.service, RECONCILE[adapter_id])(
                                    self.sid, operation, {"action": {"adapter_id": adapter_id}, "payload": {}}, {},
                                    operation_id=operation["operation_id"]))):
                for adapter_id in held[kind]:
                    with self.subTest(held=kind, adapter_id=adapter_id):
                        with self.assertRaises(ServiceRefusal) as caught:
                            call(adapter_id)
                        self.assertEqual((caught.exception.code, str(caught.exception)), ("service-refusal", refusals[kind]))
        begin.assert_not_called()
        self.assertEqual(self.state()["revision"], state["revision"])
        self.assertEqual(sorted((path, path.stat().st_size) for path in self.root.rglob("*")), files)
        # Dispatch looks the target up on the object, so a patch on the method intercepts it with the arguments forwarded
        # unchanged; an id outside a table keeps the same refusal, and no KeyError escapes either dispatch.
        service = object.__new__(WorkflowService)
        service._lock = mock.Mock(side_effect=nullcontext)
        service._state = mock.Mock(return_value={"status": "active", "stage": "apply"})
        service.engine = types.SimpleNamespace(pending_items=mock.Mock(return_value=False), begin_operation=mock.Mock())
        arguments = dict(action_id="dispatched", plan_sha256="a" * 64, precondition_evidence_ids=["proof"], owner_consent_evidence_id=None,
                         diagnostic_fixture_runner=None, diagnostic_fixture_result=None)
        for adapter_id in (pc_records.ADAPTER_STORAGE_BACKUP_CREATE, "fixture.unlisted"):
            action, payload = {"action_id": "dispatched", "adapter_id": adapter_id}, {"fictional": True}
            intent = {"action": action, "payload": payload}
            service._binding = mock.Mock(return_value=(action, payload))
            service.inspect_operation = mock.Mock(return_value={"operation": operation, "intent": intent})
            if adapter_id in EXECUTE:
                with mock.patch.object(service, EXECUTE[adapter_id], return_value="patched-execute") as target:
                    self.assertEqual(service.execute_action("session-fixture", **arguments), "patched-execute")
                target.assert_called_once_with("session-fixture", service._state.return_value, action, payload, **arguments)
                with mock.patch.object(service, RECONCILE[adapter_id], return_value="patched-reconcile") as target:
                    self.assertEqual(service.reconcile_operation("session-fixture", operation_id="dispatched"), "patched-reconcile")
                target.assert_called_once_with("session-fixture", operation, intent, payload, operation_id="dispatched")
                continue
            for kind, call in (("execute", lambda: service.execute_action("session-fixture", **arguments)),
                               ("reconcile", lambda: service.reconcile_operation("session-fixture", operation_id="dispatched"))):
                with self.subTest(unlisted=kind):
                    with self.assertRaises(ServiceRefusal) as caught:
                        call()
                    self.assertEqual(str(caught.exception), refusals[kind])
        service.engine.begin_operation.assert_not_called()


class CompositionTests(unittest.TestCase):
    def test_mixins_define_disjoint_names_and_one_init(self):
        # D-070, D-071: WorkflowService is one class built from mixins, and a name defined twice resolves silently by
        # method order; so no two mixins share a non-dunder name, the composed class adds none of its own, and only
        # ExecuteMixin, which builds the service's state, defines __init__.
        mixins = WorkflowService.__mro__[1:-1]
        self.assertIs(WorkflowService.__mro__[-1], object)
        owners = {}
        for mixin in mixins:
            for name in vars(mixin):
                if not (name.startswith("__") and name.endswith("__")):
                    owners.setdefault(name, []).append(mixin.__name__)
        self.assertEqual({name: classes for name, classes in owners.items() if len(classes) > 1}, {})
        self.assertEqual([name for name in vars(WorkflowService) if not (name.startswith("__") and name.endswith("__"))], [])
        self.assertEqual([mixin.__name__ for mixin in mixins if "__init__" in vars(mixin)], ["ExecuteMixin"])

    def test_only_the_dispatch_reaches_the_targets(self):
        # D-071: G11 refuses service._x, not self._x inside a mixin. So no function names a target except through the tables,
        # and only a target calls the shared paths that rely on execute_action's and reconcile_operation's checks.
        targets = set(EXECUTE.values()) | set(RECONCILE.values())
        callers = {"_run_fixed_adapter": set(EXECUTE.values()), "_reconcile_storage": set(RECONCILE.values())}
        found = []
        for path in sorted((ROOT / "scripts").glob("*.py")):
            for function in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for node in ast.walk(function):
                        if isinstance(node, ast.Attribute) and (node.attr in targets or function.name not in callers.get(node.attr, {function.name})):
                            found.append((path.name, node.lineno, function.name, node.attr))
                        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in targets:
                            found.append((path.name, node.lineno, function.name, node.value))
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
