"""Tests of the pure decision rules (engine_decisions). Nothing here touches a file.

Run with supported Python: -I -S -B -m unittest discover -s tests -p test_engine_decisions.py -v
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import engine_decisions
from engine_decisions import remaining_actions, reply_matches
from engine_journal import WorkflowRefusal
import pc_records

IDS = ("a1", "a2", "a3", "a4")
SHA_A, SHA_B = "a" * 64, "b" * 64
CLOCK = "2026-10-26T00:00:00.000000Z"


def operation(action_id, kind=None):
    return {"action_id": action_id, "outcome": "failed" if kind else "succeeded",
            "resolution": {"kind": kind, "evidence_ids": ["e"], "recorded_utc": "2026-10-26T00:00:00.000000Z",
                           "owner_message_id": None} if kind else None}


class RemainingActionsTests(unittest.TestCase):
    def test_runs_in_plan_order_and_skips_consumed_actions(self):
        self.assertEqual(remaining_actions(IDS, {}, IDS, {}), IDS)
        self.assertEqual(remaining_actions(IDS, {}, IDS, {"o1": operation("a1")}), ("a2", "a3", "a4"))

    def test_missing_depends_on_means_every_earlier_action(self):
        operations = {"o1": operation("a1"), "o2": operation("a2", "verified_failure")}
        self.assertEqual(remaining_actions(IDS, {}, IDS, operations), ())
        self.assertEqual(remaining_actions(IDS, {"a3": (), "a4": None}, IDS, operations), ("a3",))

    def test_verified_failure_blocks_only_its_dependents_transitively(self):
        operations = {"o1": operation("a1", "verified_failure")}
        depends_on = {"a2": ("a1",), "a3": ("a2",), "a4": ()}
        self.assertEqual(remaining_actions(IDS, depends_on, IDS, operations), ("a4",))

    def test_an_action_not_approved_excludes_its_dependents(self):
        depends_on = {"a2": (), "a3": ("a1",), "a4": ("a3",)}
        self.assertEqual(remaining_actions(IDS, depends_on, ("a2", "a3", "a4"), {}), ("a2",))

    def test_any_unsuccessful_or_open_operation_blocks_its_dependents(self):
        depends_on = {"a2": ("a1",), "a3": (), "a4": ("a3",)}
        for operations in ({"o1": operation("a1", "replan_required")}, {"o1": dict(operation("a1"), outcome=None)},
                           {"o1": dict(operation("a1"), outcome="unknown")}):
            with self.subTest(outcome=operations["o1"]["outcome"]):
                self.assertEqual(remaining_actions(IDS, depends_on, IDS, operations), ("a3", "a4"))

    def test_needs_that_are_not_a_list_of_earlier_ids_block(self):
        # Only earlier ids of the plan can be needed: anything else blocks the action and so its dependents.
        failed = {"o1": operation("a1", "verified_failure")}
        cases = (({"a2": "a1"}, failed), ({"a2": {"a1": True}}, {}), ({"a2": 1}, {}), ({"a2": ("a3",)}, {}), ({"a2": ("zz",)}, {}),
                 ({"a2": ("a2",)}, {}), ({"a2": [["a1"]]}, {}))
        for needs, operations in cases:
            depends_on = dict(needs, a3=(), a4=("a2",))
            with self.subTest(needs=needs["a2"]):
                self.assertEqual(remaining_actions(IDS, depends_on, IDS, operations), ("a3",) if operations else ("a1", "a3"))

    def test_a_succeeded_action_left_out_of_a_later_approval_still_counts_as_met(self):
        operations = {"o1": operation("a1"), "o2": operation("a2")}
        depends_on = {"a2": ("a1",), "a3": ("a2",), "a4": ("a3",)}
        self.assertEqual(remaining_actions(IDS, depends_on, ("a3", "a4"), operations), ("a3", "a4"))

    def test_only_the_first_remaining_action_may_start(self):
        # The result is in plan order; a later id can remain while the one it needs has not run, so callers start only [0].
        depends_on = {"a2": ("a1",), "a3": ("a2",), "a4": ("a3",)}
        self.assertEqual(remaining_actions(IDS, depends_on, IDS, {})[0], "a1")
        self.assertIn("only the first of them may start", remaining_actions.__doc__)


class ReplyTests(unittest.TestCase):
    """The comparison of the owner's typed reply with its phrase (the reply's own rule; pure)."""

    def test_separators_case_and_one_final_full_stop_do_not_count(self):
        for quote in ("delete 12 files", "Delete 12 Files.", "  delete  12\tfiles ", "DELETE 12 FILES", "delete 12, files", "delete, 12 files."):
            with self.subTest(accepted=quote):
                self.assertTrue(reply_matches(quote, "delete 12 files"))
        firmware = "update firmware on device 2, I have my recovery key"
        self.assertTrue(reply_matches("Update firmware on device 2 I have my recovery key.", firmware))

    def test_look_alikes_controls_and_merged_numbers_never_match(self):
        refused = {"delete 12 files": ("delete 12 \ufb01les", "delete 12 file\u017f", "delete\x1c12\x1dfiles", "delete 1 2 files", "delete 1,2 files",
                                       "de lete 12 fi les", "delete 12 files..", "delete 12 files!", "delete 12 files\n\n.", "delete \uff11\uff12 files",
                                       "delete 12 files please", "yes", "", 12, None),
                   "update firmware on device 2, I have my recovery key": ("update \ufb01rmware on device 2, I have my recovery key",
                                                                           "update firmware on device 2, I have my recovery \u212aey")}
        for phrase, quotes in refused.items():
            for quote in quotes:
                with self.subTest(refused=quote):
                    self.assertFalse(reply_matches(quote, phrase))

    def test_a_final_line_break_from_the_host_does_not_count(self):
        # A host may end the reply with a line feed or a carriage return and line feed; one inside the reply still refuses.
        for quote in ("delete 12 files\n", "delete 12 files\r\n", "Delete 12 files.\n", "delete 12 files \r\n", "delete 12 files\r"):
            with self.subTest(accepted=repr(quote)):
                self.assertTrue(reply_matches(quote, "delete 12 files"))
        for quote in ("delete\n12 files", "delete 12\r\nfiles", "\ndelete 12 files", "delete 12 files\n\x00", "delete 12 files\n.", "delete 12 files\x0b\n"):
            with self.subTest(refused=repr(quote)):
                self.assertFalse(reply_matches(quote, "delete 12 files"))


def action(action_id, adapter_id=pc_records.ADAPTER_STORAGE_BACKUP_CREATE, **extra):
    """A plan action as the rules read it: its id, adapter, payload hash and kind."""
    return {"action_id": action_id, "adapter_id": adapter_id, "adapter_payload_sha256": SHA_A,
            "kind": pc_records.ADAPTERS[adapter_id]["kinds"][0], **extra}


def refused(test, code, call):
    with test.assertRaises(WorkflowRefusal) as caught:
        call()
    test.assertEqual(caught.exception.code, code)


class DecisionRuleTests(unittest.TestCase):
    """The plan rules as pure functions: composition, subset closure, the dependency check and the conditional-decision match."""

    def recovery_rule(self, adapter_id, requires_recovery):
        """validate_plan_document on one action of ``adapter_id``, with ``requires_recovery`` and no evidence."""
        facts = pc_records.ADAPTERS[adapter_id]
        action = {"action_id": "a1", "kind": facts["kinds"][0], "target": "Fictional", "benefit": "Fictional", "risk": "Fictional", "reversibility": "Fictional",
                  "verification": "Fictional", "mutating": True, "requires_os_consent": facts["os_consent"] == "always", "requires_recovery": requires_recovery,
                  "recovery_evidence_ids": [], "adapter_id": adapter_id, "adapter_payload_evidence_id": "p1", "adapter_payload_sha256": SHA_A,
                  "adapter_plan_sha256": SHA_B, "target_inventory_evidence_id": "i1", "target_inventory_sha256": SHA_A}
        document = {"plan_id": "fictional-plan", "summary": "Fictional", "evidence_ids": ["e1"], "actions": [action]}
        engine_decisions.validate_plan_document({"mode": "fixture"}, document)

    def test_only_a_restore_or_a_purge_always_binds_recovery(self):
        for adapter_id in (pc_records.ADAPTER_PACKAGE_REINSTALL, pc_records.ADAPTER_SYSTEM_REPAIR):
            with self.subTest(adapter_id=adapter_id):
                self.recovery_rule(adapter_id, False)
        for adapter_id in (pc_records.ADAPTER_STORAGE_RESTORE, pc_records.ADAPTER_STORAGE_QUARANTINE_RESTORE, pc_records.ADAPTER_STORAGE_PURGE):
            with self.subTest(adapter_id=adapter_id), self.assertRaises(WorkflowRefusal):
                self.recovery_rule(adapter_id, False)

    def test_typed_reply_actions_share_a_plan_only_with_their_own_adapter_and_firmware_stands_alone(self):
        purge, selected = pc_records.ADAPTER_STORAGE_PURGE, pc_records.ADAPTER_STORAGE_DELETE_SELECTED
        firmware, repair = pc_records.ADAPTER_SYSTEM_FIRMWARE_UPDATE, pc_records.ADAPTER_SYSTEM_REPAIR
        for actions in ([action("a1", purge), action("a2", purge)], [action("a1"), action("a2", pc_records.ADAPTER_STORAGE_QUARANTINE)],
                        [action("a1", firmware)], [action("a1", repair), action("a2")], [action("a1", selected), action("a2", selected)]):
            with self.subTest(accepted=[a["adapter_id"] for a in actions]):
                engine_decisions.check_composition(actions)
        for actions in ([action("a1", purge), action("a2")], [action("a1"), action("a2", purge)], [action("a1", purge), action("a2", selected)],
                        [action("a1", firmware), action("a2", firmware)], [action("a1", firmware), action("a2")],
                        [action("a1", pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS), action("a2", pc_records.ADAPTER_STORAGE_RESTORE)]):
            with self.subTest(refused=[a["adapter_id"] for a in actions]):
                refused(self, "plan-composition", lambda: engine_decisions.check_composition(actions))

    def test_an_approved_action_comes_with_every_action_it_depends_on(self):
        check, depends_on = engine_decisions.check_approval, {"a2": ["a1"], "a3": [], "a4": ["a3"]}
        for approved in (IDS, ("a1", "a2"), ("a3", "a4"), ("a1",), ("a3",), ("a1", "a3")):
            with self.subTest(accepted=approved):
                check(IDS, depends_on, approved, False, {})
        for approved in (("a2",), ("a4",), ("a2", "a3", "a4"), ("a1", "a4")):
            with self.subTest(refused=approved):
                refused(self, "approval-dependencies", lambda: check(IDS, depends_on, approved, False, {}))
        # A missing depends_on means every earlier action; an action that already succeeded counts as met; a failed one does not.
        refused(self, "approval-dependencies", lambda: check(IDS, {}, ("a2",), False, {}))
        check(IDS, {}, ("a2",), False, {"o1": operation("a1")})
        refused(self, "approval-dependencies", lambda: check(IDS, {}, ("a2",), False, {"o1": operation("a1", "verified_failure")}))
        # A plan that needs the typed reply is approved whole.
        refused(self, "approval-whole", lambda: check(IDS, {"a2": [], "a3": [], "a4": []}, ("a1", "a2"), True, {}))
        check(IDS, {}, IDS, True, {})

    def test_depends_on_names_only_distinct_earlier_ids_of_the_plan(self):
        check = engine_decisions.check_depends_on
        for depends_on in ({}, {"a2": None}, {"a2": ["a1"], "a3": [], "a4": ["a1", "a3"]}, {"a4": ["a3", "a2", "a1"]}):
            with self.subTest(accepted=depends_on):
                check(list(IDS), depends_on)
        for depends_on in ({"a2": ["a3"]}, {"a2": ["a2"]}, {"a2": ["zz"]}, {"a3": ["a1", "a1"]}, {"a2": "a1"}, {"a2": ("a1",)}, {"a2": [1]},
                           {"a1": ["a1"]}, {"a3": [["a1"]]}, {"a1": ["a2"], "a2": ["a1"]}):
            with self.subTest(refused=depends_on):
                refused(self, "plan-depends-on", lambda: check(list(IDS), depends_on))

    def test_conditional_decision_matches_action_payload_decision_names_and_timing(self):
        upgrade = action("a1", pc_records.ADAPTER_PACKAGE_UPGRADE)
        payload = {"flags": ["install_scripts", "runtime_line_change"],
                   "conditional": {"run_install_scripts": ["@scope/helper@2.0.0", "example-helper@1.0.0"], "runtime_line_change": []}}
        rows = [{"action_id": "a1", "payload_sha256": SHA_A, "decision": "run_install_scripts", "names": ["@scope/helper@2.0.0", "example-helper@1.0.0"],
                 "message_id": "m1", "recorded_utc": CLOCK},
                {"action_id": "a1", "payload_sha256": SHA_A, "decision": "runtime_line_change", "names": [], "message_id": "m2", "recorded_utc": CLOCK}]

        def state(decisions, timing="now"):
            return {"conditional_decisions": decisions, "settings": {"timing": timing}}
        engine_decisions.require_conditional(state(rows), upgrade, payload)
        engine_decisions.require_conditional(state([]), upgrade, {"flags": ["high_risk"]})  # nothing to decide
        engine_decisions.require_conditional(state([]), action("a1"), None)  # an adapter without conditional decisions
        cases = {"no record": (state(rows[:1]), upgrade, payload), "a None payload": (state(rows), upgrade, None),
                 "another payload hash": (state(rows), dict(upgrade, adapter_payload_sha256=SHA_B), payload),
                 "another action": (state(rows), dict(upgrade, action_id="a2"), payload),
                 "other names": (state(rows), upgrade, dict(payload, conditional=dict(payload["conditional"], run_install_scripts=["other@1.0.0"]))),
                 "a scheduled session": (state(rows, "scheduled"), upgrade, payload),
                 "a flag without its decision": (state(rows), upgrade, {"flags": ["install_scripts"]}),
                 "a decision without its flag": (state(rows), upgrade, {"flags": [], "conditional": {"runtime_line_change": []}}),
                 "an adapter without the decision": (state(rows), action("a1", pc_records.ADAPTER_PACKAGE_REINSTALL), payload)}
        for name, (current, target, bound) in cases.items():
            with self.subTest(refused=name):
                refused(self, "conditional-decision-required", lambda: engine_decisions.require_conditional(current, target, bound))
        self.assertEqual(engine_decisions.needed_decisions(payload), payload["conditional"])
        for names in (["Example-Helper"], ["b@1", "a@1"], ["a@1", "a@1"], [], ["-x@1"], ["x@1;rm"], ["x@١"]):
            with self.subTest(names=names):
                self.assertFalse(engine_decisions.valid_names("run_install_scripts", names))

    def test_conditional_rows_are_typed_and_bound_to_the_current_plan(self):
        row = {"action_id": "a1", "payload_sha256": SHA_A, "decision": "runtime_line_change", "names": [], "message_id": "m1", "recorded_utc": CLOCK}

        def state(rows, plan=True):
            return {"used_message_ids": [], "irreversible_warning": None, "approval": None, "conditional_decisions": rows, "revision": 1,
                    "plan": {"sha256": SHA_A, "document": {"actions": [action("a1", pc_records.ADAPTER_PACKAGE_UPGRADE)]}} if plan else None}
        engine_decisions.typed_state(state([row]), 1000)
        cases = {"no plan": state([row], plan=False), "another action": state([dict(row, action_id="a2")]),
                 "an action id that is not text": state([dict(row, action_id=["a1"])]), "a bad payload hash": state([dict(row, payload_sha256="x")]),
                 "an unknown decision": state([dict(row, decision="anything")]), "names for a runtime line": state([dict(row, names=["x@1"])]),
                 "unsorted names": state([dict(row, decision="run_install_scripts", names=["b@1", "a@1"])]), "the same decision twice": state([row, row]),
                 "a bad message id": state([dict(row, message_id="a/b")]), "a bad time": state([dict(row, recorded_utc="today")]),
                 "an extra field": state([dict(row, quote="yes")]), "over the cap": state([row] * (engine_decisions.MAX_CONDITIONAL_DECISIONS + 1))}
        for name, value in cases.items():
            with self.subTest(refused=name), self.assertRaises(WorkflowRefusal):
                engine_decisions.typed_state(value, 1000)
        self.assertEqual(engine_decisions.MAX_CONDITIONAL_DECISIONS, 100)

    def test_followup_needs_one_removal_plan_after_this_sessions_durable_unpartial_backup(self):
        backup = action("b1", adapter_plan_sha256=SHA_B)
        removal = action("r1", pc_records.ADAPTER_STORAGE_REMOVE_ORIGINALS)
        receipt = {"plan_sha256": SHA_B, "outcome": "succeeded", "durable": True}

        def state(stage="verify", outcome="succeeded", followed=(backup,)):
            return {"stage": stage, "plan": {"sha256": SHA_A, "document": {"actions": list(followed)}},
                    "operations": {"o1": {"action_id": "b1", "plan_sha256": SHA_A, "outcome": outcome}}}
        engine_decisions.check_followup(state(), {"actions": [removal]}, [receipt])
        for name, (current, document) in {"before verification": (state("apply"), [removal]), "a failed backup": (state(outcome="failed"), [removal]),
                                          "no backup": (state(followed=(action("q1", pc_records.ADAPTER_STORAGE_QUARANTINE),)), [removal]),
                                          "a second follow-up": (state(followed=(backup, removal)), [removal]),
                                          "an action that removes nothing": (state(), [removal, action("q1", pc_records.ADAPTER_STORAGE_QUARANTINE)])}.items():
            with self.subTest(refused=name):
                refused(self, "followup-plan", lambda: engine_decisions.check_followup(current, {"actions": document}, [receipt]))
        for name, value in {"partial": dict(receipt, outcome="partial"), "not durable": dict(receipt, durable=False), "no durability": {"plan_sha256": SHA_B,
                            "outcome": "succeeded"}, "another backup": dict(receipt, plan_sha256=SHA_A), "no receipt": None}.items():
            with self.subTest(refused=name):
                refused(self, "followup-receipt", lambda: engine_decisions.check_followup(state(), {"actions": [removal]}, [value]))

    def test_followup_notes_name_the_disk_the_synced_services_and_read_only_files(self):
        notes = engine_decisions.followup_notes
        rows = [{"root_id": "r", "relative_path": "a.txt", "read_only": False}, {"root_id": "r", "relative_path": "b.txt", "read_only": True}]
        text, read_only = notes([{"disk_relation": "same", "sources_synced": ["OneDrive"]}], rows)
        self.assertEqual(text, ["This backup is on the same disk as the originals; if the disk fails, both copies are lost.",
                                "This also removes them from OneDrive on all devices.", "1 of these files are read-only; the plan removes them too."])
        self.assertEqual(read_only, [{"root_id": "r", "relative_path": "b.txt"}])
        self.assertEqual(notes([{"disk_relation": "different", "sources_synced": []}], rows[:1]), ([], []))
        for relation in ("unknown", None, "different-ish"):
            with self.subTest(relation=relation):
                self.assertIn("may be on the same disk", notes([{"disk_relation": relation, "sources_synced": []}], rows[:1])[0][0])
        for receipt, files in (({"disk_relation": "same", "sources_synced": "OneDrive"}, rows), ({"disk_relation": "same"}, rows),
                               ({"disk_relation": "same", "sources_synced": ["One<Drive>"]}, rows), ({"disk_relation": "same", "sources_synced": []},
                                                                                                     [{"root_id": "r", "relative_path": "a.txt"}])):
            with self.subTest(receipt=receipt, files=files), self.assertRaises(WorkflowRefusal):
                notes([receipt], files)


if __name__ == "__main__":
    unittest.main()
