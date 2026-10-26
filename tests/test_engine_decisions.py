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
from engine_decisions import remaining_actions, reply_matches

IDS = ("a1", "a2", "a3", "a4")


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
                                       "de lete 12 fi les", "delete 12 files..", "delete 12 files!", "delete 12 files\n", "delete \uff11\uff12 files",
                                       "delete 12 files please", "yes", "", 12, None),
                   "update firmware on device 2, I have my recovery key": ("update \ufb01rmware on device 2, I have my recovery key",
                                                                           "update firmware on device 2, I have my recovery \u212aey")}
        for phrase, quotes in refused.items():
            for quote in quotes:
                with self.subTest(refused=quote):
                    self.assertFalse(reply_matches(quote, phrase))


if __name__ == "__main__":
    unittest.main()
