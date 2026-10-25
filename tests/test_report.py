"""Session report tests (scripts/report.py, templates/report.html), fictional data only.

Run with supported Python: -I -S -B -m unittest discover -s tests -p test_report.py -v
Engine-driven fixtures live under work/test-fixtures/rp-<id>/ and are removed after each test. The page's program
itself is exercised by tests/test_report_ui.cjs under Node; these tests check the record, the embedding and the CSP.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import itertools
from pathlib import Path
import re
import shutil
import sys
import unicodedata
import unittest
from unittest import mock
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_paths
import pc_records
import report
import workflow_core
from clock_helpers import start_forward_only_clock

WORK = ROOT / "work" / "test-fixtures"
TEMPLATE = ROOT / "templates" / "report.html"
CLOCK = "2026-01-02T03:04:05.000006Z"
TITLES = ["Scope", "Findings", "Plan", "Assistant reviews of the plan", "Approvals", "Outcomes", "Free space", "Package results",
          "Recovery copies kept"]
DATA_BLOCK = re.compile(r'<script type="application/json" id="report-data">(.*?)</script>', re.S)
HOSTILE = ("</script><script>globalThis.injected=1</script><!-- <img src=x onerror=alert(1)> &amp; \u2028 \u202e "
           "@@SCRIPT_SHA256@@ @@STYLE_SHA256@@ @@REPORT_DATA@@ end")
SUMMARY = "patchcairn.assessment.summary"
OPERATION = "operation-" + "0" * 32
# The record digest of report_session() rendered at CLOCK (PLAN.md 4.4 step 6: the report record layout).
GOLDEN_SHA256 = "7512daed5dfcaaced5cbae637582828dbe6ab610413a25f3ad4cd94b62aaac87"


def owner(quote, message_id, **extra):
    """An owner-decision record as the engine's _owner writes it, plus ``extra``."""
    return {"owner_id": "owner", "quote": quote, "message_id": message_id, "source": "current_owner_chat", "recorded_utc": CLOCK,
            "settings_revision": 0, **extra}


def report_session(**changes):
    """A hand-built snapshot shaped like WorkflowEngine.read_session: one plan, two reviews, an approval and a
    finished operation, all fictional."""
    scope = {"roots": ["fictional-selected-folder"], "purpose": "Fictional report fixture only"}
    action = {"action_id": "fictional-action", "kind": "backup_create", "target": "Fictional component",
              "benefit": "A fictional copy", "risk": "Fictional data could change", "reversibility": "Keep the fictional source",
              "verification": "Check the fictional copy", "mutating": True, "requires_os_consent": False, "requires_recovery": False,
              "recovery_evidence_ids": [], "adapter_id": pc_records.ADAPTER_STORAGE_BACKUP_CREATE}
    document = {"plan_id": "fictional-plan", "summary": "Fictional reviewed plan", "evidence_ids": ["rp-ev-1"], "actions": [action]}
    plan_sha256 = pc_records.digest(document)
    review = {"evidence_ids": ["rp-ev-2"], "notes": "Fictional assistant review pass", "plan_sha256": plan_sha256,
              "settings_revision": 0, "recorded_utc": CLOCK, "verdict": "approved"}
    session = {
        "schema_version": 1, "session_id": "session-" + "0" * 31 + "1", "engine_id": "0" * 32, "backend": "patchcairn.workflow.python",
        "mode": "fixture", "platform": "unknown", "created_utc": CLOCK, "updated_utc": CLOCK, "creation_scope_sha256": pc_records.digest(scope),
        "owner_id": "owner", "revision": 9, "settings_revision": 0, "job": "security_updates", "stage": "apply", "status": "active",
        "settings": {"scope": scope, "control": "guided", "timing": "now", "checkpoints": []},
        "scope_authorization": owner("Look only at this fictional folder.", "fictional-scope", scope_sha256=pc_records.digest(scope)),
        "evidence": {"rp-ev-1": {"evidence_id": "rp-ev-1", "path": "evidence/rp-ev-1.bin", "sha256": "a" * 64, "size": 10,
                                 "kind": "inventory", "scope": scope, "settings_revision": 0, "observed_utc": CLOCK,
                                 "registered_utc": CLOCK, "facts": {"complete": True, "item_count": 1}}},
        "plan": {"document": document, "sha256": plan_sha256, "settings_revision": 0, "registered_utc": CLOCK},
        "reviews": [dict(review, reviewer_id="fictional-reviewer-a", role="compatibility_data"),
                    dict(review, reviewer_id="fictional-reviewer-b", role="evidence_security")],
        "approval": owner("Apply this exact fictional action.", "fictional-plan", plan_sha256=plan_sha256, action_ids=["fictional-action"],
                          permanent_loss_action_ids=[]),
        "irreversible_ack": None, "standing_policy": None,
        "operations": {OPERATION: {"operation_id": OPERATION, "action_id": "fictional-action", "plan_sha256": plan_sha256,
                                   "settings_revision": 0, "started_utc": CLOCK, "finished_utc": CLOCK, "outcome": "succeeded",
                                   "evidence_ids": [], "summary": "Fictional outcome as recorded", "authorization": {},
                                   "pause_requested": False, "resolution": None, "mutating": True,
                                   "adapter_id": pc_records.ADAPTER_STORAGE_BACKUP_CREATE}},
        "pending": {}, "schedule": None, "schedule_triggers": [], "last_reconciled_utc": None, "stop_reason": None,
    }
    session.update(changes)
    return session


def summary_for(session, **changes):
    """A fictional assessment summary bound to the session's job, mode, scope and settings revision."""
    record = {"schema": SUMMARY, "schema_version": 1, "job": session["job"], "mode": session["mode"],
              "scope_sha256": pc_records.digest(session["settings"]["scope"]), "settings_revision": session["settings_revision"],
              "summary": "Fictional assessment summary", "findings": ["Fictional finding A"],
              "limitations": ["Fictional limitation B"], "assessed_evidence_ids": sorted(session["evidence"])[:1]}
    record.update(changes)
    return record


def embedded(page):
    """(html, data block, decoded record) of a rendered page."""
    html = page.decode("utf-8")
    block = DATA_BLOCK.search(html)[1]
    return html, block, pc_records.decode_strict(block.encode("ascii"))


def rendered(session, **options):
    return embedded(report.render_session(session, **options))[2]


def items(record, key):
    """The field lists of a section, in order, each as a list of (label, value)."""
    return [[tuple(pair) for pair in content] for kind, content in record[key] if kind == "fields"]


def pairs(record, key):
    return [pair for item in items(record, key) for pair in item]


def notes(record, key):
    return [content for kind, content in record[key] if kind == "note"]


def shown(record, key):
    """Every text a section shows: its headings, notes and each field's label and value."""
    return " | ".join(content if kind != "fields" else " | ".join(label + ": " + value for label, value in content)
                      for kind, content in record[key])


class Shown(dict):
    """Field values by label; an absent label reads as None, so a missing row fails an assertion instead of erroring."""

    def __missing__(self, label):
        return None


def decision(record, name):
    """The one Approvals entry with this decision name (an empty Shown when there is not exactly one)."""
    found = [Shown(item) for item in items(record, "approvals") if ("Decision", name) in item]
    return found[0] if len(found) == 1 else Shown()


def hashed(text):
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


class ReportTests(unittest.TestCase):
    def setUp(self):
        start_forward_only_clock(self)

    def refused(self, call, code):
        with self.assertRaises(pc_records.Refusal) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def engine(self):
        root = WORK / ("rp-" + uuid.uuid4().hex[:12])
        root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, root)
        return root, workflow_core.WorkflowEngine(root, verify_artifact=lambda binding: None)

    def driven_session(self):
        """A fixture session driven through the public engine methods up to one finished operation."""
        root, engine = self.engine()
        scope = {"roots": ["fictional-selected-folder"], "purpose": "Fictional report fixture only; no host collection"}
        sid = engine.create_session(scope=scope, checkpoints=[])["session_id"]
        numbers = itertools.count(1)

        def evidence(kind, facts=None, content=None):
            evidence_id = "rp-ev-" + str(next(numbers))
            data = pc_records.encoded({"fictional": True, "facts": facts or {}} if content is None else content)
            engine.register_evidence(sid, evidence_id=evidence_id, content=data, kind=kind, scope=scope, facts=facts)
            return evidence_id

        engine.authorize_scope(sid, owner_quote="Back up only this fictional selected folder.", owner_message_id="fictional-owner-scope")
        engine.advance_stage(sid, evidence_ids=[evidence("scope_confirmation", {"scope_confirmed": True})])
        engine.advance_stage(sid, evidence_ids=[evidence("inventory", {"complete": True, "item_count": 1})])
        engine.advance_stage(sid, evidence_ids=[evidence("research", {"applicability_checked": True, "official_sources_checked": True})])
        inventory = {"fictional": True, "entries": [{"name": "fictional.data", "size": 1}]}
        lower = {"schema": "patchcairn.storage", "schema_version": 1, "kind": "backup", "inventory": inventory, "fixture": True}
        payload = {"schema": "patchcairn.storage.adapter", "schema_version": 1, "operation": pc_records.ADAPTER_STORAGE_BACKUP_CREATE,
                   "storage_plan": lower, "storage_plan_sha256": pc_records.digest(lower), "output_root": str(root / "work" / "rp-out"),
                   "mode": "fixture", "protected_roots": []}
        action = {"action_id": "fictional-action", "kind": "backup_create", "target": "Fictional component",
                  "benefit": "A fictional copy of the selected folder", "risk": "Fictional data could change",
                  "reversibility": "Keep the fictional source", "verification": "Check the fictional copy", "mutating": True,
                  "requires_os_consent": False, "requires_recovery": False, "recovery_evidence_ids": [],
                  "adapter_id": payload["operation"], "adapter_payload_evidence_id": evidence("adapter_payload", content=payload),
                  "adapter_payload_sha256": pc_records.digest(payload), "adapter_plan_sha256": pc_records.digest(lower),
                  "target_inventory_evidence_id": evidence("inventory", {"complete": True, "item_count": 1}, inventory),
                  "target_inventory_sha256": pc_records.digest(inventory)}
        plan = {"plan_id": "fictional-plan", "summary": "Fictional reviewed plan",
                "evidence_ids": [evidence("inventory", {"complete": True, "item_count": 1})], "actions": [action]}
        plan_sha256 = engine.register_plan(sid, plan=plan)["data"]["plan_sha256"]
        for reviewer, role in (("fictional-reviewer-a", "compatibility_data"), ("fictional-reviewer-b", "evidence_security")):
            engine.record_review(sid, plan_sha256=plan_sha256, reviewer_id=reviewer, role=role, verdict="approved",
                                 evidence_ids=[evidence("review", {"reviewed": True})], notes="Fictional assistant review pass")
        engine.approve_plan(sid, plan_sha256=plan_sha256, action_ids=["fictional-action"], owner_quote="Apply this exact fictional action.",
                            owner_message_id="fictional-owner-plan")
        engine.advance_stage(sid, evidence_ids=[])
        binding = {key: action[key] for key in ("adapter_id", "adapter_payload_sha256", "adapter_plan_sha256", "target_inventory_sha256")}
        precondition = evidence("precondition", {"action_id": "fictional-action", "plan_sha256": plan_sha256, "identity_matches": True,
                                                 "scope_matches": True, "content_matches": True, "compatibility_checked": True,
                                                 "provenance_checked": True, **binding})
        operation_id = engine.begin_operation(sid, action_id="fictional-action", plan_sha256=plan_sha256,
                                              precondition_evidence_ids=[precondition])["data"]["operation_id"]
        outcome = evidence("outcome", {"operation_id": operation_id, "action_id": "fictional-action", "plan_sha256": plan_sha256,
                                       "outcome": "succeeded"})
        engine.finish_operation(sid, operation_id=operation_id, outcome="succeeded", evidence_ids=[outcome],
                                summary="Fictional outcome as recorded")
        return engine.read_session(sid)

    def test_report_renders_session(self):
        state = self.driven_session()
        page = report.render_session(
            state, assessment=summary_for(state),
            free_space=[{"volume": "fictional-volume", "before_bytes": 1000, "after_bytes": 1500, "expected_net_bytes": 400}],
            packages=[{"manager": "fictional-manager", "package": "Fictional.Package", "outcome": "upgraded", "restart": "none"}],
            retained=[{"kind": "backup", "location": "work/fictional-backup", "bytes": 2048}])
        html, _, record = embedded(page)
        self.assertEqual(re.findall(r"<h2>([^<]*)</h2>", html), TITLES)
        self.assertIs(pc_records.READERS[report.SCHEMA](record), record)
        self.assertEqual(set(record), {"schema", "schema_version", "generated_utc", "title", "banner", "header", *report.SECTIONS})
        self.assertEqual(record["title"], "PatchCairn session report: security_updates, created " + state["created_utc"][:10])
        self.assertEqual(record["banner"], report.BANNER)
        self.assertIn(("Session", state["session_id"]), pairs(record, "header"))
        self.assertIn(("Mode", "practice with made-up data (fixture)"), pairs(record, "header"))
        self.assertEqual(notes(record, "header"), [report.PAGE_NOTE, report.TIME_NOTE])
        self.assertIn(("Plan fingerprint (SHA-256)", state["plan"]["sha256"]), pairs(record, "plan"))
        self.assertIn(report.PLAN_NOTE, notes(record, "plan"))
        self.assertIn(("How the result will be checked", "Check the fictional copy"), pairs(record, "plan"))
        self.assertIn(("How it can be undone", "Keep the fictional source"), pairs(record, "plan"))
        reviews = [dict(item) for item in items(record, "reviews")]
        self.assertEqual([(row["Reviewer"], row["Role"], row["Review result"]) for row in reviews],
                         [("fictional-reviewer-a", "Compatibility and data safety (compatibility_data)", "no reason to stop found (approved)"),
                          ("fictional-reviewer-b", "Evidence and security (evidence_security)", "no reason to stop found (approved)")])
        self.assertTrue(all(row["Plan fingerprint"] == report.SAME_PLAN for row in reviews))
        approval = decision(record, "Plan approval")
        self.assertEqual((approval["Quoted instruction"], approval["Message id"], approval["Given in"], approval["Approved actions"],
                          approval["Plan fingerprint"]),
                         ("Apply this exact fictional action.", "fictional-owner-plan", "the chat (current_owner_chat)", "fictional-action",
                          report.SAME_PLAN))
        [operation] = state["operations"].values()
        self.assertEqual(items(record, "outcomes"), [[
            ("Action", "fictional-action"), ("Plan fingerprint", report.SAME_PLAN), ("Authorized by", "the plan approval (message fictional-owner-plan)"),
            ("Started (UTC)", operation["started_utc"]), ("Finished (UTC)", operation["finished_utc"]), ("Result", "succeeded"),
            ("Summary", "Fictional outcome as recorded"), ("Resolution", "not recorded")]])
        self.assertEqual(notes(record, "outcomes"), [])  # a succeeded step from the current plan needs no note
        # The full plan fingerprint appears only under Plan (and inside evidence records, which are copied as written).
        for key in report.SECTIONS:
            if key not in ("plan", "findings"):
                self.assertNotIn(state["plan"]["sha256"], shown(record, key), key)
        # Findings: what was found first, then the evidence records in observed order (rp-ev-10 is last, not second).
        self.assertEqual(record["findings"][0], ["heading", "What was found"])
        self.assertEqual(items(record, "findings")[0][:2], [("Summary", "Fictional assessment summary"), ("Problem found", "Fictional finding A")])
        evidence_ids = [dict(item)["Evidence"] for item in items(record, "findings")[1:]]
        self.assertEqual(evidence_ids, ["rp-ev-" + str(number) for number in range(1, 11)])
        kinds = [kind for kind, _ in record["findings"]]
        self.assertEqual(kinds, ["heading", "fields", "heading", "note"] + ["fields"] * 10)
        self.assertEqual(record["findings"][2:4], [["heading", "Technical records (evidence)"], ["note", report.EVIDENCE_NOTE]])
        self.assertIn(("Recorded value", "scope_confirmed: true"), pairs(record, "findings"))
        self.assertIn(("Selected folder or drive", "fictional-selected-folder"), pairs(record, "scope"))
        self.assertEqual(dict(items(record, "free_space")[0])["Measured change"], "500 bytes more free space")
        self.assertEqual(dict(items(record, "free_space")[0])["Expected change (estimate)"], "400 bytes more free space")
        self.assertIn(("Package", "Fictional.Package"), pairs(record, "packages"))
        self.assertIn(("Size", "about 2.0 KB (2,048 bytes)"), pairs(record, "retained"))
        self.assertEqual(notes(record, "retained"), [report.RETAINED_NOTE])

    def test_hostile_text_is_inert(self):
        session = report_session(platform="windows")
        access = {"schema": "patchcairn.assessment.access", "schema_version": 1, "target": "selected_paths",
                  "operations": ["metadata", "content_read"], "llm_content": ["sel-1"], "sensitive_exceptions": [],
                  "local_content": [{"id": "sel-1", "kind": "path", "source": "C:/Fictional/na\u202eme.txt", "selection": HOSTILE}]}
        session["settings"]["scope"] = {"roots": ["D:\\Fictional\\Photos", "D:\\Fictional/na\u202eme"], "purpose": HOSTILE, "assessment": access}
        session["plan"]["document"]["summary"] = HOSTILE
        session["approval"]["quote"] = HOSTILE
        session["evidence"]["rp-ev-1"]["facts"] = {HOSTILE: HOSTILE, "nested": [HOSTILE]}
        session["operations"][OPERATION]["summary"] = HOSTILE
        session["plan"]["document"]["actions"][0]["target"] = "D:\\Fictional\\na\u202eme"
        session["standing_policy"] = owner("Fictional policy", "fictional-policy", action_kinds=["backup_create"], max_actions=1,
                                           used_actions=0, expires_utc=CLOCK, targets=["D:\\Fictional\\" + HOSTILE])
        page = report.render_session(session, assessment=summary_for(session, summary=HOSTILE, findings=[HOSTILE]),
                                     packages=[{"manager": HOSTILE, "package": HOSTILE, "outcome": HOSTILE, "restart": HOSTILE}],
                                     retained=[{"kind": HOSTILE, "location": "D:\\Fictional\\" + HOSTILE, "bytes": None}])
        # The script boundaries are checked before anything is decoded: hostile text must not end the data block.
        html, template = page.decode("utf-8"), TEMPLATE.read_text(encoding="utf-8")
        for tag in ("<script", "</script", "<img", "<!--"):
            self.assertEqual(html.count(tag), template.count(tag), tag)
        self.assertFalse(set(DATA_BLOCK.search(html)[1]) & set("<>&"))
        record = embedded(page)[2]
        self.assertIs(pc_records.READERS[report.SCHEMA](record), record)
        self.assertEqual(pc_records.decode_strict(pc_records.encoded(record)), record)
        escaped = pc_paths.display(HOSTILE)
        self.assertIn("</script><script>", escaped)
        self.assertIn("\\u2028 \\u202e @@SCRIPT_SHA256@@ @@STYLE_SHA256@@ @@REPORT_DATA@@", escaped)
        # Placeholder text inside session data is never substituted: the data goes in last.
        self.assertNotIn("@@", html.replace(DATA_BLOCK.search(html)[1], ""))
        for key, pair in (("scope", ("Purpose", escaped)), ("plan", ("Summary", escaped)), ("findings", ("Summary", escaped)),
                          ("findings", ("Problem found", escaped)), ("findings", ("Recorded value", escaped + ": " + escaped)),
                          ("outcomes", ("Summary", escaped)), ("retained", ("Kind", escaped)),
                          ("retained", ("Location", "D:\\Fictional\\" + escaped)), ("approvals", ("Quoted instruction", escaped)),
                          ("packages", ("Manager", escaped)), ("packages", ("Package", escaped)), ("packages", ("Result", escaped)),
                          ("packages", ("Restart", escaped)), ("scope", ("Selected folder or drive", "D:\\Fictional\\Photos")),
                          ("scope", ("Selected folder or drive", "D:\\Fictional/na\\u202eme")),
                          ("scope", ("Content to read", "sel-1: C:/Fictional/na\\u202eme.txt (" + escaped + ")")),
                          ("plan", ("Target", "D:\\Fictional\\na\\u202eme")), ("approvals", ("Targets", "D:\\Fictional\\" + escaped))):
            with self.subTest(section=key, label=pair[0]):
                self.assertIn(pair, pairs(record, key))
        self.assertIn(("Allowed checks", "file and system details (metadata), reading selected file contents (content_read)"),
                      pairs(record, "scope"))
        self.assertIn(("Assessment covers", "selected folders or files (selected_paths)"), pairs(record, "scope"))
        self.assertIn(("Selected file contents the assistant may see", "sel-1"), pairs(record, "scope"))
        self.assertIn(("Selected files that may be read although they are normally private (sensitive exceptions)", "None listed"),
                      pairs(record, "scope"))
        # With no selected contents, the page still says what the allowed checks can put in the chat.
        session["settings"]["scope"]["assessment"] = dict(access, operations=["metadata"], local_content=[], llm_content=[])
        self.assertIn(("Selected file contents the assistant may see", "None listed. File names, folder names, sizes and other details from "
                       "the allowed checks can still appear in the chat with the assistant."), pairs(rendered(session), "scope"))
        # Outside a Windows session a backslash is part of a name, so it is escaped and only "/" separates.
        session = report_session()
        session["settings"]["scope"] = {"roots": ["fictional\\name/na\u202eme"], "purpose": "Fictional"}
        self.assertIn(("Selected folder or drive", "fictional\\u005cname/na\\u202eme"), pairs(rendered(session), "scope"))

    def test_no_control_characters_reach_the_page(self):
        # Hostile text with control, format, separator and unassigned characters goes into every string input except the
        # times the report parses, the kinds that pick a branch and the evidence ids it matches; no string in the record
        # may keep one of those characters.
        evil = HOSTILE + "\u200b\x00\x1b\n\t\u2029\u0378\ufeff"
        keep = {"created_utc", "observed_utc", "started_utc", "assessed_evidence_ids", "schema", "kind"}

        def poisoned(value, key=None):
            if isinstance(value, dict):
                return {name: poisoned(item, name) for name, item in value.items()}
            if isinstance(value, list):
                return [poisoned(item, key) for item in value]
            return value + evil if isinstance(value, str) and key not in keep else value

        plan_sha256 = report_session()["plan"]["sha256"]
        access = {"schema": "patchcairn.assessment.access", "schema_version": 1, "target": "selected_paths", "operations": ["metadata"],
                  "local_content": [{"id": "sel-1", "kind": "path", "source": "C:/Fictional/a.txt", "selection": "lines 1-5"}],
                  "llm_content": ["sel-1"], "sensitive_exceptions": ["sel-1"]}
        operation = dict(report_session()["operations"][OPERATION], outcome="failed",
                         authorization={"kind": "exact_plan", "message_id": "fictional-plan", "plan_sha256": plan_sha256, "action_id": "a"},
                         resolution={"kind": "replan_required", "evidence_ids": [], "recorded_utc": CLOCK, "owner_message_id": "m"},
                         restart_pending={"evidence_id": "rp-ev-1", "recorded_utc": CLOCK},
                         restart_decision=owner("Restart later.", "fictional-restart", choice="defer", operation_id=OPERATION,
                                                plan_sha256=plan_sha256, not_before_utc=CLOCK, attestation="coordinator-attested"))
        session = report_session(
            platform="windows", settings={"scope": {"roots": ["D:\\Fictional\\Photos"], "purpose": "Fictional", "assessment": access},
                                          "control": "guided", "timing": "now", "checkpoints": []},
            irreversible_ack=owner("Fictional loss accepted.", "fictional-ack", plan_sha256=plan_sha256, action_ids=["fictional-action"]),
            standing_policy=owner("Fictional policy.", "fictional-policy", action_kinds=["backup_create"], targets=["D:\\Fictional"],
                                  max_actions=2, used_actions=1, expires_utc=CLOCK, attestation="other"),
            schedule=owner("Fictional schedule.", "fictional-schedule", proposal={"when_utc": CLOCK, "description": "Fictional"}),
            operations={OPERATION: operation},
            pending={"c": {"kind": "checkpoint", "checkpoint": "plan", "action_id": "fictional-action",
                           "owner_instruction": owner("Continue.", "fictional-continue")},
                     "r": {"kind": "reconciliation", "operation_id": OPERATION, "owner_instruction": owner("Replan.", "fictional-replan")},
                     "p": {"kind": "protected_consent", "record": owner("Consent handled.", "fictional-consent", plan_sha256=plan_sha256,
                                                                        action_id="fictional-action")},
                     "a": {"kind": "assessment_finish", "record": {"summary_evidence_id": "rp-ev-1",
                                                                   "owner_instruction": owner("Finish.", "fictional-finish")}}})
        session["evidence"]["rp-ev-1"]["facts"] = {"plain": "text", "nested": {"list": ["a", "b"]}, "flag": True}
        session = poisoned(session)
        session["mode"] = "fixture"
        session["evidence"]["rp-ev-1"]["facts"][evil] = evil
        session["evidence"]["rp-ev-1"]["kind"] += evil
        session["operations"][OPERATION]["resolution"]["kind"] += evil
        session["operations"][OPERATION]["summary"] += "\ud800"
        session["pending"]["u"] = {"kind": "fictional" + evil, "owner_instruction": poisoned(owner("Other.", "fictional-other"))}
        summary = summary_for(session)
        summary.update(summary=evil, findings=[evil], limitations=[evil + "\udfff"])
        record = rendered(session, assessment=summary,
                          free_space=[{"volume": "D:\\" + evil, "before_bytes": 5, "after_bytes": None, "expected_net_bytes": None}],
                          packages=[{"manager": evil + "\ud800", "package": evil, "outcome": evil, "restart": evil}],
                          retained=[{"kind": evil, "location": "D:\\" + evil, "bytes": 1}])

        def strings(value):
            if isinstance(value, dict):
                for name, item in value.items():
                    yield name
                    yield from strings(item)
            elif isinstance(value, list):
                for item in value:
                    yield from strings(item)
            elif isinstance(value, str):
                yield value

        texts = list(strings(record))
        for text in texts:
            hidden = sorted({f"U+{ord(char):04X}" for char in text if unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp", "Cs", "Cn"}})
            self.assertEqual(hidden, [], text[:120])
        joined = "\n".join(texts)
        for escape in ("\\u202e", "\\u200b", "\\u0000", "\\u001b", "\\u000a", "\\u0009", "\\u2029", "\\u0378", "\\ufeff", "\\ud800", "\\udfff"):
            self.assertIn(escape, joined)
        self.assertIn("Other owner decision (fictional", joined)

    def test_csp_is_strict(self):
        html = report.render_session(report_session()).decode("utf-8")
        first_meta = re.search(r"<meta [^>]*>", html.split("<head>", 1)[1].split("</head>", 1)[0])[0]
        match = re.fullmatch(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)">', first_meta)
        self.assertIsNotNone(match, "the CSP must be the first meta in the head: " + first_meta)
        policy = match[1]
        programs, styles = re.findall(r"<script>(.*?)</script>", html, re.S), re.findall(r"<style>(.*?)</style>", html, re.S)
        self.assertEqual((len(programs), len(styles)), (1, 1))
        self.assertEqual(policy.split("; "), ["default-src 'none'", f"script-src 'sha256-{hashed(programs[0])}'",
                                              f"style-src 'sha256-{hashed(styles[0])}'", "connect-src 'none'", "img-src 'none'",
                                              "base-uri 'none'", "form-action 'none'"])
        self.assertIn("connect-src 'none'", policy)
        self.assertNotIn("unsafe-", html)
        self.assertNotIn("@@", html.replace(DATA_BLOCK.search(html)[1], ""))
        # The template keeps each placeholder once, outside the program and the style; anything else is refused.
        template = TEMPLATE.read_text(encoding="utf-8")
        self.assertEqual(report._page(template, "{}"), html.replace(DATA_BLOCK.search(html)[1], "{}").encode("utf-8"))
        for mark in (report.SCRIPT_HASH, report.STYLE_HASH, report.DATA):
            self.assertEqual(template.count(mark), 1, mark)
        broken = (template.replace("'use strict';", "'use strict';" + report.DATA),
                  template.replace("</style>", report.SCRIPT_HASH + "</style>"),
                  template.replace("</body>", "<script>'use strict';</script></body>"),
                  template.replace(report.DATA_ELEMENT, '<div id="report-data">' + report.DATA + "</div>"))
        for number, changed in enumerate(broken):
            with self.subTest(template=number):
                self.refused(lambda: report._page(changed, "{}"), "report-template")

    def test_template_sections_match_record(self):
        # The program's key list, the template's section ids and the record's sections are one list, in one order.
        template = TEMPLATE.read_text(encoding="utf-8")
        [program] = re.findall(r"<script>(.*?)</script>", template, re.S)
        [keys] = re.findall(r"for \(const key of \[([^\]]*)\]\)", program)
        self.assertEqual(re.findall(r"'([^']*)'", keys), list(report.SECTIONS))
        self.assertEqual(re.findall(r'<section id="([^"]+)"><h2>[^<]*</h2></section>', template), list(report.SECTIONS))
        self.assertEqual(re.findall(r"<h2>([^<]*)</h2>", template), TITLES)

    def test_node_fixture_uses_report_wording(self):
        # tests/test_report_ui.cjs renders hand-written records; their texts must be report.py's, word for word.
        node = (ROOT / "tests" / "test_report_ui.cjs").read_text(encoding="utf-8")
        texts = {name: getattr(report, name) for name in (
            "BANNER", "PAGE_NOTE", "TIME_NOTE", "DECISIONS_NOTE", "SCOPE_NOTE", "REVIEWS_NOTE", "OWNER_ATTESTED", "REVIEW_ATTESTED",
            "UNLABELLED", "NO_FINDINGS", "EVIDENCE_HEADING", "EVIDENCE_NOTE", "PLAN_NOTE", "SAME_PLAN", "NO_RESULT", "RESTART_WAITING",
            "RESTART_UNDECIDED", "OUTCOMES_NOTE", "EARLIER_PLAN_NOTE", "EXPLORER_NOTE", "RETAINED_NOTE")}
        texts.update(zip(("FREE_SPACE_MEASURED", "FREE_SPACE_ESTIMATE", "FREE_SPACE_UNITS"), report.FREE_SPACE_NOTES))
        for name, text in texts.items():
            with self.subTest(text=name):
                self.assertIn(f'const {name} = "{text}";\n', node)

    def test_no_csv_or_ledger_text(self):
        sources = {"template": TEMPLATE.read_text(encoding="utf-8"), "report.py": (ROOT / "scripts" / "report.py").read_text(encoding="utf-8")}
        texts = dict(sources, output=report.render_session(report_session()).decode("utf-8"))
        for name, text in texts.items():
            with self.subTest(text=name):
                self.assertIsNone(re.search(r"(?i)ledger|csv", text))
                # No link, download, image or remote asset; the page shows recorded outcomes without wording of its own.
                self.assertIsNone(re.search(r"(?i)<a\s|href|\bdownload\b|<img|<link|src=|https?:|url\(|@import", text))
        for name, text in sources.items():
            with self.subTest(source=name):
                self.assertIsNone(re.search(r"(?i)\bsafe\b|backed up|success|\bclean\b|\bproves?\b|independent", text))

    def test_refuses_non_session_input(self):
        session = report_session()
        operation = session["operations"][OPERATION]
        row = {"volume": "v", "before_bytes": 1, "after_bytes": 2, "expected_net_bytes": None}
        cases = {
            "typed record": ({"schema": report.SCHEMA, "schema_version": 1}, {}, "schema-name"),
            "no schema_version": ({key: value for key, value in session.items() if key != "schema_version"}, {}, "schema-version"),
            "list": ([session], {}, "record-shape"),
            "missing plan": ({key: value for key, value in session.items() if key != "plan"}, {}, "report-input"),
            "missing pending": ({key: value for key, value in session.items() if key != "pending"}, {}, "report-input"),
            "reviews not a list": (dict(session, reviews={}), {}, "report-input"),
            "missing settings": ({key: value for key, value in session.items() if key != "settings"}, {}, "report-input"),
            "roots not text": (dict(session, settings={"scope": {"roots": [1], "purpose": "Fictional"}}), {}, "report-input"),
            "assessment access without target": (dict(session, settings={"scope": {"roots": [], "purpose": "Fictional", "assessment": {}}}),
                                                 {}, "report-input"),
            "action not a record": (dict(session, plan=dict(session["plan"], document={"plan_id": "p", "summary": "s", "actions": ["x"]})),
                                    {}, "report-input"),
            "fact key not text": (dict(session, evidence={"e": dict(session["evidence"]["rp-ev-1"], facts={1: "x"})}), {}, "report-input"),
            "observed time not UTC text": (dict(session, evidence={"e": dict(session["evidence"]["rp-ev-1"], observed_utc="yesterday")}),
                                           {}, "utc-time"),
            "operation not a record": (dict(session, operations={"o": 5}), {}, "report-input"),
            "outcome not text": (dict(session, operations={"o": dict(operation, outcome=5)}), {}, "report-input"),
            "resolution not a record": (dict(session, operations={"o": dict(operation, resolution="done")}), {}, "report-input"),
            "restart decision not a record": (dict(session, operations={"o": dict(operation, restart_decision=[])}), {}, "report-input"),
            "attestation not text": (dict(session, approval=dict(session["approval"], attestation=7)), {}, "report-input"),
            "pending item not a record": (dict(session, pending={"p": "x"}), {}, "report-input"),
            "schedule without proposal": (dict(session, schedule=owner("Fictional schedule", "fictional-schedule")), {}, "report-input"),
            "policy count too large": (dict(session, standing_policy=owner("Fictional policy", "fictional-policy", action_kinds=[], targets=[],
                                                                           max_actions=10 ** 20, used_actions=0, expires_utc=CLOCK)),
                                       {}, "report-input"),
            "session id missing": (dict(session, session_id=None), {}, "report-input"),
            "created time not UTC text": (dict(session, created_utc="2026-01-02"), {}, "report-input"),
            "negative settings revision": (dict(session, settings_revision=-1), {}, "report-input"),
            "authorization not a record": (dict(session, operations={"o": dict(operation, authorization="approved")}), {}, "report-input"),
            "authorization without kind": (dict(session, operations={"o": dict(operation, authorization={"message_id": "m"})}), {}, "report-input"),
            "plan approval without message": (dict(session, operations={"o": dict(operation, authorization={"kind": "exact_plan"})}), {},
                                              "report-input"),
            "restart pending not a record": (dict(session, operations={"o": dict(operation, restart_pending="3010")}), {}, "report-input"),
            "unknown pending kind without quote": (dict(session, pending={"p": {"kind": "fictional-kind", "record": {"note": "x"}}}), {},
                                                   "report-input"),
            "free_space not a list": (session, {"free_space": {"volume": "v"}}, "report-input"),
            "free_space unknown key": (session, {"free_space": [dict(row, extra=1)]}, "report-input"),
            "free_space missing key": (session, {"free_space": [{"volume": "v", "before_bytes": 1, "after_bytes": 2}]}, "report-input"),
            "free_space text bytes": (session, {"free_space": [dict(row, before_bytes="1")]}, "report-input"),
            "free_space bool bytes": (session, {"free_space": [dict(row, before_bytes=True)]}, "report-input"),
            "free_space negative": (session, {"free_space": [dict(row, before_bytes=-1)]}, "report-input"),
            "free_space 21 digits": (session, {"free_space": [dict(row, after_bytes=10 ** 20)]}, "report-input"),
            "free_space expected 21 digits": (session, {"free_space": [dict(row, expected_net_bytes=-10 ** 20)]}, "report-input"),
            "free_space no volume": (session, {"free_space": [dict(row, volume=None)]}, "report-input"),
            "packages not text": (session, {"packages": [{"manager": "m", "package": "p", "outcome": 1, "restart": "r"}]}, "report-input"),
            "packages unknown key": (session, {"packages": [{"manager": "m", "package": "p", "outcome": "o", "restart": "r",
                                                             "version": "1"}]}, "report-input"),
            "retained float bytes": (session, {"retained": [{"kind": "backup", "location": "l", "bytes": 1.5}]}, "report-input"),
            "retained negative bytes": (session, {"retained": [{"kind": "backup", "location": "l", "bytes": -1}]}, "report-input"),
            "retained 21 digits": (session, {"retained": [{"kind": "backup", "location": "l", "bytes": 10 ** 20}]}, "report-input"),
            "retained no location": (session, {"retained": [{"kind": "backup", "location": None, "bytes": 1}]}, "report-input"),
        }
        for name, (value, options, code) in cases.items():
            with self.subTest(case=name):
                self.refused(lambda: report.render_session(value, **options), code)
        # Just inside the bound is accepted.
        self.assertIn(("Free space after", "about 100000.0 PB (99,999,999,999,999,999,999 bytes)"),
                      pairs(rendered(session, free_space=[dict(row, after_bytes=10 ** 20 - 1)]), "free_space"))

    def test_assessment_binding(self):
        session = report_session(settings_revision=2)
        later = dict(session, evidence=dict(session["evidence"], **{"rp-ev-2": dict(session["evidence"]["rp-ev-1"], evidence_id="rp-ev-2")}))
        cases = {
            "another job": summary_for(session, job="storage_cleanup"), "another mode": summary_for(session, mode="real"),
            "another scope": summary_for(session, scope_sha256="0" * 64), "unknown key": summary_for(session, extra="x"),
            "findings not text": summary_for(session, findings=[1]), "assessed ids not a list": summary_for(session, assessed_evidence_ids="rp-ev-1"),
            "assessed id the session lacks": summary_for(session, assessed_evidence_ids=["rp-ev-1", "rp-ev-9"]),
            "no assessed ids": summary_for(session, assessed_evidence_ids=[]),
            "later settings revision": summary_for(session, settings_revision=3),
            "negative settings revision": summary_for(session, settings_revision=-1),
            "revision not an integer": summary_for(session, settings_revision=True),
        }
        for name, summary in cases.items():
            with self.subTest(case=name):
                self.refused(lambda: report.render_session(later, assessment=summary), "report-input")
        self.refused(lambda: report.render_session(session, assessment=dict(summary_for(session), schema="patchcairn.service")), "schema-name")
        self.refused(lambda: report.render_session(session, assessment=[summary_for(session)]), "record-shape")
        # A summary from an earlier settings revision still renders (a report of history), and says so.
        record = rendered(later, assessment=summary_for(later, settings_revision=0, assessed_evidence_ids=["rp-ev-1", "rp-ev-2"]))
        self.assertIn(("Settings revision", "Settings changed after this assessment (assessed at settings revision 0, now revision 2). "
                                            "The findings may not match the current settings."), pairs(record, "findings"))
        self.assertNotIn("Settings revision", dict(pairs(rendered(later, assessment=summary_for(later)), "findings")))

    def test_assessment_keys_match_engine_reader(self):
        # report.ASSESSMENT_KEYS copies the engine's summary fields: the engine's registered reader accepts exactly them.
        engine_reader, summary = pc_records.READERS[SUMMARY], summary_for(report_session())
        self.assertEqual(set(summary), report.ASSESSMENT_KEYS)
        self.assertIs(engine_reader(summary), summary)
        for key in sorted(report.ASSESSMENT_KEYS - {"schema", "schema_version"}):
            with self.subTest(engine_summary_without=key):
                self.assertRaises(pc_records.Refusal, engine_reader, {k: v for k, v in summary.items() if k != key})
        self.assertRaises(pc_records.Refusal, engine_reader, dict(summary, extra="x"))

    def test_same_input_same_bytes(self):
        """The same input gives the same bytes for the same Python version, and the input is not changed."""
        session = report_session()
        options = {"assessment": summary_for(session), "packages": [{"manager": "m", "package": "p", "outcome": "o", "restart": "r"}]}
        before = copy.deepcopy((session, options))
        with mock.patch("pc_records.utc_now", return_value=CLOCK):
            first, second = (report.render_session(session, **options) for _ in range(2))
        self.assertEqual(first, second)
        self.assertEqual((session, options), before)
        self.assertEqual(embedded(first)[2]["generated_utc"], CLOCK)

    def test_absent_sections_not_recorded(self):
        _, engine = self.engine()
        state = engine.read_session(engine.create_session(checkpoints=[])["session_id"])
        with mock.patch("pc_records.utc_now", return_value=CLOCK):
            page = report.render_session(state)
            self.assertEqual(report.render_session(state, free_space=[], packages=[], retained=[]), page)
        html, _, record = embedded(page)
        self.assertEqual(re.findall(r"<h2>([^<]*)</h2>", html), TITLES)
        for key in report.SECTIONS:
            with self.subTest(section=key):
                self.assertIn("not recorded", shown(record, key).lower())
        self.assertIn(("Selected folders or drives", "None listed"), pairs(record, "scope"))
        self.assertIn(("Assessment covers", "not recorded"), pairs(record, "scope"))
        self.assertEqual(notes(record, "findings"), ["Assessment summary: not recorded.", report.NO_FINDINGS, report.EVIDENCE_NOTE,
                                                     "Evidence: not recorded."])
        self.assertIn("That does not mean the computer has none", report.NO_FINDINGS)
        self.assertEqual(notes(record, "approvals"), [report.DECISIONS_NOTE, "Plan approval: not recorded.",
                                                      "Agreement to a permanent deletion (irreversible-loss acknowledgment): not recorded.",
                                                      "Standing permission for routine steps (standing policy): not recorded."])
        self.assertEqual(record["scope"][-2:], [["note", "Scope decision: not recorded."], ["note", report.SCOPE_NOTE]])
        for key in ("plan", "reviews", "outcomes", "free_space", "packages", "retained"):
            self.assertEqual(record[key], [["note", "Not recorded."]], key)
        # Empty lists inside a recorded summary show "None listed", and the no-findings caveat stays.
        record = rendered(report_session(), assessment=summary_for(report_session(), findings=[], limitations=[]))
        self.assertIn(("Problems found", "None listed"), pairs(record, "findings"))
        self.assertIn(("Limitations", "None listed"), pairs(record, "findings"))
        self.assertIn(report.NO_FINDINGS, notes(record, "findings"))
        self.assertNotIn(report.NO_FINDINGS, notes(rendered(report_session(), assessment=summary_for(report_session())), "findings"))
        # A real session carries no fictional-demonstration banner.
        self.assertIsNone(rendered(report_session(mode="real"))["banner"])

    def test_attestation_labels(self):
        session = report_session(standing_policy=owner("Fictional standing policy", "fictional-policy", action_kinds=["backup_create"],
                                                       targets=["Fictional component"], max_actions=3, used_actions=1, expires_utc=CLOCK,
                                                       attestation="fictional-other-label\u202e"))
        session["scope_authorization"]["attestation"] = report.ATTESTED
        session["reviews"][0]["attestation"] = report.ATTESTED
        session["reviews"][1]["attestation"] = "fictional-review-label"
        record = rendered(session)
        scope_decision = dict(items(record, "scope")[1])
        self.assertEqual(scope_decision["How this was recorded"], "Written by the assistant from the owner's message (coordinator-attested)")
        self.assertEqual(decision(record, "Plan approval")["How this was recorded"], "Not stated: this record does not say how it was made.")
        self.assertEqual(decision(record, "Standing permission for routine steps (standing policy)")["How this was recorded"],
                         "Unrecognised label: fictional-other-label\\u202e")
        self.assertEqual([dict(item)["How this was recorded"] for item in items(record, "reviews")],
                         ["Written by the assistant from an AI review pass (coordinator-attested)", "Unrecognised label: fictional-review-label"])
        # Only the exact label counts: near misses and a blank label are unrecognised.
        for label, shown_as in ((" ", "Unrecognised label: (blank)"), ("", "Unrecognised label: (blank)"),
                                ("coordinator-attested ", "Unrecognised label: coordinator-attested "),
                                ("xcoordinator-attested", "Unrecognised label: xcoordinator-attested"),
                                ("Coordinator-attested", "Unrecognised label: Coordinator-attested")):
            with self.subTest(label=label):
                session["reviews"][0]["attestation"] = label
                session["scope_authorization"]["attestation"] = label
                record_label = rendered(session)
                self.assertEqual(dict(items(record_label, "reviews")[0])["How this was recorded"], shown_as)
                self.assertEqual(dict(items(record_label, "scope")[1])["How this was recorded"], shown_as)
        del session["reviews"][1]["attestation"]
        self.assertEqual(dict(items(rendered(session), "reviews")[1])["How this was recorded"], report.UNLABELLED)
        # The notes stand whatever the labels say: the short form under the scope decision, the full note first under
        # Approvals, and the reviews note first under Reviews whenever a review exists.
        for labelled in (record, rendered(report_session(scope_authorization=None, approval=None))):
            self.assertEqual(labelled["scope"][-1], ["note", report.SCOPE_NOTE])
            self.assertEqual(labelled["approvals"][0], ["note", report.DECISIONS_NOTE])
            self.assertEqual(labelled["reviews"][0], ["note", report.REVIEWS_NOTE])
        self.assertEqual(rendered(report_session(reviews=[]))["reviews"], [["note", "Not recorded."]])
        self.assertEqual(report.DECISIONS_NOTE, "The AI assistant wrote these entries, quoting the owner's messages in the chat or terminal. "
                                                "This page cannot show who typed those messages. To confirm a decision, find the quoted words "
                                                "in the conversation history.")
        self.assertEqual(report.SCOPE_NOTE, "Written by the AI assistant from the owner's message; see the note under Approvals.")
        self.assertEqual(report.REVIEWS_NOTE, "Reviews are checks of the plan made by AI assistant passes, not by a person or an outside company. "
                                              "'Approved' here means that pass found no reason to stop. It is not the owner's approval.")
        for text in (report.DECISIONS_NOTE, report.SCOPE_NOTE, report.REVIEWS_NOTE, report.OWNER_ATTESTED, report.REVIEW_ATTESTED, report.UNLABELLED):
            self.assertIsNone(re.search(r"(?i)proves? (that )?(a|the) (human|person|owner)|independent|verified by", text))

    def test_every_owner_decision_is_shown(self):
        plan_sha256 = report_session()["plan"]["sha256"]
        operation = dict(report_session()["operations"][OPERATION], restart_decision=owner(
            "Restart later, fictionally.", "fictional-restart", choice="defer", operation_id=OPERATION, plan_sha256=plan_sha256,
            not_before_utc="2026-01-02T05:00:00Z"))

        def at(seconds, quote, message_id, **extra):
            return dict(owner(quote, message_id, **extra), recorded_utc=f"2026-01-02T03:04:{seconds:02d}Z")

        session = report_session(
            irreversible_ack=owner("I accept the fictional loss.", "fictional-ack", type="permanent_data_loss", plan_sha256=plan_sha256,
                                   action_ids=["fictional-action"], scope_sha256="b" * 64, acknowledge_irreversible_loss=True),
            standing_policy=owner("Allow fictional routine steps.", "fictional-policy", action_kinds=["backup_create"], targets=["Fictional A"],
                                  action_bindings=[], max_actions=3, used_actions=1, expires_utc=CLOCK, scope_sha256="b" * 64),
            schedule=owner("Start at the fictional time.", "fictional-schedule", proposal={"when_utc": CLOCK, "description": "Fictional"},
                           creates_os_schedule=False, decision_ids=["fictional-schedule"], activation=None, ready_for_trigger=True),
            operations={OPERATION: operation},
            pending={
                "checkpoint-plan": {"pending_id": "checkpoint-plan", "kind": "checkpoint", "checkpoint": "plan", "action_id": None,
                                    "created_utc": CLOCK, "resolved": True, "settings_revision": 0,
                                    "owner_instruction": at(1, "Continue, fictionally.", "fictional-continue")},
                "checkpoint-open": {"pending_id": "checkpoint-open", "kind": "checkpoint", "checkpoint": "finish", "action_id": None,
                                    "created_utc": CLOCK, "resolved": False, "settings_revision": 0},
                "reconcile-op": {"pending_id": "reconcile-op", "kind": "reconciliation", "operation_id": OPERATION, "created_utc": CLOCK,
                                 "resolved": True, "settings_revision": 0, "owner_instruction": at(2, "Make a new plan.", "fictional-replan")},
                "consent-a": {"pending_id": "consent-a", "kind": "protected_consent", "resolved": True,
                              "record": at(3, "I handled the prompt.", "fictional-consent", plan_sha256=plan_sha256, action_id="fictional-action",
                                           evidence_id="rp-ev-1")},
                "other-x": {"pending_id": "other-x", "kind": "fictional‮kind", "resolved": True,
                            "owner_instruction": at(4, "A fictional later decision kind.", "fictional-other")},
                "assessment-finish-x": {"pending_id": "assessment-finish-x", "kind": "assessment_finish", "resolved": True,
                                        "record": {"summary_evidence_id": "rp-ev-1", "summary_sha256": "c" * 64, "verification_evidence_ids": [],
                                                   "owner_instruction": at(4, "Finish the fictional assessment.", "fictional-finish")}},
                "checkpoint-step": {"pending_id": "checkpoint-step", "kind": "checkpoint", "checkpoint": "before_action",
                                    "action_id": "fictional-action", "created_utc": CLOCK, "resolved": True, "settings_revision": 0,
                                    "owner_instruction": at(5, "Go ahead with the step.", "fictional-step")},
                "restart-op": {"pending_id": "restart-op", "kind": "restart", "operation_id": OPERATION, "resolved": False, "created_utc": CLOCK}})
        # As read from disk: canonical JSON sorts the pending keys, which is not the order the owner decided in.
        session = pc_records.decode_strict(pc_records.encoded(session))
        self.assertEqual(list(session["pending"])[:3], ["assessment-finish-x", "checkpoint-open", "checkpoint-plan"])
        record = rendered(session)
        names = [dict(item)["Decision"] for item in items(record, "approvals")]
        self.assertEqual(names, ["Plan approval", "Agreement to a permanent deletion (irreversible-loss acknowledgment)",
                                 "Standing permission for routine steps (standing policy)", "Go-ahead at a checkpoint",
                                 "Choice after an unfinished step (reconciliation)",
                                 "Operating-system permission prompt handled (protected consent)", "Assessment closed (assessment completion)",
                                 "Other owner decision (fictional\\u202ekind)", "Go-ahead at a checkpoint", "Schedule decision", "Restart decision"])
        ack = decision(record, names[1])
        self.assertEqual((ack["Quoted instruction"], ack["Message id"], ack["Actions it covers"], ack["Plan fingerprint"]),
                         ("I accept the fictional loss.", "fictional-ack", "fictional-action", report.SAME_PLAN))
        policy = decision(record, names[2])
        self.assertEqual((policy["Kinds of step allowed"], policy["Targets"], policy["Steps allowed"], policy["Steps used"], policy["Expires (UTC)"]),
                         ("backup_create", "Fictional A", "3", "1", CLOCK))
        checkpoints = [Shown(item) for item in items(record, "approvals") if ("Decision", names[3]) in item]
        self.assertEqual([(row["Checkpoint"], row["Action"], row["Message id"]) for row in checkpoints],
                         [("plan", "none (whole session)", "fictional-continue"), ("before_action", "fictional-action", "fictional-step")])
        self.assertEqual(decision(record, names[4])["Operation"], OPERATION)
        self.assertEqual((decision(record, names[5])["Action"], decision(record, names[5])["Plan fingerprint"]), ("fictional-action", report.SAME_PLAN))
        self.assertEqual(decision(record, names[6])["Summary evidence"], "rp-ev-1")
        self.assertEqual(decision(record, names[7])["Message id"], "fictional-other")
        restart = decision(record, "Restart decision")
        self.assertEqual(decision(record, "Schedule decision")["Scheduled for (UTC)"], CLOCK)
        self.assertEqual((restart["Choice"], restart["Operation"], restart["Not before (UTC)"], restart["Plan fingerprint"]),
                         ("Restart later (defer)", OPERATION, "2026-01-02T05:00:00Z", report.SAME_PLAN))
        names = [name for name in names if name != "Go-ahead at a checkpoint"]
        for name in names:
            with self.subTest(decision=name):
                self.assertEqual(decision(record, name)["How this was recorded"], report.UNLABELLED)
                self.assertEqual(decision(record, name)["Given in"], "the chat (current_owner_chat)")
        self.assertNotIn("Plan approval: not recorded.", notes(record, "approvals"))
        # A missing main record keeps its place, so the reader sees which decision is absent.
        record = rendered(dict(session, approval=None, standing_policy=None, pending={}, schedule=None, operations=report_session()["operations"]))
        self.assertEqual([content if kind == "note" else dict(content)["Decision"] for kind, content in record["approvals"]],
                         [report.DECISIONS_NOTE, "Plan approval: not recorded.", names[1],
                          "Standing permission for routine steps (standing policy): not recorded."])

    def test_outcomes_without_a_result(self):
        session = report_session()
        started = dict(session["operations"][OPERATION], outcome=None, finished_utc=None, summary="Waiting for an actual operation outcome")
        earlier = dict(started, operation_id="operation-" + "f" * 32, action_id="fictional-earlier", started_utc="2026-01-02T03:04:04Z",
                       outcome="failed", finished_utc="2026-01-02T03:04:05Z",
                       resolution={"kind": "replan_required", "evidence_ids": [], "recorded_utc": CLOCK, "owner_message_id": "fictional-replan"})
        session["plan"]["document"]["actions"].append(dict(session["plan"]["document"]["actions"][0], action_id="fictional-later"))
        session["operations"] = {OPERATION: started, earlier["operation_id"]: earlier}
        record = rendered(session)
        first, second = (Shown(item) for item in items(record, "outcomes"))
        self.assertEqual((first["Action"], first["Result"], first["Resolution"], first["Resolution recorded (UTC)"]),
                         ("fictional-earlier", "failed", "A new plan is needed before anything else changes (replan_required)", CLOCK))
        self.assertEqual((second["Result"], second["Finished (UTC)"], second["Resolution"], second["Resolution recorded (UTC)"]),
                         (report.NO_RESULT, "not recorded", "not recorded", None))
        self.assertTrue(report.NO_RESULT.startswith("No result recorded: this step started, but no result had been recorded"))
        self.assertTrue(report.NO_RESULT.endswith(" Ask the assistant (PatchCairn: status) before starting anything else on this computer."))
        self.assertNotIn("in progress", shown(record, "outcomes"))
        self.assertEqual(record["outcomes"][0], ["note", report.OUTCOMES_NOTE])
        self.assertEqual(record["outcomes"][-1], ["note", "Planned steps not started: fictional-later. They may still be waiting to run, or may "
                                                          "have been skipped."])
        self.assertTrue(report.OUTCOMES_NOTE.endswith("ask the assistant what changed and what was kept (PatchCairn: status, then "
                                                      "PatchCairn: resolve)."))
        # The note appears only when a step failed, is partial or unknown, or has no result.
        for outcome, shown_note in (("succeeded", False), ("failed", True), ("partial", True), ("unknown", True), (None, True)):
            with self.subTest(outcome=outcome):
                single = report_session()
                single["operations"][OPERATION]["outcome"] = outcome
                self.assertEqual(report.OUTCOMES_NOTE in notes(rendered(single), "outcomes"), shown_note)
        effects = dict(earlier, resolution=dict(earlier["resolution"], kind="effects_accounted"))
        self.assertEqual(Shown(items(rendered(dict(session, operations={OPERATION: effects})), "outcomes")[0])["Resolution"],
                         "What changed was accounted for after the session stopped (effects_accounted)")
        other = dict(earlier, resolution=dict(earlier["resolution"], kind="fictional‮kind"))
        self.assertEqual(Shown(items(rendered(dict(session, operations={OPERATION: other})), "outcomes")[0])["Resolution"], "fictional\\u202ekind")

    def test_restart_pending(self):
        session = report_session(platform="windows")
        plan_sha256 = session["plan"]["sha256"]
        pending = {"evidence_id": "rp-ev-1", "sha256": "a" * 64, "before_boot_evidence_id": "rp-ev-1", "before_boot_sha256": "a" * 64,
                   "original_exit_code": 3010, "recorded_utc": CLOCK, "decision_ids": []}
        waiting = dict(session["operations"][OPERATION], outcome=None, finished_utc=None, restart_pending=pending)
        row = Shown(items(rendered(dict(session, operations={OPERATION: waiting})), "outcomes")[0])
        self.assertEqual((row["Result"], row["Restart decision"]), (report.RESTART_WAITING, report.RESTART_UNDECIDED))
        self.assertEqual(report.RESTART_WAITING, "Waiting for a restart: the installer reported that the computer must restart to finish this "
                                                 "step (code 3010). The step stays unfinished until the computer has restarted and the result "
                                                 "is checked.")
        self.assertEqual(report.RESTART_UNDECIDED, "Not decided yet. Tell the assistant whether to restart now or later (PatchCairn: resolve).")
        self.assertIn(report.OUTCOMES_NOTE, notes(rendered(dict(session, operations={OPERATION: dict(waiting, outcome="unknown")})), "outcomes"))
        for choice, words in (("defer", "Restart later (defer)"), ("authorize", "Restart allowed; you restart the computer yourself (authorize)"),
                              ("fictional", "fictional")):
            with self.subTest(choice=choice):
                decided = dict(waiting, restart_decision=owner("Fictional restart choice.", "fictional-restart", choice=choice,
                                                               operation_id=OPERATION, plan_sha256=plan_sha256, not_before_utc=CLOCK))
                record = rendered(dict(session, operations={OPERATION: decided}))
                row = Shown(items(record, "outcomes")[0])
                self.assertEqual((row["Result"], row["Restart decision"]), (report.RESTART_WAITING, words))
                entry = decision(record, "Restart decision")
                self.assertEqual((entry["Choice"], entry["Not before (UTC)"], entry["Plan fingerprint"]), (words, CLOCK, report.SAME_PLAN))
        # Once a boot is checked the step is no longer waiting; its recorded result shows again.
        checked = dict(decided, restart_verification={"evidence_id": "rp-ev-1", "sha256": "a" * 64, "recorded_utc": CLOCK,
                                                      "boot_observed": True, "behavior_passed": True})
        row = Shown(items(rendered(dict(session, operations={OPERATION: checked})), "outcomes")[0])
        self.assertEqual(row["Result"], report.NO_RESULT)
        unchecked = dict(checked, restart_verification=dict(checked["restart_verification"], boot_observed=False))
        self.assertEqual(Shown(items(rendered(dict(session, operations={OPERATION: unchecked})), "outcomes")[0])["Result"], report.RESTART_WAITING)
        self.assertIsNone(Shown(items(rendered(session), "outcomes")[0])["Restart decision"])

    def test_replanned_outcomes(self):
        session = report_session()
        current = session["plan"]["sha256"]
        earlier = dict(session["operations"][OPERATION], operation_id="operation-" + "e" * 32, action_id="fictional-old", plan_sha256="e" * 64,
                       started_utc="2026-01-02T03:04:01Z", authorization={"kind": "standing_policy", "message_id": "fictional-policy",
                                                                          "plan_sha256": "e" * 64, "action_id": "fictional-old"})
        now = dict(session["operations"][OPERATION], authorization={"kind": "exact_plan", "message_id": "fictional-plan", "plan_sha256": current,
                                                                   "action_id": "fictional-action"})
        session = pc_records.decode_strict(pc_records.encoded(dict(session, operations={earlier["operation_id"]: earlier, OPERATION: now})))
        record = rendered(session)
        rows = [Shown(item) for item in items(record, "outcomes")]
        self.assertEqual([(row["Action"], row["Plan fingerprint"], row["Authorized by"]) for row in rows],
                         [("fictional-old", "An earlier plan (fingerprint begins eeeeeeee)", "the standing permission (message fictional-policy)"),
                          ("fictional-action", report.SAME_PLAN, "the plan approval (message fictional-plan)")])
        self.assertEqual(notes(record, "outcomes"), [report.EARLIER_PLAN_NOTE])
        self.assertEqual(report.EARLIER_PLAN_NOTE, "Some steps belong to an earlier plan in this session. That plan, its reviews and its approval "
                                                   "were replaced by the plan above, so this page does not show them; each step still shows who "
                                                   "authorized it.")
        # Without a current plan every step belongs to an earlier one; other kinds and an empty record are shown as they are.
        record = rendered(dict(session, plan=None, approval=None, reviews=[], operations={
            OPERATION: dict(now, authorization={"kind": "fictional‮kind"}), "o": dict(earlier, authorization={})}))
        self.assertEqual(notes(record, "outcomes"), [report.EARLIER_PLAN_NOTE])
        self.assertEqual([(row["Plan fingerprint"], row["Authorized by"]) for row in (Shown(item) for item in items(record, "outcomes"))],
                         [("An earlier plan (fingerprint begins eeeeeeee)", "not recorded"),
                          ("An earlier plan (fingerprint begins " + current[:8] + ")", "fictional\\u202ekind")])
        self.assertNotIn(report.EARLIER_PLAN_NOTE, notes(rendered(report_session()), "outcomes"))

    def test_free_space_and_sizes(self):
        def shown_row(**values):
            row = dict({"volume": "D:\\", "before_bytes": None, "after_bytes": None, "expected_net_bytes": None}, **values)
            return dict(items(rendered(report_session(platform="windows"), free_space=[row]), "free_space")[0])

        more = shown_row(before_bytes=100_000_000_000, after_bytes=111_811_160_064, expected_net_bytes=11_000_000_000)
        self.assertEqual(more, {"Drive": "D:\\", "Free space before": "about 100.0 GB (100,000,000,000 bytes)",
                                "Free space after": "about 111.8 GB (111,811,160,064 bytes)",
                                "Measured change": "about 11.8 GB more free space (11,811,160,064 bytes)",
                                "Expected change (estimate)": "about 11.0 GB more free space (11,000,000,000 bytes)"})
        less = shown_row(before_bytes=10_000_000_000, after_bytes=5_300_000_000, expected_net_bytes=-999_960_000)
        self.assertEqual((less["Measured change"], less["Expected change (estimate)"]),
                         ("about 4.7 GB less free space (4,700,000,000 bytes)", "about 1.0 GB less free space (999,960,000 bytes)"))
        same = shown_row(before_bytes=5, after_bytes=5, expected_net_bytes=0)
        self.assertEqual((same["Free space before"], same["Measured change"], same["Expected change (estimate)"]), ("5 bytes", "No change", "No change"))
        one = shown_row(before_bytes=1, after_bytes=2, expected_net_bytes=-1)
        self.assertEqual((one["Free space before"], one["Measured change"], one["Expected change (estimate)"]),
                         ("1 byte", "1 byte more free space", "1 byte less free space"))
        # A missing measurement gives no computed change.
        for values in ({"after_bytes": 1000}, {"before_bytes": 1000}, {}):
            with self.subTest(measured=values):
                row = shown_row(**values)
                self.assertEqual(row["Measured change"], "not recorded")
                self.assertEqual(row["Expected change (estimate)"], "not recorded")
        self.assertEqual(shown_row(before_bytes=950_000, after_bytes=0)["Free space before"], "about 950.0 KB (950,000 bytes)")
        # Three short notes; the File Explorer sentence only for a Windows session.
        row = [{"volume": "D:", "before_bytes": 1, "after_bytes": 1, "expected_net_bytes": None}]
        measured, estimate, units = report.FREE_SPACE_NOTES
        self.assertEqual(notes(rendered(report_session(), free_space=row), "free_space"), [measured, estimate, "1 GB here is 1,000,000,000 bytes."])
        self.assertEqual(notes(rendered(report_session(platform="windows"), free_space=row), "free_space"),
                         [measured, estimate, "1 GB here is 1,000,000,000 bytes. Windows File Explorer counts 1,073,741,824 bytes per GB, so "
                                              "it shows a slightly smaller number."])
        self.assertTrue(measured.endswith("such as downloads or system updates."))
        self.assertTrue(estimate.startswith("The expected change is PatchCairn's estimate") and "Quarantine keeps files on the same drive" in estimate)
        retained = rendered(report_session(), retained=[{"kind": "backup", "location": "work/b", "bytes": 3_210_000_000},
                                                        {"kind": "quarantine", "location": "work/q", "bytes": None}])
        self.assertEqual([dict(item)["Size"] for item in items(retained, "retained")], ["about 3.2 GB (3,210,000,000 bytes)", "not recorded"])

    def test_read_report_layout_rules(self):
        with mock.patch("pc_records.utc_now", return_value=CLOCK):
            good = rendered(report_session())
        read = pc_records.READERS[report.SCHEMA]
        self.assertIs(read(good), good)
        bad = {
            "extra key": dict(good, extra=[["note", "x"]]),
            "missing section": {key: value for key, value in good.items() if key != "packages"},
            "empty section": dict(good, packages=[]),
            "section not a list": dict(good, packages={"note": "x"}),
            "unknown block kind": dict(good, packages=[["script", "x"]]),
            "empty note": dict(good, packages=[["note", " "]]),
            "block of three": dict(good, packages=[["note", "x", "y"]]),
            "bad header pair": dict(good, header=[["fields", [["Session"]]]]),
            "header value not text": dict(good, header=[["fields", [["Session", 1]]]]),
            "empty fields": dict(good, plan=[["fields", []]]),
            "banner not text": dict(good, banner=1),
            "empty banner": dict(good, banner=""),
            "title missing text": dict(good, title=""),
        }
        for name, record in bad.items():
            with self.subTest(record=name):
                self.refused(lambda: read(record), "report-record")
        self.refused(lambda: read(dict(good, generated_utc="yesterday")), "utc-time")
        self.refused(lambda: read(dict(good, schema_version="1")), "schema-version")

    def test_report_record_golden_bytes(self):
        with mock.patch("pc_records.utc_now", return_value=CLOCK):
            _, block, record = embedded(report.render_session(report_session()))
        data = pc_records.encoded(record)
        self.assertEqual(block, data.decode("ascii").replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))
        self.assertEqual(hashlib.sha256(data).hexdigest(), GOLDEN_SHA256)


if __name__ == "__main__":
    unittest.main()
