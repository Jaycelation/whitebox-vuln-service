"""Tests for the security-audit skill handoff: export, schema conformance, and ingest.

The exported records are checked against the vendored copy of the skill's
`report-schema.json` by a small interpreter for the keywords that schema uses, so a
drift in either direction fails here. The skill's own `validate-findings.cjs` is the
authoritative check and runs in CI; see third_party/security-audit-skill/README.md.

Discoverable by the project's CI (`python -m unittest discover -s tests`) and runnable
directly (`DATA_DIR=$(mktemp -d) python tests/test_audit_phase.py`).
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="whitebox-audit-test-"))

from fastapi.testclient import TestClient  # noqa: E402

import app as service  # noqa: E402
import whitebox_audit as audit  # noqa: E402
import whitebox_evidence as evidence  # noqa: E402

SCHEMA = json.loads((Path(__file__).resolve().parent.parent / "third_party" / "security-audit-skill"
                     / "report-schema.json").read_text("utf-8"))
SCAN_ID = "c" * 32
NOWHERE = Path("/nonexistent-source-root")


# --- An independent reading of the schema -------------------------------------------------

def has_visible_content(text: str) -> bool:
    """The schema's `visibleContent`: real characters, no control or format code points."""
    if not isinstance(text, str) or not text.strip():
        return False
    categories = [unicodedata.category(character) for character in text]
    if any(category in {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"} for category in categories):
        return False
    return any(category != "Zs" for category in categories)


def check(instance: Any, schema: dict[str, Any], path: str = "") -> list[str]:
    errors: list[str] = []
    if "oneOf" in schema:
        matches = [option for option in schema["oneOf"] if not check(instance, option, path)]
        if len(matches) != 1:
            return [f"{path or '/'}: matched {len(matches)} of {len(schema['oneOf'])} record variants"]
        return []
    expected = schema.get("type")
    if expected == "array" and not isinstance(instance, list):
        return [f"{path}: expected an array"]
    if expected == "object" and not isinstance(instance, dict):
        return [f"{path}: expected an object"]
    if expected == "string" and not isinstance(instance, str):
        return [f"{path}: expected a string"]
    if expected == "integer" and not isinstance(instance, int):
        return [f"{path}: expected an integer"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']}")
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], instance):
            errors.append(f"{path}: {instance!r} does not match {schema['pattern']}")
        if schema.get("visibleContent") and not has_visible_content(instance):
            errors.append(f"{path}: {instance!r} has no visible content")
    if isinstance(instance, int) and "minimum" in schema and instance < schema["minimum"]:
        errors.append(f"{path}: below {schema['minimum']}")
    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if schema.get("uniqueItems") and len(instance) != len({json.dumps(item, sort_keys=True) for item in instance}):
            errors.append(f"{path}: items are not unique")
        for index, item in enumerate(instance):
            errors += check(item, schema.get("items", {}), f"{path}[{index}]")
    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in instance:
                errors.append(f"{path}: missing {name!r}")
        if schema.get("additionalProperties") is False:
            for name in instance:
                if name not in properties:
                    errors.append(f"{path}: unexpected {name!r}")
        for name, value in instance.items():
            if name in properties:
                errors += check(value, properties[name], f"{path}.{name}")
    return errors


# --- Findings -----------------------------------------------------------------------------

def traced(line: int = 20, vuln_class: str = "command-injection", confidence: str = "high",
           cwe: str = "CWE-78") -> dict[str, Any]:
    finding = service.make_finding(
        tool="dataflow", category="sast", severity="critical",
        title=f"Command injection: request input reaches an OS command", message="views.py:20 → helpers.py:3",
        path="helpers.py", line=3, rule_id=f"dataflow.python.{vuln_class}", confidence=confidence,
        source_root=NOWHERE,
    )
    finding["cwe"] = cwe
    finding["trace"] = [
        {"kind": "source", "path": "views.py", "line": line, "scope": "ping()", "detail": "Request input"},
        {"kind": "call", "path": "views.py", "line": line + 1, "scope": "views.py", "detail": "Passed to run()"},
        {"kind": "parameter", "path": "helpers.py", "line": 1, "scope": "run()",
         "detail": "Parameter host of run() reaches the next step"},
        {"kind": "sink", "path": "helpers.py", "line": 3, "scope": "helpers.py", "detail": "Used as an OS command"},
    ]
    finding["cvss"] = evidence.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "static-trace", [])
    finding["evidence"] = {"level": "reachable", "items": ["A trace reaches the sink."],
                           "automatic": {"level": "reachable", "items": ["A trace reaches the sink."],
                                         "cvss": finding["cvss"]}}
    finding["match_key"] = service.finding_match_key(finding)
    return finding


class ExportTests(unittest.TestCase):
    def test_a_traced_finding_matches_the_schema(self) -> None:
        records = audit.export([traced()])
        self.assertEqual(check(records, SCHEMA), [])
        self.assertEqual(len(records), 1)

    def test_trace_kinds_use_the_skill_vocabulary(self) -> None:
        record = audit.export([traced()])[0]
        self.assertEqual([step["kind"] for step in record["trace"]],
                         ["entrypoint", "propagation", "propagation", "sink"])
        self.assertEqual((record["trace"][0]["file"], record["trace"][0]["scope"]), ("views.py", "ping()"))

    def test_nothing_leaves_as_confirmed(self) -> None:
        """A static trace is not a demonstrated vulnerability, whoever triaged it."""
        reviewed = traced()
        reviewed["triage_status"] = "confirmed"
        reviewed["triage_decided_by"] = "manual"
        record = audit.export([reviewed])[0]
        self.assertEqual(record["verdict"], "needs_validation")
        self.assertTrue(any("no sandboxed reproduction" in blocker for blocker in record["blockers"]))
        self.assertTrue(any("never executed" in blocker for blocker in record["blockers"]))

    def test_a_false_positive_leaves_as_rejected_with_its_control(self) -> None:
        dismissed = traced()
        dismissed["triage_status"] = "false_positive"
        dismissed["agent_review"] = {"verdict": "false_positive",
                                     "blocking_controls": ["shlex.quote at helpers.py:2"]}
        record = audit.export([dismissed])[0]
        self.assertEqual((record["verdict"], record["reason"]), ("rejected", "shlex.quote at helpers.py:2"))
        self.assertEqual(check([record], SCHEMA), [])

    def test_untraced_findings_are_not_exported(self) -> None:
        secret = service.make_finding(tool="gitleaks", category="secret", severity="high", title="AWS key",
                                      path="conf/.env", line=2, rule_id="aws-access-key", source_root=NOWHERE)
        dependency = service.make_finding(tool="trivy", category="dependency", severity="high", title="CVE-2020-1",
                                          path="requirements.txt", rule_id="CVE-2020-1", source_root=NOWHERE)
        self.assertEqual(audit.export([secret, dependency]), [])

    def test_steps_the_analysis_could_not_place_are_dropped(self) -> None:
        partial = traced()
        partial["trace"].insert(1, {"kind": "call", "path": "views.py", "line": None, "detail": "Unplaced"})
        partial["trace"].insert(1, {"kind": "mystery", "path": "views.py", "line": 9, "detail": "Unknown kind"})
        record = audit.export([partial])[0]
        self.assertEqual(len(record["trace"]), 4)
        self.assertEqual(check([record], SCHEMA), [])

    def test_duplicates_and_repeated_fingerprints_are_dropped(self) -> None:
        duplicate = traced()
        duplicate["fp_check"] = {"verdict": "duplicate", "duplicate_of": "a" * 24}
        twin = traced()  # the same match_key, so the same fingerprint
        self.assertEqual(len(audit.export([traced(), duplicate, twin])), 1)

    def test_a_name_matched_flow_says_so(self) -> None:
        record = audit.export([traced(confidence="medium")])[0]
        self.assertTrue(any("matched by name" in blocker for blocker in record["blockers"]))

    def test_the_validation_plan_names_both_ends_and_a_payload(self) -> None:
        plan = audit.export([traced()])[0]["validation_plan"]
        self.assertIn("views.py:20", plan["local"])
        self.assertIn("helpers.py:3", plan["local"])
        self.assertIn("; id", plan["local"])
        self.assertIn("reachable", plan["deployment"])

    def test_records_are_sorted_by_fingerprint(self) -> None:
        """The skill's validator rejects records in any other order."""
        low = traced(vuln_class="open-redirect", cwe="CWE-601")
        low["cvss"] = evidence.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "static-trace", [])
        records = audit.export([low, traced()])
        self.assertEqual([record["fingerprint"] for record in records],
                         sorted([audit.fingerprint(traced()), audit.fingerprint(low)]))

    def test_the_scored_copy_of_a_repeated_fingerprint_wins(self) -> None:
        unscored = traced()
        unscored["cvss"] = None
        unscored["title"] = "Unscored copy"
        self.assertEqual(audit.export([unscored, traced()])[0]["title"], traced()["title"])

    def test_provenance_makes_no_coverage_claim(self) -> None:
        records = audit.export([traced()])
        note = audit.provenance(SCAN_ID, "demo", records)
        self.assertEqual(note["records"], {"confirmed": 0, "needs_validation": 1, "rejected": 0})
        self.assertIn("no coverage-ledger.json", note["coverage_claim"])
        self.assertIn("nothing here was executed", note["contents"])


# --- Ingest -------------------------------------------------------------------------------

def record_for(finding: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    item = {
        "verdict": "confirmed",
        "fingerprint": audit.fingerprint(finding),
        "title": "Command injection in the ping handler",
        "description": "An unauthenticated request runs a shell command.",
        "root_cause": "The host parameter is interpolated into a shell string at helpers.py:3.",
        "severity": {"likelihood": {"score": "high", "reason": "Reachable without a credential."},
                     "impact": {"score": "critical", "reason": "Arbitrary command execution."},
                     "overall_severity": "critical"},
        "confidence": {"score": "high", "reason": "Reproduced in the sandbox."},
        "execution": {"attacker_perspective": "An unauthenticated client.", "payloads": ["127.0.0.1; id"],
                      "instructions": ["POST /ping with host=127.0.0.1; id"],
                      "observed_result": "The id output appeared in the response body."},
        "remediation": {"strategy": "Pass the host as an argument list instead of a shell string."},
    }
    item.update(overrides)
    return item


class IngestTests(unittest.TestCase):
    def test_a_confirmed_record_becomes_an_agent_decision(self) -> None:
        finding = traced()
        self.assertTrue(audit.apply_record(finding, record_for(finding), "2026-10-25T00:00:00+00:00"))
        self.assertEqual((finding["triage_status"], finding["triage_decided_by"]), ("confirmed", "agent"))
        self.assertEqual(finding["triage_source"], "security-audit-skill")
        self.assertIn("security-audit skill:", finding["triage_note"])
        self.assertEqual(finding["evidence"]["level"], "confirmed")
        self.assertIn("A security-audit skill run confirmed this finding.", finding["evidence"]["items"])

    def test_a_confirmed_record_without_a_reproduction_is_downgraded(self) -> None:
        finding = traced()
        item = record_for(finding)
        item["execution"] = {"attacker_perspective": "x", "payloads": ["x"], "instructions": ["x"],
                             "observed_result": ""}
        self.assertFalse(audit.apply_record(finding, item, "2026-10-25T00:00:00+00:00"))
        self.assertEqual(finding["triage_status"], "needs_review")
        self.assertEqual(finding["audit_review"]["verdict"], "needs_validation")
        self.assertIn("observed result", finding["audit_review"]["blockers"][0])

    def test_a_rejected_record_becomes_a_false_positive(self) -> None:
        finding = traced()
        item = record_for(finding, verdict="rejected", reason="shlex.quote at helpers.py:2 escapes the value.")
        self.assertTrue(audit.apply_record(finding, item, "2026-10-25T00:00:00+00:00"))
        self.assertEqual(finding["triage_status"], "false_positive")
        self.assertIsNone(finding["cvss"])

    def test_a_rejected_record_without_a_reason_is_downgraded(self) -> None:
        finding = traced()
        self.assertFalse(audit.apply_record(finding, record_for(finding, verdict="rejected"), "now"))
        self.assertEqual(finding["audit_review"]["verdict"], "needs_validation")

    def test_a_needs_validation_record_is_stored_without_a_decision(self) -> None:
        finding = traced()
        item = record_for(finding, verdict="needs_validation", blockers=["No sandbox was available."],
                          validation_plan={"local": "Drive the handler in a sandbox."})
        self.assertFalse(audit.apply_record(finding, item, "now"))
        self.assertEqual(finding["triage_status"], "needs_review")
        self.assertEqual(finding["audit_review"]["blockers"], ["No sandbox was available."])

    def test_a_record_never_sets_a_cvss_vector_of_its_own(self) -> None:
        """The record carries a qualitative severity; the service keeps its own scoring."""
        finding = traced()
        audit.apply_record(finding, record_for(finding), "now")
        self.assertIsNone(finding["triage_cvss_vector"])
        self.assertEqual(finding["cvss"]["basis"], "static-trace")

    def test_malformed_input_is_refused_with_reasons(self) -> None:
        self.assertEqual(audit.read_records({"findings": []})[0], [])
        self.assertEqual(audit.read_records([{"verdict": "confirmed"}]), ([], ["Record 0 has no usable fingerprint."]))
        records, errors = audit.read_records([
            {"verdict": "nonsense", "fingerprint": "whitebox:a"},
            {"verdict": "confirmed", "fingerprint": "whitebox:b"},
            {"verdict": "rejected", "fingerprint": "whitebox:b"},
        ])
        self.assertEqual([record["fingerprint"] for record in records], ["whitebox:b"])
        self.assertEqual(len(errors), 2)

    def test_more_records_than_the_cap_are_refused(self) -> None:
        many = [{"verdict": "confirmed", "fingerprint": f"whitebox:{index}"} for index in range(audit.MAX_RECORDS + 1)]
        self.assertEqual(audit.read_records(many)[0], [])


# --- Endpoints ----------------------------------------------------------------------------

class AuditEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        findings = [traced(), service.make_finding(tool="gitleaks", category="secret", severity="high",
                                                   title="AWS key", path="conf/.env", line=2,
                                                   rule_id="aws-access-key", source_root=NOWHERE)]
        directory = service.job_dir(SCAN_ID)
        directory.mkdir(parents=True, exist_ok=True)
        report = {"scan_id": SCAN_ID, "summary": service.summarize(findings, []), "scanners": [], "findings": findings}
        (directory / "report.json").write_text(json.dumps(report), "utf-8")
        service.initialize_storage()
        now = service.utc_now()
        with service.connect_db() as db:
            db.execute("DELETE FROM scans WHERE id = ?", (SCAN_ID,))
            db.execute("DELETE FROM triage_decisions WHERE project = ?", ("audit-test",))
            db.execute(
                "INSERT INTO scans (id, name, status, created_at, updated_at, finished_at, scanners_json, upload_bytes) "
                "VALUES (?, ?, 'completed', ?, ?, ?, ?, 0)",
                (SCAN_ID, "audit-test", now, now, now, json.dumps(["dataflow", "gitleaks"])),
            )
        self.client = TestClient(service.app)
        self.fingerprint = audit.fingerprint(traced())

    def test_the_export_endpoint_serves_schema_valid_records(self) -> None:
        records = self.client.get(f"/api/scans/{SCAN_ID}/report.findings.json").json()
        self.assertEqual(check(records, SCHEMA), [])
        self.assertEqual([record["fingerprint"] for record in records], [self.fingerprint])

    def test_the_handoff_endpoint_carries_its_provenance(self) -> None:
        body = self.client.get(f"/api/scans/{SCAN_ID}/audit/handoff").json()
        self.assertEqual(body["provenance"]["project"], "audit-test")
        self.assertEqual(body["provenance"]["records"]["needs_validation"], 1)

    def test_ingesting_a_run_records_decisions_and_updates_the_summary(self) -> None:
        self.assertEqual(self.client.get(f"/api/scans/{SCAN_ID}/audit").json(), {"status": "none"})
        item = record_for(traced())
        body = self.client.post(f"/api/scans/{SCAN_ID}/audit", json={"records": [item]}).json()
        self.assertEqual(body["audit"]["records"], {"confirmed": 1, "needs_validation": 0, "rejected": 0})
        self.assertEqual(body["summary"]["triage"]["confirmed"], 1)
        report = self.client.get(f"/api/scans/{SCAN_ID}/report").json()
        finding = report["findings"][0]
        self.assertEqual(finding["triage_status"], "confirmed")
        self.assertEqual(finding["audit_review"]["severity"], "critical")
        self.assertEqual(self.client.get(f"/api/scans/{SCAN_ID}/audit").json()["records"]["confirmed"], 1)

    def test_a_decision_carries_to_the_next_scan_of_the_project(self) -> None:
        self.client.post(f"/api/scans/{SCAN_ID}/audit",
                         json={"records": [record_for(traced())]})
        later = [traced()]
        service.check_false_positives(later, NOWHERE)
        service.apply_triage_decisions("audit-test", later)
        self.assertEqual(later[0]["triage_status"], "confirmed")
        self.assertEqual(later[0]["triage_source"], "earlier_scan")

    def test_a_reviewers_decision_is_never_overridden(self) -> None:
        finding_id = self.client.get(f"/api/scans/{SCAN_ID}/report").json()["findings"][0]["id"]
        self.client.patch(f"/api/scans/{SCAN_ID}/findings/{finding_id}",
                          json={"status": "false_positive", "note": "Checked by hand: the host is an enum."})
        item = record_for(traced())
        body = self.client.post(f"/api/scans/{SCAN_ID}/audit", json={"records": [item]}).json()
        self.assertEqual(body["audit"]["records"]["confirmed"], 0)
        self.assertTrue(body["audit"]["errors"])
        finding = self.client.get(f"/api/scans/{SCAN_ID}/report").json()["findings"][0]
        self.assertEqual((finding["triage_status"], finding["triage_decided_by"]), ("false_positive", "manual"))

    def test_an_unknown_fingerprint_is_reported_not_applied(self) -> None:
        item = record_for(traced(), fingerprint="whitebox:" + "f" * 32)
        body = self.client.post(f"/api/scans/{SCAN_ID}/audit", json={"records": [item]}).json()
        self.assertEqual(body["audit"]["unmatched_fingerprints"], ["whitebox:" + "f" * 32])
        self.assertEqual(body["audit"]["records"]["confirmed"], 0)

    def test_records_that_are_all_unusable_are_refused(self) -> None:
        response = self.client.post(f"/api/scans/{SCAN_ID}/audit", json={"records": [{"verdict": "confirmed"}]})
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
