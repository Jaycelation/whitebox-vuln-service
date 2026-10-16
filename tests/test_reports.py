"""Tests for the reviewer-authored reports module and its API endpoints.

Discoverable by the project's CI (`python -m unittest discover -s tests`)
and runnable directly (`DATA_DIR=$(mktemp -d) python tests/test_reports.py`).
Tests use temporary storage and a seeded report; no scanner binaries run.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="whitebox-test-"))

from fastapi.testclient import TestClient  # noqa: E402

import app  # noqa: E402
import whitebox_reports  # noqa: E402

SCAN_ID = "c" * 32
GOOD_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class ReportsModuleTests(unittest.TestCase):
    """Unit tests for whitebox_reports, independent of storage and HTTP."""

    def test_draft_copies_identifiers_without_inventing_narrative(self) -> None:
        draft = whitebox_reports.draft_from_finding(
            {"title": "SQL injection", "cwe": "CWE-89", "severity": "high"}
        )
        self.assertEqual(draft["title"], "SQL injection")
        self.assertEqual(draft["cwe"], "CWE-89")
        self.assertEqual(draft["severity"], "high")
        # Narrative fields are left for the reviewer.
        for key in ("summary", "technical_details", "impact", "remediation", "validation_needed"):
            self.assertEqual(draft[key], "")

    def test_draft_recovers_cwe_from_rule_id(self) -> None:
        draft = whitebox_reports.draft_from_finding({"rule_id": "py.sqli.cwe_89"})
        self.assertEqual(draft["cwe"], "CWE-89")

    def test_draft_severity_follows_evidence_backed_vector(self) -> None:
        draft = whitebox_reports.draft_from_finding(
            {"title": "x", "severity": "low", "cvss": {"vector": GOOD_VECTOR}}
        )
        self.assertEqual(draft["cvss_vector"], GOOD_VECTOR)
        self.assertEqual(draft["severity"], "critical")

    def test_draft_drops_invalid_vector_and_unknown_severity(self) -> None:
        draft = whitebox_reports.draft_from_finding(
            {"title": "x", "severity": "bogus", "cvss": {"vector": "not-a-vector"}}
        )
        self.assertEqual(draft["cvss_vector"], "")
        self.assertEqual(draft["severity"], "unknown")

    def test_draft_handles_empty_finding(self) -> None:
        draft = whitebox_reports.draft_from_finding(None)
        self.assertEqual(draft["title"], "Untitled report")
        self.assertEqual(draft["cwe"], "")
        self.assertEqual(draft["severity"], "unknown")

    def test_apply_update_strips_and_recomputes_from_vector(self) -> None:
        item = whitebox_reports.draft_from_finding(None)
        result = whitebox_reports.apply_update(
            item,
            whitebox_reports.ReportItemUpdate(summary="  hello  ", cvss_vector=GOOD_VECTOR),
        )
        self.assertEqual(result["summary"], "hello")
        self.assertEqual(result["severity"], "critical")
        self.assertAlmostEqual(result["cvss_score"], 9.8, places=1)

    def test_apply_update_clears_score_without_vector(self) -> None:
        item = {**whitebox_reports.draft_from_finding(None), "cvss_score": 9.8}
        result = whitebox_reports.apply_update(
            item, whitebox_reports.ReportItemUpdate(cvss_vector="")
        )
        self.assertIsNone(result["cvss_score"])

    def test_apply_update_rejects_blank_title_and_bad_vector(self) -> None:
        item = whitebox_reports.draft_from_finding(None)
        with self.assertRaises(ValueError):
            whitebox_reports.apply_update(item, whitebox_reports.ReportItemUpdate(title="   "))
        with self.assertRaises(ValueError):
            whitebox_reports.apply_update(item, whitebox_reports.ReportItemUpdate(cvss_vector="nope"))

    def test_render_markdown_escapes_and_placeholders(self) -> None:
        items = [{
            "number": 1, "title": "Inject `evil` #1", "cwe": "CWE-89",
            "severity": "critical", "cvss_vector": GOOD_VECTOR, "cvss_score": 9.8,
            "summary": "", "technical_details": "detail", "impact": "",
            "remediation": "", "validation_needed": "", "finding_id": "a" * 24,
        }]
        md = whitebox_reports.render_markdown("Proj `x`", SCAN_ID, items)
        self.assertIn("## REPORT-01: Inject \\`evil\\` \\#1", md)
        self.assertIn("**Severity:** Critical (9.8)", md)
        self.assertIn("_To be completed by reviewer._", md)  # blank summary
        self.assertIn("Source finding ID: `" + "a" * 24 + "`", md)
        # Scanner-supplied project name is escaped and never breaks the heading.
        self.assertIn("# Security report: Proj \\`x\\`", md)

    def test_render_markdown_handles_empty_report(self) -> None:
        md = whitebox_reports.render_markdown("Proj", SCAN_ID, [])
        self.assertIn("_No report entries yet._", md)


class CuratedReportEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(".")
        self.findings = [
            app.make_finding(tool="semgrep", category="sast", severity="error", title="SQL injection", path="src/a.py", line=10, end_line=12, rule_id="py.sqli.cwe-89", source_root=root),
            app.make_finding(tool="gitleaks", category="secret", severity="high", title="AWS key", path="conf/.env", line=2, rule_id="aws-access-key", source_root=root),
        ]
        directory = app.job_dir(SCAN_ID)
        directory.mkdir(parents=True, exist_ok=True)
        report = {"scan_id": SCAN_ID, "summary": app.summarize(self.findings, []), "scanners": [], "findings": self.findings}
        (directory / "report.json").write_text(json.dumps(report), "utf-8")
        app.initialize_storage()
        now = app.utc_now()
        with app.connect_db() as db:
            db.execute("DELETE FROM report_items WHERE scan_id = ?", (SCAN_ID,))
            db.execute("DELETE FROM report_sequences WHERE scan_id = ?", (SCAN_ID,))
            db.execute("DELETE FROM scans WHERE id = ?", (SCAN_ID,))
            db.execute(
                "INSERT INTO scans (id, name, status, created_at, updated_at, finished_at, scanners_json, upload_bytes) "
                "VALUES (?, ?, 'completed', ?, ?, ?, ?, 0)",
                (SCAN_ID, "demo", now, now, now, json.dumps(["semgrep", "gitleaks"])),
            )
        self.client = TestClient(app.app)
        self.base = f"/api/scans/{SCAN_ID}/reports"

    def test_create_from_finding_copies_identifiers(self) -> None:
        fid = self.findings[0]["id"]
        response = self.client.post(self.base, json={"finding_id": fid})
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["number"], 1)
        self.assertEqual(body["title"], "SQL injection")
        self.assertEqual(body["cwe"], "CWE-89")
        self.assertEqual(body["finding_id"], fid)
        self.assertEqual(body["summary"], "")

    def test_manual_entry_and_sequential_numbering(self) -> None:
        first = self.client.post(self.base, json={}).json()
        second = self.client.post(self.base, json={}).json()
        self.assertEqual(first["number"], 1)
        self.assertEqual(second["number"], 2)
        self.assertEqual(first["title"], "Untitled report")
        self.assertIsNone(first["finding_id"])

    def test_numbering_stays_monotonic_after_delete(self) -> None:
        first = self.client.post(self.base, json={}).json()
        self.assertEqual(self.client.delete(f"{self.base}/{first['id']}").status_code, 204)
        third = self.client.post(self.base, json={}).json()
        self.assertEqual(third["number"], 2)  # 1 is not reused

    def test_duplicate_finding_is_rejected(self) -> None:
        fid = self.findings[0]["id"]
        self.assertEqual(self.client.post(self.base, json={"finding_id": fid}).status_code, 201)
        dup = self.client.post(self.base, json={"finding_id": fid})
        self.assertEqual(dup.status_code, 409)

    def test_create_validates_finding_id(self) -> None:
        self.assertEqual(self.client.post(self.base, json={"finding_id": "xyz"}).status_code, 422)
        self.assertEqual(self.client.post(self.base, json={"finding_id": "a" * 24}).status_code, 404)

    def test_patch_updates_fields_and_recomputes_severity(self) -> None:
        item_id = self.client.post(self.base, json={}).json()["id"]
        response = self.client.patch(
            f"{self.base}/{item_id}",
            json={"summary": "  reviewed  ", "cvss_vector": GOOD_VECTOR},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["summary"], "reviewed")
        self.assertEqual(body["severity"], "critical")
        self.assertAlmostEqual(body["cvss_score"], 9.8, places=1)

    def test_patch_rejects_bad_vector_and_null(self) -> None:
        item_id = self.client.post(self.base, json={}).json()["id"]
        self.assertEqual(self.client.patch(f"{self.base}/{item_id}", json={"cvss_vector": "nope"}).status_code, 422)
        self.assertEqual(self.client.patch(f"{self.base}/{item_id}", json={"summary": None}).status_code, 422)

    def test_patch_unknown_entry_returns_404(self) -> None:
        self.assertEqual(self.client.patch(f"{self.base}/{'d' * 32}", json={"summary": "x"}).status_code, 404)
        self.assertEqual(self.client.patch(f"{self.base}/short", json={"summary": "x"}).status_code, 404)

    def test_list_is_ordered_by_number(self) -> None:
        self.client.post(self.base, json={})
        self.client.post(self.base, json={})
        body = self.client.get(self.base).json()
        self.assertEqual(body["scan_id"], SCAN_ID)
        self.assertEqual([item["number"] for item in body["items"]], [1, 2])

    def test_markdown_export_headers_and_body(self) -> None:
        item_id = self.client.post(self.base, json={"finding_id": self.findings[0]["id"]}).json()["id"]
        self.client.patch(f"{self.base}/{item_id}", json={"cvss_vector": GOOD_VECTOR})
        response = self.client.get(f"{self.base}.md")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/markdown"))
        self.assertIn(f"whitebox-reports-{SCAN_ID}.md", response.headers["content-disposition"])
        self.assertIn("## REPORT-01: SQL injection", response.text)
        self.assertIn("**Severity:** Critical (9.8)", response.text)
        self.assertIn("_To be completed by reviewer._", response.text)

    def test_delete_is_idempotent_and_removes_from_list(self) -> None:
        item_id = self.client.post(self.base, json={}).json()["id"]
        self.assertEqual(self.client.delete(f"{self.base}/{item_id}").status_code, 204)
        self.assertEqual(self.client.delete(f"{self.base}/{item_id}").status_code, 404)
        self.assertEqual(self.client.get(self.base).json()["items"], [])

    def test_deleting_scan_removes_report_items(self) -> None:
        self.client.post(self.base, json={})
        self.assertEqual(self.client.delete(f"/api/scans/{SCAN_ID}").status_code, 204)
        with app.connect_db() as db:
            remaining = db.execute("SELECT COUNT(*) FROM report_items WHERE scan_id = ?", (SCAN_ID,)).fetchone()[0]
            sequences = db.execute("SELECT COUNT(*) FROM report_sequences WHERE scan_id = ?", (SCAN_ID,)).fetchone()[0]
        self.assertEqual(remaining, 0)
        self.assertEqual(sequences, 0)

    def test_unknown_scan_returns_404(self) -> None:
        missing = f"/api/scans/{'e' * 32}/reports"
        self.assertEqual(self.client.get(missing).status_code, 404)
        self.assertEqual(self.client.post(missing, json={}).status_code, 404)
        self.assertEqual(self.client.get(missing + ".md").status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
