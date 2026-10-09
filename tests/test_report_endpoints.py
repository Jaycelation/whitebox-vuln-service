"""Tests for report filtering and SARIF export endpoints.

Runnable without pytest:

    DATA_DIR=$(mktemp -d) .venv/bin/python tests/test_report_endpoints.py

Also discoverable by pytest if it is installed.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="whitebox-test-"))

from fastapi.testclient import TestClient  # noqa: E402

import app  # noqa: E402

SCAN_ID = "a" * 32


def _seed_report() -> TestClient:
    root = Path(".")
    findings = [
        app.make_finding(tool="semgrep", category="sast", severity="error", title="SQL injection", path="src/a.py", line=10, end_line=12, rule_id="py.sqli", references=["https://example.com/1"], source_root=root),
        app.make_finding(tool="gitleaks", category="secret", severity="high", title="AWS key", path="conf/.env", line=2, rule_id="aws-access-key", source_root=root),
        app.make_finding(tool="trivy", category="dependency", severity="low", title="CVE-2020-0001", path="requirements.txt", rule_id="CVE-2020-0001", source_root=root),
    ]
    directory = app.job_dir(SCAN_ID)
    directory.mkdir(parents=True, exist_ok=True)
    report = {"scan_id": SCAN_ID, "summary": app.summarize(findings, []), "scanners": [], "findings": findings}
    (directory / "report.json").write_text(json.dumps(report), "utf-8")
    app.initialize_storage()
    now = app.utc_now()
    with app.connect_db() as db:
        db.execute("DELETE FROM scans WHERE id = ?", (SCAN_ID,))
        db.execute(
            "INSERT INTO scans (id, name, status, created_at, updated_at, finished_at, scanners_json, upload_bytes) "
            "VALUES (?, ?, 'completed', ?, ?, ?, ?, 0)",
            (SCAN_ID, "test", now, now, now, json.dumps(["semgrep", "gitleaks", "trivy"])),
        )
    return TestClient(app.app)


def test_full_report_includes_filter_metadata() -> None:
    client = _seed_report()
    body = client.get(f"/api/scans/{SCAN_ID}/report").json()
    assert body["filter"]["matched"] == 3
    assert body["filter"]["returned"] == 3
    assert len(body["findings"]) == 3


def test_severity_filter() -> None:
    client = _seed_report()
    # "error" normalizes to "high"; only trivy is "low"
    body = client.get(f"/api/scans/{SCAN_ID}/report", params={"severity": "low"}).json()
    assert body["filter"]["returned"] == 1
    assert body["findings"][0]["tool"] == "trivy"
    body = client.get(f"/api/scans/{SCAN_ID}/report", params={"severity": "high"}).json()
    assert {f["tool"] for f in body["findings"]} == {"semgrep", "gitleaks"}


def test_tool_and_category_and_path_filters() -> None:
    client = _seed_report()
    assert client.get(f"/api/scans/{SCAN_ID}/report", params={"tool": "semgrep"}).json()["filter"]["returned"] == 1
    assert client.get(f"/api/scans/{SCAN_ID}/report", params={"category": "secret"}).json()["findings"][0]["tool"] == "gitleaks"
    body = client.get(f"/api/scans/{SCAN_ID}/report", params={"path_contains": "src/"}).json()
    assert body["filter"]["returned"] == 1 and body["findings"][0]["path"] == "src/a.py"


def test_pagination() -> None:
    client = _seed_report()
    body = client.get(f"/api/scans/{SCAN_ID}/report", params={"limit": 1, "offset": 1}).json()
    assert body["filter"]["matched"] == 3
    assert body["filter"]["returned"] == 1
    assert body["filter"]["offset"] == 1


def test_invalid_filter_returns_422() -> None:
    client = _seed_report()
    response = client.get(f"/api/scans/{SCAN_ID}/report", params={"severity": "nope"})
    assert response.status_code == 422
    assert "invalid" in response.json()["detail"]


def test_sarif_export() -> None:
    client = _seed_report()
    response = client.get(f"/api/scans/{SCAN_ID}/report.sarif")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/sarif+json")
    sarif = response.json()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 3
    semgrep_run = next(r for r in sarif["runs"] if r["tool"]["driver"]["name"] == "semgrep")
    result = semgrep_run["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert result["locations"][0]["physicalLocation"]["region"]["endLine"] == 12
    assert "_rule_index" not in semgrep_run


def test_unknown_scan_returns_404() -> None:
    client = _seed_report()
    assert client.get(f"/api/scans/{'b' * 32}/report").status_code == 404
    assert client.get(f"/api/scans/{'b' * 32}/report.sarif").status_code == 404


if __name__ == "__main__":
    passed = 0
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            function()
            print(f"ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
