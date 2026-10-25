"""Write a representative audit export so the skill's own validator can check it.

The project's tests check the export against the vendored schema; this script feeds the
authoritative check in CI:

    python tests/export_sample_findings.py /tmp/findings.json
    node <skill-dir>/validate-findings.cjs /tmp/findings.json

It covers every vulnerability class the dataflow scanner reports and all three record
verdicts the service can produce.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_audit_phase import traced  # noqa: E402

import app as service  # noqa: E402
import whitebox_audit as audit  # noqa: E402
import whitebox_dataflow as dataflow  # noqa: E402


def sample() -> list[dict]:
    findings = []
    for index, (vuln_class, details) in enumerate(dataflow.VULN_CLASSES.items()):
        finding = traced(line=20 + index, vuln_class=vuln_class, cwe=details["cwe"],
                         confidence="medium" if index % 2 else "high")
        finding["title"] = f"{details['title']}: request input reaches {details['sink']}"
        finding["trace"][-1]["detail"] = f"Used as {details['sink']}"
        if index == 0:  # a finding a reviewer already dismissed leaves as rejected
            finding["triage_status"] = "false_positive"
            finding["agent_review"] = {"verdict": "false_positive",
                                       "blocking_controls": [f"shlex.quote at helpers.py:2"]}
        if index == 1:  # a finding a reviewer confirmed still leaves as needs_validation
            finding["triage_status"] = "confirmed"
        finding["match_key"] = service.finding_match_key(finding)
        findings.append(finding)
    return audit.export(findings)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    records = sample()
    Path(sys.argv[1]).write_text(json.dumps(records, ensure_ascii=False, indent=2), "utf-8")
    verdicts = sorted({record["verdict"] for record in records})
    print(f"{len(records)} records written to {sys.argv[1]} ({', '.join(verdicts)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
