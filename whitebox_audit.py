"""Hand the scan's traced findings to the security-audit skill and record what it returns.

The service and the skill (https://github.com/cloudflare/security-audit-skill) do
different work. The scanners produce the same findings on every run but cannot
reason about a trust boundary; the skill runs a six-phase agent audit that can,
but has no scanner of its own. This module is the seam between them.

`export` turns every finding that has a source-to-sink trace into a record in the
skill's `findings.json` format, so a run reads them as prior input instead of
re-deriving the flow. Records leave as `needs_validation`, never as `confirmed`: a
static trace is not a demonstrated vulnerability, and the skill's `confirmed`
variant requires a reproduction with an observed result that no scanner can
honestly supply. A finding already triaged as a false positive leaves as
`rejected` and carries the control that blocked it.

The service writes `findings.json` and its own provenance sidecar, and nothing
else. `run-metadata.json`, `architecture.md`, and `coverage-ledger.json` belong to
the skill's parent agent, and the service has no coverage claim to make: it ships
no ledger rather than one that implies surfaces were audited.

`read_records` and `apply_record` take the `findings.json` of a finished run and
record its verdicts as agent triage decisions, matched by fingerprint. A record is
untrusted input: every string is cleaned and capped, a `confirmed` record that
shows no reproduction and a `rejected` record that names no reason are both
downgraded to `needs_validation`, and a decision a person made is never
overridden (the caller skips those findings).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import whitebox_evidence

SKILL_REPO = "https://github.com/cloudflare/security-audit-skill"
VERDICTS = ("confirmed", "needs_validation", "rejected")
MAX_RECORDS = 500
# The skill's trace vocabulary; a step the analysis cannot place is dropped.
TRACE_KINDS = {"source": "entrypoint", "call": "propagation", "parameter": "propagation", "sink": "sink"}
FINGERPRINT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
# `visibleContent` in the schema rejects blank and invisible text, so collapse
# whitespace and drop control, separator, and default-ignorable code points.
INVISIBLE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f­؜᠎​-‏"
    r"  ‪-‮⁠-⁤⁦-⁩︀-️﻿￹-￻]"
)

NO_SANDBOX = ("The scanner service has no OS-enforced sandbox, so the flow was never executed: "
              "the trace is static evidence only.")
NOT_MODELLED = ("The analysis does not model validation inside an if statement, deployment "
                "configuration, or routing, so a guard on the path can still make this unreachable.")
NAME_MATCHED = ("The flow crosses helper functions matched by name across the project, so this "
                "path may not exist.")
PAYLOAD_HINTS = {
    "CWE-78": "a shell metacharacter such as `; id`",
    "CWE-94": "an expression with an observable effect, such as a write inside the scratch directory",
    "CWE-89": "a quote followed by a condition that changes the result set",
    "CWE-22": "a traversal sequence such as `../../etc/hostname`",
    "CWE-918": "a URL pointing at an isolated loopback listener",
    "CWE-502": "a serialized object the loader will instantiate",
    "CWE-79": "a script payload that survives the template's escaping",
    "CWE-601": "an absolute URL to another origin",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def visible(value: Any, limit: int, fallback: str = "") -> str:
    text = " ".join(INVISIBLE.sub(" ", str(value if value is not None else "")).split())
    return text[:limit].rstrip() or fallback


# --- Export -------------------------------------------------------------------------------

def fingerprint(finding: dict[str, Any]) -> str:
    """Source-derived and stable across validation states, as the schema requires."""
    key = str(finding.get("match_key") or finding.get("id") or "")
    return f"whitebox:{key}" if FINGERPRINT.fullmatch(f"whitebox:{key}") else ""


def trace_of(finding: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for step in finding.get("trace") or []:
        if not isinstance(step, dict):
            continue
        kind, path, line = TRACE_KINDS.get(step.get("kind")), step.get("path"), step.get("line")
        if kind is None or not path or not isinstance(line, int) or line < 1:
            continue
        entry = {
            "kind": kind,
            "file": str(path),
            "line": line,
            # The analysis names the function only where it summarized one; the file is the
            # honest fallback scope rather than a guess.
            "scope": visible(step.get("scope"), 200, fallback=str(path)),
            "description": visible(step.get("detail"), 300, fallback=f"Step in the {kind} position"),
        }
        if entry not in steps:  # the schema requires unique steps
            steps.append(entry)
    return steps


def evidence_of(finding: dict[str, Any], trace: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entry = next((step for step in trace if step["kind"] == "entrypoint"), None)
    sink = next((step for step in reversed(trace) if step["kind"] == "sink"), trace[-1])
    basis = (finding.get("cvss") or {}).get("basis")
    rule = visible(finding.get("rule_id"), 120, fallback="dataflow")
    items = [{
        "file": sink["file"],
        "line": sink["line"],
        "description": visible(
            f"Sink reported by the {finding.get('tool')} scanner, rule {rule}"
            + (f", scored from {basis}" if basis else "") + f". {sink['description']}.",
            500, fallback="Sink location reported by the scanner."),
    }]
    if entry is not None:
        item = {
            "file": entry["file"],
            "line": entry["line"],
            "description": visible(
                f"Cross-function taint analysis places request input here. {entry['description']}.",
                500, fallback="Request input enters here."),
        }
        if item not in items:
            items.insert(0, item)
    return items


def blockers_of(finding: dict[str, Any]) -> list[str]:
    blockers = [NO_SANDBOX, NOT_MODELLED]
    if finding.get("confidence") == "medium":
        blockers.append(NAME_MATCHED)
    review = finding.get("agent_review") or {}
    if review.get("verdict") == "uncertain" and review.get("summary"):
        blockers.append(visible(f"The service's own review was uncertain: {review['summary']}", 500))
    check = finding.get("fp_check") or {}
    if check.get("verdict") == "likely_false_positive":
        reasons = "; ".join(visible(reason, 200) for reason in (check.get("reasons") or [])[:5])
        blockers.append(visible(f"The false-positive check flagged this finding: {reasons}", 500,
                                fallback="The false-positive check flagged this finding."))
    if finding.get("triage_status") == "confirmed":
        blockers.append("A reviewer confirmed this finding from source; no sandboxed reproduction was recorded.")
    # Unique, as the schema requires, and in the order they were added.
    return list(dict.fromkeys(blocker for blocker in blockers if blocker))


def validation_plan(finding: dict[str, Any], trace: list[dict[str, Any]]) -> dict[str, str]:
    entry = next((step for step in trace if step["kind"] == "entrypoint"), None)
    sink = next((step for step in reversed(trace) if step["kind"] == "sink"), trace[-1])
    hint = PAYLOAD_HINTS.get(str(finding.get("cwe")), "a value that changes what the sink does")
    start = f"{entry['file']}:{entry['line']}" if entry is not None else "the entry point"
    return {
        "local": visible(
            f"In an OS-enforced sandbox with no external network, drive {start} with {hint} and observe "
            f"whether it reaches {sink['file']}:{sink['line']} unchanged. Read the path between the two "
            "steps first: the analysis does not model an allow-list or type check written as a condition.",
            1000, fallback="Drive the entry point with a payload and observe the sink in a sandbox."),
        "deployment": visible(
            "Confirm the entry point is routed and reachable by the principal the severity assumes, and "
            "that no proxy, framework default, or platform control strips the payload before the sink.",
            1000, fallback="Confirm the entry point is reachable in the deployed configuration."),
    }


def claimed_root_cause(finding: dict[str, Any], trace: list[dict[str, Any]]) -> str:
    entry = next((step for step in trace if step["kind"] == "entrypoint"), None)
    sink = next((step for step in reversed(trace) if step["kind"] == "sink"), trace[-1])
    start = f"{entry['file']}:{entry['line']}" if entry is not None else "an unresolved entry point"
    return visible(
        f"{finding.get('cwe') or 'Untrusted input'}: request input at {start} reaches "
        f"{sink['file']}:{sink['line']} ({sink['description']}) and the analysis found no sanitizer "
        "for this class on the path.",
        2000, fallback="Request input reaches a dangerous operation with no sanitizer on the path.")


def rejection_reason(finding: dict[str, Any]) -> str:
    controls = (finding.get("agent_review") or {}).get("blocking_controls") or []
    joined = "; ".join(visible(control, 300) for control in controls[:5])
    note = visible(finding.get("triage_note"), 1000)
    return visible(joined or note, 2000,
                   fallback="Triaged as a false positive in the scanner service; no reason was recorded.")


def record(finding: dict[str, Any]) -> dict[str, Any] | None:
    """One schema record, or None when the finding is not source-grounded enough to send."""
    trace = trace_of(finding)
    identifier = fingerprint(finding)
    if not trace or not identifier:
        return None
    common = {
        "fingerprint": identifier,
        "title": visible(finding.get("title"), 300, fallback="Request input reaches a dangerous operation"),
        "description": visible(finding.get("message"), 2000, fallback=claimed_root_cause(finding, trace)),
        "claimed_root_cause": claimed_root_cause(finding, trace),
        "trace": trace,
        "evidence": evidence_of(finding, trace),
    }
    if finding.get("triage_status") == "false_positive":
        return {"verdict": "rejected", **common, "reason": rejection_reason(finding)}
    return {
        "verdict": "needs_validation", **common,
        "blockers": blockers_of(finding),
        "validation_plan": validation_plan(finding, trace),
    }


def export(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The scan's traced findings as the skill's findings.json.

    Findings are considered highest score first, so the scored copy of a repeated
    fingerprint is the one that is sent, and the records come out sorted by fingerprint,
    which the skill's own validator requires.
    """
    def rank(finding: dict[str, Any]) -> tuple[float, str]:
        return (-((finding.get("cvss") or {}).get("score") or 0.0), str(finding.get("id") or ""))

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in sorted(findings, key=rank):
        if (finding.get("fp_check") or {}).get("duplicate_of"):
            continue
        item = record(finding)
        if item is None or item["fingerprint"] in seen:
            continue
        seen.add(item["fingerprint"])
        records.append(item)
    return sorted(records, key=lambda item: item["fingerprint"])


def provenance(scan_id: str, project: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Sidecar describing where the records came from; not one of the skill's own run files."""
    counts = {verdict: sum(1 for item in records if item["verdict"] == verdict) for verdict in VERDICTS}
    return {
        "produced_by": "whitebox-vuln-service",
        "skill": SKILL_REPO,
        "scan_id": scan_id,
        "project": project,
        "generated_at": utc_now(),
        "records": counts,
        "contents": ("Static source-to-sink traces from a scanner run, as prior candidates. No record "
                     "is confirmed: nothing here was executed or reproduced."),
        "coverage_claim": ("None. The service ships no coverage-ledger.json; a scanner run is not a "
                           "coverage claim over the surfaces it happened to touch."),
    }


# --- Ingest -------------------------------------------------------------------------------

def read_records(data: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate a finished run's findings.json; returns the usable records and the problems."""
    if not isinstance(data, list):
        return [], ["findings.json must be a JSON array of records."]
    if len(data) > MAX_RECORDS:
        return [], [f"findings.json holds {len(data)} records; the limit is {MAX_RECORDS}."]
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            errors.append(f"Record {index} is not an object.")
            continue
        identifier = str(item.get("fingerprint") or "")
        if not FINGERPRINT.fullmatch(identifier):
            errors.append(f"Record {index} has no usable fingerprint.")
            continue
        if item.get("verdict") not in VERDICTS:
            errors.append(f"Record {identifier} has an unknown verdict.")
            continue
        if identifier in seen:
            errors.append(f"Record {identifier} repeats an earlier fingerprint.")
            continue
        seen.add(identifier)
        records.append(item)
    return records, errors


def normalize(item: dict[str, Any]) -> dict[str, Any]:
    """Enforce the evidence rules on one record, as the service does on its own reviews."""
    verdict = item["verdict"]
    execution = item.get("execution") if isinstance(item.get("execution"), dict) else {}
    severity = item.get("severity") if isinstance(item.get("severity"), dict) else {}
    confidence = item.get("confidence") if isinstance(item.get("confidence"), dict) else {}
    remediation = item.get("remediation") if isinstance(item.get("remediation"), dict) else {}
    review = {
        "verdict": verdict,
        "fingerprint": str(item["fingerprint"]),
        "title": visible(item.get("title"), 300, fallback="(untitled record)"),
        "summary": visible(item.get("description"), 1000),
        "root_cause": visible(item.get("root_cause") or item.get("claimed_root_cause"), 2000),
        "severity": visible(severity.get("overall_severity"), 20),
        "confidence": visible(confidence.get("score"), 20),
        "observed_result": visible(execution.get("observed_result"), 1000),
        "remediation": visible(remediation.get("strategy"), 1000),
        "blockers": [visible(blocker, 500) for blocker in (item.get("blockers") or [])[:10] if visible(blocker, 500)],
        "reason": visible(item.get("reason"), 2000),
        "source": "security-audit-skill",
    }
    if verdict == "confirmed" and not (review["observed_result"] and review["severity"]):
        review["verdict"] = "needs_validation"
        review["blockers"].insert(0, "Downgraded on ingest: a confirmed record must carry an observed "
                                     "result and an overall severity.")
    if verdict == "rejected" and not review["reason"]:
        review["verdict"] = "needs_validation"
        review["blockers"].insert(0, "Downgraded on ingest: a rejected record must give the reason the "
                                     "candidate was refuted.")
    return review


def apply_record(finding: dict[str, Any], item: dict[str, Any], now: str) -> bool:
    """Store the record on the finding; returns True when it became a triage decision."""
    review = normalize(item)
    review["ingested_at"] = now
    finding["audit_review"] = review
    if review["verdict"] == "needs_validation":
        return False
    finding["triage_status"] = "confirmed" if review["verdict"] == "confirmed" else "false_positive"
    detail = review["root_cause"] or review["reason"] or review["summary"]
    finding["triage_note"] = visible(f"security-audit skill: {review['title']} — {detail}", 2000)
    finding["triage_source"] = "security-audit-skill"
    finding["triage_decided_by"] = "agent"
    finding["triage_updated_at"] = now
    # The record carries a qualitative severity, not a CVSS vector; the service keeps its own.
    finding["triage_cvss_vector"] = None
    whitebox_evidence.apply_triage(finding)
    return True


def summary(applied: list[dict[str, Any]], skipped: list[str], errors: list[str]) -> dict[str, Any]:
    counts = dict.fromkeys(VERDICTS, 0)
    for review in applied:
        counts[review["verdict"]] += 1
    return {
        "status": "completed" if not errors else "partial",
        "skill": SKILL_REPO,
        "ingested_at": utc_now(),
        "records": counts,
        "unmatched_fingerprints": skipped[:50],
        "errors": errors[:50],
    }
