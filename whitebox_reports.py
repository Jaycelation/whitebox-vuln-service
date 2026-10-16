"""Reviewer-authored vulnerability reports and Markdown export."""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field

import whitebox_evidence


Severity = Literal["critical", "high", "medium", "low", "info", "none", "unknown"]


class ReportItemUpdate(BaseModel):
    title: str | None = Field(None, max_length=240)
    cwe: str | None = Field(None, max_length=240)
    severity: Severity | None = None
    cvss_vector: str | None = Field(None, max_length=120)
    summary: str | None = Field(None, max_length=6000)
    technical_details: str | None = Field(None, max_length=12000)
    impact: str | None = Field(None, max_length=6000)
    remediation: str | None = Field(None, max_length=6000)
    validation_needed: str | None = Field(None, max_length=6000)


def draft_from_finding(finding: dict[str, Any] | None) -> dict[str, str]:
    """Copy identifiers and candidate ratings, without inventing validation or impact."""
    finding = finding or {}
    cwe = finding.get("cwe") if isinstance(finding.get("cwe"), str) else ""
    if not cwe:
        match = re.search(r"\bCWE[-_ ]?(\d+)\b", str(finding.get("rule_id") or ""), re.I)
        if match:
            cwe = f"CWE-{match.group(1)}"
    cvss = finding.get("cvss") or {}
    vector = cvss.get("vector") if isinstance(cvss, dict) else ""
    if not isinstance(vector, str) or not whitebox_evidence.valid_vector(vector):
        vector = ""
    severity = finding.get("severity")
    if severity not in ("critical", "high", "medium", "low", "info", "unknown"):
        severity = "unknown"
    return {
        "title": str(finding.get("title") or ("Untitled finding" if finding else "Untitled report"))[:240],
        "cwe": cwe[:240],
        "severity": whitebox_evidence.cvss_rating(whitebox_evidence.cvss31_base_score(vector)) if vector else severity,
        "cvss_vector": vector,
        "summary": "",
        "technical_details": "",
        "impact": "",
        "remediation": "",
        "validation_needed": "",
    }


def apply_update(item: dict[str, Any], update: ReportItemUpdate) -> dict[str, Any]:
    changes = update.model_dump(exclude_unset=True) if hasattr(update, "model_dump") else update.dict(exclude_unset=True)
    for key, value in changes.items():
        if value is None:
            raise ValueError(f"{key} cannot be null")
        changes[key] = value.strip() if isinstance(value, str) else value
    if "title" in changes and not changes["title"]:
        raise ValueError("title cannot be empty")
    if "cvss_vector" in changes and changes["cvss_vector"] and not whitebox_evidence.valid_vector(changes["cvss_vector"]):
        raise ValueError("cvss_vector must be a valid CVSS 3.x base vector")
    result = {**item, **changes}
    vector = result.get("cvss_vector") or ""
    if vector:
        score = whitebox_evidence.cvss31_base_score(vector)
        result["cvss_score"] = score
        result["severity"] = whitebox_evidence.cvss_rating(score)
    else:
        result["cvss_score"] = None
    return result


def _inline(value: Any) -> str:
    """Keep scanner-supplied titles from changing Markdown structure."""
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", str(value or "").replace("\n", " ").replace("\r", " "))


def _paragraph(value: Any) -> str:
    return str(value or "").strip() or "_To be completed by reviewer._"


def render_markdown(project: str, scan_id: str, items: list[dict[str, Any]]) -> str:
    lines = [f"# Security report: {_inline(project)}", "", f"Scan ID: `{scan_id}`", ""]
    if not items:
        lines.extend(("_No report entries yet._", ""))
    for item in sorted(items, key=lambda entry: entry["number"]):
        score = item.get("cvss_score")
        severity = str(item.get("severity") or "unknown").capitalize()
        if score is not None:
            severity += f" ({score:.1f})"
        lines.extend((
            f"## REPORT-{item['number']:02d}: {_inline(item['title'])}", "",
            f"**CWE:** {_inline(item.get('cwe') or 'Not assigned')}", "",
            f"**Severity:** {severity}", "",
            f"**CVSS:** `{item['cvss_vector']}`" if item.get("cvss_vector") else "**CVSS:** Not assessed", "",
        ))
        for label, key in (
            ("Summary", "summary"), ("Technical Details", "technical_details"),
            ("Impact", "impact"), ("Remediation", "remediation"),
            ("Validation needed", "validation_needed"),
        ):
            lines.extend((f"**{label}:** {_paragraph(item.get(key))}", ""))
        if item.get("finding_id"):
            lines.extend((f"Source finding ID: `{item['finding_id']}`", ""))
    return "\n".join(lines).rstrip() + "\n"
