"""One classification for findings from every scanner.

Scanners describe the same weakness differently: Semgrep rules carry CWE and
OWASP metadata, Trivy and OSV advisories list CWE ids, the dataflow scanner has
its own vulnerability classes, and secret scanners have none. Each finding gets
`classification` with normalized CWE ids, OWASP Top 10 2021 categories and a
vulnerability class, so findings can be grouped, filtered and matched across
tools by what they are rather than by which tool reported them.

Where a scanner gives no OWASP category it is derived from the CWE using the
OWASP Top 10 2021 mapping; the `owasp_source` field says which it was.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

OWASP_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

# CWE ids mapped to each category in the OWASP Top 10 2021 (common subset).
_OWASP_CWES = {
    "A01:2021": (22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540,
                 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275),
    "A02:2021": (261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347,
                 523, 720, 757, 759, 760, 780, 818, 916),
    "A03:2021": (20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470,
                 471, 564, 610, 643, 644, 652, 917, 1336),
    "A04:2021": (73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501,
                 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173),
    "A05:2021": (2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174),
    "A06:2021": (937, 1035, 1104),
    "A07:2021": (255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798,
                 940, 1216),
    "A08:2021": (345, 353, 426, 494, 502, 565, 784, 829, 830, 915),
    "A09:2021": (117, 223, 532, 778),
    "A10:2021": (918,),
}
CWE_TO_OWASP = {f"CWE-{number}": category for category, numbers in _OWASP_CWES.items() for number in numbers}

# Vulnerability classes; the injection names match the dataflow scanner's classes.
CWE_TO_CLASS = {
    "CWE-77": "command-injection", "CWE-78": "command-injection", "CWE-88": "command-injection",
    "CWE-94": "code-injection", "CWE-95": "code-injection",
    "CWE-89": "sql-injection", "CWE-564": "sql-injection",
    "CWE-22": "path-traversal", "CWE-23": "path-traversal", "CWE-35": "path-traversal", "CWE-73": "path-traversal",
    "CWE-918": "ssrf",
    "CWE-502": "deserialization",
    "CWE-79": "xss", "CWE-80": "xss",
    "CWE-1336": "template-injection",
    "CWE-601": "open-redirect",
    "CWE-611": "xxe", "CWE-776": "xxe",
    "CWE-90": "ldap-injection", "CWE-643": "xpath-injection", "CWE-943": "nosql-injection",
    "CWE-798": "hardcoded-secret", "CWE-259": "hardcoded-secret", "CWE-321": "hardcoded-secret",
    "CWE-326": "weak-crypto", "CWE-327": "weak-crypto", "CWE-328": "weak-crypto", "CWE-330": "weak-crypto",
    "CWE-338": "weak-crypto", "CWE-916": "weak-crypto",
    "CWE-295": "tls-validation", "CWE-319": "cleartext-transport",
    "CWE-352": "csrf",
    "CWE-434": "file-upload",
    "CWE-862": "missing-authorization", "CWE-863": "missing-authorization", "CWE-639": "missing-authorization",
    "CWE-287": "authentication", "CWE-306": "authentication",
    "CWE-1321": "prototype-pollution", "CWE-915": "mass-assignment",
    "CWE-1333": "redos", "CWE-400": "resource-exhaustion",
    "CWE-532": "sensitive-logging", "CWE-200": "information-exposure", "CWE-209": "information-exposure",
}
# Classes that the dataflow scanner and Semgrep's rules describe differently: the
# dataflow `template-injection` class covers XSS (CWE-79), so treat them as one.
EQUIVALENT_CLASSES = {"template-injection": "xss"}

_CWE = re.compile(r"\bCWE[-_ ]?(\d{1,5})\b", re.IGNORECASE)
_OWASP = re.compile(r"\bA(\d{1,2}):(20\d\d)\b", re.IGNORECASE)


def normalize_cwes(values: Any) -> list[str]:
    """CWE ids as `CWE-<n>` from strings like 'CWE-89: Improper ...', '89' or integers."""
    if values is None:
        return []
    if isinstance(values, (str, int)):
        values = [values]
    found: list[str] = []
    for value in values if isinstance(values, Iterable) else []:
        if isinstance(value, bool):
            continue
        if isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit()):
            matches = [str(int(value))]
        elif isinstance(value, str):
            matches = _CWE.findall(value)
        else:
            continue
        for number in matches:
            cwe = f"CWE-{int(number)}"
            if cwe not in found:
                found.append(cwe)
    return found[:10]


def normalize_owasp(values: Any) -> list[str]:
    """OWASP Top 10 ids as `A03:2021` from strings like 'A03:2021 - Injection'."""
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    found: list[str] = []
    for value in values if isinstance(values, Iterable) else []:
        for number, year in _OWASP.findall(str(value)):
            category = f"A{int(number):02d}:{year}"
            if category not in found:
                found.append(category)
    return found[:10]


# Fallback CWE and OWASP category for findings whose scanner names none.
_CATEGORY_DEFAULTS = {
    "secret": (["CWE-798"], ["A07:2021"]),
    "misconfiguration": ([], ["A05:2021"]),
    "dependency": ([], ["A06:2021"]),
}


def classify(finding: dict[str, Any], cwe: Any = None, owasp: Any = None, vuln_class: str | None = None) -> dict[str, Any]:
    """Set `classification` (and `cwe`, the primary id) on a finding and return it."""
    category = finding.get("category")
    cwes = normalize_cwes(cwe)
    if not cwes:
        cwes = list(_CATEGORY_DEFAULTS.get(category, ([], []))[0])
    owasp_ids = normalize_owasp(owasp)
    source = "scanner" if owasp_ids else None
    # Prefer the 2021 edition: older Semgrep rules also list 2017 categories.
    current = [item for item in owasp_ids if item.endswith(":2021")]
    if current:
        owasp_ids = current
    elif cwes:
        derived = []
        for item in cwes:
            mapped = CWE_TO_OWASP.get(item)
            if mapped and mapped not in derived:
                derived.append(mapped)
        if derived:
            owasp_ids, source = derived, "cwe-mapping"
    if category == "dependency":
        # A known-vulnerable component is A06 whatever the underlying weakness.
        owasp_ids = ["A06:2021"] + [item for item in owasp_ids if item != "A06:2021"]
        source = source or "category"
    if not owasp_ids and category in _CATEGORY_DEFAULTS:
        owasp_ids, source = list(_CATEGORY_DEFAULTS[category][1]), "category"
    if vuln_class is None:
        vuln_class = next((CWE_TO_CLASS[item] for item in cwes if item in CWE_TO_CLASS), None)
        if vuln_class is None and category == "secret":
            vuln_class = "hardcoded-secret"
    classification = {
        "cwe": cwes,
        "owasp": owasp_ids,
        "owasp_names": [OWASP_2021[item] for item in owasp_ids if item in OWASP_2021],
        "owasp_source": source,
        "class": vuln_class,
    }
    finding["classification"] = classification
    if cwes and not finding.get("cwe"):
        finding["cwe"] = cwes[0]
    return classification


def same_weakness(first: dict[str, Any], second: dict[str, Any]) -> bool:
    """Whether two findings describe the same kind of weakness (shared CWE or class)."""
    a = first.get("classification") or {}
    b = second.get("classification") or {}
    if set(a.get("cwe") or []) & set(b.get("cwe") or []):
        return True
    class_a = EQUIVALENT_CLASSES.get(a.get("class"), a.get("class"))
    class_b = EQUIVALENT_CLASSES.get(b.get("class"), b.get("class"))
    return bool(class_a) and class_a == class_b


def summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts by OWASP category, CWE and class, without double-counting duplicates."""
    owasp: dict[str, int] = {}
    cwes: dict[str, int] = {}
    classes: dict[str, int] = {}
    for finding in findings:
        if (finding.get("fp_check") or {}).get("verdict") == "duplicate":
            continue
        classification = finding.get("classification") or {}
        for item in classification.get("owasp") or ["unclassified"]:
            owasp[item] = owasp.get(item, 0) + 1
        for item in classification.get("cwe") or []:
            cwes[item] = cwes.get(item, 0) + 1
        name = classification.get("class") or "unclassified"
        classes[name] = classes.get(name, 0) + 1

    def ranked(counts: dict[str, int], limit: int | None = None) -> dict[str, int]:
        items = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        return dict(items[:limit] if limit else items)

    return {"owasp": dict(sorted(owasp.items())), "cwe": ranked(cwes, 25), "vuln_class": ranked(classes)}
