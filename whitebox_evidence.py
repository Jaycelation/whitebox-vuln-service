"""Evidence levels and CVSS for findings.

A finding gets a CVSS score only when there is concrete evidence that the issue
is real in this code base:

- confirmed: a reviewer (person or agent) confirmed it in triage.
- reachable: a concrete code path exists. For code, a traced flow from request
  input to the sink. For a dependency, the advisory names the vulnerable
  function and the project calls it.
- present: the code or package is there, but no exploitable path was shown, for
  example a vulnerable package that is imported, a pattern match, or a secret.
- unverified: only a version matched (the package is never imported) or the
  false-positive check flagged it.
- false_positive: a reviewer marked it as a false positive.

Scores are CVSS 3.1 base scores computed from a vector that is stored with the
reasons for each metric. A static trace is strong evidence, not a working
exploit, so the score's basis says how it was derived.
"""
from __future__ import annotations

import math
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

EVIDENCE_LEVELS = ("confirmed", "reachable", "present", "unverified", "false_positive")
SCORED_LEVELS = frozenset({"confirmed", "reachable"})

# Typical vectors per vulnerability class, for an unauthenticated network attacker.
CLASS_VECTORS = {
    "command-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "code-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sql-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "path-traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
    "template-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "open-redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
}
CLASS_REASONS = {
    "command-injection": "Arbitrary OS commands run with the service's privileges (C/I/A high).",
    "code-injection": "Attacker-supplied code is evaluated (C/I/A high).",
    "deserialization": "Untrusted data is deserialized, which typically allows code execution (C/I/A high).",
    "sql-injection": "The attacker controls part of a SQL statement (read and modify data).",
    "path-traversal": "The attacker controls a file path; scored for reading files (C high).",
    "ssrf": "The server sends requests to an attacker-chosen URL, reaching internal services (scope changed).",
    "template-injection": "Attacker input is rendered as HTML or a template; scored as reflected XSS (user interaction).",
    "open-redirect": "Users can be redirected to an attacker's site (user interaction).",
}

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_VECTOR = re.compile(r"^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$")


def _roundup(value: float) -> float:
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss_rating(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def valid_vector(vector: str) -> bool:
    return bool(_VECTOR.match(vector or ""))


def cvss31_base_score(vector: str) -> float:
    """CVSS v3.1 base score (specification section 7.1)."""
    if not valid_vector(vector):
        raise ValueError(f"Not a CVSS 3.x base vector: {vector!r}")
    metrics = dict(part.split(":") for part in vector.split("/")[1:])
    changed = metrics["S"] == "C"
    privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
    iss = 1 - (1 - _WEIGHTS["C"][metrics["C"]]) * (1 - _WEIGHTS["I"][metrics["I"]]) * (1 - _WEIGHTS["A"][metrics["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * _WEIGHTS["AV"][metrics["AV"]] * _WEIGHTS["AC"][metrics["AC"]] * privileges * _WEIGHTS["UI"][metrics["UI"]]
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def score(vector: str, basis: str, reasons: list[str]) -> dict[str, Any]:
    value = cvss31_base_score(vector)
    return {"version": "3.1", "vector": vector.replace("CVSS:3.0/", "CVSS:3.1/"), "score": value,
            "rating": cvss_rating(value), "basis": basis, "reasons": reasons}


# --- Authentication markers near an entry point -------------------------------------------

AUTH_MARKERS = re.compile(
    r"(@login_required|@permission_required|@staff_member_required|@user_passes_test|@jwt_required|@auth_required|"
    r"@requires_auth|@authenticated|IsAuthenticated|Depends\(\s*get_current_\w*user|@PreAuthorize|@Secured|@RolesAllowed|"
    r"\[Authorize|passport\.authenticate|ensureLoggedIn|isAuthenticated|requireAuth|authMiddleware|verifyToken|"
    r"middleware\(\s*['\"]auth|Auth::check|auth\(\)->check|before_action\s+:authenticate|authenticate_user!|"
    r"\.is_authenticated|current_user\.is_authenticated|getUserPrincipal\(|User\.Identity\.IsAuthenticated)"
)
# Where a function or route handler starts, per language.
DEFINITION = re.compile(
    r"^\s*(?:async\s+def|def|function|func|(?:public|private|protected|internal)\b)|"
    r"\b(?:app|router|route)\.(?:get|post|put|delete|patch|all|route)\s*\("
)


def authentication_marker(root: Path, path: str | None, line: int | None) -> str | None:
    """Find a login check in the entry point's function or in the decorators above it."""
    if not path or not line:
        return None
    try:
        lines = (root / path).read_text("utf-8", errors="replace").splitlines()
    except OSError:
        return None
    number = min(line, len(lines)) - 1
    definition = None
    while number >= 0 and line - number < 400:
        text = lines[number]
        stripped = text.strip()
        if definition is not None and number < definition and stripped and not stripped.startswith(("@", "[")):
            break  # above the decorators: another statement or function
        # A commented-out check (`# @login_required`) protects nothing.
        match = None if stripped.startswith(("#", "//", "/*", "*", "--")) else AUTH_MARKERS.search(text)
        if match:
            return f"{match.group(1).strip()} ({path}:{number + 1})"
        if definition is None and DEFINITION.search(text):
            definition = number
        number -= 1
    return None


# --- Which dependencies does the code import? ---------------------------------------------

PYTHON_MODULES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL", "python-dateutil": "dateutil", "scikit-learn": "sklearn",
    "opencv-python": "cv2", "pycryptodome": "Crypto", "pycrypto": "Crypto", "pyjwt": "jwt", "python-jose": "jose",
    "djangorestframework": "rest_framework", "protobuf": "google", "msgpack-python": "msgpack", "mysqlclient": "MySQLdb",
    "psycopg2-binary": "psycopg2", "pyopenssl": "OpenSSL", "attrs": "attr", "python-multipart": "multipart",
    "flask-sqlalchemy": "flask_sqlalchemy", "pymysql": "pymysql", "setuptools": "setuptools", "pyasn1": "pyasn1",
}
SKIP_DIRECTORIES = frozenset({".git", "node_modules", "vendor", "third_party", ".venv", "venv", "site-packages", "dist", "build", "__pycache__"})
_PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w., ]*))", re.MULTILINE)
_JS_IMPORT = re.compile(r"""(?:require\(\s*|import\(\s*|from\s+|import\s+)['"]([^'"./][^'"]*)['"]""")
_GO_IMPORT = re.compile(r'"([\w.\-]+\.[\w.\-]+/[^"]+)"')
_RUBY_REQUIRE = re.compile(r"""^\s*require\s+['"]([^'"]+)['"]""", re.MULTILINE)
_JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.MULTILINE)
_PHP_USE = re.compile(r"^\s*use\s+([\w\\]+)", re.MULTILINE)
_CS_USING = re.compile(r"^\s*using\s+(?:static\s+)?([\w.]+)\s*;", re.MULTILINE)


class ImportIndex:
    """Where each imported module or package name appears in the project."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.locations: dict[str, dict[str, list[str]]] = {name: {} for name in ("python", "javascript", "go", "ruby", "java", "php", "csharp")}
        for directory, subdirectories, files in os.walk(root):
            subdirectories[:] = [name for name in subdirectories if name not in SKIP_DIRECTORIES]
            for file_name in files:
                self._index(Path(directory) / file_name)

    def _add(self, language: str, name: str, path: Path, text: str, position: int) -> None:
        line = text.count("\n", 0, position) + 1
        relative = path.relative_to(self.root).as_posix()
        entries = self.locations[language].setdefault(name, [])
        if len(entries) < 20:
            entries.append(f"{relative}:{line}")

    def _index(self, path: Path) -> None:
        suffix = path.suffix.lower()
        language = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
                    ".ts": "javascript", ".tsx": "javascript", ".go": "go", ".rb": "ruby", ".java": "java", ".kt": "java",
                    ".php": "php", ".cs": "csharp"}.get(suffix)
        if language is None or path.name.endswith((".min.js", ".bundle.js")):
            return
        try:
            if path.stat().st_size > 2_000_000:
                return
            text = path.read_text("utf-8", errors="replace")
        except OSError:
            return
        if language == "python":
            for match in _PY_IMPORT.finditer(text):
                names = [match.group(1)] if match.group(1) else [part.strip().split(" as ")[0] for part in match.group(2).split(",")]
                for name in names:
                    if name:
                        self._add(language, name.split(".")[0].lower(), path, text, match.start())
        elif language == "javascript":
            for match in _JS_IMPORT.finditer(text):
                spec = match.group(1)
                name = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
                self._add(language, name.lower(), path, text, match.start())
        elif language == "go":
            for match in _GO_IMPORT.finditer(text):
                self._add(language, match.group(1), path, text, match.start())
        elif language == "ruby":
            for match in _RUBY_REQUIRE.finditer(text):
                self._add(language, match.group(1).split("/")[0].lower(), path, text, match.start())
        elif language == "java":
            for match in _JAVA_IMPORT.finditer(text):
                self._add(language, match.group(1), path, text, match.start())
        elif language == "php":
            for match in _PHP_USE.finditer(text):
                self._add(language, match.group(1).lstrip("\\").lower(), path, text, match.start())
        else:
            for match in _CS_USING.finditer(text):
                self._add(language, match.group(1), path, text, match.start())

    def usages(self, ecosystem: str | None, package: str) -> list[str]:
        ecosystem = (ecosystem or "").lower()
        name = package.strip()
        if ecosystem in ("pypi", "pip", "poetry", "pipenv"):
            module = PYTHON_MODULES.get(name.lower(), name.lower().replace("-", "_").replace(".", "_"))
            return self.locations["python"].get(module.lower(), [])
        if ecosystem in ("npm", "yarn", "pnpm", "node-pkg"):
            return self.locations["javascript"].get(name.lower(), [])
        if ecosystem in ("go", "gomod", "gobinary"):
            return [location for imported, places in self.locations["go"].items()
                    if imported == name or imported.startswith(name + "/") for location in places]
        if ecosystem in ("rubygems", "bundler", "gemspec"):
            return self.locations["ruby"].get(name.lower().replace("-", "/").split("/")[0], []) or self.locations["ruby"].get(name.lower(), [])
        if ecosystem in ("maven", "gradle", "jar", "pom"):
            # Packages often differ from the groupId's last part (jackson-databind is
            # com.fasterxml.jackson.core but imports com.fasterxml.jackson.databind).
            group = ".".join(name.split(":")[0].split(".")[:3])
            return [location for imported, places in self.locations["java"].items()
                    if imported == group or imported.startswith(group + ".") for location in places]
        if ecosystem in ("packagist", "composer"):
            vendor = name.split("/")[0].lower()
            return [location for imported, places in self.locations["php"].items() if imported.split("\\")[0] == vendor for location in places]
        if ecosystem in ("nuget", "dotnet-core", "dotnet-deps"):
            return [location for imported, places in self.locations["csharp"].items()
                    if imported == name or imported.startswith(name + ".") for location in places]
        return []

    def symbol_calls(self, symbols: list[str]) -> list[str]:
        """Call sites of any of the given function names (from an advisory)."""
        names = {symbol.split(".")[-1] for symbol in symbols if symbol}
        if not names:
            return []
        pattern = re.compile(r"\b(" + "|".join(re.escape(name) for name in sorted(names)) + r")\s*\(")
        hits: list[str] = []
        for directory, subdirectories, files in os.walk(self.root):
            subdirectories[:] = [name for name in subdirectories if name not in SKIP_DIRECTORIES]
            for file_name in files:
                path = Path(directory) / file_name
                if path.suffix not in (".go", ".py", ".js", ".ts", ".java", ".rb", ".php", ".cs"):
                    continue
                try:
                    text = path.read_text("utf-8", errors="replace")
                except OSError:
                    continue
                for match in pattern.finditer(text):
                    hits.append(f"{path.relative_to(self.root).as_posix()}:{text.count(chr(10), 0, match.start()) + 1}")
                    if len(hits) >= 10:
                        return hits
        return hits


# --- Assessment ---------------------------------------------------------------------------

def automatic_evidence(finding: dict[str, Any], root: Path, imports: ImportIndex) -> tuple[str, list[str]]:
    """Evidence level from the code alone, ignoring triage decisions."""
    check = finding.get("fp_check") or {}
    category, tool = finding.get("category"), finding.get("tool")
    trace = finding.get("trace") or []
    if trace and tool == "dataflow":
        source, sink = trace[0], trace[-1]
        calls = sum(1 for step in trace if step.get("kind") == "call")
        items = [f"Request input at {source.get('path')}:{source.get('line')} reaches the sink at {sink.get('path')}:{sink.get('line')}"
                 + (f" through {calls} function call(s)." if calls else " in the same function.")]
        if finding.get("confidence") == "medium":
            items.append("Calls between functions were matched by function name; check the trace.")
        level = "reachable"
    elif category == "dependency":
        package = finding.get("package") or ""
        usages = imports.usages(finding.get("ecosystem"), package)
        symbols = finding.get("affected_symbols") or []
        calls = imports.symbol_calls(symbols) if symbols and usages else []
        if calls:
            level = "reachable"
            items = [f"The advisory names the vulnerable function(s) {', '.join(symbols[:5])}; called at {', '.join(calls[:5])}."]
        elif usages and symbols:
            level = "present"
            items = [f"{package} is imported ({', '.join(usages[:3])}), but the vulnerable function(s) {', '.join(symbols[:5])} are not called."]
        elif usages:
            level = "present"
            items = [f"{package} {finding.get('package_version') or ''} is imported at {', '.join(usages[:3])}. "
                     "The advisory does not name the vulnerable function, so whether the project calls it is not checked."]
        else:
            level = "unverified"
            items = [f"Only the version of {package} matches the advisory; the project never imports it "
                     "(transitive, unused, or build-time only)."]
    elif category == "secret":
        level, items = "present", ["A credential-shaped value is in the code. Whether it is live is not checked: the service never uses found credentials."]
    elif category == "misconfiguration":
        level, items = "present", ["Configuration matches a hardening rule; impact depends on how it is deployed."]
    else:
        level, items = "present", ["A code pattern matched, without a traced path from request input."]
    if check.get("verdict") == "likely_false_positive":
        # A heuristic flag lowers the level one step but never hides the finding.
        level = "present" if level == "reachable" else "unverified"
        items = items + [f"False-positive check: {' '.join(check.get('reasons') or [])}"]
    return level, items


def assess_finding(finding: dict[str, Any], root: Path, imports: ImportIndex) -> None:
    level, items = automatic_evidence(finding, root, imports)
    cvss = cvss_for(finding, root) if level in SCORED_LEVELS else None
    finding["evidence"] = {"level": level, "items": items, "automatic": {"level": level, "items": items, "cvss": cvss}}
    finding["cvss"] = cvss
    apply_triage(finding)


def apply_triage(finding: dict[str, Any]) -> None:
    """Combine the stored automatic evidence with the finding's triage decision."""
    evidence = finding.get("evidence") or {}
    automatic = evidence.get("automatic") or {"level": evidence.get("level", "present"), "items": evidence.get("items", []), "cvss": finding.get("cvss")}
    status = finding.get("triage_status", "needs_review")
    if status == "false_positive":
        level, items, cvss = "false_positive", ["A reviewer marked this finding as a false positive."], None
    elif status == "confirmed":
        level = "confirmed"
        items = ["A reviewer confirmed this finding."] + ([f"Note: {finding['triage_note']}"] if finding.get("triage_note") else [])
        override = finding.get("triage_cvss_vector")
        if override and valid_vector(override):
            cvss = score(override, "reviewer", ["Vector set by the reviewer."])
        else:
            cvss = automatic.get("cvss") or cvss_for(finding, Path("/nonexistent"))
    else:
        level, items, cvss = automatic["level"], [], automatic.get("cvss")
    finding["evidence"] = {"level": level, "items": items + list(automatic.get("items", [])), "automatic": automatic}
    finding["cvss"] = cvss


def cvss_for(finding: dict[str, Any], root: Path) -> dict[str, Any] | None:
    override = finding.get("triage_cvss_vector")
    if override and valid_vector(override):
        return score(override, "reviewer", ["Vector set by the reviewer."])
    if finding.get("category") == "dependency":
        advisory = finding.get("advisory_cvss") or {}
        if valid_vector(advisory.get("vector", "")):
            return score(advisory["vector"], "advisory", [f"Advisory vector from {advisory.get('source', 'the advisory')}; the vulnerable code is reachable."])
        return None
    vuln_class = (finding.get("rule_id") or "").rsplit(".", 1)[-1]
    vector = CLASS_VECTORS.get(vuln_class)
    if vector is None:
        return None
    reasons = [CLASS_REASONS[vuln_class]]
    trace = finding.get("trace") or []
    marker = authentication_marker(root, trace[0].get("path"), trace[0].get("line")) if trace else None
    if marker:
        vector = vector.replace("/PR:N/", "/PR:L/")
        reasons.append(f"The entry point appears to require login: {marker} (PR:L).")
    else:
        reasons.append("No authentication marker found near the entry point; scored as reachable without login (PR:N).")
    return score(vector, "static-trace", reasons)


def assess(findings: list[dict[str, Any]], root: Path) -> None:
    imports = ImportIndex(root)
    by_id = {finding["id"]: finding for finding in findings}
    for finding in findings:
        assess_finding(finding, root, imports)
    # A duplicate shares the evidence and score of the finding it repeats.
    for finding in findings:
        canonical = by_id.get((finding.get("fp_check") or {}).get("duplicate_of") or "")
        if canonical is not None:
            automatic = dict(canonical["evidence"]["automatic"])
            automatic["items"] = [f"Duplicate of {canonical['id']}."] + list(automatic["items"])
            finding["evidence"] = {"level": automatic["level"], "items": automatic["items"], "automatic": automatic}
            finding["cvss"] = automatic["cvss"]
            apply_triage(finding)


def summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    levels = dict.fromkeys(EVIDENCE_LEVELS, 0)
    ratings = dict.fromkeys(("critical", "high", "medium", "low", "none"), 0)
    for finding in findings:
        level = (finding.get("evidence") or {}).get("level", "present")
        levels[level] = levels.get(level, 0) + 1
        if finding.get("cvss"):
            ratings[finding["cvss"]["rating"]] += 1
    return {"evidence": levels, "cvss": ratings}
