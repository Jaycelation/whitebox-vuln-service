from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import stat
import sys
import threading
import time
import uuid
import zipfile
from contextlib import AsyncExitStack, asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import whitebox_dataflow
import whitebox_evidence
import whitebox_verify


def positive_int_setting(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    value = int(raw) if raw else default
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


DATA_DIR = Path(os.getenv("DATA_DIR", "./data")).resolve()
DB_PATH = DATA_DIR / "scans.sqlite3"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))
MAX_EXPANDED_BYTES = int(os.getenv("MAX_EXPANDED_BYTES", str(1024 * 1024 * 1024)))
MAX_ARCHIVE_ENTRIES = int(os.getenv("MAX_ARCHIVE_ENTRIES", "20000"))
MAX_FINDINGS = int(os.getenv("MAX_FINDINGS", "10000"))
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "900"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
VERIFY_MAX_FINDINGS = positive_int_setting("VERIFY_MAX_FINDINGS", 20)
VERIFY_CONCURRENCY = positive_int_setting("VERIFY_CONCURRENCY", 3)
PRUNE_INTERVAL_SECONDS = positive_int_setting("PRUNE_INTERVAL_SECONDS", 3600)
SCAN_CONCURRENCY = positive_int_setting("SCAN_CONCURRENCY", 1)
SCANNER_PARALLELISM = positive_int_setting("SCANNER_PARALLELISM", 1)
MAX_SCANNER_PROCESSES = positive_int_setting("MAX_SCANNER_PROCESSES", SCAN_CONCURRENCY * SCANNER_PARALLELISM)
API_KEY = os.getenv("API_KEY", "")
DEFAULT_SCANNERS = ("semgrep", "dataflow", "gitleaks", "trivy", "osv-scanner")
SCANNER_BINARIES = {
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "trivy": "trivy",
    "osv-scanner": "osv-scanner",
    "joern": "joern-scan",
    # Cross-function source-to-sink analysis; runs Semgrep several times.
    "dataflow": "semgrep",
}
# Every Trivy process that finds its vulnerability database out of date downloads
# it into the shared cache, so concurrent runs repeat the download and write the
# same files. Joern is a memory-heavy JVM. Semgrep runs that share HOME were
# tested concurrently with the pinned version and are only bound by the total cap.
DEFAULT_SCANNER_PROCESS_LIMITS = {"trivy": 1, "joern": 1}


def scanner_process_limits(raw: str) -> dict[str, int]:
    """Apply comma-separated name=limit overrides to the defaults; 0 removes a limit."""
    limits = dict(DEFAULT_SCANNER_PROCESS_LIMITS)
    for entry in raw.split(","):
        if not entry.strip():
            continue
        name, separator, value = (part.strip() for part in entry.partition("="))
        if not separator or name not in SCANNER_BINARIES or not value.isdigit():
            raise ValueError(f"Invalid SCANNER_PROCESS_LIMITS entry: {entry.strip()!r}")
        if int(value):
            limits[name] = int(value)
        else:
            limits.pop(name, None)
    return limits


SCANNER_PROCESS_LIMITS = scanner_process_limits(os.getenv("SCANNER_PROCESS_LIMITS", ""))
SCAN_STATUSES = ("queued", "running", "completed", "partial", "failed")
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CATEGORIES = ("sast", "secret", "dependency", "misconfiguration")
JOB_QUEUE: asyncio.Queue[str] = asyncio.Queue(maxsize=10)
RECOVERING = False
SCANNER_SLOTS: ScannerSlots | None = None
LOGGER = logging.getLogger("whitebox")


class Metrics:
    """Process-local counters for GET /api/metrics. They reset when the service restarts."""

    def __init__(self) -> None:
        self.active_scans = 0
        self.active_scanner_processes = 0
        self.scan_durations: dict[str, list[float]] = {}
        self.scanner_runs: dict[tuple[str, str], int] = {}
        self.scanner_durations: dict[str, list[float]] = {}

    def observe_scan(self, status: str, seconds: float) -> None:
        total = self.scan_durations.setdefault(status, [0.0, 0])
        total[0] += seconds
        total[1] += 1

    def observe_scanner(self, name: str, status: str, seconds: float) -> None:
        self.scanner_runs[(name, status)] = self.scanner_runs.get((name, status), 0) + 1
        total = self.scanner_durations.setdefault(name, [0.0, 0])
        total[0] += seconds
        total[1] += 1


METRICS = Metrics()


async def complete_thread_work(function: Any, *args: Any) -> Any:
    """Let filesystem work finish before cancellation triggers directory cleanup."""
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        with suppress(Exception, asyncio.CancelledError):
            task.result()
        raise


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect_db() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                finished_at TEXT,
                scanners_json TEXT NOT NULL,
                upload_bytes INTEGER NOT NULL,
                error TEXT,
                summary_json TEXT,
                scanner_results_json TEXT
            )"""
        )
        # Databases created before summaries were stored are upgraded in place.
        existing = {column["name"] for column in db.execute("PRAGMA table_info(scans)")}
        for column in ("summary_json", "scanner_results_json"):
            if column not in existing:
                try:
                    db.execute(f"ALTER TABLE scans ADD COLUMN {column} TEXT")
                except sqlite3.OperationalError as exc:
                    if "duplicate column" not in str(exc):
                        raise
        db.execute("CREATE INDEX IF NOT EXISTS scans_status_created_at ON scans (status, created_at)")
        db.execute("CREATE INDEX IF NOT EXISTS scans_created_at ON scans (created_at)")
        # Decisions are per project (the scan name) and match findings by match_key.
        db.execute(
            """CREATE TABLE IF NOT EXISTS triage_decisions (
                project TEXT NOT NULL,
                match_key TEXT NOT NULL,
                status TEXT NOT NULL,
                note TEXT,
                updated_at TEXT NOT NULL,
                scan_id TEXT,
                finding_id TEXT,
                cvss_vector TEXT,
                PRIMARY KEY (project, match_key)
            )"""
        )
        decision_columns = {column["name"] for column in db.execute("PRAGMA table_info(triage_decisions)")}
        for column, definition in (("cvss_vector", "TEXT"), ("decided_by", "TEXT NOT NULL DEFAULT 'manual'")):
            if column not in decision_columns:
                with suppress(sqlite3.OperationalError):
                    db.execute(f"ALTER TABLE triage_decisions ADD COLUMN {column} {definition}")


def job_dir(scan_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return DATA_DIR / "jobs" / scan_id


def get_scan_row(scan_id: str) -> sqlite3.Row | None:
    with connect_db() as db:
        return db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()


def update_scan(scan_id: str, **fields: Any) -> None:
    allowed = {"status", "updated_at", "finished_at", "error", "summary_json", "scanner_results_json"}
    unknown = set(fields) - allowed
    if unknown:
        # Dropping the whole update would silently lose status changes too.
        raise ValueError(f"Unsupported scan fields: {', '.join(sorted(unknown))}")
    if not fields:
        return
    names = list(fields)
    assignments = ", ".join(f"{name} = ?" for name in names)
    values = [fields[name] for name in names]
    with connect_db() as db:
        db.execute(f"UPDATE scans SET {assignments} WHERE id = ?", (*values, scan_id))


def scanner_inventory() -> list[dict[str, Any]]:
    inventory = []
    for name, binary in SCANNER_BINARIES.items():
        executable = shutil.which(binary)
        inventory.append({"name": name, "available": executable is not None})
    return inventory


def public_scan(row: sqlite3.Row, *, include_summary: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": row["id"],
        "name": row["name"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "finished_at": row["finished_at"],
        "scanners": json.loads(row["scanners_json"]),
        "upload_bytes": row["upload_bytes"],
        "error": row["error"],
    }
    if include_summary:
        if row["summary_json"] is not None:
            result["summary"] = json.loads(row["summary_json"])
            result["scanner_results"] = json.loads(row["scanner_results_json"] or "null")
            return result
        # Rows finished before summaries were stored: read the report once, then backfill.
        report_path = job_dir(row["id"]) / "report.json"
        if report_path.is_file():
            try:
                report = json.loads(report_path.read_text("utf-8"))
                result["summary"] = report.get("summary")
                result["scanner_results"] = report.get("scanners")
            except (OSError, json.JSONDecodeError):
                result["summary"] = None
            else:
                store_report_summary(row["id"], result["summary"], result["scanner_results"])
    return result


def store_report_summary(scan_id: str, summary: Any, scanner_results: Any) -> None:
    with connect_db() as db:
        db.execute(
            "UPDATE scans SET summary_json = ?, scanner_results_json = ? WHERE id = ? AND summary_json IS NULL",
            (json.dumps(summary), json.dumps(scanner_results), scan_id),
        )


def validate_zip_archive(path: Path) -> list[tuple[zipfile.ZipInfo, PurePosixPath]]:
    try:
        archive = zipfile.ZipFile(path)
        infos = archive.infolist()
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ValueError("Upload is not a valid ZIP archive") from exc

    if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
        raise ValueError(f"ZIP must contain between 1 and {MAX_ARCHIVE_ENTRIES} entries")

    expanded = 0
    seen: set[str] = set()
    validated: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
    with archive:
        for info in infos:
            raw_name = info.filename
            if not raw_name or "\x00" in raw_name or "\\" in raw_name or raw_name.startswith("/"):
                raise ValueError("ZIP contains an unsafe path")
            parts = raw_name.split("/")
            if any(part == ".." for part in parts) or (parts and ":" in parts[0]):
                raise ValueError("ZIP contains an unsafe path")
            relative = PurePosixPath(*[part for part in parts if part not in ("", ".")])
            if not relative.parts:
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("ZIP symlinks are not accepted")
            if info.flag_bits & 0x1:
                raise ValueError("Encrypted ZIP entries are not accepted")
            key = relative.as_posix().rstrip("/")
            if key in seen:
                raise ValueError("ZIP contains duplicate paths")
            seen.add(key)
            if not info.is_dir():
                expanded += info.file_size
                if info.file_size < 0 or expanded > MAX_EXPANDED_BYTES:
                    raise ValueError(f"Expanded ZIP size exceeds {MAX_EXPANDED_BYTES} bytes")
            validated.append((info, relative))
    return validated


def extract_zip(path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    validated = validate_zip_archive(path)
    total_written = 0
    with zipfile.ZipFile(path) as archive:
        for info, relative in validated:
            target = destination.joinpath(*relative.parts)
            resolved = target.resolve()
            if not resolved.is_relative_to(destination.resolve()):
                raise ValueError("ZIP contains an unsafe path")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info, "r") as source, target.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    written += len(chunk)
                    total_written += len(chunk)
                    if total_written > MAX_EXPANDED_BYTES or written > info.file_size:
                        raise ValueError("Expanded ZIP size exceeded the configured limit")
                    output.write(chunk)
            if written != info.file_size:
                raise ValueError("ZIP entry size did not match its directory record")
    children = list(destination.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return destination


def clean_text(value: Any, limit: int = 2000) -> str:
    text = "".join(character if character.isprintable() or character == "\t" else " " for character in str(value or ""))
    text = text.replace("\x00", " ").strip()
    return text[:limit]


def normalized_path(value: Any, source_root: Path) -> str | None:
    if not value:
        return None
    raw = str(value).replace("\\", "/")
    root = source_root.resolve().as_posix().rstrip("/")
    if raw.startswith(root + "/"):
        raw = raw[len(root) + 1 :]
    elif raw == root:
        return "."
    path = PurePosixPath(raw)
    if path.is_absolute():
        return path.name or None
    if any(part == ".." for part in path.parts):
        return path.name or None
    return clean_text(path.as_posix(), 1000)


def normalize_severity(value: Any) -> str:
    severity = str(value or "unknown").strip().lower()
    aliases = {"error": "high", "warning": "medium", "informational": "info", "none": "unknown"}
    severity = aliases.get(severity, severity)
    return severity if severity in SEVERITIES else "unknown"


def make_finding(
    *,
    tool: str,
    category: str,
    severity: Any,
    title: Any,
    message: Any = "",
    path: Any = None,
    line: Any = None,
    end_line: Any = None,
    rule_id: Any = None,
    confidence: Any = None,
    references: Any = None,
    package: Any = None,
    package_version: Any = None,
    aliases: Any = None,
    source_root: Path,
) -> dict[str, Any]:
    try:
        start = int(line) if line is not None else None
    except (ValueError, TypeError):
        start = None
    try:
        end = int(end_line) if end_line is not None else None
    except (ValueError, TypeError):
        end = None
    refs = []
    if isinstance(references, str):
        references = [references]
    if isinstance(references, list):
        refs = [clean_text(ref, 500) for ref in references if isinstance(ref, str) and ref.startswith(("https://", "http://"))][:10]
    finding = {
        "tool": tool,
        "category": category,
        "severity": normalize_severity(severity),
        "title": clean_text(title or rule_id or "Potential issue", 240),
        "message": clean_text(message, 2000),
        "path": normalized_path(path, source_root),
        "line": start if start and start > 0 else None,
        "end_line": end if end and end > 0 else None,
        "rule_id": clean_text(rule_id, 200) or None,
        "confidence": clean_text(confidence, 40) or None,
        "references": refs,
        "triage_status": "needs_review",
    }
    fingerprint = "|".join(
        str(finding[key] or "") for key in ("tool", "rule_id", "path", "line", "title")
    )
    finding["id"] = hashlib.sha256(fingerprint.encode("utf-8", "replace")).hexdigest()[:24]
    # Package details let dependency findings from different scanners be matched.
    if package:
        finding["package"] = clean_text(package, 200)
        finding["package_version"] = clean_text(package_version, 100) or None
        finding["aliases"] = sorted({clean_text(alias, 100) for alias in aliases or [] if isinstance(alias, str) and alias})[:20]
    return finding


def parse_semgrep(data: Any, source_root: Path) -> list[dict[str, Any]]:
    findings = []
    for item in data.get("results", []) if isinstance(data, dict) else []:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        title = (extra.get("message") or item.get("check_id") or "Semgrep finding").splitlines()[0]
        findings.append(
            make_finding(
                tool="semgrep",
                category="sast",
                severity=extra.get("severity"),
                title=title,
                message=extra.get("message"),
                path=item.get("path"),
                line=(item.get("start") or {}).get("line"),
                end_line=(item.get("end") or {}).get("line"),
                rule_id=item.get("check_id"),
                confidence=metadata.get("confidence"),
                references=metadata.get("references"),
                source_root=source_root,
            )
        )
    return findings


def parse_gitleaks(data: Any, source_root: Path) -> list[dict[str, Any]]:
    findings = []
    for item in data if isinstance(data, list) else []:
        rule = item.get("RuleID") or item.get("rule") or "secret-pattern"
        findings.append(
            make_finding(
                tool="gitleaks",
                category="secret",
                severity="high",
                title=f"Potential secret: {rule}",
                message="A secret pattern matched. The matched value is redacted.",
                path=item.get("File") or item.get("file"),
                line=item.get("StartLine") or item.get("startLine"),
                rule_id=rule,
                references=item.get("References"),
                source_root=source_root,
            )
        )
    return findings


def parse_trivy(data: Any, source_root: Path) -> list[dict[str, Any]]:
    findings = []
    results = data.get("Results", []) if isinstance(data, dict) else []
    for result in results:
        target = result.get("Target")
        for item in result.get("Vulnerabilities") or []:
            refs = [item.get("PrimaryURL")] if item.get("PrimaryURL") else []
            vuln_id = item.get("VulnerabilityID") or item.get("PkgName") or "dependency-vulnerability"
            package = item.get("PkgName") or "package"
            installed = item.get("InstalledVersion") or "unknown version"
            fixed = item.get("FixedVersion")
            message = f"{package} {installed} is affected."
            if fixed:
                message += f" Fixed version: {fixed}."
            finding = make_finding(
                    tool="trivy",
                    category="dependency",
                    severity=item.get("Severity"),
                    title=item.get("Title") or vuln_id,
                    message=message,
                    path=target,
                    line=None,
                    rule_id=vuln_id,
                    references=refs,
                    package=item.get("PkgName"),
                    package_version=item.get("InstalledVersion"),
                    aliases=item.get("VendorIDs"),
                    source_root=source_root,
                )
            finding["ecosystem"] = clean_text(result.get("Type"), 40) or None
            finding["advisory_cvss"] = trivy_advisory_cvss(item)
            findings.append(finding)
        for item in result.get("Misconfigurations") or []:
            cause = item.get("CauseMetadata") or {}
            findings.append(
                make_finding(
                    tool="trivy",
                    category="misconfiguration",
                    severity=item.get("Severity"),
                    title=item.get("Title") or item.get("ID") or "Configuration issue",
                    message=item.get("Message") or item.get("Resolution"),
                    path=target,
                    line=cause.get("StartLine"),
                    end_line=cause.get("EndLine"),
                    rule_id=item.get("ID"),
                    references=item.get("References"),
                    source_root=source_root,
                )
            )
        for item in result.get("Secrets") or []:
            secret_rule = item.get("RuleID") or "secret-pattern"
            findings.append(
                make_finding(
                    tool="trivy",
                    category="secret",
                    severity=item.get("Severity"),
                    title=item.get("Title") or f"Potential secret: {secret_rule}",
                    message="A secret pattern matched. The matched value is redacted.",
                    path=target,
                    line=item.get("StartLine"),
                    end_line=item.get("EndLine"),
                    rule_id=secret_rule,
                    source_root=source_root,
                )
            )
    return findings


def trivy_advisory_cvss(item: dict[str, Any]) -> dict[str, Any] | None:
    sources = item.get("CVSS") or {}
    preferred = [item.get("SeveritySource"), "ghsa", "nvd", "redhat"]
    for name in [name for name in preferred if name] + [name for name in sources if name not in preferred]:
        vector = (sources.get(name) or {}).get("V3Vector")
        if isinstance(vector, str) and whitebox_evidence.valid_vector(vector):
            return {"vector": vector, "score": (sources[name] or {}).get("V3Score"), "source": name}
    return None


def osv_advisory_cvss(vulnerability: dict[str, Any]) -> dict[str, Any] | None:
    for entry in vulnerability.get("severity") or []:
        vector = entry.get("score") if isinstance(entry, dict) else None
        if isinstance(vector, str) and whitebox_evidence.valid_vector(vector):
            return {"vector": vector, "score": whitebox_evidence.cvss31_base_score(vector), "source": "osv"}
    return None


def osv_affected_symbols(vulnerability: dict[str, Any]) -> list[str]:
    """Vulnerable functions named by the advisory (Go advisories list them)."""
    symbols: list[str] = []
    for affected in vulnerability.get("affected") or []:
        specific = (affected or {}).get("ecosystem_specific") or {}
        for imported in specific.get("imports") or []:
            symbols.extend(str(symbol) for symbol in imported.get("symbols") or [])
        symbols.extend(str(symbol) for symbol in specific.get("affected_functions") or [])
    return sorted({clean_text(symbol, 200) for symbol in symbols if symbol})[:50]


def osv_severity(vulnerability: dict[str, Any]) -> str:
    database = vulnerability.get("database_specific") or {}
    direct = database.get("severity") or database.get("max_severity")
    if direct:
        severity = normalize_severity(direct)
        if severity != "unknown":
            return severity
    for score in vulnerability.get("severity") or []:
        raw = score.get("score") if isinstance(score, dict) else None
        try:
            numeric = float(raw)
        except (TypeError, ValueError):
            continue
        if numeric >= 9:
            return "critical"
        if numeric >= 7:
            return "high"
        if numeric >= 4:
            return "medium"
        return "low"
    return "unknown"


def osv_fixed_versions(vulnerability: dict[str, Any]) -> list[str]:
    fixed: set[str] = set()
    for affected in vulnerability.get("affected") or []:
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                if event.get("fixed"):
                    fixed.add(str(event["fixed"]))
    return sorted(fixed)[:10]


def parse_osv(data: Any, source_root: Path) -> list[dict[str, Any]]:
    findings = []
    for result in data.get("results", []) if isinstance(data, dict) else []:
        source = result.get("source") or {}
        source_path = source.get("path")
        for package_result in result.get("packages") or []:
            package = package_result.get("package") or {}
            name = package.get("name") or "dependency"
            version = package.get("version") or "unknown version"
            for vulnerability in package_result.get("vulnerabilities") or []:
                vuln_id = vulnerability.get("id") or "OSV vulnerability"
                aliases = vulnerability.get("aliases") or []
                summary = vulnerability.get("summary") or vulnerability.get("details") or "Known vulnerability in dependency."
                fixed = osv_fixed_versions(vulnerability)
                message = f"{name} {version}: {clean_text(summary, 1000)}"
                if fixed:
                    message += " Fixed version(s): " + ", ".join(fixed) + "."
                refs = [ref.get("url") for ref in vulnerability.get("references") or [] if isinstance(ref, dict)]
                finding = make_finding(
                        tool="osv-scanner",
                        category="dependency",
                        severity=osv_severity(vulnerability),
                        title=f"{vuln_id}: {clean_text(summary, 180)}",
                        message=message,
                        path=source_path,
                        rule_id=vuln_id,
                        references=refs,
                        package=package.get("name"),
                        package_version=package.get("version"),
                        aliases=aliases,
                        source_root=source_root,
                    )
                finding["ecosystem"] = clean_text(package.get("ecosystem"), 40) or None
                finding["advisory_cvss"] = osv_advisory_cvss(vulnerability)
                finding["affected_symbols"] = osv_affected_symbols(vulnerability)
                findings.append(finding)
    return findings


JOERN_RESULT = re.compile(r"^Result:\s*(?P<score>[0-9]+(?:\.[0-9]+)?)\s*:\s*(?P<title>.*?):\s*(?P<location>.+)$")


def parse_joern(path: Path, source_root: Path) -> list[dict[str, Any]]:
    findings = []
    if not path.is_file():
        return findings
    for raw_line in path.read_text("utf-8", errors="replace").splitlines():
        match = JOERN_RESULT.match(raw_line.strip())
        if not match:
            continue
        location = match.group("location").rsplit(":", 2)
        if len(location) != 3 or not location[1].isdigit():
            continue
        score = float(match.group("score"))
        severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
        findings.append(
            make_finding(
                tool="joern",
                category="sast",
                severity=severity,
                title=match.group("title"),
                message=f"Joern query score: {score:g}.",
                path=location[0],
                line=location[1],
                rule_id=match.group("title"),
                source_root=source_root,
            )
        )
    return findings


def parse_dataflow(data: Any, source_root: Path) -> list[dict[str, Any]]:
    findings = []
    for item in data.get("findings", []) if isinstance(data, dict) else []:
        details = whitebox_dataflow.VULN_CLASSES.get(item.get("class")) if isinstance(item, dict) else None
        if details is None:
            continue
        trace = []
        for step in item.get("trace", [])[:20]:
            if not isinstance(step, dict):
                continue
            line = step.get("line")
            trace.append({
                "kind": clean_text(step.get("kind"), 20),
                "path": normalized_path(step.get("path"), source_root),
                "line": line if isinstance(line, int) and line > 0 else None,
                "detail": clean_text(step.get("detail"), 300),
            })
        steps = " → ".join(f"{step['detail']} ({step['path']}:{step['line']})" for step in trace)
        finding = make_finding(
            tool="dataflow",
            category="sast",
            severity=details["severity"],
            title=f"{details['title']}: request input reaches {details['sink']}",
            message=steps or f"Request input reaches {details['sink']}.",
            path=item.get("path"),
            line=item.get("line"),
            end_line=item.get("end_line"),
            rule_id=f"dataflow.{clean_text(item.get('language'), 20)}.{item['class']}",
            # Flows through summarized helpers match functions by name, so they are less certain.
            confidence="medium" if item.get("interprocedural") else "high",
            references=[f"https://cwe.mitre.org/data/definitions/{details['cwe'].split('-')[1]}.html"],
            source_root=source_root,
        )
        finding["cwe"] = details["cwe"]
        finding["trace"] = trace
        findings.append(finding)
    return findings


def scanner_command(name: str, source_root: Path, raw_output: Path) -> list[str]:
    binary = SCANNER_BINARIES[name]
    if name == "semgrep":
        return [binary, "scan", "--config", "p/default", "--json", "--output", str(raw_output), "--metrics=off", "--timeout", "30", "--jobs", "2", str(source_root)]
    if name == "gitleaks":
        return [binary, "dir", "--no-banner", "--no-color", "--redact=100", "--exit-code", "0", "--report-format", "json", "--report-path", str(raw_output), str(source_root)]
    if name == "trivy":
        return [binary, "fs", "--format", "json", "--output", str(raw_output), "--scanners", "vuln,misconfig,secret", "--exit-code", "0", "--no-progress", "--disable-telemetry", "--timeout", "10m", "--cache-dir", str(DATA_DIR / "cache" / "trivy"), str(source_root)]
    if name == "osv-scanner":
        return [binary, "scan", "source", "-r", str(source_root), "--format", "json"]
    if name == "joern":
        return [binary, str(source_root), "--overwrite"]
    if name == "dataflow":
        # Leave the analysis time to finish its last pass and write a report.
        deadline = max(SCAN_TIMEOUT_SECONDS - 30, 30)
        script = Path(whitebox_dataflow.__file__).resolve()
        return [sys.executable, str(script), "--output", str(raw_output), "--deadline", str(deadline), str(source_root)]
    raise ValueError("Unsupported scanner")


def parse_scanner_output(name: str, raw_output: Path, source_root: Path) -> list[dict[str, Any]]:
    if name == "joern":
        if not raw_output.is_file() or raw_output.stat().st_size > 100 * 1024 * 1024:
            raise ValueError("Missing or oversized scanner report")
        return parse_joern(raw_output, source_root)
    if not raw_output.is_file() or raw_output.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("Missing or oversized scanner report")
    data = json.loads(raw_output.read_text("utf-8", errors="replace"))
    parsers = {
        "semgrep": parse_semgrep,
        "gitleaks": parse_gitleaks,
        "trivy": parse_trivy,
        "osv-scanner": parse_osv,
        "dataflow": parse_dataflow,
    }
    return parsers[name](data, source_root)


def osv_found_no_manifests(stderr_path: Path) -> bool:
    try:
        with stderr_path.open("rb") as handle:
            handle.seek(max(stderr_path.stat().st_size - 4096, 0))
            tail = handle.read().decode("utf-8", "replace")
    except OSError:
        return False
    return "No package sources found" in tail


async def terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except asyncio.TimeoutError:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(Exception):
            await process.wait()


async def run_scanner(name: str, source_root: Path, work_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw_output = work_dir / ("joern.txt" if name == "joern" else f"{name}.json")
    stderr_path = work_dir / f"{name}.stderr"
    stdout_path = raw_output if name in ("osv-scanner", "joern") else work_dir / f"{name}.stdout"
    started = time.monotonic()
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(DATA_DIR / "home"),
            "XDG_CACHE_HOME": str(DATA_DIR / "cache"),
            "SEMGREP_SEND_METRICS": "off",
        }
    )
    try:
        with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
            process = await asyncio.create_subprocess_exec(
                *scanner_command(name, source_root, raw_output),
                # joern-scan writes its workspace into the working directory; keep it
                # out of the source tree that other scanners may be reading.
                cwd=str(work_dir if name == "joern" else source_root),
                env=env,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
            try:
                await asyncio.wait_for(process.wait(), timeout=SCAN_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                await terminate_process(process)
                return (
                    {"name": name, "status": "timed_out", "exit_code": process.returncode, "duration_seconds": round(time.monotonic() - started, 2), "finding_count": 0, "error": "Scanner exceeded the configured time limit."},
                    [],
                )
    except FileNotFoundError:
        return (
            {"name": name, "status": "failed", "exit_code": None, "duration_seconds": round(time.monotonic() - started, 2), "finding_count": 0, "error": "Scanner executable is unavailable."},
            [],
        )
    except asyncio.CancelledError:
        if "process" in locals():
            await terminate_process(process)
        raise
    except Exception:
        return (
            {"name": name, "status": "failed", "exit_code": None, "duration_seconds": round(time.monotonic() - started, 2), "finding_count": 0, "error": "Scanner could not be started."},
            [],
        )

    if name == "osv-scanner" and process.returncode == 128 and osv_found_no_manifests(stderr_path):
        # A project without dependency manifests has nothing for OSV to check; that is not a failure.
        return (
            {"name": name, "status": "completed", "exit_code": process.returncode, "duration_seconds": round(time.monotonic() - started, 2), "finding_count": 0, "error": None, "note": "No dependency manifests or lockfiles found."},
            [],
        )
    try:
        findings = parse_scanner_output(name, raw_output, source_root)
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return (
            {"name": name, "status": "failed", "exit_code": process.returncode, "duration_seconds": round(time.monotonic() - started, 2), "finding_count": 0, "error": "Scanner did not produce a readable report."},
            [],
        )
    if process.returncode not in (0, 1):
        return (
            {"name": name, "status": "failed", "exit_code": process.returncode, "duration_seconds": round(time.monotonic() - started, 2), "finding_count": len(findings), "error": "Scanner exited with an error; any parsed findings may be incomplete."},
            findings,
        )
    return (
        {"name": name, "status": "completed", "exit_code": process.returncode, "duration_seconds": round(time.monotonic() - started, 2), "finding_count": len(findings), "error": None},
        findings,
    )


class ScannerSlots:
    """Scanner process limits shared by every scan on one event loop."""

    def __init__(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.total = asyncio.Semaphore(MAX_SCANNER_PROCESSES)
        self.per_scanner = {name: asyncio.Semaphore(limit) for name, limit in SCANNER_PROCESS_LIMITS.items()}

    @asynccontextmanager
    async def acquire(self, name: str):
        async with AsyncExitStack() as stack:
            if name in self.per_scanner:
                # Wait for the tool's own slot first so a blocked scanner does
                # not hold one of the shared process slots.
                await stack.enter_async_context(self.per_scanner[name])
            await stack.enter_async_context(self.total)
            yield


def scanner_slots() -> ScannerSlots:
    global SCANNER_SLOTS
    if SCANNER_SLOTS is None or SCANNER_SLOTS.loop is not asyncio.get_running_loop():
        SCANNER_SLOTS = ScannerSlots()
    return SCANNER_SLOTS


async def run_scanner_in_slot(name: str, source_root: Path, work_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    async with scanner_slots().acquire(name):
        METRICS.active_scanner_processes += 1
        try:
            scanner_result, findings = await run_scanner(name, source_root, work_dir)
        finally:
            METRICS.active_scanner_processes -= 1
    METRICS.observe_scanner(name, str(scanner_result.get("status", "unknown")), float(scanner_result.get("duration_seconds") or 0))
    return scanner_result, findings


async def run_scanners(names: list[str], source_root: Path, work_dir: Path) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    """Run a scan's scanners and return their results in the requested order."""
    if SCANNER_PARALLELISM <= 1 or len(names) <= 1:
        return [await run_scanner_in_slot(name, source_root, work_dir) for name in names]
    parallel = asyncio.Semaphore(SCANNER_PARALLELISM)

    async def run_one(name: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        async with parallel:
            return await run_scanner_in_slot(name, source_root, work_dir)

    # Cancelling the scan cancels every task here; run_scanner then stops its process group.
    async with asyncio.TaskGroup() as group:
        tasks = [group.create_task(run_one(name), name=f"whitebox-scanner-{name}") for name in names]
    return [task.result() for task in tasks]


def summarize(findings: list[dict[str, Any]], scanners: list[dict[str, Any]]) -> dict[str, Any]:
    severities = {severity: 0 for severity in SEVERITIES}
    by_tool: dict[str, int] = {}
    for finding in findings:
        severities[finding["severity"]] += 1
        by_tool[finding["tool"]] = by_tool.get(finding["tool"], 0) + 1
    return {
        "total_findings": len(findings),
        "severity": severities,
        "by_tool": by_tool,
        "scanners_completed": sum(1 for scanner in scanners if scanner["status"] == "completed"),
        "scanners_failed": sum(1 for scanner in scanners if scanner["status"] != "completed"),
        "findings_truncated": False,
    }


# False-positive checks only advise. They set fp_check on a finding and never
# change triage_status, which only a person or an agent may set.
TEST_DIRECTORIES = frozenset({"test", "tests", "__tests__", "testing", "spec", "specs", "testdata", "test_data", "fixture", "fixtures", "mocks", "__mocks__"})
EXAMPLE_DIRECTORIES = frozenset({"example", "examples", "sample", "samples", "demo", "demos", "doc", "docs"})
VENDORED_DIRECTORIES = frozenset({"node_modules", "vendor", "third_party", "third-party", "bower_components", "site-packages", ".venv", "venv"})
TEST_FILE = re.compile(r"(^test_.+\.py$|_test\.(py|go)$|\.(test|spec)\.[cm]?[jt]sx?$|Tests?\.(java|kt|cs)$)")
EXAMPLE_FILE = re.compile(r"(\.(example|sample|template|dist)$|\.md$|\.rst$)", re.IGNORECASE)
GENERATED_FILE = re.compile(r"\.(min\.js|min\.css|bundle\.js|map)$", re.IGNORECASE)
PLACEHOLDER_MARKERS = ("example", "dummy", "placeholder", "changeme", "change_me", "your_", "your-", "<your", "xxxx", "fake", "redacted", "insert_")
ENVIRONMENT_MARKERS = ("os.environ", "getenv(", "process.env", "env(", "${", "{{")
SUPPRESSION_MARKERS = ("nosec", "noqa", "nosemgrep", "gitleaks:allow", "trivy:ignore", "nosonar", "lgtm[", "pragma: allowlist secret")
TRIAGE_STATUSES = ("needs_review", "confirmed", "false_positive", "accepted_risk", "fixed")
FP_VERDICTS = ("needs_review", "likely_false_positive", "duplicate")
MAX_CONTEXT_FILE_BYTES = 5 * 1024 * 1024


def path_kind(path: str) -> str | None:
    parts = [part.lower() for part in PurePosixPath(path).parts]
    name = PurePosixPath(path).name
    if any(part in VENDORED_DIRECTORIES for part in parts[:-1]):
        return "vendored"
    if any(part in TEST_DIRECTORIES for part in parts[:-1]) or TEST_FILE.search(name):
        return "test"
    if any(part in EXAMPLE_DIRECTORIES for part in parts[:-1]) or EXAMPLE_FILE.search(name):
        return "example"
    if GENERATED_FILE.search(name):
        return "generated"
    return None


class SourceLines:
    """Read finding lines from the extracted source; never follows paths outside it."""

    def __init__(self, source_root: Path) -> None:
        self.root = source_root.resolve()
        self.files: dict[str, list[str] | None] = {}

    def get(self, path: str | None, line: int | None) -> str | None:
        if not path or not line:
            return None
        if path not in self.files:
            self.files[path] = None
            target = (self.root / path).resolve()
            if target.is_relative_to(self.root) and target.is_file() and target.stat().st_size <= MAX_CONTEXT_FILE_BYTES:
                with suppress(OSError):
                    self.files[path] = target.read_text("utf-8", errors="replace").splitlines()
        lines = self.files[path]
        if lines is None or not 1 <= line <= len(lines):
            return None
        return lines[line - 1]


def finding_match_key(finding: dict[str, Any], line_text: str | None = None) -> str:
    """Key that recognizes the same finding in a later scan of the project."""
    base = [finding.get("tool"), finding.get("rule_id"), finding.get("path")]
    if finding.get("category") == "dependency":
        parts = [*base, (finding.get("package") or "").lower()]
    elif finding.get("category") != "secret" and line_text is not None and line_text.strip():
        # Code content survives edits that move the line. Secrets are keyed by
        # position instead, so no hash of a secret-bearing line is stored.
        parts = [*base, " ".join(line_text.split())]
    else:
        parts = [*base, finding.get("line")]
    return hashlib.sha256("|".join(str(part or "") for part in parts).encode("utf-8", "replace")).hexdigest()[:32]


def check_false_positives(findings: list[dict[str, Any]], source_root: Path) -> None:
    """Add fp_check and match_key to each finding while the source is still extracted."""
    lines = SourceLines(source_root)
    canonical: dict[tuple[str, str, str], str] = {}
    for finding in findings:
        reasons: list[str] = []
        likely_false = False
        path = finding.get("path") or ""
        category = finding.get("category")
        line_text = lines.get(path, finding.get("line"))
        kind = path_kind(path) if path else None
        if kind in ("test", "example"):
            likely_false = True
            reasons.append("In test code or fixtures." if kind == "test" else "In an example, template or documentation file.")
        elif kind == "vendored":
            reasons.append("In vendored third-party code; fix it upstream or by updating the dependency.")
        elif kind == "generated":
            reasons.append("In a generated or minified file; review the source it was built from.")
        if line_text is not None:
            lowered = line_text.lower()
            nearby = lowered
            previous = (lines.get(path, finding["line"] - 1) or "").strip().lower()
            # A marker on the line above counts only on a comment line of its own,
            # not as a trailing comment that belongs to the previous statement.
            if previous.startswith(("#", "//", "/*", "*", "--")):
                nearby += "\n" + previous
            suppression = next((marker for marker in SUPPRESSION_MARKERS if marker in nearby), None)
            if suppression:
                likely_false = True
                reasons.append(f"Suppressed inline with '{suppression}'.")
            if category == "secret":
                if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
                    likely_false = True
                    reasons.append("The value looks like a placeholder or documentation example.")
                elif any(marker in lowered for marker in ENVIRONMENT_MARKERS):
                    likely_false = True
                    reasons.append("The value is read from the environment or a template variable.")
        verdict = "likely_false_positive" if likely_false else "needs_review"
        duplicate_of = None
        if category == "dependency" and finding.get("package"):
            package = (finding["package"].lower(), finding.get("package_version") or "")
            keys = [(*package, identifier) for identifier in {finding.get("rule_id"), *finding.get("aliases", [])} if identifier]
            duplicate_of = next((canonical[key] for key in keys if key in canonical), None)
            for key in keys:
                canonical.setdefault(key, duplicate_of or finding["id"])
            if duplicate_of:
                verdict = "duplicate"
                reasons.append(f"Same vulnerability and package version as finding {duplicate_of}.")
        elif category == "secret" and path and finding.get("line"):
            # Gitleaks and Trivy both report most secrets; one decision should cover both.
            key = ("secret", path, str(finding["line"]))
            duplicate_of = canonical.setdefault(key, finding["id"])
            if duplicate_of != finding["id"]:
                verdict = "duplicate"
                reasons.append(f"Same secret location as finding {duplicate_of}.")
            else:
                duplicate_of = None
        finding["fp_check"] = {"verdict": verdict, "reasons": reasons, "duplicate_of": duplicate_of}
        finding["match_key"] = finding_match_key(finding, line_text)


def triage_summary(findings: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    verdicts = dict.fromkeys(FP_VERDICTS, 0)
    statuses = dict.fromkeys(TRIAGE_STATUSES, 0)
    for finding in findings:
        verdict = (finding.get("fp_check") or {}).get("verdict", "needs_review")
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        status = finding.get("triage_status", "needs_review")
        statuses[status] = statuses.get(status, 0) + 1
    return {"fp_check": verdicts, "triage": statuses}


def apply_triage_decisions(project: str, findings: list[dict[str, Any]]) -> None:
    """Carry triage decisions made on earlier scans of the same project forward."""
    keys = [finding["match_key"] for finding in findings if finding.get("match_key")]
    if not keys:
        return
    decisions: dict[str, sqlite3.Row] = {}
    with connect_db() as db:
        for start in range(0, len(keys), 500):
            chunk = keys[start : start + 500]
            placeholders = ",".join("?" * len(chunk))
            for row in db.execute(
                f"SELECT * FROM triage_decisions WHERE project = ? AND match_key IN ({placeholders})", (project, *chunk)
            ):
                decisions[row["match_key"]] = row
    for finding in findings:
        decision = decisions.get(finding.get("match_key"))
        if decision is not None:
            finding["triage_status"] = decision["status"]
            finding["triage_note"] = decision["note"]
            finding["triage_updated_at"] = decision["updated_at"]
            finding["triage_source"] = "earlier_scan"
            finding["triage_cvss_vector"] = decision["cvss_vector"]
            finding["triage_decided_by"] = decision["decided_by"]


async def process_scan(scan_id: str) -> None:
    row = get_scan_row(scan_id)
    if row is None:
        return
    directory = job_dir(scan_id)
    upload_path = directory / "source.zip"
    work_dir = directory / "work"
    extract_dir = directory / "source"
    update_scan(scan_id, status="running", updated_at=utc_now(), error=None)
    interrupted = False
    started = time.monotonic()
    METRICS.active_scans += 1
    try:
        source_root = await complete_thread_work(extract_zip, upload_path, extract_dir)
        scanners: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        work_dir.mkdir(parents=True, exist_ok=True)
        results = await run_scanners(json.loads(row["scanners_json"]), source_root, work_dir)
        # Merge in requested order so parallel runs dedupe and truncate exactly like sequential ones.
        for scanner_result, scanner_findings in results:
            scanners.append(scanner_result)
            for finding in scanner_findings:
                if finding["id"] in seen:
                    continue
                seen.add(finding["id"])
                if len(findings) < MAX_FINDINGS:
                    findings.append(finding)
        truncated = len(seen) > len(findings)
        # Runs before cleanup because some checks read the finding's source line.
        await complete_thread_work(check_false_positives, findings, source_root)
        apply_triage_decisions(row["name"], findings)
        await complete_thread_work(whitebox_evidence.assess, findings, source_root)
        await complete_thread_work(whitebox_verify.attach_context, findings, source_root)
        verification = await run_verification(row["name"], scan_id, findings)
        report = {
            "scan_id": scan_id,
            "created_at": row["created_at"],
            "finished_at": utc_now(),
            "summary": summarize(findings, scanners),
            "scanners": scanners,
            "findings": findings,
            "triage_note": "Scanner output is candidate evidence. Review each result in source context before treating it as a vulnerability.",
            "verification": verification,
        }
        report["summary"]["findings_truncated"] = truncated
        report["summary"].update(triage_summary(findings))
        report["summary"].update(whitebox_evidence.summary(findings))
        report_path = directory / "report.json"
        temporary_report = directory / "report.json.tmp"
        temporary_report.write_text(json.dumps(report, ensure_ascii=False, indent=2), "utf-8")
        temporary_report.replace(report_path)
        completed = sum(scanner["status"] == "completed" for scanner in scanners)
        if completed == len(scanners):
            status = "completed"
        elif completed:
            status = "partial"
        else:
            status = "failed"
        update_scan(
            scan_id,
            status=status,
            updated_at=utc_now(),
            finished_at=utc_now(),
            error=None,
            summary_json=json.dumps(report["summary"]),
            scanner_results_json=json.dumps(scanners),
        )
        METRICS.observe_scan(status, time.monotonic() - started)
    except asyncio.CancelledError:
        interrupted = True
        update_scan(scan_id, status="queued", updated_at=utc_now(), error="Service restarted while this scan was running.")
        raise
    except Exception as exc:
        message = "Source archive could not be extracted." if isinstance(exc, (ValueError, zipfile.BadZipFile)) else "Scan could not be completed."
        update_scan(scan_id, status="failed", updated_at=utc_now(), finished_at=utc_now(), error=message)
        METRICS.observe_scan("failed", time.monotonic() - started)
    finally:
        METRICS.active_scans -= 1
        shutil.rmtree(work_dir, ignore_errors=True)
        shutil.rmtree(extract_dir, ignore_errors=True)
        if not interrupted:
            with suppress(OSError):
                upload_path.unlink()


async def queue_worker() -> None:
    while True:
        scan_id = await JOB_QUEUE.get()
        try:
            await process_scan(scan_id)
        finally:
            JOB_QUEUE.task_done()


def recover_and_prune() -> list[str]:
    prune_expired()
    with connect_db() as db:
        rows = db.execute("SELECT * FROM scans WHERE status IN ('queued', 'running') ORDER BY created_at").fetchall()
        for row in rows:
            if row["status"] == "running":
                db.execute(
                    "UPDATE scans SET status = 'queued', updated_at = ?, error = ? WHERE id = ?",
                    (utc_now(), "Service restarted while this scan was running.", row["id"]),
                )
    with connect_db() as db:
        rows = db.execute("SELECT id FROM scans WHERE status = 'queued' ORDER BY created_at").fetchall()
    pending = []
    for row in rows:
        directory = job_dir(row["id"])
        if (directory / "source.zip").is_file():
            # A hard restart can leave an incomplete extraction or scanner output.
            shutil.rmtree(directory / "source", ignore_errors=True)
            shutil.rmtree(directory / "work", ignore_errors=True)
            pending.append(row["id"])
        else:
            update_scan(row["id"], status="failed", updated_at=utc_now(), finished_at=utc_now(), error="Queued upload is no longer available.")
    return pending


def prune_expired() -> int:
    # utc_now() is the only writer of created_at and produces fixed-width UTC
    # ISO-8601 text, so string order is time order and the index can be used.
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat(timespec="seconds")
    with connect_db() as db:
        rows = db.execute(
            "SELECT id FROM scans WHERE status IN ('completed', 'partial', 'failed') AND created_at < ?",
            (cutoff,),
        ).fetchall()
    # Remove files outside any write transaction so slow disks never block other writers.
    for row in rows:
        shutil.rmtree(job_dir(row["id"]), ignore_errors=True)
        with connect_db() as db:
            db.execute("DELETE FROM scans WHERE id = ?", (row["id"],))
    return len(rows)


async def prune_periodically() -> None:
    while True:
        await asyncio.sleep(PRUNE_INTERVAL_SECONDS)
        try:
            await complete_thread_work(prune_expired)
        except Exception:
            LOGGER.exception("Pruning expired scans failed; retrying in %s seconds", PRUNE_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global JOB_QUEUE, RECOVERING, SCANNER_SLOTS
    JOB_QUEUE = asyncio.Queue(maxsize=10)
    SCANNER_SLOTS = None
    initialize_storage()
    pending = recover_and_prune()
    initial = pending[:JOB_QUEUE.maxsize]
    for scan_id in initial:
        JOB_QUEUE.put_nowait(scan_id)
    RECOVERING = len(pending) > len(initial)

    async def feed_recovered_jobs() -> None:
        global RECOVERING
        for scan_id in pending[len(initial):]:
            await JOB_QUEUE.put(scan_id)
        RECOVERING = False

    workers = [
        asyncio.create_task(queue_worker(), name=f"whitebox-scan-worker-{index}")
        for index in range(SCAN_CONCURRENCY)
    ]
    recovery = asyncio.create_task(feed_recovered_jobs(), name="whitebox-queue-recovery")
    pruner = asyncio.create_task(prune_periodically(), name="whitebox-pruner")
    try:
        # Even an oversized durable backlog must not block API startup.
        yield
    finally:
        for task in (recovery, pruner):
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        # Each interrupted scan goes back to queued with its upload kept for retry.
        for worker in workers:
            worker.cancel()
        for worker in workers:
            with suppress(asyncio.CancelledError):
                await worker
        RECOVERING = False


app = FastAPI(
    title="Whitebox Vulnerability Check Service",
    description="Self-hosted source archive scanning with open tools and normalized JSON findings.",
    version="0.1.0",
    lifespan=lifespan,
)


class UploadLimitMiddleware:
    def __init__(self, application: Any, max_request_bytes: int):
        self.application = application
        self.max_request_bytes = max_request_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        is_upload = scope.get("type") == "http" and scope.get("method") == "POST" and scope.get("path") == "/api/scans"
        if not is_upload:
            await self.application(scope, receive, send)
            return
        content_length = next((value for key, value in scope.get("headers", []) if key == b"content-length"), None)
        if content_length:
            try:
                if int(content_length) > self.max_request_bytes:
                    await JSONResponse(status_code=413, content={"detail": "Request body exceeds the upload limit."})(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})(scope, receive, send)
                return

        received = 0
        exceeded = False
        response_started = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received, exceeded
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_request_bytes:
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if exceeded:
                return
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        await self.application(scope, limited_receive, guarded_send)
        if exceeded and not response_started:
            await JSONResponse(status_code=413, content={"detail": "Request body exceeds the upload limit."})(scope, receive, send)


app.add_middleware(UploadLimitMiddleware, max_request_bytes=MAX_UPLOAD_BYTES + 2 * 1024 * 1024)


def require_api_key(authorization: str | None = Header(default=None)) -> None:
    if API_KEY and not hmac.compare_digest(authorization or "", f"Bearer {API_KEY}"):
        raise HTTPException(status_code=401, detail="A valid bearer token is required")


api = APIRouter(prefix="/api", dependencies=[Depends(require_api_key)])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def home() -> dict[str, str]:
    return {"service": "Whitebox Vulnerability Check Service", "ui": "/ui/", "docs": "/docs", "health": "/health"}


@app.get("/ui", include_in_schema=False)
def ui_redirect() -> RedirectResponse:
    return RedirectResponse(url="/ui/", status_code=307)


@api.get("/scanners")
def get_scanners() -> dict[str, Any]:
    return {"scanners": scanner_inventory(), "default": list(DEFAULT_SCANNERS)}


def count_scans_by_status() -> dict[str, int]:
    counts = dict.fromkeys(SCAN_STATUSES, 0)
    with connect_db() as db:
        for row in db.execute("SELECT status, COUNT(*) AS total FROM scans GROUP BY status"):
            counts[row["status"]] = row["total"]
    return counts


def prometheus_label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_metrics(scans_by_status: dict[str, int]) -> str:
    lines: list[str] = []

    def family(name: str, kind: str, help_text: str, samples: list[tuple[str, dict[str, str], float]]) -> None:
        lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"))
        for suffix, labels, value in samples:
            label_text = ",".join(f'{key}="{prometheus_label(label)}"' for key, label in labels.items())
            number = str(value) if isinstance(value, int) else repr(round(float(value), 6))
            lines.append(f"{name}{suffix}{{{label_text}}} {number}" if labels else f"{name}{suffix} {number}")

    family("whitebox_queue_depth", "gauge", "Scans waiting in the queue.", [("", {}, JOB_QUEUE.qsize())])
    family("whitebox_queue_capacity", "gauge", "Scans the queue holds before uploads get 503.", [("", {}, JOB_QUEUE.maxsize)])
    family("whitebox_recovering", "gauge", "1 while recovered scans are still being queued after a restart.", [("", {}, int(RECOVERING))])
    family(
        "whitebox_scans", "gauge", "Stored scans by status.",
        [("", {"status": status}, total) for status, total in sorted(scans_by_status.items())],
    )
    family("whitebox_scan_workers", "gauge", "Scans this process can run at once (SCAN_CONCURRENCY).", [("", {}, SCAN_CONCURRENCY)])
    family("whitebox_active_scans", "gauge", "Scans this process is running now.", [("", {}, METRICS.active_scans)])
    family(
        "whitebox_scanner_process_limit", "gauge", "Scanner processes allowed at once (MAX_SCANNER_PROCESSES).",
        [("", {}, MAX_SCANNER_PROCESSES)],
    )
    family(
        "whitebox_active_scanner_processes", "gauge", "Scanner processes this process is running now.",
        [("", {}, METRICS.active_scanner_processes)],
    )
    scan_durations = {status: METRICS.scan_durations.get(status, [0.0, 0]) for status in ("completed", "partial", "failed")}
    family(
        "whitebox_scan_duration_seconds", "summary", "Time from scan start to finish since this process started.",
        [
            sample
            for status, (seconds, count) in sorted(scan_durations.items())
            for sample in (("_sum", {"status": status}, seconds), ("_count", {"status": status}, count))
        ],
    )
    family(
        "whitebox_scanner_runs_total", "counter", "Scanner runs by result since this process started.",
        [("", {"scanner": name, "status": status}, total) for (name, status), total in sorted(METRICS.scanner_runs.items())],
    )
    family(
        "whitebox_scanner_duration_seconds", "summary", "Scanner run time since this process started.",
        [
            sample
            for name, (seconds, count) in sorted(METRICS.scanner_durations.items())
            for sample in (("_sum", {"scanner": name}, seconds), ("_count", {"scanner": name}, count))
        ],
    )
    return "\n".join(lines) + "\n"


@api.get("/metrics", response_class=PlainTextResponse)
async def get_metrics() -> PlainTextResponse:
    scans_by_status = await asyncio.to_thread(count_scans_by_status)
    # Render on the event loop so the counters are not read while scans update them.
    return PlainTextResponse(render_metrics(scans_by_status), media_type="text/plain; version=0.0.4; charset=utf-8")


@api.post("/scans", status_code=202)
async def create_scan(
    source: UploadFile = File(..., description="ZIP archive containing a source tree"),
    scanners: str = Form(",".join(DEFAULT_SCANNERS), description="Comma-separated scanner names"),
    name: str = Form("source-upload", max_length=100),
) -> dict[str, Any]:
    requested = list(dict.fromkeys(part.strip() for part in scanners.split(",") if part.strip()))
    if not requested:
        raise HTTPException(status_code=422, detail="Select at least one scanner")
    unknown = [scanner for scanner in requested if scanner not in SCANNER_BINARIES]
    if unknown:
        raise HTTPException(status_code=422, detail={"message": "Unknown scanner", "unknown": unknown})
    available = {entry["name"] for entry in scanner_inventory() if entry["available"]}
    missing = [scanner for scanner in requested if scanner not in available]
    if missing:
        raise HTTPException(status_code=422, detail={"message": "Requested scanner is not installed", "missing": missing})
    if RECOVERING or JOB_QUEUE.full():
        raise HTTPException(status_code=503, detail="Scan queue is full; retry later")

    scan_id = uuid.uuid4().hex
    directory = job_dir(scan_id)
    directory.mkdir(parents=True, exist_ok=False)
    upload_path = directory / "source.zip"
    uploaded = 0
    accepted = False
    try:
        with upload_path.open("xb") as output:
            while chunk := await source.read(1024 * 1024):
                uploaded += len(chunk)
                if uploaded > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail=f"ZIP exceeds the {MAX_UPLOAD_BYTES}-byte upload limit")
                output.write(chunk)
        try:
            await complete_thread_work(validate_zip_archive, upload_path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        display_name = clean_text(name, 100) or "source-upload"
        now = utc_now()
        # Upload and validation yield control. Recheck immediately before the
        # synchronous insert/enqueue pair so concurrent uploads cannot overfill.
        if RECOVERING or JOB_QUEUE.full():
            raise HTTPException(status_code=503, detail="Scan queue is full; retry later")
        with connect_db() as db:
            db.execute(
                "INSERT INTO scans (id, name, status, created_at, updated_at, scanners_json, upload_bytes) VALUES (?, ?, 'queued', ?, ?, ?, ?)",
                (scan_id, display_name, now, now, json.dumps(requested), uploaded),
            )
        JOB_QUEUE.put_nowait(scan_id)
        accepted = True
        return {"id": scan_id, "status": "queued", "status_url": f"/api/scans/{scan_id}", "report_url": f"/api/scans/{scan_id}/report"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not accept the source archive") from exc
    finally:
        if not accepted:
            shutil.rmtree(directory, ignore_errors=True)
            with suppress(sqlite3.Error):
                with connect_db() as db:
                    db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await source.close()


@api.get("/scans")
def list_scans(limit: int = 50) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    with connect_db() as db:
        rows = db.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return {"scans": [public_scan(row) for row in rows]}


@api.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    job_dir(scan_id)
    row = get_scan_row(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return public_scan(row)


def load_report(scan_id: str) -> tuple[sqlite3.Row, dict[str, Any]]:
    job_dir(scan_id)
    row = get_scan_row(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    report_path = job_dir(scan_id) / "report.json"
    if not report_path.is_file():
        raise HTTPException(status_code=409, detail=f"Report is not ready; scan status is {row['status']}")
    try:
        return row, json.loads(report_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Stored report is unreadable") from exc


def parse_filter_values(raw: str | None, allowed: tuple[str, ...], label: str) -> set[str] | None:
    if raw is None:
        return None
    values = {part.strip().lower() for part in raw.split(",") if part.strip()}
    if not values:
        return None
    invalid = sorted(values - set(allowed))
    if invalid:
        raise HTTPException(status_code=422, detail={"message": f"Unknown {label}", "invalid": invalid, "allowed": list(allowed)})
    return values


def filter_findings(
    findings: list[dict[str, Any]],
    *,
    severity: set[str] | None,
    tool: set[str] | None,
    category: set[str] | None,
    path_contains: str | None,
    triage_status: set[str] | None = None,
    fp_verdict: set[str] | None = None,
    evidence: set[str] | None = None,
) -> list[dict[str, Any]]:
    needle = path_contains.lower() if path_contains else None
    selected = []
    for finding in findings:
        if triage_status is not None and finding.get("triage_status", "needs_review") not in triage_status:
            continue
        if fp_verdict is not None and (finding.get("fp_check") or {}).get("verdict", "needs_review") not in fp_verdict:
            continue
        if evidence is not None and (finding.get("evidence") or {}).get("level", "present") not in evidence:
            continue
        if severity is not None and finding.get("severity") not in severity:
            continue
        if tool is not None and finding.get("tool") not in tool:
            continue
        if category is not None and finding.get("category") not in category:
            continue
        if needle is not None and needle not in (finding.get("path") or "").lower():
            continue
        selected.append(finding)
    return selected


SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "none",
}


def findings_to_sarif(scan_id: str, report: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    runs: dict[str, dict[str, Any]] = {}
    for finding in findings:
        tool = finding.get("tool") or "whitebox"
        run = runs.setdefault(
            tool,
            {
                "tool": {"driver": {"name": tool, "informationUri": "https://github.com/Jaycelation/whitebox-vuln-service", "rules": []}},
                "results": [],
                "_rule_index": {},
            },
        )
        driver = run["tool"]["driver"]
        rule_key = finding.get("rule_id") or finding.get("title") or "finding"
        if rule_key not in run["_rule_index"]:
            run["_rule_index"][rule_key] = len(driver["rules"])
            driver["rules"].append(
                {
                    "id": rule_key,
                    "name": rule_key,
                    "shortDescription": {"text": clean_text(finding.get("title"), 240) or rule_key},
                    "helpUri": (finding.get("references") or [None])[0],
                    "properties": {"category": finding.get("category"), "security-severity-level": finding.get("severity")},
                }
            )
        location: dict[str, Any] = {}
        if finding.get("path"):
            region: dict[str, Any] = {}
            if finding.get("line"):
                region["startLine"] = finding["line"]
            if finding.get("end_line"):
                region["endLine"] = finding["end_line"]
            physical: dict[str, Any] = {"artifactLocation": {"uri": finding["path"]}}
            if region:
                physical["region"] = region
            location = {"physicalLocation": physical}
        result = {
            "ruleId": rule_key,
            "ruleIndex": run["_rule_index"][rule_key],
            "level": SARIF_LEVELS.get(finding.get("severity"), "none"),
            "message": {"text": finding.get("message") or finding.get("title") or rule_key},
            "partialFingerprints": {"whiteboxFindingId": finding.get("id", "")},
            "properties": {
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "triage_status": finding.get("triage_status"),
                "fp_verdict": (finding.get("fp_check") or {}).get("verdict"),
                "evidence": (finding.get("evidence") or {}).get("level"),
                **({"cvss_vector": finding["cvss"]["vector"], "security-severity": str(finding["cvss"]["score"])} if finding.get("cvss") else {}),
                "duplicate_of": (finding.get("fp_check") or {}).get("duplicate_of"),
            },
        }
        if location:
            result["locations"] = [location]
        if finding.get("trace"):
            result["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {
                    "physicalLocation": {"artifactLocation": {"uri": step["path"]}, **({"region": {"startLine": step["line"]}} if step.get("line") else {})},
                    "message": {"text": step.get("detail") or step.get("kind") or "step"},
                }}
                for step in finding["trace"] if step.get("path")
            ]}]}]
        # Only human or agent decisions suppress a result; heuristic verdicts stay visible.
        if finding.get("triage_status") in ("false_positive", "accepted_risk"):
            suppression: dict[str, Any] = {"kind": "external", "status": "accepted"}
            if finding.get("triage_note"):
                suppression["justification"] = finding["triage_note"]
            result["suppressions"] = [suppression]
        run["results"].append(result)
    for run in runs.values():
        run.pop("_rule_index", None)
        # GitHub ranks alerts by the rule's security-severity; use the highest evidence-backed score.
        for result in run["results"]:
            value = result["properties"].get("security-severity")
            if value is not None:
                rule = run["tool"]["driver"]["rules"][result["ruleIndex"]]
                current = rule["properties"].get("security-severity")
                if current is None or float(value) > float(current):
                    rule["properties"]["security-severity"] = value
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": list(runs.values()) or [{"tool": {"driver": {"name": "whitebox-vuln-service", "rules": []}}, "results": []}],
    }


@api.get("/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    severity: str | None = None,
    tool: str | None = None,
    category: str | None = None,
    path_contains: str | None = None,
    triage_status: str | None = None,
    fp_verdict: str | None = None,
    evidence: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    _, report = load_report(scan_id)
    findings = report.get("findings") or []
    severity_filter = parse_filter_values(severity, SEVERITIES, "severity")
    tool_filter = parse_filter_values(tool, tuple(SCANNER_BINARIES), "tool")
    category_filter = parse_filter_values(category, CATEGORIES, "category")
    triage_filter = parse_filter_values(triage_status, TRIAGE_STATUSES, "triage_status")
    verdict_filter = parse_filter_values(fp_verdict, FP_VERDICTS, "fp_verdict")
    evidence_filter = parse_filter_values(evidence, whitebox_evidence.EVIDENCE_LEVELS, "evidence")
    filters = (severity_filter, tool_filter, category_filter, path_contains, triage_filter, verdict_filter, evidence_filter)
    if any(value is not None for value in filters):
        findings = filter_findings(
            findings,
            severity=severity_filter,
            tool=tool_filter,
            category=category_filter,
            path_contains=clean_text(path_contains, 1000) if path_contains else None,
            triage_status=triage_filter,
            fp_verdict=verdict_filter,
            evidence=evidence_filter,
        )
    matched = len(findings)
    offset = max(0, offset)
    if offset or limit is not None:
        end = offset + max(0, limit) if limit is not None else None
        findings = findings[offset:end]
    report["findings"] = findings
    report["filter"] = {
        "matched": matched,
        "returned": len(findings),
        "offset": offset,
        "limit": limit,
        "applied": {
            "severity": severity,
            "tool": tool,
            "category": category,
            "path_contains": path_contains,
            "triage_status": triage_status,
            "fp_verdict": fp_verdict,
            "evidence": evidence,
        },
    }
    return report


class TriageUpdate(BaseModel):
    status: str = Field(description="One of: " + ", ".join(TRIAGE_STATUSES))
    note: str = Field("", max_length=2000, description="Why the finding has this status")
    cvss_vector: str | None = Field(None, description="Optional CVSS 3.1 base vector set by the reviewer, e.g. CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")


REPORT_WRITE_LOCK = threading.Lock()


def store_triage_decision(db: sqlite3.Connection, project: str, key: str, status: str, note: str | None, updated_at: str,
                          scan_id: str, finding_id: str, vector: str | None, decided_by: str) -> None:
    db.execute(
        "INSERT INTO triage_decisions (project, match_key, status, note, updated_at, scan_id, finding_id, cvss_vector, decided_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (project, match_key) DO UPDATE SET "
        "status = excluded.status, note = excluded.note, updated_at = excluded.updated_at, scan_id = excluded.scan_id, "
        "finding_id = excluded.finding_id, cvss_vector = excluded.cvss_vector, decided_by = excluded.decided_by",
        (project, key, status, note, updated_at, scan_id, finding_id, vector, decided_by),
    )


async def run_verification(project: str, scan_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Let Claude review the evidence-backed findings and record its verdicts."""
    if not whitebox_verify.enabled():
        return {"status": "disabled"}
    try:
        pairs = await whitebox_verify.verify_findings(
            findings, model=whitebox_verify.VERIFY_MODEL, max_findings=VERIFY_MAX_FINDINGS, concurrency=VERIFY_CONCURRENCY,
        )
    except Exception as exc:  # for example the SDK or credentials are missing
        LOGGER.exception("Claude verification failed")
        return {"status": "failed", "error": clean_text(f"{type(exc).__name__}: {exc}", 300)}
    decisions = [(finding, review) for finding, review in pairs if whitebox_verify.apply_review(finding, review)]
    if decisions:
        with connect_db() as db:
            for finding, review in decisions:
                store_triage_decision(db, project, finding.get("match_key") or finding_match_key(finding), finding["triage_status"],
                                      finding["triage_note"], review["reviewed_at"], scan_id, finding["id"],
                                      finding.get("triage_cvss_vector"), "agent")
    return whitebox_verify.summary(pairs, whitebox_verify.VERIFY_MODEL)


@api.post("/scans/{scan_id}/verify")
async def verify_scan(scan_id: str) -> dict[str, Any]:
    """Run (or re-run) Claude's review on a finished report, using the code stored with it."""
    if not whitebox_verify.enabled():
        raise HTTPException(status_code=409, detail="Claude verification is off; set VERIFY_WITH_CLAUDE=1 and ANTHROPIC_API_KEY.")
    row, report = await asyncio.to_thread(load_report, scan_id)
    result = await run_verification(row["name"], scan_id, report.get("findings") or [])

    def save() -> dict[str, Any]:
        with REPORT_WRITE_LOCK:
            _, current = load_report(scan_id)
            reviewed = {finding["id"]: finding for finding in report.get("findings") or [] if "agent_review" in finding}
            for index, finding in enumerate(current.get("findings") or []):
                if finding["id"] in reviewed and finding.get("triage_decided_by") != "manual":
                    current["findings"][index] = reviewed[finding["id"]]
            current["verification"] = result
            current.setdefault("summary", {}).update(triage_summary(current["findings"]))
            current["summary"].update(whitebox_evidence.summary(current["findings"]))
            directory = job_dir(scan_id)
            temporary = directory / "report.json.tmp"
            temporary.write_text(json.dumps(current, ensure_ascii=False, indent=2), "utf-8")
            temporary.replace(directory / "report.json")
            update_scan(scan_id, summary_json=json.dumps(current["summary"]))
            return result

    return await asyncio.to_thread(save)


@api.patch("/scans/{scan_id}/findings/{finding_id}")
def triage_finding(scan_id: str, finding_id: str, update: TriageUpdate) -> dict[str, Any]:
    status = update.status.strip().lower()
    if status not in TRIAGE_STATUSES:
        raise HTTPException(status_code=422, detail={"message": "Unknown triage status", "allowed": list(TRIAGE_STATUSES)})
    if not re.fullmatch(r"[0-9a-f]{24}", finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    note = clean_text(update.note, 2000)
    vector = (update.cvss_vector or "").strip() or None
    if vector and not whitebox_evidence.valid_vector(vector):
        raise HTTPException(status_code=422, detail="cvss_vector must be a CVSS 3.x base vector like CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    with REPORT_WRITE_LOCK:
        row, report = load_report(scan_id)
        findings = report.get("findings") or []
        target = next((finding for finding in findings if finding.get("id") == finding_id), None)
        if target is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        # A decision covers every scanner's copy of the same dependency vulnerability.
        root = (target.get("fp_check") or {}).get("duplicate_of") or target["id"]
        group = [
            finding for finding in findings
            if finding.get("id") == root or (finding.get("fp_check") or {}).get("duplicate_of") == root
        ]
        now = utc_now()
        with connect_db() as db:
            for finding in group:
                key = finding.get("match_key") or finding_match_key(finding)
                finding["match_key"] = key
                if status == "needs_review":
                    db.execute("DELETE FROM triage_decisions WHERE project = ? AND match_key = ?", (row["name"], key))
                else:
                    store_triage_decision(db, row["name"], key, status, note, now, scan_id, finding["id"], vector, "manual")
                finding["triage_status"] = status
                finding["triage_note"] = note or None
                finding["triage_updated_at"] = now
                finding["triage_source"] = "manual"
                finding["triage_cvss_vector"] = vector
                finding["triage_decided_by"] = None if status == "needs_review" else "manual"
                whitebox_evidence.apply_triage(finding)
        report.setdefault("summary", {}).update(triage_summary(findings))
        report["summary"].update(whitebox_evidence.summary(findings))
        directory = job_dir(scan_id)
        temporary_report = directory / "report.json.tmp"
        temporary_report.write_text(json.dumps(report, ensure_ascii=False, indent=2), "utf-8")
        temporary_report.replace(directory / "report.json")
        update_scan(scan_id, summary_json=json.dumps(report["summary"]))
    return {"finding": target, "updated": [finding["id"] for finding in group], "summary": report["summary"]}


@api.get("/scans/{scan_id}/report.sarif")
def get_report_sarif(scan_id: str) -> JSONResponse:
    _, report = load_report(scan_id)
    sarif = findings_to_sarif(scan_id, report, report.get("findings") or [])
    return JSONResponse(content=sarif, media_type="application/sarif+json")


@api.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str) -> None:
    job_dir(scan_id)
    row = get_scan_row(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row["status"] in ("queued", "running"):
        raise HTTPException(status_code=409, detail="Queued or running scans cannot be deleted")
    shutil.rmtree(job_dir(scan_id), ignore_errors=True)
    with connect_db() as db:
        db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


app.include_router(api)
app.mount("/ui", StaticFiles(directory=Path(__file__).parent / "web", html=True), name="ui")
