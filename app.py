from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import sqlite3
import stat
import time
import uuid
import zipfile
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse


DATA_DIR = Path(os.getenv("DATA_DIR", "./data")).resolve()
DB_PATH = DATA_DIR / "scans.sqlite3"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))
MAX_EXPANDED_BYTES = int(os.getenv("MAX_EXPANDED_BYTES", str(1024 * 1024 * 1024)))
MAX_ARCHIVE_ENTRIES = int(os.getenv("MAX_ARCHIVE_ENTRIES", "20000"))
MAX_FINDINGS = int(os.getenv("MAX_FINDINGS", "10000"))
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "900"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
API_KEY = os.getenv("API_KEY", "")
DEFAULT_SCANNERS = ("semgrep", "gitleaks", "trivy", "osv-scanner")
SCANNER_BINARIES = {
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "trivy": "trivy",
    "osv-scanner": "osv-scanner",
    "joern": "joern-scan",
}
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CATEGORIES = ("sast", "secret", "dependency", "misconfiguration")
JOB_QUEUE: asyncio.Queue[str] = asyncio.Queue(maxsize=10)
RECOVERING = False


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
                error TEXT
            )"""
        )


def job_dir(scan_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return DATA_DIR / "jobs" / scan_id


def get_scan_row(scan_id: str) -> sqlite3.Row | None:
    with connect_db() as db:
        return db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()


def update_scan(scan_id: str, **fields: Any) -> None:
    allowed = {"status", "updated_at", "finished_at", "error"}
    if not fields or not set(fields).issubset(allowed):
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
        report_path = job_dir(row["id"]) / "report.json"
        if report_path.is_file():
            try:
                report = json.loads(report_path.read_text("utf-8"))
                result["summary"] = report.get("summary")
                result["scanner_results"] = report.get("scanners")
            except (OSError, json.JSONDecodeError):
                result["summary"] = None
    return result


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
            findings.append(
                make_finding(
                    tool="trivy",
                    category="dependency",
                    severity=item.get("Severity"),
                    title=item.get("Title") or vuln_id,
                    message=message,
                    path=target,
                    line=None,
                    rule_id=vuln_id,
                    references=refs,
                    source_root=source_root,
                )
            )
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
                findings.append(
                    make_finding(
                        tool="osv-scanner",
                        category="dependency",
                        severity=osv_severity(vulnerability),
                        title=f"{vuln_id}: {clean_text(summary, 180)}",
                        message=message,
                        path=source_path,
                        rule_id=vuln_id,
                        references=refs,
                        source_root=source_root,
                    )
                )
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


def scanner_command(name: str, source_root: Path, raw_output: Path) -> list[str]:
    binary = SCANNER_BINARIES[name]
    if name == "semgrep":
        return [binary, "scan", "--config", "auto", "--json", "--output", str(raw_output), "--metrics=off", "--timeout", "30", "--jobs", "2", str(source_root)]
    if name == "gitleaks":
        return [binary, "dir", "--no-banner", "--no-color", "--redact=100", "--exit-code", "0", "--report-format", "json", "--report-path", str(raw_output), str(source_root)]
    if name == "trivy":
        return [binary, "fs", "--format", "json", "--output", str(raw_output), "--scanners", "vuln,misconfig,secret", "--exit-code", "0", "--no-progress", "--disable-telemetry", "--timeout", "10m", "--cache-dir", str(DATA_DIR / "cache" / "trivy"), str(source_root)]
    if name == "osv-scanner":
        return [binary, "scan", "source", "-r", str(source_root), "--format", "json"]
    if name == "joern":
        return [binary, str(source_root), "--overwrite"]
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
    }
    return parsers[name](data, source_root)


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
                cwd=str(source_root),
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
    try:
        source_root = await complete_thread_work(extract_zip, upload_path, extract_dir)
        scanners: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        work_dir.mkdir(parents=True, exist_ok=True)
        for name in json.loads(row["scanners_json"]):
            scanner_result, scanner_findings = await run_scanner(name, source_root, work_dir)
            scanners.append(scanner_result)
            for finding in scanner_findings:
                if finding["id"] in seen:
                    continue
                seen.add(finding["id"])
                if len(findings) < MAX_FINDINGS:
                    findings.append(finding)
        truncated = len(seen) > len(findings)
        report = {
            "scan_id": scan_id,
            "created_at": row["created_at"],
            "finished_at": utc_now(),
            "summary": summarize(findings, scanners),
            "scanners": scanners,
            "findings": findings,
            "triage_note": "Scanner output is candidate evidence. Review each result in source context before treating it as a vulnerability.",
        }
        report["summary"]["findings_truncated"] = truncated
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
        update_scan(scan_id, status=status, updated_at=utc_now(), finished_at=utc_now(), error=None)
    except asyncio.CancelledError:
        interrupted = True
        update_scan(scan_id, status="queued", updated_at=utc_now(), error="Service restarted while this scan was running.")
        raise
    except Exception as exc:
        message = "Source archive could not be extracted." if isinstance(exc, (ValueError, zipfile.BadZipFile)) else "Scan could not be completed."
        update_scan(scan_id, status="failed", updated_at=utc_now(), finished_at=utc_now(), error=message)
    finally:
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


def prune_expired() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    with connect_db() as db:
        rows = db.execute("SELECT * FROM scans ORDER BY created_at").fetchall()
        for row in rows:
            created = datetime.fromisoformat(row["created_at"])
            if row["status"] in ("completed", "partial", "failed") and created < cutoff:
                shutil.rmtree(job_dir(row["id"]), ignore_errors=True)
                db.execute("DELETE FROM scans WHERE id = ?", (row["id"],))


@asynccontextmanager
async def lifespan(_: FastAPI):
    global JOB_QUEUE, RECOVERING
    JOB_QUEUE = asyncio.Queue(maxsize=10)
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

    worker = asyncio.create_task(queue_worker(), name="whitebox-scan-worker")
    recovery = asyncio.create_task(feed_recovered_jobs(), name="whitebox-queue-recovery")
    try:
        # Even an oversized durable backlog must not block API startup.
        yield
    finally:
        recovery.cancel()
        with suppress(asyncio.CancelledError):
            await recovery
        worker.cancel()
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
    return {"service": "Whitebox Vulnerability Check Service", "docs": "/docs", "health": "/health"}


@api.get("/scanners")
def get_scanners() -> dict[str, Any]:
    return {"scanners": scanner_inventory(), "default": list(DEFAULT_SCANNERS)}


@api.post("/scans", status_code=202)
async def create_scan(
    source: UploadFile = File(..., description="ZIP archive containing a source tree"),
    scanners: str = Form(",".join(DEFAULT_SCANNERS), description="Comma-separated scanner names"),
    name: str = Form("source-upload", max_length=100),
) -> dict[str, Any]:
    prune_expired()
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
) -> list[dict[str, Any]]:
    needle = path_contains.lower() if path_contains else None
    selected = []
    for finding in findings:
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
            },
        }
        if location:
            result["locations"] = [location]
        run["results"].append(result)
    for run in runs.values():
        run.pop("_rule_index", None)
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
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    _, report = load_report(scan_id)
    findings = report.get("findings") or []
    severity_filter = parse_filter_values(severity, SEVERITIES, "severity")
    tool_filter = parse_filter_values(tool, tuple(SCANNER_BINARIES), "tool")
    category_filter = parse_filter_values(category, CATEGORIES, "category")
    if any(value is not None for value in (severity_filter, tool_filter, category_filter, path_contains)):
        findings = filter_findings(
            findings,
            severity=severity_filter,
            tool=tool_filter,
            category=category_filter,
            path_contains=clean_text(path_contains, 1000) if path_contains else None,
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
        "applied": {"severity": severity, "tool": tool, "category": category, "path_contains": path_contains},
    }
    return report


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
