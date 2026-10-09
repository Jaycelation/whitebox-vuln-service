from __future__ import annotations

import asyncio
import os
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Literal

import httpx
from mcp.server.fastmcp import FastMCP


API_URL = os.getenv("WHITEBOX_API_URL", "http://127.0.0.1:8000").rstrip("/")
API_KEY = os.getenv("WHITEBOX_API_KEY", "")
MAX_SOURCE_BYTES = int(os.getenv("WHITEBOX_MAX_SOURCE_BYTES", str(1024 * 1024 * 1024)))
MAX_ARCHIVE_BYTES = int(os.getenv("WHITEBOX_MAX_ARCHIVE_BYTES", str(200 * 1024 * 1024)))
MAX_SOURCE_FILES = int(os.getenv("WHITEBOX_MAX_SOURCE_FILES", "20000"))
DEFAULT_SCANNERS = ("semgrep", "dataflow", "gitleaks", "trivy", "osv-scanner")
KNOWN_SCANNERS = frozenset((*DEFAULT_SCANNERS, "joern"))
EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".next",
        ".nuxt",
        ".turbo",
        "dist",
        "build",
        "target",
    }
)

mcp = FastMCP(
    "whitebox-vuln-service",
    instructions=(
        "Use this MCP server to scan a local source repository with the configured "
        "Whitebox Vulnerability Check Service. Source files are archived locally and "
        "sent directly to that service; tool results contain findings, not source code. "
        "Only scan repositories the user is authorized to review."
    ),
)


def _headers() -> dict[str, str]:
    if API_KEY:
        return {"Authorization": f"Bearer {API_KEY}"}
    return {}


def _allowed_roots() -> list[Path]:
    configured = os.getenv("WHITEBOX_ALLOWED_ROOTS", "")
    raw_roots = [item for item in configured.split(os.pathsep) if item.strip()]
    if not raw_roots:
        project_root = os.getenv("CLAUDE_PROJECT_DIR")
        raw_roots = [project_root or str(Path.cwd())]

    roots: list[Path] = []
    for raw_root in raw_roots:
        try:
            root = Path(raw_root).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and root not in roots:
            roots.append(root)
    return roots


def _resolve_repository(repository_path: str | None) -> Path:
    default_root = os.getenv("CLAUDE_PROJECT_DIR") or str(Path.cwd())
    candidate = Path(repository_path or default_root).expanduser()
    if not candidate.is_absolute():
        candidate = Path(default_root) / candidate
    try:
        repository = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Repository path does not exist or cannot be resolved") from exc
    if not repository.is_dir():
        raise ValueError("Repository path must be a directory")

    roots = _allowed_roots()
    if not roots:
        raise ValueError("No valid scan roots are configured in WHITEBOX_ALLOWED_ROOTS")
    if not any(repository == root or repository.is_relative_to(root) for root in roots):
        allowed = ", ".join(str(root) for root in roots)
        raise ValueError(f"Repository is outside the configured scan roots: {allowed}")
    return repository


def _create_archive(repository: Path) -> tuple[Path, int, int]:
    descriptor, archive_name = tempfile.mkstemp(prefix="whitebox-source-", suffix=".zip")
    os.close(descriptor)
    archive_path = Path(archive_name)
    total_source_bytes = 0
    file_count = 0
    try:
        with zipfile.ZipFile(
            archive_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
            allowZip64=True,
        ) as archive:
            for current, directories, filenames in os.walk(repository, followlinks=False):
                current_path = Path(current)
                directories[:] = [
                    name
                    for name in directories
                    if name not in EXCLUDED_DIRECTORIES
                    and not (current_path / name).is_symlink()
                ]
                for filename in filenames:
                    source = current_path / filename
                    if source.is_symlink() or not source.is_file():
                        continue
                    try:
                        size = source.stat().st_size
                    except OSError as exc:
                        raise ValueError(f"Could not read source file: {source.name}") from exc
                    total_source_bytes += size
                    file_count += 1
                    if total_source_bytes > MAX_SOURCE_BYTES:
                        raise ValueError("Repository exceeds WHITEBOX_MAX_SOURCE_BYTES")
                    if file_count > MAX_SOURCE_FILES:
                        raise ValueError("Repository exceeds WHITEBOX_MAX_SOURCE_FILES")

                    relative = source.relative_to(repository).as_posix()
                    if "\\" in relative or "\x00" in relative:
                        raise ValueError("Repository contains a path unsupported by the ZIP scanner")
                    archive.write(source, arcname=relative)
                    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
                        raise ValueError("Archive exceeds WHITEBOX_MAX_ARCHIVE_BYTES")

        # ZIP writes its central directory on close; it counts toward upload size.
        if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("Archive exceeds WHITEBOX_MAX_ARCHIVE_BYTES")
        if file_count == 0:
            raise ValueError("Repository has no scanable files")
        return archive_path, total_source_bytes, file_count
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise


async def _api_request(method: str, path: str, **kwargs: Any) -> Any:
    timeout = httpx.Timeout(60.0, connect=10.0)
    try:
        async with httpx.AsyncClient(headers=_headers(), timeout=timeout) as client:
            response = await client.request(method, f"{API_URL}{path}", **kwargs)
    except httpx.RequestError as exc:
        raise RuntimeError(
            f"Cannot reach the scanner service at {API_URL}. Start it with docker compose up -d."
        ) from exc

    if response.is_error:
        try:
            payload = response.json()
            detail = payload.get("detail", payload) if isinstance(payload, dict) else payload
            if isinstance(detail, dict):
                detail = detail.get("message", detail)
            message = str(detail)
        except (ValueError, TypeError):
            message = response.reason_phrase
        raise RuntimeError(f"Scanner API returned HTTP {response.status_code}: {message[:600]}")
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError("Scanner API returned an invalid JSON response") from exc


@mcp.tool()
async def whitebox_list_scanners() -> dict[str, Any]:
    """List scanner names, availability, and the service's default scanner set."""
    return await _api_request("GET", "/api/scanners")


@mcp.tool()
async def whitebox_scan_repository(
    repository_path: str | None = None,
    profile: Literal["standard", "standard_plus_joern"] = "standard",
    scanners: list[str] | None = None,
) -> dict[str, Any]:
    """Queue a scan of an authorized local repository and return its scan ID.

    Omit repository_path to scan the current Claude project directory (or the
    MCP process working directory). Standard runs Semgrep, the cross-function
    dataflow analysis (request input to sink, with a trace per finding), Gitleaks,
    Trivy, and OSV-Scanner. standard_plus_joern also requires Joern to be installed in the
    scanner service. Joern uses its installed query set; custom source/sink models
    are not implied by this profile.
    """
    repository = _resolve_repository(repository_path)
    if scanners is not None:
        selected = list(dict.fromkeys(name.strip() for name in scanners if name.strip()))
        if not selected:
            raise ValueError("Select at least one scanner")
        unknown = [name for name in selected if name not in KNOWN_SCANNERS]
        if unknown:
            raise ValueError(f"Unknown scanner names: {', '.join(unknown)}")
    elif profile == "standard_plus_joern":
        selected = [*DEFAULT_SCANNERS, "joern"]
    else:
        selected = list(DEFAULT_SCANNERS)

    inventory = await _api_request("GET", "/api/scanners")
    available = {
        entry.get("name")
        for entry in inventory.get("scanners", [])
        if isinstance(entry, dict) and entry.get("available")
    }
    missing = [name for name in selected if name not in available]
    if missing:
        guidance = "Set INSTALL_JOERN=1 in .env and rebuild with docker compose build" if "joern" in missing else ""
        suffix = f". {guidance}" if guidance else ""
        raise ValueError(f"Requested scanners are not installed: {', '.join(missing)}{suffix}")

    archive_path, source_bytes, file_count = await asyncio.to_thread(_create_archive, repository)
    try:
        with archive_path.open("rb") as archive_file:
            result = await _api_request(
                "POST",
                "/api/scans",
                data={"name": repository.name[:100], "scanners": ",".join(selected)},
                files={
                    "source": (
                        f"{repository.name or 'source'}.zip",
                        archive_file,
                        "application/zip",
                    )
                },
            )
    finally:
        archive_path.unlink(missing_ok=True)

    return {
        **result,
        "repository": repository.name,
        "scanners": selected,
        "source_file_count": file_count,
        "source_bytes": source_bytes,
        "excluded_directories": sorted(EXCLUDED_DIRECTORIES),
        "next_step": "Call whitebox_scan_status with this scan_id. When status is completed, partial, or failed, call whitebox_get_report. Failed scans may have a diagnostic report; archive extraction failures do not.",
    }


@mcp.tool()
async def whitebox_scan_status(scan_id: str) -> dict[str, Any]:
    """Get the queue or execution status for a scan ID returned by whitebox_scan_repository."""
    if not re.fullmatch(r"[0-9a-f]{32}", scan_id):
        raise ValueError("Invalid scan ID")
    return await _api_request("GET", f"/api/scans/{scan_id}")


@mcp.tool()
async def whitebox_get_report(
    scan_id: str,
    offset: int = 0,
    limit: int = 25,
    fp_verdict: str | None = None,
    triage_status: str | None = None,
) -> dict[str, Any]:
    """Get a scan summary and a page of findings; secret values are redacted by the service.

    Each finding has fp_check (verdict likely_false_positive, duplicate, or needs_review,
    with reasons) and triage_status. Pass fp_verdict="needs_review" to skip likely false
    positives and duplicates, or comma-separate several values.
    """
    if not re.fullmatch(r"[0-9a-f]{32}", scan_id):
        raise ValueError("Invalid scan ID")
    if offset < 0:
        raise ValueError("offset must be zero or greater")
    page_size = min(max(limit, 1), 50)
    params = {key: value for key, value in (("fp_verdict", fp_verdict), ("triage_status", triage_status)) if value}
    status, report = await asyncio.gather(
        _api_request("GET", f"/api/scans/{scan_id}"),
        _api_request("GET", f"/api/scans/{scan_id}/report", params=params),
    )
    findings = report.get("findings", []) if isinstance(report, dict) else []
    total = len(findings)
    page = findings[offset : offset + page_size]
    return {
        "scan_id": scan_id,
        "status": status.get("status"),
        "summary": report.get("summary"),
        "scanners": report.get("scanners"),
        "findings": page,
        "pagination": {
            "offset": offset,
            "returned": len(page),
            "total": total,
            "next_offset": offset + len(page) if offset + len(page) < total else None,
        },
    }


TRIAGE_STATUSES = frozenset({"needs_review", "confirmed", "false_positive", "accepted_risk", "fixed"})


@mcp.tool()
async def whitebox_triage_finding(
    scan_id: str,
    finding_id: str,
    status: str,
    note: str = "",
) -> dict[str, Any]:
    """Record a triage decision for a finding after checking it in the source.

    status is one of: false_positive, confirmed, accepted_risk, fixed, needs_review
    (needs_review clears an earlier decision). Explain the evidence in note, for
    example why the input is not attacker-controlled. The decision also applies to
    duplicates of the finding and to the same finding in later scans of the project.
    """
    if not re.fullmatch(r"[0-9a-f]{32}", scan_id):
        raise ValueError("Invalid scan ID")
    if not re.fullmatch(r"[0-9a-f]{24}", finding_id):
        raise ValueError("Invalid finding ID")
    if status not in TRIAGE_STATUSES:
        raise ValueError("status must be one of: " + ", ".join(sorted(TRIAGE_STATUSES)))
    return await _api_request(
        "PATCH",
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"status": status, "note": note[:2000]},
    )


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
