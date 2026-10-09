# Whitebox Vulnerability Check Service

A self-hosted API that accepts a ZIP of source code, runs free scanners locally in a restricted container, and stores normalized JSON findings. It is intended for internal use on source you are authorized to review.

## Included scanners

| Scanner | What it checks |
| --- | --- |
| Semgrep Community Edition | Source patterns and common code security issues |
| Dataflow (`dataflow`) | Request input that reaches a dangerous sink across functions and files, with a trace; built on Semgrep CE taint mode |
| Gitleaks | Secrets in the uploaded working tree; matched secret values are redacted |
| Trivy | Dependency vulnerabilities, configuration issues, and secrets |
| OSV-Scanner | Known vulnerabilities in supported dependencies and lockfiles |

Joern can be enabled in the image, but is off by default because its current Linux release archive is about 1.67 GB and it requires a JDK. Set `INSTALL_JOERN=1` in `.env` and rebuild to install it. The service will then accept `scanners=joern`.

```sh
docker compose build --no-cache
docker compose up -d
```

CodeQL CLI is not bundled or invoked. Its terms limit use on non-open-source code and automated database generation, and prohibit making the CLI available as a hosted solution. Review the current [CodeQL terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md) and use a properly licensed GitHub Code Security setup when applicable.

## Start

Requires Docker Engine with the Compose plugin. From this directory:

```sh
cp .env.example .env
docker compose up --build -d
```

The API binds to `127.0.0.1:8000`. Open [http://127.0.0.1:8000/ui/](http://127.0.0.1:8000/ui/) for the analysis dashboard, or [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) for interactive API documentation. The dashboard asks for the API key on a separate entry screen and only shows scans after the key is accepted. It visualizes findings by severity and scanner, and supports search, filtering, detail inspection, JSON export, ZIP upload, and light/dark themes. The key remains in page memory and must be entered again after a reload. Scanner findings still require manual validation. The first build downloads scanner binaries; Semgrep rules and vulnerability databases may be fetched when scans run. Source archives are not sent to a scanning SaaS by this service, although the scanners may access their rule/advisory services for updates and matching. The sample Compose file uses Cloudflare and Google public DNS; set `DNS_SERVER` and `DNS_FALLBACK_SERVER` in `.env` to your organization resolvers when needed.

For a private network deployment, set a long random `API_KEY` in `.env`, set `BIND_ADDRESS=0.0.0.0`, and place the service behind a trusted TLS reverse proxy. Allow the selected TCP port through the host firewall only for trusted clients. Do not bind the unauthenticated default configuration to a public interface.

## Submit a scan

The upload must be a ZIP archive. Include the source tree in the archive; one enclosing directory is detected automatically. No URL cloning or build scripts are run.

```sh
curl -sS -X POST http://127.0.0.1:8000/api/scans \
  -F 'name=my-project' \
  -F 'scanners=semgrep,gitleaks,trivy,osv-scanner' \
  -F 'source=@./my-project.zip;type=application/zip'
```

If `API_KEY` is configured, add `-H 'Authorization: Bearer YOUR_API_KEY'` to API requests.

The create response contains an `id`. Poll the `status_url` until the state is `completed`, `partial`, or `failed`, then retrieve `report_url`:

```sh
curl -sS http://127.0.0.1:8000/api/scans/SCAN_ID
curl -sS http://127.0.0.1:8000/api/scans/SCAN_ID/report
```

### Filter the report

`GET /api/scans/SCAN_ID/report` accepts optional query parameters to narrow large reports server-side. Filtering and pagination are applied to the `findings` array only; the `summary` always reflects the full scan. The response gains a `filter` object describing what was matched and returned.

| Parameter | Description |
| --- | --- |
| `severity` | Comma-separated: `critical`, `high`, `medium`, `low`, `info`, `unknown` |
| `tool` | Comma-separated: `semgrep`, `gitleaks`, `trivy`, `osv-scanner`, `joern` |
| `category` | Comma-separated: `sast`, `secret`, `dependency`, `misconfiguration` |
| `path_contains` | Case-insensitive substring match on a finding's `path` |
| `limit`, `offset` | Paginate the matched findings |

An unknown `severity`, `tool`, or `category` value returns `422` with the offending values listed.

```sh
# Only high and critical SAST findings, first 20
curl -sS 'http://127.0.0.1:8000/api/scans/SCAN_ID/report?severity=critical,high&category=sast&limit=20'
```

### SARIF export

`GET /api/scans/SCAN_ID/report.sarif` returns the findings as SARIF 2.1.0 (`application/sarif+json`), with one run per tool. This uploads directly to GitHub code scanning or any SARIF-aware viewer. Severities map to SARIF levels as critical/high → `error`, medium → `warning`, low/info → `note`, unknown → `none`.

```sh
curl -sS http://127.0.0.1:8000/api/scans/SCAN_ID/report.sarif -o results.sarif
```

## Tests

The report-endpoint tests run with the service's virtualenv and do not require pytest:

```sh
DATA_DIR=$(mktemp -d) .venv/bin/python tests/test_report_endpoints.py
```

## MCP integration for Claude Code and ChatGPT

The MCP adapter lets an agent queue scans against a local source directory and retrieve scanner status and findings. Source files are archived locally and uploaded directly to this service; the MCP responses contain findings and summaries, not source contents. The adapter accepts scan paths only under `WHITEBOX_ALLOWED_ROOTS`. If that variable is unset, it limits access to Claude Code's `CLAUDE_PROJECT_DIR` or the MCP process's working directory.

Install the adapter from this repository with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install --editable .
```

The package provides five MCP tools: `whitebox_list_scanners`, `whitebox_scan_repository`, `whitebox_scan_status`, `whitebox_get_report`, and `whitebox_triage_finding`. An agent can read a finding's `fp_check`, check the source itself, and record a false-positive or confirmed verdict with its evidence. `whitebox_scan_repository` defaults to Semgrep, Gitleaks, Trivy, and OSV-Scanner. Its `standard_plus_joern` profile adds Joern and requires `INSTALL_JOERN=1` in the service's `.env`, followed by an image rebuild. That profile runs the installed Joern query set; it does not add custom framework-specific source/sink models.

### Claude Code

With the scanner API running locally, register the stdio server:

```sh
claude mcp add --scope user --transport stdio \
  --env WHITEBOX_API_URL=http://127.0.0.1:8000 \
  whitebox-scanner -- whitebox-mcp
```

Claude Code supplies `CLAUDE_PROJECT_DIR`, which becomes the default allowed scan root. To permit additional roots, set `WHITEBOX_ALLOWED_ROOTS` to a path-separated list. If the scanner API uses an API key, also configure `WHITEBOX_API_KEY` in the MCP server environment; keep the value out of committed project files. Check the connection with `claude mcp list`.

### ChatGPT

ChatGPT connects to remote MCP servers. For this local scanner, use OpenAI's Secure MCP Tunnel so the MCP server remains private. Create a tunnel in OpenAI Platform, install `tunnel-client`, then run it beside the scanner:

```sh
export WHITEBOX_API_URL=http://127.0.0.1:8000
export WHITEBOX_ALLOWED_ROOTS=/path/to/authorized/projects
export CONTROL_PLANE_API_KEY=YOUR_OPENAI_RUNTIME_KEY

tunnel-client init \
  --sample sample_mcp_stdio_local \
  --profile whitebox \
  --tunnel-id YOUR_TUNNEL_ID \
  --mcp-command "whitebox-mcp"
tunnel-client doctor --profile whitebox --explain
tunnel-client run --profile whitebox
```

Add `WHITEBOX_API_KEY` to the environment when the scanner API is protected. In ChatGPT, create a developer-mode app and select the tunnel. Current ChatGPT documentation lists full MCP tools, including actions, for Business and Enterprise/Edu; Pro users have read/fetch-only MCP access. Workspace admin settings and OpenAI Platform tunnel permissions may be required. See [ChatGPT MCP app setup](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt) and [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

The MCP adapter exposes scan creation as an action that queues work and stores a report. It does not expose arbitrary shell commands, repository writes, or source-code retrieval.

Other endpoints:

- `GET /api/scanners` lists installed scanners.
- `GET /api/scans?limit=50` lists recent jobs.
- `GET /api/metrics` returns Prometheus text-format metrics: queue depth, stored scans by status, active scans and scanner processes, and scan and scanner run counts and durations. It uses the same bearer token as the other `/api` endpoints. Counts and durations cover the running process and reset when the service restarts.
- `PATCH /api/scans/{id}/findings/{finding_id}` records a triage decision; see [Recording triage decisions](#recording-triage-decisions).
- `DELETE /api/scans/{id}` removes a finished job and its report.
- `GET /health` is an unauthenticated health check.

## Report shape and triage

Every finding has a stable id, scanner, category, severity, rule/advisory id, file path, line, references, an automatic `fp_check`, and a `triage_status` that starts as `needs_review`. Dependency findings also carry `package`, `package_version`, and `aliases`. Secret values are not included. Tool severity is kept as candidate evidence; it is not a probability that the issue is exploitable. Confirm source-to-sink reachability, input control, runtime configuration, and impact before reporting or fixing a result. The report also gives per-tool status, run time, exit code, and a severity summary.

### Source-to-sink analysis

Dependency scanners report vulnerable library versions, and Semgrep CE follows untrusted input only within a single function. The `dataflow` scanner (`whitebox_dataflow.py`) reports request input that reaches a dangerous sink through calls between functions and files. It runs Semgrep CE taint mode in stages:

1. It finds functions whose parameter reaches a sink, such as `run_ping(target)` calling `os.system`. Calls to those functions, with tainted data in that parameter's position, then count as sinks.
2. It finds functions that return request input. Calls to those functions then count as sources.
3. It repeats both steps until no new functions appear (at most 8 rounds), so chains like controller → service → helper → sink are covered.
4. A final pass reports request input that reaches a sink. Each finding has a `trace` of steps from source to sink. The dashboard shows the trace, and the SARIF export carries it as `codeFlows`.

| | Covered |
| --- | --- |
| Languages | Python (Flask, Django, FastAPI), JavaScript/TypeScript (Express, Koa), Java (Servlet, Spring), PHP (plain, Laravel), Go (net/http, gin, echo), Ruby (Rails), C# (ASP.NET) |
| Vulnerability classes | Command injection, code injection, SQL injection, path traversal, SSRF, unsafe deserialization, template injection/XSS, open redirect |

Each class has sanitizers, such as `int()`, `shlex.quote`, `escapeshellarg`, `htmlspecialchars`, and `os.path.basename`. Constant strings never count as tainted. Functions that return an HTTP response are not treated as sources.

Limits:

- Functions are matched by name across the project, so two unrelated functions with the same name can produce a flow that does not exist. Very generic names like `get` and `run` only match plain calls, never method calls. Flows through summarized functions get `confidence: medium`, and flows within one function get `high`.
- Validation in an `if` statement (an allow-list check, `is_numeric`) is not modeled, so validated input can still be reported. Data passed through globals across `include`/`require` of a dynamically built path (common in legacy PHP) is not followed.
- Escaping functions are trusted even where they are insufficient, for example `mysqli_real_escape_string` around a number.
- The default `.semgrepignore` skips `tests/`, `node_modules/`, vendored and minified files.

The test fixtures in `tests/fixtures/dataflow/` hold 29 expected flows across the seven languages, including two-level chains, source wrappers, methods, and sanitized or constant inputs that must not be reported. The suite requires an exact match. On intentionally vulnerable open-source apps it found, for example, DVWA's command injection, SQL injection, and open redirect at low/medium/high, NodeGoat's `eval` injection and SSRF, and pygoat's `pickle` deserialization, `eval`, raw SQL, and SSRF.

### Evidence levels and CVSS

A finding gets a CVSS 3.1 score only when there is concrete evidence that it is real in this code. A vulnerable version number is not enough. Each finding has `evidence.level`, the `evidence.items` explaining it, and `cvss` (null when not scored).

| Level | Meaning | CVSS |
| --- | --- | --- |
| `confirmed` | A reviewer confirmed it through triage. | Yes |
| `reachable` | A concrete path exists: a `dataflow` trace from request input to the sink, or a dependency whose advisory names the vulnerable function and the project calls it. | Yes |
| `present` | The code or package is there but no path was shown: an imported vulnerable package whose advisory does not name the function, a Semgrep pattern match, a secret, or a misconfiguration. | No; the advisory's own score is shown for reference |
| `unverified` | Only the version matched (the project never imports the package), or the false-positive check flagged it. | No |
| `false_positive` | A reviewer marked it as a false positive. | No |

Scores are computed with the CVSS 3.1 base formula, and `cvss.reasons` explains each adjustment.

- **Traced code flows** start from a class vector for an unauthenticated network attacker: 9.8 for command, code, and SQL injection and deserialization, 7.5 for path traversal (file read), 7.2 for SSRF, and 6.1 for XSS and open redirect. When the entry point's function, or a decorator or annotation directly above it, checks login, `PR:N` becomes `PR:L`. Examples are `@login_required`, `request.user.is_authenticated`, `@PreAuthorize`, `[Authorize]`, and `passport.authenticate`. Commented-out checks do not count.
- **Reachable dependencies** use the advisory's vector from Trivy (NVD/GHSA) or OSV.
- **Reviewers** can set their own vector when confirming, for example `PR:H` for an admin-only endpoint. Pass `cvss_vector` to `PATCH /api/scans/{id}/findings/{finding_id}` or to the MCP `whitebox_triage_finding` tool. The vector is stored with the decision and applied to later scans.

`GET /api/scans/{id}/report?evidence=confirmed,reachable` lists only evidence-backed findings. The summary counts findings by evidence level and by CVSS rating, and the dashboard sorts scored findings first. In SARIF, only scored findings carry `security-severity`, so GitHub code scanning ranks by evidence-backed scores.

A static trace is strong evidence but not a working exploit: validation in an `if` statement, configuration, and deployment can still make it unexploitable. Most advisories do not name the vulnerable function, so most dependency findings stop at `present`. On pygoat, 11 of 716 findings were scored. Each was a traced flow and a known vulnerability of the app, and views that check login scored 8.8 instead of 9.8. 222 dependency findings were `unverified` because the package is never imported.

### Claude review of scored findings

When enabled, Claude reviews each finding that has a CVSS score from a traced flow. It reads the trace and the code around every step, then records one of three verdicts:

- `confirmed`: attacker-controlled input reaches the sink with nothing on the path that stops it. Claude describes the attack.
- `false_positive`: a specific control blocks the flow, such as validation, conversion to a number, or a parameterized query. Claude names the control and its file and line.
- `uncertain`: the code shown is not enough to decide. Nothing changes.

`confirmed` and `false_positive` become triage decisions with `triage_decided_by: "agent"` and a note starting with `Claude (<model>):`, so the evidence level and CVSS follow, as for a person's decision. Claude may also return a corrected CVSS vector, for example when the endpoint requires an admin login. Each reviewed finding keeps `agent_review` with the verdict, summary, reasoning, attack scenario or blocking controls, model, and time. The report has a `verification` summary.

Safeguards:

- **A person's decision is never overridden.** Findings you triaged are skipped, and `POST /api/scans/{id}/verify` re-runs the review on a finished report without touching them.
- **Verdicts must cite evidence.** The scanned code is untrusted and may contain comments written to steer a reviewer, so the prompt marks it as data. A `false_positive` that names no blocking control, or a `confirmed` without an attack, is downgraded to `uncertain`.
- **Verdicts are reused.** They are stored per project and match key, so unchanged code is not sent again on the next scan.
- **Refusals are handled.** Requests use the API's server-side fallback (`fallbacks: "default"`), so a request a safety classifier declines is retried on Anthropic's recommended model. A request that is still declined, or fails, leaves the finding `uncertain` and never fails the scan.

**Data sent to Anthropic.** This step is off by default. When on, the code around each reviewed finding, about 12 lines on either side of each trace step and at most 400 lines per finding, is sent to the Claude API together with the trace. Lines that a secret scanner flagged are replaced with `[redacted: possible secret]`. The same excerpts are stored in the report as `code_context`, and the dashboard shows them with the traced lines highlighted. Enable it in `.env`:

```sh
VERIFY_WITH_CLAUDE=1
ANTHROPIC_API_KEY=sk-ant-...
VERIFY_MODEL=claude-opus-5-5     # default
VERIFY_MAX_FINDINGS=20           # highest scores first, per scan
VERIFY_CONCURRENCY=3
```

Then run `docker compose up -d`. The MCP adapter exposes the re-run as `whitebox_verify_scan`.

### False-positive checks

While the source is still extracted, each finding gets `fp_check`: a `verdict`, the `reasons` for it, and `duplicate_of` when it repeats another finding. The check only advises. It never changes `triage_status` and never hides a finding.

| Verdict | When |
| --- | --- |
| `likely_false_positive` | The file is test code or a fixture, or an example, template, or documentation file. The finding's line has a suppression comment (`nosec`, `noqa`, `nosemgrep`, `gitleaks:allow`, `trivy:ignore`, `NOSONAR`, `pragma: allowlist secret`), or a comment line directly above it does. For secrets: the value looks like a placeholder or documentation example, or it is read from the environment or a template variable. |
| `duplicate` | Another finding was reported first for the same package version and vulnerability, matching CVE, GHSA, and PYSEC IDs through their aliases. A secret at the same file and line also counts; Gitleaks and Trivy usually both report it. |
| `needs_review` | No signal. Findings in vendored or generated files keep this verdict, with a reason noting where they are. |

On a project with three pinned Python dependencies, OSV-Scanner and Trivy together reported 170 dependency findings for 68 distinct vulnerabilities. The other 102 are marked `duplicate`. Source lines are read only to compute these checks and are not stored.

Use `GET /api/scans/{id}/report?fp_verdict=needs_review` to list only findings without a false-positive signal, or `triage_status=false_positive` to list decisions.

### Recording triage decisions

`PATCH /api/scans/{id}/findings/{finding_id}` with `{"status": "...", "note": "..."}` records a decision. Status is one of `false_positive`, `confirmed`, `accepted_risk`, `fixed`, or `needs_review` (which clears the decision). The decision also covers the finding's duplicates, updates the stored report and summary, and is applied automatically to later scans with the same `name`.

Later scans match code findings by rule, file, and the whitespace-normalized text of the flagged line, so a decision survives code moving to another line. Secrets are matched by rule, file, and line number, and no hash of a secret-bearing line is stored. Dependency findings are matched by rule, manifest, and package. In the SARIF export, `false_positive` and `accepted_risk` results carry a SARIF `suppressions` entry with the note as justification, so GitHub code scanning dismisses them. Heuristic verdicts alone are never suppressed. The MCP adapter exposes this as `whitebox_triage_finding`, and `whitebox_get_report` accepts `fp_verdict` and `triage_status` filters.

Source archives are removed after a scan. Normalized reports and metadata remain in the `scanner-data` Docker volume for 30 days by default; set `RETENTION_DAYS` to adjust this. Expired jobs are removed at startup and then every hour in the background; set `PRUNE_INTERVAL_SECONDS` to change the interval. Delete a job explicitly through the API or remove all stored data with `docker compose down -v`.

`completed` means every requested scanner completed; `partial` means some completed and some failed or timed out. If none completed, the job is `failed`, and its report still contains scanner diagnostics and any parsed findings. A failure before scanner execution (such as an extraction error) has no report; check the scan's `error` field.

Accepted jobs survive service restarts. An interrupted scan retains its source ZIP and starts again from a clean extraction on startup. Recovery handles every interrupted job (one per `SCAN_CONCURRENCY` worker) plus all ten queued jobs. If concurrent uploads fill the queue, excess requests receive HTTP `503` and can be retried; their temporary uploads are removed.

Larger recovery backlogs are fed into the queue in the background so the API can start immediately. New uploads receive HTTP `503` while recovered jobs are still waiting to enter the queue.

## Limits and data flow

- Default upload size is 200 MiB; expanded ZIP size is limited to 1 GiB.
- The API accepts up to 20,000 ZIP entries by default. The MCP adapter defaults to 20,000 source files and checks the size of the finalized ZIP, including its directory metadata. If you customize these limits, keep `WHITEBOX_MAX_SOURCE_FILES` at or below the API's `MAX_ARCHIVE_ENTRIES`.
- By default one scan runs at a time and runs its scanners one after another, with up to 10 queued jobs. `SCAN_CONCURRENCY` sets how many scans run at once, and `SCANNER_PARALLELISM` sets how many scanners one scan runs at once. `MAX_SCANNER_PROCESSES` caps scanner processes across all scans and defaults to the product of the two. Reports do not depend on these settings: scanners and findings keep the requested order.
- `SCANNER_PROCESS_LIMITS` caps individual tools across all scans. It takes comma-separated `name=limit` overrides of the default `trivy=1,joern=1`; `0` removes a cap. Each Trivy process that finds its vulnerability database out of date downloads it into the shared cache, so concurrent Trivy runs repeat the download and write the same files. Joern is a memory-heavy JVM. Semgrep 1.179.0 was tested running concurrently with a shared home directory and has no cap by default.
- More concurrency needs more CPU and memory. The Compose file limits the container to 2 CPUs and 6 GB (`CPU_LIMIT`, `MEMORY_LIMIT`); raise them along with these settings. Semgrep already uses two jobs per process, and `pids_limit` (512) counts threads as well as processes. Measure with your own repositories before raising limits; `GET /api/metrics` shows queue depth, active scanner processes, and scanner run times.
- Run one Uvicorn worker per data directory, as configured in the Docker image. The queue is local to that process; multiple API workers or replicas sharing a data directory are not supported.
- Each scanner has a 15-minute timeout by default.
- ZIP traversal paths, duplicate paths, encrypted entries, and symlinks are rejected.
- The scanner container runs as an unprivileged user with all Linux capabilities dropped and a read-only root filesystem.
- Semgrep's `p/default` rules, Trivy vulnerability data, and OSV vulnerability matching can require internet access. Semgrep uses an explicit ruleset because `auto` is incompatible with `--metrics=off` in the pinned version. Scanners do not receive credentials from this service.
- Semgrep-maintained rules have usage restrictions. This configuration is for your own internal, self-hosted use; do not offer it as a competing or hosted SaaS scanner without checking the rule license and obtaining the required rights.
- This is static analysis and dependency checking, not proof that a finding is exploitable. Reports need human validation.

## Development checks

Install the service and MCP dependencies in a virtual environment, then run the regression suite:

```bash
python -m pip install -r requirements.txt -e .
python -m unittest discover -s tests -v
```

Tests use temporary storage and mocked scanner execution; they do not invoke scanner binaries or scan external targets. They cover concurrent queue admission, cancellation during upload/extraction/scanning, restart recovery, result states, API upload validation, MCP archive limits, scan concurrency and per-tool process limits, report ordering under parallel scanning, pruning, stored scan summaries, the metrics endpoint, false-positive checks and triage, source-to-sink analysis, evidence levels and CVSS, and Claude review (with the Anthropic SDK against a mocked HTTP transport, never the real API). The dataflow tests run Semgrep when it is installed (CI installs it) and are skipped otherwise. GitHub Actions runs the suite on Python 3.11, 3.12, and 3.13. Real scanner integration still requires the Docker image and installed scanners.
