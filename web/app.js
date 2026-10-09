"use strict";

const $ = (id) => document.getElementById(id);
const severityOrder = ["critical", "high", "medium", "low", "info", "unknown"];
const severityRank = Object.fromEntries(severityOrder.map((name, index) => [name, index]));
const evidenceOrder = ["confirmed", "reachable", "present", "unverified", "false_positive"];
const evidenceLabels = {
  confirmed: "Đã xác nhận", reachable: "Có đường khai thác", present: "Có trong code",
  unverified: "Chưa chứng minh", false_positive: "False positive",
};
function evidenceLevel(finding) { return finding.evidence?.level || "present"; }
const state = { key: "", scans: [], selected: null, report: null, shown: 40, loading: false, unlocked: false };

function node(tag, className, content) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (content !== undefined && content !== null) element.textContent = String(content);
  return element;
}

function clear(element) { element.replaceChildren(); }
function text(id, value) { $(id).textContent = value === undefined || value === null ? "—" : String(value); }
function prettyDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat("vi-VN", { dateStyle: "medium", timeStyle: "short" }).format(date);
}
function notice(message, error = false) {
  const box = $("notice");
  box.textContent = message;
  box.className = error ? "notice error" : "notice";
  if (!message) box.classList.add("hidden");
}
async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.key) headers.set("Authorization", `Bearer ${state.key}`);
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  if (response.status === 204) return null;
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof body.detail === "string" ? body.detail : `HTTP ${response.status}`;
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return body;
}
function selectedFromHash() {
  const match = location.hash.match(/^#scan\/([0-9a-f]{32})$/);
  return match ? match[1] : null;
}
function setConnectionStatus(value) { text("service-state", value); }
function loginError(message) {
  const element = $("login-error");
  element.textContent = message;
  element.classList.toggle("hidden", !message);
}
function unlockScreen() {
  state.unlocked = true;
  $("api-key").value = "";
  $("auth-screen").classList.add("hidden");
  $("app-shell").classList.remove("hidden");
  loginError("");
}
function lockScreen(message = "") {
  state.unlocked = false;
  state.key = "";
  state.scans = [];
  state.selected = null;
  state.report = null;
  $("api-key").value = "";
  $("app-shell").classList.add("hidden");
  $("auth-screen").classList.remove("hidden");
  loginError(message);
  closeDetail();
  $("api-key").focus();
}
function applyTheme(theme) {
  const active = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = active;
  document.querySelectorAll(".theme-toggle").forEach((button) => {
    button.textContent = active === "light" ? "☾ Chế độ tối" : "☀ Chế độ sáng";
  });
  try { localStorage.setItem("whitebox-theme", active); } catch { /* Theme remains active for this page. */ }
}

async function loadScans({ quiet = false } = {}) {
  if (state.loading) return false;
  state.loading = true;
  try {
    const data = await api("/api/scans?limit=200");
    state.scans = Array.isArray(data.scans) ? data.scans : [];
    setConnectionStatus("Connected");
    if (!quiet) notice("");
    const preferred = selectedFromHash() || state.selected;
    state.selected = state.scans.some((scan) => scan.id === preferred) ? preferred : state.scans[0]?.id || null;
    renderScanList();
    await loadSelectedReport();
    return Boolean(state.key);
  } catch (error) {
    setConnectionStatus(error.status === 401 ? "Key required" : "Unavailable");
    if (state.unlocked) {
      if (error.status === 401) lockScreen("API key không còn hợp lệ. Vui lòng đăng nhập lại.");
      else if (!quiet) notice(`Không tải được danh sách scan: ${error.message}`, true);
    } else {
      state.key = "";
      loginError(error.status === 401 ? "API key không đúng. Kiểm tra giá trị trong file .env." : `Không kết nối được dịch vụ: ${error.message}`);
    }
    return false;
  } finally { state.loading = false; }
}

function renderScanList() {
  const list = $("scan-list");
  clear(list);
  if (!state.scans.length) {
    list.append(node("p", "muted inset", "Chưa có scan nào. Tạo scan mới để bắt đầu."));
    return;
  }
  for (const scan of state.scans) {
    const button = node("button", `scan-item${scan.id === state.selected ? " active" : ""}`);
    button.type = "button";
    const icon = node("span", "scan-icon", "⌁");
    const content = node("span");
    content.append(node("strong", "", scan.name || "Untitled scan"), node("small", "", `${scan.status || "unknown"} · ${prettyDate(scan.created_at)}`));
    button.append(icon, content);
    button.addEventListener("click", () => {
      if (state.selected === scan.id) return;
      state.selected = scan.id;
      location.hash = `scan/${scan.id}`;
      renderScanList();
      loadSelectedReport();
    });
    list.append(button);
  }
}

async function loadSelectedReport() {
  const id = state.selected;
  const scan = state.scans.find((item) => item.id === id);
  if (!scan) {
    state.report = null;
    $("dashboard").classList.add("hidden");
    $("empty-state").classList.remove("hidden");
    $("empty-state").querySelector("p:last-child").textContent = "Chưa có lượt scan. Dùng New scan để tải mã nguồn ZIP lên.";
    return;
  }
  $("empty-state").classList.add("hidden");
  $("dashboard").classList.remove("hidden");
  text("project-title", scan.name || "Untitled scan");
  text("scan-date", prettyDate(scan.created_at));
  text("scan-id", `ID ${scan.id}`);
  text("scan-status", scan.status || "unknown");
  $("scan-status").className = `status-pill ${["partial", "failed", "queued", "running"].includes(scan.status) ? scan.status : ""}`;
  state.report = null;
  if (["queued", "running"].includes(scan.status)) {
    setRunBanner("Scan đang chạy. Trang sẽ tự cập nhật khi có báo cáo.");
    renderReport();
    return;
  }
  try {
    const report = await api(`/api/scans/${id}/report`);
    if (state.selected !== id) return;
    state.report = report;
    const failed = (report.scanners || []).filter((scanner) => scanner.status !== "completed");
    setRunBanner(failed.length ? `Báo cáo chưa đầy đủ: ${failed.map((item) => item.name).join(", ")} không hoàn tất. Xem trạng thái scanner trong JSON.` : "");
  } catch (error) {
    if (error.status === 401) { lockScreen("API key không còn hợp lệ. Vui lòng đăng nhập lại."); return; }
    setRunBanner(error.status === 409 ? "Báo cáo chưa sẵn sàng. Trang sẽ thử tải lại." : `Không tải được báo cáo: ${error.message}`);
  }
  renderReport();
}
function setRunBanner(message) {
  const banner = $("run-banner");
  banner.textContent = message;
  banner.classList.toggle("hidden", !message);
}

function renderReport() {
  const report = state.report;
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const counts = Object.fromEntries(severityOrder.map((severity) => [severity, 0]));
  const tools = new Map();
  for (const finding of findings) {
    const severity = severityOrder.includes(finding.severity) ? finding.severity : "unknown";
    counts[severity] += 1;
    const tool = String(finding.tool || "unknown");
    tools.set(tool, (tools.get(tool) || 0) + 1);
  }
  text("metric-total", findings.length);
  text("metric-critical", counts.critical);
  text("metric-high", counts.high);
  text("metric-medium", counts.medium);
  text("severity-count", `${findings.length} findings`);
  text("scanner-count", `${(report?.scanners || []).length} scanners`);
  $("download-report").disabled = !report;
  renderSeverityChart(counts, findings.length);
  renderToolChart(tools, findings.length);
  renderToolFilter(tools);
  renderFindings();
}

function renderSeverityChart(counts, total) {
  const chart = $("severity-chart");
  const legend = $("severity-legend");
  clear(chart); clear(legend);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 1000 15");
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", "15");
  const colors = { critical: "#f56c79", high: "#f5a66a", medium: "#e0be70", low: "#6b9de6", info: "#5bcfba", unknown: "#778497" };
  let x = 0;
  for (const severity of severityOrder) {
    const width = total ? counts[severity] / total * 1000 : 0;
    if (width) {
      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      rect.setAttribute("x", String(x)); rect.setAttribute("y", "0");
      rect.setAttribute("width", String(width)); rect.setAttribute("height", "15");
      rect.setAttribute("fill", colors[severity]);
      svg.append(rect);
    }
    x += width;
    const item = node("div", "legend-item");
    const label = node("span", "legend-label");
    label.append(node("i", `swatch ${severity}`), node("span", "", severity));
    item.append(label, node("b", "", counts[severity]));
    legend.append(item);
  }
  chart.append(svg);
}

function renderToolChart(tools, total) {
  const chart = $("tool-chart"); clear(chart);
  if (!tools.size) { chart.append(node("p", "muted", "Chưa có kết quả scanner.")); return; }
  for (const [tool, count] of [...tools].sort((a, b) => b[1] - a[1])) {
    const row = node("div", "tool-row");
    const head = node("div", "tool-row-head");
    head.append(node("span", "", tool), node("b", "", count));
    const progress = node("progress");
    progress.max = total || 1; progress.value = count;
    row.append(head, progress); chart.append(row);
  }
}
function renderToolFilter(tools) {
  const select = $("tool-filter");
  const selected = select.value;
  select.replaceChildren(new Option("All scanners", "all"));
  for (const tool of [...tools.keys()].sort()) select.add(new Option(tool, tool));
  select.value = tools.has(selected) ? selected : "all";
}

function filteredFindings() {
  const findings = Array.isArray(state.report?.findings) ? state.report.findings : [];
  const severity = $("severity-filter").value;
  const tool = $("tool-filter").value;
  const evidence = $("evidence-filter").value;
  const query = $("finding-search").value.trim().toLocaleLowerCase();
  return findings.filter((item) => {
    if (severity !== "all" && item.severity !== severity) return false;
    if (tool !== "all" && item.tool !== tool) return false;
    if (evidence === "scored" && !item.cvss) return false;
    if (!["all", "scored"].includes(evidence) && evidenceLevel(item) !== evidence) return false;
    if (!query) return true;
    return [item.title, item.message, item.path, item.rule_id].some((value) => String(value || "").toLocaleLowerCase().includes(query));
  }).sort((a, b) => (b.cvss?.score ?? -1) - (a.cvss?.score ?? -1)
    || evidenceOrder.indexOf(evidenceLevel(a)) - evidenceOrder.indexOf(evidenceLevel(b))
    || (severityRank[a.severity] ?? 6) - (severityRank[b.severity] ?? 6)
    || String(a.path || "").localeCompare(String(b.path || "")));
}
function renderFindings() {
  const findings = filteredFindings();
  const body = $("findings-body"); clear(body);
  text("visible-count", findings.length);
  for (const finding of findings.slice(0, state.shown)) {
    const row = node("tr", "finding-row");
    row.tabIndex = 0;
    row.setAttribute("aria-label", `Xem finding: ${finding.title || "Potential issue"}`);
    const severity = node("td");
    severity.append(node("span", `severity-badge ${severityOrder.includes(finding.severity) ? finding.severity : "unknown"}`, finding.severity || "unknown"));
    if (finding.cvss) severity.append(node("span", `cvss-badge ${finding.cvss.rating}`, `CVSS ${finding.cvss.score.toFixed(1)}`));
    const description = node("td");
    const level = evidenceLevel(finding);
    const rule = node("span", "finding-rule", finding.rule_id || finding.category || "");
    rule.prepend(node("span", `evidence-chip ${level}`, evidenceLabels[level] || level));
    description.append(node("span", "finding-title", finding.title || "Potential issue"), rule);
    const locationCell = node("td");
    locationCell.append(node("span", "location", `${finding.path || "Unknown file"}${finding.line ? `:${finding.line}` : ""}`));
    const toolCell = node("td", "tool-name", finding.tool || "—");
    row.append(severity, description, locationCell, toolCell, node("td", "row-arrow", "↗"));
    row.addEventListener("click", () => showDetail(finding));
    row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); showDetail(finding); } });
    body.append(row);
  }
  $("no-findings").classList.toggle("hidden", findings.length > 0);
  $("show-more").classList.toggle("hidden", findings.length <= state.shown);
}

function detailSection(parent, label, value, code = false) {
  const section = node("section", "detail-section");
  section.append(node("h3", "", label), node(code ? "code" : "p", "", value || "—"));
  parent.append(section);
}
function showDetail(finding) {
  const content = $("detail-content"); clear(content);
  content.append(node("h2", "detail-title", finding.title || "Potential issue"));
  const meta = node("div", "detail-meta");
  meta.append(node("span", `severity-badge ${severityOrder.includes(finding.severity) ? finding.severity : "unknown"}`, finding.severity || "unknown"), node("span", "severity-badge", finding.tool || "unknown"), node("span", "severity-badge", finding.category || "unknown"));
  content.append(meta);
  const info = node("section", "detail-section");
  info.append(node("h3", "", "LOCATION & RULE"));
  const dl = node("dl", "detail-kv");
  for (const [label, value] of [["File", finding.path], ["Line", finding.line], ["Rule ID", finding.rule_id], ["Confidence", finding.confidence], ["Triage", finding.triage_status || "needs_review"]]) {
    dl.append(node("dt", "", label), node("dd", "", value || "—"));
  }
  info.append(dl); content.append(info);
  const trace = Array.isArray(finding.trace) ? finding.trace : [];
  if (trace.length) {
    const section = node("section", "detail-section");
    section.append(node("h3", "", "DATA FLOW · SOURCE → SINK"));
    const list = node("ol", "trace-list");
    for (const step of trace) {
      const item = node("li", `trace-step ${["source", "sink"].includes(step.kind) ? step.kind : "hop"}`);
      item.append(node("span", "trace-detail", step.detail || step.kind || "Step"), node("span", "trace-location", `${step.path || "?"}${step.line ? `:${step.line}` : ""}`));
      list.append(item);
    }
    section.append(list);
    content.append(section);
  } else {
    detailSection(content, "DETAILS", finding.message || finding.title);
  }
  const level = evidenceLevel(finding);
  const evidenceBox = node("section", "detail-section");
  evidenceBox.append(node("h3", "", `BẰNG CHỨNG · ${(evidenceLabels[level] || level).toUpperCase()}`));
  const evidenceList = node("ul", "evidence-list");
  for (const item of finding.evidence?.items || []) evidenceList.append(node("li", "", item));
  evidenceBox.append(evidenceList);
  if (finding.cvss) {
    const scoreLine = node("p", "cvss-line");
    scoreLine.append(node("span", `cvss-badge ${finding.cvss.rating}`, `CVSS ${finding.cvss.version} · ${finding.cvss.score.toFixed(1)} ${finding.cvss.rating}`), node("code", "cvss-vector", finding.cvss.vector));
    evidenceBox.append(scoreLine);
    const reasons = node("ul", "evidence-list");
    for (const reason of finding.cvss.reasons || []) reasons.append(node("li", "", reason));
    evidenceBox.append(reasons);
  } else {
    const advisory = finding.advisory_cvss?.vector ? ` Điểm của advisory (chỉ tham khảo): ${finding.advisory_cvss.score ?? ""} — ${finding.advisory_cvss.vector}.` : "";
    evidenceBox.append(node("p", "cvss-none", `Không chấm CVSS: chưa có bằng chứng cho thấy lỗi khai thác được trong code này.${advisory}`));
  }
  content.append(evidenceBox);
  const check = finding.fp_check;
  if (check && check.verdict && check.verdict !== "needs_review") {
    const reasons = (check.reasons || []).join(" ");
    detailSection(content, "FALSE-POSITIVE CHECK", `${check.verdict === "duplicate" ? "Duplicate" : "Likely false positive"}. ${reasons}`);
  }
  const refs = Array.isArray(finding.references) ? finding.references : [];
  if (refs.length) {
    const section = node("section", "detail-section"); section.append(node("h3", "", "REFERENCES"));
    for (const value of refs) {
      try {
        const url = new URL(value);
        if (!["https:", "http:"].includes(url.protocol)) continue;
        const link = node("a", "", value);
        link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer";
        section.append(link);
      } catch { /* Ignore malformed scanner references. */ }
    }
    content.append(section);
  }
  $("detail-backdrop").classList.remove("hidden");
  $("detail-panel").classList.remove("hidden");
  $("detail-panel").focus();
}
function closeDetail() {
  $("detail-backdrop").classList.add("hidden");
  $("detail-panel").classList.add("hidden");
}

$("key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.key = $("api-key").value.trim().replace(/^Bearer\s+/i, "");
  if (!state.key) { loginError("Nhập API key để tiếp tục."); return; }
  loginError("");
  state.scans = []; state.selected = null;
  const button = $("connect-button");
  button.disabled = true;
  button.textContent = "Đang kiểm tra...";
  try { if (await loadScans()) unlockScreen(); }
  finally { button.disabled = false; button.textContent = "Vào dashboard →"; }
});
$("lock-session").addEventListener("click", () => lockScreen());
document.querySelectorAll(".theme-toggle").forEach((button) => button.addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
}));
$("refresh-scans").addEventListener("click", () => loadScans());
$("finding-search").addEventListener("input", () => { state.shown = 40; renderFindings(); });
$("severity-filter").addEventListener("change", () => { state.shown = 40; renderFindings(); });
$("tool-filter").addEventListener("change", () => { state.shown = 40; renderFindings(); });
$("evidence-filter").addEventListener("change", () => { state.shown = 40; renderFindings(); });
$("show-more").addEventListener("click", () => { state.shown += 40; renderFindings(); });
document.querySelectorAll(".metric-card").forEach((button) => button.addEventListener("click", () => {
  $("severity-filter").value = button.dataset.severity;
  state.shown = 40; renderFindings();
  document.querySelector(".findings-section").scrollIntoView({ behavior: "smooth" });
}));
$("download-report").addEventListener("click", () => {
  if (!state.report) return;
  const blob = new Blob([JSON.stringify(state.report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = node("a"); link.href = url; link.download = `whitebox-report-${state.selected}.json`;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("close-detail").addEventListener("click", closeDetail);
$("detail-backdrop").addEventListener("click", closeDetail);
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDetail(); });
$("upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const selected = [...form.querySelectorAll('input[name="scanner"]:checked')].map((input) => input.value);
  if (!selected.length) { notice("Chọn ít nhất một scanner.", true); return; }
  const file = $("scan-file").files[0];
  if (!file) { notice("Chọn tệp ZIP mã nguồn.", true); return; }
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true; button.textContent = "Uploading...";
  try {
    const body = new FormData();
    body.set("name", $("scan-name").value.trim() || file.name);
    body.set("scanners", selected.join(","));
    body.set("source", file);
    const scan = await api("/api/scans", { method: "POST", body });
    form.reset();
    state.selected = scan.id;
    location.hash = `scan/${scan.id}`;
    notice("Đã nhận source. Scan đang xếp hàng.");
    await loadScans({ quiet: true });
  } catch (error) {
    if (error.status === 401) lockScreen("API key không còn hợp lệ. Vui lòng đăng nhập lại.");
    else notice(`Không tạo được scan: ${error.message}`, true);
  }
  finally { button.disabled = false; button.textContent = "Upload & scan"; }
});
window.addEventListener("hashchange", () => {
  const id = selectedFromHash();
  if (id && id !== state.selected && state.scans.some((scan) => scan.id === id)) {
    state.selected = id; renderScanList(); loadSelectedReport();
  }
});
let savedTheme = "dark";
try { savedTheme = localStorage.getItem("whitebox-theme") || "dark"; } catch { /* Storage can be disabled. */ }
applyTheme(savedTheme);
setInterval(() => { if (state.unlocked && state.scans.some((scan) => ["queued", "running"].includes(scan.status))) loadScans({ quiet: true }); }, 15000);
