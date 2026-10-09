"use strict";

const $ = (id) => document.getElementById(id);
const severityOrder = ["critical", "high", "medium", "low", "info", "unknown"];
const severityRank = Object.fromEntries(severityOrder.map((name, index) => [name, index]));
const state = { key: "", scans: [], selected: null, report: null, shown: 40, loading: false };

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

async function loadScans({ quiet = false } = {}) {
  if (state.loading) return;
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
  } catch (error) {
    setConnectionStatus(error.status === 401 ? "Key required" : "Unavailable");
    if (!quiet && error.status !== 401) notice(`Không tải được danh sách scan: ${error.message}`, true);
    if (!quiet && error.status === 401 && state.key) notice("API key không hợp lệ. Kiểm tra lại khóa trong .env.", true);
    if (!state.scans.length) {
      renderScanList();
      $("dashboard").classList.add("hidden");
      $("empty-state").classList.remove("hidden");
    }
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
  const query = $("finding-search").value.trim().toLocaleLowerCase();
  return findings.filter((item) => {
    if (severity !== "all" && item.severity !== severity) return false;
    if (tool !== "all" && item.tool !== tool) return false;
    if (!query) return true;
    return [item.title, item.message, item.path, item.rule_id].some((value) => String(value || "").toLocaleLowerCase().includes(query));
  }).sort((a, b) => (severityRank[a.severity] ?? 6) - (severityRank[b.severity] ?? 6) || String(a.path || "").localeCompare(String(b.path || "")));
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
    const description = node("td");
    description.append(node("span", "finding-title", finding.title || "Potential issue"), node("span", "finding-rule", finding.rule_id || finding.category || ""));
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
  detailSection(content, "EVIDENCE", finding.message || finding.title);
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
  state.scans = []; state.selected = null;
  await loadScans();
});
$("refresh-scans").addEventListener("click", () => loadScans());
$("finding-search").addEventListener("input", () => { state.shown = 40; renderFindings(); });
$("severity-filter").addEventListener("change", () => { state.shown = 40; renderFindings(); });
$("tool-filter").addEventListener("change", () => { state.shown = 40; renderFindings(); });
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
  const link = node("a"); link.href = url; link.download = `astra-report-${state.selected}.json`;
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
  } catch (error) { notice(`Không tạo được scan: ${error.message}`, true); }
  finally { button.disabled = false; button.textContent = "Upload & scan"; }
});
window.addEventListener("hashchange", () => {
  const id = selectedFromHash();
  if (id && id !== state.selected && state.scans.some((scan) => scan.id === id)) {
    state.selected = id; renderScanList(); loadSelectedReport();
  }
});
loadScans();
setInterval(() => { if (state.scans.some((scan) => ["queued", "running"].includes(scan.status))) loadScans({ quiet: true }); }, 15000);
