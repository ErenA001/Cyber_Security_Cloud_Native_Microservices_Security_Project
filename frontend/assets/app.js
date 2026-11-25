const state = {
  user: null,
  view: "dashboard",
  history: [],
  latestAnalysis: "",
  latestEvents: [],
  aiConfigured: false,
  aiVerified: false,
  scanReports: [],
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function showToast(message, isError = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("visible"), 3600);
}

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  if (method !== "GET" && method !== "HEAD") headers.set("X-Requested-With", "XMLHttpRequest");
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...options, method, headers, credentials: "same-origin" });
  const contentType = response.headers.get("content-type") || "";
  let payload = null;
  if (contentType.includes("application/json")) {
    try { payload = await response.json(); } catch (_) { payload = null; }
  } else {
    try { payload = { detail: (await response.text()).slice(0, 240) }; } catch (_) { payload = null; }
  }
  if (!response.ok) {
    const message = payload && (payload.detail || payload.error) ? (payload.detail || payload.error) : `Request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function showLogin() {
  state.user = null;
  state.history = [];
  state.latestAnalysis = "";
  state.latestEvents = [];
  state.aiVerified = false;
  const chatMessages = $("#chat-messages");
  if (chatMessages) {
    chatMessages.replaceChildren();
    addMessage("assistant", "Hello. I can help explain microservices security, review saved security evidence, and suggest defensive improvements. What would you like to investigate?");
  }
  const loginForm = $("#login-form");
  if (loginForm) loginForm.reset();
  const loginError = $("#login-error");
  if (loginError) loginError.textContent = "";
  const passwordForm = $("#password-change-form");
  if (passwordForm) passwordForm.reset();
  $("#app-shell").classList.add("hidden");
  $("#login-screen").classList.remove("hidden");
}

function showApp(user) {
  state.user = user;
  $("#login-screen").classList.add("hidden");
  $("#app-shell").classList.remove("hidden");
  $("#user-name").textContent = user.username;
  $("#user-role").textContent = (user.role || "user").toUpperCase();
  $("#user-avatar").textContent = (user.username || "C").slice(0, 1).toUpperCase();
  $("#greeting-name").textContent = user.username;
  setView("dashboard");
  refreshDashboard();
  loadChatHistory();
}

function setView(view) {
  state.view = view;
  const titles = { dashboard: "Overview", analyst: "AI Analyst", lab: "Security Lab", events: "Event Log", settings: "Security Settings" };
  $$(".view-section").forEach((section) => section.classList.add("hidden"));
  const target = $(`#${view}-view`);
  if (target) target.classList.remove("hidden");
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  $("#topbar-title").textContent = titles[view] || "Overview";
  if (view === "events") loadEvents();
  if (view === "analyst") updateAnalystContext();
  if (view === "lab") loadScanReports();
}

function safeDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown time";
  return date.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function eventLabel(value) {
  return String(value || "event").replace(/\.simulated$/i, " (simulated)").replace(/[._-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function setServiceStatus(name, stateName, label) {
  const node = $(`#status-${name}`);
  if (!node) return;
  node.className = `service-state ${stateName}`;
  node.replaceChildren(document.createElement("i"), document.createTextNode(label));
}

function renderChart(timeline = []) {
  const chart = $("#activity-chart");
  chart.replaceChildren();
  if (!timeline.length) {
    const empty = document.createElement("div");
    empty.className = "loading-line";
    empty.textContent = "No activity data yet";
    chart.appendChild(empty);
    return;
  }
  const max = Math.max(1, ...timeline.map((item) => (item.critical || 0) + (item.warning || 0) + (item.info || 0)));
  timeline.forEach((item) => {
    const column = document.createElement("div");
    column.className = "chart-column";
    column.title = `${item.label}: ${item.critical || 0} critical, ${item.warning || 0} warnings, ${item.info || 0} info`;
    [
      ["critical", item.critical || 0],
      ["warning", item.warning || 0],
      ["info", item.info || 0],
    ].forEach(([kind, count]) => {
      const bar = document.createElement("div");
      bar.className = `chart-bar ${kind}`;
      bar.style.height = `${count ? Math.max(5, (count / max) * 100) : 2}%`;
      bar.setAttribute("aria-label", `${kind}: ${count}`);
      column.appendChild(bar);
    });
    chart.appendChild(column);
  });
}

function makeRecentEvent(event) {
  const row = document.createElement("div");
  row.className = "recent-event";
  const marker = document.createElement("span");
  marker.className = `event-marker ${event.severity}`;
  const main = document.createElement("div");
  main.className = "recent-event-main";
  const title = document.createElement("div");
  title.className = "recent-event-title";
  title.textContent = eventLabel(event.event_type);
  const meta = document.createElement("div");
  meta.className = "recent-event-meta";
  const source = document.createElement("span");
  source.textContent = event.source || "unknown";
  const time = document.createElement("span");
  time.textContent = safeDate(event.created_at);
  meta.append(source, time);
  main.append(title, meta);
  const severity = document.createElement("span");
  severity.className = `event-severity ${event.severity}`;
  severity.textContent = event.severity;
  row.append(marker, main, severity);
  return row;
}

function renderRecentEvents(events) {
  const target = $("#recent-events");
  target.replaceChildren();
  if (!events.length) {
    const empty = document.createElement("div");
    empty.className = "loading-line";
    empty.textContent = "No security events recorded yet. Try a safe simulation in Security Lab.";
    target.appendChild(empty);
    return;
  }
  events.slice(0, 5).forEach((event) => target.appendChild(makeRecentEvent(event)));
}

function renderEventTable(events) {
  const body = $("#events-table-body");
  body.replaceChildren();
  $("#event-count-label").textContent = `${events.length} RECORDS`;
  if (!events.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "empty-cell";
    cell.textContent = "No events match this filter.";
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  events.forEach((event) => {
    const row = document.createElement("tr");
    const severityCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `severity-badge ${event.severity}`;
    badge.textContent = event.severity;
    severityCell.appendChild(badge);
    const nameCell = document.createElement("td");
    nameCell.className = "event-name-cell";
    nameCell.textContent = eventLabel(event.event_type);
    const sourceCell = document.createElement("td");
    sourceCell.textContent = event.source || "-";
    const actorCell = document.createElement("td");
    actorCell.textContent = event.actor || "system";
    const timeCell = document.createElement("td");
    timeCell.textContent = safeDate(event.created_at);
    row.append(severityCell, nameCell, sourceCell, actorCell, timeCell);
    body.appendChild(row);
  });
}

async function loadEvents() {
  const severity = $("#severity-filter").value;
  const query = severity ? `?limit=100&severity=${encodeURIComponent(severity)}` : "?limit=100";
  try {
    const data = await api(`/api/monitor/events${query}`);
    state.latestEvents = data.events || [];
    renderEventTable(state.latestEvents);
    updateAnalystContext();
  } catch (error) {
    if (error.status === 401) return showLogin();
    showToast(error.message, true);
  }
}

async function refreshDashboard() {
  try {
    const [summaryResult, eventsResult, gatewayResult, authResult, aiResult, monitorResult] = await Promise.allSettled([
      api("/api/monitor/summary"),
      api("/api/monitor/events?limit=12"),
      api("/api/health"),
      api("/api/auth/health"),
      api("/api/ai/health"),
      api("/api/monitor/health"),
    ]);

    if (summaryResult.status === "fulfilled") {
      const summary = summaryResult.value;
      $("#metric-critical").textContent = summary.critical ?? 0;
      $("#metric-warnings").textContent = summary.warnings ?? 0;
      $("#metric-total").textContent = summary.total_events ?? 0;
      $("#metric-total-foot").textContent = `Last 24 hours / ${summary.all_time_events ?? 0} all-time`;
      renderChart(summary.timeline || []);
    }
    if (eventsResult.status === "fulfilled") {
      state.latestEvents = eventsResult.value.events || [];
      renderRecentEvents(state.latestEvents);
      updateAnalystContext();
    }

    const sessionExpired = [summaryResult, eventsResult].some((result) => result.status === "rejected" && result.reason?.status === 401);
    if (sessionExpired) {
      showLogin();
      return;
    }

    const gatewayOk = gatewayResult.status === "fulfilled";
    const authOk = authResult.status === "fulfilled";
    const monitorOk = monitorResult.status === "fulfilled";
    const aiOk = aiResult.status === "fulfilled";
    setServiceStatus("gateway", gatewayOk ? "ok" : "down", gatewayOk ? "Operational" : "Offline");
    setServiceStatus("auth", authOk ? "ok" : "down", authOk ? "Operational" : "Offline");
    setServiceStatus("monitor", monitorOk ? "ok" : "down", monitorOk ? "Operational" : "Offline");

    if (aiOk) {
      state.aiConfigured = Boolean(aiResult.value.provider_configured);
      const configured = state.aiConfigured;
      setServiceStatus("ai", state.aiVerified ? "ok" : "warn", state.aiVerified ? "Verified" : configured ? "Key configured" : "Key needed");
      $("#metric-ai").textContent = configured ? (state.aiVerified ? "Connected" : "Configured") : "Key needed";
      $("#metric-ai-foot").textContent = configured ? (state.aiVerified ? "Live inference verified" : "Inference not yet checked") : "Add NVIDIA_API_KEY to .env";
      $("#ai-dot").style.background = state.aiVerified ? "var(--green)" : "var(--amber)";
      $("#provider-chip").innerHTML = `<span class="pulse-dot"></span> ${state.aiVerified ? "NVIDIA NIM CONNECTED" : configured ? "NVIDIA KEY CONFIGURED" : "NVIDIA KEY REQUIRED"}`;
      $("#chat-model-label").textContent = `${aiResult.value.provider} / ${aiResult.value.model}`;
    } else {
      setServiceStatus("ai", "down", "Offline");
      $("#metric-ai").textContent = "Offline";
      $("#metric-ai-foot").textContent = "AI service unavailable";
      $("#provider-chip").textContent = "AI service offline";
    }
    $("#sidebar-gateway-status").textContent = gatewayOk ? "Operational" : "Offline";
  } catch (error) {
    showToast(error.message, true);
  }
}

function updateAnalystContext() {
  $("#context-event-count").textContent = state.latestEvents.length;
}

function renderAnalysis(text) {
  const target = $("#analysis-content");
  target.replaceChildren();
  const content = document.createElement("div");
  content.className = "analysis-text";
  content.textContent = text;
  target.appendChild(content);
}

async function analyzeLatestEvents() {
  const buttons = [$("#dashboard-analyze-button"), $("#analyst-analyze-button")].filter(Boolean);
  buttons.forEach((button) => { button.disabled = true; button.textContent = "Analyzing..."; });
  try {
    const result = await api("/api/ai/analyze-events", { method: "POST", body: "{}" });
    state.aiVerified = true;
    $("#metric-ai").textContent = "Connected";
    $("#metric-ai-foot").textContent = "Live inference verified";
    $("#provider-chip").innerHTML = '<span class="pulse-dot"></span> NVIDIA NIM CONNECTED';
    setServiceStatus("ai", "ok", "Verified");
    state.latestAnalysis = result.reply || "No analysis was returned.";
    renderAnalysis(state.latestAnalysis);
    addMessage("assistant", `Event analysis (${result.events_analyzed} events, ${result.scans_analyzed || 0} scans):\n\n${state.latestAnalysis}`);
    state.history.push({ role: "user", content: "Analyze latest security events and container scan reports." }, { role: "assistant", content: state.latestAnalysis });
    state.history = state.history.slice(-20);
    showToast("AI analysis completed.");
  } catch (error) {
    if (error.status === 401) showLogin();
    else showToast(error.message, true);
  } finally {
    buttons.forEach((button) => {
      button.disabled = false;
      button.innerHTML = button.id === "dashboard-analyze-button" ? '<span class="sparkle">&#10022;</span> Analyze recent events' : '&#10022; Analyze latest events';
    });
  }
}

function addMessage(role, text) {
  const messages = $("#chat-messages");
  const row = document.createElement("div");
  row.className = `chat-message ${role === "user" ? "user-message" : "assistant-message"}`;
  const avatar = document.createElement("div");
  avatar.className = "message-avatar";
  avatar.textContent = role === "user" ? (state.user?.username || "U").slice(0, 2).toUpperCase() : "CG";
  const body = document.createElement("div");
  body.className = "message-body";
  const author = document.createElement("div");
  author.className = "message-author";
  author.textContent = role === "user" ? (state.user?.username || "You") : "CloudGuard AI";
  const roleTag = document.createElement("span");
  roleTag.textContent = role === "user" ? "YOU" : "ASSISTANT";
  author.appendChild(roleTag);
  const content = document.createElement("div");
  content.className = "message-text";
  content.textContent = text;
  body.append(author, content);
  row.append(avatar, body);
  messages.appendChild(row);
  messages.scrollTop = messages.scrollHeight;
}

async function sendChatMessage(message) {
  const cleanMessage = message.trim();
  if (!cleanMessage) return;
  addMessage("user", cleanMessage);
  const sendButton = $("#chat-send");
  sendButton.disabled = true;
  sendButton.textContent = "...";
  try {
    const result = await api("/api/ai/chat", {
      method: "POST",
      body: JSON.stringify({ message: cleanMessage }),
    });
    const reply = result.reply || "No response was returned.";
    state.aiVerified = true;
    addMessage("assistant", reply);
    state.history.push({ role: "user", content: cleanMessage }, { role: "assistant", content: reply });
    state.history = state.history.slice(-20);
    const chip = $("#provider-chip");
    if (chip) chip.innerHTML = '<span class="pulse-dot"></span> NVIDIA NIM CONNECTED';
    $("#metric-ai").textContent = "Connected";
    $("#metric-ai-foot").textContent = "Live inference verified";
    setServiceStatus("ai", "ok", "Verified");
  } catch (error) {
    if (error.status === 401) showLogin();
    else addMessage("assistant", `I could not complete that request: ${error.message}`);
  } finally {
    sendButton.disabled = false;
    sendButton.textContent = "\u27a4";
    $("#chat-input").focus();
  }
}

async function loadChatHistory() {
  try {
    const result = await api("/api/ai/history?limit=40");
    const messages = result.messages || [];
    state.history = messages.map(({ role, content }) => ({ role, content }));
    if (messages.length) {
      const target = $("#chat-messages");
      target.replaceChildren();
      messages.forEach((message) => addMessage(message.role, message.content));
    }
  } catch (error) {
    if (error.status === 401) showLogin();
    else showToast(`Could not load saved chat history: ${error.message}`, true);
  }
}

async function clearChatHistory() {
  if (!window.confirm("Start a new conversation? This clears the saved AI chat history for your account.")) return;
  try {
    await api("/api/ai/history", { method: "DELETE", body: "{}" });
    state.history = [];
    const target = $("#chat-messages");
    target.replaceChildren();
    addMessage("assistant", "Hello. I can help explain microservices security, review saved security evidence, and suggest defensive improvements. What would you like to investigate?");
    showToast("A new conversation has started.");
  } catch (error) {
    if (error.status === 401) showLogin();
    else showToast(error.message, true);
  }
}

function renderScanReports(reports) {
  state.scanReports = reports || [];
  const summaryTarget = $("#scan-summary");
  const body = $("#scan-table-body");
  summaryTarget.replaceChildren();
  body.replaceChildren();
  if (!state.scanReports.length) {
    summaryTarget.textContent = "No real Trivy scan has been uploaded yet. Run the command above to scan the four local images.";
    summaryTarget.className = "scan-summary scan-empty";
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.className = "empty-cell";
    cell.textContent = "No scan reports yet.";
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  summaryTarget.className = "scan-summary";
  const latest = state.scanReports[0];
  const counts = latest.summary || {};
  const stats = [
    ["LATEST IMAGE", latest.image || "Unknown"],
    ["CRITICAL", counts.critical || 0],
    ["HIGH", counts.high || 0],
    ["TOTAL FINDINGS", (counts.vulnerabilities || 0) + (counts.misconfigurations || 0) + (counts.secrets || 0)],
  ];
  stats.forEach(([label, value]) => {
    const card = document.createElement("div");
    card.className = "scan-stat";
    const title = document.createElement("span");
    title.textContent = label;
    const content = document.createElement("strong");
    content.textContent = value;
    card.append(title, content);
    summaryTarget.appendChild(card);
  });
  state.scanReports.forEach((report) => {
    const row = document.createElement("tr");
    const values = [
      report.image || "-", `${report.scanner || "Trivy"} ${report.scanner_version || ""}`.trim(),
      report.summary?.critical || 0, report.summary?.high || 0, report.summary?.medium || 0,
      (report.summary?.vulnerabilities || 0) + (report.summary?.misconfigurations || 0) + (report.summary?.secrets || 0),
      safeDate(report.created_at),
    ];
    values.forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = String(value);
      row.appendChild(cell);
    });
    body.appendChild(row);
  });
}

function renderAssessmentReports(reports) {
  const body = $("#assessment-table-body");
  body.replaceChildren();
  if (!reports.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "empty-cell";
    cell.textContent = "No assessment results yet. Run python3 tests/security_regression.py from the project folder.";
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  reports.forEach((report) => {
    const row = document.createElement("tr");
    const values = [report.name || "Security assessment", String(report.status || "unknown").toUpperCase(), report.passed || 0, report.failed || 0, safeDate(report.created_at)];
    values.forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = String(value);
      row.appendChild(cell);
    });
    body.appendChild(row);
  });
}

async function loadScanReports() {
  try {
    const [scanResult, assessmentResult] = await Promise.all([
      api("/api/monitor/scan-reports?limit=10"),
      api("/api/monitor/assessment-reports?limit=10"),
    ]);
    renderScanReports(scanResult.scan_reports || []);
    renderAssessmentReports(assessmentResult.assessment_reports || []);
  } catch (error) {
    if (error.status === 401) showLogin();
    else showToast(`Could not load scan reports: ${error.message}`, true);
  }
}

async function copyCommand(command) {
  try {
    await navigator.clipboard.writeText(command);
    showToast("Command copied. Run it from the CloudGuard project folder.");
  } catch (_) {
    showToast(`Copy this command from the screen: ${command}`, true);
  }
}

async function downloadSecurityReport() {
  const button = $("#download-report-button");
  button.disabled = true;
  try {
    const report = await api("/api/monitor/report");
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `cloudguard-security-report-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast("Security report downloaded.");
  } catch (error) {
    if (error.status === 401) showLogin();
    else showToast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function handlePasswordChange(event) {
  event.preventDefault();
  const errorNode = $("#password-change-error");
  const currentPassword = $("#current-password").value;
  const newPassword = $("#new-password").value;
  const confirmPassword = $("#confirm-password").value;
  errorNode.textContent = "";
  if (newPassword.length < 14) {
    errorNode.textContent = "The new password must contain at least 14 characters.";
    return;
  }
  if (newPassword !== confirmPassword) {
    errorNode.textContent = "The new passwords do not match.";
    return;
  }
  const button = $("#password-change-form button[type='submit']");
  button.disabled = true;
  try {
    await api("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
    $("#password-change-form").reset();
    showLogin();
    showToast("Password changed. Sign in with your new password.");
  } catch (error) {
    if (error.status === 401) showLogin();
    else errorNode.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function simulateScenario(scenario, button) {
  if (button) button.disabled = true;
  try {
    const result = await api("/api/monitor/simulate", { method: "POST", body: JSON.stringify({ scenario }) });
    showToast(result.notice || "Synthetic event created.");
    await refreshDashboard();
    if (state.view === "events") await loadEvents();
  } catch (error) {
    showToast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const button = $("#login-form button");
  const errorNode = $("#login-error");
  errorNode.textContent = "";
  button.disabled = true;
  try {
    const result = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: $("#username").value.trim(), password: $("#password").value }),
    });
    $("#password").value = "";
    showApp(result.user);
  } catch (error) {
    errorNode.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function handleLogout() {
  try { await api("/api/auth/logout", { method: "POST", body: "{}" }); } catch (_) { /* Clear the UI even if the session has expired. */ }
  state.history = [];
  showLogin();
  showToast("You have signed out.");
}

async function initialize() {
  $("#login-form").addEventListener("submit", handleLogin);
  $("#logout-button").addEventListener("click", handleLogout);
  $("#refresh-button").addEventListener("click", refreshDashboard);
  $("#events-refresh-button").addEventListener("click", loadEvents);
  $("#severity-filter").addEventListener("change", loadEvents);
  $("#dashboard-analyze-button").addEventListener("click", analyzeLatestEvents);
  $("#analyst-analyze-button").addEventListener("click", analyzeLatestEvents);
  $("#insight-open-chat").addEventListener("click", () => setView("analyst"));
  $("#lab-open-events").addEventListener("click", () => setView("events"));
  $$("[data-open-events]").forEach((button) => button.addEventListener("click", () => setView("events")));
  $$(".nav-item").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
  $$("[data-simulate]").forEach((button) => button.addEventListener("click", () => simulateScenario(button.dataset.simulate, button)));
  $$("[data-prompt]").forEach((button) => button.addEventListener("click", () => sendChatMessage(button.dataset.prompt)));
  $("#chat-clear-button").addEventListener("click", clearChatHistory);
  $("#refresh-scans-button").addEventListener("click", loadScanReports);
  $("#copy-scan-command").addEventListener("click", () => copyCommand("python3 scripts/scan_local_images.py"));
  $("#copy-baseline-build-command").addEventListener("click", () => copyCommand("python3 scripts/build_baseline_images.py"));
  $("#copy-baseline-scan-command").addEventListener("click", () => copyCommand("python3 scripts/scan_local_images.py --images cloudguard-baseline/auth:original,cloudguard-baseline/ai:original,cloudguard-baseline/logger:original,cloudguard-baseline/gateway:original"));
  $("#copy-assessment-command").addEventListener("click", () => copyCommand("python3 tests/security_regression.py"));
  $("#copy-resilience-command").addEventListener("click", () => copyCommand("python3 tests/resilience_test.py"));
  $("#download-report-button").addEventListener("click", downloadSecurityReport);
  $("#password-change-form").addEventListener("submit", handlePasswordChange);
  $("#chat-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = $("#chat-input");
    const value = input.value;
    input.value = "";
    sendChatMessage(value);
  });

  try {
    const session = await api("/api/auth/me");
    showApp(session.user);
  } catch (_) {
    showLogin();
  }
}

document.addEventListener("DOMContentLoaded", initialize);
