const API_BASE = "https://hyat-views.onrender.com";
const HISTORY_KEY = "hyaet_scan_history";

let currentResult = null;
let history = [];
let activeCard = "status";

document.addEventListener("DOMContentLoaded", () => {
  history = readHistory();
  setupTheme();
  setupModes();
  setupCards();
  setupActions();
  document.getElementById("scan-form").addEventListener("submit", onSingleScan);
  document.getElementById("batch-form").addEventListener("submit", onBatchScan);
  renderHistory();
  renderIdle();
  probeApi();
  loadRemoteHistory();
});

function setupTheme() {
  const buttons = document.querySelectorAll(".theme-btn");
  const saved = localStorage.getItem("hyaet_theme") || "navy";
  applyTheme(saved);
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      applyTheme(button.dataset.theme);
    });
  });
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme === "navy" ? "" : theme;
  if (theme === "navy") delete document.documentElement.dataset.theme;
  localStorage.setItem("hyaet_theme", theme);
  document.querySelectorAll(".theme-btn").forEach((button) => {
    button.classList.toggle("active", button.dataset.theme === theme);
  });
}

function setupModes() {
  const singleBtn = document.getElementById("single-mode-btn");
  const batchBtn = document.getElementById("batch-mode-btn");
  singleBtn.addEventListener("click", () => setMode("single"));
  batchBtn.addEventListener("click", () => setMode("batch"));
}

function setMode(mode) {
  const single = mode === "single";
  document.getElementById("single-mode-btn").classList.toggle("active", single);
  document.getElementById("batch-mode-btn").classList.toggle("active", !single);
  document.getElementById("scan-form").hidden = !single;
  document.getElementById("batch-form").hidden = single;
}

function setupCards() {
  document.querySelectorAll(".metric-card").forEach((card) => {
    card.addEventListener("click", () => {
      activeCard = card.dataset.card;
      renderDetail();
    });
  });
}

function setupActions() {
  document.getElementById("download-json-btn").addEventListener("click", downloadJson);
  document.getElementById("copy-summary-btn").addEventListener("click", copySummary);
  document.getElementById("clear-history-btn").addEventListener("click", () => {
    history = [];
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
    setNote("Session log cleared.");
  });
}

async function onSingleScan(event) {
  event.preventDefault();
  const input = document.getElementById("scan-input");
  const target = input.value.trim();
  if (!target) return;
  await runTargets([target]);
  input.value = "";
}

async function onBatchScan(event) {
  event.preventDefault();
  const input = document.getElementById("batch-input");
  const targets = input.value
    .split(/[\n,]+/)
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 20);
  if (!targets.length) {
    setNote("Add at least one URL, one per line.");
    return;
  }
  await runTargets(targets);
  input.value = "";
}

async function runTargets(targets) {
  const button = document.querySelector("#" + (targets.length > 1 ? "batch-form" : "scan-form") + " .btn-primary");
  if (button) {
    button.disabled = true;
    button.textContent = "Scanning…";
  }
  setMetrics("SCANNING", "…", "…", "scanning");
  const results = [];
  for (let i = 0; i < targets.length; i += 1) {
    if (targets.length > 1) setMetrics("SCANNING " + (i + 1) + "/" + targets.length, "…", "…", "scanning");
    results.push(await scanOne(targets[i]));
  }
  const worst = results.slice().sort((a, b) => a.reputationScore - b.reputationScore)[0];
  currentResult = worst;
  currentResult.batchSize = results.length;
  currentResult.batchHigh = results.filter((item) => item.status === "HIGH RISK").length;
  setMetrics(worst.status, worst.reputationScore + " / 100", String(worst.threatFlags), toneFor(worst.status));
  results.forEach(remember);
  renderHistory();
  renderDetail();
  const via = worst.source === "api" ? "Hyæt API" : "on-device engine (API unreachable)";
  setNote(results.length > 1 ? "Batch of " + results.length + " finished via " + via + "." : "Scan finished via " + via + ".");
  document.querySelectorAll(".btn-primary").forEach((node) => {
    node.disabled = false;
  });
  document.querySelector("#scan-form .btn-primary").textContent = "Run Deep Scan";
  document.querySelector("#batch-form .btn-primary").textContent = "Run Batch Deep Scan";
}

async function scanOne(raw) {
  const local = window.HyaetEngine.analyzeTarget(raw);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(API_BASE + "/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: local.url || raw }),
      signal: controller.signal
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "API status " + response.status);
    const apiChecks = Array.isArray(data.checks) && data.checks.length ? data.checks : null;
    const apiReasons = Array.isArray(data.reasons) && data.reasons.length ? data.reasons : null;
    return {
      url: data.url || local.url,
      status: data.status || local.status,
      reputationScore: Number.isFinite(data.reputationScore) ? data.reputationScore : local.reputationScore,
      threatFlags: Number.isFinite(data.threatFlags) ? data.threatFlags : local.threatFlags,
      reasons: apiReasons || local.reasons,
      checks: apiChecks || local.checks,
      scannedAt: data.scannedAt || local.scannedAt,
      source: "api",
      detailFrom: apiChecks ? "api" : "local",
      logged: Boolean(data.logged)
    };
  } catch (err) {
    return { ...local, source: "offline", detailFrom: "local", logged: false, error: err.message };
  } finally {
    clearTimeout(timer);
  }
}

function renderIdle() {
  setMetrics("READY", "100 / 100", "0", "ready");
  renderDetail();
}

function setMetrics(status, score, flags, tone) {
  const statusNode = document.getElementById("status-val");
  statusNode.textContent = status;
  statusNode.dataset.tone = tone;
  document.getElementById("score-val").textContent = score;
  document.getElementById("threat-val").textContent = flags;
  document.querySelectorAll(".metric-card").forEach((card) => {
    card.classList.toggle("active", card.dataset.card === activeCard);
  });
}

function toneFor(status) {
  if (status === "HIGH RISK") return "bad";
  if (status === "SUSPICIOUS") return "warn";
  if (status === "CLEAN") return "ok";
  return "ready";
}

function renderDetail() {
  const panel = document.getElementById("detail-panel");
  document.querySelectorAll(".metric-card").forEach((card) => {
    card.classList.toggle("active", card.dataset.card === activeCard);
  });
  if (!currentResult) {
    panel.innerHTML = "<p class=\"detail-empty\">Tap a card after a scan. Status, score, and flags each open the signals behind that number.</p>";
    return;
  }

  const result = currentResult;
  const sourceLine = result.source === "api"
    ? "Score from the live Hyæt API" + (result.logged ? " · saved to Neon" : "")
    : "API did not answer. These numbers are from the on-device engine.";
  const detailNote = result.detailFrom === "local" && result.source === "api"
    ? "The live API has not been updated yet, so it does not send per-check reasons. The list below is the same 9-point engine to deploy with server.js."
    : "";

  let body = "";
  if (activeCard === "status") {
    body = "<p class=\"detail-lead\">" + escapeHtml(result.status) + (result.batchSize > 1 ? " · worst of " + result.batchSize : "") + "</p><p>" + escapeHtml(result.url) + "</p>";
  } else if (activeCard === "score") {
    body = "<p class=\"detail-lead\">" + result.reputationScore + " / 100</p><p>100 minus the weight of every hit check.</p>";
  } else {
    const reasons = result.reasons.length ? result.reasons.map((reason) => "<li>" + escapeHtml(reason) + "</li>").join("") : "<li>No threat flags on this target.</li>";
    body = "<p class=\"detail-lead\">" + result.threatFlags + " flag" + (result.threatFlags === 1 ? "" : "s") + "</p><ul class=\"reason-list\">" + reasons + "</ul>";
  }

  const checks = (result.checks || []).map((check) => {
    return "<li class=\"" + (check.hit ? "hit" : "clear") + "\"><span>" + escapeHtml(check.label) + "</span><b>" + (check.hit ? "HIT" : "CLEAR") + "</b><small>" + escapeHtml(check.detail) + "</small></li>";
  }).join("");

  panel.innerHTML = "<p class=\"detail-source\">" + escapeHtml(sourceLine) + "</p>" + body + (detailNote ? "<p class=\"detail-note\">" + escapeHtml(detailNote) + "</p>" : "") + "<ul class=\"check-list\">" + checks + "</ul>";
}

function remember(result) {
  history.unshift({
    url: result.url,
    status: result.status,
    reputationScore: result.reputationScore,
    threatFlags: result.threatFlags,
    scannedAt: result.scannedAt,
    source: result.source
  });
  history = history.slice(0, 10);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
}

function readHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    return [];
  }
}

function renderHistory() {
  const list = document.getElementById("history-list");
  if (!history.length) {
    list.innerHTML = "<p class=\"empty-log\">No scan logs available in this session.</p>";
    return;
  }
  list.innerHTML = "";
  history.forEach((item) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "log-item " + (item.status === "HIGH RISK" || item.status === "SUSPICIOUS" ? "bad" : "ok");
    const url = document.createElement("span");
    url.className = "log-target";
    url.textContent = item.url;
    const meta = document.createElement("span");
    meta.className = "log-meta";
    meta.textContent = item.status + " · " + item.reputationScore;
    row.append(url, meta);
    row.addEventListener("click", () => {
      document.getElementById("scan-input").value = item.url;
      setNote("Loaded a previous target. Run Deep Scan to check it again.");
      setMode("single");
      currentResult = {
        ...item,
        reasons: [],
        checks: [],
        detailFrom: "local",
        source: item.source || "offline"
      };
      setMetrics(item.status, item.reputationScore + " / 100", String(item.threatFlags ?? 0), toneFor(item.status));
      renderDetail();
    });
    list.appendChild(row);
  });
}

function downloadJson() {
  if (!currentResult && !history.length) {
    setNote("Run a scan first.");
    return;
  }
  const payload = { latest: currentResult, history };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "hyaet-scan-" + Date.now() + ".json";
  link.click();
  URL.revokeObjectURL(link.href);
  setNote("JSON log downloaded.");
}

async function copySummary() {
  if (!currentResult) {
    setNote("Run a scan first.");
    return;
  }
  const lines = [
    "Hyæt Views Scan Summary",
    "Target: " + currentResult.url,
    "Status: " + currentResult.status,
    "Reputation: " + currentResult.reputationScore + " / 100",
    "Threat flags: " + currentResult.threatFlags,
    "Source: " + (currentResult.source === "api" ? "Hyæt API" : "On-device engine"),
    "Signals:",
    ...(currentResult.reasons.length ? currentResult.reasons.map((reason) => "- " + reason) : ["- none"])
  ];
  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    setNote("Summary copied.");
  } catch (err) {
    setNote("Clipboard blocked by the browser.");
  }
}

function setNote(message) {
  document.getElementById("action-note").textContent = message;
}

async function probeApi() {
  const pill = document.getElementById("engine-pill");
  try {
    const response = await fetch(API_BASE + "/", { signal: AbortSignal.timeout(12000) });
    if (!response.ok) throw new Error("offline");
    const data = await response.json();
    pill.textContent = data.version ? "API online · v" + data.version : "API online";
    pill.dataset.state = "online";
  } catch (err) {
    pill.textContent = "API unreachable";
    pill.dataset.state = "offline";
  }
}

async function loadRemoteHistory() {
  if (history.length) return;
  try {
    const response = await fetch(API_BASE + "/history", { signal: AbortSignal.timeout(12000) });
    if (!response.ok) return;
    const data = await response.json();
    if (!Array.isArray(data.logs) || !data.logs.length) return;
    history = data.logs.slice(0, 10).map((row) => ({
      url: row.url,
      status: row.status,
      reputationScore: row.reputationScore,
      threatFlags: row.threatFlags,
      scannedAt: row.scannedAt,
      source: "api"
    }));
    renderHistory();
  } catch (err) {
    /* Older Render builds have no /history route. Local scans still work. */
  }
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "\u0026amp;")
    .replace(/</g, "\u0026lt;")
    .replace(/>/g, "\u0026gt;")
    .replace(/"/g, "\u0026quot;")
    .replace(/'/g, "\u0026#39;");
}
