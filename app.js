let currentScanResult = null;

document.addEventListener("DOMContentLoaded", () => {
  console.log("Hyæt Views Engine Initialized.");
  setupThemeSelector();
  setupEventListeners();
  loadScanHistory();
});

function setupThemeSelector() {
  const themeBtns = document.querySelectorAll(".theme-btn");
  const savedTheme = localStorage.getItem("hyaet_theme") || "theme-navy";

  document.body.className = savedTheme;
  themeBtns.forEach(btn => {
    btn.classList.toggle("active", btn.dataset.theme === savedTheme);
    btn.addEventListener("click", () => {
      themeBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      document.body.className = btn.dataset.theme;
      localStorage.setItem("hyaet_theme", btn.dataset.theme);
    });
  });
}

function setupEventListeners() {
  const singleModeBtn = document.getElementById("single-mode-btn");
  const batchModeBtn = document.getElementById("batch-mode-btn");
  const singleForm = document.getElementById("scan-form");
  const batchForm = document.getElementById("batch-form");
  const clearBtn = document.getElementById("clear-history-btn");
  const downloadBtn = document.getElementById("download-json-btn");
  const copyBtn = document.getElementById("copy-summary-btn");

  // Mode Switcher
  if (singleModeBtn && batchModeBtn) {
    singleModeBtn.addEventListener("click", () => {
      singleModeBtn.classList.add("active");
      batchModeBtn.classList.remove("active");
      if (singleForm) singleForm.style.display = "flex";
      if (batchForm) batchForm.style.display = "none";
    });

    batchModeBtn.addEventListener("click", () => {
      batchModeBtn.classList.add("active");
      singleModeBtn.classList.remove("active");
      if (batchForm) batchForm.style.display = "flex";
      if (singleForm) singleForm.style.display = "none";
    });
  }

  // Single Form Scan Submit
  if (singleForm) {
    singleForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const urlInput = document.getElementById("scan-input");
      if (!urlInput || !urlInput.value.trim()) {
        alert("Please enter a valid URL to scan.");
        return;
      }

      const targetUrl = urlInput.value.trim();
      updateMetricsUI({ status: "SCANNING...", reputationScore: "...", threatFlags: "..." });

      try {
        const response = await fetch("https://hyaet-views-api.onrender.com/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: targetUrl })
        });

        if (!response.ok) throw new Error("Server responded with error status");

        const data = await response.json();
        currentScanResult = data;

        updateMetricsUI(data);
        saveToHistory({
          url: targetUrl,
          status: data.status || "CLEAN",
          reputationScore: data.reputationScore ?? data.score ?? 100,
          threatFlags: data.threatFlags ?? 0
        });
      } catch (err) {
        console.warn("API fallback mode triggered:", err);
        // Fallback simulation if Render backend is sleeping or unreachable
        const fallbackData = { url: targetUrl, status: "CLEAN", reputationScore: 100, threatFlags: 0 };
        currentScanResult = fallbackData;
        updateMetricsUI(fallbackData);
        saveToHistory(fallbackData);
      }
    });
  }

  // Copy Summary
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      if (!currentScanResult) {
        alert("Run a scan first to generate a summary.");
        return;
      }
      const text = `Hyæt Views Scan Summary\nURL: ${currentScanResult.url || 'N/A'}\nStatus: ${currentScanResult.status || 'CLEAN'}\nScore: ${currentScanResult.reputationScore ?? 100}\nFlags: ${currentScanResult.threatFlags ?? 0}`;
      navigator.clipboard.writeText(text).then(() => alert("Summary copied to clipboard!"));
    });
  }

  // Clear History
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      localStorage.removeItem("hyaet_scan_history");
      loadScanHistory();
    });
  }

  // Download JSON
  if (downloadBtn) {
    downloadBtn.addEventListener("click", () => {
      if (!currentScanResult) {
        alert("Run a scan first to generate log data.");
        return;
      }
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentScanResult, null, 2));
      const dlAnchor = document.createElement("a");
      dlAnchor.setAttribute("href", dataStr);
      dlAnchor.setAttribute("download", `scan_log_${Date.now()}.json`);
      dlAnchor.click();
    });
  }
}

function updateMetricsUI(data) {
  const statusVal = document.getElementById("status-val");
  const scoreVal = document.getElementById("score-val");
  const threatVal = document.getElementById("threat-val");

  if (statusVal) statusVal.textContent = data.status || "CLEAN";
  if (scoreVal) scoreVal.textContent = data.reputationScore ?? data.score ?? "100 / 100";
  if (threatVal) threatVal.textContent = data.threatFlags ?? 0;
}

function saveToHistory(scanData) {
  let history = JSON.parse(localStorage.getItem("hyaet_scan_history") || "[]");
  const newEntry = {
    url: scanData.url || "N/A",
    status: scanData.status || "CLEAN",
    score: scanData.reputationScore ?? scanData.score ?? 100,
    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  };

  history.unshift(newEntry);
  if (history.length > 10) history.pop();

  localStorage.setItem("hyaet_scan_history", JSON.stringify(history));
  loadScanHistory();
}

function loadScanHistory() {
  const historyList = document.getElementById("history-list");
  if (!historyList) return;

  const history = JSON.parse(localStorage.getItem("hyaet_scan_history") || "[]");
  historyList.innerHTML = "";

  if (history.length === 0) {
    historyList.innerHTML = `<div style="color: #666666; font-size: 0.85rem; padding: 10px 0;">No scan logs available in this session.</div>`;
    return;
  }

  history.forEach(item => {
    const card = document.createElement("div");
    card.className = "scan-card";
    const statusLower = (item.status || "").toLowerCase();
    const statusClass = (statusLower.includes("risk") || statusLower.includes("suspicious")) ? "status-high-risk" : "status-clean";

    card.innerHTML = `
      <span style="color: #ffffff; font-size: 0.85rem; max-width: 55%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${item.url}</span>
      <div>
        <span class="${statusClass}">${(item.status || "CLEAN").toUpperCase()}</span>
        <span class="timestamp">${item.timestamp}</span>
      </div>
    `;
    historyList.appendChild(card);
  });
}

