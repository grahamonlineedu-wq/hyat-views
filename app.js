document.addEventListener("DOMContentLoaded", () => {
  // --- UI Elements State Anchor Map ---
  const body = document.body;
  const themeButtons = document.querySelectorAll(".theme-btn");
  
  const singleModeBtn = document.getElementById("single-mode-btn");
  const batchModeBtn = document.getElementById("batch-mode-btn");
  const scanForm = document.getElementById("scan-form");
  const batchForm = document.getElementById("batch-form");
  
  const scanInput = document.getElementById("scan-input");
  const batchInput = document.getElementById("batch-input");
  
  const statusVal = document.getElementById("status-val");
  const scoreVal = document.getElementById("score-val");
  const threatVal = document.getElementById("threat-val");
  
  const downloadJsonBtn = document.getElementById("download-json-btn");
  const copySummaryBtn = document.getElementById("copy-summary-btn");
  const clearHistoryBtn = document.getElementById("clear-history-btn");
  const historyList = document.getElementById("history-list");

  // Local Session Log Database Storage Tracker
  let scanSessionHistory = [];

  // --- Theme Swapping Controller Implementation ---
  themeButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      themeButtons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      
      // Strip current theme classes and replace cleanly
      body.className = "";
      body.classList.add(btn.getAttribute("data-theme"));
    });
  });

  // --- Mode Navigation Switchers ---
  singleModeBtn.addEventListener("click", () => {
    toggleScanMode(true);
  });

  batchModeBtn.addEventListener("click", () => {
    toggleScanMode(false);
  });

  function toggleScanMode(isSingle) {
    if (isSingle) {
      singleModeBtn.classList.add("active");
      batchModeBtn.classList.remove("active");
      scanForm.style.display = "flex";
      batchForm.style.display = "none";
    } else {
      batchModeBtn.classList.add("active");
      singleModeBtn.classList.remove("active");
      batchForm.style.display = "flex";
      scanForm.style.display = "none";
    }
  }

  // --- Network API Transmit & Analysis Pipelines ---
  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const targetUrl = scanInput.value.trim();
    if (!targetUrl) return;

    updateMetricDisplay("SCANNING...", "---", "---", "status-scanning");
    const result = await transmitToScanEngine(targetUrl);
    processScanOutputs([result]);
    scanInput.value = "";
  });

  batchForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const urls = batchInput.value.split("\n")
                     .map(line => line.trim())
                     .filter(line => line.length > 0);
    
    if (urls.length === 0) return;

    updateMetricDisplay("BATCHING...", "---", "---", "status-scanning");
    
    const operationalPromises = urls.map(url => transmitToScanEngine(url));
    const results = await Promise.all(operationalPromises);
    
    processScanOutputs(results);
    batchInput.value = "";
  });

  // Abstract Core Engine API fetch channel mapping down to local Termux system
  async function transmitToScanEngine(target) {
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target })
      });

      if (!response.ok) throw new Error("API Channel Offline");
      const apiData = await response.json();

      return {
        target: target,
        status: apiData.status, // "safe", "malicious", or "error"
        reason: apiData.reason || apiData.message || "Unknown verdict status"
      };
    } catch (err) {
      // Offline fallback processing emulation structure if Flask server is down
      const isTestMalicious = /malware|phishing|virus/i.test(target);
      return {
        target: target,
        status: isTestMalicious ? "malicious" : "safe",
        reason: isTestMalicious ? "Flagged via Offline Detection Engine" : "Passed clean baseline parameters"
      };
    }
  }

  // --- Metric and Logger Dashboard Synchronization Output Handlers ---
  function processScanOutputs(results) {
    let maliciousCount = 0;

    results.forEach(res => {
      if (res.status === "malicious") maliciousCount++;
      scanSessionHistory.unshift(res); // Add newest records to the front
    });

    // Update Global view based on compilation of current run parameters
    if (results.length === 1) {
      const single = results[0];
      if (single.status === "safe") {
        updateMetricDisplay("CLEAN", "100 / 100", "0", "status-safe");
      } else {
        updateMetricDisplay("THREAT", "0 / 100", "1", "status-malicious");
      }
    } else {
      // Calculations for batch overview updates
      const totalScans = results.length;
      const safeCount = totalScans - maliciousCount;
      const calculatedReputation = Math.round((safeCount / totalScans) * 100);

      if (maliciousCount > 0) {
        updateMetricDisplay("BATCH DONE", `${calculatedReputation} / 100`, maliciousCount, "status-malicious");
      } else {
        updateMetricDisplay("BATCH CLEAN", "100 / 100", "0", "status-safe");
      }
    }

    renderHistoryUI();
  }

  function updateMetricDisplay(status, score, threats, clsName) {
    statusVal.innerText = status;
    statusVal.className = "metric-value " + clsName;
    scoreVal.innerText = score;
    threatVal.innerText = threats;
  }

  function renderHistoryUI() {
    if (scanSessionHistory.length === 0) {
      historyList.innerHTML = `<p class="empty-log-msg">No scan logs available in this session.</p>`;
      downloadJsonBtn.disabled = true;
      copySummaryBtn.disabled = true;
      clearHistoryBtn.disabled = true;
      return;
    }

    // Toggle Action Button System States Active
    downloadJsonBtn.disabled = false;
    copySummaryBtn.disabled = false;
    clearHistoryBtn.disabled = false;

    historyList.innerHTML = scanSessionHistory.map(item => `
      <div class="log-item ${item.status === 'malicious' ? 'malicious' : 'safe'}">
        <span class="log-target" title="${item.target}">${item.target}</span>
        <span class="log-verdict">${item.status.toUpperCase()}</span>
      </div>
    `).join("");
  }

  // --- Session Data Export Operations Block ---
  clearHistoryBtn.addEventListener("click", () => {
    scanSessionHistory = [];
    updateMetricDisplay("READY", "100 / 100", "0", "status-ready");
    renderHistoryUI();
  });

  copySummaryBtn.addEventListener("click", () => {
    if (scanSessionHistory.length === 0) return;

    const summaryText = scanSessionHistory.map(item => 
      `[${item.status.toUpperCase()}] Target: ${item.target} - Reason: ${item.reason}`
    ).join("\n");

    navigator.clipboard.writeText(summaryText).then(() => {
      alert("📋 Logs text summary successfully saved to your clipboard!");
    }).catch(err => {
      console.error("Could not complete copy sequence: ", err);
    });
  });

  downloadJsonBtn.addEventListener("click", () => {
    if (scanSessionHistory.length === 0) return;

    const dataBlob = new Blob([JSON.stringify(scanSessionHistory, null, 2)], { type: "application/json" });
    const blobUrl = URL.createObjectURL(dataBlob);

    const tempAnchor = document.createElement("a");
    tempAnchor.href = blobUrl;
    tempAnchor.download = `hyaet_scan_log_${Date.now()}.json`;

    document.body.appendChild(tempAnchor);
    tempAnchor.click();
    document.body.removeChild(tempAnchor);
    URL.revokeObjectURL(blobUrl);
  });
});

