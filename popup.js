document.addEventListener("DOMContentLoaded", () => {
  const scanActiveBtn = document.getElementById("scan-active-btn");
  const statusDisplay = document.getElementById("ext-status");
  const scoreDisplay = document.getElementById("ext-score");

  // Automatically load current active tab URL on open
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      document.getElementById("ext-url-input").value = tabs[0].url;
    }
  });

  if (scanActiveBtn) {
    scanActiveBtn.addEventListener("click", () => {
      const targetUrl = document.getElementById("ext-url-input").value.trim();
      if (!targetUrl) return;

      if (statusDisplay) statusDisplay.textContent = "ANALYZING...";

      chrome.runtime.sendMessage(
        { action: "scanUrl", url: targetUrl },
        (response) => {
          if (response && response.success) {
            const data = response.data;
            if (statusDisplay) statusDisplay.textContent = data.status || "CLEAN";
            if (scoreDisplay) scoreDisplay.textContent = (data.reputationScore ?? data.score ?? 100) + " / 100";
          } else {
            if (statusDisplay) statusDisplay.textContent = "API OFFLINE";
            if (scoreDisplay) scoreDisplay.textContent = "N/A";
          }
        }
      );
    });
  }
});

