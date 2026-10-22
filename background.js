const API_SCAN = "https://hyat-views.onrender.com/scan";

chrome.runtime.onInstalled.addListener(() => {
  console.log("Hyæt Views threat detector installed.");
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action !== "scanUrl") return;

  fetch(API_SCAN, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: request.url })
  })
    .then(async (response) => {
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        sendResponse({ success: false, error: data.error || "API status " + response.status });
        return;
      }
      sendResponse({ success: true, data });
    })
    .catch((error) => sendResponse({ success: false, error: error.message }));

  return true;
});
