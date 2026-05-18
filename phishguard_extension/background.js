// PhishGuard — Background Service Worker
// Scans every new URL navigated to and updates the extension badge.

const API_BASE = "http://127.0.0.1:8000";

const BADGE = {
  safe:    { text: "✓",  color: "#00e5a0" },
  medium:  { text: "!",  color: "#ffb547" },
  danger:  { text: "✗",  color: "#ff3e6c" },
  loading: { text: "…",  color: "#7c6af7" },
  error:   { text: "?",  color: "#6b6b8a" },
};

function setBadge(tabId, type) {
  const b = BADGE[type] || BADGE.error;
  chrome.action.setBadgeText({ tabId, text: b.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

async function scanTab(tabId, url) {
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;

  setBadge(tabId, "loading");

  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) throw new Error("API error");
    const data = await res.json();

    if (data.label === "legit" && data.risk_level === "SAFE") {
      setBadge(tabId, "safe");
    } else if (data.risk_level === "MEDIUM") {
      setBadge(tabId, "medium");
    } else if (data.risk_level === "HIGH") {
      setBadge(tabId, "danger");

      // Show a Chrome notification for HIGH risk
      chrome.notifications.create(`phish-${tabId}`, {
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: "⚠ PhishGuard Warning",
        message: `This site may be phishing!\n${url.slice(0, 80)}`,
        priority: 2,
      });
    } else {
      setBadge(tabId, "safe");
    }

    // Cache result for popup to read if needed
    chrome.storage.session.set({ [`result_${tabId}`]: data });

  } catch (_) {
    setBadge(tabId, "error");
  }
}

// Trigger on every completed navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    scanTab(tabId, tab.url);
  }
});