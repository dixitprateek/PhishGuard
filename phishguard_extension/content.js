// PhishGuard — Content Script
// Injects a warning banner at the top of HIGH-risk pages.
// Runs after the page loads; reads the cached scan result from background.js.

(async () => {
  const tabId = await new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_TAB_ID" }, resolve);
  }).catch(() => null);

  if (!tabId) return;

  const result = await chrome.storage.session.get(`result_${tabId}`)
    .then((r) => r[`result_${tabId}`])
    .catch(() => null);

  if (!result || result.risk_level !== "HIGH") return;

  // Don't inject twice
  if (document.getElementById("phishguard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.innerHTML = `
    <div style="
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      background: #ff3e6c; color: #fff;
      font-family: 'Segoe UI', sans-serif; font-size: 13px; font-weight: 600;
      padding: 10px 16px;
      display: flex; align-items: center; gap: 12px;
      box-shadow: 0 2px 12px rgba(255,62,108,0.5);
    ">
      <span style="font-size:18px;">🚨</span>
      <span>
        <strong>PhishGuard Warning:</strong>
        This page has been flagged as a phishing site
        (${Math.round(result.confidence * 100)}% confidence).
        Proceed with extreme caution.
      </span>
      <button onclick="this.parentElement.parentElement.remove()" style="
        margin-left: auto; background: rgba(255,255,255,0.2);
        border: none; color: #fff; padding: 4px 10px;
        border-radius: 4px; cursor: pointer; font-size: 12px;
      ">Dismiss</button>
    </div>
  `;
  document.body.prepend(banner);
})();

// Handle GET_TAB_ID message from content script itself
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "GET_TAB_ID") reply(sender.tab?.id);
});