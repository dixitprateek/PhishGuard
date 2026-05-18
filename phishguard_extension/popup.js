// const API_BASE = "http://127.0.0.1:8000";

// // ── DOM refs ──────────────────────────────────────────────────────────────────
// const statusDot   = document.getElementById("statusDot");
// const currentUrl  = document.getElementById("currentUrl");
// const resultCard  = document.getElementById("resultCard");
// const loadingState = document.getElementById("loadingState");
// const resultState  = document.getElementById("resultState");
// const errorState   = document.getElementById("errorState");
// const verdictIcon  = document.getElementById("verdictIcon");
// const verdictLabel = document.getElementById("verdictLabel");
// const verdictSub   = document.getElementById("verdictSub");
// const confBar      = document.getElementById("confBar");
// const confPct      = document.getElementById("confPct");
// const scanBtn      = document.getElementById("scanBtn");
// const scanCount    = document.getElementById("scanCount");
// const errorMsg     = document.getElementById("errorMsg");


// // ── State helpers ─────────────────────────────────────────────────────────────

// function showLoading() {
//   loadingState.style.display = "flex";
//   resultState.style.display  = "none";
//   errorState.style.display   = "none";
//   resultCard.className = "result-card";
//   scanBtn.disabled = true;
// }

// function showResult(data) {
//   loadingState.style.display = "none";
//   errorState.style.display   = "none";
//   resultState.style.display  = "block";
//   scanBtn.disabled = false;

//   const isSafe   = data.label === "legit";
//   const isMedium = data.risk_level === "MEDIUM";
//   const cls      = isSafe ? "safe" : (isMedium ? "warn" : "danger");

//   resultCard.className = `result-card ${cls}`;

//   verdictIcon.textContent = isSafe ? "✅" : (isMedium ? "⚠️" : "🚨");
//   verdictLabel.textContent = isSafe ? "SAFE" : (isMedium ? "SUSPICIOUS" : "PHISHING");
//   verdictLabel.className = cls;

//   if (data.reason) {
//     verdictSub.textContent = data.reason;
//   } else {
//     const pct = Math.round(data.confidence * 100);
//     verdictSub.textContent = isSafe
//       ? `${100 - pct}% phishing probability`
//       : `${pct}% phishing probability`;
//   }

//   // Confidence bar shows P(phishing)
//   const barPct = Math.round(data.confidence * 100);
//   confBar.style.width = `${barPct}%`;
//   confBar.className = `conf-bar-fill ${cls}`;
//   confPct.textContent = `${barPct}%`;

//   // Save to storage
//   chrome.storage.local.get(["scanHistory", "scanToday"], (res) => {
//     const history = res.scanHistory || [];
//     history.unshift({ ...data, savedAt: new Date().toISOString() });
//     if (history.length > 200) history.pop();

//     const today = new Date().toDateString();
//     const todayData = res.scanToday || { date: today, count: 0 };
//     const count = (todayData.date === today) ? todayData.count + 1 : 1;

//     chrome.storage.local.set({
//       scanHistory: history,
//       scanToday: { date: today, count },
//     });
//     scanCount.textContent = count;
//   });
// }

// function showError(msg) {
//   loadingState.style.display = "none";
//   resultState.style.display  = "none";
//   errorState.style.display   = "block";
//   scanBtn.disabled = false;
//   errorMsg.textContent = msg;
//   resultCard.className = "result-card";
//   statusDot.className = "status-dot offline";
// }


// // ── API calls ─────────────────────────────────────────────────────────────────

// async function checkHealth() {
//   try {
//     const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
//     if (res.ok) {
//       statusDot.className = "status-dot";
//       return true;
//     }
//   } catch (_) {}
//   statusDot.className = "status-dot offline";
//   return false;
// }

// async function scanUrl(url) {
//   showLoading();
//   currentUrl.textContent = url;

//   const alive = await checkHealth();
//   if (!alive) {
//     showError("⚠  API offline — run: python -m uvicorn api:app --port 8000");
//     return;
//   }

//   try {
//     const res = await fetch(`${API_BASE}/scan`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ url }),
//       signal: AbortSignal.timeout(8000),
//     });

//     if (!res.ok) throw new Error(`HTTP ${res.status}`);
//     const data = await res.json();
//     showResult(data);
//   } catch (err) {
//     showError(`Scan failed: ${err.message}`);
//   }
// }


// // ── Init ──────────────────────────────────────────────────────────────────────

// async function init() {
//   // Load today's scan count from storage
//   chrome.storage.local.get(["scanToday"], (res) => {
//     const today = new Date().toDateString();
//     const d = res.scanToday || { date: today, count: 0 };
//     scanCount.textContent = d.date === today ? d.count : 0;
//   });

//   // Get the current tab URL
//   const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
//   const url = tab?.url || "";

//   if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
//     currentUrl.textContent = "(internal page)";
//     showError("Cannot scan browser internal pages.");
//     return;
//   }

//   await scanUrl(url);
// }

// // Rescan button
// scanBtn.addEventListener("click", async () => {
//   const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
//   if (tab?.url) await scanUrl(tab.url);
// });

// init();

const API_BASE = "http://127.0.0.1:8000";

// ── DOM refs ──────────────────────────────────────────────────────────────────
const statusDot   = document.getElementById("statusDot");
const currentUrl  = document.getElementById("currentUrl");
const resultCard  = document.getElementById("resultCard");
const loadingState = document.getElementById("loadingState");
const resultState  = document.getElementById("resultState");
const errorState   = document.getElementById("errorState");
const verdictIcon  = document.getElementById("verdictIcon");
const verdictLabel = document.getElementById("verdictLabel");
const verdictSub   = document.getElementById("verdictSub");
const confBar      = document.getElementById("confBar");
const confPct      = document.getElementById("confPct");
const scanBtn      = document.getElementById("scanBtn");
const scanCount    = document.getElementById("scanCount");
const errorMsg     = document.getElementById("errorMsg");


// ── State helpers ─────────────────────────────────────────────────────────────

function showLoading() {
  loadingState.style.display = "flex";
  resultState.style.display  = "none";
  errorState.style.display   = "none";
  resultCard.className = "result-card";
  scanBtn.disabled = true;
}

function showResult(data) {
  loadingState.style.display = "none";
  errorState.style.display   = "none";
  resultState.style.display  = "block";
  scanBtn.disabled = false;

  const isSafe   = data.label === "legit";
  const isMedium = data.risk_level === "MEDIUM";
  const cls      = isSafe ? "safe" : (isMedium ? "warn" : "danger");

  resultCard.className = `result-card ${cls}`;

  verdictIcon.textContent = isSafe ? "✅" : (isMedium ? "⚠️" : "🚨");
  verdictLabel.textContent = isSafe ? "SAFE" : (isMedium ? "SUSPICIOUS" : "PHISHING");
  verdictLabel.className = cls;

  if (data.reason) {
    verdictSub.textContent = data.reason;
  } else {
    const pct = Math.round(data.confidence * 100);
    verdictSub.textContent = isSafe
      ? `${100 - pct}% phishing probability`
      : `${pct}% phishing probability`;
  }

  // Confidence bar shows P(phishing)
  const barPct = Math.round(data.confidence * 100);
  confBar.style.width = `${barPct}%`;
  confBar.className = `conf-bar-fill ${cls}`;
  confPct.textContent = `${barPct}%`;

  // Save to storage
  chrome.storage.local.get(["scanHistory", "scanToday"], (res) => {
    const history = res.scanHistory || [];
    history.unshift({ ...data, savedAt: new Date().toISOString() });
    if (history.length > 200) history.pop();

    const today = new Date().toDateString();
    const todayData = res.scanToday || { date: today, count: 0 };
    const count = (todayData.date === today) ? todayData.count + 1 : 1;

    chrome.storage.local.set({
      scanHistory: history,
      scanToday: { date: today, count },
    });
    scanCount.textContent = count;
  });
}

function showError(msg) {
  loadingState.style.display = "none";
  resultState.style.display  = "none";
  errorState.style.display   = "block";
  scanBtn.disabled = false;
  errorMsg.textContent = msg;
  resultCard.className = "result-card";
  statusDot.className = "status-dot offline";
}


// ── API calls ─────────────────────────────────────────────────────────────────

async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      statusDot.className = "status-dot";
      return true;
    }
  } catch (_) {}
  statusDot.className = "status-dot offline";
  return false;
}

async function scanUrl(url) {
  showLoading();
  currentUrl.textContent = url;

  const alive = await checkHealth();
  if (!alive) {
    showError("⚠  API offline — run: python -m uvicorn api:app --port 8000");
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    showResult(data);
  } catch (err) {
    showError(`Scan failed: ${err.message}`);
  }
}


// ── Init ──────────────────────────────────────────────────────────────────────

async function init() {
  // Load today's scan count from storage
  chrome.storage.local.get(["scanToday"], (res) => {
    const today = new Date().toDateString();
    const d = res.scanToday || { date: today, count: 0 };
    scanCount.textContent = d.date === today ? d.count : 0;
  });

  // Get the current tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || "";

  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
    currentUrl.textContent = "(internal page)";
    showError("Cannot scan browser internal pages.");
    return;
  }

  await scanUrl(url);
}

// Rescan button
scanBtn.addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) await scanUrl(tab.url);
});

// Dashboard link — chrome extensions can't use target="_blank" anchor tags
document.getElementById("dashLink").addEventListener("click", () => {
  // Try Live Server port first (5500), fallback path for direct file open
  // Update DASHBOARD_URL below to match wherever your index.html is served
  const DASHBOARD_URL = "http://127.0.0.1:5500/frontend/index.html";
  chrome.tabs.create({ url: DASHBOARD_URL });
});

init();