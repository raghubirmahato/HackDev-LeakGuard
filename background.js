// HackDev LeakGuard - background service worker
// Only ever transmits a 5-character SHA-1 prefix to the HIBP API (k-anonymity model).
// The full password and full hash never leave the device.

const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";
const FETCH_TIMEOUT_MS = 6000;

// In-memory cache of prefix -> { suffixes: Map<suffix, count>, fetchedAt: number }
const prefixCache = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function parseRangeResponse(text) {
  const suffixes = new Map();
  const lines = text.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [suffix, countStr] = trimmed.split(":");
    if (!suffix || !countStr) continue;
    const count = parseInt(countStr, 10);
    if (Number.isFinite(count)) {
      suffixes.set(suffix.toUpperCase(), count);
    }
  }
  return suffixes;
}

async function checkPrefix(prefix) {
  const normalizedPrefix = prefix.toUpperCase();
  const cached = prefixCache.get(normalizedPrefix);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return { ok: true, suffixes: Object.fromEntries(cached.suffixes) };
  }

  try {
    const response = await fetchWithTimeout(
      `${HIBP_RANGE_URL}${normalizedPrefix}`,
      { headers: { "Add-Padding": "true" } },
      FETCH_TIMEOUT_MS
    );
    if (!response.ok) {
      return { ok: false, error: `HIBP API returned HTTP ${response.status}` };
    }
    const text = await response.text();
    const suffixes = parseRangeResponse(text);
    prefixCache.set(normalizedPrefix, { suffixes, fetchedAt: Date.now() });
    return { ok: true, suffixes: Object.fromEntries(suffixes) };
  } catch (err) {
    const message = err && err.name === "AbortError" ? "HIBP request timed out" : String(err && err.message ? err.message : err);
    return { ok: false, error: message };
  }
}

async function bumpStat(key, delta) {
  const stored = await chrome.storage.local.get(["stats"]);
  const stats = stored.stats || { checked: 0, breached: 0 };
  stats[key] = (stats[key] || 0) + delta;
  await chrome.storage.local.set({ stats });
  return stats;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || typeof message !== "object") return false;

  if (message.type === "checkPrefix") {
    checkPrefix(message.prefix).then(sendResponse);
    return true; // keep the message channel open for the async response
  }

  if (message.type === "recordCheck") {
    bumpStat("checked", 1).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message.type === "recordBreach") {
    bumpStat("breached", 1).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message.type === "getSettings") {
    chrome.storage.sync
      .get(["enabled", "whitelist"])
      .then((stored) =>
        sendResponse({
          enabled: stored.enabled !== false,
          whitelist: stored.whitelist || [],
        })
      );
    return true;
  }

  return false;
});

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    await chrome.storage.sync.set({ enabled: true, whitelist: [] });
    await chrome.storage.local.set({ stats: { checked: 0, breached: 0 } });
  }
});
