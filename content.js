// HackDev LeakGuard - content script
// Detects password fields on login / signup / reset-password pages and warns
// the user if the password they typed has appeared in a known data breach.
// The password itself is never sent anywhere: only a SHA-1 hash is computed
// locally, and only the first 5 hex characters of that hash ever leave the
// device (HaveIBeenPwned's k-anonymity range API).

(function () {
  "use strict";

  const lib = self.HackDevLeakGuard;
  if (!lib) return; // pagelogic.js failed to load; nothing we can safely do

  const DEBOUNCE_MS = 600;
  const SCAN_DELAY_MS = 250;
  const MIN_PASSWORD_LENGTH = 4;
  const BANNER_HOST_ATTR = "data-hackdev-leakguard";

  const trackedFields = new WeakSet();
  // field -> { seq, lastHash }. `seq` identifies the latest check so that slow or
  // out-of-order responses for an older value never overwrite a newer result;
  // `lastHash` is the hash the banner currently reflects, so re-checking the same
  // value (e.g. on blur right after the debounced check) is skipped.
  let fieldState = new WeakMap();

  let settings = { enabled: true, whitelist: [] };
  let active = false;
  let observer = null;
  let scanScheduled = false;

  // chrome.runtime.sendMessage throws synchronously once the extension has been
  // reloaded or updated underneath an open tab, and reports "no receiver" style
  // failures through lastError. Both are treated as "no response".
  function send(message) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) {
            resolve(null);
            return;
          }
          resolve(response);
        });
      } catch {
        resolve(null);
      }
    });
  }

  async function sha1Hex(text) {
    if (!self.crypto || !self.crypto.subtle) return null;
    const data = new TextEncoder().encode(text);
    const digest = await self.crypto.subtle.digest("SHA-1", data);
    return lib.bufferToHex(digest);
  }

  function ensureBanner(field) {
    let host = field.__hackdevBannerHost;
    if (host && host.isConnected) return host.shadowRoot.querySelector(".hd-banner");
    host = document.createElement("div");
    host.setAttribute(BANNER_HOST_ATTR, "");
    host.style.all = "initial";
    field.insertAdjacentElement("afterend", host);
    const shadow = host.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = `
      .hd-banner {
        font: 13px/1.4 -apple-system, Segoe UI, Roboto, sans-serif;
        margin-top: 6px;
        padding: 8px 10px;
        border-radius: 6px;
        display: flex;
        align-items: flex-start;
        gap: 6px;
        max-width: 420px;
      }
      .hd-banner.high { background: #fdecea; color: #7a271a; border: 1px solid #f5b5ac; }
      .hd-banner.medium { background: #fff4e5; color: #7a4a00; border: 1px solid #f7c98b; }
      .hd-banner.low { background: #fff9e6; color: #6b5900; border: 1px solid #f0e29a; }
      .hd-banner.hidden { display: none; }
    `;
    const banner = document.createElement("div");
    banner.className = "hd-banner hidden";
    shadow.appendChild(style);
    shadow.appendChild(banner);
    field.__hackdevBannerHost = host;
    return banner;
  }

  function showBanner(field, level, message) {
    if (level === "safe" || !message) {
      // Don't inject a banner host into the page just to keep it hidden.
      const host = field.__hackdevBannerHost;
      if (!host || !host.isConnected) return;
      const banner = host.shadowRoot.querySelector(".hd-banner");
      banner.className = "hd-banner hidden";
      banner.textContent = "";
      return;
    }
    const banner = ensureBanner(field);
    banner.className = `hd-banner ${level}`;
    banner.textContent = `⚠ HackDev LeakGuard: ${message}`;
  }

  function getState(field) {
    let state = fieldState.get(field);
    if (!state) {
      state = { seq: 0, lastHash: null };
      fieldState.set(field, state);
    }
    return state;
  }

  async function checkPassword(field) {
    if (!active) return;
    const state = getState(field);
    const seq = ++state.seq;
    const isCurrent = () => active && fieldState.get(field) === state && state.seq === seq;

    const value = field.value;
    if (!value || value.length < MIN_PASSWORD_LENGTH) {
      state.lastHash = null;
      showBanner(field, "safe", "");
      return;
    }
    const hex = await sha1Hex(value);
    if (!hex) return; // no WebCrypto available (e.g. insecure context) - fail silent, no warning shown
    if (!isCurrent() || hex === state.lastHash) return;

    let split;
    try {
      split = lib.splitHash(hex);
    } catch {
      return;
    }

    const response = await send({ type: "checkPrefix", prefix: split.prefix });
    if (!isCurrent()) return; // superseded by a newer value, or LeakGuard was switched off
    if (!response || !response.ok) return;

    state.lastHash = hex;
    send({ type: "recordCheck" });
    const count = response.suffixes ? response.suffixes[split.suffix] : undefined;
    const level = lib.riskLevel(count);
    if (level !== "safe") {
      send({ type: "recordBreach" });
    }
    showBanner(field, level, lib.riskMessage(level, count || 0));
  }

  function attachField(field) {
    if (trackedFields.has(field)) return;
    trackedFields.add(field);
    const debounced = lib.debounce(() => checkPassword(field), DEBOUNCE_MS);
    field.addEventListener("input", debounced);
    field.addEventListener("blur", () => checkPassword(field));
  }

  function scanForFields() {
    scanScheduled = false;
    if (!active) return;
    document.querySelectorAll('input[type="password"]').forEach(attachField);
  }

  // Mutations arrive in bursts on dynamic pages (and our own banners cause some),
  // so coalesce them into at most one scan per SCAN_DELAY_MS.
  function scheduleScan() {
    if (scanScheduled) return;
    scanScheduled = true;
    setTimeout(scanForFields, SCAN_DELAY_MS);
  }

  function start() {
    if (active) return;
    active = true;
    scanForFields();
    observer = new MutationObserver(scheduleScan);
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  function stop() {
    if (!active) return;
    active = false;
    if (observer) observer.disconnect();
    observer = null;
    fieldState = new WeakMap(); // drops in-flight checks and remembered results
    document.querySelectorAll(`[${BANNER_HOST_ATTR}]`).forEach((host) => host.remove());
  }

  function applySettings() {
    const shouldRun = settings.enabled !== false && !lib.isWhitelisted(location.hostname, settings.whitelist);
    if (shouldRun) start();
    else stop();
  }

  async function init() {
    const response = await send({ type: "getSettings" });
    if (response) settings = response;
    applySettings();

    // Pick up toggles from the popup / options page without requiring a reload.
    if (chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== "sync") return;
        if (changes.enabled) settings = { ...settings, enabled: changes.enabled.newValue !== false };
        if (changes.whitelist) settings = { ...settings, whitelist: changes.whitelist.newValue || [] };
        if (changes.enabled || changes.whitelist) applySettings();
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
