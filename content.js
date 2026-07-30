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
  const trackedFields = new WeakSet();

  function collectTextSignals() {
    const signals = [];
    document.querySelectorAll("h1, h2, h3, button, [type=submit], label").forEach((el) => {
      const text = (el.textContent || el.value || "").trim();
      if (text && text.length < 80) signals.push(text);
    });
    return signals;
  }

  function pageContext() {
    const passwordFields = Array.from(document.querySelectorAll('input[type="password"]'));
    const firstAutocomplete = passwordFields.length ? passwordFields[0].getAttribute("autocomplete") : null;
    const guess = lib.classifyPageType(location.href, document.title, collectTextSignals());
    const pageType = lib.refineClassification(guess, firstAutocomplete, passwordFields.length);
    return { pageType, passwordFields };
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
    const banner = ensureBanner(field);
    if (level === "safe" || !message) {
      banner.className = "hd-banner hidden";
      banner.textContent = "";
      return;
    }
    banner.className = `hd-banner ${level}`;
    banner.textContent = `⚠ HackDev LeakGuard: ${message}`;
  }

  async function checkPassword(field) {
    const value = field.value;
    if (!value || value.length < 4) {
      showBanner(field, "safe", "");
      return;
    }
    const hex = await sha1Hex(value);
    if (!hex) return; // no WebCrypto available (e.g. insecure context) - fail silent, no warning shown

    let split;
    try {
      split = lib.splitHash(hex);
    } catch {
      return;
    }

    chrome.runtime.sendMessage({ type: "checkPrefix", prefix: split.prefix }, (response) => {
      if (chrome.runtime.lastError || !response || !response.ok) return;
      chrome.runtime.sendMessage({ type: "recordCheck" });
      const count = response.suffixes ? response.suffixes[split.suffix] : undefined;
      const level = lib.riskLevel(count);
      if (level !== "safe") {
        chrome.runtime.sendMessage({ type: "recordBreach" });
      }
      showBanner(field, level, lib.riskMessage(level, count || 0));
    });
  }

  function attachField(field) {
    if (trackedFields.has(field)) return;
    trackedFields.add(field);
    const debounced = lib.debounce(() => checkPassword(field), DEBOUNCE_MS);
    field.addEventListener("input", debounced);
    field.addEventListener("blur", () => checkPassword(field));
  }

  function scanForFields() {
    const { pageType, passwordFields } = pageContext();
    if (pageType === "unknown" && passwordFields.length === 0) return;
    passwordFields.forEach(attachField);
  }

  async function init() {
    const settings = await new Promise((resolve) =>
      chrome.runtime.sendMessage({ type: "getSettings" }, (r) => resolve(r || { enabled: true, whitelist: [] }))
    );
    if (!settings.enabled) return;
    if (lib.isWhitelisted(location.hostname, settings.whitelist)) return;

    scanForFields();
    const observer = new MutationObserver(() => scanForFields());
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
