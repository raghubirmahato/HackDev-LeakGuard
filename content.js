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
  // field -> { seq, lastHash, dismissedHash }. `seq` identifies the latest check so
  // that slow or out-of-order responses for an older value never overwrite a newer
  // result; `lastHash` is the hash the banner currently reflects, so re-checking the
  // same value (e.g. on blur right after the debounced check) is skipped;
  // `dismissedHash` is a password the user closed the warning for.
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

  const SVG_NS = "http://www.w3.org/2000/svg";
  const PRIVACY_NOTE = "Checked privately by HackDev LeakGuard: only a 5-character hash prefix left your device.";

  const BANNER_CSS = `
    .hd-banner {
      box-sizing: border-box;
      display: flex;
      align-items: flex-start;
      gap: 7px;
      margin: 6px 0 10px;
      padding: 6px 4px 6px 9px;
      border: 1px solid;
      border-left-width: 3px;
      border-radius: 6px;
      font: 12.5px/1.4 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      text-align: left;
      animation: hd-in 0.14s ease-out;
    }
    .hd-banner[hidden] { display: none; }
    .hd-banner.high { background: #fef2f2; border-color: #fecaca; border-left-color: #dc2626; color: #7f1d1d; }
    .hd-banner.medium { background: #fff7ed; border-color: #fed7aa; border-left-color: #ea580c; color: #7c2d12; }
    .hd-banner.low { background: #fefce8; border-color: #fde68a; border-left-color: #ca8a04; color: #713f12; }
    .hd-icon { flex: none; width: 15px; height: 15px; margin-top: 1px; }
    .high .hd-icon { color: #dc2626; }
    .medium .hd-icon { color: #ea580c; }
    .low .hd-icon { color: #ca8a04; }
    .hd-text { flex: 1; min-width: 0; }
    .hd-title { font-weight: 600; }
    .hd-close {
      flex: none;
      display: grid;
      place-items: center;
      width: 18px;
      height: 18px;
      padding: 0;
      border: 0;
      border-radius: 4px;
      background: transparent;
      color: inherit;
      font: 15px/1 system-ui, sans-serif;
      opacity: 0.55;
      cursor: pointer;
    }
    .hd-close:hover { opacity: 1; background: rgba(0, 0, 0, 0.06); }
    .hd-close:focus-visible { opacity: 1; outline: 2px solid currentColor; outline-offset: 1px; }
    @keyframes hd-in { from { opacity: 0; transform: translateY(-2px); } to { opacity: 1; transform: none; } }
    @media (prefers-reduced-motion: reduce) { .hd-banner { animation: none; } }
  `;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  // Built with DOM APIs rather than innerHTML so it also works on pages that
  // enforce Trusted Types.
  function warningIcon() {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "hd-icon");
    svg.setAttribute("viewBox", "0 0 20 20");
    svg.setAttribute("aria-hidden", "true");
    const triangle = document.createElementNS(SVG_NS, "path");
    triangle.setAttribute("fill", "currentColor");
    triangle.setAttribute("d", "M8.68 2.79a1.5 1.5 0 0 1 2.64 0l6.9 12.47a1.5 1.5 0 0 1-1.32 2.24H3.1a1.5 1.5 0 0 1-1.32-2.24l6.9-12.47Z");
    const mark = document.createElementNS(SVG_NS, "path");
    mark.setAttribute("stroke", "#fff");
    mark.setAttribute("stroke-width", "1.8");
    mark.setAttribute("stroke-linecap", "round");
    mark.setAttribute("d", "M10 7.3v4.2M10 14.4v.1");
    svg.append(triangle, mark);
    return svg;
  }

  function ensureBanner(field) {
    const existing = field.__hackdevBanner;
    if (existing && existing.host.isConnected) return existing;

    const host = document.createElement("div");
    host.setAttribute(BANNER_HOST_ATTR, "");
    // Isolate from page CSS, and be a block so following content (e.g. a
    // "Forgot password?" link) is pushed below the banner instead of overlapping it.
    host.style.cssText = "all: initial; display: block;";
    field.insertAdjacentElement("afterend", host);
    const shadow = host.attachShadow({ mode: "open" });

    const style = el("style");
    style.textContent = BANNER_CSS;
    const root = el("div", "hd-banner");
    root.hidden = true;
    root.setAttribute("role", "alert");
    root.title = PRIVACY_NOTE;
    const title = el("span", "hd-title");
    const detail = el("span", "hd-detail");
    const body = el("div", "hd-text");
    body.append(title, " ", detail);
    const close = el("button", "hd-close", "\u00d7");
    close.type = "button";
    close.title = "Dismiss";
    close.setAttribute("aria-label", "Dismiss warning");
    // Keep focus in the password field so dismissing doesn't interrupt typing.
    close.addEventListener("mousedown", (e) => e.preventDefault());
    close.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const state = fieldState.get(field);
      if (state) state.dismissedHash = state.lastHash;
      hideBanner(field);
    });
    root.append(warningIcon(), body, close);
    shadow.append(style, root);

    const banner = { host, root, title, detail };
    field.__hackdevBanner = banner;
    return banner;
  }

  function hideBanner(field) {
    // Don't inject a banner host into the page just to keep it hidden.
    const banner = field.__hackdevBanner;
    if (!banner || !banner.host.isConnected) return;
    banner.root.hidden = true;
  }

  function showBanner(field, level, title, message) {
    const banner = ensureBanner(field);
    banner.root.className = `hd-banner ${level}`;
    banner.title.textContent = title;
    banner.detail.textContent = message;
    // Line up with the field rather than stretching across wide containers.
    const width = field.getBoundingClientRect().width;
    banner.root.style.maxWidth = `${Math.min(Math.max(width, 240), 420)}px`;
    banner.root.hidden = false;
  }

  function collectTextSignals() {
    const signals = [];
    document.querySelectorAll("h1, h2, h3, button, [type=submit], label").forEach((node) => {
      const text = (node.textContent || node.value || "").trim();
      if (text && text.length < 80) signals.push(text);
    });
    return signals;
  }

  // Only computed when a warning is about to be shown, so it costs nothing on
  // the vast majority of page updates.
  function pageTypeFor(field) {
    const autocomplete = (field.getAttribute("autocomplete") || "").toLowerCase();
    if (autocomplete.includes("current-password")) return "login";
    if (autocomplete.includes("new-password")) return "signup";
    const guess = lib.classifyPageType(location.href, document.title, collectTextSignals());
    return lib.refineClassification(guess, null, document.querySelectorAll('input[type="password"]').length);
  }

  function getState(field) {
    let state = fieldState.get(field);
    if (!state) {
      state = { seq: 0, lastHash: null, dismissedHash: null };
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
      hideBanner(field);
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
    if (level === "safe" || hex === state.dismissedHash) {
      hideBanner(field);
      return;
    }
    showBanner(field, level, lib.riskTitle(level), lib.riskMessage(level, count, pageTypeFor(field)));
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
