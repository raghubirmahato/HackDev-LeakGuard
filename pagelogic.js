// HackDev LeakGuard - pure, DOM-free logic shared by content.js and the test suite.
// No `document`/`window`/`chrome` references allowed in this file so it can be
// loaded and unit-tested directly under plain Node.js.

(function (root) {
  "use strict";

  const SIGNUP_PATTERNS = [
    /sign[\s-]?up/i,
    /create[\s-]?(an?[\s-]?)?account/i,
    /register/i,
    /get[\s-]?started/i,
    /join[\s-]?now/i,
  ];

  const RESET_PATTERNS = [
    /reset\b.*password/i,
    /password.*\breset/i,
    /forgot\b.*password/i,
    /change[\s-]?password/i,
    /recover[\s-]?(your[\s-]?)?account/i,
    /new[\s-]?password/i,
  ];

  const LOGIN_PATTERNS = [
    /log[\s-]?in/i,
    /sign[\s-]?in/i,
    /welcome[\s-]?back/i,
    /authenticate/i,
  ];

  /**
   * Classify what kind of credential page this looks like, from cheap signals
   * available without touching any live form: the URL, the document title,
   * and (optionally) nearby heading/button text already extracted by the caller.
   *
   * @param {string} url
   * @param {string} title
   * @param {string[]} textSignals - extra strings (headings, button labels, autocomplete hints)
   * @returns {"signup"|"reset"|"login"|"unknown"}
   */
  function classifyPageType(url, title, textSignals) {
    const haystack = [url || "", title || "", ...(textSignals || [])].join(" ");
    if (SIGNUP_PATTERNS.some((re) => re.test(haystack))) return "signup";
    if (RESET_PATTERNS.some((re) => re.test(haystack))) return "reset";
    if (LOGIN_PATTERNS.some((re) => re.test(haystack))) return "login";
    return "unknown";
  }

  /**
   * Given the autocomplete attribute of a password field (if any) and the
   * number of password-type fields on the form, refine a page-type guess.
   * autocomplete="new-password" strongly implies signup/reset;
   * "current-password" strongly implies login.
   *
   * @param {"signup"|"reset"|"login"|"unknown"} guess
   * @param {string|null} autocomplete
   * @param {number} passwordFieldCount
   */
  function refineClassification(guess, autocomplete, passwordFieldCount) {
    const normalized = (autocomplete || "").toLowerCase();
    if (normalized === "new-password") {
      return guess === "unknown" ? "signup" : guess;
    }
    if (normalized === "current-password") {
      return guess === "unknown" ? "login" : guess;
    }
    if (guess === "unknown" && passwordFieldCount >= 2) {
      // Two password fields with no other signal usually means signup/reset
      // (password + confirm-password).
      return "signup";
    }
    return guess;
  }

  /** Convert an ArrayBuffer (e.g. from crypto.subtle.digest) to an uppercase hex string. */
  function bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex.toUpperCase();
  }

  /** Split a 40-char SHA-1 hex digest into the 5-char k-anonymity prefix and 35-char suffix. */
  function splitHash(hexDigest) {
    if (typeof hexDigest !== "string" || hexDigest.length !== 40) {
      throw new Error("Expected a 40-character SHA-1 hex digest");
    }
    return { prefix: hexDigest.slice(0, 5), suffix: hexDigest.slice(5) };
  }

  /** Map a breach occurrence count to a human severity level. */
  function riskLevel(count) {
    if (!count || count <= 0) return "safe";
    if (count < 100) return "low";
    if (count < 10000) return "medium";
    return "high";
  }

  /** Short headline for the warning banner (severity is conveyed by color). */
  function riskTitle(level) {
    return level === "high" || level === "medium" || level === "low" ? "Leaked password" : "";
  }

  function formatTimes(count) {
    return count === 1 ? "once" : `${count.toLocaleString()} times`;
  }

  /**
   * Explanation + advice for the warning banner. On a login page the password is
   * the user's existing one, so the advice is to change it rather than pick another.
   *
   * @param {"high"|"medium"|"low"|"safe"} level
   * @param {number} count
   * @param {"signup"|"reset"|"login"|"unknown"} [pageType]
   */
  function riskMessage(level, count, pageType) {
    if (level !== "high" && level !== "medium" && level !== "low") return "";
    const seen = `Seen ${formatTimes(count)} in data breaches.`;
    if (pageType === "login") return `${seen} Change it after signing in.`;
    switch (level) {
      case "high":
        return `${seen} Don't use it.`;
      case "medium":
        return `${seen} Pick another.`;
      default:
        return `${seen} Consider another.`;
    }
  }

  /** Simple debounce helper. */
  function debounce(fn, waitMs) {
    let timer = null;
    return function debounced(...args) {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), waitMs);
    };
  }

  /**
   * Reduce a user-entered whitelist entry to a bare hostname, so that pasting a
   * full URL ("https://app.example.com:8443/login") or a wildcard ("*.example.com")
   * still matches the page's `location.hostname`.
   */
  function normalizeDomain(entry) {
    let d = String(entry || "").trim().toLowerCase();
    d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // scheme
    d = d.split(/[/?#]/)[0]; // path, query, fragment
    d = d.replace(/^[^@]*@/, ""); // userinfo
    d = d.replace(/:\d*$/, ""); // port
    d = d.replace(/^\*\./, ""); // wildcard (subdomains already match)
    d = d.replace(/\.$/, ""); // trailing dot of a fully-qualified name
    return d;
  }

  /** Check whether a hostname matches any entry in a whitelist (exact or subdomain match). */
  function isWhitelisted(hostname, whitelist) {
    if (!hostname || !Array.isArray(whitelist)) return false;
    const host = hostname.toLowerCase().replace(/\.$/, "");
    return whitelist.some((entry) => {
      const w = normalizeDomain(entry);
      if (!w) return false;
      return host === w || host.endsWith(`.${w}`);
    });
  }

  const api = {
    classifyPageType,
    refineClassification,
    bufferToHex,
    splitHash,
    riskLevel,
    riskTitle,
    riskMessage,
    debounce,
    normalizeDomain,
    isWhitelisted,
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.HackDevLeakGuard = api;
  }
})(typeof self !== "undefined" ? self : this);
