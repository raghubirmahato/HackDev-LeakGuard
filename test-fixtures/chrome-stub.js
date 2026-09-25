// Manual browser test harness stub: simulates the `chrome.runtime`/`chrome.storage`
// APIs so content.js can run in a plain tab (outside a real installed extension)
// while still making a REAL network call to the HIBP API, exactly like background.js does.
window.chrome = {
  runtime: {
    sendMessage(message, callback) {
      (async () => {
        if (message.type === "getSettings") {
          callback({ enabled: true, whitelist: [] });
          return;
        }
        if (message.type === "checkPrefix") {
          try {
            const res = await fetch(`https://api.pwnedpasswords.com/range/${message.prefix}`, {
              headers: { "Add-Padding": "true" },
            });
            if (!res.ok) {
              callback({ ok: false, error: `HIBP API returned HTTP ${res.status}` });
              return;
            }
            const text = await res.text();
            const suffixes = {};
            for (const line of text.split("\n")) {
              const [suffix, countStr] = line.trim().split(":");
              if (suffix && countStr) suffixes[suffix.toUpperCase()] = parseInt(countStr, 10);
            }
            callback({ ok: true, suffixes });
          } catch (err) {
            callback({ ok: false, error: String(err) });
          }
          return;
        }
        if (message.type === "recordCheck" || message.type === "recordBreach") {
          window.__hackdevTestCounters = window.__hackdevTestCounters || { checked: 0, breached: 0 };
          if (message.type === "recordCheck") window.__hackdevTestCounters.checked++;
          if (message.type === "recordBreach") window.__hackdevTestCounters.breached++;
          callback({ ok: true });
          return;
        }
        callback(null);
      })();
    },
    lastError: null,
  },
  storage: {
    sync: { get: async () => ({}), set: async () => {} },
    local: { get: async () => ({}), set: async () => {} },
    onChanged: { addListener() {} },
  },
};
