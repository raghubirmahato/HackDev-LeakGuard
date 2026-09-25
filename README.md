# HackDev LeakGuard

A Chrome extension (Manifest V3) that watches login, signup, and reset-password forms as you
type and warns you in-page if the password has appeared in a known data breach — using
[HaveIBeenPwned's Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) via its
k-anonymity range endpoint. **Your password never leaves your device** — only the first 5
characters of its SHA-1 hash are ever sent over the network.

Part of the [HackDev](https://github.com/raghubirrajmahato15/raghubirrajmahato15) toolkit.

## How it works

1. A content script detects password fields on the current page, including fields added later by
   single-page apps.
2. As you type (debounced) or when the field loses focus, the password is hashed locally with
   `crypto.subtle.digest("SHA-1", ...)` — the plaintext password never leaves the tab.
3. Only the first **5 hex characters** of that hash are sent to
   `https://api.pwnedpasswords.com/range/{prefix}` (the background service worker performs the
   fetch). The API returns every known breached hash sharing that prefix (typically hundreds of
   candidates), and the extension checks locally whether the remaining 35 characters match.
4. If a match is found, a small in-page warning banner appears next to the field, showing how many
   times the password has been seen in known breaches. Nothing is ever displayed or transmitted about *which*
   password it was beyond that.

This is the same [k-anonymity model](https://www.troyhunt.com/ive-just-launched-pwned-passwords-v2/)
used by Chrome's and Firefox's own built-in breached-password warnings.

## Features

- Runs on every website out of the box — no per-site setup or domain list needed
- Works across dynamically-rendered / single-page-app forms via a `MutationObserver`
- Color-coded severity (low / medium / high) based on breach frequency, with advice that fits the
  page: on a login form it tells you to change the password, on signup/reset to pick another
- Dismissible warning that stays out of the page's way (it won't come back for the same password)
- Popup showing an on/off toggle and a running count of passwords checked / breaches flagged
  (the toggle takes effect in open tabs immediately)
- Optional exclusion list on the options page for sites you want it to *skip* (bare domains,
  wildcards like `*.example.com`, or pasted URLs are all accepted); leave it empty to check
  everywhere
- Zero telemetry, zero external analytics — the only network call is the HIBP range lookup

## Install (unpacked, for development/review)

1. Clone this repo.
2. Open `chrome://extensions` in Chrome/Edge/Brave.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select this repository's folder.
5. Visit any login/signup/reset-password page and try typing a common password
   (e.g. `password123`) into the password field — a warning banner should appear within about a
   second.

## Project layout

```
manifest.json     Extension manifest (MV3)
background.js     Service worker — performs the HIBP range API fetch, caches responses
content.js        Detects password fields, hashes input, shows the in-page warning banner
pagelogic.js      Pure, DOM-free logic (classification, hashing helpers, risk scoring) — shared
                  by content.js and the test suite so it can be unit-tested outside a browser
popup.html/js      Toolbar popup UI (enable/disable, stats)
options.html/js    Optional list of sites to exclude
tests/             Automated tests (see Testing below)
test-fixtures/     Standalone HTML pages used to manually verify detection in a real browser
```

## Testing

Two layers of automated tests, both using Node's built-in `node:test` runner (no extra
dependencies to install):

```bash
npm test          # offline unit tests for pagelogic.js (classification, hashing, risk scoring)
npm run test:live # adds a live integration test against the real HIBP API
```

`tests/test_pagelogic.js` covers page-type classification, the SHA-1 → prefix/suffix split, risk
bucketing, domain whitelisting and normalization, and debouncing — all pure functions, no network or browser needed.

`tests/test_hibp_integration.js` makes real calls to `api.pwnedpasswords.com` to confirm: a known
breached password (`password`) is correctly found via the k-anonymity range lookup, a
cryptographically random password is (as expected) not found, and only a 5-character prefix is
ever required to query the API.

Beyond the automated suite, the detection + banner behavior was manually verified in a real
browser tab against three fixture pages under `test-fixtures/` (login, signup, reset-password),
confirming: correct page-type classification in each case, the warning banner appearing with the
real breach count for a known-weak password, and the banner correctly clearing for a strong
random password.

## Privacy

- The plaintext password is never sent anywhere, logged, or stored.
- Only a 5-character hash prefix is ever transmitted, to HaveIBeenPwned's public API.
- No analytics, tracking, or third-party scripts.

## Legal

This tool is a defensive aid to help you notice reused/breached passwords on sites you're
signing into or registering with. It is not a guarantee of security and should not replace a
password manager or multi-factor authentication.

## License

MIT
