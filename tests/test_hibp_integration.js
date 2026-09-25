// Live integration test against the real HaveIBeenPwned Pwned Passwords API.
// Requires network access. Run with: node --test tests/test_hibp_integration.js
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const lib = require("../pagelogic.js");

async function sha1HexNode(text) {
  return crypto.createHash("sha1").update(text, "utf8").digest("hex").toUpperCase();
}

async function fetchRange(prefix) {
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true" },
  });
  if (!res.ok) throw new Error(`HIBP returned HTTP ${res.status}`);
  const text = await res.text();
  const suffixes = new Map();
  for (const line of text.split("\n")) {
    const [suffix, countStr] = line.trim().split(":");
    if (suffix && countStr) suffixes.set(suffix.toUpperCase(), parseInt(countStr, 10));
  }
  return suffixes;
}

test(
  "a known breached password ('password') is found via the k-anonymity range API",
  { timeout: 15000 },
  async () => {
    const hex = await sha1HexNode("password");
    const { prefix, suffix } = lib.splitHash(hex);
    const suffixes = await fetchRange(prefix);
    assert.ok(suffixes.has(suffix), "expected 'password' hash suffix to be present in the HIBP range response");
    const count = suffixes.get(suffix);
    assert.ok(count > 1000000, `expected a very high breach count for 'password', got ${count}`);
    assert.equal(lib.riskLevel(count), "high");
  }
);

test(
  "a long random password is NOT found in the range API (extremely low false-positive risk)",
  { timeout: 15000 },
  async () => {
    const random = crypto.randomBytes(32).toString("hex"); // 64 random hex chars, astronomically unlikely to be breached
    const hex = await sha1HexNode(random);
    const { prefix, suffix } = lib.splitHash(hex);
    const suffixes = await fetchRange(prefix);
    assert.ok(!suffixes.has(suffix), "did not expect a random 32-byte password to appear in a breach corpus");
    assert.equal(lib.riskLevel(undefined), "safe");
  }
);

test("only the 5-character prefix is ever needed to query the API (k-anonymity holds)", { timeout: 15000 }, async () => {
  const hex = await sha1HexNode("password");
  const { prefix } = lib.splitHash(hex);
  assert.equal(prefix.length, 5);
  // Confirm the range endpoint accepts just the prefix and returns many candidate suffixes,
  // proving the full password/hash never needs to be transmitted.
  const suffixes = await fetchRange(prefix);
  assert.ok(suffixes.size > 100, "expected the k-anonymity range response to contain many candidate hashes");
});
