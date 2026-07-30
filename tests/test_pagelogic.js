// Pure-logic unit tests for pagelogic.js. Run with: node --test tests/
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const lib = require("../pagelogic.js");

test("classifyPageType detects signup from URL", () => {
  assert.equal(lib.classifyPageType("https://example.com/signup", "Example", []), "signup");
  assert.equal(lib.classifyPageType("https://example.com/register", "Create your account", []), "signup");
});

test("classifyPageType detects reset from title", () => {
  assert.equal(lib.classifyPageType("https://example.com/account", "Reset your password", []), "reset");
  assert.equal(lib.classifyPageType("https://example.com/x", "Forgot Password?", []), "reset");
});

test("classifyPageType detects login from text signals", () => {
  assert.equal(lib.classifyPageType("https://example.com/", "Example", ["Sign in to continue"]), "login");
});

test("classifyPageType returns unknown when nothing matches", () => {
  assert.equal(lib.classifyPageType("https://example.com/dashboard", "Dashboard", ["Save changes"]), "unknown");
});

test("refineClassification uses autocomplete=new-password to imply signup", () => {
  assert.equal(lib.refineClassification("unknown", "new-password", 1), "signup");
});

test("refineClassification uses autocomplete=current-password to imply login", () => {
  assert.equal(lib.refineClassification("unknown", "current-password", 1), "login");
});

test("refineClassification does not override an existing confident guess", () => {
  assert.equal(lib.refineClassification("login", "new-password", 1), "login");
});

test("refineClassification falls back to signup for 2+ password fields with no other signal", () => {
  assert.equal(lib.refineClassification("unknown", null, 2), "signup");
  assert.equal(lib.refineClassification("unknown", null, 1), "unknown");
});

test("bufferToHex matches Node's own SHA-1 hex digest for a known string", async () => {
  const text = "password";
  const nodeHex = crypto.createHash("sha1").update(text, "utf8").digest("hex").toUpperCase();

  const data = new TextEncoder().encode(text);
  const { webcrypto } = require("node:crypto");
  const digest = await webcrypto.subtle.digest("SHA-1", data);
  const libHex = lib.bufferToHex(digest);

  assert.equal(libHex, nodeHex);
  assert.equal(libHex.length, 40);
});

test("splitHash divides a 40-char digest into a 5-char prefix and 35-char suffix", () => {
  const hex = "A".repeat(40);
  const { prefix, suffix } = lib.splitHash(hex);
  assert.equal(prefix, "AAAAA");
  assert.equal(suffix.length, 35);
  assert.equal(prefix + suffix, hex);
});

test("splitHash rejects malformed digests", () => {
  assert.throws(() => lib.splitHash("tooshort"));
  assert.throws(() => lib.splitHash(12345));
});

test("riskLevel buckets breach counts correctly", () => {
  assert.equal(lib.riskLevel(0), "safe");
  assert.equal(lib.riskLevel(undefined), "safe");
  assert.equal(lib.riskLevel(5), "low");
  assert.equal(lib.riskLevel(500), "medium");
  assert.equal(lib.riskLevel(50000), "high");
});

test("riskMessage produces a non-empty message for any breached level", () => {
  assert.equal(lib.riskMessage("safe", 0), "");
  assert.match(lib.riskMessage("low", 5), /5/);
  assert.match(lib.riskMessage("medium", 500), /500/);
  assert.match(lib.riskMessage("high", 999999), /do not use/i);
});

test("isWhitelisted matches exact host and subdomains, not unrelated domains", () => {
  const list = ["example.com"];
  assert.equal(lib.isWhitelisted("example.com", list), true);
  assert.equal(lib.isWhitelisted("app.example.com", list), true);
  assert.equal(lib.isWhitelisted("notexample.com", list), false);
  assert.equal(lib.isWhitelisted("example.com.evil.com", list), false);
});

test("debounce collapses rapid calls into a single trailing invocation", async () => {
  let calls = 0;
  const debounced = lib.debounce(() => {
    calls += 1;
  }, 20);

  debounced();
  debounced();
  debounced();

  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.equal(calls, 1);
});
