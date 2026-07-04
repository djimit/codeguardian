import { test } from "node:test";
import { strict as assert } from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { scanBestPractices } from "../src/core/best-practices.js";
import { scanHighEntropy } from "../src/core/entropy.js";

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "cg-test-"));
}

test("scanBestPractices detects SSL verification disabled", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, "app.js"), `
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    const config = { rejectUnauthorized: false };
  `);

  const result = scanBestPractices({ repoRoot: tmpDir });
  assert.ok(result.findings.length >= 2, "Should detect both SSL bypasses");
  const tls = result.findings.find((f) => f.title.includes("SSL"));
  assert.ok(tls, "Should find SSL verification finding");
  assert.equal(tls.severity, "high");
});

test("scanBestPractices detects debug mode", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, ".env"), `DEBUG=true`);

  const result = scanBestPractices({ repoRoot: tmpDir });
  const debug = result.findings.find((f) => f.title.includes("Debug"));
  assert.ok(debug, "Should detect debug mode");
});

test("scanBestPractices detects insecure env fallback", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, "config.js"), `
    const dbHost = process.env.DB_HOST || 'localhost';
  `);

  const result = scanBestPractices({ repoRoot: tmpDir });
  const fallback = result.findings.find((f) => f.title.includes("Insecure Environment"));
  assert.ok(fallback, "Should detect insecure fallback");
});

test("scanBestPractices detects eval usage", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, "handler.js"), `
    const result = eval(userInput);
  `);

  const result = scanBestPractices({ repoRoot: tmpDir });
  const evalFinding = result.findings.find((f) => f.title.includes("eval"));
  assert.ok(evalFinding, "Should detect eval usage");
  assert.equal(evalFinding.severity, "high");
});

test("scanBestPractices detects weak crypto", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, "hash.js"), `
    const hash = crypto.createHash('md5');
  `);

  const result = scanBestPractices({ repoRoot: tmpDir });
  const crypto = result.findings.find((f) => f.title.includes("Cryptographic"));
  assert.ok(crypto, "Should detect weak crypto");
});

test("scanHighEntropy detects high entropy strings", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, "config.js"), "const apiKey = \"xK9mN2pQ8rT4vW6yZ1aB3cD5eF7gH9iJ0kLmNoPqRsTuVwXyZ\";\n");

  const result = scanHighEntropy({ repoRoot: tmpDir });
  assert.ok(result.findings.length > 0, "Should detect high entropy string");
});

test("scanHighEntropy skips test files", () => {
  const tmpDir = makeTmpDir();
  fs.mkdirSync(path.join(tmpDir, "tests"));
  fs.writeFileSync(path.join(tmpDir, "tests", "config.test.js"), "const apiKey = \"xK9mN2pQ8rT4vW6yZ1aB3cD5eF7gH9iJ0kL\";\n");

  const result = scanHighEntropy({ repoRoot: tmpDir });
  assert.equal(result.findings.length, 0, "Should skip test files");
});

test("scanHighEntropy skips hashes and UUIDs", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, "config.js"), `
    const sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const uuid = "550e8400-e29b-41d4-a716-446655440000";
  `);

  const result = scanHighEntropy({ repoRoot: tmpDir });
  assert.equal(result.findings.length, 0, "Should skip hashes and UUIDs");
});
