import { test } from "node:test";
import { strict as assert } from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { loadConfig } from "../src/core/config.js";
import { applySuppressions } from "../src/core/suppressions.js";

test("loadConfig returns defaults when no config file", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  const config = loadConfig(tmpDir);
  assert.equal(config.fail_on, "critical");
  assert.deepEqual(config.suppressions, []);
  assert.equal(config.history.retention_days, 90);
});

test("loadConfig parses YAML config file", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  fs.writeFileSync(path.join(tmpDir, ".codeguardian.yml"), [
    "fail_on: high",
    "suppressions:",
    "  - rule_id: pii-bsn",
    "    path: \"**/tests/**\"",
    "    reason: Test data",
    "    expires: 2026-12-31",
    "history:",
    "  enabled: true",
    "  retention_days: 30"
  ].join("\n"));

  const config = loadConfig(tmpDir);
  assert.equal(config.fail_on, "high");
  assert.equal(config.suppressions.length, 1);
  assert.equal(config.suppressions[0].rule_id, "pii-bsn");
  assert.equal(config.history.retention_days, 30);
});

test("applySuppressions filters matching findings", () => {
  const findings = [
    { severity: "critical", category: "privacy-pii", files: ["src/tests/fixtures/data.js"], source: { ruleId: "pii-bsn" } },
    { severity: "high", category: "privacy-pii", files: ["src/app.js"], source: { ruleId: "pii-bsn" } }
  ];
  const suppressions = [
    { rule_id: "pii-bsn", path: "**/tests/**", reason: "Test data" }
  ];

  const { visible, suppressed } = applySuppressions(findings, suppressions);
  assert.equal(visible.length, 1);
  assert.equal(suppressed.length, 1);
  assert.equal(visible[0].files[0], "src/app.js");
});

test("applySuppressions respects expiry", () => {
  const findings = [
    { severity: "critical", category: "privacy-pii", files: ["src/test.js"], source: { ruleId: "pii-bsn" } }
  ];
  const suppressions = [
    { rule_id: "pii-bsn", path: "**/*", expires: "2020-01-01" }
  ];

  const { visible, suppressed } = applySuppressions(findings, suppressions);
  assert.equal(visible.length, 1);
  assert.equal(suppressed.length, 0);
});

test("applySuppressions wildcard rule_id matches all", () => {
  const findings = [
    { severity: "low", category: "privacy-pii", files: ["docs/example.js"], source: { ruleId: "pii-email" } }
  ];
  const suppressions = [
    { rule_id: "*", path: "docs/**" }
  ];

  const { visible, suppressed } = applySuppressions(findings, suppressions);
  assert.equal(suppressed.length, 1);
});
