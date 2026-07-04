import { test } from "node:test";
import { strict as assert } from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { generateFix, applyFix, generateFixReport } from "../src/core/autofix.js";

test("generateFix returns null for non-dependency findings", () => {
  const finding = { category: "privacy-pii", files: ["src/app.js"] };
  assert.equal(generateFix(finding), null);
});

test("generateFix returns null when no fix version", () => {
  const finding = {
    category: "dependency-cve",
    files: ["package.json"],
    proposedFix: "Remove this package",
    title: "CVE-2024-1234: Test"
  };
  assert.equal(generateFix(finding, "."), null);
});

test("generateFix creates patch for package.json", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
    dependencies: { "ws": "5.2.3" }
  }, null, 2));

  const finding = {
    id: "abc123",
    category: "dependency-cve",
    files: ["package.json"],
    proposedFix: "Update ws to version 5.2.5",
    title: "CVE-2024-1234: Test vulnerability"
  };

  const fix = generateFix(finding, tmpDir);
  assert.ok(fix, "Should generate fix");
  assert.equal(fix.packageName, "ws");
  assert.equal(fix.from, "5.2.3");
  assert.equal(fix.to, "5.2.5");
  assert.equal(fix.safe, true);
  assert.equal(fix.patches.length, 1);
});

test("generateFix marks major version bump as unsafe", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
    dependencies: { "react": "17.0.0" }
  }, null, 2));

  const finding = {
    id: "def456",
    category: "dependency-cve",
    files: ["package.json"],
    proposedFix: "Update react to version 18.0.0",
    title: "CVE-2024-9999: Test"
  };

  const fix = generateFix(finding, tmpDir);
  assert.equal(fix.safe, false);
});

test("applyFix modifies file content", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
    dependencies: { "ws": "5.2.3" }
  }, null, 2));

  const fix = {
    packageName: "ws",
    from: "5.2.3",
    to: "5.2.5",
    patches: [{ old: '"ws": "5.2.3"', new: '"ws": "5.2.5"', file: "package.json" }]
  };

  const result = applyFix(fix, tmpDir);
  assert.equal(result, true);

  const updated = JSON.parse(fs.readFileSync(path.join(tmpDir, "package.json"), "utf8"));
  assert.equal(updated.dependencies.ws, "5.2.5");
});

test("generateFixReport shows fix count", () => {
  const fixes = [
    { packageName: "ws", from: "5.2.3", to: "5.2.5", file: "package.json", safe: true },
    { packageName: "react", from: "17.0.0", to: "18.0.0", file: "package.json", safe: false }
  ];
  const report = generateFixReport(fixes);
  assert.ok(report.includes("2 fix(es)"));
  assert.ok(report.includes("1 safe fixes"));
});

test("generateFixReport handles empty fixes", () => {
  const report = generateFixReport([]);
  assert.ok(report.includes("Geen automatische fixes"));
});
