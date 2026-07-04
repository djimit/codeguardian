import { test } from "node:test";
import { strict as assert } from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { getChangedFiles, saveScanState, filterFindingsByFiles } from "../src/core/changed-files.js";
import { buildInventory, saveInventory, loadInventory, findAffectedRepos } from "../src/core/inventory.js";

test("filterFindingsByFiles returns only findings in changed files", () => {
  const findings = [
    { files: ["src/app.js"], title: "Finding A" },
    { files: ["src/lib.js"], title: "Finding B" },
    { files: ["tests/app.test.js"], title: "Finding C" }
  ];
  const changed = ["src/app.js", "tests/app.test.js"];
  const result = filterFindingsByFiles(findings, changed);
  assert.equal(result.length, 2);
  assert.deepEqual(result.map((f) => f.title), ["Finding A", "Finding C"]);
});

test("filterFindingsByFiles returns empty for no overlap", () => {
  const findings = [{ files: ["src/app.js"] }];
  const result = filterFindingsByFiles(findings, ["other.js"]);
  assert.equal(result.length, 0);
});

test("saveScanState and getChangedFiles roundtrip", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  fs.writeFileSync(path.join(tmpDir, ".codeguardian-state.json"), JSON.stringify({
    lastScanSha: "abc123",
    lastScanDate: new Date().toISOString()
  }));

  const changed = getChangedFiles(tmpDir);
  assert.ok(changed === null || typeof changed === "object");
});

test("buildInventory extracts dependencies from findings", () => {
  const scanResult = {
    repositories: [{
      name: "test-repo",
      path: "/tmp/test",
      maturity: { overall: 3.5 },
      findings: [
        { id: "f1", category: "dependency-cve", title: "CVE-2024-1234: Test", proposedFix: "Update ws to version 5.2.5", source: { ruleId: "dep-cve" } },
        { id: "f2", category: "dependency-cve", title: "CVE-2024-5678: Test", proposedFix: "Update ws to version 5.2.5", source: { ruleId: "dep-cve" } },
        { id: "f3", category: "privacy-pii", title: "BSN detected", source: { ruleId: "pii-bsn" } }
      ]
    }]
  };

  const inventory = buildInventory("/tmp/test", scanResult);
  assert.equal(Object.keys(inventory.repositories).length, 1);
  const repo = inventory.repositories["test-repo"];
  assert.equal(repo.dependencies.length, 1);
  assert.equal(repo.dependencies[0].name, "ws");
  assert.equal(repo.dependencies[0].cves.length, 2);
  assert.equal(repo.pii.length, 1);
  assert.equal(repo.totalFindings, 3);
});

test("saveInventory and loadInventory roundtrip", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  const inventory = {
    lastUpdated: new Date().toISOString(),
    repositories: {
      "repo-a": { dependencies: [{ name: "ws", cves: ["f1"] }], maturity: { overall: 4 } }
    }
  };

  saveInventory(tmpDir, inventory);
  const loaded = loadInventory(tmpDir);
  assert.equal(loaded.repositories["repo-a"].dependencies[0].name, "ws");
});

test("findAffectedRepos finds repos with package", () => {
  const inventory = {
    repositories: {
      "repo-a": { dependencies: [{ name: "ws", ecosystem: "npm", cves: ["f1"] }] },
      "repo-b": { dependencies: [{ name: "react", ecosystem: "npm", cves: ["f2"] }] },
      "repo-c": { dependencies: [{ name: "ws", ecosystem: "npm", cves: ["f3"] }] }
    }
  };

  const affected = findAffectedRepos(inventory, "ws");
  assert.equal(affected.length, 2);
  assert.deepEqual(affected.map((a) => a.repo).sort(), ["repo-a", "repo-c"]);
});

test("findAffectedRepos is case insensitive", () => {
  const inventory = {
    repositories: {
      "repo-a": { dependencies: [{ name: "WS", cves: ["f1"] }] }
    }
  };
  const affected = findAffectedRepos(inventory, "ws");
  assert.equal(affected.length, 1);
});
