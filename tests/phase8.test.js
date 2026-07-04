import { test } from "node:test";
import { strict as assert } from "node:assert";
import { generatePrReviewComments } from "../src/core/pr-review.js";
import { generateRotationPlaybook, generateAllPlaybooks, playbooksToMarkdown } from "../src/core/secret-rotation.js";
import { scanSupplyChain } from "../src/core/supply-chain.js";

test("generatePrReviewComments returns empty for no findings", () => {
  const report = { repositories: [{ name: "test", findings: [] }] };
  const comments = generatePrReviewComments({ report, owner: "o", repo: "r", prNumber: 1 });
  assert.equal(comments.length, 0);
});

test("generateRotationPlaybook generates API key playbook", () => {
  const finding = {
    title: "API Key detected",
    category: "secret-exposure",
    files: ["src/config.js"],
    location: { line: 5 }
  };
  const playbook = generateRotationPlaybook(finding);
  assert.equal(playbook.type, "api-key");
  assert.ok(playbook.steps.length > 0);
  assert.ok(playbook.ghCommands.length > 0);
  assert.ok(playbook.ghCommands[0].includes("gh secret set"));
});

test("generateRotationPlaybook generates DB URL playbook", () => {
  const finding = {
    title: "Database URL detected",
    category: "secret-exposure",
    files: ["src/db.js"],
    location: { line: 12 }
  };
  const playbook = generateRotationPlaybook(finding);
  assert.equal(playbook.type, "db-url");
  assert.ok(playbook.steps.join("\n").includes("CREATE USER"));
});

test("generateAllPlaybooks filters secret findings only", () => {
  const findings = [
    { title: "API Key detected", category: "secret-exposure", files: ["a.js"], location: { line: 1 } },
    { title: "BSN detected", category: "privacy-pii", files: ["b.js"], location: { line: 2 } },
    { title: "Password in config", category: "secret-exposure", files: ["c.js"], location: { line: 3 } }
  ];
  const playbooks = generateAllPlaybooks(findings);
  assert.equal(playbooks.length, 2);
});

test("playbooksToMarkdown generates markdown output", () => {
  const findings = [
    { title: "API Key detected", category: "secret-exposure", files: ["a.js"], location: { line: 1 } }
  ];
  const playbooks = generateAllPlaybooks(findings);
  const md = playbooksToMarkdown(playbooks);
  assert.ok(md.includes("Rotation Playbook"));
  assert.ok(md.includes("gh secret set"));
});

test("scanSupplyChain detects typosquatting", async () => {
  const { execSync } = await import("node:child_process");
  const fs = await import("node:fs");
  const path = await import("node:path");
  const os = await import("node:os");

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-sc-"));
  fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
    dependencies: { "lodahs": "1.0.0", "react": "18.0.0" }
  }));

  const findings = await scanSupplyChain({ repoRoot: tmpDir, advisories: false });
  const typo = findings.find((f) => f.supplyChainSignal?.type === "typosquatting");
  assert.ok(typo, "Should detect lodahs as typosquat of lodash");
  assert.equal(typo.supplyChainSignal.similarTo, "lodash");
});

test("scanSupplyChain does not flag legitimate packages", async () => {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const os = await import("node:os");

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-sc-"));
  fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
    dependencies: { "react": "18.0.0", "express": "4.18.0" }
  }));

  const findings = await scanSupplyChain({ repoRoot: tmpDir, advisories: false });
  assert.equal(findings.length, 0);
});
