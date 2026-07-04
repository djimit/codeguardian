import { test } from "node:test";
import { strict as assert } from "node:assert";
import { calculateRisk, riskLabel, riskColor, enrichFindingsWithRisk, sortByRisk } from "../src/core/risk-engine.js";

test("critical finding in production has high risk", () => {
  const finding = {
    severity: "critical",
    category: "secret-exposure",
    files: ["/src/auth/token.js"],
    exploitAvailable: true
  };
  const score = calculateRisk(finding, { isPublicRepo: true });
  assert.ok(score >= 80, `Expected >= 80, got ${score}`);
});

test("low finding in test file has low risk", () => {
  const finding = {
    severity: "low",
    category: "privacy-pii",
    files: ["tests/fixtures/data.js"]
  };
  const score = calculateRisk(finding, { isPrivateRepo: true });
  assert.ok(score <= 40, `Expected <= 40, got ${score}`);
});

test("test file context reduces risk", () => {
  const prod = {
    severity: "high",
    category: "dependency-cve",
    files: ["src/app.js"]
  };
  const test = {
    severity: "high",
    category: "dependency-cve",
    files: ["tests/app.test.js"]
  };
  const prodScore = calculateRisk(prod, {});
  const testScore = calculateRisk(test, {});
  assert.ok(prodScore > testScore, `Prod (${prodScore}) should be > test (${testScore})`);
});

test("public repo increases risk vs private", () => {
  const finding = {
    severity: "medium",
    category: "dependency-cve",
    files: ["lib/utils.js"]
  };
  const pub = calculateRisk(finding, { isPublicRepo: true });
  const priv = calculateRisk(finding, { isPrivateRepo: true });
  assert.ok(pub > priv, `Public (${pub}) should be > private (${priv})`);
});

test("recent CVE scores higher than old one", () => {
  const recent = {
    severity: "high",
    category: "dependency-cve",
    files: ["src/app.js"],
    publishedDate: new Date().toISOString()
  };
  const old = {
    severity: "high",
    category: "dependency-cve",
    files: ["src/app.js"],
    publishedDate: "2020-01-01T00:00:00Z"
  };
  assert.ok(calculateRisk(recent, {}) > calculateRisk(old, {}));
});

test("riskLabel returns correct labels", () => {
  assert.equal(riskLabel(90), "Critical Risk");
  assert.equal(riskLabel(70), "High Risk");
  assert.equal(riskLabel(50), "Medium Risk");
  assert.equal(riskLabel(30), "Low Risk");
  assert.equal(riskLabel(10), "Minimal Risk");
});

test("enrichFindingsWithRisk adds riskScore and riskLabel", () => {
  const findings = [
    { severity: "critical", category: "secret-exposure", files: ["src/auth.js"] },
    { severity: "low", category: "privacy-pii", files: ["tests/data.js"] }
  ];
  const enriched = enrichFindingsWithRisk(findings, {});
  assert.ok(enriched[0].riskScore > enriched[1].riskScore);
  assert.ok(enriched[0].riskLabel);
  assert.ok(enriched[1].riskLabel);
});

test("sortByRisk orders descending", () => {
  const findings = [
    { severity: "low", files: ["tests/a.js"], riskScore: 10 },
    { severity: "critical", files: ["src/a.js"], riskScore: 90 },
    { severity: "medium", files: ["src/b.js"], riskScore: 50 }
  ];
  const sorted = sortByRisk(findings);
  assert.equal(sorted[0].riskScore, 90);
  assert.equal(sorted[1].riskScore, 50);
  assert.equal(sorted[2].riskScore, 10);
});
