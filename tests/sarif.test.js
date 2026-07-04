import { test } from "node:test";
import { strict as assert } from "node:assert";
import { formatSarifReport } from "../src/core/sarif.js";

test("formatSarifReport produces valid SARIF structure", () => {
  const input = {
    repositories: [{
      name: "test-repo",
      findings: [
        {
          id: "f1",
          title: "CVE-2024-1234: Test vulnerability",
          severity: "critical",
          category: "dependency-cve",
          explanation: "A test vulnerability",
          proposedFix: "Update package",
          confidence: "high",
          falsePositiveRisk: "low",
          files: ["package.json"],
          location: { line: 10, column: 1 },
          source: { ruleId: "dependency-cve-CVE-2024-1234" }
        }
      ]
    }],
    summary: {
      totalFindings: 1,
      totalRepositories: 1,
      bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      maturity: { overall: 3.5 }
    }
  };

  const sarif = formatSarifReport(input);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 1);
  assert.equal(sarif.runs[0].results[0].level, "error");
});

test("formatSarifReport maps severity to level correctly", () => {
  const input = {
    repositories: [{
      name: "test",
      findings: [
        { id: "1", title: "Critical", severity: "critical", category: "secret", files: ["a.js"], source: { ruleId: "r1" } },
        { id: "2", title: "High", severity: "high", category: "secret", files: ["b.js"], source: { ruleId: "r2" } },
        { id: "3", title: "Medium", severity: "medium", category: "secret", files: ["c.js"], source: { ruleId: "r3" } },
        { id: "4", title: "Low", severity: "low", category: "secret", files: ["d.js"], source: { ruleId: "r4" } },
        { id: "5", title: "Info", severity: "info", category: "secret", files: ["e.js"], source: { ruleId: "r5" } }
      ]
    }],
    summary: { totalFindings: 5, totalRepositories: 1, bySeverity: {}, maturity: {} }
  };

  const sarif = formatSarifReport(input);
  const levels = sarif.runs[0].results.map((r) => r.level);
  assert.deepEqual(levels, ["error", "error", "warning", "warning", "note"]);
});

test("formatSarifReport deduplicates rules", () => {
  const input = {
    repositories: [{
      name: "test",
      findings: [
        { id: "1", title: "Same rule", severity: "high", category: "secret", files: ["a.js"], source: { ruleId: "same-rule" } },
        { id: "2", title: "Same rule", severity: "high", category: "secret", files: ["b.js"], source: { ruleId: "same-rule" } }
      ]
    }],
    summary: { totalFindings: 2, totalRepositories: 1, bySeverity: {}, maturity: {} }
  };

  const sarif = formatSarifReport(input);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 1);
  assert.equal(sarif.runs[0].results.length, 2);
});

test("formatSarifReport handles empty findings", () => {
  const input = {
    repositories: [{ name: "test", findings: [] }],
    summary: { totalFindings: 0, totalRepositories: 1, bySeverity: {}, maturity: {} }
  };

  const sarif = formatSarifReport(input);
  assert.equal(sarif.runs[0].results.length, 0);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 0);
});
