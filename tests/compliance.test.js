import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  mapFindingToControls,
  enrichFindingWithCompliance,
  enrichFindingsWithCompliance,
  generateComplianceSummary,
  complianceToMarkdown,
  getAvailableFrameworks
} from "../src/core/compliance.js";

test("mapFindingToControls maps secret to BIO and AVG controls", () => {
  const finding = { category: "secret-exposure", severity: "critical" };
  const mappings = mapFindingToControls(finding);
  assert.ok(mappings.length > 0);
  const frameworks = new Set(mappings.map((m) => m.framework));
  assert.ok(frameworks.has("BIO2"));
  assert.ok(frameworks.has("AVG"));
});

test("mapFindingToControls maps PII to AVG controls", () => {
  const finding = { category: "privacy-pii", severity: "high" };
  const mappings = mapFindingToControls(finding);
  const frameworks = new Set(mappings.map((m) => m.framework));
  assert.ok(frameworks.has("AVG"));
  assert.ok(frameworks.has("BIO2"));
});

test("mapFindingToControls maps CVE to BIO and NIS2 controls", () => {
  const finding = { category: "dependency-cve", severity: "critical" };
  const mappings = mapFindingToControls(finding);
  const frameworks = new Set(mappings.map((m) => m.framework));
  assert.ok(frameworks.has("BIO2"));
  assert.ok(frameworks.has("NIS2"));
  assert.ok(frameworks.has("NORA"));
});

test("enrichFindingWithCompliance adds complianceMapping", () => {
  const finding = { category: "secret-exposure", severity: "critical" };
  const enriched = enrichFindingWithCompliance(finding);
  assert.ok(enriched.complianceMapping.length > 0);
  assert.ok(enriched.complianceControls.length > 0);
  assert.ok(enriched.complianceControls[0].includes("."));
});

test("generateComplianceSummary aggregates by control", () => {
  const findings = [
    { category: "secret-exposure", severity: "critical", complianceMapping: mapFindingToControls({ category: "secret-exposure" }) },
    { category: "secret-exposure", severity: "high", complianceMapping: mapFindingToControls({ category: "secret-exposure" }) },
    { category: "privacy-pii", severity: "medium", complianceMapping: mapFindingToControls({ category: "privacy-pii" }) }
  ];

  const summary = generateComplianceSummary(findings);
  assert.ok(summary.length > 0);

  const bio2_23 = summary.find((s) => s.controlId === "BIO.2.3");
  assert.ok(bio2_23, "Should have BIO.2.3 entry");
  assert.equal(bio2_23.findings, 2);
  assert.equal(bio2_23.maxSeverity, "critical");
});

test("complianceToMarkdown generates markdown table", () => {
  const findings = [
    { category: "secret-exposure", severity: "critical", complianceMapping: mapFindingToControls({ category: "secret-exposure" }) }
  ];
  const summary = generateComplianceSummary(findings);
  const md = complianceToMarkdown(summary);
  assert.ok(md.includes("BIO2"));
  assert.ok(md.includes("BIO.2.3"));
  assert.ok(md.includes("Compliance Overzicht"));
});

test("complianceToMarkdown returns empty string for no findings", () => {
  const md = complianceToMarkdown([]);
  assert.equal(md, "");
});

test("getAvailableFrameworks returns all frameworks", () => {
  const frameworks = getAvailableFrameworks();
  assert.equal(frameworks.length, 4);
  const ids = frameworks.map((f) => f.id);
  assert.ok(ids.includes("BIO2"));
  assert.ok(ids.includes("NORA"));
  assert.ok(ids.includes("AVG"));
  assert.ok(ids.includes("NIS2"));
});
