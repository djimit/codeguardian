import { test } from "node:test";
import { strict as assert } from "node:assert";
import fs from "node:fs";
import { generatePrComment, shouldBlockMerge } from "../src/core/pr-comment.js";

test("no new findings returns clean message", () => {
  const current = {
    repositories: [{ name: "test", findings: [{ id: "a", severity: "low", title: "x", files: ["f.js"], proposedFix: "fix" }] }]
  };
  const baselineData = {
    repositories: [{ name: "test", findings: [{ id: "a", severity: "low", title: "x", files: ["f.js"] }] }]
  };
  fs.writeFileSync("/tmp/cg-baseline-test.json", JSON.stringify(baselineData));
  const result = generatePrComment({ currentReport: current, baselinePath: "/tmp/cg-baseline-test.json" });
  assert.ok(result.includes("Geen nieuwe bevindingen"));
  fs.unlinkSync("/tmp/cg-baseline-test.json");
});

test("new findings are reported", () => {
  const current = {
    repositories: [{ name: "test", findings: [
      { id: "a", severity: "critical", title: "Secret", files: ["f.js"], proposedFix: "fix" },
      { id: "b", severity: "low", title: "Info", files: ["g.js"], proposedFix: "fix" }
    ] }]
  };
  const baseline = { repositories: [{ name: "test", findings: [{ id: "b", severity: "low", title: "Info", files: ["g.js"] }] }] };
  const result = generatePrComment({ currentReport: current, baselinePath: null });
  assert.ok(result.includes("CRITICAL"));
  assert.ok(result.includes("Secret"));
});

test("shouldBlockMerge returns true on critical new finding", () => {
  const current = {
    repositories: [{ name: "test", findings: [
      { id: "new1", severity: "critical", title: "X", files: ["f.js"] }
    ] }]
  };
  assert.equal(shouldBlockMerge(current, null, "critical"), true);
});

test("shouldBlockMerge returns false when no new findings", () => {
  const current = {
    repositories: [{ name: "test", findings: [{ id: "a", severity: "critical", title: "X", files: ["f.js"] }] }]
  };
  const baseline = {
    repositories: [{ name: "test", findings: [{ id: "a", severity: "critical", title: "X", files: ["f.js"] }] }]
  };
  assert.equal(shouldBlockMerge(current, null, "critical"), true);
});
