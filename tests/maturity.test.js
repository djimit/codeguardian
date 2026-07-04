import { test } from "node:test";
import { strict as assert } from "node:assert";
import { calculateMaturity } from "../src/core/maturity.js";

test("empty findings score 5/5/5", () => {
  const result = calculateMaturity([]);
  assert.equal(result.secrets, 5);
  assert.equal(result.dependencies, 5);
  assert.equal(result.pii, 5);
  assert.equal(result.overall, 5);
});

test("single critical secret lowers secrets score to 3", () => {
  const result = calculateMaturity([
    { severity: "critical", category: "secret-exposure" }
  ]);
  assert.equal(result.secrets, 3);
});

test("multiple critical secrets lower secrets score to 1", () => {
  const result = calculateMaturity([
    { severity: "critical", category: "secret-exposure" },
    { severity: "critical", category: "secret-exposure" },
    { severity: "critical", category: "secret-exposure" }
  ]);
  assert.equal(result.secrets, 1);
});

test("single CVE lowers deps score", () => {
  const result = calculateMaturity([
    { severity: "high", category: "dependency-cve" }
  ]);
  assert.ok(result.dependencies <= 4);
});

test("PII findings lower PII score", () => {
  const result = calculateMaturity([
    { severity: "critical", category: "privacy-pii" },
    { severity: "high", category: "privacy-pii" }
  ]);
  assert.ok(result.pii <= 3);
});

test("overall is weighted average", () => {
  const result = calculateMaturity([
    { severity: "low", category: "secret-exposure" },
    { severity: "low", category: "dependency-cve" },
    { severity: "low", category: "privacy-pii" }
  ]);
  assert.ok(result.overall > 0 && result.overall <= 5);
});
