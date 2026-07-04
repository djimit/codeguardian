import { test } from "node:test";
import { strict as assert } from "node:assert";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanPII } from "../src/core/pii-scanner.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.join(__dirname, "fixtures");

test("PII scanner detects BSN with valid elfproef", () => {
  const result = scanPII({ repoRoot: fixtureDir });
  const bsnFindings = result.findings.filter((f) => f.title.includes("BSN"));
  assert.ok(bsnFindings.length > 0, "Should detect BSN");
});

test("PII scanner detects valid IBAN", () => {
  const result = scanPII({ repoRoot: fixtureDir });
  const ibanFindings = result.findings.filter((f) => f.title.includes("IBAN"));
  assert.ok(ibanFindings.length > 0, "Should detect IBAN");
});

test("PII scanner excludes example.com emails", () => {
  const result = scanPII({ repoRoot: fixtureDir });
  const emailFindings = result.findings.filter((f) => f.title.includes("Email"));
  const exampleEmail = emailFindings.find((f) => f.exploitScenario?.includes("example.com"));
  assert.ok(!exampleEmail, "Should not flag example.com emails");
});

test("PII scanner detects non-example emails", () => {
  const result = scanPII({ repoRoot: fixtureDir });
  const emailFindings = result.findings.filter((f) => f.title.includes("Email"));
  assert.ok(emailFindings.length > 0, "Should detect non-example emails");
});

test("PII scanner detects Dutch phone numbers", () => {
  const result = scanPII({ repoRoot: fixtureDir });
  const phoneFindings = result.findings.filter((f) => f.title.includes("Phone"));
  assert.ok(phoneFindings.length > 0, "Should detect phone numbers");
});

test("PII scanner detects postal codes", () => {
  const result = scanPII({ repoRoot: fixtureDir });
  const postalFindings = result.findings.filter((f) => f.title.includes("Postal"));
  assert.ok(postalFindings.length > 0, "Should detect postal codes");
});

test("PII scanner detects KvK with context", () => {
  const result = scanPII({ repoRoot: fixtureDir });
  const kvkFindings = result.findings.filter((f) => f.title.includes("KvK"));
  assert.ok(kvkFindings.length > 0, "Should detect KvK with context");
});
