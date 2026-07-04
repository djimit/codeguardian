import { test } from "node:test";
import { strict as assert } from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { appendHistory, readHistory, getTrendData, recordScan } from "../src/core/history.js";

test("appendHistory writes JSONL entry", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  appendHistory(tmpDir, { repos: 3, findings: { total: 5 } });

  const historyPath = path.join(tmpDir, ".codeguardian-history.jsonl");
  const content = fs.readFileSync(historyPath, "utf8");
  const entry = JSON.parse(content.trim());
  assert.equal(entry.repos, 3);
  assert.equal(entry.findings.total, 5);
  assert.ok(entry.date);
});

test("readHistory returns entries within retention", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  appendHistory(tmpDir, { repos: 1, findings: { total: 2 } });
  appendHistory(tmpDir, { repos: 2, findings: { total: 3 } });

  const entries = readHistory(tmpDir, 90);
  assert.equal(entries.length, 2);
});

test("readHistory filters expired entries", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  const historyPath = path.join(tmpDir, ".codeguardian-history.jsonl");

  const oldEntry = JSON.stringify({
    date: "2020-01-01T00:00:00Z",
    repos: 1,
    findings: { total: 10 }
  });
  const newEntry = JSON.stringify({
    date: new Date().toISOString(),
    repos: 1,
    findings: { total: 1 }
  });

  fs.writeFileSync(historyPath, oldEntry + "\n" + newEntry + "\n");
  const entries = readHistory(tmpDir, 90);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].findings.total, 1);
});

test("getTrendData formats trend entries", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
  appendHistory(tmpDir, {
    repos: 2,
    findings: { total: 5, critical: 1, high: 2 },
    maturity: { overall: 3.5 }
  });

  const trend = getTrendData(tmpDir);
  assert.equal(trend.length, 1);
  assert.equal(trend[0].maturity, 3.5);
  assert.equal(trend[0].totalFindings, 5);
  assert.equal(trend[0].critical, 1);
});
