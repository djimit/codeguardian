import { test } from "node:test";
import { strict as assert } from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { formatJsonReport, writeJsonReport } from "../src/core/report-formatter.js";

test("writeJsonReport writes a parseable report without whole-report stringification", () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cg-report-")), "report.json");
  const report = {
    repositories: Array.from({ length: 3 }, (_, i) => ({ name: `repo-${i}`, findings: [{ id: String(i) }] })),
    summary: { totalRepositories: 3, totalFindings: 3 }
  };

  writeJsonReport(file, report);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), JSON.parse(formatJsonReport(report)));
});
