import fs from "node:fs";
import path from "node:path";

export function appendHistory(repoRoot = ".", entry = {}) {
  const historyPath = path.join(repoRoot, ".codeguardian-history.jsonl");
  const line = JSON.stringify({
    date: new Date().toISOString(),
    ...entry
  }) + "\n";

  fs.appendFileSync(historyPath, line);
}

export function readHistory(repoRoot = ".", retentionDays = 90) {
  const historyPath = path.join(repoRoot, ".codeguardian-history.jsonl");
  const entries = [];

  let content;
  try {
    content = fs.readFileSync(historyPath, "utf8");
  } catch {
    return [];
  }

  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

  for (const line of content.trim().split("\n")) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (new Date(entry.date).getTime() >= cutoff) {
        entries.push(entry);
      }
    } catch {
      // skip malformed lines
    }
  }

  return entries;
}

export function recordScan(repoRoot, scanResult) {
  const entry = {
    repos: scanResult.summary?.totalRepositories || 0,
    findings: scanResult.summary?.bySeverity || {},
    maturity: scanResult.summary?.maturity || {}
  };
  appendHistory(repoRoot, entry);
}

export function getTrendData(repoRoot = ".", retentionDays = 90) {
  const entries = readHistory(repoRoot, retentionDays);
  return entries.map((e) => ({
    date: e.date,
    maturity: e.maturity?.overall ?? null,
    totalFindings: e.findings?.total ?? 0,
    critical: e.findings?.critical ?? 0,
    high: e.findings?.high ?? 0,
    medium: e.findings?.medium ?? 0,
    low: e.findings?.low ?? 0
  }));
}
