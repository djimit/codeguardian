import fs from "node:fs";

function findNewFindings(currentFindings, baselineFindings) {
  const baselineIds = new Set(baselineFindings.map((f) => f.id));
  return currentFindings.filter((f) => !baselineIds.has(f.id));
}

function groupByRepo(findings) {
  const grouped = {};
  for (const f of findings) {
    const repoName = f.repoName || "unknown";
    if (!grouped[repoName]) grouped[repoName] = [];
    grouped[repoName].push(f);
  }
  return grouped;
}

export function generatePrComment({ currentReport, baselinePath }) {
  let baseline = { repositories: [] };
  if (baselinePath && fs.existsSync(baselinePath)) {
    try {
      baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
    } catch {
      // invalid baseline, treat as empty
    }
  }

  const currentFindings = currentReport.repositories.flatMap((r) =>
    r.findings.map((f) => ({ ...f, repoName: r.name }))
  );
  const baselineFindings = baseline.repositories?.flatMap((r) =>
    r.findings?.map((f) => ({ ...f, repoName: r.name })) ?? []
  ) ?? [];

  const newFindings = findNewFindings(currentFindings, baselineFindings);

  if (newFindings.length === 0) {
    return "## CodeGuardian PR Check\n\nGeen nieuwe bevindingen. Alle issues uit baseline zijn opgelost of geen regressie.";
  }

  const grouped = groupByRepo(newFindings);
  const lines = ["## CodeGuardian PR Check\n"];
  lines.push(`${newFindings.length} nieuwe bevindingen vergeleken met baseline:\n`);

  for (const [repo, findings] of Object.entries(grouped)) {
    lines.push(`### ${repo}\n`);
    for (const f of findings.slice(0, 10)) {
      const loc = f.location ? `${f.files[0]}:${f.location.line}` : f.files[0];
      lines.push(`- **${f.severity.toUpperCase()}** ${loc}: ${f.title}`);
    }
    if (findings.length > 10) {
      lines.push(`- ... en nog ${findings.length - 10} bevindingen`);
    }
    lines.push("");
  }

  const criticalCount = newFindings.filter((f) => f.severity === "critical").length;
  const highCount = newFindings.filter((f) => f.severity === "high").length;

  if (criticalCount > 0) {
    lines.push(`\n **${criticalCount} CRITICAL** findings — merge geblokkeerd.`);
  }
  if (highCount > 0) {
    lines.push(`\n **${highCount} HIGH** findings — vereist review.`);
  }

  return lines.join("\n");
}

export function shouldBlockMerge(currentReport, baselinePath, threshold = "critical") {
  const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const minLevel = order[threshold] ?? 4;

  let baseline = { repositories: [] };
  if (baselinePath && fs.existsSync(baselinePath)) {
    try { baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8")); } catch {}
  }

  const currentFindings = currentReport.repositories.flatMap((r) =>
    r.findings.map((f) => ({ ...f, repoName: r.name }))
  );
  const baselineFindings = baseline.repositories?.flatMap((r) =>
    r.findings?.map((f) => ({ ...f, repoName: r.name })) ?? []
  ) ?? [];

  const newFindings = findNewFindings(currentFindings, baselineFindings);
  return newFindings.some((f) => (order[f.severity] ?? 0) >= minLevel);
}
