import { maturityToMarkdown } from "./maturity.js";
import { riskLabel, riskColor } from "./risk-engine.js";
import { complianceToMarkdown } from "./compliance.js";

function maskValue(value) {
  if (!value || value.length < 8) return "****";
  return value.slice(0, 4) + "****" + value.slice(-2);
}

function severityEmoji(severity) {
  switch (severity) {
    case "critical": return "CRITICAL";
    case "high": return "HIGH";
    case "medium": return "MEDIUM";
    case "low": return "LOW";
    default: return "INFO";
  }
}

function urgencyLabel(severity) {
  switch (severity) {
    case "critical": return "[ONMIDDELLIJK]";
    case "high": return "[DEZE WEEK]";
    case "medium": return "[GEPLAND]";
    case "low": return "[VOLGENDE SPRINT]";
    default: return "[VOLGENDE SPRINT]";
  }
}

export function formatMarkdownReport({ repositories, summary, username, date, baseline }) {
  const lines = [];
  const scanDate = date || new Date().toLocaleDateString("nl-NL", {
    day: "numeric", month: "long", year: "numeric"
  });

  lines.push("# CodeGuardian — Scanrapport");
  lines.push("");
  lines.push(`Gebruiker\t${username ?? "unknown"}`);
  lines.push(`Datum\t${scanDate}`);
  lines.push(`Repositories\t${summary.totalRepositories}`);
  lines.push(`Bevindingen\t${summary.totalFindings}`);
  lines.push(`Maturity\t${maturityToMarkdown(summary.maturity)}`);
  lines.push(`Risk\t${summary.avgRisk ?? 0}/100 avg · ${summary.maxRisk ?? 0}/100 max`);
  lines.push(`Scores\t1 Afwezig · 2 Minimaal · 3 Basis · 4 Goed · 5 Best practice`);

  if (baseline) {
    const baselineIds = new Set(baseline.flatMap((r) => r.findings?.map((f) => f.id) || []));
    const currentIds = new Set(repositories.flatMap((r) => r.findings.map((f) => f.id)));
    const newCount = [...currentIds].filter((id) => !baselineIds.has(id)).length;
    const resolvedCount = [...baselineIds].filter((id) => !currentIds.has(id)).length;
    if (newCount > 0 || resolvedCount > 0) {
      lines.push(`📊 **Trend**: ${newCount} nieuw, ${resolvedCount} opgelost sinds vorige scan`);
      lines.push("");
    }
  }

  lines.push("");
  lines.push("## Uitgevoerde scans");
  lines.push("");

  const scanTypes = [
    { name: "Secrets & Tokens", category: "secret-exposure", description: "API keys, tokens, wachtwoorden, private keys, database URLs (20+ patronen + entropy analyse)" },
    { name: "Dependency CVEs", category: "dependency-cve", description: "Bekende kwetsbaarheden (CVEs) in npm, PyPI, Go en Maven packages via OSV.dev" },
    { name: "Persoonsgegevens (PII)", category: "privacy-pii", description: "BSN (elfproef), IBAN (mod-97), e-mailadressen, telefoonnummers, KvK-nummers, postcodes (NL-specifiek)" },
    { name: "Security Best Practices", category: "security-bypass", description: "SSL bypass, debug mode, insecure fallbacks, eval, weak crypto, CORS" },
    { name: "Supply Chain Risks", category: "supply-chain-risk", description: "Typosquatting, suspicious packages, GitHub Advisory Database" }
  ];

  for (const scan of scanTypes) {
    lines.push("");
    lines.push(`### ${scan.name}`);
    lines.push("");
    lines.push(`**Wat wordt getest:** ${scan.description}`);
    lines.push("");

    const reposWithFindings = repositories.filter((r) =>
      r.findings.some((f) => f.category === scan.category)
    );

    if (reposWithFindings.length === 0) {
      lines.push("Geen bevindingen.");
      continue;
    }

    for (const repo of reposWithFindings) {
      const repoFindings = repo.findings.filter((f) => f.category === scan.category);
      lines.push("");
      lines.push(`**${repo.name}** — ${repoFindings.length} bevindingen`);
      lines.push("");

      const sorted = [...repoFindings].sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));

      for (const finding of sorted) {
        const masked = finding.exploitScenario
          ? maskValue(finding.exploitScenario)
          : "****";
        const location = finding.location
          ? `${finding.files[0]}:${finding.location.line}`
          : finding.files[0];
        const risk = finding.riskScore != null ? ` [risk: ${finding.riskScore}]` : "";
        lines.push(`- **${severityEmoji(finding.severity)}** ${location}: ${finding.title} (${masked})${risk}`);
        lines.push(`  ${finding.proposedFix}`);
      }
    }
  }

  lines.push("");
  lines.push("## Actielijst");
  lines.push("");

  const allFindings = repositories.flatMap((r) =>
    r.findings.map((f) => ({ ...f, repoName: r.name }))
  );

  const prioritized = [
    ...allFindings.filter((f) => f.severity === "critical"),
    ...allFindings.filter((f) => f.severity === "high"),
    ...allFindings.filter((f) => f.severity === "medium"),
    ...allFindings.filter((f) => f.severity === "low")
  ];

  for (const finding of prioritized.slice(0, 50)) {
    const location = finding.location
      ? `${finding.repoName}/${finding.files[0]}:${finding.location.line}`
      : `${finding.repoName}/${finding.files[0]}`;
    lines.push(`- **${severityEmoji(finding.severity)}** ${urgencyLabel(finding.severity)} ${finding.title} in ${location}`);
    lines.push(`  ${finding.proposedFix}`);
  }

  if (prioritized.length > 50) {
    lines.push("");
    lines.push(`... en nog ${prioritized.length - 50} bevindingen.`);
  }

  const complianceMd = complianceToMarkdown(summary.compliance || []);
  if (complianceMd) {
    lines.push("");
    lines.push(complianceMd);
  }

  lines.push("");
  lines.push("---");
  lines.push("*Gegenereerd door CodeGuardian Scanner*");

  return lines.join("\n") + "\n";
}

export function formatJsonReport({ repositories, summary }) {
  return JSON.stringify({ repositories, summary }, null, 2);
}
