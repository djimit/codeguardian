const CONTROLS = {
  "BIO2": {
    name: "BIO2 Baseline Informatiebeveiliging Overheid",
    version: "2.0",
    controls: [
      { id: "BIO.1.1", title: "Beveiligingsbeleid", categories: ["policy"] },
      { id: "BIO.2.1", title: "Toegangsbeveiliging", categories: ["secret-exposure", "security-bypass"] },
      { id: "BIO.2.3", title: "Geheimhouding van authenticatiegegevens", categories: ["secret-exposure"] },
      { id: "BIO.3.1", title: "Cryptografische maatregelen", categories: ["secret-exposure", "infrastructure-disclosure"] },
      { id: "BIO.4.1", title: "Secure development", categories: ["dependency-cve", "security-bypass"] },
      { id: "BIO.4.2", title: "Beveiligingsreview", categories: ["dependency-cve", "secret-exposure", "privacy-pii"] },
      { id: "BIO.5.1", title: "Logging en monitoring", categories: ["policy"] },
      { id: "BIO.6.1", title: "Beheer van technische kwetsbaarheden", categories: ["dependency-cve"] },
      { id: "BIO.7.1", title: "Bescherming van persoonsgegevens", categories: ["privacy-pii"] },
      { id: "BIO.8.1", title: "Incidentrespons", categories: ["policy"] }
    ]
  },
  "NORA": {
    name: "NORA Referentie Architectuur",
    version: "3.0",
    controls: [
      { id: "NORA.AC.1", title: "Authenticatie", categories: ["secret-exposure", "security-bypass"] },
      { id: "NORA.AC.2", title: "Autorisatie", categories: ["security-bypass"] },
      { id: "NORA.DP.1", title: "Data protectie", categories: ["privacy-pii"] },
      { id: "NORA.DP.2", title: "Data classificatie", categories: ["privacy-pii", "secret-exposure"] },
      { id: "NORA.SC.1", title: "Supply chain security", categories: ["dependency-cve"] },
      { id: "NORA.SC.2", title: "Component beveiliging", categories: ["dependency-cve"] },
      { id: "NORA.IM.1", title: "Identity management", categories: ["secret-exposure"] },
      { id: "NORA.LOG.1", title: "Logging", categories: ["policy"] }
    ]
  },
  "AVG": {
    name: "AVG / GDPR",
    version: "2016/679",
    controls: [
      { id: "AVG.5.1", title: "Beginselen van gegevensverwerking", categories: ["privacy-pii"] },
      { id: "AVG.17", title: "Beveiliging van verwerking", categories: ["privacy-pii", "secret-exposure", "dependency-cve"] },
      { id: "AVG.25", title: "Gegevensbescherming door ontwerp", categories: ["privacy-pii", "dependency-cve"] },
      { id: "AVG.32", title: "Beveiliging van de verwerking", categories: ["secret-exposure", "security-bypass", "infrastructure-disclosure"] },
      { id: "AVG.33", title: "Melding van inbreuk", categories: ["privacy-pii", "secret-exposure"] },
      { id: "AVG.35", title: "Gegevensbeschermingseffectbeoordeling", categories: ["privacy-pii"] }
    ]
  },
  "NIS2": {
    name: "NIS2 / Cyberbeveiligingswet",
    version: "2024",
    controls: [
      { id: "NIS2.5", title: "Risicomanagement", categories: ["dependency-cve", "secret-exposure"] },
      { id: "NIS2.6", title: "Beveiligingsmaatregelen", categories: ["dependency-cve", "secret-exposure", "security-bypass"] },
      { id: "NIS2.7", title: "Incidenthantering", categories: ["policy"] },
      { id: "NIS2.8", title: "Business continuity", categories: ["policy"] },
      { id: "NIS2.9", title: "Supply chain security", categories: ["dependency-cve"] },
      { id: "NIS2.10", title: "Beveiliging van netwerk- en informatiesystemen", categories: ["secret-exposure", "infrastructure-disclosure"] }
    ]
  }
};

export function mapFindingToControls(finding) {
  const mappings = [];
  const category = finding.category || "";

  for (const [framework, { name: frameworkName, version, controls }] of Object.entries(CONTROLS)) {
    for (const control of controls) {
      if (control.categories.some((c) => category.includes(c) || matchesCategory(category, c))) {
        mappings.push({
          framework,
          frameworkName,
          version,
          controlId: control.id,
          controlTitle: control.title,
          findingCategory: category
        });
      }
    }
  }

  return mappings;
}

function matchesCategory(category, controlCategory) {
  if (controlCategory === "secret-exposure" && category.includes("secret")) return true;
  if (controlCategory === "dependency-cve" && category.includes("dependency")) return true;
  if (controlCategory === "privacy-pii" && category.includes("pii")) return true;
  return false;
}

export function enrichFindingWithCompliance(finding) {
  const complianceMapping = mapFindingToControls(finding);
  return {
    ...finding,
    complianceMapping,
    complianceControls: complianceMapping.map((m) => m.controlId)
  };
}

export function enrichFindingsWithCompliance(findings) {
  return findings.map(enrichFindingWithCompliance);
}

export function generateComplianceSummary(findings) {
  const summary = {};

  for (const finding of findings) {
    for (const mapping of finding.complianceMapping || []) {
      const key = `${mapping.framework}.${mapping.controlId}`;
      if (!summary[key]) {
        summary[key] = {
          framework: mapping.framework,
          frameworkName: mapping.frameworkName,
          controlId: mapping.controlId,
          controlTitle: mapping.controlTitle,
          findings: 0,
          maxSeverity: "info",
          categories: new Set()
        };
      }
      summary[key].findings++;
      summary[key].categories.add(mapping.findingCategory);
      if (severityRank(finding.severity) > severityRank(summary[key].maxSeverity)) {
        summary[key].maxSeverity = finding.severity;
      }
    }
  }

  for (const entry of Object.values(summary)) {
    entry.categories = Array.from(entry.categories);
  }

  return Object.values(summary).sort((a, b) => {
    if (a.framework !== b.framework) return a.framework.localeCompare(b.framework);
    return a.controlId.localeCompare(b.controlId);
  });
}

function severityRank(severity) {
  const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return order[severity] ?? 0;
}

export function complianceToMarkdown(summary) {
  if (summary.length === 0) return "";

  const lines = ["## Compliance Overzicht", ""];
  let currentFramework = null;

  for (const entry of summary) {
    if (entry.framework !== currentFramework) {
      currentFramework = entry.framework;
      lines.push(`### ${entry.framework} — ${entry.frameworkName}`);
      lines.push("");
    }
    const sev = entry.maxSeverity.toUpperCase();
    lines.push(`- **${entry.controlId}** ${entry.controlTitle} — ${entry.findings} bevindingen (max: ${sev})`);
  }

  return lines.join("\n");
}

export function getAvailableFrameworks() {
  return Object.entries(CONTROLS).map(([id, { name, version }]) => ({ id, name, version }));
}
