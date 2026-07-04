const SARIF_VERSION = "2.1.0";
const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

const SEVERITY_TO_LEVEL = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "warning",
  info: "note"
};

export function formatSarifReport({ repositories, summary, toolName = "CodeGuardian" }) {
  const rules = [];
  const results = [];
  const ruleIds = new Set();

  for (const repo of repositories) {
    for (const finding of repo.findings) {
      const ruleId = finding.source?.ruleId || `${finding.category}-${finding.id}`;

      if (!ruleIds.has(ruleId)) {
        ruleIds.add(ruleId);
        rules.push({
          id: ruleId,
          name: finding.category,
          shortDescription: { text: finding.title },
          fullDescription: { text: finding.explanation || finding.title },
          defaultConfiguration: { level: SEVERITY_TO_LEVEL[finding.severity] || "warning" },
          properties: {
            category: finding.category,
            severity: finding.severity,
            confidence: finding.confidence || "medium",
            falsePositiveRisk: finding.falsePositiveRisk || "unknown"
          }
        });
      }

      const location = finding.location ? {
        physicalArtifactLocation: {
          artifactLocation: {
            uri: finding.files?.[0] || ""
          },
          region: {
            startLine: finding.location.line || 1,
            startColumn: finding.location.column || 1
          }
        }
      } : {
        physicalArtifactLocation: {
          artifactLocation: { uri: finding.files?.[0] || "" }
        }
      };

      results.push({
        ruleId,
        level: SEVERITY_TO_LEVEL[finding.severity] || "warning",
        message: { text: `${finding.title}. ${finding.proposedFix || ""}`.trim() },
        locations: [location],
        properties: {
          findingId: finding.id,
          category: finding.category,
          severity: finding.severity,
          riskScore: finding.riskScore ?? null,
          compliance: finding.complianceControls || []
        }
      });
    }
  }

  return {
    version: SARIF_VERSION,
    $schema: SARIF_SCHEMA,
    runs: [{
      tool: {
        driver: {
          name: toolName,
          informationUri: "https://github.com/djimit/codeguardian",
          rules,
          properties: {
            totalFindings: summary.totalFindings || 0,
            totalRepositories: summary.totalRepositories || 0,
            maturity: summary.maturity?.overall ?? null
          }
        }
      },
      results,
      properties: {
        totalFindings: summary.totalFindings || 0,
        bySeverity: summary.bySeverity || {},
        maturity: summary.maturity || {}
      }
    }]
  };
}
