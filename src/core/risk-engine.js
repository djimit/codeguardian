const SEVERITY_BASE = { critical: 100, high: 75, medium: 50, low: 25, info: 10 };

const TEST_PATTERNS = [
  "/test/", "/tests/", "/__tests__/", "/spec/", "/fixtures/",
  ".test.", ".spec.", "/__test__/", "/testing/"
];

const PROD_PATTERNS = [
  "/src/", "/lib/", "/app/", "/server/", "/api/", "/services/"
];

function isTestFile(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return TEST_PATTERNS.some((p) => normalized.includes(p));
}

function isProdFile(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return PROD_PATTERNS.some((p) => normalized.includes(p));
}

export function calculateRisk(finding, context = {}) {
  let score = 0;

  score += (SEVERITY_BASE[finding.severity] ?? 50) * 0.4;

  if (finding.exploitAvailable) score += 20;
  else if (finding.exploitScenario) score += 10;

  if (context.isPublicRepo) score += 15;
  else if (context.isPrivateRepo) score += 5;
  else score += 10;

  const files = finding.files || [];
  if (files.some(isTestFile)) score += 2;
  else if (files.some(isProdFile)) score += 15;
  else score += 8;

  if (finding.publishedDate) {
    const daysSince = (Date.now() - new Date(finding.publishedDate)) / 86400000;
    if (daysSince < 30) score += 10;
    else if (daysSince < 90) score += 5;
  } else if (finding.category === "dependency-cve") {
    score += 5;
  }

  return Math.min(100, Math.round(score));
}

export function riskLabel(score) {
  if (score >= 80) return "Critical Risk";
  if (score >= 60) return "High Risk";
  if (score >= 40) return "Medium Risk";
  if (score >= 20) return "Low Risk";
  return "Minimal Risk";
}

export function riskColor(score) {
  if (score >= 80) return "#dc2626";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#eab308";
  if (score >= 20) return "#22c55e";
  return "#3b82f6";
}

export function enrichFindingsWithRisk(findings, context = {}) {
  return findings.map((f) => ({
    ...f,
    riskScore: calculateRisk(f, context),
    riskLabel: riskLabel(calculateRisk(f, context))
  }));
}

export function sortByRisk(findings) {
  return [...findings].sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));
}
