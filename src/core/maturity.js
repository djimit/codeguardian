const SEVERITY_WEIGHTS = { critical: 10, high: 5, medium: 2, low: 1, info: 0 };

const THRESHOLDS = [
  { maxSeverity: 4, minScore: 25, score: 1 },
  { maxSeverity: 3, minScore: 12, score: 2 },
  { minScore: 6, score: 3 },
  { maxCount: 5, score: 4 },
];

function scoreDimension(findings, categoryFilter) {
  const relevant = findings.filter((f) => categoryFilter(f.category));
  if (relevant.length === 0) return 5;

  let weightedScore = 0;
  for (const f of relevant) {
    weightedScore += SEVERITY_WEIGHTS[f.severity] ?? 1;
  }

  const maxSeverity = relevant.reduce((max, f) => {
    const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    return Math.max(max, order[f.severity] ?? 0);
  }, 0);

  for (const t of THRESHOLDS) {
    if (t.maxSeverity !== undefined && maxSeverity >= t.maxSeverity && weightedScore >= t.minScore) {
      return t.score;
    }
    if (t.maxSeverity === undefined && t.minScore !== undefined && weightedScore >= t.minScore) {
      return t.score;
    }
    if (t.maxCount !== undefined && relevant.length <= t.maxCount && weightedScore < 6) {
      return t.score;
    }
  }

  return 3;
}

function isSecretCategory(category) {
  return category === "secret-exposure" ||
    category === "security-bypass" ||
    category === "infrastructure-disclosure" ||
    category.includes("secret");
}

function isDepCategory(category) {
  return category === "dependency-cve";
}

function isPIICategory(category) {
  return category === "privacy-pii";
}

export function calculateMaturity(findings) {
  const secrets = scoreDimension(findings, isSecretCategory);
  const deps = scoreDimension(findings, isDepCategory);
  const pii = scoreDimension(findings, isPIICategory);

  const overall = Math.round(
    (secrets * 0.4 + deps * 0.35 + pii * 0.25) * 10
  ) / 10;

  return {
    secrets,
    dependencies: deps,
    pii,
    overall,
    label: maturityLabel(overall)
  };
}

function maturityLabel(score) {
  if (score >= 4.5) return "Best practice";
  if (score >= 3.5) return "Goed";
  if (score >= 2.5) return "Basis";
  if (score >= 1.5) return "Minimaal";
  return "Afwezig";
}

export function maturityToMarkdown(maturity) {
  return [
    `Secrets ${maturity.secrets}/5`,
    `Deps ${maturity.dependencies}/5`,
    `PII ${maturity.pii}/5`
  ].join(" · ");
}
