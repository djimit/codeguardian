import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import crypto from "node:crypto";

const TEST_DIR_PATTERNS = [
  "/test/", "/tests/", "/__tests__/", "/spec/", "/fixtures/",
  ".test.", ".spec.", "/__test__/", "/testing/"
];

const IGNORE_DIRS = [
  "node_modules/", ".venv/", "venv/", "__pycache__/",
  ".git/", "dist/", "build/", "coverage/", ".next/",
  "vendor/", "target/", "out/"
];

const PII_PATTERNS = [
  {
    type: "bsn",
    regex: /\b\d{9}\b|\b\d{3}[-.\s]\d{3}[-.\s]\d{3}\b/,
    severity: "critical",
    title: "BSN Number detected",
    explanation: "Dutch BSN (Burgerservicenummer) detected. BSN is sensitive PII under GDPR/AVG.",
    proposedFix: "Remove PII from source code. Use anonymized test data or environment variables."
  },
  {
    type: "iban",
    regex: /\bNL\d{2}[A-Z]{4}\d{10}\b/i,
    severity: "high",
    title: "IBAN detected",
    explanation: "Dutch IBAN bank account number detected. Financial data is sensitive under GDPR/AVG.",
    proposedFix: "Remove PII from source code. Use environment variables or a secrets manager."
  },
  {
    type: "kvk",
    regex: /\b\d{8}\b/,
    severity: "medium",
    title: "KvK Number detected",
    explanation: "KvK (Kamer van Koophandel) number detected. Business registration data may be PII.",
    proposedFix: "Remove PII from source code. Use environment variables or a secrets manager.",
    contextKeywords: ["kvk", "KvK", "handelsregister", "chamber of commerce"]
  },
  {
    type: "email",
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
    severity: "low",
    title: "Email Address detected",
    explanation: "Email address detected in source code. May constitute PII under GDPR/AVG.",
    proposedFix: "Remove PII from source code. Use environment variables or a secrets manager.",
    excludeDomains: ["example.com", "test.com", "localhost", "example.org", ".local", "noreply@", "no-reply@"]
  },
  {
    type: "phone",
    regex: /(?:(?:\+31|0031)[-\s]?[1-9]\d{0,2}[-\s]?\d{6,8}|\b06[-\s]?\d{8})\b/,
    severity: "low",
    title: "Dutch Phone Number detected",
    explanation: "Dutch phone number detected. Phone numbers are PII under GDPR/AVG.",
    proposedFix: "Remove PII from source code. Use environment variables or a secrets manager."
  },
  {
    type: "postalcode",
    regex: /\b[1-9]\d{3}\s?[A-Z]{2}\b/,
    severity: "low",
    title: "Dutch Postal Code detected",
    explanation: "Dutch postal code detected. Combined with house number this is PII under GDPR/AVG.",
    proposedFix: "Remove PII from source code. Use environment variables or a secrets manager."
  }
];

function isTestFile(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return TEST_DIR_PATTERNS.some((p) => normalized.includes(p));
}

function shouldIgnore(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return IGNORE_DIRS.some((p) => normalized.includes("/" + p) || normalized.startsWith(p));
}

function downgradeSeverity(severity) {
  const order = ["info", "low", "medium", "high", "critical"];
  const idx = order.indexOf(severity);
  if (idx <= 0) return "info";
  return order[idx - 1];
}

function validateBsn(value) {
  const digits = value.replace(/[-.\s]/g, "");
  if (digits.length !== 9) return false;
  let sum = 0;
  for (let i = 0; i < 8; i++) {
    sum += parseInt(digits[i], 10) * (9 - i);
  }
  sum += parseInt(digits[8], 10) * (-1);
  return sum % 11 === 0;
}

function validateIban(value) {
  const cleaned = value.replace(/\s/g, "").toUpperCase();
  if (!/^NL\d{2}[A-Z]{4}\d{10}$/.test(cleaned)) return false;
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  let numeric = "";
  for (const ch of rearranged) {
    if (ch >= "A" && ch <= "Z") {
      numeric += (ch.charCodeAt(0) - 55).toString();
    } else {
      numeric += ch;
    }
  }
  let remainder = numeric;
  while (remainder.length > 2) {
    const block = remainder.slice(0, 9);
    remainder = (parseInt(block, 10) % 97).toString() + remainder.slice(block.length);
  }
  return parseInt(remainder, 10) % 97 === 1;
}

function hasContextKeyword(content, matchIndex, keywords) {
  const windowStart = Math.max(0, matchIndex - 80);
  const windowEnd = Math.min(content.length, matchIndex + 80);
  const context = content.slice(windowStart, windowEnd).toLowerCase();
  return keywords.some((kw) => context.includes(kw.toLowerCase()));
}

function walkDir(dir, base = dir, results = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!shouldIgnore(fullPath) && entry.name !== ".git") {
        walkDir(fullPath, base, results);
      }
    } else if (entry.isFile()) {
      results.push(path.relative(base, fullPath));
    }
  }
  return results;
}

function getGitTrackedFiles(repoRoot) {
  try {
    const output = execSync("git ls-files", {
      cwd: repoRoot, encoding: "utf8", timeout: 30_000
    });
    const files = output.trim().split("\n").filter(Boolean);
    if (files.length > 0) return files;
  } catch {
    // fallback to directory walk
  }
  return walkDir(repoRoot);
}

function lineFromIndex(content, index) {
  return content.slice(0, index).split("\n").length;
}

export function scanPII({ repoRoot = ".", ignorePatterns = [], includeGitHistory = false } = {}) {
  const startTime = Date.now();
  const findings = [];
  const stats = {
    filesScanned: 0,
    filesSkipped: 0,
    findingsByType: {},
    durationMs: 0
  };

  const trackedFiles = getGitTrackedFiles(repoRoot);
  const seen = new Set();

  for (const filePath of trackedFiles) {
    if (shouldIgnore(filePath)) {
      stats.filesSkipped++;
      continue;
    }
    if (ignorePatterns.some((p) => filePath.includes(p))) {
      stats.filesSkipped++;
      continue;
    }

    const fullPath = path.join(repoRoot, filePath);
    let content;
    try {
      content = fs.readFileSync(fullPath, "utf8");
    } catch {
      stats.filesSkipped++;
      continue;
    }

    stats.filesScanned++;
    const isTest = isTestFile(filePath);

    for (const pattern of PII_PATTERNS) {
      const patternRegex = new RegExp(pattern.regex.source, pattern.regex.flags + "g");
      let piiMatch;

      while ((piiMatch = patternRegex.exec(content)) !== null) {
        const value = piiMatch[0];
        const dedupKey = `${pattern.type}:${filePath}:${value}`;
        if (seen.has(dedupKey)) continue;

        if (pattern.type === "bsn" && !validateBsn(value)) continue;
        if (pattern.type === "iban" && !validateIban(value)) continue;
        if (pattern.type === "email" && pattern.excludeDomains) {
          if (pattern.excludeDomains.some((d) => value.toLowerCase().includes(d))) continue;
        }
        if (pattern.type === "kvk" && pattern.contextKeywords) {
          if (!hasContextKeyword(content, piiMatch.index, pattern.contextKeywords)) continue;
        }

        seen.add(dedupKey);
        let severity = pattern.severity;
        if (isTest) severity = downgradeSeverity(severity);

        const line = lineFromIndex(content, piiMatch.index);
        const masked = value.length > 4
          ? value.slice(0, 4) + "****" + value.slice(-2)
          : "****";

        const idSource = [pattern.type, "privacy-pii", filePath, String(line), "audit"].join("|");
        findings.push({
          id: crypto.createHash("sha256").update(idSource).digest("hex").slice(0, 16),
          title: pattern.title,
          severity,
          confidence: pattern.type === "kvk" ? "medium" : "high",
          category: "privacy-pii",
          files: [filePath],
          explanation: pattern.explanation,
          exploitScenario: masked,
          proposedFix: pattern.proposedFix,
          location: { file: filePath, line, column: 1 },
          source: { ruleId: `pii-${pattern.type}`, layer: "audit" },
          detectionMethod: "pattern",
          falsePositiveRisk: pattern.type === "kvk" ? "high" : "medium",
          remediationEffort: "low",
          complianceMapping: []
        });

        stats.findingsByType[pattern.type] = (stats.findingsByType[pattern.type] ?? 0) + 1;
      }
    }
  }

  stats.durationMs = Date.now() - startTime;
  return { findings, stats };
}
