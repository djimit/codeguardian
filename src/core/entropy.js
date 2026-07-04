import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const IGNORE_DIRS = [
  "node_modules/", ".venv/", "venv/", "__pycache__/",
  "dist/", "build/", "coverage/", ".next/", "vendor/", ".git/"
];

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svgz",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
  ".mp3", ".mp4", ".avi", ".mov", ".exe", ".dll", ".so",
  ".class", ".jar", ".pyc", ".ds_store"
]);

const LOCK_FILES = new Set([
  "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
  "poetry.lock", "Gemfile.lock", "composer.lock", "Cargo.lock"
]);

const TEST_DIR_PATTERNS = [
  "/test/", "/tests/", "/__tests__/", "/spec/", "/fixtures/", "/mocks/",
  "tests/", "test/", "__tests__/", "spec/", "fixtures/", "mocks/"
];

const STRING_PATTERN = /['"]([A-Za-z0-9+/=_\-]{20,})['"]/g;
const ASSIGNMENT_PATTERN = /(?:const|let|var)\s+(\w+)\s*=\s*['"]([A-Za-z0-9+/=_\-]{20,})['"]/g;

const ENTROPY_THRESHOLD = 4.5;
const MIN_LENGTH = 20;

function shouldIgnore(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  if (IGNORE_DIRS.some((p) => normalized.includes("/" + p) || normalized.startsWith(p))) return true;
  const ext = path.extname(filePath).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) return true;
  if (LOCK_FILES.has(path.basename(filePath))) return true;
  return false;
}

function isTestFile(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return TEST_DIR_PATTERNS.some((p) => normalized.includes(p));
}

function calculateEntropy(str) {
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] ?? 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isBenignHighEntropy(value) {
  if (/^[0-9a-f]{40,64}$/i.test(value)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-/.test(value)) return true;
  if (/^https?:\/\//.test(value)) return true;
  if (value.includes("/") || value.includes(".")) return true;
  if (/^sha(256|384|512)-[A-Za-z0-9+/=]+$/.test(value)) return true;
  if (/^[A-Za-z0-9+/=]{20,}$/.test(value) && !/[A-Z]/.test(value) && !/\d/.test(value)) return true;
  return false;
}

function getGitTrackedFiles(repoRoot) {
  try {
    const output = execSync("git ls-files", { cwd: repoRoot, encoding: "utf8", timeout: 5_000, stdio: ["pipe", "pipe", "pipe"] });
    const files = output.trim().split("\n").filter(Boolean);
    if (files.length > 0) return files;
  } catch { /* not a git repo */ }
  return walkDir(repoRoot);
}

function walkDir(dir, base = dir, results = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return results; }
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!shouldIgnore(fullPath) && entry.name !== ".git") walkDir(fullPath, base, results);
    } else if (entry.isFile()) {
      results.push(path.relative(base, fullPath));
    }
  }
  return results;
}

function lineFromIndex(content, index) {
  return content.slice(0, index).split("\n").length;
}

export function scanHighEntropy({ repoRoot = "." } = {}) {
  const findings = [];
  const files = getGitTrackedFiles(repoRoot);
  const seen = new Set();

  for (const filePath of files) {
    if (shouldIgnore(filePath)) continue;

    const fullPath = path.join(repoRoot, filePath);
    let content;
    try { content = fs.readFileSync(fullPath, "utf8"); } catch { continue; }

    const isTest = isTestFile(filePath);
    if (isTest) continue;

    let match;
    STRING_PATTERN.lastIndex = 0;
    while ((match = STRING_PATTERN.exec(content)) !== null) {
      const value = match[1];
      if (value.length < MIN_LENGTH) continue;
      if (isBenignHighEntropy(value)) continue;

      const entropy = calculateEntropy(value);
      if (entropy < ENTROPY_THRESHOLD) continue;

      const dedupKey = `entropy:${filePath}:${value.slice(0, 10)}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      const line = lineFromIndex(content, match.index);
      const masked = value.slice(0, 4) + "****" + value.slice(-2);

      findings.push({
        id: `entropy-${findings.length}`,
        title: "High Entropy String (Possible Secret)",
        severity: entropy > 5.0 ? "high" : "medium",
        confidence: entropy > 5.0 ? "high" : "medium",
        category: "secret-exposure",
        files: [filePath],
        location: { file: filePath, line, column: 1 },
        explanation: `High entropy string detected (entropy: ${entropy.toFixed(2)}). This may be an API key, token, or password.`,
        exploitScenario: masked,
        proposedFix: "Verify if this is a secret. If so, rotate immediately and move to environment variable or secrets manager.",
        source: { ruleId: "entropy-high-string", layer: "audit" },
        detectionMethod: "entropy",
        falsePositiveRisk: "high",
        remediationEffort: "low",
        complianceMapping: [],
        entropyScore: parseFloat(entropy.toFixed(2))
      });
    }
  }

  return { findings };
}
