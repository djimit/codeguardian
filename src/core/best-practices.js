import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const IGNORE_DIRS = [
  "node_modules/", ".venv/", "venv/", "__pycache__/",
  ".git/", "dist/", "build/", "coverage/", ".next/", "vendor/"
];

const RULES = [
  {
    id: "tls-reject-unauthorized",
    title: "SSL/TLS Verification Disabled",
    severity: "high",
    category: "security-bypass",
    patterns: [
      /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0['"]?/,
      /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]/,
      /rejectUnauthorized\s*:\s*false/,
      /strictSSL\s*:\s*false/,
      /secure\s*:\s*false/,
      /NODE_ENV\s*=\s*['"]development['"]\s*#.*(?:prod|production)/i
    ],
    explanation: "Disabling SSL/TLS verification allows man-in-the-middle attacks. This should never be used in production.",
    proposedFix: "Remove the SSL bypass. Use proper certificate validation. For self-signed certs in dev, add the CA to the trust store instead."
  },
  {
    id: "debug-mode-enabled",
    title: "Debug/Development Mode Enabled",
    severity: "low",
    category: "security-bypass",
    patterns: [
      /DEBUG\s*=\s*true/,
      /DEVELOPMENT\s*=\s*true/,
      /DEBUG\s*=\s*['"]1['"]/,
      /verbose\s*:\s*true/
    ],
    explanation: "Debug mode in production can expose sensitive information through error messages and stack traces.",
    proposedFix: "Set DEBUG=false in production. Use environment-specific configuration files."
  },
  {
    id: "insecure-env-fallback",
    title: "Insecure Environment Variable Fallback",
    severity: "medium",
    category: "security-bypass",
    patterns: [
      /process\.env\.\w+\s*\|\|\s*['"][^'"]+['"]/,
      /(?:const|let|var)\s+\w+\s*=\s*process\.env\.\w+\s*\|\|\s*['"][^'"]+['"]/,
      /(?:const|let|var)\s+\w+\s*=\s*env\.\w+\s*\|\|\s*['"][^'"]+['"]/
    ],
    explanation: "Hardcoded fallback values for environment variables can lead to insecure defaults in production.",
    proposedFix: "Remove hardcoded fallbacks. Use explicit configuration validation at startup. Fail fast if required env vars are missing."
  },
  {
    id: "console-log-secrets",
    title: "Potential Secret Logging",
    severity: "medium",
    category: "infrastructure-disclosure",
    patterns: [
      /console\.(log|debug|info)\s*\(\s*['"][^'"]*(?:password|secret|token|key|credential)/i,
      /console\.(log|debug|info)\s*\(\s*`[^`]*\$\{[^}]*(?:password|secret|token|key)/i,
      /logger\.(log|debug|info)\s*\(\s*['"][^'"]*(?:password|secret|token|key)/i
    ],
    explanation: "Logging sensitive values can expose them in log aggregation systems and log files.",
    proposedFix: "Remove sensitive values from log statements. Use redaction or structured logging with field filtering."
  },
  {
    id: "eval-usage",
    title: "Dangerous eval() Usage",
    severity: "high",
    category: "security-bypass",
    patterns: [
      /\beval\s*\(/,
      /new\s+Function\s*\(/,
      /setTimeout\s*\(\s*['"]/,
      /setInterval\s*\(\s*['"]/
    ],
    explanation: "eval() and dynamic code execution can lead to code injection vulnerabilities.",
    proposedFix: "Use JSON.parse() for data parsing. Use Function constructors only with static strings. Never pass user input to eval()."
  },
  {
    id: "weak-crypto",
    title: "Weak Cryptographic Algorithm",
    severity: "medium",
    category: "security-bypass",
    patterns: [
      /createHash\s*\(\s*['"]md5['"]\s*\)/,
      /createHash\s*\(\s*['"]sha1['"]\s*\)/,
      /CryptoJS\.MD5\s*\(/,
      /CryptoJS\.SHA1\s*\(/,
      /require\s*\(\s*['"]md5['"]\s*\)/
    ],
    explanation: "MD5 and SHA-1 are cryptographically broken and should not be used for security purposes.",
    proposedFix: "Use SHA-256 or stronger. For password hashing, use bcrypt, scrypt, or argon2."
  },
  {
    id: "missing-helmet",
    title: "Security Headers Not Configured",
    severity: "medium",
    category: "security-bypass",
    patterns: [
      /app\.use\s*\(\s*express\s*\.\s*static/,
    ],
    condition: (content, filePath) => {
      if (!filePath.includes("app.") && !filePath.includes("server.") && !filePath.includes("index.")) return false;
      return !content.includes("helmet") && !content.includes("Strict-Transport-Security");
    },
    explanation: "Missing security headers (HSTS, CSP, X-Frame-Options) increases attack surface.",
    proposedFix: "Add helmet middleware: app.use(helmet()). Configure Content-Security-Policy appropriately."
  },
  {
    id: "cors-wildcard",
    title: "Permissive CORS Configuration",
    severity: "medium",
    category: "security-bypass",
    patterns: [
      /cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]\s*\)/,
      /Access-Control-Allow-Origin\s*:\s*['"]\*['"]/,
      /app\.use\s*\(\s*cors\s*\(\s*\)\s*\)/
    ],
    explanation: "Wildcard CORS allows any origin to access your API, enabling CSRF and data theft.",
    proposedFix: "Configure CORS with specific allowed origins. Use an origin whitelist."
  }
];

function shouldIgnore(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return IGNORE_DIRS.some((p) => normalized.includes("/" + p) || normalized.startsWith(p));
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

export function scanBestPractices({ repoRoot = "." } = {}) {
  const findings = [];
  const files = getGitTrackedFiles(repoRoot);
  const seen = new Set();

  for (const filePath of files) {
    if (shouldIgnore(filePath)) continue;

    const fullPath = path.join(repoRoot, filePath);
    let content;
    try { content = fs.readFileSync(fullPath, "utf8"); } catch { continue; }

    for (const rule of RULES) {
      if (rule.condition && !rule.condition(content, filePath)) continue;

      if (!rule.patterns) continue;
      for (const pattern of rule.patterns) {
        const regex = new RegExp(pattern.source, pattern.flags + "g");
        let match;
        while ((match = regex.exec(content)) !== null) {
          const dedupKey = `${rule.id}:${filePath}:${match.index}`;
          if (seen.has(dedupKey)) continue;
          seen.add(dedupKey);

          findings.push({
            id: `bp-${rule.id}-${findings.length}`,
            title: rule.title,
            severity: rule.severity,
            confidence: "medium",
            category: rule.category,
            files: [filePath],
            location: { file: filePath, line: lineFromIndex(content, match.index), column: 1 },
            explanation: rule.explanation,
            exploitScenario: match[0].slice(0, 20) + "...",
            proposedFix: rule.proposedFix,
            source: { ruleId: `best-practice-${rule.id}`, layer: "audit" },
            detectionMethod: "pattern",
            falsePositiveRisk: "medium",
            remediationEffort: "low",
            complianceMapping: []
          });
        }
      }
    }
  }

  return { findings };
}
