import fs from "node:fs";
import path from "node:path";

const POPULAR_PACKAGES = [
  "lodash", "react", "express", "axios", "moment", "chalk", "debug", "request",
  "commander", "inquirer", "webpack", "babel", "jest", "mocha", "typescript",
  "eslint", "prettier", "dotenv", "cors", "helmet", "jsonwebtoken", "bcrypt",
  "mongoose", "sequelize", "redis", "socket.io", "uuid", "rimraf", "mkdirp",
  "glob", "minimatch", "semver", "yargs", "chalk", "ora", "listr", "execa",
  "cross-env", "nodemon", "pm2", "winston", "morgan", "multer", "sharp",
  "node-fetch", "got", "superagent", "cheerio", "jsdom", "handlebars", "ejs",
  "pug", "marked", "sanitize-html", "validator", "dayjs", "date-fns"
];

const WHITELIST_PATTERNS = [
  /^@types\//,
  /^@babel\//,
  /^@angular\//,
  /^@vue\//,
  /^@react-/,
  /^@testing-library\//,
  /^@nestjs\//,
  /^@aws-sdk\//,
  /^@google-cloud\//,
  /^@azure\//,
  /^@sentry\//,
  /^@storybook\//,
  /^@typescript-eslint\//,
  /^babel-/,
  /^eslint-/,
  /^jest-/,
  /^webpack-/,
  /^postcss-/,
  /^autoprefixer$/
];

function levenshtein(a, b) {
  const matrix = Array(b.length + 1).fill(null).map(() => Array(a.length + 1).fill(null));
  for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= b.length; j++) matrix[j][0] = j;
  for (let j = 1; j <= b.length; j++) {
    for (let i = 1; i <= a.length; i++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,
        matrix[j - 1][i] + 1,
        matrix[j - 1][i - 1] + cost
      );
    }
  }
  return matrix[b.length][a.length];
}

function isWhitelisted(name) {
  return WHITELIST_PATTERNS.some((p) => p.test(name));
}

function checkTyposquatting(packageName) {
  if (POPULAR_PACKAGES.includes(packageName.toLowerCase())) return null;
  if (isWhitelisted(packageName)) return null;

  for (const popular of POPULAR_PACKAGES) {
    if (packageName.length < popular.length - 2) continue;
    if (packageName.length > popular.length + 2) continue;
    const distance = levenshtein(packageName.toLowerCase(), popular.toLowerCase());
    if (distance >= 1 && distance <= 2) {
      return {
        type: "typosquatting",
        similarTo: popular,
        distance,
        severity: distance === 1 ? "high" : "medium"
      };
    }
  }
  return null;
}

function checkHeuristicSignals(packageName, manifestPath) {
  const signals = [];

  if (/-(utils|helpers|tools|lib|core|pkg|package)$/.test(packageName)) {
    const baseName = packageName.replace(/-(utils|helpers|tools|lib|core|pkg|package)$/, "");
    if (POPULAR_PACKAGES.some((p) => p.includes(baseName) || baseName.includes(p))) {
      signals.push({
        type: "suspicious-suffix",
        detail: `Package name ends with common suffix and resembles popular package`
      });
    }
  }

  return signals;
}

async function checkAdvisoryDatabase(packageName) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    const response = await fetch(
      `https://api.github.com/advisories?ecosystem=npm&affects=${packageName}`,
      {
        headers: { "Accept": "application/vnd.github+json" },
        signal: controller.signal
      }
    );
    clearTimeout(timeout);

    if (!response.ok) return [];
    const data = await response.json();

    return data
      .filter((a) => a.severity === "critical" || a.severity === "high")
      .map((a) => ({
        type: "advisory-match",
        advisoryId: a.ghsa_id,
        severity: a.severity,
        summary: a.summary,
        url: a.html_url
      }));
  } catch {
    return [];
  }
}

export async function scanSupplyChain({ repoRoot = ".", advisories = true } = {}) {
  const findings = [];
  const manifests = findManifestsSimple(repoRoot);

  for (const manifest of manifests) {
    const packages = extractPackageNames(manifest);
    for (const pkg of packages) {
      const typo = checkTyposquatting(pkg.name);
      if (typo) {
        findings.push({
          id: `supplychain-typo-${pkg.name}`,
          title: `Possible typosquat: ${pkg.name} (resembles ${typo.similarTo})`,
          severity: typo.severity,
          confidence: "medium",
          category: "supply-chain-risk",
          files: [manifest.path],
          explanation: `Package "${pkg.name}" is similar to popular package "${typo.similarTo}" (distance: ${typo.distance}). This may be a typosquatting attempt.`,
          proposedFix: `Verify this is the intended package. If not, replace with "${typo.similarTo}".`,
          source: { ruleId: "supply-chain-typosquatting", layer: "audit" },
          detectionMethod: "supply-chain",
          falsePositiveRisk: "medium",
          remediationEffort: "low",
          complianceMapping: [],
          supplyChainSignal: typo
        });
      }

      const signals = checkHeuristicSignals(pkg.name, manifest.path);
      for (const signal of signals) {
        findings.push({
          id: `supplychain-heuristic-${pkg.name}-${signal.type}`,
          title: `Suspicious package name: ${pkg.name}`,
          severity: "low",
          confidence: "low",
          category: "supply-chain-risk",
          files: [manifest.path],
          explanation: signal.detail,
          proposedFix: `Review package "${pkg.name}" and verify its legitimacy.`,
          source: { ruleId: "supply-chain-heuristic", layer: "audit" },
          detectionMethod: "supply-chain",
          falsePositiveRisk: "high",
          remediationEffort: "low",
          complianceMapping: [],
          supplyChainSignal: signal
        });
      }

      if (advisories) {
        const advisoryHits = await checkAdvisoryDatabase(pkg.name);
        for (const hit of advisoryHits) {
          findings.push({
            id: `supplychain-advisory-${pkg.name}-${hit.advisoryId}`,
            title: `Package ${pkg.name} in GitHub Advisory Database`,
            severity: hit.severity,
            confidence: "high",
            category: "supply-chain-risk",
            files: [manifest.path],
            explanation: `${hit.summary} (${hit.url})`,
            proposedFix: `Review the advisory and update or replace this package.`,
            source: { ruleId: "supply-chain-advisory", layer: "audit" },
            detectionMethod: "supply-chain",
            falsePositiveRisk: "low",
            remediationEffort: "medium",
            complianceMapping: [],
            supplyChainSignal: hit
          });
        }
      }
    }
  }

  return findings;
}

function findManifestsSimple(repoRoot) {
  const manifests = [];
  const files = ["package.json", "requirements.txt", "go.mod", "Cargo.toml", "pyproject.toml"];
  for (const file of files) {
    const fullPath = path.join(repoRoot, file);
    if (fs.existsSync(fullPath) && !fullPath.includes("/.git/")) {
      manifests.push({ path: file, fullPath });
    }
  }
  return manifests;
}

function extractPackageNames(manifest) {
  const content = fs.readFileSync(manifest.fullPath, "utf8");
  const ext = path.extname(manifest.path);
  const packages = [];

  if (ext === ".json") {
    try {
      const json = JSON.parse(content);
      const deps = { ...(json.dependencies ?? {}), ...(json.devDependencies ?? {}) };
      for (const name of Object.keys(deps)) {
        packages.push({ name, version: deps[name] });
      }
    } catch { /* skip */ }
  } else if (manifest.path === "requirements.txt") {
    for (const line of content.split("\n")) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*==/);
      if (match) packages.push({ name: match[1], version: "*" });
    }
  } else if (manifest.path === "go.mod") {
    for (const line of content.split("\n")) {
      const match = line.match(/^\s*([a-zA-Z0-9./-]+\/[a-zA-Z0-9./-]+)\s+v/);
      if (match) packages.push({ name: match[1], version: "*" });
    }
  }

  return packages;
}
