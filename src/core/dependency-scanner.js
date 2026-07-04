import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import crypto from "node:crypto";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const BATCH_SIZE = 10;
const BATCH_DELAY_MS = 100;
const REQUEST_TIMEOUT_MS = 30_000;

const SEVERITY_MAP = {
  CRITICAL: "critical",
  HIGH: "high",
  MODERATE: "medium",
  MEDIUM: "medium",
  LOW: "low"
};

const MANIFEST_FILES = [
  { file: "package.json", ecosystem: "npm", parser: parsePackageJson },
  { file: "requirements.txt", ecosystem: "PyPI", parser: parseRequirementsTxt },
  { file: "go.mod", ecosystem: "Go", parser: parseGoMod },
  { file: "Cargo.toml", ecosystem: "crates.io", parser: parseCargoToml },
  { file: "pom.xml", ecosystem: "Maven", parser: parsePomXml },
  { file: "Gemfile", ecosystem: "RubyGems", parser: parseGemfile },
  { file: "uv.lock", ecosystem: "PyPI", parser: parseUvLock }
];

const IGNORE_DIRS = [
  "node_modules/", ".venv/", "venv/", "__pycache__/",
  ".git/", "dist/", "build/", "coverage/", ".next/",
  "vendor/", "target/", "out/"
];

function shouldIgnoreDir(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return IGNORE_DIRS.some((p) => normalized.includes("/" + p) || normalized.startsWith(p));
}

function findManifests(repoRoot) {
  const manifests = [];
  try {
    const output = execSync("git ls-files", {
      cwd: repoRoot, encoding: "utf8", timeout: 30_000
    });
    for (const line of output.trim().split("\n")) {
      if (!line) continue;
      const basename = path.basename(line);
      const match = MANIFEST_FILES.find((m) => m.file === basename);
      if (match && !shouldIgnoreDir(line)) {
        manifests.push({ path: line, ecosystem: match.ecosystem, parser: match.parser });
      }
    }
  } catch {
    for (const { file, ecosystem, parser } of MANIFEST_FILES) {
      const fullPath = path.join(repoRoot, file);
      if (fs.existsSync(fullPath)) {
        manifests.push({ path: file, ecosystem, parser });
      }
    }
  }
  return manifests;
}

function parsePackageJson(content) {
  try {
    const json = JSON.parse(content);
    const deps = { ...(json.dependencies ?? {}), ...(json.devDependencies ?? {}) };
    return Object.entries(deps).map(([name, version]) => ({
      name, version: String(version).replace(/[\^~>=<>=<\s]/g, "").split(" ")[0] || ""
    }));
  } catch {
    return [];
  }
}

function parseRequirementsTxt(content) {
  const packages = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*==\s*([^\s;]+)/);
    if (match) packages.push({ name: match[1], version: match[2] });
  }
  return packages;
}

function parseGoMod(content) {
  const packages = [];
  for (const line of content.split("\n")) {
    const match = line.match(/^\s*([a-zA-Z0-9./-]+\/[a-zA-Z0-9./-]+)\s+v(\d+\.\d+\.\d+)/);
    if (match) packages.push({ name: match[1], version: match[2] });
  }
  return packages;
}

function parseCargoToml(content) {
  const packages = [];
  let inDeps = false;
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "[dependencies]") { inDeps = true; continue; }
    if (trimmed.startsWith("[") && trimmed !== "[dependencies]") { inDeps = false; continue; }
    if (inDeps) {
      const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
      if (match) packages.push({ name: match[1], version: match[2] });
    }
  }
  return packages;
}

function parsePomXml(content) {
  const packages = [];
  const dependencyPattern = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>[\s\S]*?<\/dependency>/g;
  let depMatch;
  while ((depMatch = dependencyPattern.exec(content)) !== null) {
    packages.push({ name: `${depMatch[1]}:${depMatch[2]}`, version: depMatch[3] });
  }
  return packages;
}

function parseGemfile(content) {
  const packages = [];
  for (const line of content.split("\n")) {
    const match = line.match(/^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/);
    if (match) packages.push({ name: match[1], version: match[2] || "*" });
  }
  return packages;
}

function parseUvLock(content) {
  const packages = [];
  let currentPkg = null;
  for (const line of content.split("\n")) {
    const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/);
    if (nameMatch) { currentPkg = { name: nameMatch[1], version: null }; continue; }
    const versionMatch = line.match(/^version\s*=\s*"([^"]+)"/);
    if (versionMatch && currentPkg) {
      currentPkg.version = versionMatch[1];
      packages.push(currentPkg);
      currentPkg = null;
    }
  }
  return packages;
}

async function queryOsvBatch(batch, batchIndex) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: batch }),
      signal: controller.signal
    });
    if (!response.ok) {
      process.stderr.write(`Warning: OSV batch ${batchIndex} returned ${response.status}\n`);
      return null;
    }
    return await response.json();
  } catch (err) {
    process.stderr.write(`Warning: OSV batch ${batchIndex} failed: ${err.message}\n`);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function scanDependencies({ repoRoot = "." } = {}) {
  const startTime = Date.now();
  const findings = [];
  const stats = {
    manifestsFound: 0,
    packagesScanned: 0,
    batchesSent: 0,
    cvesFound: 0,
    durationMs: 0
  };

  const manifests = findManifests(repoRoot);
  stats.manifestsFound = manifests.length;

  const allPackages = [];
  for (const manifest of manifests) {
    const fullPath = path.join(repoRoot, manifest.path);
    let content;
    try { content = fs.readFileSync(fullPath, "utf8"); } catch { continue; }
    const packages = manifest.parser(content);
    for (const pkg of packages) {
      if (pkg.version && pkg.version !== "*" && pkg.version !== "") {
        allPackages.push({ ...pkg, manifestPath: manifest.path, ecosystem: manifest.ecosystem });
      }
    }
  }

  stats.packagesScanned = allPackages.length;

  for (let i = 0; i < allPackages.length; i += BATCH_SIZE) {
    const batch = allPackages.slice(i, i + BATCH_SIZE).map((pkg) => ({
      package: { name: pkg.name, ecosystem: pkg.ecosystem },
      version: pkg.version
    }));

    const result = await queryOsvBatch(batch, stats.batchesSent);
    stats.batchesSent++;

    if (result?.results) {
      for (let j = 0; j < result.results.length; j++) {
        const vulns = result.results[j]?.vulns;
        if (!vulns) continue;
        const pkg = allPackages[i + j];
        for (const vuln of vulns) {
          const severity = SEVERITY_MAP[vuln.severity?.[0]?.score?.baseSeverity] ?? "medium";
          const fixVersion = vuln.affected?.[0]?.ranges?.[0]?.events?.find((e) => e.fixed)?.fixed ?? "latest";
          const idSource = [vuln.id, "dependency-cve", pkg.manifestPath, "audit"].join("|");
          findings.push({
            id: crypto.createHash("sha256").update(idSource).digest("hex").slice(0, 16),
            title: `${vuln.id}: ${vuln.summary ?? "Known vulnerability"}`,
            severity,
            confidence: "high",
            category: "dependency-cve",
            files: [pkg.manifestPath],
            explanation: `${vuln.detail ?? "No description available."} Affected: ${pkg.name}@${pkg.version}.`,
            exploitScenario: pkg.name,
            proposedFix: `Update ${pkg.name} to version ${fixVersion}`,
            source: { ruleId: `dependency-cve-${vuln.id}`, layer: "audit" },
            detectionMethod: "osv-api",
            falsePositiveRisk: "low",
            remediationEffort: severity === "critical" ? "high" : "medium",
            complianceMapping: [],
            publishedDate: vuln.published || null,
            exploitAvailable: vuln.database_specific?.cisa_known_exploited || false
          });
          stats.cvesFound++;
        }
      }
    }

    if (i + BATCH_SIZE < allPackages.length) {
      await sleep(BATCH_DELAY_MS);
    }
  }

  stats.durationMs = Date.now() - startTime;
  return { findings, stats };
}
