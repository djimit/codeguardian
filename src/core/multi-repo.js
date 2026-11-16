import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { scanDependencies } from "./dependency-scanner.js";
import { scanPII } from "./pii-scanner.js";
import { calculateMaturity } from "./maturity.js";
import { loadConfig } from "./config.js";
import { applySuppressions } from "./suppressions.js";
import { enrichFindingsWithRisk } from "./risk-engine.js";
import { enrichFindingsWithCompliance, generateComplianceSummary } from "./compliance.js";
import { scanSupplyChain } from "./supply-chain.js";
import { scanBestPractices } from "./best-practices.js";
import { scanHighEntropy } from "./entropy.js";



function sanitizeRepoName(name) {
  if (!/^[a-zA-Z0-9._/-]+$/.test(name)) {
    throw new Error(`Invalid repository name: ${name}`);
  }
  return name;
}

async function discoverGitHubRepos(username) {
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    throw new Error(`Invalid username: ${username}`);
  }
  try {
    const output = execFileSync(
      "gh",
      ["repo", "list", username, "--limit", "1000", "--json", "nameWithOwner", "--jq", ".[].nameWithOwner"],
      { encoding: "utf8", timeout: 60_000 }
    );
    return output.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

function cloneRepo(repoFullName, tmpDir, includeHistory = false) {
  const sanitized = sanitizeRepoName(repoFullName);
  const target = path.join(tmpDir, sanitized.replace("/", "__"));
  try {
    const cloneArgs = ["clone"];
    if (!includeHistory) cloneArgs.push("--depth", "1");
    cloneArgs.push(`https://github.com/${sanitized}.git`, target);
    execFileSync("git", cloneArgs, {
      encoding: "utf8", timeout: includeHistory ? 300_000 : 120_000, stdio: "pipe"
    });
    return target;
  } catch {
    return null;
  }
}

async function runWithConcurrency(items, concurrency, fn) {
  const results = [];
  let index = 0;

  async function worker() {
    while (index < items.length) {
      const item = items[index++];
      const result = await fn(item);
      results.push(result);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

export async function scanRepositories({
  repos = [],
  username = null,
  localPaths = [],
  concurrency = 4,
  scanners = { secrets: true, dependencies: true, pii: true, history: false },
  onProgress = null
} = {}) {
  const startTime = Date.now();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "codeguardian-"));

  let allRepoPaths = localPaths.map((p) => {
    if (typeof p === "string") {
      return { name: p.split("/").pop() || p, path: path.resolve(p), source: "local" };
    }
    return p;
  });

  if (username) {
    const ghRepos = await discoverGitHubRepos(username);
    for (const repoFullName of ghRepos) {
      const localPath = cloneRepo(repoFullName, tmpDir, scanners.history);
      if (localPath) {
        allRepoPaths.push({ name: repoFullName, path: localPath, source: "github" });
      }
    }
  }

  for (const repo of repos) {
    if (repo.owner && repo.name) {
      const fullName = `${repo.owner}/${repo.name}`;
      const localPath = cloneRepo(fullName, tmpDir, scanners.history);
      if (localPath) {
        allRepoPaths.push({ name: fullName, path: localPath, source: "github" });
      }
    } else if (repo.path) {
      const repoPath = path.resolve(repo.path);
      if (fs.existsSync(repoPath)) {
        allRepoPaths.push({
          name: repo.path.split("/").pop() || repo.path,
          path: repoPath,
          source: "local"
        });
      }
    }
  }

  const results = await runWithConcurrency(allRepoPaths, concurrency, async (repoInfo) => {
    const config = loadConfig(repoInfo.path);
    const repoFindings = [];
    const repoStats = { secrets: null, dependencies: null, pii: null };

    if (scanners.dependencies) {
      try {
        const depResult = await scanDependencies({ repoRoot: repoInfo.path });
        repoFindings.push(...depResult.findings);
        repoStats.dependencies = depResult.stats;
      } catch (err) {
        repoStats.dependencies = { error: err.message };
        throw new Error(`dependency scan failed for ${repoInfo.name}: ${err.message}`);
      }
    }

    if (scanners.pii) {
      try {
        const piiResult = scanPII({ repoRoot: repoInfo.path, includeGitHistory: scanners.history });
        repoFindings.push(...piiResult.findings);
        repoStats.pii = piiResult.stats;
      } catch (err) {
        repoStats.pii = { error: err.message };
        throw new Error(`PII scan failed for ${repoInfo.name}: ${err.message}`);
      }
    }

    if (scanners.secrets) {
      try {
        const { runRepoAudit } = await import("@djimit/security-review-commons");
        const auditResult = runRepoAudit({ repoRoot: repoInfo.path });
        if (auditResult.findings) {
          repoFindings.push(...auditResult.findings);
          repoStats.secrets = auditResult.stats || { findings: auditResult.findings.length };
        }
      } catch (err) {
        repoStats.secrets = { error: err.message };
        throw new Error(`secret scan failed for ${repoInfo.name}: ${err.message}`);
      }
    }

    try {
      const bpResult = scanBestPractices({ repoRoot: repoInfo.path });
      repoFindings.push(...bpResult.findings);
    } catch { /* best-effort */ }

    try {
      const entropyResult = scanHighEntropy({ repoRoot: repoInfo.path });
      repoFindings.push(...entropyResult.findings);
    } catch { /* best-effort */ }

    try {
      const scResult = await scanSupplyChain({ repoRoot: repoInfo.path, advisories: false });
      repoFindings.push(...scResult);
    } catch { /* best-effort */ }

    const { visible, suppressed } = applySuppressions(repoFindings, config.suppressions);
    const risky = enrichFindingsWithRisk(visible, { isPublicRepo: false });
    const compliant = enrichFindingsWithCompliance(risky);
    const maturity = calculateMaturity(compliant);

    const result = {
      name: repoInfo.name,
      path: repoInfo.path,
      source: repoInfo.source,
      findings: compliant,
      suppressed,
      maturity,
      stats: repoStats,
      summary: {
        critical: compliant.filter((f) => f.severity === "critical").length,
        high: compliant.filter((f) => f.severity === "high").length,
        medium: compliant.filter((f) => f.severity === "medium").length,
        low: compliant.filter((f) => f.severity === "low").length,
        info: compliant.filter((f) => f.severity === "info").length,
        total: compliant.length,
        avgRisk: compliant.length > 0
          ? Math.round(compliant.reduce((s, f) => s + (f.riskScore ?? 0), 0) / compliant.length)
          : 0,
        maxRisk: compliant.length > 0
          ? Math.max(...compliant.map((f) => f.riskScore ?? 0))
          : 0
      }
    };

    if (onProgress) {
      onProgress(result);
    }

    return result;
  });

  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  const bySeverity = {
    critical: results.reduce((sum, r) => sum + r.summary.critical, 0),
    high: results.reduce((sum, r) => sum + r.summary.high, 0),
    medium: results.reduce((sum, r) => sum + r.summary.medium, 0),
    low: results.reduce((sum, r) => sum + r.summary.low, 0),
    info: results.reduce((sum, r) => sum + r.summary.info, 0),
    total: totalFindings
  };

  const byCategory = {};
  for (const repo of results) {
    for (const finding of repo.findings) {
      byCategory[finding.category] = (byCategory[finding.category] ?? 0) + 1;
    }
  }

  const allFindings = results.flatMap((r) => r.findings);
  const overallMaturity = calculateMaturity(allFindings);
  const complianceSummary = generateComplianceSummary(allFindings);

  const totalSuppressed = results.reduce((sum, r) => sum + (r.suppressed?.length || 0), 0);

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      break;
    } catch (err) {
      if (attempt === 2) {
        process.stderr.write(`Warning: could not clean up tmp dir ${tmpDir}: ${err.message}\n`);
      }
    }
  }

  return {
    repositories: results,
    summary: {
      totalRepositories: results.length,
      totalFindings,
      totalSuppressed,
      bySeverity,
      byCategory,
      maturity: overallMaturity,
      compliance: complianceSummary,
      avgRisk: allFindings.length > 0
        ? Math.round(allFindings.reduce((s, f) => s + (f.riskScore ?? 0), 0) / allFindings.length)
        : 0,
      maxRisk: allFindings.length > 0
        ? Math.max(...allFindings.map((f) => f.riskScore ?? 0))
        : 0
    },
    durationMs: Date.now() - startTime
  };
}
