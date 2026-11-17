#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { scanRepositories } from "../src/core/multi-repo.js";
import { loadConfig } from "../src/core/config.js";
import { formatMarkdownReport, formatJsonReport, writeJsonReport } from "../src/core/report-formatter.js";
import { startDashboard } from "../src/dashboard/server.js";
import { generatePrComment, shouldBlockMerge } from "../src/core/pr-comment.js";
import { scanStagedFiles } from "../src/core/staged-scan.js";
import { installPreCommitHook } from "../src/core/hook.js";
import { recordScan } from "../src/core/history.js";
import { generateFix, applyFix, generateFixReport } from "../src/core/autofix.js";
import { getChangedFiles, saveScanState, filterFindingsByFiles } from "../src/core/changed-files.js";
import { buildInventory, saveInventory, loadInventory, findAffectedRepos } from "../src/core/inventory.js";
import { formatSarifReport } from "../src/core/sarif.js";
import { startServer } from "../src/server.js";
import { generatePrReviewComments, postPrReviewComments } from "../src/core/pr-review.js";
import { generateAllPlaybooks, playbooksToMarkdown, executeGhSecretCommand } from "../src/core/secret-rotation.js";
import { scanSupplyChain } from "../src/core/supply-chain.js";
import { runInit } from "../src/core/init.js";
import { autoFixAndPr } from "../src/core/auto-pr.js";

function printHelp() {
  const help = `
codeguardian — Multi-repo code security scanner

Usage:
  codeguardian scan [options]
  codeguardian dashboard [options]
  codeguardian pr-check [options]
  codeguardian install-hook [options]
  codeguardian fix [options]
  codeguardian inventory [options]
  codeguardian pr-review [options]
  codeguardian rotation [options]
  codeguardian init [options]
  codeguardian auto-pr [options]
  codeguardian server [options]

Scan options:
  --repos <patterns>     Comma-separated GitHub repo patterns (e.g., "djimit/*")
  --username <name>      GitHub username/org to auto-discover repos
  --path <paths>         Comma-separated local paths to scan
  --output <path>        Write JSON report to file (for dashboard)
  --scanners <list>      Comma-separated: secrets,dependencies,pii (default: all)
  --concurrency <n>      Max parallel scans (default: 4)
  --format <fmt>         Output: markdown, json (default: markdown)
  --fail-on <severity>   Exit 1 if finding at or above severity (default: critical)
  --staged-only          Scan only staged files (for pre-commit hook)
  --help, -h             Show this help

Hook Options:
  --hook-path <path>     Custom hook path (default: .git/hooks/pre-commit)

Examples:
  codeguardian scan --username djimit
  codeguardian scan --path ./my-project,./another-project
  codeguardian scan --repos djimit/security-review-commons,djimit/djimitflo
  codeguardian install-hook
`;
  process.stdout.write(help);
}

function parseArgs(argv) {
  const args = {
    format: "markdown",
    scanners: { secrets: true, dependencies: true, pii: true, history: false },
    concurrency: 4,
    failOn: "critical",
    repos: [],
    paths: [],
    username: null,
    output: null,
    dashboard: false,
    port: 3000,
    baseline: null,
    prCheck: false,
    stagedOnly: false,
    hookPath: null,
    apply: false,
    incremental: false,
    since: null,
    prNumber: null,
    post: false,
    rotationType: null,
    execute: false,
    autoPr: false
  };

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    const next = argv[i + 1];

    if (token === "--help" || token === "-h") {
      printHelp();
      process.exit(0);
    } else if (token === "--repos") {
      args.repos = next.split(",").map((s) => s.trim()).filter(Boolean);
      i++;
    } else if (token === "--username") {
      args.username = next;
      i++;
    } else if (token === "--path") {
      args.paths = next.split(",").map((s) => s.trim()).filter(Boolean);
      i++;
    } else if (token === "--scanners") {
      const enabled = next.split(",").map((s) => s.trim());
      args.scanners = {
        secrets: enabled.includes("secrets"),
        dependencies: enabled.includes("dependencies"),
        pii: enabled.includes("pii"),
        history: enabled.includes("history")
      };
      i++;
    } else if (token === "--concurrency") {
      args.concurrency = parseInt(next, 10);
      i++;
    } else if (token === "--format") {
      args.format = next;
      i++;
    } else if (token === "--fail-on") {
      args.failOn = next;
      i++;
    } else if (token === "--output") {
      args.output = next;
      i++;
    } else if (token === "--port") {
      args.port = parseInt(next, 10);
      i++;
    } else if (token === "dashboard") {
      args.dashboard = true;
    } else if (token === "--baseline") {
      args.baseline = next;
      i++;
    } else if (token === "pr-check") {
      args.prCheck = true;
    } else if (token === "--staged-only") {
      args.stagedOnly = true;
    } else if (token === "--hook-path") {
      args.hookPath = next;
      i++;
    } else if (token === "--apply") {
      args.apply = true;
    } else if (token === "--pr") {
      args.prNumber = parseInt(next, 10);
      i++;
    } else if (token === "--post") {
      args.post = true;
    } else if (token === "--type") {
      args.rotationType = next;
      i++;
    } else if (token === "--execute") {
      args.execute = true;
    } else if (token === "--auto-pr") {
      args.autoPr = true;
    } else if (token === "--incremental") {
      args.incremental = true;
    } else if (token === "--since") {
      args.since = next;
      i++;
    }
  }

  return args;
}

function getOwnerRepo() {
  try {
    const url = execSync("git remote get-url origin", {
      encoding: "utf8", timeout: 5000
    }).trim();
    const match = url.match(/github\.com[:/]([^/]+)\/([^/.]+)/);
    if (match) return { owner: match[1], repo: match[2] };
  } catch { /* fallback */ }
  return { owner: "unknown", repo: "unknown" };
}

function shouldFail(findings, failOn) {
  const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const threshold = order[failOn] ?? 4;
  return findings.some((f) => (order[f.severity] ?? 0) >= threshold);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (process.argv[2] === "install-hook") {
    installPreCommitHook({ hookPath: args.hookPath, failOn: args.failOn });
    return;
  }

  if (process.argv[2] === "fix") {
    if (!args.output || !fs.existsSync(args.output)) {
      process.stderr.write("Error: fix requires --output <report.json> from a previous scan\n");
      process.exit(1);
    }
    const report = JSON.parse(fs.readFileSync(args.output, "utf8"));
    const fixes = [];
    for (const repo of report.repositories) {
      for (const finding of repo.findings) {
        const fix = generateFix(finding, repo.path);
        if (fix) fixes.push(fix);
      }
    }
    process.stdout.write(generateFixReport(fixes) + "\n");
    if (args.apply) {
      let applied = 0;
      for (const fix of fixes.filter((f) => f.safe)) {
        const repo = report.repositories.find((r) =>
          r.findings.some((f) => f.id === fix.findingId)
        );
        if (repo && applyFix(fix, repo.path)) applied++;
      }
      process.stdout.write(`\n${applied} fix(es) toegepast.\n`);
    }
    return;
  }

  if (process.argv[2] === "inventory") {
    if (args.output && fs.existsSync(args.output)) {
      const report = JSON.parse(fs.readFileSync(args.output, "utf8"));
      const inventory = buildInventory(".", report);
      saveInventory(".", inventory);
      process.stdout.write(`Inventory saved to .codeguardian-inventory.json (${Object.keys(inventory.repositories).length} repos)\n`);
    } else {
      const inventory = loadInventory(".");
      if (!inventory) {
        process.stderr.write("Error: no inventory found. Run scan first, then 'codeguardian inventory --output report.json'\n");
        process.exit(1);
      }
      const repos = Object.keys(inventory.repositories);
      process.stdout.write(`Asset Inventory (${repos.length} repos, last updated: ${inventory.lastUpdated})\n\n`);
      for (const [name, repo] of Object.entries(inventory.repositories)) {
        process.stdout.write(`${name}\n`);
        process.stdout.write(`  Maturity: ${repo.maturity?.overall ?? "-"}/5\n`);
        process.stdout.write(`  Dependencies: ${repo.dependencies?.length ?? 0}\n`);
        process.stdout.write(`  Secret types: ${repo.secrets?.length ?? 0}\n`);
        process.stdout.write(`  PII types: ${repo.pii?.length ?? 0}\n`);
        process.stdout.write(`  Total findings: ${repo.totalFindings}\n\n`);
      }
    }
    return;
  }

  if (process.argv[2] === "pr-review") {
    if (!args.output || !fs.existsSync(args.output)) {
      process.stderr.write("Error: pr-review requires --output <report.json>\n");
      process.exit(1);
    }
    if (!args.prNumber) {
      process.stderr.write("Error: pr-review requires --pr <number>\n");
      process.exit(1);
    }
    const report = JSON.parse(fs.readFileSync(args.output, "utf8"));
    const ownerRepo = getOwnerRepo();
    const comments = generatePrReviewComments({
      report,
      owner: ownerRepo.owner,
      repo: ownerRepo.repo,
      prNumber: args.prNumber
    });
    if (comments.length === 0) {
      process.stdout.write("Geen nieuwe bevindingen in deze PR.\n");
      return;
    }
    if (args.post) {
      const result = postPrReviewComments(ownerRepo.owner, ownerRepo.repo, args.prNumber, comments);
      process.stdout.write(`${result.posted} comment(s) gepost op PR #${args.prNumber}\n`);
    } else {
      process.stdout.write(`Dry-run: ${comments.length} comment(s) klaar om te posten:\n\n`);
      for (const c of comments) {
        process.stdout.write(`  ${c.path}:${c.line} — ${c.body.split("\n")[0]}\n`);
      }
    }
    return;
  }

  if (process.argv[2] === "rotation") {
    if (!args.output || !fs.existsSync(args.output)) {
      process.stderr.write("Error: rotation requires --output <report.json>\n");
      process.exit(1);
    }
    const report = JSON.parse(fs.readFileSync(args.output, "utf8"));
    const allFindings = report.repositories.flatMap((r) => r.findings);
    let playbooks = generateAllPlaybooks(allFindings);
    if (args.rotationType) {
      playbooks = playbooks.filter((p) => p.type === args.rotationType);
    }
    process.stdout.write(playbooksToMarkdown(playbooks));
    if (args.execute) {
      for (const pb of playbooks) {
        for (const cmd of pb.ghCommands) {
          const result = executeGhSecretCommand(cmd);
          process.stdout.write(result.success ? `  ✓ ${cmd}\n` : `  ✗ ${cmd}: ${result.error}\n`);
        }
      }
    }
    return;
  }

  if (process.argv[2] === "init") {
    runInit({ cwd: args.paths[0] || ".", interactive: true });
    return;
  }

  if (process.argv[2] === "auto-pr") {
    if (!args.output || !fs.existsSync(args.output)) {
      process.stderr.write("Error: auto-pr requires --output <report.json>\n");
      process.exit(1);
    }
    const result = autoFixAndPr({
      reportPath: args.output,
      repoRoot: args.paths[0] || ".",
      createPr: args.autoPr
    });
    if (result.success) {
      process.stdout.write(`✅ ${result.fixes || 0} fix(es) toegepast\n`);
      if (result.pr?.url) process.stdout.write(`PR: ${result.pr.url}\n`);
    } else {
      process.stderr.write(`Error: ${result.error || result.message}\n`);
    }
    return;
  }

  if (process.argv[2] === "server") {
    startServer({ port: args.port });
    return;
  }

  if (args.dashboard) {
    startDashboard({ port: args.port, reportPath: args.output });
    return;
  }

  if (args.prCheck) {
    const reportPath = args.output;
    if (!reportPath || !fs.existsSync(reportPath)) {
      process.stderr.write("Error: pr-check requires --output <report.json>\n");
      process.exit(1);
    }
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    const comment = generatePrComment({ currentReport: report, baselinePath: args.baseline });
    process.stdout.write(comment + "\n");
    if (shouldBlockMerge(report, args.baseline, args.failOn)) {
      process.exitCode = 1;
    }
    return;
  }

  if (args.stagedOnly) {
    const findings = await scanStagedFiles({ scanners: args.scanners });
    if (findings.length > 0) {
      process.stdout.write(`\nCodeGuardian: ${findings.length} findings in staged files:\n`);
      for (const f of findings) {
        const loc = f.location ? `${f.files[0]}:${f.location.line}` : f.files[0];
        process.stdout.write(`  [${f.severity.toUpperCase()}] ${loc}: ${f.title}\n`);
      }
      if (shouldFail(findings, args.failOn)) {
        process.exitCode = 1;
      }
    }
    return;
  }

  if (!args.username && args.repos.length === 0 && args.paths.length === 0) {
    process.stderr.write("Error: provide --username, --repos, or --path\n");
    printHelp();
    process.exit(1);
  }

  const repos = [];
  for (const pattern of args.repos) {
    if (pattern.includes("/")) {
      const [owner, name] = pattern.split("/");
      repos.push({ owner, name });
    }
  }

  process.stderr.write(`Scanning with concurrency ${args.concurrency}...\n`);

  let incrementalInfo = null;
  if (args.incremental && args.paths.length > 0) {
    const changed = getChangedFiles(args.paths[0], args.since);
    if (changed && changed.files.length > 0) {
      incrementalInfo = changed;
      process.stderr.write(`Incremental scan: ${changed.files.length} changed files since ${changed.baselineSha.slice(0, 8)}\n`);
    } else if (changed) {
      process.stderr.write("No changed files since last scan.\n");
      return;
    }
  }

  const result = await scanRepositories({
    repos,
    username: args.username,
    localPaths: args.paths,
    concurrency: args.concurrency,
    scanners: args.scanners,
    onProgress: (repo) => {
      process.stderr.write(`  ${repo.name}: ${repo.summary.total} findings (maturity: ${repo.maturity.overall}/5)\n`);
    }
  });

  if (incrementalInfo) {
    for (const repo of result.repositories) {
      repo.findings = filterFindingsByFiles(repo.findings, incrementalInfo.files);
      repo.summary.total = repo.findings.length;
    }
    result.summary.totalFindings = result.repositories.reduce((s, r) => s + r.summary.total, 0);
  }

  if (args.paths.length > 0) {
    saveScanState(args.paths[0]);
  }

  if (args.output) {
    if (args.format === "sarif") {
      fs.writeFileSync(args.output, JSON.stringify(formatSarifReport(result), null, 2));
    } else {
      writeJsonReport(args.output, result);
    }
    process.stderr.write(`Report written to ${args.output}\n`);
  }

  if (args.format === "sarif" && !args.output) {
    process.stdout.write(JSON.stringify(formatSarifReport(result), null, 2) + "\n");
  } else if (args.format === "json" && !args.output) {
    process.stdout.write(formatJsonReport(result) + "\n");
  } else if (!args.output || args.format === "markdown") {
    let baseline = null;
    if (args.baseline && fs.existsSync(args.baseline)) {
      try { baseline = JSON.parse(fs.readFileSync(args.baseline, "utf8")).repositories; } catch {}
    }
    process.stdout.write(formatMarkdownReport({
      repositories: result.repositories,
      summary: result.summary,
      username: args.username,
      baseline
    }));
  }

  const config = loadConfig(args.paths[0] || ".");
  if (config.history?.enabled) {
    try {
      recordScan(args.paths[0] || ".", result);
    } catch (err) {
      process.stderr.write(`Warning: history not written: ${err.message}\n`);
    }
  }

  const allFindings = result.repositories.flatMap((r) => r.findings);
  if (shouldFail(allFindings, args.failOn)) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(2);
});
