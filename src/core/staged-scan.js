import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { scanPII } from "./pii-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";

function getStagedFiles() {
  try {
    const output = execSync("git diff --cached --name-only --diff-filter=ACMR", {
      encoding: "utf8", timeout: 5000
    });
    return output.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

const IGNORE_DIRS = [
  "node_modules/", ".venv/", "venv/", "__pycache__/",
  ".git/", "dist/", "build/", "coverage/", ".next/"
];

function shouldIgnore(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return IGNORE_DIRS.some((p) => normalized.includes("/" + p) || normalized.startsWith(p));
}

const MANIFEST_FILES = ["package.json", "requirements.txt", "go.mod", "Cargo.toml", "pyproject.toml", "uv.lock", "Gemfile"];

function isManifest(filePath) {
  return MANIFEST_FILES.includes(path.basename(filePath));
}

export async function scanStagedFiles({ scanners = { pii: true, dependencies: true } } = {}) {
  const stagedFiles = getStagedFiles();
  const findings = [];

  if (!stagedFiles.length) return findings;

  const stagedSet = new Set(stagedFiles);
  const hasManifestChanges = stagedFiles.some((f) => isManifest(f) && !shouldIgnore(f));

  if (scanners.pii) {
    const piiResult = scanPII({ repoRoot: ".", ignorePatterns: [] });
    for (const finding of piiResult.findings) {
      if (finding.files?.some((f) => stagedSet.has(f) && !shouldIgnore(f))) {
        findings.push(finding);
      }
    }
  }

  if (scanners.dependencies && hasManifestChanges) {
    try {
      const depResult = await scanDependencies({ repoRoot: "." });
      for (const finding of depResult.findings) {
        if (finding.severity === "critical" || finding.severity === "high") {
          findings.push(finding);
        }
      }
    } catch {
      // dependency scan failed, skip silently in hook context
    }
  }

  return findings;
}
