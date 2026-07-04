import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const STATE_FILE = ".codeguardian-state.json";

export function getChangedFiles(repoRoot = ".", sinceRef = null) {
  const statePath = path.join(repoRoot, STATE_FILE);

  let baselineSha = sinceRef;
  if (!baselineSha) {
    try {
      const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
      baselineSha = state.lastScanSha;
    } catch {
      baselineSha = null;
    }
  }

  if (!baselineSha) {
    return null;
  }

  try {
    const currentSha = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot, encoding: "utf8", timeout: 5000
    }).trim();

    const output = execFileSync("git", ["diff", "--name-only", `${baselineSha}..${currentSha}`], {
      cwd: repoRoot, encoding: "utf8", timeout: 10000
    });

    const files = output.trim().split("\n").filter(Boolean);
    return { files, currentSha, baselineSha };
  } catch {
    return null;
  }
}

export function saveScanState(repoRoot = ".", sha = null) {
  const statePath = path.join(repoRoot, STATE_FILE);
  const stateSha = sha || getHeadSha(repoRoot);
  if (!stateSha) return;

  const state = {
    lastScanSha: stateSha,
    lastScanDate: new Date().toISOString()
  };

  try {
    fs.writeFileSync(statePath, JSON.stringify(state, null, 2));
  } catch {
    // best-effort
  }
}

function getHeadSha(repoRoot) {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot, encoding: "utf8", timeout: 5000
    }).trim();
  } catch {
    return null;
  }
}

export function filterFindingsByFiles(findings, changedFiles) {
  const changedSet = new Set(changedFiles);
  return findings.filter((f) => f.files?.some((file) => changedSet.has(file)));
}

export function getChangedPackages(repoRoot = ".", changedFiles = []) {
  const manifestFiles = ["package.json", "requirements.txt", "go.mod", "Cargo.toml", "pyproject.toml", "uv.lock"];
  const changed = changedFiles.filter((f) => manifestFiles.includes(path.basename(f)));
  return changed;
}
