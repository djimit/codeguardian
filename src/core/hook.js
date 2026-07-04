import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const HOOK_SCRIPT = `#!/bin/sh
# CodeGuardian pre-commit hook
codeguardian scan --staged-only --fail-on \${CODEGUARDIAN_FAIL_ON:-critical}
`;

export function installPreCommitHook({ hookPath = null, failOn = "critical" } = {}) {
  let targetPath = hookPath;

  if (!targetPath) {
    try {
      const gitDir = execSync("git rev-parse --git-dir", {
        encoding: "utf8", cwd: process.cwd(), timeout: 5000
      }).trim();
      targetPath = path.join(gitDir, "hooks", "pre-commit");
    } catch {
      process.stderr.write("Error: not a git repository. Run this command from a git repo root.\n");
      process.exit(1);
    }
  }

  const hookDir = path.dirname(targetPath);
  fs.mkdirSync(hookDir, { recursive: true });

  let existing = "";
  try {
    existing = fs.readFileSync(targetPath, "utf8");
  } catch {
    // hook doesn't exist yet
  }

  if (existing.includes("CodeGuardian pre-commit hook")) {
    process.stdout.write(`Hook already installed at ${targetPath}\n`);
    return;
  }

  const content = existing
    ? existing + "\n" + HOOK_SCRIPT.replace("${CODEGUARDIAN_FAIL_ON:-critical}", failOn)
    : HOOK_SCRIPT.replace("${CODEGUARDIAN_FAIL_ON:-critical}", failOn);

  fs.writeFileSync(targetPath, content.trim() + "\n");
  fs.chmodSync(targetPath, 0o755);

  process.stdout.write(`CodeGuardian pre-commit hook installed at ${targetPath}\n`);
  process.stdout.write(`Fail threshold: ${failOn}\n`);
}
