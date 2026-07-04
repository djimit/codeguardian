import { test } from "node:test";
import { strict as assert } from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execSync } from "node:child_process";
import { createFixBranch, commitFixes } from "../src/core/auto-pr.js";

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "cg-pr-"));
}

function initGitRepo(tmpDir) {
  try {
    execSync("git init", { cwd: tmpDir, encoding: "utf8", timeout: 5000, stdio: "pipe" });
    execSync("git config user.email 'test@test.com'", { cwd: tmpDir, encoding: "utf8", timeout: 5000, stdio: "pipe" });
    execSync("git config user.name 'Test'", { cwd: tmpDir, encoding: "utf8", timeout: 5000, stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

test("createFixBranch creates a git branch", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, "test.txt"), "hello\n");

  if (!initGitRepo(tmpDir)) return; // skip if git not available
  execSync("git add .", { cwd: tmpDir, encoding: "utf8", timeout: 5000, stdio: "pipe" });
  execSync('git commit -m "init"', { cwd: tmpDir, encoding: "utf8", timeout: 5000, stdio: "pipe" });

  const branch = createFixBranch({ repoRoot: tmpDir });
  assert.ok(branch, "Should create a branch");
  assert.ok(branch.startsWith("codeguardian/fix-"), "Branch should have prefix");
});

test("commitFixes commits package file changes", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, "package.json"), '{"dependencies": {"ws": "5.2.3"}}\n');

  if (!initGitRepo(tmpDir)) return;
  execSync("git add .", { cwd: tmpDir, encoding: "utf8", timeout: 5000, stdio: "pipe" });
  execSync('git commit -m "init"', { cwd: tmpDir, encoding: "utf8", timeout: 5000, stdio: "pipe" });

  // Simulate a fix being applied (change version)
  fs.writeFileSync(path.join(tmpDir, "package.json"), '{"dependencies": {"ws": "5.2.5"}}\n');

  const fixes = [{
    file: "package.json",
    packageName: "ws",
    from: "5.2.3",
    to: "5.2.5",
    patches: [{ old: '"ws": "5.2.3"', new: '"ws": "5.2.5"', file: "package.json" }]
  }];

  const result = commitFixes({ repoRoot: tmpDir, fixes });
  assert.equal(result, true, "Should commit successfully");
});

test("commitFixes treats package names as commit message data", () => {
  const tmpDir = makeTmpDir();
  fs.writeFileSync(path.join(tmpDir, "package.json"), '{"dependencies": {"ws": "5.2.3"}}\n');

  if (!initGitRepo(tmpDir)) return;
  execSync("git add .", { cwd: tmpDir, encoding: "utf8", timeout: 5000, stdio: "pipe" });
  execSync('git commit -m "init"', { cwd: tmpDir, encoding: "utf8", timeout: 5000, stdio: "pipe" });
  fs.writeFileSync(path.join(tmpDir, "package.json"), '{"dependencies": {"ws": "5.2.5"}}\n');

  const marker = path.join(tmpDir, "pwned");
  const fixes = [{
    file: "package.json",
    packageName: `ws"; touch ${marker}; echo "`,
    from: "5.2.3",
    to: "5.2.5",
    patches: [{ old: '"ws": "5.2.3"', new: '"ws": "5.2.5"', file: "package.json" }]
  }];

  const result = commitFixes({ repoRoot: tmpDir, fixes });
  assert.equal(result, true, "Should commit successfully");
  assert.equal(fs.existsSync(marker), false, "Package name must not execute as shell");
});
