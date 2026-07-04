import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const CONFIG_TEMPLATE = `# CodeGuardian Configuratie
# Gegenereerd door codeguardian init

# Fail threshold voor pre-commit en CI
fail_on: {fail_on}

# Scanners
scanners:
  secrets: {secrets}
  dependencies: {dependencies}
  pii: {pii}

# Suppressions
suppressions:
{suppressions}

# History tracking
history:
  enabled: {history_enabled}
  retention_days: {retention_days}
`;

const PRE_COMMIT_HOOK = `#!/bin/sh
# CodeGuardian pre-commit hook
codeguardian scan --staged-only --fail-on \${CODEGUARDIAN_FAIL_ON:-critical}
`;

function ask(question, defaultValue) {
  process.stdout.write(`${question} [${defaultValue}]: `);
  const answer = readlineSync();
  return answer.trim() || defaultValue;
}

function readlineSync() {
  const BUFSIZE = 256;
  const buf = Buffer.alloc(BUFSIZE);
  let bytesRead = 0;
  try {
    bytesRead = fs.readSync(0, buf, 0, BUFSIZE, null);
  } catch { return ""; }
  return buf.toString("utf8", 0, bytesRead).replace(/\n$/, "");
}

export function runInit({ cwd = ".", interactive = true, yes = false } = {}) {
  const configPath = path.join(cwd, ".codeguardian.yml");

  if (fs.existsSync(configPath)) {
    process.stdout.write(`.codeguardian.yml bestaat al. Overschrijven? (y/N): `);
    const answer = readlineSync();
    if (answer.toLowerCase() !== "y") {
      process.stdout.write("Geannuleerd.\n");
      return;
    }
  }

  let config = {
    fail_on: "critical",
    secrets: true,
    dependencies: true,
    pii: true,
    suppressions: [],
    history_enabled: true,
    retention_days: 90,
    install_hook: true
  };

  if (interactive && !yes && process.stdin.isTTY) {
    process.stdout.write("\n🛡️  CodeGuardian Setup Wizard\n");
    process.stdout.write("================================\n\n");

    config.fail_on = ask("Fail threshold (critical/high/medium/low)", "critical");
    config.secrets = ask("Secret scanning? (y/n)", "y").toLowerCase() === "y";
    config.dependencies = ask("Dependency CVE scanning? (y/n)", "y").toLowerCase() === "y";
    config.pii = ask("PII scanning? (y/n)", "y").toLowerCase() === "y";
    config.history_enabled = ask("History tracking? (y/n)", "y").toLowerCase() === "y";
    config.retention_days = parseInt(ask("History retention (days)", "90"), 10);
    config.install_hook = ask("Install pre-commit hook? (y/n)", "y").toLowerCase() === "y";

    process.stdout.write("\nWil je suppressions toevoegen? (y/n): ");
    if (readlineSync().toLowerCase() === "y") {
      config.suppressions = collectSuppressions();
    }
  }

  const yamlContent = CONFIG_TEMPLATE
    .replace("{fail_on}", config.fail_on)
    .replace("{secrets}", config.secrets)
    .replace("{dependencies}", config.dependencies)
    .replace("{pii}", config.pii)
    .replace("{history_enabled}", config.history_enabled)
    .replace("{retention_days}", config.retention_days)
    .replace("{suppressions}", formatSuppressions(config.suppressions));

  fs.writeFileSync(configPath, yamlContent);
  process.stdout.write(`\n✅ .codeguardian.yml aangemaakt\n`);

  if (config.install_hook) {
    installHook(cwd);
  }

  process.stdout.write("\n📋 Volgende stappen:\n");
  process.stdout.write("  1. Test: codeguardian scan --path .\n");
  process.stdout.write("  2. Dashboard: codeguardian scan --path . --output report.json && codeguardian dashboard --output report.json\n");
  process.stdout.write("  3. Auto-fix: codeguardian fix --output report.json --apply\n");
  process.stdout.write("  4. PR review: codeguardian pr-review --output report.json --pr <number> --post\n");
}

function collectSuppressions() {
  const suppressions = [];
  while (true) {
    process.stdout.write("\n  Suppression toevoegen? (leeg = stop): ");
    const ruleId = readlineSync();
    if (!ruleId) break;

    process.stdout.write("  Path pattern (* = alle): ");
    const pattern = readlineSync() || "*";

    process.stdout.write("  Reden: ");
    const reason = readlineRead();

    process.stdout.write("  Vervaldatum (YYYY-MM-DD, leeg = nooit): ");
    const expires = readlineRead();

    suppressions.push({ rule_id: ruleId, path: pattern, reason, ...(expires && { expires }) });
  }
  return suppressions;
}

function readlineRead() {
  return readlineSync();
}

function formatSuppressions(suppressions) {
  if (suppressions.length === 0) return "  # - rule_id: pii-bsn\n  #   path: \"**/tests/**\"\n  #   reason: Test data";

  return suppressions.map((s) => {
    let lines = `  - rule_id: ${s.rule_id}\n    path: "${s.path}"\n    reason: ${s.reason}`;
    if (s.expires) lines += `\n    expires: ${s.expires}`;
    return lines;
  }).join("\n");
}

function installHook(cwd) {
  try {
    const gitDir = execSync("git rev-parse --git-dir", {
      cwd, encoding: "utf8", timeout: 5000
    }).trim();
    const hookPath = path.join(gitDir, "hooks", "pre-commit");
    const hookDir = path.dirname(hookPath);
    fs.mkdirSync(hookDir, { recursive: true });

    let existing = "";
    try { existing = fs.readFileSync(hookPath, "utf8"); } catch { /* new */ }

    if (existing.includes("CodeGuardian")) {
      process.stdout.write("⚠️  Pre-commit hook bestaat al\n");
      return;
    }

    const content = existing ? existing + "\n" + PRE_COMMIT_HOOK : PRE_COMMIT_HOOK;
    fs.writeFileSync(hookPath, content.trim() + "\n");
    fs.chmodSync(hookPath, 0o755);
    process.stdout.write("✅ Pre-commit hook geïnstalleerd\n");
  } catch {
    process.stderr.write("⚠️  Kon hook niet installeren (geen git repo)\n");
  }
}
