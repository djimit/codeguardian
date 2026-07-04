import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PLAYBOOKS = {
  "api-key": {
    label: "API Key",
    detect: (title) => /api.?key|token|bearer|secret.?key/i.test(title),
    steps: (finding) => {
      const secretName = generateSecretName(finding.title);
      return [
        `## Rotation Playbook: API Key`,
        ``,
        `**Detected**: ${finding.title}`,
        `**Location**: ${finding.files?.[0]}:${finding.location?.line ?? "?"}`,
        ``,
        `### Stappen:`,
        ``,
        `1. **Revoke oude key** in provider dashboard`,
        `2. **Genereer nieuwe key** in provider dashboard`,
        `3. **Store als GitHub Secret**:`,
        `   \`\`\`bash`,
        `   gh secret set ${secretName} --body "$NEW_KEY"`,
        `   \`\`\``,
        `4. **Update code** om env var te gebruiken:`,
        `   \`\`\`js`,
        `   // Verwijder: const apiKey = "hardcoded-value"`,
        `   // Vervang door:`,
        `   const apiKey = process.env.${secretName};`,
        `   \`\`\``,
        `5. **Verifieer** dat de applicatie werkt met de nieuwe key`,
        `6. **Revoke oude key** in provider dashboard (indien nog niet gedaan)`
      ];
    }
  },
  "db-url": {
    label: "Database URL",
    detect: (title) => /database.?url|db.?connection|postgres:\/\/|mysql:\/\//i.test(title),
    steps: (finding) => {
      const secretName = "DATABASE_URL";
      return [
        `## Rotation Playbook: Database Connection String`,
        ``,
        `**Detected**: ${finding.title}`,
        `**Location**: ${finding.files?.[0]}:${finding.location?.line ?? "?"}`,
        ``,
        `### Stappen:`,
        ``,
        `1. **Create nieuwe DB user** met minimale permissions:`,
        `   \`\`\`sql`,
        `   CREATE USER app_new WITH PASSWORD 'secure_random_password';`,
        `   GRANT CONNECT ON DATABASE mydb TO app_new;`,
        `   GRANT USAGE ON SCHEMA public TO app_new;`,
        `   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_new;`,
        `   \`\`\``,
        `2. **Store als GitHub Secret**:`,
        `   \`\`\`bash`,
        `   gh secret set ${secretName} --body "postgresql://app_new:PASSWORD@host:5432/mydb"`,
        `   \`\`\``,
        `3. **Update code**:`,
        `   \`\`\`js`,
        `   const dbUrl = process.env.DATABASE_URL;`,
        `   \`\`\``,
        `4. **Test connectivity**: \`npm run db:migrate\` of equivalent`,
        `5. **Rotate oude password**: \`ALTER USER app_old PASSWORD 'new_random';`,
        `6. **Monitor** applicatie logs voor connection errors`
      ];
    }
  },
  "private-key": {
    label: "Private Key",
    detect: (title) => /private.?key|ssh.?key|rsa.?key|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY/i.test(title),
    steps: (finding) => {
      const secretName = generateSecretName(finding.title);
      return [
        `## Rotation Playbook: Private Key`,
        ``,
        `**Detected**: ${finding.title}`,
        `**Location**: ${finding.files?.[0]}:${finding.location?.line ?? "?"}`,
        ``,
        `### Stappen:`,
        ``,
        `1. **Genereer nieuwe keypair**:`,
        `   \`\`\`bash`,
        `   ssh-keygen -t ed25519 -f ~/.ssh/app_deploy_new`,
        `   \`\`\``,
        `2. **Deploy public key** naar doelsystemen:`,
        `   \`\`\`bash`,
        `   ssh-copy-id -i ~/.ssh/app_deploy_new.pub user@server`,
        `   \`\`\``,
        `3. **Store private key als GitHub Secret**:`,
        `   \`\`\`bash`,
        `   gh secret set ${secretName} --body "$(cat ~/.ssh/app_deploy_new)"`,
        `   \`\`\``,
        `4. **Update code** om uit env te lezen:`,
        `   \`\`\`js`,
        `   const privateKey = process.env.${secretName};`,
        `   \`\`\``,
        `5. **Test SSH connectivity** met nieuwe key`,
        `6. **Verwijder oude key** van alle servers: \`~/.ssh/authorized_keys\``
      ];
    }
  },
  "password": {
    label: "Password",
    detect: (title) => /password|passwd|pwd|credential/i.test(title),
    steps: (finding) => {
      const secretName = generateSecretName(finding.title);
      return [
        `## Rotation Playbook: Password`,
        ``,
        `**Detected**: ${finding.title}`,
        `**Location**: ${finding.files?.[0]}:${finding.location?.line ?? "?"}`,
        ``,
        `### Stappen:`,
        ``,
        `1. **Identificeer service** waar het password voor is`,
        `2. **Reset password** via admin panel of CLI`,
        `3. **Store als GitHub Secret**:`,
        `   \`\`\`bash`,
        `   gh secret set ${secretName} --body "$NEW_PASSWORD"`,
        `   \`\`\``,
        `4. **Update code**:`,
        `   \`\`\`js`,
        `   const password = process.env.${secretName};`,
        `   \`\`\``,
        `5. **Verifieer** dat de applicatie werkt`,
        `6. **Check** of het oude password ergens elders is hergebruik — rotate ook daar`
      ];
    }
  }
};

function generateSecretName(title) {
  const cleaned = title
    .replace(/[^a-zA-Z0-9 ]/g, "")
    .replace(/(api|key|token|secret|password|db|database|private|ssh)/gi, "")
    .trim()
    .replace(/\s+/g, "_")
    .toUpperCase()
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "");
  return cleaned || "ROTATED_SECRET";
}

function detectSecretType(title) {
  for (const [type, config] of Object.entries(PLAYBOOKS)) {
    if (config.detect(title)) return type;
  }
  return "api-key";
}

export function generateRotationPlaybook(finding) {
  const type = detectSecretType(finding.title);
  const playbook = PLAYBOOKS[type];
  return {
    type,
    label: playbook.label,
    steps: playbook.steps(finding),
    ghCommands: extractGhCommands(playbook.steps(finding))
  };
}

function extractGhCommands(steps) {
  const commands = [];
  for (const step of steps) {
    const match = step.match(/gh secret set.*/);
    if (match) commands.push(match[0].trim());
  }
  return commands;
}

export function generateAllPlaybooks(findings) {
  const secretFindings = findings.filter(
    (f) => f.category?.includes("secret") || f.category === "security-bypass"
  );

  return secretFindings.map((f) => generateRotationPlaybook(f));
}

export function executeGhSecretCommand(command) {
  const parsed = parseGhSecretCommand(command);
  if (!parsed) return { success: false, error: "unsupported gh secret command" };

  const secretBody = resolveSecretBody(parsed.body);
  if (!secretBody.success) return secretBody;

  try {
    const result = execFileSync("gh", ["secret", "set", parsed.name, "--body", secretBody.body], {
      encoding: "utf8",
      timeout: 10_000,
      stdio: ["pipe", "pipe", "pipe"]
    });
    return { success: true, output: result.trim() };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function parseGhSecretCommand(command) {
  const match = command.match(/^gh\s+secret\s+set\s+([A-Z0-9_]+)\s+--body\s+(.+)$/);
  if (!match) return null;
  const body = match[2].trim().replace(/^["']|["']$/g, "");
  return { name: match[1], body };
}

function resolveSecretBody(body) {
  const envVar = body.match(/^\$([A-Z0-9_]+)$/)?.[1];
  if (envVar) {
    const value = process.env[envVar];
    return value
      ? { success: true, body: value }
      : { success: false, error: `missing secret body env ${envVar}` };
  }

  const catPath = body.match(/^\$\(cat\s+(.+)\)$/)?.[1];
  if (catPath) {
    const file = expandHome(catPath.trim().replace(/^["']|["']$/g, ""));
    try {
      return { success: true, body: fs.readFileSync(file, "utf8") };
    } catch {
      return { success: false, error: `secret body file not found: ${file}` };
    }
  }

  if (body.includes("$(") || body.includes("`")) {
    return { success: false, error: "unsupported secret body expression" };
  }

  return { success: true, body };
}

function expandHome(filePath) {
  if (filePath === "~") return os.homedir();
  if (filePath.startsWith("~/")) return path.join(os.homedir(), filePath.slice(2));
  return filePath;
}

export function playbookToMarkdown(playbook) {
  return playbook.steps.join("\n");
}

export function playbooksToMarkdown(playbooks) {
  if (playbooks.length === 0) return "Geen secrets gevonden die rotation nodig hebben.";

  const lines = ["# CodeGuardian — Secret Rotation Playbooks\n"];
  for (const pb of playbooks) {
    lines.push(pb.steps.join("\n"));
    lines.push("\n---\n");
  }
  return lines.join("\n");
}
