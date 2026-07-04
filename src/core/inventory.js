import fs from "node:fs";
import path from "node:path";

const INVENTORY_FILE = ".codeguardian-inventory.json";

export function buildInventory(repoRoot, scanResult) {
  const inventory = {
    lastUpdated: new Date().toISOString(),
    repositories: {}
  };

  for (const repo of scanResult.repositories) {
    const deps = new Map();
    const secrets = new Set();
    const pii = new Set();

    for (const finding of repo.findings) {
      if (finding.category === "dependency-cve") {
        const pkg = extractPackage(finding);
        if (pkg) {
          const existing = deps.get(pkg.name) || { ...pkg, cves: [] };
          existing.cves.push(finding.id);
          deps.set(pkg.name, existing);
        }
      }
      if (finding.category?.includes("secret")) {
        secrets.add(finding.source?.ruleId || finding.title);
      }
      if (finding.category === "privacy-pii") {
        pii.add(finding.source?.ruleId || finding.title);
      }
    }

    inventory.repositories[repo.name] = {
      path: repo.path,
      maturity: repo.maturity,
      dependencies: Array.from(deps.values()),
      secrets: Array.from(secrets),
      pii: Array.from(pii),
      totalFindings: repo.findings.length
    };
  }

  return inventory;
}

export function saveInventory(repoRoot, inventory) {
  const filePath = path.join(repoRoot, INVENTORY_FILE);
  fs.writeFileSync(filePath, JSON.stringify(inventory, null, 2));
}

export function loadInventory(repoRoot) {
  try {
    const filePath = path.join(repoRoot, INVENTORY_FILE);
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

export function findAffectedRepos(inventory, packageName) {
  const affected = [];
  for (const [name, repo] of Object.entries(inventory.repositories || {})) {
    const match = repo.dependencies?.find((d) =>
      d.name.toLowerCase() === packageName.toLowerCase()
    );
    if (match) {
      affected.push({ repo: name, cves: match.cves });
    }
  }
  return affected;
}

function extractPackage(finding) {
  if (finding.proposedFix) {
    const match = finding.proposedFix.match(/Update\s+(\S+)\s+to/i);
    if (match) {
      return { name: match[1], ecosystem: "unknown" };
    }
  }
  if (finding.exploitScenario) {
    return { name: finding.exploitScenario, ecosystem: "unknown" };
  }
  return null;
}
