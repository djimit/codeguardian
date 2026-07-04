import fs from "node:fs";
import path from "node:path";

export function generateFix(finding, repoRoot = ".") {
  if (finding.category !== "dependency-cve") return null;

  const fixVersion = extractFixVersion(finding.proposedFix);
  if (!fixVersion) return null;

  const manifestPath = finding.files?.[0];
  if (!manifestPath) return null;

  const fullPath = path.join(repoRoot, manifestPath);
  if (!fs.existsSync(fullPath)) return null;

  const ext = path.extname(manifestPath);
  const packageName = extractPackageName(finding.proposedFix);
  if (!packageName) return null;

  switch (ext) {
    case ".json":
      return fixPackageJson(fullPath, packageName, fixVersion, finding);
    case ".txt":
      return fixRequirementsTxt(fullPath, packageName, fixVersion, finding);
    case ".toml":
      return fixUvLock(fullPath, packageName, fixVersion, finding);
    default:
      return null;
  }
}

function extractFixVersion(proposedFix) {
  if (!proposedFix) return null;
  const match = proposedFix.match(/version\s+([\d.]+)/i);
  return match ? match[1] : null;
}

function extractPackageName(proposedFix) {
  if (!proposedFix) return null;
  const match = proposedFix.match(/Update\s+(\S+)\s+to/i);
  return match ? match[1] : null;
}

function fixPackageJson(filePath, packageName, fixVersion, finding) {
  const content = fs.readFileSync(filePath, "utf8");
  const json = JSON.parse(content);

  const sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
  let section = null;
  let currentVersion = null;

  for (const sec of sections) {
    if (json[sec]?.[packageName]) {
      section = sec;
      currentVersion = json[sec][packageName];
      break;
    }
  }

  if (!section) return null;

  const oldPattern = new RegExp(`"${packageName}"\\s*:\\s*"${currentVersion.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`);
  const match = content.match(oldPattern);
  if (!match) return null;

  return {
    type: "dependency-bump",
    file: finding.files[0],
    packageName,
    from: currentVersion,
    to: fixVersion,
    findingId: finding.id,
    description: `Bump ${packageName} from ${currentVersion} to ${fixVersion}`,
    patches: [{ old: match[0], new: match[0].replace(currentVersion, fixVersion), file: finding.files[0] }],
    safe: isSafeBump(currentVersion, fixVersion)
  };
}

function fixRequirementsTxt(filePath, packageName, fixVersion, finding) {
  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split("\n");
  const idx = lines.findIndex((l) => {
    const match = l.match(/^([a-zA-Z0-9_-]+)\s*==\s*([^\s;]+)/);
    return match && match[1].toLowerCase() === packageName.toLowerCase();
  });

  if (idx === -1) return null;

  const oldLine = lines[idx];
  const newLine = `${packageName}==${fixVersion}`;

  return {
    type: "dependency-bump",
    file: finding.files[0],
    packageName,
    from: oldLine.match(/==\s*([^\s;]+)/)?.[1] || "?",
    to: fixVersion,
    findingId: finding.id,
    description: `Bump ${packageName} to ${fixVersion}`,
    patches: [{ old: oldLine, new: newLine, file: finding.files[0] }],
    safe: true
  };
}

function fixUvLock(filePath, packageName, fixVersion, finding) {
  return {
    type: "dependency-bump",
    file: finding.files[0],
    packageName,
    from: "?",
    to: fixVersion,
    findingId: finding.id,
    description: `Update ${packageName} to ${fixVersion} (uv sync required)`,
    patches: [],
    safe: false,
    note: "Run `uv sync` after updating pyproject.toml"
  };
}

function isSafeBump(from, to) {
  const fromMajor = from.match(/^(\d+)/);
  const toMajor = to.match(/^(\d+)/);
  if (!fromMajor || !toMajor) return false;
  return fromMajor[1] === toMajor[1];
}

export function applyFix(fix, repoRoot = ".") {
  if (!fix || !fix.patches?.length) return false;

  for (const patch of fix.patches) {
    const filePath = path.join(repoRoot, patch.file);
    const content = fs.readFileSync(filePath, "utf8");
    if (!content.includes(patch.old)) return false;
    const updated = content.replace(patch.old, patch.new);
    fs.writeFileSync(filePath, updated);
  }

  return true;
}

export function generateFixReport(fixes) {
  if (fixes.length === 0) return "Geen automatische fixes beschikbaar.";

  const lines = ["# CodeGuardian Auto-Fix\n"];
  lines.push(`${fixes.length} fix(es) beschikbaar:\n`);

  for (const fix of fixes) {
    const safe = fix.safe ? "" : " **— manual review required**";
    lines.push(`- **${fix.packageName}** ${fix.from} → ${fix.to} (${fix.file})${safe}`);
  }

  const safeFixes = fixes.filter((f) => f.safe);
  lines.push("");
  lines.push(`${safeFixes.length} safe fixes kunnen automatisch worden toegepast.`);
  lines.push("");
  lines.push("Run `codeguardian fix --apply` om safe fixes toe te passen.");

  return lines.join("\n");
}
