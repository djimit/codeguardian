import { execFileSync } from "node:child_process";

function getPrDiff(owner, repo, prNumber) {
  try {
    const output = execFileSync(
      "gh",
      ["api", `repos/${owner}/${repo}/pulls/${prNumber}/files`, "--jq", ".[] | {filename, patch}"],
      { encoding: "utf8", timeout: 30_000 }
    );
    return output;
  } catch {
    return null;
  }
}

function parseDiffHunks(patch) {
  const hunks = [];
  const lines = patch.split("\n");
  let currentHunk = null;

  for (const line of lines) {
    const hunkMatch = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      if (currentHunk) hunks.push(currentHunk);
      currentHunk = {
        oldStart: parseInt(hunkMatch[1], 10),
        newStart: parseInt(hunkMatch[2], 10),
        newLines: []
      };
    } else if (currentHunk && line.startsWith("+") && !line.startsWith("+++")) {
      currentHunk.newLines.push(line.slice(1));
    }
  }
  if (currentHunk) hunks.push(currentHunk);
  return hunks;
}

function isLineInDiff(filename, line, files) {
  const file = files.find((f) => f.filename === filename);
  if (!file || !file.patch) return false;

  const hunks = parseDiffHunks(file.patch);
  for (const hunk of hunks) {
    if (line >= hunk.newStart && line < hunk.newStart + hunk.newLines.length) {
      return true;
    }
  }
  return false;
}

export function generatePrReviewComments({ report, owner, repo, prNumber }) {
  const files = getPrDiff(owner, repo, prNumber);
  if (!files) return [];

  const comments = [];
  const prFiles = parsePrFiles(files);

  for (const repo of report.repositories) {
    for (const finding of repo.findings) {
      const file = finding.files?.[0];
      const line = finding.location?.line;
      if (!file || !line) continue;

      if (!isLineInDiff(file, line, prFiles)) continue;

      const risk = finding.riskScore != null ? ` | **Risk**: ${finding.riskScore}/100` : "";
      const compliance = finding.complianceControls?.length
        ? ` | **Compliance**: ${finding.complianceControls.slice(0, 3).join(", ")}`
        : "";

      comments.push({
        path: file,
        line,
        side: "RIGHT",
        body: `🛡️ **CodeGuardian**: [${finding.severity.toUpperCase()}] ${finding.title}\n\n${finding.proposedFix || finding.explanation || ""}\n\n${risk}${compliance}`
      });
    }
  }

  return comments;
}

function parsePrFiles(rawOutput) {
  const files = [];
  const blocks = rawOutput.split(/\n(?=\{)/);
  for (const block of blocks) {
    try {
      files.push(JSON.parse(block));
    } catch {
      // skip malformed
    }
  }
  return files;
}

export function postPrReviewComments(owner, repo, prNumber, comments) {
  if (comments.length === 0) return { posted: 0 };

  const event = comments.some((c) => c.body.includes("CRITICAL"))
    ? "REQUEST_CHANGES"
    : "COMMENT";

  const reviewBody = {
    body: `CodeGuardian found ${comments.length} issue(s) in this PR.`,
    event,
    comments
  };

  try {
    execFileSync(
      "gh",
      ["api", `repos/${owner}/${repo}/pulls/${prNumber}/reviews`, "--method", "POST", "--input", "-"],
      {
        input: JSON.stringify(reviewBody),
        encoding: "utf8",
        timeout: 30_000
      }
    );
    return { posted: comments.length, event };
  } catch (err) {
    return { posted: 0, error: err.message };
  }
}
