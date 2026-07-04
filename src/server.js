import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { scanRepositories } from "./core/multi-repo.js";
import { formatMarkdownReport, formatJsonReport } from "./core/report-formatter.js";
import { formatSarifReport } from "./core/sarif.js";
import { buildInventory, saveInventory } from "./core/inventory.js";

export function startServer({ port = 8080 } = {}) {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);

    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", version: "1.0.0" }));
      return;
    }

    if (url.pathname === "/scan" && req.method === "POST") {
      try {
        const body = await readBody(req);
        const { paths, username, format = "json" } = JSON.parse(body);

        const result = await scanRepositories({
          username,
          localPaths: paths || [],
          scanners: { secrets: true, dependencies: true, pii: true }
        });

        const reportDir = "/reports";
        fs.mkdirSync(reportDir, { recursive: true });
        const reportPath = path.join(reportDir, `scan-${Date.now()}.json`);
        fs.writeFileSync(reportPath, formatJsonReport(result));
        saveInventory(reportDir, buildInventory(reportDir, result));

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          status: "complete",
          reportPath,
          summary: result.summary
        }));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
      return;
    }

    if (url.pathname === "/report" && req.method === "GET") {
      const reportDir = "/reports";
      const latest = getLatestReport(reportDir);
      if (!latest) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "No reports found" }));
        return;
      }
      const data = JSON.parse(fs.readFileSync(latest, "utf8"));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(data));
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  });

  server.listen(port, () => {
    console.log(`CodeGuardian server: http://localhost:${port}`);
    console.log(`  POST /scan    - Scan repos (body: { paths, username, format })`);
    console.log(`  GET  /report  - Latest report`);
    console.log(`  GET  /health  - Health check`);
  });

  return server;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => { data += chunk; });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function getLatestReport(dir) {
  try {
    const files = fs.readdirSync(dir)
      .filter((f) => f.startsWith("scan-") && f.endsWith(".json"))
      .sort()
      .reverse();
    return files.length > 0 ? path.join(dir, files[0]) : null;
  } catch {
    return null;
  }
}
