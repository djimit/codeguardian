import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getTrendData, readHistory } from "../core/history.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DASHBOARD_HTML = path.join(__dirname, "index.html");

export function startDashboard({ port = 3000, reportPath = null } = {}) {
  const reportDir = reportPath ? path.dirname(reportPath) : process.cwd();

  const server = http.createServer((req, res) => {
    if (req.url === "/api/report") {
      try {
        const data = reportPath
          ? JSON.parse(fs.readFileSync(reportPath, "utf8"))
          : { repositories: [], summary: {} };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      } catch {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Report not found. Run scan first." }));
      }
      return;
    }

    if (req.url === "/api/history") {
      const trend = getTrendData(reportDir);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(trend));
      return;
    }

    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(fs.readFileSync(DASHBOARD_HTML, "utf8"));
  });

  server.listen(port, () => {
    console.log(`CodeGuardian Dashboard: http://localhost:${port}`);
  });

  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PORT ?? "3000", 10);
  const reportPath = process.env.REPORT_PATH ?? null;
  startDashboard({ port, reportPath });
}
