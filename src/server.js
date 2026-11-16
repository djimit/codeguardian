import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { scanRepositories } from "./core/multi-repo.js";
import { formatMarkdownReport, formatJsonReport } from "./core/report-formatter.js";
import { formatSarifReport } from "./core/sarif.js";
import { buildInventory, saveInventory } from "./core/inventory.js";

const DEFAULT_MAX_BODY_BYTES = 1_048_576;

export function startServer({
  port = 8080,
  host = process.env.CODEGUARDIAN_HOST ?? "127.0.0.1",
  token = process.env.CODEGUARDIAN_TOKEN?.trim() || null,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES
} = {}) {
  if (!isLoopback(host) && !token) {
    throw new Error("CODEGUARDIAN_TOKEN is required when CODEGUARDIAN_HOST is not loopback");
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);

    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", version: "1.0.0" }));
      return;
    }

    if ((url.pathname === "/scan" && req.method === "POST") || (url.pathname === "/report" && req.method === "GET")) {
      if (!authorized(req, token)) {
        res.writeHead(401, { "Content-Type": "application/json", "WWW-Authenticate": "Bearer" });
        res.end(JSON.stringify({ error: "Unauthorized" }));
        return;
      }
    }

    if (url.pathname === "/scan" && req.method === "POST") {
      try {
        const body = await readBody(req, maxBodyBytes);
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
        res.writeHead(err.statusCode || 400, { "Content-Type": "application/json" });
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

  server.listen(port, host, () => {
    console.log(`CodeGuardian server: http://${host}:${server.address().port}`);
    console.log(`  POST /scan    - Scan repos (body: { paths, username, format })`);
    console.log(`  GET  /report  - Latest report`);
    console.log(`  GET  /health  - Health check`);
  });

  return server;
}

function isLoopback(host) {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

function authorized(req, token) {
  if (!token) return true;
  const value = req.headers.authorization;
  if (typeof value !== "string" || !value.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(value.slice(7));
  const expected = Buffer.from(token);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let data = "";
    let bytes = 0;
    let rejected = false;
    req.on("data", (chunk) => {
      if (rejected) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        rejected = true;
        const error = new Error(`Request body exceeds ${maxBytes} bytes`);
        error.statusCode = 413;
        reject(error);
        return;
      }
      data += chunk;
    });
    req.on("end", () => { if (!rejected) resolve(data); });
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
