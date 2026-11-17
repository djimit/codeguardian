import { test } from "node:test";
import { strict as assert } from "node:assert";
import http from "node:http";
import { startServer } from "../src/server.js";

function request(server, { method, path, token, body } = {}) {
  const { port } = server.address();
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      method,
      path,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(body ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } : {})
      }
    }, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

test("server requires bearer auth for protected endpoints", async () => {
  const server = startServer({ port: 0, token: "test-token" });
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    assert.equal((await request(server, { method: "GET", path: "/report" })).status, 401);
    assert.equal((await request(server, { method: "GET", path: "/report", token: "test-token" })).status, 404);
    assert.equal((await request(server, { method: "GET", path: "/health" })).status, 200);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("server rejects oversized scan bodies", async () => {
  const server = startServer({ port: 0, token: "test-token", maxBodyBytes: 10 });
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    const result = await request(server, {
      method: "POST",
      path: "/scan",
      token: "test-token",
      body: JSON.stringify({ paths: ["123456789012345"] })
    });
    assert.equal(result.status, 413);
    assert.match(result.body, /exceeds 10 bytes/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
