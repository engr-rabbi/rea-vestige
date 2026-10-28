import { describe, expect, it, afterAll, beforeAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "../../src/config/config.js";
import { createPlatform, type Platform } from "../../src/server/context.js";
import { serveHttp } from "../../src/server/http.js";
import type { Server as HttpServer } from "node:http";

/**
 * HTTP transport security: bearer-token auth, Host allowlist (DNS-rebinding),
 * Origin validation, session handling. Addresses the reference design's
 * allowlist-only HTTP weakness with a required token + constant-time compare.
 */

let platform: Platform;
let dataDir: string;
let http: { server: HttpServer; url: string; close: () => Promise<void> };

beforeAll(async () => {
  dataDir = await mkdtemp(path.join(os.tmpdir(), "vestige-http-"));
  const config = loadConfig({ VESTIGE_DATA_DIR: dataDir, VESTIGE_WORK_DIR: path.join(dataDir, "work") });
  platform = await createPlatform(config);
});

afterAll(async () => {
  await http?.close();
  await platform.close();
  await rm(dataDir, { recursive: true, force: true });
});

const startServer = async (token?: string, host = "127.0.0.1"): Promise<void> => {
  http = await serveHttp(platform, { host, port: 0, token, allowedOrigins: [] });
};

describe("streamable HTTP transport security", () => {
  it("refuses non-loopback binds without a token", async () => {
    await expect(
      serveHttp(platform, { host: "0.0.0.0", port: 0, allowedOrigins: [] }),
    ).rejects.toThrow(/bearer token/i);
  });

  it("serves /mcp on loopback without a token (local single-operator mode)", async () => {
    await startServer();
    try {
      const res = await fetch(http.url, { method: "POST", body: "not-json" });
      // Protocol-level error (400) proves the endpoint is reachable & guarded.
      expect([400, 406, 415, 500]).toContain(res.status);
    } finally {
      await http.close();
    }
  });

  it("rejects missing bearer token with 401 when token is configured", async () => {
    await startServer("secret-token-123");
    try {
      const res = await fetch(http.url, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }) });
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toContain("Bearer");
    } finally {
      await http.close();
    }
  });

  it("rejects wrong bearer token with 401", async () => {
    await startServer("secret-token-123");
    try {
      const res = await fetch(http.url, {
        method: "POST",
        headers: { authorization: "Bearer wrong-token" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      });
      expect(res.status).toBe(401);
    } finally {
      await http.close();
    }
  });

  it("accepts the correct bearer token and completes initialize handshake", async () => {
    await startServer("secret-token-123");
    try {
      const res = await fetch(http.url, {
        method: "POST",
        headers: {
          authorization: "Bearer secret-token-123",
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "http-test", version: "0.0.0" },
          },
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { result?: { serverInfo?: { name: string } } };
      expect(body.result?.serverInfo?.name).toBe("vestige-mcp");
    } finally {
      await http.close();
    }
  });

  it("rejects foreign Host headers (DNS-rebinding guard)", async () => {
    await startServer();
    try {
      // fetch() refuses to override Host; use node:http directly.
      const { request } = await import("node:http");
      const url = new URL(http.url);
      const status: number = await new Promise((resolve, reject) => {
        const req = request(
          {
            host: url.hostname,
            port: url.port,
            path: url.pathname,
            method: "POST",
            headers: { host: "evil.example.com" },
          },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on("error", reject);
        req.end(JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }));
      });
      expect(status).toBe(403);
    } finally {
      await http.close();
    }
  }, 15_000);

  it("rejects disallowed Origins with 403", async () => {
    await startServer();
    try {
      const res = await fetch(http.url, {
        method: "POST",
        headers: { origin: "https://untrusted.example" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      });
      expect(res.status).toBe(403);
    } finally {
      await http.close();
    }
  });

  it("returns 404 for non-/mcp paths", async () => {
    await startServer();
    try {
      const res = await fetch(`${http.url.replace(/\/mcp$/, "")}/other`, { method: "GET" });
      expect(res.status).toBe(404);
    } finally {
      await http.close();
    }
  });
});
