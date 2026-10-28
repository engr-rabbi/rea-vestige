import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import {
  localhostAllowedHostnames,
  WebStandardStreamableHTTPServerTransport,
  type McpServer,
} from "@modelcontextprotocol/server";
import type { Platform } from "./context.js";
import { createLogger } from "../util/log.js";

/**
 * Streamable HTTP transport with defense in depth (design fix for the
 * reference's allowlist-only HTTP auth):
 *   - loopback bind by default; non-loopback binds require a bearer token
 *   - Host header allowlist (DNS-rebinding protection) via the SDK helper
 *   - Origin allowlist for browser-based clients
 *   - per-session transports so multiple clients don't evict each other
 *   - constant-time token comparison; tokens are never logged
 */

const constantTimeEquals = (a: string, b: string): boolean => {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    // Still burn comparable time to avoid a cheap length oracle.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
};

export interface HttpServeOptions {
  host: string;
  port: number;
  token?: string;
  allowedOrigins: string[];
}

interface SessionSlot {
  transport: InstanceType<typeof WebStandardStreamableHTTPServerTransport>;
  server: McpServer;
  lastSeen: number;
}

const isLoopbackHost = (host: string): boolean =>
  host === "127.0.0.1" || host === "localhost" || host === "::1";

export const serveHttp = async (
  platform: Platform,
  options: HttpServeOptions,
): Promise<{ server: HttpServer; url: string; close: () => Promise<void> }> => {
  const log = createLogger(platform.config.logLevel);
  const sessions = new Map<string, SessionSlot>();
  const loopback = isLoopbackHost(options.host);

  if (!loopback && !options.token) {
    throw new Error(
      "Refusing to bind non-loopback HTTP without a bearer token (set VESTIGE_HTTP_TOKEN).",
    );
  }

  const httpServer = createHttpServer(
    async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      if (url.pathname !== "/mcp") {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "not_found", message: "Only /mcp is served." }));
        return;
      }

      // --- Host header validation (DNS rebinding) ---
      const hostHeader = req.headers.host ?? "";
      const headerHostname = hostHeader.replace(/:\d+$/, "").toLowerCase();
      const allowedHosts = [...localhostAllowedHostnames(), ...(loopback ? [] : [options.host])];
      const hostOk = allowedHosts.some(
        (h) => headerHostname === h.toLowerCase(),
      );
      if (!hostOk) {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "forbidden_host", message: "Host header not allowed." }));
        return;
      }

      // --- Origin validation for browser clients ---
      const origin = req.headers.origin;
      if (origin !== undefined) {
        const originAllowed =
          options.allowedOrigins.includes(origin) ||
          /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(origin);
        if (!originAllowed) {
          res.writeHead(403, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "forbidden_origin", message: "Origin not allowed." }));
          return;
        }
      }

      // --- Bearer token (required for non-loopback; optional on loopback) ---
      if (options.token) {
        const header = req.headers.authorization ?? "";
        const match = /^Bearer\s+(.+)$/i.exec(header);
        if (!match || !constantTimeEquals(match[1] ?? "", options.token)) {
          res.writeHead(401, {
            "content-type": "application/json",
            "www-authenticate": 'Bearer realm="vestige-mcp"',
          });
          res.end(
            JSON.stringify({ error: "unauthorized", message: "A valid bearer token is required." }),
          );
          return;
        }
      }

      // --- Body size cap ---
      const contentLength = Number(req.headers["content-length"] ?? "0");
      if (contentLength > 8 * 1024 * 1024) {
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "payload_too_large", message: "Request body exceeds 8 MiB." }));
        return;
      }

      const sessionIdHeader = req.headers["mcp-session-id"];
      const isInitialize = req.method === "POST";

      let slot: SessionSlot | undefined;
      if (typeof sessionIdHeader === "string" && sessions.has(sessionIdHeader)) {
        slot = sessions.get(sessionIdHeader);
      } else if (isInitialize) {
        const transport = new WebStandardStreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableJsonResponse: true,
        });
        // Fresh server per session with the full tool/resource/prompt surface.
        const { buildServer } = await import("./buildServer.js");
        const sessionServer = buildServer(platform);
        await sessionServer.connect(transport);
        const id = randomUUID();
        slot = { transport, server: sessionServer, lastSeen: Date.now() };
        sessions.set(id, slot);
        log.info("http session opened", { sessionId: id });
      }

      if (!slot) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            error: "invalid_session",
            message: "No valid MCP session. Send an initialize request first.",
          }),
        );
        return;
      }
      slot.lastSeen = Date.now();

      // Bridge node:http to the Web-standard transport.
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const body = Buffer.concat(chunks);
      const request = new Request(url.href, {
        method: req.method,
        headers: Object.fromEntries(
          Object.entries(req.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : (v ?? "")]),
        ),
        ...(body.length > 0 ? { body, ...(req.method !== "GET" && req.method !== "HEAD" ? { duplex: "half" } : {}) } : {}),
      });

      const response = await slot.transport.handleRequest(request);
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });
      const responseBody = await response.arrayBuffer();
      res.writeHead(response.status, headers);
      if (responseBody.byteLength > 0) {
        res.end(Buffer.from(responseBody));
      } else {
        res.end();
      }

      // Reap sessions idle > 30 minutes.
      const now = Date.now();
      for (const [id, s] of sessions) {
        if (now - s.lastSeen > 30 * 60 * 1000) {
          void s.transport.close().catch(() => {});
          void s.server.close().catch(() => {});
          sessions.delete(id);
          log.info("http session reaped", { sessionId: id });
        }
      }
    },
  );

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(options.port, options.host, () => resolve());
  });

  const address = httpServer.address();
  const boundPort = typeof address === "object" && address !== null ? address.port : options.port;
  const url = `http://${options.host}:${String(boundPort)}/mcp`;

  return {
    server: httpServer,
    url,
    close: async () => {
      for (const [, slot] of sessions) {
        await slot.transport.close().catch(() => {});
        await slot.server.close().catch(() => {});
      }
      sessions.clear();
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    },
  };
};
