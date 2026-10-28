#!/usr/bin/env node
import { loadConfig } from "../config/config.js";
import { createPlatform } from "./context.js";
import { buildServer } from "./buildServer.js";
import { serveHttp } from "./http.js";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { createLogger } from "../util/log.js";
import { PRODUCT } from "../version.js";

/**
 * Server entry: stdio by default (stdout reserved for the MCP protocol;
 * logs go to stderr), streamable HTTP with `--http`.
 */

const parseArgs = (argv: string[]): { http: boolean; host?: string; port?: number } => {
  let http = false;
  let host: string | undefined;
  let port: number | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--http") http = true;
    else if (arg === "--host") host = argv[++i];
    else if (arg === "--port") port = Number(argv[++i]);
    else if (arg === "--help" || arg === "-h") {
      process.stdout.write(
        `Usage: vestige mcp [--http] [--host H] [--port N]\n\n` +
          `stdio transport by default. --http enables the streamable HTTP\n` +
          `transport on POST /mcp with Host/Origin allowlisting and bearer-token\n` +
          `auth for non-loopback binds (set VESTIGE_HTTP_TOKEN).\n`,
      );
      process.exit(0);
    }
  }
  return { http, host, port };
};

const main = async (): Promise<void> => {
  const args = parseArgs(process.argv.slice(2));
  const config = loadConfig();
  if (args.host) config.http.host = args.host;
  if (args.port !== undefined) config.http.port = args.port;
  const log = createLogger(config.logLevel);

  const platform = await createPlatform(config, log);
  const shutdown = async (signal: string): Promise<void> => {
    log.info(`received ${signal}; shutting down`);
    try {
      await platform.close();
    } finally {
      process.exit(0);
    }
  };
  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));

  if (args.http) {
    const http = await serveHttp(platform, {
      host: config.http.host,
      port: config.http.port,
      token: config.http.token,
      allowedOrigins: config.http.allowedOrigins,
    });
    log.info(`${PRODUCT.mcpServerName} listening (streamable HTTP)`, { url: http.url });
    // Keep the process alive; close handled via shutdown.
  } else {
    const server = buildServer(platform);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log.info(`${PRODUCT.mcpServerName} listening (stdio)`);
  }
};

main().catch((error: unknown) => {
  // Startup failures: emit one line to stderr and exit non-zero.
  process.stderr.write(
    `${PRODUCT.name}: startup failed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
});
