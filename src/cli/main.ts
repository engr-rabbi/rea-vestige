#!/usr/bin/env node
/**
 * Vestige CLI. One command surface for registration, analysis, evidence,
 * reports, and diagnostics; shares the platform with the MCP server.
 * stdout carries machine-readable JSON; logs go to stderr.
 */
import { loadConfig, type VestigeConfig } from "../config/config.js";
import { createPlatform, type Platform } from "../server/context.js";
import { silentLogger } from "../util/log.js";
import { PRODUCT } from "../version.js";
import { projectError, VestigeError } from "../errors/errors.js";
import { renderReport } from "../services/analysisService.js";
import { writeFile } from "node:fs/promises";
import { serveHttp } from "../server/http.js";
import { buildServer } from "../server/buildServer.js";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";

const usage = (): string => `
${PRODUCT.displayName} v${PRODUCT.version} — ${PRODUCT.description}

Usage:
  vestige mcp [--http] [--host H] [--port N]   Run the MCP server (stdio default)
  vestige register <path> [label]              Register an analysis target
  vestige targets                              List registered targets
  vestige inspect <artifactId>                 Target metadata + provider support
  vestige providers                            Provider capabilities + availability
  vestige analyze <artifactId> [--provider id] [--capability op]
  vestige status <jobId>                       Show analysis job status
  vestige findings <artifactId> [--kind k] [--limit n]
  vestige evidence <evidenceId>                Fetch + verify one evidence record
  vestige export <artifactId> [--format markdown|json] [--out file]
  vestige doctor                               Self-diagnostics
  vestige version                              Print version
`.trim();

const out = (value: unknown): void => {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
};

const die = (error: unknown): never => {
  const payload = projectError(error);
  process.stderr.write(`${payload.code}: ${payload.message}\nRemediation: ${payload.remediation}\n`);
  process.exit(1);
};

interface Args {
  _: string[];
  flags: Record<string, string | boolean>;
}

const parseArgs = (argv: string[]): Args => {
  const _: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a?.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    } else if (a) {
      _.push(a);
    }
  }
  return { _, flags };
};

const makePlatform = async (config: VestigeConfig): Promise<Platform> =>
  createPlatform(config, silentLogger);

const main = async (): Promise<void> => {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  if (command === "version" || args.flags.version) {
    out({ name: PRODUCT.name, version: PRODUCT.version });
    return;
  }
  if (!command || command === "help" || args.flags.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const config = loadConfig();

  if (command === "mcp") {
    if (args.flags.http) {
      const platform = await makePlatform(config);
      const http = await serveHttp(platform, {
        host: args.flags.host ? String(args.flags.host) : config.http.host,
        port: args.flags.port ? Number(args.flags.port) : config.http.port,
        token: config.http.token,
        allowedOrigins: config.http.allowedOrigins,
      });
      process.stderr.write(`vestige mcp listening on ${http.url}\n`);
      // keep alive
      return;
    }
    const platform = await makePlatform(config);
    const server = buildServer(platform);
    await server.connect(new StdioServerTransport());
    return;
  }

  const platform = await makePlatform(config);
  try {
    switch (command) {
      case "register": {
        const targetPath = args._[1];
        if (!targetPath) die(new VestigeError({ code: "invalid_input", message: "register requires a path", remediation: "Run: vestige register <path> [label]", retryable: false }));
        const { artifact, created } = await platform.targets.register(
          targetPath,
          typeof args.flags.label === "string" ? args.flags.label : args._[2],
        );
        out({ artifact, created });
        break;
      }
      case "targets": {
        out({ targets: await platform.targets.list() });
        break;
      }
      case "inspect": {
        const id = args._[1];
        if (!id) die(new VestigeError({ code: "invalid_input", message: "inspect requires an artifactId", remediation: "Run: vestige inspect <artifactId>", retryable: false }));
        const artifact = await platform.targets.require(id);
        const supportedBy = platform.providers.list().filter((p) => p.supports(artifact)).map((p) => p.descriptor);
        out({ artifact, supportedBy });
        break;
      }
      case "providers": {
        const availability = await platform.providers.availability();
        out({
          providers: availability.map((p) => ({
            id: p.descriptor.id,
            name: p.descriptor.name,
            version: p.descriptor.version,
            formats: p.descriptor.formats,
            ...(p.availability.available
              ? { available: true as const, detail: p.availability.detail }
              : { available: false as const, reason: p.availability.reason, guidance: p.availability.guidance }),
          })),
        });
        break;
      }
      case "analyze": {
        const id = args._[1];
        if (!id) die(new VestigeError({ code: "invalid_input", message: "analyze requires an artifactId", remediation: "Run: vestige analyze <artifactId>", retryable: false }));
        const provider = typeof args.flags.provider === "string" ? args.flags.provider : undefined;
        const capability = typeof args.flags.capability === "string" ? [args.flags.capability] : [];
        const record = platform.analysis.startAnalysis(id, provider, capability);
        await record.done;
        out({ job: record.job });
        if (record.job.status === "failed") process.exitCode = 1;
        break;
      }
      case "status": {
        const jobId = args._[1];
        if (!jobId) die(new VestigeError({ code: "invalid_input", message: "status requires a jobId", remediation: "Run: vestige status <jobId>", retryable: false }));
        out({ job: platform.jobs.require(jobId).job });
        break;
      }
      case "findings": {
        const id = args._[1];
        if (!id) die(new VestigeError({ code: "invalid_input", message: "findings requires an artifactId", remediation: "Run: vestige findings <artifactId>", retryable: false }));
        await platform.targets.require(id);
        let findings = await platform.store.getFindings(id);
        const kind = typeof args.flags.kind === "string" ? args.flags.kind : undefined;
        if (kind) findings = findings.filter((f) => f.kind === kind);
        const limit = typeof args.flags.limit === "string" ? Number(args.flags.limit) : 100;
        out({ findings: findings.slice(0, limit), total: findings.length });
        break;
      }
      case "evidence": {
        const id = args._[1];
        if (!id) die(new VestigeError({ code: "invalid_input", message: "evidence requires an evidenceId", remediation: "Run: vestige evidence <evidenceId>", retryable: false }));
        const evidence = await platform.store.getEvidence(id);
        if (!evidence) die(new VestigeError({ code: "not_found", message: `Evidence '${id}' not found or failed verification`, remediation: "List findings and use their evidenceIds.", retryable: false }));
        out({ evidence, verified: true });
        break;
      }
      case "export": {
        const id = args._[1];
        if (!id) die(new VestigeError({ code: "invalid_input", message: "export requires an artifactId", remediation: "Run: vestige export <artifactId>", retryable: false }));
        const artifact = await platform.targets.require(id);
        const findings = await platform.store.getFindings(id);
        const format = args.flags.format === "json" ? "json" : "markdown";
        const content =
          format === "json"
            ? JSON.stringify({ artifact, findings }, null, 2)
            : renderReport(
                artifact,
                findings,
                findings.reduce((n, f) => n + f.evidenceIds.length, 0),
                platform.jobs.list().map((j) => ({ jobId: j.jobId, providerId: j.providerId, status: j.status, finishedAt: j.finishedAt })),
              );
        if (typeof args.flags.out === "string") {
          await writeFile(args.flags.out, content, "utf8");
          out({ written: args.flags.out, format, findings: findings.length });
        } else {
          process.stdout.write(content.endsWith("\n") ? content : `${content}\n`);
        }
        break;
      }
      case "doctor": {
        const availability = await platform.providers.availability();
        out({
          server: { name: PRODUCT.mcpServerName, version: PRODUCT.version },
          runtime: { node: process.version, platform: process.platform },
          dataDir: config.dataDir,
          workDir: config.workDir,
          providers: availability.map((p) => ({
            id: p.descriptor.id,
            available: p.availability.available,
            ...(p.availability.available
              ? { detail: p.availability.detail }
              : {
                  reason: p.availability.reason,
                  guidance: p.availability.guidance,
                }),
          })),
        });
        break;
      }
      default:
        die(new VestigeError({ code: "invalid_input", message: `Unknown command '${command}'`, remediation: "Run: vestige help", retryable: false }));
    }
  } finally {
    await platform.close();
  }
};

main().catch((error: unknown) => {
  die(error);
});
