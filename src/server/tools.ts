import type { McpServer } from "@modelcontextprotocol/server";
import { PRODUCT } from "../version.js";
import { projectError, VestigeError } from "../errors/errors.js";
import { verifyEvidence } from "../domain/evidence.js";
import { renderReport } from "../services/analysisService.js";
import type { Platform } from "./context.js";
import {
  analyzeInput,
  diagnosticsInput,
  exportReportInput,
  getEvidenceInput,
  getTargetInput,
  jobCancelInput,
  jobStatusInput,
  listFindingsInput,
  listProvidersInput,
  listTargetsInput,
  registerTargetInputSchema,
} from "./toolSchemas.js";

/**
 * Tool registration. Every handler:
 *  - receives SDK-validated input (Zod contracts)
 *  - requires explicit target registration before any analysis access
 *  - returns structuredContent on success AND typed error payloads on failure
 *  - never writes to original artifacts
 */

/** Uniform result envelope: content + structuredContent. */
const ok = (structured: unknown, text?: string) => ({
  content: [{ type: "text" as const, text: text ?? JSON.stringify(structured, null, 2) }],
  structuredContent: structured as Record<string, unknown>,
});

/** Typed error envelope — errors stay machine-readable (design fix W4). */
const fail = (error: unknown) => {
  const payload = projectError(error);
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: `${payload.code}: ${payload.message}\nRemediation: ${payload.remediation}` }],
    structuredContent: { error: payload } as Record<string, unknown>,
  };
};

export interface ProgressReporter {
  (update: { phase: string; stepsDone: number; stepsTotal: number | null; message?: string }): Promise<void>;
}

/** Emit MCP progress notifications when the client provided a progressToken. */
export const progressFromContext = (
  ctx: { mcpReq: { _meta?: { progressToken?: string | number }; notify: (n: { method: string; params: Record<string, unknown> }) => Promise<void> } },
): ProgressReporter | undefined => {
  const token = ctx.mcpReq._meta?.progressToken;
  if (token === undefined) return undefined;
  let sequence = 0;
  return async (update) => {
    sequence += 1;
    try {
      await ctx.mcpReq.notify({
        method: "notifications/progress",
        params: {
          progressToken: token,
          progress: sequence,
          ...(update.stepsTotal !== null ? { total: update.stepsTotal } : {}),
          ...(update.message ? { message: `${update.phase}: ${update.message}` } : { message: update.phase }),
        },
      });
    } catch {
      /* progress is best-effort; never fail an operation for it */
    }
  };
};

type ToolCtx = Parameters<Parameters<McpServer["registerTool"]>[2]>[1];

export const registerTools = (server: McpServer, platform: Platform): void => {
  server.registerTool(
    "vestige_register_target",
    {
      title: "Register analysis target",
      description:
        "Register a file or directory for analysis. Validates the path (canonicalization, symlink policy, allowed roots), computes SHA-256, and identifies the format. Read-only: the artifact is never modified.",
      inputSchema: registerTargetInputSchema,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (args: { path: string; label?: string }, ctx: ToolCtx) => {
      try {
        const { artifact, created, resolved } = await platform.targets.register(
          args.path,
          args.label,
          ctx.mcpReq.signal,
        );
        return ok({
          artifact,
          created,
          canonicalPath: resolved.canonicalPath,
          message: created
            ? "Target registered. Analysis requires an explicit vestige_analyze call."
            : "Target already registered (identical path and content).",
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_list_targets",
    {
      title: "List registered targets",
      description: "List all registered analysis targets with identity digests.",
      inputSchema: listTargetsInput,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => {
      try {
        const targets = await platform.targets.list();
        return ok({ targets, count: targets.length });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_get_target",
    {
      title: "Get target metadata",
      description:
        "Get one registered target's metadata plus which providers support it.",
      inputSchema: getTargetInput,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (args: { artifactId: string }) => {
      try {
        const artifact = await platform.targets.require(args.artifactId);
        const supporting = platform.providers
          .list()
          .filter((p) => p.supports(artifact))
          .map((p) => p.descriptor);
        return ok({ artifact, supportedBy: supporting });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_list_providers",
    {
      title: "List analysis providers",
      description:
        "List providers with capabilities and live availability (including installation guidance when a tool like Ghidra is missing).",
      inputSchema: listProvidersInput,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => {
      try {
        const providers = await platform.providers.availability();
        const capabilities = platform.providers.capabilities();
        return ok({
          providers: providers.map((p) => ({
            ...p.descriptor,
            availability: p.availability,
            capabilities: capabilities.find((c) => c.provider.id === p.descriptor.id)?.capabilities ?? [],
          })),
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_analyze",
    {
      title: "Start analysis job",
      description:
        "Start an asynchronous analysis job on a registered target. Returns a jobId immediately; poll vestige_job_status. Progress notifications are sent when the client supplies a progressToken in _meta.",
      inputSchema: analyzeInput,
      annotations: { readOnlyHint: true, openWorldHint: false, destructiveHint: false },
    },
    async (args: { artifactId: string; provider?: string; capabilities: string[] }, ctx: ToolCtx) => {
      try {
        // Fast validation of provider id before job creation.
        if (args.provider && !platform.providers.get(args.provider)) {
          return fail(
            new VestigeError({
              code: "invalid_input",
              message: `Unknown provider '${args.provider}'.`,
              remediation: "Call vestige_list_providers to see registered provider ids.",
              retryable: false,
            }),
          );
        }
        const record = platform.analysis.startAnalysis(
          args.artifactId,
          args.provider,
          args.capabilities,
        );
        const progress = progressFromContext(ctx as never);
        void record.done.then(() => {
          /* terminal; nothing to do */
        }).catch(() => {});
        if (progress) {
          const onProgress = (u: { phase: string; stepsDone: number; stepsTotal: number | null; message?: string }): void => {
            void progress(u);
          };
          // Wire progress by wrapping the job's done promise polling: the
          // provider pushes into the job; we poll at 250ms intervals.
          const interval = setInterval(() => {
            onProgress(record.job.progress);
            if (
              record.job.status === "completed" ||
              record.job.status === "failed" ||
              record.job.status === "cancelled"
            ) {
              clearInterval(interval);
            }
          }, 250);
          interval.unref?.();
        }
        return ok({
          jobId: record.job.jobId,
          status: record.job.status,
          artifactId: record.job.artifactId,
          providerId: record.job.providerId,
          poll: "vestige_job_status",
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_job_status",
    {
      title: "Get job status",
      description: "Get the status, progress, and result counts of an analysis job.",
      inputSchema: jobStatusInput,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (args: { jobId: string }) => {
      try {
        const rec = platform.jobs.require(args.jobId);
        return ok({ job: rec.job });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_job_cancel",
    {
      title: "Cancel analysis job",
      description:
        "Cancel a queued or running analysis job. Evidence already persisted is retained and the job becomes 'cancelled'.",
      inputSchema: jobCancelInput,
      annotations: { readOnlyHint: true, openWorldHint: false, destructiveHint: false },
    },
    async (args: { jobId: string }) => {
      try {
        const cancelled = platform.jobs.cancel(args.jobId);
        const rec = platform.jobs.get(args.jobId);
        return ok({ cancelled, job: rec?.job ?? null });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_list_findings",
    {
      title: "List findings",
      description:
        "List evidence-linked findings for a target, optionally filtered by kind or confidence, with pagination.",
      inputSchema: listFindingsInput,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (args: {
      artifactId: string;
      kind?: string;
      confidence?: string;
      limit: number;
      offset: number;
    }) => {
      try {
        await platform.targets.require(args.artifactId);
        let findings = await platform.store.getFindings(args.artifactId);
        if (args.kind) findings = findings.filter((f) => f.kind === args.kind);
        if (args.confidence) findings = findings.filter((f) => f.confidence === args.confidence);
        const total = findings.length;
        const page = findings.slice(args.offset, args.offset + args.limit);
        return ok({ findings: page, total, offset: args.offset, limit: args.limit });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_get_evidence",
    {
      title: "Get evidence record",
      description:
        "Fetch one evidence record by id. Records are re-authenticated against their content digest before being served.",
      inputSchema: getEvidenceInput,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (args: { evidenceId: string }) => {
      try {
        const evidence = await platform.store.getEvidence(args.evidenceId);
        if (!evidence) {
          return fail(new VestigeError({
            code: "not_found",
            message: `Evidence '${args.evidenceId}' does not exist or failed re-verification.`,
            remediation: "List findings first and use evidenceIds referenced by them.",
            retryable: false,
          }));
        }
        return ok({ evidence, verified: verifyEvidence(evidence) });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_export_report",
    {
      title: "Export analysis report",
      description:
        "Export a deterministic markdown or JSON report for a target into the Vestige workspace and return its absolute path.",
      inputSchema: exportReportInput,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (args: { artifactId: string; format: "markdown" | "json" }) => {
      try {
        const artifact = await platform.targets.require(args.artifactId);
        const findings = await platform.store.getFindings(args.artifactId);
        const jobRows = platform.jobs
          .list()
          .filter((j) => j.artifactId === args.artifactId)
          .map((j) => ({
            jobId: j.jobId,
            providerId: j.providerId,
            status: j.status,
            finishedAt: j.finishedAt,
          }));
        const evidenceCount = await platform.store
          .artifactsWithFindings()
          .then(async () => {
            // Count evidence referenced by findings (cheap, bounded).
            const ids = new Set<string>();
            for (const f of findings) for (const id of f.evidenceIds) ids.add(id);
            return ids.size;
          });
        const dir = await platform.workspace.ensureDir("reports");
        const ext = args.format === "markdown" ? "md" : "json";
        const file = `${dir}/${args.artifactId}.${ext}`;
        const { writeFile } = await import("node:fs/promises");
        if (args.format === "markdown") {
          await writeFile(file, renderReport(artifact, findings, evidenceCount, jobRows), "utf8");
        } else {
          await writeFile(
            file,
            JSON.stringify({ artifact, findings, evidenceCount, jobs: jobRows }, null, 2),
            "utf8",
          );
        }
        return ok({ path: file, format: args.format, findingsCount: findings.length });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "vestige_diagnostics",
    {
      title: "Run self-diagnostics",
      description:
        "Report versions, configuration facts, data directories, and provider availability. Never contains secrets.",
      inputSchema: diagnosticsInput,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => {
      try {
        const providers = await platform.providers.availability();
        return ok({
          server: { name: PRODUCT.mcpServerName, version: PRODUCT.version },
          runtime: { node: process.version, platform: process.platform },
          dataDir: platform.config.dataDir,
          workDir: platform.config.workDir,
          allowedRootsConfigured: platform.config.allowedRoots.length,
          providers: providers.map((p) => ({
            id: p.descriptor.id,
            version: p.descriptor.version,
            formats: p.descriptor.formats,
            available: p.availability.available,
            ...(p.availability.available ? {} : { reason: p.availability.reason, guidance: p.availability.guidance }),
          })),
        });
      } catch (error) {
        return fail(error);
      }
    },
  );
};
