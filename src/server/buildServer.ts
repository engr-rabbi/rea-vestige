import { McpServer, ResourceTemplate, type Variables } from "@modelcontextprotocol/server";
import { z } from "zod";
import { PRODUCT } from "../version.js";
import { projectError } from "../errors/errors.js";
import { renderReport } from "../services/analysisService.js";
import type { Platform } from "./context.js";
import { registerTools } from "./tools.js";

/**
 * MCP server assembly: tools + resources + prompts, with server instructions
 * that teach agents the evidence-first workflow.
 */

const serverInstructions = (): string => `
${PRODUCT.displayName} is an evidence-driven reverse engineering platform.

Workflow:
1. vestige_register_target — register an authorized artifact (path → SHA-256 commitment + format identification).
2. vestige_list_providers — see which providers can analyze it and whether external tools (e.g. Ghidra) are available.
3. vestige_analyze — start an analysis job; poll vestige_job_status (progress notifications arrive if you pass a progressToken in _meta).
4. vestige_list_findings — browse evidence-linked findings; every finding carries provider, method, location, and confidence.
5. vestige_get_evidence — fetch the underlying observation for any finding (records are tamper-checked).
6. vestige_export_report — produce a deterministic markdown/JSON report.

Confidence semantics:
- observed-fact: read directly from artifact bytes.
- static-inference: derived by static analysis.
- runtime-observation: produced by executing the target (Vestige never does this by default).
- ai-interpretation: AI-generated interpretation.
- hypothesis: unverified idea.

Safety: targets are analyzed read-only; paths are canonicalized and symlink-checked; external tools run shell-free with bounded output and hard timeouts; unknown targets are never executed.
`.trim();

export const buildServer = (platform: Platform): McpServer => {
  const server = new McpServer(
    { name: PRODUCT.mcpServerName, version: PRODUCT.version },
    {
      capabilities: {
        resources: {},
        prompts: {},
      },
      instructions: serverInstructions(),
    },
  );

  registerTools(server, platform);

  // ---- Resources: large artifacts live here, not in tool responses ----
  server.registerResource(
    "target",
    new ResourceTemplate("vestige://target/{artifactId}", {
      list: async () => {
        const targets = await platform.targets.list();
        return {
          resources: targets.map((t) => ({
            uri: `vestige://target/${t.artifactId}`,
            name: t.label ?? t.path,
            mimeType: "application/json",
          })),
        };
      },
    }),
    { mimeType: "application/json" },
    async (uri: URL, variables: Variables) => {
      try {
        const artifact = await platform.targets.require(String(variables.artifactId));
        return {
          contents: [
            { uri: uri.href, mimeType: "application/json", text: JSON.stringify(artifact, null, 2) },
          ],
        };
      } catch (error) {
        throw new Error(projectError(error).message);
      }
    },
  );

  server.registerResource(
    "target-findings",
    new ResourceTemplate("vestige://target/{artifactId}/findings", {
      list: undefined,
    }),
    { mimeType: "application/json" },
    async (uri: URL, variables: Variables) => {
      try {
        const artifact = await platform.targets.require(String(variables.artifactId));
        const findings = await platform.store.getFindings(artifact.artifactId);
        return {
          contents: [
            { uri: uri.href, mimeType: "application/json", text: JSON.stringify(findings, null, 2) },
          ],
        };
      } catch (error) {
        throw new Error(projectError(error).message);
      }
    },
  );

  server.registerResource(
    "target-report",
    new ResourceTemplate("vestige://target/{artifactId}/report.md", {
      list: undefined,
    }),
    { mimeType: "text/markdown" },
    async (uri: URL, variables: Variables) => {
      try {
        const artifact = await platform.targets.require(String(variables.artifactId));
        const findings = await platform.store.getFindings(artifact.artifactId);
        const report = renderReport(
          artifact,
          findings,
          findings.reduce((n, f) => n + f.evidenceIds.length, 0),
          platform.jobs
            .list()
            .filter((j) => j.artifactId === artifact.artifactId)
            .map((j) => ({ jobId: j.jobId, providerId: j.providerId, status: j.status, finishedAt: j.finishedAt })),
        );
        return {
          contents: [{ uri: uri.href, mimeType: "text/markdown", text: report }],
        };
      } catch (error) {
        throw new Error(projectError(error).message);
      }
    },
  );

  // ---- Prompts: guided investigations ----
  server.registerPrompt(
    "vestige_investigate_target",
    {
      title: "Guided target investigation",
      description:
        "Step-by-step investigation plan for a registered target using Vestige tools, with evidence-first guidance.",
      argsSchema: z.object({
        artifactId: z.string().min(4).describe("Registered artifact id (va_…)"),
      }),
    },
    ({ artifactId }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              `Investigate registered target ${artifactId} with the Vestige MCP tools.`,
              "Plan:",
              "1. vestige_get_target to confirm identity (sha256, format, architecture).",
              "2. vestige_list_providers to pick the best available provider for this format.",
              `3. vestige_analyze with artifactId ${artifactId}; track progress via vestige_job_status.`,
              "4. vestige_list_findings grouped by kind; for each important claim open the backing evidence with vestige_get_evidence.",
              "5. Distinguish observed-fact from static-inference claims in your conclusions and cite finding/evidence ids.",
              "6. vestige_export_report for a durable summary.",
              "Rules: never infer unsupported capabilities; when providers disagree, report the disagreement; do not fabricate symbols or code.",
            ].join("\n"),
          },
        },
      ],
    }),
  );

  server.registerPrompt(
    "vestige_triage_javascript",
    {
      title: "JavaScript/Electron triage",
      description:
        "Focused triage plan for JavaScript and Electron artifacts: entry points, IPC surface, routes, dependencies.",
      argsSchema: z.object({
        artifactId: z.string().min(4).describe("Registered artifact id (va_…)"),
      }),
    },
    ({ artifactId }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              `Triage the JavaScript/Electron target ${artifactId}.`,
              "1. vestige_get_target — confirm format.",
              `2. vestige_analyze artifactId=${artifactId} provider=javascript.`,
              "3. From findings: list entrypoint, ipc-channel, route, dependency kinds separately.",
              "4. For every ipc-channel finding, note whether the channel name is a literal string (observed) or dynamic (unknown).",
              "5. Check imports/exports for privileged APIs (nodeIntegration, remote, child_process, fs) and report them with evidence ids.",
              "6. Summarize the IPC boundary surface and recommend what deeper analysis would add.",
            ].join("\n"),
          },
        },
      ],
    }),
  );

  return server;
};
