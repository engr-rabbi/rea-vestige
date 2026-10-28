import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  createPlatform,
  type Platform,
} from "../../src/server/context.js";
import { loadConfig } from "../../src/config/config.js";
import { buildServer } from "../../src/server/buildServer.js";
import { InMemoryTransport, type McpServer } from "@modelcontextprotocol/server";
import { Client } from "@modelcontextprotocol/client";

/**
 * Real MCP client ↔ server conformance: initialize, tools/list, tool calls,
 * resources/read — over InMemoryTransport using the official SDK client.
 */

let platform: Platform;
let dataDir: string;
let targetDir: string;
let artifactId: string;
let client: Client;
let server: McpServer;

beforeEach(async () => {
  dataDir = await mkdtemp(path.join(os.tmpdir(), "vestige-mcp-"));
  targetDir = await mkdtemp(path.join(os.tmpdir(), "vestige-mcp-tgt-"));
  const config = loadConfig({ VESTIGE_DATA_DIR: dataDir, VESTIGE_WORK_DIR: path.join(dataDir, "work") });
  platform = await createPlatform(config);
  server = buildServer(platform);
  client = new Client({ name: "vestige-test-client", version: "0.1.0" });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await server.connect(serverT);
  await client.connect(clientT);

  const file = path.join(targetDir, "sample.js");
  await writeFile(file, "import express from 'express';\nexport default 1;\n");
  const reg = await platform.targets.register(file);
  artifactId = reg.artifact.artifactId;
});

afterEach(async () => {
  await client.close();
  await server.close();
  await platform.close();
  await rm(dataDir, { recursive: true, force: true });
  await rm(targetDir, { recursive: true, force: true });
});

describe("MCP server conformance", () => {
  it("exchanges initialize handshake", async () => {
    const serverInfo = await client.getServerVersion();
    expect(serverInfo?.name).toBe("vestige-mcp");
  });

  it("advertises the tool surface", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toContain("vestige_register_target");
    expect(names).toContain("vestige_analyze");
    expect(names).toContain("vestige_list_findings");
    expect(names).toContain("vestige_get_evidence");
    expect(names).toContain("vestige_diagnostics");
    expect(names.length).toBeGreaterThanOrEqual(10);
    // Zod contracts projected into advertised input schemas
    const analyze = tools.find((t) => t.name === "vestige_analyze");
    expect(analyze?.inputSchema).toBeTruthy();
    expect((analyze?.inputSchema as { type?: string }).type).toBe("object");
  });

  it("registers a target through the MCP tool", async () => {
    const file = path.join(targetDir, "second.js");
    await writeFile(file, "const x = require('path');\n");
    const result = await client.callTool({
      name: "vestige_register_target",
      arguments: { path: file, label: "second" },
    });
    expect(result.isError).toBeFalsy();
    const structured = result.structuredContent as { artifact?: { format: string } };
    expect(structured.artifact?.format).toBe("javascript");
  });

  it("rejects invalid paths with typed error payload in structuredContent", async () => {
    const result = await client.callTool({
      name: "vestige_register_target",
      arguments: { path: "/nonexistent/vestige/xyz" },
    });
    expect(result.isError).toBe(true);
    const structured = result.structuredContent as { error?: { code: string; remediation: string } };
    expect(structured.error?.code).toBe("path_rejected");
    expect(structured.error?.remediation).toBeTruthy();
  });

  it("rejects unregistered targets on analyze (job fails with typed error)", async () => {
    const result = await client.callTool({
      name: "vestige_analyze",
      arguments: { artifactId: "va_doesnotexist00" },
    });
    expect(result.isError).toBeFalsy();
    const jobId = (result.structuredContent as { jobId: string }).jobId;
    // Async job: the failure surfaces via vestige_job_status.
    let job: { status: string; error?: { code: string } } | undefined;
    for (let i = 0; i < 20; i++) {
      const status = await client.callTool({ name: "vestige_job_status", arguments: { jobId } });
      job = (status.structuredContent as { job: typeof job }).job;
      if (job?.status === "failed") break;
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(job?.status).toBe("failed");
    expect(["path_rejected", "provider_unavailable"]).toContain(job?.error?.code);
  });

  it("completes a full analyze→findings→evidence workflow", async () => {
    // Register a directory target (JS provider supports it)
    const reg = await client.callTool({
      name: "vestige_register_target",
      arguments: { path: targetDir },
    });
    const structured = reg.structuredContent as { artifact: { artifactId: string } };
    const dirId = structured.artifact.artifactId;

    const analyze = await client.callTool({
      name: "vestige_analyze",
      arguments: { artifactId: dirId, provider: "javascript" },
    });
    expect(analyze.isError).toBeFalsy();
    const jobRef = analyze.structuredContent as { jobId: string };

    // Wait for job completion
    let job: { status: string; evidenceCount: number; error?: { message: string } } | undefined;
    for (let i = 0; i < 50; i++) {
      const status = await client.callTool({
        name: "vestige_job_status",
        arguments: { jobId: jobRef.jobId },
      });
      job = (status.structuredContent as { job: typeof job }).job;
      if (job?.status === "completed" || job?.status === "failed" || job?.status === "cancelled") break;
      await new Promise((r) => setTimeout(r, 100));
    }
    expect(job?.status, JSON.stringify(job?.error)).toBe("completed");
    expect(job?.evidenceCount ?? 0).toBeGreaterThan(0);

    const findings = await client.callTool({
      name: "vestige_list_findings",
      arguments: { artifactId: dirId, limit: 50 },
    });
    const list = findings.structuredContent as {
      findings: Array<{ findingId: string; evidenceIds: string[]; kind: string }>;
      total: number;
    };
    expect(list.total).toBeGreaterThan(0);

    const evidenceId = list.findings[0]?.evidenceIds[0];
    expect(evidenceId).toBeTruthy();
    const evidence = await client.callTool({
      name: "vestige_get_evidence",
      arguments: { evidenceId },
    });
    const ev = evidence.structuredContent as { verified: boolean; evidence: { provider: { id: string } } };
    expect(ev.verified).toBe(true);
    expect(ev.evidence.provider.id).toBe("javascript");
  });

  it("cancels a running job", async () => {
    const reg = await client.callTool({
      name: "vestige_register_target",
      arguments: { path: targetDir },
    });
    const dirId = (reg.structuredContent as { artifact: { artifactId: string } }).artifact.artifactId;
    const analyze = await client.callTool({
      name: "vestige_analyze",
      arguments: { artifactId: dirId, provider: "javascript" },
    });
    const jobId = (analyze.structuredContent as { jobId: string }).jobId;
    const cancelled = await client.callTool({
      name: "vestige_job_cancel",
      arguments: { jobId },
    });
    expect(cancelled.isError).toBeFalsy();
    // Wait for terminal state
    for (let i = 0; i < 30; i++) {
      const status = await client.callTool({ name: "vestige_job_status", arguments: { jobId } });
      const j = (status.structuredContent as { job: { status: string } }).job;
      if (["completed", "failed", "cancelled"].includes(j.status)) break;
      await new Promise((r) => setTimeout(r, 50));
    }
  });

  it("serves resources: target metadata and findings", async () => {
    const { resources } = await client.listResources();
    expect(resources.length).toBeGreaterThan(0);
    const read = await client.readResource({ uri: `vestige://target/${artifactId}` });
    const first = read.contents[0];
    const text = first && "text" in first ? first.text : "";
    expect(JSON.parse(text).artifactId).toBe(artifactId);
  });

  it("serves prompts: guided investigation", async () => {
    const { prompts } = await client.listPrompts();
    const names = prompts.map((p) => p.name);
    expect(names).toContain("vestige_investigate_target");
    expect(names).toContain("vestige_triage_javascript");
    const result = await client.getPrompt({
      name: "vestige_investigate_target",
      arguments: { artifactId },
    });
    expect(result.messages.length).toBeGreaterThan(0);
  });

  it("reports diagnostics including availability guidance", async () => {
    const result = await client.callTool({ name: "vestige_diagnostics", arguments: {} });
    const diag = result.structuredContent as {
      providers: Array<{ id: string; available: boolean; guidance?: string }>;
    };
    const ids = diag.providers.map((p) => p.id).sort();
    expect(ids).toEqual(["ghidra", "javascript", "native"]);
    const ghidra = diag.providers.find((p) => p.id === "ghidra");
    if (ghidra && !ghidra.available) {
      expect(ghidra.guidance).toContain("GHIDRA_INSTALL_DIR");
    }
  });

  it("validates tool inputs (Zod contract enforcement)", async () => {
    // The SDK converts schema violations into isError tool results.
    const result = await client.callTool({
      name: "vestige_analyze",
      arguments: { artifactId: 12345 as unknown as string },
    });
    expect(result.isError).toBe(true);
  });
});
