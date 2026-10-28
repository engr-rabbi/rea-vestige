import { describe, expect, it, afterAll } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

/**
 * End-to-end: spawn the built Vestige server as a real subprocess (stdio
 * transport), connect the official SDK client, and run register → analyze →
 * findings → evidence → report. This validates the documented quick-start
 * against the real transport, not an in-process fake.
 */

const SERVER_ENTRY = path.resolve(import.meta.dirname ?? ".", "../../dist/cli/main.js");
const client = new Client({ name: "vestige-e2e-client", version: "0.1.0" });

const dataDir = await mkdtemp(path.join(os.tmpdir(), "vestige-e2e-data-"));
const targetDir = await mkdtemp(path.join(os.tmpdir(), "vestige-e2e-tgt-"));

afterAll(async () => {
  await client.close().catch(() => {});
  await rm(dataDir, { recursive: true, force: true });
  await rm(targetDir, { recursive: true, force: true });
});

describe("e2e: stdio MCP server", () => {
  it("completes the documented workflow over real stdio", async () => {
    // Prepare a target: a small Electron-style app fixture.
    await writeFile(
      path.join(targetDir, "main.js"),
      `const { app, ipcMain } = require("electron");
ipcMain.handle("app:ping", () => "pong");
module.exports = app;
`,
    );
    await writeFile(
      path.join(targetDir, "package.json"),
      JSON.stringify({ name: "e2e-app", main: "main.js", dependencies: { electron: "31.0.0" } }),
    );

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [SERVER_ENTRY, "mcp"],
      env: {
        ...process.env,
        VESTIGE_DATA_DIR: dataDir,
        VESTIGE_WORK_DIR: path.join(dataDir, "work"),
        VESTIGE_LOG_LEVEL: "error",
      } as Record<string, string>,
    });
    await client.connect(transport);

    // 1. Server identity
    const info = await client.getServerVersion();
    expect(info?.name).toBe("vestige-mcp");

    // 2. Tool discovery
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain("vestige_register_target");

    // 3. Register the target
    const reg = await client.callTool({
      name: "vestige_register_target",
      arguments: { path: targetDir },
    });
    expect(reg.isError).toBeFalsy();
    const artifactId = (reg.structuredContent as { artifact: { artifactId: string } })
      .artifact.artifactId;

    // 4. Analyze with the javascript provider
    const analyze = await client.callTool({
      name: "vestige_analyze",
      arguments: { artifactId, provider: "javascript" },
    });
    expect(analyze.isError).toBeFalsy();
    const jobId = (analyze.structuredContent as { jobId: string }).jobId;

    // 5. Poll job status until terminal
    let status = "";
    let evidenceCount = 0;
    for (let i = 0; i < 100; i++) {
      const s = await client.callTool({ name: "vestige_job_status", arguments: { jobId } });
      const job = (s.structuredContent as { job: { status: string; evidenceCount: number; error?: { message: string } } }).job;
      status = job.status;
      evidenceCount = job.evidenceCount;
      if (["completed", "failed", "cancelled"].includes(status)) {
        if (status === "failed") throw new Error(`analysis failed: ${job.error?.message}`);
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    expect(status).toBe("completed");
    expect(evidenceCount).toBeGreaterThan(0);

    // 6. Findings + evidence retrieval with verification
    const findings = await client.callTool({
      name: "vestige_list_findings",
      arguments: { artifactId, kind: "ipc-channel" },
    });
    const ipcFindings = (findings.structuredContent as {
      findings: Array<{ name: string; evidenceIds: string[] }>;
    }).findings;
    expect(ipcFindings.some((f) => f.name.includes("app:ping"))).toBe(true);

    const evidence = await client.callTool({
      name: "vestige_get_evidence",
      arguments: { evidenceId: ipcFindings[0]?.evidenceIds[0] },
    });
    expect((evidence.structuredContent as { verified: boolean }).verified).toBe(true);

    // 7. Export report (markdown)
    const report = await client.callTool({
      name: "vestige_export_report",
      arguments: { artifactId, format: "markdown" },
    });
    const reportPath = (report.structuredContent as { path: string }).path;
    const { readFile } = await import("node:fs/promises");
    const reportBody = await readFile(reportPath, "utf8");
    expect(reportBody).toContain("Vestige analysis report");
    expect(reportBody).toContain(artifactId);

    // 8. Resources and prompts over the same session
    const { resources } = await client.listResources();
    expect(resources.some((r) => r.uri === `vestige://target/${artifactId}`)).toBe(true);
    const { prompts } = await client.listPrompts();
    expect(prompts.map((p) => p.name)).toContain("vestige_investigate_target");
  }, 120_000);
});
