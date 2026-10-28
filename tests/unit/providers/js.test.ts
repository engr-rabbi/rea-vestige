import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { analyzeJavaScript, collectJsSources } from "../../../src/providers/javascript/analyze.js";
import { buildJsProject, JS_GROUND_TRUTH } from "../../fixtures/jsProject.js";
import type { AnalyzeRequest } from "../../../src/providers/types.js";

describe("JavaScript provider (fixture ground truth)", () => {
  let tmp: string;
  let projectDir: string;
  let artifactSha: string;
  const noopSignal = new AbortController().signal;

  beforeEach(async () => {
    tmp = await mkdtemp(path.join(os.tmpdir(), "vestige-js-"));
    projectDir = buildJsProject(path.join(tmp, "sample-app"));
    const { sha256Hex } = await import("../../../src/util/hash.js");
    const { readFile } = await import("node:fs/promises");
    artifactSha = sha256Hex(await readFile(path.join(projectDir, "main.js")));
    void artifactSha;
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  const makeRequest = (artifactId = "va_js", sha = "c".repeat(64)): AnalyzeRequest => ({
    artifactId,
    artifactPath: projectDir,
    artifactSha256: sha,
    format: "directory",
    capabilities: [],
    signal: noopSignal,
    onProgress: () => {},
  });

  it("collects JS sources excluding node_modules", async () => {
    const sources = await collectJsSources(projectDir, true);
    expect(sources.length).toBeGreaterThanOrEqual(3);
  });

  it("finds exactly the known import sources in main.js (ground truth)", async () => {
    const result = await analyzeJavaScript(makeRequest());
    const mainFindings = result.findings.filter(
      (f) => f.kind === "import" && f.location.artifactPath === "main.js",
    );
    const names = mainFindings.map((f) => f.name).sort();
    expect(names).toEqual([...JS_GROUND_TRUTH.mainJs.imports].sort());
  });

  it("finds the known IPC channels across files", async () => {
    const result = await analyzeJavaScript(makeRequest());
    const ipc = result.findings.filter((f) => f.kind === "ipc-channel");
    const channelNames = ipc.map((f) => f.name);
    for (const c of JS_GROUND_TRUTH.mainJs.ipcMainChannels) {
      expect(channelNames.some((n) => n.includes(`"${c}"`)), c).toBe(true);
    }
    for (const c of JS_GROUND_TRUTH.rendererJs.ipcRendererChannels) {
      expect(channelNames.some((n) => n.includes(`"${c}"`)), c).toBe(true);
    }
  });

  it("distinguishes ipcMain from ipcRenderer sides", async () => {
    const result = await analyzeJavaScript(makeRequest());
    const ipc = result.findings.filter((f) => f.kind === "ipc-channel");
    const mainSide = ipc.filter((f) => f.attributes.api === "ipcMain");
    const rendererSide = ipc.filter((f) => f.attributes.api === "ipcRenderer");
    expect(mainSide.length).toBe(JS_GROUND_TRUTH.mainJs.ipcMainChannels.length);
    expect(rendererSide.length).toBe(JS_GROUND_TRUTH.rendererJs.ipcRendererChannels.length);
  });

  it("finds exactly the known express routes (ground truth)", async () => {
    const result = await analyzeJavaScript(makeRequest());
    const routes = result.findings.filter((f) => f.kind === "route");
    const routeNames = routes.map((f) => f.name).sort();
    expect(routeNames).toEqual(
      JS_GROUND_TRUTH.serverJs.routes.map((r) => `${r.method} ${r.path}`).sort(),
    );
  });

  it("finds exports in renderer-bridge.js", async () => {
    const result = await analyzeJavaScript(makeRequest());
    const exportsForFile = result.findings.filter(
      (f) => f.kind === "export" && f.location.artifactPath === "lib/renderer-bridge.js",
    );
    expect(exportsForFile.map((f) => f.name).sort()).toEqual(
      [...JS_GROUND_TRUTH.rendererJs.exports].sort(),
    );
  });

  it("reads manifest facts: electron dependency + main entry", async () => {
    const result = await analyzeJavaScript(makeRequest());
    const deps = result.findings.filter((f) => f.kind === "dependency");
    expect(deps.some((f) => f.name === "electron@31.0.0")).toBe(true);
    const entries = result.findings.filter((f) => f.kind === "entrypoint");
    expect(entries.some((f) => f.name === JS_GROUND_TRUTH.packageJson.main)).toBe(true);
  });

  it("links every finding to at least one evidence record", async () => {
    const result = await analyzeJavaScript(makeRequest());
    const evidenceIds = new Set(result.evidence.map((e) => e.evidenceId));
    expect(evidenceIds.size).toBeGreaterThan(0);
    for (const f of result.findings) {
      expect(f.evidenceIds.length).toBeGreaterThan(0);
      for (const id of f.evidenceIds) {
        expect(evidenceIds.has(id), `finding ${f.name} references missing evidence ${id}`).toBe(true);
      }
    }
  });

  it("records evidence confidence as static-inference for AST facts", async () => {
    const result = await analyzeJavaScript(makeRequest());
    const astEvidence = result.evidence.filter((e) => e.kind === "ast-parse");
    expect(astEvidence.length).toBeGreaterThan(0);
    for (const e of astEvidence) {
      expect(e.confidence).toBe("static-inference");
      expect(e.method).toContain("acorn");
    }
  });

  it("reports parse gaps instead of failing on mixed content", async () => {
    // Add a syntactically broken file; analysis must continue.
    const { writeFile } = await import("node:fs/promises");
    await writeFile(path.join(projectDir, "broken.js"), "import { from (;");
    const result = await analyzeJavaScript(makeRequest());
    const gaps = result.evidence.filter((e) =>
      typeof e.observation === "object" && e.observation !== null && "parseGap" in e.observation,
    );
    expect(gaps.length).toBeGreaterThan(0);
    expect(result.diagnostics.filesFailed).toBeGreaterThan(0);
  });
});
