import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "../../src/config/config.js";
import { createPlatform } from "../../src/server/context.js";
import { analyzeJavaScript } from "../../src/providers/javascript/analyze.js";
import { parseElf } from "../../src/providers/native/elf.js";
import { buildElf64, ELF64_GROUND_TRUTH } from "../fixtures/builders.js";
import { buildJsProject, JS_GROUND_TRUTH } from "../fixtures/jsProject.js";

/**
 * Regression tests: golden expectations over deterministic fixtures.
 * If a parser change alters these outputs, the change must be reviewed —
 * this is the platform's accuracy guardrail (Stage F).
 */

describe("regression: native ELF symbols", () => {
  it("symbol names remain stable (golden list)", () => {
    const info = parseElf(buildElf64());
    const golden = [...ELF64_GROUND_TRUTH.symbols.map((s) => s.name)].sort();
    expect(info.symbols.map((s) => s.name).sort()).toEqual(golden);
  });

  it("symbol addressing remains stable (golden values)", () => {
    const info = parseElf(buildElf64());
    for (const s of ELF64_GROUND_TRUTH.symbols) {
      const found = info.symbols.find((x) => x.name === s.name);
      expect(`${found?.type}:${found?.value}`).toBe(`${s.type}:${s.value.toString(16)}`);
    }
  });
});

describe("regression: javascript analysis golden facts", () => {
  let tmp: string;
  let projectDir: string;

  beforeEach(async () => {
    tmp = await mkdtemp(path.join(os.tmpdir(), "vestige-golden-"));
    projectDir = buildJsProject(path.join(tmp, "app"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it("IPC channel count is stable (golden)", async () => {
    const result = await analyzeJavaScript({
      artifactId: "va_golden",
      artifactPath: projectDir,
      artifactSha256: "e".repeat(64),
      format: "directory",
      capabilities: [],
      signal: new AbortController().signal,
      onProgress: () => {},
    });
    const ipc = result.findings.filter((f) => f.kind === "ipc-channel");
    const expected =
      JS_GROUND_TRUTH.mainJs.ipcMainChannels.length +
      JS_GROUND_TRUTH.rendererJs.ipcRendererChannels.length;
    expect(ipc).toHaveLength(expected);
  });

  it("route set is stable (golden)", async () => {
    const result = await analyzeJavaScript({
      artifactId: "va_golden2",
      artifactPath: projectDir,
      artifactSha256: "f".repeat(64),
      format: "directory",
      capabilities: [],
      signal: new AbortController().signal,
      onProgress: () => {},
    });
    const routes = result.findings.filter((f) => f.kind === "route").map((f) => f.name).sort();
    expect(routes).toEqual(JS_GROUND_TRUTH.serverJs.routes.map((r) => `${r.method} ${r.path}`).sort());
  });
});

describe("regression: full platform workflow determinism", () => {
  it("two identical analyses produce identical finding identity sets", async () => {
    const dataDir = await mkdtemp(path.join(os.tmpdir(), "vestige-det-"));
    const targetDir = await mkdtemp(path.join(os.tmpdir(), "vestige-det-t-"));
    const config = loadConfig({ VESTIGE_DATA_DIR: dataDir });
    const platform = await createPlatform(config);
    try {
      const file = path.join(targetDir, "stable.js");
      await writeFile(file, "import fs from 'node:fs';\nexport const version = 1;\n");
      const reg = await platform.targets.register(file);
      const rec1 = platform.jobs.create(reg.artifact.artifactId, "javascript", []);
      await platform.analysis.run(rec1, "javascript");
      const ids1 = (await platform.store.getFindings(reg.artifact.artifactId))
        .map((f) => f.findingId)
        .sort();
      // Second identical run (fresh cache to force re-run)
      const rec2 = platform.jobs.create(reg.artifact.artifactId, "javascript", []);
      await platform.analysis.run(rec2, "javascript");
      const ids2 = (await platform.store.getFindings(reg.artifact.artifactId))
        .map((f) => f.findingId)
        .sort();
      expect(ids1).toEqual(ids2);
    } finally {
      await platform.close();
      await rm(dataDir, { recursive: true, force: true });
      await rm(targetDir, { recursive: true, force: true });
    }
  });
});
