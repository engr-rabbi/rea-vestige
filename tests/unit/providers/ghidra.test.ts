import { describe, expect, it } from "vitest";
import os from "node:os";
import path from "node:path";
import { buildAnalyzeHeadlessArgv, runGhidraAnalysis, VESTIGE_GHIDRA_SCRIPT } from "../../../src/providers/ghidra/bridge.js";
import { detectGhidraInstallation } from "../../../src/providers/ghidra/availability.js";
import type { AnalyzeRequest } from "../../../src/providers/types.js";

describe("Ghidra bridge (documented integration boundary)", () => {
  it("builds argv arrays with script and output paths (no shell)", () => {
    const argv = buildAnalyzeHeadlessArgv({
      analyzeHeadlessPath: "/opt/ghidra/support/analyzeHeadless",
      projectDir: "/tmp/ws/project",
      projectName: "vestige",
      artifactPath: "/targets/sample.elf",
      scriptDir: "/tmp/ws/scripts",
      outputPath: "/tmp/ws/ghidra-dump.json",
    });
    expect(Array.isArray(argv)).toBe(true);
    expect(argv).toContain("-import");
    expect(argv).toContain("/targets/sample.elf");
    expect(argv).toContain("-postScript");
    expect(argv).toContain("vestige_dump.py");
    expect(argv).toContain("-deleteProject");
  });

  it("script is a Ghidra headless script that never executes the target", () => {
    expect(VESTIGE_GHIDRA_SCRIPT).toContain("getScriptArgs()");
    expect(VESTIGE_GHIDRA_SCRIPT).toContain("getCurrentProgram()");
    expect(VESTIGE_GHIDRA_SCRIPT).toContain("json.dump");
  });

  it("reports unavailable with actionable guidance when Ghidra is missing", async () => {
    const result = await detectGhidraInstallation("/nonexistent/ghidra", "linux");
    expect(result.available).toBe(false);
    if (!result.available) {
      expect(result.reason).toContain("does not contain support/analyzeHeadless");
      expect(result.guidance).toContain("ghidra-sre.org");
      expect(result.guidance).toContain("GHIDRA_INSTALL_DIR");
    }
  });

  it("detects a fake installation layout", async () => {
    const { mkdtemp, mkdir, writeFile, chmod, rm } = await import("node:fs/promises");
    const tmp = await mkdtemp(path.join(os.tmpdir(), "vestige-ghidra-detect-"));
    try {
      const support = `${tmp}/support`;
      await mkdir(support, { recursive: true });
      const scriptPath = `${support}/analyzeHeadless`;
      await writeFile(scriptPath, "#!/bin/sh\n");
      await chmod(scriptPath, 0o755);
      const result = await detectGhidraInstallation(tmp, "linux");
      expect(result.available).toBe(true);
      if (result.available) {
        expect(result.installation?.analyzeHeadlessPath).toBe(scriptPath);
      }
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });

  const noopSignal = new AbortController().signal;
  const makeRequest = (): AnalyzeRequest => ({
    artifactId: "va_ghidra",
    artifactPath: "/targets/sample.elf",
    artifactSha256: "d".repeat(64),
    format: "elf",
    capabilities: ["decompile"],
    signal: noopSignal,
    onProgress: () => {},
  });

  const dump = {
    schema: "vestige.ghidra.dump/1",
    programName: "sample.elf",
    languageID: "x86:LE:64:default",
    imageBase: "00400000",
    functionCount: 2,
    functions: [
      {
        entry: "00401000",
        name: "vestige_main",
        isThunk: false,
        bodySize: 32,
        params: [{ name: "argc", type: "int" }],
        callers: ["00402000"],
        callees: ["00401040"],
        decompiled: "int vestige_main(int argc) { return 0; }",
      },
      {
        entry: "00401040",
        name: "vestige_helper",
        isThunk: false,
        bodySize: 16,
        params: [],
        callers: [],
        callees: [],
        decompiled: null,
      },
    ],
  };

  it("parses and converts a valid dump into findings + evidence", async () => {
    const { mkdtemp, writeFile } = await import("node:fs/promises");
    const ws = await mkdtemp(path.join(os.tmpdir(), "vestige-ghidra-run-"));
    await writeFile(`${ws}/ghidra-dump.json`, JSON.stringify(dump));
    const result = await runGhidraAnalysis(
      { ...makeRequest(), __scratchDir: ws } as AnalyzeRequest,
      {
        run: async () => ({ code: 0, stdout: "", stderr: "", timedOut: false }),
        timeoutMs: 1000,
        install: {
          analyzeHeadlessPath: "/fake/analyzeHeadless",
          installDir: "/fake",
          platform: "posix",
        },
      },
    );
    const functions = result.findings.filter((f) => f.kind === "function");
    expect(functions.map((f) => f.name).sort()).toEqual(["vestige_helper", "vestige_main"]);
    const main = functions.find((f) => f.name === "vestige_main");
    expect(main?.location.virtualAddress).toBe("0x00401000");
    // Decompile evidence exists for the function with decompiled output
    const decompiled = result.evidence.filter((e) => {
      const obs = e.observation as { decompiled?: string };
      return typeof obs === "object" && obs !== null && "decompiled" in obs;
    });
    expect(decompiled.length).toBe(1);
  });

  it("rejects malformed dumps (schema-validated)", async () => {
    const { mkdtemp, writeFile } = await import("node:fs/promises");
    const ws = await mkdtemp(path.join(os.tmpdir(), "vestige-ghidra-bad-"));
    await writeFile(`${ws}/ghidra-dump.json`, JSON.stringify({ schema: "wrong" }));
    await expect(
      runGhidraAnalysis(
        { ...makeRequest(), __scratchDir: ws } as AnalyzeRequest,
        {
          run: async () => ({ code: 0, stdout: "", stderr: "", timedOut: false }),
          timeoutMs: 1000,
          install: { analyzeHeadlessPath: "/fake", installDir: "/fake", platform: "posix" },
        },
      ),
    ).rejects.toThrow();
  });

  it("surfaces analyzeHeadless failures", async () => {
    await expect(
      runGhidraAnalysis(makeRequest(), {
        run: async () => ({ code: 1, stdout: "", stderr: "fatal", timedOut: false }),
        timeoutMs: 1000,
        install: { analyzeHeadlessPath: "/fake", installDir: "/fake", platform: "posix" },
      }),
    ).rejects.toThrow(/exited with code 1/);
  });

  it("surfaces timeouts", async () => {
    await expect(
      runGhidraAnalysis(makeRequest(), {
        run: async () => ({ code: null, stdout: "", stderr: "", timedOut: true }),
        timeoutMs: 1000,
        install: { analyzeHeadlessPath: "/fake", installDir: "/fake", platform: "posix" },
      }),
    ).rejects.toThrow(/exceeded/);
  });
});
