import { mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import { buildEvidence } from "../../domain/evidence.js";
import { buildFinding } from "../../domain/finding.js";
import type { AnalyzeRequest, ProviderResult } from "../types.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Finding } from "../../domain/finding.js";

/**
 * Ghidra headless bridge (documented integration boundary).
 *
 * How it works:
 *  1. Vestige writes `vestige_dump.py` (a Ghidra headless script) into a
 *     scratch workspace owned by this run.
 *  2. Vestige launches `analyzeHeadless <projectDir> <projectName> -import
 *     <artifact> -scriptPath <ws> -postScript vestige_dump.py <out.json>`
 *     with argv arrays only, a hard timeout, and abort support.
 *  3. The script exports function inventory, references, and decompiled
 *     signatures as JSON; Vestige validates the JSON shape with Zod and
 *     converts it into evidence + findings.
 *
 * The Ghidra-side script executes only inside the operator's Ghidra
 * installation, on a copy of the target imported into a disposable project.
 * Vestige never executes the target itself. Without Ghidra installed the
 * provider reports `unavailable` with installation guidance; every
 * argument-construction and output-parsing step is unit-tested against
 * fixtures, so the bridge contract is verified without a Ghidra install.
 */

export const buildAnalyzeHeadlessArgv = (options: {
  analyzeHeadlessPath: string;
  projectDir: string;
  projectName: string;
  artifactPath: string;
  scriptDir: string;
  outputPath: string;
}): string[] => [
  options.analyzeHeadlessPath,
  options.projectDir,
  options.projectName,
  "-import",
  options.artifactPath,
  "-analysisTimeoutPerFile",
  "600",
  "-scriptPath",
  options.scriptDir,
  "-postScript",
  "vestige_dump.py",
  options.outputPath,
  "-deleteProject",
];

/** The Ghidra headless script content (Jython, Ghidra 11.x compatible). */
export const VESTIGE_GHIDRA_SCRIPT = `# vestige_dump.py — Ghidra headless script for the Vestige platform.
# Writes a bounded JSON inventory of functions, references, and data to argv.
# Runs inside Ghidra's JVM; it never executes the analyzed target.
import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0]
max_functions = 5000

program = getCurrentProgram()
fm = program.getFunctionManager()
monitor = ConsoleTaskMonitor()

functions = []
listing = program.getListing()
di = DecompInterface()
di.openProgram(program)

for func in fm.getFunctions(True):
    if len(functions) >= max_functions:
        break
    entry = str(func.getEntryPoint())
    body_size = int(func.getBody().getNumAddresses())
    params = []
    try:
        for p in func.getParameters():
            params.append({"name": str(p.getName()), "type": str(p.getDataType())})
    except Exception:
        pass
    called = []
    try:
        for callee in func.getCalledFunctions(monitor):
            called.append(str(callee.getEntryPoint()))
    except Exception:
        pass
    decompiled = None
    try:
        result = di.decompileFunction(func, 20, monitor)
        if result.decompileCompleted():
            decompiled = result.getDecompiledFunction().getC()
            if len(decompiled) > 8000:
                decompiled = decompiled[:8000]
    except Exception:
        pass
    functions.append({
        "entry": entry,
        "name": str(func.getName()),
        "isThunk": bool(func.isThunk()),
        "bodySize": body_size,
        "params": params,
        "callers": [str(c) for c in func.getCallingFunctions(monitor)][:50],
        "callees": called[:50],
        "decompiled": decompiled,
    })

payload = {
    "schema": "vestige.ghidra.dump/1",
    "programName": str(program.getName()),
    "languageID": str(program.getLanguageID()),
    "imageBase": str(program.getImageBase()),
    "functionCount": len(functions),
    "functions": functions,
}

with open(out_path, "w") as handle:
    json.dump(payload, handle)
print("VESTIGE_DUMP_WRITTEN " + out_path)
`;

const dumpSchema = z.object({
  schema: z.literal("vestige.ghidra.dump/1"),
  programName: z.string(),
  languageID: z.string(),
  imageBase: z.string(),
  functionCount: z.number().int().nonnegative(),
  functions: z
    .array(
      z.object({
        entry: z.string(),
        name: z.string(),
        isThunk: z.boolean(),
        bodySize: z.number().int().nonnegative(),
        params: z.array(z.object({ name: z.string(), type: z.string() })),
        callers: z.array(z.string()),
        callees: z.array(z.string()),
        decompiled: z.string().nullable().optional(),
      }),
    )
    .max(5000),
});

export interface GhidraRunnerOptions {
  run: (options: {
    command: string;
    argv: string[];
    timeoutMs: number;
    signal?: AbortSignal;
  }) => Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean }>;
  timeoutMs: number;
  install: { analyzeHeadlessPath: string; installDir: string; platform: string };
}

/**
 * Execute the Ghidra headless bridge and convert the validated dump into
 * evidence + findings. Runs fully inside a disposable project directory.
 */
export const runGhidraAnalysis = async (
  request: AnalyzeRequest,
  options: GhidraRunnerOptions,
): Promise<ProviderResult> => {
  const scratch = (request as AnalyzeRequest & { __scratchDir?: string }).__scratchDir;
  const workDir = scratch ?? path.join(os.tmpdir(), `vestige-ghidra-${Date.now()}`);
  const projectDir = path.join(workDir, "project");
  const scriptDir = path.join(workDir, "scripts");
  const outputPath = path.join(workDir, "ghidra-dump.json");
  await mkdir(projectDir, { recursive: true });
  await mkdir(scriptDir, { recursive: true });
  await writeFile(path.join(scriptDir, "vestige_dump.py"), VESTIGE_GHIDRA_SCRIPT, "utf8");

  const argv = buildAnalyzeHeadlessArgv({
    analyzeHeadlessPath: options.install.analyzeHeadlessPath,
    projectDir,
    projectName: "vestige",
    artifactPath: request.artifactPath,
    scriptDir,
    outputPath,
  });

  request.onProgress({
    phase: "ghidra-headless",
    stepsDone: 1,
    stepsTotal: 3,
    message: "analyzeHeadless launched (this can take minutes for large binaries)",
  });

  const result = await options.run({
    command: options.install.analyzeHeadlessPath,
    argv,
    timeoutMs: options.timeoutMs,
    signal: request.signal,
  });
  if (result.timedOut) {
    throw new Error(`Ghidra analysis exceeded ${String(options.timeoutMs)}ms`);
  }
  if (result.code !== 0) {
    throw new Error(
      `analyzeHeadless exited with code ${String(result.code)}: ${result.stderr.slice(0, 2000)}`,
    );
  }
  let raw: string;
  try {
    raw = await (await import("node:fs/promises")).readFile(outputPath, "utf8");
  } catch {
    throw new Error(
      "Ghidra did not produce the expected dump file; the bridge script may have failed.",
    );
  }
  const dump = dumpSchema.parse(JSON.parse(raw));

  const provider = {
    id: "ghidra",
    name: "Vestige Ghidra Bridge",
    version: "0.1.0",
  };
  const evidence: Evidence[] = [];
  const findings: Finding[] = [];
  const now = new Date().toISOString();
  const limitations = [
    "Facts derive from Ghidra's headless analysis of the artifact.",
    "Decompiled snippets are truncated to 8 KiB per function.",
    "Function inventory capped at 5,000 functions.",
  ];

  const headerEv = buildEvidence({
    artifactId: request.artifactId,
    artifactSha256: request.artifactSha256,
    provider,
    kind: "external-tool",
    confidence: "observed-fact",
    method: `ghidra analyzeHeadless (${dump.languageID})`,
    collectedAt: now,
    locations: [],
    observation: {
      programName: dump.programName,
      languageID: dump.languageID,
      imageBase: dump.imageBase,
      functionCount: dump.functionCount,
    },
    limitations,
  });
  evidence.push(headerEv);

  for (const fn of dump.functions) {
    const fnEv = buildEvidence({
      artifactId: request.artifactId,
      artifactSha256: request.artifactSha256,
      provider,
      kind: "external-tool",
      confidence: "observed-fact",
      method: `ghidra function manager (${options.install.installDir})`,
      collectedAt: now,
      locations: [{ type: "virtual-address", address: `0x${fn.entry}` }],
      observation: {
        name: fn.name,
        entry: fn.entry,
        bodySize: fn.bodySize,
        isThunk: fn.isThunk,
        params: fn.params,
        callees: fn.callees,
        callers: fn.callers,
      },
      limitations,
    });
    evidence.push(fnEv);
    findings.push(
      buildFinding({
        artifactId: request.artifactId,
        artifactSha256: request.artifactSha256,
        kind: "function",
        name: fn.name,
        summary: `Function '${fn.name}' at 0x${fn.entry} (${String(fn.bodySize)} bytes, ${String(fn.params.length)} params)`,
        provider,
        confidence: "observed-fact",
        method: "ghidra headless function inventory",
        collectedAt: now,
        location: { virtualAddress: `0x${fn.entry}` },
        evidenceIds: [fnEv.evidenceId],
        attributes: {
          entry: fn.entry,
          bodySize: fn.bodySize,
          calleeCount: fn.callees.length,
          callerCount: fn.callers.length,
          decompiledAvailable: fn.decompiled != null,
        },
        limitations,
      }),
    );
    if (fn.decompiled) {
      const decEv = buildEvidence({
        artifactId: request.artifactId,
        artifactSha256: request.artifactSha256,
        provider,
        kind: "external-tool",
        confidence: "static-inference",
        method: "ghidra decompiler",
        collectedAt: now,
        locations: [{ type: "virtual-address", address: `0x${fn.entry}` }],
        observation: { decompiled: fn.decompiled },
        limitations: [...limitations, "Decompiler output is machine-generated; review before relying on it."],
      });
      evidence.push(decEv);
    }
  }

  return {
    findings,
    evidence,
    diagnostics: {
      programName: dump.programName,
      languageID: dump.languageID,
      functionCount: dump.functionCount,
    },
  };
};
