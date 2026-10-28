import type {
  AnalysisProvider,
  AnalyzeRequest,
  Availability,
  CapabilityDescriptor,
  ProviderDescriptor,
  ProviderResult,
} from "../types.js";
import { detectGhidraInstallation } from "./availability.js";
import { runGhidraAnalysis } from "./bridge.js";
import { runBounded } from "../../process/runBounded.js";

/**
 * Ghidra decompilation provider. Availability-dependent: when Ghidra is not
 * installed, `checkAvailability()` explains exactly how to enable it, and
 * analysis requests fail with `provider_unavailable` + guidance.
 */
export class GhidraProvider implements AnalysisProvider {
  readonly descriptor: ProviderDescriptor = {
    id: "ghidra",
    name: "Vestige Ghidra Bridge",
    version: "0.1.0",
    formats: ["elf", "pe", "macho"],
    summary:
      "Headless Ghidra analysis: function inventory, call graph, and decompilation via analyzeHeadless with a disposable project per run.",
  };

  private cachedDetection?: Awaited<ReturnType<typeof detectGhidraInstallation>>;

  constructor(private readonly envInstallDir?: string) {}

  capabilities(): CapabilityDescriptor[] {
    return [
      {
        operation: "decompile",
        description:
          "Decompile functions to C via Ghidra's decompiler (headless, bounded per-function timeout).",
        limitations: [
          "Requires Ghidra 11.x and Java 21+.",
          "Function inventory capped at 5,000; decompiled bodies truncated to 8 KiB.",
        ],
        requiresExternalTool: true,
      },
      {
        operation: "call-graph",
        description:
          "Caller/callee relationships per function from Ghidra's function manager.",
        limitations: ["Call graph depth is limited to direct neighbors."],
        requiresExternalTool: true,
      },
    ];
  }

  async checkAvailability(): Promise<Availability> {
    this.cachedDetection ??= await detectGhidraInstallation(this.envInstallDir);
    const a = this.cachedDetection;
    return a.available
      ? { available: true, detail: a.detail }
      : { available: false, reason: a.reason, guidance: a.guidance };
  }

  supports(artifact: { format: string }): boolean {
    return ["elf", "pe", "macho"].includes(artifact.format);
  }

  async analyze(request: AnalyzeRequest): Promise<ProviderResult> {
    const availability = await this.checkAvailability();
    if (!availability.available) {
      const err = new Error(availability.reason) as Error & { payload?: unknown };
      err.payload = {
        code: "provider_unavailable",
        message: `Provider 'ghidra' is unavailable: ${availability.reason}`,
        remediation: availability.guidance,
        retryable: false,
      };
      throw err;
    }
    const install = this.cachedDetection?.installation;
    if (!install) throw new Error("Ghidra installation paths not resolved");
    return runGhidraAnalysis(request, {
      run: async ({ command, argv, timeoutMs, signal }) => {
        const r = await runBounded({
          command,
          argv,
          timeoutMs,
          signal,
          maxOutputBytes: 8 * 1024 * 1024,
        });
        return {
          code: r.code,
          stdout: r.stdout,
          stderr: r.stderr,
          timedOut: r.timedOut,
        };
      },
      timeoutMs: 600_000,
      install,
    });
  }
}
