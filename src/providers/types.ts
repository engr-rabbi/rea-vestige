import { z } from "zod";

/**
 * Provider contract. Application services depend only on this interface —
 * never on concrete external tools (dependency direction requirement).
 */

export const providerDescriptorSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  /** Provider implementation version (semver-ish). */
  version: z.string().min(1),
  /** Artifact formats this provider handles. */
  formats: z.array(z.string()).min(1),
  summary: z.string().min(1),
});

export type ProviderDescriptor = z.infer<typeof providerDescriptorSchema>;

export const capabilityDescriptorSchema = z.object({
  /** Stable operation name, e.g. "extract-symbols". */
  operation: z.string().min(1),
  description: z.string().min(1),
  /** Documented limitations shown to agents up front. */
  limitations: z.array(z.string()).default([]),
  /** Whether this capability requires executing external tools. */
  requiresExternalTool: z.boolean().default(false),
});

export type CapabilityDescriptor = z.infer<typeof capabilityDescriptorSchema>;

export type Availability =
  | { available: true; detail?: string }
  | {
      available: false;
      reason: string;
      /** Actionable installation/compatibility guidance. */
      guidance: string;
    };

export interface AnalyzeRequest {
  artifactId: string;
  artifactPath: string;
  artifactSha256: string;
  format: string;
  architecture?: string;
  /** Capability operations to run; empty = all available. */
  capabilities: string[];
  signal: AbortSignal;
  /** Progress callback (phase, stepsDone, stepsTotal?, message?). */
  onProgress: (update: {
    phase: string;
    stepsDone: number;
    stepsTotal: number | null;
    message?: string;
  }) => void;
}

import type { Finding } from "../domain/finding.js";
import type { Evidence } from "../domain/evidence.js";

export interface ProviderResult {
  findings: Finding[];
  evidence: Evidence[];
  diagnostics: Record<string, unknown>;
}

export interface AnalysisProvider {
  readonly descriptor: ProviderDescriptor;
  capabilities(): CapabilityDescriptor[];
  /** Cheap availability probe (never long-running). */
  checkAvailability(): Promise<Availability>;
  /** Whether this provider can analyze the given artifact. */
  supports(artifact: {
    format: string;
    architecture?: string;
    isDirectory?: boolean;
  }): boolean;
  analyze(request: AnalyzeRequest): Promise<ProviderResult>;
}
