import { z } from "zod";
import { registerTargetInputSchema } from "../domain/artifact.js";

/**
 * MCP tool contracts. Zod is the single source of truth: the SDK projects
 * these into advertised JSON schemas and validates inputs on the wire.
 */

export const listTargetsInput = z.object({}).strict();
export const getTargetInput = z.object({
  artifactId: z.string().min(4),
});
export const listProvidersInput = z.object({}).strict();
export const analyzeInput = z.object({
  artifactId: z.string().min(4),
  provider: z.string().min(1).optional(),
  capabilities: z.array(z.string().min(1)).max(20).default([]),
});
export const jobStatusInput = z.object({
  jobId: z.string().min(4),
});
export const jobCancelInput = z.object({
  jobId: z.string().min(4),
});
export const listFindingsInput = z.object({
  artifactId: z.string().min(4),
  kind: z.string().min(1).optional(),
  confidence: z.string().min(1).optional(),
  limit: z.number().int().positive().max(1000).default(100),
  offset: z.number().int().nonnegative().default(0),
});
export const getEvidenceInput = z.object({
  evidenceId: z.string().min(4),
});
export const exportReportInput = z.object({
  artifactId: z.string().min(4),
  format: z.enum(["markdown", "json"]).default("markdown"),
});
export const diagnosticsInput = z.object({}).strict();

export { registerTargetInputSchema };
