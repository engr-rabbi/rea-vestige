import { z } from "zod";

export const JOB_STATUSES = [
  "queued",
  "running",
  "completed",
  "failed",
  "cancelled",
] as const;

export type JobStatus = (typeof JOB_STATUSES)[number];

export const jobSchema = z.object({
  jobId: z.string().min(4),
  artifactId: z.string().min(4),
  providerId: z.string().min(1),
  /** Requested capabilities; empty means all supported by the provider. */
  capabilities: z.array(z.string()).default([]),
  status: z.enum(JOB_STATUSES),
  /** Progress reporting: phase name + monotonic step counter + optional total. */
  progress: z.object({
    phase: z.string(),
    stepsDone: z.number().int().nonnegative(),
    stepsTotal: z.number().int().nonnegative().nullable(),
    message: z.string().max(300).optional(),
  }),
  findingsCount: z.number().int().nonnegative().default(0),
  evidenceCount: z.number().int().nonnegative().default(0),
  queuedAt: z.string().datetime(),
  startedAt: z.string().datetime().nullable(),
  finishedAt: z.string().datetime().nullable(),
  /** Stable error payload when status is failed. */
  error: z
    .object({
      code: z.string(),
      message: z.string(),
      remediation: z.string(),
    })
    .nullable(),
});

export type Job = z.infer<typeof jobSchema>;
