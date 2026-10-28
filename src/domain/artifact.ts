import { z } from "zod";

/**
 * Artifact formats Vestige can identify via magic bytes / structure.
 * Only formats with a working parser may be added here.
 */
export const ARTIFACT_FORMATS = [
  "elf",
  "pe",
  "macho",
  "javascript",
  "json",
  "directory",
  "unknown",
] as const;

export type ArtifactFormat = (typeof ARTIFACT_FORMATS)[number];

export const artifactSchema = z.object({
  /** Content-derived stable identifier: `va_<sha256[:16]>`. */
  artifactId: z.string().min(4),
  label: z.string().min(1).max(200).optional(),
  /** Canonical absolute path at registration time. */
  path: z.string().min(1),
  /** SHA-256 of the artifact content at registration (commitment digest). */
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  sizeBytes: z.number().int().nonnegative(),
  format: z.enum(ARTIFACT_FORMATS),
  architecture: z.string().optional(),
  registeredAt: z.string().datetime(),
});

export type Artifact = z.infer<typeof artifactSchema>;

export const registerTargetInputSchema = z.object({
  path: z.string().min(1).describe(
    "Absolute path to a file or directory the operator is authorized to analyze.",
  ),
  label: z.string().min(1).max(200).optional(),
});
export type RegisterTargetInput = z.infer<typeof registerTargetInputSchema>;
