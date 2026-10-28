import { z } from "zod";
import { contentId } from "../util/hash.js";
import { canonicalJsonString } from "../util/hash.js";
import type { ConfidenceLevel } from "./evidence.js";

/** Finding kinds across providers. Providers must map observations onto these. */
export const FINDING_KINDS = [
  "function",
  "symbol",
  "section",
  "import",
  "export",
  "string",
  "dependency",
  "module",
  "route",
  "ipc-channel",
  "interpreter",
  "library",
  "entrypoint",
  "format-feature",
  "dynamic-link",
] as const;

export type FindingKind = (typeof FINDING_KINDS)[number];

export const findingSchema = z.object({
  /** Content-addressed identifier: `vf_<sha256[:24]>`. */
  findingId: z.string().min(4),
  artifactId: z.string().min(4),
  artifactSha256: z.string().regex(/^[a-f0-9]{64}$/),
  kind: z.enum(FINDING_KINDS),
  name: z.string().min(1).max(500),
  /** Canonical summary line for display. */
  summary: z.string().max(2000),
  provider: z.object({
    id: z.string().min(1),
    name: z.string().min(1),
    version: z.string().min(1),
  }),
  confidence: z.enum([
    "observed-fact",
    "static-inference",
    "runtime-observation",
    "ai-interpretation",
    "hypothesis",
  ]),
  /** Method used to obtain this finding (deterministic description). */
  method: z.string().min(1),
  collectedAt: z.string().datetime(),
  /** Location of the observation inside the artifact. */
  location: z
    .object({
      fileOffset: z.number().int().nonnegative().optional(),
      virtualAddress: z.string().optional(),
      artifactPath: z.string().optional(),
      line: z.number().int().positive().optional(),
      section: z.string().optional(),
    })
    .default({}),
  /** Evidence records that back this finding (provenance links). */
  evidenceIds: z.array(z.string()).max(256).default([]),
  /** Structured attributes (arch-specific or provider-specific). */
  attributes: z.record(z.string(), z.unknown()).default({}),
  limitations: z.array(z.string()).max(16).default([]),
});

export type Finding = z.infer<typeof findingSchema>;

const semanticContent = (f: Omit<Finding, "findingId">): string =>
  canonicalJsonString({
    artifactId: f.artifactId,
    artifactSha256: f.artifactSha256,
    kind: f.kind,
    name: f.name,
    summary: f.summary,
    provider: f.provider,
    confidence: f.confidence satisfies ConfidenceLevel,
    method: f.method,
    location: f.location,
    attributes: f.attributes,
    limitations: f.limitations,
  });

export const buildFinding = (
  input: Omit<Finding, "findingId">,
): Finding => ({
  ...input,
  findingId: contentId("vf", semanticContent(input)),
});

export const verifyFinding = (finding: Finding): boolean => {
  const { findingId: _ignored, ...rest } = finding;
  return contentId("vf", semanticContent(rest)) === finding.findingId;
};
