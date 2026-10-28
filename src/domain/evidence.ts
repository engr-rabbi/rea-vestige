import { z } from "zod";
import { contentId } from "../util/hash.js";
import { canonicalJsonString } from "../util/hash.js";

/**
 * Evidence epistemic class. Vestige forces every observation to declare what
 * kind of knowledge it is (platform requirement; improvement over the
 * reference's 3-level scale):
 *
 * - observed-fact        : directly read from the artifact bytes (headers, sections, strings)
 * - static-inference     : conclusion of static analysis (AST/CFG/heuristics)
 * - runtime-observation  : produced by executing the target (never done by default)
 * - ai-interpretation    : AI-generated interpretation (only when explicitly configured)
 * - hypothesis           : unverified idea recorded for follow-up
 */
export const CONFIDENCE_LEVELS = [
  "observed-fact",
  "static-inference",
  "runtime-observation",
  "ai-interpretation",
  "hypothesis",
] as const;

export type ConfidenceLevel = (typeof CONFIDENCE_LEVELS)[number];

export const EVIDENCE_KINDS = [
  "magic-bytes",
  "header-parse",
  "section-parse",
  "symbol-parse",
  "string-extraction",
  "ast-parse",
  "manifest-parse",
  "external-tool",
  "cross-reference",
  "heuristic",
] as const;

export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];

export const evidenceLocationSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("file-offset"),
    offset: z.number().int().nonnegative(),
    length: z.number().int().nonnegative().optional(),
  }),
  z.object({
    type: z.literal("virtual-address"),
    address: z.string().min(1),
  }),
  z.object({
    type: z.literal("artifact-path"),
    path: z.string().min(1),
    line: z.number().int().positive().optional(),
    column: z.number().int().positive().optional(),
  }),
  z.object({
    type: z.literal("section"),
    section: z.string().min(1),
  }),
]);
export type EvidenceLocation = z.infer<typeof evidenceLocationSchema>;

export const evidenceSchema = z.object({
  /** Content-addressed identifier: `ve_<sha256[:24]>` of the semantic content. */
  evidenceId: z.string().min(4),
  artifactId: z.string().min(4),
  artifactSha256: z.string().regex(/^[a-f0-9]{64}$/),
  provider: z.object({
    id: z.string().min(1),
    name: z.string().min(1),
    version: z.string().min(1),
  }),
  /** External tool used, with version, when the evidence came from one. */
  tool: z
    .object({
      name: z.string().min(1),
      version: z.string().optional(),
    })
    .optional(),
  kind: z.enum(EVIDENCE_KINDS),
  confidence: z.enum(CONFIDENCE_LEVELS),
  /** How the evidence was obtained (e.g. "acorn 8.19 AST parse"). */
  method: z.string().min(1),
  collectedAt: z.string().datetime(),
  locations: z.array(evidenceLocationSchema).max(64).default([]),
  /** Verbatim (bounded) observation content or a stable reference to it. */
  observation: z.union([z.string().max(100_000), z.record(z.string(), z.unknown())]),
  limitations: z.array(z.string()).max(32).default([]),
});

export type Evidence = z.infer<typeof evidenceSchema>;

/**
 * Semantic content = the fields that define the evidence's identity.
 * Display-only metadata is excluded from the digest on purpose, so the same
 * observation recorded at different times keeps one stable identity.
 */
const semanticContent = (e: Omit<Evidence, "evidenceId">): string =>
  canonicalJsonString({
    artifactId: e.artifactId,
    artifactSha256: e.artifactSha256,
    provider: e.provider,
    tool: e.tool ?? null,
    kind: e.kind,
    confidence: e.confidence,
    method: e.method,
    locations: e.locations,
    observation: e.observation,
    limitations: e.limitations,
  });

/** Build an Evidence record, deriving its content-addressed identity. */
export const buildEvidence = (
  input: Omit<Evidence, "evidenceId">,
): Evidence => ({
  ...input,
  evidenceId: contentId("ve", semanticContent(input)),
});

/**
 * Re-authenticate a stored evidence record: its ID must still match its
 * semantic content. Tampered records are rejected instead of served.
 */
export const verifyEvidence = (evidence: Evidence): boolean => {
  const { evidenceId: _ignored, ...rest } = evidence;
  return contentId("ve", semanticContent(rest)) === evidence.evidenceId;
};
