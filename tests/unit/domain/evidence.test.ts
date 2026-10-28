import { describe, expect, it } from "vitest";
import { buildEvidence, verifyEvidence, type Evidence } from "../../../src/domain/evidence.js";
import { buildFinding, verifyFinding } from "../../../src/domain/finding.js";
import { canonicalJsonString, contentId } from "../../../src/util/hash.js";

const baseEvidence: Omit<Evidence, "evidenceId"> = {
  artifactId: "va_abcdef0123456789",
  artifactSha256: "a".repeat(64),
  provider: { id: "native", name: "Vestige Native", version: "0.1.0" },
  kind: "symbol-parse",
  confidence: "observed-fact",
  method: "test",
  collectedAt: "2026-01-01T00:00:00.000Z",
  locations: [],
  observation: { symbols: ["a", "b"] },
  limitations: [],
};

describe("evidence identity", () => {
  it("derives a stable content-addressed id", () => {
    const a = buildEvidence(baseEvidence);
    const b = buildEvidence({ ...baseEvidence, collectedAt: "2027-06-06T12:00:00.000Z" });
    // collectedAt is display metadata excluded from identity
    expect(a.evidenceId).toBe(b.evidenceId);
    expect(a.evidenceId).toMatch(/^ve_[0-9a-f]{24}$/);
  });

  it("changes identity when semantic content changes", () => {
    const a = buildEvidence(baseEvidence);
    const b = buildEvidence({ ...baseEvidence, observation: { symbols: ["a"] } });
    expect(a.evidenceId).not.toBe(b.evidenceId);
  });

  it("rejects tampered records on re-verification", () => {
    const e = buildEvidence(baseEvidence);
    expect(verifyEvidence(e)).toBe(true);
    const tampered: Evidence = { ...e, observation: { symbols: ["evil"] } };
    expect(verifyEvidence(tampered)).toBe(false);
  });

  it("canonicalizes JSON deterministically regardless of key order", () => {
    expect(canonicalJsonString({ b: 1, a: { d: 2, c: 3 } })).toBe(
      canonicalJsonString({ a: { c: 3, d: 2 }, b: 1 }),
    );
  });

  it("produces prefixed content ids", () => {
    expect(contentId("vf", "x")).toMatch(/^vf_[0-9a-f]{24}$/);
  });
});

describe("finding identity", () => {
  const baseFinding = {
    artifactId: "va_abcdef0123456789",
    artifactSha256: "a".repeat(64),
    kind: "function" as const,
    name: "main",
    summary: "Function 'main'",
    provider: { id: "native", name: "Vestige Native", version: "0.1.0" },
    confidence: "observed-fact" as const,
    method: "test",
    collectedAt: "2026-01-01T00:00:00.000Z",
    location: {},
    evidenceIds: ["ve_x"],
    attributes: {},
    limitations: [],
  };

  it("is stable and tamper-checked", () => {
    const f = buildFinding(baseFinding);
    expect(f.findingId).toMatch(/^vf_[0-9a-f]{24}$/);
    expect(verifyFinding(f)).toBe(true);
    expect(verifyFinding({ ...f, name: "other" })).toBe(false);
  });

  it("same facts → same finding id (dedup by identity)", () => {
    const a = buildFinding(baseFinding);
    const b = buildFinding({ ...baseFinding, collectedAt: "2030-01-01T00:00:00.000Z" });
    expect(a.findingId).toBe(b.findingId);
  });
});
