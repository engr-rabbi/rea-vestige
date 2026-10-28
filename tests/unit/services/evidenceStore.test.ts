import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { EvidenceStore } from "../../../src/services/evidenceStore.js";
import { buildEvidence } from "../../../src/domain/evidence.js";
import { buildFinding } from "../../../src/domain/finding.js";

describe("EvidenceStore", () => {
  let dataDir: string;
  let store: EvidenceStore;

  beforeEach(async () => {
    dataDir = await mkdtemp(path.join(os.tmpdir(), "vestige-store-"));
    store = new EvidenceStore(dataDir);
  });

  afterEach(async () => {
    await rm(dataDir, { recursive: true, force: true });
  });

  const makeEvidence = (artifactId = "va_test") =>
    buildEvidence({
      artifactId,
      artifactSha256: "b".repeat(64),
      provider: { id: "native", name: "N", version: "0.1.0" },
      kind: "string-extraction",
      confidence: "observed-fact",
      method: "test extraction",
      collectedAt: new Date().toISOString(),
      locations: [{ type: "file-offset", offset: 16 }],
      observation: { strings: ["hello world"] },
      limitations: [],
    });

  it("stores and retrieves evidence by id", async () => {
    const e = makeEvidence();
    const created = await store.putEvidence(e);
    expect(created).toBe(true);
    const fetched = await store.getEvidence(e.evidenceId);
    expect(fetched?.evidenceId).toBe(e.evidenceId);
    expect(fetched?.observation).toEqual({ strings: ["hello world"] });
  });

  it("deduplicates identical evidence (content-addressed)", async () => {
    const e1 = makeEvidence();
    const e2 = makeEvidence();
    expect(e1.evidenceId).toBe(e2.evidenceId);
    expect(await store.putEvidence(e1)).toBe(true);
    expect(await store.putEvidence(e2)).toBe(false);
  });

  it("refuses to store tampered evidence", async () => {
    const e = makeEvidence();
    const tampered = { ...e, observation: { strings: ["evil"] } };
    await expect(store.putEvidence(tampered)).rejects.toThrow(/identity mismatch/);
  });

  it("persists findings and round-trips them", async () => {
    const e = makeEvidence();
    await store.putEvidence(e);
    const f = buildFinding({
      artifactId: "va_test",
      artifactSha256: "b".repeat(64),
      kind: "string",
      name: "hello world",
      summary: "String 'hello world'",
      provider: { id: "native", name: "N", version: "0.1.0" },
      confidence: "observed-fact",
      method: "test",
      collectedAt: new Date().toISOString(),
      location: { fileOffset: 16 },
      evidenceIds: [e.evidenceId],
      attributes: {},
      limitations: [],
    });
    await store.putFindings("va_test", [f]);
    const fetched = await store.getFindings("va_test");
    expect(fetched).toHaveLength(1);
    expect(fetched[0]?.findingId).toBe(f.findingId);
    expect(fetched[0]?.evidenceIds).toEqual([e.evidenceId]);
  });

  it("returns empty findings for unknown artifacts", async () => {
    expect(await store.getFindings("va_missing")).toEqual([]);
    expect(await store.getEvidence("ve_missing")).toBeUndefined();
  });

  it("lists artifacts with findings", async () => {
    const e = makeEvidence("va_present");
    await store.putEvidence(e);
    const f = buildFinding({
      artifactId: "va_present",
      artifactSha256: "b".repeat(64),
      kind: "string",
      name: "x",
      summary: "x",
      provider: { id: "native", name: "N", version: "0.1.0" },
      confidence: "observed-fact",
      method: "t",
      collectedAt: new Date().toISOString(),
      location: {},
      evidenceIds: [e.evidenceId],
      attributes: {},
      limitations: [],
    });
    await store.putFindings("va_present", [f]);
    expect(await store.artifactsWithFindings()).toContain("va_present");
  });
});
