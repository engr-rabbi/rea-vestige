import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { AnalysisService } from "../../../src/services/analysisService.js";
import { TargetRegistry } from "../../../src/services/targetRegistry.js";
import { EvidenceStore } from "../../../src/services/evidenceStore.js";
import { JobManager } from "../../../src/services/jobManager.js";
import { ProviderRegistry } from "../../../src/services/providerRegistry.js";
import type { AnalysisProvider, AnalyzeRequest, ProviderResult } from "../../../src/providers/types.js";
import { buildEvidence } from "../../../src/domain/evidence.js";

/** Fake provider with call counting for cache tests. */
const makeFakeProvider = (): AnalysisProvider & { calls: number } => {
  let calls = 0;
  return {
    get calls(): number {
      return calls;
    },
    descriptor: {
      id: "fake",
      name: "Fake Provider",
      version: "1.0.0",
      formats: ["javascript"],
      summary: "test provider",
    },
    capabilities: () => [],
    checkAvailability: async () => ({ available: true }),
    supports: (artifact: { format: string }) => artifact.format === "javascript",
    analyze: async (request: AnalyzeRequest): Promise<ProviderResult> => {
      calls += 1;
      request.onProgress({ phase: "step", stepsDone: 1, stepsTotal: 1 });
      const evidence = buildEvidence({
        artifactId: request.artifactId,
        artifactSha256: request.artifactSha256,
        provider: { id: "fake", name: "Fake Provider", version: "1.0.0" },
        kind: "heuristic",
        confidence: "static-inference",
        method: "fake",
        collectedAt: new Date().toISOString(),
        locations: [],
        observation: { n: calls },
        limitations: [],
      });
      return { findings: [], evidence: [evidence], diagnostics: {} };
    },
  } as AnalysisProvider & { calls: number };
};

describe("AnalysisService (cache + orchestration)", () => {
  let dataDir: string;
  let targets: TargetRegistry;
  let providers: ProviderRegistry;
  let store: EvidenceStore;
  let jobs: JobManager;
  let service: AnalysisService;
  let artifactId: string;

  beforeEach(async () => {
    dataDir = await mkdtemp(path.join(os.tmpdir(), "vestige-svc-"));
    targets = new TargetRegistry(dataDir);
    providers = new ProviderRegistry();
    store = new EvidenceStore(dataDir);
    jobs = new JobManager();
    service = new AnalysisService(targets, providers, store, jobs, dataDir);
    const file = path.join(dataDir, "sample.js");
    await writeFile(file, "import x from 'y';\n");
    const reg = await targets.register(file);
    artifactId = reg.artifact.artifactId;
  });

  afterEach(async () => {
    await rm(dataDir, { recursive: true, force: true });
  });

  it("runs a synchronous analysis and persists results", async () => {
    const provider = makeFakeProvider();
    providers.register(provider);
    const record = jobs.create(artifactId, "fake", []);
    await service.run(record, "fake");
    expect(record.job.status).toBe("completed");
    expect(record.job.evidenceCount).toBe(1);
    expect(provider.calls).toBe(1);
    const findings = await store.getFindings(artifactId);
    expect(findings).toEqual([]);
  });

  it("serves cached results without re-running the provider", async () => {
    const provider = makeFakeProvider();
    providers.register(provider);
    const rec1 = jobs.create(artifactId, "fake", []);
    await service.run(rec1, "fake");
    const rec2 = jobs.create(artifactId, "fake", []);
    await service.run(rec2, "fake");
    expect(provider.calls).toBe(1); // second run served from cache
    expect(rec2.job.status).toBe("completed");
    expect(rec2.job.evidenceCount).toBe(1);
  });

  it("cache key changes when capability set changes", async () => {
    const provider = makeFakeProvider();
    providers.register(provider);
    const rec1 = jobs.create(artifactId, "fake", []);
    await service.run(rec1, "fake", ["a"]);
    const rec2 = jobs.create(artifactId, "fake", []);
    await service.run(rec2, "fake", ["b"]);
    expect(provider.calls).toBe(2);
  });

  it("marks failed jobs with typed error payloads for unavailable providers", async () => {
    const rec = jobs.create(artifactId, "missing", []);
    await expect(service.run(rec, "missing")).rejects.toMatchObject({
      payload: { code: "provider_unavailable" },
    });
    expect(rec.job.status).toBe("failed");
    expect(rec.job.error?.code).toBe("provider_unavailable");
  });

  it("marks jobs cancelled when signal aborts mid-run", async () => {
    const provider = makeFakeProvider();
    providers.register(provider);
    const rec = jobs.create(artifactId, "fake", []);
    jobs.markRunning(rec);
    rec.controller.abort();
    await service.run(rec, "fake");
    expect(rec.job.status).toBe("cancelled");
  });

  it("fails when no provider supports the format", async () => {
    const file = path.join(dataDir, "blob.bin");
    await writeFile(file, Buffer.from([0, 1, 2, 3]));
    const reg = await targets.register(file);
    const rec = jobs.create(reg.artifact.artifactId, "auto", []);
    await expect(service.run(rec)).rejects.toMatchObject({
      payload: { code: "provider_unavailable" },
    });
  });
});

describe("AnalysisService (auto provider selection)", () => {
  let dataDir: string;
  let targets: TargetRegistry;
  let providers: ProviderRegistry;
  let store: EvidenceStore;
  let jobs: JobManager;
  let service: AnalysisService;
  let artifactId: string;

  /** Provider that supports javascript but reports itself unavailable. */
  const makeUnavailableProvider = (
    id: string,
    reason: string,
    guidance: string,
  ): AnalysisProvider => ({
    descriptor: {
      id,
      name: `Unavailable ${id}`,
      version: "1.0.0",
      formats: ["javascript"],
      summary: "test provider that is unavailable",
    },
    capabilities: () => [],
    checkAvailability: async () => ({ available: false, reason, guidance }),
    supports: (artifact: { format: string }) => artifact.format === "javascript",
    analyze: async (): Promise<ProviderResult> => {
      throw new Error("must not be called while unavailable");
    },
  });

  beforeEach(async () => {
    dataDir = await mkdtemp(path.join(os.tmpdir(), "vestige-autosel-"));
    targets = new TargetRegistry(dataDir);
    providers = new ProviderRegistry();
    store = new EvidenceStore(dataDir);
    jobs = new JobManager();
    service = new AnalysisService(targets, providers, store, jobs, dataDir);
    const file = path.join(dataDir, "sample.js");
    await writeFile(file, "import x from 'y';\n");
    const reg = await targets.register(file);
    artifactId = reg.artifact.artifactId;
  });

  afterEach(async () => {
    await rm(dataDir, { recursive: true, force: true });
  });

  it("auto mode falls back to the first AVAILABLE format-supporting provider", async () => {
    // Registry order is alphabetical: the unavailable provider sorts first
    // and must be skipped instead of failing the whole job (regression test
    // for the ghidra-before-native auto-selection failure).
    providers.register(
      makeUnavailableProvider(
        "aaa-external",
        "No external toolchain found.",
        "Install the external toolchain and retry.",
      ),
    );
    const provider = makeFakeProvider();
    providers.register(provider);
    const rec = jobs.create(artifactId, "auto", []);
    await service.run(rec);
    expect(rec.job.status).toBe("completed");
    expect(rec.job.providerId).toBe("fake");
    expect(provider.calls).toBe(1);
  });

  it("auto mode treats a throwing checkAvailability as unavailable and keeps walking", async () => {
    const throwing = makeUnavailableProvider("aaa-throwing", "probe failed", "check setup");
    throwing.checkAvailability = async () => {
      throw new Error("probe exploded");
    };
    providers.register(throwing);
    const provider = makeFakeProvider();
    providers.register(provider);
    const rec = jobs.create(artifactId, "auto", []);
    await service.run(rec);
    expect(rec.job.status).toBe("completed");
    expect(rec.job.providerId).toBe("fake");
  });

  it("auto mode fails with an aggregated payload when every candidate is unavailable", async () => {
    providers.register(
      makeUnavailableProvider("aaa-a", "reason A", "guidance A"),
    );
    providers.register(
      makeUnavailableProvider("bbb-b", "reason B", "guidance B"),
    );
    const rec = jobs.create(artifactId, "auto", []);
    await expect(service.run(rec)).rejects.toMatchObject({
      payload: {
        code: "provider_unavailable",
        message: expect.stringContaining("aaa-a (reason A)"),
      },
    });
    expect(rec.job.status).toBe("failed");
    expect(rec.job.error?.message).toContain("bbb-b (reason B)");
    expect(rec.job.error?.remediation).toContain("guidance A");
    expect(rec.job.error?.remediation).toContain("guidance B");
  });

  it("explicit provider mode never silently reroutes to another provider", async () => {
    providers.register(
      makeUnavailableProvider("aaa-external", "No external toolchain found.", "Install it."),
    );
    const provider = makeFakeProvider();
    providers.register(provider);
    const rec = jobs.create(artifactId, "aaa-external", []);
    await expect(service.run(rec, "aaa-external")).rejects.toMatchObject({
      payload: {
        code: "provider_unavailable",
        message: "Provider 'aaa-external' is unavailable: No external toolchain found.",
      },
    });
    expect(rec.job.status).toBe("failed");
    expect(provider.calls).toBe(0);
    expect(rec.job.providerId).toBe("aaa-external");
  });

  it("explicit provider registered but mismatched format is a typed failure", async () => {
    const provider = makeFakeProvider(); // supports javascript only
    providers.register(provider);
    const file = path.join(dataDir, "blob.bin");
    await writeFile(file, Buffer.from([0, 1, 2, 3]));
    const reg = await targets.register(file);
    const rec = jobs.create(reg.artifact.artifactId, "fake", []);
    await expect(service.run(rec, "fake")).rejects.toMatchObject({
      payload: {
        code: "provider_unavailable",
        message: expect.stringContaining("does not support format"),
      },
    });
    expect(provider.calls).toBe(0);
  });
});
