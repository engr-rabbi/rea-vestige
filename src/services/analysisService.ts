import { mkdir, readFile, writeFile, rename } from "node:fs/promises";
import path from "node:path";
import type { AnalysisProvider, Availability, ProviderResult } from "../providers/types.js";
import type { Artifact } from "../domain/artifact.js";
import type { Finding } from "../domain/finding.js";
import { VestigeError, providerUnavailable, projectError } from "../errors/errors.js";
import { canonicalJsonString, sha256Hex } from "../util/hash.js";
import type { EvidenceStore } from "./evidenceStore.js";
import type { JobManager, JobRecord } from "./jobManager.js";
import type { ProviderRegistry } from "./providerRegistry.js";
import type { TargetRegistry } from "./targetRegistry.js";

/**
 * Analysis orchestration: registers jobs, routes to providers, persists
 * evidence/findings, and serves content-addressed cached results.
 *
 * Cache key = SHA-256(canonical{providerId, providerVersion, capability set,
 * artifactSha256, optionsVersion}). Cached hits are re-emitted as verified
 * evidence records (re-hashed on read by the store).
 */
export class AnalysisService {
  constructor(
    private readonly targets: TargetRegistry,
    private readonly providers: ProviderRegistry,
    private readonly store: EvidenceStore,
    private readonly jobs: JobManager,
    private readonly dataDir: string,
  ) {}

  private cacheKey(
    provider: AnalysisProvider,
    artifact: Artifact,
    capabilities: string[],
  ): string {
    return sha256Hex(
      canonicalJsonString({
        v: 1,
        providerId: provider.descriptor.id,
        providerVersion: provider.descriptor.version,
        capabilities: [...capabilities].sort(),
        artifactSha256: artifact.sha256,
      }),
    );
  }

  private async readCache(key: string): Promise<ProviderResult | undefined> {
    try {
      const body = await readFile(
        path.join(this.dataDir, "cache", `${key}.json`),
        "utf8",
      );
      const parsed = JSON.parse(body) as ProviderResult;
      // Re-verify every cached record before trusting it.
      for (const e of parsed.evidence) {
        if (!(await this.verify(e))) return undefined;
      }
      return parsed;
    } catch {
      return undefined;
    }
  }

  private async verify(e: unknown): Promise<boolean> {
    try {
      const { verifyEvidence } = await import("../domain/evidence.js");
      return verifyEvidence(e as never);
    } catch {
      return false;
    }
  }

  private async writeCache(key: string, result: ProviderResult): Promise<void> {
    const dir = path.join(this.dataDir, "cache");
    const file = path.join(dir, `${key}.json`);
    try {
      await mkdir(dir, { recursive: true });
      const tmp = `${file}.tmp`;
      await writeFile(tmp, JSON.stringify(result), "utf8");
      await rename(tmp, file);
    } catch {
      /* cache write failures are non-fatal */
    }
  }

  /**
   * Start an analysis job. Returns the job record; results are stored in the
   * evidence store and counted on the job. Never throws for provider-level
   * failures — those mark the job failed with a stable error payload.
   */
  startAnalysis(
    artifactId: string,
    providerId?: string,
    capabilities: string[] = [],
  ): JobRecord {
    // Validate ids up-front so callers get fast, typed failures.
    const record = this.jobs.create(artifactId, providerId ?? "auto", capabilities);
    void this.run(record, providerId, capabilities).catch(() => {
      /* run() handles its own failures */
    });
    return record;
  }

  /**
   * Select a provider for the job. Auto mode walks every format-supporting
   * candidate in registry order and picks the first that is actually
   * AVAILABLE (probe-then-commit). Explicit mode never silently reroutes:
   * an unavailable or format-mismatched requested provider is a typed
   * failure, so operators always know which provider ran.
   */
  private async selectProvider(
    record: JobRecord,
    providerId: string | undefined,
    artifact: Artifact,
  ): Promise<AnalysisProvider> {
    const requested = providerId ? this.providers.get(providerId) : undefined;

    if (providerId && !requested) {
      throw this.failJob(record, providerUnavailable(
        providerId,
        `provider '${providerId}' is not registered`,
        "Run vestige_providers (CLI: vestige providers) to list registered providers, supported formats, and availability.",
      ));
    }
    if (providerId && requested && !requested.supports(artifact)) {
      throw this.failJob(record, providerUnavailable(
        providerId,
        `provider '${providerId}' does not support format '${artifact.format}'`,
        `Run vestige_providers (CLI: vestige providers) to see which providers support format '${artifact.format}'.`,
      ));
    }

    const candidates: AnalysisProvider[] = providerId
      ? requested
        ? [requested]
        : []
      : this.providers.supporting(artifact);

    let selected: AnalysisProvider | undefined;
    const tried: Array<{ id: string; reason: string; guidance: string }> = [];
    let formatMatched = false;
    for (const candidate of candidates) {
      if (!candidate.supports(artifact)) continue;
      formatMatched = true;
      let availability: Availability;
      try {
        availability = await candidate.checkAvailability();
      } catch (error) {
        availability = {
          available: false,
          reason: error instanceof Error ? error.message : String(error),
          guidance: "Run vestige_providers (CLI: vestige providers) to inspect provider diagnostics.",
        };
      }
      if (availability.available) {
        selected = candidate;
        break;
      }
      tried.push({
        id: candidate.descriptor.id,
        reason: availability.reason,
        guidance: availability.guidance,
      });
    }

    if (!selected) {
      throw this.failJob(record, this.buildUnavailableFailure(
        providerId,
        artifact,
        formatMatched,
        tried,
      ));
    }
    return selected;
  }

  /** Mark the job failed and produce the typed error to surface upstream. */
  private failJob(record: JobRecord, failure: VestigeError): VestigeError {
    this.jobs.markFailed(record, {
      code: failure.payload.code,
      message: failure.payload.message,
      remediation: failure.payload.remediation,
    });
    return failure;
  }

  private buildUnavailableFailure(
    providerId: string | undefined,
    artifact: Artifact,
    formatMatched: boolean,
    tried: Array<{ id: string; reason: string; guidance: string }>,
  ): VestigeError {
    if (providerId && tried.length > 0) {
      const only = tried[0];
      if (only) {
        return providerUnavailable(providerId, only.reason, only.guidance);
      }
    }
    if (tried.length > 0) {
      const detail = tried.map((u) => `${u.id} (${u.reason})`).join("; ");
      const guidanceSteps = [...new Set(tried.map((u) => u.guidance))]
        .map((g) => `- ${g}`)
        .join("\n");
      return providerUnavailable(
        "auto",
        `no available provider for format '${artifact.format}'; tried: ${detail}`,
        `Make one of the tried providers available, then retry:\n${guidanceSteps}\nOr run analysis with an explicit --provider once its prerequisites are installed.`,
      );
    }
    if (formatMatched) {
      return providerUnavailable(
        providerId ?? "auto",
        `no registered provider supports this artifact (format '${artifact.format}'${artifact.architecture ? `, architecture '${artifact.architecture}'` : ""})`,
        "Run vestige_providers (CLI: vestige providers) to inspect per-format and per-architecture support.",
      );
    }
    return providerUnavailable(
      providerId ?? "auto",
      `no registered provider supports format '${artifact.format}'`,
      "Run vestige_providers (CLI: vestige providers) to list registered providers and the formats they support.",
    );
  }

  /** Analyze synchronously (used by CLI and tests). */
  async run(
    record: JobRecord,
    providerId?: string,
    capabilities: string[] = [],
  ): Promise<ProviderResult> {
    try {
      return await this.runInner(record, providerId, capabilities);
    } catch (error) {
      if (record.controller.signal.aborted) {
        this.jobs.markCancelled(record);
        return { findings: [], evidence: [], diagnostics: { cancelled: true } };
      }
      const payload = projectError(error);
      this.jobs.markFailed(record, {
        code: payload.code,
        message: payload.message,
        remediation: payload.remediation,
      });
      throw new VestigeError(payload, { cause: error });
    }
  }

  private async runInner(
    record: JobRecord,
    providerId?: string,
    capabilities: string[] = [],
  ): Promise<ProviderResult> {
    const artifact = await this.targets.require(record.job.artifactId);
    const provider = await this.selectProvider(record, providerId, artifact);

    // Record the provider that will actually run so auto-resolved jobs
    // never display a provider that was not used.
    this.jobs.setProvider(record, provider.descriptor.id);

    const key = this.cacheKey(provider, artifact, capabilities);
    const cached = await this.readCache(key);
    if (cached) {
      for (const e of cached.evidence) await this.store.putEvidence(e);
      await this.store.putFindings(artifact.artifactId, cached.findings);
      this.jobs.markCompleted(record, cached.findings.length, cached.evidence.length);
      record.job.progress = {
        phase: "completed (cached)",
        stepsDone: 1,
        stepsTotal: 1,
      };
      return cached;
    }

    this.jobs.markRunning(record);
    const result = await provider.analyze({
      artifactId: artifact.artifactId,
      artifactPath: artifact.path,
      artifactSha256: artifact.sha256,
      format: artifact.format,
      architecture: artifact.architecture,
      capabilities,
      signal: record.controller.signal,
      onProgress: (u) => this.jobs.progress(record, u),
    });
    // Persist evidence first (cancel-safe), then findings, then counts.
    for (const evidence of result.evidence) {
      await this.store.putEvidence(evidence);
      if (record.controller.signal.aborted) {
        this.jobs.markCancelled(record);
        return result;
      }
    }
    await this.store.putFindings(artifact.artifactId, result.findings);
    if (record.controller.signal.aborted) {
      this.jobs.markCancelled(record);
      return result;
    }
    await this.writeCache(key, result);
    this.jobs.markCompleted(record, result.findings.length, result.evidence.length);
    return result;
  }
}

/** Build a deterministic markdown report from findings + evidence. */
export const renderReport = (
  artifact: Artifact,
  findings: Finding[],
  evidenceCount: number,
  jobRows: Array<{ jobId: string; providerId: string; status: string; finishedAt: string | null }>,
): string => {
  const lines: string[] = [];
  lines.push(`# Vestige analysis report`);
  lines.push("");
  lines.push(`- Artifact: \`${artifact.path}\``);
  lines.push(`- Artifact ID: \`${artifact.artifactId}\``);
  lines.push(`- SHA-256: \`${artifact.sha256}\``);
  lines.push(`- Format: ${artifact.format}${artifact.architecture ? ` (${artifact.architecture})` : ""}`);
  lines.push(`- Registered: ${artifact.registeredAt}`);
  lines.push(`- Evidence records: ${evidenceCount}`);
  lines.push("");
  lines.push(`## Findings (${findings.length})`);
  lines.push("");
  lines.push("| ID | Kind | Name | Confidence | Provider | Method |");
  lines.push("|---|---|---|---|---|---|");
  for (const f of findings) {
    lines.push(
      `| ${f.findingId.slice(0, 14)}… | ${f.kind} | ${f.name.replace(/\|/g, "\\|")} | ${f.confidence} | ${f.provider.id}@${f.provider.version} | ${f.method.replace(/\|/g, "\\|")} |`,
    );
  }
  lines.push("");
  lines.push(`## Jobs`);
  lines.push("");
  for (const j of jobRows) {
    lines.push(`- ${j.jobId} — ${j.providerId} — ${j.status}${j.finishedAt ? ` (${j.finishedAt})` : ""}`);
  }
  lines.push("");
  lines.push(
    "Confidence legend: `observed-fact` = read directly from artifact bytes; `static-inference` = derived by static analysis; `runtime-observation` = produced by executing the target; `ai-interpretation` = AI-generated; `hypothesis` = unverified.",
  );
  return lines.join("\n");
};


