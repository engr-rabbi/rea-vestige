import { randomId } from "../util/hash.js";
import { notFound } from "../errors/errors.js";
import type { Job } from "../domain/job.js";

export interface JobRecord {
  job: Job;
  controller: AbortController;
  /** Resolves when the job reaches a terminal state. */
  done: Promise<void>;
  /** @internal resolver used by the manager on terminal transitions. */
  resolveDone: () => void;
}

/**
 * In-process job manager with AbortController-based cancellation and
 * monotonic progress. Jobs survive reply suppression: status remains
 * queryable after a client cancels a tool call (addresses the reference's
 * cancellation gap where partial evidence was lost with the reply).
 */
export class JobManager {
  private readonly jobs = new Map<string, JobRecord>();
  private readonly maxJobs: number;

  constructor(maxJobs = 200) {
    this.maxJobs = maxJobs;
  }

  create(artifactId: string, providerId: string, capabilities: string[]): JobRecord {
    // Bounded retention: drop oldest terminal jobs.
    if (this.jobs.size >= this.maxJobs) {
      const terminal = [...this.jobs.entries()].filter(
        ([, rec]) =>
          rec.job.status === "completed" ||
          rec.job.status === "failed" ||
          rec.job.status === "cancelled",
      );
      if (terminal.length > 0) {
        const oldest = terminal[0];
        if (oldest) this.jobs.delete(oldest[0]);
      }
    }
    const job: Job = {
      jobId: randomId("vj"),
      artifactId,
      providerId,
      capabilities,
      status: "queued",
      progress: { phase: "queued", stepsDone: 0, stepsTotal: null },
      findingsCount: 0,
      evidenceCount: 0,
      queuedAt: new Date().toISOString(),
      startedAt: null,
      finishedAt: null,
      error: null,
    };
    let resolveDone!: () => void;
    const done = new Promise<void>((resolve) => {
      resolveDone = resolve;
    });
    const record: JobRecord = {
      job,
      controller: new AbortController(),
      done,
      resolveDone,
    };
    this.jobs.set(job.jobId, record);
    return record;
  }

  get(jobId: string): JobRecord | undefined {
    return this.jobs.get(jobId);
  }

  require(jobId: string): JobRecord {
    const rec = this.jobs.get(jobId);
    if (!rec) throw notFound("Job", jobId);
    return rec;
  }

  list(): Job[] {
    return [...this.jobs.values()].map((r) => r.job);
  }

  markRunning(rec: JobRecord): void {
    rec.job.status = "running";
    rec.job.startedAt = new Date().toISOString();
  }

  /**
   * Record the provider actually used. Auto-selected jobs are created with
   * providerId "auto"; once selection resolves, the concrete provider is
   * recorded so status/report views never claim a provider that did not run.
   */
  setProvider(rec: JobRecord, providerId: string): void {
    rec.job.providerId = providerId;
  }

  progress(
    rec: JobRecord,
    update: {
      phase: string;
      stepsDone: number;
      stepsTotal: number | null;
      message?: string;
    },
  ): void {
    if (rec.job.status !== "running" && rec.job.status !== "queued") return;
    rec.job.progress = {
      phase: update.phase,
      stepsDone: update.stepsDone,
      stepsTotal: update.stepsTotal,
      ...(update.message !== undefined ? { message: update.message } : {}),
    };
  }

  markCompleted(rec: JobRecord, findingsCount: number, evidenceCount: number): void {
    rec.job.status = "completed";
    rec.job.findingsCount = findingsCount;
    rec.job.evidenceCount = evidenceCount;
    rec.job.finishedAt = new Date().toISOString();
    rec.job.progress = {
      ...rec.job.progress,
      stepsDone: rec.job.progress.stepsTotal ?? rec.job.progress.stepsDone,
      phase: "completed",
    };
    rec.resolveDone();
  }

  markFailed(rec: JobRecord, error: { code: string; message: string; remediation: string }): void {
    rec.job.status = "failed";
    rec.job.error = error;
    rec.job.finishedAt = new Date().toISOString();
    rec.resolveDone();
  }

  markCancelled(rec: JobRecord): void {
    rec.job.status = "cancelled";
    rec.job.finishedAt = new Date().toISOString();
    rec.resolveDone();
  }

  cancel(jobId: string): boolean {
    const rec = this.jobs.get(jobId);
    if (!rec) return false;
    if (
      rec.job.status === "completed" ||
      rec.job.status === "failed" ||
      rec.job.status === "cancelled"
    ) {
      return false;
    }
    rec.controller.abort();
    return true;
  }
}
