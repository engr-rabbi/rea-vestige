import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { JobManager } from "../../../src/services/jobManager.js";

describe("JobManager", () => {
  let jobs: JobManager;

  beforeEach(() => {
    jobs = new JobManager();
  });

  afterEach(() => {
    // no cleanup needed; in-memory
  });

  it("creates queued jobs with ids and transitions to running", () => {
    const rec = jobs.create("va_x", "native", []);
    expect(rec.job.status).toBe("queued");
    expect(rec.job.jobId).toMatch(/^vj_/);
    jobs.markRunning(rec);
    expect(rec.job.status).toBe("running");
    expect(rec.job.startedAt).toBeTruthy();
  });

  it("tracks progress monotonically", () => {
    const rec = jobs.create("va_x", "native", []);
    jobs.markRunning(rec);
    jobs.progress(rec, { phase: "parse", stepsDone: 1, stepsTotal: 3 });
    expect(rec.job.progress.stepsDone).toBe(1);
    expect(rec.job.progress.stepsTotal).toBe(3);
    // Progress after completion must not mutate terminal state.
    jobs.markCompleted(rec, 2, 3);
    jobs.progress(rec, { phase: "late", stepsDone: 99, stepsTotal: 3 });
    expect(rec.job.progress.phase).toBe("completed");
  });

  it("completes with counts and resolves done", async () => {
    const rec = jobs.create("va_x", "native", []);
    jobs.markRunning(rec);
    setTimeout(() => jobs.markCompleted(rec, 5, 6), 10);
    await rec.done;
    expect(rec.job.status).toBe("completed");
    expect(rec.job.findingsCount).toBe(5);
    expect(rec.job.evidenceCount).toBe(6);
  });

  it("cancels running jobs via AbortController", async () => {
    const rec = jobs.create("va_x", "native", []);
    jobs.markRunning(rec);
    expect(rec.controller.signal.aborted).toBe(false);
    expect(jobs.cancel(rec.job.jobId)).toBe(true);
    expect(rec.controller.signal.aborted).toBe(true);
    jobs.markCancelled(rec);
    await rec.done;
    expect(rec.job.status).toBe("cancelled");
  });

  it("ignore cancel on terminal jobs", async () => {
    const rec = jobs.create("va_x", "native", []);
    jobs.markRunning(rec);
    jobs.markCompleted(rec, 1, 1);
    expect(jobs.cancel(rec.job.jobId)).toBe(false);
  });

  it("requires existing jobs (typed not_found)", () => {
    expect(() => jobs.require("vj_missing")).toThrow(/does not exist/);
  });

  it("enforces bounded retention of terminal jobs", () => {
    const small = new JobManager(3);
    for (let i = 0; i < 5; i++) {
      const rec = small.create(`va_${i}`, "native", []);
      small.markRunning(rec);
      small.markCompleted(rec, 0, 0);
    }
    expect(small.list().length).toBeLessThanOrEqual(3);
  });
});
