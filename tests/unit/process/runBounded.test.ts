import { describe, expect, it } from "vitest";
import { runBounded } from "../../../src/process/runBounded.js";
import { existsSync } from "node:fs";

const node = process.execPath;

describe("runBounded", () => {
  it("captures stdout and exit code", async () => {
    const r = await runBounded({ command: node, argv: ["-e", "console.log('hello')"] });
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toBe("hello");
  });

  it("passes argv safely — no shell interpolation (injection resistance)", async () => {
    // If argv were shell-interpolated, `$(...)` or `&& touch` would execute.
    const payload = "pwned'; touch /tmp/vestige-injection-proof; echo '";
    const r = await runBounded({
      command: node,
      argv: ["-e", "console.log(process.argv[1])", payload],
    });
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toBe(payload);
    const { existsSync } = await import("node:fs");
    expect(existsSync("/tmp/vestige-injection-proof")).toBe(false);
  });

  it("kills long-running children on timeout", async () => {
    const r = await runBounded({
      command: node,
      argv: ["-e", "setInterval(()=>{},1000)"],
      timeoutMs: 300,
    });
    expect(r.timedOut).toBe(true);
  });

  it("truncates oversized output and stops the child", async () => {
    const r = await runBounded({
      command: node,
      argv: ["-e", "process.stdout.write('x'.repeat(10_000_000))"],
      maxOutputBytes: 1_000_000,
      timeoutMs: 10_000,
    });
    expect(r.outputTruncated).toBe(true);
    expect(r.stdout.length).toBeLessThanOrEqual(1_000_000);
  });

  it("honors AbortSignal cancellation", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 150);
    const r = await runBounded({
      command: node,
      argv: ["-e", "setInterval(()=>{},1000)"],
      signal: controller.signal,
      timeoutMs: 10_000,
    });
    expect(r.timedOut).toBe(false);
    expect(r.code === null || r.code !== 0).toBe(true);
  });

  it("reports spawn failures without throwing", async () => {
    const r = await runBounded({
      command: "/nonexistent/vestige-tool-xyz",
      argv: [],
    });
    expect(r.code).toBeNull();
    expect(r.stderr).toContain("spawn failed");
  });

  it("keeps argv entries intact (no shell splitting)", async () => {
    const r = await runBounded({
      command: node,
      argv: ["-e", "console.log(JSON.stringify(process.argv.slice(1)))", "a b", "c d"],
    });
    expect(JSON.parse(r.stdout.trim())).toEqual(["a b", "c d"]);
  });
});

describe("injection proof", () => {
  it("proof file does not exist after suite", () => {
    expect(existsSync("/tmp/vestige-injection-proof")).toBe(false);
  });
});
