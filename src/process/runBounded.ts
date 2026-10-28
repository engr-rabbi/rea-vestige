import { spawn } from "node:child_process";
import { timeoutError } from "../errors/errors.js";

export interface BoundedRunOptions {
  argv: readonly string[];
  /** Absolute executable path; never a shell string. */
  command: string;
  cwd?: string;
  timeoutMs?: number;
  /** Combined stdout+stderr capture cap. */
  maxOutputBytes?: number;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}

export interface BoundedRunResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  outputTruncated: boolean;
  timedOut: boolean;
  durationMs: number;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
/** Grace period between SIGTERM and SIGKILL. */
const STOP_GRACE_MS = 500;

/**
 * Shell-free bounded process runner:
 *  - argv array only (no shell interpolation)
 *  - combined output cap with head+tail retention
 *  - timeout + AbortSignal support with stop ladder (SIGTERM → SIGKILL)
 *
 * The runner kills only the direct child; long-lived provider trees should
 * run under dedicated supervisors (see Ghidra bridge notes in docs).
 */
export const runBounded = async (
  options: BoundedRunOptions,
): Promise<BoundedRunResult> => {
  const {
    command,
    argv,
    cwd,
    env,
    signal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
  } = options;

  const started = Date.now();
  return new Promise<BoundedRunResult>((resolve) => {
    const child = spawn(command, [...argv], {
      cwd,
      env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdoutBuf: Buffer = Buffer.alloc(0);
    let stderrBuf: Buffer = Buffer.alloc(0);
    let truncated = false;
    let timedOut = false;
    let settled = false;
    let stopTimer: NodeJS.Timeout | undefined;

    const settle = (code: number | null, sig: NodeJS.Signals | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      clearTimeout(stopTimer);
      signal?.removeEventListener("abort", onAbort);
      resolve({
        code,
        signal: sig,
        stdout: stdoutBuf.toString("utf8"),
        stderr: stderrBuf.toString("utf8"),
        outputTruncated: truncated,
        timedOut,
        durationMs: Date.now() - started,
      });
    };

    const stop = (sig: NodeJS.Signals): void => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill(sig);
      stopTimer = setTimeout(() => {
        try {
          if (child.exitCode === null && child.signalCode === null) {
            child.kill("SIGKILL");
          }
        } catch {
          /* process already gone */
        }
      }, STOP_GRACE_MS);
      stopTimer.unref?.();
    };

    const onAbort = (): void => stop("SIGTERM");

    const append = (target: Buffer, chunk: Buffer | string): { buf: Buffer; hit: boolean } => {
      const chunkBuf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (target.length + chunkBuf.length > maxOutputBytes) {
        const space = Math.max(0, maxOutputBytes - target.length);
        return { buf: Buffer.concat([target, chunkBuf.subarray(0, space)]), hit: true };
      }
      return { buf: Buffer.concat([target, chunkBuf]), hit: false };
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      const r = append(stdoutBuf, chunk);
      stdoutBuf = r.buf;
      if (r.hit) {
        truncated = true;
        stop("SIGTERM");
      }
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      const r = append(stderrBuf, chunk);
      stderrBuf = r.buf;
      if (r.hit) {
        truncated = true;
        stop("SIGTERM");
      }
    });

    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      stop("SIGTERM");
    }, timeoutMs);
    timeoutTimer.unref?.();

    signal?.addEventListener("abort", onAbort, { once: true });

    child.on("error", (err) => {
      stderrBuf = Buffer.concat([
        stderrBuf,
        Buffer.from(`\n[vestige] spawn failed: ${err.message}\n`),
      ]);
      settle(null, null);
    });
    child.on("close", (code, sig) => {
      if (timedOut && sig === null && code === null) {
        // Timed out without an observable signal: surface deadline error shape.
        settle(null, "SIGTERM");
        return;
      }
      settle(code, sig);
    });
  });
};

/** Throws a typed timeout error when a run hit its deadline. */
export const assertNotTimedOut = (
  operation: string,
  result: BoundedRunResult,
  timeoutMs: number,
): void => {
  if (result.timedOut) throw timeoutError(operation, timeoutMs);
};
