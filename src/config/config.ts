import os from "node:os";
import path from "node:path";
import { z } from "zod";
import type { LogLevel } from "../util/log.js";
import { invalidInput } from "../errors/errors.js";

const positiveInt = z.coerce
  .number()
  .int()
  .positive()
  .or(z.literal("").transform(() => undefined));

const configSchema = z.object({
  VESTIGE_DATA_DIR: z.string().optional(),
  VESTIGE_WORK_DIR: z.string().optional(),
  VESTIGE_LOG_LEVEL: z
    .enum(["trace", "debug", "info", "warn", "error", "silent"])
    .optional(),
  VESTIGE_MAX_INPUT_FILE_BYTES: positiveInt.optional(),
  VESTIGE_MAX_SCAN_FILES: positiveInt.optional(),
  VESTIGE_TOOL_TIMEOUT_MS: positiveInt.optional(),
  VESTIGE_MAX_TOOL_OUTPUT_BYTES: positiveInt.optional(),
  VESTIGE_HTTP_PORT: positiveInt.optional(),
  VESTIGE_HTTP_HOST: z.string().optional(),
  VESTIGE_HTTP_TOKEN: z.string().optional(),
  VESTIGE_HTTP_ALLOWED_ORIGINS: z.string().optional(),
  VESTIGE_ALLOWED_ROOTS: z.string().optional(),
  GHIDRA_INSTALL_DIR: z.string().optional(),
});

export interface VestigeConfig {
  dataDir: string;
  workDir: string;
  logLevel: LogLevel;
  maxInputFileBytes: number;
  maxScanFiles: number;
  toolTimeoutMs: number;
  maxToolOutputBytes: number;
  http: {
    port: number;
    host: string;
    /** Bearer token required for non-loopback binds (never logged). */
    token?: string;
    allowedOrigins: string[];
  };
  /** Explicit allowed roots for target registration; empty = open local mode. */
  allowedRoots: string[];
  ghidraInstallDir?: string;
}

export const defaultDataDir = (): string =>
  process.env.VESTIGE_DATA_DIR?.trim()
    ? path.resolve(process.env.VESTIGE_DATA_DIR)
    : path.join(os.homedir(), ".vestige");

/**
 * Validate and resolve configuration. Unknown keys are ignored; invalid
 * values produce an actionable error naming the constraint (never the value).
 */
export const loadConfig = (
  source: NodeJS.ProcessEnv = process.env,
): VestigeConfig => {
  const parsed = configSchema.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
      .join("; ");
    throw invalidInput(
      `Invalid configuration: ${issues}`,
      "Fix the offending environment variables or .env entries, then restart. See .env.example.",
    );
  }
  const v = parsed.data;
  const dataDir = v.VESTIGE_DATA_DIR?.trim()
    ? path.resolve(v.VESTIGE_DATA_DIR)
    : path.join(os.homedir(), ".vestige");
  const workDir = v.VESTIGE_WORK_DIR?.trim()
    ? path.resolve(v.VESTIGE_WORK_DIR)
    : path.join(dataDir, "work");

  const token = v.VESTIGE_HTTP_TOKEN?.trim() || undefined;
  const host = v.VESTIGE_HTTP_HOST?.trim() || "127.0.0.1";
  const port = v.VESTIGE_HTTP_PORT ?? 0;
  const loopback =
    host === "127.0.0.1" || host === "localhost" || host === "::1";
  if (!loopback && !token) {
    throw invalidInput(
      "VESTIGE_HTTP_HOST is non-loopback but no VESTIGE_HTTP_TOKEN is set.",
      "Set a strong VESTIGE_HTTP_TOKEN (e.g. `openssl rand -hex 32`) or bind to 127.0.0.1.",
    );
  }
  return {
    dataDir,
    workDir,
    logLevel: v.VESTIGE_LOG_LEVEL ?? "info",
    maxInputFileBytes: v.VESTIGE_MAX_INPUT_FILE_BYTES ?? 52_428_800,
    maxScanFiles: v.VESTIGE_MAX_SCAN_FILES ?? 2_000,
    toolTimeoutMs: v.VESTIGE_TOOL_TIMEOUT_MS ?? 120_000,
    maxToolOutputBytes: v.VESTIGE_MAX_TOOL_OUTPUT_BYTES ?? 4_194_304,
    http: {
      port,
      host,
      token,
      allowedOrigins: (v.VESTIGE_HTTP_ALLOWED_ORIGINS ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    },
    allowedRoots: (v.VESTIGE_ALLOWED_ROOTS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    ghidraInstallDir: v.GHIDRA_INSTALL_DIR?.trim() || undefined,
  };
};
