/**
 * Central redaction applied to every log line and to captured external-tool
 * output before it is stored as evidence. Addresses the reference design's
 * weakness where redaction was opt-in per provider.
 */

const SECRET_PATTERNS: RegExp[] = [
  // Bearer tokens / API keys commonly appearing in tool output or env dumps.
  /bearer\s+[\w\-._~+/]+=*/gi,
  /(?:api[_-]?key|apikey|secret|password|token|authorization)\s*[:=]\s*\S+/gi,
];

const REDACTED = "[redacted]";

export const redactText = (text: string): string => {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (match) =>
      // Keep very short benign matches (e.g. a bare header name) intact.
      match.length <= 8 ? match : REDACTED,
    );
  }
  return out;
};

export type LogLevel =
  | "trace"
  | "debug"
  | "info"
  | "warn"
  | "error"
  | "silent";

const LEVEL_WEIGHT: Record<LogLevel, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  silent: 100,
};

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

/**
 * JSON logger writing to stderr only, so stdout stays reserved for the
 * stdio MCP transport and CLI machine-readable output. Every message and
 * string field value passes through the central redactor.
 */
export const createLogger = (
  level: LogLevel = "info",
  destination: NodeJS.WritableStream = process.stderr,
): Logger => {
  const threshold = LEVEL_WEIGHT[level];
  const emit = (
    lineLevel: Exclude<LogLevel, "silent">,
    message: string,
    fields?: Record<string, unknown>,
  ): void => {
    if (LEVEL_WEIGHT[lineLevel] < threshold) return;
    const entry: Record<string, unknown> = {
      ts: new Date().toISOString(),
      level: lineLevel,
      msg: redactText(message),
    };
    if (fields) {
      for (const [key, value] of Object.entries(fields)) {
        entry[key] =
          typeof value === "string"
            ? redactText(value)
            : value instanceof Error
              ? redactText(String(value.stack ?? value.message))
              : value;
      }
    }
    destination.write(`${JSON.stringify(entry)}\n`);
  };
  return {
    debug: (m, f) => emit("debug", m, f),
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
  };
};

export const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};
