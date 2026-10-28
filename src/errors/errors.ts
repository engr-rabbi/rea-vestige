/**
 * Machine-readable error contract. Every tool failure is projected into this
 * shape so MCP clients can consume typed errors from `structuredContent`
 * (improvement over the reference implementation, which stripped structured
 * error payloads from the wire).
 */

export const ERROR_CODES = [
  "invalid_input",
  "target_not_registered",
  "path_rejected",
  "artifact_changed",
  "artifact_unreadable",
  "unsupported_format",
  "provider_unavailable",
  "provider_failed",
  "cancelled",
  "timeout",
  "resource_limit",
  "job_not_found",
  "not_found",
  "internal",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export interface ErrorPayload {
  code: ErrorCode;
  /** Human-readable summary safe for display. */
  message: string;
  /** Producer-authored next step for the caller. */
  remediation: string;
  /** Machine-readable details (constraint names, never raw secret values). */
  details?: Record<string, unknown>;
  retryable: boolean;
}

export class VestigeError extends Error {
  readonly payload: ErrorPayload;

  constructor(payload: ErrorPayload, options?: { cause?: unknown }) {
    super(payload.message, { cause: options?.cause });
    this.name = "VestigeError";
    this.payload = payload;
  }
}

export const invalidInput = (
  message: string,
  remediation: string,
  details?: Record<string, unknown>,
): VestigeError =>
  new VestigeError({
    code: "invalid_input",
    message,
    remediation,
    details,
    retryable: false,
  });

export const targetNotRegistered = (path: string): VestigeError =>
  new VestigeError({
    code: "target_not_registered",
    message: `Target is not registered for analysis: ${path}`,
    remediation:
      "Register the target first with vestige_register_target (CLI: vestige register <path>), then retry.",
    retryable: false,
  });

export const pathRejected = (
  message: string,
  remediation: string,
  details?: Record<string, unknown>,
): VestigeError =>
  new VestigeError({
    code: "path_rejected",
    message,
    remediation,
    details,
    retryable: false,
  });

export const providerUnavailable = (
  providerId: string,
  reason: string,
  guidance: string,
): VestigeError =>
  new VestigeError({
    code: "provider_unavailable",
    message: `Provider '${providerId}' is unavailable: ${reason}`,
    remediation: guidance,
    details: { provider: providerId },
    retryable: false,
  });

export const resourceLimit = (
  resource: string,
  limit: number | string,
  remediation: string,
): VestigeError =>
  new VestigeError({
    code: "resource_limit",
    message: `Resource limit exceeded: ${resource} (limit: ${String(limit)})`,
    remediation,
    details: { resource, limit },
    retryable: true,
  });

export const timeoutError = (
  operation: string,
  timeoutMs: number,
): VestigeError =>
  new VestigeError({
    code: "timeout",
    message: `Operation '${operation}' exceeded its ${String(timeoutMs)}ms deadline.`,
    remediation:
      "Retry with a larger timeout if supported, or reduce input size. Cancellation is honored between phases.",
    details: { operation, timeoutMs },
    retryable: true,
  });

export const notFound = (what: string, id: string): VestigeError =>
  new VestigeError({
    code: "not_found",
    message: `${what} '${id}' does not exist.`,
    remediation: `List available entries first (e.g. vestige_list_targets) and retry with a valid identifier.`,
    retryable: false,
  });

export const internalError = (
  message: string,
  cause?: unknown,
): VestigeError =>
  new VestigeError({ code: "internal", message, remediation: "Report this as a bug with the request identifier and server logs.", retryable: true }, { cause });

/** Project any thrown value into the stable wire error payload. */
export const projectError = (error: unknown): ErrorPayload => {
  if (error instanceof VestigeError) return error.payload;
  if (error instanceof Error) {
    if (error.name === "AbortError" || /cancel/i.test(error.message)) {
      return {
        code: "cancelled",
        message: error.message,
        remediation: "The operation was cancelled. Partial results may be available via vestige_job_status.",
        retryable: true,
      };
    }
    return {
      code: "internal",
      message: `Unexpected failure: ${error.message}`,
      remediation:
        "Retry the operation. If it persists, run vestige_diagnostics and include the output in a bug report.",
      retryable: true,
    };
  }
  return {
    code: "internal",
    message: "Unexpected non-error failure.",
    remediation: "Retry the operation; if it persists, run vestige_diagnostics.",
    retryable: true,
  };
};
