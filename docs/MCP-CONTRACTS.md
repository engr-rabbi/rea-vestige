# MCP contracts reference

Server name: `vestige-mcp` · Protocol: MCP over stdio (default) or streamable HTTP (`/mcp`).
SDK: `@modelcontextprotocol/server` 2.4.0 (pinned). All tool inputs are declared with Zod
contracts; the SDK advertises JSON schemas and validates calls. Errors are returned as
`isError` results with a machine-readable payload in `structuredContent.error`:

```json
{
  "error": {
    "code": "path_rejected | target_not_registered | invalid_input | provider_unavailable | timeout | resource_limit | not_found | cancelled | internal | …",
    "message": "human-readable summary",
    "remediation": "producer-authored next step",
    "details": {},
    "retryable": false
  }
}
```

## Tools

### vestige_register_target
Register an authorized file/directory for analysis. Validates the path (canonicalization,
symlink policy, allowed roots), computes SHA-256, identifies format. Read-only.
- Input: `{ path: string (min 1), label?: string (≤200) }`
- Output: `{ artifact, created, canonicalPath, message }`
- Errors: `path_rejected` (nonexistent, traversal, symlink-escape, NUL, outside allowed roots)

### vestige_list_targets
- Input: `{}` — Output: `{ targets: Artifact[], count }`

### vestige_get_target
- Input: `{ artifactId }` — Output: `{ artifact, supportedBy: ProviderDescriptor[] }`

### vestige_list_providers
- Input: `{}` — Output: `{ providers: [{ id, name, version, formats, availability, capabilities }] }`
- Availability is probed live; unavailable providers include `reason` + `guidance`
  (e.g., Ghidra installation instructions).

### vestige_analyze
Start an async job. Poll `vestige_job_status`; pass `_meta.progressToken` for progress
notifications.
- Input: `{ artifactId, provider?: string, capabilities?: string[] }`
- Output: `{ jobId, status, artifactId, providerId, poll }`
- The tool returns immediately; provider failures surface as `job.error` with the same
  typed error payload shape.

### vestige_job_status / vestige_job_cancel
- Input: `{ jobId }` — Output: `{ job }` / `{ cancelled, job }`
- Cancelling aborts the provider via `AbortSignal`; already-persisted evidence is retained
  and the job ends as `cancelled`.

### vestige_list_findings
- Input: `{ artifactId, kind?, confidence?, limit (≤1000, default 100), offset }`
- Output: `{ findings: Finding[], total, offset, limit }`

### vestige_get_evidence
- Input: `{ evidenceId }` — Output: `{ evidence, verified: true }`
- Records are re-authenticated against their content digest on every read; failed
  verification is surfaced as `not_found` rather than serving tampered data.

### vestige_export_report
- Input: `{ artifactId, format: "markdown" | "json" }` — Output: `{ path, format, findingsCount }`
- Writes a deterministic report into the isolated workspace; the path is absolute and
  safe to read with any tool.

### vestige_diagnostics
- Input: `{}` — Output: versions, runtime, data dirs, per-provider availability with guidance.

## Resources

| URI | MIME | Contents |
|---|---|---|
| `vestige://target/{artifactId}` | application/json | Artifact metadata (path, sha256, format, architecture) |
| `vestige://target/{artifactId}/findings` | application/json | Full finding list |
| `vestige://target/{artifactId}/report.md` | text/markdown | Deterministic markdown report |

`resources/list` enumerates registered targets.

## Prompts

| Name | Args | Purpose |
|---|---|---|
| `vestige_investigate_target` | `artifactId` | Evidence-first investigation plan (identity → providers → analyze → findings → evidence → report) |
| `vestige_triage_javascript` | `artifactId` | JS/Electron triage: entry points, IPC surface, routes, privileged imports |

## Progress & cancellation

Clients MAY include `_meta.progressToken` on `vestige_analyze`; the server emits
`notifications/progress` (monotonic counter, optional `total`, human message). Cancellation
sources: client `notifications/cancelled` (SDK aborts the request signal), or explicit
`vestige_job_cancel`. Evidence persisted before cancellation remains queryable.

## Session behavior

- **stdio**: one session per process; stdout is protocol-only; logs (redacted JSON) on stderr.
- **HTTP**: `POST /mcp`; per-session transports (parallel clients OK); initialize returns a
  session id; idle sessions reaped after 30 min; bearer token required for non-loopback binds;
  Host/Origin allowlists enforced; 8 MiB request cap.
