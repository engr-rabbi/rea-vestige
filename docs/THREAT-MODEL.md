# Vestige threat model

Scope: Vestige analyzes software artifacts the operator owns or is explicitly authorized to
analyze. This document enumerates assets, attacker classes, and the controls in v0.1. It is a
living document — update it with every security-relevant change.

## 1. Assets

| Asset | Location | Notes |
|---|---|---|
| Original target artifacts | operator filesystem | Must remain unmodified; read-only access |
| Evidence store | `VESTIGE_DATA_DIR/evidence` | Integrity-critical: agents reason from it |
| Registry | `VESTIGE_DATA_DIR/registry` | Defines what is authorized |
| Workspace | `VESTIGE_WORK_DIR` | Scratch; deletable by design |
| Bearer token (HTTP mode) | env `VESTIGE_HTTP_TOKEN` | Never logged; constant-time compared |
| Logs | stderr | Must not leak secrets or sensitive artifact content |

## 2. Attackers and threats

### A. Malicious artifact (untrusted input to parsers)
- **T1 Crafted binary/parser confusion** — malformed ELF/PE/Mach-O crafted to corrupt parsing memory or produce misleading output.
  *Controls*: pure-TS bounds-checked parsing (no native memory unsafety), out-of-bounds reads rejected with parse gaps, symbol caps (20k/table), 64 MiB read cap. *Residual*: a buggy parser could mis-report structure — mitigated by fixture ground truth + parse-gap reporting, never by trust.
- **T2 Pathological JS sources** (billion-laughs style ASTs, huge generated files).
  *Controls*: 1 MiB/file cap, 2,000-file scan cap, 120k AST-node cap with typed `resource_limit` error, `node_modules`/build dirs excluded.
- **T3 Evidence poisoning via crafted content** — artifact crafted so its analysis fabricates evidence IDs.
  *Controls*: evidence IDs are digests of the provider observation, not artifact-controlled strings; re-verification on read rejects tampered records.

### B. Malicious MCP client (network or local agent)
- **T4 Unregistered/unauthorized target access**.
  *Controls*: registry-gated analysis; `VESTIGE_ALLOWED_ROOTS` restricts registration to operator-approved directories; canonical-path + `realpath` checks.
- **T5 Path traversal / symlink escape** (`../../`, symlink chains, NUL bytes).
  *Controls*: NUL rejection, `realpath` before admission, allowed-root containment after resolution, symlink policy (`reject` available), `resolveWithin` containment for directory reads. Tested in `tests/security/` and `tests/unit/security/`.
- **T6 Command injection via target paths/names**.
  *Controls*: external tools are only ever spawned with **argv arrays** (`shell: false`); paths are never interpolated into shell strings; injection resistance is asserted by `tests/unit/process/runBounded.test.ts`.
- **T7 HTTP: DNS rebinding / browser-origin attacks**.
  *Controls*: Host-header allowlist (SDK `localhostAllowedHostnames` + configured host), Origin validation, non-loopback binds refuse to start without a bearer token; tokens compared in constant time; no token in logs or error payloads.
- **T8 Resource exhaustion via API abuse** (huge job storms, oversized payloads).
  *Controls*: 8 MiB HTTP body cap, bounded job retention (200), output caps on child processes, per-tool timeouts, bounded evidence objects (100 KiB observation cap).

### C. Local attacker with filesystem access
- **T9 Evidence/registry tampering**.
  *Controls*: content-derived IDs re-authenticated on read (tampered records are refused, not served); atomic writes (tmp+rename); registry schema-validated on load. *Residual*: an attacker with write access to `VESTIGE_DATA_DIR` can delete data — protect the directory with OS permissions.
- **T10 Symlink games inside data dir** — out of scope for v0.1 hardening (local-trust boundary), documented as residual risk.

### D. Supply chain
- **T11 Dependency compromise**.
  *Controls*: exact-pinned runtime deps (`@modelcontextprotocol/server` 2.4.0, zod 4.6.7, acorn 8.19.0, acorn-walk 8.3.4 — 4 runtime packages), `npm audit` in CI, lockfile committed. Small surface is a design goal: tool-dependent providers are gated behind availability checks instead of npm packages.

## 3. Explicit non-goals (v0.1)

- **No runtime execution of targets.** Dynamic/runtime observation is not implemented; there is
  no sandbox to escape. Any future runtime capability must ship with an isolation policy,
  explicit opt-in, and its own threat model section.
- **No multi-tenancy.** HTTP mode assumes a single operator per deployment; use network-level
  isolation (e.g., bind to loopback behind an authenticated proxy) for shared hosts.
- **No license-bypass, credential theft, stealth, or unauthorized-persistence features.**
  Vestige is for authorized analysis and defensive understanding only.

## 4. Security test coverage map

| Threat | Test |
|---|---|
| T2 | `tests/unit/providers/js.test.ts` (parse gaps), oversized-file case in `tests/security/` |
| T4/T5 | `tests/security/security.test.ts`, `tests/unit/security/pathGuard.test.ts` |
| T6 | `tests/unit/process/runBounded.test.ts` (argv injection proof) |
| T7 | `tests/integration/httpAuth.test.ts` (401/403 paths, token handshake) |
| T3/T9 | `tests/unit/domain/evidence.test.ts` (tamper), `tests/security/security.test.ts` (read-path verification) |
| T8 | `tests/unit/process/runBounded.test.ts` (oversize, timeout), job retention in `tests/unit/services/jobManager.test.ts` |

## 5. Reporting

See [`../SECURITY.md`](../SECURITY.md) for the vulnerability reporting policy.
