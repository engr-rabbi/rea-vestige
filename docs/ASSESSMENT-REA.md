# Stage A — Repository Assessment: reference implementation `morluto/rea`

- Reference inspected: `rea-main.zip` (GitHub `morluto/rea`, package `rea-agents`, version **6.8.0**, MIT license, © 2026 morluto).
- Inspection method: direct source reading plus three structured code-exploration passes over `src/`, `tests/`, `bridge/`, `docs/`, and `.github/`. Findings below cite files and symbols. Items marked **[H]** are hypotheses that require follow-up; everything else was verified in source.
- Purpose: inform the design of an independent, improved platform (this repository, "Vestige"). No REA code, branding, or binaries were copied; REA's MIT license permits reuse, but the new implementation was written from scratch unless explicitly noted.

---

## 1. Repository overview

| Aspect | Verified observation |
|---|---|
| Layout | Single npm package (`rea-agents`), ESM, no npm workspaces; task orchestration via turbo (`turbo.json`) |
| Toolchain | TypeScript strict, vitest (multi-project), oxlint/oxfmt, knip, jscpd, stryker (mutation), husky, release-please |
| Runtime | Node `^22.23.4 || ^24.22.1 || >=26.12.1` (`.nvmrc` 24.22.1) |
| MCP SDK | `@modelcontextprotocol/server` **2.3.1** + `@modelcontextprotocol/client` 2.3.1 (current 2.x split-package line; 2.4.0 is latest at assessment time) |
| Validation | Zod 4.6.6 everywhere; contracts are the single source of truth projected into SDK registration via Standard Schema |
| Parser | `@babel/parser` 8 behind an inert parser boundary (`src/domain/javascript/javascriptSourceParser.ts`) |
| Size | 6,526 files; `src/` ≈ 36 MB / 3,000+ TS files (1,114 in `src/domain` alone); 2,000+ test files |

Entry points: `scripts/rea.mjs` (dispatcher) → `src/main.ts` (MCP stdio/HTTP) or `src/cli.ts`; composition root `src/composition/` (~41 factory modules); server assembly `src/server/createServer.ts` (1,340 lines, ~60 `register*Tools` modules, 141 `registerTool` call sites).

## 2. Architecture and execution flow (verified)

Dependency direction is clean and enforced by a meta-test (`tests/evaluation/moduleBoundaries.test.ts` + `scripts/lib/module-boundaries.mjs`):

```
main/cli ──▶ server/cli adapters ──▶ application services ──▶ provider adapters ──▶ process foundation
                     │                        │                                          │
                     └──▶ contracts (Zod) ◀── domain (pure) ◀───────────────────────────┘
```

- **MCP layer** (`src/server/`): class chain `McpServer` → `RequestTrackingMcpServer` (drain tracking) → `EvidenceMcpServerCore` (registration projection, error-transport wrapping, prompt completion) → `EvidenceMcpServer` / `DeferredEvidenceMcpServer` (lazy runtime materialization from a build-recorded tool catalog with SHA-256-verified catalog bytes, `src/main/deferredRuntime.ts`).
- **Tool registration** (`src/server/toolRegistrationOptions.ts`): canonical Zod contracts projected straight into `registerTool` via Standard Schema; advertised schemas can be rewritten under a byte budget while the canonical parser stays authoritative (`EvidenceMcpServerCore.registerTool`).
- **Evidence model** (`src/domain/evidence.ts`): one central `evidenceSchema`; `evidence_id` is a content-derived digest (`ev_…`) over canonical JSON of semantic fields (excluding display-only `local_path`), re-authenticated on parse ("tampered semantic ID" rejection). Confidence enum `observed|derived|inferred`; authority enum (`shipped-artifact`, `controlled-replay`, `historical-reference`, `external-service`, `analyst-inference`); typed locations (address / offset / path); limitations array; `raw_result` kept alongside `normalized_result`.
- **Session/admission** (`src/application/binary/BinarySession.ts`, `src/server/analysisAdmission.ts`): target resolution canonicalizes the path, opens with `O_NOFOLLOW`, commits SHA-256, serializes target transitions; every provider-backed tool runs under `withAdmittedAnalysis`; mutating external commands retire the session (`src/server/externalMutationAdmission.ts`).
- **Process foundation** (`src/process/`): `execFileOutput` (shell-free, bounded, abortable, `stopSignal` with grace ladder); `spawnOwnedProviderProcess` (detached process group + run-token env, supervisor with bounded diagnostics, `ProviderStartupDeadline`); `cleanupOwnedProcessGroup` with process-table snapshot + token verification loop; Windows Job Objects via native addon (`native/windows/src/`, `src/process/WindowsAuthority.ts`).
- **Ghidra integration** (`src/ghidra/`, `bridge/ghidra/ReaGhidraBridge.java`): availability probing (`GhidraInstallation.inspectGhidraInstallation`), headless launch with batch-safe argv on Windows, NDJSON request/response over a Unix socket with `rw-------` perms (loopback TCP + endpoint file on Windows), per-request bearer tokens compared in constant time, target snapshot copied into a private runtime root and re-hashed before use (`GhidraTargetSnapshot.createGhidraTargetSnapshot`).
- **JavaScript/Electron** (`src/javascript/`, `src/domain/javascript/`): Babel AST inside a heap-limited worker (`src/javascript/analysis/JavaScriptAnalysisWorkerServer.ts`, NDJSON frame budgets, forced GC), module IR, route inventory with explicit gap/omission records, Electron IPC admission only through proven `ipcMain`/`ipcRenderer` namespace paths (`electronStaticAnalysisIpc.ts`).
- **Configuration** (`src/config/`): env-only, Zod-validated, one module per setting with colocated tests; rejects NUL bytes; messages name constraints, never rejected values.
- **Logging** (`src/logger.ts`): pino, JSON, stderr-only (`dest: 2`), `REA_LOG_LEVEL`.

## 3. Verified strengths worth preserving (design inspiration)

1. **Content-addressed evidence identity** with tamper detection (`src/domain/evidence.ts#computeEvidenceId`, `parseEvidence`).
2. **Admission before analysis**: canonical path + `O_NOFOLLOW` + SHA-256 commitment (`src/application/BinaryTargetResolver.ts#parseBinaryTarget`, `src/filesystem/RegularFile.ts#openRegularFile`).
3. **Shell-free process execution everywhere**, argv arrays, stop ladders, owned process groups, run tokens (`src/process/`).
4. **Contract-first tools**: Zod contracts are the single source of truth for inputs, outputs, annotations, and docs (`src/contracts/`, `docs/mcp-contracts.md`).
5. **Provider availability diagnostics** instead of hard requirements (`src/application/AnalysisProvider.ts#ProviderAvailability`, `GhidraDoctor`).
6. **Bounded everything**: output budgets, diagnostic budgets, frame budgets, late-output caps.
7. **Programmatic fixtures**: binaries synthesized in-process (e.g. `tests/fixtures/machoArmSlices.ts`); captured golden tool outputs committed with provenance (`tests/fixtures/golden/provenance.json`).
8. **Defensive stdio startup** (`src/main/StdioStartupInput.ts`) and stdout purity for the protocol.

## 4. Verified weaknesses / gaps (the improvement matrix)

| # | Weakness (verified location) | Impact | Priority | Vestige response |
|---|---|---|---|---|
| W1 | No accuracy benchmarks: no precision/recall/false-positive infrastructure anywhere in `src/` or `tests/` ("accuracy" enforced only via coverage %, hand-reviewed `docs/verification/*.md`) | Accuracy claims are not measurable | **P0** | Deterministic fixture ground truth + benchmark harness measuring precision/recall/FPR/latency; results published only from actual runs |
| W2 | HTTP transport auth = Host/Origin allowlist only; "plain HTTP without TLS or client authentication" (`src/server/http/serveStreamableHttp.ts:489`, `docs/mcp-contracts.md:752`) | Non-loopback deployments expose tools unauthenticated | **P0** | Bearer-token auth (constant-time compare) required for any non-loopback HTTP bind + loopback default + Host/Origin allowlist |
| W3 | Single-session HTTP: new `initialize` evicts the live session; drain-timeout wedges endpoint into 503 (`serveStreamableHttp.ts:202–220`) | Poor multi-client behavior | P1 | Multi-session HTTP with per-session state and idle reaping |
| W4 | Error `structuredContent` stripped from the wire for `isError` results (`EvidenceMcpServerCore.ts:504–519`) | Clients can't consume typed errors programmatically | P1 | Typed error payloads delivered in `structuredContent` with machine-readable codes |
| W5 | Composition root: 1,340-line `createServer.ts`, ~45-entry hand-maintained `closeProviders()` list | Easy to add provider without cleanup entry | P1 | Small explicit composition with provider registry that owns cleanup automatically (single close path) |
| W6 | No MCP resources; large bundles returned via tool results only (0 hits for `registerResource`) | Big reports bloat tool responses | P1 | MCP resources for reports/evidence collections with stable URIs |
| W7 | Normalization fragmented across dozens of per-domain `normalize*` modules (no registry) | Cross-provider comparison semantics vary | P2 | Single normalization layer + shared finding taxonomy |
| W8 | Log redaction opt-in per provider (no pino `redact`); `sync:false` stderr destination can drop final logs (`src/logger.ts`) | Secret leakage risk by omission | P1 | Central redaction middleware on the logger + secret pattern scrubbing on captured output |
| W9 | Memory caps Windows-only for provider trees (`ProviderProcess.ts:308` throws on POSIX); POSIX cleanup can give up after revalidation limit (`ProcessOwnership.ts:394`) | Resource-limit asymmetry | P2 | Document honestly; use worker threads + heap caps for in-process parsing on all platforms |
| W10 | Deferred startup narrow (HTTP/scoped families force full eager startup, `src/main.ts:106–117`) | Slow starts in common agent setups | P3 | Simple fast start: providers constructed lazily on first use |
| W11 | No general content-addressed analysis cache (only Kuna's project cache, `src/kuna/KunaProjectCache.ts`) | Repeated analyses re-run | P2 | Content-addressed cache keyed by (provider, providerVersion, target SHA-256, options digest) |
| W12 | Evidence ID legacy-compat branch can diagnose but never admit old records (`usesPre66NullCoverageIdentity`) | Sharp operational edge | P3 | Single evidence-ID scheme; explicit version field for future evolution |
| W13 | Known cancellation gap: SDK-suppressed error replies lose partial-observation recovery (`docs/mcp-contracts.md:888`) | Lost partial evidence on cancel | P3 | Persist partial evidence before cancel handling; job records survive reply suppression |
| W14 | `withAdmittedAnalysis` "fixed" overload performs no session admission (`src/server/analysisAdmission.ts:26–33`) | Correctness relies on call-site discipline | P3 | No admission-free path exists in the new tool layer (type-level guarantee) |

**Dependency risks (verified):** large transitive surface for an analysis CLI (`playwright-core`, `isomorphic-git`, `openpgp`, `@lydell/node-pty` always installed even when unused); `cross-spawn` history of advisories; engines pin excludes current Node 22.x LTS minors below 22.23.4. **[H]** Some heavy deps appear load-bearing only for optional providers; a leaner default install is feasible (Vestige ships a minimal dependency set and gates tool-dependent providers behind availability checks instead of npm packages).

## 5. License posture

- REA code is **MIT** (LICENSE, © 2026 morluto). `THIRD_PARTY_NOTICES.md` + `licenses/` inventory MIT/Apache-2.0/ISC/BSD deps. Ghidra bridge scripts are REA-authored (MIT) calling Ghidra's public APIs — no GPL code is copied into JS; Ghidra itself remains external and optional.
- Vestige is independently implemented; reference used for architectural learning only. MIT license + own `THIRD_PARTY_NOTICES.md`; no REA branding, no "official REA" claims.

## 6. Migration / implementation plan (carried into Stages B–I)

1. **Foundation**: strict TS ESM package; Zod domain contracts (artifact/evidence/finding/job); content-addressed evidence IDs; central PathGuard; bounded process runner; redacting logger (addresses W8, W14).
2. **Providers**: registry with capability descriptors + availability diagnostics (REA pattern, simplified); Tier-1 pure-TS providers (JavaScript/Electron via acorn; ELF/PE/Mach-O header+symbol parsers; strings); Tier-2 Ghidra headless integration behind a documented boundary with availability detection (REA pattern, independent protocol).
3. **MCP**: stdio default; streamable HTTP with bearer-token auth (W2); typed errors in structuredContent (W4); MCP **resources** for reports/evidence (W6); progress + cancellation via AbortController; evidence persisted before cancel replies (W13).
4. **Accuracy**: deterministic fixture builders with embedded ground truth; benchmark harness computing precision/recall/FPR/latency; regression tests on golden results (W1).
5. **Ops**: cache keyed by content digests (W11); diagnostics command; security tests (traversal, symlink, oversized output, timeout/cancel, injection); CI with audit + secret scan.

*Assessment complete; no reference code was modified. Original ZIP preserved at `/home/z/my-project/upload/rea-main.zip`.*
