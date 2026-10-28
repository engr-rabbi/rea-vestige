# Vestige architecture

## 1. Goals

1. **Evidence over assertions** — analysis output is only as good as its provenance; every finding links to re-authenticated evidence.
2. **Measurable accuracy** — deterministic fixtures with embedded ground truth; benchmarks computed, not claimed.
3. **Least privilege by default** — explicit target registration, read-only analysis, bounded process execution.
4. **Dependency discipline** — application services depend on provider *interfaces*, never on external tools directly.

## 2. Module map and dependency direction

```
┌────────────────────────────────────────────────────────────────────┐
│ Entry points                                                       │
│   src/cli/main.ts        (one-shot commands)                       │
│   src/server/main.ts     (MCP server: stdio | streamable HTTP)     │
└──────────────┬─────────────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────────────┐
│ Composition root: src/server/context.ts                            │
│   the ONLY place that instantiates concrete providers              │
└──────────────┬─────────────────────────────────────────────────────┘
               ▼
┌────────────────────────────┐   ┌──────────────────────────────────┐
│ Application services       │   │ Contracts & domain (pure, Zod)   │
│   src/services/            │   │   src/domain/artifact.ts         │
│    AnalysisService         │──▶│   src/domain/evidence.ts         │
│    TargetRegistry          │   │   src/domain/finding.ts          │
│    EvidenceStore           │   │   src/domain/job.ts              │
│    JobManager              │   │   src/domain/format.ts           │
│    ProviderRegistry        │   │   src/providers/types.ts         │
└──────────────┬─────────────┘   │   src/server/toolSchemas.ts      │
               ▼                 └──────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────┐
│ Providers (src/providers/*) — depend on interfaces only            │
│   javascript/  (in-process acorn AST)                              │
│   native/      (pure-TS ELF · PE · Mach-O)                         │
│   ghidra/      (external analyzeHeadless behind a testable bridge) │
└──────────────┬─────────────────────────────────────────────────────┘
               ▼
┌──────────────────────────┐  ┌───────────────────────────────────┐
│ Security (src/security)  │  │ Process (src/process)             │
│   PathGuard (admission)  │  │   runBounded (argv arrays, caps,  │
│   Workspace (isolated    │  │    timeouts, abort, stop ladder)  │
│    scratch dirs)         │  │                                   │
└──────────────────────────┘  └───────────────────────────────────┘
```

**Enforced rules**

- `domain/` imports nothing except `util/` and Zod. No I/O in domain logic (except format probing helpers that only read bytes passed to them).
- `services/` may import `domain/`, `security/`, `process/`, `errors/`, `util/` — never concrete providers.
- `providers/` may import `domain/`, `security/`, `process/`, `errors/`, `util/` — never `services/` or `server/`.
- `server/` composes everything; `context.ts` is the single composition root (fixes the reference project's 1,340-line composition with a hand-maintained close list — here providers are registered once and own their cleanup semantics).

## 3. Data flow: registration → analysis → evidence

1. **Register** (`vestige_register_target`): `PathGuard.admit()` canonicalizes the path (`realpath`, symlink policy, allowed roots, regular-file/dir check, readability). `sha256Artifact()` computes the identity digest (streaming for files; bounded manifest walk for directories). The registry persists atomically (tmp file + rename). The artifact is **never written to**.
2. **Analyze** (`vestige_analyze`): `AnalysisService` validates the target exists in the registry (unregistered ⇒ typed failure), selects a provider by declared format support and availability, computes the cache key = SHA-256(canonical{providerId, providerVersion, capabilities, artifactSha256}), and runs the provider with an `AbortSignal` and progress callback.
3. **Persist**: provider `Evidence` records are content-verified (`ve_…` IDs re-derived and compared), stored under `data/evidence/objects/`, indexed in an append-only JSONL; `Finding` records are stored per artifact. Evidence is written **before** findings and before the completed status — cancellation keeps partial evidence.
4. **Consume**: `vestige_list_findings` → `vestige_get_evidence` (re-authenticated on every read), resources (`vestige://target/…`), and `vestige_export_report` (deterministic markdown/JSON).

## 4. MCP layer

- Built on the current stable `@modelcontextprotocol/server` **2.x** (split-package line), pinned exactly.
- Tools are registered with **Zod contracts** — the SDK projects them into advertised JSON schemas and validates inputs; handlers additionally return **typed error payloads inside `structuredContent`** on failure (machine-readable `code` + `remediation`), instead of text-only errors.
- **Resources** expose large artifacts: `vestige://target/{id}`, `…/findings`, `…/report.md` — reports never bloat tool responses.
- **Prompts** (`vestige_investigate_target`, `vestige_triage_javascript`) encode the evidence-first workflow.
- **Progress**: `notifications/progress` are emitted when the client supplies a `progressToken`; cancellation flows from the request `AbortSignal` into providers; job state survives client cancellation (queryable via `vestige_job_status`).
- **stdio**: stdout is reserved for protocol bytes; all logs go to stderr as redacted JSON.
- **HTTP**: per-session transports (new sessions do not evict each other), bearer-token auth for non-loopback binds (constant-time compare), Host-header allowlist, Origin validation, 8 MiB body cap, idle-session reaping.

## 5. Persistence layout

```
<VESTIGE_DATA_DIR>/
├── registry/targets.json          # canonical JSON, atomic rename
├── evidence/
│   ├── objects/<xx>/<ve_id>.json  # immutable evidence objects (content-verified on read)
│   ├── findings/<artifactId>.json # finding records per artifact
│   └── index.jsonl                # append-only metadata index
├── cache/<sha256>.json            # provider results keyed by content digest
└── work/                          # isolated scratch (reports, ghidra projects)
```

## 6. Testing strategy

| Layer | Location | Focus |
|---|---|---|
| Unit | `tests/unit/` | domain identity/tamper checks, PathGuard, runBounded (timeout/abort/oversize/injection), registries, cache, parsers vs fixture ground truth, config, redaction |
| Integration | `tests/integration/` | real MCP client ↔ server over InMemoryTransport (tools, resources, prompts, validation), HTTP transport security |
| Security | `tests/security/` | traversal, symlink escape, allowed roots, unregistered targets, tampering detection, containment |
| Regression | `tests/regression/` | golden finding identities; two identical runs must produce identical ID sets |
| E2E | `tests/e2e/` | spawns the real server as a subprocess, official SDK client over stdio, full register→analyze→findings→evidence→report workflow |
| Benchmarks | `scripts/benchmarks/` | precision/recall/FPR/latency vs fixture ground truth |

Fixture binaries are **synthesized in code** (`tests/fixtures/builders.ts`) — no compiled
artifacts are committed, and every fixture embeds its own ground truth.
