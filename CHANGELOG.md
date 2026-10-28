# Changelog

All notable changes are documented here. Format follows Keep a Changelog; versioning is
semver. Pre-1.0 releases may break APIs between minor versions.

## [0.1.1] — 2026-10-28

### Fixed
- **Auto provider selection now falls back on unavailability.** In `auto` mode the
  first format-matching provider was selected and, if its runtime prerequisites were
  missing (e.g. Ghidra not installed), the whole job failed even when another
  registered provider (e.g. `native`) could have run. Selection now probes each
  format-matching candidate in registry order and commits to the first AVAILABLE
  one (`selectProvider` in `src/services/analysisService.ts`); a throwing
  `checkAvailability()` is treated as unavailable. If every candidate is
  unavailable, the job fails with an aggregated `provider_unavailable` payload
  listing each tried provider, its reason, and per-provider remediation.
- **Jobs record the provider that actually ran.** Auto-resolved jobs were created
  with `providerId: "auto"` and never updated; `JobManager.setProvider` now records
  the concrete provider after selection so status/report views never claim a
  provider that did not run.
- **Explicit provider requests never silently reroute.** A registered-but-unavailable
  or format-mismatched explicit provider remains a typed failure (kept operator
  predictability), with sharper messages distinguishing "not registered" from
  "does not support format".

### Added
- 5 regression tests for auto-selection (fallback, throwing availability probe,
  aggregated all-unavailable failure, explicit no-reroute, explicit format
  mismatch). Suite now 142 tests.

## [0.1.0] — 2026-10-28

Initial release.

### Added
- **MCP server** (`vestige mcp`): stdio transport (default) and streamable HTTP (`--http`)
  with bearer-token auth for non-loopback binds, Host/Origin allowlists, per-session
  transports, and idle reaping. Built on `@modelcontextprotocol/server` 2.4.0 (pinned).
- **MCP surface**: 11 tools (register/list/get targets, list providers, analyze, job
  status/cancel, list findings, get evidence, export report, diagnostics), 3 resources
  (`vestige://target/…`, `…/findings`, `…/report.md`), 2 guided prompts, progress
  notifications via `progressToken`, and typed error payloads in `structuredContent`.
- **CLI** (`vestige`): `register`, `targets`, `inspect`, `providers`, `analyze`, `status`,
  `findings`, `evidence`, `export`, `doctor`, `version`.
- **Domain model**: content-addressed evidence (`ve_…`) and finding (`vf_…`) identities with
  re-authentication on read; 5-level confidence taxonomy (observed-fact, static-inference,
  runtime-observation, ai-interpretation, hypothesis); typed locations; provider/method
  provenance on every record.
- **Providers**
  - `javascript`: acorn-AST module graph (imports/requires/dynamic imports/exports), Electron
    IPC channel discovery (literal names, namespace-admitted callees), express-style route
    inventory, package.json manifest facts.
  - `native`: pure-TypeScript ELF (32/64), PE (PE32/PE32+), Mach-O (incl. FAT) structural
    parsers — headers, sections, symbols, PE imports/exports, Mach-O dylibs, strings.
  - `ghidra`: optional headless decompilation behind a documented, unit-tested bridge
    (argv construction, schema-validated dump parsing, timeout/failure surfacing,
    availability detection with install guidance).
- **Security**: explicit target registration with canonical-path admission (realpath, symlink
  policy, allowed roots, NUL/traversal rejection); isolated workspace; shell-free bounded
  process runner (output caps, timeouts, stop ladder, abort); central log redaction.
- **Persistence**: atomic JSON registry, content-addressed evidence objects, per-artifact
  findings, append-only index, content-digest result cache.
- **Testing**: 137 tests across unit/integration/security/regression/e2e layers, including a
  real stdio end-to-end run with the official SDK client; deterministic binary fixture
  builders with embedded ground truth (no compiled artifacts committed).
- **Benchmarks**: precision/recall/FPR/latency harness (`npm run bench:record`) — results in
  `docs/BENCHMARKS.md` produced by an actual run.
- **Release engineering**: GitHub Actions CI (typecheck/lint/test/audit), issue & PR
  templates, MIT license, third-party notices, full documentation set.
