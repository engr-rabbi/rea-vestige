# Compatibility

Honest distinction between **tested in this checkout** and **intended/reasonably expected**.
Do not assume untested platforms work; CI matrix expansion is tracked in CONTRIBUTING.md.

## Runtime

| Component | Tested (this checkout) | Intended |
|---|---|---|
| Node.js | 24.22.1 (Linux x64) | ≥20.19 (LTS line); engines field enforces |
| TypeScript | 5.9.3 strict, `NodeNext` | — |
| MCP SDK | `@modelcontextprotocol/server` 2.4.0, `@modelcontextprotocol/client` 2.4.0 (tests) | 2.x line |
| Zod | 4.6.7 | 4.x |
| acorn | 8.19.0 (+ acorn-walk 8.3.4) | 8.x |

## Operating systems

| OS | Status | Notes |
|---|---|---|
| Linux x64 | ✅ **Tested** — full suite (137 tests) + benchmarks + e2e over real stdio | Primary development platform |
| macOS arm64/x64 | ⚠️ Intended, not exercised here | Pure-TS parsers are endian-aware; Mach-O tests cover the format; no OS-specific code paths are known-required. Report issues via GitHub |
| Windows x64 | ⚠️ Intended, not exercised here | `path` handling uses `node:path` (platform-correct); no shell is ever spawned (`shell:false`), so no cmd.exe quoting class of bugs. Known gap: no `O_NOFOLLOW` on Windows — PathGuard uses `lstat` fallback |

## External tools

| Tool | Required? | Tested | Notes |
|---|---|---|---|
| Ghidra 11.x + Java 21+ | No (optional) | ❌ Not installed in this checkout | Bridge contract unit-tested with an injected runner; availability detection tested against a fake install layout. Real-headless runs are untested here — the provider reports honestly and fails safely |
| objdump / rizin / others | No | — | Not integrated in v0.1 |

## Environments

| Environment | Status |
|---|---|
| Local CLI (`node dist/cli/main.js …`) | ✅ Tested |
| stdio MCP server + official SDK client | ✅ Tested (`tests/e2e/stdio.test.ts`) |
| Streamable HTTP + bearer token | ✅ Tested (`tests/integration/httpAuth.test.ts`) |
| Container (Docker) | ⚠️ Not shipped in v0.1 — a plain `node:24-alpine` runtime with the built `dist/` and a writable `VESTIGE_DATA_DIR` is sufficient |

## Known limitations (v0.1)

- Evidence store is filesystem-based (JSON/JSONL) — appropriate for single-operator scale, not concurrent multi-writer scale.
- Directory identity hashing caps at 2,000 files / 1 MiB per file (larger files marked `oversized` in the digest).
- No runtime/dynamic observation by design (see THREAT-MODEL §3).
- Ghidra bridge exercised against fixtures only, not a live Ghidra installation.
