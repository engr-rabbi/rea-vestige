# Provider guide

Providers are the pluggable analysis engines. Application services depend only on the
`AnalysisProvider` interface (`src/providers/types.ts`):

```ts
interface AnalysisProvider {
  descriptor: ProviderDescriptor;              // id, name, version, formats, summary
  capabilities(): CapabilityDescriptor[];      // operations + documented limitations
  checkAvailability(): Promise<Availability>;  // cheap probe; guidance when unavailable
  supports(artifact): boolean;                 // format-based routing
  analyze(request: AnalyzeRequest): Promise<ProviderResult>;  // findings + evidence + diagnostics
}
```

Rules every provider must honor:

1. **Read-only.** Never write to the artifact. All derived files go to the workspace.
2. **Declare limitations up front** — they are copied into every evidence record the provider emits.
3. **Confidence discipline** — only claim `observed-fact` for facts read directly from bytes.
4. **Bound everything** — caps on files, nodes, symbols, strings, and time.
5. **Honor the AbortSignal** — check between phases; persist-safe cancellation is handled by the service.
6. **Never execute the target.**

## javascript provider (`id: javascript`)

In-process static analysis using the acorn parser (pinned 8.19.0).

- **module-graph**: ESM imports, CJS requires, dynamic imports, exports per file.
- **electron-ipc**: `ipcMain.handle/on/once(channel, …)` and `ipcRenderer.invoke/send/sendSync/on/once(channel, …)` with **literal** channel names; only direct `ipcMain`/`ipcRenderer` identifier callees are admitted (wrapper indirection is reported as unknown, not guessed).
- **route-inventory**: express-style `app.get/post/put/delete/patch/all/use("/literal", …)` routes.
- **manifest facts**: `package.json` — electron dependency, main entry, dependency list.

Known limitations (also advertised at runtime): computed/aliased specifiers unresolved;
JSX/TS parsed best-effort (failures become explicit parse gaps, never silent omissions);
`node_modules`, `dist`, `build`, `out`, `.next`, `coverage`, `vendor` excluded from scans.

## native provider (`id: native`)

Pure-TypeScript structural parsers — deterministic, no external dependencies, extensively
tested against synthesized binaries with known ground truth.

| Format | Extracted |
|---|---|
| ELF 32/64 LE/BE | header (class/endian/machine/type/entry), sections, `.symtab`/`.dynsym` symbols (name/value/size/type/bind), PT_INTERP interpreter |
| PE / PE32+ | COFF + optional header, sections, export directory (names+ordinals), import directory (DLLs + function names via hint/name thunks) |
| Mach-O (incl. FAT first slice) | header, LC_SEGMENT_64 sections, LC_SYMTAB symbols, LC_LOAD_DYLIB links |

- **extract-strings**: printable ASCII ≥6 chars with file offsets (capped at 1,000).
- Caps: 64 MiB read window; 20,000 symbols/table; out-of-bounds structures become explicit `parseGaps` in evidence rather than false facts.

## ghidra provider (`id: ghidra`) — optional external tool

Headless decompilation via Ghidra's `analyzeHeadless`. Documented integration boundary:

1. Vestige writes `vestige_dump.py` (a Ghidra headless script) into an isolated scratch dir.
2. Vestige launches `analyzeHeadless <projectDir> vestige -import <artifact> -scriptPath <ws> -postScript vestige_dump.py <out.json> -deleteProject` with argv arrays, a 10-minute deadline, and abort support. The disposable project lives in the workspace; `-deleteProject` cleans it up.
3. The script exports functions (entry, name, params, callers/callees, decompiled C ≤8 KiB) as JSON with schema `vestige.ghidra.dump/1`; Vestige validates it with Zod before converting to evidence/findings.

**Availability & setup**

```bash
# 1. Install Ghidra 11.x from https://ghidra-sre.org/ (requires Java 21+)
# 2. Point Vestige at it:
export GHIDRA_INSTALL_DIR=/opt/ghidra   # dir containing support/analyzeHeadless
# 3. Verify:
node dist/cli/main.js doctor
```

Without Ghidra, the provider reports `unavailable` with installation guidance and analysis
requests fail with `provider_unavailable` + that guidance — every other provider keeps working.
The bridge contract (argv construction, dump parsing, failure/timeouts) is unit-tested without
a Ghidra installation (`tests/unit/providers/ghidra.test.ts`).

Troubleshooting: ensure `support/analyzeHeadless` is executable (`chmod +x`), Java ≥21 is on
PATH, and the target format is one Ghidra supports. Large binaries may take minutes — watch
progress via `vestige_job_status`.

## Adding a provider

1. Implement `AnalysisProvider` in `src/providers/<your>/`.
2. Register it in `src/server/context.ts` (the composition root — the only registration site).
3. Add fixture builders with embedded ground truth + unit tests asserting precision/recall on
   those fixtures; add a golden regression test.
4. Document capabilities **and limitations**; never advertise what isn't demonstrated.
