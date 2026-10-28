# Vestige accuracy benchmarks

> Numbers below were produced by an actual run of scripts/benchmarks/run-benchmarks.mjs against deterministic fixtures with embedded ground truth. Precision = TP/(TP+FP) on exact identifier match; recall = TP/(TP+FN); FPR = FP/(TP+FP).

- Generated: 2026-10-28T06:32:35.214Z
- Runtime: Node v24.22.1 on linux/x64

## native: ELF64 symbol extraction

- Fixture: synthetic ELF64 executable (4 known symbols, .symtab)
- Iterations: 200
- Mean latency: 0.03 ms (max 1.51 ms)
- Precision: 100.0% (TP 4, FP 0, FN 0)
- Recall: 100.0%
- False-positive rate: 0.0%

## javascript: module graph + Electron IPC + routes

- Fixture: synthetic Electron app (3 sources, manifest, 3 IPC + 3 routes)
- Iterations: 20
- Mean latency: 3.98 ms (max 21.08 ms)
- imports: precision 100.0%, recall 100.0%, FPR 0.0% (TP 4, FP 0, FN 0)
- ipcChannels: precision 100.0%, recall 100.0%, FPR 0.0% (TP 4, FP 0, FN 0)
- routes: precision 100.0%, recall 100.0%, FPR 0.0% (TP 3, FP 0, FN 0)
- Evidence linkage: 22/22 findings carry evidence ids (17 evidence records)
