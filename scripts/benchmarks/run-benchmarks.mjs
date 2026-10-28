/**
 * Vestige accuracy benchmark harness (Stage F).
 *
 * Measures precision / recall / false-positive rate / wall-clock latency of
 * provider outputs against DETERMINISTIC FIXTURE GROUND TRUTH. Results are
 * only recorded when this script actually runs (`npm run bench:record`);
 * committed numbers always refer to a specific build and fixture set.
 *
 * Usage: node scripts/benchmarks/run-benchmarks.mjs [--write]
 */
import { writeFileSync, mkdtempSync, rmSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

// Fixture builders are dependency-free TypeScript (node builtins only), so
// Node's type-stripping import works for them; parser/analysis code is
// imported from the compiled dist to benchmark the shipped implementation.
const { buildElf64: buildElf, ELF64_GROUND_TRUTH: ELF_GT } = await import(
  path.join(root, "tests/fixtures/builders.ts")
);

const { parseElf } = await import(path.join(root, "dist/providers/native/elf.js"));
const { analyzeJavaScript } = await import(path.join(root, "dist/providers/javascript/analyze.js"));
const { sha256Hex } = await import(path.join(root, "dist/util/hash.js"));

const jsFixture = await import(path.join(root, "tests/fixtures/jsProject.ts"));
const buildJsProject = jsFixture.buildJsProject;
const JS_GT = jsFixture.JS_GROUND_TRUTH;

const metrics = (expected, actual) => {
  const expectedSet = new Set(expected);
  const actualSet = new Set(actual);
  const tp = [...actualSet].filter((x) => expectedSet.has(x)).length;
  const fp = actualSet.size - tp;
  const fn = expectedSet.size - tp;
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const fpr = tp + fp === 0 ? 0 : fp / (tp + fp);
  return { tp, fp, fn, precision, recall, fpr };
};

const fmtPct = (x) => `${(x * 100).toFixed(1)}%`;

// ---------- Benchmark 1: ELF symbol extraction ----------
const benchElf = () => {
  const image = buildElf();
  const iterations = 200;
  const times = [];
  let lastInfo;
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    lastInfo = parseElf(image);
    times.push(performance.now() - t0);
  }
  const expected = ELF_GT.symbols.map((s) => s.name);
  const actual = lastInfo.symbols.map((s) => s.name);
  return {
    name: "native: ELF64 symbol extraction",
    fixture: "synthetic ELF64 executable (4 known symbols, .symtab)",
    iterations,
    metrics: metrics(expected, actual),
    latency: {
      meanMs: times.reduce((a, b) => a + b, 0) / times.length,
      maxMs: Math.max(...times),
    },
  };
};

// ---------- Benchmark 2: JavaScript analysis ----------
const benchJs = async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "vestige-bench-js-"));
  try {
    const projectDir = buildJsProject(path.join(dir, "app"));
    let result;
    const times = [];
    const iterations = 20;
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      result = await analyzeJavaScript({
        artifactId: "va_bench",
        artifactPath: projectDir,
        artifactSha256: sha256Hex("bench"),
        format: "directory",
        capabilities: [],
        signal: new AbortController().signal,
        onProgress: () => {},
      });
      times.push(performance.now() - t0);
    }

    const imports = result.findings.filter((f) => f.kind === "import").map((f) => f.name);
    const expectedImports = [
      ...JS_GT.mainJs.imports,
      ...JS_GT.serverJs.imports,
    ];
    const ipc = result.findings.filter((f) => f.kind === "ipc-channel");
    const expectedIpcChannels = [
      ...JS_GT.mainJs.ipcMainChannels,
      ...JS_GT.rendererJs.ipcRendererChannels,
    ];
    const actualChannels = ipc.map((f) => {
      const m = /"([^"]+)"/.exec(f.name);
      return m?.[1] ?? f.name;
    });
    const routes = result.findings.filter((f) => f.kind === "route").map((f) => f.name);
    const expectedRoutes = JS_GT.serverJs.routes.map((r) => `${r.method} ${r.path}`);

    return {
      name: "javascript: module graph + Electron IPC + routes",
      fixture: "synthetic Electron app (3 sources, manifest, 3 IPC + 3 routes)",
      iterations,
      metrics: {
        imports: metrics(expectedImports, imports),
        ipcChannels: metrics(expectedIpcChannels, actualChannels),
        routes: metrics(expectedRoutes, routes),
      },
      latency: {
        meanMs: times.reduce((a, b) => a + b, 0) / times.length,
        maxMs: Math.max(...times),
      },
      evidenceLinked: {
        findingsTotal: result.findings.length,
        findingsWithEvidence: result.findings.filter((f) => f.evidenceIds.length > 0).length,
        evidenceRecords: result.evidence.length,
      },
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

// ---------- Run ----------
const report = {
  generatedAt: new Date().toISOString(),
  node: process.version,
  platform: `${process.platform}/${process.arch}`,
  note: "Numbers below were produced by an actual run of scripts/benchmarks/run-benchmarks.mjs against deterministic fixtures with embedded ground truth. Precision = TP/(TP+FP) on exact identifier match; recall = TP/(TP+FN); FPR = FP/(TP+FP).",
  benchmarks: [],
};

process.stdout.write("Running ELF benchmark...\n");
report.benchmarks.push(benchElf());
process.stdout.write("Running JavaScript benchmark...\n");
report.benchmarks.push(await benchJs());

const markdown = () => {
  const lines = [
    "# Vestige accuracy benchmarks",
    "",
    `> ${report.note}`,
    "",
    `- Generated: ${report.generatedAt}`,
    `- Runtime: Node ${report.node} on ${report.platform}`,
    "",
  ];
  for (const b of report.benchmarks) {
    lines.push(`## ${b.name}`);
    lines.push("");
    lines.push(`- Fixture: ${b.fixture}`);
    lines.push(`- Iterations: ${String(b.iterations)}`);
    lines.push(`- Mean latency: ${b.latency.meanMs.toFixed(2)} ms (max ${b.latency.maxMs.toFixed(2)} ms)`);
    const m = b.metrics;
    if (m.precision !== undefined) {
      lines.push(`- Precision: ${fmtPct(m.precision)} (TP ${String(m.tp)}, FP ${String(m.fp)}, FN ${String(m.fn)})`);
      lines.push(`- Recall: ${fmtPct(m.recall)}`);
      lines.push(`- False-positive rate: ${fmtPct(m.fpr)}`);
    } else {
      for (const [k, v] of Object.entries(m)) {
        lines.push(`- ${k}: precision ${fmtPct(v.precision)}, recall ${fmtPct(v.recall)}, FPR ${fmtPct(v.fpr)} (TP ${String(v.tp)}, FP ${String(v.fp)}, FN ${String(v.fn)})`);
      }
    }
    if (b.evidenceLinked) {
      lines.push(`- Evidence linkage: ${String(b.evidenceLinked.findingsWithEvidence)}/${String(b.evidenceLinked.findingsTotal)} findings carry evidence ids (${String(b.evidenceLinked.evidenceRecords)} evidence records)`);
    }
    lines.push("");
  }
  return lines.join("\n");
};

if (process.argv.includes("--write")) {
  mkdirSync(path.join(root, "docs"), { recursive: true });
  writeFileSync(path.join(root, "docs", "BENCHMARKS.md"), markdown());
  writeFileSync(path.join(root, "docs", "benchmarks-latest.json"), JSON.stringify(report, null, 2));
  process.stdout.write(`Wrote docs/BENCHMARKS.md and docs/benchmarks-latest.json\n`);
} else {
  process.stdout.write(markdown());
}
