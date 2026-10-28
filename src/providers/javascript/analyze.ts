import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import * as acorn from "acorn";
import * as walk from "acorn-walk";
import { buildEvidence } from "../../domain/evidence.js";
import { buildFinding } from "../../domain/finding.js";
import { resourceLimit } from "../../errors/errors.js";
import { sha256Hex } from "../../util/hash.js";
import type {
  AnalyzeRequest,
  ProviderResult,
} from "../types.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Finding } from "../../domain/finding.js";

export const JS_PROVIDER = {
  id: "javascript",
  name: "Vestige JavaScript Static Analysis",
  version: "0.1.0",
} as const;

const MAX_FILE_BYTES = 1_000_000;
const MAX_FILES = 2_000;
const MAX_NODES_PER_FILE = 120_000;

const JS_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
]);

const isJsFile = (name: string): boolean =>
  JS_EXTS.has(path.extname(name).toLowerCase());

export interface JsModuleSummary {
  moduleType: "esm" | "cjs" | "mixed" | "unknown";
  imports: Array<{ source: string; specifier: string; kind: string }>;
  exports: string[];
  requires: string[];
  dynamicImports: string[];
}

interface SourceFileResult {
  relPath: string;
  sha256: string;
  summary: JsModuleSummary;
  electronChannels: Array<{ method: string; channel: string; api: string }>;
  routes: Array<{ method: string; path: string; framework: string }>;
  loc: number;
}

/** Parse one JS/TS-ish file with acorn (JSX and TS are best-effort via allowFailed). */
const parseModule = (
  source: string,
): { program: acorn.Program | undefined; error?: string } => {
  const bases = { ecmaVersion: "latest" as const, sourceType: "module" as const };
  try {
    return { program: acorn.parse(source, bases) };
  } catch {
    try {
      return {
        program: acorn.parse(source, {
          ecmaVersion: "latest",
          sourceType: "script",
        }),
      };
    } catch (err) {
      return { program: undefined, error: String(err) };
    }
  }
};

const stringArg = (node: acorn.Node): string | undefined => {
  if (
    node.type === "Literal" &&
    typeof (node as unknown as { value?: unknown }).value === "string"
  ) {
    return (node as unknown as { value: string }).value;
  }
  if (
    node.type === "TemplateLiteral" &&
    (node as unknown as { expressions: unknown[] }).expressions.length === 0
  ) {
    const quasis = (node as unknown as { quasis: Array<{ value: { cooked: string } }> }).quasis;
    return quasis[0]?.value.cooked;
  }
  return undefined;
};

const analyzeSource = async (
  absPath: string,
  relPath: string,
): Promise<SourceFileResult | { error: string }> => {
  const st = await stat(absPath);
  if (st.size > MAX_FILE_BYTES) {
    return { error: `file exceeds ${String(MAX_FILE_BYTES)} bytes` };
  }
  const source = await readFile(absPath, "utf8");
  const { program, error } = parseModule(source);
  if (!program) return { error: error ?? "parse failed" };

  const summary: JsModuleSummary = {
    moduleType: "unknown",
    imports: [],
    exports: [],
    requires: [],
    dynamicImports: [],
  };
  const electronChannels: SourceFileResult["electronChannels"] = [];
  const routes: SourceFileResult["routes"] = [];
  let sawEsm = false;
  let sawCjs = false;
  let nodeCount = 0;

  const onNode = (node: acorn.Node): void => {
    nodeCount += 1;
    if (nodeCount > MAX_NODES_PER_FILE) {
      throw resourceLimit(
        "ast-nodes",
        MAX_NODES_PER_FILE,
        "Split large generated files or exclude them from the target directory.",
      );
    }
    switch (node.type) {
      case "ImportDeclaration": {
        const n = node as unknown as {
          source: acorn.Node;
          specifiers: Array<{ type: string; local: { name: string }; imported?: { name: string } }>;
          importKind?: string;
        };
        const src = stringArg(n.source);
        if (src) {
          sawEsm = true;
          for (const spec of n.specifiers) {
            summary.imports.push({
              source: src,
              specifier:
                spec.type === "ImportDefaultSpecifier"
                  ? "default"
                  : (spec.imported?.name ?? spec.local.name),
              kind: spec.type,
            });
          }
          if (n.specifiers.length === 0) {
            summary.imports.push({ source: src, specifier: "(side-effect)", kind: "ImportDeclaration" });
          }
        }
        break;
      }
      case "ExportNamedDeclaration":
      case "ExportDefaultDeclaration": {
        sawEsm = true;
        const n = node as unknown as {
          declaration?: {
            id?: { name?: string };
            type?: string;
            declarations?: Array<{ id: { name?: string } }>;
          };
          specifiers?: Array<{ exported: { name?: string } }>;
        };
        const decl = n.declaration;
        if (decl?.id?.name) summary.exports.push(decl.id.name);
        // export const a = 1, b = 2 → VariableDeclaration with declarations
        for (const d of decl?.declarations ?? []) {
          if (d.id?.name) summary.exports.push(d.id.name);
        }
        for (const spec of n.specifiers ?? []) {
          if (spec.exported.name) summary.exports.push(spec.exported.name);
        }
        if (node.type === "ExportDefaultDeclaration") summary.exports.push("default");
        break;
      }
      case "CallExpression": {
        const n = node as unknown as {
          callee: acorn.Node;
          arguments: acorn.Node[];
        };
        // require("x")
        if (n.callee.type === "Identifier" && (n.callee as unknown as { name: string }).name === "require") {
          const arg = n.arguments[0] ? stringArg(n.arguments[0]) : undefined;
          if (arg) {
            sawCjs = true;
            summary.requires.push(arg);
          }
        }
        // dynamic import("x")
        if (n.callee.type === "Import") {
          const arg = n.arguments[0] ? stringArg(n.arguments[0]) : undefined;
          if (arg) summary.dynamicImports.push(arg);
        }
        // Electron IPC: ipcMain.handle/on(channel), ipcRenderer.invoke/send/sendSync/on(channel)
        if (n.callee.type === "MemberExpression") {
          const callee = n.callee as unknown as {
            object: acorn.Node;
            property: acorn.Node;
          };
          const objName =
            callee.object.type === "Identifier"
              ? (callee.object as unknown as { name: string }).name
              : undefined;
          const propName =
            callee.property.type === "Identifier"
              ? (callee.property as unknown as { name: string }).name
              : stringArg(callee.property);
          if (objName === "ipcMain" && propName && ["handle", "on", "once"].includes(propName)) {
            const channel = n.arguments[0] ? stringArg(n.arguments[0]) : undefined;
            if (channel) electronChannels.push({ method: propName, channel, api: "ipcMain" });
          }
          if (objName === "ipcRenderer" && propName && ["invoke", "send", "sendSync", "on", "once"].includes(propName)) {
            const channel = n.arguments[0] ? stringArg(n.arguments[0]) : undefined;
            if (channel) electronChannels.push({ method: propName, channel, api: "ipcRenderer" });
          }
          // Express/Connect/fastify-style routes: app.get("/path", ...)
          if (
            objName &&
            propName &&
            ["get", "post", "put", "delete", "patch", "all", "use"].includes(propName)
          ) {
            const route = n.arguments[0] ? stringArg(n.arguments[0]) : undefined;
            if (route && route.startsWith("/")) {
              routes.push({ method: propName.toUpperCase(), path: route, framework: "express-style" });
            }
          }
        }
        break;
      }
      default:
        break;
    }
  };

  walk.ancestor(program, {
    ImportDeclaration: onNode as never,
    ExportNamedDeclaration: onNode as never,
    ExportDefaultDeclaration: onNode as never,
    CallExpression: onNode as never,
  });

  summary.moduleType = sawEsm && sawCjs ? "mixed" : sawEsm ? "esm" : sawCjs ? "cjs" : "unknown";
  return {
    relPath,
    sha256: sha256Hex(source),
    summary,
    electronChannels,
    routes,
    loc: source.split("\n").length,
  };
};

/** Scan a directory (or single file) for JS sources, bounded by caps. */
export const collectJsSources = async (
  root: string,
  isDirectory: boolean,
  maxFiles = MAX_FILES,
  signal?: AbortSignal,
): Promise<Array<{ absPath: string; relPath: string }>> => {
  const out: Array<{ absPath: string; relPath: string }> = [];
  const skipDirs = new Set([
    "node_modules", ".git", "dist", "build", "out", ".next", "coverage", "vendor",
  ]);
  if (!isDirectory) {
    if (isJsFile(root)) out.push({ absPath: root, relPath: path.basename(root) });
    return out;
  }
  const queue: Array<{ abs: string; rel: string }> = [{ abs: root, rel: "" }];
  while (queue.length > 0 && out.length < maxFiles) {
    if (signal?.aborted) break;
    const current = queue.shift();
    if (!current) break;
    let entries;
    try {
      entries = await readdir(current.abs, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) break;
      const abs = path.join(current.abs, entry.name);
      const rel = current.rel ? `${current.rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) queue.push({ abs, rel });
      } else if (entry.isFile() && isJsFile(entry.name)) {
        out.push({ absPath: abs, relPath: rel });
      }
    }
  }
  return out;
};

export interface JsAnalysisOptions {
  maxFiles: number;
}

/** Read and classify package.json manifest facts (Electron markers, main entry). */
const analyzeManifest = async (
  rootDir: string,
): Promise<Record<string, unknown> | undefined> => {
  const manifestPath = path.join(rootDir, "package.json");
  let raw: string;
  try {
    raw = await readFile(manifestPath, "utf8");
  } catch {
    return undefined;
  }
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return parsed;
  } catch {
    return { parseError: true };
  }
};

/** Core JS/Electron static analysis producing findings + evidence. */
export const analyzeJavaScript = async (
  request: AnalyzeRequest,
  options: JsAnalysisOptions = { maxFiles: MAX_FILES },
): Promise<ProviderResult> => {
  const st = await stat(request.artifactPath);
  const isDirectory = st.isDirectory();
  const sources = await collectJsSources(
    request.artifactPath,
    isDirectory,
    options.maxFiles,
    request.signal,
  );

  const provider = { ...JS_PROVIDER };
  const evidence: Evidence[] = [];
  const findings: Finding[] = [];
  const now = new Date().toISOString();
  const artifactId = request.artifactId;
  const sha = request.artifactSha256;
  const limitations = [
    "Static analysis only: dynamic requires, computed imports, and string-built routes are not resolved.",
    "JSX/TypeScript are parsed best-effort; type-only constructs may fail parsing and are recorded as parse gaps.",
  ];

  const method = `acorn ${acorn.version ?? "8.x"} AST walk (static)`;
  let parsedCount = 0;
  let failedCount = 0;

  const total = sources.length;
  let step = 0;
  const pushEvidence = (
    kind: Evidence["kind"],
    observation: Evidence["observation"],
    locations: Evidence["locations"] = [],
  ): Evidence => {
    const e = buildEvidence({
      artifactId,
      artifactSha256: sha,
      provider,
      kind,
      confidence: "static-inference",
      method,
      collectedAt: now,
      locations,
      observation,
      limitations,
    });
    evidence.push(e);
    return e;
  };

  const pushFinding = (
    kind: Finding["kind"],
    name: string,
    summary: string,
    evidenceIds: string[],
    attributes: Finding["attributes"] = {},
    artifactPath?: string,
  ): void => {
    findings.push(
      buildFinding({
        artifactId,
        artifactSha256: sha,
        kind,
        name,
        summary,
        provider,
        confidence: "static-inference",
        method,
        collectedAt: now,
        location: artifactPath ? { artifactPath } : {},
        evidenceIds,
        attributes,
        limitations,
      }),
    );
  };

  // Manifest (package.json) facts: Electron markers, dependencies, entry points.
  if (isDirectory) {
    const manifest = await analyzeManifest(request.artifactPath);
    if (manifest && !manifest.parseError) {
      const deps = {
        ...(manifest.dependencies as Record<string, string> | undefined),
        ...(manifest.devDependencies as Record<string, string> | undefined),
      };
      const electronVersion = deps?.electron;
      const mainEntry =
        typeof manifest.main === "string" ? manifest.main : undefined;
      const manifestEvidence = pushEvidence(
        "manifest-parse",
        {
          file: "package.json",
          electron: electronVersion ?? null,
          main: mainEntry ?? null,
          scripts: Object.keys(
            (manifest.scripts as Record<string, string> | undefined) ?? {},
          ).slice(0, 30),
        },
        [{ type: "artifact-path", path: "package.json" }],
      );
      pushFinding(
        "dependency",
        electronVersion ? `electron@${electronVersion}` : "package-manifest",
        electronVersion
          ? `Electron application detected (electron ${electronVersion})`
          : "package.json manifest present",
        [manifestEvidence.evidenceId],
        { electron: electronVersion ?? null, main: mainEntry ?? null },
        "package.json",
      );
      if (mainEntry) {
        pushFinding(
          "entrypoint",
          mainEntry,
          `Package main entry: ${mainEntry}`,
          [manifestEvidence.evidenceId],
          { file: mainEntry },
          "package.json",
        );
      }
      for (const [dep, version] of Object.entries(deps ?? {}).slice(0, 100)) {
        const ev = pushEvidence(
          "manifest-parse",
          { dependency: dep, version },
          [{ type: "artifact-path", path: "package.json" }],
        );
        pushFinding(
          "dependency",
          `${dep}@${version}`,
          `Declared dependency ${dep}@${version}`,
          [ev.evidenceId],
          { version },
          "package.json",
        );
      }
    }
  }

  for (const source of sources) {
    if (request.signal.aborted) break;
    step += 1;
    request.onProgress({
      phase: "parse",
      stepsDone: step,
      stepsTotal: total,
      message: source.relPath,
    });
    let result: SourceFileResult | { error: string };
    try {
      result = await analyzeSource(source.absPath, source.relPath);
    } catch (err) {
      if (request.signal.aborted) break;
      result = { error: String(err) };
    }
    if ("error" in result) {
      failedCount += 1;
      pushEvidence(
        "heuristic",
        { parseGap: result.error, file: source.relPath },
        [{ type: "artifact-path", path: source.relPath }],
      );
      continue;
    }
    parsedCount += 1;
    const fileEvidence = pushEvidence(
      "ast-parse",
      {
        file: result.relPath,
        moduleType: result.summary.moduleType,
        imports: result.summary.imports.slice(0, 200),
        requires: result.summary.requires.slice(0, 200),
        dynamicImports: result.summary.dynamicImports.slice(0, 100),
        exports: result.summary.exports.slice(0, 200),
        linesOfCode: result.loc,
      },
      [{ type: "artifact-path", path: result.relPath }],
    );

    for (const exp of result.summary.exports.slice(0, 100)) {
      pushFinding(
        "export",
        exp,
        `${result.relPath} exports '${exp}' (${result.summary.moduleType})`,
        [fileEvidence.evidenceId],
        { file: result.relPath },
        result.relPath,
      );
    }
    const uniqueImports = [
      ...new Set([
        ...result.summary.imports.map((i) => i.source),
        ...result.summary.requires,
        ...result.summary.dynamicImports,
      ]),
    ].slice(0, 200);
    for (const dep of uniqueImports) {
      pushFinding(
        "import",
        dep,
        `${result.relPath} imports '${dep}'`,
        [fileEvidence.evidenceId],
        { file: result.relPath },
        result.relPath,
      );
    }
    for (const channel of result.electronChannels.slice(0, 100)) {
      const ev = pushEvidence(
        "cross-reference",
        { electronIpc: channel, file: result.relPath },
        [{ type: "artifact-path", path: result.relPath }],
      );
      pushFinding(
        "ipc-channel",
        `${channel.api}.${channel.method}("${channel.channel}")`,
        `Electron IPC channel '${channel.channel}' via ipc${channel.api === "ipcMain" ? "Main" : "Renderer"}.${channel.method}() in ${result.relPath}`,
        [ev.evidenceId],
        { file: result.relPath, api: channel.api, method: channel.method },
        result.relPath,
      );
    }
    for (const route of result.routes.slice(0, 100)) {
      const ev = pushEvidence(
        "cross-reference",
        { route, file: result.relPath },
        [{ type: "artifact-path", path: result.relPath }],
      );
      pushFinding(
        "route",
        `${route.method} ${route.path}`,
        `${route.framework} route ${route.method} ${route.path} in ${result.relPath}`,
        [ev.evidenceId],
        { file: result.relPath, framework: route.framework },
        result.relPath,
      );
    }
  }

  const summaryEvidence = pushEvidence("heuristic", {
    scope: isDirectory ? "directory" : "file",
    filesParsed: parsedCount,
    filesFailed: failedCount,
    filesConsidered: sources.length,
  });

  pushFinding(
    "format-feature",
    "javascript-scan-summary",
    `Scanned ${String(sources.length)} JS sources: ${String(parsedCount)} parsed, ${String(failedCount)} with parse gaps`,
    [summaryEvidence.evidenceId],
    { parsedCount, failedCount, considered: sources.length },
  );

  return {
    findings,
    evidence,
    diagnostics: {
      filesConsidered: sources.length,
      filesParsed: parsedCount,
      filesFailed: failedCount,
    },
  };
};
