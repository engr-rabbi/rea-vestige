import { open } from "node:fs/promises";
import { buildEvidence } from "../../domain/evidence.js";
import { buildFinding } from "../../domain/finding.js";
import type {
  AnalyzeRequest,
  ProviderResult,
} from "../types.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Finding } from "../../domain/finding.js";
import { parseElf, type ElfInfo } from "./elf.js";
import { parsePe, type PeInfo } from "./pe.js";
import { parseMacho, type MachoInfo, CPU_TYPES } from "./macho.js";

export const NATIVE_PROVIDER = {
  id: "native",
  name: "Vestige Native Binary Analysis",
  version: "0.1.0",
} as const;

const MAX_READ_BYTES = 64 * 1024 * 1024;

/** Read up to maxReadBytes of the file (native headers live at the front). */
const readArtifact = async (path: string, signal?: AbortSignal): Promise<Buffer> => {
  const handle = await open(path, "r");
  try {
    const size = (await handle.stat()).size;
    const len = Math.min(size, MAX_READ_BYTES);
    const buffer = Buffer.alloc(len);
    await handle.read(buffer, 0, len, 0);
    signal?.throwIfAborted();
    return buffer;
  } finally {
    await handle.close();
  }
};

/** Extract printable ASCII strings (>= minLen) with their file offsets. */
export const extractStrings = (
  buffer: Buffer,
  minLen = 6,
  maxStrings = 5_000,
): Array<{ value: string; offset: number }> => {
  const out: Array<{ value: string; offset: number }> = [];
  let start = -1;
  const push = (end: number): void => {
    const len = end - start;
    if (len >= minLen && out.length < maxStrings) {
      out.push({
        value: buffer.subarray(start, end).toString("latin1"),
        offset: start,
      });
    }
  };
  for (let i = 0; i < buffer.length; i++) {
    const b = buffer[i];
    const printable = b >= 0x20 && b <= 0x7e;
    if (printable) {
      if (start === -1) start = i;
    } else {
      if (start !== -1) push(i);
      start = -1;
    }
    if (out.length >= maxStrings) break;
  }
  if (start !== -1) push(buffer.length);
  return out;
};

const kindConfidence = "observed-fact" as const;

/** Analyze a native binary (ELF / PE / Mach-O) via pure byte parsing. */
export const analyzeNative = async (
  request: AnalyzeRequest,
): Promise<ProviderResult> => {
  const buffer = await readArtifact(request.artifactPath, request.signal);
  const provider = { ...NATIVE_PROVIDER };
  const evidence: Evidence[] = [];
  const findings: Finding[] = [];
  const now = new Date().toISOString();
  const limitations = [
    "Header/section/symbol parsing only; no disassembly or decompilation.",
    "Files larger than the read cap are analyzed by their leading bytes.",
  ];
  const method = "pure-TypeScript byte-structure parse (vestige native provider)";

  request.onProgress({ phase: "identify", stepsDone: 0, stepsTotal: 3 });

  const pushEvidence = (
    kind: Evidence["kind"],
    observation: Evidence["observation"],
    locations: Evidence["locations"] = [],
  ): Evidence => {
    const e = buildEvidence({
      artifactId: request.artifactId,
      artifactSha256: request.artifactSha256,
      provider,
      kind,
      confidence: kindConfidence,
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
    location: Finding["location"] = {},
  ): void => {
    findings.push(
      buildFinding({
        artifactId: request.artifactId,
        artifactSha256: request.artifactSha256,
        kind,
        name,
        summary,
        provider,
        confidence: kindConfidence,
        method,
        collectedAt: now,
        location,
        evidenceIds,
        attributes,
        limitations,
      }),
    );
  };

  const pushSymbols = (
    symbols: Array<{ name: string; value: string; type?: string; bind?: string; sectionIndex?: number; table?: string }>,
    kind: Finding["kind"] = "symbol",
  ): void => {
    const ev = pushEvidence(
      "symbol-parse",
      { symbols: symbols.slice(0, 2000), totalSymbols: symbols.length },
    );
    for (const sym of symbols.slice(0, 1000)) {
      pushFinding(
        kind,
        sym.name,
        `${kind === "function" ? "Function" : "Symbol"} '${sym.name}' at 0x${sym.value}${sym.type ? ` (${sym.type}${sym.bind ? `, ${sym.bind}` : ""})` : ""}`,
        [ev.evidenceId],
        { ...sym },
        sym.value !== "0" ? { virtualAddress: sym.value } : {},
      );
    }
  };

  request.onProgress({ phase: "parse-headers", stepsDone: 1, stepsTotal: 3 });

  if (buffer.length >= 4 && buffer[0] === 0x7f && buffer.subarray(1, 4).toString("latin1") === "ELF") {
    const info: ElfInfo = parseElf(buffer);
    const headerEvidence = pushEvidence(
      "header-parse",
      {
        format: "elf",
        is64: info.is64,
        littleEndian: info.littleEndian,
        machine: info.machineName,
        type: info.typeName,
        entry: `0x${info.entry}`,
        interpreter: info.interpreter ?? null,
        sectionCount: info.sections.length,
        parseGaps: info.parseGaps,
      },
      [{ type: "file-offset", offset: 0, length: 64 }],
    );
    pushFinding(
      "format-feature",
      `elf-${info.machineName}`,
      `ELF ${info.is64 ? "64-bit" : "32-bit"} ${info.typeName} for ${info.machineName}, entry 0x${info.entry}`,
      [headerEvidence.evidenceId],
      { machine: info.machineName, type: info.typeName, is64: info.is64 },
    );
    if (info.interpreter) {
      pushFinding(
        "interpreter",
        info.interpreter,
        `ELF program interpreter: ${info.interpreter}`,
        [headerEvidence.evidenceId],
        { interpreter: info.interpreter },
      );
    }
    const secEv = pushEvidence(
      "section-parse",
      { sections: info.sections.slice(0, 200), total: info.sections.length },
    );
    for (const sec of info.sections.slice(0, 100)) {
      pushFinding(
        "section",
        sec.name || `(unnamed@${String(sec.offset)})`,
        `Section '${sec.name}' type=${String(sec.type)} size=${String(sec.size)} addr=0x${sec.addr}`,
        [secEv.evidenceId],
        { ...sec },
        sec.addr !== "0" ? { virtualAddress: sec.addr } : { section: sec.name },
      );
    }
    request.onProgress({ phase: "parse-symbols", stepsDone: 2, stepsTotal: 3 });
    const functions = info.symbols.filter((s) => s.type === "func");
    pushSymbols(
      functions.map((f) => ({ name: f.name, value: f.value, type: f.type, bind: f.bind, sectionIndex: f.sectionIndex, table: f.table })),
      "function",
    );
    const others = info.symbols.filter((s) => s.type !== "func");
    pushSymbols(
      others.map((f) => ({ name: f.name, value: f.value, type: f.type, bind: f.bind, sectionIndex: f.sectionIndex, table: f.table })),
      "symbol",
    );
  } else if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
    const info: PeInfo = parsePe(buffer);
    const headerEvidence = pushEvidence(
      "header-parse",
      {
        format: "pe",
        machine: info.machineName,
        pe32plus: info.isPe32Plus,
        entryRva: `0x${info.entryRva}`,
        imageBase: `0x${info.imageBase}`,
        subsystem: info.subsystemName,
        sectionCount: info.sections.length,
        parseGaps: info.parseGaps,
      },
      [{ type: "file-offset", offset: 0, length: 64 }],
    );
    pushFinding(
      "format-feature",
      `pe-${info.machineName}`,
      `PE ${info.isPe32Plus ? "PE32+" : "PE32"} ${info.machineName} ${info.subsystemName}, entry RVA 0x${info.entryRva}`,
      [headerEvidence.evidenceId],
      { machine: info.machineName, subsystem: info.subsystemName, pe32plus: info.isPe32Plus },
    );
    const secEv = pushEvidence(
      "section-parse",
      { sections: info.sections.slice(0, 200) },
    );
    for (const sec of info.sections.slice(0, 100)) {
      pushFinding(
        "section",
        sec.name,
        `PE section '${sec.name}' vaddr=0x${sec.virtualAddress.toString(16)} rawsize=${String(sec.sizeOfRawData)}`,
        [secEv.evidenceId],
        { ...sec },
        { section: sec.name },
      );
    }
    request.onProgress({ phase: "parse-symbols", stepsDone: 2, stepsTotal: 3 });
    if (info.exports.length > 0) {
      const expEv = pushEvidence("symbol-parse", { exports: info.exports.slice(0, 2000), total: info.exports.length });
      for (const exp of info.exports.slice(0, 1000)) {
        pushFinding(
          "export",
          exp.name,
          `PE export '${exp.name}' (ordinal ${String(exp.ordinal)})`,
          [expEv.evidenceId],
          { ordinal: exp.ordinal },
        );
      }
    }
    for (const imp of info.imports.slice(0, 100)) {
      const impEv = pushEvidence("cross-reference", { dll: imp.dll, imports: imp.imports.slice(0, 500) });
      pushFinding(
        "import",
        imp.dll,
        `PE import from '${imp.dll}' (${String(imp.imports.length)} functions)`,
        [impEv.evidenceId],
        { dll: imp.dll, functions: imp.imports.slice(0, 100) },
      );
    }
  } else {
    const info: MachoInfo = parseMacho(buffer);
    const headerEvidence = pushEvidence(
      "header-parse",
      {
        format: "macho",
        is64: info.is64,
        littleEndian: info.littleEndian,
        cputype: CPU_TYPES[info.cputype] ?? String(info.cputype),
        filetype: info.filetype,
        loadCommands: info.ncmds,
        parseGaps: info.parseGaps,
      },
      [{ type: "file-offset", offset: 0, length: 32 }],
    );
    pushFinding(
      "format-feature",
      `macho-${CPU_TYPES[info.cputype] ?? String(info.cputype)}`,
      `Mach-O ${info.is64 ? "64-bit" : "32-bit"} ${CPU_TYPES[info.cputype] ?? String(info.cputype)}, ${String(info.ncmds)} load commands`,
      [headerEvidence.evidenceId],
      { cputype: info.cputype, is64: info.is64 },
    );
    const secEv = pushEvidence(
      "section-parse",
      { sections: info.sections.slice(0, 200) },
    );
    for (const sec of info.sections.slice(0, 100)) {
      pushFinding(
        "section",
        `${sec.segment},${sec.name}`,
        `Mach-O section '${sec.name}' in ${sec.segment} addr=0x${sec.addr} size=${String(sec.size)}`,
        [secEv.evidenceId],
        { ...sec },
        { section: sec.name },
      );
    }
    request.onProgress({ phase: "parse-symbols", stepsDone: 2, stepsTotal: 3 });
    pushSymbols(
      info.symbols.map((s) => ({ name: s.name, value: s.value, type: String(s.type) })),
      "symbol",
    );
    for (const lib of info.dylibs.slice(0, 100)) {
      const libEv = pushEvidence("cross-reference", { dylib: lib.name });
      pushFinding(
        "dynamic-link",
        lib.name,
        `Links against ${lib.name}`,
        [libEv.evidenceId],
        { dylib: lib.name },
      );
    }
  }

  // String extraction (bounded) with offsets as evidence.
  request.onProgress({ phase: "strings", stepsDone: 3, stepsTotal: 3 });
  const strings = extractStrings(buffer, 6, 1000);
  if (strings.length > 0) {
    const strEv = pushEvidence(
      "string-extraction",
      { strings: strings.slice(0, 500), totalExtracted: strings.length },
      strings.slice(0, 50).map((s) => ({ type: "file-offset" as const, offset: s.offset })),
    );
    pushFinding(
      "string",
      `strings(${String(strings.length)})`,
      `Extracted ${String(strings.length)} printable strings (first: ${strings[0]?.value.slice(0, 60) ?? ""})`,
      [strEv.evidenceId],
      { count: strings.length },
    );
  }

  return {
    findings,
    evidence,
    diagnostics: {
      bytesRead: buffer.length,
      findings: findings.length,
      evidenceRecords: evidence.length,
    },
  };
};
