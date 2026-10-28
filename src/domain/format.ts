import { open } from "node:fs/promises";
import path from "node:path";
import type { ArtifactFormat } from "./artifact.js";

export interface FormatProbe {
  format: ArtifactFormat;
  architecture?: string;
  detail?: string;
}

const readU16 = (b: Buffer, o: number, le: boolean): number =>
  le ? b.readUInt16LE(o) : b.readUInt16BE(o);
const readU32 = (b: Buffer, o: number, le: boolean): number =>
  le ? b.readUInt32LE(o) : b.readUInt32BE(o);

const MACHO_MAGICS = new Set([0xfeedfacf, 0xcffaedfe, 0xfeedface, 0xcefaedfe]);
const ELF_MACHINES: Record<number, string> = {
  0x03: "x86",
  0x3e: "x86-64",
  0xb7: "aarch64",
  0x28: "arm",
  0x08: "mips",
  0x14: "powerpc",
  0x15: "powerpc64",
  0xf3: "riscv",
};

/** Identify a format from its leading bytes plus optional filename hint. */
export const probeFormat = (head: Buffer, fileName?: string): FormatProbe => {
  if (head.length >= 4) {
    if (head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46) {
      const is64 = head[4] === 0x02;
      const le = head[5] === 0x01;
      const machine =
        head.length >= 20 ? (ELF_MACHINES[readU16(head, 18, le)] ?? "unknown") : "unknown";
      return { format: "elf", architecture: `${is64 ? "64-bit" : "32-bit"} ${machine}` };
    }
    if (head[0] === 0x4d && head[1] === 0x5a) {
      return { format: "pe", architecture: "unknown" };
    }
    const be32 = readU32(head, 0, false);
    const le32 = readU32(head, 0, true);
    if (MACHO_MAGICS.has(be32) || MACHO_MAGICS.has(le32)) {
      return { format: "macho" };
    }
  }
  // Filename extension hint (checked before weak text heuristics).
  const ext = fileName ? path.extname(fileName).toLowerCase() : "";
  const JS_EXTS = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);
  if (JS_EXTS.has(ext)) return { format: "javascript", detail: `extension ${ext}` };
  if (ext === ".json") return { format: "json" };

  if (head.length >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) {
    return { format: "javascript", detail: "utf8-bom" };
  }
  // Heuristic text checks for JavaScript (source or CJS/ESM module).
  const text = head.subarray(0, 1024).toString("utf8");
  if (
    /(^|\n)\s*(import\s|export\s|#!.*node|require\(|module\.exports|define\()/.test(text)
  ) {
    return { format: "javascript" };
  }
  if (text.startsWith("{") || text.startsWith("[")) {
    return { format: "json" };
  }
  return { format: "unknown" };
};

/** Probe a real file by reading its first 4 KiB (read-only, bounded). */
export const probeFormatHead = async (
  filePath: string,
  isDirectory: boolean,
): Promise<FormatProbe> => {
  if (isDirectory) return { format: "directory" };
  const handle = await open(filePath, "r");
  try {
    const head = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(head, 0, head.length, 0);
    return probeFormat(head.subarray(0, bytesRead), filePath);
  } finally {
    await handle.close();
  }
};
