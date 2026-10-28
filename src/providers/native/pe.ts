/**
 * Pure-TypeScript PE parser: DOS header, COFF header, optional header,
 * section table, export directory and import directory names.
 */

export interface PeSection {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  characteristics: number;
}

export interface PeExport {
  ordinal: number;
  name: string;
  rva: number;
}

export interface PeImport {
  dll: string;
  imports: string[];
}

export interface PeInfo {
  machine: number;
  machineName: string;
  isPe32Plus: boolean;
  entryRva: string;
  imageBase: string;
  subsystem: number;
  subsystemName: string;
  sections: PeSection[];
  exports: PeExport[];
  imports: PeImport[];
  parseGaps: string[];
}

const MACHINES: Record<number, string> = {
  0x014c: "i386",
  0x8664: "x86-64",
  0x01c0: "arm",
  0xaa64: "aarch64",
  0x01c4: "armnt",
};
const SUBSYSTEMS: Record<number, string> = {
  1: "native", 2: "windows-gui", 3: "windows-cui", 9: "windows-ce",
  10: "efi-application", 14: "efi-boot-driver",
};

export const parsePe = (buffer: Buffer): PeInfo => {
  if (buffer.length < 0x40 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    throw new Error("not a PE (missing MZ)");
  }
  const e_lfanew = buffer.readUInt32LE(0x3c);
  if (buffer.length < e_lfanew + 24 || buffer.readUInt32LE(e_lfanew) !== 0x00004550) {
    throw new Error("PE signature missing");
  }
  const parseGaps: string[] = [];
  const coff = e_lfanew + 4;
  const machine = buffer.readUInt16LE(coff);
  const numSections = buffer.readUInt16LE(coff + 2);
  const sizeOfOptional = buffer.readUInt16LE(coff + 16);
  const opt = coff + 20;
  const magic = buffer.readUInt16LE(opt);
  const isPe32Plus = magic === 0x20b;
  const entryRva = buffer.readUInt32LE(opt + (isPe32Plus ? 16 : 16));
  const imageBase = isPe32Plus
    ? buffer.readBigUInt64LE(opt + 24)
    : BigInt(buffer.readUInt32LE(opt + 28));
  const subsystem = buffer.readUInt16LE(opt + (isPe32Plus ? 68 : 68));

  const secBase = opt + sizeOfOptional;
  const sections: PeSection[] = [];
  const readName = (base: number): string => {
    const raw = buffer.subarray(base, base + 8);
    const end = raw.indexOf(0);
    return raw.subarray(0, end === -1 ? 8 : end).toString("utf8");
  };
  for (let i = 0; i < numSections; i++) {
    const base = secBase + i * 40;
    if (base + 40 > buffer.length) {
      parseGaps.push(`section ${String(i)} out of bounds`);
      break;
    }
    sections.push({
      name: readName(base),
      virtualSize: buffer.readUInt32LE(base + 8),
      virtualAddress: buffer.readUInt32LE(base + 12),
      sizeOfRawData: buffer.readUInt32LE(base + 16),
      pointerToRawData: buffer.readUInt32LE(base + 20),
      characteristics: buffer.readUInt32LE(base + 36),
    });
  }

  /** RVA → file offset via section mapping. */
  const rvaToOffset = (rva: number): number => {
    for (const sec of sections) {
      if (rva >= sec.virtualAddress && rva < sec.virtualAddress + Math.max(sec.virtualSize, sec.sizeOfRawData)) {
        return sec.pointerToRawData + (rva - sec.virtualAddress);
      }
    }
    return -1;
  };

  const exports: PeExport[] = [];
  const imports: PeImport[] = [];

  // Data directories live at the end of the optional header.
  const dataDirs = opt + (isPe32Plus ? 112 : 96);
  const readDir = (index: number): { rva: number; size: number } => ({
    rva: buffer.readUInt32LE(dataDirs + index * 8),
    size: buffer.readUInt32LE(dataDirs + index * 8 + 4),
  });

  // Export directory (index 0)
  const exportDir = readDir(0);
  if (exportDir.rva > 0) {
    const off = rvaToOffset(exportDir.rva);
    if (off >= 0 && off + 40 <= buffer.length) {
      const ordinalBase = buffer.readUInt32LE(off + 16);
      const numNames = buffer.readUInt32LE(off + 24);
      const namesRva = buffer.readUInt32LE(off + 32);
      const namesOff = rvaToOffset(namesRva);
      const capped = Math.min(numNames, 5000);
      if (namesOff >= 0) {
        for (let i = 0; i < capped; i++) {
          const namePtrRva = buffer.readUInt32LE(namesOff + i * 4);
          const nameOff = rvaToOffset(namePtrRva);
          if (nameOff < 0) {
            parseGaps.push(`export name ${String(i)} unmapped`);
            continue;
          }
          const end = buffer.indexOf(0, nameOff);
          exports.push({
            ordinal: ordinalBase + i,
            name: buffer.subarray(nameOff, end === -1 ? nameOff + 256 : end).toString("utf8"),
            rva: 0,
          });
        }
      }
    } else {
      parseGaps.push("export directory unmapped");
    }
  }

  // Import directory (index 1) — walk IMAGE_IMPORT_DESCRIPTORs.
  const importDir = readDir(1);
  if (importDir.rva > 0) {
    let off = rvaToOffset(importDir.rva);
    let guard = 0;
    while (off >= 0 && off + 20 <= buffer.length && guard < 256) {
      guard += 1;
      const nameRva = buffer.readUInt32LE(off + 12);
      if (nameRva === 0) break;
      const nameOff = rvaToOffset(nameRva);
      if (nameOff < 0) {
        parseGaps.push("import descriptor name unmapped");
        break;
      }
      const dllEnd = buffer.indexOf(0, nameOff);
      const dll = buffer.subarray(nameOff, dllEnd === -1 ? nameOff + 128 : dllEnd).toString("utf8");
      // OriginalFirstThunk (hint/name table)
      const oftRva = buffer.readUInt32LE(off);
      const thunkOff = rvaToOffset(oftRva);
      const names: string[] = [];
      if (thunkOff >= 0) {
        const thunkSize = isPe32Plus ? 8 : 4;
        for (let i = 0; i < 4096; i++) {
          const t = thunkOff + i * thunkSize;
          if (t + thunkSize > buffer.length) break;
          const thunk = isPe32Plus
            ? buffer.readBigUInt64LE(t)
            : BigInt(buffer.readUInt32LE(t));
          if (thunk === 0n) break;
          const flagBit = isPe32Plus ? 1n << 63n : 1n << 31n;
          if ((thunk & flagBit) !== 0n) continue; // import by ordinal
          const hintRva = Number(thunk & 0x7fffffffn);
          const hintOff = rvaToOffset(hintRva);
          if (hintOff >= 0 && hintOff + 2 <= buffer.length) {
            const end = buffer.indexOf(0, hintOff + 2);
            names.push(buffer.subarray(hintOff + 2, end === -1 ? hintOff + 258 : end).toString("utf8"));
          }
          if (names.length >= 500) break;
        }
      }
      imports.push({ dll, imports: names });
      off += 20;
    }
  }

  return {
    machine,
    machineName: MACHINES[machine] ?? `machine-0x${machine.toString(16)}`,
    isPe32Plus,
    entryRva: entryRva.toString(16),
    imageBase: imageBase.toString(16),
    subsystem,
    subsystemName: SUBSYSTEMS[subsystem] ?? `subsystem-${String(subsystem)}`,
    sections,
    exports,
    imports,
    parseGaps,
  };
};
