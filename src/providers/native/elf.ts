/**
 * Pure-TypeScript ELF parser (little/big endian, 32/64-bit).
 * Extracts header facts, sections, and symbols from .symtab/.dynsym.
 * Deterministic and side-effect free; never executes the target.
 */

export interface ElfSection {
  name: string;
  type: number;
  flags: number;
  addr: string;
  offset: number;
  size: number;
}

export interface ElfSymbol {
  name: string;
  value: string;
  size: number;
  type: string;
  bind: string;
  sectionIndex: number;
  table: "symtab" | "dynsym";
}

export interface ElfInfo {
  is64: boolean;
  littleEndian: boolean;
  machine: number;
  machineName: string;
  entry: string;
  type: number;
  typeName: string;
  sections: ElfSection[];
  symbols: ElfSymbol[];
  interpreter?: string;
  parseGaps: string[];
}

const MACHINES: Record<number, string> = {
  0x02: "sparc",
  0x03: "x86",
  0x08: "mips",
  0x14: "powerpc",
  0x15: "powerpc64",
  0x28: "arm",
  0x32: "ia64",
  0x3e: "x86-64",
  0xb7: "aarch64",
  0xf3: "riscv",
};

const SYM_TYPES: Record<number, string> = {
  0: "notype", 1: "object", 2: "func", 3: "section", 4: "file",
  5: "common", 6: "tls", 10: "gnu-ifunc",
};
const SYM_BINDS: Record<number, string> = {
  0: "local", 1: "global", 2: "weak", 10: "gnu-unique",
};
const ELF_TYPES: Record<number, string> = {
  0: "none", 1: "rel", 2: "exec", 3: "dyn", 4: "core",
};

export const parseElf = (buffer: Buffer): ElfInfo => {
  if (buffer.length < 64) throw new Error("ELF too small");
  const is64 = buffer[4] === 2;
  const le = buffer[5] === 1;
  const u16 = (o: number): number => (le ? buffer.readUInt16LE(o) : buffer.readUInt16BE(o));
  const u32 = (o: number): number => (le ? buffer.readUInt32LE(o) : buffer.readUInt32BE(o));
  const u64 = (o: number): bigint =>
    le ? buffer.readBigUInt64LE(o) : buffer.readBigUInt64BE(o);

  const machine = u16(18);
  const type = u16(16);
  const entry = (is64 ? u64(24) : BigInt(u32(24))).toString(16);
  const parseGaps: string[] = [];

  // Section header table
  const shoff = is64 ? Number(u64(0x28)) : u32(0x20);
  const shentsize = u16(0x3a);
  const shnum = u16(0x3c);
  const shstrndx = u16(0x3e);

  const sections: ElfSection[] = [];
  const readCStr = (offset: number): string => {
    const end = buffer.indexOf(0, offset);
    return buffer.subarray(offset, end === -1 ? Math.min(offset + 4096, buffer.length) : end).toString("utf8");
  };

  let strtabSectionOffset = 0;
  if (shnum > 0 && shoff > 0) {
    const strHeader = shoff + shstrndx * shentsize;
    if (strHeader + shentsize <= buffer.length) {
      strtabSectionOffset = is64 ? Number(u64(strHeader + 0x18)) : u32(strHeader + 0x10);
    }
    for (let i = 0; i < shnum; i++) {
      const base = shoff + i * shentsize;
      if (base + shentsize > buffer.length) {
        parseGaps.push(`section ${String(i)} header out of bounds`);
        break;
      }
      const nameOffset = u32(base);
      const name = strtabSectionOffset
        ? readCStr(strtabSectionOffset + nameOffset)
        : "";
      sections.push({
        name,
        type: u32(base + 4),
        flags: Number(is64 ? u64(base + 8) : BigInt(u32(base + 8))),
        addr: (is64 ? u64(base + 0x10) : BigInt(u32(base + 0x10))).toString(16),
        offset: is64 ? Number(u64(base + 0x18)) : u32(base + 0x10),
        size: is64 ? Number(u64(base + 0x20)) : u32(base + 0x14),
      });
    }
  } else {
    parseGaps.push("no section header table (stripped section headers)");
  }

  const symbols: ElfSymbol[] = [];
  const parseSymtab = (
    sectionIdx: number,
    table: "symtab" | "dynsym",
  ): void => {
    const sec = sections[sectionIdx];
    if (!sec) return;
    // Companion string table is linked via sh_link.
    const linkBase = shoff + sectionIdx * shentsize + (is64 ? 0x28 : 0x18);
    const linkIdx = u32(linkBase);
    const strSec = sections[linkIdx];
    const strOff = strSec?.offset ?? 0;
    const symSize = is64 ? 24 : 16;
    const count = Math.floor(sec.size / symSize);
    const maxSymbols = 20_000;
    for (let i = 0; i < count && symbols.length < maxSymbols; i++) {
      const base = sec.offset + i * symSize;
      if (base + symSize > buffer.length) {
        parseGaps.push(`symbol ${String(i)} in ${table} out of bounds`);
        break;
      }
      const nameOff = u32(base);
      const name = strOff ? readCStr(strOff + nameOff) : "";
      if (!name) continue;
      const info = buffer[base + (is64 ? 4 : 12)];
      const value = is64 ? u64(base + 8) : BigInt(u32(base + 4));
      const size = is64 ? Number(u64(base + 0x10)) : u32(base + 8);
      symbols.push({
        name,
        value: value.toString(16),
        size,
        type: SYM_TYPES[info & 0xf] ?? `unknown-${String(info & 0xf)}`,
        bind: SYM_BINDS[info >> 4] ?? `unknown-${String(info >> 4)}`,
        sectionIndex: u16(base + (is64 ? 6 : 14)),
        table,
      });
    }
  };

  for (let i = 0; i < sections.length; i++) {
    const sec = sections[i];
    if (!sec) continue;
    if (sec.type === 2 /* SHT_SYMTAB */ || sec.type === 11 /* SHT_DYNSYM */) {
      parseSymtab(i, sec.type === 2 ? "symtab" : "dynsym");
    }
  }

  // PT_INTERP: find interpreter string via program headers (simplified scan).
  let interpreter: string | undefined;
  const phoff = is64 ? Number(u64(0x20)) : u32(0x1c);
  const phentsize = u16(0x36);
  const phnum = u16(0x38);
  for (let i = 0; i < phnum; i++) {
    const base = phoff + i * phentsize;
    if (base + phentsize > buffer.length) break;
    const ptype = u32(base);
    if (ptype === 3 /* PT_INTERP */) {
      const off = is64 ? Number(u64(base + 8)) : u32(base + 4);
      const size = is64 ? Number(u64(base + 0x20)) : u32(base + 0x10);
      interpreter = buffer.subarray(off, off + Math.min(size, 512)).toString("utf8").replace(/\0.*$/, "");
    }
  }

  return {
    is64,
    littleEndian: le,
    machine,
    machineName: MACHINES[machine] ?? `machine-${String(machine)}`,
    entry,
    type,
    typeName: ELF_TYPES[type] ?? `type-${String(type)}`,
    sections,
    symbols,
    interpreter,
    parseGaps,
  };
};
