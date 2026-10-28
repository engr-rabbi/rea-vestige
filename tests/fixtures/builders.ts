/**
 * Deterministic binary fixture builders (Stage F accuracy foundation).
 * These construct real ELF64/PE32+/Mach-O64 byte images with KNOWN ground
 * truth so provider output can be scored for precision/recall. No compiled
 * binaries are committed; everything is synthesized from bytes.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";

const enc = (s: string): Buffer => Buffer.from(s, "latin1");

export interface ElfFixtureSpec {
  symbols: Array<{ name: string; value: number; size: number; type: "func" | "object" | "notype"; bind: "global" | "local" | "weak" }>;
  interpreter?: string;
}

export const ELF64_GROUND_TRUTH = {
  symbols: [
    { name: "vestige_main", value: 0x1000, size: 16, type: "func", bind: "global" },
    { name: "vestige_helper", value: 0x1010, size: 32, type: "func", bind: "local" },
    { name: "vestige_counter", value: 0x2000, size: 4, type: "object", bind: "global" },
    { name: "vestige_secret_key", value: 0x2010, size: 64, type: "object", bind: "local" },
  ],
  interpreter: "/lib64/ld-linux-x86-64.so.2",
} as const satisfies ElfFixtureSpec;

const symTypeCode = (t: string): number => (t === "func" ? 2 : t === "object" ? 1 : 0);
const symBindCode = (b: string): number => (b === "global" ? 1 : b === "weak" ? 2 : 0);

/** Build a minimal but structurally valid ELF64 executable. */
export const buildElf64 = (
  spec: ElfFixtureSpec = ELF64_GROUND_TRUTH,
): Buffer => {
  const strtabStrings: string[] = ["\0"];
  const addString = (pool: string[], s: string): number => {
    let offset = 0;
    for (const existing of pool) offset += existing.length;
    pool.push(`${s}\0`);
    return offset;
  };
  const symtab: Buffer[] = [Buffer.alloc(24)]; // null symbol

  for (const sym of spec.symbols) {
    const nameOff = addString(strtabStrings, sym.name);
    const entry = Buffer.alloc(24);
    entry.writeUInt32LE(nameOff, 0);
    entry.writeUInt8((symBindCode(sym.bind) << 4) | symTypeCode(sym.type), 4);
    entry.writeUInt8(0, 5); // st_other
    entry.writeUInt16LE(1, 6); // st_shndx = .text
    entry.writeBigUInt64LE(BigInt(sym.value), 8);
    entry.writeBigUInt64LE(BigInt(sym.size), 16);
    symtab.push(entry);
  }
  const strtab = Buffer.concat(strtabStrings.map(enc));

  const ehsize = 64;
  const phentsize = 56;
  const phnum = spec.interpreter ? 2 : 1;
  const phoff = ehsize;
  const textContent = Buffer.alloc(0x100, 0x90); // .text content (nop sled)

  // Program headers: PT_LOAD + optional PT_INTERP
  const programHeaders: Buffer[] = [];
  const load = Buffer.alloc(56);
  load.writeUInt32LE(1, 0); // PT_LOAD
  load.writeUInt32LE(5, 4); // R+X
  load.writeUInt32LE(0, 8); // offset
  load.writeBigUInt64LE(0x400000n, 16); // vaddr
  load.writeBigUInt64LE(0x400000n, 24);
  load.writeBigUInt64LE(BigInt(textContent.length + 0x400), 32); // filesz (rough)
  load.writeBigUInt64LE(BigInt(textContent.length + 0x400), 40);
  load.writeBigUInt64LE(0x1000n, 48); // align
  programHeaders.push(load);
  let interpContent = Buffer.alloc(0);
  if (spec.interpreter) {
    interpContent = Buffer.concat([enc(spec.interpreter), Buffer.from([0])]);
    const interp = Buffer.alloc(56);
    interp.writeUInt32LE(3, 0); // PT_INTERP
    interp.writeUInt32LE(4, 4);
    interp.writeUInt32LE(phoff + phentsize, 8); // offset placeholder fixed below
    interp.writeBigUInt64LE(0x400318n, 16);
    interp.writeBigUInt64LE(0x400318n, 24);
    interp.writeBigUInt64LE(BigInt(interpContent.length), 32);
    interp.writeBigUInt64LE(BigInt(interpContent.length), 40);
    interp.writeBigUInt64LE(1n, 48);
    programHeaders.push(interp);
  }
  // Fix PT_INTERP offset = phoff + phentsize (right after headers)
  const fileOffAfterPh = phoff + phnum * phentsize;
  if (spec.interpreter) {
    programHeaders[1]?.writeUInt32LE(fileOffAfterPh, 8);
  }

  // Layout after program headers: [interp][.text][.symtab][.strtab][section headers][.shstrtab]
  let cursor = fileOffAfterPh;
  if (spec.interpreter) cursor += interpContent.length;
  const textOffset = cursor;
  cursor += textContent.length;
  const symtabOffset = cursor;
  const symtabBuf = Buffer.concat(symtab);
  cursor += symtabBuf.length;
  const strtabOffset = cursor;
  cursor += strtab.length;

  // Section headers — all five entries defined up front, then filled.
  const shentsize = 64;
  const sections: Array<{ nameOff: number; type: number; flags: number; addr: number; offset: number; size: number; link: number; info: number; align: number; entsize: number }> = [
    { nameOff: 0, type: 0, flags: 0, addr: 0, offset: 0, size: 0, link: 0, info: 0, align: 0, entsize: 0 }, // null
    { nameOff: 0, type: 1, flags: 6, addr: 0x401000, offset: 0, size: 0, link: 0, info: 0, align: 16, entsize: 0 }, // .text
    { nameOff: 0, type: 2, flags: 0, addr: 0, offset: symtabOffset, size: symtabBuf.length, link: 0, info: 0, align: 8, entsize: 24 }, // .symtab
    { nameOff: 0, type: 3, flags: 0, addr: 0, offset: strtabOffset, size: strtab.length, link: 0, info: 0, align: 1, entsize: 0 }, // .strtab
    { nameOff: 0, type: 3, flags: 0, addr: 0, offset: 0, size: 0, link: 0, info: 0, align: 1, entsize: 0 }, // .shstrtab
  ];
  const shstrndx = 4;

  const shoff = cursor;
  const shstrtabOffset = shoff + sections.length * shentsize;
  const shstrtabStringsFinal: string[] = ["\0"];
  addString(shstrtabStringsFinal, ".text");
  addString(shstrtabStringsFinal, ".symtab");
  addString(shstrtabStringsFinal, ".strtab");
  addString(shstrtabStringsFinal, ".shstrtab");
  const shstrtab = Buffer.concat(shstrtabStringsFinal.map(enc));
  sections[1]!.offset = textOffset;
  sections[1]!.size = textContent.length;
  sections[1]!.nameOff = shstrtab.indexOf(enc(".text\0"));
  sections[2]!.nameOff = shstrtab.indexOf(enc(".symtab\0"));
  sections[3]!.nameOff = shstrtab.indexOf(enc(".strtab\0"));
  sections[2]!.link = 3; // symtab → strtab
  sections[4]!.offset = shstrtabOffset;
  sections[4]!.size = shstrtab.length;
  sections[4]!.nameOff = shstrtab.indexOf(enc(".shstrtab\0"));

  const shHeaders = sections.map((s) => {
    const b = Buffer.alloc(64);
    b.writeUInt32LE(s.nameOff, 0);
    b.writeUInt32LE(s.type, 4);
    b.writeBigUInt64LE(BigInt(s.flags), 8);
    b.writeBigUInt64LE(BigInt(s.addr), 16);
    b.writeBigUInt64LE(BigInt(s.offset), 24);
    b.writeBigUInt64LE(BigInt(s.size), 32);
    b.writeUInt32LE(s.link, 40);
    b.writeUInt32LE(s.info, 44);
    b.writeBigUInt64LE(BigInt(s.align), 48);
    b.writeBigUInt64LE(BigInt(s.entsize), 56);
    return b;
  });

  const header = Buffer.alloc(64);
  header.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0); // magic, 64-bit, LE, v1
  header.writeUInt16LE(2, 16); // ET_EXEC
  header.writeUInt16LE(0x3e, 18); // x86-64
  header.writeUInt32LE(1, 20);
  header.writeBigUInt64LE(0x401000n, 24); // entry
  header.writeBigUInt64LE(BigInt(phoff), 32);
  header.writeBigUInt64LE(BigInt(shoff), 40);
  header.writeUInt32LE(0, 48);
  header.writeUInt16LE(ehsize, 52);
  header.writeUInt16LE(phentsize, 54);
  header.writeUInt16LE(phnum, 56);
  header.writeUInt16LE(shentsize, 58);
  header.writeUInt16LE(sections.length, 60);
  header.writeUInt16LE(shstrndx, 62);

  return Buffer.concat([
    header,
    ...programHeaders,
    ...(spec.interpreter ? [interpContent] : []),
    textContent,
    symtabBuf,
    strtab,
    ...shHeaders,
    shstrtab,
  ]);
};

/** PE32+ (x86-64) fixture with 2 named exports and 1 DLL import. */
export const PE64_GROUND_TRUTH = {
  exports: ["vestige_export_a", "vestige_export_b"],
  imports: { dll: "VSTIGE32.dll", functions: ["VstigeOpen", "VstigeClose"] },
} as const;

export const buildPe64 = (): Buffer => {
  const dos = Buffer.alloc(0x80);
  dos.write("MZ", 0, "latin1");
  dos.writeUInt32LE(0x80, 0x3c);

  const pe = Buffer.alloc(0x400);

  // PE signature + COFF
  pe.writeUInt32LE(0x00004550, 0);
  pe.writeUInt16LE(0x8664, 4); // machine
  pe.writeUInt16LE(2, 6); // numSections
  pe.writeUInt32LE(0, 8); // timestamp
  pe.writeUInt32LE(0, 12);
  pe.writeUInt32LE(0, 16);
  pe.writeUInt16LE(0xf0, 20); // sizeOfOptional (PE32+)
  pe.writeUInt16LE(0x22, 22); // characteristics
  const opt = 24;
  pe.writeUInt16LE(0x20b, opt); // PE32+ magic
  pe.writeUInt16LE(14, opt + 2);
  pe.writeUInt32LE(0x200, opt + 4); // SizeOfCode
  pe.writeUInt32LE(0x1000, opt + 16); // AddressOfEntryPoint
  pe.writeBigUInt64LE(0x140000000n, opt + 24); // ImageBase
  pe.writeUInt32LE(0x1000, opt + 32); // SectionAlignment
  pe.writeUInt32LE(0x200, opt + 36); // FileAlignment
  pe.writeUInt16LE(3, opt + 68); // Subsystem CUI
  const dataDirs = opt + 112;
  // Data directory 0 = export, 1 = import (RVAs filled after layout planning)
  const exportRva = 0x2000;
  const importRva = 0x2028;
  pe.writeUInt32LE(exportRva, dataDirs);
  pe.writeUInt32LE(0x80, dataDirs + 4);
  pe.writeUInt32LE(importRva, dataDirs + 8);
  pe.writeUInt32LE(0x28, dataDirs + 12);

  const secBase = opt + 0xf0;
  const writeSection = (idx: number, name: string, vsize: number, vaddr: number, rawsize: number, rawptr: number): void => {
    const base = secBase + idx * 40;
    pe.write(name, base, "latin1");
    pe.writeUInt32LE(vsize, base + 8);
    pe.writeUInt32LE(vaddr, base + 12);
    pe.writeUInt32LE(rawsize, base + 16);
    pe.writeUInt32LE(rawptr, base + 20);
    pe.writeUInt32LE(0x60000020, base + 36); // characteristics
  };
  // .text at RVA 0x1000 (raw 0x400), .rdata at RVA 0x2000 (raw 0x600)
  writeSection(0, ".text\0\0\0", 0x200, 0x1000, 0x200, 0x400);
  writeSection(1, ".rdata\0\0", 0x180, 0x2000, 0x200, 0x600);

  // Build .rdata content: export dir, names, dll name, import descriptors, IAT
  const rdata = Buffer.alloc(0x200);
  // Export directory at rdata offset 0 (RVA 0x2000)
  const nameStrings: Array<{ str: string; rva: number }> = [];
  const placeString = (str: string): number => {
    const rva = 0x2000 + 0xa0 + nameStrings.reduce((n, s) => n + s.str.length + 1, 0);
    nameStrings.push({ str, rva });
    return rva;
  };
  const dllNameRva = placeString(PE64_GROUND_TRUTH.imports.dll);
  const exportNameRvas = PE64_GROUND_TRUTH.exports.map(placeString);
  // Import thunks point at IMAGE_IMPORT_BY_NAME entries: 2-byte hint + name.
  const hintBase = 0x140; // rdata offset for hint/name entries (past all name strings)
  let hintOff = hintBase;
  const importThunkRvas = PE64_GROUND_TRUTH.imports.functions.map((fn) => {
    const rva = 0x2000 + hintOff;
    hintOff += 2 + fn.length + 1;
    return rva;
  });

  rdata.writeUInt32LE(0, 0); // characteristics
  rdata.writeUInt32LE(0, 4);
  rdata.writeUInt16LE(0, 8);
  rdata.writeUInt16LE(0, 10);
  rdata.writeUInt32LE(dllNameRva, 12); // module name RVA
  rdata.writeUInt32LE(1, 16); // ordinal base
  rdata.writeUInt32LE(2, 20); // number of functions
  rdata.writeUInt32LE(2, 24); // number of names
  rdata.writeUInt32LE(0x2000 + 0x60, 28); // address of functions (EAT)
  rdata.writeUInt32LE(0x2000 + 0x50, 32); // address of names
  rdata.writeUInt32LE(0x2000 + 0x70, 36); // address of ordinals
  // EAT
  rdata.writeUInt32LE(0x1010, 0x60);
  rdata.writeUInt32LE(0x1020, 0x64);
  // Names array
  rdata.writeUInt32LE(exportNameRvas[0] ?? 0, 0x50);
  rdata.writeUInt32LE(exportNameRvas[1] ?? 0, 0x54);
  // Ordinals
  rdata.writeUInt16LE(0, 0x70);
  rdata.writeUInt16LE(1, 0x72);
  // Name strings
  let sOff = 0xa0;
  for (const { str } of nameStrings) {
    rdata.write(str, sOff, "latin1");
    sOff += str.length + 1;
  }
  // hint/name entries at 0x140: 2-byte hint (0) + name + NUL
  PE64_GROUND_TRUTH.imports.functions.forEach((fn, i) => {
    const base = hintBase + PE64_GROUND_TRUTH.imports.functions
      .slice(0, i)
      .reduce((n, f) => n + 2 + f.length + 1, 0);
    rdata.writeUInt16LE(0, base); // hint
    rdata.write(fn, base + 2, "latin1");
  });
  // Import descriptors at rdata 0x28 (RVA 0x2028): 2 × 20 bytes, ends before 0x50.
  const oftRva = 0x2000 + 0x100; // hint/name thunks (well past string area)
  rdata.writeUInt32LE(oftRva, 0x28);          // OriginalFirstThunk
  rdata.writeUInt32LE(0, 0x2c);               // TimeDateStamp
  rdata.writeUInt32LE(0, 0x30);               // ForwarderChain
  rdata.writeUInt32LE(dllNameRva, 0x34);      // Name RVA
  rdata.writeUInt32LE(0x2000 + 0x120, 0x38);  // FirstThunk (IAT)
  // Descriptor terminator (0x3c..0x50) remains zero.
  // hint/name thunks (PE32+ 8-byte thunks) at 0x100 → point at hint/name entries
  importThunkRvas.forEach((rva, i) => {
    rdata.writeBigUInt64LE(BigInt(rva), 0x100 + i * 8);
  });
  rdata.writeBigUInt64LE(0n, 0x100 + importThunkRvas.length * 8);
  // IAT at 0x120 mirrors OFT
  importThunkRvas.forEach((rva, i) => {
    rdata.writeBigUInt64LE(BigInt(rva), 0x120 + i * 8);
  });
  rdata.writeBigUInt64LE(0n, 0x120 + importThunkRvas.length * 8);

  const dosLen = dos.length; // 0x80
  const peFileOffset = dosLen; // 0x80
  const total = peFileOffset + 0x400 + 0x200 + 0x200;
  const image = Buffer.alloc(total);
  dos.copy(image, 0);
  pe.copy(image, peFileOffset);
  const textRaw = Buffer.alloc(0x200, 0x90);
  textRaw.copy(image, 0x400);
  rdata.copy(image, 0x600);
  return image;
};

/** Mach-O64 (x86_64) fixture with 2 sections, 2 symbols, 1 dylib. */
export const MACHO64_GROUND_TRUTH = {
  symbols: [
    { name: "_vestige_entry", value: 0x1000, type: 15 },
    { name: "_vestige_flag", value: 0x2000, type: 15 },
  ],
  dylib: "/usr/lib/libvestige.1.dylib",
  sections: [
    { segment: "__TEXT", name: "__text" },
    { segment: "__DATA", name: "__data" },
  ],
} as const;

export const buildMacho64 = (): Buffer => {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64
  header.writeUInt32LE(0x01000007, 4); // CPU x86-64
  header.writeUInt32LE(3, 8); // CPU subtyp
  header.writeUInt32LE(2, 12); // MH_EXECUTE
  const ncmds = 3;
  header.writeUInt32LE(ncmds, 16);
  const sizeofcmdsOffset = 20;

  const seg = Buffer.alloc(72 + 2 * 80);
  seg.writeUInt32LE(0x19, 0); // LC_SEGMENT_64
  seg.writeUInt32LE(72 + 2 * 80, 4);
  seg.write("__TEXT", 8, "latin1");
  seg.writeBigUInt64LE(0x100000000n, 24); // vmaddr
  seg.writeBigUInt64LE(0x1000n, 32);
  seg.writeBigUInt64LE(0n, 40);
  seg.writeBigUInt64LE(0x1000n, 48);
  seg.writeUInt32LE(7, 56);
  seg.writeUInt32LE(5, 60);
  seg.writeUInt32LE(2, 64); // nsects
  seg.writeUInt32LE(0, 68);
  const sect = (i: number, name: string, segName: string, addr: number): void => {
    const base = 72 + i * 80;
    seg.write(name, base, "latin1");
    seg.write(segName, base + 16, "latin1");
    seg.writeBigUInt64LE(BigInt(addr), base + 32);
    seg.writeBigUInt64LE(0x10n, base + 40);
  };
  sect(0, MACHO64_GROUND_TRUTH.sections[0]?.name ?? "__text", "__TEXT", 0x1000001000);
  sect(1, MACHO64_GROUND_TRUTH.sections[1]?.name ?? "__data", "__DATA", 0x100002000);

  // LC_SYMTAB
  const symtabData: Buffer[] = [];
  const strtabStrings: Buffer[] = [Buffer.from([0])];
  let stroff = 1;
  for (const sym of MACHO64_GROUND_TRUTH.symbols) {
    const entry = Buffer.alloc(16);
    entry.writeUInt32LE(stroff, 0);
    entry.writeUInt8(sym.type, 4);
    entry.writeBigUInt64LE(BigInt(sym.value), 8);
    symtabData.push(entry);
    strtabStrings.push(Buffer.concat([Buffer.from(`${sym.name}\0`, "latin1")]));
    stroff += sym.name.length + 1;
  }
  const symtabBuf = Buffer.concat(symtabData);
  const strtab = Buffer.concat(strtabStrings);

  const symtabCmd = Buffer.alloc(24);
  symtabCmd.writeUInt32LE(0x2, 0); // LC_SYMTAB
  symtabCmd.writeUInt32LE(24, 4);
  symtabCmd.writeUInt32LE(0x200, 8); // symoff (file offset, fixed below)
  symtabCmd.writeUInt32LE(symtabData.length, 12);
  symtabCmd.writeUInt32LE(0x300, 16); // stroff
  symtabCmd.writeUInt32LE(strtab.length, 20);

  const dylibName = Buffer.concat([Buffer.from(MACHO64_GROUND_TRUTH.dylib, "latin1"), Buffer.from([0])]);
  const dylibCmd = Buffer.alloc(24 + dylibName.length + 4);
  dylibCmd.writeUInt32LE(0xc, 0); // LC_LOAD_DYLIB
  dylibCmd.writeUInt32LE(dylibCmd.length, 4);
  dylibCmd.writeUInt32LE(24, 8); // name offset (from cmd start)
  dylibName.copy(dylibCmd, 24);

  const cmds = [seg, symtabCmd, dylibCmd];
  const sizeofcmds = cmds.reduce((n, c) => n + c.length, 0);
  header.writeUInt32LE(sizeofcmds, sizeofcmdsOffset);

  const headerEnd = 32 + sizeofcmds;
  // symoff/stroff are file offsets after load commands
  symtabCmd.writeUInt32LE(headerEnd, 8);
  symtabCmd.writeUInt32LE(headerEnd + symtabBuf.length, 16);

  return Buffer.concat([header, ...cmds, symtabBuf, strtab]);
};

/** Write a fixture to disk; returns the path. */
export const writeFixture = (dir: string, name: string, content: Buffer | string): string => {
  mkdirSync(dir, { recursive: true });
  const file = `${dir}/${name}`;
  writeFileSync(file, content);
  return file;
};

/** Read back for debugging parity between builder and file. */
export const readFixture = (path: string): Buffer => readFileSync(path);
