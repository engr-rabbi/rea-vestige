/**
 * Pure-TypeScript Mach-O parser (32/64-bit, native or byte-swapped, plus
 * minimal FAT/universal binary handling for the first architecture slice).
 */

export interface MachoSection {
  segment: string;
  name: string;
  addr: string;
  size: number;
}

export interface MachoSymbol {
  name: string;
  value: string;
  type: number;
}

export interface MachoLoadDylib {
  name: string;
}

export interface MachoInfo {
  is64: boolean;
  littleEndian: boolean;
  cputype: number;
  filetype: number;
  ncmds: number;
  sections: MachoSection[];
  symbols: MachoSymbol[];
  dylibs: MachoLoadDylib[];
  entrypoint?: string;
  parseGaps: string[];
}

export const CPU_TYPES: Record<number, string> = {
  7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000c: "arm64",
};

export const parseMacho = (buffer: Buffer): MachoInfo => {
  if (buffer.length < 32) throw new Error("Mach-O too small");

  // FAT/universal container: locate the first 64-bit slice if needed.
  let base = 0;
  const magicLE = buffer.readUInt32LE(0);
  const magicBE = buffer.readUInt32BE(0);
  if (magicBE === 0xcafebabe || magicBE === 0xcafebabf || magicLE === 0xbebafeca) {
    const be = magicBE === 0xcafebabe || magicBE === 0xcafebabf;
    const nfat = be ? buffer.readUInt32BE(4) : buffer.readUInt32LE(4);
    for (let i = 0; i < Math.min(nfat, 16); i++) {
      const archBase = 8 + i * 20;
      const cputype = be ? buffer.readUInt32BE(archBase) : buffer.readUInt32LE(archBase);
      const offset = be ? buffer.readUInt32BE(archBase + 8) : buffer.readUInt32LE(archBase + 8);
      if (cputype & 0x01000000) {
        base = offset;
        break;
      }
      base = offset; // fall back to first slice
    }
  }

  const readHeader = (offset: number): MachoInfo => {
    if (offset + 32 > buffer.length) throw new Error("Mach-O slice out of bounds");
    const m0 = buffer.readUInt32LE(offset);
    const is64 = m0 === 0xfeedfacf;
    const swap = m0 === 0xcefaedfe || m0 === 0xcffaedfe ? false : true;
    // Native endianness detection: 0xfeedfacf (64) / 0xfeedface (32) when read LE.
    const le = m0 === 0xfeedfacf || m0 === 0xfeedface;
    const is64Final = le
      ? m0 === 0xfeedfacf
      : buffer.readUInt32LE(offset) === 0xcffaedfe;
    const u32 = (o: number): number =>
      le ? buffer.readUInt32LE(o) : buffer.readUInt32BE(o);
    void is64;
    void swap;
    void magicLE;
    void magicBE;

    const cputype = u32(offset + 4);
    const filetype = u32(offset + 12);
    const ncmds = u32(offset + 16);
    const sizeofcmds = u32(offset + 20);
    const parseGaps: string[] = [];
    const sections: MachoSection[] = [];
    const symbols: MachoSymbol[] = [];
    const dylibs: MachoLoadDylib[] = [];
    let entrypoint: string | undefined;

    let cmdOffset = offset + (is64Final ? 32 : 28);
    const cmdsEnd = Math.min(cmdOffset + sizeofcmds, buffer.length);
    let cmdGuard = 0;
    while (cmdOffset + 8 <= cmdsEnd && cmdGuard < ncmds + 8) {
      cmdGuard += 1;
      const cmd = u32(cmdOffset);
      const cmdSize = u32(cmdOffset + 4);
      if (cmdSize < 8 || cmdOffset + cmdSize > buffer.length) break;

      // LC_SEGMENT (0x1) / LC_SEGMENT_64 (0x19)
      if (cmd === 0x19 || cmd === 0x1) {
        const _segName = buffer.subarray(cmdOffset + 8, cmdOffset + 24).toString("utf8").replace(/\0.*$/, "");
        const nsects = u32(cmdOffset + (is64Final ? 64 : 48));
        const sectBase = cmdOffset + (is64Final ? 72 : 56);
        const sectSize = is64Final ? 80 : 68;
        for (let i = 0; i < nsects; i++) {
          const s = sectBase + i * sectSize;
          if (s + 16 > buffer.length) break;
          const sectName = buffer.subarray(s, s + 16).toString("utf8").replace(/\0.*$/, "");
          const sectSeg = buffer.subarray(s + 16, s + 32).toString("utf8").replace(/\0.*$/, "");
          const addr = is64Final
            ? buffer.readBigUInt64LE(s + 32)
            : BigInt(buffer.readUInt32LE(s + 32));
          const size = is64Final
            ? Number(buffer.readBigUInt64LE(s + 40))
            : buffer.readUInt32LE(s + 40);
          sections.push({ segment: sectSeg, name: sectName, addr: addr.toString(16), size });
        }
      }
      // LC_UNIXTHREAD (0x5) entrypoint (simplified: read first thread PC)
      else if (cmd === 0x5 && entrypoint === undefined) {
        const count = u32(cmdOffset + 8);
        if (count >= 4) {
          const pc = u32(cmdOffset + 28);
          entrypoint = pc.toString(16);
        }
      }
      // LC_LOAD_DYLIB (0xc) / LC_LOAD_WEAK_DYLIB (0x18) / LC_REEXPORT_DYLIB (0x1f)
      else if (cmd === 0xc || cmd === 0x18 || cmd === 0x1f) {
        const nameOffset = u32(cmdOffset + 8);
        const nameStart = cmdOffset + nameOffset;
        const end = buffer.indexOf(0, nameStart);
        dylibs.push({
          name: buffer.subarray(nameStart, end === -1 ? nameStart + 256 : end).toString("utf8"),
        });
      }
      // LC_SYMTAB (0x2)
      else if (cmd === 0x2) {
        const symoff = u32(cmdOffset + 8);
        const nsyms = u32(cmdOffset + 12);
        const stroff = u32(cmdOffset + 16);
        const strsize = u32(cmdOffset + 20);
        const symSize = is64Final ? 16 : 12;
        const maxSyms = 20_000;
        for (let i = 0; i < Math.min(nsyms, maxSyms); i++) {
          const s = symoff + i * symSize;
          if (s + symSize > buffer.length) {
            parseGaps.push(`symbol ${String(i)} out of bounds`);
            break;
          }
          const n_strx = u32(s);
          const n_type = buffer[s + 4];
          const n_value = is64Final
            ? buffer.readBigUInt64LE(s + 8)
            : BigInt(buffer.readUInt32LE(s + 8));
          const nameEnd = stroff + n_strx <= buffer.length
            ? buffer.indexOf(0, stroff + n_strx)
            : -1;
          const name =
            n_strx > 0 && stroff + n_strx < buffer.length && nameEnd !== -1
              ? buffer.subarray(stroff + n_strx, Math.min(nameEnd, stroff + n_strx + 1024)).toString("utf8")
              : "";
          if (name) symbols.push({ name, value: n_value.toString(16), type: n_type });
        }
        void strsize;
      }
      cmdOffset += cmdSize;
    }

    return {
      is64: is64Final,
      littleEndian: le,
      cputype,
      filetype,
      ncmds,
      sections,
      symbols,
      dylibs,
      entrypoint,
      parseGaps,
    };
  };

  return readHeader(base);
};
