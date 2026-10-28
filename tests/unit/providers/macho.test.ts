import { describe, expect, it } from "vitest";
import { parseMacho } from "../../../src/providers/native/macho.js";
import { buildMacho64, MACHO64_GROUND_TRUTH } from "../../fixtures/builders.js";

describe("Mach-O parser (fixture ground truth)", () => {
  it("parses header facts", () => {
    const info = parseMacho(buildMacho64());
    expect(info.is64).toBe(true);
    expect(info.littleEndian).toBe(true);
    expect(info.filetype).toBe(2);
    expect(info.ncmds).toBe(3);
  });

  it("extracts sections with segments (ground truth)", () => {
    const info = parseMacho(buildMacho64());
    const pairs = info.sections.map((s) => `${s.segment},${s.name}`);
    expect(pairs).toEqual(
      MACHO64_GROUND_TRUTH.sections.map((s) => `${s.segment},${s.name}`),
    );
  });

  it("extracts exactly the known symbols", () => {
    const info = parseMacho(buildMacho64());
    const names = info.symbols.map((s) => s.name).sort();
    expect(names).toEqual(MACHO64_GROUND_TRUTH.symbols.map((s) => s.name).sort());
    for (const expected of MACHO64_GROUND_TRUTH.symbols) {
      const sym = info.symbols.find((s) => s.name === expected.name);
      expect(sym?.value).toBe(expected.value.toString(16));
    }
  });

  it("extracts linked dylibs", () => {
    const info = parseMacho(buildMacho64());
    expect(info.dylibs.map((d) => d.name)).toContain(MACHO64_GROUND_TRUTH.dylib);
  });

  it("rejects tiny buffers", () => {
    expect(() => parseMacho(Buffer.from("MZ"))).toThrow();
  });
});
