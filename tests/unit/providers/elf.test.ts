import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseElf } from "../../../src/providers/native/elf.js";
import { buildElf64, ELF64_GROUND_TRUTH, writeFixture } from "../../fixtures/builders.js";

describe("ELF parser (fixture ground truth)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(path.join(os.tmpdir(), "vestige-elf-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it("parses header facts", () => {
    const info = parseElf(buildElf64());
    expect(info.is64).toBe(true);
    expect(info.littleEndian).toBe(true);
    expect(info.machineName).toBe("x86-64");
    expect(info.typeName).toBe("exec");
    expect(info.entry).toBe("401000");
  });

  it("extracts exactly the known symbols (ground truth)", () => {
    const info = parseElf(buildElf64());
    const names = info.symbols.map((s) => s.name).sort();
    expect(names).toEqual(ELF64_GROUND_TRUTH.symbols.map((s) => s.name).sort());
  });

  it("classifies symbol types and binds correctly", () => {
    const info = parseElf(buildElf64());
    for (const expected of ELF64_GROUND_TRUTH.symbols) {
      const sym = info.symbols.find((s) => s.name === expected.name);
      expect(sym, expected.name).toBeTruthy();
      expect(sym?.type).toBe(expected.type);
      expect(sym?.bind).toBe(expected.bind);
      expect(sym?.size).toBe(expected.size);
      expect(sym?.value).toBe(expected.value.toString(16));
    }
  });

  it("extracts the program interpreter", () => {
    const info = parseElf(buildElf64());
    expect(info.interpreter).toBe(ELF64_GROUND_TRUTH.interpreter);
  });

  it("lists sections including .text and .symtab", () => {
    const info = parseElf(buildElf64());
    const names = info.sections.map((s) => s.name);
    expect(names).toContain(".text");
    expect(names).toContain(".symtab");
    expect(names).toContain(".strtab");
  });

  it("parses a file from disk identically", async () => {
    const file = writeFixture(tmp, "sample.elf", buildElf64());
    const { readFileSync } = await import("node:fs");
    const info = parseElf(readFileSync(file));
    expect(info.symbols.map((s) => s.name).sort()).toEqual(
      ELF64_GROUND_TRUTH.symbols.map((s) => s.name).sort(),
    );
  });

  it("rejects non-ELF buffers", () => {
    expect(() => parseElf(Buffer.from("MZ not an elf"))).toThrow();
  });
});
