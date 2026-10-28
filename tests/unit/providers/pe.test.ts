import { describe, expect, it } from "vitest";
import { parsePe } from "../../../src/providers/native/pe.js";
import { buildPe64, PE64_GROUND_TRUTH } from "../../fixtures/builders.js";

describe("PE parser (fixture ground truth)", () => {
  it("parses header facts", () => {
    const info = parsePe(buildPe64());
    expect(info.machineName).toBe("x86-64");
    expect(info.isPe32Plus).toBe(true);
    expect(info.subsystemName).toBe("windows-cui");
    expect(info.entryRva).toBe("1000");
  });

  it("extracts sections", () => {
    const info = parsePe(buildPe64());
    const names = info.sections.map((s) => s.name);
    expect(names).toEqual([".text", ".rdata"]);
  });

  it("extracts exactly the known exports (ground truth)", () => {
    const info = parsePe(buildPe64());
    const names = info.exports.map((e) => e.name).sort();
    expect(names).toEqual([...PE64_GROUND_TRUTH.exports].sort());
  });

  it("extracts the import dll and its functions", () => {
    const info = parsePe(buildPe64());
    expect(info.imports).toHaveLength(1);
    expect(info.imports[0]?.dll).toBe(PE64_GROUND_TRUTH.imports.dll);
    expect(info.imports[0]?.imports.sort()).toEqual(
      [...PE64_GROUND_TRUTH.imports.functions].sort(),
    );
  });

  it("rejects non-PE buffers", () => {
    expect(() => parsePe(Buffer.from("\u007fELF"))).toThrow();
  });
});
