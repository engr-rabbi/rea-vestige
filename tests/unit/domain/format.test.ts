import { describe, expect, it } from "vitest";
import { probeFormat, probeFormatHead } from "../../../src/domain/format.js";
import { buildElf64, buildPe64, buildMacho64 } from "../../fixtures/builders.js";
import { writeFixture } from "../../fixtures/builders.js";
import os from "node:os";
import path from "node:path";

describe("format probing", () => {
  it("identifies ELF by magic and architecture", () => {
    const probe = probeFormat(buildElf64());
    expect(probe.format).toBe("elf");
    expect(probe.architecture).toContain("x86-64");
    expect(probe.architecture).toContain("64-bit");
  });

  it("identifies PE by MZ", () => {
    expect(probeFormat(buildPe64()).format).toBe("pe");
  });

  it("identifies Mach-O by magic", () => {
    expect(probeFormat(buildMacho64()).format).toBe("macho");
  });

  it("identifies JavaScript source heuristics", () => {
    expect(probeFormat(Buffer.from("import x from 'y';\n")).format).toBe("javascript");
    expect(probeFormat(Buffer.from("#!/usr/bin/env node\nrequire('fs');")).format).toBe("javascript");
    expect(probeFormat(Buffer.from('{"json": true}')).format).toBe("json");
    expect(probeFormat(Buffer.from([0, 1, 2, 3, 4])).format).toBe("unknown");
  });

  it("probes a real file from disk", async () => {
    const dir = path.join(os.tmpdir(), `vestige-fmt-${Date.now()}`);
    const file = writeFixture(dir, "sample.elf", buildElf64());
    const probe = await probeFormatHead(file, false);
    expect(probe.format).toBe("elf");
  });
});
