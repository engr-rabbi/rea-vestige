import type {
  AnalysisProvider,
  AnalyzeRequest,
  Availability,
  CapabilityDescriptor,
  ProviderDescriptor,
  ProviderResult,
} from "../types.js";
import { NATIVE_PROVIDER } from "./analyze.js";
import { analyzeNative } from "./analyze.js";

/**
 * Native binary analyzer (ELF / PE / Mach-O) implemented with pure
 * TypeScript byte parsing — deterministic, in-process, read-only.
 */
export class NativeProvider implements AnalysisProvider {
  readonly descriptor: ProviderDescriptor = {
    ...NATIVE_PROVIDER,
    formats: ["elf", "pe", "macho"],
    summary:
      "In-process structural analysis of ELF, PE, and Mach-O binaries: headers, sections, symbols, exports/imports, linked libraries, and strings.",
  };

  capabilities(): CapabilityDescriptor[] {
    return [
      {
        operation: "header-inspection",
        description:
          "Parse ELF/PE/Mach-O headers, section tables, and program/container facts.",
        limitations: [
          "Reads at most the first 64 MiB of very large files.",
        ],
        requiresExternalTool: false,
      },
      {
        operation: "extract-symbols",
        description:
          "Enumerate symbols/functions from ELF .symtab/.dynsym and Mach-O LC_SYMTAB; PE exports from the export directory.",
        limitations: [
          "No disassembly or decompilation (pair with the Ghidra provider for that).",
          "Symbol tables capped at 20,000 entries per table.",
        ],
        requiresExternalTool: false,
      },
      {
        operation: "imports-exports",
        description:
          "PE import/export directories and Mach-O linked dylibs.",
        limitations: ["Ordinal-only PE imports are recorded as ordinals, not names."],
        requiresExternalTool: false,
      },
      {
        operation: "extract-strings",
        description:
          "Extract printable ASCII strings with file offsets (bounded to 1,000).",
        limitations: ["ASCII-only; UTF-16 strings are not extracted in this release."],
        requiresExternalTool: false,
      },
    ];
  }

  async checkAvailability(): Promise<Availability> {
    return { available: true, detail: "in-process parsers" };
  }

  supports(artifact: { format: string }): boolean {
    return ["elf", "pe", "macho"].includes(artifact.format);
  }

  async analyze(request: AnalyzeRequest): Promise<ProviderResult> {
    return analyzeNative(request);
  }
}
