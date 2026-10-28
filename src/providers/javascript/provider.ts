import { stat } from "node:fs/promises";
import type {
  AnalysisProvider,
  AnalyzeRequest,
  Availability,
  CapabilityDescriptor,
  ProviderDescriptor,
  ProviderResult,
} from "../types.js";
import { analyzeJavaScript, JS_PROVIDER } from "./analyze.js";

/**
 * Static JavaScript / TypeScript / Electron analyzer.
 * In-process (acorn AST), read-only, no execution of the target.
 */
export class JavaScriptProvider implements AnalysisProvider {
  readonly descriptor: ProviderDescriptor = {
    ...JS_PROVIDER,
    formats: ["javascript", "directory"],
    summary:
      "AST-based static analysis for JavaScript/TypeScript sources: modules, imports/exports, Electron IPC channels, and express-style routes.",
  };

  capabilities(): CapabilityDescriptor[] {
    return [
      {
        operation: "module-graph",
        description:
          "Enumerate JS files and their ESM imports, CJS requires, dynamic imports, and exports.",
        limitations: [
          "Computed/aliased module specifiers are not resolved.",
          "node_modules and common build outputs are excluded from scans.",
        ],
        requiresExternalTool: false,
      },
      {
        operation: "electron-ipc",
        description:
          "Detect ipcMain/ipcRenderer channel usage (handle/on/once, invoke/send/sendSync) with literal channel names.",
        limitations: [
          "Only direct ipcMain/ipcRenderer identifier callees are admitted; re-exports and wrappers are not followed.",
          "Channel names built dynamically are reported as parse gaps, not resolved values.",
        ],
        requiresExternalTool: false,
      },
      {
        operation: "route-inventory",
        description:
          "Inventory express-style routes (app.get/post/put/delete/patch/all/use with literal string paths).",
        limitations: [
          "Framework-specific registration APIs other than the express-style pattern are not recognized.",
        ],
        requiresExternalTool: false,
      },
    ];
  }

  async checkAvailability(): Promise<Availability> {
    return { available: true, detail: "in-process acorn parser" };
  }

  supports(artifact: { format: string }): boolean {
    return artifact.format === "javascript" || artifact.format === "directory";
  }

  async analyze(request: AnalyzeRequest): Promise<ProviderResult> {
    // Validate the path still exists and is file/dir before scanning.
    const st = await stat(request.artifactPath);
    if (!st.isFile() && !st.isDirectory()) {
      throw new Error("target is neither file nor directory");
    }
    return analyzeJavaScript(request);
  }
}
