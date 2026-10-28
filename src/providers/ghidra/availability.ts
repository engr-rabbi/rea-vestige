import { access, constants } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Availability } from "../types.js";

export interface GhidraInstallation {
  installDir: string;
  analyzeHeadlessPath: string;
  platform: "posix" | "windows";
}

const COMMON_LOCATIONS = (platform: string): string[] => {
  const candidates: string[] = [];
  if (platform === "win32") {
    candidates.push("C:\\ghidra", "C:\\Program Files\\ghidra");
  } else {
    candidates.push("/opt/ghidra", "/usr/local/ghidra", "/usr/share/ghidra");
    candidates.push(path.join(os.homedir(), "ghidra"));
    candidates.push(path.join(os.homedir(), "opt", "ghidra"));
  }
  return candidates;
};

/** Find analyzeHeadless under an install dir (top-level or one level deep). */
export const findAnalyzeHeadless = async (
  installDir: string,
  platform: string,
): Promise<string | undefined> => {
  const scriptName = platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless";
  const direct = path.join(installDir, "support", scriptName);
  try {
    await access(direct, constants.X_OK | constants.R_OK);
    return direct;
  } catch {
    /* fall through */
  }
  // One level deep (e.g. <dir>/ghidra_11.x_PUBLIC/support/analyzeHeadless)
  try {
    const entries = await (await import("node:fs/promises")).readdir(installDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const nested = path.join(installDir, entry.name, "support", scriptName);
      try {
        await access(nested, constants.X_OK | constants.R_OK);
        return nested;
      } catch {
        continue;
      }
    }
  } catch {
    /* unreadable dir */
  }
  return undefined;
};

/**
 * Detect a usable Ghidra installation (env var first, then common locations).
 * Returns actionable guidance when unavailable — never a hard requirement.
 */
export const detectGhidraInstallation = async (
  envInstallDir?: string,
  platform: string = process.platform,
): Promise<Availability & { installation?: GhidraInstallation }> => {
  const scriptName = platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless";
  const candidates: string[] = [];
  if (envInstallDir) candidates.push(envInstallDir);
  candidates.push(...COMMON_LOCATIONS(platform));

  for (const dir of candidates) {
    const script = await findAnalyzeHeadless(dir, platform);
    if (script) {
      return {
        available: true,
        detail: `Ghidra detected at ${dir}`,
        installation: {
          installDir: dir,
          analyzeHeadlessPath: script,
          platform: platform === "win32" ? "windows" : "posix",
        },
      };
    }
  }
  return {
    available: false,
    reason: envInstallDir
      ? `GHIDRA_INSTALL_DIR='${envInstallDir}' does not contain support/${scriptName}.`
      : "No Ghidra installation found (searched GHIDRA_INSTALL_DIR and common locations).",
    guidance:
      "Install Ghidra from https://ghidra-sre.org/ (free, official releases) and set GHIDRA_INSTALL_DIR to the directory containing support/analyzeHeadless. Java 21+ is required. The native provider (ELF/PE/Mach-O) remains available without Ghidra.",
  };
};
