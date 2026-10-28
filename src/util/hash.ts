import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";

/**
 * Stable JSON canonicalization (RFC 8785 subset):
 * object keys sorted lexicographically, no insignificant whitespace.
 */
export const canonicalJsonString = (value: unknown): string => {
  const walk = (node: unknown): unknown => {
    if (node === null || node === undefined) return null;
    if (Array.isArray(node)) return node.map(walk);
    if (typeof node === "object") {
      const entries = Object.entries(node as Record<string, unknown>)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return Object.fromEntries(entries.map(([k, v]) => [k, walk(v)]));
    }
    return node;
  };
  return JSON.stringify(walk(value));
};

export const sha256Hex = (data: Buffer | string): string =>
  createHash("sha256").update(data).digest("hex");

/** Stream a file's SHA-256 without loading it fully into memory. */
export const sha256File = async (
  filePath: string,
  signal?: AbortSignal,
): Promise<string> => {
  const hash = createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(filePath);
    const onAbort = (): void => {
      stream.destroy();
      reject(new Error("hashing cancelled"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    stream.on("data", (chunk: string | Buffer) => hash.update(chunk));
    stream.on("error", (err) => {
      signal?.removeEventListener("abort", onAbort);
      reject(err);
    });
    stream.on("end", () => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    });
  });
  return hash.digest("hex");
};

/** Bounded directory identity: sorted rel paths + per-file SHA-256 + sizes. */
export const sha256Directory = async (
  dirPath: string,
  options: { maxFiles?: number; maxFileBytes?: number } = {},
  signal?: AbortSignal,
): Promise<string> => {
  const { readdir, stat } = await import("node:fs/promises");
  const maxFiles = options.maxFiles ?? 2_000;
  const maxFileBytes = options.maxFileBytes ?? 1_048_576;
  const skip = new Set(["node_modules", ".git", "dist", "build", "out", ".next", "coverage", "vendor"]);
  const entries: string[] = [];
  const walk = async (dir: string, rel: string): Promise<void> => {
    if (entries.length >= maxFiles || signal?.aborted) return;
    let list;
    try {
      list = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of list.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (entries.length >= maxFiles) return;
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (!skip.has(e.name)) await walk(`${dir}/${e.name}`, childRel);
        continue;
      }
      if (!e.isFile()) continue;
      let size = 0;
      try {
        size = (await stat(`${dir}/${e.name}`)).size;
      } catch {
        continue;
      }
      const digest =
        size <= maxFileBytes ? await sha256File(`${dir}/${e.name}`, signal) : "oversized";
      entries.push(`${childRel}:${String(size)}:${digest}`);
    }
  };
  await walk(dirPath, "");
  return sha256Hex(canonicalJsonString({ version: 1, entries }));
};

/** Hash a file or directory identity (read-only). */
export const sha256Artifact = async (
  filePath: string,
  isDirectory: boolean,
  signal?: AbortSignal,
): Promise<string> =>
  isDirectory
    ? sha256Directory(filePath, undefined, signal)
    : sha256File(filePath, signal);

/** Short content-derived identifier with a type prefix, e.g. `ve_ab12…`. */
export const contentId = (prefix: string, content: string): string => {
  const digest = sha256Hex(content);
  return `${prefix}_${digest.slice(0, 24)}`;
};

/** Random identifier with a type prefix (for jobs and other non-content entities). */
export const randomId = (prefix: string): string =>
  `${prefix}_${randomUUID().replaceAll("-", "").slice(0, 20)}`;
