import { access, constants as fsConstants } from "node:fs/promises";
import { lstat, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { pathRejected } from "../errors/errors.js";

export interface PathGuardOptions {
  /** Absolute directories an operator explicitly allowed for target registration. */
  allowedRoots?: string[];
  /** Optional max path length guard (defense in depth). */
  maxPathLength?: number;
}

export interface ResolvedPath {
  /** Canonical absolute path after realpath resolution. */
  canonicalPath: string;
  originalPath: string;
  sizeBytes: number;
  isDirectory: boolean;
}

/**
 * Canonical path validation used at target admission:
 *  - rejects NUL bytes, empty and non-absolute (unless resolveWithin is used) paths
 *  - resolves symlinks via realpath and requires the result to stay inside an allowed root
 *  - rejects symlinked final components when `symlinkPolicy` is "reject"
 *
 * The guard never executes or writes to the target.
 */
export class PathGuard {
  private readonly allowedRoots: string[];
  private readonly maxPathLength: number;

  constructor(options: PathGuardOptions = {}) {
    this.allowedRoots = (options.allowedRoots ?? []).map((root) =>
      path.resolve(root),
    );
    this.maxPathLength = options.maxPathLength ?? 4096;
  }

  /** True when no explicit allowlist was configured (local single-operator mode). */
  get openMode(): boolean {
    return this.allowedRoots.length === 0;
  }

  private assertInsideAllowedRoots(canonicalPath: string): void {
    if (this.openMode) return;
    const inside = this.allowedRoots.some(
      (root) =>
        canonicalPath === root || canonicalPath.startsWith(root + path.sep),
    );
    if (!inside) {
      throw pathRejected(
        "Path is outside the configured allowed roots.",
        "Move the artifact under one of the allowed roots or add the root to VESTIGE_ALLOWED_ROOTS.",
        { allowedRoots: this.allowedRoots.length },
      );
    }
  }

  /**
   * Admit a path for read-only registration. Returns canonical path and
   * basic stat facts. Throws VestigeError (`path_rejected`) on any policy
   * violation, traversal attempt, or non-regular/non-directory target.
   */
  async admit(
    rawPath: string,
    symlinkPolicy: "reject" | "resolve" = "resolve",
  ): Promise<ResolvedPath> {
    if (rawPath.length === 0 || rawPath.includes("\0")) {
      throw pathRejected(
        "Path must be non-empty and contain no NUL bytes.",
        "Provide a plain filesystem path.",
      );
    }
    if (rawPath.length > this.maxPathLength) {
      throw pathRejected(
        `Path exceeds maximum length (${String(this.maxPathLength)}).`,
        "Shorten the path or move the artifact.",
      );
    }

    const absolute = path.resolve(rawPath);

    // Stat the final component WITHOUT following symlinks to detect them.
    let lstats;
    try {
      lstats = await lstat(absolute);
    } catch {
      throw pathRejected(
        "Path does not exist or is not accessible to the current user.",
        "Verify the path and permissions, then register the target again.",
        { path: rawPath },
      );
    }
    const isSymlink = lstats.isSymbolicLink();
    if (isSymlink && symlinkPolicy === "reject") {
      throw pathRejected(
        "Symlinked targets are rejected by policy.",
        "Register the real file location instead.",
      );
    }

    let canonicalPath: string;
    try {
      canonicalPath = await realpath(absolute);
    } catch {
      throw pathRejected(
        "Path could not be canonicalized (broken symlink or permission issue).",
        "Verify the target exists and is readable.",
      );
    }

    this.assertInsideAllowedRoots(canonicalPath);

    let stats;
    try {
      stats = await stat(canonicalPath);
    } catch {
      throw pathRejected(
        "Canonical target is not accessible.",
        "Verify file permissions; Vestige only needs read access.",
      );
    }
    const isDirectory = stats.isDirectory();
    if (!isDirectory && !stats.isFile()) {
      throw pathRejected(
        "Only regular files and directories may be registered (no FIFOs, sockets, or devices).",
        "Point Vestige at a regular file or a directory.",
      );
    }

    // Readable check (read-only admission).
    try {
      await access(canonicalPath, fsConstants.R_OK);
    } catch {
      throw pathRejected(
        "Target is not readable by the current user.",
        "Grant read permission or run under an account with read access.",
      );
    }

    return {
      canonicalPath,
      originalPath: rawPath,
      sizeBytes: stats.size,
      isDirectory,
    };
  }

  /**
   * Resolve a child path that must remain within a parent directory
   * (used when reading directory-type targets). Rejects traversal outside.
   */
  resolveWithin(parentCanonical: string, childRelative: string): string {
    if (childRelative.includes("\0")) {
      throw pathRejected("Path contains NUL bytes.", "Provide a plain path.");
    }
    const joined = path.resolve(parentCanonical, childRelative);
    const inside =
      joined === parentCanonical ||
      joined.startsWith(parentCanonical + path.sep);
    if (!inside) {
      throw pathRejected(
        "Path escapes the registered target directory.",
        "Request paths inside the target only.",
        { path: childRelative },
      );
    }
    return joined;
  }
}
