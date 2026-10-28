import { mkdir, rm, mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

/**
 * Isolated workspace for all files Vestige derives (reports, provider scratch).
 * Original artifacts are never written to; generated content lives here.
 */
export class Workspace {
  private readonly created: string[] = [];

  constructor(private readonly rootDir: string) {}

  static async create(rootDir?: string): Promise<Workspace> {
    const root = rootDir ?? path.join(os.tmpdir(), "vestige-work");
    await mkdir(root, { recursive: true });
    return new Workspace(root);
  }

  get root(): string {
    return this.rootDir;
  }

  /** Create a fresh scratch directory owned by one operation. */
  async scratch(prefix: string): Promise<string> {
    const dir = await mkdtemp(path.join(this.rootDir, `${prefix}-`));
    this.created.push(dir);
    return dir;
  }

  async ensureDir(relative: string): Promise<string> {
    const dir = path.resolve(this.rootDir, relative);
    if (!dir.startsWith(path.resolve(this.rootDir) + path.sep) && dir !== path.resolve(this.rootDir)) {
      throw new Error("workspace path escapes root");
    }
    await mkdir(dir, { recursive: true });
    return dir;
  }

  /** Remove scratch directories created through this workspace (idempotent). */
  async cleanup(): Promise<void> {
    const dirs = [...this.created];
    this.created.length = 0;
    await Promise.allSettled(
      dirs.map((dir) =>
        rm(dir, { recursive: true, force: true, maxRetries: 2, retryDelay: 50 }),
      ),
    );
  }
}
