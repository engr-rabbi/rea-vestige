import { mkdir, readFile, writeFile, rename } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { artifactSchema, type Artifact } from "../domain/artifact.js";
import { sha256Artifact } from "../util/hash.js";
import { PathGuard, type ResolvedPath } from "../security/pathGuard.js";
import { pathRejected } from "../errors/errors.js";
import { invalidInput } from "../errors/errors.js";

const registryFileSchema = z.object({
  version: z.literal(1),
  targets: z.array(artifactSchema),
});

/**
 * Target registry: explicit, opt-in registration of artifacts the operator
 * is authorized to analyze. Persists as canonical JSON with atomic rename.
 * Registration is read-only with respect to the artifact itself.
 */
export class TargetRegistry {
  private readonly filePath: string;
  private readonly guard: PathGuard;
  private cache: Map<string, Artifact> | undefined;

  constructor(
    dataDir: string,
    guardOptions?: { allowedRoots?: string[] },
  ) {
    this.filePath = path.join(dataDir, "registry", "targets.json");
    this.guard = new PathGuard({ allowedRoots: guardOptions?.allowedRoots });
  }

  get pathGuard(): PathGuard {
    return this.guard;
  }

  private async load(): Promise<Map<string, Artifact>> {
    if (this.cache) return this.cache;
    let raw = "";
    try {
      raw = await readFile(this.filePath, "utf8");
    } catch {
      /* first run */
    }
    let parsed: z.infer<typeof registryFileSchema>;
    try {
      const doc = raw.trim() ? JSON.parse(raw) : { version: 1, targets: [] };
      parsed = registryFileSchema.parse(doc);
    } catch (err) {
      throw invalidInput(
        "Target registry file is corrupt.",
        "Back it up and remove targets.json to start fresh; re-register targets.",
        { file: this.filePath, cause: String(err) },
      );
    }
    this.cache = new Map(parsed.targets.map((t) => [t.artifactId, t]));
    return this.cache;
  }

  private async persist(map: Map<string, Artifact>): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    const body = JSON.stringify(
      { version: 1, targets: [...map.values()] },
      null,
      2,
    );
    const tmp = `${this.filePath}.tmp`;
    await writeFile(tmp, body, "utf8");
    await rename(tmp, this.filePath);
  }

  /**
   * Register a target: canonicalize + hash + classify. Never modifies the
   * artifact. Re-registering an identical path+content returns the existing
   * record (stable artifactId derived from SHA-256 and path).
   */
  async register(
    rawPath: string,
    label?: string,
    signal?: AbortSignal,
  ): Promise<{ artifact: Artifact; created: boolean; resolved: ResolvedPath }> {
    const resolved = await this.guard.admit(rawPath);
    const sha256 = await sha256Artifact(resolved.canonicalPath, resolved.isDirectory, signal);
    const format = await import("../domain/format.js").then((m) =>
      m.probeFormatHead(resolved.canonicalPath, resolved.isDirectory),
    );
    const artifactId = `va_${sha256.slice(0, 16)}`;
    const map = await this.load();
    const existing = map.get(artifactId);
    if (existing && existing.path === resolved.canonicalPath) {
      return { artifact: existing, created: false, resolved };
    }
    const artifact: Artifact = {
      artifactId,
      label: label?.trim() || undefined,
      path: resolved.canonicalPath,
      sha256,
      sizeBytes: resolved.sizeBytes,
      format: format.format,
      architecture: format.architecture,
      registeredAt: new Date().toISOString(),
    };
    artifactSchema.parse(artifact);
    map.set(artifactId, artifact);
    await this.persist(map);
    return { artifact, created: true, resolved };
  }

  async list(): Promise<Artifact[]> {
    const map = await this.load();
    return [...map.values()].sort((a, b) =>
      a.registeredAt < b.registeredAt ? -1 : 1,
    );
  }

  async get(artifactId: string): Promise<Artifact | undefined> {
    const map = await this.load();
    return map.get(artifactId);
  }

  /** Require a registered target by id; throws target_not_registered otherwise. */
  async require(artifactId: string): Promise<Artifact> {
    const found = await this.get(artifactId);
    if (!found) {
      throw pathRejected(
        `No registered target with id '${artifactId}'.`,
        "Register the target first via vestige_register_target (CLI: vestige register <path>).",
        { artifactId },
      );
    }
    return found;
  }
}
