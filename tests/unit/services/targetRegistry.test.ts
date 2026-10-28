import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { TargetRegistry } from "../../../src/services/targetRegistry.js";

describe("TargetRegistry", () => {
  let dataDir: string;
  let targetDir: string;
  let registry: TargetRegistry;

  beforeEach(async () => {
    dataDir = await mkdtemp(path.join(os.tmpdir(), "vestige-reg-"));
    targetDir = await mkdtemp(path.join(os.tmpdir(), "vestige-tgt-"));
    registry = new TargetRegistry(dataDir);
  });

  afterEach(async () => {
    await rm(dataDir, { recursive: true, force: true });
    await rm(targetDir, { recursive: true, force: true });
  });

  it("registers a file target with sha256 and format", async () => {
    const file = path.join(targetDir, "sample.js");
    await writeFile(file, "import x from 'y';\nexport default x;\n");
    const { artifact, created } = await registry.register(file);
    expect(created).toBe(true);
    expect(artifact.format).toBe("javascript");
    expect(artifact.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(artifact.artifactId).toBe(`va_${artifact.sha256.slice(0, 16)}`);
  });

  it("is idempotent for identical path+content", async () => {
    const file = path.join(targetDir, "same.txt");
    await writeFile(file, "same");
    const first = await registry.register(file);
    const second = await registry.register(file);
    expect(first.created).toBe(true);
    expect(second.created).toBe(false);
    expect(second.artifact.artifactId).toBe(first.artifact.artifactId);
  });

  it("lists and retrieves targets", async () => {
    const f1 = path.join(targetDir, "a.txt");
    const f2 = path.join(targetDir, "b.txt");
    await writeFile(f1, "a");
    await writeFile(f2, "b");
    await registry.register(f1);
    await registry.register(f2);
    const all = await registry.list();
    expect(all).toHaveLength(2);
    const one = await registry.get(all[0]?.artifactId ?? "");
    expect(one).toBeTruthy();
  });

  it("require() throws a typed error for unknown ids", async () => {
    await expect(registry.require("va_missing00000000")).rejects.toMatchObject({
      payload: { code: "path_rejected" },
    });
  });

  it("persists across instances", async () => {
    const file = path.join(targetDir, "persist.txt");
    await writeFile(file, "persist");
    const { artifact } = await registry.register(file);
    const second = new TargetRegistry(dataDir);
    const found = await second.get(artifact.artifactId);
    expect(found?.path).toBe(artifact.path);
  });

  it("registers directories", async () => {
    await mkdir(path.join(targetDir, "proj"), { recursive: true });
    const { artifact } = await registry.register(path.join(targetDir, "proj"));
    expect(artifact.format).toBe("directory");
  });

  it("rejects unreadable/unauthorized paths via guard", async () => {
    await expect(registry.register("/definitely/not/a/real/path/xyz")).rejects.toMatchObject({
      payload: { code: "path_rejected" },
    });
  });
});
