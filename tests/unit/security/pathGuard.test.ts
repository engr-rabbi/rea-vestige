import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, symlink, mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PathGuard } from "../../../src/security/pathGuard.js";

describe("PathGuard", () => {
  let tmp: string;
  let guard: PathGuard;

  beforeEach(async () => {
    tmp = await mkdtemp(path.join(os.tmpdir(), "vestige-guard-"));
    guard = new PathGuard();
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it("admits a regular file and canonicalizes it", async () => {
    const file = path.join(tmp, "sample.bin");
    await writeFile(file, "hello");
    const resolved = await guard.admit(file);
    expect(resolved.canonicalPath).toBe(path.resolve(file));
    expect(resolved.sizeBytes).toBe(5);
    expect(resolved.isDirectory).toBe(false);
  });

  it("rejects non-existent paths", async () => {
    await expect(guard.admit(path.join(tmp, "missing.bin"))).rejects.toMatchObject({
      payload: { code: "path_rejected" },
    });
  });

  it("rejects NUL bytes and empty paths", async () => {
    await expect(guard.admit("bad\0path")).rejects.toMatchObject({ payload: { code: "path_rejected" } });
    await expect(guard.admit("")).rejects.toMatchObject({ payload: { code: "path_rejected" } });
  });

  it("resolves symlinks by default", async () => {
    const real = path.join(tmp, "real.bin");
    await writeFile(real, "x");
    const link = path.join(tmp, "link.bin");
    await symlink(real, link);
    const resolved = await guard.admit(link);
    expect(resolved.canonicalPath).toBe(path.resolve(real));
  });

  it("rejects symlinks under strict policy", async () => {
    const real = path.join(tmp, "real2.bin");
    await writeFile(real, "x");
    const link = path.join(tmp, "link2.bin");
    await symlink(real, link);
    await expect(guard.admit(link, "reject")).rejects.toMatchObject({
      payload: { code: "path_rejected" },
    });
  });

  it("enforces allowed roots", async () => {
    const allowed = path.join(tmp, "allowed");
    const forbidden = path.join(tmp, "forbidden");
    await mkdir(allowed);
    await mkdir(forbidden);
    const f1 = path.join(allowed, "a.bin");
    const f2 = path.join(forbidden, "b.bin");
    await writeFile(f1, "a");
    await writeFile(f2, "b");
    const strict = new PathGuard({ allowedRoots: [allowed] });
    await expect(strict.admit(f1)).resolves.toBeTruthy();
    await expect(strict.admit(f2)).rejects.toMatchObject({ payload: { code: "path_rejected" } });
  });

  it("rejects symlink escape out of allowed roots (resolved then checked)", async () => {
    const allowed = path.join(tmp, "allowed2");
    const outside = path.join(tmp, "outside2");
    await mkdir(allowed);
    await mkdir(outside);
    const inside = path.join(allowed, "link");
    await writeFile(path.join(outside, "secret.bin"), "s");
    await symlink(path.join(outside, "secret.bin"), inside);
    const strict = new PathGuard({ allowedRoots: [allowed] });
    await expect(strict.admit(inside)).rejects.toMatchObject({
      payload: { code: "path_rejected" },
    });
  });

  describe("resolveWithin", () => {
    it("allows children inside the parent", () => {
      const parent = path.resolve("/tmp/vestige-target");
      expect(guard.resolveWithin(parent, "sub/file.js")).toBe(path.join(parent, "sub/file.js"));
    });

    it("blocks ../ traversal outside the parent", () => {
      const parent = path.resolve("/tmp/vestige-target");
      expect(() => guard.resolveWithin(parent, "../../etc/passwd")).toThrow();
      // Backslash traversal only escapes on Windows; on POSIX it is a literal name.
      if (process.platform === "win32") {
        expect(() => guard.resolveWithin(parent, "..\\..\\windows")).toThrow();
      } else {
        expect(guard.resolveWithin(parent, "..\\..\\windows")).toBe(
          path.join(parent, "..\\..\\windows"),
        );
      }
    });

    it("blocks NUL injection", () => {
      expect(() => guard.resolveWithin("/tmp/x", "a\0b")).toThrow();
    });
  });
});
