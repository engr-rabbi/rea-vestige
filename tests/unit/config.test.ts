import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config/config.js";

describe("config", () => {
  it("applies documented defaults", () => {
    const config = loadConfig({});
    expect(config.logLevel).toBe("info");
    expect(config.maxToolOutputBytes).toBe(4_194_304);
    expect(config.http.host).toBe("127.0.0.1");
    expect(config.allowedRoots).toEqual([]);
  });

  it("respects environment overrides", () => {
    const config = loadConfig({
      VESTIGE_LOG_LEVEL: "debug",
      VESTIGE_TOOL_TIMEOUT_MS: "5000",
      VESTIGE_DATA_DIR: "/tmp/vestige-data",
    });
    expect(config.logLevel).toBe("debug");
    expect(config.toolTimeoutMs).toBe(5000);
    expect(config.dataDir).toBe("/tmp/vestige-data");
  });

  it("rejects invalid values with actionable errors (no value echo)", () => {
    expect(() =>
      loadConfig({ VESTIGE_LOG_LEVEL: "loud" as never }),
    ).toThrow(/VESTIGE_LOG_LEVEL/);
  });

  it("refuses non-loopback HTTP binds without a token", () => {
    expect(() =>
      loadConfig({ VESTIGE_HTTP_HOST: "0.0.0.0" }),
    ).toThrow(/VESTIGE_HTTP_TOKEN/);
  });

  it("accepts non-loopback binds with a token", () => {
    const config = loadConfig({
      VESTIGE_HTTP_HOST: "0.0.0.0",
      VESTIGE_HTTP_TOKEN: "test-token-value",
    });
    expect(config.http.token).toBe("test-token-value");
  });

  it("parses allowed roots and origins lists", () => {
    const config = loadConfig({
      VESTIGE_ALLOWED_ROOTS: "/a,/b",
      VESTIGE_HTTP_ALLOWED_ORIGINS: "https://x.example,https://y.example",
    });
    expect(config.allowedRoots).toEqual(["/a", "/b"]);
    expect(config.http.allowedOrigins).toEqual(["https://x.example", "https://y.example"]);
  });
});
