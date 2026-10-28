import { describe, expect, it } from "vitest";
import { redactText, createLogger } from "../../../src/util/log.js";

describe("central redaction", () => {
  it("redacts bearer tokens", () => {
    expect(redactText("Authorization: Bearer abc123secret")).not.toContain("abc123secret");
  });

  it("redacts key=value secrets", () => {
    expect(redactText("password=hunter2")).not.toContain("hunter2");
    expect(redactText("api_key=abcd1234")).not.toContain("abcd1234");
  });

  it("leaves benign text untouched", () => {
    expect(redactText("analyzed 42 symbols in /usr/bin/ls")).toBe(
      "analyzed 42 symbols in /usr/bin/ls",
    );
  });

  it("logger writes JSON lines to stderr with redaction", () => {
    const lines: string[] = [];
    const fake = { write: (s: string): void => void lines.push(s) } as unknown as NodeJS.WritableStream;
    const log = createLogger("info", fake);
    log.warn("token=supersecret", { detail: "password=hunter2" });
    expect(lines).toHaveLength(1);
    const line = lines[0] ?? "";
    expect(line).not.toContain("supersecret");
    expect(line).not.toContain("hunter2");
    expect(JSON.parse(line).level).toBe("warn");
  });

  it("respects log level thresholds", () => {
    const lines: string[] = [];
    const fake = { write: (s: string): void => void lines.push(s) } as unknown as NodeJS.WritableStream;
    const log = createLogger("error", fake);
    log.info("hidden");
    log.error("shown");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("shown");
  });
});
