import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    testTimeout: 30_000,
    // E2E spawns the real server; give it headroom.
    hookTimeout: 60_000,
    // Fail-fast disabled: full signal preferred in CI runs.
    bail: 0,
  },
});
