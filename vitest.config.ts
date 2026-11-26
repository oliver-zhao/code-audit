import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/**/test/**/*.test.ts"],
    environment: "node",
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // The CLI integration tests spawn child processes and write run directories.
    pool: "forks",
    fileParallelism: false,
    // Strip the real external tools from PATH so unit tests stay hermetic; the
    // real-tool test file re-adds .tools/bin explicitly.
    setupFiles: ["./packages/core/test/setup.ts"],
  },
});
