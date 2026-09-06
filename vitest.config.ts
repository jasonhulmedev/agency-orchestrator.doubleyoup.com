import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { fileURLToPath } from "node:url";

// Absolute path to the Node-only stub for the "cloudflare:workers" built-in (see below).
const cloudflareWorkersStub = fileURLToPath(
  new URL("./test/stubs/cloudflare-workers.ts", import.meta.url),
);

// Two projects, run in one `vitest` invocation:
//
//  • "node"    — the pre-existing pure-unit + validator/app-client/routing tests. They mock
//                `fetch` with vi.spyOn and never touch the Durable Object, so they stay on
//                the fast Node runtime exactly as before. Because they import the Worker
//                entry (which now transitively imports the workerd built-in
//                "cloudflare:workers"), the Node project aliases that module to a stub — the
//                DO is never instantiated here.
//
//  • "workers" — the NEW tests that must run under the REAL workerd runtime: the NonceStore
//                Durable Object (SQLite storage), the /actuate replay end-to-end, and edge
//                ed25519 crypto. Bindings + the DO SQLite migration come from wrangler.toml.
export default defineConfig({
  test: {
    projects: [
      {
        resolve: {
          alias: {
            "cloudflare:workers": cloudflareWorkersStub,
          },
        },
        test: {
          name: "node",
          environment: "node",
          include: [
            "test/validators.test.ts",
            "test/app-client.test.ts",
            "test/index.test.ts",
            "test/dispatch.test.ts",
          ],
        },
      },
      {
        plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.toml" } })],
        test: {
          name: "workers",
          include: ["test/**/*.worker.test.ts"],
        },
      },
    ],
  },
});
