import { defineConfig } from "vitest/config";

// Plain Node environment: the validators and app client use only `fetch` and
// Web Crypto (`crypto.subtle`), both native in the Node version this repo runs
// on, so tests mock `fetch` and exercise the real signing/crypto code without
// needing the heavier Workers test pool.
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
