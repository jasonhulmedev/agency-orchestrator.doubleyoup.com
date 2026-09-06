// Node-only stub for the workerd built-in module "cloudflare:workers".
//
// The Node vitest project imports the Worker entry (src/index.ts), which transitively
// imports src/nonce-store.ts -> `import { DurableObject } from "cloudflare:workers"`. That
// module only exists inside workerd, so under plain Node it would fail to resolve. The Node
// project aliases "cloudflare:workers" to this file (see vitest.config.ts) purely so the
// module graph loads. The NonceStore DO is never INSTANTIATED under Node — the /actuate Node
// tests use a fake NONCE_STORE binding — so this base class only needs to exist, not work.
// The real DO behavior is exercised under the actual workerd runtime by the workers-pool
// project (test/nonce-store.worker.test.ts).
export class DurableObject<Env = unknown> {
  protected ctx: unknown;
  protected env: Env;
  constructor(ctx: unknown, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
