// The Worker's runtime bindings — plain `[vars]` (public config) and secrets
// (set with `wrangler secret put`, NEVER committed). Everything an agency
// connects during onboarding lands here as a Cloudflare secret in THEIR own
// account; this Worker never persists a credential anywhere else.
//
// Optional-marked fields are the agency service credentials: a validator for a
// credential that isn't set reports a clear "not configured" result rather than
// throwing, so an agency can bring services online one at a time and watch each
// go green.
export interface Env {
  // ── Public config (wrangler.toml [vars]) ──────────────────────────────────
  // Our control-plane app base URL, e.g. "https://app.doubleyoup.com".
  APP_BASE_URL: string;

  // ── Direction-A OAuth2 client credentials (secrets) ───────────────────────
  // Issued by our app at onboarding. Exchanged for a short-lived access token
  // (client_credentials grant) that authenticates this Worker's calls back to us.
  DY_CLIENT_ID: string;
  DY_CLIENT_SECRET: string;

  // ── Direction-B signed-dispatch verification (secret) ─────────────────────
  // The agency's OWN ed25519 PUBLIC key (SPKI PEM) — the public half of the
  // per-account keypair our app generated at onboarding (Account.signingKeyPublic).
  // Used ONLY to verify the signature on inbound POST /actuate jobs: the platform
  // (orchestrator) hands this Worker a job signed with the matching PRIVATE key,
  // which never leaves our app. Set with `wrangler secret put DY_SIGNING_PUBLIC_KEY`
  // (value = the account's signingKeyPublic). Unset => /actuate fails closed
  // (verification is impossible, so nothing is actuated).
  DY_SIGNING_PUBLIC_KEY?: string;

  // ── Agency service credentials (secrets) ──────────────────────────────────
  // Google Cloud service-account key — the entire downloaded JSON as one string.
  GCP_SERVICE_ACCOUNT_KEY?: string;

  // S3 (or any S3-compatible store, e.g. R2 via S3_ENDPOINT).
  S3_ACCESS_KEY_ID?: string;
  S3_SECRET_ACCESS_KEY?: string;
  S3_REGION?: string;
  S3_BUCKET?: string;
  // Optional: a custom S3 endpoint (R2 / MinIO / Wasabi …). When set the
  // validator uses path-style addressing against it; when unset it targets AWS.
  S3_ENDPOINT?: string;

  // Stripe secret key (the agency's own account — used for the subscription).
  STRIPE_SECRET_KEY?: string;

  // Cloudflare ACCOUNT-owned custom API token (created under Manage Account →
  // Account API Tokens in the agency's own account — NOT My Profile → API
  // Tokens, which fails) with "Workers R2 Storage: Edit" + "Account API
  // Tokens: Edit" — used by the platform to create per-site R2 media buckets
  // and mint per-site scoped keys in the agency's account. High-privilege:
  // set only as a Worker secret, never in wrangler.toml [vars].
  R2_PROVISION_API_TOKEN?: string;

  // AI provider keys.
  ANTHROPIC_API_KEY?: string;
  OPENROUTER_API_KEY?: string;
  // OpenAI — also authenticates Codex (same key, same account).
  OPENAI_API_KEY?: string;
}
