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

  // ── Direction-B replay protection (Durable Object binding) ────────────────
  // The single-use nonce store that makes a signed /actuate job actuatable at
  // most once (see src/nonce-store.ts). Declared in wrangler.toml and auto-
  // provisioned by `wrangler deploy` in whichever account runs it — it needs
  // NO per-account id, preserving the identical-config-per-agency model. Durable
  // Objects require the Workers Paid plan on the deploying account.
  NONCE_STORE: DurableObjectNamespace<import("./nonce-store.js").NonceStore>;

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
  // Probed read-only by /validate (validators.ts::validateGCP), and used by the
  // Direction-B `gcp-*` actuators (src/actuate.ts: gcp-instance-create,
  // gcp-network-create, gcp-firewall-create, gcp-address-create,
  // gcp-router-nat-create, the gcp-*-get/list reads, the gcp-*-delete teardown
  // ops, and the planning/47 update ops gcp-instance-set-metadata /
  // gcp-instance-restart) to mint a FULL
  // cloud-platform-scoped token and create Compute Engine resources in the
  // agency's own project (every op is pinned to the key's own project_id). The
  // key never leaves this Worker; only the short-lived token it mints reaches
  // Google, in an Authorization header.
  GCP_SERVICE_ACCOUNT_KEY?: string;

  // S3 (or any S3-compatible store, e.g. R2 via S3_ENDPOINT). Probed by /validate's
  // write probe, and used by the Direction-B `db-export` actuator to PRESIGN a
  // single-object PUT URL the agency's cell uploads a DB dump to — the credential
  // itself never leaves this Worker (only the derived, short-lived URL reaches the cell).
  // ONE deliberate exception (planning/47): `gcp-instance-set-metadata` substitutes
  // these values into a cell node's startup script in place of the fixed
  // `@@DY_T1_S3_BUCKET@@` / `@@DY_T2_S3_*@@` placeholders, so the node's backup runners
  // can write to the agency's own store. The values go ONLY into that node's instance
  // metadata in the agency's own GCP project — never back to the platform, which never
  // holds them.
  S3_ACCESS_KEY_ID?: string;
  S3_SECRET_ACCESS_KEY?: string;
  S3_REGION?: string;
  S3_BUCKET?: string;
  // Optional: a custom S3 endpoint (R2 / MinIO / Wasabi …). When set the
  // validator uses path-style addressing against it; when unset it targets AWS.
  S3_ENDPOINT?: string;
  // Optional (hub#64): a SECOND bucket, used by Tier-1 (restic) only. Tier-1 and Tier-2
  // want opposite things from a bucket — restic needs DELETE (it removes its own per-run
  // lock object, and `forget`/`prune` retention is implemented entirely by deleting),
  // while Tier-2 is a write-once full whose whole purpose is to survive a compromised
  // credential and therefore wants a retention/lock policy. UNSET falls back to S3_BUCKET,
  // which is the pre-hub#64 behaviour (both tiers in one bucket); set it to an UNLOCKED
  // bucket to split them. Same credential either way: S3_ACCESS_KEY_ID /
  // S3_SECRET_ACCESS_KEY / S3_REGION / S3_ENDPOINT cover both buckets.
  // It is the bucket NAME, not a URL. Setting it to the "S3 API" URL the R2 dashboard
  // shows has happened on a live Worker; gcp-instance-set-metadata now refuses that
  // shape rather than splicing a URL into the node's backup repository path.
  S3_BACKUP_BUCKET?: string;

  // Stripe secret key (the agency's own account — used for the subscription).
  STRIPE_SECRET_KEY?: string;

  // Cloudflare ACCOUNT-owned custom API token (created under Manage Account →
  // Account API Tokens in the agency's own account — NOT My Profile → API
  // Tokens, which fails) with "Workers R2 Storage: Edit" + "Account API
  // Tokens: Edit" — used by the platform to create per-site R2 media buckets
  // and mint per-site scoped keys in the agency's account. High-privilege:
  // set only as a Worker secret, never in wrangler.toml [vars].
  R2_PROVISION_API_TOKEN?: string;

  // Cloudflare API token for the agency's OWN zones — Zone:DNS:Edit + Zone:Read +
  // Zone:Cache Purge + Zone → Cache Rules: Edit + "Zone WAF Write" (Zone → WAF → Edit in the
  // token editor) on the zone(s) the platform may manage.
  // Used by the Direction-B actuators (src/actuate.ts): `dns-record-upsert` (create/update
  // DNS records), `cache-purge` (purge a zone's cache), `cache-rule-upsert` (the "edge page
  // cache" Cache Rules) and `waf-rule-upsert` (the edge-defense WAF baseline + the Cloudflare
  // Managed Ruleset), all through this Worker, so the platform never needs
  // direct access to the agency's Cloudflare zones. Also probed read-only by /validate
  // (validators.ts::validateCfDns, including Cache Rules and WAF read probes); the edit + purge
  // scopes are exercised for real on first use. Set only as a Worker secret, never in [vars].
  CF_DNS_API_TOKEN?: string;

  // ── Direction-B cell-agent access (secrets) ───────────────────────────────
  // The agency's OWN on-VM cell-agent — the base URL of the cell-agent this
  // agency runs (e.g. "https://cell-syd.doubleyoup.com") and its bearer token.
  // Used ONLY by the Direction-B cell actuators (src/actuate.ts): `wp-cli` POSTs a
  // shell-quoted `wp <args>` command and `db-export` POSTs a DB-export-and-upload
  // script, both to `${CELL_AGENT_URL}/exec` with `Authorization: Bearer
  // ${CELL_AGENT_TOKEN}` — the agency's own cell credential, never a platform
  // credential. If EITHER is missing the actuator returns a clean ok:false and
  // makes no call. Set only as Worker secrets, never in wrangler.toml [vars].
  //
  // v1 LIMITATION: single-cell (one agency cell). A multi-cell agency needs
  // per-cell resolution (a cell selector + a map of URL/token pairs) before
  // these ops can target more than one cell.
  CELL_AGENT_URL?: string;
  CELL_AGENT_TOKEN?: string;

  // AI provider keys.
  ANTHROPIC_API_KEY?: string;
  OPENROUTER_API_KEY?: string;
  // OpenAI — also authenticates Codex (same key, same account).
  OPENAI_API_KEY?: string;
}
