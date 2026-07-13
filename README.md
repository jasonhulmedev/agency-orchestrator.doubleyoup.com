# agency-orchestrator.doubleyoup.com

The **agency-side glue** for the doubleyoup agency-cloud pivot — a Cloudflare
Worker that each agency deploys into **their own** Cloudflare account (pulled
from our GitHub, so we never need write access to their account).

This is thin, always-on glue: it does **not** run heavy jobs. In the full
design the long-running orchestration runs on a compute box in the agency's own
Google Cloud; the Worker just dispatches and makes light API calls.

## Phase 1 scope (this repo, today)

**Onboarding + credential self-validation only — NO infrastructure
provisioning.** The Worker:

1. Validates each service credential the agency connected (Google Cloud, S3,
   Stripe, and the AI provider keys) with a **real authenticated call** to each
   provider, returning a specific, actionable error for anything that's wrong.
2. Talks back to our control-plane app over **Direction-A OAuth2** (a
   short-lived access token minted from the agency's client credentials) to
   prove the round-trip and signal onboarding complete.

Provisioning, the inbound signed handshake (Direction B), the update pipeline,
and everything else come in later phases.

## How the credentials live

Every credential is a **Cloudflare secret in the agency's own account**. This
Worker never persists them anywhere else and we never hold them. See
`wrangler.toml` (header comment) and `.dev.vars.example` for the full list.

| Name | Type | Purpose |
| --- | --- | --- |
| `APP_BASE_URL` | var | our control-plane app base, e.g. `https://app.doubleyoup.com` |
| `DY_CLIENT_ID` / `DY_CLIENT_SECRET` | secrets | Direction-A OAuth2 client credentials issued by our app at onboarding |
| `GCP_SERVICE_ACCOUNT_KEY` | secret | the entire Google Cloud service-account JSON |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` / `S3_REGION` / `S3_BUCKET` | secrets | S3 credentials (region defaults to `us-east-1`) |
| `S3_ENDPOINT` | secret (optional) | set for an S3-compatible store (R2/MinIO/Wasabi); uses path-style addressing |
| `STRIPE_SECRET_KEY` | secret | the agency's Stripe secret key |
| `ANTHROPIC_API_KEY` / `OPENROUTER_API_KEY` | secrets | AI provider keys |

## Where setup instructions live

The full, step-by-step setup — how to generate each credential and add it as a
secret — lives in the **doubleyoup onboarding wizard** (in the app), not here, so
it stays one central, instantly-updatable source of truth. Open the app's
`/onboarding` and follow the wizard.

The Worker's own root URL (`GET /`) is a **thin landing page**: a short intro, a
link into the onboarding wizard, and one genuinely-standalone feature — a live
**Check my setup** self-check button that tests this Worker's own secrets without
needing an app login (it just calls `POST /validate` and shows a green ✓ / red ✗
per credential; secret values are never shown).

## Deploy (no terminal needed)

Deploy the Worker into **your** Cloudflare account via **Cloudflare Workers
Builds**: in the Cloudflare dashboard → **Workers & Pages** → **Create** →
**Connect to Git**, pick this repository, and let Cloudflare build & deploy it.
Every push to `main` re-deploys automatically. (`APP_BASE_URL` is already set in
`wrangler.toml` and points at our app.) Add your secrets via the onboarding
wizard's instructions, then open the Worker's root URL and press **Check my
setup** until every item is green.

## Onboarding flow

The onboarding wizard in the app drives this end to end. Under the hood the
Worker exposes three endpoints:

1. **Validate.** `POST /validate` returns `{ok, detail}` for every credential.
   The landing page's **Check my setup** button calls this and renders a green ✓
   / red ✗ per credential (never the secret values).
2. **Check the round-trip.** `GET /whoami` proves your Direction-A credentials
   work by resolving your account against our app.
3. **Complete.** `POST /complete` re-validates and, if everything is green,
   calls our app to flip your status to onboarded and unlock the product.

## Advanced / CLI alternative (`wrangler`)

Prefer the command line? You can deploy and set secrets with `wrangler` instead
of the dashboard. You need `wrangler` and a login to **your** Cloudflare account
(`wrangler login`).

```
# 1. Pull this repo and install
npm install

# 2. Set your secrets (one prompt each). At minimum the Direction-A pair plus
#    whichever services you're connecting:
wrangler secret put DY_CLIENT_ID
wrangler secret put DY_CLIENT_SECRET
wrangler secret put GCP_SERVICE_ACCOUNT_KEY   # paste the whole service-account JSON
wrangler secret put S3_ACCESS_KEY_ID
wrangler secret put S3_SECRET_ACCESS_KEY
wrangler secret put S3_REGION                 # e.g. us-east-1 (or "auto" for R2)
wrangler secret put S3_BUCKET
wrangler secret put S3_ENDPOINT               # optional — only for R2/MinIO/Wasabi
wrangler secret put STRIPE_SECRET_KEY
wrangler secret put ANTHROPIC_API_KEY
wrangler secret put OPENROUTER_API_KEY

# 3. Confirm APP_BASE_URL in wrangler.toml points at our app, then deploy
npm run deploy
```

## Endpoints

| Method + path | Purpose |
| --- | --- |
| `GET /` | thin landing page (HTML): intro, onboarding-wizard link, and a live **Check my setup** self-check button |
| `GET /health` | liveness — `{ok:true, service:"agency-orchestrator"}` |
| `POST /validate` | run every validator; returns `{ok, gcp, s3, stripe, ai}`, each `{ok, detail}` |
| `GET /whoami` | exercise Direction-A end-to-end; returns `{ok, accountId}` |
| `POST /complete` | if all green, call our app's onboarding-complete route; returns `{ok, validation, callback}` |

> `POST /complete` re-validates and calls our app's `onboarding-complete` route
> (now live). It stays resilient — if that callback is ever unreachable it still
> validates and reports `callback.ok:false` rather than failing outright.

## Local dev

```
cp .dev.vars.example .dev.vars   # fill in real values (git-ignored)
npm run dev                      # wrangler dev
npm test                         # vitest — token-exchange caching + every validator (mocked fetch)
npm run typecheck                # tsc --noEmit
```

## What this Worker is (and isn't)

- It's a **Cloudflare Worker** (`wrangler dev` / `wrangler deploy`), not a Node
  service — no server process, no queue, no database.
- Worker-native only: **`fetch` + Web Crypto** (`crypto.subtle`). No AWS/GCP
  SDKs. The SigV4 signer (S3) and the RS256 JWT-bearer mint (GCP) are
  hand-rolled against Web Crypto.
- Inbound requests are **not yet signature-verified**: in Phase 1 the agency
  triggers `/validate` and `/complete` themselves. The Direction-B signed
  handshake (our app → this Worker) is Phase 2.
