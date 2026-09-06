# Direction-B R2 proof — live run steps

Proves ONE service (R2 bucket provisioning) runs through the agency's OWN Cloudflare
Worker with the agency's OWN credentials, driven by a signed job from the platform — as
if the platform had no direct R2 access. The platform R2 token is never used on this path.

Chain: **orchestrator** (originates) → **app** (ed25519-signs the job; private key stays
app-side) → **agency Worker** `/actuate` (verifies signature + freshness + op, then creates
the bucket with the agency's `R2_PROVISION_API_TOKEN`).

Branch (all three repos): `feat/direction-b-r2-proof`.

## Prereqs

- The target agency = an `Account` that has completed (or started) onboarding, so it has a
  Direction-B keypair: `Account.signingKeyPublic` (SPKI PEM) set and the matching private
  key in `AccountSecret`. The keypair is generated at the first onboarding step
  (`generateAgencyOAuthClientAction` → `ensureAgencySigningKey`). Use Jason's own agency
  account. If `signingKeyPublic` is null, click "Generate OAuth client" once in `/onboarding`
  (or call `ensureAgencySigningKey(accountId)`).
- `Account.orchestratorUrl` = the deployed agency Worker base URL (public https).
- The agency Worker already has its onboarding secrets set, including
  `R2_PROVISION_API_TOKEN` (account-owned CF token with Workers R2 Storage: Edit).

## 1. Read the account's public key + Worker URL (app DB)

The public key is a text/PEM column. Read it and the account id from the app DB
(`DATABASE_URL`, the cp-db). SQL:

```sql
SELECT id, name, orchestratorUrl, signingKeyPublic FROM Account
WHERE name LIKE '%<your agency>%';
```

Keep `id` (the `<accountId>` for the trigger) and copy `signingKeyPublic` verbatim (the full
`-----BEGIN PUBLIC KEY----- … -----END PUBLIC KEY-----` block).

## 2. Set the new Worker secret

New secret this proof adds: **`DY_SIGNING_PUBLIC_KEY`** = the account's `signingKeyPublic`.
It is the ONLY new secret; everything else is already set from onboarding.

```sh
# from agency-orchestrator.doubleyoup.com/, logged into the AGENCY's Cloudflare account
# (wrangler login). Pipe the PEM in so newlines are preserved:
printf '%s' "$SIGNING_KEY_PUBLIC_PEM" | wrangler secret put DY_SIGNING_PUBLIC_KEY
# or from a file:  wrangler secret put DY_SIGNING_PUBLIC_KEY < account-public.pem
```

(The Worker strips all whitespace before base64-decoding, so a single-line or wrapped PEM
both work — only the base64 body between the armor matters.)

## 3. Deploy the three changes

- **Agency Worker** (this repo): `npm install && npm run deploy` (adds `POST /actuate`).
- **app**: deploy the branch (adds `POST /internal/agency/dispatch/provision-r2`) via the
  normal app deploy. No DB migration — no schema change.
- **orchestrator**: deploy the branch (adds `src/agency-dispatch.ts` + the
  `proof:agency-r2` script). No new env vars; it reuses `APP_BASE_URL` + the service token.

## 4. Trigger the proof

From `orchestrator.doubleyoup.com/`, with the orchestrator env loaded (so it can auth to
app: `APP_BASE_URL` + `SERVICE_SIGNING_KEY`/`SERVICE_TOKEN_SECRET`):

```sh
# accountId REQUIRED; bucket name defaults to a throwaway dy-agency-proof-<random>
npm run proof:agency-r2 -- <accountId>
# or pin the bucket name:
npm run proof:agency-r2 -- <accountId> dy-agency-proof-live1
```

Success prints:
`SUCCESS — bucket "dy-agency-proof-…" created in the agency account (<cfAccountId>).`

## 5. Verify

**Bucket exists in the AGENCY's R2 account** (names only — no data):

```sh
# in the agency's Cloudflare account
wrangler r2 bucket list        # look for dy-agency-proof-…
# or CF API with the agency's R2 token:
curl -s -H "authorization: Bearer $R2_PROVISION_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/<cfAccountId>/r2/buckets" | jq '.result[].name'
```

**Platform R2 token untouched** — the platform token
(`orchestrator` `R2_PROVISION_API_TOKEN` / `config.r2.provisionApiToken`) is never read on
this path. Confirm by:
- The bucket appears in the **agency's** account, not the platform account
  (`wrangler r2 bucket list` in the platform account does NOT show it).
- Optionally `grep` the run: the only Cloudflare calls come from the Worker
  (`/accounts?per_page=1` + `/r2/buckets`), authenticated with the Worker's own token; the
  orchestrator makes zero Cloudflare calls (it only calls app + the Worker).

## Cleanup (reversible)

```sh
# in the agency account
wrangler r2 bucket delete dy-agency-proof-…
```

## Negative sanity checks (optional, prove fail-closed)

- POST `/actuate` with a wrong/absent signature → HTTP 401, no bucket created.
- Re-run the same bucket name → `already-existed` (idempotent), still ok.

## Notes / possible blockers

- If `Account.signingKeyPublic` is null → the app endpoint returns a 400 ("no Direction-B
  signing key — complete onboarding first"). Fix: generate the key (see Prereqs).
- If the agency's `R2_PROVISION_API_TOKEN` lacks Workers R2 Storage: Edit → the Worker
  returns `ok:false` with a clear CF denial detail (no platform fallback). This proof only
  needs bucket-CREATE scope (it does NOT mint scoped keys — that stays deferred, H1).
- Replay protection here is the ±120s timestamp window only; a true single-use nonce needs a
  shared edge store (KV/D1/DO) and is noted as future hardening in `src/dispatch-verify.ts`.
