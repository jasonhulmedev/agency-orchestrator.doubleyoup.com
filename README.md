# agency-orchestrator.doubleyoup.com

The **agency-side glue** for the doubleyoup agency-cloud pivot — a Cloudflare
Worker that each agency deploys into **their own** Cloudflare account (pulled
from our GitHub, so we never need write access to their account).

This is thin, always-on glue. It does **not** run heavy jobs. The platform
orchestrator runs the long jobs and sends this Worker one signed job per action.
The Worker acts with the agency's own credentials.

## Scope

The Worker does three things.

1. It validates each service credential the agency connected (Google Cloud, S3,
   Stripe, R2 provisioning, Cloudflare DNS and the AI provider keys) with a
   **real authenticated call** to each provider, returning a specific,
   actionable error for anything that's wrong.
2. It talks back to our control-plane app over **Direction-A OAuth2** (a
   short-lived access token minted from the agency's client credentials) to
   prove the round-trip and signal onboarding complete.
3. It runs signed Direction-B jobs (`POST /actuate`). With these jobs it builds
   and tears down the agency's cell in the agency's own Google Cloud project. It
   also manages DNS, tunnels, cache, WAF, custom hostnames, Workers routes, R2
   media, the branded-media `HOSTMAP`, the edge session gate and Cloud Run
   services in the agency's own accounts.

## How the credentials live

Every credential is a **Cloudflare secret in the agency's own account**. This
Worker never persists them anywhere else and we never hold them. See
`wrangler.toml` (header comment) and `.dev.vars.example` for the full list.

| Name | Type | Purpose |
| --- | --- | --- |
| `APP_BASE_URL` | var | our control-plane app base, e.g. `https://app.doubleyoup.com` |
| `DY_CLIENT_ID` / `DY_CLIENT_SECRET` | secrets | Direction-A OAuth2 client credentials issued by our app at onboarding. This Worker sends `DY_CLIENT_SECRET` to our app's `/oauth/token` on every token exchange, so our app sees it in transit (it stores only a hash). `DY_CLIENT_SECRET` is also the root of your session gate's minter caller key. That key stops the OTHER scripts in your Cloudflare account from minting session ID tokens; it does not hide anything from our app. **After you change `DY_CLIENT_SECRET`, have the platform deploy the gate of each of your cells at once** (orchestrator: `npm run cell-session-path -- gate --cell <cell> --apply`): until then, every session on that cell answers 503. `/validate` reports whether each deployed gate carries the current key (`cfDns.workersScope.gateCallerKeys`) |
| `GCP_SERVICE_ACCOUNT_KEY` | secret | the entire Google Cloud service-account JSON |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` / `S3_REGION` / `S3_BUCKET` | secrets | object-store (backup) credentials — **Cloudflare R2 recommended**, or AWS S3 (region defaults to `us-east-1`; use `auto` for R2) |
| `S3_BACKUP_BUCKET` | secret (optional) | a SECOND bucket, used by **Tier-1 (restic) only**. Leave it unset and both backup tiers share `S3_BUCKET` (the existing behaviour). Set it when `S3_BUCKET` carries an object-lock / retention policy: restic needs **delete** (it removes its own per-run lock object, and `forget`/`prune` retention is implemented entirely by deleting), so point this at an **unlocked** bucket. Same credential covers both buckets |
| `S3_ENDPOINT` | secret (optional) | set for Cloudflare R2 (recommended) or another S3-compatible store (MinIO/Wasabi); uses path-style addressing. When set, `/validate` proves the credential can actually **write** the bucket with an object **PUT** probe (no bucket list, best-effort deleted after), so a normally-scoped R2 Object Read&Write key — which is denied bucket-level `ListObjectsV2` — still validates green, while a read-only key or a non-S3 endpoint is correctly caught |
| `STRIPE_SECRET_KEY` | secret | the agency's Stripe secret key |
| `R2_PROVISION_API_TOKEN` | secret | Cloudflare **account-owned** token (Manage Account → Account API Tokens in their account) with Workers R2 Storage: Edit + Account API Tokens: Edit — creates per-site media buckets + mints per-site keys. Must NOT be a My Profile → API Tokens (user) token — those fail the account-scoped check |
| `CF_DNS_API_TOKEN` | secret | Cloudflare API token with **Zone:DNS:Edit + Zone:Read + Zone:Cache Purge + Zone → Cache Rules: Edit + "Zone WAF Write"** (the WAF permission is listed as Zone → WAF → Edit in the API-token editor) on the agency zone(s) the platform may manage — used by the Direction-B `dns-record-upsert` (create/update DNS records; an optional `expect` guard refuses the write when the record changed since the app's preview; a guarded write holds a short lease on its zone + type + name in the existing `NONCE_STORE` Durable Object, so two confirmed changes to one record cannot overwrite each other), `dns-record-get` (read-only: the records at one name, for the app's preview diff and its check after a change), `cache-purge` (purge a zone's cache), `cache-rule-upsert` (the "edge page cache" Cache Rules for the zone's WordPress sites — its `*-production.<zone>` routing hosts plus the customer domains onboarded onto the zone as Cloudflare-for-SaaS custom hostnames, never the zone apex, your other in-zone hosts or a `media.*` host — the Worker builds the rules itself; the platform sends only a host suffix, a TTL and on/off) and `waf-rule-upsert` (the edge-defense baseline: five WAF custom rules — block RU/CN/KP, block the WordPress admin/login surface from outside AU/US/GB/NZ/FR/IE, managed-challenge the rest of the login surface, managed-challenge the front end from outside that list except verified search crawlers, your zone's infrastructure hosts and `*-media.<zone>` hosts, and skip the Managed Ruleset for every request to your cell-agent hosts — plus, only when the operator asks for it, the Cloudflare Managed Ruleset on a Pro or higher zone, touching only the execute rule this Worker created (a rollback disables it, never deletes it); it refuses, changing nothing, when your zone's plan has no room for the rules) actuators (`POST /actuate`) so the platform manages your zones **through this Worker**, never with direct access. Both rule ops build their rules in this Worker — the platform never sends an expression, an action or a country list (for `waf-rule-upsert` it sends only hosts inside your zone, which the Worker checks). `/validate` probes it read-only (zone list, plus a Cache Rules read probe and a WAF read probe); the edit + purge scopes are exercised on first use For branded media (hub#133) the same token also needs **Zone → SSL and Certificates → Edit** (the custom hostname), **Zone → Workers Routes → Edit** (the media route) and **Account → Workers KV Storage → Edit** (the `HOSTMAP` entry); `/validate` probes each read-only and names every missing one in `cfDns.brandedMedia` (advisory: it does not turn `cfDns` red). See [Branded media ops](#branded-media-ops) |
| `CF_CUSTOM_HOSTNAME_ZONE` | secret | hub#46 customer domains: the NAME of the agency zone that holds your customers' Cloudflare-for-SaaS custom hostnames (e.g. `example.com`, the zone of your `host.` CNAME target). The `custom-hostname-upsert` / `-get` / `-delete` ops act on this zone only; a signed job names a hostname, never a zone. They use `CF_DNS_API_TOKEN`, which then also needs **Zone → SSL and Certificates → Edit** on this zone. Set it as a secret (not a plain variable) so a redeploy keeps it. `/validate` reports, read-only, whether the token can read the zone's custom hostnames and which fallback origin the zone has (`cfDns.customHostnames`) |
| `MEDIA_WORKER_SCRIPT` | var (optional) | hub#133: the script name of your media Worker. `worker-route-upsert` points every media route at this script; a signed job can never name a script. Default `doubleyoup-media` |
| `MEDIA_ACCOUNT_ID` | var (optional) | hub#133: the Cloudflare account id (32 hex characters) of your media Worker and its `HOSTMAP` namespace. The `media-hostmap-*` ops and the `/validate` KV probe use only this account. Unset: they use the ONLY account `CF_DNS_API_TOKEN` sees; a token that sees two or more accounts is refused, never guessed. Set it when one token covers zones of several accounts |
| `MEDIA_HOSTMAP_KV_ID` | var (optional) | hub#133: the id (32 hex characters) of the Workers KV namespace your media Worker binds as `HOSTMAP`. The `media-hostmap-*` ops write only to this namespace. Unset: the Worker uses the namespace titled `HOSTMAP` in the media account (`/validate` reports `hostmapNamespace: found` or `missing`) |
| `DY_WORKER_NAME` | secret | this Worker's own script name, as the Cloudflare dashboard shows it (e.g. `my-agency-orchestrator`). It can differ from `name` in your fork's `wrangler.toml`. The `edge-gate-deploy` op binds your cell's session gate to this Worker's `SessionGateMinter` entrypoint by this name, and refuses while it is unset. Not secret, but set it as a secret so a redeploy keeps it. `/validate` reports whether it is set (`cfDns.workersScope.workerName`) |
| `ANTHROPIC_API_KEY` / `OPENROUTER_API_KEY` / `OPENAI_API_KEY` | secrets | AI provider keys — set at least one (`OPENAI_API_KEY` also covers Codex) |
| `DY_SIGNING_PUBLIC_KEY` | secret | your account's ed25519 public key (SPKI PEM) from onboarding. `/actuate` checks each job with it. Unset, `/actuate` refuses every job |
| `CELL_AGENT_URL` / `CELL_AGENT_TOKEN` | secrets | your cell-agent base URL and bearer token. The `wp-cli`, `db-export` and `db-import` ops post to its `/exec` endpoint. The `provision-ssh-keys` op posts to its `/provision-ssh-keys` endpoint and needs the **gateway** cell-agent, not the web node. All four ops share this one pair, and it serves one cell only: on a cell where the web node and the gateway are separate machines, the pair reaches only one of them |
| `CELL_FILE_AGENT_URL` / `CELL_FILE_AGENT_TOKEN` | secrets (optional) | a fallback file-node agent for `r2-site-key-install`. A current job names its own agent, and the job's pair wins, so most agencies do not set them. Set both or neither |
| `R2_EXPECTED_ACCOUNT_ID` | var (optional) | the Cloudflare account id that `R2_PROVISION_API_TOKEN` must belong to. When set, the `r2-media-*` and `r2-site-key-*` ops refuse any other account |
| `MEDIA_SITE_SECRET` | secret | hub#222: at least 32 characters (for example `openssl rand -hex 32`). The root of every site's media credential for `POST /media/*`, see [Media soft delete](#media-soft-delete). Changing it invalidates every site's credential until `media-site-credential-install` runs again |

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
Builds**:

1. **Fork this repo into your own GitHub account** (the **Fork** button, top
   right). Cloudflare Workers Builds connects through the Cloudflare GitHub App,
   which you can only install on a repo you own — so you connect it to *your
   fork*, not to this upstream repo.
2. In the Cloudflare dashboard → **Workers & Pages** → **Create** → **Connect to
   Git**, pick **your fork**, and let Cloudflare build & deploy it. Every push to
   your fork's `main` re-deploys automatically. (`APP_BASE_URL` is already set in
   `wrangler.toml` and points at our app.)
3. Add your secrets via the onboarding wizard's instructions, then open the
   Worker's root URL and press **Check my setup** until every item is green.

### Keeping your Worker up to date

Your fork does **not** update on its own — it drifts behind this upstream repo
until you sync it, so you would miss our fixes and new capabilities. To pull the
latest: open your fork on GitHub, and on the `main` branch use **Sync fork →
Update branch**. That fast-forwards your fork to our latest `main`, which triggers
your Workers Build to redeploy. Your Cloudflare **secrets live on the Worker, not
in the repo**, so a sync never touches them. Re-run **Check my setup** afterwards.

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
wrangler secret put S3_BACKUP_BUCKET          # optional — Tier-1's own UNLOCKED bucket; unset = same as S3_BUCKET
wrangler secret put S3_ENDPOINT               # optional — only for R2/MinIO/Wasabi
wrangler secret put STRIPE_SECRET_KEY
wrangler secret put R2_PROVISION_API_TOKEN  # ACCOUNT-owned token (Manage Account -> Account API Tokens): Workers R2 Storage: Edit + Account API Tokens: Edit
wrangler secret put ANTHROPIC_API_KEY
wrangler secret put OPENROUTER_API_KEY
wrangler secret put OPENAI_API_KEY          # also covers Codex (same key/account)

# 3. Confirm APP_BASE_URL in wrangler.toml points at our app, then deploy
npm run deploy
```

## Endpoints

| Method + path | Purpose |
| --- | --- |
| `GET /` | thin landing page (HTML): intro, onboarding-wizard link, and a live **Check my setup** self-check button |
| `GET /health` | liveness — `{ok:true, service:"agency-orchestrator"}` |
| `POST /validate` | run every validator; returns `{ok, gcp, s3, stripe, ai, r2Provision, cfDns}`, each `{ok, detail}` |
| `GET /whoami` | exercise Direction-A end-to-end; returns `{ok, accountId}` |
| `POST /complete` | if all green, call our app's onboarding-complete route; returns `{ok, validation, callback}` |
| `POST /actuate` | runs one signed Direction-B job (ed25519 signature and a single-use nonce). Only the platform calls it |
| `POST /media/sign-put`, `/media/replace`, `/media/delete`, `/media/rename` | hub#222: the site-facing media API. Only a site's mu-plugin calls it, with its own credential (see [Media soft delete](#media-soft-delete)) |

> `POST /complete` re-validates and calls our app's `onboarding-complete` route
> (now live). It stays resilient — if that callback is ever unreachable it still
> validates and reports `callback.ok:false` rather than failing outright.

## Branded media ops

hub#133: the platform serves a site's media from a branded host, either
`<slug>-media.<your-zone>` or `media.<customer-domain>` (a Cloudflare-for-SaaS
custom hostname on your zone). It creates the three pieces in **your**
Cloudflare account through these signed `/actuate` ops, all with
`CF_DNS_API_TOKEN`. Every op checks the hostname grammar (lowercase FQDN, no
wildcard) and refuses an unknown param key.

| Op | Params | What it does |
| --- | --- | --- |
| `custom-hostname-upsert` | `{hostname, customOriginServer}` | hub#46. Creates the custom hostname on `CF_CUSTOM_HOSTNAME_ZONE`; `customOriginServer` must be inside that zone. Idempotent |
| `custom-hostname-get` | `{hostname, customOriginServer}` | hub#46, read only. Returns `status`, `sslStatus`, `customOriginServer` and `errors` (the status op) |
| `custom-hostname-delete` | `{hostname, customOriginServer}` | hub#46. A hostname that is already gone is `already-absent` (ok). All three hub#46 ops carry the same `{hostname, customOriginServer}` shape; `customOriginServer` must be inside `CF_CUSTOM_HOSTNAME_ZONE` |
| `worker-route-upsert` | `{zone, hostname, routeId?}` | Creates the route `<hostname>/*` → `MEDIA_WORKER_SCRIPT` in `zone` and returns its `routeId` (`created`). The zone is resolved with your token; the hostname must be in the zone or be a custom hostname of it. An existing route for the pattern is `unchanged` (with its `routeId`) when it points at the media Worker; a route to another script is refused (`foreign`), never repointed. A failed create (for example a race with another upsert) is `ok:false`; a re-run converges. Store the returned `routeId` and pass it back; without it the op lists the routes of your zone once |
| `worker-route-delete` | `{zone, hostname, routeId?}` | Deletes the route `<hostname>/*` only when it points at `MEDIA_WORKER_SCRIPT` (`deleted`). The route is read by its `routeId`; without one, or when it is stale (404), the op lists the routes of your zone once, so a replacement route is still found and deleted. No route for the pattern → `already-absent` (ok). A route to another script is refused (`foreign`). A `routeId` whose route has another pattern is refused. The delete never creates a route |
| `media-hostmap-upsert` | `{hostname, value}` | Writes `hostname → value` into the `HOSTMAP` namespace only. `value` must match `^[a-z0-9-]{1,46}$` (the media Worker's slug pattern) |
| `media-hostmap-delete` | `{hostname}` | Deletes the `HOSTMAP` entry. A 404 is `already-absent` (ok) |

There is no generic KV-write op and no op that routes to any other script.

## Media soft delete

hub#222: this Worker is the only writer of a site's R2 media bucket
(`doubleyoup-media-<prefix>`). The site holds no R2 key. Its mu-plugin calls
`POST /media/*` with a per-site credential, and every delete, rename and
overwrite first copies the old object to `trash/<UTC yyyy-mm-dd>/<key>`. A
bucket lock keeps `trash/` for 30 days; a lifecycle rule deletes it after 31.

Setup: add the secret `MEDIA_SITE_SECRET` (at least 32 characters, for example
`openssl rand -hex 32`). The routes and ops sign R2 requests with
`R2_PROVISION_API_TOKEN` (Cloudflare's S3 form of the token: its id and the
SHA-256 of its value), so that token must be set too. Changing
`MEDIA_SITE_SECRET` invalidates every site's credential until
`media-site-credential-install` runs again for each site.

**Site-facing routes.** `Authorization: Bearer <credential>`, where the
credential is `hex(HMAC-SHA256(MEDIA_SITE_SECRET, <bucket>))` (64 lowercase hex
characters, compared in constant time). Every body names the site's `bucket`.
A key must be under `<prefix>/`, never under `trash/` or `<prefix>/trash/`, and
never hold a `.` or `..` segment. Rate limit: 600 requests a minute per bucket
(answer 429 with `Retry-After`), counted after the credential check.

| Route | Body | What it does |
| --- | --- | --- |
| `/media/sign-put` | `{bucket, key, contentType, contentLength}` | Returns `upload: {method, url, headers, expiresAt}`: a presigned PUT, valid 10 minutes, that signs `if-none-match: *`, the content type and the length. Send exactly those headers. R2 answers 412 when the key exists, so a site can create but never overwrite |
| `/media/replace` | `{bucket, key, contentType, contentLength}` | Moves the current object to trash, deletes it, then returns a create-once `upload` for the key. No current object: `previous: "already-absent"` |
| `/media/delete` | `{bucket, key}` | Moves the object to trash, then deletes it. Missing: `status: "already-absent"` (ok) |
| `/media/rename` | `{bucket, from, to}` | Copies `from` to `to` (409 when `to` holds another revision, also one uploaded during the rename), moves `from` to trash, deletes `from`. Missing `from`: `already-absent` (ok) |

Each route is safe to retry. A trash copy keeps the metadata
(`x-amz-metadata-directive: COPY`) and is taken only while the source still has
the ETag the Worker read (`x-amz-copy-source-if-match`); an object that changes
in between is not deleted (409). Every Worker copy is create-once in R2
(`cf-copy-destination-if-none-match: *`), so a copy never replaces an object.
A revision is the ETag and the metadata: when the same key goes to trash twice
in one day as another revision (other bytes, or the same bytes with another
content type), the second copy goes to `trash/<day>.<revision hash>/<key>`,
because the lock forbids overwriting the first.

R2's DeleteObject takes no condition. So delete, replace and rename take a
60-second lease on the key being deleted (Durable Object instance
`media-lease:<bucket>`): a second request for the same key answers 409 and the
site retries. The final DELETE starts only while the lease has room for it, and
the same Durable Object turn records it as pending. A DELETE that times out or
gets a 5xx may still land at R2 later, so its record outlives the lease: while
the key still holds the revision that DELETE targeted, delete, replace and
rename of that key answer 409 (and nothing can re-create the key, because every
write is create-once). Once the key is absent or holds another revision, the
old DELETE has landed and the key is free. A record older than one hour is
dropped, and the Worker logs a warning with the bucket and the key. A DELETE
that R2 applies later than one hour is an accepted remaining risk: it is
smaller than the per-site R2 key with Object Read & Write that this replaces.
A trash copy counts only when R2 answers with a complete
`CopyObjectResult`; an unreadable, empty or cut-off answer fails the request
and nothing is deleted.

**Signed ops.**

| Op | Params | What it does |
| --- | --- | --- |
| `media-bucket-protect` | `{bucket}` | Lifecycle rule `doubleyoup-trash-expire` (delete `trash/` after 31 days) and bucket lock `doubleyoup-trash-lock` (`trash/`, 30 days). Keeps every other rule. A re-run writes nothing (`unchanged`) |
| `media-site-credential-install` | `{slug, bucket, workerUrl, fileAgentUrl?, fileAgentToken?}` | Derives the site credential and posts it with `workerUrl` to the file-node cell-agent `/update-r2-config` (Worker mode), which writes `DOUBLEYOUP_MEDIA_WORKER_URL` and `DOUBLEYOUP_MEDIA_SITE_TOKEN` and removes `DOUBLEYOUP_R2_KEY` and `DOUBLEYOUP_R2_SECRET`. The answer never carries the credential. Idempotent |
| `media-site-key-revoke` | `{slug, bucket, tokenId}` | Deletes the site's old R2 key, only when its name shows `r2-site-key-install` minted it for this bucket. Missing: `already-absent` |
| `media-trash-list` | `{bucket, prefix?, cursor?}` | One page (up to 1000) of `trash/<prefix>` objects: `entries` and `cursor` (null on the last page) |
| `media-restore` | `{bucket, trashKey, targetKey?}` | Copies a trash object back (default target: the key without `trash/<day>/`). A target with other bytes is refused (`code: 409`); with the same bytes it is `already-restored` |
| `media-bulk-credential` | `{bucket, prefix, ttlSeconds}` | An R2 temporary credential (object-read-write) for one bucket and one prefix under `<prefix>/`, 60 to 43200 seconds, for a bulk offload engine. The one op whose answer carries a credential |

`npm run proof:media` proves the R2 behaviour this relies on against a scratch
bucket: see [PROOF-MEDIA.md](PROOF-MEDIA.md).

## Local dev

```
cp .dev.vars.example .dev.vars   # fill in real values (git-ignored)
npm run dev                      # wrangler dev
npm test                         # vitest — validators, token exchange, signed dispatch and the op families (mocked fetch), plus the nonce store and session gate under workerd
npm run typecheck                # tsc --noEmit
```

## What this Worker is (and isn't)

- It's a **Cloudflare Worker** (`wrangler dev` / `wrangler deploy`), not a Node
  service — no server process, no queue, no database.
- Worker-native only: **`fetch` + Web Crypto** (`crypto.subtle`). No AWS/GCP
  SDKs. The SigV4 signer (S3) and the RS256 JWT-bearer mint (GCP) are
  hand-rolled against Web Crypto.
- The Direction-B signed handshake (our app → this Worker) is **live**: `POST
  /actuate` verifies an ed25519 signature + a single-use nonce before running any
  op in `DISPATCH_OP_REGISTRY` (`src/ops.ts`). The ops cover R2 media, DNS,
  cache, WAF, custom hostnames, Cloudflare tunnels, Workers routes and the
  branded-media `HOSTMAP`, the edge session gate, `wp-cli`, SSH keys and DB
  export/import on the cell, and the cell's Google Cloud resources (instances,
  networks, subnets, firewalls, addresses, routers and NAT, snapshots, quota and
  Cloud Run). `/validate`
  and `/complete` stay agency-triggered.
