// Credential self-validation (pivot spec §4 step 5 / answers Q4).
//
// Each validator makes a REAL authenticated call to the provider and returns a
// specific, actionable {ok, detail}. The agency iterates on `/validate` in their
// own Cloudflare dashboard until every result is green — no round-trips back to
// us to debug. A credential that isn't configured yet returns a clear
// "not configured" result (ok:false) rather than throwing.
//
// Worker-native only: fetch + Web Crypto (crypto.subtle). No AWS/GCP SDKs.

import type { Env } from "./env.js";
import { signS3Request } from "./sigv4.js";
import { errorMessage, extractXmlTag, isWorkerScriptName, stripTrailingSlash } from "./util.js";
import { probeCustomHostnameScope, type CustomHostnameScopeReport } from "./actuate-custom-hostname.js";
import { cellRunServiceAccountFor } from "./dispatch-params.js";

export interface ValidationResult {
  ok: boolean;
  detail: string;
  /**
   * GCP only (planning/51): the update-path permissions testIamPermissions did NOT report at project
   * level. ADVISORY — it never changes `ok`. Absent for every other credential.
   */
  missingUpdatePermissions?: string[];
  /**
   * GCP only (planning/49 Phase 3): the Cloud Run permissions of the session ops that testIamPermissions
   * did NOT report at project level. ADVISORY — it never changes `ok`. Tested in a SEPARATE call; ABSENT
   * when that call failed (the advisory is then "unknown", and the detail says so).
   */
  missingSessionPermissions?: string[];
  /**
   * GCP only (planning/49 Phase 3): may the Worker's service account act as the session runtime identity
   * `dy-run@<project>`? Tested on that service account itself. ADVISORY — it never changes `ok`.
   */
  runServiceAccountActAs?: RunServiceAccountActAsState;
  /**
   * cfDns only (hub#46): can the token read the custom hostnames of CF_CUSTOM_HOSTNAME_ZONE, and does
   * that zone have a Cloudflare-for-SaaS fallback origin? ADVISORY — it never changes `ok`. Absent for
   * every other credential.
   */
  customHostnames?: CustomHostnameScopeReport;
  /**
   * cfDns only (planning/49 Phase 3): can the token READ Workers scripts on its account and Workers
   * routes on the zone it lists first? A read cannot prove the Edit scopes the edge gate needs.
   * ADVISORY — it never changes `ok`.
   */
  workersScope?: WorkersScopeReport;
}

/**
 * The actAs check on `dy-run@<project>`: held; denied (the account exists and the Worker does not hold
 * the permission on it); not-found (no such account); unknown (the check could not be made or Google
 * refused it without saying which).
 */
export type RunServiceAccountActAsState = "held" | "denied" | "not-found" | "unknown";

/** One Workers read probe: the read worked, Cloudflare refused it (401/403), or the probe was inconclusive. */
export type WorkersReadState = "read-ok" | "denied" | "unknown";

/** The two Workers read probes /validate makes with CF_DNS_API_TOKEN, and whether DY_WORKER_NAME is set. */
export interface WorkersScopeReport {
  scripts: WorkersReadState;
  routes: WorkersReadState;
  /**
   * planning/49 Phase 3 (I4): is DY_WORKER_NAME set? edge-gate-deploy binds the session gate to this Worker
   * by that name and refuses without it. A presence check only (the deploy checks that the script exists).
   */
  workerName: "set" | "unset";
}

export interface AllValidations {
  gcp: ValidationResult;
  s3: ValidationResult;
  stripe: ValidationResult;
  ai: ValidationResult;
  r2Provision: ValidationResult;
  cfDns: ValidationResult;
}

// ── S3 / object storage ────────────────────────────────────────────────────────

// The object-store credential (S3_*), resolved and defaulted from Env once so the
// two validation strategies below don't each re-derive it. `endpoint` is set only
// for an S3-compatible store (Cloudflare R2 / MinIO / Wasabi); it is undefined for
// real AWS S3.
interface ObjectStoreCredential {
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  region: string;
  endpoint?: string;
}

// The write probe uploads a tiny object under a UNIQUE key each run. Unique because a
// WORM / Object-Lock bucket blocks OVERWRITE of an existing key — reusing a fixed key
// would false-RED a locked bucket on the second validation; a fresh key is always a NEW
// object (which WORM permits), so re-validation stays reliable. It is best-effort deleted
// after (a locked bucket refuses the delete by design; the tiny marker is then retained —
// harmless). A PUT (not a GET) is used deliberately: the store's only job is receiving
// backup PUTs, so a read probe could go green on a key that can't actually write.
const OBJECT_STORE_PROBE_KEY_PREFIX = ".doubleyoup-connectivity-probe";
const OBJECT_STORE_PROBE_BODY = "doubleyoup object-store connectivity + write probe";

function objectStoreProbeKey(): string {
  return `${OBJECT_STORE_PROBE_KEY_PREFIX}-${crypto.randomUUID()}`;
}

// Prove the object-store credential can authenticate AND actually WRITE to the bucket by
// uploading (then best-effort deleting) a tiny probe object. WRITE — not read — because the
// store's sole job is receiving backup PUTs: a read/list probe can pass on a key that then
// can't write (a read-only token, or a bucket whose lock/policy blocks writes), i.e. a green
// check that doesn't prove the thing that matters (review finding #3).
//
// URL style differs by whether a custom S3_ENDPOINT is set:
//   • custom endpoint (recommended Cloudflare R2 path, also MinIO / Wasabi) — path-style
//     <endpoint>/<bucket>/<key>.
//   • real AWS S3 (no endpoint) — virtual-hosted-style <bucket>.s3.<region>.amazonaws.com/<key>.
// Both go through the same write probe (probeObjectStoreWithWrite), which fails CLOSED on any
// response that isn't a genuine S3 one, so a mis-typed / non-S3 S3_ENDPOINT can't false-green
// (review finding #1).
export async function validateS3(env: Env): Promise<ValidationResult> {
  if (!env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY || !env.S3_BUCKET) {
    return {
      ok: false,
      detail:
        "S3 not configured — set the S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY and S3_BUCKET secrets.",
    };
  }

  const credential: ObjectStoreCredential = {
    accessKeyId: env.S3_ACCESS_KEY_ID,
    secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    bucket: env.S3_BUCKET,
    region: env.S3_REGION || "us-east-1",
    endpoint: env.S3_ENDPOINT ? stripTrailingSlash(env.S3_ENDPOINT) : undefined,
  };

  const bucketUrl = credential.endpoint
    ? `${credential.endpoint}/${encodeURIComponent(credential.bucket)}`
    : `https://${credential.bucket}.s3.${credential.region}.amazonaws.com`;
  const where = credential.endpoint ?? `s3.${credential.region}.amazonaws.com`;
  return probeObjectStoreWithWrite(credential, bucketUrl, where);
}

// Both object-store paths (custom-endpoint R2/MinIO/Wasabi and real AWS S3) run this ONE
// write probe: PUT a tiny unique object, judge the response, then best-effort delete it.
// It fails CLOSED on anything that isn't a genuine S3 response so a mis-typed or non-S3
// S3_ENDPOINT cannot false-green (#1), and it proves WRITE, not just read (#3).
//
// Response precedence (deliberate + unambiguous):
//   3xx / opaque redirect ... endpoint redirected (not a direct S3 API) -> fail (redirect:"manual")
//   2xx WITH an ETag ........ genuine S3 PutObject succeeded -> writable -> ok
//   2xx WITHOUT an ETag ..... not an S3 object store (proxy/SPA/health page) -> fail (#1)
//   InvalidAccessKeyId ...... bad access key id -> fail
//   SignatureDoesNotMatch ... bad secret / region -> fail
//   NoSuchBucket ............ wrong bucket or endpoint -> fail
//   403 / AccessDenied ...... authenticated but not authorized to WRITE -> fail (#3)
//   4xx/5xx with NO S3 <Code> non-S3 endpoint -> fail (#1)
//   any other S3 <Code> ..... generic failure with the HTTP status + code
async function probeObjectStoreWithWrite(
  cred: ObjectStoreCredential,
  bucketUrl: string,
  where: string,
): Promise<ValidationResult> {
  const probeUrl = `${bucketUrl}/${objectStoreProbeKey()}`;

  let response: Response;
  try {
    const signed = await signS3Request({
      method: "PUT",
      url: probeUrl,
      region: cred.region,
      accessKeyId: cred.accessKeyId,
      secretAccessKey: cred.secretAccessKey,
      body: OBJECT_STORE_PROBE_BODY,
    });
    // redirect:"manual" so a redirecting host surfaces as a 3xx we can reject, rather than
    // silently following to some 200 landing page (which would false-green — #1).
    response = await fetch(signed.url, {
      method: "PUT",
      headers: signed.headers,
      body: OBJECT_STORE_PROBE_BODY,
      redirect: "manual",
    });
  } catch (err) {
    return { ok: false, detail: `Object store request could not be sent: ${errorMessage(err)}.` };
  }

  // A redirect means S3_ENDPOINT points at a redirecting/proxy host, not the S3 API itself.
  // With redirect:"manual" a real 3xx keeps its status; a runtime that instead yields an
  // opaque-redirect filtered response reports status 0 — treat both as a redirect failure.
  if (response.status === 0 || (response.status >= 300 && response.status < 400)) {
    // On the custom-endpoint path a redirect means S3_ENDPOINT isn't the direct S3 API; on the
    // AWS path a 301 PermanentRedirect means the bucket is in a different region (wrong S3_REGION),
    // so point at the knob that actually applies.
    const hint = cred.endpoint
      ? "set S3_ENDPOINT to the direct S3/R2 API endpoint, not a redirecting or proxy host"
      : "the bucket appears to be in a different region — set S3_REGION to the bucket's actual region";
    return {
      ok: false,
      detail: `Object store endpoint ${where} redirected the request (HTTP ${response.status || "3xx"}) — ${hint}.`,
    };
  }

  if (response.status >= 200 && response.status < 300) {
    // A genuine S3 PutObject always returns an ETag of the stored object. Its ABSENCE means
    // the 2xx came from something that is NOT an S3-compatible store (a proxy, SPA or health
    // page answering 200 for any path), so we must NOT report success — that is the false
    // green (#1). Drain the body either way so the connection frees.
    const etag = response.headers.get("etag");
    await response.text().catch(() => "");
    if (!etag) {
      return {
        ok: false,
        detail: `Object store endpoint ${where} returned HTTP ${response.status} but no S3 ETag — S3_ENDPOINT does not look like an S3-compatible object store. Check S3_ENDPOINT.`,
      };
    }
    // Write proven. Best-effort remove the marker (a WORM/locked bucket refuses this — fine).
    await bestEffortDeleteProbe(cred, probeUrl);
    return {
      ok: true,
      detail: `Object store bucket "${cred.bucket}" at ${where} is writable (a probe object was uploaded with the credential).`,
    };
  }

  // 4xx/5xx: a genuine S3 store returns an XML <Error><Code>. Map the known codes; the
  // ABSENCE of any code is itself a signal the endpoint isn't S3-compatible (#1).
  const body = (await response.text().catch(() => "")).slice(0, 500);
  const code = extractXmlTag(body, "Code");

  if (code === "InvalidAccessKeyId") {
    return { ok: false, detail: "S3 access key not recognised (InvalidAccessKeyId) — check S3_ACCESS_KEY_ID." };
  }
  if (code === "SignatureDoesNotMatch") {
    return {
      ok: false,
      detail:
        'S3 signature mismatch (SignatureDoesNotMatch) — check S3_SECRET_ACCESS_KEY and S3_REGION (use "auto" for Cloudflare R2).',
    };
  }
  if (code === "NoSuchBucket") {
    return {
      ok: false,
      detail: `Object store bucket "${cred.bucket}" not found (NoSuchBucket) — check S3_BUCKET and S3_ENDPOINT.`,
    };
  }
  if (response.status === 403 || code === "AccessDenied") {
    return {
      ok: false,
      detail:
        `Object store write denied (403) for bucket "${cred.bucket}" — the key authenticated but is not authorized to WRITE. ` +
        "For Cloudflare R2, scope the API token to this bucket with Object Read & Write; for AWS the key needs s3:PutObject.",
    };
  }
  if (!code) {
    return {
      ok: false,
      detail: `Object store endpoint ${where} returned HTTP ${response.status} with no S3 error code — S3_ENDPOINT may not be an S3-compatible object store. Check S3_ENDPOINT.`,
    };
  }
  // Surface R2/S3's own <Message> for any code we don't special-case above — it names the
  // exact rejected argument (e.g. an unsupported header or a malformed value), which is what
  // an operator actually needs to fix a generic 4xx like InvalidArgument.
  const message = extractXmlTag(body, "Message");
  return {
    ok: false,
    detail: `Object store write check failed with HTTP ${response.status} (${code})${
      message ? `: ${message}` : ""
    }.`,
  };
}

// Best-effort cleanup of the probe object. NEVER affects the validation result: a WORM /
// Object-Lock bucket refuses the delete (by design) and any network hiccup is irrelevant —
// the write already succeeded, which is what we validated.
async function bestEffortDeleteProbe(cred: ObjectStoreCredential, probeUrl: string): Promise<void> {
  try {
    const signed = await signS3Request({
      method: "DELETE",
      url: probeUrl,
      region: cred.region,
      accessKeyId: cred.accessKeyId,
      secretAccessKey: cred.secretAccessKey,
    });
    const response = await fetch(signed.url, {
      method: "DELETE",
      headers: signed.headers,
      redirect: "manual",
    });
    await response.text().catch(() => "");
  } catch {
    // cleanup only — ignore
  }
}

// ── Stripe ──────────────────────────────────────────────────────────────────

// GET /v1/account with the secret key as a bearer token. 200 => the key works.
export async function validateStripe(env: Env): Promise<ValidationResult> {
  if (!env.STRIPE_SECRET_KEY) {
    return { ok: false, detail: "Stripe not configured — set the STRIPE_SECRET_KEY secret." };
  }

  try {
    const response = await fetch("https://api.stripe.com/v1/account", {
      headers: {
        authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        accept: "application/json",
      },
    });

    if (response.status === 200) {
      const account = (await response.json()) as { id?: string };
      // Stripe key prefixes encode the mode; report it so the agency can catch a
      // test key pasted where a live key belongs (or vice-versa).
      const isLive = env.STRIPE_SECRET_KEY.includes("_live_");
      const accountId = account.id ?? "unknown";
      return {
        ok: true,
        detail: `Stripe account ${accountId} authenticated (${isLive ? "live" : "test"} mode).`,
      };
    }
    if (response.status === 401) {
      return { ok: false, detail: "Stripe rejected the key (401 Unauthorized) — check STRIPE_SECRET_KEY." };
    }

    const body = (await response.json().catch(() => null)) as { error?: { message?: string } } | null;
    const message = body?.error?.message;
    return {
      ok: false,
      detail: `Stripe check failed with HTTP ${response.status}${message ? `: ${message}` : ""}.`,
    };
  } catch (err) {
    return { ok: false, detail: `Stripe request could not be sent: ${errorMessage(err)}.` };
  }
}

// ── R2 provisioning ─────────────────────────────────────────────────────────

// GET /user/tokens/verify only validates USER-owned tokens (My Profile → API
// Tokens) — it returns a 401 "Invalid API Token" even for a perfectly valid
// ACCOUNT-owned token (Manage Account → Account API Tokens), which is what
// this credential must be. So instead we hit a cheap account-scoped read
// (GET /accounts?per_page=1) that authenticates against account tokens: a
// 200 with a non-empty result proves the token is valid, though — like the
// user-tokens endpoint — it can't enumerate the permission groups the token
// was minted with, so a green result here does not guarantee the R2 Storage
// / Account API Tokens edit scopes are actually present. Those scopes are
// only exercised for real on the first site provision (bucket create +
// scoped-key mint).
export async function validateR2Provision(env: Env): Promise<ValidationResult> {
  if (!env.R2_PROVISION_API_TOKEN) {
    return {
      ok: false,
      detail: "R2 provisioning not configured — set the R2_PROVISION_API_TOKEN secret.",
    };
  }

  try {
    const response = await fetch("https://api.cloudflare.com/client/v4/accounts?per_page=1", {
      headers: {
        authorization: `Bearer ${env.R2_PROVISION_API_TOKEN}`,
        accept: "application/json",
      },
    });

    if (response.status === 200) {
      const body = (await response.json().catch(() => null)) as {
        success?: boolean;
        result?: Array<{ name?: string }>;
      } | null;
      if (body?.success && body.result && body.result.length > 0) {
        const accountName = body.result[0]?.name;
        return {
          ok: true,
          detail: `R2 provisioning token valid${accountName ? ` — account: ${accountName}` : ""}. Permissions are exercised on first site provision.`,
        };
      }
      return {
        ok: false,
        detail: "R2 provisioning token check returned no accounts — check R2_PROVISION_API_TOKEN.",
      };
    }
    if (response.status === 401 || response.status === 403) {
      return {
        ok: false,
        detail:
          "Cloudflare rejected the token — check R2_PROVISION_API_TOKEN (must be an ACCOUNT-owned token: Manage Account → Account API Tokens).",
      };
    }

    const body = (await response.json().catch(() => null)) as {
      errors?: Array<{ message?: string }>;
    } | null;
    const message = body?.errors?.[0]?.message;
    return {
      ok: false,
      detail: `R2 provisioning token check failed with HTTP ${response.status}${message ? `: ${message}` : ""}.`,
    };
  } catch (err) {
    return {
      ok: false,
      detail: `R2 provisioning token check could not be sent (transient network error?): ${errorMessage(err)}.`,
    };
  }
}

// ── Cloudflare DNS (Direction-B dns-record-upsert + cache-purge + cache-rule-upsert) ─

// READ-ONLY probe: GET /zones?per_page=1 proves CF_DNS_API_TOKEN authenticates and can
// list at least one zone (Zone:Read). Like validateR2Provision, Cloudflare can't tell us
// which permission groups a token was minted with, so a green here proves Zone:Read on
// >= 1 zone but NOT Zone:DNS:Edit or Zone:Cache Purge — those scopes are exercised for
// real on the first dns-record-upsert / cache-purge dispatch, which reports a clear denial
// if the scope is missing. We never write a record or purge a cache from a validator.
/**
 * READ-ONLY probe of the account-level Cloudflare Tunnel scope (planning/40): resolve the token's
 * account, then GET one cfd_tunnel. Returns a short human status string (never throws) folded into
 * the cfDns detail — a 200 proves the token can manage tunnels; a 401/403 means the account-level
 * Cloudflare Tunnel scope is missing (add it for automated cell provisioning).
 */
async function probeCfTunnelScope(token: string): Promise<string> {
  try {
    const acctResponse = await fetch("https://api.cloudflare.com/client/v4/accounts?per_page=1", {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
    if (acctResponse.status === 401 || acctResponse.status === 403) {
      return "Tunnel management: NOT available — token cannot access an account (add account-level Cloudflare Tunnel: Edit for automated cell provisioning).";
    }
    const acctBody = (await acctResponse.json().catch(() => null)) as {
      success?: boolean;
      result?: Array<{ id?: string }>;
    } | null;
    const accountId = acctBody?.success && acctBody.result && acctBody.result.length > 0 ? acctBody.result[0]?.id : undefined;
    if (!accountId) {
      return "Tunnel management: could not resolve the token's account to probe the Cloudflare Tunnel scope.";
    }
    const tunnelResponse = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/cfd_tunnel?per_page=1`,
      { headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
    );
    if (tunnelResponse.status === 200) {
      return "Tunnel management: OK (account-level Cloudflare Tunnel present).";
    }
    if (tunnelResponse.status === 401 || tunnelResponse.status === 403) {
      return "Tunnel management: NOT available — add account-level Cloudflare Tunnel: Edit for automated cell provisioning.";
    }
    return `Tunnel management: check inconclusive (HTTP ${tunnelResponse.status}).`;
  } catch (err) {
    return `Tunnel management: probe could not be sent (${errorMessage(err)}).`;
  }
}

/**
 * READ-ONLY probe of the Zone → Cache Rules scope (the `cache-rule-upsert` op, edge page caching):
 * GET the cache-settings phase entrypoint of the zone the zone list returned. Returns a short human
 * status string (never throws) folded into the cfDns detail. A 200 (rules exist) or 404 (no Cache
 * Rules yet) proves the token may READ cache rules; Cloudflare cannot tell us whether it may also
 * EDIT them, so that is exercised on the first cache-rule-upsert. A 401/403 means the scope is
 * missing entirely.
 */
async function probeCacheRulesScope(token: string, zoneId: string | undefined): Promise<string> {
  if (!zoneId) {
    return "Cache Rules: could not probe (the zone list returned no zone id).";
  }
  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zoneId)}/rulesets/phases/http_request_cache_settings/entrypoint`,
      { headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
    );
    if (response.status === 200 || response.status === 404) {
      return "Cache Rules: read access OK (Zone → Cache Rules: Edit is exercised on the first edge-cache rule upsert).";
    }
    if (response.status === 401 || response.status === 403) {
      return "Cache Rules: NOT available — add Zone → Cache Rules: Edit for edge page caching.";
    }
    return `Cache Rules: check inconclusive (HTTP ${response.status}).`;
  } catch (err) {
    return `Cache Rules: probe could not be sent (${errorMessage(err)}).`;
  }
}

/**
 * READ-ONLY probe of the WAF scope (the `waf-rule-upsert` op, edge defense): GET the
 * firewall-custom phase entrypoint of the zone the zone list returned. Returns a short human status
 * string (never throws) folded into the cfDns detail. A 200 (rules exist) or 404 (no custom rules
 * yet) proves the token may READ custom rules; Cloudflare cannot tell us whether it may also EDIT
 * them, so that is exercised on the first waf-rule-upsert. A 401/403 means the scope is missing.
 *
 * "Zone WAF Write" is Cloudflare's API permission-group name for this ruleset phase; the dashboard's
 * token editor lists it under Zone as "WAF", with Edit. Both names are in the message because
 * Cloudflare labels these by product, not by phase, and the two do not always read the same.
 */
async function probeWafRulesScope(token: string, zoneId: string | undefined): Promise<string> {
  if (!zoneId) {
    return "WAF rules: could not probe (the zone list returned no zone id).";
  }
  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zoneId)}/rulesets/phases/http_request_firewall_custom/entrypoint`,
      { headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
    );
    if (response.status === 200 || response.status === 404) {
      return 'WAF rules: read access OK ("Zone WAF Write" is exercised on the first edge-defense rule upsert).';
    }
    if (response.status === 401 || response.status === 403) {
      return 'WAF rules: NOT available — add the "Zone WAF Write" permission (Zone → WAF → Edit in the API-token editor) for edge defense.';
    }
    return `WAF rules: check inconclusive (HTTP ${response.status}).`;
  } catch (err) {
    return `WAF rules: probe could not be sent (${errorMessage(err)}).`;
  }
}

/** One READ-ONLY Workers probe: GET `url` with the token and classify the answer. Never throws. */
async function probeWorkersRead(token: string, url: string): Promise<{ state: WorkersReadState; status: string }> {
  try {
    const response = await fetch(url, { headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
    if (response.status === 200) {
      return { state: "read-ok", status: "HTTP 200" };
    }
    if (response.status === 401 || response.status === 403) {
      return { state: "denied", status: `HTTP ${response.status}` };
    }
    return { state: "unknown", status: `HTTP ${response.status}` };
  } catch (err) {
    return { state: "unknown", status: `not sent: ${errorMessage(err)}` };
  }
}

/**
 * planning/49 Phase 3: READ-ONLY probes of the two Workers scopes the session edge gate needs (decision
 * C). Workers Scripts on the token's account (the edge-gate deploy uploads a script) and Workers Routes
 * on the zone the zone list returned first (a route puts the gate in front of a session host). A READ
 * cannot prove Edit: Cloudflare offers no way to test an edit scope without writing, so the row says so,
 * and Edit is exercised on the first edge-gate deploy and route upsert. ADVISORY: never changes `ok`.
 */
async function probeWorkersScope(
  token: string,
  zone: { id: string | undefined; name: string | undefined },
  workerName: string | undefined,
): Promise<{ detail: string; report: WorkersScopeReport }> {
  const editNote =
    "A read cannot prove Workers Scripts: Edit or Workers Routes: Edit; those are exercised on the first edge-gate deploy and route upsert.";

  // The account: the same first-account lookup the tunnel probe uses.
  let accountId: string | undefined;
  try {
    const acctResponse = await fetch("https://api.cloudflare.com/client/v4/accounts?per_page=1", {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
    const acctBody = (await acctResponse.json().catch(() => null)) as { success?: boolean; result?: Array<{ id?: string }> } | null;
    if (acctBody?.success && Array.isArray(acctBody.result) && acctBody.result.length > 0) {
      accountId = acctBody.result[0]?.id;
    }
  } catch {
    accountId = undefined;
  }

  let scripts: { state: WorkersReadState; status: string } = { state: "unknown", status: "the token's account could not be resolved" };
  if (accountId) {
    scripts = await probeWorkersRead(token, `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/workers/scripts`);
  }
  let routes: { state: WorkersReadState; status: string } = { state: "unknown", status: "the zone list returned no zone id" };
  if (zone.id) {
    routes = await probeWorkersRead(token, `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zone.id)}/workers/routes`);
  }

  const zoneText = zone.name ?? "the first listed zone";
  const scriptsText = workersReadText(scripts, "Workers scripts on the account", "Account → Workers Scripts: Edit");
  const routesText = workersReadText(routes, `Workers routes on ${zoneText}`, "Zone → Workers Routes: Edit");
  // planning/49 Phase 3 (I4): the gate reaches this Worker's SessionGateMinter by the name in DY_WORKER_NAME.
  let workerNameState: "set" | "unset" = "unset";
  let workerNameText =
    "DY_WORKER_NAME: NOT set — set it to this Worker's own script name as Cloudflare shows it (`wrangler secret put DY_WORKER_NAME`); the edge-gate deploy refuses without it";
  if (workerName) {
    workerNameState = "set";
    // The value is echoed only when it is a script name; anything else could be any text.
    workerNameText = "DY_WORKER_NAME: set, but NOT a Worker script name (lowercase letters, digits, \"-\" and \"_\", at most 63 characters)";
    if (isWorkerScriptName(workerName)) {
      workerNameText = `DY_WORKER_NAME: set ("${workerName}")`;
    }
  }
  return {
    detail: `Session edge gate (advisory, does not affect this check): ${scriptsText}; ${routesText}; ${workerNameText}. ${editNote}`,
    report: { scripts: scripts.state, routes: routes.state, workerName: workerNameState },
  };
}

/** One Workers probe as row text. */
function workersReadText(probe: { state: WorkersReadState; status: string }, what: string, scope: string): string {
  if (probe.state === "read-ok") {
    return `${what}: read OK`;
  }
  if (probe.state === "denied") {
    return `${what}: NOT readable (${probe.status}) — add ${scope}`;
  }
  return `${what}: check inconclusive (${probe.status})`;
}

export async function validateCfDns(env: Env): Promise<ValidationResult> {
  if (!env.CF_DNS_API_TOKEN) {
    return {
      ok: false,
      detail: "Cloudflare DNS not configured — set the CF_DNS_API_TOKEN secret (Zone:DNS:Edit + Zone:Read).",
    };
  }

  try {
    const response = await fetch("https://api.cloudflare.com/client/v4/zones?per_page=1", {
      headers: {
        authorization: `Bearer ${env.CF_DNS_API_TOKEN}`,
        accept: "application/json",
      },
    });

    if (response.status === 200) {
      const body = (await response.json().catch(() => null)) as {
        success?: boolean;
        result?: Array<{ id?: string; name?: string }>;
      } | null;
      if (body?.success && body.result && body.result.length > 0) {
        const zoneName = body.result[0]?.name;
        // planning/40: the SAME token now also drives cf-tunnel-create/-config (automated cell
        // routing), which need account-level Cloudflare Tunnel. Probe that scope and fold its status
        // into the detail — non-fatal so a DNS-only token still validates green, but a missing tunnel
        // scope is surfaced here (a routable-cell provision would otherwise fail on first dispatch).
        const tunnelStatus = await probeCfTunnelScope(env.CF_DNS_API_TOKEN);
        // Edge page caching: the same token also drives cache-rule-upsert. Same non-fatal pattern.
        const cacheRulesStatus = await probeCacheRulesScope(env.CF_DNS_API_TOKEN, body.result[0]?.id);
        // Edge defense: the same token also drives waf-rule-upsert. Same non-fatal pattern — a
        // missing WAF scope must be visible HERE, not on the first apply against a live zone.
        const wafRulesStatus = await probeWafRulesScope(env.CF_DNS_API_TOKEN, body.result[0]?.id);
        // hub#46 customer domains: the same token also drives the custom-hostname ops, on the zone in
        // CF_CUSTOM_HOSTNAME_ZONE. Same non-fatal pattern: an agency with no customer domains yet still
        // validates green, but a missing scope or fallback origin shows here, not on a customer's domain.
        const customHostnames = await probeCustomHostnameScope(env);
        // planning/49 Phase 3: the session edge gate's Workers scopes. Same non-fatal pattern.
        const workers = await probeWorkersScope(env.CF_DNS_API_TOKEN, { id: body.result[0]?.id, name: zoneName }, env.DY_WORKER_NAME);
        return {
          ok: true,
          detail: `Cloudflare DNS token valid${zoneName ? ` — can read zone ${zoneName}` : ""}. DNS edit permission is exercised on the first DNS dispatch. ${tunnelStatus} ${cacheRulesStatus} ${wafRulesStatus} ${customHostnames.detail} ${workers.detail}`,
          customHostnames,
          workersScope: workers.report,
        };
      }
      return {
        ok: false,
        detail:
          "Cloudflare DNS token authenticated but can list no zones — scope CF_DNS_API_TOKEN to the zone(s) the platform should manage (Zone:Read + Zone:DNS:Edit).",
      };
    }
    if (response.status === 401 || response.status === 403) {
      return {
        ok: false,
        detail: "Cloudflare rejected the token — check CF_DNS_API_TOKEN (needs Zone:Read + Zone:DNS:Edit).",
      };
    }

    const body = (await response.json().catch(() => null)) as {
      errors?: Array<{ message?: string }>;
    } | null;
    const message = body?.errors?.[0]?.message;
    return {
      ok: false,
      detail: `Cloudflare DNS token check failed with HTTP ${response.status}${message ? `: ${message}` : ""}.`,
    };
  } catch (err) {
    return {
      ok: false,
      detail: `Cloudflare DNS token check could not be sent (transient network error?): ${errorMessage(err)}.`,
    };
  }
}

// ── AI providers ──────────────────────────────────────────────────────────────

// Anthropic: a minimal authenticated read of the models list.
export async function validateAnthropic(env: Env): Promise<ValidationResult> {
  if (!env.ANTHROPIC_API_KEY) {
    return { ok: false, detail: "Anthropic not configured — set the ANTHROPIC_API_KEY secret." };
  }

  // A Claude Code OAuth / setup-token ("sk-ant-oat…", from `claude setup-token`) is NOT a standard
  // API key: it authenticates via the OAuth Bearer flow, Anthropic rejects it for third-party API
  // use (disabled 2026-02-20), and the x-api-key probe below cannot verify it. Per an explicit
  // product decision (Jason) we ACCEPT it on FORMAT ONLY — green so onboarding is not blocked —
  // WITHOUT verifying it works. This is deliberately not a working-credential check; whether such a
  // token is usable is left to be handled at runtime. TODO: revisit if the platform gains an
  // OAuth-aware Anthropic runtime path (or Anthropic re-enables third-party OAuth).
  if (env.ANTHROPIC_API_KEY.startsWith("sk-ant-oat")) {
    return {
      ok: true,
      detail:
        "Anthropic Claude setup-token accepted on FORMAT ONLY — NOT verified. OAuth/setup-tokens are not usable for third-party API calls; usability is handled at runtime.",
    };
  }

  try {
    const response = await fetch("https://api.anthropic.com/v1/models?limit=1", {
      headers: {
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        accept: "application/json",
      },
    });

    if (response.status === 200) {
      return { ok: true, detail: "Anthropic API key authenticated." };
    }
    if (response.status === 401) {
      return { ok: false, detail: "Anthropic rejected the key (401) — check ANTHROPIC_API_KEY." };
    }
    return { ok: false, detail: `Anthropic check failed with HTTP ${response.status}.` };
  } catch (err) {
    return { ok: false, detail: `Anthropic request could not be sent: ${errorMessage(err)}.` };
  }
}

// OpenRouter: GET /key returns the key's own metadata — a cheap authenticated read.
export async function validateOpenRouter(env: Env): Promise<ValidationResult> {
  if (!env.OPENROUTER_API_KEY) {
    return { ok: false, detail: "OpenRouter not configured — set the OPENROUTER_API_KEY secret." };
  }

  try {
    const response = await fetch("https://openrouter.ai/api/v1/key", {
      headers: {
        authorization: `Bearer ${env.OPENROUTER_API_KEY}`,
        accept: "application/json",
      },
    });

    if (response.status === 200) {
      const body = (await response.json().catch(() => null)) as { data?: { label?: string } } | null;
      const label = body?.data?.label;
      return { ok: true, detail: `OpenRouter API key authenticated${label ? ` (${label})` : ""}.` };
    }
    if (response.status === 401) {
      return { ok: false, detail: "OpenRouter rejected the key (401) — check OPENROUTER_API_KEY." };
    }
    return { ok: false, detail: `OpenRouter check failed with HTTP ${response.status}.` };
  } catch (err) {
    return { ok: false, detail: `OpenRouter request could not be sent: ${errorMessage(err)}.` };
  }
}

// OpenAI (also covers Codex, which authenticates with the same key): a
// minimal authenticated read of the models list.
export async function validateOpenAI(env: Env): Promise<ValidationResult> {
  if (!env.OPENAI_API_KEY) {
    return { ok: false, detail: "OpenAI not configured — set the OPENAI_API_KEY secret." };
  }

  try {
    const response = await fetch("https://api.openai.com/v1/models", {
      headers: {
        authorization: `Bearer ${env.OPENAI_API_KEY}`,
        accept: "application/json",
      },
    });

    if (response.status === 200) {
      return { ok: true, detail: "OpenAI API key authenticated." };
    }
    if (response.status === 401) {
      return { ok: false, detail: "OpenAI rejected the key (401) — check OPENAI_API_KEY." };
    }
    return { ok: false, detail: `OpenAI check failed with HTTP ${response.status}.` };
  } catch (err) {
    return { ok: false, detail: `OpenAI request could not be sent: ${errorMessage(err)}.` };
  }
}

// Aggregate AI result surfaced at /validate. All three providers are optional and
// the platform only needs ONE working AI backend, so the aggregate is green when at
// least one CONFIGURED provider validates (any-of, not all-of). A configured-but-broken
// key does NOT block onboarding — it is still listed in the detail so the agency can fix
// or remove it, but as long as one provider works the check passes. A provider that isn't
// configured is neither counted nor held against the agency. Only red when every
// configured provider fails (or none is configured).
export async function validateAI(env: Env): Promise<ValidationResult> {
  const providers: Array<{ name: string; configured: boolean; result: ValidationResult }> = [
    { name: "Anthropic", configured: !!env.ANTHROPIC_API_KEY, result: await validateAnthropic(env) },
    { name: "OpenRouter", configured: !!env.OPENROUTER_API_KEY, result: await validateOpenRouter(env) },
    { name: "OpenAI", configured: !!env.OPENAI_API_KEY, result: await validateOpenAI(env) },
  ];

  const configured = providers.filter((provider) => provider.configured);
  if (configured.length === 0) {
    return {
      ok: false,
      detail: "No AI keys configured — set ANTHROPIC_API_KEY, OPENROUTER_API_KEY and/or OPENAI_API_KEY (any one is enough).",
    };
  }

  // any-of: one working provider is enough. The detail still names every configured
  // provider's status so a broken key stays visible even when the aggregate is green.
  const anyOk = configured.some((provider) => provider.result.ok);
  const detail = configured
    .map((provider) => `${provider.name}: ${provider.result.ok ? "ok" : provider.result.detail}`)
    .join(" | ");
  return { ok: anyOk, detail };
}

// ── Google Cloud ──────────────────────────────────────────────────────────────

// Base64url-encode raw bytes (JWT segments are base64url with no padding).
function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeString(value: string): string {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

// Convert a PEM private key to its raw DER bytes for crypto.subtle.importKey.
// Google service-account keys ship the private key as PKCS#8 PEM
// ("-----BEGIN PRIVATE KEY-----"); JSON.parse already turned the JSON "\n"
// escapes into real newlines, so stripping the armor + all whitespace and
// base64-decoding yields the DER.
function pemToDer(pem: string): Uint8Array {
  const base64Body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(atob(base64Body), (char) => char.charCodeAt(0));
}

// The shape of the downloaded service-account key JSON (GCP_SERVICE_ACCOUNT_KEY). Shared with
// the Direction-B gcp-instance-create actuator (actuate.ts), which parses the same secret.
export interface ServiceAccountKey {
  client_email?: string;
  private_key?: string;
  project_id?: string;
  token_uri?: string;
}

interface GoogleTokenResponse {
  access_token?: string;
}

// The three OAuth2 scopes this Worker ever mints a Google access token for. A scope bounds what
// the TOKEN may do (the service account's IAM roles still bound what the agency has granted):
//   - READ_ONLY is the DEFAULT and is all validateGCP's PROJECT-level testIamPermissions probe needs —
//     least-privilege for a probe that must never be able to change anything.
//   - IAM is requested ONLY by validateGCP's actAs check on the session runtime identity (planning/49
//     Phase 3): the IAM API's serviceAccounts.testIamPermissions accepts the `iam` or `cloud-platform`
//     scope and not the read-only one. `iam` is the narrower of the two (the IAM API only). The token is
//     used for that ONE read and never leaves the Worker.
//   - CLOUD_PLATFORM (full) is requested ONLY by the Direction-B `gcp-*` write actuators
//     (actuate.ts::mintPinnedGcpAccessToken — the one place that asks for it, on behalf of
//     gcp-instance-create / gcp-network-create / gcp-firewall-create / gcp-address-create /
//     gcp-router-nat-create),
//     because creating a Compute Engine resource is a write the read-only scope cannot
//     authorize. That escalation is inherent to those ops and deliberate; nothing else asks
//     for it, and validateGCP stays on the read-only default.
export const GOOGLE_SCOPE_CLOUD_PLATFORM_READ_ONLY = "https://www.googleapis.com/auth/cloud-platform.read-only";
export const GOOGLE_SCOPE_CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform";
export const GOOGLE_SCOPE_IAM = "https://www.googleapis.com/auth/iam";

// Mint a Google OAuth2 access token via the JWT-bearer grant (RFC 7523 /
// Google's "server-to-server" flow): build a JWT signed with the service
// account's RS256 private key, POST it as the assertion, receive a bearer token.
// This avoids any Google SDK — pure Web Crypto + fetch. Throws on failure.
// The returned token is a bearer credential: callers place it in an Authorization
// header and MUST NOT log it or echo it in any result/detail.
export async function mintGoogleAccessToken(options: {
  clientEmail: string;
  privateKeyPem: string;
  tokenUri: string;
  /** OAuth2 scope to request. Defaults to READ-ONLY so a probe stays least-privilege. */
  scope?: string;
}): Promise<string> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const scope = options.scope ?? GOOGLE_SCOPE_CLOUD_PLATFORM_READ_ONLY;

  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: options.clientEmail,
    scope,
    aud: options.tokenUri,
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  };

  const signingInput =
    `${base64UrlEncodeString(JSON.stringify(header))}.` +
    `${base64UrlEncodeString(JSON.stringify(claims))}`;

  // Import the PKCS#8 private key for RS256 (RSASSA-PKCS1-v1_5 + SHA-256) and
  // sign the "<header>.<claims>" input. workerd and Node both support this.
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(options.privateKeyPem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, new TextEncoder().encode(signingInput)),
  );
  const jwt = `${signingInput}.${base64UrlEncodeBytes(signatureBytes)}`;

  const form = new URLSearchParams();
  form.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  form.set("assertion", jwt);

  const response = await fetch(options.tokenUri, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: form.toString(),
  });

  if (!response.ok) {
    const body = (await response.text()).slice(0, 300);
    throw new Error(`Google token endpoint returned HTTP ${response.status}. ${body}`);
  }
  const data = (await response.json()) as GoogleTokenResponse;
  if (!data.access_token) {
    throw new Error("Google token endpoint response had no access_token.");
  }
  return data.access_token;
}

/**
 * planning/49 Phase 2: mint a Google-signed ID TOKEN for `audience` from a service-account key.
 * Cloud Run checks an ID token, not an access token, before it lets a caller invoke an IAM-protected
 * service, and the audience must be the service's URL.
 *
 * The same RS256 JWT-bearer grant as mintGoogleAccessToken, with ONE difference: the assertion carries
 * `target_audience` instead of `scope`, and Google answers with `id_token`. The token goes back to the
 * caller alone, who puts it in an Authorization header and never logs or echoes it.
 */
export async function mintGoogleIdToken(options: {
  clientEmail: string;
  privateKeyPem: string;
  tokenUri: string;
  /** The URL of the Cloud Run service the token is for. */
  audience: string;
}): Promise<string> {
  const nowSeconds = Math.floor(Date.now() / 1000);

  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: options.clientEmail,
    sub: options.clientEmail,
    aud: options.tokenUri,
    target_audience: options.audience,
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  };

  const signingInput =
    `${base64UrlEncodeString(JSON.stringify(header))}.` +
    `${base64UrlEncodeString(JSON.stringify(claims))}`;

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(options.privateKeyPem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, new TextEncoder().encode(signingInput)),
  );
  const jwt = `${signingInput}.${base64UrlEncodeBytes(signatureBytes)}`;

  const form = new URLSearchParams();
  form.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  form.set("assertion", jwt);

  const response = await fetch(options.tokenUri, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: form.toString(),
  });

  if (!response.ok) {
    const body = (await response.text()).slice(0, 300);
    throw new Error(`Google token endpoint returned HTTP ${response.status}. ${body}`);
  }
  const data = (await response.json()) as { id_token?: string };
  if (!data.id_token) {
    throw new Error("Google token endpoint response had no id_token.");
  }
  return data.id_token;
}

// The permissions doubleyoup's GCP integration REQUIRES. Cell provisioning (planning/34) builds a
// whole cell in the agency's OWN project through signed jobs -> the agency Worker: a VPC + subnet,
// two firewall rules, a Cloud NAT (via a router), a static gateway address, and one VM per node.
// These are the EXACT compute.*.create permissions those actuators call (actuate.ts) — no more:
// the VM body attaches no service account, so no iam.serviceAccounts.actAs is needed. A single
// `roles/compute.admin` grant on the project covers every one of them (the onboarding page tells the
// agency to grant exactly that). This is the single source of truth for the required set — keep it
// matched to what the provisioning code actually does with the key (do NOT over-ask).
//
// We no longer require resourcemanager.projects.get (the old read-only probe): the provisioning code
// never calls it, so requiring it would force a second Viewer grant for nothing. The project's
// existence + the Cloud Resource Manager API being on are still confirmed implicitly — testIamPermissions
// runs on the cloudresourcemanager endpoint and 403s if that API is off (handled below).
export const REQUIRED_GCP_PERMISSIONS = [
  "compute.networks.create",
  "compute.subnetworks.create",
  "compute.firewalls.create",
  "compute.routers.create",
  "compute.addresses.create",
  "compute.instances.create",
];

// planning/51 (hub#58): the permissions the in-place UPDATE path and its reads use — discover a cell's
// VMs (gcp-instances-list), read one (gcp-instance-get), publish its boot script and reboot it
// (gcp-instance-set-metadata / gcp-instance-restart), take a boot-disk revert point first
// (gcp-disk-snapshot-create), and take a hand-built node's service account off before its metadata is
// set (gcp-instance-remove-service-account, review finding 4). Onboarding never needed them, so an agency could pass /validate and still
// fail every update op. They are tested in the SAME testIamPermissions call and reported, but they are
// ADVISORY: they never change `ok`. Two reasons. Onboarding must not start failing for an agency that
// has not used an update yet. And a grant scoped to named VMs with IAM Conditions (planning/51 decision
// A, the syd cell) does not show at project level at all, so a project-level miss is not proof of a
// missing grant. Test such a grant on the instance itself.
export const UPDATE_GCP_PERMISSIONS = [
  "compute.instances.list",
  "compute.instances.get",
  "compute.instances.setMetadata",
  "compute.instances.stop",
  "compute.instances.start",
  "compute.instances.setServiceAccount",
  "compute.disks.createSnapshot",
  "compute.snapshots.create",
  "compute.snapshots.get",
];

// planning/49 Phase 3: the Cloud Run permissions the SESSION ops use (actuate.ts): the upsert reads the
// service, creates or updates it, reads its IAM policy before a patch, and waits on the operation; the
// delete deletes it and waits; and the session is invoked with an ID token of the Worker's own identity
// (the edge gate's minter, like the probe invoke). ADVISORY, for the update-path reasons above: an agency
// that has not opened a session must still pass, and a grant with IAM Conditions on service names
// (planning/49 decision B, the syd cell) does not show at project level. Tested in a SEPARATE
// testIamPermissions call (probeSessionPermissions), so an error there — e.g. Google refusing a
// permission name for this resource — makes only this advisory "unknown" and can never change the
// required check. The subnet and actAs permissions are not here: the subnet ones are compute rights,
// and actAs is tested on the runtime service account itself.
export const SESSION_GCP_PERMISSIONS = [
  "run.services.get",
  "run.services.create",
  "run.services.update",
  "run.services.delete",
  "run.services.getIamPolicy",
  "run.operations.get",
  "run.routes.invoke",
];

/**
 * planning/49 Phase 3: the session-path permission check, in its OWN testIamPermissions call with the
 * same read-only token. Never throws: any failure (a fetch error, a non-200, a garbled body) is
 * "unknown" (missing: null), described in the advisory sentence.
 */
async function probeSessionPermissions(input: { accessToken: string; projectId: string }): Promise<{ missing: string[] | null; detail: string }> {
  const unknownHead = " Session path (advisory, does not affect this check): the Cloud Run permissions could not be checked";
  let response: Response;
  try {
    response = await fetch(
      `https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(input.projectId)}:testIamPermissions`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${input.accessToken}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ permissions: SESSION_GCP_PERMISSIONS }),
      },
    );
  } catch (err) {
    return { missing: null, detail: `${unknownHead} (the call could not be sent: ${errorMessage(err)}).` };
  }
  const body = (await response.json().catch(() => null)) as { permissions?: unknown; error?: { message?: string } } | null;
  if (response.status !== 200) {
    const message = body?.error?.message;
    return { missing: null, detail: `${unknownHead} (HTTP ${response.status}${message ? `: ${message}` : ""}).` };
  }
  if (body === null || (body.permissions !== undefined && !Array.isArray(body.permissions))) {
    return { missing: null, detail: `${unknownHead} (the answer was not a permission list).` };
  }
  // An absent list is Google's answer for "none held".
  const held = new Set(Array.isArray(body.permissions) ? (body.permissions as unknown[]) : []);
  const missing = SESSION_GCP_PERMISSIONS.filter((permission) => !held.has(permission));
  return { missing, detail: sessionPermissionsNote(missing) };
}

/** The advisory sentence /validate appends about the session-path Cloud Run permissions. */
function sessionPermissionsNote(missing: string[]): string {
  if (missing.length === 0) {
    return ` Session path (advisory): all ${SESSION_GCP_PERMISSIONS.length} Cloud Run permission(s) held at project level.`;
  }
  return (
    ` Session path (advisory, does not affect this check): ${missing.length} of ${SESSION_GCP_PERMISSIONS.length} Cloud Run ` +
    `permission(s) not held at project level: ${missing.join(", ")}. A grant with IAM Conditions on service names does ` +
    "not show at project level."
  );
}

/**
 * planning/49 Phase 3: test `iam.serviceAccounts.actAs` on the session runtime identity
 * `dy-run@<project>` itself (the onboarding grant is on that account, not on the project). Mints its own
 * `iam`-scoped token (see GOOGLE_SCOPE_IAM). ADVISORY and never throws: every failure is "unknown".
 * Google answers 404 for an account that does not exist. A 200 lists the permissions held, so a 200
 * without actAs means the account exists and the grant is missing.
 */
async function probeRunServiceAccountActAs(input: {
  clientEmail: string;
  privateKeyPem: string;
  tokenUri: string;
  projectId: string;
}): Promise<{ state: RunServiceAccountActAsState; detail: string }> {
  const runServiceAccount = cellRunServiceAccountFor(input.projectId);
  const head = " Session runtime identity (advisory";
  const notAffecting = ", does not affect this check)";

  let accessToken: string;
  try {
    accessToken = await mintGoogleAccessToken({
      clientEmail: input.clientEmail,
      privateKeyPem: input.privateKeyPem,
      tokenUri: input.tokenUri,
      scope: GOOGLE_SCOPE_IAM,
    });
  } catch (err) {
    return {
      state: "unknown",
      detail: `${head}${notAffecting}: could not mint a token to test iam.serviceAccounts.actAs on ${runServiceAccount}: ${errorMessage(err)}.`,
    };
  }

  const url =
    `https://iam.googleapis.com/v1/projects/${encodeURIComponent(input.projectId)}/serviceAccounts/` +
    `${encodeURIComponent(runServiceAccount)}:testIamPermissions`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ permissions: ["iam.serviceAccounts.actAs"] }),
    });
  } catch (err) {
    return { state: "unknown", detail: `${head}${notAffecting}: the actAs check on ${runServiceAccount} could not be sent: ${errorMessage(err)}.` };
  }

  if (response.status === 404) {
    return {
      state: "not-found",
      detail: `${head}${notAffecting}: ${runServiceAccount} was not found. Create it once at onboarding (it needs no roles).`,
    };
  }
  if (response.status !== 200) {
    return {
      state: "unknown",
      detail:
        `${head}${notAffecting}: the actAs check on ${runServiceAccount} answered HTTP ${response.status}. Google can refuse ` +
        "the check without saying whether the account exists.",
    };
  }
  const body = (await response.json().catch(() => null)) as { permissions?: string[] } | null;
  const held = Array.isArray(body?.permissions) && body.permissions.includes("iam.serviceAccounts.actAs");
  if (held) {
    return { state: "held", detail: `${head}): the service account may act as ${runServiceAccount} (iam.serviceAccounts.actAs).` };
  }
  return {
    state: "denied",
    detail:
      `${head}${notAffecting}: the service account does NOT hold iam.serviceAccounts.actAs on ${runServiceAccount}. ` +
      "Grant it on that service account (roles/iam.serviceAccountUser), not on the project.",
  };
}

/** The advisory sentence /validate appends about the update-path permissions. */
function updatePermissionsNote(missing: string[]): string {
  if (missing.length === 0) {
    return ` Update path (advisory): all ${UPDATE_GCP_PERMISSIONS.length} update permission(s) held at project level.`;
  }
  return (
    ` Update path (advisory, does not affect this check): ${missing.length} of ${UPDATE_GCP_PERMISSIONS.length} update ` +
    `permission(s) not held at project level: ${missing.join(", ")}. A grant scoped to named VMs with IAM Conditions ` +
    `does not show at project level — test it on the instance.`
  );
}

// Parse the SA-key JSON, mint an access token, then check the service account holds every
// REQUIRED_GCP_PERMISSIONS via testIamPermissions. ok when the token mints AND none are missing.
// The same call also reports the UPDATE_GCP_PERMISSIONS, as an advisory only (see above).
export async function validateGCP(env: Env): Promise<ValidationResult> {
  if (!env.GCP_SERVICE_ACCOUNT_KEY) {
    return {
      ok: false,
      detail: "Google Cloud not configured — set the GCP_SERVICE_ACCOUNT_KEY secret (the service-account JSON).",
    };
  }

  let key: ServiceAccountKey;
  try {
    key = JSON.parse(env.GCP_SERVICE_ACCOUNT_KEY) as ServiceAccountKey;
  } catch {
    return {
      ok: false,
      detail: "Google Cloud service-account key is not valid JSON — paste the entire downloaded key file.",
    };
  }

  const clientEmail = key.client_email;
  const privateKeyPem = key.private_key;
  const projectId = key.project_id;
  const tokenUri = key.token_uri || "https://oauth2.googleapis.com/token";
  if (!clientEmail || !privateKeyPem || !projectId) {
    return {
      ok: false,
      detail:
        "Google Cloud key JSON is missing client_email, private_key or project_id — use a service-account key, not an OAuth client ID.",
    };
  }

  let accessToken: string;
  try {
    accessToken = await mintGoogleAccessToken({ clientEmail, privateKeyPem, tokenUri });
  } catch (err) {
    return {
      ok: false,
      detail: `Google Cloud auth failed — could not mint an access token: ${errorMessage(err)}. Check the service-account key.`,
    };
  }

  try {
    // testIamPermissions returns the SUBSET of the passed permissions the caller actually holds —
    // role-agnostic (it does not matter whether Viewer, Editor or a custom role grants them). We diff
    // the result against REQUIRED_GCP_PERMISSIONS and report exactly what is missing. The call itself
    // needs no permission, but the project must exist and the Cloud Resource Manager API must be on.
    const response = await fetch(
      `https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(projectId)}:testIamPermissions`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${accessToken}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ permissions: [...REQUIRED_GCP_PERMISSIONS, ...UPDATE_GCP_PERMISSIONS] }),
      },
    );

    if (response.status === 200) {
      const heldBody = (await response.json().catch(() => null)) as { permissions?: string[] } | null;
      const held = new Set(heldBody?.permissions ?? []);
      const missing = REQUIRED_GCP_PERMISSIONS.filter((permission) => !held.has(permission));
      const missingUpdatePermissions = UPDATE_GCP_PERMISSIONS.filter((permission) => !held.has(permission));
      const updateNote = updatePermissionsNote(missingUpdatePermissions);
      // planning/49 Phase 3: the session rows, each in its OWN call. ADVISORY, like the update-path note:
      // neither changes `ok`, and a failure of either only makes that row "unknown".
      const sessionPermissions = await probeSessionPermissions({ accessToken, projectId });
      const actAs = await probeRunServiceAccountActAs({ clientEmail, privateKeyPem, tokenUri, projectId });
      const advisoryNotes = `${updateNote}${sessionPermissions.detail}${actAs.detail}`;
      const sessionFields: Pick<ValidationResult, "missingSessionPermissions" | "runServiceAccountActAs"> = {
        runServiceAccountActAs: actAs.state,
      };
      if (sessionPermissions.missing !== null) {
        sessionFields.missingSessionPermissions = sessionPermissions.missing;
      }
      if (missing.length === 0) {
        return {
          ok: true,
          detail: `Google Cloud authenticated as ${clientEmail}; project "${projectId}" accessible with all ${REQUIRED_GCP_PERMISSIONS.length} required permission(s).${advisoryNotes}`,
          missingUpdatePermissions,
          ...sessionFields,
        };
      }
      return {
        ok: false,
        detail: `Google Cloud authenticated as ${clientEmail}, but the service account is missing ${missing.length} required permission(s): ${missing.join(", ")}. Grant the service account "roles/compute.admin" on the project — it covers every permission the cell provisioner needs.${advisoryNotes}`,
        missingUpdatePermissions,
        ...sessionFields,
      };
    }
    if (response.status === 403) {
      return {
        ok: false,
        detail: `Google Cloud project "${projectId}" permission check was denied (403) — enable the Cloud Resource Manager API on the project, and check the service account can see the project.`,
      };
    }
    if (response.status === 404) {
      return {
        ok: false,
        detail: `Google Cloud project "${projectId}" not found (404) — check project_id in the key JSON.`,
      };
    }
    const body = (await response.json().catch(() => null)) as { error?: { message?: string } } | null;
    const message = body?.error?.message;
    return {
      ok: false,
      detail: `Google Cloud project check failed with HTTP ${response.status}${message ? `: ${message}` : ""}.`,
    };
  } catch (err) {
    return { ok: false, detail: `Google Cloud project check could not be sent: ${errorMessage(err)}.` };
  }
}

// ── Aggregate ─────────────────────────────────────────────────────────────────

// Run every validator in parallel. Independent network calls — no ordering
// requirement — so Promise.all keeps /validate responsive.
export async function validateAll(env: Env): Promise<AllValidations> {
  const [gcp, s3, stripe, ai, r2Provision, cfDns] = await Promise.all([
    validateGCP(env),
    validateS3(env),
    validateStripe(env),
    validateAI(env),
    validateR2Provision(env),
    validateCfDns(env),
  ]);
  return { gcp, s3, stripe, ai, r2Provision, cfDns };
}
