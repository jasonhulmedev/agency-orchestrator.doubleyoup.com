// hub#133 part 2 — branded media on an agency cell (agency Worker side): the Workers route and the HOSTMAP
// entry that send one media host to the AGENCY's own media Worker. The custom hostname (for a customer
// domain) is the hub#46 op set in actuate-custom-hostname.ts; it is not repeated here.
//
//   worker-route-upsert   read the route by its known id (the job's routeId, else the id this Worker
//                         recorded); it points at MEDIA_WORKER_SCRIPT -> "unchanged"; another script ->
//                         refused as foreign. No live known route -> POST `<hostname>/*` -> MEDIA_WORKER_SCRIPT;
//                         created -> "created" + routeId. A POST refused as a duplicate pattern (a route
//                         under an id nobody knows) -> ok:false, unresolved: true.
//   worker-route-delete   read the route by its known id; DELETE it when it points at MEDIA_WORKER_SCRIPT;
//                         another script -> refused as foreign (the agency made it, not the platform). No
//                         live known route -> a probe POST of the pattern: refused as a duplicate ->
//                         ok:false, unresolved: true; created -> the probe is deleted -> "already-absent".
//   media-hostmap-upsert  PUT `<hostname>` -> `<value>` into the HOSTMAP namespace. A PUT overwrites, so a
//                         re-run converges.
//   media-hostmap-delete  DELETE that key; a 404 counts as "already-absent".
//
// WHAT IS PINNED. The script is env.MEDIA_WORKER_SCRIPT (default "doubleyoup-media"). The namespace is
// env.MEDIA_HOSTMAP_KV_ID, or else the account's namespace titled "HOSTMAP" (the same lookup orchestrator
// src/cloudflare.ts uses for the platform). A signed job names neither, so it can not route another script
// or write another namespace.
//
// THE ZONE. The route ops resolve the job's zone NAME with the agency's own CF_DNS_API_TOKEN (resolveZoneId,
// the dns-record-upsert lookup), so a job can only act on a zone that token can see. The upsert then
// accepts the hostname only when it is the zone or a name under it (`<slug>-media.<agency zone>`), or when
// it is already a custom hostname of THAT zone (`media.<customer domain>`, made by custom-hostname-upsert
// first). Any other hostname is refused before a route is written. The delete needs no such proof: it
// removes only the exact route `<hostname>/*` in that zone, and only when it points at the media Worker,
// so it still works after the custom hostname is gone.
//
// NO ZONE-WIDE SCAN, ON ANY PATH. Cloudflare can not read a route by pattern, only list them all, and a
// list per host costs O(routes in the zone) per op. So every lookup is by id: the routeId the platform
// stored from the upsert, else the id this Worker recorded when it created the route (NonceStore Durable
// Object, one instance per zone, one row per media host). When no known id names a live route, the op asks
// Cloudflare with a POST of the pattern, which Cloudflare refuses for an existing pattern. A refusal means
// a route exists under an unknown id (a hand-made route, or a replacement of a stale id): the op reports
// `unresolved` and changes nothing. It never answers "already-absent" while such a route may exist.
//
// THE ACCOUNT of the HOSTMAP namespace is MEDIA_ACCOUNT_ID, or the token's only account (media-account.ts).
//
// Every call uses the agency's own CF_DNS_API_TOKEN, which needs Zone → Workers Routes: Edit (routes) and
// Account → Workers KV Storage: Edit (HOSTMAP) for these ops.

import type { Env } from "./env.js";
import { CF_API, cloudflareErrorMessage, cloudflareHeaders, resolveZoneId, type CloudflareEnvelope } from "./actuate.js";
import { findCustomHostname } from "./actuate-custom-hostname.js";
import { isNameAtOrUnderZone } from "./dispatch-params-custom-hostname.js";
import { resolveMediaAccountId } from "./media-account.js";
import {
  mediaWorkerRoutePatternFor,
  type MediaHostmapDeleteParams,
  type MediaHostmapUpsertParams,
  type MediaWorkerRouteParams,
} from "./dispatch-params-branded-media.js";
import { errorMessage, isWorkerScriptName } from "./util.js";

/** The agency media Worker's script name when MEDIA_WORKER_SCRIPT is not set. */
export const DEFAULT_MEDIA_WORKER_SCRIPT = "doubleyoup-media";

/** The title of the KV namespace the media Worker binds as HOSTMAP. */
export const MEDIA_HOSTMAP_NAMESPACE_TITLE = "HOSTMAP";

// A Workers KV namespace id is 32 lowercase hex characters.
const KV_NAMESPACE_ID_RE = /^[0-9a-f]{32}$/;

// Cloudflare lists KV namespaces at most 100 per page. Bounded, so a huge account can not keep one
// request spinning; an account with more than 1000 namespaces pins MEDIA_HOSTMAP_KV_ID instead.
const KV_NAMESPACE_PAGE_SIZE = 100;
const KV_NAMESPACE_MAX_PAGES = 10;

const MEDIA_ROUTE_UNAUTHORIZED_HINT =
  "Cloudflare denied the Workers route call — CF_DNS_API_TOKEN needs Zone → Workers Routes: Edit on this zone.";
// Cloudflare's error code for "a route with the same pattern already exists".
const MEDIA_ROUTE_DUPLICATE_PATTERN_CODE = 10020;
const MEDIA_HOSTMAP_UNAUTHORIZED_HINT =
  "Cloudflare denied the Workers KV call — CF_DNS_API_TOKEN needs Account → Workers KV Storage: Edit.";

export type MediaWorkerRouteUpsertResult =
  | { ok: true; op: "worker-route-upsert"; pattern: string; script: string; routeId: string; status: "created" | "unchanged" }
  | { ok: false; op: "worker-route-upsert"; pattern: string; script: string; detail: string; foreign?: true; unresolved?: true };

export type MediaWorkerRouteDeleteResult =
  | { ok: true; op: "worker-route-delete"; pattern: string; script: string; status: "deleted" | "already-absent" }
  | { ok: false; op: "worker-route-delete"; pattern: string; script: string; detail: string; foreign?: true; unresolved?: true };

export type MediaHostmapUpsertResult =
  | { ok: true; op: "media-hostmap-upsert"; hostname: string; value: string; status: "written" }
  | { ok: false; op: "media-hostmap-upsert"; hostname: string; detail: string };

export type MediaHostmapDeleteResult =
  | { ok: true; op: "media-hostmap-delete"; hostname: string; status: "deleted" | "already-absent" }
  | { ok: false; op: "media-hostmap-delete"; hostname: string; detail: string };

interface CloudflareMediaRoute {
  id?: string;
  pattern?: string;
  script?: string;
}

/** The script every media route points at, or the reason MEDIA_WORKER_SCRIPT is unusable. */
export function configuredMediaWorkerScript(env: Env): { script: string } | { error: string } {
  const configured = env.MEDIA_WORKER_SCRIPT;
  if (configured === undefined || configured === "") {
    return { script: DEFAULT_MEDIA_WORKER_SCRIPT };
  }
  if (!isWorkerScriptName(configured)) {
    return { error: "MEDIA_WORKER_SCRIPT is not a Worker script name (lowercase letters, digits, \"-\" and \"_\", at most 63 characters)." };
  }
  return { script: configured };
}

/** The script name to report in a refusal when MEDIA_WORKER_SCRIPT is unusable. */
function reportedScriptOf(env: Env): string {
  const configured = configuredMediaWorkerScript(env);
  if ("script" in configured) {
    return configured.script;
  }
  return "(invalid MEDIA_WORKER_SCRIPT)";
}

/**
 * ONE route, read by its id: the route, null when Cloudflare has no route with that id, or the reason
 * the read failed. This is the bounded lookup of the steady path (one request, whatever the zone holds).
 */
async function readMediaRouteById(
  token: string,
  zoneId: string,
  routeId: string,
): Promise<{ route: CloudflareMediaRoute | null } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zoneId)}/workers/routes/${encodeURIComponent(routeId)}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to read the Workers route: ${errorMessage(err)}` };
  }
  if (response.status === 404) {
    await response.text().catch(() => "");
    return { route: null };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return { error: MEDIA_ROUTE_UNAUTHORIZED_HINT };
  }
  const route = body?.result as CloudflareMediaRoute | null | undefined;
  if (!response.ok || !body?.success || !route || typeof route !== "object") {
    return { error: `Workers route read failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return { route: { ...route, id: routeId } };
}

/** The Durable Object instance that records the media route ids of one zone (NonceStore, see there). */
function mediaRouteIdStore(env: Env, zoneId: string) {
  return env.NONCE_STORE.get(env.NONCE_STORE.idFromName(`media-routes:${zoneId}`));
}

type KnownMediaRoute =
  | { route: CloudflareMediaRoute & { id: string } }
  | { route: null }
  | { error: string };

/**
 * The media route of `pattern`, read by id, never by listing the zone. It tries the job's routeId, then the
 * id this Worker recorded when it created the route — at most two reads. `{route: null}` means "no LIVE
 * route under a known id"; it does NOT mean the pattern has no route (a route made elsewhere, or a
 * replacement of a stale id, has an id nobody passed here). A known id whose route has ANOTHER pattern is
 * refused: the id is a hint, never an authority, so it can not point an op at some other host's route.
 * A recorded id whose route is gone is forgotten.
 */
async function readKnownMediaRoute(
  token: string,
  env: Env,
  zoneId: string,
  pattern: string,
  jobRouteId: string | undefined,
): Promise<KnownMediaRoute> {
  const store = mediaRouteIdStore(env, zoneId);
  const recordedRouteId = await store.readMediaRouteId(pattern);
  const knownRouteIds: string[] = [];
  if (jobRouteId !== undefined) {
    knownRouteIds.push(jobRouteId);
  }
  if (recordedRouteId !== null && recordedRouteId !== jobRouteId) {
    knownRouteIds.push(recordedRouteId);
  }

  for (const routeId of knownRouteIds) {
    const byId = await readMediaRouteById(token, zoneId, routeId);
    if ("error" in byId) {
      return byId;
    }
    if (byId.route === null) {
      if (routeId === recordedRouteId) {
        await store.clearMediaRouteId(pattern);
      }
      continue;
    }
    if (byId.route.pattern !== pattern) {
      return { error: `Workers route ${routeId} has the pattern "${byId.route.pattern ?? "(none)"}", not "${pattern}" — refusing to act on it.` };
    }
    return { route: { ...byId.route, id: routeId } };
  }
  return { route: null };
}

type MediaRouteCreateOutcome =
  | { created: string }
  | { duplicate: true }
  | { error: string };

/**
 * POST `pattern` -> `script`. Cloudflare refuses a second route with the same pattern (code 10020), so a
 * create can never make a duplicate, and that refusal is itself the bounded answer to "does a route with
 * this pattern exist?" (no list of the zone).
 */
async function createMediaRoute(token: string, zoneId: string, pattern: string, script: string): Promise<MediaRouteCreateOutcome> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zoneId)}/workers/routes`, {
      method: "POST",
      headers: cloudflareHeaders(token),
      body: JSON.stringify({ pattern, script }),
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to create the Workers route: ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return { error: MEDIA_ROUTE_UNAUTHORIZED_HINT };
  }
  const created = body?.result as { id?: unknown } | null | undefined;
  if (response.ok && body?.success && typeof created?.id === "string" && created.id.length > 0) {
    return { created: created.id };
  }
  const isDuplicatePattern = (body?.errors ?? []).some(
    (error) => error.code === MEDIA_ROUTE_DUPLICATE_PATTERN_CODE || /already exists/i.test(error.message ?? ""),
  );
  if (isDuplicatePattern) {
    return { duplicate: true };
  }
  return { error: `Workers route create failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
}

/** DELETE one route by id: deleted, already gone (404), or the reason it failed. */
async function deleteMediaRouteById(token: string, zoneId: string, routeId: string): Promise<{ deleted: boolean } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zoneId)}/workers/routes/${encodeURIComponent(routeId)}`, {
      method: "DELETE",
      headers: cloudflareHeaders(token),
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to delete the Workers route: ${errorMessage(err)}` };
  }
  if (response.status === 404) {
    await response.text().catch(() => "");
    return { deleted: false };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return { error: MEDIA_ROUTE_UNAUTHORIZED_HINT };
  }
  if (!response.ok || !body?.success) {
    return { error: `Workers route delete failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return { deleted: true };
}

/** The detail of an `unresolved` result: a route for the pattern exists, and no known id names it. */
function unresolvedRouteDetail(pattern: string): string {
  return (
    `a Workers route for "${pattern}" exists, but neither the job nor this Worker knows its id, and this op ` +
    `does not list the zone's routes to find it. It was left unchanged. Re-run with its routeId.`
  );
}

/**
 * Null when the media host may get a route in this zone, else the reason it may not. The host is allowed
 * when it is the zone or under it, or when it is already a custom hostname of this zone (a customer domain
 * the agency zone serves through Cloudflare for SaaS).
 */
async function mediaHostZoneRefusal(token: string, zone: { name: string; id: string }, hostname: string): Promise<string | null> {
  if (isNameAtOrUnderZone(hostname, zone.name)) {
    return null;
  }
  const lookup = await findCustomHostname({ token, zone: zone.name, zoneId: zone.id }, hostname);
  if ("error" in lookup) {
    return `hostname "${hostname}" is outside zone "${zone.name}", and its custom hostname could not be checked: ${lookup.error}`;
  }
  if (lookup.found === null) {
    return `hostname "${hostname}" is not in zone "${zone.name}" and is not a custom hostname of it — create it with custom-hostname-upsert first.`;
  }
  return null;
}

export async function actuateMediaWorkerRouteUpsert(params: MediaWorkerRouteParams, env: Env): Promise<MediaWorkerRouteUpsertResult> {
  const pattern = mediaWorkerRoutePatternFor(params.hostname);
  const reportedScript = reportedScriptOf(env);
  const failure = (detail: string): MediaWorkerRouteUpsertResult => ({
    ok: false,
    op: "worker-route-upsert",
    pattern,
    script: reportedScript,
    detail,
  });

  const configuredScript = configuredMediaWorkerScript(env);
  if ("error" in configuredScript) {
    return failure(configuredScript.error);
  }
  const script = configuredScript.script;
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return failure("CF_DNS_API_TOKEN is not configured on this Worker.");
  }
  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) {
    return failure(zone.error);
  }
  const zoneRefusal = await mediaHostZoneRefusal(token, { name: params.zone, id: zone.id }, params.hostname);
  if (zoneRefusal !== null) {
    return failure(zoneRefusal);
  }

  // A re-run: one read by the known id (the job's, else the one recorded at create).
  const known = await readKnownMediaRoute(token, env, zone.id, pattern, params.routeId);
  if ("error" in known) {
    return failure(known.error);
  }
  if (known.route !== null) {
    const route = known.route;
    if (route.script !== script) {
      // The agency (or another tool) routed this host elsewhere on purpose. Never take that route over.
      const otherScript = route.script ?? "(no script)";
      return {
        ok: false,
        op: "worker-route-upsert",
        pattern,
        script,
        detail: `a Workers route for "${pattern}" already points at "${otherScript}", not "${script}". It was left unchanged.`,
        foreign: true,
      };
    }
    // Record it, so a later call without the routeId still reads this one route.
    await mediaRouteIdStore(env, zone.id).writeMediaRouteId(pattern, route.id);
    return { ok: true, op: "worker-route-upsert", pattern, script, routeId: route.id, status: "unchanged" };
  }

  // No live route under a known id: create it. On a new host this POST is the only Cloudflare write.
  const creation = await createMediaRoute(token, zone.id, pattern, script);
  if ("error" in creation) {
    return failure(creation.error);
  }
  if ("duplicate" in creation) {
    // A route for the pattern exists under an id nobody passed (made by hand, or a replacement of the
    // stored one). Finding it would mean listing every route of the zone, so say so instead.
    return { ok: false, op: "worker-route-upsert", pattern, script, detail: unresolvedRouteDetail(pattern), unresolved: true };
  }
  await mediaRouteIdStore(env, zone.id).writeMediaRouteId(pattern, creation.created);
  return { ok: true, op: "worker-route-upsert", pattern, script, routeId: creation.created, status: "created" };
}

export async function actuateMediaWorkerRouteDelete(params: MediaWorkerRouteParams, env: Env): Promise<MediaWorkerRouteDeleteResult> {
  const pattern = mediaWorkerRoutePatternFor(params.hostname);
  const reportedScript = reportedScriptOf(env);
  const failure = (detail: string): MediaWorkerRouteDeleteResult => ({
    ok: false,
    op: "worker-route-delete",
    pattern,
    script: reportedScript,
    detail,
  });

  const configuredScript = configuredMediaWorkerScript(env);
  if ("error" in configuredScript) {
    return failure(configuredScript.error);
  }
  const script = configuredScript.script;
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return failure("CF_DNS_API_TOKEN is not configured on this Worker.");
  }
  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) {
    return failure(zone.error);
  }
  const store = mediaRouteIdStore(env, zone.id);

  const known = await readKnownMediaRoute(token, env, zone.id, pattern, params.routeId);
  if ("error" in known) {
    return failure(known.error);
  }
  if (known.route !== null) {
    const route = known.route;
    if (route.script !== script) {
      const otherScript = route.script ?? "(no script)";
      return {
        ok: false,
        op: "worker-route-delete",
        pattern,
        script,
        detail: `the Workers route for "${pattern}" points at "${otherScript}", not "${script}", so this platform did not make it. It was left in place.`,
        foreign: true,
      };
    }
    const deletion = await deleteMediaRouteById(token, zone.id, route.id);
    if ("error" in deletion) {
      return failure(deletion.error);
    }
    await store.clearMediaRouteId(pattern);
    // A route that vanished between the read and the delete (404) is the state the caller asked for.
    if (deletion.deleted) {
      return { ok: true, op: "worker-route-delete", pattern, script, status: "deleted" };
    }
    return { ok: true, op: "worker-route-delete", pattern, script, status: "already-absent" };
  }

  // No live route under a known id. That is NOT proof the pattern has no route: a stale id may have been
  // replaced by another route. Ask Cloudflare with a create, which it refuses for an existing pattern —
  // two calls at most, never a list of the zone. A create that succeeds proves the pattern was free; the
  // probe route is removed at once (it points at the media Worker this op is unrouting anyway).
  const probe = await createMediaRoute(token, zone.id, pattern, script);
  if ("error" in probe) {
    return failure(`could not check whether a Workers route for "${pattern}" exists: ${probe.error}`);
  }
  if ("duplicate" in probe) {
    return { ok: false, op: "worker-route-delete", pattern, script, detail: unresolvedRouteDetail(pattern), unresolved: true };
  }
  const probeRemoval = await deleteMediaRouteById(token, zone.id, probe.created);
  if ("error" in probeRemoval) {
    // Keep the probe's id, so a re-run of this delete reads and removes exactly that route.
    await store.writeMediaRouteId(pattern, probe.created);
    return failure(`the probe route ${probe.created} for "${pattern}" could not be removed: ${probeRemoval.error} Re-run the delete.`);
  }
  return { ok: true, op: "worker-route-delete", pattern, script, status: "already-absent" };
}

// ── HOSTMAP ─────────────────────────────────────────────────────────────────────────

/** The account and the HOSTMAP namespace id, or the reason they could not be found. */
async function resolveHostmapNamespace(token: string, env: Env): Promise<{ accountId: string; namespaceId: string } | { error: string }> {
  // MEDIA_ACCOUNT_ID, or the token's ONLY account. Never "the first account it lists": a token that sees
  // two accounts would then write another account's HOSTMAP and report success.
  const account = await resolveMediaAccountId(token, env, MEDIA_HOSTMAP_UNAUTHORIZED_HINT);
  if (!account.ok) {
    return { error: account.error };
  }
  const pinnedId = env.MEDIA_HOSTMAP_KV_ID;
  if (pinnedId !== undefined && pinnedId !== "") {
    if (!KV_NAMESPACE_ID_RE.test(pinnedId)) {
      return { error: "MEDIA_HOSTMAP_KV_ID is not a Workers KV namespace id (32 lowercase hex characters)." };
    }
    return { accountId: account.id, namespaceId: pinnedId };
  }

  for (let page = 1; page <= KV_NAMESPACE_MAX_PAGES; page++) {
    const query = new URLSearchParams({ per_page: String(KV_NAMESPACE_PAGE_SIZE), page: String(page) });
    let response: Response;
    try {
      response = await fetch(`${CF_API}/accounts/${encodeURIComponent(account.id)}/storage/kv/namespaces?${query.toString()}`, {
        headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      });
    } catch (err) {
      return { error: `could not reach Cloudflare to list KV namespaces: ${errorMessage(err)}` };
    }
    const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
    if (response.status === 401 || response.status === 403) {
      return { error: MEDIA_HOSTMAP_UNAUTHORIZED_HINT };
    }
    if (!body?.success || !Array.isArray(body.result)) {
      return { error: `KV namespace lookup failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
    }
    const namespaces = body.result as Array<{ id?: unknown; title?: unknown }>;
    for (const namespace of namespaces) {
      if (namespace.title === MEDIA_HOSTMAP_NAMESPACE_TITLE && typeof namespace.id === "string" && namespace.id.length > 0) {
        return { accountId: account.id, namespaceId: namespace.id };
      }
    }
    // A short page is the last page.
    if (namespaces.length < KV_NAMESPACE_PAGE_SIZE) {
      break;
    }
  }
  return {
    error: `no Workers KV namespace titled "${MEDIA_HOSTMAP_NAMESPACE_TITLE}" on the account — deploy the media Worker with its HOSTMAP binding, or set MEDIA_HOSTMAP_KV_ID.`,
  };
}

function hostmapValueUrl(accountId: string, namespaceId: string, hostname: string): string {
  return `${CF_API}/accounts/${encodeURIComponent(accountId)}/storage/kv/namespaces/${encodeURIComponent(namespaceId)}/values/${encodeURIComponent(hostname)}`;
}

export async function actuateMediaHostmapUpsert(params: MediaHostmapUpsertParams, env: Env): Promise<MediaHostmapUpsertResult> {
  const { hostname, value } = params;
  const failure = (detail: string): MediaHostmapUpsertResult => ({ ok: false, op: "media-hostmap-upsert", hostname, detail });

  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return failure("CF_DNS_API_TOKEN is not configured on this Worker.");
  }
  const namespace = await resolveHostmapNamespace(token, env);
  if ("error" in namespace) {
    return failure(namespace.error);
  }

  let response: Response;
  try {
    // The media Worker reads the value verbatim, so it is stored as raw text, never as JSON.
    response = await fetch(hostmapValueUrl(namespace.accountId, namespace.namespaceId, hostname), {
      method: "PUT",
      headers: { authorization: `Bearer ${token}`, "content-type": "text/plain" },
      body: value,
    });
  } catch (err) {
    return failure(`could not reach Cloudflare to write the HOSTMAP entry: ${errorMessage(err)}`);
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return failure(MEDIA_HOSTMAP_UNAUTHORIZED_HINT);
  }
  if (!response.ok || !body?.success) {
    return failure(`HOSTMAP write failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`);
  }
  return { ok: true, op: "media-hostmap-upsert", hostname, value, status: "written" };
}

export async function actuateMediaHostmapDelete(params: MediaHostmapDeleteParams, env: Env): Promise<MediaHostmapDeleteResult> {
  const { hostname } = params;
  const failure = (detail: string): MediaHostmapDeleteResult => ({ ok: false, op: "media-hostmap-delete", hostname, detail });

  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return failure("CF_DNS_API_TOKEN is not configured on this Worker.");
  }
  const namespace = await resolveHostmapNamespace(token, env);
  if ("error" in namespace) {
    return failure(namespace.error);
  }

  let response: Response;
  try {
    response = await fetch(hostmapValueUrl(namespace.accountId, namespace.namespaceId, hostname), {
      method: "DELETE",
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return failure(`could not reach Cloudflare to delete the HOSTMAP entry: ${errorMessage(err)}`);
  }
  if (response.status === 404) {
    await response.text().catch(() => "");
    return { ok: true, op: "media-hostmap-delete", hostname, status: "already-absent" };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return failure(MEDIA_HOSTMAP_UNAUTHORIZED_HINT);
  }
  if (!response.ok || !body?.success) {
    return failure(`HOSTMAP delete failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`);
  }
  return { ok: true, op: "media-hostmap-delete", hostname, status: "deleted" };
}
