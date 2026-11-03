// hub#133 part 2 — branded media on an agency cell (agency Worker side): the Workers route and the HOSTMAP
// entry that send one media host to the AGENCY's own media Worker. The custom hostname (for a customer
// domain) is the hub#46 op set in actuate-custom-hostname.ts; it is not repeated here.
//
//   worker-route-upsert   find the route of `<hostname>/*` (see THE ROUTE LOOKUP); it points at
//                         MEDIA_WORKER_SCRIPT -> "unchanged" + routeId; another script -> refused as foreign.
//                         No route -> POST `<hostname>/*` -> MEDIA_WORKER_SCRIPT -> "created" + routeId. A
//                         refused POST (a duplicate-pattern race included) -> ok:false; a re-run converges.
//   worker-route-delete   find the route the same way; DELETE it when it points at MEDIA_WORKER_SCRIPT;
//                         another script -> refused as foreign (the agency made it, not the platform). No
//                         route -> "already-absent". The delete never creates anything.
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
// THE ROUTE LOOKUP. Cloudflare reads a route by id or lists the zone's routes; it has no read by pattern.
// Steady path: the platform stores the routeId the upsert returns and passes it back, so a call is one
// read by id. Recovery path (no routeId, a stale one, or a lost upsert response): one list of THIS agency
// zone's routes, filtered to the exact pattern. That list is bounded by Cloudflare's cap of 1,000 Workers
// routes per zone, is scoped to one agency zone and its own token, and does not grow with the number of
// agencies, cells or sites of the platform. The hub#93 workers-route-* ops (findWorkerRoutesByPattern,
// reused here) and orchestrator ensureWorkerRoute use the same shape. A stale routeId therefore never
// turns into a false "already-absent": a 404 on the id falls through to the list, which finds a replacement.
//
// THE ACCOUNT of the HOSTMAP namespace is MEDIA_ACCOUNT_ID, or the token's only account (media-account.ts).
//
// Every call uses the agency's own CF_DNS_API_TOKEN, which needs Zone → Workers Routes: Edit (routes) and
// Account → Workers KV Storage: Edit (HOSTMAP) for these ops.

import type { Env } from "./env.js";
import {
  CF_API,
  cloudflareErrorMessage,
  cloudflareHeaders,
  findWorkerRoutesByPattern,
  resolveZoneId,
  type CloudflareEnvelope,
} from "./actuate.js";
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
const MEDIA_HOSTMAP_UNAUTHORIZED_HINT =
  "Cloudflare denied the Workers KV call — CF_DNS_API_TOKEN needs Account → Workers KV Storage: Edit.";

export type MediaWorkerRouteUpsertResult =
  | { ok: true; op: "worker-route-upsert"; pattern: string; script: string; routeId: string; status: "created" | "unchanged" }
  | { ok: false; op: "worker-route-upsert"; pattern: string; script: string; detail: string; foreign?: true };

export type MediaWorkerRouteDeleteResult =
  | { ok: true; op: "worker-route-delete"; pattern: string; script: string; status: "deleted" | "already-absent" }
  | { ok: false; op: "worker-route-delete"; pattern: string; script: string; detail: string; foreign?: true };

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

type MediaRouteLookup =
  | { route: CloudflareMediaRoute & { id: string } }
  | { route: null }
  | { error: string };

/**
 * The ONE media route of `pattern` in the zone, null when the zone has none, or the reason the lookup failed.
 *
 * Steady path: the job's routeId -> one read by id. A live route with this pattern is the answer. A live
 * route with ANOTHER pattern is refused: the id is a hint, never an authority, so it can not point an op at
 * some other host's route. A 404 (a stale id) falls through to the list, so a replacement route made under
 * a new id is still found — a stale id never turns into a false "already-absent".
 *
 * Recovery path: one list of this agency zone's routes (findWorkerRoutesByPattern, the hub#93 lookup),
 * filtered to the exact pattern. Bounded: see the header comment. Two routes with one pattern is ambiguous
 * and refused (Cloudflare should not allow it).
 */
async function findTheMediaRoute(
  token: string,
  zoneId: string,
  pattern: string,
  jobRouteId: string | undefined,
): Promise<MediaRouteLookup> {
  if (jobRouteId !== undefined) {
    const byId = await readMediaRouteById(token, zoneId, jobRouteId);
    if ("error" in byId) {
      return byId;
    }
    if (byId.route !== null) {
      if (byId.route.pattern !== pattern) {
        return { error: `Workers route ${jobRouteId} has the pattern "${byId.route.pattern ?? "(none)"}", not "${pattern}" — refusing to act on it.` };
      }
      return { route: { ...byId.route, id: jobRouteId } };
    }
  }

  const listed = await findWorkerRoutesByPattern(token, zoneId, pattern);
  if ("error" in listed) {
    return listed;
  }
  if (listed.routes.length === 0) {
    return { route: null };
  }
  if (listed.routes.length > 1) {
    const routeIds = listed.routes.map((route) => route.id).join(", ");
    return { error: `more than one Workers route has the pattern "${pattern}" (${routeIds}); refusing to guess which one is ours.` };
  }
  const onlyRoute = listed.routes[0];
  return { route: { ...onlyRoute, id: onlyRoute.id as string } };
}

/** POST `pattern` -> `script`: the new route's id, or the reason the create failed. */
async function createMediaRoute(token: string, zoneId: string, pattern: string, script: string): Promise<{ created: string } | { error: string }> {
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
  // Any refusal (a duplicate-pattern race included) is reported as is. A re-run lists the zone and converges.
  return { error: `Workers route create failed with HTTP ${response.status}${cloudflareErrorMessage(body)}. Re-run the upsert.` };
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

  const lookup = await findTheMediaRoute(token, zone.id, pattern, params.routeId);
  if ("error" in lookup) {
    return failure(lookup.error);
  }
  if (lookup.route !== null) {
    const route = lookup.route;
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
    return { ok: true, op: "worker-route-upsert", pattern, script, routeId: route.id, status: "unchanged" };
  }

  const creation = await createMediaRoute(token, zone.id, pattern, script);
  if ("error" in creation) {
    return failure(creation.error);
  }
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

  // The delete never creates anything: "not found" comes from the zone's own route list, not from a probe.
  const lookup = await findTheMediaRoute(token, zone.id, pattern, params.routeId);
  if ("error" in lookup) {
    return failure(lookup.error);
  }
  if (lookup.route === null) {
    return { ok: true, op: "worker-route-delete", pattern, script, status: "already-absent" };
  }
  const route = lookup.route;
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
  // A route that vanished between the read and the delete (404) is the state the caller asked for.
  if (deletion.deleted) {
    return { ok: true, op: "worker-route-delete", pattern, script, status: "deleted" };
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
