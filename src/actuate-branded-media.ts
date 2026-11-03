// hub#133 part 2 — branded media on an agency cell (agency Worker side): the Workers route and the HOSTMAP
// entry that send one media host to the AGENCY's own media Worker. The custom hostname (for a customer
// domain) is the hub#46 op set in actuate-custom-hostname.ts; it is not repeated here.
//
//   worker-route-upsert   find the route `<hostname>/*` in the zone; none -> POST it to MEDIA_WORKER_SCRIPT;
//                         one to that script -> "unchanged"; one to another script -> refused as foreign.
//   worker-route-delete   DELETE that route when it points at MEDIA_WORKER_SCRIPT; absent -> "already-absent";
//                         another script -> refused as foreign (the agency made it, not the platform).
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
// Every call uses the agency's own CF_DNS_API_TOKEN, which needs Zone → Workers Routes: Edit (routes) and
// Account → Workers KV Storage: Edit (HOSTMAP) for these ops.

import type { Env } from "./env.js";
import { CF_API, cloudflareErrorMessage, cloudflareHeaders, resolveAccountId, resolveZoneId, type CloudflareEnvelope } from "./actuate.js";
import { findCustomHostname } from "./actuate-custom-hostname.js";
import { isNameAtOrUnderZone } from "./dispatch-params-custom-hostname.js";
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

/** The routes in a zone whose pattern is EXACTLY `pattern`, or the reason the list failed. */
async function findMediaRoutesByPattern(
  token: string,
  zoneId: string,
  pattern: string,
): Promise<{ routes: CloudflareMediaRoute[] } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zoneId)}/workers/routes`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to list Workers routes: ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return { error: MEDIA_ROUTE_UNAUTHORIZED_HINT };
  }
  if (!body?.success || !Array.isArray(body.result)) {
    return { error: `Workers route lookup failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  // Exact pattern only: `*.<zone>/*` or `<host>/admin*` is a DIFFERENT route and is never touched.
  const routes = (body.result as CloudflareMediaRoute[]).filter((route) => route.id && route.pattern === pattern);
  return { routes };
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

  const existing = await findMediaRoutesByPattern(token, zone.id, pattern);
  if ("error" in existing) {
    return failure(existing.error);
  }
  if (existing.routes.length > 1) {
    return failure(`${existing.routes.length} Workers routes already match "${pattern}" — ambiguous, refusing to change any of them.`);
  }
  const existingRoute = existing.routes[0];
  if (existingRoute) {
    if (existingRoute.script === script) {
      return { ok: true, op: "worker-route-upsert", pattern, script, routeId: existingRoute.id as string, status: "unchanged" };
    }
    // The agency (or another tool) routed this host elsewhere on purpose. Never take that route over.
    const otherScript = existingRoute.script ?? "(no script)";
    return {
      ok: false,
      op: "worker-route-upsert",
      pattern,
      script,
      detail: `a Workers route for "${pattern}" already points at "${otherScript}", not "${script}". It was left unchanged.`,
      foreign: true,
    };
  }

  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zone.id)}/workers/routes`, {
      method: "POST",
      headers: cloudflareHeaders(token),
      body: JSON.stringify({ pattern, script }),
    });
  } catch (err) {
    return failure(`could not reach Cloudflare to create the Workers route: ${errorMessage(err)}`);
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return failure(MEDIA_ROUTE_UNAUTHORIZED_HINT);
  }
  const created = body?.result as { id?: unknown } | null | undefined;
  if (!response.ok || !body?.success || typeof created?.id !== "string" || created.id.length === 0) {
    return failure(`Workers route create failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`);
  }
  return { ok: true, op: "worker-route-upsert", pattern, script, routeId: created.id, status: "created" };
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
  const existing = await findMediaRoutesByPattern(token, zone.id, pattern);
  if ("error" in existing) {
    return failure(existing.error);
  }
  if (existing.routes.length === 0) {
    return { ok: true, op: "worker-route-delete", pattern, script, status: "already-absent" };
  }
  if (existing.routes.length > 1) {
    return failure(`${existing.routes.length} Workers routes match "${pattern}" — ambiguous, refusing to delete one.`);
  }
  const route = existing.routes[0];
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

  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zone.id)}/workers/routes/${encodeURIComponent(route.id as string)}`, {
      method: "DELETE",
      headers: cloudflareHeaders(token),
    });
  } catch (err) {
    return failure(`could not reach Cloudflare to delete the Workers route: ${errorMessage(err)}`);
  }
  // A route that vanished between the list and the delete is the state the caller asked for.
  if (response.status === 404) {
    await response.text().catch(() => "");
    return { ok: true, op: "worker-route-delete", pattern, script, status: "already-absent" };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return failure(MEDIA_ROUTE_UNAUTHORIZED_HINT);
  }
  if (!response.ok || !body?.success) {
    return failure(`Workers route delete failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`);
  }
  return { ok: true, op: "worker-route-delete", pattern, script, status: "deleted" };
}

// ── HOSTMAP ─────────────────────────────────────────────────────────────────────────

/** The account and the HOSTMAP namespace id, or the reason they could not be found. */
async function resolveHostmapNamespace(token: string, env: Env): Promise<{ accountId: string; namespaceId: string } | { error: string }> {
  const account = await resolveAccountId(token, MEDIA_HOSTMAP_UNAUTHORIZED_HINT);
  if ("error" in account) {
    return account;
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
