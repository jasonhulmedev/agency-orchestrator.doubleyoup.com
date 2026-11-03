// hub#133 part 2 — the PARAMS of the four branded-media ops (agency Worker side): worker-route-upsert,
// worker-route-delete, media-hostmap-upsert and media-hostmap-delete. Branded media on an agency cell
// serves a site's media from a host of its own (`<slug>-media.<agency zone>` or `media.<customer domain>`)
// through the AGENCY's media Worker, in the agency's own Cloudflare account. The three Cloudflare objects
// behind one such host are:
//   1. a Cloudflare-for-SaaS custom hostname, for a customer domain only: the hub#46 ops
//      custom-hostname-upsert / -get / -delete (dispatch-params-custom-hostname.ts) — ONE shared op set;
//   2. a Workers route `<hostname>/*` -> the agency media Worker (worker-route-*);
//   3. a HOSTMAP KV entry `<hostname>` -> the site's media prefix (media-hostmap-*).
//
// WHY A FILE OF ITS OWN. dispatch-params.ts is shared by many branches at once. These validators sit
// here so a parallel branch that appends to dispatch-params.ts does not conflict with this one.
//
// WHAT A JOB CAN NOT NAME. The route's SCRIPT is not a parameter: it is env.MEDIA_WORKER_SCRIPT. The KV
// NAMESPACE is not a parameter: it is env.MEDIA_HOSTMAP_KV_ID or the namespace titled "HOSTMAP". The
// route PATTERN is derived, `<hostname>/*`, and the hostname grammar has no wildcard. Every validator
// refuses an unknown key, so a job that tries to carry a `script` or a `namespaceId` is refused, not
// silently trimmed. So no signed job can route any script or write any KV key.
//
// THE ZONE. worker-route-* carry the agency zone NAME. The actuator resolves it with the agency's own
// CF_DNS_API_TOKEN (exactly as dns-record-upsert does), so a job can only act on a zone the agency's
// token can see. For the upsert, the hostname must be the zone or a name under it, OR a custom hostname
// that already exists on that zone — the actuator checks that before it creates the route. The delete
// removes only the exact route `<hostname>/*` in that zone and only when it points at the media Worker,
// so it needs no such check (and still works after the custom hostname is gone).
//
// THE ROUTE ID. Both route ops take an optional `routeId`, the id the upsert returned. The actuator reads
// that one route by id (else the id the Worker itself recorded at create), and never lists the zone's
// routes (one list per host would be quadratic work across a zone with many branded hosts). The id is
// re-checked against Cloudflare, so it selects a route but grants nothing.

import type { ParamsVerdict } from "./dispatch-params.js";
import { isCustomHostnameFqdn } from "./dispatch-params-custom-hostname.js";

/**
 * The media Worker's SLUG_PATTERN (media-worker.doubleyoup.com src/index.js). The Worker reads the HOSTMAP
 * value as the site's media prefix, refuses any value outside this pattern, and derives the bucket
 * `doubleyoup-media-<value>` from it, so a value the Worker would refuse is refused here before it is written.
 */
export const MEDIA_HOSTMAP_VALUE_RE = /^[a-z0-9-]{1,46}$/;

// The same zone-apex grammar dns-record-upsert accepts (dispatch-params.ts DNS_ZONE_RE), without "_":
// a zone that owns a media host is a host name.
const MEDIA_ZONE_LABEL = "(?!-)[a-z0-9-]{1,63}(?<!-)";
const MEDIA_ZONE_RE = new RegExp(`^${MEDIA_ZONE_LABEL}(\\.${MEDIA_ZONE_LABEL})+$`);
const MEDIA_ZONE_MAX_LENGTH = 253;

const MEDIA_HOSTNAME_RULE =
  "must be a lowercase fully-qualified domain name (letters, digits and hyphens, two or more labels, no wildcard, no trailing dot)";

/** worker-route-upsert / worker-route-delete: the media route for ONE exact host. */
export interface MediaWorkerRouteParams {
  /** The agency zone NAME (e.g. "agency.example"); resolved to a zone id with the agency's own token. */
  zone: string;
  /** The media host, e.g. "acme-media.agency.example" or "media.customer.example". */
  hostname: string;
  /**
   * Optional: the route id an earlier worker-route-upsert returned (the platform stores it with the host).
   * With it, the op reads and deletes that ONE route directly; the Worker's own record of the id is the
   * fallback, and no path lists every route in the zone.
   * It is re-checked against Cloudflare (pattern and script), so a wrong id is refused, never trusted.
   */
  routeId?: string;
}

// A Workers route id is 32 lowercase hex characters.
const MEDIA_ROUTE_ID_RE = /^[0-9a-f]{32}$/;

/** media-hostmap-upsert: write `hostname -> value` into the pinned HOSTMAP namespace. */
export interface MediaHostmapUpsertParams {
  hostname: string;
  /** The site's media prefix, in the media Worker's SLUG_PATTERN. */
  value: string;
}

/** media-hostmap-delete: remove the HOSTMAP entry of one host. */
export interface MediaHostmapDeleteParams {
  hostname: string;
}

/** The route pattern of one media host. Always an exact host, never a wildcard. */
export function mediaWorkerRoutePatternFor(hostname: string): string {
  return `${hostname}/*`;
}

/** True when `value` is a lowercase zone apex name in the grammar above. */
export function isMediaZoneName(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  if (value.length > MEDIA_ZONE_MAX_LENGTH) {
    return false;
  }
  return MEDIA_ZONE_RE.test(value);
}

/** The reason `raw` carries a key other than `allowedKeys`, or null. */
function unknownKeyReason(raw: Record<string, unknown>, allowedKeys: readonly string[]): string | null {
  for (const key of Object.keys(raw)) {
    if (!allowedKeys.includes(key)) {
      return `unknown key "${key}" (allowed: ${allowedKeys.join(", ")})`;
    }
  }
  return null;
}

function isPlainParamsObject(raw: unknown): raw is Record<string, unknown> {
  if (typeof raw !== "object" || raw === null) {
    return false;
  }
  return !Array.isArray(raw);
}

function validateMediaWorkerRouteParams(raw: unknown): ParamsVerdict<MediaWorkerRouteParams> {
  if (!isPlainParamsObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, ["zone", "hostname", "routeId"]);
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (!isMediaZoneName(raw.zone)) {
    return { ok: false, reason: "zone must be a lowercase zone name (two or more labels, no wildcard)" };
  }
  if (!isCustomHostnameFqdn(raw.hostname)) {
    return { ok: false, reason: `hostname ${MEDIA_HOSTNAME_RULE}` };
  }
  if (raw.routeId === undefined) {
    return { ok: true, params: { zone: raw.zone, hostname: raw.hostname } };
  }
  if (typeof raw.routeId !== "string" || !MEDIA_ROUTE_ID_RE.test(raw.routeId)) {
    return { ok: false, reason: "routeId must be a Workers route id (32 lowercase hex characters)" };
  }
  return { ok: true, params: { zone: raw.zone, hostname: raw.hostname, routeId: raw.routeId } };
}

export function validateMediaWorkerRouteUpsertParams(raw: unknown): ParamsVerdict<MediaWorkerRouteParams> {
  return validateMediaWorkerRouteParams(raw);
}

export function validateMediaWorkerRouteDeleteParams(raw: unknown): ParamsVerdict<MediaWorkerRouteParams> {
  return validateMediaWorkerRouteParams(raw);
}

export function validateMediaHostmapUpsertParams(raw: unknown): ParamsVerdict<MediaHostmapUpsertParams> {
  if (!isPlainParamsObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, ["hostname", "value"]);
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (!isCustomHostnameFqdn(raw.hostname)) {
    return { ok: false, reason: `hostname ${MEDIA_HOSTNAME_RULE}` };
  }
  if (typeof raw.value !== "string" || !MEDIA_HOSTMAP_VALUE_RE.test(raw.value)) {
    return { ok: false, reason: "value must match the media Worker's slug pattern (1-46 of a-z, 0-9 and \"-\")" };
  }
  return { ok: true, params: { hostname: raw.hostname, value: raw.value } };
}

export function validateMediaHostmapDeleteParams(raw: unknown): ParamsVerdict<MediaHostmapDeleteParams> {
  if (!isPlainParamsObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, ["hostname"]);
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (!isCustomHostnameFqdn(raw.hostname)) {
    return { ok: false, reason: `hostname ${MEDIA_HOSTNAME_RULE}` };
  }
  return { ok: true, params: { hostname: raw.hostname } };
}
