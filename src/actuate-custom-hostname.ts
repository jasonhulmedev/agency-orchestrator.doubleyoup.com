// hub#46 — the three custom-hostname actuators (agency Worker side), plus the read-only /validate probe.
//
// A customer domain of an agency cell site (www.example.com.au) is a Cloudflare-for-SaaS CUSTOM
// HOSTNAME in the AGENCY's own zone. The customer CNAMEs to `host.<agency zone>`. Cloudflare matches
// the custom hostname, issues its DV certificate (HTTP validation) and forwards the request, with the
// customer's Host header, to the hostname's `custom_origin_server`: the cell's origin host in the same
// zone, a proxied CNAME to the cell's tunnel. The tunnel's catch-all sends it to the web node's nginx,
// which picks the site by server_name.
//
//   custom-hostname-upsert  find the hostname; none -> POST it; `deleted` -> DELETE + POST (the slot
//                           stays occupied until deleted, so a plain POST fails with 1406); anything
//                           else -> leave it as it is and report it. Idempotent: a re-run converges.
//   custom-hostname-get     READ the hostname's status, SSL status and validation errors.
//   custom-hostname-delete  DELETE the hostname; an absent one is "already-absent". Idempotent.
//
// THE ZONE COMES FROM THIS WORKER'S ENV ONLY (CF_CUSTOM_HOSTNAME_ZONE), never from a job. A signed job
// names a hostname, never a zone, so a job can never point this Worker at another zone — even one the
// agency's token can also see. The token is the agency's own CF_DNS_API_TOKEN, which needs
// "SSL and Certificates: Edit" on that zone.
//
// SELF-CONTAINED ON PURPOSE. This module imports no values from actuate.ts or validators.ts: actuate.ts
// imports validators.ts, and validators.ts imports the /validate probe below, so importing either of
// them here would make an import cycle. The small zone lookup is therefore its own copy here.

import type { Env } from "./env.js";
import { errorMessage } from "./util.js";
import {
  type CustomHostnameDeleteParams,
  type CustomHostnameGetParams,
  type CustomHostnameUpsertParams,
  customHostnameZoneReason,
  isCustomHostnameFqdn,
} from "./dispatch-params-custom-hostname.js";

const CLOUDFLARE_API = "https://api.cloudflare.com/client/v4";

// The one scope these ops need beyond Zone:Read, named as the API-token editor shows it.
const CUSTOM_HOSTNAME_SCOPE_HINT = 'CF_DNS_API_TOKEN needs "SSL and Certificates: Edit" on the zone (Zone → SSL and Certificates → Edit in the API-token editor)';

// Cloudflare's `?hostname=` filter is not an exact match, and the list pages at 20 by default. So the
// lookup asks for bigger pages and follows them until the EXACT name appears or a short (last) page
// comes back. Bounded, so a very large zone cannot keep one request spinning.
const CUSTOM_HOSTNAME_PER_PAGE = 50;
const CUSTOM_HOSTNAME_MAX_PAGES = 5;

// Cloudflare's error code for "Duplicate custom hostname": the hostname slot is already taken.
const CLOUDFLARE_DUPLICATE_CUSTOM_HOSTNAME_CODE = 1406;

// A validation error list is reported back to the platform, so it is bounded in count and length.
const MAX_REPORTED_ERRORS = 5;
const MAX_REPORTED_ERROR_LENGTH = 300;

/** Cloudflare's view of one custom hostname, as this Worker reports it. It never carries a token. */
export interface CustomHostnameView {
  id: string;
  hostname: string;
  /** pending | active | moved | deleted | blocked | pending_deletion | ... */
  status: string;
  /** initializing | pending_validation | active | validation_timed_out | ... ("" when Cloudflare gave none). */
  sslStatus: string;
  /** The origin Cloudflare forwards this hostname to, or null when it uses the zone's fallback origin. */
  customOriginServer: string | null;
  /** The hostname's ownership verification errors, as Cloudflare words them (bounded). */
  verificationErrors: string[];
  /** The certificate's validation errors, as Cloudflare words them (bounded). */
  sslValidationErrors: string[];
}

/**
 * created   — there was no custom hostname for the name; this run created it.
 * recreated — the one there was `deleted` (Cloudflare gave up validating it); this run deleted the dead
 *             entry and created a fresh one.
 * unchanged — one exists that is not `deleted` (validating, active, blocked, pending_deletion). It is
 *             reported as it is and never edited: re-pointing a working hostname moves live traffic,
 *             and a `blocked` one needs a human.
 */
export type CustomHostnameUpsertAction = "created" | "recreated" | "unchanged";

export type CustomHostnameUpsertResult =
  | {
      ok: true;
      op: "custom-hostname-upsert";
      zone: string;
      hostname: string;
      action: CustomHostnameUpsertAction;
      customHostname: CustomHostnameView;
    }
  | { ok: false; op: "custom-hostname-upsert"; hostname: string; detail: string };

export type CustomHostnameGetResult =
  | { ok: true; op: "custom-hostname-get"; zone: string; hostname: string; found: false }
  | { ok: true; op: "custom-hostname-get"; zone: string; hostname: string; found: true; customHostname: CustomHostnameView }
  | { ok: false; op: "custom-hostname-get"; hostname: string; detail: string };

export type CustomHostnameDeleteResult =
  | { ok: true; op: "custom-hostname-delete"; zone: string; hostname: string; status: "deleted" | "already-absent" }
  | { ok: false; op: "custom-hostname-delete"; hostname: string; detail: string };

interface CloudflareEnvelope {
  success?: boolean;
  errors?: Array<{ code?: number; message?: string }>;
  result?: unknown;
}

/** Cloudflare's raw custom-hostname object, read defensively. */
interface CloudflareCustomHostname {
  id?: unknown;
  hostname?: unknown;
  status?: unknown;
  custom_origin_server?: unknown;
  verification_errors?: unknown;
  ssl?: { status?: unknown; validation_errors?: unknown } | null;
}

function authorizationHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, accept: "application/json" };
}

function cloudflareMessage(body: CloudflareEnvelope | null): string {
  const message = body?.errors?.[0]?.message;
  if (typeof message !== "string" || message.length === 0) {
    return "";
  }
  return `: ${message}`;
}

function hasCloudflareErrorCode(body: CloudflareEnvelope | null, code: number): boolean {
  if (!body || !Array.isArray(body.errors)) {
    return false;
  }
  return body.errors.some((error) => error?.code === code);
}

/** A bounded list of strings: at most MAX_REPORTED_ERRORS entries, each at most MAX_REPORTED_ERROR_LENGTH chars. */
function boundedMessages(values: string[]): string[] {
  const bounded: string[] = [];
  for (const value of values) {
    if (bounded.length >= MAX_REPORTED_ERRORS) {
      break;
    }
    bounded.push(value.slice(0, MAX_REPORTED_ERROR_LENGTH));
  }
  return bounded;
}

/** Cloudflare's verification_errors is a list of strings. Anything else is ignored. */
function readVerificationErrors(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const messages: string[] = [];
  for (const entry of raw) {
    if (typeof entry === "string" && entry.length > 0) {
      messages.push(entry);
    }
  }
  return boundedMessages(messages);
}

/** Cloudflare's ssl.validation_errors is a list of { message }. Anything else is ignored. */
function readSslValidationErrors(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const messages: string[] = [];
  for (const entry of raw) {
    const message = (entry as { message?: unknown } | null)?.message;
    if (typeof message === "string" && message.length > 0) {
      messages.push(message);
    }
  }
  return boundedMessages(messages);
}

/** The view of a raw object, or null when it lacks an id or a hostname (then it is not used at all). */
export function customHostnameViewOf(raw: CloudflareCustomHostname): CustomHostnameView | null {
  if (typeof raw.id !== "string" || raw.id.length === 0) {
    return null;
  }
  if (typeof raw.hostname !== "string" || raw.hostname.length === 0) {
    return null;
  }
  let status = "";
  if (typeof raw.status === "string") {
    status = raw.status;
  }
  let sslStatus = "";
  if (typeof raw.ssl?.status === "string") {
    sslStatus = raw.ssl.status;
  }
  let customOriginServer: string | null = null;
  if (typeof raw.custom_origin_server === "string" && raw.custom_origin_server.length > 0) {
    customOriginServer = raw.custom_origin_server;
  }
  return {
    id: raw.id,
    hostname: raw.hostname,
    status,
    sslStatus,
    customOriginServer,
    verificationErrors: readVerificationErrors(raw.verification_errors),
    sslValidationErrors: readSslValidationErrors(raw.ssl?.validation_errors),
  };
}

/** The configured agency zone, lowercase, or a reason it cannot be used. */
export function configuredCustomHostnameZone(env: Env): { zone: string } | { error: string } {
  const configured = env.CF_CUSTOM_HOSTNAME_ZONE;
  if (configured === undefined || configured.trim().length === 0) {
    return {
      error:
        "CF_CUSTOM_HOSTNAME_ZONE is not configured on this Worker — set it (as a secret, so a redeploy keeps it) " +
        "to the agency zone that holds its customers' custom hostnames, e.g. example.com.",
    };
  }
  // A pasted value often carries a trailing newline or space. The zone name itself never does.
  const zone = configured.trim().toLowerCase();
  if (!isCustomHostnameFqdn(zone)) {
    return { error: "CF_CUSTOM_HOSTNAME_ZONE is not a zone name (expected a lowercase name such as example.com)." };
  }
  return { zone };
}

interface ResolvedCustomHostnameZone {
  token: string;
  zone: string;
  zoneId: string;
}

/**
 * The token, the configured zone and that zone's id. Exactly ONE zone with exactly that name must be
 * visible to the token: none means the token cannot see it (wrong account or no Zone:Read), and more
 * than one would be a guess.
 */
async function resolveCustomHostnameZone(env: Env): Promise<ResolvedCustomHostnameZone | { error: string }> {
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return { error: "CF_DNS_API_TOKEN is not configured on this Worker." };
  }
  const configured = configuredCustomHostnameZone(env);
  if ("error" in configured) {
    return configured;
  }
  const zone = configured.zone;

  const query = new URLSearchParams({ name: zone, per_page: "2" });
  let response: Response;
  try {
    response = await fetch(`${CLOUDFLARE_API}/zones?${query.toString()}`, { headers: authorizationHeaders(token) });
  } catch (err) {
    return { error: `could not reach Cloudflare to resolve zone "${zone}": ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { error: `Cloudflare rejected CF_DNS_API_TOKEN for the zone lookup — it needs Zone:Read on ${zone}.` };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!body?.success || !Array.isArray(body.result)) {
    return { error: `zone lookup failed with HTTP ${response.status}${cloudflareMessage(body)}.` };
  }
  // The name filter is exact, but the name is re-checked so a looser match can never pick another zone.
  const matches = (body.result as Array<{ id?: unknown; name?: unknown }>).filter(
    (candidate) => candidate.name === zone && typeof candidate.id === "string" && candidate.id.length > 0,
  );
  if (matches.length === 0) {
    return { error: `zone "${zone}" is not visible to CF_DNS_API_TOKEN — check CF_CUSTOM_HOSTNAME_ZONE and the token's zone scope.` };
  }
  if (matches.length > 1) {
    return { error: `zone lookup for "${zone}" returned ${matches.length} zones — refusing to guess.` };
  }
  return { token, zone, zoneId: matches[0]?.id as string };
}

function customHostnamesPath(zoneId: string): string {
  return `${CLOUDFLARE_API}/zones/${encodeURIComponent(zoneId)}/custom_hostnames`;
}

/** The custom hostname for EXACTLY `hostname` (null when the zone has none), or a reason the read failed. */
async function findCustomHostname(
  resolved: ResolvedCustomHostnameZone,
  hostname: string,
): Promise<{ found: CustomHostnameView | null } | { error: string }> {
  for (let page = 1; page <= CUSTOM_HOSTNAME_MAX_PAGES; page++) {
    const query = new URLSearchParams({ hostname, per_page: String(CUSTOM_HOSTNAME_PER_PAGE), page: String(page) });
    let response: Response;
    try {
      response = await fetch(`${customHostnamesPath(resolved.zoneId)}?${query.toString()}`, {
        headers: authorizationHeaders(resolved.token),
      });
    } catch (err) {
      return { error: `could not reach Cloudflare to read custom hostnames: ${errorMessage(err)}` };
    }
    const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
    if (response.status === 401 || response.status === 403) {
      return { error: `Cloudflare denied reading custom hostnames in ${resolved.zone} — ${CUSTOM_HOSTNAME_SCOPE_HINT}${cloudflareMessage(body)}.` };
    }
    if (!response.ok || !body?.success || !Array.isArray(body.result)) {
      return { error: `custom hostname lookup failed with HTTP ${response.status}${cloudflareMessage(body)}.` };
    }
    const rows = body.result as CloudflareCustomHostname[];
    for (const row of rows) {
      if (row.hostname !== hostname) {
        continue;
      }
      const view = customHostnameViewOf(row);
      if (view !== null) {
        return { found: view };
      }
    }
    // A short page is the last page: the zone really has no entry for this exact name.
    if (rows.length < CUSTOM_HOSTNAME_PER_PAGE) {
      return { found: null };
    }
  }
  // Every page was full and none held the name. Saying "not found" here could make the upsert POST
  // into a 1406, so the read fails instead of guessing.
  return {
    error: `custom hostname lookup for ${hostname} read ${CUSTOM_HOSTNAME_MAX_PAGES} full pages without an exact match — refusing to guess.`,
  };
}

/** POST a new custom hostname. HTTP DV validation and TLS 1.2 minimum, the platform's settings. */
async function createCustomHostname(
  resolved: ResolvedCustomHostnameZone,
  hostname: string,
  customOriginServer: string,
): Promise<{ created: CustomHostnameView } | { duplicate: true } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(customHostnamesPath(resolved.zoneId), {
      method: "POST",
      headers: { ...authorizationHeaders(resolved.token), "content-type": "application/json" },
      body: JSON.stringify({
        hostname,
        ssl: { method: "http", type: "dv", settings: { min_tls_version: "1.2" } },
        custom_origin_server: customOriginServer,
      }),
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to create the custom hostname: ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return { error: `Cloudflare denied creating the custom hostname in ${resolved.zone} — ${CUSTOM_HOSTNAME_SCOPE_HINT}${cloudflareMessage(body)}.` };
  }
  if (hasCloudflareErrorCode(body, CLOUDFLARE_DUPLICATE_CUSTOM_HOSTNAME_CODE)) {
    return { duplicate: true };
  }
  if (!response.ok || !body?.success || !body.result || typeof body.result !== "object") {
    return { error: `creating the custom hostname failed with HTTP ${response.status}${cloudflareMessage(body)}.` };
  }
  const view = customHostnameViewOf(body.result as CloudflareCustomHostname);
  if (view === null) {
    return { error: "Cloudflare created the custom hostname but returned no id — read it back with custom-hostname-get." };
  }
  return { created: view };
}

/** DELETE one custom hostname by id. A 404 means it is already gone, which is the wanted outcome. */
async function deleteCustomHostnameById(
  resolved: ResolvedCustomHostnameZone,
  id: string,
): Promise<{ status: "deleted" | "already-absent" } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${customHostnamesPath(resolved.zoneId)}/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: authorizationHeaders(resolved.token),
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to delete the custom hostname: ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 404) {
    return { status: "already-absent" };
  }
  if (response.status === 401 || response.status === 403) {
    return { error: `Cloudflare denied deleting the custom hostname in ${resolved.zone} — ${CUSTOM_HOSTNAME_SCOPE_HINT}${cloudflareMessage(body)}.` };
  }
  if (!response.ok) {
    return { error: `deleting the custom hostname failed with HTTP ${response.status}${cloudflareMessage(body)}.` };
  }
  return { status: "deleted" };
}

function upsertFailure(hostname: string, detail: string): CustomHostnameUpsertResult {
  return { ok: false, op: "custom-hostname-upsert", hostname, detail };
}

/**
 * Create the custom hostname, or report the one that exists. See the header for the three branches.
 * Never edits an entry that is not `deleted`, and never touches any other custom hostname.
 */
export async function actuateCustomHostnameUpsert(params: CustomHostnameUpsertParams, env: Env): Promise<CustomHostnameUpsertResult> {
  const { hostname, customOriginServer } = params;
  const resolved = await resolveCustomHostnameZone(env);
  if ("error" in resolved) {
    return upsertFailure(hostname, resolved.error);
  }
  const zoneRefusal = customHostnameZoneReason({ hostname, customOriginServer }, resolved.zone);
  if (zoneRefusal !== null) {
    return upsertFailure(hostname, zoneRefusal);
  }

  const lookup = await findCustomHostname(resolved, hostname);
  if ("error" in lookup) {
    return upsertFailure(hostname, lookup.error);
  }
  const existing = lookup.found;

  if (existing !== null && existing.status !== "deleted") {
    // Validating, active, blocked or pending_deletion: report it as it is (see the action notes above).
    return { ok: true, op: "custom-hostname-upsert", zone: resolved.zone, hostname, action: "unchanged", customHostname: existing };
  }

  let action: CustomHostnameUpsertAction = "created";
  if (existing !== null) {
    // `deleted` still holds the hostname slot, so it must go before the POST below can succeed.
    const deleted = await deleteCustomHostnameById(resolved, existing.id);
    if ("error" in deleted) {
      return upsertFailure(hostname, `the dead (deleted) custom hostname could not be removed: ${deleted.error}`);
    }
    action = "recreated";
  }

  const created = await createCustomHostname(resolved, hostname, customOriginServer);
  if ("duplicate" in created) {
    // Another run created it between our read and our POST. Read it back and report it.
    const reread = await findCustomHostname(resolved, hostname);
    if ("error" in reread) {
      return upsertFailure(hostname, `Cloudflare reports the hostname exists (1406), but reading it back failed: ${reread.error}`);
    }
    if (reread.found === null) {
      return upsertFailure(hostname, "Cloudflare reports the hostname exists (1406), but it is not in this zone — it may belong to another Cloudflare account.");
    }
    return { ok: true, op: "custom-hostname-upsert", zone: resolved.zone, hostname, action: "unchanged", customHostname: reread.found };
  }
  if ("error" in created) {
    if (action === "recreated") {
      // The one moment the hostname has NO custom hostname at all: say so plainly. A re-run creates it.
      return upsertFailure(hostname, `the dead custom hostname was removed, but creating the new one FAILED, so ${hostname} has none now: ${created.error}`);
    }
    return upsertFailure(hostname, created.error);
  }
  return { ok: true, op: "custom-hostname-upsert", zone: resolved.zone, hostname, action, customHostname: created.created };
}

/** READ one custom hostname. `found:false` means the zone has no entry for the name. */
export async function actuateCustomHostnameGet(params: CustomHostnameGetParams, env: Env): Promise<CustomHostnameGetResult> {
  const { hostname } = params;
  const resolved = await resolveCustomHostnameZone(env);
  if ("error" in resolved) {
    return { ok: false, op: "custom-hostname-get", hostname, detail: resolved.error };
  }
  const zoneRefusal = customHostnameZoneReason({ hostname }, resolved.zone);
  if (zoneRefusal !== null) {
    return { ok: false, op: "custom-hostname-get", hostname, detail: zoneRefusal };
  }
  const lookup = await findCustomHostname(resolved, hostname);
  if ("error" in lookup) {
    return { ok: false, op: "custom-hostname-get", hostname, detail: lookup.error };
  }
  if (lookup.found === null) {
    return { ok: true, op: "custom-hostname-get", zone: resolved.zone, hostname, found: false };
  }
  return { ok: true, op: "custom-hostname-get", zone: resolved.zone, hostname, found: true, customHostname: lookup.found };
}

/** DELETE one custom hostname. An absent one is "already-absent". Never touches another hostname. */
export async function actuateCustomHostnameDelete(params: CustomHostnameDeleteParams, env: Env): Promise<CustomHostnameDeleteResult> {
  const { hostname } = params;
  const resolved = await resolveCustomHostnameZone(env);
  if ("error" in resolved) {
    return { ok: false, op: "custom-hostname-delete", hostname, detail: resolved.error };
  }
  const zoneRefusal = customHostnameZoneReason({ hostname }, resolved.zone);
  if (zoneRefusal !== null) {
    return { ok: false, op: "custom-hostname-delete", hostname, detail: zoneRefusal };
  }
  const lookup = await findCustomHostname(resolved, hostname);
  if ("error" in lookup) {
    return { ok: false, op: "custom-hostname-delete", hostname, detail: lookup.error };
  }
  if (lookup.found === null) {
    return { ok: true, op: "custom-hostname-delete", zone: resolved.zone, hostname, status: "already-absent" };
  }
  const deleted = await deleteCustomHostnameById(resolved, lookup.found.id);
  if ("error" in deleted) {
    return { ok: false, op: "custom-hostname-delete", hostname, detail: deleted.error };
  }
  return { ok: true, op: "custom-hostname-delete", zone: resolved.zone, hostname, status: deleted.status };
}

// ── /validate: the read-only custom-hostname probe ──────────────────────────────────────────

/** What /validate reports about custom hostnames. Advisory: it never changes the cfDns `ok`. */
export interface CustomHostnameScopeReport {
  /** The configured CF_CUSTOM_HOSTNAME_ZONE (lowercase), or null when it is not set or not a zone name. */
  zone: string | null;
  /** True when the token may READ the zone's custom hostnames (the edit scope is exercised on first use). */
  canReadCustomHostnames: boolean;
  /** The zone's Cloudflare-for-SaaS fallback origin, or null when none is set or it could not be read. */
  fallbackOrigin: string | null;
  /** Cloudflare's status of that fallback origin (for example "active"), or null. */
  fallbackOriginStatus: string | null;
  /** One human sentence, folded into the cfDns detail. */
  detail: string;
}

/** Read the zone's fallback origin. Never throws. */
async function readFallbackOrigin(
  resolved: ResolvedCustomHostnameZone,
): Promise<{ origin: string | null; status: string | null; note: string }> {
  let response: Response;
  try {
    response = await fetch(`${customHostnamesPath(resolved.zoneId)}/fallback_origin`, {
      headers: authorizationHeaders(resolved.token),
    });
  } catch (err) {
    return { origin: null, status: null, note: `the fallback origin could not be read (${errorMessage(err)}).` };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 404) {
    return { origin: null, status: null, note: "NO fallback origin is set on the zone." };
  }
  if (!response.ok || !body?.success) {
    return { origin: null, status: null, note: `the fallback origin check was inconclusive (HTTP ${response.status}${cloudflareMessage(body)}).` };
  }
  const result = body.result as { origin?: unknown; status?: unknown } | null;
  if (typeof result?.origin !== "string" || result.origin.length === 0) {
    return { origin: null, status: null, note: "NO fallback origin is set on the zone." };
  }
  let status: string | null = null;
  if (typeof result.status === "string") {
    status = result.status;
  }
  return { origin: result.origin, status, note: `fallback origin ${result.origin} (${status ?? "status unknown"}).` };
}

/**
 * READ-ONLY probe for /validate: can the token read the configured zone's custom hostnames, and does
 * the zone have a fallback origin? Never throws, never writes, and never puts the token in its output.
 */
export async function probeCustomHostnameScope(env: Env): Promise<CustomHostnameScopeReport> {
  const resolved = await resolveCustomHostnameZone(env);
  if ("error" in resolved) {
    const configured = configuredCustomHostnameZone(env);
    let zone: string | null = null;
    if ("zone" in configured) {
      zone = configured.zone;
    }
    return {
      zone,
      canReadCustomHostnames: false,
      fallbackOrigin: null,
      fallbackOriginStatus: null,
      detail: `Custom hostnames: not available — ${resolved.error}`,
    };
  }

  let listResponse: Response;
  try {
    listResponse = await fetch(`${customHostnamesPath(resolved.zoneId)}?per_page=1`, {
      headers: authorizationHeaders(resolved.token),
    });
  } catch (err) {
    return {
      zone: resolved.zone,
      canReadCustomHostnames: false,
      fallbackOrigin: null,
      fallbackOriginStatus: null,
      detail: `Custom hostnames: the probe could not be sent (${errorMessage(err)}).`,
    };
  }
  const listBody = (await listResponse.json().catch(() => null)) as CloudflareEnvelope | null;
  if (listResponse.status === 401 || listResponse.status === 403) {
    return {
      zone: resolved.zone,
      canReadCustomHostnames: false,
      fallbackOrigin: null,
      fallbackOriginStatus: null,
      detail: `Custom hostnames: NOT available on ${resolved.zone} — ${CUSTOM_HOSTNAME_SCOPE_HINT}${cloudflareMessage(listBody)}.`,
    };
  }
  if (!listResponse.ok || !listBody?.success) {
    // Typically Cloudflare for SaaS is not enabled on the zone. Cloudflare's own message says which.
    return {
      zone: resolved.zone,
      canReadCustomHostnames: false,
      fallbackOrigin: null,
      fallbackOriginStatus: null,
      detail: `Custom hostnames: check inconclusive on ${resolved.zone} (HTTP ${listResponse.status}${cloudflareMessage(listBody)}) — is Cloudflare for SaaS enabled on the zone?`,
    };
  }

  const fallback = await readFallbackOrigin(resolved);
  return {
    zone: resolved.zone,
    canReadCustomHostnames: true,
    fallbackOrigin: fallback.origin,
    fallbackOriginStatus: fallback.status,
    detail: `Custom hostnames: read access OK on ${resolved.zone} ("SSL and Certificates: Edit" is exercised on the first custom-hostname upsert); ${fallback.note}`,
  };
}
