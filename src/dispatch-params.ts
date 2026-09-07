// Direction-B PER-OP PARAMS (agency Worker side) — the typed params object each op
// carries, plus a strict validator for each.
//
// The job's `params` field is an opaque signed STRING (the app's JSON.stringify of one
// of the objects below). This module is what runs AFTER the signature verifies:
// index.ts::handleActuate JSON.parses that string (guarded — malformed => fail closed,
// nothing actuated) and hands the parsed value to the op's validator here, which either
// returns a fresh, typed params object containing ONLY the known keys, or a reason.
//
// ── TWIN of the app's src/server/services/agency-dispatch-params.ts ─────────────────
// The app refuses to SIGN params that fail these same rules; this Worker re-checks them
// as the last line before a Cloudflare API call (defense in depth — the two sides are
// separately deployed, so neither trusts the other's validation). Keep the rule bodies in
// lockstep with the app copy: a rule present on only one side is either an unsignable job
// (app stricter) or an unchecked actuation input (Worker looser). Both are bugs.
//
// Worker-native only: plain string handling, no Node APIs.

/** Outcome of validating a parsed params object for one op. */
export type ParamsVerdict<P> = { ok: true; params: P } | { ok: false; reason: string };

// ── provision-r2 ───────────────────────────────────────────────────────────────────

export interface ProvisionR2Params {
  bucketName: string;
}

// R2 bucket-name grammar: 3-63 chars, lowercase letters / digits / hyphens, first and
// last char alphanumeric.
const R2_BUCKET_NAME_RE = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

/** True when `name` is a syntactically valid R2 bucket name. */
export function isValidR2BucketName(name: string): boolean {
  return R2_BUCKET_NAME_RE.test(name);
}

export function validateProvisionR2Params(raw: unknown): ParamsVerdict<ProvisionR2Params> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const bucketName = raw.bucketName;
  if (typeof bucketName !== "string" || !isValidR2BucketName(bucketName)) {
    return {
      ok: false,
      reason:
        "bucketName must be a valid R2 bucket name (3-63 chars: lowercase letters, digits, hyphens; first/last alphanumeric)",
    };
  }
  return { ok: true, params: { bucketName } };
}

// ── dns-record-upsert ──────────────────────────────────────────────────────────────

// Record types the platform may upsert in an agency zone. Deliberately small; extend on
// purpose (MX/SRV/CAA carry extra fields this params shape doesn't model).
export const DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT"] as const;
export type DnsRecordType = (typeof DNS_RECORD_TYPES)[number];

/**
 * ALL values are strings (the signed-job convention: no numbers/booleans anywhere in a
 * job, so the two runtimes can never disagree on formatting). `proxied` is "true"|"false";
 * `ttl` is a numeric string ("1" = Cloudflare "automatic").
 */
export interface DnsRecordUpsertParams {
  /** The zone NAME (e.g. "example.com") — resolved to a zone id by the actuator. */
  zone: string;
  type: DnsRecordType;
  /** Fully-qualified record name, within `zone` (equal to it or ending in ".<zone>"). */
  name: string;
  content: string;
  proxied: "true" | "false";
  ttl: string;
}

// One DNS label: 1-63 chars of [a-z0-9_-], not starting or ending with "-". Underscore is
// allowed because service/verification names need it (_dmarc, _acme-challenge, ...).
// Lowercase only — DNS is case-insensitive, so callers normalize before signing rather than
// having two spellings of one record.
const DNS_LABEL = "(?!-)[a-z0-9_-]{1,63}(?<!-)";
// A zone apex: two or more labels (no wildcard, no leading/trailing dot).
const DNS_ZONE_RE = new RegExp(`^${DNS_LABEL}(\\.${DNS_LABEL})+$`);
// A record name: labels like a zone, optionally with a leading "*." wildcard label.
const DNS_RECORD_NAME_RE = new RegExp(`^(\\*\\.)?${DNS_LABEL}(\\.${DNS_LABEL})*$`);
const DNS_NAME_MAX_LENGTH = 253;
// Cloudflare: 1 = automatic; otherwise 60-86400 (30 on Enterprise zones). We admit the
// Enterprise floor and let Cloudflare reject 30-59 on a non-Enterprise zone (surfaced as a
// clean ok:false detail).
const DNS_TTL_AUTO = 1;
const DNS_TTL_MIN = 30;
const DNS_TTL_MAX = 86_400;
const DNS_CONTENT_MAX_LENGTH = 4096;

export function validateDnsRecordUpsertParams(raw: unknown): ParamsVerdict<DnsRecordUpsertParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { zone, type, name, content, proxied, ttl } = raw;

  if (typeof zone !== "string" || zone.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a lowercase DNS zone name (e.g. example.com)" };
  }
  if (typeof type !== "string" || !(DNS_RECORD_TYPES as readonly string[]).includes(type)) {
    return { ok: false, reason: `type must be one of ${DNS_RECORD_TYPES.join(", ")}` };
  }
  if (typeof name !== "string" || name.length > DNS_NAME_MAX_LENGTH || !DNS_RECORD_NAME_RE.test(name)) {
    return { ok: false, reason: "name must be a lowercase fully-qualified DNS record name" };
  }
  // The record must live inside the zone — otherwise the actuator's existing-record lookup
  // (filtered by name) can never match and Cloudflare would reject the write anyway.
  const nameWithoutWildcard = name.startsWith("*.") ? name.slice(2) : name;
  const nameIsInZone = nameWithoutWildcard === zone || nameWithoutWildcard.endsWith(`.${zone}`);
  if (!nameIsInZone) {
    return { ok: false, reason: "name must be within zone (equal to it or a subdomain of it)" };
  }
  if (
    typeof content !== "string" ||
    content.length === 0 ||
    content.length > DNS_CONTENT_MAX_LENGTH ||
    content.trim() !== content
  ) {
    return {
      ok: false,
      reason: `content must be a non-empty string (max ${DNS_CONTENT_MAX_LENGTH} chars, no leading/trailing whitespace)`,
    };
  }
  if (proxied !== "true" && proxied !== "false") {
    return { ok: false, reason: 'proxied must be the string "true" or "false"' };
  }
  // Cloudflare can only proxy A/AAAA/CNAME; a proxied TXT is always a Cloudflare error.
  if (type === "TXT" && proxied === "true") {
    return { ok: false, reason: "a TXT record cannot be proxied" };
  }
  if (typeof ttl !== "string" || !/^[0-9]{1,6}$/.test(ttl)) {
    return { ok: false, reason: 'ttl must be a numeric string ("1" = automatic)' };
  }
  const ttlSeconds = Number(ttl);
  const ttlIsAllowed =
    ttlSeconds === DNS_TTL_AUTO || (ttlSeconds >= DNS_TTL_MIN && ttlSeconds <= DNS_TTL_MAX);
  if (!ttlIsAllowed) {
    return { ok: false, reason: `ttl must be "1" (automatic) or ${DNS_TTL_MIN}-${DNS_TTL_MAX} seconds` };
  }

  // Return a FRESH object holding only the known keys — never the caller's object — so an
  // extra key in the parsed params can never ride along into the actuator.
  return {
    ok: true,
    params: { zone, type: type as DnsRecordType, name, content, proxied, ttl },
  };
}

// ── cache-purge ──────────────────────────────────────────────────────────────────────

// The three ways Cloudflare can purge a zone's cache. Exactly ONE target selector applies
// per mode: "everything" (whole zone, no list), "files" (a list of exact URLs), or "hosts"
// (a list of hostnames). Deliberately small + explicit so a caller can't accidentally send
// a whole-zone purge when it meant a targeted one, or mix selectors.
export const CACHE_PURGE_MODES = ["everything", "files", "hosts"] as const;
export type CachePurgeMode = (typeof CACHE_PURGE_MODES)[number];

// Cloudflare caps a single purge_cache call at 30 URLs / 30 hosts on non-Enterprise zones;
// we hold both list modes to 1..30 so an over-sized list fails here rather than at the edge.
const CACHE_PURGE_LIST_MAX = 30;
// A generous ceiling on a single file URL — long enough for real query-string cache keys,
// short enough to reject a junk mega-string. (Cloudflare's own practical URL cap is ~2 KB.)
const CACHE_PURGE_URL_MAX_LENGTH = 2048;

/**
 * A cache-purge job. The `params` field rides as an opaque SIGNED string, so unlike the
 * older all-strings ops this one carries real arrays — validated strictly on BOTH sides.
 * Modelled as a discriminated union on `mode` so exactly one selector is present:
 *   - everything: whole-zone purge, no list;
 *   - files: 1..30 absolute https URLs, each within `zone`;
 *   - hosts: 1..30 lowercase hostnames, each within `zone`.
 */
export type CachePurgeParams =
  | { zone: string; mode: "everything" }
  | { zone: string; mode: "files"; files: string[] }
  | { zone: string; mode: "hosts"; hosts: string[] };

/**
 * True when `entry` is an absolute https URL whose host is within `zone`. Parsing an
 * untrusted URL genuinely needs the try/catch (there is no non-throwing WHATWG parse we
 * can rely on identically across Node + workerd). The host is validated with the SAME zone
 * grammar as the DNS op and must be equal to `zone` or a subdomain of it, so a purge can't
 * be aimed at a URL outside the resolved zone (Cloudflare would reject it anyway).
 */
function isValidCachePurgeFileUrl(entry: unknown, zone: string): boolean {
  if (
    typeof entry !== "string" ||
    entry.length === 0 ||
    entry.length > CACHE_PURGE_URL_MAX_LENGTH ||
    entry.trim() !== entry
  ) {
    return false;
  }
  let url: URL;
  try {
    url = new URL(entry);
  } catch {
    return false;
  }
  if (url.protocol !== "https:") return false;
  const host = url.hostname;
  if (host.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(host)) return false;
  return host === zone || host.endsWith(`.${zone}`);
}

/**
 * True when `entry` is a bare lowercase hostname (no scheme, no wildcard) within `zone`.
 * Reuses the DNS zone grammar (lowercase, 2+ labels), matching the DNS op's "callers
 * normalize before signing" rule rather than normalizing here.
 */
function isValidCachePurgeHostname(entry: unknown, zone: string): boolean {
  if (
    typeof entry !== "string" ||
    entry.length === 0 ||
    entry.length > DNS_NAME_MAX_LENGTH ||
    entry.trim() !== entry
  ) {
    return false;
  }
  if (!DNS_ZONE_RE.test(entry)) return false;
  return entry === zone || entry.endsWith(`.${zone}`);
}

export function validateCachePurgeParams(raw: unknown): ParamsVerdict<CachePurgeParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { zone, mode, files, hosts } = raw;

  if (typeof zone !== "string" || zone.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a lowercase DNS zone name (e.g. example.com)" };
  }
  if (typeof mode !== "string" || !(CACHE_PURGE_MODES as readonly string[]).includes(mode)) {
    return { ok: false, reason: `mode must be one of ${CACHE_PURGE_MODES.join(", ")}` };
  }

  // everything: whole-zone purge — neither target list may be present (a stray list here is
  // almost always a caller bug: it MEANT a targeted purge but sent the wrong mode).
  if (mode === "everything") {
    if (files !== undefined || hosts !== undefined) {
      return { ok: false, reason: 'mode "everything" must not carry a files or hosts list' };
    }
    return { ok: true, params: { zone, mode: "everything" } };
  }

  // files: 1..30 absolute https URLs within the zone; the hosts list must be absent.
  if (mode === "files") {
    if (hosts !== undefined) {
      return { ok: false, reason: 'mode "files" must not carry a hosts list' };
    }
    if (!Array.isArray(files) || files.length < 1 || files.length > CACHE_PURGE_LIST_MAX) {
      return { ok: false, reason: `files must be an array of 1-${CACHE_PURGE_LIST_MAX} absolute https URLs` };
    }
    // Build a FRESH array of only the validated string entries — never the caller's array —
    // so an extra element property can't ride along into the signed params.
    const cleanFiles: string[] = [];
    for (const entry of files) {
      if (!isValidCachePurgeFileUrl(entry, zone)) {
        return { ok: false, reason: "each files entry must be an absolute https URL within zone" };
      }
      cleanFiles.push(entry as string);
    }
    return { ok: true, params: { zone, mode: "files", files: cleanFiles } };
  }

  // hosts: 1..30 lowercase hostnames within the zone; the files list must be absent.
  if (mode === "hosts") {
    if (files !== undefined) {
      return { ok: false, reason: 'mode "hosts" must not carry a files list' };
    }
    if (!Array.isArray(hosts) || hosts.length < 1 || hosts.length > CACHE_PURGE_LIST_MAX) {
      return { ok: false, reason: `hosts must be an array of 1-${CACHE_PURGE_LIST_MAX} hostnames` };
    }
    const cleanHosts: string[] = [];
    for (const entry of hosts) {
      if (!isValidCachePurgeHostname(entry, zone)) {
        return { ok: false, reason: "each hosts entry must be a lowercase hostname within zone" };
      }
      cleanHosts.push(entry as string);
    }
    return { ok: true, params: { zone, mode: "hosts", hosts: cleanHosts } };
  }

  // Unreachable: `mode` was allowlisted above. Fail closed rather than fall through.
  return { ok: false, reason: `mode must be one of ${CACHE_PURGE_MODES.join(", ")}` };
}

// ── wp-cli ─────────────────────────────────────────────────────────────────────────
// Run a wp-cli command in a cell site's docroot, through the on-VM cell-agent (the first
// "heavy"/data-plane Direction-B op — see actuate.ts::actuateWpCli). Unlike the Cloudflare
// ops above, this actuates ON THE AGENCY's cell, so the security burden shifts:
//
//   1. `docroot` is the ONLY thing that selects WHICH site runs the command, so it is pinned
//      to a strict grammar — an absolute /var/www/<slug> OR /sites/<slug>/public path,
//      lowercase slug, NOTHING else. The grammar admits no "..", no trailing slash, no extra
//      path segment, and no shell metacharacter, so a traversal or an injected-path attack
//      cannot pass this gate (the cell-agent then re-guards it with realpath under its allowed
//      roots; a /sites/<slug>/public docroot runs under the site's own per-site OS user).
//   2. `args` are the wp-cli arguments and are DELIBERATELY not charset-restricted — a real
//      wp-cli value can legitimately contain spaces, quotes, "$", ";", etc. (e.g.
//      `wp option update blogname "A; B & C"`). They are made safe NOT by rejecting
//      metacharacters here but by SHELL-QUOTING each one in the actuator (actuate.ts), so
//      every arg reaches wp-cli as exactly one literal token. We only bound the count + size.

export interface WpCliParams {
  /** The site's docroot on the cell, e.g. "/var/www/<slug>" — selects the target site. */
  docroot: string;
  /** The wp-cli arguments, e.g. ["option","get","siteurl"] — 1..30 non-empty strings. */
  args: string[];
}

// An absolute cell docroot in one of the two forms the cell-agent's /exec guard accepts:
//   - /var/www/<slug>       (Docker-era sites), OR
//   - /sites/<slug>/public  (storage-tier sites — the live cell layout, run under the site's
//                            own per-site OS user via the agent's setpriv path).
// <slug> is a lowercase DNS-style label (starts alphanumeric, then up to 63 of [a-z0-9-]).
// Anchored at both ends, so there is no "..", no trailing slash, no extra path segment, and no
// shell metacharacter — the docroot can only ever name one real site directory.
const WP_CLI_DOCROOT_RE =
  /^(\/var\/www\/[a-z0-9][a-z0-9-]{0,63}|\/sites\/[a-z0-9][a-z0-9-]{0,63}\/public)$/;
// A wp-cli invocation is a handful of short arguments; 30 is generous and stops a junk mega-list.
const WP_CLI_ARGS_MAX = 30;
// A generous per-argument ceiling — long enough for a real option value or a serialized blob,
// short enough to reject a junk mega-string.
const WP_CLI_ARG_MAX_LENGTH = 8192;

export function validateWpCliParams(raw: unknown): ParamsVerdict<WpCliParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { docroot, args } = raw;

  if (typeof docroot !== "string" || !WP_CLI_DOCROOT_RE.test(docroot)) {
    return {
      ok: false,
      reason:
        "docroot must be an absolute cell docroot (/var/www/<slug> or /sites/<slug>/public) with a lowercase slug, no '..', no trailing slash, no extra path segment",
    };
  }
  if (!Array.isArray(args) || args.length < 1 || args.length > WP_CLI_ARGS_MAX) {
    return { ok: false, reason: `args must be an array of 1-${WP_CLI_ARGS_MAX} wp-cli argument strings` };
  }
  // Build a FRESH array of only the validated string entries — never the caller's array — so an
  // extra element property can't ride along into the signed params. Reject empty/oversized/
  // non-string entries, but NOT metacharacters: the actuator shell-quotes each arg (that is
  // what makes an arbitrary value safe), so charset-restricting here would only break valid
  // wp-cli values without adding safety.
  const cleanArgs: string[] = [];
  for (const entry of args) {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > WP_CLI_ARG_MAX_LENGTH) {
      return {
        ok: false,
        reason: `each args entry must be a non-empty string (max ${WP_CLI_ARG_MAX_LENGTH} chars)`,
      };
    }
    cleanArgs.push(entry);
  }

  return { ok: true, params: { docroot, args: cleanArgs } };
}

// ── shared ─────────────────────────────────────────────────────────────────────────

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
