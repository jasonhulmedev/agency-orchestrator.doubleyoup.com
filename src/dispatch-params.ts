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
//   1. `docroot` selects the WORKING DIRECTORY the command runs in, pinned to a strict grammar —
//      an absolute /var/www/<slug> OR /sites/<slug>/public path, lowercase slug, NOTHING else.
//      The grammar admits no "..", no trailing slash, no extra path segment, and no shell
//      metacharacter, so a traversal or an injected-path attack cannot pass this gate (the
//      cell-agent then re-guards it with realpath under its allowed roots). But `docroot` is NOT
//      the only thing that selects which SITE the command touches: `args` are unrestricted by
//      design (safety is the quoting, not a charset), so a wp-cli flag like
//      `--path=/var/www/otherslug` is passed literally and would redirect wp-cli elsewhere. On
//      the storage tier the per-site OS user + NFS root_squash contain such a cross-site
//      `--path`; on the /var/www Docker-era path the command runs as shared `www-data`, so
//      `docroot` alone does NOT isolate. A future caller that forwards tenant-influenced args
//      must not rely on `docroot` for cross-tenant isolation.
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

// ── db-export ──────────────────────────────────────────────────────────────────────
// Export a cell site's WordPress DB and upload it STRAIGHT from the cell to the agency's own
// object store via a presigned PUT URL — the dump never passes through the Worker (the Worker's
// actuate.ts::actuateDbExport mints the URL and relays only a small script). Two params, both
// platform-generated and both strictly grammared:
//   1. `docroot` — the SAME grammar as wp-cli (an absolute /var/www/<slug> or /sites/<slug>/public
//      path): selects the site whose DB is exported and the working directory the export runs in.
//   2. `objectKey` — the object key the dump lands under. The ORCHESTRATOR generates it ONCE,
//      before its retry loop (db-exports/<slug>-<timestamp>.sql), so a re-signed retry re-uploads
//      to the SAME key: a true overwrite, which is what makes this op idempotent (F1). The grammar
//      pins it under the db-exports/ prefix as ONE lowercase filename segment ending in .sql — no
//      leading slash, no "/" after the prefix, no "..", no whitespace or shell metacharacter — so a
//      signed key can never name an object outside that prefix and is safe to place in a URL path.

export interface DbExportParams {
  /** The site's docroot on the cell — selects the site + the export's working directory. */
  docroot: string;
  /** The object key the dump is uploaded to, e.g. "db-exports/<slug>-<timestamp>.sql". */
  objectKey: string;
}

// db-exports/<name>.sql where <name> is 1..121 chars of [a-z0-9._-] starting alphanumeric. Anchored
// at both ends and no "/" admitted after the prefix, so the key can only ever be one object directly
// under db-exports/.
const DB_EXPORT_OBJECT_KEY_RE = /^db-exports\/[a-z0-9][a-z0-9._-]{0,120}\.sql$/;

export function validateDbExportParams(raw: unknown): ParamsVerdict<DbExportParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { docroot, objectKey } = raw;

  if (typeof docroot !== "string" || !WP_CLI_DOCROOT_RE.test(docroot)) {
    return {
      ok: false,
      reason:
        "docroot must be an absolute cell docroot (/var/www/<slug> or /sites/<slug>/public) with a lowercase slug, no '..', no trailing slash, no extra path segment",
    };
  }
  // The grammar admits "." inside <name> (a dotted timestamp is legitimate); the explicit ".."
  // check keeps the "no traversal-looking key" rule literal even though no "/" can follow the prefix.
  if (typeof objectKey !== "string" || !DB_EXPORT_OBJECT_KEY_RE.test(objectKey) || objectKey.includes("..")) {
    return {
      ok: false,
      reason:
        "objectKey must be db-exports/<name>.sql with a lowercase <name> of [a-z0-9._-] (1-121 chars), no '..', no leading slash, no extra path segment",
    };
  }

  return { ok: true, params: { docroot, objectKey } };
}

// ── db-import ────────────────────────────────────────────────────────────────────────
// Import a SQL dump from the agency's own object store INTO a cell site's WordPress DB — the
// reverse of db-export. The dump flows object store -> cell (the Worker's actuate.ts::actuateDbImport
// PRESIGNS a single-object GET URL the cell `curl`s down, then runs `wp db import`); the dump never
// passes through the Worker. Two params, both strictly grammared — the SAME two db-export carries:
//   1. `docroot` — the wp-cli/db-export docroot grammar: selects the site whose DB is REPLACED.
//   2. `objectKey` — the object key of the dump to read, under the same db-exports/ prefix + .sql
//      grammar db-export writes (a db-import normally re-loads a dump db-export produced). The
//      caller (orchestrator) supplies it — unlike db-export it is NOT generated here, because a
//      db-import names an EXISTING dump to restore.
//
// DESTRUCTIVE + NON-IDEMPOTENT: `wp db import` REPLACES the site's DB with the dump's contents. The
// orchestrator registers db-import non-idempotent (AGENCY_OP_IDEMPOTENT), so the F1 dispatcher runs
// it exactly once and never auto-retries a transient failure — a re-apply of a dump WITHOUT DROP
// TABLE would double-insert. This validator does not (cannot) inspect the dump; the run-once contract
// is the safety control, alongside the download-before-import order in actuate.ts (a failed download
// aborts before the DB is touched).

export interface DbImportParams {
  /** The site's docroot on the cell — selects the site whose DB is replaced + the working directory. */
  docroot: string;
  /** The object key of the dump to import, e.g. "db-exports/<slug>-<timestamp>.sql". */
  objectKey: string;
}

export function validateDbImportParams(raw: unknown): ParamsVerdict<DbImportParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { docroot, objectKey } = raw;

  if (typeof docroot !== "string" || !WP_CLI_DOCROOT_RE.test(docroot)) {
    return {
      ok: false,
      reason:
        "docroot must be an absolute cell docroot (/var/www/<slug> or /sites/<slug>/public) with a lowercase slug, no '..', no trailing slash, no extra path segment",
    };
  }
  // Same object-key grammar as db-export (a db-import normally re-loads a db-export dump): the "."
  // check keeps the "no traversal-looking key" rule literal even though no "/" can follow the prefix.
  if (typeof objectKey !== "string" || !DB_EXPORT_OBJECT_KEY_RE.test(objectKey) || objectKey.includes("..")) {
    return {
      ok: false,
      reason:
        "objectKey must be db-exports/<name>.sql with a lowercase <name> of [a-z0-9._-] (1-121 chars), no '..', no leading slash, no extra path segment",
    };
  }

  return { ok: true, params: { docroot, objectKey } };
}

// ── GCP shared grammars ──────────────────────────────────────────────────────────────
// Grammars shared by the GCP ops below: gcp-instance-create's OPTIONAL networking fields and the
// gcp-network-create / gcp-firewall-create / gcp-address-create resource ops (planning/34 phase 2).
// Every GCP value a job carries becomes either a URL path segment or a JSON body field of a
// Compute Engine call, so each grammar is anchored, lowercase, and admits no "/", "?", "#",
// whitespace or other URL/JSON metacharacter — the grammar IS the injection guard, alongside
// encodeURIComponent + JSON.stringify in the actuator (see the gcp-instance-create note below).

// A Compute Engine resource name (RFC 1035): 1-63 chars, lowercase-letter start, [-a-z0-9],
// alphanumeric end. Used for network / subnetwork / firewall-rule / address names and for
// instance network tags. The same grammar as GCP_INSTANCE_NAME_RE below.
const GCP_RESOURCE_NAME_RE = /^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$/;
const GCP_RESOURCE_NAME_RULE =
  "must be a Compute Engine resource name (1-63 chars: lowercase letter first, then lowercase letters, digits, hyphens; alphanumeric last)";
const GCP_PROJECT_ID_RULE =
  "project must be a GCP project id (6-30 chars: lowercase letter first, then lowercase letters, digits, hyphens; alphanumeric last)";
// A Compute REGION, e.g. australia-southeast1 (<geo>-<area><n>). A zone ("...-a") does not match.
const GCP_REGION_RE = /^[a-z]+-[a-z0-9]+$/;
// One dotted-quad octet, 0-255, no leading zero.
const IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
// A plain IPv4 address — the reserved external IP an instance attaches.
const IPV4_ADDRESS_RE = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`);
// Any IPv4 CIDR block, prefix /0-/32 — a firewall SOURCE range, where 0.0.0.0/0 is legitimate.
const IPV4_CIDR_RE = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}\\/(?:3[0-2]|[12]?[0-9])$`);
// A subnet's primary range: a PRIVATE (RFC 1918) IPv4 block no smaller than GCP's /29 floor —
// 10/8 at /8-/29, 172.16/12 at /12-/29, or 192.168/16 at /16-/29. A public block or a /30+ is
// rejected here rather than at Google.
const GCP_SUBNET_CIDR_RE = new RegExp(
  `^(?:10(?:\\.${IPV4_OCTET}){3}\\/(?:[89]|1[0-9]|2[0-9])` +
    `|172\\.(?:1[6-9]|2[0-9]|3[01])(?:\\.${IPV4_OCTET}){2}\\/(?:1[2-9]|2[0-9])` +
    `|192\\.168(?:\\.${IPV4_OCTET}){2}\\/(?:1[6-9]|2[0-9]))$`,
);
// Google allows at most 64 network tags per instance.
const GCP_INSTANCE_TAGS_MAX = 64;
// Google caps a metadata VALUE at 256 KB; the startup script is one metadata value. Measured in
// JS string length (UTF-16 units) — for an ASCII shell script that equals its byte length.
const GCP_STARTUP_SCRIPT_MAX_LENGTH = 256 * 1024;

/**
 * Validate a list of Compute Engine resource names (tags / target tags): a non-empty array of
 * 1..`max` strings, each matching GCP_RESOURCE_NAME_RE. Returns a FRESH array of the validated
 * entries — never the caller's array — or null when anything about the list is wrong.
 */
function cleanGcpResourceNameList(value: unknown, max: number): string[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > max) {
    return null;
  }
  const clean: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string" || !GCP_RESOURCE_NAME_RE.test(entry)) {
      return null;
    }
    clean.push(entry);
  }
  return clean;
}

// ── gcp-instance-create ──────────────────────────────────────────────────────────────
// Create ONE Compute Engine VM in the AGENCY's own GCP project — the first GCP WRITE through
// Direction-B (actuate.ts::actuateGcpInstanceCreate, with the agency's own GCP_SERVICE_ACCOUNT_KEY).
// Four REQUIRED string params (each pinned to the exact GCP resource-name grammar) plus OPTIONAL
// params, every one of which leaves the body byte-identical to the four-field form when absent:
//   1. `project`     — the project id (6-30 chars: lowercase-letter start, [a-z0-9-], alphanumeric end).
//   2. `zone`        — a Compute zone, e.g. australia-southeast1-a (<region>-<area><n>-<letter>).
//   3. `name`        — the instance name (RFC 1035: 1-63 chars, lowercase-letter start, [-a-z0-9],
//                      alphanumeric end).
//   4. `machineType` — a machine-type name, e.g. e2-small / n2-standard-4 (<family>-<shape>[-<n>]).
//   5. `dataDiskGb`  — OPTIONAL: when present, a SECOND non-boot persistent data disk of this many GB
//                      (the file node's storage) is attached; absent => a single-boot-disk VM.
//                      An integer in [10, 65536].
//   6. `network`     — OPTIONAL: the NAME of a VPC network in `project` to attach instead of "default".
//   7. `subnetwork`  — OPTIONAL: the NAME of a subnetwork in `project`, in the zone's region.
//   8. `tags`        — OPTIONAL: 1-64 network tags (firewall targets), each a resource name.
//   9. `externalIp`  — OPTIONAL: a reserved IPv4 address to attach as the VM's external IP (a
//                      ONE_TO_ONE_NAT access config). Absent => NO external IP (the private default).
//  10. `startupScript` — OPTIONAL: the `startup-script` metadata value (planning/34 phase 3 bootstrap).
// The string values are the ONLY job-derived STRINGS that reach Google: `project` + `zone` become
// URL path segments of the instances.insert call, and the rest land in its JSON body. The grammars
// admit no "/", "?", "#", ".", whitespace or any other URL/JSON metacharacter, so a signed value
// can never re-path the API call (e.g. a zone of "a/../..") or smuggle a second field — this
// validation IS the injection guard, alongside encodeURIComponent + JSON.stringify in the actuator.
// `network` / `subnetwork` are deliberately BARE NAMES, not URLs: the actuator expands them into
// project-relative paths, so a signed job can never point the interface at another project's VPC.
// `dataDiskGb` (when present) reaches Google only as the body's numeric `diskSizeGb`; bounding it to
// a whole number in [10, 65536] keeps it a plain integer that can carry no metacharacter.
// `startupScript` is the ONE opaque value: a shell script legitimately contains any character, and
// it reaches Google only as a JSON.stringify'd metadata value (never a URL segment), so it is
// length-capped (Google's 256 KB metadata-value limit) rather than charset-restricted.
//
// NON-IDEMPOTENT: creating the same instance name twice is a 409 from GCP, and a lost response may
// already have created the VM. The orchestrator registers it `false` in AGENCY_OP_IDEMPOTENT, so
// the F1 dispatcher runs it exactly once and never auto-retries (like db-import).

export interface GcpInstanceCreateParams {
  /** The agency's GCP project id the VM is created in. */
  project: string;
  /** The Compute Engine zone, e.g. "australia-southeast1-a". */
  zone: string;
  /** The instance name — unique within project + zone. */
  name: string;
  /** The machine-type name, e.g. "e2-small". */
  machineType: string;
  /**
   * OPTIONAL size in GB of a second, non-boot persistent data disk (the file node's storage).
   * When present, the actuator attaches it alongside the boot disk; when absent, the VM has a boot
   * disk only and the instance body is unchanged.
   */
  dataDiskGb?: number;
  /** OPTIONAL name of the VPC network (in `project`) to attach to; absent => the "default" network. */
  network?: string;
  /** OPTIONAL name of the subnetwork (in `project`, in the zone's region) to attach to. */
  subnetwork?: string;
  /** OPTIONAL network tags (1-64 resource names) — the firewall-rule targets this VM matches. */
  tags?: string[];
  /** OPTIONAL reserved external IPv4 address to attach; absent => no external IP (private VM). */
  externalIp?: string;
  /** OPTIONAL startup-script metadata value (opaque shell script, at most 256 KB). */
  startupScript?: string;
}

const GCP_PROJECT_ID_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const GCP_ZONE_RE = /^[a-z]+-[a-z0-9]+-[a-z]$/;
const GCP_INSTANCE_NAME_RE = /^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$/;
const GCP_MACHINE_TYPE_RE = /^[a-z0-9]+-[a-z0-9-]+$/;
// The zone + machine-type grammars are open-ended on length (a real value is ~10-25 chars); cap
// both so a junk mega-string fails here rather than at Google. Project + name are length-bound
// by their own grammars.
const GCP_RESOURCE_NAME_MAX_LENGTH = 63;
// A data disk is a whole number of GB. 10 GB is Google's floor for a pd-balanced disk and 65536 GB
// (64 TB) is its per-disk ceiling; reject anything outside that range here rather than at Google.
const GCP_DATA_DISK_MIN_GB = 10;
const GCP_DATA_DISK_MAX_GB = 65_536;

export function validateGcpInstanceCreateParams(raw: unknown): ParamsVerdict<GcpInstanceCreateParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, zone, name, machineType, dataDiskGb, network, subnetwork, tags, externalIp, startupScript } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return {
      ok: false,
      reason:
        "project must be a GCP project id (6-30 chars: lowercase letter first, then lowercase letters, digits, hyphens; alphanumeric last)",
    };
  }
  if (typeof zone !== "string" || zone.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a Compute Engine zone name (e.g. australia-southeast1-a)" };
  }
  if (typeof name !== "string" || !GCP_INSTANCE_NAME_RE.test(name)) {
    return {
      ok: false,
      reason:
        "name must be a Compute Engine instance name (1-63 chars: lowercase letter first, then lowercase letters, digits, hyphens; alphanumeric last)",
    };
  }
  if (
    typeof machineType !== "string" ||
    machineType.length > GCP_RESOURCE_NAME_MAX_LENGTH ||
    !GCP_MACHINE_TYPE_RE.test(machineType)
  ) {
    return { ok: false, reason: "machineType must be a Compute Engine machine-type name (e.g. e2-small)" };
  }
  // dataDiskGb is OPTIONAL: absent/undefined => a single-boot-disk VM (unchanged). When present it
  // must be a whole number of GB within GCP's persistent-disk size range.
  if (
    dataDiskGb !== undefined &&
    (typeof dataDiskGb !== "number" ||
      !Number.isInteger(dataDiskGb) ||
      dataDiskGb < GCP_DATA_DISK_MIN_GB ||
      dataDiskGb > GCP_DATA_DISK_MAX_GB)
  ) {
    return {
      ok: false,
      reason: `dataDiskGb, when present, must be an integer number of GB in [${GCP_DATA_DISK_MIN_GB}, ${GCP_DATA_DISK_MAX_GB}]`,
    };
  }
  // The OPTIONAL networking fields. Each is checked only when present (absent/undefined => the
  // default-network, private, untagged, no-metadata VM — unchanged). `network` / `subnetwork` are
  // bare resource NAMES (never URLs — see the section note).
  if (network !== undefined && (typeof network !== "string" || !GCP_RESOURCE_NAME_RE.test(network))) {
    return { ok: false, reason: `network, when present, ${GCP_RESOURCE_NAME_RULE}` };
  }
  if (subnetwork !== undefined && (typeof subnetwork !== "string" || !GCP_RESOURCE_NAME_RE.test(subnetwork))) {
    return { ok: false, reason: `subnetwork, when present, ${GCP_RESOURCE_NAME_RULE}` };
  }
  let cleanTags: string[] | undefined;
  if (tags !== undefined) {
    const validatedTags = cleanGcpResourceNameList(tags, GCP_INSTANCE_TAGS_MAX);
    if (validatedTags === null) {
      return {
        ok: false,
        reason: `tags, when present, must be an array of 1-${GCP_INSTANCE_TAGS_MAX} network tags, each a Compute Engine resource name`,
      };
    }
    cleanTags = validatedTags;
  }
  if (externalIp !== undefined && (typeof externalIp !== "string" || !IPV4_ADDRESS_RE.test(externalIp))) {
    return { ok: false, reason: "externalIp, when present, must be an IPv4 address (e.g. 35.244.66.16)" };
  }
  // startupScript is opaque (any character is legitimate in a shell script) but bounded: non-empty
  // and within Google's metadata-value limit.
  if (
    startupScript !== undefined &&
    (typeof startupScript !== "string" || startupScript.length === 0 || startupScript.length > GCP_STARTUP_SCRIPT_MAX_LENGTH)
  ) {
    return {
      ok: false,
      reason: `startupScript, when present, must be a non-empty string of at most ${GCP_STARTUP_SCRIPT_MAX_LENGTH} characters`,
    };
  }

  // Return a FRESH object holding only the known keys — never the caller's object — so an extra key
  // can never ride along into the instance body the actuator builds. Every optional field is added
  // ONLY when present, so an absent value keeps the signed params (and the body the actuator builds)
  // identical to the four-field form.
  const params: GcpInstanceCreateParams = { project, zone, name, machineType };
  if (dataDiskGb !== undefined) {
    params.dataDiskGb = dataDiskGb;
  }
  if (network !== undefined) {
    params.network = network;
  }
  if (subnetwork !== undefined) {
    params.subnetwork = subnetwork;
  }
  if (cleanTags !== undefined) {
    params.tags = cleanTags;
  }
  if (externalIp !== undefined) {
    params.externalIp = externalIp;
  }
  if (startupScript !== undefined) {
    params.startupScript = startupScript;
  }
  return { ok: true, params };
}

// ── gcp-network-create ───────────────────────────────────────────────────────────────
// Create a cell's dedicated VPC in the AGENCY's own project: a CUSTOM-mode network plus ONE regional
// subnet (planning/34 phase 2 — the web/file/data/gateway VMs all land on this subnet). Five REQUIRED
// strings, each pinned to a strict grammar:
//   1. `project`     — the project id (the actuator pins it to the SA key's own project).
//   2. `region`      — a Compute region, e.g. australia-southeast1 (a URL path segment).
//   3. `networkName` — the VPC's resource name, e.g. dy-cell-australia-southeast1.
//   4. `subnetName`  — the subnet's resource name.
//   5. `ipCidr`      — the subnet's primary range: a PRIVATE (RFC 1918) IPv4 block, /8-/29, e.g.
//                      10.20.0.0/24. Not user-configurable in the cell flow (fixed per cell).
//
// IDEMPOTENT: both inserts treat Google's 409 alreadyExists as success, so a re-run of a half-built
// cell resumes (planning/34 "partial-failure = resume on re-run"). The orchestrator registers it
// `true` in AGENCY_OP_IDEMPOTENT, so the F1 dispatcher may auto-retry a transient failure.

export interface GcpNetworkCreateParams {
  /** The agency's GCP project id the network is created in. */
  project: string;
  /** The Compute Engine region of the subnet, e.g. "australia-southeast1". */
  region: string;
  /** The custom-mode VPC network's name. */
  networkName: string;
  /** The regional subnetwork's name. */
  subnetName: string;
  /** The subnet's primary IPv4 range — a private RFC 1918 block between /8 and /29. */
  ipCidr: string;
}

export function validateGcpNetworkCreateParams(raw: unknown): ParamsVerdict<GcpNetworkCreateParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, networkName, subnetName, ipCidr } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast1)" };
  }
  if (typeof networkName !== "string" || !GCP_RESOURCE_NAME_RE.test(networkName)) {
    return { ok: false, reason: `networkName ${GCP_RESOURCE_NAME_RULE}` };
  }
  if (typeof subnetName !== "string" || !GCP_RESOURCE_NAME_RE.test(subnetName)) {
    return { ok: false, reason: `subnetName ${GCP_RESOURCE_NAME_RULE}` };
  }
  if (typeof ipCidr !== "string" || !GCP_SUBNET_CIDR_RE.test(ipCidr)) {
    return {
      ok: false,
      reason: "ipCidr must be a private (RFC 1918) IPv4 CIDR block between /8 and /29 (e.g. 10.20.0.0/24)",
    };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, networkName, subnetName, ipCidr } };
}

// ── gcp-firewall-create ──────────────────────────────────────────────────────────────
// Create ONE INGRESS firewall rule on a cell's VPC in the AGENCY's own project (planning/34 phase 2:
// one rule for public tcp:22 to the `dy-gateway` tag, one allow-all rule inside the subnet). Six
// REQUIRED params:
//   1. `project`      — the project id (pinned to the SA key's own project by the actuator).
//   2. `networkName`  — the VPC the rule attaches to (a resource name; becomes "global/networks/<name>").
//   3. `ruleName`     — the rule's resource name.
//   4. `allowed`      — 1-32 entries of { protocol, ports? }: `protocol` from the small allowlist
//                       (tcp / udp / icmp / all); `ports` (tcp/udp ONLY, 1-256 entries) are single
//                       ports or low-high ranges within 0-65535. icmp / all carry no ports.
//   5. `sourceRanges` — 1-256 IPv4 CIDR blocks the rule admits traffic FROM (0.0.0.0/0 is legitimate:
//                       the gateway's public sshd, hardened + fail2ban'd, per the live SFTP gateway).
//   6. `targetTags`   — 1-256 network tags the rule applies TO. Required non-empty on purpose: a rule
//                       always names its target scope (an untagged rule would apply to every VM in
//                       the network — a tcp:22-from-anywhere rule must never do that by accident).
// Every list is rebuilt as a FRESH array of validated entries, and every `allowed` entry as a fresh
// object of only its known keys.
//
// IDEMPOTENT: the insert treats Google's 409 alreadyExists as success (a re-run resumes). Registered
// `true` in AGENCY_OP_IDEMPOTENT. Note that idempotence is by NAME — a re-run with a different body
// under the same ruleName is a no-op, not an update.

export const GCP_FIREWALL_PROTOCOLS = ["tcp", "udp", "icmp", "all"] as const;
export type GcpFirewallProtocol = (typeof GCP_FIREWALL_PROTOCOLS)[number];

export interface GcpFirewallAllowed {
  protocol: GcpFirewallProtocol;
  /** tcp/udp only: single ports ("22") or ranges ("8000-8080"), each within 0-65535. */
  ports?: string[];
}

export interface GcpFirewallCreateParams {
  /** The agency's GCP project id the rule is created in. */
  project: string;
  /** The VPC network the rule attaches to. */
  networkName: string;
  /** The firewall rule's name — unique within the project. */
  ruleName: string;
  /** What the rule allows — at least one protocol entry. */
  allowed: GcpFirewallAllowed[];
  /** IPv4 CIDR source ranges the rule admits. */
  sourceRanges: string[];
  /** The network tags of the instances the rule applies to. */
  targetTags: string[];
}

// A port or a low-high range: 1-5 digits each, no leading zero. The numeric bound (<= 65535 and
// low <= high) is checked separately in isValidGcpFirewallPort.
const GCP_FIREWALL_PORT_RE = /^(0|[1-9][0-9]{0,4})(?:-(0|[1-9][0-9]{0,4}))?$/;
const GCP_FIREWALL_PORT_MAX = 65_535;
// Google allows up to 256 source ranges / target tags / ports per rule; the number of `allowed`
// entries has no meaningful reason to exceed a handful (one per protocol + port set).
const GCP_FIREWALL_LIST_MAX = 256;
const GCP_FIREWALL_ALLOWED_MAX = 32;

/** True when `value` is a port ("22") or a low-high range ("8000-8080") within 0-65535. */
function isValidGcpFirewallPort(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const match = GCP_FIREWALL_PORT_RE.exec(value);
  if (!match) return false;
  const low = Number(match[1]);
  if (low > GCP_FIREWALL_PORT_MAX) return false;
  if (match[2] === undefined) return true;
  const high = Number(match[2]);
  return high <= GCP_FIREWALL_PORT_MAX && low <= high;
}

/**
 * Validate ONE `allowed` entry into a fresh { protocol, ports? } object, or return the reason it is
 * invalid. `ports` may be present only for tcp/udp (Google rejects ports on icmp/all).
 */
function cleanGcpFirewallAllowed(entry: unknown): { ok: true; allowed: GcpFirewallAllowed } | { ok: false; reason: string } {
  if (!isPlainObject(entry)) {
    return { ok: false, reason: "each allowed entry must be an object { protocol, ports? }" };
  }
  const { protocol, ports } = entry;
  if (typeof protocol !== "string" || !(GCP_FIREWALL_PROTOCOLS as readonly string[]).includes(protocol)) {
    return { ok: false, reason: `each allowed entry's protocol must be one of ${GCP_FIREWALL_PROTOCOLS.join(", ")}` };
  }
  const typedProtocol = protocol as GcpFirewallProtocol;
  if (ports === undefined) {
    return { ok: true, allowed: { protocol: typedProtocol } };
  }
  if (typedProtocol !== "tcp" && typedProtocol !== "udp") {
    return { ok: false, reason: `allowed ports apply to tcp/udp only (protocol "${typedProtocol}" must not carry ports)` };
  }
  if (!Array.isArray(ports) || ports.length < 1 || ports.length > GCP_FIREWALL_LIST_MAX) {
    return { ok: false, reason: `allowed ports, when present, must be an array of 1-${GCP_FIREWALL_LIST_MAX} port strings` };
  }
  const cleanPorts: string[] = [];
  for (const port of ports) {
    if (!isValidGcpFirewallPort(port)) {
      return { ok: false, reason: 'each allowed port must be a port ("22") or a low-high range ("8000-8080") within 0-65535' };
    }
    cleanPorts.push(port as string);
  }
  return { ok: true, allowed: { protocol: typedProtocol, ports: cleanPorts } };
}

export function validateGcpFirewallCreateParams(raw: unknown): ParamsVerdict<GcpFirewallCreateParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, networkName, ruleName, allowed, sourceRanges, targetTags } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof networkName !== "string" || !GCP_RESOURCE_NAME_RE.test(networkName)) {
    return { ok: false, reason: `networkName ${GCP_RESOURCE_NAME_RULE}` };
  }
  if (typeof ruleName !== "string" || !GCP_RESOURCE_NAME_RE.test(ruleName)) {
    return { ok: false, reason: `ruleName ${GCP_RESOURCE_NAME_RULE}` };
  }

  if (!Array.isArray(allowed) || allowed.length < 1 || allowed.length > GCP_FIREWALL_ALLOWED_MAX) {
    return { ok: false, reason: `allowed must be an array of 1-${GCP_FIREWALL_ALLOWED_MAX} { protocol, ports? } entries` };
  }
  const cleanAllowed: GcpFirewallAllowed[] = [];
  for (const entry of allowed) {
    const verdict = cleanGcpFirewallAllowed(entry);
    if (!verdict.ok) {
      return { ok: false, reason: verdict.reason };
    }
    cleanAllowed.push(verdict.allowed);
  }

  if (!Array.isArray(sourceRanges) || sourceRanges.length < 1 || sourceRanges.length > GCP_FIREWALL_LIST_MAX) {
    return { ok: false, reason: `sourceRanges must be an array of 1-${GCP_FIREWALL_LIST_MAX} IPv4 CIDR blocks` };
  }
  const cleanSourceRanges: string[] = [];
  for (const range of sourceRanges) {
    if (typeof range !== "string" || !IPV4_CIDR_RE.test(range)) {
      return { ok: false, reason: "each sourceRanges entry must be an IPv4 CIDR block (e.g. 0.0.0.0/0 or 10.20.0.0/24)" };
    }
    cleanSourceRanges.push(range);
  }

  const cleanTargetTags = cleanGcpResourceNameList(targetTags, GCP_FIREWALL_LIST_MAX);
  if (cleanTargetTags === null) {
    return {
      ok: false,
      reason: `targetTags must be an array of 1-${GCP_FIREWALL_LIST_MAX} network tags, each a Compute Engine resource name`,
    };
  }

  return {
    ok: true,
    params: { project, networkName, ruleName, allowed: cleanAllowed, sourceRanges: cleanSourceRanges, targetTags: cleanTargetTags },
  };
}

// ── gcp-address-create ───────────────────────────────────────────────────────────────
// Reserve ONE regional static EXTERNAL IPv4 address in the AGENCY's own project — the cell gateway's
// public SFTP endpoint (planning/34 phase 2; the only node with an external IP). Three REQUIRED
// strings, each pinned to a strict grammar: `project` (pinned to the SA key's own project by the
// actuator), `region` (a URL path segment) and `addressName` (a resource name). The actuator reads
// the reserved IP back and returns it (or null while Google is still assigning it).
//
// IDEMPOTENT: the insert treats Google's 409 alreadyExists as success and the read-back then returns
// the existing reservation's IP, so a re-run resumes. Registered `true` in AGENCY_OP_IDEMPOTENT.

export interface GcpAddressCreateParams {
  /** The agency's GCP project id the address is reserved in. */
  project: string;
  /** The Compute Engine region, e.g. "australia-southeast1". */
  region: string;
  /** The reserved address's resource name. */
  addressName: string;
}

export function validateGcpAddressCreateParams(raw: unknown): ParamsVerdict<GcpAddressCreateParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, addressName } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast1)" };
  }
  if (typeof addressName !== "string" || !GCP_RESOURCE_NAME_RE.test(addressName)) {
    return { ok: false, reason: `addressName ${GCP_RESOURCE_NAME_RULE}` };
  }

  return { ok: true, params: { project, region, addressName } };
}

// ── shared ─────────────────────────────────────────────────────────────────────────

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
