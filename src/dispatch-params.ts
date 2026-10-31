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

// The custom-hostname module imports only a TYPE from this one, so this import makes no runtime cycle.
import { isCustomHostnameFqdn } from "./dispatch-params-custom-hostname.js";
import { RATE_LIMIT_MITIGATION_SECONDS, RATE_LIMIT_PERIOD_SECONDS, RATE_LIMIT_REQUESTS_MAX } from "./edge-rate-limit.js";

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

// ── cache-rule-upsert ────────────────────────────────────────────────────────────────
// Upsert the ONE standing "edge page cache" Cache Rule (phase http_request_cache_settings) in an
// agency zone, so anonymous visitors to the agency's WordPress sites are served from Cloudflare's
// edge. Actuated with the agency's own CF_DNS_API_TOKEN, which now also carries
// Zone → Cache Rules: Edit (a deploy-time scope add, not a new secret).
//
// NARROW AUTHORITY (Direction-B principle, fail-closed): the job carries only a host SUFFIX, a TTL
// and an on/off switch — NEVER a raw expression or raw action_parameters. The Worker builds the
// whole rule itself (edge-cache-rule.ts) from these three values, so the platform can at most turn
// a fixed, WordPress-safe cache rule on or off for the zone's WordPress sites: its
// `-production.<zone>` routing hosts plus the customer domains onboarded onto the zone as
// Cloudflare-for-SaaS custom hostnames, and never the zone apex, the agency's other in-zone hosts
// or a branded media host (edge-cache-rule.ts "WHICH HOSTS"). The suffix must be
// EXACTLY "-production." + a zone name; the actuator then resolves that zone with the agency's own
// token and fails closed when the token cannot see it — the same "restricted to its own zone" rule
// dns-record-upsert follows. Unlike the older all-strings ops, the TTL is a real number and
// `enabled` a real boolean (the signed `params` rides as an opaque string, so that is safe).

/** Every edge-cache host suffix is this prefix + the zone name. */
export const EDGE_CACHE_HOST_SUFFIX_PREFIX = "-production.";
// The edge TTL bounds: below 60s the cache barely helps; above an hour a published edit stays
// stale too long for an agency site without an automatic purge-on-publish.
export const EDGE_CACHE_TTL_MIN_SECONDS = 60;
export const EDGE_CACHE_TTL_MAX_SECONDS = 3600;

export interface CacheRuleUpsertParams {
  /** "-production." + the agency zone, e.g. "-production.example.com". */
  hostSuffix: string;
  /** The edge TTL in whole seconds, 60..3600. */
  edgeTtlSeconds: number;
  /** false disables the rule in place (a rollback that keeps the rule). Absent in the job => true. */
  enabled: boolean;
}

/**
 * The zone a valid edge-cache host suffix names ("-production.example.com" -> "example.com"), or
 * null when the suffix is not exactly the prefix + a lowercase zone name (same grammar as the DNS
 * op's zone). The grammar admits only [a-z0-9_.-], so the suffix is safe to embed in a quoted
 * Rules-language string.
 */
export function edgeCacheZoneFromHostSuffix(hostSuffix: string): string | null {
  if (!hostSuffix.startsWith(EDGE_CACHE_HOST_SUFFIX_PREFIX)) {
    return null;
  }
  const zone = hostSuffix.slice(EDGE_CACHE_HOST_SUFFIX_PREFIX.length);
  if (zone.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(zone)) {
    return null;
  }
  return zone;
}

export function validateCacheRuleUpsertParams(raw: unknown): ParamsVerdict<CacheRuleUpsertParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { hostSuffix, edgeTtlSeconds, enabled } = raw;

  if (typeof hostSuffix !== "string" || edgeCacheZoneFromHostSuffix(hostSuffix) === null) {
    return {
      ok: false,
      reason: 'hostSuffix must be "-production." followed by a lowercase DNS zone name (e.g. -production.example.com)',
    };
  }
  if (
    typeof edgeTtlSeconds !== "number" ||
    !Number.isInteger(edgeTtlSeconds) ||
    edgeTtlSeconds < EDGE_CACHE_TTL_MIN_SECONDS ||
    edgeTtlSeconds > EDGE_CACHE_TTL_MAX_SECONDS
  ) {
    return {
      ok: false,
      reason: `edgeTtlSeconds must be an integer from ${EDGE_CACHE_TTL_MIN_SECONDS} to ${EDGE_CACHE_TTL_MAX_SECONDS}`,
    };
  }
  if (enabled !== undefined && typeof enabled !== "boolean") {
    return { ok: false, reason: "enabled, when present, must be true or false" };
  }

  // An absent `enabled` means "on". Normalize it here so the actuator always sees a boolean.
  let enabledValue = true;
  if (enabled === false) {
    enabledValue = false;
  }
  // A FRESH object holding only the known keys, so an extra key can never ride along.
  return { ok: true, params: { hostSuffix, edgeTtlSeconds, enabled: enabledValue } };
}

// ── waf-rule-upsert ──────────────────────────────────────────────────────────────────
// Upsert the edge-defense baseline in an agency zone: five WAF custom rules (block RU/CN/KP, block
// the WordPress admin/login surface from outside the allow-list, managed-challenge the rest of the
// login surface, managed-challenge the front end from outside the allow-list, and skip the Managed
// Ruleset for every request to the cell-agent hosts) plus, ONLY on request, the execute rule this op
// owns for the Cloudflare Managed Ruleset. Actuated with the agency's own CF_DNS_API_TOKEN, which
// needs Zone → WAF : Edit (a deploy-time scope add, not a new secret).
//
// NARROW AUTHORITY (Direction-B principle, fail-closed): the job carries a zone NAME, an on/off
// switch, two HOST lists and a Managed Ruleset switch — NEVER an expression, an action, a path or a
// country list. The country lists are CONSTANTS in edge-waf-rule.ts: a signed country list could
// block every visitor to every site on the agency's zone. A host list cannot: every host must be
// the zone apex or inside the zone, so the worst a bad list does is WEAKEN protection for some of
// the zone's own hosts — an excluded host loses the front-end challenge, and an agent host (always
// also excluded) loses the Managed Ruleset too. No host list can block a visitor.
//
// STRICT KEYS. Unlike the older ops (which drop an unknown key), an unknown key here FAILS the job:
// a country list or a raw expression in these params is a caller bug or an attack, never a
// harmless extra, and silently dropping it would hide which.
//
// The actuator resolves the zone with the agency's own token and fails closed when it cannot see
// it — the same "restricted to its own zone" rule dns-record-upsert follows.

export interface WafRuleUpsertParams {
  /** The agency zone NAME (e.g. "sbmstudio.com.au"); the actuator resolves it to a zone id. */
  zone: string;
  /** false switches the four protective rules off in place (rollback). Absent in the job => true. */
  enabled: boolean;
  /** 1..100 hosts the front-end challenge never applies to (the zone's own infrastructure). */
  excludedHosts: string[];
  /** 1..30 cell-agent hosts: every request to them skips the Managed Ruleset. Each must also be in excludedHosts. */
  agentHosts: string[];
  /**
   * true brings the execute rule THIS op owns for the Cloudflare Managed Ruleset (description
   * "doubleyoup-managed-ruleset") to the same `enabled` state as the run, AFTER the custom rules:
   * enabled:true deploys or re-enables it (Pro plan and above), enabled:false disables it (never
   * deletes it). An execute rule another owner created is never touched. false leaves the managed
   * phase alone. Opt-in: the script sends false unless the operator passes --managed-ruleset.
   */
  includeManagedRuleset: boolean;
}

/** Every key a waf-rule-upsert job may carry. Anything else fails the job. */
const WAF_RULE_UPSERT_KEYS: readonly string[] = ["zone", "enabled", "excludedHosts", "agentHosts", "includeManagedRuleset"];
// Generous for one zone's infrastructure; Cloudflare's 4,096-character expression limit is the real
// ceiling, and the builder checks that before any write.
const WAF_EXCLUDED_HOSTS_MAX = 100;
// Three agents per cell (web, file, gateway), so ten cells on one zone.
const WAF_AGENT_HOSTS_MAX = 30;

/**
 * Validate one host list: an array of `min`..`max` distinct lowercase hostnames, each the zone apex or
 * inside the zone. Returns a FRESH array, never the caller's.
 */
function cleanWafHostList(
  value: unknown,
  zone: string,
  label: string,
  max: number,
): { ok: true; hosts: string[] } | { ok: false; reason: string } {
  const rule = `${label} must be an array of 1-${max} distinct lowercase hostnames, each the zone apex or inside the zone`;
  if (!Array.isArray(value) || value.length < 1 || value.length > max) {
    return { ok: false, reason: rule };
  }
  const hosts: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string" || entry.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(entry)) {
      return { ok: false, reason: rule };
    }
    const insideZone = entry === zone || entry.endsWith(`.${zone}`);
    if (!insideZone) {
      return { ok: false, reason: `${label} entry "${entry}" is not the zone apex or inside the zone ${zone}` };
    }
    if (hosts.includes(entry)) {
      return { ok: false, reason: `${label} lists "${entry}" twice` };
    }
    hosts.push(entry);
  }
  return { ok: true, hosts };
}

export function validateWafRuleUpsertParams(raw: unknown): ParamsVerdict<WafRuleUpsertParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  for (const key of Object.keys(raw)) {
    if (!WAF_RULE_UPSERT_KEYS.includes(key)) {
      return { ok: false, reason: `unknown param "${key}" — waf-rule-upsert takes only ${WAF_RULE_UPSERT_KEYS.join(", ")}` };
    }
  }
  const { zone, enabled, excludedHosts, agentHosts, includeManagedRuleset } = raw;

  // The same zone grammar the DNS ops use. It also reaches the front-end rule's media-suffix clause,
  // inside a quoted string, which this grammar keeps safe.
  if (typeof zone !== "string" || zone.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a lowercase DNS zone name (e.g. example.com)" };
  }
  if (enabled !== undefined && typeof enabled !== "boolean") {
    return { ok: false, reason: "enabled, when present, must be true or false" };
  }
  const excluded = cleanWafHostList(excludedHosts, zone, "excludedHosts", WAF_EXCLUDED_HOSTS_MAX);
  if (!excluded.ok) {
    return excluded;
  }
  const agents = cleanWafHostList(agentHosts, zone, "agentHosts", WAF_AGENT_HOSTS_MAX);
  if (!agents.ok) {
    return agents;
  }
  // An agent host the front-end rule does not exempt would get a managed challenge on its API
  // whenever the caller's country is outside the allow-list — every heavy op would then fail there.
  for (const agentHost of agents.hosts) {
    if (!excluded.hosts.includes(agentHost)) {
      return { ok: false, reason: `agentHosts entry "${agentHost}" must also be in excludedHosts (the agent API must never be challenged)` };
    }
  }
  if (typeof includeManagedRuleset !== "boolean") {
    return { ok: false, reason: "includeManagedRuleset must be true or false" };
  }

  // An absent `enabled` means "on". Normalize it here so the actuator always sees a boolean.
  let enabledValue = true;
  if (enabled === false) {
    enabledValue = false;
  }
  return {
    ok: true,
    params: {
      zone,
      enabled: enabledValue,
      excludedHosts: excluded.hosts,
      agentHosts: agents.hosts,
      includeManagedRuleset,
    },
  };
}

// ── waf-edge-sync ────────────────────────────────────────────────────────────────────
// hub#44 phase 2 (specs/edge-security-via-worker.md). ONE op owns every platform rule in an agency
// zone's firewall-custom phase: the six baseline rules (the five of waf-rule-upsert, with the same
// descriptions so they are patched in place, plus `doubleyoup-xmlrpc`) and the packed ban "chunk"
// rules (`doubleyoup-edge-block:<n>`, `doubleyoup-edge-challenge:<n>`). Every run carries the zone's
// WHOLE desired state, never a diff, so a re-run converges.
//
// NARROW AUTHORITY, as for waf-rule-upsert: the job carries hosts, IP values and User-Agent strings —
// never an expression, an action or a country list. The Worker builds every rule (edge-waf-sync.ts).
// A ban can only ever BLOCK or CHALLENGE (the list it sits in decides which), and only on the hosts it
// names, or on the whole zone minus `excludedHosts` (`hosts: []`). It can never touch the zone's own
// infrastructure hosts: a site host in `excludedHosts` is refused, and a global clause exempts them.
//
// STRICT, at every level: an unknown key fails the job, and so does a DUPLICATE list value (app sends
// canonical, de-duplicated params — spec Amendment A1). IP values must already be CANONICAL (A3), so
// the same ban always renders the same clause text, which is what sticky packing finds clauses by.
//
// TWIN: app's agency-dispatch-params.ts enforces the same rules before it signs.

/** The baseline switches of a waf-edge-sync job: waf-rule-upsert's fields plus the xmlrpc switch. */
export interface WafEdgeSyncBaseline {
  /**
   * false switches the four protective baseline rules AND the xmlrpc rule off IN PLACE (rollback). The
   * agent skip stays on. No baseline rule is ever deleted (spec Amendment A2).
   */
  enabled: boolean;
  /** 1..100 hosts in the zone that no site rule may target; the front-end challenge exempts them. */
  excludedHosts: string[];
  /** 1..30 cell-agent hosts (each also in excludedHosts): every request to them skips the Managed Ruleset. */
  agentHosts: string[];
  /** The waf-rule-upsert meaning: bring OUR Managed Ruleset execute rule to `enabled`, after the custom rules. */
  includeManagedRuleset: boolean;
  /** "block" = the xmlrpc rule is enabled (when `enabled` is true). "off" = present but disabled. */
  xmlrpc: "block" | "off";
}

/** One ban-like entry of the `block` list. `hosts: []` = the whole zone except excludedHosts. */
export interface WafEdgeSyncBlockEntry {
  key: string;
  hosts: string[];
  ips: string[];
  uas: string[];
}

/** One entry of the `challenge` list. `all: true` challenges EVERY request to the entry's hosts. */
export interface WafEdgeSyncChallengeEntry {
  key: string;
  hosts: string[];
  all?: true;
  ips: string[];
  uas: string[];
}

/** One rate-limit threshold (Amendment A7): `requests` per `periodSeconds` per IP, then a block. */
export interface WafEdgeSyncRateLimitThreshold {
  /** 1..1,000,000. */
  requests: number;
  /** 10 or 60. */
  periodSeconds: number;
  /** One of 10, 60, 120, 300, 600, 3600, 86400. The actuator also checks the zone's plan allows it. */
  mitigationSeconds: number;
}

/**
 * The rate-limit switch (Amendment A7). Absent in the job => `{ enabled: false }`. enabled:true needs
 * both thresholds; with enabled:false they are optional (both or neither). enabled:false leaves our two
 * rate-limit rules present but disabled when they exist, and creates nothing.
 */
export type WafEdgeSyncRateLimit =
  | { enabled: true; origin: WafEdgeSyncRateLimitThreshold; expensive: WafEdgeSyncRateLimitThreshold }
  | { enabled: false; origin?: WafEdgeSyncRateLimitThreshold; expensive?: WafEdgeSyncRateLimitThreshold };

export interface WafEdgeSyncParams {
  /** The agency zone NAME; the actuator resolves it with the agency's own token. */
  zone: string;
  baseline: WafEdgeSyncBaseline;
  block: WafEdgeSyncBlockEntry[];
  challenge: WafEdgeSyncChallengeEntry[];
  /**
   * 0..10 custom-rule slots the op leaves free under the plan's cap when a run GROWS the platform's
   * rules (Amendment A10: a run that ends with the same number or fewer needs only its peak to fit).
   * Absent in the job => 3.
   */
  reservedSlots: number;
  /** true deletes the legacy `doubleyoup-ban:*` and `doubleyoup-geo:*` rules, after this run's own writes. */
  retireLegacy: boolean;
  /** The two rate-limit rules. Their own budget; a failure there never blocks the custom rules. */
  rateLimit: WafEdgeSyncRateLimit;
}

const WAF_EDGE_SYNC_KEYS: readonly string[] = [
  "zone",
  "baseline",
  "block",
  "challenge",
  "reservedSlots",
  "retireLegacy",
  "rateLimit",
];
const WAF_EDGE_SYNC_RATE_LIMIT_KEYS: readonly string[] = ["enabled", "origin", "expensive"];
const WAF_EDGE_SYNC_RATE_LIMIT_THRESHOLD_KEYS: readonly string[] = ["requests", "periodSeconds", "mitigationSeconds"];
const WAF_EDGE_SYNC_BASELINE_KEYS: readonly string[] = [
  "enabled",
  "excludedHosts",
  "agentHosts",
  "includeManagedRuleset",
  "xmlrpc",
];
const WAF_EDGE_SYNC_BLOCK_ENTRY_KEYS: readonly string[] = ["key", "hosts", "ips", "uas"];
const WAF_EDGE_SYNC_CHALLENGE_ENTRY_KEYS: readonly string[] = ["key", "hosts", "all", "ips", "uas"];

/** An entry key: what app derives from the ban id. Unique within its list. */
const WAF_EDGE_SYNC_ENTRY_KEY_RE = /^[a-z0-9]{1,32}$/;
const WAF_EDGE_SYNC_ENTRY_HOSTS_MAX = 500;
const WAF_EDGE_SYNC_ENTRY_IPS_MAX = 100;
const WAF_EDGE_SYNC_ENTRY_UAS_MAX = 10;
const WAF_EDGE_SYNC_UA_MIN_LENGTH = 8;
const WAF_EDGE_SYNC_UA_MAX_LENGTH = 256;
const WAF_EDGE_SYNC_RESERVED_SLOTS_MAX = 10;
export const WAF_EDGE_SYNC_RESERVED_SLOTS_DEFAULT = 3;

/** The reason `raw` carries a key outside `allowedKeys`, or null. `label` names the object. */
function unknownKeyReason(raw: Record<string, unknown>, allowedKeys: readonly string[], label: string): string | null {
  for (const key of Object.keys(raw)) {
    if (!allowedKeys.includes(key)) {
      return `unknown key "${key}" in ${label} — it takes only ${allowedKeys.join(", ")}`;
    }
  }
  return null;
}

// The narrowest networks a ban may name are /8 (IPv4) and /24 (IPv6): a wider value would block or
// challenge a large share of the internet on the hosts it names.
const IPV4_NETWORK_PREFIX_MIN = 8;
const IPV6_NETWORK_PREFIX_MIN = 24;

/** The four octets of a canonical dotted-decimal IPv4 address (no leading zeros), or null. */
function canonicalIpv4Octets(text: string): number[] | null {
  const parts = text.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const octets: number[] = [];
  for (const part of parts) {
    // "0", or 1-3 digits without a leading zero: "01" is not canonical.
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) {
      return null;
    }
    const octet = Number(part);
    if (octet > 255) {
      return null;
    }
    octets.push(octet);
  }
  return octets;
}

/** The eight 16-bit groups of an IPv6 address written with lowercase hex and at most one "::", or null. */
function ipv6Groups(text: string): number[] | null {
  // Lowercase hex and colons only: an upper-case digit or an embedded dotted IPv4 is not canonical.
  if (text.length < 2 || text.length > 39 || !/^[0-9a-f:]+$/.test(text)) {
    return null;
  }
  const groupRe = /^[0-9a-f]{1,4}$/;
  const doubleColonIndex = text.indexOf("::");
  if (doubleColonIndex === -1) {
    const parts = text.split(":");
    if (parts.length !== 8) {
      return null;
    }
    const groups: number[] = [];
    for (const part of parts) {
      if (!groupRe.test(part)) {
        return null;
      }
      groups.push(parseInt(part, 16));
    }
    return groups;
  }
  // ":::" or a second "::" is malformed.
  if (text.indexOf("::", doubleColonIndex + 1) !== -1 || text.includes(":::")) {
    return null;
  }
  const headText = text.slice(0, doubleColonIndex);
  const tailText = text.slice(doubleColonIndex + 2);
  let headParts: string[] = [];
  if (headText.length > 0) {
    headParts = headText.split(":");
  }
  let tailParts: string[] = [];
  if (tailText.length > 0) {
    tailParts = tailText.split(":");
  }
  // "::" stands for at least one group, so at most seven are written out.
  if (headParts.length + tailParts.length > 7) {
    return null;
  }
  const groups: number[] = [];
  for (const part of headParts) {
    if (!groupRe.test(part)) {
      return null;
    }
    groups.push(parseInt(part, 16));
  }
  const zeroGroupCount = 8 - headParts.length - tailParts.length;
  for (let index = 0; index < zeroGroupCount; index += 1) {
    groups.push(0);
  }
  for (const part of tailParts) {
    if (!groupRe.test(part)) {
      return null;
    }
    groups.push(parseInt(part, 16));
  }
  return groups;
}

/**
 * The RFC 5952 text of eight IPv6 groups: lowercase hex without leading zeros, and the LONGEST run of
 * two or more zero groups written as "::" (the leftmost run on a tie). A single zero group stays "0".
 */
export function rfc5952Ipv6Text(groups: readonly number[]): string {
  let bestRunStart = -1;
  let bestRunLength = 0;
  let runStart = -1;
  for (let index = 0; index <= groups.length; index += 1) {
    const isZero = index < groups.length && groups[index] === 0;
    if (isZero) {
      if (runStart === -1) {
        runStart = index;
      }
      continue;
    }
    if (runStart !== -1) {
      const runLength = index - runStart;
      // Strictly longer only, so the LEFTMOST of two equal runs wins.
      if (runLength > bestRunLength) {
        bestRunStart = runStart;
        bestRunLength = runLength;
      }
      runStart = -1;
    }
  }
  const hexGroups = groups.map((group) => group.toString(16));
  if (bestRunLength < 2) {
    return hexGroups.join(":");
  }
  const head = hexGroups.slice(0, bestRunStart).join(":");
  const tail = hexGroups.slice(bestRunStart + bestRunLength).join(":");
  return `${head}::${tail}`;
}

/** True when every bit after the first `prefixLength` bits of `groups` (each `bitsPerGroup` wide) is zero. */
function hostBitsAreZero(groups: readonly number[], bitsPerGroup: number, prefixLength: number): boolean {
  for (let index = 0; index < groups.length; index += 1) {
    const groupStartBit = index * bitsPerGroup;
    const networkBitsInGroup = Math.max(0, Math.min(bitsPerGroup, prefixLength - groupStartBit));
    const hostBitsInGroup = bitsPerGroup - networkBitsInGroup;
    if (hostBitsInGroup === 0) {
      continue;
    }
    const hostMask = 2 ** hostBitsInGroup - 1;
    if ((groups[index] as number) % (hostMask + 1) !== 0) {
      return false;
    }
  }
  return true;
}

/**
 * The two IPv6 ranges that carry IPv4 addresses, as their first six 16-bit groups: ::/96
 * (IPv4-compatible; it also holds the unspecified :: and the loopback ::1) and ::ffff:0:0/96
 * (IPv4-mapped). A ban there could match IPv4 clients or nothing at all, so neither is a ban value.
 */
const IPV6_EMBEDDED_IPV4_RANGES: ReadonlyArray<readonly number[]> = [
  [0, 0, 0, 0, 0, 0],
  [0, 0, 0, 0, 0, 0xffff],
];

/**
 * True when the IPv6 range `groups`/`prefixLength` shares any address with the /96 range
 * `rangeGroups`: their first min(prefixLength, 96) bits are equal. So a range inside the /96, and a
 * wider range that contains it (such as ::/24), both overlap.
 */
function overlapsIpv6Slash96(groups: readonly number[], prefixLength: number, rangeGroups: readonly number[]): boolean {
  const comparedBits = Math.min(prefixLength, 96);
  for (let index = 0; index < 6; index += 1) {
    const bitsInGroup = Math.max(0, Math.min(16, comparedBits - index * 16));
    if (bitsInGroup === 0) {
      break;
    }
    const shift = 16 - bitsInGroup;
    if ((groups[index] as number) >> shift !== (rangeGroups[index] as number) >> shift) {
      return false;
    }
  }
  return true;
}

/**
 * The reason `value` is not a CANONICAL ban IP value (spec Amendment A3), or null:
 *   - IPv4: dotted decimal, no leading zeros. A host is the bare address (no "/32"). A network is
 *     "<address>/8..31" with the host bits zero.
 *   - IPv6: RFC 5952 text, no embedded dotted IPv4. A host is bare (no "/128"). A network is
 *     "<address>/24..127" with the host bits zero. Nothing that overlaps ::/96 or ::ffff:0:0/96
 *     (Amendment A10), so neither ::, ::1 nor an IPv4-mapped address.
 * "0.0.0.0/0" and "::/0" fail the prefix floor. Canonical text means one ban always renders one clause.
 */
export function canonicalEdgeIpReason(value: unknown): string | null {
  if (typeof value !== "string") {
    return "an IP value must be a string";
  }
  const slashIndex = value.indexOf("/");
  let addressText = value;
  let prefixText: string | null = null;
  if (slashIndex !== -1) {
    addressText = value.slice(0, slashIndex);
    prefixText = value.slice(slashIndex + 1);
  }
  let prefixLength: number | null = null;
  if (prefixText !== null) {
    if (!/^[1-9][0-9]{0,2}$/.test(prefixText)) {
      return `"${value}" has a malformed prefix length`;
    }
    prefixLength = Number(prefixText);
  }

  if (!addressText.includes(":")) {
    const octets = canonicalIpv4Octets(addressText);
    if (octets === null) {
      return `"${value}" is not a canonical IPv4 address (dotted decimal, no leading zeros)`;
    }
    if (prefixLength === null) {
      return null;
    }
    if (prefixLength < IPV4_NETWORK_PREFIX_MIN || prefixLength > 31) {
      return `"${value}": an IPv4 network must be /${IPV4_NETWORK_PREFIX_MIN} to /31 (write a single host without /32)`;
    }
    if (!hostBitsAreZero(octets, 8, prefixLength)) {
      return `"${value}" has host bits set — write the network address`;
    }
    return null;
  }

  const groups = ipv6Groups(addressText);
  if (groups === null || rfc5952Ipv6Text(groups) !== addressText) {
    return `"${value}" is not a canonical IPv6 address (RFC 5952: lowercase, no leading zeros, the longest zero run as ::)`;
  }
  if (prefixLength !== null) {
    if (prefixLength < IPV6_NETWORK_PREFIX_MIN || prefixLength > 127) {
      return `"${value}": an IPv6 network must be /${IPV6_NETWORK_PREFIX_MIN} to /127 (write a single host without /128)`;
    }
    if (!hostBitsAreZero(groups, 16, prefixLength)) {
      return `"${value}" has host bits set — write the network address`;
    }
  }
  let rangePrefixLength = 128;
  if (prefixLength !== null) {
    rangePrefixLength = prefixLength;
  }
  for (const range of IPV6_EMBEDDED_IPV4_RANGES) {
    if (overlapsIpv6Slash96(groups, rangePrefixLength, range)) {
      return `"${value}" overlaps ::/96 or ::ffff:0:0/96 (the IPv6 ranges that carry IPv4 addresses) — ban the IPv4 address instead`;
    }
  }
  return null;
}

/**
 * The reason `value` is not a User-Agent a ban may match, or null: printable ASCII, 8-256 characters,
 * with no `"` and no `\`. The value lands inside a quoted Rules-language string, and those two are
 * the only characters that could end or escape it.
 */
export function edgeUserAgentReason(value: unknown): string | null {
  if (typeof value !== "string") {
    return "a User-Agent value must be a string";
  }
  if (value.length < WAF_EDGE_SYNC_UA_MIN_LENGTH || value.length > WAF_EDGE_SYNC_UA_MAX_LENGTH) {
    return `a User-Agent value must be ${WAF_EDGE_SYNC_UA_MIN_LENGTH}-${WAF_EDGE_SYNC_UA_MAX_LENGTH} characters`;
  }
  if (!/^[\x20-\x7e]+$/.test(value)) {
    return "a User-Agent value must be printable ASCII";
  }
  if (value.includes('"') || value.includes("\\")) {
    return 'a User-Agent value must not contain " or \\';
  }
  return null;
}

/**
 * Validate one string list of an entry: an array of 0..`max` distinct values, each passing
 * `valueReason`. Returns a FRESH array, never the caller's.
 */
function cleanEntryList(
  value: unknown,
  label: string,
  max: number,
  valueReason: (entry: unknown) => string | null,
): { ok: true; values: string[] } | { ok: false; reason: string } {
  if (!Array.isArray(value) || value.length > max) {
    return { ok: false, reason: `${label} must be an array of 0-${max} values` };
  }
  const values: string[] = [];
  for (const entry of value) {
    const reason = valueReason(entry);
    if (reason !== null) {
      return { ok: false, reason: `${label}: ${reason}` };
    }
    // Strict: a duplicate is a caller bug (app de-duplicates before signing), never silently merged.
    if (values.includes(entry as string)) {
      return { ok: false, reason: `${label} lists "${String(entry)}" twice` };
    }
    values.push(entry as string);
  }
  return { ok: true, values };
}

/** The reason `value` is not a site host for a ban entry, or null. Custom domains may lie outside the zone. */
function edgeSiteHostReason(value: unknown): string | null {
  if (!isCustomHostnameFqdn(value)) {
    return `"${String(value)}" is not a lowercase fully-qualified host name`;
  }
  return null;
}

/** One validated entry of either list. `all` is false when the job left it out. */
interface ValidEdgeEntry {
  key: string;
  hosts: string[];
  ips: string[];
  uas: string[];
  all: boolean;
}

type EdgeEntryVerdict = { ok: true; entry: ValidEdgeEntry } | { ok: false; reason: string };

/** Validate one block or challenge entry. `allowAll` is true only for the challenge list. */
function validateWafEdgeSyncEntry(
  raw: unknown,
  label: string,
  allowAll: boolean,
  excludedHosts: readonly string[],
): EdgeEntryVerdict {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: `${label} must be a JSON object` };
  }
  let allowedKeys = WAF_EDGE_SYNC_BLOCK_ENTRY_KEYS;
  if (allowAll) {
    allowedKeys = WAF_EDGE_SYNC_CHALLENGE_ENTRY_KEYS;
  }
  const unknownKey = unknownKeyReason(raw, allowedKeys, label);
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  const key = raw.key;
  if (typeof key !== "string" || !WAF_EDGE_SYNC_ENTRY_KEY_RE.test(key)) {
    return { ok: false, reason: `${label}.key must be 1-32 lowercase letters or digits` };
  }
  const hosts = cleanEntryList(raw.hosts, `${label}.hosts`, WAF_EDGE_SYNC_ENTRY_HOSTS_MAX, edgeSiteHostReason);
  if (!hosts.ok) {
    return hosts;
  }
  // A site rule must never reach the zone's own infrastructure (the agent API, the control plane).
  for (const host of hosts.values) {
    if (excludedHosts.includes(host)) {
      return { ok: false, reason: `${label}.hosts lists "${host}", which is in baseline.excludedHosts` };
    }
  }
  const ips = cleanEntryList(raw.ips, `${label}.ips`, WAF_EDGE_SYNC_ENTRY_IPS_MAX, canonicalEdgeIpReason);
  if (!ips.ok) {
    return ips;
  }
  const uas = cleanEntryList(raw.uas, `${label}.uas`, WAF_EDGE_SYNC_ENTRY_UAS_MAX, edgeUserAgentReason);
  if (!uas.ok) {
    return uas;
  }
  // `all` is either absent or literally true: `all: false` is a caller bug, not a harmless default.
  let all = false;
  if (raw.all !== undefined) {
    if (raw.all !== true) {
      return { ok: false, reason: `${label}.all, when present, must be true` };
    }
    all = true;
  }
  if (ips.values.length === 0 && uas.values.length === 0 && !all) {
    return { ok: false, reason: `${label} needs at least one of ips, uas or all` };
  }
  return { ok: true, entry: { key, hosts: hosts.values, ips: ips.values, uas: uas.values, all } };
}

/** Validate a block or challenge list: an array of entries with keys unique within the list. */
function validateWafEdgeSyncList(
  raw: unknown,
  listName: "block" | "challenge",
  excludedHosts: readonly string[],
): { ok: true; entries: ValidEdgeEntry[] } | { ok: false; reason: string } {
  if (!Array.isArray(raw)) {
    return { ok: false, reason: `${listName} must be an array (empty for none)` };
  }
  const allowAll = listName === "challenge";
  const seenKeys: string[] = [];
  const entries: ValidEdgeEntry[] = [];
  for (let index = 0; index < raw.length; index += 1) {
    const verdict = validateWafEdgeSyncEntry(raw[index], `${listName}[${index}]`, allowAll, excludedHosts);
    if (!verdict.ok) {
      return verdict;
    }
    if (seenKeys.includes(verdict.entry.key)) {
      return { ok: false, reason: `${listName} has two entries with key "${verdict.entry.key}"` };
    }
    seenKeys.push(verdict.entry.key);
    entries.push(verdict.entry);
  }
  return { ok: true, entries };
}

type RateLimitThresholdVerdict = { ok: true; threshold: WafEdgeSyncRateLimitThreshold } | { ok: false; reason: string };

function validateRateLimitThreshold(raw: unknown, label: string): RateLimitThresholdVerdict {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: `${label} must be a JSON object` };
  }
  const unknownKey = unknownKeyReason(raw, WAF_EDGE_SYNC_RATE_LIMIT_THRESHOLD_KEYS, label);
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  const { requests, periodSeconds, mitigationSeconds } = raw;
  if (typeof requests !== "number" || !Number.isInteger(requests) || requests < 1 || requests > RATE_LIMIT_REQUESTS_MAX) {
    return { ok: false, reason: `${label}.requests must be an integer from 1 to ${RATE_LIMIT_REQUESTS_MAX}` };
  }
  if (typeof periodSeconds !== "number" || !RATE_LIMIT_PERIOD_SECONDS.includes(periodSeconds)) {
    return { ok: false, reason: `${label}.periodSeconds must be one of ${RATE_LIMIT_PERIOD_SECONDS.join(", ")}` };
  }
  if (typeof mitigationSeconds !== "number" || !RATE_LIMIT_MITIGATION_SECONDS.includes(mitigationSeconds)) {
    return { ok: false, reason: `${label}.mitigationSeconds must be one of ${RATE_LIMIT_MITIGATION_SECONDS.join(", ")}` };
  }
  return { ok: true, threshold: { requests, periodSeconds, mitigationSeconds } };
}

type RateLimitVerdict = { ok: true; rateLimit: WafEdgeSyncRateLimit } | { ok: false; reason: string };

/** The `rateLimit` key (Amendment A7). Absent => disabled. Returns a FRESH object. */
function validateWafEdgeSyncRateLimit(raw: unknown): RateLimitVerdict {
  if (raw === undefined) {
    return { ok: true, rateLimit: { enabled: false } };
  }
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "rateLimit, when present, must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, WAF_EDGE_SYNC_RATE_LIMIT_KEYS, "rateLimit");
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (typeof raw.enabled !== "boolean") {
    return { ok: false, reason: "rateLimit.enabled must be true or false" };
  }
  const hasOrigin = raw.origin !== undefined;
  const hasExpensive = raw.expensive !== undefined;
  if (!hasOrigin && !hasExpensive) {
    if (raw.enabled) {
      return { ok: false, reason: "rateLimit.enabled true needs both rateLimit.origin and rateLimit.expensive" };
    }
    return { ok: true, rateLimit: { enabled: false } };
  }
  if (!hasOrigin || !hasExpensive) {
    return { ok: false, reason: "rateLimit takes both origin and expensive, or neither" };
  }
  const origin = validateRateLimitThreshold(raw.origin, "rateLimit.origin");
  if (!origin.ok) {
    return origin;
  }
  const expensive = validateRateLimitThreshold(raw.expensive, "rateLimit.expensive");
  if (!expensive.ok) {
    return expensive;
  }
  if (raw.enabled) {
    return { ok: true, rateLimit: { enabled: true, origin: origin.threshold, expensive: expensive.threshold } };
  }
  return { ok: true, rateLimit: { enabled: false, origin: origin.threshold, expensive: expensive.threshold } };
}

export function validateWafEdgeSyncParams(raw: unknown): ParamsVerdict<WafEdgeSyncParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownTopKey = unknownKeyReason(raw, WAF_EDGE_SYNC_KEYS, "waf-edge-sync params");
  if (unknownTopKey !== null) {
    return { ok: false, reason: unknownTopKey };
  }
  const { zone, baseline, block, challenge, reservedSlots, retireLegacy, rateLimit } = raw;

  if (typeof zone !== "string" || zone.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a lowercase DNS zone name (e.g. example.com)" };
  }

  if (!isPlainObject(baseline)) {
    return { ok: false, reason: "baseline must be a JSON object" };
  }
  const unknownBaselineKey = unknownKeyReason(baseline, WAF_EDGE_SYNC_BASELINE_KEYS, "baseline");
  if (unknownBaselineKey !== null) {
    return { ok: false, reason: unknownBaselineKey };
  }
  if (typeof baseline.enabled !== "boolean") {
    return { ok: false, reason: "baseline.enabled must be true or false" };
  }
  // The same host rules as waf-rule-upsert: both lists lie in the zone, and every agent host is excluded.
  const excluded = cleanWafHostList(baseline.excludedHosts, zone, "baseline.excludedHosts", WAF_EXCLUDED_HOSTS_MAX);
  if (!excluded.ok) {
    return excluded;
  }
  const agents = cleanWafHostList(baseline.agentHosts, zone, "baseline.agentHosts", WAF_AGENT_HOSTS_MAX);
  if (!agents.ok) {
    return agents;
  }
  for (const agentHost of agents.hosts) {
    if (!excluded.hosts.includes(agentHost)) {
      return {
        ok: false,
        reason: `baseline.agentHosts entry "${agentHost}" must also be in baseline.excludedHosts (the agent API must never be challenged)`,
      };
    }
  }
  if (typeof baseline.includeManagedRuleset !== "boolean") {
    return { ok: false, reason: "baseline.includeManagedRuleset must be true or false" };
  }
  if (baseline.xmlrpc !== "block" && baseline.xmlrpc !== "off") {
    return { ok: false, reason: 'baseline.xmlrpc must be "block" or "off"' };
  }

  const blockList = validateWafEdgeSyncList(block, "block", excluded.hosts);
  if (!blockList.ok) {
    return blockList;
  }
  const challengeList = validateWafEdgeSyncList(challenge, "challenge", excluded.hosts);
  if (!challengeList.ok) {
    return challengeList;
  }

  let reservedSlotsValue = WAF_EDGE_SYNC_RESERVED_SLOTS_DEFAULT;
  if (reservedSlots !== undefined) {
    if (
      typeof reservedSlots !== "number" ||
      !Number.isInteger(reservedSlots) ||
      reservedSlots < 0 ||
      reservedSlots > WAF_EDGE_SYNC_RESERVED_SLOTS_MAX
    ) {
      return { ok: false, reason: `reservedSlots, when present, must be an integer from 0 to ${WAF_EDGE_SYNC_RESERVED_SLOTS_MAX}` };
    }
    reservedSlotsValue = reservedSlots;
  }
  if (typeof retireLegacy !== "boolean") {
    return { ok: false, reason: "retireLegacy must be true or false" };
  }
  const rateLimitVerdict = validateWafEdgeSyncRateLimit(rateLimit);
  if (!rateLimitVerdict.ok) {
    return rateLimitVerdict;
  }

  // FRESH objects holding only the known keys, so nothing extra can ride along into the actuator.
  const blockEntries: WafEdgeSyncBlockEntry[] = [];
  for (const entry of blockList.entries) {
    blockEntries.push({ key: entry.key, hosts: entry.hosts, ips: entry.ips, uas: entry.uas });
  }
  const challengeEntries: WafEdgeSyncChallengeEntry[] = [];
  for (const entry of challengeList.entries) {
    const challengeEntry: WafEdgeSyncChallengeEntry = { key: entry.key, hosts: entry.hosts, ips: entry.ips, uas: entry.uas };
    if (entry.all) {
      challengeEntry.all = true;
    }
    challengeEntries.push(challengeEntry);
  }
  return {
    ok: true,
    params: {
      zone,
      baseline: {
        enabled: baseline.enabled,
        excludedHosts: excluded.hosts,
        agentHosts: agents.hosts,
        includeManagedRuleset: baseline.includeManagedRuleset,
        xmlrpc: baseline.xmlrpc,
      },
      block: blockEntries,
      challenge: challengeEntries,
      reservedSlots: reservedSlotsValue,
      retireLegacy,
      rateLimit: rateLimitVerdict.rateLimit,
    },
  };
}

// ── cf-tunnel-create ─────────────────────────────────────────────────────────────────
// Create (idempotently, by name) a per-cell Cloudflare **named tunnel** in the agency's own CF
// account and return its id + connector token (planning/40 Component A). Actuated with the agency's
// own CF_DNS_API_TOKEN, which now also carries account-level `Cloudflare Tunnel: Edit` (a deploy-time
// scope add, not a new secret). One platform-generated param:
//   1. `tunnelName` — the per-cell tunnel name the platform derives (e.g. "dy-cell-<region>"). It
//      reaches Cloudflare only as a JSON body field of the cfd_tunnel create; the grammar (a lowercase
//      resource name) is defense-in-depth alongside JSON.stringify in the actuator.
// IDEMPOTENT: the actuator reuses a non-deleted tunnel of the same name (registered `true` in the
// orchestrator's AGENCY_OP_IDEMPOTENT, so a transient failure may auto-retry; a re-run reuses the
// existing tunnel + re-fetches its token).

export interface CfTunnelCreateParams {
  /** The per-cell tunnel name the platform derives, e.g. "dy-cell-australia-southeast2". */
  tunnelName: string;
}

// A lowercase Compute-style resource name: 1-63 chars, alphanumeric start + end, [a-z0-9-] within.
const CF_TUNNEL_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function validateCfTunnelCreateParams(raw: unknown): ParamsVerdict<CfTunnelCreateParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { tunnelName } = raw;
  if (typeof tunnelName !== "string" || !CF_TUNNEL_NAME_RE.test(tunnelName)) {
    return {
      ok: false,
      reason:
        "tunnelName must be a lowercase name (1-63 chars: letter/digit first and last, letters, digits, hyphens within)",
    };
  }
  return { ok: true, params: { tunnelName } };
}

// ── cf-tunnel-config ─────────────────────────────────────────────────────────────────
// Set a per-cell tunnel's remotely-managed ingress (planning/40 Component A): map public hostnames to
// origin services the connector (cloudflared on the gateway) reaches over the VPC — e.g. the web
// node's cell-agent at http://<web-internal-dns>:9440. Actuated with the same CF_DNS_API_TOKEN /
// tunnel scope. Two params, plus one optional:
//   1. `tunnelId` — the cfd_tunnel id from cf-tunnel-create (a 32-char hex id; a URL path segment).
//   2. `ingress` — 1..20 { hostname, service } rules. The tunnel is per-cell (dedicated), so the
//      actuator writes the FULL config (a PUT) and appends the mandatory catch-all rule itself, so a
//      caller can neither omit it nor smuggle a second catch-all.
//   3. `catchAllService` (OPTIONAL) — what the appended catch-all points at: an http(s) origin URL
//      under the SAME grammar as a rule's `service`, or `http_status:<3 digits>`. Absent => the
//      actuator's default, http_status:404, so every existing caller's config is byte-identical. A
//      cell sets it to the web node's nginx (:80) so EVERY site host on the cell (a DNS CNAME to the
//      tunnel) lands on nginx, which selects the site by server_name — per-site edge wiring is then
//      DNS-only and never edits this config (the platform's CF token can't reach an agency tunnel).
// The `service` is an http(s) origin URL (scheme + host + optional port, NO path) — the host may be a
// GCP-internal DNS name (dots + hyphens), which cloudflared on the gateway resolves over the VPC.

export interface CfTunnelConfigIngressRule {
  /** The public hostname (a FQDN on the agency's zone), e.g. "cell-australia-southeast2.example.com". */
  hostname: string;
  /** The origin service URL, e.g. "http://dy-web-...internal:9440" (scheme + host + optional port). */
  service: string;
  /** OPTIONAL: exactly `{ httpHostHeader }` — a kept session route's setting (cleanCfTunnelOriginRequest). */
  originRequest?: CfTunnelOriginRequest;
}

export interface CfTunnelConfigParams {
  /** The cfd_tunnel id to configure (from cf-tunnel-create). */
  tunnelId: string;
  /** The ingress rules; the actuator appends the mandatory catch-all (`catchAllService`, else http_status:404). */
  ingress: CfTunnelConfigIngressRule[];
  /** OPTIONAL: the catch-all's service — an http(s) origin URL (a rule's `service` grammar) or
   *  `http_status:<3 digits>`. Absent => http_status:404 (unchanged). */
  catchAllService?: string;
  /** OPTIONAL: the top-level `warp-routing` key, exactly `{ enabled }` (cleanCfTunnelWarpRouting). Absent => not written. */
  warpRouting?: CfTunnelWarpRouting;
}

// A Cloudflare tunnel id: a lowercase-hex UUID (the cfd_tunnel API returns a 36-char hyphenated UUID,
// e.g. 031b5bee-a61a-444f-882e-451fd644e59f); also accept a bare 32-hex form for robustness. Also a URL
// path segment; encodeURIComponent'd in the actuator anyway.
const CF_TUNNEL_ID_RE = /^([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
// An http(s) origin service: scheme + host (alnum, dots, hyphens — a public host OR a GCP-internal DNS
// name) + OPTIONAL port. No path/query, no userinfo, no shell/URL metacharacter.
const CF_TUNNEL_SERVICE_RE = /^https?:\/\/[a-z0-9](?:[a-z0-9.-]{0,253})(?::([0-9]{1,5}))?$/;
// The ONLY non-origin form a catch-all may take: cloudflared's fixed-status responder (http_status:404
// is the actuator's default). Exactly 3 digits — a status code, nothing else.
const CF_TUNNEL_HTTP_STATUS_SERVICE_RE = /^http_status:[0-9]{3}$/;
const CF_TUNNEL_CATCH_ALL_REASON =
  "catchAllService, when present, must be http_status:<3 digits> or an http(s) origin URL (scheme + host + optional port, no path)";
const CF_TUNNEL_INGRESS_MAX = 20;
const TCP_PORT_MAX = 65_535;

export function validateCfTunnelConfigParams(raw: unknown): ParamsVerdict<CfTunnelConfigParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { tunnelId, ingress, catchAllService, warpRouting } = raw;

  if (typeof tunnelId !== "string" || !CF_TUNNEL_ID_RE.test(tunnelId)) {
    return { ok: false, reason: "tunnelId must be a lowercase-hex Cloudflare tunnel id (a 36-char UUID, or 32 hex chars)" };
  }
  if (!Array.isArray(ingress) || ingress.length < 1 || ingress.length > CF_TUNNEL_INGRESS_MAX) {
    return { ok: false, reason: `ingress must be an array of 1-${CF_TUNNEL_INGRESS_MAX} { hostname, service } rules` };
  }
  // Build a FRESH array of only the validated { hostname, service } — never the caller's objects — so
  // an extra key on a rule can never ride along into the tunnel config the actuator writes.
  const cleanIngress: CfTunnelConfigIngressRule[] = [];
  for (const rule of ingress) {
    if (!isPlainObject(rule)) {
      return { ok: false, reason: "each ingress rule must be an object { hostname, service }" };
    }
    const { hostname, service, originRequest } = rule;
    if (typeof hostname !== "string" || hostname.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(hostname)) {
      return { ok: false, reason: "each ingress hostname must be a lowercase fully-qualified hostname (2+ labels)" };
    }
    if (typeof service !== "string") {
      return { ok: false, reason: "each ingress service must be an http(s) origin URL (scheme + host + optional port, no path)" };
    }
    const serviceMatch = CF_TUNNEL_SERVICE_RE.exec(service);
    if (!serviceMatch) {
      return { ok: false, reason: "each ingress service must be an http(s) origin URL (scheme + host + optional port, no path)" };
    }
    if (serviceMatch[1] !== undefined && Number(serviceMatch[1]) > TCP_PORT_MAX) {
      return { ok: false, reason: "each ingress service port must be 0-65535" };
    }
    // planning/50 integration review M1: a kept session route's originRequest, in its ONE shape.
    const cleanOrigin = cleanCfTunnelOriginRequest(originRequest);
    if (!cleanOrigin.ok) {
      return { ok: false, reason: cleanOrigin.reason };
    }
    if (cleanOrigin.value === undefined) {
      cleanIngress.push({ hostname, service });
    } else {
      cleanIngress.push({ hostname, service, originRequest: cleanOrigin.value });
    }
  }

  // The optional catch-all. ABSENT => return exactly the two-key params object every earlier caller
  // gets (no `catchAllService` key at all), so the signed bytes and the written config are unchanged.
  // PRESENT => either the http_status form or an origin URL under the SAME grammar (and port bound)
  // as a rule's `service` above — a catch-all is just a hostname-less rule, so it may reach only what
  // a named rule may reach. Anything else (null, a number, "") fails closed.
  const params: CfTunnelConfigParams = { tunnelId, ingress: cleanIngress };
  if (catchAllService !== undefined) {
    if (typeof catchAllService !== "string") {
      return { ok: false, reason: CF_TUNNEL_CATCH_ALL_REASON };
    }
    if (!CF_TUNNEL_HTTP_STATUS_SERVICE_RE.test(catchAllService)) {
      const catchAllMatch = CF_TUNNEL_SERVICE_RE.exec(catchAllService);
      if (!catchAllMatch) {
        return { ok: false, reason: CF_TUNNEL_CATCH_ALL_REASON };
      }
      if (catchAllMatch[1] !== undefined && Number(catchAllMatch[1]) > TCP_PORT_MAX) {
        return { ok: false, reason: "catchAllService port must be 0-65535" };
      }
    }
    params.catchAllService = catchAllService;
  }
  // planning/50 integration review M2: the top-level warp-routing key, written back as it was read.
  // ABSENT => no key, so every earlier caller's signed bytes and written config are unchanged.
  if (warpRouting !== undefined) {
    const cleanWarp = cleanCfTunnelWarpRouting(warpRouting);
    if (!cleanWarp.ok) {
      return { ok: false, reason: cleanWarp.reason };
    }
    params.warpRouting = cleanWarp.value;
  }
  return { ok: true, params };
}

// ── cf-tunnel-delete ─────────────────────────────────────────────────────────────────
// Delete a per-cell Cloudflare tunnel on teardown (planning/40 Phase B) — the mirror of
// cf-tunnel-create, so an auto-cell teardown doesn't orphan the tunnel in the agency's account.
// One param: the cfd_tunnel id (same UUID grammar as cf-tunnel-config). IDEMPOTENT: a 404 (already
// deleted) is success, so a resumed teardown converges.

export interface CfTunnelDeleteParams {
  /** The cfd_tunnel id to delete (from the Cell row's tunnelId). */
  tunnelId: string;
}

export function validateCfTunnelDeleteParams(raw: unknown): ParamsVerdict<CfTunnelDeleteParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { tunnelId } = raw;
  if (typeof tunnelId !== "string" || !CF_TUNNEL_ID_RE.test(tunnelId)) {
    return { ok: false, reason: "tunnelId must be a lowercase-hex Cloudflare tunnel id (a 36-char UUID, or 32 hex chars)" };
  }
  return { ok: true, params: { tunnelId } };
}

// ── dns-record-delete ────────────────────────────────────────────────────────────────
// Delete ONE DNS record (type + name) in an agency zone on teardown (planning/40 Phase B) — the
// mirror of dns-record-upsert, so an auto-cell teardown removes the agent-host CNAME. Three params,
// the same grammars dns-record-upsert uses (no content/ttl/proxied — a delete keys on type + name).
// IDEMPOTENT: a record already gone is success.

export interface DnsRecordDeleteParams {
  /** The zone NAME (e.g. "example.com") — resolved to a zone id by the actuator. */
  zone: string;
  type: DnsRecordType;
  /** Fully-qualified record name, within `zone`. */
  name: string;
}

export function validateDnsRecordDeleteParams(raw: unknown): ParamsVerdict<DnsRecordDeleteParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { zone, type, name } = raw;
  if (typeof zone !== "string" || zone.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a lowercase DNS zone name (e.g. example.com)" };
  }
  if (typeof type !== "string" || !(DNS_RECORD_TYPES as readonly string[]).includes(type)) {
    return { ok: false, reason: `type must be one of ${DNS_RECORD_TYPES.join(", ")}` };
  }
  if (typeof name !== "string" || name.length > DNS_NAME_MAX_LENGTH || !DNS_RECORD_NAME_RE.test(name)) {
    return { ok: false, reason: "name must be a lowercase fully-qualified DNS record name" };
  }
  const nameWithoutWildcard = name.startsWith("*.") ? name.slice(2) : name;
  const nameIsInZone = nameWithoutWildcard === zone || nameWithoutWildcard.endsWith(`.${zone}`);
  if (!nameIsInZone) {
    return { ok: false, reason: "name must be within zone (equal to it or a subdomain of it)" };
  }
  return { ok: true, params: { zone, type: type as DnsRecordType, name } };
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
// gcp-network-create / gcp-firewall-create / gcp-address-create / gcp-router-nat-create resource ops
// (planning/34 phases 2-3).
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
// A NAME PREFIX for the resume instances.list filter: like a Compute resource name but, being a
// PREFIX, it MAY end in a hyphen (e.g. "dy-"). 1-63 chars, lowercase-letter start, [-a-z0-9] only —
// no regex metacharacter, so it is safe to embed in the server-side aggregatedList `name` filter.
const GCP_NAME_PREFIX_RE = /^[a-z][-a-z0-9]{0,62}$/;
const GCP_NAME_PREFIX_RULE =
  "namePrefix must be an instance-name prefix (1-63 chars: lowercase letter first, then lowercase letters, digits, hyphens; a trailing hyphen is allowed)";

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
    (typeof startupScript !== "string" || startupScript.length === 0 || new TextEncoder().encode(startupScript).length > GCP_STARTUP_SCRIPT_MAX_LENGTH)
  ) {
    return {
      ok: false,
      reason: `startupScript, when present, must be a non-empty string of at most ${GCP_STARTUP_SCRIPT_MAX_LENGTH} bytes`,
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

  const params: GcpFirewallCreateParams = {
    project,
    networkName,
    ruleName,
    allowed: cleanAllowed,
    sourceRanges: cleanSourceRanges,
    targetTags: cleanTargetTags,
  };
  // hub#93: the cell's ONE sessions rule is pinned to its exact shape (sessionsFirewallRuleShapeReason,
  // in the planning/49 section below). Every other rule name is unaffected.
  const sessionsRuleReason = sessionsFirewallRuleShapeReason(params);
  if (sessionsRuleReason !== null) {
    return { ok: false, reason: sessionsRuleReason };
  }
  return { ok: true, params };
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

// ── gcp-router-nat-create ────────────────────────────────────────────────────────────
// Create ONE regional Cloud Router carrying ONE inline Cloud NAT on a cell's VPC in the AGENCY's own
// project (planning/34 phase 3). WHY: every cell VM except the gateway has NO external IP, so without
// a NAT the private web/file/data nodes have no egress at all — no apt, no cell-agent bundle fetch,
// no cloudflared. The NAT uses Google-managed IPs (AUTO_ONLY), so no address reservation is needed,
// and covers every subnet of the network (ALL_SUBNETWORKS_ALL_IP_RANGES) — the cell has exactly one.
// Five REQUIRED strings, each pinned to a strict grammar:
//   1. `project`     — the project id (pinned to the SA key's own project by the actuator).
//   2. `region`      — a Compute region (a URL path segment; a router is regional).
//   3. `networkName` — the VPC the router attaches to (becomes "global/networks/<name>").
//   4. `routerName`  — the router's resource name.
//   5. `natName`     — the NAT config's name inside the router.
//
// IDEMPOTENT: the insert treats Google's 409 alreadyExists as success (a re-run resumes). Registered
// `true` in AGENCY_OP_IDEMPOTENT. Idempotence is by ROUTER NAME — a re-run against a same-named router
// created elsewhere with a different (or no) NAT is a no-op, not an update.

export interface GcpRouterNatCreateParams {
  /** The agency's GCP project id the router is created in. */
  project: string;
  /** The Compute Engine region of the router, e.g. "australia-southeast1". */
  region: string;
  /** The VPC network the router attaches to. */
  networkName: string;
  /** The Cloud Router's resource name. */
  routerName: string;
  /** The inline Cloud NAT config's name. */
  natName: string;
}

export function validateGcpRouterNatCreateParams(raw: unknown): ParamsVerdict<GcpRouterNatCreateParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, networkName, routerName, natName } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast1)" };
  }
  if (typeof networkName !== "string" || !GCP_RESOURCE_NAME_RE.test(networkName)) {
    return { ok: false, reason: `networkName ${GCP_RESOURCE_NAME_RULE}` };
  }
  if (typeof routerName !== "string" || !GCP_RESOURCE_NAME_RE.test(routerName)) {
    return { ok: false, reason: `routerName ${GCP_RESOURCE_NAME_RULE}` };
  }
  if (typeof natName !== "string" || !GCP_RESOURCE_NAME_RE.test(natName)) {
    return { ok: false, reason: `natName ${GCP_RESOURCE_NAME_RULE}` };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, networkName, routerName, natName } };
}

// ── gcp-firewall-get ───────────────────────────────────────────────────────────────
// READ-ONLY: confirm ONE cell firewall rule EXISTS in the AGENCY's own project (planning/34 resume
// verification — review finding 1). On a re-run an already-existed rule was trusted by NAME; this op
// GETs it so the caller can turn "trusted by name" into a real confirmation, or warn clearly if the
// rule is gone. Firewalls are GLOBAL resources, so there is NO region. Two REQUIRED strings, each
// pinned to a strict grammar: `project` (pinned to the SA key's own project) and `ruleName` (a
// resource name). Low blast radius (a read), but validated with the SAME rigor as the create ops —
// it still extends the signed-dispatch surface.
//
// IDEMPOTENT: a read has no side effect, so a re-run converges trivially. Registered `true` in
// AGENCY_OP_IDEMPOTENT.

export interface GcpFirewallGetParams {
  /** The agency's GCP project id the rule lives in. */
  project: string;
  /** The firewall rule's resource name to read back. */
  ruleName: string;
}

export function validateGcpFirewallGetParams(raw: unknown): ParamsVerdict<GcpFirewallGetParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, ruleName } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof ruleName !== "string" || !GCP_RESOURCE_NAME_RE.test(ruleName)) {
    return { ok: false, reason: `ruleName ${GCP_RESOURCE_NAME_RULE}` };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, ruleName } };
}

// ── gcp-router-get ─────────────────────────────────────────────────────────────────
// READ-ONLY: confirm ONE cell Cloud Router EXISTS and carries its NAT in the AGENCY's own project
// (planning/34 resume verification). On a re-run an already-existed router was trusted by NAME, but a
// same-named router WITHOUT the cell NAT would leave the private VMs with no egress — so this op GETs
// the router and (in the actuator) reports its inline NAT config names. Routers are REGIONAL. Three
// REQUIRED strings, each pinned to a strict grammar: `project` (pinned to the SA key's own project),
// `region` (a URL path segment) and `routerName` (a resource name).
//
// IDEMPOTENT: a read has no side effect. Registered `true` in AGENCY_OP_IDEMPOTENT.

export interface GcpRouterGetParams {
  /** The agency's GCP project id the router lives in. */
  project: string;
  /** The Compute Engine region of the router, e.g. "australia-southeast1". */
  region: string;
  /** The Cloud Router's resource name to read back. */
  routerName: string;
}

export function validateGcpRouterGetParams(raw: unknown): ParamsVerdict<GcpRouterGetParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, routerName } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast1)" };
  }
  if (typeof routerName !== "string" || !GCP_RESOURCE_NAME_RE.test(routerName)) {
    return { ok: false, reason: `routerName ${GCP_RESOURCE_NAME_RULE}` };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, routerName } };
}

// ── gcp-instances-list ───────────────────────────────────────────────────────────
// READ-ONLY: list the agency's Compute Engine instances whose name starts with `namePrefix`, so a
// caller resuming a half-built cell can DISCOVER which of the cell's VMs already exist and in which
// ZONE (planning/34 zone fallback — a cell lives in ONE zone, and there is no registry, so resume-
// safety comes from discovery, not storage). Two REQUIRED strings: `project` (pinned to the SA key's
// own project) and `namePrefix` (the server-side `name` filter, so the response is bounded). The
// caller narrows the returned list to the cell's EXACT node names, so an over-broad prefix is safe.
//
// IDEMPOTENT: a read has no side effect. Registered `true` in AGENCY_OP_IDEMPOTENT.

export interface GcpInstancesListParams {
  /** The agency's GCP project id to list instances in. */
  project: string;
  /** The instance-name prefix the server-side aggregatedList filter narrows to (e.g. "dy-"). */
  namePrefix: string;
}

export function validateGcpInstancesListParams(raw: unknown): ParamsVerdict<GcpInstancesListParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, namePrefix } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof namePrefix !== "string" || !GCP_NAME_PREFIX_RE.test(namePrefix)) {
    return { ok: false, reason: GCP_NAME_PREFIX_RULE };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, namePrefix } };
}

// ── GCP teardown ops (the five deletes) ──────────────────────────────────────────────
// The reverse of the cell-infra create ops above: everything a cell teardown removes (planning/34
// teardown). Each delete reuses the SAME grammar as its create twin, because every value is still a
// URL path segment of a Compute Engine call — the grammar IS the injection guard, and a name these
// ops could never have created can never be named for deletion either.
//
// ALL FIVE ARE IDEMPOTENT: Google answers a delete of a resource that is not there with 404
// notFound, which the actuators report as success ("already-absent"). That is what lets a re-run of
// a partly-torn-down cell RESUME rather than fail on what it already removed.
//
// A caller cannot ask these ops to delete an arbitrary resource by accident of naming alone: the
// platform derives every name from the cell's fixed naming scheme before it signs the job. These
// validators are the second guard — shape + grammar — not the first.

// ── gcp-instance-delete ──────────────────────────────────────────────────────────────
// Delete ONE Compute Engine VM in the AGENCY's own project (planning/34 teardown). This is the FIRST
// teardown step: while a VM is alive its subnet, its reserved IP and its network are all in use, so
// every later delete would fail with Google's resourceInUse. Three REQUIRED strings:
//   1. `project` — the project id (the actuator pins it to the SA key's own project).
//   2. `zone`    — the Compute zone the VM lives in, e.g. australia-southeast1-a (a URL path segment).
//   3. `name`    — the instance's resource name.
// The file node's DATA DISK is deliberately NOT removed with the VM: gcp-instance-create attaches it
// with autoDelete:false because it holds the sites' files, so it survives as an orphaned disk for an
// operator to deal with. Only the boot disk goes with the VM.
//
// IDEMPOTENT: a 404 notFound is reported as "already-absent", so a re-run resumes.

export interface GcpInstanceDeleteParams {
  /** The agency's GCP project id the VM lives in. */
  project: string;
  /** The Compute Engine zone of the VM, e.g. "australia-southeast1-a". */
  zone: string;
  /** The instance's resource name. */
  name: string;
}

export function validateGcpInstanceDeleteParams(raw: unknown): ParamsVerdict<GcpInstanceDeleteParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, zone, name } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof zone !== "string" || zone.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a Compute Engine zone name (e.g. australia-southeast1-a)" };
  }
  if (typeof name !== "string" || !GCP_RESOURCE_NAME_RE.test(name)) {
    return { ok: false, reason: `name ${GCP_RESOURCE_NAME_RULE}` };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, zone, name } };
}

// ── gcp-address-delete ───────────────────────────────────────────────────────────────
// Release the cell gateway's reserved regional static external IP in the AGENCY's own project
// (planning/34 teardown). Runs AFTER the VMs: a reservation attached to a live VM is in use and
// Google refuses to release it. Three REQUIRED strings, the same three gcp-address-create takes:
// `project` (pinned to the SA key's own project by the actuator), `region` (a URL path segment) and
// `addressName` (a resource name).
//
// IDEMPOTENT: a 404 notFound is reported as "already-absent".

export interface GcpAddressDeleteParams {
  /** The agency's GCP project id the reservation lives in. */
  project: string;
  /** The Compute Engine region of the reservation, e.g. "australia-southeast1". */
  region: string;
  /** The reserved address's resource name. */
  addressName: string;
}

export function validateGcpAddressDeleteParams(raw: unknown): ParamsVerdict<GcpAddressDeleteParams> {
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

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, addressName } };
}

// ── gcp-firewall-delete ──────────────────────────────────────────────────────────────
// Delete ONE firewall rule from a cell's VPC in the AGENCY's own project (planning/34 teardown — a
// network delete fails while any rule still attaches to it). Firewalls are GLOBAL resources, so
// there is NO region: two REQUIRED strings, `project` (pinned to the SA key's own project by the
// actuator) and `ruleName` (a resource name) — the same pair gcp-firewall-get takes.
//
// IDEMPOTENT: a 404 notFound is reported as "already-absent".

export interface GcpFirewallDeleteParams {
  /** The agency's GCP project id the rule lives in. */
  project: string;
  /** The firewall rule's resource name. */
  ruleName: string;
}

export function validateGcpFirewallDeleteParams(raw: unknown): ParamsVerdict<GcpFirewallDeleteParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, ruleName } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof ruleName !== "string" || !GCP_RESOURCE_NAME_RE.test(ruleName)) {
    return { ok: false, reason: `ruleName ${GCP_RESOURCE_NAME_RULE}` };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, ruleName } };
}

// ── gcp-router-delete ────────────────────────────────────────────────────────────────
// Delete the cell's regional Cloud Router in the AGENCY's own project (planning/34 teardown). The
// inline Cloud NAT goes WITH it: the NAT is a FIELD of the router, not a resource of its own, so
// there is deliberately no separate NAT delete op — the mirror of gcp-router-nat-create, which
// creates both in one insert. Three REQUIRED strings: `project` (pinned to the SA key's own project
// by the actuator), `region` (a URL path segment — a router is regional) and `routerName`.
//
// IDEMPOTENT: a 404 notFound is reported as "already-absent".

export interface GcpRouterDeleteParams {
  /** The agency's GCP project id the router lives in. */
  project: string;
  /** The Compute Engine region of the router, e.g. "australia-southeast1". */
  region: string;
  /** The Cloud Router's resource name (its inline NAT is deleted with it). */
  routerName: string;
}

export function validateGcpRouterDeleteParams(raw: unknown): ParamsVerdict<GcpRouterDeleteParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, routerName } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast1)" };
  }
  if (typeof routerName !== "string" || !GCP_RESOURCE_NAME_RE.test(routerName)) {
    return { ok: false, reason: `routerName ${GCP_RESOURCE_NAME_RULE}` };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, routerName } };
}

// ── gcp-network-delete ───────────────────────────────────────────────────────────────
// Delete a cell's dedicated VPC in the AGENCY's own project: its ONE regional subnet FIRST, then the
// network itself (planning/34 teardown). ONE op for both, because the order is not optional — a
// networks.delete while the subnet still exists is Google's resourceInUse. The exact mirror of
// gcp-network-create, which creates the network then the subnet. Four REQUIRED strings:
//   1. `project`     — the project id (pinned to the SA key's own project by the actuator).
//   2. `region`      — the subnet's Compute region (a URL path segment; the network is global).
//   3. `networkName` — the VPC's resource name.
//   4. `subnetName`  — the subnet's resource name.
//
// IDEMPOTENT: a 404 notFound on EITHER delete is reported as that resource's "already-absent", so a
// re-run that already removed the subnet still goes on to remove the network.

export interface GcpNetworkDeleteParams {
  /** The agency's GCP project id the VPC lives in. */
  project: string;
  /** The Compute Engine region of the subnet, e.g. "australia-southeast1". */
  region: string;
  /** The custom-mode VPC network's name. */
  networkName: string;
  /** The regional subnetwork's name — deleted BEFORE the network. */
  subnetName: string;
}

export function validateGcpNetworkDeleteParams(raw: unknown): ParamsVerdict<GcpNetworkDeleteParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, networkName, subnetName } = raw;

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

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, networkName, subnetName } };
}

// ── GCP in-place UPDATE ops: gcp-instance-set-metadata / gcp-instance-restart ────────
// planning/47: a provisioned agency cell could not be CHANGED after creation — no op reached a
// node's startup script, and the cell-agent's /exec cannot write a root-owned credential file. These
// two ops close that gap: `gcp-instance-set-metadata` merges keys into a VM's metadata (the
// `startup-script` Google runs AS ROOT on every boot is one such key), and `gcp-instance-restart`
// reboots the VM gracefully so the new script runs. Together they are "update a cell node"; the
// first consumer arms the file node's backup timers (hub#52).
//
// TWO boundaries bound the set-metadata op:
//   1. WHICH KEYS may be set — the fixed GCP_METADATA_KEYS allowlist below (exactly `startup-script`
//      today), enforced HERE in the validator, so a disallowed key is a 400 with no token minted and
//      no GCP call made, and a request mixing an allowed key with a disallowed one is refused WHOLE
//      (nothing partially applied). Read the allowlist's own comment for why it exists and what it
//      does — and does not — constrain.
//   2. WHAT is substituted into a value — the Worker-side PLACEHOLDER substitution in actuate.ts (a
//      fixed allowlist of `@@DY_T2_S3_*@@` names mapped to the agency's own S3_* secrets; any other
//      `@@...@@` is refused). That runs in the actuator because only the actuator holds `env`.

// ── gcp-instance-set-metadata ────────────────────────────────────────────────────────
// MERGE keys into ONE VM's metadata in the AGENCY's own project. Four REQUIRED params:
//   1. `project` — the project id (pinned to the SA key's own project by the actuator).
//   2. `zone`    — the Compute zone the VM lives in (a URL path segment).
//   3. `name`    — the instance's resource name (a URL path segment).
//   4. `items`   — 1-32 { key, value } entries to set. `key` must pass Google's metadata-key grammar
//                  ([a-zA-Z0-9_-], 1-128 chars) AND be on the fixed GCP_METADATA_KEYS allowlist
//                  (exactly `startup-script` today — see its comment), and must be unique within the
//                  request (two values for one key would be ambiguous). `value` is the ONE opaque
//                  field — a shell script legitimately contains any character — so it is
//                  length-capped at Google's 256 KB per-value limit and must be non-empty (an empty
//                  startup script is always a caller bug, never a desired state). It reaches Google
//                  only as a JSON.stringify'd body field, never a URL segment.
// ONE OPTIONAL param (planning/47): `expectedFingerprint`, the fingerprint the caller read. The
// actuator refuses the write when the instance's fingerprint is no longer that value (see the pinned
// twin block "the caller's expected metadata fingerprint").
// Keys NOT named in `items` are PRESERVED: the actuator reads the instance, merges, and writes back
// with the instance's current metadata FINGERPRINT, which Google rejects when stale (HTTP 412) — the
// concurrency guard against clobbering a change made between the read and the write.
//
// IDEMPOTENT: setting a key to a value converges — a re-run re-reads the fingerprint and writes the
// same values. Registered `true` in AGENCY_OP_IDEMPOTENT.

/**
 * The FIXED allowlist of instance-metadata KEYS this op may set. Exactly `startup-script` for now.
 *
 * WHY an allowlist at all: without one, this op is a general-purpose remote-configuration channel on
 * the agency's VM. `ssh-keys` grants a persistent interactive login; `enable-oslogin`,
 * `serial-port-enable` and their relatives each open an access path of their own. Those are
 * categorically different from "update the boot script the platform already authors": the boot-script
 * capability is one the provisioning model already has and already documents (gcp-instance-create's
 * `startupScript`), whereas silently acquiring SSH into an agency's VM would be a NEW capability — and
 * acquiring new capabilities unannounced is precisely what the Direction-B boundary exists to prevent.
 * The allowlist also bounds a plain bug: a mis-targeted call with the wrong `items` cannot clobber
 * unrelated VM configuration.
 *
 * WHAT it does NOT do: it does NOT reduce the op's ultimate capability. A startup script runs as root
 * on every boot, so a caller who can set it can do anything on the node — including adding an SSH key
 * from inside the script. The allowlist is here to keep the op's STATED purpose and its ACTUAL
 * capability aligned, so that widening it (say, to `shutdown-script` or `ssh-keys`) is a deliberate,
 * reviewed decision rather than an accident of "any key passes the grammar". Do not read it as the op
 * being more constrained than root-on-the-node; read it as the op doing only what it says it does.
 *
 * Twin of the orchestrator's GCP_METADATA_KEYS (agency-dispatch.ts); the app's validator should carry
 * the same list. Extend all three together.
 */
export const GCP_METADATA_KEYS = ["startup-script"] as const;
export type GcpMetadataKey = (typeof GCP_METADATA_KEYS)[number];

export interface GcpInstanceMetadataItem {
  /** The metadata key — one of GCP_METADATA_KEYS (exactly "startup-script" today). */
  key: GcpMetadataKey;
  /** The value — opaque, non-empty, at most 256 KB. May carry `@@DY_T2_S3_*@@` placeholders. */
  value: string;
}

/** True when `key` is on the fixed GCP_METADATA_KEYS allowlist (narrows the type). */
function isAllowlistedMetadataKey(key: string): key is GcpMetadataKey {
  return (GCP_METADATA_KEYS as readonly string[]).includes(key);
}

export interface GcpInstanceSetMetadataParams {
  /** The agency's GCP project id the VM lives in. */
  project: string;
  /** The Compute Engine zone of the VM, e.g. "australia-southeast1-a". */
  zone: string;
  /** The instance's resource name. */
  name: string;
  /** The entries to set (merged into the instance's existing metadata; other keys survive). */
  items: GcpInstanceMetadataItem[];
  /**
   * planning/47: the metadata fingerprint the CALLER read before it decided what to write (see the
   * pinned twin block "the caller's expected metadata fingerprint"). Absent = the op's own
   * read-then-write guard only.
   */
  expectedFingerprint?: string;
}

// Google's metadata KEY grammar: letters, digits, hyphen, underscore; 1-128 chars. Anchored, so a key
// can carry no whitespace, "/" or other JSON/URL metacharacter.
const GCP_METADATA_KEY_RE = /^[a-zA-Z0-9_-]{1,128}$/;
const GCP_METADATA_KEY_RULE =
  "each items entry's key must be a Compute Engine metadata key (1-128 chars of letters, digits, hyphens, underscores)";
// Google caps ONE metadata value at 256 KB — the same cap gcp-instance-create's startupScript uses.
const GCP_METADATA_VALUE_MAX_LENGTH = GCP_STARTUP_SCRIPT_MAX_LENGTH;
// A cell-node update sets a handful of keys; 32 is generous and stops a junk mega-list.
const GCP_METADATA_ITEMS_MAX = 32;

export function validateGcpInstanceSetMetadataParams(raw: unknown): ParamsVerdict<GcpInstanceSetMetadataParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, zone, name, items } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof zone !== "string" || zone.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a Compute Engine zone name (e.g. australia-southeast1-a)" };
  }
  if (typeof name !== "string" || !GCP_RESOURCE_NAME_RE.test(name)) {
    return { ok: false, reason: `name ${GCP_RESOURCE_NAME_RULE}` };
  }
  if (!Array.isArray(items) || items.length < 1 || items.length > GCP_METADATA_ITEMS_MAX) {
    return { ok: false, reason: `items must be an array of 1-${GCP_METADATA_ITEMS_MAX} { key, value } entries` };
  }

  // Build a FRESH array of fresh { key, value } objects — never the caller's objects — so an extra
  // property on an entry can never ride along into the metadata body the actuator writes. The WHOLE
  // request is refused on the first bad entry (no partial list is ever returned, so nothing is ever
  // partially applied). A key named twice is refused: the merge would have to pick one, and guessing
  // is how a wrong boot script lands on a node.
  const cleanItems: GcpInstanceMetadataItem[] = [];
  const seenKeys = new Set<string>();
  for (const entry of items) {
    if (!isPlainObject(entry)) {
      return { ok: false, reason: "each items entry must be an object { key, value }" };
    }
    const { key, value } = entry;
    // Grammar FIRST (bounds what the allowlist reason below may echo to 128 safe chars), then the
    // allowlist — the reason NAMES the offending key so a mis-targeted call is diagnosable.
    if (typeof key !== "string" || !GCP_METADATA_KEY_RE.test(key)) {
      return { ok: false, reason: GCP_METADATA_KEY_RULE };
    }
    if (!isAllowlistedMetadataKey(key)) {
      return {
        ok: false,
        reason: `each items entry's key must be one of the allowlisted metadata keys (${GCP_METADATA_KEYS.join(", ")}); got "${key}"`,
      };
    }
    if (seenKeys.has(key)) {
      return { ok: false, reason: `items names the metadata key "${key}" more than once` };
    }
    if (typeof value !== "string" || value.length === 0 || new TextEncoder().encode(value).length > GCP_METADATA_VALUE_MAX_LENGTH) {
      return {
        ok: false,
        reason: `each items entry's value must be a non-empty string of at most ${GCP_METADATA_VALUE_MAX_LENGTH} bytes`,
      };
    }
    seenKeys.add(key);
    cleanItems.push({ key, value });
  }

  const fingerprint = expectedFingerprintVerdict(raw.expectedFingerprint);
  if (!fingerprint.ok) {
    return { ok: false, reason: fingerprint.reason };
  }

  // A FRESH object of only the known keys — never the caller's object. `expectedFingerprint` is
  // present only when the caller sent one, so a request without it signs and actuates as before.
  const params: GcpInstanceSetMetadataParams = { project, zone, name, items: cleanItems };
  if (fingerprint.expectedFingerprint !== undefined) {
    params.expectedFingerprint = fingerprint.expectedFingerprint;
  }
  return { ok: true, params };
}

// ── gcp-instance-restart ─────────────────────────────────────────────────────────────
// GRACEFULLY restart ONE VM in the AGENCY's own project: instances.stop (an ACPI shutdown the guest
// OS honours — nfs-server stops, filesystems unmount), then instances.start. Deliberately NOT
// instances.reset, which is a hard power cycle: the first node this restarts is the cell's NFS file
// node, which deserves a clean shutdown. Three REQUIRED strings, the same three gcp-instance-delete
// takes: `project` (pinned to the SA key's own project by the actuator), `zone` and `name` (both URL
// path segments).
//
// NON-IDEMPOTENT: every run reboots the VM again, and for the file node every reboot interrupts every
// site on the cell for about a minute while the web node's NFS mounts recover. A re-dispatch after a
// lost response could therefore reboot a node that had already come back — so the orchestrator
// registers it `false` in AGENCY_OP_IDEMPOTENT and runs it exactly once (like gcp-instance-create),
// leaving "did it come back?" to the caller's own health probe.

export interface GcpInstanceRestartParams {
  /** The agency's GCP project id the VM lives in. */
  project: string;
  /** The Compute Engine zone of the VM, e.g. "australia-southeast1-a". */
  zone: string;
  /** The instance's resource name. */
  name: string;
}

export function validateGcpInstanceRestartParams(raw: unknown): ParamsVerdict<GcpInstanceRestartParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, zone, name } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof zone !== "string" || zone.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a Compute Engine zone name (e.g. australia-southeast1-a)" };
  }
  if (typeof name !== "string" || !GCP_RESOURCE_NAME_RE.test(name)) {
    return { ok: false, reason: `name ${GCP_RESOURCE_NAME_RULE}` };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, zone, name } };
}

// ── provision-ssh-keys ───────────────────────────────────────────────────────────────
// Declare the FULL set of authorized SSH public keys for a cell site's shell login on the
// gateway (planning/39 — cell SSH access, increment 1). This is the per-ACCOUNT key spine:
// the app fans an account's keys out to every one of its cell-hosted sites, and the actuator
// RELAYS the whole set to the gateway cell-agent's /provision-ssh-keys, which writes one
// authorized_keys file for the site login. The op DECLARES the whole desired set (not
// add/remove deltas), which is what makes it idempotent + resume-safe (planning/39): a re-run
// converges on the same file.
//
// SAFE + ADDITIVE (planning/39 increment 1): this only writes a public-key FILE on the gateway;
// it changes no sshd_config and does nothing until a LATER shell Match block references the file.
//
// Three params, each strictly grammared:
//   1. `project` — the agency's GCP project id (the existing GCP project grammar). It selects the
//      agency's cell at the platform layer; the gateway cell-agent itself only needs slug + keys.
//   2. `slug`    — the site slug (the existing storage-tier slug grammar, <=27 so `site_<slug>`
//      fits the 32-char Linux login cap — the SFTP precedent). Selects the site's login.
//   3. `authorizedKeys` — the FULL desired set of authorized public keys (0..MAX). Each entry is
//      re-checked against the strict single-line OpenSSH public-key grammar (type + base64 blob +
//      optional comment) — the SAME grammar the SFTP file-node script enforces. An EMPTY set is
//      legitimate: it revokes every key (the gateway writes an empty file). Charset + a per-key
//      length cap + a bounded array length are the guard; the gateway script re-validates every
//      line (defence in depth), so a malformed key can never reach an authorized_keys file.

export interface ProvisionSshKeysParams {
  /** The agency's GCP project id — selects the agency's cell at the platform layer. */
  project: string;
  /** The site slug — selects the site's gateway login. */
  slug: string;
  /** The FULL desired set of authorized OpenSSH public keys (0..MAX). */
  authorizedKeys: string[];
}

// The agency's GCP project id (6-30 chars: lowercase-letter start, [a-z0-9-], alphanumeric end) —
// the SAME grammar the gcp-* ops use. Redeclared here (not shared) so this op's twin section stays
// byte-identical across the two repos without depending on where the gcp constant is defined.
const SSH_KEYS_PROJECT_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
// The storage-tier slug: [a-z0-9-], 1..27 chars, so the derived login `site_<slug>` fits Linux's
// 32-char cap (the SFTP precedent: site-provision-sftp-user.sh). Anchored, no metacharacter.
const SSH_KEYS_SLUG_RE = /^[a-z0-9-]{1,27}$/;
// A well-formed single-line OpenSSH public key: a known key-type token, then the base64 blob, then
// an OPTIONAL comment of printable ASCII. Byte-for-byte the grammar the SFTP file-node script
// enforces (site-provision-sftp-user.sh) — accepts ed25519 / rsa / the three ecdsa curves / the two
// FIDO sk- types; rejects a PEM private key (no key-type token), any control char, and (being
// anchored, with [ -~] excluding newline) a multi-line value.
const SSH_PUBLIC_KEY_LINE_RE =
  /^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]{20,}={0,3}(?: [ -~]*)?$/;
// A generous per-key ceiling — an ed25519 line is ~90 chars, a 4096-bit rsa line ~740; 8192 leaves
// room for a long comment and still rejects a junk mega-string.
const SSH_PUBLIC_KEY_MAX_LENGTH = 8192;
// The desired set can be empty (revoke all) up to this ceiling — an account's admins hold a handful
// of keys, so 50 is generous and stops a junk mega-list.
const SSH_KEYS_MAX = 50;

export function validateProvisionSshKeysParams(raw: unknown): ParamsVerdict<ProvisionSshKeysParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, slug, authorizedKeys } = raw;

  if (typeof project !== "string" || !SSH_KEYS_PROJECT_RE.test(project)) {
    return {
      ok: false,
      reason:
        "project must be a GCP project id (6-30 chars: lowercase letter first, then lowercase letters, digits, hyphens; alphanumeric last)",
    };
  }
  if (typeof slug !== "string" || !SSH_KEYS_SLUG_RE.test(slug)) {
    return { ok: false, reason: "slug must be a storage-tier slug ([a-z0-9-], 1-27 chars)" };
  }
  // The desired set: an array of 0..MAX keys. Empty is legitimate (revoke every key).
  if (!Array.isArray(authorizedKeys) || authorizedKeys.length > SSH_KEYS_MAX) {
    return { ok: false, reason: `authorizedKeys must be an array of 0-${SSH_KEYS_MAX} OpenSSH public keys` };
  }
  // Build a FRESH array of only the validated key lines — never the caller's array — so an extra
  // element property can't ride along into the signed params. Every entry must be a single-line
  // OpenSSH public key within the length cap; a private key, a multi-line value, or garbage is
  // rejected here (and re-rejected by the gateway script).
  const cleanKeys: string[] = [];
  for (const entry of authorizedKeys) {
    if (
      typeof entry !== "string" ||
      entry.length === 0 ||
      entry.length > SSH_PUBLIC_KEY_MAX_LENGTH ||
      !SSH_PUBLIC_KEY_LINE_RE.test(entry)
    ) {
      return {
        ok: false,
        reason: `each authorizedKeys entry must be a single-line OpenSSH public key (max ${SSH_PUBLIC_KEY_MAX_LENGTH} chars)`,
      };
    }
    cleanKeys.push(entry);
  }

  return { ok: true, params: { project, slug, authorizedKeys: cleanKeys } };
}

// ── hub#43: agency-owned media — r2-media-buckets, r2-media-state, r2-site-key-install, r2-site-key-revoke ──
// hub#43 moves an agency's sites off the PLATFORM's R2 account and onto the agency's own. The platform
// must never hold a write key to the agency's account, so the per-site write key is minted by THIS Worker
// with the agency's own R2_PROVISION_API_TOKEN and sent straight to the agency's own FILE-NODE cell-agent,
// which writes it into the site's locked wp-config. The platform sees names, ids and hosts, never a key.
//
// THE FILE-NODE AGENT IN THE JOB. The install job names that agent: `fileAgentUrl` and `fileAgentToken`. The
// platform derives the token, so no agency can set it as a Worker secret. The two keys come together or not
// at all. A job from an older platform carries neither, and the Worker then uses its own CELL_FILE_AGENT_*
// secrets. app signs the pair only when the host is a file-agent host of the site's own cell
// (agency-dispatch-site-binding.ts), so a key is never posted to a host outside that cell.
//
// THIS BLOCK IS A PINNED TWIN. The app and the agency Worker carry it byte for byte, and each repo's test
// suite pins the sha256 of the block (from this marker up to the next section marker, the hub#58 block).
// A change on one side only fails that side's suite. Change both twins and both pins together.
//
// Four ops, all narrow on purpose:
//   r2-media-buckets      READ the NAMES of the buckets in the agency's R2 account (names only, no objects, no keys).
//   r2-media-state        READ one media bucket (does it exist?) and the keys this op family minted for it.
//   r2-site-key-install   MINT one bucket-scoped read-write key and STAGE it on the file node. NOT idempotent:
//                         every run mints a NEW key. It runs once under F1, and a lost answer is settled by
//                         r2-media-state (which lists the keys) and r2-site-key-revoke, never by a resend.
//   r2-site-key-revoke    DELETE one key, only if its name proves this op family made it for that bucket.
//
// Every bucket these ops touch is named `doubleyoup-media-<prefix>`, the shape the media Worker derives from
// the site's key prefix. They cannot name an agency's backup bucket, a database dump bucket or any other.

/** r2-media-buckets takes no parameters: it lists the bucket names of the account the Worker's token belongs to. */
export type R2MediaBucketsParams = Record<string, never>;

export interface R2MediaStateParams {
  /** The media bucket, `doubleyoup-media-<prefix>`. */
  bucket: string;
}

export interface R2SiteKeyInstallParams {
  /** The media bucket, `doubleyoup-media-<prefix>`. It must already exist (provision-r2 creates it). */
  bucket: string;
  /** The site slug: the file-node cell-agent derives the site's config path from it. */
  slug: string;
  /** The site's R2 key prefix (DOUBLEYOUP_R2_PREFIX). The bucket name must be `doubleyoup-media-<prefix>`. */
  prefix: string;
  /** The public host that serves the bucket (the agency's media Worker host), e.g. media.<agency zone>. */
  mediaHost: string;
  /** A short unique tag for this key (lowercase letters and digits). It becomes part of the key's name. */
  label: string;
  /**
   * The site's FILE-NODE cell-agent, exactly `https://<lowercase host>`: no path, port, query or user part.
   * Sent together with `fileAgentToken`, or neither is sent (a job from an older platform).
   */
  fileAgentUrl?: string;
  /** The bearer token of that agent: 64 lowercase hex characters. A secret: no answer or reason repeats it. */
  fileAgentToken?: string;
}

export interface R2SiteKeyRevokeParams {
  /** The media bucket the key was minted for. */
  bucket: string;
  /** The Cloudflare API token id (the S3 access key id). 32 lowercase hex characters. */
  tokenId: string;
}

const R2_MEDIA_BUCKET_PREFIX = "doubleyoup-media-";
const R2_MEDIA_PREFIX_RE = /^[a-z0-9][a-z0-9-]{0,45}$/;
const R2_MEDIA_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,45}$/;
const R2_MEDIA_LABEL_RE = /^[a-z0-9]{1,16}$/;
const R2_TOKEN_ID_RE = /^[a-f0-9]{32}$/;
const R2_MEDIA_HOST_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const R2_FILE_AGENT_URL_SCHEME = "https://";
const R2_FILE_AGENT_TOKEN_RE = /^[a-f0-9]{64}$/;

/**
 * True for exactly `https://<lowercase DNS host>`. The host grammar has no "/", ":", "?", "#" or "@", so a path, a
 * port, a query, a fragment and a user part are all refused, and so is a trailing slash.
 */
export function isR2FileAgentUrl(value: unknown): value is string {
  if (typeof value !== "string" || !value.startsWith(R2_FILE_AGENT_URL_SCHEME)) {
    return false;
  }
  const host = value.slice(R2_FILE_AGENT_URL_SCHEME.length);
  return host.length <= 253 && R2_MEDIA_HOST_RE.test(host);
}

/** True for `doubleyoup-media-<prefix>` with a valid prefix (R2's 63-character cap is met by the 46-character prefix). */
export function isR2MediaBucketName(name: unknown): name is string {
  if (typeof name !== "string" || !name.startsWith(R2_MEDIA_BUCKET_PREFIX)) {
    return false;
  }
  return R2_MEDIA_PREFIX_RE.test(name.slice(R2_MEDIA_BUCKET_PREFIX.length));
}

/** The name every key of this op family carries: `dy-media-<bucket>-<label>`. The revoke op trusts only this shape. */
export function r2SiteKeyNameFor(bucket: string, label: string): string {
  return `dy-media-${bucket}-${label}`;
}

const R2_MEDIA_BUCKET_RULE =
  "bucket must be doubleyoup-media-<prefix> (prefix: 1-46 characters, lowercase letters, digits and hyphens, starting with a letter or digit)";

export function validateR2MediaBucketsParams(raw: unknown): ParamsVerdict<R2MediaBucketsParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  if (Object.keys(raw).length !== 0) {
    return { ok: false, reason: "r2-media-buckets takes no parameters" };
  }
  return { ok: true, params: {} };
}

export function validateR2MediaStateParams(raw: unknown): ParamsVerdict<R2MediaStateParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  if (!isR2MediaBucketName(raw.bucket)) {
    return { ok: false, reason: R2_MEDIA_BUCKET_RULE };
  }
  return { ok: true, params: { bucket: raw.bucket } };
}

export function validateR2SiteKeyInstallParams(raw: unknown): ParamsVerdict<R2SiteKeyInstallParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { bucket, slug, prefix, mediaHost, label, fileAgentUrl, fileAgentToken } = raw;
  if (!isR2MediaBucketName(bucket)) {
    return { ok: false, reason: R2_MEDIA_BUCKET_RULE };
  }
  if (typeof slug !== "string" || !R2_MEDIA_SLUG_RE.test(slug)) {
    return { ok: false, reason: "slug must be 1-46 lowercase letters, digits and hyphens, starting with a letter or digit" };
  }
  if (typeof prefix !== "string" || !R2_MEDIA_PREFIX_RE.test(prefix)) {
    return { ok: false, reason: "prefix must be 1-46 lowercase letters, digits and hyphens, starting with a letter or digit" };
  }
  if (bucket !== `${R2_MEDIA_BUCKET_PREFIX}${prefix}`) {
    return { ok: false, reason: "bucket must be exactly doubleyoup-media-<prefix> for this prefix" };
  }
  if (typeof mediaHost !== "string" || mediaHost.length > 253 || !R2_MEDIA_HOST_RE.test(mediaHost)) {
    return { ok: false, reason: "mediaHost must be a lowercase DNS host name" };
  }
  if (typeof label !== "string" || !R2_MEDIA_LABEL_RE.test(label)) {
    return { ok: false, reason: "label must be 1-16 lowercase letters and digits" };
  }
  // A job from an older platform names no file-node agent. It stays valid, and the Worker uses its own secrets.
  if (fileAgentUrl === undefined && fileAgentToken === undefined) {
    return { ok: true, params: { bucket, slug, prefix, mediaHost, label } };
  }
  // One key without the other is refused: half a pair is a bug, and a URL must never meet another source's token.
  // The reasons name the rule only, never the value (the token is a secret).
  if (!isR2FileAgentUrl(fileAgentUrl)) {
    return { ok: false, reason: "fileAgentUrl must be exactly https://<lowercase DNS host> (no path, port, query or user part), sent together with fileAgentToken" };
  }
  if (typeof fileAgentToken !== "string" || !R2_FILE_AGENT_TOKEN_RE.test(fileAgentToken)) {
    return { ok: false, reason: "fileAgentToken must be 64 lowercase hex characters, sent together with fileAgentUrl" };
  }
  return { ok: true, params: { bucket, slug, prefix, mediaHost, label, fileAgentUrl, fileAgentToken } };
}

export function validateR2SiteKeyRevokeParams(raw: unknown): ParamsVerdict<R2SiteKeyRevokeParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { bucket, tokenId } = raw;
  if (!isR2MediaBucketName(bucket)) {
    return { ok: false, reason: R2_MEDIA_BUCKET_RULE };
  }
  if (typeof tokenId !== "string" || !R2_TOKEN_ID_RE.test(tokenId)) {
    return { ok: false, reason: "tokenId must be a 32-character lowercase-hex Cloudflare API token id" };
  }
  return { ok: true, params: { bucket, tokenId } };
}

// ── planning/47: the boot-script update — the caller's expected metadata fingerprint ─────
// planning/47 makes an agency cell's nodes boot the CURRENT startup scripts: the orchestrator reads a
// node's metadata (gcp-instance-get reports its fingerprint and non-secret facts about its boot
// script), shows the operator what would change, and only then publishes (gcp-instance-set-metadata).
// The actuator's own read-then-write already refuses a change made between ITS read and ITS write
// (Google's 412). That is not enough: a change made between the CALLER's read and the op would be
// merged over, and the operator would have approved a diff against a script that is no longer there.
//
// So gcp-instance-set-metadata takes ONE OPTIONAL param more: `expectedFingerprint`, the fingerprint
// the caller read. The actuator compares it with the fingerprint it reads itself and refuses the
// write, with nothing written, when they differ (the discriminable `staleFingerprint` result). An
// absent `expectedFingerprint` keeps the op as it was, for the callers that do not send one.
//
// The value is Google's opaque token (base64 of 8 bytes today). It is never parsed, only compared;
// the grammar bounds it and keeps it a single safe word in a detail string.
//
// THIS BLOCK IS A PINNED TWIN. The app and the agency Worker carry it byte for byte, and each repo's
// test suite pins the sha256 of the block (from this marker up to the next section marker, the
// hub#58 block). A change on one side only fails that side's suite. Change both twins and both pins
// together.

/** A Compute Engine metadata fingerprint as gcp-instance-get reports it: 1-64 base64 characters. */
export const GCP_METADATA_FINGERPRINT_RE = /^[A-Za-z0-9+/=_-]{1,64}$/;
export const GCP_METADATA_FINGERPRINT_RULE =
  "expectedFingerprint must be a Compute Engine metadata fingerprint (1-64 base64 characters), as gcp-instance-get reports it";

/**
 * The verdict on the OPTIONAL `expectedFingerprint` of gcp-instance-set-metadata: absent (the op keeps
 * its own read-then-write guard only), a valid fingerprint, or the refusal reason.
 */
export function expectedFingerprintVerdict(
  value: unknown,
): { ok: true; expectedFingerprint: string | undefined } | { ok: false; reason: string } {
  if (value === undefined) {
    return { ok: true, expectedFingerprint: undefined };
  }
  if (typeof value !== "string" || !GCP_METADATA_FINGERPRINT_RE.test(value)) {
    return { ok: false, reason: GCP_METADATA_FINGERPRINT_RULE };
  }
  return { ok: true, expectedFingerprint: value };
}

// ── cf-tunnel-token-get (planning/47 decision G) ─────────────────────────────────────
// READ-ONLY: the CONNECTOR token of ONE Cloudflare tunnel (`cloudflared tunnel run --token <token>`),
// in the account the Worker's own CF_DNS_API_TOKEN belongs to. A saga-built cell's gateway runs the
// cell's tunnel connector, and gateway.sh writes that token from its injected DY_TUNNEL_TOKEN on every
// boot. To publish the CURRENT gateway.sh, the platform renders it with the token this op returns.
//
// THE ONE SECRET THIS OP RETURNS. The orchestrator puts it ONLY into the rendered gateway boot script
// inside the boot-script publish (gcp-instance-set-metadata), the same way the provision saga uses
// cf-tunnel-create's token. It never logs it, never prints it, never returns it to an operator and
// never stores it. app signs this op ONLY for the recorded Cell.tunnelId of one of the account's own
// saga-built cells (app agency-dispatch-binding.ts), so no other tunnel's token can be read.
//
// One REQUIRED string, `tunnelId`, with the grammar cf-tunnel-get uses.
//
// IDEMPOTENT: a read has no side effect. Registered `true` in AGENCY_OP_IDEMPOTENT.

export interface CfTunnelTokenGetParams {
  /** The cfd_tunnel id whose connector token is read. */
  tunnelId: string;
}

export function validateCfTunnelTokenGetParams(raw: unknown): ParamsVerdict<CfTunnelTokenGetParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { tunnelId } = raw;
  if (typeof tunnelId !== "string" || !CF_TUNNEL_ID_RE.test(tunnelId)) {
    return { ok: false, reason: "tunnelId must be a lowercase-hex Cloudflare tunnel id (a 36-char UUID, or 32 hex chars)" };
  }

  // A FRESH object of only the known key — never the caller's object.
  return { ok: true, params: { tunnelId } };
}

// ── gcp-instance-metadata-diff (planning/47 review M1/M2) ────────────────────────────
// READ-ONLY twin of gcp-instance-set-metadata: the SAME params (minus expectedFingerprint), the same
// placeholder substitution, and NO write. It answers with the sha256 of each value as a write would
// send it, and which keys already hold exactly that value. A file-node script holds the agency's
// object-store credential once substituted, so only this Worker can say whether the node's metadata
// already equals what the platform would publish: the reboot path refuses unless it does.
//
// A separate op (not a flag on set-metadata) on purpose: an app or Worker that predates it REFUSES the
// op name, where an unknown flag would be dropped by the validator and the call would WRITE.
//
// IDEMPOTENT: a read has no side effect. Registered `true` in AGENCY_OP_IDEMPOTENT.

export type GcpInstanceMetadataDiffParams = Omit<GcpInstanceSetMetadataParams, "expectedFingerprint">;

export function validateGcpInstanceMetadataDiffParams(raw: unknown): ParamsVerdict<GcpInstanceMetadataDiffParams> {
  if (isPlainObject(raw) && raw.expectedFingerprint !== undefined) {
    return { ok: false, reason: "gcp-instance-metadata-diff takes no expectedFingerprint: it writes nothing" };
  }
  const verdict = validateGcpInstanceSetMetadataParams(raw);
  if (!verdict.ok) {
    return verdict;
  }
  const { project, zone, name, items } = verdict.params;
  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, zone, name, items } };
}

// ── cf-tunnel-connections-get (planning/47 review M2/L4) ─────────────────────────────
// READ-ONLY: the CONNECTORS of ONE tunnel, as Cloudflare reports them — each connector's id, version
// and the origin IPs its connections come from. Non-secret. The gateway's pre-reboot check compares
// the origin IPs with the gateway's external IP, so it knows the gateway runs THIS tunnel's connector
// without reading the token on the node. app signs it only for a tunnel one of the account's cells
// records (Cell.tunnelId).
//
// One REQUIRED string, `tunnelId`, with the grammar cf-tunnel-get uses.
//
// IDEMPOTENT: a read has no side effect. Registered `true` in AGENCY_OP_IDEMPOTENT.

export interface CfTunnelConnectionsGetParams {
  /** The cfd_tunnel id whose connectors are read. */
  tunnelId: string;
}

export function validateCfTunnelConnectionsGetParams(raw: unknown): ParamsVerdict<CfTunnelConnectionsGetParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { tunnelId } = raw;
  if (typeof tunnelId !== "string" || !CF_TUNNEL_ID_RE.test(tunnelId)) {
    return { ok: false, reason: "tunnelId must be a lowercase-hex Cloudflare tunnel id (a 36-char UUID, or 32 hex chars)" };
  }

  // A FRESH object of only the known key — never the caller's object.
  return { ok: true, params: { tunnelId } };
}

// ── hub#58: syd through its Worker — cf-tunnel-get and gcp-disk-snapshot-create ──────
// planning/51 (hub#58) moves the syd cell onto the path every agency cell already uses: signed jobs
// through the agency's own Worker, on the agency's own credentials. Three ops are new for that. All
// are narrow on purpose. One READS a tunnel's ingress config. One takes a SNAPSHOT of one cell node's
// boot disk. One REMOVES the service account a cell node runs as (it can only take one away, never
// attach one). None of them deletes anything.
//
// THIS BLOCK IS A PINNED TWIN. The app and the agency Worker carry it byte for byte, and each repo's
// test suite pins the sha256 of the block (from this marker up to the next section marker, the
// planning/49 block). A change on one side only fails that side's suite. Change both twins and both
// pins together.

// ── cf-tunnel-get ────────────────────────────────────────────────────────────────────
// READ-ONLY: GET one Cloudflare tunnel's remotely-managed ingress config (planning/51 decision E).
//
// WHY A READ IS NEEDED. cf-tunnel-config is a FULL-config PUT: every rule the caller does not send is
// deleted. syd's tunnel has other writers (the session runner's routes, the custom-domain routes), so
// a writer that cannot see the live config would delete their rules. The orchestrator reads the
// config with this op, keeps every rule it does not own, and only then PUTs.
//
// One REQUIRED string, `tunnelId`, with the same grammar cf-tunnel-config and cf-tunnel-delete use.
// The Worker reads the tunnel in the account its own CF_DNS_API_TOKEN belongs to, and app signs this
// op only for a tunnel that one of the account's own cells records (app agency-dispatch.ts).
//
// IDEMPOTENT: a read has no side effect. Registered `true` in AGENCY_OP_IDEMPOTENT.

export interface CfTunnelGetParams {
  /** The cfd_tunnel id whose ingress config is read. */
  tunnelId: string;
}

export function validateCfTunnelGetParams(raw: unknown): ParamsVerdict<CfTunnelGetParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { tunnelId } = raw;
  if (typeof tunnelId !== "string" || !CF_TUNNEL_ID_RE.test(tunnelId)) {
    return { ok: false, reason: "tunnelId must be a lowercase-hex Cloudflare tunnel id (a 36-char UUID, or 32 hex chars)" };
  }

  // A FRESH object of only the known key — never the caller's object.
  return { ok: true, params: { tunnelId } };
}

// ── gcp-disk-snapshot-create ─────────────────────────────────────────────────────────
// SNAPSHOT-ONLY: take a snapshot of ONE cell node's BOOT disk in the AGENCY's own project
// (planning/51 decision H). It is the revert point before a node reboots onto a new startup script:
// if the node does not come back, its boot disk is restored from this snapshot.
//
// Four REQUIRED strings:
//   1. `project`  — the project id (the Worker pins it to the SA key's own project);
//   2. `zone`     — the zone of the VM (a URL path segment);
//   3. `instance` — the VM, PINNED to the cell-node name shape dy-<web|file|data|gw|gateway>-<cell>-<n>.
//                   syd shares its project with the control plane, so the project pin alone does not
//                   keep this op away from the control-plane VM. The name pin does (dy-cp-1 does not
//                   match), and app signs the op only for a CellNode of one of the account's own cells;
//   4. `label`    — 1-16 lowercase letters and digits, e.g. the window date "20261020".
//
// THE SNAPSHOT NAME IS DERIVED, never free-form: `<instance>-boot-<label>` (diskSnapshotNameFor). So a
// signed job cannot name, and therefore cannot collide with, a snapshot this op did not make. The
// Worker snapshots the instance's ONE boot disk only. It never takes a disk name from the job.
//
// IDEMPOTENT: a snapshot that already exists under the derived name, of this same boot disk, is
// reported "already-existed" with its current status. That is also how a caller polls for READY: it
// sends the same params again. Registered `true` in AGENCY_OP_IDEMPOTENT.

export interface GcpDiskSnapshotCreateParams {
  /** The agency's GCP project id the VM lives in. */
  project: string;
  /** The Compute Engine zone of the VM, e.g. "australia-southeast1-a". */
  zone: string;
  /** The cell node whose boot disk is snapshotted, e.g. "dy-data-syd-1". */
  instance: string;
  /** The suffix that makes the snapshot name unique per window, e.g. "20261020". */
  label: string;
}

/**
 * A cell node's VM name: `dy-` + a node role + `-` + the cell part + `-` + an index. The role list
 * covers both naming schemes in use: the saga's `dy-gateway-<region>-1` and syd's `dy-gw-syd-1`. The
 * control-plane VM (`dy-cp-1`) does not match, by design.
 */
const CELL_NODE_INSTANCE_NAME_RE = /^dy-(?:web|file|data|gw|gateway)-[a-z0-9](?:[a-z0-9-]{0,48}[a-z0-9])?-[0-9]{1,3}$/;
const DISK_SNAPSHOT_LABEL_RE = /^[a-z0-9]{1,16}$/;

/** The ONE snapshot name this op may create for `instance` and `label` (the caller validates both). */
export function diskSnapshotNameFor(instance: string, label: string): string {
  return `${instance}-boot-${label}`;
}

export function validateGcpDiskSnapshotCreateParams(raw: unknown): ParamsVerdict<GcpDiskSnapshotCreateParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, zone, instance, label } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof zone !== "string" || zone.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a Compute Engine zone name (e.g. australia-southeast1-a)" };
  }
  if (typeof instance !== "string" || !GCP_RESOURCE_NAME_RE.test(instance) || !CELL_NODE_INSTANCE_NAME_RE.test(instance)) {
    return {
      ok: false,
      reason: "instance must be a cell node VM name: dy-<web|file|data|gw|gateway>-<cell>-<n> (e.g. dy-data-syd-1)",
    };
  }
  if (typeof label !== "string" || !DISK_SNAPSHOT_LABEL_RE.test(label)) {
    return { ok: false, reason: "label must be 1-16 lowercase letters and digits (e.g. 20261020)" };
  }
  const snapshotName = diskSnapshotNameFor(instance, label);
  if (!GCP_RESOURCE_NAME_RE.test(snapshotName)) {
    return {
      ok: false,
      reason: `the snapshot name ${snapshotName} would not be a valid Compute Engine resource name (max 63 characters) — use a shorter label`,
    };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, zone, instance, label } };
}

// ── gcp-instance-remove-service-account ──────────────────────────────────────────────
// Take the SERVICE ACCOUNT off ONE cell node, and leave the VM STOPPED (planning/51 review finding 4).
//
// WHY. syd's VMs were built by hand and run as the project's default Compute service account. Google
// requires iam.serviceAccounts.actAs on a VM's attached account to set its metadata, because a
// startup-script runs as root with that account's token. The agency's key must never hold actAs, so
// the account comes off first; then the startup-script can be published, and the VM starts on it.
// Changing a VM's account needs the VM stopped, so this op stops it and does NOT start it: the
// caller publishes and then starts it with gcp-instance-restart (which only starts a stopped VM).
//
// It can only REMOVE: the request names no account and no scope, so no signed job can attach one.
//
// Three REQUIRED strings, the same grammars as gcp-instance-restart, with the name PINNED to the
// cell-node shape (as gcp-disk-snapshot-create): the control-plane VM dy-cp-1 shares syd's project,
// and its name does not match. app signs the op only for a CellNode of one of the account's own cells.
//
// NOT IDEMPOTENT for a retry: the first call stops a running VM. A VM that already runs as no account
// is reported "already-none" and nothing is changed.

export interface GcpInstanceRemoveServiceAccountParams {
  /** The agency's GCP project id the VM lives in. */
  project: string;
  /** The Compute Engine zone of the VM, e.g. "australia-southeast1-a". */
  zone: string;
  /** The cell node, e.g. "dy-data-syd-1". */
  name: string;
}

export function validateGcpInstanceRemoveServiceAccountParams(raw: unknown): ParamsVerdict<GcpInstanceRemoveServiceAccountParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, zone, name } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof zone !== "string" || zone.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a Compute Engine zone name (e.g. australia-southeast1-a)" };
  }
  if (typeof name !== "string" || !GCP_RESOURCE_NAME_RE.test(name) || !CELL_NODE_INSTANCE_NAME_RE.test(name)) {
    return {
      ok: false,
      reason: "name must be a cell node VM name: dy-<web|file|data|gw|gateway>-<cell>-<n> (e.g. dy-data-syd-1)",
    };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, zone, name } };
}

// ── cf-tunnel-config: the keep-foreign extras (planning/50 integration review M1, M2) ───────
// The orchestrator's ONE tunnel writer (cell-ingress-keep.ts) reads a tunnel's live config and writes
// back every rule it does not own. Two live shapes must survive that round trip byte for byte, so
// cf-tunnel-config accepts them — and ONLY in these exact shapes:
//   - a rule's `originRequest` of exactly `{ httpHostHeader: <lowercase FQDN> }`: the one setting the
//     session runner's route recipes write (infra cell-run/provision-*-route.sh: the Run service's own
//     host, e.g. "pma-docs-123.australia-southeast1.run.app");
//   - the top-level `warp-routing` key of exactly `{ enabled: <boolean> }` (cf-tunnel-get's warpRouting).
// Any other originRequest key or top-level key still fails closed: it never reaches a signature.

export interface CfTunnelOriginRequest {
  /** The Host header cloudflared sends to the origin: a lowercase FQDN. */
  httpHostHeader: string;
}

export interface CfTunnelWarpRouting {
  enabled: boolean;
}

const CF_TUNNEL_ORIGIN_REQUEST_REASON =
  "an ingress rule's originRequest, when present, must be exactly { httpHostHeader: <lowercase fully-qualified hostname> }";
const CF_TUNNEL_WARP_ROUTING_REASON = "warpRouting, when present, must be exactly { enabled: <boolean> }";

/** A rule's optional originRequest: absent => undefined; exactly `{ httpHostHeader }` => a FRESH copy. */
export function cleanCfTunnelOriginRequest(raw: unknown): { ok: true; value: CfTunnelOriginRequest | undefined } | { ok: false; reason: string } {
  if (raw === undefined) {
    return { ok: true, value: undefined };
  }
  if (!isPlainObject(raw)) {
    return { ok: false, reason: CF_TUNNEL_ORIGIN_REQUEST_REASON };
  }
  const keys = Object.keys(raw);
  if (keys.length !== 1 || keys[0] !== "httpHostHeader") {
    return { ok: false, reason: CF_TUNNEL_ORIGIN_REQUEST_REASON };
  }
  const { httpHostHeader } = raw;
  if (typeof httpHostHeader !== "string" || httpHostHeader.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(httpHostHeader)) {
    return { ok: false, reason: CF_TUNNEL_ORIGIN_REQUEST_REASON };
  }
  return { ok: true, value: { httpHostHeader } };
}

/** The optional warp-routing key: exactly `{ enabled: <boolean> }` => a FRESH copy. */
export function cleanCfTunnelWarpRouting(raw: unknown): { ok: true; value: CfTunnelWarpRouting } | { ok: false; reason: string } {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: CF_TUNNEL_WARP_ROUTING_REASON };
  }
  const keys = Object.keys(raw);
  if (keys.length !== 1 || keys[0] !== "enabled" || typeof raw.enabled !== "boolean") {
    return { ok: false, reason: CF_TUNNEL_WARP_ROUTING_REASON };
  }
  return { ok: true, value: { enabled: raw.enabled } };
}

// ── planning/49: the agency-side ephemeral-compute ops ───────────────────────────────
// planning/49 places the terminal / phpMyAdmin / staging runner in the AGENCY's own GCP project, as
// a Cloud Run service with Direct VPC egress onto that cell's own VPC. In the agency's own project,
// the three conditions for Direct VPC egress (same project, same region, same VPC) are all
// satisfiable by resources these ops create.
//
// ONE FACT RUNS THROUGH ALL OF THEM. A Direct-VPC-egress Cloud Run service does NOT join the
// project's internal DNS. A node's short hostname does not resolve from inside it, so every address
// such a service gets (an NFS mount target, a database host) must be an IP LITERAL. That is why
// `gcp-instance-get` exists (no other op returns a node's address: gcp-instances-list parses only
// `name` and `zone`), and why an NFS volume's `server` must be a private IPv4 literal.

// ── gcp-instance-get ─────────────────────────────────────────────────────────────────
// READ-ONLY: GET ONE Compute Engine VM in the AGENCY's own project and report its in-VPC PRIVATE
// IPv4 address and its lifecycle status (planning/49 Phase 1, "cell coordinates become facts").
// Three REQUIRED strings, each with the same grammar its twin gcp-instance-delete uses: `project`
// (pinned to the SA key's own project by the actuator), `zone` and `name` (both URL path segments).
//
// A MISSING INSTANCE IS NOT A FAILURE: the actuator answers found:false, like gcp-firewall-get, so a
// caller that reads back a replaced or renamed VM gets a clean "not there", not an error to parse.
//
// IDEMPOTENT: a read has no side effect. Registered `true` in AGENCY_OP_IDEMPOTENT.

export interface GcpInstanceGetParams {
  /** The agency's GCP project id the VM lives in. */
  project: string;
  /** The Compute Engine zone of the VM, e.g. "australia-southeast1-a". */
  zone: string;
  /** The instance's resource name. */
  name: string;
}

export function validateGcpInstanceGetParams(raw: unknown): ParamsVerdict<GcpInstanceGetParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, zone, name } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof zone !== "string" || zone.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a Compute Engine zone name (e.g. australia-southeast1-a)" };
  }
  if (typeof name !== "string" || !GCP_RESOURCE_NAME_RE.test(name)) {
    return { ok: false, reason: `name ${GCP_RESOURCE_NAME_RULE}` };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, zone, name } };
}

// ── planning/49 Phase 2: the Cloud Run subnet, the Cloud Run service, the premise probe ──
// The names below are PINNED, not free-form (review M2/M3, 2026-10-07). Each one is DERIVED from a
// value the same request carries and this file has already validated. A signed job therefore cannot
// point a subnet op at the cell's NODE subnet, attach a service to another network, run it as
// another identity, or take over a Cloud Run service this platform does not name.
//
// planning/49 Phase 3 (I3) relaxes ONE thing, for a hand-built cell whose names the saga did not make:
// a SESSION service and a SITE-form subnet op may name the cell's network and its per-site subnet by
// REGISTRY name (Cell.network, Cell.runSubnetPrefix). The twin still pins the shape: the network is a
// Compute name, and the subnet is `<prefix><NNN>` for the job's OWN slot. app binds both names to the
// cell's recorded facts before it signs (agency-dispatch-site-binding.ts), and the Worker reads the
// subnet back and checks its network, range and description before it uses it. The probe keeps the
// saga names.

/** The cell's VPC network: `dy-cell-<region>` (orchestrator cell-provision.ts cellResourceNames). */
export function cellNetworkNameFor(region: string): string {
  return `dy-cell-${region}`;
}

/** The cell's Cloud Run subnet: `dy-cell-<region>-run` (planning/49 §4.1). */
function cellRunSubnetNameFor(region: string): string {
  return `dy-cell-${region}-run`;
}

/**
 * The RUNTIME identity of every Cloud Run service on a cell: `dy-run@<project>`. The agency creates
 * it ONCE at onboarding and grants the Worker's own service account `iam.serviceAccounts.actAs` on
 * it, so the Worker never needs serviceAccountAdmin (planning/49 §4.1, §8). Exported so the Worker's
 * /validate tests actAs on exactly this account.
 */
export function cellRunServiceAccountFor(project: string): string {
  return `dy-run@${project}.iam.gserviceaccount.com`;
}

// ── hub#93: per-site Run subnets (one /24 per site) ──────────────────────────────────
// Every session service of a site (term-, pma-, staging-, sterm-, spma-<slug>) egresses from that
// site's OWN subnet, so the file node's exports and the data node's grants can tell one site's
// session from another's. A site holds ONE Run slot N (0-127, recorded in app as Site.runSlot), and
// every value below is DERIVED from N, here, on both sides of the boundary:
//   subnet  `dy-cell-<region>-run-s<NNN>` (NNN = N zero-padded to three digits)
//   range   10.20.(128+N).0/24, inside the session supernet 10.20.128.0/17
//   description `doubleyoup site subnet: <slug>` — set at create, and Google refuses to patch it
//           later (hub#93 gate G4), so the Worker can bind a subnet to its site by reading it back.
// The slug is NOT in the subnet name: `dy-cell-australia-southeast2-run-` is already 33 characters,
// a slug can be longer than the 30 left, and a Compute name stops at 63. The probe subnet
// `dy-cell-<region>-run` (10.20.4.0/24) is unchanged and gets no export and no grant.
//
// These helpers are PURE. A derive helper given a slot outside 0-127 THROWS a RangeError: it is only
// ever called after the validator checked the slot, so reaching it with a bad one is a programming
// error that must not produce a plausible-looking range.

/** The supernet every per-site session subnet lives in: 128 /24 slots (hub#93 §1). */
export const SITE_RUN_SUPERNET_CIDR = "10.20.128.0/17";
/** The lowest Run slot. */
export const SITE_RUN_SLOT_MIN = 0;
/** The highest Run slot: 10.20.(128+127).0/24 = 10.20.255.0/24 is the last /24 of the supernet. */
export const SITE_RUN_SLOT_MAX = 127;
/** Slot N lives in the third octet 128+N. */
const SITE_RUN_SLOT_THIRD_OCTET_BASE = 128;
/** The fixed head of every per-site subnet description; the site slug follows it. */
const SITE_SUBNET_DESCRIPTION_PREFIX = "doubleyoup site subnet: ";
/**
 * A site slug where a per-site subnet, a session host or an NFS path names it: [a-z0-9-], alphanumeric
 * at both ends, at most 46 characters. 46 is app's own ceiling for a slug (sites.ts uniqueSlug: a 39-char
 * base plus "-" plus a 6-char disambiguation suffix). Anchored, so no "/", ".", space or quote appears.
 */
const SITE_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,44}[a-z0-9])?$/;
/** The NFS export root on the file node. Every per-site export path sits under it (hub#93 §3). */
const SITE_STORAGE_ROOT = "/srv/dy-storage";

/** True when `value` is a Run slot: an integer from 0 to 127. */
export function isSiteRunSlot(value: unknown): value is number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    return false;
  }
  return value >= SITE_RUN_SLOT_MIN && value <= SITE_RUN_SLOT_MAX;
}

/** True when `value` is a site slug in the grammar above. */
export function isSiteSlug(value: unknown): value is string {
  return typeof value === "string" && SITE_SLUG_RE.test(value);
}

/** Throw unless `slot` is a Run slot. Every derive helper calls this first. */
function assertSiteRunSlot(slot: number): void {
  if (!isSiteRunSlot(slot)) {
    throw new RangeError(`a Run slot must be an integer from ${SITE_RUN_SLOT_MIN} to ${SITE_RUN_SLOT_MAX}, got ${String(slot)}`);
  }
}

/** The zero-padded slot label in a per-site subnet name: 0 -> "s000", 7 -> "s007", 127 -> "s127". */
export function siteRunSlotLabel(slot: number): string {
  assertSiteRunSlot(slot);
  return `s${String(slot).padStart(3, "0")}`;
}

/** Slot N -> its subnet's primary range, 10.20.(128+N).0/24. The ONE derivation of the range. */
export function siteRunSubnetCidrForSlot(slot: number): string {
  assertSiteRunSlot(slot);
  return `10.20.${SITE_RUN_SLOT_THIRD_OCTET_BASE + slot}.0/24`;
}

/** The name prefix every per-site subnet of an agency cell starts with: `dy-cell-<region>-run-s`. */
export function cellSiteRunSubnetNamePrefixFor(region: string): string {
  return `${cellRunSubnetNameFor(region)}-s`;
}

/** An agency cell's per-site subnet for slot N: `dy-cell-<region>-run-s<NNN>`. */
export function cellSiteRunSubnetNameFor(region: string, slot: number): string {
  return `${cellRunSubnetNameFor(region)}-${siteRunSlotLabel(slot)}`;
}

/**
 * A per-site subnet NAME PREFIX as the registry records it (Cell.runSubnetPrefix, planning/49 decision
 * D): a lowercase letter, then at most 59 of [-a-z0-9]. Slot N's subnet is `<prefix><NNN>`, so the
 * whole name stays within a Compute name's 63 characters. The same grammar app's set-cell-facts checks
 * (cell-facts-plan.ts RUN_SUBNET_PREFIX_RE). The saga prefix `dy-cell-<region>-run-s` matches it.
 */
const SITE_RUN_SUBNET_PREFIX_RE = /^[a-z][-a-z0-9]{0,59}$/;

/** The three zero-padded slot digits a per-site subnet name ends with: 7 -> "007". */
function siteRunSlotDigits(slot: number): string {
  assertSiteRunSlot(slot);
  return String(slot).padStart(3, "0");
}

/** Slot N's per-site subnet under a registry prefix: `<prefix><NNN>`, e.g. `dy-subnet-run-syd-s007`. */
export function siteRunSubnetNameFor(prefix: string, slot: number): string {
  return `${prefix}${siteRunSlotDigits(slot)}`;
}

/**
 * True when `name` is a per-site subnet name for `slot`: a registry prefix (SITE_RUN_SUBNET_PREFIX_RE)
 * followed by exactly the slot's three digits. The saga name `dy-cell-<region>-run-s<NNN>` passes. The
 * twin cannot know WHICH prefix the cell records; app binds that before signing. False (never a throw)
 * for a slot outside 0-127 or a value that is not a string.
 */
export function isSiteRunSubnetNameForSlot(name: unknown, slot: number): name is string {
  if (typeof name !== "string" || !isSiteRunSlot(slot)) {
    return false;
  }
  const digits = siteRunSlotDigits(slot);
  if (!name.endsWith(digits)) {
    return false;
  }
  const prefix = name.slice(0, name.length - digits.length);
  return SITE_RUN_SUBNET_PREFIX_RE.test(prefix) && GCP_RESOURCE_NAME_RE.test(name);
}

/** The rule a per-site subnet name must follow, for a refusal reason. */
function siteRunSubnetNameRule(slot: number, region: string): string {
  return (
    `a registry name prefix (a lowercase letter, then at most 59 of [-a-z0-9]) followed by the slot's three digits ` +
    `"${siteRunSlotDigits(slot)}", e.g. "${cellSiteRunSubnetNameFor(region, slot)}"`
  );
}

/**
 * The slot a per-site subnet name encodes, or null when the name is not exactly
 * `dy-cell-<region>-run-s<NNN>` with a canonical three-digit NNN from 000 to 127.
 */
export function siteRunSlotFromSubnetName(region: string, subnetName: string): number | null {
  return siteRunSlotFromPrefixedSubnetName(cellSiteRunSubnetNamePrefixFor(region), subnetName);
}

/**
 * The slot a per-site subnet name encodes under a given name prefix (the saga's, or a registry
 * Cell.runSubnetPrefix, planning/49 Phase 3), or null when the name is not exactly `<prefix><NNN>` with a
 * canonical three-digit NNN from 000 to 127.
 */
export function siteRunSlotFromPrefixedSubnetName(prefix: string, subnetName: string): number | null {
  if (!subnetName.startsWith(prefix)) {
    return null;
  }
  const digits = subnetName.slice(prefix.length);
  if (!/^[0-9]{3}$/.test(digits)) {
    return null;
  }
  const slot = Number(digits);
  if (!isSiteRunSlot(slot)) {
    return null;
  }
  return slot;
}

/** The description a site's subnet is created with: `doubleyoup site subnet: <slug>`. */
export function siteSubnetDescriptionFor(slug: string): string {
  return `${SITE_SUBNET_DESCRIPTION_PREFIX}${slug}`;
}

/**
 * The slug a subnet's description binds it to, or null when the description is not EXACTLY
 * `doubleyoup site subnet: <slug>` with a slug in the site grammar (a missing, foreign or edited
 * description binds the subnet to no site).
 */
export function siteSlugFromSubnetDescription(description: unknown): string | null {
  if (typeof description !== "string" || !description.startsWith(SITE_SUBNET_DESCRIPTION_PREFIX)) {
    return null;
  }
  const slug = description.slice(SITE_SUBNET_DESCRIPTION_PREFIX.length);
  if (!isSiteSlug(slug)) {
    return null;
  }
  return slug;
}

/** The network tag every VM of an agency cell carries: `dy-cell-<region>-node`. */
function cellNodeTagFor(region: string): string {
  return `dy-cell-${region}-node`;
}

/** The ONE sessions firewall rule of an agency cell: `dy-cell-<region>-sessions-to-nodes`. */
export function cellSessionsFirewallRuleNameFor(region: string): string {
  return `dy-cell-${region}-sessions-to-nodes`;
}

/**
 * The exact sessions rule (hub#93 §2, decision D4): from the session supernet to the cell's node tag,
 * tcp 3306 (MariaDB) and tcp+udp 2049 (NFS). It mirrors the probe's `<cell>-run-to-nodes` rule
 * (orchestrator cellRunIngressPolicy) with the supernet as its source, and is created with the
 * existing gcp-firewall-create. One rule per cell: every site needs the same ports on the same two
 * hosts, so a per-site rule would add no isolation — the per-site exports and grants are the
 * isolation layer.
 */
export function cellSessionsFirewallRuleFor(project: string, region: string): GcpFirewallCreateParams {
  return {
    project,
    networkName: cellNetworkNameFor(region),
    ruleName: cellSessionsFirewallRuleNameFor(region),
    allowed: [
      { protocol: "tcp", ports: ["3306", "2049"] },
      { protocol: "udp", ports: ["2049"] },
    ],
    sourceRanges: [SITE_RUN_SUPERNET_CIDR],
    targetTags: [cellNodeTagFor(region)],
  };
}

/**
 * gcp-firewall-create's extra rule for the sessions rule. A rule NAMED `dy-cell-<region>-sessions-to-nodes`
 * must be EXACTLY cellSessionsFirewallRuleFor(project, region): any other source range, port or target
 * under that name is refused, so a caller bug cannot widen the one rule every site's sessions share.
 * Returns null for every other rule name (they are not pinned).
 */
export function sessionsFirewallRuleShapeReason(params: GcpFirewallCreateParams): string | null {
  const match = /^dy-cell-(.+)-sessions-to-nodes$/.exec(params.ruleName);
  if (match === null) {
    return null;
  }
  const region = match[1];
  if (region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return "a sessions rule must be named dy-cell-<region>-sessions-to-nodes for a Compute region";
  }
  const expected = cellSessionsFirewallRuleFor(params.project, region);
  // Compare the canonical JSON of the cleaned params with the canonical rule, part by part, so the
  // reason names the part that differs. Order matters: the rule is built in one fixed order.
  if (params.networkName !== expected.networkName) {
    return `a sessions rule must attach to "${expected.networkName}" (the cell's own VPC)`;
  }
  if (JSON.stringify(params.sourceRanges) !== JSON.stringify(expected.sourceRanges)) {
    return `a sessions rule must have exactly the source range ${SITE_RUN_SUPERNET_CIDR}`;
  }
  if (JSON.stringify(params.targetTags) !== JSON.stringify(expected.targetTags)) {
    return `a sessions rule must target exactly the "${cellNodeTagFor(region)}" tag`;
  }
  if (JSON.stringify(params.allowed) !== JSON.stringify(expected.allowed)) {
    return "a sessions rule must allow exactly tcp 3306 and 2049, then udp 2049";
  }
  return null;
}

// ── gcp-subnet-create / -get / -delete: the probe form and the SITE form ─────────────
// Each of the three subnet ops accepts exactly ONE of two shapes, never a free-form name or range:
//   PROBE form (planning/49 Phase 2, unchanged): the cell's ONE probe subnet `dy-cell-<region>-run`.
//   SITE form (hub#93 §2): `{ project, region, slot, siteSlug }`, plus (planning/49 Phase 3) an
//            OPTIONAL pair `network` + `subnet`, both or neither:
//              neither — the saga names, derived as before: `dy-cell-<region>` and
//                        `dy-cell-<region>-run-s<NNN>`. A job without the pair signs exactly as before.
//              both    — REGISTRY names for a cell the saga did not build (syd: `dy-vpc` and
//                        `dy-subnet-run-syd-s<NNN>`). `network` is a Compute name, and `subnet` is
//                        `<prefix><NNN>` for the job's own slot (isSiteRunSubnetNameForSlot).
//            The range and the description are always DERIVED from the slot and the slug. A site-form
//            job that ALSO carries networkName / subnetName / ipCidr (the probe form's keys) is refused.
// A job carrying `slot` or `siteSlug` is a site-form job; any other job is a probe-form job.
//
// What the twin CAN check: the shapes agree (a valid slot, a valid slug, a subnet name for that slot).
// What it CANNOT check, because it holds no DB: that N is THIS slug's slot, and that the names are the
// cell's recorded ones. app checks both in buildDispatch before it signs (agency-dispatch-site-binding.ts),
// and the Worker binds the subnet to the slug with its description (set at create, read back before
// every upsert and delete) and checks its network on every read-back.
//
// AN OLD WORKER DROPS THE PAIR SILENTLY (its validator returns only the keys it knows), and would then
// act on the saga name instead. So the Worker ECHOES the network and subnet it used in every site-form
// result, and a caller that sent the pair refuses a result without that echo.

/** The SITE form of a subnet op: a slot and a slug, and optionally the cell's registry names. */
export interface GcpSiteSubnetRef {
  /** The agency's GCP project id the subnet lives in. */
  project: string;
  /** The Compute Engine region of the subnet (and of the cell), e.g. "australia-southeast2". */
  region: string;
  /** The site's Run slot, 0-127. */
  slot: number;
  /** The site's slug — the subnet's description binds it to this site. */
  siteSlug: string;
  /** OPTIONAL, only with `subnet`: the cell's network by registry name. Absent: `dy-cell-<region>`. */
  network?: string;
  /** OPTIONAL, only with `network`: `<prefix><NNN>` for `slot`. Absent: `dy-cell-<region>-run-s<NNN>`. */
  subnet?: string;
}

/** True when a validated subnet-op params object is the SITE form. */
export function isGcpSiteSubnetRef(params: object): params is GcpSiteSubnetRef {
  return "siteSlug" in params;
}

/** The network a validated site-form ref names: its registry `network`, else the saga's `dy-cell-<region>`. */
export function siteSubnetRefNetworkName(ref: GcpSiteSubnetRef): string {
  if (ref.network !== undefined) {
    return ref.network;
  }
  return cellNetworkNameFor(ref.region);
}

/** The subnet a validated site-form ref names: its registry `subnet`, else the saga's `dy-cell-<region>-run-s<NNN>`. */
export function siteSubnetRefSubnetName(ref: GcpSiteSubnetRef): string {
  if (ref.subnet !== undefined) {
    return ref.subnet;
  }
  return cellSiteRunSubnetNameFor(ref.region, ref.slot);
}

/** True when a RAW params object asks for the site form (it names a slot or a slug). */
function asksForSiteSubnetForm(raw: Record<string, unknown>): boolean {
  return raw.slot !== undefined || raw.siteSlug !== undefined;
}

/**
 * Validate the SITE form shared by the three subnet ops. `op` only names the op in a reason. Without
 * the registry pair, the derived subnet name must itself be a valid Compute name, which bounds the
 * region's length.
 */
function validateGcpSiteSubnetRef(raw: Record<string, unknown>, op: string): ParamsVerdict<GcpSiteSubnetRef> {
  const { project, region, slot, siteSlug, network, subnet } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast2)" };
  }
  if (!isSiteRunSlot(slot)) {
    return { ok: false, reason: `slot must be a Run slot: an integer from ${SITE_RUN_SLOT_MIN} to ${SITE_RUN_SLOT_MAX}` };
  }
  if (!isSiteSlug(siteSlug)) {
    return { ok: false, reason: "siteSlug must be a site slug ([a-z0-9-], 1-46 chars, alphanumeric at both ends)" };
  }
  // NEVER the probe form's free-form keys: the site form names its subnet by `network` + `subnet` (or
  // derives both), and always derives the range. A caller that sends the probe keys has confused the
  // two forms, and silently ignoring the values would hide that.
  if (raw.networkName !== undefined || raw.subnetName !== undefined || raw.ipCidr !== undefined) {
    return {
      ok: false,
      reason: `the site form of ${op} derives the range itself and names its subnet by network + subnet — it must not carry networkName, subnetName or ipCidr`,
    };
  }

  // NEITHER registry name: the saga names, exactly as before the pair existed.
  if (network === undefined && subnet === undefined) {
    if (!GCP_RESOURCE_NAME_RE.test(cellSiteRunSubnetNameFor(region, slot))) {
      return { ok: false, reason: `region is too long: the derived subnet name ${GCP_RESOURCE_NAME_RULE}` };
    }
    // A FRESH object of only the four known keys — never the caller's object.
    return { ok: true, params: { project, region, slot, siteSlug } };
  }

  // BOTH registry names, or the job is refused: one name alone would pair a registry name with a
  // derived one, which no cell has.
  if (network === undefined || subnet === undefined) {
    return { ok: false, reason: `the site form of ${op} takes network and subnet together, or neither` };
  }
  if (typeof network !== "string" || !GCP_RESOURCE_NAME_RE.test(network)) {
    return { ok: false, reason: `network ${GCP_RESOURCE_NAME_RULE}` };
  }
  if (!isSiteRunSubnetNameForSlot(subnet, slot)) {
    return { ok: false, reason: `subnet must be the site's own Run subnet for slot ${slot}: ${siteRunSubnetNameRule(slot, region)}` };
  }

  // A FRESH object of only the six known keys — never the caller's object.
  return { ok: true, params: { project, region, slot, siteSlug, network, subnet } };
}

// ── gcp-subnet-create ────────────────────────────────────────────────────────────────
// Create a Cloud Run subnet on the cell's EXISTING VPC in the AGENCY's own project (planning/49 §4.1).
// It is separate from the node subnet, because Direct VPC egress takes addresses from a subnet and
// must not compete with the VMs. gcp-network-create stays the "build the VPC" op; this adds ONE range
// to a built VPC.
//
// PROBE form — five REQUIRED strings:
//   1. `project`     — pinned to the SA key's own project by the actuator.
//   2. `region`      — a Compute region (a URL path segment).
//   3. `networkName` — PINNED: exactly `dy-cell-<region>`.
//   4. `subnetName`  — PINNED: exactly `dy-cell-<region>-run`.
//   5. `ipCidr`      — a PRIVATE (RFC 1918) block, /8-/26. The platform sends CELL_RUN_SUBNET_CIDR.
//                      /26 is Cloud Run's own floor for a Direct VPC egress subnet (review L4), so
//                      this is a separate rule from GCP_SUBNET_CIDR_RE (which allows /29).
// SITE form — `{ project, region, slot, siteSlug }` (+ the optional registry pair `network` + `subnet`).
// The Worker creates the site's subnet (`subnet`, else `dy-cell-<region>-run-s<NNN>`) on the cell's
// network (`network`, else `dy-cell-<region>`) with the range 10.20.(128+N).0/24 and the description
// `doubleyoup site subnet: <siteSlug>`. An EXISTING subnet of that name passes only when its network,
// its range AND its description match exactly; anything else is a conflict, never adopted.
//
// IDEMPOTENT: Google's 409 alreadyExists is success, so a re-run resumes. For the probe form,
// idempotence is by NAME: a re-run with a DIFFERENT ipCidr is a no-op, so the caller reads the range
// back with gcp-subnet-get.

/** The PROBE form of gcp-subnet-create (planning/49 Phase 2). */
export interface GcpProbeSubnetCreateParams {
  /** The agency's GCP project id the subnet is created in. */
  project: string;
  /** The Compute Engine region of the subnet, e.g. "australia-southeast2". */
  region: string;
  /** The cell's EXISTING VPC: exactly `dy-cell-<region>`. */
  networkName: string;
  /** The Cloud Run subnet: exactly `dy-cell-<region>-run`. */
  subnetName: string;
  /** The subnet's primary IPv4 range — a private RFC 1918 block between /8 and /26. */
  ipCidr: string;
}

/** gcp-subnet-create takes the probe form or the site form. */
export type GcpSubnetCreateParams = GcpProbeSubnetCreateParams | GcpSiteSubnetRef;

/**
 * A Cloud Run subnet range: a PRIVATE (RFC 1918) IPv4 block from /8 to /26. Direct VPC egress
 * needs at least a /26, so a smaller block is refused here rather than at Google.
 */
const RUN_SUBNET_CIDR_RE = new RegExp(
  `^(?:10(?:\\.${IPV4_OCTET}){3}\\/(?:[89]|1[0-9]|2[0-6])` +
    `|172\\.(?:1[6-9]|2[0-9]|3[01])(?:\\.${IPV4_OCTET}){2}\\/(?:1[2-9]|2[0-6])` +
    `|192\\.168(?:\\.${IPV4_OCTET}){2}\\/(?:1[6-9]|2[0-6]))$`,
);

export function validateGcpSubnetCreateParams(raw: unknown): ParamsVerdict<GcpSubnetCreateParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  if (asksForSiteSubnetForm(raw)) {
    return validateGcpSiteSubnetRef(raw, "gcp-subnet-create");
  }
  const { project, region, networkName, subnetName, ipCidr } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast2)" };
  }
  const expectedNetwork = cellNetworkNameFor(region);
  if (networkName !== expectedNetwork) {
    return { ok: false, reason: `networkName must be exactly "${expectedNetwork}" (the cell's own VPC)` };
  }
  const expectedSubnet = cellRunSubnetNameFor(region);
  if (subnetName !== expectedSubnet) {
    return { ok: false, reason: `subnetName must be exactly "${expectedSubnet}" (the cell's Cloud Run subnet)` };
  }
  if (typeof ipCidr !== "string" || !RUN_SUBNET_CIDR_RE.test(ipCidr)) {
    return {
      ok: false,
      reason: "ipCidr must be a private (RFC 1918) IPv4 CIDR block between /8 and /26 (e.g. 10.20.4.0/24)",
    };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, networkName: expectedNetwork, subnetName: expectedSubnet, ipCidr } };
}

// ── gcp-subnet-get ───────────────────────────────────────────────────────────────────
// READ-ONLY: does ONE subnet EXIST in the AGENCY's own project, and what is its primary range? The
// subnet twin of gcp-firewall-get.
//   PROBE / NAMED form — `{ project, region, subnetName }`. NOT pinned: a read of the node subnet is
//            harmless and useful. Idempotence of the probe-form create is by NAME, so reading
//            `ipCidrRange` back is how a caller sees a same-named subnet with a different range.
//   SITE form — `{ project, region, slot, siteSlug }` (+ the optional registry pair). The Worker reads
//            the site's subnet and also reports its description and whether network + range +
//            description match this site. This is the read the slot reconcile uses after an UNKNOWN
//            create outcome (hub#93 M5).
//
// IDEMPOTENT: a read has no side effect.

/** The NAMED form of gcp-subnet-get: any subnet, by name. */
export interface GcpNamedSubnetRef {
  /** The agency's GCP project id the subnet lives in. */
  project: string;
  /** The Compute Engine region of the subnet, e.g. "australia-southeast2". */
  region: string;
  /** The subnetwork's resource name to read back. */
  subnetName: string;
}

/** gcp-subnet-get takes the named form or the site form. */
export type GcpSubnetGetParams = GcpNamedSubnetRef | GcpSiteSubnetRef;

export function validateGcpSubnetGetParams(raw: unknown): ParamsVerdict<GcpSubnetGetParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  if (asksForSiteSubnetForm(raw)) {
    return validateGcpSiteSubnetRef(raw, "gcp-subnet-get");
  }
  const { project, region, subnetName } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast2)" };
  }
  if (typeof subnetName !== "string" || !GCP_RESOURCE_NAME_RE.test(subnetName)) {
    return { ok: false, reason: `subnetName ${GCP_RESOURCE_NAME_RULE}` };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, subnetName } };
}

// ── gcp-subnet-delete ────────────────────────────────────────────────────────────────
// Delete a Cloud Run subnet. gcp-network-delete deletes exactly ONE named subnet and then the network,
// so a cell that has a Run subnet could not be torn down without this op: Google answers the network
// delete with `resourceInUse` while a second subnet is still attached.
//
// THE NAME IS NEVER FREE-FORM. This op destroys infrastructure, it can run against a LIVE cell, and the
// cell's NODE subnet `dy-cell-<region>-subnet` is one typo away. Deleting that would take a live cell
// off the network. Teardown removes the node subnet through gcp-network-delete, where the order is not
// optional.
//   PROBE form — `subnetName` must be EXACTLY `dy-cell-<region>-run`.
//   SITE form  — `{ project, region, slot, siteSlug }` (+ the optional registry pair). The Worker reads
//            the site's subnet first and refuses unless it is on the named network and its description
//            is EXACTLY `doubleyoup site subnet: <siteSlug>` — this site's, not merely any doubleyoup
//            description (hub#93 §2, §5 H6).
//
// IDEMPOTENT: Google's 404 is "already-absent" (success), the same rule the teardown ops follow.

/** The PROBE form of gcp-subnet-delete. */
export interface GcpProbeSubnetDeleteParams {
  /** The agency's GCP project id the subnet lives in. */
  project: string;
  /** The Compute Engine region of the subnet, e.g. "australia-southeast2". */
  region: string;
  /** EXACTLY `dy-cell-<region>-run`, nothing else. */
  subnetName: string;
}

/** gcp-subnet-delete takes the probe form or the site form. */
export type GcpSubnetDeleteParams = GcpProbeSubnetDeleteParams | GcpSiteSubnetRef;

export function validateGcpSubnetDeleteParams(raw: unknown): ParamsVerdict<GcpSubnetDeleteParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  if (asksForSiteSubnetForm(raw)) {
    return validateGcpSiteSubnetRef(raw, "gcp-subnet-delete");
  }
  const { project, region, subnetName } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast2)" };
  }
  const expectedSubnet = cellRunSubnetNameFor(region);
  if (subnetName !== expectedSubnet) {
    return {
      ok: false,
      reason:
        `subnetName must be exactly "${expectedSubnet}" — gcp-subnet-delete removes a cell's Cloud Run subnet ` +
        "and nothing else (the cell's node subnet is deleted by gcp-network-delete, with the network)",
    };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, subnetName: expectedSubnet } };
}

// ── gcp-subnets-list ─────────────────────────────────────────────────────────────────
// READ-ONLY (hub#93 §2): every subnet in the cell's region whose name starts with the cell's per-site
// subnet prefix — the per-site subnets, orphans included — without 128 reads. The cell teardown uses it
// to find and delete every site subnet BEFORE any VM. Two REQUIRED strings: `project` (pinned to the SA
// key's own project by the actuator) and `region`, plus (planning/49 Phase 3) an OPTIONAL pair
// `network` + `subnetPrefix`, both or neither:
//   neither — the saga's prefix `dy-cell-<region>-run-s`, DERIVED from the region, and no network
//             filter: exactly as before the pair existed.
//   both    — a REGISTRY network and Run subnet prefix (syd: `dy-vpc` + `dy-subnet-run-syd-s`), with the
//             same grammar as the session upsert's names. The actuator lists only subnets ON that
//             network whose names start with that prefix; each entry's slot is parsed under it.
// app binds the pair to the effective names of the account's cell at (project, region) before it signs.
// The actuator reads every page or fails closed: a teardown that relied on a partial list would leave a
// subnet behind and then fail the network delete. An old Worker would drop the pair silently and list
// under the saga prefix, so the result ECHOES the prefix and the network filter it used.
//
// IDEMPOTENT: a read has no side effect.

export interface GcpSubnetsListParams {
  /** The agency's GCP project id the subnets live in. */
  project: string;
  /** The Compute Engine region of the cell, e.g. "australia-southeast2". */
  region: string;
  /** OPTIONAL, only with `subnetPrefix`: the cell's network by registry name. Absent: no network filter. */
  network?: string;
  /** OPTIONAL, only with `network`: the cell's Run subnet name prefix. Absent: `dy-cell-<region>-run-s`. */
  subnetPrefix?: string;
}

/** The name prefix a validated gcp-subnets-list job lists under: its `subnetPrefix`, else the saga's. */
export function subnetsListNamePrefix(params: GcpSubnetsListParams): string {
  if (params.subnetPrefix !== undefined) {
    return params.subnetPrefix;
  }
  return cellSiteRunSubnetNamePrefixFor(params.region);
}

export function validateGcpSubnetsListParams(raw: unknown): ParamsVerdict<GcpSubnetsListParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, network, subnetPrefix } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast2)" };
  }

  // NEITHER: the saga prefix, exactly as before. A FRESH object of only the known keys.
  if (network === undefined && subnetPrefix === undefined) {
    return { ok: true, params: { project, region } };
  }
  if (network === undefined || subnetPrefix === undefined) {
    return { ok: false, reason: "gcp-subnets-list takes network and subnetPrefix together, or neither" };
  }
  if (typeof network !== "string" || !GCP_RESOURCE_NAME_RE.test(network)) {
    return { ok: false, reason: `network ${GCP_RESOURCE_NAME_RULE}` };
  }
  if (typeof subnetPrefix !== "string" || !SITE_RUN_SUBNET_PREFIX_RE.test(subnetPrefix)) {
    return {
      ok: false,
      reason: "subnetPrefix must be a registry Run subnet name prefix: a lowercase letter, then at most 59 of [-a-z0-9]",
    };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, network, subnetPrefix } };
}

// ── gcp-project-quota-get ────────────────────────────────────────────────────────────
// READ-ONLY (hub#93 §1 "Quota", §6): the AGENCY project's live SUBNETWORKS quota — how many subnets the
// project holds now (`usage`) and how many it may hold (`limit`). The per-site Run slot allocator needs
// this LIVE read just before it allocates, because the quota is per PROJECT: every cell's node subnet,
// probe subnet and site subnets, and any subnet the agency made itself, share it. A "two per cell"
// formula would miss the subnets the platform does not know about (hub#93 L5).
//
// ONE REQUIRED string, `project` (pinned to the SA key's own project by the actuator). The metric is
// NOT a parameter: this op reads SUBNETWORKS and nothing else. The actuator reads Compute
// `projects.get` and its `quotas[]` list (the list `gcloud compute project-info describe` prints), and
// fails closed when the SUBNETWORKS entry is missing or repeated, or when its `usage` or `limit` is not
// a whole number of at least 0. A failed read is never "zero subnets in use".
//
// IDEMPOTENT: a read has no side effect.

/** The ONE Compute quota metric gcp-project-quota-get reads. */
export const GCP_PROJECT_QUOTA_METRIC = "SUBNETWORKS";

export interface GcpProjectQuotaGetParams {
  /** The agency's GCP project id whose SUBNETWORKS quota is read. */
  project: string;
}

export function validateGcpProjectQuotaGetParams(raw: unknown): ParamsVerdict<GcpProjectQuotaGetParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }

  // A FRESH object of only the known key — never the caller's object. Any other key (a `metric`, for
  // one) is dropped, not honoured: the metric is fixed.
  return { ok: true, params: { project } };
}

// ── Cloud Run: service names, the premise probe, and the shared grammars ─────────────
// ONE Cloud Run (v2) service in the AGENCY's own project and region, on the cell's own VPC
// (planning/49 §4.3). The upsert carries what the three on-cell `provision-*.sh` recipes set today,
// minus everything that is POLICY rather than configuration.
//
// WHAT IS A PARAM AND WHAT IS NOT, because the split is the security boundary:
//   PARAMS  project / region / serviceName / image / runServiceAccount / network / subnet / cpu /
//           memory / maxInstances / env / secretEnv / nfsVolumes / probe / specLabel.
//   FIXED by the actuator: ingress (INGRESS_TRAFFIC_ALL), VPC egress (PRIVATE_RANGES_ONLY), gen2,
//           the container port (8080), the request timeout (3600s), minInstances (0), the
//           `managed-by` label, invoker IAM ON, and (for a probe) the command and its program. The
//           `dy-spec` label carries `specLabel` and nothing else.
//
// THERE IS NO `allUsers` PATH AND NO `allowUnauthenticated` PARAM. Not defaulted to false: ABSENT.
// planning/49 §1: an agency project in a Workspace organisation with the default
// constraints/iam.allowedPolicyMemberDomains REFUSES an allUsers binding. The design never needs one:
// callers present a Google ID token and Cloud Run's own IAM does the rest. These ops write NO IAM
// policy. The Worker's own service account gets run.invoker on its project once, at onboarding.

/** The host label of each session purpose. The service name IS the label (planning/49 §3.2). */
export const CLOUD_RUN_SESSION_SERVICE_PREFIXES = ["term", "pma", "staging", "sterm", "spma"] as const;
/** The ONE service name the Phase 2 premise probe uses. Not a session name, so it cannot collide. */
export const CLOUD_RUN_PROBE_SERVICE_NAME = "dy-run-probe";
/**
 * The ONE image the premise probe may run (Jason's decision, 2026-10-12: a stock public image with
 * a command override). The Worker supplies the command and the program. The platform supplies only
 * the targets.
 *
 * PINNED BY DIGEST (review M1/L2), so the publisher cannot repoint it. This is the linux/amd64
 * MANIFEST of `python:3.12-slim` (Cloud Run runs linux/amd64), read from Docker Hub's tags API on
 * 2026-10-12. The multi-arch INDEX digest at the same time was
 * sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1. A new digest is a change
 * to both twins and a Worker sync.
 */
export const CLOUD_RUN_PROBE_IMAGE =
  "docker.io/library/python@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe";
/**
 * The ONE public Artifact Registry repo the platform publishes session images to (planning/49 §4.5).
 * A signed job may choose the DIGEST, but not the registry or the image name, so a session can run
 * only an image the platform published. This is the platform's publishing location, the same for every
 * cell and every agency. It is not a cell fact and does not move with any cell, even though syd also
 * lives in that project and region.
 */
export const SESSION_IMAGE_REPO = "australia-southeast1-docker.pkg.dev/doubleyoup/dy-run-public";
/**
 * The image name in SESSION_IMAGE_REPO that each session prefix may run.
 *
 * pma and spma run `dy-run-pma` (planning/49 Phase 4), the platform's image derived from stock
 * phpMyAdmin, never the stock image. The stock image verifies nothing, so anyone holding an ID token
 * for the service would get the site's DB. dy-run-pma verifies the session token itself, and it reads
 * the DB credentials from its read-only `platform/<slug>` mount, so no password travels in env.
 */
export const SESSION_IMAGE_NAMES: Readonly<Record<CloudRunSessionServicePrefix, string>> = {
  term: "dy-run-terminal",
  sterm: "dy-run-terminal",
  pma: "dy-run-pma",
  spma: "dy-run-pma",
  staging: "dy-run-wp",
};
/** The ONLY ports the probe may test: MariaDB on the data node and NFS on the file node. */
export const CLOUD_RUN_PROBE_PORTS = ["2049", "3306"] as const;
const CLOUD_RUN_PROBE_TARGETS_MAX = 8;

// A Cloud Run SERVICE name: a Compute-style name capped at 49 characters (the name becomes a label
// of the generated *.run.app hostname).
const CLOUD_RUN_SERVICE_NAME_RE = /^[a-z]([-a-z0-9]{0,47}[a-z0-9])?$/;
// The part of a session service name after its prefix: the site slug.
const CLOUD_RUN_SESSION_SLUG_RE = /^[a-z0-9][a-z0-9-]*$/;
// A container image reference PINNED BY DIGEST: <host>[:port]/<path>@sha256:<64 hex>. No tag form
// is accepted (review M1/L2): a tag can be repointed by its publisher, a digest cannot. The probe
// image is pinned exactly (CLOUD_RUN_PROBE_IMAGE), and a session image to SESSION_IMAGE_REPO plus the
// image name of its prefix.
const CONTAINER_IMAGE_RE =
  /^[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?(?:\/[a-z0-9][a-z0-9._-]*){1,6}@sha256:[a-f0-9]{64}$/;
const CONTAINER_IMAGE_MAX_LENGTH = 512;
// Cloud Run CPU: whole cores (1/2/4/8) or millicores ("500m" … "8000m"). v2 takes no decimal form.
const RUN_CPU_RE = /^(?:[1248]|[1-9][0-9]{2,3}m)$/;
// Cloud Run memory: a whole number of MiB or GiB, e.g. "512Mi" / "2Gi".
const RUN_MEMORY_RE = /^[1-9][0-9]{0,4}(?:Mi|Gi)$/;
// A session service is a SINGLE container for a SINGLE user. 100 catches a typo. The NFS invariant
// below is far tighter.
const RUN_MAX_INSTANCES_MIN = 1;
const RUN_MAX_INSTANCES_MAX = 100;
// POSIX env-var grammar. Google SETS four variables on every container and rejects a service that
// declares one of them; naming them here beats relaying Google's message.
const RUN_ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const RUN_RESERVED_ENV_NAMES = ["PORT", "K_SERVICE", "K_REVISION", "K_CONFIGURATION"];
// An env VALUE is opaque, so it is bounded rather than charset-checked. An EMPTY value is legitimate.
const RUN_ENV_VALUE_MAX_LENGTH = 32 * 1024;
const RUN_ENV_MAX = 64;
const RUN_SECRET_ENV_MAX = 32;
// A Secret Manager secret's short name, and a version: "latest" or a positive integer.
const SECRET_MANAGER_NAME_RE = /^[a-zA-Z0-9_-]{1,255}$/;
const SECRET_MANAGER_VERSION_RE = /^(?:latest|[1-9][0-9]{0,18})$/;
// A session service mounts its own site's tree, plus at most a few helpers.
const RUN_NFS_VOLUMES_MAX = 8;
// An absolute POSIX path of [A-Za-z0-9._-] segments. Anchored, so no NUL, newline, space, quote,
// backslash or empty segment can appear. "." and ".." segments are refused separately.
const POSIX_ABSOLUTE_PATH_RE = /^(?:\/[A-Za-z0-9._-]+)+$/;
const POSIX_PATH_MAX_LENGTH = 512;
// A PRIVATE (RFC 1918) IPv4 LITERAL. A hostname cannot match a dotted quad, which is the point: a
// Direct-VPC-egress service does not join the project's internal DNS, so a hostname never resolves.
// A PUBLIC address is refused for a different reason: it would reach across the internet.
const PRIVATE_IPV4_ADDRESS_RE = new RegExp(
  `^(?:10(?:\\.${IPV4_OCTET}){3}` +
    `|172\\.(?:1[6-9]|2[0-9]|3[01])(?:\\.${IPV4_OCTET}){2}` +
    `|192\\.168(?:\\.${IPV4_OCTET}){2})$`,
);

/** True when `name` is a session service name: `<prefix>-<slug>`, prefix from the fixed list. */
function isCloudRunSessionServiceName(name: string): boolean {
  if (!CLOUD_RUN_SERVICE_NAME_RE.test(name)) {
    return false;
  }
  for (const prefix of CLOUD_RUN_SESSION_SERVICE_PREFIXES) {
    const head = `${prefix}-`;
    if (name.startsWith(head) && CLOUD_RUN_SESSION_SLUG_RE.test(name.slice(head.length))) {
      return true;
    }
  }
  return false;
}

/**
 * The reason a Cloud Run service name is not allowed for an op, or null when it is. `allowed` says
 * which names the op may touch: session services, the probe service, or either.
 */
function cloudRunServiceNameReason(serviceName: unknown, allowed: "session" | "probe" | "either"): string | null {
  if (typeof serviceName !== "string") {
    return "serviceName must be a string";
  }
  const isProbe = serviceName === CLOUD_RUN_PROBE_SERVICE_NAME;
  const isSession = isCloudRunSessionServiceName(serviceName);
  const sessionRule = `one of ${CLOUD_RUN_SESSION_SERVICE_PREFIXES.map((prefix) => `${prefix}-<slug>`).join(", ")} (at most 49 characters)`;
  if (allowed === "probe" && !isProbe) {
    return `serviceName must be exactly "${CLOUD_RUN_PROBE_SERVICE_NAME}" for this op`;
  }
  if (allowed === "session" && !isSession) {
    return `serviceName must be a session service name: ${sessionRule}`;
  }
  if (allowed === "either" && !isProbe && !isSession) {
    return `serviceName must be a session service name (${sessionRule}) or "${CLOUD_RUN_PROBE_SERVICE_NAME}"`;
  }
  return null;
}

/** One session purpose's host label prefix, e.g. "term" for `term-<slug>`. */
type CloudRunSessionServicePrefix = (typeof CLOUD_RUN_SESSION_SERVICE_PREFIXES)[number];

/**
 * Split a session service name into its prefix and site slug ("sterm-docs-892769" -> sterm,
 * docs-892769), or null when the name is not `<prefix>-<slug>` with a slug in the site grammar. No two
 * prefixes overlap once the hyphen is included ("term-" is not a prefix of "sterm-"), so at most one
 * prefix can match.
 */
export function splitCloudRunSessionServiceName(
  serviceName: string,
): { prefix: CloudRunSessionServicePrefix; slug: string } | null {
  if (!isCloudRunSessionServiceName(serviceName)) {
    return null;
  }
  for (const prefix of CLOUD_RUN_SESSION_SERVICE_PREFIXES) {
    const head = `${prefix}-`;
    if (!serviceName.startsWith(head)) {
      continue;
    }
    const slug = serviceName.slice(head.length);
    if (!isSiteSlug(slug)) {
      return null;
    }
    return { prefix, slug };
  }
  return null;
}

/**
 * The EXACT NFS export paths a session service may mount (hub#93 §2, §3), per purpose. They are the
 * paths the session recipes mount today (infra cell-run/provision-terminal.sh, provision-staging.sh,
 * provision-staging-terminal.sh), all under the same slug as the service:
 *   term    sites/<slug>, platform/<slug>
 *   staging sites/<slug>, platform/<slug>-staging
 *   sterm   sites/<slug>/staging, platform/<slug>-staging
 *   pma     platform/<slug>          (planning/49 Phase 4: the image reads the DB credentials here)
 *   spma    platform/<slug>-staging
 * EXACT paths, not a prefix test: a prefix test on `sites/<slug>` would also admit `sites/<slug>-x`,
 * which is ANOTHER site's tree. And a staging service gets no path to the LIVE `platform/<slug>`, which
 * holds the live DB password. A pma or spma service gets no `sites/` tree: it needs the DB credentials
 * only, never the site's files. Its one volume must also be read-only
 * (SESSION_PREFIXES_WITH_READ_ONLY_NFS).
 */
export function siteSessionNfsPathsFor(prefix: CloudRunSessionServicePrefix, slug: string): string[] {
  const sitesPath = `${SITE_STORAGE_ROOT}/sites/${slug}`;
  const platformPath = `${SITE_STORAGE_ROOT}/platform/${slug}`;
  const stagingPlatformPath = `${SITE_STORAGE_ROOT}/platform/${slug}-staging`;
  if (prefix === "term") {
    return [sitesPath, platformPath];
  }
  if (prefix === "staging") {
    return [sitesPath, stagingPlatformPath];
  }
  if (prefix === "sterm") {
    return [`${sitesPath}/staging`, stagingPlatformPath];
  }
  if (prefix === "pma") {
    return [platformPath];
  }
  if (prefix === "spma") {
    return [stagingPlatformPath];
  }
  return [];
}

/**
 * The session prefixes whose every NFS volume must carry `readOnly: true` (planning/49 Phase 4).
 * phpMyAdmin only READS wp-config-real.php from `platform/<slug>`. That directory holds the live DB
 * password and the platform's config for the site, and phpMyAdmin is a large web app the user drives.
 * A read-only mount means a flaw in it can read that directory but never rewrite it.
 */
export const SESSION_PREFIXES_WITH_READ_ONLY_NFS: readonly CloudRunSessionServicePrefix[] = ["pma", "spma"];

/** True when `value` is an absolute POSIX path that contains no "." or ".." segment. */
function isTraversalFreeAbsolutePath(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > POSIX_PATH_MAX_LENGTH) {
    return false;
  }
  if (!POSIX_ABSOLUTE_PATH_RE.test(value)) {
    return false;
  }
  for (const segment of value.split("/")) {
    if (segment === "." || segment === "..") {
      return false;
    }
  }
  return true;
}

/** A Cloud Run plain environment variable. `value` is opaque (bounded), never a secret. */
export interface CloudRunEnvVar {
  name: string;
  value: string;
}

/** A Cloud Run env var sourced from ONE Secret Manager secret version in the SAME project. */
export interface CloudRunSecretEnvVar {
  name: string;
  /** The Secret Manager secret's short name (not a full resource path). */
  secretName: string;
  /** "latest" or a numeric version. */
  version: string;
}

/** ONE NFS volume the service mounts from a node inside the cell's VPC. */
export interface CloudRunNfsVolume {
  /** The volume's name within the service (a Compute-style resource name). */
  name: string;
  /** The NFS server — a PRIVATE (RFC 1918) IPv4 LITERAL. A hostname never resolves. */
  server: string;
  /** The exported path ON the server, e.g. "/srv/dy-storage/sites/<slug>". */
  path: string;
  /** Where the container sees it, e.g. "/sites/<slug>". */
  mountPath: string;
  /** Mount read-only. Absent => read-write. */
  readOnly?: boolean;
}

/** ONE TCP target the premise probe opens a connection to. */
export interface CloudRunProbeTarget {
  /** A PRIVATE (RFC 1918) IPv4 literal on the cell's VPC. */
  ip: string;
  /** One of CLOUD_RUN_PROBE_PORTS, as a string. */
  port: string;
}

/** The premise probe: which TCP targets to open. The Worker owns the image's command and program. */
export interface CloudRunProbeSpec {
  tcpTargets: CloudRunProbeTarget[];
}

/** Validate the OPTIONAL `env` list into a FRESH array, or return the reason it is invalid. */
function cleanCloudRunEnv(value: unknown): { ok: true; env: CloudRunEnvVar[] | undefined } | { ok: false; reason: string } {
  if (value === undefined) {
    return { ok: true, env: undefined };
  }
  if (!Array.isArray(value) || value.length > RUN_ENV_MAX) {
    return { ok: false, reason: `env, when present, must be an array of 0-${RUN_ENV_MAX} { name, value } entries` };
  }
  const clean: CloudRunEnvVar[] = [];
  const seenNames = new Set<string>();
  for (const entry of value) {
    if (!isPlainObject(entry)) {
      return { ok: false, reason: "each env entry must be an object { name, value }" };
    }
    const { name, value: entryValue } = entry;
    if (typeof name !== "string" || !RUN_ENV_NAME_RE.test(name)) {
      return { ok: false, reason: "each env entry's name must be an environment-variable name (1-128 chars of letters, digits, underscores; not starting with a digit)" };
    }
    if (RUN_RESERVED_ENV_NAMES.includes(name)) {
      return { ok: false, reason: `env must not set "${name}" — Cloud Run sets it on every container (reserved: ${RUN_RESERVED_ENV_NAMES.join(", ")})` };
    }
    if (seenNames.has(name)) {
      return { ok: false, reason: `env names the variable "${name}" more than once` };
    }
    if (typeof entryValue !== "string" || entryValue.length > RUN_ENV_VALUE_MAX_LENGTH) {
      return { ok: false, reason: `each env entry's value must be a string of at most ${RUN_ENV_VALUE_MAX_LENGTH} characters` };
    }
    seenNames.add(name);
    clean.push({ name, value: entryValue });
  }
  return { ok: true, env: clean };
}

/** Validate the OPTIONAL `secretEnv` list into a FRESH array, or return the reason it is invalid. */
function cleanCloudRunSecretEnv(
  value: unknown,
): { ok: true; secretEnv: CloudRunSecretEnvVar[] | undefined } | { ok: false; reason: string } {
  if (value === undefined) {
    return { ok: true, secretEnv: undefined };
  }
  if (!Array.isArray(value) || value.length > RUN_SECRET_ENV_MAX) {
    return { ok: false, reason: `secretEnv, when present, must be an array of 0-${RUN_SECRET_ENV_MAX} { name, secretName, version } entries` };
  }
  const clean: CloudRunSecretEnvVar[] = [];
  const seenNames = new Set<string>();
  for (const entry of value) {
    if (!isPlainObject(entry)) {
      return { ok: false, reason: "each secretEnv entry must be an object { name, secretName, version }" };
    }
    const { name, secretName, version } = entry;
    if (typeof name !== "string" || !RUN_ENV_NAME_RE.test(name)) {
      return { ok: false, reason: "each secretEnv entry's name must be an environment-variable name (1-128 chars of letters, digits, underscores; not starting with a digit)" };
    }
    if (RUN_RESERVED_ENV_NAMES.includes(name)) {
      return { ok: false, reason: `secretEnv must not set "${name}" — Cloud Run sets it on every container (reserved: ${RUN_RESERVED_ENV_NAMES.join(", ")})` };
    }
    if (seenNames.has(name)) {
      return { ok: false, reason: `secretEnv names the variable "${name}" more than once` };
    }
    if (typeof secretName !== "string" || !SECRET_MANAGER_NAME_RE.test(secretName)) {
      return { ok: false, reason: "each secretEnv entry's secretName must be a Secret Manager secret name (1-255 chars of letters, digits, hyphens, underscores)" };
    }
    if (typeof version !== "string" || !SECRET_MANAGER_VERSION_RE.test(version)) {
      return { ok: false, reason: 'each secretEnv entry\'s version must be "latest" or a positive integer' };
    }
    seenNames.add(name);
    clean.push({ name, secretName, version });
  }
  return { ok: true, secretEnv: clean };
}

/**
 * Validate the OPTIONAL `nfsVolumes` list into a FRESH array, or return the reason it is invalid.
 * Two rules are the design's invariants, not shape checks (planning/49 §4.3): `server` MUST be a
 * private IPv4 LITERAL, and a volume name and a mountPath each appear ONCE.
 */
function cleanCloudRunNfsVolumes(
  value: unknown,
): { ok: true; nfsVolumes: CloudRunNfsVolume[] | undefined } | { ok: false; reason: string } {
  if (value === undefined) {
    return { ok: true, nfsVolumes: undefined };
  }
  if (!Array.isArray(value) || value.length < 1 || value.length > RUN_NFS_VOLUMES_MAX) {
    return { ok: false, reason: `nfsVolumes, when present, must be an array of 1-${RUN_NFS_VOLUMES_MAX} { name, server, path, mountPath, readOnly? } entries` };
  }
  const clean: CloudRunNfsVolume[] = [];
  const seenNames = new Set<string>();
  const seenMountPaths = new Set<string>();
  for (const entry of value) {
    if (!isPlainObject(entry)) {
      return { ok: false, reason: "each nfsVolumes entry must be an object { name, server, path, mountPath, readOnly? }" };
    }
    const { name, server, path, mountPath, readOnly } = entry;
    if (typeof name !== "string" || !GCP_RESOURCE_NAME_RE.test(name)) {
      return { ok: false, reason: `each nfsVolumes entry's name ${GCP_RESOURCE_NAME_RULE}` };
    }
    if (seenNames.has(name)) {
      return { ok: false, reason: `nfsVolumes names the volume "${name}" more than once` };
    }
    if (typeof server !== "string" || !PRIVATE_IPV4_ADDRESS_RE.test(server)) {
      return {
        ok: false,
        reason:
          "each nfsVolumes entry's server must be a PRIVATE (RFC 1918) IPv4 literal, e.g. 10.20.0.4 — a hostname does not " +
          "resolve from a Direct-VPC-egress service, and a public address would mount an export over the internet",
      };
    }
    if (!isTraversalFreeAbsolutePath(path)) {
      return { ok: false, reason: `each nfsVolumes entry's path must be an absolute POSIX path of [A-Za-z0-9._-] segments with no "." or ".." segment (at most ${POSIX_PATH_MAX_LENGTH} chars)` };
    }
    if (!isTraversalFreeAbsolutePath(mountPath)) {
      return { ok: false, reason: `each nfsVolumes entry's mountPath must be an absolute POSIX path of [A-Za-z0-9._-] segments with no "." or ".." segment (at most ${POSIX_PATH_MAX_LENGTH} chars)` };
    }
    if (seenMountPaths.has(mountPath)) {
      return { ok: false, reason: `nfsVolumes mounts "${mountPath}" more than once` };
    }
    if (readOnly !== undefined && typeof readOnly !== "boolean") {
      return { ok: false, reason: "each nfsVolumes entry's readOnly, when present, must be a boolean" };
    }
    seenNames.add(name);
    seenMountPaths.add(mountPath);
    const volume: CloudRunNfsVolume = { name, server, path, mountPath };
    if (readOnly !== undefined) {
      volume.readOnly = readOnly;
    }
    clean.push(volume);
  }
  return { ok: true, nfsVolumes: clean };
}

/**
 * Validate the OPTIONAL `probe` spec into a FRESH object, or return the reason it is invalid. Each
 * target is a private IPv4 literal and one of CLOUD_RUN_PROBE_PORTS. No target repeats. The probe
 * reaches nothing else, so it can only answer the premise question (planning/49 §9 Phase 2).
 */
function cleanCloudRunProbe(value: unknown): { ok: true; probe: CloudRunProbeSpec | undefined } | { ok: false; reason: string } {
  if (value === undefined) {
    return { ok: true, probe: undefined };
  }
  if (!isPlainObject(value)) {
    return { ok: false, reason: "probe, when present, must be an object { tcpTargets }" };
  }
  const { tcpTargets } = value;
  if (!Array.isArray(tcpTargets) || tcpTargets.length < 1 || tcpTargets.length > CLOUD_RUN_PROBE_TARGETS_MAX) {
    return { ok: false, reason: `probe.tcpTargets must be an array of 1-${CLOUD_RUN_PROBE_TARGETS_MAX} { ip, port } entries` };
  }
  const allowedPorts: readonly string[] = CLOUD_RUN_PROBE_PORTS;
  const clean: CloudRunProbeTarget[] = [];
  const seenTargets = new Set<string>();
  for (const entry of tcpTargets) {
    if (!isPlainObject(entry)) {
      return { ok: false, reason: "each probe.tcpTargets entry must be an object { ip, port }" };
    }
    const { ip, port } = entry;
    if (typeof ip !== "string" || !PRIVATE_IPV4_ADDRESS_RE.test(ip)) {
      return { ok: false, reason: "each probe target's ip must be a PRIVATE (RFC 1918) IPv4 literal" };
    }
    if (typeof port !== "string" || !allowedPorts.includes(port)) {
      return { ok: false, reason: `each probe target's port must be one of ${CLOUD_RUN_PROBE_PORTS.join(", ")} (as a string)` };
    }
    const key = `${ip}:${port}`;
    if (seenTargets.has(key)) {
      return { ok: false, reason: `probe.tcpTargets names ${key} more than once` };
    }
    seenTargets.add(key);
    clean.push({ ip, port });
  }
  return { ok: true, probe: { tcpTargets: clean } };
}

// ── cloudrun-service-upsert ──────────────────────────────────────────────────────────
// Create or update ONE Cloud Run service. The actuator READS the service first. It CREATES a missing
// one with the `managed-by` label, and it PATCHes an existing one ONLY when that one carries the label,
// is not still reconciling, and its IAM policy holds no allUsers / allAuthenticatedUsers binding
// (review M1, L5). So a same-named service this platform did not create is never taken over.
//
// TWO KINDS OF SERVICE, told apart by `probe`:
//   THE PREMISE PROBE (`probe` set) is the only service that runs a stock public image: exactly
//     CLOUD_RUN_PROBE_IMAGE under exactly CLOUD_RUN_PROBE_SERVICE_NAME, on the probe subnet
//     `dy-cell-<region>-run`, with NO env, secretEnv, nfsVolumes or slot, and maxInstances 1. The
//     Worker sets its command and program itself.
//   A SESSION SERVICE (no `probe`) — `<prefix>-<slug>` — is the hub#93 / planning/49 M4 lift. Until
//     M4 every non-probe upsert was refused, because a signed session service could name any NFS
//     server and path on the agency's VPC. The lift is TWO layers, because this file is PURE:
//       1. HERE (both twins): the NAME grammar. The job carries its site's Run `slot`. `network` is a
//          Compute name, and `subnet` is `<prefix><NNN>` for that slot (isSiteRunSubnetNameForSlot): the
//          saga's `dy-cell-<region>` + `dy-cell-<region>-run-s<NNN>`, or a hand-built cell's registry
//          names (planning/49 Phase 3: syd's `dy-vpc` + `dy-subnet-run-syd-s<NNN>`). Each NFS volume's
//          `server` must be a private literal and its `path` one of the EXACT per-purpose paths for the
//          service's OWN slug (siteSessionNfsPathsFor). A pma or spma volume must be read-only
//          (SESSION_PREFIXES_WITH_READ_ONLY_NFS). `maxInstances` must be exactly 1: one writer per
//          NFS mount, and the per-site /24 is sized for one instance per service (hub#93 G1).
//       2. app ONLY, before it signs (agency-dispatch-site-binding.ts): slug -> Site -> Cell must match
//          the job's project, region and account, the slot must be Site.runSlot, its subnet must be
//          confirmed created, `network` must be the cell's effective network and `subnet` its effective
//          Run subnet prefix + the slot's digits (Cell.network / Cell.runSubnetPrefix, or the saga names
//          for a saga-built cell), each NFS server must be the cell's file node, and a DY_DB_HOST env
//          entry must be the cell's data node. The twin can see that the shapes agree; it cannot know
//          that N is THIS slug's slot, or which names the cell records.
//     A session image is pinned to SESSION_IMAGE_REPO plus the image name of its prefix. The digest
//     is the caller's choice (planning/49 §4.5).
//     OPTIONAL `specLabel` (a session only, never the probe): a GCP label value the Worker writes as the
//     `dy-spec` label, on create and on every patch (a patch without it removes the label). The
//     orchestrator compares it with the spec it would send, so a stale service converges on the next
//     open (planning/49 decision F).
//     The Worker adds a third check at actuation: it reads the subnet and refuses unless it is on the
//     job's network, its description names the same slug and its range is the one derived from the
//     slot (D7).
//
// IDEMPOTENT: a re-dispatch with the same params converges on the same named service.

export interface CloudRunServiceUpsertParams {
  /** The agency's GCP project id the service is created in. */
  project: string;
  /** The Cloud Run region, e.g. "australia-southeast2". */
  region: string;
  /** A session service name (`<prefix>-<slug>`), or the probe name when `probe` is set. */
  serviceName: string;
  /** The container image reference. Exactly CLOUD_RUN_PROBE_IMAGE when `probe` is set, else SESSION_IMAGE_REPO/<name of the prefix>@sha256:<64 hex>. */
  image: string;
  /** EXACTLY `dy-run@<project>.iam.gserviceaccount.com`. */
  runServiceAccount: string;
  /** The probe: EXACTLY `dy-cell-<region>`. A session: a Compute name (the cell's network, bound by app). */
  network: string;
  /** The probe: EXACTLY `dy-cell-<region>-run`. A session: `<prefix><NNN>` for `slot` (the prefix bound by app). */
  subnet: string;
  /** Cloud Run CPU, e.g. "1" or "1000m". */
  cpu: string;
  /** Cloud Run memory, e.g. "2Gi". */
  memory: string;
  /** The instance ceiling. MUST be exactly 1 for a session service and for the probe. */
  maxInstances: number;
  /** A session service only: its site's Run slot (0-127). Never with `probe`. */
  slot?: number;
  /** OPTIONAL plain environment variables. Never with `probe`. */
  env?: CloudRunEnvVar[];
  /** OPTIONAL Secret Manager-sourced environment variables. Never with `probe`. */
  secretEnv?: CloudRunSecretEnvVar[];
  /** OPTIONAL NFS volumes mounted from inside the cell's VPC. Never with `probe`. */
  nfsVolumes?: CloudRunNfsVolume[];
  /** OPTIONAL: makes this the planning/49 Phase 2 premise probe. */
  probe?: CloudRunProbeSpec;
  /** OPTIONAL, a session only: the `dy-spec` label value (a GCP label value, 1-63 of [a-z0-9_-]). */
  specLabel?: string;
}

/** A GCP label VALUE as `specLabel` must be: 1-63 of lowercase letters, digits, underscores and hyphens. */
const CLOUD_RUN_SPEC_LABEL_RE = /^[a-z0-9_-]{1,63}$/;

export function validateCloudRunServiceUpsertParams(raw: unknown): ParamsVerdict<CloudRunServiceUpsertParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, serviceName, image, runServiceAccount, network, subnet, cpu, memory, maxInstances, slot, env, secretEnv, nfsVolumes, probe, specLabel } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast2)" };
  }
  const cleanedProbe = cleanCloudRunProbe(probe);
  if (!cleanedProbe.ok) {
    return { ok: false, reason: cleanedProbe.reason };
  }
  const isProbe = cleanedProbe.probe !== undefined;

  let nameReason: string | null;
  if (isProbe) {
    nameReason = cloudRunServiceNameReason(serviceName, "probe");
  } else {
    nameReason = cloudRunServiceNameReason(serviceName, "session");
  }
  if (nameReason !== null) {
    return { ok: false, reason: nameReason };
  }
  const imageGrammarReason = "image must be a container image reference pinned by digest: <registry>/<path>@sha256:<64 hex>";
  if (typeof image !== "string") {
    return { ok: false, reason: imageGrammarReason };
  }
  if (isProbe) {
    if (image.length > CONTAINER_IMAGE_MAX_LENGTH || !CONTAINER_IMAGE_RE.test(image)) {
      return { ok: false, reason: imageGrammarReason };
    }
    if (image !== CLOUD_RUN_PROBE_IMAGE) {
      return { ok: false, reason: `a probe must run exactly "${CLOUD_RUN_PROBE_IMAGE}"` };
    }
  } else {
    // A session image is pinned to the platform's public repo and to the image name of its prefix.
    // Only the digest is the caller's choice. The pin is an exact match, so it also covers the grammar:
    // a tag, uppercase hex or a trailing newline gets this refusal, which names the pinned repo.
    const sessionImageName = splitCloudRunSessionServiceName(serviceName as string);
    if (sessionImageName === null) {
      return { ok: false, reason: "serviceName must be <prefix>-<slug> with a site slug ([a-z0-9-], alphanumeric at both ends)" };
    }
    const imageName = SESSION_IMAGE_NAMES[sessionImageName.prefix];
    const expectedImagePrefix = `${SESSION_IMAGE_REPO}/${imageName}@sha256:`;
    const imageDigest = image.slice(expectedImagePrefix.length);
    const hasExpectedPrefix = image.startsWith(expectedImagePrefix);
    const hasValidDigest = /^[a-f0-9]{64}$/.test(imageDigest);
    if (!hasExpectedPrefix || !hasValidDigest) {
      return {
        ok: false,
        reason: `a ${sessionImageName.prefix}- session service must run ${SESSION_IMAGE_REPO}/${imageName}@sha256:<64 hex> (the platform's public session image repo, planning/49 §4.5)`,
      };
    }
  }
  const expectedServiceAccount = cellRunServiceAccountFor(project);
  if (runServiceAccount !== expectedServiceAccount) {
    return { ok: false, reason: `runServiceAccount must be exactly "${expectedServiceAccount}" (the cell's runtime identity)` };
  }

  // THE NETWORK AND THE SUBNET. The probe runs on the saga's network and probe subnet, exactly, and
  // carries no slot. A session service runs on its site's OWN subnet for the slot the job carries: a
  // registry prefix + the slot's digits, on a network named by a Compute name. app binds both names to
  // the cell's recorded facts before it signs; here only the shape is checked.
  let cleanNetwork: string;
  let cleanSubnet: string;
  if (isProbe) {
    const expectedNetwork = cellNetworkNameFor(region);
    if (network !== expectedNetwork) {
      return { ok: false, reason: `network must be exactly "${expectedNetwork}" (the cell's own VPC)` };
    }
    if (slot !== undefined) {
      return { ok: false, reason: "a probe must not carry a slot — it runs on the probe subnet, not a site's" };
    }
    const expectedSubnet = cellRunSubnetNameFor(region);
    if (subnet !== expectedSubnet) {
      return { ok: false, reason: `subnet must be exactly "${expectedSubnet}" (the cell's Cloud Run subnet)` };
    }
    cleanNetwork = expectedNetwork;
    cleanSubnet = expectedSubnet;
  } else {
    if (typeof network !== "string" || !GCP_RESOURCE_NAME_RE.test(network)) {
      return { ok: false, reason: `network ${GCP_RESOURCE_NAME_RULE} (the cell's own VPC)` };
    }
    if (!isSiteRunSlot(slot)) {
      return {
        ok: false,
        reason:
          `a session service must carry its site's Run slot: an integer from ${SITE_RUN_SLOT_MIN} to ${SITE_RUN_SLOT_MAX} ` +
          "(it runs on that site's own subnet, never the shared probe subnet)",
      };
    }
    if (!isSiteRunSubnetNameForSlot(subnet, slot)) {
      return { ok: false, reason: `subnet must be the site's own Run subnet for slot ${slot}: ${siteRunSubnetNameRule(slot, region)}` };
    }
    cleanNetwork = network;
    cleanSubnet = subnet;
  }

  if (typeof cpu !== "string" || !RUN_CPU_RE.test(cpu)) {
    return { ok: false, reason: 'cpu must be a Cloud Run CPU value: "1", "2", "4", "8" or a millicore value like "1000m"' };
  }
  if (typeof memory !== "string" || !RUN_MEMORY_RE.test(memory)) {
    return { ok: false, reason: 'memory must be a Cloud Run memory value, e.g. "512Mi" or "2Gi"' };
  }
  if (
    typeof maxInstances !== "number" ||
    !Number.isInteger(maxInstances) ||
    maxInstances < RUN_MAX_INSTANCES_MIN ||
    maxInstances > RUN_MAX_INSTANCES_MAX
  ) {
    return { ok: false, reason: `maxInstances must be an integer in [${RUN_MAX_INSTANCES_MIN}, ${RUN_MAX_INSTANCES_MAX}]` };
  }

  const cleanedEnv = cleanCloudRunEnv(env);
  if (!cleanedEnv.ok) {
    return { ok: false, reason: cleanedEnv.reason };
  }
  const cleanedSecretEnv = cleanCloudRunSecretEnv(secretEnv);
  if (!cleanedSecretEnv.ok) {
    return { ok: false, reason: cleanedSecretEnv.reason };
  }
  const cleanedNfsVolumes = cleanCloudRunNfsVolumes(nfsVolumes);
  if (!cleanedNfsVolumes.ok) {
    return { ok: false, reason: cleanedNfsVolumes.reason };
  }

  if (isProbe) {
    // THE PROBE CARRIES NOTHING BUT ITS TARGETS (Jason's decision, 2026-10-12: refuse nfsVolumes).
    // env and secretEnv are refused too: the Worker sets the probe's one variable itself.
    if (cleanedNfsVolumes.nfsVolumes !== undefined) {
      return { ok: false, reason: "a probe must not mount nfsVolumes — it opens TCP connections and reads no data" };
    }
    if (cleanedEnv.env !== undefined || cleanedSecretEnv.secretEnv !== undefined) {
      return { ok: false, reason: "a probe must not carry env or secretEnv — the Worker sets the probe's environment itself" };
    }
    if (maxInstances !== 1) {
      return { ok: false, reason: `a probe must have maxInstances exactly 1 (got ${maxInstances})` };
    }
    if (specLabel !== undefined) {
      return { ok: false, reason: "a probe must not carry a specLabel — the dy-spec label is for session services" };
    }
  } else {
    if (specLabel !== undefined && (typeof specLabel !== "string" || !CLOUD_RUN_SPEC_LABEL_RE.test(specLabel))) {
      return { ok: false, reason: "specLabel, when present, must be a GCP label value: 1-63 of lowercase letters, digits, underscores and hyphens" };
    }
    // A SESSION SERVICE: ONE instance (hub#93 G1 sizes each site's /24 for one instance per service),
    // and only its OWN site's export paths for its purpose.
    if (maxInstances !== 1) {
      return {
        ok: false,
        reason:
          `a session service must have maxInstances exactly 1 (got ${maxInstances}) — it serves one user, it may be ` +
          "an NFS single writer, and its site's /24 is sized for one instance per service",
      };
    }
    const sessionName = splitCloudRunSessionServiceName(serviceName as string);
    if (sessionName === null) {
      return { ok: false, reason: "serviceName must be <prefix>-<slug> with a site slug ([a-z0-9-], alphanumeric at both ends)" };
    }
    const allowedPaths = siteSessionNfsPathsFor(sessionName.prefix, sessionName.slug);
    for (const volume of cleanedNfsVolumes.nfsVolumes ?? []) {
      if (!allowedPaths.includes(volume.path)) {
        let allowedText = "no NFS volume at all";
        if (allowedPaths.length > 0) {
          allowedText = `only ${allowedPaths.join(" or ")}`;
        }
        return {
          ok: false,
          reason: `a ${sessionName.prefix}- session for "${sessionName.slug}" may mount ${allowedText} — not "${volume.path}"`,
        };
      }
      // An absent readOnly means read-write, so only an explicit `true` passes.
      const mustBeReadOnly = SESSION_PREFIXES_WITH_READ_ONLY_NFS.includes(sessionName.prefix);
      if (mustBeReadOnly && volume.readOnly !== true) {
        return {
          ok: false,
          reason: `a ${sessionName.prefix}- session must mount "${volume.path}" read-only (readOnly: true)`,
        };
      }
    }
  }

  // THE SINGLE-WRITER INVARIANT (planning/49 §4.3), as code rather than a comment. Two instances of
  // one NFS-mounting service would write the same site's files through two independent mounts, with
  // nothing in the stack to lock against. The session rule above already requires exactly 1; this
  // stays as the invariant's own statement, so it holds even if that rule is ever relaxed.
  if (cleanedNfsVolumes.nfsVolumes !== undefined && maxInstances !== 1) {
    return {
      ok: false,
      reason:
        "maxInstances must be exactly 1 when nfsVolumes is present — an NFS-mounting service is a SINGLE writer, " +
        `and there is nothing in the stack for a second instance to lock against (got ${maxInstances})`,
    };
  }

  // A FRESH object of only the known keys — never the caller's object — so no extra key (an
  // `allowUnauthenticated`, an `ingress`, a raw `template`) can ride along under the platform's
  // signature. Every optional field is added ONLY when present, so a probe's params are byte-identical
  // to what they were before the session form existed.
  const params: CloudRunServiceUpsertParams = {
    project,
    region,
    serviceName: serviceName as string,
    image,
    runServiceAccount: expectedServiceAccount,
    network: cleanNetwork,
    subnet: cleanSubnet,
    cpu,
    memory,
    maxInstances,
  };
  if (!isProbe) {
    params.slot = slot as number;
  }
  if (cleanedEnv.env !== undefined) {
    params.env = cleanedEnv.env;
  }
  if (cleanedSecretEnv.secretEnv !== undefined) {
    params.secretEnv = cleanedSecretEnv.secretEnv;
  }
  if (cleanedNfsVolumes.nfsVolumes !== undefined) {
    params.nfsVolumes = cleanedNfsVolumes.nfsVolumes;
  }
  if (cleanedProbe.probe !== undefined) {
    params.probe = cleanedProbe.probe;
  }
  if (typeof specLabel === "string") {
    params.specLabel = specLabel;
  }
  return { ok: true, params };
}

// ── cloudrun-service-get / -delete / cloudrun-probe-invoke ───────────────────────────
// The same three params each: `project` (pinned to the SA key's own project by the actuator),
// `region` and `serviceName`.
//   get    — READ-ONLY: found, uri, urls, ready, and whether it carries the managed-by label. The uri
//            read-back is load-bearing: planning/49 §3.2 derives every session origin from the
//            service NAME, and the caller asserts the derived URL is among the service's urls.
//            planning/49 Phase 3 adds what the service RUNS: its Direct VPC egress network and subnet,
//            its image and its `dy-spec` label, so a caller can tell a current service from a stale one.
//   delete — how a session ENDS. The actuator deletes ONLY a service with the managed-by label
//            (review M1). Google's 404 is "already-absent", so a re-run converges.
// In a GCP project SHARED with a hand-built cell (syd's), app also binds a session name on get and
// delete to a site of the dispatching account before it signs (agency-dispatch-binding.ts): there the
// project pin alone admits every session service in the project.
//   probe-invoke — READ-ONLY in effect: call the PROBE service (that name only) once WITHOUT a token
//            (it must refuse) and once with a Google ID token minted from the agency's own key, and
//            return the probe's TCP results. This is how "invoked with an ID token from the agency's
//            own SA" (planning/49 §9 Phase 2) is possible at all: the platform holds no such key.

export interface CloudRunServiceGetParams {
  project: string;
  region: string;
  serviceName: string;
}

export interface CloudRunServiceDeleteParams {
  project: string;
  region: string;
  serviceName: string;
}

export interface CloudRunProbeInvokeParams {
  project: string;
  region: string;
  /** EXACTLY CLOUD_RUN_PROBE_SERVICE_NAME. */
  serviceName: string;
}

/** The shared validator body for the three {project, region, serviceName} ops. */
function validateCloudRunServiceRef(
  raw: unknown,
  allowedNames: "session" | "probe" | "either",
): ParamsVerdict<{ project: string; region: string; serviceName: string }> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, serviceName } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast2)" };
  }
  const nameReason = cloudRunServiceNameReason(serviceName, allowedNames);
  if (nameReason !== null) {
    return { ok: false, reason: nameReason };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, serviceName: serviceName as string } };
}

export function validateCloudRunServiceGetParams(raw: unknown): ParamsVerdict<CloudRunServiceGetParams> {
  return validateCloudRunServiceRef(raw, "either");
}

export function validateCloudRunServiceDeleteParams(raw: unknown): ParamsVerdict<CloudRunServiceDeleteParams> {
  return validateCloudRunServiceRef(raw, "either");
}

export function validateCloudRunProbeInvokeParams(raw: unknown): ParamsVerdict<CloudRunProbeInvokeParams> {
  return validateCloudRunServiceRef(raw, "probe");
}

// ── workers-route-upsert / workers-route-delete ──────────────────────────────────────
// The Workers route that puts the edge gate in front of ONE session host in the agency's OWN zone
// (planning/49 §3.2, §8; hub#93 §2: the agency site delete removes it after its service is gone). Four
// REQUIRED strings each:
//   1. `zone`    — the agency zone NAME (the actuator resolves it to a zone id with the agency's own token).
//   2. `host`    — EXACTLY `<session service name>.<zone>`: a session prefix + the site slug as ONE label,
//                  then the zone. The route pattern is DERIVED, `<host>/*`, so it is always an exact host.
//   3. `project` — the cell's GCP project. PINNED by the actuator to its service-account key's OWN
//                  project, so a job can only name the cell this Worker serves.
//   4. `region`  — the cell's Compute region.
// THE SHARP EDGE (planning/49 §8): `*.<zone>/*` would route every site in the zone through the gate.
// So no wildcard, no bare zone, no extra label, and no host that is not
// {term,pma,staging,sterm,spma}-<slug>.<zone> can be signed. The script is not a parameter either: it is
// DERIVED, `dy-gate-<project>-<region>` (edgeGateScriptNameFor), so each cell has its own edge gate (one
// session key per cell, planning/49 Phase 3) and a job can never point a route at another script. The
// actuator never takes over a route that points elsewhere. A region has exactly one hyphen
// (GCP_REGION_RE), so two (project, region) pairs never derive the same name. A derived name longer than
// EDGE_GATE_SCRIPT_NAME_MAX_LENGTH is refused: 63 is the longest Worker name that still fits one DNS label
// (`<name>.<subdomain>.workers.dev`).
// app also checks, before signing (agency-dispatch-site-binding.ts), that the zone is the slug's own
// cell's Cell.cfZone, that the project and region are that cell's, and that the cell belongs to the
// dispatching account; the twin holds no DB.
//
// IDEMPOTENT: upsert creates an absent route and leaves a correct one alone; delete treats an absent
// route as "already-absent".

/** The longest edge-gate script name: one DNS label, so the script can also have a workers.dev route. */
export const EDGE_GATE_SCRIPT_NAME_MAX_LENGTH = 63;

/** The ONE Worker script a cell's session routes may point at: `dy-gate-<project>-<region>`. */
export function edgeGateScriptNameFor(project: string, region: string): string {
  return `dy-gate-${project}-${region}`;
}

/**
 * The reason the edge-gate script name derived from (project, region) cannot be used, or null when it
 * fits EDGE_GATE_SCRIPT_NAME_MAX_LENGTH. The route ops and edge-gate-deploy share this one rule.
 */
function edgeGateScriptNameReason(project: string, region: string): string | null {
  const script = edgeGateScriptNameFor(project, region);
  if (script.length <= EDGE_GATE_SCRIPT_NAME_MAX_LENGTH) {
    return null;
  }
  return (
    `the derived edge-gate script name "${script}" is ${script.length} characters — a Worker name must be at most ` +
    `${EDGE_GATE_SCRIPT_NAME_MAX_LENGTH} (one DNS label)`
  );
}

/**
 * True when `value` is a Compute REGION name (e.g. australia-southeast1), in the grammar every region
 * param here uses. Exported for the agency Worker's session-gate minter, which checks the region label
 * of a Cloud Run URL with it.
 */
export function isGcpRegionName(value: unknown): value is string {
  return typeof value === "string" && value.length <= GCP_RESOURCE_NAME_MAX_LENGTH && GCP_REGION_RE.test(value);
}

export interface WorkersRouteParams {
  /** The agency's Cloudflare zone NAME, e.g. "sbmstudio.com.au". */
  zone: string;
  /** EXACTLY `<prefix>-<slug>.<zone>`. */
  host: string;
  /** The cell's GCP project (pinned by the actuator to its key's own project). */
  project: string;
  /** The cell's Compute region. */
  region: string;
}

export type WorkersRouteUpsertParams = WorkersRouteParams;
export type WorkersRouteDeleteParams = WorkersRouteParams;

/** The Workers route pattern for a validated session host: `<host>/*`. */
export function workersRoutePatternFor(host: string): string {
  return `${host}/*`;
}

/** The shared validator body for the two route ops. */
function validateWorkersRouteParams(raw: unknown): ParamsVerdict<WorkersRouteParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { zone, host, project, region } = raw;

  if (typeof zone !== "string" || zone.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a lowercase DNS zone name (e.g. example.com)" };
  }
  const hostRule = `host must be exactly <session service name>.${zone}, e.g. term-<slug>.${zone} (one label before the zone, no wildcard)`;
  if (typeof host !== "string" || host.length > DNS_NAME_MAX_LENGTH || !host.endsWith(`.${zone}`)) {
    return { ok: false, reason: hostRule };
  }
  const label = host.slice(0, host.length - zone.length - 1);
  if (label.includes(".") || splitCloudRunSessionServiceName(label) === null) {
    return { ok: false, reason: hostRule };
  }
  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (typeof region !== "string" || region.length > GCP_RESOURCE_NAME_MAX_LENGTH || !GCP_REGION_RE.test(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast2)" };
  }
  const scriptReason = edgeGateScriptNameReason(project, region);
  if (scriptReason !== null) {
    return { ok: false, reason: scriptReason };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { zone, host, project, region } };
}

export function validateWorkersRouteUpsertParams(raw: unknown): ParamsVerdict<WorkersRouteUpsertParams> {
  return validateWorkersRouteParams(raw);
}

export function validateWorkersRouteDeleteParams(raw: unknown): ParamsVerdict<WorkersRouteDeleteParams> {
  return validateWorkersRouteParams(raw);
}

// ── edge-gate-deploy ─────────────────────────────────────────────────────────────────
// planning/49 §5.1, Phase 3 (I4): deploy the cell's SESSION EDGE GATE. The agency Worker uploads ITS OWN
// embedded gate script (src/session-gate/gate.js in that repo); no script bytes travel from the platform.
// The script is the DERIVED `dy-gate-<project>-<region>` (edgeGateScriptNameFor), the same script the
// route ops point at. Five REQUIRED params:
//   1. `project`       — the cell's GCP project. PINNED by the actuator to its service-account key's own
//                        project. With the project's NUMBER it gives the Cloud Run URL suffix
//                        `-<projectNumber>.<region>.run.app` that the gate forwards to.
//   2. `region`        — the cell's Compute region.
//   3. `zone`          — the cell's Cloudflare zone NAME (Cell.cfZone). The gate answers only on
//                        `<session service name>.<zone>`, and the script goes into the Cloudflare account
//                        that holds this zone (a Workers route can run only a script of its zone's account).
//   4. `sessionSecret` — the cell's session secret, EXACTLY 64 lowercase hex (planning/49 §5.2, step 2 of
//                        the key chain). The gate holds it as a secret_text binding, its only copy.
//                        A LIVE KEY: no refusal here names the value, only the rule, and no result,
//                        error text or log on either side may contain it.
//   5. `keyVersion`    — the cell's EFFECTIVE Cell.sessionKeyVersion, an integer from 1 to 9999. The gate
//                        carries it as a plain binding, so a re-deploy can tell a rotated key apart.
// The derived script name must fit EDGE_GATE_SCRIPT_NAME_MAX_LENGTH, as for the route ops.
// app binds project, region, zone and keyVersion to ONE cell of the dispatching account before it signs
// (agency-dispatch-binding.ts). Neither side can check the secret itself: only the orchestrator holds the
// master key the secret is derived from.
//
// IDEMPOTENT: the actuator leaves a gate whose version and bindings already match unchanged, and
// otherwise uploads the same script with the same bindings, so a re-run converges.

/** The highest per-cell session key version (Cell.sessionKeyVersion, planning/49 Phase 3). */
export const SESSION_KEY_VERSION_MAX = 9999;
// The cell's session secret: the 64-hex text of 32 HKDF bytes (orchestrator session-token.ts).
const SESSION_SECRET_RE = /^[0-9a-f]{64}$/;

export interface EdgeGateDeployParams {
  /** The cell's GCP project (pinned by the actuator to its key's own project). */
  project: string;
  /** The cell's Compute region. */
  region: string;
  /** The cell's Cloudflare zone NAME, e.g. "sbmstudio.com.au". */
  zone: string;
  /** The cell's session secret, 64 lowercase hex. A LIVE KEY: never log, store or echo it. */
  sessionSecret: string;
  /** The cell's effective session key version, 1-9999. */
  keyVersion: number;
}

export function validateEdgeGateDeployParams(raw: unknown): ParamsVerdict<EdgeGateDeployParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const { project, region, zone, sessionSecret, keyVersion } = raw;

  if (typeof project !== "string" || !GCP_PROJECT_ID_RE.test(project)) {
    return { ok: false, reason: GCP_PROJECT_ID_RULE };
  }
  if (!isGcpRegionName(region)) {
    return { ok: false, reason: "region must be a Compute Engine region name (e.g. australia-southeast2)" };
  }
  if (typeof zone !== "string" || zone.length > DNS_NAME_MAX_LENGTH || !DNS_ZONE_RE.test(zone)) {
    return { ok: false, reason: "zone must be a lowercase DNS zone name (e.g. example.com)" };
  }
  // The rule only, NEVER the value: this reason reaches the caller (app's 400, the Worker's 400 body).
  if (typeof sessionSecret !== "string" || !SESSION_SECRET_RE.test(sessionSecret)) {
    return { ok: false, reason: "sessionSecret must be exactly 64 lowercase hex characters (the cell's session secret)" };
  }
  if (
    typeof keyVersion !== "number" ||
    !Number.isSafeInteger(keyVersion) ||
    keyVersion < 1 ||
    keyVersion > SESSION_KEY_VERSION_MAX
  ) {
    return { ok: false, reason: `keyVersion must be an integer from 1 to ${SESSION_KEY_VERSION_MAX}` };
  }
  const scriptReason = edgeGateScriptNameReason(project, region);
  if (scriptReason !== null) {
    return { ok: false, reason: scriptReason };
  }

  // A FRESH object of only the known keys — never the caller's object.
  return { ok: true, params: { project, region, zone, sessionSecret, keyVersion } };
}

// ── shared ─────────────────────────────────────────────────────────────────────────

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
