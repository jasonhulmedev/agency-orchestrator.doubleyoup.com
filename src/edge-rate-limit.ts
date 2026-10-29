// The Worker's OWN builder for the two RATE-LIMIT rules of the `waf-edge-sync` op (hub#44 phase 2,
// specs/edge-security-via-worker.md, Amendment A7). PURE: no fetch, no Node APIs. The actuator
// (actuate.ts::reconcileEdgeRateLimit) reads the zone's http_ratelimit phase and does the writes.
//
// WHAT THE OP OWNS in the zone's http_ratelimit phase, matched by EXACT description:
//   doubleyoup-ratelimit-origin     every request the common exclusions leave
//   doubleyoup-ratelimit-expensive  the requests that are costly for WordPress to answer: the REST API
//                                   (/wp-json/ and ?rest_route=), admin-ajax.php, a search (?s=) and
//                                   WooCommerce AJAX (?wc-ajax=)
// Both count per IP (and per Cloudflare data center, which Cloudflare always adds) and BLOCK an IP
// that goes over its threshold for `mitigationSeconds`. Every other rule in the phase is FOREIGN: it
// counts against the phase's own rule budget and is never written.
//
// COMMON EXCLUSIONS (neither rule counts these requests): the zone's infrastructure hosts
// (`excludedHosts`), the per-site media hosts (`*-media.<zone>`), verified bots, a request carrying a
// `wordpress_logged_in_` cookie, and static files (by path extension).
//
// WHAT EACH PLAN ALLOWS — Cloudflare's docs, checked 2026-10-29
// (https://developers.cloudflare.com/waf/rate-limiting-rules/#availability):
//   rules per zone       Free 1, Pro 2, Business 5, Enterprise 100
//   expression fields    Free: Path, Verified Bot
//                        Pro: Host, URI, Path, Full URI, Query, Verified Bot
//                        Business: Pro's + Method, Source IP, User Agent
//                        Enterprise: general request fields, request header fields, Verified Bot, ...
//   counting             IP only below Business; no custom counting expression below Business
//   cache exclusion      Business and up only, so `requests_to_origin` is always false here: a request
//                        served from the edge cache COUNTS, on every plan (one meaning everywhere)
//   counting period      Pro up to 60 s, Business up to 600 s, Enterprise up to 65,535 s
//   mitigation timeout   Pro up to 1 h, Business and Enterprise up to 1 day
// A clause whose field the zone's plan does not allow is LEFT OUT — never replaced by a wider or a
// narrower test — and named in `omittedClauses`. On Pro and Business that is exactly one clause: the
// logged-in cookie (Cookie is not in their field lists), so a logged-in editor's requests count too.
//
// FIELD CHOICES, kept to the fields the availability table names for the plan:
//   - verified bots: `cf.client.bot`. The table links "Verified Bot" to cf.bot_management.verified_bot,
//     but that field's own page says it needs Enterprise with Bot Management, while the table offers
//     Verified Bot on Free. cf.client.bot is the all-plans field that "provides the same information".
//   - static files: `ends_with(http.request.uri.path, ".css")` per extension — the Path field only.
//     The table does not name http.request.uri.path.extension, so this module does not rely on it.
//     ends_with is case-sensitive: an upper-case extension is COUNTED, never exempted (fails safe).
//   - query arguments: the raw query string (Query), `starts_with(query, "s=") or query contains
//     "&s="`. The table does not name the decoded argument-map fields. A percent-encoded argument name
//     is not matched by the expensive rule; the origin rule still counts that request.
//
// CANONICAL TEXT. Hosts are sorted and de-duplicated, so a re-ordered host list renders the same rule
// and a re-run writes nothing.

/** The stable identities of our two rate-limit rules. */
export const RATE_LIMIT_ORIGIN_DESCRIPTION = "doubleyoup-ratelimit-origin";
export const RATE_LIMIT_EXPENSIVE_DESCRIPTION = "doubleyoup-ratelimit-expensive";
export const RATE_LIMIT_DESCRIPTIONS: readonly string[] = [RATE_LIMIT_ORIGIN_DESCRIPTION, RATE_LIMIT_EXPENSIVE_DESCRIPTION];

/** The Cloudflare phase that holds rate-limit rules. */
export const RATE_LIMIT_PHASE = "http_ratelimit";

/** Counting periods the job may ask for (Amendment A7). Every paid plan allows both. */
export const RATE_LIMIT_PERIOD_SECONDS: readonly number[] = [10, 60];

/**
 * Mitigation timeouts the job may ask for. Cloudflare's two pages disagree: the parameters page lists
 * 0, 10, 60, 120, 300, 600, 3600, 86400; the availability footnote lists a longer set (10, 15, 20, ...).
 * This is the set BOTH pages list, minus 0 (0 means "throttle", which needs Enterprise with Block).
 * Each plan then allows only the values up to its maximum (RATE_LIMIT_PLAN_LIMITS).
 */
export const RATE_LIMIT_MITIGATION_SECONDS: readonly number[] = [10, 60, 120, 300, 600, 3600, 86400];

/**
 * The largest `requests` value the job may carry. Cloudflare documents a minimum of 1 and no maximum;
 * this bound is the Worker's own sanity limit, not a Cloudflare one.
 */
export const RATE_LIMIT_REQUESTS_MAX = 1_000_000;

/**
 * Static-file extensions neither rule counts: exactly the cell nginx's static set (Amendment A10),
 * the same list as the custom rules' `all` exemption (edge-waf-sync.ts). nginx sends every other
 * path to PHP, so those requests must count.
 */
export const RATE_LIMIT_STATIC_EXTENSIONS: readonly string[] = ["css", "js", "jpg", "jpeg", "gif", "png", "webp", "svg", "woff", "woff2"];

/** Cloudflare's rule-expression field groups this module uses (labels as in the availability table). */
export type RateLimitField = "host" | "path" | "query" | "verifiedBot" | "cookie";

interface RateLimitPlanLimits {
  rules: number;
  maxPeriodSeconds: number;
  maxMitigationSeconds: number;
  fields: readonly RateLimitField[];
}

/** Per-plan limits, keyed by Cloudflare's plan `legacy_id`. See the header for the source. */
const RATE_LIMIT_PLAN_LIMITS: Readonly<Record<string, RateLimitPlanLimits>> = {
  free: { rules: 1, maxPeriodSeconds: 10, maxMitigationSeconds: 10, fields: ["path", "verifiedBot"] },
  pro: { rules: 2, maxPeriodSeconds: 60, maxMitigationSeconds: 3600, fields: ["host", "path", "query", "verifiedBot"] },
  business: { rules: 5, maxPeriodSeconds: 600, maxMitigationSeconds: 86400, fields: ["host", "path", "query", "verifiedBot"] },
  enterprise: {
    rules: 100,
    maxPeriodSeconds: 65535,
    maxMitigationSeconds: 86400,
    fields: ["host", "path", "query", "verifiedBot", "cookie"],
  },
};

/** The rate-limit rule budget of a plan. Unknown => Free's, so a guess can only refuse. */
export function rateLimitRuleCapForPlan(planLegacyId: string | null): number {
  const free = RATE_LIMIT_PLAN_LIMITS.free as RateLimitPlanLimits;
  if (planLegacyId === null) {
    return free.rules;
  }
  const limits = RATE_LIMIT_PLAN_LIMITS[planLegacyId];
  if (limits === undefined) {
    return free.rules;
  }
  return limits.rules;
}

/** One threshold, as the job carries it. */
export interface RateLimitThreshold {
  requests: number;
  periodSeconds: number;
  mitigationSeconds: number;
}

/** The rule body Cloudflare's ruleset API takes for a rate-limit rule. */
export interface RateLimitRule {
  description: string;
  expression: string;
  action: "block";
  ratelimit: {
    characteristics: string[];
    period: number;
    requests_per_period: number;
    mitigation_timeout: number;
    requests_to_origin: boolean;
  };
  enabled: boolean;
}

export interface RateLimitRuleInput {
  /** The agency zone NAME; it lands in the media-host suffix clause. */
  zone: string;
  planLegacyId: string | null;
  excludedHosts: readonly string[];
  enabled: boolean;
  origin: RateLimitThreshold;
  expensive: RateLimitThreshold;
}

export type RateLimitRulesVerdict =
  | { ok: true; origin: RateLimitRule; expensive: RateLimitRule; omittedClauses: string[] }
  | { ok: false; reason: string };

/** One named clause and the field group it needs. */
interface RateLimitClause {
  name: string;
  field: RateLimitField;
  text: string;
}

/** Cloudflare's limit on one rule expression. */
const RATE_LIMIT_EXPRESSION_MAX_LENGTH = 4096;

/** `{"a" "b"}`, sorted and de-duplicated. Hosts are validated DNS names, so no value needs escaping. */
function quotedSortedSet(values: readonly string[]): string {
  const sorted = [...new Set(values)].sort();
  return `{${sorted.map((value) => `"${value}"`).join(" ")}}`;
}

/** True when the raw query string carries the argument `name` (first, or after an `&`). */
function queryArgumentTest(name: string): string {
  return `(starts_with(http.request.uri.query, "${name}=") or http.request.uri.query contains "&${name}=")`;
}

/** The exclusions both rules share, in a fixed order. */
function commonExclusionClauses(zone: string, excludedHosts: readonly string[]): RateLimitClause[] {
  const staticTests = RATE_LIMIT_STATIC_EXTENSIONS.map((extension) => `ends_with(http.request.uri.path, ".${extension}")`);
  return [
    // The host exclusions compare the Host header as sent (Cloudflare does not lowercase it). That
    // fails closed: a mixed-case Host is not excluded, so its requests are counted.
    { name: "excludedHosts", field: "host", text: `http.host in ${quotedSortedSet(excludedHosts)}` },
    // The leading "-" keeps the zone apex and a host such as media.<zone> out of the suffix (as in
    // the front-end geo rule, edge-waf-rule.ts).
    { name: "mediaHosts", field: "host", text: `ends_with(http.host, "-media.${zone}")` },
    { name: "verifiedBots", field: "verifiedBot", text: "cf.client.bot" },
    { name: "loggedInCookie", field: "cookie", text: 'http.cookie contains "wordpress_logged_in_"' },
    { name: "staticFiles", field: "path", text: staticTests.join(" or ") },
  ];
}

/** What makes a request "expensive", in a fixed order. */
function expensiveInclusionClauses(): RateLimitClause[] {
  return [
    { name: "wpJsonPath", field: "path", text: 'starts_with(http.request.uri.path, "/wp-json/")' },
    { name: "adminAjaxPath", field: "path", text: 'http.request.uri.path eq "/wp-admin/admin-ajax.php"' },
    { name: "searchQueryArg", field: "query", text: queryArgumentTest("s") },
    { name: "restRouteQueryArg", field: "query", text: queryArgumentTest("rest_route") },
    { name: "wcAjaxQueryArg", field: "query", text: queryArgumentTest("wc-ajax") },
  ];
}

/** Each exclusion as `not (<clause>)`, joined with " and ". */
function exclusionText(clauses: readonly RateLimitClause[]): string {
  return clauses.map((clause) => `not (${clause.text})`).join(" and ");
}

function rateLimitRule(description: string, expression: string, threshold: RateLimitThreshold, enabled: boolean): RateLimitRule {
  return {
    description,
    expression,
    action: "block",
    ratelimit: {
      // cf.colo.id is mandatory (Cloudflare adds it anyway; every documented API example lists it).
      characteristics: ["cf.colo.id", "ip.src"],
      period: threshold.periodSeconds,
      requests_per_period: threshold.requests,
      mitigation_timeout: threshold.mitigationSeconds,
      requests_to_origin: false,
    },
    enabled,
  };
}

/** Why a threshold does not suit the plan, or null when it does. */
function thresholdPlanReason(label: string, threshold: RateLimitThreshold, plan: string, limits: RateLimitPlanLimits): string | null {
  if (threshold.periodSeconds > limits.maxPeriodSeconds) {
    return `${label}.periodSeconds ${threshold.periodSeconds} is over the ${limits.maxPeriodSeconds} s plan "${plan}" allows`;
  }
  if (threshold.mitigationSeconds > limits.maxMitigationSeconds) {
    return `${label}.mitigationSeconds ${threshold.mitigationSeconds} is over the ${limits.maxMitigationSeconds} s plan "${plan}" allows`;
  }
  return null;
}

/**
 * Build both rule bodies for the zone's plan. A clause the plan does not allow is left out and named
 * in `omittedClauses`. Refuses (never throws) an unknown plan, a threshold over the plan's limits or
 * an over-long expression.
 */
export function buildRateLimitRules(input: RateLimitRuleInput): RateLimitRulesVerdict {
  if (input.planLegacyId === null) {
    return { ok: false, reason: "the zone's plan is unknown, so its rate-limit limits are unknown" };
  }
  const limits = RATE_LIMIT_PLAN_LIMITS[input.planLegacyId];
  if (limits === undefined) {
    return { ok: false, reason: `plan "${input.planLegacyId}" is unknown, so its rate-limit limits are unknown` };
  }
  if (input.excludedHosts.length === 0) {
    return { ok: false, reason: "excludedHosts is empty (Cloudflare rejects an empty set)" };
  }
  const originReason = thresholdPlanReason("origin", input.origin, input.planLegacyId, limits);
  if (originReason !== null) {
    return { ok: false, reason: originReason };
  }
  const expensiveReason = thresholdPlanReason("expensive", input.expensive, input.planLegacyId, limits);
  if (expensiveReason !== null) {
    return { ok: false, reason: expensiveReason };
  }

  const omittedClauses: string[] = [];
  const allowed = (clause: RateLimitClause): boolean => {
    if (limits.fields.includes(clause.field)) {
      return true;
    }
    omittedClauses.push(clause.name);
    return false;
  };
  // Path is on every plan, so the static-file exclusion and the two path inclusions always remain:
  // neither expression can come out empty, and the expensive rule never widens to every request.
  const exclusions = commonExclusionClauses(input.zone, input.excludedHosts).filter(allowed);
  const inclusions = expensiveInclusionClauses().filter(allowed);
  const originExpression = exclusionText(exclusions);
  const inclusionText = inclusions.map((clause) => clause.text).join(" or ");
  const expensiveExpression = `(${inclusionText}) and ${exclusionText(exclusions)}`;

  const origin = rateLimitRule(RATE_LIMIT_ORIGIN_DESCRIPTION, originExpression, input.origin, input.enabled);
  const expensive = rateLimitRule(RATE_LIMIT_EXPENSIVE_DESCRIPTION, expensiveExpression, input.expensive, input.enabled);
  for (const rule of [origin, expensive]) {
    if (rule.expression.length > RATE_LIMIT_EXPRESSION_MAX_LENGTH) {
      return {
        ok: false,
        reason: `rule "${rule.description}" would be ${rule.expression.length} characters, over Cloudflare's ${RATE_LIMIT_EXPRESSION_MAX_LENGTH}-character limit — shorten excludedHosts`,
      };
    }
  }
  return { ok: true, origin, expensive, omittedClauses };
}

/** The parts of an existing rate-limit rule the drift check reads. */
export interface ExistingRateLimitRule {
  description?: string;
  expression?: string;
  action?: string;
  action_parameters?: unknown;
  enabled?: boolean;
  ratelimit?: unknown;
}

function isEmptyObjectOrAbsent(value: unknown): boolean {
  if (value === undefined || value === null) {
    return true;
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  return Object.keys(value).length === 0;
}

function sameStringSet(left: unknown, right: readonly string[]): boolean {
  if (!Array.isArray(left)) {
    return false;
  }
  const leftSorted = [...left].map(String).sort();
  const rightSorted = [...right].sort();
  if (leftSorted.length !== rightSorted.length) {
    return false;
  }
  return leftSorted.every((value, index) => value === rightSorted[index]);
}

/**
 * True when the live rule differs from the desired one in anything we own. Cloudflare's own extra
 * fields (`id`, `version`, `ref`, ...) are never compared. A custom response or a counting expression
 * someone added to OUR rule is drift: the next write replaces the rule with our definition.
 */
export function rateLimitRuleDrifted(existing: ExistingRateLimitRule, desired: RateLimitRule): boolean {
  if (existing.description !== desired.description) {
    return true;
  }
  if (existing.action !== desired.action) {
    return true;
  }
  if (existing.expression !== desired.expression) {
    return true;
  }
  if (existing.enabled !== desired.enabled) {
    return true;
  }
  if (!isEmptyObjectOrAbsent(existing.action_parameters)) {
    return true;
  }
  if (typeof existing.ratelimit !== "object" || existing.ratelimit === null) {
    return true;
  }
  const live = existing.ratelimit as Record<string, unknown>;
  const wanted = desired.ratelimit;
  if (!sameStringSet(live.characteristics, wanted.characteristics)) {
    return true;
  }
  if (live.period !== wanted.period) {
    return true;
  }
  if (live.requests_per_period !== wanted.requests_per_period) {
    return true;
  }
  if (live.mitigation_timeout !== wanted.mitigation_timeout) {
    return true;
  }
  const liveRequestsToOrigin = live.requests_to_origin === true;
  if (liveRequestsToOrigin !== wanted.requests_to_origin) {
    return true;
  }
  if (typeof live.counting_expression === "string" && live.counting_expression.length > 0) {
    return true;
  }
  return false;
}
