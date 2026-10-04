// The "edge page cache" Cache Rules — the Worker's OWN builder for the `cache-rule-upsert` op.
//
// The platform never sends this Worker an expression or action_parameters: it sends only a host
// suffix, a TTL and an on/off switch (dispatch-params.ts::validateCacheRuleUpsertParams), and THIS
// module turns them into the full rules. That keeps the platform's authority narrow (Direction-B,
// fail-closed): the most a signed job can do is switch a fixed, WordPress-safe pair of page-cache
// rules on or off for `*-production.<zone>` hosts.
//
// ── TWIN of the orchestrator's src/edge-cache-rule.ts ──────────────────────────────────
// The orchestrator applies the SAME rules to the platform zone (doubleyoup.com). Keep both
// expressions and both action_parameters byte-identical across the two copies, or platform sites
// and agency sites cache different paths.
//
// RESPECT-ORIGIN, NOT FORCE-CACHE. The cache rule's edge_ttl mode is `bypass_by_default`: Cloudflare
// caches a response ONLY when the origin sends a cacheable Cache-Control (`public, s-maxage=N`),
// and skips the cache entirely when the origin sends none. The origin side is the platform's
// per-site nginx edge-cache snippet on the cell (with the `doubleyoup-edge-cache` mu-plugin as the
// WordPress-state backstop): it marks a genuinely anonymous 200 HTML page `public` and everything
// else `private, no-store`, and never marks a response carrying a Set-Cookie as public. Only the
// origin knows the real login/session/cart state and the real slugs. (`respect_origin` was
// deliberately NOT chosen: with no Cache-Control from the origin it caches for Cloudflare's
// DEFAULT edge TTL — a force-cache of every header-less response.)
//
// WHY TWO RULES — storing vs SERVING. Excluding cookie-bearing requests from the cache rule only
// stops THEIR responses from being stored; Cloudflare's default cache key ignores cookies, so a
// shopper with a cart cookie (or a logged-in admin, or a returning commenter) requesting a URL an
// anonymous visitor already got stored would be SERVED that anonymous copy. The BYPASS rule closes
// that: a personal-cookie request for an HTML page on the host is `cache: false` (neither served
// from nor stored to the cache). The two expressions are MUTUALLY EXCLUSIVE on the cookie clause,
// so exactly one rule ever matches a request and their order in the ruleset does not matter.
//
// The cache rule's path/query/cookie exclusions are DEFENSE IN DEPTH for STORING only; serving an
// already-stored copy is the bypass rule's job (above). The browser TTL follows the origin.
//
// `edgeTtlSeconds` still arrives in the signed op (validated 60..3600) for wire compatibility, but
// it no longer lands in a rule: the edge TTL is the origin's s-maxage.
//
// PURE: no fetch, no Node APIs — unit-tested in test/dispatch.test.ts.

import {
  EDGE_CACHE_TTL_MAX_SECONDS,
  EDGE_CACHE_TTL_MIN_SECONDS,
  edgeCacheZoneFromHostSuffix,
} from "./dispatch-params.js";

/** The stable identity of our CACHE rule — the upsert finds it by this description on every run. */
export const EDGE_CACHE_RULE_DESCRIPTION = "doubleyoup: edge page cache";

/** The stable identity of our BYPASS rule (personal-cookie requests are never served a shared copy). */
export const EDGE_CACHE_BYPASS_RULE_DESCRIPTION = "doubleyoup: edge page cache (bypass personal cookies)";

/** The descriptions of OUR rules — anything else in the cache-settings phase is somebody else's. */
export const EDGE_CACHE_RULE_DESCRIPTIONS: readonly string[] = [EDGE_CACHE_BYPASS_RULE_DESCRIPTION, EDGE_CACHE_RULE_DESCRIPTION];

/** The Cloudflare ruleset phase that holds Cache Rules. */
export const EDGE_CACHE_PHASE = "http_request_cache_settings";

// Paths that are per-user or state-changing in WordPress / WooCommerce: never cache them.
const EDGE_CACHE_EXCLUDED_PATH_PREFIXES = [
  "/wp-admin",
  "/wp-login.php",
  "/wp-json",
  "/xmlrpc.php",
  "/wp-cron.php",
  "/cart",
  "/checkout",
  "/my-account",
];

// Query fragments that mark a preview or a cart action: never cache them.
const EDGE_CACHE_EXCLUDED_QUERY_FRAGMENTS = ["preview=", "add-to-cart", "wc-ajax"];

// Cookies that mark a visitor whose pages are personal (logged in, unlocked a password post, left
// a comment, or has a WooCommerce cart/session). The cache rule REFUSES these requests (never store
// for them) and the bypass rule CLAIMS them (never serve them a stored copy) — the same list on both
// sides is what makes the two rules mutually exclusive. Keep it NARROW: only cookies that mark
// server-rendered personalized state. (Cloudflare's `contains` is case-sensitive: exact case.)
//
// DECIDED — PHPSESSID is deliberately NOT a bypass cookie (WP Engine ignores it too). It carries a
// unique per-visitor ID, so bypassing on it would hand ZERO cache to every session-carrying visitor.
// It is safe to leave out because the STORE side already refuses the leak: the response that starts
// a PHP session carries a Set-Cookie, so the origin marks it `private, no-store` and nothing is stored.
// `wordpress_sec_` is also absent: a logged-in visitor always carries `wordpress_logged_in_` too.
const EDGE_CACHE_PERSONAL_COOKIE_FRAGMENTS = [
  "wordpress_logged_in_",
  "wp-postpass_",
  "comment_author_",
  "woocommerce_items_in_cart",
  "wp_woocommerce_session_",
  "woocommerce_cart_hash",
];

/** The rule body Cloudflare's ruleset API takes (POST/PATCH of one rule). */
export interface EdgeCacheRule {
  description: string;
  expression: string;
  action: "set_cache_settings";
  action_parameters: Record<string, unknown>;
  enabled: boolean;
}

/** Both rules for one zone. Apply `bypass` first so a fresh ruleset lists it first (cosmetic — see header). */
export interface EdgeCacheRuleSet {
  bypass: EdgeCacheRule;
  cache: EdgeCacheRule;
}

export interface EdgeCacheRuleInput {
  /** "-production." + the zone, e.g. "-production.example.com". */
  hostSuffix: string;
  edgeTtlSeconds: number;
  /** Absent => true. false keeps BOTH rules but disables them. */
  enabled?: boolean;
}

/**
 * A verdict, not a throw: actuators in this Worker never throw (they answer ok:false), so a bad
 * input comes back as a reason. The validator has already rejected bad input before actuation, so
 * the ok:false branch is defense in depth.
 */
export type EdgeCacheRulesVerdict = { ok: true; rules: EdgeCacheRuleSet } | { ok: false; reason: string };

/**
 * Clamp an edge TTL to the allowed range (whole seconds). Returns null for a non-finite value,
 * which has no meaningful clamp.
 */
export function clampEdgeCacheTtl(seconds: number): number | null {
  if (!Number.isFinite(seconds)) {
    return null;
  }
  const wholeSeconds = Math.round(seconds);
  if (wholeSeconds < EDGE_CACHE_TTL_MIN_SECONDS) {
    return EDGE_CACHE_TTL_MIN_SECONDS;
  }
  if (wholeSeconds > EDGE_CACHE_TTL_MAX_SECONDS) {
    return EDGE_CACHE_TTL_MAX_SECONDS;
  }
  return wholeSeconds;
}

/** The clauses both rules share: an HTML-ish page (no extension, .php, .html) on a production host. */
function edgeCachePageOnHostClauses(hostSuffix: string): string[] {
  return [`ends_with(http.host, "${hostSuffix}")`, '(http.request.uri.path.extension in {"" "php" "html"})'];
}

/** The CACHE rule's expression. `hostSuffix` must already be validated (safe to quote). */
function edgeCacheExpression(hostSuffix: string): string {
  const clauses: string[] = ['(http.request.method in {"GET" "HEAD"})', ...edgeCachePageOnHostClauses(hostSuffix)];
  for (const pathPrefix of EDGE_CACHE_EXCLUDED_PATH_PREFIXES) {
    clauses.push(`not starts_with(http.request.uri.path, "${pathPrefix}")`);
  }
  for (const queryFragment of EDGE_CACHE_EXCLUDED_QUERY_FRAGMENTS) {
    clauses.push(`not http.request.uri.query contains "${queryFragment}"`);
  }
  for (const cookieFragment of EDGE_CACHE_PERSONAL_COOKIE_FRAGMENTS) {
    clauses.push(`not http.cookie contains "${cookieFragment}"`);
  }
  return clauses.join(" and ");
}

/**
 * The BYPASS rule's expression: an HTML-ish page on the host requested WITH a personal cookie. No
 * method clause (Cloudflare only ever serves GET/HEAD from cache; bypassing the rest is a no-op) and
 * no path/query clauses (a bypass can never be too wide). The extension clause matters: without it a
 * logged-in admin's CSS/JS/images would also bypass the cache, which would be a real slowdown.
 */
function edgeCacheBypassExpression(hostSuffix: string): string {
  const cookieClauses = EDGE_CACHE_PERSONAL_COOKIE_FRAGMENTS.map((fragment) => `http.cookie contains "${fragment}"`);
  return [...edgeCachePageOnHostClauses(hostSuffix), `(${cookieClauses.join(" or ")})`].join(" and ");
}

/** Build both rule bodies from the three narrow inputs. */
export function buildEdgeCacheRules(input: EdgeCacheRuleInput): EdgeCacheRulesVerdict {
  // The suffix is embedded inside a quoted Rules-language string, so it must pass the strict
  // "-production.<zone>" grammar first (only [a-z0-9_.-] can reach the expression).
  if (edgeCacheZoneFromHostSuffix(input.hostSuffix) === null) {
    return { ok: false, reason: `hostSuffix "${input.hostSuffix}" is not "-production." + a lowercase zone name` };
  }
  // The clamp still runs so a non-finite TTL is refused the same way on both twins, even though the
  // value no longer appears in a rule — the origin owns the TTL.
  const edgeTtlSeconds = clampEdgeCacheTtl(input.edgeTtlSeconds);
  if (edgeTtlSeconds === null) {
    return { ok: false, reason: "edgeTtlSeconds must be a finite number" };
  }
  let enabled = true;
  if (input.enabled === false) {
    enabled = false;
  }

  const rules: EdgeCacheRuleSet = {
    bypass: {
      description: EDGE_CACHE_BYPASS_RULE_DESCRIPTION,
      expression: edgeCacheBypassExpression(input.hostSuffix),
      action: "set_cache_settings",
      // Bypass: never serve this request from the cache, never store its response.
      action_parameters: { cache: false },
      enabled,
    },
    cache: {
      description: EDGE_CACHE_RULE_DESCRIPTION,
      expression: edgeCacheExpression(input.hostSuffix),
      action: "set_cache_settings",
      action_parameters: {
        // Eligible for cache — but `bypass_by_default` means Cloudflare stores a response ONLY when
        // the origin's Cache-Control says so, and stores nothing when the origin sends none. No
        // `default` TTL and no status_code_ttl: both belong to override mode; the origin marks
        // every non-200 response `private, no-store` instead.
        cache: true,
        edge_ttl: { mode: "bypass_by_default" },
        browser_ttl: { mode: "respect_origin" },
      },
      enabled,
    },
  };
  return { ok: true, rules };
}

/** The two rules in apply order (bypass first). */
export function edgeCacheRulesInOrder(rules: EdgeCacheRuleSet): EdgeCacheRule[] {
  return [rules.bypass, rules.cache];
}

/**
 * Deep equality for JSON values. Object key ORDER is ignored (Cloudflare may return keys in a
 * different order than we sent them); array order matters.
 */
export function jsonValuesEqual(left: unknown, right: unknown): boolean {
  if (left === right) {
    return true;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right)) {
      return false;
    }
    if (left.length !== right.length) {
      return false;
    }
    for (let index = 0; index < left.length; index += 1) {
      if (!jsonValuesEqual(left[index], right[index])) {
        return false;
      }
    }
    return true;
  }
  const leftIsObject = typeof left === "object" && left !== null;
  const rightIsObject = typeof right === "object" && right !== null;
  if (!leftIsObject || !rightIsObject) {
    return false;
  }
  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const leftKeys = Object.keys(leftRecord);
  const rightKeys = Object.keys(rightRecord);
  if (leftKeys.length !== rightKeys.length) {
    return false;
  }
  for (const key of leftKeys) {
    if (!Object.prototype.hasOwnProperty.call(rightRecord, key)) {
      return false;
    }
    if (!jsonValuesEqual(leftRecord[key], rightRecord[key])) {
      return false;
    }
  }
  return true;
}

/** The parts of an existing Cloudflare rule the drift check reads. */
export interface ExistingRulesetRule {
  action?: string;
  expression?: string;
  action_parameters?: unknown;
  enabled?: boolean;
}

/**
 * True when the live rule differs from the desired one in anything we own: action, expression,
 * action_parameters or enabled. A match means the upsert does nothing.
 */
export function edgeCacheRuleDrifted(existing: ExistingRulesetRule, desired: EdgeCacheRule): boolean {
  if (existing.action !== desired.action) {
    return true;
  }
  if (existing.expression !== desired.expression) {
    return true;
  }
  if (existing.enabled !== desired.enabled) {
    return true;
  }
  return !jsonValuesEqual(existing.action_parameters, desired.action_parameters);
}
