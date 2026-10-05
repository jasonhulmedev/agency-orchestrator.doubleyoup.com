// The "edge page cache" Cache Rules — the Worker's OWN builder for the `cache-rule-upsert` op.
//
// The platform never sends this Worker an expression or action_parameters: it sends only a host
// suffix, a TTL and an on/off switch (dispatch-params.ts::validateCacheRuleUpsertParams), and THIS
// module turns them into the full rules. That keeps the platform's authority narrow (Direction-B,
// fail-closed): the most a signed job can do is switch a fixed, WordPress-safe pair of page-cache
// rules on or off for the zone's WordPress sites — its `*-production.<zone>` routing hosts and the
// customer domains onboarded onto the zone as Cloudflare-for-SaaS custom hostnames (see
// "WHICH HOSTS" below). The host set is derived HERE from the suffix; the job cannot widen it.
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
// ── WHICH HOSTS (edgeCacheHostClause) ──────────────────────────────────────────────────
//
// A customer domain (`bsodigital.com.au`) is onboarded as a Cloudflare-for-SaaS CUSTOM HOSTNAME on
// the agency's zone, NOT as a DNS record in it. For a non-O2O custom hostname Cloudflare applies the
// SaaS PROVIDER's zone settings to the traffic, so a Cache Rule on THIS zone is what governs
// customer-domain traffic — one rule covers every custom hostname the zone will ever carry, with no
// per-domain re-apply. (Under O2O the customer's own zone settings win instead, so our rule simply
// does not take effect there: no cache, no risk.) The host clause is therefore a two-arm OR:
//
//   ends_with(http.host, "-production.<zone>")        <- the internal routing hosts, and
//   or ( not http.host contains ".<zone>"             <- a FOREIGN domain: a custom hostname
//        and http.host ne "<zone>"                    <- ...but not the zone apex
//        and not starts_with(http.host, "media.") )   <- ...and not a branded media host
//
// WHY "NOT IN THIS ZONE" IS A SAFE STAND-IN FOR "IS A CUSTOM HOSTNAME". Only two kinds of hostname
// ever reach a zone's rulesets: a (proxied) DNS record IN the zone, and a custom hostname ON the
// zone. The first arm's exclusions remove the first kind, so what is left is the second kind — the
// customer domains the platform onboarded. A stranger cannot register a custom hostname on the
// agency's zone, and a bare CNAME to its fallback origin without one is refused by Cloudflare
// (error 1014) before any ruleset runs.
//
// THE THREE EXCLUSIONS, each load-bearing:
//   - `not http.host contains ".<zone>"` removes every in-zone host — the agency's own tooling and,
//     importantly, its CF-for-SaaS fallback-origin and cell-origin hosts. Deliberately `contains`
//     and not `ends_with`: a decorated form of an in-zone host (a trailing-dot FQDN) still contains
//     ".<zone>" and so still fails CLOSED, where `ends_with` would let it through. The cost is that
//     a foreign domain embedding ".<zone>" as a substring is never cached; the failure direction is
//     "not cached", not "wrongly cached".
//   - `http.host ne "<zone>"` is the APEX TRAP: `example.com` does not contain ".example.com", so
//     without this clause the zone apex — the AGENCY's own marketing site, which the platform may
//     not even host — would start being cached.
//   - `not starts_with(http.host, "media.")` keeps BRANDED MEDIA hosts out. `media.<domain>` is an
//     exact platform convention, and those hosts are served by the media Worker out of R2 — a
//     different origin that never signs up to this rule's Cache-Control contract. There is nothing
//     to win: media objects carry real file extensions, so the extension clause already skips them.
//
// WHAT STOPS A MISTAKE HERE FROM CACHING SOMETHING PERSONAL: `bypass_by_default` + the origin. Even
// if some host did slip past these exclusions, Cloudflare stores NOTHING unless that host's origin
// answered with a cacheable Cache-Control. The host clause is scoping; the origin is the guarantee.
//
// CASE: Cloudflare does NOT lowercase `http.host` (its docs recommend `lower(http.host)` for
// case-insensitive matching), and every clause here is case-sensitive. A mixed-case Host on an
// in-zone host would therefore escape the exclusions. `lower()` is not used because it is unproven
// in this phase on these zones and a rejected expression blocks the whole apply; the origin veto
// above bounds the consequence to "a public page gets cached", not "a personal page gets cached".
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
// `/wc-api` is WooCommerce's payment-gateway callback endpoint: a cached answer there is a
// correctness bug, not just a personalization one. (`/wp-json/wc` is covered by `/wp-json`.)
//
// DECIDED — deliberately NOT added, although WP Engine's default exclusions have them (so nobody
// "completes" the parity later):
//   - page names `store` / `check-out`: a shop archive at /store is high-traffic and exactly what we
//     want cached; a real cart-holder is already caught by the cookie bypass. Keeping these
//     cacheable is a deliberate improvement over WP Engine, not an oversight.
//   - `/coupon`, `/products-compare`: plugin-specific paths, not core WooCommerce; a speculative
//     path costs hit rate for no proven benefit.
// The better long-term play for Woo personalization is WP Engine's own recommended pattern: render
// the variants into the cached HTML and let client-side JS pick one from the cookie, so the page
// stays cacheable instead of bypassed. That is a per-site theme change, not something this layer
// can do.
const EDGE_CACHE_EXCLUDED_PATH_PREFIXES = [
  "/wp-admin",
  "/wp-login.php",
  "/wp-json",
  "/xmlrpc.php",
  "/wp-cron.php",
  "/cart",
  "/checkout",
  "/my-account",
  "/wc-api",
];

// Query fragments that mark a preview or a cart action: never cache them.
const EDGE_CACHE_EXCLUDED_QUERY_FRAGMENTS = ["preview=", "add-to-cart", "wc-ajax"];

// ── MARKETING QUERY PARAMETERS (utm_*, gclid, fbclid) — INVESTIGATED 2026-10-05, NOT SHIPPED ──
//
// THE PROBLEM, and it is the big one. Cloudflare's default cache key is the FULL URL including the
// query string, so `/post/` reached from twelve ad creatives is twelve cache objects, each of which
// has to be filled from PHP once. WP Engine does not strip these either — their Edge Full Page
// Cache caches each unique query string as its own object — which is a large part of why a real
// 30-day report for one of their sites shows 233,676 MISSes against 1.9M hits. Normalising these
// params OUT OF THE CACHE KEY turns most of that column into hits. It is the biggest honest win
// available, and it is NOT taken here. What was checked, against Cloudflare's current docs:
//
//   1. Cache Rules -> Cache Key -> Query String (include/exclude named params).
//      THE CLEAN FIX, and ENTERPRISE ONLY. developers.cloudflare.com/cache/how-to/cache-keys/
//      publishes a per-plan table whose "Query string" row reads Free: No, Pro: No, Business: No,
//      Enterprise: Yes. It is the only mechanism that changes the CACHE KEY while leaving the
//      ORIGIN request untouched. An agency zone on anything below Enterprise is out.
//
//   2. A Transform Rule (URL rewrite) stripping the params before the cache lookup.
//      EXPRESSIBLE ON PRO, but unproven and not free of consequences.
//      - Transform Rules are available on every plan (Free 10, Pro 25 active rules). Regular
//        expressions are Business+, both for the `matches` operator and for `regex_replace()`, so
//        the usual regex recipe is out below Business. BUT `remove_query_args(
//        http.request.uri.query, "utm_source", ...)` is a plain function, not a regex, and the
//        match side needs only `contains` — so the whole rule IS writable on Pro.
//      - URL rewrites run in `http_request_transform`, ahead of Cache Rules
//        (`http_request_cache_settings`) and ahead of the cache lookup. COULD NOT VERIFY from
//        Cloudflare's own documentation that the cache key is then built from the REWRITTEN URL;
//        their URL-rewrite page says nothing about caching. Every third-party guide asserts it,
//        and the execution order makes it very likely, but it is the load-bearing fact and it
//        needs one live proof (two requests differing only in `utm_source`, same `cf-cache-status`
//        object) on a throwaway host before it goes anywhere near customer traffic.
//      - THE TRAP: a URL rewrite strips the params from what the ORIGIN sees as well. On Pro there
//        is no way to decouple those — decoupling is exactly the Enterprise cache-key feature
//        above. Client-side analytics are unaffected (a rewrite never changes the browser's URL,
//        so GA/GTM still read them from window.location), but anything reading them SERVER-side
//        stops seeing them: Gravity Forms dynamic population from a query string, any plugin that
//        stamps a UTM onto an order or a form submission, some affiliate plugins. That is a
//        per-site question, not a platform-wide one, so a zone-wide rule is the wrong shape for it.
//        It is also exactly the kind of judgement an agency must make for its own zone, which is a
//        second reason this Worker does not grow an op for it.
//
//   3. nginx. It cannot do this. nginx is the ORIGIN here; the cache key is built at the Cloudflare
//      edge before the request is ever sent to us, so nothing nginx emits can collapse two cache
//      entries into one. Honest answer: not at this layer.
//
//   4. Cache Rules -> Cache Key -> "Sort query string" (`cache_key.ignore_query_strings_order`).
//      Available on ALL plans, and DELIBERATELY NOT TAKEN. It only merges URLs that differ in
//      param ORDER, and ad platforms emit a fixed order, so the real gain is near zero — while it
//      would merge `?a=1&a=2` with `?a=2&a=1`, which PHP resolves to DIFFERENT values of $_GET['a'].
//      A near-zero win is not worth any chance of serving one page's HTML for another's URL.
//
// So: the real fix needs an Enterprise zone, or a proven-then-opt-in Transform Rule per zone whose
// origin-visibility cost each site has accepted. Neither belongs in this builder today.

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
//
// DECIDED 2026-10-05 — `woocommerce_items_in_cart` is deliberately NOT here any more, so that an
// EMPTY cart keeps its cache. WP Engine value-matches `woocommerce_items_in_cart=[1-9]+`: a visitor
// whose cart is empty still gets cached pages. Cloudflare's `contains` cannot look at a cookie's
// value, and the `matches` operator that could needs a Business plan (the platform zone is Pro), so
// the choice at the edge is "bypass every value, including 0" or "do not look at this cookie at
// all". Neither edge rule needs to look at it:
//   - SERVING: WooCommerce writes `woocommerce_items_in_cart` and `woocommerce_cart_hash` in the
//     SAME call (WC_Cart_Session::set_cart_cookies) and clears both in the same call, so a visitor
//     who has anything in their cart always carries the cart hash too — which is still in this
//     list. Dropping the counter costs the bypass rule nothing.
//   - STORING: the origin makes the precise decision. The cell's nginx map value-matches
//     `(^|;\s*)woocommerce_items_in_cart=[1-9]` and the `doubleyoup-edge-cache` mu-plugin applies
//     the same test in PHP, so a real cart is still never marked public.
// Keeping it here would have meant the edge bypassed an empty-cart visitor the origin was happy to
// serve from cache — i.e. the WP Engine behaviour we are trying to beat.
const EDGE_CACHE_PERSONAL_COOKIE_FRAGMENTS = [
  "wordpress_logged_in_",
  "wp-postpass_",
  "comment_author_",
  "wp_woocommerce_session_",
  "woocommerce_cart_hash",
  // WP Engine parity for WooCommerce: both are Woo-only, so a non-Woo site never carries them and
  // loses no cache hits. `store_notice` is Woo's dismissed-store-notice cookie (`store_notice<id>`).
  "woocommerce_recently_viewed",
  "store_notice",
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

/**
 * The host clause both rules share: an internal `<slug>-production.<zone>` routing host, OR a
 * foreign domain on the zone (a Cloudflare-for-SaaS custom hostname = a customer domain), with the
 * zone apex and the branded media hosts carved back out. See "WHICH HOSTS" in the header for why
 * each exclusion is there and why `contains` rather than `ends_with`.
 *
 * Both `hostSuffix` and `zone` must already be validated (they land inside quoted Rules-language
 * strings).
 */
function edgeCacheHostClause(hostSuffix: string, zone: string): string {
  const internalProductionHost = `ends_with(http.host, "${hostSuffix}")`;
  const notInThisZone = `not http.host contains ".${zone}"`;
  const notTheZoneApex = `http.host ne "${zone}"`;
  const notABrandedMediaHost = 'not starts_with(http.host, "media.")';
  const customHostname = `(${notInThisZone} and ${notTheZoneApex} and ${notABrandedMediaHost})`;
  return `(${internalProductionHost} or ${customHostname})`;
}

/** The clauses both rules share: an HTML-ish page (no extension, .php, .html) on one of our hosts. */
function edgeCachePageOnHostClauses(hostSuffix: string, zone: string): string[] {
  return [edgeCacheHostClause(hostSuffix, zone), '(http.request.uri.path.extension in {"" "php" "html"})'];
}

/** The CACHE rule's expression. `hostSuffix` / `zone` must already be validated (safe to quote). */
function edgeCacheExpression(hostSuffix: string, zone: string): string {
  const clauses: string[] = ['(http.request.method in {"GET" "HEAD"})', ...edgeCachePageOnHostClauses(hostSuffix, zone)];
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
function edgeCacheBypassExpression(hostSuffix: string, zone: string): string {
  const cookieClauses = EDGE_CACHE_PERSONAL_COOKIE_FRAGMENTS.map((fragment) => `http.cookie contains "${fragment}"`);
  return [...edgeCachePageOnHostClauses(hostSuffix, zone), `(${cookieClauses.join(" or ")})`].join(" and ");
}

/** Build both rule bodies from the three narrow inputs. */
export function buildEdgeCacheRules(input: EdgeCacheRuleInput): EdgeCacheRulesVerdict {
  // The suffix is embedded inside a quoted Rules-language string, so it must pass the strict
  // "-production.<zone>" grammar first (only [a-z0-9_.-] can reach the expression). The validated
  // ZONE is kept, not discarded: the host clause needs it for the custom-hostname arm, and it
  // carries exactly the same guarantee as the suffix.
  const zone = edgeCacheZoneFromHostSuffix(input.hostSuffix);
  if (zone === null) {
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
      expression: edgeCacheBypassExpression(input.hostSuffix, zone),
      action: "set_cache_settings",
      // Bypass: never serve this request from the cache, never store its response.
      action_parameters: { cache: false },
      enabled,
    },
    cache: {
      description: EDGE_CACHE_RULE_DESCRIPTION,
      expression: edgeCacheExpression(input.hostSuffix, zone),
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
