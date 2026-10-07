// The EDGE-DEFENSE baseline — the Worker's OWN builder for the `waf-rule-upsert` op: five WAF custom
// rules plus the Cloudflare Managed Ruleset.
//
// The platform never sends this Worker an expression, an action, a path or a country list. It sends a
// zone name, an on/off switch, two lists of HOSTS inside that zone and a switch for the Managed
// Ruleset (dispatch-params.ts::validateWafRuleUpsertParams). THIS module turns them into the rules
// from its own templates and constants. The country lists stay CONSTANTS on purpose: a signed country
// list could block AU or allow only KP and take every site on the agency's zone offline. A host list
// cannot do that — the worst a bad one does is exempt an in-zone host from the front-end challenge.
//
// WHAT THE FIVE RULES DO, in APPLY order:
//   1. doubleyoup-country-block  BLOCK traffic from a small set of high-abuse countries (RU/CN/KP).
//   2. doubleyoup-wpadmin-geo    BLOCK the WordPress admin/login surface (/wp-admin + /wp-login.php)
//                                for everyone outside the allow-list (AU/US/GB/NZ/FR/IE).
//   3. doubleyoup-login-gate     MANAGED-CHALLENGE what is left of the login surface, so brute force
//                                dies at the edge: /wp-login.php unconditionally, and /wp-admin/
//                                except admin-ajax.php and an already-logged-in session.
//   4. doubleyoup-frontend-geo   MANAGED-CHALLENGE everything else from outside the allow-list, except
//                                verified search-engine crawlers, the zone's infrastructure hosts
//                                (`excludedHosts`) and its per-site media hosts (`*-media.<zone>`).
//   5. the agent skip            SKIP the Managed Ruleset for EVERY request to the cell-agent hosts
//                                (`agentHosts`). They serve no WordPress: each is a bearer-authenticated
//                                machine API whose request bodies carry shell commands and presigned
//                                URLs, and the Managed Ruleset blocks those bodies (measured on syd: a
//                                db-export 403'd at the edge until a skip existed). The live syd rule
//                                skipped /exec only; every path is skipped now (review H1, 2026-10-07),
//                                because the agents' other endpoints carry the same kind of body. It is
//                                NOT a protection, so `enabled:false` (the rollback) leaves it ON.
// Plus, ONLY when the job asks for it (`includeManagedRuleset`, off by default in the script), the
// Cloudflare Managed Ruleset in http_request_firewall_managed. The actuator touches only the execute
// rule THIS op created, and only AFTER rule 5 is in force (the same 403 would otherwise hit the agents
// in between).
//
// ORDER IS THE POLICY. Cloudflare evaluates a ruleset top-down and the first terminating action wins,
// so the rules are applied STRICTEST FIRST (country block -> admin geo -> login gate -> front end):
//   - a request from a blocked country to /wp-login.php is BLOCKED, not challenged;
//   - a request from a non-allow-listed country to /wp-admin is BLOCKED, not challenged;
//   - a request from an allow-listed country to /wp-login.php is CHALLENGED.
// The order only decides where a NEW rule lands. A rule that already exists is PATCHed where it is, so
// a zone whose rules were created in another order (syd's: login gate first) keeps that order.
//
// NO PER-SITE HOST CLAUSE — deliberate, and the whole point. A WAF custom rule is evaluated per ZONE
// across ALL of that zone's traffic, which is what makes it cover a site served on its own customer
// domain (a Cloudflare-for-SaaS custom hostname on this zone). The host lists only EXEMPT the zone's
// own infrastructure. The blast radius is the whole zone, including the agency's own site.
//
// THE LIVE syd RULES. doubleyoup.com carries these five rules today (applied with the orchestrator's
// own token). The descriptions here are IDENTICAL, so this op finds them and PATCHes them in place.
// For syd-equivalent hosts the rendered text is byte-identical to the live rules EXCEPT three
// deliberate changes, so the first run against syd updates exactly three rules' text:
//   - wp-admin geo: `starts_with` + the admin-ajax.php exemption (the 2026-10-04 fix, see below);
//   - front-end geo: one clause APPENDED, `and not ends_with(http.host, "-media.<zone>")` (the media
//     hosts, Jason 2026-10-07). The live text is an exact prefix of the new text;
//   - the agent skip: `(http.host eq "cell-syd.doubleyoup.com" and starts_with(http.request.uri.path,
//     "/exec"))` becomes `(http.host in {"cell-syd.doubleyoup.com"})` (every path, review H1).
// The run also MOVES syd's login gate from first to third (see ORDER IS THE POLICY).
// test/dispatch.test.ts pins all five live strings and every difference.
//
// CASE. Cloudflare does not lowercase `http.host`, and the host clauses are case-sensitive (as the
// live rules are). Both fail SAFE on a mixed-case Host: the front-end exemption does not match, so
// the request is challenged rather than exempted; the agent skip does not match, so the Managed
// Ruleset still runs rather than being skipped.
//
// ── TWIN of the orchestrator's src/edge-waf-rule.ts ────────────────────────────────────
// The orchestrator keeps a byte-identical copy to print, in a dry run, exactly what this Worker will
// build. Both test files pin the same text.
//
// PURE: no fetch, no Node APIs — unit-tested in test/dispatch.test.ts. The inputs MUST already have
// passed validateWafRuleUpsertParams: hosts are lowercase DNS names, so nothing here can break out of a
// quoted Rules-language string (escapeRulesString is defense in depth).

import { jsonValuesEqual } from "./edge-cache-rule.js";

/** The stable identity of the uniform country-BLOCK rule. */
export const WAF_COUNTRY_BLOCK_DESCRIPTION = "doubleyoup-country-block";

/** The stable identity of the WordPress admin/login geo-lockdown rule. */
export const WAF_WPADMIN_GEO_DESCRIPTION = "doubleyoup-wpadmin-geo";

/** The stable identity of the login managed-challenge rule (the "edge login gate"). */
export const WAF_LOGIN_GATE_DESCRIPTION = "doubleyoup-login-gate";

/** The stable identity of the front-end geo managed-challenge rule. */
export const WAF_FRONTEND_GEO_DESCRIPTION = "doubleyoup-frontend-geo";

/**
 * The stable identity of the agent skip rule. Copied EXACTLY from the live syd rule — it does not
 * start with "doubleyoup-", and changing it would make this op create a second rule next to syd's.
 * It still says "exec" because that is what the live rule is called; since 2026-10-07 the rule skips
 * EVERY path on the agent hosts (wafExecSkipExpression).
 */
export const WAF_EXEC_SKIP_DESCRIPTION = "skip managed WAF for cell-agent exec (internal bearer-authed endpoint)";

/** The Cloudflare ruleset phase that holds WAF custom rules. */
export const WAF_PHASE = "http_request_firewall_custom";

/** The phase the Managed Ruleset executes in — and the phase the agent skip rule skips. */
export const WAF_MANAGED_PHASE = "http_request_firewall_managed";

/**
 * The Cloudflare Managed Ruleset. The id is a Cloudflare-wide constant, not per account: it is the id
 * Cloudflare's own docs deploy, and the one live on doubleyoup.com.
 */
export const CLOUDFLARE_MANAGED_RULESET_ID = "efb7b8c949ac4650a09736fc376e9aee";

/** The description of the execute rule this op adds when it deploys the Managed Ruleset. */
export const MANAGED_RULESET_RULE_DESCRIPTION = "doubleyoup-managed-ruleset";

/**
 * The descriptions of OUR five custom rules, in apply order. Matched EXACTLY, never by prefix: the
 * agent skip rule's description does not start with "doubleyoup-", and a prefix would also claim the
 * `doubleyoup-ban:<id>` rules the ban system owns. Anything else in the phase is somebody else's and is
 * reported, never touched.
 */
export const WAF_RULE_DESCRIPTIONS: readonly string[] = [
  WAF_COUNTRY_BLOCK_DESCRIPTION,
  WAF_WPADMIN_GEO_DESCRIPTION,
  WAF_LOGIN_GATE_DESCRIPTION,
  WAF_FRONTEND_GEO_DESCRIPTION,
  WAF_EXEC_SKIP_DESCRIPTION,
];

/**
 * Cloudflare's custom-rule allowance per zone plan, keyed on the zone's `plan.legacy_id`
 * (developers.cloudflare.com/waf/custom-rules: Free 5, Pro 20, Business 100, Enterprise 1,000).
 * The actuator REFUSES before any write when our rules plus the zone's other rules would not fit.
 */
const WAF_CUSTOM_RULE_CAP_BY_PLAN: Readonly<Record<string, number>> = {
  free: 5,
  pro: 20,
  business: 100,
  enterprise: 1000,
};

/** The cap assumed for a plan we do not recognise: the smallest one, so a guess can only refuse. */
export const WAF_UNKNOWN_PLAN_RULE_CAP = 5;

/** The plans that may deploy the Cloudflare Managed Ruleset (Pro and above). */
const PLANS_WITH_MANAGED_RULESET: readonly string[] = ["pro", "business", "enterprise"];

/** The custom-rule allowance for a zone plan; an absent or unknown plan gets the Free allowance. */
export function wafCustomRuleCapForPlan(planLegacyId: string | null): number {
  if (planLegacyId === null) {
    return WAF_UNKNOWN_PLAN_RULE_CAP;
  }
  const cap = WAF_CUSTOM_RULE_CAP_BY_PLAN[planLegacyId];
  if (cap === undefined) {
    return WAF_UNKNOWN_PLAN_RULE_CAP;
  }
  return cap;
}

/** True only for a plan Cloudflare lets deploy the Managed Ruleset. Unknown => false. */
export function planSupportsManagedRuleset(planLegacyId: string | null): boolean {
  if (planLegacyId === null) {
    return false;
  }
  return PLANS_WITH_MANAGED_RULESET.includes(planLegacyId);
}

/**
 * Cloudflare's limit on one rule expression (4,096 characters). Checked by the builder, so an
 * over-long host list is refused with nothing written instead of failing half-way through the writes.
 */
export const WAF_EXPRESSION_MAX_LENGTH = 4096;

/** Countries blocked outright. ISO-3166 alpha-2. A CONSTANT: no signed job can change it. */
const WAF_BLOCK_COUNTRIES: readonly string[] = ["RU", "CN", "KP"];

/**
 * The allow-list: countries that may reach the WordPress admin/login surface and that are NOT
 * challenged on the front end. ISO-3166 alpha-2. A CONSTANT: no signed job can change it.
 */
const WAF_ALLOW_COUNTRIES: readonly string[] = ["AU", "US", "GB", "NZ", "FR", "IE"];

/** The rule body Cloudflare's ruleset API takes (POST/PATCH of one rule). */
export interface WafRule {
  description: string;
  expression: string;
  action: "block" | "managed_challenge" | "skip";
  /** Only the agent skip rule carries action parameters; the key is ABSENT on the other four. */
  action_parameters?: { phases: string[] };
  enabled: boolean;
}

/** All five rules for one zone, named. */
export interface WafRuleSet {
  countryBlock: WafRule;
  wpAdminGeo: WafRule;
  loginGate: WafRule;
  frontendGeo: WafRule;
  execSkip: WafRule;
}

/** What the builder needs: the validated params minus the Managed Ruleset switch. */
export interface WafRuleInput {
  /** The agency zone NAME; it lands in the media-host suffix clause. */
  zone: string;
  /** false switches the four PROTECTIVE rules off in place (rollback). The agent skip stays on. */
  enabled: boolean;
  /** Hosts the front-end challenge never applies to — the zone's own infrastructure. */
  excludedHosts: readonly string[];
  /** Cell-agent hosts: every request to them skips the Managed Ruleset. */
  agentHosts: readonly string[];
}

/**
 * A verdict, not a throw: actuators in this Worker never throw (they answer ok:false), so a bad state
 * comes back as a reason. An empty list is an edit-time bug (the validator refuses one); an over-long
 * expression is a real input limit.
 */
export type WafRulesVerdict = { ok: true; rules: WafRuleSet } | { ok: false; reason: string };

/**
 * Escape a value for a Cloudflare Rules-language double-quoted string literal. Country codes are
 * constants and hosts are validated DNS names, so this never changes a value — defense in depth.
 */
function escapeRulesString(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/** Trim / upper-case / dedupe ISO alpha-2 codes, preserving first-seen order. */
export function normalizeWafCountryCodes(codes: readonly string[]): string[] {
  const seen = new Set<string>();
  const normalized: string[] = [];
  for (const raw of codes) {
    const code = raw.trim().toUpperCase();
    if (code.length === 0) {
      continue;
    }
    if (seen.has(code)) {
      continue;
    }
    seen.add(code);
    normalized.push(code);
  }
  return normalized;
}

/** `{"a" "b"}` — a Rules-language set of quoted values, in the order given. */
function quotedSet(values: readonly string[]): string {
  const quoted = values.map((value) => `"${escapeRulesString(value)}"`);
  return `{${quoted.join(" ")}}`;
}

/** `ip.geoip.country in {"US" "GB"}` — country-set membership (quoted string values). */
function countrySetExpression(codes: readonly string[]): string {
  return `ip.geoip.country in ${quotedSet(codes)}`;
}

/**
 * The ONE path BOTH the admin geo-lockdown and the login gate exempt, built once so the two rules
 * cannot drift apart on it.
 *
 * WHY admin-ajax.php is exempt from an "admin" rule: despite living under /wp-admin/ it serves
 * FRONT-END functionality in most themes and plugins — contact forms, add-to-cart, search filters,
 * load-more. Blocking or challenging it breaks ordinary visitors on the PUBLIC site, silently and
 * half-way (the page renders, the interactions fail). It is not an admin surface in practice.
 *
 * It is still covered by the country BLOCK rule, which runs FIRST, so a blocked country gets no
 * admin-ajax either — and by the front-end challenge, like every other front-end request.
 */
const WP_ADMIN_AJAX_PATH = "/wp-admin/admin-ajax.php";

function wpAdminAjaxExemptionClause(): string {
  return `not (http.request.uri.path eq "${WP_ADMIN_AJAX_PATH}")`;
}

/** The uniform country-BLOCK expression. Null for an empty set (CF rejects `{}`; it means "block nothing"). */
export function wafCountryBlockExpression(codes: readonly string[]): string | null {
  const normalized = normalizeWafCountryCodes(codes);
  if (normalized.length === 0) {
    return null;
  }
  return countrySetExpression(normalized);
}

/**
 * The WordPress admin/login geo-lockdown expression. Null for an empty set (CF rejects `{}`, and here
 * it would BLOCK the admin surface from everywhere — an allow-list of nobody).
 *
 * THE PREFIX HAS NO TRAILING SLASH — `starts_with(path, "/wp-admin")` — and that DIFFERS from the
 * login gate below, which uses `"/wp-admin/"` WITH the slash. Do NOT "harmonise" them:
 *   - here the bare `/wp-admin` (no slash) must match. WordPress 301s it to `/wp-admin/`, and that
 *     redirect should not be reachable from a non-allow-listed country. With a trailing slash in
 *     the prefix, bare `/wp-admin` would fall out of the rule entirely and reopen the hole.
 *   - the login gate wants the opposite: it challenges the admin AREA, and the bare path is just a
 *     redirect to a page this rule already covers.
 *
 * It was `contains "/wp-admin"` until 2026-10-04. `contains` matched the substring ANYWHERE, so an
 * ordinary article at `/docs/wp-admin-tips/` was BLOCKED for every visitor outside the allow-list.
 * `starts_with` is strictly narrower (every path it matches, `contains` matched too) and it still
 * catches bare `/wp-admin`. It would lose a WordPress install BELOW the docroot root
 * (`/blog/wp-admin/`), but the platform cannot produce one: core is installed AT the docroot with a
 * path-less `--url`, an import rsyncs only `wp-content/` into that docroot, and a multisite dump is
 * refused outright.
 */
export function wafWpAdminGeoExpression(codes: readonly string[]): string | null {
  const normalized = normalizeWafCountryCodes(codes);
  if (normalized.length === 0) {
    return null;
  }
  return (
    `(starts_with(http.request.uri.path, "/wp-admin") or http.request.uri.path eq "/wp-login.php") ` +
    `and ${wpAdminAjaxExemptionClause()} ` +
    `and not (${countrySetExpression(normalized)})`
  );
}

/**
 * The edge login-gate expression: managed-challenge the WP login/admin surface. The exemptions are
 * deliberately structured so the ACTUAL login endpoint (/wp-login.php) is challenged UNCONDITIONALLY
 * — Cloudflare cannot validate a WordPress session, so ANY cookie/query-based exemption there is
 * forgeable by an attacker and would defeat the whole gate. So:
 *
 *  - /wp-login.php  -> challenge with NO exemptions (the unbypassable brute-force gate).
 *  - /wp-admin/*    -> challenge, EXCEPT admin-ajax.php and an already-logged-in session
 *    (`wordpress_logged_in_*` cookie). A forged-cookie bypass HERE is harmless: /wp-admin/ without a
 *    real session just 302s back to the gated /wp-login.php, so the exemption only spares genuine
 *    logged-in admins (and the post-SSO redirect, which lands on /wp-admin/ already carrying the
 *    cookie) from re-friction.
 *
 * THE PREFIX HAS A TRAILING SLASH — `starts_with(path, "/wp-admin/")` — and that DIFFERS from the
 * admin geo rule above, which uses `"/wp-admin"` WITHOUT it. Do NOT "harmonise" them: this rule
 * gates the admin AREA, and bare `/wp-admin` is only a 301 to `/wp-admin/`, which IS gated. The geo
 * rule needs the bare path too, because there the redirect itself must not be reachable.
 */
export function wafLoginGateExpression(): string {
  return [
    // The login endpoint itself: challenged unconditionally (no forgeable exemption).
    '(http.request.uri.path eq "/wp-login.php")',
    "or",
    // The admin area: challenged, but spare AJAX and genuine logged-in sessions. The admin-ajax
    // clause is the SAME builder the geo rule uses, so the two exemptions cannot drift apart.
    '(starts_with(http.request.uri.path, "/wp-admin/")',
    `and ${wpAdminAjaxExemptionClause()}`,
    'and not (http.cookie contains "wordpress_logged_in_"))',
  ].join(" ");
}

/**
 * The front-end geo expression. Its first three clauses are the live syd text, byte for byte; the
 * fourth is the per-site MEDIA exemption. Media hosts are `<slug>-media.<zone>` (app's
 * agencyMediaHostFor, hub#43): one per site, so listing them would mean a re-run per new site. A
 * subresource request (an image on a page) cannot solve a challenge, so without this clause every
 * image on a site would break for a visitor outside the allow-list. The suffix keeps the leading "-",
 * so it cannot match the zone apex or a host such as `media.<zone>` (those are listed explicitly when
 * they are infrastructure).
 */
export function wafFrontendGeoExpression(
  allowCountries: readonly string[],
  excludedHosts: readonly string[],
  zone: string,
): string {
  return (
    `not (${countrySetExpression(allowCountries)}) ` +
    'and not (cf.verified_bot_category eq "Search Engine Crawler") ' +
    `and not (http.host in ${quotedSet(excludedHosts)}) ` +
    `and not ends_with(http.host, "-media.${escapeRulesString(zone)}")`
  );
}

/**
 * The agent skip expression: EVERY request to a cell-agent host, whatever the path (review H1). The
 * agent hosts serve no WordPress, so there is nothing on them for the Managed Ruleset to protect, and
 * the agents' endpoints all carry the command bodies it blocks. One form for any number of hosts (an
 * agency cell has three agents: web, file and gateway).
 */
export function wafExecSkipExpression(agentHosts: readonly string[]): string {
  return `(http.host in ${quotedSet(agentHosts)})`;
}

/** Build all five rule bodies. `enabled:false` keeps every rule but switches the four protections off. */
export function buildEdgeWafRules(input: WafRuleInput): WafRulesVerdict {
  const countryBlockExpression = wafCountryBlockExpression(WAF_BLOCK_COUNTRIES);
  if (countryBlockExpression === null) {
    return { ok: false, reason: "the country-block list resolved to an empty set" };
  }
  const allowCountries = normalizeWafCountryCodes(WAF_ALLOW_COUNTRIES);
  const wpAdminGeoExpression = wafWpAdminGeoExpression(allowCountries);
  if (wpAdminGeoExpression === null) {
    return { ok: false, reason: "the allow-list resolved to an empty set" };
  }
  if (input.excludedHosts.length === 0) {
    return { ok: false, reason: "excludedHosts is empty (Cloudflare rejects an empty set)" };
  }
  if (input.agentHosts.length === 0) {
    return { ok: false, reason: "agentHosts is empty — there is no cell-agent host to exempt" };
  }

  const rules: WafRuleSet = {
    countryBlock: {
      description: WAF_COUNTRY_BLOCK_DESCRIPTION,
      expression: countryBlockExpression,
      action: "block",
      enabled: input.enabled,
    },
    wpAdminGeo: {
      description: WAF_WPADMIN_GEO_DESCRIPTION,
      expression: wpAdminGeoExpression,
      action: "block",
      enabled: input.enabled,
    },
    loginGate: {
      description: WAF_LOGIN_GATE_DESCRIPTION,
      expression: wafLoginGateExpression(),
      action: "managed_challenge",
      enabled: input.enabled,
    },
    frontendGeo: {
      description: WAF_FRONTEND_GEO_DESCRIPTION,
      expression: wafFrontendGeoExpression(allowCountries, input.excludedHosts, input.zone),
      action: "managed_challenge",
      enabled: input.enabled,
    },
    execSkip: {
      description: WAF_EXEC_SKIP_DESCRIPTION,
      expression: wafExecSkipExpression(input.agentHosts),
      action: "skip",
      action_parameters: { phases: [WAF_MANAGED_PHASE] },
      // Always on, even in a rollback: it keeps the cell-agent working (see the header, rule 5).
      enabled: true,
    },
  };

  for (const rule of edgeWafRulesInOrder(rules)) {
    if (rule.expression.length > WAF_EXPRESSION_MAX_LENGTH) {
      return {
        ok: false,
        reason:
          `rule "${rule.description}" would be ${rule.expression.length} characters, over Cloudflare's ` +
          `${WAF_EXPRESSION_MAX_LENGTH}-character expression limit — shorten the host lists`,
      };
    }
  }
  return { ok: true, rules };
}

/** The five rules in APPLY order — strictest first (see the header: order is the policy). */
export function edgeWafRulesInOrder(rules: WafRuleSet): WafRule[] {
  return [rules.countryBlock, rules.wpAdminGeo, rules.loginGate, rules.frontendGeo, rules.execSkip];
}

/** The execute rule that deploys the Cloudflare Managed Ruleset zone-wide with its default actions. */
export function buildManagedRulesetExecuteRule(): Record<string, unknown> {
  return {
    description: MANAGED_RULESET_RULE_DESCRIPTION,
    expression: "true",
    action: "execute",
    action_parameters: { id: CLOUDFLARE_MANAGED_RULESET_ID },
    enabled: true,
  };
}

/** The parts of an existing Cloudflare rule the drift check reads. */
export interface ExistingWafRule {
  action?: string;
  expression?: string;
  enabled?: boolean;
  action_parameters?: unknown;
}

/** True for an absent, null or `{}` action_parameters — what a block/challenge rule carries. */
function isEmptyActionParameters(value: unknown): boolean {
  if (value === undefined || value === null) {
    return true;
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  return Object.keys(value).length === 0;
}

/**
 * True when the live rule differs from the desired one in anything we own: action, expression,
 * enabled, or action_parameters. A match means the upsert does nothing. For the four rules without
 * action_parameters, any NON-empty value on the live rule is drift (someone added a custom response);
 * for the skip rule the parameters must be equal. Cloudflare's own extra fields (`id`, `ref`,
 * `version`, `logging`, ...) are not ours and are never compared.
 */
export function wafRuleDrifted(existing: ExistingWafRule, desired: WafRule): boolean {
  if (existing.action !== desired.action) {
    return true;
  }
  if (existing.expression !== desired.expression) {
    return true;
  }
  if (existing.enabled !== desired.enabled) {
    return true;
  }
  if (desired.action_parameters === undefined) {
    return !isEmptyActionParameters(existing.action_parameters);
  }
  return !jsonValuesEqual(existing.action_parameters, desired.action_parameters);
}
