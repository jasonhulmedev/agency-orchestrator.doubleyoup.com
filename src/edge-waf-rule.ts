// The standing EDGE-DEFENSE WAF custom rules — the Worker's OWN builder for the `waf-rule-upsert` op.
//
// The platform never sends this Worker an expression, an action, a country list or a rule body: it
// sends only a zone name and an on/off switch (dispatch-params.ts::validateWafRuleUpsertParams), and
// THIS module turns them into the full rules from its own constants. That keeps the platform's
// authority as narrow as it can be (Direction-B, fail-closed): the most a signed job can do is switch
// a fixed, known-safe set of three WordPress-defense rules on or off for one zone. A signed job can
// NEVER widen the blocked-country list, narrow the admin allow-list, or change an action — which
// matters here more than for any other op, because all three of those would be a self-inflicted
// outage of every site on the agency's zone.
//
// WHAT THE THREE RULES DO:
//   1. doubleyoup-country-block  BLOCK traffic from a small set of high-abuse countries (RU/CN/KP).
//   2. doubleyoup-wpadmin-geo    BLOCK the WordPress admin/login surface (/wp-admin + /wp-login.php)
//                                for everyone outside the allow-list (AU/US/GB/NZ/FR/IE).
//   3. doubleyoup-login-gate     MANAGED-CHALLENGE what is left of the login surface, so brute force
//                                dies at the edge: /wp-login.php unconditionally, and /wp-admin/
//                                except admin-ajax.php and an already-logged-in session.
//
// ORDER IS THE POLICY. Cloudflare evaluates a ruleset top-down and the first terminating action wins,
// so the rules are applied STRICTEST FIRST (country block -> admin geo -> login gate):
//   - a request from a blocked country to /wp-login.php is BLOCKED, not challenged;
//   - a request from a non-allow-listed country to /wp-admin is BLOCKED, not challenged;
//   - a request from an allow-listed country to /wp-login.php is CHALLENGED.
// Applying in this order also means a PARTIAL apply (a zone out of custom-rule budget) leaves the
// most protective rules in force rather than the least.
//
// NO HOST CLAUSE — deliberate, and the whole point. A WAF custom rule is evaluated per ZONE across
// ALL of that zone's traffic, which is what makes it cover a site served on its own customer domain
// (a Cloudflare-for-SaaS custom hostname on this zone). A rule scoped to `<slug>-production.<zone>`
// would protect the platform hostname and leave the real customer domain open. The blast radius is
// the whole zone, including the agency's own site — exactly as these rules already behave on the
// platform's own zone.
//
// ── TWIN of the orchestrator's src/edge-waf-rule.ts ────────────────────────────────────
// The orchestrator applies the SAME three rules to the platform zone (doubleyoup.com). Keep every
// expression byte-identical across the two copies, or platform sites and agency sites get different
// protection. Both test files pin the same text.
//
// ONE ASYMMETRY, on purpose: the orchestrator's copy lets the PLATFORM override the two country
// lists from its own env (COUNTRY_BLOCK_LIST / GEO_ALLOW_COUNTRIES). This copy takes no override at
// all — an agency zone always gets the default policy, because the only other way to vary it would
// be to let a signed job carry a country list.
//
// PURE: no fetch, no Node APIs — unit-tested in test/dispatch.test.ts.

/** The stable identity of the uniform country-BLOCK rule. */
export const WAF_COUNTRY_BLOCK_DESCRIPTION = "doubleyoup-country-block";

/** The stable identity of the WordPress admin/login geo-lockdown rule. */
export const WAF_WPADMIN_GEO_DESCRIPTION = "doubleyoup-wpadmin-geo";

/** The stable identity of the login managed-challenge rule (the "edge login gate"). */
export const WAF_LOGIN_GATE_DESCRIPTION = "doubleyoup-login-gate";

/** The Cloudflare ruleset phase that holds WAF custom rules. */
export const WAF_PHASE = "http_request_firewall_custom";

/**
 * The descriptions of OUR rules, in apply order — anything else in the firewall-custom phase is
 * somebody else's and is reported, never touched.
 */
export const WAF_RULE_DESCRIPTIONS: readonly string[] = [
  WAF_COUNTRY_BLOCK_DESCRIPTION,
  WAF_WPADMIN_GEO_DESCRIPTION,
  WAF_LOGIN_GATE_DESCRIPTION,
];

/**
 * HARD CAP on how many rules this op may ever place in a zone. Cloudflare's firewall-custom phase
 * allows 5 custom rules on a Free zone (20 on Pro), and neither side knows an agency zone's plan — so
 * the op must fit in a Free zone next to a rule or two of the agency's own. Three rules today; the
 * builder REFUSES to emit more than this, so adding a fourth is a deliberate act and adding a fifth
 * fails here rather than silently dropping a rule on a live zone.
 */
export const WAF_RULE_BUDGET = 4;

/**
 * The number of custom rules a Cloudflare FREE zone allows in this phase. Used only to EXPLAIN a
 * Cloudflare refusal to the operator — never to decide for Cloudflare, because a Pro zone allows 20
 * and this Worker cannot read the zone's plan.
 */
export const WAF_FREE_PLAN_RULE_LIMIT = 5;

/** Countries blocked outright. ISO-3166 alpha-2. A CONSTANT: no signed job can change it. */
const WAF_BLOCK_COUNTRIES: readonly string[] = ["RU", "CN", "KP"];

/**
 * Countries allowed to reach the WordPress admin/login surface; everyone else is BLOCKED there.
 * ISO-3166 alpha-2. A CONSTANT: no signed job can change it.
 */
const WAF_ADMIN_ALLOW_COUNTRIES: readonly string[] = ["AU", "US", "GB", "NZ", "FR", "IE"];

/** The rule body Cloudflare's ruleset API takes (POST/PATCH of one rule). */
export interface WafRule {
  description: string;
  expression: string;
  action: "block" | "managed_challenge";
  enabled: boolean;
}

/** All three rules for one zone, named. */
export interface WafRuleSet {
  countryBlock: WafRule;
  wpAdminGeo: WafRule;
  loginGate: WafRule;
}

/**
 * A verdict, not a throw: actuators in this Worker never throw (they answer ok:false), so a bad
 * state comes back as a reason. Both failure modes here are edit-time bugs (an emptied constant
 * list, a rule set over budget), so this branch is defense in depth.
 */
export type WafRulesVerdict = { ok: true; rules: WafRuleSet } | { ok: false; reason: string };

/**
 * Escape a value for a Cloudflare Rules-language double-quoted string literal. The country lists are
 * constants here, so this is defense in depth against a bad edit.
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

/** `ip.geoip.country in {"US" "GB"}` — country-set membership (quoted string values). */
function countrySetExpression(codes: readonly string[]): string {
  const set = codes.map((code) => `"${escapeRulesString(code)}"`).join(" ");
  return `ip.geoip.country in {${set}}`;
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
 * NOTE `contains "/wp-admin"` (not starts_with) is the PLATFORM's live text and is reproduced
 * verbatim: it also matches a path that merely contains "/wp-admin" anywhere. That is the existing
 * policy, deliberately not redesigned here.
 */
export function wafWpAdminGeoExpression(codes: readonly string[]): string | null {
  const normalized = normalizeWafCountryCodes(codes);
  if (normalized.length === 0) {
    return null;
  }
  return (
    `(http.request.uri.path contains "/wp-admin" or http.request.uri.path eq "/wp-login.php") ` +
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
 */
export function wafLoginGateExpression(): string {
  return [
    // The login endpoint itself: challenged unconditionally (no forgeable exemption).
    '(http.request.uri.path eq "/wp-login.php")',
    "or",
    // The admin area: challenged, but spare AJAX and genuine logged-in sessions.
    '(starts_with(http.request.uri.path, "/wp-admin/")',
    'and not (http.request.uri.path eq "/wp-admin/admin-ajax.php")',
    'and not (http.cookie contains "wordpress_logged_in_"))',
  ].join(" ");
}

/** Build all three rule bodies. `enabled:false` keeps every rule but switches it off (rollback). */
export function buildEdgeWafRules(input: { enabled: boolean }): WafRulesVerdict {
  const countryBlockExpression = wafCountryBlockExpression(WAF_BLOCK_COUNTRIES);
  if (countryBlockExpression === null) {
    return { ok: false, reason: "the country-block list resolved to an empty set" };
  }
  const wpAdminGeoExpression = wafWpAdminGeoExpression(WAF_ADMIN_ALLOW_COUNTRIES);
  if (wpAdminGeoExpression === null) {
    return { ok: false, reason: "the admin geo allow-list resolved to an empty set" };
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
  };

  // The budget guard is on the OUTPUT, so it still holds if someone adds a fourth or fifth rule to
  // the set above. A zone's custom-rule allowance is small and this Worker cannot read its plan.
  const ordered = edgeWafRulesInOrder(rules);
  if (ordered.length > WAF_RULE_BUDGET) {
    return { ok: false, reason: `the edge-defense rule set is ${ordered.length} rules, over the budget of ${WAF_RULE_BUDGET}` };
  }
  return { ok: true, rules };
}

/** The three rules in APPLY order — strictest first (see the header: order is the policy). */
export function edgeWafRulesInOrder(rules: WafRuleSet): WafRule[] {
  return [rules.countryBlock, rules.wpAdminGeo, rules.loginGate];
}

/** The parts of an existing Cloudflare rule the drift check reads. */
export interface ExistingWafRule {
  action?: string;
  expression?: string;
  enabled?: boolean;
}

/**
 * True when the live rule differs from the desired one in anything we own: action, expression or
 * enabled. A match means the upsert does nothing. There is no action_parameters comparison because
 * none of the three rules carries any — `block` and `managed_challenge` take no parameters, and an
 * extra parameter a future Cloudflare adds is not ours to fight over.
 */
export function wafRuleDrifted(existing: ExistingWafRule, desired: WafRule): boolean {
  if (existing.action !== desired.action) {
    return true;
  }
  if (existing.expression !== desired.expression) {
    return true;
  }
  return existing.enabled !== desired.enabled;
}
