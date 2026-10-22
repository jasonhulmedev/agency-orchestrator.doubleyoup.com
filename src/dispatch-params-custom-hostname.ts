// hub#46 — the PARAMS of the three custom-hostname ops (agency Worker side): custom-hostname-upsert,
// custom-hostname-get and custom-hostname-delete. A customer domain of an agency cell site is a
// Cloudflare-for-SaaS custom hostname in the AGENCY's own zone, created with the agency's own token,
// so its cert and its routing live in the account the customer's CNAME points at.
//
// WHY A FILE OF ITS OWN. dispatch-params.ts is shared by many branches at once. These validators sit
// here so a parallel branch that appends to dispatch-params.ts does not conflict with this one.
//
// ── TWIN of the app's src/server/services/agency-dispatch-params-custom-hostname.ts ─────────────────
// The block between the two markers below is BYTE-IDENTICAL in both repos, and both test suites pin
// its sha256 (test/custom-hostname-ops.test.ts here, agency-dispatch-params-custom-hostname.test.ts in
// app). A rule changed on one side only fails that side's suite. The header above the block differs.
//
// WHAT IS NOT IN THE TWIN. The zone rules need the AGENCY ZONE, which the two sides learn in different
// ways: the Worker reads it from its own env (CF_CUSTOM_HOSTNAME_ZONE, never from the job), and app
// reads the cell's recorded Cell.cfZone. Both run customHostnameZoneReason (inside the block) against
// their own value.

import type { ParamsVerdict } from "./dispatch-params.js";

// ── custom-hostname ops (hub#46): twin block start
/**
 * The PLATFORM's own zone. No customer hostname of an agency may be this zone or a name in it: the
 * platform zone holds the control plane (app.doubleyoup.com) and every platform host.
 */
export const CUSTOM_HOSTNAME_PLATFORM_ZONE = "doubleyoup.com";

/** custom-hostname-upsert: create the custom hostname, or return the one that exists. */
export interface CustomHostnameUpsertParams {
  /** The customer's domain, e.g. "www.example.com.au". */
  hostname: string;
  /** The cell's origin host in the agency zone (Cell.originHost), e.g. "cell-<region>-origin.<zone>". */
  customOriginServer: string;
}

/** custom-hostname-get: read one custom hostname. */
export interface CustomHostnameGetParams {
  hostname: string;
}

/** custom-hostname-delete: delete one custom hostname. */
export interface CustomHostnameDeleteParams {
  hostname: string;
}

// One label: 1-63 lowercase letters, digits or hyphens, not starting or ending with a hyphen. No
// underscore: a customer hostname is a host name, not a service record.
const CUSTOM_HOSTNAME_LABEL = "(?!-)[a-z0-9-]{1,63}(?<!-)";
// The last label starts with a letter, so an IPv4 literal ("1.2.3.4") is never a hostname. An IDN
// top-level label ("xn--...") still passes.
const CUSTOM_HOSTNAME_TLD_LABEL = "[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?";
// Two or more labels. No wildcard (wildcard custom hostnames are Enterprise-only) and no trailing dot.
const CUSTOM_HOSTNAME_RE = new RegExp(`^(?:${CUSTOM_HOSTNAME_LABEL}\\.)+${CUSTOM_HOSTNAME_TLD_LABEL}$`);
const CUSTOM_HOSTNAME_MAX_LENGTH = 253;

const CUSTOM_HOSTNAME_RULE =
  "must be a lowercase fully-qualified domain name (letters, digits and hyphens, two or more labels, no wildcard, no trailing dot)";

/** True when `value` is a lowercase fully-qualified host name in the grammar above. */
export function isCustomHostnameFqdn(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  if (value.length > CUSTOM_HOSTNAME_MAX_LENGTH) {
    return false;
  }
  return CUSTOM_HOSTNAME_RE.test(value);
}

/** True when `name` is `zone` itself or a name under it. Both are lowercase. */
export function isNameAtOrUnderZone(name: string, zone: string): boolean {
  if (name === zone) {
    return true;
  }
  return name.endsWith(`.${zone}`);
}

/** The reason `raw` carries a key other than `allowedKeys`, or null. */
function unknownCustomHostnameKeyReason(raw: Record<string, unknown>, allowedKeys: readonly string[]): string | null {
  for (const key of Object.keys(raw)) {
    if (!allowedKeys.includes(key)) {
      return `unknown key "${key}" (allowed: ${allowedKeys.join(", ")})`;
    }
  }
  return null;
}

/** The reason `hostname` is not a customer hostname this op may act on, or null. */
function customHostnameReason(hostname: unknown): string | null {
  if (!isCustomHostnameFqdn(hostname)) {
    return `hostname ${CUSTOM_HOSTNAME_RULE}`;
  }
  if (isNameAtOrUnderZone(hostname, CUSTOM_HOSTNAME_PLATFORM_ZONE)) {
    return `hostname must not be ${CUSTOM_HOSTNAME_PLATFORM_ZONE} or a name under it (the platform zone)`;
  }
  return null;
}

/** Shared by the get and delete ops: exactly one key, `hostname`. */
function validateCustomHostnameOnlyParams(raw: unknown): ParamsVerdict<{ hostname: string }> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const record = raw as Record<string, unknown>;
  const unknownKey = unknownCustomHostnameKeyReason(record, ["hostname"]);
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  const hostnameRefusal = customHostnameReason(record.hostname);
  if (hostnameRefusal !== null) {
    return { ok: false, reason: hostnameRefusal };
  }
  return { ok: true, params: { hostname: record.hostname as string } };
}

export function validateCustomHostnameUpsertParams(raw: unknown): ParamsVerdict<CustomHostnameUpsertParams> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const record = raw as Record<string, unknown>;
  const unknownKey = unknownCustomHostnameKeyReason(record, ["hostname", "customOriginServer"]);
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  const hostnameRefusal = customHostnameReason(record.hostname);
  if (hostnameRefusal !== null) {
    return { ok: false, reason: hostnameRefusal };
  }
  if (!isCustomHostnameFqdn(record.customOriginServer)) {
    return { ok: false, reason: `customOriginServer ${CUSTOM_HOSTNAME_RULE}` };
  }
  return {
    ok: true,
    params: { hostname: record.hostname as string, customOriginServer: record.customOriginServer as string },
  };
}

export function validateCustomHostnameGetParams(raw: unknown): ParamsVerdict<CustomHostnameGetParams> {
  return validateCustomHostnameOnlyParams(raw);
}

export function validateCustomHostnameDeleteParams(raw: unknown): ParamsVerdict<CustomHostnameDeleteParams> {
  return validateCustomHostnameOnlyParams(raw);
}

/**
 * The rules that need the AGENCY ZONE (lowercase), or null when the params satisfy them:
 *   - the hostname is a CUSTOMER domain, so it is neither the agency zone nor a name under it (an
 *     agency's own hosts are DNS records in its zone, not custom hostnames);
 *   - the custom origin server is a name strictly under the agency zone. Cloudflare forwards a custom
 *     hostname only to a proxied record in the same account, and the cell's origin host is one.
 */
export function customHostnameZoneReason(params: { hostname: string; customOriginServer?: string }, zone: string): string | null {
  if (isNameAtOrUnderZone(params.hostname, zone)) {
    return `hostname must not be the agency zone ${zone} or a name under it`;
  }
  if (params.customOriginServer === undefined) {
    return null;
  }
  if (!params.customOriginServer.endsWith(`.${zone}`)) {
    return `customOriginServer must be a name under the agency zone ${zone}`;
  }
  return null;
}
// ── custom-hostname ops (hub#46): twin block end
