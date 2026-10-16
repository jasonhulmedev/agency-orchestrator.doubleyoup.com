// planning/47 decision G — `cf-tunnel-token-get`: READ one tunnel's CONNECTOR token, so the platform
// can publish the CURRENT gateway.sh on a saga-built cell's gateway (the node that runs the cell's
// tunnel connector; gateway.sh writes the token from its injected DY_TUNNEL_TOKEN on every boot).
//
// THE ONE SECRET THIS OP RETURNS, like cf-tunnel-create's `connectorToken`. The Worker never logs it
// and never puts it in a detail string. The orchestrator puts it only into the rendered gateway boot
// script of one publish. app signs the op only for the recorded tunnel of one of the account's own
// saga-built cells.
//
// FAIL CLOSED: the token Cloudflare returns is checked to be a connector token FOR THIS TUNNEL (its
// base64 JSON names the tunnel id as `t`) before it is returned, so a wrong answer can never reach a
// boot script. A detail string never carries any part of it.

import type { Env } from "./env.js";
import type { CfTunnelTokenGetParams } from "./dispatch-params.js";
import { CF_TUNNEL_UNAUTHORIZED_HINT, fetchCfTunnelToken, resolveAccountId } from "./actuate.js";

export type CfTunnelTokenGetResult =
  | { ok: true; op: "cf-tunnel-token-get"; tunnelId: string; connectorToken: string }
  | { ok: false; op: "cf-tunnel-token-get"; tunnelId: string; detail: string };

/** A connector token: base64 of a small JSON object. Bounded; never parsed beyond its `t` field. */
const CONNECTOR_TOKEN_RE = /^[A-Za-z0-9+/=_-]{40,2048}$/;

/** Both forms of a tunnel id, compared without dashes. */
function tunnelIdKey(tunnelId: string): string {
  return tunnelId.replace(/-/g, "").toLowerCase();
}

/**
 * True when `connectorToken` is a connector token for `tunnelId`: base64 (standard or URL-safe) of a
 * JSON object whose `t` is that tunnel id. PURE and exported for the unit tests.
 */
export function isConnectorTokenForTunnel(connectorToken: string, tunnelId: string): boolean {
  if (!CONNECTOR_TOKEN_RE.test(connectorToken)) {
    return false;
  }
  let decoded: unknown;
  try {
    const standard = connectorToken.replace(/-/g, "+").replace(/_/g, "/");
    decoded = JSON.parse(atob(standard));
  } catch {
    return false;
  }
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    return false;
  }
  const named = (decoded as { t?: unknown }).t;
  if (typeof named !== "string") {
    return false;
  }
  return tunnelIdKey(named) === tunnelIdKey(tunnelId);
}

export async function actuateCfTunnelTokenGet(params: CfTunnelTokenGetParams, env: Env): Promise<CfTunnelTokenGetResult> {
  const { tunnelId } = params;
  const failure = (detail: string): CfTunnelTokenGetResult => ({ ok: false, op: "cf-tunnel-token-get", tunnelId, detail });

  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return failure("CF_DNS_API_TOKEN is not configured on this Worker.");
  }
  const account = await resolveAccountId(token, CF_TUNNEL_UNAUTHORIZED_HINT);
  if ("error" in account) {
    return failure(account.error);
  }
  const connector = await fetchCfTunnelToken(token, account.id, tunnelId);
  if ("error" in connector) {
    return failure(connector.error);
  }
  if (!isConnectorTokenForTunnel(connector.token, tunnelId)) {
    return failure("Cloudflare answered with a value that is not a connector token for this tunnel — refusing to return it.");
  }
  return { ok: true, op: "cf-tunnel-token-get", tunnelId, connectorToken: connector.token };
}
