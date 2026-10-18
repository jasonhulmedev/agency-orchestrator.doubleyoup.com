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
import type { CfTunnelConnectionsGetParams, CfTunnelTokenGetParams, GcpInstanceMetadataDiffParams } from "./dispatch-params.js";
import {
  CF_API,
  CF_TUNNEL_UNAUTHORIZED_HINT,
  GCP_COMPUTE_API,
  cloudflareErrorMessage,
  fetchCfTunnelToken,
  mintPinnedGcpAccessToken,
  readComputeInstance,
  renderMetadataItems,
  resolveAccountId,
  utf8Sha256Hex,
  type CloudflareEnvelope,
} from "./actuate.js";
import { errorMessage } from "./util.js";

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

// ── gcp-instance-metadata-diff (planning/47 review M1/M2) ────────────────────────────────────────
// The read-only twin of gcp-instance-set-metadata: the same substitution (renderMetadataItems), the
// same instance read, and NO write. It reports, per key, the sha256 of the value a write would send
// and whether the instance already holds exactly that value. Hashes and key names only: a substituted
// file-node script carries the agency's object-store credential.

export type GcpInstanceMetadataDiffResult =
  | {
      ok: true;
      op: "gcp-instance-metadata-diff";
      instanceName: string;
      /** The metadata fingerprint now (what a following set-metadata's expectedFingerprint names). */
      fingerprint: string | null;
      /** sha256 hex of each value AS A WRITE WOULD SEND IT (after substitution), keyed by key. */
      valuesSha256: Record<string, string>;
      /** The keys whose existing value is already byte-identical to that value. */
      unchangedKeys: string[];
      placeholdersSubstituted: string[];
      /** Non-secret resolved values only (PLACEHOLDER_VALUES_SAFE_TO_ECHO). */
      placeholderValues: Record<string, string>;
    }
  | { ok: false; op: "gcp-instance-metadata-diff"; instanceName: string; detail: string };

export async function actuateGcpInstanceMetadataDiff(params: GcpInstanceMetadataDiffParams, env: Env): Promise<GcpInstanceMetadataDiffResult> {
  const { project, zone } = params;
  const instanceName = params.name;
  const failure = (detail: string): GcpInstanceMetadataDiffResult => ({ ok: false, op: "gcp-instance-metadata-diff", instanceName, detail });

  const rendered = renderMetadataItems(params.items, env);
  if (!rendered.ok) {
    return failure(rendered.detail);
  }
  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const instanceUrl =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/zones/${encodeURIComponent(zone)}/instances/${encodeURIComponent(instanceName)}`;
  const current = await readComputeInstance({ url: instanceUrl, accessToken: token.accessToken, what: `instance "${instanceName}"`, project });
  if (!current.ok) {
    return failure(current.detail);
  }
  let fingerprint: string | null = null;
  const reportedFingerprint = current.instance.metadata?.fingerprint;
  if (typeof reportedFingerprint === "string" && reportedFingerprint.length > 0) {
    fingerprint = reportedFingerprint;
  }
  const existingItems = current.instance.metadata?.items ?? [];
  const valuesSha256: Record<string, string> = {};
  const unchangedKeys: string[] = [];
  for (const item of rendered.renderedItems) {
    valuesSha256[item.key] = await utf8Sha256Hex(item.value);
    const existing = existingItems.find((entry) => entry.key === item.key);
    if (existing !== undefined && existing.value === item.value) {
      unchangedKeys.push(item.key);
    }
  }
  return {
    ok: true,
    op: "gcp-instance-metadata-diff",
    instanceName,
    fingerprint,
    valuesSha256,
    unchangedKeys,
    placeholdersSubstituted: rendered.placeholdersSubstituted,
    placeholderValues: rendered.placeholderValues,
  };
}

// ── cf-tunnel-connections-get (planning/47 review M2/L4) ─────────────────────────────────────────
// READ-ONLY: GET .../cfd_tunnel/<id>/connections in the Worker token's own account. Reported per
// connector: its id, version, and the DISTINCT origin IPs of its connections. FAIL CLOSED: an answer
// of another shape is refused, never half-reported.

export interface TunnelConnector {
  connectorId: string;
  version: string | null;
  originIps: string[];
  connectionCount: number;
}

export type CfTunnelConnectionsGetResult =
  | { ok: true; op: "cf-tunnel-connections-get"; tunnelId: string; connectors: TunnelConnector[] }
  | { ok: false; op: "cf-tunnel-connections-get"; tunnelId: string; detail: string };

const CONNECTOR_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CONNECTOR_VERSION_RE = /^[A-Za-z0-9._+-]{1,64}$/;
const ORIGIN_IPV4_RE = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;
const ORIGIN_IPV6_RE = /^[0-9a-fA-F:]{2,39}$/;

/**
 * The connectors of Cloudflare's /connections answer, or the reason it is refused. PURE and exported
 * for the unit tests. Every connector must carry an id; each connection an origin IP of IPv4 or IPv6
 * shape. A connector with no connections is reported with none.
 */
export function parseTunnelConnections(result: unknown): { ok: true; connectors: TunnelConnector[] } | { ok: false; reason: string } {
  if (!Array.isArray(result)) {
    return { ok: false, reason: "the connections answer is not a list" };
  }
  const connectors: TunnelConnector[] = [];
  for (const entry of result) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      return { ok: false, reason: "a connector entry is not an object" };
    }
    const connector = entry as { id?: unknown; client_id?: unknown; version?: unknown; client_version?: unknown; conns?: unknown };
    const connectorId = typeof connector.id === "string" ? connector.id : connector.client_id;
    if (typeof connectorId !== "string" || !CONNECTOR_ID_RE.test(connectorId)) {
      return { ok: false, reason: "a connector has no id of the expected shape" };
    }
    let version: string | null = null;
    const reportedVersion = typeof connector.version === "string" ? connector.version : connector.client_version;
    if (typeof reportedVersion === "string" && CONNECTOR_VERSION_RE.test(reportedVersion)) {
      version = reportedVersion;
    }
    const conns = connector.conns === undefined ? [] : connector.conns;
    if (!Array.isArray(conns)) {
      return { ok: false, reason: "a connector's connections are not a list" };
    }
    const originIps: string[] = [];
    for (const conn of conns) {
      const originIp = conn !== null && typeof conn === "object" ? (conn as { origin_ip?: unknown }).origin_ip : undefined;
      if (typeof originIp !== "string" || !(ORIGIN_IPV4_RE.test(originIp) || ORIGIN_IPV6_RE.test(originIp))) {
        return { ok: false, reason: "a connection has no origin IP of the expected shape" };
      }
      if (!originIps.includes(originIp)) {
        originIps.push(originIp);
      }
    }
    connectors.push({ connectorId, version, originIps, connectionCount: conns.length });
  }
  return { ok: true, connectors };
}

export async function actuateCfTunnelConnectionsGet(params: CfTunnelConnectionsGetParams, env: Env): Promise<CfTunnelConnectionsGetResult> {
  const { tunnelId } = params;
  const failure = (detail: string): CfTunnelConnectionsGetResult => ({ ok: false, op: "cf-tunnel-connections-get", tunnelId, detail });

  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return failure("CF_DNS_API_TOKEN is not configured on this Worker.");
  }
  const account = await resolveAccountId(token, CF_TUNNEL_UNAUTHORIZED_HINT);
  if ("error" in account) {
    return failure(account.error);
  }
  let response: Response;
  try {
    response = await fetch(
      `${CF_API}/accounts/${encodeURIComponent(account.id)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/connections`,
      { headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
    );
  } catch (err) {
    return failure(`could not reach Cloudflare to read the tunnel's connections: ${errorMessage(err)}`);
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return failure(CF_TUNNEL_UNAUTHORIZED_HINT);
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!body?.success) {
    return failure(`the tunnel connections read failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`);
  }
  const parsed = parseTunnelConnections(body.result);
  if (!parsed.ok) {
    return failure(`refusing to report the tunnel's connections: ${parsed.reason}.`);
  }
  return { ok: true, op: "cf-tunnel-connections-get", tunnelId, connectors: parsed.connectors };
}
