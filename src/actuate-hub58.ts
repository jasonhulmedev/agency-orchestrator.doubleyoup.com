// hub#58 / planning/51 ACTUATION (agency Worker side) — the two ops that let the platform manage the
// syd cell through this Worker instead of over SSH:
//
//   cf-tunnel-get             READ one tunnel's remotely-managed ingress config, so the orchestrator
//                             can keep every rule it does not own before it writes (decision E);
//   gcp-disk-snapshot-create  SNAPSHOT one cell node's boot disk, the revert point before that node
//                             reboots onto a new startup script (decision H).
//
// Both run with the AGENCY's own credentials only — CF_DNS_API_TOKEN and GCP_SERVICE_ACCOUNT_KEY —
// through the same helpers every other op in actuate.ts uses, so the account resolution, the project
// pin and the token mint cannot drift between ops. Neither op changes a running resource, and neither
// deletes anything.
//
// They live in their own module so that the large, frequently-changed actuate.ts stays untouched
// except for the helper exports this module needs.
//
// FAIL CLOSED ON UNKNOWN SHAPES. Both ops read a response from an external API and act on what they
// read: the orchestrator rewrites a tunnel config from the first, and a boot disk is chosen from the
// second. A shape this code does not fully understand is reported as ok:false with the reason,
// never guessed at.

import type { Env } from "./env.js";
import {
  diskSnapshotNameFor,
  type CfTunnelGetParams,
  type GcpDiskSnapshotCreateParams,
} from "./dispatch-params.js";
import {
  CF_API,
  CF_TUNNEL_UNAUTHORIZED_HINT,
  GCP_COMPUTE_API,
  cloudflareErrorMessage,
  gcpHeaders,
  googleErrorMessage,
  isAlreadyExists,
  mintPinnedGcpAccessToken,
  resolveAccountId,
  waitForComputeOperation,
  type CloudflareEnvelope,
  type ComputeInsertResponse,
} from "./actuate.js";
import { errorMessage } from "./util.js";

// ── cf-tunnel-get ────────────────────────────────────────────────────────────────────

/**
 * One ingress rule as cf-tunnel-get reports it. The hostname, service and path are returned as
 * Cloudflare stores them. The rule's `originRequest` settings are returned by NAME only: the
 * orchestrator only needs to know that a rule has settings cf-tunnel-config cannot write back.
 */
export interface CfTunnelGetRule {
  /** The rule's hostname, or null for a hostname-less rule (the catch-all). */
  hostname: string | null;
  /** The origin service, e.g. "http://localhost:80" or "http_status:404". */
  service: string;
  /** The rule's path regex, or null when it has none. */
  path: string | null;
  /** The names of the rule's originRequest settings, sorted. [] when it has none. */
  originRequestKeys: string[];
}

export type CfTunnelGetResult =
  | {
      ok: true;
      op: "cf-tunnel-get";
      tunnelId: string;
      /** Who manages the config: "cloudflare" (remote) or "local". null when Cloudflare did not say. */
      source: string | null;
      /** Cloudflare's config version number, or null when it did not say. */
      version: number | null;
      /** Every ingress rule, in the order cloudflared evaluates them (the catch-all is last). */
      rules: CfTunnelGetRule[];
      /** The names of every top-level config key other than `ingress` (e.g. "originRequest"), sorted. */
      otherConfigKeys: string[];
    }
  | { ok: false; op: "cf-tunnel-get"; tunnelId: string; detail: string };

/** The keys an ingress rule may carry (cloudflared's rule schema). Any other key fails closed. */
const TUNNEL_RULE_KEYS: readonly string[] = ["hostname", "service", "path", "originRequest"];
/** A sane upper bound for one tunnel. Far above the 20-rule budget the write op allows. */
const TUNNEL_RULES_MAX = 1000;
const TUNNEL_HOSTNAME_MAX_LENGTH = 253;
const TUNNEL_SERVICE_MAX_LENGTH = 2048;
const TUNNEL_PATH_MAX_LENGTH = 2048;
/** A config or originRequest key NAME: what cloudflared's YAML/JSON keys look like. */
const TUNNEL_CONFIG_KEY_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const TUNNEL_CONFIG_KEYS_MAX = 64;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The sorted key names of `record`, or null when a name is not a plain config key. */
function configKeyNames(record: Record<string, unknown>): string[] | null {
  const names = Object.keys(record);
  if (names.length > TUNNEL_CONFIG_KEYS_MAX) {
    return null;
  }
  for (const name of names) {
    if (!TUNNEL_CONFIG_KEY_RE.test(name)) {
      return null;
    }
  }
  return names.sort();
}

/** Parse one ingress rule, or explain why its shape is not one this op understands. */
function parseTunnelRule(rule: unknown, index: number): { ok: true; rule: CfTunnelGetRule } | { ok: false; reason: string } {
  if (!isPlainRecord(rule)) {
    return { ok: false, reason: `ingress rule ${index} is not an object` };
  }
  for (const key of Object.keys(rule)) {
    if (!TUNNEL_RULE_KEYS.includes(key)) {
      return { ok: false, reason: `ingress rule ${index} carries the key "${key.slice(0, 64)}", which this op does not understand` };
    }
  }

  const { hostname, service, path, originRequest } = rule;
  if (typeof service !== "string" || service.length === 0 || service.length > TUNNEL_SERVICE_MAX_LENGTH) {
    return { ok: false, reason: `ingress rule ${index} has no usable service` };
  }

  let parsedHostname: string | null = null;
  if (hostname !== undefined) {
    if (typeof hostname !== "string" || hostname.length === 0 || hostname.length > TUNNEL_HOSTNAME_MAX_LENGTH) {
      return { ok: false, reason: `ingress rule ${index} has a hostname that is not a usable string` };
    }
    parsedHostname = hostname;
  }

  let parsedPath: string | null = null;
  if (path !== undefined) {
    if (typeof path !== "string" || path.length > TUNNEL_PATH_MAX_LENGTH) {
      return { ok: false, reason: `ingress rule ${index} has a path that is not a usable string` };
    }
    parsedPath = path;
  }

  let originRequestKeys: string[] = [];
  if (originRequest !== undefined) {
    if (!isPlainRecord(originRequest)) {
      return { ok: false, reason: `ingress rule ${index} has an originRequest that is not an object` };
    }
    const names = configKeyNames(originRequest);
    if (names === null) {
      return { ok: false, reason: `ingress rule ${index} has originRequest keys this op does not understand` };
    }
    originRequestKeys = names;
  }

  return { ok: true, rule: { hostname: parsedHostname, service, path: parsedPath, originRequestKeys } };
}

/** What parseTunnelConfiguration extracts from Cloudflare's `result` object. */
export type ParsedTunnelConfiguration =
  | { ok: true; source: string | null; version: number | null; rules: CfTunnelGetRule[]; otherConfigKeys: string[] }
  | { ok: false; reason: string };

/**
 * Parse the `result` of GET /accounts/{id}/cfd_tunnel/{tunnelId}/configurations. PURE and exported
 * for the unit tests. A tunnel that has never been configured answers with no config or no ingress,
 * which is reported as zero rules. Every other surprise is a refusal with the reason.
 */
export function parseTunnelConfiguration(result: unknown, tunnelId: string): ParsedTunnelConfiguration {
  if (!isPlainRecord(result)) {
    return { ok: false, reason: "Cloudflare answered without a configuration object" };
  }

  // A result for some OTHER tunnel would be a Cloudflare-side fault; never report it as this one.
  const reportedTunnelId = result.tunnel_id;
  if (reportedTunnelId !== undefined && (typeof reportedTunnelId !== "string" || reportedTunnelId.toLowerCase() !== tunnelId)) {
    return { ok: false, reason: "Cloudflare answered with the configuration of a different tunnel" };
  }

  let source: string | null = null;
  if (typeof result.source === "string" && result.source.length > 0 && result.source.length <= 64) {
    source = result.source;
  }
  let version: number | null = null;
  if (typeof result.version === "number" && Number.isInteger(result.version)) {
    version = result.version;
  }

  const config = result.config;
  if (config === undefined || config === null) {
    return { ok: true, source, version, rules: [], otherConfigKeys: [] };
  }
  if (!isPlainRecord(config)) {
    return { ok: false, reason: "the tunnel's config is not an object" };
  }

  const topLevelNames = configKeyNames(config);
  if (topLevelNames === null) {
    return { ok: false, reason: "the tunnel's config has top-level keys this op does not understand" };
  }
  const otherConfigKeys = topLevelNames.filter((name) => name !== "ingress");

  const ingress = config.ingress;
  if (ingress === undefined) {
    return { ok: true, source, version, rules: [], otherConfigKeys };
  }
  if (!Array.isArray(ingress)) {
    return { ok: false, reason: "the tunnel's ingress is not a list" };
  }
  if (ingress.length > TUNNEL_RULES_MAX) {
    return { ok: false, reason: `the tunnel has ${ingress.length} ingress rules, more than this op reads (${TUNNEL_RULES_MAX})` };
  }

  const rules: CfTunnelGetRule[] = [];
  for (let index = 0; index < ingress.length; index += 1) {
    const parsed = parseTunnelRule(ingress[index], index);
    if (!parsed.ok) {
      return { ok: false, reason: parsed.reason };
    }
    rules.push(parsed.rule);
  }
  return { ok: true, source, version, rules, otherConfigKeys };
}

export async function actuateCfTunnelGet(params: CfTunnelGetParams, env: Env): Promise<CfTunnelGetResult> {
  const { tunnelId } = params;
  const failure = (detail: string): CfTunnelGetResult => ({ ok: false, op: "cf-tunnel-get", tunnelId, detail });

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
      `${CF_API}/accounts/${encodeURIComponent(account.id)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/configurations`,
      { headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
    );
  } catch (err) {
    return failure(`could not reach Cloudflare to read the tunnel config: ${errorMessage(err)}`);
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return failure(CF_TUNNEL_UNAUTHORIZED_HINT);
  }
  if (response.status === 404) {
    await response.text().catch(() => "");
    return failure(
      "Cloudflare has no configuration for this tunnel in the account CF_DNS_API_TOKEN belongs to — check the tunnel id and that the token is from the account that owns the tunnel.",
    );
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!body?.success) {
    return failure(`tunnel config read failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`);
  }

  const parsed = parseTunnelConfiguration(body.result, tunnelId);
  if (!parsed.ok) {
    return failure(`refusing to report the tunnel config: ${parsed.reason}.`);
  }
  return {
    ok: true,
    op: "cf-tunnel-get",
    tunnelId,
    source: parsed.source,
    version: parsed.version,
    rules: parsed.rules,
    otherConfigKeys: parsed.otherConfigKeys,
  };
}

// ── gcp-disk-snapshot-create ─────────────────────────────────────────────────────────

export type GcpDiskSnapshotCreateResult =
  | {
      ok: true;
      op: "gcp-disk-snapshot-create";
      instanceName: string;
      /** The instance's boot disk, the disk that was snapshotted. */
      diskName: string;
      snapshotName: string;
      /** "created" = this call started the snapshot; "already-existed" = a snapshot of this disk had the name. */
      status: "created" | "already-existed";
      /** Google's snapshot status (READY, CREATING, UPLOADING, FAILED, DELETING), or null when unread. */
      snapshotStatus: string | null;
    }
  | { ok: false; op: "gcp-disk-snapshot-create"; instanceName: string; snapshotName: string; detail: string };

/** The instance fields this op reads. */
interface ComputeInstanceDisksResponse {
  disks?: Array<{ boot?: unknown; source?: unknown }>;
  error?: ComputeInsertResponse["error"];
}

/** The snapshot fields this op reads. */
interface ComputeSnapshotResponse {
  status?: unknown;
  sourceDisk?: unknown;
  error?: ComputeInsertResponse["error"];
}

/** Google's error message from a snapshot read (the fields are typed loosely, so wrap them). */
function snapshotErrorMessage(body: ComputeSnapshotResponse | null): string {
  if (body === null) {
    return "";
  }
  return googleErrorMessage({ error: body.error });
}

/** A disk's identity, parsed from its Compute Engine URL. */
interface ComputeDiskIdentity {
  project: string;
  zone: string;
  disk: string;
}

/**
 * The zonal disk URL forms Google returns in `disks[].source` and a snapshot's `sourceDisk`. A
 * regional disk (`/regions/`) does not match, by design: cell nodes use zonal disks, and anything
 * else is a shape this op refuses.
 */
const ZONAL_DISK_URL_RE =
  /^https:\/\/(?:www\.googleapis\.com|compute\.googleapis\.com)\/compute\/(?:v1|beta)\/projects\/([a-z][a-z0-9-]{4,28}[a-z0-9])\/zones\/([a-z]+-[a-z0-9]+-[a-z])\/disks\/([a-z]([-a-z0-9]{0,61}[a-z0-9])?)$/;

/** Parse a zonal disk URL, or null when it is not one. PURE and exported for the unit tests. */
export function parseZonalDiskUrl(value: unknown): ComputeDiskIdentity | null {
  if (typeof value !== "string") {
    return null;
  }
  const match = ZONAL_DISK_URL_RE.exec(value);
  if (match === null) {
    return null;
  }
  return { project: match[1] as string, zone: match[2] as string, disk: match[3] as string };
}

/**
 * The ONE boot disk of an instance, in the op's own project and zone, or the reason there is not
 * exactly one. PURE and exported for the unit tests.
 */
export function bootDiskOf(
  instance: ComputeInstanceDisksResponse | null,
  project: string,
  zone: string,
): { ok: true; disk: string } | { ok: false; reason: string } {
  if (instance === null || !Array.isArray(instance.disks)) {
    return { ok: false, reason: "the instance reports no disks" };
  }
  const bootDisks = instance.disks.filter((disk) => disk !== null && typeof disk === "object" && disk.boot === true);
  if (bootDisks.length !== 1) {
    return { ok: false, reason: `the instance reports ${bootDisks.length} boot disks, not exactly one` };
  }
  const identity = parseZonalDiskUrl(bootDisks[0]?.source);
  if (identity === null) {
    return { ok: false, reason: "the boot disk's source is not a zonal disk URL this op understands" };
  }
  if (identity.project !== project || identity.zone !== zone) {
    return { ok: false, reason: "the boot disk is not in the instance's own project and zone" };
  }
  return { ok: true, disk: identity.disk };
}

/** How reading the snapshot of the derived name ended. */
type SnapshotRead =
  | { kind: "absent" }
  | { kind: "same-disk"; status: string | null }
  | { kind: "other-disk" }
  | { kind: "failed"; detail: string };

async function readSnapshotFor(input: {
  project: string;
  zone: string;
  disk: string;
  snapshotName: string;
  accessToken: string;
}): Promise<SnapshotRead> {
  const { project, zone, disk, snapshotName, accessToken } = input;
  const url = `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}/global/snapshots/${encodeURIComponent(snapshotName)}`;

  let response: Response;
  try {
    response = await fetch(url, { headers: gcpHeaders(accessToken) });
  } catch (err) {
    return { kind: "failed", detail: `could not reach Google Compute Engine to read snapshot "${snapshotName}": ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as ComputeSnapshotResponse | null;
  if (response.status === 404) {
    return { kind: "absent" };
  }
  if (response.status === 401 || response.status === 403) {
    return {
      kind: "failed",
      detail:
        `Google Cloud denied reading snapshot "${snapshotName}" (HTTP ${response.status})${snapshotErrorMessage(body)} — the ` +
        `service account needs compute.snapshots.get on project "${project}".`,
    };
  }
  if (!response.ok || body === null) {
    return { kind: "failed", detail: `reading snapshot "${snapshotName}" failed with HTTP ${response.status}${snapshotErrorMessage(body)}.` };
  }

  const source = parseZonalDiskUrl(body.sourceDisk);
  const sameDisk = source !== null && source.project === project && source.zone === zone && source.disk === disk;
  if (!sameDisk) {
    return { kind: "other-disk" };
  }
  let status: string | null = null;
  if (typeof body.status === "string" && body.status.length > 0 && body.status.length <= 32) {
    status = body.status;
  }
  return { kind: "same-disk", status };
}

// A first snapshot of a ~10-20 GB boot disk can take minutes. One operations.wait call (up to about
// two minutes) keeps this sync op bounded; a caller polls for READY by sending the same params again.
const DISK_SNAPSHOT_WAIT_ATTEMPTS = 1;

export async function actuateGcpDiskSnapshotCreate(
  params: GcpDiskSnapshotCreateParams,
  env: Env,
): Promise<GcpDiskSnapshotCreateResult> {
  const { project, zone, instance, label } = params;
  const snapshotName = diskSnapshotNameFor(instance, label);
  const failure = (detail: string): GcpDiskSnapshotCreateResult => ({
    ok: false,
    op: "gcp-disk-snapshot-create",
    instanceName: instance,
    snapshotName,
    detail,
  });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const zonePath = `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}/zones/${encodeURIComponent(zone)}`;

  // 1. The instance, and from it the ONE boot disk. The disk name never comes from the job.
  let instanceResponse: Response;
  try {
    instanceResponse = await fetch(`${zonePath}/instances/${encodeURIComponent(instance)}`, {
      headers: gcpHeaders(token.accessToken),
    });
  } catch (err) {
    return failure(`could not reach Google Compute Engine to read instance "${instance}": ${errorMessage(err)}`);
  }
  const instanceBody = (await instanceResponse.json().catch(() => null)) as ComputeInstanceDisksResponse | null;
  if (instanceResponse.status === 404) {
    return failure(`instance "${instance}" was not found in zone ${zone} of project "${project}" — nothing was snapshotted.`);
  }
  if (instanceResponse.status === 401 || instanceResponse.status === 403) {
    return failure(
      `Google Cloud denied reading instance "${instance}" (HTTP ${instanceResponse.status})${googleErrorMessage(instanceBody)} — ` +
        `the service account needs compute.instances.get on it.`,
    );
  }
  if (!instanceResponse.ok) {
    return failure(`reading instance "${instance}" failed with HTTP ${instanceResponse.status}${googleErrorMessage(instanceBody)}.`);
  }
  const bootDisk = bootDiskOf(instanceBody, project, zone);
  if (!bootDisk.ok) {
    return failure(`refusing to snapshot: ${bootDisk.reason}.`);
  }
  const disk = bootDisk.disk;

  // 2. A snapshot under the derived name may already exist (a re-run, or the caller polling).
  const existing = await readSnapshotFor({ project, zone, disk, snapshotName, accessToken: token.accessToken });
  if (existing.kind === "failed") {
    return failure(existing.detail);
  }
  if (existing.kind === "other-disk") {
    return failure(`a snapshot named "${snapshotName}" already exists for a different disk — use another label.`);
  }
  if (existing.kind === "same-disk") {
    return {
      ok: true,
      op: "gcp-disk-snapshot-create",
      instanceName: instance,
      diskName: disk,
      snapshotName,
      status: "already-existed",
      snapshotStatus: existing.status,
    };
  }

  // 3. Create it.
  let createResponse: Response;
  try {
    createResponse = await fetch(`${zonePath}/disks/${encodeURIComponent(disk)}/createSnapshot`, {
      method: "POST",
      headers: gcpHeaders(token.accessToken),
      body: JSON.stringify({
        name: snapshotName,
        description: `doubleyoup revert point: the boot disk of ${instance} before a startup-script reboot (planning/51).`,
      }),
    });
  } catch (err) {
    return failure(`could not reach Google Compute Engine to snapshot disk "${disk}": ${errorMessage(err)}`);
  }
  const createBody = (await createResponse.json().catch(() => null)) as ComputeInsertResponse | null;

  if (createResponse.status === 409 && isAlreadyExists(createBody)) {
    // Another call created it between our read and our create. Read it once more and report that.
    const raced = await readSnapshotFor({ project, zone, disk, snapshotName, accessToken: token.accessToken });
    if (raced.kind === "same-disk") {
      return {
        ok: true,
        op: "gcp-disk-snapshot-create",
        instanceName: instance,
        diskName: disk,
        snapshotName,
        status: "already-existed",
        snapshotStatus: raced.status,
      };
    }
    return failure(`Google reports a snapshot named "${snapshotName}" already exists, but it is not a snapshot of disk "${disk}".`);
  }
  if (createResponse.status === 401 || createResponse.status === 403) {
    return failure(
      `Google Cloud denied the snapshot of disk "${disk}" (HTTP ${createResponse.status})${googleErrorMessage(createBody)} — ` +
        `the service account needs compute.disks.createSnapshot on the disk and compute.snapshots.create on project "${project}".`,
    );
  }
  if (!createResponse.ok) {
    return failure(`the snapshot of disk "${disk}" failed with HTTP ${createResponse.status}${googleErrorMessage(createBody)}.`);
  }
  const operationName = typeof createBody?.name === "string" ? createBody.name : "";
  if (operationName === "") {
    return failure(`Google accepted the snapshot of disk "${disk}" but returned no operation to follow.`);
  }

  // 4. Wait once, bounded. A wait that ends with errors is a failure. A wait that is still running
  //    is not: the snapshot was accepted, and the caller polls with the same params.
  const wait = await waitForComputeOperation({
    waitUrl: `${zonePath}/operations/${encodeURIComponent(operationName)}/wait`,
    accessToken: token.accessToken,
    what: `snapshot of disk "${disk}"`,
    maxAttempts: DISK_SNAPSHOT_WAIT_ATTEMPTS,
  });
  if (!wait.ok && wait.completed) {
    return failure(wait.detail);
  }

  const afterCreate = await readSnapshotFor({ project, zone, disk, snapshotName, accessToken: token.accessToken });
  let snapshotStatus: string | null = null;
  if (afterCreate.kind === "same-disk") {
    snapshotStatus = afterCreate.status;
  }
  return {
    ok: true,
    op: "gcp-disk-snapshot-create",
    instanceName: instance,
    diskName: disk,
    snapshotName,
    status: "created",
    snapshotStatus,
  };
}
