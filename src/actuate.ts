// Direction-B ACTUATION (agency Worker side). Runs a verified job using the AGENCY's
// OWN credentials — R2_PROVISION_API_TOKEN to create an R2 bucket, CF_DNS_API_TOKEN to
// upsert a DNS record / purge cache in one of the agency's zones, CELL_AGENT_TOKEN to run
// a wp-cli command on the agency's own cell via its on-VM cell-agent (the first "heavy"
// data-plane op), the agency's S3_* object-store credential to PRESIGN a URL the cell
// uploads a DB dump to (`db-export`) or downloads one from (`db-import`), and — for
// `gcp-instance-create` — the agency's GCP_SERVICE_ACCOUNT_KEY to mint a Google access
// token and create a Compute Engine VM in the agency's own project. There is deliberately
// NO platform credential anywhere in this Worker to fall back to: if the agency's token is
// missing or unauthorized, actuation fails cleanly rather than reaching for ours.
//
// Every actuator here runs ONLY after dispatch-verify.ts::verifyDispatch returned ok:true,
// the nonce was consumed, and the op's params validated (index.ts::handleActuate via
// ops.ts). Actuators return a structured result and NEVER throw for a Cloudflare-side
// failure: the route answers 200 with ok:false + detail so the orchestrator classifies
// the failure, not the HTTP layer.
//
// Worker-native only: fetch. Cloudflare request BODIES are always JSON.stringify'd
// objects and QUERY strings always go through URLSearchParams — no value from a job is
// ever string-interpolated into a URL.

import type { Env } from "./env.js";
import type {
  DnsRecordUpsertParams,
  CachePurgeParams,
  WpCliParams,
  DbExportParams,
  DbImportParams,
  GcpInstanceCreateParams,
} from "./dispatch-params.js";
import { presignS3Put, presignS3Get } from "./sigv4.js";
import { type ServiceAccountKey, GOOGLE_SCOPE_CLOUD_PLATFORM, mintGoogleAccessToken } from "./validators.js";
import { errorMessage, stripTrailingSlash } from "./util.js";

const CF_API = "https://api.cloudflare.com/client/v4";

export type ProvisionR2Result =
  | { ok: true; op: "provision-r2"; bucket: string; status: "created" | "already-existed"; accountId: string }
  | { ok: false; op: "provision-r2"; bucket: string; detail: string };

export type DnsRecordUpsertResult =
  | { ok: true; op: "dns-record-upsert"; action: "created" | "updated"; recordId: string; name: string }
  | { ok: false; op: "dns-record-upsert"; name: string; detail: string };

export type CachePurgeResult =
  | { ok: true; op: "cache-purge"; mode: "everything" | "files" | "hosts"; zone: string; count: number }
  | { ok: false; op: "cache-purge"; zone: string; detail: string };

export type WpCliResult =
  | { ok: true; op: "wp-cli"; exitCode: number; stdout: string; stderr: string }
  | { ok: false; op: "wp-cli"; detail: string };

// Deliberately SMALL: the dump itself never comes back through the Worker (it went cell -> object
// store), and the presigned URL is never echoed — only the key the caller already chose.
export type DbExportResult =
  | { ok: true; op: "db-export"; objectKey: string; exitCode: 0 }
  | { ok: false; op: "db-export"; objectKey: string; detail: string; exitCode?: number };

// Symmetric with DbExportResult: the dump never comes back through the Worker (it went object
// store -> cell), and the presigned URL is never echoed — only the key the caller already chose.
export type DbImportResult =
  | { ok: true; op: "db-import"; objectKey: string; exitCode: 0 }
  | { ok: false; op: "db-import"; objectKey: string; detail: string; exitCode?: number };

// instances.insert is ASYNC: a 2xx returns a long-running Operation, not the VM. Success here
// means "Google ACCEPTED the create" — `operationName` + `status` (PENDING/RUNNING/DONE) are
// what a caller polls. The minted access token is never part of either variant.
export type GcpInstanceCreateResult =
  | { ok: true; op: "gcp-instance-create"; instanceName: string; operationName: string; status: string }
  | { ok: false; op: "gcp-instance-create"; instanceName: string; detail: string };

export type ActuateResult =
  | ProvisionR2Result
  | DnsRecordUpsertResult
  | CachePurgeResult
  | WpCliResult
  | DbExportResult
  | DbImportResult
  | GcpInstanceCreateResult;

interface CloudflareEnvelope {
  success?: boolean;
  errors?: Array<{ code?: number; message?: string }>;
  result?: unknown;
}

function cloudflareHeaders(token: string): Record<string, string> {
  return {
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    accept: "application/json",
  };
}

// ── provision-r2 ───────────────────────────────────────────────────────────────────
// Mirrors the orchestrator's own ensureR2Bucket (orchestrator/src/cloudflare.ts):
// POST /accounts/{id}/r2/buckets, treating a 409 (bucket already exists) as idempotent
// success.

/**
 * Resolve the account id the R2_PROVISION_API_TOKEN belongs to. An account-owned token is
 * scoped to exactly one account, so GET /accounts?per_page=1 returns it — the same cheap,
 * account-scoped read the R2 validator already uses. Avoids a separate account-id secret.
 */
async function resolveAccountId(token: string): Promise<{ id: string } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/accounts?per_page=1`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to resolve account: ${errorMessage(err)}` };
  }

  if (response.status === 401 || response.status === 403) {
    return {
      error:
        "Cloudflare rejected R2_PROVISION_API_TOKEN — it must be an ACCOUNT-owned token (Manage Account → Account API Tokens) with Workers R2 Storage: Edit.",
    };
  }

  const body = (await response.json().catch(() => null)) as
    | { success?: boolean; result?: Array<{ id?: string }> }
    | null;
  const id = body?.success && body.result && body.result.length > 0 ? body.result[0]?.id : undefined;
  if (!id) {
    return { error: `could not resolve the token's account (HTTP ${response.status})` };
  }
  return { id };
}

/**
 * Create the R2 bucket idempotently with the agency's own token. 200/201 => created;
 * 409 (or a "bucket already exists" error code) => already-existed (idempotent success);
 * anything else => a clean failure with the CF message. NEVER falls back to a platform
 * credential (there is none).
 */
export async function actuateProvisionR2(bucketName: string, env: Env): Promise<ProvisionR2Result> {
  const token = env.R2_PROVISION_API_TOKEN;
  if (!token) {
    return {
      ok: false,
      op: "provision-r2",
      bucket: bucketName,
      detail: "R2_PROVISION_API_TOKEN is not configured on this Worker.",
    };
  }

  const account = await resolveAccountId(token);
  if ("error" in account) {
    return { ok: false, op: "provision-r2", bucket: bucketName, detail: account.error };
  }

  let response: Response;
  try {
    response = await fetch(`${CF_API}/accounts/${encodeURIComponent(account.id)}/r2/buckets`, {
      method: "POST",
      headers: cloudflareHeaders(token),
      body: JSON.stringify({ name: bucketName }),
    });
  } catch (err) {
    return {
      ok: false,
      op: "provision-r2",
      bucket: bucketName,
      detail: `could not reach Cloudflare to create the bucket: ${errorMessage(err)}`,
    };
  }

  if (response.status === 200 || response.status === 201) {
    await response.text().catch(() => "");
    return { ok: true, op: "provision-r2", bucket: bucketName, status: "created", accountId: account.id };
  }

  // 409 is the canonical "already exists". Some CF responses instead return 400 with the
  // R2 "bucket already exists" error code (10004), so treat that as idempotent too.
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  const alreadyExists =
    response.status === 409 ||
    (body?.errors ?? []).some((e) => e.code === 10004 || /already exists/i.test(e.message ?? ""));
  if (alreadyExists) {
    return {
      ok: true,
      op: "provision-r2",
      bucket: bucketName,
      status: "already-existed",
      accountId: account.id,
    };
  }

  if (response.status === 401 || response.status === 403) {
    return {
      ok: false,
      op: "provision-r2",
      bucket: bucketName,
      detail:
        "Cloudflare denied bucket creation — R2_PROVISION_API_TOKEN needs Workers R2 Storage: Edit on this account.",
    };
  }

  const message = body?.errors?.[0]?.message;
  return {
    ok: false,
    op: "provision-r2",
    bucket: bucketName,
    detail: `bucket create failed with HTTP ${response.status}${message ? `: ${message}` : ""}.`,
  };
}

// ── dns-record-upsert ──────────────────────────────────────────────────────────────
// Idempotent upsert of ONE record (type + name) in an agency zone, with the agency's own
// CF_DNS_API_TOKEN (Zone:DNS:Edit + Zone:Read):
//   1. GET  /zones?name=<zone>                       -> exactly one zone id, else fail
//   2. GET  /zones/:zid/dns_records?type=&name=      -> 0 matches => create, 1 => update
//   3. POST /zones/:zid/dns_records  |  PUT /zones/:zid/dns_records/:rid
// Two or more existing records with the same type+name (legal for TXT/A) is AMBIGUOUS —
// "update the first one" could clobber an unrelated record (an SPF TXT, a round-robin A),
// so that fails closed with a clear detail instead of guessing.
//
// Idempotency matters for replay protection (review finding F1): handleActuate BURNS the
// nonce before actuating, so a transient Cloudflare failure cannot be retried by re-POSTing
// the same signed job — the platform must re-sign with a fresh nonce. That is harmless for
// an upsert (re-running converges to the same record). A future NON-idempotent op must
// solve this deliberately (e.g. bind the nonce to a completed side effect) before it is
// added to the registry.

interface CloudflareZoneSummary {
  id?: string;
  name?: string;
}

interface CloudflareDnsRecordSummary {
  id?: string;
  name?: string;
  type?: string;
}

/** First Cloudflare error message from a response body, if any (for detail strings). */
function cloudflareErrorMessage(body: CloudflareEnvelope | null): string {
  const message = body?.errors?.[0]?.message;
  return message ? `: ${message}` : "";
}

function dnsFailure(name: string, detail: string): DnsRecordUpsertResult {
  return { ok: false, op: "dns-record-upsert", name, detail };
}

/**
 * Resolve the zone NAME to the zone id the token can see. Exactly one match is required:
 * zero means the token can't see the zone (wrong account or missing Zone:Read), more than
 * one would be ambiguous (should not happen for an exact-name filter, but never guess).
 */
async function resolveZoneId(token: string, zoneName: string): Promise<{ id: string } | { error: string }> {
  const query = new URLSearchParams({ name: zoneName, per_page: "2" });
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones?${query.toString()}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to resolve zone "${zoneName}": ${errorMessage(err)}` };
  }

  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return {
      error:
        "Cloudflare rejected CF_DNS_API_TOKEN — it needs Zone:Read + Zone:DNS:Edit on the target zone(s).",
    };
  }

  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!body?.success || !Array.isArray(body.result)) {
    return { error: `zone lookup failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  // Cloudflare's `name` filter is an exact match, but re-check the name defensively so a
  // looser server-side match can never pick a different zone.
  const zones = (body.result as CloudflareZoneSummary[]).filter((zone) => zone.name === zoneName && zone.id);
  if (zones.length === 0) {
    return {
      error: `zone "${zoneName}" is not visible to CF_DNS_API_TOKEN — check the zone name and the token's zone scope.`,
    };
  }
  if (zones.length > 1) {
    return { error: `zone lookup for "${zoneName}" returned ${zones.length} zones — refusing to guess.` };
  }
  return { id: zones[0].id as string };
}

/**
 * Find the existing record(s) with this exact type + name. Returns the full match list so
 * the caller can distinguish create (0) / update (1) / ambiguous (2+).
 */
async function findExistingRecords(
  token: string,
  zoneId: string,
  params: DnsRecordUpsertParams,
): Promise<{ records: CloudflareDnsRecordSummary[] } | { error: string }> {
  const query = new URLSearchParams({ type: params.type, name: params.name, per_page: "5" });
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zoneId)}/dns_records?${query.toString()}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to list DNS records: ${errorMessage(err)}` };
  }

  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return { error: "Cloudflare denied listing DNS records — CF_DNS_API_TOKEN needs Zone:DNS:Edit on this zone." };
  }
  if (!body?.success || !Array.isArray(body.result)) {
    return { error: `DNS record lookup failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  // Re-check type + name on each row (defensive, as with the zone lookup).
  const records = (body.result as CloudflareDnsRecordSummary[]).filter(
    (record) => record.id && record.type === params.type && record.name === params.name,
  );
  return { records };
}

/**
 * Upsert the record with the agency's own CF_DNS_API_TOKEN. Returns a structured result;
 * never throws for a Cloudflare-side failure. NEVER falls back to a platform credential
 * (there is none).
 */
export async function actuateDnsRecordUpsert(
  params: DnsRecordUpsertParams,
  env: Env,
): Promise<DnsRecordUpsertResult> {
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return dnsFailure(params.name, "CF_DNS_API_TOKEN is not configured on this Worker.");
  }

  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) {
    return dnsFailure(params.name, zone.error);
  }

  const existing = await findExistingRecords(token, zone.id, params);
  if ("error" in existing) {
    return dnsFailure(params.name, existing.error);
  }
  if (existing.records.length > 1) {
    return dnsFailure(
      params.name,
      `${existing.records.length} existing ${params.type} records already match "${params.name}" — ambiguous, refusing to update one of them.`,
    );
  }

  // The signed params are all strings by convention; Cloudflare wants real JSON types here.
  const recordBody = JSON.stringify({
    type: params.type,
    name: params.name,
    content: params.content,
    proxied: params.proxied === "true",
    ttl: Number(params.ttl),
  });

  const existingRecord = existing.records[0];
  const action: "created" | "updated" = existingRecord ? "updated" : "created";
  const url = existingRecord
    ? `${CF_API}/zones/${encodeURIComponent(zone.id)}/dns_records/${encodeURIComponent(existingRecord.id as string)}`
    : `${CF_API}/zones/${encodeURIComponent(zone.id)}/dns_records`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: existingRecord ? "PUT" : "POST",
      headers: cloudflareHeaders(token),
      body: recordBody,
    });
  } catch (err) {
    return dnsFailure(params.name, `could not reach Cloudflare to write the DNS record: ${errorMessage(err)}`);
  }

  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return dnsFailure(
      params.name,
      "Cloudflare denied the DNS write — CF_DNS_API_TOKEN needs Zone:DNS:Edit on this zone.",
    );
  }
  const written = body?.success ? (body.result as CloudflareDnsRecordSummary | undefined) : undefined;
  if (!written?.id) {
    return dnsFailure(
      params.name,
      `DNS record ${action === "created" ? "create" : "update"} failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`,
    );
  }

  return { ok: true, op: "dns-record-upsert", action, recordId: written.id, name: params.name };
}

// ── cache-purge ──────────────────────────────────────────────────────────────────────
// Purge an agency zone's Cloudflare cache with the agency's own CF_DNS_API_TOKEN (which now
// also carries Zone:Cache Purge — a deploy-time scope add, not a new secret):
//   1. GET  /zones?name=<zone>          -> exactly one zone id, else fail (reuses resolveZoneId)
//   2. POST /zones/:zid/purge_cache     -> {purge_everything:true} | {files:[...]} | {hosts:[...]}
// No new onboarding validator: like the DNS edit scope, the Cache Purge scope is exercised
// for real on the FIRST purge, which reports a clear denial (401/403) if it is missing.
//
// A cache purge is idempotent and safe to repeat, so the F1 replay-nonce note (handleActuate
// burns the nonce before actuating) does not bite here: a retry means re-signing a fresh job,
// and re-running a purge just re-evicts already-evicted content — zero additional effect.

function cachePurgeFailure(zone: string, detail: string): CachePurgeResult {
  return { ok: false, op: "cache-purge", zone, detail };
}

/**
 * Purge the zone's cache with the agency's own CF_DNS_API_TOKEN. Returns a structured result;
 * never throws for a Cloudflare-side failure. NEVER falls back to a platform credential
 * (there is none). The purge body is chosen by `params.mode` and always built with
 * JSON.stringify; the zone id is encodeURIComponent'd into the path.
 */
export async function actuateCachePurge(params: CachePurgeParams, env: Env): Promise<CachePurgeResult> {
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return cachePurgeFailure(params.zone, "CF_DNS_API_TOKEN is not configured on this Worker.");
  }

  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) {
    return cachePurgeFailure(params.zone, zone.error);
  }

  // Exactly one selector per mode. `count` is the number of targeted evictions, and 0 for a
  // whole-zone ("everything") purge — reported back so the caller can log what happened.
  let purgeBody: Record<string, unknown>;
  let count: number;
  if (params.mode === "everything") {
    purgeBody = { purge_everything: true };
    count = 0;
  } else if (params.mode === "files") {
    purgeBody = { files: params.files };
    count = params.files.length;
  } else {
    purgeBody = { hosts: params.hosts };
    count = params.hosts.length;
  }

  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zone.id)}/purge_cache`, {
      method: "POST",
      headers: cloudflareHeaders(token),
      body: JSON.stringify(purgeBody),
    });
  } catch (err) {
    return cachePurgeFailure(params.zone, `could not reach Cloudflare to purge the cache: ${errorMessage(err)}`);
  }

  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return cachePurgeFailure(
      params.zone,
      "Cloudflare denied the cache purge — CF_DNS_API_TOKEN needs Zone:Cache Purge on this zone.",
    );
  }
  if (!body?.success) {
    return cachePurgeFailure(
      params.zone,
      `cache purge failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`,
    );
  }

  return { ok: true, op: "cache-purge", mode: params.mode, zone: params.zone, count };
}

// ── wp-cli ─────────────────────────────────────────────────────────────────────────────
// The first "heavy"/data-plane Direction-B op: run a wp-cli command in a cell site's docroot
// through the agency's OWN on-VM cell-agent, authenticated with the agency's OWN
// CELL_AGENT_TOKEN. This re-authenticates, through the signed-Worker path, the exec power the
// platform's orchestrator already has directly (cells.ts::execOnCell) — so it MUST stay behind
// the same verify + single-use-nonce gate (index.ts::handleActuate). It proves the rewiring
// pattern (orchestrator -> signed job -> agency Worker -> cell-agent -> executes on the cell)
// that later carries backups/DB/migrations/provisioning.
//
// COMMAND INJECTION is the main risk here. The cell-agent runs the command we send under
// `sh -lc "cd <docroot> && <cmd>"`, so an unquoted argument is a shell-injection hole: an arg
// like `; rm -rf /` or `$(...)` would be interpreted by the shell, not handed to wp-cli. We
// defuse that by SHELL-QUOTING every argument (shellQuoteArg): each becomes exactly one literal
// wp-cli token. This per-arg quoting + the strict docroot grammar (dispatch-params.ts) are the
// load-bearing security controls of this op.
//
// F1 (retry / nonce) NOTE: wp-cli is NOT idempotent in general (e.g. `wp plugin update`), and
// handleActuate BURNS the job's nonce on receipt, so a TRANSIENT failure of a non-idempotent
// command cannot be retried by re-POSTing — it needs a re-signed job with a fresh nonce, which
// for a non-idempotent command could double-apply. The Direction-B proof deliberately uses a
// READ-ONLY command (`option get siteurl`), so F1 does not bite here. Before wiring a
// non-idempotent wp-cli use into an automatic flow, the F1 dispatcher contract (bind the nonce
// to a completed side effect, or gate re-sign on a confirmed non-effect) must land first.
//
// v1 LIMITATION: CELL_AGENT_URL / CELL_AGENT_TOKEN are SINGLE-CELL (one agency cell). A
// multi-cell agency needs per-cell resolution (a cell selector in the params + a map of
// URL/token pairs) before this op can target more than one cell.

// A conservative cap on how much stdout/stderr the Worker RELAYS BACK to the orchestrator.
// This bounds the RETURN payload ONLY — it does NOT bound the Worker's memory (by the time
// truncateOutput runs, the whole reply is already parsed in memory). Worker memory is bounded
// separately by WP_CLI_RESPONSE_MAX_BYTES below, which stops reading the stream before a huge
// reply can be buffered.
const WP_CLI_OUTPUT_MAX_CHARS = 64 * 1024;
// A HARD cap on how many bytes of the cell-agent reply the Worker will buffer at all. A signed
// command with very large output (e.g. `wp db export -`, or `wp eval` echoing a big string)
// makes the agent return a multi-MB/GB body; buffering it whole would exhaust the Worker's
// 128 MB and turn a success into a 500. We read the response as a STREAM and abort past this
// cap, failing closed rather than OOMing. GENUINELY large-output ops (DB export, media dumps)
// must stream to R2 directly, NOT return through the Worker — this op is for small-output
// commands (reads, single option writes), and this cap enforces that.
const WP_CLI_RESPONSE_MAX_BYTES = 1024 * 1024;
// The cell-agent's /exec default timeout is 60s; send the same explicit bound. A read-only
// command finishes well inside this.
const WP_CLI_EXEC_TIMEOUT_MS = 60_000;

/**
 * POSIX single-quote one argument so the cell-agent's `sh -lc` treats it as ONE literal token.
 * Inside single quotes the shell interprets EVERY character literally (no $, backtick, ;, glob,
 * or whitespace splitting); the only character single quotes cannot contain is a single quote,
 * so an embedded one is closed, escaped as \', and reopened ('\''). This is the standard,
 * complete POSIX-sh single-quoting rule — the load-bearing anti-injection control for this op.
 */
function shellQuoteArg(arg: string): string {
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

/** Truncate relayed command output to a bounded size, marking when it was cut. */
function truncateOutput(text: string): string {
  if (text.length <= WP_CLI_OUTPUT_MAX_CHARS) return text;
  return text.slice(0, WP_CLI_OUTPUT_MAX_CHARS) + "\n…[truncated]";
}

/**
 * Read a Response body as a STREAM, accumulating at most `capBytes` bytes. If the body exceeds
 * the cap, STOP reading (cancel the stream — never buffer the rest) and report overflow. This is
 * what keeps a huge cell-agent reply from exhausting the Worker's memory: we fail closed instead
 * of OOMing. On success the accumulated bytes (<= cap) are decoded to a UTF-8 string for the
 * caller to JSON.parse.
 */
async function readBodyCapped(
  response: Response,
  capBytes: number,
): Promise<{ ok: true; text: string } | { ok: false; detail: string }> {
  const stream = response.body;
  if (!stream) {
    return { ok: false, detail: "cell-agent returned no response body." };
  }
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > capBytes) {
        // Past the cap: drop what we have and stop reading — do NOT buffer the rest (the whole
        // point of the cap is that a huge reply never lands in Worker memory).
        await reader.cancel().catch(() => {});
        return {
          ok: false,
          detail: `cell-agent output exceeded ${capBytes} bytes (${Math.round(capBytes / 1024)} KiB) — this op is for small-output commands; large-output ops (e.g. wp db export) must stream to R2, not return through the Worker.`,
        };
      }
      chunks.push(value);
    }
  } catch (err) {
    return { ok: false, detail: `error reading cell-agent response: ${errorMessage(err)}` };
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(merged) };
}

function wpCliFailure(detail: string): WpCliResult {
  return { ok: false, op: "wp-cli", detail };
}

/**
 * The outcome of ONE cell-agent /exec call, as the cell ops see it: either the exec COMPLETED
 * (any exit code — interpreting it is the op's job) or the relay itself failed (unreachable,
 * redirected, auth rejected, oversized reply, agent-side error) with a ready-to-return detail.
 */
type CellAgentExecOutcome =
  | { ok: true; code: number; stdout: string; stderr: string }
  | { ok: false; detail: string };

/**
 * POST a script to the agency's cell-agent /exec and read the bounded reply. This is the ONE
 * relay both cell ops (wp-cli, db-export) share, so the fail-closed rules live in one place:
 * refuse redirects, surface an auth rejection cleanly, cap the reply in memory, and treat any
 * non-200 / non-JSON / code-less body as a cell-agent-side error rather than a completed exec.
 * The caller has already checked CELL_AGENT_URL / CELL_AGENT_TOKEN are configured.
 */
async function execOnCellAgent(
  cellAgentUrl: string,
  cellAgentToken: string,
  request: { script: string; docroot: string; timeoutMs: number },
): Promise<CellAgentExecOutcome> {
  // The exact request shape the cell-agent's /exec endpoint accepts (infra/cell-agent/agent.php):
  // POST /exec, Authorization: Bearer <token>, body { script, docroot, timeoutMs }. It answers
  // HTTP 200 with { code, stdout, stderr } even when the command's exit code is non-zero.
  let response: Response;
  try {
    response = await fetch(stripTrailingSlash(cellAgentUrl) + "/exec", {
      method: "POST",
      headers: {
        authorization: `Bearer ${cellAgentToken}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        script: request.script,
        docroot: request.docroot,
        timeoutMs: request.timeoutMs,
      }),
      // "manual", NOT "error": workerd does not implement redirect:"error" and throws at runtime
      // ("Invalid redirect value ... use manual and check the response status code"). We still
      // refuse to FOLLOW a redirect (a signed job must reach the configured cell-agent, not be
      // bounced elsewhere), so we ask for the redirect verbatim and reject it below — preserving
      // the original "don't silently follow" intent that redirect:"error" was reaching for.
      redirect: "manual",
    });
  } catch (err) {
    return { ok: false, detail: `could not reach the cell-agent /exec: ${errorMessage(err)}` };
  }

  // The cell-agent should never 3xx. With redirect:"manual" a redirect surfaces as either an
  // opaqueredirect response (status 0) or a 3xx status — treat EITHER as a fail-closed error
  // rather than following it: a redirect means a misconfigured CELL_AGENT_URL, not a valid exec.
  if (response.status === 0 || (response.status >= 300 && response.status < 400)) {
    await response.body?.cancel().catch(() => {});
    return { ok: false, detail: `cell-agent redirected unexpectedly (HTTP ${response.status}) — refusing to follow.` };
  }

  if (response.status === 401 || response.status === 403) {
    await response.body?.cancel().catch(() => {});
    return { ok: false, detail: "the cell-agent rejected CELL_AGENT_TOKEN (bearer auth failed)." };
  }

  // Read the reply as a STREAM with a hard byte cap so a very large output cannot make the
  // Worker buffer a multi-MB/GB body and exhaust its 128 MB memory (see WP_CLI_RESPONSE_MAX_BYTES).
  // The cell-agent's own error bodies (bad json / bad docroot / spawn failure) are tiny, so this
  // cap only ever trips on a genuinely huge command output — which neither cell op is for.
  const read = await readBodyCapped(response, WP_CLI_RESPONSE_MAX_BYTES);
  if (!read.ok) {
    return { ok: false, detail: read.detail };
  }

  // Only NOW parse — the buffered text is bounded (<= cap). JSON.parse needs the try/catch (no
  // non-throwing parse); a non-JSON reply is treated as a cell-agent-side error below.
  let body: { code?: number; stdout?: string; stderr?: string; error?: string } | null;
  try {
    body = JSON.parse(read.text) as { code?: number; stdout?: string; stderr?: string; error?: string };
  } catch {
    body = null;
  }

  // A non-200, a missing/non-JSON body, or a body without a numeric `code` is a cell-agent-side
  // error (bad json, bad docroot, spawn failure, ...), not a completed exec — report it as ok:false.
  if (!response.ok || !body || typeof body.code !== "number") {
    const detail = body?.error ? `: ${body.error}` : "";
    return { ok: false, detail: `cell-agent /exec failed with HTTP ${response.status}${detail}.` };
  }

  return { ok: true, code: body.code, stdout: body.stdout ?? "", stderr: body.stderr ?? "" };
}

/**
 * Run `wp <args>` in `params.docroot` on the agency's cell via the cell-agent's /exec endpoint,
 * using the agency's OWN CELL_AGENT_TOKEN. Returns a structured result; a cell-agent-side
 * failure is reported as ok:false + detail (the route still answers HTTP 200, so the
 * orchestrator classifies it), never a thrown 500. NEVER uses a platform credential (there is
 * none here). A NON-ZERO wp-cli exit is NOT a failure of this actuator — it is a successful exec
 * whose exitCode is carried back for the caller to interpret.
 */
export async function actuateWpCli(params: WpCliParams, env: Env): Promise<WpCliResult> {
  const cellAgentUrl = env.CELL_AGENT_URL;
  const cellAgentToken = env.CELL_AGENT_TOKEN;
  if (!cellAgentUrl || !cellAgentToken) {
    return wpCliFailure("CELL_AGENT_URL / CELL_AGENT_TOKEN are not configured on this Worker.");
  }

  // Build the command by shell-quoting EACH argument. Every element becomes one literal wp-cli
  // token, so a metacharacter-laden arg can never be interpreted by the cell-agent's shell.
  const command = `wp ${params.args.map(shellQuoteArg).join(" ")}`;

  const exec = await execOnCellAgent(cellAgentUrl, cellAgentToken, {
    script: command,
    docroot: params.docroot,
    timeoutMs: WP_CLI_EXEC_TIMEOUT_MS,
  });
  if (!exec.ok) {
    return wpCliFailure(exec.detail);
  }

  return {
    ok: true,
    op: "wp-cli",
    exitCode: exec.code,
    stdout: truncateOutput(exec.stdout),
    stderr: truncateOutput(exec.stderr),
  };
}

// ── db-export ──────────────────────────────────────────────────────────────────────────
// The first LARGE-OUTPUT Direction-B op: the agency's cell exports a site's WordPress DB and
// uploads the dump STRAIGHT to the agency's own object store (S3_* — R2 in practice). The dump
// flows cell -> R2 and never through this Worker (the wp-cli op's byte cap exists precisely
// because a DB dump must not come back through here). The Worker's only jobs are to:
//   1. PRESIGN a single-object PUT URL with the agency's S3_* credential (sigv4.ts::presignS3Put).
//      The URL is the ONLY thing that reaches the cell — it embeds a derived signature, NOT the
//      secret key, is valid for DB_EXPORT_PRESIGN_EXPIRES_SECONDS, and can do exactly one thing:
//      PUT that one key. No object-store credential ever lands on the cell.
//   2. Relay a short script to the cell-agent's /exec (the SAME relay wp-cli uses, with the
//      agency's own CELL_AGENT_TOKEN) that exports the DB to a temp FILE, `curl --upload-file`s
//      that file to the presigned URL, and removes the file. A file, not a stream: curl then sends
//      a Content-Length, whereas a chunked/streamed PUT can be rejected by a presigned S3 PUT.
//   3. Return a SMALL result: {ok, op, objectKey, exitCode}. Never the dump, never the URL.
//
// IDEMPOTENCY (F1): the orchestrator generates `objectKey` ONCE before its retry loop, so a
// re-signed retry after a transient failure PUTs to the SAME key — an overwrite that converges.
// That is why `db-export` is registered idempotent (AGENCY_OP_IDEMPOTENT) while wp-cli is not.
//
// TIME BUDGET: the presign expiry is the effective export+upload window — R2 checks
// X-Amz-Date + X-Amz-Expires when the PUT ARRIVES, so the export must finish and the upload
// begin within it. The exec timeout is set just inside that window. A very large DB may need a
// wider window, or a streaming/multipart approach, later.

// How long the presigned PUT stays valid, from the moment this Worker mints it.
const DB_EXPORT_PRESIGN_EXPIRES_SECONDS = 600;
// The cell-agent kills the exec at this bound. Held just inside the presign window so a slow
// export is cut off by the agent rather than left uploading to an already-expired URL.
const DB_EXPORT_EXEC_TIMEOUT_MS = 540_000;
// How much of the cell's stderr/stdout we quote into a FAILURE detail (each). Enough to see a
// mysqldump / curl error, small enough to keep the result small.
const DB_EXPORT_DETAIL_OUTPUT_MAX_CHARS = 2048;

/**
 * The POSIX-sh script the cell runs (under the cell-agent's `sh -lc "cd <docroot> && <script>"`,
 * dash on the Debian cells — so no `pipefail`, and one `;`-joined line). Steps:
 *   set -eu                       fail fast on any error or unset variable
 *   T=$(mktemp)                   a temp FILE for the dump (local /tmp, not the NFS docroot)
 *   trap 'rm -f "$T"' EXIT INT TERM  remove the dump on EVERY exit path — success, a failed
 *                                 export/upload (set -e exits still run EXIT), or a signal
 *   wp db export "$T" ...         dump the DB to the file (--add-drop-table matches the
 *                                 platform's own backup dumps; --quiet drops the success line)
 *   curl --upload-file "$T" URL   PUT the file to the presigned URL (--upload-file implies PUT
 *                                 and sends Content-Length; --fail-with-body turns an HTTP >= 400
 *                                 into a non-zero exit AND keeps the store's error body on stdout
 *                                 for the failure detail; -sS = no progress bar, errors shown)
 * The presigned URL is single-quoted (shellQuoteArg): it carries `&` and `=`, and although it is
 * Worker-generated (not attacker data) it is quoted like every other value we hand to a shell.
 */
export function buildDbExportScript(presignedUrl: string): string {
  return [
    "set -eu",
    "T=$(mktemp)",
    `trap 'rm -f "$T"' EXIT INT TERM`,
    'wp db export "$T" --add-drop-table --quiet',
    `curl -sS --fail-with-body --upload-file "$T" ${shellQuoteArg(presignedUrl)}`,
  ].join("; ");
}

/**
 * Scrub the presigned URL — and, belt-and-braces, any SigV4 query credential/signature — out of
 * text we are about to return as a failure detail. curl's error lines do not normally echo the
 * URL, but the detail must never carry a still-valid upload capability or the access-key ID.
 */
function redactPresignedUrl(text: string, presignedUrl: string): string {
  return text
    .split(presignedUrl)
    .join("[presigned-url]")
    .replace(/X-Amz-Signature=[0-9a-fA-F]+/g, "X-Amz-Signature=[redacted]")
    .replace(/X-Amz-Credential=[^&\s'"]+/g, "X-Amz-Credential=[redacted]");
}

/** Bound one output stream for inclusion in a failure detail, marking when it was cut. */
function truncateForDetail(text: string): string {
  if (text.length <= DB_EXPORT_DETAIL_OUTPUT_MAX_CHARS) return text;
  return text.slice(0, DB_EXPORT_DETAIL_OUTPUT_MAX_CHARS) + "…[truncated]";
}

function dbExportFailure(objectKey: string, detail: string, exitCode?: number): DbExportResult {
  if (exitCode === undefined) {
    return { ok: false, op: "db-export", objectKey, detail };
  }
  return { ok: false, op: "db-export", objectKey, detail, exitCode };
}

/**
 * Export the DB of the site at `params.docroot` on the agency's cell and upload it to
 * `params.objectKey` in the agency's S3_BUCKET, via a presigned PUT the cell uses. Returns a
 * structured result; every failure (missing config, presign/relay error, a non-zero exit from
 * the export or the upload) is ok:false + detail, never a thrown 500. NEVER uses a platform
 * credential (there is none here), and NEVER returns the dump or the presigned URL.
 */
export async function actuateDbExport(params: DbExportParams, env: Env): Promise<DbExportResult> {
  const objectKey = params.objectKey;

  if (!env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY || !env.S3_BUCKET) {
    return dbExportFailure(
      objectKey,
      "S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY / S3_BUCKET are not configured on this Worker.",
    );
  }
  const cellAgentUrl = env.CELL_AGENT_URL;
  const cellAgentToken = env.CELL_AGENT_TOKEN;
  if (!cellAgentUrl || !cellAgentToken) {
    return dbExportFailure(objectKey, "CELL_AGENT_URL / CELL_AGENT_TOKEN are not configured on this Worker.");
  }

  // Same store resolution as the /validate write probe (validators.ts::validateS3): a custom
  // endpoint (R2/MinIO/Wasabi) is path-style, no endpoint is real AWS; region defaults like there.
  const presigned = await presignS3Put({
    endpoint: env.S3_ENDPOINT ? stripTrailingSlash(env.S3_ENDPOINT) : undefined,
    bucket: env.S3_BUCKET,
    region: env.S3_REGION || "us-east-1",
    accessKeyId: env.S3_ACCESS_KEY_ID,
    secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    key: objectKey,
    expiresSeconds: DB_EXPORT_PRESIGN_EXPIRES_SECONDS,
  });

  const exec = await execOnCellAgent(cellAgentUrl, cellAgentToken, {
    script: buildDbExportScript(presigned.url),
    docroot: params.docroot,
    timeoutMs: DB_EXPORT_EXEC_TIMEOUT_MS,
  });
  if (!exec.ok) {
    return dbExportFailure(objectKey, exec.detail);
  }

  // Unlike wp-cli, a non-zero exit IS a failure here: `set -e` means the export or the upload
  // did not complete, so the object may be missing or partial. Quote the cell's (bounded,
  // redacted) output so the operator can see WHICH step failed and why.
  if (exec.code !== 0) {
    const outputParts: string[] = [];
    if (exec.stderr) outputParts.push(`stderr: ${truncateForDetail(exec.stderr)}`);
    if (exec.stdout) outputParts.push(`stdout: ${truncateForDetail(exec.stdout)}`);
    const output = outputParts.length > 0 ? ` — ${outputParts.join(" | ")}` : "";
    return dbExportFailure(
      objectKey,
      redactPresignedUrl(`DB export or upload failed on the cell (exit ${exec.code})${output}`, presigned.url),
      exec.code,
    );
  }

  return { ok: true, op: "db-export", objectKey, exitCode: 0 };
}

// ── db-import ────────────────────────────────────────────────────────────────────────────
// The reverse of db-export: the agency's cell DOWNLOADS a DB dump from the agency's own object
// store and loads it into the site's WordPress DB with `wp db import`. The dump flows object store
// -> cell and never through this Worker (symmetric with db-export's cell -> object store). The
// Worker's only jobs are to:
//   1. PRESIGN a single-object GET URL with the agency's S3_* credential (sigv4.ts::presignS3Get) —
//      the ONLY thing that reaches the cell: it grants exactly one GET of one key, expires, and
//      embeds a derived signature, not the secret key. No object-store credential lands on the cell.
//   2. Relay a short script to the cell-agent's /exec (the SAME relay wp-cli/db-export use, with the
//      agency's own CELL_AGENT_TOKEN) that `curl`s the dump to a temp FILE, `wp db import`s it, and
//      removes the file. The DOWNLOAD happens BEFORE the import, and `set -e` aborts on a failed
//      download — so a bad/expired URL or a missing object can never leave the DB half-replaced.
//   3. Return a SMALL result: {ok, op, objectKey, exitCode}. Never the dump, never the URL.
//
// DESTRUCTIVE + NON-IDEMPOTENT (F1): `wp db import` REPLACES the site's DB. The orchestrator
// registers db-import NON-idempotent (AGENCY_OP_IDEMPOTENT), so dispatchWithRetry runs it exactly
// once and never auto-retries a transient failure — a re-apply of a dump without DROP TABLE would
// double-insert. handleActuate burns the nonce on receipt, so a re-run needs a fresh-signed job,
// which the F1 contract deliberately withholds for a non-idempotent op.
//
// TIME BUDGET: same as db-export — the presign expiry bounds the download+import window, and the
// exec timeout is held just inside it. A very large dump may need a wider window later.

// How long the presigned GET stays valid, from the moment this Worker mints it.
const DB_IMPORT_PRESIGN_EXPIRES_SECONDS = 600;
// The cell-agent kills the exec at this bound, held just inside the presign window so a slow
// download+import is cut off by the agent rather than left reading an already-expired URL.
const DB_IMPORT_EXEC_TIMEOUT_MS = 540_000;
// How much of the cell's stderr/stdout we quote into a FAILURE detail (each). Enough to see a
// curl / wp-db-import error, small enough to keep the result small.
const DB_IMPORT_DETAIL_OUTPUT_MAX_CHARS = 2048;

/**
 * The POSIX-sh script the cell runs (under the cell-agent's `sh -lc "cd <docroot> && <script>"`,
 * dash on the Debian cells — so no `pipefail`, and one `;`-joined line). Steps:
 *   set -eu                       fail fast on any error or unset variable
 *   T=$(mktemp)                   a temp FILE for the dump (local /tmp, not the NFS docroot)
 *   trap 'rm -f "$T"' EXIT INT TERM  remove the dump on EVERY exit path — success, a failed
 *                                 download/import (set -e exits still run EXIT), or a signal
 *   curl ... -o "$T" URL          DOWNLOAD the dump to the file FIRST (--fail-with-body turns an
 *                                 HTTP >= 400 into a non-zero exit AND keeps the store's error body
 *                                 for the failure detail; -sS = no progress bar, errors shown). set
 *                                 -e means a failed download aborts BEFORE the DB is touched.
 *   wp db import "$T"             load the dump into the site's DB (only reached on a good download)
 * The presigned URL is single-quoted (shellQuoteArg): it carries `&` and `=`, and although it is
 * Worker-generated (not attacker data) it is quoted like every other value we hand to a shell.
 */
export function buildDbImportScript(presignedUrl: string): string {
  return [
    "set -eu",
    "T=$(mktemp)",
    `trap 'rm -f "$T"' EXIT INT TERM`,
    `curl -sS --fail-with-body -o "$T" ${shellQuoteArg(presignedUrl)}`,
    'wp db import "$T"',
  ].join("; ");
}

/** Bound one output stream for a db-import failure detail, marking when it was cut. */
function truncateForImportDetail(text: string): string {
  if (text.length <= DB_IMPORT_DETAIL_OUTPUT_MAX_CHARS) return text;
  return text.slice(0, DB_IMPORT_DETAIL_OUTPUT_MAX_CHARS) + "…[truncated]";
}

function dbImportFailure(objectKey: string, detail: string, exitCode?: number): DbImportResult {
  if (exitCode === undefined) {
    return { ok: false, op: "db-import", objectKey, detail };
  }
  return { ok: false, op: "db-import", objectKey, detail, exitCode };
}

/**
 * Download the dump at `params.objectKey` in the agency's S3_BUCKET and import it into the DB of the
 * site at `params.docroot` on the agency's cell, via a presigned GET the cell uses. Returns a
 * structured result; every failure (missing config, presign/relay error, a non-zero exit from the
 * download or the import) is ok:false + detail, never a thrown 500. NEVER uses a platform credential
 * (there is none here), and NEVER returns the dump or the presigned URL.
 */
export async function actuateDbImport(params: DbImportParams, env: Env): Promise<DbImportResult> {
  const objectKey = params.objectKey;

  if (!env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY || !env.S3_BUCKET) {
    return dbImportFailure(
      objectKey,
      "S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY / S3_BUCKET are not configured on this Worker.",
    );
  }
  const cellAgentUrl = env.CELL_AGENT_URL;
  const cellAgentToken = env.CELL_AGENT_TOKEN;
  if (!cellAgentUrl || !cellAgentToken) {
    return dbImportFailure(objectKey, "CELL_AGENT_URL / CELL_AGENT_TOKEN are not configured on this Worker.");
  }

  // Same store resolution as db-export / the /validate write probe: a custom endpoint
  // (R2/MinIO/Wasabi) is path-style, no endpoint is real AWS; region defaults the same way.
  const presigned = await presignS3Get({
    endpoint: env.S3_ENDPOINT ? stripTrailingSlash(env.S3_ENDPOINT) : undefined,
    bucket: env.S3_BUCKET,
    region: env.S3_REGION || "us-east-1",
    accessKeyId: env.S3_ACCESS_KEY_ID,
    secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    key: objectKey,
    expiresSeconds: DB_IMPORT_PRESIGN_EXPIRES_SECONDS,
  });

  const exec = await execOnCellAgent(cellAgentUrl, cellAgentToken, {
    script: buildDbImportScript(presigned.url),
    docroot: params.docroot,
    timeoutMs: DB_IMPORT_EXEC_TIMEOUT_MS,
  });
  if (!exec.ok) {
    return dbImportFailure(objectKey, exec.detail);
  }

  // A non-zero exit IS a failure here: `set -e` means the download or the import did not complete,
  // so the DB may be untouched (download failed first — the safe case) or partially replaced (the
  // import failed mid-file). Quote the cell's (bounded, redacted) output so the operator can see
  // WHICH step failed and why.
  if (exec.code !== 0) {
    const outputParts: string[] = [];
    if (exec.stderr) outputParts.push(`stderr: ${truncateForImportDetail(exec.stderr)}`);
    if (exec.stdout) outputParts.push(`stdout: ${truncateForImportDetail(exec.stdout)}`);
    const output = outputParts.length > 0 ? ` — ${outputParts.join(" | ")}` : "";
    return dbImportFailure(
      objectKey,
      redactPresignedUrl(`DB download or import failed on the cell (exit ${exec.code})${output}`, presigned.url),
      exec.code,
    );
  }

  return { ok: true, op: "db-import", objectKey, exitCode: 0 };
}

// ── gcp-instance-create ──────────────────────────────────────────────────────────────────
// The first GCP WRITE through Direction-B: create ONE Compute Engine VM in the AGENCY's own
// project, authenticated with the agency's own GCP_SERVICE_ACCOUNT_KEY (the same secret /validate
// probes read-only). Two steps:
//   1. Mint a Google access token from the key (validators.ts::mintGoogleAccessToken — the RS256
//      JWT-bearer grant, no SDK) with the FULL cloud-platform scope. validateGCP mints READ-ONLY;
//      this op cannot, because instances.insert is a write. The scope escalation is inherent to the
//      op and is the ONLY place the Worker asks for it. The token is per-call, lives in a local, is
//      sent only as an Authorization header to Google, and is never logged or returned.
//   2. POST projects/{project}/zones/{zone}/instances with a MINIMAL, PRIVATE body: one boot disk
//      (Debian 12, auto-delete) and one interface on the project's default VPC with NO accessConfigs
//      => NO external IP. No `serviceAccounts` either, so the VM carries no identity of its own
//      (and the create needs no iam.serviceAccounts.actAs). This is a proof VM, not a host.
//
// INJECTION SURFACE: `project` + `zone` are URL path segments, and all four params land in the
// JSON body. They pass the strict grammars in dispatch-params.ts first (no "/", ".", "?", "#",
// whitespace), then go through encodeURIComponent + JSON.stringify here — belt and braces.
//
// ASYNC: a 2xx is a long-running Operation ({name, status, ...}), not the VM. We report ACCEPTED
// (ok:true + the operation) and leave polling to the caller. A non-2xx (403 missing permission,
// 404 no such project/zone/network, 409 name taken) is a TERMINAL ok:false carrying Google's own
// message — the orchestrator classifies a 200 ok:false as actuated-failure and never retries it.
//
// NON-IDEMPOTENT (F1): a second insert of the same name is a 409, and a lost response may already
// have created the VM. The orchestrator registers this op `false` in AGENCY_OP_IDEMPOTENT, so
// dispatchWithRetry runs it exactly once and never auto-retries a transient failure (like db-import).

const GCP_COMPUTE_API = "https://compute.googleapis.com/compute/v1";
// The boot image every proof VM is created from: Debian 12 from Google's public debian-cloud
// project, addressed by image FAMILY so it always resolves to the current patched image.
const GCP_INSTANCE_BOOT_IMAGE = "projects/debian-cloud/global/images/family/debian-12";
const GOOGLE_DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";

/**
 * What instances.insert answers with. A 2xx is an Operation (`name`, `status`, and — only once
 * DONE with a failure — `error.errors`); a non-2xx is Google's standard error envelope
 * (`error.message`). One shape covers both so a single parse serves both paths.
 */
interface ComputeInsertResponse {
  name?: string;
  status?: string;
  error?: {
    message?: string;
    errors?: Array<{ code?: string; message?: string }>;
  };
}

function gcpInstanceCreateFailure(instanceName: string, detail: string): GcpInstanceCreateResult {
  return { ok: false, op: "gcp-instance-create", instanceName, detail };
}

/** Google's top-level error message from a response body, if any (for detail strings). */
function googleErrorMessage(body: ComputeInsertResponse | null): string {
  const message = body?.error?.message;
  return message ? `: ${message}` : "";
}

/**
 * Create the VM described by `params` in the agency's own project with the agency's own
 * GCP_SERVICE_ACCOUNT_KEY. Returns a structured result; every failure (missing/malformed key, a
 * token-mint failure, an unreachable API, a non-2xx from Google) is ok:false + detail, never a
 * thrown 500. NEVER uses a platform credential (there is none here), and NEVER returns or logs the
 * minted access token.
 */
export async function actuateGcpInstanceCreate(
  params: GcpInstanceCreateParams,
  env: Env,
): Promise<GcpInstanceCreateResult> {
  const instanceName = params.name;

  if (!env.GCP_SERVICE_ACCOUNT_KEY) {
    return gcpInstanceCreateFailure(instanceName, "GCP_SERVICE_ACCOUNT_KEY is not configured on this Worker.");
  }
  // Parse the key the same way validateGCP does. JSON.parse needs the try/catch (no non-throwing
  // parse); a non-object result (e.g. the literal `null`) is treated as malformed too.
  let key: ServiceAccountKey | null;
  try {
    key = JSON.parse(env.GCP_SERVICE_ACCOUNT_KEY) as ServiceAccountKey | null;
  } catch {
    key = null;
  }
  if (!key || typeof key !== "object") {
    return gcpInstanceCreateFailure(
      instanceName,
      "GCP_SERVICE_ACCOUNT_KEY is not valid JSON — it must be the entire downloaded service-account key file.",
    );
  }
  const clientEmail = key.client_email;
  const privateKeyPem = key.private_key;
  if (!clientEmail || !privateKeyPem) {
    return gcpInstanceCreateFailure(
      instanceName,
      "GCP_SERVICE_ACCOUNT_KEY is missing client_email or private_key — use a service-account key, not an OAuth client ID.",
    );
  }
  // PIN the target to the key's OWN project (review defense-in-depth). Cross-tenant is already
  // impossible — the SA key IS the tenant boundary, so a job can never reach another agency's
  // project (403) — but this makes the code ENFORCE the "in the agency's own project" guarantee the
  // op claims, so a signed job cannot create a VM in some other project the agency's SA happens to
  // hold IAM in. Reject BEFORE minting any token or making any call.
  if (!key.project_id || params.project !== key.project_id) {
    return gcpInstanceCreateFailure(
      instanceName,
      `project "${params.project}" does not match the service-account key's own project` +
        `${key.project_id ? ` ("${key.project_id}")` : ""} — a VM is only created in the agency's own project.`,
    );
  }
  const tokenUri = key.token_uri || GOOGLE_DEFAULT_TOKEN_URI;

  // FULL cloud-platform scope — the write scope this op needs (see the section note). The token
  // stays in this local and goes only into the Authorization header below.
  let accessToken: string;
  try {
    accessToken = await mintGoogleAccessToken({
      clientEmail,
      privateKeyPem,
      tokenUri,
      scope: GOOGLE_SCOPE_CLOUD_PLATFORM,
    });
  } catch (err) {
    return gcpInstanceCreateFailure(
      instanceName,
      `could not mint a Google access token from GCP_SERVICE_ACCOUNT_KEY: ${errorMessage(err)}`,
    );
  }

  // The two path segments are grammar-checked upstream AND URL-encoded here; the body is built
  // with JSON.stringify from the four validated fields only.
  const url =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(params.project)}` +
    `/zones/${encodeURIComponent(params.zone)}/instances`;
  const instanceBody = JSON.stringify({
    name: instanceName,
    machineType: `zones/${params.zone}/machineTypes/${params.machineType}`,
    disks: [
      {
        boot: true,
        autoDelete: true,
        initializeParams: { sourceImage: GCP_INSTANCE_BOOT_IMAGE },
      },
    ],
    // ONE interface on the default VPC and deliberately NO accessConfigs => no external IP.
    networkInterfaces: [{ network: "global/networks/default" }],
  });

  // Default redirect handling, NOT redirect:"error" — workerd throws on that value at runtime
  // (the gotcha the cell-agent relay above documents). Google's API does not redirect.
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: instanceBody,
    });
  } catch (err) {
    return gcpInstanceCreateFailure(
      instanceName,
      `could not reach Google Compute Engine to create the instance: ${errorMessage(err)}`,
    );
  }

  const body = (await response.json().catch(() => null)) as ComputeInsertResponse | null;

  if (response.ok) {
    // A 2xx must carry an Operation. Its ABSENCE means we cannot confirm Google accepted the
    // create, so fail closed rather than report a success we cannot point at.
    const operationName = body?.name;
    if (!operationName) {
      return gcpInstanceCreateFailure(
        instanceName,
        `Compute Engine returned HTTP ${response.status} but no operation — cannot confirm the instance create was accepted.`,
      );
    }
    // An insert normally returns PENDING/RUNNING; if Google ever answers with an already-DONE
    // operation that carries errors, that is a failed create, not a success.
    const operationErrors = body?.error?.errors ?? [];
    if (operationErrors.length > 0) {
      const messages = operationErrors.map((entry) => entry.message ?? entry.code ?? "unknown error").join("; ");
      return gcpInstanceCreateFailure(instanceName, `instance create operation ${operationName} failed: ${messages}.`);
    }
    return {
      ok: true,
      op: "gcp-instance-create",
      instanceName,
      operationName,
      status: body?.status ?? "UNKNOWN",
    };
  }

  if (response.status === 401 || response.status === 403) {
    return gcpInstanceCreateFailure(
      instanceName,
      `Google Cloud denied the instance create (HTTP ${response.status})${googleErrorMessage(body)} — the service account ` +
        `needs compute.instances.create (e.g. roles/compute.instanceAdmin.v1) on project "${params.project}".`,
    );
  }
  if (response.status === 409) {
    // Unlike provision-r2's "already exists", this is a FAILURE: the op is a create of a NEW named
    // VM, and a name collision means either a stale VM to clean up or a caller bug — never a
    // converged success to report as ok.
    return gcpInstanceCreateFailure(
      instanceName,
      `an instance named "${instanceName}" already exists in ${params.project}/${params.zone}${googleErrorMessage(body)} — ` +
        "instance create is not idempotent; pick a new name or delete the existing VM first.",
    );
  }

  return gcpInstanceCreateFailure(
    instanceName,
    `instance create failed with HTTP ${response.status}${googleErrorMessage(body)}.`,
  );
}
