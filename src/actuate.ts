// Direction-B ACTUATION (agency Worker side). Runs a verified job using the AGENCY's
// OWN credentials — R2_PROVISION_API_TOKEN to create an R2 bucket, CF_DNS_API_TOKEN to
// upsert a DNS record / purge cache in one of the agency's zones, and (the first "heavy"
// data-plane op) CELL_AGENT_TOKEN to run a wp-cli command on the agency's own cell via its
// on-VM cell-agent. There is deliberately NO platform credential anywhere in this Worker to
// fall back to: if the agency's token is missing or unauthorized, actuation fails cleanly
// rather than reaching for ours.
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
import type { DnsRecordUpsertParams, CachePurgeParams, WpCliParams } from "./dispatch-params.js";
import { errorMessage } from "./util.js";

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

export type ActuateResult = ProvisionR2Result | DnsRecordUpsertResult | CachePurgeResult | WpCliResult;

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

// A conservative cap on how much stdout/stderr the Worker relays back. wp-cli output can be
// large (e.g. a DB export echoed to stdout); truncate so the actuate response stays bounded.
const WP_CLI_OUTPUT_MAX_CHARS = 64 * 1024;
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

function wpCliFailure(detail: string): WpCliResult {
  return { ok: false, op: "wp-cli", detail };
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

  // The exact request shape the cell-agent's /exec endpoint accepts (infra/cell-agent/agent.php):
  // POST /exec, Authorization: Bearer <token>, body { script, docroot, timeoutMs }. It answers
  // HTTP 200 with { code, stdout, stderr } even when the command's exit code is non-zero.
  let response: Response;
  try {
    response = await fetch(cellAgentUrl.replace(/\/+$/, "") + "/exec", {
      method: "POST",
      headers: {
        authorization: `Bearer ${cellAgentToken}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        script: command,
        docroot: params.docroot,
        timeoutMs: WP_CLI_EXEC_TIMEOUT_MS,
      }),
      redirect: "error",
    });
  } catch (err) {
    return wpCliFailure(`could not reach the cell-agent to run wp-cli: ${errorMessage(err)}`);
  }

  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return wpCliFailure("the cell-agent rejected CELL_AGENT_TOKEN (bearer auth failed).");
  }

  const body = (await response.json().catch(() => null)) as
    | { code?: number; stdout?: string; stderr?: string; error?: string }
    | null;

  // A non-200, a missing body, or a body without a numeric `code` is a cell-agent-side error
  // (bad json, bad docroot, spawn failure, ...), not a completed exec — report it as ok:false.
  if (!response.ok || !body || typeof body.code !== "number") {
    const detail = body?.error ? `: ${body.error}` : "";
    return wpCliFailure(`cell-agent /exec failed with HTTP ${response.status}${detail}.`);
  }

  return {
    ok: true,
    op: "wp-cli",
    exitCode: body.code,
    stdout: truncateOutput(body.stdout ?? ""),
    stderr: truncateOutput(body.stderr ?? ""),
  };
}
