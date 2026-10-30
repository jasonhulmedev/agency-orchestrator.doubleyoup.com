// hub#43 ACTUATION (agency Worker side) — agency-owned media.
//
//   r2-media-buckets      READ the names of the buckets in this account (names only).
//   r2-media-state        READ whether one media bucket exists, and the keys this op family minted for it.
//   r2-site-key-install   MINT one bucket-scoped read-write key in the agency's own Cloudflare account and
//                         STAGE it on the site's file node, straight from this Worker to the agency's own
//                         cell-agent. The key value is not returned to the platform in the answer.
//   r2-site-key-revoke    DELETE one such key.
//
// Everything runs on the agency's OWN R2_PROVISION_API_TOKEN (an account-owned token that can create
// buckets and API tokens) and the agency's own file-node cell-agent. The platform does not hold the R2 token.
// Caveat: the platform does hold the agency cell-agent bearer tokens (to run scripts on the agency's nodes), so "the
// platform never sees the key" means only that no answer of this op carries it.
//
// WHICH FILE-NODE AGENT. The signed install job names it (fileAgentUrl + fileAgentToken): the platform derives the
// token from the site's own cell, so no agency can configure it here. app signs the pair only for a file-agent host
// of that cell. The job's pair wins. CELL_FILE_AGENT_URL / CELL_FILE_AGENT_TOKEN are an OPTIONAL fallback, used only
// for a job without the pair (from a platform older than these params). With neither, the install refuses before
// it mints. The token is never repeated in an answer.
//
// WHY THE KEY GOES WORKER -> FILE NODE. hub#43 (decided 2026-10-08): the platform does not hold a write key
// to the agency's account again (no key value is handed to it). The earlier copy ran with such a key on the platform's VM and the key had
// to be revoked by hand. Here the Worker mints the key and posts it to the file node's /set-r2-target
// endpoint (mode "stage"), which writes DOUBLEYOUP_R2_NEXT_* into the site's locked wp-config. The answer
// this op returns holds the key's id and name, never its value.
//
// THE KEY'S SCOPE. One bucket, Object Read & Write ("Workers R2 Storage Bucket Item Write",
// 2efd5506f9c8494dacb1fa10a3e7d5b6), the same permission group and resource key the platform's own
// per-site keys use; the platform proved on 2026-08-19 that Cloudflare enforces the bucket scope
// (orchestrator scripts/verify-r2-scoping.ts). The S3 secret is sha256(token value) and the access key
// id is the token id.
//
// NOT IDEMPOTENT. Every install mints a NEW key (a key's value can only be read once, at creation, so
// "find the old one" cannot return its secret) and never deletes an older one: a site that already runs
// on the older key must not lose it because an install ran again. Keys are named
// `dy-media-<bucket>-<label>`; r2-media-state lists them and r2-site-key-revoke deletes one by id after
// the caller has proven it is not the live key. If the stage step fails, the key just minted is deleted
// again, so a refusal leaves nothing behind.
//
// FAIL CLOSED. A response this code does not fully understand is ok:false with the reason.

import type { Env } from "./env.js";
import {
  r2SiteKeyNameFor,
  type R2MediaBucketsParams,
  type R2MediaStateParams,
  type R2SiteKeyInstallParams,
  type R2SiteKeyRevokeParams,
} from "./dispatch-params.js";
import { CF_API, cloudflareErrorMessage, cloudflareHeaders, readBodyCapped, resolveAccountId, type CloudflareEnvelope } from "./actuate.js";
import { errorMessage, stripTrailingSlash } from "./util.js";

/** "Workers R2 Storage Bucket Item Write": read, write and list objects within ONE bucket. */
export const R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID = "2efd5506f9c8494dacb1fa10a3e7d5b6";

const AGENT_REPLY_MAX_BYTES = 64 * 1024;
const TOKEN_LIST_PAGE_SIZE = 50;
const TOKEN_LIST_MAX_PAGES = 20;

export interface R2MediaKeySummary {
  tokenId: string;
  name: string;
  /** ISO time the key was issued, when Cloudflare reports it. */
  issuedOn: string | null;
}

export type R2MediaStateResult =
  | {
      ok: true;
      op: "r2-media-state";
      bucket: string;
      bucketExists: boolean;
      accountId: string;
      endpointHost: string;
      /** false when the token cannot list API tokens: `keys` is then empty and says nothing. */
      keysReadable: boolean;
      keys: R2MediaKeySummary[];
    }
  | { ok: false; op: "r2-media-state"; bucket: string; detail: string };

export type R2MediaBucketsResult =
  | {
      ok: true;
      op: "r2-media-buckets";
      accountId: string;
      endpointHost: string;
      /** Bucket names only, sorted. True when the list was cut at the cap: it may be incomplete. */
      buckets: string[];
      truncated: boolean;
    }
  | { ok: false; op: "r2-media-buckets"; detail: string };

export type R2SiteKeyInstallResult =
  | {
      ok: true;
      op: "r2-site-key-install";
      bucket: string;
      tokenId: string;
      tokenName: string;
      endpointHost: string;
      /** The marker hash the file node computed for the staged target (no secret). */
      stagedHex: string | null;
    }
  | {
      ok: false;
      op: "r2-site-key-install";
      bucket: string;
      detail: string;
      /**
       * Set ONLY when the answer of the file-node agent was ambiguous (a throw, a 5xx or 524, a body that is not
       * JSON). The key was minted and may or may not be staged, so it is NOT deleted here: the caller reads
       * the staged key id from the file node and the key list from r2-media-state, and settles it.
       */
      maybeStagedKeyId?: string;
      maybeStagedKeyName?: string;
    };

export type R2SiteKeyRevokeResult =
  | { ok: true; op: "r2-site-key-revoke"; bucket: string; tokenId: string; status: "revoked" | "already-absent" }
  | { ok: false; op: "r2-site-key-revoke"; bucket: string; detail: string };

function endpointHostFor(accountId: string): string {
  return `${accountId}.r2.cloudflarestorage.com`;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  let hex = "";
  for (const byte of digest) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

async function cfJson(
  method: string,
  path: string,
  token: string,
  body?: unknown,
): Promise<{ status: number; envelope: CloudflareEnvelope | null } | { error: string }> {
  try {
    const response = await fetch(`${CF_API}${path}`, {
      method,
      headers: cloudflareHeaders(token),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const envelope = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
    return { status: response.status, envelope };
  } catch (err) {
    return { error: `could not reach Cloudflare: ${errorMessage(err)}` };
  }
}

const TOKEN_UNAUTHORIZED_HINT =
  "Cloudflare denied the request: R2_PROVISION_API_TOKEN must be an ACCOUNT-owned token with Workers R2 Storage: Edit and Account API Tokens: Edit.";

interface TokenRecord {
  id?: string;
  name?: string;
  issued_on?: string;
}

/**
 * hub#43 M3: a key name belongs to a bucket only when what follows `dy-media-<bucket>-` is exactly the label
 * shape. Prefixes with hyphens exist (docs and docs-892769, rareepicgamer and rareepicgamer-19f933): a plain
 * startsWith would let the key of `docs-892769` count as a key of `docs`.
 */
export function keyNameBelongsToBucket(name: string, bucket: string): boolean {
  const namePrefix = `dy-media-${bucket}-`;
  if (!name.startsWith(namePrefix)) return false;
  return /^[a-z0-9]{1,16}$/.test(name.slice(namePrefix.length));
}

/**
 * hub#43 L7: resolve the account of the token, and when R2_EXPECTED_ACCOUNT_ID is configured, refuse a token that
 * belongs to any other account (a wrong token pasted into the Worker must not mint keys somewhere else).
 */
async function resolveMediaAccount(token: string, env: Env): Promise<{ id: string } | { error: string }> {
  const account = await resolveAccountId(token, TOKEN_UNAUTHORIZED_HINT);
  if ("error" in account) {
    return account;
  }
  const expected = env.R2_EXPECTED_ACCOUNT_ID;
  if (typeof expected === "string" && expected !== "" && expected.toLowerCase() !== account.id.toLowerCase()) {
    return { error: "R2_PROVISION_API_TOKEN belongs to a different Cloudflare account than R2_EXPECTED_ACCOUNT_ID: refusing." };
  }
  return account;
}

async function listMediaKeys(
  accountId: string,
  token: string,
  bucket: string,
): Promise<{ readable: boolean; keys: R2MediaKeySummary[] } | { error: string }> {
  const keys: R2MediaKeySummary[] = [];
  for (let page = 1; page <= TOKEN_LIST_MAX_PAGES; page += 1) {
    const reply = await cfJson("GET", `/accounts/${encodeURIComponent(accountId)}/tokens?page=${page}&per_page=${TOKEN_LIST_PAGE_SIZE}`, token);
    if ("error" in reply) {
      return { error: reply.error };
    }
    if (reply.status === 401 || reply.status === 403) {
      // The token cannot read API tokens. Say so; do not pretend there are none.
      return { readable: false, keys: [] };
    }
    if (reply.status !== 200 || !reply.envelope?.success || !Array.isArray(reply.envelope.result)) {
      return { error: `listing API tokens failed with HTTP ${reply.status}${cloudflareErrorMessage(reply.envelope)}` };
    }
    const records = reply.envelope.result as TokenRecord[];
    for (const record of records) {
      if (typeof record.id === "string" && typeof record.name === "string" && keyNameBelongsToBucket(record.name, bucket)) {
        keys.push({ tokenId: record.id, name: record.name, issuedOn: typeof record.issued_on === "string" ? record.issued_on : null });
      }
    }
    if (records.length < TOKEN_LIST_PAGE_SIZE) {
      return { readable: true, keys };
    }
  }
  return { error: `more than ${TOKEN_LIST_MAX_PAGES * TOKEN_LIST_PAGE_SIZE} API tokens: refusing to guess which belong to ${bucket}` };
}

async function bucketExists(accountId: string, token: string, bucket: string): Promise<boolean | { error: string }> {
  const reply = await cfJson("GET", `/accounts/${encodeURIComponent(accountId)}/r2/buckets/${encodeURIComponent(bucket)}`, token);
  if ("error" in reply) {
    return { error: reply.error };
  }
  if (reply.status === 404) {
    return false;
  }
  if (reply.status === 401 || reply.status === 403) {
    return { error: TOKEN_UNAUTHORIZED_HINT };
  }
  if (reply.status === 200 && reply.envelope?.success) {
    return true;
  }
  return { error: `reading the bucket failed with HTTP ${reply.status}${cloudflareErrorMessage(reply.envelope)}` };
}

export async function readR2MediaState(params: R2MediaStateParams, env: Env): Promise<R2MediaStateResult> {
  const token = env.R2_PROVISION_API_TOKEN;
  if (!token) {
    return { ok: false, op: "r2-media-state", bucket: params.bucket, detail: "R2_PROVISION_API_TOKEN is not configured on this Worker." };
  }
  const account = await resolveMediaAccount(token, env);
  if ("error" in account) {
    return { ok: false, op: "r2-media-state", bucket: params.bucket, detail: account.error };
  }
  const exists = await bucketExists(account.id, token, params.bucket);
  if (typeof exists === "object") {
    return { ok: false, op: "r2-media-state", bucket: params.bucket, detail: exists.error };
  }
  const keys = await listMediaKeys(account.id, token, params.bucket);
  if ("error" in keys) {
    return { ok: false, op: "r2-media-state", bucket: params.bucket, detail: keys.error };
  }
  return {
    ok: true,
    op: "r2-media-state",
    bucket: params.bucket,
    bucketExists: exists,
    accountId: account.id,
    endpointHost: endpointHostFor(account.id),
    keysReadable: keys.readable,
    keys: keys.keys,
  };
}

async function deleteToken(accountId: string, token: string, tokenId: string): Promise<boolean> {
  const reply = await cfJson("DELETE", `/accounts/${encodeURIComponent(accountId)}/tokens/${encodeURIComponent(tokenId)}`, token);
  if ("error" in reply) {
    return false;
  }
  return reply.status === 200 || reply.status === 404;
}

/** The file-node cell-agent the install posts the new key to, and where the pair came from. */
interface FileAgentTarget {
  url: string;
  token: string;
  /** "job" = the signed job's fileAgentUrl + fileAgentToken; "worker-secrets" = CELL_FILE_AGENT_URL / _TOKEN. */
  source: "job" | "worker-secrets";
}

/**
 * The job's pair when it carries BOTH keys, else the Worker's own pair when BOTH secrets are set, else null.
 * A pair is never mixed across the two sources: a URL from one with a token from the other would post the
 * key with a bearer the host was never meant to get.
 */
function fileAgentTargetFor(params: R2SiteKeyInstallParams, env: Env): FileAgentTarget | null {
  if (params.fileAgentUrl && params.fileAgentToken) {
    return { url: params.fileAgentUrl, token: params.fileAgentToken, source: "job" };
  }
  if (env.CELL_FILE_AGENT_URL && env.CELL_FILE_AGENT_TOKEN) {
    return { url: env.CELL_FILE_AGENT_URL, token: env.CELL_FILE_AGENT_TOKEN, source: "worker-secrets" };
  }
  return null;
}

export async function actuateR2SiteKeyInstall(params: R2SiteKeyInstallParams, env: Env): Promise<R2SiteKeyInstallResult> {
  const failure = (detail: string): R2SiteKeyInstallResult => ({ ok: false, op: "r2-site-key-install", bucket: params.bucket, detail });
  const token = env.R2_PROVISION_API_TOKEN;
  if (!token) {
    return failure("R2_PROVISION_API_TOKEN is not configured on this Worker.");
  }
  const fileAgent = fileAgentTargetFor(params, env);
  if (fileAgent === null) {
    // Refuse BEFORE minting: a key with nowhere to go is a leak waiting to happen.
    return failure(
      "the signed job names no file-node cell-agent (fileAgentUrl / fileAgentToken), and CELL_FILE_AGENT_URL / CELL_FILE_AGENT_TOKEN are not configured on this Worker (the file node's cell-agent).",
    );
  }

  const account = await resolveMediaAccount(token, env);
  if ("error" in account) {
    return failure(account.error);
  }
  const exists = await bucketExists(account.id, token, params.bucket);
  if (typeof exists === "object") {
    return failure(exists.error);
  }
  if (!exists) {
    return failure(`the bucket ${params.bucket} does not exist in this account: run provision-r2 first.`);
  }

  // Mint ONE key scoped to THIS bucket only.
  const tokenName = r2SiteKeyNameFor(params.bucket, params.label);
  const resourceKey = `com.cloudflare.edge.r2.bucket.${account.id}_default_${params.bucket}`;
  const minted = await cfJson("POST", `/accounts/${encodeURIComponent(account.id)}/tokens`, token, {
    name: tokenName,
    policies: [
      {
        effect: "allow",
        permission_groups: [{ id: R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID }],
        resources: { [resourceKey]: "*" },
      },
    ],
  });
  if ("error" in minted) {
    return failure(minted.error);
  }
  if (minted.status === 401 || minted.status === 403) {
    return failure(TOKEN_UNAUTHORIZED_HINT);
  }
  const record = (minted.envelope?.result ?? null) as { id?: string; value?: string } | null;
  if (minted.status !== 200 || !minted.envelope?.success || !record || typeof record.id !== "string" || typeof record.value !== "string" || record.value === "") {
    // hub#43 L10: a token that came back WITHOUT a value cannot be used, and it exists. Delete it.
    if (record && typeof record.id === "string" && record.id !== "") {
      const removedEmpty = await deleteToken(account.id, token, record.id);
      return failure(
        `creating the key failed with HTTP ${minted.status}${cloudflareErrorMessage(minted.envelope)}: the answer had no key value. ${removedEmpty ? "The empty token was deleted again." : `The token ${record.id} could NOT be deleted: revoke it.`}`,
      );
    }
    return failure(`creating the key failed with HTTP ${minted.status}${cloudflareErrorMessage(minted.envelope)}`);
  }
  const tokenId = record.id;
  const accessKeyId = tokenId;
  const secretAccessKey = await sha256Hex(record.value);

  // Stage it on the file node. redirect:"manual": a redirect means a wrong file-agent URL, and following it would
  // send the key and the bearer to another host. workerd's fetch has no redirect:"error" (it throws on that value),
  // so "manual" is the only way to refuse, and the status check below refuses every 3xx and the opaque status 0.
  let response: Response;
  try {
    response = await fetch(`${stripTrailingSlash(fileAgent.url)}/set-r2-target`, {
      method: "POST",
      headers: { authorization: `Bearer ${fileAgent.token}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        slug: params.slug,
        mode: "stage",
        bucket: params.bucket,
        endpoint: `https://${endpointHostFor(account.id)}`,
        mediaHost: params.mediaHost,
        mediaBase: `https://${params.mediaHost}/${params.prefix}`,
        key: accessKeyId,
        secret: secretAccessKey,
      }),
      redirect: "manual",
    });
  } catch (err) {
    // AMBIGUOUS: the request may have reached the agent and staged the key. Do NOT delete it. Hand the id back.
    return {
      ok: false,
      op: "r2-site-key-install",
      bucket: params.bucket,
      detail: `could not read the answer of the file-node cell-agent /set-r2-target: ${errorMessage(err)}. The key ${tokenId} was minted and MAY be staged: it was not deleted. Read the staged key id and the key list before doing anything else.`,
      maybeStagedKeyId: tokenId,
      maybeStagedKeyName: tokenName,
    };
  }

  // hub#43 H3. Only a DEFINITE refusal deletes the new key: a redirect or a 4xx (the agent did not take the
  // request), or the agent's own JSON `ok: false`. Anything else (5xx, 524, a body that is not JSON, a body
  // that cannot be read) is AMBIGUOUS: the key may be staged, so it is kept and its id is handed back.
  let stagedHex: string | null = null;
  let stageDetail = "";
  let staged = false;
  let definiteRefusal = false;
  if (response.status === 0 || (response.status >= 300 && response.status < 400)) {
    await response.body?.cancel().catch(() => {});
    stageDetail = `the file-node cell-agent redirected (HTTP ${response.status}): refusing to follow.`;
    definiteRefusal = true;
  } else if (response.status >= 400 && response.status < 500) {
    await response.body?.cancel().catch(() => {});
    // Name the token by its SOURCE, never by its value.
    let rejectedTokenName = "CELL_FILE_AGENT_TOKEN";
    if (fileAgent.source === "job") {
      rejectedTokenName = "the fileAgentToken of the signed job";
    }
    stageDetail =
      response.status === 401 || response.status === 403
        ? `the file-node cell-agent rejected ${rejectedTokenName} (bearer auth failed).`
        : `the file-node cell-agent refused the request (HTTP ${response.status}).`;
    definiteRefusal = true;
  } else {
    const read = await readBodyCapped(response, AGENT_REPLY_MAX_BYTES);
    if (!read.ok) {
      stageDetail = read.detail;
    } else {
      let body: { ok?: boolean; error?: string; stderr?: string; staged?: { hex?: string | null } | null } | null = null;
      try {
        body = JSON.parse(read.text);
      } catch {
        body = null;
      }
      if (response.ok && body && body.ok === true) {
        staged = true;
        stagedHex = typeof body.staged?.hex === "string" ? body.staged.hex : null;
      } else {
        // The agent's refusal text carries reasons only; it never echoes a key. Cap it anyway.
        const reason = body?.error ? `: ${body.error}` : "";
        const stderr = body?.stderr ? ` (${String(body.stderr).slice(0, 300)})` : "";
        stageDetail = `the file-node cell-agent did not confirm staging (HTTP ${response.status}${reason}${stderr}).`;
        if (body !== null && body.ok === false) {
          definiteRefusal = true;
        }
      }
    }
  }
  if (!staged && definiteRefusal) {
    const removed = await deleteToken(account.id, token, tokenId);
    return failure(`${stageDetail} ${removed ? "The new key was deleted again, nothing is left behind." : `The new key ${tokenId} could NOT be deleted: it is an orphan the caller revokes.`}`);
  }
  if (!staged) {
    return {
      ok: false,
      op: "r2-site-key-install",
      bucket: params.bucket,
      detail: `${stageDetail} The key ${tokenId} was minted and MAY be staged: it was not deleted. Read the staged key id and the key list before doing anything else.`,
      maybeStagedKeyId: tokenId,
      maybeStagedKeyName: tokenName,
    };
  }
  return {
    ok: true,
    op: "r2-site-key-install",
    bucket: params.bucket,
    tokenId,
    tokenName,
    endpointHost: endpointHostFor(account.id),
    stagedHex,
  };
}

export async function actuateR2SiteKeyRevoke(params: R2SiteKeyRevokeParams, env: Env): Promise<R2SiteKeyRevokeResult> {
  const failure = (detail: string): R2SiteKeyRevokeResult => ({ ok: false, op: "r2-site-key-revoke", bucket: params.bucket, detail });
  const token = env.R2_PROVISION_API_TOKEN;
  if (!token) {
    return failure("R2_PROVISION_API_TOKEN is not configured on this Worker.");
  }
  const account = await resolveMediaAccount(token, env);
  if ("error" in account) {
    return failure(account.error);
  }
  // Read the key first: only a key whose NAME proves this op family minted it for THIS bucket may be deleted.
  // This op can never revoke the Worker's own token, a backup key or another bucket's key.
  const read = await cfJson("GET", `/accounts/${encodeURIComponent(account.id)}/tokens/${encodeURIComponent(params.tokenId)}`, token);
  if ("error" in read) {
    return failure(read.error);
  }
  if (read.status === 404) {
    return { ok: true, op: "r2-site-key-revoke", bucket: params.bucket, tokenId: params.tokenId, status: "already-absent" };
  }
  if (read.status === 401 || read.status === 403) {
    return failure(TOKEN_UNAUTHORIZED_HINT);
  }
  const record = (read.envelope?.result ?? null) as TokenRecord | null;
  if (read.status !== 200 || !read.envelope?.success || !record || typeof record.name !== "string") {
    return failure(`reading the key failed with HTTP ${read.status}${cloudflareErrorMessage(read.envelope)}`);
  }
  if (!keyNameBelongsToBucket(record.name, params.bucket)) {
    return failure(`the key's name does not show that this op family minted it for ${params.bucket}: refusing to delete it.`);
  }
  const deleted = await cfJson("DELETE", `/accounts/${encodeURIComponent(account.id)}/tokens/${encodeURIComponent(params.tokenId)}`, token);
  if ("error" in deleted) {
    return failure(deleted.error);
  }
  if (deleted.status === 404) {
    return { ok: true, op: "r2-site-key-revoke", bucket: params.bucket, tokenId: params.tokenId, status: "already-absent" };
  }
  if (deleted.status !== 200 || !deleted.envelope?.success) {
    return failure(`deleting the key failed with HTTP ${deleted.status}${cloudflareErrorMessage(deleted.envelope)}`);
  }
  return { ok: true, op: "r2-site-key-revoke", bucket: params.bucket, tokenId: params.tokenId, status: "revoked" };
}

const BUCKET_LIST_PAGE_SIZE = 1000;
const BUCKET_LIST_MAX_PAGES = 5;

/**
 * READ the names of every bucket in the agency's R2 account. Names only: no object, no key, no size.
 * [unverified] the exact Cloudflare response shape: the code accepts `result.buckets` (the documented
 * shape) and a bare array, and pages with `result_info.cursor` when one is returned.
 */
export async function readR2MediaBuckets(_params: R2MediaBucketsParams, env: Env): Promise<R2MediaBucketsResult> {
  const token = env.R2_PROVISION_API_TOKEN;
  if (!token) {
    return { ok: false, op: "r2-media-buckets", detail: "R2_PROVISION_API_TOKEN is not configured on this Worker." };
  }
  const account = await resolveMediaAccount(token, env);
  if ("error" in account) {
    return { ok: false, op: "r2-media-buckets", detail: account.error };
  }
  const names: string[] = [];
  let cursor = "";
  let truncated = false;
  for (let page = 1; page <= BUCKET_LIST_MAX_PAGES; page += 1) {
    const query = new URLSearchParams({ per_page: String(BUCKET_LIST_PAGE_SIZE) });
    if (cursor !== "") {
      query.set("cursor", cursor);
    }
    const reply = await cfJson("GET", `/accounts/${encodeURIComponent(account.id)}/r2/buckets?${query.toString()}`, token);
    if ("error" in reply) {
      return { ok: false, op: "r2-media-buckets", detail: reply.error };
    }
    if (reply.status === 401 || reply.status === 403) {
      return { ok: false, op: "r2-media-buckets", detail: TOKEN_UNAUTHORIZED_HINT };
    }
    if (reply.status !== 200 || !reply.envelope?.success) {
      return { ok: false, op: "r2-media-buckets", detail: `listing buckets failed with HTTP ${reply.status}${cloudflareErrorMessage(reply.envelope)}` };
    }
    const result = reply.envelope.result as unknown;
    let records: unknown[] = [];
    if (Array.isArray(result)) {
      records = result;
    } else if (typeof result === "object" && result !== null && Array.isArray((result as { buckets?: unknown }).buckets)) {
      records = (result as { buckets: unknown[] }).buckets;
    }
    for (const record of records) {
      const name = typeof record === "object" && record !== null ? (record as { name?: unknown }).name : undefined;
      if (typeof name === "string" && name.length > 0) {
        names.push(name);
      }
    }
    const info = (reply.envelope as { result_info?: { cursor?: unknown } }).result_info;
    const nextCursor = typeof info?.cursor === "string" ? info.cursor : "";
    if (nextCursor === "" || records.length === 0) {
      break;
    }
    cursor = nextCursor;
    if (page === BUCKET_LIST_MAX_PAGES) {
      truncated = true;
    }
  }
  return {
    ok: true,
    op: "r2-media-buckets",
    accountId: account.id,
    endpointHost: endpointHostFor(account.id),
    buckets: [...new Set(names)].sort(),
    truncated,
  };
}
