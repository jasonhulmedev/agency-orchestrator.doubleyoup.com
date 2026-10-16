// hub#43 ACTUATION (agency Worker side) — agency-owned media.
//
//   r2-media-state        READ whether one media bucket exists, and the keys this op family minted for it.
//   r2-site-key-install   MINT one bucket-scoped read-write key in the agency's own Cloudflare account and
//                         STAGE it on the site's file node, straight from this Worker to the agency's own
//                         cell-agent. The platform never receives the key.
//   r2-site-key-revoke    DELETE one such key.
//
// Everything runs on the agency's OWN R2_PROVISION_API_TOKEN (an account-owned token that can create
// buckets and API tokens) and the agency's own file-node cell-agent. The platform holds neither.
//
// WHY THE KEY GOES WORKER -> FILE NODE. hub#43 (decided 2026-10-08): the platform never holds a write key
// to the agency's account again. The earlier copy ran with such a key on the platform's VM and the key had
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
  | { ok: false; op: "r2-site-key-install"; bucket: string; detail: string };

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

async function listMediaKeys(
  accountId: string,
  token: string,
  bucket: string,
): Promise<{ readable: boolean; keys: R2MediaKeySummary[] } | { error: string }> {
  const namePrefix = `dy-media-${bucket}-`;
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
      if (typeof record.id === "string" && typeof record.name === "string" && record.name.startsWith(namePrefix)) {
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
  const account = await resolveAccountId(token, TOKEN_UNAUTHORIZED_HINT);
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

export async function actuateR2SiteKeyInstall(params: R2SiteKeyInstallParams, env: Env): Promise<R2SiteKeyInstallResult> {
  const failure = (detail: string): R2SiteKeyInstallResult => ({ ok: false, op: "r2-site-key-install", bucket: params.bucket, detail });
  const token = env.R2_PROVISION_API_TOKEN;
  if (!token) {
    return failure("R2_PROVISION_API_TOKEN is not configured on this Worker.");
  }
  const agentUrl = env.CELL_FILE_AGENT_URL;
  const agentToken = env.CELL_FILE_AGENT_TOKEN;
  if (!agentUrl || !agentToken) {
    // Refuse BEFORE minting: a key with nowhere to go is a leak waiting to happen.
    return failure("CELL_FILE_AGENT_URL / CELL_FILE_AGENT_TOKEN are not configured on this Worker (the file node's cell-agent).");
  }

  const account = await resolveAccountId(token, TOKEN_UNAUTHORIZED_HINT);
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
  if (minted.status !== 200 || !minted.envelope?.success || !record || typeof record.id !== "string" || typeof record.value !== "string") {
    return failure(`creating the key failed with HTTP ${minted.status}${cloudflareErrorMessage(minted.envelope)}`);
  }
  const tokenId = record.id;
  const accessKeyId = tokenId;
  const secretAccessKey = await sha256Hex(record.value);

  // Stage it on the file node. redirect:"manual": a redirect means a wrong CELL_FILE_AGENT_URL.
  let response: Response;
  try {
    response = await fetch(`${stripTrailingSlash(agentUrl)}/set-r2-target`, {
      method: "POST",
      headers: { authorization: `Bearer ${agentToken}`, "content-type": "application/json", accept: "application/json" },
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
    const removed = await deleteToken(account.id, token, tokenId);
    return failure(
      `could not reach the file-node cell-agent /set-r2-target: ${errorMessage(err)}. ${removed ? "The new key was deleted again." : `The new key ${tokenId} could NOT be deleted: revoke it.`}`,
    );
  }

  let stagedHex: string | null = null;
  let stageDetail = "";
  let staged = false;
  if (response.status === 0 || (response.status >= 300 && response.status < 400)) {
    await response.body?.cancel().catch(() => {});
    stageDetail = `the file-node cell-agent redirected (HTTP ${response.status}): refusing to follow.`;
  } else if (response.status === 401 || response.status === 403) {
    await response.body?.cancel().catch(() => {});
    stageDetail = "the file-node cell-agent rejected CELL_FILE_AGENT_TOKEN (bearer auth failed).";
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
        stageDetail = `the file-node cell-agent refused to stage (HTTP ${response.status}${reason}${stderr}).`;
      }
    }
  }
  if (!staged) {
    const removed = await deleteToken(account.id, token, tokenId);
    return failure(`${stageDetail} ${removed ? "The new key was deleted again, nothing is left behind." : `The new key ${tokenId} could NOT be deleted: revoke it.`}`);
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
  const account = await resolveAccountId(token, TOKEN_UNAUTHORIZED_HINT);
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
  if (!record.name.startsWith(`dy-media-${params.bucket}-`)) {
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
