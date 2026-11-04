// hub#222 ACTUATION (agency Worker side) — media soft delete, the Direction-B half.
//
//   media-bucket-protect           PUT the `trash/` lifecycle rule (delete after 31 days) and the `trash/` bucket lock
//                                  (30 days) on ONE media bucket. Read-modify-write: every rule this op does not own
//                                  is kept as it is, and a re-run writes nothing when both rules are already right.
//   media-site-credential-install  DERIVE the site's credential (HMAC-SHA256(MEDIA_SITE_SECRET, bucket)) and POST it
//                                  with this Worker's URL to the site's file-node cell-agent /update-r2-config (Worker
//                                  mode, infra 43b21b6), which writes DOUBLEYOUP_MEDIA_WORKER_URL +
//                                  DOUBLEYOUP_MEDIA_SITE_TOKEN and removes DOUBLEYOUP_R2_KEY + DOUBLEYOUP_R2_SECRET.
//                                  The credential goes Worker -> file node only; no answer carries it. Idempotent: the
//                                  credential is derived, so a re-run writes the same values.
//   media-site-key-revoke          DELETE the site's old per-site R2 key. The same guard as r2-site-key-revoke: only a
//                                  key whose NAME proves r2-site-key-install minted it for this bucket. 404 =
//                                  already-absent, so it converges.
//   media-trash-list               READ one page (at most 1000) of `trash/` keys. Paged with an opaque cursor.
//   media-restore                  COPY one trash object back to a live key, create-once: 409 when the target exists
//                                  with other bytes; "already-restored" when it holds the same bytes (a retry).
//   media-bulk-credential          MINT an R2 temporary access credential (POST /r2/temp-access-credentials) for ONE
//                                  bucket and ONE site prefix, object-read-write, at most 12 hours. Its parent is
//                                  R2_PROVISION_API_TOKEN. It is the ONE op whose answer carries a credential: it is
//                                  meant for a bulk offload engine and expires on its own. Not idempotent (each run
//                                  mints a new credential), but harmless to repeat.
//
// All on the agency's OWN R2_PROVISION_API_TOKEN (it needs Workers R2 Storage: Edit, which covers bucket lifecycle and
// lock configuration) and the agency's own file-node cell-agent. FAIL CLOSED: an answer this code does not fully
// understand is ok:false with the reason.

import type { Env } from "./env.js";
import { CF_API, cloudflareErrorMessage, cloudflareHeaders, readBodyCapped, type CloudflareEnvelope } from "./actuate.js";
import { actuateR2SiteKeyRevoke } from "./actuate-r2-media.js";
import {
  MEDIA_TRASH_PREFIX,
  mediaBucketSitePrefix,
  type MediaBucketProtectParams,
  type MediaBulkCredentialParams,
  type MediaRestoreParams,
  type MediaSiteCredentialInstallParams,
  type MediaSiteKeyRevokeParams,
  type MediaTrashListParams,
} from "./dispatch-params-media.js";
import { configuredMediaSiteSecret, mediaSiteCredential } from "./media-site-api.js";
import {
  copyMediaObject,
  headMediaObject,
  listMediaObjects,
  mediaStoreIdentity,
  type MediaStoreIdentity,
  type MediaTrashEntry,
} from "./media-store.js";
import { errorMessage, stripTrailingSlash } from "./util.js";

/** The ids of the two rules this op owns. Every other rule id is left alone. */
export const MEDIA_TRASH_LIFECYCLE_RULE_ID = "doubleyoup-trash-expire";
export const MEDIA_TRASH_LOCK_RULE_ID = "doubleyoup-trash-lock";
/** Trash objects are locked for 30 days and expire after 31 (hub#222). */
export const MEDIA_TRASH_LOCK_SECONDS = 30 * 24 * 60 * 60;
export const MEDIA_TRASH_EXPIRE_SECONDS = 31 * 24 * 60 * 60;

const MEDIA_TRASH_LIST_PAGE_SIZE = 1000;
const AGENT_REPLY_MAX_BYTES = 64 * 1024;

// ── shared ──────────────────────────────────────────────────────────────────────────────────────────

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

function bucketPath(identity: MediaStoreIdentity, bucket: string, sub: string): string {
  return `/accounts/${encodeURIComponent(identity.accountId)}/r2/buckets/${encodeURIComponent(bucket)}/${sub}`;
}

function deniedOrFailed(what: string, reply: { status: number; envelope: CloudflareEnvelope | null }): string {
  if (reply.status === 401 || reply.status === 403) {
    return `Cloudflare denied ${what}: R2_PROVISION_API_TOKEN needs Workers R2 Storage: Edit.`;
  }
  if (reply.status === 404) {
    return `${what} failed: the bucket does not exist in this account (HTTP 404${cloudflareErrorMessage(reply.envelope)}).`;
  }
  return `${what} failed with HTTP ${reply.status}${cloudflareErrorMessage(reply.envelope)}`;
}

// ── media-bucket-protect ──────────────────────────────────────────────────────────────────────────────

export type MediaBucketProtectResult =
  | {
      ok: true;
      op: "media-bucket-protect";
      bucket: string;
      lifecycle: "created" | "updated" | "unchanged";
      lock: "created" | "updated" | "unchanged";
      /** How many rules of other owners each configuration holds (kept as they were). */
      otherLifecycleRules: number;
      otherLockRules: number;
    }
  | { ok: false; op: "media-bucket-protect"; bucket: string; detail: string };

/** The lifecycle rule this op owns: delete `trash/` objects 31 days after they were written. */
export function mediaTrashLifecycleRule(): Record<string, unknown> {
  return {
    id: MEDIA_TRASH_LIFECYCLE_RULE_ID,
    enabled: true,
    conditions: { prefix: MEDIA_TRASH_PREFIX },
    deleteObjectsTransition: { condition: { type: "Age", maxAge: MEDIA_TRASH_EXPIRE_SECONDS } },
  };
}

/** The bucket-lock rule this op owns: no delete or overwrite of a `trash/` object for 30 days. */
export function mediaTrashLockRule(): Record<string, unknown> {
  return {
    id: MEDIA_TRASH_LOCK_RULE_ID,
    enabled: true,
    prefix: MEDIA_TRASH_PREFIX,
    condition: { type: "Age", maxAgeSeconds: MEDIA_TRASH_LOCK_SECONDS },
  };
}

function lifecycleRuleMatches(rule: Record<string, unknown>): boolean {
  if (rule.enabled !== true) return false;
  const conditions = rule.conditions as { prefix?: unknown } | undefined;
  if (conditions?.prefix !== MEDIA_TRASH_PREFIX) return false;
  const transition = rule.deleteObjectsTransition as { condition?: { type?: unknown; maxAge?: unknown } } | undefined;
  if (transition?.condition?.type !== "Age" || transition.condition.maxAge !== MEDIA_TRASH_EXPIRE_SECONDS) return false;
  // A storage-class transition or a multipart abort on OUR rule is drift too: the rule must be exactly ours.
  if (rule.storageClassTransitions !== undefined && !(Array.isArray(rule.storageClassTransitions) && rule.storageClassTransitions.length === 0)) {
    return false;
  }
  if (rule.abortMultipartUploadsTransition !== undefined && rule.abortMultipartUploadsTransition !== null) {
    return false;
  }
  return true;
}

function lockRuleMatches(rule: Record<string, unknown>): boolean {
  if (rule.enabled !== true) return false;
  if (rule.prefix !== MEDIA_TRASH_PREFIX) return false;
  const condition = rule.condition as { type?: unknown; maxAgeSeconds?: unknown } | undefined;
  return condition?.type === "Age" && condition.maxAgeSeconds === MEDIA_TRASH_LOCK_SECONDS;
}

type RuleMerge = { rules: Record<string, unknown>[]; change: "created" | "updated" | "unchanged"; others: number };

/** Keep every rule with another id; put ours in (or leave it when it already matches). */
function mergeOwnedRule(
  current: Record<string, unknown>[],
  ownedId: string,
  wanted: Record<string, unknown>,
  matches: (rule: Record<string, unknown>) => boolean,
): RuleMerge {
  const others = current.filter((rule) => rule.id !== ownedId);
  const ours = current.filter((rule) => rule.id === ownedId);
  if (ours.length === 1 && matches(ours[0] as Record<string, unknown>)) {
    return { rules: current, change: "unchanged", others: others.length };
  }
  let change: "created" | "updated" = "created";
  if (ours.length > 0) {
    change = "updated";
  }
  return { rules: [...others, wanted], change, others: others.length };
}

async function readRules(
  identity: MediaStoreIdentity,
  bucket: string,
  sub: "lifecycle" | "lock",
): Promise<Record<string, unknown>[] | { error: string }> {
  const reply = await cfJson("GET", bucketPath(identity, bucket, sub), identity.apiToken);
  if ("error" in reply) {
    return reply;
  }
  if (reply.status !== 200 || !reply.envelope?.success) {
    return { error: deniedOrFailed(`reading the ${sub} rules of ${bucket}`, reply) };
  }
  const result = (reply.envelope.result ?? {}) as { rules?: unknown };
  if (result.rules === undefined || result.rules === null) {
    return [];
  }
  if (!Array.isArray(result.rules)) {
    return { error: `the ${sub} rules of ${bucket} are not a list: refusing to write over them.` };
  }
  const rules: Record<string, unknown>[] = [];
  for (const rule of result.rules) {
    if (typeof rule !== "object" || rule === null || typeof (rule as { id?: unknown }).id !== "string") {
      return { error: `a ${sub} rule of ${bucket} has no id: refusing to write over it.` };
    }
    rules.push(rule as Record<string, unknown>);
  }
  return rules;
}

async function writeRules(
  identity: MediaStoreIdentity,
  bucket: string,
  sub: "lifecycle" | "lock",
  rules: Record<string, unknown>[],
): Promise<{ ok: true } | { error: string }> {
  const reply = await cfJson("PUT", bucketPath(identity, bucket, sub), identity.apiToken, { rules });
  if ("error" in reply) {
    return reply;
  }
  if (reply.status !== 200 || !reply.envelope?.success) {
    return { error: deniedOrFailed(`writing the ${sub} rules of ${bucket}`, reply) };
  }
  return { ok: true };
}

export async function actuateMediaBucketProtect(params: MediaBucketProtectParams, env: Env): Promise<MediaBucketProtectResult> {
  const failure = (detail: string): MediaBucketProtectResult => ({ ok: false, op: "media-bucket-protect", bucket: params.bucket, detail });
  const identity = await mediaStoreIdentity(env);
  if ("error" in identity) {
    return failure(identity.error);
  }

  // Lifecycle first: should the lock write fail after it, the bucket only gained an expiry for trash/, which is
  // harmless on its own. The lock is what refuses deletes, and a re-run adds it.
  const lifecycleRules = await readRules(identity, params.bucket, "lifecycle");
  if ("error" in lifecycleRules) {
    return failure(lifecycleRules.error);
  }
  const lifecycle = mergeOwnedRule(lifecycleRules, MEDIA_TRASH_LIFECYCLE_RULE_ID, mediaTrashLifecycleRule(), lifecycleRuleMatches);
  if (lifecycle.change !== "unchanged") {
    const written = await writeRules(identity, params.bucket, "lifecycle", lifecycle.rules);
    if ("error" in written) {
      return failure(written.error);
    }
  }

  const lockRules = await readRules(identity, params.bucket, "lock");
  if ("error" in lockRules) {
    return failure(`${lockRules.error} (the lifecycle rule is ${lifecycle.change})`);
  }
  const lock = mergeOwnedRule(lockRules, MEDIA_TRASH_LOCK_RULE_ID, mediaTrashLockRule(), lockRuleMatches);
  if (lock.change !== "unchanged") {
    const written = await writeRules(identity, params.bucket, "lock", lock.rules);
    if ("error" in written) {
      return failure(`${written.error} (the lifecycle rule is ${lifecycle.change})`);
    }
  }

  return {
    ok: true,
    op: "media-bucket-protect",
    bucket: params.bucket,
    lifecycle: lifecycle.change,
    lock: lock.change,
    otherLifecycleRules: lifecycle.others,
    otherLockRules: lock.others,
  };
}

// ── media-site-credential-install ─────────────────────────────────────────────────────────────────────

export type MediaSiteCredentialInstallResult =
  | {
      ok: true;
      op: "media-site-credential-install";
      slug: string;
      bucket: string;
      workerUrl: string;
      /** The constants the file node wrote. Names only: the token value never leaves the agency side. */
      constants: readonly string[];
    }
  | { ok: false; op: "media-site-credential-install"; slug: string; bucket: string; detail: string };

/** The wp-config constants of Worker mode (agreed with infra: update-r2-config.sh, 43b21b6). */
export const MEDIA_WORKER_MODE_CONSTANTS = ["DOUBLEYOUP_MEDIA_WORKER_URL", "DOUBLEYOUP_MEDIA_SITE_TOKEN"] as const;

interface FileAgentTarget {
  url: string;
  token: string;
  source: "job" | "env";
}

function fileAgentTargetFor(params: MediaSiteCredentialInstallParams, env: Env): FileAgentTarget | null {
  if (params.fileAgentUrl !== undefined && params.fileAgentToken !== undefined) {
    return { url: params.fileAgentUrl, token: params.fileAgentToken, source: "job" };
  }
  if (env.CELL_FILE_AGENT_URL && env.CELL_FILE_AGENT_TOKEN) {
    return { url: env.CELL_FILE_AGENT_URL, token: env.CELL_FILE_AGENT_TOKEN, source: "env" };
  }
  return null;
}

export async function actuateMediaSiteCredentialInstall(
  params: MediaSiteCredentialInstallParams,
  env: Env,
): Promise<MediaSiteCredentialInstallResult> {
  const failure = (detail: string): MediaSiteCredentialInstallResult => ({
    ok: false,
    op: "media-site-credential-install",
    slug: params.slug,
    bucket: params.bucket,
    detail,
  });
  const secret = configuredMediaSiteSecret(env);
  if (secret === null) {
    return failure("MEDIA_SITE_SECRET is not configured on this Worker (at least 32 characters).");
  }
  const fileAgent = fileAgentTargetFor(params, env);
  if (fileAgent === null) {
    return failure(
      "the signed job names no file-node cell-agent (fileAgentUrl / fileAgentToken), and CELL_FILE_AGENT_URL / CELL_FILE_AGENT_TOKEN are not configured on this Worker.",
    );
  }
  const credential = await mediaSiteCredential(secret, params.bucket);

  // redirect:"manual" for the same reason as r2-site-key-install: a redirect means a wrong agent URL, and following
  // it would send the credential and the bearer to another host.
  let response: Response;
  try {
    response = await fetch(`${stripTrailingSlash(fileAgent.url)}/update-r2-config`, {
      method: "POST",
      headers: { authorization: `Bearer ${fileAgent.token}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        slug: params.slug,
        bucket: params.bucket,
        media_worker_url: params.workerUrl,
        media_site_token: credential,
      }),
      redirect: "manual",
    });
  } catch (err) {
    // Re-running is safe (the credential is derived), so the caller just retries.
    return failure(`could not reach the file-node cell-agent /update-r2-config: ${errorMessage(err)}. Safe to retry.`);
  }

  if (response.status === 0 || (response.status >= 300 && response.status < 400)) {
    await response.body?.cancel().catch(() => {});
    return failure(`the file-node cell-agent redirected (HTTP ${response.status}): refusing to follow.`);
  }
  if (response.status === 401 || response.status === 403) {
    await response.body?.cancel().catch(() => {});
    let rejectedTokenName = "CELL_FILE_AGENT_TOKEN";
    if (fileAgent.source === "job") {
      rejectedTokenName = "the fileAgentToken of the signed job";
    }
    return failure(`the file-node cell-agent rejected ${rejectedTokenName} (bearer auth failed).`);
  }
  const read = await readBodyCapped(response, AGENT_REPLY_MAX_BYTES);
  if (!read.ok) {
    return failure(read.detail);
  }
  let body: { ok?: unknown; error?: unknown; stderr?: unknown } | null = null;
  try {
    body = JSON.parse(read.text);
  } catch {
    body = null;
  }
  if (!response.ok || body === null || body.ok !== true) {
    let reason = "";
    if (body !== null && typeof body.error === "string") {
      reason = `: ${body.error}`;
    }
    let stderr = "";
    if (body !== null && typeof body.stderr === "string" && body.stderr !== "") {
      // The agent's stderr never holds the token (update-r2-config.sh prints names, not values), but cap it anyway.
      stderr = ` (${body.stderr.slice(0, 500)})`;
    }
    return failure(`the file-node cell-agent refused /update-r2-config (HTTP ${response.status})${reason}${stderr}`);
  }
  return {
    ok: true,
    op: "media-site-credential-install",
    slug: params.slug,
    bucket: params.bucket,
    workerUrl: params.workerUrl,
    constants: MEDIA_WORKER_MODE_CONSTANTS,
  };
}

// ── media-site-key-revoke ─────────────────────────────────────────────────────────────────────────────

export type MediaSiteKeyRevokeResult =
  | { ok: true; op: "media-site-key-revoke"; slug: string; bucket: string; tokenId: string; status: "revoked" | "already-absent" }
  | { ok: false; op: "media-site-key-revoke"; slug: string; bucket: string; detail: string };

export async function actuateMediaSiteKeyRevoke(params: MediaSiteKeyRevokeParams, env: Env): Promise<MediaSiteKeyRevokeResult> {
  // The hub#43 revoke already does exactly this: read the key, delete it only when its NAME proves that
  // r2-site-key-install minted it for this bucket, and treat 404 as already-absent.
  const revoked = await actuateR2SiteKeyRevoke({ bucket: params.bucket, tokenId: params.tokenId }, env);
  if (!revoked.ok) {
    return { ok: false, op: "media-site-key-revoke", slug: params.slug, bucket: params.bucket, detail: revoked.detail };
  }
  return {
    ok: true,
    op: "media-site-key-revoke",
    slug: params.slug,
    bucket: params.bucket,
    tokenId: revoked.tokenId,
    status: revoked.status,
  };
}

// ── media-trash-list ──────────────────────────────────────────────────────────────────────────────────

export type MediaTrashListResult =
  | {
      ok: true;
      op: "media-trash-list";
      bucket: string;
      entries: MediaTrashEntry[];
      /** Pass back as `cursor` for the next page; null on the last page. */
      cursor: string | null;
    }
  | { ok: false; op: "media-trash-list"; bucket: string; detail: string };

export async function readMediaTrashList(params: MediaTrashListParams, env: Env): Promise<MediaTrashListResult> {
  const failure = (detail: string): MediaTrashListResult => ({ ok: false, op: "media-trash-list", bucket: params.bucket, detail });
  const identity = await mediaStoreIdentity(env);
  if ("error" in identity) {
    return failure(identity.error);
  }
  const listPrefix = `${MEDIA_TRASH_PREFIX}${params.prefix ?? ""}`;
  const page = await listMediaObjects(identity, params.bucket, listPrefix, MEDIA_TRASH_LIST_PAGE_SIZE, params.cursor);
  if ("error" in page) {
    return failure(page.error);
  }
  return { ok: true, op: "media-trash-list", bucket: params.bucket, entries: page.entries, cursor: page.nextCursor };
}

// ── media-restore ─────────────────────────────────────────────────────────────────────────────────────

export type MediaRestoreResult =
  | {
      ok: true;
      op: "media-restore";
      bucket: string;
      trashKey: string;
      targetKey: string;
      status: "restored" | "already-restored";
    }
  | {
      ok: false;
      op: "media-restore";
      bucket: string;
      /** 404: no such trash object. 409: the target holds other bytes. 412: the trash object changed during the copy. */
      code?: 404 | 409 | 412;
      detail: string;
    };

export async function actuateMediaRestore(params: MediaRestoreParams, env: Env): Promise<MediaRestoreResult> {
  const failure = (detail: string, code?: 404 | 409 | 412): MediaRestoreResult => {
    const result: MediaRestoreResult = { ok: false, op: "media-restore", bucket: params.bucket, detail };
    if (code !== undefined) {
      result.code = code;
    }
    return result;
  };
  const identity = await mediaStoreIdentity(env);
  if ("error" in identity) {
    return failure(identity.error);
  }
  const source = await headMediaObject(identity, params.bucket, params.trashKey);
  if (source !== null && "error" in source) {
    return failure(source.error);
  }
  if (source === null) {
    return failure(`${params.trashKey} is not in trash (expired, or never there).`, 404);
  }
  const target = await headMediaObject(identity, params.bucket, params.targetKey);
  if (target !== null && "error" in target) {
    return failure(target.error);
  }
  if (target !== null && target.etag === source.etag) {
    return {
      ok: true,
      op: "media-restore",
      bucket: params.bucket,
      trashKey: params.trashKey,
      targetKey: params.targetKey,
      status: "already-restored",
    };
  }
  if (target !== null) {
    return failure(`${params.targetKey} already exists with other bytes: a restore never overwrites. Restore to another targetKey.`, 409);
  }
  // Create-once by the HEAD above: R2's CopyObject has no If-None-Match on the target. The copy keeps the trash
  // object's metadata (x-amz-metadata-directive: COPY), and the trash object stays in trash.
  const copied = await copyMediaObject(identity, params.bucket, params.trashKey, params.targetKey, source.etag);
  if (!copied.ok) {
    if (copied.status === 412) {
      return failure(`${params.trashKey} changed during the restore: nothing was restored.`, 412);
    }
    return failure(copied.error);
  }
  return {
    ok: true,
    op: "media-restore",
    bucket: params.bucket,
    trashKey: params.trashKey,
    targetKey: params.targetKey,
    status: "restored",
  };
}

// ── media-bulk-credential ─────────────────────────────────────────────────────────────────────────────

export type MediaBulkCredentialResult =
  | {
      ok: true;
      op: "media-bulk-credential";
      bucket: string;
      prefix: string;
      endpoint: string;
      region: "auto";
      accessKeyId: string;
      secretAccessKey: string;
      sessionToken: string;
      expiresAt: string;
    }
  | { ok: false; op: "media-bulk-credential"; bucket: string; detail: string };

export async function actuateMediaBulkCredential(params: MediaBulkCredentialParams, env: Env): Promise<MediaBulkCredentialResult> {
  const failure = (detail: string): MediaBulkCredentialResult => ({ ok: false, op: "media-bulk-credential", bucket: params.bucket, detail });
  const identity = await mediaStoreIdentity(env);
  if ("error" in identity) {
    return failure(identity.error);
  }
  // The validator already pins the prefix under the bucket's own site prefix; check once more before minting.
  if (!params.prefix.startsWith(`${mediaBucketSitePrefix(params.bucket)}/`)) {
    return failure("prefix is outside the site's prefix: refusing.");
  }
  const reply = await cfJson("POST", `/accounts/${encodeURIComponent(identity.accountId)}/r2/temp-access-credentials`, identity.apiToken, {
    bucket: params.bucket,
    parentAccessKeyId: identity.accessKeyId,
    permission: "object-read-write",
    ttlSeconds: params.ttlSeconds,
    prefixes: [params.prefix],
  });
  if ("error" in reply) {
    return failure(reply.error);
  }
  if (reply.status === 401 || reply.status === 403) {
    return failure("Cloudflare denied the temporary credential: R2_PROVISION_API_TOKEN needs Workers R2 Storage: Edit.");
  }
  const result = (reply.envelope?.result ?? null) as { accessKeyId?: unknown; secretAccessKey?: unknown; sessionToken?: unknown } | null;
  const complete =
    result !== null &&
    typeof result.accessKeyId === "string" &&
    result.accessKeyId !== "" &&
    typeof result.secretAccessKey === "string" &&
    result.secretAccessKey !== "" &&
    typeof result.sessionToken === "string" &&
    result.sessionToken !== "";
  if (reply.status !== 200 || !reply.envelope?.success || !complete) {
    return failure(`minting the temporary credential failed with HTTP ${reply.status}${cloudflareErrorMessage(reply.envelope)}`);
  }
  return {
    ok: true,
    op: "media-bulk-credential",
    bucket: params.bucket,
    prefix: params.prefix,
    endpoint: identity.endpoint,
    region: "auto",
    accessKeyId: result.accessKeyId as string,
    secretAccessKey: result.secretAccessKey as string,
    sessionToken: result.sessionToken as string,
    expiresAt: new Date(Date.now() + params.ttlSeconds * 1000).toISOString(),
  };
}
