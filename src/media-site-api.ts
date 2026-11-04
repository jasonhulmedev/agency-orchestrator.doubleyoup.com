// hub#222 — the SITE-FACING media API (agency Worker side).
//
// The site's mu-plugin holds no R2 key. It calls these four routes with its per-site credential instead, and the
// Worker is the only party that deletes or replaces an object:
//
//   POST /media/sign-put   {bucket, key, contentType, contentLength}  -> a presigned create-once PUT for one new key
//   POST /media/replace    {bucket, key, contentType, contentLength}  -> current object to trash, then a create-once PUT
//   POST /media/delete     {bucket, key}                              -> current object to trash, then deleted
//   POST /media/rename     {bucket, from, to}                         -> `from` copied to `to` (create-once), `from` to
//                                                                        trash, `from` deleted
//
// AUTH. `Authorization: Bearer <credential>`, where credential = hex(HMAC-SHA256(MEDIA_SITE_SECRET, bucket)). The
// site gets it as DOUBLEYOUP_MEDIA_SITE_TOKEN (media-site-credential-install writes it), next to its bucket
// (DOUBLEYOUP_R2_BUCKET). The check is crypto.subtle.verify, which compares in constant time. This is NOT
// Direction-B: no platform signature, no nonce. A credential opens exactly one bucket, and only these four routes.
//
// RATE LIMIT. 600 authenticated requests per minute per bucket (MEDIA_SITE_RATE_LIMIT_PER_MINUTE), counted in a
// Durable Object instance of that bucket only (`media-rate:<bucket>`), so no site shares a counter or a lock with
// another. One WordPress upload asks for about ten URLs (the original and its sizes), so 600 is about 60 uploads a
// minute; a bulk offload uses media-bulk-credential instead. The limit is counted AFTER the credential check, so
// nobody can use up a site's budget with wrong credentials.
//
// CREATE-ONCE. Every presigned PUT signs `if-none-match: *`, the content type and the content length. R2 then
// refuses (412) a PUT onto a key that exists, so a site can create objects but never overwrite one: an overwrite
// goes through /media/replace, which moves the old bytes to trash first.
//
// RETRIES. Every route is safe to repeat. A missing source is a no-op success. A rename whose target already holds
// the source's revision skips the copy. A trash copy that already holds the same revision (ETag and metadata) is
// reused.
//
// ONE WRITER PER KEY. R2's DeleteObject takes no condition, so "delete exactly the version that went to trash" needs
// the key to stay still between the HEAD and the DELETE. While a live object exists, only this Worker can change it:
// a presigned PUT is create-once (412 on an existing key) and every Worker copy is create-once
// (cf-copy-destination-if-none-match). So each route that deletes takes a short lease on its key first, in the
// bucket's own Durable Object instance (`media-lease:<bucket>`, the NonceStore lease table). A second request for the
// same key gets 409 and retries; requests for other keys or other sites never wait. The DELETE starts only while the
// lease still has room for it (deleteFenceViolation), so a stalled request can not delete after its lease expired.
//
// NEVER LOGGED. The credential, the secret and the presigned URL are never logged and never put in an error.

import type { Env } from "./env.js";
import {
  isMediaBucketForSite,
  mediaLiveKeyViolation,
  mediaUploadViolation,
} from "./dispatch-params-media.js";
import {
  copyMediaObject,
  deleteMediaObject,
  headMediaObject,
  mediaStoreIdentity,
  moveToTrash,
  sameMediaRevision,
  type MediaObjectHead,
  type MediaStoreIdentity,
} from "./media-store.js";
import { canonicalHeaderValue, presignS3Put } from "./sigv4.js";
import { readBodyCapped } from "./actuate.js";

export const MEDIA_SITE_RATE_LIMIT_PER_MINUTE = 600;
const MEDIA_SITE_RATE_WINDOW_MS = 60_000;

/** How long one request may hold the lease on a key it trashes. A crashed request frees the key after this. */
export const MEDIA_KEY_LEASE_TTL_MS = 60_000;
/** The longest wait for R2's answer to the final DELETE. */
export const MEDIA_DELETE_TIMEOUT_MS = 10_000;
// Room left for clock steps and the Durable Object round trip: the DELETE must be answered this long before the
// lease expires.
const MEDIA_LEASE_SAFETY_MARGIN_MS = 5_000;

/** How long a presigned PUT stays valid: 10 minutes (hub#222 allows at most 15). */
export const MEDIA_PRESIGN_TTL_SECONDS = 600;

/** MEDIA_SITE_SECRET must be at least this long; a shorter one is treated as not configured. */
export const MEDIA_SITE_SECRET_MIN_LENGTH = 32;

const MEDIA_REQUEST_MAX_BYTES = 16 * 1024;
const CREDENTIAL_HEX_RE = /^[a-f0-9]{64}$/;
const BEARER_PREFIX = "Bearer ";

export const MEDIA_SITE_ACTIONS = ["sign-put", "replace", "delete", "rename"] as const;
export type MediaSiteAction = (typeof MEDIA_SITE_ACTIONS)[number];

export function isMediaSiteAction(value: string): value is MediaSiteAction {
  return (MEDIA_SITE_ACTIONS as readonly string[]).includes(value);
}

function json(body: unknown, status: number, extraHeaders?: Record<string, string>): Response {
  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    // A presigned URL is a short-lived capability: no cache may keep it.
    "cache-control": "no-store",
  };
  if (extraHeaders !== undefined) {
    for (const [name, value] of Object.entries(extraHeaders)) {
      headers[name] = value;
    }
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function refuse(status: number, error: string, extraHeaders?: Record<string, string>): Response {
  return json({ ok: false, error }, status, extraHeaders);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

async function siteCredentialKey(secret: string, usage: "sign" | "verify"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

/** The site credential of `bucket`: hex(HMAC-SHA256(MEDIA_SITE_SECRET, bucket)). Never log the result. */
export async function mediaSiteCredential(secret: string, bucket: string): Promise<string> {
  const key = await siteCredentialKey(secret, "sign");
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(bucket));
  return bytesToHex(new Uint8Array(signature));
}

/** Constant-time check of a presented credential against `bucket`'s (crypto.subtle.verify). */
export async function verifyMediaSiteCredential(secret: string, bucket: string, presented: string): Promise<boolean> {
  if (!CREDENTIAL_HEX_RE.test(presented)) {
    return false;
  }
  const key = await siteCredentialKey(secret, "verify");
  return crypto.subtle.verify("HMAC", key, hexToBytes(presented), new TextEncoder().encode(bucket));
}

/** The configured MEDIA_SITE_SECRET, or null when it is missing or too short to trust. */
export function configuredMediaSiteSecret(env: Env): string | null {
  const secret = env.MEDIA_SITE_SECRET;
  if (typeof secret !== "string" || secret.length < MEDIA_SITE_SECRET_MIN_LENGTH) {
    return null;
  }
  return secret;
}

async function readJsonBody(request: Request): Promise<Record<string, unknown> | null> {
  // Stream with a cap: the route is public, so a huge body must never be buffered whole.
  const response = new Response(request.body);
  const read = await readBodyCapped(response, MEDIA_REQUEST_MAX_BYTES);
  if (!read.ok) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(read.text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  return parsed as Record<string, unknown>;
}

const ALLOWED_FIELDS: Record<MediaSiteAction, readonly string[]> = {
  "sign-put": ["bucket", "key", "contentType", "contentLength"],
  replace: ["bucket", "key", "contentType", "contentLength"],
  delete: ["bucket", "key"],
  rename: ["bucket", "from", "to"],
};

function unknownFieldReason(body: Record<string, unknown>, action: MediaSiteAction): string | null {
  const allowed = ALLOWED_FIELDS[action];
  for (const field of Object.keys(body)) {
    if (!allowed.includes(field)) {
      return `${action} does not take "${field}"`;
    }
  }
  return null;
}

interface CreateOnceUpload {
  method: "PUT";
  url: string;
  /** Send exactly these headers with the PUT: they are signed. */
  headers: Record<string, string>;
  expiresAt: string;
}

async function createOnceUpload(
  identity: MediaStoreIdentity,
  bucket: string,
  key: string,
  contentType: string,
  contentLength: number,
  nowMs: number,
): Promise<CreateOnceUpload> {
  // The site sends exactly these headers, so they carry the value that SigV4 signs (inner whitespace collapsed).
  const headers: Record<string, string> = {
    "content-length": String(contentLength),
    "content-type": canonicalHeaderValue(contentType),
    "if-none-match": "*",
  };
  const presigned = await presignS3Put({
    endpoint: identity.endpoint,
    bucket,
    region: "auto",
    accessKeyId: identity.accessKeyId,
    secretAccessKey: identity.secretAccessKey,
    key,
    expiresSeconds: MEDIA_PRESIGN_TTL_SECONDS,
    nowMs,
    signedHeaders: headers,
  });
  return {
    method: "PUT",
    url: presigned.url,
    headers,
    expiresAt: new Date(nowMs + MEDIA_PRESIGN_TTL_SECONDS * 1000).toISOString(),
  };
}

function upstreamStatus(status: number): number {
  if (status === 409 || status === 412) {
    return 409;
  }
  return 502;
}

async function handleSignPut(identity: MediaStoreIdentity, bucket: string, body: Record<string, unknown>, nowMs: number): Promise<Response> {
  const keyViolation = mediaLiveKeyViolation(bucket, body.key, "key");
  if (keyViolation !== null) {
    return refuse(400, keyViolation);
  }
  const uploadViolation = mediaUploadViolation(body.contentType, body.contentLength);
  if (uploadViolation !== null) {
    return refuse(400, uploadViolation);
  }
  const key = body.key as string;
  const upload = await createOnceUpload(identity, bucket, key, body.contentType as string, body.contentLength as number, nowMs);
  return json({ ok: true, action: "sign-put", key, upload }, 200);
}

interface KeyLease {
  key: string;
  /** Date.now() when the lease was granted (taken just BEFORE the request, so it never overstates the time left). */
  acquiredAtMs: number;
  /** Set when the DELETE failed, so its outcome is unknown: the lease is then kept until it expires (withKeyLease). */
  keepUntilExpiry: boolean;
}

type KeyLeaseOutcome<T> = { acquired: true; value: T } | { acquired: false; response: Response };

/**
 * Run `work` while holding the lease on `key` in the bucket's own Durable Object instance. A key that another
 * request holds answers 409 (retry). The lease is released afterwards, except when the work could not tell
 * whether its DELETE was applied: R2 may still apply that DELETE, so the key stays held until the lease expires.
 */
async function withKeyLease<T>(env: Env, bucket: string, key: string, work: (lease: KeyLease) => Promise<T>): Promise<KeyLeaseOutcome<T>> {
  const leaseStore = env.NONCE_STORE.get(env.NONCE_STORE.idFromName(`media-lease:${bucket}`));
  const holder = crypto.randomUUID();
  const acquiredAtMs = Date.now();
  const outcome = await leaseStore.acquireLease(key, holder, MEDIA_KEY_LEASE_TTL_MS);
  if (outcome === "busy") {
    return { acquired: false, response: refuse(409, `another media request is changing ${key}: nothing was changed, retry.`) };
  }
  const lease: KeyLease = { key, acquiredAtMs, keepUntilExpiry: false };
  try {
    const value = await work(lease);
    return { acquired: true, value };
  } finally {
    if (!lease.keepUntilExpiry) {
      // A failed release must not hide the result: the lease then expires on its own after its TTL. This catch
      // exists for that reason only.
      try {
        await leaseStore.releaseLease(key, holder);
      } catch {
        // Nothing to do: the lease expires after MEDIA_KEY_LEASE_TTL_MS.
      }
    }
  }
}

/** Why the final DELETE must not start now, or null when the lease still has room for it. */
function deleteFenceViolation(lease: KeyLease): string | null {
  const latestStartMs = lease.acquiredAtMs + MEDIA_KEY_LEASE_TTL_MS - MEDIA_DELETE_TIMEOUT_MS - MEDIA_LEASE_SAFETY_MARGIN_MS;
  if (Date.now() <= latestStartMs) {
    return null;
  }
  return `${lease.key} took too long to move to trash: the original was not deleted, retry.`;
}

/** Move `key` to trash and delete it, under `lease` on that key. A missing key is "already-absent". */
async function trashAndDelete(
  identity: MediaStoreIdentity,
  bucket: string,
  lease: KeyLease,
  nowMs: number,
): Promise<{ ok: true; status: "trashed" | "already-absent"; trashKey: string | null } | { ok: false; httpStatus: number; error: string }> {
  const key = lease.key;
  const head = await headMediaObject(identity, bucket, key);
  if (head !== null && "error" in head) {
    return { ok: false, httpStatus: 502, error: head.error };
  }
  if (head === null) {
    return { ok: true, status: "already-absent", trashKey: null };
  }
  const moved = await moveToTrash(identity, bucket, key, head, nowMs);
  if (!moved.ok) {
    if (moved.status === 412 || moved.status === 404) {
      // The object changed or vanished between the HEAD and the copy. Nothing was deleted; the site can retry.
      return { ok: false, httpStatus: 409, error: `${key} changed while it was moved to trash: nothing was deleted, retry.` };
    }
    return { ok: false, httpStatus: upstreamStatus(moved.status), error: moved.error };
  }
  // The DELETE is unconditional (R2 has no If-Match on DeleteObject). It removes exactly the revision that went to
  // trash only because the lease kept every other writer off this key since the HEAD: check that it still does.
  const fenceViolation = deleteFenceViolation(lease);
  if (fenceViolation !== null) {
    return { ok: false, httpStatus: 503, error: fenceViolation };
  }
  const deleted = await deleteMediaObject(identity, bucket, key, MEDIA_DELETE_TIMEOUT_MS);
  if (!deleted.ok) {
    // A timeout or a 5xx does not prove that R2 left the object alone: it may still apply this DELETE. Keep the key
    // held until the lease expires, so no new upload can land on it before that late DELETE.
    lease.keepUntilExpiry = true;
    return { ok: false, httpStatus: 502, error: `${deleted.error} (the trash copy ${moved.trashKey} exists)` };
  }
  return { ok: true, status: "trashed", trashKey: moved.trashKey };
}

async function handleReplace(env: Env, identity: MediaStoreIdentity, bucket: string, body: Record<string, unknown>, nowMs: number): Promise<Response> {
  const keyViolation = mediaLiveKeyViolation(bucket, body.key, "key");
  if (keyViolation !== null) {
    return refuse(400, keyViolation);
  }
  const uploadViolation = mediaUploadViolation(body.contentType, body.contentLength);
  if (uploadViolation !== null) {
    return refuse(400, uploadViolation);
  }
  const key = body.key as string;
  const leased = await withKeyLease(env, bucket, key, (lease) => trashAndDelete(identity, bucket, lease, nowMs));
  if (!leased.acquired) {
    return leased.response;
  }
  const trashed = leased.value;
  if (!trashed.ok) {
    return refuse(trashed.httpStatus, trashed.error);
  }
  const upload = await createOnceUpload(identity, bucket, key, body.contentType as string, body.contentLength as number, nowMs);
  return json({ ok: true, action: "replace", key, previous: trashed.status, trashKey: trashed.trashKey, upload }, 200);
}

async function handleDelete(env: Env, identity: MediaStoreIdentity, bucket: string, body: Record<string, unknown>, nowMs: number): Promise<Response> {
  const keyViolation = mediaLiveKeyViolation(bucket, body.key, "key");
  if (keyViolation !== null) {
    return refuse(400, keyViolation);
  }
  const key = body.key as string;
  const leased = await withKeyLease(env, bucket, key, (lease) => trashAndDelete(identity, bucket, lease, nowMs));
  if (!leased.acquired) {
    return leased.response;
  }
  const trashed = leased.value;
  if (!trashed.ok) {
    return refuse(trashed.httpStatus, trashed.error);
  }
  return json({ ok: true, action: "delete", key, status: trashed.status, trashKey: trashed.trashKey }, 200);
}

async function handleRename(env: Env, identity: MediaStoreIdentity, bucket: string, body: Record<string, unknown>, nowMs: number): Promise<Response> {
  const fromViolation = mediaLiveKeyViolation(bucket, body.from, "from");
  if (fromViolation !== null) {
    return refuse(400, fromViolation);
  }
  const toViolation = mediaLiveKeyViolation(bucket, body.to, "to");
  if (toViolation !== null) {
    return refuse(400, toViolation);
  }
  const from = body.from as string;
  const to = body.to as string;
  if (from === to) {
    return refuse(400, "from and to must differ");
  }
  // The lease is on `from`, the key that gets deleted. `to` needs none: the copy onto it is create-once in R2 itself.
  const leased = await withKeyLease(env, bucket, from, (lease) => renameUnderLease(identity, bucket, lease, to, nowMs));
  if (!leased.acquired) {
    return leased.response;
  }
  return leased.value;
}

async function renameUnderLease(identity: MediaStoreIdentity, bucket: string, lease: KeyLease, to: string, nowMs: number): Promise<Response> {
  const from = lease.key;
  const source = await headMediaObject(identity, bucket, from);
  if (source !== null && "error" in source) {
    return refuse(502, source.error);
  }
  if (source === null) {
    // Nothing to rename: a retry of a rename that already finished, or a key that never existed.
    return json({ ok: true, action: "rename", from, to, status: "already-absent", trashKey: null }, 200);
  }

  const targetCheck = await renameTargetState(identity, bucket, to, source);
  if (targetCheck === "error") {
    return refuse(502, `reading ${to} failed`);
  }
  if (targetCheck === "other") {
    return refuse(409, `${to} already exists with another revision: a rename never overwrites.`);
  }
  if (targetCheck === "absent") {
    const copied = await copyMediaObject(identity, bucket, from, to, source.etag);
    if (!copied.ok && copied.status !== 412) {
      return refuse(upstreamStatus(copied.status), copied.error);
    }
    if (!copied.ok) {
      // 412: either `to` was created after our HEAD (by a presigned PUT, say) or `from` changed. R2 refused the copy,
      // so nothing was overwritten. Read `to` again: it may be a retry's copy of this very revision.
      const recheck = await renameTargetState(identity, bucket, to, source);
      if (recheck !== "same") {
        return refuse(409, `${to} or ${from} changed during the rename: nothing was overwritten or deleted, retry.`);
      }
    }
  }

  const trashed = await trashAndDelete(identity, bucket, lease, nowMs);
  if (!trashed.ok) {
    return refuse(trashed.httpStatus, `${trashed.error} (${to} was written)`);
  }
  return json({ ok: true, action: "rename", from, to, status: "renamed", trashKey: trashed.trashKey }, 200);
}

/** The state of a rename target: absent, the source's own revision (a retry), another revision, or unreadable. */
async function renameTargetState(
  identity: MediaStoreIdentity,
  bucket: string,
  to: string,
  source: MediaObjectHead,
): Promise<"absent" | "same" | "other" | "error"> {
  const target = await headMediaObject(identity, bucket, to);
  if (target === null) {
    return "absent";
  }
  if ("error" in target) {
    return "error";
  }
  if (sameMediaRevision(target, source)) {
    return "same";
  }
  return "other";
}

/** POST /media/<action>. The router calls this only for a POST with a known action. */
export async function handleMediaSiteRequest(request: Request, env: Env, action: MediaSiteAction): Promise<Response> {
  const secret = configuredMediaSiteSecret(env);
  if (secret === null) {
    return refuse(503, "the media API is not configured on this Worker (MEDIA_SITE_SECRET).");
  }
  const body = await readJsonBody(request);
  if (body === null) {
    return refuse(400, `body must be a JSON object of at most ${MEDIA_REQUEST_MAX_BYTES} bytes`);
  }
  if (!isMediaBucketForSite(body.bucket)) {
    return refuse(400, "bucket must be the site's media bucket, doubleyoup-media-<prefix>");
  }
  const bucket = body.bucket;

  const authorization = request.headers.get("authorization") ?? "";
  if (!authorization.startsWith(BEARER_PREFIX)) {
    return refuse(401, "missing site credential", { "www-authenticate": "Bearer" });
  }
  const presented = authorization.slice(BEARER_PREFIX.length).trim();
  const credentialOk = await verifyMediaSiteCredential(secret, bucket, presented);
  if (!credentialOk) {
    return refuse(401, "wrong site credential", { "www-authenticate": "Bearer" });
  }

  const rateStore = env.NONCE_STORE.get(env.NONCE_STORE.idFromName(`media-rate:${bucket}`));
  const rate = await rateStore.countRequest(bucket, MEDIA_SITE_RATE_WINDOW_MS, MEDIA_SITE_RATE_LIMIT_PER_MINUTE);
  if (!rate.allowed) {
    const retryAfterSeconds = Math.max(1, Math.ceil(rate.retryAfterMs / 1000));
    return refuse(429, `more than ${MEDIA_SITE_RATE_LIMIT_PER_MINUTE} media requests a minute for this site`, {
      "retry-after": String(retryAfterSeconds),
    });
  }

  const unknownField = unknownFieldReason(body, action);
  if (unknownField !== null) {
    return refuse(400, unknownField);
  }

  const identity = await mediaStoreIdentity(env);
  if ("error" in identity) {
    return refuse(503, identity.error);
  }
  const nowMs = Date.now();
  if (action === "sign-put") {
    return handleSignPut(identity, bucket, body, nowMs);
  }
  if (action === "replace") {
    return handleReplace(env, identity, bucket, body, nowMs);
  }
  if (action === "delete") {
    return handleDelete(env, identity, bucket, body, nowMs);
  }
  return handleRename(env, identity, bucket, body, nowMs);
}
