// hub#222 — the S3 side of media soft delete: the Worker's own R2 identity and the object operations that the
// site-facing media API (media-site-api.ts) and the Direction-B media ops (actuate-media.ts) share.
//
// THE WORKER'S R2 IDENTITY. The Worker already holds R2_PROVISION_API_TOKEN, an account-owned token with "Workers R2
// Storage: Edit". Cloudflare derives S3 credentials from any API token: the access key id is the token's id and the
// secret access key is the SHA-256 (hex) of the token value (developers.cloudflare.com/r2/api/tokens). So the
// Worker signs S3 requests with that token and needs no new secret. The token id comes from
// GET /accounts/{id}/tokens/verify. Account id and token id are cached for the life of the isolate: one Cloudflare
// API read per isolate, not per request.
//
// THE TRASH MOVE (moveToTrash). Copy the live object to `trash/<UTC yyyy-mm-dd>/<key>` with
// x-amz-metadata-directive: COPY (the content type, cache control and custom metadata travel with it), then the
// caller deletes the original. A bucket lock keeps `trash/` objects for 30 days, so a trash key can NOT be
// overwritten: when that key is already taken by ANOTHER revision (the same key deleted twice in one day), the copy
// goes to `trash/<yyyy-mm-dd>.<revision>/<key>` instead, where <revision> is a hash of the ETag and the metadata.
// When the trash key already holds the SAME revision, the copy is skipped: that is a retry of a move that already
// copied. A revision is the ETag AND the metadata (sameMediaRevision): the ETag covers the bytes only, so the same
// bytes uploaded again with a corrected content type are a new revision that needs its own trash copy.
//
// CREATE-ONCE COPIES. Every copy signs R2's `cf-copy-destination-if-none-match: *` (an R2 extension of CopyObject,
// developers.cloudflare.com/r2/api/s3/extensions). R2 checks it when it commits the target, so a copy never
// replaces an object, also one that a presigned PUT created a moment after our HEAD. A refused copy is a 412.
//
// NEVER LOGGED. No function here logs or returns the token, the derived secret or a presigned URL in an error.

import type { Env } from "./env.js";
import { CF_API, cloudflareErrorMessage, resolveAccountId, type CloudflareEnvelope } from "./actuate.js";
import { encodeS3KeyPath, awsUriEncodeComponent, signS3Request } from "./sigv4.js";
import { MEDIA_TRASH_PREFIX } from "./dispatch-params-media.js";
import { errorMessage, extractXmlTag } from "./util.js";

const R2_REGION = "auto";
const S3_ERROR_BODY_MAX_CHARS = 2000;
const TOKEN_UNAUTHORIZED_HINT =
  "Cloudflare denied the request: R2_PROVISION_API_TOKEN must be an ACCOUNT-owned token with Workers R2 Storage: Edit.";

export interface MediaStoreIdentity {
  accountId: string;
  /** `https://<account>.r2.cloudflarestorage.com`, R2's S3 endpoint for the account. */
  endpoint: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** The Cloudflare API token itself, for the REST calls (lifecycle, lock, temp credentials). */
  apiToken: string;
}

interface CachedIdentity {
  apiToken: string;
  expectedAccountId: string;
  identity: MediaStoreIdentity;
}

// One entry per isolate. Keyed on the token value and the pinned account, so a rotated secret (a new isolate
// anyway, in practice) never reuses an old identity.
let cachedIdentity: CachedIdentity | null = null;

/** Tests only: forget the cached identity. */
export function resetMediaStoreIdentityCache(): void {
  cachedIdentity = null;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  let hex = "";
  for (const byte of digest) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

async function readTokenId(accountId: string, apiToken: string): Promise<{ id: string } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/accounts/${encodeURIComponent(accountId)}/tokens/verify`, {
      headers: { authorization: `Bearer ${apiToken}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to verify R2_PROVISION_API_TOKEN: ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    return { error: TOKEN_UNAUTHORIZED_HINT };
  }
  const envelope = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  const result = (envelope?.result ?? null) as { id?: unknown; status?: unknown } | null;
  if (response.status !== 200 || !envelope?.success || !result || typeof result.id !== "string" || result.id === "") {
    return { error: `verifying R2_PROVISION_API_TOKEN failed with HTTP ${response.status}${cloudflareErrorMessage(envelope)}` };
  }
  if (result.status !== undefined && result.status !== "active") {
    return { error: "R2_PROVISION_API_TOKEN is not active." };
  }
  return { id: result.id };
}

/**
 * The Worker's R2 identity: account, S3 endpoint and S3 credentials derived from R2_PROVISION_API_TOKEN. When
 * R2_EXPECTED_ACCOUNT_ID is set, a token of any other account is refused (the same rule as the hub#43 ops).
 */
export async function mediaStoreIdentity(env: Env): Promise<MediaStoreIdentity | { error: string }> {
  const apiToken = env.R2_PROVISION_API_TOKEN;
  if (!apiToken) {
    return { error: "R2_PROVISION_API_TOKEN is not configured on this Worker." };
  }
  const expectedAccountId = (env.R2_EXPECTED_ACCOUNT_ID ?? "").toLowerCase();
  if (cachedIdentity !== null && cachedIdentity.apiToken === apiToken && cachedIdentity.expectedAccountId === expectedAccountId) {
    return cachedIdentity.identity;
  }

  const account = await resolveAccountId(apiToken, TOKEN_UNAUTHORIZED_HINT);
  if ("error" in account) {
    return account;
  }
  if (expectedAccountId !== "" && expectedAccountId !== account.id.toLowerCase()) {
    return { error: "R2_PROVISION_API_TOKEN belongs to a different Cloudflare account than R2_EXPECTED_ACCOUNT_ID: refusing." };
  }
  const tokenId = await readTokenId(account.id, apiToken);
  if ("error" in tokenId) {
    return tokenId;
  }
  const identity: MediaStoreIdentity = {
    accountId: account.id,
    endpoint: `https://${account.id}.r2.cloudflarestorage.com`,
    accessKeyId: tokenId.id,
    secretAccessKey: await sha256Hex(apiToken),
    apiToken,
  };
  cachedIdentity = { apiToken, expectedAccountId, identity };
  return identity;
}

/** The path-style URL of one object (the key encoded once per segment, the way presignS3Put encodes it). */
export function mediaObjectUrl(identity: MediaStoreIdentity, bucket: string, key: string): string {
  return `${identity.endpoint}/${awsUriEncodeComponent(bucket)}/${encodeS3KeyPath(key)}`;
}

async function sendSigned(
  identity: MediaStoreIdentity,
  method: "GET" | "HEAD" | "PUT" | "DELETE",
  url: string,
  extraHeaders?: Record<string, string>,
  timeoutMs?: number,
): Promise<Response | { error: string }> {
  const signed = await signS3Request({
    method,
    url,
    region: R2_REGION,
    accessKeyId: identity.accessKeyId,
    secretAccessKey: identity.secretAccessKey,
    extraHeaders,
    pathIsEncoded: true,
  });
  try {
    const init: RequestInit = { method, headers: signed.headers };
    if (timeoutMs !== undefined) {
      init.signal = AbortSignal.timeout(timeoutMs);
    }
    return await fetch(signed.url, init);
  } catch (err) {
    return { error: `could not reach R2: ${errorMessage(err)}` };
  }
}

async function s3ErrorDetail(what: string, response: Response): Promise<string> {
  const text = (await response.text().catch(() => "")).slice(0, S3_ERROR_BODY_MAX_CHARS);
  const code = extractXmlTag(text, "Code");
  let detail = `${what} failed with HTTP ${response.status}`;
  if (code !== null) {
    detail += ` (${code})`;
  }
  return detail;
}

export interface MediaObjectHead {
  /** The ETag without its quotes. */
  etag: string;
  contentType: string | null;
  size: number | null;
  /**
   * The metadata that CopyObject carries along (system headers and x-amz-meta-*), as one stable string. Two
   * objects with the same ETag but other metadata are different revisions (sameMediaRevision).
   */
  metadataFingerprint: string;
}

// The system metadata that x-amz-metadata-directive: COPY keeps (R2's CopyObject list), plus every x-amz-meta-*.
const FINGERPRINT_SYSTEM_HEADERS = [
  "cache-control",
  "content-disposition",
  "content-encoding",
  "content-language",
  "content-type",
  "expires",
];
const CUSTOM_METADATA_HEADER_PREFIX = "x-amz-meta-";

function metadataFingerprintOf(headers: Headers): string {
  const names: string[] = [...FINGERPRINT_SYSTEM_HEADERS];
  const customNames: string[] = [];
  for (const [name] of headers) {
    if (name.startsWith(CUSTOM_METADATA_HEADER_PREFIX)) {
      customNames.push(name);
    }
  }
  customNames.sort();
  names.push(...customNames);
  const parts: string[] = [];
  for (const name of names) {
    const value = headers.get(name);
    if (value === null) {
      continue;
    }
    // JSON quoting keeps a value that holds "=" or a newline from running into the next part.
    parts.push(`${name}=${JSON.stringify(value)}`);
  }
  return parts.join("\n");
}

/** True when both HEADs show the same bytes AND the same metadata. */
export function sameMediaRevision(first: MediaObjectHead, second: MediaObjectHead): boolean {
  if (first.etag !== second.etag) {
    return false;
  }
  return first.metadataFingerprint === second.metadataFingerprint;
}

/** HEAD one object: its ETag and content type, null when it does not exist. */
export async function headMediaObject(
  identity: MediaStoreIdentity,
  bucket: string,
  key: string,
): Promise<MediaObjectHead | null | { error: string }> {
  const response = await sendSigned(identity, "HEAD", mediaObjectUrl(identity, bucket, key));
  if ("error" in response) {
    return response;
  }
  if (response.status === 404) {
    return null;
  }
  if (response.status !== 200) {
    return { error: `reading ${key} failed with HTTP ${response.status}` };
  }
  const etag = (response.headers.get("etag") ?? "").replace(/"/g, "");
  const sizeText = response.headers.get("content-length");
  let size: number | null = null;
  if (sizeText !== null && /^\d+$/.test(sizeText)) {
    size = Number(sizeText);
  }
  return {
    etag,
    contentType: response.headers.get("content-type"),
    size,
    metadataFingerprint: metadataFingerprintOf(response.headers),
  };
}

/**
 * CopyObject inside one bucket, keeping the source's metadata (x-amz-metadata-directive: COPY). The copy is
 * create-once: it never replaces an existing target (cf-copy-destination-if-none-match: *, a 412 otherwise). With
 * `sourceEtag`, the copy happens only while the source still has that ETag (x-amz-copy-source-if-match), so a
 * copy never takes newer bytes than the caller checked.
 */
export async function copyMediaObject(
  identity: MediaStoreIdentity,
  bucket: string,
  sourceKey: string,
  targetKey: string,
  sourceEtag?: string,
): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const headers: Record<string, string> = {
    "x-amz-copy-source": `/${awsUriEncodeComponent(bucket)}/${encodeS3KeyPath(sourceKey)}`,
    "x-amz-metadata-directive": "COPY",
    "cf-copy-destination-if-none-match": "*",
  };
  if (sourceEtag !== undefined && sourceEtag !== "") {
    headers["x-amz-copy-source-if-match"] = `"${sourceEtag}"`;
  }
  const response = await sendSigned(identity, "PUT", mediaObjectUrl(identity, bucket, targetKey), headers);
  if ("error" in response) {
    return { ok: false, status: 0, error: response.error };
  }
  if (response.status !== 200) {
    return { ok: false, status: response.status, error: await s3ErrorDetail(`copying ${sourceKey} to ${targetKey}`, response) };
  }
  // S3 can answer a CopyObject with 200 and an <Error> body; treat that as a failure.
  const body = await response.text().catch(() => "");
  if (body.includes("<Error>")) {
    const code = extractXmlTag(body, "Code") ?? "unknown error";
    return { ok: false, status: 500, error: `copying ${sourceKey} to ${targetKey} failed (${code})` };
  }
  return { ok: true };
}

/**
 * DeleteObject. A missing object is success (S3 answers 204 either way). R2's DeleteObject takes no condition, so
 * the caller must make sure that nothing else changes the key meanwhile (media-site-api.ts holds a key lease).
 * `timeoutMs` bounds the request; status 0 means the outcome is unknown (R2 may still apply the delete).
 */
export async function deleteMediaObject(
  identity: MediaStoreIdentity,
  bucket: string,
  key: string,
  timeoutMs?: number,
): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const response = await sendSigned(identity, "DELETE", mediaObjectUrl(identity, bucket, key), undefined, timeoutMs);
  if ("error" in response) {
    return { ok: false, status: 0, error: response.error };
  }
  if (response.status === 204 || response.status === 200 || response.status === 404) {
    return { ok: true };
  }
  return { ok: false, status: response.status, error: await s3ErrorDetail(`deleting ${key}`, response) };
}

/** `yyyy-mm-dd` of `nowMs` in UTC. */
export function utcDay(nowMs: number): string {
  return new Date(nowMs).toISOString().slice(0, 10);
}

/**
 * The revision as a folder-name part: 32 hex characters of the SHA-256 of the ETag and the metadata fingerprint.
 * Two revisions with the same bytes but other metadata get different folders, so neither blocks the other's trash
 * copy.
 */
async function revisionFolderPart(source: MediaObjectHead): Promise<string> {
  const digest = await sha256Hex(`${source.etag}\n${source.metadataFingerprint}`);
  return digest.slice(0, 32);
}

export type TrashMoveResult =
  | { ok: true; trashKey: string; copied: boolean }
  | { ok: false; status: number; error: string };

/**
 * Copy `key` (whose HEAD the caller already read) into trash. The caller deletes the original afterwards. Safe to
 * re-run: a trash key that already holds the same revision (ETag and metadata) is reused, not copied again.
 */
export async function moveToTrash(
  identity: MediaStoreIdentity,
  bucket: string,
  key: string,
  source: MediaObjectHead,
  nowMs: number,
): Promise<TrashMoveResult> {
  const day = utcDay(nowMs);
  const revisionFolder = await revisionFolderPart(source);
  const candidates = [`${MEDIA_TRASH_PREFIX}${day}/${key}`, `${MEDIA_TRASH_PREFIX}${day}.${revisionFolder}/${key}`];
  for (const trashKey of candidates) {
    const existing = await headMediaObject(identity, bucket, trashKey);
    if (existing !== null && "error" in existing) {
      return { ok: false, status: 502, error: existing.error };
    }
    if (existing !== null && sameMediaRevision(existing, source)) {
      return { ok: true, trashKey, copied: false };
    }
    if (existing !== null) {
      // Another revision already sits at this trash key, and the bucket lock forbids overwriting it: try the next key.
      continue;
    }
    const copied = await copyMediaObject(identity, bucket, key, trashKey, source.etag);
    if (!copied.ok) {
      return copied;
    }
    return { ok: true, trashKey, copied: true };
  }
  return {
    ok: false,
    status: 409,
    error: `both trash keys for ${key} already hold other revisions: refusing to delete the original without a trash copy.`,
  };
}

export interface MediaTrashEntry {
  key: string;
  size: number | null;
  lastModified: string | null;
  etag: string | null;
}

function decodeXmlText(text: string): string {
  return text.replace(/&(#x[0-9a-fA-F]+|#\d+|amp|lt|gt|quot|apos);/g, (_whole, entity: string) => {
    if (entity === "amp") return "&";
    if (entity === "lt") return "<";
    if (entity === "gt") return ">";
    if (entity === "quot") return '"';
    if (entity === "apos") return "'";
    if (entity.startsWith("#x")) return String.fromCodePoint(parseInt(entity.slice(2), 16));
    return String.fromCodePoint(parseInt(entity.slice(1), 10));
  });
}

/** One ListObjectsV2 page under `prefix`. */
export async function listMediaObjects(
  identity: MediaStoreIdentity,
  bucket: string,
  prefix: string,
  maxKeys: number,
  cursor?: string,
): Promise<{ entries: MediaTrashEntry[]; nextCursor: string | null } | { error: string }> {
  const query = new URLSearchParams();
  query.set("list-type", "2");
  query.set("prefix", prefix);
  query.set("max-keys", String(maxKeys));
  if (cursor !== undefined) {
    query.set("continuation-token", cursor);
  }
  const url = `${identity.endpoint}/${awsUriEncodeComponent(bucket)}?${query.toString()}`;
  const response = await sendSigned(identity, "GET", url);
  if ("error" in response) {
    return response;
  }
  if (response.status !== 200) {
    return { error: await s3ErrorDetail(`listing ${prefix}`, response) };
  }
  const xml = await response.text();
  const entries: MediaTrashEntry[] = [];
  const contentsRe = /<Contents>([\s\S]*?)<\/Contents>/g;
  for (let match = contentsRe.exec(xml); match !== null; match = contentsRe.exec(xml)) {
    const block = match[1] ?? "";
    const rawKey = extractXmlTag(block, "Key");
    if (rawKey === null) {
      continue;
    }
    const sizeText = extractXmlTag(block, "Size");
    let size: number | null = null;
    if (sizeText !== null && /^\d+$/.test(sizeText)) {
      size = Number(sizeText);
    }
    const etagText = extractXmlTag(block, "ETag");
    let etag: string | null = null;
    if (etagText !== null) {
      etag = decodeXmlText(etagText).replace(/"/g, "");
    }
    entries.push({ key: decodeXmlText(rawKey), size, lastModified: extractXmlTag(block, "LastModified"), etag });
  }
  let nextCursor: string | null = null;
  if (extractXmlTag(xml, "IsTruncated") === "true") {
    const token = extractXmlTag(xml, "NextContinuationToken");
    if (token === null || token === "") {
      return { error: `listing ${prefix} returned a truncated page without a continuation token` };
    }
    nextCursor = decodeXmlText(token);
  }
  return { entries, nextCursor };
}
