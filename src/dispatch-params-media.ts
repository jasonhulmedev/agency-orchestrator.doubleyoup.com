// ── hub#222: media soft delete ─────────────────────────────────────────────────────────────────────
// The PARAMS of the media soft-delete ops (agency Worker side), and the key rules the site-facing media API
// (media-site-api.ts) shares with them.
//
// THE MODEL (hub#222, approved by Jason 2026-11-03). The agency Worker is the only writer of a site's R2 media
// bucket. The site holds no R2 key: its mu-plugin calls this Worker with a per-site credential, and every delete,
// rename and overwrite first copies the object to `trash/<UTC yyyy-mm-dd>/<key>`. A bucket lock keeps `trash/`
// for 30 days and a lifecycle rule expires it after 31.
//
// THIS FILE IS A PINNED TWIN. The app signs these Direction-B ops and carries this file byte for byte; each repo's
// test suite pins the sha256 of the whole file (here: test/media-soft-delete.test.ts). Change both twins and both
// pins together. That is why the file imports nothing: the same bytes must compile in both repos.
//
// Six Direction-B ops:
//   media-bucket-protect           the `trash/` lifecycle rule (expire after 31 days) and the `trash/` bucket lock
//                                  (30 days) on ONE media bucket. Idempotent: it keeps every other rule.
//   media-site-credential-install  write the Worker-mode wp-config constants (DOUBLEYOUP_MEDIA_WORKER_URL,
//                                  DOUBLEYOUP_MEDIA_SITE_TOKEN) through the site's file-node cell-agent, which removes
//                                  DOUBLEYOUP_R2_KEY / DOUBLEYOUP_R2_SECRET. Idempotent: the credential is derived.
//   media-site-key-revoke          delete the site's old per-site R2 key (minted by r2-site-key-install).
//   media-trash-list               READ one page of `trash/` keys.
//   media-restore                  copy one trash object back, create-once (never over a live object).
//   media-bulk-credential          a short-lived R2 temporary credential for ONE bucket and ONE site prefix, for a
//                                  bulk offload engine only.
//
// Every bucket is `doubleyoup-media-<prefix>` (isR2MediaBucketName), and every live key is `<prefix>/...`, the shape
// the mu-plugin writes (doubleyoup_r2_prefix() . '/' . <uploads-relative path>).

/** Outcome of validating a parsed params object (the same shape as dispatch-params.ts::ParamsVerdict). */
export type MediaParamsVerdict<P> = { ok: true; params: P } | { ok: false; reason: string };

/** The name of the bucket area that holds soft-deleted objects. */
export const MEDIA_TRASH_PREFIX = "trash/";

const MEDIA_BUCKET_NAME_PREFIX = "doubleyoup-media-";

/**
 * The longest live key, in UTF-8 bytes. R2 allows 1024; a trash key adds `trash/<date>.<revision>/` (6 + 10 + 1 +
 * 32 + 1 = 50 bytes), so a live key keeps room for that.
 */
export const MEDIA_KEY_MAX_BYTES = 900;
const MEDIA_TRASH_KEY_MAX_BYTES = 1024;
const MEDIA_TRASH_LIST_PREFIX_MAX_BYTES = 900;
const MEDIA_TRASH_LIST_CURSOR_MAX_LENGTH = 1024;

/** The longest-lived bulk credential: 12 hours (hub#222). */
export const MEDIA_BULK_CREDENTIAL_MAX_TTL_SECONDS = 43200;
export const MEDIA_BULK_CREDENTIAL_MIN_TTL_SECONDS = 60;

/** One presigned upload carries at most 5 GiB, the R2 limit of a single PUT. */
export const MEDIA_UPLOAD_MAX_BYTES = 5 * 1024 * 1024 * 1024;

const MEDIA_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,45}$/;
// The same grammars as dispatch-params.ts (R2_MEDIA_PREFIX_RE, R2_MEDIA_HOST_RE), repeated so this file stands alone.
const MEDIA_BUCKET_SITE_PREFIX_RE = /^[a-z0-9][a-z0-9-]{0,45}$/;
const MEDIA_HOST_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const MEDIA_HOST_MAX_LENGTH = 253;
const HTTPS_SCHEME = "https://";
const MEDIA_TOKEN_ID_RE = /^[a-f0-9]{32}$/;
const MEDIA_FILE_AGENT_TOKEN_RE = /^[a-f0-9]{64}$/;
// A MIME type with optional parameters, printable ASCII only (no CR/LF), as an HTTP header value can carry it.
const MEDIA_CONTENT_TYPE_RE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}(?:\s*;\s*[ -~]{1,200})?$/;
const MEDIA_CONTENT_TYPE_MAX_LENGTH = 255;
// A ListObjectsV2 continuation token is opaque; R2's are base64-like. Printable ASCII, no spaces.
const MEDIA_CURSOR_RE = /^[!-~]+$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unknownKeyReason(raw: Record<string, unknown>, allowedKeys: readonly string[], op: string): string | null {
  for (const key of Object.keys(raw)) {
    if (!allowedKeys.includes(key)) {
      return `${op} does not take "${key}"`;
    }
  }
  return null;
}

function utf8Length(text: string): number {
  return new TextEncoder().encode(text).byteLength;
}

/** The site prefix of a media bucket: `doubleyoup-media-<prefix>` -> `<prefix>`. Call only for a valid bucket name. */
export function mediaBucketSitePrefix(bucket: string): string {
  return bucket.slice(MEDIA_BUCKET_NAME_PREFIX.length);
}

/**
 * The path rules every key and key prefix of these ops follows: no empty segment (so no leading "/" and no "//"),
 * no "." or ".." segment, no backslash, no control character. A ".." anywhere in a SEGMENT name ("a..b.jpg") is a
 * normal file name and stays allowed; only a ".." SEGMENT is a path trick.
 */
function pathRuleViolation(path: string, allowTrailingSlash: boolean): string | null {
  if (path.length === 0) {
    return "must not be empty";
  }
  for (const character of path) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return "must not contain a control character";
    }
    if (character === "\\") {
      return "must not contain a backslash";
    }
  }
  let segments = path.split("/");
  if (allowTrailingSlash && path.endsWith("/")) {
    segments = segments.slice(0, -1);
  }
  for (const segment of segments) {
    if (segment === "") {
      return "must not start with \"/\" or contain an empty segment (\"//\")";
    }
    if (segment === "." || segment === "..") {
      return "must not contain a \".\" or \"..\" segment";
    }
  }
  return null;
}

/**
 * The reason a LIVE key is refused for `bucket`, or null when it is fine. A live key is `<prefix>/<rest>`: under the
 * site's own prefix, never under `trash/`, and never under `<prefix>/trash/` either (the media Worker refuses to
 * serve both, so such an object could never be read).
 */
export function mediaLiveKeyViolation(bucket: string, key: unknown, field: string): string | null {
  if (typeof key !== "string") {
    return `${field} must be a string`;
  }
  if (utf8Length(key) > MEDIA_KEY_MAX_BYTES) {
    return `${field} must be at most ${MEDIA_KEY_MAX_BYTES} bytes`;
  }
  const pathViolation = pathRuleViolation(key, false);
  if (pathViolation !== null) {
    return `${field} ${pathViolation}`;
  }
  if (key.startsWith(MEDIA_TRASH_PREFIX)) {
    return `${field} must not be under trash/`;
  }
  const sitePrefix = `${mediaBucketSitePrefix(bucket)}/`;
  if (!key.startsWith(sitePrefix) || key.length === sitePrefix.length) {
    return `${field} must be under the site's prefix ${sitePrefix}`;
  }
  if (key.slice(sitePrefix.length).startsWith(MEDIA_TRASH_PREFIX)) {
    return `${field} must not be under ${sitePrefix}trash/`;
  }
  return null;
}

/** The reason a TRASH key is refused, or null. A trash key is `trash/<day folder>/<live key>`. */
export function mediaTrashKeyViolation(key: unknown, field: string): string | null {
  if (typeof key !== "string") {
    return `${field} must be a string`;
  }
  if (utf8Length(key) > MEDIA_TRASH_KEY_MAX_BYTES) {
    return `${field} must be at most ${MEDIA_TRASH_KEY_MAX_BYTES} bytes`;
  }
  const pathViolation = pathRuleViolation(key, false);
  if (pathViolation !== null) {
    return `${field} ${pathViolation}`;
  }
  if (!key.startsWith(MEDIA_TRASH_PREFIX)) {
    return `${field} must be under trash/`;
  }
  // trash/<day folder>/<at least one more segment>
  if (key.split("/").length < 3) {
    return `${field} must be trash/<day>/<key>`;
  }
  return null;
}

/**
 * The live key a trash key restores to by default: `trash/<day folder>/<key>` -> `<key>`. The day folder is
 * `yyyy-mm-dd` or `yyyy-mm-dd.<revision>` (media-store.ts::moveToTrash); either way it is one segment.
 */
export function mediaDefaultRestoreTarget(trashKey: string): string {
  const segments = trashKey.split("/");
  return segments.slice(2).join("/");
}

/** True for exactly `https://<lowercase DNS host>`: no path, port, query, user part or trailing slash. */
export function isMediaHttpsOrigin(value: unknown): value is string {
  if (typeof value !== "string" || !value.startsWith(HTTPS_SCHEME)) {
    return false;
  }
  const host = value.slice(HTTPS_SCHEME.length);
  return host.length <= MEDIA_HOST_MAX_LENGTH && MEDIA_HOST_RE.test(host);
}

export function isMediaBucketForSite(bucket: unknown): bucket is string {
  if (typeof bucket !== "string" || !bucket.startsWith(MEDIA_BUCKET_NAME_PREFIX)) {
    return false;
  }
  if (!MEDIA_BUCKET_SITE_PREFIX_RE.test(mediaBucketSitePrefix(bucket))) {
    return false;
  }
  // A site whose prefix is "trash" would write its live media under trash/: never a valid site bucket here.
  return mediaBucketSitePrefix(bucket) !== "trash";
}

const MEDIA_BUCKET_RULE =
  "bucket must be doubleyoup-media-<prefix> (prefix: 1-46 characters, lowercase letters, digits and hyphens, starting with a letter or digit; not \"trash\")";

/** The verdict on a site upload's content type and length (sign-put and replace). */
export function mediaUploadViolation(contentType: unknown, contentLength: unknown): string | null {
  if (typeof contentType !== "string" || contentType.length > MEDIA_CONTENT_TYPE_MAX_LENGTH || !MEDIA_CONTENT_TYPE_RE.test(contentType)) {
    return "contentType must be a MIME type such as image/jpeg (printable ASCII, at most 255 characters)";
  }
  if (typeof contentLength !== "number" || !Number.isSafeInteger(contentLength) || contentLength < 0 || contentLength > MEDIA_UPLOAD_MAX_BYTES) {
    return `contentLength must be a whole number of bytes from 0 to ${MEDIA_UPLOAD_MAX_BYTES}`;
  }
  return null;
}

// ── media-bucket-protect ───────────────────────────────────────────────────────────────────────────────

export interface MediaBucketProtectParams {
  bucket: string;
}

export function validateMediaBucketProtectParams(raw: unknown): MediaParamsVerdict<MediaBucketProtectParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, ["bucket"], "media-bucket-protect");
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (!isMediaBucketForSite(raw.bucket)) {
    return { ok: false, reason: MEDIA_BUCKET_RULE };
  }
  return { ok: true, params: { bucket: raw.bucket } };
}

// ── media-site-credential-install ──────────────────────────────────────────────────────────────────────

export interface MediaSiteCredentialInstallParams {
  /** The site slug: the file-node cell-agent derives the site's config path from it. */
  slug: string;
  /** The site's media bucket. The credential is HMAC-SHA256(MEDIA_SITE_SECRET, bucket). */
  bucket: string;
  /** This agency Worker's public base URL, exactly `https://<lowercase host>`: DOUBLEYOUP_MEDIA_WORKER_URL. */
  workerUrl: string;
  /** The site's FILE-NODE cell-agent, `https://<lowercase host>`. Sent with fileAgentToken, or neither is sent. */
  fileAgentUrl?: string;
  /** The bearer token of that agent: 64 lowercase hex characters. A secret: no answer repeats it. */
  fileAgentToken?: string;
}

export function validateMediaSiteCredentialInstallParams(raw: unknown): MediaParamsVerdict<MediaSiteCredentialInstallParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, ["slug", "bucket", "workerUrl", "fileAgentUrl", "fileAgentToken"], "media-site-credential-install");
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (typeof raw.slug !== "string" || !MEDIA_SLUG_RE.test(raw.slug)) {
    return { ok: false, reason: "slug must be 1-46 lowercase letters, digits and hyphens, starting with a letter or digit" };
  }
  if (!isMediaBucketForSite(raw.bucket)) {
    return { ok: false, reason: MEDIA_BUCKET_RULE };
  }
  if (!isMediaHttpsOrigin(raw.workerUrl)) {
    return { ok: false, reason: "workerUrl must be exactly https://<lowercase host> (no path, port, query or trailing slash)" };
  }
  const hasAgentUrl = raw.fileAgentUrl !== undefined;
  const hasAgentToken = raw.fileAgentToken !== undefined;
  if (hasAgentUrl !== hasAgentToken) {
    return { ok: false, reason: "fileAgentUrl and fileAgentToken go together: send both or neither" };
  }
  const params: MediaSiteCredentialInstallParams = { slug: raw.slug, bucket: raw.bucket, workerUrl: raw.workerUrl };
  if (hasAgentUrl) {
    if (!isMediaHttpsOrigin(raw.fileAgentUrl)) {
      return { ok: false, reason: "fileAgentUrl must be exactly https://<lowercase host> (no path, port, query or trailing slash)" };
    }
    if (typeof raw.fileAgentToken !== "string" || !MEDIA_FILE_AGENT_TOKEN_RE.test(raw.fileAgentToken)) {
      return { ok: false, reason: "fileAgentToken must be 64 lowercase hex characters" };
    }
    params.fileAgentUrl = raw.fileAgentUrl;
    params.fileAgentToken = raw.fileAgentToken;
  }
  return { ok: true, params };
}

// ── media-site-key-revoke ──────────────────────────────────────────────────────────────────────────────

export interface MediaSiteKeyRevokeParams {
  /** The site slug (reported back; the key's NAME is what proves it belongs to the bucket). */
  slug: string;
  /** The media bucket the key was minted for: the revoke deletes only a key named dy-media-<bucket>-<label>. */
  bucket: string;
  /** The Cloudflare API token id of the old key (its S3 access key id). */
  tokenId: string;
}

export function validateMediaSiteKeyRevokeParams(raw: unknown): MediaParamsVerdict<MediaSiteKeyRevokeParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, ["slug", "bucket", "tokenId"], "media-site-key-revoke");
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (typeof raw.slug !== "string" || !MEDIA_SLUG_RE.test(raw.slug)) {
    return { ok: false, reason: "slug must be 1-46 lowercase letters, digits and hyphens, starting with a letter or digit" };
  }
  if (!isMediaBucketForSite(raw.bucket)) {
    return { ok: false, reason: MEDIA_BUCKET_RULE };
  }
  if (typeof raw.tokenId !== "string" || !MEDIA_TOKEN_ID_RE.test(raw.tokenId)) {
    return { ok: false, reason: "tokenId must be 32 lowercase hex characters (a Cloudflare API token id)" };
  }
  return { ok: true, params: { slug: raw.slug, bucket: raw.bucket, tokenId: raw.tokenId } };
}

// ── media-trash-list ───────────────────────────────────────────────────────────────────────────────────

export interface MediaTrashListParams {
  bucket: string;
  /** Optional: narrow the page to `trash/<prefix>`, e.g. "2026-11-04/" or "2026-11-04/acme/2024/". */
  prefix?: string;
  /** Optional: the `cursor` a previous page returned. */
  cursor?: string;
}

export function validateMediaTrashListParams(raw: unknown): MediaParamsVerdict<MediaTrashListParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, ["bucket", "prefix", "cursor"], "media-trash-list");
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (!isMediaBucketForSite(raw.bucket)) {
    return { ok: false, reason: MEDIA_BUCKET_RULE };
  }
  const params: MediaTrashListParams = { bucket: raw.bucket };
  if (raw.prefix !== undefined) {
    if (typeof raw.prefix !== "string" || utf8Length(raw.prefix) > MEDIA_TRASH_LIST_PREFIX_MAX_BYTES) {
      return { ok: false, reason: `prefix must be a string of at most ${MEDIA_TRASH_LIST_PREFIX_MAX_BYTES} bytes` };
    }
    // The prefix is RELATIVE to trash/; an empty prefix means "all of trash/" and is the same as leaving it out.
    if (raw.prefix !== "") {
      const violation = pathRuleViolation(raw.prefix, true);
      if (violation !== null) {
        return { ok: false, reason: `prefix ${violation}` };
      }
      params.prefix = raw.prefix;
    }
  }
  if (raw.cursor !== undefined) {
    if (typeof raw.cursor !== "string" || raw.cursor.length > MEDIA_TRASH_LIST_CURSOR_MAX_LENGTH || !MEDIA_CURSOR_RE.test(raw.cursor)) {
      return { ok: false, reason: "cursor must be the cursor a previous media-trash-list page returned" };
    }
    params.cursor = raw.cursor;
  }
  return { ok: true, params };
}

// ── media-restore ──────────────────────────────────────────────────────────────────────────────────────

export interface MediaRestoreParams {
  bucket: string;
  /** The trash object, `trash/<day>/<key>`. */
  trashKey: string;
  /** The live key to restore to. Default: the trash key without `trash/<day>/`. */
  targetKey: string;
}

export function validateMediaRestoreParams(raw: unknown): MediaParamsVerdict<MediaRestoreParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, ["bucket", "trashKey", "targetKey"], "media-restore");
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (!isMediaBucketForSite(raw.bucket)) {
    return { ok: false, reason: MEDIA_BUCKET_RULE };
  }
  const trashViolation = mediaTrashKeyViolation(raw.trashKey, "trashKey");
  if (trashViolation !== null) {
    return { ok: false, reason: trashViolation };
  }
  const trashKey = raw.trashKey as string;
  let targetKey: unknown = raw.targetKey;
  if (targetKey === undefined) {
    targetKey = mediaDefaultRestoreTarget(trashKey);
  }
  const targetViolation = mediaLiveKeyViolation(raw.bucket, targetKey, "targetKey");
  if (targetViolation !== null) {
    return { ok: false, reason: targetViolation };
  }
  return { ok: true, params: { bucket: raw.bucket, trashKey, targetKey: targetKey as string } };
}

// ── media-bulk-credential ──────────────────────────────────────────────────────────────────────────────

export interface MediaBulkCredentialParams {
  bucket: string;
  /** `<site prefix>/` or a folder under it, ending in "/". Never trash/. */
  prefix: string;
  /** 60 to 43200 seconds (12 hours). */
  ttlSeconds: number;
}

export function validateMediaBulkCredentialParams(raw: unknown): MediaParamsVerdict<MediaBulkCredentialParams> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "params must be a JSON object" };
  }
  const unknownKey = unknownKeyReason(raw, ["bucket", "prefix", "ttlSeconds"], "media-bulk-credential");
  if (unknownKey !== null) {
    return { ok: false, reason: unknownKey };
  }
  if (!isMediaBucketForSite(raw.bucket)) {
    return { ok: false, reason: MEDIA_BUCKET_RULE };
  }
  const sitePrefix = `${mediaBucketSitePrefix(raw.bucket)}/`;
  if (typeof raw.prefix !== "string" || !raw.prefix.startsWith(sitePrefix) || !raw.prefix.endsWith("/")) {
    return { ok: false, reason: `prefix must be ${sitePrefix} or a folder under it, ending in "/"` };
  }
  if (utf8Length(raw.prefix) > MEDIA_KEY_MAX_BYTES) {
    return { ok: false, reason: `prefix must be at most ${MEDIA_KEY_MAX_BYTES} bytes` };
  }
  const pathViolation = pathRuleViolation(raw.prefix, true);
  if (pathViolation !== null) {
    return { ok: false, reason: `prefix ${pathViolation}` };
  }
  if (raw.prefix.slice(sitePrefix.length).startsWith(MEDIA_TRASH_PREFIX)) {
    return { ok: false, reason: `prefix must not be under ${sitePrefix}trash/` };
  }
  const ttl = raw.ttlSeconds;
  if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < MEDIA_BULK_CREDENTIAL_MIN_TTL_SECONDS || ttl > MEDIA_BULK_CREDENTIAL_MAX_TTL_SECONDS) {
    return {
      ok: false,
      reason: `ttlSeconds must be a whole number from ${MEDIA_BULK_CREDENTIAL_MIN_TTL_SECONDS} to ${MEDIA_BULK_CREDENTIAL_MAX_TTL_SECONDS}`,
    };
  }
  return { ok: true, params: { bucket: raw.bucket, prefix: raw.prefix, ttlSeconds: ttl } };
}
