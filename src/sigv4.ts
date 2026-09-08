// AWS Signature Version 4 signer for S3 (and S3-compatible) requests.
//
// This is the same hand-rolled SigV4 scheme the doubleyoup media Worker uses to
// read R2, generalized to (a) an arbitrary host/path/query, (b) any region, and
// (c) GET/HEAD reads OR a PUT/DELETE with a body — so it can sign both a
// ListObjectsV2 read and the object PUT/DELETE the write-probe uses (against real
// AWS S3 or an S3-compatible endpoint: R2, MinIO, Wasabi). A bodyless request signs
// the SHA-256 of ""; a request WITH a body signs the literal "UNSIGNED-PAYLOAD" (see
// the payload-hash comment below for why — it's the workerd edge write-probe fix).
// The second half of the file is the QUERY-PARAMETER PRESIGNER (presignS3Url /
// presignS3Put): a URL a third party (the agency's cell) can PUT to without holding the
// credential — used by the Direction-B `db-export` actuator.
//
// INVARIANT: the headers we return to SEND are exactly the headers we SIGNED
// (minus Host, which the runtime sets from the URL) and the wire path/query
// byte-match the canonical request — otherwise the signature check fails. The
// caller MUST still send a body on a body request, but because it is signed
// UNSIGNED-PAYLOAD the exact bytes are no longer hash-verified by the store.

const textEncoder = new TextEncoder();

// SigV4 for S3 uses the fixed service name "s3"; the region is caller-supplied
// (real AWS regions, or "auto" for R2).
const S3_SERVICE = "s3";

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

async function sha256Hex(message: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(message));
  return toHex(new Uint8Array(digest));
}

async function hmacSha256(keyBytes: Uint8Array, message: string): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, textEncoder.encode(message));
  return new Uint8Array(signature);
}

// AWS UriEncode for a single component: escape everything except the unreserved
// set (A-Za-z0-9-_.~). encodeURIComponent already leaves the unreserved set plus
// "!'()*" unescaped and emits upper-hex %XX, so we only additionally escape
// "!'()*" to land exactly on the AWS rule.
function awsUriEncodeComponent(component: string): string {
  return encodeURIComponent(component).replace(
    /[!'()*]/g,
    (char) => "%" + char.charCodeAt(0).toString(16).toUpperCase(),
  );
}

// Canonical URI: encode each path segment but keep "/" as the separator.
function canonicalUri(pathname: string): string {
  return pathname.split("/").map(awsUriEncodeComponent).join("/");
}

// Canonical query string: each key and value AWS-encoded, pairs sorted by
// encoded key (then value). S3 requires this exact ordering/encoding in the
// signature even when the wire query is in a different order.
function canonicalQueryString(searchParams: URLSearchParams): string {
  const encodedPairs: Array<[string, string]> = [];
  for (const [key, value] of searchParams) {
    encodedPairs.push([awsUriEncodeComponent(key), awsUriEncodeComponent(value)]);
  }
  encodedPairs.sort((a, b) => {
    if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
    if (a[1] !== b[1]) return a[1] < b[1] ? -1 : 1;
    return 0;
  });
  return encodedPairs.map(([key, value]) => `${key}=${value}`).join("&");
}

export interface SignedRequest {
  url: string;
  headers: Headers;
}

// Build a SigV4-signed request for the given S3 URL. The URL may carry a query
// string (e.g. "?list-type=2&max-keys=1"); it is signed as-is. For a PUT, pass the
// body — it is signed as UNSIGNED-PAYLOAD (the store won't hash-verify the bytes),
// so the same body must still be sent, but its exact framing no longer matters.
export async function signS3Request(options: {
  method: "GET" | "HEAD" | "PUT" | "DELETE";
  url: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  body?: string;
}): Promise<SignedRequest> {
  const parsed = new URL(options.url);
  const host = parsed.host; // includes a non-default port if present

  // Amazon-format timestamp: "YYYYMMDDTHHMMSSZ" (no punctuation, no millis).
  const amzDate = new Date()
    .toISOString()
    .replace(/[:-]/g, "")
    .replace(/\.\d{3}Z$/, "Z");
  const dateStamp = amzDate.slice(0, 8);

  // Payload-hash choice — and the crux of the workerd write-probe fix:
  //   • bodyless GET/HEAD/DELETE ... the SHA-256 of "" (these already work — unchanged).
  //   • any request WITH a body .... the literal "UNSIGNED-PAYLOAD", NOT sha256(body).
  //
  // Why UNSIGNED-PAYLOAD for a body request: on Cloudflare's edge (workerd) the outbound
  // fetch frames the PUT body differently than Node does, and R2's S3 API then rejects a
  // PUT that carries a fixed body-hash with 400 InvalidArgument. Node and local
  // `wrangler dev` egress to R2's lenient public endpoint and succeed (200 + ETag), so
  // this only bites the DEPLOYED Worker. Signing the body as UNSIGNED-PAYLOAD tells R2 not
  // to verify the body hash, so the runtime's body framing can no longer cause a mismatch.
  // The request stays fully authenticated — the SigV4 signature still covers the method,
  // path, query and every signed header — and the probe object's byte-integrity is
  // irrelevant here (it's a throwaway connectivity/write check).
  const payloadHash = options.body === undefined ? await sha256Hex("") : "UNSIGNED-PAYLOAD";

  // Minimal signed header set: host + the two mandatory x-amz-* headers.
  const signedValues = new Map<string, string>();
  signedValues.set("host", host);
  signedValues.set("x-amz-content-sha256", payloadHash);
  signedValues.set("x-amz-date", amzDate);

  const sortedNames = [...signedValues.keys()].sort();
  const canonicalHeaders = sortedNames
    .map((name) => `${name}:${signedValues.get(name)}\n`)
    .join("");
  const signedHeaderList = sortedNames.join(";");

  const canonicalRequest =
    `${options.method}\n` +
    `${canonicalUri(parsed.pathname)}\n` +
    `${canonicalQueryString(parsed.searchParams)}\n` +
    `${canonicalHeaders}\n` +
    `${signedHeaderList}\n` +
    `${payloadHash}`;

  const scope = `${dateStamp}/${options.region}/${S3_SERVICE}/aws4_request`;
  const stringToSign =
    `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await sha256Hex(canonicalRequest)}`;

  // Derive the signing key: HMAC chain over date → region → service → "aws4_request".
  const kDate = await hmacSha256(textEncoder.encode("AWS4" + options.secretAccessKey), dateStamp);
  const kRegion = await hmacSha256(kDate, options.region);
  const kService = await hmacSha256(kRegion, S3_SERVICE);
  const kSigning = await hmacSha256(kService, "aws4_request");
  const signature = toHex(await hmacSha256(kSigning, stringToSign));

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${options.accessKeyId}/${scope}, ` +
    `SignedHeaders=${signedHeaderList}, Signature=${signature}`;

  // Send exactly what we signed, minus Host (runtime sets it from the URL).
  const outHeaders = new Headers();
  outHeaders.set("x-amz-content-sha256", payloadHash);
  outHeaders.set("x-amz-date", amzDate);
  outHeaders.set("authorization", authorization);

  return { url: options.url, headers: outHeaders };
}

// ── Query-parameter PRESIGNING (a URL a THIRD PARTY can use, no credential attached) ──────
//
// The auth-HEADER signer above is for requests THIS Worker sends. A PRESIGNED URL is different:
// the signature travels in the QUERY STRING (X-Amz-Signature=...) so that someone WITHOUT the
// S3 credential — here, the agency's cell, running `curl --upload-file` — can make exactly one
// kind of request (one method, one object) until the URL expires. The secret key never leaves
// this Worker; the URL carries only a derived signature, the access-key ID, and the expiry.
//
// The scheme is the standard SigV4 "Authenticating Requests: Using Query Parameters":
//   canonical request = <METHOD>\n<encoded path>\n<canonical query WITHOUT X-Amz-Signature>\n
//                       host:<host>\n\nhost\nUNSIGNED-PAYLOAD
//   canonical query   = X-Amz-Algorithm=AWS4-HMAC-SHA256
//                     & X-Amz-Credential=<akid>/<date>/<region>/s3/aws4_request   (slashes %2F)
//                     & X-Amz-Date=<YYYYMMDDTHHMMSSZ> & X-Amz-Expires=<seconds>
//                     & X-Amz-SignedHeaders=host                                    (sorted)
//   string to sign    = AWS4-HMAC-SHA256\n<amzDate>\n<scope>\nsha256(canonical request)
//   signature         = hex(HMAC(kSigning, string to sign)), appended as X-Amz-Signature.
//
// Payload: ALWAYS "UNSIGNED-PAYLOAD". For a presigned URL the signer never sees the body (the
// cell produces it later), so the body hash cannot be part of the signature — this is the ONLY
// payload mode that makes sense for a presign, and it is also exactly the mode the header signer
// above had to adopt for its PUT (see the workerd write-probe note): R2 then does not hash-verify
// the bytes, but the signature still binds the method, path, query, host and expiry.
//
// Only `host` is a signed header — the uploader (curl) adds its own Content-Length / User-Agent /
// Expect headers, and none of those may be covered by the signature or the upload would fail.

/** A presigned URL plus the two intermediate strings it was derived from (for the pin test +
 *  diagnostics — neither contains the secret key; the signature is derived FROM them WITH it). */
export interface PresignedUrl {
  url: string;
  canonicalRequest: string;
  stringToSign: string;
}

// Amazon-format timestamp: "YYYYMMDDTHHMMSSZ" (no punctuation, no millis).
function formatAmzDate(date: Date): string {
  return date
    .toISOString()
    .replace(/[:-]/g, "")
    .replace(/\.\d{3}Z$/, "Z");
}

// Derive the SigV4 signing key: HMAC chain over date → region → service → "aws4_request".
async function deriveSigningKey(secretAccessKey: string, dateStamp: string, region: string): Promise<Uint8Array> {
  const kDate = await hmacSha256(textEncoder.encode("AWS4" + secretAccessKey), dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, S3_SERVICE);
  return hmacSha256(kService, "aws4_request");
}

/**
 * Presign an S3 URL (query-parameter SigV4) for `method`, valid for `expiresSeconds` from
 * `nowMs` (default: now — injectable so a test can pin the exact output).
 *
 * `url` is `<scheme>://<host>[:port]<path>` with an OPTIONAL existing query. The PATH must
 * already be AWS-URI-encoded (presignS3Put does this): for S3 the canonical URI is the wire
 * path taken byte-for-byte (single encoding, no re-encoding), so we sign `pathname` verbatim
 * — re-encoding it here would turn an intended "%2A" into "%252A" and break the signature.
 * Any query already on `url` is folded into the canonical (sorted) query and re-emitted on the
 * wire in that same sorted form, so wire bytes == signed bytes.
 */
export async function presignS3Url(options: {
  method: "GET" | "PUT";
  url: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  expiresSeconds: number;
  nowMs?: number;
}): Promise<PresignedUrl> {
  const parsed = new URL(options.url);
  const host = parsed.host; // includes a non-default port if present

  const amzDate = formatAmzDate(new Date(options.nowMs ?? Date.now()));
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${options.region}/${S3_SERVICE}/aws4_request`;

  // The signed query: everything already on the URL plus the five X-Amz-* auth parameters.
  // X-Amz-Signature is deliberately NOT here — it is computed FROM this query and appended after.
  const query = new URLSearchParams(parsed.searchParams);
  query.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
  query.set("X-Amz-Credential", `${options.accessKeyId}/${scope}`);
  query.set("X-Amz-Date", amzDate);
  query.set("X-Amz-Expires", String(options.expiresSeconds));
  query.set("X-Amz-SignedHeaders", "host");
  const canonicalQuery = canonicalQueryString(query);

  const canonicalRequest =
    `${options.method}\n` +
    `${parsed.pathname}\n` +
    `${canonicalQuery}\n` +
    `host:${host}\n` +
    `\n` +
    `host\n` +
    `UNSIGNED-PAYLOAD`;

  const stringToSign =
    `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await sha256Hex(canonicalRequest)}`;

  const signingKey = await deriveSigningKey(options.secretAccessKey, dateStamp, options.region);
  const signature = toHex(await hmacSha256(signingKey, stringToSign));

  // Wire URL: the SAME sorted, AWS-encoded query we signed, then the signature last.
  const url = `${parsed.protocol}//${host}${parsed.pathname}?${canonicalQuery}&X-Amz-Signature=${signature}`;
  return { url, canonicalRequest, stringToSign };
}

/**
 * Presign a PUT of ONE object so a third party can upload it without the credential.
 *
 * URL style follows the validate write-probe (validators.ts::validateS3):
 *   • `endpoint` set (Cloudflare R2, MinIO, Wasabi) — path-style `<endpoint>/<bucket>/<key>`;
 *   • no `endpoint` (real AWS S3) — virtual-hosted `https://<bucket>.s3.<region>.amazonaws.com/<key>`.
 * The bucket and each `/`-separated key segment are AWS-URI-encoded exactly once here; the
 * path then goes to presignS3Url verbatim (see its encoding contract).
 */
export async function presignS3Put(options: {
  endpoint?: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  key: string;
  expiresSeconds: number;
  nowMs?: number;
}): Promise<PresignedUrl> {
  const encodedKey = options.key.split("/").map(awsUriEncodeComponent).join("/");

  let objectUrl: string;
  if (options.endpoint) {
    const endpoint = new URL(options.endpoint);
    // Keep any path prefix the endpoint carries (normally none — R2 endpoints are bare hosts),
    // minus a trailing slash so the join never produces "//".
    const basePath = endpoint.pathname.replace(/\/+$/, "");
    objectUrl = `${endpoint.protocol}//${endpoint.host}${basePath}/${awsUriEncodeComponent(options.bucket)}/${encodedKey}`;
  } else {
    objectUrl = `https://${options.bucket}.s3.${options.region}.amazonaws.com/${encodedKey}`;
  }

  return presignS3Url({
    method: "PUT",
    url: objectUrl,
    region: options.region,
    accessKeyId: options.accessKeyId,
    secretAccessKey: options.secretAccessKey,
    expiresSeconds: options.expiresSeconds,
    nowMs: options.nowMs,
  });
}
