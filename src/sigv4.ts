// AWS Signature Version 4 signer for S3 (and S3-compatible) GET/HEAD requests.
//
// This is the same hand-rolled SigV4 scheme the doubleyoup media Worker uses to
// read R2, generalized to (a) an arbitrary host/path/query and (b) any region,
// so it can sign a ListObjectsV2 probe against either real AWS S3 or an
// S3-compatible endpoint (R2, MinIO, Wasabi). We only ever sign empty-body
// GET/HEAD reads here, so the payload hash is always the SHA-256 of "".
//
// INVARIANT: the headers we return to SEND are exactly the headers we SIGNED
// (minus Host, which the runtime sets from the URL) and the wire path/query
// byte-match the canonical request — otherwise the signature check fails.

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

// Build a SigV4-signed GET/HEAD for the given S3 URL. The URL may carry a query
// string (e.g. "?list-type=2&max-keys=1"); it is signed as-is.
export async function signS3Request(options: {
  method: "GET" | "HEAD";
  url: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}): Promise<SignedRequest> {
  const parsed = new URL(options.url);
  const host = parsed.host; // includes a non-default port if present

  // Amazon-format timestamp: "YYYYMMDDTHHMMSSZ" (no punctuation, no millis).
  const amzDate = new Date()
    .toISOString()
    .replace(/[:-]/g, "")
    .replace(/\.\d{3}Z$/, "Z");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256Hex(""); // GET/HEAD carry no body

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
