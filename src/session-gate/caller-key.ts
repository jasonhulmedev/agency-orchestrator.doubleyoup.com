// planning/49 Phase 4 (I3), decision D1 (A): the CALLER KEY of the SessionGateMinter.
//
// WHY: a Workers service binding carries no caller identity. Any Worker script in the same Cloudflare account
// can bind this Worker's SessionGateMinter entrypoint and ask it for Google ID tokens (I4 review M2). So the
// gate proves who it is on every mint call with a key that no other script in the account can compute:
//
//   key   = HKDF-SHA256(ikm = the UTF-8 text of DY_CLIENT_SECRET, empty salt,
//                       info = "dy-session-minter-caller/v1:" + <gate script name>, 32 bytes)
//   proof = { audience, ts, mac }, mac = base64url(HMAC-SHA256(key, "v1|" + audience + "|" + ts)), no padding
//
// <gate script name> is the derived `dy-gate-<project>-<region>` (edgeGateScriptNameFor). ts is Unix seconds.
//
// THE ROOT is DY_CLIENT_SECRET: a high-entropy secret that every fork already has (app issues 32 random
// bytes as 43 base64url characters at onboarding and keeps only a scrypt hash of it). A Worker script cannot
// read another script's secrets, so another script in the account cannot compute the key. The key is bound
// to ONE gate script, so it signs only for that gate's (project, region).
//
// TRUST EDGE (review L2): DY_CLIENT_SECRET is NOT known to this Worker alone. app-client.ts sends it to our
// app's /oauth/token on every token exchange, so our app sees it in transit (and keeps its hash at rest).
// Whoever can read it there can compute every caller key of this Worker. That alone mints nothing: a caller
// must also run a script in the agency's Cloudflare account that binds the minter. The caller key protects
// the minter from the OTHER scripts of the account, not from our app.
//
// edge-gate-deploy puts the key into the gate as the secret_text binding DY_MINTER_CALLER_KEY (64 lowercase
// hex) and a NON-secret fingerprint of it as DY_MINTER_CALLER_FINGERPRINT. The minter derives the same key
// again from DY_CLIENT_SECRET and the audience's region, so it stores nothing.
//
// LIMIT: a principal with Workers Scripts: Edit on the account can still re-upload the gate with its secret
// bindings kept. No caller check stops that (plan §Risks).
//
// This module imports nothing, so the minter, edge-gate-deploy and /validate can all use it without an
// import cycle. gate.js holds its own copy of the MAC (it is uploaded alone); test/session-gate.test.ts
// checks that the two agree.

/** The gate binding that carries the caller key (secret_text, 64 lowercase hex). */
export const MINTER_CALLER_KEY_BINDING = "DY_MINTER_CALLER_KEY";
/** The gate binding that carries the key's non-secret fingerprint (plain_text). /validate reads it back. */
export const MINTER_CALLER_FINGERPRINT_BINDING = "DY_MINTER_CALLER_FINGERPRINT";
/** The HKDF info prefix of the caller key. The gate script name follows it. */
export const MINTER_CALLER_KEY_INFO_PREFIX = "dy-session-minter-caller/v1:";
/** The version tag at the start of every MAC message. */
export const MINTER_CALLER_PROOF_VERSION = "v1";
/** The largest allowed distance, in seconds, between the proof's ts and the minter's clock. */
export const MINTER_CALLER_PROOF_MAX_SKEW_SECONDS = 60;
/** The fixed message of the caller key fingerprint: HMAC-SHA256(key = the 32 key bytes, this message). */
export const MINTER_CALLER_KEY_FINGERPRINT_MESSAGE = "doubleyoup-minter-caller-key-fingerprint/v1";
/**
 * The shortest DY_CLIENT_SECRET that may be the root of a caller key. app issues 43 characters. An empty or
 * short root would give a key that anyone can guess, so a shorter one is refused, never used.
 */
export const CLIENT_SECRET_MIN_LENGTH = 32;

const CALLER_KEY_BITS = 256;
const FINGERPRINT_HEX_LENGTH = 16;

/** True when `clientSecret` may be the root of a caller key (a string of at least CLIENT_SECRET_MIN_LENGTH). */
export function isUsableClientSecret(clientSecret: unknown): clientSecret is string {
  return typeof clientSecret === "string" && clientSecret.length >= CLIENT_SECRET_MIN_LENGTH;
}

/** The caller key of one gate script: 32 bytes. The caller must check isUsableClientSecret first. */
export async function deriveMinterCallerKey(clientSecret: string, gateScriptName: string): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey("raw", new TextEncoder().encode(clientSecret), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(MINTER_CALLER_KEY_INFO_PREFIX + gateScriptName),
    },
    ikm,
    CALLER_KEY_BITS,
  );
  return new Uint8Array(bits);
}

/** The key as the gate's DY_MINTER_CALLER_KEY binding carries it: 64 lowercase hex characters. */
export function minterCallerKeyHex(key: Uint8Array): string {
  let hex = "";
  for (const byte of key) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * A NON-secret fingerprint of a caller key: the first 16 hex characters of
 * HMAC-SHA256(key = the 32 key bytes, message = MINTER_CALLER_KEY_FINGERPRINT_MESSAGE). The same style as
 * the session key fingerprint: it shows that the key changed and says nothing usable about the key.
 */
export async function minterCallerKeyFingerprint(key: Uint8Array): Promise<string> {
  const mac = await hmacSha256(key, MINTER_CALLER_KEY_FINGERPRINT_MESSAGE);
  return minterCallerKeyHex(mac).slice(0, FINGERPRINT_HEX_LENGTH);
}

/** The MAC message of one proof: "v1|" + audience + "|" + ts. */
export function minterCallerProofMessage(audience: string, ts: number): string {
  return `${MINTER_CALLER_PROOF_VERSION}|${audience}|${ts}`;
}

/** The MAC of one proof, base64url with no padding (43 characters). */
export async function minterCallerProofMac(key: Uint8Array, audience: string, ts: number): Promise<string> {
  return bytesToBase64url(await hmacSha256(key, minterCallerProofMessage(audience, ts)));
}

/**
 * True when `ts` and `mac` prove that the caller holds `key` for `audience`, at most
 * MINTER_CALLER_PROOF_MAX_SKEW_SECONDS from `nowSeconds` in either direction. The MAC is compared in
 * constant time. Returns a boolean only, so no refusal can say which part failed.
 */
export async function verifyMinterCallerProof(
  key: Uint8Array,
  audience: string,
  ts: unknown,
  mac: unknown,
  nowSeconds: number,
): Promise<boolean> {
  if (typeof ts !== "number" || !Number.isSafeInteger(ts)) {
    return false;
  }
  if (Math.abs(nowSeconds - ts) > MINTER_CALLER_PROOF_MAX_SKEW_SECONDS) {
    return false;
  }
  if (typeof mac !== "string") {
    return false;
  }
  const expectedMac = await minterCallerProofMac(key, audience, ts);
  return timingSafeEqualStrings(mac, expectedMac);
}

async function hmacSha256(key: Uint8Array, message: string): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(message)));
}

/** base64url(bytes) with NO padding, as Node's digest("base64url") and gate.js's bytesToBase64url. */
function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Constant-time comparison of two strings, so timing does not leak how many MAC characters matched. Only the
 * length (public: every MAC is 43 characters) can end it early.
 */
function timingSafeEqualStrings(received: string, expected: string): boolean {
  if (received.length !== expected.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < expected.length; index++) {
    difference |= received.charCodeAt(index) ^ expected.charCodeAt(index);
  }
  return difference === 0;
}
