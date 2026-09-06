// Direction-B signed-dispatch VERIFICATION (agency Worker side). This is the trust
// boundary: the platform (orchestrator) POSTs a job it wants THIS Worker to run, and
// this module decides whether to believe it — using ONLY the agency's own ed25519
// PUBLIC key (DY_SIGNING_PUBLIC_KEY). The matching PRIVATE key lives in our control-
// plane app and never leaves it, so a valid signature proves the job really came from
// the platform. Nothing in here can be actuated without a good signature.
//
// Worker-native only: Web Crypto (crypto.subtle) + fetch, matching the existing SigV4
// validators. ed25519 is verified with the standard { name: "Ed25519" } algorithm,
// which Cloudflare Workers support at the repo's compatibility_date.
//
// ── CANONICAL SERIALIZATION — MUST stay byte-for-byte identical to the app's ────────
// app/src/server/services/agency-dispatch-signing.ts::canonicalizeDispatchJob. A job is
// a FLAT map of exactly the five string fields in DISPATCH_JOB_KEYS; its canonical form
// is compact JSON with those five keys in ASCENDING codepoint order (the fixed order of
// the constant below), each key + value escaped by JSON.stringify, no whitespace. The
// signed/verified bytes are the UTF-8 encoding of that string. If these two functions
// ever diverge by a single byte, every verification silently fails. Do not "tidy" one
// without the other.

import type { Env } from "./env.js";

// The ops this Worker will actuate. Enforced INDEPENDENTLY of the app's copy (defense in
// depth): a job whose `op` is not here is rejected before any side effect. Adding an op here
// is gated on the replay-hardening prerequisite documented at FRESHNESS_WINDOW_SECONDS —
// only idempotent ops are safe on the timestamp window alone.
export const DISPATCH_OPS = ["provision-r2"] as const;
export type DispatchOp = (typeof DISPATCH_OPS)[number];

// The five canonical job keys, in the FIXED ascending-codepoint order the serializer
// emits them. Also the exact-key allowlist: a job with any other/missing key is rejected.
export const DISPATCH_JOB_KEYS = ["accountId", "bucketName", "nonce", "op", "timestamp"] as const;

export interface DispatchJob {
  op: DispatchOp;
  bucketName: string;
  accountId: string;
  timestamp: string;
  nonce: string;
}

// How far the job's `timestamp` may be from "now" (either direction) and still be fresh.
// The timestamp window is the ONLY replay protection here: a captured job CAN be replayed
// freely within this window.
//
// ⚠️ HARD PREREQUISITE before extending DISPATCH_OPS: the ±window admits replay, so it is
// only safe today because the sole op — provision-r2 — is IDEMPOTENT (replaying it just
// re-creates/no-ops the same bucket). A shared SINGLE-USE nonce store (Workers KV / D1 /
// Durable Object, to remember spent nonces across isolates + requests — module scope is
// NOT enough at the edge) is a REQUIRED precondition before adding ANY non-idempotent or
// destructive op to the allowlist. Do not add such an op on the timestamp window alone.
export const FRESHNESS_WINDOW_SECONDS = 120;

// R2 bucket-name grammar, mirrored from the app so the actuator re-checks it (the app
// won't sign an invalid name, but the Worker is the last line before the CF API call).
const R2_BUCKET_NAME_RE = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

/** True when `name` is a syntactically valid R2 bucket name. */
export function isValidR2BucketName(name: string): boolean {
  return R2_BUCKET_NAME_RE.test(name);
}

// Byte-for-byte twin of the app's canonicalizeDispatchJob (see the header note).
export function canonicalizeDispatchJob(job: DispatchJob): string {
  const parts: string[] = [];
  for (const key of DISPATCH_JOB_KEYS) {
    const value = (job as unknown as Record<string, unknown>)[key];
    if (typeof value !== "string") {
      throw new Error(`dispatch job field "${key}" must be a string`);
    }
    parts.push(`${JSON.stringify(key)}:${JSON.stringify(value)}`);
  }
  return `{${parts.join(",")}}`;
}

// Ed25519 SPKI DER is a fixed 44-byte structure: a 12-byte prefix followed by the raw
// 32-byte public key. We import the RAW key (universally supported by Web Crypto) rather
// than depend on "spki" import in workerd. This prefix is the standard OID header for an
// Ed25519 SubjectPublicKeyInfo; a key that doesn't start with it isn't an Ed25519 SPKI.
const ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";

/**
 * Parse an SPKI-PEM ed25519 public key into the raw 32 bytes, or return null if it is not
 * a well-formed ed25519 SPKI (fail closed — never guess).
 */
function ed25519RawPublicKeyFromSpkiPem(pem: string): Uint8Array | null {
  const base64Body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  let der: Uint8Array;
  try {
    der = Uint8Array.from(atob(base64Body), (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
  if (der.length !== 44) return null;

  let prefixHex = "";
  for (let i = 0; i < 12; i++) prefixHex += der[i].toString(16).padStart(2, "0");
  if (prefixHex !== ED25519_SPKI_PREFIX_HEX) return null;

  return der.subarray(12);
}

/** Discriminated verification outcome. `reason` is a short, non-secret code for logging. */
export type VerifyResult =
  | { ok: true; job: DispatchJob }
  | { ok: false; reason: string };

/**
 * Validate an untrusted inbound job object into a typed DispatchJob, rejecting a job that
 * is missing a field, carries an extra field, or has a non-string value. Rejecting EXTRA
 * keys keeps the verified canonical bytes unambiguous (the signature only covers the five
 * canonical fields).
 */
function coerceJob(raw: unknown): DispatchJob | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length !== DISPATCH_JOB_KEYS.length) return null;
  for (const key of DISPATCH_JOB_KEYS) {
    if (typeof obj[key] !== "string") return null;
  }
  return {
    op: obj.op as DispatchOp,
    bucketName: obj.bucketName as string,
    accountId: obj.accountId as string,
    timestamp: obj.timestamp as string,
    nonce: obj.nonce as string,
  };
}

/**
 * Verify an inbound {job, signature} against the agency's public key. Fails CLOSED on:
 *   - a missing/malformed public key (can't verify => reject),
 *   - a malformed job (wrong/missing/extra fields, non-string values),
 *   - an `op` not on the allowlist,
 *   - a timestamp outside the ±FRESHNESS_WINDOW_SECONDS window (or unparseable),
 *   - a bad base64 signature,
 *   - a signature that doesn't verify over the canonical bytes.
 * Only { ok: true } means the caller may actuate.
 *
 * `nowMs` and `freshnessWindowSeconds` are injectable for testing; they default to real
 * time and the standing window.
 */
export async function verifyDispatch(input: {
  rawJob: unknown;
  signatureB64: unknown;
  publicKeyPem: string | undefined;
  nowMs?: number;
  freshnessWindowSeconds?: number;
}): Promise<VerifyResult> {
  const { rawJob, signatureB64, publicKeyPem } = input;
  const nowMs = input.nowMs ?? Date.now();
  const windowSeconds = input.freshnessWindowSeconds ?? FRESHNESS_WINDOW_SECONDS;

  if (!publicKeyPem) {
    return { ok: false, reason: "signing public key not configured" };
  }
  if (typeof signatureB64 !== "string" || !signatureB64) {
    return { ok: false, reason: "missing signature" };
  }

  const job = coerceJob(rawJob);
  if (!job) {
    return { ok: false, reason: "malformed job (expected exactly the five string fields)" };
  }
  if (!DISPATCH_OPS.includes(job.op)) {
    return { ok: false, reason: `op "${job.op}" is not allowlisted` };
  }

  const jobMs = Date.parse(job.timestamp);
  if (!Number.isFinite(jobMs)) {
    return { ok: false, reason: "unparseable timestamp" };
  }
  if (Math.abs(nowMs - jobMs) > windowSeconds * 1000) {
    return { ok: false, reason: "timestamp outside freshness window" };
  }

  const rawKey = ed25519RawPublicKeyFromSpkiPem(publicKeyPem);
  if (!rawKey) {
    return { ok: false, reason: "signing public key is not a valid ed25519 SPKI PEM" };
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = Uint8Array.from(atob(signatureB64), (char) => char.charCodeAt(0));
  } catch {
    return { ok: false, reason: "signature is not valid base64" };
  }

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("raw", rawKey, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return { ok: false, reason: "could not import signing public key" };
  }

  const canonical = canonicalizeDispatchJob(job);
  // Wrap the verify: a throw (e.g. a malformed key/signature the importKey didn't catch, or
  // a runtime crypto error) must surface as a fail-closed {ok:false, reason} — the module's
  // uniform contract — NOT propagate out as a 500. Either way, nothing is actuated.
  let verified: boolean;
  try {
    verified = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      signatureBytes,
      new TextEncoder().encode(canonical),
    );
  } catch {
    return { ok: false, reason: "signature verify error" };
  }
  if (!verified) {
    return { ok: false, reason: "signature does not verify" };
  }

  return { ok: true, job };
}

/** Read the configured signing public key from the Worker env. */
export function signingPublicKey(env: Env): string | undefined {
  return env.DY_SIGNING_PUBLIC_KEY;
}
