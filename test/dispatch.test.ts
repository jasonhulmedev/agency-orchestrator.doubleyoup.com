// Direction-B signed-dispatch tests (agency Worker side).
//
// The security-critical assertion is the CROSS-SIDE round trip: a job signed with the
// SAME ed25519 scheme + public-key encoding our control-plane app uses (ed25519 over the
// canonical UTF-8 bytes; the public key exported as SPKI PEM, exactly what onboarding
// stores on Account.signingKeyPublic) MUST verify with the Worker's verifyDispatch — and
// every negative case (tampered job, wrong key, stale timestamp, disallowed op) MUST fail
// closed. Plus the /actuate route itself: an unverified request must actuate NOTHING (no
// fetch to Cloudflare).
//
// This test stays Worker-native (Web Crypto only, no node:crypto/Buffer) so the Worker
// repo keeps its "fetch + Web Crypto only, no nodejs_compat" guarantee. Web Crypto's
// ed25519 sign produces the identical signature scheme as the app's Node crypto.sign
// over the identical canonical bytes, so this is a faithful app->Worker round trip.

import { describe, it, expect, vi, afterEach, beforeAll } from "vitest";
import worker from "../src/index.js";
import type { Env } from "../src/env.js";
import {
  type DispatchJob,
  canonicalizeDispatchJob,
  verifyDispatch,
} from "../src/dispatch-verify.js";

// ── Web-Crypto helpers (no Node APIs) ───────────────────────────────────────────────
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

interface TestKeypair {
  publicKeyPem: string;
  privateKey: CryptoKey;
}

async function makeKeypair(): Promise<TestKeypair> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  // SPKI PEM — exactly the encoding onboarding stores (line-wrapping is irrelevant; the
  // Worker strips all whitespace before decoding).
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${bytesToBase64(spki)}\n-----END PUBLIC KEY-----\n`;
  return { publicKeyPem, privateKey: kp.privateKey };
}

// Sign EXACTLY as app/src/server/services/agency-dispatch-signing.ts::signDispatchJob does:
// ed25519 over the canonical UTF-8 bytes, base64. Signing over the Worker's
// canonicalizeDispatchJob is legitimate because the test also asserts that output equals
// the pinned EXPECTED_CANONICAL that the app side is independently pinned to.
async function signAsApp(job: DispatchJob, privateKey: CryptoKey): Promise<string> {
  const canonical = canonicalizeDispatchJob(job);
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, privateKey, new TextEncoder().encode(canonical)),
  );
  return bytesToBase64(sig);
}

// A fixed job so the canonical-bytes assertion below is stable. FREEZE_MS is this job's
// own timestamp, used as `nowMs` so the freshness window passes deterministically.
const FREEZE_MS = Date.parse("2026-09-05T00:00:00.000Z");
function sampleJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return {
    op: "provision-r2",
    bucketName: "dy-agency-proof-abc123",
    accountId: "acct_test_1",
    timestamp: "2026-09-05T00:00:00.000Z",
    nonce: "0123456789abcdef0123456789abcdef",
    ...overrides,
  };
}

// The ONE canonical byte-string both sides must agree on. This exact literal is also
// pinned in the app's agency-dispatch-signing.test.ts — if either canonicalizer drifts,
// one of the two tests breaks.
const EXPECTED_CANONICAL =
  `{"accountId":"acct_test_1",` +
  `"bucketName":"dy-agency-proof-abc123",` +
  `"nonce":"0123456789abcdef0123456789abcdef",` +
  `"op":"provision-r2",` +
  `"timestamp":"2026-09-05T00:00:00.000Z"}`;

afterEach(() => {
  vi.restoreAllMocks();
});

describe("canonicalization agrees with the app (byte-for-byte)", () => {
  it("produces the pinned canonical string", () => {
    expect(canonicalizeDispatchJob(sampleJob())).toBe(EXPECTED_CANONICAL);
  });
});

describe("verifyDispatch — cross-side round trip + negatives", () => {
  it("verifies a job signed the app way with the matching public key", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.job.bucketName).toBe("dy-agency-proof-abc123");
  });

  it("rejects a tampered job (bucket swapped after signing)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const tampered = { ...job, bucketName: "attacker-bucket" };
    const verdict = await verifyDispatch({
      rawJob: tampered,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/does not verify/);
  });

  it("rejects a signature made with a different key", async () => {
    const signer = await makeKeypair();
    const other = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, signer.privateKey);

    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem: other.publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/does not verify/);
  });

  it("rejects a stale timestamp (outside the freshness window)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    // "now" is 10 minutes after the job's timestamp — well outside ±120s.
    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS + 10 * 60 * 1000,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/freshness window/);
  });

  it("rejects a non-allowlisted op even when correctly signed", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    // A validly-signed job whose op is not allowlisted must still be refused.
    const job = { ...sampleJob(), op: "delete-everything" } as unknown as DispatchJob;
    const signature = await signAsApp(job, privateKey);

    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/not allowlisted/);
  });

  it("rejects a job with an extra field (exact-key allowlist)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const withExtra = { ...job, extra: "x" };
    const verdict = await verifyDispatch({
      rawJob: withExtra,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/malformed job/);
  });

  it("fails closed when no public key is configured", async () => {
    const { privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem: undefined,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/not configured/);
  });
});

describe("POST /actuate route", () => {
  let publicKeyPem: string;
  let privateKey: CryptoKey;
  beforeAll(async () => {
    ({ publicKeyPem, privateKey } = await makeKeypair());
  });

  function envWith(overrides: Partial<Env> = {}): Env {
    return {
      APP_BASE_URL: "https://app.example.test",
      DY_CLIENT_ID: "client-abc",
      DY_CLIENT_SECRET: "secret-xyz",
      DY_SIGNING_PUBLIC_KEY: publicKeyPem,
      R2_PROVISION_API_TOKEN: "cf-token-xyz",
      ...overrides,
    };
  }

  function actuateRequest(body: unknown): Request {
    return new Request("http://localhost/actuate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  it("returns 401 and calls NO Cloudflare API for an unverified (unsigned) request", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const response = await worker.fetch(
      actuateRequest({ job: sampleJob(), signature: "not-a-real-signature" }),
      envWith(),
    );
    expect(response.status).toBe(401);
    const body = (await response.json()) as { ok: boolean; reason?: string };
    expect(body.ok).toBe(false);
    // Nothing was actuated: the CF API was never touched.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("actuates a verified provision-r2 job via the agency's own R2 token (created)", async () => {
    // Freeze time so the fixed-timestamp job is fresh at fetch time.
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url ?? String(input);
      calls.push(url);
      // 1) account resolution
      if (url.includes("/accounts?per_page=1")) {
        return new Response(JSON.stringify({ success: true, result: [{ id: "acct-cf-1", name: "Agency" }] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      // 2) bucket create — assert it used the agency token, not any platform credential
      if (/\/accounts\/acct-cf-1\/r2\/buckets$/.test(url)) {
        const auth = new Headers(init?.headers).get("authorization");
        expect(auth).toBe("Bearer cf-token-xyz");
        return new Response(JSON.stringify({ success: true, result: { name: job.bucketName } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch to ${url}`);
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      op: string;
      bucket: string;
      status: string;
      accountId: string;
    };
    expect(body).toMatchObject({
      ok: true,
      op: "provision-r2",
      bucket: "dy-agency-proof-abc123",
      status: "created",
      accountId: "acct-cf-1",
    });
    expect(calls.some((u) => u.includes("/r2/buckets"))).toBe(true);
    vi.useRealTimers();
  });

  it("treats an existing bucket (409) as idempotent success", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url ?? String(input);
      if (url.includes("/accounts?per_page=1")) {
        return new Response(JSON.stringify({ success: true, result: [{ id: "acct-cf-1" }] }), { status: 200 });
      }
      return new Response(JSON.stringify({ success: false, errors: [{ code: 10004, message: "The bucket already exists." }] }), {
        status: 409,
      });
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; status: string };
    expect(body.ok).toBe(true);
    expect(body.status).toBe("already-existed");
    vi.useRealTimers();
  });

  it("reports a clean failure (no platform fallback) when the agency R2 token is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ R2_PROVISION_API_TOKEN: undefined }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail?: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/R2_PROVISION_API_TOKEN is not configured/);
    // It did not try to reach Cloudflare with some other credential.
    expect(fetchSpy).not.toHaveBeenCalled();
    vi.useRealTimers();
  });
});
