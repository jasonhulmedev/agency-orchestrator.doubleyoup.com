// Direction-B replay-protection tests that MUST run under the real workerd runtime (the
// "workers" project in vitest.config.ts). This is the correct home for:
//   • the NonceStore Durable Object (SQLite storage) — a DO cannot be exercised under Node;
//   • the /actuate single-use replay guard end-to-end (real DO in the request path), for
//     BOTH registered ops;
//   • ed25519 verification under workerd — a prior review flagged that the Worker's crypto
//     was only ever tested under Node, so here we verify a Node-produced signature under the
//     actual edge runtime.
//
// The actuators are mocked so nothing reaches Cloudflare and we can assert exactly how many
// times actuation ran. Everything else (verifyDispatch crypto, the DO, the op registry, the
// params parse/validate, the route wiring) is the real code path.

import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock BOTH actuators: the replay tests assert on how many times each runs, and we never want
// a test to hit the real Cloudflare API. Hoisted above the imports by Vitest, so the op
// registry (which imports "./actuate.js") also picks up these mocks.
vi.mock("../src/actuate.js", () => ({
  actuateProvisionR2: vi.fn(async (bucketName: string) => ({
    ok: true as const,
    op: "provision-r2" as const,
    bucket: bucketName,
    status: "created" as const,
    accountId: "acct-mock",
  })),
  actuateDnsRecordUpsert: vi.fn(async (params: { name: string }) => ({
    ok: true as const,
    op: "dns-record-upsert" as const,
    action: "created" as const,
    recordId: "rec-mock",
    name: params.name,
  })),
}));

import worker from "../src/index.js";
import { actuateProvisionR2, actuateDnsRecordUpsert } from "../src/actuate.js";
import type { Env } from "../src/env.js";
import type { NonceStore } from "../src/nonce-store.js";
import { nonceExpiresAtMs } from "../src/nonce-store.js";
import {
  canonicalizeDispatchJob,
  verifyDispatch,
  type DispatchJob,
} from "../src/dispatch-verify.js";

// The pool's `env` carries the real bindings from wrangler.toml (incl. NONCE_STORE); type it
// as our own Env so member access is checked.
const workerEnv = env as unknown as Env;

// ── Web-Crypto helpers (no Node APIs — this runs in workerd) ─────────────────────────
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function makeKeypair(): Promise<{ publicKeyPem: string; privateKey: CryptoKey }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const spki = new Uint8Array(
    (await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer,
  );
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${bytesToBase64(spki)}\n-----END PUBLIC KEY-----\n`;
  return { publicKeyPem, privateKey: kp.privateKey };
}

async function signAsApp(job: DispatchJob, privateKey: CryptoKey): Promise<string> {
  const canonical = canonicalizeDispatchJob(job);
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, privateKey, new TextEncoder().encode(canonical)),
  );
  return bytesToBase64(sig);
}

// The one singleton nonce store /actuate routes to, addressed exactly as the Worker does.
function nonceStub() {
  const ns = workerEnv.NONCE_STORE;
  return ns.get(ns.idFromName("dirb-nonce"));
}

// POST the identical signed envelope twice and return both responses — the replay shape
// shared by both ops' end-to-end tests.
async function postTwice(job: DispatchJob, signature: string, testEnv: Env): Promise<[Response, Response]> {
  const bodyText = JSON.stringify({ job, signature });
  const makeRequest = () =>
    new Request("https://worker.test/actuate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: bodyText,
    });
  const first = await worker.fetch(makeRequest(), testEnv);
  const second = await worker.fetch(makeRequest(), testEnv);
  return [first, second];
}

describe("NonceStore.consume — real Durable Object, SQLite-backed", () => {
  it("is fresh on first use, replay on the same nonce, fresh on a distinct nonce", async () => {
    const stub = nonceStub();
    const notAfter = nonceExpiresAtMs(Date.now());
    const nonceA = "unit-a-0000000000000000000000a1";
    const nonceB = "unit-b-0000000000000000000000b2";

    expect(await stub.consume(nonceA, notAfter)).toBe("fresh");
    expect(await stub.consume(nonceA, notAfter)).toBe("replay");
    expect(await stub.consume(nonceB, notAfter)).toBe("fresh");
  });

  it("prunes an expired nonce so it neither lingers nor blocks a later re-use", async () => {
    const stub = nonceStub();
    const expiredNonce = "unit-expired-000000000000000cc3";
    const liveNonce = "unit-live-0000000000000000000d4";

    // Record a nonce whose retention horizon is already in the past.
    expect(await stub.consume(expiredNonce, Date.now() - 60_000)).toBe("fresh");
    // Any later consume prunes expired rows first; this one prunes the expired nonce AND
    // records the live one.
    expect(await stub.consume(liveNonce, nonceExpiresAtMs(Date.now()))).toBe("fresh");

    // Reach into the DO's SQLite to confirm the expired row is physically gone, the live one
    // remains. Robust to any rows left by other tests — we assert on these two nonces only.
    const rows = (await runInDurableObject(stub, (_instance: NonceStore, state) =>
      state.storage.sql.exec("SELECT nonce FROM nonces").toArray(),
    )) as Array<{ nonce: string }>;
    const nonces = rows.map((row) => row.nonce);
    expect(nonces).not.toContain(expiredNonce);
    expect(nonces).toContain(liveNonce);

    // And re-using the (now pruned) expired nonce is treated as fresh, not replay.
    expect(await stub.consume(expiredNonce, nonceExpiresAtMs(Date.now()))).toBe("fresh");
  });
});

describe("POST /actuate — single-use replay protection end-to-end (real DO)", () => {
  const r2Spy = vi.mocked(actuateProvisionR2);
  const dnsSpy = vi.mocked(actuateDnsRecordUpsert);

  beforeEach(() => {
    r2Spy.mockClear();
    dnsSpy.mockClear();
  });

  it("provision-r2: actuates a valid job once (200), then rejects the identical replay (401) with no second actuation", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job: DispatchJob = {
      op: "provision-r2",
      params: JSON.stringify({ bucketName: "dy-agency-replay-e2e-01" }),
      accountId: "acct_replay_e2e",
      // Fresh "now" so the timestamp window passes without faking time.
      timestamp: new Date().toISOString(),
      nonce: `e2e-${crypto.randomUUID().replace(/-/g, "")}`,
    };
    const signature = await signAsApp(job, privateKey);
    const testEnv: Env = {
      ...workerEnv,
      DY_SIGNING_PUBLIC_KEY: publicKeyPem,
      R2_PROVISION_API_TOKEN: "cf-token-xyz",
    };

    const [first, second] = await postTwice(job, signature, testEnv);

    // First dispatch: verified, fresh nonce -> actuates once, 200.
    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as { ok: boolean; status?: string };
    expect(firstBody.ok).toBe(true);
    expect(r2Spy).toHaveBeenCalledTimes(1);
    expect(r2Spy).toHaveBeenCalledWith("dy-agency-replay-e2e-01", expect.anything());

    // Exact same {job, signature}: still verifies + still fresh by timestamp, but the nonce
    // is now spent -> rejected as a replay BEFORE any side effect.
    expect(second.status).toBe(401);
    const secondBody = (await second.json()) as { ok: boolean; reason?: string; error?: string };
    expect(secondBody.ok).toBe(false);
    expect(secondBody.reason).toBe("replay");

    // The actuator did NOT run a second time, and the other op's actuator never ran.
    expect(r2Spy).toHaveBeenCalledTimes(1);
    expect(dnsSpy).not.toHaveBeenCalled();
  });

  it("dns-record-upsert: actuates once (200) with the validated params, then rejects the replay (401)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const dnsParams = {
      zone: "jasonhulme.com",
      type: "TXT",
      name: "_dy-dirb-proof.jasonhulme.com",
      content: "dy-dirb-proof-replay-e2e",
      proxied: "false",
      ttl: "1",
    };
    const job: DispatchJob = {
      op: "dns-record-upsert",
      params: JSON.stringify(dnsParams),
      accountId: "acct_replay_e2e",
      timestamp: new Date().toISOString(),
      nonce: `e2e-dns-${crypto.randomUUID().replace(/-/g, "")}`,
    };
    const signature = await signAsApp(job, privateKey);
    const testEnv: Env = {
      ...workerEnv,
      DY_SIGNING_PUBLIC_KEY: publicKeyPem,
      CF_DNS_API_TOKEN: "cf-dns-token-abc",
    };

    const [first, second] = await postTwice(job, signature, testEnv);

    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as { ok: boolean; op?: string; action?: string };
    expect(firstBody).toMatchObject({ ok: true, op: "dns-record-upsert", action: "created" });
    // The registry handed the actuator the PARSED + VALIDATED params object (not the string).
    expect(dnsSpy).toHaveBeenCalledTimes(1);
    expect(dnsSpy).toHaveBeenCalledWith(dnsParams, expect.anything());

    expect(second.status).toBe(401);
    const secondBody = (await second.json()) as { ok: boolean; reason?: string };
    expect(secondBody).toEqual({ ok: false, error: "unverified dispatch", reason: "replay" });

    expect(dnsSpy).toHaveBeenCalledTimes(1);
    expect(r2Spy).not.toHaveBeenCalled();
  });
});

describe("ed25519 verification under the real workerd runtime", () => {
  // A signature produced OFFLINE by Node's crypto.sign (node:crypto) over the canonical
  // bytes, alongside the matching SPKI-PEM public key. Verifying it here proves an app-side
  // (Node) signature verifies under workerd — the cross-runtime guarantee a prior review
  // flagged (crypto was previously only tested under Node). Regenerated for the five-key
  // {accountId, nonce, op, params, timestamp} schema. To regenerate if the canonicalization
  // ever changes again, sign canonicalizeDispatchJob(NODE_JOB) with crypto.sign(null, ...)
  // using a fresh ed25519 keypair and paste the SPKI PEM + base64 sig.
  const NODE_JOB: DispatchJob = {
    op: "provision-r2",
    params: JSON.stringify({ bucketName: "dy-agency-nodefixture-abc123" }),
    accountId: "acct_node_fixture",
    timestamp: "2026-09-05T00:00:00.000Z",
    nonce: "aaaabbbbccccddddeeeeffff00001111",
  };
  const NODE_PUBLIC_KEY_PEM =
    "-----BEGIN PUBLIC KEY-----\n" +
    "MCowBQYDK2VwAyEA/XacejTltnvq6mJZ2VRTtNktni9ywCgBthR+vh9WVXI=\n" +
    "-----END PUBLIC KEY-----\n";
  const NODE_SIGNATURE_B64 =
    "52I4aFlH/LXljbFDy/CjwD3RGqQL8OZfYvsks7jD6jhHbKMU9Ii5+3MmnRR6REBAX1Towx7/72DAaSuZ4rlxAQ==";
  const NODE_JOB_MS = Date.parse(NODE_JOB.timestamp);

  it("verifies a Node-produced ed25519 signature (cross-runtime app -> Worker)", async () => {
    const verdict = await verifyDispatch({
      rawJob: NODE_JOB,
      signatureB64: NODE_SIGNATURE_B64,
      publicKeyPem: NODE_PUBLIC_KEY_PEM,
      nowMs: NODE_JOB_MS,
    });
    expect(verdict.ok).toBe(true);
  });

  it("round-trips a Web-Crypto sign -> verify entirely under workerd", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job: DispatchJob = { ...NODE_JOB, nonce: "workerd-roundtrip-1111222233334444" };
    const signature = await signAsApp(job, privateKey);

    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem,
      nowMs: Date.parse(job.timestamp),
    });
    expect(verdict.ok).toBe(true);
  });
});
