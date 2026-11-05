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
  actuateDnsRecordGet: vi.fn(async () => ({
    ok: true as const,
    op: "dns-record-get" as const,
    zoneFound: true,
    records: [],
  })),
}));

import worker from "../src/index.js";
import { actuateProvisionR2, actuateDnsRecordUpsert, actuateDnsRecordGet } from "../src/actuate.js";
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

describe("NonceStore leases (waf-edge-sync, one instance per zone) — real Durable Object", () => {
  function leaseStub(zone: string) {
    const ns = workerEnv.NONCE_STORE;
    return ns.get(ns.idFromName(`edge-sync-lease:${zone}`));
  }

  it("grants one holder at a time; only the holder releases; then the next holder gets it", async () => {
    const stub = leaseStub("lease-a.example.com");
    expect(await stub.acquireLease("lease-a.example.com", "run-1", 300_000)).toBe("acquired");
    expect(await stub.acquireLease("lease-a.example.com", "run-2", 300_000)).toBe("busy");
    // The same holder asking again is busy too: a lease is not re-entrant.
    expect(await stub.acquireLease("lease-a.example.com", "run-1", 300_000)).toBe("busy");
    // A non-holder's release changes nothing.
    await stub.releaseLease("lease-a.example.com", "run-2");
    expect(await stub.acquireLease("lease-a.example.com", "run-3", 300_000)).toBe("busy");
    await stub.releaseLease("lease-a.example.com", "run-1");
    expect(await stub.acquireLease("lease-a.example.com", "run-2", 300_000)).toBe("acquired");
    await stub.releaseLease("lease-a.example.com", "run-2");
  });

  it("frees an expired lease (a run that died without releasing), and zones do not share a lease", async () => {
    const stub = leaseStub("lease-b.example.com");
    expect(await stub.acquireLease("lease-b.example.com", "dead-run", 300_000)).toBe("acquired");
    expect(await leaseStub("lease-c.example.com").acquireLease("lease-c.example.com", "other-zone-run", 300_000)).toBe("acquired");
    // Age the lease past its expiry, as if the dead run's 5 minutes had passed.
    await runInDurableObject(stub, (_instance: NonceStore, state) => {
      state.storage.sql.exec("UPDATE leases SET expires_at = ? WHERE lease_key = ?", Date.now() - 1, "lease-b.example.com");
    });
    expect(await stub.acquireLease("lease-b.example.com", "next-run", 300_000)).toBe("acquired");
    // The dead run's late release cannot free the next run's lease.
    await stub.releaseLease("lease-b.example.com", "dead-run");
    expect(await stub.acquireLease("lease-b.example.com", "third-run", 300_000)).toBe("busy");
  });
});

describe("NonceStore media key leases with a pending-delete record (hub#222) — real Durable Object", () => {
  function mediaLeaseStub(bucket: string) {
    const ns = workerEnv.NONCE_STORE;
    return ns.get(ns.idFromName(`media-lease:${bucket}`));
  }

  it("a recorded DELETE outlives its lease until a holder clears it; only the lease holder can record", async () => {
    const stub = mediaLeaseStub("doubleyoup-media-lease-a");
    const key = "lease-a/a.png";
    expect(await stub.acquireMediaKey(key, "req-1", 60_000, 3_600_000)).toEqual({ outcome: "acquired", pendingDelete: null, expiredPendingDeletes: [] });
    expect(await stub.acquireMediaKey(key, "req-2", 60_000, 3_600_000)).toEqual({ outcome: "busy" });
    expect(await stub.beginMediaDelete(key, "req-2", "rev-1", 15_000)).toBe("lease-lost");
    expect(await stub.beginMediaDelete(key, "req-1", "rev-1", 15_000)).toBe("recorded");
    // The DELETE's outcome is unknown: req-1 ends without clearing its record.
    await stub.finishMediaKey(key, "req-1", null);
    const next = await stub.acquireMediaKey(key, "req-3", 60_000, 3_600_000);
    expect(next.outcome).toBe("acquired");
    if (next.outcome === "acquired") {
      expect(next.pendingDelete).toMatchObject({ holder: "req-1", revision: "rev-1" });
    }
    // req-3 proved the DELETE landed and clears req-1's record.
    await stub.finishMediaKey(key, "req-3", "req-1");
    expect(await stub.acquireMediaKey(key, "req-4", 60_000, 3_600_000)).toEqual({ outcome: "acquired", pendingDelete: null, expiredPendingDeletes: [] });
    await stub.finishMediaKey(key, "req-4", null);
  });

  it("refuses to record when too little lease is left, and drops a record older than the quarantine", async () => {
    const stub = mediaLeaseStub("doubleyoup-media-lease-b");
    const key = "lease-b/a.png";
    expect((await stub.acquireMediaKey(key, "req-1", 60_000, 3_600_000)).outcome).toBe("acquired");
    expect(await stub.beginMediaDelete(key, "req-1", "rev-1", 61_000)).toBe("lease-lost");
    expect(await stub.beginMediaDelete(key, "req-1", "rev-1", 15_000)).toBe("recorded");
    await stub.finishMediaKey(key, "req-1", null);
    const agedStartedAtMs = Date.now() - 3_600_001;
    await runInDurableObject(stub, (_instance: NonceStore, state) => {
      state.storage.sql.exec("UPDATE media_pending_deletes SET started_at = ? WHERE object_key = ?", agedStartedAtMs, key);
    });
    // The acquire that drops the aged record returns it, so the Worker can log the reopen of the key.
    expect(await stub.acquireMediaKey(key, "req-2", 60_000, 3_600_000)).toEqual({
      outcome: "acquired",
      pendingDelete: null,
      expiredPendingDeletes: [{ objectKey: key, holder: "req-1", revision: "rev-1", startedAtMs: agedStartedAtMs }],
    });
    await stub.finishMediaKey(key, "req-2", null);
    expect(await stub.acquireMediaKey(key, "req-3", 60_000, 3_600_000)).toEqual({
      outcome: "acquired",
      pendingDelete: null,
      expiredPendingDeletes: [],
    });
    await stub.finishMediaKey(key, "req-3", null);
  });

  it("an acquire of one key sweeps and returns the aged records of every other key of the bucket", async () => {
    const stub = mediaLeaseStub("doubleyoup-media-lease-c");
    const recordUnknownDelete = async (key: string, holder: string, revision: string) => {
      expect((await stub.acquireMediaKey(key, holder, 60_000, 3_600_000)).outcome).toBe("acquired");
      expect(await stub.beginMediaDelete(key, holder, revision, 15_000)).toBe("recorded");
      await stub.finishMediaKey(key, holder, null);
    };
    await recordUnknownDelete("lease-b/c.png", "req-c", "rev-c");
    await recordUnknownDelete("lease-b/a.png", "req-a", "rev-a");
    const agedStartedAtMs = Date.now() - 3_600_001;
    await runInDurableObject(stub, (_instance: NonceStore, state) => {
      state.storage.sql.exec("UPDATE media_pending_deletes SET started_at = ?", agedStartedAtMs);
    });
    // b.png has no record of its own, but its acquire runs the bucket-wide sweep, so it must return both drops.
    expect(await stub.acquireMediaKey("lease-b/b.png", "req-b", 60_000, 3_600_000)).toEqual({
      outcome: "acquired",
      pendingDelete: null,
      expiredPendingDeletes: [
        { objectKey: "lease-b/a.png", holder: "req-a", revision: "rev-a", startedAtMs: agedStartedAtMs },
        { objectKey: "lease-b/c.png", holder: "req-c", revision: "rev-c", startedAtMs: agedStartedAtMs },
      ],
    });
    await stub.finishMediaKey("lease-b/b.png", "req-b", null);
    expect(await stub.acquireMediaKey("lease-b/a.png", "req-a2", 60_000, 3_600_000)).toEqual({
      outcome: "acquired",
      pendingDelete: null,
      expiredPendingDeletes: [],
    });
    await stub.finishMediaKey("lease-b/a.png", "req-a2", null);
  });
});

describe("NonceStore.countRequest (hub#222 per-site media rate limit) — real Durable Object", () => {
  function rateStub(bucket: string) {
    const ns = workerEnv.NONCE_STORE;
    return ns.get(ns.idFromName(`media-rate:${bucket}`));
  }

  it("allows `limit` requests in a window, refuses the next with a retry time, and starts over in a new window", async () => {
    const stub = rateStub("doubleyoup-media-rate-a");
    for (let index = 0; index < 3; index += 1) {
      expect(await stub.countRequest("doubleyoup-media-rate-a", 60_000, 3)).toEqual({ allowed: true });
    }
    const refused = await stub.countRequest("doubleyoup-media-rate-a", 60_000, 3);
    expect(refused.allowed).toBe(false);
    if (!refused.allowed) {
      expect(refused.retryAfterMs).toBeGreaterThan(0);
      expect(refused.retryAfterMs).toBeLessThanOrEqual(60_000);
    }
    // Another bucket has its own instance and its own counter.
    expect(await rateStub("doubleyoup-media-rate-b").countRequest("doubleyoup-media-rate-b", 60_000, 3)).toEqual({ allowed: true });
    // Move the window back, as if a minute had passed.
    await runInDurableObject(stub, (_instance: NonceStore, state) => {
      state.storage.sql.exec("UPDATE rate_windows SET window_start = window_start - 60000 WHERE rate_key = ?", "doubleyoup-media-rate-a");
    });
    expect(await stub.countRequest("doubleyoup-media-rate-a", 60_000, 3)).toEqual({ allowed: true });
  });
});

describe("POST /actuate — single-use replay protection end-to-end (real DO)", () => {
  const r2Spy = vi.mocked(actuateProvisionR2);
  const dnsSpy = vi.mocked(actuateDnsRecordUpsert);
  const dnsGetSpy = vi.mocked(actuateDnsRecordGet);

  beforeEach(() => {
    r2Spy.mockClear();
    dnsSpy.mockClear();
    dnsGetSpy.mockClear();
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

  it("dns-record-get: a read op is single-use too — actuates once (200), then rejects the replay (401)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const getParams = { zone: "example.com", name: "www.example.com", type: "CNAME" };
    const job: DispatchJob = {
      op: "dns-record-get",
      params: JSON.stringify(getParams),
      accountId: "acct_replay_e2e",
      timestamp: new Date().toISOString(),
      nonce: `e2e-dnsget-${crypto.randomUUID().replace(/-/g, "")}`,
    };
    const signature = await signAsApp(job, privateKey);
    const testEnv: Env = {
      ...workerEnv,
      DY_SIGNING_PUBLIC_KEY: publicKeyPem,
      CF_DNS_API_TOKEN: "cf-dns-token-abc",
    };

    const [first, second] = await postTwice(job, signature, testEnv);

    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ ok: true, op: "dns-record-get", zoneFound: true, records: [] });
    expect(dnsGetSpy).toHaveBeenCalledTimes(1);
    expect(dnsGetSpy).toHaveBeenCalledWith(getParams, expect.anything());

    expect(second.status).toBe(401);
    expect(await second.json()).toEqual({ ok: false, error: "unverified dispatch", reason: "replay" });
    expect(dnsGetSpy).toHaveBeenCalledTimes(1);
    expect(dnsSpy).not.toHaveBeenCalled();
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
