// planning/49 Phase 3 (I4), decision A: the SessionGateMinter (src/session-gate/minter.ts and the named
// entrypoint in src/index.ts). It mints Google ID tokens from the agency's own key ONLY for this project's
// session service URLs, and says nothing but a reason code when it does not.
//
// planning/49 Phase 4 (I3), decision D1 A: the CALLER. A v2 gate proves itself with a caller key
// (src/session-gate/caller-key.ts); a v1 gate's bare audience string is served for term- and sterm- only.
// The proofs here are built by this file's own code from the recipe, not with the code under test, and the
// recipe itself is pinned to vectors computed by a separate HKDF/HMAC implementation (Python).

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env.js";
import { mintSessionGateIdToken, parseSessionGateAudience, readProjectNumber } from "../src/session-gate/minter.js";
import {
  CLIENT_SECRET_MIN_LENGTH,
  deriveMinterCallerKey,
  minterCallerKeyFingerprint,
  minterCallerKeyHex,
  minterCallerProofMac,
  verifyMinterCallerProof,
} from "../src/session-gate/caller-key.js";
import { edgeGateScriptNameFor } from "../src/dispatch-params.js";
import { SessionGateMinter } from "../src/index.js";
import gateV2 from "../src/session-gate/gate.js";
import gateV1 from "./fixtures/session-gate-v1.js";
// The released v1 bytes, to prove the fixture IS v1 (the pin lives in test/session-gate.test.ts).
import GATE_V1_SOURCE from "./fixtures/session-gate-v1.js?raw";

const PROJECT_NUMBER = "123456789012";
const REGION = "australia-southeast2";
// A test client secret of the length app issues (43 base64url characters).
const CLIENT_SECRET = "unit-test-client-secret-not-a-real-one-0001";
const OTHER_CLIENT_SECRET = "unit-test-client-secret-not-a-real-one-0002";
const GATE_V1_SHA256 = "cd5b6e3a661747e5fb4b40713a1fa4b2206cbb6b40ccf35016b54cb04623b5f7";

// Vectors from an independent HKDF (RFC 5869) and HMAC implementation (Python's hmac + hashlib), for
// CLIENT_SECRET and the gate script dy-gate-dy-agency-proof-australia-southeast2.
const VECTOR_GATE_SCRIPT = "dy-gate-dy-agency-proof-australia-southeast2";
const VECTOR_CALLER_KEY_HEX = "7b1eab777358b371e6e62d42117d5919b44e8e442605f2e9690861b9574abc77";
const VECTOR_FINGERPRINT = "725390655535460c";
const VECTOR_AUDIENCE = "https://pma-docs-892769-123456789012.australia-southeast2.run.app";
const VECTOR_TS = 1793404800;
const VECTOR_MAC = "5IiC-CfevaYzhhg0WJdpVDZi2UQ8F4pREFuY5cjS3eE";
// The same secret's key for the gate of ANOTHER region (australia-southeast1).
const VECTOR_OTHER_REGION_KEY_HEX = "8601531bf8b79f0f74b0efda9fb6f4434a6dba94b0e813efb89c7d342c1bec24";

let privateKeyPem: string;

beforeAll(async () => {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = Buffer.from((await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)) as ArrayBuffer).toString("base64");
  privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

/** An Env whose service-account key belongs to `projectId`. Each test uses its own project, because the
 *  minter caches project numbers per isolate. */
function envForProject(projectId: string, overrides: Partial<Env> = {}): Env {
  return {
    APP_BASE_URL: "https://app.example.test",
    DY_CLIENT_ID: "client-abc",
    DY_CLIENT_SECRET: CLIENT_SECRET,
    NONCE_STORE: undefined as unknown as Env["NONCE_STORE"],
    GCP_SERVICE_ACCOUNT_KEY: JSON.stringify({
      type: "service_account",
      project_id: projectId,
      private_key: privateKeyPem,
      client_email: `sa@${projectId}.iam.gserviceaccount.com`,
      token_uri: "https://oauth2.googleapis.com/token",
    }),
    ...overrides,
  };
}

function fakeIdToken(audience: string, exp: number): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ aud: audience, exp })}.signature`;
}

function claimsOfAssertion(assertion: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(assertion.split(".")[1] as string, "base64url").toString("utf8")) as Record<string, unknown>;
}

interface GoogleMockOptions {
  projectId: string;
  projectNumber?: string;
  projectsGetStatus?: number;
  idTokenExp?: number;
  idTokenStatus?: number;
  /** Answer a run.app origin fetch (the gate interop tests) with this. Absent: such a fetch throws. */
  originReply?: () => Response;
}

/** Mock Google: the token endpoint (access or ID token by the assertion) and projects.get. */
function mockGoogle(options: GoogleMockOptions) {
  const calls: Array<{ url: string; method: string; scope?: unknown; targetAudience?: unknown; request?: Request }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      const method = init?.method ?? "GET";
      if (url === "https://oauth2.googleapis.com/token") {
        const assertion = new URLSearchParams(String(init?.body)).get("assertion") as string;
        const claims = claimsOfAssertion(assertion);
        calls.push({ url, method, scope: claims.scope, targetAudience: claims.target_audience });
        if (typeof claims.target_audience === "string") {
          if (options.idTokenStatus !== undefined) {
            return new Response("upstream says no: internal detail", { status: options.idTokenStatus });
          }
          const exp = options.idTokenExp ?? Math.floor(Date.now() / 1000) + 3600;
          return Response.json({ id_token: fakeIdToken(claims.target_audience, exp) });
        }
        return Response.json({ access_token: "read-only-access-token", expires_in: 3600 });
      }
      if (input instanceof Request) {
        calls.push({ url, method: input.method, request: input });
      } else {
        calls.push({ url, method });
      }
      if (url === `https://cloudresourcemanager.googleapis.com/v1/projects/${options.projectId}`) {
        if (options.projectsGetStatus !== undefined && options.projectsGetStatus !== 200) {
          return Response.json({ error: { message: "permission denied on resource" } }, { status: options.projectsGetStatus });
        }
        return Response.json({ projectId: options.projectId, projectNumber: options.projectNumber ?? PROJECT_NUMBER });
      }
      if (options.originReply !== undefined && new URL(url).hostname.endsWith(".run.app")) {
        return options.originReply();
      }
      throw new Error(`unexpected fetch ${url}`);
    }),
  );
  return calls;
}

/** HKDF-SHA256 with an empty salt: 32 bytes. */
async function hkdf32(ikmText: string, info: string): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey("raw", new TextEncoder().encode(ikmText), "HKDF", false, ["deriveBits"]);
  const parameters = { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode(info) };
  return new Uint8Array(await crypto.subtle.deriveBits(parameters, ikm, 256));
}

/** HMAC-SHA256(key, message), base64url with no padding (or hex). */
async function hmac(key: Uint8Array, message: string, encoding: "base64url" | "hex" = "base64url"): Promise<string> {
  const hmacKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(message));
  return Buffer.from(mac).toString(encoding);
}

/** The caller key, written out here from the recipe (not the code under test). */
async function independentCallerKey(clientSecret: string, gateScript: string): Promise<Uint8Array> {
  return hkdf32(clientSecret, `dy-session-minter-caller/v1:${gateScript}`);
}

/** A v2 mint request for `audience`, written out here from the recipe. */
async function proofRequest(key: Uint8Array, audience: string, ts: number): Promise<{ audience: string; ts: number; mac: string }> {
  return { audience, ts, mac: await hmac(key, `v1|${audience}|${ts}`) };
}

/** A v2 mint request made with the key of `projectId`'s gate in REGION, at the current time. */
async function validProofRequest(projectId: string, audience: string): Promise<{ audience: string; ts: number; mac: string }> {
  const key = await independentCallerKey(CLIENT_SECRET, edgeGateScriptNameFor(projectId, REGION));
  return proofRequest(key, audience, Math.floor(Date.now() / 1000));
}

function audienceFor(serviceName: string, region = REGION): string {
  return `https://${serviceName}-${PROJECT_NUMBER}.${region}.run.app`;
}

describe("parseSessionGateAudience: exactly this shape, no network", () => {
  it("accepts a session service's deterministic URL for every session prefix", () => {
    expect(parseSessionGateAudience(`https://term-docs-892769-${PROJECT_NUMBER}.${REGION}.run.app`)).toEqual({
      serviceName: "term-docs-892769",
      projectNumber: PROJECT_NUMBER,
      region: REGION,
    });
    for (const serviceName of ["pma-x", "staging-x", "sterm-x", "spma-x"]) {
      expect(parseSessionGateAudience(`https://${serviceName}-${PROJECT_NUMBER}.${REGION}.run.app`)).toMatchObject({ serviceName });
    }
  });

  it("refuses every other string", () => {
    const base = `term-x-${PROJECT_NUMBER}.${REGION}.run.app`;
    const refused: unknown[] = [
      undefined,
      null,
      42,
      { toString: () => `https://${base}` },
      `http://${base}`,
      `https://${base}/`,
      `https://${base}/path`,
      `https://${base}?q=1`,
      `https://${base}#f`,
      `https://${base}:443`,
      `https://user@${base}`,
      `https://${base.toUpperCase()}`,
      `https://a.${base}`,
      `https://${base}.evil.example`,
      `https://term-x-${PROJECT_NUMBER}.${REGION}.run.app.evil.example`,
      `https://term-x.${REGION}.run.app`,
      `https://term-x-0${PROJECT_NUMBER}.${REGION}.run.app`,
      `https://ssh-x-${PROJECT_NUMBER}.${REGION}.run.app`,
      `https://dy-run-probe-${PROJECT_NUMBER}.${REGION}.run.app`,
      `https://term--${PROJECT_NUMBER}.${REGION}.run.app`,
      `https://term-x-${PROJECT_NUMBER}.australia.run.app`,
      `https://term-x-${PROJECT_NUMBER}.${REGION}.a.run.app`,
      `https://${PROJECT_NUMBER}.${REGION}.run.app`,
      ` https://${base}`,
      `https://${base}\n`,
    ];
    for (const audience of refused) {
      expect(parseSessionGateAudience(audience), String(audience)).toBeNull();
    }
  });

  it("refuses a label longer than 63 characters: Cloud Run gives that service no deterministic URL", () => {
    // A 49-character service name + "-" + a 12-digit number = 62; a 20-digit number pushes it past 63.
    const longestServiceName = `term-${"a".repeat(44)}`;
    expect(parseSessionGateAudience(`https://${longestServiceName}-${PROJECT_NUMBER}.${REGION}.run.app`)).not.toBeNull();
    expect(parseSessionGateAudience(`https://${longestServiceName}-12345678901234567890.${REGION}.run.app`)).toBeNull();
  });
});

describe("mintSessionGateIdToken", () => {
  it("mints an ID token for this project's session URL, with the exp read from the token", async () => {
    const env = envForProject("dy-minter-ok");
    const audience = `https://term-docs-892769-${PROJECT_NUMBER}.${REGION}.run.app`;
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const calls = mockGoogle({ projectId: "dy-minter-ok", idTokenExp: exp });

    const result = await mintSessionGateIdToken(env, audience);

    expect(result).toEqual({ ok: true, idToken: fakeIdToken(audience, exp), expiresAt: exp });
    // projects.get with a READ-ONLY token, then the ID token for exactly that audience.
    expect(calls.map((call) => call.url)).toEqual([
      "https://oauth2.googleapis.com/token",
      "https://cloudresourcemanager.googleapis.com/v1/projects/dy-minter-ok",
      "https://oauth2.googleapis.com/token",
    ]);
    expect(calls[0]?.scope).toBe("https://www.googleapis.com/auth/cloud-platform.read-only");
    expect(calls[2]?.targetAudience).toBe(audience);
  });

  it("reads the project number once per isolate", async () => {
    const env = envForProject("dy-minter-cache");
    const calls = mockGoogle({ projectId: "dy-minter-cache" });
    await mintSessionGateIdToken(env, `https://term-a-${PROJECT_NUMBER}.${REGION}.run.app`);
    // A pma- audience in another region, with a proof from that region's gate key.
    const otherRegionAudience = `https://pma-b-${PROJECT_NUMBER}.australia-southeast1.run.app`;
    const otherRegionKey = await independentCallerKey(CLIENT_SECRET, edgeGateScriptNameFor("dy-minter-cache", "australia-southeast1"));
    const minted = await mintSessionGateIdToken(env, await proofRequest(otherRegionKey, otherRegionAudience, Math.floor(Date.now() / 1000)));
    expect(minted.ok).toBe(true);
    const projectReads = calls.filter((call) => call.url.startsWith("https://cloudresourcemanager.googleapis.com/"));
    expect(projectReads).toHaveLength(1);
  });

  it("refuses a malformed audience before any network call", async () => {
    const env = envForProject("dy-minter-shape");
    const calls = mockGoogle({ projectId: "dy-minter-shape" });
    for (const audience of ["https://evil.example", `https://term-x-${PROJECT_NUMBER}.${REGION}.run.app/`, 7]) {
      expect(await mintSessionGateIdToken(env, audience)).toEqual({ ok: false, reason: "audience-refused" });
    }
    // The v2 form with a malformed audience is an audience refusal too, whatever its proof.
    const key = await independentCallerKey(CLIENT_SECRET, edgeGateScriptNameFor("dy-minter-shape", REGION));
    const badAudienceProof = await proofRequest(key, "https://evil.example", Math.floor(Date.now() / 1000));
    expect(await mintSessionGateIdToken(env, badAudienceProof)).toEqual({ ok: false, reason: "audience-refused" });
    for (const request of [null, undefined, [audienceFor("term-x")], { audience: 7 }]) {
      expect(await mintSessionGateIdToken(env, request), JSON.stringify(request)).toEqual({ ok: false, reason: "audience-refused" });
    }
    expect(calls).toHaveLength(0);
  });

  it("refuses ANOTHER project's session URL, and mints no ID token", async () => {
    const env = envForProject("dy-minter-other");
    const calls = mockGoogle({ projectId: "dy-minter-other", projectNumber: PROJECT_NUMBER });
    const result = await mintSessionGateIdToken(env, `https://term-x-999999999999.${REGION}.run.app`);
    expect(result).toEqual({ ok: false, reason: "audience-refused" });
    expect(calls.filter((call) => call.targetAudience !== undefined)).toHaveLength(0);
  });

  it("is unavailable, with no detail, when the key is missing or Google fails", async () => {
    const audience = `https://term-x-${PROJECT_NUMBER}.${REGION}.run.app`;
    mockGoogle({ projectId: "unused" });
    const noKey = { ...envForProject("dy-minter-nokey"), GCP_SERVICE_ACCOUNT_KEY: undefined };
    expect(await mintSessionGateIdToken(noKey, audience)).toEqual({ ok: false, reason: "unavailable" });
    const garbledKey = { ...envForProject("dy-minter-garbled"), GCP_SERVICE_ACCOUNT_KEY: "{not json" };
    expect(await mintSessionGateIdToken(garbledKey, audience)).toEqual({ ok: false, reason: "unavailable" });
    vi.unstubAllGlobals();

    mockGoogle({ projectId: "dy-minter-denied", projectsGetStatus: 403 });
    expect(await mintSessionGateIdToken(envForProject("dy-minter-denied"), audience)).toEqual({ ok: false, reason: "unavailable" });
    vi.unstubAllGlobals();

    mockGoogle({ projectId: "dy-minter-idfail", idTokenStatus: 400 });
    const idFail = await mintSessionGateIdToken(envForProject("dy-minter-idfail"), audience);
    expect(idFail).toEqual({ ok: false, reason: "unavailable" });
    expect(JSON.stringify(idFail)).not.toContain("internal detail");
    vi.unstubAllGlobals();

    // An ID token whose exp is already past is never handed to the gate.
    mockGoogle({ projectId: "dy-minter-expired", idTokenExp: Math.floor(Date.now() / 1000) - 10 });
    expect(await mintSessionGateIdToken(envForProject("dy-minter-expired"), audience)).toEqual({ ok: false, reason: "unavailable" });
  });
});

describe("the minter caller key (planning/49 Phase 4 I3): the recipe, pinned", () => {
  it("derives the caller key, its fingerprint and a proof MAC exactly as the independent vectors", async () => {
    expect(CLIENT_SECRET.length).toBeGreaterThanOrEqual(CLIENT_SECRET_MIN_LENGTH);
    const key = await deriveMinterCallerKey(CLIENT_SECRET, VECTOR_GATE_SCRIPT);
    expect(minterCallerKeyHex(key)).toBe(VECTOR_CALLER_KEY_HEX);
    expect(Buffer.from(await independentCallerKey(CLIENT_SECRET, VECTOR_GATE_SCRIPT)).toString("hex")).toBe(VECTOR_CALLER_KEY_HEX);
    expect(await minterCallerKeyFingerprint(key)).toBe(VECTOR_FINGERPRINT);
    expect(await minterCallerProofMac(key, VECTOR_AUDIENCE, VECTOR_TS)).toBe(VECTOR_MAC);
    // The derived gate script name is the existing one, and another region's gate has another key.
    expect(edgeGateScriptNameFor("dy-agency-proof", REGION)).toBe(VECTOR_GATE_SCRIPT);
    const otherRegionKey = await deriveMinterCallerKey(CLIENT_SECRET, edgeGateScriptNameFor("dy-agency-proof", "australia-southeast1"));
    expect(minterCallerKeyHex(otherRegionKey)).toBe(VECTOR_OTHER_REGION_KEY_HEX);
  });

  it("verifyMinterCallerProof: accepts within 60 s either way, refuses everything else", async () => {
    const key = await deriveMinterCallerKey(CLIENT_SECRET, VECTOR_GATE_SCRIPT);
    const now = VECTOR_TS;
    expect(await verifyMinterCallerProof(key, VECTOR_AUDIENCE, VECTOR_TS, VECTOR_MAC, now)).toBe(true);
    expect(await verifyMinterCallerProof(key, VECTOR_AUDIENCE, VECTOR_TS, VECTOR_MAC, now + 60)).toBe(true);
    expect(await verifyMinterCallerProof(key, VECTOR_AUDIENCE, VECTOR_TS, VECTOR_MAC, now - 60)).toBe(true);
    expect(await verifyMinterCallerProof(key, VECTOR_AUDIENCE, VECTOR_TS, VECTOR_MAC, now + 61)).toBe(false);
    expect(await verifyMinterCallerProof(key, VECTOR_AUDIENCE, VECTOR_TS, VECTOR_MAC, now - 61)).toBe(false);
    const otherKey = await deriveMinterCallerKey(OTHER_CLIENT_SECRET, VECTOR_GATE_SCRIPT);
    expect(await verifyMinterCallerProof(otherKey, VECTOR_AUDIENCE, VECTOR_TS, VECTOR_MAC, now)).toBe(false);
    expect(await verifyMinterCallerProof(key, VECTOR_AUDIENCE.replace("pma-", "term-"), VECTOR_TS, VECTOR_MAC, now)).toBe(false);
    expect(await verifyMinterCallerProof(key, VECTOR_AUDIENCE, VECTOR_TS + 1, VECTOR_MAC, now)).toBe(false);
    const flipped = VECTOR_MAC.slice(0, -1) + (VECTOR_MAC.endsWith("A") ? "B" : "A");
    for (const [ts, mac] of [
      [VECTOR_TS, flipped],
      [VECTOR_TS, VECTOR_MAC + "="],
      [VECTOR_TS, VECTOR_MAC.slice(1)],
      [VECTOR_TS, ""],
      [VECTOR_TS, undefined],
      [VECTOR_TS, 42],
      [String(VECTOR_TS), VECTOR_MAC],
      [VECTOR_TS + 0.5, VECTOR_MAC],
      [undefined, VECTOR_MAC],
      [Number.NaN, VECTOR_MAC],
    ] as Array<[unknown, unknown]>) {
      expect(await verifyMinterCallerProof(key, VECTOR_AUDIENCE, ts, mac, now), `${String(ts)} ${String(mac)}`).toBe(false);
    }
  });
});

describe("mintSessionGateIdToken: the caller proof (gate v2)", () => {
  it("mints for EVERY session prefix with a valid proof", async () => {
    const projectId = "dy-minter-proof-ok";
    const env = envForProject(projectId);
    mockGoogle({ projectId });
    for (const serviceName of ["term-a", "sterm-a", "pma-a", "spma-a", "staging-a"]) {
      const result = await mintSessionGateIdToken(env, await validProofRequest(projectId, audienceFor(serviceName)));
      expect(result, serviceName).toMatchObject({ ok: true });
    }
  });

  it("refuses, with no detail and no network call: a wrong key, another region's gate, a stale or future ts, another audience, a broken MAC", async () => {
    const projectId = "dy-minter-proof-bad";
    const env = envForProject(projectId);
    const calls = mockGoogle({ projectId });
    const audience = audienceFor("pma-docs");
    const now = Math.floor(Date.now() / 1000);
    const rightKey = await independentCallerKey(CLIENT_SECRET, edgeGateScriptNameFor(projectId, REGION));
    const wrongSecretKey = await independentCallerKey(OTHER_CLIENT_SECRET, edgeGateScriptNameFor(projectId, REGION));
    const otherRegionKey = await independentCallerKey(CLIENT_SECRET, edgeGateScriptNameFor(projectId, "australia-southeast1"));
    const otherProjectKey = await independentCallerKey(CLIENT_SECRET, edgeGateScriptNameFor("someone-else", REGION));
    const valid = await proofRequest(rightKey, audience, now);
    const refused: Array<{ name: string; request: unknown }> = [
      { name: "another DY_CLIENT_SECRET", request: await proofRequest(wrongSecretKey, audience, now) },
      { name: "the key of another region's gate", request: await proofRequest(otherRegionKey, audience, now) },
      { name: "the key of another project's gate", request: await proofRequest(otherProjectKey, audience, now) },
      { name: "a stale ts (61 s old)", request: await proofRequest(rightKey, audience, now - 61) },
      { name: "a future ts (61 s ahead)", request: await proofRequest(rightKey, audience, now + 61) },
      { name: "a MAC for another audience", request: { ...(await proofRequest(rightKey, audienceFor("pma-other"), now)), audience } },
      { name: "a MAC for another ts", request: { ...valid, ts: now - 1 } },
      { name: "DY_CLIENT_SECRET's own text as the key", request: await proofRequest(new TextEncoder().encode(CLIENT_SECRET), audience, now) },
      { name: "a flipped MAC", request: { ...valid, mac: valid.mac.slice(0, -1) + (valid.mac.endsWith("A") ? "B" : "A") } },
      { name: "a hex MAC", request: { ...valid, mac: await hmac(rightKey, `v1|${audience}|${now}`, "hex") } },
      { name: "ts as a string", request: { ...valid, ts: String(now) } },
      { name: "no mac", request: { audience, ts: now } },
      { name: "no ts", request: { audience, mac: valid.mac } },
      { name: "an object with no proof at all", request: { audience } },
    ];
    for (const testCase of refused) {
      expect(await mintSessionGateIdToken(env, testCase.request), testCase.name).toEqual({ ok: false, reason: "caller-refused" });
    }
    expect(calls).toHaveLength(0);
    // The same audience with the valid proof is served.
    expect(await mintSessionGateIdToken(env, valid)).toMatchObject({ ok: true });
  });

  it("an object request ALWAYS needs a valid proof, even for term- (it never falls back to the keyless v1 rule)", async () => {
    const projectId = "dy-minter-proof-term";
    const env = envForProject(projectId);
    const calls = mockGoogle({ projectId });
    const audience = audienceFor("term-docs");
    expect(await mintSessionGateIdToken(env, { audience })).toEqual({ ok: false, reason: "caller-refused" });
    expect(await mintSessionGateIdToken(env, { audience, ts: Math.floor(Date.now() / 1000), mac: "x" })).toEqual({ ok: false, reason: "caller-refused" });
    expect(calls).toHaveLength(0);
  });

  it("is unavailable for a proof when this Worker cannot check it (no usable DY_CLIENT_SECRET or service-account key)", async () => {
    const projectId = "dy-minter-proof-config";
    const calls = mockGoogle({ projectId });
    const request = await validProofRequest(projectId, audienceFor("pma-docs"));
    const configs: Array<Partial<Env>> = [
      { DY_CLIENT_SECRET: undefined as unknown as string },
      { DY_CLIENT_SECRET: "" },
      { DY_CLIENT_SECRET: CLIENT_SECRET.slice(0, CLIENT_SECRET_MIN_LENGTH - 1) },
      { GCP_SERVICE_ACCOUNT_KEY: undefined },
    ];
    for (const overrides of configs) {
      expect(await mintSessionGateIdToken(envForProject(projectId, overrides), request)).toEqual({ ok: false, reason: "unavailable" });
    }
    expect(calls).toHaveLength(0);
  });

  it("a proof made with a key derived from an EMPTY or short secret is never accepted", async () => {
    const projectId = "dy-minter-proof-empty";
    const calls = mockGoogle({ projectId });
    const gateScript = edgeGateScriptNameFor(projectId, REGION);
    for (const weakSecret of ["", "short"]) {
      const weakKey = await independentCallerKey(weakSecret, gateScript);
      const request = await proofRequest(weakKey, audienceFor("pma-docs"), Math.floor(Date.now() / 1000));
      const result = await mintSessionGateIdToken(envForProject(projectId, { DY_CLIENT_SECRET: weakSecret }), request);
      expect(result.ok, JSON.stringify(weakSecret)).toBe(false);
    }
    expect(calls).toHaveLength(0);
  });
});

describe("mintSessionGateIdToken: the transition rule for a call WITHOUT a proof (gate v1)", () => {
  it("serves term- and sterm- only; pma-, spma- and staging- are refused before any network call", async () => {
    const projectId = "dy-minter-keyless";
    const env = envForProject(projectId);
    const calls = mockGoogle({ projectId });
    for (const serviceName of ["pma-a", "spma-a", "staging-a"]) {
      expect(await mintSessionGateIdToken(env, audienceFor(serviceName)), serviceName).toEqual({ ok: false, reason: "caller-refused" });
    }
    expect(calls).toHaveLength(0);
    for (const serviceName of ["term-a", "sterm-a"]) {
      expect(await mintSessionGateIdToken(env, audienceFor(serviceName)), serviceName).toMatchObject({ ok: true });
    }
  });

  it("serves term- without a proof even when DY_CLIENT_SECRET is unusable (the v1 path does not need it)", async () => {
    const projectId = "dy-minter-keyless-nosecret";
    mockGoogle({ projectId });
    const env = envForProject(projectId, { DY_CLIENT_SECRET: "" });
    expect(await mintSessionGateIdToken(env, audienceFor("term-a"))).toMatchObject({ ok: true });
  });
});

describe("readProjectNumber (shared with edge-gate-deploy)", () => {
  it("pins the project to the key's own project before any network call", async () => {
    const calls = mockGoogle({ projectId: "someone-else" });
    const outcome = await readProjectNumber(envForProject("dy-minter-pin"), "someone-else");
    expect(outcome.ok).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("names the permission to add when projects.get is denied", async () => {
    mockGoogle({ projectId: "dy-minter-perm", projectsGetStatus: 403 });
    const outcome = await readProjectNumber(envForProject("dy-minter-perm"), "dy-minter-perm");
    expect(outcome).toEqual({
      ok: false,
      detail:
        'reading the number of project "dy-minter-perm" failed with HTTP 403: permission denied on resource. ' +
        "The Worker's service account needs resourcemanager.projects.get on its own project (roles/browser has it).",
    });
  });
});

describe("SessionGateMinter (the named entrypoint)", () => {
  it("answers over its one RPC method with the minter's result, for both request forms", async () => {
    const projectId = "dy-minter-entrypoint";
    const env = envForProject(projectId);
    mockGoogle({ projectId });
    const minter = new SessionGateMinter({} as never, env);
    expect(await minter.mintIdToken("https://evil.example")).toEqual({ ok: false, reason: "audience-refused" });
    const minted = await minter.mintIdToken(`https://term-x-${PROJECT_NUMBER}.${REGION}.run.app`);
    expect(minted.ok).toBe(true);
    expect(await minter.mintIdToken(audienceFor("pma-x"))).toEqual({ ok: false, reason: "caller-refused" });
    expect((await minter.mintIdToken(await validProofRequest(projectId, audienceFor("pma-x")))).ok).toBe(true);
  });
});

// ── The gates against this minter: the released v1 (still live until updated) and v2 ──────────────────

const GATE_SESSION_SECRET = "603807493e9f841f3f587631aad45bc075fa1cc8ec73adba4872405dc05ba367";
const GATE_ZONE = "sbmstudio.com.au";

/** A v1 session token for `host`, written out here from the hub#76 recipe. */
async function signSessionToken(host: string, slug: string, purpose: string): Promise<string> {
  const hostKey = await hkdf32(GATE_SESSION_SECRET, `doubleyoup-ephemeral-session-v1/host:${host}`);
  const payload = Buffer.from(JSON.stringify({ siteId: "site_test_1", slug, purpose, uid: 119076, exp: 4102444800 }), "utf8").toString("base64url");
  return `${payload}.${await hmac(hostKey, payload)}`;
}

/** The bindings edge-gate-deploy gives the gate of `projectId` in REGION, with the real minter as DY_MINTER. */
async function gateBindings(projectId: string, env: Env): Promise<Record<string, unknown>> {
  const callerKey = await independentCallerKey(CLIENT_SECRET, edgeGateScriptNameFor(projectId, REGION));
  return {
    DY_SESSION_SECRET: GATE_SESSION_SECRET,
    DY_ZONE_SUFFIX: `.${GATE_ZONE}`,
    DY_RUN_URL_SUFFIX: `-${PROJECT_NUMBER}.${REGION}.run.app`,
    DY_MINTER: new SessionGateMinter({} as never, env),
    DY_MINTER_CALLER_KEY: Buffer.from(callerKey).toString("hex"),
  };
}

describe("the released gate v1 against this minter (the transition)", () => {
  it("the fixture is the released v1, byte for byte", async () => {
    const digest = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(GATE_V1_SOURCE))).toString("hex");
    expect(digest).toBe(GATE_V1_SHA256);
    expect(GATE_V1_SOURCE.split("\n")[0]).toBe("// dy-session-gate v1");
  });

  it("a v1 gate still opens a term- session: it sends the bare audience, and the minter serves term-", async () => {
    const projectId = "dy-minter-v1-term";
    const env = envForProject(projectId);
    const calls = mockGoogle({ projectId, originReply: () => new Response("terminal page") });
    const host = `term-v1-site.${GATE_ZONE}`;
    const token = await signSessionToken(host, "v1-site", "terminal");
    // A v1 gate has no DY_MINTER_CALLER_KEY binding.
    const { DY_MINTER_CALLER_KEY: _unused, ...v1Bindings } = await gateBindings(projectId, env);
    const response = await gateV1.fetch(new Request(`https://${host}/?token=${token}`), v1Bindings);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("terminal page");
    const originCalls = calls.filter((call) => call.request !== undefined);
    expect(originCalls).toHaveLength(1);
    expect(originCalls[0]?.request?.headers.get("x-serverless-authorization")).toMatch(/^Bearer /);
  });

  it("a v1 gate gets NO ID token for a pma- host: a bare 503, and no origin fetch", async () => {
    const projectId = "dy-minter-v1-pma";
    const env = envForProject(projectId);
    const calls = mockGoogle({ projectId, originReply: () => new Response("pma page") });
    const host = `pma-v1-site.${GATE_ZONE}`;
    const token = await signSessionToken(host, "v1-site", "pma");
    const { DY_MINTER_CALLER_KEY: _unused, ...v1Bindings } = await gateBindings(projectId, env);
    const response = await gateV1.fetch(new Request(`https://${host}/?token=${token}`), v1Bindings);
    expect(response.status).toBe(503);
    expect(await response.text()).toBe("session gateway unavailable");
    expect(calls).toHaveLength(0);
  });
});

describe("gate v2 against this minter", () => {
  it("opens a term- and a pma- session with the caller proof; pma- carries the verified token in X-DY-Session-Token", async () => {
    const projectId = "dy-minter-v2";
    const env = envForProject(projectId);
    const calls = mockGoogle({ projectId, originReply: () => new Response("origin page") });
    const bindings = await gateBindings(projectId, env);

    const termHost = `term-v2-site.${GATE_ZONE}`;
    const termToken = await signSessionToken(termHost, "v2-site", "terminal");
    const termResponse = await gateV2.fetch(new Request(`https://${termHost}/?token=${termToken}`), bindings);
    expect(termResponse.status).toBe(200);

    const pmaHost = `pma-v2-site.${GATE_ZONE}`;
    const pmaToken = await signSessionToken(pmaHost, "v2-site", "pma");
    const pmaResponse = await gateV2.fetch(
      new Request(`https://${pmaHost}/index.php?token=${pmaToken}`, { headers: { "x-dy-session-token": "client-forged" } }),
      bindings,
    );
    expect(pmaResponse.status).toBe(200);

    const originRequests = calls.filter((call) => call.request !== undefined).map((call) => call.request as Request);
    expect(originRequests.map((request) => new URL(request.url).hostname)).toEqual([
      `term-v2-site-${PROJECT_NUMBER}.${REGION}.run.app`,
      `pma-v2-site-${PROJECT_NUMBER}.${REGION}.run.app`,
    ]);
    expect(originRequests[0]?.headers.get("x-dy-session-token")).toBeNull();
    expect(originRequests[1]?.headers.get("x-dy-session-token")).toBe(pmaToken);
  });

  it("a v2 gate whose caller key is not this Worker's gets a bare 503 for every prefix, and no origin fetch", async () => {
    const projectId = "dy-minter-v2-wrongkey";
    const env = envForProject(projectId);
    const calls = mockGoogle({ projectId, originReply: () => new Response("origin page") });
    const wrongKey = await independentCallerKey(OTHER_CLIENT_SECRET, edgeGateScriptNameFor(projectId, REGION));
    const bindings = { ...(await gateBindings(projectId, env)), DY_MINTER_CALLER_KEY: Buffer.from(wrongKey).toString("hex") };
    for (const [prefix, purpose] of [
      ["term", "terminal"],
      ["pma", "pma"],
    ]) {
      const host = `${prefix}-v2-wrong.${GATE_ZONE}`;
      const token = await signSessionToken(host, "v2-wrong", purpose as string);
      const response = await gateV2.fetch(new Request(`https://${host}/?token=${token}`), bindings);
      expect(response.status, prefix).toBe(503);
    }
    expect(calls).toHaveLength(0);
  });
});
