// planning/49 Phase 3 (I4): the per-cell session edge gate (src/session-gate/gate.js), under Node.
//
// The gate is uploaded ALONE (edge-gate-deploy), so it is tested here as a module of its own: the I2 key
// vectors, the host grammar against the twin, token checks, and the request flow with a fake minter and a
// mocked fetch. test/session-gate.worker.test.ts runs the same gate under the real workerd runtime.

import { afterEach, describe, expect, it, vi } from "vitest";
// Vite's `?raw` suffix: gate.js as text, to compare with the generated module and pin its sha256.
import GATE_SOURCE_ON_DISK from "../src/session-gate/gate.js?raw";
import gate, { configurationProblem, deriveHostKey, resolveHostTarget, verifyToken } from "../src/session-gate/gate.js";
import type { SessionGateEnv } from "../src/session-gate/gate.js";
import { SESSION_GATE_SOURCE } from "../src/session-gate/gate-source.js";
import { SESSION_GATE_COMPATIBILITY_DATE } from "../src/actuate-edge-gate.js";
import { splitCloudRunSessionServiceName } from "../src/dispatch-params.js";
import { minterCallerProofMac, verifyMinterCallerProof } from "../src/session-gate/caller-key.js";

// What each gate version IS: the sha256 of gate.js and the compatibility date it is uploaded with
// (SESSION_GATE_COMPATIBILITY_DATE in src/actuate-edge-gate.ts).
//
// A CHANGE TO gate.js OR TO THE COMPATIBILITY DATE NEEDS A NEW MARKER VERSION: raise the number on gate.js's
// first line and ADD an entry here. Never make this test pass by editing the hash or the date of an
// existing version. edge-gate-deploy compares the deployed source byte for byte, so a same-version change
// would still deploy, but it refuses to put a LOWER version over a higher one: two different gates under
// one version number would make that downgrade guard compare the wrong things.
//
// v1 is released (planning/49 Phase 3 I6 deployed it on 2026-10-27), so from v1 on the rule above holds
// without exception. v2 (planning/49 Phase 4 I3) adds the minter caller proof with its version-skew retry,
// X-DY-Session-Token, the ?token= fallback to the cookie, and the staging token-strip page.
const GATE_VERSIONS: Record<number, { sha256: string; compatibilityDate: string }> = {
  1: { sha256: "cd5b6e3a661747e5fb4b40713a1fa4b2206cbb6b40ccf35016b54cb04623b5f7", compatibilityDate: "2026-01-01" },
  2: { sha256: "b7645b2df93fd20068d653063e1a58301d4ee59147031f200a23f736257e2398", compatibilityDate: "2026-01-01" },
};

// ── I2 vectors (orchestrator src/session-token.test.ts; the same recipe as app and the container) ──
const SHARED_TEST_SECRET = "unit-test-master-key-not-a-real-secret";
const SHARED_SECRET_HOST_KEYS: Record<string, string> = {
  "term-docs-892769.doubleyoup.com": "gWyh1r7A5axSpqc-rnMp2XxI0jApi2QHBy-iihqsKgI",
  "sterm-docs-892769.doubleyoup.com": "zbiITkA1AjhjbYB5x0uwmNWzCQU6iHONmjOEF7lJFn0",
  "term-other-site.doubleyoup.com": "HPIRIy1ASVELoasyOfFiaZkzbra5pwMQYbAnyemjC2U",
};
// Cell A's v1 session secret (HKDF of the test master key for "ephemeral-session-secret:v1:<Cell.id>").
const CELL_A_V1_SECRET = "603807493e9f841f3f587631aad45bc075fa1cc8ec73adba4872405dc05ba367";
const CELL_A_V1_TERM_DOCS_HOST_KEY = "O7kn2G9wDF-pw1Lk7t6Czb5_OiclM_Y_2mY_zYYBYRs";
// A terminal token for docs-892769 signed with cell A v1's host key (exp 2100-01-01).
const CELL_A_V1_CHAIN_TOKEN =
  "eyJzaXRlSWQiOiJzaXRlX3Rlc3RfMSIsInNsdWciOiJkb2NzLTg5Mjc2OSIsInB1cnBvc2UiOiJ0ZXJtaW5hbCIsInVpZCI6MTE5MDc2LCJleHAiOjQxMDI0NDQ4MDB9.KPl03eKG2FrOdwSKC6wYVlNDrftjrNQeqqDMNk7L2wE";
const CELL_A_V2_SECRET = "46d993d0738e210e275c771df8fe78ef9e98c6cf3b1faa2ed222a7d93f51b572";

const ZONE_SUFFIX = ".sbmstudio.com.au";
const RUN_URL_SUFFIX = "-123456789012.australia-southeast2.run.app";
const FAR_FUTURE_EXP = 4102444800;
// A gate's minter caller key (64 lowercase hex), as edge-gate-deploy binds it.
const MINTER_CALLER_KEY_HEX = "7b1eab777358b371e6e62d42117d5919b44e8e442605f2e9690861b9574abc77";

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function utf8ToBase64url(text: string): string {
  return Buffer.from(text, "utf8").toString("base64url");
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Buffer.from(digest).toString("hex");
}

/** HMAC-SHA256(key, message) as base64url. */
async function hmacBase64url(key: Uint8Array, message: string): Promise<string> {
  const hmacKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(message))));
}

/** The host key, written out here from the recipe rather than taken from gate.js. */
async function independentHostKey(sessionSecret: string, host: string): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey("raw", new TextEncoder().encode(sessionSecret), "HKDF", false, ["deriveBits"]);
  const info = new TextEncoder().encode(`doubleyoup-ephemeral-session-v1/host:${host}`);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info }, ikm, 256));
}

/** A v1 session token for `host`, signed by the test's own implementation of the key chain. */
async function signSessionToken(sessionSecret: string, host: string, claims: Record<string, unknown>): Promise<string> {
  const payload = utf8ToBase64url(JSON.stringify(claims));
  const signature = await hmacBase64url(await independentHostKey(sessionSecret, host), payload);
  return `${payload}.${signature}`;
}

function terminalClaims(slug: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { siteId: "site_test_1", slug, purpose: "terminal", uid: 119076, exp: FAR_FUTURE_EXP, ...overrides };
}

interface FakeMinter {
  mintIdToken: ReturnType<typeof vi.fn>;
}

function okMinter(expiresInSeconds = 3600): FakeMinter {
  return {
    // Gate v2 sends { audience, ts, mac }.
    mintIdToken: vi.fn(async (request: { audience: string }) => ({
      ok: true,
      idToken: `id-token-for:${request.audience}`,
      expiresAt: Math.floor(Date.now() / 1000) + expiresInSeconds,
    })),
  };
}

function gateEnv(minter: FakeMinter, overrides: Partial<SessionGateEnv> = {}): SessionGateEnv {
  return {
    DY_SESSION_SECRET: CELL_A_V1_SECRET,
    DY_ZONE_SUFFIX: ZONE_SUFFIX,
    DY_RUN_URL_SUFFIX: RUN_URL_SUFFIX,
    DY_MINTER: minter as unknown as SessionGateEnv["DY_MINTER"],
    DY_MINTER_CALLER_KEY: MINTER_CALLER_KEY_HEX,
    DY_SESSION_KEY_VERSION: "1",
    DY_SESSION_KEY_FINGERPRINT: "0123456789abcdef",
    DY_MINTER_CALLER_FINGERPRINT: "fedcba9876543210",
    ...overrides,
  };
}

/** The redirect mode of each origin fetch, in order (see mockOrigin). */
let originRedirectModes: Array<string | undefined> = [];

/** Mock the global fetch with one origin reply; returns the requests the gate sent. */
function mockOrigin(reply: () => Response = () => new Response("origin body", { status: 200, headers: { "x-origin": "1" } })): Request[] {
  const sent: Request[] = [];
  originRedirectModes = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request, init?: RequestInit) => {
      sent.push(input);
      originRedirectModes.push(init?.redirect);
      return reply();
    }),
  );
  return sent;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("session gate: the embedded source", () => {
  it("gate-source.ts is gate.js, byte for byte (regenerate with npm run embed-session-gate)", () => {
    expect(SESSION_GATE_SOURCE).toBe(GATE_SOURCE_ON_DISK);
  });

  it("the first line is the marker, and gate.js and its compatibility date are pinned to that version (a change needs a NEW version)", async () => {
    const firstLine = GATE_SOURCE_ON_DISK.split("\n")[0];
    const match = /^\/\/ dy-session-gate v([1-9][0-9]*)$/.exec(firstLine as string);
    expect(match).not.toBeNull();
    const version = Number((match as RegExpExecArray)[1]);
    const knownVersions = Object.keys(GATE_VERSIONS).map(Number);
    // The current version is the newest one: a new gate gets a NEW entry, never an edited old one.
    expect(version).toBe(Math.max(...knownVersions));
    const pinned = GATE_VERSIONS[version] as { sha256: string; compatibilityDate: string };
    expect(await sha256Hex(GATE_SOURCE_ON_DISK)).toBe(pinned.sha256);
    expect(SESSION_GATE_COMPATIBILITY_DATE).toBe(pinned.compatibilityDate);
  });

  it("imports nothing: Cloudflare runs it as a single module", () => {
    expect(GATE_SOURCE_ON_DISK).not.toMatch(/^\s*import[\s{*]/m);
    expect(GATE_SOURCE_ON_DISK).not.toMatch(/\brequire\(/);
    expect(GATE_SOURCE_ON_DISK).toMatch(/^export default \{$/m);
  });
});

describe("session gate: the key chain (I2 vectors)", () => {
  it("derives the shared-secret host keys", async () => {
    for (const [host, expected] of Object.entries(SHARED_SECRET_HOST_KEYS)) {
      expect(base64url(await deriveHostKey(SHARED_TEST_SECRET, host))).toBe(expected);
    }
  });

  it("derives cell A's v1 host key from the 64-hex secret TEXT, and lower-cases the host", async () => {
    expect(base64url(await deriveHostKey(CELL_A_V1_SECRET, "term-docs-892769.doubleyoup.com"))).toBe(CELL_A_V1_TERM_DOCS_HOST_KEY);
    expect(base64url(await deriveHostKey(CELL_A_V1_SECRET, "TERM-Docs-892769.doubleyoup.com"))).toBe(CELL_A_V1_TERM_DOCS_HOST_KEY);
  });

  it("verifies the chain token with cell A v1's host key and returns its claims", async () => {
    const hostKey = await deriveHostKey(CELL_A_V1_SECRET, "term-docs-892769.doubleyoup.com");
    expect(await verifyToken(CELL_A_V1_CHAIN_TOKEN, hostKey, "terminal", "docs-892769")).toEqual({
      siteId: "site_test_1",
      slug: "docs-892769",
      purpose: "terminal",
      uid: 119076,
      exp: FAR_FUTURE_EXP,
    });
  });

  it("refuses the chain token under cell A v2, another host, or the secret used directly as the key", async () => {
    const v2Key = await deriveHostKey(CELL_A_V2_SECRET, "term-docs-892769.doubleyoup.com");
    expect(await verifyToken(CELL_A_V1_CHAIN_TOKEN, v2Key, "terminal", "docs-892769")).toBeNull();
    const otherHostKey = await deriveHostKey(CELL_A_V1_SECRET, "sterm-docs-892769.doubleyoup.com");
    expect(await verifyToken(CELL_A_V1_CHAIN_TOKEN, otherHostKey, "terminal", "docs-892769")).toBeNull();
    // No master-key fallback (syd's EPHEMERAL_SESSION_ACCEPT_MASTER is not carried over).
    const secretAsKey = new TextEncoder().encode(CELL_A_V1_SECRET);
    expect(await verifyToken(CELL_A_V1_CHAIN_TOKEN, secretAsKey, "terminal", "docs-892769")).toBeNull();
  });

  it("agrees with the test's own implementation of the chain", async () => {
    const host = "pma-westernmoneyfair.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("westernmoneyfair", { purpose: "pma" }));
    const hostKey = await deriveHostKey(CELL_A_V1_SECRET, host);
    expect(await verifyToken(token, hostKey, "pma", "westernmoneyfair")).toMatchObject({ purpose: "pma", slug: "westernmoneyfair" });
  });
});

describe("session gate: verifyToken refusals", () => {
  const host = "term-docs-892769.sbmstudio.com.au";

  it("refuses a wrong purpose, a wrong slug, an expired token, and a tampered token", async () => {
    const hostKey = await deriveHostKey(CELL_A_V1_SECRET, host);
    const valid = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("docs-892769"));
    expect(await verifyToken(valid, hostKey, "terminal", "docs-892769")).not.toBeNull();
    expect(await verifyToken(valid, hostKey, "pma", "docs-892769")).toBeNull();
    expect(await verifyToken(valid, hostKey, "terminal", "docs-892770")).toBeNull();

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expired = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("docs-892769", { exp: nowSeconds - 1 }));
    expect(await verifyToken(expired, hostKey, "terminal", "docs-892769")).toBeNull();
    const noExp = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("docs-892769", { exp: "never" }));
    expect(await verifyToken(noExp, hostKey, "terminal", "docs-892769")).toBeNull();
    // exp must be a safe integer, as in the minter: no fraction, no float beyond 2^53.
    for (const exp of [FAR_FUTURE_EXP + 0.5, 1e300, Number.MAX_SAFE_INTEGER + 2]) {
      const odd = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("docs-892769", { exp }));
      expect(await verifyToken(odd, hostKey, "terminal", "docs-892769")).toBeNull();
    }

    const [payload, signature] = valid.split(".") as [string, string];
    const forgedPayload = utf8ToBase64url(JSON.stringify(terminalClaims("docs-892769", { uid: 0 })));
    expect(await verifyToken(`${forgedPayload}.${signature}`, hostKey, "terminal", "docs-892769")).toBeNull();
    const flippedSignature = signature.slice(0, -1) + (signature.endsWith("A") ? "B" : "A");
    expect(await verifyToken(`${payload}.${flippedSignature}`, hostKey, "terminal", "docs-892769")).toBeNull();
  });

  it("refuses malformed tokens without throwing", async () => {
    const hostKey = await deriveHostKey(CELL_A_V1_SECRET, host);
    for (const token of [null, undefined, "", ".", "abc", "abc.", ".abc", "a.b.c", "%%%.%%%", "a".repeat(5000)]) {
      expect(await verifyToken(token as string, hostKey, "terminal", "docs-892769")).toBeNull();
    }
    // A correctly SIGNED payload that is not JSON, or JSON null.
    for (const rawPayload of ["not json", "null", "42"]) {
      const payload = utf8ToBase64url(rawPayload);
      const signature = await hmacBase64url(await independentHostKey(CELL_A_V1_SECRET, host), payload);
      expect(await verifyToken(`${payload}.${signature}`, hostKey, "terminal", "docs-892769")).toBeNull();
    }
  });
});

describe("session gate: resolveHostTarget", () => {
  it("maps each session prefix to its purpose, with the label as the Cloud Run service name", () => {
    expect(resolveHostTarget("term-docs-892769.sbmstudio.com.au", ZONE_SUFFIX)).toEqual({
      expectedPurpose: "terminal",
      slug: "docs-892769",
      host: "term-docs-892769.sbmstudio.com.au",
      label: "term-docs-892769",
    });
    expect(resolveHostTarget("pma-x.sbmstudio.com.au", ZONE_SUFFIX)).toMatchObject({ expectedPurpose: "pma", slug: "x" });
    expect(resolveHostTarget("sterm-x.sbmstudio.com.au", ZONE_SUFFIX)).toMatchObject({ expectedPurpose: "terminal", slug: "x" });
    expect(resolveHostTarget("spma-x.sbmstudio.com.au", ZONE_SUFFIX)).toMatchObject({ expectedPurpose: "pma", slug: "x" });
    expect(resolveHostTarget("staging-x.sbmstudio.com.au", ZONE_SUFFIX)).toMatchObject({ expectedPurpose: "staging", slug: "x" });
    expect(resolveHostTarget("TERM-X.SBMSTUDIO.COM.AU", ZONE_SUFFIX)).toMatchObject({ host: "term-x.sbmstudio.com.au", label: "term-x" });
  });

  it("refuses every host that is not exactly one session label in the zone", () => {
    const refused = [
      "sbmstudio.com.au",
      "term-x.evilsbmstudio.com.au",
      "term-x.sbmstudio.com.au.evil.example",
      "a.term-x.sbmstudio.com.au",
      "term-.sbmstudio.com.au",
      "term--x.sbmstudio.com.au",
      "term-x-.sbmstudio.com.au",
      "ssh-x.sbmstudio.com.au",
      "x.sbmstudio.com.au",
      "agencydoubleyoup.example.workers.dev",
      `term-${"a".repeat(45)}.sbmstudio.com.au`,
    ];
    for (const host of refused) {
      expect(resolveHostTarget(host, ZONE_SUFFIX), host).toBeNull();
    }
    // The longest label that is still a session service name (49 characters).
    expect(resolveHostTarget(`term-${"a".repeat(44)}.sbmstudio.com.au`, ZONE_SUFFIX)).not.toBeNull();
  });

  it("accepts exactly the labels the twin's splitCloudRunSessionServiceName accepts, with the same purpose", () => {
    const purposeByPrefix: Record<string, string> = { term: "terminal", sterm: "terminal", pma: "pma", spma: "pma", staging: "staging" };
    const labels = [
      "term-docs-892769",
      "sterm-docs-892769",
      "pma-a",
      "spma-a1",
      "staging-lawnsbydavid",
      "term-",
      "term--a",
      "term-a-",
      "terma",
      "stermx",
      "staging",
      "dy-run-probe",
      "term-UPPER",
      `pma-${"b".repeat(46)}`,
      `pma-${"b".repeat(44)}`,
      `staging-${"c".repeat(41)}`,
      `staging-${"c".repeat(42)}`,
    ];
    for (const label of labels) {
      const twin = splitCloudRunSessionServiceName(label);
      const gateTarget = resolveHostTarget(`${label}${ZONE_SUFFIX}`, ZONE_SUFFIX);
      if (twin === null) {
        // An uppercase label is lowered by the gate (hosts are case-insensitive), so compare on the lowered label.
        if (label !== label.toLowerCase()) {
          continue;
        }
        expect(gateTarget, label).toBeNull();
        continue;
      }
      expect(gateTarget, label).toEqual({
        expectedPurpose: purposeByPrefix[twin.prefix],
        slug: twin.slug,
        host: `${label}${ZONE_SUFFIX}`,
        label,
      });
    }
  });
});

describe("session gate: configuration", () => {
  it("names the first missing or malformed binding, never a value", () => {
    const minter = okMinter();
    expect(configurationProblem(gateEnv(minter))).toBeNull();
    expect(configurationProblem(gateEnv(minter, { DY_SESSION_SECRET: undefined }))).toMatch(/^DY_SESSION_SECRET/);
    expect(configurationProblem(gateEnv(minter, { DY_SESSION_SECRET: CELL_A_V1_SECRET.toUpperCase() }))).toMatch(/^DY_SESSION_SECRET/);
    expect(configurationProblem(gateEnv(minter, { DY_SESSION_SECRET: SHARED_TEST_SECRET }))).toMatch(/^DY_SESSION_SECRET/);
    expect(configurationProblem(gateEnv(minter, { DY_ZONE_SUFFIX: "sbmstudio.com.au" }))).toMatch(/^DY_ZONE_SUFFIX/);
    expect(configurationProblem(gateEnv(minter, { DY_ZONE_SUFFIX: ".com" }))).toMatch(/^DY_ZONE_SUFFIX/);
    expect(configurationProblem(gateEnv(minter, { DY_RUN_URL_SUFFIX: ".run.app" }))).toMatch(/^DY_RUN_URL_SUFFIX/);
    expect(configurationProblem(gateEnv(minter, { DY_RUN_URL_SUFFIX: "-123.evil.example" }))).toMatch(/^DY_RUN_URL_SUFFIX/);
    expect(configurationProblem(gateEnv(minter, { DY_RUN_URL_SUFFIX: "-123.australia-southeast2.run.app/x" }))).toMatch(/^DY_RUN_URL_SUFFIX/);
    expect(configurationProblem(gateEnv(minter, { DY_MINTER: undefined }))).toMatch(/^DY_MINTER/);
    // Gate v2: the caller key must be 64 lowercase hex. The message names the binding, never a value.
    for (const callerKey of [undefined, "", MINTER_CALLER_KEY_HEX.toUpperCase(), MINTER_CALLER_KEY_HEX.slice(2), `${MINTER_CALLER_KEY_HEX}00`]) {
      const problem = configurationProblem(gateEnv(minter, { DY_MINTER_CALLER_KEY: callerKey }));
      expect(problem, String(callerKey)).toBe("DY_MINTER_CALLER_KEY is not set to 64 lowercase hex characters");
    }
  });

  it("answers 500 for a misconfigured gate: no minter call, no origin fetch, no value in the body", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const token = await signSessionToken(CELL_A_V1_SECRET, "term-x.sbmstudio.com.au", terminalClaims("x"));
    const badRunSuffix = "-123.evil.example";
    const response = await gate.fetch(
      new Request(`https://term-x.sbmstudio.com.au/?token=${token}`),
      gateEnv(minter, { DY_RUN_URL_SUFFIX: badRunSuffix }),
    );
    expect(response.status).toBe(500);
    const body = await response.text();
    expect(body).toMatch(/^edge gate misconfigured: DY_RUN_URL_SUFFIX/);
    expect(body).not.toContain(badRunSuffix);
    expect(body).not.toContain(CELL_A_V1_SECRET);
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });
});

describe("session gate: the request flow", () => {
  it("404s a host outside the cell's session hosts, with no minter call and no origin fetch", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    for (const url of ["https://sbmstudio.com.au/", "https://agencydoubleyoup.example.workers.dev/", "https://x.sbmstudio.com.au/"]) {
      const response = await gate.fetch(new Request(url), gateEnv(minter));
      expect(response.status).toBe(404);
    }
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it("401s an absent or invalid token at the edge: no minter call, no origin fetch (a bot never wakes the container)", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const otherHostToken = await signSessionToken(CELL_A_V1_SECRET, "term-y.sbmstudio.com.au", terminalClaims("y"));
    const wrongPurposeToken = await signSessionToken(CELL_A_V1_SECRET, "term-x.sbmstudio.com.au", terminalClaims("x", { purpose: "pma" }));
    const requests = [
      new Request("https://term-x.sbmstudio.com.au/"),
      new Request("https://term-x.sbmstudio.com.au/?token=garbage"),
      new Request(`https://term-x.sbmstudio.com.au/?token=${otherHostToken}`),
      new Request(`https://term-x.sbmstudio.com.au/?token=${wrongPurposeToken}`),
      new Request("https://term-x.sbmstudio.com.au/", { headers: { cookie: `__Host-dy_egt=${otherHostToken}`, "sec-fetch-site": "same-origin" } }),
      new Request("https://term-x.sbmstudio.com.au/ws", { headers: { upgrade: "websocket" } }),
    ];
    for (const request of requests) {
      const response = await gate.fetch(request, gateEnv(minter));
      expect(response.status).toBe(401);
      expect(response.headers.get("cache-control")).toBe("no-store");
    }
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it("forwards a valid query-token request to the derived run.app origin with the minted ID token, and sets the gate cookie", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-26T00:00:00.000Z"));
    const nowSeconds = Math.floor(Date.now() / 1000);
    const minter = okMinter();
    const sent = mockOrigin();
    // A pma host: it keeps the client's other cookies (a terminal host forwards none, tested below).
    const host = "pma-flow-a.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-a", { purpose: "pma", exp: nowSeconds + 600 }));
    const request = new Request(`https://${host}/static/app.js?token=${token}&x=1`, {
      method: "POST",
      body: "request body",
      headers: {
        authorization: "Bearer client-supplied",
        "x-serverless-authorization": "Bearer client-supplied-too",
        cookie: "theme=dark; __Host-dy_egt=stale-cookie-token; lang=en",
        "x-custom": "kept",
      },
    });

    const response = await gate.fetch(request, gateEnv(minter));

    const audience = `https://pma-flow-a${RUN_URL_SUFFIX}`;
    expect(minter.mintIdToken).toHaveBeenCalledTimes(1);
    // Gate v2: the minter gets { audience, ts, mac }, a caller proof made now with DY_MINTER_CALLER_KEY.
    const mintRequest = minter.mintIdToken.mock.calls[0]?.[0] as { audience: string; ts: number; mac: string };
    expect(Object.keys(mintRequest).sort()).toEqual(["audience", "mac", "ts"]);
    expect(mintRequest.audience).toBe(audience);
    expect(mintRequest.ts).toBe(nowSeconds);
    expect(await verifyMinterCallerProof(Buffer.from(MINTER_CALLER_KEY_HEX, "hex"), audience, mintRequest.ts, mintRequest.mac, nowSeconds)).toBe(true);
    expect(sent).toHaveLength(1);
    const forwarded = sent[0] as Request;
    // Same path, method and body. The verified ?token= leaves the query: a pma- container reads the token
    // from X-DY-Session-Token.
    expect(forwarded.url).toBe(`${audience}/static/app.js?x=1`);
    expect(forwarded.headers.get("x-dy-session-token")).toBe(token);
    expect(forwarded.method).toBe("POST");
    expect(await forwarded.text()).toBe("request body");
    // Only the gate's ID token reaches Cloud Run's IAM check: it replaces the client's
    // X-Serverless-Authorization, the header Cloud Run checks first. The client's Authorization passes on.
    expect(forwarded.headers.get("x-serverless-authorization")).toBe(`Bearer id-token-for:${audience}`);
    expect(forwarded.headers.get("authorization")).toBe("Bearer client-supplied");
    // The gate's own cookie is removed; the others pass.
    expect(forwarded.headers.get("cookie")).toBe("theme=dark; lang=en");
    expect(forwarded.headers.get("x-custom")).toBe("kept");
    expect(originRedirectModes).toEqual(["manual"]);

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("origin body");
    expect(response.headers.get("x-origin")).toBe("1");
    expect(response.headers.get("set-cookie")).toBe(`__Host-dy_egt=${token}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`);
  });

  it("re-authenticates off the cookie alone from this host's own pages (Sec-Fetch-Site same-origin or none), with no new cookie", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "pma-flow-b.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-b", { purpose: "pma" }));
    for (const fetchSite of ["same-origin", "none"]) {
      const response = await gate.fetch(
        new Request(`https://${host}/next`, { headers: { cookie: `__Host-dy_egt=${token}; theme=dark`, "sec-fetch-site": fetchSite } }),
        gateEnv(minter),
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("set-cookie")).toBeNull();
    }
    expect(sent).toHaveLength(2);
    expect((sent[0] as Request).url).toBe(`https://pma-flow-b${RUN_URL_SUFFIX}/next`);
    expect((sent[0] as Request).headers.get("cookie")).toBe("theme=dark");
  });

  it("401s a COOKIE-ONLY request from anywhere but this host's own pages: no minter call, no origin fetch", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "pma-flow-g.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-g", { purpose: "pma" }));
    // Another site (cross-site), a sibling host of the zone such as a tenant's staging site (same-site), and
    // a request with no Sec-Fetch-Site at all.
    for (const fetchSite of ["cross-site", "same-site", null]) {
      const headers: Record<string, string> = { cookie: `__Host-dy_egt=${token}` };
      if (fetchSite !== null) {
        headers["sec-fetch-site"] = fetchSite;
      }
      const response = await gate.fetch(new Request(`https://${host}/sql.php`, { method: "POST", headers }), gateEnv(minter));
      expect(response.status).toBe(401);
    }
    // The old cookie name is not read at all.
    const oldName = await gate.fetch(
      new Request(`https://${host}/`, { headers: { cookie: `__dy_egt=${token}`, "sec-fetch-site": "same-origin" } }),
      gateEnv(minter),
    );
    expect(oldName.status).toBe(401);
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it("a query token is served whatever Sec-Fetch-Site says (the app opens the session from another site)", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "pma-flow-h.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-h", { purpose: "pma" }));
    const response = await gate.fetch(new Request(`https://${host}/?token=${token}`, { headers: { "sec-fetch-site": "cross-site" } }), gateEnv(minter));
    expect(response.status).toBe(200);
    expect(sent).toHaveLength(1);
  });

  it("a terminal host (term-, sterm-) forwards NO Cookie header at all", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    for (const label of ["term-flow-i", "sterm-flow-i"]) {
      const host = `${label}.sbmstudio.com.au`;
      const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-i"));
      const response = await gate.fetch(
        new Request(`https://${host}/?token=${token}`, { headers: { cookie: "theme=dark; __Host-dy_egt=old; lang=en" } }),
        gateEnv(minter),
      );
      expect(response.status).toBe(200);
    }
    expect(sent).toHaveLength(2);
    for (const forwarded of sent) {
      expect(forwarded.headers.get("cookie")).toBeNull();
    }
  });

  it("returns an origin redirect to the browser and never follows it (redirect: manual on every origin fetch)", async () => {
    const minter = okMinter();
    const sent = mockOrigin(() => new Response(null, { status: 302, headers: { location: "https://elsewhere.example/steal" } }));
    const host = "pma-flow-j.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-j", { purpose: "pma" }));
    const response = await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter));
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("https://elsewhere.example/steal");
    // ONE fetch, to the origin, with redirect: manual: the gate itself never requested elsewhere.example.
    expect(sent).toHaveLength(1);
    expect((sent[0] as Request).url).toBe(`https://pma-flow-j${RUN_URL_SUFFIX}/`);
    expect(originRedirectModes).toEqual(["manual"]);
  });

  it("returns the origin's answer to a WebSocket upgrade VERBATIM, with no cookie", async () => {
    const minter = okMinter();
    // Node cannot build a 101 Response; the gate must hand back the very object fetch returned.
    const originUpgradeAnswer = new Response(null, { status: 200, headers: { "x-upgrade": "origin" } });
    const sent = mockOrigin(() => originUpgradeAnswer);
    const host = "term-flow-c.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-c"));
    const response = await gate.fetch(
      new Request(`https://${host}/ws?token=${token}`, { headers: { upgrade: "websocket", connection: "Upgrade", origin: `https://${host}` } }),
      gateEnv(minter),
    );
    expect(response).toBe(originUpgradeAnswer);
    expect(response.headers.get("set-cookie")).toBeNull();
    const forwarded = sent[0] as Request;
    expect(forwarded.url).toBe(`https://term-flow-c${RUN_URL_SUFFIX}/ws?token=${token}`);
    expect(forwarded.headers.get("upgrade")).toBe("websocket");
    expect(originRedirectModes).toEqual(["manual"]);
  });

  it("401s a WebSocket upgrade whose Origin is not this host, even with a valid query token: no fetch", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "term-flow-k.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-k"));
    for (const origin of [null, "https://staging-acme.sbmstudio.com.au", "https://evil.example", `http://${host}`, "null"]) {
      const headers: Record<string, string> = { upgrade: "websocket", connection: "Upgrade", cookie: `__Host-dy_egt=${token}` };
      if (origin !== null) {
        headers.origin = origin;
      }
      const viaQuery = await gate.fetch(new Request(`https://${host}/ws?token=${token}`, { headers }), gateEnv(minter));
      expect(viaQuery.status).toBe(401);
      const viaCookie = await gate.fetch(new Request(`https://${host}/ws`, { headers }), gateEnv(minter));
      expect(viaCookie.status).toBe(401);
    }
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it("serves the REAL terminal page's request sequence: GET /?token=T from the app, then the WebSocket /ws?token=T", async () => {
    // The infra terminal (cell-run/terminal-image/server/index.js) inlines every asset into the page and
    // reads the token ONLY from ?token=. Its page JS opens
    //   new WebSocket(wsProto + "//" + location.host + "/ws?token=" + encodeURIComponent(token))
    // so a browser makes exactly these two requests. The first is a navigation from the app (another site);
    // the second comes from the page itself and carries the cookie the first answer set.
    const minter = okMinter();
    const upgradeAnswer = new Response(null, { status: 200, headers: { "x-upgrade": "origin" } });
    let call = 0;
    const sent = mockOrigin(() => {
      call += 1;
      if (call === 1) {
        return new Response("<!doctype html>terminal page", { headers: { "content-type": "text/html; charset=utf-8" } });
      }
      return upgradeAnswer;
    });
    const host = "term-docs-892769.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("docs-892769"));

    const page = await gate.fetch(
      new Request(`https://${host}/?token=${token}`, {
        headers: { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
      }),
      gateEnv(minter),
    );
    expect(page.status).toBe(200);
    const setCookie = page.headers.get("set-cookie") as string;
    expect(setCookie).toMatch(/^__Host-dy_egt=[^;]+; Path=\/; Max-Age=\d+; HttpOnly; Secure; SameSite=Lax$/);
    const cookiePair = setCookie.split(";")[0] as string;

    const socket = await gate.fetch(
      new Request(`https://${host}/ws?token=${encodeURIComponent(token)}`, {
        headers: {
          upgrade: "websocket",
          connection: "Upgrade",
          origin: `https://${host}`,
          cookie: cookiePair,
          "sec-fetch-site": "same-origin",
          "sec-fetch-mode": "websocket",
        },
      }),
      gateEnv(minter),
    );
    expect(socket).toBe(upgradeAnswer);

    expect(sent).toHaveLength(2);
    const [pageRequest, socketRequest] = sent as [Request, Request];
    expect(pageRequest.url).toBe(`https://term-docs-892769${RUN_URL_SUFFIX}/?token=${token}`);
    expect(socketRequest.url).toBe(`https://term-docs-892769${RUN_URL_SUFFIX}/ws?token=${encodeURIComponent(token)}`);
    // The container gets the token where it reads it (the query) and no cookie.
    expect(new URL(socketRequest.url).searchParams.get("token")).toBe(token);
    expect(socketRequest.headers.get("cookie")).toBeNull();
    expect(socketRequest.headers.get("upgrade")).toBe("websocket");
  });

  it("caches the ID token per audience, and mints again near its expiry", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-26T00:00:00.000Z"));
    const minter = okMinter(3600);
    mockOrigin();
    const host = "term-flow-d.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-d"));
    const send = () => gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter));

    await send();
    await send();
    expect(minter.mintIdToken).toHaveBeenCalledTimes(1);
    // 3600 s token, 300 s margin: at +3299 s it is still used, at +3300 s it is minted again.
    vi.setSystemTime(new Date(Date.parse("2026-10-26T00:00:00.000Z") + 3299 * 1000));
    await send();
    expect(minter.mintIdToken).toHaveBeenCalledTimes(1);
    vi.setSystemTime(new Date(Date.parse("2026-10-26T00:00:00.000Z") + 3300 * 1000));
    await send();
    expect(minter.mintIdToken).toHaveBeenCalledTimes(2);
  });

  it("answers a bare 503 when the minter refuses, throws or answers garbage, and fetches nothing", async () => {
    const minters: FakeMinter[] = [
      { mintIdToken: vi.fn(async () => ({ ok: false, reason: "audience-refused" })) },
      { mintIdToken: vi.fn(async () => ({ ok: false, reason: "unavailable" })) },
      {
        mintIdToken: vi.fn(async () => {
          throw new Error("RPC dropped: internal detail");
        }),
      },
      { mintIdToken: vi.fn(async () => ({ ok: true, idToken: 42 })) },
      { mintIdToken: vi.fn(async () => null) },
    ];
    let index = 0;
    for (const minter of minters) {
      index += 1;
      const sent = mockOrigin();
      const host = `term-flow-e${index}.sbmstudio.com.au`;
      const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims(`flow-e${index}`));
      const response = await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter));
      expect(response.status).toBe(503);
      expect(await response.text()).toBe("session gateway unavailable");
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(sent).toHaveLength(0);
    }
  });

  it("serves the I2 chain token for its host under cell A v1, and refuses it under v2", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const env = gateEnv(minter, { DY_ZONE_SUFFIX: ".doubleyoup.com" });
    const ok = await gate.fetch(new Request(`https://term-docs-892769.doubleyoup.com/?token=${CELL_A_V1_CHAIN_TOKEN}`), env);
    expect(ok.status).toBe(200);
    expect((sent[0] as Request).url).toBe(`https://term-docs-892769${RUN_URL_SUFFIX}/?token=${CELL_A_V1_CHAIN_TOKEN}`);
    const refused = await gate.fetch(
      new Request(`https://term-docs-892769.doubleyoup.com/?token=${CELL_A_V1_CHAIN_TOKEN}`),
      gateEnv(minter, { DY_ZONE_SUFFIX: ".doubleyoup.com", DY_SESSION_SECRET: CELL_A_V2_SECRET }),
    );
    expect(refused.status).toBe(401);
  });

  it("never puts the session secret in any answer", async () => {
    const minter = okMinter();
    mockOrigin();
    const host = "term-flow-f.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("flow-f"));
    const answers = [
      await gate.fetch(new Request("https://elsewhere.example/"), gateEnv(minter)),
      await gate.fetch(new Request(`https://${host}/`), gateEnv(minter)),
      await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter)),
      await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter, { DY_MINTER: undefined })),
    ];
    for (const answer of answers) {
      expect(await answer.text()).not.toContain(CELL_A_V1_SECRET);
      for (const [, value] of answer.headers) {
        expect(value).not.toContain(CELL_A_V1_SECRET);
      }
    }
  });
});

describe("session gate v2: the minter caller proof", () => {
  it("sends { audience, ts, mac } with the MAC of the independent vector (the minter's own recipe)", async () => {
    // The vector of test/session-gate-minter.test.ts, computed by a separate HKDF/HMAC implementation:
    // this caller key, this audience, this ts.
    const vectorTs = 1793404800;
    const vectorMac = "5IiC-CfevaYzhhg0WJdpVDZi2UQ8F4pREFuY5cjS3eE";
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(vectorTs * 1000));
    const minter = okMinter();
    mockOrigin();
    const host = "pma-docs-892769.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("docs-892769", { purpose: "pma" }));
    const response = await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter));
    expect(response.status).toBe(200);
    const audience = "https://pma-docs-892769-123456789012.australia-southeast2.run.app";
    expect(minter.mintIdToken).toHaveBeenCalledWith({ audience, ts: vectorTs, mac: vectorMac });
    expect(await minterCallerProofMac(Buffer.from(MINTER_CALLER_KEY_HEX, "hex"), audience, vectorTs)).toBe(vectorMac);
  });

  it("makes a NEW proof for each mint call (the minter refuses a proof older than 60 s)", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const start = Date.parse("2026-10-31T00:00:00.000Z");
    vi.setSystemTime(new Date(start));
    // A 400 s ID token: with the 300 s refresh margin it is minted again after 100 s.
    const minter = okMinter(400);
    mockOrigin();
    const host = "term-proof-b.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("proof-b"));
    await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter));
    vi.setSystemTime(new Date(start + 101 * 1000));
    await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter));
    expect(minter.mintIdToken).toHaveBeenCalledTimes(2);
    const first = minter.mintIdToken.mock.calls[0]?.[0] as { ts: number; mac: string };
    const second = minter.mintIdToken.mock.calls[1]?.[0] as { ts: number; mac: string };
    expect(second.ts - first.ts).toBe(101);
    expect(second.mac).not.toBe(first.mac);
  });

  it("answers 500 without a caller key: no minter call, no origin fetch, no key in the body", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "term-proof-c.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("proof-c"));
    const response = await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter, { DY_MINTER_CALLER_KEY: undefined }));
    expect(response.status).toBe(500);
    expect(await response.text()).toBe("edge gate misconfigured: DY_MINTER_CALLER_KEY is not set to 64 lowercase hex characters");
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });
});

describe("session gate v2: X-DY-Session-Token", () => {
  it("pma- and spma- hosts get the verified QUERY token; a client-sent value never reaches the origin", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const tokens: string[] = [];
    for (const label of ["pma-hdr-a", "spma-hdr-a"]) {
      const host = `${label}.sbmstudio.com.au`;
      const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("hdr-a", { purpose: "pma" }));
      tokens.push(token);
      const response = await gate.fetch(
        new Request(`https://${host}/index.php?token=${token}`, { headers: { "X-DY-Session-Token": "forged-by-the-client" } }),
        gateEnv(minter),
      );
      expect(response.status).toBe(200);
    }
    expect(sent).toHaveLength(2);
    expect((sent[0] as Request).headers.get("x-dy-session-token")).toBe(tokens[0]);
    expect((sent[1] as Request).headers.get("x-dy-session-token")).toBe(tokens[1]);
  });

  it("a cookie-only pma- request gets the verified COOKIE token, not the client's header", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "pma-hdr-b.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("hdr-b", { purpose: "pma" }));
    const response = await gate.fetch(
      new Request(`https://${host}/sql.php`, {
        method: "POST",
        headers: { cookie: `__Host-dy_egt=${token}; pma_lang=en`, "sec-fetch-site": "same-origin", "x-dy-session-token": "forged-by-the-client" },
      }),
      gateEnv(minter),
    );
    expect(response.status).toBe(200);
    const forwarded = sent[0] as Request;
    expect(forwarded.headers.get("x-dy-session-token")).toBe(token);
    // The gate's own cookie still does not travel (the token goes only in the header the gate writes).
    expect(forwarded.headers.get("cookie")).toBe("pma_lang=en");
  });

  it("term- and sterm- hosts get NO X-DY-Session-Token, a client-sent one is deleted, and the query keeps the token", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const tokens: string[] = [];
    for (const label of ["term-hdr-c", "sterm-hdr-c"]) {
      const host = `${label}.sbmstudio.com.au`;
      const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("hdr-c"));
      tokens.push(token);
      const response = await gate.fetch(
        new Request(`https://${host}/?token=${token}`, { headers: { "x-dy-session-token": token } }),
        gateEnv(minter),
      );
      expect(response.status, label).toBe(200);
    }
    expect(sent).toHaveLength(2);
    for (const forwarded of sent) {
      expect(forwarded.headers.get("x-dy-session-token")).toBeNull();
    }
    // The terminal keeps its own token path: the query passes unchanged.
    expect(new URL((sent[0] as Request).url).searchParams.get("token")).toBe(tokens[0]);
    expect(new URL((sent[1] as Request).url).searchParams.get("token")).toBe(tokens[1]);
  });

  it("staging- hosts get the verified token in X-DY-Session-Token too (from the cookie, and from a non-GET ?token=)", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "staging-hdr-f.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("hdr-f", { purpose: "staging" }));
    const viaCookie = await gate.fetch(
      new Request(`https://${host}/wp-admin/`, {
        headers: { cookie: `__Host-dy_egt=${token}; wordpress_test_cookie=1`, "sec-fetch-site": "same-origin", "x-dy-session-token": "forged" },
      }),
      gateEnv(minter),
    );
    expect(viaCookie.status).toBe(200);
    const viaQuery = await gate.fetch(
      new Request(`https://${host}/wp-admin/admin-ajax.php?token=${token}&action=x`, {
        method: "POST",
        body: "a=1",
        headers: { "x-dy-session-token": "forged" },
      }),
      gateEnv(minter),
    );
    expect(viaQuery.status).toBe(200);
    expect(sent).toHaveLength(2);
    expect((sent[0] as Request).headers.get("x-dy-session-token")).toBe(token);
    expect((sent[0] as Request).headers.get("cookie")).toBe("wordpress_test_cookie=1");
    expect((sent[1] as Request).headers.get("x-dy-session-token")).toBe(token);
    expect((sent[1] as Request).url).toBe(`https://staging-hdr-f${RUN_URL_SUFFIX}/wp-admin/admin-ajax.php?action=x`);
    expect(await (sent[1] as Request).text()).toBe("a=1");
  });

  it("a WebSocket upgrade on a term- host also loses a client-sent X-DY-Session-Token", async () => {
    const minter = okMinter();
    const sent = mockOrigin(() => new Response(null, { status: 200 }));
    const host = "term-hdr-d.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("hdr-d"));
    await gate.fetch(
      new Request(`https://${host}/ws?token=${token}`, {
        headers: { upgrade: "websocket", connection: "Upgrade", origin: `https://${host}`, "x-dy-session-token": "forged" },
      }),
      gateEnv(minter),
    );
    expect(sent).toHaveLength(1);
    expect((sent[0] as Request).headers.get("x-dy-session-token")).toBeNull();
  });

  it("an invalid token on a pma- host is still a 401 at the edge: no minter call, no origin fetch", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "pma-hdr-e.sbmstudio.com.au";
    const terminalToken = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("hdr-e"));
    for (const request of [
      new Request(`https://${host}/`, { headers: { "x-dy-session-token": terminalToken } }),
      new Request(`https://${host}/?token=${terminalToken}`),
    ]) {
      const response = await gate.fetch(request, gateEnv(minter));
      expect(response.status).toBe(401);
    }
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });
});

describe("session gate v2: a ?token= that does not verify counts as no token (phpMyAdmin's own CSRF token)", () => {
  // phpMyAdmin's GET forms and links carry its own CSRF `token`. Such a request is COOKIE-ONLY: the cookie
  // must verify, and Sec-Fetch-Site must be same-origin or none.
  const CSRF_LIKE = "4a7b2c9d8e1f0a3b6c5d4e7f8a9b0c1d";

  it("serves ?token=<csrf-like> with a valid cookie from this host's own page, keeps the CSRF token, and sets no cookie", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const cases: Array<{ label: string; purpose: string; header: boolean }> = [
      { label: "pma-csrf-a", purpose: "pma", header: true },
      { label: "spma-csrf-a", purpose: "pma", header: true },
      { label: "staging-csrf-a", purpose: "staging", header: true },
      { label: "term-csrf-a", purpose: "terminal", header: false },
    ];
    for (const testCase of cases) {
      const host = `${testCase.label}.sbmstudio.com.au`;
      const cookieToken = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("csrf-a", { purpose: testCase.purpose }));
      for (const fetchSite of ["same-origin", "none"]) {
        const response = await gate.fetch(
          new Request(`https://${host}/index.php?route=/database/structure&db=wp&token=${CSRF_LIKE}`, {
            headers: { cookie: `__Host-dy_egt=${cookieToken}`, "sec-fetch-site": fetchSite },
          }),
          gateEnv(minter),
        );
        expect(response.status, `${testCase.label} ${fetchSite}`).toBe(200);
        expect(response.headers.get("set-cookie"), testCase.label).toBeNull();
      }
      const forwarded = sent[sent.length - 1] as Request;
      // The CSRF token is not the session token, so it passes to the container unchanged.
      expect(forwarded.url, testCase.label).toBe(`https://${testCase.label}${RUN_URL_SUFFIX}/index.php?route=/database/structure&db=wp&token=${CSRF_LIKE}`);
      if (testCase.header) {
        expect(forwarded.headers.get("x-dy-session-token"), testCase.label).toBe(cookieToken);
      } else {
        expect(forwarded.headers.get("x-dy-session-token"), testCase.label).toBeNull();
      }
    }
    expect(sent).toHaveLength(8);
  });

  it("401s the same ?token=<csrf-like> request from another site, a sibling host or with no Sec-Fetch-Site: no minter call, no fetch", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    for (const [label, purpose] of [
      ["pma-csrf-b", "pma"],
      ["staging-csrf-b", "staging"],
      ["term-csrf-b", "terminal"],
    ] as const) {
      const host = `${label}.sbmstudio.com.au`;
      const cookieToken = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("csrf-b", { purpose }));
      for (const fetchSite of ["cross-site", "same-site", null]) {
        const headers: Record<string, string> = { cookie: `__Host-dy_egt=${cookieToken}` };
        if (fetchSite !== null) {
          headers["sec-fetch-site"] = fetchSite;
        }
        for (const query of [`?token=${CSRF_LIKE}`, "?token=junk", "?token=", `?db=wp&token=${CSRF_LIKE}`]) {
          const response = await gate.fetch(new Request(`https://${host}/index.php${query}`, { headers }), gateEnv(minter));
          expect(response.status, `${label} ${String(fetchSite)} ${query}`).toBe(401);
        }
      }
    }
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it("401s a ?token= that does not verify when there is no valid cookie, even from this host's own page", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "pma-csrf-c.sbmstudio.com.au";
    const otherHostToken = await signSessionToken(CELL_A_V1_SECRET, "pma-other.sbmstudio.com.au", terminalClaims("other", { purpose: "pma" }));
    for (const cookie of [null, "__Host-dy_egt=junk", `__Host-dy_egt=${otherHostToken}`]) {
      const headers: Record<string, string> = { "sec-fetch-site": "same-origin" };
      if (cookie !== null) {
        headers.cookie = cookie;
      }
      const response = await gate.fetch(new Request(`https://${host}/?token=${CSRF_LIKE}`, { headers }), gateEnv(minter));
      expect(response.status, String(cookie)).toBe(401);
    }
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it("never sets a cookie from a ?token= that does not verify, even a token valid for another host", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "pma-csrf-d.sbmstudio.com.au";
    const cookieToken = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("csrf-d", { purpose: "pma" }));
    const otherHostToken = await signSessionToken(CELL_A_V1_SECRET, "pma-other.sbmstudio.com.au", terminalClaims("other", { purpose: "pma" }));
    const response = await gate.fetch(
      new Request(`https://${host}/?token=${otherHostToken}`, { headers: { cookie: `__Host-dy_egt=${cookieToken}`, "sec-fetch-site": "same-origin" } }),
      gateEnv(minter),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toBeNull();
    expect((sent[0] as Request).headers.get("x-dy-session-token")).toBe(cookieToken);
  });

  it("a ?token= that verifies wins over a valid older cookie, and replaces it", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "pma-csrf-e.sbmstudio.com.au";
    const olderToken = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("csrf-e", { purpose: "pma", uid: 1 }));
    const freshToken = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("csrf-e", { purpose: "pma", uid: 2 }));
    const response = await gate.fetch(
      new Request(`https://${host}/?token=${freshToken}`, { headers: { cookie: `__Host-dy_egt=${olderToken}`, "sec-fetch-site": "cross-site" } }),
      gateEnv(minter),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toMatch(new RegExp(`^__Host-dy_egt=${freshToken.replace(/[.]/g, "\\.")};`));
    expect((sent[0] as Request).headers.get("x-dy-session-token")).toBe(freshToken);
  });

  it("a WebSocket with ?token=<junk> rides on a valid cookie only with this host's Origin", async () => {
    const minter = okMinter();
    const upgradeAnswer = new Response(null, { status: 200 });
    const sent = mockOrigin(() => upgradeAnswer);
    const host = "term-csrf-f.sbmstudio.com.au";
    const cookieToken = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("csrf-f"));
    const headers = { upgrade: "websocket", connection: "Upgrade", cookie: `__Host-dy_egt=${cookieToken}` };
    const served = await gate.fetch(new Request(`https://${host}/ws?token=junk`, { headers: { ...headers, origin: `https://${host}` } }), gateEnv(minter));
    expect(served).toBe(upgradeAnswer);
    const refused = await gate.fetch(new Request(`https://${host}/ws?token=junk`, { headers: { ...headers, origin: "https://evil.example" } }), gateEnv(minter));
    expect(refused.status).toBe(401);
    expect(sent).toHaveLength(1);
  });
});

describe("session gate v2: a verified ?token= leaves the origin's query on pma-, spma- and staging- hosts", () => {
  it("removes only the first `token` parameter and keeps every other parameter's bytes and order", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "pma-strip-a.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("strip-a", { purpose: "pma" }));
    const cases: Array<{ query: string; forwarded: string }> = [
      { query: `?token=${token}`, forwarded: "" },
      { query: `?route=/sql&token=${token}&db=wp`, forwarded: "?route=/sql&db=wp" },
      { query: `?a=%7E&token=${token}&b=x+y&c`, forwarded: "?a=%7E&b=x+y&c" },
      { query: `?token=${token}&token=csrf-own`, forwarded: "?token=csrf-own" },
      { query: `?&token=${token}&&a=1&`, forwarded: "?a=1" },
      // The same decoding as url.searchParams: a percent-encoded name is still `token`.
      { query: `?tok%65n=${token}&a=1`, forwarded: "?a=1" },
    ];
    for (const testCase of cases) {
      const response = await gate.fetch(new Request(`https://${host}/index.php${testCase.query}`), gateEnv(minter));
      expect(response.status, testCase.query).toBe(200);
      expect((sent[sent.length - 1] as Request).url, testCase.query).toBe(`https://pma-strip-a${RUN_URL_SUFFIX}/index.php${testCase.forwarded}`);
    }
  });

  it("spma- and a staging- WebSocket lose it too; term- and sterm- keep it (the terminal reads only the query)", async () => {
    const minter = okMinter();
    const sent = mockOrigin(() => new Response(null, { status: 200 }));
    const cases: Array<{ label: string; purpose: string; webSocket: boolean; keeps: boolean }> = [
      { label: "spma-strip-b", purpose: "pma", webSocket: false, keeps: false },
      { label: "staging-strip-b", purpose: "staging", webSocket: true, keeps: false },
      { label: "term-strip-b", purpose: "terminal", webSocket: false, keeps: true },
      { label: "sterm-strip-b", purpose: "terminal", webSocket: true, keeps: true },
    ];
    for (const testCase of cases) {
      const host = `${testCase.label}.sbmstudio.com.au`;
      const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("strip-b", { purpose: testCase.purpose }));
      const headers: Record<string, string> = {};
      if (testCase.webSocket) {
        headers.upgrade = "websocket";
        headers.connection = "Upgrade";
        headers.origin = `https://${host}`;
      }
      await gate.fetch(new Request(`https://${host}/x?token=${token}&k=v`, { headers }), gateEnv(minter));
      const forwardedQuery = new URL((sent[sent.length - 1] as Request).url).search;
      if (testCase.keeps) {
        expect(forwardedQuery, testCase.label).toBe(`?token=${token}&k=v`);
      } else {
        expect(forwardedQuery, testCase.label).toBe("?k=v");
      }
    }
    expect(sent).toHaveLength(4);
  });
});

/** Decode the five entities the gate's escapeHtmlAttribute writes. */
function decodeHtmlAttribute(text: string): string {
  return text.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

async function cspHashOf(scriptText: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(scriptText)));
  return `'sha256-${Buffer.from(digest).toString("base64")}'`;
}

describe("session gate v2: the staging token-strip page (DS5)", () => {
  const STRIP_SCRIPT = 'location.replace(document.getElementById("next").href);';

  it("answers a staging- GET with a verified ?token= with the page and the cookie: no minter call, no origin fetch", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-31T00:00:00.000Z"));
    const nowSeconds = Math.floor(Date.now() / 1000);
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "staging-page-a.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("page-a", { purpose: "staging", exp: nowSeconds + 3600 }));
    const response = await gate.fetch(
      new Request(`https://${host}/wp-admin/edit.php?token=${token}&post_type=page`, {
        headers: { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
      }),
      gateEnv(minter),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("set-cookie")).toBe(`__Host-dy_egt=${token}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax`);
    expect(response.headers.get("content-security-policy")).toBe(
      `default-src 'none'; script-src ${await cspHashOf(STRIP_SCRIPT)}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    );
    const body = await response.text();
    expect(body).toBe(
      "<!doctype html><meta charset=utf-8><title>Opening staging</title>" +
        `<a id="next" href="https://${host}/wp-admin/edit.php?post_type=page">Continue</a>` +
        `<script>${STRIP_SCRIPT}</script>`,
    );
    // The page itself never carries the token, and loads nothing.
    expect(body).not.toContain(token);
    expect(body).not.toMatch(/\bsrc=/);
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it("the page's next request (same-origin, the cookie, no token) reaches the origin with the token in X-DY-Session-Token", async () => {
    const minter = okMinter();
    const sent = mockOrigin(() => new Response("<html>wp-admin</html>", { headers: { "content-type": "text/html" } }));
    const host = "staging-page-b.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("page-b", { purpose: "staging" }));
    const page = await gate.fetch(new Request(`https://${host}/?token=${token}`, { headers: { "sec-fetch-site": "cross-site" } }), gateEnv(minter));
    const cookiePair = (page.headers.get("set-cookie") as string).split(";")[0] as string;
    const nextUrl = decodeHtmlAttribute(/href="([^"]*)"/.exec(await page.text())?.[1] as string);
    expect(nextUrl).toBe(`https://${host}/`);

    const next = await gate.fetch(
      new Request(nextUrl, { headers: { cookie: cookiePair, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate" } }),
      gateEnv(minter),
    );
    expect(next.status).toBe(200);
    expect(await next.text()).toBe("<html>wp-admin</html>");
    expect(next.headers.get("set-cookie")).toBeNull();
    expect(sent).toHaveLength(1);
    const forwarded = sent[0] as Request;
    expect(forwarded.url).toBe(`https://staging-page-b${RUN_URL_SUFFIX}/`);
    expect(forwarded.headers.get("x-dy-session-token")).toBe(token);
    expect(forwarded.headers.get("cookie")).toBeNull();
  });

  it("HEAD gets the page too; POST, a WebSocket and the other hosts do not", async () => {
    const minter = okMinter();
    const sent = mockOrigin(() => new Response(null, { status: 200, headers: { "x-origin": "1" } }));
    const host = "staging-page-c.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("page-c", { purpose: "staging" }));
    const head = await gate.fetch(new Request(`https://${host}/?token=${token}`, { method: "HEAD" }), gateEnv(minter));
    expect(head.headers.get("content-security-policy")).not.toBeNull();
    expect(sent).toHaveLength(0);

    const post = await gate.fetch(new Request(`https://${host}/wp-login.php?token=${token}`, { method: "POST", body: "log=a" }), gateEnv(minter));
    expect(post.headers.get("x-origin")).toBe("1");
    expect(post.headers.get("set-cookie")).not.toBeNull();
    const socket = await gate.fetch(
      new Request(`https://${host}/ws?token=${token}`, { headers: { upgrade: "websocket", connection: "Upgrade", origin: `https://${host}` } }),
      gateEnv(minter),
    );
    expect(socket.headers.get("x-origin")).toBe("1");
    for (const [label, purpose] of [
      ["pma-page-c", "pma"],
      ["spma-page-c", "pma"],
      ["term-page-c", "terminal"],
      ["sterm-page-c", "terminal"],
    ] as const) {
      const otherHost = `${label}.sbmstudio.com.au`;
      const otherToken = await signSessionToken(CELL_A_V1_SECRET, otherHost, terminalClaims("page-c", { purpose }));
      const response = await gate.fetch(new Request(`https://${otherHost}/?token=${otherToken}`), gateEnv(minter));
      expect(response.headers.get("x-origin"), label).toBe("1");
      expect(response.headers.get("content-security-policy"), label).toBeNull();
    }
    expect(sent).toHaveLength(6);
  });

  it("the next URL is absolute on this host, and escaped: a path cannot send the browser elsewhere", async () => {
    const minter = okMinter();
    mockOrigin();
    const host = "staging-page-d.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("page-d", { purpose: "staging" }));
    const cases: Array<{ path: string; next: string }> = [
      { path: `//evil.example/?token=${token}`, next: `https://${host}//evil.example/` },
      { path: `/a'b/?x=1&token=${token}&y=2`, next: `https://${host}/a'b/?x=1&y=2` },
      { path: `/%22%3E%3Cscript%3E?token=${token}`, next: `https://${host}/%22%3E%3Cscript%3E` },
    ];
    for (const testCase of cases) {
      const response = await gate.fetch(new Request(`https://${host}${testCase.path}`), gateEnv(minter));
      const body = await response.text();
      const rawHref = /<a id="next" href="([^"]*)">/.exec(body)?.[1] as string;
      expect(rawHref, testCase.path).not.toMatch(/['<>]/);
      const nextUrl = decodeHtmlAttribute(rawHref);
      expect(nextUrl, testCase.path).toBe(testCase.next);
      expect(new URL(nextUrl).host, testCase.path).toBe(host);
      // Exactly one script element: the constant one.
      expect(body.match(/<script>/g), testCase.path).toHaveLength(1);
      expect(body.endsWith(`<script>${STRIP_SCRIPT}</script>`), testCase.path).toBe(true);
    }
  });

  it("a staging- ?token= that does not verify gets no page: the cookie-only rule decides", async () => {
    const minter = okMinter();
    const sent = mockOrigin();
    const host = "staging-page-e.sbmstudio.com.au";
    const cookieToken = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("page-e", { purpose: "staging" }));
    const crossSite = await gate.fetch(
      new Request(`https://${host}/?token=junk`, { headers: { cookie: `__Host-dy_egt=${cookieToken}`, "sec-fetch-site": "cross-site" } }),
      gateEnv(minter),
    );
    expect(crossSite.status).toBe(401);
    const sameOrigin = await gate.fetch(
      new Request(`https://${host}/?token=junk`, { headers: { cookie: `__Host-dy_egt=${cookieToken}`, "sec-fetch-site": "same-origin" } }),
      gateEnv(minter),
    );
    expect(sameOrigin.status).toBe(200);
    expect(sameOrigin.headers.get("content-security-policy")).toBeNull();
    expect(sameOrigin.headers.get("set-cookie")).toBeNull();
    expect(sent).toHaveLength(1);
    expect((sent[0] as Request).url).toBe(`https://staging-page-e${RUN_URL_SUFFIX}/?token=junk`);
  });
});

describe("session gate v2: version skew (review M1)", () => {
  /** An agency Worker rolled back below gate v2 (c0a9586): its minter reads only a bare audience string. */
  function rolledBackMinter(): FakeMinter {
    return {
      mintIdToken: vi.fn(async (request: unknown) => {
        // c0a9586 parseSessionGateAudience: typeof audience !== "string" -> null -> "audience-refused".
        if (typeof request !== "string") {
          return { ok: false, reason: "audience-refused" };
        }
        return { ok: true, idToken: `id-token-for:${request}`, expiresAt: Math.floor(Date.now() / 1000) + 3600 };
      }),
    };
  }

  it("term- and sterm- ask once more with the bare audience, and open", async () => {
    for (const label of ["term-skew-a", "sterm-skew-a"]) {
      const minter = rolledBackMinter();
      const sent = mockOrigin();
      const host = `${label}.sbmstudio.com.au`;
      const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("skew-a"));
      const response = await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter));
      expect(response.status, label).toBe(200);
      const audience = `https://${label}${RUN_URL_SUFFIX}`;
      expect(minter.mintIdToken).toHaveBeenCalledTimes(2);
      expect(minter.mintIdToken.mock.calls[0]?.[0]).toMatchObject({ audience });
      expect(minter.mintIdToken.mock.calls[1]?.[0]).toBe(audience);
      expect(sent).toHaveLength(1);
      expect((sent[0] as Request).headers.get("x-serverless-authorization")).toBe(`Bearer id-token-for:${audience}`);
    }
  });

  it("pma-, spma- and staging- never ask without the proof: a bare 503, one minter call, no origin fetch", async () => {
    for (const [label, purpose] of [
      ["pma-skew-b", "pma"],
      ["spma-skew-b", "pma"],
      ["staging-skew-b", "staging"],
    ] as const) {
      const minter = rolledBackMinter();
      const sent = mockOrigin();
      const host = `${label}.sbmstudio.com.au`;
      const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("skew-b", { purpose }));
      // A cookie-only request from the host's own page, so a staging- host reaches the minter (a GET with
      // ?token= would get the token-strip page and no minter call).
      const response = await gate.fetch(
        new Request(`https://${host}/`, { headers: { cookie: `__Host-dy_egt=${token}`, "sec-fetch-site": "same-origin" } }),
        gateEnv(minter),
      );
      expect(response.status, label).toBe(503);
      expect(minter.mintIdToken, label).toHaveBeenCalledTimes(1);
      expect(typeof minter.mintIdToken.mock.calls[0]?.[0], label).toBe("object");
      expect(sent, label).toHaveLength(0);
    }
  });

  it("a term- host does NOT ask again after caller-refused, unavailable, a garbage answer or a dropped call", async () => {
    const answers: Array<() => Promise<unknown>> = [
      async () => ({ ok: false, reason: "caller-refused" }),
      async () => ({ ok: false, reason: "unavailable" }),
      async () => ({ ok: false }),
      async () => null,
      async () => {
        throw new Error("RPC dropped");
      },
    ];
    let index = 0;
    for (const answer of answers) {
      index += 1;
      const minter: FakeMinter = { mintIdToken: vi.fn(answer) };
      const sent = mockOrigin();
      const host = `term-skew-c${index}.sbmstudio.com.au`;
      const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims(`skew-c${index}`));
      const response = await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter));
      expect(response.status, String(index)).toBe(503);
      expect(minter.mintIdToken, String(index)).toHaveBeenCalledTimes(1);
      expect(sent).toHaveLength(0);
    }
  });

  it("asks only once more: a second audience-refused is a 503", async () => {
    const minter: FakeMinter = { mintIdToken: vi.fn(async () => ({ ok: false, reason: "audience-refused" })) };
    const sent = mockOrigin();
    const host = "term-skew-d.sbmstudio.com.au";
    const token = await signSessionToken(CELL_A_V1_SECRET, host, terminalClaims("skew-d"));
    const response = await gate.fetch(new Request(`https://${host}/?token=${token}`), gateEnv(minter));
    expect(response.status).toBe(503);
    expect(minter.mintIdToken).toHaveBeenCalledTimes(2);
    expect(sent).toHaveLength(0);
  });
});
