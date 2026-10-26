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

// What each gate version IS: the sha256 of gate.js and the compatibility date it is uploaded with
// (SESSION_GATE_COMPATIBILITY_DATE in src/actuate-edge-gate.ts).
//
// A CHANGE TO gate.js OR TO THE COMPATIBILITY DATE NEEDS A NEW MARKER VERSION: raise the number on gate.js's
// first line and ADD an entry here. Never make this test pass by editing the hash or the date of an
// existing version. edge-gate-deploy compares the deployed source byte for byte, so a same-version change
// would still deploy, but it refuses to put a LOWER version over a higher one: two different gates under
// one version number would make that downgrade guard compare the wrong things.
//
// v1 is not released yet (planning/49 I6 deploys it first), which is why its entry still changes with the
// I4 review fixes. From the first deploy on, the rule above holds without exception.
const GATE_VERSIONS: Record<number, { sha256: string; compatibilityDate: string }> = {
  1: { sha256: "cd5b6e3a661747e5fb4b40713a1fa4b2206cbb6b40ccf35016b54cb04623b5f7", compatibilityDate: "2026-01-01" },
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
    mintIdToken: vi.fn(async (audience: string) => ({
      ok: true,
      idToken: `id-token-for:${audience}`,
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
    DY_SESSION_KEY_VERSION: "1",
    DY_SESSION_KEY_FINGERPRINT: "0123456789abcdef",
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
    expect(minter.mintIdToken).toHaveBeenCalledWith(audience);
    expect(sent).toHaveLength(1);
    const forwarded = sent[0] as Request;
    // Same path and query (the container reads ?token=), same method and body.
    expect(forwarded.url).toBe(`${audience}/static/app.js?token=${token}&x=1`);
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
    expect((sent[0] as Request).url).toBe(`https://pma-flow-j${RUN_URL_SUFFIX}/?token=${token}`);
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
