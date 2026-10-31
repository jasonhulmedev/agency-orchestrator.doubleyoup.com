// planning/49 Phase 3 (I4): the session gate and its minter under the REAL workerd runtime (the "workers"
// project in vitest.config.ts).
//
// Two things only workerd can show:
//   • the gate's Web Crypto (HKDF, HMAC), btoa/atob and Request forwarding behave in workerd as under Node
//     (the I2 vectors again);
//   • the SessionGateMinter named entrypoint answers over workerd RPC. `exports.SessionGateMinter` (ctx.exports,
//     on by compatibility date 2025-11-17) is a loopback service binding to that entrypoint: the same kind of
//     binding edge-gate-deploy gives the gate as DY_MINTER, here to this Worker's own main module.
// The test env has no GCP_SERVICE_ACCOUNT_KEY, so the minter never reaches Google: a refused audience, a refused
// caller and an unavailable mint are the answers it can give here, and each proves the RPC path.
//
// planning/49 Phase 4 (I3): the transition rule over REAL workerd RPC. A call with no caller proof (what any
// other script that binds the minter can send, and what a v1 gate sends) is refused for pma-, spma- and
// staging-, and a v2 gate's { audience, ts, mac } object crosses the binding intact. The staging token-strip
// page (its CSP hash, its cookie) and the pma- query strip run here too.

import { exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import gate, { deriveHostKey, verifyToken } from "../src/session-gate/gate.js";
import type { SessionGateEnv } from "../src/session-gate/gate.js";
import type { SessionGateMintResult } from "../src/session-gate/minter.js";

interface MinterBinding {
  mintIdToken(audience: unknown): Promise<SessionGateMintResult>;
}

// ctx.exports is typed by `wrangler types`, which this repo does not generate; name the one entrypoint used.
const minterBinding = (exports as unknown as { SessionGateMinter: MinterBinding }).SessionGateMinter;

const CELL_A_V1_SECRET = "603807493e9f841f3f587631aad45bc075fa1cc8ec73adba4872405dc05ba367";
const CELL_A_V1_TERM_DOCS_HOST_KEY = "O7kn2G9wDF-pw1Lk7t6Czb5_OiclM_Y_2mY_zYYBYRs";
const CELL_A_V1_CHAIN_TOKEN =
  "eyJzaXRlSWQiOiJzaXRlX3Rlc3RfMSIsInNsdWciOiJkb2NzLTg5Mjc2OSIsInB1cnBvc2UiOiJ0ZXJtaW5hbCIsInVpZCI6MTE5MDc2LCJleHAiOjQxMDI0NDQ4MDB9.KPl03eKG2FrOdwSKC6wYVlNDrftjrNQeqqDMNk7L2wE";
const RUN_URL_SUFFIX = "-123456789012.australia-southeast2.run.app";
// A gate's minter caller key (64 lowercase hex), as edge-gate-deploy binds it.
const MINTER_CALLER_KEY_HEX = "7b1eab777358b371e6e62d42117d5919b44e8e442605f2e9690861b9574abc77";

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A v1 session token for `host`, signed with the host key (Web Crypto: this file runs in workerd). */
async function signTerminalToken(host: string, slug: string, purpose = "terminal"): Promise<string> {
  const claims = { siteId: "site_test_1", slug, purpose, uid: 119076, exp: 4102444800 };
  const payload = bytesToBase64url(new TextEncoder().encode(JSON.stringify(claims)));
  const hostKey = await deriveHostKey(CELL_A_V1_SECRET, host);
  const key = await crypto.subtle.importKey("raw", hostKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
  return `${payload}.${bytesToBase64url(signature)}`;
}

function gateEnv(minter: unknown): SessionGateEnv {
  return {
    DY_SESSION_SECRET: CELL_A_V1_SECRET,
    DY_ZONE_SUFFIX: ".doubleyoup.com",
    DY_RUN_URL_SUFFIX: RUN_URL_SUFFIX,
    DY_MINTER: minter as SessionGateEnv["DY_MINTER"],
    DY_MINTER_CALLER_KEY: MINTER_CALLER_KEY_HEX,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("session gate under workerd", () => {
  it("derives cell A's v1 host key and verifies the I2 chain token", async () => {
    const hostKey = await deriveHostKey(CELL_A_V1_SECRET, "term-docs-892769.doubleyoup.com");
    expect(bytesToBase64url(hostKey)).toBe(CELL_A_V1_TERM_DOCS_HOST_KEY);
    expect(await verifyToken(CELL_A_V1_CHAIN_TOKEN, hostKey, "terminal", "docs-892769")).toMatchObject({ slug: "docs-892769", uid: 119076 });
    expect(await verifyToken(CELL_A_V1_CHAIN_TOKEN, hostKey, "pma", "docs-892769")).toBeNull();
  });

  it("forwards a valid request with its method, body and query to the run.app origin", async () => {
    const minter = { mintIdToken: vi.fn(async () => ({ ok: true, idToken: "id-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 })) };
    const sent: Request[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      sent.push(input as Request);
      return new Response("origin");
    });
    const response = await gate.fetch(
      new Request(`https://term-docs-892769.doubleyoup.com/api?token=${CELL_A_V1_CHAIN_TOKEN}`, {
        method: "POST",
        body: "payload",
        headers: { cookie: "__Host-dy_egt=old; keep=1", authorization: "Bearer client" },
      }),
      gateEnv(minter),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toMatch(/^__Host-dy_egt=.+; Path=\/; Max-Age=\d+; HttpOnly; Secure; SameSite=Lax$/);
    const forwarded = sent[0] as Request;
    expect(forwarded.url).toBe(`https://term-docs-892769${RUN_URL_SUFFIX}/api?token=${CELL_A_V1_CHAIN_TOKEN}`);
    expect(forwarded.method).toBe("POST");
    expect(await forwarded.text()).toBe("payload");
    expect(forwarded.headers.get("x-serverless-authorization")).toBe("Bearer id-token");
    expect(forwarded.headers.get("authorization")).toBe("Bearer client");
    // A terminal host forwards no Cookie header at all.
    expect(forwarded.headers.get("cookie")).toBeNull();
  });

  it("answers a staging- GET with a verified ?token= with the token-strip page: its CSP hash, its cookie, no fetch", async () => {
    const minter = { mintIdToken: vi.fn(async () => ({ ok: false, reason: "unavailable" })) };
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      throw new Error("no origin fetch is allowed in this test");
    });
    const host = "staging-docs-892769.doubleyoup.com";
    const token = await signTerminalToken(host, "docs-892769", "staging");
    const response = await gate.fetch(new Request(`https://${host}/wp-admin/?token=${token}&a=1`), gateEnv(minter));
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toMatch(/^__Host-dy_egt=.+; Path=\/; Max-Age=\d+; HttpOnly; Secure; SameSite=Lax$/);
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    const body = await response.text();
    expect(body).toContain(`href="https://${host}/wp-admin/?a=1"`);
    const script = /<script>(.*)<\/script>/.exec(body)?.[1] as string;
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(script)));
    let binary = "";
    for (const byte of digest) {
      binary += String.fromCharCode(byte);
    }
    expect(response.headers.get("content-security-policy")).toContain(`script-src 'sha256-${btoa(binary)}';`);
    expect(minter.mintIdToken).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("forwards a pma- request without the verified ?token=, and with it in X-DY-Session-Token", async () => {
    const minter = { mintIdToken: vi.fn(async () => ({ ok: true, idToken: "id-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 })) };
    const sent: Request[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      sent.push(input as Request);
      return new Response("origin");
    });
    const host = "pma-docs-892769.doubleyoup.com";
    const token = await signTerminalToken(host, "docs-892769", "pma");
    const response = await gate.fetch(new Request(`https://${host}/index.php?route=/&token=${token}&db=x`), gateEnv(minter));
    expect(response.status).toBe(200);
    const forwarded = sent[0] as Request;
    expect(forwarded.url).toBe(`https://pma-docs-892769${RUN_URL_SUFFIX}/index.php?route=/&db=x`);
    expect(forwarded.headers.get("x-dy-session-token")).toBe(token);
  });
});

describe("SessionGateMinter over workerd RPC", () => {
  it("refuses an audience that is not one of this project's session URLs", async () => {
    expect(await minterBinding.mintIdToken("https://evil.example")).toEqual({ ok: false, reason: "audience-refused" });
    expect(await minterBinding.mintIdToken(`https://term-x${RUN_URL_SUFFIX}/`)).toEqual({ ok: false, reason: "audience-refused" });
  });

  it("is unavailable, with no detail, when this Worker has no service-account key", async () => {
    expect(await minterBinding.mintIdToken(`https://term-x${RUN_URL_SUFFIX}`)).toEqual({ ok: false, reason: "unavailable" });
  });

  it("refuses a call with NO caller proof for pma-, spma- and staging- (the transition rule), and lets term- and sterm- through it", async () => {
    for (const prefix of ["pma", "spma", "staging"]) {
      expect(await minterBinding.mintIdToken(`https://${prefix}-x${RUN_URL_SUFFIX}`), prefix).toEqual({ ok: false, reason: "caller-refused" });
    }
    // term- and sterm- pass the caller check without a proof; this Worker then has no key to mint with.
    for (const prefix of ["term", "sterm"]) {
      expect(await minterBinding.mintIdToken(`https://${prefix}-x${RUN_URL_SUFFIX}`), prefix).toEqual({ ok: false, reason: "unavailable" });
    }
  });

  it("takes a v2 { audience, ts, mac } object over RPC without an error", async () => {
    // The object crosses the binding and goes to the proof check. With no service-account key here the minter
    // cannot check a proof, so the answer is "unavailable" (test/session-gate-minter.test.ts checks the proof
    // itself, and that an object never falls back to the keyless rule, under Node).
    const ts = Math.floor(Date.now() / 1000);
    for (const prefix of ["term", "pma"]) {
      const proof = { audience: `https://${prefix}-x${RUN_URL_SUFFIX}`, ts, mac: "A".repeat(43) };
      expect(await minterBinding.mintIdToken(proof), prefix).toEqual({ ok: false, reason: "unavailable" });
    }
  });

  it("is the gate's DY_MINTER: a valid session gets a bare 503 when no ID token can be minted, and no origin fetch", async () => {
    // A host no other test used, so the gate's per-isolate ID token cache holds nothing for it. Any fetch
    // here would be a bug, so the mock fails loudly instead of reaching the network.
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      throw new Error("no origin fetch is allowed in this test");
    });
    const token = await signTerminalToken("term-rpc-check.doubleyoup.com", "rpc-check");
    const response = await gate.fetch(new Request(`https://term-rpc-check.doubleyoup.com/?token=${token}`), gateEnv(minterBinding));
    expect(response.status).toBe(503);
    expect(await response.text()).toBe("session gateway unavailable");
    expect(fetchSpy).not.toHaveBeenCalled();
    // An invalid token never reaches the minter or the origin.
    const unauthorized = await gate.fetch(new Request("https://term-docs-892769.doubleyoup.com/?token=bad"), gateEnv(minterBinding));
    expect(unauthorized.status).toBe(401);
  });
});
