// planning/49 Phase 3 (I4), decision A: the SessionGateMinter (src/session-gate/minter.ts and the named
// entrypoint in src/index.ts). It mints Google ID tokens from the agency's own key ONLY for this project's
// session service URLs, and says nothing but a reason code when it does not.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env.js";
import { mintSessionGateIdToken, parseSessionGateAudience, readProjectNumber } from "../src/session-gate/minter.js";
import { SessionGateMinter } from "../src/index.js";

const PROJECT_NUMBER = "123456789012";
const REGION = "australia-southeast2";

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
});

/** An Env whose service-account key belongs to `projectId`. Each test uses its own project, because the
 *  minter caches project numbers per isolate. */
function envForProject(projectId: string): Env {
  return {
    APP_BASE_URL: "https://app.example.test",
    DY_CLIENT_ID: "client-abc",
    DY_CLIENT_SECRET: "secret-xyz",
    NONCE_STORE: undefined as unknown as Env["NONCE_STORE"],
    GCP_SERVICE_ACCOUNT_KEY: JSON.stringify({
      type: "service_account",
      project_id: projectId,
      private_key: privateKeyPem,
      client_email: `sa@${projectId}.iam.gserviceaccount.com`,
      token_uri: "https://oauth2.googleapis.com/token",
    }),
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
}

/** Mock Google: the token endpoint (access or ID token by the assertion) and projects.get. */
function mockGoogle(options: GoogleMockOptions) {
  const calls: Array<{ url: string; method: string; scope?: unknown; targetAudience?: unknown }> = [];
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
      calls.push({ url, method });
      if (url === `https://cloudresourcemanager.googleapis.com/v1/projects/${options.projectId}`) {
        if (options.projectsGetStatus !== undefined && options.projectsGetStatus !== 200) {
          return Response.json({ error: { message: "permission denied on resource" } }, { status: options.projectsGetStatus });
        }
        return Response.json({ projectId: options.projectId, projectNumber: options.projectNumber ?? PROJECT_NUMBER });
      }
      throw new Error(`unexpected fetch ${url}`);
    }),
  );
  return calls;
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
    await mintSessionGateIdToken(env, `https://pma-b-${PROJECT_NUMBER}.australia-southeast1.run.app`);
    const projectReads = calls.filter((call) => call.url.startsWith("https://cloudresourcemanager.googleapis.com/"));
    expect(projectReads).toHaveLength(1);
  });

  it("refuses a malformed audience before any network call", async () => {
    const env = envForProject("dy-minter-shape");
    const calls = mockGoogle({ projectId: "dy-minter-shape" });
    for (const audience of ["https://evil.example", `https://term-x-${PROJECT_NUMBER}.${REGION}.run.app/`, 7]) {
      expect(await mintSessionGateIdToken(env, audience)).toEqual({ ok: false, reason: "audience-refused" });
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
  it("answers over its one RPC method with the minter's result", async () => {
    const env = envForProject("dy-minter-entrypoint");
    mockGoogle({ projectId: "dy-minter-entrypoint" });
    const minter = new SessionGateMinter({} as never, env);
    expect(await minter.mintIdToken("https://evil.example")).toEqual({ ok: false, reason: "audience-refused" });
    const minted = await minter.mintIdToken(`https://term-x-${PROJECT_NUMBER}.${REGION}.run.app`);
    expect(minted.ok).toBe(true);
  });
});
