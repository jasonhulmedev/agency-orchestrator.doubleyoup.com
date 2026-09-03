import { describe, it, expect, vi, afterEach } from "vitest";
import type { Env } from "../src/env.js";
import {
  validateS3,
  validateStripe,
  validateAnthropic,
  validateOpenRouter,
  validateOpenAI,
  validateAI,
  validateGCP,
  validateR2Provision,
} from "../src/validators.js";

// Minimal Env with only the Direction-A fields; each test spreads in the
// service credential(s) it exercises.
const baseEnv: Env = {
  APP_BASE_URL: "https://app.example.test",
  DY_CLIENT_ID: "client-abc",
  DY_CLIENT_SECRET: "secret-xyz",
};

// A fetch mock that dispatches by URL substring. Any unrouted URL throws, so a
// test that accidentally hits the network fails loudly instead of hanging.
interface Route {
  match: (url: string) => boolean;
  respond: () => Response;
}
function routedFetch(routes: Route[]) {
  return vi.fn(async (input: unknown) => {
    const url = String(input);
    for (const route of routes) {
      if (route.match(url)) return route.respond();
    }
    throw new Error(`unexpected fetch to ${url}`);
  });
}

function xmlResponse(inner: string, status: number): Response {
  return new Response(`<?xml version="1.0"?><Error>${inner}</Error>`, { status });
}
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ── S3 ────────────────────────────────────────────────────────────────────────

describe("validateS3", () => {
  const s3Env: Env = {
    ...baseEnv,
    S3_ACCESS_KEY_ID: "AKIAEXAMPLE",
    S3_SECRET_ACCESS_KEY: "secret",
    S3_REGION: "us-east-1",
    S3_BUCKET: "my-bucket",
  };
  const r2Env: Env = {
    ...s3Env,
    S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com",
    S3_REGION: "auto",
  };
  // A genuine S3 PutObject 2xx carries an ETag of the stored object; the write probe requires it.
  function putOk(): Response {
    return new Response("", { status: 200, headers: { etag: '"abc123"' } });
  }

  it("reports not-configured without hitting the network", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3(baseEnv);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/not configured/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("AWS path: PUTs a probe object (never lists) and is ok on 2xx + ETag", async () => {
    const fetchMock = routedFetch([
      { match: (u) => u.includes("my-bucket.s3.us-east-1.amazonaws.com/"), respond: putOk },
    ]);
    vi.stubGlobal("fetch", fetchMock);

    const result = await validateS3(s3Env);
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/writable/);

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.method).toBe("PUT");
    expect(String(url)).toContain("/.doubleyoup-connectivity-probe-");
    expect(String(url)).not.toContain("list-type=2");
    const headers = new Headers(init.headers);
    expect(headers.get("authorization")).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\//);
    expect(headers.get("x-amz-date")).toBeTruthy();
  });

  it("R2/custom endpoint: path-style PUT probe, ok on 2xx + ETag (no bucket list)", async () => {
    const fetchMock = routedFetch([
      {
        match: (u) => u.startsWith("https://acct.r2.cloudflarestorage.com/my-bucket/.doubleyoup-connectivity-probe-"),
        respond: putOk,
      },
    ]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3(r2Env);
    expect(result.ok).toBe(true);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.method).toBe("PUT");
    expect(String(url)).not.toContain("list-type=2");
  });

  // #1 — a non-S3 endpoint (SPA/proxy/health page) answering 200 must NOT false-green.
  it("fails a 2xx WITHOUT an S3 ETag — the #1 false-green guard", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => new Response("hello", { status: 200 }) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3({ ...r2Env, S3_ENDPOINT: "https://not-s3.example.test" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/S3 ETag|S3-compatible/i);
    expect(result.detail).toMatch(/S3_ENDPOINT/);
  });

  // #1 — a redirecting host must be rejected, not silently followed to a 200 page.
  it("fails on a redirect (endpoint is not a direct S3 API)", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => new Response(null, { status: 302 }) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3({ ...r2Env, S3_ENDPOINT: "https://redirects.example.test" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/redirect/i);
  });

  // #1 — a 4xx with no S3 <Code> means the endpoint isn't S3-compatible.
  it("fails a 4xx with no S3 error code (non-S3 endpoint)", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => new Response("Not Found", { status: 404 }) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3({ ...r2Env, S3_ENDPOINT: "https://not-s3.example.test" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/no S3 error code|not be an S3/i);
  });

  // #3 — a read-only key (or a write-blocked bucket) 403s on the PUT and must fail.
  it("fails a 403 AccessDenied on write — #3 (proves write, not read)", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => xmlResponse("<Code>AccessDenied</Code>", 403) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3(r2Env);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/WRITE|Read & Write|PutObject/i);
  });

  it("maps NoSuchBucket to a bucket-check message", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => xmlResponse("<Code>NoSuchBucket</Code>", 404) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3(r2Env);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/NoSuchBucket/);
    expect(result.detail).toMatch(/S3_BUCKET/);
  });

  it("maps InvalidAccessKeyId to a key-specific message", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => xmlResponse("<Code>InvalidAccessKeyId</Code>", 403) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3(r2Env);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/S3_ACCESS_KEY_ID/);
  });

  it("maps SignatureDoesNotMatch to a secret/region message", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => xmlResponse("<Code>SignatureDoesNotMatch</Code>", 403) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3(r2Env);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/SignatureDoesNotMatch/);
    expect(result.detail).toMatch(/S3_SECRET_ACCESS_KEY/);
  });

  it("best-effort deletes the probe object after a successful write", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: putOk }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3(r2Env);
    expect(result.ok).toBe(true);
    // one PUT (the probe) + one DELETE (cleanup)
    expect(fetchMock.mock.calls.length).toBe(2);
    const methods = fetchMock.mock.calls.map((c) => ((c as unknown[])[1] as RequestInit).method);
    expect(methods).toEqual(["PUT", "DELETE"]);
  });
});

// ── Stripe ──────────────────────────────────────────────────────────────────

describe("validateStripe", () => {
  it("reports not-configured", async () => {
    const result = await validateStripe(baseEnv);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/not configured/);
  });

  it("is ok on 200 and reports the account + mode", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch([
        { match: (u) => u === "https://api.stripe.com/v1/account", respond: () => jsonResponse({ id: "acct_123" }) },
      ]),
    );
    const result = await validateStripe({ ...baseEnv, STRIPE_SECRET_KEY: "sk_live_abc" });
    expect(result.ok).toBe(true);
    expect(result.detail).toContain("acct_123");
    expect(result.detail).toContain("live");
  });

  it("reports test mode for a test key", async () => {
    vi.stubGlobal("fetch", routedFetch([{ match: () => true, respond: () => jsonResponse({ id: "acct_t" }) }]));
    const result = await validateStripe({ ...baseEnv, STRIPE_SECRET_KEY: "sk_test_abc" });
    expect(result.ok).toBe(true);
    expect(result.detail).toContain("test");
  });

  it("maps 401 to a key-check message", async () => {
    vi.stubGlobal("fetch", routedFetch([{ match: () => true, respond: () => new Response("", { status: 401 }) }]));
    const result = await validateStripe({ ...baseEnv, STRIPE_SECRET_KEY: "sk_live_bad" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/STRIPE_SECRET_KEY/);
  });
});

// ── AI ──────────────────────────────────────────────────────────────────────

describe("validateAnthropic / validateOpenRouter", () => {
  it("Anthropic ok on 200", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch([{ match: (u) => u.startsWith("https://api.anthropic.com/v1/models"), respond: () => jsonResponse({ data: [] }) }]),
    );
    const result = await validateAnthropic({ ...baseEnv, ANTHROPIC_API_KEY: "sk-ant-x" });
    expect(result.ok).toBe(true);
  });

  it("Anthropic 401 → key-check message", async () => {
    vi.stubGlobal("fetch", routedFetch([{ match: () => true, respond: () => new Response("", { status: 401 }) }]));
    const result = await validateAnthropic({ ...baseEnv, ANTHROPIC_API_KEY: "bad" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/ANTHROPIC_API_KEY/);
  });

  it("OpenRouter ok on 200 with a label", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch([{ match: (u) => u === "https://openrouter.ai/api/v1/key", respond: () => jsonResponse({ data: { label: "prod" } }) }]),
    );
    const result = await validateOpenRouter({ ...baseEnv, OPENROUTER_API_KEY: "or-x" });
    expect(result.ok).toBe(true);
    expect(result.detail).toContain("prod");
  });

  it("OpenAI ok on 200", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch([{ match: (u) => u === "https://api.openai.com/v1/models", respond: () => jsonResponse({ data: [] }) }]),
    );
    const result = await validateOpenAI({ ...baseEnv, OPENAI_API_KEY: "sk-oai-x" });
    expect(result.ok).toBe(true);
  });

  it("OpenAI reports not-configured without hitting the network", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateOpenAI(baseEnv);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/not configured/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("OpenAI 401 → key-check message", async () => {
    vi.stubGlobal("fetch", routedFetch([{ match: () => true, respond: () => new Response("", { status: 401 }) }]));
    const result = await validateOpenAI({ ...baseEnv, OPENAI_API_KEY: "bad" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/OPENAI_API_KEY/);
  });
});

describe("validateAI aggregate", () => {
  it("is not-ok when no AI key is configured", async () => {
    const result = await validateAI(baseEnv);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/No AI keys/);
    expect(result.detail).toContain("OPENAI_API_KEY");
  });

  it("is ok when the only configured provider passes", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch([{ match: (u) => u.startsWith("https://api.anthropic.com"), respond: () => jsonResponse({ data: [] }) }]),
    );
    const result = await validateAI({ ...baseEnv, ANTHROPIC_API_KEY: "sk-ant-x" });
    expect(result.ok).toBe(true);
    expect(result.detail).toContain("Anthropic: ok");
  });

  it("is not-ok when one configured provider fails, and names both", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch([
        { match: (u) => u.startsWith("https://api.anthropic.com"), respond: () => jsonResponse({ data: [] }) },
        { match: (u) => u.startsWith("https://openrouter.ai"), respond: () => new Response("", { status: 401 }) },
      ]),
    );
    const result = await validateAI({ ...baseEnv, ANTHROPIC_API_KEY: "sk-ant-x", OPENROUTER_API_KEY: "bad" });
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("Anthropic: ok");
    expect(result.detail).toContain("OpenRouter:");
  });

  it("is ok with all three providers configured and passing, and names all three", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch([
        { match: (u) => u.startsWith("https://api.anthropic.com"), respond: () => jsonResponse({ data: [] }) },
        { match: (u) => u.startsWith("https://openrouter.ai"), respond: () => jsonResponse({ data: {} }) },
        { match: (u) => u.startsWith("https://api.openai.com"), respond: () => jsonResponse({ data: [] }) },
      ]),
    );
    const result = await validateAI({
      ...baseEnv,
      ANTHROPIC_API_KEY: "sk-ant-x",
      OPENROUTER_API_KEY: "or-x",
      OPENAI_API_KEY: "sk-oai-x",
    });
    expect(result.ok).toBe(true);
    expect(result.detail).toContain("Anthropic: ok");
    expect(result.detail).toContain("OpenRouter: ok");
    expect(result.detail).toContain("OpenAI: ok");
  });
});

// ── R2 provisioning ─────────────────────────────────────────────────────────

describe("validateR2Provision", () => {
  it("reports not-configured without hitting the network", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateR2Provision(baseEnv);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/not configured/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("is ok when the token authenticates a scoped account read", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch([
        {
          match: (u) => u === "https://api.cloudflare.com/client/v4/accounts?per_page=1",
          respond: () => jsonResponse({ success: true, result: [{ name: "Acme Agency" }] }),
        },
      ]),
    );
    const result = await validateR2Provision({ ...baseEnv, R2_PROVISION_API_TOKEN: "cf-token" });
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/valid/);
    expect(result.detail).toContain("Acme Agency");
  });

  it("maps 401 to a token-check message", async () => {
    vi.stubGlobal("fetch", routedFetch([{ match: () => true, respond: () => new Response("", { status: 401 }) }]));
    const result = await validateR2Provision({ ...baseEnv, R2_PROVISION_API_TOKEN: "bad-token" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/R2_PROVISION_API_TOKEN/);
  });
});

// ── GCP ───────────────────────────────────────────────────────────────────────

// Build a real service-account key JSON with a freshly generated RSA key so the
// validator's RS256 JWT signing runs for real; only the token + project HTTP
// calls are mocked.
async function makeServiceAccountKey(projectId = "demo-project"): Promise<string> {
  // generateKey returns CryptoKey | CryptoKeyPair; an RSA sign/verify algorithm
  // always yields a pair, and exportKey("pkcs8") yields an ArrayBuffer — cast
  // the union types the DOM/Workers lib can't narrow on its own.
  const keyPair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(
    (await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)) as ArrayBuffer,
  );
  let binary = "";
  for (const byte of pkcs8) binary += String.fromCharCode(byte);
  const base64 = btoa(binary);
  const pem = `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  return JSON.stringify({
    type: "service_account",
    project_id: projectId,
    private_key: pem,
    client_email: `sa@${projectId}.iam.gserviceaccount.com`,
    token_uri: "https://oauth2.googleapis.com/token",
  });
}

describe("validateGCP", () => {
  it("reports not-configured", async () => {
    const result = await validateGCP(baseEnv);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/not configured/);
  });

  it("reports malformed JSON", async () => {
    const result = await validateGCP({ ...baseEnv, GCP_SERVICE_ACCOUNT_KEY: "{not json" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/not valid JSON/);
  });

  it("mints a token via the JWT-bearer grant and is ok when the project authorizes", async () => {
    const key = await makeServiceAccountKey();
    const fetchMock = routedFetch([
      { match: (u) => u === "https://oauth2.googleapis.com/token", respond: () => jsonResponse({ access_token: "ya29.test", expires_in: 3600 }) },
      { match: (u) => u.includes("cloudresourcemanager.googleapis.com/v1/projects/demo-project"), respond: () => jsonResponse({ projectId: "demo-project" }) },
    ]);
    vi.stubGlobal("fetch", fetchMock);

    const result = await validateGCP({ ...baseEnv, GCP_SERVICE_ACCOUNT_KEY: key });
    expect(result.ok).toBe(true);
    expect(result.detail).toContain("demo-project");

    // The token request is a JWT-bearer assertion; the project call carries the bearer.
    const [, tokenInit] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(String(tokenInit.body)).toContain("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer");
    expect(String(tokenInit.body)).toContain("assertion=");
    const [, projectInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(new Headers(projectInit.headers).get("authorization")).toBe("Bearer ya29.test");
  });

  it("reports a 403 project denial after the token mints", async () => {
    const key = await makeServiceAccountKey();
    vi.stubGlobal(
      "fetch",
      routedFetch([
        { match: (u) => u.includes("oauth2.googleapis.com/token"), respond: () => jsonResponse({ access_token: "ya29.test" }) },
        { match: (u) => u.includes("cloudresourcemanager.googleapis.com"), respond: () => jsonResponse({ error: { message: "denied" } }, 403) },
      ]),
    );
    const result = await validateGCP({ ...baseEnv, GCP_SERVICE_ACCOUNT_KEY: key });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/403/);
    expect(result.detail).toMatch(/Viewer/);
  });

  it("reports a token-mint failure clearly", async () => {
    const key = await makeServiceAccountKey();
    vi.stubGlobal(
      "fetch",
      routedFetch([{ match: (u) => u.includes("oauth2.googleapis.com/token"), respond: () => jsonResponse({ error: "invalid_grant" }, 400) }]),
    );
    const result = await validateGCP({ ...baseEnv, GCP_SERVICE_ACCOUNT_KEY: key });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/could not mint an access token/);
  });
});
