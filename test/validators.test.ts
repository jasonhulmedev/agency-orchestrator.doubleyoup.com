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

  it("reports not-configured without hitting the network", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3(baseEnv);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/not configured/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("signs a ListObjectsV2 and is ok on 200", async () => {
    const fetchMock = routedFetch([
      { match: (u) => u.includes("my-bucket.s3.us-east-1.amazonaws.com"), respond: () => new Response("", { status: 200 }) },
    ]);
    vi.stubGlobal("fetch", fetchMock);

    const result = await validateS3(s3Env);
    expect(result.ok).toBe(true);
    expect(result.detail).toContain("my-bucket");

    // The request must carry a SigV4 Authorization header + x-amz-date.
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(headers.get("authorization")).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\//);
    expect(headers.get("x-amz-date")).toBeTruthy();
  });

  // ── S3-compatible / R2 endpoint: object-probe path (no bucket list) ─────────
  it("uses an object probe (never a bucket list) when S3_ENDPOINT is set, and is ok on 404 NoSuchKey", async () => {
    const fetchMock = routedFetch([
      {
        match: (u) =>
          u.startsWith("https://acct.r2.cloudflarestorage.com/my-bucket/.doubleyoup-connectivity-probe"),
        respond: () => xmlResponse("<Code>NoSuchKey</Code>", 404),
      },
    ]);
    vi.stubGlobal("fetch", fetchMock);

    const result = await validateS3({
      ...s3Env,
      S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com",
      S3_REGION: "auto",
    });
    expect(result.ok).toBe(true);

    // The whole point: a scoped R2 key 403s on ListObjectsV2, so we must NOT list.
    const calledUrl = String((fetchMock.mock.calls[0] as unknown[])[0]);
    expect(calledUrl).not.toContain("list-type=2");
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init.headers).get("authorization")).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\//);
  });

  it("is ok when the probe object happens to exist (200) on a custom endpoint", async () => {
    const fetchMock = routedFetch([
      { match: (u) => u.includes("acct.r2.cloudflarestorage.com/my-bucket/"), respond: () => new Response("", { status: 200 }) },
    ]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3({ ...s3Env, S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com", S3_REGION: "auto" });
    expect(result.ok).toBe(true);
  });

  it("maps a real AccessDenied on the R2 probe to a scope-check message", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => xmlResponse("<Code>AccessDenied</Code>", 403) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3({ ...s3Env, S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com", S3_REGION: "auto" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/not authorized to read this bucket/i);
    expect(result.detail).toMatch(/R2/);
  });

  it("maps NoSuchBucket on the R2 probe to a bucket-check message", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => xmlResponse("<Code>NoSuchBucket</Code>", 404) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3({ ...s3Env, S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com", S3_REGION: "auto" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/NoSuchBucket/);
    expect(result.detail).toMatch(/S3_BUCKET/);
  });

  it("maps InvalidAccessKeyId on the R2 probe to a key-specific message", async () => {
    const fetchMock = routedFetch([{ match: () => true, respond: () => xmlResponse("<Code>InvalidAccessKeyId</Code>", 403) }]);
    vi.stubGlobal("fetch", fetchMock);
    const result = await validateS3({ ...s3Env, S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com", S3_REGION: "auto" });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/S3_ACCESS_KEY_ID/);
  });

  it("gives an actionable message on 403 AccessDenied (AWS list path)", async () => {
    const fetchMock = routedFetch([
      { match: () => true, respond: () => xmlResponse("<Code>AccessDenied</Code>", 403) },
    ]);
    vi.stubGlobal("fetch", fetchMock);

    const result = await validateS3(s3Env);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/access denied/i);
    expect(result.detail).toMatch(/ListBucket/);
  });

  it("maps InvalidAccessKeyId to a key-specific message", async () => {
    const fetchMock = routedFetch([
      { match: () => true, respond: () => xmlResponse("<Code>InvalidAccessKeyId</Code>", 403) },
    ]);
    vi.stubGlobal("fetch", fetchMock);

    const result = await validateS3(s3Env);
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/S3_ACCESS_KEY_ID/);
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
