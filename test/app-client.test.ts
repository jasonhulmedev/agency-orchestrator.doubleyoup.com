import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { Env } from "../src/env.js";
import { getAppAccessToken, callApp, _resetTokenCacheForTests } from "../src/app-client.js";

const baseEnv: Env = {
  APP_BASE_URL: "https://app.example.test",
  DY_CLIENT_ID: "client-abc",
  DY_CLIENT_SECRET: "secret-xyz",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("Direction-A token exchange", () => {
  // Control the clock so the caching/expiry logic is deterministic.
  let now = 1_000_000;

  beforeEach(() => {
    _resetTokenCacheForTests();
    now = 1_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("mints a token, caches it, and reuses it within its lifetime", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ access_token: "token-A", expires_in: 3600 }));
    vi.stubGlobal("fetch", fetchMock);

    const first = await getAppAccessToken(baseEnv);
    const second = await getAppAccessToken(baseEnv);

    expect(first).toBe("token-A");
    expect(second).toBe("token-A");
    // Cached: the second call must not hit the token endpoint again.
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // It POSTs a form-encoded client_credentials grant to /oauth/token.
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://app.example.test/oauth/token");
    expect(init.method).toBe("POST");
    const body = String(init.body);
    expect(body).toContain("grant_type=client_credentials");
    expect(body).toContain("client_id=client-abc");
    expect(body).toContain("client_secret=secret-xyz");
  });

  it("refreshes the token ~60s before expiry, not before", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ access_token: "token-A", expires_in: 3600 }))
      .mockResolvedValueOnce(jsonResponse({ access_token: "token-B", expires_in: 3600 }));
    vi.stubGlobal("fetch", fetchMock);

    expect(await getAppAccessToken(baseEnv)).toBe("token-A");

    // Usable window is (3600 - 60) = 3540s. Just inside it: still cached.
    now += (3540 - 1) * 1000;
    expect(await getAppAccessToken(baseEnv)).toBe("token-A");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // Just past the 60s-before-expiry boundary: a fresh token is minted.
    now += 2 * 1000;
    expect(await getAppAccessToken(baseEnv)).toBe("token-B");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("throws a clear error on a non-2xx token response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("nope", { status: 401 })));
    await expect(getAppAccessToken(baseEnv)).rejects.toThrow(/HTTP 401/);
  });

  it("throws when the token response has no access_token", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ expires_in: 3600 })));
    await expect(getAppAccessToken(baseEnv)).rejects.toThrow(/no access_token/);
  });

  it("callApp attaches the bearer token and targets the app path", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ access_token: "token-A", expires_in: 3600 }))
      .mockResolvedValueOnce(jsonResponse({ accountId: "acct_1" }));
    vi.stubGlobal("fetch", fetchMock);

    const response = await callApp(baseEnv, "/api/agency/me", { method: "GET" });
    expect(response.status).toBe(200);

    const [url, init] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(url).toBe("https://app.example.test/api/agency/me");
    const headers = new Headers(init.headers);
    expect(headers.get("authorization")).toBe("Bearer token-A");
  });
});
