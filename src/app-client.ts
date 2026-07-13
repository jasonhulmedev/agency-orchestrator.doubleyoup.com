// Direction-A auth: the agency Worker → our control-plane app.
//
// The Worker holds long-lived OAuth2 client credentials (DY_CLIENT_ID /
// DY_CLIENT_SECRET, issued at onboarding) and exchanges them for a short-lived
// bearer access token via the client_credentials grant. Per the pivot spec §3.2:
// a leaked access token is only good for minutes, and the client secret can be
// rotated on our side without redeploying the Worker.
//
// The token is cached in module scope until shortly before it expires, so a
// burst of app calls reuses one token instead of re-hitting /oauth/token each
// time. This is best-effort: a Worker can run across several isolates, each with
// its own module scope, so at worst a few isolates each mint their own token —
// that is fine and expected for edge caching.

import type { Env } from "./env.js";
import { stripTrailingSlash } from "./util.js";

// Refresh this many seconds BEFORE the real expiry, so we never present a token
// that expires mid-flight between our check and the app receiving the request.
const EXPIRY_SKEW_SECONDS = 60;

// Fallback lifetime if the token endpoint omits expires_in (it shouldn't).
const DEFAULT_TOKEN_LIFETIME_SECONDS = 3600;

interface CachedToken {
  accessToken: string;
  // Absolute epoch-ms after which we must mint a fresh token. Already includes
  // the skew subtraction, so a simple `Date.now() < usableUntilMs` is the whole
  // freshness check.
  usableUntilMs: number;
}

let cachedToken: CachedToken | null = null;

// Test-only: clear the module-level cache between cases. Not used at runtime.
export function _resetTokenCacheForTests(): void {
  cachedToken = null;
}

interface TokenResponse {
  access_token?: string;
  expires_in?: number;
}

// Return a valid app access token, reusing the cached one until it is within
// EXPIRY_SKEW_SECONDS of expiry. Throws on any non-2xx or malformed response so
// callers can surface a clear failure.
export async function getAppAccessToken(env: Env): Promise<string> {
  const now = Date.now();
  if (cachedToken && now < cachedToken.usableUntilMs) {
    return cachedToken.accessToken;
  }

  const tokenUrl = `${stripTrailingSlash(env.APP_BASE_URL)}/oauth/token`;

  // client_credentials grant, form-encoded per OAuth2 (RFC 6749 §4.4 / §2.3.1).
  const form = new URLSearchParams();
  form.set("grant_type", "client_credentials");
  form.set("client_id", env.DY_CLIENT_ID);
  form.set("client_secret", env.DY_CLIENT_SECRET);

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: form.toString(),
  });

  if (!response.ok) {
    const body = (await response.text()).slice(0, 300);
    throw new Error(
      `OAuth token exchange failed: ${tokenUrl} returned HTTP ${response.status}. ${body}`,
    );
  }

  const data = (await response.json()) as TokenResponse;
  if (!data.access_token) {
    throw new Error("OAuth token exchange succeeded but the response had no access_token.");
  }

  const lifetimeSeconds = data.expires_in ?? DEFAULT_TOKEN_LIFETIME_SECONDS;
  // Guard against a tiny/negative lifetime producing an already-expired cache
  // entry: cache for at least 1s so a same-tick second call still reuses it.
  const usableSeconds = Math.max(lifetimeSeconds - EXPIRY_SKEW_SECONDS, 1);
  cachedToken = {
    accessToken: data.access_token,
    usableUntilMs: now + usableSeconds * 1000,
  };
  return cachedToken.accessToken;
}

// Make an authenticated call to our app, attaching the Direction-A bearer token.
// Thin wrapper over fetch: resolves the token (from cache or a fresh exchange),
// sets Authorization, and lets the caller inspect the raw Response.
export async function callApp(env: Env, path: string, init: RequestInit = {}): Promise<Response> {
  const token = await getAppAccessToken(env);
  const url = `${stripTrailingSlash(env.APP_BASE_URL)}${path}`;

  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${token}`);
  if (!headers.has("accept")) {
    headers.set("accept", "application/json");
  }

  return fetch(url, { ...init, headers });
}
