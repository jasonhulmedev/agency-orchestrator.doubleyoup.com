// Credential self-validation (pivot spec §4 step 5 / answers Q4).
//
// Each validator makes a REAL authenticated call to the provider and returns a
// specific, actionable {ok, detail}. The agency iterates on `/validate` in their
// own Cloudflare dashboard until every result is green — no round-trips back to
// us to debug. A credential that isn't configured yet returns a clear
// "not configured" result (ok:false) rather than throwing.
//
// Worker-native only: fetch + Web Crypto (crypto.subtle). No AWS/GCP SDKs.

import type { Env } from "./env.js";
import { signS3Request } from "./sigv4.js";
import { errorMessage, extractXmlTag } from "./util.js";

export interface ValidationResult {
  ok: boolean;
  detail: string;
}

export interface AllValidations {
  gcp: ValidationResult;
  s3: ValidationResult;
  stripe: ValidationResult;
  ai: ValidationResult;
}

// ── S3 ────────────────────────────────────────────────────────────────────────

// Prove the S3 credential can authenticate AND read the bucket by signing a
// ListObjectsV2 with max-keys=1 (the cheapest read; needs s3:ListBucket). Works
// against real AWS (virtual-hosted-style) or any S3-compatible endpoint
// (path-style, e.g. R2) when S3_ENDPOINT is set.
export async function validateS3(env: Env): Promise<ValidationResult> {
  if (!env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY || !env.S3_BUCKET) {
    return {
      ok: false,
      detail:
        "S3 not configured — set the S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY and S3_BUCKET secrets.",
    };
  }

  const region = env.S3_REGION || "us-east-1";
  const bucket = env.S3_BUCKET;

  let requestUrl: string;
  if (env.S3_ENDPOINT) {
    // Custom endpoint (R2 / MinIO / Wasabi) — path-style: <endpoint>/<bucket>.
    const base = env.S3_ENDPOINT.replace(/\/+$/, "");
    requestUrl = `${base}/${encodeURIComponent(bucket)}?list-type=2&max-keys=1`;
  } else {
    // AWS — virtual-hosted-style: <bucket>.s3.<region>.amazonaws.com.
    requestUrl = `https://${bucket}.s3.${region}.amazonaws.com/?list-type=2&max-keys=1`;
  }

  try {
    const signed = await signS3Request({
      method: "GET",
      url: requestUrl,
      region,
      accessKeyId: env.S3_ACCESS_KEY_ID,
      secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    });
    const response = await fetch(signed.url, { method: "GET", headers: signed.headers });

    if (response.status === 200) {
      const where = env.S3_ENDPOINT ? env.S3_ENDPOINT : `s3.${region}.amazonaws.com`;
      return { ok: true, detail: `S3 bucket "${bucket}" is readable at ${where}.` };
    }

    // Non-200: mine the S3 XML error for an actionable hint.
    const body = (await response.text()).slice(0, 500);
    const code = extractXmlTag(body, "Code");

    if (code === "InvalidAccessKeyId") {
      return { ok: false, detail: "S3 access key not recognised (InvalidAccessKeyId) — check S3_ACCESS_KEY_ID." };
    }
    if (code === "SignatureDoesNotMatch") {
      return {
        ok: false,
        detail: "S3 signature mismatch (SignatureDoesNotMatch) — check S3_SECRET_ACCESS_KEY and S3_REGION.",
      };
    }
    if (response.status === 404 || code === "NoSuchBucket") {
      return {
        ok: false,
        detail: `S3 bucket "${bucket}" not found (404) — check S3_BUCKET, S3_REGION and S3_ENDPOINT.`,
      };
    }
    if (response.status === 403 || code === "AccessDenied") {
      return {
        ok: false,
        detail: `S3 access denied (403) for bucket "${bucket}" — the key authenticated but lacks s3:ListBucket, or a bucket policy denies it.`,
      };
    }
    return {
      ok: false,
      detail: `S3 check failed with HTTP ${response.status}${code ? ` (${code})` : ""}.`,
    };
  } catch (err) {
    return { ok: false, detail: `S3 request could not be sent: ${errorMessage(err)}.` };
  }
}

// ── Stripe ──────────────────────────────────────────────────────────────────

// GET /v1/account with the secret key as a bearer token. 200 => the key works.
export async function validateStripe(env: Env): Promise<ValidationResult> {
  if (!env.STRIPE_SECRET_KEY) {
    return { ok: false, detail: "Stripe not configured — set the STRIPE_SECRET_KEY secret." };
  }

  try {
    const response = await fetch("https://api.stripe.com/v1/account", {
      headers: {
        authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        accept: "application/json",
      },
    });

    if (response.status === 200) {
      const account = (await response.json()) as { id?: string };
      // Stripe key prefixes encode the mode; report it so the agency can catch a
      // test key pasted where a live key belongs (or vice-versa).
      const isLive = env.STRIPE_SECRET_KEY.includes("_live_");
      const accountId = account.id ?? "unknown";
      return {
        ok: true,
        detail: `Stripe account ${accountId} authenticated (${isLive ? "live" : "test"} mode).`,
      };
    }
    if (response.status === 401) {
      return { ok: false, detail: "Stripe rejected the key (401 Unauthorized) — check STRIPE_SECRET_KEY." };
    }

    const body = (await response.json().catch(() => null)) as { error?: { message?: string } } | null;
    const message = body?.error?.message;
    return {
      ok: false,
      detail: `Stripe check failed with HTTP ${response.status}${message ? `: ${message}` : ""}.`,
    };
  } catch (err) {
    return { ok: false, detail: `Stripe request could not be sent: ${errorMessage(err)}.` };
  }
}

// ── AI providers ──────────────────────────────────────────────────────────────

// Anthropic: a minimal authenticated read of the models list.
export async function validateAnthropic(env: Env): Promise<ValidationResult> {
  if (!env.ANTHROPIC_API_KEY) {
    return { ok: false, detail: "Anthropic not configured — set the ANTHROPIC_API_KEY secret." };
  }

  try {
    const response = await fetch("https://api.anthropic.com/v1/models?limit=1", {
      headers: {
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        accept: "application/json",
      },
    });

    if (response.status === 200) {
      return { ok: true, detail: "Anthropic API key authenticated." };
    }
    if (response.status === 401) {
      return { ok: false, detail: "Anthropic rejected the key (401) — check ANTHROPIC_API_KEY." };
    }
    return { ok: false, detail: `Anthropic check failed with HTTP ${response.status}.` };
  } catch (err) {
    return { ok: false, detail: `Anthropic request could not be sent: ${errorMessage(err)}.` };
  }
}

// OpenRouter: GET /key returns the key's own metadata — a cheap authenticated read.
export async function validateOpenRouter(env: Env): Promise<ValidationResult> {
  if (!env.OPENROUTER_API_KEY) {
    return { ok: false, detail: "OpenRouter not configured — set the OPENROUTER_API_KEY secret." };
  }

  try {
    const response = await fetch("https://openrouter.ai/api/v1/key", {
      headers: {
        authorization: `Bearer ${env.OPENROUTER_API_KEY}`,
        accept: "application/json",
      },
    });

    if (response.status === 200) {
      const body = (await response.json().catch(() => null)) as { data?: { label?: string } } | null;
      const label = body?.data?.label;
      return { ok: true, detail: `OpenRouter API key authenticated${label ? ` (${label})` : ""}.` };
    }
    if (response.status === 401) {
      return { ok: false, detail: "OpenRouter rejected the key (401) — check OPENROUTER_API_KEY." };
    }
    return { ok: false, detail: `OpenRouter check failed with HTTP ${response.status}.` };
  } catch (err) {
    return { ok: false, detail: `OpenRouter request could not be sent: ${errorMessage(err)}.` };
  }
}

// Aggregate AI result surfaced at /validate. Both providers are optional; the
// aggregate is green only when at least one AI key is configured and EVERY
// configured provider validates. A provider that isn't configured is neither
// counted nor held against the agency.
export async function validateAI(env: Env): Promise<ValidationResult> {
  const providers: Array<{ name: string; configured: boolean; result: ValidationResult }> = [
    { name: "Anthropic", configured: !!env.ANTHROPIC_API_KEY, result: await validateAnthropic(env) },
    { name: "OpenRouter", configured: !!env.OPENROUTER_API_KEY, result: await validateOpenRouter(env) },
  ];

  const configured = providers.filter((provider) => provider.configured);
  if (configured.length === 0) {
    return {
      ok: false,
      detail: "No AI keys configured — set ANTHROPIC_API_KEY and/or OPENROUTER_API_KEY.",
    };
  }

  const allOk = configured.every((provider) => provider.result.ok);
  const detail = configured
    .map((provider) => `${provider.name}: ${provider.result.ok ? "ok" : provider.result.detail}`)
    .join(" | ");
  return { ok: allOk, detail };
}

// ── Google Cloud ──────────────────────────────────────────────────────────────

// Base64url-encode raw bytes (JWT segments are base64url with no padding).
function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeString(value: string): string {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

// Convert a PEM private key to its raw DER bytes for crypto.subtle.importKey.
// Google service-account keys ship the private key as PKCS#8 PEM
// ("-----BEGIN PRIVATE KEY-----"); JSON.parse already turned the JSON "\n"
// escapes into real newlines, so stripping the armor + all whitespace and
// base64-decoding yields the DER.
function pemToDer(pem: string): Uint8Array {
  const base64Body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(atob(base64Body), (char) => char.charCodeAt(0));
}

interface ServiceAccountKey {
  client_email?: string;
  private_key?: string;
  project_id?: string;
  token_uri?: string;
}

interface GoogleTokenResponse {
  access_token?: string;
}

// Mint a Google OAuth2 access token via the JWT-bearer grant (RFC 7523 /
// Google's "server-to-server" flow): build a JWT signed with the service
// account's RS256 private key, POST it as the assertion, receive a bearer token.
// This avoids any Google SDK — pure Web Crypto + fetch. Throws on failure.
async function mintGoogleAccessToken(options: {
  clientEmail: string;
  privateKeyPem: string;
  tokenUri: string;
}): Promise<string> {
  const nowSeconds = Math.floor(Date.now() / 1000);

  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: options.clientEmail,
    // Least-privilege: read-only cloud-platform scope is enough for a
    // projects.get authorization probe.
    scope: "https://www.googleapis.com/auth/cloud-platform.read-only",
    aud: options.tokenUri,
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  };

  const signingInput =
    `${base64UrlEncodeString(JSON.stringify(header))}.` +
    `${base64UrlEncodeString(JSON.stringify(claims))}`;

  // Import the PKCS#8 private key for RS256 (RSASSA-PKCS1-v1_5 + SHA-256) and
  // sign the "<header>.<claims>" input. workerd and Node both support this.
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(options.privateKeyPem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, new TextEncoder().encode(signingInput)),
  );
  const jwt = `${signingInput}.${base64UrlEncodeBytes(signatureBytes)}`;

  const form = new URLSearchParams();
  form.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  form.set("assertion", jwt);

  const response = await fetch(options.tokenUri, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: form.toString(),
  });

  if (!response.ok) {
    const body = (await response.text()).slice(0, 300);
    throw new Error(`Google token endpoint returned HTTP ${response.status}. ${body}`);
  }
  const data = (await response.json()) as GoogleTokenResponse;
  if (!data.access_token) {
    throw new Error("Google token endpoint response had no access_token.");
  }
  return data.access_token;
}

// Parse the SA-key JSON, mint an access token, then authorize a cheap
// projects.get. ok when the token mints AND the project call authorizes.
export async function validateGCP(env: Env): Promise<ValidationResult> {
  if (!env.GCP_SERVICE_ACCOUNT_KEY) {
    return {
      ok: false,
      detail: "Google Cloud not configured — set the GCP_SERVICE_ACCOUNT_KEY secret (the service-account JSON).",
    };
  }

  let key: ServiceAccountKey;
  try {
    key = JSON.parse(env.GCP_SERVICE_ACCOUNT_KEY) as ServiceAccountKey;
  } catch {
    return {
      ok: false,
      detail: "Google Cloud service-account key is not valid JSON — paste the entire downloaded key file.",
    };
  }

  const clientEmail = key.client_email;
  const privateKeyPem = key.private_key;
  const projectId = key.project_id;
  const tokenUri = key.token_uri || "https://oauth2.googleapis.com/token";
  if (!clientEmail || !privateKeyPem || !projectId) {
    return {
      ok: false,
      detail:
        "Google Cloud key JSON is missing client_email, private_key or project_id — use a service-account key, not an OAuth client ID.",
    };
  }

  let accessToken: string;
  try {
    accessToken = await mintGoogleAccessToken({ clientEmail, privateKeyPem, tokenUri });
  } catch (err) {
    return {
      ok: false,
      detail: `Google Cloud auth failed — could not mint an access token: ${errorMessage(err)}. Check the service-account key.`,
    };
  }

  try {
    const response = await fetch(
      `https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(projectId)}`,
      { headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" } },
    );

    if (response.status === 200) {
      return {
        ok: true,
        detail: `Google Cloud authenticated as ${clientEmail}; project "${projectId}" is accessible.`,
      };
    }
    if (response.status === 403) {
      return {
        ok: false,
        detail: `Google Cloud token minted but project "${projectId}" access was denied (403) — grant the service account at least the Viewer role and enable the Cloud Resource Manager API.`,
      };
    }
    if (response.status === 404) {
      return {
        ok: false,
        detail: `Google Cloud project "${projectId}" not found (404) — check project_id in the key JSON.`,
      };
    }
    const body = (await response.json().catch(() => null)) as { error?: { message?: string } } | null;
    const message = body?.error?.message;
    return {
      ok: false,
      detail: `Google Cloud project check failed with HTTP ${response.status}${message ? `: ${message}` : ""}.`,
    };
  } catch (err) {
    return { ok: false, detail: `Google Cloud project check could not be sent: ${errorMessage(err)}.` };
  }
}

// ── Aggregate ─────────────────────────────────────────────────────────────────

// Run every validator in parallel. Independent network calls — no ordering
// requirement — so Promise.all keeps /validate responsive.
export async function validateAll(env: Env): Promise<AllValidations> {
  const [gcp, s3, stripe, ai] = await Promise.all([
    validateGCP(env),
    validateS3(env),
    validateStripe(env),
    validateAI(env),
  ]);
  return { gcp, s3, stripe, ai };
}
