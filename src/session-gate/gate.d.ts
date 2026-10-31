// Types for gate.js, for the TypeScript tests that import it. gate.js stays plain JavaScript because it is
// uploaded to Cloudflare as-is (edge-gate-deploy, through the generated gate-source.ts).

/** The claims a session host's token must carry, from the host alone. */
export interface SessionHostTarget {
  expectedPurpose: "terminal" | "pma" | "staging";
  slug: string;
  /** The full lower-cased host: the key is derived from it. */
  host: string;
  /** The host label: the Cloud Run service name. */
  label: string;
}

/** The v1 session token claims. */
export interface SessionTokenClaims {
  siteId: string;
  slug: string;
  purpose: string;
  uid: number;
  exp: number;
}

/** What gate v2 sends to the minter: the audience and its caller proof (see the header of gate.js). */
export interface SessionGateMintRequest {
  audience: string;
  /** Unix seconds when the proof was made. */
  ts: number;
  /** base64url(HMAC-SHA256(caller key, "v1|" + audience + "|" + ts)), no padding. */
  mac: string;
}

/** The gate's bindings (see the header of gate.js). */
export interface SessionGateEnv {
  DY_SESSION_SECRET?: string;
  DY_ZONE_SUFFIX?: string;
  DY_RUN_URL_SUFFIX?: string;
  DY_MINTER?: { mintIdToken(request: SessionGateMintRequest): Promise<unknown> };
  DY_MINTER_CALLER_KEY?: string;
  DY_SESSION_KEY_VERSION?: string;
  DY_SESSION_KEY_FINGERPRINT?: string;
  DY_MINTER_CALLER_FINGERPRINT?: string;
}

export function configurationProblem(env: SessionGateEnv): string | null;
export function resolveHostTarget(hostname: string, zoneSuffix: string): SessionHostTarget | null;
export function deriveHostKey(sessionSecret: string, hostname: string): Promise<Uint8Array>;
export function verifyToken(
  token: string | null | undefined,
  hostKey: Uint8Array,
  expectedPurpose: string,
  expectedSlug: string,
): Promise<SessionTokenClaims | null>;

declare const gate: {
  fetch(request: Request, env: SessionGateEnv): Promise<Response>;
};
export default gate;
