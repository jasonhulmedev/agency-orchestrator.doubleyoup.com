// planning/49 Phase 3 (I4), decision A — the SessionGateMinter: Google ID tokens for the session edge gate.
//
// The gate (gate.js, a separate script with a separate blast radius) holds NO Google key. It calls this
// Worker through a Workers service binding to the named entrypoint SessionGateMinter (src/index.ts), and
// this module mints an ID token from the agency's OWN service-account key — but ONLY for an audience that
// is one of THIS project's session service URLs:
//
//   https://<session service name>-<projectNumber>.<region>.run.app
//
// where <session service name> is `<prefix>-<slug>` in the twin grammar (term, pma, staging, sterm, spma),
// <projectNumber> is the number of the project the service-account key belongs to, and <region> is a
// Compute region name. Exactly that string: no path, no trailing slash, no port, no userinfo, no query, no
// other host. That is Cloud Run's deterministic URL, which exists only while its first label is at most 63
// characters, so a longer label is refused too. Anything else gets NO token.
//
// The project number is read once per isolate (Cloud Resource Manager projects.get, which needs
// resourcemanager.projects.get — roles/browser has it) and cached; it never changes for a project.
//
// THE CALLER (planning/49 Phase 4 I3, decision D1 A; I4 review M2). A service binding carries no caller
// identity, so any script in the same Cloudflare account could bind this entrypoint. Two request forms:
//   • gate v2: { audience, ts, mac }, a caller proof made with the gate's caller key (caller-key.ts). The
//     minter derives the key again from DY_CLIENT_SECRET and the gate script name of (its own project, the
//     audience's region), refuses a ts more than 60 s from its clock, and compares the MAC in constant time.
//     This form ALWAYS needs a valid proof, for every prefix.
//   • gate v1: the bare audience string, no proof. TRANSITION RULE: served ONLY for term- and sterm-
//     audiences, whose container verifies the session token itself, so an ID token alone opens nothing
//     there. pma-, spma- and staging- (and any prefix added later) need the v2 proof. Drop this form once
//     every cell's gate is v2 (planning/49 Phase 4 I8).
// The caller is checked before any network call, so a refused caller never makes this Worker call Google.
//
// NEVER LOGS AND NEVER EXPLAINS: a failure returns a reason CODE, never a detail. The gate turns any failure
// into a bare 503, and a Google error body never travels towards a browser. "caller-refused" covers every
// proof failure alike (no proof, a stale or future ts, a wrong MAC), so it says nothing about the key.

import type { Env } from "../env.js";
import { mintPinnedGcpIdToken, readPinnedServiceAccountKey } from "../actuate.js";
import { mintGoogleAccessToken } from "../validators.js";
import { edgeGateScriptNameFor, isGcpRegionName, splitCloudRunSessionServiceName } from "../dispatch-params.js";
import { errorMessage } from "../util.js";
import { deriveMinterCallerKey, isUsableClientSecret, verifyMinterCallerProof } from "./caller-key.js";

/** What the gate gets back over RPC. A failure carries a code only. */
export type SessionGateMintResult =
  | { ok: true; idToken: string; expiresAt: number }
  | { ok: false; reason: "audience-refused" | "caller-refused" | "unavailable" };

/**
 * The session prefixes a call WITHOUT a caller proof (a v1 gate) may still get a token for: the terminal
 * hosts, whose container checks the session token itself. An allow-list, so a new prefix needs the proof.
 */
export const KEYLESS_TRANSITION_PREFIXES: readonly string[] = Object.freeze(["term", "sterm"]);

/** The parts of an allowed audience. */
export interface SessionGateAudience {
  serviceName: string;
  projectNumber: string;
  region: string;
}

const CLOUD_RESOURCE_MANAGER_PROJECTS_URL = "https://cloudresourcemanager.googleapis.com/v1/projects";
// A GCP project number: a positive decimal integer (12 digits today).
const PROJECT_NUMBER_RE = /^[1-9][0-9]{0,19}$/;
// The whole audience: "https://" + one label + "." + one label + ".run.app", and nothing before or after.
// Lowercase only, so no second spelling of one URL is accepted.
const RUN_APP_AUDIENCE_RE = /^https:\/\/([a-z0-9-]+)\.([a-z0-9-]+)\.run\.app$/;
// Cloud Run gives a service its deterministic URL only while that DNS label fits 63 characters.
const DETERMINISTIC_URL_LABEL_MAX_LENGTH = 63;

const AUDIENCE_REFUSED: SessionGateMintResult = { ok: false, reason: "audience-refused" };
const CALLER_REFUSED: SessionGateMintResult = { ok: false, reason: "caller-refused" };
const UNAVAILABLE: SessionGateMintResult = { ok: false, reason: "unavailable" };

// Per-isolate cache: project id -> project number.
const projectNumberCache = new Map<string, string>();

/**
 * Split an audience into its session service name, project number and region, or null when it is not
 * EXACTLY `https://<session service name>-<projectNumber>.<region>.run.app`. Makes no network call.
 */
export function parseSessionGateAudience(audience: unknown): SessionGateAudience | null {
  if (typeof audience !== "string") {
    return null;
  }
  const match = RUN_APP_AUDIENCE_RE.exec(audience);
  if (match === null) {
    return null;
  }
  const label = match[1] as string;
  const region = match[2] as string;
  if (label.length > DETERMINISTIC_URL_LABEL_MAX_LENGTH) {
    return null;
  }
  if (!isGcpRegionName(region)) {
    return null;
  }
  // The project number is the digits after the LAST hyphen; the service name is everything before it.
  const lastHyphen = label.lastIndexOf("-");
  if (lastHyphen <= 0) {
    return null;
  }
  const serviceName = label.slice(0, lastHyphen);
  const projectNumber = label.slice(lastHyphen + 1);
  if (!PROJECT_NUMBER_RE.test(projectNumber)) {
    return null;
  }
  if (splitCloudRunSessionServiceName(serviceName) === null) {
    return null;
  }
  return { serviceName, projectNumber, region };
}

/** The outcome of reading a project's number. */
export type ProjectNumberOutcome = { ok: true; projectNumber: string } | { ok: false; detail: string };

/**
 * The project NUMBER of `project`, which must be the service-account key's own project (the same pin every
 * gcp-* op uses). Read once per isolate with a READ-ONLY token (Cloud Resource Manager projects.get), then
 * cached. A failure is ok:false + a detail for edge-gate-deploy's result; the minter never passes it on.
 */
export async function readProjectNumber(env: Env, project: string): Promise<ProjectNumberOutcome> {
  const cached = projectNumberCache.get(project);
  if (cached !== undefined) {
    return { ok: true, projectNumber: cached };
  }

  const key = readPinnedServiceAccountKey(env, project);
  if (!key.ok) {
    return { ok: false, detail: key.detail };
  }
  let accessToken: string;
  try {
    // mintGoogleAccessToken's default scope is cloud-platform.read-only: a read needs no more.
    accessToken = await mintGoogleAccessToken({
      clientEmail: key.clientEmail,
      privateKeyPem: key.privateKeyPem,
      tokenUri: key.tokenUri,
    });
  } catch (err) {
    return { ok: false, detail: `could not mint a Google access token from GCP_SERVICE_ACCOUNT_KEY: ${errorMessage(err)}` };
  }

  let response: Response;
  try {
    response = await fetch(`${CLOUD_RESOURCE_MANAGER_PROJECTS_URL}/${encodeURIComponent(project)}`, {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
    });
  } catch (err) {
    return { ok: false, detail: `could not reach Cloud Resource Manager to read project "${project}": ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as {
    projectId?: unknown;
    projectNumber?: unknown;
    error?: { message?: string };
  } | null;
  if (response.status !== 200) {
    const message = body?.error?.message;
    return {
      ok: false,
      detail:
        `reading the number of project "${project}" failed with HTTP ${response.status}${message ? `: ${message}` : ""}. ` +
        "The Worker's service account needs resourcemanager.projects.get on its own project (roles/browser has it).",
    };
  }
  if (body === null || body.projectId !== project || typeof body.projectNumber !== "string" || !PROJECT_NUMBER_RE.test(body.projectNumber)) {
    return { ok: false, detail: `Cloud Resource Manager returned no project number for project "${project}"` };
  }
  projectNumberCache.set(project, body.projectNumber);
  return { ok: true, projectNumber: body.projectNumber };
}

/** The project id inside GCP_SERVICE_ACCOUNT_KEY, or null when the key is absent or unreadable. */
function serviceAccountKeyProjectId(env: Env): string | null {
  if (!env.GCP_SERVICE_ACCOUNT_KEY) {
    return null;
  }
  // JSON.parse has no non-throwing form.
  let key: { project_id?: unknown } | null;
  try {
    key = JSON.parse(env.GCP_SERVICE_ACCOUNT_KEY) as { project_id?: unknown } | null;
  } catch {
    return null;
  }
  if (key === null || typeof key !== "object" || typeof key.project_id !== "string" || key.project_id.length === 0) {
    return null;
  }
  return key.project_id;
}

/** The `exp` claim of a Google ID token (a JWT), or null when it cannot be read or is not in the future. */
function idTokenExpiresAt(idToken: string): number | null {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const payloadSegment = parts[1] as string;
  const standard = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard.padEnd(Math.ceil(standard.length / 4) * 4, "=");
  // atob and JSON.parse both throw on garbage, and a garbled token must not reach the gate.
  let claims: { exp?: unknown } | null;
  try {
    claims = JSON.parse(atob(padded)) as { exp?: unknown } | null;
  } catch {
    return null;
  }
  if (claims === null || typeof claims !== "object") {
    return null;
  }
  const exp = claims.exp;
  if (typeof exp !== "number" || !Number.isSafeInteger(exp) || exp <= Math.floor(Date.now() / 1000)) {
    return null;
  }
  return exp;
}

/** A mint call, read from either request form. `proof` is null for the v1 form (a bare audience string). */
interface MintRequest {
  audience: unknown;
  proof: { ts: unknown; mac: unknown } | null;
}

/**
 * Read the request a gate sent: the v1 bare audience string (no proof), or the v2 object
 * `{ audience, ts, mac }`. Null for anything else. An object ALWAYS counts as carrying a proof, even when
 * `ts` or `mac` is missing, so it can never fall back to the keyless v1 rule.
 */
function readMintRequest(request: unknown): MintRequest | null {
  if (typeof request === "string") {
    return { audience: request, proof: null };
  }
  if (typeof request !== "object" || request === null || Array.isArray(request)) {
    return null;
  }
  const fields = request as Record<string, unknown>;
  return { audience: fields.audience, proof: { ts: fields.ts, mac: fields.mac } };
}

type CallerVerdict = "allowed" | "refused" | "unavailable";

/**
 * May this caller get a token for this audience? A v1 call (no proof) only for a KEYLESS_TRANSITION_PREFIXES
 * audience. A v2 call only with a valid proof for the gate script of (this Worker's own project, the
 * audience's region). "unavailable" when this Worker cannot check a proof (no usable service-account key or
 * DY_CLIENT_SECRET): that is this Worker's configuration, not the caller's fault. Makes no network call.
 */
async function callerVerdictFor(
  env: Env,
  parsed: SessionGateAudience,
  audience: string,
  proof: MintRequest["proof"],
): Promise<CallerVerdict> {
  if (proof === null) {
    const sessionName = splitCloudRunSessionServiceName(parsed.serviceName);
    if (sessionName !== null && KEYLESS_TRANSITION_PREFIXES.includes(sessionName.prefix)) {
      return "allowed";
    }
    return "refused";
  }

  const ownProject = serviceAccountKeyProjectId(env);
  if (ownProject === null) {
    return "unavailable";
  }
  if (!isUsableClientSecret(env.DY_CLIENT_SECRET)) {
    return "unavailable";
  }
  // The gate that may ask for this audience: the one edge-gate-deploy made for this project and the
  // audience's region. A key of another region's gate does not verify, so a gate signs only for its own cell.
  const gateScriptName = edgeGateScriptNameFor(ownProject, parsed.region);
  const callerKey = await deriveMinterCallerKey(env.DY_CLIENT_SECRET, gateScriptName);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const proofIsValid = await verifyMinterCallerProof(callerKey, audience, proof.ts, proof.mac, nowSeconds);
  if (!proofIsValid) {
    return "refused";
  }
  return "allowed";
}

/**
 * The minter's one operation: an ID token for the requested audience when it is one of this project's session
 * service URLs AND the caller passes callerVerdictFor, else a refusal with no token. `request` is a v2 gate's
 * `{ audience, ts, mac }` or a v1 gate's bare audience string. The audience shape and the caller are checked
 * before any network call. The token and its exp go back to the gate alone; nothing is logged.
 */
export async function mintSessionGateIdToken(env: Env, request: unknown): Promise<SessionGateMintResult> {
  const mintRequest = readMintRequest(request);
  if (mintRequest === null) {
    return AUDIENCE_REFUSED;
  }
  const parsed = parseSessionGateAudience(mintRequest.audience);
  if (parsed === null) {
    return AUDIENCE_REFUSED;
  }
  const audience = mintRequest.audience as string;

  const callerVerdict = await callerVerdictFor(env, parsed, audience, mintRequest.proof);
  if (callerVerdict === "refused") {
    return CALLER_REFUSED;
  }
  if (callerVerdict === "unavailable") {
    return UNAVAILABLE;
  }

  const ownProject = serviceAccountKeyProjectId(env);
  if (ownProject === null) {
    return UNAVAILABLE;
  }
  const projectNumber = await readProjectNumber(env, ownProject);
  if (!projectNumber.ok) {
    return UNAVAILABLE;
  }
  if (parsed.projectNumber !== projectNumber.projectNumber) {
    return AUDIENCE_REFUSED;
  }

  const minted = await mintPinnedGcpIdToken(env, ownProject, audience);
  if (!minted.ok) {
    return UNAVAILABLE;
  }
  const expiresAt = idTokenExpiresAt(minted.idToken);
  if (expiresAt === null) {
    return UNAVAILABLE;
  }
  return { ok: true, idToken: minted.idToken, expiresAt };
}
