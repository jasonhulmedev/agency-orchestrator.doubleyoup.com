// planning/49 Phase 3 (I4) — edge-gate-deploy: upload THIS Worker's own embedded session edge gate
// (src/session-gate/gate.js, carried as text by the generated gate-source.ts) into the agency's Cloudflare
// account as the cell's gate script, with the cell's session secret. No script bytes come from the platform
// (planning/49 §5.1): a signed job can choose only the cell (project, region, zone) and its key.
//
// THE SCRIPT is DERIVED, `dy-gate-<project>-<region>` (edgeGateScriptNameFor), the same script the route ops
// point at. It goes into the Cloudflare account that holds the job's zone (the zone lookup reports it): a
// Workers route can run only a script of its own zone's account. Token: the agency's CF_DNS_API_TOKEN, which
// gains Account → Workers Scripts: Edit (planning/49 decision C; a scope add, not a new secret).
//
// NEVER TAKE OVER A SCRIPT. If a script with that name exists and its main module does not start with the
// gate's marker line ("// dy-session-gate v<N>"), this platform did not make it, and it is left alone. That
// also protects the platform's own `dy-edge-gate` and every other script in an account shared with the
// platform (syd's), whatever the token's account-wide Scripts:Edit would allow.
//
// NEVER DOWNGRADE. A deployed gate whose marker version is HIGHER than the embedded one was deployed by a
// newer copy of this Worker; this fork is older, so it refuses instead of putting an older gate back.
//
// THE BINDINGS (what gate.js reads, plus two convergence markers):
//   DY_SESSION_SECRET           secret_text  the cell's session secret. Cloudflare never returns its value.
//   DY_ZONE_SUFFIX              plain_text   "." + zone
//   DY_RUN_URL_SUFFIX           plain_text   "-<projectNumber>.<region>.run.app" (the project NUMBER is read
//                                            from Cloud Resource Manager, cached per isolate)
//   DY_MINTER                   service      DY_WORKER_NAME, entrypoint SessionGateMinter (this Worker)
//   DY_SESSION_KEY_VERSION      plain_text   the job's keyVersion
//   DY_SESSION_KEY_FINGERPRINT  plain_text   sessionKeyFingerprint(secret): the ONLY way to see later that
//                                            the secret changed, because the secret itself is never readable
//   DY_MINTER_CALLER_KEY        secret_text  (gate v2, planning/49 Phase 4 I3) the gate's minter caller key,
//                                            64 lowercase hex: HKDF of THIS Worker's DY_CLIENT_SECRET for this
//                                            gate script (src/session-gate/caller-key.ts). The gate signs every
//                                            mint call with it; the minter derives it again to check.
//   DY_MINTER_CALLER_FINGERPRINT plain_text  minterCallerKeyFingerprint(key), for the same reason as the
//                                            session key fingerprint: a changed DY_CLIENT_SECRET gives another
//                                            fingerprint, so the next deploy is "updated", never "unchanged"
//
// NO LOGS (review L7): session tokens travel in `?token=` and in the gate's cookie, so no Cloudflare log may
// record a gate request. The upload sets Workers Logs / observability OFF, logpush OFF, and no tail or
// streaming-tail consumers, explicitly, and "unchanged" and the read-back both require that state. (A live
// `wrangler tail` by a member of the agency's Cloudflare account is outside what a script's settings
// control.)
//
// FLOW:
//   0. PIN `project` to GCP_SERVICE_ACCOUNT_KEY's project_id; refuse when DY_WORKER_NAME is unset or not a
//      script name, or DY_CLIENT_SECRET cannot be the root of a caller key; derive the caller key (no
//      network call before any of these)
//   1. the project number (projects.get, read-only token, cached)
//   2. GET /zones?name=<zone> -> the zone's account id
//   3. GET .../workers/scripts/<script>/settings: a 404 carrying Cloudflare's "Worker not found" code is
//      absent; any other 404 is a refusal. Present: GET .../content/v2; refuse unless the main module starts
//      with the marker; refuse a downgrade
//   4. GET .../workers/scripts/<DY_WORKER_NAME>/settings: the minter's Worker must exist in that account
//   5. "unchanged" (no write) only when the deployed script is ONE module, BYTE FOR BYTE the embedded gate,
//      with the same compatibility date, no compatibility flags, every log off and EXACTLY the wanted
//      bindings
//   6. otherwise ONE multipart PUT, then read the settings back and refuse unless they are exactly the
//      wanted ones -> "created" or "updated"
//
// SECRET HYGIENE: the session secret and the caller key go into the upload body and nowhere else. No result
// carries either, and every failure detail passes through withoutSecrets before it leaves, in case an
// upstream error ever quoted one. This module sends DY_CLIENT_SECRET nowhere (only app-client.ts sends it,
// to our app's /oauth/token; see the TRUST EDGE in src/session-gate/caller-key.ts). This module logs nothing.
//
// IDEMPOTENT: a re-run of a converged gate is "unchanged"; any other re-run uploads the same script with the
// same settings.

import type { Env } from "./env.js";
import { type EdgeGateDeployParams, edgeGateScriptNameFor } from "./dispatch-params.js";
import { CF_API, type CloudflareEnvelope, cloudflareErrorMessage, readPinnedServiceAccountKey, resolveZoneId } from "./actuate.js";
import { readProjectNumber } from "./session-gate/minter.js";
import { SESSION_GATE_SOURCE } from "./session-gate/gate-source.js";
import {
  CLIENT_SECRET_MIN_LENGTH,
  MINTER_CALLER_FINGERPRINT_BINDING,
  MINTER_CALLER_KEY_BINDING,
  deriveMinterCallerKey,
  isUsableClientSecret,
  minterCallerKeyFingerprint,
  minterCallerKeyHex,
} from "./session-gate/caller-key.js";
import { errorMessage, isWorkerScriptName } from "./util.js";

/** The first line of every gate this platform made starts with this, followed by the gate version. */
export const SESSION_GATE_MARKER_PREFIX = "// dy-session-gate v";
/** The module name the gate is uploaded under (its main_module). */
export const SESSION_GATE_MAIN_MODULE = "dy-session-gate.js";
/**
 * The gate's compatibility date. It is part of the gate: test/session-gate.test.ts pins it per marker
 * version next to gate.js's sha256, so changing it fails that test until the gate gets a new version.
 */
export const SESSION_GATE_COMPATIBILITY_DATE = "2026-01-01";
/** The named entrypoint of this Worker that the gate's DY_MINTER binding calls (src/index.ts). */
export const SESSION_GATE_MINTER_ENTRYPOINT = "SessionGateMinter";
/** The fixed message of the key fingerprint: HMAC-SHA256(key = the secret's UTF-8 text, this message). */
export const SESSION_KEY_FINGERPRINT_MESSAGE = "doubleyoup-session-key-fingerprint/v1";
const SESSION_KEY_FINGERPRINT_HEX_LENGTH = 16;
/**
 * Cloudflare's error code for "This Worker does not exist on your account" (wrangler's
 * WORKER_NOT_FOUND_ERR_CODE). Only a 404 that carries it means the script is absent.
 */
export const CLOUDFLARE_WORKER_NOT_FOUND_CODE = 10007;

/**
 * The logging settings of every gate upload: Workers Logs, invocation logs and traces off, logpush off, no
 * tail consumers. Sent explicitly, so no account default can turn a log on for a new gate.
 */
export const SESSION_GATE_LOGGING_METADATA = {
  logpush: false,
  observability: { enabled: false, logs: { enabled: false, invocation_logs: false }, traces: { enabled: false } },
  tail_consumers: [],
  streaming_tail_consumers: [],
} as const;

const BINDING_SESSION_SECRET = "DY_SESSION_SECRET";
const BINDING_ZONE_SUFFIX = "DY_ZONE_SUFFIX";
const BINDING_RUN_URL_SUFFIX = "DY_RUN_URL_SUFFIX";
const BINDING_MINTER = "DY_MINTER";
const BINDING_KEY_VERSION = "DY_SESSION_KEY_VERSION";
const BINDING_KEY_FINGERPRINT = "DY_SESSION_KEY_FINGERPRINT";

const SESSION_GATE_VERSION_RE = /^\/\/ dy-session-gate v([1-9][0-9]{0,5})(?:\r?\n|$)/;

const WORKERS_SCRIPTS_UNAUTHORIZED_HINT =
  "Cloudflare denied the Workers script call — CF_DNS_API_TOKEN needs Account → Workers Scripts: Edit on the account that holds the zone.";

export type EdgeGateDeployStatus = "created" | "updated" | "unchanged";

export type EdgeGateDeployResult =
  | {
      ok: true;
      op: "edge-gate-deploy";
      script: string;
      status: EdgeGateDeployStatus;
      /** The marker version of the gate now deployed. */
      gateVersion: number;
      keyVersion: number;
      /** sessionKeyFingerprint of the deployed secret. Non-secret. */
      keyFingerprint: string;
      /** `-<projectNumber>.<region>.run.app`: a session origin is `https://<service name>` + this. */
      runUrlSuffix: string;
      /** The Worker the gate's DY_MINTER binding calls (DY_WORKER_NAME, a valid script name). */
      minterWorker: string;
    }
  | { ok: false; op: "edge-gate-deploy"; script: string; detail: string; foreign?: true };

/** The gate version in a script's first line, or null when the script does not start with the marker. */
export function sessionGateVersionOf(source: string): number | null {
  const match = SESSION_GATE_VERSION_RE.exec(source);
  if (match === null) {
    return null;
  }
  return Number(match[1]);
}

/** The Cloud Run URL suffix of a project and region: `-<projectNumber>.<region>.run.app`. */
export function sessionGateRunUrlSuffix(projectNumber: string, region: string): string {
  return `-${projectNumber}.${region}.run.app`;
}

/**
 * A NON-SECRET fingerprint of a session secret: the first 16 hex characters of
 * HMAC-SHA256(key = the secret's UTF-8 text, message = SESSION_KEY_FINGERPRINT_MESSAGE). It shows that the
 * secret changed without revealing it (64 bits of an HMAC output say nothing usable about the key).
 */
export async function sessionKeyFingerprint(sessionSecret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(sessionSecret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(SESSION_KEY_FINGERPRINT_MESSAGE)));
  let hex = "";
  for (const byte of mac) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex.slice(0, SESSION_KEY_FINGERPRINT_HEX_LENGTH);
}

/** `text` with every occurrence of each secret value replaced, so no failure detail can carry one. */
function withoutSecrets(text: string, secretValues: string[]): string {
  let redacted = text;
  for (const secretValue of secretValues) {
    redacted = redacted.split(secretValue).join("[redacted]");
  }
  return redacted;
}

/** One binding in the script upload metadata. */
type GateBinding =
  | { type: "secret_text"; name: string; text: string }
  | { type: "plain_text"; name: string; text: string }
  | { type: "service"; name: string; service: string; entrypoint: string };

/** The bindings a gate for this cell must have — the ONE list both the upload and the comparison use. */
function wantedGateBindings(input: {
  sessionSecret: string;
  zone: string;
  runUrlSuffix: string;
  keyVersion: number;
  keyFingerprint: string;
  workerName: string;
  callerKeyHex: string;
  callerKeyFingerprint: string;
}): GateBinding[] {
  return [
    { type: "secret_text", name: BINDING_SESSION_SECRET, text: input.sessionSecret },
    { type: "plain_text", name: BINDING_ZONE_SUFFIX, text: `.${input.zone}` },
    { type: "plain_text", name: BINDING_RUN_URL_SUFFIX, text: input.runUrlSuffix },
    { type: "service", name: BINDING_MINTER, service: input.workerName, entrypoint: SESSION_GATE_MINTER_ENTRYPOINT },
    { type: "plain_text", name: BINDING_KEY_VERSION, text: String(input.keyVersion) },
    // Review L4: the fingerprint is written ONLY here, from the job's secret. Cloudflare never returns a
    // secret_text value, so a DY_SESSION_SECRET changed OUTSIDE edge-gate-deploy (a hand `wrangler secret
    // put`) keeps this old fingerprint, and the next deploy with the same secret reports "unchanged" while
    // the gate runs the other key. Only a change made through this op is visible here.
    { type: "plain_text", name: BINDING_KEY_FINGERPRINT, text: input.keyFingerprint },
    // Gate v2: the same rule for the caller key. A DY_MINTER_CALLER_KEY changed by hand keeps the old
    // fingerprint and reads "unchanged"; the minter then refuses every proof, so that gate answers 503.
    { type: "secret_text", name: MINTER_CALLER_KEY_BINDING, text: input.callerKeyHex },
    { type: "plain_text", name: MINTER_CALLER_FINGERPRINT_BINDING, text: input.callerKeyFingerprint },
  ];
}

/**
 * A comparable form of one binding as Cloudflare's settings read reports it. A secret_text compares by
 * name and type only (Cloudflare never returns the value, and no value is put in the signature). A service
 * binding compares its target Worker and entrypoint.
 */
function bindingSignature(binding: Record<string, unknown>): string {
  if (binding.type === "secret_text") {
    return "secret_text";
  }
  if (binding.type === "plain_text" && typeof binding.text === "string") {
    return `plain_text:${binding.text}`;
  }
  if (binding.type === "service" && typeof binding.service === "string") {
    let entrypoint = "";
    if (typeof binding.entrypoint === "string") {
      entrypoint = binding.entrypoint;
    }
    return `service:${binding.service}:${entrypoint}`;
  }
  return `other:${String(binding.type)}`;
}

/** True when `actual` (a settings read) is EXACTLY `wanted`: the same names, each with the same signature. */
function bindingsMatch(actual: unknown[], wanted: GateBinding[]): boolean {
  if (actual.length !== wanted.length) {
    return false;
  }
  const actualByName = new Map<string, string>();
  for (const entry of actual) {
    if (entry === null || typeof entry !== "object") {
      return false;
    }
    const binding = entry as Record<string, unknown>;
    if (typeof binding.name !== "string" || actualByName.has(binding.name)) {
      return false;
    }
    actualByName.set(binding.name, bindingSignature(binding));
  }
  for (const binding of wanted) {
    if (actualByName.get(binding.name) !== bindingSignature(binding as unknown as Record<string, unknown>)) {
      return false;
    }
  }
  return true;
}

/** The parts of a script's settings read that the gate's state depends on. */
interface ScriptSettings {
  bindings: unknown[];
  compatibilityDate: unknown;
  compatibilityFlags: unknown;
  logpush: unknown;
  observability: unknown;
  tailConsumers: unknown;
  streamingTailConsumers: unknown;
}

/** True when `value` is absent or an empty list (no consumers, no flags). */
function isAbsentOrEmptyList(value: unknown): boolean {
  if (value === undefined || value === null) {
    return true;
  }
  return Array.isArray(value) && value.length === 0;
}

/** True when an observability sub-setting (`logs`, `traces`) is absent or not enabled. */
function isSubSettingOff(value: unknown): boolean {
  if (value === undefined || value === null) {
    return true;
  }
  if (typeof value !== "object") {
    return false;
  }
  return (value as { enabled?: unknown }).enabled !== true;
}

/**
 * True when no log can record a gate request: logpush not on, no tail or streaming-tail consumer, and
 * observability absent or with its master switch, logs and traces all not on. Cloudflare fills defaults
 * into what it reports (head_sampling_rate, persist, ...), so only the switches are compared.
 */
function loggingIsOff(settings: ScriptSettings): boolean {
  if (settings.logpush === true) {
    return false;
  }
  if (!isAbsentOrEmptyList(settings.tailConsumers) || !isAbsentOrEmptyList(settings.streamingTailConsumers)) {
    return false;
  }
  const observability = settings.observability;
  if (observability === undefined || observability === null) {
    return true;
  }
  if (typeof observability !== "object") {
    return false;
  }
  const switches = observability as { enabled?: unknown; logs?: unknown; traces?: unknown };
  if (switches.enabled === true) {
    return false;
  }
  return isSubSettingOff(switches.logs) && isSubSettingOff(switches.traces);
}

/** True when the settings are exactly what an upload of the embedded gate with `wanted` gives. */
function settingsMatch(settings: ScriptSettings, wanted: GateBinding[]): boolean {
  if (settings.compatibilityDate !== SESSION_GATE_COMPATIBILITY_DATE) {
    return false;
  }
  if (!isAbsentOrEmptyList(settings.compatibilityFlags)) {
    return false;
  }
  if (!loggingIsOff(settings)) {
    return false;
  }
  return bindingsMatch(settings.bindings, wanted);
}

/** The URL of one Worker script in one account. */
function workerScriptUrl(accountId: string, scriptName: string): string {
  return `${CF_API}/accounts/${encodeURIComponent(accountId)}/workers/scripts/${encodeURIComponent(scriptName)}`;
}

/** True when a Cloudflare envelope carries the error `code`. */
function hasCloudflareErrorCode(body: CloudflareEnvelope | null, code: number): boolean {
  if (body === null || !Array.isArray(body.errors)) {
    return false;
  }
  return body.errors.some((error) => error?.code === code);
}

type ScriptSettingsRead = { kind: "absent" } | { kind: "present"; settings: ScriptSettings } | { kind: "failed"; detail: string };

/**
 * GET a script's settings. A 404 is "absent" ONLY when it carries Cloudflare's "Worker not found" code: any
 * other 404 (a wrong path, an account the token cannot see, a proxy in the way) is a refusal, so a gate is
 * never created over a script that merely failed to answer. Never throws.
 */
async function readScriptSettings(token: string, accountId: string, scriptName: string): Promise<ScriptSettingsRead> {
  let response: Response;
  try {
    response = await fetch(`${workerScriptUrl(accountId, scriptName)}/settings`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { kind: "failed", detail: `could not reach Cloudflare to read the settings of Worker "${scriptName}": ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { kind: "failed", detail: WORKERS_SCRIPTS_UNAUTHORIZED_HINT };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 404) {
    if (hasCloudflareErrorCode(body, CLOUDFLARE_WORKER_NOT_FOUND_CODE)) {
      return { kind: "absent" };
    }
    return {
      kind: "failed",
      detail:
        `reading the settings of Worker "${scriptName}" answered HTTP 404 without Cloudflare's "Worker not found" ` +
        `error (code ${CLOUDFLARE_WORKER_NOT_FOUND_CODE})${cloudflareErrorMessage(body)}, so it is not treated as absent.`,
    };
  }
  const result = body?.success ? (body.result as Record<string, unknown> | null | undefined) : undefined;
  if (!result || !Array.isArray(result.bindings)) {
    return { kind: "failed", detail: `reading the settings of Worker "${scriptName}" failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return {
    kind: "present",
    settings: {
      bindings: result.bindings,
      compatibilityDate: result.compatibility_date,
      compatibilityFlags: result.compatibility_flags,
      logpush: result.logpush,
      observability: result.observability,
      tailConsumers: result.tail_consumers,
      streamingTailConsumers: result.streaming_tail_consumers,
    },
  };
}

/** A deployed script's main module, and how it is packaged. */
interface DeployedScriptSource {
  source: string;
  /** "module" for an ES-module Worker (multipart answer), "service-worker" for a plain-text script. */
  format: "module" | "service-worker";
  /** How many modules the script has (1 for a service-worker script). */
  moduleCount: number;
}

/**
 * GET a script's MAIN MODULE source (content/v2). A module Worker answers multipart/form-data with one part
 * per module and names the main one in the `cf-entrypoint` header (wrangler's own reader relies on the
 * same); a service-worker script answers its plain text. Anything unreadable is a failure, so the caller
 * never takes a script over on a guess.
 */
async function readScriptMainModule(
  token: string,
  accountId: string,
  scriptName: string,
): Promise<{ ok: true; script: DeployedScriptSource } | { ok: false; detail: string }> {
  const unreadable = (why: string) => ({
    ok: false as const,
    detail: `the source of the existing Worker "${scriptName}" could not be read (${why}), so it is not replaced`,
  });
  let response: Response;
  try {
    response = await fetch(`${workerScriptUrl(accountId, scriptName)}/content/v2`, {
      headers: { authorization: `Bearer ${token}` },
    });
  } catch (err) {
    return unreadable(`Cloudflare could not be reached: ${errorMessage(err)}`);
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { ok: false, detail: WORKERS_SCRIPTS_UNAUTHORIZED_HINT };
  }
  if (response.status !== 200) {
    await response.text().catch(() => "");
    return unreadable(`HTTP ${response.status}`);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("multipart/form-data")) {
    return { ok: true, script: { source: await response.text(), format: "service-worker", moduleCount: 1 } };
  }
  // formData() throws on a malformed multipart body, which must refuse, not crash the op.
  let form: FormData;
  try {
    form = await response.formData();
  } catch (err) {
    return unreadable(`the multipart answer could not be parsed: ${errorMessage(err)}`);
  }
  const partNames = new Set<string>(form.keys());
  let mainModuleName = response.headers.get("cf-entrypoint");
  if (mainModuleName === null) {
    if (partNames.size !== 1) {
      return unreadable(`no cf-entrypoint header and ${partNames.size} modules`);
    }
    mainModuleName = [...partNames][0] as string;
  }
  const mainModule = form.get(mainModuleName);
  if (mainModule === null) {
    return unreadable(`no part for the main module "${mainModuleName}"`);
  }
  let source: string;
  if (typeof mainModule === "string") {
    source = mainModule;
  } else {
    source = await mainModule.text();
  }
  return { ok: true, script: { source, format: "module", moduleCount: partNames.size } };
}

/**
 * True when the deployed script runs EXACTLY the embedded gate: one ES module whose text is
 * SESSION_GATE_SOURCE byte for byte. The marker alone proves nothing (anyone with Scripts:Edit can write
 * it), so only the full text counts.
 */
function isEmbeddedGate(script: DeployedScriptSource): boolean {
  return script.format === "module" && script.moduleCount === 1 && script.source === SESSION_GATE_SOURCE;
}

/**
 * ONE multipart PUT of the gate: the module and its metadata (main_module, compatibility date, bindings and
 * the logging settings, all off).
 */
async function uploadGateScript(token: string, accountId: string, scriptName: string, bindings: GateBinding[]): Promise<{ ok: true } | { ok: false; detail: string }> {
  const metadata = {
    main_module: SESSION_GATE_MAIN_MODULE,
    compatibility_date: SESSION_GATE_COMPATIBILITY_DATE,
    bindings,
    ...SESSION_GATE_LOGGING_METADATA,
  };
  const form = new FormData();
  form.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
  form.append(SESSION_GATE_MAIN_MODULE, new Blob([SESSION_GATE_SOURCE], { type: "application/javascript+module" }), SESSION_GATE_MAIN_MODULE);

  let response: Response;
  try {
    // No content-type header: FormData sets the multipart boundary itself.
    response = await fetch(workerScriptUrl(accountId, scriptName), {
      method: "PUT",
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      body: form,
    });
  } catch (err) {
    return { ok: false, detail: `could not reach Cloudflare to upload the gate script: ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { ok: false, detail: WORKERS_SCRIPTS_UNAUTHORIZED_HINT };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!body?.success) {
    return { ok: false, detail: `the gate script upload failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return { ok: true };
}

export async function actuateEdgeGateDeploy(params: EdgeGateDeployParams, env: Env): Promise<EdgeGateDeployResult> {
  const script = edgeGateScriptNameFor(params.project, params.region);
  // Every secret value the upload carries: the session secret now, the caller key once it is derived.
  const secretValues: string[] = [params.sessionSecret];
  const failure = (detail: string, foreign?: true): EdgeGateDeployResult => {
    const result: EdgeGateDeployResult = { ok: false, op: "edge-gate-deploy", script, detail: withoutSecrets(detail, secretValues) };
    if (foreign) {
      result.foreign = true;
    }
    return result;
  };

  // 0. No network call before these.
  const pin = readPinnedServiceAccountKey(env, params.project);
  if (!pin.ok) {
    return failure(pin.detail);
  }
  const workerName = env.DY_WORKER_NAME;
  if (!workerName) {
    return failure(
      "DY_WORKER_NAME is not set on this Worker. Set it to this Worker's own script name as Cloudflare shows it " +
        "(`wrangler secret put DY_WORKER_NAME`), so the session gate can call this Worker's SessionGateMinter.",
    );
  }
  if (!isWorkerScriptName(workerName)) {
    // The value is not echoed: it is not a script name, so it could be anything.
    return failure('DY_WORKER_NAME is not a Worker script name (lowercase letters, digits, "-" and "_", at most 63 characters).');
  }
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return failure("CF_DNS_API_TOKEN is not configured on this Worker.");
  }
  if (!isUsableClientSecret(env.DY_CLIENT_SECRET)) {
    // The rule only, never the value. Without a usable root the gate would get a key anyone could compute.
    return failure(
      `DY_CLIENT_SECRET is not set on this Worker, or is shorter than ${CLIENT_SECRET_MIN_LENGTH} characters. It is the root ` +
        "of the session gate's minter caller key, so the gate is not deployed without it. Set it to the client secret the " +
        "platform issued at onboarding.",
    );
  }
  // The gate's caller key (planning/49 Phase 4 I3): bound to this gate script, so it signs only for this cell.
  const callerKey = await deriveMinterCallerKey(env.DY_CLIENT_SECRET, script);
  const callerKeyHex = minterCallerKeyHex(callerKey);
  secretValues.push(callerKeyHex);
  const callerKeyFingerprint = await minterCallerKeyFingerprint(callerKey);
  const gateVersion = sessionGateVersionOf(SESSION_GATE_SOURCE);
  if (gateVersion === null) {
    // Unreachable while test/session-gate.test.ts passes; never upload a gate a later deploy cannot recognise.
    return failure("the embedded gate script does not start with its marker line, so it is not uploaded");
  }

  // 1. The project number, for the Cloud Run URL suffix.
  const projectNumber = await readProjectNumber(env, params.project);
  if (!projectNumber.ok) {
    return failure(projectNumber.detail);
  }
  const runUrlSuffix = sessionGateRunUrlSuffix(projectNumber.projectNumber, params.region);

  // 2. The zone's account: the gate must live in the account whose routes will run it.
  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) {
    return failure(zone.error);
  }
  if (zone.accountId === null) {
    return failure(`the zone lookup for "${params.zone}" reported no Cloudflare account, so the gate has nowhere to go`);
  }

  // 3. The existing gate, if any. Never take over a script this platform did not make, never downgrade.
  const existing = await readScriptSettings(token, zone.accountId, script);
  if (existing.kind === "failed") {
    return failure(existing.detail);
  }
  let existingScript: DeployedScriptSource | null = null;
  if (existing.kind === "present") {
    const read = await readScriptMainModule(token, zone.accountId, script);
    if (!read.ok) {
      return failure(read.detail);
    }
    const existingVersion = sessionGateVersionOf(read.script.source);
    if (existingVersion === null) {
      return failure(
        `a Worker named "${script}" already exists and does not start with the session gate's marker, so this platform did not make it. It was left unchanged.`,
        true,
      );
    }
    if (existingVersion > gateVersion) {
      return failure(
        `the deployed "${script}" is session gate v${existingVersion}, newer than this Worker's v${gateVersion}: this fork is older ` +
          "than the deployed gate, so it does not overwrite it. Sync the fork, then deploy again.",
      );
    }
    existingScript = read.script;
  }

  // 4. The minter's Worker must exist in the same account, or the gate's binding would point nowhere.
  const minterWorker = await readScriptSettings(token, zone.accountId, workerName);
  if (minterWorker.kind === "failed") {
    return failure(minterWorker.detail);
  }
  if (minterWorker.kind === "absent") {
    return failure(
      `DY_WORKER_NAME ("${workerName}") names no Worker script in the Cloudflare account that holds zone "${params.zone}". ` +
        "Set it to this Worker's own script name as Cloudflare shows it.",
    );
  }

  // 5. Unchanged: exactly the embedded gate, with exactly the wanted settings. The wanted bindings include
  // both fingerprints, so a changed session secret OR a changed caller key is "updated", never "unchanged".
  const keyFingerprint = await sessionKeyFingerprint(params.sessionSecret);
  const wanted = wantedGateBindings({
    sessionSecret: params.sessionSecret,
    zone: params.zone,
    runUrlSuffix,
    keyVersion: params.keyVersion,
    keyFingerprint,
    workerName,
    callerKeyHex,
    callerKeyFingerprint,
  });
  const success = (status: EdgeGateDeployStatus): EdgeGateDeployResult => ({
    ok: true,
    op: "edge-gate-deploy",
    script,
    status,
    gateVersion,
    keyVersion: params.keyVersion,
    keyFingerprint,
    runUrlSuffix,
    minterWorker: workerName,
  });
  if (existing.kind === "present" && existingScript !== null && isEmbeddedGate(existingScript) && settingsMatch(existing.settings, wanted)) {
    return success("unchanged");
  }

  // 6. One upload, then the read-back: what Cloudflare reports now is what the gate runs with.
  // UNAVOIDABLE RACE (review L2): Cloudflare has no conditional PUT for a Worker script (no If-Match on a
  // version), so between the marker check in step 3 and this PUT another writer with Scripts:Edit could
  // replace the script, and this PUT would then overwrite that script. The window is one request long, the
  // name is derived per cell, and only holders of the account's Scripts:Edit can write there.
  const upload = await uploadGateScript(token, zone.accountId, script, wanted);
  if (!upload.ok) {
    return failure(upload.detail);
  }
  const readBack = await readScriptSettings(token, zone.accountId, script);
  if (readBack.kind !== "present") {
    let why = "the script is absent";
    if (readBack.kind === "failed") {
      why = readBack.detail;
    }
    return failure(`the gate script was uploaded, but its settings could not be read back: ${why}`);
  }
  if (!settingsMatch(readBack.settings, wanted)) {
    return failure(
      `the gate script was uploaded, but the settings Cloudflare reports for "${script}" (bindings, compatibility date or logging) are not the ones sent`,
    );
  }
  if (existing.kind === "absent") {
    return success("created");
  }
  return success("updated");
}
