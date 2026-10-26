// planning/49 Phase 3 (I4): edge-gate-deploy (src/actuate-edge-gate.ts) against a fake Cloudflare account.
// The fake keeps scripts in memory and answers the settings read, the content/v2 read and the multipart PUT
// the way Cloudflare does: a secret_text binding is reported WITHOUT its value, a missing script is a 404
// with error code 10007, and the observability settings come back with Cloudflare's defaults filled in.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env.js";
import type { EdgeGateDeployParams } from "../src/dispatch-params.js";
import {
  actuateEdgeGateDeploy,
  SESSION_GATE_COMPATIBILITY_DATE,
  SESSION_GATE_MAIN_MODULE,
  sessionGateVersionOf,
  sessionKeyFingerprint,
} from "../src/actuate-edge-gate.js";
import { SESSION_GATE_SOURCE } from "../src/session-gate/gate-source.js";

const PROJECT = "dy-agency-proof";
const REGION = "australia-southeast2";
const ZONE = "sbmstudio.com.au";
const ACCOUNT_ID = "acct-sbm";
const PROJECT_NUMBER = "123456789012";
const GATE_SCRIPT = "dy-gate-dy-agency-proof-australia-southeast2";
const WORKER_NAME = "sbmstudio";
const CF_TOKEN = "cf-dns-token-abc";
const SECRET_V1 = "603807493e9f841f3f587631aad45bc075fa1cc8ec73adba4872405dc05ba367";
const SECRET_V2 = "46d993d0738e210e275c771df8fe78ef9e98c6cf3b1faa2ed222a7d93f51b572";
const PARAMS: EdgeGateDeployParams = { project: PROJECT, region: REGION, zone: ZONE, sessionSecret: SECRET_V1, keyVersion: 1 };
const SCRIPTS_URL = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/scripts`;

// The settings Cloudflare reports for a gate uploaded with every log off (defaults filled in, as the API does).
const LOGGING_OFF_SETTINGS: Record<string, unknown> = {
  compatibility_date: "2026-01-01",
  compatibility_flags: [],
  logpush: false,
  observability: {
    enabled: false,
    head_sampling_rate: 1,
    logs: { enabled: false, head_sampling_rate: 1, invocation_logs: false, persist: true },
    traces: { enabled: false, head_sampling_rate: 1, persist: true },
  },
  tail_consumers: null,
};

let serviceAccountKey: string;

beforeAll(async () => {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = Buffer.from((await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)) as ArrayBuffer).toString("base64");
  serviceAccountKey = JSON.stringify({
    type: "service_account",
    project_id: PROJECT,
    private_key: `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`,
    client_email: `sa@${PROJECT}.iam.gserviceaccount.com`,
    token_uri: "https://oauth2.googleapis.com/token",
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function envWith(overrides: Partial<Env> = {}): Env {
  return {
    APP_BASE_URL: "https://app.example.test",
    DY_CLIENT_ID: "client-abc",
    DY_CLIENT_SECRET: "secret-xyz",
    NONCE_STORE: undefined as unknown as Env["NONCE_STORE"],
    GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey,
    CF_DNS_API_TOKEN: CF_TOKEN,
    DY_WORKER_NAME: WORKER_NAME,
    ...overrides,
  };
}

/** The bindings Cloudflare reports for a gate of `secret` (no value for the secret_text). */
async function reportedGateBindings(secret: string, keyVersion = 1, workerName = WORKER_NAME): Promise<unknown[]> {
  return [
    { type: "secret_text", name: "DY_SESSION_SECRET" },
    { type: "plain_text", name: "DY_ZONE_SUFFIX", text: `.${ZONE}` },
    { type: "plain_text", name: "DY_RUN_URL_SUFFIX", text: `-${PROJECT_NUMBER}.${REGION}.run.app` },
    { type: "service", name: "DY_MINTER", service: workerName, entrypoint: "SessionGateMinter", environment: "production" },
    { type: "plain_text", name: "DY_SESSION_KEY_VERSION", text: String(keyVersion) },
    { type: "plain_text", name: "DY_SESSION_KEY_FINGERPRINT", text: await sessionKeyFingerprint(secret) },
  ];
}

interface FakeScript {
  /** "module" answers content/v2 as multipart, "service-worker" as plain text. */
  format: "module" | "service-worker";
  source: string;
  bindings: unknown[];
  /** The other settings Cloudflare reports. Default: LOGGING_OFF_SETTINGS. */
  settings?: Record<string, unknown>;
  /** Leave out the cf-entrypoint header on the multipart answer (then one module only). */
  noEntrypointHeader?: boolean;
  /** Add a second module next to the main one. */
  extraModule?: boolean;
}

interface FakeCloudflareOptions {
  scripts?: Record<string, FakeScript>;
  zoneAccountId?: string | null;
  settingsStatus?: number;
  /** For a script that does not exist: answer 404 with this body instead of Cloudflare's code 10007. */
  notFoundBody?: unknown;
  contentStatus?: number;
  putReply?: { status: number; body: unknown };
  /** Drop this binding name from what the settings read reports after a PUT. */
  dropAfterPut?: string;
  /** Report these settings after a PUT, over what the PUT sent. */
  reportAfterPut?: Record<string, unknown>;
}

interface RecordedCall {
  method: string;
  url: string;
  auth: string | null;
  metadata?: Record<string, unknown>;
  moduleSource?: string;
}

/** What Cloudflare reports for the settings an upload's metadata asked for (defaults filled in). */
function settingsReportedFor(metadata: Record<string, unknown>): Record<string, unknown> {
  const observability = (metadata.observability ?? {}) as { enabled?: boolean; logs?: Record<string, unknown>; traces?: Record<string, unknown> };
  return {
    compatibility_date: metadata.compatibility_date,
    compatibility_flags: metadata.compatibility_flags ?? [],
    logpush: metadata.logpush ?? false,
    observability: {
      enabled: observability.enabled ?? false,
      head_sampling_rate: 1,
      logs: { head_sampling_rate: 1, persist: true, invocation_logs: true, ...observability.logs },
      traces: { head_sampling_rate: 1, persist: true, enabled: false, ...observability.traces },
    },
    tail_consumers: metadata.tail_consumers ?? null,
    streaming_tail_consumers: metadata.streaming_tail_consumers ?? null,
  };
}

/** A fake Cloudflare account + Google (token endpoint and projects.get). Records every call. */
function fakeCloudflare(options: FakeCloudflareOptions = {}) {
  const scripts = new Map<string, FakeScript>(Object.entries(options.scripts ?? {}));
  const calls: RecordedCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      const method = init?.method ?? "GET";
      const auth = new Headers(init?.headers).get("authorization");

      if (url === "https://oauth2.googleapis.com/token") {
        return Response.json({ access_token: "google-read-only", expires_in: 3600 });
      }
      if (url === `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}`) {
        return Response.json({ projectId: PROJECT, projectNumber: PROJECT_NUMBER });
      }

      const call: RecordedCall = { method, url, auth };
      calls.push(call);
      const parsed = new URL(url);

      if (parsed.pathname === "/client/v4/zones") {
        const zone: Record<string, unknown> = { id: "zone-sbm", name: ZONE };
        if (options.zoneAccountId !== null) {
          zone.account = { id: options.zoneAccountId ?? ACCOUNT_ID };
        }
        return Response.json({ success: true, result: [zone] });
      }

      const scriptMatch = /^\/client\/v4\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)(\/settings|\/content\/v2)?$/.exec(parsed.pathname);
      if (scriptMatch === null || scriptMatch[1] !== ACCOUNT_ID) {
        throw new Error(`unexpected fetch ${method} ${url}`);
      }
      const scriptName = decodeURIComponent(scriptMatch[2] as string);
      const suffix = scriptMatch[3];
      const script = scripts.get(scriptName);

      if (suffix === "/settings" && method === "GET") {
        if (options.settingsStatus !== undefined) {
          return Response.json({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }, { status: options.settingsStatus });
        }
        if (script === undefined) {
          if (options.notFoundBody !== undefined) {
            return Response.json(options.notFoundBody, { status: 404 });
          }
          return Response.json({ success: false, errors: [{ code: 10007, message: "This Worker does not exist on your account." }] }, { status: 404 });
        }
        return Response.json({ success: true, result: { ...(script.settings ?? LOGGING_OFF_SETTINGS), bindings: script.bindings } });
      }

      if (suffix === "/content/v2" && method === "GET") {
        if (options.contentStatus !== undefined) {
          return new Response("error", { status: options.contentStatus });
        }
        if (script === undefined) {
          return Response.json({ success: false }, { status: 404 });
        }
        if (script.format === "service-worker") {
          return new Response(script.source, { headers: { "content-type": "application/javascript" } });
        }
        if (script.noEntrypointHeader) {
          const single = new FormData();
          single.append("only.js", new Blob([script.source], { type: "application/javascript+module" }), "only.js");
          return new Response(single);
        }
        const form = new FormData();
        if (script.extraModule) {
          form.append("helper.js", new Blob(["export const helper = 1;"], { type: "application/javascript+module" }), "helper.js");
        }
        form.append("main.js", new Blob([script.source], { type: "application/javascript+module" }), "main.js");
        return new Response(form, { headers: { "cf-entrypoint": "main.js" } });
      }

      if (suffix === undefined && method === "PUT") {
        const form = init?.body as FormData;
        call.metadata = JSON.parse(await (form.get("metadata") as Blob).text()) as Record<string, unknown>;
        call.moduleSource = await (form.get(SESSION_GATE_MAIN_MODULE) as Blob).text();
        if (options.putReply !== undefined) {
          return Response.json(options.putReply.body, { status: options.putReply.status });
        }
        // Cloudflare reports a secret_text binding without its value.
        const sent = call.metadata.bindings as Array<Record<string, unknown>>;
        const reported: unknown[] = [];
        for (const binding of sent) {
          if (binding.name === options.dropAfterPut) {
            continue;
          }
          if (binding.type === "secret_text") {
            reported.push({ type: "secret_text", name: binding.name });
            continue;
          }
          reported.push({ ...binding });
        }
        const settings = { ...settingsReportedFor(call.metadata), ...options.reportAfterPut };
        scripts.set(scriptName, { format: "module", source: call.moduleSource, bindings: reported, settings });
        return Response.json({ success: true, result: { id: scriptName } });
      }

      throw new Error(`unexpected fetch ${method} ${url}`);
    }),
  );
  return { calls, scripts };
}

/** The minter's Worker, present in the account. */
function minterWorkerScript(): FakeScript {
  return { format: "module", source: "export default {}", bindings: [] };
}

/** The converged gate as a deploy of PARAMS leaves it. */
async function convergedGateScript(overrides: Partial<FakeScript> = {}): Promise<FakeScript> {
  return { format: "module", source: SESSION_GATE_SOURCE, bindings: await reportedGateBindings(SECRET_V1), ...overrides };
}

function expectNoSecretIn(value: unknown, secret = SECRET_V1): void {
  expect(JSON.stringify(value)).not.toContain(secret);
}

describe("edge-gate-deploy helpers", () => {
  it("sessionKeyFingerprint is the first 16 hex of HMAC-SHA256(secret text, the fixed message)", async () => {
    const hmacKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET_V1), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode("doubleyoup-session-key-fingerprint/v1")));
    const expected = Buffer.from(mac).toString("hex").slice(0, 16);
    expect(await sessionKeyFingerprint(SECRET_V1)).toBe(expected);
    expect(await sessionKeyFingerprint(SECRET_V2)).not.toBe(expected);
    expect(expected).toMatch(/^[0-9a-f]{16}$/);
  });

  it("sessionGateVersionOf reads the marker of the FIRST line only", () => {
    expect(sessionGateVersionOf(SESSION_GATE_SOURCE)).toBe(1);
    expect(sessionGateVersionOf("// dy-session-gate v12\nexport default {}")).toBe(12);
    expect(sessionGateVersionOf("// dy-session-gate v3")).toBe(3);
    expect(sessionGateVersionOf("// dy-session-gate v3\r\nx")).toBe(3);
    expect(sessionGateVersionOf("export default {}\n// dy-session-gate v1")).toBeNull();
    expect(sessionGateVersionOf(" // dy-session-gate v1\n")).toBeNull();
    expect(sessionGateVersionOf("// dy-session-gate v0\n")).toBeNull();
    expect(sessionGateVersionOf("// dy-session-gate v1x\n")).toBeNull();
    expect(sessionGateVersionOf("// dy-edge-gate\n")).toBeNull();
  });
});

describe("actuateEdgeGateDeploy", () => {
  it("creates the gate: ONE multipart PUT of the embedded script with the six bindings and every log OFF, then reads them back", async () => {
    const { calls } = fakeCloudflare({ scripts: { [WORKER_NAME]: minterWorkerScript() } });

    const result = await actuateEdgeGateDeploy(PARAMS, envWith());

    const fingerprint = await sessionKeyFingerprint(SECRET_V1);
    expect(result).toEqual({
      ok: true,
      op: "edge-gate-deploy",
      script: GATE_SCRIPT,
      status: "created",
      gateVersion: 1,
      keyVersion: 1,
      keyFingerprint: fingerprint,
      runUrlSuffix: `-${PROJECT_NUMBER}.${REGION}.run.app`,
      minterWorker: WORKER_NAME,
    });
    expectNoSecretIn(result);

    const puts = calls.filter((call) => call.method === "PUT");
    expect(puts).toHaveLength(1);
    const put = puts[0] as RecordedCall;
    expect(put.url).toBe(`${SCRIPTS_URL}/${GATE_SCRIPT}`);
    expect(put.moduleSource).toBe(SESSION_GATE_SOURCE);
    expect(put.metadata).toEqual({
      main_module: SESSION_GATE_MAIN_MODULE,
      compatibility_date: SESSION_GATE_COMPATIBILITY_DATE,
      bindings: [
        { type: "secret_text", name: "DY_SESSION_SECRET", text: SECRET_V1 },
        { type: "plain_text", name: "DY_ZONE_SUFFIX", text: `.${ZONE}` },
        { type: "plain_text", name: "DY_RUN_URL_SUFFIX", text: `-${PROJECT_NUMBER}.${REGION}.run.app` },
        { type: "service", name: "DY_MINTER", service: WORKER_NAME, entrypoint: "SessionGateMinter" },
        { type: "plain_text", name: "DY_SESSION_KEY_VERSION", text: "1" },
        { type: "plain_text", name: "DY_SESSION_KEY_FINGERPRINT", text: fingerprint },
      ],
      // Review L7: no log, logpush job or tail may record a gate request (tokens travel in the URL and cookie).
      logpush: false,
      observability: { enabled: false, logs: { enabled: false, invocation_logs: false }, traces: { enabled: false } },
      tail_consumers: [],
      streaming_tail_consumers: [],
    });
    // The read order: zone, the gate's settings (absent), the minter Worker's settings, the PUT, the read-back.
    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET https://api.cloudflare.com/client/v4/zones?name=${ZONE}&per_page=2`,
      `GET ${SCRIPTS_URL}/${GATE_SCRIPT}/settings`,
      `GET ${SCRIPTS_URL}/${WORKER_NAME}/settings`,
      `PUT ${SCRIPTS_URL}/${GATE_SCRIPT}`,
      `GET ${SCRIPTS_URL}/${GATE_SCRIPT}/settings`,
    ]);
    for (const call of calls) {
      expect(call.auth).toBe(`Bearer ${CF_TOKEN}`);
    }
  });

  it("is unchanged ONLY for one module that is the embedded gate byte for byte, with the same date, every log off and exactly the wanted bindings", async () => {
    const { calls } = fakeCloudflare({ scripts: { [WORKER_NAME]: minterWorkerScript(), [GATE_SCRIPT]: await convergedGateScript() } });
    const result = await actuateEdgeGateDeploy(PARAMS, envWith());
    expect(result).toMatchObject({ ok: true, status: "unchanged", script: GATE_SCRIPT, keyVersion: 1 });
    expect(calls.filter((call) => call.method !== "GET")).toHaveLength(0);
    expect(calls.map((call) => call.url)).toContain(`${SCRIPTS_URL}/${GATE_SCRIPT}/content/v2`);
  });

  it("updates anything else that carries the marker: other bytes, another module, another date or flags, a log on, other bindings", async () => {
    const converged = await convergedGateScript();
    const cases: Array<{ name: string; existing: FakeScript; params?: EdgeGateDeployParams }> = [
      { name: "new secret, same version number", existing: converged, params: { ...PARAMS, sessionSecret: SECRET_V2 } },
      { name: "new key version", existing: converged, params: { ...PARAMS, sessionSecret: SECRET_V2, keyVersion: 2 } },
      // Review M1: the marker and a self-written fingerprint prove nothing; only the full text counts.
      { name: "the same marker, other bytes", existing: { ...converged, source: `${SESSION_GATE_SOURCE}\nexport const extra = 1;\n` } },
      { name: "the marker alone", existing: { ...converged, source: "// dy-session-gate v1\nexport default { fetch() { return fetch('https://evil.example'); } }" } },
      { name: "a second module next to the exact gate", existing: { ...converged, extraModule: true } },
      { name: "a service-worker script with the exact text", existing: { ...converged, format: "service-worker" } },
      { name: "a multipart answer without cf-entrypoint, one module, no bindings", existing: { ...converged, noEntrypointHeader: true, bindings: [] } },
      { name: "the minter bound to another Worker", existing: { ...converged, bindings: await reportedGateBindings(SECRET_V1, 1, "agencydoubleyoup") } },
      { name: "another compatibility date", existing: { ...converged, settings: { ...LOGGING_OFF_SETTINGS, compatibility_date: "2025-01-01" } } },
      { name: "compatibility flags", existing: { ...converged, settings: { ...LOGGING_OFF_SETTINGS, compatibility_flags: ["nodejs_compat"] } } },
      { name: "logpush on", existing: { ...converged, settings: { ...LOGGING_OFF_SETTINGS, logpush: true } } },
      { name: "observability on", existing: { ...converged, settings: { ...LOGGING_OFF_SETTINGS, observability: { enabled: true } } } },
      {
        name: "logs on under a master switch that is off",
        existing: { ...converged, settings: { ...LOGGING_OFF_SETTINGS, observability: { enabled: false, logs: { enabled: true } } } },
      },
      {
        name: "traces on",
        existing: { ...converged, settings: { ...LOGGING_OFF_SETTINGS, observability: { enabled: false, traces: { enabled: true } } } },
      },
      { name: "a tail consumer", existing: { ...converged, settings: { ...LOGGING_OFF_SETTINGS, tail_consumers: [{ service: "spy" }] } } },
      { name: "a streaming tail consumer", existing: { ...converged, settings: { ...LOGGING_OFF_SETTINGS, streaming_tail_consumers: [{ name: "spy" }] } } },
    ];
    for (const testCase of cases) {
      const params = testCase.params ?? PARAMS;
      const { calls } = fakeCloudflare({ scripts: { [WORKER_NAME]: minterWorkerScript(), [GATE_SCRIPT]: testCase.existing } });
      const result = await actuateEdgeGateDeploy(params, envWith());
      expect(result, testCase.name).toMatchObject({
        ok: true,
        status: "updated",
        keyVersion: params.keyVersion,
        keyFingerprint: await sessionKeyFingerprint(params.sessionSecret),
      });
      expectNoSecretIn(result, params.sessionSecret);
      const puts = calls.filter((call) => call.method === "PUT");
      expect(puts, testCase.name).toHaveLength(1);
      expect((puts[0] as RecordedCall).moduleSource).toBe(SESSION_GATE_SOURCE);
      expect((puts[0] as RecordedCall).metadata?.logpush).toBe(false);
      vi.unstubAllGlobals();
    }
  });

  it("refuses a DOWNGRADE: a deployed gate with a higher marker version is never overwritten", async () => {
    for (const version of [2, 99]) {
      const { calls } = fakeCloudflare({
        scripts: { [WORKER_NAME]: minterWorkerScript(), [GATE_SCRIPT]: await convergedGateScript({ source: `// dy-session-gate v${version}\nexport default {}` }) },
      });
      const result = await actuateEdgeGateDeploy(PARAMS, envWith());
      expect(result).toEqual({
        ok: false,
        op: "edge-gate-deploy",
        script: GATE_SCRIPT,
        detail:
          `the deployed "${GATE_SCRIPT}" is session gate v${version}, newer than this Worker's v1: this fork is older than the deployed gate, ` +
          "so it does not overwrite it. Sync the fork, then deploy again.",
      });
      expect(calls.filter((call) => call.method !== "GET")).toHaveLength(0);
      vi.unstubAllGlobals();
    }
  });

  it("NEVER takes over a script without the gate's marker, and touches no other script", async () => {
    const foreignScripts: FakeScript[] = [
      { format: "module", source: "export default { fetch() { return new Response('agency'); } }", bindings: [] },
      { format: "service-worker", source: "addEventListener('fetch', () => {})", bindings: [] },
      // syd's platform gate, by its marker-less first line.
      { format: "module", source: "// dy-edge-gate: the platform's gate\nexport default {}", bindings: [] },
    ];
    for (const foreign of foreignScripts) {
      const { calls } = fakeCloudflare({
        scripts: { [WORKER_NAME]: minterWorkerScript(), [GATE_SCRIPT]: foreign, "dy-edge-gate": minterWorkerScript() },
      });
      const result = await actuateEdgeGateDeploy(PARAMS, envWith());
      expect(result).toEqual({
        ok: false,
        op: "edge-gate-deploy",
        script: GATE_SCRIPT,
        foreign: true,
        detail: `a Worker named "${GATE_SCRIPT}" already exists and does not start with the session gate's marker, so this platform did not make it. It was left unchanged.`,
      });
      expect(calls.filter((call) => call.method !== "GET")).toHaveLength(0);
      for (const call of calls) {
        expect(call.url).not.toContain("dy-edge-gate");
      }
      vi.unstubAllGlobals();
    }
  });

  it("refuses when the existing script's source cannot be read", async () => {
    for (const contentStatus of [500, 404]) {
      const { calls } = fakeCloudflare({
        scripts: { [WORKER_NAME]: minterWorkerScript(), [GATE_SCRIPT]: await convergedGateScript() },
        contentStatus,
      });
      const result = await actuateEdgeGateDeploy(PARAMS, envWith());
      expect(result).toMatchObject({ ok: false, script: GATE_SCRIPT });
      expect((result as { detail: string }).detail).toBe(
        `the source of the existing Worker "${GATE_SCRIPT}" could not be read (HTTP ${contentStatus}), so it is not replaced`,
      );
      expect(calls.filter((call) => call.method === "PUT")).toHaveLength(0);
      vi.unstubAllGlobals();
    }
  });

  it("treats a settings 404 as absent ONLY with Cloudflare's \"Worker not found\" code 10007; any other 404 is a refusal", async () => {
    for (const notFoundBody of [{ success: false, errors: [{ code: 7003, message: "Could not route to /accounts/acct-sbm/workers" }] }, { success: false }, "not json"]) {
      const { calls } = fakeCloudflare({ scripts: { [WORKER_NAME]: minterWorkerScript() }, notFoundBody });
      const result = await actuateEdgeGateDeploy(PARAMS, envWith());
      expect(result).toMatchObject({ ok: false, script: GATE_SCRIPT });
      expect((result as { detail: string }).detail).toMatch(
        new RegExp(`^reading the settings of Worker "${GATE_SCRIPT}" answered HTTP 404 without Cloudflare's "Worker not found" error \\(code 10007\\)`),
      );
      expect(calls.filter((call) => call.method === "PUT")).toHaveLength(0);
      vi.unstubAllGlobals();
    }
  });

  it("refuses BEFORE any network call without DY_WORKER_NAME, with a malformed one (not echoed), or for another project", async () => {
    const refusals: Array<{ env: Env; params: EdgeGateDeployParams; detail: RegExp; mustNotContain?: string }> = [
      { env: envWith({ DY_WORKER_NAME: undefined }), params: PARAMS, detail: /^DY_WORKER_NAME is not set on this Worker\. .*wrangler secret put DY_WORKER_NAME/ },
      { env: envWith({ DY_WORKER_NAME: "Sbm Studio" }), params: PARAMS, detail: /^DY_WORKER_NAME is not a Worker script name/, mustNotContain: "Sbm Studio" },
      { env: envWith({ DY_WORKER_NAME: "<script>-sbm" }), params: PARAMS, detail: /^DY_WORKER_NAME is not a Worker script name/, mustNotContain: "<script>" },
      { env: envWith(), params: { ...PARAMS, project: "someone-else-1" }, detail: /dy-agency-proof/ },
      { env: envWith({ CF_DNS_API_TOKEN: undefined }), params: PARAMS, detail: /^CF_DNS_API_TOKEN is not configured/ },
    ];
    for (const refusal of refusals) {
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);
      const result = await actuateEdgeGateDeploy(refusal.params, refusal.env);
      expect(result.ok).toBe(false);
      const detail = (result as { detail: string }).detail;
      expect(detail).toMatch(refusal.detail);
      if (refusal.mustNotContain !== undefined) {
        expect(JSON.stringify(result)).not.toContain(refusal.mustNotContain);
      }
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.unstubAllGlobals();
    }
  });

  it("refuses when DY_WORKER_NAME names no script in the zone's account (the binding would point nowhere)", async () => {
    const { calls } = fakeCloudflare({ scripts: {} });
    const result = await actuateEdgeGateDeploy(PARAMS, envWith());
    expect(result).toMatchObject({ ok: false, script: GATE_SCRIPT });
    expect((result as { detail: string }).detail).toMatch(/^DY_WORKER_NAME \("sbmstudio"\) names no Worker script in the Cloudflare account that holds zone "sbmstudio\.com\.au"/);
    expect(calls.filter((call) => call.method === "PUT")).toHaveLength(0);
  });

  it("refuses when the zone reports no account, or the token lacks Workers Scripts access", async () => {
    fakeCloudflare({ scripts: { [WORKER_NAME]: minterWorkerScript() }, zoneAccountId: null });
    const noAccount = await actuateEdgeGateDeploy(PARAMS, envWith());
    expect((noAccount as { detail: string }).detail).toBe(`the zone lookup for "${ZONE}" reported no Cloudflare account, so the gate has nowhere to go`);
    vi.unstubAllGlobals();

    for (const settingsStatus of [401, 403]) {
      fakeCloudflare({ scripts: { [WORKER_NAME]: minterWorkerScript() }, settingsStatus });
      const denied = await actuateEdgeGateDeploy(PARAMS, envWith());
      expect((denied as { detail: string }).detail).toMatch(/CF_DNS_API_TOKEN needs Account → Workers Scripts: Edit/);
      vi.unstubAllGlobals();
    }
  });

  it("fails when the read-back does not show exactly the settings sent (a binding, the date, or a log turned on)", async () => {
    const readBackFailures: FakeCloudflareOptions[] = [
      { dropAfterPut: "DY_MINTER" },
      { reportAfterPut: { compatibility_date: "2024-01-01" } },
      { reportAfterPut: { logpush: true } },
      { reportAfterPut: { observability: { enabled: true } } },
      { reportAfterPut: { tail_consumers: [{ service: "spy" }] } },
    ];
    for (const options of readBackFailures) {
      fakeCloudflare({ scripts: { [WORKER_NAME]: minterWorkerScript() }, ...options });
      const result = await actuateEdgeGateDeploy(PARAMS, envWith());
      expect(result).toEqual({
        ok: false,
        op: "edge-gate-deploy",
        script: GATE_SCRIPT,
        detail: `the gate script was uploaded, but the settings Cloudflare reports for "${GATE_SCRIPT}" (bindings, compatibility date or logging) are not the ones sent`,
      });
      vi.unstubAllGlobals();
    }
  });

  it("redacts the secret from a failure detail, even when Cloudflare's error quotes it", async () => {
    fakeCloudflare({
      scripts: { [WORKER_NAME]: minterWorkerScript() },
      putReply: { status: 400, body: { success: false, errors: [{ code: 10021, message: `binding DY_SESSION_SECRET value ${SECRET_V1} is invalid` }] } },
    });
    const result = await actuateEdgeGateDeploy(PARAMS, envWith());
    expect(result.ok).toBe(false);
    expect((result as { detail: string }).detail).toBe(
      "the gate script upload failed with HTTP 400: binding DY_SESSION_SECRET value [redacted] is invalid.",
    );
    expectNoSecretIn(result);
  });
});
