// hub#58 / planning/51 — the two ops that let the platform manage the syd cell through this Worker:
// cf-tunnel-get (a READ of one tunnel's ingress config) and gcp-disk-snapshot-create (a SNAPSHOT of
// one cell node's boot disk). Worker side.
//
// What these tests pin:
//   - the twin validators accept the real cell-node names (syd's and the saga's) and refuse the
//     control-plane VM, a free-form snapshot name and every malformed field;
//   - the twin block is byte-identical with the app copy (the sha256 pin below — the app's test pins
//     the SAME value);
//   - cf-tunnel-get reports a config exactly, and FAILS CLOSED on any shape it does not understand;
//   - gcp-disk-snapshot-create snapshots the instance's ONE boot disk only, never a disk the job names,
//     reports an existing snapshot of the same disk as "already-existed", and refuses one of another disk;
//   - both ops use only the agency's own credentials, and neither token is echoed.

import { describe, it, expect, vi, afterEach } from "vitest";
// Vite's `?raw` suffix: the Worker's own params source as text, for the twin-block pin. TypeScript has
// no declaration for it in this repo (no @types/node, no vite/client types), so the import is ignored
// by the type checker on purpose. @ts-ignore rather than @ts-expect-error: another branch (hub#93)
// adds a `*?raw` declaration, and this line must stay correct with or without it.
// @ts-ignore
import rawDispatchParamsSource from "../src/dispatch-params.ts?raw";
import type { Env } from "../src/env.js";
import { DISPATCH_OPS } from "../src/dispatch-verify.js";
import { DISPATCH_OP_REGISTRY } from "../src/ops.js";
import {
  diskSnapshotNameFor,
  validateCfTunnelGetParams,
  validateGcpDiskSnapshotCreateParams,
} from "../src/dispatch-params.js";
import {
  actuateCfTunnelGet,
  actuateGcpDiskSnapshotCreate,
  bootDiskOf,
  parseTunnelConfiguration,
  parseZonalDiskUrl,
  regionOfZone,
  snapshotCreatedAt,
} from "../src/actuate-hub58.js";

const dispatchParamsSource: string = rawDispatchParamsSource as string;

// ── The twin pin ─────────────────────────────────────────────────────────────────────

const TWIN_BLOCK_START_MARKER = "// ── hub#58: syd through its Worker";
const TWIN_BLOCK_END_MARKER = "\n// ── planning/49: the agency-side ephemeral-compute ops";
// The app's src/server/services/agency-dispatch-params-hub58.test.ts pins the SAME value.
const TWIN_BLOCK_SHA256 = "5a4af8600bcb162ce51d0d20325c1d8ece9507940ae361ad391cea94b0be17dc";

const TUNNEL_ID = "025cb230-c588-43f3-ad76-cce2869aefdd";
const CF_ACCOUNT_ID = "acct-cf-1";
const CF_TOKEN = "cf-dns-token-must-not-be-echoed";
const GCP_ACCESS_TOKEN = "ya29.must-not-be-echoed";
const PROJECT = "doubleyoup";
const ZONE = "australia-southeast1-a";

function errorText(verdict: { ok: boolean; reason?: string }): string {
  return verdict.ok ? "" : (verdict.reason ?? "");
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("hub#58 twin block", () => {
  it("is byte-identical with the app copy (pinned sha256 — change BOTH twins and BOTH pins together)", async () => {
    const start = dispatchParamsSource.indexOf(TWIN_BLOCK_START_MARKER);
    const end = dispatchParamsSource.indexOf(TWIN_BLOCK_END_MARKER, start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const block = dispatchParamsSource.slice(start, end);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(block)));
    let hex = "";
    for (const byte of digest) {
      hex += byte.toString(16).padStart(2, "0");
    }
    expect(hex).toBe(TWIN_BLOCK_SHA256);
  });

  it("both ops are allowlisted and registered", () => {
    expect(DISPATCH_OPS).toContain("cf-tunnel-get");
    expect(DISPATCH_OPS).toContain("gcp-disk-snapshot-create");
    expect(typeof DISPATCH_OP_REGISTRY["cf-tunnel-get"].actuate).toBe("function");
    expect(typeof DISPATCH_OP_REGISTRY["gcp-disk-snapshot-create"].actuate).toBe("function");
  });
});

// ── Validators ───────────────────────────────────────────────────────────────────────

describe("cf-tunnel-get params (twin of the app's rules)", () => {
  it("accepts a tunnel id in both forms and returns ONLY the known key", () => {
    expect(validateCfTunnelGetParams({ tunnelId: TUNNEL_ID, extra: "dropped" })).toEqual({ ok: true, params: { tunnelId: TUNNEL_ID } });
    const bare = "025cb230c58843f3ad76cce2869aefdd";
    expect(validateCfTunnelGetParams({ tunnelId: bare })).toEqual({ ok: true, params: { tunnelId: bare } });
  });

  it("refuses a non-object and a malformed tunnel id", () => {
    expect(validateCfTunnelGetParams(null).ok).toBe(false);
    expect(validateCfTunnelGetParams([TUNNEL_ID]).ok).toBe(false);
    for (const tunnelId of ["", "not-a-uuid", TUNNEL_ID.toUpperCase(), `${TUNNEL_ID}/configurations`, 42]) {
      expect(errorText(validateCfTunnelGetParams({ tunnelId }))).toMatch(/^tunnelId must be a lowercase-hex Cloudflare tunnel id/);
    }
  });
});

describe("gcp-disk-snapshot-create params (twin of the app's rules)", () => {
  const good = { project: PROJECT, zone: ZONE, instance: "dy-data-syd-1", label: "20261020" };

  it("accepts syd's node names, the saga's node names and a second web node; returns ONLY the known keys", () => {
    for (const instance of [
      "dy-web-syd-1",
      "dy-web-syd-2",
      "dy-file-syd-1",
      "dy-data-syd-1",
      "dy-gw-syd-1",
      "dy-web-australia-southeast2-1",
      "dy-gateway-australia-southeast2-1",
    ]) {
      expect(validateGcpDiskSnapshotCreateParams({ ...good, instance, extra: "dropped" })).toEqual({
        ok: true,
        params: { ...good, instance },
      });
    }
  });

  it("refuses the control-plane VM and any VM that is not a cell node", () => {
    for (const instance of ["dy-cp-1", "dy-cp-syd-1", "gke-node-1", "dy-web", "dy-web-syd", "dy-web-syd-1-extra-", "DY-WEB-SYD-1", "dy-db-syd-1"]) {
      expect(errorText(validateGcpDiskSnapshotCreateParams({ ...good, instance }))).toMatch(/^instance must be a cell node VM name/);
    }
  });

  it("refuses a bad project, zone and label, field by field", () => {
    expect(errorText(validateGcpDiskSnapshotCreateParams({ ...good, project: "Doubleyoup" }))).toMatch(/^project must be a GCP project id/);
    expect(errorText(validateGcpDiskSnapshotCreateParams({ ...good, zone: "australia-southeast1" }))).toMatch(/^zone must be a Compute Engine zone/);
    for (const label of ["", "2026-10-20", "Window1", "a".repeat(17), 20261020]) {
      expect(errorText(validateGcpDiskSnapshotCreateParams({ ...good, label }))).toMatch(/^label must be 1-16 lowercase letters and digits/);
    }
    expect(validateGcpDiskSnapshotCreateParams("dy-data-syd-1").ok).toBe(false);
  });

  it("the snapshot name is DERIVED as <instance>-boot-<label>, and an over-long one is refused", () => {
    expect(diskSnapshotNameFor("dy-data-syd-1", "20261020")).toBe("dy-data-syd-1-boot-20261020");
    // 63 is Google's cap. This name is 44 + 6 + 16 = 66 characters.
    const longInstance = "dy-gateway-australia-southeast2-abcdefghij-1";
    expect(longInstance.length).toBe(44);
    expect(errorText(validateGcpDiskSnapshotCreateParams({ ...good, instance: longInstance, label: "a".repeat(16) }))).toMatch(
      /would not be a valid Compute Engine resource name/,
    );
    expect(validateGcpDiskSnapshotCreateParams({ ...good, instance: longInstance, label: "a".repeat(13) }).ok).toBe(true);
  });
});

// ── cf-tunnel-get: the config parse ──────────────────────────────────────────────────

describe("parseTunnelConfiguration: exact report, fail closed on unknown shapes", () => {
  it("reports every rule in order, with path and originRequest NAMES, and the other top-level keys", () => {
    const parsed = parseTunnelConfiguration(
      {
        tunnel_id: TUNNEL_ID,
        version: 41,
        source: "cloudflare",
        config: {
          ingress: [
            { hostname: "cell-syd.doubleyoup.com", service: "http://localhost:9440" },
            { hostname: "lawnsbydavid-production.doubleyoup.com", service: "http://localhost:80" },
            { hostname: "term-docs.doubleyoup.com", service: "https://term-docs-123.australia-southeast1.run.app", originRequest: { noTLSVerify: true, httpHostHeader: "x" } },
            { hostname: "api.example.com", path: "^/v1/", service: "http://localhost:80" },
            { service: "http_status:404" },
          ],
          "warp-routing": { enabled: false },
          originRequest: { connectTimeout: 30 },
        },
      },
      TUNNEL_ID,
    );
    expect(parsed).toEqual({
      ok: true,
      source: "cloudflare",
      version: 41,
      otherConfigKeys: ["originRequest", "warp-routing"],
      rules: [
        { hostname: "cell-syd.doubleyoup.com", service: "http://localhost:9440", path: null, originRequestKeys: [] },
        { hostname: "lawnsbydavid-production.doubleyoup.com", service: "http://localhost:80", path: null, originRequestKeys: [] },
        {
          hostname: "term-docs.doubleyoup.com",
          service: "https://term-docs-123.australia-southeast1.run.app",
          path: null,
          originRequestKeys: ["httpHostHeader", "noTLSVerify"],
        },
        { hostname: "api.example.com", service: "http://localhost:80", path: "^/v1/", originRequestKeys: [] },
        { hostname: null, service: "http_status:404", path: null, originRequestKeys: [] },
      ],
    });
  });

  it("a never-configured tunnel (no config, or no ingress) is zero rules, not a failure", () => {
    expect(parseTunnelConfiguration({ tunnel_id: TUNNEL_ID, config: null }, TUNNEL_ID)).toEqual({
      ok: true,
      source: null,
      version: null,
      rules: [],
      otherConfigKeys: [],
    });
    expect(parseTunnelConfiguration({ config: {} }, TUNNEL_ID)).toMatchObject({ ok: true, rules: [] });
  });

  it("refuses every shape it does not understand, and names why", () => {
    const refusals: Array<[unknown, RegExp]> = [
      [null, /without a configuration object/],
      [{ tunnel_id: "another-tunnel", config: { ingress: [] } }, /a different tunnel/],
      [{ config: "yaml text" }, /config is not an object/],
      [{ config: { ingress: { hostname: "x" } } }, /ingress is not a list/],
      [{ config: { ingress: ["http://localhost:80"] } }, /rule 0 is not an object/],
      [{ config: { ingress: [{ hostname: "a.example.com" }] } }, /rule 0 has no usable service/],
      [{ config: { ingress: [{ hostname: "a.example.com", service: "" }] } }, /rule 0 has no usable service/],
      [{ config: { ingress: [{ hostname: 7, service: "http://localhost:80" }] } }, /rule 0 has a hostname that is not a usable string/],
      [{ config: { ingress: [{ hostname: "a.example.com", service: "http://localhost:80", headers: {} }] } }, /carries the key "headers"/],
      [{ config: { ingress: [{ service: "http://localhost:80", originRequest: "x" }] } }, /originRequest that is not an object/],
      [{ config: { ingress: [{ service: "http://localhost:80", originRequest: { "bad key": 1 } }] } }, /originRequest keys this op does not understand/],
      [{ config: { ingress: [], "1bad": true } }, /top-level keys this op does not understand/],
    ];
    for (const [result, reason] of refusals) {
      const parsed = parseTunnelConfiguration(result, TUNNEL_ID);
      expect(parsed.ok).toBe(false);
      if (!parsed.ok) {
        expect(parsed.reason).toMatch(reason);
      }
    }
  });
});

// ── cf-tunnel-get: the actuator ──────────────────────────────────────────────────────

interface RecordedCall {
  url: string;
  method: string;
  auth: string | null;
  body: string | null;
}

/** Route every fetch through `handler`, and record each call. */
function mockFetch(handler: (call: RecordedCall) => { status?: number; body: unknown }): RecordedCall[] {
  const calls: RecordedCall[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const headers = new Headers(init?.headers);
    const call: RecordedCall = {
      url: String(input),
      method: init?.method ?? "GET",
      auth: headers.get("authorization"),
      body: typeof init?.body === "string" ? init.body : null,
    };
    calls.push(call);
    const answer = handler(call);
    return new Response(JSON.stringify(answer.body), {
      status: answer.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  });
  return calls;
}

const CONFIG_URL = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/configurations`;

function cfEnv(overrides: Partial<Env> = {}): Env {
  return { CF_DNS_API_TOKEN: CF_TOKEN, ...overrides } as Env;
}

describe("actuateCfTunnelGet", () => {
  it("resolves the token's account, GETs the config with the agency's own token, and reports it", async () => {
    const calls = mockFetch((call) => {
      if (call.url.startsWith("https://api.cloudflare.com/client/v4/accounts?")) {
        return { body: { success: true, result: [{ id: CF_ACCOUNT_ID }] } };
      }
      if (call.url === CONFIG_URL) {
        return {
          body: {
            success: true,
            result: {
              tunnel_id: TUNNEL_ID,
              version: 7,
              source: "cloudflare",
              config: { ingress: [{ hostname: "a.doubleyoup.com", service: "http://localhost:80" }, { service: "http_status:404" }] },
            },
          },
        };
      }
      return { status: 500, body: { success: false } };
    });

    const result = await actuateCfTunnelGet({ tunnelId: TUNNEL_ID }, cfEnv());
    expect(result).toEqual({
      ok: true,
      op: "cf-tunnel-get",
      tunnelId: TUNNEL_ID,
      source: "cloudflare",
      version: 7,
      otherConfigKeys: [],
      rules: [
        { hostname: "a.doubleyoup.com", service: "http://localhost:80", path: null, originRequestKeys: [] },
        { hostname: null, service: "http_status:404", path: null, originRequestKeys: [] },
      ],
    });
    // A READ: no PUT, no POST, and the token never comes back.
    expect(calls.map((call) => call.method)).toEqual(["GET", "GET"]);
    expect(calls[1]?.auth).toBe(`Bearer ${CF_TOKEN}`);
    expect(JSON.stringify(result)).not.toContain(CF_TOKEN);
  });

  it("is ok:false with no Cloudflare call when the token is not configured", async () => {
    const calls = mockFetch(() => ({ body: {} }));
    const result = await actuateCfTunnelGet({ tunnelId: TUNNEL_ID }, cfEnv({ CF_DNS_API_TOKEN: undefined }));
    expect(result).toMatchObject({ ok: false, op: "cf-tunnel-get", tunnelId: TUNNEL_ID });
    expect(calls).toEqual([]);
  });

  it("a 404 says the tunnel is not in the token's account; a 403 names the tunnel scope", async () => {
    for (const [status, reason] of [
      [404, /no configuration for this tunnel in the account CF_DNS_API_TOKEN belongs to/],
      [403, /Cloudflare Tunnel: Edit/],
    ] as const) {
      mockFetch((call) => {
        if (call.url.startsWith("https://api.cloudflare.com/client/v4/accounts?")) {
          return { body: { success: true, result: [{ id: CF_ACCOUNT_ID }] } };
        }
        return { status, body: { success: false } };
      });
      const result = await actuateCfTunnelGet({ tunnelId: TUNNEL_ID }, cfEnv());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.detail).toMatch(reason);
      }
      vi.restoreAllMocks();
    }
  });

  it("fails closed when the config carries a rule key it does not understand", async () => {
    mockFetch((call) => {
      if (call.url.startsWith("https://api.cloudflare.com/client/v4/accounts?")) {
        return { body: { success: true, result: [{ id: CF_ACCOUNT_ID }] } };
      }
      return { body: { success: true, result: { config: { ingress: [{ service: "http://localhost:80", unknown: 1 }] } } } };
    });
    const result = await actuateCfTunnelGet({ tunnelId: TUNNEL_ID }, cfEnv());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toMatch(/^refusing to report the tunnel config: ingress rule 0 carries the key "unknown"/);
    }
  });
});

// ── gcp-disk-snapshot-create ─────────────────────────────────────────────────────────

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** A REAL service-account key, so the RS256 mint runs; only the HTTP calls are mocked. */
async function makeServiceAccountKey(projectId: string): Promise<string> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)) as ArrayBuffer);
  const pem = `-----BEGIN PRIVATE KEY-----\n${bytesToBase64(pkcs8).match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  return JSON.stringify({
    type: "service_account",
    project_id: projectId,
    private_key: pem,
    client_email: `agency-dogfood@${projectId}.iam.gserviceaccount.com`,
    token_uri: "https://oauth2.googleapis.com/token",
  });
}

const COMPUTE = "https://compute.googleapis.com/compute/v1";
const INSTANCE_URL = `${COMPUTE}/projects/${PROJECT}/zones/${ZONE}/instances/dy-data-syd-1`;
const SNAPSHOT_URL = `${COMPUTE}/projects/${PROJECT}/global/snapshots/dy-data-syd-1-boot-20261020`;
const CREATE_URL = `${COMPUTE}/projects/${PROJECT}/zones/${ZONE}/disks/dy-data-syd-1/createSnapshot`;
const BOOT_DISK_URL = `https://www.googleapis.com/compute/v1/projects/${PROJECT}/zones/${ZONE}/disks/dy-data-syd-1`;
const DATA_DISK_URL = `https://www.googleapis.com/compute/v1/projects/${PROJECT}/zones/${ZONE}/disks/dy-file-syd-1-data`;
const SNAPSHOT_PARAMS = { project: PROJECT, zone: ZONE, instance: "dy-data-syd-1", label: "20261020" };

const INSTANCE_BODY = {
  name: "dy-data-syd-1",
  disks: [
    { boot: true, source: BOOT_DISK_URL },
    { boot: false, source: DATA_DISK_URL },
  ],
};

describe("regionOfZone", () => {
  it("drops the zone letter only", () => {
    expect(regionOfZone("australia-southeast1-a")).toBe("australia-southeast1");
    expect(regionOfZone("australia-southeast2-c")).toBe("australia-southeast2");
    expect(regionOfZone("us-central1-f")).toBe("us-central1");
  });
});

describe("bootDiskOf / parseZonalDiskUrl", () => {
  it("finds the ONE boot disk in the instance's own project and zone", () => {
    expect(bootDiskOf(INSTANCE_BODY, PROJECT, ZONE)).toEqual({ ok: true, disk: "dy-data-syd-1" });
    expect(parseZonalDiskUrl(`${COMPUTE}/projects/${PROJECT}/zones/${ZONE}/disks/d1`)).toEqual({ project: PROJECT, zone: ZONE, disk: "d1" });
  });

  it("refuses zero or two boot disks, a regional disk, and a disk in another project or zone", () => {
    expect(bootDiskOf({ disks: [] }, PROJECT, ZONE)).toMatchObject({ ok: false });
    expect(bootDiskOf(null, PROJECT, ZONE)).toMatchObject({ ok: false });
    expect(bootDiskOf({ disks: [{ boot: true, source: BOOT_DISK_URL }, { boot: true, source: DATA_DISK_URL }] }, PROJECT, ZONE)).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/2 boot disks/),
    });
    const regional = `https://www.googleapis.com/compute/v1/projects/${PROJECT}/regions/australia-southeast1/disks/d1`;
    expect(bootDiskOf({ disks: [{ boot: true, source: regional }] }, PROJECT, ZONE)).toMatchObject({ ok: false });
    expect(bootDiskOf({ disks: [{ boot: true, source: BOOT_DISK_URL }] }, "other-project", ZONE)).toMatchObject({ ok: false });
    expect(bootDiskOf({ disks: [{ boot: true, source: BOOT_DISK_URL }] }, PROJECT, "australia-southeast1-b")).toMatchObject({ ok: false });
    expect(parseZonalDiskUrl("http://www.googleapis.com/compute/v1/projects/p-12345/zones/a-b1-c/disks/d")).toBeNull();
  });
});

describe("actuateGcpDiskSnapshotCreate", () => {
  /** The token mint, the instance read, and whatever `routes` adds. Unknown URLs answer 500. */
  async function setUp(routes: (call: RecordedCall) => { status?: number; body: unknown } | null) {
    const env = { GCP_SERVICE_ACCOUNT_KEY: await makeServiceAccountKey(PROJECT) } as Env;
    const calls = mockFetch((call) => {
      if (call.url === "https://oauth2.googleapis.com/token") {
        return { body: { access_token: GCP_ACCESS_TOKEN, expires_in: 3600, token_type: "Bearer" } };
      }
      const routed = routes(call);
      if (routed !== null) {
        return routed;
      }
      if (call.url === INSTANCE_URL) {
        return { body: INSTANCE_BODY };
      }
      return { status: 500, body: { error: { message: `unexpected ${call.method} ${call.url}` } } };
    });
    const googleCalls = () => calls.filter((call) => call.url !== "https://oauth2.googleapis.com/token");
    return { env, calls, googleCalls };
  }

  it("snapshots the instance's BOOT disk under the derived name, waits once, and reports the status", async () => {
    let snapshotReads = 0;
    const { env, googleCalls } = await setUp((call) => {
      if (call.url === SNAPSHOT_URL) {
        snapshotReads += 1;
        if (snapshotReads === 1) {
          return { status: 404, body: { error: { code: 404, message: "not found" } } };
        }
        return { body: { status: "READY", sourceDisk: BOOT_DISK_URL, creationTimestamp: "2026-10-20T09:00:01.123-07:00" } };
      }
      if (call.url === CREATE_URL) {
        return { body: { name: "operation-123", status: "RUNNING" } };
      }
      if (call.url.endsWith("/operations/operation-123/wait")) {
        return { body: { name: "operation-123", status: "DONE" } };
      }
      return null;
    });

    const result = await actuateGcpDiskSnapshotCreate(SNAPSHOT_PARAMS, env);
    expect(result).toEqual({
      ok: true,
      op: "gcp-disk-snapshot-create",
      instanceName: "dy-data-syd-1",
      diskName: "dy-data-syd-1",
      snapshotName: "dy-data-syd-1-boot-20261020",
      status: "created",
      snapshotStatus: "READY",
      createdAt: "2026-10-20T09:00:01.123-07:00",
    });

    const calls = googleCalls();
    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET ${INSTANCE_URL}`,
      `GET ${SNAPSHOT_URL}`,
      `POST ${CREATE_URL}`,
      `POST ${COMPUTE}/projects/${PROJECT}/zones/${ZONE}/operations/operation-123/wait`,
      `GET ${SNAPSHOT_URL}`,
    ]);
    const createBody = JSON.parse(calls[2]?.body ?? "{}") as Record<string, unknown>;
    expect(Object.keys(createBody).sort()).toEqual(["description", "name", "storageLocations"]);
    expect(createBody.name).toBe("dy-data-syd-1-boot-20261020");
    // Review finding 15: the snapshot stays in the disk's own region, never a multi-region.
    expect(createBody.storageLocations).toEqual(["australia-southeast1"]);
    // Never the data disk, whatever the instance reports.
    expect(calls.some((call) => call.url.includes("dy-file-syd-1-data"))).toBe(false);
    for (const call of calls) {
      expect(call.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    }
    expect(JSON.stringify(result)).not.toContain(GCP_ACCESS_TOKEN);
  });

  it("an existing snapshot of the SAME disk is already-existed (this is how a caller polls) — no create", async () => {
    const { env, googleCalls } = await setUp((call) => {
      if (call.url === SNAPSHOT_URL) {
        return { body: { status: "CREATING", sourceDisk: BOOT_DISK_URL, creationTimestamp: "2026-09-01T00:00:00.000-07:00" } };
      }
      return null;
    });
    const result = await actuateGcpDiskSnapshotCreate(SNAPSHOT_PARAMS, env);
    // createdAt is reported, so the caller can refuse an OLD snapshot under a reused label (finding 16).
    expect(result).toMatchObject({ ok: true, status: "already-existed", snapshotStatus: "CREATING", createdAt: "2026-09-01T00:00:00.000-07:00" });
    expect(googleCalls().some((call) => call.method === "POST")).toBe(false);
  });

  it("a creationTimestamp that is missing or not a date is reported as null (the caller fails closed)", async () => {
    expect(snapshotCreatedAt(undefined)).toBeNull();
    expect(snapshotCreatedAt("")).toBeNull();
    expect(snapshotCreatedAt("not a date")).toBeNull();
    expect(snapshotCreatedAt(1760000000)).toBeNull();
    expect(snapshotCreatedAt(`2026-10-20T00:00:00Z${"x".repeat(64)}`)).toBeNull();
    expect(snapshotCreatedAt("2026-10-20T00:00:00.000-07:00")).toBe("2026-10-20T00:00:00.000-07:00");
    const { env } = await setUp((call) => {
      if (call.url === SNAPSHOT_URL) {
        return { body: { status: "READY", sourceDisk: BOOT_DISK_URL } };
      }
      return null;
    });
    expect(await actuateGcpDiskSnapshotCreate(SNAPSHOT_PARAMS, env)).toMatchObject({ ok: true, status: "already-existed", createdAt: null });
  });

  it("an existing snapshot of ANOTHER disk under the name is refused — no create", async () => {
    const { env, googleCalls } = await setUp((call) => {
      if (call.url === SNAPSHOT_URL) {
        return { body: { status: "READY", sourceDisk: DATA_DISK_URL } };
      }
      return null;
    });
    const result = await actuateGcpDiskSnapshotCreate(SNAPSHOT_PARAMS, env);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toMatch(/already exists for a different disk/);
    }
    expect(googleCalls().some((call) => call.method === "POST")).toBe(false);
  });

  it("refuses an instance whose boot disk is not exactly one zonal disk in its own project and zone", async () => {
    const { env, googleCalls } = await setUp((call) => {
      if (call.url === INSTANCE_URL) {
        return { body: { disks: [{ boot: true, source: `https://www.googleapis.com/compute/v1/projects/other-project/zones/${ZONE}/disks/x` }] } };
      }
      return null;
    });
    const result = await actuateGcpDiskSnapshotCreate(SNAPSHOT_PARAMS, env);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toMatch(/^refusing to snapshot: the boot disk is not in the instance's own project and zone/);
    }
    expect(googleCalls().map((call) => call.url)).toEqual([INSTANCE_URL]);
  });

  it("a missing instance is ok:false and nothing is created", async () => {
    const { env, googleCalls } = await setUp((call) => {
      if (call.url === INSTANCE_URL) {
        return { status: 404, body: { error: { code: 404, message: "not found" } } };
      }
      return null;
    });
    const result = await actuateGcpDiskSnapshotCreate(SNAPSHOT_PARAMS, env);
    expect(result).toMatchObject({ ok: false, op: "gcp-disk-snapshot-create", snapshotName: "dy-data-syd-1-boot-20261020" });
    expect(googleCalls().length).toBe(1);
  });

  it("a denied create names both permissions; an operation that ends with errors is a failure", async () => {
    {
      const { env } = await setUp((call) => {
        if (call.url === SNAPSHOT_URL) {
          return { status: 404, body: { error: { code: 404 } } };
        }
        if (call.url === CREATE_URL) {
          return { status: 403, body: { error: { code: 403, message: "Required 'compute.disks.createSnapshot' permission" } } };
        }
        return null;
      });
      const result = await actuateGcpDiskSnapshotCreate(SNAPSHOT_PARAMS, env);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.detail).toMatch(/compute\.disks\.createSnapshot on the disk and compute\.snapshots\.create/);
      }
      vi.restoreAllMocks();
    }
    {
      const { env } = await setUp((call) => {
        if (call.url === SNAPSHOT_URL) {
          return { status: 404, body: { error: { code: 404 } } };
        }
        if (call.url === CREATE_URL) {
          return { body: { name: "operation-9", status: "RUNNING" } };
        }
        if (call.url.endsWith("/operations/operation-9/wait")) {
          return { body: { name: "operation-9", status: "DONE", error: { errors: [{ code: "QUOTA_EXCEEDED", message: "snapshot quota" }] } } };
        }
        return null;
      });
      const result = await actuateGcpDiskSnapshotCreate(SNAPSHOT_PARAMS, env);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.detail).toMatch(/snapshot quota/);
      }
    }
  });

  it("a wait that is still running is NOT a failure: the snapshot was accepted, and the caller polls", async () => {
    let snapshotReads = 0;
    const { env } = await setUp((call) => {
      if (call.url === SNAPSHOT_URL) {
        snapshotReads += 1;
        if (snapshotReads === 1) {
          return { status: 404, body: { error: { code: 404 } } };
        }
        return { body: { status: "UPLOADING", sourceDisk: BOOT_DISK_URL } };
      }
      if (call.url === CREATE_URL) {
        return { body: { name: "operation-5", status: "RUNNING" } };
      }
      if (call.url.endsWith("/operations/operation-5/wait")) {
        return { body: { name: "operation-5", status: "RUNNING" } };
      }
      return null;
    });
    const result = await actuateGcpDiskSnapshotCreate(SNAPSHOT_PARAMS, env);
    expect(result).toMatchObject({ ok: true, status: "created", snapshotStatus: "UPLOADING" });
  });

  it("is pinned to the SA key's OWN project, with NO Google call for another project", async () => {
    const env = { GCP_SERVICE_ACCOUNT_KEY: await makeServiceAccountKey(PROJECT) } as Env;
    const calls = mockFetch(() => ({ body: {} }));
    const result = await actuateGcpDiskSnapshotCreate({ ...SNAPSHOT_PARAMS, project: "sbm-website-272023" }, env);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toMatch(/does not match the service-account key's own project/);
    }
    expect(calls).toEqual([]);
  });
});
