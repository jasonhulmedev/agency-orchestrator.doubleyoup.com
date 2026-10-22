// hub#46 — the three custom-hostname ops (custom-hostname-upsert / -get / -delete) and the /validate
// probe. Worker side.
//
// What these tests pin:
//   - the twin block is byte-identical with the app copy (the sha256 pin below — app pins the SAME value);
//   - the validators accept a customer FQDN and refuse every malformed one, the platform zone, and any
//     extra key — so a signed job can never carry a zone;
//   - the actuators act ONLY on the zone in CF_CUSTOM_HOSTNAME_ZONE, refuse a hostname inside it and an
//     origin outside it, and call nothing when the zone or the token is not set;
//   - the upsert creates an absent hostname with HTTP DV, recreates a `deleted` one, and leaves every
//     other state alone; get and delete behave as reads / idempotent deletes;
//   - /validate reports read access and the fallback origin, read-only, and never echoes the token.

import { describe, it, expect, vi, afterEach } from "vitest";
// Vite's `?raw` suffix gives the module source as text, for the twin-block pin (see hub58-ops.test.ts).
// @ts-ignore
import rawCustomHostnameParamsSource from "../src/dispatch-params-custom-hostname.ts?raw";
import type { Env } from "../src/env.js";
import { DISPATCH_OPS } from "../src/dispatch-verify.js";
import { DISPATCH_OP_REGISTRY } from "../src/ops.js";
import {
  CUSTOM_HOSTNAME_PLATFORM_ZONE,
  customHostnameZoneReason,
  isCustomHostnameFqdn,
  validateCustomHostnameDeleteParams,
  validateCustomHostnameGetParams,
  validateCustomHostnameUpsertParams,
} from "../src/dispatch-params-custom-hostname.js";
import {
  actuateCustomHostnameDelete,
  actuateCustomHostnameGet,
  actuateCustomHostnameUpsert,
  probeCustomHostnameScope,
  configuredCustomHostnameZone,
} from "../src/actuate-custom-hostname.js";
import { validateCfDns } from "../src/validators.js";

const customHostnameParamsSource: string = rawCustomHostnameParamsSource as string;

const TWIN_BLOCK_START_MARKER = "// ── custom-hostname ops (hub#46): twin block start";
const TWIN_BLOCK_END_MARKER = "// ── custom-hostname ops (hub#46): twin block end";
// The app's src/server/services/agency-dispatch-params-custom-hostname.test.ts pins the SAME value.
const TWIN_BLOCK_SHA256 = "dbe2e69b4d97c2a46c979030a3bdc8948e8b3b9fc4d32e1f81d42fdb92ce106d";

const CF_TOKEN = "cf-dns-token-must-not-be-echoed";
const AGENCY_ZONE = "sbmstudio.com.au";
const ZONE_ID = "zone-id-sbm";
const ORIGIN = "cell-australia-southeast2-origin.sbmstudio.com.au";
const HOSTNAME = "www.ellissi.com.au";

function envWith(overrides: Partial<Env> = {}): Env {
  return {
    APP_BASE_URL: "https://app.doubleyoup.com",
    DY_CLIENT_ID: "client",
    DY_CLIENT_SECRET: "secret",
    CF_DNS_API_TOKEN: CF_TOKEN,
    CF_CUSTOM_HOSTNAME_ZONE: AGENCY_ZONE,
    ...overrides,
  } as Env;
}

function reasonOf(verdict: { ok: boolean; reason?: string }): string {
  if (verdict.ok) {
    return "";
  }
  return verdict.reason ?? "";
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ── A routed fetch mock: every Cloudflare call is recorded and answered by the test's handler ──

interface RecordedCall {
  method: string;
  url: string;
  body: unknown;
  authorization: string | null;
}

type Answer = { status: number; body: unknown };

function mockCloudflare(handler: (call: RecordedCall) => Answer): RecordedCall[] {
  const calls: RecordedCall[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    let body: unknown = undefined;
    if (typeof init?.body === "string") {
      body = JSON.parse(init.body);
    }
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const call: RecordedCall = { method, url, body, authorization: headers.authorization ?? null };
    calls.push(call);
    const answer = handler(call);
    return new Response(JSON.stringify(answer.body), { status: answer.status, headers: { "content-type": "application/json" } });
  });
  return calls;
}

const ZONE_LIST_OK: Answer = { status: 200, body: { success: true, result: [{ id: ZONE_ID, name: AGENCY_ZONE }] } };

function customHostnameRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "ch-1",
    hostname: HOSTNAME,
    status: "pending",
    ssl: { status: "pending_validation", validation_errors: [] },
    custom_origin_server: ORIGIN,
    verification_errors: [],
    ...overrides,
  };
}

/** A zone whose custom-hostname list returns `rows`, with POST/DELETE answered by the given answers. */
function zoneWith(rows: Array<Record<string, unknown>>, writes: { post?: Answer; del?: Answer } = {}) {
  return (call: RecordedCall): Answer => {
    if (call.url.startsWith("https://api.cloudflare.com/client/v4/zones?")) {
      return ZONE_LIST_OK;
    }
    const base = `https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/custom_hostnames`;
    if (call.method === "GET" && call.url.startsWith(`${base}?`)) {
      return { status: 200, body: { success: true, result: rows } };
    }
    if (call.method === "POST" && call.url === base) {
      return writes.post ?? { status: 200, body: { success: true, result: customHostnameRow({ id: "ch-new" }) } };
    }
    if (call.method === "DELETE" && call.url.startsWith(`${base}/`)) {
      return writes.del ?? { status: 200, body: { success: true, result: { id: "ch-1" } } };
    }
    return { status: 500, body: { success: false, errors: [{ message: `unexpected ${call.method} ${call.url}` }] } };
  };
}

// ── The twin pin + registration ──────────────────────────────────────────────────────

describe("custom-hostname twin block", () => {
  it("is byte-identical with the app copy (pinned sha256 — change BOTH twins and BOTH pins together)", async () => {
    const start = customHostnameParamsSource.indexOf(TWIN_BLOCK_START_MARKER);
    const end = customHostnameParamsSource.indexOf(TWIN_BLOCK_END_MARKER, start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const block = customHostnameParamsSource.slice(start, end);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(block)));
    let hex = "";
    for (const byte of digest) {
      hex += byte.toString(16).padStart(2, "0");
    }
    expect(hex).toBe(TWIN_BLOCK_SHA256);
  });

  it("all three ops are allowlisted and registered", () => {
    for (const op of ["custom-hostname-upsert", "custom-hostname-get", "custom-hostname-delete"] as const) {
      expect(DISPATCH_OPS).toContain(op);
      expect(typeof DISPATCH_OP_REGISTRY[op].actuate).toBe("function");
    }
  });
});

// ── Validators ───────────────────────────────────────────────────────────────────────

describe("custom-hostname params (twin of the app's rules)", () => {
  it("accepts a customer FQDN and an origin host, and returns ONLY the known keys", () => {
    expect(validateCustomHostnameUpsertParams({ hostname: HOSTNAME, customOriginServer: ORIGIN })).toEqual({
      ok: true,
      params: { hostname: HOSTNAME, customOriginServer: ORIGIN },
    });
    expect(validateCustomHostnameGetParams({ hostname: "ellissi.com.au", customOriginServer: ORIGIN })).toEqual({
      ok: true,
      params: { hostname: "ellissi.com.au", customOriginServer: ORIGIN },
    });
    // review M3: a read names the cell's origin, so it can say whether the entry is the platform's.
    expect(reasonOf(validateCustomHostnameGetParams({ hostname: HOSTNAME }))).toMatch(/^customOriginServer must be/);
    expect(validateCustomHostnameDeleteParams({ hostname: "xn--bcher-kva.example", customOriginServer: ORIGIN })).toEqual({
      ok: true,
      params: { hostname: "xn--bcher-kva.example", customOriginServer: ORIGIN },
    });
    // review M1: a delete must name the cell's origin, so it can only remove the platform's own entry.
    expect(reasonOf(validateCustomHostnameDeleteParams({ hostname: HOSTNAME }))).toMatch(/^customOriginServer must be/);
  });

  it("refuses ANY extra key — so a job can never carry a zone or an ssl method", () => {
    expect(reasonOf(validateCustomHostnameUpsertParams({ hostname: HOSTNAME, customOriginServer: ORIGIN, zone: "evil.com" }))).toMatch(
      /^unknown key "zone"/,
    );
    expect(reasonOf(validateCustomHostnameGetParams({ hostname: HOSTNAME, customOriginServer: ORIGIN, zoneId: ZONE_ID }))).toMatch(/^unknown key "zoneId"/);
    expect(reasonOf(validateCustomHostnameDeleteParams({ hostname: HOSTNAME, customOriginServer: ORIGIN, ssl: "txt" }))).toMatch(/^unknown key "ssl"/);
  });

  it("refuses a non-object and every malformed hostname", () => {
    expect(validateCustomHostnameGetParams(null).ok).toBe(false);
    expect(validateCustomHostnameGetParams([HOSTNAME]).ok).toBe(false);
    for (const hostname of [
      "",
      "localhost",
      "WWW.Example.com",
      "*.example.com",
      "www.example.com.",
      ".example.com",
      "-www.example.com",
      "www-.example.com",
      "www..example.com",
      "1.2.3.4",
      "_dmarc.example.com",
      "www.example.com/path",
      "www example.com",
      `${"a".repeat(64)}.example.com`,
      `${"a.".repeat(127)}com`,
      42,
    ]) {
      expect(reasonOf(validateCustomHostnameGetParams({ hostname, customOriginServer: ORIGIN })), String(hostname)).toMatch(
        /^hostname must be a lowercase fully-qualified domain name/,
      );
    }
  });

  it("refuses the platform zone and every name under it", () => {
    for (const hostname of [CUSTOM_HOSTNAME_PLATFORM_ZONE, "app.doubleyoup.com", "host.doubleyoup.com", "a.b.doubleyoup.com"]) {
      expect(reasonOf(validateCustomHostnameUpsertParams({ hostname, customOriginServer: ORIGIN }))).toMatch(/must not be doubleyoup\.com/);
    }
    // A name that only ENDS in the same letters is not under the zone.
    expect(validateCustomHostnameGetParams({ hostname: "notdoubleyoup.com", customOriginServer: ORIGIN }).ok).toBe(true);
  });

  it("refuses a malformed customOriginServer", () => {
    for (const customOriginServer of ["", "http://origin.example.com", "*.sbmstudio.com.au", "Origin.sbmstudio.com.au", undefined]) {
      expect(reasonOf(validateCustomHostnameUpsertParams({ hostname: HOSTNAME, customOriginServer }))).toMatch(/^customOriginServer must be/);
    }
  });

  it("the zone rules: no hostname in the agency zone, and the origin strictly under it", () => {
    expect(customHostnameZoneReason({ hostname: HOSTNAME, customOriginServer: ORIGIN }, AGENCY_ZONE)).toBeNull();
    expect(customHostnameZoneReason({ hostname: AGENCY_ZONE }, AGENCY_ZONE)).toMatch(/must not be the agency zone/);
    expect(customHostnameZoneReason({ hostname: "host.sbmstudio.com.au" }, AGENCY_ZONE)).toMatch(/must not be the agency zone/);
    expect(customHostnameZoneReason({ hostname: HOSTNAME, customOriginServer: AGENCY_ZONE }, AGENCY_ZONE)).toMatch(/customOriginServer must be a name under/);
    expect(customHostnameZoneReason({ hostname: HOSTNAME, customOriginServer: "origin.evil.com" }, AGENCY_ZONE)).toMatch(/customOriginServer must be a name under/);
    expect(customHostnameZoneReason({ hostname: HOSTNAME, customOriginServer: "xsbmstudio.com.au" }, AGENCY_ZONE)).toMatch(/customOriginServer must be a name under/);
  });

  it("isCustomHostnameFqdn is the shared grammar", () => {
    expect(isCustomHostnameFqdn("ellissi.com.au")).toBe(true);
    expect(isCustomHostnameFqdn("ellissi")).toBe(false);
  });
});

// ── custom-hostname-upsert ───────────────────────────────────────────────────────────

describe("custom-hostname-upsert", () => {
  const params = { hostname: HOSTNAME, customOriginServer: ORIGIN };

  it("calls nothing and fails cleanly when CF_CUSTOM_HOSTNAME_ZONE or the token is not set", async () => {
    const calls = mockCloudflare(() => ({ status: 500, body: {} }));
    const noZone = await actuateCustomHostnameUpsert(params, envWith({ CF_CUSTOM_HOSTNAME_ZONE: undefined }));
    expect(noZone.ok).toBe(false);
    expect(JSON.stringify(noZone)).toMatch(/CF_CUSTOM_HOSTNAME_ZONE is not configured/);
    const noToken = await actuateCustomHostnameUpsert(params, envWith({ CF_DNS_API_TOKEN: undefined }));
    expect(JSON.stringify(noToken)).toMatch(/CF_DNS_API_TOKEN is not configured/);
    const badZone = await actuateCustomHostnameUpsert(params, envWith({ CF_CUSTOM_HOSTNAME_ZONE: "not a zone" }));
    expect(JSON.stringify(badZone)).toMatch(/is not a zone name/);
    expect(calls).toHaveLength(0);
  });

  it("review L1: refuses the PLATFORM zone (or a name under it) as CF_CUSTOM_HOSTNAME_ZONE, for every op, calling nothing", async () => {
    const calls = mockCloudflare(zoneWith([customHostnameRow()]));
    for (const zone of ["doubleyoup.com", " DoubleYouP.com\n", "agency.doubleyoup.com"]) {
      const env = envWith({ CF_CUSTOM_HOSTNAME_ZONE: zone });
      const answers = [
        await actuateCustomHostnameUpsert(params, env),
        await actuateCustomHostnameGet({ hostname: HOSTNAME, customOriginServer: ORIGIN }, env),
        await actuateCustomHostnameDelete({ hostname: HOSTNAME, customOriginServer: ORIGIN }, env),
      ];
      for (const answer of answers) {
        expect(answer.ok, zone).toBe(false);
        expect(JSON.stringify(answer), zone).toMatch(/must be the agency's own zone, not doubleyoup\.com/);
      }
      const report = await probeCustomHostnameScope(env);
      expect(report.canReadCustomHostnames, zone).toBe(false);
    }
    expect(calls).toHaveLength(0);
    // A look-alike is not the platform zone.
    expect(configuredCustomHostnameZone(envWith({ CF_CUSTOM_HOSTNAME_ZONE: "notdoubleyoup.com" }))).toEqual({ zone: "notdoubleyoup.com" });
  });

  it("creates an absent hostname in the ENV zone with HTTP DV + TLS 1.2 and the given origin", async () => {
    const calls = mockCloudflare(zoneWith([]));
    // A trailing newline in the pasted secret is tolerated.
    const result = await actuateCustomHostnameUpsert(params, envWith({ CF_CUSTOM_HOSTNAME_ZONE: `${AGENCY_ZONE}\n` }));
    expect(result).toMatchObject({ ok: true, op: "custom-hostname-upsert", zone: AGENCY_ZONE, hostname: HOSTNAME, action: "created", originMatches: true });
    expect(calls[0]?.url).toBe(`https://api.cloudflare.com/client/v4/zones?name=${AGENCY_ZONE}&per_page=2`);
    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toBe(`https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/custom_hostnames`);
    expect(post?.body).toEqual({
      hostname: HOSTNAME,
      ssl: { method: "http", type: "dv", settings: { min_tls_version: "1.2" } },
      custom_origin_server: ORIGIN,
    });
    for (const call of calls) {
      expect(call.authorization).toBe(`Bearer ${CF_TOKEN}`);
    }
    expect(JSON.stringify(result)).not.toContain(CF_TOKEN);
  });

  it("an existing validating, active, blocked or pending_deletion hostname is reported and never written", async () => {
    for (const row of [
      customHostnameRow(),
      customHostnameRow({ status: "active", ssl: { status: "active" } }),
      customHostnameRow({ status: "blocked" }),
      customHostnameRow({ status: "pending_deletion", ssl: { status: "active" } }),
    ]) {
      const calls = mockCloudflare(zoneWith([row]));
      const result = await actuateCustomHostnameUpsert(params, envWith());
      expect(result).toMatchObject({ ok: true, action: "unchanged", customHostname: { id: "ch-1", status: row.status }, originMatches: true });
      expect(calls.filter((call) => call.method !== "GET")).toHaveLength(0);
      vi.restoreAllMocks();
    }
  });

  it("review M3: an entry with another origin, or none, is reported unchanged with originMatches:false — even a dead one is never deleted", async () => {
    for (const row of [
      customHostnameRow({ custom_origin_server: "other-origin.sbmstudio.com.au", status: "active", ssl: { status: "active" } }),
      customHostnameRow({ custom_origin_server: null }),
      customHostnameRow({ custom_origin_server: "other-origin.sbmstudio.com.au", status: "deleted" }),
    ]) {
      const calls = mockCloudflare(zoneWith([row]));
      const result = await actuateCustomHostnameUpsert(params, envWith());
      expect(result).toMatchObject({ ok: true, action: "unchanged", originMatches: false });
      expect(calls.filter((call) => call.method !== "GET")).toHaveLength(0);
      vi.restoreAllMocks();
    }
  });

  it("a `deleted` hostname is DELETEd and then re-created", async () => {
    const calls = mockCloudflare(zoneWith([customHostnameRow({ status: "deleted", ssl: { status: "validation_timed_out" } })]));
    const result = await actuateCustomHostnameUpsert(params, envWith());
    expect(result).toMatchObject({ ok: true, action: "recreated", customHostname: { id: "ch-new" }, originMatches: true });
    const writes = calls.filter((call) => call.method !== "GET").map((call) => `${call.method} ${call.url.replace(/^.*custom_hostnames/, "")}`);
    expect(writes).toEqual(["DELETE /ch-1", "POST "]);
  });

  it("a failed create after the delete says plainly that the hostname has none now", async () => {
    mockCloudflare(
      zoneWith([customHostnameRow({ status: "deleted" })], { post: { status: 400, body: { success: false, errors: [{ code: 1000, message: "nope" }] } } }),
    );
    const result = await actuateCustomHostnameUpsert(params, envWith());
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).toMatch(/has none now/);
  });

  it("a 1406 duplicate (a concurrent create) is read back and reported as unchanged", async () => {
    let lists = 0;
    mockCloudflare((call) => {
      if (call.url.startsWith("https://api.cloudflare.com/client/v4/zones?")) {
        return ZONE_LIST_OK;
      }
      if (call.method === "GET") {
        lists += 1;
        if (lists === 1) {
          return { status: 200, body: { success: true, result: [] } };
        }
        return { status: 200, body: { success: true, result: [customHostnameRow()] } };
      }
      return { status: 409, body: { success: false, errors: [{ code: 1406, message: "Duplicate custom hostname found." }] } };
    });
    const result = await actuateCustomHostnameUpsert(params, envWith());
    expect(result).toMatchObject({ ok: true, action: "unchanged", customHostname: { id: "ch-1" }, originMatches: true });
  });

  it("refuses a hostname inside the agency zone and an origin outside it, before any custom-hostname call", async () => {
    const calls = mockCloudflare(zoneWith([]));
    const inside = await actuateCustomHostnameUpsert({ hostname: "shop.sbmstudio.com.au", customOriginServer: ORIGIN }, envWith());
    expect(JSON.stringify(inside)).toMatch(/must not be the agency zone/);
    const outside = await actuateCustomHostnameUpsert({ hostname: HOSTNAME, customOriginServer: "syd-origin.doubleyoup.com" }, envWith());
    expect(JSON.stringify(outside)).toMatch(/customOriginServer must be a name under the agency zone/);
    expect(calls.filter((call) => call.url.includes("custom_hostnames"))).toHaveLength(0);
  });

  it("a zone the token cannot see fails closed", async () => {
    mockCloudflare(() => ({ status: 200, body: { success: true, result: [{ id: "other", name: "other.com" }] } }));
    const result = await actuateCustomHostnameUpsert(params, envWith());
    expect(JSON.stringify(result)).toMatch(/is not visible to CF_DNS_API_TOKEN/);
  });

  it("a 403 on the list names the missing SSL and Certificates scope", async () => {
    mockCloudflare((call) => {
      if (call.url.startsWith("https://api.cloudflare.com/client/v4/zones?")) {
        return ZONE_LIST_OK;
      }
      return { status: 403, body: { success: false, errors: [{ code: 10000, message: "Authentication error" }] } };
    });
    const result = await actuateCustomHostnameUpsert(params, envWith());
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).toMatch(/SSL and Certificates: Edit/);
    expect(JSON.stringify(result)).not.toContain(CF_TOKEN);
  });

  it("a prefix/substring match from Cloudflare's filter is never taken for the exact name", async () => {
    const calls = mockCloudflare(zoneWith([customHostnameRow({ id: "ch-other", hostname: `shop.${HOSTNAME}`, status: "deleted" })]));
    const result = await actuateCustomHostnameUpsert(params, envWith());
    expect(result).toMatchObject({ ok: true, action: "created" });
    expect(calls.filter((call) => call.method === "DELETE")).toHaveLength(0);
  });
});

// ── custom-hostname-get ──────────────────────────────────────────────────────────────

describe("custom-hostname-get", () => {
  it("reports status, SSL status, origin and bounded validation errors", async () => {
    const calls = mockCloudflare(
      zoneWith([
        customHostnameRow({
          verification_errors: ["custom hostname does not CNAME to this zone."],
          ssl: {
            status: "pending_validation",
            validation_errors: Array.from({ length: 8 }, (_, index) => ({ message: `error ${index} ${"x".repeat(400)}` })),
          },
        }),
      ]),
    );
    const result = await actuateCustomHostnameGet({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
    expect(result).toMatchObject({
      ok: true,
      op: "custom-hostname-get",
      zone: AGENCY_ZONE,
      found: true,
      customHostname: {
        id: "ch-1",
        status: "pending",
        sslStatus: "pending_validation",
        customOriginServer: ORIGIN,
        verificationErrors: ["custom hostname does not CNAME to this zone."],
      },
    });
    if (result.ok && result.found) {
      expect(result.customHostname.sslValidationErrors).toHaveLength(5);
      expect(result.customHostname.sslValidationErrors[0]?.length).toBe(300);
    }
    expect(calls.filter((call) => call.method !== "GET")).toHaveLength(0);
  });

  it("review M3: reports originMatches — true for the cell's origin, false for another one", async () => {
    mockCloudflare(zoneWith([customHostnameRow({ status: "active", ssl: { status: "active" } })]));
    const ours = await actuateCustomHostnameGet({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
    expect(ours).toMatchObject({ ok: true, found: true, originMatches: true });
    vi.restoreAllMocks();
    mockCloudflare(zoneWith([customHostnameRow({ status: "active", ssl: { status: "active" }, custom_origin_server: "wpe-origin.sbmstudio.com.au" })]));
    const foreign = await actuateCustomHostnameGet({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
    expect(foreign).toMatchObject({ ok: true, found: true, originMatches: false });
  });

  it("reports found:false when the zone has no entry for the name", async () => {
    mockCloudflare(zoneWith([]));
    const result = await actuateCustomHostnameGet({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
    expect(result).toEqual({ ok: true, op: "custom-hostname-get", zone: AGENCY_ZONE, hostname: HOSTNAME, found: false });
  });

  it("follows full pages, and refuses to guess when every page is full and none matches", async () => {
    const fullPage = Array.from({ length: 50 }, (_, index) => customHostnameRow({ id: `ch-${index}`, hostname: `x${index}.${HOSTNAME}` }));
    mockCloudflare(zoneWith(fullPage));
    const result = await actuateCustomHostnameGet({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).toMatch(/refusing to guess/);
  });
});

// ── custom-hostname-delete ───────────────────────────────────────────────────────────

describe("custom-hostname-delete", () => {
  it("an absent hostname is already-absent and nothing is deleted", async () => {
    const calls = mockCloudflare(zoneWith([]));
    const result = await actuateCustomHostnameDelete({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
    expect(result).toEqual({ ok: true, op: "custom-hostname-delete", zone: AGENCY_ZONE, hostname: HOSTNAME, status: "already-absent" });
    expect(calls.filter((call) => call.method === "DELETE")).toHaveLength(0);
  });

  it("deletes the exact entry by id; a 404 on the delete is already-absent", async () => {
    const calls = mockCloudflare(zoneWith([customHostnameRow()]));
    const result = await actuateCustomHostnameDelete({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
    expect(result).toMatchObject({ ok: true, status: "deleted" });
    expect(calls.find((call) => call.method === "DELETE")?.url).toBe(`https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/custom_hostnames/ch-1`);
    vi.restoreAllMocks();
    mockCloudflare(zoneWith([customHostnameRow()], { del: { status: 404, body: { success: false } } }));
    const gone = await actuateCustomHostnameDelete({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
    expect(gone).toMatchObject({ ok: true, status: "already-absent" });
  });

  it("refuses a name inside the agency zone (never one of the agency's own hosts)", async () => {
    const calls = mockCloudflare(zoneWith([]));
    const result = await actuateCustomHostnameDelete({ hostname: "host.sbmstudio.com.au", customOriginServer: ORIGIN }, envWith());
    expect(result.ok).toBe(false);
    expect(calls.filter((call) => call.url.includes("custom_hostnames"))).toHaveLength(0);
  });

  it("review M1: an entry with ANOTHER origin, or none, is left in place and reported foreign", async () => {
    for (const row of [
      customHostnameRow({ custom_origin_server: "wpe-origin.sbmstudio.com.au" }),
      customHostnameRow({ custom_origin_server: null }),
    ]) {
      const calls = mockCloudflare(zoneWith([row]));
      const result = await actuateCustomHostnameDelete({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
      expect(result).toMatchObject({ ok: false, op: "custom-hostname-delete", foreign: true });
      expect(JSON.stringify(result)).toMatch(/left in place/);
      expect(calls.filter((call) => call.method === "DELETE")).toHaveLength(0);
      vi.restoreAllMocks();
    }
  });

  it("review M1: the origin match is case-insensitive", async () => {
    mockCloudflare(zoneWith([customHostnameRow({ custom_origin_server: ORIGIN.toUpperCase() })]));
    const result = await actuateCustomHostnameDelete({ hostname: HOSTNAME, customOriginServer: ORIGIN }, envWith());
    expect(result).toMatchObject({ ok: true, status: "deleted" });
  });

  it("refuses an origin outside the agency zone before any custom-hostname call", async () => {
    const calls = mockCloudflare(zoneWith([customHostnameRow()]));
    const result = await actuateCustomHostnameDelete({ hostname: HOSTNAME, customOriginServer: "origin.evil.com" }, envWith());
    expect(JSON.stringify(result)).toMatch(/customOriginServer must be a name under the agency zone/);
    expect(calls.filter((call) => call.url.includes("custom_hostnames"))).toHaveLength(0);
  });
});

// ── /validate ───────────────────────────────────────────────────────────────────────

describe("/validate custom-hostname probe", () => {
  function probeZone(list: Answer, fallback: Answer) {
    return (call: RecordedCall): Answer => {
      expect(call.method).toBe("GET");
      if (call.url.startsWith("https://api.cloudflare.com/client/v4/zones?")) {
        return ZONE_LIST_OK;
      }
      if (call.url.endsWith("/custom_hostnames/fallback_origin")) {
        return fallback;
      }
      return list;
    };
  }

  it("reports read access and the fallback origin", async () => {
    mockCloudflare(
      probeZone(
        { status: 200, body: { success: true, result: [] } },
        { status: 200, body: { success: true, result: { origin: ORIGIN, status: "active" } } },
      ),
    );
    const report = await probeCustomHostnameScope(envWith());
    expect(report).toMatchObject({ zone: AGENCY_ZONE, canReadCustomHostnames: true, fallbackOrigin: ORIGIN, fallbackOriginStatus: "active" });
    expect(report.detail).toContain(`fallback origin ${ORIGIN} (active)`);
    expect(report.detail).not.toContain(CF_TOKEN);
  });

  it("reports a missing fallback origin", async () => {
    mockCloudflare(probeZone({ status: 200, body: { success: true, result: [] } }, { status: 404, body: { success: false, errors: [{ message: "not found" }] } }));
    const report = await probeCustomHostnameScope(envWith());
    expect(report).toMatchObject({ canReadCustomHostnames: true, fallbackOrigin: null });
    expect(report.detail).toContain("NO fallback origin is set");
  });

  it("reports a missing SSL and Certificates scope", async () => {
    mockCloudflare(probeZone({ status: 403, body: { success: false } }, { status: 403, body: { success: false } }));
    const report = await probeCustomHostnameScope(envWith());
    expect(report).toMatchObject({ zone: AGENCY_ZONE, canReadCustomHostnames: false, fallbackOrigin: null });
    expect(report.detail).toMatch(/SSL and Certificates: Edit/);
  });

  it("reports an unset zone without calling Cloudflare", async () => {
    const calls = mockCloudflare(() => ({ status: 500, body: {} }));
    const report = await probeCustomHostnameScope(envWith({ CF_CUSTOM_HOSTNAME_ZONE: undefined }));
    expect(report).toMatchObject({ zone: null, canReadCustomHostnames: false });
    expect(report.detail).toMatch(/CF_CUSTOM_HOSTNAME_ZONE is not configured/);
    expect(calls).toHaveLength(0);
  });

  it("is folded into the cfDns result, which stays green without it", async () => {
    mockCloudflare((call) => {
      if (call.url.includes("/custom_hostnames")) {
        return { status: 403, body: { success: false } };
      }
      if (call.url.includes("/accounts")) {
        return { status: 200, body: { success: true, result: [{ id: "acct" }] } };
      }
      if (call.url.includes("/rulesets/")) {
        return { status: 404, body: { success: false } };
      }
      return ZONE_LIST_OK;
    });
    const result = await validateCfDns(envWith());
    expect(result.ok).toBe(true);
    expect(result.customHostnames).toMatchObject({ zone: AGENCY_ZONE, canReadCustomHostnames: false });
    expect(result.detail).toMatch(/Custom hostnames: NOT available/);
    expect(JSON.stringify(result)).not.toContain(CF_TOKEN);
  });
});
