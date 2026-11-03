// hub#133 part 2 — the four branded-media ops (worker-route-upsert / -delete, media-hostmap-upsert /
// -delete). Worker side.
//
// What these tests pin:
//   - each op is on the allowlist and in the registry, and a signed job for it canonicalises and actuates
//     end to end through /actuate;
//   - the validators refuse a script or namespace override, a bad hostname and a bad HOSTMAP value;
//   - the route upsert refuses a hostname outside the zone (unless it is a custom hostname of that zone),
//     creates an absent route, reports its own route as unchanged and refuses a foreign one;
//   - the route delete removes only the media Worker's route and treats an absent one as already-absent;
//   - the HOSTMAP ops write only the pinned (or the HOSTMAP-titled) namespace, and a delete 404 is ok.

import { describe, it, expect, vi, afterEach } from "vitest";
import type { Env } from "../src/env.js";
import { DISPATCH_OPS, canonicalizeDispatchJob, type DispatchJob } from "../src/dispatch-verify.js";
import worker from "../src/index.js";
import { DISPATCH_OP_REGISTRY } from "../src/ops.js";
import {
  MEDIA_HOSTMAP_VALUE_RE,
  validateMediaHostmapDeleteParams,
  validateMediaHostmapUpsertParams,
  validateMediaWorkerRouteDeleteParams,
  validateMediaWorkerRouteUpsertParams,
} from "../src/dispatch-params-branded-media.js";
import {
  actuateMediaHostmapDelete,
  actuateMediaHostmapUpsert,
  actuateMediaWorkerRouteDelete,
  actuateMediaWorkerRouteUpsert,
  DEFAULT_MEDIA_WORKER_SCRIPT,
} from "../src/actuate-branded-media.js";

const CF = "https://api.cloudflare.com/client/v4";
const AGENCY_ZONE = "agency.example";
const ZONE_ID = "zone-id-1";
const ACCOUNT_ID = "acct-1";
const IN_ZONE_HOST = "acme-media.agency.example";
const CUSTOMER_HOST = "media.customer.example";
const HOSTMAP_ID = "0123456789abcdef0123456789abcdef";
const PINNED_HOSTMAP_ID = "fedcba9876543210fedcba9876543210";
const DNS_TOKEN = "cf-dns-token";
const ROUTE_ID = "aaaabbbbccccddddeeeeffff00001111";
const OTHER_ACCOUNT_ID = "acct-2";
const PINNED_ACCOUNT_ID = "9999aaaa9999aaaa9999aaaa9999aaaa";

const ROUTES_URL = `${CF}/zones/${ZONE_ID}/workers/routes`;
const KV_LIST_URL = `${CF}/accounts/${ACCOUNT_ID}/storage/kv/namespaces?per_page=100&page=1`;

function hostmapValueUrl(namespaceId: string, hostname: string): string {
  return `${CF}/accounts/${ACCOUNT_ID}/storage/kv/namespaces/${namespaceId}/values/${hostname}`;
}

interface RecordedCall {
  method: string;
  url: string;
  body: string | undefined;
  contentType: string | null;
  authorization: string | null;
}

type Answer = { status: number; body: unknown };

function mockCloudflare(handler: (call: RecordedCall) => Answer): RecordedCall[] {
  const calls: RecordedCall[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    let body: string | undefined = undefined;
    if (typeof init?.body === "string") {
      body = init.body;
    }
    const call: RecordedCall = {
      method: (init?.method ?? "GET").toUpperCase(),
      url: String(input),
      body,
      contentType: headers["content-type"] ?? null,
      authorization: headers.authorization ?? null,
    };
    calls.push(call);
    const answer = handler(call);
    return new Response(JSON.stringify(answer.body), { status: answer.status, headers: { "content-type": "application/json" } });
  });
  return calls;
}

function env(overrides: Partial<Env> = {}): Env {
  return { CF_DNS_API_TOKEN: DNS_TOKEN, ...overrides } as Env;
}

const OK_EMPTY: Answer = { status: 200, body: { success: true, result: null } };
const NOT_FOUND: Answer = { status: 404, body: { success: false, errors: [{ code: 10009, message: "key not found" }] } };

/**
 * A Cloudflare zone holding `routes` and `customHostnames`. Route POST answers `rt-new` (or 10020 for a
 * pattern that already has a route), a route GET by id answers that route, route DELETE answers ok; everything not modelled is a 500, so a stray call fails the test loudly.
 */
function zoneWith(routes: Array<Record<string, unknown>>, customHostnames: Array<Record<string, unknown>> = []) {
  return (call: RecordedCall): Answer => {
    if (call.url === `${CF}/zones?name=${AGENCY_ZONE}&per_page=2`) {
      return { status: 200, body: { success: true, result: [{ id: ZONE_ID, name: AGENCY_ZONE }] } };
    }
    if (call.url.startsWith(`${CF}/zones/${ZONE_ID}/custom_hostnames?`)) {
      return { status: 200, body: { success: true, result: customHostnames } };
    }
    if (call.method === "GET" && call.url === ROUTES_URL) {
      return { status: 200, body: { success: true, result: routes } };
    }
    if (call.method === "POST" && call.url === ROUTES_URL) {
      // Cloudflare refuses a second route with the same pattern (error 10020).
      const requested = JSON.parse(call.body ?? "{}") as { pattern?: string };
      if (routes.some((route) => route.pattern === requested.pattern)) {
        return { status: 409, body: { success: false, errors: [{ code: 10020, message: "A route with the same pattern already exists" }] } };
      }
      return { status: 200, body: { success: true, result: { id: "rt-new" } } };
    }
    if (call.method === "GET" && call.url.startsWith(`${ROUTES_URL}/`)) {
      const routeId = call.url.slice(`${ROUTES_URL}/`.length);
      const route = routes.find((candidate) => candidate.id === routeId);
      if (route === undefined) {
        return NOT_FOUND;
      }
      return { status: 200, body: { success: true, result: { pattern: route.pattern, script: route.script } } };
    }
    if (call.method === "DELETE" && call.url.startsWith(`${ROUTES_URL}/`)) {
      return { status: 200, body: { success: true, result: { id: "deleted" } } };
    }
    return { status: 500, body: { success: false } };
  };
}

/** An account whose KV namespaces are `namespaces`; value writes go to `onValue`. */
function accountWith(namespaces: Array<Record<string, unknown>>, onValue: (call: RecordedCall) => Answer = () => OK_EMPTY) {
  return (call: RecordedCall): Answer => {
    if (call.url === `${CF}/accounts?per_page=5`) {
      return { status: 200, body: { success: true, result: [{ id: ACCOUNT_ID }] } };
    }
    if (call.url === KV_LIST_URL) {
      return { status: 200, body: { success: true, result: namespaces } };
    }
    if (call.url.includes("/storage/kv/namespaces/") && call.url.includes("/values/")) {
      return onValue(call);
    }
    return { status: 500, body: { success: false } };
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ── registry ────────────────────────────────────────────────────────────────────────

describe("branded-media ops: allowlist and registry", () => {
  it("every op is allowlisted and has validateParams + actuate", () => {
    for (const op of ["worker-route-upsert", "worker-route-delete", "media-hostmap-upsert", "media-hostmap-delete"] as const) {
      expect(DISPATCH_OPS).toContain(op);
      expect(typeof DISPATCH_OP_REGISTRY[op].validateParams).toBe("function");
      expect(typeof DISPATCH_OP_REGISTRY[op].actuate).toBe("function");
    }
  });

  it("adds no generic KV-write op and no route-any-script op", () => {
    const opNames = DISPATCH_OPS as readonly string[];
    expect(opNames.filter((op) => /kv/i.test(op))).toEqual([]);
    expect(opNames).not.toContain("worker-route-any");
  });
});

// ── validators ──────────────────────────────────────────────────────────────────────

describe("branded-media ops: params", () => {
  it("accepts a zone + hostname for both route ops", () => {
    for (const validate of [validateMediaWorkerRouteUpsertParams, validateMediaWorkerRouteDeleteParams]) {
      expect(validate({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST })).toEqual({ ok: true, params: { zone: AGENCY_ZONE, hostname: IN_ZONE_HOST } });
      expect(validate({ zone: AGENCY_ZONE, hostname: CUSTOMER_HOST }).ok).toBe(true);
    }
  });

  it("accepts an optional routeId and refuses a malformed one", () => {
    for (const validate of [validateMediaWorkerRouteUpsertParams, validateMediaWorkerRouteDeleteParams]) {
      expect(validate({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID })).toEqual({
        ok: true,
        params: { zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID },
      });
      for (const badRouteId of ["rt-1", "", 7, null, ROUTE_ID.toUpperCase(), `${ROUTE_ID}0`]) {
        expect(validate({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: badRouteId })).toMatchObject({
          ok: false,
          reason: expect.stringContaining("routeId"),
        });
      }
    }
  });

  it("refuses a script override on the route ops", () => {
    for (const validate of [validateMediaWorkerRouteUpsertParams, validateMediaWorkerRouteDeleteParams]) {
      const verdict = validate({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, script: "evil-worker" });
      expect(verdict.ok).toBe(false);
    }
    expect(validateMediaWorkerRouteUpsertParams({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, pattern: "*/*" }).ok).toBe(false);
  });

  it("refuses a namespace override on the HOSTMAP ops", () => {
    expect(validateMediaHostmapUpsertParams({ hostname: IN_ZONE_HOST, value: "acme", namespaceId: PINNED_HOSTMAP_ID }).ok).toBe(false);
    expect(validateMediaHostmapDeleteParams({ hostname: IN_ZONE_HOST, namespaceId: PINNED_HOSTMAP_ID }).ok).toBe(false);
  });

  it("refuses a bad hostname on every op", () => {
    const badHosts = ["*.agency.example", "Acme.agency.example", "localhost", "acme.agency.example.", "a b.example", "", 7];
    for (const hostname of badHosts) {
      expect(validateMediaWorkerRouteUpsertParams({ zone: AGENCY_ZONE, hostname }).ok).toBe(false);
      expect(validateMediaWorkerRouteDeleteParams({ zone: AGENCY_ZONE, hostname }).ok).toBe(false);
      expect(validateMediaHostmapUpsertParams({ hostname, value: "acme" }).ok).toBe(false);
      expect(validateMediaHostmapDeleteParams({ hostname }).ok).toBe(false);
    }
  });

  it("refuses a bad zone on the route ops", () => {
    for (const zone of ["", "com", "*.agency.example", "Agency.example", "agency.example."]) {
      expect(validateMediaWorkerRouteUpsertParams({ zone, hostname: IN_ZONE_HOST }).ok).toBe(false);
    }
  });

  it("refuses a HOSTMAP value outside the media Worker's SLUG pattern", () => {
    expect(validateMediaHostmapUpsertParams({ hostname: IN_ZONE_HOST, value: "acme-2" }).ok).toBe(true);
    expect(validateMediaHostmapUpsertParams({ hostname: IN_ZONE_HOST, value: "a".repeat(46) }).ok).toBe(true);
    for (const value of ["", "Acme", "acme/../x", "acme_2", "a".repeat(47), "acme.media", 5]) {
      expect(validateMediaHostmapUpsertParams({ hostname: IN_ZONE_HOST, value }).ok).toBe(false);
    }
    expect(MEDIA_HOSTMAP_VALUE_RE.source).toBe("^[a-z0-9-]{1,46}$");
  });
});

// ── worker-route-upsert / -delete ───────────────────────────────────────────────────

describe("worker-route-upsert", () => {
  it("creates an absent route for an in-zone host, pointing at the default media Worker", async () => {
    const calls = mockCloudflare(zoneWith([]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env());
    expect(result).toEqual({
      ok: true,
      op: "worker-route-upsert",
      pattern: `${IN_ZONE_HOST}/*`,
      script: DEFAULT_MEDIA_WORKER_SCRIPT,
      routeId: "rt-new",
      status: "created",
    });
    const posts = calls.filter((call) => call.method === "POST");
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]?.body ?? "{}")).toEqual({ pattern: `${IN_ZONE_HOST}/*`, script: "doubleyoup-media" });
    // An in-zone host needs no custom-hostname lookup, and a new route needs no zone-wide route list.
    expect(calls.some((call) => call.url.includes("/custom_hostnames"))).toBe(false);
    expect(calls.some((call) => call.method === "GET" && call.url === ROUTES_URL)).toBe(false);
    for (const call of calls) {
      expect(call.authorization).toBe(`Bearer ${DNS_TOKEN}`);
    }
  });

  it("uses MEDIA_WORKER_SCRIPT when it is set", async () => {
    const calls = mockCloudflare(zoneWith([]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env({ MEDIA_WORKER_SCRIPT: "agency-media" }));
    expect(result).toMatchObject({ ok: true, script: "agency-media", status: "created" });
    const post = calls.find((call) => call.method === "POST");
    expect(JSON.parse(post?.body ?? "{}")).toEqual({ pattern: `${IN_ZONE_HOST}/*`, script: "agency-media" });
  });

  it("refuses an unusable MEDIA_WORKER_SCRIPT before any call", async () => {
    const calls = mockCloudflare(zoneWith([]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env({ MEDIA_WORKER_SCRIPT: "Bad Script" }));
    expect(result).toMatchObject({ ok: false, detail: expect.stringMatching(/MEDIA_WORKER_SCRIPT is not a Worker script name/) });
    expect(calls).toEqual([]);
  });

  it("is idempotent with the stored routeId: one read by id, no list and no write", async () => {
    const calls = mockCloudflare(zoneWith([{ id: ROUTE_ID, pattern: `${IN_ZONE_HOST}/*`, script: "doubleyoup-media" }]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID }, env());
    expect(result).toMatchObject({ ok: true, routeId: ROUTE_ID, status: "unchanged" });
    expect(calls.filter((call) => call.method !== "GET")).toEqual([]);
    expect(calls.some((call) => call.url === ROUTES_URL)).toBe(false);
    expect(calls.filter((call) => call.url === `${ROUTES_URL}/${ROUTE_ID}`)).toHaveLength(1);
  });

  it("is idempotent without a routeId: the refused create falls back to the lookup and reports unchanged", async () => {
    const calls = mockCloudflare(zoneWith([{ id: "rt-1", pattern: `${IN_ZONE_HOST}/*`, script: "doubleyoup-media" }]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env());
    expect(result).toMatchObject({ ok: true, routeId: "rt-1", status: "unchanged" });
    // The one POST was refused by Cloudflare (duplicate pattern), so nothing was written.
    expect(calls.filter((call) => call.method !== "GET").map((call) => call.method)).toEqual(["POST"]);
  });

  it("recreates the route when the stored routeId no longer exists", async () => {
    const calls = mockCloudflare(zoneWith([]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID }, env());
    expect(result).toMatchObject({ ok: true, routeId: "rt-new", status: "created" });
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(1);
  });

  it("refuses a routeId whose route has another pattern", async () => {
    const calls = mockCloudflare(zoneWith([{ id: ROUTE_ID, pattern: `other.${AGENCY_ZONE}/*`, script: "doubleyoup-media" }]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringMatching(/has the pattern "other\.agency\.example\/\*"/) });
    expect(calls.filter((call) => call.method !== "GET")).toEqual([]);
  });

  it("refuses to take over a route that points at another script", async () => {
    const calls = mockCloudflare(zoneWith([{ id: "rt-1", pattern: `${IN_ZONE_HOST}/*`, script: "agency-own-worker" }]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env());
    expect(result).toMatchObject({ ok: false, foreign: true, detail: expect.stringContaining("agency-own-worker") });
    expect(calls.filter((call) => call.method !== "GET").map((call) => call.method)).toEqual(["POST"]);
  });

  it("refuses to take over another script's route found by routeId", async () => {
    const calls = mockCloudflare(zoneWith([{ id: ROUTE_ID, pattern: `${IN_ZONE_HOST}/*`, script: "agency-own-worker" }]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID }, env());
    expect(result).toMatchObject({ ok: false, foreign: true });
    expect(calls.filter((call) => call.method !== "GET")).toEqual([]);
  });

  it("reports the create error when the create fails and no route exists", async () => {
    mockCloudflare((call) => {
      if (call.method === "POST") {
        return { status: 400, body: { success: false, errors: [{ code: 10019, message: "script not found" }] } };
      }
      return zoneWith([])(call);
    });
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringMatching(/create failed with HTTP 400.*script not found/) });
  });

  it("refuses a hostname outside the zone that is not a custom hostname of it", async () => {
    const calls = mockCloudflare(zoneWith([], []));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: CUSTOMER_HOST }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringMatching(/is not in zone "agency\.example" and is not a custom hostname of it/) });
    expect(calls.filter((call) => call.method !== "GET")).toEqual([]);
    expect(calls.some((call) => call.url === ROUTES_URL)).toBe(false);
  });

  it("accepts a customer media host that is a custom hostname of the zone", async () => {
    const calls = mockCloudflare(
      zoneWith([], [{ id: "ch-1", hostname: CUSTOMER_HOST, status: "active", ssl: { status: "active" }, custom_origin_server: `origin.${AGENCY_ZONE}` }]),
    );
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: CUSTOMER_HOST }, env());
    expect(result).toMatchObject({ ok: true, pattern: `${CUSTOMER_HOST}/*`, status: "created" });
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(1);
  });

  it("refuses a zone the agency token can not see", async () => {
    mockCloudflare((call) => {
      if (call.url.startsWith(`${CF}/zones?`)) {
        return { status: 200, body: { success: true, result: [] } };
      }
      return { status: 500, body: { success: false } };
    });
    const result = await actuateMediaWorkerRouteUpsert({ zone: "other.example", hostname: "acme-media.other.example" }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringMatching(/not visible to CF_DNS_API_TOKEN/) });
  });

  it("names the missing Workers Routes scope on a 403", async () => {
    mockCloudflare((call) => {
      if (call.url === ROUTES_URL) {
        return { status: 403, body: { success: false, errors: [{ code: 10000, message: "Authentication error" }] } };
      }
      return zoneWith([])(call);
    });
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringContaining("Workers Routes: Edit") });
  });

  it("calls nothing without CF_DNS_API_TOKEN", async () => {
    const calls = mockCloudflare(zoneWith([]));
    const result = await actuateMediaWorkerRouteUpsert({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, {} as Env);
    expect(result).toMatchObject({ ok: false, detail: expect.stringContaining("CF_DNS_API_TOKEN") });
    expect(calls).toEqual([]);
  });
});

describe("worker-route-delete", () => {
  it("deletes the media Worker's route", async () => {
    const calls = mockCloudflare(zoneWith([{ id: "rt-1", pattern: `${IN_ZONE_HOST}/*`, script: "doubleyoup-media" }]));
    const result = await actuateMediaWorkerRouteDelete({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env());
    expect(result).toEqual({ ok: true, op: "worker-route-delete", pattern: `${IN_ZONE_HOST}/*`, script: "doubleyoup-media", status: "deleted" });
    expect(calls.filter((call) => call.method === "DELETE").map((call) => call.url)).toEqual([`${ROUTES_URL}/rt-1`]);
  });

  it("is idempotent: an absent route is already-absent", async () => {
    const calls = mockCloudflare(zoneWith([{ id: "rt-9", pattern: `other.${AGENCY_ZONE}/*`, script: "doubleyoup-media" }]));
    const result = await actuateMediaWorkerRouteDelete({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env());
    expect(result).toMatchObject({ ok: true, status: "already-absent" });
    expect(calls.filter((call) => call.method === "DELETE")).toEqual([]);
  });

  it("a route that vanished before the DELETE (404) is already-absent", async () => {
    mockCloudflare((call) => {
      if (call.method === "DELETE") {
        return NOT_FOUND;
      }
      return zoneWith([{ id: "rt-1", pattern: `${IN_ZONE_HOST}/*`, script: "doubleyoup-media" }])(call);
    });
    const result = await actuateMediaWorkerRouteDelete({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env());
    expect(result).toMatchObject({ ok: true, status: "already-absent" });
  });

  it("refuses to delete a route that points at another script", async () => {
    const calls = mockCloudflare(zoneWith([{ id: "rt-1", pattern: `${IN_ZONE_HOST}/*`, script: "agency-own-worker" }]));
    const result = await actuateMediaWorkerRouteDelete({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, env());
    expect(result).toMatchObject({ ok: false, foreign: true });
    expect(calls.filter((call) => call.method === "DELETE")).toEqual([]);
  });

  it("with the stored routeId: one read by id and one DELETE, no zone-wide list", async () => {
    const calls = mockCloudflare(zoneWith([{ id: ROUTE_ID, pattern: `${IN_ZONE_HOST}/*`, script: "doubleyoup-media" }]));
    const result = await actuateMediaWorkerRouteDelete({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID }, env());
    expect(result).toMatchObject({ ok: true, status: "deleted" });
    expect(calls.some((call) => call.url === ROUTES_URL)).toBe(false);
    expect(calls.filter((call) => call.method === "DELETE").map((call) => call.url)).toEqual([`${ROUTES_URL}/${ROUTE_ID}`]);
  });

  it("with a stored routeId that is gone: already-absent, no list", async () => {
    const calls = mockCloudflare(zoneWith([]));
    const result = await actuateMediaWorkerRouteDelete({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID }, env());
    expect(result).toMatchObject({ ok: true, status: "already-absent" });
    expect(calls.some((call) => call.url === ROUTES_URL)).toBe(false);
    expect(calls.filter((call) => call.method === "DELETE")).toEqual([]);
  });

  it("refuses a routeId that points at another host's route", async () => {
    const calls = mockCloudflare(zoneWith([{ id: ROUTE_ID, pattern: `other.${AGENCY_ZONE}/*`, script: "doubleyoup-media" }]));
    const result = await actuateMediaWorkerRouteDelete({ zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID }, env());
    expect(result).toMatchObject({ ok: false });
    expect(calls.filter((call) => call.method === "DELETE")).toEqual([]);
  });
});

// ── media-hostmap-upsert / -delete ──────────────────────────────────────────────────

describe("HOSTMAP account: never the first account a multi-account token lists", () => {
  /** A token that sees two accounts; each account has its own HOSTMAP namespace. */
  function twoAccounts(onValue: (call: RecordedCall) => Answer = () => OK_EMPTY) {
    return (call: RecordedCall): Answer => {
      if (call.url === `${CF}/accounts?per_page=5`) {
        return { status: 200, body: { success: true, result: [{ id: OTHER_ACCOUNT_ID }, { id: ACCOUNT_ID }] } };
      }
      if (call.url.includes("/storage/kv/namespaces?")) {
        return { status: 200, body: { success: true, result: [{ id: HOSTMAP_ID, title: "HOSTMAP" }] } };
      }
      if (call.url.includes("/values/")) {
        return onValue(call);
      }
      return { status: 500, body: { success: false } };
    };
  }

  it("refuses to write when the token sees two accounts and MEDIA_ACCOUNT_ID is unset", async () => {
    const calls = mockCloudflare(twoAccounts());
    const result = await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringContaining("MEDIA_ACCOUNT_ID") });
    expect(calls.filter((call) => call.method !== "GET")).toEqual([]);
  });

  it("refuses to delete when the token sees two accounts and MEDIA_ACCOUNT_ID is unset", async () => {
    const calls = mockCloudflare(twoAccounts());
    const result = await actuateMediaHostmapDelete({ hostname: IN_ZONE_HOST }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringContaining("MEDIA_ACCOUNT_ID") });
    expect(calls.filter((call) => call.method !== "GET")).toEqual([]);
  });

  it("writes only to MEDIA_ACCOUNT_ID, without listing the token's accounts", async () => {
    const calls = mockCloudflare(twoAccounts());
    const result = await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env({ MEDIA_ACCOUNT_ID: PINNED_ACCOUNT_ID }));
    expect(result).toMatchObject({ ok: true, status: "written" });
    expect(calls.some((call) => call.url.startsWith(`${CF}/accounts?`))).toBe(false);
    const puts = calls.filter((call) => call.method === "PUT").map((call) => call.url);
    expect(puts).toEqual([`${CF}/accounts/${PINNED_ACCOUNT_ID}/storage/kv/namespaces/${HOSTMAP_ID}/values/${IN_ZONE_HOST}`]);
  });

  it("refuses a malformed MEDIA_ACCOUNT_ID before any call", async () => {
    const calls = mockCloudflare(twoAccounts());
    const result = await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env({ MEDIA_ACCOUNT_ID: "acct-1" }));
    expect(result).toMatchObject({ ok: false, detail: expect.stringContaining("MEDIA_ACCOUNT_ID") });
    expect(calls).toEqual([]);
  });
});

describe("media-hostmap-upsert", () => {
  it("PUTs the raw value into the namespace titled HOSTMAP", async () => {
    const calls = mockCloudflare(accountWith([{ id: "b".repeat(32), title: "OTHER" }, { id: HOSTMAP_ID, title: "HOSTMAP" }]));
    const result = await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env());
    expect(result).toEqual({ ok: true, op: "media-hostmap-upsert", hostname: IN_ZONE_HOST, value: "acme", status: "written" });
    const puts = calls.filter((call) => call.method === "PUT");
    expect(puts.map((call) => [call.url, call.body, call.contentType])).toEqual([[hostmapValueUrl(HOSTMAP_ID, IN_ZONE_HOST), "acme", "text/plain"]]);
  });

  it("is idempotent: a second run writes the same value again", async () => {
    const calls = mockCloudflare(accountWith([{ id: HOSTMAP_ID, title: "HOSTMAP" }]));
    await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env());
    const second = await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env());
    expect(second).toMatchObject({ ok: true, status: "written" });
    const puts = calls.filter((call) => call.method === "PUT");
    expect(puts).toHaveLength(2);
    expect(puts[0]?.url).toBe(puts[1]?.url);
    expect(puts[0]?.body).toBe(puts[1]?.body);
  });

  it("writes only MEDIA_HOSTMAP_KV_ID when it is pinned, without listing namespaces", async () => {
    const calls = mockCloudflare(accountWith([{ id: HOSTMAP_ID, title: "HOSTMAP" }]));
    const result = await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env({ MEDIA_HOSTMAP_KV_ID: PINNED_HOSTMAP_ID }));
    expect(result).toMatchObject({ ok: true });
    expect(calls.some((call) => call.url === KV_LIST_URL)).toBe(false);
    expect(calls.filter((call) => call.method === "PUT").map((call) => call.url)).toEqual([hostmapValueUrl(PINNED_HOSTMAP_ID, IN_ZONE_HOST)]);
  });

  it("refuses a malformed MEDIA_HOSTMAP_KV_ID before it writes", async () => {
    const calls = mockCloudflare(accountWith([]));
    const result = await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env({ MEDIA_HOSTMAP_KV_ID: "../other" }));
    expect(result).toMatchObject({ ok: false, detail: expect.stringContaining("MEDIA_HOSTMAP_KV_ID") });
    expect(calls.filter((call) => call.method !== "GET")).toEqual([]);
  });

  it("refuses when the account has no HOSTMAP namespace", async () => {
    const calls = mockCloudflare(accountWith([{ id: "b".repeat(32), title: "OTHER" }]));
    const result = await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringMatching(/no Workers KV namespace titled "HOSTMAP"/) });
    expect(calls.filter((call) => call.method !== "GET")).toEqual([]);
  });

  it("names the missing Workers KV scope on a 403", async () => {
    mockCloudflare(accountWith([{ id: HOSTMAP_ID, title: "HOSTMAP" }], () => ({ status: 403, body: { success: false, errors: [{ code: 10000 }] } })));
    const result = await actuateMediaHostmapUpsert({ hostname: IN_ZONE_HOST, value: "acme" }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringContaining("Workers KV Storage: Edit") });
  });
});

describe("media-hostmap-delete", () => {
  it("deletes the key", async () => {
    const calls = mockCloudflare(accountWith([{ id: HOSTMAP_ID, title: "HOSTMAP" }]));
    const result = await actuateMediaHostmapDelete({ hostname: IN_ZONE_HOST }, env());
    expect(result).toEqual({ ok: true, op: "media-hostmap-delete", hostname: IN_ZONE_HOST, status: "deleted" });
    expect(calls.filter((call) => call.method === "DELETE").map((call) => call.url)).toEqual([hostmapValueUrl(HOSTMAP_ID, IN_ZONE_HOST)]);
  });

  it("a 404 counts as already-absent", async () => {
    mockCloudflare(accountWith([{ id: HOSTMAP_ID, title: "HOSTMAP" }], () => NOT_FOUND));
    const result = await actuateMediaHostmapDelete({ hostname: IN_ZONE_HOST }, env());
    expect(result).toEqual({ ok: true, op: "media-hostmap-delete", hostname: IN_ZONE_HOST, status: "already-absent" });
  });

  it("reports any other failure", async () => {
    mockCloudflare(accountWith([{ id: HOSTMAP_ID, title: "HOSTMAP" }], () => ({ status: 500, body: { success: false, errors: [{ code: 1, message: "boom" }] } })));
    const result = await actuateMediaHostmapDelete({ hostname: IN_ZONE_HOST }, env());
    expect(result).toMatchObject({ ok: false, detail: expect.stringMatching(/HTTP 500/) });
  });
});

// ── signed jobs end to end ──────────────────────────────────────────────────────────

describe("branded-media ops: a signed /actuate job canonicalises and actuates", () => {
  function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  // A stand-in NONCE_STORE that reports every nonce fresh: these tests are about the ops, not replay.
  const freshNonceStore = {
    idFromName: () => ({}),
    get: () => ({ consume: async () => "fresh" as const }),
  } as unknown as Env["NONCE_STORE"];

  async function signedActuateRequest(op: string, params: Record<string, unknown>): Promise<{ request: Request; publicKeyPem: string; canonical: string }> {
    const keyPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", keyPair.publicKey)) as ArrayBuffer);
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${bytesToBase64(spki)}\n-----END PUBLIC KEY-----\n`;
    const job = {
      op,
      params: JSON.stringify(params),
      accountId: "acct_test_1",
      timestamp: new Date().toISOString(),
      nonce: "0123456789abcdef0123456789abcdef",
    } as DispatchJob;
    const canonical = canonicalizeDispatchJob(job);
    const signatureBytes = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, keyPair.privateKey, new TextEncoder().encode(canonical)));
    const request = new Request("http://localhost/actuate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ job, signature: bytesToBase64(signatureBytes) }),
    });
    return { request, publicKeyPem, canonical };
  }

  function allOfCloudflare(call: RecordedCall): Answer {
    if (call.url.startsWith(`${CF}/accounts`)) {
      return accountWith([{ id: HOSTMAP_ID, title: "HOSTMAP" }])(call);
    }
    return zoneWith([])(call);
  }

  const cases: Array<{ op: string; params: Record<string, unknown>; expected: Record<string, unknown> }> = [
    { op: "worker-route-upsert", params: { zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, expected: { ok: true, status: "created" } },
    { op: "worker-route-delete", params: { zone: AGENCY_ZONE, hostname: IN_ZONE_HOST }, expected: { ok: true, status: "already-absent" } },
    {
      op: "worker-route-delete",
      params: { zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, routeId: ROUTE_ID },
      expected: { ok: true, status: "already-absent" },
    },
    { op: "media-hostmap-upsert", params: { hostname: IN_ZONE_HOST, value: "acme" }, expected: { ok: true, status: "written" } },
    { op: "media-hostmap-delete", params: { hostname: IN_ZONE_HOST }, expected: { ok: true, status: "deleted" } },
  ];

  for (const testCase of cases) {
    it(`${testCase.op} ${Object.keys(testCase.params).join("+")}: canonical bytes are the five fields in key order, and the job actuates`, async () => {
      const { request, publicKeyPem, canonical } = await signedActuateRequest(testCase.op, testCase.params);
      expect(canonical.startsWith(`{"accountId":"acct_test_1","nonce":"0123456789abcdef0123456789abcdef","op":${JSON.stringify(testCase.op)},"params":`)).toBe(true);
      expect(canonical).toContain(JSON.stringify(JSON.stringify(testCase.params)));
      mockCloudflare(allOfCloudflare);
      const response = await worker.fetch(request, { ...env(), DY_SIGNING_PUBLIC_KEY: publicKeyPem, NONCE_STORE: freshNonceStore } as Env);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ op: testCase.op, ...testCase.expected });
    });
  }

  it("a signed job that carries a script override is a 400 and calls nothing", async () => {
    const { request, publicKeyPem } = await signedActuateRequest("worker-route-upsert", { zone: AGENCY_ZONE, hostname: IN_ZONE_HOST, script: "evil" });
    const calls = mockCloudflare(allOfCloudflare);
    const response = await worker.fetch(request, { ...env(), DY_SIGNING_PUBLIC_KEY: publicKeyPem, NONCE_STORE: freshNonceStore } as Env);
    expect(response.status).toBe(400);
    expect(calls).toEqual([]);
  });

  it("a signed job that carries a namespace override is a 400 and calls nothing", async () => {
    const { request, publicKeyPem } = await signedActuateRequest("media-hostmap-upsert", { hostname: IN_ZONE_HOST, value: "acme", namespaceId: PINNED_HOSTMAP_ID });
    const calls = mockCloudflare(allOfCloudflare);
    const response = await worker.fetch(request, { ...env(), DY_SIGNING_PUBLIC_KEY: publicKeyPem, NONCE_STORE: freshNonceStore } as Env);
    expect(response.status).toBe(400);
    expect(calls).toEqual([]);
  });
});
