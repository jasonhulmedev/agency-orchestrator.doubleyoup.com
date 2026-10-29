// hub#44 phase 2 — the `waf-edge-sync` op (specs/edge-security-via-worker.md, Amendments A1-A6).
//
// What these tests pin:
//   - the GOLDEN rule text: every clause form, the chunk join, the xmlrpc rule;
//   - the params validator (the twin of app's), refusal by refusal, including canonical IPs and UAs;
//   - the actuator against a STATEFUL fake of Cloudflare's rulesets API (it applies every POST /
//     PATCH / DELETE, honours `position`, and snapshots the phase after each write), so the tests can
//     check the zone's state BETWEEN writes, not only the final one:
//       * Free / unknown plan => planTooSmall, zero writes; capExceeded (end state and peak), zero writes;
//       * foreign rules never written, moved or deleted, and reported; pre-empting skips reported;
//       * a baseline written by waf-rule-upsert is patched in place (no delete, no create);
//       * write order: create -> gain patch -> lose patch -> delete empty;
//       * a seeded random walk: no still-wanted clause ever leaves its chunk, every addition lands
//         before any removal, and a clause once present is never absent again in that run;
//       * retireLegacy runs last, and only after every write of ours succeeded;
//       * the documented order of our rules, with foreign rules keeping their relative order;
//       * deterministic splitting of an oversized entry.
// Fixtures use example values only (this repo is public).

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import worker from "../src/index.js";
import type { Env } from "../src/env.js";
import { DISPATCH_OPS, canonicalizeDispatchJob, type DispatchJob } from "../src/dispatch-verify.js";
import { DISPATCH_OP_REGISTRY } from "../src/ops.js";
import {
  canonicalEdgeIpReason,
  edgeUserAgentReason,
  rfc5952Ipv6Text,
  validateWafEdgeSyncParams,
  type WafEdgeSyncParams,
} from "../src/dispatch-params.js";
import {
  EDGE_SYNC_DISPATCH_TIMEOUT_MS,
  EDGE_SYNC_LEASE_TTL_MS,
  actuateWafEdgeSync,
  actuateWafRuleUpsert,
  type WafEdgeSyncResult,
} from "../src/actuate.js";
import {
  EDGE_SYNC_BUDGET_REACHED,
  EDGE_SYNC_DEADLINE_REACHED,
  EDGE_SYNC_RATE_LIMIT_RESERVE,
  EDGE_SYNC_REQUEST_TIMEOUT_MS,
  EDGE_SYNC_RUN_DEADLINE_MS,
  EDGE_SYNC_RUN_LIMITS,
  EDGE_SYNC_SUBREQUEST_BUDGET,
  EDGE_SYNC_SUBREQUESTS_BEFORE_ACTUATION,
  EDGE_SYNC_WRITE_UNKNOWN,
  type EdgeSyncRunLimits,
} from "../src/edge-sync-budget.js";
import {
  RATE_LIMIT_EXPENSIVE_DESCRIPTION,
  RATE_LIMIT_ORIGIN_DESCRIPTION,
  RATE_LIMIT_STATIC_EXTENSIONS,
  buildRateLimitRules,
  rateLimitRuleCapForPlan,
} from "../src/edge-rate-limit.js";
import {
  EDGE_CHUNK_MAX_LENGTH,
  EDGE_STATIC_EXTENSIONS,
  WAF_SYNC_BASELINE_DESCRIPTIONS,
  WAF_XMLRPC_DESCRIPTION,
  buildEdgeChunkRule,
  buildEdgeClauses,
  buildXmlrpcRule,
  chunkClausesForPlanning,
  classifyWafRuleDescription,
  isCanonicalEdgeClause,
  joinChunkClauses,
  planStickyChunks,
  splitChunkExpression,
  wafXmlrpcExpression,
  type EdgeClauseEntry,
} from "../src/edge-waf-sync.js";
import {
  CLOUDFLARE_MANAGED_RULESET_ID,
  MANAGED_RULESET_RULE_DESCRIPTION,
  WAF_COUNTRY_BLOCK_DESCRIPTION,
  WAF_EXEC_SKIP_DESCRIPTION,
  WAF_EXPRESSION_MAX_LENGTH,
  WAF_FRONTEND_GEO_DESCRIPTION,
  WAF_LOGIN_GATE_DESCRIPTION,
  WAF_WPADMIN_GEO_DESCRIPTION,
  buildEdgeWafRules,
  edgeWafRulesInOrder,
} from "../src/edge-waf-rule.js";

// ── fixtures ──────────────────────────────────────────────────────────────────────────

const ZONE = "example.com";
const EXCLUDED_HOSTS = ["cell-x.example.com", "host.example.com"];
const AGENT_HOSTS = ["cell-x.example.com"];
const TOKEN = "cf-dns-token-abc";

/** A valid job, as app would send it. Every actuation test runs its params through the validator first. */
function rawParams(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    zone: ZONE,
    baseline: {
      enabled: true,
      excludedHosts: [...EXCLUDED_HOSTS],
      agentHosts: [...AGENT_HOSTS],
      includeManagedRuleset: false,
      xmlrpc: "block",
    },
    block: [],
    challenge: [],
    reservedSlots: 3,
    retireLegacy: false,
    ...overrides,
  };
}

function validParams(overrides: Record<string, unknown> = {}): WafEdgeSyncParams {
  const verdict = validateWafEdgeSyncParams(rawParams(overrides));
  if (!verdict.ok) {
    throw new Error(`fixture is invalid: ${verdict.reason}`);
  }
  return verdict.params;
}

/**
 * An in-memory stand-in for the NonceStore lease methods, with the Durable Object's semantics (an
 * unexpired lease held by another holder => "busy"; only the holder releases). One "instance" per
 * name, as idFromName gives. The real Durable Object is tested in test/nonce-store.worker.test.ts.
 */
class FakeLeaseNamespace {
  /** Leases by "<instance name>|<lease key>". */
  leases = new Map<string, { holder: string; expiresAt: number }>();
  /** Every acquire, in order, with its outcome. */
  acquires: Array<{ instance: string; leaseKey: string; outcome: "acquired" | "busy" }> = [];
  /** How many releases were called. */
  releases = 0;
  /** When true, every acquire succeeds: the world before the lease, for the overlap tests. */
  disabled = false;

  idFromName(name: string): string {
    return name;
  }

  get(instance: string) {
    return {
      acquireLease: async (leaseKey: string, holder: string, ttlMs: number): Promise<"acquired" | "busy"> => {
        const slot = `${instance}|${leaseKey}`;
        const held = this.leases.get(slot);
        let outcome: "acquired" | "busy" = "acquired";
        if (!this.disabled && held !== undefined && held.expiresAt > Date.now()) {
          outcome = "busy";
        } else {
          this.leases.set(slot, { holder, expiresAt: Date.now() + ttlMs });
        }
        this.acquires.push({ instance, leaseKey, outcome });
        return outcome;
      },
      releaseLease: async (leaseKey: string, holder: string): Promise<void> => {
        this.releases += 1;
        const slot = `${instance}|${leaseKey}`;
        if (this.leases.get(slot)?.holder === holder) {
          this.leases.delete(slot);
        }
      },
    };
  }
}

function envWithToken(leases: FakeLeaseNamespace = new FakeLeaseNamespace()): Env {
  return { CF_DNS_API_TOKEN: TOKEN, NONCE_STORE: leases } as unknown as Env;
}

/** The baseline rule bodies the Worker builds for the fixture hosts (5 + xmlrpc), in apply order. */
function baselineBodies(enabled = true, xmlrpcEnabled = enabled): Record<string, ReturnType<typeof buildXmlrpcRule>> {
  const built = buildEdgeWafRules({ zone: ZONE, enabled, excludedHosts: EXCLUDED_HOSTS, agentHosts: AGENT_HOSTS });
  if (!built.ok) throw new Error(built.reason);
  return {
    country: built.rules.countryBlock,
    wpadmin: built.rules.wpAdminGeo,
    xmlrpc: buildXmlrpcRule(xmlrpcEnabled),
    login: built.rules.loginGate,
    frontend: built.rules.frontendGeo,
    skip: built.rules.execSkip,
  };
}

/** A zone whose custom phase holds one agency rule and none of ours (so its entrypoint exists). */
function agencyRulesOnly(): FakeRule[] {
  return [{ id: "f-agency", description: "agency-log-office", expression: "ip.src in {203.0.113.0/24}", action: "log", enabled: true }];
}

/** The six baseline rules as a zone holds them, with fixed ids, in the documented order. */
function baselineRulesInOrder(): FakeRule[] {
  const bodies = baselineBodies();
  return [
    { id: "b-country", ...bodies.country },
    { id: "b-wpadmin", ...bodies.wpadmin },
    { id: "b-xmlrpc", ...bodies.xmlrpc },
    { id: "b-login", ...bodies.login },
    { id: "b-frontend", ...bodies.frontend },
    { id: "b-skip", ...bodies.skip },
  ] as FakeRule[];
}

/** One site-ip clause, built by the Worker's own builder (so the fixtures cannot drift from it). */
function siteIpClause(ip: string, hosts: string[]): string {
  const built = buildEdgeClauses([{ hosts, ips: [ip], uas: [], all: false }], EXCLUDED_HOSTS);
  if (!built.ok || built.clauses.length !== 1) throw new Error("fixture clause did not build as one clause");
  return built.clauses[0] as string;
}

/** `count` distinct long host names (each about `length` characters) under a site domain. */
function longHosts(prefix: string, count: number, length = 200): string[] {
  const hosts: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const label = `${prefix}${index}`.padEnd(Math.min(length - 12, 60), "x");
    const filler = "y".repeat(Math.max(0, length - label.length - 12));
    // Labels max 63 characters: split the filler into 60-character labels.
    const fillerLabels: string[] = [];
    for (let start = 0; start < filler.length; start += 60) {
      fillerLabels.push(filler.slice(start, start + 60));
    }
    hosts.push([label, ...fillerLabels, "example.net"].join("."));
  }
  return hosts;
}

// ── a stateful fake of Cloudflare's zone + rulesets API ───────────────────────────────

interface FakeRule {
  id: string;
  description?: string;
  expression?: string;
  action?: string;
  enabled?: boolean;
  action_parameters?: unknown;
  ratelimit?: unknown;
}

type FakePhase = "custom" | "managed" | "ratelimit";

interface FakeWrite {
  method: string;
  phase: FakePhase;
  /** The description of the rule written (for a DELETE: of the rule deleted). */
  description: string;
  ruleId: string | null;
  body?: Record<string, unknown>;
}

const PHASE_NAMES: Record<FakePhase, string> = {
  custom: "http_request_firewall_custom",
  managed: "http_request_firewall_managed",
  ratelimit: "http_ratelimit",
};
const RULESET_IDS: Record<FakePhase, string> = { custom: "rs-custom", managed: "rs-managed", ratelimit: "rs-ratelimit" };
const FAKE_PHASES: readonly FakePhase[] = ["custom", "managed", "ratelimit"];

/**
 * What Cloudflare enforces on a rate-limit rule, restated here from its docs (independently of the
 * Worker's own table): the plan's rule budget, the Cookie field only on Enterprise, Pro's 60 s period
 * and 1 h mitigation maximums, and no cache exclusion below Business.
 */
const FAKE_RATE_LIMIT_PLANS: Record<string, { rules: number; maxPeriod: number; maxMitigation: number; cookie: boolean; cacheExclusion: boolean }> = {
  free: { rules: 1, maxPeriod: 10, maxMitigation: 10, cookie: false, cacheExclusion: false },
  pro: { rules: 2, maxPeriod: 60, maxMitigation: 3600, cookie: false, cacheExclusion: false },
  business: { rules: 5, maxPeriod: 600, maxMitigation: 86400, cookie: false, cacheExclusion: true },
  enterprise: { rules: 100, maxPeriod: 65535, maxMitigation: 86400, cookie: true, cacheExclusion: true },
};

function cloneRules(rules: FakeRule[]): FakeRule[] {
  return rules.map((rule) => JSON.parse(JSON.stringify(rule)) as FakeRule);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

class FakeCloudflare {
  plan: string | null = "pro";
  customRules: FakeRule[] | null;
  managedRules: FakeRule[] | null = null;
  rateLimitRules: FakeRule[] | null = null;
  /** Every write, in order. */
  writes: FakeWrite[] = [];
  /** The custom phase after each custom-phase write. */
  snapshots: FakeRule[][] = [];
  /** Every request, in order (method + path). */
  requests: string[] = [];
  /** A write for which this returns true answers HTTP 500 and changes nothing. */
  failWrite: ((write: FakeWrite) => boolean) | null = null;
  /** A phase whose entrypoint read answers HTTP 403. */
  failRead: FakePhase | null = null;
  /** For each request, in order: did it carry an AbortSignal? */
  signals: boolean[] = [];
  /** A request for which this returns true never answers: it fails only when its signal aborts. */
  hang: ((method: string, path: string) => boolean) | null = null;
  /** A fake clock (ms) that every request moves on by `msPerRequest`; tests hand `() => clockMs` to the run. */
  clockMs = 0;
  msPerRequest = 0;
  private nextId = 1;

  constructor(customRules: FakeRule[] | null) {
    this.customRules = customRules === null ? null : cloneRules(customRules);
  }

  install(): this {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      this.signals.push(init?.signal instanceof AbortSignal);
      this.clockMs += this.msPerRequest;
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (this.hang !== null && this.hang(init?.method ?? "GET", new URL(url).pathname)) {
        const signal = init?.signal;
        this.requests.push(`${init?.method ?? "GET"} ${new URL(url).pathname} (hung)`);
        return new Promise<Response>((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(signal.reason));
        });
      }
      return this.handle(input, init);
    });
    return this;
  }

  /** The description of every custom rule, in order. */
  customDescriptions(): string[] {
    return (this.customRules ?? []).map((rule) => rule.description ?? "");
  }

  private rulesOf(phase: FakePhase): FakeRule[] | null {
    if (phase === "custom") return this.customRules;
    if (phase === "managed") return this.managedRules;
    return this.rateLimitRules;
  }

  private setRulesOf(phase: FakePhase, rules: FakeRule[]): void {
    if (phase === "custom") this.customRules = rules;
    else if (phase === "managed") this.managedRules = rules;
    else this.rateLimitRules = rules;
  }

  /** Cloudflare's refusal of a rate-limit rule the zone's plan does not allow, or null. */
  private rateLimitRefusal(rule: Record<string, unknown>): string | null {
    const limits = FAKE_RATE_LIMIT_PLANS[this.plan ?? ""];
    if (limits === undefined) return "rate limiting rules are not available on this plan";
    const config = rule.ratelimit as Record<string, unknown> | undefined;
    if (config === undefined) return "a rate limiting rule needs a ratelimit object";
    if (!limits.cookie && String(rule.expression ?? "").includes("http.cookie")) return "the field http.cookie is not allowed on this plan";
    if (Number(config.period) > limits.maxPeriod) return "period is not allowed on this plan";
    if (Number(config.mitigation_timeout) > limits.maxMitigation) return "mitigation_timeout is not allowed on this plan";
    if (config.requests_to_origin === true && !limits.cacheExclusion) return "requests_to_origin is not allowed on this plan";
    if (!Array.isArray(config.characteristics) || !config.characteristics.includes("cf.colo.id")) return "characteristics must include cf.colo.id";
    return null;
  }

  private newId(): string {
    const id = `new-${this.nextId}`;
    this.nextId += 1;
    return id;
  }

  private insertAt(rules: FakeRule[], rule: FakeRule, position: unknown): void {
    const place = position as { before?: string; after?: string; index?: number } | undefined;
    if (place === undefined) {
      rules.push(rule);
      return;
    }
    if (typeof place.before === "string") {
      const anchor = rules.findIndex((candidate) => candidate.id === place.before);
      if (anchor === -1) throw new Error(`position.before names an unknown rule ${place.before}`);
      rules.splice(anchor, 0, rule);
      return;
    }
    if (typeof place.after === "string") {
      const anchor = rules.findIndex((candidate) => candidate.id === place.after);
      if (anchor === -1) throw new Error(`position.after names an unknown rule ${place.after}`);
      rules.splice(anchor + 1, 0, rule);
      return;
    }
    throw new Error("unsupported position");
  }

  private definitionOf(body: Record<string, unknown>, id: string): FakeRule {
    const definition: Record<string, unknown> = { ...body, id };
    delete definition.position;
    return definition as unknown as FakeRule;
  }

  private handle(input: RequestInfo | URL, init: RequestInit | undefined): Response {
    let url: string;
    if (typeof input === "string") url = input;
    else if (input instanceof URL) url = input.toString();
    else url = input.url;
    const method = init?.method ?? "GET";
    expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${TOKEN}`);
    const parsed = new URL(url);
    const path = parsed.pathname;
    this.requests.push(`${method} ${path}`);
    let body: Record<string, unknown> | undefined;
    if (typeof init?.body === "string") body = JSON.parse(init.body) as Record<string, unknown>;

    if (path === "/client/v4/zones" && method === "GET") {
      const zone: Record<string, unknown> = { id: "zone-1", name: parsed.searchParams.get("name") };
      if (this.plan !== null) zone.plan = { legacy_id: this.plan };
      return jsonResponse({ success: true, result: [zone] });
    }
    for (const candidate of FAKE_PHASES) {
      if (path !== `/client/v4/zones/zone-1/rulesets/phases/${PHASE_NAMES[candidate]}/entrypoint` || method !== "GET") continue;
      if (this.failRead === candidate) return jsonResponse({ success: false, errors: [{ message: "Authentication error" }] }, 403);
      const rules = this.rulesOf(candidate);
      if (rules === null) return jsonResponse({ success: false, errors: [{ message: "not found" }] }, 404);
      return jsonResponse({ success: true, result: { id: RULESET_IDS[candidate], rules: cloneRules(rules) } });
    }

    // Writes.
    const ruleMatch = /^\/client\/v4\/zones\/zone-1\/rulesets\/(rs-custom|rs-managed|rs-ratelimit)\/rules(?:\/([^/]+))?$/.exec(path);
    let phase: FakePhase = "custom";
    let ruleId: string | null = null;
    if (path === "/client/v4/zones/zone-1/rulesets" && method === "POST") {
      const named = FAKE_PHASES.find((candidate) => PHASE_NAMES[candidate] === body?.phase);
      if (named === undefined) throw new Error(`entrypoint create for an unknown phase ${String(body?.phase)}`);
      phase = named;
    } else if (ruleMatch !== null) {
      phase = FAKE_PHASES.find((candidate) => RULESET_IDS[candidate] === ruleMatch[1]) as FakePhase;
      ruleId = ruleMatch[2] === undefined ? null : decodeURIComponent(ruleMatch[2]);
    } else {
      throw new Error(`unexpected fetch ${method} ${url}`);
    }
    const target = this.rulesOf(phase);
    let description = String(body?.description ?? "");
    if (method === "POST" && ruleMatch === null) description = "entrypoint";
    if (method === "DELETE") {
      description = target?.find((rule) => rule.id === ruleId)?.description ?? "";
    }
    const write: FakeWrite = { method, phase, description, ruleId, body };
    if (this.failWrite !== null && this.failWrite(write)) {
      return jsonResponse({ success: false, errors: [{ code: 20200, message: "simulated failure" }] }, 500);
    }
    // Cloudflare refuses an expression over 4,096 characters, so the fake does too.
    const writtenRules = (body?.rules as Array<Record<string, unknown>> | undefined) ?? (body === undefined ? [] : [body]);
    for (const rule of writtenRules) {
      if (typeof rule.expression === "string" && rule.expression.length > WAF_EXPRESSION_MAX_LENGTH) {
        return jsonResponse({ success: false, errors: [{ code: 20120, message: "expression is too long" }] }, 400);
      }
      if (phase === "ratelimit" && method !== "DELETE") {
        const refusal = this.rateLimitRefusal(rule);
        if (refusal !== null) return jsonResponse({ success: false, errors: [{ code: 20217, message: refusal }] }, 400);
      }
    }
    if (phase === "ratelimit" && method === "POST") {
      const limits = FAKE_RATE_LIMIT_PLANS[this.plan ?? ""];
      const after = (target?.length ?? 0) + writtenRules.length;
      if (limits === undefined || after > limits.rules) {
        return jsonResponse({ success: false, errors: [{ code: 20210, message: "exceeded the maximum number of rate limiting rules" }] }, 400);
      }
    }
    this.writes.push(write);

    const rulesetId = RULESET_IDS[phase];
    if (method === "POST" && ruleMatch === null) {
      const created = ((body?.rules ?? []) as Array<Record<string, unknown>>).map((rule) => this.definitionOf(rule, this.newId()));
      this.setRulesOf(phase, created);
    } else {
      if (target === null) throw new Error(`write to a missing ${phase} entrypoint`);
      if (method === "POST") {
        this.insertAt(target, this.definitionOf(body ?? {}, this.newId()), body?.position);
      } else if (method === "PATCH") {
        const index = target.findIndex((rule) => rule.id === ruleId);
        if (index === -1) return jsonResponse({ success: false, errors: [{ message: "rule not found" }] }, 404);
        target.splice(index, 1);
        const replacement = this.definitionOf(body ?? {}, ruleId as string);
        if (body?.position === undefined) target.splice(index, 0, replacement);
        else this.insertAt(target, replacement, body.position);
      } else if (method === "DELETE") {
        const index = target.findIndex((rule) => rule.id === ruleId);
        if (index === -1) return jsonResponse({ success: false, errors: [{ message: "rule not found" }] }, 404);
        target.splice(index, 1);
      } else {
        throw new Error(`unexpected write method ${method}`);
      }
    }
    if (phase === "custom") this.snapshots.push(cloneRules(this.customRules ?? []));
    return jsonResponse({ success: true, result: { id: rulesetId, rules: cloneRules(this.rulesOf(phase) ?? []) } });
  }
}

/** A request, as the clause evaluator below reads it. */
interface ExampleRequest {
  host: string;
  path: string;
  ip: string;
  userAgent: string;
}

/** Cloudflare's http.request.uri.path.extension: after the last dot of the last segment, lowercased. */
function pathExtension(path: string): string {
  const lastSegment = path.split("/").pop() ?? "";
  const lastDot = lastSegment.lastIndexOf(".");
  if (lastDot <= 0) return "";
  return lastSegment.slice(lastDot + 1).toLowerCase();
}

function quotedValues(setBody: string): string[] {
  return [...setBody.matchAll(/"([^"]*)"/g)].map((match) => match[1] as string);
}

function hostTestMatches(hostTest: string, host: string): boolean {
  // Cloudflare does not lowercase http.host: the site test lowercases it, the global test does not.
  const included = /^lower\(http\.host\) in \{(.*)\}$/.exec(hostTest);
  if (included !== null) return quotedValues(included[1] as string).includes(host.toLowerCase());
  const excluded = /^not http\.host in \{(.*)\}$/.exec(hostTest);
  if (excluded !== null) return !quotedValues(excluded[1] as string).includes(host);
  throw new Error(`not a host test the evaluator knows: ${hostTest}`);
}

/**
 * True when one of OUR canonical clause forms matches the request. A tiny evaluator for exactly the
 * forms buildEdgeClauses renders (single IPs only); any other text throws, so a test cannot pass by
 * a form it does not understand.
 */
function clauseMatches(clause: string, request: ExampleRequest): boolean {
  const ipClause = /^\(ip\.src in \{([^}]*)\} and (.*)\)$/.exec(clause);
  if (ipClause !== null) {
    return (ipClause[1] as string).split(" ").includes(request.ip) && hostTestMatches(ipClause[2] as string, request.host);
  }
  const userAgentClause = /^\(http\.user_agent contains "([^"]*)" and (.*)\)$/.exec(clause);
  if (userAgentClause !== null) {
    return request.userAgent.includes(userAgentClause[1] as string) && hostTestMatches(userAgentClause[2] as string, request.host);
  }
  const allClause = /^\((.*) and not http\.request\.uri\.path\.extension in \{(.*)\}\)$/.exec(clause);
  if (allClause !== null) {
    const exempt = quotedValues(allClause[2] as string).includes(pathExtension(request.path));
    return hostTestMatches(allClause[1] as string, request.host) && !exempt;
  }
  // A bare host test: the pre-A9 `all` form.
  return hostTestMatches(clause, request.host);
}

function anyClauseMatches(clauses: readonly string[], request: ExampleRequest): boolean {
  return clauses.some((clause) => clauseMatches(clause, request));
}

/** The clauses of every chunk rule in a phase snapshot, keyed by chunk description. */
function chunkClauses(rules: readonly FakeRule[]): Map<string, Set<string>> {
  const chunks = new Map<string, Set<string>>();
  for (const rule of rules) {
    if (classifyWafRuleDescription(rule.description).owner !== "chunk") continue;
    chunks.set(rule.description as string, new Set(splitChunkExpression(rule.expression ?? "")));
  }
  return chunks;
}

/** Every (chunk kind, clause) pair present in a snapshot, as "block|<clause>" strings. */
function presentClauses(rules: readonly FakeRule[]): Set<string> {
  const present = new Set<string>();
  for (const [description, clauses] of chunkClauses(rules)) {
    const kind = description.startsWith("doubleyoup-edge-block:") ? "block" : "challenge";
    for (const clause of clauses) present.add(`${kind}|${clause}`);
  }
  return present;
}

/** The writes as "METHOD description" strings, for order assertions. */
function writeLog(fake: FakeCloudflare): string[] {
  return fake.writes.map((write) => `${write.method} ${write.description}`);
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ── golden text ───────────────────────────────────────────────────────────────────────

/** The static-file exemption every `all` clause carries (Amendment A9), as golden text. */
const STATIC_EXEMPTION =
  'not http.request.uri.path.extension in {"css" "js" "jpg" "jpeg" "gif" "png" "webp" "svg" "woff" "woff2"}';

describe("waf-edge-sync: golden rule text", () => {
  it("renders each clause form canonically: sorted, de-duplicated, fixed spacing", () => {
    const entries: EdgeClauseEntry[] = [
      // Site ip: the IPs and the hosts are sorted, whatever order they arrive in.
      { hosts: ["b.example.com", "a.example.org"], ips: ["198.51.100.7", "192.0.2.0/24"], uas: [], all: false },
      // Site ua: one clause per User-Agent.
      { hosts: ["a.example.com"], ips: [], uas: ["ZetaBot/2.0", "BadBot/1.0 (+https://bad.example)"], all: false },
      // Site all.
      { hosts: ["www.a.example.com", "a.example.com"], ips: [], uas: [], all: true },
      // Global entries: the host test becomes "every host but the zone's infrastructure".
      { hosts: [], ips: ["2001:db8::/32"], uas: ["EvilCrawler/9"], all: true },
      // A second entry rendering an identical clause is one clause, not two.
      { hosts: ["a.example.org", "b.example.com"], ips: ["192.0.2.0/24", "198.51.100.7"], uas: [], all: false },
    ];
    const built = buildEdgeClauses(entries, ["host.example.com", "cell-x.example.com"]);
    expect(built).toEqual({
      ok: true,
      clauses: [
        '(http.user_agent contains "BadBot/1.0 (+https://bad.example)" and lower(http.host) in {"a.example.com"})',
        '(http.user_agent contains "EvilCrawler/9" and not http.host in {"cell-x.example.com" "host.example.com"})',
        '(http.user_agent contains "ZetaBot/2.0" and lower(http.host) in {"a.example.com"})',
        '(ip.src in {192.0.2.0/24 198.51.100.7} and lower(http.host) in {"a.example.org" "b.example.com"})',
        '(ip.src in {2001:db8::/32} and not http.host in {"cell-x.example.com" "host.example.com"})',
        `(lower(http.host) in {"a.example.com" "www.a.example.com"} and ${STATIC_EXEMPTION})`,
        `(not http.host in {"cell-x.example.com" "host.example.com"} and ${STATIC_EXEMPTION})`,
      ],
    });
    // A10: both static lists are exactly the cell nginx static set.
    const nginxStaticSet = ["css", "gif", "jpeg", "jpg", "js", "png", "svg", "webp", "woff", "woff2"];
    expect([...EDGE_STATIC_EXTENSIONS].sort()).toEqual(nginxStaticSet);
    expect([...RATE_LIMIT_STATIC_EXTENSIONS].sort()).toEqual(nginxStaticSet);
    // Every form the builder renders is one the chunk parser accepts as ours.
    if (built.ok) {
      for (const clause of built.clauses) expect(isCanonicalEdgeClause(clause), clause).toBe(true);
    }
  });

  it("A9: an `all` clause leaves static files alone, while an ip ban on the same site still covers them", () => {
    const siteHosts = ["www.a.example.com", "a.example.com"];
    const challenge = buildEdgeClauses([{ hosts: siteHosts, ips: [], uas: [], all: true }], EXCLUDED_HOSTS);
    const block = buildEdgeClauses([{ hosts: siteHosts, ips: ["192.0.2.7"], uas: [], all: false }], EXCLUDED_HOSTS);
    const globalChallenge = buildEdgeClauses([{ hosts: [], ips: [], uas: [], all: true }], EXCLUDED_HOSTS);
    if (!challenge.ok || !block.ok || !globalChallenge.ok) throw new Error("fixture clauses refused");
    const visitor = { ip: "203.0.113.5", userAgent: "Mozilla/5.0 (example)" };
    const banned = { ip: "192.0.2.7", userAgent: "Mozilla/5.0 (example)" };
    const page = { ...visitor, host: "www.a.example.com", path: "/" };

    // Site Under Attack: pages are challenged; images, styles, scripts and fonts are not.
    expect(anyClauseMatches(challenge.clauses, page)).toBe(true);
    expect(anyClauseMatches(challenge.clauses, { ...page, path: "/index.php" })).toBe(true);
    expect(anyClauseMatches(challenge.clauses, { ...page, path: "/logo.png.php" })).toBe(true);
    for (const path of ["/wp-content/uploads/logo.png", "/LOGO.PNG", "/wp-content/themes/t/style.css", "/app.js", "/fonts/a.woff2"]) {
      expect(anyClauseMatches(challenge.clauses, { ...page, path }), path).toBe(false);
    }
    // A10: extensions the cell nginx sends to PHP are challenged like pages.
    for (const path of ["/favicon.ico", "/img/hero.avif", "/fonts/a.ttf", "/app.js.map"]) {
      expect(anyClauseMatches(challenge.clauses, { ...page, path }), path).toBe(true);
    }
    // A10: the Host header's case does not matter to a site clause.
    expect(anyClauseMatches(challenge.clauses, { ...page, host: "WWW.A.Example.COM" })).toBe(true);
    expect(anyClauseMatches(block.clauses, { ...banned, host: "A.EXAMPLE.com", path: "/" })).toBe(true);
    // An ip ban on the SAME site still covers its static files: a banned IP stays banned.
    expect(anyClauseMatches(block.clauses, { ...banned, host: "a.example.com", path: "/wp-content/uploads/logo.png" })).toBe(true);
    expect(anyClauseMatches(block.clauses, { ...banned, host: "a.example.com", path: "/" })).toBe(true);
    expect(anyClauseMatches(block.clauses, { ...visitor, host: "a.example.com", path: "/" })).toBe(false);
    for (const clause of block.clauses) expect(clause).not.toContain("http.request.uri.path.extension");

    // Global under_attack: the same exemption, every host but the zone's infrastructure.
    expect(anyClauseMatches(globalChallenge.clauses, { ...visitor, host: "shop.example.org", path: "/cart" })).toBe(true);
    expect(anyClauseMatches(globalChallenge.clauses, { ...visitor, host: "shop.example.org", path: "/img/hero.webp" })).toBe(false);
    expect(anyClauseMatches(globalChallenge.clauses, { ...visitor, host: "host.example.com", path: "/" })).toBe(false);
  });

  it("joins a chunk's clauses sorted with ' or ', and builds the chunk and xmlrpc rule bodies", () => {
    const clauses = ['http.host in {"b.example.com"}', '(ip.src in {192.0.2.1} and http.host in {"a.example.com"})'];
    expect(joinChunkClauses(clauses)).toBe(
      '(ip.src in {192.0.2.1} and http.host in {"a.example.com"}) or http.host in {"b.example.com"}',
    );
    expect(buildEdgeChunkRule("block", 3, clauses)).toEqual({
      description: "doubleyoup-edge-block:3",
      expression: '(ip.src in {192.0.2.1} and http.host in {"a.example.com"}) or http.host in {"b.example.com"}',
      action: "block",
      enabled: true,
    });
    expect(buildEdgeChunkRule("challenge", 1, clauses).action).toBe("managed_challenge");
    expect(buildEdgeChunkRule("challenge", 1, clauses).description).toBe("doubleyoup-edge-challenge:1");

    expect(wafXmlrpcExpression()).toBe('http.request.uri.path eq "/xmlrpc.php"');
    expect(buildXmlrpcRule(true)).toEqual({
      description: "doubleyoup-xmlrpc",
      expression: 'http.request.uri.path eq "/xmlrpc.php"',
      action: "block",
      enabled: true,
    });
    expect(buildXmlrpcRule(false).enabled).toBe(false);
    expect(EDGE_CHUNK_MAX_LENGTH).toBeLessThan(WAF_EXPRESSION_MAX_LENGTH);
  });

  it("splits a chunk expression back into its exact clauses, even with ' or ' inside a quoted User-Agent", () => {
    const clauses = [
      '(http.user_agent contains "this or that) {x}" and http.host in {"a.example.com"})',
      '(ip.src in {192.0.2.1} and not http.host in {"cell-x.example.com"})',
      'http.host in {"a.example.com" "b.example.com"}',
    ];
    expect(splitChunkExpression(joinChunkClauses(clauses))).toEqual(clauses);
    expect(splitChunkExpression("")).toEqual([]);
    // A hand-edited chunk comes back as its top-level disjuncts.
    expect(splitChunkExpression('(a or b) or c and d or "x or y"')).toEqual(["(a or b)", "c and d", '"x or y"']);
  });

  it("classifies rules by EXACT description: baseline, chunk, legacy, foreign", () => {
    for (const description of WAF_SYNC_BASELINE_DESCRIPTIONS) {
      expect(classifyWafRuleDescription(description)).toEqual({ owner: "baseline" });
    }
    expect(WAF_SYNC_BASELINE_DESCRIPTIONS).toEqual([
      WAF_COUNTRY_BLOCK_DESCRIPTION,
      WAF_WPADMIN_GEO_DESCRIPTION,
      WAF_LOGIN_GATE_DESCRIPTION,
      WAF_FRONTEND_GEO_DESCRIPTION,
      WAF_EXEC_SKIP_DESCRIPTION,
      WAF_XMLRPC_DESCRIPTION,
    ]);
    expect(classifyWafRuleDescription("doubleyoup-edge-block:12")).toEqual({ owner: "chunk", kind: "block", chunkNumber: 12 });
    expect(classifyWafRuleDescription("doubleyoup-edge-challenge:1")).toEqual({ owner: "chunk", kind: "challenge", chunkNumber: 1 });
    expect(classifyWafRuleDescription("doubleyoup-ban:abc123")).toEqual({ owner: "legacy" });
    expect(classifyWafRuleDescription("doubleyoup-geo:site:allow-ips")).toEqual({ owner: "legacy" });
    for (const foreign of [
      undefined,
      "",
      "doubleyoup-edge-block:0",
      "doubleyoup-edge-block:01",
      "doubleyoup-edge-block:x",
      "doubleyoup-edge-block:",
      "doubleyoup-xmlrpc ",
      "tmp-block-xmlrpc",
      "doubleyoup-managed-ruleset",
    ]) {
      expect(classifyWafRuleDescription(foreign)).toEqual({ owner: "foreign" });
    }
  });
});

// ── the params validator (twin of app's) ──────────────────────────────────────────────

describe("waf-edge-sync: params validation", () => {
  const FULL = {
    block: [
      { key: "ban1", hosts: ["a.example.com", "shop.example.org"], ips: ["192.0.2.7"], uas: [] },
      { key: "ban2", hosts: [], ips: [], uas: ["BadBot/1.0 (+https://bad.example)"] },
    ],
    challenge: [
      { key: "ban3", hosts: ["a.example.com"], all: true, ips: [], uas: [] },
      { key: "ban4", hosts: [], ips: ["2001:db8::/32"], uas: [] },
    ],
  };

  it("accepts a full job and returns a FRESH object with only the known keys (reservedSlots defaults to 3)", () => {
    const raw = rawParams(FULL);
    delete raw.reservedSlots;
    const verdict = validateWafEdgeSyncParams(raw);
    expect(verdict).toEqual({
      ok: true,
      params: {
        zone: ZONE,
        baseline: {
          enabled: true,
          excludedHosts: EXCLUDED_HOSTS,
          agentHosts: AGENT_HOSTS,
          includeManagedRuleset: false,
          xmlrpc: "block",
        },
        block: FULL.block,
        challenge: FULL.challenge,
        reservedSlots: 3,
        retireLegacy: false,
        rateLimit: { enabled: false },
      },
    });
    if (!verdict.ok) throw new Error("unreachable");
    expect(verdict.params.block[0]?.hosts).not.toBe(FULL.block[0]?.hosts);
    expect(validParams({ reservedSlots: 0 }).reservedSlots).toBe(0);
    expect(validParams({ reservedSlots: 10 }).reservedSlots).toBe(10);
  });

  it("refuses an unknown key at EVERY level — a rule text or a country list never rides along", () => {
    const refusals: Array<Record<string, unknown>> = [
      rawParams({ expression: "true" }),
      rawParams({ baseline: { ...(rawParams().baseline as object), countries: ["AU"] } }),
      rawParams({ block: [{ key: "a1", hosts: [], ips: ["192.0.2.1"], uas: [], action: "skip" }] }),
      rawParams({ challenge: [{ key: "a1", hosts: [], ips: ["192.0.2.1"], uas: [], expression: "true" }] }),
      // `all` exists only in the challenge list.
      rawParams({ block: [{ key: "a1", hosts: ["a.example.com"], all: true, ips: [], uas: [] }] }),
    ];
    for (const raw of refusals) {
      const verdict = validateWafEdgeSyncParams(raw);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(/unknown key/);
    }
  });

  it("refuses bad input field by field (fails closed)", () => {
    const baseline = rawParams().baseline as Record<string, unknown>;
    const entry = (overrides: Record<string, unknown>) => ({ key: "a1", hosts: ["a.example.com"], ips: ["192.0.2.1"], uas: [], ...overrides });
    const bad: Array<Record<string, unknown>> = [
      rawParams({ zone: "Example.com" }),
      rawParams({ zone: "localhost" }),
      rawParams({ baseline: "on" }),
      rawParams({ baseline: { ...baseline, enabled: undefined } }),
      rawParams({ baseline: { ...baseline, enabled: "true" } }),
      rawParams({ baseline: { ...baseline, excludedHosts: [] } }),
      rawParams({ baseline: { ...baseline, excludedHosts: ["host.example.org"] } }),
      rawParams({ baseline: { ...baseline, agentHosts: ["other.example.com"] } }),
      rawParams({ baseline: { ...baseline, agentHosts: [] } }),
      rawParams({ baseline: { ...baseline, includeManagedRuleset: undefined } }),
      rawParams({ baseline: { ...baseline, xmlrpc: "allow" } }),
      rawParams({ baseline: { ...baseline, xmlrpc: undefined } }),
      rawParams({ block: undefined }),
      rawParams({ block: {} }),
      rawParams({ challenge: "none" }),
      rawParams({ block: ["a1"] }),
      rawParams({ block: [entry({ key: "A1" })] }),
      rawParams({ block: [entry({ key: "a".repeat(33) })] }),
      rawParams({ block: [entry({ key: "a-1" })] }),
      rawParams({ block: [entry({ key: "" })] }),
      rawParams({ block: [entry({}), entry({ ips: ["192.0.2.2"] })] }),
      rawParams({ block: [entry({ hosts: ["A.example.com"] })] }),
      rawParams({ block: [entry({ hosts: ["*.example.com"] })] }),
      rawParams({ block: [entry({ hosts: ["192.0.2.1"] })] }),
      rawParams({ block: [entry({ hosts: ["a.example.com."] })] }),
      rawParams({ block: [entry({ hosts: ["host.example.com"] })] }),
      rawParams({ block: [entry({ hosts: ["cell-x.example.com"] })] }),
      rawParams({ block: [entry({ hosts: "a.example.com" })] }),
      rawParams({ block: [entry({ hosts: undefined })] }),
      rawParams({ block: [entry({ ips: undefined })] }),
      rawParams({ block: [entry({ uas: undefined })] }),
      rawParams({ block: [entry({ ips: [], uas: [] })] }),
      rawParams({ challenge: [entry({ ips: [], uas: [], all: false })] }),
      rawParams({ challenge: [entry({ all: "true" })] }),
      rawParams({ block: [entry({ hosts: longHosts("h", 501, 20) })] }),
      rawParams({ block: [entry({ ips: Array.from({ length: 101 }, (_, index) => `10.0.${Math.floor(index / 250)}.${index % 250}`) })] }),
      rawParams({ block: [entry({ ips: [], uas: Array.from({ length: 11 }, (_, index) => `ExampleBot/${index}.0`) })] }),
      rawParams({ reservedSlots: 11 }),
      rawParams({ reservedSlots: -1 }),
      rawParams({ reservedSlots: 1.5 }),
      rawParams({ reservedSlots: "3" }),
      rawParams({ retireLegacy: undefined }),
      rawParams({ retireLegacy: "false" }),
    ];
    expect(validateWafEdgeSyncParams(null).ok).toBe(false);
    expect(validateWafEdgeSyncParams([]).ok).toBe(false);
    for (const raw of bad) {
      const verdict = validateWafEdgeSyncParams(raw);
      if (verdict.ok) throw new Error(`accepted: ${JSON.stringify(raw)}`);
    }
    // Custom domains may lie outside the zone; the zone apex is a host like any other.
    expect(validateWafEdgeSyncParams(rawParams({ block: [entry({ hosts: ["shop.example.org", "example.com"] })] })).ok).toBe(true);
  });

  it("refuses DUPLICATE list values (app sends de-duplicated params, Amendment A1)", () => {
    const entry = (overrides: Record<string, unknown>) => ({ key: "a1", hosts: ["a.example.com"], ips: ["192.0.2.1"], uas: [], ...overrides });
    for (const duplicate of [
      { hosts: ["a.example.com", "a.example.com"] },
      { ips: ["192.0.2.1", "192.0.2.1"] },
      { uas: ["ExampleBot/1.0", "ExampleBot/1.0"] },
    ]) {
      const verdict = validateWafEdgeSyncParams(rawParams({ block: [entry(duplicate)] }));
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(/twice/);
    }
  });

  it("accepts only CANONICAL IP values (Amendment A3)", () => {
    const canonical = [
      "192.0.2.1",
      "0.0.0.0",
      "255.255.255.255",
      "10.0.0.0/8",
      "192.0.2.0/24",
      "192.0.2.4/31",
      "2001:db8::1",
      "2001:db8::/32",
      "2001:db8:1::/48",
      "2001:d00::/24",
      "1:0:0:1::1",
      "2001:db8:0:1:1:1:1:1",
      "1::1:0:0:1",
      "2001:db8:aaaa:bbbb:cccc:dddd:eeee:fffe/127",
      // A10 boundaries: next to ::/96 and ::ffff:0:0/96, but outside both.
      "64:ff9b::/96",
      "::fffe:0:0/96",
      "::1:0:0:0/80",
      "fe80::/24",
    ];
    for (const value of canonical) {
      expect(canonicalEdgeIpReason(value), value).toBeNull();
    }
    const refused = [
      "192.0.2.1/32", // a host is written bare
      "192.000.2.1", // leading zeros
      "01.2.3.4",
      "256.0.0.1",
      "192.0.2",
      "192.0.2.1.5",
      "192.0.2.0/24 ", // padding
      "192.0.2.1/24", // host bits set
      "10.0.0.0/7", // wider than /8
      "0.0.0.0/0",
      "10.0.0.0/08", // a prefix with a leading zero
      "10.0.0.0/",
      "::/0",
      "2001:db8::/23", // wider than /24
      "2001:db8::1/128", // a host is written bare
      "2001:db8::1/64", // host bits set
      "2001:DB8::1", // upper case
      "2001:0db8::1", // a leading zero
      "2001:db8:0:0:0:0:0:1", // the zero run is not compressed
      "2001:db8::0:1", // not the longest compression
      "1::1:0:0:0:1", // compresses the shorter run
      "2001:db8:0:1:1:1:1:1".replace("0:1:1:1:1:1", ":1:1:1:1:1"), // "::" for ONE zero group
      "::ffff:192.0.2.1", // embedded dotted IPv4
      // A10 (review probe): nothing that overlaps ::/96 or ::ffff:0:0/96, the ranges that carry IPv4.
      "::", // unspecified
      "::1", // loopback, inside ::/96
      "::/96",
      "::ffff:0:0/96",
      "::ffff:102:304", // ::ffff:1.2.3.4, IPv4-mapped
      "::ffff:c000:200/120", // a network inside the mapped range
      "::102:304", // IPv4-compatible
      "::/24", // contains both ranges
      "::/95",
      "2001:db8:::1",
      "1:2:3:4:5:6:7:8:9",
      "gggg::1",
      "",
      42,
    ];
    for (const value of refused) {
      expect(canonicalEdgeIpReason(value), String(value)).not.toBeNull();
    }
    expect(rfc5952Ipv6Text([0x2001, 0xdb8, 0, 0, 1, 0, 0, 1])).toBe("2001:db8::1:0:0:1");
    expect(rfc5952Ipv6Text([1, 0, 1, 1, 1, 1, 1, 1])).toBe("1:0:1:1:1:1:1:1");
  });

  it("accepts a User-Agent only as printable ASCII, 8-256 characters, without \" or \\", () => {
    expect(edgeUserAgentReason("ExampleBot/1.0")).toBeNull();
    expect(edgeUserAgentReason("a".repeat(8))).toBeNull();
    expect(edgeUserAgentReason("a".repeat(256))).toBeNull();
    for (const value of ["a".repeat(7), "a".repeat(257), 'Bad"Bot/1.0', "Bad\\Bot/1.0", "BadBot/1.0\n", "BadBöt/1.0x", 7]) {
      expect(edgeUserAgentReason(value), String(value)).not.toBeNull();
    }
  });
});

// ── splitting ─────────────────────────────────────────────────────────────────────────

describe("waf-edge-sync: deterministic splitting of an oversized entry", () => {
  it("cuts the SORTED hosts into groups of the largest size that fits, whatever order they arrive in", () => {
    const hosts = longHosts("split", 60, 100);
    const entry: EdgeClauseEntry = { hosts, ips: ["192.0.2.9"], uas: [], all: false };
    const whole = `(ip.src in {192.0.2.9} and lower(http.host) in {${[...hosts].sort().map((host) => `"${host}"`).join(" ")}})`;
    expect(whole.length).toBeGreaterThan(EDGE_CHUNK_MAX_LENGTH);

    const first = buildEdgeClauses([entry], EXCLUDED_HOSTS);
    const shuffled = buildEdgeClauses([{ ...entry, hosts: [...hosts].reverse() }], EXCLUDED_HOSTS);
    if (!first.ok || !shuffled.ok) throw new Error("split refused");
    expect(shuffled.clauses).toEqual(first.clauses);
    expect(first.clauses.length).toBeGreaterThan(1);

    // Every clause fits; together they cover every host exactly once, in sorted groups of one size G.
    const sortedHosts = [...hosts].sort();
    const groups = first.clauses.map((clause) => {
      expect(clause.length).toBeLessThanOrEqual(EDGE_CHUNK_MAX_LENGTH);
      return [...clause.matchAll(/"([^"]+)"/g)].map((match) => match[1] as string);
    });
    groups.sort((left, right) => sortedHosts.indexOf(left[0] as string) - sortedHosts.indexOf(right[0] as string));
    expect(groups.flat()).toEqual(sortedHosts);
    const groupSize = (groups[0] as string[]).length;
    for (const group of groups.slice(0, -1)) expect(group.length).toBe(groupSize);
    // G is the LARGEST size that fits: groups of G + 1 would overflow somewhere.
    let largerOverflows = false;
    for (let start = 0; start < sortedHosts.length; start += groupSize + 1) {
      const group = sortedHosts.slice(start, start + groupSize + 1);
      const clause = `(ip.src in {192.0.2.9} and lower(http.host) in {${group.map((host) => `"${host}"`).join(" ")}})`;
      if (clause.length > EDGE_CHUNK_MAX_LENGTH) largerOverflows = true;
    }
    expect(largerOverflows).toBe(true);
  });

  it("counts the A9 exemption when it splits: hosts that fit bare but not with the exemption are split", () => {
    const hosts: string[] = [];
    const bareHostTest = () => `lower(http.host) in {${[...hosts].sort().map((host) => `"${host}"`).join(" ")}}`;
    for (let index = 0; bareHostTest().length < 3900; index += 1) {
      hosts.push(`u${index}.${"x".repeat(50)}.example.net`);
    }
    expect(bareHostTest().length).toBeLessThanOrEqual(EDGE_CHUNK_MAX_LENGTH);
    expect(`(${bareHostTest()} and ${STATIC_EXEMPTION})`.length).toBeGreaterThan(EDGE_CHUNK_MAX_LENGTH);

    const built = buildEdgeClauses([{ hosts, ips: [], uas: [], all: true }], EXCLUDED_HOSTS);
    if (!built.ok) throw new Error(built.reason);
    expect(built.clauses).toHaveLength(2);
    const covered: string[] = [];
    for (const clause of built.clauses) {
      expect(clause.length).toBeLessThanOrEqual(EDGE_CHUNK_MAX_LENGTH);
      expect(clause.endsWith(` and ${STATIC_EXEMPTION})`)).toBe(true);
      covered.push(...quotedValues(clause.slice(0, clause.indexOf(" and not http.request"))));
    }
    expect(covered.sort()).toEqual([...hosts].sort());
  });

  it("refuses (invalid) a global clause or an IP list that cannot fit even with one host — before any custom write", async () => {
    const manyIpv6 = Array.from({ length: 100 }, (_, index) => `2001:db8:a${index}:bbbb:cccc:dddd:eeee:fffe/127`);
    const ipHeavy = buildEdgeClauses([{ hosts: ["a.example.com"], ips: manyIpv6, uas: [], all: false }], EXCLUDED_HOSTS);
    expect(ipHeavy.ok).toBe(false);

    const manyIpv4 = Array.from({ length: 100 }, (_, index) => `198.51.100.${index}`);
    const longExcluded = longHosts("infra", 14, 200).map((host) => host.replace("example.net", "example.com"));
    const globalClause = buildEdgeClauses([{ hosts: [], ips: manyIpv4, uas: [], all: false }], longExcluded);
    expect(globalClause.ok).toBe(false);

    const fake = new FakeCloudflare(baselineRulesInOrder()).install();
    const result = await actuateWafEdgeSync(
      validParams({ block: [{ key: "heavy", hosts: ["a.example.com"], ips: manyIpv6, uas: [] }] }),
      envWithToken(),
    );
    expect(result).toMatchObject({ ok: false, op: "waf-edge-sync", zone: ZONE, code: "invalid" });
    // The custom phase is not even read; the rate-limit part (off in this job) ran and wrote nothing.
    expect(fake.writes).toEqual([]);
    expect(fake.requests.some((request) => request.includes("http_request_firewall_custom"))).toBe(false);
    expect(result).toMatchObject({ rateLimit: { ok: true, created: [], patched: [], deleted: [] } });
  });
});

// ── the packer (pure) ─────────────────────────────────────────────────────────────────

describe("waf-edge-sync: sticky first-fit packing (pure)", () => {
  it("keeps still-wanted clauses in place, fills the first chunk with room, and numbers new chunks from the smallest unused", () => {
    const plans = planStickyChunks(
      [
        { chunkNumber: 2, clauses: ["keep-b", "drop-c"] },
        // Too long to take new-f next to it, even though it is about to leave: the room check counts it.
        { chunkNumber: 3, clauses: ["drop-d-long-clause-text-xx"] },
      ],
      ["keep-b", "new-e", "new-f"],
      30,
    );
    expect(plans.map((plan) => [plan.chunkNumber, plan.isNew, plan.keptClauses, plan.gainedClauses, plan.lostClauses, plan.finalClauses])).toEqual([
      // A new chunk takes number 1 (unused), and the lowest-numbered chunk with room gets the next clause.
      [1, true, [], ["new-f"], [], ["new-f"]],
      // keep-b + drop-c + new-e = 6 + 6 + 5 + 8 = 25 characters: fits the 30-character budget.
      [2, false, ["keep-b"], ["new-e"], ["drop-c"], ["keep-b", "new-e"]],
      [3, false, [], [], ["drop-d-long-clause-text-xx"], []],
    ]);
    // The gain write still holds the clause the chunk will lose.
    expect(plans[1]?.gainClauses).toEqual(["drop-c", "keep-b", "new-e"]);
    expect(plans[0]?.gainClauses).toBeNull();
  });

  it("keeps a clause found in TWO chunks only in the lowest-numbered one", () => {
    const plans = planStickyChunks(
      [
        { chunkNumber: 1, clauses: ["dup"] },
        { chunkNumber: 2, clauses: ["dup", "other"] },
      ],
      ["dup", "other"],
    );
    expect(plans[0]?.finalClauses).toEqual(["dup"]);
    expect(plans[1]?.finalClauses).toEqual(["other"]);
    expect(plans[1]?.lostClauses).toEqual(["dup"]);
  });
});

// ── actuation ─────────────────────────────────────────────────────────────────────────

describe("waf-edge-sync: actuation", () => {
  it("a fresh zone: ONE create of the entrypoint holding every rule in the documented order", async () => {
    const fake = new FakeCloudflare(null).install();
    const params = validParams({
      block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }],
      challenge: [{ key: "ban2", hosts: ["a.example.com"], all: true, ips: [], uas: [] }],
    });
    const result = await actuateWafEdgeSync(params, envWithToken());
    const expectedOrder = [
      "doubleyoup-edge-block:1",
      WAF_COUNTRY_BLOCK_DESCRIPTION,
      WAF_WPADMIN_GEO_DESCRIPTION,
      WAF_XMLRPC_DESCRIPTION,
      "doubleyoup-edge-challenge:1",
      WAF_LOGIN_GATE_DESCRIPTION,
      WAF_FRONTEND_GEO_DESCRIPTION,
      WAF_EXEC_SKIP_DESCRIPTION,
    ];
    expect(result).toEqual({
      ok: true,
      op: "waf-edge-sync",
      zone: ZONE,
      plan: "pro",
      cap: 20,
      reservedSlots: 3,
      rulesUsed: 8,
      foreign: [],
      preempting: [],
      created: expectedOrder,
      patched: [],
      deleted: [],
      legacyDeleted: [],
      chunks: { block: 1, challenge: 1 },
      managedRuleset: "not-requested",
      rateLimit: { ok: true, created: [], patched: [], deleted: [], omittedClauses: [] },
    } satisfies WafEdgeSyncResult);
    expect(writeLog(fake)).toEqual(["POST entrypoint"]);
    expect(fake.customDescriptions()).toEqual(expectedOrder);
    const bodies = baselineBodies();
    expect(fake.customRules?.[1]).toMatchObject(bodies.country);
    expect(fake.customRules?.[0]).toMatchObject({
      expression: '(ip.src in {192.0.2.7} and lower(http.host) in {"a.example.com"})',
      action: "block",
      enabled: true,
    });
    expect(fake.customRules?.[4]).toMatchObject({
      expression: `(lower(http.host) in {"a.example.com"} and ${STATIC_EXEMPTION})`,
      action: "managed_challenge",
    });

    // Idempotent: the same state again writes nothing.
    fake.writes = [];
    const again = await actuateWafEdgeSync(params, envWithToken());
    expect(again.ok).toBe(true);
    expect(fake.writes).toEqual([]);
  });

  it("refuses a run that ADDS protection on a Free or unknown plan with planTooSmall, writing NOTHING", async () => {
    for (const plan of ["free", null, "some-new-plan"]) {
      const fake = new FakeCloudflare(baselineRulesInOrder());
      fake.plan = plan;
      fake.install();
      const result = await actuateWafEdgeSync(
        validParams({ block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }] }),
        envWithToken(),
      );
      expect(result).toMatchObject({ ok: false, op: "waf-edge-sync", zone: ZONE, code: "planTooSmall" });
      expect(fake.writes).toEqual([]);
      vi.restoreAllMocks();
    }
  });

  it("refuses capExceeded, writing NOTHING, when the end state would not fit cap − reservedSlots", async () => {
    // Pro: 20 rules, 3 reserved => 17 usable. 11 foreign + 6 baseline + 1 chunk = 18.
    const foreign: FakeRule[] = Array.from({ length: 11 }, (_, index) => ({
      id: `f-${index}`,
      description: `agency-rule-${index}`,
      expression: `http.host eq "f${index}.example.com"`,
      action: "block",
      enabled: true,
    }));
    const block = [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }];
    const fake = new FakeCloudflare([...foreign, ...baselineRulesInOrder()]).install();
    const refused = await actuateWafEdgeSync(validParams({ block }), envWithToken());
    expect(refused).toMatchObject({ ok: false, code: "capExceeded" });
    expect(fake.writes).toEqual([]);

    // With two reserved slots the same state fits (18 <= 18).
    const fits = await actuateWafEdgeSync(validParams({ block, reservedSlots: 2 }), envWithToken());
    expect(fits.ok).toBe(true);
    expect(writeLog(fake)).toEqual(["POST doubleyoup-edge-block:1"]);
  });

  it("refuses capExceeded, writing NOTHING, when the PEAK (creates before deletes) would not fit the cap", async () => {
    // 10 legacy + 4 foreign today; the run creates 6 baseline + 1 chunk before it may delete anything.
    const legacy: FakeRule[] = Array.from({ length: 10 }, (_, index) => ({
      id: `l-${index}`,
      description: `doubleyoup-ban:ban${index}`,
      expression: `ip.src in {198.51.100.${index}}`,
      action: "block",
      enabled: true,
    }));
    const foreign: FakeRule[] = Array.from({ length: 4 }, (_, index) => ({
      id: `f-${index}`,
      description: `agency-rule-${index}`,
      expression: "true",
      action: "log",
      enabled: true,
    }));
    const fake = new FakeCloudflare([...foreign, ...legacy]).install();
    const block = [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }];
    // retireLegacy: the END state fits (4 + 7 = 11 <= 17), but the peak is 14 + 7 = 21 > 20.
    const peak = await actuateWafEdgeSync(validParams({ block, retireLegacy: true }), envWithToken());
    expect(peak).toMatchObject({ ok: false, code: "capExceeded" });
    if (!peak.ok && peak.code === "capExceeded") expect(peak.detail).toMatch(/peak/);
    // Without retireLegacy the end state itself does not fit (4 + 7 + 10 = 21 > 17).
    const steady = await actuateWafEdgeSync(validParams({ block, retireLegacy: false }), envWithToken());
    expect(steady).toMatchObject({ ok: false, code: "capExceeded" });
    expect(fake.writes).toEqual([]);
  });

  it("never writes, moves or deletes a FOREIGN rule; reports each one and the skips that can pre-empt ours", async () => {
    const bodies = baselineBodies();
    const initial: FakeRule[] = [
      { id: "f-skip-top", description: "agency-allow-office", expression: "ip.src in {203.0.113.0/24}", action: "skip", action_parameters: { ruleset: "current" }, enabled: true },
      { id: "f-skip-off", description: "agency-old-skip", expression: "true", action: "skip", action_parameters: { ruleset: "current" }, enabled: false },
      { id: "l-geo-skip", description: "doubleyoup-geo:site1:allow-ips", expression: "ip.src in {203.0.113.9}", action: "skip", action_parameters: { ruleset: "current" }, enabled: true },
      { id: "b-country", ...bodies.country },
      { id: "f-block-mid", description: "agency-block-path", expression: 'http.request.uri.path eq "/secret"', action: "block", enabled: true },
      { id: "b-wpadmin", ...bodies.wpadmin },
      { id: "b-login", ...bodies.login },
      { id: "b-frontend", ...bodies.frontend },
      { id: "b-skip", ...bodies.skip },
      { id: "f-skip-bottom", description: "", expression: "true", action: "skip", action_parameters: { ruleset: "current" }, enabled: true },
    ] as FakeRule[];
    const fake = new FakeCloudflare(initial).install();
    const result = await actuateWafEdgeSync(
      validParams({
        block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }],
        challenge: [{ key: "ban2", hosts: [], ips: ["198.51.100.0/24"], uas: [] }],
      }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(result.detail);

    // Every foreign rule is byte-identical, and they keep their order relative to each other.
    const foreignIds = ["f-skip-top", "f-skip-off", "f-block-mid", "f-skip-bottom"];
    const after = fake.customRules ?? [];
    for (const id of foreignIds) {
      expect(after.find((rule) => rule.id === id)).toEqual(initial.find((rule) => rule.id === id));
    }
    expect(after.filter((rule) => foreignIds.includes(rule.id)).map((rule) => rule.id)).toEqual(foreignIds);
    // No write named a foreign (or legacy) rule — not even as a position anchor.
    for (const write of fake.writes) {
      expect(foreignIds).not.toContain(write.ruleId);
      const position = JSON.stringify(write.body?.position ?? {});
      for (const id of [...foreignIds, "l-geo-skip"]) expect(position).not.toContain(id);
    }
    // The legacy rule is untouched too (retireLegacy is false), and is not reported as foreign.
    expect(after.find((rule) => rule.id === "l-geo-skip")).toEqual(initial[2]);

    const positionOf = (id: string) => after.findIndex((rule) => rule.id === id) + 1;
    expect(result.foreign).toEqual([
      { description: "agency-allow-office", action: "skip", position: positionOf("f-skip-top") },
      { description: "agency-old-skip", action: "skip", position: positionOf("f-skip-off") },
      { description: "agency-block-path", action: "block", position: positionOf("f-block-mid") },
      { description: "", action: "skip", position: positionOf("f-skip-bottom") },
    ]);
    // Enabled skips ABOVE one of ours: the foreign one and the legacy geo allow-ips rule. Not the
    // disabled skip, and not the skip below all of ours.
    expect(result.preempting).toEqual([
      { description: "agency-allow-office", action: "skip", position: positionOf("f-skip-top") },
      { description: "doubleyoup-geo:site1:allow-ips", action: "skip", position: positionOf("l-geo-skip") },
    ]);
    expect(result.rulesUsed).toBe(after.length);

    // retireLegacy removes the legacy geo skip and nothing foreign: every foreign rule is still byte-identical.
    fake.writes = [];
    const retired = await actuateWafEdgeSync(
      validParams({
        block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }],
        challenge: [{ key: "ban2", hosts: [], ips: ["198.51.100.0/24"], uas: [] }],
        retireLegacy: true,
      }),
      envWithToken(),
    );
    if (!retired.ok) throw new Error(retired.detail);
    expect(writeLog(fake)).toEqual(["DELETE doubleyoup-geo:site1:allow-ips"]);
    const afterRetire = fake.customRules ?? [];
    for (const id of foreignIds) {
      expect(afterRetire.find((rule) => rule.id === id)).toEqual(initial.find((rule) => rule.id === id));
    }
    expect(retired.foreign.map((rule) => rule.description)).toEqual(["agency-allow-office", "agency-old-skip", "agency-block-path", ""]);
    expect(retired.preempting.map((rule) => rule.description)).toEqual(["agency-allow-office"]);
    expect(retired.legacyDeleted).toEqual(["doubleyoup-geo:site1:allow-ips"]);
  });

  it("patches a baseline that waf-rule-upsert wrote IN PLACE: no delete, no create of the five", async () => {
    const fake = new FakeCloudflare(null).install();
    const upsert = await actuateWafRuleUpsert(
      { zone: ZONE, enabled: true, excludedHosts: EXCLUDED_HOSTS, agentHosts: AGENT_HOSTS, includeManagedRuleset: false },
      envWithToken(),
    );
    expect(upsert.ok).toBe(true);
    const fiveIds = new Map((fake.customRules ?? []).map((rule) => [rule.description, rule.id]));
    expect(fiveIds.size).toBe(5);
    fake.writes = [];

    const result = await actuateWafEdgeSync(
      validParams({ block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }] }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(result.detail);
    // Only the two NEW rules are created; the five keep their ids and are not even patched (no drift).
    expect(writeLog(fake)).toEqual(["POST doubleyoup-edge-block:1", "POST doubleyoup-xmlrpc"]);
    expect(result.created).toEqual(["doubleyoup-edge-block:1", "doubleyoup-xmlrpc"]);
    expect(result.patched).toEqual([]);
    for (const [description, id] of fiveIds) {
      expect((fake.customRules ?? []).find((rule) => rule.description === description)?.id).toBe(id);
    }

    // A rollback (enabled:false) switches the four protections and xmlrpc off IN PLACE; the agent skip stays on.
    fake.writes = [];
    const rollback = await actuateWafEdgeSync(
      validParams({
        baseline: { ...(rawParams().baseline as object), enabled: false },
        block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }],
      }),
      envWithToken(),
    );
    if (!rollback.ok) throw new Error(rollback.detail);
    expect(fake.writes.every((write) => write.method === "PATCH")).toBe(true);
    expect(rollback.patched).toEqual([
      WAF_COUNTRY_BLOCK_DESCRIPTION,
      WAF_WPADMIN_GEO_DESCRIPTION,
      WAF_XMLRPC_DESCRIPTION,
      WAF_LOGIN_GATE_DESCRIPTION,
      WAF_FRONTEND_GEO_DESCRIPTION,
    ]);
    const state = new Map((fake.customRules ?? []).map((rule) => [rule.description, rule]));
    for (const description of [WAF_COUNTRY_BLOCK_DESCRIPTION, WAF_WPADMIN_GEO_DESCRIPTION, WAF_LOGIN_GATE_DESCRIPTION, WAF_FRONTEND_GEO_DESCRIPTION]) {
      expect(state.get(description)?.enabled).toBe(false);
      expect(state.get(description)?.id).toBe(fiveIds.get(description));
    }
    expect(state.get(WAF_XMLRPC_DESCRIPTION)?.enabled).toBe(false);
    expect(state.get(WAF_EXEC_SKIP_DESCRIPTION)?.enabled).toBe(true);
    // The ban chunk is not a baseline rule: it stays on.
    expect(state.get("doubleyoup-edge-block:1")?.enabled).toBe(true);
    expect(rollback.rulesUsed).toBe(7);
  });

  it('xmlrpc "off" keeps the rule, DISABLED, in its place (stable positions and cap maths)', async () => {
    const fake = new FakeCloudflare(baselineRulesInOrder()).install();
    const result = await actuateWafEdgeSync(
      validParams({ baseline: { ...(rawParams().baseline as object), xmlrpc: "off" } }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(result.detail);
    expect(writeLog(fake)).toEqual(["PATCH doubleyoup-xmlrpc"]);
    expect(fake.customRules?.find((rule) => rule.id === "b-xmlrpc")).toMatchObject({ enabled: false, expression: wafXmlrpcExpression() });
    expect(fake.customDescriptions()).toEqual(baselineRulesInOrder().map((rule) => rule.description));
  });

  it("writes in the order create -> gain patch -> lose patch -> delete empty, so no wanted clause is ever absent", async () => {
    // Long hosts make each clause 1,000-3,500 characters, so room in a 4,000-character chunk is easy to steer.
    const clauseA = siteIpClause("192.0.2.1", longHosts("a", 9)); // kept in chunk 1
    const clauseB = siteIpClause("192.0.2.2", longHosts("b", 5)); // kept in chunk 2
    const clauseC = siteIpClause("192.0.2.3", longHosts("c", 5)); // leaves chunk 2
    const clauseD = siteIpClause("192.0.2.4", longHosts("d", 14)); // leaves chunk 3, which empties
    const clauseE = siteIpClause("192.0.2.5", longHosts("e", 7)); // new: fits chunk 1
    const clauseF = siteIpClause("192.0.2.6", longHosts("f", 17)); // new: fits nowhere => new chunk 4
    expect(clauseA.length + 4 + clauseE.length).toBeLessThanOrEqual(EDGE_CHUNK_MAX_LENGTH);
    expect(clauseA.length + 4 + clauseE.length + 4 + clauseF.length).toBeGreaterThan(EDGE_CHUNK_MAX_LENGTH);
    expect(clauseA.length + 4 + clauseF.length).toBeGreaterThan(EDGE_CHUNK_MAX_LENGTH);
    expect(clauseB.length + clauseC.length + 8 + clauseF.length).toBeGreaterThan(EDGE_CHUNK_MAX_LENGTH);
    expect(clauseD.length + 4 + clauseF.length).toBeGreaterThan(EDGE_CHUNK_MAX_LENGTH);

    const baseline = baselineRulesInOrder();
    const initial: FakeRule[] = [
      { id: "c1", ...buildEdgeChunkRule("block", 1, [clauseA]) },
      { id: "c2", ...buildEdgeChunkRule("block", 2, [clauseB, clauseC]) },
      { id: "c3", ...buildEdgeChunkRule("block", 3, [clauseD]) },
      ...baseline,
    ] as FakeRule[];
    const fake = new FakeCloudflare(initial).install();
    const result = await actuateWafEdgeSync(
      validParams({
        block: [
          { key: "a", hosts: longHosts("a", 9), ips: ["192.0.2.1"], uas: [] },
          { key: "b", hosts: longHosts("b", 5), ips: ["192.0.2.2"], uas: [] },
          { key: "e", hosts: longHosts("e", 7), ips: ["192.0.2.5"], uas: [] },
          { key: "f", hosts: longHosts("f", 17), ips: ["192.0.2.6"], uas: [] },
        ],
      }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(result.detail);
    expect(writeLog(fake)).toEqual([
      "POST doubleyoup-edge-block:4",
      "PATCH doubleyoup-edge-block:1",
      "PATCH doubleyoup-edge-block:2",
      "DELETE doubleyoup-edge-block:3",
    ]);
    // Between the writes: A and B never left their chunks; C and D stayed until every addition landed.
    const [afterCreate, afterGain, afterLose, afterDelete] = fake.snapshots.map(chunkClauses);
    expect(afterCreate?.get("doubleyoup-edge-block:4")).toEqual(new Set([clauseF]));
    expect(afterGain?.get("doubleyoup-edge-block:1")).toEqual(new Set([clauseA, clauseE]));
    expect(afterGain?.get("doubleyoup-edge-block:2")).toEqual(new Set([clauseB, clauseC]));
    expect(afterGain?.get("doubleyoup-edge-block:3")).toEqual(new Set([clauseD]));
    expect(afterLose?.get("doubleyoup-edge-block:2")).toEqual(new Set([clauseB]));
    expect(afterDelete?.has("doubleyoup-edge-block:3")).toBe(false);
    expect(result.created).toEqual(["doubleyoup-edge-block:4"]);
    expect(result.patched).toEqual(["doubleyoup-edge-block:1", "doubleyoup-edge-block:2"]);
    expect(result.deleted).toEqual(["doubleyoup-edge-block:3"]);
    expect(result.chunks).toEqual({ block: 3, challenge: 0 });
    // The new chunk sits with the other block chunks, above the baseline.
    expect(fake.customDescriptions().slice(0, 4)).toEqual([
      "doubleyoup-edge-block:1",
      "doubleyoup-edge-block:2",
      "doubleyoup-edge-block:4",
      WAF_COUNTRY_BLOCK_DESCRIPTION,
    ]);
  });

  it("a chunk that both gains and loses gets TWO writes: gain (still holding the old clause), then lose", async () => {
    const kept = siteIpClause("192.0.2.1", ["a.example.com"]);
    const leaving = siteIpClause("192.0.2.2", ["a.example.com"]);
    const arriving = siteIpClause("192.0.2.3", ["a.example.com"]);
    const fake = new FakeCloudflare([{ id: "c1", ...buildEdgeChunkRule("block", 1, [kept, leaving]) }, ...baselineRulesInOrder()] as FakeRule[]).install();
    const result = await actuateWafEdgeSync(
      validParams({
        block: [
          { key: "k", hosts: ["a.example.com"], ips: ["192.0.2.1"], uas: [] },
          { key: "n", hosts: ["a.example.com"], ips: ["192.0.2.3"], uas: [] },
        ],
      }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(result.detail);
    expect(writeLog(fake)).toEqual(["PATCH doubleyoup-edge-block:1", "PATCH doubleyoup-edge-block:1"]);
    expect(fake.writes[0]?.body?.expression).toBe(joinChunkClauses([kept, leaving, arriving]));
    expect(fake.writes[1]?.body?.expression).toBe(joinChunkClauses([kept, arriving]));
    expect(result.patched).toEqual(["doubleyoup-edge-block:1"]);
  });

  it("puts our rules in the documented order; foreign rules keep their order relative to each other", async () => {
    const bodies = baselineBodies();
    // The baseline in a scrambled order (login gate first, as an older zone had it), foreign rules between.
    const initial: FakeRule[] = [
      { id: "b-login", ...bodies.login },
      { id: "f-one", description: "agency-one", expression: "true", action: "log", enabled: true },
      { id: "b-skip", ...bodies.skip },
      { id: "b-country", ...bodies.country },
      { id: "f-two", description: "agency-two", expression: "true", action: "log", enabled: true },
      { id: "b-wpadmin", ...bodies.wpadmin },
      { id: "b-frontend", ...bodies.frontend },
      { id: "l-ban", description: "doubleyoup-ban:old1", expression: "ip.src in {198.51.100.1}", action: "block", enabled: true },
    ] as FakeRule[];
    const fake = new FakeCloudflare(initial).install();
    const result = await actuateWafEdgeSync(
      validParams({
        block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }],
        challenge: [{ key: "ban2", hosts: ["a.example.com"], ips: [], uas: ["ExampleBot/1.0"] }],
      }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(result.detail);
    const ours = fake.customDescriptions().filter((description) => {
      const owner = classifyWafRuleDescription(description).owner;
      return owner === "baseline" || owner === "chunk";
    });
    expect(ours).toEqual([
      "doubleyoup-edge-block:1",
      WAF_COUNTRY_BLOCK_DESCRIPTION,
      WAF_WPADMIN_GEO_DESCRIPTION,
      WAF_XMLRPC_DESCRIPTION,
      "doubleyoup-edge-challenge:1",
      WAF_LOGIN_GATE_DESCRIPTION,
      WAF_FRONTEND_GEO_DESCRIPTION,
      WAF_EXEC_SKIP_DESCRIPTION,
    ]);
    const after = fake.customRules ?? [];
    const indexOf = (id: string) => after.findIndex((rule) => rule.id === id);
    expect(indexOf("f-one")).toBeLessThan(indexOf("f-two"));
    expect(indexOf("f-two")).toBeLessThan(indexOf("l-ban"));
    // New rules were PLACED on create, relative to ours: the block chunk before the country block.
    const blockCreate = fake.writes.find((write) => write.description === "doubleyoup-edge-block:1");
    expect(blockCreate?.body?.position).toEqual({ before: "b-country" });
    const xmlrpcCreate = fake.writes.find((write) => write.description === WAF_XMLRPC_DESCRIPTION);
    expect(xmlrpcCreate?.body?.position).toEqual({ after: "b-wpadmin" });
    // Only OUR rules moved, each with its full definition.
    for (const write of fake.writes.filter((candidate) => candidate.method === "PATCH")) {
      expect(write.body?.position).toBeDefined();
      expect(typeof write.body?.expression).toBe("string");
    }
    expect(result.foreign.map((rule) => [rule.description, rule.position])).toEqual([
      ["agency-one", indexOf("f-one") + 1],
      ["agency-two", indexOf("f-two") + 1],
    ]);
    // A second run finds everything in place.
    fake.writes = [];
    await actuateWafEdgeSync(
      validParams({
        block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }],
        challenge: [{ key: "ban2", hosts: ["a.example.com"], ips: [], uas: ["ExampleBot/1.0"] }],
      }),
      envWithToken(),
    );
    expect(fake.writes).toEqual([]);
  });

  it("retireLegacy deletes the legacy rules LAST — after every write of ours, the Managed Ruleset included", async () => {
    const initial: FakeRule[] = [
      { id: "l-ban", description: "doubleyoup-ban:old1", expression: "ip.src in {198.51.100.1}", action: "block", enabled: true },
      { id: "l-geo", description: "doubleyoup-geo:site1:frontend", expression: "true", action: "managed_challenge", enabled: true },
      { id: "f-keep", description: "agency-keep", expression: "true", action: "log", enabled: true },
    ];
    const fake = new FakeCloudflare(initial).install();
    const result = await actuateWafEdgeSync(
      validParams({
        baseline: { ...(rawParams().baseline as object), includeManagedRuleset: true },
        block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["198.51.100.1"], uas: [] }],
        retireLegacy: true,
      }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(result.detail);
    const log = writeLog(fake);
    expect(log.slice(-2)).toEqual(["DELETE doubleyoup-ban:old1", "DELETE doubleyoup-geo:site1:frontend"]);
    const firstLegacyDelete = log.indexOf("DELETE doubleyoup-ban:old1");
    const lastOtherWrite = Math.max(...log.map((entry, index) => (entry.includes("doubleyoup-ban:") || entry.includes("doubleyoup-geo:") ? -1 : index)));
    expect(lastOtherWrite).toBeLessThan(firstLegacyDelete);
    // The managed-phase write is among the writes BEFORE the legacy deletes.
    expect(fake.writes.findIndex((write) => write.phase === "managed")).toBeLessThan(firstLegacyDelete);
    expect(fake.managedRules?.[0]).toMatchObject({ description: MANAGED_RULESET_RULE_DESCRIPTION, action: "execute", action_parameters: { id: CLOUDFLARE_MANAGED_RULESET_ID } });
    expect(result.created).toContain(MANAGED_RULESET_RULE_DESCRIPTION);
    expect(result.managedRuleset).toBe("deployed");
    expect(result.legacyDeleted).toEqual(["doubleyoup-ban:old1", "doubleyoup-geo:site1:frontend"]);
    expect(fake.customDescriptions()).not.toContain("doubleyoup-ban:old1");
    expect(fake.customDescriptions()).toContain("agency-keep");
  });

  it("retireLegacy deletes NOTHING when one of our writes fails: writeFailed, with what landed", async () => {
    const legacy: FakeRule = { id: "l-ban", description: "doubleyoup-ban:old1", expression: "ip.src in {198.51.100.1}", action: "block", enabled: true };
    const kept = siteIpClause("192.0.2.1", ["a.example.com"]);
    const leaving = siteIpClause("192.0.2.2", ["a.example.com"]);
    const fake = new FakeCloudflare([legacy, { id: "c1", ...buildEdgeChunkRule("block", 1, [kept, leaving]) }, ...baselineRulesInOrder()] as FakeRule[]);
    // The LOSE patch of chunk 1 fails (its body no longer carries the leaving clause).
    fake.failWrite = (write) => write.method === "PATCH" && typeof write.body?.expression === "string" && !String(write.body.expression).includes("192.0.2.2");
    fake.install();
    const result = await actuateWafEdgeSync(
      validParams({
        block: [
          { key: "k", hosts: ["a.example.com"], ips: ["192.0.2.1"], uas: [] },
          { key: "n", hosts: ["a.example.com"], ips: ["192.0.2.3"], uas: [] },
        ],
        retireLegacy: true,
      }),
      envWithToken(),
    );
    expect(result).toMatchObject({
      ok: false,
      op: "waf-edge-sync",
      zone: ZONE,
      code: "writeFailed",
      landed: { created: [], patched: ["doubleyoup-edge-block:1"], deleted: [] },
    });
    expect(fake.writes.some((write) => write.method === "DELETE")).toBe(false);
    expect(fake.customDescriptions()).toContain("doubleyoup-ban:old1");
  });

  it("retireLegacy false leaves the legacy rules alone and counts them", async () => {
    const legacy: FakeRule = { id: "l-geo", description: "doubleyoup-geo:site1:block", expression: "true", action: "block", enabled: true };
    const fake = new FakeCloudflare([legacy, ...baselineRulesInOrder()]).install();
    const result = await actuateWafEdgeSync(validParams({ retireLegacy: false }), envWithToken());
    if (!result.ok) throw new Error(result.detail);
    expect(fake.writes).toEqual([]);
    expect(result.rulesUsed).toBe(7);
    expect(result.foreign).toEqual([]);
    expect(result.legacyDeleted).toEqual([]);
  });

  it("A10: resolves a duplicated BASELINE description — keeps the lowest copy, patches it, deletes the others last", async () => {
    // The lower copy of the login gate is switched off (a hand edit); the documented one sits after it.
    const baseline = baselineRulesInOrder();
    const loginGate = baseline[3] as FakeRule;
    const lowerTwin: FakeRule = { ...loginGate, id: "b-login-lower-twin", enabled: false };
    const startRules = [lowerTwin, ...baseline];
    const fake = new FakeCloudflare(cloneRules(startRules)).install();
    const result = await actuateWafEdgeSync(
      validParams({ block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }] }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(result.detail);
    // The kept copy is the LOWEST one (the twin): switched back on, then moved into place. The later
    // copy (the old documented one) is deleted once the kept copy is in force; only moves follow it.
    const deleteIndex = fake.writes.findIndex((write) => write.method === "DELETE");
    expect(fake.writes[deleteIndex]).toMatchObject({ description: WAF_LOGIN_GATE_DESCRIPTION, ruleId: loginGate.id });
    const twinSwitchOn = fake.writes.findIndex(
      (write) => write.method === "PATCH" && write.ruleId === "b-login-lower-twin" && write.body?.enabled === true && write.body?.position === undefined,
    );
    expect(twinSwitchOn).toBeGreaterThanOrEqual(0);
    expect(twinSwitchOn).toBeLessThan(deleteIndex);
    for (const write of fake.writes.slice(deleteIndex + 1)) expect(write).toMatchObject({ method: "PATCH", body: { position: {} } });
    expect(result.deleted).toEqual([WAF_LOGIN_GATE_DESCRIPTION]);
    expect(result.patched).toContain(WAF_LOGIN_GATE_DESCRIPTION);
    const loginCopies = (fake.customRules ?? []).filter((rule) => rule.description === WAF_LOGIN_GATE_DESCRIPTION);
    expect(loginCopies.map((rule) => rule.id)).toEqual(["b-login-lower-twin"]);
    expect(loginCopies[0]).toMatchObject(baselineBodies().login);
    // At every step at least one ENABLED login gate is in force.
    for (const state of [startRules, ...fake.snapshots]) {
      const enabledGates = state.filter((rule) => rule.description === WAF_LOGIN_GATE_DESCRIPTION && rule.enabled !== false);
      expect(enabledGates.length).toBeGreaterThanOrEqual(1);
    }
    expect(fake.customDescriptions()).toEqual([
      "doubleyoup-edge-block:1",
      WAF_COUNTRY_BLOCK_DESCRIPTION,
      WAF_WPADMIN_GEO_DESCRIPTION,
      WAF_XMLRPC_DESCRIPTION,
      WAF_LOGIN_GATE_DESCRIPTION,
      WAF_FRONTEND_GEO_DESCRIPTION,
      WAF_EXEC_SKIP_DESCRIPTION,
    ]);
    // Converged: the next run writes nothing.
    fake.writes = [];
    const again = await actuateWafEdgeSync(
      validParams({ block: [{ key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] }] }),
      envWithToken(),
    );
    expect(again.ok).toBe(true);
    expect(fake.writes).toEqual([]);
  });

  it("refuses a missing token, touching nothing", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const noToken = await actuateWafEdgeSync(validParams(), {} as Env);
    expect(noToken).toEqual({
      ok: false,
      op: "waf-edge-sync",
      zone: ZONE,
      code: "notConfigured",
      detail: "CF_DNS_API_TOKEN is not configured on this Worker.",
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("reports cloudflare when the rules cannot be read, writing nothing", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (new URL(url).pathname === "/client/v4/zones") {
        return jsonResponse({ success: true, result: [{ id: "zone-1", name: ZONE, plan: { legacy_id: "pro" } }] });
      }
      return jsonResponse({ success: false, errors: [{ message: "Authentication error" }] }, 403);
    });
    const result = await actuateWafEdgeSync(validParams(), envWithToken());
    expect(result).toMatchObject({ ok: false, code: "cloudflare" });
  });
});

// ── overlapping runs: the per-zone lease, and duplicates resolved, never refused ──────

describe("waf-edge-sync: overlapping runs", () => {
  const LEASE_INSTANCE = `edge-sync-lease:${ZONE}`;
  const LEASE_SLOT = `${LEASE_INSTANCE}|${ZONE}`;
  const ban1 = { key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] };
  const ban2 = { key: "ban2", hosts: ["a.example.com"], ips: ["192.0.2.8"], uas: [] };

  it("refuses busy, touching nothing, while another run holds the zone's lease", async () => {
    const leases = new FakeLeaseNamespace();
    expect(await leases.get(LEASE_INSTANCE).acquireLease(ZONE, "another-run", EDGE_SYNC_LEASE_TTL_MS)).toBe("acquired");
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const result = await actuateWafEdgeSync(validParams({ block: [ban1] }), envWithToken(leases));
    expect(result).toMatchObject({ ok: false, op: "waf-edge-sync", zone: ZONE, code: "busy" });
    expect(fetchSpy).not.toHaveBeenCalled();
    // The refused run did not release the holder's lease.
    expect(leases.leases.get(LEASE_SLOT)?.holder).toBe("another-run");
    expect(EDGE_SYNC_LEASE_TTL_MS).toBe(5 * 60 * 1000);
  });

  it("releases the lease at the end of every run: success, refusal and failed write alike", async () => {
    const leases = new FakeLeaseNamespace();
    new FakeCloudflare(baselineRulesInOrder()).install();
    expect((await actuateWafEdgeSync(validParams(), envWithToken(leases))).ok).toBe(true);
    expect(leases.leases.has(LEASE_SLOT)).toBe(false);
    vi.restoreAllMocks();

    const freeZone = new FakeCloudflare(baselineRulesInOrder());
    freeZone.plan = "free";
    freeZone.install();
    expect(await actuateWafEdgeSync(validParams({ block: [ban1] }), envWithToken(leases))).toMatchObject({ ok: false, code: "planTooSmall" });
    expect(leases.leases.has(LEASE_SLOT)).toBe(false);
    vi.restoreAllMocks();

    const failingZone = new FakeCloudflare(baselineRulesInOrder());
    failingZone.failWrite = () => true;
    failingZone.install();
    expect(await actuateWafEdgeSync(validParams({ block: [ban1] }), envWithToken(leases))).toMatchObject({ ok: false, code: "writeFailed" });
    expect(leases.leases.has(LEASE_SLOT)).toBe(false);

    // One lease instance per zone, keyed by the zone.
    expect(leases.acquires).toEqual([
      { instance: LEASE_INSTANCE, leaseKey: ZONE, outcome: "acquired" },
      { instance: LEASE_INSTANCE, leaseKey: ZONE, outcome: "acquired" },
      { instance: LEASE_INSTANCE, leaseKey: ZONE, outcome: "acquired" },
    ]);
  });

  it("with the lease, two runs started together: one applies, the other is busy, and no rule is duplicated", async () => {
    const leases = new FakeLeaseNamespace();
    const fake = new FakeCloudflare(baselineRulesInOrder()).install();
    const params = validParams({ block: [ban1] });
    const results = await Promise.all([actuateWafEdgeSync(params, envWithToken(leases)), actuateWafEdgeSync(params, envWithToken(leases))]);
    const codes = results.map((result) => (result.ok ? "ok" : result.code)).sort();
    expect(codes).toEqual(["busy", "ok"]);
    expect(fake.customDescriptions().filter((description) => description === "doubleyoup-edge-block:1")).toHaveLength(1);
  });

  it("WITHOUT the lease (a run that outlived it), the chunk an overlap duplicated is resolved by the next run, never refused", async () => {
    const leases = new FakeLeaseNamespace();
    leases.disabled = true;
    const fake = new FakeCloudflare(baselineRulesInOrder()).install();
    const wantedParams = validParams({ block: [ban1, ban2] });
    await Promise.all([
      actuateWafEdgeSync(validParams({ block: [ban1] }), envWithToken(leases)),
      actuateWafEdgeSync(wantedParams, envWithToken(leases)),
    ]);
    // Both runs created chunk 1: the state an overlap leaves.
    const copies = (fake.customRules ?? []).filter((rule) => rule.description === "doubleyoup-edge-block:1");
    expect(copies).toHaveLength(2);
    const keptId = (copies[0] as FakeRule).id;
    const laterId = (copies[1] as FakeRule).id;

    leases.disabled = false;
    const startState = cloneRules(fake.customRules ?? []);
    fake.writes = [];
    fake.snapshots = [];
    const resolved = await actuateWafEdgeSync(wantedParams, envWithToken(leases));
    if (!resolved.ok) throw new Error(resolved.detail);
    // The later copy goes LAST, and only once the kept copy (the lowest position) holds every wanted clause.
    expect(fake.writes.at(-1)).toMatchObject({ method: "DELETE", description: "doubleyoup-edge-block:1", ruleId: laterId });
    const states = [startState, ...fake.snapshots];
    const beforeDelete = states[states.length - 2] as FakeRule[];
    const wanted = [siteIpClause("192.0.2.7", ["a.example.com"]), siteIpClause("192.0.2.8", ["a.example.com"])];
    const keptBeforeDelete = beforeDelete.find((rule) => rule.id === keptId) as FakeRule;
    expect(new Set(splitChunkExpression(keptBeforeDelete.expression ?? ""))).toEqual(new Set(wanted));
    expect(resolved.deleted).toEqual(["doubleyoup-edge-block:1"]);
    const finalCopies = (fake.customRules ?? []).filter((rule) => rule.description === "doubleyoup-edge-block:1");
    expect(finalCopies.map((rule) => rule.id)).toEqual([keptId]);

    // Converged: the next run writes nothing.
    fake.writes = [];
    expect((await actuateWafEdgeSync(wantedParams, envWithToken(leases))).ok).toBe(true);
    expect(fake.writes).toEqual([]);
  });

  it("keeps the copy with the LOWEST position, whatever its contents, and moves the other copy's wanted clause into it first", async () => {
    const clauseA = siteIpClause("192.0.2.7", ["a.example.com"]);
    const clauseB = siteIpClause("192.0.2.8", ["a.example.com"]);
    const baseline = baselineRulesInOrder();
    const fake = new FakeCloudflare([
      { id: "first-copy", ...buildEdgeChunkRule("block", 1, [clauseA]) },
      ...baseline.slice(0, 2),
      { id: "second-copy", ...buildEdgeChunkRule("block", 1, [clauseA, clauseB]) },
      ...baseline.slice(2),
    ] as FakeRule[]).install();
    const result = await actuateWafEdgeSync(validParams({ block: [ban1, ban2] }), envWithToken());
    if (!result.ok) throw new Error(result.detail);
    expect(fake.writes.map((write) => [write.method, write.ruleId])).toEqual([
      ["PATCH", "first-copy"],
      ["DELETE", "second-copy"],
    ]);
    expect(fake.customRules?.find((rule) => rule.id === "first-copy")?.expression).toBe(joinChunkClauses([clauseA, clauseB]));
    expect(result.patched).toEqual(["doubleyoup-edge-block:1"]);
    expect(result.deleted).toEqual(["doubleyoup-edge-block:1"]);
    expect(result.chunks).toEqual({ block: 1, challenge: 0 });
  });
});

// ── rate limiting (Amendment A7) ──────────────────────────────────────────────────────

describe("waf-edge-sync: rate limiting (Amendment A7)", () => {
  const ORIGIN_THRESHOLD = { requests: 600, periodSeconds: 60, mitigationSeconds: 600 };
  const EXPENSIVE_THRESHOLD = { requests: 60, periodSeconds: 10, mitigationSeconds: 3600 };
  const RATE_LIMIT_ON = { enabled: true, origin: ORIGIN_THRESHOLD, expensive: EXPENSIVE_THRESHOLD };
  const STATIC_TEXT = ["css", "js", "jpg", "jpeg", "gif", "png", "webp", "svg", "woff", "woff2"]
    .map((extension) => `ends_with(http.request.uri.path, ".${extension}")`)
    .join(" or ");
  const HOSTS_TEXT = 'not (http.host in {"cell-x.example.com" "host.example.com"}) and not (ends_with(http.host, "-media.example.com"))';
  const PRO_EXCLUSIONS = `${HOSTS_TEXT} and not (cf.client.bot) and not (${STATIC_TEXT})`;
  const ENTERPRISE_EXCLUSIONS = `${HOSTS_TEXT} and not (cf.client.bot) and not (http.cookie contains "wordpress_logged_in_") and not (${STATIC_TEXT})`;
  const EXPENSIVE_INCLUSIONS =
    '(starts_with(http.request.uri.path, "/wp-json/") or http.request.uri.path eq "/wp-admin/admin-ajax.php" or ' +
    '(starts_with(http.request.uri.query, "s=") or http.request.uri.query contains "&s=") or ' +
    '(starts_with(http.request.uri.query, "rest_route=") or http.request.uri.query contains "&rest_route=") or ' +
    '(starts_with(http.request.uri.query, "wc-ajax=") or http.request.uri.query contains "&wc-ajax="))';
  const ban1 = { key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] };

  function expectedRule(description: string, expression: string, threshold: typeof ORIGIN_THRESHOLD, enabled = true) {
    return {
      description,
      expression,
      action: "block",
      ratelimit: {
        characteristics: ["cf.colo.id", "ip.src"],
        period: threshold.periodSeconds,
        requests_per_period: threshold.requests,
        mitigation_timeout: threshold.mitigationSeconds,
        requests_to_origin: false,
      },
      enabled,
    };
  }
  const PRO_ORIGIN = expectedRule(RATE_LIMIT_ORIGIN_DESCRIPTION, PRO_EXCLUSIONS, ORIGIN_THRESHOLD);
  const PRO_EXPENSIVE = expectedRule(RATE_LIMIT_EXPENSIVE_DESCRIPTION, `${EXPENSIVE_INCLUSIONS} and ${PRO_EXCLUSIONS}`, EXPENSIVE_THRESHOLD);

  function foreignRateLimitRule(id: string): FakeRule {
    return {
      id,
      description: `agency-${id}`,
      expression: 'starts_with(http.request.uri.path, "/api/")',
      action: "managed_challenge",
      ratelimit: { characteristics: ["cf.colo.id", "ip.src"], period: 10, requests_per_period: 50, mitigation_timeout: 0 },
      enabled: true,
    };
  }

  it("builds both rules for the plan (golden text); Pro and Business leave out ONLY the cookie clause, and name it", () => {
    const input = {
      zone: ZONE,
      excludedHosts: [...EXCLUDED_HOSTS].reverse(),
      enabled: true,
      origin: ORIGIN_THRESHOLD,
      expensive: EXPENSIVE_THRESHOLD,
    };
    expect(buildRateLimitRules({ ...input, planLegacyId: "pro" })).toEqual({
      ok: true,
      origin: PRO_ORIGIN,
      expensive: PRO_EXPENSIVE,
      omittedClauses: ["loggedInCookie"],
    });
    expect(buildRateLimitRules({ ...input, planLegacyId: "business" })).toMatchObject({ ok: true, omittedClauses: ["loggedInCookie"] });
    expect(buildRateLimitRules({ ...input, planLegacyId: "enterprise", enabled: false })).toEqual({
      ok: true,
      origin: expectedRule(RATE_LIMIT_ORIGIN_DESCRIPTION, ENTERPRISE_EXCLUSIONS, ORIGIN_THRESHOLD, false),
      expensive: expectedRule(RATE_LIMIT_EXPENSIVE_DESCRIPTION, `${EXPENSIVE_INCLUSIONS} and ${ENTERPRISE_EXCLUSIONS}`, EXPENSIVE_THRESHOLD, false),
      omittedClauses: [],
    });
    // A block over Pro's 1 h maximum is refused; Business allows a day.
    const dayLong = { ...input, expensive: { ...EXPENSIVE_THRESHOLD, mitigationSeconds: 86400 } };
    expect(buildRateLimitRules({ ...dayLong, planLegacyId: "pro" }).ok).toBe(false);
    expect(buildRateLimitRules({ ...dayLong, planLegacyId: "business" }).ok).toBe(true);
    expect(buildRateLimitRules({ ...input, planLegacyId: "some-new-plan" }).ok).toBe(false);
    expect(buildRateLimitRules({ ...input, planLegacyId: null }).ok).toBe(false);
    // Budgets: Free 1, Pro 2, Business 5, Enterprise 100; an unknown plan gets Free's.
    expect([null, "free", "pro", "business", "enterprise", "some-new-plan"].map(rateLimitRuleCapForPlan)).toEqual([1, 1, 2, 5, 100, 1]);
  });

  it("validates rateLimit strictly: absent = disabled, unknown keys refused at both levels, thresholds both or neither", () => {
    expect(validParams().rateLimit).toEqual({ enabled: false });
    expect(validParams({ rateLimit: { enabled: false } }).rateLimit).toEqual({ enabled: false });
    expect(validParams({ rateLimit: RATE_LIMIT_ON }).rateLimit).toEqual(RATE_LIMIT_ON);
    expect(validParams({ rateLimit: { ...RATE_LIMIT_ON, enabled: false } }).rateLimit).toEqual({ ...RATE_LIMIT_ON, enabled: false });
    const widest = { requests: 1_000_000, periodSeconds: 10, mitigationSeconds: 86400 };
    expect(validParams({ rateLimit: { ...RATE_LIMIT_ON, origin: widest } }).rateLimit).toEqual({ ...RATE_LIMIT_ON, origin: widest });
    const threshold = (overrides: Record<string, unknown>) => ({ ...ORIGIN_THRESHOLD, ...overrides });
    const bad: unknown[] = [
      "on",
      null,
      {},
      { enabled: "true" },
      { enabled: true },
      { enabled: true, origin: ORIGIN_THRESHOLD },
      { enabled: false, expensive: EXPENSIVE_THRESHOLD },
      { ...RATE_LIMIT_ON, characteristics: ["ip.src"] },
      { ...RATE_LIMIT_ON, origin: threshold({ expression: "true" }) },
      { ...RATE_LIMIT_ON, origin: threshold({ requests: 0 }) },
      { ...RATE_LIMIT_ON, origin: threshold({ requests: 1.5 }) },
      { ...RATE_LIMIT_ON, origin: threshold({ requests: 1_000_001 }) },
      { ...RATE_LIMIT_ON, origin: threshold({ requests: "600" }) },
      { ...RATE_LIMIT_ON, origin: threshold({ periodSeconds: 30 }) },
      { ...RATE_LIMIT_ON, origin: threshold({ periodSeconds: undefined }) },
      { ...RATE_LIMIT_ON, origin: threshold({ mitigationSeconds: 0 }) },
      { ...RATE_LIMIT_ON, origin: threshold({ mitigationSeconds: 7200 }) },
      { ...RATE_LIMIT_ON, expensive: threshold({ mitigationSeconds: 15 }) },
      { ...RATE_LIMIT_ON, expensive: [] },
    ];
    for (const rateLimit of bad) {
      const verdict = validateWafEdgeSyncParams(rawParams({ rateLimit }));
      if (verdict.ok) throw new Error(`accepted rateLimit ${JSON.stringify(rateLimit)}`);
    }
  });

  it("creates both rules AFTER every custom write (legacy retirement included), and a re-run writes nothing", async () => {
    const legacy: FakeRule = { id: "l-ban", description: "doubleyoup-ban:old1", expression: "ip.src in {198.51.100.1}", action: "block", enabled: true };
    const fake = new FakeCloudflare([legacy, ...baselineRulesInOrder()]).install();
    const params = validParams({ block: [ban1], retireLegacy: true, rateLimit: RATE_LIMIT_ON });
    const result = await actuateWafEdgeSync(params, envWithToken());
    if (!result.ok) throw new Error(result.detail);
    expect(fake.writes.map((write) => `${write.phase} ${write.method} ${write.description}`)).toEqual([
      "custom POST doubleyoup-edge-block:1",
      "custom DELETE doubleyoup-ban:old1",
      "ratelimit POST entrypoint",
    ]);
    expect(fake.writes.at(-1)?.body).toEqual({ name: "default", kind: "zone", phase: "http_ratelimit", rules: [PRO_ORIGIN, PRO_EXPENSIVE] });
    expect(result.rateLimit).toEqual({
      ok: true,
      created: [RATE_LIMIT_ORIGIN_DESCRIPTION, RATE_LIMIT_EXPENSIVE_DESCRIPTION],
      patched: [],
      deleted: [],
      omittedClauses: ["loggedInCookie"],
    });
    expect((fake.rateLimitRules ?? []).map((rule) => rule.expression ?? "").some((expression) => expression.includes("http.cookie"))).toBe(false);

    fake.writes = [];
    const again = await actuateWafEdgeSync(params, envWithToken());
    expect(again.ok).toBe(true);
    expect(fake.writes).toEqual([]);
  });

  it("appends to a phase that holds foreign rules and never writes one of them (Business: 5 slots)", async () => {
    const fake = new FakeCloudflare(baselineRulesInOrder());
    fake.plan = "business";
    const foreign = [foreignRateLimitRule("f1"), foreignRateLimitRule("f2")];
    fake.rateLimitRules = cloneRules(foreign);
    fake.install();
    const result = await actuateWafEdgeSync(validParams({ rateLimit: RATE_LIMIT_ON }), envWithToken());
    if (!result.ok) throw new Error(result.detail);
    expect(fake.writes.map((write) => `${write.method} ${write.description}`)).toEqual([
      `POST ${RATE_LIMIT_ORIGIN_DESCRIPTION}`,
      `POST ${RATE_LIMIT_EXPENSIVE_DESCRIPTION}`,
    ]);
    for (const write of fake.writes) expect(write.body?.position).toBeUndefined();
    expect((fake.rateLimitRules ?? []).slice(0, 2)).toEqual(foreign);
    expect((fake.rateLimitRules ?? []).map((rule) => rule.description)).toEqual([
      "agency-f1",
      "agency-f2",
      RATE_LIMIT_ORIGIN_DESCRIPTION,
      RATE_LIMIT_EXPENSIVE_DESCRIPTION,
    ]);
    expect(result.rateLimit).toMatchObject({ ok: true, omittedClauses: ["loggedInCookie"] });
  });

  it("refuses capExceeded for rate limiting ALONE: writes neither rule, still applies the custom rules", async () => {
    // Pro: 2 rate-limit rules. One foreign rule + our two = 3.
    const fake = new FakeCloudflare(baselineRulesInOrder());
    const foreign = foreignRateLimitRule("f1");
    // One of ours already exists, drifted: it is NOT patched either, because the pair does not fit.
    const ourOld = { ...PRO_ORIGIN, id: "r-origin", ratelimit: { ...PRO_ORIGIN.ratelimit, requests_per_period: 5 } } as FakeRule;
    fake.rateLimitRules = cloneRules([foreign, ourOld]);
    fake.install();
    const result = await actuateWafEdgeSync(validParams({ block: [ban1], rateLimit: RATE_LIMIT_ON }), envWithToken());
    if (!result.ok) throw new Error(result.detail);
    expect(result.rateLimit).toMatchObject({ ok: false, code: "capExceeded", created: [], patched: [], deleted: [], omittedClauses: ["loggedInCookie"] });
    expect(result.rateLimit.detail).toMatch(/2 rate-limit rules/);
    // The custom rules were applied all the same.
    expect(result.created).toEqual(["doubleyoup-edge-block:1"]);
    expect(fake.writes.filter((write) => write.phase === "ratelimit")).toEqual([]);
    expect(fake.rateLimitRules).toEqual([foreign, ourOld]);
  });

  it("enabled:false (or absent) switches our rules off IN PLACE, keeps everything else, and creates nothing", async () => {
    const fake = new FakeCloudflare(baselineRulesInOrder());
    fake.rateLimitRules = [foreignRateLimitRule("f0")];
    fake.plan = "business";
    fake.install();
    await actuateWafEdgeSync(validParams({ rateLimit: RATE_LIMIT_ON }), envWithToken());
    const createdRules = cloneRules(fake.rateLimitRules ?? []);
    expect(createdRules.filter((rule) => rule.enabled === true)).toHaveLength(3);

    // Absent => disabled: our two are PATCHed off, otherwise byte-identical, same ids; the foreign rule is untouched.
    fake.writes = [];
    const off = await actuateWafEdgeSync(validParams(), envWithToken());
    if (!off.ok) throw new Error(off.detail);
    expect(fake.writes.map((write) => `${write.method} ${write.description}`)).toEqual([
      `PATCH ${RATE_LIMIT_ORIGIN_DESCRIPTION}`,
      `PATCH ${RATE_LIMIT_EXPENSIVE_DESCRIPTION}`,
    ]);
    expect(off.rateLimit).toEqual({ ok: true, created: [], patched: [RATE_LIMIT_ORIGIN_DESCRIPTION, RATE_LIMIT_EXPENSIVE_DESCRIPTION], deleted: [], omittedClauses: [] });
    expect(fake.rateLimitRules).toEqual(createdRules.map((rule) => (rule.description === "agency-f0" ? rule : { ...rule, enabled: false })));
    expect(fake.rateLimitRules?.[0]).toEqual(createdRules[0]);

    // Disabled again: nothing to do.
    fake.writes = [];
    await actuateWafEdgeSync(validParams({ rateLimit: { enabled: false } }), envWithToken());
    expect(fake.writes).toEqual([]);

    // Disabled WITH new thresholds: the definition is updated, and stays off.
    const newOrigin = { ...ORIGIN_THRESHOLD, requests: 900 };
    await actuateWafEdgeSync(validParams({ rateLimit: { enabled: false, origin: newOrigin, expensive: EXPENSIVE_THRESHOLD } }), envWithToken());
    expect(fake.writes.map((write) => `${write.method} ${write.description}`)).toEqual([`PATCH ${RATE_LIMIT_ORIGIN_DESCRIPTION}`]);
    expect(fake.rateLimitRules?.find((rule) => rule.description === RATE_LIMIT_ORIGIN_DESCRIPTION)).toMatchObject({
      enabled: false,
      ratelimit: { requests_per_period: 900 },
    });

    // A zone without our rules: disabled creates nothing, whether the phase exists or not.
    vi.restoreAllMocks();
    const bare = new FakeCloudflare(baselineRulesInOrder()).install();
    const bareResult = await actuateWafEdgeSync(validParams({ rateLimit: { enabled: false, origin: ORIGIN_THRESHOLD, expensive: EXPENSIVE_THRESHOLD } }), envWithToken());
    expect(bare.writes).toEqual([]);
    expect(bareResult).toMatchObject({ ok: true, rateLimit: { ok: true, created: [], patched: [], omittedClauses: ["loggedInCookie"] } });
    bare.rateLimitRules = [foreignRateLimitRule("f9")];
    await actuateWafEdgeSync(validParams(), envWithToken());
    expect(bare.writes).toEqual([]);
  });

  it("refuses a block the plan does not allow (invalid) without touching the phase, and still applies the custom rules", async () => {
    const fake = new FakeCloudflare(baselineRulesInOrder()).install();
    const result = await actuateWafEdgeSync(
      validParams({ block: [ban1], rateLimit: { ...RATE_LIMIT_ON, expensive: { ...EXPENSIVE_THRESHOLD, mitigationSeconds: 86400 } } }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(result.detail);
    expect(result.rateLimit).toMatchObject({ ok: false, code: "invalid", created: [], patched: [] });
    expect(result.rateLimit.detail).toMatch(/86400/);
    expect(result.created).toEqual(["doubleyoup-edge-block:1"]);
    expect(fake.requests.some((request) => request.includes("http_ratelimit"))).toBe(false);
  });

  it("reports a rate-limit read or write failure in rateLimit (with what landed), never as a failed run", async () => {
    const fake = new FakeCloudflare(baselineRulesInOrder());
    fake.rateLimitRules = [];
    fake.failWrite = (write) => write.phase === "ratelimit" && write.description === RATE_LIMIT_EXPENSIVE_DESCRIPTION;
    fake.install();
    const result = await actuateWafEdgeSync(validParams({ block: [ban1], rateLimit: RATE_LIMIT_ON }), envWithToken());
    if (!result.ok) throw new Error(result.detail);
    expect(result.created).toEqual(["doubleyoup-edge-block:1"]);
    expect(result.rateLimit).toMatchObject({ ok: false, code: "writeFailed", created: [RATE_LIMIT_ORIGIN_DESCRIPTION], patched: [] });

    fake.failWrite = null;
    fake.failRead = "ratelimit";
    const unreadable = await actuateWafEdgeSync(validParams({ block: [ban1], rateLimit: RATE_LIMIT_ON }), envWithToken());
    expect(unreadable).toMatchObject({ ok: true, rateLimit: { ok: false, code: "cloudflare" } });
  });

  it("resolves a duplicated rule of ours: keeps the first, deletes the later copy BEFORE creating the missing rule", async () => {
    const fake = new FakeCloudflare(baselineRulesInOrder());
    fake.plan = "pro";
    // An overlap left two copies of the origin rule and no expensive rule (Pro: the phase is full).
    fake.rateLimitRules = cloneRules([
      { ...PRO_ORIGIN, id: "r-origin-first", ratelimit: { ...PRO_ORIGIN.ratelimit, requests_per_period: 5 } },
      { ...PRO_ORIGIN, id: "r-origin-later" },
    ] as FakeRule[]);
    fake.install();
    const result = await actuateWafEdgeSync(validParams({ rateLimit: RATE_LIMIT_ON }), envWithToken());
    if (!result.ok) throw new Error(result.detail);
    expect(fake.writes.map((write) => [write.method, write.description, write.ruleId])).toEqual([
      ["PATCH", RATE_LIMIT_ORIGIN_DESCRIPTION, "r-origin-first"],
      ["DELETE", RATE_LIMIT_ORIGIN_DESCRIPTION, "r-origin-later"],
      ["POST", RATE_LIMIT_EXPENSIVE_DESCRIPTION, null],
    ]);
    expect(result.rateLimit).toEqual({
      ok: true,
      created: [RATE_LIMIT_EXPENSIVE_DESCRIPTION],
      patched: [RATE_LIMIT_ORIGIN_DESCRIPTION],
      deleted: [RATE_LIMIT_ORIGIN_DESCRIPTION],
      omittedClauses: ["loggedInCookie"],
    });
    expect((fake.rateLimitRules ?? []).map((rule) => rule.id)).toEqual(["r-origin-first", "new-1"]);
  });
});

// ── Amendment A10: the code review's findings, as regression tests ────────────────────

describe("waf-edge-sync: Amendment A10 (review regressions)", () => {
  const ban1 = { key: "ban1", hosts: ["a.example.com"], ips: ["192.0.2.7"], uas: [] };
  const ban2 = { key: "ban2", hosts: ["a.example.com"], ips: ["192.0.2.8"], uas: [] };
  const BASELINE_OFF = { ...(rawParams().baseline as object), enabled: false };

  /** One of our rate-limit rules, switched on, inside every plan's limits (Free included). */
  function enabledRateLimitRule(id: string): FakeRule {
    return {
      id,
      description: RATE_LIMIT_ORIGIN_DESCRIPTION,
      expression: "true",
      action: "block",
      enabled: true,
      ratelimit: { characteristics: ["cf.colo.id", "ip.src"], period: 10, requests_per_period: 5, mitigation_timeout: 10, requests_to_origin: false },
    };
  }

  /** A zone that grew our rules on Pro: the baseline with a site Under Attack chunk inside it. */
  function zoneWithUnderAttackChunk(): FakeRule[] {
    const underAttack = buildEdgeClauses([{ hosts: ["shop.example.org"], ips: [], uas: [], all: true }], EXCLUDED_HOSTS);
    if (!underAttack.ok) throw new Error(underAttack.reason);
    const chunk = { id: "c1", ...buildEdgeChunkRule("challenge", 1, underAttack.clauses) } as FakeRule;
    const baseline = baselineRulesInOrder();
    return [...baseline.slice(0, 3), chunk, ...baseline.slice(3)];
  }

  function agencyRules(count: number): FakeRule[] {
    return Array.from({ length: count }, (_, index) => ({
      id: `f${index}`,
      description: `agency-rule-${index}`,
      expression: "true",
      action: "log",
      enabled: true,
    }));
  }

  // Finding 1 (probe scenarioCapBlocksRemoval).
  it("a run that SHRINKS our rules is never refused by the reserved slots: Under Attack off + rollback on a full zone", async () => {
    // Pro: 20 rules, 3 reserved. 7 of ours + 12 foreign = 19 > 17, but the run only removes.
    const startRules = [...zoneWithUnderAttackChunk(), ...agencyRules(12)];
    const fake = new FakeCloudflare(startRules).install();
    const result = await actuateWafEdgeSync(validParams({ challenge: [], baseline: BASELINE_OFF }), envWithToken());
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    expect(fake.writes.length).toBeGreaterThan(0);
    expect(fake.writes.filter((write) => write.method === "POST")).toEqual([]);
    expect(fake.customDescriptions()).not.toContain("doubleyoup-edge-challenge:1");
    expect(result.deleted).toEqual(["doubleyoup-edge-challenge:1"]);
    // Every baseline rule now carries its rolled-back definition.
    const rolledBack = Object.values(baselineBodies(false));
    for (const body of rolledBack) {
      expect(fake.customRules?.find((rule) => rule.description === body.description), body.description).toMatchObject(body);
    }
    expect(fake.customDescriptions().filter((description) => description.startsWith("agency-rule-"))).toHaveLength(12);
  });

  it("a run that keeps the same number of rules needs only the peak to fit (a ban swapped for another on a full zone)", async () => {
    // 13 foreign + 6 baseline + 1 chunk = 20 = the Pro cap: over cap − reservedSlots, but no growth.
    const chunk = { id: "c1", ...buildEdgeChunkRule("block", 1, [siteIpClause("192.0.2.7", ["a.example.com"])]) } as FakeRule;
    const fake = new FakeCloudflare([chunk, ...baselineRulesInOrder(), ...agencyRules(13)]).install();
    const swapped = await actuateWafEdgeSync(validParams({ block: [ban2] }), envWithToken());
    if (!swapped.ok) throw new Error(`${swapped.code}: ${swapped.detail}`);
    // The gain patch (holding both bans), then the lose patch: no create, so the peak is today's 20.
    expect(writeLog(fake)).toEqual(["PATCH doubleyoup-edge-block:1", "PATCH doubleyoup-edge-block:1"]);
    // Growing on the same zone is still refused, writing nothing.
    fake.writes = [];
    // Two bans of about 3,000 characters each cannot share a chunk: the run must create a second one.
    const longBanOne = { key: "long1", hosts: longHosts("grow", 15), ips: ["198.51.100.9"], uas: [] };
    const longBanTwo = { key: "long2", hosts: longHosts("more", 15), ips: ["198.51.100.10"], uas: [] };
    const grown = await actuateWafEdgeSync(validParams({ block: [ban2, longBanOne, longBanTwo] }), envWithToken());
    expect(grown).toMatchObject({ ok: false, code: "capExceeded" });
    expect(fake.writes).toEqual([]);
  });

  it("a removal-only run works on ANY plan (Free, unknown): deletes, clause removals, disables, Managed Ruleset rollback", async () => {
    for (const plan of ["free", null, "some-new-plan"]) {
      const fake = new FakeCloudflare(zoneWithUnderAttackChunk());
      fake.plan = plan;
      fake.install();
      const result = await actuateWafEdgeSync(
        validParams({ challenge: [], baseline: { ...BASELINE_OFF, includeManagedRuleset: true } }),
        envWithToken(),
      );
      if (!result.ok) throw new Error(`${String(plan)}: ${result.code}: ${result.detail}`);
      expect(result.deleted).toEqual(["doubleyoup-edge-challenge:1"]);
      expect(result.managedRuleset).toBe("absent");
      expect(fake.writes.filter((write) => write.method === "POST")).toEqual([]);
      vi.restoreAllMocks();
    }
  });

  it("planTooSmall still refuses, writing nothing, any run on Free that adds: a baseline switch-on or edit, an added clause", async () => {
    const offBaseline = baselineRulesInOrder().map((rule) => ({ ...rule, enabled: false }));
    const editedBaseline = baselineRulesInOrder().map((rule) => {
      if (rule.description !== WAF_COUNTRY_BLOCK_DESCRIPTION) return rule;
      return { ...rule, expression: `${rule.expression ?? ""} and ip.src ne 203.0.113.1` };
    });
    const chunk = { id: "c1", ...buildEdgeChunkRule("block", 1, [siteIpClause("192.0.2.7", ["a.example.com"])]) } as FakeRule;
    const cases: Array<{ name: string; rules: FakeRule[]; params: WafEdgeSyncParams }> = [
      { name: "switch the baseline on", rules: offBaseline, params: validParams() },
      // The op cannot tell a widened expression from a narrowed one, so an expression change counts.
      { name: "rewrite a hand-edited baseline block rule", rules: editedBaseline, params: validParams() },
      { name: "add a clause to a chunk", rules: [chunk, ...baselineRulesInOrder()], params: validParams({ block: [ban1, ban2] }) },
    ];
    for (const testCase of cases) {
      const fake = new FakeCloudflare(testCase.rules);
      fake.plan = "free";
      fake.install();
      const result = await actuateWafEdgeSync(testCase.params, envWithToken());
      expect(result, testCase.name).toMatchObject({ ok: false, code: "planTooSmall" });
      expect(fake.writes, testCase.name).toEqual([]);
      vi.restoreAllMocks();
    }
  });

  // Finding 10.
  it("the peak refusal gives advice that works: free slots by hand or upgrade — never 'a run that creates nothing'", async () => {
    const legacy: FakeRule[] = Array.from({ length: 10 }, (_, index) => ({
      id: `l-${index}`,
      description: `doubleyoup-ban:ban${index}`,
      expression: `ip.src in {198.51.100.${index}}`,
      action: "block",
      enabled: true,
    }));
    const fake = new FakeCloudflare([...legacy, ...agencyRules(4)]).install();
    const peak = await actuateWafEdgeSync(validParams({ block: [ban1], retireLegacy: true }), envWithToken());
    expect(peak).toMatchObject({ ok: false, code: "capExceeded" });
    if (peak.ok) throw new Error("expected a refusal");
    expect(peak.detail).toContain(WAF_XMLRPC_DESCRIPTION);
    expect(peak.detail).toContain("Free 1 slot(s)");
    expect(peak.detail).toContain("delete foreign rules");
    expect(peak.detail).toContain("delete legacy");
    expect(peak.detail).toContain("upgrade the zone's plan");
    expect(peak.detail).not.toMatch(/creates nothing/);
    expect(fake.writes).toEqual([]);
  });

  // Finding 3 (probe scenarioRateLimitDisableBlockedByCustomFailure). Finding 8: the xmlrpc twin is resolved.
  it("a duplicated xmlrpc rule no longer blocks anything: the twin is deleted and the rate-limit off switch runs", async () => {
    const baseline = baselineRulesInOrder();
    const xmlrpcTwin = { ...(baseline[2] as FakeRule), id: "dup-xmlrpc" };
    const fake = new FakeCloudflare([...baseline, xmlrpcTwin]);
    fake.rateLimitRules = [enabledRateLimitRule("rl1")];
    fake.install();
    const result = await actuateWafEdgeSync(validParams({ rateLimit: { enabled: false } }), envWithToken());
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    expect(writeLog(fake)).toEqual([`DELETE ${WAF_XMLRPC_DESCRIPTION}`, `PATCH ${RATE_LIMIT_ORIGIN_DESCRIPTION}`]);
    expect(fake.writes[0]?.ruleId).toBe("dup-xmlrpc");
    expect(fake.rateLimitRules?.[0]?.enabled).toBe(false);
    expect(result.rateLimit).toMatchObject({ ok: true, patched: [RATE_LIMIT_ORIGIN_DESCRIPTION] });
  });

  it("the rate-limit off switch runs whatever the custom part did: planTooSmall, capExceeded, invalid, cloudflare, writeFailed", async () => {
    const cases: Array<{ name: string; code: string; setUp: (fake: FakeCloudflare) => void; params: Record<string, unknown> }> = [
      { name: "planTooSmall", code: "planTooSmall", setUp: (fake) => (fake.plan = "free"), params: { block: [ban1] } },
      {
        name: "capExceeded",
        code: "capExceeded",
        setUp: (fake) => fake.customRules?.push(...agencyRules(11)),
        params: { block: [ban1] },
      },
      {
        name: "invalid",
        code: "invalid",
        setUp: () => undefined,
        params: {
          block: [{ key: "heavy", hosts: ["a.example.com"], ips: Array.from({ length: 100 }, (_, i) => `2001:db8:a${i}:bbbb:cccc:dddd:eeee:fffe/127`), uas: [] }],
        },
      },
      { name: "cloudflare", code: "cloudflare", setUp: (fake) => (fake.failRead = "custom"), params: { block: [ban1] } },
      {
        name: "writeFailed",
        code: "writeFailed",
        setUp: (fake) => (fake.failWrite = (write) => write.phase === "custom"),
        params: { block: [ban1] },
      },
    ];
    for (const testCase of cases) {
      const fake = new FakeCloudflare(baselineRulesInOrder());
      fake.rateLimitRules = [enabledRateLimitRule("rl1")];
      testCase.setUp(fake);
      fake.install();
      const result = await actuateWafEdgeSync(validParams({ ...testCase.params, rateLimit: { enabled: false } }), envWithToken());
      expect(result, testCase.name).toMatchObject({ ok: false, code: testCase.code });
      expect(result.rateLimit, testCase.name).toMatchObject({ ok: true, patched: [RATE_LIMIT_ORIGIN_DESCRIPTION] });
      expect(fake.rateLimitRules?.[0]?.enabled, testCase.name).toBe(false);
      // The custom phase is written only by the writeFailed case's refused write: nothing landed.
      expect(fake.writes.filter((write) => write.phase === "custom"), testCase.name).toEqual([]);
      vi.restoreAllMocks();
    }
  });

  // Finding 4 (probe scenarioRateLimitDisableWithPlanInvalidThresholds).
  it("enabled:false switches our rate-limit rules off even when its thresholds would not build for the plan", async () => {
    const fake = new FakeCloudflare(baselineRulesInOrder());
    fake.rateLimitRules = [enabledRateLimitRule("rl1")];
    fake.install();
    const tooLong = { requests: 100, periodSeconds: 60, mitigationSeconds: 86400 };
    const result = await actuateWafEdgeSync(validParams({ rateLimit: { enabled: false, origin: tooLong, expensive: tooLong } }), envWithToken());
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    expect(fake.rateLimitRules?.[0]?.enabled).toBe(false);
    expect(result.rateLimit).toMatchObject({ ok: false, code: "invalid", patched: [RATE_LIMIT_ORIGIN_DESCRIPTION], created: [] });
    expect(result.rateLimit.detail).toContain("switched off all the same");
    // The same thresholds with enabled:true refuse the rate-limit part, writing nothing there.
    fake.writes = [];
    const enable = await actuateWafEdgeSync(validParams({ rateLimit: { enabled: true, origin: tooLong, expensive: tooLong } }), envWithToken());
    if (!enable.ok) throw new Error(`${enable.code}: ${enable.detail}`);
    expect(enable.rateLimit).toMatchObject({ ok: false, code: "invalid", created: [], patched: [] });
    expect(fake.writes).toEqual([]);
  });

  // Finding 8: lease hygiene.
  it("releases the lease when the run throws", async () => {
    const leases = new FakeLeaseNamespace();
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      // A response whose status cannot be read: an unexpected throw inside the run.
      return {
        get status(): number {
          throw new Error("unexpected failure inside the run");
        },
      } as unknown as Response;
    });
    await expect(actuateWafEdgeSync(validParams(), envWithToken(leases))).rejects.toThrow("unexpected failure inside the run");
    expect(leases.leases.size).toBe(0);
  });

  it("a failed lease release never loses the run's result: it is logged, and the lease expires on its own", async () => {
    const leases = new FakeLeaseNamespace();
    const brokenRelease = {
      idFromName: (name: string) => leases.idFromName(name),
      get: (instance: string) => ({
        acquireLease: leases.get(instance).acquireLease,
        releaseLease: async (): Promise<void> => {
          throw new Error("Durable Object reset");
        },
      }),
    };
    const fake = new FakeCloudflare(baselineRulesInOrder()).install();
    const logged = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const env = { CF_DNS_API_TOKEN: TOKEN, NONCE_STORE: brokenRelease } as unknown as Env;
    const result = await actuateWafEdgeSync(validParams({ block: [ban1] }), env);
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    expect(result.created).toEqual(["doubleyoup-edge-block:1"]);
    expect(writeLog(fake)).toEqual(["POST doubleyoup-edge-block:1"]);
    expect(logged).toHaveBeenCalledTimes(1);
    expect(String(logged.mock.calls[0]?.[0])).toContain(ZONE);
    expect(String(logged.mock.calls[0]?.[0])).toContain("Durable Object reset");
  });

  // Finding 9.
  it("reports the Managed Ruleset status, with waf-rule-upsert's values", async () => {
    const fake = new FakeCloudflare(baselineRulesInOrder()).install();
    const withManaged = { baseline: { ...(rawParams().baseline as object), includeManagedRuleset: true } };
    const first = await actuateWafEdgeSync(validParams(withManaged), envWithToken());
    const second = await actuateWafEdgeSync(validParams(withManaged), envWithToken());
    const rollback = await actuateWafEdgeSync(
      validParams({ baseline: { ...(rawParams().baseline as object), enabled: false, includeManagedRuleset: true } }),
      envWithToken(),
    );
    const without = await actuateWafEdgeSync(validParams(), envWithToken());
    const statuses = [first, second, rollback, without].map((result) => (result.ok ? result.managedRuleset : result.code));
    expect(statuses).toEqual(["deployed", "already-deployed", "disabled", "not-requested"]);
    expect(fake.managedRules?.[0]).toMatchObject({ description: MANAGED_RULESET_RULE_DESCRIPTION, enabled: false });
    vi.restoreAllMocks();

    // Re-review probe F8: another owner's switched-off execute rule is left off and reported.
    const handManaged = new FakeCloudflare(baselineRulesInOrder());
    handManaged.managedRules = [
      { id: "m9", description: "hand managed", expression: "true", action: "execute", action_parameters: { id: CLOUDFLARE_MANAGED_RULESET_ID }, enabled: false },
    ];
    handManaged.install();
    const theirs = await actuateWafEdgeSync(validParams(withManaged), envWithToken());
    expect(theirs).toMatchObject({ ok: true, managedRuleset: "present-disabled" });
    expect(handManaged.writes).toEqual([]);
  });

  // Finding 12 is in "accepts only CANONICAL IP values". The probe's User-Agent round trip:
  it("a User-Agent with parentheses, braces or ' or ' survives a chunk round trip; one with a quote is refused", () => {
    expect(edgeUserAgentReason('abc" or true or "')).not.toBeNull();
    expect(edgeUserAgentReason("a}) or (true")).toBeNull();
    const built = buildEdgeClauses(
      [
        { hosts: ["a.example.com"], ips: [], uas: ["foo) or (bar", "a}) or (true"], all: false },
        { hosts: [], ips: ["192.0.2.4"], uas: [], all: false },
      ],
      EXCLUDED_HOSTS,
    );
    if (!built.ok) throw new Error(built.reason);
    const expression = joinChunkClauses(built.clauses);
    expect(splitChunkExpression(expression)).toEqual(built.clauses);
    expect(chunkClausesForPlanning(expression, built.clauses)).toEqual({ clauses: built.clauses, canonical: true });
  });

  // Finding 13.
  it("a hand-edited chunk that does not parse into our clauses is rewritten in ONE patch to canonical clauses only", async () => {
    const wanted = siteIpClause("192.0.2.7", ["a.example.com"]);
    const handEdits = [
      // A raw string: its backslash is literal, but the splitter reads it as an escape.
      `http.request.uri.path contains r"C:\\" or ${wanted}`,
      // An escaped quote inside a normal string: splits, but the piece is not one of ours.
      `(http.user_agent contains "x\\" or y" and lower(http.host) in {"a.example.com"}) or ${wanted}`,
      // One of ours next to a piece that is not.
      `${wanted} or (ip.src in {198.51.100.1})`,
    ];
    for (const handEdit of handEdits) {
      const handEdited: FakeRule = { id: "c1", description: "doubleyoup-edge-block:1", expression: handEdit, action: "block", enabled: true };
      const startRules = [handEdited, ...baselineRulesInOrder()];
      const fake = new FakeCloudflare(startRules).install();
      const result = await actuateWafEdgeSync(validParams({ block: [ban1] }), envWithToken());
      if (!result.ok) throw new Error(`${handEdit}: ${result.code}: ${result.detail}`);
      expect(fake.writes, handEdit).toHaveLength(1);
      expect(fake.writes[0], handEdit).toMatchObject({ method: "PATCH", ruleId: "c1" });
      expect(fake.writes[0]?.body?.expression, handEdit).toBe(joinChunkClauses([wanted]));
      // The wanted clause is in the chunk before and after the patch.
      for (const state of [startRules, ...fake.snapshots]) {
        expect(state.find((rule) => rule.id === "c1")?.expression, handEdit).toContain(wanted);
      }
      fake.writes = [];
      expect((await actuateWafEdgeSync(validParams({ block: [ban1] }), envWithToken())).ok).toBe(true);
      expect(fake.writes, handEdit).toEqual([]);
      vi.restoreAllMocks();
    }

    // A hand-edited chunk that also GAINS a clause: still one patch, and only canonical clauses.
    const gaining: FakeRule = { id: "c1", description: "doubleyoup-edge-block:1", expression: handEdits[0] as string, action: "block", enabled: true };
    const fake = new FakeCloudflare([gaining, ...baselineRulesInOrder()]).install();
    const gained = await actuateWafEdgeSync(validParams({ block: [ban1, ban2] }), envWithToken());
    if (!gained.ok) throw new Error(`${gained.code}: ${gained.detail}`);
    expect(writeLog(fake)).toEqual(["PATCH doubleyoup-edge-block:1"]);
    expect(fake.writes[0]?.body?.expression).toBe(joinChunkClauses([wanted, siteIpClause("192.0.2.8", ["a.example.com"])]));
    vi.restoreAllMocks();

    // Re-review probe F13: a raw string whose quote the splitter misreads, with a gained clause.
    const shopWanted = siteIpClause("192.0.2.1", ["shop.example.org"]);
    const shopGained = siteIpClause("192.0.2.2", ["shop.example.org"]);
    const misread = `${shopWanted} or http.user_agent contains r"a\\" or http.host eq "b or c"`;
    expect(splitChunkExpression(misread).length).toBeGreaterThan(2); // the splitter is fooled
    const misreadZone = new FakeCloudflare([
      { id: "c1", description: "doubleyoup-edge-block:1", expression: misread, action: "block", enabled: true },
      ...baselineRulesInOrder(),
    ]).install();
    const shopBans = [
      { key: "b1", hosts: ["shop.example.org"], ips: ["192.0.2.1"], uas: [] },
      { key: "b2", hosts: ["shop.example.org"], ips: ["192.0.2.2"], uas: [] },
    ];
    const rewritten = await actuateWafEdgeSync(validParams({ block: shopBans }), envWithToken());
    if (!rewritten.ok) throw new Error(`${rewritten.code}: ${rewritten.detail}`);
    expect(writeLog(misreadZone)).toEqual(["PATCH doubleyoup-edge-block:1"]);
    expect(misreadZone.writes[0]?.body?.expression).toBe(joinChunkClauses([shopWanted, shopGained]));
  });
});

// ── the A10 re-review: R1, R4, R5, the lease against the dispatch timeout ──────────────

describe("waf-edge-sync: A10 re-review (probe3 and probe4)", () => {
  const shopBan = (ip: string) => ({ key: `ban${ip.replaceAll(".", "")}`, hosts: ["shop.example.org"], ips: [ip], uas: [] });
  const shopClause = (ip: string) => siteIpClause(ip, ["shop.example.org"]);
  const ourManagedRule = (): FakeRule => ({
    id: "m1",
    description: MANAGED_RULESET_RULE_DESCRIPTION,
    expression: "true",
    action: "execute",
    action_parameters: { id: CLOUDFLARE_MANAGED_RULESET_ID },
    enabled: true,
  });

  /** True when an ENABLED chunk in `rules` carries `clause` as one of our canonical clauses. */
  function clauseInForce(rules: FakeRule[], clause: string): boolean {
    return rules.some((rule) => {
      if (!(rule.description ?? "").startsWith("doubleyoup-edge-") || rule.enabled === false) return false;
      const content = chunkClausesForPlanning(rule.expression ?? "", [clause]);
      return content.canonical && content.clauses.includes(clause);
    });
  }

  // R1 (probe3 N1).
  it("R1: on Free, an expired ban is removed although the job includes the Managed Ruleset (unavailable-on-plan, rule untouched)", async () => {
    for (const plan of ["free", null]) {
      const chunk = { id: "c1", ...buildEdgeChunkRule("block", 1, [shopClause("192.0.2.1")]) } as FakeRule;
      const fake = new FakeCloudflare([chunk, ...baselineRulesInOrder()]);
      fake.plan = plan;
      fake.managedRules = [ourManagedRule()];
      fake.install();
      const result = await actuateWafEdgeSync(
        validParams({ block: [], baseline: { ...(rawParams().baseline as object), includeManagedRuleset: true } }),
        envWithToken(),
      );
      if (!result.ok) throw new Error(`${String(plan)}: ${result.code}: ${result.detail}`);
      expect(result.managedRuleset).toBe("unavailable-on-plan");
      expect(fake.customDescriptions()).not.toContain("doubleyoup-edge-block:1");
      expect(writeLog(fake)).toEqual(["DELETE doubleyoup-edge-block:1"]);
      // The managed phase is not even read; our deployed rule stays exactly as it was.
      expect(fake.requests.some((request) => request.includes("http_request_firewall_managed"))).toBe(false);
      expect(fake.managedRules).toEqual([ourManagedRule()]);
      vi.restoreAllMocks();
    }
  });

  // R4 (probe3 N3).
  it("R4: on Free, a switched-off chunk that only loses a clause is rewritten (switched back on, never grown)", async () => {
    const chunk = { id: "c1", ...buildEdgeChunkRule("block", 1, [shopClause("192.0.2.1"), shopClause("192.0.2.2")]), enabled: false } as FakeRule;
    const fake = new FakeCloudflare([chunk, ...baselineRulesInOrder()]);
    fake.plan = "free";
    fake.install();
    const result = await actuateWafEdgeSync(validParams({ block: [shopBan("192.0.2.1")] }), envWithToken());
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    expect(writeLog(fake)).toEqual(["PATCH doubleyoup-edge-block:1"]);
    expect(fake.customRules?.[0]).toMatchObject({ id: "c1", expression: joinChunkClauses([shopClause("192.0.2.1")]), enabled: true });
  });

  it("R4: on Free, a change to the agent skip does not block an expired-ban removal in the same run", async () => {
    const chunk = { id: "c1", ...buildEdgeChunkRule("block", 1, [shopClause("192.0.2.1"), shopClause("192.0.2.2")]) } as FakeRule;
    const fake = new FakeCloudflare([chunk, ...baselineRulesInOrder()]);
    fake.plan = "free";
    fake.install();
    // A second agent host changes ONLY the skip (every agent host is already an excluded host).
    const wider = { ...(rawParams().baseline as object), agentHosts: [...EXCLUDED_HOSTS] };
    const result = await actuateWafEdgeSync(validParams({ block: [shopBan("192.0.2.1")], baseline: wider }), envWithToken());
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    expect([...writeLog(fake)].sort()).toEqual(["PATCH doubleyoup-edge-block:1", `PATCH ${WAF_EXEC_SKIP_DESCRIPTION}`].sort());
    expect(fake.customRules?.[0]?.expression).toBe(joinChunkClauses([shopClause("192.0.2.1")]));
  });

  // probe3 N2.
  it("on Free, an expired-ban removal that also MOVES our rules back into order is allowed (a move adds nothing)", async () => {
    const chunk = { id: "c1", ...buildEdgeChunkRule("block", 1, [shopClause("192.0.2.1"), shopClause("192.0.2.2")]) } as FakeRule;
    const baseline = baselineRulesInOrder();
    const outOfOrder = [baseline[3], baseline[0], baseline[1], baseline[2], chunk, baseline[4], baseline[5]] as FakeRule[];
    const fake = new FakeCloudflare(outOfOrder);
    fake.plan = "free";
    fake.install();
    const result = await actuateWafEdgeSync(validParams({ block: [shopBan("192.0.2.1")] }), envWithToken());
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    expect(fake.writes.filter((write) => write.method === "POST")).toEqual([]);
    expect(fake.customDescriptions()).toEqual([
      "doubleyoup-edge-block:1",
      WAF_COUNTRY_BLOCK_DESCRIPTION,
      WAF_WPADMIN_GEO_DESCRIPTION,
      WAF_XMLRPC_DESCRIPTION,
      WAF_LOGIN_GATE_DESCRIPTION,
      WAF_FRONTEND_GEO_DESCRIPTION,
      WAF_EXEC_SKIP_DESCRIPTION,
    ]);
  });

  // probe3 N4.
  it("a duplicated baseline rule whose LOWER copy is off and edited: the lower copy is repaired before the live copy goes", async () => {
    const baseline = baselineRulesInOrder();
    const frontend = baseline[4] as FakeRule;
    const editedLow: FakeRule = { ...frontend, id: "fg-low", enabled: false, expression: `${frontend.expression ?? ""} and http.host eq "x.example.com"` };
    const startRules = [baseline[0], baseline[1], baseline[2], baseline[3], editedLow, { ...frontend, id: "fg-high" }, baseline[5]] as FakeRule[];
    const fake = new FakeCloudflare(startRules).install();
    const result = await actuateWafEdgeSync(validParams(), envWithToken());
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    const copies = (fake.customRules ?? []).filter((rule) => rule.description === WAF_FRONTEND_GEO_DESCRIPTION);
    expect(copies.map((rule) => rule.id)).toEqual(["fg-low"]);
    expect(copies[0]).toMatchObject(baselineBodies().frontend);
    // An enabled, canonical frontend geo rule is in force at every step.
    for (const state of [startRules, ...fake.snapshots]) {
      const live = state.some(
        (rule) => rule.description === WAF_FRONTEND_GEO_DESCRIPTION && rule.enabled !== false && rule.expression === frontend.expression,
      );
      expect(live).toBe(true);
    }
  });

  // probe3 N5.
  it("a broken chunk holding a wanted clause only inside not(...): the clause stays in force at every step", async () => {
    const wanted = shopClause("192.0.2.1");
    const broken: FakeRule = { id: "c1", description: "doubleyoup-edge-block:1", expression: `not ${wanted} and ip.src in {192.0.2.99}`, action: "block", enabled: true };
    const good = { id: "c2", ...buildEdgeChunkRule("block", 2, [wanted]) } as FakeRule;
    const startRules = [broken, good, ...baselineRulesInOrder()];
    const fake = new FakeCloudflare(startRules).install();
    const result = await actuateWafEdgeSync(validParams({ block: [shopBan("192.0.2.1")] }), envWithToken());
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    for (const state of [startRules, ...fake.snapshots]) expect(clauseInForce(state, wanted)).toBe(true);
    const chunks = (fake.customRules ?? []).filter((rule) => (rule.description ?? "").startsWith("doubleyoup-edge-block:"));
    expect(chunks).toHaveLength(1);
    expect(chunks[0]?.expression).toBe(joinChunkClauses([wanted]));
  });

  // probe3 N6: pins the A10 decision that a duplicate counts as a rule in the zone.
  it("a duplicate counts as a rule in the zone: replacing it with a needed chunk keeps the count, so only the peak applies", async () => {
    const wanted = shopClause("192.0.2.1");
    const chunk = { id: "c1", ...buildEdgeChunkRule("block", 1, [wanted]) } as FakeRule;
    const duplicate = { id: "c1dup", ...buildEdgeChunkRule("block", 1, [wanted]) } as FakeRule;
    const foreign: FakeRule[] = Array.from({ length: 10 }, (_, index) => ({
      id: `f${index}`,
      description: `agency-rule-${index}`,
      expression: "true",
      action: "log",
      enabled: true,
    }));
    // 18 rules, one above cap − reservedSlots (17). The run creates a challenge chunk and deletes the duplicate.
    const fake = new FakeCloudflare([chunk, duplicate, ...baselineRulesInOrder(), ...foreign]).install();
    const result = await actuateWafEdgeSync(
      validParams({ block: [shopBan("192.0.2.1")], challenge: [{ key: "u1", hosts: ["shop.example.org"], ips: [], uas: [], all: true }] }),
      envWithToken(),
    );
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    expect(fake.customRules).toHaveLength(18);
    expect(result.created).toEqual(["doubleyoup-edge-challenge:1"]);
    expect(result.deleted).toEqual(["doubleyoup-edge-block:1"]);
  });

  // R5.
  it("R5: the rate-limit capExceeded detail states what the custom part did", async () => {
    const thresholds = { requests: 600, periodSeconds: 60, mitigationSeconds: 600 };
    const rateLimitOn = { enabled: true, origin: thresholds, expensive: thresholds };
    const foreignRateLimit: FakeRule = {
      id: "rl-agency",
      description: "agency-api-limit",
      expression: 'starts_with(http.request.uri.path, "/api/")',
      action: "managed_challenge",
      ratelimit: { characteristics: ["cf.colo.id", "ip.src"], period: 10, requests_per_period: 50, mitigation_timeout: 0 },
      enabled: true,
    };
    const applied = new FakeCloudflare(baselineRulesInOrder());
    applied.rateLimitRules = [foreignRateLimit];
    applied.install();
    const afterApply = await actuateWafEdgeSync(validParams({ rateLimit: rateLimitOn }), envWithToken());
    expect(afterApply).toMatchObject({ ok: true, rateLimit: { ok: false, code: "capExceeded" } });
    expect(afterApply.rateLimit?.detail).toContain("The custom rules were applied.");
    vi.restoreAllMocks();

    const refused = new FakeCloudflare([...baselineRulesInOrder(), ...Array.from({ length: 12 }, (_, index) => ({
      id: `f${index}`,
      description: `agency-rule-${index}`,
      expression: "true",
      action: "log",
      enabled: true,
    }))]);
    refused.rateLimitRules = [foreignRateLimit];
    refused.install();
    const afterRefusal = await actuateWafEdgeSync(validParams({ block: [shopBan("192.0.2.1")], rateLimit: rateLimitOn }), envWithToken());
    expect(afterRefusal).toMatchObject({ ok: false, code: "capExceeded", rateLimit: { ok: false, code: "capExceeded" } });
    expect(afterRefusal.rateLimit?.detail).toContain("The custom part refused (capExceeded) and wrote nothing.");
    expect(afterRefusal.rateLimit?.detail).not.toContain("were applied");
    vi.restoreAllMocks();

    const failed = new FakeCloudflare(baselineRulesInOrder());
    failed.rateLimitRules = [foreignRateLimit];
    failed.failWrite = (write) => write.phase === "custom";
    failed.install();
    const afterFailure = await actuateWafEdgeSync(validParams({ block: [shopBan("192.0.2.1")], rateLimit: rateLimitOn }), envWithToken());
    expect(afterFailure).toMatchObject({ ok: false, code: "writeFailed" });
    expect(afterFailure.rateLimit?.detail).toContain("(writeFailed)");
    expect(afterFailure.rateLimit?.detail).not.toContain("were applied");
  });

  // The lease against the dispatcher.
  it("the lease outlasts a whole dispatch attempt: TTL >= 2 x the orchestrator's 120 s waf-edge-sync timeout", () => {
    // Mirrors EDGE_SYNC_DISPATCH_OPTIONS.timeoutMs in the orchestrator (src/handlers/edge-sync.ts).
    // Raising that timeout means raising EDGE_SYNC_LEASE_TTL_MS with it (see their comments).
    expect(EDGE_SYNC_DISPATCH_TIMEOUT_MS).toBe(120_000);
    expect(EDGE_SYNC_LEASE_TTL_MS).toBeGreaterThanOrEqual(2 * EDGE_SYNC_DISPATCH_TIMEOUT_MS);
  });
});

// ── waf-rule-upsert is unchanged by the run limits (byte for byte) ────────────────────

/** Every fetch the spied `fetch` saw, as text: method, URL, headers, body and the init's keys. */
function fetchTranscript(): string {
  const lines: string[] = [];
  for (const [input, init] of vi.mocked(globalThis.fetch).mock.calls) {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const requestInit = (init ?? {}) as RequestInit;
    lines.push(
      [
        `${requestInit.method ?? "GET"} ${url}`,
        JSON.stringify(requestInit.headers ?? null),
        String(requestInit.body ?? ""),
        `init keys: ${Object.keys(requestInit).join(",")}`,
      ].join("\n"),
    );
  }
  return lines.join("\n---\n");
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("waf-rule-upsert: unchanged by the waf-edge-sync run limits", () => {
  it("sends byte-for-byte the requests it sent before (no signal, same bodies), on create, drift, rollback and the Managed Ruleset", async () => {
    const upsertParams = { zone: ZONE, enabled: true, excludedHosts: EXCLUDED_HOSTS, agentHosts: AGENT_HOSTS, includeManagedRuleset: true };
    const transcripts: string[] = [];

    // A fresh zone: the entrypoint is created with the five rules, then the Managed Ruleset.
    const fresh = new FakeCloudflare(null).install();
    expect((await actuateWafRuleUpsert(upsertParams, envWithToken())).ok).toBe(true);
    transcripts.push(fetchTranscript());
    vi.restoreAllMocks();

    // Drift and a missing rule: one PATCH, one POST; our Managed Ruleset rule already on.
    const drifted = (fresh.customRules ?? [])
      .filter((rule) => rule.description !== WAF_FRONTEND_GEO_DESCRIPTION)
      .map((rule) => (rule.description === WAF_LOGIN_GATE_DESCRIPTION ? { ...rule, enabled: false } : rule));
    const second = new FakeCloudflare(drifted);
    second.managedRules = cloneRules(fresh.managedRules ?? []);
    second.install();
    expect((await actuateWafRuleUpsert(upsertParams, envWithToken())).ok).toBe(true);
    transcripts.push(fetchTranscript());
    vi.restoreAllMocks();

    // A rollback: every rule switched off, the Managed Ruleset rule disabled.
    const third = new FakeCloudflare(second.customRules);
    third.managedRules = cloneRules(second.managedRules ?? []);
    third.install();
    expect((await actuateWafRuleUpsert({ ...upsertParams, enabled: false }, envWithToken())).ok).toBe(true);
    transcripts.push(fetchTranscript());

    // The three runs did what they are for (so the recorded transcript is not trivially empty).
    expect(transcripts[0]?.match(/^POST /gm)).toHaveLength(6);
    expect(transcripts[1]?.match(/^PATCH /gm)).toHaveLength(1);
    expect(transcripts[1]?.match(/^POST /gm)).toHaveLength(1);
    expect(transcripts[2]?.match(/^PATCH /gm)).toHaveLength(4);
    const transcript = transcripts.join("\n=====\n");
    expect(transcript).not.toContain("signal");
    // Recorded from the code before the run limits existed (commit 910cc49).
    expect(await sha256Hex(transcript)).toBe("dfcb51fa72090f8504d432d919bf97696d48d11a524f1c92cc1cb0c9a70bbbf5");
  });
});

// ── the run limits: wall time and subrequests ─────────────────────────────────────────

describe("waf-edge-sync: run limits (deadline, request timeout, subrequest budget)", () => {
  // Measured by the test below (fake Cloudflare; nonce + lease + every Cloudflare call).
  const MEASURED_PRO_WORST = { mixed: { needed: 44, runs: 1 }, "all chunks": { needed: 62, runs: 2 } };
  const THRESHOLDS = { requests: 600, periodSeconds: 60, mitigationSeconds: 600 };
  const RATE_LIMIT_ON = { enabled: true, origin: THRESHOLDS, expensive: THRESHOLDS };
  const MANAGED_ON = { ...(rawParams().baseline as object), includeManagedRuleset: true };

  /** `count` bans, one IP each, on one site: `ipBase.0` … */
  function bans(count: number, prefix = "198.51.100"): Array<{ key: string; hosts: string[]; ips: string[]; uas: string[] }> {
    return Array.from({ length: count }, (_, index) => ({ key: `ban${index}`, hosts: ["shop.example.org"], ips: [`${prefix}.${index}`], uas: [] }));
  }

  /** The limits of a test run: the defaults, the fake's clock, and any override. */
  function testLimits(fake: FakeCloudflare, overrides: Partial<EdgeSyncRunLimits> = {}): EdgeSyncRunLimits {
    return { ...EDGE_SYNC_RUN_LIMITS, now: () => fake.clockMs, ...overrides };
  }

  /** Every subrequest of one invocation: the nonce consume, the lease calls, the Cloudflare calls. */
  function subrequestsOf(fake: FakeCloudflare, leases: FakeLeaseNamespace): number {
    return EDGE_SYNC_SUBREQUESTS_BEFORE_ACTUATION + leases.acquires.length + leases.releases + fake.requests.length;
  }

  /** Every clause of an ENABLED edge chunk, as our canonical clauses. */
  function clausesInForce(rules: FakeRule[]): Set<string> {
    const inForce = new Set<string>();
    for (const rule of rules) {
      if (!(rule.description ?? "").startsWith("doubleyoup-edge-") || rule.enabled === false) continue;
      for (const clause of splitChunkExpression(rule.expression ?? "")) inForce.add(clause);
    }
    return inForce;
  }

  it("pins the limits: deadline < dispatch timeout < lease / 2, and a request timeout well inside the deadline", () => {
    expect(EDGE_SYNC_RUN_DEADLINE_MS).toBe(100_000);
    // The custom part's calls end by 55 s, leaving the rate-limit part its read and two writes at
    // their full 15 s timeouts: 55 + 3 × 15 ≤ 100.
    const customPartEndsByMs = EDGE_SYNC_RUN_DEADLINE_MS - EDGE_SYNC_RATE_LIMIT_RESERVE * EDGE_SYNC_REQUEST_TIMEOUT_MS;
    expect(customPartEndsByMs).toBe(55_000);
    expect(EDGE_SYNC_RATE_LIMIT_RESERVE).toBe(3);
    expect(EDGE_SYNC_REQUEST_TIMEOUT_MS).toBe(15_000);
    expect(55_000 + EDGE_SYNC_RATE_LIMIT_RESERVE * EDGE_SYNC_REQUEST_TIMEOUT_MS).toBeLessThanOrEqual(EDGE_SYNC_RUN_DEADLINE_MS);
    expect(EDGE_SYNC_RUN_DEADLINE_MS).toBeLessThan(EDGE_SYNC_DISPATCH_TIMEOUT_MS);
    expect(EDGE_SYNC_DISPATCH_TIMEOUT_MS).toBeLessThan(EDGE_SYNC_LEASE_TTL_MS / 2);
    expect(EDGE_SYNC_REQUEST_TIMEOUT_MS).toBeLessThanOrEqual(EDGE_SYNC_RUN_DEADLINE_MS / 4);
    expect(EDGE_SYNC_SUBREQUEST_BUDGET).toBe(45);
    expect(EDGE_SYNC_RUN_LIMITS).toMatchObject({
      subrequestBudget: EDGE_SYNC_SUBREQUEST_BUDGET,
      runDeadlineMs: EDGE_SYNC_RUN_DEADLINE_MS,
      requestTimeoutMs: EDGE_SYNC_REQUEST_TIMEOUT_MS,
    });
  });

  it("gives EVERY Cloudflare call of a run a timeout signal (custom, managed and rate-limit phases)", async () => {
    const fake = new FakeCloudflare(agencyRulesOnly());
    fake.rateLimitRules = [];
    fake.install();
    const result = await actuateWafEdgeSync(validParams({ block: bans(2), baseline: MANAGED_ON, rateLimit: RATE_LIMIT_ON }), envWithToken());
    if (!result.ok) throw new Error(`${result.code}: ${result.detail}`);
    expect(fake.requests.some((request) => request.includes("http_request_firewall_managed"))).toBe(true);
    expect(fake.requests.some((request) => request.includes("rs-ratelimit"))).toBe(true);
    expect(fake.signals.length).toBe(fake.requests.length);
    expect(fake.signals.every((carried) => carried)).toBe(true);
  });

  it("measures the subrequests of typical runs (all within the budget in ONE invocation)", async () => {
    const measured: Record<string, number> = {};
    const scenarios: Array<{ name: string; rules: FakeRule[] | null; rateLimitRules: FakeRule[] | null; params: WafEdgeSyncParams }> = [
      {
        name: "fresh zone: 6 baseline + 2 chunks + Managed Ruleset + rate limit",
        rules: null,
        rateLimitRules: null,
        params: validParams({ block: bans(2), challenge: [{ key: "ua1", hosts: ["shop.example.org"], ips: [], uas: [], all: true }], baseline: MANAGED_ON, rateLimit: RATE_LIMIT_ON }),
      },
      {
        name: "agency rules only: 6 baseline + 2 chunks created one by one + Managed Ruleset + rate limit",
        rules: agencyRulesOnly(),
        rateLimitRules: [],
        params: validParams({ block: bans(2), challenge: [{ key: "ua1", hosts: ["shop.example.org"], ips: [], uas: [], all: true }], baseline: MANAGED_ON, rateLimit: RATE_LIMIT_ON }),
      },
      {
        name: "steady state (nothing to write), Managed Ruleset + rate limit",
        rules: null,
        rateLimitRules: null,
        params: validParams({ block: bans(2), baseline: MANAGED_ON, rateLimit: RATE_LIMIT_ON }),
      },
    ];
    for (const scenario of scenarios) {
      const fake = new FakeCloudflare(scenario.rules);
      fake.rateLimitRules = scenario.rateLimitRules;
      fake.install();
      if (scenario.name.startsWith("steady")) {
        // Bring the zone to the state first, then measure the run that finds nothing to do.
        await actuateWafEdgeSync(scenario.params, envWithToken());
        fake.requests = [];
      }
      const leases = new FakeLeaseNamespace();
      const result = await actuateWafEdgeSync(scenario.params, envWithToken(leases));
      if (!result.ok) throw new Error(`${scenario.name}: ${result.code}: ${result.detail}`);
      expect(result.rateLimit.ok, scenario.name).toBe(true);
      measured[scenario.name] = subrequestsOf(fake, leases);
      vi.restoreAllMocks();
    }
    expect(measured).toEqual({
      "fresh zone: 6 baseline + 2 chunks + Managed Ruleset + rate limit": 10,
      "agency rules only: 6 baseline + 2 chunks created one by one + Managed Ruleset + rate limit": 18,
      "steady state (nothing to write), Managed Ruleset + rate limit": 7,
    });
  });

  it("measures Pro zones at their cap with every kind of write: what one run would need, and the runs it takes at 45", async () => {
    // Clauses sized so each chunk has room for exactly one newcomer: every chunk gains one ban and
    // loses one (two writes), then moves (a third).
    const keptHosts = (number: number) => longHosts(`k${number}`, 4);
    const lostHosts = (number: number) => longHosts(`l${number}`, 4);
    const newHosts = (number: number) => longHosts(`n${number}`, 9);
    function reversedChunks(count: number): FakeRule[] {
      const chunks: FakeRule[] = [];
      for (let number = count; number >= 1; number -= 1) {
        const clauses = [siteIpClause(`192.0.2.${number}`, keptHosts(number)), siteIpClause(`192.0.2.${number + 100}`, lostHosts(number))];
        chunks.push({ id: `c${number}`, ...buildEdgeChunkRule("block", number, clauses) } as FakeRule);
      }
      return chunks;
    }
    function churnParams(count: number): WafEdgeSyncParams {
      const kept = Array.from({ length: count }, (_, index) => ({ key: `kept${index}`, hosts: keptHosts(index + 1), ips: [`192.0.2.${index + 1}`], uas: [] }));
      const arriving = Array.from({ length: count }, (_, index) => ({ key: `new${index}`, hosts: newHosts(index + 1), ips: [`192.0.2.${index + 201}`], uas: [] }));
      return validParams({ block: [...kept, ...arriving], baseline: MANAGED_ON, rateLimit: RATE_LIMIT_ON, retireLegacy: true });
    }
    const reversedOffBaseline = () => baselineRulesInOrder().map((rule) => ({ ...rule, enabled: false })).reverse();
    const legacy: FakeRule[] = Array.from({ length: 4 }, (_, index) => ({
      id: `l-${index}`,
      description: `doubleyoup-ban:old${index}`,
      expression: `ip.src in {198.51.100.${index}}`,
      action: "block",
      enabled: true,
    }));
    const scenarios: Array<{ name: string; zone: () => FakeRule[]; chunkCount: number }> = [
      {
        // The baseline off and reversed, 6 reversed chunks, 2 duplicate chunks, 4 legacy, 2 agency rules.
        name: "mixed",
        chunkCount: 6,
        zone: () => {
          const chunks = reversedChunks(6);
          const copies = [chunks[0], chunks[1]].map((chunk) => ({ ...(chunk as FakeRule), id: `${(chunk as FakeRule).id}-copy` }));
          const agency = [...agencyRulesOnly(), { ...(agencyRulesOnly()[0] as FakeRule), id: "f-two", description: "agency-two" }];
          return [...chunks, ...reversedOffBaseline(), ...copies, ...legacy, ...agency];
        },
      },
      // The most writes 20 rules can need: every slot but the baseline is a chunk that gains, loses and moves.
      { name: "all chunks", chunkCount: 14, zone: () => [...reversedChunks(14), ...reversedOffBaseline()] },
    ];
    const measured: Record<string, { needed: number; runs: number }> = {};
    for (const scenario of scenarios) {
      expect(scenario.zone(), scenario.name).toHaveLength(20);
      const params = churnParams(scenario.chunkCount);

      // With no budget to speak of: everything in one run.
      const unlimited = new FakeCloudflare(scenario.zone());
      unlimited.rateLimitRules = [];
      unlimited.install();
      const leases = new FakeLeaseNamespace();
      const oneRun = await actuateWafEdgeSync(params, envWithToken(leases), testLimits(unlimited, { subrequestBudget: 1000 }));
      if (!oneRun.ok) throw new Error(`${scenario.name}: ${oneRun.code}: ${oneRun.detail}`);
      const chunkContentPatches = unlimited.writes.filter(
        (write) => write.method === "PATCH" && write.description.startsWith("doubleyoup-edge-block:") && write.body?.position === undefined,
      );
      expect(chunkContentPatches, scenario.name).toHaveLength(2 * scenario.chunkCount);
      const needed = subrequestsOf(unlimited, leases);
      vi.restoreAllMocks();

      // At the default budget: as many runs as it takes, nothing lost on the way.
      const limited = new FakeCloudflare(scenario.zone());
      limited.rateLimitRules = [];
      limited.install();
      const wanted = new Set(params.block.map((entry) => siteIpClause(entry.ips[0] as string, entry.hosts)));
      const outcomes = await convergeWithInvariants(limited, params, wanted, EDGE_SYNC_SUBREQUEST_BUDGET);
      measured[scenario.name] = { needed, runs: outcomes.length };
      vi.restoreAllMocks();
    }
    expect(measured).toEqual(MEASURED_PRO_WORST);
  });

  it("stops before the next write when the subrequest budget is reached; landed is exact and the next run continues", async () => {
    const fake = new FakeCloudflare(agencyRulesOnly()).install();
    const params = validParams({ block: bans(2) });
    // 3 (nonce + lease) + zone + read = 5; 3 held for the rate-limit part: 4 creates fit in 12.
    const leases = new FakeLeaseNamespace();
    const first = await actuateWafEdgeSync(params, envWithToken(leases), testLimits(fake, { subrequestBudget: 12 }));
    expect(first).toMatchObject({ ok: false, code: "writeFailed" });
    if (first.ok || first.code !== "writeFailed") throw new Error("expected writeFailed");
    expect(first.detail.startsWith(`${EDGE_SYNC_BUDGET_REACHED}. Stopped before: create rule`)).toBe(true);
    const createsThatLanded = fake.writes.filter((write) => write.method === "POST").map((write) => write.description);
    expect(createsThatLanded).toHaveLength(4);
    expect(first.landed).toEqual({ created: createsThatLanded, patched: [], deleted: [] });
    // The rate-limit part still ran on its reserve (one read: the job leaves rate limiting off).
    expect(first.rateLimit).toMatchObject({ ok: true });
    expect(subrequestsOf(fake, leases)).toBeLessThanOrEqual(12);

    // The next run continues from the zone's real state and finishes.
    const second = await actuateWafEdgeSync(params, envWithToken(), testLimits(fake, { subrequestBudget: 12 }));
    if (!second.ok) throw new Error(`${second.code}: ${second.detail}`);
    expect(fake.customDescriptions().filter((description) => description.startsWith("doubleyoup-"))).toEqual([
      "doubleyoup-edge-block:1",
      WAF_COUNTRY_BLOCK_DESCRIPTION,
      WAF_WPADMIN_GEO_DESCRIPTION,
      WAF_XMLRPC_DESCRIPTION,
      WAF_LOGIN_GATE_DESCRIPTION,
      WAF_FRONTEND_GEO_DESCRIPTION,
    ]);
  });

  it("stops the custom part's calls by 55 s, with what landed; the rate-limit part still runs; the next run continues", async () => {
    const fake = new FakeCloudflare(agencyRulesOnly());
    fake.msPerRequest = 10_000;
    fake.install();
    const params = validParams({ block: bans(2) });
    // Custom calls start at 0 s (zone), 10 s (read), 20, 30 and 40 s (creates, the last one ending by
    // 55 s). A create at 50 s could end at 65 s, inside the 45 s held for the rate-limit part: refused.
    const first = await actuateWafEdgeSync(params, envWithToken(), testLimits(fake));
    expect(first).toMatchObject({ ok: false, code: "writeFailed" });
    if (first.ok || first.code !== "writeFailed") throw new Error("expected writeFailed");
    expect(first.detail.startsWith(`${EDGE_SYNC_DEADLINE_REACHED}. Stopped before: create rule`)).toBe(true);
    const createsThatLanded = fake.writes.map((write) => write.description);
    expect(createsThatLanded).toHaveLength(3);
    expect(first.landed).toEqual({ created: createsThatLanded, patched: [], deleted: [] });
    // The rate-limit part runs on its own time, at 50 s: its read, and nothing to write.
    expect(first.rateLimit).toMatchObject({ ok: true });
    expect(fake.requests).toHaveLength(6);
    expect(fake.requests.at(-1)).toContain("http_ratelimit");

    fake.msPerRequest = 0;
    const second = await actuateWafEdgeSync(params, envWithToken(), testLimits(fake));
    expect(second.ok).toBe(true);
  });

  it("every call at its full 15 s timeout: the rate-limit switch-off still lands, and the 100 s deadline stops only the extra work", async () => {
    // Rate limiting on, with a later copy of our origin rule (left by overlapping runs).
    const fake = new FakeCloudflare(agencyRulesOnly());
    fake.rateLimitRules = [];
    fake.install();
    const enabled = await actuateWafEdgeSync(validParams({ rateLimit: RATE_LIMIT_ON }), envWithToken());
    if (!enabled.ok) throw new Error(`${enabled.code}: ${enabled.detail}`);
    const origin = fake.rateLimitRules.find((rule) => rule.description === RATE_LIMIT_ORIGIN_DESCRIPTION) as FakeRule;
    fake.rateLimitRules.push({ ...origin, id: "rl-later-copy" });
    fake.customRules = agencyRulesOnly();
    fake.writes = [];
    fake.requests = [];
    fake.msPerRequest = EDGE_SYNC_REQUEST_TIMEOUT_MS;

    // Rate limiting off, and a custom part with more work than its 55 s allow.
    const result = await actuateWafEdgeSync(validParams({ block: bans(2) }), envWithToken(), testLimits(fake));
    expect(result).toMatchObject({ ok: false, code: "writeFailed" });
    if (result.ok || result.code !== "writeFailed") throw new Error("expected writeFailed");
    // Custom: zone (0 s), read (15 s), one create (30 s); a create at 45 s could end at 60 s.
    expect(result.detail.startsWith(`${EDGE_SYNC_DEADLINE_REACHED}. Stopped before: create rule`)).toBe(true);
    expect(result.landed.created).toHaveLength(1);
    // Rate limit: read (45 s), both rules switched off (60 s, 75 s). The later copy's delete would
    // start at 90 s and could end after 100 s: stopped, for the next run.
    expect(fake.rateLimitRules.filter((rule) => rule.id !== "rl-later-copy").every((rule) => rule.enabled === false)).toBe(true);
    expect(result.rateLimit).toMatchObject({
      ok: false,
      code: "writeFailed",
      patched: [RATE_LIMIT_ORIGIN_DESCRIPTION, RATE_LIMIT_EXPENSIVE_DESCRIPTION],
      deleted: [],
    });
    expect(result.rateLimit?.detail).toBe(
      `${EDGE_SYNC_DEADLINE_REACHED}. Stopped before: delete a duplicate of rate-limit rule "${RATE_LIMIT_ORIGIN_DESCRIPTION}".`,
    );
    expect(fake.clockMs).toBe(6 * EDGE_SYNC_REQUEST_TIMEOUT_MS);

    fake.msPerRequest = 0;
    const second = await actuateWafEdgeSync(validParams({ block: bans(2) }), envWithToken(), testLimits(fake));
    expect(second.ok).toBe(true);
    expect(fake.rateLimitRules.map((rule) => rule.id)).not.toContain("rl-later-copy");
  });

  it("a write that hangs is cut by its timeout and reported UNKNOWN, kept out of landed; the next run continues", async () => {
    const UNKNOWN_TEXT = "UNKNOWN: Cloudflare did not answer in time; the write may or may not have landed; the next run re-reads the zone.";
    expect(EDGE_SYNC_WRITE_UNKNOWN).toBe(UNKNOWN_TEXT);
    const params = validParams({ block: bans(2), baseline: MANAGED_ON, rateLimit: RATE_LIMIT_ON });
    const scenarios: Array<{ name: string; hangs: (method: string, path: string) => boolean }> = [
      { name: "custom create", hangs: (method, path) => method === "POST" && path.endsWith("/rs-custom/rules") },
      { name: "Managed Ruleset create", hangs: (method, path) => method === "POST" && path.endsWith("/rs-managed/rules") },
      { name: "rate-limit create", hangs: (method, path) => method === "POST" && path.endsWith("/rs-ratelimit/rules") },
    ];
    for (const scenario of scenarios) {
      const fake = new FakeCloudflare(agencyRulesOnly());
      fake.managedRules = [];
      fake.rateLimitRules = [];
      let hungAlready = false;
      fake.hang = (method, path) => {
        if (hungAlready || !scenario.hangs(method, path)) return false;
        hungAlready = true;
        return true;
      };
      fake.install();
      const result = await actuateWafEdgeSync(params, envWithToken(), testLimits(fake, { requestTimeoutMs: 20 }));
      expect(hungAlready, scenario.name).toBe(true);
      const answeredWrites = fake.writes.filter((write) => write.phase !== "ratelimit").map((write) => write.description);
      if (scenario.name === "rate-limit create") {
        // The custom part finished; the rate-limit part reports the UNKNOWN write and lists none.
        if (!result.ok) throw new Error(`${scenario.name}: ${result.code}: ${result.detail}`);
        expect(result.rateLimit).toMatchObject({ ok: false, code: "writeFailed", created: [] });
        expect(result.rateLimit?.detail, scenario.name).toContain(UNKNOWN_TEXT);
      } else {
        expect(result, scenario.name).toMatchObject({ ok: false, code: "writeFailed" });
        if (result.ok || result.code !== "writeFailed") throw new Error("expected writeFailed");
        expect(result.detail, scenario.name).toContain(UNKNOWN_TEXT);
        // landed lists exactly the writes Cloudflare answered: the hung one is not among them.
        expect([...result.landed.created, ...result.landed.patched], scenario.name).toEqual(answeredWrites);
        expect(result.landed.created, scenario.name).not.toContain(MANAGED_RULESET_RULE_DESCRIPTION);
      }

      fake.hang = null;
      const second = await actuateWafEdgeSync(params, envWithToken(), testLimits(fake, { requestTimeoutMs: 20 }));
      if (!second.ok) throw new Error(`${scenario.name}, next run: ${second.code}: ${second.detail}`);
      expect(second.rateLimit.ok, scenario.name).toBe(true);
      vi.restoreAllMocks();
    }
  });

  it("wanted-ban gains and removals land before cosmetic moves: a tight budget defers only the moves", async () => {
    // Our rules out of order (login gate on top), one ban leaving chunk 1, one ban arriving.
    const leaving = siteIpClause("192.0.2.1", ["shop.example.org"]);
    const staying = siteIpClause("192.0.2.2", ["shop.example.org"]);
    const baseline = baselineRulesInOrder();
    const chunk = { id: "c1", ...buildEdgeChunkRule("block", 1, [leaving, staying]) } as FakeRule;
    const startRules = [baseline[3], baseline[0], baseline[1], baseline[2], chunk, baseline[4], baseline[5]] as FakeRule[];
    const fake = new FakeCloudflare(startRules).install();
    const params = validParams({
      block: [
        { key: "staying", hosts: ["shop.example.org"], ips: ["192.0.2.2"], uas: [] },
        { key: "arriving", hosts: ["shop.example.org"], ips: ["192.0.2.3"], uas: [] },
      ],
    });
    // 5 (nonce, lease, zone, read) + gain + lose = 7; 3 held for the rate-limit part => budget 10.
    const first = await actuateWafEdgeSync(params, envWithToken(), testLimits(fake, { subrequestBudget: 10 }));
    expect(first).toMatchObject({ ok: false, code: "writeFailed" });
    if (first.ok || first.code !== "writeFailed") throw new Error("expected writeFailed");
    expect(first.detail).toContain("Stopped before: move rule");
    expect(writeLog(fake)).toEqual(["PATCH doubleyoup-edge-block:1", "PATCH doubleyoup-edge-block:1"]);
    expect(fake.customRules?.find((rule) => rule.id === "c1")?.expression).toBe(
      joinChunkClauses([staying, siteIpClause("192.0.2.3", ["shop.example.org"])]),
    );

    fake.writes = [];
    const second = await actuateWafEdgeSync(params, envWithToken(), testLimits(fake));
    expect(second.ok).toBe(true);
    expect(fake.writes.every((write) => write.method === "PATCH" && write.body?.position !== undefined)).toBe(true);
    expect(fake.customDescriptions()[0]).toBe("doubleyoup-edge-block:1");
  });

  it("a full zone converges over several runs at the DEFAULT budget, never losing a wanted clause", async () => {
    // Business zone migrating from legacy: 30 legacy ban rules to retire, 30 bans to carry in chunks,
    // the baseline, the Managed Ruleset and rate limiting — more than one invocation can write.
    const legacy: FakeRule[] = Array.from({ length: 30 }, (_, index) => ({
      id: `l-${index}`,
      description: `doubleyoup-ban:old${index}`,
      expression: `ip.src in {198.51.100.${index}}`,
      action: "block",
      enabled: true,
    }));
    const fake = new FakeCloudflare([...legacy, ...agencyRulesOnly()]);
    fake.plan = "business";
    fake.rateLimitRules = [];
    fake.install();
    const params = validParams({ block: bans(30), baseline: MANAGED_ON, rateLimit: RATE_LIMIT_ON, retireLegacy: true });
    const wanted = new Set(params.block.map((entry) => siteIpClause(entry.ips[0] as string, entry.hosts)));
    const outcomes = await convergeWithInvariants(fake, params, wanted, EDGE_SYNC_SUBREQUEST_BUDGET);
    expect(outcomes.length).toBeGreaterThan(1);
    expect(fake.customDescriptions().filter((description) => description.startsWith("doubleyoup-ban:"))).toEqual([]);
    expect(fake.rateLimitRules?.map((rule) => rule.description)).toEqual([RATE_LIMIT_ORIGIN_DESCRIPTION, RATE_LIMIT_EXPENSIVE_DESCRIPTION]);
    expect(fake.managedRules?.[0]?.description).toBe(MANAGED_RULESET_RULE_DESCRIPTION);
  });

  it("churn converges at small budgets too: gains, removals, duplicates and moves, never losing a wanted clause", async () => {
    for (const budget of [10, 11, 13, 17]) {
      const baseline = baselineRulesInOrder();
      const old = [siteIpClause("192.0.2.1", ["shop.example.org"]), siteIpClause("192.0.2.2", ["shop.example.org"])];
      const chunkOne = { id: "c1", ...buildEdgeChunkRule("block", 1, old) } as FakeRule;
      const chunkOneCopy = { id: "c1-copy", ...buildEdgeChunkRule("block", 1, old) } as FakeRule;
      const startRules = [baseline[5], chunkOne, baseline[0], baseline[1], chunkOneCopy, baseline[2], baseline[3], baseline[4]] as FakeRule[];
      const fake = new FakeCloudflare(startRules).install();
      const params = validParams({
        block: [{ key: "kept", hosts: ["shop.example.org"], ips: ["192.0.2.2"], uas: [] }, ...bans(6, "203.0.113")],
        challenge: [{ key: "ua1", hosts: ["shop.example.org"], ips: [], uas: [], all: true }],
      });
      const underAttack = buildEdgeClauses([{ hosts: ["shop.example.org"], ips: [], uas: [], all: true }], EXCLUDED_HOSTS);
      if (!underAttack.ok) throw new Error(underAttack.reason);
      const wanted = new Set([...params.block.map((entry) => siteIpClause(entry.ips[0] as string, entry.hosts)), ...underAttack.clauses]);
      const outcomes = await convergeWithInvariants(fake, params, wanted, budget);
      if (budget === 10) expect(outcomes.length).toBeGreaterThan(2);
      vi.restoreAllMocks();
    }
  });

  /**
   * Re-run until the run succeeds (at most 20 runs). Checks, across every write of every run: a wanted
   * clause once in force is never absent again; within a run no content write follows a move; every
   * invocation stays within `budget` subrequests; a stopped run says so and lands something. Ends
   * with a run that writes nothing. Returns each run's outcome code.
   */
  async function convergeWithInvariants(fake: FakeCloudflare, params: WafEdgeSyncParams, wanted: Set<string>, budget: number): Promise<string[]> {
    const outcomes: string[] = [];
    const seenInForce = new Set<string>();
    for (const clause of clausesInForce(fake.customRules ?? [])) if (wanted.has(clause)) seenInForce.add(clause);
    for (let run = 0; run < 20; run += 1) {
      const leases = new FakeLeaseNamespace();
      fake.writes = [];
      fake.snapshots = [];
      fake.requests = [];
      const result = await actuateWafEdgeSync(params, envWithToken(leases), testLimits(fake, { subrequestBudget: budget }));
      outcomes.push(result.ok ? "ok" : result.code);
      expect(subrequestsOf(fake, leases), `run ${run}`).toBeLessThanOrEqual(budget);
      for (const state of fake.snapshots) {
        const inForce = clausesInForce(state);
        for (const clause of seenInForce) expect(inForce.has(clause), `run ${run}: ${clause}`).toBe(true);
        for (const clause of inForce) if (wanted.has(clause)) seenInForce.add(clause);
      }
      const firstMove = fake.writes.findIndex((write) => write.method === "PATCH" && write.body?.position !== undefined);
      if (firstMove !== -1) {
        for (const write of fake.writes.slice(firstMove)) {
          if (write.phase === "custom") expect(write, `run ${run}: a content write after a move`).toMatchObject({ method: "PATCH", body: { position: {} } });
        }
      }
      if (result.ok) {
        expect([...wanted].every((clause) => clausesInForce(fake.customRules ?? []).has(clause))).toBe(true);
        fake.writes = [];
        const again = await actuateWafEdgeSync(params, envWithToken(), testLimits(fake, { subrequestBudget: budget }));
        expect(again.ok).toBe(true);
        expect(fake.writes).toEqual([]);
        return outcomes;
      }
      if (result.code !== "writeFailed") throw new Error(`run ${run}: ${result.code}: ${result.detail}`);
      expect(result.detail.startsWith(EDGE_SYNC_BUDGET_REACHED), `run ${run}: ${result.detail}`).toBe(true);
      expect(fake.writes.length, `run ${run} made no progress`).toBeGreaterThan(0);
    }
    throw new Error(`did not converge in 20 runs: ${outcomes.join(", ")}`);
  }
});

// ── a seeded random walk over the sticky invariants ───────────────────────────────────

/** mulberry32: a tiny deterministic PRNG, so a failure always reproduces. */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = state;
    mixed = Math.imul(mixed ^ (mixed >>> 15), mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
}

describe("waf-edge-sync: random add/remove sequences (property)", () => {
  it("no still-wanted clause leaves its chunk, additions land before removals, and a present clause is never absent again", async () => {
    const random = seededRandom(20261029);
    const pick = <T>(values: readonly T[]): T => values[Math.floor(random() * values.length)] as T;
    // Sites with host sets of very different sizes (long names fill chunks fast and force splits).
    const sites: string[][] = [
      ["a.example.com"],
      ["b.example.com", "www.b.example.com"],
      longHosts("c", 6, 150),
      longHosts("d", 12, 180),
      longHosts("e", 30, 200), // over the budget for one clause: split into host groups
      ["shop.example.org", "www.shop.example.org"],
    ];
    const ips = ["192.0.2.1", "192.0.2.2", "198.51.100.0/24", "203.0.113.7", "2001:db8::/32", "2001:db8::5", "10.0.0.0/8"];
    const userAgents = ["ExampleBot/1.0", "BadCrawler/2.1 (+https://bad.example)", "ScraperKit/0.9"];

    interface PoolEntry {
      kind: "block" | "challenge";
      key: string;
      siteIndex: number | null;
      ips: string[];
      uas: string[];
      all: boolean;
    }
    const pool: PoolEntry[] = [];
    for (let index = 0; index < 28; index += 1) {
      const kind = random() < 0.55 ? "block" : "challenge";
      const isGlobal = random() < 0.15;
      const shape = random();
      let entryIps: string[] = [];
      let entryUas: string[] = [];
      let all = false;
      if (kind === "challenge" && !isGlobal && shape < 0.2) {
        all = true;
      } else if (shape < 0.6) {
        entryIps = [pick(ips)];
      } else {
        entryUas = [pick(userAgents)];
      }
      pool.push({ kind, key: `k${index}`, siteIndex: isGlobal ? null : Math.floor(random() * sites.length), ips: entryIps, uas: entryUas, all });
    }

    const fake = new FakeCloudflare(null);
    fake.plan = "business";
    fake.install();
    // What the walk exercised, so it can never silently become trivial.
    const coverage = { chunkCreates: 0, chunkDeletes: 0, twoWriteChunks: 0, maxChunksOfOneKind: 0 };

    for (let round = 0; round < 40; round += 1) {
      // A site sometimes gains or loses a domain: every clause on it changes text (a re-split for site e).
      if (random() < 0.3) {
        const siteIndex = Math.floor(random() * sites.length);
        const site = sites[siteIndex] as string[];
        if (random() < 0.5 && site.length > 1) site.pop();
        else site.push(`extra${round}.site${siteIndex}.example.net`);
      }
      const chosen = pool.filter(() => random() < 0.45);
      const toEntry = (entry: PoolEntry) => {
        const hosts = entry.siteIndex === null ? [] : [...(sites[entry.siteIndex] as string[])];
        const value: Record<string, unknown> = { key: entry.key, hosts, ips: entry.ips, uas: entry.uas };
        if (entry.all) value.all = true;
        return value;
      };
      const params = validParams({
        block: chosen.filter((entry) => entry.kind === "block").map(toEntry),
        challenge: chosen.filter((entry) => entry.kind === "challenge").map(toEntry),
      });

      const wantedBlock = buildEdgeClauses(params.block.map((entry) => ({ ...entry, all: false })), EXCLUDED_HOSTS);
      const wantedChallenge = buildEdgeClauses(params.challenge.map((entry) => ({ ...entry, all: entry.all === true })), EXCLUDED_HOSTS);
      if (!wantedBlock.ok || !wantedChallenge.ok) throw new Error("the walk built an invalid state");
      const wanted = new Set([
        ...wantedBlock.clauses.map((clause) => `block|${clause}`),
        ...wantedChallenge.clauses.map((clause) => `challenge|${clause}`),
      ]);

      const before = chunkClauses(fake.customRules ?? []);
      fake.snapshots = [];
      fake.writes = [];
      const result = await actuateWafEdgeSync(params, envWithToken());
      if (!result.ok) throw new Error(`round ${round}: ${result.detail}`);

      // 1. Sticky: a clause that was in chunk X and is still wanted is in chunk X after EVERY write.
      //    And no write — the gain writes included — ever holds a chunk over the 4,000-character budget.
      for (const snapshot of fake.snapshots) {
        for (const rule of snapshot) {
          if (classifyWafRuleDescription(rule.description).owner === "chunk") {
            expect((rule.expression ?? "").length, `round ${round}: ${rule.description} over budget mid-run`).toBeLessThanOrEqual(EDGE_CHUNK_MAX_LENGTH);
          }
        }
        const during = chunkClauses(snapshot);
        for (const [description, clauses] of before) {
          const kind = description.startsWith("doubleyoup-edge-block:") ? "block" : "challenge";
          for (const clause of clauses) {
            if (!wanted.has(`${kind}|${clause}`)) continue;
            expect(during.get(description)?.has(clause), `round ${round}: ${description} lost a wanted clause`).toBe(true);
          }
        }
      }
      // 2. Additions before removals: up to the last write that adds a clause, nothing is removed.
      const startState = new Set<string>();
      for (const [description, clauses] of before) {
        const kind = description.startsWith("doubleyoup-edge-block:") ? "block" : "challenge";
        for (const clause of clauses) startState.add(`${kind}|${clause}`);
      }
      const states: Array<Set<string>> = [startState, ...fake.snapshots.map(presentClauses)];
      let lastAddition = 0;
      for (let index = 1; index < states.length; index += 1) {
        for (const clause of states[index] as Set<string>) {
          if (!(states[index - 1] as Set<string>).has(clause)) lastAddition = index;
        }
      }
      for (let index = 1; index <= lastAddition; index += 1) {
        for (const clause of states[index - 1] as Set<string>) {
          expect((states[index] as Set<string>).has(clause), `round ${round}: a clause left before every addition landed`).toBe(true);
        }
      }
      // 3. A wanted clause, once present, is never absent again in this run.
      for (const clause of wanted) {
        let seen = false;
        for (const state of states) {
          if (state.has(clause)) seen = true;
          else expect(seen, `round ${round}: ${clause.slice(0, 60)} vanished`).toBe(false);
        }
      }
      // 4. The end state is exactly the wanted set: each clause in exactly one chunk, every chunk
      //    canonical and inside the budget, our rules in the documented order.
      const finalRules = fake.customRules ?? [];
      const finalChunks = chunkClauses(finalRules);
      const finalPresent: string[] = [];
      for (const [description, clauses] of finalChunks) {
        const kind = description.startsWith("doubleyoup-edge-block:") ? "block" : "challenge";
        expect(clauses.size).toBeGreaterThan(0);
        const rule = finalRules.find((candidate) => candidate.description === description) as FakeRule;
        expect(rule.expression).toBe(joinChunkClauses([...clauses]));
        expect((rule.expression ?? "").length).toBeLessThanOrEqual(EDGE_CHUNK_MAX_LENGTH);
        for (const clause of clauses) finalPresent.push(`${kind}|${clause}`);
      }
      expect(finalPresent.length).toBe(new Set(finalPresent).size);
      expect(new Set(finalPresent)).toEqual(wanted);
      const ourOrder = finalRules
        .map((rule) => rule.description ?? "")
        .map((description) => {
          const ownership = classifyWafRuleDescription(description);
          if (ownership.owner === "chunk") return ownership.kind === "block" ? `0-block-${String(ownership.chunkNumber).padStart(6, "0")}` : `4-challenge-${String(ownership.chunkNumber).padStart(6, "0")}`;
          const rank: Record<string, string> = {
            [WAF_COUNTRY_BLOCK_DESCRIPTION]: "1",
            [WAF_WPADMIN_GEO_DESCRIPTION]: "2",
            [WAF_XMLRPC_DESCRIPTION]: "3",
            [WAF_LOGIN_GATE_DESCRIPTION]: "5",
            [WAF_FRONTEND_GEO_DESCRIPTION]: "6",
            [WAF_EXEC_SKIP_DESCRIPTION]: "7",
          };
          return rank[description] ?? "";
        });
      expect(ourOrder).toEqual([...ourOrder].sort());
      expect(result.chunks.block + result.chunks.challenge).toBe(finalChunks.size);
      coverage.chunkCreates += fake.writes.filter((write) => write.method === "POST" && write.description.startsWith("doubleyoup-edge-")).length;
      coverage.chunkDeletes += fake.writes.filter((write) => write.method === "DELETE").length;
      const patchedChunks = fake.writes.filter((write) => write.method === "PATCH").map((write) => write.description);
      coverage.twoWriteChunks += patchedChunks.length - new Set(patchedChunks).size;
      coverage.maxChunksOfOneKind = Math.max(coverage.maxChunksOfOneKind, result.chunks.block, result.chunks.challenge);

      // 5. Idempotent: the same state again writes nothing.
      fake.writes = [];
      const again = await actuateWafEdgeSync(params, envWithToken());
      expect(again.ok).toBe(true);
      expect(fake.writes, `round ${round}: a re-run wrote`).toEqual([]);
    }
    expect(coverage.chunkCreates).toBeGreaterThan(5);
    expect(coverage.chunkDeletes).toBeGreaterThan(2);
    expect(coverage.twoWriteChunks).toBeGreaterThan(2);
    expect(coverage.maxChunksOfOneKind).toBeGreaterThanOrEqual(3);
  });
});

// ── through the signed /actuate route ─────────────────────────────────────────────────

describe("waf-edge-sync: the signed dispatch path", () => {
  let publicKeyPem: string;
  let privateKey: CryptoKey;
  beforeAll(async () => {
    const keypair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", keypair.publicKey)) as ArrayBuffer);
    let binary = "";
    for (const byte of spki) binary += String.fromCharCode(byte);
    publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${btoa(binary)}\n-----END PUBLIC KEY-----\n`;
    privateKey = keypair.privateKey;
  });

  async function signedRequest(params: unknown): Promise<Request> {
    const job: DispatchJob = {
      op: "waf-edge-sync",
      params: JSON.stringify(params),
      accountId: "acct_test_1",
      timestamp: new Date().toISOString(),
      nonce: "ef56ef56ef56ef56ef56ef56ef56ef56",
    };
    const signature = new Uint8Array(
      await crypto.subtle.sign({ name: "Ed25519" }, privateKey, new TextEncoder().encode(canonicalizeDispatchJob(job))),
    );
    let binary = "";
    for (const byte of signature) binary += String.fromCharCode(byte);
    return new Request("http://localhost/actuate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ job, signature: btoa(binary) }),
    });
  }

  function routeEnv(): Env {
    return {
      DY_SIGNING_PUBLIC_KEY: publicKeyPem,
      CF_DNS_API_TOKEN: TOKEN,
      NONCE_STORE: {
        idFromName: () => ({}),
        get: () => ({
          consume: async () => "fresh" as const,
          acquireLease: async () => "acquired" as const,
          releaseLease: async () => undefined,
        }),
      },
    } as unknown as Env;
  }

  it("counts every subrequest of a signed invocation: the nonce consume before the actuator, then the run's own", async () => {
    const calls = { consume: 0, acquire: 0, release: 0 };
    const env = {
      DY_SIGNING_PUBLIC_KEY: publicKeyPem,
      CF_DNS_API_TOKEN: TOKEN,
      NONCE_STORE: {
        idFromName: () => ({}),
        get: () => ({
          consume: async () => {
            calls.consume += 1;
            return "fresh" as const;
          },
          acquireLease: async () => {
            calls.acquire += 1;
            return "acquired" as const;
          },
          releaseLease: async () => {
            calls.release += 1;
          },
        }),
      },
    } as unknown as Env;
    const fake = new FakeCloudflare(null).install();
    const response = await worker.fetch(await signedRequest(rawParams()), env);
    expect(response.status).toBe(200);
    // The budget assumes exactly these: one subrequest before the actuator, two for the lease.
    expect(calls.consume).toBe(EDGE_SYNC_SUBREQUESTS_BEFORE_ACTUATION);
    expect(calls.acquire + calls.release).toBe(2);
    // zone + custom read + entrypoint create + rate-limit read, plus the three above.
    expect(calls.consume + calls.acquire + calls.release + fake.requests.length).toBe(7);
  });

  it("is allowlisted and routed to its own validator and actuator", async () => {
    expect(DISPATCH_OPS).toContain("waf-edge-sync");
    expect(typeof DISPATCH_OP_REGISTRY["waf-edge-sync"].validateParams).toBe("function");
    const fake = new FakeCloudflare(null).install();
    const response = await worker.fetch(await signedRequest(rawParams()), routeEnv());
    expect(response.status).toBe(200);
    const body = (await response.json()) as WafEdgeSyncResult;
    expect(body).toMatchObject({ ok: true, op: "waf-edge-sync", zone: ZONE, rulesUsed: 6, chunks: { block: 0, challenge: 0 } });
    expect(fake.customDescriptions()).toEqual(edgeWafRulesOrderWithXmlrpc());
  });

  it("A8 over the wire: {enabled:false} alone and a plan-disallowed block are 200s; a value outside the API set is a 400", async () => {
    const fake = new FakeCloudflare(baselineRulesInOrder()).install();
    const off = await worker.fetch(await signedRequest(rawParams({ rateLimit: { enabled: false } })), routeEnv());
    expect(off.status).toBe(200);
    expect(await off.json()).toMatchObject({ ok: true, rateLimit: { ok: true, created: [], patched: [], deleted: [], omittedClauses: [] } });

    // 86400 s is in Cloudflare's API set but over Pro's 1 h: only the rate-limit part is refused.
    const thresholds = { requests: 60, periodSeconds: 60, mitigationSeconds: 86400 };
    const overPlan = await worker.fetch(
      await signedRequest(rawParams({ rateLimit: { enabled: true, origin: thresholds, expensive: thresholds } })),
      routeEnv(),
    );
    expect(overPlan.status).toBe(200);
    expect(await overPlan.json()).toMatchObject({ ok: true, rateLimit: { ok: false, code: "invalid" } });
    expect(fake.writes.filter((write) => write.phase === "ratelimit")).toEqual([]);

    // 7200 s is not in the API set at all: a schema refusal of the whole op.
    const outsideSet = { ...thresholds, mitigationSeconds: 7200 };
    const refused = await worker.fetch(
      await signedRequest(rawParams({ rateLimit: { enabled: true, origin: outsideSet, expensive: thresholds } })),
      routeEnv(),
    );
    expect(refused.status).toBe(400);
  });

  it("refuses invalid params with 400 and touches no Cloudflare API", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const response = await worker.fetch(await signedRequest(rawParams({ expression: "true" })), routeEnv());
    expect(response.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

/** The six baseline descriptions in the documented order (no chunks). */
function edgeWafRulesOrderWithXmlrpc(): string[] {
  const built = buildEdgeWafRules({ zone: ZONE, enabled: true, excludedHosts: EXCLUDED_HOSTS, agentHosts: AGENT_HOSTS });
  if (!built.ok) throw new Error(built.reason);
  const five = edgeWafRulesInOrder(built.rules).map((rule) => rule.description);
  return [five[0] as string, five[1] as string, WAF_XMLRPC_DESCRIPTION, five[2] as string, five[3] as string, five[4] as string];
}
