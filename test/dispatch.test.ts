// Direction-B signed-dispatch tests (agency Worker side).
//
// The security-critical assertion is the CROSS-SIDE round trip: a job signed with the
// SAME ed25519 scheme + public-key encoding our control-plane app uses (ed25519 over the
// canonical UTF-8 bytes; the public key exported as SPKI PEM, exactly what onboarding
// stores on Account.signingKeyPublic) MUST verify with the Worker's verifyDispatch — and
// every negative case (tampered job, wrong key, stale timestamp, disallowed op) MUST fail
// closed. Plus the /actuate route itself: an unverified request must actuate NOTHING (no
// fetch to Cloudflare), and the op registry must route each op to its own validator +
// actuator using ONLY the agency's own credential for that op.
//
// This test stays Worker-native (Web Crypto only, no node:crypto/Buffer) so the Worker
// repo keeps its "fetch + Web Crypto only, no nodejs_compat" guarantee. Web Crypto's
// ed25519 sign produces the identical signature scheme as the app's Node crypto.sign
// over the identical canonical bytes, so this is a faithful app->Worker round trip.

import { describe, it, expect, vi, afterEach, beforeAll } from "vitest";
import worker from "../src/index.js";
import type { Env } from "../src/env.js";
import {
  type DispatchJob,
  canonicalizeDispatchJob,
  verifyDispatch,
} from "../src/dispatch-verify.js";
import {
  CACHE_PURGE_MODES,
  isValidR2BucketName,
  validateProvisionR2Params,
  validateDnsRecordUpsertParams,
  validateCachePurgeParams,
  validateWpCliParams,
  validateDbExportParams,
  validateDbImportParams,
} from "../src/dispatch-params.js";
import { DISPATCH_OP_REGISTRY, parseDispatchParams } from "../src/ops.js";
import { buildDbExportScript, buildDbImportScript } from "../src/actuate.js";

// ── Web-Crypto helpers (no Node APIs) ───────────────────────────────────────────────
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

interface TestKeypair {
  publicKeyPem: string;
  privateKey: CryptoKey;
}

async function makeKeypair(): Promise<TestKeypair> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  // SPKI PEM — exactly the encoding onboarding stores (line-wrapping is irrelevant; the
  // Worker strips all whitespace before decoding).
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${bytesToBase64(spki)}\n-----END PUBLIC KEY-----\n`;
  return { publicKeyPem, privateKey: kp.privateKey };
}

// Sign EXACTLY as app/src/server/services/agency-dispatch-signing.ts::signDispatchJob does:
// ed25519 over the canonical UTF-8 bytes, base64. Signing over the Worker's
// canonicalizeDispatchJob is legitimate because the test also asserts that output equals
// the pinned EXPECTED_CANONICAL that the app side is independently pinned to.
async function signAsApp(job: DispatchJob, privateKey: CryptoKey): Promise<string> {
  const canonical = canonicalizeDispatchJob(job);
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, privateKey, new TextEncoder().encode(canonical)),
  );
  return bytesToBase64(sig);
}

// A fixed job so the canonical-bytes assertion below is stable. FREEZE_MS is this job's
// own timestamp, used as `nowMs` so the freshness window passes deterministically.
const FREEZE_MS = Date.parse("2026-09-05T00:00:00.000Z");
const R2_PARAMS = { bucketName: "dy-agency-proof-abc123" };
function sampleJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return {
    op: "provision-r2",
    // The app sets params = JSON.stringify(<op params object>) — mirror that exactly.
    params: JSON.stringify(R2_PARAMS),
    accountId: "acct_test_1",
    timestamp: "2026-09-05T00:00:00.000Z",
    nonce: "0123456789abcdef0123456789abcdef",
    ...overrides,
  };
}

// A dns-record-upsert job (all-string params, the signed-job convention).
const DNS_PARAMS = {
  zone: "jasonhulme.com",
  type: "TXT",
  name: "_dy-dirb-proof.jasonhulme.com",
  content: "dy-dirb-proof-abc123",
  proxied: "false",
  ttl: "1",
};
function dnsJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "dns-record-upsert",
    params: JSON.stringify(DNS_PARAMS),
    nonce: "fedcba9876543210fedcba9876543210",
    ...overrides,
  });
}

// A cache-purge job — a SAFE targeted (files) purge of one in-zone URL by default.
const CACHE_PARAMS = {
  zone: "doubleyoup.com",
  mode: "files",
  files: ["https://doubleyoup.com/_dy-dirb-proof-cache"],
};
function cachePurgeJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "cache-purge",
    params: JSON.stringify(CACHE_PARAMS),
    nonce: "aa55aa55aa55aa55aa55aa55aa55aa55",
    ...overrides,
  });
}

// A wp-cli job — a SAFE read-only command (option get siteurl) by default.
const WP_CLI_PARAMS = {
  docroot: "/var/www/example",
  args: ["option", "get", "siteurl"],
};
function wpCliJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "wp-cli",
    params: JSON.stringify(WP_CLI_PARAMS),
    nonce: "bb66bb66bb66bb66bb66bb66bb66bb66",
    ...overrides,
  });
}

// A db-export job — the orchestrator-generated object key for a real storage-tier dogfood site.
const DB_EXPORT_PARAMS = {
  docroot: "/sites/geelongns/public",
  objectKey: "db-exports/geelongns-2026-09-07t01-02-03z.sql",
};
function dbExportJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "db-export",
    params: JSON.stringify(DB_EXPORT_PARAMS),
    nonce: "cc77cc77cc77cc77cc77cc77cc77cc77",
    ...overrides,
  });
}

// A db-import job — the caller names an EXISTING dump (same object-key grammar as db-export).
const DB_IMPORT_PARAMS = {
  docroot: "/sites/geelongns/public",
  objectKey: "db-exports/geelongns-2026-09-07t01-02-03z.sql",
};
function dbImportJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "db-import",
    params: JSON.stringify(DB_IMPORT_PARAMS),
    nonce: "dd88dd88dd88dd88dd88dd88dd88dd88",
    ...overrides,
  });
}

// The ONE canonical byte-string both sides must agree on. This exact literal is also
// pinned in the app's agency-dispatch-signing.test.ts — if either canonicalizer drifts,
// one of the two tests breaks. Note the params value is the app's JSON.stringify output,
// re-escaped as a JSON string by the canonicalizer (hence the \" sequences).
const EXPECTED_CANONICAL =
  `{"accountId":"acct_test_1",` +
  `"nonce":"0123456789abcdef0123456789abcdef",` +
  `"op":"provision-r2",` +
  `"params":"{\\"bucketName\\":\\"dy-agency-proof-abc123\\"}",` +
  `"timestamp":"2026-09-05T00:00:00.000Z"}`;

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("canonicalization agrees with the app (byte-for-byte)", () => {
  it("produces the pinned canonical string", () => {
    expect(canonicalizeDispatchJob(sampleJob())).toBe(EXPECTED_CANONICAL);
  });

  it("treats params as an opaque string — nested JSON survives canonicalize + parse exactly", () => {
    // A params string with nested objects/arrays/unicode/escapes: the canonicalizer must
    // not touch it (no re-serialization), and JSON.parse on the Worker must yield the
    // identical structure the app stringified.
    const nested = { a: { b: [1, "two", { c: null }] }, unicode: "zéro — ✓", quote: 'say "hi"' };
    const paramsString = JSON.stringify(nested);
    const job = sampleJob({ params: paramsString });
    const canonical = canonicalizeDispatchJob(job);
    expect(canonical).toContain(`"params":${JSON.stringify(paramsString)}`);
    const parsed = parseDispatchParams(job.params);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.params).toEqual(nested);
  });
});

describe("verifyDispatch — cross-side round trip + negatives", () => {
  it("verifies a job signed the app way with the matching public key", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.job.params).toBe(JSON.stringify(R2_PARAMS));
  });

  it("verifies a dns-record-upsert job whose params string carries nested JSON", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = dnsJob();
    const signature = await signAsApp(job, privateKey);

    const verdict = await verifyDispatch({ rawJob: job, signatureB64: signature, publicKeyPem, nowMs: FREEZE_MS });
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      const parsed = parseDispatchParams(verdict.job.params);
      expect(parsed.ok && parsed.params).toEqual(DNS_PARAMS);
    }
  });

  it("rejects a tampered job (params swapped after signing)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const tampered = { ...job, params: JSON.stringify({ bucketName: "attacker-bucket" }) };
    const verdict = await verifyDispatch({
      rawJob: tampered,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/does not verify/);
  });

  it("rejects a semantically-equal params string with different bytes (signature is over exact bytes)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    // Same JSON meaning, one extra space: NOT the signed bytes => must fail.
    const respaced = { ...job, params: '{"bucketName": "dy-agency-proof-abc123"}' };
    const verdict = await verifyDispatch({ rawJob: respaced, signatureB64: signature, publicKeyPem, nowMs: FREEZE_MS });
    expect(verdict.ok).toBe(false);
  });

  it("rejects a signature made with a different key", async () => {
    const signer = await makeKeypair();
    const other = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, signer.privateKey);

    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem: other.publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/does not verify/);
  });

  it("rejects a stale timestamp (outside the freshness window)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    // "now" is 10 minutes after the job's timestamp — well outside ±120s.
    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS + 10 * 60 * 1000,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/freshness window/);
  });

  it("rejects a non-allowlisted op even when correctly signed", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    // A validly-signed job whose op is not allowlisted must still be refused.
    const job = { ...sampleJob(), op: "delete-everything" } as unknown as DispatchJob;
    const signature = await signAsApp(job, privateKey);

    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/not allowlisted/);
  });

  it("rejects a job with an extra field (exact-key allowlist)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const withExtra = { ...job, extra: "x" };
    const verdict = await verifyDispatch({
      rawJob: withExtra,
      signatureB64: signature,
      publicKeyPem,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/malformed job/);
  });

  it("rejects the OLD five-field schema (bucketName instead of params)", async () => {
    const { publicKeyPem, privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const legacy = { op: job.op, bucketName: "dy-agency-proof-abc123", accountId: job.accountId, timestamp: job.timestamp, nonce: job.nonce };
    const verdict = await verifyDispatch({ rawJob: legacy, signatureB64: signature, publicKeyPem, nowMs: FREEZE_MS });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/malformed job/);
  });

  it("fails closed when no public key is configured", async () => {
    const { privateKey } = await makeKeypair();
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const verdict = await verifyDispatch({
      rawJob: job,
      signatureB64: signature,
      publicKeyPem: undefined,
      nowMs: FREEZE_MS,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/not configured/);
  });
});

describe("per-op params validation (Worker side — twin of the app's rules)", () => {
  it("parseDispatchParams fails closed on a malformed params string", () => {
    expect(parseDispatchParams("{not json").ok).toBe(false);
    expect(parseDispatchParams("").ok).toBe(false);
    expect(parseDispatchParams('{"a":1}')).toEqual({ ok: true, params: { a: 1 } });
  });

  it("isValidR2BucketName enforces the R2 grammar", () => {
    expect(isValidR2BucketName("dy-agency-proof-abc123")).toBe(true);
    expect(isValidR2BucketName("abc")).toBe(true);
    expect(isValidR2BucketName("AB-upper")).toBe(false);
    expect(isValidR2BucketName("-leading")).toBe(false);
    expect(isValidR2BucketName("trailing-")).toBe(false);
    expect(isValidR2BucketName("ab")).toBe(false);
    expect(isValidR2BucketName("a".repeat(64))).toBe(false);
    expect(isValidR2BucketName("under_score")).toBe(false);
  });

  it("provision-r2: accepts a valid bucketName and returns ONLY the known key", () => {
    const verdict = validateProvisionR2Params({ bucketName: "dy-ok-bucket", extra: "ignored" });
    expect(verdict).toEqual({ ok: true, params: { bucketName: "dy-ok-bucket" } });
  });

  it("provision-r2: rejects a non-object, a missing name, and an invalid name", () => {
    expect(validateProvisionR2Params("dy-ok-bucket").ok).toBe(false);
    expect(validateProvisionR2Params(null).ok).toBe(false);
    expect(validateProvisionR2Params([]).ok).toBe(false);
    expect(validateProvisionR2Params({}).ok).toBe(false);
    expect(validateProvisionR2Params({ bucketName: "Bad_Name" }).ok).toBe(false);
    expect(validateProvisionR2Params({ bucketName: 42 }).ok).toBe(false);
  });

  it("dns-record-upsert: accepts valid params (TXT, A, wildcard CNAME, apex) and returns only known keys", () => {
    expect(validateDnsRecordUpsertParams({ ...DNS_PARAMS, extra: "x" })).toEqual({ ok: true, params: DNS_PARAMS });

    const apexA = { zone: "example.com", type: "A", name: "example.com", content: "203.0.113.10", proxied: "true", ttl: "1" };
    expect(validateDnsRecordUpsertParams(apexA).ok).toBe(true);

    const wildcard = { zone: "example.com", type: "CNAME", name: "*.example.com", content: "host.doubleyoup.com", proxied: "true", ttl: "300" };
    expect(validateDnsRecordUpsertParams(wildcard).ok).toBe(true);

    const aaaa = { zone: "example.com", type: "AAAA", name: "v6.example.com", content: "2001:db8::1", proxied: "false", ttl: "86400" };
    expect(validateDnsRecordUpsertParams(aaaa).ok).toBe(true);
  });

  it("dns-record-upsert: rejects bad input field by field", () => {
    const bad = (overrides: Record<string, unknown>) => validateDnsRecordUpsertParams({ ...DNS_PARAMS, ...overrides });

    expect(validateDnsRecordUpsertParams(null).ok).toBe(false);
    expect(validateDnsRecordUpsertParams("string").ok).toBe(false);
    // type outside the allowlist
    expect(bad({ type: "MX" }).ok).toBe(false);
    expect(bad({ type: "txt" }).ok).toBe(false); // case-sensitive allowlist
    expect(bad({ type: undefined }).ok).toBe(false);
    // zone
    expect(bad({ zone: "" }).ok).toBe(false);
    expect(bad({ zone: "Jasonhulme.com" }).ok).toBe(false); // uppercase
    expect(bad({ zone: "localhost" }).ok).toBe(false); // single label
    expect(bad({ zone: "*.jasonhulme.com" }).ok).toBe(false); // wildcard zone
    // name
    expect(bad({ name: "" }).ok).toBe(false);
    expect(bad({ name: "proof.other-zone.com" }).ok).toBe(false); // outside zone
    expect(bad({ name: "notjasonhulme.com" }).ok).toBe(false); // suffix trick
    expect(bad({ name: "bad host.jasonhulme.com" }).ok).toBe(false); // space
    expect(bad({ name: "-lead.jasonhulme.com" }).ok).toBe(false);
    // content
    expect(bad({ content: "" }).ok).toBe(false);
    expect(bad({ content: " padded " }).ok).toBe(false);
    expect(bad({ content: 123 }).ok).toBe(false);
    expect(bad({ content: "x".repeat(4097) }).ok).toBe(false);
    // proxied (must be the STRING "true"/"false")
    expect(bad({ proxied: true }).ok).toBe(false);
    expect(bad({ proxied: "yes" }).ok).toBe(false);
    expect(bad({ type: "TXT", proxied: "true" }).ok).toBe(false); // TXT can't be proxied
    // ttl (numeric string: 1 or 30..86400)
    expect(bad({ ttl: 1 }).ok).toBe(false);
    expect(bad({ ttl: "auto" }).ok).toBe(false);
    expect(bad({ ttl: "0" }).ok).toBe(false);
    expect(bad({ ttl: "5" }).ok).toBe(false);
    expect(bad({ ttl: "86401" }).ok).toBe(false);
    expect(bad({ ttl: "-1" }).ok).toBe(false);
    expect(bad({ ttl: "1.5" }).ok).toBe(false);
  });

  it("the op registry has exactly the allowlisted ops, each with validateParams + actuate", () => {
    expect(Object.keys(DISPATCH_OP_REGISTRY).sort()).toEqual([
      "cache-purge",
      "db-export",
      "db-import",
      "dns-record-upsert",
      "provision-r2",
      "wp-cli",
    ]);
    for (const entry of Object.values(DISPATCH_OP_REGISTRY)) {
      expect(typeof entry.validateParams).toBe("function");
      expect(typeof entry.actuate).toBe("function");
    }
  });

  // ── cache-purge (twin of the app's rules) ─────────────────────────────────────────

  it("cache-purge exposes exactly the three modes", () => {
    expect([...CACHE_PURGE_MODES]).toEqual(["everything", "files", "hosts"]);
  });

  it("cache-purge: accepts everything / files / hosts and returns only known keys", () => {
    expect(validateCachePurgeParams({ zone: "doubleyoup.com", mode: "everything", extra: "x" })).toEqual({
      ok: true,
      params: { zone: "doubleyoup.com", mode: "everything" },
    });
    expect(validateCachePurgeParams({ ...CACHE_PARAMS, extra: "x" })).toEqual({ ok: true, params: CACHE_PARAMS });
    expect(
      validateCachePurgeParams({ zone: "doubleyoup.com", mode: "hosts", hosts: ["doubleyoup.com", "cdn.doubleyoup.com"] }),
    ).toEqual({ ok: true, params: { zone: "doubleyoup.com", mode: "hosts", hosts: ["doubleyoup.com", "cdn.doubleyoup.com"] } });
  });

  it("cache-purge: rejects bad input field by field", () => {
    const bad = (overrides: Record<string, unknown>) =>
      validateCachePurgeParams({ zone: "doubleyoup.com", mode: "everything", ...overrides });

    expect(validateCachePurgeParams(null).ok).toBe(false);
    expect(validateCachePurgeParams("string").ok).toBe(false);
    expect(validateCachePurgeParams([]).ok).toBe(false);
    // zone
    expect(bad({ zone: "" }).ok).toBe(false);
    expect(bad({ zone: "Doubleyoup.com" }).ok).toBe(false); // uppercase
    expect(bad({ zone: "localhost" }).ok).toBe(false); // single label
    expect(bad({ zone: "*.doubleyoup.com" }).ok).toBe(false); // wildcard zone
    // mode
    expect(bad({ mode: "all" }).ok).toBe(false);
    expect(bad({ mode: "Everything" }).ok).toBe(false); // case-sensitive
    expect(bad({ mode: undefined }).ok).toBe(false);
    // everything must carry no list
    expect(bad({ mode: "everything", files: ["https://doubleyoup.com/x"] }).ok).toBe(false);
    expect(bad({ mode: "everything", hosts: ["doubleyoup.com"] }).ok).toBe(false);
    // files list shape
    expect(bad({ mode: "files" }).ok).toBe(false); // missing list
    expect(bad({ mode: "files", files: [] }).ok).toBe(false); // empty
    expect(bad({ mode: "files", files: Array.from({ length: 31 }, () => "https://doubleyoup.com/x") }).ok).toBe(false);
    expect(bad({ mode: "files", files: ["https://doubleyoup.com/x"], hosts: ["doubleyoup.com"] }).ok).toBe(false);
    // files entries
    expect(bad({ mode: "files", files: [42] }).ok).toBe(false); // non-string
    expect(bad({ mode: "files", files: ["http://doubleyoup.com/x"] }).ok).toBe(false); // not https
    expect(bad({ mode: "files", files: ["ftp://doubleyoup.com/x"] }).ok).toBe(false); // not https
    expect(bad({ mode: "files", files: ["/relative/path"] }).ok).toBe(false); // not absolute
    expect(bad({ mode: "files", files: ["not a url"] }).ok).toBe(false); // malformed
    expect(bad({ mode: "files", files: ["https://evil.com/x"] }).ok).toBe(false); // out of zone
    expect(bad({ mode: "files", files: ["https://notdoubleyoup.com/x"] }).ok).toBe(false); // suffix trick
    expect(bad({ mode: "files", files: [" https://doubleyoup.com/x "] }).ok).toBe(false); // padded
    expect(bad({ mode: "files", files: [`https://doubleyoup.com/${"a".repeat(2100)}`] }).ok).toBe(false); // too long
    // hosts list shape
    expect(bad({ mode: "hosts" }).ok).toBe(false); // missing list
    expect(bad({ mode: "hosts", hosts: [] }).ok).toBe(false); // empty
    expect(bad({ mode: "hosts", hosts: Array.from({ length: 31 }, () => "doubleyoup.com") }).ok).toBe(false);
    expect(bad({ mode: "hosts", hosts: ["doubleyoup.com"], files: ["https://doubleyoup.com/x"] }).ok).toBe(false);
    // hosts entries
    expect(bad({ mode: "hosts", hosts: [42] }).ok).toBe(false); // non-string
    expect(bad({ mode: "hosts", hosts: ["Doubleyoup.com"] }).ok).toBe(false); // uppercase
    expect(bad({ mode: "hosts", hosts: ["https://doubleyoup.com/x"] }).ok).toBe(false); // URL, not a hostname
    expect(bad({ mode: "hosts", hosts: ["*.doubleyoup.com"] }).ok).toBe(false); // wildcard
    expect(bad({ mode: "hosts", hosts: ["evil.com"] }).ok).toBe(false); // out of zone
    expect(bad({ mode: "hosts", hosts: ["notdoubleyoup.com"] }).ok).toBe(false); // suffix trick
  });

  // ── wp-cli (twin of the app's rules) ──────────────────────────────────────────────

  it("wp-cli: accepts BOTH docroot forms (/var/www/<slug> and /sites/<slug>/public) and returns only known keys", () => {
    expect(validateWpCliParams({ ...WP_CLI_PARAMS, extra: "x" })).toEqual({ ok: true, params: WP_CLI_PARAMS });
    // Docker-era /var/www form.
    expect(validateWpCliParams({ docroot: "/var/www/site1", args: ["cache"] }).ok).toBe(true);
    // Storage-tier /sites/<slug>/public form — the live cell layout, incl. real dogfood slugs.
    expect(validateWpCliParams({ docroot: "/sites/geelongns/public", args: ["option", "get", "siteurl"] }).ok).toBe(true);
    expect(validateWpCliParams({ docroot: "/sites/docs-892769/public", args: ["cache"] }).ok).toBe(true);
    expect(validateWpCliParams({ docroot: "/sites/rareepicgamer-19f933/public", args: ["cache"] }).ok).toBe(true);
    // A 30-arg list is the max.
    expect(
      validateWpCliParams({ docroot: "/var/www/a", args: Array.from({ length: 30 }, (_, i) => `a${i}`) }).ok,
    ).toBe(true);
  });

  it("wp-cli: rejects a bad docroot (wrong root, traversal, trailing slash, extra/short segment, bad slug, metachars)", () => {
    const bad = (docroot: unknown) => validateWpCliParams({ docroot, args: ["option", "get", "siteurl"] });
    expect(validateWpCliParams(null).ok).toBe(false);
    expect(validateWpCliParams("string").ok).toBe(false);
    expect(bad(42).ok).toBe(false);
    expect(bad("").ok).toBe(false);
    expect(bad("/etc/passwd").ok).toBe(false); // wrong root
    expect(bad("relative/path").ok).toBe(false); // not absolute
    // /var/www/<slug> form
    expect(bad("/var/www/").ok).toBe(false); // no slug
    expect(bad("/var/www/site/").ok).toBe(false); // trailing slash
    expect(bad("/var/www/site/public").ok).toBe(false); // extra path segment
    expect(bad("/var/www/../etc").ok).toBe(false); // traversal
    expect(bad("/var/www/../../etc/passwd").ok).toBe(false); // traversal
    expect(bad("/var/www/Site").ok).toBe(false); // uppercase slug
    expect(bad("/var/www/site;rm").ok).toBe(false); // shell metachar
    expect(bad("/var/www/site space").ok).toBe(false); // space
    // /sites/<slug>/public form
    expect(bad("/sites//public").ok).toBe(false); // empty slug
    expect(bad("/sites/site").ok).toBe(false); // missing /public suffix
    expect(bad("/sites/site/private").ok).toBe(false); // non-/public suffix
    expect(bad("/sites/site/public/").ok).toBe(false); // trailing slash
    expect(bad("/sites/site/public/wp").ok).toBe(false); // extra path segment past /public
    expect(bad("/sites/x/public/../..").ok).toBe(false); // traversal
    expect(bad("/sites/Site/public").ok).toBe(false); // uppercase slug
    expect(bad("/sites/site;rm/public").ok).toBe(false); // shell metachar in slug
    expect(bad("/sites/site space/public").ok).toBe(false); // space
  });

  it("wp-cli: rejects a bad args list (missing, empty, oversized, non-string, empty entry, mega-string)", () => {
    const bad = (args: unknown) => validateWpCliParams({ docroot: "/var/www/example", args });
    expect(bad(undefined).ok).toBe(false); // missing
    expect(bad("option get siteurl").ok).toBe(false); // not an array
    expect(bad([]).ok).toBe(false); // empty
    expect(bad(Array.from({ length: 31 }, () => "x")).ok).toBe(false); // oversized
    expect(bad(["option", 42]).ok).toBe(false); // non-string entry
    expect(bad(["option", ""]).ok).toBe(false); // empty entry
    expect(bad(["option", "a".repeat(8193)]).ok).toBe(false); // over per-arg cap
  });

  it("wp-cli: does NOT reject metacharacters in args (they are shell-quoted by the actuator, not banned here)", () => {
    // The injection defense is per-arg shell-quoting in the actuator, NOT charset-banning here —
    // a real wp-cli value can legitimately contain these characters, so validation must accept them.
    expect(validateWpCliParams({ docroot: "/var/www/example", args: ["option", "update", "blogname", "A; B & C"] }).ok).toBe(true);
    expect(validateWpCliParams({ docroot: "/var/www/example", args: ["eval", "$(reboot)"] }).ok).toBe(true);
    expect(validateWpCliParams({ docroot: "/var/www/example", args: ["x", "`id`"] }).ok).toBe(true);
    expect(validateWpCliParams({ docroot: "/var/www/example", args: ["say", "it's \"quoted\""] }).ok).toBe(true);
  });

  // ── db-export (twin of the app's rules) ───────────────────────────────────────────

  it("db-export: accepts BOTH docroot forms + a well-formed objectKey and returns only known keys", () => {
    expect(validateDbExportParams({ ...DB_EXPORT_PARAMS, extra: "x" })).toEqual({ ok: true, params: DB_EXPORT_PARAMS });
    expect(validateDbExportParams({ docroot: "/var/www/site1", objectKey: "db-exports/site1-2026-09-07t01-02-03z.sql" }).ok).toBe(true);
    expect(validateDbExportParams({ docroot: "/sites/docs-892769/public", objectKey: "db-exports/docs-892769-20260907.sql" }).ok).toBe(true);
    // Dots and underscores are legitimate inside the filename; the shortest name is one char.
    expect(validateDbExportParams({ docroot: "/var/www/a", objectKey: "db-exports/a.sql" }).ok).toBe(true);
    expect(validateDbExportParams({ docroot: "/var/www/a", objectKey: "db-exports/a_b.c-d.sql" }).ok).toBe(true);
    // The longest admissible name: 1 + 120 chars before ".sql".
    expect(validateDbExportParams({ docroot: "/var/www/a", objectKey: `db-exports/a${"b".repeat(120)}.sql` }).ok).toBe(true);
  });

  it("db-export: rejects a bad docroot with the same grammar as wp-cli", () => {
    const bad = (docroot: unknown) => validateDbExportParams({ docroot, objectKey: DB_EXPORT_PARAMS.objectKey });
    expect(validateDbExportParams(null).ok).toBe(false);
    expect(validateDbExportParams("string").ok).toBe(false);
    expect(bad(undefined).ok).toBe(false);
    expect(bad("/etc/passwd").ok).toBe(false); // wrong root
    expect(bad("/var/www/../etc").ok).toBe(false); // traversal
    expect(bad("/var/www/site/").ok).toBe(false); // trailing slash
    expect(bad("/sites/site").ok).toBe(false); // missing /public
    expect(bad("/sites/x/public/../..").ok).toBe(false); // traversal
    expect(bad("/sites/Site/public").ok).toBe(false); // uppercase slug
    expect(bad("/sites/site;rm/public").ok).toBe(false); // shell metachar
  });

  it("db-export: rejects a bad objectKey (prefix, leading slash, extra segment, '..', case, suffix, charset, length)", () => {
    const bad = (objectKey: unknown) => validateDbExportParams({ docroot: DB_EXPORT_PARAMS.docroot, objectKey });
    expect(bad(undefined).ok).toBe(false); // missing
    expect(bad(42).ok).toBe(false); // non-string
    expect(bad("").ok).toBe(false);
    expect(bad("geelongns.sql").ok).toBe(false); // outside the db-exports/ prefix
    expect(bad("backups/geelongns.sql").ok).toBe(false); // wrong prefix
    expect(bad("/db-exports/geelongns.sql").ok).toBe(false); // leading slash
    expect(bad("db-exports/").ok).toBe(false); // no name
    expect(bad("db-exports/.sql").ok).toBe(false); // empty name
    expect(bad("db-exports/sub/geelongns.sql").ok).toBe(false); // extra path segment
    expect(bad("db-exports/../etc/passwd.sql").ok).toBe(false); // traversal
    expect(bad("db-exports/a..sql").ok).toBe(false); // ".." inside the name (explicit rule)
    expect(bad("db-exports/-lead.sql").ok).toBe(false); // must start alphanumeric
    expect(bad("db-exports/Geelongns.sql").ok).toBe(false); // uppercase
    expect(bad("db-exports/geelongns.SQL").ok).toBe(false); // uppercase suffix
    expect(bad("db-exports/geelongns.sql.gz").ok).toBe(false); // not .sql
    expect(bad("db-exports/geelongns").ok).toBe(false); // no suffix
    expect(bad("db-exports/geelongns 1.sql").ok).toBe(false); // space
    expect(bad("db-exports/geelongns;rm.sql").ok).toBe(false); // shell metachar
    expect(bad("db-exports/geelongns?x=1.sql").ok).toBe(false); // URL metachar
    expect(bad("db-exports/geelongns%2f.sql").ok).toBe(false); // percent-encoding
    expect(bad(`db-exports/a${"b".repeat(121)}.sql`).ok).toBe(false); // one over the length cap
  });

  it("db-export: a verdict names the offending field", () => {
    const docrootVerdict = validateDbExportParams({ docroot: "/etc", objectKey: DB_EXPORT_PARAMS.objectKey });
    expect(docrootVerdict.ok).toBe(false);
    if (!docrootVerdict.ok) expect(docrootVerdict.reason).toMatch(/^docroot must be/);
    const keyVerdict = validateDbExportParams({ docroot: DB_EXPORT_PARAMS.docroot, objectKey: "x.sql" });
    expect(keyVerdict.ok).toBe(false);
    if (!keyVerdict.ok) expect(keyVerdict.reason).toMatch(/^objectKey must be db-exports\//);
  });

  // ── db-import (twin of the app's rules; same two-field shape as db-export) ─────────
  it("db-import: accepts BOTH docroot forms + a well-formed objectKey and returns only known keys", () => {
    expect(validateDbImportParams({ ...DB_IMPORT_PARAMS, extra: "x" })).toEqual({ ok: true, params: DB_IMPORT_PARAMS });
    expect(validateDbImportParams({ docroot: "/var/www/site1", objectKey: "db-exports/site1-2026-09-07t01-02-03z.sql" }).ok).toBe(true);
    expect(validateDbImportParams({ docroot: "/sites/docs-892769/public", objectKey: "db-exports/docs-892769-20260907.sql" }).ok).toBe(true);
  });

  it("db-import: rejects a bad docroot with the same grammar as wp-cli/db-export", () => {
    const bad = (docroot: unknown) => validateDbImportParams({ docroot, objectKey: DB_IMPORT_PARAMS.objectKey });
    expect(validateDbImportParams(null).ok).toBe(false);
    expect(bad("/etc").ok).toBe(false);
    expect(bad("/var/www/../etc").ok).toBe(false);
    expect(bad("/sites/geelongns").ok).toBe(false); // missing /public
    expect(bad("/var/www/Site").ok).toBe(false); // uppercase slug
    expect(bad("/var/www/site/").ok).toBe(false); // trailing slash
  });

  it("db-import: rejects a bad objectKey (prefix, leading slash, extra segment, '..', case, suffix, charset)", () => {
    const bad = (objectKey: unknown) => validateDbImportParams({ docroot: DB_IMPORT_PARAMS.docroot, objectKey });
    expect(bad("geelongns.sql").ok).toBe(false); // outside the db-exports/ prefix
    expect(bad("/db-exports/geelongns.sql").ok).toBe(false); // leading slash
    expect(bad("db-exports/sub/geelongns.sql").ok).toBe(false); // extra path segment
    expect(bad("db-exports/../etc/passwd.sql").ok).toBe(false); // traversal
    expect(bad("db-exports/a..sql").ok).toBe(false); // ".." inside the name
    expect(bad("db-exports/Geelongns.sql").ok).toBe(false); // uppercase
    expect(bad("db-exports/geelongns.SQL").ok).toBe(false); // uppercase suffix
    expect(bad("db-exports/geelongns.sql.gz").ok).toBe(false); // not .sql
    expect(bad("db-exports/geelongns;rm.sql").ok).toBe(false); // shell metachar
  });

  it("db-import: a verdict names the offending field", () => {
    const docrootVerdict = validateDbImportParams({ docroot: "/etc", objectKey: DB_IMPORT_PARAMS.objectKey });
    expect(docrootVerdict.ok).toBe(false);
    if (!docrootVerdict.ok) expect(docrootVerdict.reason).toMatch(/^docroot must be/);
    const keyVerdict = validateDbImportParams({ docroot: DB_IMPORT_PARAMS.docroot, objectKey: "x.sql" });
    expect(keyVerdict.ok).toBe(false);
    if (!keyVerdict.ok) expect(keyVerdict.reason).toMatch(/^objectKey must be db-exports\//);
  });
});

describe("POST /actuate route", () => {
  let publicKeyPem: string;
  let privateKey: CryptoKey;
  beforeAll(async () => {
    ({ publicKeyPem, privateKey } = await makeKeypair());
  });

  // A stand-in NONCE_STORE binding for these Node tests. They exercise the ACTUATE path
  // (real actuators, fetch mocked), NOT replay defense — that has dedicated real-DO tests
  // under the workers pool (test/nonce-store.worker.test.ts). It always reports the nonce as
  // fresh so actuation proceeds.
  const freshNonceStore = {
    idFromName: () => ({}),
    get: () => ({ consume: async () => "fresh" as const }),
  } as unknown as Env["NONCE_STORE"];

  // A NONCE_STORE whose consume() rejects — models the DO being unavailable / a storage
  // error. handleActuate deliberately has no try/catch around consume, so this must surface
  // as a rejection (a 5xx over HTTP), never a 200, and must NOT actuate.
  const throwingNonceStore = {
    idFromName: () => ({}),
    get: () => ({
      consume: async () => {
        throw new Error("nonce store unavailable");
      },
    }),
  } as unknown as Env["NONCE_STORE"];

  function envWith(overrides: Partial<Env> = {}): Env {
    return {
      APP_BASE_URL: "https://app.example.test",
      DY_CLIENT_ID: "client-abc",
      DY_CLIENT_SECRET: "secret-xyz",
      DY_SIGNING_PUBLIC_KEY: publicKeyPem,
      R2_PROVISION_API_TOKEN: "cf-token-xyz",
      CF_DNS_API_TOKEN: "cf-dns-token-abc",
      CELL_AGENT_URL: "https://cell.example.test",
      CELL_AGENT_TOKEN: "cell-token-123",
      // The agency's object store (R2-shaped), as the db-export actuator presigns against it.
      S3_ACCESS_KEY_ID: "s3-akid-example",
      S3_SECRET_ACCESS_KEY: "s3-secret-example",
      S3_REGION: "auto",
      S3_BUCKET: "agency-backups",
      S3_ENDPOINT: "https://acct123.r2.example.test",
      NONCE_STORE: freshNonceStore,
      ...overrides,
    };
  }

  function actuateRequest(body: unknown): Request {
    return new Request("http://localhost/actuate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }

  function urlOf(input: RequestInfo | URL): string {
    if (typeof input === "string") return input;
    if (input instanceof URL) return input.toString();
    return input.url;
  }

  it("returns 401 and calls NO Cloudflare API for an unverified (unsigned) request", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const response = await worker.fetch(
      actuateRequest({ job: sampleJob(), signature: "not-a-real-signature" }),
      envWith(),
    );
    expect(response.status).toBe(401);
    const body = (await response.json()) as { ok: boolean; reason?: string };
    expect(body.ok).toBe(false);
    // Nothing was actuated: the CF API was never touched.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("fails closed (no actuation, never 200) when the nonce store errors", async () => {
    // Verification passes (valid signature + fresh timestamp), so control reaches the nonce
    // consume — which here throws. A future refactor must never let this become a bypass:
    // the request must fail (rejection / 5xx), and the actuator must not run.
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    await expect(
      worker.fetch(actuateRequest({ job, signature }), envWith({ NONCE_STORE: throwingNonceStore })),
    ).rejects.toThrow(/nonce store unavailable/);

    // The actuator was never reached — no Cloudflare call, no side effect.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns 400 and actuates NOTHING for a correctly-signed job whose params is not JSON", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sampleJob({ params: "{not json" });
    const signature = await signAsApp(job, privateKey); // authentic, but params unusable
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error: string; reason: string };
    expect(body).toMatchObject({ ok: false, error: "invalid params" });
    expect(body.reason).toMatch(/not valid JSON/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns 400 and actuates NOTHING for a correctly-signed job whose params fail the op's validation", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sampleJob({ params: JSON.stringify({ bucketName: "Bad_Name" }) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error: string; reason: string };
    expect(body).toMatchObject({ ok: false, error: "invalid params" });
    expect(body.reason).toMatch(/bucketName/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns 400 and actuates NOTHING when a valid op is given ANOTHER op's params", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    // dns params under the provision-r2 op: the registry routes to the R2 validator, which
    // must reject (no bucketName), so the op/params pairing can't be crossed.
    const job = sampleJob({ params: JSON.stringify(DNS_PARAMS) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("actuates a verified provision-r2 job via the agency's own R2 token (created)", async () => {
    // Freeze time so the fixed-timestamp job is fresh at fetch time.
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = urlOf(input);
      calls.push(url);
      // 1) account resolution
      if (url.includes("/accounts?per_page=1")) {
        return jsonResponse({ success: true, result: [{ id: "acct-cf-1", name: "Agency" }] });
      }
      // 2) bucket create — assert it used the agency token, not any platform credential
      if (/\/accounts\/acct-cf-1\/r2\/buckets$/.test(url)) {
        const auth = new Headers(init?.headers).get("authorization");
        expect(auth).toBe("Bearer cf-token-xyz");
        expect(JSON.parse(String(init?.body))).toEqual({ name: R2_PARAMS.bucketName });
        return jsonResponse({ success: true, result: { name: R2_PARAMS.bucketName } });
      }
      throw new Error(`unexpected fetch to ${url}`);
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      op: string;
      bucket: string;
      status: string;
      accountId: string;
    };
    expect(body).toMatchObject({
      ok: true,
      op: "provision-r2",
      bucket: "dy-agency-proof-abc123",
      status: "created",
      accountId: "acct-cf-1",
    });
    expect(calls.some((u) => u.includes("/r2/buckets"))).toBe(true);
  });

  it("treats an existing bucket (409) as idempotent success", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);

    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = urlOf(input);
      if (url.includes("/accounts?per_page=1")) {
        return jsonResponse({ success: true, result: [{ id: "acct-cf-1" }] });
      }
      return jsonResponse({ success: false, errors: [{ code: 10004, message: "The bucket already exists." }] }, 409);
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; status: string };
    expect(body.ok).toBe(true);
    expect(body.status).toBe("already-existed");
  });

  it("reports a clean failure (no platform fallback) when the agency R2 token is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sampleJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ R2_PROVISION_API_TOKEN: undefined }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail?: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/R2_PROVISION_API_TOKEN is not configured/);
    // It did not try to reach Cloudflare with some other credential.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── dns-record-upsert through the registry ────────────────────────────────────────

  // A routed CF DNS API mock: zone lookup, record list (configurable matches), then the
  // create (POST) or update (PUT) call. Every call must carry the DNS token and never
  // the R2 token — the op's own credential, no cross-credential leakage.
  function mockDnsApi(existing: Array<{ id: string; type: string; name: string }>) {
    const calls: Array<{ method: string; url: string; body?: unknown }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      const auth = new Headers(init?.headers).get("authorization");
      expect(auth).toBe("Bearer cf-dns-token-abc");
      expect(auth).not.toContain("cf-token-xyz");
      calls.push({ method, url, body: init?.body ? JSON.parse(String(init.body)) : undefined });

      const parsed = new URL(url);
      if (parsed.pathname === "/client/v4/zones" && method === "GET") {
        expect(parsed.searchParams.get("name")).toBe("jasonhulme.com");
        return jsonResponse({ success: true, result: [{ id: "zone-1", name: "jasonhulme.com" }] });
      }
      if (parsed.pathname === "/client/v4/zones/zone-1/dns_records" && method === "GET") {
        expect(parsed.searchParams.get("type")).toBe("TXT");
        expect(parsed.searchParams.get("name")).toBe("_dy-dirb-proof.jasonhulme.com");
        return jsonResponse({ success: true, result: existing });
      }
      if (parsed.pathname === "/client/v4/zones/zone-1/dns_records" && method === "POST") {
        return jsonResponse({ success: true, result: { id: "rec-new", name: "_dy-dirb-proof.jasonhulme.com" } });
      }
      if (parsed.pathname === "/client/v4/zones/zone-1/dns_records/rec-existing" && method === "PUT") {
        return jsonResponse({ success: true, result: { id: "rec-existing", name: "_dy-dirb-proof.jasonhulme.com" } });
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    return calls;
  }

  it("dns-record-upsert: CREATES (POST) when no record matches, using CF_DNS_API_TOKEN only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dnsJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockDnsApi([]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({
      ok: true,
      op: "dns-record-upsert",
      action: "created",
      recordId: "rec-new",
      name: "_dy-dirb-proof.jasonhulme.com",
    });

    const write = calls.find((c) => c.method === "POST");
    expect(write).toBeDefined();
    // Real JSON types on the wire (proxied boolean, ttl number), built with JSON.stringify.
    expect(write?.body).toEqual({
      type: "TXT",
      name: "_dy-dirb-proof.jasonhulme.com",
      content: "dy-dirb-proof-abc123",
      proxied: false,
      ttl: 1,
    });
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
  });

  it("dns-record-upsert: UPDATES (PUT) the one matching record when it already exists", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dnsJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockDnsApi([{ id: "rec-existing", type: "TXT", name: "_dy-dirb-proof.jasonhulme.com" }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "dns-record-upsert",
      action: "updated",
      recordId: "rec-existing",
      name: "_dy-dirb-proof.jasonhulme.com",
    });
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
  });

  it("dns-record-upsert: refuses to guess when 2+ records match (no write)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dnsJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockDnsApi([
      { id: "rec-a", type: "TXT", name: "_dy-dirb-proof.jasonhulme.com" },
      { id: "rec-b", type: "TXT", name: "_dy-dirb-proof.jasonhulme.com" },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/ambiguous/);
    expect(calls.every((c) => c.method === "GET")).toBe(true);
  });

  it("dns-record-upsert: fails cleanly when the token cannot see the zone (no write)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dnsJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      jsonResponse({ success: true, result: [] }),
    );

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/not visible to CF_DNS_API_TOKEN/);
    expect(fetchSpy).toHaveBeenCalledTimes(1); // the zone lookup only
  });

  it("dns-record-upsert: surfaces a Cloudflare write error as ok:false (still HTTP 200)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dnsJob();
    const signature = await signAsApp(job, privateKey);
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const parsed = new URL(urlOf(input));
      if (parsed.pathname === "/client/v4/zones") {
        return jsonResponse({ success: true, result: [{ id: "zone-1", name: "jasonhulme.com" }] });
      }
      if ((init?.method ?? "GET") === "GET") return jsonResponse({ success: true, result: [] });
      return jsonResponse({ success: false, errors: [{ code: 9005, message: "Content for TXT record is invalid." }] }, 400);
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/create failed with HTTP 400: Content for TXT record is invalid/);
  });

  it("dns-record-upsert: reports a clean failure and touches NO API when CF_DNS_API_TOKEN is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dnsJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // R2 token IS present — it must not be used as a substitute.
    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ CF_DNS_API_TOKEN: undefined }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/CF_DNS_API_TOKEN is not configured/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("dns-record-upsert: a signed job with invalid DNS params is 400 with no API call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dnsJob({ params: JSON.stringify({ ...DNS_PARAMS, type: "MX" }) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/type must be one of/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── cache-purge through the registry ──────────────────────────────────────────────

  // A routed CF cache-purge API mock: zone lookup, then the POST /zones/:id/purge_cache.
  // Every call must carry the DNS token and never the R2 token — the op's own credential.
  function mockCachePurgeApi() {
    const calls: Array<{ method: string; url: string; body?: unknown }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      const auth = new Headers(init?.headers).get("authorization");
      expect(auth).toBe("Bearer cf-dns-token-abc");
      expect(auth).not.toContain("cf-token-xyz");
      calls.push({ method, url, body: init?.body ? JSON.parse(String(init.body)) : undefined });

      const parsed = new URL(url);
      if (parsed.pathname === "/client/v4/zones" && method === "GET") {
        expect(parsed.searchParams.get("name")).toBe("doubleyoup.com");
        return jsonResponse({ success: true, result: [{ id: "zone-1", name: "doubleyoup.com" }] });
      }
      if (parsed.pathname === "/client/v4/zones/zone-1/purge_cache" && method === "POST") {
        return jsonResponse({ success: true, result: { id: "zone-1" } });
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    return calls;
  }

  it("cache-purge: files mode POSTs {files:[...]} using CF_DNS_API_TOKEN only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cachePurgeJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockCachePurgeApi();

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "cache-purge",
      mode: "files",
      zone: "doubleyoup.com",
      count: 1,
    });
    const write = calls.find((c) => c.method === "POST");
    expect(write?.url).toMatch(/\/zones\/zone-1\/purge_cache$/);
    expect(write?.body).toEqual({ files: ["https://doubleyoup.com/_dy-dirb-proof-cache"] });
  });

  it("cache-purge: everything mode POSTs {purge_everything:true}", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cachePurgeJob({ params: JSON.stringify({ zone: "doubleyoup.com", mode: "everything" }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockCachePurgeApi();

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "cache-purge",
      mode: "everything",
      zone: "doubleyoup.com",
      count: 0,
    });
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ purge_everything: true });
  });

  it("cache-purge: hosts mode POSTs {hosts:[...]}", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cachePurgeJob({
      params: JSON.stringify({ zone: "doubleyoup.com", mode: "hosts", hosts: ["doubleyoup.com", "cdn.doubleyoup.com"] }),
    });
    const signature = await signAsApp(job, privateKey);
    const calls = mockCachePurgeApi();

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; count: number };
    expect(body.ok).toBe(true);
    expect(body.count).toBe(2);
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ hosts: ["doubleyoup.com", "cdn.doubleyoup.com"] });
  });

  it("cache-purge: fails cleanly when the token cannot see the zone (no purge)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cachePurgeJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      jsonResponse({ success: true, result: [] }),
    );

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/not visible to CF_DNS_API_TOKEN/);
    expect(fetchSpy).toHaveBeenCalledTimes(1); // the zone lookup only — no purge attempted
  });

  it("cache-purge: surfaces a Cloudflare purge error as ok:false (still HTTP 200)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cachePurgeJob();
    const signature = await signAsApp(job, privateKey);
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const parsed = new URL(urlOf(input));
      if (parsed.pathname === "/client/v4/zones") {
        return jsonResponse({ success: true, result: [{ id: "zone-1", name: "doubleyoup.com" }] });
      }
      if ((init?.method ?? "GET") === "POST") {
        return jsonResponse({ success: false, errors: [{ code: 1012, message: "Request must contain one of..." }] }, 400);
      }
      throw new Error("unexpected");
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/cache purge failed with HTTP 400/);
  });

  it("cache-purge: reports a clean failure and touches NO API when CF_DNS_API_TOKEN is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cachePurgeJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // R2 token IS present — it must not be used as a substitute.
    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ CF_DNS_API_TOKEN: undefined }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/CF_DNS_API_TOKEN is not configured/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("cache-purge: a signed job with invalid params is 400 with no API call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cachePurgeJob({ params: JSON.stringify({ zone: "doubleyoup.com", mode: "files", files: ["https://evil.com/x"] }) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/within zone/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── wp-cli through the registry ───────────────────────────────────────────────────
  // The cell-agent's /exec: POST { script, docroot, timeoutMs }, Authorization: Bearer <token>,
  // answers HTTP 200 with { code, stdout, stderr } (even for a non-zero code). The critical
  // assertions here are that a metacharacter-laden arg is SHELL-QUOTED into one literal token
  // (command-injection defense), and that the agency's OWN cell token is used, never a platform
  // credential.
  function mockCellAgent(
    reply: { code?: number; stdout?: string; stderr?: string; error?: string },
    status = 200,
  ) {
    const calls: Array<{
      url: string;
      method: string;
      auth: string | null;
      redirect: RequestInit["redirect"];
      body: { script?: string; docroot?: string; timeoutMs?: number };
    }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      const auth = new Headers(init?.headers).get("authorization");
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      calls.push({ url, method, auth, redirect: init?.redirect, body });
      if (url.endsWith("/exec") && method === "POST") {
        return jsonResponse(reply, status);
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    return calls;
  }

  it("wp-cli: relays `wp <args>` to the cell-agent /exec using CELL_AGENT_TOKEN only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockCellAgent({ code: 0, stdout: "https://example.test\n", stderr: "" });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "wp-cli",
      exitCode: 0,
      stdout: "https://example.test\n",
      stderr: "",
    });
    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call.url).toBe("https://cell.example.test/exec");
    expect(call.method).toBe("POST");
    // The agency's OWN cell token — never a platform / Cloudflare credential.
    expect(call.auth).toBe("Bearer cell-token-123");
    expect(call.auth).not.toContain("cf-token-xyz");
    expect(call.auth).not.toContain("cf-dns-token-abc");
    expect(call.body.docroot).toBe("/var/www/example");
    // Each arg is single-quoted: `wp 'option' 'get' 'siteurl'`.
    expect(call.body.script).toBe("wp 'option' 'get' 'siteurl'");
  });

  it("wp-cli: SHELL-QUOTES a metacharacter-laden arg into ONE literal token (command-injection defense)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob({
      params: JSON.stringify({ docroot: "/var/www/example", args: ["option", "get", "; rm -rf /"] }),
    });
    const signature = await signAsApp(job, privateKey);
    const calls = mockCellAgent({ code: 0, stdout: "", stderr: "" });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    // The dangerous arg is a SINGLE single-quoted token — the cell-agent's `sh -lc` hands it to
    // wp-cli literally and never interprets the `;` or runs `rm`.
    expect(calls[0].body.script).toBe("wp 'option' 'get' '; rm -rf /'");
  });

  it("wp-cli: command-substitution + backtick args are quoted literally (no shell interpretation)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob({
      params: JSON.stringify({ docroot: "/var/www/example", args: ["eval", "$(reboot)", "`id`"] }),
    });
    const signature = await signAsApp(job, privateKey);
    const calls = mockCellAgent({ code: 0, stdout: "", stderr: "" });

    await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(calls[0].body.script).toBe("wp 'eval' '$(reboot)' '`id`'");
  });

  it("wp-cli: an embedded single quote is escaped as '\\'' and stays one token", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob({
      params: JSON.stringify({ docroot: "/var/www/example", args: ["eval", "echo 'pwned'"] }),
    });
    const signature = await signAsApp(job, privateKey);
    const calls = mockCellAgent({ code: 0, stdout: "", stderr: "" });

    await worker.fetch(actuateRequest({ job, signature }), envWith());
    // POSIX close-quote / escaped-quote / reopen-quote: 'echo '\''pwned'\''' is one literal arg.
    expect(calls[0].body.script).toBe("wp 'eval' 'echo '\\''pwned'\\'''");
  });

  it("wp-cli: fails closed (ok:false) when the cell-agent reply exceeds the byte cap (no OOM)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob();
    const signature = await signAsApp(job, privateKey);
    // A reply whose stdout alone is > 1 MiB — the Worker must STOP reading the stream and fail,
    // never buffer the whole body (that is the OOM footgun this cap closes).
    const huge = "a".repeat(1024 * 1024 + 1024);
    mockCellAgent({ code: 0, stdout: huge, stderr: "" });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/output exceeded/);
  });

  it("wp-cli: a large-but-under-cap reply streams + parses; the RETURN is truncated to the relay cap", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob();
    const signature = await signAsApp(job, privateKey);
    // 100 KiB stdout: under the 1 MiB memory cap (so it succeeds) but over the 64 KiB relay cap
    // (so the RETURN payload is truncated — the two caps are different concerns).
    const bigButOk = "b".repeat(100 * 1024);
    mockCellAgent({ code: 0, stdout: bigButOk, stderr: "" });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; stdout: string };
    expect(body.ok).toBe(true);
    expect(body.stdout.length).toBeLessThan(100 * 1024);
    expect(body.stdout).toMatch(/\[truncated\]$/);
  });

  it("wp-cli: a non-zero exit code is a successful exec (ok:true) with the code carried back", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob();
    const signature = await signAsApp(job, privateKey);
    mockCellAgent({ code: 1, stdout: "", stderr: "Error: option not found" });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "wp-cli",
      exitCode: 1,
      stdout: "",
      stderr: "Error: option not found",
    });
  });

  it("wp-cli: a cell-agent 401 becomes a clean ok:false (no bypass)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob();
    const signature = await signAsApp(job, privateKey);
    mockCellAgent({ error: "unauthorized" }, 401);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/rejected CELL_AGENT_TOKEN/);
  });

  it("wp-cli: a cell-agent 3xx redirect is fail-closed (ok:false), not followed", async () => {
    // The fetch uses redirect:"manual" (workerd rejects redirect:"error" at runtime), so a
    // redirect surfaces as a 3xx (or an opaqueredirect status 0). Either way the Worker must
    // REFUSE to follow it — a redirect means a misconfigured CELL_AGENT_URL, not a valid exec.
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob();
    const signature = await signAsApp(job, privateKey);
    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      calls.push(urlOf(input));
      return new Response(null, { status: 302, headers: { location: "https://elsewhere.example/exec" } });
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/redirected unexpectedly \(HTTP 302\)/);
    // Exactly one request was issued (the /exec) — the redirect target was NOT fetched.
    expect(calls).toEqual(["https://cell.example.test/exec"]);
  });

  it("wp-cli: a cell-agent 400 (e.g. bad docroot on the VM) surfaces as ok:false, still HTTP 200", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob();
    const signature = await signAsApp(job, privateKey);
    mockCellAgent({ error: "docroot must be under /var/www or /sites/<slug>/public" }, 400);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/cell-agent \/exec failed with HTTP 400/);
  });

  it("wp-cli: reports a clean failure and touches NO cell-agent when CELL_AGENT_URL/TOKEN are missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ CELL_AGENT_URL: undefined, CELL_AGENT_TOKEN: undefined }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/CELL_AGENT_URL \/ CELL_AGENT_TOKEN are not configured/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("wp-cli: a signed job with an invalid docroot is 400 with no cell-agent call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wpCliJob({
      params: JSON.stringify({ docroot: "/var/www/../etc", args: ["option", "get", "siteurl"] }),
    });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/docroot must be/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── db-export through the registry ────────────────────────────────────────────────
  // The Worker presigns a single-object PUT with the agency's S3_* credential and relays ONE
  // script to the cell-agent /exec (same relay + CELL_AGENT_TOKEN as wp-cli). The load-bearing
  // assertions: the presigned URL is the ONLY store-related thing in the script (no S3 secret),
  // the script exports to a temp FILE then uploads then cleans up, the result is small and never
  // echoes the URL, and every relay failure mode is fail-closed exactly like wp-cli.

  /** Pull the single-quoted presigned URL back out of the relayed script. */
  function presignedUrlIn(script: string): string {
    const match = /--upload-file "\$T" '([^']+)'$/.exec(script);
    if (!match) throw new Error(`no quoted presigned URL at the end of the script: ${script}`);
    return match[1];
  }

  it("db-export: relays export -> upload-to-presigned-URL -> cleanup to the cell-agent using CELL_AGENT_TOKEN only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockCellAgent({ code: 0, stdout: "", stderr: "" });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    // A SMALL result: exactly these four keys — never the dump, never the presigned URL.
    expect(await response.json()).toEqual({
      ok: true,
      op: "db-export",
      objectKey: DB_EXPORT_PARAMS.objectKey,
      exitCode: 0,
    });

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call.url).toBe("https://cell.example.test/exec");
    expect(call.method).toBe("POST");
    // The agency's OWN cell token — never a platform / Cloudflare / S3 credential.
    expect(call.auth).toBe("Bearer cell-token-123");
    // workerd: redirect:"manual" (never follow; a 3xx is rejected below).
    expect(call.redirect).toBe("manual");
    expect(call.body.docroot).toBe("/sites/geelongns/public");
    // The exec timeout sits just inside the 600 s presign window.
    expect(call.body.timeoutMs).toBe(540_000);

    const script = call.body.script ?? "";
    const presignedUrl = presignedUrlIn(script);
    // The exact script shape (buildDbExportScript is the single source of truth for it).
    expect(script).toBe(buildDbExportScript(presignedUrl));
    expect(script).toBe(
      "set -eu; " +
        "T=$(mktemp); " +
        `trap 'rm -f "$T"' EXIT INT TERM; ` +
        'wp db export "$T" --add-drop-table --quiet; ' +
        `curl -sS --fail-with-body --upload-file "$T" '${presignedUrl}'`,
    );

    // The presigned URL targets the agency's bucket + the signed objectKey, path-style at the
    // configured endpoint, with the full SigV4 query set and a 600 s expiry.
    const url = new URL(presignedUrl);
    expect(url.origin).toBe("https://acct123.r2.example.test");
    expect(url.pathname).toBe(`/agency-backups/${DB_EXPORT_PARAMS.objectKey}`);
    expect(url.searchParams.get("X-Amz-Algorithm")).toBe("AWS4-HMAC-SHA256");
    expect(url.searchParams.get("X-Amz-Credential")).toMatch(/^s3-akid-example\/\d{8}\/auto\/s3\/aws4_request$/);
    expect(url.searchParams.get("X-Amz-Expires")).toBe("600");
    expect(url.searchParams.get("X-Amz-SignedHeaders")).toBe("host");
    expect(url.searchParams.get("X-Amz-Signature")).toMatch(/^[0-9a-f]{64}$/);
    // NO object-store credential reaches the cell — only the derived URL.
    expect(script).not.toContain("s3-secret-example");
    expect(JSON.stringify(call.body)).not.toContain("s3-secret-example");
  });

  it("db-export: targets AWS virtual-hosted-style when the agency has no S3_ENDPOINT", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockCellAgent({ code: 0, stdout: "", stderr: "" });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ S3_ENDPOINT: undefined, S3_REGION: "us-east-1" }),
    );
    expect(response.status).toBe(200);
    const url = new URL(presignedUrlIn(calls[0].body.script ?? ""));
    expect(url.host).toBe("agency-backups.s3.us-east-1.amazonaws.com");
    expect(url.pathname).toBe(`/${DB_EXPORT_PARAMS.objectKey}`);
  });

  it("db-export: a NON-ZERO exit is ok:false (unlike wp-cli) with the cell's output quoted and the URL redacted", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob();
    const signature = await signAsApp(job, privateKey);
    // A store rejection: --fail-with-body exits 22 with the S3 error XML on stdout; make the
    // stderr ALSO echo the full presigned URL (curl does not normally, but the detail must be
    // safe even if a future curl/wp did) to prove the redaction.
    let relayedScript = "";
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { script: string };
      relayedScript = body.script;
      const presignedUrl = presignedUrlIn(body.script);
      return jsonResponse({
        code: 22,
        stdout: "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
        stderr: `curl: (22) The requested URL returned error: 403 for ${presignedUrl}`,
      });
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; objectKey: string; exitCode: number; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("db-export");
    expect(body.objectKey).toBe(DB_EXPORT_PARAMS.objectKey);
    expect(body.exitCode).toBe(22);
    expect(body.detail).toMatch(/DB export or upload failed on the cell \(exit 22\)/);
    // The operator sees WHICH step failed and the store's reason ...
    expect(body.detail).toContain("curl: (22)");
    expect(body.detail).toContain("AccessDenied");
    // ... but NEVER the still-valid upload capability or the access-key ID.
    const presignedUrl = presignedUrlIn(relayedScript);
    expect(body.detail).not.toContain(presignedUrl);
    expect(body.detail).not.toMatch(/X-Amz-Signature=[0-9a-f]{64}/);
    expect(body.detail).not.toContain("s3-akid-example");
    expect(body.detail).toContain("[presigned-url]");
  });

  it("db-export: a wp-cli/mysqldump failure (export step) surfaces stderr in the detail", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob();
    const signature = await signAsApp(job, privateKey);
    mockCellAgent({ code: 1, stdout: "", stderr: "Error: Failed to get current SQL modes. Reason: Access denied for user" });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; exitCode: number; detail: string };
    expect(body.ok).toBe(false);
    expect(body.exitCode).toBe(1);
    expect(body.detail).toMatch(/exit 1\) — stderr: Error: Failed to get current SQL modes/);
  });

  it("db-export: a cell-agent 3xx redirect is fail-closed (ok:false), not followed", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob();
    const signature = await signAsApp(job, privateKey);
    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      calls.push(urlOf(input));
      return new Response(null, { status: 302, headers: { location: "https://elsewhere.example/exec" } });
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/redirected unexpectedly \(HTTP 302\)/);
    expect(calls).toEqual(["https://cell.example.test/exec"]);
  });

  it("db-export: a cell-agent 401 becomes a clean ok:false (no bypass)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob();
    const signature = await signAsApp(job, privateKey);
    mockCellAgent({ error: "unauthorized" }, 401);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/rejected CELL_AGENT_TOKEN/);
  });

  it("db-export: a cell-agent 400 (e.g. bad docroot on the VM) surfaces as ok:false, still HTTP 200", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob();
    const signature = await signAsApp(job, privateKey);
    mockCellAgent({ error: "docroot must be under /var/www or /sites/<slug>/public" }, 400);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/cell-agent \/exec failed with HTTP 400/);
  });

  it("db-export: reports a clean failure and touches NOTHING when the S3_* credential is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    for (const missing of ["S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "S3_BUCKET"] as const) {
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ [missing]: undefined }));
      expect(response.status).toBe(200);
      const body = (await response.json()) as { ok: boolean; detail: string };
      expect(body.ok).toBe(false);
      expect(body.detail).toMatch(/S3_ACCESS_KEY_ID \/ S3_SECRET_ACCESS_KEY \/ S3_BUCKET are not configured/);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("db-export: reports a clean failure and touches NO cell-agent when CELL_AGENT_URL/TOKEN are missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ CELL_AGENT_URL: undefined, CELL_AGENT_TOKEN: undefined }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/CELL_AGENT_URL \/ CELL_AGENT_TOKEN are not configured/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("db-export: a signed job with an invalid objectKey is 400 with no presign and no cell-agent call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob({
      params: JSON.stringify({ docroot: "/sites/geelongns/public", objectKey: "../../etc/passwd.sql" }),
    });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/objectKey must be db-exports\//);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("db-export: a valid op given wp-cli's params is 400 with no cell-agent call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbExportJob({ params: JSON.stringify(WP_CLI_PARAMS) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── db-import through the registry ──────────────────────────────────────────────────
  // The reverse of db-export: the Worker presigns a single-object GET with the agency's S3_*
  // credential and relays ONE script to the cell-agent /exec (same relay + CELL_AGENT_TOKEN).
  // Load-bearing assertions: the presigned GET URL is the ONLY store-related thing in the script
  // (no S3 secret), the script DOWNLOADS to a temp FILE BEFORE `wp db import` (so a failed download
  // never half-replaces the DB), the result is small and never echoes the URL, and a non-zero exit
  // is ok:false with the URL redacted.

  /** Pull the single-quoted presigned GET URL back out of the relayed import script. */
  function presignedGetUrlIn(script: string): string {
    const match = /-o "\$T" '([^']+)'/.exec(script);
    if (!match) throw new Error(`no quoted presigned URL in the download step: ${script}`);
    return match[1];
  }

  it("db-import: relays download-to-file -> wp db import to the cell-agent using CELL_AGENT_TOKEN only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbImportJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockCellAgent({ code: 0, stdout: "", stderr: "" });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    // A SMALL result: exactly these four keys — never the dump, never the presigned URL.
    expect(await response.json()).toEqual({
      ok: true,
      op: "db-import",
      objectKey: DB_IMPORT_PARAMS.objectKey,
      exitCode: 0,
    });

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call.url).toBe("https://cell.example.test/exec");
    expect(call.method).toBe("POST");
    // The agency's OWN cell token — never a platform / Cloudflare / S3 credential.
    expect(call.auth).toBe("Bearer cell-token-123");
    expect(call.redirect).toBe("manual");
    expect(call.body.docroot).toBe("/sites/geelongns/public");
    expect(call.body.timeoutMs).toBe(540_000);

    const script = call.body.script ?? "";
    const presignedUrl = presignedGetUrlIn(script);
    // The exact script shape (buildDbImportScript is the single source of truth for it): DOWNLOAD
    // (curl -o) comes BEFORE the import (wp db import), so a failed download aborts under set -e.
    expect(script).toBe(buildDbImportScript(presignedUrl));
    expect(script).toBe(
      "set -eu; " +
        "T=$(mktemp); " +
        `trap 'rm -f "$T"' EXIT INT TERM; ` +
        `curl -sS --fail-with-body -o "$T" '${presignedUrl}'; ` +
        'wp db import "$T"',
    );
    expect(script.indexOf("curl")).toBeLessThan(script.indexOf("wp db import"));

    // The presigned URL is a GET, targets the agency's bucket + the signed objectKey, path-style at
    // the configured endpoint, with the full SigV4 query set and a 600 s expiry.
    const url = new URL(presignedUrl);
    expect(url.origin).toBe("https://acct123.r2.example.test");
    expect(url.pathname).toBe(`/agency-backups/${DB_IMPORT_PARAMS.objectKey}`);
    expect(url.searchParams.get("X-Amz-Algorithm")).toBe("AWS4-HMAC-SHA256");
    expect(url.searchParams.get("X-Amz-Credential")).toMatch(/^s3-akid-example\/\d{8}\/auto\/s3\/aws4_request$/);
    expect(url.searchParams.get("X-Amz-Expires")).toBe("600");
    expect(url.searchParams.get("X-Amz-SignedHeaders")).toBe("host");
    expect(url.searchParams.get("X-Amz-Signature")).toMatch(/^[0-9a-f]{64}$/);
    // NO object-store credential reaches the cell — only the derived URL.
    expect(script).not.toContain("s3-secret-example");
    expect(JSON.stringify(call.body)).not.toContain("s3-secret-example");
  });

  it("db-import: targets AWS virtual-hosted-style when the agency has no S3_ENDPOINT", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbImportJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockCellAgent({ code: 0, stdout: "", stderr: "" });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ S3_ENDPOINT: undefined, S3_REGION: "us-east-1" }),
    );
    expect(response.status).toBe(200);
    const url = new URL(presignedGetUrlIn(calls[0].body.script ?? ""));
    expect(url.host).toBe("agency-backups.s3.us-east-1.amazonaws.com");
    expect(url.pathname).toBe(`/${DB_IMPORT_PARAMS.objectKey}`);
  });

  it("db-import: a NON-ZERO exit is ok:false with the cell's output quoted and the URL redacted", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbImportJob();
    const signature = await signAsApp(job, privateKey);
    // A download rejection: --fail-with-body exits 22; make stderr echo the full presigned URL to
    // prove the redaction (curl does not normally, but the detail must be safe even if it did).
    let relayedScript = "";
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { script: string };
      relayedScript = body.script;
      const presignedUrl = presignedGetUrlIn(body.script);
      return jsonResponse({
        code: 22,
        stdout: "",
        stderr: `curl: (22) The requested URL returned error: 403 for ${presignedUrl}`,
      });
    });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; objectKey: string; exitCode: number; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("db-import");
    expect(body.objectKey).toBe(DB_IMPORT_PARAMS.objectKey);
    expect(body.exitCode).toBe(22);
    expect(body.detail).toMatch(/DB download or import failed on the cell \(exit 22\)/);
    expect(body.detail).toContain("curl: (22)");
    // ... but NEVER the still-valid download capability or the access-key ID.
    const presignedUrl = presignedGetUrlIn(relayedScript);
    expect(body.detail).not.toContain(presignedUrl);
    expect(body.detail).not.toMatch(/X-Amz-Signature=[0-9a-f]{64}/);
    expect(body.detail).not.toContain("s3-akid-example");
    expect(body.detail).toContain("[presigned-url]");
  });

  it("db-import: a cell-agent 401 becomes a clean ok:false (no bypass)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbImportJob();
    const signature = await signAsApp(job, privateKey);
    mockCellAgent({ error: "unauthorized" }, 401);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/rejected CELL_AGENT_TOKEN/);
  });

  it("db-import: reports a clean failure and touches NOTHING when the S3_* credential is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbImportJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    for (const missing of ["S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "S3_BUCKET"] as const) {
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ [missing]: undefined }));
      expect(response.status).toBe(200);
      const body = (await response.json()) as { ok: boolean; detail: string };
      expect(body.ok).toBe(false);
      expect(body.detail).toMatch(/S3_ACCESS_KEY_ID \/ S3_SECRET_ACCESS_KEY \/ S3_BUCKET are not configured/);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("db-import: reports a clean failure and touches NO cell-agent when CELL_AGENT_URL/TOKEN are missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbImportJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ CELL_AGENT_URL: undefined, CELL_AGENT_TOKEN: undefined }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/CELL_AGENT_URL \/ CELL_AGENT_TOKEN are not configured/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("db-import: a signed job with an invalid objectKey is 400 with no presign and no cell-agent call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = dbImportJob({
      params: JSON.stringify({ docroot: "/sites/geelongns/public", objectKey: "../../etc/passwd.sql" }),
    });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/objectKey must be db-exports\//);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
