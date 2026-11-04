// hub#222 — media soft delete, Worker side: the site-facing media API (/media/*) and the six Direction-B ops.
//
// What these tests pin:
//   - every validator refuses a bad key, a trash/ key, a ".." segment, a key outside the site's prefix, unknown
//     fields, and returns ONLY the known keys;
//   - the site API refuses a wrong or missing credential, a credential of ANOTHER bucket, and rate-limits per site;
//   - sign-put returns a presigned PUT that signs if-none-match: * (create-once), the content type and length,
//     with a TTL of at most 15 minutes;
//   - delete / replace / rename copy to trash/<UTC day>/<key> with x-amz-metadata-directive: COPY, then delete;
//     a missing source is a no-op success, and a retry neither copies twice nor overwrites a trash object;
//   - media-bucket-protect keeps every rule it does not own and converges (a re-run writes nothing);
//   - media-site-credential-install posts the derived credential to the file node only, never in the answer;
//   - media-restore is create-once (409 on a target with other bytes) and idempotent on a retry;
//   - media-bulk-credential asks Cloudflare for one bucket, one prefix, object-read-write, the requested TTL;
//   - no answer or error carries MEDIA_SITE_SECRET, the R2 token or its derived S3 secret.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
// @ts-ignore (see test/hub58-ops.test.ts for why this is ignored)
import rawMediaParamsSource from "../src/dispatch-params-media.ts?raw";
import type { Env } from "../src/env.js";
import { DISPATCH_OPS } from "../src/dispatch-verify.js";
import worker from "../src/index.js";
import { DISPATCH_OP_REGISTRY } from "../src/ops.js";
import {
  mediaLiveKeyViolation,
  validateMediaBucketProtectParams,
  validateMediaBulkCredentialParams,
  validateMediaRestoreParams,
  validateMediaSiteCredentialInstallParams,
  validateMediaSiteKeyRevokeParams,
  validateMediaTrashListParams,
} from "../src/dispatch-params-media.js";
import {
  MEDIA_KEY_LEASE_TTL_MS,
  MEDIA_PRESIGN_TTL_SECONDS,
  MEDIA_SITE_RATE_LIMIT_PER_MINUTE,
  mediaSiteCredential,
  verifyMediaSiteCredential,
} from "../src/media-site-api.js";
import { resetMediaStoreIdentityCache } from "../src/media-store.js";
import {
  MEDIA_TRASH_EXPIRE_SECONDS,
  MEDIA_TRASH_LOCK_SECONDS,
  actuateMediaBucketProtect,
  actuateMediaBulkCredential,
  actuateMediaRestore,
  actuateMediaSiteCredentialInstall,
  actuateMediaSiteKeyRevoke,
  readMediaTrashList,
} from "../src/actuate-media.js";
import { presignS3Put } from "../src/sigv4.js";

const mediaParamsSource: string = rawMediaParamsSource as string;
// The app's copy of src/dispatch-params-media.ts pins the SAME value. Change both twins and both pins together.
const MEDIA_PARAMS_SHA256 = "ee158d053e90657e5d10545ac84b73137c64402dff66d020edcc99ff18e12999";

const ACCOUNT_ID = "043e3bdaf4a6849a2d745269084c0e5f";
const R2_TOKEN = "r2-provision-token-must-not-be-echoed";
const R2_TOKEN_ID = "fedcba9876543210fedcba9876543210";
const SITE_SECRET = "media-site-secret-must-never-be-echoed-0123456789";
const BUCKET = "doubleyoup-media-acme";
const OTHER_BUCKET = "doubleyoup-media-other";
const S3_ENDPOINT = `https://${ACCOUNT_ID}.r2.cloudflarestorage.com`;
const CF = "https://api.cloudflare.com/client/v4";
const AGENT_URL = "https://file-agent.example.org";
const AGENT_TOKEN = "file-agent-bearer-must-not-be-echoed";
const JOB_AGENT_URL = "https://cell-region-file.example.org";
const JOB_AGENT_TOKEN = "0123456789abcdef".repeat(4);
const WORKER_URL = "https://agency-worker.example.workers.dev";
const NOW = Date.parse("2026-11-04T10:20:30.000Z");

/** A deterministic hex "MD5" of the bytes for the fake store (FNV-1a, twice, for 16 hex characters). */
function fakeEtag(body: string): string {
  let first = 0x811c9dc5;
  let second = 0x01000193;
  for (let index = 0; index < body.length; index += 1) {
    const code = body.charCodeAt(index);
    first = Math.imul(first ^ code, 0x01000193) >>> 0;
    second = Math.imul(second ^ code, 0x811c9dc5) >>> 0;
  }
  return first.toString(16).padStart(8, "0") + second.toString(16).padStart(8, "0");
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  let hex = "";
  for (const byte of digest) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

// ── a fake R2 (S3 API) + Cloudflare REST API + file-node agent, all behind one fetch mock ─────────────

interface StoredObject {
  etag: string;
  contentType: string;
  body: string;
}

interface Recorded {
  method: string;
  url: string;
  headers: Headers;
  body: string | null;
}

class FakeCloud {
  objects = new Map<string, StoredObject>();
  lifecycleRules: Record<string, unknown>[] = [];
  lockRules: Record<string, unknown>[] = [];
  calls: Recorded[] = [];
  agentReply: { status: number; body: unknown } = { status: 200, body: { ok: true } };
  tokenRecord: { status: number; name?: string } = { status: 200, name: `dy-media-${BUCKET}-a1` };
  tempCredentialReply: { status: number; body: unknown } = {
    status: 200,
    body: { success: true, result: { accessKeyId: "tmp-akid", secretAccessKey: "tmp-secret", sessionToken: "tmp-session" } },
  };
  failNextDelete = false;
  /**
   * Runs before the fake answers each S3 request, so a test can let another writer act at that exact moment (an
   * interleaving). It may await another Worker request.
   */
  beforeS3Answer: ((method: string, key: string, headers: Headers) => Promise<void>) | null = null;

  put(key: string, body: string, contentType = "image/jpeg"): void {
    // The ETag depends on the bytes only, like a real single-part ETag (an MD5): the same bytes uploaded again with
    // another content type keep their ETag.
    this.objects.set(key, { etag: fakeEtag(body), contentType, body });
  }

  /** What a site's presigned create-once PUT does: R2 refuses it (412) when the key exists. */
  presignedUpload(key: string, body: string, contentType = "image/jpeg"): 200 | 412 {
    if (this.objects.has(key)) {
      return 412;
    }
    this.put(key, body, contentType);
    return 200;
  }

  install(): this {
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL, init?: RequestInit) => this.handle(input, init));
    return this;
  }

  async handle(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? init.body : null;
    this.calls.push({ method, url, headers, body });
    if (this.beforeS3Answer !== null && url.startsWith(S3_ENDPOINT)) {
      const key = decodeURIComponent(new URL(url).pathname.split("/").slice(2).join("/"));
      await this.beforeS3Answer(method, key, headers);
    }
    return this.answer(method, url, headers, body);
  }

  s3Calls(): Recorded[] {
    return this.calls.filter((call) => call.url.startsWith(S3_ENDPOINT));
  }

  writes(): string[] {
    const lines: string[] = [];
    for (const call of this.s3Calls()) {
      if (call.method === "PUT" || call.method === "DELETE") {
        const key = decodeURIComponent(new URL(call.url).pathname.split("/").slice(2).join("/"));
        let line = `${call.method} ${key}`;
        const source = call.headers.get("x-amz-copy-source");
        if (source !== null) {
          line += ` <- ${decodeURIComponent(source.split("/").slice(2).join("/"))}`;
        }
        lines.push(line);
      }
    }
    return lines;
  }

  private cfJson(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }

  private answer(method: string, url: string, headers: Headers, body: string | null): Response {
    if (url === `${CF}/accounts?per_page=1`) {
      return this.cfJson({ success: true, result: [{ id: ACCOUNT_ID }] });
    }
    if (url === `${CF}/accounts/${ACCOUNT_ID}/tokens/verify`) {
      return this.cfJson({ success: true, result: { id: R2_TOKEN_ID, status: "active" } });
    }
    const bucketApi = `${CF}/accounts/${ACCOUNT_ID}/r2/buckets/${BUCKET}/`;
    if (url === `${bucketApi}lifecycle` || url === `${bucketApi}lock`) {
      const isLifecycle = url.endsWith("lifecycle");
      if (method === "GET") {
        return this.cfJson({ success: true, result: { rules: isLifecycle ? this.lifecycleRules : this.lockRules } });
      }
      const rules = (JSON.parse(body ?? "{}") as { rules: Record<string, unknown>[] }).rules;
      if (isLifecycle) {
        this.lifecycleRules = rules;
      } else {
        this.lockRules = rules;
      }
      return this.cfJson({ success: true, result: {} });
    }
    if (url === `${CF}/accounts/${ACCOUNT_ID}/r2/temp-access-credentials`) {
      return this.cfJson(this.tempCredentialReply.body, this.tempCredentialReply.status);
    }
    if (url.startsWith(`${CF}/accounts/${ACCOUNT_ID}/tokens/`)) {
      if (this.tokenRecord.status === 404) {
        return this.cfJson({ success: false, errors: [{ code: 1003, message: "not found" }] }, 404);
      }
      if (method === "GET") {
        return this.cfJson({ success: true, result: { id: "x", name: this.tokenRecord.name } });
      }
      return this.cfJson({ success: true, result: { id: "x" } });
    }
    if (url.startsWith(AGENT_URL) || url.startsWith(JOB_AGENT_URL)) {
      return this.cfJson(this.agentReply.body, this.agentReply.status);
    }
    if (url.startsWith(S3_ENDPOINT)) {
      return this.answerS3(method, url, headers);
    }
    return new Response("unexpected", { status: 599 });
  }

  private answerS3(method: string, url: string, headers: Headers): Response {
    const parsed = new URL(url);
    const segments = parsed.pathname.split("/");
    const bucket = segments[1];
    const key = decodeURIComponent(segments.slice(2).join("/"));
    if (bucket !== BUCKET) {
      return new Response("<Error><Code>AccessDenied</Code></Error>", { status: 403 });
    }
    if (method === "GET" && key === "") {
      return this.answerList(parsed);
    }
    const existing = this.objects.get(key);
    if (method === "HEAD") {
      if (existing === undefined) {
        return new Response(null, { status: 404 });
      }
      return new Response(null, {
        status: 200,
        headers: { etag: `"${existing.etag}"`, "content-type": existing.contentType, "content-length": String(existing.body.length) },
      });
    }
    if (method === "PUT") {
      const copySource = headers.get("x-amz-copy-source");
      if (copySource === null) {
        return new Response("<Error><Code>NotImplemented</Code></Error>", { status: 501 });
      }
      const sourceKey = decodeURIComponent(copySource.split("/").slice(2).join("/"));
      const source = this.objects.get(sourceKey);
      if (source === undefined) {
        return new Response("<Error><Code>NoSuchKey</Code></Error>", { status: 404 });
      }
      const ifMatch = headers.get("x-amz-copy-source-if-match");
      if (ifMatch !== null && ifMatch !== `"${source.etag}"`) {
        return new Response("<Error><Code>PreconditionFailed</Code></Error>", { status: 412 });
      }
      if (headers.get("cf-copy-destination-if-none-match") === "*" && existing !== undefined) {
        // R2 checks the destination condition when it commits the copy.
        return new Response("<Error><Code>PreconditionFailed</Code></Error>", { status: 412 });
      }
      if (key.startsWith("trash/") && existing !== undefined) {
        // The bucket lock: a trash object can not be overwritten.
        return new Response("<Error><Code>ObjectLockedByBucketPolicy</Code></Error>", { status: 409 });
      }
      let contentType = source.contentType;
      if (headers.get("x-amz-metadata-directive") !== "COPY") {
        contentType = "application/octet-stream";
      }
      this.objects.set(key, { etag: source.etag, contentType, body: source.body });
      return new Response("<CopyObjectResult><ETag>x</ETag></CopyObjectResult>", { status: 200 });
    }
    if (method === "DELETE") {
      if (this.failNextDelete) {
        this.failNextDelete = false;
        return new Response("<Error><Code>InternalError</Code></Error>", { status: 500 });
      }
      this.objects.delete(key);
      return new Response(null, { status: 204 });
    }
    return new Response("unexpected", { status: 599 });
  }

  private answerList(parsed: URL): Response {
    const prefix = parsed.searchParams.get("prefix") ?? "";
    const maxKeys = Number(parsed.searchParams.get("max-keys") ?? "1000");
    const start = Number(parsed.searchParams.get("continuation-token") ?? "0");
    const keys = [...this.objects.keys()].filter((key) => key.startsWith(prefix)).sort();
    const page = keys.slice(start, start + maxKeys);
    let xml = "<ListBucketResult>";
    for (const key of page) {
      const object = this.objects.get(key) as StoredObject;
      xml += `<Contents><Key>${key.replace(/&/g, "&amp;")}</Key><Size>${object.body.length}</Size><ETag>&quot;${object.etag}&quot;</ETag><LastModified>2026-11-04T00:00:00.000Z</LastModified></Contents>`;
    }
    const truncated = start + maxKeys < keys.length;
    xml += `<IsTruncated>${truncated}</IsTruncated>`;
    if (truncated) {
      xml += `<NextContinuationToken>${start + maxKeys}</NextContinuationToken>`;
    }
    xml += "</ListBucketResult>";
    return new Response(xml, { status: 200 });
  }
}

class FakeRateStore {
  counts = new Map<string, number>();
  leases = new Map<string, { holder: string; expiresAt: number }>();
  acquireLease(leaseKey: string, holder: string, ttlMs: number): "acquired" | "busy" {
    const held = this.leases.get(leaseKey);
    if (held !== undefined && held.expiresAt > Date.now()) {
      return "busy";
    }
    this.leases.set(leaseKey, { holder, expiresAt: Date.now() + ttlMs });
    return "acquired";
  }
  releaseLease(leaseKey: string, holder: string): void {
    if (this.leases.get(leaseKey)?.holder === holder) {
      this.leases.delete(leaseKey);
    }
  }
  countRequest(rateKey: string, _windowMs: number, limit: number): { allowed: true } | { allowed: false; retryAfterMs: number } {
    const count = this.counts.get(rateKey) ?? 0;
    if (count >= limit) {
      return { allowed: false, retryAfterMs: 12_000 };
    }
    this.counts.set(rateKey, count + 1);
    return { allowed: true };
  }
}

function fakeNonceStore(): { namespace: unknown; instances: Map<string, FakeRateStore> } {
  const instances = new Map<string, FakeRateStore>();
  const namespace = {
    idFromName: (name: string) => name,
    get: (id: string) => {
      let store = instances.get(id);
      if (store === undefined) {
        store = new FakeRateStore();
        instances.set(id, store);
      }
      return store;
    },
  };
  return { namespace, instances };
}

function env(overrides: Partial<Env> = {}): Env {
  const nonce = fakeNonceStore();
  return {
    R2_PROVISION_API_TOKEN: R2_TOKEN,
    MEDIA_SITE_SECRET: SITE_SECRET,
    CELL_FILE_AGENT_URL: AGENT_URL,
    CELL_FILE_AGENT_TOKEN: AGENT_TOKEN,
    NONCE_STORE: nonce.namespace,
    ...overrides,
  } as unknown as Env;
}

async function siteRequest(action: string, body: unknown, credential: string | null, workerEnv: Env): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (credential !== null) {
    headers.authorization = `Bearer ${credential}`;
  }
  const request = new Request(`https://worker.example/media/${action}`, { method: "POST", headers, body: JSON.stringify(body) });
  return worker.fetch(request, workerEnv);
}

async function expectNoSecrets(value: unknown): Promise<void> {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  expect(text).not.toContain(SITE_SECRET);
  expect(text).not.toContain(R2_TOKEN);
  expect(text).not.toContain(await sha256Hex(R2_TOKEN));
  expect(text).not.toContain(AGENT_TOKEN);
}

beforeEach(() => {
  resetMediaStoreIdentityCache();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ── registry + twin ────────────────────────────────────────────────────────────────────────────────────

describe("hub#222 registry and twin", () => {
  it("all six ops are allowlisted and registered", () => {
    const ops = [
      "media-bucket-protect",
      "media-site-credential-install",
      "media-site-key-revoke",
      "media-trash-list",
      "media-restore",
      "media-bulk-credential",
    ] as const;
    for (const op of ops) {
      expect(DISPATCH_OPS).toContain(op);
      expect(typeof DISPATCH_OP_REGISTRY[op].validateParams).toBe("function");
      expect(typeof DISPATCH_OP_REGISTRY[op].actuate).toBe("function");
    }
  });

  it("dispatch-params-media.ts is byte-identical with the app copy (pinned sha256: change BOTH twins and BOTH pins)", async () => {
    expect(await sha256Hex(mediaParamsSource)).toBe(MEDIA_PARAMS_SHA256);
  });

  it("dispatch-params-media.ts imports nothing, so the same bytes compile in the app", () => {
    expect(mediaParamsSource).not.toMatch(/^import /m);
  });
});

// ── validators ─────────────────────────────────────────────────────────────────────────────────────────

describe("hub#222 key rules", () => {
  it("accepts a key under the site's prefix", () => {
    expect(mediaLiveKeyViolation(BUCKET, "acme/2026/11/photo.jpg", "key")).toBeNull();
    expect(mediaLiveKeyViolation(BUCKET, "acme/2026/11/a..b.jpg", "key")).toBeNull();
    expect(mediaLiveKeyViolation(BUCKET, "acme/2026/11/ünïcode file.jpg", "key")).toBeNull();
  });

  it.each([
    ["trash/2026-11-04/acme/a.jpg", "trash/"],
    ["acme/trash/a.jpg", "trash/"],
    ["acme/../other/a.jpg", ".."],
    ["acme/./a.jpg", "\".\""],
    ["/acme/a.jpg", "empty segment"],
    ["acme//a.jpg", "empty segment"],
    ["other/a.jpg", "site's prefix"],
    ["acmex/a.jpg", "site's prefix"],
    ["acme/", "empty segment"],
    ["acme", "site's prefix"],
    ["acme/a\\b.jpg", "backslash"],
    ["acme/a\nb.jpg", "control character"],
    ["", "empty"],
  ])("refuses %j", (key, fragment) => {
    const violation = mediaLiveKeyViolation(BUCKET, key, "key");
    expect(violation).not.toBeNull();
    expect(violation).toContain(fragment);
  });

  it("refuses a key that is too long and a key that is not a string", () => {
    expect(mediaLiveKeyViolation(BUCKET, `acme/${"a".repeat(900)}`, "key")).toContain("at most");
    expect(mediaLiveKeyViolation(BUCKET, 42, "key")).toContain("string");
  });
});

describe("hub#222 Direction-B validators", () => {
  it("media-bucket-protect: a media bucket only, no other field", () => {
    expect(validateMediaBucketProtectParams({ bucket: BUCKET })).toEqual({ ok: true, params: { bucket: BUCKET } });
    expect(validateMediaBucketProtectParams({ bucket: "agency-backups" }).ok).toBe(false);
    expect(validateMediaBucketProtectParams({ bucket: "doubleyoup-media-trash" }).ok).toBe(false);
    expect(validateMediaBucketProtectParams({ bucket: BUCKET, rules: [] }).ok).toBe(false);
    expect(validateMediaBucketProtectParams([BUCKET]).ok).toBe(false);
  });

  it("media-site-credential-install: slug, bucket, https worker origin; the agent pair goes together", () => {
    const base = { slug: "acme", bucket: BUCKET, workerUrl: WORKER_URL };
    expect(validateMediaSiteCredentialInstallParams(base)).toEqual({ ok: true, params: base });
    const withAgent = { ...base, fileAgentUrl: JOB_AGENT_URL, fileAgentToken: JOB_AGENT_TOKEN };
    expect(validateMediaSiteCredentialInstallParams(withAgent)).toEqual({ ok: true, params: withAgent });
    expect(validateMediaSiteCredentialInstallParams({ ...base, fileAgentUrl: JOB_AGENT_URL }).ok).toBe(false);
    expect(validateMediaSiteCredentialInstallParams({ ...base, workerUrl: "http://agency.example" }).ok).toBe(false);
    expect(validateMediaSiteCredentialInstallParams({ ...base, workerUrl: `${WORKER_URL}/` }).ok).toBe(false);
    expect(validateMediaSiteCredentialInstallParams({ ...base, workerUrl: `${WORKER_URL}/media` }).ok).toBe(false);
    expect(validateMediaSiteCredentialInstallParams({ ...base, slug: "Acme" }).ok).toBe(false);
    // The credential is derived on the Worker: a job can never carry one.
    expect(validateMediaSiteCredentialInstallParams({ ...base, token: "x" }).ok).toBe(false);
  });

  it("media-site-key-revoke: slug, bucket and a 32-hex token id", () => {
    const params = { slug: "acme", bucket: BUCKET, tokenId: R2_TOKEN_ID };
    expect(validateMediaSiteKeyRevokeParams(params)).toEqual({ ok: true, params });
    expect(validateMediaSiteKeyRevokeParams({ ...params, tokenId: "nope" }).ok).toBe(false);
    expect(validateMediaSiteKeyRevokeParams({ ...params, bucket: "agency-backups" }).ok).toBe(false);
  });

  it("media-trash-list: optional relative prefix and cursor", () => {
    expect(validateMediaTrashListParams({ bucket: BUCKET })).toEqual({ ok: true, params: { bucket: BUCKET } });
    expect(validateMediaTrashListParams({ bucket: BUCKET, prefix: "" })).toEqual({ ok: true, params: { bucket: BUCKET } });
    expect(validateMediaTrashListParams({ bucket: BUCKET, prefix: "2026-11-04/", cursor: "abc=" })).toEqual({
      ok: true,
      params: { bucket: BUCKET, prefix: "2026-11-04/", cursor: "abc=" },
    });
    expect(validateMediaTrashListParams({ bucket: BUCKET, prefix: "../" }).ok).toBe(false);
    expect(validateMediaTrashListParams({ bucket: BUCKET, prefix: "/x" }).ok).toBe(false);
    expect(validateMediaTrashListParams({ bucket: BUCKET, cursor: "has space" }).ok).toBe(false);
  });

  it("media-restore: a trash key, and a target under the site's prefix (default: the original key)", () => {
    expect(validateMediaRestoreParams({ bucket: BUCKET, trashKey: "trash/2026-11-04/acme/a.jpg" })).toEqual({
      ok: true,
      params: { bucket: BUCKET, trashKey: "trash/2026-11-04/acme/a.jpg", targetKey: "acme/a.jpg" },
    });
    expect(validateMediaRestoreParams({ bucket: BUCKET, trashKey: "trash/2026-11-04.etag9/acme/a.jpg" })).toEqual({
      ok: true,
      params: { bucket: BUCKET, trashKey: "trash/2026-11-04.etag9/acme/a.jpg", targetKey: "acme/a.jpg" },
    });
    expect(validateMediaRestoreParams({ bucket: BUCKET, trashKey: "acme/a.jpg" }).ok).toBe(false);
    expect(validateMediaRestoreParams({ bucket: BUCKET, trashKey: "trash/a.jpg" }).ok).toBe(false);
    expect(validateMediaRestoreParams({ bucket: BUCKET, trashKey: "trash/2026-11-04/../x" }).ok).toBe(false);
    // The default target of another site's trash key is outside this site's prefix.
    expect(validateMediaRestoreParams({ bucket: BUCKET, trashKey: "trash/2026-11-04/other/a.jpg" }).ok).toBe(false);
    expect(validateMediaRestoreParams({ bucket: BUCKET, trashKey: "trash/2026-11-04/acme/a.jpg", targetKey: "trash/x/acme/a.jpg" }).ok).toBe(false);
  });

  it("media-bulk-credential: the site prefix or a folder under it, ttl 60..43200", () => {
    const params = { bucket: BUCKET, prefix: "acme/", ttlSeconds: 43200 };
    expect(validateMediaBulkCredentialParams(params)).toEqual({ ok: true, params });
    expect(validateMediaBulkCredentialParams({ ...params, prefix: "acme/2024/" }).ok).toBe(true);
    expect(validateMediaBulkCredentialParams({ ...params, ttlSeconds: 43201 }).ok).toBe(false);
    expect(validateMediaBulkCredentialParams({ ...params, ttlSeconds: 59 }).ok).toBe(false);
    expect(validateMediaBulkCredentialParams({ ...params, ttlSeconds: 600.5 }).ok).toBe(false);
    expect(validateMediaBulkCredentialParams({ ...params, prefix: "acme" }).ok).toBe(false);
    expect(validateMediaBulkCredentialParams({ ...params, prefix: "" }).ok).toBe(false);
    expect(validateMediaBulkCredentialParams({ ...params, prefix: "trash/" }).ok).toBe(false);
    expect(validateMediaBulkCredentialParams({ ...params, prefix: "acme/trash/" }).ok).toBe(false);
    expect(validateMediaBulkCredentialParams({ ...params, prefix: "acme/../" }).ok).toBe(false);
    expect(validateMediaBulkCredentialParams({ ...params, prefix: "other/" }).ok).toBe(false);
  });
});

// ── the site credential ────────────────────────────────────────────────────────────────────────────────

describe("hub#222 site credential", () => {
  it("is HMAC-SHA256(secret, bucket) in hex, and verifies only for its own bucket", async () => {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SITE_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(BUCKET)));
    let expectedHex = "";
    for (const byte of expected) {
      expectedHex += byte.toString(16).padStart(2, "0");
    }
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    expect(credential).toBe(expectedHex);
    expect(await verifyMediaSiteCredential(SITE_SECRET, BUCKET, credential)).toBe(true);
    expect(await verifyMediaSiteCredential(SITE_SECRET, OTHER_BUCKET, credential)).toBe(false);
    expect(await verifyMediaSiteCredential(SITE_SECRET, BUCKET, credential.toUpperCase())).toBe(false);
    expect(await verifyMediaSiteCredential(SITE_SECRET, BUCKET, credential.slice(0, 63))).toBe(false);
  });
});

// ── sigv4: the create-once presign ────────────────────────────────────────────────────────────────────

describe("hub#222 presigned create-once PUT", () => {
  it("signs if-none-match, content-type and content-length next to host", async () => {
    const presigned = await presignS3Put({
      endpoint: S3_ENDPOINT,
      bucket: BUCKET,
      region: "auto",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "SECRETEXAMPLE",
      key: "acme/2026/11/a b.jpg",
      expiresSeconds: 600,
      nowMs: NOW,
      signedHeaders: { "If-None-Match": "*", "content-type": "image/jpeg", "content-length": "12" },
    });
    const url = new URL(presigned.url);
    expect(url.searchParams.get("X-Amz-SignedHeaders")).toBe("content-length;content-type;host;if-none-match");
    expect(presigned.canonicalRequest).toContain("\nif-none-match:*\n");
    expect(presigned.canonicalRequest).toContain("\ncontent-type:image/jpeg\n");
    expect(url.pathname).toBe(`/${BUCKET}/acme/2026/11/a%20b.jpg`);
  });
});

// ── the site-facing API ────────────────────────────────────────────────────────────────────────────────

describe("hub#222 /media/* auth and limits", () => {
  it("refuses a missing, wrong or other-bucket credential before touching R2", async () => {
    const fake = new FakeCloud().install();
    const workerEnv = env();
    const otherCredential = await mediaSiteCredential(SITE_SECRET, OTHER_BUCKET);
    const body = { bucket: BUCKET, key: "acme/a.jpg" };
    expect((await siteRequest("delete", body, null, workerEnv)).status).toBe(401);
    expect((await siteRequest("delete", body, "0".repeat(64), workerEnv)).status).toBe(401);
    expect((await siteRequest("delete", body, otherCredential, workerEnv)).status).toBe(401);
    expect((await siteRequest("delete", body, "not-hex", workerEnv)).status).toBe(401);
    expect(fake.calls).toEqual([]);
  });

  it("answers 503 when MEDIA_SITE_SECRET is unset or too short", async () => {
    new FakeCloud().install();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const unset = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.jpg" }, credential, env({ MEDIA_SITE_SECRET: undefined }));
    expect(unset.status).toBe(503);
    const short = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.jpg" }, credential, env({ MEDIA_SITE_SECRET: "short" }));
    expect(short.status).toBe(503);
  });

  it("rate-limits per bucket, after the credential check", async () => {
    new FakeCloud().install();
    const nonce = fakeNonceStore();
    const workerEnv = env({ NONCE_STORE: nonce.namespace as Env["NONCE_STORE"] });
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const store = new FakeRateStore();
    store.counts.set(BUCKET, MEDIA_SITE_RATE_LIMIT_PER_MINUTE);
    nonce.instances.set(`media-rate:${BUCKET}`, store);

    const wrong = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.jpg" }, "0".repeat(64), workerEnv);
    expect(wrong.status).toBe(401);
    const limited = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.jpg" }, credential, workerEnv);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("12");

    // Another site has its own counter.
    const otherCredential = await mediaSiteCredential(SITE_SECRET, OTHER_BUCKET);
    const other = await siteRequest("sign-put", { bucket: OTHER_BUCKET, key: "other/a.jpg", contentType: "image/png", contentLength: 1 }, otherCredential, workerEnv);
    expect(other.status).toBe(200);
  });

  it("refuses bad keys, trash keys and unknown fields with 400", async () => {
    const fake = new FakeCloud().install();
    const workerEnv = env();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const cases: Array<[string, unknown]> = [
      ["sign-put", { bucket: BUCKET, key: "trash/2026-11-04/acme/a.jpg", contentType: "image/jpeg", contentLength: 1 }],
      ["sign-put", { bucket: BUCKET, key: "acme/../other/a.jpg", contentType: "image/jpeg", contentLength: 1 }],
      ["sign-put", { bucket: BUCKET, key: "other/a.jpg", contentType: "image/jpeg", contentLength: 1 }],
      ["sign-put", { bucket: BUCKET, key: "acme/a.jpg", contentType: "image/jpeg\r\nx: y", contentLength: 1 }],
      ["sign-put", { bucket: BUCKET, key: "acme/a.jpg", contentType: "image/jpeg", contentLength: -1 }],
      ["delete", { bucket: BUCKET, key: "trash/2026-11-04/acme/a.jpg" }],
      ["delete", { bucket: BUCKET, key: "acme/a.jpg", force: true }],
      ["rename", { bucket: BUCKET, from: "acme/a.jpg", to: "trash/x/acme/a.jpg" }],
      ["rename", { bucket: BUCKET, from: "acme/a.jpg", to: "acme/a.jpg" }],
      ["replace", { bucket: BUCKET, key: "acme/trash/a.jpg", contentType: "image/jpeg", contentLength: 1 }],
    ];
    for (const [action, body] of cases) {
      const response = await siteRequest(action, body, credential, workerEnv);
      expect(response.status, `${action} ${JSON.stringify(body)}`).toBe(400);
    }
    expect(fake.s3Calls()).toEqual([]);
  });

  it("refuses a body over 16 KiB without reading it whole", async () => {
    const fake = new FakeCloud().install();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.jpg", padding: "x".repeat(20_000) }, credential, env());
    expect(response.status).toBe(400);
    expect(fake.calls).toEqual([]);
  });

  it("an unknown /media/ action is a 404", async () => {
    new FakeCloud().install();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("purge", { bucket: BUCKET }, credential, env());
    expect(response.status).toBe(404);
  });
});

describe("hub#222 /media/sign-put", () => {
  it("returns a create-once presigned PUT of at most 15 minutes, and writes nothing", async () => {
    const fake = new FakeCloud().install();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("sign-put", { bucket: BUCKET, key: "acme/2026/11/a.jpg", contentType: "image/jpeg", contentLength: 1234 }, credential, env());
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = (await response.json()) as { ok: boolean; upload: { method: string; url: string; headers: Record<string, string>; expiresAt: string } };
    expect(body.ok).toBe(true);
    expect(body.upload.method).toBe("PUT");
    expect(body.upload.headers).toEqual({ "content-length": "1234", "content-type": "image/jpeg", "if-none-match": "*" });
    const url = new URL(body.upload.url);
    expect(url.origin).toBe(S3_ENDPOINT);
    expect(url.pathname).toBe(`/${BUCKET}/acme/2026/11/a.jpg`);
    expect(Number(url.searchParams.get("X-Amz-Expires"))).toBe(MEDIA_PRESIGN_TTL_SECONDS);
    expect(MEDIA_PRESIGN_TTL_SECONDS).toBeLessThanOrEqual(900);
    expect(url.searchParams.get("X-Amz-SignedHeaders")).toContain("if-none-match");
    expect(url.searchParams.get("X-Amz-Credential")).toMatch(new RegExp(`^${R2_TOKEN_ID}/`));
    expect(Date.parse(body.upload.expiresAt) - NOW).toBe(MEDIA_PRESIGN_TTL_SECONDS * 1000);
    expect(fake.writes()).toEqual([]);
    await expectNoSecrets(body);
  });
});

describe("hub#222 /media/sign-put header values", () => {
  it("returns the content type as SigV4 signs it (inner whitespace collapsed), so the upload matches its signature", async () => {
    new FakeCloud().install();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("sign-put", { bucket: BUCKET, key: "acme/a.txt", contentType: "text/plain;  charset=utf-8", contentLength: 5 }, credential, env());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { upload: { headers: Record<string, string> } };
    expect(body.upload.headers["content-type"]).toBe("text/plain; charset=utf-8");
  });
});

describe("hub#222 /media/delete", () => {
  it("copies to trash/<UTC day>/<key> keeping the content type, then deletes", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/a.png", "png-bytes", "image/png");
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.png" }, credential, env());
    const body = (await response.json()) as Record<string, unknown>;
    expect(response.status).toBe(200);
    expect(body).toMatchObject({ ok: true, status: "trashed", trashKey: "trash/2026-11-04/acme/a.png" });
    expect(fake.writes()).toEqual(["PUT trash/2026-11-04/acme/a.png <- acme/a.png", "DELETE acme/a.png"]);
    const copy = fake.s3Calls().find((call) => call.method === "PUT");
    expect(copy?.headers.get("x-amz-metadata-directive")).toBe("COPY");
    expect(copy?.headers.get("x-amz-copy-source-if-match")).toBe(`"${fakeEtag("png-bytes")}"`);
    expect(copy?.headers.get("cf-copy-destination-if-none-match")).toBe("*");
    expect(copy?.headers.get("authorization")).toContain("cf-copy-destination-if-none-match");
    expect(copy?.headers.get("authorization")).toContain("x-amz-copy-source");
    expect(fake.objects.get("trash/2026-11-04/acme/a.png")?.contentType).toBe("image/png");
    expect(fake.objects.has("acme/a.png")).toBe(false);
  });

  it("a missing source is a no-op success", async () => {
    const fake = new FakeCloud().install();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("delete", { bucket: BUCKET, key: "acme/gone.png" }, credential, env());
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ ok: true, status: "already-absent", trashKey: null });
    expect(fake.writes()).toEqual([]);
  });

  it("a retry after a failed delete reuses the trash copy instead of copying again", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/a.png", "png-bytes", "image/png");
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const workerEnv = env();
    fake.failNextDelete = true;
    const first = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.png" }, credential, workerEnv);
    expect(first.status).toBe(502);
    expect(fake.objects.has("acme/a.png")).toBe(true);
    // R2 may still apply the failed DELETE, so the key stays held until the lease expires.
    const tooSoon = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.png" }, credential, workerEnv);
    expect(tooSoon.status).toBe(409);
    vi.setSystemTime(NOW + MEDIA_KEY_LEASE_TTL_MS + 1);
    const second = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.png" }, credential, workerEnv);
    expect(second.status).toBe(200);
    expect(fake.writes()).toEqual([
      "PUT trash/2026-11-04/acme/a.png <- acme/a.png",
      "DELETE acme/a.png",
      "DELETE acme/a.png",
    ]);
  });

  it("the same key deleted twice in one day goes to a second trash folder, never over the locked first copy", async () => {
    const fake = new FakeCloud().install();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const workerEnv = env();
    fake.put("acme/a.png", "first", "image/png");
    await siteRequest("delete", { bucket: BUCKET, key: "acme/a.png" }, credential, workerEnv);
    fake.put("acme/a.png", "second", "image/png");
    const response = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.png" }, credential, workerEnv);
    const body = (await response.json()) as { ok: boolean; trashKey: string };
    expect(body.ok).toBe(true);
    expect(body.trashKey).toMatch(/^trash\/2026-11-04\.[a-f0-9]{32}\/acme\/a\.png$/);
    expect(fake.objects.get("trash/2026-11-04/acme/a.png")?.body).toBe("first");
    expect(fake.objects.get(body.trashKey)?.body).toBe("second");
  });

  it("the same bytes with another content type are a new revision: both get a trash copy", async () => {
    const fake = new FakeCloud().install();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const workerEnv = env();
    fake.put("acme/a.jpg", "same-bytes", "application/octet-stream");
    await siteRequest("delete", { bucket: BUCKET, key: "acme/a.jpg" }, credential, workerEnv);
    fake.put("acme/a.jpg", "same-bytes", "image/jpeg");
    expect(fake.objects.get("acme/a.jpg")?.etag).toBe(fake.objects.get("trash/2026-11-04/acme/a.jpg")?.etag);

    const response = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.jpg" }, credential, workerEnv);
    const body = (await response.json()) as { ok: boolean; status: string; trashKey: string };
    expect(body).toMatchObject({ ok: true, status: "trashed" });
    expect(body.trashKey).not.toBe("trash/2026-11-04/acme/a.jpg");
    expect(fake.objects.get("trash/2026-11-04/acme/a.jpg")?.contentType).toBe("application/octet-stream");
    expect(fake.objects.get(body.trashKey)?.contentType).toBe("image/jpeg");
    expect(fake.objects.has("acme/a.jpg")).toBe(false);
  });

  it("a second request for the same key waits its turn: a replace during a delete changes nothing (409)", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/a.png", "v1", "image/png");
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const workerEnv = env();
    let competing: Response | null = null;
    let uploadStatus: number | null = null;
    fake.beforeS3Answer = async (method, key) => {
      if (method !== "DELETE" || key !== "acme/a.png" || competing !== null) {
        return;
      }
      // Request A has copied v1 to trash and is about to delete. Request B tries to replace the same key, and a
      // presigned upload of v2 races in.
      competing = await siteRequest("replace", { bucket: BUCKET, key: "acme/a.png", contentType: "image/png", contentLength: 2 }, credential, workerEnv);
      uploadStatus = fake.presignedUpload("acme/a.png", "v2", "image/png");
    };
    const response = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.png" }, credential, workerEnv);
    expect(response.status).toBe(200);
    expect((competing as Response | null)?.status).toBe(409);
    // v1 still existed when the upload raced in, so create-once refused it: no version was lost unseen.
    expect(uploadStatus).toBe(412);
    expect(fake.objects.get("trash/2026-11-04/acme/a.png")?.body).toBe("v1");
    expect(fake.writes()).toEqual(["PUT trash/2026-11-04/acme/a.png <- acme/a.png", "DELETE acme/a.png"]);
  });

  it("a request that took too long after its trash copy does not delete (its lease may have expired)", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/a.png", "v1", "image/png");
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    fake.beforeS3Answer = async (method, key) => {
      if (method === "PUT" && key.startsWith("trash/")) {
        vi.setSystemTime(NOW + MEDIA_KEY_LEASE_TTL_MS - 1000);
      }
    };
    const response = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.png" }, credential, env());
    expect(response.status).toBe(503);
    expect(fake.objects.get("acme/a.png")?.body).toBe("v1");
    expect(fake.objects.get("trash/2026-11-04/acme/a.png")?.body).toBe("v1");
    expect(fake.writes()).toEqual(["PUT trash/2026-11-04/acme/a.png <- acme/a.png"]);
  });

  it("an object that changes between the HEAD and the copy is not deleted (409)", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/a.png", "v1");
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await fake.handle(input, init);
      if ((init?.method ?? "GET") === "HEAD" && String(input).endsWith("/acme/a.png")) {
        fake.put("acme/a.png", "v2");
      }
      return response;
    });
    const response = await siteRequest("delete", { bucket: BUCKET, key: "acme/a.png" }, credential, env());
    expect(response.status).toBe(409);
    expect(fake.objects.get("acme/a.png")?.body).toBe("v2");
  });
});

describe("hub#222 /media/replace", () => {
  it("moves the current object to trash, deletes it, then returns a create-once PUT", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/a.jpg", "old");
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("replace", { bucket: BUCKET, key: "acme/a.jpg", contentType: "image/jpeg", contentLength: 3 }, credential, env());
    const body = (await response.json()) as { previous: string; trashKey: string; upload: { headers: Record<string, string> } };
    expect(response.status).toBe(200);
    expect(body.previous).toBe("trashed");
    expect(body.trashKey).toBe("trash/2026-11-04/acme/a.jpg");
    expect(body.upload.headers["if-none-match"]).toBe("*");
    expect(fake.writes()).toEqual(["PUT trash/2026-11-04/acme/a.jpg <- acme/a.jpg", "DELETE acme/a.jpg"]);
    await expectNoSecrets(body);
  });

  it("with no current object it is a plain create-once PUT (a retry after the move)", async () => {
    const fake = new FakeCloud().install();
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("replace", { bucket: BUCKET, key: "acme/a.jpg", contentType: "image/jpeg", contentLength: 3 }, credential, env());
    expect(await response.json()).toMatchObject({ ok: true, previous: "already-absent", trashKey: null });
    expect(fake.writes()).toEqual([]);
  });
});

describe("hub#222 /media/rename", () => {
  it("copies from -> to, moves from to trash, deletes from", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/old.jpg", "bytes", "image/jpeg");
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("rename", { bucket: BUCKET, from: "acme/old.jpg", to: "acme/new.jpg" }, credential, env());
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ ok: true, status: "renamed", trashKey: "trash/2026-11-04/acme/old.jpg" });
    expect(fake.writes()).toEqual([
      "PUT acme/new.jpg <- acme/old.jpg",
      "PUT trash/2026-11-04/acme/old.jpg <- acme/old.jpg",
      "DELETE acme/old.jpg",
    ]);
    expect(fake.objects.get("acme/new.jpg")?.contentType).toBe("image/jpeg");
  });

  it("never overwrites a target that a presigned upload creates after the target HEAD (409, R2 refuses the copy)", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/old.jpg", "a");
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    fake.beforeS3Answer = async (method, key, headers) => {
      if (method === "PUT" && key === "acme/new.jpg" && headers.get("x-amz-copy-source") !== null) {
        expect(fake.presignedUpload("acme/new.jpg", "uploaded", "image/png")).toBe(200);
      }
    };
    const response = await siteRequest("rename", { bucket: BUCKET, from: "acme/old.jpg", to: "acme/new.jpg" }, credential, env());
    expect(response.status).toBe(409);
    expect(fake.objects.get("acme/new.jpg")?.body).toBe("uploaded");
    expect(fake.objects.get("acme/new.jpg")?.contentType).toBe("image/png");
    expect(fake.objects.get("acme/old.jpg")?.body).toBe("a");
    expect(fake.writes()).toEqual(["PUT acme/new.jpg <- acme/old.jpg"]);
  });

  it("never overwrites a target with other bytes (409)", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/old.jpg", "a");
    fake.put("acme/new.jpg", "b");
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const response = await siteRequest("rename", { bucket: BUCKET, from: "acme/old.jpg", to: "acme/new.jpg" }, credential, env());
    expect(response.status).toBe(409);
    expect(fake.writes()).toEqual([]);
  });

  it("a retry whose copy already landed skips the copy; a finished rename is a no-op", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/old.jpg", "a");
    const source = fake.objects.get("acme/old.jpg") as StoredObject;
    fake.objects.set("acme/new.jpg", { ...source });
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    const workerEnv = env();
    const retry = await siteRequest("rename", { bucket: BUCKET, from: "acme/old.jpg", to: "acme/new.jpg" }, credential, workerEnv);
    expect(retry.status).toBe(200);
    expect(fake.writes()).toEqual(["PUT trash/2026-11-04/acme/old.jpg <- acme/old.jpg", "DELETE acme/old.jpg"]);
    const again = await siteRequest("rename", { bucket: BUCKET, from: "acme/old.jpg", to: "acme/new.jpg" }, credential, workerEnv);
    expect(await again.json()).toMatchObject({ ok: true, status: "already-absent" });
  });
});

// ── Direction-B actuators ──────────────────────────────────────────────────────────────────────────────

describe("hub#222 media-bucket-protect", () => {
  it("adds the trash/ lifecycle and lock rules and keeps every other rule", async () => {
    const fake = new FakeCloud().install();
    const foreignLifecycle = { id: "agency-own-rule", enabled: true, conditions: { prefix: "tmp/" }, deleteObjectsTransition: { condition: { type: "Age", maxAge: 86400 } } };
    const foreignLock = { id: "agency-own-lock", enabled: true, prefix: "legal/", condition: { type: "Indefinite" } };
    fake.lifecycleRules = [foreignLifecycle];
    fake.lockRules = [foreignLock];
    const result = await actuateMediaBucketProtect({ bucket: BUCKET }, env());
    expect(result).toEqual({
      ok: true,
      op: "media-bucket-protect",
      bucket: BUCKET,
      lifecycle: "created",
      lock: "created",
      otherLifecycleRules: 1,
      otherLockRules: 1,
    });
    expect(fake.lifecycleRules).toEqual([
      foreignLifecycle,
      { id: "doubleyoup-trash-expire", enabled: true, conditions: { prefix: "trash/" }, deleteObjectsTransition: { condition: { type: "Age", maxAge: MEDIA_TRASH_EXPIRE_SECONDS } } },
    ]);
    expect(fake.lockRules).toEqual([
      foreignLock,
      { id: "doubleyoup-trash-lock", enabled: true, prefix: "trash/", condition: { type: "Age", maxAgeSeconds: MEDIA_TRASH_LOCK_SECONDS } },
    ]);
    expect(MEDIA_TRASH_LOCK_SECONDS).toBe(30 * 86400);
    expect(MEDIA_TRASH_EXPIRE_SECONDS).toBe(31 * 86400);
  });

  it("converges: a re-run writes nothing", async () => {
    const fake = new FakeCloud().install();
    await actuateMediaBucketProtect({ bucket: BUCKET }, env());
    fake.calls = [];
    const result = await actuateMediaBucketProtect({ bucket: BUCKET }, env());
    expect(result).toMatchObject({ ok: true, lifecycle: "unchanged", lock: "unchanged" });
    expect(fake.calls.filter((call) => call.method === "PUT")).toEqual([]);
  });

  it("repairs a drifted own rule in place", async () => {
    const fake = new FakeCloud().install();
    fake.lockRules = [{ id: "doubleyoup-trash-lock", enabled: false, prefix: "trash/", condition: { type: "Age", maxAgeSeconds: 60 } }];
    const result = await actuateMediaBucketProtect({ bucket: BUCKET }, env());
    expect(result).toMatchObject({ ok: true, lock: "updated" });
    expect(fake.lockRules).toHaveLength(1);
    expect(fake.lockRules[0]).toMatchObject({ enabled: true, condition: { maxAgeSeconds: MEDIA_TRASH_LOCK_SECONDS } });
  });

  it("refuses to write over a rules answer it does not understand", async () => {
    const fake = new FakeCloud().install();
    fake.lifecycleRules = [{ enabled: true } as Record<string, unknown>];
    const result = await actuateMediaBucketProtect({ bucket: BUCKET }, env());
    expect(result.ok).toBe(false);
    expect(fake.calls.filter((call) => call.method === "PUT")).toEqual([]);
  });

  it("refuses without R2_PROVISION_API_TOKEN, and a token of another account when R2_EXPECTED_ACCOUNT_ID is set", async () => {
    new FakeCloud().install();
    expect((await actuateMediaBucketProtect({ bucket: BUCKET }, env({ R2_PROVISION_API_TOKEN: undefined }))).ok).toBe(false);
    const wrongAccount = await actuateMediaBucketProtect({ bucket: BUCKET }, env({ R2_EXPECTED_ACCOUNT_ID: "f".repeat(32) }));
    expect(wrongAccount.ok).toBe(false);
  });
});

describe("hub#222 media-site-credential-install", () => {
  it("posts the derived credential and the Worker URL to the job's file-node agent; the answer carries no credential", async () => {
    const fake = new FakeCloud().install();
    const params = { slug: "acme", bucket: BUCKET, workerUrl: WORKER_URL, fileAgentUrl: JOB_AGENT_URL, fileAgentToken: JOB_AGENT_TOKEN };
    const result = await actuateMediaSiteCredentialInstall(params, env());
    expect(result).toEqual({
      ok: true,
      op: "media-site-credential-install",
      slug: "acme",
      bucket: BUCKET,
      workerUrl: WORKER_URL,
      constants: ["DOUBLEYOUP_MEDIA_WORKER_URL", "DOUBLEYOUP_MEDIA_SITE_TOKEN"],
    });
    const post = fake.calls.find((call) => call.url === `${JOB_AGENT_URL}/update-r2-config`);
    expect(post?.method).toBe("POST");
    expect(post?.headers.get("authorization")).toBe(`Bearer ${JOB_AGENT_TOKEN}`);
    const credential = await mediaSiteCredential(SITE_SECRET, BUCKET);
    expect(JSON.parse(post?.body ?? "{}")).toEqual({ slug: "acme", bucket: BUCKET, media_worker_url: WORKER_URL, media_site_token: credential });
    expect(JSON.stringify(result)).not.toContain(credential);
    await expectNoSecrets(result);
  });

  it("falls back to CELL_FILE_AGENT_* and refuses with neither", async () => {
    const fake = new FakeCloud().install();
    const params = { slug: "acme", bucket: BUCKET, workerUrl: WORKER_URL };
    expect((await actuateMediaSiteCredentialInstall(params, env())).ok).toBe(true);
    expect(fake.calls.some((call) => call.url === `${AGENT_URL}/update-r2-config`)).toBe(true);
    const refused = await actuateMediaSiteCredentialInstall(params, env({ CELL_FILE_AGENT_URL: undefined, CELL_FILE_AGENT_TOKEN: undefined }));
    expect(refused.ok).toBe(false);
  });

  it("refuses without MEDIA_SITE_SECRET, before any call", async () => {
    const fake = new FakeCloud().install();
    const result = await actuateMediaSiteCredentialInstall({ slug: "acme", bucket: BUCKET, workerUrl: WORKER_URL }, env({ MEDIA_SITE_SECRET: undefined }));
    expect(result.ok).toBe(false);
    expect(fake.calls).toEqual([]);
  });

  it("reports a refusal of the agent without the credential or the bearer", async () => {
    const fake = new FakeCloud().install();
    fake.agentReply = { status: 500, body: { error: "update-r2-config failed", stderr: "!! bucket mismatch" } };
    const result = await actuateMediaSiteCredentialInstall({ slug: "acme", bucket: BUCKET, workerUrl: WORKER_URL }, env());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("bucket mismatch");
    }
    await expectNoSecrets(result);
    expect(JSON.stringify(result)).not.toContain(await mediaSiteCredential(SITE_SECRET, BUCKET));
  });

  it("refuses to follow a redirect", async () => {
    const fake = new FakeCloud().install();
    fake.agentReply = { status: 302, body: {} };
    const result = await actuateMediaSiteCredentialInstall({ slug: "acme", bucket: BUCKET, workerUrl: WORKER_URL }, env());
    expect(result.ok).toBe(false);
    expect(fake.calls.find((call) => call.url.endsWith("/update-r2-config"))).toBeDefined();
  });
});

describe("hub#222 media-site-key-revoke", () => {
  it("revokes a key minted for the bucket, reports a missing key as already-absent, refuses a foreign key", async () => {
    const fake = new FakeCloud().install();
    const params = { slug: "acme", bucket: BUCKET, tokenId: R2_TOKEN_ID };
    expect(await actuateMediaSiteKeyRevoke(params, env())).toMatchObject({ ok: true, status: "revoked", slug: "acme" });
    fake.tokenRecord = { status: 404 };
    expect(await actuateMediaSiteKeyRevoke(params, env())).toMatchObject({ ok: true, status: "already-absent" });
    fake.tokenRecord = { status: 200, name: "agency-backup-key" };
    const foreign = await actuateMediaSiteKeyRevoke(params, env());
    expect(foreign.ok).toBe(false);
  });
});

describe("hub#222 media-trash-list", () => {
  it("lists trash/ only, one page at a time, with a cursor", async () => {
    const fake = new FakeCloud().install();
    fake.put("acme/live.jpg", "x");
    for (let index = 0; index < 1001; index += 1) {
      fake.put(`trash/2026-11-04/acme/${String(index).padStart(4, "0")}.jpg`, "x");
    }
    const first = await readMediaTrashList({ bucket: BUCKET }, env());
    if (!first.ok) throw new Error(first.detail);
    expect(first.entries).toHaveLength(1000);
    expect(first.entries.every((entry) => entry.key.startsWith("trash/"))).toBe(true);
    expect(first.cursor).toBe("1000");
    const second = await readMediaTrashList({ bucket: BUCKET, cursor: first.cursor as string }, env());
    if (!second.ok) throw new Error(second.detail);
    expect(second.entries).toHaveLength(1);
    expect(second.cursor).toBeNull();
    const listCall = fake.s3Calls().find((call) => call.method === "GET");
    expect(new URL(listCall?.url ?? "").searchParams.get("prefix")).toBe("trash/");
  });

  it("narrows to trash/<prefix>", async () => {
    const fake = new FakeCloud().install();
    fake.put("trash/2026-11-03/acme/a.jpg", "x");
    fake.put("trash/2026-11-04/acme/b.jpg", "x");
    const result = await readMediaTrashList({ bucket: BUCKET, prefix: "2026-11-04/" }, env());
    if (!result.ok) throw new Error(result.detail);
    expect(result.entries.map((entry) => entry.key)).toEqual(["trash/2026-11-04/acme/b.jpg"]);
    expect(result.entries[0]?.etag).toBe(fakeEtag("x"));
  });
});

describe("hub#222 media-restore", () => {
  it("copies the trash object back create-once, keeping its content type", async () => {
    const fake = new FakeCloud().install();
    fake.put("trash/2026-11-04/acme/a.png", "bytes", "image/png");
    const result = await actuateMediaRestore({ bucket: BUCKET, trashKey: "trash/2026-11-04/acme/a.png", targetKey: "acme/a.png" }, env());
    expect(result).toMatchObject({ ok: true, status: "restored" });
    expect(fake.writes()).toEqual(["PUT acme/a.png <- trash/2026-11-04/acme/a.png"]);
    expect(fake.objects.get("acme/a.png")?.contentType).toBe("image/png");
    expect(fake.objects.has("trash/2026-11-04/acme/a.png")).toBe(true);
  });

  it("a retry is already-restored; a target with other bytes is 409; a missing trash key is 404", async () => {
    const fake = new FakeCloud().install();
    fake.put("trash/2026-11-04/acme/a.png", "bytes");
    const params = { bucket: BUCKET, trashKey: "trash/2026-11-04/acme/a.png", targetKey: "acme/a.png" };
    await actuateMediaRestore(params, env());
    expect(await actuateMediaRestore(params, env())).toMatchObject({ ok: true, status: "already-restored" });
    fake.put("acme/a.png", "newer");
    expect(await actuateMediaRestore(params, env())).toMatchObject({ ok: false, code: 409 });
    expect(fake.objects.get("acme/a.png")?.body).toBe("newer");
    expect(await actuateMediaRestore({ ...params, trashKey: "trash/2026-11-04/acme/none.png" }, env())).toMatchObject({ ok: false, code: 404 });
  });

  it("never overwrites a live object that a presigned upload creates after the target HEAD (409)", async () => {
    const fake = new FakeCloud().install();
    fake.put("trash/2026-11-04/acme/a.png", "old", "image/png");
    fake.beforeS3Answer = async (method, key, headers) => {
      if (method === "PUT" && key === "acme/a.png" && headers.get("x-amz-copy-source") !== null) {
        expect(fake.presignedUpload("acme/a.png", "fresh-upload", "image/png")).toBe(200);
      }
    };
    const result = await actuateMediaRestore({ bucket: BUCKET, trashKey: "trash/2026-11-04/acme/a.png", targetKey: "acme/a.png" }, env());
    expect(result).toMatchObject({ ok: false, code: 409 });
    expect(fake.objects.get("acme/a.png")?.body).toBe("fresh-upload");
  });

  it("a target with the same bytes but other metadata is another revision (409), not already-restored", async () => {
    const fake = new FakeCloud().install();
    fake.put("trash/2026-11-04/acme/a.png", "bytes", "image/png");
    fake.put("acme/a.png", "bytes", "application/octet-stream");
    const result = await actuateMediaRestore({ bucket: BUCKET, trashKey: "trash/2026-11-04/acme/a.png", targetKey: "acme/a.png" }, env());
    expect(result).toMatchObject({ ok: false, code: 409 });
  });
});

describe("hub#222 media-bulk-credential", () => {
  it("asks Cloudflare for one bucket, one prefix, object-read-write, with the R2 token as parent", async () => {
    const fake = new FakeCloud().install();
    const result = await actuateMediaBulkCredential({ bucket: BUCKET, prefix: "acme/", ttlSeconds: 3600 }, env());
    expect(result).toEqual({
      ok: true,
      op: "media-bulk-credential",
      bucket: BUCKET,
      prefix: "acme/",
      endpoint: S3_ENDPOINT,
      region: "auto",
      accessKeyId: "tmp-akid",
      secretAccessKey: "tmp-secret",
      sessionToken: "tmp-session",
      expiresAt: new Date(NOW + 3600 * 1000).toISOString(),
    });
    const call = fake.calls.find((entry) => entry.url.endsWith("/r2/temp-access-credentials"));
    expect(JSON.parse(call?.body ?? "{}")).toEqual({
      bucket: BUCKET,
      parentAccessKeyId: R2_TOKEN_ID,
      permission: "object-read-write",
      ttlSeconds: 3600,
      prefixes: ["acme/"],
    });
    await expectNoSecrets(result);
  });

  it("fails closed on an incomplete answer", async () => {
    const fake = new FakeCloud().install();
    fake.tempCredentialReply = { status: 200, body: { success: true, result: { accessKeyId: "a" } } };
    expect((await actuateMediaBulkCredential({ bucket: BUCKET, prefix: "acme/", ttlSeconds: 3600 }, env())).ok).toBe(false);
  });
});
