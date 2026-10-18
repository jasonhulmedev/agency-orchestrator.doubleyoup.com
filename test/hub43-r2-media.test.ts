// hub#43 — agency-owned media ops, Worker side: r2-media-state, r2-site-key-install, r2-site-key-revoke.
//
// What these tests pin:
//   - the twin validators pin the bucket to `doubleyoup-media-<prefix>` (an agency's backup bucket cannot be
//     named), pin bucket == doubleyoup-media-<prefix> for the install, and return ONLY the known keys;
//   - the twin block is byte-identical with the app copy (the sha256 pin below; the app's test pins the SAME value);
//   - the install mints ONE key scoped to ONE bucket, posts the key straight to the FILE-NODE cell-agent, and
//     never returns the key or its secret; a refused stage deletes the key it just minted;
//   - the install refuses BEFORE minting when the file-node agent is not configured or the bucket is missing;
//   - the revoke deletes only a key whose NAME proves this op family minted it for that bucket;
//   - the state read reports keys by id and name and says plainly when the token cannot list tokens.

import { describe, it, expect, vi, afterEach } from "vitest";
// @ts-ignore (see test/hub58-ops.test.ts for why this is ignored)
import rawDispatchParamsSource from "../src/dispatch-params.ts?raw";
import type { Env } from "../src/env.js";
import { DISPATCH_OPS } from "../src/dispatch-verify.js";
import { DISPATCH_OP_REGISTRY } from "../src/ops.js";
import {
  r2SiteKeyNameFor,
  validateR2MediaStateParams,
  validateR2SiteKeyInstallParams,
  validateR2SiteKeyRevokeParams,
} from "../src/dispatch-params.js";
import { actuateR2SiteKeyInstall, actuateR2SiteKeyRevoke, keyNameBelongsToBucket, readR2MediaBuckets, readR2MediaState, R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID } from "../src/actuate-r2-media.js";

const dispatchParamsSource: string = rawDispatchParamsSource as string;

const TWIN_BLOCK_START_MARKER = "// ── hub#43: agency-owned media";
// The planning/47 twin block follows this one, so this block ends where that one starts (the two blocks are adjacent).
const TWIN_BLOCK_END_MARKER = "\n// ── planning/47: the boot-script update";
// The app's src/server/services/agency-dispatch-params-hub43.test.ts pins the SAME value.
const TWIN_BLOCK_SHA256 = "f2b700d3ef4e712143ed625abb15a9aca3a6c2ef9712ae8115e1f364a4eea2cc";

const ACCOUNT_ID = "043e3bdaf4a6849a2d745269084c0e5f";
const R2_TOKEN = "r2-provision-token-must-not-be-echoed";
const AGENT_URL = "https://file-agent.example.org";
const AGENT_TOKEN = "file-agent-bearer-must-not-be-echoed";
const BUCKET = "doubleyoup-media-acme";
const TOKEN_ID = "0123456789abcdef0123456789abcdef";
const TOKEN_VALUE = "cf-token-value-never-leaves-the-worker";

function errorText(verdict: { ok: boolean; reason?: string }): string {
  return verdict.ok ? "" : (verdict.reason ?? "");
}

afterEach(() => {
  vi.restoreAllMocks();
});

interface RecordedCall {
  url: string;
  method: string;
  auth: string | null;
  body: string | null;
}

function mockFetch(handler: (call: RecordedCall) => { status?: number; body: unknown }): RecordedCall[] {
  const calls: RecordedCall[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const call: RecordedCall = {
      url: String(input),
      method: init?.method ?? "GET",
      auth: headers.get("authorization"),
      body: typeof init?.body === "string" ? init.body : null,
    };
    calls.push(call);
    const answer = handler(call);
    return new Response(JSON.stringify(answer.body), { status: answer.status ?? 200, headers: { "content-type": "application/json" } });
  });
  return calls;
}

function env(overrides: Partial<Env> = {}): Env {
  return { R2_PROVISION_API_TOKEN: R2_TOKEN, CELL_FILE_AGENT_URL: AGENT_URL, CELL_FILE_AGENT_TOKEN: AGENT_TOKEN, ...overrides } as Env;
}

const CF = "https://api.cloudflare.com/client/v4";
const ACCOUNTS_URL = `${CF}/accounts?per_page=1`;
const BUCKET_URL = `${CF}/accounts/${ACCOUNT_ID}/r2/buckets/${BUCKET}`;
const TOKENS_URL = `${CF}/accounts/${ACCOUNT_ID}/tokens`;
const STAGE_URL = `${AGENT_URL}/set-r2-target`;

describe("hub#43 twin block", () => {
  it("is byte-identical with the app copy (pinned sha256: change BOTH twins and BOTH pins together)", async () => {
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

  it("the three ops are allowlisted and registered", () => {
    for (const op of ["r2-media-buckets", "r2-media-state", "r2-site-key-install", "r2-site-key-revoke"] as const) {
      expect(DISPATCH_OPS).toContain(op);
      expect(typeof DISPATCH_OP_REGISTRY[op].actuate).toBe("function");
    }
  });
});

describe("r2-media-state params", () => {
  it("accepts doubleyoup-media-<prefix> and returns ONLY the known key", () => {
    expect(validateR2MediaStateParams({ bucket: BUCKET, extra: "dropped" })).toEqual({ ok: true, params: { bucket: BUCKET } });
  });

  it("refuses every other bucket, so a backup or dump bucket can never be named", () => {
    for (const bucket of ["sbmstudio", "sbmstudio-backups-tier1", "doubleyoup-media", "doubleyoup-media-", "doubleyoup-media--x", "DOUBLEYOUP-MEDIA-ACME", "doubleyoup-media-acme/../x", "doubleyoup-media-" + "a".repeat(47), 42, null]) {
      expect(errorText(validateR2MediaStateParams({ bucket }))).toMatch(/^bucket must be doubleyoup-media-<prefix>/);
    }
    expect(validateR2MediaStateParams("x").ok).toBe(false);
  });
});

describe("r2-site-key-install params", () => {
  const good = { bucket: BUCKET, slug: "acme", prefix: "acme", mediaHost: "media.example.org", label: "k1abc" };

  it("accepts a good job and returns ONLY the known keys", () => {
    expect(validateR2SiteKeyInstallParams({ ...good, extra: "dropped" })).toEqual({ ok: true, params: good });
    // A prefix that is not the slug (docs-892769 style) is fine when the bucket follows it.
    expect(validateR2SiteKeyInstallParams({ ...good, slug: "docs", prefix: "docs-892769", bucket: "doubleyoup-media-docs-892769" }).ok).toBe(true);
  });

  it("refuses a bucket that is not exactly doubleyoup-media-<prefix> for this prefix", () => {
    expect(errorText(validateR2SiteKeyInstallParams({ ...good, bucket: "doubleyoup-media-other" }))).toMatch(/exactly doubleyoup-media-<prefix>/);
    expect(errorText(validateR2SiteKeyInstallParams({ ...good, bucket: "sbmstudio" }))).toMatch(/^bucket must be doubleyoup-media-<prefix>/);
  });

  it("refuses a bad slug, prefix, host and label, field by field", () => {
    expect(errorText(validateR2SiteKeyInstallParams({ ...good, slug: "Acme" }))).toMatch(/^slug must be/);
    expect(errorText(validateR2SiteKeyInstallParams({ ...good, prefix: "-x" }))).toMatch(/^prefix must be/);
    for (const mediaHost of ["", "media", "Media.Example.org", "media.example.org/x", "media.example.org:8080", "a b.example.org", 7]) {
      expect(errorText(validateR2SiteKeyInstallParams({ ...good, mediaHost }))).toMatch(/^mediaHost must be a lowercase DNS host name/);
    }
    for (const label of ["", "A", "a-b", "a".repeat(17), 3]) {
      expect(errorText(validateR2SiteKeyInstallParams({ ...good, label }))).toMatch(/^label must be 1-16/);
    }
    expect(validateR2SiteKeyInstallParams(null).ok).toBe(false);
  });
});

describe("r2-site-key-revoke params", () => {
  it("accepts a 32-hex token id and refuses everything else", () => {
    expect(validateR2SiteKeyRevokeParams({ bucket: BUCKET, tokenId: TOKEN_ID, extra: 1 })).toEqual({ ok: true, params: { bucket: BUCKET, tokenId: TOKEN_ID } });
    for (const tokenId of ["", "ABCDEF0123456789abcdef0123456789", "0123456789abcdef", `${TOKEN_ID}/x`, TOKEN_ID + "0", 5]) {
      expect(errorText(validateR2SiteKeyRevokeParams({ bucket: BUCKET, tokenId }))).toMatch(/^tokenId must be a 32-character lowercase-hex/);
    }
    expect(errorText(validateR2SiteKeyRevokeParams({ bucket: "sbmstudio", tokenId: TOKEN_ID }))).toMatch(/^bucket must be/);
  });

  it("the key name is dy-media-<bucket>-<label>", () => {
    expect(r2SiteKeyNameFor(BUCKET, "k1abc")).toBe("dy-media-doubleyoup-media-acme-k1abc");
  });
});

describe("readR2MediaState", () => {
  it("reports the bucket and the keys this op family minted for it, by id and name only", async () => {
    mockFetch((call) => {
      if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
      if (call.url === BUCKET_URL) return { body: { success: true, result: { name: BUCKET } } };
      if (call.url.startsWith(`${TOKENS_URL}?`)) {
        return {
          body: {
            success: true,
            result: [
              { id: TOKEN_ID, name: `dy-media-${BUCKET}-k1abc`, issued_on: "2026-10-16T01:02:03Z" },
              { id: "ffffffffffffffffffffffffffffffff", name: "dy-media-doubleyoup-media-other-k1", issued_on: "x" },
              { id: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", name: "sbmstudio-backup-key" },
            ],
          },
        };
      }
      return { status: 500, body: { success: false } };
    });
    const result = await readR2MediaState({ bucket: BUCKET }, env());
    expect(result).toEqual({
      ok: true,
      op: "r2-media-state",
      bucket: BUCKET,
      bucketExists: true,
      accountId: ACCOUNT_ID,
      endpointHost: `${ACCOUNT_ID}.r2.cloudflarestorage.com`,
      keysReadable: true,
      keys: [{ tokenId: TOKEN_ID, name: `dy-media-${BUCKET}-k1abc`, issuedOn: "2026-10-16T01:02:03Z" }],
    });
    expect(JSON.stringify(result)).not.toContain(R2_TOKEN);
  });

  it("says so when the token cannot list API tokens, and when the bucket is absent", async () => {
    mockFetch((call) => {
      if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
      if (call.url === BUCKET_URL) return { status: 404, body: { success: false } };
      if (call.url.startsWith(`${TOKENS_URL}?`)) return { status: 403, body: { success: false } };
      return { status: 500, body: { success: false } };
    });
    const result = await readR2MediaState({ bucket: BUCKET }, env());
    expect(result).toMatchObject({ ok: true, bucketExists: false, keysReadable: false, keys: [] });
  });

  it("is ok:false with no Cloudflare call when the token is not configured", async () => {
    const calls = mockFetch(() => ({ body: {} }));
    const result = await readR2MediaState({ bucket: BUCKET }, env({ R2_PROVISION_API_TOKEN: undefined }));
    expect(result).toMatchObject({ ok: false, op: "r2-media-state" });
    expect(calls).toEqual([]);
  });
});

describe("actuateR2SiteKeyInstall", () => {
  const params = { bucket: BUCKET, slug: "acme", prefix: "acme", mediaHost: "media.example.org", label: "k1abc" };

  function happyHandler(stage: { status?: number; body: unknown } = { body: { ok: true, mode: "stage", staged: { hex: "abcdef0123456789" } } }) {
    return (call: RecordedCall) => {
      if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
      if (call.url === BUCKET_URL) return { body: { success: true, result: { name: BUCKET } } };
      if (call.url === TOKENS_URL && call.method === "POST") return { body: { success: true, result: { id: TOKEN_ID, value: TOKEN_VALUE } } };
      if (call.url === STAGE_URL) return stage;
      if (call.url === `${TOKENS_URL}/${TOKEN_ID}` && call.method === "DELETE") return { body: { success: true } };
      return { status: 500, body: { success: false } };
    };
  }

  it("mints ONE bucket-scoped key, stages it on the file node, and returns no key and no secret", async () => {
    const calls = mockFetch(happyHandler());
    const result = await actuateR2SiteKeyInstall(params, env());
    expect(result).toEqual({
      ok: true,
      op: "r2-site-key-install",
      bucket: BUCKET,
      tokenId: TOKEN_ID,
      tokenName: `dy-media-${BUCKET}-k1abc`,
      endpointHost: `${ACCOUNT_ID}.r2.cloudflarestorage.com`,
      stagedHex: "abcdef0123456789",
    });

    // The mint: one policy, one bucket resource, the bucket-scoped permission group.
    const mint = calls.find((call) => call.url === TOKENS_URL && call.method === "POST");
    const mintBody = JSON.parse(mint?.body ?? "{}");
    expect(mintBody.name).toBe(`dy-media-${BUCKET}-k1abc`);
    expect(mintBody.policies).toHaveLength(1);
    expect(mintBody.policies[0].permission_groups).toEqual([{ id: R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID }]);
    expect(Object.keys(mintBody.policies[0].resources)).toEqual([`com.cloudflare.edge.r2.bucket.${ACCOUNT_ID}_default_${BUCKET}`]);
    expect(mint?.auth).toBe(`Bearer ${R2_TOKEN}`);

    // The stage: straight to the file node, with the S3 key id and sha256(value) as the secret.
    const stage = calls.find((call) => call.url === STAGE_URL);
    expect(stage?.auth).toBe(`Bearer ${AGENT_TOKEN}`);
    const stageBody = JSON.parse(stage?.body ?? "{}");
    expect(stageBody).toMatchObject({
      slug: "acme",
      mode: "stage",
      bucket: BUCKET,
      endpoint: `https://${ACCOUNT_ID}.r2.cloudflarestorage.com`,
      mediaHost: "media.example.org",
      mediaBase: "https://media.example.org/acme",
      key: TOKEN_ID,
    });
    const expectedSecret = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(TOKEN_VALUE))))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    expect(stageBody.secret).toBe(expectedSecret);

    // Nothing secret comes back.
    const text = JSON.stringify(result);
    for (const secret of [TOKEN_VALUE, expectedSecret, R2_TOKEN, AGENT_TOKEN]) {
      expect(text).not.toContain(secret);
    }
    // And no older key was deleted.
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
  });

  it("refuses BEFORE minting when the file-node agent is not configured", async () => {
    const calls = mockFetch(happyHandler());
    for (const overrides of [{ CELL_FILE_AGENT_URL: undefined }, { CELL_FILE_AGENT_TOKEN: undefined }]) {
      const result = await actuateR2SiteKeyInstall(params, env(overrides));
      expect(result).toMatchObject({ ok: false, op: "r2-site-key-install" });
      expect(JSON.stringify(result)).toMatch(/CELL_FILE_AGENT/);
    }
    expect(calls).toEqual([]);
  });

  it("refuses BEFORE minting when the bucket does not exist", async () => {
    const calls = mockFetch((call) => {
      if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
      if (call.url === BUCKET_URL) return { status: 404, body: { success: false } };
      return { status: 500, body: { success: false } };
    });
    const result = await actuateR2SiteKeyInstall(params, env());
    expect(result).toMatchObject({ ok: false });
    expect(JSON.stringify(result)).toMatch(/run provision-r2 first/);
    expect(calls.some((call) => call.method === "POST")).toBe(false);
  });

  it("H3: a DEFINITE refusal (JSON ok:false, a 4xx, a redirect) deletes the new key and says so", async () => {
    for (const reply of [
      // What the cell-agent really sends for a refusal before any write (exit 4 or 2 of set-r2-target.sh): a 409 with
      // JSON ok:false. It never sends a 200 with ok:false.
      { status: 409, body: { ok: false, refused: true, error: "set-r2-target refused: nothing written", code: 4, stderr: "!! the staged key is not the key id the caller expects: nothing written" } },
      { status: 400, body: { error: "bad slug" } },
      { status: 401, body: { error: "unauthorized" } },
      { status: 404, body: { error: "no such route" } },
    ]) {
      vi.restoreAllMocks();
      const calls = mockFetch(happyHandler(reply));
      const result = await actuateR2SiteKeyInstall(params, env());
      expect(result).toMatchObject({ ok: false, op: "r2-site-key-install" });
      expect(JSON.stringify(result)).toMatch(/deleted again/);
      expect(result).not.toHaveProperty("maybeStagedKeyId");
      expect(calls.filter((call) => call.method === "DELETE").map((call) => call.url)).toEqual([`${TOKENS_URL}/${TOKEN_ID}`]);
      expect(JSON.stringify(result)).not.toContain(TOKEN_VALUE);
    }
  });

  it("H3: an AMBIGUOUS answer (a throw, a 500, a 524, a body that is not JSON) KEEPS the key and hands back its id", async () => {
    const ambiguous: Array<(call: RecordedCall) => { status?: number; body: unknown }> = [
      (call) => {
        if (call.url === STAGE_URL) throw new Error("connect ECONNRESET");
        return happyHandler()(call);
      },
      happyHandler({ status: 500, body: { error: "set-r2-target failed", stderr: "refused: something" } }),
      happyHandler({ status: 524, body: { error: "origin timeout" } }),
      happyHandler({ status: 200, body: "<html>not json</html>" }),
    ];
    for (const handler of ambiguous) {
      vi.restoreAllMocks();
      const calls = mockFetch(handler);
      const result = await actuateR2SiteKeyInstall(params, env());
      expect(result).toMatchObject({ ok: false, op: "r2-site-key-install", maybeStagedKeyId: TOKEN_ID });
      expect(JSON.stringify(result)).toMatch(/MAY be staged/);
      expect(calls.some((call) => call.method === "DELETE")).toBe(false);
      expect(JSON.stringify(result)).not.toContain(TOKEN_VALUE);
    }
  });

  it("a key that could NOT be deleted after a definite refusal is reported by id", async () => {
    mockFetch((call) => {
      if (call.url === `${TOKENS_URL}/${TOKEN_ID}` && call.method === "DELETE") return { status: 500, body: { success: false } };
      return happyHandler({ status: 400, body: { error: "x" } })(call);
    });
    const result = await actuateR2SiteKeyInstall(params, env());
    expect(JSON.stringify(result)).toContain(`${TOKEN_ID} could NOT be deleted`);
  });

  it("L10: a token that came back with no value is deleted, never used", async () => {
    const calls = mockFetch((call) => {
      if (call.url === TOKENS_URL && call.method === "POST") return { body: { success: true, result: { id: TOKEN_ID } } };
      return happyHandler()(call);
    });
    const result = await actuateR2SiteKeyInstall(params, env());
    expect(result).toMatchObject({ ok: false });
    expect(JSON.stringify(result)).toMatch(/no key value/);
    expect(calls.filter((call) => call.method === "DELETE").map((call) => call.url)).toEqual([`${TOKENS_URL}/${TOKEN_ID}`]);
    expect(calls.some((call) => call.url === STAGE_URL)).toBe(false);
  });

  it("L7: a token of another account than R2_EXPECTED_ACCOUNT_ID is refused by every media op, before a mint", async () => {
    const calls = mockFetch(happyHandler());
    const wrong = env({ R2_EXPECTED_ACCOUNT_ID: "ffffffffffffffffffffffffffffffff" });
    expect(await actuateR2SiteKeyInstall(params, wrong)).toMatchObject({ ok: false });
    expect(await readR2MediaState({ bucket: BUCKET }, wrong)).toMatchObject({ ok: false });
    expect(await readR2MediaBuckets({}, wrong)).toMatchObject({ ok: false });
    expect(await actuateR2SiteKeyRevoke({ bucket: BUCKET, tokenId: TOKEN_ID }, wrong)).toMatchObject({ ok: false });
    expect(calls.some((call) => call.method === "POST")).toBe(false);
    const right = await readR2MediaBuckets({}, env({ R2_EXPECTED_ACCOUNT_ID: ACCOUNT_ID.toUpperCase() }));
    expect(JSON.stringify(right)).not.toMatch(/different Cloudflare account/);
  });

  it("a Cloudflare denial of the mint says what the token needs, with no stage call", async () => {
    const calls = mockFetch((call) => {
      if (call.url === TOKENS_URL && call.method === "POST") return { status: 403, body: { success: false } };
      return happyHandler()(call);
    });
    const result = await actuateR2SiteKeyInstall(params, env());
    expect(JSON.stringify(result)).toMatch(/Account API Tokens: Edit/);
    expect(calls.some((call) => call.url === STAGE_URL)).toBe(false);
  });
});

describe("actuateR2SiteKeyRevoke", () => {
  const params = { bucket: BUCKET, tokenId: TOKEN_ID };
  const keyUrl = `${TOKENS_URL}/${TOKEN_ID}`;

  it("deletes a key whose name proves this op family minted it for this bucket", async () => {
    const calls = mockFetch((call) => {
      if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
      if (call.url === keyUrl && call.method === "GET") return { body: { success: true, result: { id: TOKEN_ID, name: `dy-media-${BUCKET}-k1abc` } } };
      if (call.url === keyUrl && call.method === "DELETE") return { body: { success: true } };
      return { status: 500, body: { success: false } };
    });
    expect(await actuateR2SiteKeyRevoke(params, env())).toEqual({ ok: true, op: "r2-site-key-revoke", bucket: BUCKET, tokenId: TOKEN_ID, status: "revoked" });
    expect(calls.map((call) => call.method)).toEqual(["GET", "GET", "DELETE"]);
  });

  it("REFUSES to delete a key of another name (the Worker's own token, a backup key, another bucket's key)", async () => {
    for (const name of ["sbmstudio-backup-key", "R2_PROVISION_API_TOKEN", "dy-media-doubleyoup-media-other-k1", `dy-media-${BUCKET}`]) {
      vi.restoreAllMocks();
      const calls = mockFetch((call) => {
        if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
        if (call.url === keyUrl && call.method === "GET") return { body: { success: true, result: { id: TOKEN_ID, name } } };
        return { status: 500, body: { success: false } };
      });
      const result = await actuateR2SiteKeyRevoke(params, env());
      expect(result).toMatchObject({ ok: false });
      expect(JSON.stringify(result)).toMatch(/refusing to delete it/);
      expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    }
  });

  it("an absent key is already-absent, on the read and on the delete", async () => {
    mockFetch((call) => {
      if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
      return { status: 404, body: { success: false } };
    });
    expect(await actuateR2SiteKeyRevoke(params, env())).toMatchObject({ ok: true, status: "already-absent" });
  });
});

describe("r2-media-buckets", () => {
  it("is allowlisted, registered, takes no params, and lists names only (sorted, de-duplicated)", async () => {
    expect(DISPATCH_OPS).toContain("r2-media-buckets");
    expect(typeof DISPATCH_OP_REGISTRY["r2-media-buckets"].actuate).toBe("function");
    expect(DISPATCH_OP_REGISTRY["r2-media-buckets"].validateParams({})).toEqual({ ok: true, params: {} });
    expect(DISPATCH_OP_REGISTRY["r2-media-buckets"].validateParams({ bucket: BUCKET }).ok).toBe(false);
    const calls = mockFetch((call) => {
      if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
      if (call.url.startsWith(`${CF}/accounts/${ACCOUNT_ID}/r2/buckets?`)) {
        return { body: { success: true, result: { buckets: [{ name: "sbmstudio", creation_date: "x" }, { name: BUCKET }, { name: BUCKET }, { nope: 1 }] } } };
      }
      return { status: 500, body: { success: false } };
    });
    const result = await readR2MediaBuckets({}, env());
    expect(result).toEqual({
      ok: true,
      op: "r2-media-buckets",
      accountId: ACCOUNT_ID,
      endpointHost: `${ACCOUNT_ID}.r2.cloudflarestorage.com`,
      buckets: [BUCKET, "sbmstudio"],
      truncated: false,
    });
    expect(JSON.stringify(result)).not.toContain(R2_TOKEN);
    expect(calls.every((call) => call.method === "GET")).toBe(true);
  });

  it("follows the cursor, and a denied token or a missing token is a plain failure", async () => {
    let page = 0;
    mockFetch((call) => {
      if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
      page += 1;
      if (page === 1) return { body: { success: true, result: { buckets: [{ name: "a-one" }] }, result_info: { cursor: "next" } } };
      return { body: { success: true, result: { buckets: [{ name: "b-two" }] } } };
    });
    const paged = await readR2MediaBuckets({}, env());
    expect(paged.ok && paged.buckets).toEqual(["a-one", "b-two"]);

    mockFetch((call) => (call.url === ACCOUNTS_URL ? { body: { success: true, result: [{ id: ACCOUNT_ID }] } } : { status: 403, body: { success: false } }));
    expect((await readR2MediaBuckets({}, env())).ok).toBe(false);
    expect((await readR2MediaBuckets({}, env({ R2_PROVISION_API_TOKEN: undefined }))).ok).toBe(false);
  });
});

describe("M3: a key name belongs to a bucket only when the rest is the exact label shape", () => {
  it("separates docs from docs-892769 and rareepicgamer from rareepicgamer-19f933", () => {
    expect(keyNameBelongsToBucket("dy-media-doubleyoup-media-docs-k1abc", "doubleyoup-media-docs")).toBe(true);
    expect(keyNameBelongsToBucket("dy-media-doubleyoup-media-docs-892769-k1abc", "doubleyoup-media-docs")).toBe(false);
    expect(keyNameBelongsToBucket("dy-media-doubleyoup-media-docs-892769-k1abc", "doubleyoup-media-docs-892769")).toBe(true);
    expect(keyNameBelongsToBucket("dy-media-doubleyoup-media-rareepicgamer-19f933-n1", "doubleyoup-media-rareepicgamer")).toBe(false);
    expect(keyNameBelongsToBucket("dy-media-doubleyoup-media-acme-", "doubleyoup-media-acme")).toBe(false);
    expect(keyNameBelongsToBucket("dy-media-doubleyoup-media-acme-" + "a".repeat(17), "doubleyoup-media-acme")).toBe(false);
    expect(keyNameBelongsToBucket("dy-media-doubleyoup-media-acme-K1", "doubleyoup-media-acme")).toBe(false);
  });

  it("the list and the revoke both use it", async () => {
    mockFetch((call) => {
      if (call.url === ACCOUNTS_URL) return { body: { success: true, result: [{ id: ACCOUNT_ID }] } };
      if (call.url === `${CF}/accounts/${ACCOUNT_ID}/r2/buckets/doubleyoup-media-docs`) return { body: { success: true, result: {} } };
      if (call.url.startsWith(`${TOKENS_URL}?`)) {
        return { body: { success: true, result: [{ id: "a".repeat(32), name: "dy-media-doubleyoup-media-docs-k1" }, { id: "b".repeat(32), name: "dy-media-doubleyoup-media-docs-892769-k1" }] } };
      }
      if (call.url === `${TOKENS_URL}/${"b".repeat(32)}`) return { body: { success: true, result: { id: "b".repeat(32), name: "dy-media-doubleyoup-media-docs-892769-k1" } } };
      return { status: 500, body: { success: false } };
    });
    const state = await readR2MediaState({ bucket: "doubleyoup-media-docs" }, env());
    expect(state.ok && state.keys.map((key) => key.tokenId)).toEqual(["a".repeat(32)]);
    const revoke = await actuateR2SiteKeyRevoke({ bucket: "doubleyoup-media-docs", tokenId: "b".repeat(32) }, env());
    expect(revoke.ok).toBe(false);
    expect(JSON.stringify(revoke)).toMatch(/refusing to delete/);
  });
});
