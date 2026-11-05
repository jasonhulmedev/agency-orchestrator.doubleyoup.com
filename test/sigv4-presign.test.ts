// SigV4 QUERY-PARAMETER presign (sigv4.ts::presignS3Url / presignS3Put) — pinned so the
// signing scheme cannot silently drift. A presigned PUT is the ONLY thing that reaches the
// agency's cell in the Direction-B `db-export` op, so a one-byte change to the canonical request
// (a header added to SignedHeaders, a re-encoded path, a hashed instead of UNSIGNED payload) would
// make every upload fail with SignatureDoesNotMatch — or, worse, quietly widen what the URL grants.
//
// Two pins:
//   1. The AWS-PUBLISHED presigned-GET example ("Authenticating Requests: Using Query Parameters
//      (AWS Signature Version 4)"): fixed key, date and URL, with the exact canonical request,
//      string-to-sign hash and signature AWS documents. Reproducing it proves the scheme is the
//      standard one, independent of this codebase.
//   2. A db-export-shaped PUT against an R2-style path-style endpoint with region "auto". Its
//      expected values were derived with an INDEPENDENT node:crypto reference implementation
//      (written from the spec, not from sigv4.ts) that also reproduces pin 1 — so pin 2 is a
//      genuine cross-check, not the code asserting itself.
//
// Worker-native (Web Crypto only), like the rest of the Worker's tests.

import { describe, it, expect, vi } from "vitest";
import { presignS3Put, presignS3Get, presignS3Url, signS3Request } from "../src/sigv4.js";

// ── Pin 1: the AWS-published example ──────────────────────────────────────────────────
const AWS_EXAMPLE = {
  method: "GET" as const,
  url: "https://examplebucket.s3.amazonaws.com/test.txt",
  region: "us-east-1",
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  expiresSeconds: 86400,
  nowMs: Date.parse("2013-05-24T00:00:00.000Z"),
};

const AWS_EXAMPLE_CANONICAL_QUERY =
  "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
  "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
  "&X-Amz-Date=20130524T000000Z" +
  "&X-Amz-Expires=86400" +
  "&X-Amz-SignedHeaders=host";

const AWS_EXAMPLE_SIGNATURE = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";

// ── Pin 2: a db-export PUT, R2-shaped (path-style endpoint, region "auto") ────────────
const DB_EXPORT_PUT = {
  endpoint: "https://acct123.r2.cloudflarestorage.com",
  bucket: "agency-backups",
  region: "auto",
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "SECRETEXAMPLE",
  key: "db-exports/geelongns-2026-09-07t01-02-03z.sql",
  expiresSeconds: 600,
  nowMs: Date.parse("2026-09-07T01:02:03.000Z"),
};

const DB_EXPORT_PUT_CANONICAL_QUERY =
  "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
  "&X-Amz-Credential=AKIDEXAMPLE%2F20260907%2Fauto%2Fs3%2Faws4_request" +
  "&X-Amz-Date=20260907T010203Z" +
  "&X-Amz-Expires=600" +
  "&X-Amz-SignedHeaders=host";

const DB_EXPORT_PUT_SIGNATURE = "8fe4cd07955b0778ffd690c19517b571a197c184c21357c90da97ac4b82df39b";

describe("presignS3Url — the AWS-published presigned-GET example (scheme pin)", () => {
  it("reproduces the documented canonical request byte-for-byte", async () => {
    const presigned = await presignS3Url(AWS_EXAMPLE);
    expect(presigned.canonicalRequest).toBe(
      "GET\n" +
        "/test.txt\n" +
        `${AWS_EXAMPLE_CANONICAL_QUERY}\n` +
        "host:examplebucket.s3.amazonaws.com\n" +
        "\n" +
        "host\n" +
        "UNSIGNED-PAYLOAD",
    );
  });

  it("reproduces the documented string-to-sign (including the canonical-request hash)", async () => {
    const presigned = await presignS3Url(AWS_EXAMPLE);
    expect(presigned.stringToSign).toBe(
      "AWS4-HMAC-SHA256\n" +
        "20130524T000000Z\n" +
        "20130524/us-east-1/s3/aws4_request\n" +
        "3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04",
    );
  });

  it("produces the documented signature and the exact wire URL", async () => {
    const presigned = await presignS3Url(AWS_EXAMPLE);
    expect(presigned.url).toBe(
      `https://examplebucket.s3.amazonaws.com/test.txt?${AWS_EXAMPLE_CANONICAL_QUERY}&X-Amz-Signature=${AWS_EXAMPLE_SIGNATURE}`,
    );
  });
});

describe("presignS3Put — the db-export PUT pin (R2 path-style, region auto)", () => {
  it("pins the canonical request: PUT, single-encoded path, sorted X-Amz query, host only, UNSIGNED-PAYLOAD", async () => {
    const presigned = await presignS3Put(DB_EXPORT_PUT);
    expect(presigned.canonicalRequest).toBe(
      "PUT\n" +
        "/agency-backups/db-exports/geelongns-2026-09-07t01-02-03z.sql\n" +
        `${DB_EXPORT_PUT_CANONICAL_QUERY}\n` +
        "host:acct123.r2.cloudflarestorage.com\n" +
        "\n" +
        "host\n" +
        "UNSIGNED-PAYLOAD",
    );
    expect(presigned.stringToSign).toBe(
      "AWS4-HMAC-SHA256\n" +
        "20260907T010203Z\n" +
        "20260907/auto/s3/aws4_request\n" +
        "11e623100784ee78e004af0779a5f118409e60bc489139fce3914bc38d5ca8c8",
    );
  });

  it("pins the wire URL: path-style <endpoint>/<bucket>/<key>, the signed query verbatim, the signature last", async () => {
    const presigned = await presignS3Put(DB_EXPORT_PUT);
    expect(presigned.url).toBe(
      "https://acct123.r2.cloudflarestorage.com/agency-backups/db-exports/geelongns-2026-09-07t01-02-03z.sql" +
        `?${DB_EXPORT_PUT_CANONICAL_QUERY}&X-Amz-Signature=${DB_EXPORT_PUT_SIGNATURE}`,
    );
  });

  it("exposes exactly the six X-Amz query parameters and nothing about the payload hash", async () => {
    const presigned = await presignS3Put(DB_EXPORT_PUT);
    const query = new URL(presigned.url).searchParams;
    expect([...query.keys()].sort()).toEqual([
      "X-Amz-Algorithm",
      "X-Amz-Credential",
      "X-Amz-Date",
      "X-Amz-Expires",
      "X-Amz-Signature",
      "X-Amz-SignedHeaders",
    ]);
    expect(query.get("X-Amz-Algorithm")).toBe("AWS4-HMAC-SHA256");
    expect(query.get("X-Amz-Credential")).toBe("AKIDEXAMPLE/20260907/auto/s3/aws4_request");
    expect(query.get("X-Amz-Date")).toBe("20260907T010203Z");
    expect(query.get("X-Amz-Expires")).toBe("600");
    // ONLY host is signed — curl's own Content-Length / User-Agent / Expect must stay unsigned.
    expect(query.get("X-Amz-SignedHeaders")).toBe("host");
    expect(query.get("X-Amz-Signature")).toMatch(/^[0-9a-f]{64}$/);
    // No x-amz-content-sha256 anywhere: a presign cannot know the body, so it is UNSIGNED-PAYLOAD.
    expect(presigned.url.toLowerCase()).not.toContain("content-sha256");
  });

  it("never embeds the secret key — only the access-key ID and a derived signature", async () => {
    const presigned = await presignS3Put(DB_EXPORT_PUT);
    expect(presigned.url).not.toContain(DB_EXPORT_PUT.secretAccessKey);
    expect(presigned.canonicalRequest).not.toContain(DB_EXPORT_PUT.secretAccessKey);
    expect(presigned.stringToSign).not.toContain(DB_EXPORT_PUT.secretAccessKey);
  });

  it("is deterministic for fixed inputs and sensitive to the key, the clock and the expiry", async () => {
    const signatureOf = (url: string) => new URL(url).searchParams.get("X-Amz-Signature");
    const base = await presignS3Put(DB_EXPORT_PUT);
    expect((await presignS3Put(DB_EXPORT_PUT)).url).toBe(base.url);
    expect(signatureOf((await presignS3Put({ ...DB_EXPORT_PUT, key: "db-exports/other.sql" })).url)).not.toBe(
      signatureOf(base.url),
    );
    expect(signatureOf((await presignS3Put({ ...DB_EXPORT_PUT, nowMs: DB_EXPORT_PUT.nowMs + 1000 })).url)).not.toBe(
      signatureOf(base.url),
    );
    expect(signatureOf((await presignS3Put({ ...DB_EXPORT_PUT, expiresSeconds: 601 })).url)).not.toBe(
      signatureOf(base.url),
    );
  });

  it("AWS-encodes the bucket and each key segment exactly ONCE (wire path == canonical path)", async () => {
    // Outside the db-export grammar, but the presigner is general: a space and "*" must be
    // percent-encoded on the wire (S3 canonicalizes them that way), "/" kept as the separator,
    // and the canonical request must sign the SAME bytes — no double-encoding of the "%".
    const presigned = await presignS3Put({ ...DB_EXPORT_PUT, key: "dir one/a b*c.sql" });
    const expectedPath = "/agency-backups/dir%20one/a%20b%2Ac.sql";
    expect(new URL(presigned.url).pathname).toBe(expectedPath);
    expect(presigned.canonicalRequest.split("\n")[1]).toBe(expectedPath);
  });

  it("targets real AWS S3 virtual-hosted-style when no endpoint is configured", async () => {
    const { endpoint: _dropped, ...withoutEndpoint } = DB_EXPORT_PUT;
    const presigned = await presignS3Put({ ...withoutEndpoint, region: "us-east-1" });
    expect(presigned.url.startsWith("https://agency-backups.s3.us-east-1.amazonaws.com/db-exports/geelongns-2026-09-07t01-02-03z.sql?")).toBe(true);
    expect(presigned.canonicalRequest.split("\n")[1]).toBe("/db-exports/geelongns-2026-09-07t01-02-03z.sql");
    expect(presigned.canonicalRequest).toContain("host:agency-backups.s3.us-east-1.amazonaws.com\n");
  });

  it("keeps an endpoint's trailing slash / path prefix from producing a double slash", async () => {
    const presigned = await presignS3Put({ ...DB_EXPORT_PUT, endpoint: "https://acct123.r2.cloudflarestorage.com/" });
    expect(new URL(presigned.url).pathname).toBe("/agency-backups/db-exports/geelongns-2026-09-07t01-02-03z.sql");
    expect(presigned.url).toBe((await presignS3Put(DB_EXPORT_PUT)).url);
  });
});

describe("presignS3Get — the db-import GET pin (same object as the PUT, method GET)", () => {
  // db-import reads back exactly the object db-export wrote, so presignS3Get MUST address it
  // identically to presignS3Put — same path, same X-Amz query (the method is NOT in the query) —
  // and differ ONLY in the canonical request's method line, which flows through to a different
  // signature. The GET signing scheme itself is already pinned against the AWS-published GET
  // example above (both go through presignS3Url), so here we pin the shared addressing + the
  // method sensitivity rather than a second magic signature.
  it("pins the canonical request: GET, the SAME single-encoded path + query as the PUT, host only, UNSIGNED-PAYLOAD", async () => {
    const presigned = await presignS3Get(DB_EXPORT_PUT);
    expect(presigned.canonicalRequest).toBe(
      "GET\n" +
        "/agency-backups/db-exports/geelongns-2026-09-07t01-02-03z.sql\n" +
        `${DB_EXPORT_PUT_CANONICAL_QUERY}\n` +
        "host:acct123.r2.cloudflarestorage.com\n" +
        "\n" +
        "host\n" +
        "UNSIGNED-PAYLOAD",
    );
  });

  it("addresses the SAME object as presignS3Put but signs a DIFFERENT signature (method-sensitive)", async () => {
    const get = await presignS3Get(DB_EXPORT_PUT);
    const put = await presignS3Put(DB_EXPORT_PUT);
    const getUrl = new URL(get.url);
    const putUrl = new URL(put.url);
    // Same object + same signed query set ...
    expect(getUrl.origin).toBe(putUrl.origin);
    expect(getUrl.pathname).toBe(putUrl.pathname);
    expect(getUrl.searchParams.get("X-Amz-Credential")).toBe(putUrl.searchParams.get("X-Amz-Credential"));
    expect(getUrl.searchParams.get("X-Amz-SignedHeaders")).toBe("host");
    // ... but the method line makes the signature differ, and the secret never appears.
    const signatureOf = (u: URL) => u.searchParams.get("X-Amz-Signature");
    expect(signatureOf(getUrl)).toMatch(/^[0-9a-f]{64}$/);
    expect(signatureOf(getUrl)).not.toBe(signatureOf(putUrl));
    expect(get.url).not.toContain(DB_EXPORT_PUT.secretAccessKey);
  });

  it("targets real AWS S3 virtual-hosted-style when no endpoint is configured", async () => {
    const { endpoint: _dropped, ...withoutEndpoint } = DB_EXPORT_PUT;
    const presigned = await presignS3Get({ ...withoutEndpoint, region: "us-east-1" });
    expect(
      presigned.url.startsWith("https://agency-backups.s3.us-east-1.amazonaws.com/db-exports/geelongns-2026-09-07t01-02-03z.sql?"),
    ).toBe(true);
    expect(presigned.canonicalRequest.split("\n")[0]).toBe("GET");
  });
});

// ── hub#222: signed header values are SigV4-canonicalized ("Trimall") ─────────────────────────────────
// Expected signatures from botocore 1.40.72 (S3SigV4Auth and S3SigV4QueryAuth, region "auto", clock pinned to
// 2026-11-04T10:20:30Z), an independent SigV4 implementation that collapses runs of whitespace in header values.
// Before this fix the signer only trimmed the ends, so a content type such as `text/plain;  charset=utf-8` got a
// signature that the store rejects.
describe("SigV4 signed header values collapse inner whitespace (hub#222)", () => {
  const credentials = {
    region: "auto",
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  };
  const pinnedNowMs = Date.parse("2026-11-04T10:20:30.000Z");

  it("presignS3Put: a content type with a double space signs like botocore", async () => {
    const presigned = await presignS3Put({
      ...credentials,
      endpoint: "https://acct.r2.cloudflarestorage.com",
      bucket: "doubleyoup-media-acme",
      key: "acme/a.txt",
      expiresSeconds: 600,
      nowMs: pinnedNowMs,
      signedHeaders: { "content-type": "text/plain;  charset=utf-8", "if-none-match": "*", "content-length": "5" },
    });
    expect(presigned.canonicalRequest).toContain("\ncontent-type:text/plain; charset=utf-8\n");
    expect(new URL(presigned.url).searchParams.get("X-Amz-Signature")).toBe(
      "2a6dbe120972dfbf120d1c51e70030c58078534e9e35e79bb99ba2db8cfbaa35",
    );
  });

  it("signS3Request: a header-signed CopyObject with a double-spaced value signs like botocore and sends the normalized value", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(pinnedNowMs);
    try {
      const signed = await signS3Request({
        ...credentials,
        method: "PUT",
        url: "https://acct.r2.cloudflarestorage.com/doubleyoup-media-acme/acme/a.txt",
        pathIsEncoded: true,
        extraHeaders: {
          "x-amz-copy-source": "/doubleyoup-media-acme/acme/src.txt",
          "x-amz-metadata-directive": "COPY",
          "content-type": "text/plain;  charset=utf-8",
        },
      });
      expect(signed.headers.get("authorization")).toBe(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261104/auto/s3/aws4_request, " +
          "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-copy-source;x-amz-date;x-amz-metadata-directive, " +
          "Signature=42450f274e5f3aa3906a1b782b26999399b40ac20237aac5ac8be9c605ade00b",
      );
      expect(signed.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    } finally {
      vi.useRealTimers();
    }
  });
});
