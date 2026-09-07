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

import { describe, it, expect } from "vitest";
import { presignS3Put, presignS3Url } from "../src/sigv4.js";

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
