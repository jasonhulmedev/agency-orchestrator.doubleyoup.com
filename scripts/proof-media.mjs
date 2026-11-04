#!/usr/bin/env node
// hub#222 media soft delete — LIVE PROOF against ONE scratch R2 bucket. See PROOF-MEDIA.md.
//
//   npm run proof:media -- <scratch bucket> [--check-bucket <name>]...
//
// It runs the Worker's own code (src/media-store.ts, src/actuate-media.ts, src/sigv4.ts) in Node, with the agency's
// R2_PROVISION_API_TOKEN from the environment, and proves:
//   (a) a presigned PUT that signs `if-none-match: *` creates a key once, and answers 412 for an existing key;
//   (b) the trash move (CopyObject with x-amz-metadata-directive: COPY) keeps the content type;
//   (c) after media-bucket-protect, a DELETE of the trash/ object is refused (409 expected);
//   (d) with --check-bucket: each named bucket exists in the token's account (are a cell's media buckets in the
//       same Cloudflare account as the agency Worker whose token this is?).
//
// It never prints the token, the derived S3 secret or a presigned URL. WARNING: after (c) the scratch bucket holds a
// trash/ object under a 30-day bucket lock, so the bucket can not be emptied or deleted for 30 days.

import { register } from "node:module";

// The Worker source imports "./x.js" for its "./x.ts" files (bundler resolution). Map that for Node, which then
// strips the types itself (Node 22.18 or newer).
register(
  "data:text/javascript," +
    encodeURIComponent(`
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
export async function resolve(specifier, context, next) {
  const fromTs = context.parentURL !== undefined && context.parentURL.endsWith(".ts");
  if (fromTs && specifier.startsWith(".") && specifier.endsWith(".js")) {
    const tsUrl = new URL(specifier.slice(0, -3) + ".ts", context.parentURL);
    if (existsSync(fileURLToPath(tsUrl))) {
      return next(tsUrl.href, context);
    }
  }
  return next(specifier, context);
}`),
);

const { mediaStoreIdentity, headMediaObject, moveToTrash, mediaObjectUrl } = await import("../src/media-store.ts");
const { actuateMediaBucketProtect } = await import("../src/actuate-media.ts");
const { validateMediaBucketProtectParams, mediaBucketSitePrefix } = await import("../src/dispatch-params-media.ts");
const { presignS3Put, signS3Request } = await import("../src/sigv4.ts");
const { CF_API } = await import("../src/actuate.ts");

function usage(message) {
  if (message) {
    console.error(`error: ${message}`);
  }
  console.error("usage: npm run proof:media -- <scratch bucket doubleyoup-media-<prefix>> [--check-bucket <name>]...");
  console.error("environment: R2_PROVISION_API_TOKEN (required), R2_EXPECTED_ACCOUNT_ID (optional)");
  process.exit(2);
}

function parseArguments(argv) {
  let bucket = null;
  const checkBuckets = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--check-bucket") {
      const name = argv[index + 1];
      if (name === undefined) {
        usage("--check-bucket needs a bucket name");
      }
      checkBuckets.push(name);
      index += 1;
      continue;
    }
    if (argument.startsWith("-")) {
      usage(`unknown option ${argument}`);
    }
    if (bucket !== null) {
      usage("name exactly one scratch bucket");
    }
    bucket = argument;
  }
  if (bucket === null) {
    usage("name the scratch bucket");
  }
  return { bucket, checkBuckets };
}

const results = [];

function record(step, passed, detail) {
  results.push({ step, passed, detail });
  const mark = passed ? "PASS" : "FAIL";
  console.log(`[${mark}] ${step}: ${detail}`);
}

async function presignedCreateOncePut(identity, bucket, key, body, contentType) {
  const length = new TextEncoder().encode(body).byteLength;
  const headers = { "content-length": String(length), "content-type": contentType, "if-none-match": "*" };
  const presigned = await presignS3Put({
    endpoint: identity.endpoint,
    bucket,
    region: "auto",
    accessKeyId: identity.accessKeyId,
    secretAccessKey: identity.secretAccessKey,
    key,
    expiresSeconds: 600,
    signedHeaders: headers,
  });
  // Node's fetch sets content-length from the body itself; it equals the signed value.
  const response = await fetch(presigned.url, {
    method: "PUT",
    headers: { "content-type": contentType, "if-none-match": "*" },
    body,
  });
  await response.body?.cancel().catch(() => {});
  return response.status;
}

async function signedDelete(identity, bucket, key) {
  const signed = await signS3Request({
    method: "DELETE",
    url: mediaObjectUrl(identity, bucket, key),
    region: "auto",
    accessKeyId: identity.accessKeyId,
    secretAccessKey: identity.secretAccessKey,
    pathIsEncoded: true,
  });
  const response = await fetch(signed.url, { method: "DELETE", headers: signed.headers });
  const text = await response.text().catch(() => "");
  const code = /<Code>([^<]*)<\/Code>/.exec(text);
  return { status: response.status, code: code ? code[1] : null };
}

async function bucketInAccount(identity, name) {
  const response = await fetch(`${CF_API}/accounts/${encodeURIComponent(identity.accountId)}/r2/buckets/${encodeURIComponent(name)}`, {
    headers: { authorization: `Bearer ${identity.apiToken}`, accept: "application/json" },
  });
  await response.body?.cancel().catch(() => {});
  return response.status;
}

async function main() {
  const { bucket, checkBuckets } = parseArguments(process.argv.slice(2));
  const verdict = validateMediaBucketProtectParams({ bucket });
  if (!verdict.ok) {
    usage(`${bucket}: ${verdict.reason}`);
  }
  if (!process.env.R2_PROVISION_API_TOKEN) {
    usage("R2_PROVISION_API_TOKEN is not set");
  }
  const env = {
    R2_PROVISION_API_TOKEN: process.env.R2_PROVISION_API_TOKEN,
    R2_EXPECTED_ACCOUNT_ID: process.env.R2_EXPECTED_ACCOUNT_ID,
  };

  const identity = await mediaStoreIdentity(env);
  if ("error" in identity) {
    console.error(`error: ${identity.error}`);
    process.exit(1);
  }
  console.log(`account ${identity.accountId}, bucket ${bucket}`);

  const bucketStatus = await bucketInAccount(identity, bucket);
  if (bucketStatus !== 200) {
    console.error(`error: the scratch bucket ${bucket} is not readable in this account (HTTP ${bucketStatus}). Create it first.`);
    process.exit(1);
  }

  const runId = new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14);
  const key = `${mediaBucketSitePrefix(bucket)}/proof-222/${runId}.txt`;
  const contentType = "text/plain; charset=utf-8";
  const body = `hub#222 proof ${runId}\n`;

  // (a) create-once
  const firstPut = await presignedCreateOncePut(identity, bucket, key, body, contentType);
  record("a1 presigned create-once PUT of a new key", firstPut === 200, `HTTP ${firstPut} (want 200)`);
  const secondPut = await presignedCreateOncePut(identity, bucket, key, "other bytes\n", contentType);
  record("a2 the same PUT onto the existing key", secondPut === 412, `HTTP ${secondPut} (want 412)`);

  // (b) the trash move keeps the content type
  const source = await headMediaObject(identity, bucket, key);
  if (source === null || "error" in source) {
    record("b  read the object back", false, source === null ? "missing" : source.error);
    return finish(checkBuckets, identity);
  }
  const moved = await moveToTrash(identity, bucket, key, source, Date.now());
  if (!moved.ok) {
    record("b  copy into trash/ (x-amz-metadata-directive: COPY)", false, moved.error);
    return finish(checkBuckets, identity);
  }
  const trashHead = await headMediaObject(identity, bucket, moved.trashKey);
  const trashType = trashHead !== null && !("error" in trashHead) ? trashHead.contentType : null;
  record(
    "b  copy into trash/ keeps the content type",
    trashType === source.contentType,
    `source "${source.contentType}", trash "${trashType}" (${moved.trashKey})`,
  );

  // (c) the bucket lock refuses a delete in trash/
  const protect = await actuateMediaBucketProtect({ bucket }, env);
  record("c1 media-bucket-protect", protect.ok, protect.ok ? `lifecycle ${protect.lifecycle}, lock ${protect.lock}` : protect.detail);
  const protectAgain = await actuateMediaBucketProtect({ bucket }, env);
  const converged = protectAgain.ok && protectAgain.lifecycle === "unchanged" && protectAgain.lock === "unchanged";
  record("c2 media-bucket-protect again writes nothing", converged, protectAgain.ok ? `lifecycle ${protectAgain.lifecycle}, lock ${protectAgain.lock}` : protectAgain.detail);
  const trashDelete = await signedDelete(identity, bucket, moved.trashKey);
  record("c3 DELETE of the trash/ object", trashDelete.status === 409, `HTTP ${trashDelete.status}${trashDelete.code ? ` ${trashDelete.code}` : ""} (want 409)`);
  const stillThere = await headMediaObject(identity, bucket, moved.trashKey);
  record("c4 the trash/ object is still there", stillThere !== null && !("error" in stillThere), stillThere === null ? "gone" : "present");

  // Tidy the live key (not locked). The trash/ object stays for 30 days by design.
  await signedDelete(identity, bucket, key);
  return finish(checkBuckets, identity);
}

async function finish(checkBuckets, identity) {
  for (const name of checkBuckets) {
    const status = await bucketInAccount(identity, name);
    let detail = `HTTP ${status}: not in this account (or the token can not see it)`;
    if (status === 200) {
      detail = "exists in the same account as this token";
    }
    record(`d  bucket ${name}`, status === 200, detail);
  }
  const failed = results.filter((entry) => !entry.passed);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  process.exit(failed.length === 0 ? 0 : 1);
}

await main();
