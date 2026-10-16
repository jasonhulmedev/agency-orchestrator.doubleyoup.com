// planning/47 — the agency-cell boot-script update, Worker side: gcp-instance-get reports the
// non-secret facts of a VM's metadata, and gcp-instance-set-metadata takes the caller's expected
// fingerprint and reports the hash of what it wrote.
//
// What these tests pin:
//   - the planning/47 twin block is byte-identical with the app copy (the sha256 pin below — the app's
//     agency-dispatch-params-p47.test.ts pins the SAME value);
//   - expectedFingerprint is OPTIONAL, signed only when sent, and refused when it is not a fingerprint;
//   - a fingerprint that is not the caller's is refused with NOTHING written (one read, no write);
//   - the read reports the fingerprint, the script's sha256 and byte count, and the bundle pin read
//     from exactly one injected line — and never one byte of the script's text.

import { describe, it, expect, vi, afterEach } from "vitest";
// Vite's `?raw` suffix: the Worker's own params source as text, for the twin-block pin (see the same
// import in hub58-ops.test.ts for why it carries @ts-ignore).
// @ts-ignore
import rawDispatchParamsSource from "../src/dispatch-params.ts?raw";
import type { Env } from "../src/env.js";
import {
  GCP_METADATA_FINGERPRINT_RULE,
  expectedFingerprintVerdict,
  validateCfTunnelTokenGetParams,
  validateGcpInstanceSetMetadataParams,
} from "../src/dispatch-params.js";
import { actuateGcpInstanceSetMetadata, bootMetadataFactsOf, readComputeInstanceAddress } from "../src/actuate.js";
import { actuateCfTunnelTokenGet, isConnectorTokenForTunnel } from "../src/actuate-p47.js";
import { DISPATCH_OPS } from "../src/dispatch-verify.js";
import { DISPATCH_OP_REGISTRY } from "../src/ops.js";

const dispatchParamsSource: string = rawDispatchParamsSource as string;

// ── The twin pin ─────────────────────────────────────────────────────────────────────

const TWIN_BLOCK_START_MARKER = "// ── planning/47: the boot-script update";
const TWIN_BLOCK_END_MARKER = "\n// ── hub#58: syd through its Worker";
// The app's src/server/services/agency-dispatch-params-p47.test.ts pins the SAME value.
const TWIN_BLOCK_SHA256 = "cb64e5617b84e60247187568ed00dc68545208ff92e366a309d87c12620f40a7";

const PROJECT = "sbm-website-272023";
const ZONE = "australia-southeast2-a";
const NODE = "dy-web-australia-southeast2-1";
const GCP_ACCESS_TOKEN = "ya29.must-not-be-echoed";
const COMPUTE = "https://compute.googleapis.com/compute/v1";
const INSTANCE_URL = `${COMPUTE}/projects/${PROJECT}/zones/${ZONE}/instances/${NODE}`;
const BUNDLE_URL = "https://bundles.doubleyoup.com/cell-bundle-20261015-f4d4ddf.tar.gz";
const BUNDLE_SHA256 = "ce440938fd0be4e01fd9b3ef5718c4506d97716ca9b878d7892e44979b22864f";
const SECRET_TOKEN = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

/** A rendered web.sh in the shape cell-bootstrap.ts writes, with a secret the read must never echo. */
const RENDERED_WEB_SCRIPT =
  "#!/bin/bash\n" +
  "set -euo pipefail\n" +
  "# ── values injected by orchestrator cell-provision (cell-bootstrap.ts): shell-quoted, read-only ──\n" +
  `readonly DY_NODE_NAME='${NODE}'\n` +
  `readonly DY_BUNDLE_URL='${BUNDLE_URL}'\n` +
  `readonly DY_BUNDLE_SHA256='${BUNDLE_SHA256}'\n` +
  `readonly DY_CELL_AGENT_TOKEN='${SECRET_TOKEN}'\n` +
  'log "bundle=${DY_BUNDLE_URL}"\n';

async function sha256HexOf(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("planning/47 twin block", () => {
  it("is byte-identical with the app copy (pinned sha256 — change BOTH twins and BOTH pins together)", async () => {
    const start = dispatchParamsSource.indexOf(TWIN_BLOCK_START_MARKER);
    const end = dispatchParamsSource.indexOf(TWIN_BLOCK_END_MARKER, start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(await sha256HexOf(dispatchParamsSource.slice(start, end))).toBe(TWIN_BLOCK_SHA256);
  });
});

// ── Validators ───────────────────────────────────────────────────────────────────────

describe("gcp-instance-set-metadata expectedFingerprint (twin of the app's rules)", () => {
  const BASE = { project: PROJECT, zone: ZONE, name: NODE, items: [{ key: "startup-script", value: "#!/bin/bash\nexit 0\n" }] };

  it("is OPTIONAL: a request without it signs exactly the four known keys, as before", () => {
    expect(validateGcpInstanceSetMetadataParams(BASE)).toEqual({ ok: true, params: BASE });
  });

  it("is signed when sent, and only the known keys ride along", () => {
    const verdict = validateGcpInstanceSetMetadataParams({ ...BASE, expectedFingerprint: "tuw1oE7hWfE=", extra: "dropped" });
    expect(verdict).toEqual({ ok: true, params: { ...BASE, expectedFingerprint: "tuw1oE7hWfE=" } });
  });

  it("refuses every value that is not a fingerprint, naming the field", () => {
    for (const bad of ["", " ", "fp abc", "fp'abc", "fp\nabc", "a".repeat(65), 42, null, ["fp"], { fp: 1 }]) {
      const verdict = validateGcpInstanceSetMetadataParams({ ...BASE, expectedFingerprint: bad });
      expect(verdict).toEqual({ ok: false, reason: GCP_METADATA_FINGERPRINT_RULE });
    }
  });

  it("expectedFingerprintVerdict: absent, valid, or the rule", () => {
    expect(expectedFingerprintVerdict(undefined)).toEqual({ ok: true, expectedFingerprint: undefined });
    expect(expectedFingerprintVerdict("A-z_0+9/=")).toEqual({ ok: true, expectedFingerprint: "A-z_0+9/=" });
    expect(expectedFingerprintVerdict("bad value")).toEqual({ ok: false, reason: GCP_METADATA_FINGERPRINT_RULE });
  });
});

// ── bootMetadataFactsOf ──────────────────────────────────────────────────────────────

describe("bootMetadataFactsOf", () => {
  it("reports the fingerprint, the script's sha256 + bytes and its ONE bundle pin — never its text", async () => {
    const facts = await bootMetadataFactsOf({
      fingerprint: "fp-1",
      items: [
        { key: "enable-oslogin", value: "TRUE" },
        { key: "startup-script", value: RENDERED_WEB_SCRIPT },
      ],
    });
    expect(facts).toEqual({
      fingerprint: "fp-1",
      startupScript: {
        sha256: await sha256HexOf(RENDERED_WEB_SCRIPT),
        bytes: new TextEncoder().encode(RENDERED_WEB_SCRIPT).length,
        bundleUrl: BUNDLE_URL,
        bundleSha256: BUNDLE_SHA256,
      },
    });
    expect(JSON.stringify(facts)).not.toContain(SECRET_TOKEN);
  });

  it("reports no startup-script for a VM without the key, and nulls for a shape it does not understand", async () => {
    expect(await bootMetadataFactsOf(undefined)).toEqual({ fingerprint: null, startupScript: null });
    expect(await bootMetadataFactsOf({ fingerprint: "", items: "not-a-list" })).toEqual({ fingerprint: null, startupScript: null });
    expect(await bootMetadataFactsOf({ fingerprint: 7, items: [{ key: "startup-script", value: 42 }, null, "x"] })).toEqual({
      fingerprint: null,
      startupScript: null,
    });
  });

  it("a data-node script (no bundle) reports null pins; an empty sha pin is null", async () => {
    const dataScript = "#!/bin/bash\nreadonly DY_NODE_NAME='dy-data-x-1'\n";
    const facts = await bootMetadataFactsOf({ fingerprint: "fp", items: [{ key: "startup-script", value: dataScript }] });
    expect(facts.startupScript?.bundleUrl).toBeNull();
    expect(facts.startupScript?.bundleSha256).toBeNull();
    const unpinned = `#!/bin/bash\nreadonly DY_BUNDLE_URL='${BUNDLE_URL}'\nreadonly DY_BUNDLE_SHA256=''\n`;
    const unpinnedFacts = await bootMetadataFactsOf({ fingerprint: "fp", items: [{ key: "startup-script", value: unpinned }] });
    expect(unpinnedFacts.startupScript?.bundleUrl).toBe(BUNDLE_URL);
    expect(unpinnedFacts.startupScript?.bundleSha256).toBeNull();
  });

  it("two pin lines, a line of another shape, or a quoted trick are NOT reported (null, never a guess)", async () => {
    const twoLines = `#!/bin/bash\nreadonly DY_BUNDLE_URL='${BUNDLE_URL}'\nreadonly DY_BUNDLE_URL='https://evil.example/x.tar.gz'\n`;
    const indented = `#!/bin/bash\n  readonly DY_BUNDLE_URL='${BUNDLE_URL}'\n`;
    const trailing = `#!/bin/bash\nreadonly DY_BUNDLE_URL='${BUNDLE_URL}' # comment\n`;
    const injected = `#!/bin/bash\nreadonly DY_BUNDLE_URL='https://x.example/a'\\''b'\n`;
    const httpUrl = "#!/bin/bash\nreadonly DY_BUNDLE_URL='http://bundles.doubleyoup.com/cell-bundle-x.tar.gz'\n";
    for (const script of [twoLines, indented, trailing, injected, httpUrl]) {
      const facts = await bootMetadataFactsOf({ fingerprint: "fp", items: [{ key: "startup-script", value: script }] });
      expect(facts.startupScript?.bundleUrl).toBeNull();
    }
  });
});

// ── The two actuators ────────────────────────────────────────────────────────────────

interface RecordedCall {
  url: string;
  method: string;
  body: string | null;
}

function mockFetch(handler: (call: RecordedCall) => { status?: number; body: unknown }): RecordedCall[] {
  const calls: RecordedCall[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const call: RecordedCall = { url: String(input), method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : null };
    calls.push(call);
    const answer = handler(call);
    return new Response(JSON.stringify(answer.body), { status: answer.status ?? 200, headers: { "content-type": "application/json" } });
  });
  return calls;
}

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
    client_email: `agency@${projectId}.iam.gserviceaccount.com`,
    token_uri: "https://oauth2.googleapis.com/token",
  });
}

/** The token mint, the instance read (with `items`), the write and its wait. Unknown URLs answer 500. */
async function setUp(items: Array<{ key: string; value: string }>, fingerprint = "fp-current") {
  const env = { GCP_SERVICE_ACCOUNT_KEY: await makeServiceAccountKey(PROJECT) } as Env;
  const calls = mockFetch((call) => {
    if (call.url === "https://oauth2.googleapis.com/token") {
      return { body: { access_token: GCP_ACCESS_TOKEN, expires_in: 3600, token_type: "Bearer" } };
    }
    if (call.url === INSTANCE_URL && call.method === "GET") {
      return {
        body: {
          name: NODE,
          status: "RUNNING",
          networkInterfaces: [{ networkIP: "10.20.0.2", network: `${COMPUTE}/projects/${PROJECT}/global/networks/dy-cell-australia-southeast2` }],
          metadata: { fingerprint, items },
        },
      };
    }
    if (call.url === `${INSTANCE_URL}/setMetadata`) {
      return { body: { name: "operation-1", status: "RUNNING" } };
    }
    if (call.url.endsWith("/operations/operation-1/wait")) {
      return { body: { name: "operation-1", status: "DONE" } };
    }
    return { status: 500, body: { error: { message: `unexpected ${call.method} ${call.url}` } } };
  });
  const googleCalls = () => calls.filter((call) => call.url !== "https://oauth2.googleapis.com/token");
  return { env, calls, googleCalls };
}

describe("actuateGcpInstanceSetMetadata with expectedFingerprint", () => {
  const NEW_SCRIPT = "#!/bin/bash\necho new\n";

  it("a fingerprint that is not the caller's is refused with NOTHING written: one read, no write", async () => {
    const { env, googleCalls } = await setUp([{ key: "startup-script", value: "#!/bin/bash\necho old\n" }], "fp-changed");
    const result = await actuateGcpInstanceSetMetadata(
      { project: PROJECT, zone: ZONE, name: NODE, items: [{ key: "startup-script", value: NEW_SCRIPT }], expectedFingerprint: "fp-read-by-caller" },
      env,
    );
    expect(result).toMatchObject({ ok: false, op: "gcp-instance-set-metadata", staleFingerprint: true });
    if (!result.ok) {
      expect(result.detail).toContain("expected fingerprint fp-read-by-caller, found fp-changed");
      expect(result.detail).toContain("nothing was written");
    }
    expect(googleCalls().map((call) => call.method)).toEqual(["GET"]);
  });

  it("the caller's fingerprint is the one written under; the result says it was checked and gives the written hash", async () => {
    const { env, googleCalls } = await setUp([{ key: "startup-script", value: "#!/bin/bash\necho old\n" }], "fp-read-by-caller");
    const result = await actuateGcpInstanceSetMetadata(
      { project: PROJECT, zone: ZONE, name: NODE, items: [{ key: "startup-script", value: NEW_SCRIPT }], expectedFingerprint: "fp-read-by-caller" },
      env,
    );
    expect(result).toEqual({
      ok: true,
      op: "gcp-instance-set-metadata",
      instanceName: NODE,
      keysSet: ["startup-script"],
      placeholdersSubstituted: [],
      placeholderValues: {},
      valuesSha256: { "startup-script": await sha256HexOf(NEW_SCRIPT) },
      unchangedKeys: [],
      expectedFingerprintChecked: true,
      operationName: "operation-1",
    });
    const write = googleCalls().find((call) => call.url.endsWith("/setMetadata"));
    expect(JSON.parse(write?.body ?? "{}").fingerprint).toBe("fp-read-by-caller");
  });

  it("a value that is already in place is reported in unchangedKeys (the write still goes out)", async () => {
    const { env, googleCalls } = await setUp([{ key: "startup-script", value: NEW_SCRIPT }]);
    const result = await actuateGcpInstanceSetMetadata(
      { project: PROJECT, zone: ZONE, name: NODE, items: [{ key: "startup-script", value: NEW_SCRIPT }] },
      env,
    );
    expect(result).toMatchObject({ ok: true, unchangedKeys: ["startup-script"], expectedFingerprintChecked: false });
    expect(googleCalls().map((call) => call.method)).toEqual(["GET", "POST", "POST"]);
  });
});

describe("readComputeInstanceAddress (gcp-instance-get) reports the boot-metadata facts", () => {
  it("fingerprint, sha256, bytes and the bundle pin; the secret in the script is never in the result", async () => {
    const { env } = await setUp([{ key: "startup-script", value: RENDERED_WEB_SCRIPT }], "fp-9");
    const result = await readComputeInstanceAddress({ project: PROJECT, zone: ZONE, name: NODE }, env);
    expect(result).toMatchObject({
      ok: true,
      found: true,
      privateIp: "10.20.0.2",
      metadata: {
        fingerprint: "fp-9",
        startupScript: {
          sha256: await sha256HexOf(RENDERED_WEB_SCRIPT),
          bytes: new TextEncoder().encode(RENDERED_WEB_SCRIPT).length,
          bundleUrl: BUNDLE_URL,
          bundleSha256: BUNDLE_SHA256,
        },
      },
    });
    expect(JSON.stringify(result)).not.toContain(SECRET_TOKEN);
    expect(JSON.stringify(result)).not.toContain(GCP_ACCESS_TOKEN);
  });
});

// ── cf-tunnel-token-get (planning/47 decision G) ─────────────────────────────────────

const TUNNEL_ID = "df27359a-2314-466d-a031-3f7fa66c1abe";
const OTHER_TUNNEL_ID = "025cb230-c588-43f3-ad76-cce2869aefdd";
const CF_ACCOUNT_ID = "acct-cf-sbm";
const CF_TOKEN = "cf-dns-token-must-not-be-echoed";
const TUNNEL_SECRET = "c2VjcmV0LXRoYXQtbXVzdC1uZXZlci1sZWFr";

/** A connector token as Cloudflare makes one: base64 of {"a": account, "t": tunnel, "s": secret}. */
function connectorTokenFor(tunnelId: string): string {
  return btoa(JSON.stringify({ a: CF_ACCOUNT_ID, t: tunnelId, s: TUNNEL_SECRET }));
}

describe("cf-tunnel-token-get params (twin of the app's rules)", () => {
  it("is allowlisted and registered", () => {
    expect(DISPATCH_OPS).toContain("cf-tunnel-token-get");
    expect(typeof DISPATCH_OP_REGISTRY["cf-tunnel-token-get"].actuate).toBe("function");
  });

  it("accepts a tunnel id in both forms and returns ONLY the known key", () => {
    expect(validateCfTunnelTokenGetParams({ tunnelId: TUNNEL_ID, extra: "dropped" })).toEqual({ ok: true, params: { tunnelId: TUNNEL_ID } });
    expect(validateCfTunnelTokenGetParams({ tunnelId: TUNNEL_ID.replace(/-/g, "") }).ok).toBe(true);
  });

  it("refuses every other shape", () => {
    for (const raw of [null, [], "x", {}, { tunnelId: "" }, { tunnelId: TUNNEL_ID.toUpperCase() }, { tunnelId: `${TUNNEL_ID}x` }, { tunnelId: 7 }]) {
      expect(validateCfTunnelTokenGetParams(raw).ok).toBe(false);
    }
  });
});

describe("isConnectorTokenForTunnel", () => {
  it("accepts a token that names this tunnel, in either id form and in URL-safe base64", () => {
    expect(isConnectorTokenForTunnel(connectorTokenFor(TUNNEL_ID), TUNNEL_ID)).toBe(true);
    expect(isConnectorTokenForTunnel(connectorTokenFor(TUNNEL_ID), TUNNEL_ID.replace(/-/g, ""))).toBe(true);
    const urlSafe = connectorTokenFor(TUNNEL_ID).replace(/\+/g, "-").replace(/\//g, "_");
    expect(isConnectorTokenForTunnel(urlSafe, TUNNEL_ID)).toBe(true);
  });

  it("refuses a token of another tunnel, a non-token and junk", () => {
    expect(isConnectorTokenForTunnel(connectorTokenFor(OTHER_TUNNEL_ID), TUNNEL_ID)).toBe(false);
    expect(isConnectorTokenForTunnel(btoa(JSON.stringify({ a: CF_ACCOUNT_ID })).padEnd(44, "="), TUNNEL_ID)).toBe(false);
    expect(isConnectorTokenForTunnel("not a token at all, with spaces", TUNNEL_ID)).toBe(false);
    expect(isConnectorTokenForTunnel(btoa("[1,2,3]").padEnd(44, "A"), TUNNEL_ID)).toBe(false);
  });
});

describe("actuateCfTunnelTokenGet", () => {
  function cfMock(tokenAnswer: { status?: number; body: unknown }): RecordedCall[] {
    return mockFetch((call) => {
      if (call.url.startsWith("https://api.cloudflare.com/client/v4/accounts?")) {
        return { body: { success: true, result: [{ id: CF_ACCOUNT_ID }] } };
      }
      if (call.url === `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/token`) {
        return tokenAnswer;
      }
      return { status: 500, body: { success: false } };
    });
  }

  it("reads the token in the Worker token's own account, and returns it only after it proves it names this tunnel", async () => {
    const calls = cfMock({ body: { success: true, result: connectorTokenFor(TUNNEL_ID) } });
    const result = await actuateCfTunnelTokenGet({ tunnelId: TUNNEL_ID }, { CF_DNS_API_TOKEN: CF_TOKEN } as Env);
    expect(result).toEqual({ ok: true, op: "cf-tunnel-token-get", tunnelId: TUNNEL_ID, connectorToken: connectorTokenFor(TUNNEL_ID) });
    expect(calls.map((call) => call.method)).toEqual(["GET", "GET"]);
  });

  it("refuses a token that names ANOTHER tunnel, and the detail carries no part of it", async () => {
    cfMock({ body: { success: true, result: connectorTokenFor(OTHER_TUNNEL_ID) } });
    const result = await actuateCfTunnelTokenGet({ tunnelId: TUNNEL_ID }, { CF_DNS_API_TOKEN: CF_TOKEN } as Env);
    expect(result).toMatchObject({ ok: false, op: "cf-tunnel-token-get", tunnelId: TUNNEL_ID });
    expect(JSON.stringify(result)).not.toContain(TUNNEL_SECRET);
    expect(JSON.stringify(result)).not.toContain(connectorTokenFor(OTHER_TUNNEL_ID));
  });

  it("a denied token, a missing token and an unconfigured Worker are ok:false with no secret in the detail", async () => {
    cfMock({ status: 403, body: { success: false } });
    const denied = await actuateCfTunnelTokenGet({ tunnelId: TUNNEL_ID }, { CF_DNS_API_TOKEN: CF_TOKEN } as Env);
    expect(denied.ok).toBe(false);
    expect(JSON.stringify(denied)).not.toContain(CF_TOKEN);
    vi.restoreAllMocks();
    cfMock({ body: { success: true, result: null } });
    expect((await actuateCfTunnelTokenGet({ tunnelId: TUNNEL_ID }, { CF_DNS_API_TOKEN: CF_TOKEN } as Env)).ok).toBe(false);
    expect((await actuateCfTunnelTokenGet({ tunnelId: TUNNEL_ID }, {} as Env)).ok).toBe(false);
  });
});
