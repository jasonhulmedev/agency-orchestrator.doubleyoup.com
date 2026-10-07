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
  validateCfTunnelCreateParams,
  validateCfTunnelConfigParams,
  validateCfTunnelDeleteParams,
  validateDnsRecordDeleteParams,
  validateWpCliParams,
  validateDbExportParams,
  validateDbImportParams,
  validateGcpInstanceCreateParams,
  validateGcpNetworkCreateParams,
  validateGcpFirewallCreateParams,
  validateGcpAddressCreateParams,
  validateGcpRouterNatCreateParams,
  validateGcpFirewallGetParams,
  validateGcpRouterGetParams,
  validateGcpInstancesListParams,
  validateGcpInstanceDeleteParams,
  validateGcpAddressDeleteParams,
  validateGcpFirewallDeleteParams,
  validateGcpRouterDeleteParams,
  validateGcpNetworkDeleteParams,
  validateGcpInstanceSetMetadataParams,
  validateGcpInstanceRestartParams,
  validateProvisionSshKeysParams,
  validateCacheRuleUpsertParams,
  validateWafRuleUpsertParams,
  edgeCacheZoneFromHostSuffix,
  GCP_FIREWALL_PROTOCOLS,
  GCP_METADATA_KEYS,
} from "../src/dispatch-params.js";
import {
  CLOUDFLARE_MANAGED_RULESET_ID,
  MANAGED_RULESET_RULE_DESCRIPTION,
  WAF_COUNTRY_BLOCK_DESCRIPTION,
  WAF_EXEC_SKIP_DESCRIPTION,
  WAF_EXPRESSION_MAX_LENGTH,
  WAF_FRONTEND_GEO_DESCRIPTION,
  WAF_LOGIN_GATE_DESCRIPTION,
  WAF_MANAGED_PHASE,
  WAF_PHASE,
  WAF_RULE_DESCRIPTIONS,
  WAF_UNKNOWN_PLAN_RULE_CAP,
  WAF_WPADMIN_GEO_DESCRIPTION,
  buildEdgeWafRules,
  buildManagedRulesetExecuteRule,
  edgeWafRulesInOrder,
  normalizeWafCountryCodes,
  planSupportsManagedRuleset,
  wafCountryBlockExpression,
  wafCustomRuleCapForPlan,
  wafExecSkipExpression,
  wafFrontendGeoExpression,
  wafLoginGateExpression,
  wafRuleDrifted,
  wafWpAdminGeoExpression,
  type WafRule,
} from "../src/edge-waf-rule.js";
import {
  EDGE_CACHE_BYPASS_RULE_DESCRIPTION,
  EDGE_CACHE_RULE_DESCRIPTION,
  buildEdgeCacheRules,
  clampEdgeCacheTtl,
  edgeCacheRuleDrifted,
  edgeCacheRulesInOrder,
  jsonValuesEqual,
} from "../src/edge-cache-rule.js";
import { DISPATCH_OP_REGISTRY, parseDispatchParams } from "../src/ops.js";
import {
  actuateCfTunnelConfig,
  buildDbExportScript,
  buildDbImportScript,
  METADATA_PLACEHOLDER_NAMES,
  PLACEHOLDER_VALUES_SAFE_TO_ECHO,
  mergeMetadataItems,
  substituteMetadataPlaceholders,
} from "../src/actuate.js";
import { GOOGLE_SCOPE_CLOUD_PLATFORM } from "../src/validators.js";

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

// A cache-rule-upsert job — the edge page-cache rule for an agency zone's production hosts.
const CACHE_RULE_PARAMS = { hostSuffix: "-production.example.com", edgeTtlSeconds: 600, enabled: true };
function cacheRuleJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "cache-rule-upsert",
    params: JSON.stringify(CACHE_RULE_PARAMS),
    nonce: "ab12ab12ab12ab12ab12ab12ab12ab12",
    ...overrides,
  });
}

// A waf-rule-upsert job — the edge-defense baseline for an agency zone: the zone, two host lists inside
// it and the Managed Ruleset switch. The country lists are Worker constants and never travel.
const WAF_RULE_PARAMS = {
  zone: "example.com",
  enabled: true,
  excludedHosts: ["cell-x.example.com", "host.example.com"],
  agentHosts: ["cell-x.example.com"],
  includeManagedRuleset: true,
};
function wafRuleJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "waf-rule-upsert",
    params: JSON.stringify(WAF_RULE_PARAMS),
    nonce: "cd34cd34cd34cd34cd34cd34cd34cd34",
    ...overrides,
  });
}

// THE LIVE syd RULES, copied verbatim from doubleyoup.com's http_request_firewall_custom phase
// (re-read 2026-10-07). For syd-equivalent hosts the builder renders three of them byte-for-byte and
// differs from the other two ONLY in the two deliberate ways pinned below.
const SYD_LIVE_LOGIN_GATE_EXPRESSION =
  '(http.request.uri.path eq "/wp-login.php") or (starts_with(http.request.uri.path, "/wp-admin/") and not (http.request.uri.path eq "/wp-admin/admin-ajax.php") and not (http.cookie contains "wordpress_logged_in_"))';
const SYD_LIVE_COUNTRY_BLOCK_EXPRESSION = 'ip.geoip.country in {"RU" "CN" "KP"}';
const SYD_LIVE_WPADMIN_GEO_EXPRESSION =
  '(http.request.uri.path contains "/wp-admin" or http.request.uri.path eq "/wp-login.php") and not (ip.geoip.country in {"AU" "US" "GB" "NZ" "FR" "IE"})';
const SYD_LIVE_FRONTEND_GEO_EXPRESSION =
  'not (ip.geoip.country in {"AU" "US" "GB" "NZ" "FR" "IE"}) and not (cf.verified_bot_category eq "Search Engine Crawler") and not (http.host in {"app.doubleyoup.com" "status.doubleyoup.com" "media.doubleyoup.com" "host.doubleyoup.com" "cell-syd.doubleyoup.com"})';
const SYD_LIVE_EXEC_SKIP_EXPRESSION =
  '(http.host eq "cell-syd.doubleyoup.com" and starts_with(http.request.uri.path, "/exec"))';
const SYD_LIVE_EXEC_SKIP_DESCRIPTION = "skip managed WAF for cell-agent exec (internal bearer-authed endpoint)";
// Deliberate change 3 (review H1, 2026-10-07): the agent skip covers EVERY path on the agent hosts.
const EXPECTED_SYD_AGENT_SKIP_EXPRESSION = '(http.host in {"cell-syd.doubleyoup.com"})';

// NOTE the two prefixes differ ON PURPOSE and must stay different: the geo rule uses "/wp-admin"
// (no trailing slash) so bare `/wp-admin` is caught, the login gate uses "/wp-admin/" (with)
// because the bare path is only a 301 into the area it already gates. See the builder's comments.
const EXPECTED_WPADMIN_GEO_EXPRESSION =
  '(starts_with(http.request.uri.path, "/wp-admin") or http.request.uri.path eq "/wp-login.php") ' +
  'and not (http.request.uri.path eq "/wp-admin/admin-ajax.php") ' +
  'and not (ip.geoip.country in {"AU" "US" "GB" "NZ" "FR" "IE"})';

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

// A provision-ssh-keys job — declare the FULL authorized-key set for a storage-tier dogfood site
// (planning/39). The gateway cell-agent writes them; nothing sensitive comes back.
const SSH_KEYS_JOB_PARAMS = {
  project: "dy-agency-proof",
  slug: "geelongns",
  authorizedKeys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample000000000000000000000000000000000 dev@laptop"],
};
function sshKeysJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "provision-ssh-keys",
    params: JSON.stringify(SSH_KEYS_JOB_PARAMS),
    nonce: "ee99ee99ee99ee99ee99ee99ee99ee99",
    ...overrides,
  });
}

// A gcp-instance-create job — a throwaway proof VM in the agency's own project (Sydney zone).
const GCP_INSTANCE_PARAMS = {
  project: "dy-agency-proof",
  zone: "australia-southeast1-a",
  name: "dy-dirb-proof-vm",
  machineType: "e2-small",
};
function gcpInstanceCreateJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-instance-create",
    params: JSON.stringify(GCP_INSTANCE_PARAMS),
    nonce: "ee99ee99ee99ee99ee99ee99ee99ee99",
    ...overrides,
  });
}

// The cell-infra ops (planning/34 phase 2), all in the same agency project as the proof VM.
// A gcp-network-create job — a cell's dedicated custom-mode VPC + its one regional subnet.
const GCP_NETWORK_PARAMS = {
  project: "dy-agency-proof",
  region: "australia-southeast1",
  networkName: "dy-cell-australia-southeast1",
  subnetName: "dy-cell-australia-southeast1-subnet",
  ipCidr: "10.20.0.0/24",
};
function gcpNetworkCreateJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-network-create",
    params: JSON.stringify(GCP_NETWORK_PARAMS),
    nonce: "11aa11aa11aa11aa11aa11aa11aa11aa",
    ...overrides,
  });
}

// A gcp-firewall-create job — the gateway's public tcp:22 rule (hardened sshd + fail2ban behind it).
const GCP_FIREWALL_PARAMS = {
  project: "dy-agency-proof",
  networkName: "dy-cell-australia-southeast1",
  ruleName: "dy-cell-allow-gateway-ssh",
  allowed: [{ protocol: "tcp", ports: ["22"] }],
  sourceRanges: ["0.0.0.0/0"],
  targetTags: ["dy-gateway"],
};
function gcpFirewallCreateJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-firewall-create",
    params: JSON.stringify(GCP_FIREWALL_PARAMS),
    nonce: "22bb22bb22bb22bb22bb22bb22bb22bb",
    ...overrides,
  });
}

// A gcp-address-create job — the gateway's reserved static external IP.
const GCP_ADDRESS_PARAMS = {
  project: "dy-agency-proof",
  region: "australia-southeast1",
  addressName: "dy-cell-gateway-ip",
};
function gcpAddressCreateJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-address-create",
    params: JSON.stringify(GCP_ADDRESS_PARAMS),
    nonce: "33cc33cc33cc33cc33cc33cc33cc33cc",
    ...overrides,
  });
}

// A gcp-router-nat-create job — the cell's Cloud Router + inline NAT (egress for the private VMs).
const GCP_ROUTER_NAT_PARAMS = {
  project: "dy-agency-proof",
  region: "australia-southeast1",
  networkName: "dy-cell-australia-southeast1",
  routerName: "dy-cell-australia-southeast1-router",
  natName: "dy-cell-australia-southeast1-nat",
};
function gcpRouterNatCreateJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-router-nat-create",
    params: JSON.stringify(GCP_ROUTER_NAT_PARAMS),
    nonce: "44dd44dd44dd44dd44dd44dd44dd44dd",
    ...overrides,
  });
}

// A gcp-firewall-get job — READ-BACK a cell firewall rule on resume (finding 1 verification). Global,
// so no region.
const GCP_FIREWALL_GET_PARAMS = {
  project: "dy-agency-proof",
  ruleName: "dy-cell-australia-southeast1-gw-ssh",
};
function gcpFirewallGetJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-firewall-get",
    params: JSON.stringify(GCP_FIREWALL_GET_PARAMS),
    nonce: "55ee55ee55ee55ee55ee55ee55ee55ee",
    ...overrides,
  });
}

// A gcp-router-get job — READ-BACK a cell Cloud Router (and its NAT config names) on resume.
const GCP_ROUTER_GET_PARAMS = {
  project: "dy-agency-proof",
  region: "australia-southeast1",
  routerName: "dy-cell-australia-southeast1-router",
};
function gcpRouterGetJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-router-get",
    params: JSON.stringify(GCP_ROUTER_GET_PARAMS),
    nonce: "66ff66ff66ff66ff66ff66ff66ff66ff",
    ...overrides,
  });
}

// A gcp-instances-list job — READ-ONLY zone discovery: list the cell's VMs by name prefix on resume.
const GCP_INSTANCES_LIST_PARAMS = {
  project: "dy-agency-proof",
  namePrefix: "dy-",
};
function gcpInstancesListJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-instances-list",
    params: JSON.stringify(GCP_INSTANCES_LIST_PARAMS),
    nonce: "77aa77aa77aa77aa77aa77aa77aa77aa",
    ...overrides,
  });
}

// The TEARDOWN ops (planning/34 teardown) — the reverse of the cell-infra creates above, against the
// same cell in the same agency project. Every one is idempotent: Google's 404 = already gone = ok.
// A gcp-instance-delete job — remove ONE cell VM (the FIRST teardown step; everything else is in use
// while a VM lives).
const GCP_INSTANCE_DELETE_PARAMS = {
  project: "dy-agency-proof",
  zone: "australia-southeast1-a",
  name: "dy-web-australia-southeast1-1",
};
function gcpInstanceDeleteJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-instance-delete",
    params: JSON.stringify(GCP_INSTANCE_DELETE_PARAMS),
    nonce: "88bb88bb88bb88bb88bb88bb88bb88bb",
    ...overrides,
  });
}

// A gcp-address-delete job — release the gateway's reserved static external IP (after the VMs).
const GCP_ADDRESS_DELETE_PARAMS = {
  project: "dy-agency-proof",
  region: "australia-southeast1",
  addressName: "dy-cell-gateway-ip",
};
function gcpAddressDeleteJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-address-delete",
    params: JSON.stringify(GCP_ADDRESS_DELETE_PARAMS),
    nonce: "99cc99cc99cc99cc99cc99cc99cc99cc",
    ...overrides,
  });
}

// A gcp-firewall-delete job — remove one cell firewall rule (GLOBAL, so no region).
const GCP_FIREWALL_DELETE_PARAMS = {
  project: "dy-agency-proof",
  ruleName: "dy-cell-australia-southeast1-gw-ssh",
};
function gcpFirewallDeleteJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-firewall-delete",
    params: JSON.stringify(GCP_FIREWALL_DELETE_PARAMS),
    nonce: "aa11aa11aa11aa11aa11aa11aa11aa11",
    ...overrides,
  });
}

// A gcp-router-delete job — remove the cell's Cloud Router; its inline NAT goes with it.
const GCP_ROUTER_DELETE_PARAMS = {
  project: "dy-agency-proof",
  region: "australia-southeast1",
  routerName: "dy-cell-australia-southeast1-router",
};
function gcpRouterDeleteJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-router-delete",
    params: JSON.stringify(GCP_ROUTER_DELETE_PARAMS),
    nonce: "bb22bb22bb22bb22bb22bb22bb22bb22",
    ...overrides,
  });
}

// A gcp-network-delete job — remove the cell's VPC: the subnet FIRST, then the network.
const GCP_NETWORK_DELETE_PARAMS = {
  project: "dy-agency-proof",
  region: "australia-southeast1",
  networkName: "dy-cell-australia-southeast1",
  subnetName: "dy-cell-australia-southeast1-subnet",
};
function gcpNetworkDeleteJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-network-delete",
    params: JSON.stringify(GCP_NETWORK_DELETE_PARAMS),
    nonce: "cc33cc33cc33cc33cc33cc33cc33cc33",
    ...overrides,
  });
}

// The two in-place UPDATE ops (planning/47), against the same cell's FILE node. The boot script the
// platform renders carries PLACEHOLDERS for the agency's object-store values (the Worker fills them
// from its own S3_* secrets) and may carry real platform secrets of its own (the restic password
// line below stands in for one — a FIXTURE value, not a credential), which a detail string must
// never echo.
const FILE_NODE_BOOT_SCRIPT =
  "#!/bin/bash\n" +
  "readonly DY_T2_ACCESS_KEY_ID='@@DY_T2_S3_ACCESS_KEY_ID@@'\n" +
  "readonly DY_T2_SECRET_ACCESS_KEY='@@DY_T2_S3_SECRET_ACCESS_KEY@@'\n" +
  "readonly DY_T2_ENDPOINT='@@DY_T2_S3_ENDPOINT@@'\n" +
  "readonly DY_T2_BUCKET='@@DY_T2_S3_BUCKET@@'\n" +
  "readonly DY_T2_REGION='@@DY_T2_S3_REGION@@'\n" +
  // hub#64: Tier-1's bucket is its own placeholder. envWith() leaves S3_BACKUP_BUCKET unset, so this
  // one renders to the SAME bucket as Tier-2 — the fallback every existing agency stays on.
  "readonly DY_T1_BUCKET='@@DY_T1_S3_BUCKET@@'\n" +
  "readonly RESTIC_PASSWORD='fixture-restic-password-must-not-echo'\n";
// What the Worker writes to Google for FILE_NODE_BOOT_SCRIPT under envWith()'s S3_* fixture values.
const FILE_NODE_BOOT_SCRIPT_RENDERED =
  "#!/bin/bash\n" +
  "readonly DY_T2_ACCESS_KEY_ID='s3-akid-example'\n" +
  "readonly DY_T2_SECRET_ACCESS_KEY='s3-secret-example'\n" +
  "readonly DY_T2_ENDPOINT='https://acct123.r2.example.test'\n" +
  "readonly DY_T2_BUCKET='agency-backups'\n" +
  "readonly DY_T2_REGION='auto'\n" +
  "readonly DY_T1_BUCKET='agency-backups'\n" +
  "readonly RESTIC_PASSWORD='fixture-restic-password-must-not-echo'\n";
const GCP_SET_METADATA_PARAMS = {
  project: "dy-agency-proof",
  zone: "australia-southeast1-a",
  name: "dy-file-australia-southeast1-1",
  items: [{ key: "startup-script", value: FILE_NODE_BOOT_SCRIPT }],
};
function gcpSetMetadataJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-instance-set-metadata",
    params: JSON.stringify(GCP_SET_METADATA_PARAMS),
    nonce: "dd44dd44dd44dd44dd44dd44dd44dd44",
    ...overrides,
  });
}

// A gcp-instance-restart job — graceful stop then start of the file node, so the new script runs.
const GCP_RESTART_PARAMS = {
  project: "dy-agency-proof",
  zone: "australia-southeast1-a",
  name: "dy-file-australia-southeast1-1",
};
function gcpRestartJob(overrides: Partial<DispatchJob> = {}): DispatchJob {
  return sampleJob({
    op: "gcp-instance-restart",
    params: JSON.stringify(GCP_RESTART_PARAMS),
    nonce: "ee55ee55ee55ee55ee55ee55ee55ee55",
    ...overrides,
  });
}

// Build a REAL service-account key JSON with a freshly generated RSA key, so the actuator's RS256
// JWT-bearer mint runs for real (only the token + Compute HTTP calls are mocked). Mirrors the
// helper in validators.test.ts; kept local so this file stays self-contained.
async function makeServiceAccountKey(projectId: string): Promise<string> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)) as ArrayBuffer);
  const base64 = bytesToBase64(pkcs8);
  const pem = `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  return JSON.stringify({
    type: "service_account",
    project_id: projectId,
    private_key: pem,
    client_email: `sa@${projectId}.iam.gserviceaccount.com`,
    token_uri: "https://oauth2.googleapis.com/token",
  });
}

/** Decode the claims segment of a JWT assertion (base64url, no padding) so a test can read `scope`. */
function jwtClaimsOf(assertion: string): Record<string, unknown> {
  const claimsSegment = assertion.split(".")[1];
  const padded = claimsSegment
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(claimsSegment.length / 4) * 4, "=");
  return JSON.parse(atob(padded)) as Record<string, unknown>;
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

  it("cf-tunnel-create: accepts a valid tunnelName and returns ONLY the known key", () => {
    expect(validateCfTunnelCreateParams({ tunnelName: "dy-cell-australia-southeast2", extra: "x" })).toEqual({
      ok: true,
      params: { tunnelName: "dy-cell-australia-southeast2" },
    });
  });

  it("cf-tunnel-create: rejects a non-object and a bad tunnelName", () => {
    expect(validateCfTunnelCreateParams(null).ok).toBe(false);
    expect(validateCfTunnelCreateParams("dy-cell").ok).toBe(false);
    expect(validateCfTunnelCreateParams({}).ok).toBe(false);
    expect(validateCfTunnelCreateParams({ tunnelName: "" }).ok).toBe(false);
    expect(validateCfTunnelCreateParams({ tunnelName: "UPPER" }).ok).toBe(false);
    expect(validateCfTunnelCreateParams({ tunnelName: "-lead" }).ok).toBe(false);
    expect(validateCfTunnelCreateParams({ tunnelName: "trail-" }).ok).toBe(false);
    expect(validateCfTunnelCreateParams({ tunnelName: "has space" }).ok).toBe(false);
    expect(validateCfTunnelCreateParams({ tunnelName: "a".repeat(64) }).ok).toBe(false);
    expect(validateCfTunnelCreateParams({ tunnelName: 42 }).ok).toBe(false);
  });

  it("cf-tunnel-config: accepts valid ingress and returns only known keys (fresh rule objects)", () => {
    const params = {
      tunnelId: "0123456789abcdef0123456789abcdef",
      ingress: [
        { hostname: "cell-australia-southeast2.example.com", service: "http://dy-web-x.internal:9440", extra: "x" },
      ],
    };
    expect(validateCfTunnelConfigParams(params)).toEqual({
      ok: true,
      params: {
        tunnelId: "0123456789abcdef0123456789abcdef",
        ingress: [{ hostname: "cell-australia-southeast2.example.com", service: "http://dy-web-x.internal:9440" }],
      },
    });
    // https origin + no explicit port is fine too.
    expect(
      validateCfTunnelConfigParams({
        tunnelId: "0123456789abcdef0123456789abcdef",
        ingress: [{ hostname: "a.example.com", service: "https://origin.example.com" }],
      }).ok,
    ).toBe(true);
    // The REAL cfd_tunnel id format is a 36-char hyphenated UUID (regression: the live provision
    // returned 031b5bee-a61a-444f-882e-451fd644e59f and the old 32-hex-only grammar rejected it).
    expect(
      validateCfTunnelConfigParams({
        tunnelId: "031b5bee-a61a-444f-882e-451fd644e59f",
        ingress: [{ hostname: "a.example.com", service: "http://x.internal:9440" }],
      }).ok,
    ).toBe(true);
  });

  it("cf-tunnel-config: rejects a bad tunnelId, empty/oversized ingress, and bad rules", () => {
    const okId = "0123456789abcdef0123456789abcdef";
    const rule = { hostname: "a.example.com", service: "http://x.internal:9440" };
    expect(validateCfTunnelConfigParams(null).ok).toBe(false);
    expect(validateCfTunnelConfigParams("x").ok).toBe(false);
    // tunnelId must be 32 lowercase hex.
    expect(validateCfTunnelConfigParams({ tunnelId: "not-hex", ingress: [rule] }).ok).toBe(false);
    expect(validateCfTunnelConfigParams({ tunnelId: okId.toUpperCase(), ingress: [rule] }).ok).toBe(false);
    // ingress bounds.
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [] }).ok).toBe(false);
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: "x" }).ok).toBe(false);
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: Array(21).fill(rule) }).ok).toBe(false);
    // rule shape.
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [{ hostname: "a.example.com" }] }).ok).toBe(false);
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [{ hostname: "localhost", service: "http://x:9440" }] }).ok).toBe(false); // single-label host
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [{ hostname: "a.example.com", service: "ftp://x:9440" }] }).ok).toBe(false); // bad scheme
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [{ hostname: "a.example.com", service: "http://x/path" }] }).ok).toBe(false); // path not allowed
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [{ hostname: "a.example.com", service: "http://x:99999" }] }).ok).toBe(false); // port > 65535
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [{ hostname: "a.example.com", service: "http_status:404" }] }).ok).toBe(false); // caller can't inject the catch-all
  });

  it("cf-tunnel-config: catchAllService is OPTIONAL — absent => no key (the 404 default); present => an origin URL (a rule's grammar) or http_status:<3 digits>", () => {
    const okId = "0123456789abcdef0123456789abcdef";
    const rule = { hostname: "a.example.com", service: "http://x.internal:9440" };

    // Absent: the params object carries NO catchAllService key at all — the signed bytes + the
    // written config of every pre-existing caller are byte-identical (toEqual ignores undefined
    // props, so pin the key's absence explicitly).
    const absent = validateCfTunnelConfigParams({ tunnelId: okId, ingress: [rule] });
    expect(absent).toEqual({ ok: true, params: { tunnelId: okId, ingress: [rule] } });
    expect(absent.ok && "catchAllService" in absent.params).toBe(false);

    // The cell case: the web node's nginx over the VPC (an http origin URL, same grammar as a rule).
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [rule], catchAllService: "http://dy-web-x.internal:80" })).toEqual({
      ok: true,
      params: { tunnelId: okId, ingress: [rule], catchAllService: "http://dy-web-x.internal:80" },
    });
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [rule], catchAllService: "https://origin.example.com" }).ok).toBe(true);
    // The fixed-status form (the explicit default, or any other 3-digit status).
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [rule], catchAllService: "http_status:404" }).ok).toBe(true);
    expect(validateCfTunnelConfigParams({ tunnelId: okId, ingress: [rule], catchAllService: "http_status:503" }).ok).toBe(true);

    // Fails closed on anything else: wrong type, empty, a malformed status, a bad scheme/path/port.
    const bad: unknown[] = [
      null,
      42,
      "",
      "http_status:40",
      "http_status:4040",
      "http_status:abc",
      "ftp://x.internal:80",
      "http://x.internal/path",
      "http://x.internal:99999",
      "x.internal:80",
    ];
    for (const catchAllService of bad) {
      const verdict = validateCfTunnelConfigParams({ tunnelId: okId, ingress: [rule], catchAllService });
      expect(verdict.ok, `should reject ${JSON.stringify(catchAllService)}`).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(/^catchAllService/);
    }
  });

  it("cf-tunnel-delete: accepts a UUID/32-hex tunnelId and rejects junk (planning/40 Phase B)", () => {
    expect(validateCfTunnelDeleteParams({ tunnelId: "031b5bee-a61a-444f-882e-451fd644e59f", extra: "x" })).toEqual({
      ok: true,
      params: { tunnelId: "031b5bee-a61a-444f-882e-451fd644e59f" },
    });
    expect(validateCfTunnelDeleteParams({ tunnelId: "0123456789abcdef0123456789abcdef" }).ok).toBe(true);
    expect(validateCfTunnelDeleteParams(null).ok).toBe(false);
    expect(validateCfTunnelDeleteParams({}).ok).toBe(false);
    expect(validateCfTunnelDeleteParams({ tunnelId: "not-hex" }).ok).toBe(false);
    expect(validateCfTunnelDeleteParams({ tunnelId: "031B5BEE-A61A-444F-882E-451FD644E59F" }).ok).toBe(false); // uppercase
  });

  it("dns-record-delete: accepts an in-zone type+name and rejects out-of-zone / bad input (planning/40 Phase B)", () => {
    expect(validateDnsRecordDeleteParams({ zone: "example.com", type: "CNAME", name: "cell-x.example.com", extra: "x" })).toEqual({
      ok: true,
      params: { zone: "example.com", type: "CNAME", name: "cell-x.example.com" },
    });
    expect(validateDnsRecordDeleteParams(null).ok).toBe(false);
    expect(validateDnsRecordDeleteParams({ zone: "example.com", type: "CNAME", name: "cell-x.other.com" }).ok).toBe(false); // out of zone
    expect(validateDnsRecordDeleteParams({ zone: "example.com", type: "MX", name: "cell-x.example.com" }).ok).toBe(false); // type not allowed
    expect(validateDnsRecordDeleteParams({ zone: "Example.com", type: "CNAME", name: "cell-x.example.com" }).ok).toBe(false); // uppercase zone
  });

  it("the op registry has exactly the allowlisted ops, each with validateParams + actuate", () => {
    expect(Object.keys(DISPATCH_OP_REGISTRY).sort()).toEqual([
      "cache-purge",
      "cache-rule-upsert",
      "cf-tunnel-config",
      "cf-tunnel-create",
      "cf-tunnel-delete",
      "db-export",
      "db-import",
      "dns-record-delete",
      "dns-record-upsert",
      "gcp-address-create",
      "gcp-address-delete",
      "gcp-firewall-create",
      "gcp-firewall-delete",
      "gcp-firewall-get",
      "gcp-instance-create",
      "gcp-instance-delete",
      "gcp-instance-restart",
      "gcp-instance-set-metadata",
      "gcp-instances-list",
      "gcp-network-create",
      "gcp-network-delete",
      "gcp-router-delete",
      "gcp-router-get",
      "gcp-router-nat-create",
      "provision-r2",
      "provision-ssh-keys",
      "waf-rule-upsert",
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

  // ── cache-rule-upsert (twin of the app's rules) ───────────────────────────────────

  it("cache-rule-upsert: accepts a suffix + TTL, defaults enabled to true, and returns only known keys", () => {
    expect(
      validateCacheRuleUpsertParams({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600, extra: "x" }),
    ).toEqual({ ok: true, params: { hostSuffix: "-production.example.com", edgeTtlSeconds: 600, enabled: true } });
    expect(
      validateCacheRuleUpsertParams({ hostSuffix: "-production.sbmstudio.com.au", edgeTtlSeconds: 60, enabled: false }),
    ).toEqual({ ok: true, params: { hostSuffix: "-production.sbmstudio.com.au", edgeTtlSeconds: 60, enabled: false } });
    expect(validateCacheRuleUpsertParams({ hostSuffix: "-production.example.com", edgeTtlSeconds: 3600 }).ok).toBe(true);
    // NEVER a raw rule: an expression / action_parameters smuggled into the job is dropped.
    const smuggled = validateCacheRuleUpsertParams({
      ...CACHE_RULE_PARAMS,
      expression: "true",
      action_parameters: { cache: true, edge_ttl: { mode: "override_origin", default: 31536000 } },
    });
    expect(smuggled).toEqual({ ok: true, params: CACHE_RULE_PARAMS });
  });

  it("cache-rule-upsert: rejects bad input field by field (fails closed)", () => {
    const bad = (overrides: Record<string, unknown>) => validateCacheRuleUpsertParams({ ...CACHE_RULE_PARAMS, ...overrides });

    expect(validateCacheRuleUpsertParams(null).ok).toBe(false);
    expect(validateCacheRuleUpsertParams([]).ok).toBe(false);
    // hostSuffix
    expect(bad({ hostSuffix: undefined }).ok).toBe(false);
    expect(bad({ hostSuffix: "" }).ok).toBe(false);
    expect(bad({ hostSuffix: "example.com" }).ok).toBe(false); // no prefix
    expect(bad({ hostSuffix: ".example.com" }).ok).toBe(false); // no prefix
    expect(bad({ hostSuffix: "-staging.example.com" }).ok).toBe(false); // wrong environment
    expect(bad({ hostSuffix: "-production.com" }).ok).toBe(false); // single-label zone
    expect(bad({ hostSuffix: "-production.Example.com" }).ok).toBe(false); // uppercase
    expect(bad({ hostSuffix: "-production.*.example.com" }).ok).toBe(false); // wildcard
    expect(bad({ hostSuffix: " -production.example.com" }).ok).toBe(false); // padded
    expect(bad({ hostSuffix: '-production.example.com") or (true' }).ok).toBe(false); // expression injection
    expect(bad({ hostSuffix: "-production.example.com\\" }).ok).toBe(false); // backslash
    expect(bad({ hostSuffix: 42 }).ok).toBe(false);
    // edgeTtlSeconds
    expect(bad({ edgeTtlSeconds: undefined }).ok).toBe(false);
    expect(bad({ edgeTtlSeconds: 59 }).ok).toBe(false);
    expect(bad({ edgeTtlSeconds: 3601 }).ok).toBe(false);
    expect(bad({ edgeTtlSeconds: 600.5 }).ok).toBe(false); // not an integer
    expect(bad({ edgeTtlSeconds: "600" }).ok).toBe(false); // a string, not a number
    expect(bad({ edgeTtlSeconds: Number.NaN }).ok).toBe(false);
    // enabled
    expect(bad({ enabled: "false" }).ok).toBe(false);
    expect(bad({ enabled: 0 }).ok).toBe(false);
    expect(bad({ enabled: null }).ok).toBe(false);
  });

  it("cache-rule-upsert: the zone is exactly the suffix minus the -production. prefix", () => {
    expect(edgeCacheZoneFromHostSuffix("-production.example.com")).toBe("example.com");
    expect(edgeCacheZoneFromHostSuffix("-production.sbmstudio.com.au")).toBe("sbmstudio.com.au");
    expect(edgeCacheZoneFromHostSuffix("-production.com")).toBeNull();
    expect(edgeCacheZoneFromHostSuffix("x-production.example.com")).toBeNull();
  });

  // ── waf-rule-upsert (twin of the app's rules) ─────────────────────────────────────

  it("waf-rule-upsert: accepts the five known keys, defaults enabled to true, and returns fresh arrays", () => {
    const withoutEnabled = {
      zone: WAF_RULE_PARAMS.zone,
      excludedHosts: [...WAF_RULE_PARAMS.excludedHosts],
      agentHosts: [...WAF_RULE_PARAMS.agentHosts],
      includeManagedRuleset: true,
    };
    const verdict = validateWafRuleUpsertParams(withoutEnabled);
    expect(verdict).toEqual({ ok: true, params: WAF_RULE_PARAMS });
    if (!verdict.ok) throw new Error(verdict.reason);
    // FRESH arrays, never the caller's, so nothing can be mutated or smuggled in after validation.
    expect(verdict.params.excludedHosts).not.toBe(withoutEnabled.excludedHosts);
    expect(verdict.params.agentHosts).not.toBe(withoutEnabled.agentHosts);

    expect(validateWafRuleUpsertParams({ ...WAF_RULE_PARAMS, enabled: false, includeManagedRuleset: false })).toEqual({
      ok: true,
      params: { ...WAF_RULE_PARAMS, enabled: false, includeManagedRuleset: false },
    });
    // The zone apex is a legitimate excluded host (and agent host).
    expect(
      validateWafRuleUpsertParams({ ...WAF_RULE_PARAMS, excludedHosts: ["example.com", "cell-x.example.com"] }).ok,
    ).toBe(true);
    expect(
      validateWafRuleUpsertParams({ ...WAF_RULE_PARAMS, excludedHosts: ["example.com"], agentHosts: ["example.com"] }).ok,
    ).toBe(true);
  });

  it("waf-rule-upsert: an UNKNOWN key FAILS the job — a country list or an expression is never silently dropped", () => {
    const smuggled: Array<Record<string, unknown>> = [
      { blockCountries: ["AU", "US", "GB"] },
      { allowCountries: ["KP"] },
      { adminAllowCountries: ["KP"] },
      { expression: "true" },
      { action: "block" },
      { description: "doubleyoup-country-block" },
      // The pre-2026-10-07 name: a stale caller fails closed instead of silently dropping the switch.
      { deployManagedRuleset: true },
    ];
    for (const extra of smuggled) {
      const verdict = validateWafRuleUpsertParams({ ...WAF_RULE_PARAMS, ...extra });
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) {
        expect(verdict.reason).toMatch(/unknown param/);
      }
    }
  });

  it("waf-rule-upsert: rejects bad input field by field (fails closed)", () => {
    const bad = (overrides: Record<string, unknown>) => validateWafRuleUpsertParams({ ...WAF_RULE_PARAMS, ...overrides });

    expect(validateWafRuleUpsertParams(null).ok).toBe(false);
    expect(validateWafRuleUpsertParams([]).ok).toBe(false);
    expect(validateWafRuleUpsertParams("example.com").ok).toBe(false);
    // Every required key must be present.
    for (const key of ["zone", "excludedHosts", "agentHosts", "includeManagedRuleset"]) {
      const copy: Record<string, unknown> = { ...WAF_RULE_PARAMS };
      delete copy[key];
      expect(validateWafRuleUpsertParams(copy).ok).toBe(false);
    }
    // zone
    expect(bad({ zone: "" }).ok).toBe(false);
    expect(bad({ zone: "com" }).ok).toBe(false); // single-label
    expect(bad({ zone: "Example.com" }).ok).toBe(false); // uppercase
    expect(bad({ zone: "*.example.com" }).ok).toBe(false); // wildcard
    expect(bad({ zone: " example.com" }).ok).toBe(false); // padded
    expect(bad({ zone: "example.com." }).ok).toBe(false); // trailing dot
    expect(bad({ zone: 42 }).ok).toBe(false);
    expect(bad({ zone: `${"a".repeat(250)}.example.com` }).ok).toBe(false); // over 253 chars
    // enabled
    expect(bad({ enabled: "false" }).ok).toBe(false);
    expect(bad({ enabled: 0 }).ok).toBe(false);
    // excludedHosts
    expect(bad({ excludedHosts: [] }).ok).toBe(false);
    expect(bad({ excludedHosts: "cell-x.example.com" }).ok).toBe(false);
    expect(bad({ excludedHosts: ["cell-x.example.com", "app.other.com"] }).ok).toBe(false); // another zone
    expect(bad({ excludedHosts: ["cell-x.example.com", "evilexample.com"] }).ok).toBe(false); // suffix trick
    expect(bad({ excludedHosts: ["cell-x.example.com", "Host.example.com"] }).ok).toBe(false); // uppercase
    expect(bad({ excludedHosts: ["cell-x.example.com", 'a".example.com'] }).ok).toBe(false); // a quote
    expect(bad({ excludedHosts: ["cell-x.example.com", "*.example.com"] }).ok).toBe(false); // wildcard
    expect(bad({ excludedHosts: ["cell-x.example.com", "cell-x.example.com"] }).ok).toBe(false); // duplicate
    expect(bad({ excludedHosts: ["cell-x.example.com", 42] }).ok).toBe(false);
    const tooManyHosts = Array.from({ length: 101 }, (_, index) => `h${index}.example.com`);
    expect(bad({ excludedHosts: tooManyHosts, agentHosts: ["h0.example.com"] }).ok).toBe(false);
    // agentHosts
    expect(bad({ agentHosts: [] }).ok).toBe(false);
    expect(bad({ agentHosts: ["cell.other.com"] }).ok).toBe(false);
    // An agent host the front-end rule does not exempt would have its API challenged.
    const notExempted = bad({ agentHosts: ["cell-y.example.com"] });
    expect(notExempted.ok).toBe(false);
    if (!notExempted.ok) {
      expect(notExempted.reason).toMatch(/must also be in excludedHosts/);
    }
    const thirtyOneAgents = Array.from({ length: 31 }, (_, index) => `cell-${index}.example.com`);
    expect(bad({ excludedHosts: thirtyOneAgents, agentHosts: thirtyOneAgents }).ok).toBe(false);
    // includeManagedRuleset
    expect(bad({ includeManagedRuleset: "true" }).ok).toBe(false);
    expect(bad({ includeManagedRuleset: undefined }).ok).toBe(false);
  });

  // ── waf-rule-upsert: the rule BUILDER (byte-identical twin of the orchestrator's) ──
  // Every expression below is pinned character for character, and the orchestrator's
  // src/edge-waf-rule.test.ts pins the SAME text, so a change on one side of the twin breaks that
  // side's test.
  //

  /** The hosts that make the builder's input equivalent to what is live on syd today. */
  const SYD_EQUIVALENT_INPUT = {
    zone: "doubleyoup.com",
    enabled: true,
    excludedHosts: [
      "app.doubleyoup.com",
      "status.doubleyoup.com",
      "media.doubleyoup.com",
      "host.doubleyoup.com",
      "cell-syd.doubleyoup.com",
    ],
    agentHosts: ["cell-syd.doubleyoup.com"],
  };

  const EXPECTED_COUNTRY_BLOCK_EXPRESSION = 'ip.geoip.country in {"RU" "CN" "KP"}';


  const EXPECTED_LOGIN_GATE_EXPRESSION =
    '(http.request.uri.path eq "/wp-login.php") ' +
    'or (starts_with(http.request.uri.path, "/wp-admin/") ' +
    'and not (http.request.uri.path eq "/wp-admin/admin-ajax.php") ' +
    'and not (http.cookie contains "wordpress_logged_in_"))';

  // The front-end rule for WAF_RULE_PARAMS (example.com, two excluded hosts).
  const EXPECTED_FRONTEND_GEO_EXPRESSION =
    'not (ip.geoip.country in {"AU" "US" "GB" "NZ" "FR" "IE"}) ' +
    'and not (cf.verified_bot_category eq "Search Engine Crawler") ' +
    'and not (http.host in {"cell-x.example.com" "host.example.com"}) ' +
    'and not ends_with(http.host, "-media.example.com")';

  const EXPECTED_EXEC_SKIP_EXPRESSION = '(http.host in {"cell-x.example.com"})';

  /** The builder input equivalent to WAF_RULE_PARAMS. */
  const WAF_BUILD_INPUT = {
    zone: WAF_RULE_PARAMS.zone,
    enabled: true,
    excludedHosts: WAF_RULE_PARAMS.excludedHosts,
    agentHosts: WAF_RULE_PARAMS.agentHosts,
  };

  /** The five rules the Worker must build for `input`, or a thrown reason. */
  function builtWafRules(input: { zone: string; enabled: boolean; excludedHosts: string[]; agentHosts: string[] } = WAF_BUILD_INPUT) {
    const built = buildEdgeWafRules(input);
    if (!built.ok) throw new Error(built.reason);
    return built.rules;
  }

  it("waf-rule-upsert: syd-equivalent hosts render the LIVE syd rules — byte-identical except the three deliberate changes", () => {
    const rules = builtWafRules(SYD_EQUIVALENT_INPUT);
    // Byte-identical to live.
    expect(rules.loginGate.expression).toBe(SYD_LIVE_LOGIN_GATE_EXPRESSION);
    expect(rules.countryBlock.expression).toBe(SYD_LIVE_COUNTRY_BLOCK_EXPRESSION);
    expect(rules.execSkip.description).toBe(SYD_LIVE_EXEC_SKIP_DESCRIPTION);
    // Deliberate change 3 (review H1): the skip covers every path on the agent host, not only /exec.
    expect(rules.execSkip.expression).not.toBe(SYD_LIVE_EXEC_SKIP_EXPRESSION);
    expect(rules.execSkip.expression).toBe(EXPECTED_SYD_AGENT_SKIP_EXPRESSION);
    expect(rules.execSkip.action).toBe("skip");
    expect(rules.execSkip.action_parameters).toEqual({ phases: ["http_request_firewall_managed"] });
    // Deliberate change 1 (2026-10-04): `starts_with` + the admin-ajax.php exemption.
    expect(rules.wpAdminGeo.expression).not.toBe(SYD_LIVE_WPADMIN_GEO_EXPRESSION);
    expect(rules.wpAdminGeo.expression).toBe(EXPECTED_WPADMIN_GEO_EXPRESSION);
    // Deliberate change 2 (2026-10-07): ONE clause appended for the per-site media hosts. The live
    // text is an exact prefix, so nothing else in the rule moved.
    expect(rules.frontendGeo.expression).toBe(
      `${SYD_LIVE_FRONTEND_GEO_EXPRESSION} and not ends_with(http.host, "-media.doubleyoup.com")`,
    );
    // Same descriptions and actions as live, in the order the descriptions are matched on.
    expect(edgeWafRulesInOrder(rules).map((rule) => [rule.description, rule.action, rule.enabled])).toEqual([
      ["doubleyoup-country-block", "block", true],
      ["doubleyoup-wpadmin-geo", "block", true],
      ["doubleyoup-login-gate", "managed_challenge", true],
      ["doubleyoup-frontend-geo", "managed_challenge", true],
      [SYD_LIVE_EXEC_SKIP_DESCRIPTION, "skip", true],
    ]);
  });

  it("waf-rule-upsert: the exact FIVE rule bodies, built from the Worker's OWN country constants", () => {
    const rules = builtWafRules();
    expect(rules.countryBlock).toEqual({
      description: "doubleyoup-country-block",
      expression: EXPECTED_COUNTRY_BLOCK_EXPRESSION,
      action: "block",
      enabled: true,
    });
    expect(rules.wpAdminGeo).toEqual({
      description: "doubleyoup-wpadmin-geo",
      expression: EXPECTED_WPADMIN_GEO_EXPRESSION,
      action: "block",
      enabled: true,
    });
    expect(rules.loginGate).toEqual({
      description: "doubleyoup-login-gate",
      expression: EXPECTED_LOGIN_GATE_EXPRESSION,
      action: "managed_challenge",
      enabled: true,
    });
    expect(rules.frontendGeo).toEqual({
      description: "doubleyoup-frontend-geo",
      expression: EXPECTED_FRONTEND_GEO_EXPRESSION,
      action: "managed_challenge",
      enabled: true,
    });
    expect(rules.execSkip).toEqual({
      description: WAF_EXEC_SKIP_DESCRIPTION,
      expression: EXPECTED_EXEC_SKIP_EXPRESSION,
      action: "skip",
      action_parameters: { phases: [WAF_MANAGED_PHASE] },
      enabled: true,
    });
    // Only the skip rule carries action_parameters — the key is absent, not undefined, elsewhere.
    expect(Object.keys(rules.countryBlock)).not.toContain("action_parameters");
    expect(WAF_PHASE).toBe("http_request_firewall_custom");
    expect(WAF_MANAGED_PHASE).toBe("http_request_firewall_managed");
  });

  it("waf-rule-upsert: the agent skip is a host SET covering every path (an agency cell has web, file and gateway agents)", () => {
    const agents = [
      "cell-australia-southeast2.example.com",
      "cell-australia-southeast2-file.example.com",
      "cell-australia-southeast2-gw.example.com",
    ];
    expect(wafExecSkipExpression(agents)).toBe(
      '(http.host in {"cell-australia-southeast2.example.com" "cell-australia-southeast2-file.example.com" "cell-australia-southeast2-gw.example.com"})',
    );
    expect(wafExecSkipExpression(["cell-syd.doubleyoup.com"])).toBe(EXPECTED_SYD_AGENT_SKIP_EXPRESSION);
    expect(wafFrontendGeoExpression(["AU"], ["cell-x.sbmstudio.com.au"], "sbmstudio.com.au")).toBe(
      'not (ip.geoip.country in {"AU"}) and not (cf.verified_bot_category eq "Search Engine Crawler") ' +
        'and not (http.host in {"cell-x.sbmstudio.com.au"}) and not ends_with(http.host, "-media.sbmstudio.com.au")',
    );
  });

  it("waf-rule-upsert: enabled:false switches the four PROTECTIONS off in place — never the /exec skip", () => {
    const disabled = builtWafRules({ ...WAF_BUILD_INPUT, enabled: false });
    expect(disabled.countryBlock.enabled).toBe(false);
    expect(disabled.wpAdminGeo.enabled).toBe(false);
    expect(disabled.loginGate.enabled).toBe(false);
    expect(disabled.frontendGeo.enabled).toBe(false);
    // The skip keeps the cell-agent's /exec working while the Managed Ruleset is deployed; switching it
    // off in a rollback would break every heavy op on the cell.
    expect(disabled.execSkip.enabled).toBe(true);
    // A rollback rewrites no expression.
    expect(disabled.countryBlock.expression).toBe(EXPECTED_COUNTRY_BLOCK_EXPRESSION);
    expect(disabled.frontendGeo.expression).toBe(EXPECTED_FRONTEND_GEO_EXPRESSION);
  });

  it("waf-rule-upsert: the expression helpers normalize codes and REFUSE an empty set", () => {
    expect(wafCountryBlockExpression(["RU", "CN", "KP"])).toBe(EXPECTED_COUNTRY_BLOCK_EXPRESSION);
    expect(wafCountryBlockExpression([" ru ", "cn", "RU", "kp"])).toBe(EXPECTED_COUNTRY_BLOCK_EXPRESSION);
    expect(wafWpAdminGeoExpression(["AU", "US", "GB", "NZ", "FR", "IE"])).toBe(EXPECTED_WPADMIN_GEO_EXPRESSION);
    expect(wafLoginGateExpression()).toBe(EXPECTED_LOGIN_GATE_EXPRESSION);
    expect(normalizeWafCountryCodes([" ru ", "cn", "RU", "", "kp"])).toEqual(["RU", "CN", "KP"]);
    // `block nothing` and `allow nobody` are both silent disasters; CF rejects `{}` anyway.
    expect(wafCountryBlockExpression([])).toBeNull();
    expect(wafCountryBlockExpression(["", "  "])).toBeNull();
    expect(wafWpAdminGeoExpression([])).toBeNull();
    // Empty host lists are refused by the builder too (the validator refuses them first).
    expect(buildEdgeWafRules({ ...WAF_BUILD_INPUT, excludedHosts: [] }).ok).toBe(false);
    expect(buildEdgeWafRules({ ...WAF_BUILD_INPUT, agentHosts: [] }).ok).toBe(false);
  });

  it("waf-rule-upsert: an over-long host list is refused by the BUILDER (Cloudflare's 4,096-character limit)", () => {
    const hosts = Array.from({ length: 100 }, (_, index) => `a-rather-long-infrastructure-host-${index}.example.com`);
    const verdict = buildEdgeWafRules({ ...WAF_BUILD_INPUT, excludedHosts: hosts, agentHosts: [hosts[0] as string] });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.reason).toMatch(/doubleyoup-frontend-geo/);
      expect(verdict.reason).toMatch(new RegExp(`${WAF_EXPRESSION_MAX_LENGTH}-character`));
    }
  });

  it("waf-rule-upsert: strictest-first order, exact descriptions, plan caps and Managed Ruleset availability", () => {
    const ordered = edgeWafRulesInOrder(builtWafRules());
    expect(ordered.map((rule) => rule.description)).toEqual([
      "doubleyoup-country-block",
      "doubleyoup-wpadmin-geo",
      "doubleyoup-login-gate",
      "doubleyoup-frontend-geo",
      "skip managed WAF for cell-agent exec (internal bearer-authed endpoint)",
    ]);
    expect([...WAF_RULE_DESCRIPTIONS]).toEqual(ordered.map((rule) => rule.description));
    expect(new Set(ordered.map((rule) => rule.description)).size).toBe(ordered.length);
    // Cloudflare's per-plan custom-rule allowance (developers.cloudflare.com/waf/custom-rules).
    expect(wafCustomRuleCapForPlan("free")).toBe(5);
    expect(wafCustomRuleCapForPlan("pro")).toBe(20);
    expect(wafCustomRuleCapForPlan("business")).toBe(100);
    expect(wafCustomRuleCapForPlan("enterprise")).toBe(1000);
    // An unknown or missing plan is treated as the SMALLEST, so a guess can only refuse.
    expect(wafCustomRuleCapForPlan(null)).toBe(WAF_UNKNOWN_PLAN_RULE_CAP);
    expect(wafCustomRuleCapForPlan("some-new-plan")).toBe(5);
    // The Managed Ruleset is Pro and above; unknown => no.
    expect(planSupportsManagedRuleset("free")).toBe(false);
    expect(planSupportsManagedRuleset("pro")).toBe(true);
    expect(planSupportsManagedRuleset("business")).toBe(true);
    expect(planSupportsManagedRuleset("enterprise")).toBe(true);
    expect(planSupportsManagedRuleset(null)).toBe(false);
    expect(planSupportsManagedRuleset("some-new-plan")).toBe(false);
    expect(CLOUDFLARE_MANAGED_RULESET_ID).toBe("efb7b8c949ac4650a09736fc376e9aee");
    expect(buildManagedRulesetExecuteRule()).toEqual({
      description: MANAGED_RULESET_RULE_DESCRIPTION,
      expression: "true",
      action: "execute",
      action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee" },
      enabled: true,
    });
  });

  it("waf-rule-upsert: the drift check covers action, expression, enabled and action_parameters", () => {
    const loginGate = builtWafRules().loginGate;
    const echoed = {
      action: "managed_challenge",
      expression: EXPECTED_LOGIN_GATE_EXPRESSION,
      enabled: true,
    };
    expect(wafRuleDrifted(echoed, loginGate)).toBe(false);
    expect(wafRuleDrifted({ ...echoed, enabled: false }, loginGate)).toBe(true);
    expect(wafRuleDrifted({ ...echoed, action: "block" }, loginGate)).toBe(true);
    expect(wafRuleDrifted({ ...echoed, expression: "true" }, loginGate)).toBe(true);
    // A live rule Cloudflare echoes WITHOUT `enabled` is drift against our `enabled:true` — we
    // would rather PATCH a rule that was already right than leave a disabled one in place.
    expect(wafRuleDrifted({ action: echoed.action, expression: echoed.expression }, loginGate)).toBe(true);
    // A block/challenge rule carries no parameters: absent, null or {} all match; anything else is drift.
    expect(wafRuleDrifted({ ...echoed, action_parameters: null }, loginGate)).toBe(false);
    expect(wafRuleDrifted({ ...echoed, action_parameters: {} }, loginGate)).toBe(false);
    expect(wafRuleDrifted({ ...echoed, action_parameters: { response: { status_code: 200 } } }, loginGate)).toBe(true);
    // The skip rule's phases must match exactly; Cloudflare's own extra fields never count.
    const execSkip = builtWafRules().execSkip;
    const echoedSkip = { ...execSkip, id: "rule-1", ref: "cf-ref", version: "3", logging: { enabled: true } };
    expect(wafRuleDrifted(echoedSkip, execSkip)).toBe(false);
    expect(wafRuleDrifted({ ...echoedSkip, action_parameters: { phases: ["http_ratelimit"] } }, execSkip)).toBe(true);
    expect(wafRuleDrifted({ ...echoedSkip, action_parameters: undefined }, execSkip)).toBe(true);
  });

  // ── waf-rule-upsert: request-level behaviour ──────────────────────────────────────
  // A tiny evaluator for EXACTLY the clause grammar these five rules emit, so the policy is pinned
  // as REQUESTS rather than as strings. The orchestrator's twin test runs the same cases.

  interface SimulatedRequest {
    country: string;
    path: string;
    cookie: string;
    host: string;
    /** cf.verified_bot_category — "" for an ordinary visitor. */
    botCategory: string;
  }

  /** Split `text` on a top-level operator (never inside parentheses). Null when absent. */
  function splitTopLevel(text: string, operator: " and " | " or "): string[] | null {
    const parts: string[] = [];
    let depth = 0;
    let current = "";
    for (let index = 0; index < text.length; index += 1) {
      const char = text[index]!;
      if (char === "(") depth += 1;
      if (char === ")") depth -= 1;
      if (depth === 0 && text.startsWith(operator, index)) {
        parts.push(current);
        current = "";
        index += operator.length - 1;
        continue;
      }
      current += char;
    }
    if (parts.length === 0) return null;
    parts.push(current);
    return parts;
  }

  /** True when the whole string is ONE parenthesised group (not "(a) and (b)"). */
  function isWrappedInParentheses(text: string): boolean {
    if (!text.startsWith("(") || !text.endsWith(")")) return false;
    let depth = 0;
    for (let index = 0; index < text.length; index += 1) {
      if (text[index] === "(") depth += 1;
      if (text[index] === ")") depth -= 1;
      if (depth === 0 && index < text.length - 1) return false;
    }
    return true;
  }

  /** The quoted members of a Rules-language set body, e.g. `"a" "b"` -> ["a", "b"]. */
  function setMembers(body: string): string[] {
    return body.split(" ").map((item) => item.replace(/"/g, ""));
  }

  function evaluateExpression(expression: string, request: SimulatedRequest): boolean {
    const text = expression.trim();

    const orParts = splitTopLevel(text, " or ");
    if (orParts) return orParts.some((part) => evaluateExpression(part, request));
    const andParts = splitTopLevel(text, " and ");
    if (andParts) return andParts.every((part) => evaluateExpression(part, request));
    if (text.startsWith("not ")) return !evaluateExpression(text.slice(4), request);
    if (isWrappedInParentheses(text)) return evaluateExpression(text.slice(1, -1), request);

    let match = /^ip\.geoip\.country in \{(.+)\}$/.exec(text);
    if (match) return setMembers(match[1]!).includes(request.country);
    match = /^http\.host in \{(.+)\}$/.exec(text);
    if (match) return setMembers(match[1]!).includes(request.host);
    match = /^http\.host eq "(.+)"$/.exec(text);
    if (match) return request.host === match[1]!;
    match = /^ends_with\(http\.host, "(.+)"\)$/.exec(text);
    if (match) return request.host.endsWith(match[1]!);
    match = /^cf\.verified_bot_category eq "(.+)"$/.exec(text);
    if (match) return request.botCategory === match[1]!;
    match = /^http\.request\.uri\.path contains "(.+)"$/.exec(text);
    if (match) return request.path.includes(match[1]!);
    match = /^http\.request\.uri\.path eq "(.+)"$/.exec(text);
    if (match) return request.path === match[1]!;
    match = /^starts_with\(http\.request\.uri\.path, "(.+)"\)$/.exec(text);
    if (match) return request.path.startsWith(match[1]!);
    match = /^http\.cookie contains "(.+)"$/.exec(text);
    if (match) return request.cookie.includes(match[1]!);
    throw new Error(`evaluator does not understand clause: ${expression}`);
  }

  /**
   * The action of the FIRST matching TERMINATING rule, else "reaches-origin". The skip rule does not
   * decide a request's fate in this phase (it only switches the Managed Ruleset off), so it is
   * stepped over here and checked separately by managedRulesetSkipped().
   */
  function edgeVerdict(request: SimulatedRequest): "block" | "managed_challenge" | "reaches-origin" {
    const ordered: WafRule[] = edgeWafRulesInOrder(builtWafRules());
    for (const rule of ordered) {
      if (rule.action === "skip") continue;
      if (evaluateExpression(rule.expression, request)) return rule.action;
    }
    return "reaches-origin";
  }

  /** True when the /exec skip rule matches, i.e. the Managed Ruleset is skipped for this request. */
  function managedRulesetSkipped(request: SimulatedRequest): boolean {
    return evaluateExpression(builtWafRules().execSkip.expression, request);
  }

  const ANON_PAGE: SimulatedRequest = {
    country: "AU",
    path: "/about-us/",
    cookie: "_ga=GA1.1",
    host: "shop-production.example.com",
    botCategory: "",
  };

  it("waf-rule-upsert: a normal page from an allowed country is UNTOUCHED — it reaches the site", () => {
    for (const country of ["AU", "US", "GB", "NZ", "FR", "IE"]) {
      expect(edgeVerdict({ ...ANON_PAGE, country })).toBe("reaches-origin");
    }
    expect(edgeVerdict({ ...ANON_PAGE, path: "/" })).toBe("reaches-origin");
    expect(edgeVerdict({ ...ANON_PAGE, path: "/shop/product/widget/" })).toBe("reaches-origin");
    // A customer domain (a CF-for-SaaS custom hostname on the zone) is covered by the same rules.
    expect(edgeVerdict({ ...ANON_PAGE, host: "www.customer-site.com.au" })).toBe("reaches-origin");
  });

  it("waf-rule-upsert: a country outside the allow-list is CHALLENGED on the front end — not blocked", () => {
    for (const country of ["DE", "IN", "BR", "SG", "CA"]) {
      expect(edgeVerdict({ ...ANON_PAGE, country })).toBe("managed_challenge");
      expect(edgeVerdict({ ...ANON_PAGE, country, host: "www.customer-site.com.au" })).toBe("managed_challenge");
    }
  });

  it("waf-rule-upsert: a VERIFIED search crawler is not challenged on the front end, but gets no admin surface", () => {
    const crawler = { ...ANON_PAGE, country: "US", botCategory: "Search Engine Crawler" };
    expect(edgeVerdict({ ...crawler, country: "DE" })).toBe("reaches-origin");
    // An UNVERIFIED claim (a spoofed user agent) is just an ordinary visitor.
    expect(edgeVerdict({ ...ANON_PAGE, country: "DE", botCategory: "" })).toBe("managed_challenge");
    // The admin geo rule runs first, so a crawler outside the allow-list still cannot reach wp-admin,
    // and a blocked country is blocked whoever it claims to be.
    expect(edgeVerdict({ ...crawler, country: "DE", path: "/wp-admin/" })).toBe("block");
    expect(edgeVerdict({ ...crawler, country: "RU" })).toBe("block");
  });

  it("waf-rule-upsert: the zone's infrastructure hosts and its per-site media hosts are NOT challenged", () => {
    const foreign = { ...ANON_PAGE, country: "DE" };
    // excludedHosts (the cell agent, the CF-for-SaaS fallback origin).
    expect(edgeVerdict({ ...foreign, host: "cell-x.example.com", path: "/health" })).toBe("reaches-origin");
    expect(edgeVerdict({ ...foreign, host: "host.example.com" })).toBe("reaches-origin");
    // A per-site media host: an image cannot solve a challenge, so it must never get one.
    expect(edgeVerdict({ ...foreign, host: "vegaevents-media.example.com", path: "/vegaevents/2026/10/a.jpg" })).toBe(
      "reaches-origin",
    );
    // The suffix carries the leading "-": `media.<zone>` and look-alikes outside the zone are NOT exempt.
    expect(edgeVerdict({ ...foreign, host: "media.example.com" })).toBe("managed_challenge");
    expect(edgeVerdict({ ...foreign, host: "vegaevents-media.example.com.attacker.net" })).toBe("managed_challenge");
    // Case-sensitive on purpose (byte-identity with the live rules): a mixed-case Host fails SAFE.
    expect(edgeVerdict({ ...foreign, host: "Cell-X.example.com" })).toBe("managed_challenge");
    // Exempt from the CHALLENGE only — the country block and the admin rules still apply there.
    expect(edgeVerdict({ ...foreign, country: "RU", host: "cell-x.example.com" })).toBe("block");
    expect(edgeVerdict({ ...foreign, host: "host.example.com", path: "/wp-login.php" })).toBe("block");
  });

  it("waf-rule-upsert: the Managed Ruleset is skipped for EVERY path on an agent host — and nowhere else", () => {
    expect(managedRulesetSkipped({ ...ANON_PAGE, host: "cell-x.example.com", path: "/exec" })).toBe(true);
    expect(managedRulesetSkipped({ ...ANON_PAGE, host: "cell-x.example.com", path: "/exec/async" })).toBe(true);
    // The agents' other endpoints carry the same kind of body (review H1), so they are skipped too.
    expect(managedRulesetSkipped({ ...ANON_PAGE, host: "cell-x.example.com", path: "/provision-site" })).toBe(true);
    expect(managedRulesetSkipped({ ...ANON_PAGE, host: "cell-x.example.com", path: "/health" })).toBe(true);
    // /exec on any other host, or a mixed-case agent host: the Managed Ruleset runs.
    expect(managedRulesetSkipped({ ...ANON_PAGE, host: "host.example.com", path: "/exec" })).toBe(false);
    expect(managedRulesetSkipped({ ...ANON_PAGE, host: "shop-production.example.com", path: "/exec" })).toBe(false);
    expect(managedRulesetSkipped({ ...ANON_PAGE, host: "CELL-X.example.com", path: "/exec" })).toBe(false);
  });

  it("waf-rule-upsert: a blocked country does NOT reach the site, on any path", () => {
    for (const country of ["RU", "CN", "KP"]) {
      expect(edgeVerdict({ ...ANON_PAGE, country })).toBe("block");
      // The country block is FIRST, so a blocked country is blocked on the login surface too —
      // never handed the softer managed challenge, and no exemption rescues it.
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-login.php" })).toBe("block");
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-admin/" })).toBe("block");
      expect(
        edgeVerdict({ ...ANON_PAGE, country, path: "/wp-admin/admin-ajax.php", cookie: "wordpress_logged_in_x=a" }),
      ).toBe("block");
    }
  });

  it("waf-rule-upsert: /wp-admin and /wp-login.php from a non-allowed country are BLOCKED", () => {
    for (const country of ["DE", "IN", "BR", "SG"]) {
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-admin/" })).toBe("block");
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-login.php" })).toBe("block");
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-admin/edit.php" })).toBe("block");
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-admin/network/sites.php" })).toBe("block");
      // The BARE path, with no trailing slash: WordPress 301s it to /wp-admin/, and that redirect
      // must not be reachable either. This is why the geo rule's prefix carries NO trailing slash
      // while the login gate's does — do not harmonise them.
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-admin" })).toBe("block");
      // The admin-geo rule runs BEFORE the login gate, so the gate's logged-in-cookie exemption
      // does not rescue a non-allowed country.
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-admin/", cookie: "wordpress_logged_in_x=a" })).toBe("block");
    }
  });

  it("waf-rule-upsert: admin-ajax.php from a NON-allowed country is NOT blocked — it is front-end, so it gets the front-end challenge", () => {
    // The bug the 2026-10-04 exemption fixes: admin-ajax.php serves contact forms, add-to-cart, search
    // filters and load-more in most themes and plugins. The admin rules must not BLOCK it. A visitor
    // from outside the allow-list meets the same front-end challenge as on every other page.
    for (const country of ["DE", "IN", "BR", "SG"]) {
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-admin/admin-ajax.php" })).toBe("managed_challenge");
    }
    // An allow-listed country reaches it — the login gate exempts it too, so the exemptions agree.
    expect(edgeVerdict({ ...ANON_PAGE, path: "/wp-admin/admin-ajax.php" })).toBe("reaches-origin");
    // The exemption is EXACT, not a prefix: it must not become a hole.
    expect(edgeVerdict({ ...ANON_PAGE, country: "DE", path: "/wp-admin/admin-ajax.php.bak" })).toBe("block");
    expect(edgeVerdict({ ...ANON_PAGE, country: "DE", path: "/wp-admin/admin-ajax.phpx" })).toBe("block");
    expect(edgeVerdict({ ...ANON_PAGE, country: "DE", path: "/wp-admin/admin-post.php" })).toBe("block");
    // A BLOCKED country still gets nothing: the country rule runs first and has no exemptions.
    for (const country of ["RU", "CN", "KP"]) {
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/wp-admin/admin-ajax.php" })).toBe("block");
    }
  });

  it("waf-rule-upsert: the admin-geo rule is ANCHORED at the path root — an ordinary article is not admin", () => {
    // The regression `starts_with` fixes (2026-10-04). The rule used to say `contains "/wp-admin"`,
    // which matched the substring ANYWHERE, so a visitor outside the allow-list was BLOCKED from an
    // ordinary article whose URL happens to contain "wp-admin". Now that visitor meets only the
    // front-end challenge, like on any other article.
    for (const country of ["DE", "IN", "BR", "SG"]) {
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/docs/wp-admin-tips/" })).toBe("managed_challenge");
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/blog/how-to-secure-wp-admin/" })).toBe("managed_challenge");
      // A WordPress install BELOW the docroot root would also fall out of the admin rule — the
      // deliberate trade. Nothing on this platform can produce one, so this pins the trade, not a layout.
      expect(edgeVerdict({ ...ANON_PAGE, country, path: "/blog/wp-admin/" })).toBe("managed_challenge");
    }
    expect(edgeVerdict({ ...ANON_PAGE, path: "/docs/wp-admin-tips/" })).toBe("reaches-origin");
    // The one false positive `starts_with` keeps: a ROOT path that begins "wp-admin". No WordPress
    // route uses it, and it is a far smaller surface than any-substring-anywhere.
    expect(edgeVerdict({ ...ANON_PAGE, country: "DE", path: "/wp-administrator/" })).toBe("block");
  });

  it("waf-rule-upsert: the login gate challenges an ALLOWED country's login surface, with its two exemptions", () => {
    expect(edgeVerdict({ ...ANON_PAGE, path: "/wp-login.php" })).toBe("managed_challenge");
    // A forged logged-in cookie must NOT bypass the login endpoint itself.
    expect(edgeVerdict({ ...ANON_PAGE, path: "/wp-login.php", cookie: "wordpress_logged_in_x=a" })).toBe("managed_challenge");
    expect(edgeVerdict({ ...ANON_PAGE, path: "/wp-admin/" })).toBe("managed_challenge");
    expect(edgeVerdict({ ...ANON_PAGE, path: "/wp-admin/options-general.php" })).toBe("managed_challenge");
    // ...except admin-ajax and a genuine logged-in session.
    expect(edgeVerdict({ ...ANON_PAGE, path: "/wp-admin/admin-ajax.php" })).toBe("reaches-origin");
    expect(edgeVerdict({ ...ANON_PAGE, path: "/wp-admin/", cookie: "_ga=1; wordpress_logged_in_abc=a%7C1" })).toBe("reaches-origin");
    // The login gate's prefix DOES carry a trailing slash, so bare /wp-admin is not challenged —
    // it is a 301 into /wp-admin/, which is. The geo rule above covers the bare path.
    expect(edgeVerdict({ ...ANON_PAGE, path: "/wp-admin" })).toBe("reaches-origin");
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

  // ── provision-ssh-keys (twin of the app's rules) ──────────────────────────────────
  // The gateway writes each `authorizedKeys` line into an authorized_keys FILE, so the strict
  // single-line OpenSSH grammar (+ the length/array caps) is the guard against a smuggled second
  // authorized_keys line or a private key.
  const SSH_ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample000000000000000000000000000000000 dev@laptop";
  const SSH_RSA = `ssh-rsa ${"A".repeat(372)}== ci@runner`;
  const SSH_ECDSA = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBExample00000000000";
  const SSH_KEYS_PARAMS = { project: "dy-agency-proof", slug: "geelongns", authorizedKeys: [SSH_ED25519] };

  it("provision-ssh-keys: accepts ed25519 / rsa / ecdsa keys, an EMPTY set (revoke-all), and returns only known keys", () => {
    expect(validateProvisionSshKeysParams({ ...SSH_KEYS_PARAMS, extra: "x" })).toEqual({ ok: true, params: SSH_KEYS_PARAMS });
    expect(validateProvisionSshKeysParams({ project: "dy-agency-proof", slug: "geelongns", authorizedKeys: [SSH_RSA] }).ok).toBe(true);
    expect(validateProvisionSshKeysParams({ project: "dy-agency-proof", slug: "geelongns", authorizedKeys: [SSH_ECDSA] }).ok).toBe(true);
    // A key WITHOUT a comment is valid (the comment is optional).
    expect(
      validateProvisionSshKeysParams({ project: "dy-agency-proof", slug: "geelongns", authorizedKeys: [SSH_ED25519.split(" ").slice(0, 2).join(" ")] }).ok,
    ).toBe(true);
    // The FULL desired set can be empty — that revokes every key on the gateway.
    expect(validateProvisionSshKeysParams({ project: "dy-agency-proof", slug: "geelongns", authorizedKeys: [] })).toEqual({
      ok: true,
      params: { project: "dy-agency-proof", slug: "geelongns", authorizedKeys: [] },
    });
    // Multiple keys are rebuilt into a fresh array of exactly the validated lines.
    expect(
      validateProvisionSshKeysParams({ project: "dy-agency-proof", slug: "geelongns", authorizedKeys: [SSH_ED25519, SSH_RSA] }),
    ).toEqual({ ok: true, params: { project: "dy-agency-proof", slug: "geelongns", authorizedKeys: [SSH_ED25519, SSH_RSA] } });
  });

  it("provision-ssh-keys: rejects a bad project / slug field by field", () => {
    const bad = (overrides: Record<string, unknown>) => validateProvisionSshKeysParams({ ...SSH_KEYS_PARAMS, ...overrides });
    expect(validateProvisionSshKeysParams(null).ok).toBe(false);
    expect(validateProvisionSshKeysParams("string").ok).toBe(false);
    expect(validateProvisionSshKeysParams([]).ok).toBe(false);
    // project (GCP project grammar)
    expect(bad({ project: "" }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false); // uppercase
    expect(bad({ project: "ab" }).ok).toBe(false); // too short
    expect(bad({ project: 42 }).ok).toBe(false);
    // slug (storage-tier grammar, <=27)
    expect(bad({ slug: "" }).ok).toBe(false);
    expect(bad({ slug: "Geelongns" }).ok).toBe(false); // uppercase
    expect(bad({ slug: "a".repeat(28) }).ok).toBe(false); // too long for site_<slug>
    expect(bad({ slug: "bad_slug" }).ok).toBe(false); // underscore not in [a-z0-9-]
    expect(bad({ slug: 7 }).ok).toBe(false);
  });

  it("provision-ssh-keys: rejects a private key, a multi-line value, garbage, an over-cap key, and an over-long list", () => {
    const bad = (authorizedKeys: unknown) => validateProvisionSshKeysParams({ project: "dy-agency-proof", slug: "geelongns", authorizedKeys });
    // A PEM PRIVATE key has no key-type token -> rejected.
    expect(bad(["-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"]).ok).toBe(false);
    // A multi-line value could smuggle a second authorized_keys line -> rejected (anchored regex).
    expect(bad([`${SSH_ED25519}\nssh-ed25519 AAAAsecond key`]).ok).toBe(false);
    expect(bad([`${SSH_ED25519}\r\nevil`]).ok).toBe(false);
    // Garbage / wrong type / empty entry / non-string.
    expect(bad(["not a key"]).ok).toBe(false);
    expect(bad(["ssh-dss AAAAB3Nza..."]).ok).toBe(false); // dss is not on the type allowlist
    expect(bad([""]).ok).toBe(false);
    expect(bad([42]).ok).toBe(false);
    // authorizedKeys must be an ARRAY.
    expect(bad(SSH_ED25519).ok).toBe(false);
    expect(bad(undefined).ok).toBe(false);
    // Over the per-key length cap (8192).
    expect(bad([`ssh-rsa ${"A".repeat(9000)}`]).ok).toBe(false);
    // Over the array cap (50).
    expect(bad(Array.from({ length: 51 }, () => SSH_ED25519)).ok).toBe(false);
  });

  // ── gcp-instance-create (twin of the app's rules) ─────────────────────────────────
  // The four fields are the ONLY job-derived data that reaches Google (two as URL path segments,
  // all four in the JSON body), so these grammars ARE the injection guard.

  it("gcp-instance-create: accepts valid params and returns ONLY the four known keys", () => {
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, extra: "x" })).toEqual({
      ok: true,
      params: GCP_INSTANCE_PARAMS,
    });
    // Other real zones / machine types.
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, zone: "us-central1-f" }).ok).toBe(true);
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, zone: "europe-west4-b" }).ok).toBe(true);
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, machineType: "n2-standard-4" }).ok).toBe(true);
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, machineType: "e2-custom-2-4096" }).ok).toBe(true);
    // Grammar edges: a 6-char + a 30-char project, a 1-char + a 63-char name.
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, project: "abcde1" }).ok).toBe(true);
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, project: `a${"b".repeat(28)}1` }).ok).toBe(true);
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, name: "a" }).ok).toBe(true);
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, name: `a${"b".repeat(61)}1` }).ok).toBe(true);
  });

  it("gcp-instance-create: rejects bad input field by field (URL/JSON metacharacters, case, length, shape)", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, ...overrides });

    expect(validateGcpInstanceCreateParams(null).ok).toBe(false);
    expect(validateGcpInstanceCreateParams("string").ok).toBe(false);
    expect(validateGcpInstanceCreateParams([]).ok).toBe(false);
    // project
    expect(bad({ project: undefined }).ok).toBe(false); // missing
    expect(bad({ project: 42 }).ok).toBe(false); // non-string
    expect(bad({ project: "" }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false); // uppercase
    expect(bad({ project: "abcde" }).ok).toBe(false); // too short (5)
    expect(bad({ project: `a${"b".repeat(29)}1` }).ok).toBe(false); // too long (31)
    expect(bad({ project: "1dy-agency" }).ok).toBe(false); // digit first
    expect(bad({ project: "dy-agency-" }).ok).toBe(false); // hyphen last
    expect(bad({ project: "dy-agency/x" }).ok).toBe(false); // path separator
    expect(bad({ project: "dy-agency.x" }).ok).toBe(false); // dot
    expect(bad({ project: "dy-agency%2f" }).ok).toBe(false); // percent-encoding
    expect(bad({ project: "../dy-agency" }).ok).toBe(false); // traversal
    // zone
    expect(bad({ zone: undefined }).ok).toBe(false); // missing
    expect(bad({ zone: "Australia-Southeast1-a" }).ok).toBe(false); // uppercase
    expect(bad({ zone: "australia-southeast1" }).ok).toBe(false); // a region, not a zone
    expect(bad({ zone: "australia-southeast1-ab" }).ok).toBe(false); // two-letter suffix
    expect(bad({ zone: "australia-southeast1-a/../.." }).ok).toBe(false); // traversal
    expect(bad({ zone: "australia southeast1-a" }).ok).toBe(false); // space
    expect(bad({ zone: "australia-southeast1-a?x=1" }).ok).toBe(false); // URL metachar
    expect(bad({ zone: `${"a".repeat(60)}-b1-c` }).ok).toBe(false); // over the length cap
    // name
    expect(bad({ name: undefined }).ok).toBe(false); // missing
    expect(bad({ name: "" }).ok).toBe(false);
    expect(bad({ name: "Bad-Name" }).ok).toBe(false); // uppercase
    expect(bad({ name: "1vm" }).ok).toBe(false); // digit first
    expect(bad({ name: "-lead" }).ok).toBe(false); // hyphen first
    expect(bad({ name: "trail-" }).ok).toBe(false); // hyphen last
    expect(bad({ name: `a${"b".repeat(63)}` }).ok).toBe(false); // 64 chars
    expect(bad({ name: "a.b" }).ok).toBe(false); // dot
    expect(bad({ name: "a/b" }).ok).toBe(false); // path separator
    expect(bad({ name: "a b" }).ok).toBe(false); // space
    // machineType
    expect(bad({ machineType: undefined }).ok).toBe(false); // missing
    expect(bad({ machineType: "e2small" }).ok).toBe(false); // no hyphen
    expect(bad({ machineType: "E2-small" }).ok).toBe(false); // uppercase
    expect(bad({ machineType: "e2-small/x" }).ok).toBe(false); // path separator
    expect(bad({ machineType: "e2-small?x" }).ok).toBe(false); // URL metachar
    expect(bad({ machineType: "e2-small x" }).ok).toBe(false); // space
    expect(bad({ machineType: `e2-${"a".repeat(64)}` }).ok).toBe(false); // over the length cap
  });

  it("gcp-instance-create: a verdict names the offending field", () => {
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ zone: "nope" }, /^zone must be/],
      [{ name: "Bad" }, /^name must be/],
      [{ machineType: "nope" }, /^machineType must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, ...overrides });
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  it("gcp-instance-create: accepts an OPTIONAL dataDiskGb at the range edges and carries it as a fifth key", () => {
    // Absent => still ONLY the four keys (backward-compatible; the acceptance test above proves this too).
    expect(validateGcpInstanceCreateParams(GCP_INSTANCE_PARAMS)).toEqual({ ok: true, params: GCP_INSTANCE_PARAMS });
    // Present at the floor (10), the ceiling (65536), and a mid value => the fifth key rides through.
    for (const size of [10, 200, 65536]) {
      expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, dataDiskGb: size })).toEqual({
        ok: true,
        params: { ...GCP_INSTANCE_PARAMS, dataDiskGb: size },
      });
    }
    // An explicit `undefined` is the same as absent — accepted, and the key is NOT added.
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, dataDiskGb: undefined })).toEqual({
      ok: true,
      params: GCP_INSTANCE_PARAMS,
    });
  });

  it("gcp-instance-create: rejects an out-of-range or non-integer dataDiskGb, and names the field", () => {
    const bad = (dataDiskGb: unknown) => validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, dataDiskGb });
    expect(bad(9).ok).toBe(false); // below the floor
    expect(bad(65537).ok).toBe(false); // above the ceiling
    expect(bad(0).ok).toBe(false);
    expect(bad(-10).ok).toBe(false);
    expect(bad(10.5).ok).toBe(false); // not an integer
    expect(bad(Number.NaN).ok).toBe(false);
    expect(bad(Number.POSITIVE_INFINITY).ok).toBe(false);
    expect(bad("20").ok).toBe(false); // a string, not a number
    expect(bad(null).ok).toBe(false); // null is not "absent"
    expect(bad({}).ok).toBe(false);
    const verdict = bad(9);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/^dataDiskGb/);
  });

  // ── gcp-instance-create: the OPTIONAL networking fields (planning/34 phase 2) ────────
  // network / subnetwork / tags / externalIp / startupScript. Each is checked only when present and
  // rides in the fresh params object ONLY when present, so an absent field keeps the signed params
  // (and the instance body) identical to the four-field form.

  const GCP_INSTANCE_NETWORKING = {
    network: "dy-cell-australia-southeast1",
    subnetwork: "dy-cell-australia-southeast1-subnet",
    tags: ["dy-gateway", "dy-cell-node"],
    externalIp: "35.244.66.16",
    startupScript: "#!/bin/sh\necho 'hello; $(whoami)' > \"/tmp/x y\"\n",
  };

  it("gcp-instance-create: accepts the OPTIONAL networking fields and carries each ONLY when present", () => {
    const full = { ...GCP_INSTANCE_PARAMS, dataDiskGb: 200, ...GCP_INSTANCE_NETWORKING };
    expect(validateGcpInstanceCreateParams({ ...full, extra: "x" })).toEqual({ ok: true, params: full });
    // Each field alone rides as the ONLY extra key.
    for (const [field, value] of Object.entries(GCP_INSTANCE_NETWORKING)) {
      expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, [field]: value })).toEqual({
        ok: true,
        params: { ...GCP_INSTANCE_PARAMS, [field]: value },
      });
    }
    // An explicit `undefined` is the same as absent — none of the keys is added.
    expect(
      validateGcpInstanceCreateParams({
        ...GCP_INSTANCE_PARAMS,
        network: undefined,
        subnetwork: undefined,
        tags: undefined,
        externalIp: undefined,
        startupScript: undefined,
      }),
    ).toEqual({ ok: true, params: GCP_INSTANCE_PARAMS });
    // The edges: 64 tags (Google's cap), a 256 KB startup script, and the tags array is a FRESH copy.
    const maxTags = Array.from({ length: 64 }, (_, i) => `tag-${i}`);
    const tagsVerdict = validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, tags: maxTags });
    expect(tagsVerdict.ok).toBe(true);
    if (tagsVerdict.ok) {
      expect(tagsVerdict.params.tags).toEqual(maxTags);
      expect(tagsVerdict.params.tags).not.toBe(maxTags);
    }
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, startupScript: "x".repeat(256 * 1024) }).ok).toBe(true);
    // A startup script is OPAQUE: shell metacharacters, quotes, newlines, unicode all pass.
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, startupScript: "rm -rf / ; `id` $(x) \"q\" 'q' \\ é\n" }).ok).toBe(true);
  });

  it("gcp-instance-create: rejects a bad optional networking field (a URL or another project's network is NOT a name), and names it", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, ...overrides });

    // network / subnetwork — bare resource names ONLY: never a URL, a path, or another project.
    for (const field of ["network", "subnetwork"]) {
      expect(bad({ [field]: "" }).ok).toBe(false);
      expect(bad({ [field]: 42 }).ok).toBe(false);
      expect(bad({ [field]: null }).ok).toBe(false); // null is not "absent"
      expect(bad({ [field]: "Bad-Net" }).ok).toBe(false); // uppercase
      expect(bad({ [field]: "1net" }).ok).toBe(false); // digit first
      expect(bad({ [field]: "net-" }).ok).toBe(false); // hyphen last
      expect(bad({ [field]: "global/networks/default" }).ok).toBe(false); // a relative URL
      expect(bad({ [field]: "projects/victim/global/networks/vpc" }).ok).toBe(false); // another project
      expect(bad({ [field]: "https://www.googleapis.com/compute/v1/projects/victim/global/networks/vpc" }).ok).toBe(false);
      expect(bad({ [field]: "../default" }).ok).toBe(false); // traversal
      expect(bad({ [field]: "a.b" }).ok).toBe(false); // dot
      expect(bad({ [field]: `a${"b".repeat(63)}` }).ok).toBe(false); // 64 chars
      const verdict = bad({ [field]: "Bad" });
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(new RegExp(`^${field}, when present, must be a Compute Engine resource name`));
    }
    // tags — 1-64 resource names
    expect(bad({ tags: [] }).ok).toBe(false); // present but empty
    expect(bad({ tags: "dy-gateway" }).ok).toBe(false); // not an array
    expect(bad({ tags: null }).ok).toBe(false);
    expect(bad({ tags: ["Dy-Gateway"] }).ok).toBe(false); // uppercase
    expect(bad({ tags: ["dy gateway"] }).ok).toBe(false); // space
    expect(bad({ tags: ["dy/gateway"] }).ok).toBe(false); // path separator
    expect(bad({ tags: [42] }).ok).toBe(false); // non-string entry
    expect(bad({ tags: ["ok", ""] }).ok).toBe(false); // empty entry
    expect(bad({ tags: Array.from({ length: 65 }, (_, i) => `tag-${i}`) }).ok).toBe(false); // over Google's cap
    // externalIp — a plain IPv4 address, nothing else
    expect(bad({ externalIp: "" }).ok).toBe(false);
    expect(bad({ externalIp: 35 }).ok).toBe(false);
    expect(bad({ externalIp: null }).ok).toBe(false);
    expect(bad({ externalIp: "35.244.66" }).ok).toBe(false); // three octets
    expect(bad({ externalIp: "35.244.66.256" }).ok).toBe(false); // octet > 255
    expect(bad({ externalIp: "35.244.066.16" }).ok).toBe(false); // leading zero
    expect(bad({ externalIp: "35.244.66.16/32" }).ok).toBe(false); // a CIDR, not an address
    expect(bad({ externalIp: "2001:db8::1" }).ok).toBe(false); // IPv6
    expect(bad({ externalIp: "dy-cell-gateway-ip" }).ok).toBe(false); // a NAME, not an address
    expect(bad({ externalIp: " 35.244.66.16" }).ok).toBe(false); // whitespace
    // startupScript — opaque but bounded: non-empty, at most 256 KB
    expect(bad({ startupScript: "" }).ok).toBe(false);
    expect(bad({ startupScript: 42 }).ok).toBe(false);
    expect(bad({ startupScript: null }).ok).toBe(false);
    expect(bad({ startupScript: "x".repeat(256 * 1024 + 1) }).ok).toBe(false);
    // Google's cap is BYTES: 100,000 box-drawing characters (3 bytes each) are well UNDER the cap in
    // characters but 300,000 bytes, so only a byte-counting guard rejects this.
    const multiByteVerdict = bad({ startupScript: "\u2500".repeat(100_000) });
    expect(multiByteVerdict.ok).toBe(false);
    if (!multiByteVerdict.ok) expect(multiByteVerdict.reason).toMatch(/at most 262144 bytes$/);
    // 87,381 x 3 bytes = 262,143: under the cap in bytes, so accepted.
    expect(validateGcpInstanceCreateParams({ ...GCP_INSTANCE_PARAMS, startupScript: "\u2500".repeat(87_381) }).ok).toBe(true);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ tags: [] }, /^tags, when present/],
      [{ externalIp: "nope" }, /^externalIp, when present/],
      [{ startupScript: "" }, /^startupScript, when present/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  // ── gcp-network-create (twin of the app's rules) ──────────────────────────────────
  // Every value is a URL path segment or a JSON body field of a Compute call, so these grammars ARE
  // the injection guard (as for gcp-instance-create).

  it("gcp-network-create: accepts valid params and returns ONLY the five known keys", () => {
    expect(validateGcpNetworkCreateParams({ ...GCP_NETWORK_PARAMS, extra: "x" })).toEqual({ ok: true, params: GCP_NETWORK_PARAMS });
    // Other real regions.
    expect(validateGcpNetworkCreateParams({ ...GCP_NETWORK_PARAMS, region: "us-central1" }).ok).toBe(true);
    expect(validateGcpNetworkCreateParams({ ...GCP_NETWORK_PARAMS, region: "europe-west4" }).ok).toBe(true);
    // Every RFC 1918 block at its range edges (/8-/29, /12-/29, /16-/29).
    for (const ipCidr of [
      "10.0.0.0/8",
      "10.20.0.0/24",
      "10.255.255.248/29",
      "172.16.0.0/12",
      "172.31.0.0/16",
      "172.20.1.0/29",
      "192.168.0.0/16",
      "192.168.1.0/24",
      "192.168.1.8/29",
    ]) {
      expect(validateGcpNetworkCreateParams({ ...GCP_NETWORK_PARAMS, ipCidr }).ok).toBe(true);
    }
  });

  it("gcp-network-create: rejects bad input field by field (a zone is not a region; a public or too-small block is not a subnet)", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpNetworkCreateParams({ ...GCP_NETWORK_PARAMS, ...overrides });

    expect(validateGcpNetworkCreateParams(null).ok).toBe(false);
    expect(validateGcpNetworkCreateParams("string").ok).toBe(false);
    expect(validateGcpNetworkCreateParams([]).ok).toBe(false);
    // project
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false); // uppercase
    expect(bad({ project: "dy-agency/x" }).ok).toBe(false); // path separator
    expect(bad({ project: "../dy-agency" }).ok).toBe(false); // traversal
    // region
    expect(bad({ region: undefined }).ok).toBe(false);
    expect(bad({ region: "australia-southeast1-a" }).ok).toBe(false); // a ZONE, not a region
    expect(bad({ region: "Australia-Southeast1" }).ok).toBe(false); // uppercase
    expect(bad({ region: "australia" }).ok).toBe(false); // no area
    expect(bad({ region: "australia-southeast1/../.." }).ok).toBe(false); // traversal
    expect(bad({ region: "australia southeast1" }).ok).toBe(false); // space
    expect(bad({ region: "australia-southeast1?x=1" }).ok).toBe(false); // URL metachar
    expect(bad({ region: `${"a".repeat(62)}-b1` }).ok).toBe(false); // over the length cap (65 chars)
    // networkName / subnetName (resource-name grammar)
    for (const field of ["networkName", "subnetName"]) {
      expect(bad({ [field]: undefined }).ok).toBe(false);
      expect(bad({ [field]: "" }).ok).toBe(false);
      expect(bad({ [field]: "Bad-Name" }).ok).toBe(false); // uppercase
      expect(bad({ [field]: "1net" }).ok).toBe(false); // digit first
      expect(bad({ [field]: "net-" }).ok).toBe(false); // hyphen last
      expect(bad({ [field]: "a/b" }).ok).toBe(false); // path separator
      expect(bad({ [field]: "a.b" }).ok).toBe(false); // dot
      expect(bad({ [field]: "a b" }).ok).toBe(false); // space
      expect(bad({ [field]: `a${"b".repeat(63)}` }).ok).toBe(false); // 64 chars
    }
    // ipCidr — a PRIVATE block between /8 and /29
    expect(bad({ ipCidr: undefined }).ok).toBe(false);
    expect(bad({ ipCidr: 42 }).ok).toBe(false);
    expect(bad({ ipCidr: "10.20.0.0" }).ok).toBe(false); // no prefix
    expect(bad({ ipCidr: "10.20.0.0/30" }).ok).toBe(false); // smaller than GCP's /29 floor
    expect(bad({ ipCidr: "10.20.0.0/32" }).ok).toBe(false);
    expect(bad({ ipCidr: "10.20.0.0/7" }).ok).toBe(false); // wider than 10/8
    expect(bad({ ipCidr: "10.256.0.0/24" }).ok).toBe(false); // octet > 255
    expect(bad({ ipCidr: "10.020.0.0/24" }).ok).toBe(false); // leading zero
    expect(bad({ ipCidr: "8.8.8.0/24" }).ok).toBe(false); // public
    expect(bad({ ipCidr: "0.0.0.0/0" }).ok).toBe(false); // everything
    expect(bad({ ipCidr: "172.15.0.0/16" }).ok).toBe(false); // just outside 172.16/12
    expect(bad({ ipCidr: "172.32.0.0/16" }).ok).toBe(false);
    expect(bad({ ipCidr: "172.16.0.0/11" }).ok).toBe(false); // wider than 172.16/12
    expect(bad({ ipCidr: "192.168.0.0/15" }).ok).toBe(false); // wider than 192.168/16
    expect(bad({ ipCidr: "192.169.0.0/16" }).ok).toBe(false);
    expect(bad({ ipCidr: "10.20.0.0/24 " }).ok).toBe(false); // whitespace
    expect(bad({ ipCidr: "10.20.0.0/24/x" }).ok).toBe(false); // path junk
    expect(bad({ ipCidr: "fd00::/8" }).ok).toBe(false); // IPv6
  });

  it("gcp-network-create: a verdict names the offending field", () => {
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ region: "australia-southeast1-a" }, /^region must be/],
      [{ networkName: "Bad" }, /^networkName must be/],
      [{ subnetName: "Bad" }, /^subnetName must be/],
      [{ ipCidr: "8.8.8.0/24" }, /^ipCidr must be a private/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = validateGcpNetworkCreateParams({ ...GCP_NETWORK_PARAMS, ...overrides });
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  // ── gcp-firewall-create (twin of the app's rules) ─────────────────────────────────

  it("gcp-firewall-create exposes exactly the four protocols", () => {
    expect([...GCP_FIREWALL_PROTOCOLS]).toEqual(["tcp", "udp", "icmp", "all"]);
  });

  it("gcp-firewall-create: accepts valid params, rebuilds every list fresh, and returns ONLY known keys", () => {
    // An extra key at the top level AND inside an allowed entry is dropped.
    expect(
      validateGcpFirewallCreateParams({
        ...GCP_FIREWALL_PARAMS,
        extra: "x",
        allowed: [{ protocol: "tcp", ports: ["22"], extra: "y" }],
      }),
    ).toEqual({ ok: true, params: GCP_FIREWALL_PARAMS });
    // The internal allow-all rule: every protocol, no ports, the subnet as source, a node tag.
    const internal = {
      project: "dy-agency-proof",
      networkName: "dy-cell-australia-southeast1",
      ruleName: "dy-cell-allow-internal",
      allowed: [{ protocol: "all" }],
      sourceRanges: ["10.20.0.0/24"],
      targetTags: ["dy-cell-node"],
    };
    expect(validateGcpFirewallCreateParams(internal)).toEqual({ ok: true, params: internal });
    // Ports at the edges (0, 65535, a full range), udp, icmp without ports, several sources + tags.
    const rich = {
      ...GCP_FIREWALL_PARAMS,
      allowed: [
        { protocol: "tcp", ports: ["0", "22", "8000-8080", "65535", "0-65535"] },
        { protocol: "udp", ports: ["53"] },
        { protocol: "icmp" },
      ],
      sourceRanges: ["0.0.0.0/0", "10.20.0.0/24", "203.0.113.7/32"],
      targetTags: ["dy-gateway", "dy-web"],
    };
    expect(validateGcpFirewallCreateParams(rich)).toEqual({ ok: true, params: rich });
    // The returned lists are FRESH copies, never the caller's arrays/objects.
    const verdict = validateGcpFirewallCreateParams(GCP_FIREWALL_PARAMS);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.params.allowed).not.toBe(GCP_FIREWALL_PARAMS.allowed);
      expect(verdict.params.allowed[0]).not.toBe(GCP_FIREWALL_PARAMS.allowed[0]);
      expect(verdict.params.allowed[0].ports).not.toBe(GCP_FIREWALL_PARAMS.allowed[0].ports);
      expect(verdict.params.sourceRanges).not.toBe(GCP_FIREWALL_PARAMS.sourceRanges);
      expect(verdict.params.targetTags).not.toBe(GCP_FIREWALL_PARAMS.targetTags);
    }
  });

  it("gcp-firewall-create: rejects bad input field by field (protocol allowlist, ports on icmp/all, port grammar, CIDR grammar, EMPTY targetTags)", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpFirewallCreateParams({ ...GCP_FIREWALL_PARAMS, ...overrides });

    expect(validateGcpFirewallCreateParams(null).ok).toBe(false);
    expect(validateGcpFirewallCreateParams([]).ok).toBe(false);
    // project / networkName / ruleName
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Bad" }).ok).toBe(false);
    expect(bad({ networkName: undefined }).ok).toBe(false);
    expect(bad({ networkName: "Bad-Net" }).ok).toBe(false);
    expect(bad({ networkName: "global/networks/default" }).ok).toBe(false); // a URL, not a name
    expect(bad({ ruleName: undefined }).ok).toBe(false);
    expect(bad({ ruleName: "rule.name" }).ok).toBe(false);
    expect(bad({ ruleName: "rule/name" }).ok).toBe(false);
    // allowed — list shape
    expect(bad({ allowed: undefined }).ok).toBe(false);
    expect(bad({ allowed: [] }).ok).toBe(false); // empty
    expect(bad({ allowed: "tcp" }).ok).toBe(false); // not an array
    expect(bad({ allowed: Array.from({ length: 33 }, () => ({ protocol: "tcp" })) }).ok).toBe(false); // oversized
    expect(bad({ allowed: ["tcp"] }).ok).toBe(false); // entry not an object
    expect(bad({ allowed: [null] }).ok).toBe(false);
    expect(bad({ allowed: [["tcp"]] }).ok).toBe(false);
    // allowed — protocol
    expect(bad({ allowed: [{ ports: ["22"] }] }).ok).toBe(false); // missing
    expect(bad({ allowed: [{ protocol: "TCP" }] }).ok).toBe(false); // case-sensitive
    expect(bad({ allowed: [{ protocol: "sctp" }] }).ok).toBe(false); // outside the allowlist
    expect(bad({ allowed: [{ protocol: "6" }] }).ok).toBe(false); // a protocol NUMBER
    expect(bad({ allowed: [{ protocol: 6 }] }).ok).toBe(false);
    // allowed — ports
    expect(bad({ allowed: [{ protocol: "icmp", ports: ["22"] }] }).ok).toBe(false); // ports on icmp
    expect(bad({ allowed: [{ protocol: "all", ports: ["22"] }] }).ok).toBe(false); // ports on all
    expect(bad({ allowed: [{ protocol: "tcp", ports: [] }] }).ok).toBe(false); // present but empty
    expect(bad({ allowed: [{ protocol: "tcp", ports: "22" }] }).ok).toBe(false); // not an array
    expect(bad({ allowed: [{ protocol: "tcp", ports: [22] }] }).ok).toBe(false); // a number, not a string
    expect(bad({ allowed: [{ protocol: "tcp", ports: ["65536"] }] }).ok).toBe(false); // over the port max
    expect(bad({ allowed: [{ protocol: "tcp", ports: ["22-65536"] }] }).ok).toBe(false);
    expect(bad({ allowed: [{ protocol: "tcp", ports: ["022"] }] }).ok).toBe(false); // leading zero
    expect(bad({ allowed: [{ protocol: "tcp", ports: ["8080-8000"] }] }).ok).toBe(false); // inverted range
    expect(bad({ allowed: [{ protocol: "tcp", ports: ["22-"] }] }).ok).toBe(false);
    expect(bad({ allowed: [{ protocol: "tcp", ports: ["-22"] }] }).ok).toBe(false);
    expect(bad({ allowed: [{ protocol: "tcp", ports: ["22,80"] }] }).ok).toBe(false);
    expect(bad({ allowed: [{ protocol: "tcp", ports: ["ssh"] }] }).ok).toBe(false);
    expect(bad({ allowed: [{ protocol: "tcp", ports: [" 22"] }] }).ok).toBe(false);
    expect(bad({ allowed: [{ protocol: "tcp", ports: [""] }] }).ok).toBe(false);
    expect(bad({ allowed: [{ protocol: "tcp", ports: Array.from({ length: 257 }, (_, i) => String(i)) }] }).ok).toBe(false); // oversized
    // sourceRanges — IPv4 CIDR blocks
    expect(bad({ sourceRanges: undefined }).ok).toBe(false);
    expect(bad({ sourceRanges: [] }).ok).toBe(false);
    expect(bad({ sourceRanges: "0.0.0.0/0" }).ok).toBe(false); // not an array
    expect(bad({ sourceRanges: ["0.0.0.0"] }).ok).toBe(false); // no prefix
    expect(bad({ sourceRanges: ["0.0.0.0/33"] }).ok).toBe(false);
    expect(bad({ sourceRanges: ["256.0.0.0/8"] }).ok).toBe(false);
    expect(bad({ sourceRanges: ["10.020.0.0/24"] }).ok).toBe(false); // leading zero
    expect(bad({ sourceRanges: ["::/0"] }).ok).toBe(false); // IPv6
    expect(bad({ sourceRanges: ["any"] }).ok).toBe(false);
    expect(bad({ sourceRanges: [42] }).ok).toBe(false);
    expect(bad({ sourceRanges: ["0.0.0.0/0", ""] }).ok).toBe(false);
    expect(bad({ sourceRanges: Array.from({ length: 257 }, () => "0.0.0.0/0") }).ok).toBe(false);
    // targetTags — REQUIRED non-empty: a rule always names its target scope
    expect(bad({ targetTags: undefined }).ok).toBe(false);
    expect(bad({ targetTags: [] }).ok).toBe(false);
    expect(bad({ targetTags: "dy-gateway" }).ok).toBe(false);
    expect(bad({ targetTags: ["Dy-Gateway"] }).ok).toBe(false);
    expect(bad({ targetTags: ["dy gateway"] }).ok).toBe(false);
    expect(bad({ targetTags: ["dy/gateway"] }).ok).toBe(false);
    expect(bad({ targetTags: [42] }).ok).toBe(false);
    expect(bad({ targetTags: Array.from({ length: 257 }, () => "t") }).ok).toBe(false);
  });

  it("gcp-firewall-create: a verdict names the offending field", () => {
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ networkName: "Bad" }, /^networkName must be/],
      [{ ruleName: "Bad" }, /^ruleName must be/],
      [{ allowed: [] }, /^allowed must be an array/],
      [{ allowed: [{ protocol: "sctp" }] }, /protocol must be one of tcp, udp, icmp, all/],
      [{ allowed: [{ protocol: "icmp", ports: ["22"] }] }, /ports apply to tcp\/udp only/],
      [{ allowed: [{ protocol: "tcp", ports: ["x"] }] }, /^each allowed port must be/],
      [{ sourceRanges: ["nope"] }, /^each sourceRanges entry must be an IPv4 CIDR/],
      [{ targetTags: [] }, /^targetTags must be an array of 1-256/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = validateGcpFirewallCreateParams({ ...GCP_FIREWALL_PARAMS, ...overrides });
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  // ── gcp-address-create (twin of the app's rules) ──────────────────────────────────

  it("gcp-address-create: accepts valid params and returns ONLY the three known keys", () => {
    expect(validateGcpAddressCreateParams({ ...GCP_ADDRESS_PARAMS, extra: "x" })).toEqual({ ok: true, params: GCP_ADDRESS_PARAMS });
    expect(validateGcpAddressCreateParams({ ...GCP_ADDRESS_PARAMS, region: "us-central1" }).ok).toBe(true);
    expect(validateGcpAddressCreateParams({ ...GCP_ADDRESS_PARAMS, addressName: "a" }).ok).toBe(true);
    expect(validateGcpAddressCreateParams({ ...GCP_ADDRESS_PARAMS, addressName: `a${"b".repeat(61)}1` }).ok).toBe(true);
  });

  it("gcp-address-create: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpAddressCreateParams({ ...GCP_ADDRESS_PARAMS, ...overrides });

    expect(validateGcpAddressCreateParams(null).ok).toBe(false);
    expect(validateGcpAddressCreateParams([]).ok).toBe(false);
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    expect(bad({ region: undefined }).ok).toBe(false);
    expect(bad({ region: "australia-southeast1-a" }).ok).toBe(false); // a zone
    expect(bad({ region: "australia-southeast1/../.." }).ok).toBe(false); // traversal
    expect(bad({ addressName: undefined }).ok).toBe(false);
    expect(bad({ addressName: "" }).ok).toBe(false);
    expect(bad({ addressName: "Bad-Name" }).ok).toBe(false);
    expect(bad({ addressName: "1ip" }).ok).toBe(false);
    expect(bad({ addressName: "a/b" }).ok).toBe(false);
    expect(bad({ addressName: "35.244.66.16" }).ok).toBe(false); // an ADDRESS, not a name
    expect(bad({ addressName: `a${"b".repeat(63)}` }).ok).toBe(false);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ region: "nope" }, /^region must be/],
      [{ addressName: "Bad" }, /^addressName must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  // ── gcp-router-nat-create (twin of the app's rules) ───────────────────────────────

  it("gcp-router-nat-create: accepts valid params and returns ONLY the five known keys", () => {
    expect(validateGcpRouterNatCreateParams({ ...GCP_ROUTER_NAT_PARAMS, extra: "x" })).toEqual({ ok: true, params: GCP_ROUTER_NAT_PARAMS });
    expect(validateGcpRouterNatCreateParams({ ...GCP_ROUTER_NAT_PARAMS, region: "us-central1" }).ok).toBe(true);
    expect(validateGcpRouterNatCreateParams({ ...GCP_ROUTER_NAT_PARAMS, routerName: "r" }).ok).toBe(true);
    expect(validateGcpRouterNatCreateParams({ ...GCP_ROUTER_NAT_PARAMS, natName: `a${"b".repeat(61)}1` }).ok).toBe(true);
  });

  it("gcp-router-nat-create: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpRouterNatCreateParams({ ...GCP_ROUTER_NAT_PARAMS, ...overrides });

    expect(validateGcpRouterNatCreateParams(null).ok).toBe(false);
    expect(validateGcpRouterNatCreateParams("string").ok).toBe(false);
    expect(validateGcpRouterNatCreateParams([]).ok).toBe(false);
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    expect(bad({ region: undefined }).ok).toBe(false);
    expect(bad({ region: "australia-southeast1-a" }).ok).toBe(false); // a zone
    expect(bad({ region: "australia-southeast1/../.." }).ok).toBe(false); // traversal
    expect(bad({ networkName: undefined }).ok).toBe(false);
    expect(bad({ networkName: "global/networks/dy-cell" }).ok).toBe(false); // a URL, not a name
    expect(bad({ routerName: undefined }).ok).toBe(false);
    expect(bad({ routerName: "" }).ok).toBe(false);
    expect(bad({ routerName: "Bad-Name" }).ok).toBe(false);
    expect(bad({ routerName: "1router" }).ok).toBe(false);
    expect(bad({ routerName: "a/b" }).ok).toBe(false);
    expect(bad({ routerName: `a${"b".repeat(63)}` }).ok).toBe(false);
    expect(bad({ natName: undefined }).ok).toBe(false);
    expect(bad({ natName: "nat_1" }).ok).toBe(false);
    expect(bad({ natName: "nat-" }).ok).toBe(false);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ region: "nope" }, /^region must be/],
      [{ networkName: "Bad" }, /^networkName must be/],
      [{ routerName: "Bad" }, /^routerName must be/],
      [{ natName: "Bad" }, /^natName must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  // ── gcp-firewall-get (twin of the app's rules) ────────────────────────────────────

  it("gcp-firewall-get: accepts valid params and returns ONLY the two known keys (no region — firewalls are global)", () => {
    expect(validateGcpFirewallGetParams({ ...GCP_FIREWALL_GET_PARAMS, extra: "x", region: "australia-southeast1" })).toEqual({
      ok: true,
      params: GCP_FIREWALL_GET_PARAMS,
    });
    expect(validateGcpFirewallGetParams({ ...GCP_FIREWALL_GET_PARAMS, ruleName: "r" }).ok).toBe(true);
  });

  it("gcp-firewall-get: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpFirewallGetParams({ ...GCP_FIREWALL_GET_PARAMS, ...overrides });

    expect(validateGcpFirewallGetParams(null).ok).toBe(false);
    expect(validateGcpFirewallGetParams([]).ok).toBe(false);
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    expect(bad({ ruleName: undefined }).ok).toBe(false);
    expect(bad({ ruleName: "" }).ok).toBe(false);
    expect(bad({ ruleName: "Bad-Name" }).ok).toBe(false);
    expect(bad({ ruleName: "1rule" }).ok).toBe(false);
    expect(bad({ ruleName: "a/b" }).ok).toBe(false);
    expect(bad({ ruleName: `a${"b".repeat(63)}` }).ok).toBe(false);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ ruleName: "Bad" }, /^ruleName must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  // ── gcp-router-get (twin of the app's rules) ──────────────────────────────────────

  it("gcp-router-get: accepts valid params and returns ONLY the three known keys", () => {
    expect(validateGcpRouterGetParams({ ...GCP_ROUTER_GET_PARAMS, extra: "x" })).toEqual({ ok: true, params: GCP_ROUTER_GET_PARAMS });
    expect(validateGcpRouterGetParams({ ...GCP_ROUTER_GET_PARAMS, region: "us-central1" }).ok).toBe(true);
    expect(validateGcpRouterGetParams({ ...GCP_ROUTER_GET_PARAMS, routerName: "r" }).ok).toBe(true);
  });

  it("gcp-router-get: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpRouterGetParams({ ...GCP_ROUTER_GET_PARAMS, ...overrides });

    expect(validateGcpRouterGetParams(null).ok).toBe(false);
    expect(validateGcpRouterGetParams([]).ok).toBe(false);
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    expect(bad({ region: undefined }).ok).toBe(false);
    expect(bad({ region: "australia-southeast1-a" }).ok).toBe(false); // a zone
    expect(bad({ region: "australia-southeast1/../.." }).ok).toBe(false); // traversal
    expect(bad({ routerName: undefined }).ok).toBe(false);
    expect(bad({ routerName: "" }).ok).toBe(false);
    expect(bad({ routerName: "Bad-Name" }).ok).toBe(false);
    expect(bad({ routerName: "a/b" }).ok).toBe(false);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ region: "nope" }, /^region must be/],
      [{ routerName: "Bad" }, /^routerName must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  // ── gcp-instances-list (twin of the app's rules) ──────────────────────────────────

  it("gcp-instances-list: accepts valid params and returns ONLY the two known keys (a trailing-hyphen prefix is allowed)", () => {
    expect(validateGcpInstancesListParams({ ...GCP_INSTANCES_LIST_PARAMS, extra: "x" })).toEqual({ ok: true, params: GCP_INSTANCES_LIST_PARAMS });
    expect(validateGcpInstancesListParams({ project: "dy-agency-proof", namePrefix: "dy-web-australia-southeast1-" }).ok).toBe(true);
    expect(validateGcpInstancesListParams({ project: "dy-agency-proof", namePrefix: "d" }).ok).toBe(true);
  });

  it("gcp-instances-list: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) => validateGcpInstancesListParams({ ...GCP_INSTANCES_LIST_PARAMS, ...overrides });

    expect(validateGcpInstancesListParams(null).ok).toBe(false);
    expect(validateGcpInstancesListParams([]).ok).toBe(false);
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    expect(bad({ namePrefix: undefined }).ok).toBe(false);
    expect(bad({ namePrefix: "" }).ok).toBe(false);
    expect(bad({ namePrefix: "Dy-" }).ok).toBe(false); // uppercase
    expect(bad({ namePrefix: "1dy" }).ok).toBe(false); // must start with a letter
    expect(bad({ namePrefix: "dy/.." }).ok).toBe(false); // path/regex metacharacter
    expect(bad({ namePrefix: `a${"b".repeat(63)}` }).ok).toBe(false); // 64 chars, over the cap

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ namePrefix: "Bad" }, /^namePrefix must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  // ── the five teardown ops (twin of the app's rules) ───────────────────────────────
  // Each delete reuses the SAME grammar as its create twin, because every value is still a URL path
  // segment of a Compute call. So a name the create ops could never have produced can never be named
  // for deletion either, and a verdict always names the offending field.

  it("gcp-instance-delete: accepts valid params and returns ONLY the three known keys", () => {
    expect(validateGcpInstanceDeleteParams({ ...GCP_INSTANCE_DELETE_PARAMS, extra: "x" })).toEqual({
      ok: true,
      params: GCP_INSTANCE_DELETE_PARAMS,
    });
    expect(validateGcpInstanceDeleteParams({ ...GCP_INSTANCE_DELETE_PARAMS, zone: "us-central1-b" }).ok).toBe(true);
  });

  it("gcp-instance-delete: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) =>
      validateGcpInstanceDeleteParams({ ...GCP_INSTANCE_DELETE_PARAMS, ...overrides });

    expect(validateGcpInstanceDeleteParams(null).ok).toBe(false);
    expect(validateGcpInstanceDeleteParams("string").ok).toBe(false);
    expect(validateGcpInstanceDeleteParams([]).ok).toBe(false);
    expect(validateGcpInstanceDeleteParams({}).ok).toBe(false);
    // project
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false); // uppercase
    expect(bad({ project: "../dy-agency" }).ok).toBe(false); // traversal
    expect(bad({ project: 42 }).ok).toBe(false);
    // zone — a REGION is not a zone
    expect(bad({ zone: undefined }).ok).toBe(false);
    expect(bad({ zone: "australia-southeast1" }).ok).toBe(false);
    expect(bad({ zone: "Australia-Southeast1-A" }).ok).toBe(false); // uppercase
    expect(bad({ zone: "australia-southeast1-a/../.." }).ok).toBe(false); // traversal
    expect(bad({ zone: "australia southeast1-a" }).ok).toBe(false); // space
    expect(bad({ zone: `${"a".repeat(62)}-b1-c` }).ok).toBe(false); // over the length cap
    // name
    expect(bad({ name: undefined }).ok).toBe(false);
    expect(bad({ name: "" }).ok).toBe(false);
    expect(bad({ name: "Bad-Name" }).ok).toBe(false); // uppercase
    expect(bad({ name: "1web" }).ok).toBe(false); // digit first
    expect(bad({ name: "web-" }).ok).toBe(false); // hyphen last
    expect(bad({ name: "a/b" }).ok).toBe(false); // path separator
    expect(bad({ name: "dy-web-*" }).ok).toBe(false); // wildcard
    expect(bad({ name: `a${"b".repeat(63)}` }).ok).toBe(false); // 64 chars
    expect(bad({ name: 42 }).ok).toBe(false);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ zone: "australia-southeast1" }, /^zone must be/],
      [{ name: "Bad" }, /^name must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  it("gcp-address-delete: accepts valid params and returns ONLY the three known keys", () => {
    expect(validateGcpAddressDeleteParams({ ...GCP_ADDRESS_DELETE_PARAMS, extra: "x" })).toEqual({
      ok: true,
      params: GCP_ADDRESS_DELETE_PARAMS,
    });
    expect(validateGcpAddressDeleteParams({ ...GCP_ADDRESS_DELETE_PARAMS, region: "europe-west4" }).ok).toBe(true);
  });

  it("gcp-address-delete: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) =>
      validateGcpAddressDeleteParams({ ...GCP_ADDRESS_DELETE_PARAMS, ...overrides });

    expect(validateGcpAddressDeleteParams(null).ok).toBe(false);
    expect(validateGcpAddressDeleteParams([]).ok).toBe(false);
    expect(validateGcpAddressDeleteParams({}).ok).toBe(false);
    // project
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    // region — a ZONE is not a region
    expect(bad({ region: undefined }).ok).toBe(false);
    expect(bad({ region: "australia-southeast1-a" }).ok).toBe(false);
    expect(bad({ region: "australia-southeast1/../.." }).ok).toBe(false);
    expect(bad({ region: `${"a".repeat(62)}-b1` }).ok).toBe(false); // over the length cap
    // addressName
    expect(bad({ addressName: undefined }).ok).toBe(false);
    expect(bad({ addressName: "" }).ok).toBe(false);
    expect(bad({ addressName: "Bad-Name" }).ok).toBe(false);
    expect(bad({ addressName: "ip-" }).ok).toBe(false);
    expect(bad({ addressName: "a/b" }).ok).toBe(false);
    expect(bad({ addressName: 42 }).ok).toBe(false);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ region: "australia-southeast1-a" }, /^region must be/],
      [{ addressName: "Bad" }, /^addressName must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  it("gcp-firewall-delete: accepts valid params and returns ONLY the two known keys (GLOBAL — no region)", () => {
    expect(validateGcpFirewallDeleteParams({ ...GCP_FIREWALL_DELETE_PARAMS, extra: "x", region: "australia-southeast1" })).toEqual({
      ok: true,
      params: GCP_FIREWALL_DELETE_PARAMS,
    });
  });

  it("gcp-firewall-delete: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) =>
      validateGcpFirewallDeleteParams({ ...GCP_FIREWALL_DELETE_PARAMS, ...overrides });

    expect(validateGcpFirewallDeleteParams(null).ok).toBe(false);
    expect(validateGcpFirewallDeleteParams([]).ok).toBe(false);
    expect(validateGcpFirewallDeleteParams({}).ok).toBe(false);
    // project
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    expect(bad({ project: "dy-agency/x" }).ok).toBe(false);
    // ruleName
    expect(bad({ ruleName: undefined }).ok).toBe(false);
    expect(bad({ ruleName: "" }).ok).toBe(false);
    expect(bad({ ruleName: "Bad-Name" }).ok).toBe(false);
    expect(bad({ ruleName: "rule-" }).ok).toBe(false);
    expect(bad({ ruleName: "global/firewalls/rule" }).ok).toBe(false); // a path, not a name
    expect(bad({ ruleName: `a${"b".repeat(63)}` }).ok).toBe(false);
    expect(bad({ ruleName: 42 }).ok).toBe(false);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ ruleName: "Bad" }, /^ruleName must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  it("gcp-router-delete: accepts valid params and returns ONLY the three known keys (the NAT needs no param)", () => {
    expect(validateGcpRouterDeleteParams({ ...GCP_ROUTER_DELETE_PARAMS, extra: "x", natName: "dy-cell-nat" })).toEqual({
      ok: true,
      params: GCP_ROUTER_DELETE_PARAMS,
    });
  });

  it("gcp-router-delete: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) =>
      validateGcpRouterDeleteParams({ ...GCP_ROUTER_DELETE_PARAMS, ...overrides });

    expect(validateGcpRouterDeleteParams(null).ok).toBe(false);
    expect(validateGcpRouterDeleteParams([]).ok).toBe(false);
    expect(validateGcpRouterDeleteParams({}).ok).toBe(false);
    // project
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    // region — a ZONE is not a region
    expect(bad({ region: undefined }).ok).toBe(false);
    expect(bad({ region: "australia-southeast1-a" }).ok).toBe(false);
    expect(bad({ region: "australia-southeast1?x=1" }).ok).toBe(false); // URL metachar
    expect(bad({ region: `${"a".repeat(62)}-b1` }).ok).toBe(false); // over the length cap
    // routerName
    expect(bad({ routerName: undefined }).ok).toBe(false);
    expect(bad({ routerName: "" }).ok).toBe(false);
    expect(bad({ routerName: "Bad-Name" }).ok).toBe(false);
    expect(bad({ routerName: "router-" }).ok).toBe(false);
    expect(bad({ routerName: "a.b" }).ok).toBe(false);
    expect(bad({ routerName: 42 }).ok).toBe(false);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ region: "australia-southeast1-a" }, /^region must be/],
      [{ routerName: "Bad" }, /^routerName must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  it("gcp-network-delete: accepts valid params and returns ONLY the four known keys (no ipCidr — a delete names no range)", () => {
    expect(validateGcpNetworkDeleteParams({ ...GCP_NETWORK_DELETE_PARAMS, extra: "x", ipCidr: "10.20.0.0/24" })).toEqual({
      ok: true,
      params: GCP_NETWORK_DELETE_PARAMS,
    });
    expect(validateGcpNetworkDeleteParams({ ...GCP_NETWORK_DELETE_PARAMS, region: "us-central1" }).ok).toBe(true);
  });

  it("gcp-network-delete: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) =>
      validateGcpNetworkDeleteParams({ ...GCP_NETWORK_DELETE_PARAMS, ...overrides });

    expect(validateGcpNetworkDeleteParams(null).ok).toBe(false);
    expect(validateGcpNetworkDeleteParams([]).ok).toBe(false);
    expect(validateGcpNetworkDeleteParams({}).ok).toBe(false);
    // project
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    // region — a ZONE is not a region
    expect(bad({ region: undefined }).ok).toBe(false);
    expect(bad({ region: "australia-southeast1-a" }).ok).toBe(false);
    expect(bad({ region: `${"a".repeat(62)}-b1` }).ok).toBe(false); // over the length cap
    // networkName / subnetName (resource-name grammar)
    for (const field of ["networkName", "subnetName"]) {
      expect(bad({ [field]: undefined }).ok).toBe(false);
      expect(bad({ [field]: "" }).ok).toBe(false);
      expect(bad({ [field]: "Bad-Name" }).ok).toBe(false); // uppercase
      expect(bad({ [field]: "1net" }).ok).toBe(false); // digit first
      expect(bad({ [field]: "net-" }).ok).toBe(false); // hyphen last
      expect(bad({ [field]: "a/b" }).ok).toBe(false); // path separator
      expect(bad({ [field]: "global/networks/dy-cell" }).ok).toBe(false); // a path, not a name
      expect(bad({ [field]: `a${"b".repeat(63)}` }).ok).toBe(false); // 64 chars
      expect(bad({ [field]: 42 }).ok).toBe(false);
    }

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ region: "australia-southeast1-a" }, /^region must be/],
      [{ networkName: "Bad" }, /^networkName must be/],
      [{ subnetName: "Bad" }, /^subnetName must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  // ── gcp-instance-set-metadata / gcp-instance-restart (planning/47, twins of the app's rules) ──
  // The update ops reuse the instance grammars (project / zone / name are URL path segments). The
  // metadata `items` list is rebuilt FRESH (known keys only), each key pinned to Google's metadata-key
  // grammar and unique, each value non-empty and under the 256 KB cap. Placeholders are NOT checked
  // here — that is the actuator's job (only it holds env) — so a value with `@@` passes validation.

  it("gcp-instance-set-metadata: accepts `startup-script` and returns ONLY the known keys, items rebuilt fresh", () => {
    const withExtras = {
      ...GCP_SET_METADATA_PARAMS,
      extra: "x",
      items: [{ ...GCP_SET_METADATA_PARAMS.items[0], smuggled: "y" }],
    };
    expect(validateGcpInstanceSetMetadataParams(withExtras)).toEqual({
      ok: true,
      params: GCP_SET_METADATA_PARAMS,
    });
    // A value exactly at the 256 KB cap is admitted.
    expect(validateGcpInstanceSetMetadataParams({ ...GCP_SET_METADATA_PARAMS, items: [{ key: "startup-script", value: "a".repeat(256 * 1024) }] }).ok).toBe(true);
    // The allowlist is exactly one key today.
    expect([...GCP_METADATA_KEYS]).toEqual(["startup-script"]);
  });

  it("gcp-instance-set-metadata: the KEY allowlist — `ssh-keys` (and every other grammar-valid key) is refused by NAME; a mixed list is refused WHOLE", () => {
    const bad = (items: unknown) => validateGcpInstanceSetMetadataParams({ ...GCP_SET_METADATA_PARAMS, items });

    // Each of these passes Google's key grammar and would open its own access path — refused.
    for (const key of ["ssh-keys", "enable-oslogin", "serial-port-enable", "shutdown-script", "startup-script-url", "Startup-Script"]) {
      const verdict = bad([{ key, value: "v" }]);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) {
        expect(verdict.reason).toBe(`each items entry's key must be one of the allowlisted metadata keys (startup-script); got "${key}"`);
      }
    }
    // One allowed + one disallowed => the WHOLE request is refused (a verdict is all-or-nothing; the
    // actuator never sees a partial list, so nothing can be partially applied).
    const mixed = bad([GCP_SET_METADATA_PARAMS.items[0], { key: "ssh-keys", value: "jason:ssh-ed25519 AAAA" }]);
    expect(mixed.ok).toBe(false);
    if (!mixed.ok) expect(mixed.reason).toMatch(/got "ssh-keys"/);
    const mixedOtherOrder = bad([{ key: "ssh-keys", value: "jason:ssh-ed25519 AAAA" }, GCP_SET_METADATA_PARAMS.items[0]]);
    expect(mixedOtherOrder.ok).toBe(false);
  });

  it("gcp-instance-set-metadata: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) =>
      validateGcpInstanceSetMetadataParams({ ...GCP_SET_METADATA_PARAMS, ...overrides });
    const badItems = (items: unknown) => bad({ items });

    expect(validateGcpInstanceSetMetadataParams(null).ok).toBe(false);
    expect(validateGcpInstanceSetMetadataParams([]).ok).toBe(false);
    expect(validateGcpInstanceSetMetadataParams({}).ok).toBe(false);
    // project / zone / name — the instance grammars
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    expect(bad({ zone: "australia-southeast1" }).ok).toBe(false); // a region is not a zone
    expect(bad({ zone: "australia-southeast1-a/../.." }).ok).toBe(false);
    expect(bad({ name: "Bad-Name" }).ok).toBe(false);
    expect(bad({ name: "a/b" }).ok).toBe(false);
    // items — shape + count
    expect(badItems(undefined).ok).toBe(false);
    expect(badItems("startup-script=x").ok).toBe(false);
    expect(badItems([]).ok).toBe(false);
    expect(badItems(Array.from({ length: 33 }, () => ({ key: "startup-script", value: "v" }))).ok).toBe(false);
    expect(badItems(["startup-script"]).ok).toBe(false);
    expect(badItems([null]).ok).toBe(false);
    // items — key grammar (checked BEFORE the allowlist, so a junk key is never echoed in a reason)
    expect(badItems([{ key: "", value: "v" }]).ok).toBe(false);
    expect(badItems([{ key: "has space", value: "v" }]).ok).toBe(false);
    expect(badItems([{ key: "a/b", value: "v" }]).ok).toBe(false);
    expect(badItems([{ key: "a.b", value: "v" }]).ok).toBe(false);
    expect(badItems([{ key: "k".repeat(129), value: "v" }]).ok).toBe(false);
    expect(badItems([{ key: 42, value: "v" }]).ok).toBe(false);
    // items — a key named twice is ambiguous
    expect(badItems([{ key: "startup-script", value: "a" }, { key: "startup-script", value: "b" }]).ok).toBe(false);
    // items — value: non-empty string under the cap
    expect(badItems([{ key: "startup-script", value: "" }]).ok).toBe(false);
    expect(badItems([{ key: "startup-script", value: 42 }]).ok).toBe(false);
    expect(badItems([{ key: "startup-script" }]).ok).toBe(false);
    expect(badItems([{ key: "startup-script", value: "a".repeat(256 * 1024 + 1) }]).ok).toBe(false);
    // Bytes, not characters: 100,000 three-byte characters are under the cap in characters only.
    const multiByteItems = badItems([{ key: "startup-script", value: "\u2500".repeat(100_000) }]);
    expect(multiByteItems.ok).toBe(false);
    if (!multiByteItems.ok) expect(multiByteItems.reason).toMatch(/at most 262144 bytes$/);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ zone: "australia-southeast1" }, /^zone must be/],
      [{ name: "Bad" }, /^name must be/],
      [{ items: [] }, /^items must be an array of 1-32/],
      [{ items: [{ key: "bad key", value: "v" }] }, /^each items entry's key must be a Compute Engine metadata key/],
      [{ items: [{ key: "ssh-keys", value: "v" }] }, /^each items entry's key must be one of the allowlisted metadata keys \(startup-script\); got "ssh-keys"$/],
      [{ items: [{ key: "startup-script", value: "a" }, { key: "startup-script", value: "b" }] }, /names the metadata key "startup-script" more than once/],
      [{ items: [{ key: "startup-script", value: "" }] }, /value must be a non-empty string/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });

  it("gcp-instance-restart: accepts valid params and returns ONLY the three known keys", () => {
    expect(validateGcpInstanceRestartParams({ ...GCP_RESTART_PARAMS, extra: "x" })).toEqual({
      ok: true,
      params: GCP_RESTART_PARAMS,
    });
  });

  it("gcp-instance-restart: rejects bad input field by field, and names the field", () => {
    const bad = (overrides: Record<string, unknown>) =>
      validateGcpInstanceRestartParams({ ...GCP_RESTART_PARAMS, ...overrides });

    expect(validateGcpInstanceRestartParams(null).ok).toBe(false);
    expect(validateGcpInstanceRestartParams([]).ok).toBe(false);
    expect(validateGcpInstanceRestartParams({}).ok).toBe(false);
    expect(bad({ project: undefined }).ok).toBe(false);
    expect(bad({ project: "Dy-Agency" }).ok).toBe(false);
    expect(bad({ zone: undefined }).ok).toBe(false);
    expect(bad({ zone: "australia-southeast1" }).ok).toBe(false); // a region is not a zone
    expect(bad({ zone: "australia southeast1-a" }).ok).toBe(false);
    expect(bad({ name: undefined }).ok).toBe(false);
    expect(bad({ name: "" }).ok).toBe(false);
    expect(bad({ name: "Bad-Name" }).ok).toBe(false);
    expect(bad({ name: "dy-file-*" }).ok).toBe(false);
    expect(bad({ name: 42 }).ok).toBe(false);

    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ project: "Bad" }, /^project must be/],
      [{ zone: "australia-southeast1" }, /^zone must be/],
      [{ name: "Bad" }, /^name must be/],
    ];
    for (const [overrides, expected] of cases) {
      const verdict = bad(overrides);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(expected);
    }
  });
});

describe("POST /actuate route", () => {
  let publicKeyPem: string;
  let privateKey: CryptoKey;
  // The agency's GCP service-account key (a real RSA key so the JWT mint runs), used ONLY by
  // the gcp-instance-create tests via envWith({ GCP_SERVICE_ACCOUNT_KEY }).
  let serviceAccountKey: string;
  beforeAll(async () => {
    ({ publicKeyPem, privateKey } = await makeKeypair());
    serviceAccountKey = await makeServiceAccountKey(GCP_INSTANCE_PARAMS.project);
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

  // ── cache-rule-upsert through the registry ────────────────────────────────────────

  // The TWO rules the Worker must build for CACHE_RULE_PARAMS — what every write body is compared to.
  // The op applies the BYPASS rule first, then the CACHE rule (edgeCacheRulesInOrder).
  function expectedRules(enabled = true) {
    const built = buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600, enabled });
    if (!built.ok) throw new Error(built.reason);
    return built.rules;
  }
  function expectedCacheRule(enabled = true) {
    return expectedRules(enabled).cache;
  }
  function expectedBypassRule(enabled = true) {
    return expectedRules(enabled).bypass;
  }
  // The id the mock assigns a newly written rule, by which of our two rules it is.
  function newIdFor(description: unknown) {
    return description === EDGE_CACHE_BYPASS_RULE_DESCRIPTION ? "rule-new-bypass" : "rule-new-cache";
  }

  // A routed CF ruleset API mock: zone lookup, the cache-settings entrypoint GET, and the three
  // writes (create entrypoint / append rule / patch rule). `entrypointRules` = the rules the zone
  // already has; null => 404 (no Cache Rules yet). `denyStatus` makes the entrypoint GET answer
  // 401/403. Every call must carry the DNS token — the op's own credential, never the R2 token.
  function mockCacheRuleApi(entrypointRules: Array<Record<string, unknown>> | null, denyStatus?: number) {
    const calls: Array<{ method: string; path: string; body?: Record<string, unknown> }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      const auth = new Headers(init?.headers).get("authorization");
      expect(auth).toBe("Bearer cf-dns-token-abc");
      const parsed = new URL(url);
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      calls.push({ method, path: parsed.pathname, body });

      if (parsed.pathname === "/client/v4/zones" && method === "GET") {
        expect(parsed.searchParams.get("name")).toBe("example.com");
        return jsonResponse({ success: true, result: [{ id: "zone-1", name: "example.com" }] });
      }
      if (
        parsed.pathname === "/client/v4/zones/zone-1/rulesets/phases/http_request_cache_settings/entrypoint" &&
        method === "GET"
      ) {
        if (denyStatus !== undefined) {
          return jsonResponse({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }, denyStatus);
        }
        if (entrypointRules === null) {
          return jsonResponse({ success: false, errors: [{ code: 10003, message: "could not find entrypoint ruleset" }] }, 404);
        }
        return jsonResponse({ success: true, result: { id: "rs-1", rules: entrypointRules } });
      }
      if (parsed.pathname === "/client/v4/zones/zone-1/rulesets" && method === "POST") {
        const createdRules = (body?.rules as Array<Record<string, unknown>>).map((rule) => ({ ...rule, id: newIdFor(rule.description) }));
        return jsonResponse({ success: true, result: { id: "rs-new", rules: createdRules } });
      }
      // Append to ANY ruleset id (rs-1 = the zone's existing entrypoint, rs-new = one this op just
      // created for the bypass rule). Stateless: the reply is the initial rules + this write.
      const appendMatch = /^\/client\/v4\/zones\/zone-1\/rulesets\/(rs-[a-z0-9-]+)\/rules$/.exec(parsed.pathname);
      if (appendMatch && method === "POST") {
        return jsonResponse({
          success: true,
          result: { id: appendMatch[1], rules: [...(entrypointRules ?? []), { ...body, id: newIdFor(body?.description) }] },
        });
      }
      if (parsed.pathname.startsWith("/client/v4/zones/zone-1/rulesets/rs-1/rules/") && method === "PATCH") {
        return jsonResponse({ success: true, result: { id: "rs-1", rules: entrypointRules } });
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    return calls;
  }

  it("cache-rule-upsert: no Cache Rules yet => creates the entrypoint with the BYPASS rule, then appends the CACHE rule to it (one read, no second create)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockCacheRuleApi(null);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "cache-rule-upsert",
      zone: "example.com",
      action: "created",
      ruleId: "rule-new-cache",
      enabled: true,
      cacheAction: "created",
      bypassRuleId: "rule-new-bypass",
      bypassAction: "created",
      otherCacheRules: [],
    });
    // Exactly ONE entrypoint read, then two writes: create (bypass) + append (cache) to the NEW ruleset.
    const entrypointReads = calls.filter((call) => call.method === "GET" && call.path.endsWith("/entrypoint"));
    expect(entrypointReads).toHaveLength(1);
    const writes = calls.filter((call) => call.method !== "GET");
    expect(writes).toHaveLength(2);
    expect(writes[0]?.path).toBe("/client/v4/zones/zone-1/rulesets");
    expect(writes[0]?.body).toEqual({
      name: "default",
      kind: "zone",
      phase: "http_request_cache_settings",
      rules: [expectedBypassRule()],
    });
    expect(writes[1]?.method).toBe("POST");
    expect(writes[1]?.path).toBe("/client/v4/zones/zone-1/rulesets/rs-new/rules");
    expect(writes[1]?.body).toEqual(expectedCacheRule());
  });

  it("cache-rule-upsert: an existing ruleset without our rule => APPENDS it and never touches the other rules", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob();
    const signature = await signAsApp(job, privateKey);
    const agencyOwnRule = {
      id: "agency-rule-1",
      description: "agency: cache images longer",
      expression: 'http.request.uri.path.extension eq "jpg"',
      action: "set_cache_settings",
      action_parameters: { cache: true },
      enabled: true,
    };
    const calls = mockCacheRuleApi([agencyOwnRule]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; action: string; ruleId: string; bypassRuleId: string; otherCacheRules: string[] };
    expect(body).toMatchObject({ ok: true, action: "created", ruleId: "rule-new-cache", bypassRuleId: "rule-new-bypass" });
    const writes = calls.filter((call) => call.method !== "GET");
    expect(writes).toHaveLength(2);
    expect(writes.map((call) => call.method)).toEqual(["POST", "POST"]);
    expect(writes.map((call) => call.path)).toEqual([
      "/client/v4/zones/zone-1/rulesets/rs-1/rules",
      "/client/v4/zones/zone-1/rulesets/rs-1/rules",
    ]);
    expect(writes[0]?.body).toEqual(expectedBypassRule());
    expect(writes[1]?.body).toEqual(expectedCacheRule());
    // The agency's own rule is never the target of a write — but it IS reported, so the platform
    // can warn if it turns out to be a stray force-cache rule.
    expect(writes.some((call) => call.path.includes("agency-rule-1"))).toBe(false);
    expect(body.otherCacheRules).toEqual(["agency: cache images longer [agency-rule-1] enabled cache=true"]);
  });

  it("cache-rule-upsert: enabled:false PATCHes BOTH existing rules in place (rollback without delete)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob({ params: JSON.stringify({ ...CACHE_RULE_PARAMS, enabled: false }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockCacheRuleApi([
      { ...expectedBypassRule(true), id: "rule-ours-bypass" },
      { ...expectedCacheRule(true), id: "rule-ours" },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "cache-rule-upsert",
      zone: "example.com",
      action: "updated",
      ruleId: "rule-ours",
      enabled: false,
      cacheAction: "updated",
      bypassRuleId: "rule-ours-bypass",
      bypassAction: "updated",
      otherCacheRules: [],
    });
    const writes = calls.filter((call) => call.method !== "GET");
    expect(writes).toHaveLength(2);
    expect(writes.map((call) => call.method)).toEqual(["PATCH", "PATCH"]);
    expect(writes[0]?.path).toBe("/client/v4/zones/zone-1/rulesets/rs-1/rules/rule-ours-bypass");
    expect(writes[0]?.body).toEqual(expectedBypassRule(false));
    expect(writes[1]?.path).toBe("/client/v4/zones/zone-1/rulesets/rs-1/rules/rule-ours");
    expect(writes[1]?.body).toEqual(expectedCacheRule(false));
  });

  it("cache-rule-upsert: a zone still carrying the shelved force-cache rule (override_origin) is PATCHed to the respect-origin action_parameters", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob();
    const signature = await signAsApp(job, privateKey);
    // The retired force-cache body, as a live zone would echo it: mode override_origin + a rule TTL +
    // status_code_ttl. Re-applying the new rule must treat it as drift and PATCH it away.
    const drifted = {
      ...expectedCacheRule(),
      id: "rule-ours",
      action_parameters: {
        cache: true,
        edge_ttl: {
          mode: "override_origin",
          default: 600,
          status_code_ttl: [
            { status_code_range: { from: 302, to: 307 }, value: -1 },
            { status_code_range: { from: 400, to: 599 }, value: -1 },
          ],
        },
        browser_ttl: { mode: "respect_origin" },
      },
    };
    const calls = mockCacheRuleApi([drifted]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; action: string; cacheAction: string; bypassAction: string };
    // The legacy zone had only the old cache rule: the bypass rule is NEW (appended) and the cache
    // rule is PATCHed — the combined action reports the strongest, the per-rule fields the detail.
    expect(body).toMatchObject({ ok: true, action: "created", cacheAction: "updated", bypassAction: "created" });
    const patch = calls.find((call) => call.method === "PATCH");
    expect(patch?.path).toBe("/client/v4/zones/zone-1/rulesets/rs-1/rules/rule-ours");
    expect(patch?.body).toEqual(expectedCacheRule());
    expect(calls.find((call) => call.method === "POST")?.body).toEqual(expectedBypassRule());
  });

  it("cache-rule-upsert: a matching rule (keys in another order) => NO write at all", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob();
    const signature = await signAsApp(job, privateKey);
    const desired = expectedCacheRule();
    // Cloudflare may echo object keys in a different order; the drift check must not care.
    const sameButReordered = {
      enabled: true,
      id: "rule-ours",
      action_parameters: {
        browser_ttl: { mode: "respect_origin" },
        edge_ttl: { mode: "bypass_by_default" },
        cache: true,
      },
      action: desired.action,
      expression: desired.expression,
      description: desired.description,
    };
    const bypassReordered = {
      action_parameters: { cache: false },
      enabled: true,
      expression: expectedBypassRule().expression,
      id: "rule-ours-bypass",
      action: "set_cache_settings",
      description: expectedBypassRule().description,
    };
    const calls = mockCacheRuleApi([sameButReordered, bypassReordered]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(await response.json()).toEqual({
      ok: true,
      op: "cache-rule-upsert",
      zone: "example.com",
      action: "unchanged",
      ruleId: "rule-ours",
      enabled: true,
      cacheAction: "unchanged",
      bypassRuleId: "rule-ours-bypass",
      bypassAction: "unchanged",
      otherCacheRules: [],
    });
    expect(calls.every((call) => call.method === "GET")).toBe(true);
  });

  it("cache-rule-upsert: two rules carrying our description => fails closed with no write", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockCacheRuleApi([
      { ...expectedCacheRule(), id: "rule-a" },
      { ...expectedCacheRule(), id: "rule-b" },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/ambiguous/);
    expect(calls.every((call) => call.method === "GET")).toBe(true);
  });

  it("cache-rule-upsert: a token without the Cache Rules scope gets a clear denial and no write", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockCacheRuleApi([], 403);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; zone: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.zone).toBe("example.com");
    expect(body.detail).toMatch(/Cache Rules: Edit/);
    expect(calls.every((call) => call.method === "GET")).toBe(true);
  });

  it("cache-rule-upsert: an expression smuggled into the signed params never reaches Cloudflare", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob({
      params: JSON.stringify({
        ...CACHE_RULE_PARAMS,
        expression: "true",
        action_parameters: { cache: true, edge_ttl: { mode: "override_origin", default: 31536000 } },
      }),
    });
    const signature = await signAsApp(job, privateKey);
    const calls = mockCacheRuleApi([]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const writes = calls.filter((call) => call.method === "POST");
    expect(writes.map((call) => call.body)).toEqual([expectedBypassRule(), expectedCacheRule()]);
    for (const write of writes) {
      expect(write.body?.expression).not.toBe("true");
      expect(JSON.stringify(write.body)).not.toContain("override_origin");
    }
  });

  it("cache-rule-upsert: fails cleanly when the token cannot see the zone (no ruleset read or write)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob();
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

  it("cache-rule-upsert: reports a clean failure and touches NO API when CF_DNS_API_TOKEN is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob();
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

  it("cache-rule-upsert: a signed job with an invalid suffix is 400 with no API call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = cacheRuleJob({ params: JSON.stringify({ ...CACHE_RULE_PARAMS, hostSuffix: "-staging.example.com" }) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/hostSuffix/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── waf-rule-upsert through the registry ──────────────────────────────────────────

  /** The five rules the Worker must write for WAF_RULE_PARAMS, in apply order. */
  function expectedWafRules(enabled = true): WafRule[] {
    const built = buildEdgeWafRules({
      zone: WAF_RULE_PARAMS.zone,
      enabled,
      excludedHosts: WAF_RULE_PARAMS.excludedHosts,
      agentHosts: WAF_RULE_PARAMS.agentHosts,
    });
    if (!built.ok) throw new Error(built.reason);
    return edgeWafRulesInOrder(built.rules);
  }
  /** The id the mock assigns a newly written rule, by which rule it is. */
  function newWafIdFor(description: unknown): string {
    if (description === WAF_COUNTRY_BLOCK_DESCRIPTION) return "rule-new-country";
    if (description === WAF_WPADMIN_GEO_DESCRIPTION) return "rule-new-wpadmin";
    if (description === WAF_LOGIN_GATE_DESCRIPTION) return "rule-new-login";
    if (description === WAF_FRONTEND_GEO_DESCRIPTION) return "rule-new-frontend";
    if (description === WAF_EXEC_SKIP_DESCRIPTION) return "rule-new-exec";
    return "rule-new-other";
  }
  /** An execute rule for the Cloudflare Managed Ruleset as Cloudflare would list it. */
  function managedExecuteRule(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      id: "managed-exec-1",
      description: "",
      expression: "true",
      action: "execute",
      action_parameters: { id: CLOUDFLARE_MANAGED_RULESET_ID },
      enabled: true,
      ...overrides,
    };
  }

  interface WafMockOptions {
    /** The zone name the lookup answers for (default example.com). */
    zoneName?: string;
    /** The zone's plan.legacy_id; null => the zone object carries no plan at all. Default "pro". */
    plan?: string | null;
    /** The managed-phase entrypoint's rules; null => 404 (none yet). Default null. */
    managedRules?: Array<Record<string, unknown>> | null;
    /** Makes the firewall-custom entrypoint GET answer this status (401/403). */
    denyStatus?: number;
    /** Makes the write of the rule with this description fail. */
    refuseWriteFor?: string;
    /** Makes every write to the MANAGED phase fail. */
    refuseManagedWrite?: boolean;
  }

  /**
   * A routed CF ruleset API mock: zone lookup (with the plan), both phase entrypoints, and the
   * writes (create entrypoint / append rule / patch rule). `customRules` = the firewall-custom rules
   * the zone already has; null => 404 (none yet). Every call must carry the DNS token.
   */
  function mockWafRuleApi(customRules: Array<Record<string, unknown>> | null, options: WafMockOptions = {}) {
    const zoneName = options.zoneName ?? "example.com";
    let plan: string | null = "pro";
    if (options.plan !== undefined) plan = options.plan;
    const managedRules = options.managedRules ?? null;
    const calls: Array<{ method: string; path: string; body?: Record<string, unknown> }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      const auth = new Headers(init?.headers).get("authorization");
      expect(auth).toBe("Bearer cf-dns-token-abc");
      const parsed = new URL(url);
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      calls.push({ method, path: parsed.pathname, body });

      if (parsed.pathname === "/client/v4/zones" && method === "GET") {
        expect(parsed.searchParams.get("name")).toBe(zoneName);
        const zone: Record<string, unknown> = { id: "zone-1", name: zoneName };
        if (plan !== null) zone.plan = { id: "plan-id", name: `${plan} plan`, legacy_id: plan };
        return jsonResponse({ success: true, result: [zone] });
      }
      if (parsed.pathname === "/client/v4/zones/zone-1/rulesets/phases/http_request_firewall_custom/entrypoint" && method === "GET") {
        if (options.denyStatus !== undefined) {
          return jsonResponse({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }, options.denyStatus);
        }
        if (customRules === null) {
          return jsonResponse({ success: false, errors: [{ code: 10003, message: "could not find entrypoint ruleset" }] }, 404);
        }
        return jsonResponse({ success: true, result: { id: "rs-1", rules: customRules } });
      }
      if (parsed.pathname === "/client/v4/zones/zone-1/rulesets/phases/http_request_firewall_managed/entrypoint" && method === "GET") {
        if (managedRules === null) {
          return jsonResponse({ success: false, errors: [{ code: 10003, message: "could not find entrypoint ruleset" }] }, 404);
        }
        return jsonResponse({ success: true, result: { id: "rs-managed", rules: managedRules } });
      }

      const writtenDescription = (body?.description ?? (body?.rules as Array<Record<string, unknown>> | undefined)?.[0]?.description) as
        | string
        | undefined;
      const isManagedWrite =
        parsed.pathname.includes("/rulesets/rs-managed/") || body?.phase === "http_request_firewall_managed";
      if (method !== "GET" && options.refuseWriteFor !== undefined && writtenDescription === options.refuseWriteFor) {
        return jsonResponse({ success: false, errors: [{ code: 20200, message: "upstream write failed" }] }, 500);
      }
      if (method !== "GET" && isManagedWrite && options.refuseManagedWrite === true) {
        return jsonResponse({ success: false, errors: [{ code: 20200, message: "managed write failed" }] }, 500);
      }

      if (parsed.pathname === "/client/v4/zones/zone-1/rulesets" && method === "POST") {
        const createdRules = (body?.rules as Array<Record<string, unknown>>).map((rule) => ({ ...rule, id: newWafIdFor(rule.description) }));
        let id = "rs-new";
        if (isManagedWrite) id = "rs-managed-new";
        return jsonResponse({ success: true, result: { id, rules: createdRules } });
      }
      // Append to ANY ruleset id. Stateless: the reply is the initial custom rules + this write.
      const appendMatch = /^\/client\/v4\/zones\/zone-1\/rulesets\/(rs-[a-z0-9-]+)\/rules$/.exec(parsed.pathname);
      if (appendMatch && method === "POST") {
        return jsonResponse({
          success: true,
          result: { id: appendMatch[1], rules: [...(customRules ?? []), { ...body, id: newWafIdFor(body?.description) }] },
        });
      }
      if (parsed.pathname.startsWith("/client/v4/zones/zone-1/rulesets/rs-1/rules/") && method === "PATCH") {
        return jsonResponse({ success: true, result: { id: "rs-1", rules: customRules } });
      }
      if (parsed.pathname.startsWith("/client/v4/zones/zone-1/rulesets/rs-managed/rules/") && method === "PATCH") {
        return jsonResponse({ success: true, result: { id: "rs-managed", rules: managedRules } });
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    return calls;
  }

  /** The calls that touched the MANAGED phase (its entrypoint read or a write into it). */
  function managedPhaseCalls(calls: Array<{ method: string; path: string; body?: Record<string, unknown> }>) {
    return calls.filter(
      (call) =>
        call.path.includes("http_request_firewall_managed") ||
        call.path.includes("/rulesets/rs-managed") ||
        call.body?.phase === "http_request_firewall_managed" ||
        call.body?.action === "execute",
    );
  }

  it("waf-rule-upsert: a fresh Pro zone => creates the entrypoint with rule 1, appends 2-5, THEN deploys the Managed Ruleset", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi(null);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "waf-rule-upsert",
      zone: "example.com",
      enabled: true,
      plan: "pro",
      ruleCap: 20,
      rules: [
        { description: "doubleyoup-country-block", action: "created", ruleId: "rule-new-country" },
        { description: "doubleyoup-wpadmin-geo", action: "created", ruleId: "rule-new-wpadmin" },
        { description: "doubleyoup-login-gate", action: "created", ruleId: "rule-new-login" },
        { description: "doubleyoup-frontend-geo", action: "created", ruleId: "rule-new-frontend" },
        { description: WAF_EXEC_SKIP_DESCRIPTION, action: "created", ruleId: "rule-new-exec" },
      ],
      otherWafRules: [],
      managedRuleset: "deployed",
    });
    const writes = calls.filter((call) => call.method !== "GET");
    expect(writes).toHaveLength(6);
    // Custom rules: ONE create (rule 1) + four appends to the NEW ruleset, in apply order.
    expect(writes[0]?.path).toBe("/client/v4/zones/zone-1/rulesets");
    expect(writes[0]?.body).toEqual({ name: "default", kind: "zone", phase: "http_request_firewall_custom", rules: [expectedWafRules()[0]] });
    for (let index = 1; index <= 4; index += 1) {
      expect(writes[index]?.path).toBe("/client/v4/zones/zone-1/rulesets/rs-new/rules");
      expect(writes[index]?.body).toEqual(expectedWafRules()[index]);
    }
    // The Managed Ruleset LAST — after the /exec skip is in force — via POST (never PUT).
    expect(writes[5]?.method).toBe("POST");
    expect(writes[5]?.path).toBe("/client/v4/zones/zone-1/rulesets");
    expect(writes[5]?.body).toEqual({
      name: "default",
      kind: "zone",
      phase: "http_request_firewall_managed",
      rules: [buildManagedRulesetExecuteRule()],
    });
    const execSkipWriteIndex = calls.findIndex((call) => call.body?.description === WAF_EXEC_SKIP_DESCRIPTION);
    const firstManagedCallIndex = calls.findIndex((call) => managedPhaseCalls([call]).length > 0);
    expect(execSkipWriteIndex).toBeGreaterThan(-1);
    expect(firstManagedCallIndex).toBeGreaterThan(execSkipWriteIndex);
  });

  it("waf-rule-upsert: an existing ruleset without our rules => APPENDS all five and never touches the agency's own rule", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const agencyOwnRule = {
      id: "agency-rule-1",
      description: "agency: allow the office",
      expression: "ip.src in {203.0.113.7}",
      action: "skip",
      enabled: true,
    };
    const calls = mockWafRuleApi([agencyOwnRule], { managedRules: [managedExecuteRule()] });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      rules: Array<{ action: string }>;
      otherWafRules: string[];
      managedRuleset: string;
    };
    expect(body.ok).toBe(true);
    expect(body.rules.map((rule) => rule.action)).toEqual(["created", "created", "created", "created", "created"]);
    const writes = calls.filter((call) => call.method !== "GET");
    // FIVE appends to the EXISTING ruleset — no create, no PUT, nothing that could replace it.
    expect(writes.map((call) => call.method)).toEqual(["POST", "POST", "POST", "POST", "POST"]);
    expect(new Set(writes.map((call) => call.path))).toEqual(new Set(["/client/v4/zones/zone-1/rulesets/rs-1/rules"]));
    expect(writes.map((call) => call.body)).toEqual(expectedWafRules());
    // The agency's own rule is never the target of a write — but it IS reported.
    expect(writes.some((call) => call.path.includes("agency-rule-1"))).toBe(false);
    expect(body.otherWafRules).toEqual(["agency: allow the office [agency-rule-1] enabled action=skip"]);
    // The Managed Ruleset was already deployed: left exactly as it is.
    expect(body.managedRuleset).toBe("already-deployed");
  });

  it("waf-rule-upsert: the live syd rule set converges IN PLACE — three deliberate changes PATCHed, the login gate MOVED, nothing added", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const sydParams = {
      zone: "doubleyoup.com",
      enabled: true,
      excludedHosts: [
        "app.doubleyoup.com",
        "status.doubleyoup.com",
        "media.doubleyoup.com",
        "host.doubleyoup.com",
        "cell-syd.doubleyoup.com",
      ],
      agentHosts: ["cell-syd.doubleyoup.com"],
      includeManagedRuleset: true,
    };
    const job = wafRuleJob({ params: JSON.stringify(sydParams) });
    const signature = await signAsApp(job, privateKey);
    // The five live rules, verbatim, in the LIVE order (login gate first), as Cloudflare lists them.
    const liveRules = [
      { id: "live-login", description: "doubleyoup-login-gate", action: "managed_challenge", expression: SYD_LIVE_LOGIN_GATE_EXPRESSION, enabled: true },
      { id: "live-country", description: "doubleyoup-country-block", action: "block", expression: SYD_LIVE_COUNTRY_BLOCK_EXPRESSION, enabled: true },
      { id: "live-wpadmin", description: "doubleyoup-wpadmin-geo", action: "block", expression: SYD_LIVE_WPADMIN_GEO_EXPRESSION, enabled: true },
      { id: "live-frontend", description: "doubleyoup-frontend-geo", action: "managed_challenge", expression: SYD_LIVE_FRONTEND_GEO_EXPRESSION, enabled: true },
      {
        id: "live-exec",
        description: SYD_LIVE_EXEC_SKIP_DESCRIPTION,
        action: "skip",
        expression: SYD_LIVE_EXEC_SKIP_EXPRESSION,
        action_parameters: { phases: ["http_request_firewall_managed"] },
        enabled: true,
      },
    ];
    const calls = mockWafRuleApi(liveRules, { zoneName: "doubleyoup.com", plan: "pro", managedRules: [managedExecuteRule()] });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "waf-rule-upsert",
      zone: "doubleyoup.com",
      enabled: true,
      plan: "pro",
      ruleCap: 20,
      rules: [
        { description: "doubleyoup-country-block", action: "unchanged", ruleId: "live-country" },
        { description: "doubleyoup-wpadmin-geo", action: "updated", ruleId: "live-wpadmin" },
        // Live order is login gate FIRST; documented order puts it after the wp-admin geo block (L1).
        { description: "doubleyoup-login-gate", action: "moved", ruleId: "live-login" },
        { description: "doubleyoup-frontend-geo", action: "updated", ruleId: "live-frontend" },
        { description: SYD_LIVE_EXEC_SKIP_DESCRIPTION, action: "updated", ruleId: "live-exec" },
      ],
      otherWafRules: [],
      // syd's live execute rule was added by hand, without our description: another owner's, left alone.
      managedRuleset: "already-deployed",
    });
    const writes = calls.filter((call) => call.method !== "GET");
    expect(writes.map((call) => `${call.method} ${call.path}`)).toEqual([
      "PATCH /client/v4/zones/zone-1/rulesets/rs-1/rules/live-wpadmin",
      "PATCH /client/v4/zones/zone-1/rulesets/rs-1/rules/live-login",
      "PATCH /client/v4/zones/zone-1/rulesets/rs-1/rules/live-frontend",
      "PATCH /client/v4/zones/zone-1/rulesets/rs-1/rules/live-exec",
    ]);
    // The three definition changes carry NO position: each already sits after its predecessor.
    expect(writes[0]?.body?.expression).toBe(EXPECTED_WPADMIN_GEO_EXPRESSION);
    expect(writes[0]?.body?.position).toBeUndefined();
    // The login gate's definition is right; ONLY its position is sent, so Cloudflare keeps the rest.
    expect(writes[1]?.body).toEqual({ position: { after: "live-wpadmin" } });
    expect(writes[2]?.body?.expression).toBe(
      `${SYD_LIVE_FRONTEND_GEO_EXPRESSION} and not ends_with(http.host, "-media.doubleyoup.com")`,
    );
    expect(writes[2]?.body?.position).toBeUndefined();
    expect(writes[3]?.body?.expression).toBe(EXPECTED_SYD_AGENT_SKIP_EXPRESSION);
    expect(writes[3]?.body?.action_parameters).toEqual({ phases: ["http_request_firewall_managed"] });
    expect(writes[3]?.body?.position).toBeUndefined();
  });

  it("waf-rule-upsert: an identical rule set in the documented order + a deployed Managed Ruleset => NO write at all", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const [countryBlock, wpAdminGeo, loginGate, frontendGeo, execSkip] = expectedWafRules();
    // With Cloudflare's extra fields, a FOREIGN rule between two of ours (no reason to move either),
    // and a managed execute rule carrying the agency's own OVERRIDES (which must survive untouched).
    const calls = mockWafRuleApi(
      [
        { ...countryBlock, id: "rule-country", ref: "cf-ref-1" },
        { id: "agency-rule", description: "agency: allow the office", expression: "ip.src in {203.0.113.7}", action: "skip", enabled: true },
        { ...wpAdminGeo, id: "rule-wpadmin", ref: "cf-ref-2" },
        { ...loginGate, id: "rule-login", ref: "cf-ref-3" },
        { ...frontendGeo, id: "rule-frontend", ref: "cf-ref-4" },
        { ...execSkip, id: "rule-exec", ref: "cf-ref-5", logging: { enabled: true } },
      ],
      {
        managedRules: [
          managedExecuteRule({
            action_parameters: { id: CLOUDFLARE_MANAGED_RULESET_ID, overrides: { rules: [{ id: "abc", action: "log" }] } },
          }),
        ],
      },
    );

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; rules: Array<{ action: string; ruleId: string }>; managedRuleset: string };
    expect(body.ok).toBe(true);
    expect(body.rules.map((rule) => rule.action)).toEqual(["unchanged", "unchanged", "unchanged", "unchanged", "unchanged"]);
    expect(body.rules.map((rule) => rule.ruleId)).toEqual(["rule-country", "rule-wpadmin", "rule-login", "rule-frontend", "rule-exec"]);
    expect(body.managedRuleset).toBe("already-deployed");
    expect(calls.every((call) => call.method === "GET")).toBe(true);
  });

  it("waf-rule-upsert: identical rules in the WRONG order are MOVED into the documented order — position only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const [countryBlock, wpAdminGeo, loginGate, frontendGeo, execSkip] = expectedWafRules();
    const calls = mockWafRuleApi([
      { ...execSkip, id: "rule-exec" },
      { ...loginGate, id: "rule-login" },
      { ...frontendGeo, id: "rule-frontend" },
      { ...countryBlock, id: "rule-country" },
      { ...wpAdminGeo, id: "rule-wpadmin" },
    ]);

    const body = (await (await worker.fetch(actuateRequest({ job, signature }), envWith())).json()) as {
      ok: boolean;
      rules: Array<{ action: string }>;
    };
    expect(body.ok).toBe(true);
    expect(body.rules.map((rule) => rule.action)).toEqual(["unchanged", "unchanged", "moved", "moved", "moved"]);
    const writes = calls.filter((call) => call.method === "PATCH");
    // Each move is relative to OUR previous rule, and carries nothing but the position. Ending order:
    // country, wp-admin, login, front end, agent skip.
    expect(writes.map((call) => [call.path.split("/").pop(), call.body])).toEqual([
      ["rule-login", { position: { after: "rule-wpadmin" } }],
      ["rule-frontend", { position: { after: "rule-login" } }],
      ["rule-exec", { position: { after: "rule-frontend" } }],
    ]);
  });

  it("waf-rule-upsert: the order check follows its OWN earlier moves (the in-memory copy is re-ordered)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const [countryBlock, wpAdminGeo, loginGate, frontendGeo, execSkip] = expectedWafRules();
    // Before the login gate moves, the front-end rule looks "after" it; once it has moved, it is not.
    const calls = mockWafRuleApi([
      { ...loginGate, id: "rule-login" },
      { ...frontendGeo, id: "rule-frontend" },
      { ...countryBlock, id: "rule-country" },
      { ...wpAdminGeo, id: "rule-wpadmin" },
      { ...execSkip, id: "rule-exec" },
    ]);

    await worker.fetch(actuateRequest({ job, signature }), envWith());
    const writes = calls.filter((call) => call.method === "PATCH");
    expect(writes.map((call) => [call.path.split("/").pop(), call.body])).toEqual([
      ["rule-login", { position: { after: "rule-wpadmin" } }],
      ["rule-frontend", { position: { after: "rule-login" } }],
    ]);
  });

  it("waf-rule-upsert: a rule that drifted AND is out of order gets ONE PATCH carrying both the definition and the position", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const [countryBlock, wpAdminGeo, loginGate, frontendGeo, execSkip] = expectedWafRules();
    const calls = mockWafRuleApi([
      { ...loginGate, id: "rule-login", enabled: false },
      { ...countryBlock, id: "rule-country" },
      { ...wpAdminGeo, id: "rule-wpadmin" },
      { ...frontendGeo, id: "rule-frontend" },
      { ...execSkip, id: "rule-exec" },
    ]);

    const body = (await (await worker.fetch(actuateRequest({ job, signature }), envWith())).json()) as { rules: Array<{ action: string }> };
    expect(body.rules.map((rule) => rule.action)).toEqual(["unchanged", "unchanged", "updated", "unchanged", "unchanged"]);
    const writes = calls.filter((call) => call.method === "PATCH");
    expect(writes).toHaveLength(1);
    expect(writes[0]?.path).toBe("/client/v4/zones/zone-1/rulesets/rs-1/rules/rule-login");
    expect(writes[0]?.body).toEqual({ ...loginGate, position: { after: "rule-wpadmin" } });
  });

  it("waf-rule-upsert: enabled:false PATCHes the four protections OFF in place and leaves the /exec skip ON", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob({ params: JSON.stringify({ ...WAF_RULE_PARAMS, enabled: false, includeManagedRuleset: false }) });
    const signature = await signAsApp(job, privateKey);
    const [countryBlock, wpAdminGeo, loginGate, frontendGeo, execSkip] = expectedWafRules(true);
    const calls = mockWafRuleApi([
      { ...countryBlock, id: "rule-country" },
      { ...wpAdminGeo, id: "rule-wpadmin" },
      { ...loginGate, id: "rule-login" },
      { ...frontendGeo, id: "rule-frontend" },
      { ...execSkip, id: "rule-exec" },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; enabled: boolean; rules: Array<{ action: string }>; managedRuleset: string };
    expect(body.ok).toBe(true);
    expect(body.enabled).toBe(false);
    expect(body.rules.map((rule) => rule.action)).toEqual(["updated", "updated", "updated", "updated", "unchanged"]);
    const writes = calls.filter((call) => call.method !== "GET");
    expect(writes.map((call) => call.path)).toEqual([
      "/client/v4/zones/zone-1/rulesets/rs-1/rules/rule-country",
      "/client/v4/zones/zone-1/rulesets/rs-1/rules/rule-wpadmin",
      "/client/v4/zones/zone-1/rulesets/rs-1/rules/rule-login",
      "/client/v4/zones/zone-1/rulesets/rs-1/rules/rule-frontend",
    ]);
    expect(writes.map((call) => call.body)).toEqual(expectedWafRules(false).slice(0, 4));
    // A rollback run did not ask for the Managed Ruleset, so the managed phase is never touched.
    expect(body.managedRuleset).toBe("not-requested");
    expect(managedPhaseCalls(calls)).toHaveLength(0);
  });

  it("waf-rule-upsert: a drifted rule (someone softened the country BLOCK to a challenge) is PATCHed back", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const [countryBlock] = expectedWafRules();
    const calls = mockWafRuleApi([{ ...countryBlock, id: "rule-country", action: "managed_challenge" }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; rules: Array<{ description: string; action: string }> };
    expect(body.ok).toBe(true);
    expect(body.rules.map((rule) => rule.action)).toEqual(["updated", "created", "created", "created", "created"]);
    const patch = calls.find((call) => call.method === "PATCH");
    expect(patch?.path).toBe("/client/v4/zones/zone-1/rulesets/rs-1/rules/rule-country");
    expect(patch?.body).toEqual(countryBlock);
  });

  it("waf-rule-upsert: two rules carrying one of our descriptions => fails closed with NO write at all", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const [countryBlock, wpAdminGeo] = expectedWafRules();
    // The ambiguity is on the SECOND rule we would apply, so this also proves the pre-scan runs
    // BEFORE any write: rule 1 must not land while rule 2's state is ambiguous.
    const calls = mockWafRuleApi([
      { ...countryBlock, id: "rule-country" },
      { ...wpAdminGeo, id: "rule-wpadmin-a" },
      { ...wpAdminGeo, id: "rule-wpadmin-b" },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string; wafRulesApplied?: unknown };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/ambiguous/);
    expect(body.detail).toMatch(/doubleyoup-wpadmin-geo/);
    expect(body.wafRulesApplied).toBeUndefined();
    expect(calls.every((call) => call.method === "GET")).toBe(true);
  });

  it("waf-rule-upsert: a Free zone without room is REFUSED before ANY write — custom or managed", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const agencyRule = { id: "agency-rule-1", description: "agency rule", expression: 'http.host eq "shop.example.com"', action: "block", enabled: false };
    const calls = mockWafRuleApi([agencyRule], { plan: "free" });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      detail: string;
      capExceeded?: boolean;
      ruleCap?: number;
      plannedRuleCount?: number;
      wafRulesApplied?: unknown;
    };
    expect(body.ok).toBe(false);
    expect(body.capExceeded).toBe(true);
    expect(body.ruleCap).toBe(5);
    // 1 existing rule (DISABLED rules count too) + 5 of ours = 6 > 5.
    expect(body.plannedRuleCount).toBe(6);
    expect(body.detail).toMatch(/refusing to change anything/);
    expect(body.detail).toMatch(/plan "free"/);
    expect(body.wafRulesApplied).toBeUndefined();
    expect(calls.every((call) => call.method === "GET")).toBe(true);
    expect(managedPhaseCalls(calls)).toHaveLength(0);
  });

  it("waf-rule-upsert: the cap counts CREATES only — a full Free zone whose rules are ours still converges", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const [countryBlock, wpAdminGeo, loginGate, frontendGeo, execSkip] = expectedWafRules();
    const calls = mockWafRuleApi(
      [
        { ...countryBlock, id: "rule-country" },
        { ...wpAdminGeo, id: "rule-wpadmin", expression: SYD_LIVE_WPADMIN_GEO_EXPRESSION },
        { ...loginGate, id: "rule-login" },
        { ...frontendGeo, id: "rule-frontend" },
        { ...execSkip, id: "rule-exec" },
      ],
      { plan: "free" },
    );

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; ruleCap: number; rules: Array<{ action: string }>; managedRuleset: string };
    expect(body.ok).toBe(true);
    expect(body.ruleCap).toBe(5);
    expect(body.rules.map((rule) => rule.action)).toEqual(["unchanged", "updated", "unchanged", "unchanged", "unchanged"]);
    // Free plan: the Managed Ruleset is not attempted at all.
    expect(body.managedRuleset).toBe("unavailable-on-plan");
    expect(managedPhaseCalls(calls)).toHaveLength(0);
  });

  it("waf-rule-upsert: a zone with NO plan in the lookup is sized as the smallest plan and gets no Managed Ruleset", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi(null, { plan: null });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; plan: string; ruleCap: number; managedRuleset: string };
    expect(body.ok).toBe(true);
    expect(body.plan).toBe("unknown");
    expect(body.ruleCap).toBe(5);
    expect(body.managedRuleset).toBe("unavailable-on-plan");
    expect(managedPhaseCalls(calls)).toHaveLength(0);
  });

  it("waf-rule-upsert: a DISABLED Managed Ruleset execute rule is left off — that is the agency's call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi(null, { managedRules: [managedExecuteRule({ enabled: false })] });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; managedRuleset: string };
    expect(body.ok).toBe(true);
    expect(body.managedRuleset).toBe("present-disabled");
    const managedWrites = managedPhaseCalls(calls).filter((call) => call.method !== "GET");
    expect(managedWrites).toHaveLength(0);
  });

  it("waf-rule-upsert: a managed entrypoint that runs OTHER rulesets gets ours APPENDED, theirs untouched", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const owaspRule = managedExecuteRule({ id: "owasp-exec", action_parameters: { id: "4814384a9e5d4991b9815dcfc25d2f1f" } });
    const calls = mockWafRuleApi(null, { managedRules: [owaspRule] });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; managedRuleset: string };
    expect(body.ok).toBe(true);
    expect(body.managedRuleset).toBe("deployed");
    const managedWrites = managedPhaseCalls(calls).filter((call) => call.method !== "GET");
    expect(managedWrites).toHaveLength(1);
    expect(managedWrites[0]?.method).toBe("POST");
    expect(managedWrites[0]?.path).toBe("/client/v4/zones/zone-1/rulesets/rs-managed/rules");
    expect(managedWrites[0]?.body).toEqual(buildManagedRulesetExecuteRule());
  });

  it("waf-rule-upsert: includeManagedRuleset:false never touches the managed phase", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob({ params: JSON.stringify({ ...WAF_RULE_PARAMS, includeManagedRuleset: false }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi(null);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; managedRuleset: string };
    expect(body.ok).toBe(true);
    expect(body.managedRuleset).toBe("not-requested");
    expect(managedPhaseCalls(calls)).toHaveLength(0);
  });

  /** OUR execute rule (the one this op creates) as Cloudflare would list it, with an agency override. */
  function ourManagedRule(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return managedExecuteRule({
      id: "managed-ours",
      description: MANAGED_RULESET_RULE_DESCRIPTION,
      action_parameters: { id: CLOUDFLARE_MANAGED_RULESET_ID, overrides: { rules: [{ id: "fp-rule", action: "log" }] } },
      ...overrides,
    });
  }
  /** Another owner's execute rule for the SAME Managed Ruleset (syd's was added by hand like this). */
  const foreignManagedRule = managedExecuteRule({ id: "managed-theirs", description: "" });

  it("waf-rule-upsert: --disable --managed-ruleset DISABLES our execute rule in place — overrides kept, never deleted", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob({ params: JSON.stringify({ ...WAF_RULE_PARAMS, enabled: false, includeManagedRuleset: true }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi(null, { managedRules: [foreignManagedRule, ourManagedRule()] });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; managedRuleset: string };
    expect(body.ok).toBe(true);
    expect(body.managedRuleset).toBe("disabled");
    const managedWrites = managedPhaseCalls(calls).filter((call) => call.method !== "GET");
    // ONE write: a PATCH of OUR rule. Another owner's execute rule is never the target; nothing is deleted.
    expect(managedWrites.map((call) => `${call.method} ${call.path}`)).toEqual([
      "PATCH /client/v4/zones/zone-1/rulesets/rs-managed/rules/managed-ours",
    ]);
    expect(managedWrites[0]?.body).toEqual({
      description: "doubleyoup-managed-ruleset",
      expression: "true",
      action: "execute",
      action_parameters: { id: CLOUDFLARE_MANAGED_RULESET_ID, overrides: { rules: [{ id: "fp-rule", action: "log" }] } },
      enabled: false,
    });
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
  });

  it("waf-rule-upsert: a rollback never touches ANOTHER owner's execute rule ('not-ours'), and reports 'absent' when nothing runs it", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const rollback = JSON.stringify({ ...WAF_RULE_PARAMS, enabled: false, includeManagedRuleset: true });

    const notOursJob = wafRuleJob({ params: rollback });
    const notOursCalls = mockWafRuleApi(null, { managedRules: [foreignManagedRule] });
    const notOurs = (await (await worker.fetch(actuateRequest({ job: notOursJob, signature: await signAsApp(notOursJob, privateKey) }), envWith())).json()) as { managedRuleset: string };
    expect(notOurs.managedRuleset).toBe("not-ours");
    expect(managedPhaseCalls(notOursCalls).filter((call) => call.method !== "GET")).toHaveLength(0);
    vi.restoreAllMocks();

    // A rollback is not plan-gated: it runs on a Free zone too (nothing of ours can be there, but it checks).
    const absentJob = wafRuleJob({ params: rollback, nonce: "ef56ef56ef56ef56ef56ef56ef56ef56" });
    const absentCalls = mockWafRuleApi(null, { plan: "free", managedRules: null });
    const absent = (await (await worker.fetch(actuateRequest({ job: absentJob, signature: await signAsApp(absentJob, privateKey) }), envWith())).json()) as { managedRuleset: string };
    expect(absent.managedRuleset).toBe("absent");
    expect(managedPhaseCalls(absentCalls).filter((call) => call.method !== "GET")).toHaveLength(0);
  });

  it("waf-rule-upsert: a rollback of an already-disabled rule of ours writes nothing ('already-disabled')", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob({ params: JSON.stringify({ ...WAF_RULE_PARAMS, enabled: false, includeManagedRuleset: true }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi(null, { managedRules: [ourManagedRule({ enabled: false })] });

    const body = (await (await worker.fetch(actuateRequest({ job, signature }), envWith())).json()) as { managedRuleset: string };
    expect(body.managedRuleset).toBe("already-disabled");
    expect(managedPhaseCalls(calls).filter((call) => call.method !== "GET")).toHaveLength(0);
  });

  it("waf-rule-upsert: --managed-ruleset after a rollback RE-ENABLES our rule in place, overrides kept", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi(null, { managedRules: [ourManagedRule({ enabled: false })] });

    const body = (await (await worker.fetch(actuateRequest({ job, signature }), envWith())).json()) as { managedRuleset: string };
    expect(body.managedRuleset).toBe("re-enabled");
    const managedWrites = managedPhaseCalls(calls).filter((call) => call.method !== "GET");
    expect(managedWrites.map((call) => `${call.method} ${call.path}`)).toEqual([
      "PATCH /client/v4/zones/zone-1/rulesets/rs-managed/rules/managed-ours",
    ]);
    expect(managedWrites[0]?.body?.enabled).toBe(true);
    expect(managedWrites[0]?.body?.action_parameters).toEqual({
      id: CLOUDFLARE_MANAGED_RULESET_ID,
      overrides: { rules: [{ id: "fp-rule", action: "log" }] },
    });
  });

  it("waf-rule-upsert: two managed rules carrying our description => the Managed Ruleset step fails closed, writing nothing there", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob({ params: JSON.stringify({ ...WAF_RULE_PARAMS, enabled: false, includeManagedRuleset: true }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi(null, { managedRules: [ourManagedRule(), ourManagedRule({ id: "managed-ours-2" })] });

    const body = (await (await worker.fetch(actuateRequest({ job, signature }), envWith())).json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/ambiguous/);
    expect(managedPhaseCalls(calls).filter((call) => call.method !== "GET")).toHaveLength(0);
  });

  it("waf-rule-upsert: a write that fails part-way FAILS LOUDLY, names what landed, and skips the Managed Ruleset", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi([], { refuseWriteFor: WAF_LOGIN_GATE_DESCRIPTION });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string; wafRulesApplied: Array<{ description: string; action: string }> };
    // NEVER ok:true with a rule missing.
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/could not apply rule "doubleyoup-login-gate"/);
    expect(body.detail).toMatch(/upstream write failed/);
    expect(body.detail).toMatch(/idempotent/);
    expect(body.wafRulesApplied).toEqual([
      { description: "doubleyoup-country-block", action: "created", ruleId: "rule-new-country" },
      { description: "doubleyoup-wpadmin-geo", action: "created", ruleId: "rule-new-wpadmin" },
    ]);
    // Nothing after the failure was attempted — least of all the Managed Ruleset (no /exec skip yet).
    expect(calls.filter((call) => call.method !== "GET")).toHaveLength(3);
    expect(managedPhaseCalls(calls)).toHaveLength(0);
  });

  it("waf-rule-upsert: a Managed Ruleset write failure is ok:false, and says all five custom rules WERE applied", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    mockWafRuleApi(null, { refuseManagedWrite: true });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    const body = (await response.json()) as { ok: boolean; detail: string; wafRulesApplied: unknown[] };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/all five custom rules were applied/);
    expect(body.detail).toMatch(/managed write failed/);
    expect(body.wafRulesApplied).toHaveLength(5);
  });

  it("waf-rule-upsert: a token without the WAF scope gets a clear, actionable denial and no write", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockWafRuleApi([], { denyStatus: 403 });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; zone: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.zone).toBe("example.com");
    // The exact Cloudflare permission name, not a 403 dump.
    expect(body.detail).toMatch(/Zone WAF Write/);
    expect(body.detail).toMatch(/API-token editor/);
    expect(calls.every((call) => call.method === "GET")).toBe(true);
  });

  it("waf-rule-upsert: a country list smuggled into the signed params is a 400 and reaches NOTHING", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob({
      params: JSON.stringify({
        ...WAF_RULE_PARAMS,
        // The over-broad authority this op exists to refuse: block everyone, allow nobody.
        blockCountries: ["AU", "US", "GB"],
        adminAllowCountries: ["KP"],
      }),
    });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/unknown param "blockCountries"/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("waf-rule-upsert: an over-long host list is refused before ANY Cloudflare call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const hosts = Array.from({ length: 100 }, (_, index) => `a-rather-long-infrastructure-host-${index}.example.com`);
    const job = wafRuleJob({ params: JSON.stringify({ ...WAF_RULE_PARAMS, excludedHosts: hosts, agentHosts: [hosts[0]] }) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/4096-character expression limit/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("waf-rule-upsert: fails cleanly when the token cannot see the zone (no ruleset read or write)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => jsonResponse({ success: true, result: [] }));

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/not visible to CF_DNS_API_TOKEN/);
    expect(fetchSpy).toHaveBeenCalledTimes(1); // the zone lookup only
  });

  it("waf-rule-upsert: reports a clean failure and touches NO API when CF_DNS_API_TOKEN is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // R2 + cell tokens ARE present — neither may be used as a substitute.
    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ CF_DNS_API_TOKEN: undefined }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/CF_DNS_API_TOKEN is not configured/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("waf-rule-upsert: a signed job with an invalid zone is 400 with no API call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = wafRuleJob({ params: JSON.stringify({ ...WAF_RULE_PARAMS, zone: "*.example.com" }) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/zone must be a lowercase DNS zone name/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("waf-rule-upsert: an unsigned or tampered job actuates NOTHING", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const response = await worker.fetch(actuateRequest({ job: wafRuleJob(), signature: "not-a-signature" }), envWith());
    expect(response.status).toBe(401);
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

  // ── provision-ssh-keys through the registry ────────────────────────────────────────
  // The Worker relays {slug, authorizedKeys} to the gateway cell-agent's DEDICATED
  // /provision-ssh-keys endpoint (NOT /exec — key material must never be shell-quoted), using the
  // agency's OWN CELL_AGENT_TOKEN. The load-bearing assertions: it hits the right endpoint with the
  // right body + token, the project is NOT forwarded (the gateway needs only slug + keys), and every
  // relay failure mode is fail-closed exactly like wp-cli.
  function mockSshKeysAgent(reply: { ok?: boolean; slug?: string; count?: number; error?: string }, status = 200) {
    const calls: Array<{
      url: string;
      method: string;
      auth: string | null;
      body: { slug?: string; authorizedKeys?: string[]; project?: string };
    }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      const auth = new Headers(init?.headers).get("authorization");
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      calls.push({ url, method, auth, body });
      if (url.endsWith("/provision-ssh-keys") && method === "POST") {
        return jsonResponse(reply, status);
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    return calls;
  }

  it("provision-ssh-keys: relays {slug, authorizedKeys} to the gateway /provision-ssh-keys using CELL_AGENT_TOKEN only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sshKeysJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockSshKeysAgent({ ok: true, slug: "geelongns", count: 1 });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, op: "provision-ssh-keys", slug: "geelongns", count: 1 });
    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call.url).toBe("https://cell.example.test/provision-ssh-keys");
    expect(call.method).toBe("POST");
    // The agency's OWN cell token — never a platform / Cloudflare credential.
    expect(call.auth).toBe("Bearer cell-token-123");
    expect(call.auth).not.toContain("cf-token-xyz");
    // The gateway needs only slug + the full key set; the platform-layer project is NOT forwarded.
    expect(call.body.slug).toBe("geelongns");
    expect(call.body.authorizedKeys).toEqual(SSH_KEYS_JOB_PARAMS.authorizedKeys);
    expect(call.body.project).toBeUndefined();
  });

  it("provision-ssh-keys: an EMPTY set (revoke-all) relays authorizedKeys:[] and reports count 0", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sshKeysJob({ params: JSON.stringify({ project: "dy-agency-proof", slug: "geelongns", authorizedKeys: [] }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockSshKeysAgent({ ok: true, slug: "geelongns", count: 0 });

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, op: "provision-ssh-keys", slug: "geelongns", count: 0 });
    expect(calls[0].body.authorizedKeys).toEqual([]);
  });

  it("provision-ssh-keys: a cell-agent 401 becomes a clean ok:false (no bypass)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sshKeysJob();
    const signature = await signAsApp(job, privateKey);
    mockSshKeysAgent({ error: "unauthorized" }, 401);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/rejected CELL_AGENT_TOKEN/);
  });

  it("provision-ssh-keys: a cell-agent 500 (script failure) surfaces as ok:false, still HTTP 200", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sshKeysJob();
    const signature = await signAsApp(job, privateKey);
    mockSshKeysAgent({ error: "chroot /sites/geelongns missing" }, 500);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/cell-agent \/provision-ssh-keys failed with HTTP 500/);
  });

  it("provision-ssh-keys: reports a clean failure and touches NO cell-agent when CELL_AGENT_URL/TOKEN are missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sshKeysJob();
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

  it("provision-ssh-keys: a signed job carrying a private key is 400 with no cell-agent call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = sshKeysJob({
      params: JSON.stringify({
        project: "dy-agency-proof",
        slug: "geelongns",
        authorizedKeys: ["-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"],
      }),
    });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/each authorizedKeys entry must be a single-line OpenSSH public key/);
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

  // ── gcp-instance-create through the registry ────────────────────────────────────────
  // The first GCP WRITE: the Worker mints a Google access token from the agency's OWN
  // GCP_SERVICE_ACCOUNT_KEY (FULL cloud-platform scope — the write scope this op needs) and POSTs
  // instances.insert. Load-bearing assertions: the JWT asks for the FULL scope (not read-only), the
  // token goes ONLY into the Compute call's Authorization header and never into the result, the
  // URL path is built from the two grammar-checked segments, the body is the MINIMAL private shape
  // (no accessConfigs => no external IP, no serviceAccounts), a 2xx Operation is ACCEPTED, and every
  // non-2xx (403 / 409 / 404) is a TERMINAL ok:false — a 409 is NOT an idempotent success here.

  const GCP_ACCESS_TOKEN = "ya29.agency-token-never-echoed";
  const GCP_INSERT_URL =
    "https://compute.googleapis.com/compute/v1/projects/dy-agency-proof/zones/australia-southeast1-a/instances";

  /** Route the two Google calls: the token endpoint (always succeeds) and instances.insert (programmable). */
  function mockGcpApi(insertReply: { body: unknown; status?: number }) {
    const calls: Array<{ method: string; url: string; auth: string | null; body?: unknown; form?: URLSearchParams }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      const auth = new Headers(init?.headers).get("authorization");
      if (url === "https://oauth2.googleapis.com/token") {
        calls.push({ method, url, auth, form: new URLSearchParams(String(init?.body)) });
        return jsonResponse({ access_token: GCP_ACCESS_TOKEN, expires_in: 3600, token_type: "Bearer" });
      }
      if (url.startsWith("https://compute.googleapis.com/")) {
        calls.push({ method, url, auth, body: init?.body ? JSON.parse(String(init.body)) : undefined });
        return jsonResponse(insertReply.body, insertReply.status ?? 200);
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    return calls;
  }

  /**
   * Route the Google calls for a MULTI-call op: the token endpoint always succeeds; each Compute call
   * consumes the NEXT programmed reply in order (an extra call throws — a test must program every call
   * it expects). Records every call: URL, method, auth header, the raw + parsed JSON body, and the
   * token form.
   */
  function mockGcpApiQueue(computeReplies: Array<{ body: unknown; status?: number }>) {
    const calls: Array<{
      method: string;
      url: string;
      auth: string | null;
      body?: unknown;
      rawBody?: string;
      form?: URLSearchParams;
    }> = [];
    const queue = [...computeReplies];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      const auth = new Headers(init?.headers).get("authorization");
      if (url === "https://oauth2.googleapis.com/token") {
        calls.push({ method, url, auth, form: new URLSearchParams(String(init?.body)) });
        return jsonResponse({ access_token: GCP_ACCESS_TOKEN, expires_in: 3600, token_type: "Bearer" });
      }
      if (url.startsWith("https://compute.googleapis.com/")) {
        const rawBody = init?.body ? String(init.body) : undefined;
        calls.push({ method, url, auth, rawBody, body: rawBody ? JSON.parse(rawBody) : undefined });
        const reply = queue.shift();
        if (!reply) {
          // gcp-instance-create now WAITS on its insert operation (planning/34 zone fallback). A test
          // that does not care about that follow-up poll need not program it: an UNPROGRAMMED
          // operations.wait call auto-answers with a clean DONE (the VM's insert finished). A test that
          // DOES care (exhaustion, still-running) programs the wait reply itself, so the queue is
          // non-empty here and this fallback never fires. Any other unexpected call still throws.
          if (url.includes("/operations/") && url.endsWith("/wait")) {
            return jsonResponse({ status: "DONE" }, 200);
          }
          throw new Error(`unexpected extra Compute call ${method} ${url}`);
        }
        return jsonResponse(reply.body, reply.status ?? 200);
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    });
    return calls;
  }

  /** Only the Compute Engine calls (the token mint filtered out). */
  function computeCalls<T extends { url: string }>(calls: T[]): T[] {
    return calls.filter((call) => call.url.startsWith("https://compute.googleapis.com/"));
  }

  const GCP_PROJECT_URL = "https://compute.googleapis.com/compute/v1/projects/dy-agency-proof";
  const GCP_REGION_URL = `${GCP_PROJECT_URL}/regions/australia-southeast1`;
  /** Google's 409 for an insert of a name that already exists. */
  function alreadyExists409(resource: string) {
    const message = `The resource '${resource}' already exists`;
    return { status: 409, body: { error: { code: 409, message, errors: [{ reason: "alreadyExists", message }] } } };
  }
  /** Google's 403 for a missing IAM permission. */
  function denied403(permission: string) {
    return { status: 403, body: { error: { code: 403, message: `Required '${permission}' permission`, status: "PERMISSION_DENIED" } } };
  }

  it("gcp-instance-create: mints a FULL-scope token from the agency's SA key and POSTs a minimal PRIVATE instance", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApi({ body: { name: "operation-1234", status: "PENDING", operationType: "insert" } });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    expect(response.status).toBe(200);
    const resultBody = await response.json();
    // The insert is ACCEPTED, then its operation is WAITED (planning/34 zone fallback). This mock
    // returns the SAME PENDING operation for the wait poll too, so within the bounded wait the op is
    // still not DONE — the op falls back to reporting the accepted async Operation (status PENDING).
    expect(resultBody).toEqual({
      ok: true,
      op: "gcp-instance-create",
      instanceName: "dy-dirb-proof-vm",
      operationName: "operation-1234",
      status: "PENDING",
    });
    // The minted token is NEVER echoed in the result.
    expect(JSON.stringify(resultBody)).not.toContain(GCP_ACCESS_TOKEN);

    // token mint + instances.insert + ONE bounded operations.wait poll.
    expect(calls).toHaveLength(3);
    const [tokenCall, insertCall, waitCall] = calls;
    expect(waitCall.method).toBe("POST");
    expect(waitCall.url).toBe(`${GCP_INSERT_URL.replace("/instances", "")}/operations/operation-1234/wait`);

    // 1) The JWT-bearer grant, signed by the agency's SA key, asks for the FULL cloud-platform
    //    scope — the write scope this op needs (validateGCP's probe stays read-only, tested in
    //    validators.test.ts).
    expect(tokenCall.method).toBe("POST");
    expect(tokenCall.form?.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    const claims = jwtClaimsOf(tokenCall.form?.get("assertion") ?? "");
    expect(claims.scope).toBe(GOOGLE_SCOPE_CLOUD_PLATFORM);
    expect(claims.scope).toBe("https://www.googleapis.com/auth/cloud-platform");
    expect(claims.iss).toBe("sa@dy-agency-proof.iam.gserviceaccount.com");
    expect(claims.aud).toBe("https://oauth2.googleapis.com/token");

    // 2) instances.insert at the grammar-checked path, bearing the minted token ONLY (never a
    //    Cloudflare / cell credential), with the minimal private body.
    expect(insertCall.url).toBe(GCP_INSERT_URL);
    expect(insertCall.method).toBe("POST");
    expect(insertCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(insertCall.auth).not.toContain("cf-token-xyz");
    expect(insertCall.auth).not.toContain("cf-dns-token-abc");
    expect(insertCall.auth).not.toContain("cell-token-123");
    expect(insertCall.body).toEqual({
      name: "dy-dirb-proof-vm",
      machineType: "zones/australia-southeast1-a/machineTypes/e2-small",
      disks: [
        {
          boot: true,
          autoDelete: true,
          initializeParams: { sourceImage: "projects/debian-cloud/global/images/family/debian-12" },
        },
      ],
      networkInterfaces: [{ network: "global/networks/default" }],
    });
    // Explicitly: NO external IP (no accessConfigs) and NO attached service account.
    const insertBody = insertCall.body as { networkInterfaces: Array<Record<string, unknown>>; serviceAccounts?: unknown };
    expect(insertBody.networkInterfaces[0]).not.toHaveProperty("accessConfigs");
    expect(insertBody).not.toHaveProperty("serviceAccounts");
    // The SA private key never leaves the Worker.
    expect(JSON.stringify(insertCall.body)).not.toContain("PRIVATE KEY");
  });

  it("gcp-instance-create: REJECTS a project that is not the SA key's own project — no token minted, no GCP call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob(); // targets project "dy-agency-proof"
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApi({ body: { name: "operation-should-not-happen", status: "PENDING" } });
    // A VALID key, but for a DIFFERENT project the agency's SA might also hold IAM in.
    const otherProjectKey = await makeServiceAccountKey("some-other-project");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: otherProjectKey }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instance-create");
    expect(body.detail).toMatch(/own project/);
    // The pin fires BEFORE minting a token or calling Compute — zero GCP fetches.
    expect(calls).toHaveLength(0);
  });

  it("gcp-instance-create: a 403 (missing compute permission) is a TERMINAL ok:false carrying Google's message, token not echoed", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApi({
      status: 403,
      body: {
        error: {
          code: 403,
          message: "Required 'compute.instances.create' permission for 'projects/dy-agency-proof/zones/australia-southeast1-a/instances/dy-dirb-proof-vm'",
          status: "PERMISSION_DENIED",
        },
      },
    });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; instanceName: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instance-create");
    expect(body.instanceName).toBe("dy-dirb-proof-vm");
    expect(body.detail).toMatch(/denied the instance create \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.instances.create' permission");
    expect(body.detail).toMatch(/roles\/compute\.instanceAdmin\.v1/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
  });

  it("gcp-instance-create: a 409 (name already exists) is ok:false — NOT an idempotent success like provision-r2", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApi({
      status: 409,
      body: { error: { code: 409, message: "The resource 'projects/dy-agency-proof/zones/australia-southeast1-a/instances/dy-dirb-proof-vm' already exists", status: "ALREADY_EXISTS" } },
    });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string; alreadyExisted?: boolean };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/already exists in dy-agency-proof\/australia-southeast1-a/);
    expect(body.detail).toMatch(/not idempotent/);
    // The DISCRIMINABLE already-existed signal a cell-level resume keys on (planning/34): a field,
    // so the orchestrator never has to match the detail string.
    expect(body.alreadyExisted).toBe(true);
  });

  it("gcp-instance-create: only a 409 carries alreadyExisted — a 403 denial does not", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApi({
      status: 403,
      body: { error: { code: 403, message: "Required 'compute.instances.create' permission", status: "PERMISSION_DENIED" } },
    });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    const body = (await response.json()) as { ok: boolean; alreadyExisted?: boolean };
    expect(body.ok).toBe(false);
    expect("alreadyExisted" in body).toBe(false);
  });

  it("gcp-instance-create: any other non-2xx (e.g. 404 no default network) is ok:false with Google's message", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApi({
      status: 404,
      body: { error: { code: 404, message: "The resource 'projects/dy-agency-proof/global/networks/default' was not found", status: "NOT_FOUND" } },
    });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/instance create failed with HTTP 404: The resource .*networks\/default' was not found/);
  });

  it("gcp-instance-create: a 2xx WITHOUT an operation is fail-closed ok:false (cannot confirm acceptance)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApi({ body: {} });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/HTTP 200 but no operation/);
  });

  it("gcp-instance-create: an already-DONE operation carrying errors is a failed create, not a success", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApi({
      body: { name: "operation-err", status: "DONE", error: { errors: [{ code: "QUOTA_EXCEEDED", message: "Quota 'CPUS' exceeded." }] } },
    });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/operation operation-err failed: Quota 'CPUS' exceeded/);
  });

  // ── gcp-instance-create: the bounded operation WAIT + the zone-exhaustion signal (planning/34) ──

  it("gcp-instance-create: WAITS on the insert operation and, when it completes DONE, reports status DONE", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-1234", status: "PENDING" } }, // insert ACCEPTED (async)
      { body: { name: "operation-1234", status: "DONE" } }, // operations.wait: finished cleanly
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-instance-create",
      instanceName: "dy-dirb-proof-vm",
      operationName: "operation-1234",
      status: "DONE",
    });
    const [insertCall, waitCall] = computeCalls(calls);
    expect(insertCall.method).toBe("POST");
    expect(insertCall.url).toBe(GCP_INSERT_URL);
    expect(waitCall.method).toBe("POST");
    expect(waitCall.url).toBe(`${GCP_PROJECT_URL}/zones/australia-southeast1-a/operations/operation-1234/wait`);
    expect(waitCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
  });

  it("gcp-instance-create: an insert operation that completes with ZONE_RESOURCE_POOL_EXHAUSTED is ok:false with the DISCRIMINABLE exhausted:true (never a detail-string match) — the zone-fallback signal", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([
      { body: { name: "operation-1234", status: "PENDING" } },
      {
        body: {
          name: "operation-1234",
          status: "DONE",
          error: { errors: [{ code: "ZONE_RESOURCE_POOL_EXHAUSTED", message: "The zone 'australia-southeast1-a' does not have enough resources available." }] },
        },
      },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; instanceName: string; detail: string; exhausted?: boolean; alreadyExisted?: boolean };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instance-create");
    expect(body.instanceName).toBe("dy-dirb-proof-vm");
    expect(body.exhausted).toBe(true);
    expect("alreadyExisted" in body).toBe(false);
    expect(body.detail).toMatch(/does not have enough resources/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
  });

  it("gcp-instance-create: an insert operation that completes with a NON-exhaustion error is ok:false WITHOUT exhausted (a genuine create failure, not a zone retry)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([
      { body: { name: "operation-1234", status: "PENDING" } },
      { body: { name: "operation-1234", status: "DONE", error: { errors: [{ code: "QUOTA_EXCEEDED", message: "Quota 'CPUS' exceeded." }] } } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string; exhausted?: boolean };
    expect(body.ok).toBe(false);
    expect("exhausted" in body).toBe(false);
    expect(body.detail).toMatch(/Quota 'CPUS' exceeded/);
  });

  it("gcp-instance-create: an insert operation STILL RUNNING after the bounded wait falls back to async ok:true (the documented residual — a late exhaustion is missed)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([
      { body: { name: "operation-1234", status: "PENDING" } }, // insert ACCEPTED
      { body: { name: "operation-1234", status: "RUNNING" } }, // wait: still not DONE within the bound
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-instance-create",
      instanceName: "dy-dirb-proof-vm",
      operationName: "operation-1234",
      status: "PENDING",
    });
  });

  it("gcp-instance-create: an already-DONE-at-insert ZONE_RESOURCE_POOL_EXHAUSTED is exhausted:true too (no separate wait needed)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([
      {
        body: {
          name: "operation-1234",
          status: "DONE",
          error: { errors: [{ code: "ZONE_RESOURCE_POOL_EXHAUSTED", message: "The zone does not have enough resources available." }] },
        },
      },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; exhausted?: boolean };
    expect(body.ok).toBe(false);
    expect(body.exhausted).toBe(true);
  });

  it("gcp-instance-create: a token-mint failure is ok:false and Compute is NEVER called", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      calls.push(urlOf(input));
      return jsonResponse({ error: "invalid_grant", error_description: "Invalid JWT Signature." }, 400);
    });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/could not mint a Google access token/);
    expect(body.detail).toContain("invalid_grant");
    // Only the token endpoint was contacted — no write was attempted without a token.
    expect(calls).toEqual(["https://oauth2.googleapis.com/token"]);
  });

  it("gcp-instance-create: reports a clean failure and touches NO API when GCP_SERVICE_ACCOUNT_KEY is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // Every OTHER agency credential is present — none may be used as a substitute.
    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/GCP_SERVICE_ACCOUNT_KEY is not configured/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gcp-instance-create: a malformed or incomplete SA key is ok:false with NO API call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    for (const badKey of ["{not json", "null", '"a string"']) {
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: badKey }));
      const body = (await response.json()) as { ok: boolean; detail: string };
      expect(body.ok).toBe(false);
      expect(body.detail).toMatch(/not valid JSON/);
    }
    // Valid JSON but not a service-account key (an OAuth client id has no private_key).
    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: JSON.stringify({ client_email: "sa@x.iam.gserviceaccount.com" }) }),
    );
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/missing client_email or private_key/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gcp-instance-create: a signed job with a path-traversal zone is 400 with NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob({
      params: JSON.stringify({ ...GCP_INSTANCE_PARAMS, zone: "australia-southeast1-a/../../projects/victim/zones/us-central1-a" }),
    });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/^zone must be/);
    // No token was minted and no write was attempted.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gcp-instance-create: a valid op given db-import's params is 400 with NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob({ params: JSON.stringify(DB_IMPORT_PARAMS) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    expect(response.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gcp-instance-create: with dataDiskGb attaches a SECOND non-boot pd-balanced data disk (autoDelete:false)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob({ params: JSON.stringify({ ...GCP_INSTANCE_PARAMS, dataDiskGb: 200 }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApi({ body: { name: "operation-1234", status: "PENDING", operationType: "insert" } });

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    expect(response.status).toBe(200);
    const resultBody = (await response.json()) as { ok: boolean };
    expect(resultBody.ok).toBe(true);

    const [, insertCall] = calls;
    // The boot disk is UNCHANGED and a second data disk is appended: boot:false, autoDelete:FALSE
    // (survives VM deletion), pd-balanced, sized to the validated dataDiskGb. The zone in the diskType
    // path is the same grammar-checked value as the machineType path.
    expect(insertCall.body).toEqual({
      name: "dy-dirb-proof-vm",
      machineType: "zones/australia-southeast1-a/machineTypes/e2-small",
      disks: [
        {
          boot: true,
          autoDelete: true,
          initializeParams: { sourceImage: "projects/debian-cloud/global/images/family/debian-12" },
        },
        {
          boot: false,
          autoDelete: false,
          initializeParams: {
            diskType: "zones/australia-southeast1-a/diskTypes/pd-balanced",
            diskSizeGb: 200,
          },
        },
      ],
      networkInterfaces: [{ network: "global/networks/default" }],
    });
    const insertBody = insertCall.body as { disks: Array<Record<string, unknown>> };
    expect(insertBody.disks).toHaveLength(2);
    expect(insertBody.disks[1].boot).toBe(false);
    expect(insertBody.disks[1].autoDelete).toBe(false);
  });

  it("gcp-instance-create: an out-of-range dataDiskGb is 400 with NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob({ params: JSON.stringify({ ...GCP_INSTANCE_PARAMS, dataDiskGb: 5 }) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }),
    );
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/^dataDiskGb/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── gcp-instance-create: the OPTIONAL networking fields through the registry ──────────
  // Backward compatibility is the load-bearing claim: with NONE of the new fields present the
  // instances.insert body is BYTE-identical to the pre-extension body (pinned as the exact JSON
  // string below). With them present, each adds exactly its own piece: the cell's own network +
  // subnet (project-relative paths derived from the validated names, the subnet's region from the
  // zone), a ONE_TO_ONE_NAT access config carrying the reserved IP, network tags, and the
  // startup-script metadata item — verbatim, as a JSON value, never in a URL.

  const PRE_EXTENSION_INSTANCE_BODY =
    '{"name":"dy-dirb-proof-vm","machineType":"zones/australia-southeast1-a/machineTypes/e2-small",' +
    '"disks":[{"boot":true,"autoDelete":true,"initializeParams":{"sourceImage":"projects/debian-cloud/global/images/family/debian-12"}}],' +
    '"networkInterfaces":[{"network":"global/networks/default"}]}';

  it("gcp-instance-create: with NO optional networking field the insert body is BYTE-identical to the pre-extension body", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-1234", status: "PENDING" } }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const [insertCall] = computeCalls(calls);
    expect(insertCall.rawBody).toBe(PRE_EXTENSION_INSTANCE_BODY);
  });

  it("gcp-instance-create: with every optional field present the body carries the cell's network/subnet, the reserved IP, tags and the startup script", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const startupScript = "#!/bin/sh\necho 'hello; $(whoami)' > \"/tmp/x y\"\n";
    const job = gcpInstanceCreateJob({
      params: JSON.stringify({
        ...GCP_INSTANCE_PARAMS,
        dataDiskGb: 200,
        network: "dy-cell-australia-southeast1",
        subnetwork: "dy-cell-australia-southeast1-subnet",
        tags: ["dy-gateway", "dy-cell-node"],
        externalIp: "35.244.66.16",
        startupScript,
      }),
    });
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-1234", status: "PENDING" } }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    expect(((await response.json()) as { ok: boolean }).ok).toBe(true);

    const [insertCall] = computeCalls(calls);
    expect(insertCall.url).toBe(GCP_INSERT_URL);
    expect(insertCall.body).toEqual({
      name: "dy-dirb-proof-vm",
      machineType: "zones/australia-southeast1-a/machineTypes/e2-small",
      disks: [
        { boot: true, autoDelete: true, initializeParams: { sourceImage: "projects/debian-cloud/global/images/family/debian-12" } },
        { boot: false, autoDelete: false, initializeParams: { diskType: "zones/australia-southeast1-a/diskTypes/pd-balanced", diskSizeGb: 200 } },
      ],
      networkInterfaces: [
        {
          // Project-relative paths built from the validated NAMES; the subnet's region derived from the zone.
          network: "global/networks/dy-cell-australia-southeast1",
          subnetwork: "regions/australia-southeast1/subnetworks/dy-cell-australia-southeast1-subnet",
          accessConfigs: [{ name: "External NAT", type: "ONE_TO_ONE_NAT", natIP: "35.244.66.16" }],
        },
      ],
      tags: { items: ["dy-gateway", "dy-cell-node"] },
      metadata: { items: [{ key: "startup-script", value: startupScript }] },
    });
    // The default network is NOT also present, and the script is verbatim (a JSON value, not a URL).
    expect(insertCall.rawBody).not.toContain("global/networks/default");
    expect(insertCall.url).not.toContain("startup");
  });

  it("gcp-instance-create: `subnetwork` alone attaches to the subnet with NO `network` key (Google infers it) and still NO external IP", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob({ params: JSON.stringify({ ...GCP_INSTANCE_PARAMS, subnetwork: "dy-subnet" }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-1234", status: "PENDING" } }]);

    await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const [insertCall] = computeCalls(calls);
    const insertBody = insertCall.body as { networkInterfaces: Array<Record<string, unknown>>; tags?: unknown; metadata?: unknown };
    expect(insertBody.networkInterfaces).toEqual([{ subnetwork: "regions/australia-southeast1/subnetworks/dy-subnet" }]);
    expect(insertBody.networkInterfaces[0]).not.toHaveProperty("accessConfigs");
    expect(insertBody).not.toHaveProperty("tags");
    expect(insertBody).not.toHaveProperty("metadata");
  });

  it("gcp-instance-create: `externalIp` alone keeps the default network and adds ONLY the ONE_TO_ONE_NAT access config", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob({ params: JSON.stringify({ ...GCP_INSTANCE_PARAMS, externalIp: "35.244.66.16" }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-1234", status: "PENDING" } }]);

    await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const [insertCall] = computeCalls(calls);
    const insertBody = insertCall.body as { networkInterfaces: Array<Record<string, unknown>>; tags?: unknown; metadata?: unknown };
    expect(insertBody.networkInterfaces).toEqual([
      { network: "global/networks/default", accessConfigs: [{ name: "External NAT", type: "ONE_TO_ONE_NAT", natIP: "35.244.66.16" }] },
    ]);
    expect(insertBody).not.toHaveProperty("tags");
    expect(insertBody).not.toHaveProperty("metadata");
  });

  it("gcp-instance-create: `tags` alone adds ONLY tags.items; the interface stays the private default", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceCreateJob({ params: JSON.stringify({ ...GCP_INSTANCE_PARAMS, tags: ["dy-web"] }) });
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-1234", status: "PENDING" } }]);

    await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const [insertCall] = computeCalls(calls);
    const insertBody = insertCall.body as { networkInterfaces: unknown; tags?: unknown; metadata?: unknown };
    expect(insertBody.networkInterfaces).toEqual([{ network: "global/networks/default" }]);
    expect(insertBody.tags).toEqual({ items: ["dy-web"] });
    expect(insertBody).not.toHaveProperty("metadata");
  });

  it("gcp-instance-create: a URL-shaped or other-project `network` is 400 with NO Google call (bare names only)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    for (const network of ["projects/victim/global/networks/vpc", "https://www.googleapis.com/compute/v1/projects/victim/global/networks/vpc", "global/networks/default"]) {
      const job = gcpInstanceCreateJob({ params: JSON.stringify({ ...GCP_INSTANCE_PARAMS, network }) });
      const signature = await signAsApp(job, privateKey);
      const fetchSpy = vi.spyOn(globalThis, "fetch");

      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
      expect(response.status).toBe(400);
      const body = (await response.json()) as { reason: string };
      expect(body.reason).toMatch(/^network, when present/);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });

  // ── gcp-network-create through the registry ──────────────────────────────────────────
  // The cell's VPC: networks.insert (custom mode) -> WAIT for its operation -> subnetworks.insert
  // -> WAIT for its operation. Load-bearing: the FULL-scope token from the agency's own SA key goes
  // ONLY into Compute Authorization headers; the URLs are built from the grammar-checked project +
  // region; both bodies hold exactly the validated fields; a 409 alreadyExists on either insert is
  // an idempotent SUCCESS (with no wait — nothing to wait on); any other failure stops the sequence
  // (a network failure means NO subnet insert); the project pin fires with ZERO fetches.

  it("gcp-network-create: creates the custom-mode VPC, WAITS for it, creates the regional subnet, WAITS for it — agency SA only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-net", status: "RUNNING", operationType: "insert" } }, // networks.insert
      { body: { name: "operation-net", status: "DONE" } }, // globalOperations.wait
      { body: { name: "operation-subnet", status: "RUNNING", operationType: "insert" } }, // subnetworks.insert
      { body: { name: "operation-subnet", status: "DONE" } }, // regionOperations.wait
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const resultBody = await response.json();
    expect(resultBody).toEqual({
      ok: true,
      op: "gcp-network-create",
      networkName: "dy-cell-australia-southeast1",
      networkStatus: "created",
      subnetName: "dy-cell-australia-southeast1-subnet",
      subnetStatus: "created",
    });
    expect(JSON.stringify(resultBody)).not.toContain(GCP_ACCESS_TOKEN);

    // The token mint asks for the FULL scope with the agency's SA identity.
    expect(calls).toHaveLength(5);
    const [tokenCall] = calls;
    expect(tokenCall.url).toBe("https://oauth2.googleapis.com/token");
    const claims = jwtClaimsOf(tokenCall.form?.get("assertion") ?? "");
    expect(claims.scope).toBe(GOOGLE_SCOPE_CLOUD_PLATFORM);
    expect(claims.iss).toBe("sa@dy-agency-proof.iam.gserviceaccount.com");

    const [networkInsert, networkWait, subnetInsert, subnetWait] = computeCalls(calls);
    for (const call of [networkInsert, networkWait, subnetInsert, subnetWait]) {
      expect(call.method).toBe("POST");
      expect(call.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    }
    expect(networkInsert.url).toBe(`${GCP_PROJECT_URL}/global/networks`);
    expect(networkInsert.body).toEqual({ name: "dy-cell-australia-southeast1", autoCreateSubnetworks: false });
    expect(networkWait.url).toBe(`${GCP_PROJECT_URL}/global/operations/operation-net/wait`);
    expect(subnetInsert.url).toBe(`${GCP_REGION_URL}/subnetworks`);
    expect(subnetInsert.body).toEqual({
      name: "dy-cell-australia-southeast1-subnet",
      network: "global/networks/dy-cell-australia-southeast1",
      ipCidrRange: "10.20.0.0/24",
      region: "regions/australia-southeast1",
    });
    expect(subnetWait.url).toBe(`${GCP_REGION_URL}/operations/operation-subnet/wait`);
    // The SA private key never leaves the Worker.
    expect(JSON.stringify(calls.map((call) => call.body))).not.toContain("PRIVATE KEY");
  });

  it("gcp-network-create: a re-run where BOTH already exist (409 + 409) is ok:true already-existed, with NO wait calls", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      alreadyExists409("projects/dy-agency-proof/global/networks/dy-cell-australia-southeast1"),
      alreadyExists409("projects/dy-agency-proof/regions/australia-southeast1/subnetworks/dy-cell-australia-southeast1-subnet"),
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-network-create",
      networkName: "dy-cell-australia-southeast1",
      networkStatus: "already-existed",
      subnetName: "dy-cell-australia-southeast1-subnet",
      subnetStatus: "already-existed",
    });
    // Exactly the two inserts — no operation to wait on.
    expect(computeCalls(calls).map((call) => call.url)).toEqual([`${GCP_PROJECT_URL}/global/networks`, `${GCP_REGION_URL}/subnetworks`]);
  });

  it("gcp-network-create: network already exists but the subnet is new => waits ONLY for the subnet (resume of a half-built cell)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      alreadyExists409("projects/dy-agency-proof/global/networks/dy-cell-australia-southeast1"),
      { body: { name: "operation-subnet", status: "RUNNING" } },
      { body: { name: "operation-subnet", status: "DONE" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; networkStatus: string; subnetStatus: string };
    expect(body.ok).toBe(true);
    expect(body.networkStatus).toBe("already-existed");
    expect(body.subnetStatus).toBe("created");
    expect(computeCalls(calls).map((call) => call.url)).toEqual([
      `${GCP_PROJECT_URL}/global/networks`,
      `${GCP_REGION_URL}/subnetworks`,
      `${GCP_REGION_URL}/operations/operation-subnet/wait`,
    ]);
  });

  it("gcp-network-create: a 403 on the network insert is a TERMINAL ok:false with Google's message and NO subnet insert", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([denied403("compute.networks.create")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; networkName: string; subnetName: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-network-create");
    expect(body.networkName).toBe("dy-cell-australia-southeast1");
    expect(body.subnetName).toBe("dy-cell-australia-southeast1-subnet");
    expect(body.detail).toMatch(/denied the network "dy-cell-australia-southeast1" create \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.networks.create' permission");
    expect(body.detail).toMatch(/roles\/compute\.networkAdmin/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-network-create: a network operation that finishes with errors is ok:false and NO subnet insert follows", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-net", status: "RUNNING" } },
      { body: { name: "operation-net", status: "DONE", error: { errors: [{ code: "QUOTA_EXCEEDED", message: "Quota 'NETWORKS' exceeded." }] } } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/network "dy-cell-australia-southeast1" create operation failed: Quota 'NETWORKS' exceeded/);
    expect(computeCalls(calls)).toHaveLength(2);
  });

  it("gcp-network-create: an operation still RUNNING after every bounded wait is ok:false (re-run resumes), NO subnet insert", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-net", status: "RUNNING" } },
      { body: { name: "operation-net", status: "RUNNING" } },
      { body: { name: "operation-net", status: "RUNNING" } },
      { body: { name: "operation-net", status: "RUNNING" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/still not DONE after 3 waits/);
    // 1 insert + exactly 3 waits, then it stopped.
    const urls = computeCalls(calls).map((call) => call.url);
    expect(urls).toHaveLength(4);
    expect(urls.filter((url) => url.endsWith("/operations/operation-net/wait"))).toHaveLength(3);
  });

  it("gcp-network-create: a subnet insert rejected by Google (e.g. resourceNotReady / bad range) is ok:false with Google's message", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([
      alreadyExists409("projects/dy-agency-proof/global/networks/dy-cell-australia-southeast1"),
      { status: 400, body: { error: { code: 400, message: "The resource 'projects/dy-agency-proof/global/networks/dy-cell-australia-southeast1' is not ready", errors: [{ reason: "resourceNotReady" }] } } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/subnetwork "dy-cell-australia-southeast1-subnet" create failed with HTTP 400: .*is not ready/);
  });

  it("gcp-network-create: a 409 whose reason is NOT alreadyExists is a failure, not an idempotent success", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { status: 409, body: { error: { code: 409, message: "Operation in progress", errors: [{ reason: "resourceInUseByAnotherResource" }] } } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/create failed with HTTP 409: Operation in progress/);
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-network-create: REJECTS a project that is not the SA key's own project — no token minted, ZERO GCP calls", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-should-not-happen", status: "RUNNING" } }]);
    const otherProjectKey = await makeServiceAccountKey("some-other-project");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: otherProjectKey }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-network-create");
    expect(body.detail).toMatch(/does not match the service-account key's own project \("some-other-project"\)/);
    expect(body.detail).toMatch(/own project/);
    expect(calls).toHaveLength(0);
  });

  it("gcp-network-create: a public ipCidr is 400 with NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob({ params: JSON.stringify({ ...GCP_NETWORK_PARAMS, ipCidr: "8.8.8.0/24" }) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/^ipCidr must be a private/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gcp-network-create: reports a clean failure and touches NO API when GCP_SERVICE_ACCOUNT_KEY is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkCreateJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    // Every OTHER agency credential is present — none may be used as a substitute.
    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/GCP_SERVICE_ACCOUNT_KEY is not configured/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── gcp-firewall-create through the registry ─────────────────────────────────────────

  it("gcp-firewall-create: POSTs ONE INGRESS rule with the validated allowed/sources/tags (protocol -> IPProtocol), agency SA only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallCreateJob({
      params: JSON.stringify({
        ...GCP_FIREWALL_PARAMS,
        allowed: [{ protocol: "tcp", ports: ["22", "8000-8080"] }, { protocol: "icmp" }],
        sourceRanges: ["0.0.0.0/0", "10.20.0.0/24"],
        targetTags: ["dy-gateway", "dy-web"],
      }),
    });
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-fw", status: "RUNNING", operationType: "insert" } }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const resultBody = await response.json();
    expect(resultBody).toEqual({ ok: true, op: "gcp-firewall-create", ruleName: "dy-cell-allow-gateway-ssh", status: "created" });
    expect(JSON.stringify(resultBody)).not.toContain(GCP_ACCESS_TOKEN);

    const [tokenCall] = calls;
    expect(jwtClaimsOf(tokenCall.form?.get("assertion") ?? "").scope).toBe(GOOGLE_SCOPE_CLOUD_PLATFORM);
    const [insertCall] = computeCalls(calls);
    expect(insertCall.method).toBe("POST");
    expect(insertCall.url).toBe(`${GCP_PROJECT_URL}/global/firewalls`);
    expect(insertCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(insertCall.body).toEqual({
      name: "dy-cell-allow-gateway-ssh",
      network: "global/networks/dy-cell-australia-southeast1",
      direction: "INGRESS",
      allowed: [{ IPProtocol: "tcp", ports: ["22", "8000-8080"] }, { IPProtocol: "icmp" }],
      sourceRanges: ["0.0.0.0/0", "10.20.0.0/24"],
      targetTags: ["dy-gateway", "dy-web"],
    });
    // icmp carries NO ports key at all, and nothing else rides along.
    const allowed = (insertCall.body as { allowed: Array<Record<string, unknown>> }).allowed;
    expect(allowed[1]).not.toHaveProperty("ports");
    expect(insertCall.body).not.toHaveProperty("denied");
    expect(insertCall.body).not.toHaveProperty("sourceTags");
  });

  it("gcp-firewall-create: the allow-all internal rule maps protocol \"all\" to IPProtocol \"all\"", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallCreateJob({
      params: JSON.stringify({
        ...GCP_FIREWALL_PARAMS,
        ruleName: "dy-cell-allow-internal",
        allowed: [{ protocol: "all" }],
        sourceRanges: ["10.20.0.0/24"],
        targetTags: ["dy-cell-node"],
      }),
    });
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-fw", status: "RUNNING" } }]);

    await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const [insertCall] = computeCalls(calls);
    expect((insertCall.body as { allowed: unknown }).allowed).toEqual([{ IPProtocol: "all" }]);
    expect((insertCall.body as { sourceRanges: unknown }).sourceRanges).toEqual(["10.20.0.0/24"]);
  });

  it("gcp-firewall-create: a 409 (rule already exists) is ok:true already-existed — idempotent by name", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([alreadyExists409("projects/dy-agency-proof/global/firewalls/dy-cell-allow-gateway-ssh")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({ ok: true, op: "gcp-firewall-create", ruleName: "dy-cell-allow-gateway-ssh", status: "already-existed" });
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-firewall-create: a 403 is a TERMINAL ok:false naming the permission, token not echoed", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([denied403("compute.firewalls.create")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; ruleName: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-firewall-create");
    expect(body.ruleName).toBe("dy-cell-allow-gateway-ssh");
    expect(body.detail).toMatch(/denied the firewall rule "dy-cell-allow-gateway-ssh" create \(HTTP 403\)/);
    expect(body.detail).toMatch(/roles\/compute\.securityAdmin/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
  });

  it("gcp-firewall-create: REJECTS a project that is not the SA key's own project — ZERO GCP calls", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-should-not-happen", status: "RUNNING" } }]);
    const otherProjectKey = await makeServiceAccountKey("some-other-project");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: otherProjectKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-firewall-create");
    expect(body.detail).toMatch(/own project/);
    expect(calls).toHaveLength(0);
  });

  it("gcp-firewall-create: ports on icmp (or an empty targetTags) is 400 with NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    for (const [overrides, expected] of [
      [{ allowed: [{ protocol: "icmp", ports: ["22"] }] }, /ports apply to tcp\/udp only/],
      [{ targetTags: [] }, /^targetTags must be an array of 1-256/],
    ] as Array<[Record<string, unknown>, RegExp]>) {
      const job = gcpFirewallCreateJob({ params: JSON.stringify({ ...GCP_FIREWALL_PARAMS, ...overrides }) });
      const signature = await signAsApp(job, privateKey);
      const fetchSpy = vi.spyOn(globalThis, "fetch");

      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
      expect(response.status).toBe(400);
      const body = (await response.json()) as { reason: string };
      expect(body.reason).toMatch(expected);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });

  // ── gcp-address-create through the registry ──────────────────────────────────────────
  // addresses.insert (EXTERNAL, regional) then addresses.get to read the reserved IP back.

  it("gcp-address-create: reserves an EXTERNAL regional address, reads it back, and returns the IP — agency SA only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpAddressCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-addr", status: "RUNNING", operationType: "insert" } }, // addresses.insert
      { body: { name: "dy-cell-gateway-ip", address: "35.244.66.16", status: "RESERVED", addressType: "EXTERNAL" } }, // addresses.get
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const resultBody = await response.json();
    expect(resultBody).toEqual({
      ok: true,
      op: "gcp-address-create",
      addressName: "dy-cell-gateway-ip",
      address: "35.244.66.16",
      status: "created",
    });
    expect(JSON.stringify(resultBody)).not.toContain(GCP_ACCESS_TOKEN);

    const [tokenCall] = calls;
    expect(jwtClaimsOf(tokenCall.form?.get("assertion") ?? "").scope).toBe(GOOGLE_SCOPE_CLOUD_PLATFORM);
    const [insertCall, getCall] = computeCalls(calls);
    expect(insertCall.method).toBe("POST");
    expect(insertCall.url).toBe(`${GCP_REGION_URL}/addresses`);
    expect(insertCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(insertCall.body).toEqual({ name: "dy-cell-gateway-ip", addressType: "EXTERNAL" });
    expect(getCall.method).toBe("GET");
    expect(getCall.url).toBe(`${GCP_REGION_URL}/addresses/dy-cell-gateway-ip`);
    expect(getCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(getCall.body).toBeUndefined();
  });

  it("gcp-address-create: a 409 (already reserved) reads the EXISTING reservation back — ok:true already-existed with its IP", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpAddressCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      alreadyExists409("projects/dy-agency-proof/regions/australia-southeast1/addresses/dy-cell-gateway-ip"),
      { body: { name: "dy-cell-gateway-ip", address: "35.244.66.16", status: "IN_USE" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-address-create",
      addressName: "dy-cell-gateway-ip",
      address: "35.244.66.16",
      status: "already-existed",
    });
    expect(computeCalls(calls).map((call) => call.method)).toEqual(["POST", "GET"]);
  });

  it("gcp-address-create: an IP not yet assigned (RESERVING without `address`, or a 404 before it is visible) is ok:true with address null", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    for (const getReply of [
      { body: { name: "dy-cell-gateway-ip", status: "RESERVING" } },
      { status: 404, body: { error: { code: 404, message: "The resource 'projects/dy-agency-proof/regions/australia-southeast1/addresses/dy-cell-gateway-ip' was not found" } } },
    ]) {
      const job = gcpAddressCreateJob();
      const signature = await signAsApp(job, privateKey);
      mockGcpApiQueue([{ body: { name: "operation-addr", status: "RUNNING" } }, getReply]);

      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
      expect(await response.json()).toEqual({
        ok: true,
        op: "gcp-address-create",
        addressName: "dy-cell-gateway-ip",
        address: null,
        status: "created",
      });
      vi.restoreAllMocks();
    }
  });

  it("gcp-address-create: a read-back failure other than not-yet-visible (e.g. 403 on get) is ok:false — the reservation stands, a re-run re-reads", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpAddressCreateJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([{ body: { name: "operation-addr", status: "RUNNING" } }, denied403("compute.addresses.get")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; addressName: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.addressName).toBe("dy-cell-gateway-ip");
    expect(body.detail).toMatch(/was reserved but reading it back failed with HTTP 403/);
    expect(body.detail).toContain("Required 'compute.addresses.get' permission");
  });

  it("gcp-address-create: a 403 on the insert is a TERMINAL ok:false and NO read-back follows", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpAddressCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([denied403("compute.addresses.create")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-address-create");
    expect(body.detail).toMatch(/denied the address "dy-cell-gateway-ip" create \(HTTP 403\)/);
    expect(body.detail).toMatch(/roles\/compute\.networkAdmin/);
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-address-create: REJECTS a project that is not the SA key's own project — ZERO GCP calls", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpAddressCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-should-not-happen", status: "RUNNING" } }]);
    const otherProjectKey = await makeServiceAccountKey("some-other-project");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: otherProjectKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-address-create");
    expect(body.detail).toMatch(/own project/);
    expect(calls).toHaveLength(0);
  });

  it("gcp-address-create: a zone in place of the region is 400 with NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpAddressCreateJob({ params: JSON.stringify({ ...GCP_ADDRESS_PARAMS, region: "australia-southeast1-a" }) });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(400);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toMatch(/^region must be/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── gcp-router-nat-create through the registry ───────────────────────────────────────
  // routers.insert (ONE router with the NAT inline) -> WAIT for its regional operation. The NAT is the
  // private VMs' only egress, so "created" must mean it EXISTS (the same wait contract as the network).

  it("gcp-router-nat-create: POSTs ONE regional router carrying the inline NAT (AUTO_ONLY, all subnets), WAITS for it — agency SA only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterNatCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-router", status: "RUNNING", operationType: "insert" } }, // routers.insert
      { body: { name: "operation-router", status: "DONE" } }, // regionOperations.wait
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const resultBody = await response.json();
    expect(resultBody).toEqual({
      ok: true,
      op: "gcp-router-nat-create",
      routerName: "dy-cell-australia-southeast1-router",
      natName: "dy-cell-australia-southeast1-nat",
      status: "created",
    });
    expect(JSON.stringify(resultBody)).not.toContain(GCP_ACCESS_TOKEN);

    const [tokenCall] = calls;
    expect(jwtClaimsOf(tokenCall.form?.get("assertion") ?? "").scope).toBe(GOOGLE_SCOPE_CLOUD_PLATFORM);
    const [insertCall, waitCall] = computeCalls(calls);
    expect(insertCall.method).toBe("POST");
    expect(insertCall.url).toBe(`${GCP_REGION_URL}/routers`);
    expect(insertCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(insertCall.body).toEqual({
      name: "dy-cell-australia-southeast1-router",
      network: "global/networks/dy-cell-australia-southeast1",
      nats: [
        {
          name: "dy-cell-australia-southeast1-nat",
          sourceSubnetworkIpRangesToNat: "ALL_SUBNETWORKS_ALL_IP_RANGES",
          natIpAllocateOption: "AUTO_ONLY",
        },
      ],
    });
    expect(waitCall.method).toBe("POST");
    expect(waitCall.url).toBe(`${GCP_REGION_URL}/operations/operation-router/wait`);
    expect(waitCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(JSON.stringify(calls.map((call) => call.body))).not.toContain("PRIVATE KEY");
  });

  it("gcp-router-nat-create: a 409 (router already exists) is ok:true already-existed with NO wait call — idempotent by name", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterNatCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([alreadyExists409("projects/dy-agency-proof/regions/australia-southeast1/routers/dy-cell-australia-southeast1-router")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-router-nat-create",
      routerName: "dy-cell-australia-southeast1-router",
      natName: "dy-cell-australia-southeast1-nat",
      status: "already-existed",
    });
    expect(computeCalls(calls).map((call) => call.url)).toEqual([`${GCP_REGION_URL}/routers`]);
  });

  it("gcp-router-nat-create: a router operation that finishes with errors is ok:false carrying Google's message", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterNatCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-router", status: "RUNNING" } },
      { body: { name: "operation-router", status: "DONE", error: { errors: [{ code: "QUOTA_EXCEEDED", message: "Quota 'ROUTERS' exceeded." }] } } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; routerName: string; natName: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-router-nat-create");
    expect(body.routerName).toBe("dy-cell-australia-southeast1-router");
    expect(body.natName).toBe("dy-cell-australia-southeast1-nat");
    expect(body.detail).toMatch(/router "dy-cell-australia-southeast1-router" create operation failed: Quota 'ROUTERS' exceeded/);
    expect(computeCalls(calls)).toHaveLength(2);
  });

  it("gcp-router-nat-create: a 403 on the insert is a TERMINAL ok:false naming the permission, token not echoed, NO wait", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterNatCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([denied403("compute.routers.create")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-router-nat-create");
    expect(body.detail).toMatch(/denied the router "dy-cell-australia-southeast1-router" create \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.routers.create' permission");
    expect(body.detail).toMatch(/roles\/compute\.networkAdmin/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-router-nat-create: REJECTS a project that is not the SA key's own project — no token minted, ZERO GCP calls", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterNatCreateJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "operation-should-not-happen", status: "RUNNING" } }]);
    const otherProjectKey = await makeServiceAccountKey("some-other-project");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: otherProjectKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-router-nat-create");
    expect(body.detail).toMatch(/does not match the service-account key's own project \("some-other-project"\)/);
    expect(calls).toHaveLength(0);
  });

  it("gcp-router-nat-create: a zone in place of the region (or a URL as networkName) is 400 with NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    for (const [overrides, expected] of [
      [{ region: "australia-southeast1-a" }, /^region must be/],
      [{ networkName: "global/networks/dy-cell-australia-southeast1" }, /^networkName must be/],
    ] as Array<[Record<string, unknown>, RegExp]>) {
      const job = gcpRouterNatCreateJob({ params: JSON.stringify({ ...GCP_ROUTER_NAT_PARAMS, ...overrides }) });
      const signature = await signAsApp(job, privateKey);
      const fetchSpy = vi.spyOn(globalThis, "fetch");

      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
      expect(response.status).toBe(400);
      const body = (await response.json()) as { reason: string };
      expect(body.reason).toMatch(expected);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });

  it("gcp-router-nat-create: reports a clean failure and touches NO API when GCP_SERVICE_ACCOUNT_KEY is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterNatCreateJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/GCP_SERVICE_ACCOUNT_KEY is not configured/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── gcp-firewall-get through the registry ────────────────────────────────────────────
  // firewalls.get (GLOBAL) — resume verification: confirm a cell rule is really present (finding 1).

  it("gcp-firewall-get: GETs the GLOBAL firewall rule and reports found:true — agency SA only, read-only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallGetJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: { name: "dy-cell-australia-southeast1-gw-ssh", network: "x" } }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const resultBody = await response.json();
    expect(resultBody).toEqual({ ok: true, op: "gcp-firewall-get", ruleName: "dy-cell-australia-southeast1-gw-ssh", found: true });
    expect(JSON.stringify(resultBody)).not.toContain(GCP_ACCESS_TOKEN);

    const [getCall] = computeCalls(calls);
    expect(getCall.method).toBe("GET");
    expect(getCall.url).toBe(`${GCP_PROJECT_URL}/global/firewalls/dy-cell-australia-southeast1-gw-ssh`);
    expect(getCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(getCall.body).toBeUndefined();
  });

  it("gcp-firewall-get: a 404 is a clean found:false (NOT a failure)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallGetJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([{ status: 404, body: { error: { code: 404, message: "not found" } } }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-firewall-get",
      ruleName: "dy-cell-australia-southeast1-gw-ssh",
      found: false,
    });
  });

  it("gcp-firewall-get: a 403 is ok:false naming the read permission, token not echoed", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallGetJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([denied403("compute.firewalls.get")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-firewall-get");
    expect(body.detail).toMatch(/denied reading firewall rule "dy-cell-australia-southeast1-gw-ssh" \(HTTP 403\)/);
    expect(body.detail).toMatch(/compute\.firewalls\.get/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
  });

  // ── gcp-router-get through the registry ──────────────────────────────────────────────
  // routers.get (REGIONAL) — resume verification: confirm the router AND its NAT are present.

  it("gcp-router-get: GETs the REGIONAL router and reports found:true with its NAT config names", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterGetJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "dy-cell-australia-southeast1-router", nats: [{ name: "dy-cell-australia-southeast1-nat" }] } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-router-get",
      routerName: "dy-cell-australia-southeast1-router",
      found: true,
      natNames: ["dy-cell-australia-southeast1-nat"],
    });

    const [getCall] = computeCalls(calls);
    expect(getCall.method).toBe("GET");
    expect(getCall.url).toBe(`${GCP_REGION_URL}/routers/dy-cell-australia-southeast1-router`);
    expect(getCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
  });

  it("gcp-router-get: a router present WITHOUT any NAT config reports found:true, natNames [] (the no-egress case)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterGetJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([{ body: { name: "dy-cell-australia-southeast1-router" } }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-router-get",
      routerName: "dy-cell-australia-southeast1-router",
      found: true,
      natNames: [],
    });
  });

  it("gcp-router-get: a 404 is a clean found:false with natNames [] (NOT a failure)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterGetJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([{ status: 404, body: { error: { code: 404, message: "not found" } } }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-router-get",
      routerName: "dy-cell-australia-southeast1-router",
      found: false,
      natNames: [],
    });
  });

  it("gcp-router-get: a 403 is ok:false naming the read permission, token not echoed", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterGetJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([denied403("compute.routers.get")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-router-get");
    expect(body.detail).toMatch(/denied reading router "dy-cell-australia-southeast1-router" \(HTTP 403\)/);
    expect(body.detail).toMatch(/compute\.routers\.get/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
  });

  // ── gcp-instances-list through the registry ──────────────────────────────────────────
  // instances.aggregatedList (spans ALL zones) — resume zone discovery (planning/34 zone fallback).

  it("gcp-instances-list: aggregatedList returns each matching instance's name + SHORT zone (parsed from the zone URL), across zones — agency SA only, read-only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstancesListJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      {
        body: {
          items: {
            "zones/australia-southeast1-b": {
              instances: [
                { name: "dy-web-australia-southeast1-1", zone: "https://www.googleapis.com/compute/v1/projects/dy-agency-proof/zones/australia-southeast1-b" },
                { name: "dy-file-australia-southeast1-1", zone: "https://www.googleapis.com/compute/v1/projects/dy-agency-proof/zones/australia-southeast1-b" },
              ],
            },
            // a scope with no instances (Google's NO_RESULTS_ON_PAGE warning) is skipped cleanly.
            "zones/australia-southeast1-a": { warning: { code: "NO_RESULTS_ON_PAGE" } },
          },
        },
      },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-instances-list",
      instances: [
        { name: "dy-web-australia-southeast1-1", zone: "australia-southeast1-b" },
        { name: "dy-file-australia-southeast1-1", zone: "australia-southeast1-b" },
      ],
    });
    const [listCall] = computeCalls(calls);
    expect(listCall.method).toBe("GET");
    expect(listCall.url.startsWith(`${GCP_PROJECT_URL}/aggregated/instances?`)).toBe(true);
    expect(listCall.url).toContain("filter=");
    expect(listCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
  });

  it("gcp-instances-list: no matching instances is ok:true with instances [] (a clean 'none' — the fresh-cell case)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstancesListJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([{ body: { items: { "zones/australia-southeast1-a": { warning: { code: "NO_RESULTS_ON_PAGE" } } } } }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({ ok: true, op: "gcp-instances-list", instances: [] });
  });

  it("gcp-instances-list: instances in DIFFERENT zones are each returned with their own zone (so the caller can detect a corrupt multi-zone cell)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstancesListJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([
      {
        body: {
          items: {
            "zones/australia-southeast1-a": { instances: [{ name: "dy-web-australia-southeast1-1", zone: "zones/australia-southeast1-a" }] },
            "zones/australia-southeast1-b": { instances: [{ name: "dy-data-australia-southeast1-1", zone: "zones/australia-southeast1-b" }] },
          },
        },
      },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-instances-list",
      instances: [
        { name: "dy-web-australia-southeast1-1", zone: "australia-southeast1-a" },
        { name: "dy-data-australia-southeast1-1", zone: "australia-southeast1-b" },
      ],
    });
  });

  it("gcp-instances-list: follows nextPageToken across pages and returns the UNION (a truncated read would risk a duplicate VM)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstancesListJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { items: { "zones/australia-southeast1-a": { instances: [{ name: "dy-web-australia-southeast1-1", zone: "zones/australia-southeast1-a" }] } }, nextPageToken: "PAGE2" } },
      { body: { items: { "zones/australia-southeast1-a": { instances: [{ name: "dy-data-australia-southeast1-1", zone: "zones/australia-southeast1-a" }] } } } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-instances-list",
      instances: [
        { name: "dy-web-australia-southeast1-1", zone: "australia-southeast1-a" },
        { name: "dy-data-australia-southeast1-1", zone: "australia-southeast1-a" },
      ],
    });
    const listCalls = computeCalls(calls);
    expect(listCalls).toHaveLength(2);
    expect(listCalls[1]!.url).toContain("pageToken=PAGE2");
  });

  it("gcp-instances-list: a 403 is ok:false naming the read permission, token not echoed", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstancesListJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([denied403("compute.instances.list")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instances-list");
    expect(body.detail).toMatch(/denied listing instances \(HTTP 403\)/);
    expect(body.detail).toMatch(/compute\.instances\.list/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
  });

  it("gcp-instances-list: a 200 PARTIAL success (unreachables) FAILS CLOSED — never reported as a complete 'none' (a missed zone would duplicate a VM)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstancesListJob();
    const signature = await signAsApp(job, privateKey);
    // Zone -a is reachable and empty; zone -b could NOT be read (its instances are OMITTED) but the
    // call still returns HTTP 200 with `unreachables`. If this were treated as complete, discovery
    // would say "none" and the orchestrator would create a duplicate VM in a fresh zone.
    mockGcpApiQueue([
      {
        body: {
          items: { "zones/australia-southeast1-a": { instances: [] } },
          unreachables: ["zones/australia-southeast1-b"],
        },
      },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instances-list");
    expect(body.detail).toMatch(/unreachable/);
    expect(body.detail).toMatch(/australia-southeast1-b/);
    expect(body.detail).toMatch(/re-run to resume/);
  });

  it("the three cell-infra GET ops REJECT a project that is not the SA key's own project — ZERO GCP calls", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const otherProjectKey = await makeServiceAccountKey("some-other-project");
    for (const job of [gcpFirewallGetJob(), gcpRouterGetJob(), gcpInstancesListJob()]) {
      const signature = await signAsApp(job, privateKey);
      const calls = mockGcpApiQueue([{ body: { name: "should-not-happen" } }]);
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: otherProjectKey }));
      const body = (await response.json()) as { ok: boolean; detail: string };
      expect(body.ok).toBe(false);
      expect(body.detail).toMatch(/own project/);
      expect(calls).toHaveLength(0);
      vi.restoreAllMocks();
    }
  });

  it("the four cell-infra ops given another op's params are 400 with NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const jobs = [
      gcpNetworkCreateJob({ params: JSON.stringify(GCP_INSTANCE_PARAMS) }),
      gcpFirewallCreateJob({ params: JSON.stringify(GCP_NETWORK_PARAMS) }),
      gcpAddressCreateJob({ params: JSON.stringify(GCP_FIREWALL_PARAMS) }),
      gcpRouterNatCreateJob({ params: JSON.stringify(GCP_ADDRESS_PARAMS) }),
    ];
    for (const job of jobs) {
      const signature = await signAsApp(job, privateKey);
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
      expect(response.status).toBe(400);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });

  // ── the five teardown (delete) ops through the registry ──────────────────────────────
  // The mirror of the create ops: each DELETEs one Compute resource with the agency's OWN SA token
  // and WAITS for the operation, so "deleted" means GONE (a later step fails with resourceInUse
  // otherwise). Load-bearing assertions: a 404 is the idempotent "already-absent" SUCCESS with
  // nothing to wait on; a 401/403 names the delete permission; gcp-instance-delete reports an
  // unconfirmed operation with the DISCRIMINABLE `stillRunning: true` (never a detail-string match);
  // and gcp-network-delete removes the SUBNET first and only then the network.

  const GCP_ZONE_URL = `${GCP_PROJECT_URL}/zones/australia-southeast1-a`;
  /** Google's 404 for a delete of a resource that is not there — the idempotent teardown success. */
  function notFound404(resource: string) {
    const message = `The resource '${resource}' was not found`;
    return { status: 404, body: { error: { code: 404, message, errors: [{ reason: "notFound", message }] } } };
  }

  it("gcp-instance-delete: DELETEs the ZONAL VM and WAITS for its operation — ok:true deleted, agency SA only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-del-web", status: "RUNNING", operationType: "delete" } }, // instances.delete
      { body: { name: "operation-del-web", status: "DONE" } }, // zoneOperations.wait
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const resultBody = await response.json();
    expect(resultBody).toEqual({
      ok: true,
      op: "gcp-instance-delete",
      instanceName: "dy-web-australia-southeast1-1",
      status: "deleted",
      operationName: "operation-del-web",
    });
    expect(JSON.stringify(resultBody)).not.toContain(GCP_ACCESS_TOKEN);

    // The token mint asks for the FULL scope with the agency's SA identity.
    const [tokenCall] = calls;
    expect(tokenCall.url).toBe("https://oauth2.googleapis.com/token");
    expect(jwtClaimsOf(tokenCall.form?.get("assertion") ?? "").scope).toBe(GOOGLE_SCOPE_CLOUD_PLATFORM);

    const [deleteCall, waitCall] = computeCalls(calls);
    expect(deleteCall.method).toBe("DELETE");
    expect(deleteCall.url).toBe(`${GCP_ZONE_URL}/instances/dy-web-australia-southeast1-1`);
    expect(deleteCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(deleteCall.body).toBeUndefined();
    expect(waitCall.method).toBe("POST");
    expect(waitCall.url).toBe(`${GCP_ZONE_URL}/operations/operation-del-web/wait`);
    expect(computeCalls(calls)).toHaveLength(2);
  });

  it("gcp-instance-delete: a 404 is already-absent (ok:true) with NOTHING to wait on — the idempotent re-run path", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      notFound404("projects/dy-agency-proof/zones/australia-southeast1-a/instances/dy-web-australia-southeast1-1"),
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    // No operationName: nothing was deleted, so there is no operation to report.
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-instance-delete",
      instanceName: "dy-web-australia-southeast1-1",
      status: "already-absent",
    });
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-instance-delete: an operation still RUNNING after every bounded wait is ok:false with stillRunning:true (re-run to resume)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-del-web", status: "RUNNING" } },
      { body: { name: "operation-del-web", status: "RUNNING" } },
      { body: { name: "operation-del-web", status: "RUNNING" } },
      { body: { name: "operation-del-web", status: "RUNNING" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; instanceName: string; detail: string; stillRunning?: true };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instance-delete");
    expect(body.instanceName).toBe("dy-web-australia-southeast1-1");
    // The DISCRIMINABLE field is the contract; the detail string is for humans only.
    expect(body.stillRunning).toBe(true);
    expect(body.detail).toMatch(/delete operation was still not DONE after 3 waits/);
    // 1 delete + exactly 3 waits, then it stopped.
    expect(computeCalls(calls)).toHaveLength(4);
  });

  it("gcp-instance-delete: a 2xx WITHOUT an operation is ok:false WITH stillRunning:true (unconfirmed, not an observed failure)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([{ body: {} }]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string; stillRunning?: true };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instance-delete");
    // Google may well have ACCEPTED this delete, so the caller must be able to re-run and resume.
    expect(body.stillRunning).toBe(true);
    expect(body.detail).toMatch(/HTTP 200 but no operation — cannot confirm the instance "dy-web-australia-southeast1-1" delete was accepted/);
    // The delete was issued once; with no operation name there is nothing to wait on.
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-instance-delete: an operation that FINISHES with errors is ok:false WITHOUT stillRunning (an observed failure, not an unconfirmed one)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-del-web", status: "RUNNING" } },
      {
        body: {
          name: "operation-del-web",
          status: "DONE",
          error: { errors: [{ code: "RESOURCE_IN_USE_BY_ANOTHER_RESOURCE", message: "The instance is in use." }] },
        },
      },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body).not.toHaveProperty("stillRunning");
    expect(body.detail).toMatch(/instance "dy-web-australia-southeast1-1" delete operation failed: The instance is in use/);
    expect(computeCalls(calls)).toHaveLength(2);
  });

  it("gcp-instance-delete: a 403 is ok:false naming compute.instances.delete, token not echoed, NO wait", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpInstanceDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([denied403("compute.instances.delete")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instance-delete");
    expect(body).not.toHaveProperty("stillRunning");
    expect(body.detail).toMatch(/denied the instance "dy-web-australia-southeast1-1" delete \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.instances.delete' permission");
    expect(body.detail).toMatch(/roles\/compute\.instanceAdmin\.v1/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-address-delete: DELETEs the REGIONAL reservation and WAITS for its operation", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpAddressDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-del-ip", status: "RUNNING" } },
      { body: { name: "operation-del-ip", status: "DONE" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-address-delete",
      addressName: "dy-cell-gateway-ip",
      status: "deleted",
    });
    const [deleteCall, waitCall] = computeCalls(calls);
    expect(deleteCall.method).toBe("DELETE");
    expect(deleteCall.url).toBe(`${GCP_REGION_URL}/addresses/dy-cell-gateway-ip`);
    expect(waitCall.url).toBe(`${GCP_REGION_URL}/operations/operation-del-ip/wait`);
  });

  it("gcp-address-delete: a 404 is already-absent (ok:true); a 403 names compute.addresses.delete", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpAddressDeleteJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([notFound404("projects/dy-agency-proof/regions/australia-southeast1/addresses/dy-cell-gateway-ip")]);

    const absent = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await absent.json()).toEqual({
      ok: true,
      op: "gcp-address-delete",
      addressName: "dy-cell-gateway-ip",
      status: "already-absent",
    });

    vi.restoreAllMocks();
    vi.setSystemTime(new Date(FREEZE_MS));
    mockGcpApiQueue([denied403("compute.addresses.delete")]);
    const denied = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await denied.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/denied the address "dy-cell-gateway-ip" delete \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.addresses.delete' permission");
  });

  it("gcp-firewall-delete: DELETEs the GLOBAL rule and waits on the GLOBAL operation", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-del-rule", status: "RUNNING" } },
      { body: { name: "operation-del-rule", status: "DONE" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-firewall-delete",
      ruleName: "dy-cell-australia-southeast1-gw-ssh",
      status: "deleted",
    });
    expect(computeCalls(calls).map((call) => call.url)).toEqual([
      `${GCP_PROJECT_URL}/global/firewalls/dy-cell-australia-southeast1-gw-ssh`,
      `${GCP_PROJECT_URL}/global/operations/operation-del-rule/wait`,
    ]);
  });

  it("gcp-firewall-delete: a 404 is already-absent (ok:true); a 403 names compute.firewalls.delete", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpFirewallDeleteJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([notFound404("projects/dy-agency-proof/global/firewalls/dy-cell-australia-southeast1-gw-ssh")]);

    const absent = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await absent.json()).toEqual({
      ok: true,
      op: "gcp-firewall-delete",
      ruleName: "dy-cell-australia-southeast1-gw-ssh",
      status: "already-absent",
    });

    vi.restoreAllMocks();
    vi.setSystemTime(new Date(FREEZE_MS));
    mockGcpApiQueue([denied403("compute.firewalls.delete")]);
    const denied = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await denied.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/denied the firewall rule "dy-cell-australia-southeast1-gw-ssh" delete \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.firewalls.delete' permission");
    expect(body.detail).toMatch(/roles\/compute\.securityAdmin/);
  });

  it("gcp-router-delete: DELETEs the REGIONAL router (its inline NAT goes with it — no separate NAT call)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-del-router", status: "RUNNING" } },
      { body: { name: "operation-del-router", status: "DONE" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-router-delete",
      routerName: "dy-cell-australia-southeast1-router",
      status: "deleted",
    });
    // Exactly the router delete + its wait — the NAT is a FIELD of the router, never its own call.
    expect(computeCalls(calls).map((call) => call.url)).toEqual([
      `${GCP_REGION_URL}/routers/dy-cell-australia-southeast1-router`,
      `${GCP_REGION_URL}/operations/operation-del-router/wait`,
    ]);
  });

  it("gcp-router-delete: a 404 is already-absent (ok:true); a 403 names compute.routers.delete", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRouterDeleteJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([notFound404("projects/dy-agency-proof/regions/australia-southeast1/routers/dy-cell-australia-southeast1-router")]);

    const absent = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await absent.json()).toEqual({
      ok: true,
      op: "gcp-router-delete",
      routerName: "dy-cell-australia-southeast1-router",
      status: "already-absent",
    });

    vi.restoreAllMocks();
    vi.setSystemTime(new Date(FREEZE_MS));
    mockGcpApiQueue([denied403("compute.routers.delete")]);
    const denied = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await denied.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/denied the router "dy-cell-australia-southeast1-router" delete \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.routers.delete' permission");
  });

  it("gcp-network-delete: deletes the SUBNET first (waiting for it) and only THEN the network", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-del-subnet", status: "RUNNING" } }, // subnetworks.delete
      { body: { name: "operation-del-subnet", status: "DONE" } }, // regionOperations.wait
      { body: { name: "operation-del-net", status: "RUNNING" } }, // networks.delete
      { body: { name: "operation-del-net", status: "DONE" } }, // globalOperations.wait
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-network-delete",
      networkName: "dy-cell-australia-southeast1",
      subnetName: "dy-cell-australia-southeast1-subnet",
      subnetStatus: "deleted",
      networkStatus: "deleted",
    });
    // The ORDER is the contract: a networks.delete with a live subnet is Google's resourceInUse.
    const computed = computeCalls(calls);
    expect(computed.map((call) => call.url)).toEqual([
      `${GCP_REGION_URL}/subnetworks/dy-cell-australia-southeast1-subnet`,
      `${GCP_REGION_URL}/operations/operation-del-subnet/wait`,
      `${GCP_PROJECT_URL}/global/networks/dy-cell-australia-southeast1`,
      `${GCP_PROJECT_URL}/global/operations/operation-del-net/wait`,
    ]);
    expect(computed.map((call) => call.method)).toEqual(["DELETE", "POST", "DELETE", "POST"]);
  });

  it("gcp-network-delete: BOTH already gone (404 + 404) is ok:true already-absent, with NO wait calls", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      notFound404("projects/dy-agency-proof/regions/australia-southeast1/subnetworks/dy-cell-australia-southeast1-subnet"),
      notFound404("projects/dy-agency-proof/global/networks/dy-cell-australia-southeast1"),
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-network-delete",
      networkName: "dy-cell-australia-southeast1",
      subnetName: "dy-cell-australia-southeast1-subnet",
      subnetStatus: "already-absent",
      networkStatus: "already-absent",
    });
    expect(computeCalls(calls).map((call) => call.url)).toEqual([
      `${GCP_REGION_URL}/subnetworks/dy-cell-australia-southeast1-subnet`,
      `${GCP_PROJECT_URL}/global/networks/dy-cell-australia-southeast1`,
    ]);
  });

  it("gcp-network-delete: a re-run that already removed the subnet still removes the network (mixed statuses)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkDeleteJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([
      notFound404("projects/dy-agency-proof/regions/australia-southeast1/subnetworks/dy-cell-australia-southeast1-subnet"),
      { body: { name: "operation-del-net", status: "RUNNING" } },
      { body: { name: "operation-del-net", status: "DONE" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; subnetStatus: string; networkStatus: string };
    expect(body.ok).toBe(true);
    expect(body.subnetStatus).toBe("already-absent");
    expect(body.networkStatus).toBe("deleted");
  });

  it("gcp-network-delete: a FAILED subnet delete stops the op — the network delete is never issued", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkDeleteJob();
    const signature = await signAsApp(job, privateKey);
    // Google's answer while something (a VM) still holds the subnet.
    const calls = mockGcpApiQueue([
      {
        status: 400,
        body: { error: { code: 400, message: "The subnetwork resource is already being used", errors: [{ reason: "resourceInUse" }] } },
      },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; networkName: string; subnetName: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-network-delete");
    expect(body.networkName).toBe("dy-cell-australia-southeast1");
    expect(body.subnetName).toBe("dy-cell-australia-southeast1-subnet");
    expect(body.detail).toMatch(/subnetwork "dy-cell-australia-southeast1-subnet" delete failed with HTTP 400: .*already being used/);
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-network-delete: an UNCONFIRMED subnet delete also stops the op — the network is never deleted under a live subnet", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      { body: { name: "operation-del-subnet", status: "RUNNING" } },
      { body: { name: "operation-del-subnet", status: "RUNNING" } },
      { body: { name: "operation-del-subnet", status: "RUNNING" } },
      { body: { name: "operation-del-subnet", status: "RUNNING" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/subnetwork "dy-cell-australia-southeast1-subnet" delete operation was still not DONE after 3 waits/);
    // 1 subnet delete + exactly 3 waits — the network delete never ran.
    expect(computeCalls(calls)).toHaveLength(4);
  });

  it("gcp-network-delete: a 403 on the SUBNET delete names compute.subnetworks.delete and issues no network delete", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkDeleteJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([denied403("compute.subnetworks.delete")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/denied the subnetwork "dy-cell-australia-southeast1-subnet" delete \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.subnetworks.delete' permission");
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-network-delete: a 403 on the NETWORK delete names compute.networks.delete (the subnet already went)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpNetworkDeleteJob();
    const signature = await signAsApp(job, privateKey);
    mockGcpApiQueue([
      notFound404("projects/dy-agency-proof/regions/australia-southeast1/subnetworks/dy-cell-australia-southeast1-subnet"),
      denied403("compute.networks.delete"),
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/denied the network "dy-cell-australia-southeast1" delete \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.networks.delete' permission");
    expect(body.detail).toMatch(/roles\/compute\.networkAdmin/);
  });

  it("the five teardown ops REJECT a project that is not the SA key's own project — ZERO GCP calls", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const otherProjectKey = await makeServiceAccountKey("some-other-project");
    const jobs = [
      gcpInstanceDeleteJob(),
      gcpAddressDeleteJob(),
      gcpFirewallDeleteJob(),
      gcpRouterDeleteJob(),
      gcpNetworkDeleteJob(),
    ];
    for (const job of jobs) {
      const signature = await signAsApp(job, privateKey);
      const calls = mockGcpApiQueue([{ body: { name: "operation-should-not-happen", status: "RUNNING" } }]);
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: otherProjectKey }));
      const body = (await response.json()) as { ok: boolean; detail: string };
      expect(body.ok).toBe(false);
      expect(body.detail).toMatch(/own project/);
      expect(calls).toHaveLength(0);
      vi.restoreAllMocks();
    }
  });

  it("the five teardown ops report a clean failure and touch NO API when GCP_SERVICE_ACCOUNT_KEY is missing", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const jobs = [
      gcpInstanceDeleteJob(),
      gcpAddressDeleteJob(),
      gcpFirewallDeleteJob(),
      gcpRouterDeleteJob(),
      gcpNetworkDeleteJob(),
    ];
    for (const job of jobs) {
      const signature = await signAsApp(job, privateKey);
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      // Every OTHER agency credential is present — none may be used as a substitute.
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
      expect(response.status).toBe(200);
      const body = (await response.json()) as { ok: boolean; detail: string };
      expect(body.ok).toBe(false);
      expect(body.detail).toMatch(/GCP_SERVICE_ACCOUNT_KEY is not configured/);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });

  it("the teardown ops given another op's params are 400 with NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const jobs = [
      // No zone / name.
      gcpInstanceDeleteJob({ params: JSON.stringify(GCP_ADDRESS_DELETE_PARAMS) }),
      // No addressName.
      gcpAddressDeleteJob({ params: JSON.stringify(GCP_ROUTER_DELETE_PARAMS) }),
      // No ruleName.
      gcpFirewallDeleteJob({ params: JSON.stringify(GCP_NETWORK_DELETE_PARAMS) }),
      // No routerName.
      gcpRouterDeleteJob({ params: JSON.stringify(GCP_INSTANCE_DELETE_PARAMS) }),
      // No networkName / subnetName.
      gcpNetworkDeleteJob({ params: JSON.stringify(GCP_ADDRESS_DELETE_PARAMS) }),
    ];
    for (const job of jobs) {
      const signature = await signAsApp(job, privateKey);
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
      expect(response.status).toBe(400);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });

  // ── gcp-instance-set-metadata through the registry (planning/47) ──────────────────────
  // The in-place update op. Load-bearing assertions: the Worker SUBSTITUTES its own S3_* values for
  // the allowlisted placeholders BEFORE any Google call (an unknown placeholder or a missing secret
  // touches NOTHING — not even the token mint); the write goes out under the fingerprint it READ,
  // with every unrelated existing key preserved IN PLACE; a stale fingerprint (412) surfaces as the
  // DISCRIMINABLE `staleFingerprint: true`, never a blind retry; and no secret — the agency's S3
  // secret, the script's own restic line, the access token — ever appears in a result or detail.

  const FILE_NODE_URL = `${GCP_ZONE_URL}/instances/dy-file-australia-southeast1-1`;
  /** instances.get for the file node with an existing boot script and two UNRELATED keys around it. */
  function fileNodeInstance(overrides: Record<string, unknown> = {}) {
    return {
      body: {
        name: "dy-file-australia-southeast1-1",
        status: "RUNNING",
        metadata: {
          fingerprint: "fp-abc123",
          items: [
            { key: "enable-oslogin", value: "TRUE" },
            { key: "startup-script", value: "#!/bin/bash\necho old\n" },
            { key: "dy-cell-bundle", value: "20260916-9c25cfd" },
          ],
        },
        ...overrides,
      },
    };
  }
  /** Google's 412 for a setMetadata whose fingerprint is stale. */
  const STALE_FINGERPRINT_412 = {
    status: 412,
    body: {
      error: {
        code: 412,
        message: "Supplied fingerprint does not match current metadata fingerprint.",
        errors: [{ reason: "conditionNotMet", message: "Supplied fingerprint does not match current metadata fingerprint." }],
      },
    },
  };

  it("gcp-instance-set-metadata: substitutes the allowlisted placeholders from the Worker's OWN S3_* secrets, MERGES under the read fingerprint (unrelated keys survive in place), WAITS to DONE — and echoes no secret", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance(), // instances.get
      { body: { name: "operation-setmeta", status: "RUNNING", operationType: "setMetadata" } }, // instances.setMetadata
      { body: { name: "operation-setmeta", status: "DONE" } }, // zoneOperations.wait
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const resultBody = await response.json();
    expect(resultBody).toEqual({
      ok: true,
      op: "gcp-instance-set-metadata",
      instanceName: "dy-file-australia-southeast1-1",
      keysSet: ["startup-script"],
      placeholdersSubstituted: [
        "@@DY_T2_S3_ACCESS_KEY_ID@@",
        "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
        "@@DY_T2_S3_ENDPOINT@@",
        "@@DY_T2_S3_BUCKET@@",
        "@@DY_T2_S3_REGION@@",
        "@@DY_T1_S3_BUCKET@@",
      ],
      // hub#64: the RESOLVED values of the four non-secret placeholders, so the operator sees WHICH
      // bucket Tier-1 landed on rather than only that a substitution happened. envWith() leaves
      // S3_BACKUP_BUCKET unset, so Tier-1 falls back to S3_BUCKET and the two buckets are equal.
      placeholderValues: {
        "@@DY_T2_S3_ENDPOINT@@": "https://acct123.r2.example.test",
        "@@DY_T2_S3_BUCKET@@": "agency-backups",
        "@@DY_T2_S3_REGION@@": "auto",
        "@@DY_T1_S3_BUCKET@@": "agency-backups",
      },
      operationName: "operation-setmeta",
    });
    // Names only in the result — never the agency's secret, the script's restic line, or the token.
    const resultText = JSON.stringify(resultBody);
    expect(resultText).not.toContain("s3-secret-example");
    expect(resultText).not.toContain("s3-akid-example");
    expect(resultText).not.toContain("fixture-restic-password");
    expect(resultText).not.toContain(GCP_ACCESS_TOKEN);
    // The two CREDENTIAL placeholders are ABSENT from the value map — not masked, not truncated.
    const reported = (resultBody as { placeholderValues: Record<string, string> }).placeholderValues;
    expect(Object.keys(reported)).not.toContain("@@DY_T2_S3_ACCESS_KEY_ID@@");
    expect(Object.keys(reported)).not.toContain("@@DY_T2_S3_SECRET_ACCESS_KEY@@");

    const [tokenCall] = calls;
    expect(tokenCall.url).toBe("https://oauth2.googleapis.com/token");
    expect(jwtClaimsOf(tokenCall.form?.get("assertion") ?? "").scope).toBe(GOOGLE_SCOPE_CLOUD_PLATFORM);

    const [getCall, setCall, waitCall] = computeCalls(calls);
    expect(getCall.method).toBe("GET");
    expect(getCall.url).toBe(FILE_NODE_URL);
    expect(getCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(setCall.method).toBe("POST");
    expect(setCall.url).toBe(`${FILE_NODE_URL}/setMetadata`);
    expect(setCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    // The fingerprint we READ is the one we WRITE under; the two unrelated keys are untouched and in
    // their original positions; the named key is replaced in place with the RENDERED script.
    expect(setCall.body).toEqual({
      fingerprint: "fp-abc123",
      items: [
        { key: "enable-oslogin", value: "TRUE" },
        { key: "startup-script", value: FILE_NODE_BOOT_SCRIPT_RENDERED },
        { key: "dy-cell-bundle", value: "20260916-9c25cfd" },
      ],
    });
    // Not a single placeholder sigil survives into the boot script Google receives.
    expect(setCall.rawBody).not.toContain("@@");
    expect(waitCall.method).toBe("POST");
    expect(waitCall.url).toBe(`${GCP_ZONE_URL}/operations/operation-setmeta/wait`);
    expect(computeCalls(calls)).toHaveLength(3);
  });

  it("gcp-instance-set-metadata: a VM with no startup-script yet gets it APPENDED after its existing items (nothing else changes); a value with no placeholder needs NO S3_* configured", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const plainScript = "#!/bin/bash\necho 'no placeholders'\n";
    const job = gcpSetMetadataJob({
      params: JSON.stringify({ ...GCP_SET_METADATA_PARAMS, items: [{ key: "startup-script", value: plainScript }] }),
    });
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance({
        metadata: {
          fingerprint: "fp-abc123",
          items: [
            { key: "enable-oslogin", value: "TRUE" },
            { key: "dy-cell-bundle", value: "20260916-9c25cfd" },
          ],
        },
      }),
      { body: { name: "operation-setmeta-2", status: "RUNNING" } },
      { body: { name: "operation-setmeta-2", status: "DONE" } },
    ]);

    // Every S3_* variable UNSET: a value without a placeholder must not even look at them.
    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({
        GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey,
        S3_ACCESS_KEY_ID: undefined,
        S3_SECRET_ACCESS_KEY: undefined,
        S3_BUCKET: undefined,
        S3_REGION: undefined,
        S3_ENDPOINT: undefined,
      }),
    );
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-instance-set-metadata",
      instanceName: "dy-file-australia-southeast1-1",
      keysSet: ["startup-script"],
      placeholdersSubstituted: [],
      // Nothing was substituted, so there is nothing to report a value for.
      placeholderValues: {},
      operationName: "operation-setmeta-2",
    });
    const [, setCall] = computeCalls(calls);
    expect(setCall.body).toEqual({
      fingerprint: "fp-abc123",
      items: [
        { key: "enable-oslogin", value: "TRUE" },
        { key: "dy-cell-bundle", value: "20260916-9c25cfd" },
        { key: "startup-script", value: plainScript },
      ],
    });
  });

  it("gcp-instance-set-metadata: the KEY allowlist through /actuate — `ssh-keys` alone, and a MIXED list of startup-script + ssh-keys, are both refused WHOLE as 400 with NO Google call (no token mint, no read, no write)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const sshKeyItem = { key: "ssh-keys", value: "jason:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIXTUREFIXTUREFIXTUREFIXTUREFIXTUREFIXTUREFIXT" };
    const jobs = [
      gcpSetMetadataJob({ params: JSON.stringify({ ...GCP_SET_METADATA_PARAMS, items: [sshKeyItem] }) }),
      // Mixed, allowed key FIRST: the valid startup-script must NOT be applied while ssh-keys is refused.
      gcpSetMetadataJob({ params: JSON.stringify({ ...GCP_SET_METADATA_PARAMS, items: [GCP_SET_METADATA_PARAMS.items[0], sshKeyItem] }) }),
      // Mixed, disallowed key FIRST.
      gcpSetMetadataJob({ params: JSON.stringify({ ...GCP_SET_METADATA_PARAMS, items: [sshKeyItem, GCP_SET_METADATA_PARAMS.items[0]] }) }),
    ];
    for (const job of jobs) {
      const signature = await signAsApp(job, privateKey);
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
      expect(response.status).toBe(400);
      const body = (await response.json()) as { ok: boolean; error: string; reason: string };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("invalid params");
      expect(body.reason).toBe('each items entry\'s key must be one of the allowlisted metadata keys (startup-script); got "ssh-keys"');
      // Nothing was applied, partially or otherwise: not one outbound request.
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });

  it("gcp-instance-set-metadata: an UNKNOWN @@PLACEHOLDER@@ is REFUSED — ok:false naming the token, NO Google call at all (not even the token mint), and no script text echoed", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const script =
      "#!/bin/bash\n" +
      "readonly DY_T2_BUCKET='@@DY_T2_S3_BUCKET@@'\n" +
      "readonly RESTIC_PASSWORD='@@DY_RESTIC_PASSWORD@@'\n" +
      "readonly SENTINEL='script-text-must-not-echo'\n";
    const job = gcpSetMetadataJob({
      params: JSON.stringify({ ...GCP_SET_METADATA_PARAMS, items: [{ key: "startup-script", value: script }] }),
    });
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; instanceName: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instance-set-metadata");
    expect(body.instanceName).toBe("dy-file-australia-southeast1-1");
    expect(body.detail).toMatch(/metadata key "startup-script": the placeholder @@DY_RESTIC_PASSWORD@@ is not on this Worker's allowlist/);
    expect(body.detail).toMatch(/refusing to write it into instance metadata/);
    expect(body.detail).not.toContain("script-text-must-not-echo");
    expect(body.detail).not.toContain("agency-backups");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gcp-instance-set-metadata: a MISSING required S3 secret FAILS (naming the variable) rather than substituting an empty credential — NO Google call", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey, S3_SECRET_ACCESS_KEY: undefined }),
    );
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/S3_SECRET_ACCESS_KEY is not configured on this Worker/);
    expect(body.detail).toMatch(/refusing to write a boot script with an empty one/);
    expect(body.detail).not.toContain("s3-akid-example");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gcp-instance-set-metadata: hub#64 — an S3_BACKUP_BUCKET holding a URL is refused BEFORE the token mint and any Google call, naming the variable", async () => {
    // The live 2026-10-06 mistake, through the whole route: the agency's S3 API URL in the optional
    // Tier-1 bucket secret. The refusal must cost nothing — no minted credential, no instance read,
    // certainly no metadata write — exactly like the unknown-placeholder and missing-secret refusals.
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey, S3_BACKUP_BUCKET: "https://acct123.r2.example.test" }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; op: string; instanceName: string; detail: string };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instance-set-metadata");
    expect(body.detail).toMatch(/metadata key "startup-script": S3_BACKUP_BUCKET looks like an endpoint URL, not a bucket name/);
    expect(body.detail).not.toContain("acct123");
    expect(body.detail).not.toContain("fixture-restic-password");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("gcp-instance-set-metadata: hub#64 — a SET S3_BACKUP_BUCKET is reported as Tier-1's own bucket, DIFFERENT from Tier-2's", async () => {
    // The whole point of the value report: the two buckets differ, visibly, from the control plane.
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance(),
      { body: { name: "operation-setmeta-t1", status: "RUNNING" } },
      { body: { name: "operation-setmeta-t1", status: "DONE" } },
    ]);

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey, S3_BACKUP_BUCKET: "agency-backups-tier1" }),
    );
    const body = (await response.json()) as { ok: boolean; placeholderValues: Record<string, string> };
    expect(body.ok).toBe(true);
    expect(body.placeholderValues["@@DY_T1_S3_BUCKET@@"]).toBe("agency-backups-tier1");
    expect(body.placeholderValues["@@DY_T2_S3_BUCKET@@"]).toBe("agency-backups");
    expect(Object.keys(body.placeholderValues).sort()).toEqual([
      "@@DY_T1_S3_BUCKET@@",
      "@@DY_T2_S3_BUCKET@@",
      "@@DY_T2_S3_ENDPOINT@@",
      "@@DY_T2_S3_REGION@@",
    ]);
    // The published script really carries the split, not just the report.
    const [, setCall] = computeCalls(calls);
    const written = (setCall.body as { items: Array<{ key: string; value: string }> }).items[1];
    expect(written.value).toContain("readonly DY_T1_BUCKET='agency-backups-tier1'\n");
    expect(written.value).toContain("readonly DY_T2_BUCKET='agency-backups'\n");
  });

  it("gcp-instance-set-metadata: an UNSET S3_ENDPOINT substitutes '' (the backup runner's encoding of native AWS) while the credentials still substitute for real", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance(),
      { body: { name: "operation-setmeta-3", status: "RUNNING" } },
      { body: { name: "operation-setmeta-3", status: "DONE" } },
    ]);

    const response = await worker.fetch(
      actuateRequest({ job, signature }),
      envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey, S3_ENDPOINT: undefined, S3_REGION: "ap-southeast-2" }),
    );
    const body = (await response.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
    const [, setCall] = computeCalls(calls);
    const written = (setCall.body as { items: Array<{ key: string; value: string }> }).items[1];
    expect(written.key).toBe("startup-script");
    expect(written.value).toContain("readonly DY_T2_ENDPOINT=''\n");
    expect(written.value).toContain("readonly DY_T2_ACCESS_KEY_ID='s3-akid-example'\n");
    expect(written.value).toContain("readonly DY_T2_SECRET_ACCESS_KEY='s3-secret-example'\n");
    expect(written.value).toContain("readonly DY_T2_REGION='ap-southeast-2'\n");
    expect(written.value).not.toContain("@@");
  });

  it("gcp-instance-set-metadata: a STALE fingerprint (412) is ok:false with the DISCRIMINABLE staleFingerprint:true — nothing written, NO blind re-read/re-write, NO wait", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([fileNodeInstance(), STALE_FINGERPRINT_412]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; op: string; detail: string; staleFingerprint?: true; unconfirmed?: true };
    expect(body.ok).toBe(false);
    expect(body.op).toBe("gcp-instance-set-metadata");
    // The FIELD is the contract; the detail is for humans.
    expect(body.staleFingerprint).toBe(true);
    expect(body).not.toHaveProperty("unconfirmed");
    expect(body.detail).toMatch(/changed between read and write \(HTTP 412, stale fingerprint\)/);
    expect(body.detail).toMatch(/nothing was written; re-run to merge against the current metadata/);
    // Exactly one GET + one setMetadata — the Worker did NOT loop on a fresh fingerprint.
    expect(computeCalls(calls)).toHaveLength(2);
    expect(JSON.stringify(body)).not.toContain("s3-secret-example");
  });

  it("gcp-instance-set-metadata: an instance that is NOT there is ok:false (nothing to update — a 404 is not a converged success here), NO write", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([notFound404("projects/dy-agency-proof/zones/australia-southeast1-a/instances/dy-file-australia-southeast1-1")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/instance "dy-file-australia-southeast1-1" was not found in project "dy-agency-proof" — nothing to update/);
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-instance-set-metadata: an instance read WITHOUT a metadata fingerprint is refused — no unguarded write", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([fileNodeInstance({ metadata: { items: [] } })]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.detail).toMatch(/returned no metadata fingerprint — refusing to write metadata without the concurrency guard/);
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-instance-set-metadata: a write whose operation is still not DONE after the ONE bounded wait is ok:false with unconfirmed:true (re-run converges)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance(),
      { body: { name: "operation-setmeta-slow", status: "RUNNING" } },
      { body: { name: "operation-setmeta-slow", status: "RUNNING" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string; unconfirmed?: true; staleFingerprint?: true };
    expect(body.ok).toBe(false);
    expect(body.unconfirmed).toBe(true);
    expect(body).not.toHaveProperty("staleFingerprint");
    expect(body.detail).toMatch(/metadata write operation was still not DONE after 1 waits/);
    // 1 GET + 1 setMetadata + exactly 1 wait.
    expect(computeCalls(calls)).toHaveLength(3);
  });

  it("gcp-instance-set-metadata: a 403 on the write names compute.instances.setMetadata, token not echoed, NO wait", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpSetMetadataJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([fileNodeInstance(), denied403("compute.instances.setMetadata")]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; detail: string; staleFingerprint?: true };
    expect(body.ok).toBe(false);
    expect(body).not.toHaveProperty("staleFingerprint");
    expect(body.detail).toMatch(/denied setting metadata on instance "dy-file-australia-southeast1-1" \(HTTP 403\)/);
    expect(body.detail).toContain("Required 'compute.instances.setMetadata' permission");
    expect(body.detail).toMatch(/roles\/compute\.instanceAdmin\.v1/);
    expect(JSON.stringify(body)).not.toContain(GCP_ACCESS_TOKEN);
    expect(computeCalls(calls)).toHaveLength(2);
  });

  // ── gcp-instance-restart through the registry (planning/47) ───────────────────────────
  // A GRACEFUL stop then start (never reset — the file node is an NFS server). Load-bearing
  // assertions: a RUNNING VM is stopped (operation WAITED to DONE) and then started (waited again);
  // a TERMINATED VM is only started ("already-stopped"); a transitional VM is refused, not raced;
  // and a failure names the PHASE plus whether the VM was confirmed stopped, with `unconfirmed`
  // only when Google accepted the action but the bounded wait could not see it finish.

  it("gcp-instance-restart: RUNNING -> stop (wait DONE) -> start (wait DONE) is ok:true stopped+started, with both operation names, agency SA only", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRestartJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance(), // instances.get -> RUNNING
      { body: { name: "operation-stop", status: "RUNNING", operationType: "stop" } }, // instances.stop
      { body: { name: "operation-stop", status: "DONE" } }, // wait -> TERMINATED
      { body: { name: "operation-start", status: "RUNNING", operationType: "start" } }, // instances.start
      { body: { name: "operation-start", status: "DONE" } }, // wait -> RUNNING
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(response.status).toBe(200);
    const resultBody = await response.json();
    expect(resultBody).toEqual({
      ok: true,
      op: "gcp-instance-restart",
      instanceName: "dy-file-australia-southeast1-1",
      stopStatus: "stopped",
      startStatus: "started",
      stopOperationName: "operation-stop",
      startOperationName: "operation-start",
    });
    expect(JSON.stringify(resultBody)).not.toContain(GCP_ACCESS_TOKEN);

    const [getCall, stopCall, stopWait, startCall, startWait] = computeCalls(calls);
    expect(getCall.method).toBe("GET");
    expect(getCall.url).toBe(FILE_NODE_URL);
    // stop, NOT reset — and an empty body.
    expect(stopCall.method).toBe("POST");
    expect(stopCall.url).toBe(`${FILE_NODE_URL}/stop`);
    expect(stopCall.body).toBeUndefined();
    expect(stopCall.auth).toBe(`Bearer ${GCP_ACCESS_TOKEN}`);
    expect(stopWait.url).toBe(`${GCP_ZONE_URL}/operations/operation-stop/wait`);
    expect(startCall.method).toBe("POST");
    expect(startCall.url).toBe(`${FILE_NODE_URL}/start`);
    expect(startCall.body).toBeUndefined();
    expect(startWait.url).toBe(`${GCP_ZONE_URL}/operations/operation-start/wait`);
    expect(computeCalls(calls)).toHaveLength(5);
    expect(computeCalls(calls).some((call) => call.url.endsWith("/reset"))).toBe(false);
  });

  it("gcp-instance-restart: a VM already TERMINATED is only STARTED — stopStatus already-stopped, no stop call, no stopOperationName", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRestartJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance({ status: "TERMINATED" }),
      { body: { name: "operation-start", status: "RUNNING" } },
      { body: { name: "operation-start", status: "DONE" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    expect(await response.json()).toEqual({
      ok: true,
      op: "gcp-instance-restart",
      instanceName: "dy-file-australia-southeast1-1",
      stopStatus: "already-stopped",
      startStatus: "started",
      startOperationName: "operation-start",
    });
    const [, startCall] = computeCalls(calls);
    expect(startCall.url).toBe(`${FILE_NODE_URL}/start`);
    expect(computeCalls(calls)).toHaveLength(3);
  });

  it("gcp-instance-restart: a VM in a TRANSITIONAL state (STOPPING) is refused — phase stop, stopped:false, no action issued", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRestartJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([fileNodeInstance({ status: "STOPPING" })]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; phase: string; stopped: boolean; detail: string; unconfirmed?: true };
    expect(body.ok).toBe(false);
    expect(body.phase).toBe("stop");
    expect(body.stopped).toBe(false);
    expect(body).not.toHaveProperty("unconfirmed");
    expect(body.detail).toMatch(/is STOPPING — a restart needs it RUNNING .* or TERMINATED .*; re-run once it settles/);
    expect(computeCalls(calls)).toHaveLength(1);
  });

  it("gcp-instance-restart: a stop still not DONE after its TWO bounded waits is phase stop, stopped:false, unconfirmed:true — the start is NEVER issued", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRestartJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance(),
      { body: { name: "operation-stop", status: "RUNNING" } },
      { body: { name: "operation-stop", status: "RUNNING" } },
      { body: { name: "operation-stop", status: "RUNNING" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; phase: string; stopped: boolean; detail: string; unconfirmed?: true };
    expect(body.ok).toBe(false);
    expect(body.phase).toBe("stop");
    expect(body.stopped).toBe(false);
    expect(body.unconfirmed).toBe(true);
    expect(body.detail).toMatch(/stop operation was still not DONE after 2 waits/);
    // GET + stop + exactly 2 waits; no start.
    expect(computeCalls(calls)).toHaveLength(4);
    expect(computeCalls(calls).some((call) => call.url.endsWith("/start"))).toBe(false);
  });

  it("gcp-instance-restart: stop confirmed but the start not DONE after its ONE wait is phase start, stopped:TRUE, unconfirmed:true (the operator-visible 'down and not back' case)", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRestartJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance(),
      { body: { name: "operation-stop", status: "RUNNING" } },
      { body: { name: "operation-stop", status: "DONE" } },
      { body: { name: "operation-start", status: "RUNNING" } },
      { body: { name: "operation-start", status: "RUNNING" } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; phase: string; stopped: boolean; detail: string; unconfirmed?: true };
    expect(body.ok).toBe(false);
    expect(body.phase).toBe("start");
    expect(body.stopped).toBe(true);
    expect(body.unconfirmed).toBe(true);
    expect(body.detail).toMatch(/start operation was still not DONE after 1 waits/);
    expect(computeCalls(calls)).toHaveLength(5);
  });

  it("gcp-instance-restart: a stop operation that FINISHES with errors is phase stop WITHOUT unconfirmed (an observed failure), and the start is never issued", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRestartJob();
    const signature = await signAsApp(job, privateKey);
    const calls = mockGcpApiQueue([
      fileNodeInstance(),
      { body: { name: "operation-stop", status: "RUNNING" } },
      { body: { name: "operation-stop", status: "DONE", error: { errors: [{ code: "INTERNAL_ERROR", message: "Guest shutdown failed." }] } } },
    ]);

    const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const body = (await response.json()) as { ok: boolean; phase: string; stopped: boolean; detail: string };
    expect(body.ok).toBe(false);
    expect(body.phase).toBe("stop");
    expect(body.stopped).toBe(false);
    expect(body).not.toHaveProperty("unconfirmed");
    expect(body.detail).toMatch(/instance "dy-file-australia-southeast1-1" stop operation failed: Guest shutdown failed/);
    expect(computeCalls(calls)).toHaveLength(3);
  });

  it("gcp-instance-restart: a 403 on the stop names compute.instances.stop (phase stop, token not echoed); a missing instance is phase stop too", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    const job = gcpRestartJob();
    const signature = await signAsApp(job, privateKey);
    const deniedCalls = mockGcpApiQueue([fileNodeInstance(), denied403("compute.instances.stop")]);

    const deniedResponse = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const denied = (await deniedResponse.json()) as { ok: boolean; phase: string; stopped: boolean; detail: string };
    expect(denied.ok).toBe(false);
    expect(denied.phase).toBe("stop");
    expect(denied.stopped).toBe(false);
    expect(denied.detail).toMatch(/denied the instance "dy-file-australia-southeast1-1" stop \(HTTP 403\)/);
    expect(denied.detail).toContain("Required 'compute.instances.stop' permission");
    expect(JSON.stringify(denied)).not.toContain(GCP_ACCESS_TOKEN);
    expect(computeCalls(deniedCalls)).toHaveLength(2);
    vi.restoreAllMocks();

    const missingCalls = mockGcpApiQueue([notFound404("projects/dy-agency-proof/zones/australia-southeast1-a/instances/dy-file-australia-southeast1-1")]);
    const missingResponse = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
    const missing = (await missingResponse.json()) as { ok: boolean; phase: string; stopped: boolean; detail: string };
    expect(missing.ok).toBe(false);
    expect(missing.phase).toBe("stop");
    expect(missing.stopped).toBe(false);
    expect(missing.detail).toMatch(/was not found in project "dy-agency-proof"/);
    expect(computeCalls(missingCalls)).toHaveLength(1);
  });

  it("the two update ops report a clean failure and touch NO API when GCP_SERVICE_ACCOUNT_KEY is missing; are pinned to the key's OWN project; and are 400 on another op's params", async () => {
    vi.setSystemTime(new Date(FREEZE_MS));
    for (const job of [gcpSetMetadataJob(), gcpRestartJob()]) {
      const signature = await signAsApp(job, privateKey);
      // No SA key — every OTHER agency credential is present and none may substitute.
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith());
      const body = (await response.json()) as { ok: boolean; detail: string };
      expect(body.ok).toBe(false);
      expect(body.detail).toMatch(/GCP_SERVICE_ACCOUNT_KEY is not configured/);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.restoreAllMocks();

      // A key for ANOTHER project: refused before any Compute call.
      const otherProjectKey = await makeServiceAccountKey("some-other-project");
      const calls = mockGcpApiQueue([{ body: { name: "should-not-happen" } }]);
      const pinned = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: otherProjectKey }));
      const pinnedBody = (await pinned.json()) as { ok: boolean; detail: string };
      expect(pinnedBody.ok).toBe(false);
      expect(pinnedBody.detail).toMatch(/own project/);
      expect(calls).toHaveLength(0);
      vi.restoreAllMocks();
    }

    // Another op's params (no items / no zone): 400, nothing called.
    const wrongParamsJobs = [
      gcpSetMetadataJob({ params: JSON.stringify(GCP_INSTANCE_DELETE_PARAMS) }),
      gcpRestartJob({ params: JSON.stringify(GCP_ADDRESS_DELETE_PARAMS) }),
    ];
    for (const job of wrongParamsJobs) {
      const signature = await signAsApp(job, privateKey);
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      const response = await worker.fetch(actuateRequest({ job, signature }), envWith({ GCP_SERVICE_ACCOUNT_KEY: serviceAccountKey }));
      expect(response.status).toBe(400);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });
});

// ── cf-tunnel-config: the appended catch-all rule ──────────────────────────────────────────
// The actuator writes the FULL ingress (a PUT) and appends the catch-all itself. Pin the two shapes
// the config PUT can take: the default (http_status:404 — every pre-existing caller) and a caller-
// named service (a cell's web-node nginx, so site hosts on the cell route by nginx server_name).
describe("actuateCfTunnelConfig: the catch-all rule", () => {
  const TUNNEL_ID = "031b5bee-a61a-444f-882e-451fd644e59f";
  const RULE = { hostname: "cell-australia-southeast2.example.com", service: "http://dy-web-x.internal:9440" };
  const env: Env = {
    APP_BASE_URL: "https://app.example.test",
    DY_CLIENT_ID: "client-abc",
    DY_CLIENT_SECRET: "secret-xyz",
    CF_DNS_API_TOKEN: "cf-dns-token-abc",
    NONCE_STORE: undefined as unknown as Env["NONCE_STORE"],
  };

  /** Mock CF: account resolution + the config PUT; returns the PUT body's ingress for assertions. */
  function mockConfigPut(): { putIngress: () => Array<{ hostname?: string; service: string }> | null } {
    let captured: Array<{ hostname?: string; service: string }> | null = null;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("/accounts?per_page=1")) {
        return new Response(JSON.stringify({ success: true, result: [{ id: "acct-cf-1" }] }), { status: 200 });
      }
      if (url.endsWith(`/accounts/acct-cf-1/cfd_tunnel/${TUNNEL_ID}/configurations`) && init?.method === "PUT") {
        captured = (JSON.parse(String(init.body)) as { config: { ingress: Array<{ hostname?: string; service: string }> } }).config.ingress;
        return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
      }
      throw new Error(`unexpected fetch to ${url}`);
    });
    return { putIngress: () => captured };
  }

  it("omitted catchAllService => the config ends with http_status:404 (unchanged default)", async () => {
    const { putIngress } = mockConfigPut();
    const result = await actuateCfTunnelConfig({ tunnelId: TUNNEL_ID, ingress: [RULE] }, env);
    expect(result).toEqual({ ok: true, op: "cf-tunnel-config", tunnelId: TUNNEL_ID, ruleCount: 1 });
    expect(putIngress()).toEqual([RULE, { service: "http_status:404" }]);
  });

  it("a given catchAllService becomes the LAST (hostname-less) rule, after every named rule", async () => {
    const { putIngress } = mockConfigPut();
    const result = await actuateCfTunnelConfig(
      { tunnelId: TUNNEL_ID, ingress: [RULE], catchAllService: "http://dy-web-x.internal:80" },
      env,
    );
    expect(result.ok).toBe(true);
    expect(putIngress()).toEqual([RULE, { service: "http://dy-web-x.internal:80" }]);
    // ruleCount reports the NAMED rules only — the catch-all is the actuator's, not the caller's.
    expect(result.ok && result.ruleCount).toBe(1);
  });
});

// ── edge page-cache rule builder (Worker copy — TWIN of the orchestrator's) ─────────────

describe("buildEdgeCacheRules: the Worker builds BOTH rules from three narrow inputs", () => {
  // ── THE TWIN PROOF ───────────────────────────────────────────────────────────────────
  // The two blocks below are the literal text BOTH repos must emit for the SAME zone. They are
  // duplicated VERBATIM in orchestrator.doubleyoup.com/src/edge-cache-rule.test.ts (there as
  // TWIN_CACHE_EXPRESSION / TWIN_BYPASS_EXPRESSION), and both repos assert against them — so a
  // change made on only one side of the twin fails that side's test.
  // The host clause, pinned on its own as well: the internal `<slug>-production.<zone>` routing
  // hosts OR a foreign domain on the zone (a Cloudflare-for-SaaS custom hostname = a CUSTOMER
  // DOMAIN), minus the zone apex and the branded media hosts. See edge-cache-rule.ts's
  // "WHICH HOSTS" header for why each exclusion is there and why `contains` rather than `ends_with`.
  const EXPECTED_HOST_CLAUSE =
    '(ends_with(http.host, "-production.example.com") or (not http.host contains ".example.com" ' +
    'and http.host ne "example.com" and not starts_with(http.host, "media.")))';

  const EXPECTED_EXPRESSION = [
    '(http.request.method in {"GET" "HEAD"})',
    'and (ends_with(http.host, "-production.example.com") or (not http.host contains ".example.com" and http.host ne "example.com" and not starts_with(http.host, "media.")))',
    'and (http.request.uri.path.extension in {"" "php" "html"})',
    'and not starts_with(http.request.uri.path, "/wp-admin")',
    'and not starts_with(http.request.uri.path, "/wp-login.php")',
    'and not starts_with(http.request.uri.path, "/wp-json")',
    'and not starts_with(http.request.uri.path, "/xmlrpc.php")',
    'and not starts_with(http.request.uri.path, "/wp-cron.php")',
    'and not starts_with(http.request.uri.path, "/cart")',
    'and not starts_with(http.request.uri.path, "/checkout")',
    'and not starts_with(http.request.uri.path, "/my-account")',
    'and not starts_with(http.request.uri.path, "/wc-api")',
    'and not http.request.uri.query contains "preview="',
    'and not http.request.uri.query contains "add-to-cart"',
    'and not http.request.uri.query contains "wc-ajax"',
    'and not http.cookie contains "wordpress_logged_in_"',
    'and not http.cookie contains "wp-postpass_"',
    'and not http.cookie contains "comment_author_"',
    'and not http.cookie contains "wp_woocommerce_session_"',
    'and not http.cookie contains "woocommerce_cart_hash"',
    'and not http.cookie contains "woocommerce_recently_viewed"',
    'and not http.cookie contains "store_notice"',
  ].join(" ");

  // The BYPASS rule: the same host + HTML-page clauses, then the personal cookies ORed. Byte-identical
  // to the orchestrator's pin.
  const EXPECTED_BYPASS_EXPRESSION = [
    '(ends_with(http.host, "-production.example.com") or (not http.host contains ".example.com" and http.host ne "example.com" and not starts_with(http.host, "media.")))',
    'and (http.request.uri.path.extension in {"" "php" "html"})',
    'and (http.cookie contains "wordpress_logged_in_"',
    'or http.cookie contains "wp-postpass_"',
    'or http.cookie contains "comment_author_"',
    'or http.cookie contains "wp_woocommerce_session_"',
    'or http.cookie contains "woocommerce_cart_hash"',
    'or http.cookie contains "woocommerce_recently_viewed"',
    'or http.cookie contains "store_notice")',
  ].join(" ");

  it("builds the exact TWO rule bodies (description, expression, action, action_parameters, enabled)", () => {
    const built = buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600 });
    expect(built).toEqual({
      ok: true,
      rules: {
        bypass: {
          description: "doubleyoup: edge page cache (bypass personal cookies)",
          expression: EXPECTED_BYPASS_EXPRESSION,
          action: "set_cache_settings",
          // BYPASS: a personal-cookie request is neither served from nor stored to the cache.
          action_parameters: { cache: false },
          enabled: true,
        },
        cache: {
          description: "doubleyoup: edge page cache",
          expression: EXPECTED_EXPRESSION,
          action: "set_cache_settings",
          // RESPECT-ORIGIN: eligible for cache, but Cloudflare stores a response ONLY when the origin
          // sends a cacheable Cache-Control (bypass_by_default) — no rule-side TTL, no status_code_ttl.
          // Pinned so a drift back to the force-cache `override_origin` mode fails this test.
          action_parameters: {
            cache: true,
            edge_ttl: { mode: "bypass_by_default" },
            browser_ttl: { mode: "respect_origin" },
          },
          enabled: true,
        },
      },
    });
    if (!built.ok) throw new Error(built.reason);
    expect(edgeCacheRulesInOrder(built.rules)).toEqual([built.rules.bypass, built.rules.cache]);
    expect(EDGE_CACHE_RULE_DESCRIPTION).toBe("doubleyoup: edge page cache");
    expect(EDGE_CACHE_BYPASS_RULE_DESCRIPTION).toBe("doubleyoup: edge page cache (bypass personal cookies)");
  });

  // THE EMPTY CART. `woocommerce_items_in_cart` is deliberately absent from BOTH expressions: WP
  // Engine value-matches `=[1-9]+` so an empty cart keeps its cache, and Cloudflare cannot read a
  // cookie's VALUE below a Business plan (`matches` is Business+). The origin makes the precise
  // call instead — the cell's nginx map and the mu-plugin both test `=[1-9]`. The BYPASS rule
  // loses nothing by it: WooCommerce writes and clears the counter and `woocommerce_cart_hash`
  // in the same call, so a real cart always carries the hash, which IS still a bypass cookie.
  it("neither rule mentions woocommerce_items_in_cart (an empty cart keeps its cache; the origin decides)", () => {
    const built = buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600 });
    if (!built.ok) throw new Error(built.reason);
    expect(built.rules.cache.expression).not.toContain("woocommerce_items_in_cart");
    expect(built.rules.bypass.expression).not.toContain("woocommerce_items_in_cart");
    // The cookie a filled cart always carries alongside it is still on both sides.
    expect(built.rules.bypass.expression).toContain('http.cookie contains "woocommerce_cart_hash"');
    expect(built.rules.cache.expression).toContain('and not http.cookie contains "woocommerce_cart_hash"');
  });

  it("a personal-cookie request (woocommerce_cart_hash, wordpress_logged_in_) is claimed by the BYPASS rule and refused by the CACHE rule", () => {
    const built = buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600 });
    if (!built.ok) throw new Error(built.reason);
    for (const cookieFragment of [
      "woocommerce_cart_hash",
      "wordpress_logged_in_",
      "wp_woocommerce_session_",
      "comment_author_",
      "wp-postpass_",
      "woocommerce_recently_viewed",
      "store_notice",
    ]) {
      // The bypass rule's cookie group CONTAINS the fragment (ORed) and carries cache:false ...
      expect(built.rules.bypass.expression).toContain(`or http.cookie contains "${cookieFragment}"`.replace(/^or /, ""));
      expect(built.rules.bypass.action_parameters).toEqual({ cache: false });
      // ... and the cache rule NEGATES the same fragment, so the two can never both match one request.
      expect(built.rules.cache.expression).toContain(`and not http.cookie contains "${cookieFragment}"`);
    }
    // Both rules are scoped to HTML-ish pages on one of our hosts, so a logged-in admin's static
    // assets are left to Cloudflare's default (not bypassed).
    expect(built.rules.bypass.expression).toContain(`${EXPECTED_HOST_CLAUSE} and (http.request.uri.path.extension in {"" "php" "html"})`);
  });

  it("enabled:false produces two disabled rules; absent means enabled", () => {
    const disabled = buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600, enabled: false });
    expect(disabled.ok && disabled.rules.cache.enabled).toBe(false);
    expect(disabled.ok && disabled.rules.bypass.enabled).toBe(false);
    const enabled = buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600 });
    expect(enabled.ok && enabled.rules.cache.enabled).toBe(true);
    expect(enabled.ok && enabled.rules.bypass.enabled).toBe(true);
  });

  it("clamps the edge TTL to 60..3600 whole seconds", () => {
    expect(clampEdgeCacheTtl(600)).toBe(600);
    expect(clampEdgeCacheTtl(10)).toBe(60);
    expect(clampEdgeCacheTtl(0)).toBe(60);
    expect(clampEdgeCacheTtl(-5)).toBe(60);
    expect(clampEdgeCacheTtl(99_999)).toBe(3600);
    expect(clampEdgeCacheTtl(600.4)).toBe(600);
    expect(clampEdgeCacheTtl(Number.NaN)).toBeNull();
    expect(clampEdgeCacheTtl(Number.POSITIVE_INFINITY)).toBeNull();
    // The builder still runs the clamp (a non-finite TTL is refused) but the TTL never reaches a
    // rule: the origin's s-maxage is the edge TTL now, so 86400s and 600s build the SAME rules.
    const clamped = buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 86_400 });
    expect(clamped).toEqual(buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600 }));
    expect(clamped.ok && "default" in (clamped.rules.cache.action_parameters.edge_ttl as Record<string, unknown>)).toBe(false);
    expect(buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: Number.NaN }).ok).toBe(false);
  });

  it("refuses any suffix that is not exactly -production.<zone> (nothing unsafe reaches the quoted expression)", () => {
    for (const hostSuffix of [
      "",
      "example.com",
      "-production.com",
      "-production.Example.com",
      '-production.example.com") or (true',
      "-production.example.com\\",
      " -production.example.com",
      "-staging.example.com",
    ]) {
      expect(buildEdgeCacheRules({ hostSuffix, edgeTtlSeconds: 600 }).ok).toBe(false);
    }
  });

  it("the host clause is the exact twin text, for a .com zone and for a multi-label agency zone", () => {
    const built = buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600 });
    if (!built.ok) throw new Error(built.reason);
    expect(built.rules.cache.expression).toContain(EXPECTED_HOST_CLAUSE);
    expect(built.rules.bypass.expression).toContain(EXPECTED_HOST_CLAUSE);
    // A real agency zone has a multi-label public suffix; the zone name lands in the clause four
    // times, so pin that shape too.
    const agency = buildEdgeCacheRules({ hostSuffix: "-production.sbmstudio.com.au", edgeTtlSeconds: 600 });
    if (!agency.ok) throw new Error(agency.reason);
    expect(agency.rules.bypass.expression).toContain(
      '(ends_with(http.host, "-production.sbmstudio.com.au") or (not http.host contains ".sbmstudio.com.au" ' +
        'and http.host ne "sbmstudio.com.au" and not starts_with(http.host, "media.")))',
    );
    // Cloudflare caps a rule expression at 4096 characters; the host clause must not push us near it.
    expect(agency.rules.cache.expression.length).toBeLessThan(2000);
  });
});

// ── WHICH HOSTS the rules claim (agency zone) ──────────────────────────────────────────
// The same request-level proof the orchestrator's twin test runs, against the text THIS Worker
// emits. The evaluator below understands exactly the clause grammar the builder produces — it is
// not a Rules-language engine, it exists so "a customer domain is cached, the agency's own hosts
// are not" is pinned as a REQUEST and not only as a string.

interface SimulatedRequest {
  method: string;
  host: string;
  path: string;
  query: string;
  cookie: string;
}

function pathExtension(path: string): string {
  const lastSegment = path.slice(path.lastIndexOf("/") + 1);
  const dot = lastSegment.lastIndexOf(".");
  if (dot < 0) {
    return "";
  }
  return lastSegment.slice(dot + 1);
}

/**
 * Split `text` on every top-level occurrence of `separator` (never inside a parenthesised group).
 * Returns a single-element array when the separator appears only inside groups.
 */
function splitTopLevel(text: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]!;
    if (char === "(") depth += 1;
    if (char === ")") depth -= 1;
    if (depth === 0 && text.startsWith(separator, index)) {
      parts.push(current);
      current = "";
      index += separator.length - 1;
      continue;
    }
    current += char;
  }
  parts.push(current);
  return parts;
}

/**
 * Drop the parentheses that wrap the WHOLE text, repeatedly. A naive slice(1, -1) would corrupt
 * `(a) or (b)` — whose first and last characters are also parens but which is not one group — so
 * each round first checks that the opening paren's partner is the final character.
 */
function stripOuterParens(text: string): string {
  let current = text.trim();
  while (current.startsWith("(") && current.endsWith(")")) {
    let depth = 0;
    let closesAtTheEnd = true;
    for (let index = 0; index < current.length; index += 1) {
      if (current[index] === "(") depth += 1;
      if (current[index] === ")") {
        depth -= 1;
        if (depth === 0 && index < current.length - 1) {
          closesAtTheEnd = false;
          break;
        }
      }
    }
    if (!closesAtTheEnd) {
      return current;
    }
    current = current.slice(1, -1).trim();
  }
  return current;
}

function evaluateClause(clause: string, request: SimulatedRequest): boolean {
  const text = stripOuterParens(clause);
  // Cloudflare's precedence: `not` binds tighter than `and`, which binds tighter than `or`. Split in
  // the same order, so the host clause's `A or (B and C and D)` is read the way Cloudflare reads it.
  const orParts = splitTopLevel(text, " or ");
  if (orParts.length > 1) {
    return orParts.some((part) => evaluateClause(part, request));
  }
  const andParts = splitTopLevel(text, " and ");
  if (andParts.length > 1) {
    return andParts.every((part) => evaluateClause(part, request));
  }
  if (text.startsWith("not ")) {
    return !evaluateClause(text.slice(4), request);
  }
  let match = /^http\.request\.method in \{(.+)\}$/.exec(text);
  if (match) {
    return match[1]!.split(" ").map((item) => item.replace(/"/g, "")).includes(request.method);
  }
  match = /^http\.request\.uri\.path\.extension in \{(.+)\}$/.exec(text);
  if (match) {
    return match[1]!.split(" ").map((item) => item.replace(/"/g, "")).includes(pathExtension(request.path));
  }
  match = /^ends_with\(http\.host, "(.+)"\)$/.exec(text);
  if (match) {
    return request.host.endsWith(match[1]!);
  }
  match = /^starts_with\(http\.host, "(.+)"\)$/.exec(text);
  if (match) {
    return request.host.startsWith(match[1]!);
  }
  match = /^http\.host contains "(.+)"$/.exec(text);
  if (match) {
    return request.host.includes(match[1]!);
  }
  match = /^http\.host ne "(.+)"$/.exec(text);
  if (match) {
    return request.host !== match[1]!;
  }
  match = /^starts_with\(http\.request\.uri\.path, "(.+)"\)$/.exec(text);
  if (match) {
    return request.path.startsWith(match[1]!);
  }
  match = /^http\.request\.uri\.query contains "(.+)"$/.exec(text);
  if (match) {
    return request.query.includes(match[1]!);
  }
  match = /^http\.cookie contains "(.+)"$/.exec(text);
  if (match) {
    return request.cookie.includes(match[1]!);
  }
  throw new Error(`evaluator does not understand clause: ${clause}`);
}

describe("the edge-cache host predicate, as requests against an agency zone", () => {
  const built = buildEdgeCacheRules({ hostSuffix: "-production.sbmstudio.com.au", edgeTtlSeconds: 600 });
  if (!built.ok) throw new Error(built.reason);
  const rules = built.rules;

  const ANON_PAGE: SimulatedRequest = { method: "GET", host: "", path: "/shop/", query: "", cookie: "_ga=GA1.1" };

  /** The cache setting the matching rule applies: "cache" / "bypass" / "none" (Cloudflare default). */
  function selectedAction(request: SimulatedRequest): "cache" | "bypass" | "none" {
    const bypassMatches = evaluateClause(rules.bypass.expression, request);
    const cacheMatches = evaluateClause(rules.cache.expression, request);
    expect(bypassMatches && cacheMatches).toBe(false);
    if (bypassMatches) return "bypass";
    if (cacheMatches) return "cache";
    return "none";
  }

  it("CACHES a customer domain onboarded as a custom hostname, and the internal -production hosts", () => {
    for (const host of ["bsodigital.com.au", "www.bsodigital.com.au", "shop.example.net"]) {
      expect(selectedAction({ ...ANON_PAGE, host })).toBe("cache");
      expect(selectedAction({ ...ANON_PAGE, host, cookie: "woocommerce_cart_hash=deadbeef" })).toBe("bypass");
      expect(selectedAction({ ...ANON_PAGE, host, path: "/wp-admin/" })).toBe("none");
      expect(selectedAction({ ...ANON_PAGE, host, path: "/style.css" })).toBe("none");
    }
    expect(selectedAction({ ...ANON_PAGE, host: "crownbedding-production.sbmstudio.com.au" })).toBe("cache");
  });

  it("CACHES NOTHING on the agency's own zone — apex, www, the fallback origin and the cell origin", () => {
    // Caching the fallback origin or a cell origin would be a genuinely bad failure mode: those
    // hosts are how Cloudflare reaches the cell, so a cached copy there poisons every custom
    // hostname riding on it.
    for (const host of [
      "sbmstudio.com.au",
      "www.sbmstudio.com.au",
      "host.sbmstudio.com.au",
      "cell-australia-southeast2-origin.sbmstudio.com.au",
      "sftp.sbmstudio.com.au",
      "staging-crownbedding.sbmstudio.com.au",
      "pma-crownbedding.sbmstudio.com.au",
      // A decorated form of an in-zone host still fails closed — that is why the clause is
      // `contains ".<zone>"` rather than `ends_with`.
      "host.sbmstudio.com.au.",
    ]) {
      expect(selectedAction({ ...ANON_PAGE, host })).toBe("none");
      expect(selectedAction({ ...ANON_PAGE, host, cookie: "wordpress_logged_in_x=admin" })).toBe("none");
    }
  });

  it("CACHES NOTHING on a branded media host (served by the media Worker from R2, not our WordPress origin)", () => {
    expect(selectedAction({ ...ANON_PAGE, host: "media.bsodigital.com.au", path: "/crownbedding/2026/07/" })).toBe("none");
    expect(selectedAction({ ...ANON_PAGE, host: "media.bsodigital.com.au", path: "/crownbedding/a.jpg" })).toBe("none");
    // The exclusion is the literal `media.` label, so a customer domain merely CONTAINING "media"
    // is unaffected.
    expect(selectedAction({ ...ANON_PAGE, host: "mediacompany.com.au" })).toBe("cache");
    expect(selectedAction({ ...ANON_PAGE, host: "social-media.example.net" })).toBe("cache");
  });
});

describe("edge-cache drift check", () => {
  it("jsonValuesEqual ignores object key order but not array order or types", () => {
    expect(jsonValuesEqual({ a: 1, b: { c: [1, 2] } }, { b: { c: [1, 2] }, a: 1 })).toBe(true);
    expect(jsonValuesEqual([1, 2], [2, 1])).toBe(false);
    expect(jsonValuesEqual({ a: 1 }, { a: "1" })).toBe(false);
    expect(jsonValuesEqual({ a: 1 }, { a: 1, b: undefined })).toBe(false);
    expect(jsonValuesEqual(null, {})).toBe(false);
    expect(jsonValuesEqual(undefined, { cache: true })).toBe(false);
  });

  it("edgeCacheRuleDrifted compares action, expression, enabled and action_parameters", () => {
    const built = buildEdgeCacheRules({ hostSuffix: "-production.example.com", edgeTtlSeconds: 600 });
    if (!built.ok) throw new Error(built.reason);
    const desired = built.rules.cache;
    // The bypass rule: a live copy "fixed" to cache:true is drift back to cache:false.
    expect(edgeCacheRuleDrifted({ ...built.rules.bypass }, built.rules.bypass)).toBe(false);
    expect(edgeCacheRuleDrifted({ ...built.rules.bypass, action_parameters: { cache: true } }, built.rules.bypass)).toBe(true);
    expect(edgeCacheRuleDrifted({ ...desired }, desired)).toBe(false);
    expect(edgeCacheRuleDrifted({ ...desired, enabled: false }, desired)).toBe(true);
    expect(edgeCacheRuleDrifted({ ...desired, expression: "true" }, desired)).toBe(true);
    expect(edgeCacheRuleDrifted({ ...desired, action: "set_config" }, desired)).toBe(true);
    expect(edgeCacheRuleDrifted({ ...desired, action_parameters: { cache: false } }, desired)).toBe(true);
    expect(edgeCacheRuleDrifted({ ...desired, action_parameters: undefined }, desired)).toBe(true);
  });
});

// ── gcp-instance-set-metadata: the placeholder substitution (the op's security boundary) ─────
// Pure-function pins on substituteMetadataPlaceholders + mergeMetadataItems. The substitution is
// NOT a template engine: a fixed allowlist, a single left-to-right scan, plain string slicing, and
// every substituted value charset-checked — so an unknown token, a half token, a missing secret or
// an unsafe value is a hard refusal, and a detail never carries a value (only names / offsets).
describe("substituteMetadataPlaceholders: fixed allowlist, fail-closed", () => {
  // Only the S3_* fields matter here; the rest of Env is irrelevant to the function under test.
  function s3Env(overrides: Partial<Env> = {}): Env {
    return {
      S3_ACCESS_KEY_ID: "AKIAFIXTUREEXAMPLE00",
      S3_SECRET_ACCESS_KEY: "fixture+secret/base64=",
      S3_BUCKET: "agency-backups",
      S3_REGION: "auto",
      S3_ENDPOINT: "https://acct123.r2.example.test/",
      ...overrides,
    } as unknown as Env;
  }

  it("exposes exactly the six backup placeholders — the five Tier-2 values plus Tier-1's own bucket", () => {
    expect([...METADATA_PLACEHOLDER_NAMES]).toEqual([
      "@@DY_T2_S3_ACCESS_KEY_ID@@",
      "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
      "@@DY_T2_S3_ENDPOINT@@",
      "@@DY_T2_S3_BUCKET@@",
      "@@DY_T2_S3_REGION@@",
      // hub#64: restic REQUIRES delete (its per-run lock object, and forget/prune retention, are
      // both implemented by deleting), so Tier-1 cannot share Tier-2's deliberately locked bucket.
      "@@DY_T1_S3_BUCKET@@",
    ]);
    expect(METADATA_PLACEHOLDER_NAMES).toHaveLength(6);
  });

  it("hub#64: S3_BACKUP_BUCKET UNSET falls back to S3_BUCKET, so both tiers keep sharing one bucket", () => {
    // The fallback is load-bearing: every agency that does nothing must keep exactly the behaviour
    // it has today. Both placeholders therefore resolve to the same value.
    expect(substituteMetadataPlaceholders("T1='@@DY_T1_S3_BUCKET@@' T2='@@DY_T2_S3_BUCKET@@'", s3Env())).toEqual({
      ok: true,
      value: "T1='agency-backups' T2='agency-backups'",
      substituted: ["@@DY_T1_S3_BUCKET@@", "@@DY_T2_S3_BUCKET@@"],
      // EQUAL reported values are what the fallback looks like from the control plane, and the only
      // way to see it without an SSH session: the orchestrator says so in the provisioning summary.
      placeholderValues: { "@@DY_T1_S3_BUCKET@@": "agency-backups", "@@DY_T2_S3_BUCKET@@": "agency-backups" },
    });
    // An EMPTY string is "unset" too — an empty bucket name would produce a node that looks
    // provisioned and never backs up, which is the failure the whole op exists to end.
    expect(substituteMetadataPlaceholders("T1='@@DY_T1_S3_BUCKET@@'", s3Env({ S3_BACKUP_BUCKET: "" }))).toEqual({
      ok: true,
      value: "T1='agency-backups'",
      substituted: ["@@DY_T1_S3_BUCKET@@"],
      placeholderValues: { "@@DY_T1_S3_BUCKET@@": "agency-backups" },
    });
  });

  it("hub#64: S3_BACKUP_BUCKET SET is used for Tier-1 only — Tier-2 still gets S3_BUCKET", () => {
    const verdict = substituteMetadataPlaceholders(
      "T1='@@DY_T1_S3_BUCKET@@' T2='@@DY_T2_S3_BUCKET@@' E='@@DY_T2_S3_ENDPOINT@@' A='@@DY_T2_S3_ACCESS_KEY_ID@@'",
      s3Env({ S3_BACKUP_BUCKET: "agency-backups-tier1" }),
    );
    expect(verdict).toEqual({
      ok: true,
      // The two buckets differ; the credential and the endpoint are shared, which is the whole
      // design — one object-store credential, two buckets with opposite retention policies.
      value:
        "T1='agency-backups-tier1' T2='agency-backups' E='https://acct123.r2.example.test' A='AKIAFIXTUREEXAMPLE00'",
      substituted: ["@@DY_T1_S3_BUCKET@@", "@@DY_T2_S3_BUCKET@@", "@@DY_T2_S3_ENDPOINT@@", "@@DY_T2_S3_ACCESS_KEY_ID@@"],
      // The two buckets DIFFER, which is how a set S3_BACKUP_BUCKET reads from the control plane.
      // The access key id was substituted but is NOT reported — it is half of a credential.
      placeholderValues: {
        "@@DY_T1_S3_BUCKET@@": "agency-backups-tier1",
        "@@DY_T2_S3_BUCKET@@": "agency-backups",
        "@@DY_T2_S3_ENDPOINT@@": "https://acct123.r2.example.test",
      },
    });
  });

  // ── which resolved VALUES may be reported (hub#64) ─────────────────────────────────────
  // The allowlist is the boundary. A placeholder it does not name must be ABSENT from the reported
  // map — not masked, not truncated — and the DEFAULT for any name must be "not reported", so that a
  // seventh placeholder added to METADATA_PLACEHOLDER_NAMES cannot start echoing a secret by itself.

  it("PLACEHOLDER_VALUES_SAFE_TO_ECHO is exactly the four NON-SECRET names — neither credential half is on it", () => {
    expect([...PLACEHOLDER_VALUES_SAFE_TO_ECHO]).toEqual([
      "@@DY_T1_S3_BUCKET@@",
      "@@DY_T2_S3_BUCKET@@",
      "@@DY_T2_S3_ENDPOINT@@",
      "@@DY_T2_S3_REGION@@",
    ]);
    // Stated as an absence, deliberately: an access key id is half of a credential, not a label.
    expect(PLACEHOLDER_VALUES_SAFE_TO_ECHO).not.toContain("@@DY_T2_S3_ACCESS_KEY_ID@@");
    expect(PLACEHOLDER_VALUES_SAFE_TO_ECHO).not.toContain("@@DY_T2_S3_SECRET_ACCESS_KEY@@");
  });

  it("every placeholder NOT on the echo allowlist is ABSENT from placeholderValues — so a new one is silent by default", () => {
    // Swept over METADATA_PLACEHOLDER_NAMES rather than written out, so a SEVENTH placeholder added
    // later is covered by this test the day it is added: unless it is also put on the echo
    // allowlist, its value must not appear. That is the "a hypothetical new secret placeholder is
    // not echoed by default" property, as a test rather than a reading of the code.
    for (const placeholder of METADATA_PLACEHOLDER_NAMES) {
      const verdict = substituteMetadataPlaceholders(`X='${placeholder}'`, s3Env({ S3_BACKUP_BUCKET: "agency-backups-tier1" }));
      expect(verdict.ok).toBe(true);
      if (!verdict.ok) continue;

      const mayEcho = (PLACEHOLDER_VALUES_SAFE_TO_ECHO as readonly string[]).includes(placeholder);
      expect(Object.keys(verdict.placeholderValues), placeholder).toEqual(mayEcho ? [placeholder] : []);
    }
  });

  it("a script carrying ALL SIX placeholders reports the four non-secret values and NEITHER credential, by key or by value", () => {
    const script =
      "A='@@DY_T2_S3_ACCESS_KEY_ID@@' S='@@DY_T2_S3_SECRET_ACCESS_KEY@@' E='@@DY_T2_S3_ENDPOINT@@' " +
      "B='@@DY_T2_S3_BUCKET@@' R='@@DY_T2_S3_REGION@@' T1='@@DY_T1_S3_BUCKET@@'";
    const verdict = substituteMetadataPlaceholders(script, s3Env({ S3_BACKUP_BUCKET: "agency-backups-tier1" }));
    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;

    expect(verdict.placeholderValues).toEqual({
      "@@DY_T2_S3_ENDPOINT@@": "https://acct123.r2.example.test",
      "@@DY_T2_S3_BUCKET@@": "agency-backups",
      "@@DY_T2_S3_REGION@@": "auto",
      "@@DY_T1_S3_BUCKET@@": "agency-backups-tier1",
    });
    // Absence by KEY and by VALUE: the credential is in `value` (it has to be — that is the point of
    // the substitution) and must not have leaked into the reported map by any route.
    const reportedText = JSON.stringify(verdict.placeholderValues);
    expect(reportedText).not.toContain("AKIAFIXTUREEXAMPLE00");
    expect(reportedText).not.toContain("fixture+secret/base64=");
    expect(verdict.value).toContain("AKIAFIXTUREEXAMPLE00");
  });

  // ── the two bucket placeholders must hold a BUCKET NAME, not a URL (hub#64) ─────────────

  it("hub#64: an endpoint URL in S3_BACKUP_BUCKET is REFUSED naming that variable and saying it looks like a URL", () => {
    // The real mistake, 2026-10-06: the agency's S3 API URL was pasted into S3_BACKUP_BUCKET. Every
    // character of it is inside BOOT_SAFE_VALUE_RE, so only a shape check catches it — and without
    // one the node would have been published with
    // DY_T1_S3_BUCKET='https://<acct>.r2.cloudflarestorage.com'.
    const url = "https://043e3bdaf4a6849a2d745269084c0e5f.r2.cloudflarestorage.com";
    const verdict = substituteMetadataPlaceholders("T1='@@DY_T1_S3_BUCKET@@'", s3Env({ S3_BACKUP_BUCKET: url }));
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.detail).toMatch(/^S3_BACKUP_BUCKET looks like an endpoint URL, not a bucket name/);
    expect(verdict.detail).toMatch(/Cloudflare's R2 dashboard labels the endpoint-plus-bucket URL "the S3 API"/);
    expect(verdict.detail).toMatch(/leave the URL in S3_ENDPOINT/);
    // The offending value is named by VARIABLE, never echoed — the same discipline as every other
    // guard here, even though a bucket name is not a credential.
    expect(verdict.detail).not.toContain(url);
    expect(verdict.detail).not.toContain("043e3bdaf4a6849a2d745269084c0e5f");
  });

  it("hub#64: a URL in S3_BUCKET is refused under S3_BUCKET's own name — Tier-2's bucket gets the same check", () => {
    const verdict = substituteMetadataPlaceholders("T2='@@DY_T2_S3_BUCKET@@'", s3Env({ S3_BUCKET: "https://acct123.r2.example.test" }));
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.detail).toMatch(/^S3_BUCKET looks like an endpoint URL, not a bucket name/);
    expect(verdict.detail).not.toContain("acct123");
  });

  it("hub#64: a bucket value that is not a URL but is not a bucket name either is refused by SHAPE, naming the variable only", () => {
    const notBucketNames: Array<[string, RegExp]> = [
      ["ab", /^S3_BACKUP_BUCKET is not a valid S3\/R2 bucket name — it must be 3 to 63 characters/],
      ["a".repeat(64), /^S3_BACKUP_BUCKET is not a valid S3\/R2 bucket name — it must be 3 to 63 characters/],
      ["Agency-Backups", /it must be 3 to 63 characters of lowercase letters/], // uppercase
      ["-agency-backups", /beginning and ending with a letter or digit/],
      ["agency-backups-", /beginning and ending with a letter or digit/],
      [".agency.backups", /beginning and ending with a letter or digit/],
      ["agency..backups", /may not contain two adjacent dots/],
      ["192.168.5.4", /may not be formatted as an IPv4 address/],
    ];
    for (const [value, expected] of notBucketNames) {
      const verdict = substituteMetadataPlaceholders("T1='@@DY_T1_S3_BUCKET@@'", s3Env({ S3_BACKUP_BUCKET: value }));
      expect(verdict.ok, value).toBe(false);
      if (verdict.ok) continue;
      expect(verdict.detail, value).toMatch(expected);
      expect(verdict.detail, value).not.toContain(value);
    }
  });

  it("hub#64: real bucket names PASS — dotted, hyphenated, digits, and the minimum length", () => {
    const realBucketNames = ["sbmstudio", "sbmstudio-backups-tier1", "doubleyoup-agency-backups", "my.bucket.name", "a1b", "123bucket"];
    for (const value of realBucketNames) {
      const verdict = substituteMetadataPlaceholders("T1='@@DY_T1_S3_BUCKET@@'", s3Env({ S3_BACKUP_BUCKET: value }));
      expect(verdict.ok, value).toBe(true);
      if (!verdict.ok) continue;
      expect(verdict.value).toBe(`T1='${value}'`);
      expect(verdict.placeholderValues["@@DY_T1_S3_BUCKET@@"]).toBe(value);
    }
  });

  it("hub#64: an S3_ENDPOINT carrying a PATH is refused — the node joins it to the bucket name", () => {
    // The opposite-direction mistake: an endpoint SHOULD be a URL, but `https://host/<bucket>` makes
    // the bucket appear twice in the repository path file.sh composes.
    const verdict = substituteMetadataPlaceholders("E='@@DY_T2_S3_ENDPOINT@@'", s3Env({ S3_ENDPOINT: "https://acct123.r2.example.test/sbmstudio" }));
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.detail).toMatch(/^S3_ENDPOINT is not a bare endpoint URL/);
    expect(verdict.detail).toMatch(/scheme:\/\/host with an optional port and NOTHING after it/);
    expect(verdict.detail).not.toContain("sbmstudio");
    // A bare host, a host with a port, and the trailing-slash form all still pass.
    for (const endpoint of ["https://acct123.r2.example.test", "https://acct123.r2.example.test/", "http://minio.internal:9000"]) {
      expect(substituteMetadataPlaceholders("E='@@DY_T2_S3_ENDPOINT@@'", s3Env({ S3_ENDPOINT: endpoint })).ok, endpoint).toBe(true);
    }
  });

  it("hub#64: an unsafe S3_BACKUP_BUCKET is refused under ITS OWN name, never S3_BUCKET's", () => {
    // The charset guard must name the variable the operator has to fix. Reporting a bad
    // S3_BACKUP_BUCKET as "S3_BUCKET" would send them to the wrong secret.
    const verdict = substituteMetadataPlaceholders("T1='@@DY_T1_S3_BUCKET@@'", s3Env({ S3_BACKUP_BUCKET: "bucket with a space" }));
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.detail).toMatch(/^S3_BACKUP_BUCKET holds a character outside/);
    expect(verdict.detail).not.toContain("bucket with a space");
  });

  it("substitutes every allowlisted placeholder from the Worker's S3_* values (endpoint trailing slash stripped), reporting each NAME once", () => {
    const script =
      "A='@@DY_T2_S3_ACCESS_KEY_ID@@' S='@@DY_T2_S3_SECRET_ACCESS_KEY@@' E='@@DY_T2_S3_ENDPOINT@@' " +
      "B='@@DY_T2_S3_BUCKET@@' R='@@DY_T2_S3_REGION@@' B2='@@DY_T2_S3_BUCKET@@'";
    expect(substituteMetadataPlaceholders(script, s3Env())).toEqual({
      ok: true,
      value:
        "A='AKIAFIXTUREEXAMPLE00' S='fixture+secret/base64=' E='https://acct123.r2.example.test' " +
        "B='agency-backups' R='auto' B2='agency-backups'",
      substituted: [
        "@@DY_T2_S3_ACCESS_KEY_ID@@",
        "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
        "@@DY_T2_S3_ENDPOINT@@",
        "@@DY_T2_S3_BUCKET@@",
        "@@DY_T2_S3_REGION@@",
      ],
      // Both credentials were substituted into the value; NEITHER is reported.
      placeholderValues: {
        "@@DY_T2_S3_ENDPOINT@@": "https://acct123.r2.example.test",
        "@@DY_T2_S3_BUCKET@@": "agency-backups",
        "@@DY_T2_S3_REGION@@": "auto",
      },
    });
  });

  it("a value with NO placeholder is returned untouched and reads no S3_* variable at all", () => {
    const script = "#!/bin/bash\necho 'no placeholders here, even an email like a@b.c is fine'\n";
    expect(substituteMetadataPlaceholders(script, {} as unknown as Env)).toEqual({
      ok: true,
      value: script,
      substituted: [],
      placeholderValues: {},
    });
  });

  it("an UNKNOWN @@TOKEN@@ is refused by name — nothing else about the value is echoed", () => {
    const verdict = substituteMetadataPlaceholders("X='@@DY_T2_S3_BUCKET@@'\nY='@@FOO@@'\nsentinel-must-not-echo\n", s3Env());
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.detail).toMatch(/^the placeholder @@FOO@@ is not on this Worker's allowlist \(@@DY_T2_S3_ACCESS_KEY_ID@@, /);
    expect(verdict.detail).not.toContain("sentinel-must-not-echo");
    expect(verdict.detail).not.toContain("agency-backups");
  });

  it("a half-formed or run-together sigil is refused by OFFSET only (no surrounding text), including a bare trailing @@", () => {
    // Two placeholders run together: the first substitutes, the leftover "DY_T2_S3_REGION@@" ends in a
    // bare sigil that starts no placeholder.
    const runTogether = substituteMetadataPlaceholders("@@DY_T2_S3_BUCKET@@DY_T2_S3_REGION@@", s3Env());
    expect(runTogether.ok).toBe(false);
    if (!runTogether.ok) {
      expect(runTogether.detail).toMatch(/^a "@@" at offset 34 does not start an allowlisted placeholder/);
    }
    const halfToken = substituteMetadataPlaceholders("echo '@@DY_T2_S3_BUCKET' secret-text", s3Env());
    expect(halfToken.ok).toBe(false);
    if (!halfToken.ok) {
      expect(halfToken.detail).toMatch(/^a "@@" at offset 6 does not start an allowlisted placeholder/);
      expect(halfToken.detail).not.toContain("secret-text");
    }
    // Case matters: the allowlist is exact.
    expect(substituteMetadataPlaceholders("@@dy_t2_s3_bucket@@", s3Env()).ok).toBe(false);
    // The orchestrator's own render marker must never reach a node unrendered.
    expect(substituteMetadataPlaceholders("# @@DY_INJECTED_VALUES@@\n", s3Env()).ok).toBe(false);
  });

  it("a MISSING required secret fails naming the variable(s) — never an empty substitution", () => {
    const one = substituteMetadataPlaceholders("B='@@DY_T2_S3_BUCKET@@'", s3Env({ S3_SECRET_ACCESS_KEY: undefined }));
    expect(one).toEqual({
      ok: false,
      detail:
        "S3_SECRET_ACCESS_KEY is not configured on this Worker — a @@DY_T2_S3_*@@ placeholder needs the agency's " +
        "object-store credential; refusing to write a boot script with an empty one.",
    });
    const all = substituteMetadataPlaceholders("B='@@DY_T2_S3_BUCKET@@'", {} as unknown as Env);
    expect(all.ok).toBe(false);
    if (!all.ok) expect(all.detail).toMatch(/^S3_ACCESS_KEY_ID \/ S3_SECRET_ACCESS_KEY \/ S3_BUCKET are not configured/);
    const empty = substituteMetadataPlaceholders("B='@@DY_T2_S3_BUCKET@@'", s3Env({ S3_ACCESS_KEY_ID: "" }));
    expect(empty.ok).toBe(false);
    if (!empty.ok) expect(empty.detail).toMatch(/^S3_ACCESS_KEY_ID is not configured/);
  });

  it("S3_ENDPOINT unset yields '' (native AWS per the backup runner) and S3_REGION unset yields us-east-1 (the Worker's own presign default)", () => {
    expect(
      substituteMetadataPlaceholders("E='@@DY_T2_S3_ENDPOINT@@' R='@@DY_T2_S3_REGION@@'", s3Env({ S3_ENDPOINT: undefined, S3_REGION: undefined })),
    ).toEqual({
      ok: true,
      value: "E='' R='us-east-1'",
      substituted: ["@@DY_T2_S3_ENDPOINT@@", "@@DY_T2_S3_REGION@@"],
      // "" is a MEANING here (native AWS S3), not a missing value, so it is reported as it stands.
      placeholderValues: { "@@DY_T2_S3_ENDPOINT@@": "", "@@DY_T2_S3_REGION@@": "us-east-1" },
    });
  });

  it("an S3_* value outside the boot-safe charset is refused naming the ENV VAR only (never the value) — and all of them are checked whenever any placeholder is present", () => {
    const unsafeCases: Array<[Partial<Env>, string]> = [
      [{ S3_BUCKET: "agency@@backups" }, "S3_BUCKET"], // a value may never carry the sigil
      [{ S3_SECRET_ACCESS_KEY: "line1\nline2" }, "S3_SECRET_ACCESS_KEY"], // newline = a second script line
      [{ S3_SECRET_ACCESS_KEY: "it's" }, "S3_SECRET_ACCESS_KEY"], // breaks out of a single-quoted word
      [{ S3_ACCESS_KEY_ID: "$HOME" }, "S3_ACCESS_KEY_ID"], // shell expansion
      [{ S3_ENDPOINT: "https://x.example.test/`id`" }, "S3_ENDPOINT"], // command substitution
      [{ S3_REGION: "a".repeat(513) }, "S3_REGION"], // over the length cap
    ];
    for (const [overrides, envName] of unsafeCases) {
      // Only the BUCKET placeholder is referenced; the unsafe value is elsewhere — still refused.
      const verdict = substituteMetadataPlaceholders("B='@@DY_T2_S3_BUCKET@@'", s3Env(overrides));
      expect(verdict.ok, JSON.stringify(Object.keys(overrides))).toBe(false);
      if (verdict.ok) continue;
      expect(verdict.detail).toMatch(new RegExp(`^${envName} holds a character outside`));
      for (const value of Object.values(overrides)) {
        expect(verdict.detail).not.toContain(String(value));
      }
    }
  });
});

describe("mergeMetadataItems: unrelated keys survive, in place", () => {
  it("replaces a named key in place, keeps every other key verbatim, and appends new keys in request order", () => {
    const existing = [
      { key: "enable-oslogin", value: "TRUE" },
      { key: "startup-script", value: "old" },
      { key: "dy-cell-bundle", value: "20260916-9c25cfd" },
    ];
    expect(
      mergeMetadataItems(existing, [
        { key: "dy-backup-epoch", value: "2026-10-05" },
        { key: "startup-script", value: "new" },
      ]),
    ).toEqual([
      { key: "enable-oslogin", value: "TRUE" },
      { key: "startup-script", value: "new" },
      { key: "dy-cell-bundle", value: "20260916-9c25cfd" },
      { key: "dy-backup-epoch", value: "2026-10-05" },
    ]);
  });

  it("an instance with no items yet gets exactly the updates; an existing empty-valued key is kept as ''", () => {
    expect(mergeMetadataItems([], [{ key: "startup-script", value: "new" }])).toEqual([{ key: "startup-script", value: "new" }]);
    expect(mergeMetadataItems([{ key: "serial-port-enable" }], [{ key: "startup-script", value: "new" }])).toEqual([
      { key: "serial-port-enable", value: "" },
      { key: "startup-script", value: "new" },
    ]);
  });
});
