// Direction-B ACTUATION (agency Worker side). Runs a verified job using the AGENCY's
// OWN credentials — R2_PROVISION_API_TOKEN to create an R2 bucket, CF_DNS_API_TOKEN to
// upsert a DNS record / purge cache / upsert the edge page-cache rule in one of the agency's
// zones, CELL_AGENT_TOKEN to run
// a wp-cli command on the agency's own cell via its on-VM cell-agent (the first "heavy"
// data-plane op), the agency's S3_* object-store credential to PRESIGN a URL the cell
// uploads a DB dump to (`db-export`) or downloads one from (`db-import`), and — for the
// `gcp-*` ops — the agency's GCP_SERVICE_ACCOUNT_KEY to mint a Google access token and
// create Compute Engine resources (a VM, a VPC + subnet, a firewall rule, a static address,
// a Cloud Router + NAT) in the agency's own project. There is deliberately NO platform credential anywhere in
// this Worker to fall back to: if the agency's token is missing or unauthorized, actuation
// fails cleanly rather than reaching for ours.
//
// Every actuator here runs ONLY after dispatch-verify.ts::verifyDispatch returned ok:true,
// the nonce was consumed, and the op's params validated (index.ts::handleActuate via
// ops.ts). Actuators return a structured result and NEVER throw for a Cloudflare-side
// failure: the route answers 200 with ok:false + detail so the orchestrator classifies
// the failure, not the HTTP layer.
//
// Worker-native only: fetch. Cloudflare request BODIES are always JSON.stringify'd
// objects and QUERY strings always go through URLSearchParams — no value from a job is
// ever string-interpolated into a URL.

import type { Env } from "./env.js";
import type {
  DnsRecordUpsertParams,
  DnsRecordDeleteParams,
  CachePurgeParams,
  CacheRuleUpsertParams,
  CfTunnelCreateParams,
  CfTunnelConfigParams,
  CfTunnelDeleteParams,
  WpCliParams,
  DbExportParams,
  DbImportParams,
  GcpInstanceCreateParams,
  GcpNetworkCreateParams,
  GcpFirewallCreateParams,
  GcpAddressCreateParams,
  GcpRouterNatCreateParams,
  GcpFirewallGetParams,
  GcpRouterGetParams,
  GcpInstancesListParams,
  GcpInstanceDeleteParams,
  GcpAddressDeleteParams,
  GcpFirewallDeleteParams,
  GcpRouterDeleteParams,
  GcpNetworkDeleteParams,
  GcpInstanceSetMetadataParams,
  GcpInstanceMetadataItem,
  GcpInstanceRestartParams,
  ProvisionSshKeysParams,
  WafRuleUpsertParams,
  WafEdgeSyncParams,
  WafEdgeSyncRateLimit,
  GcpInstanceGetParams,
  GcpSubnetCreateParams,
  GcpSubnetGetParams,
  GcpSubnetDeleteParams,
  CloudRunServiceUpsertParams,
  CloudRunServiceGetParams,
  CloudRunServiceDeleteParams,
  CloudRunProbeInvokeParams,
  GcpSiteSubnetRef,
  GcpSubnetsListParams,
  WorkersRouteUpsertParams,
  WorkersRouteDeleteParams,
  GcpProjectQuotaGetParams,
} from "./dispatch-params.js";
import {
  edgeCacheZoneFromHostSuffix,
  edgeGateScriptNameFor,
  GCP_PROJECT_QUOTA_METRIC,
  isGcpSiteSubnetRef,
  siteRunSlotFromPrefixedSubnetName,
  subnetsListNamePrefix,
  siteSubnetRefNetworkName,
  siteSubnetRefSubnetName,
  siteRunSubnetCidrForSlot,
  siteSlugFromSubnetDescription,
  siteSubnetDescriptionFor,
  splitCloudRunSessionServiceName,
  workersRoutePatternFor,
} from "./dispatch-params.js";
import {
  EDGE_CACHE_PHASE,
  EDGE_CACHE_RULE_DESCRIPTIONS,
  buildEdgeCacheRules,
  edgeCacheRuleDrifted,
  edgeCacheRulesInOrder,
  type EdgeCacheRule,
} from "./edge-cache-rule.js";
import {
  CLOUDFLARE_MANAGED_RULESET_ID,
  MANAGED_RULESET_RULE_DESCRIPTION,
  WAF_MANAGED_PHASE,
  WAF_PHASE,
  WAF_RULE_DESCRIPTIONS,
  WAF_UNKNOWN_PLAN_RULE_CAP,
  buildEdgeWafRules,
  buildManagedRulesetExecuteRule,
  edgeWafRulesInOrder,
  planSupportsManagedRuleset,
  wafCustomRuleCapForPlan,
  wafRuleDrifted,
  type WafRule,
} from "./edge-waf-rule.js";
import {
  buildEdgeChunkRule,
  buildEdgeClauses,
  buildXmlrpcRule,
  classifyWafRuleDescription,
  edgeChunkDescription,
  planStickyChunks,
  splitChunkExpression,
  type EdgeChunkKind,
  type EdgeChunkPlan,
  type EdgeClauseEntry,
  type ExistingEdgeChunk,
} from "./edge-waf-sync.js";
import {
  RATE_LIMIT_DESCRIPTIONS,
  RATE_LIMIT_EXPENSIVE_DESCRIPTION,
  RATE_LIMIT_ORIGIN_DESCRIPTION,
  RATE_LIMIT_PHASE,
  buildRateLimitRules,
  rateLimitRuleCapForPlan,
  rateLimitRuleDrifted,
  type RateLimitRule,
} from "./edge-rate-limit.js";
import { presignS3Put, presignS3Get } from "./sigv4.js";
import type { CustomHostnameDeleteResult, CustomHostnameGetResult, CustomHostnameUpsertResult } from "./actuate-custom-hostname.js";
import { type ServiceAccountKey, GOOGLE_SCOPE_CLOUD_PLATFORM, mintGoogleAccessToken, mintGoogleIdToken } from "./validators.js";
import { errorMessage, stripTrailingSlash } from "./util.js";
import type { CfTunnelGetResult, GcpDiskSnapshotCreateResult, GcpInstanceRemoveServiceAccountResult } from "./actuate-hub58.js";
import type { R2MediaBucketsResult, R2MediaStateResult, R2SiteKeyInstallResult, R2SiteKeyRevokeResult } from "./actuate-r2-media.js";
import type { CfTunnelConnectionsGetResult, CfTunnelTokenGetResult, GcpInstanceMetadataDiffResult } from "./actuate-p47.js";
import type { EdgeGateDeployResult } from "./actuate-edge-gate.js";

export const CF_API = "https://api.cloudflare.com/client/v4";

export type ProvisionR2Result =
  | { ok: true; op: "provision-r2"; bucket: string; status: "created" | "already-existed"; accountId: string }
  | { ok: false; op: "provision-r2"; bucket: string; detail: string };

export type DnsRecordUpsertResult =
  | { ok: true; op: "dns-record-upsert"; action: "created" | "updated"; recordId: string; name: string }
  | { ok: false; op: "dns-record-upsert"; name: string; detail: string };

export type CachePurgeResult =
  | { ok: true; op: "cache-purge"; mode: "everything" | "files" | "hosts"; zone: string; count: number }
  | { ok: false; op: "cache-purge"; zone: string; detail: string };

/** What one upsert did to one rule: created it (or created the entrypoint with it), PATCHed it, or left it. */
export type CacheRuleAction = "created" | "updated" | "unchanged";

// The op manages TWO rules (edge-cache-rule.ts: the personal-cookie BYPASS rule + the CACHE rule).
// `ruleId` / `action` describe the whole op from the CACHE rule's point of view (`action` is the
// strongest of the two: created > updated > unchanged), the bypass* fields the bypass rule;
// `otherCacheRules` lists every cache-settings rule in the zone that is NOT ours (a stray
// force-cache rule under another name would otherwise sit next to the safe pair unnoticed — the
// platform warns the operator; this Worker never touches them).
export type CacheRuleUpsertResult =
  | {
      ok: true;
      op: "cache-rule-upsert";
      zone: string;
      action: CacheRuleAction;
      ruleId: string;
      enabled: boolean;
      cacheAction: CacheRuleAction;
      bypassRuleId: string;
      bypassAction: CacheRuleAction;
      otherCacheRules: string[];
    }
  | { ok: false; op: "cache-rule-upsert"; zone: string; detail: string };

/**
 * What one upsert did to one WAF rule: created it (or created the entrypoint with it), PATCHed its
 * definition (and, if needed, its position), PATCHed ONLY its position ("moved", definition untouched),
 * or left it.
 */
export type WafRuleAction = "created" | "updated" | "moved" | "unchanged";

/** One of the five edge-defense rules, and what THIS dispatch did to it. */
export interface WafRuleOutcome {
  /** The rule's stable description, e.g. "doubleyoup-country-block". */
  description: string;
  action: WafRuleAction;
  ruleId: string;
}

/**
 * What THIS dispatch did about the Cloudflare Managed Ruleset. "Ours" is the execute rule with the
 * description "doubleyoup-managed-ruleset" (the one this op creates); any other execute rule that runs
 * the Managed Ruleset belongs to another owner and is never written.
 *   not-requested       — the job did not include the Managed Ruleset (the default);
 *   unavailable-on-plan — enable was asked for, but the zone is below Pro (or its plan is unknown);
 *   deployed            — enable: no execute rule for it existed, so this run added ours;
 *   re-enabled          — enable: ours was switched off (an earlier rollback), so this run switched it on;
 *   already-deployed    — enable: ours, or another owner's, is already on (left exactly as it was);
 *   present-disabled    — enable: none of ours, and another owner's is switched off (left off: their call);
 *   disabled            — rollback: ours was on, so this run switched it off (never deleted);
 *   already-disabled    — rollback: ours was already off;
 *   not-ours            — rollback: none of ours; another owner's execute rule runs it (left untouched);
 *   absent              — rollback: nothing runs the Managed Ruleset in this zone.
 */
export type ManagedRulesetStatus =
  | "not-requested"
  | "unavailable-on-plan"
  | "deployed"
  | "re-enabled"
  | "already-deployed"
  | "present-disabled"
  | "disabled"
  | "already-disabled"
  | "not-ours"
  | "absent";

// The op manages FIVE custom rules (edge-waf-rule.ts) plus, on request, the Managed Ruleset.
// `rules` on SUCCESS is every custom rule, in apply order — ok:true means all five are in force.
// `plan` is the zone's plan.legacy_id ("unknown" when Cloudflare did not say) and `ruleCap` the
// custom-rule allowance the op sized itself against. `otherWafRules` lists every custom rule in the
// phase that is NOT ours — they share the allowance and, because our new rules are APPENDED, one that
// skips traffic sits ahead of ours and wins. Reported; this Worker never touches them.
//
// On FAILURE, `capExceeded` (+ `ruleCap`, `plannedRuleCount`) means the op REFUSED before any write
// because the zone has no room; `wafRulesApplied` is the prefix of our rules that DID land before a
// later write failed, so a partial apply is never silent.
export type WafRuleUpsertResult =
  | {
      ok: true;
      op: "waf-rule-upsert";
      zone: string;
      enabled: boolean;
      plan: string;
      ruleCap: number;
      rules: WafRuleOutcome[];
      otherWafRules: string[];
      managedRuleset: ManagedRulesetStatus;
    }
  | {
      ok: false;
      op: "waf-rule-upsert";
      zone: string;
      detail: string;
      wafRulesApplied?: WafRuleOutcome[];
      capExceeded?: true;
      ruleCap?: number;
      plannedRuleCount?: number;
    };

// `connectorToken` is the ONE deliberate secret in a result (planning/40 decision 3 (c)): the
// orchestrator consumes it transiently — injects it into the gateway's cloudflared exactly as the
// manual token path does — and NEVER logs or stores it (the dispatch layer logs no result bodies, and
// provision-cell keeps it out of the summary). The purer Worker-side-injection model is a later
// hardening. `status` is "already-existed" when a non-deleted tunnel of the same name was reused.
export type CfTunnelCreateResult =
  | { ok: true; op: "cf-tunnel-create"; tunnelId: string; connectorToken: string; status: "created" | "already-existed" }
  | { ok: false; op: "cf-tunnel-create"; detail: string };

export type CfTunnelConfigResult =
  | { ok: true; op: "cf-tunnel-config"; tunnelId: string; ruleCount: number }
  | { ok: false; op: "cf-tunnel-config"; tunnelId: string; detail: string };

// planning/40 Phase B teardown: a delete CONVERGES — "already-absent" (Cloudflare 404) is success, so
// a resumed teardown re-runs harmlessly (mirrors the GCP delete ops).
export type CfTunnelDeleteResult =
  | { ok: true; op: "cf-tunnel-delete"; tunnelId: string; status: "deleted" | "already-absent" }
  | { ok: false; op: "cf-tunnel-delete"; tunnelId: string; detail: string };

export type DnsRecordDeleteResult =
  | { ok: true; op: "dns-record-delete"; name: string; status: "deleted" | "already-absent" }
  | { ok: false; op: "dns-record-delete"; name: string; detail: string };

export type WpCliResult =
  | { ok: true; op: "wp-cli"; exitCode: number; stdout: string; stderr: string }
  | { ok: false; op: "wp-cli"; detail: string };

// Deliberately SMALL: the dump itself never comes back through the Worker (it went cell -> object
// store), and the presigned URL is never echoed — only the key the caller already chose.
export type DbExportResult =
  | { ok: true; op: "db-export"; objectKey: string; exitCode: 0 }
  | { ok: false; op: "db-export"; objectKey: string; detail: string; exitCode?: number };

// Symmetric with DbExportResult: the dump never comes back through the Worker (it went object
// store -> cell), and the presigned URL is never echoed — only the key the caller already chose.
export type DbImportResult =
  | { ok: true; op: "db-import"; objectKey: string; exitCode: 0 }
  | { ok: false; op: "db-import"; objectKey: string; detail: string; exitCode?: number };

// instances.insert is ASYNC: a 2xx returns a long-running Operation, not the VM. Success here
// means "Google ACCEPTED the create" — `operationName` + `status` (PENDING/RUNNING/DONE) are
// what a caller polls. The minted access token is never part of either variant.
//
// `alreadyExisted` (ok:false ONLY) is set to true when Google answered the insert with 409 — the
// named VM already exists. The op itself stays NON-idempotent (a 409 is still reported ok:false,
// see actuateGcpInstanceCreate), but a CELL-level caller resuming a half-built cell (planning/34
// "resume on re-run") needs a discriminable "the node is already there" signal it can treat as
// skip-and-continue, rather than matching on the detail string. Absent on every other failure.
//
// `exhausted` (ok:false ONLY) is set to true when the insert's operation COMPLETED with a
// ZONE_RESOURCE_POOL_EXHAUSTED error — the zone lacked capacity for the machine type (planning/34
// zone fallback). Like `alreadyExisted` it is a DISCRIMINABLE field (never a detail-string match),
// so the cell-level caller can retry the create in another zone. Absent on every other failure.
export type GcpInstanceCreateResult =
  | { ok: true; op: "gcp-instance-create"; instanceName: string; operationName: string; status: string }
  | { ok: false; op: "gcp-instance-create"; instanceName: string; detail: string; alreadyExisted?: true; exhausted?: true };

// The IDEMPOTENT cell-infra ops report, per resource, whether THIS run created it or found it
// already there (Google's 409 alreadyExists) — the same vocabulary as provision-r2's status.
export type GcpResourceStatus = "created" | "already-existed";

// Two resources, two statuses: "created" for the network/subnet means the Worker WAITED for its
// insert Operation to reach DONE (see actuateGcpNetworkCreate), so the resource exists on return.
export type GcpNetworkCreateResult =
  | {
      ok: true;
      op: "gcp-network-create";
      networkName: string;
      networkStatus: GcpResourceStatus;
      subnetName: string;
      subnetStatus: GcpResourceStatus;
    }
  | { ok: false; op: "gcp-network-create"; networkName: string; subnetName: string; detail: string };

// firewalls.insert is async: "created" means Google ACCEPTED the insert.
export type GcpFirewallCreateResult =
  | { ok: true; op: "gcp-firewall-create"; ruleName: string; status: GcpResourceStatus }
  | { ok: false; op: "gcp-firewall-create"; ruleName: string; detail: string };

// `address` is the reserved IP read back after the insert, or null while Google is still
// assigning it (the caller re-reads); never a credential.
export type GcpAddressCreateResult =
  | { ok: true; op: "gcp-address-create"; addressName: string; address: string | null; status: GcpResourceStatus }
  | { ok: false; op: "gcp-address-create"; addressName: string; detail: string };

// One insert, one status: the router and its inline NAT are created together. "created" means the
// Worker WAITED for the insert Operation to reach DONE (see actuateGcpRouterNatCreate), so the NAT
// is in place on return — the private VMs created next boot with egress.
export type GcpRouterNatCreateResult =
  | { ok: true; op: "gcp-router-nat-create"; routerName: string; natName: string; status: GcpResourceStatus }
  | { ok: false; op: "gcp-router-nat-create"; routerName: string; natName: string; detail: string };

// READ-ONLY resume verification (planning/34, review finding 1). `found` says whether the named rule
// is actually present now (404 => false), so a caller resuming a half-built cell can turn an
// already-existed rule from "trusted by name" into a real confirmation. ok:false is a read failure
// (auth / unreachable / an unexpected non-2xx) — the reservation-style "the resource stands, re-run".
export type GcpFirewallGetResult =
  | { ok: true; op: "gcp-firewall-get"; ruleName: string; found: boolean }
  | { ok: false; op: "gcp-firewall-get"; ruleName: string; detail: string };

// READ-ONLY resume verification. `found` says whether the router exists now; `natNames` lists its
// inline NAT config names so the caller can confirm the CELL's NAT is present (a same-named router
// WITHOUT it leaves the private VMs with no egress). `natNames` is [] when the router has no NAT or
// was not found. ok:false is a read failure.
export type GcpRouterGetResult =
  | { ok: true; op: "gcp-router-get"; routerName: string; found: boolean; natNames: string[] }
  | { ok: false; op: "gcp-router-get"; routerName: string; detail: string };

// READ-ONLY zone discovery (planning/34 zone fallback). `instances` is every Compute Engine instance
// whose name matches the caller's prefix, each with its SHORT zone name (e.g. australia-southeast1-b),
// so a caller resuming a half-built cell can find which of its VMs already exist and pin the whole
// cell to their one zone. ok:false is a read failure (auth / unreachable / a non-2xx / an
// incomplete paged read) — the caller must NOT treat that as "no VMs" (it would risk a duplicate).
export type GcpInstancesListResult =
  | { ok: true; op: "gcp-instances-list"; instances: Array<{ name: string; zone: string }> }
  | { ok: false; op: "gcp-instances-list"; detail: string };

// The IDEMPOTENT teardown ops report, per resource, whether THIS run deleted it or found it already
// gone (Google's 404 notFound) — the teardown mirror of the create ops' created | already-existed.
export type GcpDeleteStatus = "deleted" | "already-absent";

// "deleted" means the Worker WAITED for the delete Operation to reach DONE, so the VM is GONE on
// return — a later subnet delete fails with resourceInUse while a VM is still alive, so this op must
// confirm, not merely accept. `operationName` is the delete Operation (absent when the VM was
// already gone — there was nothing to delete and nothing to wait on).
//
// `stillRunning` (ok:false ONLY) is set when Google ACCEPTED the delete but its operation did not
// reach DONE inside the bounded wait (or the wait poll itself could not be completed). A
// DISCRIMINABLE field, like gcp-instance-create's `exhausted` — the caller reports "re-run to
// resume" off this field, NEVER off a string match on `detail`. Absent on every other failure.
export type GcpInstanceDeleteResult =
  | { ok: true; op: "gcp-instance-delete"; instanceName: string; status: GcpDeleteStatus; operationName?: string }
  | { ok: false; op: "gcp-instance-delete"; instanceName: string; detail: string; stillRunning?: true };

export type GcpAddressDeleteResult =
  | { ok: true; op: "gcp-address-delete"; addressName: string; status: GcpDeleteStatus }
  | { ok: false; op: "gcp-address-delete"; addressName: string; detail: string };

export type GcpFirewallDeleteResult =
  | { ok: true; op: "gcp-firewall-delete"; ruleName: string; status: GcpDeleteStatus }
  | { ok: false; op: "gcp-firewall-delete"; ruleName: string; detail: string };

// One delete, one status: the inline Cloud NAT is a field of the router, so it goes with it.
export type GcpRouterDeleteResult =
  | { ok: true; op: "gcp-router-delete"; routerName: string; status: GcpDeleteStatus }
  | { ok: false; op: "gcp-router-delete"; routerName: string; detail: string };

// Two resources, two statuses — the subnet is deleted (and confirmed) FIRST, then the network, so a
// caller sees exactly which of the two this run removed and which was already gone.
export type GcpNetworkDeleteResult =
  | {
      ok: true;
      op: "gcp-network-delete";
      networkName: string;
      subnetName: string;
      subnetStatus: GcpDeleteStatus;
      networkStatus: GcpDeleteStatus;
    }
  | { ok: false; op: "gcp-network-delete"; networkName: string; subnetName: string; detail: string };

// planning/47 in-place update. `keysSet` names the keys THIS run wrote (the request's keys — never
// their values, which may carry a substituted secret); `placeholdersSubstituted` names the
// `@@DY_T2_S3_*@@` placeholders the Worker filled from its own S3_* configuration (names only, see
// actuateGcpInstanceSetMetadata). The metadata write is WAITED to DONE, so ok:true means the new
// metadata is in place and a following gcp-instance-restart boots with it.
//
// `placeholderValues` carries the RESOLVED value of the substituted placeholders that are NOT
// secrets — and only those, by the hardcoded PLACEHOLDER_VALUES_SAFE_TO_ECHO allowlist. It exists
// because reporting that a placeholder was "substituted" says nothing about WHAT it resolved to:
// `@@DY_T1_S3_BUCKET@@` falls back to S3_BUCKET when the optional S3_BACKUP_BUCKET secret is unset,
// and on 2026-10-06 that fallback was reported as a clean substitution while Tier-1 kept writing to
// the wrong bucket. A placeholder the allowlist does not name is ABSENT from this map — not masked,
// not truncated.
//
// planning/47 boot-script update: `valuesSha256` is the sha256 (hex, of the UTF-8 bytes) of each value
// AS WRITTEN — after the substitution, so it is the hash gcp-instance-get reports for that key once the
// write is in place, and the caller's read-back compares the two. A hash, never the value: a file-node
// script carries the agency's object-store credential once substituted. `unchangedKeys` names the keys
// whose existing value was already byte-identical (the write still goes out; nothing else differs).
// `expectedFingerprintChecked` is true when the request carried `expectedFingerprint` and the
// instance's fingerprint equalled it, false when the request carried none. A caller that SENT one and
// gets no `true` back is talking to a Worker that ignored it.
//
// `staleFingerprint` (ok:false ONLY) is set when Google rejected the write with 412 — the instance's
// metadata changed between this op's read and its write — and, since planning/47, also when the
// instance's fingerprint is not the caller's `expectedFingerprint` (then NO write was sent). A
// DISCRIMINABLE field (never a detail-string match): the caller re-runs DELIBERATELY (a re-run
// re-reads and re-merges); the Worker never retries it blindly, because a blind re-write is exactly how
// a concurrent change gets clobbered.
// `unconfirmed` (ok:false ONLY) is set when Google ACCEPTED the write but its operation did not reach
// DONE inside the bounded wait — the metadata may well be in place; a re-run converges. Each is absent
// on every other failure.
export type GcpInstanceSetMetadataResult =
  | {
      ok: true;
      op: "gcp-instance-set-metadata";
      instanceName: string;
      keysSet: string[];
      placeholdersSubstituted: string[];
      /** Non-secret resolved values only, keyed by placeholder name. See the comment above. */
      placeholderValues: Record<string, string>;
      /** sha256 hex of each value AS WRITTEN (after substitution), keyed by metadata key. Never a value. */
      valuesSha256: Record<string, string>;
      /** The request's keys whose existing value was already byte-identical to the written one. */
      unchangedKeys: string[];
      /** True when the request's expectedFingerprint was checked and matched; false when none was sent. */
      expectedFingerprintChecked: boolean;
      operationName: string;
    }
  | {
      ok: false;
      op: "gcp-instance-set-metadata";
      instanceName: string;
      detail: string;
      staleFingerprint?: true;
      unconfirmed?: true;
    };

// planning/47: a GRACEFUL stop then start. Each half's Compute operation is WAITED to DONE — Google's
// confirmation of the TERMINATED / RUNNING transition — so ok:true means the VM is RUNNING again on its
// (possibly new) startup script. `stopStatus` is "already-stopped" when the VM was TERMINATED before
// the op touched it (nothing to stop; only the start ran). On ok:false, `phase` names the half that
// failed and `stopped` says whether the VM had been confirmed TERMINATED by then, so a caller can tell
// "stop failed, VM untouched" from "stopped, but the start did not confirm" — those need different
// operator responses. `unconfirmed` is set when Google ACCEPTED the stop/start but its operation did
// not reach DONE inside the bounded wait (the transition may still complete on its own; re-run once
// the VM settles — a re-run on a TERMINATED VM only starts it).
export type GcpInstanceRestartResult =
  | {
      ok: true;
      op: "gcp-instance-restart";
      instanceName: string;
      stopStatus: "stopped" | "already-stopped";
      startStatus: "started";
      stopOperationName?: string;
      startOperationName: string;
    }
  | {
      ok: false;
      op: "gcp-instance-restart";
      instanceName: string;
      detail: string;
      phase: "stop" | "start";
      stopped: boolean;
      unconfirmed?: true;
    };

// Deliberately SMALL: the authorized_keys file lives ON the gateway; nothing sensitive comes back.
// `count` echoes how many key lines the gateway wrote (0 = the set was revoked), so the caller can
// confirm the whole desired set landed without the Worker re-reading the file.
export type ProvisionSshKeysResult =
  | { ok: true; op: "provision-ssh-keys"; slug: string; count: number }
  | { ok: false; op: "provision-ssh-keys"; slug: string; detail: string };

// planning/49 Phase 1 — READ one VM's in-VPC PRIVATE IPv4 (and, planning/47, the non-secret facts of
// its metadata: InstanceBootMetadataFacts). `found` is false on a 404 (a clean "that
// VM is not there", like gcp-firewall-get), and then `privateIp` and `status` are null. `privateIp` is
// also null for a found instance with no network interface. Google should never produce that state,
// and we report it as null, not as an empty string. ok:false is a read failure.
export type GcpInstanceGetResult =
  | {
      ok: true;
      op: "gcp-instance-get";
      instanceName: string;
      found: boolean;
      /** The instance's first network interface's internal IP, or null (not found / no interface). */
      privateIp: string | null;
      /**
       * The short name of the VPC network THAT interface is on, e.g. "dy-cell-australia-southeast2",
       * or null. Review L5: the caller checks it is the cell's own network before it accepts the IP.
       */
      network: string | null;
      /** PROVISIONING | STAGING | RUNNING | STOPPING | TERMINATED | … , or null when not found. */
      status: string | null;
      /**
       * hub#58 review finding 4: the e-mails of the service accounts the VM runs as ([] = none), or null
       * when not found or when Google answered a shape this op does not understand (the caller then
       * treats the account as UNKNOWN). Setting the metadata of a VM that runs as an account needs
       * iam.serviceAccounts.actAs on it, which the agency's key never holds.
       */
      serviceAccounts: string[] | null;
      /**
       * planning/47: NON-SECRET facts about the VM's metadata, so a boot-script update can show what it
       * would replace and prove what it wrote. null when not found. See InstanceBootMetadataFacts.
       */
      metadata: InstanceBootMetadataFacts | null;
      /**
       * planning/47 review M2/L4: the first interface's EXTERNAL IPv4 (its first access config's natIP),
       * or null (none, or not found). Non-secret. The gateway's preflight compares it with the origin
       * IPs of the cell tunnel's connectors.
       */
      externalIp: string | null;
      /**
       * planning/47 review N1: Google's `lastStartTimestamp` (when the VM last started), passed only as an
       * RFC 3339 string; null when absent, malformed, or not found. Non-secret. The reboot path requires
       * the boot's done-marker to be LATER than it, so a marker from the previous boot is never accepted.
       */
      lastStartTimestamp: string | null;
    }
  | { ok: false; op: "gcp-instance-get"; instanceName: string; detail: string };

// planning/47 — what gcp-instance-get reports about a VM's metadata. EVERY field is non-secret by
// construction: the fingerprint is Google's concurrency token, the script is reported as a sha256 and a
// byte count (a file-node script carries the agency's object-store credential, so its TEXT never leaves
// this Worker), and the two bundle facts are the platform's own PUBLIC pin, read from exactly one
// `readonly DY_BUNDLE_URL='...'` / `readonly DY_BUNDLE_SHA256='...'` line of the injected block and
// reported only when the line matches its strict grammar. Any other line, value or key is not read.
export interface InstanceBootMetadataFacts {
  /** The metadata fingerprint (what gcp-instance-set-metadata's expectedFingerprint names), or null. */
  fingerprint: string | null;
  /**
   * planning/47 review L7: the OTHER metadata keys that run code at boot or shutdown and are present
   * (names only, from BOOT_TIME_METADATA_KEYS): a boot also runs a startup-script-url or cloud-init's
   * user-data, and a graceful stop runs a shutdown script. The platform authors none of them.
   */
  otherBootKeys: string[];
  /** The `startup-script` key, or null when the VM has none. */
  startupScript: {
    /** sha256 hex of the value's UTF-8 bytes (what gcp-instance-set-metadata reports in valuesSha256). */
    sha256: string;
    bytes: number;
    /** The bundle a boot of this script installs, or null (no such line, several, or another shape). */
    bundleUrl: string | null;
    /** That bundle's pinned sha256, or null (no such line, several, an empty pin, or another shape). */
    bundleSha256: string | null;
  } | null;
}

// planning/49 Phase 2 — the Cloud Run subnet. "created" means the Worker WAITED for the insert to
// reach DONE, so the subnet exists on return. "already-existed" is Google's 409 alreadyExists; for the
// SITE form (hub#93) it is reported only after a read-back found the derived range AND this site's
// description on it.
//
// `outcome` (ok:false, SITE form ONLY) is what the platform's slot release rule (hub#93 M5) keys on,
// a DISCRIMINABLE field, never a detail-string match:
//   refused  — DEFINITE: no subnet was made by this call (a 4xx from Google, an operation that finished
//              with errors, or a call that was never sent). The caller may release the slot.
//   unknown  — the create may still land (Google unreachable, a 5xx, an accepted insert whose wait did
//              not finish). The caller KEEPS the slot and reconciles with gcp-subnet-get.
//   conflict — a subnet of the derived name already exists with another range or description. It is
//              not adopted and not changed.
//
// THE ECHO (planning/49 Phase 3, SITE form ONLY): `network` and `subnet` are the names this Worker USED —
// the job's registry pair, or the saga names when the job sent none. They are on every site-form result,
// ok or not. An older Worker drops a registry pair it does not know and acts on the saga names, and it
// never answers with these two fields, so a caller that sent the pair refuses a result without them.
export type GcpSiteSubnetCreateOutcome = "refused" | "unknown" | "conflict";
export type GcpSubnetCreateResult =
  | { ok: true; op: "gcp-subnet-create"; subnetName: string; status: GcpResourceStatus; network?: string; subnet?: string }
  | {
      ok: false;
      op: "gcp-subnet-create";
      subnetName: string;
      detail: string;
      outcome?: GcpSiteSubnetCreateOutcome;
      network?: string;
      subnet?: string;
    };

// READ-ONLY. `ipCidrRange` is the primary range (null when not found). Idempotence of the probe-form
// create is by NAME, so this is how a caller sees a same-named subnet with a different range.
// The SITE form (hub#93) also reports the subnet's `description`, the slot it was asked about, and
// `matchesSite`: true only when the subnet exists on the network asked for, with the range derived from
// the slot AND the exact description of this site. That is the read the platform's slot reconcile uses
// (M5). It echoes `network` and `subnet` like the create (see above).
export type GcpSubnetGetResult =
  | { ok: true; op: "gcp-subnet-get"; subnetName: string; found: boolean; ipCidrRange: string | null }
  | {
      ok: true;
      op: "gcp-subnet-get";
      subnetName: string;
      found: boolean;
      ipCidrRange: string | null;
      description: string | null;
      slot: number;
      siteSlug: string;
      matchesSite: boolean;
      network: string;
      subnet: string;
    }
  | { ok: false; op: "gcp-subnet-get"; subnetName: string; detail: string; network?: string; subnet?: string };

// "deleted" means the Worker WAITED for the delete to reach DONE. "already-absent" is a 404. On a
// failure, `inUse` is true when Google refused because another resource still uses the subnet (review
// L4: Direct VPC egress can hold addresses after the last service is gone). That is "retry later".
// `foreign` (SITE form ONLY) is true when the subnet exists but is not on the network asked for, or its
// description does not name THIS site exactly: it is left in place (hub#93 §2). The SITE form echoes
// `network` and `subnet` like the create (see above).
export type GcpSubnetDeleteResult =
  | { ok: true; op: "gcp-subnet-delete"; subnetName: string; status: GcpDeleteStatus; network?: string; subnet?: string }
  | {
      ok: false;
      op: "gcp-subnet-delete";
      subnetName: string;
      detail: string;
      inUse: boolean;
      foreign?: true;
      network?: string;
      subnet?: string;
    };

/** One per-site subnet as gcp-subnets-list reports it. */
export interface GcpSiteSubnetListEntry {
  name: string;
  /** The slot the name encodes, or null when the suffix is not a canonical 000-127. */
  slot: number | null;
  ipCidrRange: string | null;
  description: string | null;
  /** The site the description binds the subnet to, or null when it is not a doubleyoup site description. */
  siteSlug: string | null;
  /** The SHORT name of the subnet's network, e.g. "dy-cell-australia-southeast2", or null. */
  network: string | null;
}

// hub#93 — READ-ONLY. Every subnet in the region whose name starts with the listed prefix
// (`dy-cell-<region>-run-s`, or the job's registry `subnetPrefix`), from EVERY page, and — with the
// registry pair — only on the job's `network`. ok:false on any read failure or an incomplete paged
// read: a teardown relying on a partial list would leave a subnet behind, so it must fail closed,
// never read as "no subnets". planning/49 Phase 3: every result ECHOES `subnetPrefix` (the prefix
// listed under) and `network` (the network filter, null for none), so a caller that sent the pair can
// refuse the result of an older Worker that dropped it.
export type GcpSubnetsListResult =
  | { ok: true; op: "gcp-subnets-list"; subnetPrefix: string; network: string | null; subnets: GcpSiteSubnetListEntry[] }
  | { ok: false; op: "gcp-subnets-list"; subnetPrefix: string; network: string | null; detail: string };

// hub#93 — READ-ONLY. The project's live SUBNETWORKS quota: `usage` (subnets the project holds now) and
// `limit`, both whole numbers as Google reports them. ok:false on any read failure or a quota list that
// does not carry exactly one well-formed SUBNETWORKS entry — never a guessed zero.
export type GcpProjectQuotaGetResult =
  | { ok: true; op: "gcp-project-quota-get"; project: string; metric: typeof GCP_PROJECT_QUOTA_METRIC; usage: number; limit: number }
  | { ok: false; op: "gcp-project-quota-get"; project: string; detail: string };

// planning/49 §8 + hub#93 — ONE exact-host Workers route to the cell's edge gate. "unchanged" means a
// route with this exact pattern already points at the gate. `foreign` (ok:false) means a route with this
// exact pattern points at ANOTHER script: it is left alone, never taken over or removed. Every result
// echoes `script`, the edge-gate script name derived from the job's project and region (planning/49
// Phase 3), so a caller can refuse the result of an older Worker that routed to a fixed script.
export type WorkersRouteUpsertResult =
  | { ok: true; op: "workers-route-upsert"; pattern: string; script: string; routeId: string; status: "created" | "unchanged" }
  | { ok: false; op: "workers-route-upsert"; pattern: string; script: string; detail: string; foreign?: true };

export type WorkersRouteDeleteResult =
  | { ok: true; op: "workers-route-delete"; pattern: string; script: string; status: GcpDeleteStatus }
  | { ok: false; op: "workers-route-delete"; pattern: string; script: string; detail: string; foreign?: true };

// planning/49 §4.3 — "created" / "updated" says which half of create-else-patch ran. The Worker WAITS
// for the operation and re-reads the service, so `uri` and `urls` are the service's real URLs (the
// caller checks the URL it derives is among `urls` — §3.2) and `revision` is the latest one's name.
export type CloudRunServiceUpsertResult =
  | {
      ok: true;
      op: "cloudrun-service-upsert";
      serviceName: string;
      status: "created" | "updated";
      uri: string;
      urls: string[];
      revision: string | null;
    }
  // `unconfirmed` is true ONLY when Google accepted the write but the Worker's bounded wait could not
  // see it finish (still running, or the wait call itself failed). The deploy may still land, so the
  // caller may poll cloudrun-service-get. Every OTHER failure is a clear refusal (orchestrator L1).
  | { ok: false; op: "cloudrun-service-upsert"; serviceName: string; detail: string; unconfirmed?: boolean };

// READ-ONLY. `ready` is true only when the TERMINAL condition is Ready AND succeeded. `managedByPlatform`
// is true when the service carries this platform's managed-by label (review M1). `reconciling` is
// Google's own flag for a deploy still in flight (review L5).
// planning/49 Phase 3 — what the service RUNS, so the orchestrator can tell a current service from a
// stale one without a second read: `network` and `subnet` (the SHORT names of its Direct VPC egress
// interface), `image` (its first container's image) and `specLabel` (its `dy-spec` label). Each is
// null when the service is absent or does not carry it.
export type CloudRunServiceGetResult =
  | {
      ok: true;
      op: "cloudrun-service-get";
      serviceName: string;
      found: boolean;
      uri: string | null;
      urls: string[];
      ready: boolean;
      managedByPlatform: boolean;
      reconciling: boolean;
      network: string | null;
      subnet: string | null;
      image: string | null;
      specLabel: string | null;
    }
  | { ok: false; op: "cloudrun-service-get"; serviceName: string; detail: string };

// A delete CONVERGES: a 404 is "already-absent". A service WITHOUT the managed-by label is refused.
export type CloudRunServiceDeleteResult =
  | { ok: true; op: "cloudrun-service-delete"; serviceName: string; status: GcpDeleteStatus }
  | { ok: false; op: "cloudrun-service-delete"; serviceName: string; detail: string };

/** ONE probe result: "open" | "refused" | "timeout" | "error:<errno>". */
export interface CloudRunProbeResultEntry {
  ip: string;
  port: string;
  result: string;
}

// planning/49 Phase 2 — the premise probe's answer. `unauthenticatedStatus` is what Cloud Run said to a
// request with NO token (it must refuse: 401 or 403). `authenticatedStatus` is what it said with a
// Google ID token from the agency's own key. `results` is the probe's TCP results, checked for shape.
export type CloudRunProbeInvokeResult =
  | {
      ok: true;
      op: "cloudrun-probe-invoke";
      serviceName: string;
      uri: string;
      unauthenticatedStatus: number;
      authenticatedStatus: number;
      results: CloudRunProbeResultEntry[];
    }
  // `public` is true when the request with NO token got an ANSWER (2xx or 3xx, review L1): the service
  // may be reachable by anyone. That is a failure here, not only in the orchestrator's verdict. A
  // token-less 404, 429 or 5xx is a plain failure without `public` (re-review L1).
  | { ok: false; op: "cloudrun-probe-invoke"; serviceName: string; detail: string; public?: boolean; unauthenticatedStatus?: number };

export type ActuateResult =
  | ProvisionR2Result
  | DnsRecordUpsertResult
  | CachePurgeResult
  | CacheRuleUpsertResult
  | WafRuleUpsertResult
  // hub#44 phase 2: every platform rule of an agency zone in one pass.
  | WafEdgeSyncResult
  // hub#46 (actuate-custom-hostname.ts): customer domains as custom hostnames in the agency zone.
  | CustomHostnameUpsertResult
  | CustomHostnameGetResult
  | CustomHostnameDeleteResult
  | CfTunnelCreateResult
  | CfTunnelConfigResult
  | CfTunnelDeleteResult
  | DnsRecordDeleteResult
  | WpCliResult
  | DbExportResult
  | DbImportResult
  | GcpInstanceCreateResult
  | GcpNetworkCreateResult
  | GcpFirewallCreateResult
  | GcpAddressCreateResult
  | GcpRouterNatCreateResult
  | GcpFirewallGetResult
  | GcpRouterGetResult
  | GcpInstancesListResult
  | GcpInstanceDeleteResult
  | GcpAddressDeleteResult
  | GcpFirewallDeleteResult
  | GcpRouterDeleteResult
  | GcpNetworkDeleteResult
  | GcpInstanceSetMetadataResult
  | GcpInstanceRestartResult
  | ProvisionSshKeysResult
  | GcpInstanceGetResult
  | GcpSubnetCreateResult
  | GcpSubnetGetResult
  | GcpSubnetDeleteResult
  | CloudRunServiceUpsertResult
  | CloudRunServiceGetResult
  | CloudRunServiceDeleteResult
  | CloudRunProbeInvokeResult
  | GcpSubnetsListResult
  | WorkersRouteUpsertResult
  | WorkersRouteDeleteResult
  // planning/49 Phase 3 (I4, actuate-edge-gate.ts): the cell's session edge gate.
  | EdgeGateDeployResult
  | GcpProjectQuotaGetResult
  // hub#58 / planning/51 (actuate-hub58.ts).
  | CfTunnelGetResult
  | CfTunnelTokenGetResult
  | CfTunnelConnectionsGetResult
  | GcpInstanceMetadataDiffResult
  | GcpDiskSnapshotCreateResult
  | GcpInstanceRemoveServiceAccountResult
  // hub#43 (actuate-r2-media.ts): agency-owned media.
  | R2MediaBucketsResult
  | R2MediaStateResult
  | R2SiteKeyInstallResult
  | R2SiteKeyRevokeResult;

export interface CloudflareEnvelope {
  success?: boolean;
  errors?: Array<{ code?: number; message?: string }>;
  result?: unknown;
}

export function cloudflareHeaders(token: string): Record<string, string> {
  return {
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    accept: "application/json",
  };
}

// ── provision-r2 ───────────────────────────────────────────────────────────────────
// Mirrors the orchestrator's own ensureR2Bucket (orchestrator/src/cloudflare.ts):
// POST /accounts/{id}/r2/buckets, treating a 409 (bucket already exists) as idempotent
// success.

/**
 * Resolve the account id the R2_PROVISION_API_TOKEN belongs to. An account-owned token is
 * scoped to exactly one account, so GET /accounts?per_page=1 returns it — the same cheap,
 * account-scoped read the R2 validator already uses. Avoids a separate account-id secret.
 */
export async function resolveAccountId(
  token: string,
  unauthorizedHint?: string,
): Promise<{ id: string } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/accounts?per_page=1`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to resolve account: ${errorMessage(err)}` };
  }

  if (response.status === 401 || response.status === 403) {
    return {
      error:
        unauthorizedHint ??
        "Cloudflare rejected R2_PROVISION_API_TOKEN — it must be an ACCOUNT-owned token (Manage Account → Account API Tokens) with Workers R2 Storage: Edit.",
    };
  }

  const body = (await response.json().catch(() => null)) as
    | { success?: boolean; result?: Array<{ id?: string }> }
    | null;
  const id = body?.success && body.result && body.result.length > 0 ? body.result[0]?.id : undefined;
  if (!id) {
    return { error: `could not resolve the token's account (HTTP ${response.status})` };
  }
  return { id };
}

/**
 * Create the R2 bucket idempotently with the agency's own token. 200/201 => created;
 * 409 (or a "bucket already exists" error code) => already-existed (idempotent success);
 * anything else => a clean failure with the CF message. NEVER falls back to a platform
 * credential (there is none).
 */
export async function actuateProvisionR2(bucketName: string, env: Env): Promise<ProvisionR2Result> {
  const token = env.R2_PROVISION_API_TOKEN;
  if (!token) {
    return {
      ok: false,
      op: "provision-r2",
      bucket: bucketName,
      detail: "R2_PROVISION_API_TOKEN is not configured on this Worker.",
    };
  }

  const account = await resolveAccountId(token);
  if ("error" in account) {
    return { ok: false, op: "provision-r2", bucket: bucketName, detail: account.error };
  }

  let response: Response;
  try {
    response = await fetch(`${CF_API}/accounts/${encodeURIComponent(account.id)}/r2/buckets`, {
      method: "POST",
      headers: cloudflareHeaders(token),
      body: JSON.stringify({ name: bucketName }),
    });
  } catch (err) {
    return {
      ok: false,
      op: "provision-r2",
      bucket: bucketName,
      detail: `could not reach Cloudflare to create the bucket: ${errorMessage(err)}`,
    };
  }

  if (response.status === 200 || response.status === 201) {
    await response.text().catch(() => "");
    return { ok: true, op: "provision-r2", bucket: bucketName, status: "created", accountId: account.id };
  }

  // 409 is the canonical "already exists". Some CF responses instead return 400 with the
  // R2 "bucket already exists" error code (10004), so treat that as idempotent too.
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  const alreadyExists =
    response.status === 409 ||
    (body?.errors ?? []).some((e) => e.code === 10004 || /already exists/i.test(e.message ?? ""));
  if (alreadyExists) {
    return {
      ok: true,
      op: "provision-r2",
      bucket: bucketName,
      status: "already-existed",
      accountId: account.id,
    };
  }

  if (response.status === 401 || response.status === 403) {
    return {
      ok: false,
      op: "provision-r2",
      bucket: bucketName,
      detail:
        "Cloudflare denied bucket creation — R2_PROVISION_API_TOKEN needs Workers R2 Storage: Edit on this account.",
    };
  }

  const message = body?.errors?.[0]?.message;
  return {
    ok: false,
    op: "provision-r2",
    bucket: bucketName,
    detail: `bucket create failed with HTTP ${response.status}${message ? `: ${message}` : ""}.`,
  };
}

// ── dns-record-upsert ──────────────────────────────────────────────────────────────
// Idempotent upsert of ONE record (type + name) in an agency zone, with the agency's own
// CF_DNS_API_TOKEN (Zone:DNS:Edit + Zone:Read):
//   1. GET  /zones?name=<zone>                       -> exactly one zone id, else fail
//   2. GET  /zones/:zid/dns_records?type=&name=      -> 0 matches => create, 1 => update
//   3. POST /zones/:zid/dns_records  |  PUT /zones/:zid/dns_records/:rid
// Two or more existing records with the same type+name (legal for TXT/A) is AMBIGUOUS —
// "update the first one" could clobber an unrelated record (an SPF TXT, a round-robin A),
// so that fails closed with a clear detail instead of guessing.
//
// Idempotency matters for replay protection (review finding F1): handleActuate BURNS the
// nonce before actuating, so a transient Cloudflare failure cannot be retried by re-POSTing
// the same signed job — the platform must re-sign with a fresh nonce. That is harmless for
// an upsert (re-running converges to the same record). A future NON-idempotent op must
// solve this deliberately (e.g. bind the nonce to a completed side effect) before it is
// added to the registry.

interface CloudflareZoneSummary {
  id?: string;
  name?: string;
  /** Deprecated by Cloudflare but still returned; `legacy_id` is "free" / "pro" / "business" / "enterprise". */
  plan?: { legacy_id?: string };
  /** The Cloudflare account that holds the zone. */
  account?: { id?: string };
}

interface CloudflareDnsRecordSummary {
  id?: string;
  name?: string;
  type?: string;
}

/** First Cloudflare error message from a response body, if any (for detail strings). */
export function cloudflareErrorMessage(body: CloudflareEnvelope | null): string {
  const message = body?.errors?.[0]?.message;
  return message ? `: ${message}` : "";
}

function dnsFailure(name: string, detail: string): DnsRecordUpsertResult {
  return { ok: false, op: "dns-record-upsert", name, detail };
}

/**
 * Resolve the zone NAME to the zone id the token can see. Exactly one match is required:
 * zero means the token can't see the zone (wrong account or missing Zone:Read), more than
 * one would be ambiguous (should not happen for an exact-name filter, but never guess).
 */
export async function resolveZoneId(
  token: string,
  zoneName: string,
): Promise<{ id: string; planLegacyId: string | null; accountId: string | null } | { error: string }> {
  const query = new URLSearchParams({ name: zoneName, per_page: "2" });
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones?${query.toString()}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to resolve zone "${zoneName}": ${errorMessage(err)}` };
  }

  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return {
      error:
        "Cloudflare rejected CF_DNS_API_TOKEN — it needs Zone:Read + Zone:DNS:Edit on the target zone(s).",
    };
  }

  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!body?.success || !Array.isArray(body.result)) {
    return { error: `zone lookup failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  // Cloudflare's `name` filter is an exact match, but re-check the name defensively so a
  // looser server-side match can never pick a different zone.
  const zones = (body.result as CloudflareZoneSummary[]).filter((zone) => zone.name === zoneName && zone.id);
  if (zones.length === 0) {
    return {
      error: `zone "${zoneName}" is not visible to CF_DNS_API_TOKEN — check the zone name and the token's zone scope.`,
    };
  }
  if (zones.length > 1) {
    return { error: `zone lookup for "${zoneName}" returned ${zones.length} zones — refusing to guess.` };
  }
  // The plan rides along for the WAF op's rule cap (waf-rule-upsert); every other caller ignores it.
  // Absent or not a string => null, which that op treats as the SMALLEST plan.
  let planLegacyId: string | null = null;
  const legacyId = zones[0].plan?.legacy_id;
  if (typeof legacyId === "string" && legacyId.length > 0) {
    planLegacyId = legacyId;
  }
  // The account rides along for edge-gate-deploy (planning/49 Phase 3): a Workers route runs only a script
  // of its zone's own account, so the gate script is uploaded there. Every other caller ignores it.
  let accountId: string | null = null;
  const zoneAccountId = zones[0].account?.id;
  if (typeof zoneAccountId === "string" && zoneAccountId.length > 0) {
    accountId = zoneAccountId;
  }
  return { id: zones[0].id as string, planLegacyId, accountId };
}

/**
 * Find the existing record(s) with this exact type + name. Returns the full match list so
 * the caller can distinguish create (0) / update (1) / ambiguous (2+).
 */
async function findExistingRecords(
  token: string,
  zoneId: string,
  type: string,
  name: string,
): Promise<{ records: CloudflareDnsRecordSummary[] } | { error: string }> {
  const query = new URLSearchParams({ type, name, per_page: "5" });
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zoneId)}/dns_records?${query.toString()}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to list DNS records: ${errorMessage(err)}` };
  }

  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return { error: "Cloudflare denied listing DNS records — CF_DNS_API_TOKEN needs Zone:DNS:Edit on this zone." };
  }
  if (!body?.success || !Array.isArray(body.result)) {
    return { error: `DNS record lookup failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  // Re-check type + name on each row (defensive, as with the zone lookup).
  const records = (body.result as CloudflareDnsRecordSummary[]).filter(
    (record) => record.id && record.type === type && record.name === name,
  );
  return { records };
}

/**
 * Upsert the record with the agency's own CF_DNS_API_TOKEN. Returns a structured result;
 * never throws for a Cloudflare-side failure. NEVER falls back to a platform credential
 * (there is none).
 */
export async function actuateDnsRecordUpsert(
  params: DnsRecordUpsertParams,
  env: Env,
): Promise<DnsRecordUpsertResult> {
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return dnsFailure(params.name, "CF_DNS_API_TOKEN is not configured on this Worker.");
  }

  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) {
    return dnsFailure(params.name, zone.error);
  }

  const existing = await findExistingRecords(token, zone.id, params.type, params.name);
  if ("error" in existing) {
    return dnsFailure(params.name, existing.error);
  }
  if (existing.records.length > 1) {
    return dnsFailure(
      params.name,
      `${existing.records.length} existing ${params.type} records already match "${params.name}" — ambiguous, refusing to update one of them.`,
    );
  }

  // The signed params are all strings by convention; Cloudflare wants real JSON types here.
  const recordBody = JSON.stringify({
    type: params.type,
    name: params.name,
    content: params.content,
    proxied: params.proxied === "true",
    ttl: Number(params.ttl),
  });

  const existingRecord = existing.records[0];
  const action: "created" | "updated" = existingRecord ? "updated" : "created";
  const url = existingRecord
    ? `${CF_API}/zones/${encodeURIComponent(zone.id)}/dns_records/${encodeURIComponent(existingRecord.id as string)}`
    : `${CF_API}/zones/${encodeURIComponent(zone.id)}/dns_records`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: existingRecord ? "PUT" : "POST",
      headers: cloudflareHeaders(token),
      body: recordBody,
    });
  } catch (err) {
    return dnsFailure(params.name, `could not reach Cloudflare to write the DNS record: ${errorMessage(err)}`);
  }

  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return dnsFailure(
      params.name,
      "Cloudflare denied the DNS write — CF_DNS_API_TOKEN needs Zone:DNS:Edit on this zone.",
    );
  }
  const written = body?.success ? (body.result as CloudflareDnsRecordSummary | undefined) : undefined;
  if (!written?.id) {
    return dnsFailure(
      params.name,
      `DNS record ${action === "created" ? "create" : "update"} failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`,
    );
  }

  return { ok: true, op: "dns-record-upsert", action, recordId: written.id, name: params.name };
}

// planning/40 Phase B: delete the agent-host CNAME on teardown. Idempotent — a record already gone
// (0 matches) is "already-absent" success; >1 match is refused (never guess which to delete).
export async function actuateDnsRecordDelete(params: DnsRecordDeleteParams, env: Env): Promise<DnsRecordDeleteResult> {
  const token = env.CF_DNS_API_TOKEN;
  if (!token) return { ok: false, op: "dns-record-delete", name: params.name, detail: "CF_DNS_API_TOKEN is not configured on this Worker." };

  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) return { ok: false, op: "dns-record-delete", name: params.name, detail: zone.error };

  const existing = await findExistingRecords(token, zone.id, params.type, params.name);
  if ("error" in existing) return { ok: false, op: "dns-record-delete", name: params.name, detail: existing.error };
  if (existing.records.length === 0) {
    return { ok: true, op: "dns-record-delete", name: params.name, status: "already-absent" };
  }
  if (existing.records.length > 1) {
    return {
      ok: false,
      op: "dns-record-delete",
      name: params.name,
      detail: `${existing.records.length} ${params.type} records match "${params.name}" — ambiguous, refusing to delete one.`,
    };
  }

  const recordId = existing.records[0].id as string;
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zone.id)}/dns_records/${encodeURIComponent(recordId)}`, {
      method: "DELETE",
      headers: cloudflareHeaders(token),
    });
  } catch (err) {
    return { ok: false, op: "dns-record-delete", name: params.name, detail: `could not reach Cloudflare to delete the DNS record: ${errorMessage(err)}` };
  }
  if (response.status === 404) {
    return { ok: true, op: "dns-record-delete", name: params.name, status: "already-absent" };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return { ok: false, op: "dns-record-delete", name: params.name, detail: "Cloudflare denied the DNS delete — CF_DNS_API_TOKEN needs Zone:DNS:Edit on this zone." };
  }
  if (!body?.success) {
    return { ok: false, op: "dns-record-delete", name: params.name, detail: `DNS record delete failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return { ok: true, op: "dns-record-delete", name: params.name, status: "deleted" };
}

// ── cf-tunnel-create / cf-tunnel-config ────────────────────────────────────────────────
// Create + configure a per-cell Cloudflare named tunnel in the agency's own account (planning/40
// Component A), with the agency's own CF_DNS_API_TOKEN (now also carrying account-level Cloudflare
// Tunnel: Edit). Tunnels are ACCOUNT-level, so both ops resolve the token's account id first (the same
// cheap read the R2 path uses) — the account-level scope is what makes that read succeed for a token
// that was previously zone-only. NEVER falls back to a platform credential (there is none).

export const CF_TUNNEL_UNAUTHORIZED_HINT =
  "Cloudflare rejected CF_DNS_API_TOKEN for tunnel management — it needs account-level Cloudflare Tunnel: Edit (Manage Account → Account API Tokens).";

/** A cfd_tunnel summary row (only the fields we read). */
interface CloudflareTunnelSummary {
  id?: string;
  name?: string;
  deleted_at?: string | null;
}

/**
 * Find a NON-deleted tunnel of this exact name (idempotency). Returns `{ tunnelId }` when exactly one
 * matches, `{ tunnelId: null }` when none, or `{ error }` on an ambiguous match or an API failure.
 * `is_deleted=false` filters server-side; we re-check name + deleted_at defensively.
 */
async function findCfTunnelByName(
  token: string,
  accountId: string,
  name: string,
): Promise<{ tunnelId: string | null } | { error: string }> {
  const query = new URLSearchParams({ name, is_deleted: "false", per_page: "5" });
  let response: Response;
  try {
    response = await fetch(`${CF_API}/accounts/${encodeURIComponent(accountId)}/cfd_tunnel?${query.toString()}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to list tunnels: ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { error: CF_TUNNEL_UNAUTHORIZED_HINT };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!body?.success || !Array.isArray(body.result)) {
    return { error: `tunnel lookup failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  const matches = (body.result as CloudflareTunnelSummary[]).filter(
    (tunnel) => tunnel.id && tunnel.name === name && !tunnel.deleted_at,
  );
  if (matches.length > 1) {
    return { error: `${matches.length} non-deleted tunnels are named "${name}" — ambiguous, refusing to guess.` };
  }
  return { tunnelId: matches.length === 1 ? (matches[0].id as string) : null };
}

/** Create a remotely-managed (config_src: cloudflare) named tunnel; returns its id. */
async function createCfTunnel(
  token: string,
  accountId: string,
  name: string,
): Promise<{ tunnelId: string } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/accounts/${encodeURIComponent(accountId)}/cfd_tunnel`, {
      method: "POST",
      headers: cloudflareHeaders(token),
      body: JSON.stringify({ name, config_src: "cloudflare" }),
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to create the tunnel: ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { error: CF_TUNNEL_UNAUTHORIZED_HINT };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  const created = body?.success ? (body.result as CloudflareTunnelSummary | undefined) : undefined;
  if (!created?.id) {
    return { error: `tunnel create failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return { tunnelId: created.id };
}

/**
 * Fetch a tunnel's connector token (`cloudflared tunnel run --token <token>`). The `/token` endpoint
 * returns the token STRING directly as `result`. This is the one secret the op returns; see
 * CfTunnelCreateResult for how the orchestrator handles it.
 */
export async function fetchCfTunnelToken(
  token: string,
  accountId: string,
  tunnelId: string,
): Promise<{ token: string } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(
      `${CF_API}/accounts/${encodeURIComponent(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}/token`,
      { headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
    );
  } catch (err) {
    return { error: `could not reach Cloudflare to fetch the tunnel token: ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { error: CF_TUNNEL_UNAUTHORIZED_HINT };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  const connectorToken = body?.success && typeof body.result === "string" ? body.result : undefined;
  if (!connectorToken) {
    return { error: `tunnel token fetch failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return { token: connectorToken };
}

export async function actuateCfTunnelCreate(params: CfTunnelCreateParams, env: Env): Promise<CfTunnelCreateResult> {
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return { ok: false, op: "cf-tunnel-create", detail: "CF_DNS_API_TOKEN is not configured on this Worker." };
  }

  const account = await resolveAccountId(token, CF_TUNNEL_UNAUTHORIZED_HINT);
  if ("error" in account) {
    return { ok: false, op: "cf-tunnel-create", detail: account.error };
  }

  const existing = await findCfTunnelByName(token, account.id, params.tunnelName);
  if ("error" in existing) {
    return { ok: false, op: "cf-tunnel-create", detail: existing.error };
  }

  let tunnelId: string;
  let status: "created" | "already-existed";
  if (existing.tunnelId) {
    tunnelId = existing.tunnelId;
    status = "already-existed";
  } else {
    const created = await createCfTunnel(token, account.id, params.tunnelName);
    if ("error" in created) {
      return { ok: false, op: "cf-tunnel-create", detail: created.error };
    }
    tunnelId = created.tunnelId;
    status = "created";
  }

  const connector = await fetchCfTunnelToken(token, account.id, tunnelId);
  if ("error" in connector) {
    return { ok: false, op: "cf-tunnel-create", detail: connector.error };
  }
  return { ok: true, op: "cf-tunnel-create", tunnelId, connectorToken: connector.token, status };
}

export async function actuateCfTunnelConfig(params: CfTunnelConfigParams, env: Env): Promise<CfTunnelConfigResult> {
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return {
      ok: false,
      op: "cf-tunnel-config",
      tunnelId: params.tunnelId,
      detail: "CF_DNS_API_TOKEN is not configured on this Worker.",
    };
  }

  const account = await resolveAccountId(token, CF_TUNNEL_UNAUTHORIZED_HINT);
  if ("error" in account) {
    return { ok: false, op: "cf-tunnel-config", tunnelId: params.tunnelId, detail: account.error };
  }

  // Per-cell dedicated tunnel => write the FULL ingress config, appending the mandatory catch-all
  // rule (a remotely-managed tunnel config's last rule must be a service-only catch-all). The caller
  // may name the catch-all's service (a cell points it at the web node's nginx so every site host
  // on the cell routes there by server_name); absent => http_status:404, exactly as before.
  // planning/50 integration review M1: a kept session route's originRequest ({ httpHostHeader } only —
  // the validator admits nothing else) is written back as it was read.
  const ingress: Array<Record<string, unknown>> = [];
  for (const rule of params.ingress) {
    if (rule.originRequest === undefined) {
      ingress.push({ hostname: rule.hostname, service: rule.service });
    } else {
      ingress.push({ hostname: rule.hostname, service: rule.service, originRequest: { httpHostHeader: rule.originRequest.httpHostHeader } });
    }
  }
  ingress.push({ service: params.catchAllService ?? "http_status:404" });
  // planning/50 integration review M2: the top-level warp-routing key, when the caller read one.
  const config: Record<string, unknown> = { ingress };
  if (params.warpRouting !== undefined) {
    config["warp-routing"] = { enabled: params.warpRouting.enabled };
  }

  let response: Response;
  try {
    response = await fetch(
      `${CF_API}/accounts/${encodeURIComponent(account.id)}/cfd_tunnel/${encodeURIComponent(params.tunnelId)}/configurations`,
      { method: "PUT", headers: cloudflareHeaders(token), body: JSON.stringify({ config }) },
    );
  } catch (err) {
    return {
      ok: false,
      op: "cf-tunnel-config",
      tunnelId: params.tunnelId,
      detail: `could not reach Cloudflare to write the tunnel config: ${errorMessage(err)}`,
    };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { ok: false, op: "cf-tunnel-config", tunnelId: params.tunnelId, detail: CF_TUNNEL_UNAUTHORIZED_HINT };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!body?.success) {
    return {
      ok: false,
      op: "cf-tunnel-config",
      tunnelId: params.tunnelId,
      detail: `tunnel config write failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`,
    };
  }
  return { ok: true, op: "cf-tunnel-config", tunnelId: params.tunnelId, ruleCount: params.ingress.length };
}

// planning/40 Phase B: delete the per-cell tunnel on teardown. Idempotent — a 404 (already deleted) is
// "already-absent" success. By teardown time the gateway VM (cloudflared) has been deleted, so the
// tunnel's connections are gone; if Cloudflare still reports active connections, that surfaces as a
// clean failure and a resumed teardown retries.
export async function actuateCfTunnelDelete(params: CfTunnelDeleteParams, env: Env): Promise<CfTunnelDeleteResult> {
  const token = env.CF_DNS_API_TOKEN;
  if (!token) return { ok: false, op: "cf-tunnel-delete", tunnelId: params.tunnelId, detail: "CF_DNS_API_TOKEN is not configured on this Worker." };

  const account = await resolveAccountId(token, CF_TUNNEL_UNAUTHORIZED_HINT);
  if ("error" in account) return { ok: false, op: "cf-tunnel-delete", tunnelId: params.tunnelId, detail: account.error };

  // Best-effort: clean up any stale connector connections FIRST — Cloudflare refuses to delete a tunnel
  // that still reports active connections. By teardown time the gateway VM (cloudflared) is deleted, so
  // its connections are stale; this forces them cleared so the delete below succeeds on the first try
  // (review #4). Ignore the outcome — a 404/none is fine, and if it fails the delete still tries.
  try {
    await fetch(`${CF_API}/accounts/${encodeURIComponent(account.id)}/cfd_tunnel/${encodeURIComponent(params.tunnelId)}/connections`, {
      method: "DELETE",
      headers: cloudflareHeaders(token),
    });
  } catch {
    // ignored — best-effort; the tunnel delete below reports the real outcome.
  }

  let response: Response;
  try {
    response = await fetch(`${CF_API}/accounts/${encodeURIComponent(account.id)}/cfd_tunnel/${encodeURIComponent(params.tunnelId)}`, {
      method: "DELETE",
      headers: cloudflareHeaders(token),
    });
  } catch (err) {
    return { ok: false, op: "cf-tunnel-delete", tunnelId: params.tunnelId, detail: `could not reach Cloudflare to delete the tunnel: ${errorMessage(err)}` };
  }
  if (response.status === 404) {
    return { ok: true, op: "cf-tunnel-delete", tunnelId: params.tunnelId, status: "already-absent" };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { ok: false, op: "cf-tunnel-delete", tunnelId: params.tunnelId, detail: CF_TUNNEL_UNAUTHORIZED_HINT };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!body?.success) {
    return { ok: false, op: "cf-tunnel-delete", tunnelId: params.tunnelId, detail: `tunnel delete failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return { ok: true, op: "cf-tunnel-delete", tunnelId: params.tunnelId, status: "deleted" };
}

// ── cache-purge ──────────────────────────────────────────────────────────────────────
// Purge an agency zone's Cloudflare cache with the agency's own CF_DNS_API_TOKEN (which now
// also carries Zone:Cache Purge — a deploy-time scope add, not a new secret):
//   1. GET  /zones?name=<zone>          -> exactly one zone id, else fail (reuses resolveZoneId)
//   2. POST /zones/:zid/purge_cache     -> {purge_everything:true} | {files:[...]} | {hosts:[...]}
// No new onboarding validator: like the DNS edit scope, the Cache Purge scope is exercised
// for real on the FIRST purge, which reports a clear denial (401/403) if it is missing.
//
// A cache purge is idempotent and safe to repeat, so the F1 replay-nonce note (handleActuate
// burns the nonce before actuating) does not bite here: a retry means re-signing a fresh job,
// and re-running a purge just re-evicts already-evicted content — zero additional effect.

function cachePurgeFailure(zone: string, detail: string): CachePurgeResult {
  return { ok: false, op: "cache-purge", zone, detail };
}

/**
 * Purge the zone's cache with the agency's own CF_DNS_API_TOKEN. Returns a structured result;
 * never throws for a Cloudflare-side failure. NEVER falls back to a platform credential
 * (there is none). The purge body is chosen by `params.mode` and always built with
 * JSON.stringify; the zone id is encodeURIComponent'd into the path.
 */
export async function actuateCachePurge(params: CachePurgeParams, env: Env): Promise<CachePurgeResult> {
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return cachePurgeFailure(params.zone, "CF_DNS_API_TOKEN is not configured on this Worker.");
  }

  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) {
    return cachePurgeFailure(params.zone, zone.error);
  }

  // Exactly one selector per mode. `count` is the number of targeted evictions, and 0 for a
  // whole-zone ("everything") purge — reported back so the caller can log what happened.
  let purgeBody: Record<string, unknown>;
  let count: number;
  if (params.mode === "everything") {
    purgeBody = { purge_everything: true };
    count = 0;
  } else if (params.mode === "files") {
    purgeBody = { files: params.files };
    count = params.files.length;
  } else {
    purgeBody = { hosts: params.hosts };
    count = params.hosts.length;
  }

  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zone.id)}/purge_cache`, {
      method: "POST",
      headers: cloudflareHeaders(token),
      body: JSON.stringify(purgeBody),
    });
  } catch (err) {
    return cachePurgeFailure(params.zone, `could not reach Cloudflare to purge the cache: ${errorMessage(err)}`);
  }

  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return cachePurgeFailure(
      params.zone,
      "Cloudflare denied the cache purge — CF_DNS_API_TOKEN needs Zone:Cache Purge on this zone.",
    );
  }
  if (!body?.success) {
    return cachePurgeFailure(
      params.zone,
      `cache purge failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`,
    );
  }

  return { ok: true, op: "cache-purge", mode: params.mode, zone: params.zone, count };
}

// ── cache-rule-upsert ────────────────────────────────────────────────────────────────
// Upsert the ONE "edge page cache" Cache Rule in an agency zone with the agency's own
// CF_DNS_API_TOKEN (which now also carries Zone → Cache Rules: Edit — a deploy-time scope add):
//   1. GET  /zones?name=<zone>                                              -> one zone id (resolveZoneId)
//   2. GET  /zones/:zid/rulesets/phases/http_request_cache_settings/entrypoint
//        404 => POST /zones/:zid/rulesets {kind:"zone", phase, rules:[rule]} (creates the entrypoint)
//   3. find OUR rule by its stable description:
//        absent  => POST  /zones/:zid/rulesets/:rid/rules           (append; other rules untouched)
//        drifted => PATCH /zones/:zid/rulesets/:rid/rules/:ruleId   (in place)
//        equal   => nothing
// The zone is DERIVED from the validated suffix ("-production.<zone>"), so the rule can only ever
// land in a zone the agency's own token can see, matching only that zone's WordPress sites — its
// `-production.<zone>` routing hosts plus the customer domains onboarded onto it as
// Cloudflare-for-SaaS custom hostnames, and NOT the zone apex, the agency's own in-zone hosts or a
// branded media host (edge-cache-rule.ts "WHICH HOSTS"). The rule body is built HERE — the job
// never carries an expression, so it cannot widen that host set.
//
// Creating the entrypoint with POST (not PUT on the entrypoint path) is deliberate: Cloudflare
// allows ONE entrypoint per phase per zone, so if one appeared between our GET and our write, the
// POST fails cleanly instead of replacing the agency's own cache rules.
//
// IDEMPOTENT (find-by-description, PATCH only on drift), so the nonce-burned-before-actuation F1
// rule does not bite: a retry re-signs a fresh job and converges on the same single rule.

/** One rule of a Cloudflare ruleset, as the ruleset API returns it (only the fields we read). */
interface CloudflareRulesetRule {
  id?: string;
  description?: string;
  expression?: string;
  action?: string;
  action_parameters?: unknown;
  enabled?: boolean;
}

interface CloudflareRuleset {
  id?: string;
  rules?: CloudflareRulesetRule[];
}

const CACHE_RULES_DENIED_DETAIL =
  "Cloudflare denied the cache rule change — CF_DNS_API_TOKEN needs Zone → Cache Rules: Edit on this zone.";

function cacheRuleFailure(zone: string, detail: string): CacheRuleUpsertResult {
  return { ok: false, op: "cache-rule-upsert", zone, detail };
}

/**
 * Read the zone's cache-settings phase entrypoint. `missing` = the zone has no Cache Rules yet
 * (Cloudflare answers 404), which the caller handles by creating the entrypoint.
 */
async function getCacheSettingsEntrypoint(
  token: string,
  zoneId: string,
): Promise<{ ruleset: CloudflareRuleset } | { missing: true } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(
      `${CF_API}/zones/${encodeURIComponent(zoneId)}/rulesets/phases/${EDGE_CACHE_PHASE}/entrypoint`,
      { headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
    );
  } catch (err) {
    return { error: `could not reach Cloudflare to read the cache rules: ${errorMessage(err)}` };
  }
  if (response.status === 404) {
    await response.text().catch(() => "");
    return { missing: true };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { error: CACHE_RULES_DENIED_DETAIL };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  const ruleset = body?.result as CloudflareRuleset | undefined;
  if (!body?.success || !ruleset || typeof ruleset.id !== "string") {
    return { error: `cache rules read failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return { ruleset };
}

/**
 * One ruleset write (create entrypoint / append rule / patch rule). All three return the full
 * updated ruleset on success, which the caller reads our rule's id from.
 */
async function writeCacheRuleset(
  token: string,
  method: "POST" | "PATCH",
  url: string,
  body: unknown,
): Promise<{ ruleset: CloudflareRuleset } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(url, { method, headers: cloudflareHeaders(token), body: JSON.stringify(body) });
  } catch (err) {
    return { error: `could not reach Cloudflare to write the cache rule: ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { error: CACHE_RULES_DENIED_DETAIL };
  }
  const envelope = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!envelope?.success) {
    return { error: `cache rule write failed with HTTP ${response.status}${cloudflareErrorMessage(envelope)}.` };
  }
  return { ruleset: (envelope.result ?? {}) as CloudflareRuleset };
}

/** The id of the rule carrying `description` in a ruleset Cloudflare returned, or "" when absent. */
function cacheRuleIdIn(ruleset: CloudflareRuleset, description: string): string {
  const rule = (ruleset.rules ?? []).find((candidate) => candidate.description === description);
  return rule?.id ?? "";
}

/**
 * One-line summaries of the rules in the zone's cache-settings ruleset that are NOT ours. Reported
 * (never acted on) so the platform can warn about a stray force-cache rule under another name.
 */
function describeOtherCacheRules(ruleset: CloudflareRuleset | null): string[] {
  const summaries: string[] = [];
  for (const rule of ruleset?.rules ?? []) {
    const description = rule.description ?? "";
    if (EDGE_CACHE_RULE_DESCRIPTIONS.includes(description)) {
      continue;
    }
    const params = (rule.action_parameters ?? {}) as { cache?: unknown; edge_ttl?: { mode?: string; default?: number } };
    const parts: string[] = [`cache=${String(params.cache ?? "unset")}`];
    if (params.edge_ttl !== undefined) {
      parts.push(`edge_ttl.mode=${params.edge_ttl.mode ?? "unset"}`);
      if (params.edge_ttl.default !== undefined) {
        parts.push(`edge_ttl.default=${params.edge_ttl.default}`);
      }
    }
    const label = description === "" ? "(no description)" : description;
    const state = rule.enabled === false ? "disabled" : "enabled";
    summaries.push(`${label} [${rule.id ?? "no id"}] ${state} ${parts.join(" ")}`);
  }
  return summaries;
}

type OneCacheRuleOutcome =
  | { action: CacheRuleAction; ruleId: string; ruleset: CloudflareRuleset }
  | { error: string };

/**
 * Upsert ONE of our rules against the ruleset as we currently know it (null = the zone has no
 * cache-settings entrypoint yet). Returns the ruleset to carry into the next rule: for a create /
 * append that is what Cloudflare returned (it carries the new ids); for a PATCH, our copy with the
 * patched rule replaced (the PATCH reply is not relied on); unchanged = untouched.
 */
async function upsertOneCacheRule(
  token: string,
  zonePath: string,
  ruleset: CloudflareRuleset | null,
  desired: EdgeCacheRule,
): Promise<OneCacheRuleOutcome> {
  // No Cache Rules in this zone yet: create the phase entrypoint holding just this rule.
  if (ruleset === null) {
    const created = await writeCacheRuleset(token, "POST", `${zonePath}/rulesets`, {
      name: "default",
      kind: "zone",
      phase: EDGE_CACHE_PHASE,
      rules: [desired],
    });
    if ("error" in created) {
      return created;
    }
    return { action: "created", ruleId: cacheRuleIdIn(created.ruleset, desired.description), ruleset: created.ruleset };
  }

  const rulesetId = ruleset.id as string;
  const rulesetPath = `${zonePath}/rulesets/${encodeURIComponent(rulesetId)}`;
  const matches = (ruleset.rules ?? []).filter((candidate) => candidate.description === desired.description);

  // Two rules with our description is AMBIGUOUS: patching one would leave the other in force, so
  // fail closed and let an operator clean it up (mirrors dns-record-upsert's 2+ match rule).
  if (matches.length > 1) {
    return {
      error: `${matches.length} cache rules already carry the description "${desired.description}" — ambiguous, refusing to change any of them.`,
    };
  }

  const existing = matches[0];
  if (existing === undefined) {
    // Absent: APPEND our rule. Every other rule in the agency's ruleset stays untouched.
    const appended = await writeCacheRuleset(token, "POST", `${rulesetPath}/rules`, desired);
    if ("error" in appended) {
      return appended;
    }
    // Carry Cloudflare's reply when it lists rules (it carries the new id); else our own copy.
    let next = appended.ruleset;
    if (!Array.isArray(next.rules)) {
      next = { ...ruleset, rules: [...(ruleset.rules ?? []), { ...desired, id: "" }] };
    }
    return { action: "created", ruleId: cacheRuleIdIn(next, desired.description), ruleset: next };
  }

  const existingId = existing.id ?? "";
  if (!edgeCacheRuleDrifted(existing, desired)) {
    return { action: "unchanged", ruleId: existingId, ruleset };
  }
  if (!existingId) {
    return { error: `Cloudflare returned our rule "${desired.description}" without an id — cannot update it.` };
  }

  const patched = await writeCacheRuleset(token, "PATCH", `${rulesetPath}/rules/${encodeURIComponent(existingId)}`, desired);
  if ("error" in patched) {
    return patched;
  }
  const replaced = (ruleset.rules ?? []).map((rule) => (rule.id === existingId ? { ...desired, id: existingId } : rule));
  return { action: "updated", ruleId: existingId, ruleset: { ...ruleset, rules: replaced } };
}

/** The strongest of two per-rule actions: created > updated > unchanged. */
function combinedCacheRuleAction(first: CacheRuleAction, second: CacheRuleAction): CacheRuleAction {
  if (first === "created" || second === "created") {
    return "created";
  }
  if (first === "updated" || second === "updated") {
    return "updated";
  }
  return "unchanged";
}

/**
 * Upsert the edge page-cache rule with the agency's own CF_DNS_API_TOKEN. Returns a structured
 * result; never throws for a Cloudflare-side failure. NEVER falls back to a platform credential
 * (there is none). Never touches any other rule in the zone.
 */
export async function actuateCacheRuleUpsert(
  params: CacheRuleUpsertParams,
  env: Env,
): Promise<CacheRuleUpsertResult> {
  // The validator already proved the suffix is "-production.<zone>"; this re-derives the zone.
  const zoneName = edgeCacheZoneFromHostSuffix(params.hostSuffix);
  if (zoneName === null) {
    return cacheRuleFailure(params.hostSuffix, "hostSuffix is not \"-production.\" + a zone name.");
  }

  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return cacheRuleFailure(zoneName, "CF_DNS_API_TOKEN is not configured on this Worker.");
  }

  const built = buildEdgeCacheRules(params);
  if (!built.ok) {
    return cacheRuleFailure(zoneName, built.reason);
  }
  // Bypass first, cache second: a fresh ruleset then lists the bypass rule first (cosmetic — the two
  // expressions are mutually exclusive, see edge-cache-rule.ts).
  const desiredRules = edgeCacheRulesInOrder(built.rules);

  // Fail closed unless the agency's own token can see EXACTLY this zone.
  const zone = await resolveZoneId(token, zoneName);
  if ("error" in zone) {
    return cacheRuleFailure(zoneName, zone.error);
  }
  const zonePath = `${CF_API}/zones/${encodeURIComponent(zone.id)}`;

  // ONE read; the ruleset is then carried in memory from write to write, so the second rule sees the
  // first one's write and a missing entrypoint is created exactly once (Cloudflare allows one per
  // phase per zone — a second POST would fail, not clobber).
  const entrypoint = await getCacheSettingsEntrypoint(token, zone.id);
  if ("error" in entrypoint) {
    return cacheRuleFailure(zoneName, entrypoint.error);
  }
  let ruleset: CloudflareRuleset | null = null;
  if (!("missing" in entrypoint)) {
    ruleset = entrypoint.ruleset;
  }
  const otherCacheRules = describeOtherCacheRules(ruleset);

  // Fail closed BEFORE any write: two rules carrying one of our descriptions is ambiguous (patching
  // one would leave the other in force). Checked for both rules up front so the first rule's write
  // never lands when the second rule's state is ambiguous (mirrors dns-record-upsert's 2+ rule).
  for (const desired of desiredRules) {
    const matchCount = (ruleset?.rules ?? []).filter((candidate) => candidate.description === desired.description).length;
    if (matchCount > 1) {
      return cacheRuleFailure(
        zoneName,
        `${matchCount} cache rules already carry the description "${desired.description}" — ambiguous, refusing to change any of them.`,
      );
    }
  }

  const outcomes: Array<{ action: CacheRuleAction; ruleId: string }> = [];
  for (const desired of desiredRules) {
    const outcome = await upsertOneCacheRule(token, zonePath, ruleset, desired);
    if ("error" in outcome) {
      return cacheRuleFailure(zoneName, outcome.error);
    }
    ruleset = outcome.ruleset;
    outcomes.push({ action: outcome.action, ruleId: outcome.ruleId });
  }
  const bypassOutcome = outcomes[0] as { action: CacheRuleAction; ruleId: string };
  const cacheOutcome = outcomes[1] as { action: CacheRuleAction; ruleId: string };

  return {
    ok: true,
    op: "cache-rule-upsert",
    zone: zoneName,
    action: combinedCacheRuleAction(bypassOutcome.action, cacheOutcome.action),
    ruleId: cacheOutcome.ruleId,
    enabled: built.rules.cache.enabled,
    cacheAction: cacheOutcome.action,
    bypassRuleId: bypassOutcome.ruleId,
    bypassAction: bypassOutcome.action,
    otherCacheRules,
  };
}

// ── waf-rule-upsert ────────────────────────────────────────────────────────────────────
// Upsert the edge-defense baseline in ONE agency zone, with the agency's own CF_DNS_API_TOKEN: the
// FIVE custom rules, then (on request, Pro and above) the Cloudflare Managed Ruleset. The rule bodies
// are built HERE (edge-waf-rule.ts) — the job carries a zone, an on/off switch and two host lists,
// never an expression, an action or a country list.
//
// SEQUENCE (each step only runs when every earlier one succeeded):
//   1. build the five rules (pure; refuses an over-long expression before any API call);
//   2. resolve the zone with the agency's token — fail closed unless it sees EXACTLY this zone — and
//      read its plan;
//   3. read the firewall-custom entrypoint ONCE;
//   4. REFUSE, writing nothing, when two rules carry one of our descriptions (ambiguous) or when the
//      rules we must CREATE plus every rule already there exceed the plan's allowance;
//   5. create / append / PATCH the five rules (the ruleset is carried in memory from write to write,
//      so a missing entrypoint is created exactly once — with POST, never PUT, so a racing create
//      fails instead of REPLACING the agency's own rules);
//   6. only then, the Managed Ruleset. Its order matters: the /exec skip (rule 5) must be in force
//      first, or the Managed Ruleset 403s the cell-agent's /exec in between (measured on syd).
//
// APPEND/UPDATE ONLY. Our rules are found by their exact descriptions and PATCHed in place; every
// other rule in either phase is left exactly where it is, in the order it is in. An existing execute
// rule for the Managed Ruleset is left untouched even when it is disabled or carries overrides.
//
// IDEMPOTENT (find-by-description, PATCH only on drift, execute rule found by ruleset id), so the
// nonce-burned-before-actuation F1 rule does not bite: a retry re-signs a fresh job and converges —
// including after a partial apply, which it resumes rather than duplicates.

// The ONE scope this op needs beyond reading the zone. "Zone WAF Write" is Cloudflare's API
// permission-group name for the WAF ruleset phases (the dashboard's token editor lists it under Zone
// as "WAF", with Edit); Cloudflare names these by product, not by phase, so quoting the API name is
// what makes this message actionable.
const WAF_RULES_DENIED_DETAIL =
  "Cloudflare denied the WAF rule change — CF_DNS_API_TOKEN needs the \"Zone WAF Write\" permission " +
  '(shown as Zone → WAF → Edit in the API-token editor) on this zone, on top of Zone:Read.';

function wafFailure(zone: string, detail: string, applied?: WafRuleOutcome[]): WafRuleUpsertResult {
  const failure: WafRuleUpsertResult = { ok: false, op: "waf-rule-upsert", zone, detail };
  if (applied !== undefined && applied.length > 0) {
    failure.wafRulesApplied = applied;
  }
  return failure;
}

/**
 * Read one of the zone's WAF phase entrypoints. `missing` = the zone has no rules in that phase yet
 * (Cloudflare answers 404), which the caller handles by creating the entrypoint.
 */
async function getWafPhaseEntrypoint(
  token: string,
  zoneId: string,
  phase: string,
): Promise<{ ruleset: CloudflareRuleset } | { missing: true } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zoneId)}/rulesets/phases/${phase}/entrypoint`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to read the ${phase} rules: ${errorMessage(err)}` };
  }
  if (response.status === 404) {
    await response.text().catch(() => "");
    return { missing: true };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { error: WAF_RULES_DENIED_DETAIL };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  const ruleset = body?.result as CloudflareRuleset | undefined;
  if (!body?.success || !ruleset || typeof ruleset.id !== "string") {
    return { error: `${phase} rules read failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  return { ruleset };
}

/** One ruleset write (create entrypoint / append rule / patch rule). Returns the updated ruleset. */
async function writeWafRuleset(
  token: string,
  method: "POST" | "PATCH",
  url: string,
  body: unknown,
): Promise<{ ruleset: CloudflareRuleset } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(url, { method, headers: cloudflareHeaders(token), body: JSON.stringify(body) });
  } catch (err) {
    return { error: `could not reach Cloudflare to write the WAF rule: ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { error: WAF_RULES_DENIED_DETAIL };
  }
  const envelope = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!envelope?.success) {
    return { error: `WAF rule write failed with HTTP ${response.status}${cloudflareErrorMessage(envelope)}.` };
  }
  return { ruleset: (envelope.result ?? {}) as CloudflareRuleset };
}

/** The id of the rule carrying `description` in a ruleset Cloudflare returned, or "" when absent. */
function wafRuleIdIn(ruleset: CloudflareRuleset, description: string): string {
  const rule = (ruleset.rules ?? []).find((candidate) => candidate.description === description);
  return rule?.id ?? "";
}

/**
 * One-line summaries of the rules in the zone's firewall-custom ruleset that are NOT ours. Reported
 * (never acted on) for two reasons: they share the rule allowance, and — because our new rules are
 * APPENDED — one of them that skips traffic sits AHEAD of ours and wins.
 */
function describeOtherWafRules(ruleset: CloudflareRuleset | null): string[] {
  const summaries: string[] = [];
  for (const rule of ruleset?.rules ?? []) {
    const description = rule.description ?? "";
    if (WAF_RULE_DESCRIPTIONS.includes(description)) {
      continue;
    }
    const label = description === "" ? "(no description)" : description;
    const state = rule.enabled === false ? "disabled" : "enabled";
    summaries.push(`${label} [${rule.id ?? "no id"}] ${state} action=${rule.action ?? "unset"}`);
  }
  return summaries;
}

type OneWafRuleOutcome = { action: WafRuleAction; ruleId: string; ruleset: CloudflareRuleset } | { error: string };

/** The index of the rule with `ruleId` in the ruleset as we know it, or -1. */
function indexOfRule(ruleset: CloudflareRuleset, ruleId: string): number {
  return (ruleset.rules ?? []).findIndex((rule) => rule.id === ruleId);
}

/**
 * Our copy of the ruleset with `ruleId` moved to directly after `anchorId` — what Cloudflare does for
 * a PATCH carrying `position: { after: anchorId }`. Kept in memory so the NEXT rule's order check sees
 * the move (the PATCH reply is not relied on).
 */
function withRuleMovedAfter(ruleset: CloudflareRuleset, ruleId: string, anchorId: string): CloudflareRuleset {
  const rules = [...(ruleset.rules ?? [])];
  const from = rules.findIndex((rule) => rule.id === ruleId);
  if (from === -1) {
    return ruleset;
  }
  const [moved] = rules.splice(from, 1);
  const anchorIndex = rules.findIndex((rule) => rule.id === anchorId);
  rules.splice(anchorIndex + 1, 0, moved as CloudflareRulesetRule);
  return { ...ruleset, rules };
}

/**
 * Upsert ONE of our rules against the ruleset as we currently know it (null = the zone has no
 * firewall-custom entrypoint yet). Returns the ruleset to carry into the next rule: for a create /
 * append that is what Cloudflare returned (it carries the new ids); for a PATCH, our copy with the
 * patched rule replaced and, after a move, re-ordered (the PATCH reply is not relied on); unchanged =
 * untouched.
 *
 * ORDER (review L1). `previousRuleId` is the id of OUR rule that comes just before this one in the
 * documented order (null for the first). An existing rule that sits BEFORE it is out of order, so its
 * PATCH carries `position: { after: previousRuleId }`; when its definition is already right, the PATCH
 * body is ONLY that position (Cloudflare keeps the definition), and the action is "moved". Only OUR
 * rules are ever moved, and only relative to each other: every other rule keeps its place, and a rule
 * of ours already after its predecessor is never moved, even with a foreign rule in between.
 */
async function upsertOneWafRule(
  token: string,
  zonePath: string,
  ruleset: CloudflareRuleset | null,
  desired: WafRule,
  previousRuleId: string | null,
): Promise<OneWafRuleOutcome> {
  // No custom rules in this zone yet: create the phase entrypoint holding just this rule.
  if (ruleset === null) {
    const created = await writeWafRuleset(token, "POST", `${zonePath}/rulesets`, {
      name: "default",
      kind: "zone",
      phase: WAF_PHASE,
      rules: [desired],
    });
    if ("error" in created) {
      return created;
    }
    return { action: "created", ruleId: wafRuleIdIn(created.ruleset, desired.description), ruleset: created.ruleset };
  }

  // The entrypoint read validates the id, and so does the create reply below — but a ruleset with
  // no id would put the literal "undefined" in every write URL, so name the problem instead.
  const rulesetId = ruleset.id;
  if (typeof rulesetId !== "string" || rulesetId.length === 0) {
    return { error: "Cloudflare returned the zone's WAF ruleset without an id — cannot add or update a rule in it." };
  }
  const rulesetPath = `${zonePath}/rulesets/${encodeURIComponent(rulesetId)}`;
  const matches = (ruleset.rules ?? []).filter((candidate) => candidate.description === desired.description);

  // Two rules with our description is AMBIGUOUS: patching one would leave the other in force, so
  // fail closed and let an operator clean it up (mirrors dns-record-upsert's 2+ match rule). The
  // caller already checked this for every rule BEFORE any write; this is the per-rule backstop.
  if (matches.length > 1) {
    return {
      error: `${matches.length} WAF rules already carry the description "${desired.description}" — ambiguous, refusing to change any of them.`,
    };
  }

  const existing = matches[0];
  if (existing === undefined) {
    // Absent: APPEND our rule. Every other rule in the agency's ruleset stays where it is.
    const appended = await writeWafRuleset(token, "POST", `${rulesetPath}/rules`, desired);
    if ("error" in appended) {
      return appended;
    }
    // Carry Cloudflare's reply when it lists rules (it carries the new id); else our own copy.
    let next = appended.ruleset;
    if (!Array.isArray(next.rules)) {
      next = { ...ruleset, rules: [...(ruleset.rules ?? []), { ...desired, id: "" }] };
    }
    return { action: "created", ruleId: wafRuleIdIn(next, desired.description), ruleset: next };
  }

  const existingId = existing.id ?? "";
  const drifted = wafRuleDrifted(existing, desired);
  let outOfOrder = false;
  if (previousRuleId !== null && existingId !== "") {
    const previousIndex = indexOfRule(ruleset, previousRuleId);
    outOfOrder = previousIndex !== -1 && indexOfRule(ruleset, existingId) < previousIndex;
  }
  if (!drifted && !outOfOrder) {
    return { action: "unchanged", ruleId: existingId, ruleset };
  }
  if (!existingId) {
    return { error: `Cloudflare returned our rule "${desired.description}" without an id — cannot update it.` };
  }

  // The PATCH body is ALWAYS the full definition, plus the position when out of order. A move of an
  // unchanged rule sends the same definition it already has. We do not send a position-only body:
  // the result would then depend on how Cloudflare merges a PATCH. If it refused that body, the run
  // would stop with only some rules written. If it cleared the omitted fields, the rule would lose
  // its description, and the next run would append a duplicate.
  const body: Record<string, unknown> = { ...desired };
  if (outOfOrder) {
    body.position = { after: previousRuleId };
  }
  const patched = await writeWafRuleset(token, "PATCH", `${rulesetPath}/rules/${encodeURIComponent(existingId)}`, body);
  if ("error" in patched) {
    return patched;
  }

  let next = ruleset;
  if (drifted) {
    const replaced = (ruleset.rules ?? []).map((rule) => (rule.id === existingId ? { ...desired, id: existingId } : rule));
    next = { ...ruleset, rules: replaced };
  }
  if (outOfOrder) {
    next = withRuleMovedAfter(next, existingId, previousRuleId as string);
  }
  let action: WafRuleAction = "moved";
  if (drifted) {
    action = "updated";
  }
  return { action, ruleId: existingId, ruleset: next };
}

/** True for an `execute` rule that runs the Cloudflare Managed Ruleset (whatever its description). */
function executesCloudflareManagedRuleset(rule: CloudflareRulesetRule): boolean {
  if (rule.action !== "execute") {
    return false;
  }
  const parameters = rule.action_parameters as { id?: unknown } | undefined;
  return parameters?.id === CLOUDFLARE_MANAGED_RULESET_ID;
}

/**
 * The PATCH body that switches OUR execute rule on or off while keeping everything else it carries —
 * expression, action and parameters, including any overrides the agency added to it since. A field
 * Cloudflare did not return falls back to the value this op would have created it with.
 */
function ourManagedRuleBody(existing: CloudflareRulesetRule, enabled: boolean): Record<string, unknown> {
  const created = buildManagedRulesetExecuteRule();
  return {
    description: MANAGED_RULESET_RULE_DESCRIPTION,
    expression: existing.expression ?? created.expression,
    action: existing.action ?? created.action,
    action_parameters: existing.action_parameters ?? created.action_parameters,
    enabled,
  };
}

/**
 * Bring the Cloudflare Managed Ruleset to the run's `enabled` state, writing ONLY the execute rule
 * this op owns — found by its exact description, MANAGED_RULESET_RULE_DESCRIPTION, and nothing else.
 * An execute rule another owner created (syd's was added by hand, without our description) is read
 * so the status is honest, but never written: it may carry overrides set after a false positive, and
 * a disabled one was switched off on purpose. A rollback DISABLES ours; it never deletes it, so
 * switching it back on is one run. See ManagedRulesetStatus for every outcome. The caller has already
 * checked the plan for an enable.
 */
async function reconcileManagedRuleset(
  token: string,
  zoneId: string,
  zonePath: string,
  enabled: boolean,
): Promise<{ status: ManagedRulesetStatus } | { error: string }> {
  const entrypoint = await getWafPhaseEntrypoint(token, zoneId, WAF_MANAGED_PHASE);
  if ("error" in entrypoint) {
    return entrypoint;
  }
  let rules: CloudflareRulesetRule[] = [];
  if (!("missing" in entrypoint)) {
    rules = entrypoint.ruleset.rules ?? [];
  }
  const ours = rules.filter((rule) => rule.description === MANAGED_RULESET_RULE_DESCRIPTION);
  const othersOwners = rules.filter(
    (rule) => rule.description !== MANAGED_RULESET_RULE_DESCRIPTION && executesCloudflareManagedRuleset(rule),
  );
  if (ours.length > 1) {
    return {
      error: `${ours.length} managed-phase rules carry the description "${MANAGED_RULESET_RULE_DESCRIPTION}" — ambiguous, refusing to change any of them.`,
    };
  }

  const ourRule = ours[0];
  if (ourRule !== undefined) {
    const ourRuleIsOn = ourRule.enabled !== false;
    if (ourRuleIsOn === enabled) {
      if (enabled) {
        return { status: "already-deployed" };
      }
      return { status: "already-disabled" };
    }
    if (!ourRule.id || "missing" in entrypoint) {
      return { error: "Cloudflare returned our Managed Ruleset execute rule without an id — cannot switch it." };
    }
    const rulesetPath = `${zonePath}/rulesets/${encodeURIComponent(entrypoint.ruleset.id as string)}`;
    const patched = await writeWafRuleset(
      token,
      "PATCH",
      `${rulesetPath}/rules/${encodeURIComponent(ourRule.id)}`,
      ourManagedRuleBody(ourRule, enabled),
    );
    if ("error" in patched) {
      return patched;
    }
    if (enabled) {
      return { status: "re-enabled" };
    }
    return { status: "disabled" };
  }

  // None of ours from here on.
  if (!enabled) {
    if (othersOwners.length > 0) {
      return { status: "not-ours" };
    }
    return { status: "absent" };
  }
  if (othersOwners.some((rule) => rule.enabled !== false)) {
    return { status: "already-deployed" };
  }
  if (othersOwners.length > 0) {
    return { status: "present-disabled" };
  }

  const executeRule = buildManagedRulesetExecuteRule();
  let written: { ruleset: CloudflareRuleset } | { error: string };
  if ("missing" in entrypoint) {
    // POST, not PUT on the entrypoint path: a racing create fails instead of replacing.
    written = await writeWafRuleset(token, "POST", `${zonePath}/rulesets`, {
      name: "default",
      kind: "zone",
      phase: WAF_MANAGED_PHASE,
      rules: [executeRule],
    });
  } else {
    const rulesetPath = `${zonePath}/rulesets/${encodeURIComponent(entrypoint.ruleset.id as string)}`;
    written = await writeWafRuleset(token, "POST", `${rulesetPath}/rules`, executeRule);
  }
  if ("error" in written) {
    return written;
  }
  return { status: "deployed" };
}

/**
 * Upsert the edge-defense baseline with the agency's own CF_DNS_API_TOKEN. Returns a structured
 * result; never throws for a Cloudflare-side failure. NEVER falls back to a platform credential
 * (there is none). Never touches any other rule in the zone.
 */
export async function actuateWafRuleUpsert(params: WafRuleUpsertParams, env: Env): Promise<WafRuleUpsertResult> {
  const zoneName = params.zone;

  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return wafFailure(zoneName, "CF_DNS_API_TOKEN is not configured on this Worker.");
  }

  const built = buildEdgeWafRules({
    zone: zoneName,
    enabled: params.enabled,
    excludedHosts: params.excludedHosts,
    agentHosts: params.agentHosts,
  });
  if (!built.ok) {
    return wafFailure(zoneName, built.reason);
  }
  // Strictest first; see edge-waf-rule.ts ("ORDER IS THE POLICY").
  const desiredRules = edgeWafRulesInOrder(built.rules);

  // Fail closed unless the agency's own token can see EXACTLY this zone.
  const zone = await resolveZoneId(token, zoneName);
  if ("error" in zone) {
    return wafFailure(zoneName, zone.error);
  }
  const zonePath = `${CF_API}/zones/${encodeURIComponent(zone.id)}`;
  const plan = zone.planLegacyId ?? "unknown";
  const ruleCap = wafCustomRuleCapForPlan(zone.planLegacyId);

  const entrypoint = await getWafPhaseEntrypoint(token, zone.id, WAF_PHASE);
  if ("error" in entrypoint) {
    return wafFailure(zoneName, entrypoint.error);
  }
  let ruleset: CloudflareRuleset | null = null;
  if (!("missing" in entrypoint)) {
    ruleset = entrypoint.ruleset;
  }
  const existingRules = ruleset?.rules ?? [];
  const otherWafRules = describeOtherWafRules(ruleset);

  // Fail closed BEFORE any write: two rules carrying one of our descriptions is ambiguous (patching
  // one would leave the other in force). Checked for every rule up front so an earlier rule's write
  // never lands while a later rule's state is ambiguous.
  let rulesToCreate = 0;
  for (const desired of desiredRules) {
    const matchCount = existingRules.filter((candidate) => candidate.description === desired.description).length;
    if (matchCount > 1) {
      return wafFailure(
        zoneName,
        `${matchCount} WAF rules already carry the description "${desired.description}" — ambiguous, refusing to change any of them.`,
      );
    }
    if (matchCount === 0) {
      rulesToCreate += 1;
    }
  }

  // The plan's allowance, also BEFORE any write. A PATCH changes no count; only a create adds one.
  // Every existing rule counts, enabled or not (Cloudflare's docs give one number per plan and do not
  // exempt disabled rules, so assuming they count can only make this refuse, never overfill).
  const plannedRuleCount = existingRules.length + rulesToCreate;
  if (plannedRuleCount > ruleCap) {
    return {
      ok: false,
      op: "waf-rule-upsert",
      zone: zoneName,
      detail:
        `refusing to change anything: zone ${zoneName} (plan "${plan}") allows ${ruleCap} custom rules, it already ` +
        `has ${existingRules.length} (${otherWafRules.length} not ours), and this op would add ${rulesToCreate} more ` +
        `— ${plannedRuleCount} in total. Free ${plannedRuleCount - ruleCap} slot(s) or upgrade the zone, then re-run.`,
      capExceeded: true,
      ruleCap,
      plannedRuleCount,
    };
  }

  const applied: WafRuleOutcome[] = [];
  // The id of OUR rule just before the current one in the documented order (strictest first), so an
  // existing rule out of that order is moved after it (review L1).
  let previousRuleId: string | null = null;
  for (const desired of desiredRules) {
    const outcome = await upsertOneWafRule(token, zonePath, ruleset, desired, previousRuleId);
    if ("error" in outcome) {
      // LOUD, never silent: name the rule that did not land and keep Cloudflare's own message.
      return wafFailure(
        zoneName,
        `could not apply rule "${desired.description}": ${outcome.error} Re-run to resume (this op is idempotent).`,
        applied,
      );
    }
    ruleset = outcome.ruleset;
    applied.push({ description: desired.description, action: outcome.action, ruleId: outcome.ruleId });
    previousRuleId = outcome.ruleId === "" ? null : outcome.ruleId;
  }

  // The Managed Ruleset — only when the job includes it, and strictly AFTER the five custom rules
  // (the agent skip is now in force). An enable needs Pro or above; a rollback runs on any plan.
  let managedRuleset: ManagedRulesetStatus = "not-requested";
  if (params.includeManagedRuleset) {
    const enableBlockedByPlan = params.enabled && !planSupportsManagedRuleset(zone.planLegacyId);
    if (enableBlockedByPlan) {
      managedRuleset = "unavailable-on-plan";
    } else {
      const managed = await reconcileManagedRuleset(token, zone.id, zonePath, params.enabled);
      if ("error" in managed) {
        return wafFailure(
          zoneName,
          `all five custom rules were applied, but the Cloudflare Managed Ruleset step failed: ${managed.error}`,
          applied,
        );
      }
      managedRuleset = managed.status;
    }
  }

  return {
    ok: true,
    op: "waf-rule-upsert",
    zone: zoneName,
    enabled: params.enabled,
    plan,
    ruleCap,
    rules: applied,
    otherWafRules,
    managedRuleset,
  };
}

// ── waf-edge-sync ──────────────────────────────────────────────────────────────────────
// hub#44 phase 2 (specs/edge-security-via-worker.md): ONE op owns every platform rule in an agency
// zone's firewall-custom phase — the six baseline rules and the packed ban chunk rules — and writes
// them in one pass with one budget check, with the agency's own CF_DNS_API_TOKEN. The rule texts are
// built by edge-waf-sync.ts and edge-waf-rule.ts; the job carries hosts, IP values and User-Agents.
//
// SEQUENCE. Every refusal comes BEFORE the first write, so a refusal writes nothing:
//   1. build the baseline and every clause (pure) — `invalid` for a clause or rule that cannot fit;
//   2. resolve the zone (`cloudflare` unless the token sees exactly this zone); a plan with the Free
//      allowance — Free itself, or a plan we do not know — is `planTooSmall` (never a partial set);
//   3. read the custom entrypoint once and sort its rules into ours, legacy and foreign (`ambiguous`
//      when two rules carry one owned description);
//   4. plan the chunks (sticky first-fit) and count: `capExceeded` when the end state would not fit
//      in cap − reservedSlots, or when the PEAK (every create lands before any delete) would not fit
//      in the cap itself;
//   5. writes, in this order: create (new chunks, missing baseline rules, each placed relative to our
//      other rules), gain patches (chunks that gain clauses, still holding what they will lose), the
//      final pass in the documented order (content patches, the lose patches, and moves of OUR rules
//      that sit before their predecessor), delete empty chunks, the Managed Ruleset (on request), and
//      LAST the legacy rules (on request). A failed write stops the run: `writeFailed`, with `landed`.
//
// FOREIGN rules are never written, moved or deleted. Inserting and moving ours shifts their indexes,
// but never their order relative to each other. No baseline rule is ever deleted (Amendment A2).
//
// IDEMPOTENT: rules are found by exact description, written only on drift, and a re-run after a
// partial apply resumes it — so the nonce-burned-before-actuation F1 rule does not bite.

/** A rule of the zone's custom phase, as the result reports it. `position` is 1-based, after the run. */
export interface WafEdgeSyncRuleReport {
  description: string;
  action: string;
  position: number;
}

/** Why the op refused, writing nothing. `busy` = another run holds the zone's lease. */
export type WafEdgeSyncRefusalCode =
  | "planTooSmall"
  | "capExceeded"
  | "ambiguous"
  | "invalid"
  | "notConfigured"
  | "cloudflare"
  | "busy";

/** The rule descriptions a run wrote, by kind of write. Legacy deletions count as deletes. */
export interface WafEdgeSyncLanded {
  created: string[];
  patched: string[];
  deleted: string[];
}

/** Why the rate-limit part did not apply (Amendment A7). The custom rules are applied either way. */
export type WafEdgeSyncRateLimitCode = "capExceeded" | "invalid" | "cloudflare" | "writeFailed";

/**
 * The rate-limit part of a run that applied the custom rules (Amendment A7). `created`, `patched` and
 * `deleted` list what landed, also when `ok` is false; `deleted` holds only later copies of one of our
 * two rules (left by overlapping runs). `omittedClauses` names each clause left out because the zone's
 * plan does not allow its field (empty when the job carried no thresholds).
 */
export interface WafEdgeSyncRateLimitReport {
  ok: boolean;
  code?: WafEdgeSyncRateLimitCode;
  detail?: string;
  created: string[];
  patched: string[];
  deleted: string[];
  omittedClauses: string[];
}

export type WafEdgeSyncResult =
  | {
      ok: true;
      op: "waf-edge-sync";
      zone: string;
      plan: string;
      cap: number;
      reservedSlots: number;
      /** The zone's custom-rule count after the run. */
      rulesUsed: number;
      foreign: WafEdgeSyncRuleReport[];
      /** Enabled `skip` rules (foreign, or legacy `doubleyoup-geo:*`) above at least one of ours. */
      preempting: WafEdgeSyncRuleReport[];
      created: string[];
      patched: string[];
      deleted: string[];
      legacyDeleted: string[];
      chunks: { block: number; challenge: number };
      rateLimit: WafEdgeSyncRateLimitReport;
    }
  | { ok: false; op: "waf-edge-sync"; zone: string; code: WafEdgeSyncRefusalCode; detail: string }
  | { ok: false; op: "waf-edge-sync"; zone: string; code: "writeFailed"; detail: string; landed: WafEdgeSyncLanded };

function wafEdgeSyncRefusal(zone: string, code: WafEdgeSyncRefusalCode, detail: string): WafEdgeSyncResult {
  return { ok: false, op: "waf-edge-sync", zone, code, detail };
}

/** One of our rules in its documented place, with the definition the run must leave it with. */
interface DesiredSyncRule {
  description: string;
  definition: WafRule;
  /** The id of the rule carrying this description in the zone (after phase A: always set). */
  ruleId: string | null;
}

/** DELETE one rule. Cloudflare answers with the updated ruleset, which this op does not rely on. */
async function deleteWafRule(token: string, url: string): Promise<{ deleted: true } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(url, { method: "DELETE", headers: cloudflareHeaders(token) });
  } catch (err) {
    return { error: `could not reach Cloudflare to delete the WAF rule: ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { error: WAF_RULES_DENIED_DETAIL };
  }
  const envelope = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (!envelope?.success) {
    return { error: `WAF rule delete failed with HTTP ${response.status}${cloudflareErrorMessage(envelope)}.` };
  }
  return { deleted: true };
}

/** Our copy of the ruleset with `rule` inserted where a POST carrying `position` puts it. */
function withRuleInserted(
  ruleset: CloudflareRuleset,
  rule: CloudflareRulesetRule,
  position: { before: string } | { after: string } | null,
): CloudflareRuleset {
  const rules = [...(ruleset.rules ?? [])];
  if (position === null) {
    rules.push(rule);
    return { ...ruleset, rules };
  }
  if ("before" in position) {
    const anchorIndex = rules.findIndex((candidate) => candidate.id === position.before);
    rules.splice(anchorIndex, 0, rule);
    return { ...ruleset, rules };
  }
  const anchorIndex = rules.findIndex((candidate) => candidate.id === position.after);
  rules.splice(anchorIndex + 1, 0, rule);
  return { ...ruleset, rules };
}

/** Our copy of the ruleset with the rule `ruleId` given `definition` (the id is kept). */
function withRuleReplaced(ruleset: CloudflareRuleset, ruleId: string, definition: WafRule): CloudflareRuleset {
  const rules = (ruleset.rules ?? []).map((rule) => {
    if (rule.id === ruleId) {
      return { ...definition, id: ruleId };
    }
    return rule;
  });
  return { ...ruleset, rules };
}

/** Our copy of the ruleset without the rule `ruleId`. */
function withRuleRemoved(ruleset: CloudflareRuleset, ruleId: string): CloudflareRuleset {
  return { ...ruleset, rules: (ruleset.rules ?? []).filter((rule) => rule.id !== ruleId) };
}

/**
 * The id Cloudflare gave the rule a POST just created: the rule carrying `description` whose id we
 * did not know before. Null when the reply does not show it.
 */
function idOfCreatedRule(reply: CloudflareRuleset, description: string, knownIds: ReadonlySet<string>): string | null {
  for (const rule of reply.rules ?? []) {
    if (rule.description !== description) {
      continue;
    }
    if (typeof rule.id === "string" && rule.id.length > 0 && !knownIds.has(rule.id)) {
      return rule.id;
    }
  }
  return null;
}

/** The plans Cloudflare's custom-rule allowance treats as Free: Free itself, and any plan we do not know. */
function planHasFreeAllowance(planLegacyId: string | null): boolean {
  return wafCustomRuleCapForPlan(planLegacyId) <= WAF_UNKNOWN_PLAN_RULE_CAP;
}

/** The longest a waf-edge-sync run holds its zone's lease. A run releases it as soon as it ends. */
export const EDGE_SYNC_LEASE_TTL_MS = 5 * 60 * 1000;

/**
 * Sync every platform rule of one agency zone with the agency's own CF_DNS_API_TOKEN. Returns a
 * structured result; never throws for a Cloudflare-side failure. NEVER falls back to a platform
 * credential (there is none). Never writes a foreign rule.
 *
 * ONE RUN PER ZONE AT A TIME. Two overlapping runs (say, a hand run of ensure-edge-waf next to a
 * scheduled sync) would each read the zone, then each create the same missing rule. So a run first
 * takes a per-zone lease in the NonceStore Durable Object (one instance per zone) and refuses with
 * `busy`, writing nothing, while another run holds it. The lease is released when the run ends; if
 * a run dies without releasing it, the lease expires after EDGE_SYNC_LEASE_TTL_MS. Duplicates that
 * still appear (a run that outlived its lease) are resolved by the run, not refused: see the
 * duplicate-chunk handling in syncEdgeZone and reconcileEdgeRateLimit.
 */
export async function actuateWafEdgeSync(params: WafEdgeSyncParams, env: Env): Promise<WafEdgeSyncResult> {
  const zoneName = params.zone;
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return wafEdgeSyncRefusal(zoneName, "notConfigured", "CF_DNS_API_TOKEN is not configured on this Worker.");
  }

  const leaseStore = env.NONCE_STORE.get(env.NONCE_STORE.idFromName(`edge-sync-lease:${zoneName}`));
  const leaseHolder = crypto.randomUUID();
  const lease = await leaseStore.acquireLease(zoneName, leaseHolder, EDGE_SYNC_LEASE_TTL_MS);
  if (lease === "busy") {
    return wafEdgeSyncRefusal(
      zoneName,
      "busy",
      `another waf-edge-sync run holds zone ${zoneName}'s lease — nothing was written. Re-run when it ends ` +
        `(the lease expires after ${EDGE_SYNC_LEASE_TTL_MS / 60000} minutes at most).`,
    );
  }
  // Every return path of syncEdgeZone comes back here, so the lease is released on each of them.
  // Only an unexpected throw skips the release, and then the lease expires on its own.
  const result = await syncEdgeZone(params, token);
  await leaseStore.releaseLease(zoneName, leaseHolder);
  return result;
}

/** The run itself, holding the zone's lease (see actuateWafEdgeSync). */
async function syncEdgeZone(params: WafEdgeSyncParams, token: string): Promise<WafEdgeSyncResult> {
  const zoneName = params.zone;

  // 1. Build everything first (pure), so an over-long rule is refused before any API call.
  const builtBaseline = buildEdgeWafRules({
    zone: zoneName,
    enabled: params.baseline.enabled,
    excludedHosts: params.baseline.excludedHosts,
    agentHosts: params.baseline.agentHosts,
  });
  if (!builtBaseline.ok) {
    return wafEdgeSyncRefusal(zoneName, "invalid", builtBaseline.reason);
  }
  // `xmlrpc: "off"` keeps the rule, disabled, so positions and the cap maths never change (A2).
  const xmlrpcEnabled = params.baseline.enabled && params.baseline.xmlrpc === "block";
  const xmlrpcRule = buildXmlrpcRule(xmlrpcEnabled);

  const blockEntries: EdgeClauseEntry[] = params.block.map((entry) => ({
    hosts: entry.hosts,
    ips: entry.ips,
    uas: entry.uas,
    all: false,
  }));
  const challengeEntries: EdgeClauseEntry[] = params.challenge.map((entry) => ({
    hosts: entry.hosts,
    ips: entry.ips,
    uas: entry.uas,
    all: entry.all === true,
  }));
  const blockClauses = buildEdgeClauses(blockEntries, params.baseline.excludedHosts);
  if (!blockClauses.ok) {
    return wafEdgeSyncRefusal(zoneName, "invalid", `block: ${blockClauses.reason}`);
  }
  const challengeClauses = buildEdgeClauses(challengeEntries, params.baseline.excludedHosts);
  if (!challengeClauses.ok) {
    return wafEdgeSyncRefusal(zoneName, "invalid", `challenge: ${challengeClauses.reason}`);
  }

  // 2. The zone and its plan.
  const zone = await resolveZoneId(token, zoneName);
  if ("error" in zone) {
    return wafEdgeSyncRefusal(zoneName, "cloudflare", zone.error);
  }
  const plan = zone.planLegacyId ?? "unknown";
  const cap = wafCustomRuleCapForPlan(zone.planLegacyId);
  if (planHasFreeAllowance(zone.planLegacyId)) {
    return wafEdgeSyncRefusal(
      zoneName,
      "planTooSmall",
      `refusing to change anything: zone ${zoneName} is on plan "${plan}", which allows ${cap} custom rules. ` +
        "The edge-security rule set needs a Pro or higher plan, and a zone never gets part of it.",
    );
  }
  const zonePath = `${CF_API}/zones/${encodeURIComponent(zone.id)}`;

  // 3. Read the custom phase once and sort its rules.
  const entrypoint = await getWafPhaseEntrypoint(token, zone.id, WAF_PHASE);
  if ("error" in entrypoint) {
    return wafEdgeSyncRefusal(zoneName, "cloudflare", entrypoint.error);
  }
  let ruleset: CloudflareRuleset | null = null;
  if (!("missing" in entrypoint)) {
    ruleset = entrypoint.ruleset;
  }
  const existingRules = ruleset?.rules ?? [];

  const existingBaseline = new Map<string, CloudflareRulesetRule>();
  const existingChunks: Record<EdgeChunkKind, Map<number, CloudflareRulesetRule>> = {
    block: new Map(),
    challenge: new Map(),
  };
  const legacyRules: CloudflareRulesetRule[] = [];
  const duplicateChunkRules: CloudflareRulesetRule[] = [];
  let foreignCount = 0;
  for (const rule of existingRules) {
    const ownership = classifyWafRuleDescription(rule.description);
    if (ownership.owner === "foreign") {
      foreignCount += 1;
      continue;
    }
    if (ownership.owner === "legacy") {
      if (params.retireLegacy && (typeof rule.id !== "string" || rule.id.length === 0)) {
        return wafEdgeSyncRefusal(zoneName, "cloudflare", `Cloudflare returned the legacy rule "${rule.description}" without an id — it cannot be retired.`);
      }
      legacyRules.push(rule);
      continue;
    }
    // Ours from here on.
    const description = rule.description as string;
    if (typeof rule.id !== "string" || rule.id.length === 0) {
      return wafEdgeSyncRefusal(zoneName, "cloudflare", `Cloudflare returned our rule "${description}" without an id — it cannot be updated.`);
    }
    if (ownership.owner === "baseline") {
      // Two baseline rules with one description: one may carry a hand edit, and writing the other
      // would leave it in force. A human must look, so refuse.
      if (existingBaseline.has(description)) {
        return wafEdgeSyncRefusal(zoneName, "ambiguous", `two WAF rules carry the description "${description}" — refusing to change any rule.`);
      }
      existingBaseline.set(description, rule);
      continue;
    }
    // Two chunk rules with one description come from overlapping runs that each created chunk N.
    // Refusing would refuse this zone for good, so resolve it: the FIRST copy (the lowest position)
    // is the chunk, planned like any other; every later copy is deleted at the end of the run, when
    // every wanted clause it held is in force in a kept or new chunk (the planner sees those clauses
    // as new and places them).
    const chunksOfKind = existingChunks[ownership.kind];
    if (chunksOfKind.has(ownership.chunkNumber)) {
      duplicateChunkRules.push(rule);
      continue;
    }
    chunksOfKind.set(ownership.chunkNumber, rule);
  }

  // 4. Plan the chunks, list our rules in their documented order, and check the budget.
  const chunkPlans: Record<EdgeChunkKind, EdgeChunkPlan[]> = {
    block: planStickyChunks(existingChunkInputs(existingChunks.block), blockClauses.clauses),
    challenge: planStickyChunks(existingChunkInputs(existingChunks.challenge), challengeClauses.clauses),
  };

  const desiredRules: DesiredSyncRule[] = [];
  const addChunkRules = (kind: EdgeChunkKind): void => {
    for (const chunkPlan of chunkPlans[kind]) {
      if (chunkPlan.finalClauses.length === 0) {
        continue;
      }
      const definition = buildEdgeChunkRule(kind, chunkPlan.chunkNumber, chunkPlan.finalClauses);
      const existing = existingChunks[kind].get(chunkPlan.chunkNumber);
      desiredRules.push({ description: definition.description, definition, ruleId: existing?.id ?? null });
    }
  };
  const addBaselineRule = (definition: WafRule): void => {
    const existing = existingBaseline.get(definition.description);
    desiredRules.push({ description: definition.description, definition, ruleId: existing?.id ?? null });
  };
  // Top to bottom (spec step 6): block chunks, the two baseline blocks, xmlrpc, challenge chunks, the
  // two baseline challenges, the agent skip. A ban block therefore beats every challenge, and the
  // agent skip (a skip of a LATER phase, not a terminating action) can sit last.
  addChunkRules("block");
  addBaselineRule(builtBaseline.rules.countryBlock);
  addBaselineRule(builtBaseline.rules.wpAdminGeo);
  addBaselineRule(xmlrpcRule);
  addChunkRules("challenge");
  addBaselineRule(builtBaseline.rules.loginGate);
  addBaselineRule(builtBaseline.rules.frontendGeo);
  addBaselineRule(builtBaseline.rules.execSkip);

  let createCount = 0;
  for (const desired of desiredRules) {
    if (desired.ruleId === null) {
      createCount += 1;
    }
  }
  let legacyAfterRun = legacyRules.length;
  if (params.retireLegacy) {
    legacyAfterRun = 0;
  }
  const usableSlots = cap - params.reservedSlots;
  const rulesAfterRun = foreignCount + desiredRules.length + legacyAfterRun;
  if (rulesAfterRun > usableSlots) {
    return wafEdgeSyncRefusal(
      zoneName,
      "capExceeded",
      `refusing to change anything: zone ${zoneName} (plan "${plan}") allows ${cap} custom rules and this op keeps ` +
        `${params.reservedSlots} free, so ${usableSlots} are usable. The run would leave ${rulesAfterRun}: ` +
        `${foreignCount} foreign + ${desiredRules.length} of ours (6 baseline, ${desiredRules.length - 6} ban chunks) + ` +
        `${legacyAfterRun} legacy. Free slots, retire the legacy rules, or upgrade the zone.`,
    );
  }
  // Every create lands before any delete, so the zone briefly holds all of today's rules plus the new ones.
  const peakRuleCount = existingRules.length + createCount;
  if (peakRuleCount > cap) {
    return wafEdgeSyncRefusal(
      zoneName,
      "capExceeded",
      `refusing to change anything: zone ${zoneName} (plan "${plan}") allows ${cap} custom rules, it has ` +
        `${existingRules.length}, and this run creates ${createCount} before it deletes anything — ${peakRuleCount} at ` +
        "the peak. Free slots first (for example, retire the legacy rules in a run that creates nothing), then re-run.",
    );
  }

  // 5. The writes.
  const created: string[] = [];
  const patched: string[] = [];
  const deleted: string[] = [];
  const legacyDeleted: string[] = [];
  const writeFailure = (detail: string): WafEdgeSyncResult => ({
    ok: false,
    op: "waf-edge-sync",
    zone: zoneName,
    code: "writeFailed",
    detail: `${detail} Re-run to resume (this op is idempotent).`,
    landed: { created: [...created], patched: [...patched], deleted: [...deleted, ...legacyDeleted] },
  });
  const notePatched = (description: string): void => {
    if (!created.includes(description) && !patched.includes(description)) {
      patched.push(description);
    }
  };

  if (ruleset === null) {
    // A zone with no custom rules at all: create the entrypoint holding every rule, in order. POST,
    // not PUT on the entrypoint path, so a racing create fails instead of replacing.
    const createdEntrypoint = await writeWafRuleset(token, "POST", `${zonePath}/rulesets`, {
      name: "default",
      kind: "zone",
      phase: WAF_PHASE,
      rules: desiredRules.map((desired) => desired.definition),
    });
    if ("error" in createdEntrypoint) {
      return writeFailure(`could not create the zone's custom-rules entrypoint: ${createdEntrypoint.error}`);
    }
    for (const desired of desiredRules) {
      created.push(desired.description);
    }
    let rulesAsCreated = createdEntrypoint.ruleset.rules;
    if (!Array.isArray(rulesAsCreated)) {
      rulesAsCreated = desiredRules.map((desired) => ({ ...desired.definition, id: "" }));
    }
    ruleset = { id: createdEntrypoint.ruleset.id, rules: rulesAsCreated };
  } else {
    const rulesetPath = `${zonePath}/rulesets/${encodeURIComponent(ruleset.id as string)}`;

    // Phase A — creates, in documented order, each placed after the nearest of OUR rules that should
    // precede it, else before the nearest that should follow it, else at the end.
    for (let index = 0; index < desiredRules.length; index += 1) {
      const desired = desiredRules[index] as DesiredSyncRule;
      if (desired.ruleId !== null) {
        continue;
      }
      const position = placementFor(desiredRules, index);
      const body: Record<string, unknown> = { ...desired.definition };
      if (position !== null) {
        body.position = position;
      }
      const knownIds = new Set((ruleset.rules ?? []).map((rule) => rule.id ?? ""));
      const reply = await writeWafRuleset(token, "POST", `${rulesetPath}/rules`, body);
      if ("error" in reply) {
        return writeFailure(`could not create rule "${desired.description}": ${reply.error}`);
      }
      created.push(desired.description);
      const newId = idOfCreatedRule(reply.ruleset, desired.description, knownIds);
      if (newId === null) {
        return writeFailure(`Cloudflare created rule "${desired.description}" but did not return its id.`);
      }
      desired.ruleId = newId;
      ruleset = withRuleInserted(ruleset, { ...desired.definition, id: newId }, position);
    }

    // Phase B — gain patches: each existing chunk that gains clauses, still holding the ones it will
    // lose, so every new clause is in force before any old one leaves.
    for (const kind of EDGE_CHUNK_KINDS) {
      for (const chunkPlan of chunkPlans[kind]) {
        if (chunkPlan.gainClauses === null) {
          continue;
        }
        const existing = existingChunks[kind].get(chunkPlan.chunkNumber) as CloudflareRulesetRule;
        const ruleId = existing.id as string;
        const definition = buildEdgeChunkRule(kind, chunkPlan.chunkNumber, chunkPlan.gainClauses);
        const reply = await writeWafRuleset(token, "PATCH", `${rulesetPath}/rules/${encodeURIComponent(ruleId)}`, { ...definition });
        if ("error" in reply) {
          return writeFailure(`could not add clauses to rule "${definition.description}": ${reply.error}`);
        }
        notePatched(definition.description);
        ruleset = withRuleReplaced(ruleset, ruleId, definition);
      }
    }

    // Phase C — the final pass, in documented order: each of our rules gets its final definition
    // (the lose patches happen here, after every gain) and, when it sits before the rule of ours that
    // should precede it, a move to just after that rule. Only our rules move; the PATCH always
    // carries the full definition (see upsertOneWafRule for why never a position-only body).
    for (let index = 0; index < desiredRules.length; index += 1) {
      const desired = desiredRules[index] as DesiredSyncRule;
      const ruleId = desired.ruleId as string;
      const current = (ruleset.rules ?? []).find((rule) => rule.id === ruleId);
      if (current === undefined) {
        return writeFailure(`rule "${desired.description}" is missing from our copy of the ruleset.`);
      }
      let predecessorId: string | null = null;
      if (index > 0) {
        predecessorId = (desiredRules[index - 1] as DesiredSyncRule).ruleId;
      }
      let outOfOrder = false;
      if (predecessorId !== null) {
        outOfOrder = indexOfRule(ruleset, ruleId) < indexOfRule(ruleset, predecessorId);
      }
      const drifted = wafRuleDrifted(current, desired.definition);
      if (!drifted && !outOfOrder) {
        continue;
      }
      const body: Record<string, unknown> = { ...desired.definition };
      if (outOfOrder) {
        body.position = { after: predecessorId };
      }
      const reply = await writeWafRuleset(token, "PATCH", `${rulesetPath}/rules/${encodeURIComponent(ruleId)}`, body);
      if ("error" in reply) {
        return writeFailure(`could not update rule "${desired.description}": ${reply.error}`);
      }
      notePatched(desired.description);
      ruleset = withRuleReplaced(ruleset, ruleId, desired.definition);
      if (outOfOrder) {
        ruleset = withRuleMovedAfter(ruleset, ruleId, predecessorId as string);
      }
    }

    // Phase D — delete the chunks left with no clause.
    for (const kind of EDGE_CHUNK_KINDS) {
      for (const chunkPlan of chunkPlans[kind]) {
        if (chunkPlan.isNew || chunkPlan.finalClauses.length > 0) {
          continue;
        }
        const existing = existingChunks[kind].get(chunkPlan.chunkNumber) as CloudflareRulesetRule;
        const ruleId = existing.id as string;
        const description = edgeChunkDescription(kind, chunkPlan.chunkNumber);
        const outcome = await deleteWafRule(token, `${rulesetPath}/rules/${encodeURIComponent(ruleId)}`);
        if ("error" in outcome) {
          return writeFailure(`could not delete the empty rule "${description}": ${outcome.error}`);
        }
        deleted.push(description);
        ruleset = withRuleRemoved(ruleset, ruleId);
      }
    }

    // Phase D, continued — the later copies of a duplicated chunk. Every wanted clause is in force in
    // a kept or new chunk by now (phases A to C), so deleting a copy cannot drop a wanted clause.
    for (const duplicate of duplicateChunkRules) {
      const ruleId = duplicate.id as string;
      const description = duplicate.description as string;
      const outcome = await deleteWafRule(token, `${rulesetPath}/rules/${encodeURIComponent(ruleId)}`);
      if ("error" in outcome) {
        return writeFailure(`could not delete a duplicate of rule "${description}": ${outcome.error}`);
      }
      deleted.push(description);
      ruleset = withRuleRemoved(ruleset, ruleId);
    }
  }

  // The Managed Ruleset — only on request, and only now: the agent skip is in force (waf-rule-upsert's
  // meaning and order). The plan check above already guarantees Pro or higher.
  if (params.baseline.includeManagedRuleset) {
    const managed = await reconcileManagedRuleset(token, zone.id, zonePath, params.baseline.enabled);
    if ("error" in managed) {
      return writeFailure(`the custom rules were applied, but the Cloudflare Managed Ruleset step failed: ${managed.error}`);
    }
    if (managed.status === "deployed") {
      created.push(MANAGED_RULESET_RULE_DESCRIPTION);
    }
    if (managed.status === "re-enabled" || managed.status === "disabled") {
      patched.push(MANAGED_RULESET_RULE_DESCRIPTION);
    }
  }

  // LAST, and only after every write of ours succeeded: retire the legacy rules (spec step 7). A ban
  // that moved into a chunk is therefore in force twice for a moment, never zero times.
  if (params.retireLegacy && legacyRules.length > 0) {
    const rulesetPath = `${zonePath}/rulesets/${encodeURIComponent(ruleset.id as string)}`;
    for (const legacyRule of legacyRules) {
      const ruleId = legacyRule.id as string;
      const description = legacyRule.description as string;
      const outcome = await deleteWafRule(token, `${rulesetPath}/rules/${encodeURIComponent(ruleId)}`);
      if ("error" in outcome) {
        return writeFailure(`could not delete the legacy rule "${description}": ${outcome.error}`);
      }
      legacyDeleted.push(description);
      ruleset = withRuleRemoved(ruleset, ruleId);
    }
  }

  // The rate-limit rules (Amendment A7), after every custom-phase write: nothing in that phase can
  // block or delay a ban, the baseline or a legacy retirement. They have their own budget, and any
  // failure there is reported in `rateLimit` while the run still succeeds.
  const rateLimit = await reconcileEdgeRateLimit({
    token,
    zoneId: zone.id,
    zonePath,
    zoneName,
    planLegacyId: zone.planLegacyId,
    excludedHosts: params.baseline.excludedHosts,
    rateLimit: params.rateLimit,
  });

  return {
    ok: true,
    op: "waf-edge-sync",
    zone: zoneName,
    plan,
    cap,
    reservedSlots: params.reservedSlots,
    ...describeRulesAfterSync(ruleset),
    created,
    patched,
    deleted,
    legacyDeleted,
    chunks: {
      block: countLiveChunks(chunkPlans.block),
      challenge: countLiveChunks(chunkPlans.challenge),
    },
    rateLimit,
  };
}

/** A rule of the http_ratelimit phase, as the ruleset API returns it (only the fields we read). */
interface CloudflareRateLimitRule extends CloudflareRulesetRule {
  ratelimit?: unknown;
}

interface EdgeRateLimitInput {
  token: string;
  zoneId: string;
  zonePath: string;
  zoneName: string;
  planLegacyId: string | null;
  excludedHosts: readonly string[];
  rateLimit: WafEdgeSyncRateLimit;
}

/**
 * The PATCH body that switches one of OUR rate-limit rules off while keeping everything else it
 * carries. Used when the job disables rate limiting without thresholds, so there is no definition to
 * rebuild the rule from.
 */
function rateLimitRuleSwitchedOff(existing: CloudflareRateLimitRule): Record<string, unknown> {
  const body: Record<string, unknown> = {
    description: existing.description,
    expression: existing.expression,
    action: existing.action,
    enabled: false,
  };
  if (existing.ratelimit !== undefined) {
    body.ratelimit = existing.ratelimit;
  }
  if (existing.action_parameters !== undefined) {
    body.action_parameters = existing.action_parameters;
  }
  return body;
}

/**
 * Bring our two rate-limit rules to the job's state (Amendment A7). Never throws and never fails the
 * op: every problem comes back as `ok: false` in the report, with what landed.
 *   - enabled: both rules must fit the phase's budget (foreign rules count against it), or NEITHER is
 *     written. Writes go: patches of our existing rules (full definition, on drift), then deletes of
 *     later copies, then creates. So the phase never holds more than foreign + 2 rules, and a kept
 *     rule carries its definition before its copy goes. A new rule is appended (Cloudflare's docs
 *     place rate-limit rules at the end of the list). Our rules never move.
 *   - disabled (or absent): our rules that exist are switched off in place, later copies are deleted,
 *     and nothing is created.
 * Two rules with one of our descriptions come from overlapping runs: the first (lowest position) is
 * kept and every later copy deleted — never a refusal, which would stall rate limiting for good.
 * Foreign rate-limit rules are never written.
 */
async function reconcileEdgeRateLimit(input: EdgeRateLimitInput): Promise<WafEdgeSyncRateLimitReport> {
  const created: string[] = [];
  const patched: string[] = [];
  const deleted: string[] = [];
  let omittedClauses: string[] = [];
  const report = (): WafEdgeSyncRateLimitReport => ({ ok: true, created, patched, deleted, omittedClauses });
  const failure = (code: WafEdgeSyncRateLimitCode, detail: string): WafEdgeSyncRateLimitReport => ({
    ok: false,
    code,
    detail,
    created: [...created],
    patched: [...patched],
    deleted: [...deleted],
    omittedClauses: [...omittedClauses],
  });

  // 1. Build our two rules (pure) when the job carries thresholds; a threshold the plan does not
  //    allow is refused here, before any rate-limit write.
  const rateLimit = input.rateLimit;
  let desiredByDescription: Map<string, RateLimitRule> | null = null;
  if (rateLimit.origin !== undefined && rateLimit.expensive !== undefined) {
    const built = buildRateLimitRules({
      zone: input.zoneName,
      planLegacyId: input.planLegacyId,
      excludedHosts: input.excludedHosts,
      enabled: rateLimit.enabled,
      origin: rateLimit.origin,
      expensive: rateLimit.expensive,
    });
    if (!built.ok) {
      return failure("invalid", built.reason);
    }
    omittedClauses = built.omittedClauses;
    desiredByDescription = new Map([
      [RATE_LIMIT_ORIGIN_DESCRIPTION, built.origin],
      [RATE_LIMIT_EXPENSIVE_DESCRIPTION, built.expensive],
    ]);
  }

  // 2. Read the phase and find our rules by exact description.
  const entrypoint = await getWafPhaseEntrypoint(input.token, input.zoneId, RATE_LIMIT_PHASE);
  if ("error" in entrypoint) {
    return failure("cloudflare", entrypoint.error);
  }
  let ruleset: CloudflareRuleset | null = null;
  if (!("missing" in entrypoint)) {
    ruleset = entrypoint.ruleset;
  }
  const existingRules = (ruleset?.rules ?? []) as CloudflareRateLimitRule[];
  const ours = new Map<string, CloudflareRateLimitRule>();
  const duplicates: CloudflareRateLimitRule[] = [];
  let foreignCount = 0;
  for (const rule of existingRules) {
    const description = rule.description ?? "";
    if (!RATE_LIMIT_DESCRIPTIONS.includes(description)) {
      foreignCount += 1;
      continue;
    }
    if (typeof rule.id !== "string" || rule.id.length === 0) {
      return failure("cloudflare", `Cloudflare returned our rate-limit rule "${description}" without an id — it cannot be updated.`);
    }
    if (ours.has(description)) {
      duplicates.push(rule);
      continue;
    }
    ours.set(description, rule);
  }

  // Deletes every later copy of one of our rules. Called after the kept rules carry their definition.
  const deleteDuplicates = async (rulesetPath: string): Promise<string | null> => {
    for (const duplicate of duplicates) {
      const description = duplicate.description as string;
      const outcome = await deleteWafRule(input.token, `${rulesetPath}/rules/${encodeURIComponent(duplicate.id as string)}`);
      if ("error" in outcome) {
        return `could not delete a duplicate of rate-limit rule "${description}": ${outcome.error} Re-run to resume.`;
      }
      deleted.push(description);
    }
    return null;
  };

  // 3. Disabled: switch ours off in place. Nothing is created, so the budget does not matter.
  if (!rateLimit.enabled) {
    if (ruleset === null) {
      return report();
    }
    const rulesetPath = `${input.zonePath}/rulesets/${encodeURIComponent(ruleset.id as string)}`;
    for (const description of RATE_LIMIT_DESCRIPTIONS) {
      const existing = ours.get(description);
      if (existing === undefined) {
        continue;
      }
      let body: Record<string, unknown>;
      const desired = desiredByDescription?.get(description);
      if (desired !== undefined) {
        if (!rateLimitRuleDrifted(existing, desired)) {
          continue;
        }
        body = { ...desired };
      } else {
        if (existing.enabled === false) {
          continue;
        }
        body = rateLimitRuleSwitchedOff(existing);
      }
      const reply = await writeWafRuleset(input.token, "PATCH", `${rulesetPath}/rules/${encodeURIComponent(existing.id as string)}`, body);
      if ("error" in reply) {
        return failure("writeFailed", `could not switch off rate-limit rule "${description}": ${reply.error} Re-run to resume.`);
      }
      patched.push(description);
    }
    const duplicateFailure = await deleteDuplicates(rulesetPath);
    if (duplicateFailure !== null) {
      return failure("writeFailed", duplicateFailure);
    }
    return report();
  }

  // 4. Enabled: the validator guarantees thresholds, so both rules were built in step 1.
  if (desiredByDescription === null) {
    return failure("invalid", "rateLimit.enabled is true but the job carries no thresholds");
  }
  const cap = rateLimitRuleCapForPlan(input.planLegacyId);
  const rulesAfterRun = foreignCount + RATE_LIMIT_DESCRIPTIONS.length;
  if (rulesAfterRun > cap) {
    return failure(
      "capExceeded",
      `wrote neither rate-limit rule: zone ${input.zoneName} (plan "${input.planLegacyId ?? "unknown"}") allows ${cap} ` +
        `rate-limit rules, and ${foreignCount} foreign + our ${RATE_LIMIT_DESCRIPTIONS.length} would make ${rulesAfterRun}. ` +
        "Free a rate-limit slot or upgrade the zone. The custom rules were applied.",
    );
  }

  if (ruleset === null) {
    // No rate-limit rules at all yet: create the entrypoint holding both. POST, not PUT on the
    // entrypoint path, so a racing create fails instead of replacing.
    const rules: RateLimitRule[] = [];
    for (const description of RATE_LIMIT_DESCRIPTIONS) {
      rules.push(desiredByDescription.get(description) as RateLimitRule);
    }
    const reply = await writeWafRuleset(input.token, "POST", `${input.zonePath}/rulesets`, {
      name: "default",
      kind: "zone",
      phase: RATE_LIMIT_PHASE,
      rules,
    });
    if ("error" in reply) {
      return failure("writeFailed", `could not create the zone's rate-limit entrypoint: ${reply.error} Re-run to resume.`);
    }
    for (const description of RATE_LIMIT_DESCRIPTIONS) {
      created.push(description);
    }
    return report();
  }

  const rulesetPath = `${input.zonePath}/rulesets/${encodeURIComponent(ruleset.id as string)}`;
  for (const description of RATE_LIMIT_DESCRIPTIONS) {
    const desired = desiredByDescription.get(description) as RateLimitRule;
    const existing = ours.get(description);
    if (existing === undefined || !rateLimitRuleDrifted(existing, desired)) {
      continue;
    }
    const reply = await writeWafRuleset(input.token, "PATCH", `${rulesetPath}/rules/${encodeURIComponent(existing.id as string)}`, {
      ...desired,
    });
    if ("error" in reply) {
      return failure("writeFailed", `could not update rate-limit rule "${description}": ${reply.error} Re-run to resume.`);
    }
    patched.push(description);
  }
  const duplicateFailure = await deleteDuplicates(rulesetPath);
  if (duplicateFailure !== null) {
    return failure("writeFailed", duplicateFailure);
  }
  for (const description of RATE_LIMIT_DESCRIPTIONS) {
    if (ours.has(description)) {
      continue;
    }
    const desired = desiredByDescription.get(description) as RateLimitRule;
    const reply = await writeWafRuleset(input.token, "POST", `${rulesetPath}/rules`, { ...desired });
    if ("error" in reply) {
      return failure("writeFailed", `could not create rate-limit rule "${description}": ${reply.error} Re-run to resume.`);
    }
    created.push(description);
  }
  return report();
}

const EDGE_CHUNK_KINDS: readonly EdgeChunkKind[] = ["block", "challenge"];

/** The packer's view of the chunk rules of one kind: number + clauses as found. */
function existingChunkInputs(chunks: ReadonlyMap<number, CloudflareRulesetRule>): ExistingEdgeChunk[] {
  const inputs: ExistingEdgeChunk[] = [];
  for (const [chunkNumber, rule] of chunks) {
    inputs.push({ chunkNumber, clauses: splitChunkExpression(rule.expression ?? "") });
  }
  return inputs;
}

/** How many chunk rules of one kind remain after the run. */
function countLiveChunks(plans: readonly EdgeChunkPlan[]): number {
  let count = 0;
  for (const chunkPlan of plans) {
    if (chunkPlan.finalClauses.length > 0) {
      count += 1;
    }
  }
  return count;
}

/**
 * Where a create of `desiredRules[index]` goes: after the nearest EXISTING rule of ours that should
 * precede it, else before the nearest existing one that should follow it, else (none of ours exists)
 * at the end of the phase.
 */
function placementFor(desiredRules: readonly DesiredSyncRule[], index: number): { before: string } | { after: string } | null {
  for (let earlier = index - 1; earlier >= 0; earlier -= 1) {
    const ruleId = (desiredRules[earlier] as DesiredSyncRule).ruleId;
    if (ruleId !== null) {
      return { after: ruleId };
    }
  }
  for (let later = index + 1; later < desiredRules.length; later += 1) {
    const ruleId = (desiredRules[later] as DesiredSyncRule).ruleId;
    if (ruleId !== null) {
      return { before: ruleId };
    }
  }
  return null;
}

/** The result's view of the phase after the run: the rule count, the foreign rules and the pre-empting skips. */
function describeRulesAfterSync(ruleset: CloudflareRuleset): {
  rulesUsed: number;
  foreign: WafEdgeSyncRuleReport[];
  preempting: WafEdgeSyncRuleReport[];
} {
  const rules = ruleset.rules ?? [];
  let lastOurIndex = -1;
  for (let index = 0; index < rules.length; index += 1) {
    const owner = classifyWafRuleDescription((rules[index] as CloudflareRulesetRule).description).owner;
    if (owner === "baseline" || owner === "chunk") {
      lastOurIndex = index;
    }
  }
  const foreign: WafEdgeSyncRuleReport[] = [];
  const preempting: WafEdgeSyncRuleReport[] = [];
  for (let index = 0; index < rules.length; index += 1) {
    const rule = rules[index] as CloudflareRulesetRule;
    const owner = classifyWafRuleDescription(rule.description).owner;
    const report: WafEdgeSyncRuleReport = {
      description: rule.description ?? "",
      action: rule.action ?? "",
      position: index + 1,
    };
    if (owner === "foreign") {
      foreign.push(report);
    }
    // An enabled skip above one of ours can stop our rule from running for the traffic it matches.
    // Reported only: a foreign rule is never moved, and a legacy one goes only with retireLegacy.
    const canPreempt = owner === "foreign" || owner === "legacy";
    if (canPreempt && rule.action === "skip" && rule.enabled !== false && index < lastOurIndex) {
      preempting.push(report);
    }
  }
  return { rulesUsed: rules.length, foreign, preempting };
}

// ── wp-cli ─────────────────────────────────────────────────────────────────────────────
// The first "heavy"/data-plane Direction-B op: run a wp-cli command in a cell site's docroot
// through the agency's OWN on-VM cell-agent, authenticated with the agency's OWN
// CELL_AGENT_TOKEN. This re-authenticates, through the signed-Worker path, the exec power the
// platform's orchestrator already has directly (cells.ts::execOnCell) — so it MUST stay behind
// the same verify + single-use-nonce gate (index.ts::handleActuate). It proves the rewiring
// pattern (orchestrator -> signed job -> agency Worker -> cell-agent -> executes on the cell)
// that later carries backups/DB/migrations/provisioning.
//
// COMMAND INJECTION is the main risk here. The cell-agent runs the command we send under
// `sh -lc "cd <docroot> && <cmd>"`, so an unquoted argument is a shell-injection hole: an arg
// like `; rm -rf /` or `$(...)` would be interpreted by the shell, not handed to wp-cli. We
// defuse that by SHELL-QUOTING every argument (shellQuoteArg): each becomes exactly one literal
// wp-cli token. This per-arg quoting + the strict docroot grammar (dispatch-params.ts) are the
// load-bearing security controls of this op.
//
// F1 (retry / nonce) NOTE: wp-cli is NOT idempotent in general (e.g. `wp plugin update`), and
// handleActuate BURNS the job's nonce on receipt, so a TRANSIENT failure of a non-idempotent
// command cannot be retried by re-POSTing — it needs a re-signed job with a fresh nonce, which
// for a non-idempotent command could double-apply. The Direction-B proof deliberately uses a
// READ-ONLY command (`option get siteurl`), so F1 does not bite here. Before wiring a
// non-idempotent wp-cli use into an automatic flow, the F1 dispatcher contract (bind the nonce
// to a completed side effect, or gate re-sign on a confirmed non-effect) must land first.
//
// v1 LIMITATION: CELL_AGENT_URL / CELL_AGENT_TOKEN are SINGLE-CELL (one agency cell). A
// multi-cell agency needs per-cell resolution (a cell selector in the params + a map of
// URL/token pairs) before this op can target more than one cell.

// A conservative cap on how much stdout/stderr the Worker RELAYS BACK to the orchestrator.
// This bounds the RETURN payload ONLY — it does NOT bound the Worker's memory (by the time
// truncateOutput runs, the whole reply is already parsed in memory). Worker memory is bounded
// separately by WP_CLI_RESPONSE_MAX_BYTES below, which stops reading the stream before a huge
// reply can be buffered.
const WP_CLI_OUTPUT_MAX_CHARS = 64 * 1024;
// A HARD cap on how many bytes of the cell-agent reply the Worker will buffer at all. A signed
// command with very large output (e.g. `wp db export -`, or `wp eval` echoing a big string)
// makes the agent return a multi-MB/GB body; buffering it whole would exhaust the Worker's
// 128 MB and turn a success into a 500. We read the response as a STREAM and abort past this
// cap, failing closed rather than OOMing. GENUINELY large-output ops (DB export, media dumps)
// must stream to R2 directly, NOT return through the Worker — this op is for small-output
// commands (reads, single option writes), and this cap enforces that.
const WP_CLI_RESPONSE_MAX_BYTES = 1024 * 1024;
// The cell-agent's /exec default timeout is 60s; send the same explicit bound. A read-only
// command finishes well inside this.
const WP_CLI_EXEC_TIMEOUT_MS = 60_000;

/**
 * POSIX single-quote one argument so the cell-agent's `sh -lc` treats it as ONE literal token.
 * Inside single quotes the shell interprets EVERY character literally (no $, backtick, ;, glob,
 * or whitespace splitting); the only character single quotes cannot contain is a single quote,
 * so an embedded one is closed, escaped as \', and reopened ('\''). This is the standard,
 * complete POSIX-sh single-quoting rule — the load-bearing anti-injection control for this op.
 */
function shellQuoteArg(arg: string): string {
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

/** Truncate relayed command output to a bounded size, marking when it was cut. */
function truncateOutput(text: string): string {
  if (text.length <= WP_CLI_OUTPUT_MAX_CHARS) return text;
  return text.slice(0, WP_CLI_OUTPUT_MAX_CHARS) + "\n…[truncated]";
}

/**
 * Read a Response body as a STREAM, accumulating at most `capBytes` bytes. If the body exceeds
 * the cap, STOP reading (cancel the stream — never buffer the rest) and report overflow. This is
 * what keeps a huge cell-agent reply from exhausting the Worker's memory: we fail closed instead
 * of OOMing. On success the accumulated bytes (<= cap) are decoded to a UTF-8 string for the
 * caller to JSON.parse.
 */
export async function readBodyCapped(
  response: Response,
  capBytes: number,
): Promise<{ ok: true; text: string } | { ok: false; detail: string }> {
  const stream = response.body;
  if (!stream) {
    return { ok: false, detail: "cell-agent returned no response body." };
  }
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > capBytes) {
        // Past the cap: drop what we have and stop reading — do NOT buffer the rest (the whole
        // point of the cap is that a huge reply never lands in Worker memory).
        await reader.cancel().catch(() => {});
        return {
          ok: false,
          detail: `cell-agent output exceeded ${capBytes} bytes (${Math.round(capBytes / 1024)} KiB) — this op is for small-output commands; large-output ops (e.g. wp db export) must stream to R2, not return through the Worker.`,
        };
      }
      chunks.push(value);
    }
  } catch (err) {
    return { ok: false, detail: `error reading cell-agent response: ${errorMessage(err)}` };
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(merged) };
}

function wpCliFailure(detail: string): WpCliResult {
  return { ok: false, op: "wp-cli", detail };
}

/**
 * The outcome of ONE cell-agent /exec call, as the cell ops see it: either the exec COMPLETED
 * (any exit code — interpreting it is the op's job) or the relay itself failed (unreachable,
 * redirected, auth rejected, oversized reply, agent-side error) with a ready-to-return detail.
 */
type CellAgentExecOutcome =
  | { ok: true; code: number; stdout: string; stderr: string }
  | { ok: false; detail: string };

/**
 * POST a script to the agency's cell-agent /exec and read the bounded reply. This is the ONE
 * relay both cell ops (wp-cli, db-export) share, so the fail-closed rules live in one place:
 * refuse redirects, surface an auth rejection cleanly, cap the reply in memory, and treat any
 * non-200 / non-JSON / code-less body as a cell-agent-side error rather than a completed exec.
 * The caller has already checked CELL_AGENT_URL / CELL_AGENT_TOKEN are configured.
 */
async function execOnCellAgent(
  cellAgentUrl: string,
  cellAgentToken: string,
  request: { script: string; docroot: string; timeoutMs: number },
): Promise<CellAgentExecOutcome> {
  // The exact request shape the cell-agent's /exec endpoint accepts (infra/cell-agent/agent.php):
  // POST /exec, Authorization: Bearer <token>, body { script, docroot, timeoutMs }. It answers
  // HTTP 200 with { code, stdout, stderr } even when the command's exit code is non-zero.
  let response: Response;
  try {
    response = await fetch(stripTrailingSlash(cellAgentUrl) + "/exec", {
      method: "POST",
      headers: {
        authorization: `Bearer ${cellAgentToken}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        script: request.script,
        docroot: request.docroot,
        timeoutMs: request.timeoutMs,
      }),
      // "manual", NOT "error": workerd does not implement redirect:"error" and throws at runtime
      // ("Invalid redirect value ... use manual and check the response status code"). We still
      // refuse to FOLLOW a redirect (a signed job must reach the configured cell-agent, not be
      // bounced elsewhere), so we ask for the redirect verbatim and reject it below — preserving
      // the original "don't silently follow" intent that redirect:"error" was reaching for.
      redirect: "manual",
    });
  } catch (err) {
    return { ok: false, detail: `could not reach the cell-agent /exec: ${errorMessage(err)}` };
  }

  // The cell-agent should never 3xx. With redirect:"manual" a redirect surfaces as either an
  // opaqueredirect response (status 0) or a 3xx status — treat EITHER as a fail-closed error
  // rather than following it: a redirect means a misconfigured CELL_AGENT_URL, not a valid exec.
  if (response.status === 0 || (response.status >= 300 && response.status < 400)) {
    await response.body?.cancel().catch(() => {});
    return { ok: false, detail: `cell-agent redirected unexpectedly (HTTP ${response.status}) — refusing to follow.` };
  }

  if (response.status === 401 || response.status === 403) {
    await response.body?.cancel().catch(() => {});
    return { ok: false, detail: "the cell-agent rejected CELL_AGENT_TOKEN (bearer auth failed)." };
  }

  // Read the reply as a STREAM with a hard byte cap so a very large output cannot make the
  // Worker buffer a multi-MB/GB body and exhaust its 128 MB memory (see WP_CLI_RESPONSE_MAX_BYTES).
  // The cell-agent's own error bodies (bad json / bad docroot / spawn failure) are tiny, so this
  // cap only ever trips on a genuinely huge command output — which neither cell op is for.
  const read = await readBodyCapped(response, WP_CLI_RESPONSE_MAX_BYTES);
  if (!read.ok) {
    return { ok: false, detail: read.detail };
  }

  // Only NOW parse — the buffered text is bounded (<= cap). JSON.parse needs the try/catch (no
  // non-throwing parse); a non-JSON reply is treated as a cell-agent-side error below.
  let body: { code?: number; stdout?: string; stderr?: string; error?: string } | null;
  try {
    body = JSON.parse(read.text) as { code?: number; stdout?: string; stderr?: string; error?: string };
  } catch {
    body = null;
  }

  // A non-200, a missing/non-JSON body, or a body without a numeric `code` is a cell-agent-side
  // error (bad json, bad docroot, spawn failure, ...), not a completed exec — report it as ok:false.
  if (!response.ok || !body || typeof body.code !== "number") {
    const detail = body?.error ? `: ${body.error}` : "";
    return { ok: false, detail: `cell-agent /exec failed with HTTP ${response.status}${detail}.` };
  }

  return { ok: true, code: body.code, stdout: body.stdout ?? "", stderr: body.stderr ?? "" };
}

/**
 * Run `wp <args>` in `params.docroot` on the agency's cell via the cell-agent's /exec endpoint,
 * using the agency's OWN CELL_AGENT_TOKEN. Returns a structured result; a cell-agent-side
 * failure is reported as ok:false + detail (the route still answers HTTP 200, so the
 * orchestrator classifies it), never a thrown 500. NEVER uses a platform credential (there is
 * none here). A NON-ZERO wp-cli exit is NOT a failure of this actuator — it is a successful exec
 * whose exitCode is carried back for the caller to interpret.
 */
export async function actuateWpCli(params: WpCliParams, env: Env): Promise<WpCliResult> {
  const cellAgentUrl = env.CELL_AGENT_URL;
  const cellAgentToken = env.CELL_AGENT_TOKEN;
  if (!cellAgentUrl || !cellAgentToken) {
    return wpCliFailure("CELL_AGENT_URL / CELL_AGENT_TOKEN are not configured on this Worker.");
  }

  // Build the command by shell-quoting EACH argument. Every element becomes one literal wp-cli
  // token, so a metacharacter-laden arg can never be interpreted by the cell-agent's shell.
  const command = `wp ${params.args.map(shellQuoteArg).join(" ")}`;

  const exec = await execOnCellAgent(cellAgentUrl, cellAgentToken, {
    script: command,
    docroot: params.docroot,
    timeoutMs: WP_CLI_EXEC_TIMEOUT_MS,
  });
  if (!exec.ok) {
    return wpCliFailure(exec.detail);
  }

  return {
    ok: true,
    op: "wp-cli",
    exitCode: exec.code,
    stdout: truncateOutput(exec.stdout),
    stderr: truncateOutput(exec.stderr),
  };
}

// ── provision-ssh-keys ───────────────────────────────────────────────────────────────
// Declare a cell site's FULL authorized-SSH-key set on the GATEWAY (planning/39 increment 1).
// Unlike wp-cli/db-export, this does NOT go through /exec: key material must never be
// shell-quoted into a command line (a comment could carry a metacharacter, and a key line is
// exactly the kind of value that belongs in a request BODY, not an argv). It relays to the
// gateway cell-agent's DEDICATED /provision-ssh-keys endpoint, which hands the JSON straight to
// the sudoers-whitelisted writer script on STDIN — the same STDIN-JSON convention the SFTP
// endpoint uses. The Worker sends ONLY {slug, authorizedKeys}: the gateway writes one
// authorized_keys file per site login and needs no GCP/project data. Uses the agency's OWN
// CELL_AGENT_TOKEN, never a platform credential.
//
// v1 LIMITATION (shared with wp-cli): CELL_AGENT_URL is SINGLE-CELL and, for THIS op, MUST point
// at the agency's GATEWAY cell-agent (where the SFTP jails + /etc/ssh/doubleyoup-keys live), not
// the web node. A multi-node / multi-cell agency needs per-node resolution before this can target
// more than that one gateway.

// A small reply is expected (a status object); cap the buffered body so a misconfigured endpoint
// can never make the Worker OOM (same reasoning as WP_CLI_RESPONSE_MAX_BYTES).
const SSH_KEYS_RESPONSE_MAX_BYTES = 64 * 1024;

function provisionSshKeysFailure(slug: string, detail: string): ProvisionSshKeysResult {
  return { ok: false, op: "provision-ssh-keys", slug, detail };
}

/**
 * Write the FULL authorized-key set for `params.slug` on the agency's GATEWAY via the cell-agent's
 * /provision-ssh-keys endpoint, using the agency's OWN CELL_AGENT_TOKEN. Idempotent (declare-the-
 * whole-set): a re-run converges on the same file. Returns a structured result; a cell-agent-side
 * failure is ok:false + detail (the route still answers HTTP 200 so the orchestrator classifies it),
 * never a thrown 500.
 */
export async function actuateProvisionSshKeys(
  params: ProvisionSshKeysParams,
  env: Env,
): Promise<ProvisionSshKeysResult> {
  const cellAgentUrl = env.CELL_AGENT_URL;
  const cellAgentToken = env.CELL_AGENT_TOKEN;
  if (!cellAgentUrl || !cellAgentToken) {
    return provisionSshKeysFailure(params.slug, "CELL_AGENT_URL / CELL_AGENT_TOKEN are not configured on this Worker.");
  }

  // The exact request shape the gateway cell-agent's /provision-ssh-keys endpoint accepts
  // (infra/cell-agent/agent.php): POST, Authorization: Bearer <token>, JSON body { slug,
  // authorizedKeys }. It answers HTTP 200 { ok, slug, count } on success and a non-2xx on failure.
  let response: Response;
  try {
    response = await fetch(stripTrailingSlash(cellAgentUrl) + "/provision-ssh-keys", {
      method: "POST",
      headers: {
        authorization: `Bearer ${cellAgentToken}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ slug: params.slug, authorizedKeys: params.authorizedKeys }),
      // "manual", not "error": workerd rejects redirect:"error" at runtime. We still refuse to
      // FOLLOW a redirect (a signed job must reach the configured gateway agent, not be bounced
      // elsewhere) — a redirect surfaces below as a fail-closed error.
      redirect: "manual",
    });
  } catch (err) {
    return provisionSshKeysFailure(params.slug, `could not reach the cell-agent /provision-ssh-keys: ${errorMessage(err)}`);
  }

  // The cell-agent should never 3xx (status 0 is workerd's opaqueredirect). Treat either as
  // fail-closed rather than following it: a redirect means a misconfigured CELL_AGENT_URL.
  if (response.status === 0 || (response.status >= 300 && response.status < 400)) {
    await response.body?.cancel().catch(() => {});
    return provisionSshKeysFailure(params.slug, `cell-agent redirected unexpectedly (HTTP ${response.status}) — refusing to follow.`);
  }
  if (response.status === 401 || response.status === 403) {
    await response.body?.cancel().catch(() => {});
    return provisionSshKeysFailure(params.slug, "the cell-agent rejected CELL_AGENT_TOKEN (bearer auth failed).");
  }

  const read = await readBodyCapped(response, SSH_KEYS_RESPONSE_MAX_BYTES);
  if (!read.ok) {
    return provisionSshKeysFailure(params.slug, read.detail);
  }

  // Only NOW parse the bounded text. A non-JSON reply is a cell-agent-side error.
  let body: { ok?: boolean; count?: number; error?: string } | null;
  try {
    body = JSON.parse(read.text) as { ok?: boolean; count?: number; error?: string };
  } catch {
    body = null;
  }

  if (!response.ok || !body || body.ok !== true) {
    const detail = body?.error ? `: ${body.error}` : "";
    return provisionSshKeysFailure(params.slug, `cell-agent /provision-ssh-keys failed with HTTP ${response.status}${detail}.`);
  }

  // Prefer the count the gateway actually wrote; fall back to the set we sent.
  const count = typeof body.count === "number" ? body.count : params.authorizedKeys.length;
  return { ok: true, op: "provision-ssh-keys", slug: params.slug, count };
}

// ── db-export ──────────────────────────────────────────────────────────────────────────
// The first LARGE-OUTPUT Direction-B op: the agency's cell exports a site's WordPress DB and
// uploads the dump STRAIGHT to the agency's own object store (S3_* — R2 in practice). The dump
// flows cell -> R2 and never through this Worker (the wp-cli op's byte cap exists precisely
// because a DB dump must not come back through here). The Worker's only jobs are to:
//   1. PRESIGN a single-object PUT URL with the agency's S3_* credential (sigv4.ts::presignS3Put).
//      The URL is the ONLY thing that reaches the cell — it embeds a derived signature, NOT the
//      secret key, is valid for DB_EXPORT_PRESIGN_EXPIRES_SECONDS, and can do exactly one thing:
//      PUT that one key. No object-store credential ever lands on the cell.
//   2. Relay a short script to the cell-agent's /exec (the SAME relay wp-cli uses, with the
//      agency's own CELL_AGENT_TOKEN) that exports the DB to a temp FILE, `curl --upload-file`s
//      that file to the presigned URL, and removes the file. A file, not a stream: curl then sends
//      a Content-Length, whereas a chunked/streamed PUT can be rejected by a presigned S3 PUT.
//   3. Return a SMALL result: {ok, op, objectKey, exitCode}. Never the dump, never the URL.
//
// IDEMPOTENCY (F1): the orchestrator generates `objectKey` ONCE before its retry loop, so a
// re-signed retry after a transient failure PUTs to the SAME key — an overwrite that converges.
// That is why `db-export` is registered idempotent (AGENCY_OP_IDEMPOTENT) while wp-cli is not.
//
// TIME BUDGET: the presign expiry is the effective export+upload window — R2 checks
// X-Amz-Date + X-Amz-Expires when the PUT ARRIVES, so the export must finish and the upload
// begin within it. The exec timeout is set just inside that window. A very large DB may need a
// wider window, or a streaming/multipart approach, later.

// How long the presigned PUT stays valid, from the moment this Worker mints it.
const DB_EXPORT_PRESIGN_EXPIRES_SECONDS = 600;
// The cell-agent kills the exec at this bound. Held just inside the presign window so a slow
// export is cut off by the agent rather than left uploading to an already-expired URL.
const DB_EXPORT_EXEC_TIMEOUT_MS = 540_000;
// How much of the cell's stderr/stdout we quote into a FAILURE detail (each). Enough to see a
// mysqldump / curl error, small enough to keep the result small.
const DB_EXPORT_DETAIL_OUTPUT_MAX_CHARS = 2048;

/**
 * The POSIX-sh script the cell runs (under the cell-agent's `sh -lc "cd <docroot> && <script>"`,
 * dash on the Debian cells — so no `pipefail`, and one `;`-joined line). Steps:
 *   set -eu                       fail fast on any error or unset variable
 *   T=$(mktemp)                   a temp FILE for the dump (local /tmp, not the NFS docroot)
 *   trap 'rm -f "$T"' EXIT INT TERM  remove the dump on EVERY exit path — success, a failed
 *                                 export/upload (set -e exits still run EXIT), or a signal
 *   wp db export "$T" ...         dump the DB to the file (--add-drop-table matches the
 *                                 platform's own backup dumps; --quiet drops the success line)
 *   curl --upload-file "$T" URL   PUT the file to the presigned URL (--upload-file implies PUT
 *                                 and sends Content-Length; --fail-with-body turns an HTTP >= 400
 *                                 into a non-zero exit AND keeps the store's error body on stdout
 *                                 for the failure detail; -sS = no progress bar, errors shown)
 * The presigned URL is single-quoted (shellQuoteArg): it carries `&` and `=`, and although it is
 * Worker-generated (not attacker data) it is quoted like every other value we hand to a shell.
 */
export function buildDbExportScript(presignedUrl: string): string {
  return [
    "set -eu",
    "T=$(mktemp)",
    `trap 'rm -f "$T"' EXIT INT TERM`,
    'wp db export "$T" --add-drop-table --quiet',
    `curl -sS --fail-with-body --upload-file "$T" ${shellQuoteArg(presignedUrl)}`,
  ].join("; ");
}

/**
 * Scrub the presigned URL — and, belt-and-braces, any SigV4 query credential/signature — out of
 * text we are about to return as a failure detail. curl's error lines do not normally echo the
 * URL, but the detail must never carry a still-valid upload capability or the access-key ID.
 */
function redactPresignedUrl(text: string, presignedUrl: string): string {
  return text
    .split(presignedUrl)
    .join("[presigned-url]")
    .replace(/X-Amz-Signature=[0-9a-fA-F]+/g, "X-Amz-Signature=[redacted]")
    .replace(/X-Amz-Credential=[^&\s'"]+/g, "X-Amz-Credential=[redacted]");
}

/** Bound one output stream for inclusion in a failure detail, marking when it was cut. */
function truncateForDetail(text: string): string {
  if (text.length <= DB_EXPORT_DETAIL_OUTPUT_MAX_CHARS) return text;
  return text.slice(0, DB_EXPORT_DETAIL_OUTPUT_MAX_CHARS) + "…[truncated]";
}

function dbExportFailure(objectKey: string, detail: string, exitCode?: number): DbExportResult {
  if (exitCode === undefined) {
    return { ok: false, op: "db-export", objectKey, detail };
  }
  return { ok: false, op: "db-export", objectKey, detail, exitCode };
}

/**
 * Export the DB of the site at `params.docroot` on the agency's cell and upload it to
 * `params.objectKey` in the agency's S3_BUCKET, via a presigned PUT the cell uses. Returns a
 * structured result; every failure (missing config, presign/relay error, a non-zero exit from
 * the export or the upload) is ok:false + detail, never a thrown 500. NEVER uses a platform
 * credential (there is none here), and NEVER returns the dump or the presigned URL.
 */
export async function actuateDbExport(params: DbExportParams, env: Env): Promise<DbExportResult> {
  const objectKey = params.objectKey;

  if (!env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY || !env.S3_BUCKET) {
    return dbExportFailure(
      objectKey,
      "S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY / S3_BUCKET are not configured on this Worker.",
    );
  }
  const cellAgentUrl = env.CELL_AGENT_URL;
  const cellAgentToken = env.CELL_AGENT_TOKEN;
  if (!cellAgentUrl || !cellAgentToken) {
    return dbExportFailure(objectKey, "CELL_AGENT_URL / CELL_AGENT_TOKEN are not configured on this Worker.");
  }

  // Same store resolution as the /validate write probe (validators.ts::validateS3): a custom
  // endpoint (R2/MinIO/Wasabi) is path-style, no endpoint is real AWS; region defaults like there.
  const presigned = await presignS3Put({
    endpoint: env.S3_ENDPOINT ? stripTrailingSlash(env.S3_ENDPOINT) : undefined,
    bucket: env.S3_BUCKET,
    region: env.S3_REGION || "us-east-1",
    accessKeyId: env.S3_ACCESS_KEY_ID,
    secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    key: objectKey,
    expiresSeconds: DB_EXPORT_PRESIGN_EXPIRES_SECONDS,
  });

  const exec = await execOnCellAgent(cellAgentUrl, cellAgentToken, {
    script: buildDbExportScript(presigned.url),
    docroot: params.docroot,
    timeoutMs: DB_EXPORT_EXEC_TIMEOUT_MS,
  });
  if (!exec.ok) {
    return dbExportFailure(objectKey, exec.detail);
  }

  // Unlike wp-cli, a non-zero exit IS a failure here: `set -e` means the export or the upload
  // did not complete, so the object may be missing or partial. Quote the cell's (bounded,
  // redacted) output so the operator can see WHICH step failed and why.
  if (exec.code !== 0) {
    const outputParts: string[] = [];
    if (exec.stderr) outputParts.push(`stderr: ${truncateForDetail(exec.stderr)}`);
    if (exec.stdout) outputParts.push(`stdout: ${truncateForDetail(exec.stdout)}`);
    const output = outputParts.length > 0 ? ` — ${outputParts.join(" | ")}` : "";
    return dbExportFailure(
      objectKey,
      redactPresignedUrl(`DB export or upload failed on the cell (exit ${exec.code})${output}`, presigned.url),
      exec.code,
    );
  }

  return { ok: true, op: "db-export", objectKey, exitCode: 0 };
}

// ── db-import ────────────────────────────────────────────────────────────────────────────
// The reverse of db-export: the agency's cell DOWNLOADS a DB dump from the agency's own object
// store and loads it into the site's WordPress DB with `wp db import`. The dump flows object store
// -> cell and never through this Worker (symmetric with db-export's cell -> object store). The
// Worker's only jobs are to:
//   1. PRESIGN a single-object GET URL with the agency's S3_* credential (sigv4.ts::presignS3Get) —
//      the ONLY thing that reaches the cell: it grants exactly one GET of one key, expires, and
//      embeds a derived signature, not the secret key. No object-store credential lands on the cell.
//   2. Relay a short script to the cell-agent's /exec (the SAME relay wp-cli/db-export use, with the
//      agency's own CELL_AGENT_TOKEN) that `curl`s the dump to a temp FILE, `wp db import`s it, and
//      removes the file. The DOWNLOAD happens BEFORE the import, and `set -e` aborts on a failed
//      download — so a bad/expired URL or a missing object can never leave the DB half-replaced.
//   3. Return a SMALL result: {ok, op, objectKey, exitCode}. Never the dump, never the URL.
//
// DESTRUCTIVE + NON-IDEMPOTENT (F1): `wp db import` REPLACES the site's DB. The orchestrator
// registers db-import NON-idempotent (AGENCY_OP_IDEMPOTENT), so dispatchWithRetry runs it exactly
// once and never auto-retries a transient failure — a re-apply of a dump without DROP TABLE would
// double-insert. handleActuate burns the nonce on receipt, so a re-run needs a fresh-signed job,
// which the F1 contract deliberately withholds for a non-idempotent op.
//
// TIME BUDGET: same as db-export — the presign expiry bounds the download+import window, and the
// exec timeout is held just inside it. A very large dump may need a wider window later.

// How long the presigned GET stays valid, from the moment this Worker mints it.
const DB_IMPORT_PRESIGN_EXPIRES_SECONDS = 600;
// The cell-agent kills the exec at this bound, held just inside the presign window so a slow
// download+import is cut off by the agent rather than left reading an already-expired URL.
const DB_IMPORT_EXEC_TIMEOUT_MS = 540_000;
// How much of the cell's stderr/stdout we quote into a FAILURE detail (each). Enough to see a
// curl / wp-db-import error, small enough to keep the result small.
const DB_IMPORT_DETAIL_OUTPUT_MAX_CHARS = 2048;

/**
 * The POSIX-sh script the cell runs (under the cell-agent's `sh -lc "cd <docroot> && <script>"`,
 * dash on the Debian cells — so no `pipefail`, and one `;`-joined line). Steps:
 *   set -eu                       fail fast on any error or unset variable
 *   T=$(mktemp)                   a temp FILE for the dump (local /tmp, not the NFS docroot)
 *   trap 'rm -f "$T"' EXIT INT TERM  remove the dump on EVERY exit path — success, a failed
 *                                 download/import (set -e exits still run EXIT), or a signal
 *   curl ... -o "$T" URL          DOWNLOAD the dump to the file FIRST (--fail-with-body turns an
 *                                 HTTP >= 400 into a non-zero exit AND keeps the store's error body
 *                                 for the failure detail; -sS = no progress bar, errors shown). set
 *                                 -e means a failed download aborts BEFORE the DB is touched.
 *   wp db import "$T"             load the dump into the site's DB (only reached on a good download)
 * The presigned URL is single-quoted (shellQuoteArg): it carries `&` and `=`, and although it is
 * Worker-generated (not attacker data) it is quoted like every other value we hand to a shell.
 */
export function buildDbImportScript(presignedUrl: string): string {
  return [
    "set -eu",
    "T=$(mktemp)",
    `trap 'rm -f "$T"' EXIT INT TERM`,
    `curl -sS --fail-with-body -o "$T" ${shellQuoteArg(presignedUrl)}`,
    'wp db import "$T"',
  ].join("; ");
}

/** Bound one output stream for a db-import failure detail, marking when it was cut. */
function truncateForImportDetail(text: string): string {
  if (text.length <= DB_IMPORT_DETAIL_OUTPUT_MAX_CHARS) return text;
  return text.slice(0, DB_IMPORT_DETAIL_OUTPUT_MAX_CHARS) + "…[truncated]";
}

function dbImportFailure(objectKey: string, detail: string, exitCode?: number): DbImportResult {
  if (exitCode === undefined) {
    return { ok: false, op: "db-import", objectKey, detail };
  }
  return { ok: false, op: "db-import", objectKey, detail, exitCode };
}

/**
 * Download the dump at `params.objectKey` in the agency's S3_BUCKET and import it into the DB of the
 * site at `params.docroot` on the agency's cell, via a presigned GET the cell uses. Returns a
 * structured result; every failure (missing config, presign/relay error, a non-zero exit from the
 * download or the import) is ok:false + detail, never a thrown 500. NEVER uses a platform credential
 * (there is none here), and NEVER returns the dump or the presigned URL.
 */
export async function actuateDbImport(params: DbImportParams, env: Env): Promise<DbImportResult> {
  const objectKey = params.objectKey;

  if (!env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY || !env.S3_BUCKET) {
    return dbImportFailure(
      objectKey,
      "S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY / S3_BUCKET are not configured on this Worker.",
    );
  }
  const cellAgentUrl = env.CELL_AGENT_URL;
  const cellAgentToken = env.CELL_AGENT_TOKEN;
  if (!cellAgentUrl || !cellAgentToken) {
    return dbImportFailure(objectKey, "CELL_AGENT_URL / CELL_AGENT_TOKEN are not configured on this Worker.");
  }

  // Same store resolution as db-export / the /validate write probe: a custom endpoint
  // (R2/MinIO/Wasabi) is path-style, no endpoint is real AWS; region defaults the same way.
  const presigned = await presignS3Get({
    endpoint: env.S3_ENDPOINT ? stripTrailingSlash(env.S3_ENDPOINT) : undefined,
    bucket: env.S3_BUCKET,
    region: env.S3_REGION || "us-east-1",
    accessKeyId: env.S3_ACCESS_KEY_ID,
    secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    key: objectKey,
    expiresSeconds: DB_IMPORT_PRESIGN_EXPIRES_SECONDS,
  });

  const exec = await execOnCellAgent(cellAgentUrl, cellAgentToken, {
    script: buildDbImportScript(presigned.url),
    docroot: params.docroot,
    timeoutMs: DB_IMPORT_EXEC_TIMEOUT_MS,
  });
  if (!exec.ok) {
    return dbImportFailure(objectKey, exec.detail);
  }

  // A non-zero exit IS a failure here: `set -e` means the download or the import did not complete,
  // so the DB may be untouched (download failed first — the safe case) or partially replaced (the
  // import failed mid-file). Quote the cell's (bounded, redacted) output so the operator can see
  // WHICH step failed and why.
  if (exec.code !== 0) {
    const outputParts: string[] = [];
    if (exec.stderr) outputParts.push(`stderr: ${truncateForImportDetail(exec.stderr)}`);
    if (exec.stdout) outputParts.push(`stdout: ${truncateForImportDetail(exec.stdout)}`);
    const output = outputParts.length > 0 ? ` — ${outputParts.join(" | ")}` : "";
    return dbImportFailure(
      objectKey,
      redactPresignedUrl(`DB download or import failed on the cell (exit ${exec.code})${output}`, presigned.url),
      exec.code,
    );
  }

  return { ok: true, op: "db-import", objectKey, exitCode: 0 };
}

// ── gcp-instance-create ──────────────────────────────────────────────────────────────────
// The first GCP WRITE through Direction-B: create ONE Compute Engine VM in the AGENCY's own
// project, authenticated with the agency's own GCP_SERVICE_ACCOUNT_KEY (the same secret /validate
// probes read-only). Two steps:
//   1. Mint a Google access token from the key (validators.ts::mintGoogleAccessToken — the RS256
//      JWT-bearer grant, no SDK) with the FULL cloud-platform scope. validateGCP mints READ-ONLY;
//      this op cannot, because instances.insert is a write. The scope escalation is inherent to the
//      op and is the ONLY place the Worker asks for it. The token is per-call, lives in a local, is
//      sent only as an Authorization header to Google, and is never logged or returned.
//   2. POST projects/{project}/zones/{zone}/instances with a MINIMAL, PRIVATE body by default: one
//      boot disk (Debian 12, auto-delete) and one interface on the project's default VPC with NO
//      accessConfigs => NO external IP. No `serviceAccounts` either, so the VM carries no identity
//      of its own (and the create needs no iam.serviceAccounts.actAs). The OPTIONAL params
//      (planning/34 phase 2 — a cell node) each add exactly one thing: `dataDiskGb` a second data
//      disk, `network`/`subnetwork` the cell's own VPC/subnet in place of "default", `tags` the
//      firewall target tags, `externalIp` a ONE_TO_ONE_NAT access config carrying a reserved
//      address, `startupScript` the `startup-script` metadata value. ABSENT => the body is
//      byte-identical to the four-field proof VM.
//
// INJECTION SURFACE: `project` + `zone` are URL path segments, and the params land in the JSON
// body. They pass the strict grammars in dispatch-params.ts first (no "/", ".", "?", "#",
// whitespace), then go through encodeURIComponent + JSON.stringify here — belt and braces.
// `network`/`subnetwork` arrive as bare names and are expanded into PROJECT-RELATIVE paths here,
// so the interface can only ever point into the pinned project. `startupScript` is the one opaque
// value; it is placed ONLY as a JSON.stringify'd metadata value, never in a URL.
//
// ASYNC: a 2xx is a long-running Operation ({name, status, ...}), not the VM. We report ACCEPTED
// (ok:true + the operation) and leave polling to the caller. A non-2xx (403 missing permission,
// 404 no such project/zone/network, 409 name taken) is a TERMINAL ok:false carrying Google's own
// message — the orchestrator classifies a 200 ok:false as actuated-failure and never retries it.
//
// NON-IDEMPOTENT (F1): a second insert of the same name is a 409, and a lost response may already
// have created the VM. The orchestrator registers this op `false` in AGENCY_OP_IDEMPOTENT, so
// dispatchWithRetry runs it exactly once and never auto-retries a transient failure (like db-import).

export const GCP_COMPUTE_API = "https://compute.googleapis.com/compute/v1";
// The boot image every proof VM is created from: Debian 12 from Google's public debian-cloud
// project, addressed by image FAMILY so it always resolves to the current patched image.
const GCP_INSTANCE_BOOT_IMAGE = "projects/debian-cloud/global/images/family/debian-12";
const GOOGLE_DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
// Google's operation error CODE for a zone that lacks capacity for the requested machine type. Read
// off the completed operation's error.errors[].code — a DISCRIMINABLE code, never a detail-string
// match. This is the signal the cell-level zone fallback keys on (planning/34).
const ZONE_RESOURCE_POOL_EXHAUSTED_CODE = "ZONE_RESOURCE_POOL_EXHAUSTED";
// How many operations.wait calls the instance create makes before it gives up and reports the
// accepted insert as async-ok. Deliberately SMALL (one ~2 min wait): exhaustion and success both
// surface within that window, and this op feeds a SYNC endpoint (planning/34 review finding 3), so
// it must fail fast to async-ok rather than block per-VM for the full 3-wait budget the regional
// network/router ops use.
const INSTANCE_CREATE_WAIT_ATTEMPTS = 1;

/**
 * What instances.insert answers with. A 2xx is an Operation (`name`, `status`, and — only once
 * DONE with a failure — `error.errors`); a non-2xx is Google's standard error envelope
 * (`error.message`). One shape covers both so a single parse serves both paths.
 */
export interface ComputeInsertResponse {
  name?: string;
  status?: string;
  error?: {
    message?: string;
    errors?: Array<{ code?: string; message?: string; reason?: string }>;
  };
}

function gcpInstanceCreateFailure(instanceName: string, detail: string): GcpInstanceCreateResult {
  return { ok: false, op: "gcp-instance-create", instanceName, detail };
}

/** Google's top-level error message from a response body, if any (for detail strings). */
export function googleErrorMessage(body: ComputeInsertResponse | null): string {
  const message = body?.error?.message;
  return message ? `: ${message}` : "";
}

/** The request headers for a Compute Engine call: the minted bearer token + JSON in/out. */
export function gcpHeaders(accessToken: string): Record<string, string> {
  return {
    authorization: `Bearer ${accessToken}`,
    "content-type": "application/json",
    accept: "application/json",
  };
}

/** The region a grammar-checked zone belongs to: "australia-southeast1-a" -> "australia-southeast1". */
function regionOfZone(zone: string): string {
  return zone.slice(0, zone.lastIndexOf("-"));
}

/** The outcome of resolving the agency's GCP write token for an op pinned to `project`. */
type GcpTokenOutcome = { ok: true; accessToken: string } | { ok: false; detail: string };

/**
 * Resolve the agency's OWN GCP write credential for an op targeting `project` — the ONE
 * implementation every gcp-* op uses, so the agency-boundary guarantee cannot drift between ops:
 *   1. read + parse GCP_SERVICE_ACCOUNT_KEY (the agency's secret — there is no platform fallback);
 *   2. PIN `project` to the key's OWN project_id, rejecting BEFORE any token is minted or any call
 *      is made (review defense-in-depth). Cross-tenant is already impossible — the SA key IS the
 *      tenant boundary, so a job can never reach another agency's project (403) — but this makes
 *      the code ENFORCE the "in the agency's own project" guarantee the ops claim: a signed job
 *      cannot create a resource in some other project the agency's SA happens to hold IAM in;
 *   3. mint a FULL cloud-platform-scoped access token (validators.ts::mintGoogleAccessToken — the
 *      RS256 JWT-bearer grant). validateGCP mints READ-ONLY; a write op cannot. This is the ONLY
 *      place the Worker asks for the write scope.
 * Every failure is ok:false + detail. The ONLY fetch made here is the token mint itself, and only
 * after the pin passes. The token goes back to the caller alone, who places it in an Authorization
 * header and never logs or echoes it.
 */
export async function mintPinnedGcpAccessToken(env: Env, project: string): Promise<GcpTokenOutcome> {
  const key = readPinnedServiceAccountKey(env, project);
  if (!key.ok) {
    return { ok: false, detail: key.detail };
  }

  let accessToken: string;
  try {
    accessToken = await mintGoogleAccessToken({
      clientEmail: key.clientEmail,
      privateKeyPem: key.privateKeyPem,
      tokenUri: key.tokenUri,
      scope: GOOGLE_SCOPE_CLOUD_PLATFORM,
    });
  } catch (err) {
    return {
      ok: false,
      detail: `could not mint a Google access token from GCP_SERVICE_ACCOUNT_KEY: ${errorMessage(err)}`,
    };
  }
  return { ok: true, accessToken };
}

/** The agency's service-account key, parsed, and PINNED to the op's project — or why it is not. */
export type PinnedServiceAccountKey =
  | { ok: true; clientEmail: string; privateKeyPem: string; tokenUri: string }
  | { ok: false; detail: string };

/**
 * Steps 1 and 2 of mintPinnedGcpAccessToken (read + parse GCP_SERVICE_ACCOUNT_KEY, then PIN `project`
 * to the key's OWN project_id), as one function so the access-token mint and the planning/49 ID-token
 * mint cannot drift apart on the agency-boundary check. Makes NO network call.
 */
export function readPinnedServiceAccountKey(env: Env, project: string): PinnedServiceAccountKey {
  if (!env.GCP_SERVICE_ACCOUNT_KEY) {
    return { ok: false, detail: "GCP_SERVICE_ACCOUNT_KEY is not configured on this Worker." };
  }
  // Parse the key the same way validateGCP does. JSON.parse needs the try/catch (no non-throwing
  // parse); a non-object result (e.g. the literal `null`) is treated as malformed too.
  let key: ServiceAccountKey | null;
  try {
    key = JSON.parse(env.GCP_SERVICE_ACCOUNT_KEY) as ServiceAccountKey | null;
  } catch {
    key = null;
  }
  if (!key || typeof key !== "object") {
    return {
      ok: false,
      detail: "GCP_SERVICE_ACCOUNT_KEY is not valid JSON — it must be the entire downloaded service-account key file.",
    };
  }
  const clientEmail = key.client_email;
  const privateKeyPem = key.private_key;
  if (!clientEmail || !privateKeyPem) {
    return {
      ok: false,
      detail:
        "GCP_SERVICE_ACCOUNT_KEY is missing client_email or private_key — use a service-account key, not an OAuth client ID.",
    };
  }
  if (!key.project_id || project !== key.project_id) {
    return {
      ok: false,
      detail:
        `project "${project}" does not match the service-account key's own project` +
        `${key.project_id ? ` ("${key.project_id}")` : ""} — a resource is only created in the agency's own project.`,
    };
  }
  return { ok: true, clientEmail, privateKeyPem, tokenUri: key.token_uri || GOOGLE_DEFAULT_TOKEN_URI };
}

/** The outcome of minting a Google ID token for an op pinned to `project`. */
export type GcpIdTokenOutcome = { ok: true; idToken: string } | { ok: false; detail: string };

/**
 * planning/49 Phase 2: mint a Google ID TOKEN for `audience` (a Cloud Run service URL) from the
 * agency's OWN key, after the same project pin every gcp-* op uses. The token goes back to the caller
 * alone, who puts it in an Authorization header and never logs or echoes it.
 */
export async function mintPinnedGcpIdToken(env: Env, project: string, audience: string): Promise<GcpIdTokenOutcome> {
  const key = readPinnedServiceAccountKey(env, project);
  if (!key.ok) {
    return { ok: false, detail: key.detail };
  }
  let idToken: string;
  try {
    idToken = await mintGoogleIdToken({
      clientEmail: key.clientEmail,
      privateKeyPem: key.privateKeyPem,
      tokenUri: key.tokenUri,
      audience,
    });
  } catch (err) {
    return { ok: false, detail: `could not mint a Google ID token from GCP_SERVICE_ACCOUNT_KEY: ${errorMessage(err)}` };
  }
  return { ok: true, idToken };
}

/**
 * Create the VM described by `params` in the agency's own project with the agency's own
 * GCP_SERVICE_ACCOUNT_KEY. Returns a structured result; every failure (missing/malformed key, a
 * token-mint failure, an unreachable API, a non-2xx from Google) is ok:false + detail, never a
 * thrown 500. NEVER uses a platform credential (there is none here), and NEVER returns or logs the
 * minted access token.
 */
export async function actuateGcpInstanceCreate(
  params: GcpInstanceCreateParams,
  env: Env,
): Promise<GcpInstanceCreateResult> {
  const instanceName = params.name;

  // Parse the agency's key, PIN the target project to the key's own project (rejecting before any
  // token or call), and mint the FULL-scope write token — the shared implementation every gcp-* op
  // uses (mintPinnedGcpAccessToken). The token stays in this local and goes only into the
  // Authorization header below.
  const token = await mintPinnedGcpAccessToken(env, params.project);
  if (!token.ok) {
    return gcpInstanceCreateFailure(instanceName, token.detail);
  }
  const accessToken = token.accessToken;

  // The two path segments are grammar-checked upstream AND URL-encoded here; the body is built
  // with JSON.stringify from the validated fields only (the four required, plus whichever optional
  // fields are present).
  const url =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(params.project)}` +
    `/zones/${encodeURIComponent(params.zone)}/instances`;

  // The boot disk: Debian 12, deleted with the VM. Always present.
  const disks: Array<Record<string, unknown>> = [
    {
      boot: true,
      autoDelete: true,
      initializeParams: { sourceImage: GCP_INSTANCE_BOOT_IMAGE },
    },
  ];
  // OPTIONAL second, non-boot data disk (the file node's storage). autoDelete is FALSE on purpose:
  // a data disk holds site files and MUST survive the VM being deleted — its lifecycle belongs to a
  // future cell-teardown, not to this create op, so this op never tears it down with the VM.
  // pd-balanced matches the reference file node (planning/34). `zone` is the same grammar-checked
  // value used in the machineType path above (no metacharacter can pass the validator), reused the
  // same way; diskSizeGb is the validated integer. When dataDiskGb is absent the body is unchanged.
  if (params.dataDiskGb !== undefined) {
    disks.push({
      boot: false,
      autoDelete: false,
      initializeParams: {
        diskType: `zones/${params.zone}/diskTypes/pd-balanced`,
        diskSizeGb: params.dataDiskGb,
      },
    });
  }

  // The single network interface. DEFAULT (no networking param present): the project's "default"
  // VPC and NO accessConfigs => no external IP — byte-identical to the pre-extension body.
  // `network` / `subnetwork` are bare grammar-checked names expanded into PROJECT-RELATIVE paths
  // here (never a caller-supplied URL, so the interface can only point into the pinned project);
  // a subnet is regional and the VM's zone must lie in that region, so its region is derived from
  // the zone. Google infers the network from the subnet when only `subnetwork` is given.
  // `externalIp` attaches the caller's reserved address as a ONE_TO_ONE_NAT access config — the
  // ONLY way this op ever gives a VM an external IP (an ephemeral one is never requested).
  const networkInterface: Record<string, unknown> = {};
  if (params.network === undefined && params.subnetwork === undefined) {
    networkInterface.network = "global/networks/default";
  }
  if (params.network !== undefined) {
    networkInterface.network = `global/networks/${params.network}`;
  }
  if (params.subnetwork !== undefined) {
    networkInterface.subnetwork = `regions/${regionOfZone(params.zone)}/subnetworks/${params.subnetwork}`;
  }
  if (params.externalIp !== undefined) {
    networkInterface.accessConfigs = [{ name: "External NAT", type: "ONE_TO_ONE_NAT", natIP: params.externalIp }];
  }

  const instance: Record<string, unknown> = {
    name: instanceName,
    machineType: `zones/${params.zone}/machineTypes/${params.machineType}`,
    disks,
    networkInterfaces: [networkInterface],
  };
  // Network tags (firewall targets) and the startup script ride ONLY when present — absent means
  // the keys are not in the body at all, not empty.
  if (params.tags !== undefined) {
    instance.tags = { items: [...params.tags] };
  }
  if (params.startupScript !== undefined) {
    instance.metadata = { items: [{ key: "startup-script", value: params.startupScript }] };
  }
  const instanceBody = JSON.stringify(instance);

  // Default redirect handling, NOT redirect:"error" — workerd throws on that value at runtime
  // (the gotcha the cell-agent relay above documents). Google's API does not redirect.
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: instanceBody,
    });
  } catch (err) {
    return gcpInstanceCreateFailure(
      instanceName,
      `could not reach Google Compute Engine to create the instance: ${errorMessage(err)}`,
    );
  }

  const body = (await response.json().catch(() => null)) as ComputeInsertResponse | null;

  if (response.ok) {
    // A 2xx must carry an Operation. Its ABSENCE means we cannot confirm Google accepted the
    // create, so fail closed rather than report a success we cannot point at.
    const operationName = body?.name;
    if (!operationName) {
      return gcpInstanceCreateFailure(
        instanceName,
        `Compute Engine returned HTTP ${response.status} but no operation — cannot confirm the instance create was accepted.`,
      );
    }
    // An insert normally returns PENDING/RUNNING; if Google ever answers with an already-DONE
    // operation that carries errors, that is a failed create, not a success.
    const operationErrors = body?.error?.errors ?? [];
    if (operationErrors.length > 0) {
      const messages = operationErrors.map((entry) => entry.message ?? entry.code ?? "unknown error").join("; ");
      const alreadyDoneCodes = operationErrors
        .map((entry) => entry.code)
        .filter((code): code is string => typeof code === "string");
      // The rare already-DONE-at-insert path can ALSO be a zone exhaustion — surface it discriminably
      // so the caller's zone fallback triggers here too, not only after a wait.
      if (alreadyDoneCodes.includes(ZONE_RESOURCE_POOL_EXHAUSTED_CODE)) {
        return {
          ok: false,
          op: "gcp-instance-create",
          instanceName,
          detail: `instance create operation ${operationName} failed: ${messages}.`,
          exhausted: true,
        };
      }
      return gcpInstanceCreateFailure(instanceName, `instance create operation ${operationName} failed: ${messages}.`);
    }

    // planning/34 zone fallback: the insert is async, and a ZONE_RESOURCE_POOL_EXHAUSTED is reported
    // only when the operation COMPLETES — so, unlike the fire-and-forget original, WAIT (bounded) for
    // this insert's ZONAL operation, reusing the same operations.wait pattern the network/router ops
    // use. The bound is SMALL (INSTANCE_CREATE_WAIT_ATTEMPTS): this feeds a sync endpoint, so a
    // still-running insert must fall back to async-ok rather than block.
    const waitUrl =
      `${GCP_COMPUTE_API}/projects/${encodeURIComponent(params.project)}` +
      `/zones/${encodeURIComponent(params.zone)}/operations/${encodeURIComponent(operationName)}/wait`;
    const waited = await waitForComputeOperation({
      waitUrl,
      accessToken,
      what: `instance "${instanceName}"`,
      maxAttempts: INSTANCE_CREATE_WAIT_ATTEMPTS,
    });
    if (waited.ok) {
      // The insert operation finished cleanly — the VM exists (or is booting).
      return { ok: true, op: "gcp-instance-create", instanceName, operationName, status: "DONE" };
    }
    if (waited.completed && waited.errorCodes.includes(ZONE_RESOURCE_POOL_EXHAUSTED_CODE)) {
      // The zone ran out of capacity for this machine type. A DISCRIMINABLE `exhausted:true` field
      // (mirrors alreadyExisted — never a detail-string match) so the cell-level caller retries the
      // create in another zone without parsing the message. The failed operation left NO VM.
      return { ok: false, op: "gcp-instance-create", instanceName, detail: waited.detail, exhausted: true };
    }
    if (waited.completed) {
      // The operation finished with a NON-exhaustion error we OBSERVED (e.g. a bad image, a quota
      // other than zone capacity): a genuine create failure. Report it rather than the old
      // always-async-ok. Not exhaustion, so the caller does NOT retry another zone.
      return gcpInstanceCreateFailure(instanceName, waited.detail);
    }
    // The operation was still RUNNING/PENDING after the bounded wait, or the wait poll could not be
    // completed. We CANNOT observe the outcome, so fall back to the op's ORIGINAL async contract:
    // report the accepted insert as ok:true + its operation to poll. DOCUMENTED RESIDUAL: a
    // ZONE_RESOURCE_POOL_EXHAUSTED that surfaces ONLY after this bounded window is therefore missed —
    // the provision reports ok, but that VM never boots. Acceptable (a re-run's discovery re-checks
    // the zone, and operator telemetry catches a non-booting node); stated so it is a known limit,
    // not a silent gap.
    return {
      ok: true,
      op: "gcp-instance-create",
      instanceName,
      operationName,
      status: body?.status ?? "UNKNOWN",
    };
  }

  if (response.status === 401 || response.status === 403) {
    return gcpInstanceCreateFailure(
      instanceName,
      `Google Cloud denied the instance create (HTTP ${response.status})${googleErrorMessage(body)} — the service account ` +
        `needs compute.instances.create (e.g. roles/compute.instanceAdmin.v1) on project "${params.project}".`,
    );
  }
  if (response.status === 409) {
    // Unlike provision-r2's "already exists", this is a FAILURE: the op is a create of a NEW named
    // VM, and a name collision means either a stale VM to clean up or a caller bug — never a
    // converged success to report as ok. `alreadyExisted:true` is the discriminable signal a
    // cell-level resume uses to skip an already-provisioned node (see GcpInstanceCreateResult).
    return {
      ok: false,
      op: "gcp-instance-create",
      instanceName,
      detail:
        `an instance named "${instanceName}" already exists in ${params.project}/${params.zone}${googleErrorMessage(body)} — ` +
        "instance create is not idempotent; pick a new name or delete the existing VM first.",
      alreadyExisted: true,
    };
  }

  return gcpInstanceCreateFailure(
    instanceName,
    `instance create failed with HTTP ${response.status}${googleErrorMessage(body)}.`,
  );
}

// ── GCP shared: idempotent insert + operation wait + read-back ─────────────────────────────
// The cell-infra ops below (planning/34 phase 2) all create a NAMED Compute Engine resource and
// are IDEMPOTENT by name: Google answers a second insert of an existing name with 409
// alreadyExists, which these ops report as success ("already-existed") so a half-built cell
// resumes on re-run. That is the deliberate opposite of gcp-instance-create's 409-is-failure —
// a VM is stateful compute, a network/rule/address is declarative configuration.

/** How a Compute Engine insert of an idempotent resource ended. */
// `definite` (failed only, hub#93 M5) says whether Google DEFINITELY did not create the resource: true
// for a 4xx answer or an operation that already carries errors, false when the create may still land
// (Google unreachable, a 5xx, a 2xx without an operation). Callers that do not need it ignore it.
type ComputeInsertOutcome =
  | { kind: "created"; operationName: string }
  | { kind: "already-existed" }
  | { kind: "failed"; detail: string; definite: boolean };

/** The `message`s of an Operation's error entries, joined for a detail string. */
export function operationErrorMessages(entries: Array<{ code?: string; message?: string }>): string {
  return entries.map((entry) => entry.message ?? entry.code ?? "unknown error").join("; ");
}

/**
 * True when a 409 body is Google's alreadyExists — the idempotent-success case. A 409 with NO error
 * entries is taken as alreadyExists too (the only 409 an insert produces); a 409 whose entries name
 * a DIFFERENT reason is not, and falls through to a failure carrying Google's message.
 */
export function isAlreadyExists(body: ComputeInsertResponse | null): boolean {
  const entries = body?.error?.errors ?? [];
  if (entries.length === 0) {
    return true;
  }
  return entries.some((entry) => entry.reason === "alreadyExists");
}

/**
 * POST an insert to Compute Engine for an IDEMPOTENT resource. A 2xx Operation is "created"
 * (ACCEPTED — the insert itself is async; the caller decides whether to wait on it), a 409
 * alreadyExists is "already-existed", and everything else — unreachable, 401/403, a 2xx without an
 * operation, an already-DONE operation carrying errors, any other non-2xx — is a terminal failure
 * carrying Google's own message. `url` is built by the caller from grammar-checked,
 * encodeURIComponent'd segments; `body` holds validated fields only and is JSON.stringify'd here.
 * `what` names the resource for detail strings; `permissionHint` names what a 403 most likely lacks.
 */
async function insertComputeResource(input: {
  url: string;
  accessToken: string;
  body: Record<string, unknown>;
  what: string;
  project: string;
  permissionHint: string;
}): Promise<ComputeInsertOutcome> {
  const { url, accessToken, what, project, permissionHint } = input;

  // Default redirect handling, NOT redirect:"error" — workerd throws on that value at runtime.
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: gcpHeaders(accessToken),
      body: JSON.stringify(input.body),
    });
  } catch (err) {
    // The request may have reached Google before the connection failed, so this is NOT definite.
    return {
      kind: "failed",
      detail: `could not reach Google Compute Engine to create ${what}: ${errorMessage(err)}`,
      definite: false,
    };
  }

  const body = (await response.json().catch(() => null)) as ComputeInsertResponse | null;

  if (response.ok) {
    // A 2xx must carry an Operation; its ABSENCE means we cannot confirm Google accepted the create.
    const operationName = body?.name;
    if (!operationName) {
      return {
        kind: "failed",
        detail: `Compute Engine returned HTTP ${response.status} but no operation — cannot confirm the ${what} create was accepted.`,
        definite: false,
      };
    }
    const operationErrors = body?.error?.errors ?? [];
    if (operationErrors.length > 0) {
      return {
        kind: "failed",
        detail: `${what} create operation ${operationName} failed: ${operationErrorMessages(operationErrors)}.`,
        definite: true,
      };
    }
    return { kind: "created", operationName };
  }

  if (response.status === 409 && isAlreadyExists(body)) {
    return { kind: "already-existed" };
  }
  if (response.status === 401 || response.status === 403) {
    return {
      kind: "failed",
      detail:
        `Google Cloud denied the ${what} create (HTTP ${response.status})${googleErrorMessage(body)} — the service account ` +
        `needs ${permissionHint} on project "${project}".`,
      definite: true,
    };
  }
  // A 4xx names the request as the fault (bad input, quota exceeded): nothing was created. A 5xx is a
  // fault on Google's side, after which the create may or may not have happened.
  const definite = response.status >= 400 && response.status < 500;
  return { kind: "failed", detail: `${what} create failed with HTTP ${response.status}${googleErrorMessage(body)}.`, definite };
}

// globalOperations.wait / regionOperations.wait / zoneOperations.wait hold the request until the
// operation is DONE or about two minutes pass, then return its current state. A network/instance
// insert takes tens of seconds, so one wait normally suffices; a small bounded count covers a slow
// region without an unbounded loop.
const GCP_OPERATION_WAIT_ATTEMPTS = 3;

/**
 * The outcome of waiting for a Compute operation to finish.
 *   - ok:true                            — the operation reached DONE with NO errors (the resource exists).
 *   - ok:false, completed:true           — the operation reached DONE but CARRIED errors (a real,
 *                                          observed create failure); `errorCodes` are its
 *                                          error.errors[].code values, so a caller can discriminate a
 *                                          specific failure (e.g. ZONE_RESOURCE_POOL_EXHAUSTED).
 *   - ok:false, completed:false          — the wait could NOT confirm the outcome: the wait call
 *                                          itself failed (unreachable / non-2xx) OR the operation was
 *                                          still not DONE within the bound. `errorCodes` is [].
 * Existing callers read only `ok`/`detail`; the extra fields are additive.
 */
type ComputeOperationWaitOutcome =
  | { ok: true }
  | { ok: false; detail: string; completed: boolean; errorCodes: string[] };

/**
 * Block until the Compute operation at `waitUrl` (.../operations/{name}/wait) is DONE, bounded to
 * `maxAttempts` wait calls (default GCP_OPERATION_WAIT_ATTEMPTS). The instance-create zone-fallback
 * path passes a SMALL value so a still-running insert falls back to async-ok quickly rather than
 * blocking the sync endpoint (see actuateGcpInstanceCreate).
 *
 * `verb` only names the ACTION in the detail strings ("create" by default, "delete" for the teardown
 * ops) so a teardown failure reads as a delete failure. It changes no behaviour.
 */
export async function waitForComputeOperation(input: {
  waitUrl: string;
  accessToken: string;
  what: string;
  maxAttempts?: number;
  verb?: string;
}): Promise<ComputeOperationWaitOutcome> {
  const { waitUrl, accessToken, what } = input;
  const maxAttempts = input.maxAttempts ?? GCP_OPERATION_WAIT_ATTEMPTS;
  const verb = input.verb ?? "create";

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    let response: Response;
    try {
      response = await fetch(waitUrl, { method: "POST", headers: gcpHeaders(accessToken) });
    } catch (err) {
      return {
        ok: false,
        detail: `could not reach Google Compute Engine while waiting for the ${what} ${verb} to finish: ${errorMessage(err)}`,
        completed: false,
        errorCodes: [],
      };
    }
    const body = (await response.json().catch(() => null)) as ComputeInsertResponse | null;
    if (!response.ok) {
      return {
        ok: false,
        detail: `waiting for the ${what} ${verb} to finish failed with HTTP ${response.status}${googleErrorMessage(body)}.`,
        completed: false,
        errorCodes: [],
      };
    }
    if (body?.status !== "DONE") {
      continue;
    }
    const operationErrors = body?.error?.errors ?? [];
    if (operationErrors.length > 0) {
      const errorCodes = operationErrors
        .map((entry) => entry.code)
        .filter((code): code is string => typeof code === "string" && code.length > 0);
      return {
        ok: false,
        detail: `${what} ${verb} operation failed: ${operationErrorMessages(operationErrors)}.`,
        completed: true,
        errorCodes,
      };
    }
    return { ok: true };
  }

  return {
    ok: false,
    detail: `the ${what} ${verb} operation was still not DONE after ${maxAttempts} waits — re-run to resume once it finishes.`,
    completed: false,
    errorCodes: [],
  };
}

// ── GCP shared: idempotent delete ───────────────────────────────────────────────────────────
// The teardown ops (planning/34 teardown) are the mirror of the create ops above and are IDEMPOTENT
// the other way round: Google answers a delete of a resource that is not there with 404 notFound,
// which is reported as success ("already-absent") so a re-run of a partly-torn-down cell resumes.

/** How a Compute Engine delete of a teardown resource ended. */
type ComputeDeleteOutcome =
  | { kind: "deleted"; operationName: string }
  | { kind: "already-absent" }
  // `unconfirmed` is true ONLY when Google ACCEPTED the delete but the wait could not confirm the
  // operation reached DONE (still running at the bound, or the wait poll itself failed). The
  // resource may well be on its way out, so the caller must say "re-run to resume" rather than
  // treat it as gone — gcp-instance-delete surfaces exactly this as `stillRunning: true`.
  //
  // `inUse` is true ONLY when Google refused the delete because ANOTHER resource still uses this
  // one (reason resourceInUseByAnotherResource / code RESOURCE_IN_USE_BY_ANOTHER_RESOURCE). planning/49
  // review L4: Cloud Run Direct VPC egress can hold addresses on a subnet for a while after its last
  // service is deleted, so gcp-subnet-delete surfaces this as a discriminable "retry later".
  | { kind: "failed"; detail: string; unconfirmed: boolean; inUse?: boolean };

/** Google's reason / code for "another resource still uses this one" (the delete is refused). */
const GCP_RESOURCE_IN_USE_REASON = "resourceInUseByAnotherResource";
const GCP_RESOURCE_IN_USE_CODE = "RESOURCE_IN_USE_BY_ANOTHER_RESOURCE";

/** True when a Compute error body or an operation's error entries say the resource is in use. */
function isResourceInUse(entries: Array<{ code?: string; reason?: string }>): boolean {
  for (const entry of entries) {
    if (entry.reason === GCP_RESOURCE_IN_USE_REASON || entry.code === GCP_RESOURCE_IN_USE_CODE) {
      return true;
    }
  }
  return false;
}

/**
 * DELETE one Compute Engine resource and WAIT for its operation to finish. The twin of
 * insertComputeResource, with the same failure vocabulary (unreachable / 401-403 with a permission
 * hint / any other non-2xx carrying Google's own message).
 *
 * Two things differ from the insert side:
 *   1. A 404 is SUCCESS ("already-absent"), not a failure. That is what makes teardown resumable —
 *      a re-run must converge, not fail on what it already removed. There is no operation to wait on.
 *   2. The wait is NOT optional. Google rejects a subnet delete with resourceInUse while an instance
 *      still holds it, and a network delete the same way while its subnet lives, so each step must be
 *      CONFIRMED gone before the caller runs the next. "deleted" therefore means the resource is
 *      gone, not merely that Google accepted the delete.
 *
 * `url` is built by the caller from grammar-checked, encodeURIComponent'd segments; `waitUrlBase` is
 * the ".../operations" collection for this delete's SCOPE (zonal / regional / global), which the
 * operation name is appended to. `what` names the resource for detail strings; `permissionHint`
 * names what a 403 most likely lacks.
 */
async function deleteComputeResource(input: {
  url: string;
  waitUrlBase: string;
  accessToken: string;
  what: string;
  project: string;
  permissionHint: string;
}): Promise<ComputeDeleteOutcome> {
  const { url, waitUrlBase, accessToken, what, project, permissionHint } = input;

  // Default redirect handling, NOT redirect:"error" — workerd throws on that value at runtime.
  let response: Response;
  try {
    response = await fetch(url, { method: "DELETE", headers: gcpHeaders(accessToken) });
  } catch (err) {
    return {
      kind: "failed",
      detail: `could not reach Google Compute Engine to delete ${what}: ${errorMessage(err)}`,
      unconfirmed: false,
    };
  }

  const body = (await response.json().catch(() => null)) as ComputeInsertResponse | null;

  if (response.status === 404) {
    return { kind: "already-absent" };
  }
  if (response.status === 401 || response.status === 403) {
    return {
      kind: "failed",
      detail:
        `Google Cloud denied the ${what} delete (HTTP ${response.status})${googleErrorMessage(body)} — the service account ` +
        `needs ${permissionHint} on project "${project}".`,
      unconfirmed: false,
    };
  }
  if (!response.ok) {
    return {
      kind: "failed",
      detail: `${what} delete failed with HTTP ${response.status}${googleErrorMessage(body)}.`,
      unconfirmed: false,
      inUse: isResourceInUse(body?.error?.errors ?? []),
    };
  }

  // A 2xx must carry an Operation; its ABSENCE means we cannot confirm Google accepted the delete.
  // `unconfirmed` becomes the caller's `stillRunning`, so it MUST be true here: a 2xx with no
  // Operation may well mean Google DID accept the delete and it is running. Reporting it as an
  // observed hard failure would be a lie, and it would tell the operator the teardown is terminal
  // when the right move is to re-run and resume (review FIX 5).
  const operationName = body?.name;
  if (!operationName) {
    return {
      kind: "failed",
      detail: `Compute Engine returned HTTP ${response.status} but no operation — cannot confirm the ${what} delete was accepted.`,
      unconfirmed: true,
    };
  }
  const operationErrors = body?.error?.errors ?? [];
  if (operationErrors.length > 0) {
    return {
      kind: "failed",
      detail: `${what} delete operation ${operationName} failed: ${operationErrorMessages(operationErrors)}.`,
      unconfirmed: false,
      inUse: isResourceInUse(operationErrors),
    };
  }

  const waited = await waitForComputeOperation({
    waitUrl: `${waitUrlBase}/${encodeURIComponent(operationName)}/wait`,
    accessToken,
    what,
    verb: "delete",
  });
  if (waited.ok) {
    return { kind: "deleted", operationName };
  }
  // completed:true = the operation finished CARRYING errors (a real, observed delete failure).
  // completed:false = we could not observe the outcome at all (see ComputeDeleteOutcome).
  if (!waited.completed) {
    return { kind: "failed", detail: waited.detail, unconfirmed: true };
  }
  return {
    kind: "failed",
    detail: waited.detail,
    unconfirmed: false,
    inUse: waited.errorCodes.includes(GCP_RESOURCE_IN_USE_CODE),
  };
}

// ── gcp-network-create ───────────────────────────────────────────────────────────────────
// A cell's dedicated VPC in the agency's own project: a CUSTOM-mode network, then ONE regional
// subnet on it (planning/34 phase 2). Both inserts are idempotent (409 alreadyExists = success).
//
// The subnet insert DEPENDS on the network insert having FINISHED: networks.insert is async, and a
// subnetworks.insert issued while the network's Operation is still RUNNING fails with Google's
// resourceNotReady. So when THIS run created the network, the Worker WAITS for that operation to
// reach DONE before inserting the subnet — and likewise waits for the subnet's own operation, so
// "created" on return means the resource EXISTS and the caller's instances.insert calls (which name
// this subnet) cannot race it. When a resource already existed there is nothing to wait on (a
// concurrent run still creating it makes the dependent insert fail cleanly; a re-run resumes).

export async function actuateGcpNetworkCreate(
  params: GcpNetworkCreateParams,
  env: Env,
): Promise<GcpNetworkCreateResult> {
  const { project, region, networkName, subnetName } = params;
  const failure = (detail: string): GcpNetworkCreateResult => ({
    ok: false,
    op: "gcp-network-create",
    networkName,
    subnetName,
    detail,
  });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const accessToken = token.accessToken;
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const projectPath = `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}`;
  const regionPath = `${projectPath}/regions/${encodeURIComponent(region)}`;

  const networkOutcome = await insertComputeResource({
    url: `${projectPath}/global/networks`,
    accessToken,
    // Custom mode: NO auto-created per-region subnets — the cell gets exactly the one subnet below.
    body: { name: networkName, autoCreateSubnetworks: false },
    what: `network "${networkName}"`,
    project,
    permissionHint: "compute.networks.create (e.g. roles/compute.networkAdmin)",
  });
  if (networkOutcome.kind === "failed") {
    return failure(networkOutcome.detail);
  }
  if (networkOutcome.kind === "created") {
    const waited = await waitForComputeOperation({
      waitUrl: `${projectPath}/global/operations/${encodeURIComponent(networkOutcome.operationName)}/wait`,
      accessToken,
      what: `network "${networkName}"`,
    });
    if (!waited.ok) {
      return failure(waited.detail);
    }
  }

  const subnetOutcome = await insertComputeResource({
    url: `${regionPath}/subnetworks`,
    accessToken,
    // Project-relative references, like the instance body's — never a caller-supplied URL.
    body: {
      name: subnetName,
      network: `global/networks/${networkName}`,
      ipCidrRange: params.ipCidr,
      region: `regions/${region}`,
    },
    what: `subnetwork "${subnetName}"`,
    project,
    permissionHint: "compute.subnetworks.create (e.g. roles/compute.networkAdmin)",
  });
  if (subnetOutcome.kind === "failed") {
    return failure(subnetOutcome.detail);
  }
  if (subnetOutcome.kind === "created") {
    const waited = await waitForComputeOperation({
      waitUrl: `${regionPath}/operations/${encodeURIComponent(subnetOutcome.operationName)}/wait`,
      accessToken,
      what: `subnetwork "${subnetName}"`,
    });
    if (!waited.ok) {
      return failure(waited.detail);
    }
  }

  return {
    ok: true,
    op: "gcp-network-create",
    networkName,
    networkStatus: networkOutcome.kind,
    subnetName,
    subnetStatus: subnetOutcome.kind,
  };
}

// ── gcp-firewall-create ──────────────────────────────────────────────────────────────────
// ONE INGRESS firewall rule on a cell's VPC in the agency's own project (planning/34 phase 2: public
// tcp:22 to the `dy-gateway` tag; allow-all inside the subnet). Idempotent by NAME: a 409 is
// success, and a re-run with a different body under the same name is a no-op, not an update. The
// insert is async; "created" means Google ACCEPTED it (nothing in the cell bring-up depends on a
// rule having finished propagating before the next step).

export async function actuateGcpFirewallCreate(
  params: GcpFirewallCreateParams,
  env: Env,
): Promise<GcpFirewallCreateResult> {
  const { project, ruleName } = params;
  const failure = (detail: string): GcpFirewallCreateResult => ({ ok: false, op: "gcp-firewall-create", ruleName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const projectPath = `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}`;

  // Map the validated entries onto Google's shape: `protocol` -> `IPProtocol` ("all" is Google's
  // own spelling for every protocol); `ports` rides only when present. Every list is rebuilt fresh.
  const allowed = params.allowed.map((entry) => {
    const rule: Record<string, unknown> = { IPProtocol: entry.protocol };
    if (entry.ports !== undefined) {
      rule.ports = [...entry.ports];
    }
    return rule;
  });

  const outcome = await insertComputeResource({
    url: `${projectPath}/global/firewalls`,
    accessToken: token.accessToken,
    body: {
      name: ruleName,
      network: `global/networks/${params.networkName}`,
      direction: "INGRESS",
      allowed,
      sourceRanges: [...params.sourceRanges],
      targetTags: [...params.targetTags],
    },
    what: `firewall rule "${ruleName}"`,
    project,
    permissionHint: "compute.firewalls.create (e.g. roles/compute.securityAdmin)",
  });
  if (outcome.kind === "failed") {
    return failure(outcome.detail);
  }
  return { ok: true, op: "gcp-firewall-create", ruleName, status: outcome.kind };
}

// ── gcp-address-create ───────────────────────────────────────────────────────────────────
// Reserve ONE regional static EXTERNAL IPv4 address in the agency's own project — the cell
// gateway's public SFTP endpoint (planning/34 phase 2). Idempotent: a 409 is success. After the
// insert the reservation is READ BACK for its IP, which is returned (or null while Google is still
// assigning it / before the new resource is visible — the caller re-reads). A read-back failure
// other than not-yet-visible is reported as ok:false even though the reservation stands: the op is
// idempotent, so a re-run hits 409 and reads again.

/** What addresses.get answers with (the fields this op reads). */
interface ComputeAddressResponse {
  address?: string;
  status?: string;
  error?: ComputeInsertResponse["error"];
}

/**
 * GET the reserved address for its IP. 404 = accepted but not yet visible => address null (ok);
 * any other non-2xx or an unreachable API => ok:false; a 2xx without an `address` yet => null.
 */
async function readComputeAddress(input: {
  url: string;
  accessToken: string;
  what: string;
}): Promise<{ ok: true; address: string | null } | { ok: false; detail: string }> {
  const { url, accessToken, what } = input;

  let response: Response;
  try {
    response = await fetch(url, { headers: gcpHeaders(accessToken) });
  } catch (err) {
    return {
      ok: false,
      detail: `${what} was reserved but reading it back failed — could not reach Google Compute Engine: ${errorMessage(err)}`,
    };
  }
  const body = (await response.json().catch(() => null)) as ComputeAddressResponse | null;

  if (response.status === 404) {
    return { ok: true, address: null };
  }
  if (!response.ok) {
    return {
      ok: false,
      detail: `${what} was reserved but reading it back failed with HTTP ${response.status}${googleErrorMessage(body)}.`,
    };
  }
  const address = typeof body?.address === "string" && body.address.length > 0 ? body.address : null;
  return { ok: true, address };
}

export async function actuateGcpAddressCreate(
  params: GcpAddressCreateParams,
  env: Env,
): Promise<GcpAddressCreateResult> {
  const { project, region, addressName } = params;
  const failure = (detail: string): GcpAddressCreateResult => ({ ok: false, op: "gcp-address-create", addressName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const accessToken = token.accessToken;
  const addressesPath =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/regions/${encodeURIComponent(region)}/addresses`;
  const what = `address "${addressName}"`;

  const outcome = await insertComputeResource({
    url: addressesPath,
    accessToken,
    // EXTERNAL is Google's default for a regional address; stated explicitly so this can never
    // silently become an internal reservation.
    body: { name: addressName, addressType: "EXTERNAL" },
    what,
    project,
    permissionHint: "compute.addresses.create (e.g. roles/compute.networkAdmin)",
  });
  if (outcome.kind === "failed") {
    return failure(outcome.detail);
  }

  const read = await readComputeAddress({
    url: `${addressesPath}/${encodeURIComponent(addressName)}`,
    accessToken,
    what,
  });
  if (!read.ok) {
    return failure(read.detail);
  }
  return { ok: true, op: "gcp-address-create", addressName, address: read.address, status: outcome.kind };
}

// ── gcp-router-nat-create ────────────────────────────────────────────────────────────────
// ONE regional Cloud Router carrying ONE inline Cloud NAT on the cell's VPC, in the agency's own
// project (planning/34 phase 3). WHY: the web/file/data nodes have NO external IP, so this NAT is
// their only route out — apt, the cell-agent bundle fetch and cloudflared all need it. Idempotent
// by router name: a 409 is success. AUTO_ONLY lets Google allocate the NAT IPs (no reservation);
// ALL_SUBNETWORKS_ALL_IP_RANGES covers the cell's one subnet.
//
// routers.insert is async. Unlike a firewall rule (nothing waits on it), the VMs created right after
// this op need the NAT AT BOOT, so when THIS run created the router the Worker WAITS for the insert
// Operation to reach DONE before returning — "created" means the NAT exists, not merely that Google
// accepted it (the same contract as gcp-network-create). When the router already existed there is
// nothing to wait on.

export async function actuateGcpRouterNatCreate(
  params: GcpRouterNatCreateParams,
  env: Env,
): Promise<GcpRouterNatCreateResult> {
  const { project, region, networkName, routerName, natName } = params;
  const failure = (detail: string): GcpRouterNatCreateResult => ({
    ok: false,
    op: "gcp-router-nat-create",
    routerName,
    natName,
    detail,
  });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const accessToken = token.accessToken;
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const regionPath =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/regions/${encodeURIComponent(region)}`;
  const what = `router "${routerName}"`;

  const outcome = await insertComputeResource({
    url: `${regionPath}/routers`,
    accessToken,
    // Project-relative network reference, like the subnet body's — never a caller-supplied URL. The
    // NAT rides INLINE on the router so one insert creates both.
    body: {
      name: routerName,
      network: `global/networks/${networkName}`,
      nats: [
        {
          name: natName,
          sourceSubnetworkIpRangesToNat: "ALL_SUBNETWORKS_ALL_IP_RANGES",
          natIpAllocateOption: "AUTO_ONLY",
        },
      ],
    },
    what,
    project,
    permissionHint: "compute.routers.create (e.g. roles/compute.networkAdmin)",
  });
  if (outcome.kind === "failed") {
    return failure(outcome.detail);
  }
  if (outcome.kind === "created") {
    const waited = await waitForComputeOperation({
      waitUrl: `${regionPath}/operations/${encodeURIComponent(outcome.operationName)}/wait`,
      accessToken,
      what,
    });
    if (!waited.ok) {
      return failure(waited.detail);
    }
  }

  return { ok: true, op: "gcp-router-nat-create", routerName, natName, status: outcome.kind };
}

// ── gcp-firewall-get ───────────────────────────────────────────────────────────────────────
// READ-ONLY resume verification (planning/34, review finding 1): GET a cell firewall rule so a caller
// resuming a half-built cell can turn an already-existed rule from "trusted by name" into a real
// confirmation, or warn clearly if it is gone. Firewalls are GLOBAL, so the path has no region. Like
// every gcp-* op it mints the agency's OWN token (there is no platform fallback) — it just reads.
// A 404 is a clean "not present" (found:false, ok:true), NOT a failure; only auth / an unreachable
// API / an unexpected non-2xx is ok:false. The read-back body is NOT diffed against the fixed cell
// policy here — that deeper compare is a separate follow-up; this op confirms EXISTENCE.

export async function readComputeFirewall(params: GcpFirewallGetParams, env: Env): Promise<GcpFirewallGetResult> {
  const { project, ruleName } = params;
  const failure = (detail: string): GcpFirewallGetResult => ({ ok: false, op: "gcp-firewall-get", ruleName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const url =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/global/firewalls/${encodeURIComponent(ruleName)}`;

  let response: Response;
  try {
    response = await fetch(url, { headers: gcpHeaders(token.accessToken) });
  } catch (err) {
    return failure(`could not reach Google Compute Engine to read firewall rule "${ruleName}": ${errorMessage(err)}`);
  }
  const body = (await response.json().catch(() => null)) as ComputeInsertResponse | null;

  if (response.status === 404) {
    return { ok: true, op: "gcp-firewall-get", ruleName, found: false };
  }
  if (response.status === 401 || response.status === 403) {
    return failure(
      `Google Cloud denied reading firewall rule "${ruleName}" (HTTP ${response.status})${googleErrorMessage(body)} — the ` +
        `service account needs compute.firewalls.get (e.g. roles/compute.viewer) on project "${project}".`,
    );
  }
  if (!response.ok) {
    return failure(`reading firewall rule "${ruleName}" failed with HTTP ${response.status}${googleErrorMessage(body)}.`);
  }
  return { ok: true, op: "gcp-firewall-get", ruleName, found: true };
}

// ── gcp-router-get ─────────────────────────────────────────────────────────────────────────
// READ-ONLY resume verification: GET a cell Cloud Router and report its inline NAT config names, so a
// caller resuming a half-built cell can confirm both the router AND its cell NAT are really present (a
// same-named router WITHOUT the NAT leaves the private VMs with no egress). Routers are REGIONAL. Same
// agency-token-only, read-only contract as gcp-firewall-get: a 404 is a clean found:false (natNames
// []), only auth / an unreachable API / an unexpected non-2xx is ok:false.

/** What routers.get answers with (the fields this op reads). */
interface ComputeRouterResponse {
  name?: string;
  /** The router's inline Cloud NAT configs; each has a `name` this op reports back. */
  nats?: Array<{ name?: string }>;
  error?: ComputeInsertResponse["error"];
}

export async function readComputeRouter(params: GcpRouterGetParams, env: Env): Promise<GcpRouterGetResult> {
  const { project, region, routerName } = params;
  const failure = (detail: string): GcpRouterGetResult => ({ ok: false, op: "gcp-router-get", routerName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const url =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/regions/${encodeURIComponent(region)}/routers/${encodeURIComponent(routerName)}`;

  let response: Response;
  try {
    response = await fetch(url, { headers: gcpHeaders(token.accessToken) });
  } catch (err) {
    return failure(`could not reach Google Compute Engine to read router "${routerName}": ${errorMessage(err)}`);
  }
  const body = (await response.json().catch(() => null)) as ComputeRouterResponse | null;

  if (response.status === 404) {
    return { ok: true, op: "gcp-router-get", routerName, found: false, natNames: [] };
  }
  if (response.status === 401 || response.status === 403) {
    return failure(
      `Google Cloud denied reading router "${routerName}" (HTTP ${response.status})${googleErrorMessage(body)} — the ` +
        `service account needs compute.routers.get (e.g. roles/compute.viewer) on project "${project}".`,
    );
  }
  if (!response.ok) {
    return failure(`reading router "${routerName}" failed with HTTP ${response.status}${googleErrorMessage(body)}.`);
  }
  // Collect the inline NAT config names so the caller can confirm the CELL's NAT is present. A router
  // with no NAT config yields an empty list (the exact "no egress" case the caller must catch).
  const natNames = Array.isArray(body?.nats)
    ? body.nats
        .map((nat) => nat?.name)
        .filter((name): name is string => typeof name === "string" && name.length > 0)
    : [];
  return { ok: true, op: "gcp-router-get", routerName, found: true, natNames };
}

// ── gcp-instances-list ───────────────────────────────────────────────────────────────────────
// READ-ONLY zone discovery (planning/34 zone fallback): list every Compute Engine instance in the
// agency's own project whose name starts with the caller's prefix, across ALL zones, so a caller
// resuming a half-built cell can find which of its VMs already exist and pin the WHOLE cell to their
// one zone (creating in another zone would DUPLICATE VMs = double billing + a split cell). Uses
// compute.instances.aggregatedList (spans every zone). Same agency-token-only, read-only contract as
// the other GET ops: auth / an unreachable API / a non-2xx is ok:false.
//
// The response is paged; this reads EVERY page (bounded) and, if it cannot finish within the bound,
// returns ok:false rather than a possibly-truncated list — the caller relies on the list being
// COMPLETE to be sure a zone is empty, so a partial read must fail closed.

/** Google's max page size for aggregatedList, and a generous page bound (a cell is a few VMs). */
const GCP_AGGREGATED_LIST_PAGE_SIZE = 500;
const GCP_AGGREGATED_LIST_MAX_PAGES = 50;

/** What instances.aggregatedList answers with (the fields this op reads). */
interface ComputeAggregatedListResponse {
  /** Keyed by scope, e.g. "zones/australia-southeast1-a"; each scope may carry `instances`. */
  items?: Record<string, { instances?: Array<{ name?: string; zone?: string }> } | undefined>;
  nextPageToken?: string;
  /**
   * Scopes (e.g. "zones/australia-southeast1-b") that could NOT be reached on a PARTIAL-SUCCESS
   * response. When present, that scope's instances are OMITTED from `items` while the call still
   * returns HTTP 200 — so a non-empty `unreachables` means the list is INCOMPLETE and must fail
   * closed (a missed VM would let the caller pick a fresh zone and duplicate it).
   */
  unreachables?: string[];
  error?: ComputeInsertResponse["error"];
}

/**
 * The SHORT zone name for a listed instance: prefer the last path segment of its `zone` URL
 * (".../zones/australia-southeast1-b" -> "australia-southeast1-b"); fall back to the aggregatedList
 * scope key ("zones/<zone>"). Returns null when neither yields a name (the instance is skipped).
 */
function shortZoneName(zoneUrl: string | undefined, scopeKey: string): string | null {
  if (typeof zoneUrl === "string" && zoneUrl.length > 0) {
    const last = zoneUrl.slice(zoneUrl.lastIndexOf("/") + 1);
    if (last.length > 0) {
      return last;
    }
  }
  if (scopeKey.startsWith("zones/")) {
    const name = scopeKey.slice("zones/".length);
    if (name.length > 0) {
      return name;
    }
  }
  return null;
}

export async function readComputeInstancesList(params: GcpInstancesListParams, env: Env): Promise<GcpInstancesListResult> {
  const { project, namePrefix } = params;
  const failure = (detail: string): GcpInstancesListResult => ({ ok: false, op: "gcp-instances-list", detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }

  const instances: Array<{ name: string; zone: string }> = [];
  let pageToken: string | undefined;
  for (let page = 1; page <= GCP_AGGREGATED_LIST_MAX_PAGES; page += 1) {
    // Server-side name filter, in Compute Engine's REGEX form: `name eq <RE2>` where the regex must
    // match the ENTIRE field (Compute filter grammar — the `~` operator is gcloud CLIENT-side only, so
    // it is NOT used here). `<prefix>.*` matches a full name that STARTS WITH the prefix. `namePrefix`
    // is grammar-checked upstream to [a-z0-9-] with a leading letter, so it carries NO regex
    // metacharacter (a hyphen is literal), and values go through URLSearchParams — no job value is
    // string-interpolated into the URL. The caller still narrows the result to the cell's EXACT node
    // names, so an over-broad prefix is harmless; only an under-broad/invalid filter would matter, and
    // this cannot exclude a name that starts with the prefix.
    const query = new URLSearchParams();
    query.set("filter", `name eq "${namePrefix}.*"`);
    query.set("maxResults", String(GCP_AGGREGATED_LIST_PAGE_SIZE));
    // Ask Google to HARD-FAIL (non-2xx) instead of returning a partial 200 when a zone scope is
    // unreachable. aggregatedList has been defaulting this toward `true` (partial success), which we
    // must NOT accept for discovery — an omitted zone would read as "empty" and duplicate a VM. We set
    // it false AND re-check `unreachables` below, so a partial slips through neither path.
    query.set("returnPartialSuccess", "false");
    if (pageToken !== undefined) {
      query.set("pageToken", pageToken);
    }
    const url = `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}/aggregated/instances?${query.toString()}`;

    let response: Response;
    try {
      response = await fetch(url, { headers: gcpHeaders(token.accessToken) });
    } catch (err) {
      return failure(`could not reach Google Compute Engine to list instances in project "${project}": ${errorMessage(err)}`);
    }
    const body = (await response.json().catch(() => null)) as ComputeAggregatedListResponse | null;

    if (response.status === 401 || response.status === 403) {
      return failure(
        `Google Cloud denied listing instances (HTTP ${response.status})${googleErrorMessage(body)} — the service account ` +
          `needs compute.instances.list (e.g. roles/compute.viewer) on project "${project}".`,
      );
    }
    if (!response.ok) {
      return failure(`listing instances failed with HTTP ${response.status}${googleErrorMessage(body)}.`);
    }
    // A 200 can still be a PARTIAL read: aggregatedList may report `unreachables` (a zone scope it
    // could not read, its instances omitted) or a body-level `error` while returning 200. Discovery
    // relies on the list being COMPLETE to conclude a zone is empty, so treat either as a failure and
    // fail closed — never as "these are all the VMs" (that path duplicates a VM in a new zone).
    if (Array.isArray(body?.unreachables) && body.unreachables.length > 0) {
      const shown = body.unreachables.slice(0, 3).join(", ");
      const more = body.unreachables.length > 3 ? ", …" : "";
      return failure(
        `listing instances returned an incomplete result — ${body.unreachables.length} scope(s) unreachable ` +
          `(${shown}${more}); re-run to resume`,
      );
    }
    if (body?.error) {
      return failure(`listing instances returned a body-level error${googleErrorMessage(body)} — incomplete; re-run to resume`);
    }

    const items = body?.items ?? {};
    for (const [scopeKey, group] of Object.entries(items)) {
      const groupInstances = group?.instances;
      if (!Array.isArray(groupInstances)) {
        continue;
      }
      for (const instance of groupInstances) {
        if (typeof instance?.name !== "string" || instance.name.length === 0) {
          continue;
        }
        const zone = shortZoneName(instance.zone, scopeKey);
        if (zone === null) {
          continue;
        }
        instances.push({ name: instance.name, zone });
      }
    }

    if (!body?.nextPageToken) {
      return { ok: true, op: "gcp-instances-list", instances };
    }
    pageToken = body.nextPageToken;
  }

  // More pages remained after the bound. Fail closed (see the header note): the caller must not treat
  // a truncated list as "these are all the VMs" or it could create a duplicate in a new zone.
  return failure(`listing instances did not complete within ${GCP_AGGREGATED_LIST_MAX_PAGES} pages — re-run to resume`);
}

// ── gcp-instance-delete ──────────────────────────────────────────────────────────────────────
// Delete ONE cell VM in the agency's own project — the FIRST teardown step (planning/34 teardown).
// The wait is load-bearing here: a subnet delete fails with Google's resourceInUse while a VM still
// holds it, so this op must confirm the VM is GONE, not merely that Google accepted the delete. When
// the wait cannot confirm DONE, the result carries `stillRunning: true` so the caller reports
// "re-run to resume" off a field, never off the detail string.
//
// The file node's DATA DISK survives on purpose (gcp-instance-create attaches it autoDelete:false —
// it holds the sites' files), so this op leaves an orphaned disk behind by design.

export async function actuateGcpInstanceDelete(
  params: GcpInstanceDeleteParams,
  env: Env,
): Promise<GcpInstanceDeleteResult> {
  const { project, zone } = params;
  const instanceName = params.name;
  const failure = (detail: string): GcpInstanceDeleteResult => ({
    ok: false,
    op: "gcp-instance-delete",
    instanceName,
    detail,
  });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const zonePath =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/zones/${encodeURIComponent(zone)}`;

  const outcome = await deleteComputeResource({
    url: `${zonePath}/instances/${encodeURIComponent(instanceName)}`,
    waitUrlBase: `${zonePath}/operations`,
    accessToken: token.accessToken,
    what: `instance "${instanceName}"`,
    project,
    permissionHint: "compute.instances.delete (e.g. roles/compute.instanceAdmin.v1)",
  });
  if (outcome.kind === "failed" && outcome.unconfirmed) {
    return { ok: false, op: "gcp-instance-delete", instanceName, detail: outcome.detail, stillRunning: true };
  }
  if (outcome.kind === "failed") {
    return failure(outcome.detail);
  }
  if (outcome.kind === "already-absent") {
    // Nothing was deleted, so there is no operation to report.
    return { ok: true, op: "gcp-instance-delete", instanceName, status: "already-absent" };
  }
  return { ok: true, op: "gcp-instance-delete", instanceName, status: "deleted", operationName: outcome.operationName };
}

// ── gcp-address-delete ───────────────────────────────────────────────────────────────────────
// Release the cell gateway's reserved regional static external IP (planning/34 teardown). Runs AFTER
// the VMs: a reservation attached to a live VM is in use and Google refuses to release it.

export async function actuateGcpAddressDelete(
  params: GcpAddressDeleteParams,
  env: Env,
): Promise<GcpAddressDeleteResult> {
  const { project, region, addressName } = params;
  const failure = (detail: string): GcpAddressDeleteResult => ({ ok: false, op: "gcp-address-delete", addressName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const regionPath =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/regions/${encodeURIComponent(region)}`;

  const outcome = await deleteComputeResource({
    url: `${regionPath}/addresses/${encodeURIComponent(addressName)}`,
    waitUrlBase: `${regionPath}/operations`,
    accessToken: token.accessToken,
    what: `address "${addressName}"`,
    project,
    permissionHint: "compute.addresses.delete (e.g. roles/compute.networkAdmin)",
  });
  if (outcome.kind === "failed") {
    return failure(outcome.detail);
  }
  return { ok: true, op: "gcp-address-delete", addressName, status: outcome.kind };
}

// ── gcp-firewall-delete ──────────────────────────────────────────────────────────────────────
// Delete ONE firewall rule from the cell's VPC (planning/34 teardown) — a network delete fails while
// any rule still attaches to it. Firewalls are GLOBAL, so the path has no region.

export async function actuateGcpFirewallDelete(
  params: GcpFirewallDeleteParams,
  env: Env,
): Promise<GcpFirewallDeleteResult> {
  const { project, ruleName } = params;
  const failure = (detail: string): GcpFirewallDeleteResult => ({ ok: false, op: "gcp-firewall-delete", ruleName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const projectPath = `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}`;

  const outcome = await deleteComputeResource({
    url: `${projectPath}/global/firewalls/${encodeURIComponent(ruleName)}`,
    waitUrlBase: `${projectPath}/global/operations`,
    accessToken: token.accessToken,
    what: `firewall rule "${ruleName}"`,
    project,
    permissionHint: "compute.firewalls.delete (e.g. roles/compute.securityAdmin)",
  });
  if (outcome.kind === "failed") {
    return failure(outcome.detail);
  }
  return { ok: true, op: "gcp-firewall-delete", ruleName, status: outcome.kind };
}

// ── gcp-router-delete ────────────────────────────────────────────────────────────────────────
// Delete the cell's regional Cloud Router (planning/34 teardown). The inline Cloud NAT goes WITH it —
// a NAT is a field of the router, not a resource of its own, so there is no separate NAT delete op
// (the mirror of gcp-router-nat-create, which creates both in one insert).

export async function actuateGcpRouterDelete(
  params: GcpRouterDeleteParams,
  env: Env,
): Promise<GcpRouterDeleteResult> {
  const { project, region, routerName } = params;
  const failure = (detail: string): GcpRouterDeleteResult => ({ ok: false, op: "gcp-router-delete", routerName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const regionPath =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/regions/${encodeURIComponent(region)}`;

  const outcome = await deleteComputeResource({
    url: `${regionPath}/routers/${encodeURIComponent(routerName)}`,
    waitUrlBase: `${regionPath}/operations`,
    accessToken: token.accessToken,
    what: `router "${routerName}"`,
    project,
    permissionHint: "compute.routers.delete (e.g. roles/compute.networkAdmin)",
  });
  if (outcome.kind === "failed") {
    return failure(outcome.detail);
  }
  return { ok: true, op: "gcp-router-delete", routerName, status: outcome.kind };
}

// ── gcp-network-delete ───────────────────────────────────────────────────────────────────────
// Delete the cell's VPC: the SUBNET first, then the network (planning/34 teardown). ONE op for both,
// because the order is not optional — a networks.delete while the subnet still exists is Google's
// resourceInUse. The exact mirror of gcp-network-create, which creates the network then the subnet.
// Each delete is WAITED to DONE inside deleteComputeResource, so the network delete only starts once
// the subnet is really gone.
//
// A failure on the subnet stops the op: the network delete is NOT attempted, because it would fail
// anyway and the caller re-runs the whole op to resume (both halves are idempotent).

export async function actuateGcpNetworkDelete(
  params: GcpNetworkDeleteParams,
  env: Env,
): Promise<GcpNetworkDeleteResult> {
  const { project, region, networkName, subnetName } = params;
  const failure = (detail: string): GcpNetworkDeleteResult => ({
    ok: false,
    op: "gcp-network-delete",
    networkName,
    subnetName,
    detail,
  });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const accessToken = token.accessToken;
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const projectPath = `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}`;
  const regionPath = `${projectPath}/regions/${encodeURIComponent(region)}`;

  const subnetOutcome = await deleteComputeResource({
    url: `${regionPath}/subnetworks/${encodeURIComponent(subnetName)}`,
    waitUrlBase: `${regionPath}/operations`,
    accessToken,
    what: `subnetwork "${subnetName}"`,
    project,
    permissionHint: "compute.subnetworks.delete (e.g. roles/compute.networkAdmin)",
  });
  if (subnetOutcome.kind === "failed") {
    return failure(subnetOutcome.detail);
  }

  const networkOutcome = await deleteComputeResource({
    url: `${projectPath}/global/networks/${encodeURIComponent(networkName)}`,
    waitUrlBase: `${projectPath}/global/operations`,
    accessToken,
    what: `network "${networkName}"`,
    project,
    permissionHint: "compute.networks.delete (e.g. roles/compute.networkAdmin)",
  });
  if (networkOutcome.kind === "failed") {
    return failure(networkOutcome.detail);
  }

  return {
    ok: true,
    op: "gcp-network-delete",
    networkName,
    subnetName,
    subnetStatus: subnetOutcome.kind,
    networkStatus: networkOutcome.kind,
  };
}

// ── gcp-instance-set-metadata ────────────────────────────────────────────────────────────────
// planning/47: MERGE keys into one cell VM's metadata in the agency's own project, so a provisioned
// cell can be UPDATED (the `startup-script` key is what Google runs as root on every boot; the first
// consumer re-renders the file node's script with the backup credentials so its timers arm). Four
// steps, in this fixed order:
//   1. SUBSTITUTE the `@@DY_T1_S3_BUCKET@@` / `@@DY_T2_S3_*@@` placeholders in every value from this
//      Worker's OWN S3_* configuration — BEFORE any token is minted or any call is made, so a value
//      this Worker will not stand behind fails with zero side effects. This is the op's second
//      security boundary (see substituteMetadataPlaceholders): the platform never holds the agency's
//      object-store credential, it sends a script with placeholders and the Worker fills them in.
//      The allowlist is FIXED and SMALL; any other `@@...@@` is refused outright, never passed
//      through — a stray placeholder in a root boot script is a failure worth refusing loudly, not a
//      value worth guessing at.
//   2. GET the instance to read its current metadata `fingerprint` + `items`.
//   3. MERGE: every existing key NOT named in the request survives verbatim (losing an unrelated key
//      on a live node is a silent, serious regression); a named key is replaced in place; a new key is
//      appended.
//   4. POST instances.setMetadata with the fingerprint from step 2 and WAIT (bounded) for the zonal
//      operation. Google rejects a STALE fingerprint with 412 — that rejection IS the concurrency
//      guard, and it is surfaced as a discriminable `staleFingerprint` failure for the caller to
//      re-run deliberately, never retried blindly inside a loop that could clobber a concurrent change.
//
// KEY ALLOWLIST (the op's FIRST boundary) is enforced upstream, in dispatch-params.ts
// validateGcpInstanceSetMetadataParams: every `items[].key` this actuator receives is on
// GCP_METADATA_KEYS (exactly `startup-script` today), and a request carrying any other key was refused
// whole as a 400 before this code ran. See that allowlist's comment for what it does and does not
// constrain — in short, it keeps the op doing only what it says, not less than root-on-the-node.
//
// INJECTION SURFACE: `project` / `zone` / `name` are grammar-checked URL path segments (encoded again
// here); the merged items land ONLY in the JSON.stringify'd body. No substituted secret is ever
// logged, echoed in a result, or placed in a detail string. A DETAIL carries placeholder NAMES, env
// var names and metadata KEYS only, never a value of any kind. A SUCCESSFUL RESULT additionally
// carries the resolved values of the placeholders PLACEHOLDER_VALUES_SAFE_TO_ECHO names — the two
// buckets, the endpoint and the region — and of nothing else; see that allowlist for why the two
// credential placeholders are absent from it and must stay absent.

/**
 * The FIXED allowlist of placeholders this Worker will substitute into a metadata value, each named
 * after the backup variable it feeds. The five `DY_T2_*` names feed Tier-2
 * (infra/storage-tier/backup-full-daily.sh reads DY_T2_ACCESS_KEY_ID / DY_T2_SECRET_ACCESS_KEY /
 * DY_T2_ENDPOINT / DY_T2_BUCKET / DY_T2_REGION); `@@DY_T1_S3_BUCKET@@` is Tier-1's own bucket name
 * (hub#64 — restic cannot operate in a bucket that refuses DELETE, so it must be able to live
 * somewhere other than Tier-2's deliberately locked bucket). Each maps to the agency's own S3_*
 * Worker secret — see resolveAgencyObjectStoreForBoot for the exact value each one yields. This is
 * NOT a template engine: no expressions, no nesting, no recursion, and a substituted value is itself
 * checked to contain no `@@` (BOOT_SAFE_VALUE_RE admits no "@"), so one substitution can never
 * manufacture another placeholder. Extend this list on purpose, one name at a time, with the matching
 * twin in the platform's renderer.
 */
export const METADATA_PLACEHOLDER_NAMES = [
  "@@DY_T2_S3_ACCESS_KEY_ID@@",
  "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
  "@@DY_T2_S3_ENDPOINT@@",
  "@@DY_T2_S3_BUCKET@@",
  "@@DY_T2_S3_REGION@@",
  "@@DY_T1_S3_BUCKET@@",
] as const;
export type MetadataPlaceholderName = (typeof METADATA_PLACEHOLDER_NAMES)[number];

/**
 * THE ALLOWLIST OF PLACEHOLDERS WHOSE RESOLVED VALUE MAY BE ECHOED BACK IN THE RESULT. Adding a name
 * to this list is how a secret would leak out of this Worker, so treat an edit here as a security
 * change and not a reporting tweak.
 *
 * These four are not credentials: two bucket names, an object-store endpoint host and an AWS region.
 * They are reported because "the placeholder was substituted" says nothing about WHAT it resolved to,
 * and that gap produced a real silent failure — `@@DY_T1_S3_BUCKET@@` falls back to S3_BUCKET when
 * the optional S3_BACKUP_BUCKET secret is unset, so a Tier-1 bucket that never changed was reported
 * as a clean substitution and an `ok` run, while restic kept writing into the locked Tier-2 bucket
 * (hub#64). Echoing the value is what makes that visible from the control plane instead of from an
 * SSH session and an mtime comparison.
 *
 * `@@DY_T2_S3_ACCESS_KEY_ID@@` and `@@DY_T2_S3_SECRET_ACCESS_KEY@@` are DELIBERATELY ABSENT and must
 * stay absent. A secret key is obvious; an access key id is half of a credential and is a
 * long-lived identifier of the agency's object store, and Direction-B's whole point is that the
 * platform never holds either half. Anything not named here is omitted from the result entirely —
 * not masked, not truncated, absent.
 */
export const PLACEHOLDER_VALUES_SAFE_TO_ECHO = [
  "@@DY_T1_S3_BUCKET@@",
  "@@DY_T2_S3_BUCKET@@",
  "@@DY_T2_S3_ENDPOINT@@",
  "@@DY_T2_S3_REGION@@",
] as const;

/** Whether one substituted placeholder's resolved value may appear in the op's result. */
function mayEchoPlaceholderValue(placeholder: MetadataPlaceholderName): boolean {
  return (PLACEHOLDER_VALUES_SAFE_TO_ECHO as readonly string[]).includes(placeholder);
}

/** The sigil every placeholder starts and ends with. A value may not contain it anywhere else. */
const PLACEHOLDER_SIGIL = "@@";
/** The shape of a well-formed placeholder TOKEN, used only to NAME an unknown one in a detail string. */
const PLACEHOLDER_TOKEN_RE = /^@@[A-Za-z0-9_]{1,64}@@/;

/**
 * The charset a substituted value must fit to be spliced into a root boot script: the characters a
 * real access-key id (uppercase alnum), secret key (base64: +/=), R2/MinIO/AWS endpoint URL (scheme,
 * dots, hyphens, a port), bucket name or region can legitimately contain — and NOTHING that could
 * break out of a shell word in either quoting style (no quote, backslash, "$", backtick, whitespace,
 * newline or other control character) and no "@" (so no `@@`). A value outside this set fails the op
 * with a message naming the ENV VAR, never the value. Bounded so a junk mega-string fails here.
 */
const BOOT_SAFE_VALUE_RE = /^[A-Za-z0-9+/=._:-]{1,512}$/;

// ── Shape guards for the values whose shape is actually known ────────────────────────────────
//
// WHY THESE EXIST ON TOP OF THE CHARSET GUARD, and why they are this specific. On 2026-10-06 an
// agency's optional S3_BACKUP_BUCKET secret was set to the agency's S3 API URL instead of the bucket
// NAME, and BOOT_SAFE_VALUE_RE passed it: ":", "/", "." and "-" are all inside that charset, so a
// whole URL sits comfortably in a guard meant to stop junk from reaching a root-run boot script. The
// published metadata read `DY_T1_S3_BUCKET='https://<acct>.r2.cloudflarestorage.com'`, and because
// file.sh composes the restic repository as `s3:<endpoint>/<bucket>/<slug>`, the next boot would have
// produced `s3:https://host/https://host/dy-backups-tier1/<slug>`.
//
// IT IS THE NATURAL MISTAKE, NOT A CARELESS ONE. Cloudflare's R2 dashboard labels the
// endpoint-plus-bucket URL "the S3 API", so that URL is what is on the clipboard when someone goes
// looking for the bucket. People will keep making it, which is why the refusal below names the
// variable and says the value looks like a URL rather than leaving them to compare two charsets.
//
// The charset guard STAYS and still runs first. These are narrower, additional checks on the three
// values whose shape this Worker actually knows — the two buckets and the endpoint. Like every other
// guard here, a refusal names the ENV VAR and the shape expected, and NEVER echoes the value: a
// bucket name is not a credential, but keeping the no-echo discipline uniform is worth more than the
// convenience of seeing the bad value in the error.

/**
 * An S3 bucket name, by S3's own naming rules: 3-63 characters, lowercase letters / digits / dots /
 * hyphens, beginning and ending with a letter or digit. R2 is stricter still (no dots), so a name
 * that passes here is accepted by both.
 *
 * Two of S3's rules are checked separately below because a regex states them badly: no two adjacent
 * dots, and not formatted as an IPv4 address.
 *
 * S3's reserved prefixes and suffixes (`xn--`, `sthree-`, `amzn-s3-demo-`, `-s3alias`, `--ol-s3`,
 * `.mrap`, `--x-s3`) are DELIBERATELY NOT enforced. S3 refuses those at bucket CREATION, so no
 * existing bucket carries one, and rejecting a name the agency's store actually accepts would break a
 * working configuration to catch a case that cannot occur.
 */
const S3_BUCKET_NAME_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

/** S3 refuses a bucket name formatted as an IPv4 address; the digits-and-dots shape is enough here. */
const IPV4_SHAPED_RE = /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/;

/** What a pasted URL carries and a bucket name never does. Named so the refusal can be specific. */
const URL_SCHEME_SEPARATOR = "://";

/**
 * A bare object-store endpoint: scheme, host, optional port, and NOTHING after it. The opposite
 * mistake to the bucket one — an endpoint SHOULD be a URL, but one carrying a path segment (e.g.
 * `https://<acct>.r2.cloudflarestorage.com/<bucket>`) is concatenated with the bucket name by
 * file.sh, so that segment ends up in the repository path twice.
 */
const S3_ENDPOINT_URL_RE = /^https?:\/\/[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$/;

/**
 * Why `value` is not a usable bucket name, or null when it is one. Guard clauses in the order an
 * operator would want to read them: the mistake that actually happens first, then the general shape,
 * then the two rules the regex cannot state.
 */
function describeBucketNameFault(envName: string, value: string): string | null {
  if (value.includes(URL_SCHEME_SEPARATOR)) {
    return (
      `${envName} looks like an endpoint URL, not a bucket name (it contains "${URL_SCHEME_SEPARATOR}") — refusing to ` +
      `splice it into a boot script, where it would become part of the backup repository path. Cloudflare's R2 ` +
      `dashboard labels the endpoint-plus-bucket URL "the S3 API", which is the usual source of this: set ` +
      `${envName} to the bucket NAME alone and leave the URL in S3_ENDPOINT.`
    );
  }
  if (!S3_BUCKET_NAME_RE.test(value)) {
    return (
      `${envName} is not a valid S3/R2 bucket name — it must be 3 to 63 characters of lowercase letters, digits, ` +
      `dots and hyphens, beginning and ending with a letter or digit.`
    );
  }
  if (value.includes("..")) {
    return `${envName} is not a valid S3/R2 bucket name — a bucket name may not contain two adjacent dots.`;
  }
  if (IPV4_SHAPED_RE.test(value)) {
    return `${envName} is not a valid S3/R2 bucket name — a bucket name may not be formatted as an IPv4 address.`;
  }
  return null;
}

/** The agency's object-store configuration as the Worker itself uses it (see the resolver below). */
interface AgencyObjectStoreConfig {
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  region: string;
  /** "" when S3_ENDPOINT is unset — the backup runner's own encoding of "native AWS S3". */
  endpoint: string;
  /** Tier-1's bucket: S3_BACKUP_BUCKET when set, otherwise `bucket` (see the resolver). */
  tier1Bucket: string;
}

/**
 * The region substituted for `@@DY_T2_S3_REGION@@` when S3_REGION is UNSET. This is the Worker's own
 * effective presign region — validators.ts::validateS3, actuateDbExport and actuateDbImport all apply
 * `env.S3_REGION || "us-east-1"` — so a node signs exactly the way the Worker (and the green /validate
 * probe) already does.
 *
 * WHY this is explicit and not left to the script: infra/storage-tier/backup-full-daily.sh has its OWN
 * fallback, `REGION="${DY_T2_REGION:-us-east-2}"` (line 74), which is NOT the Worker's. If this op
 * substituted "" for an unset S3_REGION, the node would sign for us-east-2 while the Worker's presign
 * (and the agency's validated configuration) use us-east-1 — two halves of one backup system silently
 * disagreeing about the region, discovered only from a failed backup. Substituting the Worker's
 * effective region is what keeps the two from disagreeing. Change this constant ONLY together with the
 * three inline defaults above.
 */
const WORKER_EFFECTIVE_S3_REGION_DEFAULT = "us-east-1";

/**
 * The endpoint substituted for `@@DY_T2_S3_ENDPOINT@@` when S3_ENDPOINT is UNSET. S3_ENDPOINT is
 * OPTIONAL by contract (env.ts: unset means real AWS; the Worker's presign then targets AWS with no
 * custom endpoint). backup-full-daily.sh encodes the SAME meaning as an EMPTY `DY_T2_ENDPOINT`
 * (line 75: "empty => AWS S3 (native)"), so "" is the one substitution whose empty value is a meaning,
 * not a missing secret. An R2/MinIO/Wasabi agency always has S3_ENDPOINT set (its /validate probe
 * would fail otherwise), so an R2 agency never reaches this default.
 */
const NATIVE_AWS_ENDPOINT_FOR_BOOT = "";

/**
 * Resolve the S3_* values a boot script may receive, by EXACTLY the rule the Worker's own S3
 * actuators and validator apply (validators.ts::validateS3, actuateDbExport, actuateDbImport):
 *   - S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY / S3_BUCKET are REQUIRED. An unset one is a hard
 *     failure naming the variable — NEVER an empty substitution, because an empty credential in a
 *     boot script produces a node that looks provisioned and silently never backs up, which is
 *     precisely the failure this op exists to end (hub#52).
 *   - S3_REGION unset => WORKER_EFFECTIVE_S3_REGION_DEFAULT (see its comment: the Worker presigns with
 *     us-east-1, the backup script would fall back to us-east-2 — this is what keeps them agreeing).
 *   - S3_ENDPOINT unset => NATIVE_AWS_ENDPOINT_FOR_BOOT, i.e. "" (see its comment: the script's own
 *     encoding of native AWS S3).
 *   - S3_BACKUP_BUCKET unset => S3_BUCKET (see the comment at the point of use: the fallback is what
 *     keeps every existing agency on its current behaviour with no action).
 * Every non-empty value must then fit BOOT_SAFE_VALUE_RE (see above), and the three values whose shape
 * this Worker knows — both buckets and the endpoint — must additionally fit that shape (see the block
 * comment above S3_BUCKET_NAME_RE: a URL passes the charset guard, and one reached a live node). All of
 * them are checked whenever ANY placeholder is present, so a broken S3 configuration fails the whole op
 * rather than half of it.
 */
function resolveAgencyObjectStoreForBoot(env: Env): { ok: true; config: AgencyObjectStoreConfig } | { ok: false; detail: string } {
  const missing: string[] = [];
  if (!env.S3_ACCESS_KEY_ID) missing.push("S3_ACCESS_KEY_ID");
  if (!env.S3_SECRET_ACCESS_KEY) missing.push("S3_SECRET_ACCESS_KEY");
  if (!env.S3_BUCKET) missing.push("S3_BUCKET");
  if (missing.length > 0) {
    return {
      ok: false,
      detail:
        `${missing.join(" / ")} ${missing.length === 1 ? "is" : "are"} not configured on this Worker — a @@DY_T2_S3_*@@ ` +
        "placeholder needs the agency's object-store credential; refusing to write a boot script with an empty one.",
    };
  }

  // The two DEFAULTED values, made explicit at the point of use. Region: an unset (or empty) S3_REGION
  // becomes the Worker's effective presign region, NOT "" — "" would let backup-full-daily.sh fall back
  // to its own us-east-2 while the Worker presigns with us-east-1 (see WORKER_EFFECTIVE_S3_REGION_DEFAULT).
  // Endpoint: an unset S3_ENDPOINT becomes "", which the script defines as native AWS S3 (see
  // NATIVE_AWS_ENDPOINT_FOR_BOOT); a set one is normalized the way the presigners normalize it.
  let region = WORKER_EFFECTIVE_S3_REGION_DEFAULT;
  if (env.S3_REGION) {
    region = env.S3_REGION;
  }
  let endpoint = NATIVE_AWS_ENDPOINT_FOR_BOOT;
  if (env.S3_ENDPOINT) {
    endpoint = stripTrailingSlash(env.S3_ENDPOINT);
  }

  // The THIRD defaulted value, and the one with a hard reason behind it (hub#64). The two tiers want
  // OPPOSITE things from a bucket: Tier-1 is restic, which REQUIRES delete (it writes a lock object
  // per run and removes it at the end, and `forget`/`prune` retention is implemented entirely by
  // deleting), while Tier-2 is a write-once full whose whole purpose is to survive a compromised
  // credential and therefore wants a retention/lock policy. On the first live Tier-1 run against an
  // agency bucket that had one, the snapshot was written, the lock could not be removed and retention
  // became permanently inert — so the two tiers must be able to sit in different buckets.
  //
  // UNSET FALLS BACK TO S3_BUCKET, and that fallback is load-bearing: every agency that does nothing
  // keeps exactly the behaviour it has today (both tiers in the one bucket), and only an agency that
  // deliberately creates an UNLOCKED Tier-1 bucket and sets S3_BACKUP_BUCKET gets the split. One
  // credential covers both buckets, so nothing else about the configuration changes.
  let tier1Bucket = env.S3_BUCKET as string;
  let tier1BucketEnvName = "S3_BUCKET";
  if (env.S3_BACKUP_BUCKET) {
    tier1Bucket = env.S3_BACKUP_BUCKET;
    tier1BucketEnvName = "S3_BACKUP_BUCKET";
  }

  const config: AgencyObjectStoreConfig = {
    accessKeyId: env.S3_ACCESS_KEY_ID as string,
    secretAccessKey: env.S3_SECRET_ACCESS_KEY as string,
    bucket: env.S3_BUCKET as string,
    region,
    endpoint,
    tier1Bucket,
  };

  // The charset guard names the ENV VAR only — a substituted value may be a secret.
  const checks: Array<[string, string]> = [
    ["S3_ACCESS_KEY_ID", config.accessKeyId],
    ["S3_SECRET_ACCESS_KEY", config.secretAccessKey],
    ["S3_BUCKET", config.bucket],
    ["S3_REGION", config.region],
    ["S3_ENDPOINT", config.endpoint],
  ];
  // Only when S3_BACKUP_BUCKET is really set: on the fallback path tier1Bucket IS the S3_BUCKET value
  // already checked above, and checking it twice would let a bad value be reported under the wrong
  // variable name.
  if (tier1BucketEnvName === "S3_BACKUP_BUCKET") {
    checks.push(["S3_BACKUP_BUCKET", config.tier1Bucket]);
  }
  for (const [envName, value] of checks) {
    if (envName === "S3_ENDPOINT" && value === "") {
      continue;
    }
    if (!BOOT_SAFE_VALUE_RE.test(value)) {
      return {
        ok: false,
        detail:
          `${envName} holds a character outside [A-Za-z0-9+/=._:-] (or is over 512 chars) — refusing to splice it ` +
          "into a boot script.",
      };
    }
  }

  // The narrower SHAPE checks, after the charset guard so a value that is junk in both ways is
  // reported under the simpler rule. See the block comment above S3_BUCKET_NAME_RE for why a URL in
  // a bucket variable is the specific mistake these catch.
  const bucketChecks: Array<[string, string]> = [["S3_BUCKET", config.bucket]];
  if (tier1BucketEnvName === "S3_BACKUP_BUCKET") {
    bucketChecks.push(["S3_BACKUP_BUCKET", config.tier1Bucket]);
  }
  for (const [envName, value] of bucketChecks) {
    const fault = describeBucketNameFault(envName, value);
    if (fault !== null) {
      return { ok: false, detail: fault };
    }
  }

  // "" is the script's own encoding of native AWS S3 (see NATIVE_AWS_ENDPOINT_FOR_BOOT), so only a
  // configured endpoint has a shape to check.
  if (config.endpoint !== "" && !S3_ENDPOINT_URL_RE.test(config.endpoint)) {
    return {
      ok: false,
      detail:
        "S3_ENDPOINT is not a bare endpoint URL — it must be scheme://host with an optional port and NOTHING after " +
        "it. An endpoint carrying a path segment (the bucket name, typically) is joined to the bucket name on the " +
        "node, so that segment lands in the backup repository path twice.",
    };
  }

  return { ok: true, config };
}

/** The resolved value one allowlisted placeholder stands for. */
function valueForPlaceholder(placeholder: MetadataPlaceholderName, config: AgencyObjectStoreConfig): string {
  if (placeholder === "@@DY_T2_S3_ACCESS_KEY_ID@@") return config.accessKeyId;
  if (placeholder === "@@DY_T2_S3_SECRET_ACCESS_KEY@@") return config.secretAccessKey;
  if (placeholder === "@@DY_T2_S3_ENDPOINT@@") return config.endpoint;
  if (placeholder === "@@DY_T2_S3_BUCKET@@") return config.bucket;
  if (placeholder === "@@DY_T1_S3_BUCKET@@") return config.tier1Bucket;
  return config.region;
}

/**
 * The detail for a `@@` that does not start an allowlisted placeholder. Names the TOKEN when it is
 * well-formed (`@@NAME@@` — a placeholder name is not a secret) and otherwise only its offset: the
 * surrounding script text is NEVER echoed, because a rendered boot script legitimately carries real
 * secrets of its own (the platform's restic repository password, for one).
 */
function describeUnknownPlaceholder(value: string, offset: number): string {
  const allowed = METADATA_PLACEHOLDER_NAMES.join(", ");
  const token = PLACEHOLDER_TOKEN_RE.exec(value.slice(offset, offset + 80));
  if (token) {
    return `the placeholder ${token[0]} is not on this Worker's allowlist (${allowed}) — refusing to write it into instance metadata.`;
  }
  return `a "@@" at offset ${offset} does not start an allowlisted placeholder (${allowed}) — refusing to write it into instance metadata.`;
}

export type PlaceholderSubstitution =
  | {
      ok: true;
      value: string;
      substituted: MetadataPlaceholderName[];
      /**
       * The RESOLVED value of each substituted placeholder that PLACEHOLDER_VALUES_SAFE_TO_ECHO
       * names, keyed by placeholder name. Anything else — both credential halves — is absent.
       */
      placeholderValues: Record<string, string>;
    }
  | { ok: false; detail: string };

/**
 * Substitute the allowlisted placeholders in ONE metadata value from the Worker's own S3_*
 * configuration. A single left-to-right scan: at every `@@` exactly one allowlisted placeholder must
 * begin, or the whole value is refused — so an unknown `@@FOO@@`, a half-formed `@@`, or two
 * placeholders run together are all hard errors, never passed through and never silently left in
 * place. Plain string slicing throughout (no regex replacement), so a secret containing "$&"-style
 * sequences can never be reinterpreted. A value with no `@@` at all is returned untouched without
 * reading any S3_* variable, so a non-secret metadata key works on a Worker with no object store
 * configured. Exported for the unit tests; `substituted` lists placeholder NAMES only, and
 * `placeholderValues` carries the resolved value of the non-secret ones (PLACEHOLDER_VALUES_SAFE_TO_ECHO).
 */
export function substituteMetadataPlaceholders(value: string, env: Env): PlaceholderSubstitution {
  const output: string[] = [];
  const substituted: MetadataPlaceholderName[] = [];
  const placeholderValues: Record<string, string> = {};
  let config: AgencyObjectStoreConfig | null = null;
  let cursor = 0;

  // Every iteration either breaks (no further sigil) or advances `cursor` past one whole placeholder,
  // so the loop terminates.
  while (true) {
    const sigilAt = value.indexOf(PLACEHOLDER_SIGIL, cursor);
    if (sigilAt === -1) {
      output.push(value.slice(cursor));
      break;
    }
    output.push(value.slice(cursor, sigilAt));

    const placeholder = METADATA_PLACEHOLDER_NAMES.find((candidate) => value.startsWith(candidate, sigilAt));
    if (placeholder === undefined) {
      return { ok: false, detail: describeUnknownPlaceholder(value, sigilAt) };
    }
    // Resolve the S3 configuration lazily, once, and only because a placeholder is really present.
    if (config === null) {
      const resolved = resolveAgencyObjectStoreForBoot(env);
      if (!resolved.ok) {
        return { ok: false, detail: resolved.detail };
      }
      config = resolved.config;
    }
    const resolvedValue = valueForPlaceholder(placeholder, config);
    output.push(resolvedValue);
    if (!substituted.includes(placeholder)) {
      substituted.push(placeholder);
    }
    // The ONE place a resolved value is kept for reporting. The allowlist is consulted here, on the
    // value itself, so a placeholder it does not name can never reach the result by any path.
    if (mayEchoPlaceholderValue(placeholder)) {
      placeholderValues[placeholder] = resolvedValue;
    }
    cursor = sigilAt + placeholder.length;
  }

  return { ok: true, value: output.join(""), substituted, placeholderValues };
}

/**
 * Substitute the allowlisted placeholders into every item, from the SAME env. Shared by
 * gcp-instance-set-metadata and its read-only twin gcp-instance-metadata-diff, so both hash exactly
 * the value a write would send. Every item resolves from one env, so two items naming one placeholder
 * agree on its value. Non-secret values only in `placeholderValues` (PLACEHOLDER_VALUES_SAFE_TO_ECHO).
 */
export function renderMetadataItems(
  items: GcpInstanceMetadataItem[],
  env: Env,
):
  | { ok: true; renderedItems: GcpInstanceMetadataItem[]; placeholdersSubstituted: MetadataPlaceholderName[]; placeholderValues: Record<string, string> }
  | { ok: false; detail: string } {
  const renderedItems: GcpInstanceMetadataItem[] = [];
  const placeholdersSubstituted: MetadataPlaceholderName[] = [];
  const placeholderValues: Record<string, string> = {};
  for (const item of items) {
    const rendered = substituteMetadataPlaceholders(item.value, env);
    if (!rendered.ok) {
      return { ok: false, detail: `metadata key "${item.key}": ${rendered.detail}` };
    }
    renderedItems.push({ key: item.key, value: rendered.value });
    for (const name of rendered.substituted) {
      if (!placeholdersSubstituted.includes(name)) {
        placeholdersSubstituted.push(name);
      }
    }
    Object.assign(placeholderValues, rendered.placeholderValues);
  }
  return { ok: true, renderedItems, placeholdersSubstituted, placeholderValues };
}

/** What instances.get answers with (the fields these ops read). */
interface ComputeInstanceResponse {
  name?: string;
  /** PROVISIONING | STAGING | RUNNING | STOPPING | SUSPENDING | SUSPENDED | REPAIRING | TERMINATED. */
  status?: string;
  metadata?: {
    /** The optimistic-concurrency token instances.setMetadata must echo back. */
    fingerprint?: string;
    items?: Array<{ key?: string; value?: string }>;
  };
  error?: ComputeInsertResponse["error"];
}

/**
 * GET one instance. A 404 is a FAILURE for both update ops (there is nothing to update or restart —
 * unlike a delete, "already absent" is not a converged success here). 401/403 names the read
 * permission; any other non-2xx carries Google's message.
 */
export async function readComputeInstance(input: {
  url: string;
  accessToken: string;
  what: string;
  project: string;
}): Promise<{ ok: true; instance: ComputeInstanceResponse } | { ok: false; detail: string }> {
  const { url, accessToken, what, project } = input;

  let response: Response;
  try {
    response = await fetch(url, { headers: gcpHeaders(accessToken) });
  } catch (err) {
    return { ok: false, detail: `could not reach Google Compute Engine to read ${what}: ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as ComputeInstanceResponse | null;

  if (response.status === 404) {
    return { ok: false, detail: `${what} was not found in project "${project}" — nothing to update.` };
  }
  if (response.status === 401 || response.status === 403) {
    return {
      ok: false,
      detail:
        `Google Cloud denied reading ${what} (HTTP ${response.status})${googleErrorMessage(body)} — the service account ` +
        `needs compute.instances.get (e.g. roles/compute.viewer) on project "${project}".`,
    };
  }
  if (!response.ok || body === null) {
    return { ok: false, detail: `reading ${what} failed with HTTP ${response.status}${googleErrorMessage(body)}.` };
  }
  return { ok: true, instance: body };
}

/** One metadata entry as Compute Engine stores it — ANY key (the instance's existing keys are not ours). */
interface ComputeMetadataItem {
  key: string;
  value: string;
}

/**
 * The merged metadata item list: every EXISTING entry whose key is not in `updates` survives
 * verbatim and in place; an existing key that IS in `updates` takes the new value in place; any
 * update key not already present is appended, in request order. A plain list merge over arbitrary
 * keys — the policy of WHICH keys the platform may set is the validator's (GCP_METADATA_KEYS), not
 * this function's. Pure and exported for the unit tests — preserving unrelated keys is the invariant
 * the merge exists for.
 */
export function mergeMetadataItems(
  existing: Array<{ key?: string; value?: string }>,
  updates: ComputeMetadataItem[],
): ComputeMetadataItem[] {
  const updateByKey = new Map<string, string>();
  for (const update of updates) {
    updateByKey.set(update.key, update.value);
  }

  const merged: ComputeMetadataItem[] = [];
  const replacedKeys = new Set<string>();
  for (const entry of existing) {
    // Google never returns a keyless item; one is skipped rather than written back malformed.
    if (typeof entry.key !== "string" || entry.key.length === 0) {
      continue;
    }
    const replacement = updateByKey.get(entry.key);
    if (replacement !== undefined) {
      merged.push({ key: entry.key, value: replacement });
      replacedKeys.add(entry.key);
      continue;
    }
    merged.push({ key: entry.key, value: entry.value ?? "" });
  }
  for (const update of updates) {
    if (!replacedKeys.has(update.key)) {
      merged.push({ key: update.key, value: update.value });
    }
  }
  return merged;
}

// A metadata write completes in seconds; one operations.wait call (up to ~2 minutes) is ample, and
// like gcp-instance-create this feeds a sync endpoint, so the bound stays at one. An unconfirmed
// write is reported `unconfirmed` for the caller to re-run (idempotent), never assumed in place.
const INSTANCE_SET_METADATA_WAIT_ATTEMPTS = 1;

export async function actuateGcpInstanceSetMetadata(
  params: GcpInstanceSetMetadataParams,
  env: Env,
): Promise<GcpInstanceSetMetadataResult> {
  const { project, zone } = params;
  const instanceName = params.name;
  const failure = (detail: string): GcpInstanceSetMetadataResult => ({
    ok: false,
    op: "gcp-instance-set-metadata",
    instanceName,
    detail,
  });

  // Step 1 — substitute, before any credential is minted or any call is made. A refusal here has
  // zero side effects on the agency's project.
  const renderedAll = renderMetadataItems(params.items, env);
  if (!renderedAll.ok) {
    return failure(renderedAll.detail);
  }
  const { renderedItems, placeholdersSubstituted, placeholderValues } = renderedAll;

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const accessToken = token.accessToken;
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const zonePath =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/zones/${encodeURIComponent(zone)}`;
  const instanceUrl = `${zonePath}/instances/${encodeURIComponent(instanceName)}`;
  const what = `instance "${instanceName}"`;

  // Step 2 — read the current fingerprint + items.
  const current = await readComputeInstance({ url: instanceUrl, accessToken, what, project });
  if (!current.ok) {
    return failure(current.detail);
  }
  const fingerprint = current.instance.metadata?.fingerprint;
  if (typeof fingerprint !== "string" || fingerprint.length === 0) {
    // Without the fingerprint there is no concurrency guard, and an unguarded write is exactly the
    // clobber this op refuses to risk.
    return failure(`${what} returned no metadata fingerprint — refusing to write metadata without the concurrency guard.`);
  }
  // planning/47: the CALLER's read. A change made after the caller read the metadata (and showed the
  // operator a diff against it) is refused here, before anything is written — never merged over.
  const expectedFingerprintChecked = params.expectedFingerprint !== undefined;
  if (params.expectedFingerprint !== undefined && params.expectedFingerprint !== fingerprint) {
    return {
      ok: false,
      op: "gcp-instance-set-metadata",
      instanceName,
      detail:
        `the metadata of ${what} changed since the caller read it (expected fingerprint ${params.expectedFingerprint}, ` +
        `found ${fingerprint}) — nothing was written; read it again and decide against the current metadata.`,
      staleFingerprint: true,
    };
  }
  const existingItems = current.instance.metadata?.items ?? [];

  // What the read-back will compare against: the hash of each value AS WRITTEN, and which keys
  // already held exactly that value. Hashes and key names only — never a value.
  const valuesSha256: Record<string, string> = {};
  const unchangedKeys: string[] = [];
  for (const item of renderedItems) {
    valuesSha256[item.key] = await utf8Sha256Hex(item.value);
    const existingEntry = existingItems.find((entry) => entry.key === item.key);
    if (existingEntry !== undefined && existingEntry.value === item.value) {
      unchangedKeys.push(item.key);
    }
  }

  // Step 3 — merge (unrelated keys survive).
  const mergedItems = mergeMetadataItems(existingItems, renderedItems);

  // Step 4 — write back under the fingerprint we read, then confirm the operation.
  let response: Response;
  try {
    response = await fetch(`${instanceUrl}/setMetadata`, {
      method: "POST",
      headers: gcpHeaders(accessToken),
      body: JSON.stringify({ fingerprint, items: mergedItems }),
    });
  } catch (err) {
    // planning/47 review L1: a fetch that throws may have thrown AFTER the request reached Google, so
    // the write may be in place. UNKNOWN, never "nothing was written": re-read before deciding.
    return {
      ok: false,
      op: "gcp-instance-set-metadata",
      instanceName,
      detail: `the setMetadata call on ${what} failed in transit (${errorMessage(err)}): it may or may not have been written — read the instance before anything else.`,
      unconfirmed: true,
    };
  }
  const body = (await response.json().catch(() => null)) as ComputeInsertResponse | null;

  if (response.status === 412) {
    // Google's conditionNotMet: the metadata changed under us. Surface it discriminably; do NOT
    // re-read and re-write here — the caller decides whether to re-run against the new state.
    return {
      ok: false,
      op: "gcp-instance-set-metadata",
      instanceName,
      detail:
        `the metadata of ${what} changed between read and write (HTTP 412, stale fingerprint)${googleErrorMessage(body)} — ` +
        "nothing was written; re-run to merge against the current metadata.",
      staleFingerprint: true,
    };
  }
  if (response.status === 401 || response.status === 403) {
    return failure(
      `Google Cloud denied setting metadata on ${what} (HTTP ${response.status})${googleErrorMessage(body)} — the service account ` +
        `needs compute.instances.setMetadata (e.g. roles/compute.instanceAdmin.v1) on project "${project}".`,
    );
  }
  if (response.status >= 500) {
    // planning/47 review L1: Google's 5xx does not say the write did not happen.
    return {
      ok: false,
      op: "gcp-instance-set-metadata",
      instanceName,
      detail: `setting metadata on ${what} answered HTTP ${response.status}${googleErrorMessage(body)}: it may or may not have been written — read the instance before anything else.`,
      unconfirmed: true,
    };
  }
  if (!response.ok) {
    return failure(`setting metadata on ${what} failed with HTTP ${response.status}${googleErrorMessage(body)}.`);
  }

  // A 2xx must carry an Operation. Without one we cannot confirm the write was accepted — but Google
  // may well have accepted it, so this is `unconfirmed` (re-run converges), not an observed failure.
  const operationName = body?.name;
  if (!operationName) {
    return {
      ok: false,
      op: "gcp-instance-set-metadata",
      instanceName,
      detail: `Compute Engine returned HTTP ${response.status} but no operation — cannot confirm the metadata write on ${what} was accepted.`,
      unconfirmed: true,
    };
  }
  const waited = await waitForComputeOperation({
    waitUrl: `${zonePath}/operations/${encodeURIComponent(operationName)}/wait`,
    accessToken,
    what,
    maxAttempts: INSTANCE_SET_METADATA_WAIT_ATTEMPTS,
    verb: "metadata write",
  });
  if (!waited.ok && waited.completed) {
    return failure(waited.detail);
  }
  if (!waited.ok) {
    return { ok: false, op: "gcp-instance-set-metadata", instanceName, detail: waited.detail, unconfirmed: true };
  }

  return {
    ok: true,
    op: "gcp-instance-set-metadata",
    instanceName,
    keysSet: renderedItems.map((item) => item.key),
    placeholdersSubstituted,
    placeholderValues,
    valuesSha256,
    unchangedKeys,
    expectedFingerprintChecked,
    operationName,
  };
}

/** The sha256 of a string's UTF-8 bytes, as lowercase hex (what `sha256sum` prints for the same bytes). */
export async function utf8Sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// ── gcp-instance-restart ─────────────────────────────────────────────────────────────────────
// planning/47: a GRACEFUL restart of one cell VM in the agency's own project — instances.stop (an
// ACPI shutdown the guest honours: nfs-server stops, filesystems unmount cleanly) and then
// instances.start — so the VM boots on whatever startup script gcp-instance-set-metadata put in place.
// NOT instances.reset: that is a hard power cycle, and the first node this restarts is the cell's NFS
// FILE node. Each half is one Compute operation WAITED to DONE, which is Google's confirmation of the
// TERMINATED / RUNNING transition; the result reports which transitions were reached so a caller can
// tell "restarted" from "stopped but the start did not confirm".
//
// A VM already TERMINATED is only started (a re-run after an unconfirmed stop converges that way); a
// VM in any transitional state (STOPPING, STAGING, ...) is refused with "re-run once it settles" rather
// than raced.

// The stop WAITS for the guest to shut down (Google gives it ~90 s before forcing the stop), so its
// operation may outlast one ~2-minute wait call on a busy node — two calls bound it at ~4 minutes. A
// start's operation reaches DONE as soon as the VM is powered on (tens of seconds), so one call is
// ample. Both small and fixed, like gcp-instance-create's bound: this feeds a sync endpoint.
export const INSTANCE_RESTART_STOP_WAIT_ATTEMPTS = 2;
const INSTANCE_RESTART_START_WAIT_ATTEMPTS = 1;

/**
 * POST one instance lifecycle action (stop / start) and WAIT for its zonal operation. The same failure
 * vocabulary as deleteComputeResource, minus the 404-is-success rule (a vanished VM cannot be
 * restarted). `unconfirmed` is true ONLY when Google ACCEPTED the action but the wait could not confirm
 * DONE — the transition may still complete on its own.
 */
export async function runInstanceLifecycleOperation(input: {
  url: string;
  waitUrlBase: string;
  accessToken: string;
  what: string;
  verb: "stop" | "start";
  maxWaitAttempts: number;
  project: string;
  permissionHint: string;
}): Promise<{ ok: true; operationName: string } | { ok: false; detail: string; unconfirmed: boolean }> {
  const { url, waitUrlBase, accessToken, what, verb, maxWaitAttempts, project, permissionHint } = input;

  let response: Response;
  try {
    response = await fetch(url, { method: "POST", headers: gcpHeaders(accessToken) });
  } catch (err) {
    return { ok: false, detail: `could not reach Google Compute Engine to ${verb} ${what}: ${errorMessage(err)}`, unconfirmed: false };
  }
  const body = (await response.json().catch(() => null)) as ComputeInsertResponse | null;

  if (response.status === 404) {
    return { ok: false, detail: `${what} was not found in project "${project}" — nothing to ${verb}.`, unconfirmed: false };
  }
  if (response.status === 401 || response.status === 403) {
    return {
      ok: false,
      detail:
        `Google Cloud denied the ${what} ${verb} (HTTP ${response.status})${googleErrorMessage(body)} — the service account ` +
        `needs ${permissionHint} on project "${project}".`,
      unconfirmed: false,
    };
  }
  if (!response.ok) {
    return { ok: false, detail: `${what} ${verb} failed with HTTP ${response.status}${googleErrorMessage(body)}.`, unconfirmed: false };
  }

  // A 2xx must carry an Operation; without one the action may still have been accepted, so this is
  // unconfirmed rather than an observed failure (the same reasoning as deleteComputeResource).
  const operationName = body?.name;
  if (!operationName) {
    return {
      ok: false,
      detail: `Compute Engine returned HTTP ${response.status} but no operation — cannot confirm the ${what} ${verb} was accepted.`,
      unconfirmed: true,
    };
  }
  const operationErrors = body?.error?.errors ?? [];
  if (operationErrors.length > 0) {
    return {
      ok: false,
      detail: `${what} ${verb} operation ${operationName} failed: ${operationErrorMessages(operationErrors)}.`,
      unconfirmed: false,
    };
  }

  const waited = await waitForComputeOperation({
    waitUrl: `${waitUrlBase}/${encodeURIComponent(operationName)}/wait`,
    accessToken,
    what,
    maxAttempts: maxWaitAttempts,
    verb,
  });
  if (waited.ok) {
    return { ok: true, operationName };
  }
  return { ok: false, detail: waited.detail, unconfirmed: !waited.completed };
}

export async function actuateGcpInstanceRestart(
  params: GcpInstanceRestartParams,
  env: Env,
): Promise<GcpInstanceRestartResult> {
  const { project, zone } = params;
  const instanceName = params.name;

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return { ok: false, op: "gcp-instance-restart", instanceName, detail: token.detail, phase: "stop", stopped: false };
  }
  const accessToken = token.accessToken;
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const zonePath =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/zones/${encodeURIComponent(zone)}`;
  const instanceUrl = `${zonePath}/instances/${encodeURIComponent(instanceName)}`;
  const waitUrlBase = `${zonePath}/operations`;
  const what = `instance "${instanceName}"`;

  // Read the VM's state first so a TERMINATED VM is only started and a transitional one is refused.
  const current = await readComputeInstance({ url: instanceUrl, accessToken, what, project });
  if (!current.ok) {
    return { ok: false, op: "gcp-instance-restart", instanceName, detail: current.detail, phase: "stop", stopped: false };
  }
  const status = current.instance.status;

  let stopStatus: "stopped" | "already-stopped";
  let stopOperationName: string | undefined;
  if (status === "RUNNING") {
    const stop = await runInstanceLifecycleOperation({
      url: `${instanceUrl}/stop`,
      waitUrlBase,
      accessToken,
      what,
      verb: "stop",
      maxWaitAttempts: INSTANCE_RESTART_STOP_WAIT_ATTEMPTS,
      project,
      permissionHint: "compute.instances.stop (e.g. roles/compute.instanceAdmin.v1)",
    });
    if (!stop.ok) {
      const stopFailure: GcpInstanceRestartResult = {
        ok: false,
        op: "gcp-instance-restart",
        instanceName,
        detail: stop.detail,
        phase: "stop",
        stopped: false,
      };
      if (stop.unconfirmed) {
        stopFailure.unconfirmed = true;
      }
      return stopFailure;
    }
    stopStatus = "stopped";
    stopOperationName = stop.operationName;
  } else if (status === "TERMINATED") {
    stopStatus = "already-stopped";
  } else {
    return {
      ok: false,
      op: "gcp-instance-restart",
      instanceName,
      detail:
        `${what} is ${status ?? "in an unknown state"} — a restart needs it RUNNING (stop then start) or TERMINATED ` +
        "(start only); re-run once it settles.",
      phase: "stop",
      stopped: false,
    };
  }

  const start = await runInstanceLifecycleOperation({
    url: `${instanceUrl}/start`,
    waitUrlBase,
    accessToken,
    what,
    verb: "start",
    maxWaitAttempts: INSTANCE_RESTART_START_WAIT_ATTEMPTS,
    project,
    permissionHint: "compute.instances.start (e.g. roles/compute.instanceAdmin.v1)",
  });
  if (!start.ok) {
    // The VM IS stopped at this point (confirmed by the stop operation, or already so) — say so, since
    // "stopped and not coming back" is the state an operator must act on.
    const startFailure: GcpInstanceRestartResult = {
      ok: false,
      op: "gcp-instance-restart",
      instanceName,
      detail: start.detail,
      phase: "start",
      stopped: true,
    };
    if (start.unconfirmed) {
      startFailure.unconfirmed = true;
    }
    return startFailure;
  }

  const result: GcpInstanceRestartResult = {
    ok: true,
    op: "gcp-instance-restart",
    instanceName,
    stopStatus,
    startStatus: "started",
    startOperationName: start.operationName,
  };
  if (stopOperationName !== undefined) {
    result.stopOperationName = stopOperationName;
  }
  return result;
}

// ── planning/49: gcp-instance-get (READ a cell node's private IP) ─────────────────────────────
// The op Phase 1 exists for. `CellNode.privateIp` is NULL for every auto-provisioned cell, and no
// other op returns an address: gcp-instances-list parses only `name` and `zone`. A Cloud Run service
// on Direct VPC egress does not join the project's internal DNS, so an NFS mount target and a DB host
// must be IP LITERALS. Without this read there is nowhere to get them.
//
// The same read-only contract as gcp-firewall-get / gcp-router-get: the agency's OWN token, a 404 is
// a clean found:false (NOT a failure), and only auth, an unreachable API or an unexpected non-2xx is
// ok:false. Deliberately NOT built on readComputeInstance(). That helper treats a 404 as a failure,
// because its callers (set-metadata / restart) have nothing to update when the VM is gone.
//
// planning/47 adds the `metadata` facts to the same read (bootMetadataFactsOf): the fingerprint, and
// the startup-script's sha256, byte count and public bundle pin. A boot-script update reads them to
// show what it would replace, sends the fingerprint back as expectedFingerprint, and reads them again
// to prove the write. The script TEXT never leaves this Worker.

/** What instances.get answers with for THIS op (the fields it reads). */
interface ComputeInstanceAddressResponse {
  name?: string;
  status?: string;
  /** Each interface's `networkIP` is its in-VPC private IPv4, on `network` (a URL). A cell node has one. */
  networkInterfaces?: Array<{ networkIP?: string; network?: string; accessConfigs?: Array<{ natIP?: unknown }> }>;
  /** The accounts the VM runs as; absent when it runs as none. */
  serviceAccounts?: unknown;
  /** planning/47: read for InstanceBootMetadataFacts only (fingerprint + the startup-script's facts). */
  metadata?: { fingerprint?: unknown; items?: unknown };
  /** planning/47 review N1: when the VM last started (RFC 3339), checked by rfc3339TimestampOf. */
  lastStartTimestamp?: unknown;
  error?: ComputeInsertResponse["error"];
}

/** An RFC 3339 date-time as Google writes one: `2026-10-17T03:05:12.345-07:00` (or a `Z` offset). */
const RFC3339_TIMESTAMP_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$/;

/**
 * planning/47 review N1: a timestamp field passed through ONLY when it is an RFC 3339 date-time that
 * parses as a date, else null. A value this op cannot read is never passed through, so the caller fails
 * closed. PURE and exported for the unit tests.
 */
export function rfc3339TimestampOf(value: unknown): string | null {
  if (typeof value !== "string" || !RFC3339_TIMESTAMP_RE.test(value)) {
    return null;
  }
  if (Number.isNaN(Date.parse(value))) {
    return null;
  }
  return value;
}

/** planning/47 review L7: the metadata keys besides `startup-script` that run code at boot or stop. */
export const BOOT_TIME_METADATA_KEYS = ["startup-script-url", "user-data", "shutdown-script", "shutdown-script-url"] as const;

/** The platform's injected bundle lines (orchestrator cell-bootstrap.ts renders `readonly KEY='value'`). */
const BOOT_BUNDLE_URL_LINE_RE = /^readonly DY_BUNDLE_URL='(https:\/\/[A-Za-z0-9.-]{1,253}\/[A-Za-z0-9._/-]{1,200})'$/gm;
const BOOT_BUNDLE_SHA256_LINE_RE = /^readonly DY_BUNDLE_SHA256='([a-f0-9]{64})'$/gm;

/** The ONE capture of `pattern` in `text`, or null when it matches zero times or more than once. */
function singleLineCapture(text: string, pattern: RegExp): string | null {
  const matches = [...text.matchAll(pattern)];
  if (matches.length !== 1) {
    return null;
  }
  return (matches[0] as RegExpMatchArray)[1] ?? null;
}

/**
 * planning/47: the non-secret facts of an instance's metadata (see InstanceBootMetadataFacts). PURE
 * apart from hashing, and exported for the unit tests. An items list of an unexpected shape reports
 * no startup-script rather than a guess; a non-string value of the key is treated the same way.
 */
export async function bootMetadataFactsOf(metadata: { fingerprint?: unknown; items?: unknown } | undefined): Promise<InstanceBootMetadataFacts> {
  let fingerprint: string | null = null;
  if (typeof metadata?.fingerprint === "string" && metadata.fingerprint.length > 0) {
    fingerprint = metadata.fingerprint;
  }
  const items = Array.isArray(metadata?.items) ? (metadata?.items as unknown[]) : [];
  let scriptText: string | null = null;
  const otherBootKeys: string[] = [];
  for (const item of items) {
    if (item === null || typeof item !== "object") {
      continue;
    }
    const entry = item as { key?: unknown; value?: unknown };
    if (typeof entry.key === "string" && (BOOT_TIME_METADATA_KEYS as readonly string[]).includes(entry.key) && !otherBootKeys.includes(entry.key)) {
      otherBootKeys.push(entry.key);
    }
    if (scriptText === null && entry.key === "startup-script" && typeof entry.value === "string") {
      scriptText = entry.value;
    }
  }
  if (scriptText === null) {
    return { fingerprint, otherBootKeys, startupScript: null };
  }
  return {
    fingerprint,
    otherBootKeys,
    startupScript: {
      sha256: await utf8Sha256Hex(scriptText),
      bytes: new TextEncoder().encode(scriptText).length,
      bundleUrl: singleLineCapture(scriptText, BOOT_BUNDLE_URL_LINE_RE),
      bundleSha256: singleLineCapture(scriptText, BOOT_BUNDLE_SHA256_LINE_RE),
    },
  };
}

/** A service-account e-mail as Google reports one (e.g. 123-compute@developer.gserviceaccount.com). */
const SERVICE_ACCOUNT_EMAIL_RE = /^[a-z0-9][a-z0-9._-]{0,99}@[a-z0-9][a-z0-9.-]{0,199}[a-z]$/;

/**
 * The e-mails of an instance's `serviceAccounts[]`: [] when the field is absent (the VM runs as no
 * account), null when it is present in any shape this code does not understand. FAIL CLOSED: a null is
 * never read as "none". PURE and exported for gcp-instance-remove-service-account and the unit tests.
 */
export function serviceAccountEmailsOf(value: unknown): string[] | null {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    return null;
  }
  const emails: string[] = [];
  for (const entry of value) {
    if (entry === null || typeof entry !== "object") {
      return null;
    }
    const email = (entry as { email?: unknown }).email;
    if (typeof email !== "string" || !SERVICE_ACCOUNT_EMAIL_RE.test(email)) {
      return null;
    }
    emails.push(email);
  }
  return emails;
}

/**
 * The first interface with a non-empty `networkIP`: its address and the SHORT name of its network
 * (the last segment of Google's network URL). Both null when there is none.
 */
function firstInterfaceAddress(body: ComputeInstanceAddressResponse | null): { address: string | null; network: string | null } {
  if (!body || !Array.isArray(body.networkInterfaces)) {
    return { address: null, network: null };
  }
  for (const networkInterface of body.networkInterfaces) {
    const address = networkInterface?.networkIP;
    if (typeof address !== "string" || address.length === 0) {
      continue;
    }
    let network: string | null = null;
    const networkUrl = networkInterface?.network;
    if (typeof networkUrl === "string" && networkUrl.length > 0) {
      const lastSegment = networkUrl.slice(networkUrl.lastIndexOf("/") + 1);
      if (lastSegment.length > 0) {
        network = lastSegment;
      }
    }
    return { address, network };
  }
  return { address: null, network: null };
}

export async function readComputeInstanceAddress(params: GcpInstanceGetParams, env: Env): Promise<GcpInstanceGetResult> {
  const { project, zone } = params;
  const instanceName = params.name;
  const failure = (detail: string): GcpInstanceGetResult => ({ ok: false, op: "gcp-instance-get", instanceName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const url =
    `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}` +
    `/zones/${encodeURIComponent(zone)}/instances/${encodeURIComponent(instanceName)}`;

  let response: Response;
  try {
    response = await fetch(url, { headers: gcpHeaders(token.accessToken) });
  } catch (err) {
    return failure(`could not reach Google Compute Engine to read instance "${instanceName}": ${errorMessage(err)}`);
  }
  const body = (await response.json().catch(() => null)) as ComputeInstanceAddressResponse | null;

  if (response.status === 404) {
    return {
      ok: true,
      op: "gcp-instance-get",
      instanceName,
      found: false,
      privateIp: null,
      network: null,
      status: null,
      serviceAccounts: null,
      metadata: null,
      externalIp: null,
      lastStartTimestamp: null,
    };
  }
  if (response.status === 401 || response.status === 403) {
    return failure(
      `Google Cloud denied reading instance "${instanceName}" (HTTP ${response.status})${googleErrorMessage(body)} — the ` +
        `service account needs compute.instances.get (e.g. roles/compute.viewer) on project "${project}".`,
    );
  }
  if (!response.ok) {
    return failure(`reading instance "${instanceName}" failed with HTTP ${response.status}${googleErrorMessage(body)}.`);
  }

  // A cell node has exactly one interface (cell-provision attaches one). An instance with none gives
  // null, not an empty string, so a caller can tell "no address reported" from a blank address.
  let status: string | null = null;
  if (typeof body?.status === "string" && body.status.length > 0) {
    status = body.status;
  }
  const firstInterface = firstInterfaceAddress(body);
  return {
    ok: true,
    op: "gcp-instance-get",
    instanceName,
    found: true,
    privateIp: firstInterface.address,
    network: firstInterface.network,
    status,
    serviceAccounts: serviceAccountEmailsOf(body?.serviceAccounts),
    metadata: await bootMetadataFactsOf(body?.metadata),
    externalIp: firstInterfaceExternalIp(body),
    lastStartTimestamp: rfc3339TimestampOf(body?.lastStartTimestamp),
  };
}

const IPV4_RE = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;

/** The first interface's first access config's natIP when it is an IPv4 address, else null. PURE. */
export function firstInterfaceExternalIp(body: ComputeInstanceAddressResponse | null): string | null {
  const firstInterface = Array.isArray(body?.networkInterfaces) ? body?.networkInterfaces[0] : undefined;
  const accessConfig = Array.isArray(firstInterface?.accessConfigs) ? firstInterface?.accessConfigs[0] : undefined;
  const natIp = accessConfig?.natIP;
  if (typeof natIp === "string" && IPV4_RE.test(natIp)) {
    return natIp;
  }
  return null;
}

// ── planning/49 Phase 2 + hub#93: gcp-subnet-create / -get / -delete / gcp-subnets-list ─────────
// A SECOND subnet (or, per site, a THIRD and more) on a cell's EXISTING VPC: the ranges the Cloud Run
// services take their Direct-VPC-egress addresses from (planning/49 §4.1). gcp-network-create stays the
// "build the VPC" op. The names this touches are PINNED upstream (dispatch-params.ts): the probe form
// names exactly `dy-cell-<region>-run`; the SITE form (hub#93) names nothing, or (planning/49 Phase 3)
// the cell's registry network + `<prefix><NNN>` subnet for its slot. The range and the description are
// always derived here from the validated slot and slug, by the twin's own helpers, and every site-form
// read-back checks the subnet's network too.

/** What subnetworks.get / .list answer with (the fields these ops read). */
interface ComputeSubnetworkResponse {
  name?: string;
  ipCidrRange?: string;
  description?: string;
  /** The network's URL, e.g. ".../global/networks/dy-cell-australia-southeast2". */
  network?: string;
  error?: ComputeInsertResponse["error"];
}

/** The outcome of reading one subnet: present, absent (404), or a read failure. */
type ComputeSubnetReadOutcome =
  | { kind: "found"; subnet: ComputeSubnetworkResponse }
  | { kind: "absent" }
  | { kind: "failed"; detail: string };

/** The `projects/<p>/regions/<r>` URL prefix for a validated project + region. */
function computeRegionPath(project: string, region: string): string {
  return `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}/regions/${encodeURIComponent(region)}`;
}

/**
 * GET one subnet. A 404 is "absent". Any other non-2xx (and an unreachable API) is a failure with
 * Google's own message. Shared by gcp-subnet-get, the site-form create and delete, and the session
 * upsert's subnet bind.
 */
async function readComputeSubnetRaw(input: {
  project: string;
  region: string;
  subnetName: string;
  accessToken: string;
}): Promise<ComputeSubnetReadOutcome> {
  const { project, region, subnetName, accessToken } = input;
  const url = `${computeRegionPath(project, region)}/subnetworks/${encodeURIComponent(subnetName)}`;

  let response: Response;
  try {
    response = await fetch(url, { headers: gcpHeaders(accessToken) });
  } catch (err) {
    return { kind: "failed", detail: `could not reach Google Compute Engine to read subnetwork "${subnetName}": ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as ComputeSubnetworkResponse | null;

  if (response.status === 404) {
    return { kind: "absent" };
  }
  if (response.status === 401 || response.status === 403) {
    return {
      kind: "failed",
      detail:
        `Google Cloud denied reading subnetwork "${subnetName}" (HTTP ${response.status})${googleErrorMessage(body)} — the ` +
        `service account needs compute.subnetworks.get (e.g. roles/compute.viewer) on project "${project}".`,
    };
  }
  if (!response.ok || body === null) {
    return { kind: "failed", detail: `reading subnetwork "${subnetName}" failed with HTTP ${response.status}${googleErrorMessage(body)}.` };
  }
  return { kind: "found", subnet: body };
}

/** A non-empty string field of a Google body, or null. */
function nonEmptyStringOrNull(value: unknown): string | null {
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  return null;
}

/** The short last segment of a Compute resource URL (".../networks/dy-cell-x" -> "dy-cell-x"), or null. */
function lastUrlSegment(url: unknown): string | null {
  if (typeof url !== "string" || url.length === 0) {
    return null;
  }
  const last = url.slice(url.lastIndexOf("/") + 1);
  if (last.length === 0) {
    return null;
  }
  return last;
}

/** What a site subnet must look like on read-back: its name and network, and the derived range and description. */
interface ExpectedSiteSubnet {
  subnetName: string;
  /** The SHORT network name the subnet must be on (the last segment of its `network` URL). */
  networkName: string;
  ipCidrRange: string;
  description: string;
}

/**
 * The names, range and description of a validated site-form ref: the job's registry names when it sent
 * them, else the saga names (planning/49 Phase 3); the range and description are always derived (hub#93 §1).
 */
function expectedSiteSubnet(params: GcpSiteSubnetRef): ExpectedSiteSubnet {
  return {
    subnetName: siteSubnetRefSubnetName(params),
    networkName: siteSubnetRefNetworkName(params),
    ipCidrRange: siteRunSubnetCidrForSlot(params.slot),
    description: siteSubnetDescriptionFor(params.siteSlug),
  };
}

/** True when a read-back subnet is on the expected network (compared by the last segment of its URL). */
function subnetIsOnNetwork(subnet: ComputeSubnetworkResponse, networkName: string): boolean {
  return lastUrlSegment(subnet.network) === networkName;
}

/** True when a read-back subnet is on the expected network and carries EXACTLY the expected range and description. */
function siteSubnetMatches(subnet: ComputeSubnetworkResponse, expected: ExpectedSiteSubnet): boolean {
  if (!subnetIsOnNetwork(subnet, expected.networkName)) {
    return false;
  }
  return subnet.ipCidrRange === expected.ipCidrRange && subnet.description === expected.description;
}

/** The echo every SITE-form result carries: the network and subnet this Worker used. */
function siteSubnetEcho(expected: ExpectedSiteSubnet): { network: string; subnet: string } {
  return { network: expected.networkName, subnet: expected.subnetName };
}

export async function actuateGcpSubnetCreate(params: GcpSubnetCreateParams, env: Env): Promise<GcpSubnetCreateResult> {
  if (isGcpSiteSubnetRef(params)) {
    return actuateGcpSiteSubnetCreate(params, env);
  }
  const { project, region, subnetName } = params;
  const failure = (detail: string): GcpSubnetCreateResult => ({ ok: false, op: "gcp-subnet-create", subnetName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const accessToken = token.accessToken;
  // Path segments are grammar-checked upstream AND URL-encoded here.
  const regionPath = computeRegionPath(project, region);

  const outcome = await insertComputeResource({
    url: `${regionPath}/subnetworks`,
    accessToken,
    // Project-relative references, like gcp-network-create's. Never a caller-supplied URL.
    body: {
      name: subnetName,
      network: `global/networks/${params.networkName}`,
      ipCidrRange: params.ipCidr,
      region: `regions/${region}`,
    },
    what: `subnetwork "${subnetName}"`,
    project,
    permissionHint: "compute.subnetworks.create (e.g. roles/compute.networkAdmin)",
  });
  if (outcome.kind === "failed") {
    return failure(outcome.detail);
  }
  // WAIT for a create, so "created" means the subnet EXISTS and a Cloud Run deploy cannot race it.
  if (outcome.kind === "created") {
    const waited = await waitForComputeOperation({
      waitUrl: `${regionPath}/operations/${encodeURIComponent(outcome.operationName)}/wait`,
      accessToken,
      what: `subnetwork "${subnetName}"`,
    });
    if (!waited.ok) {
      return failure(waited.detail);
    }
  }
  return { ok: true, op: "gcp-subnet-create", subnetName, status: outcome.kind };
}

/**
 * The SITE form of gcp-subnet-create (hub#93 §2). Creates the site's subnet (the registry name, else
 * `dy-cell-<region>-run-s<NNN>`) on the cell's own network (the registry name, else `dy-cell-<region>`)
 * with the range derived from the slot and the description `doubleyoup site subnet: <slug>` — the only
 * moment the description can be set (Google refuses to patch it later, hub#93 G4). A 409 is success
 * ONLY after a read-back finds it on that network with the derived range AND this site's description;
 * anything else is a conflict and the subnet is left exactly as it is. Every failure says whether it is
 * DEFINITE, so the platform releases a slot only when no subnet can have been made (M5).
 */
async function actuateGcpSiteSubnetCreate(params: GcpSiteSubnetRef, env: Env): Promise<GcpSubnetCreateResult> {
  const { project, region } = params;
  const expected = expectedSiteSubnet(params);
  const subnetName = expected.subnetName;
  const echo = siteSubnetEcho(expected);
  const what = `subnetwork "${subnetName}"`;
  const failure = (detail: string, outcome: GcpSiteSubnetCreateOutcome): GcpSubnetCreateResult => ({
    ok: false,
    op: "gcp-subnet-create",
    subnetName,
    detail,
    outcome,
    ...echo,
  });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    // Nothing was sent to Google, so no subnet can have been made.
    return failure(token.detail, "refused");
  }
  const accessToken = token.accessToken;
  const regionPath = computeRegionPath(project, region);

  const inserted = await insertComputeResource({
    url: `${regionPath}/subnetworks`,
    accessToken,
    // Project-relative references, and names the twin grammar-checked and app bound to the registry.
    // The range and the description are always DERIVED, never a caller-supplied value.
    body: {
      name: subnetName,
      network: `global/networks/${expected.networkName}`,
      ipCidrRange: expected.ipCidrRange,
      region: `regions/${region}`,
      description: expected.description,
    },
    what,
    project,
    permissionHint: "compute.subnetworks.create (e.g. roles/compute.networkAdmin)",
  });
  if (inserted.kind === "failed") {
    if (inserted.definite) {
      return failure(inserted.detail, "refused");
    }
    return failure(`${inserted.detail} The subnet may still be created: read it back before releasing its slot.`, "unknown");
  }

  if (inserted.kind === "created") {
    const waited = await waitForComputeOperation({
      waitUrl: `${regionPath}/operations/${encodeURIComponent(inserted.operationName)}/wait`,
      accessToken,
      what,
    });
    if (waited.ok) {
      return { ok: true, op: "gcp-subnet-create", subnetName, status: "created", ...echo };
    }
    // completed:true = the operation FINISHED with errors: an observed failure, no subnet.
    // completed:false = the outcome could not be observed: the subnet may still appear.
    if (waited.completed) {
      return failure(waited.detail, "refused");
    }
    return failure(`${waited.detail} The subnet may still be created: read it back before releasing its slot.`, "unknown");
  }

  // 409: a subnet of this name exists. Adopt it ONLY if it is exactly this site's subnet.
  const existing = await readComputeSubnetRaw({ project, region, subnetName, accessToken });
  if (existing.kind === "failed") {
    return failure(`${what} already exists, but reading it back failed: ${existing.detail}`, "unknown");
  }
  if (existing.kind === "absent") {
    // Gone between the 409 and the read (another delete raced this create). Nothing is ours to report.
    return failure(`${what} was reported as existing but is not present on read-back — re-run to resume.`, "unknown");
  }
  if (!siteSubnetMatches(existing.subnet, expected)) {
    const foundNetwork = lastUrlSegment(existing.subnet.network) ?? "(none)";
    const foundRange = nonEmptyStringOrNull(existing.subnet.ipCidrRange) ?? "(none)";
    const foundDescription = nonEmptyStringOrNull(existing.subnet.description) ?? "(none)";
    return failure(
      `${what} already exists on network ${foundNetwork} with range ${foundRange} and description "${foundDescription}", ` +
        `not ${expected.networkName}, ${expected.ipCidrRange} and "${expected.description}". It is not this site's subnet ` +
        "and was left unchanged.",
      "conflict",
    );
  }
  return { ok: true, op: "gcp-subnet-create", subnetName, status: "already-existed", ...echo };
}

export async function readComputeSubnet(params: GcpSubnetGetParams, env: Env): Promise<GcpSubnetGetResult> {
  if (isGcpSiteSubnetRef(params)) {
    return readComputeSiteSubnet(params, env);
  }
  const { project, region, subnetName } = params;
  const failure = (detail: string): GcpSubnetGetResult => ({ ok: false, op: "gcp-subnet-get", subnetName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const read = await readComputeSubnetRaw({ project, region, subnetName, accessToken: token.accessToken });
  if (read.kind === "failed") {
    return failure(read.detail);
  }
  if (read.kind === "absent") {
    return { ok: true, op: "gcp-subnet-get", subnetName, found: false, ipCidrRange: null };
  }
  return { ok: true, op: "gcp-subnet-get", subnetName, found: true, ipCidrRange: nonEmptyStringOrNull(read.subnet.ipCidrRange) };
}

/**
 * The SITE form of gcp-subnet-get (hub#93): read the site's subnet and say whether it is exactly this
 * site's — on the network asked for, with the derived range AND the site's own description. The
 * platform's slot reconcile keys on `matchesSite` after an unknown create outcome (M5): found and
 * matching -> confirmed; not found -> the slot may be released.
 */
async function readComputeSiteSubnet(params: GcpSiteSubnetRef, env: Env): Promise<GcpSubnetGetResult> {
  const { project, region } = params;
  const expected = expectedSiteSubnet(params);
  const subnetName = expected.subnetName;
  const echo = siteSubnetEcho(expected);

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return { ok: false, op: "gcp-subnet-get", subnetName, detail: token.detail, ...echo };
  }
  const read = await readComputeSubnetRaw({ project, region, subnetName, accessToken: token.accessToken });
  if (read.kind === "failed") {
    return { ok: false, op: "gcp-subnet-get", subnetName, detail: read.detail, ...echo };
  }
  if (read.kind === "absent") {
    return {
      ok: true,
      op: "gcp-subnet-get",
      subnetName,
      found: false,
      ipCidrRange: null,
      description: null,
      slot: params.slot,
      siteSlug: params.siteSlug,
      matchesSite: false,
      ...echo,
    };
  }
  return {
    ok: true,
    op: "gcp-subnet-get",
    subnetName,
    found: true,
    ipCidrRange: nonEmptyStringOrNull(read.subnet.ipCidrRange),
    description: nonEmptyStringOrNull(read.subnet.description),
    slot: params.slot,
    siteSlug: params.siteSlug,
    matchesSite: siteSubnetMatches(read.subnet, expected),
    ...echo,
  };
}

export async function actuateGcpSubnetDelete(params: GcpSubnetDeleteParams, env: Env): Promise<GcpSubnetDeleteResult> {
  let subnetName: string;
  let siteExpected: ExpectedSiteSubnet | null = null;
  // The SITE form echoes the names it used on every result (planning/49 Phase 3). The probe form does not.
  let echo: { network?: string; subnet?: string } = {};
  if (isGcpSiteSubnetRef(params)) {
    siteExpected = expectedSiteSubnet(params);
    subnetName = siteExpected.subnetName;
    echo = siteSubnetEcho(siteExpected);
  } else {
    subnetName = params.subnetName;
  }
  const { project, region } = params;

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return { ok: false, op: "gcp-subnet-delete", subnetName, detail: token.detail, inUse: false, ...echo };
  }
  const regionPath = computeRegionPath(project, region);

  // SITE form: read first, and delete ONLY a subnet on the network asked for whose description names
  // THIS site exactly (hub#93 §2). A subnet of that name that some other process made, one on another
  // network, or another site's, is left alone.
  if (siteExpected !== null) {
    const existing = await readComputeSubnetRaw({ project, region, subnetName, accessToken: token.accessToken });
    if (existing.kind === "failed") {
      return { ok: false, op: "gcp-subnet-delete", subnetName, detail: existing.detail, inUse: false, ...echo };
    }
    if (existing.kind === "absent") {
      return { ok: true, op: "gcp-subnet-delete", subnetName, status: "already-absent", ...echo };
    }
    if (!subnetIsOnNetwork(existing.subnet, siteExpected.networkName)) {
      const foundNetwork = lastUrlSegment(existing.subnet.network) ?? "(none)";
      return {
        ok: false,
        op: "gcp-subnet-delete",
        subnetName,
        detail:
          `subnetwork "${subnetName}" is on the network "${foundNetwork}", not "${siteExpected.networkName}", so it is ` +
          "not this site's subnet. It was left in place.",
        inUse: false,
        foreign: true,
        ...echo,
      };
    }
    if (existing.subnet.description !== siteExpected.description) {
      const foundDescription = nonEmptyStringOrNull(existing.subnet.description) ?? "(none)";
      return {
        ok: false,
        op: "gcp-subnet-delete",
        subnetName,
        detail:
          `subnetwork "${subnetName}" has the description "${foundDescription}", not "${siteExpected.description}", so it is ` +
          "not this site's subnet. It was left in place.",
        inUse: false,
        foreign: true,
        ...echo,
      };
    }
  }

  // The shared delete: a 404 is SUCCESS ("already-absent"), and the delete is WAITED to DONE, so the
  // network delete that runs next can assume this subnet is really gone.
  const outcome = await deleteComputeResource({
    url: `${regionPath}/subnetworks/${encodeURIComponent(subnetName)}`,
    waitUrlBase: `${regionPath}/operations`,
    accessToken: token.accessToken,
    what: `subnetwork "${subnetName}"`,
    project,
    permissionHint: "compute.subnetworks.delete (e.g. roles/compute.networkAdmin)",
  });
  if (outcome.kind === "failed") {
    let detail = outcome.detail;
    const inUse = outcome.inUse === true;
    if (inUse) {
      detail +=
        " Cloud Run Direct VPC egress can hold addresses on this subnet for a while after its last service is " +
        "deleted. Re-run later; nothing else was changed.";
    }
    return { ok: false, op: "gcp-subnet-delete", subnetName, detail, inUse, ...echo };
  }
  return { ok: true, op: "gcp-subnet-delete", subnetName, status: outcome.kind, ...echo };
}

// ── hub#93: gcp-subnets-list ─────────────────────────────────────────────────────────────────
// READ-ONLY: every subnet in the cell's region whose name starts with the per-site prefix (the saga's
// `dy-cell-<region>-run-s`, or the job's registry `subnetPrefix`, planning/49 Phase 3) — the per-site Run
// subnets, orphans included — so the cell teardown can delete each one BEFORE any VM without 128 reads.
// With the registry pair, a subnet on any network other than the job's `network` is left out. Every page
// is read; an incomplete read is ok:false, never a short list.

/** Google's max page size for subnetworks.list, and a page bound (128 slots fit in one page). */
const GCP_SUBNETWORKS_LIST_PAGE_SIZE = 500;
const GCP_SUBNETWORKS_LIST_MAX_PAGES = 10;

/** What subnetworks.list answers with (the fields this op reads). */
interface ComputeSubnetworkListResponse {
  items?: ComputeSubnetworkResponse[];
  nextPageToken?: string;
  error?: ComputeInsertResponse["error"];
}

export async function readComputeSubnetsList(params: GcpSubnetsListParams, env: Env): Promise<GcpSubnetsListResult> {
  const { project, region } = params;
  const namePrefix = subnetsListNamePrefix(params);
  // The network filter: the job's registry network, or none (the saga form lists by name only, as before).
  const networkFilter = params.network ?? null;
  const echo = { subnetPrefix: namePrefix, network: networkFilter };
  const failure = (detail: string): GcpSubnetsListResult => ({ ok: false, op: "gcp-subnets-list", ...echo, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }

  const subnets: GcpSiteSubnetListEntry[] = [];
  let pageToken: string | undefined;
  for (let page = 1; page <= GCP_SUBNETWORKS_LIST_MAX_PAGES; page += 1) {
    // Server-side name filter in Compute Engine's regex form, `name eq <RE2>` matching the WHOLE name.
    // The prefix is derived from a grammar-checked region, or is a grammar-checked registry prefix
    // ([-a-z0-9] only either way), so it carries no regex metacharacter, and it goes through
    // URLSearchParams. The prefix (and the network, with the pair) is re-checked on every entry below.
    const query = new URLSearchParams();
    query.set("filter", `name eq "${namePrefix}.*"`);
    query.set("maxResults", String(GCP_SUBNETWORKS_LIST_PAGE_SIZE));
    if (pageToken !== undefined) {
      query.set("pageToken", pageToken);
    }
    const url = `${computeRegionPath(project, region)}/subnetworks?${query.toString()}`;

    let response: Response;
    try {
      response = await fetch(url, { headers: gcpHeaders(token.accessToken) });
    } catch (err) {
      return failure(`could not reach Google Compute Engine to list subnetworks in "${region}": ${errorMessage(err)}`);
    }
    const body = (await response.json().catch(() => null)) as ComputeSubnetworkListResponse | null;

    if (response.status === 401 || response.status === 403) {
      return failure(
        `Google Cloud denied listing subnetworks (HTTP ${response.status})${googleErrorMessage(body)} — the service account ` +
          `needs compute.subnetworks.list (e.g. roles/compute.viewer) on project "${project}".`,
      );
    }
    if (!response.ok || body === null) {
      return failure(`listing subnetworks failed with HTTP ${response.status}${googleErrorMessage(body)}.`);
    }
    if (body.error) {
      return failure(`listing subnetworks returned a body-level error${googleErrorMessage(body)} — incomplete; re-run to resume`);
    }

    for (const subnet of body.items ?? []) {
      const name = subnet?.name;
      if (typeof name !== "string" || !name.startsWith(namePrefix)) {
        continue;
      }
      if (networkFilter !== null && !subnetIsOnNetwork(subnet, networkFilter)) {
        continue;
      }
      subnets.push({
        name,
        slot: siteRunSlotFromPrefixedSubnetName(namePrefix, name),
        ipCidrRange: nonEmptyStringOrNull(subnet.ipCidrRange),
        description: nonEmptyStringOrNull(subnet.description),
        siteSlug: siteSlugFromSubnetDescription(subnet.description),
        network: lastUrlSegment(subnet.network),
      });
    }

    if (!body.nextPageToken) {
      return { ok: true, op: "gcp-subnets-list", ...echo, subnets };
    }
    pageToken = body.nextPageToken;
  }

  return failure(
    `listing subnetworks did not finish within ${GCP_SUBNETWORKS_LIST_MAX_PAGES} pages — the list is incomplete; re-run to resume`,
  );
}

// ── hub#93: gcp-project-quota-get ─────────────────────────────────────────────────────────────
// READ-ONLY: the project's live SUBNETWORKS usage and limit, from Compute `projects.get` `quotas[]`. The
// platform's Run slot allocator refuses a new slot when usage + pending + 1 would exceed the limit, so a
// wrong number here is either a refused slot or a subnet create that fails on quota after the slot is
// taken. That is why every doubtful answer is ok:false rather than a best guess.

/** One `quotas[]` entry as Compute `projects.get` answers it (the fields this op reads). */
interface ComputeQuotaEntry {
  metric?: unknown;
  limit?: unknown;
  usage?: unknown;
}

/** What Compute `projects.get` answers with (the fields this op reads). */
interface ComputeProjectResponse {
  quotas?: unknown;
  error?: ComputeInsertResponse["error"];
}

/** True when `value` is a whole number of at least 0 — the only shape a subnet count or limit can have. */
function isWholeQuotaFigure(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

export async function readComputeProjectSubnetQuota(params: GcpProjectQuotaGetParams, env: Env): Promise<GcpProjectQuotaGetResult> {
  const { project } = params;
  const failure = (detail: string): GcpProjectQuotaGetResult => ({ ok: false, op: "gcp-project-quota-get", project, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const url = `${GCP_COMPUTE_API}/projects/${encodeURIComponent(project)}`;

  let response: Response;
  try {
    response = await fetch(url, { headers: gcpHeaders(token.accessToken) });
  } catch (err) {
    return failure(`could not reach Google Compute Engine to read project "${project}": ${errorMessage(err)}`);
  }
  const body = (await response.json().catch(() => null)) as ComputeProjectResponse | null;

  if (response.status === 401 || response.status === 403) {
    return failure(
      `Google Cloud denied reading project "${project}" (HTTP ${response.status})${googleErrorMessage(body)} — the service ` +
        `account needs compute.projects.get (e.g. roles/compute.viewer) on project "${project}".`,
    );
  }
  if (!response.ok || body === null) {
    return failure(`reading project "${project}" failed with HTTP ${response.status}${googleErrorMessage(body)}.`);
  }
  if (body.error) {
    return failure(`reading project "${project}" returned a body-level error${googleErrorMessage(body)}.`);
  }
  if (!Array.isArray(body.quotas)) {
    return failure(`project "${project}" answered without a quotas list, so its ${GCP_PROJECT_QUOTA_METRIC} usage is unknown.`);
  }

  const matching: ComputeQuotaEntry[] = [];
  for (const entry of body.quotas as unknown[]) {
    if (typeof entry !== "object" || entry === null) {
      continue;
    }
    const quota = entry as ComputeQuotaEntry;
    if (quota.metric === GCP_PROJECT_QUOTA_METRIC) {
      matching.push(quota);
    }
  }
  if (matching.length !== 1) {
    return failure(
      `project "${project}" lists ${matching.length} ${GCP_PROJECT_QUOTA_METRIC} quota entries, not exactly one, so its ` +
        "subnet usage cannot be read safely.",
    );
  }
  const { usage, limit } = matching[0];
  if (!isWholeQuotaFigure(usage) || !isWholeQuotaFigure(limit)) {
    return failure(
      `project "${project}"'s ${GCP_PROJECT_QUOTA_METRIC} quota entry does not carry a whole-number usage and limit, so ` +
        "its subnet usage cannot be read safely.",
    );
  }
  return { ok: true, op: "gcp-project-quota-get", project, metric: GCP_PROJECT_QUOTA_METRIC, usage, limit };
}

// ── planning/49 Phase 2: the Cloud Run ops ────────────────────────────────────────────────────
// ONE Cloud Run (v2) service in the AGENCY's own project, on the cell's own VPC, with the same agency
// GCP_SERVICE_ACCOUNT_KEY every gcp-* op uses. No platform credential is here either.
//
// FIXED IN PLACE, never taken from a job (planning/49 §4.3): ingress, VPC egress, gen2, the port, the
// request timeout, minInstances, the managed-by label, invoker IAM ON, and the probe's command and
// program. NO IAM policy is ever WRITTEN here, so there is no path to an allUsers binding. The one IAM
// call is a READ (getIamPolicy) that refuses to update a service with a public binding (review M1).

const GCP_CLOUD_RUN_API = "https://run.googleapis.com/v2";
/** Cloud Run runs every container on this port. Fixed policy, not a job parameter. */
const CLOUD_RUN_CONTAINER_PORT = 8080;
/** A session may be a long-lived shell or WebSocket. 3600s is Cloud Run's own ceiling. */
const CLOUD_RUN_REQUEST_TIMEOUT = "3600s";
/** Scale to zero when idle — the whole point of an EPHEMERAL tier. */
const CLOUD_RUN_MIN_INSTANCES = 0;
/** How long ONE operations wait call blocks, and how many are made before the op gives up. */
const CLOUD_RUN_OPERATION_WAIT_TIMEOUT = "60s";
const CLOUD_RUN_OPERATION_WAIT_ATTEMPTS = 3;
/**
 * The label every service this platform creates carries (review M1). PATCH and DELETE require it, so
 * a same-named service that someone else made is never taken over or removed.
 */
const CLOUD_RUN_MANAGED_BY_LABEL_KEY = "managed-by";
const CLOUD_RUN_MANAGED_BY_LABEL_VALUE = "doubleyoup";
/**
 * planning/49 decision F: the label that carries the job's `specLabel`. The orchestrator compares it with
 * the spec it would send, so a stale service converges on the next open. Written on create AND on every
 * patch, and left out of a patch whose job carries no specLabel: the labels map is ONE field, replaced
 * whole by the PATCH, so leaving the key out removes it and the service matches its spec exactly.
 */
const CLOUD_RUN_SPEC_LABEL_KEY = "dy-spec";
/** IAM members that make a service public. A service with either is never updated (review M1). */
const CLOUD_RUN_PUBLIC_MEMBERS = ["allUsers", "allAuthenticatedUsers"];
/**
 * The shape of an operation name Google returns, which goes back into a URL PATH (it is a resource
 * path, so it cannot be percent-encoded whole). Checked, not trusted: a name with "../" or a query
 * string would re-path the wait call. Real names are `projects/<p>/locations/<l>/operations/<id>`.
 */
const CLOUD_RUN_OPERATION_NAME_RE = /^projects\/[a-z0-9-]{1,63}\/locations\/[a-z0-9-]{1,63}\/operations\/[A-Za-z0-9._-]{1,128}$/;

/**
 * The premise probe's program (planning/49 §9 Phase 2), run by CLOUD_RUN_PROBE_IMAGE as
 * `python3 -c <program>`. It serves HTTP on $PORT. On each GET it tries a TCP connection to each
 * target in DY_PROBE_TARGETS (which the Worker builds from the VALIDATED targets) up to 3 times, 1 s
 * apart (review L6: one lost SYN is not "closed"), and answers with the first "open" or the last
 * failure: open / refused / timeout / error:<errno>. It reads no data, writes no file and sends no payload.
 * The Worker owns this text. A signed job carries only the targets.
 */
export const CLOUD_RUN_PROBE_PROGRAM = [
  "import json",
  "import os",
  "import socket",
  "import time",
  "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer",
  "",
  'TARGETS = json.loads(os.environ["DY_PROBE_TARGETS"])',
  "",
  "",
  "def check_once(ip, port):",
  "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
  "    sock.settimeout(3)",
  "    try:",
  "        sock.connect((ip, int(port)))",
  '        return "open"',
  "    except socket.timeout:",
  '        return "timeout"',
  "    except ConnectionRefusedError:",
  '        return "refused"',
  "    except OSError as error:",
  '        return "error:" + str(error.errno or 0)',
  "    finally:",
  "        sock.close()",
  "",
  "",
  "def check(ip, port):",
  "    result = check_once(ip, port)",
  "    for _ in range(2):",
  '        if result == "open":',
  "            break",
  "        time.sleep(1)",
  "        result = check_once(ip, port)",
  "    return result",
  "",
  "",
  "class Handler(BaseHTTPRequestHandler):",
  "    def do_GET(self):",
  "        results = []",
  "        for target in TARGETS:",
  '            result = check(target["ip"], target["port"])',
  '            results.append({"ip": target["ip"], "port": target["port"], "result": result})',
  '        body = json.dumps({"results": results}).encode()',
  "        self.send_response(200)",
  '        self.send_header("Content-Type", "application/json")',
  '        self.send_header("Content-Length", str(len(body)))',
  "        self.end_headers()",
  "        self.wfile.write(body)",
  "",
  "    def log_message(self, format, *args):",
  "        pass",
  "",
  "",
  'ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()',
  "",
].join("\n");
/** The probe's ONE environment variable, set by the Worker, never by a job. */
const CLOUD_RUN_PROBE_TARGETS_ENV = "DY_PROBE_TARGETS";
/** A probe answer bigger than this is not the probe's answer. */
const CLOUD_RUN_PROBE_BODY_MAX_LENGTH = 16 * 1024;
/** One probe result value, exactly as CLOUD_RUN_PROBE_PROGRAM writes it. */
const CLOUD_RUN_PROBE_RESULT_RE = /^(?:open|refused|timeout|error:[0-9]{1,5})$/;
/**
 * A cold probe can answer 429 "no available instance" with maxInstances 1 (the 2026-10-07 W2 probe
 * saw this on 1 of 2 cold connects), or 503 while it starts. So the invoke tries a few times.
 */
const CLOUD_RUN_PROBE_INVOKE_ATTEMPTS = 4;
/** The gap between probe invoke attempts. An object, so a test can set it to 0 (real timers there). */
export const cloudRunProbeInvokeTuning = { retryDelayMs: 3000 };

/** What a Cloud Run v2 Operation looks like (the fields these ops read). */
interface CloudRunOperation {
  name?: string;
  done?: boolean;
  error?: { code?: number; message?: string };
  code?: number;
  message?: string;
}

/** What a Cloud Run v2 Service looks like (the fields these ops read). */
interface CloudRunService {
  name?: string;
  uri?: string;
  urls?: string[];
  labels?: Record<string, string>;
  reconciling?: boolean;
  latestCreatedRevision?: string;
  terminalCondition?: { type?: string; state?: string; message?: string };
  /**
   * The deployed spec. The probe invoke reads its OWN DY_PROBE_TARGETS back from here, and
   * cloudrun-service-get reports the image and the Direct VPC egress names from it.
   */
  template?: {
    containers?: Array<{ image?: string; env?: Array<{ name?: string; value?: string }> }>;
    vpcAccess?: { networkInterfaces?: Array<{ network?: string; subnetwork?: string }> };
  };
  error?: { code?: number; message?: string };
  code?: number;
  message?: string;
}

/** What getIamPolicy answers with (the fields these ops read). */
interface CloudRunIamPolicy {
  bindings?: Array<{ role?: string; members?: string[] }>;
  error?: { code?: number; message?: string };
  message?: string;
}

/** Google's top-level error message from a Cloud Run response body, if any (for detail strings). */
function cloudRunErrorMessage(body: { error?: { message?: string }; message?: string } | null): string {
  const message = body?.error?.message ?? body?.message;
  if (message) {
    return `: ${message}`;
  }
  return "";
}

/** The short last segment of a Cloud Run resource path, e.g. ".../revisions/term-x-00001-abc". */
function cloudRunShortName(resourcePath: string | undefined): string | null {
  if (typeof resourcePath !== "string" || resourcePath.length === 0) {
    return null;
  }
  const last = resourcePath.slice(resourcePath.lastIndexOf("/") + 1);
  if (last.length === 0) {
    return null;
  }
  return last;
}

/** The service's URLs as strings only (Cloud Run lists every URL that serves the service). */
function cloudRunServiceUrls(service: CloudRunService): string[] {
  const urls: string[] = [];
  if (Array.isArray(service.urls)) {
    for (const url of service.urls) {
      if (typeof url === "string" && url.length > 0) {
        urls.push(url);
      }
    }
  }
  return urls;
}

/** True when the service carries this platform's managed-by label (review M1). */
function isManagedByPlatform(service: CloudRunService): boolean {
  return service.labels?.[CLOUD_RUN_MANAGED_BY_LABEL_KEY] === CLOUD_RUN_MANAGED_BY_LABEL_VALUE;
}

/** The `projects/<p>/locations/<r>/services` collection URL for a validated project + region. */
function cloudRunServicesUrl(project: string, region: string): string {
  return `${GCP_CLOUD_RUN_API}/projects/${encodeURIComponent(project)}/locations/${encodeURIComponent(region)}/services`;
}

/** The outcome of reading one Cloud Run service: present, absent (404), or a read failure. */
type CloudRunServiceReadOutcome =
  | { kind: "found"; service: CloudRunService }
  | { kind: "absent" }
  | { kind: "failed"; detail: string };

/**
 * GET one Cloud Run service. A 404 is "absent". Any other non-2xx (and an unreachable API) is a
 * failure with Google's own message. A 403 names both the role AND API enablement, because a project
 * without the Cloud Run API enabled is the first thing planning/49 §10 expects the probe to find.
 */
async function readCloudRunServiceRaw(input: {
  url: string;
  accessToken: string;
  serviceName: string;
  project: string;
}): Promise<CloudRunServiceReadOutcome> {
  const { url, accessToken, serviceName, project } = input;

  let response: Response;
  try {
    response = await fetch(url, { headers: gcpHeaders(accessToken) });
  } catch (err) {
    return { kind: "failed", detail: `could not reach Cloud Run to read service "${serviceName}": ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as CloudRunService | null;

  if (response.status === 404) {
    return { kind: "absent" };
  }
  if (response.status === 401 || response.status === 403) {
    return {
      kind: "failed",
      detail:
        `Google Cloud denied reading Cloud Run service "${serviceName}" (HTTP ${response.status})` +
        `${cloudRunErrorMessage(body)} — the service account needs run.services.get (e.g. roles/run.admin) on ` +
        `project "${project}". If the Cloud Run API is not enabled on that project, enable it first.`,
    };
  }
  if (!response.ok || body === null) {
    return {
      kind: "failed",
      detail: `reading Cloud Run service "${serviceName}" failed with HTTP ${response.status}${cloudRunErrorMessage(body)}.`,
    };
  }
  return { kind: "found", service: body };
}

/**
 * The PUBLIC members (allUsers / allAuthenticatedUsers) bound on one service, read with getIamPolicy,
 * or the reason the read failed. A READ: nothing here writes IAM.
 */
async function readCloudRunPublicMembers(input: {
  serviceUrl: string;
  accessToken: string;
  serviceName: string;
  project: string;
}): Promise<{ ok: true; publicMembers: string[] } | { ok: false; detail: string }> {
  const { serviceUrl, accessToken, serviceName, project } = input;

  let response: Response;
  try {
    response = await fetch(`${serviceUrl}:getIamPolicy`, { headers: gcpHeaders(accessToken) });
  } catch (err) {
    return { ok: false, detail: `could not reach Cloud Run to read the IAM policy of "${serviceName}": ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as CloudRunIamPolicy | null;
  if (!response.ok || body === null) {
    return {
      ok: false,
      detail:
        `reading the IAM policy of Cloud Run service "${serviceName}" failed with HTTP ${response.status}` +
        `${cloudRunErrorMessage(body)} — the service account needs run.services.getIamPolicy (e.g. roles/run.admin) ` +
        `on project "${project}".`,
    };
  }

  const publicMembers: string[] = [];
  for (const binding of body.bindings ?? []) {
    for (const member of binding.members ?? []) {
      if (CLOUD_RUN_PUBLIC_MEMBERS.includes(member) && !publicMembers.includes(member)) {
        publicMembers.push(member);
      }
    }
  }
  return { ok: true, publicMembers };
}

/** How a Cloud Run operation wait ended (orchestrator review L1 needs the difference). */
type CloudRunWaitOutcome =
  | { kind: "done" }
  /** The operation finished WITH an error, or the name was unsafe: a clear failure. */
  | { kind: "failed"; detail: string }
  /** The operation may still be running (wait bound hit, or the wait call failed). Not confirmed. */
  | { kind: "unconfirmed"; detail: string };

/**
 * Block until a Cloud Run operation is done, bounded to CLOUD_RUN_OPERATION_WAIT_ATTEMPTS calls of
 * `:wait`. A deploy still running at the bound is UNCONFIRMED: it may still land, so it is never
 * assumed to have landed and never reported as a plain failure.
 */
async function waitForCloudRunOperation(input: {
  operationName: string;
  accessToken: string;
  what: string;
  verb: string;
}): Promise<CloudRunWaitOutcome> {
  const { operationName, accessToken, what, verb } = input;

  if (!CLOUD_RUN_OPERATION_NAME_RE.test(operationName)) {
    return {
      kind: "unconfirmed",
      detail: `Cloud Run returned an operation name this Worker will not put in a URL ("${operationName}") — the ${what} ${verb} may still be running; re-run to resume.`,
    };
  }
  const waitUrl = `${GCP_CLOUD_RUN_API}/${operationName}:wait`;

  for (let attempt = 1; attempt <= CLOUD_RUN_OPERATION_WAIT_ATTEMPTS; attempt += 1) {
    let response: Response;
    try {
      response = await fetch(waitUrl, {
        method: "POST",
        headers: gcpHeaders(accessToken),
        body: JSON.stringify({ timeout: CLOUD_RUN_OPERATION_WAIT_TIMEOUT }),
      });
    } catch (err) {
      return { kind: "unconfirmed", detail: `could not reach Cloud Run while waiting for the ${what} ${verb} to finish: ${errorMessage(err)}` };
    }
    const body = (await response.json().catch(() => null)) as CloudRunOperation | null;
    if (!response.ok) {
      return {
        kind: "unconfirmed",
        detail: `waiting for the ${what} ${verb} to finish failed with HTTP ${response.status}${cloudRunErrorMessage(body)}.`,
      };
    }
    if (body?.done !== true) {
      continue;
    }
    if (body.error) {
      return { kind: "failed", detail: `${what} ${verb} operation failed${cloudRunErrorMessage(body)}.` };
    }
    return { kind: "done" };
  }

  return {
    kind: "unconfirmed",
    detail: `the ${what} ${verb} operation was still not done after ${CLOUD_RUN_OPERATION_WAIT_ATTEMPTS} waits — re-run to resume once it finishes.`,
  };
}

/**
 * Build the Cloud Run v2 Service body from the VALIDATED params plus this module's fixed policy.
 * PURE and exported, so the split between "parameter" and "fixed policy" (this op's security
 * boundary) can be asserted directly.
 */
export function buildCloudRunServiceBody(params: CloudRunServiceUpsertParams): Record<string, unknown> {
  const env: Array<Record<string, unknown>> = [];
  for (const entry of params.env ?? []) {
    env.push({ name: entry.name, value: entry.value });
  }
  for (const entry of params.secretEnv ?? []) {
    env.push({ name: entry.name, valueSource: { secretKeyRef: { secret: entry.secretName, version: entry.version } } });
  }

  const volumes: Array<Record<string, unknown>> = [];
  const volumeMounts: Array<Record<string, unknown>> = [];
  for (const volume of params.nfsVolumes ?? []) {
    volumes.push({ name: volume.name, nfs: { server: volume.server, path: volume.path, readOnly: volume.readOnly === true } });
    volumeMounts.push({ name: volume.name, mountPath: volume.mountPath });
  }

  const container: Record<string, unknown> = {
    image: params.image,
    ports: [{ name: "http1", containerPort: CLOUD_RUN_CONTAINER_PORT }],
    resources: { limits: { cpu: params.cpu, memory: params.memory } },
  };

  // THE PROBE: the Worker's own program under the stock image. The validator already refused env,
  // secretEnv and nfsVolumes for a probe, so the one variable below is the probe's whole environment.
  if (params.probe !== undefined) {
    const targets: Array<{ ip: string; port: string }> = [];
    for (const target of params.probe.tcpTargets) {
      targets.push({ ip: target.ip, port: target.port });
    }
    container.command = ["python3"];
    container.args = ["-c", CLOUD_RUN_PROBE_PROGRAM];
    env.push({ name: CLOUD_RUN_PROBE_TARGETS_ENV, value: JSON.stringify(targets) });
  }

  if (env.length > 0) {
    container.env = env;
  }
  if (volumeMounts.length > 0) {
    container.volumeMounts = volumeMounts;
  }

  const template: Record<string, unknown> = {
    serviceAccount: params.runServiceAccount,
    timeout: CLOUD_RUN_REQUEST_TIMEOUT,
    executionEnvironment: "EXECUTION_ENVIRONMENT_GEN2",
    scaling: { minInstanceCount: CLOUD_RUN_MIN_INSTANCES, maxInstanceCount: params.maxInstances },
    // Direct VPC egress onto the cell's OWN VPC: an interface on the cell network and the Run subnet,
    // with only private ranges going through it.
    vpcAccess: {
      networkInterfaces: [{ network: params.network, subnetwork: params.subnet }],
      egress: "PRIVATE_RANGES_ONLY",
    },
    containers: [container],
  };
  if (volumes.length > 0) {
    template.volumes = volumes;
  }

  // The labels: managed-by always, and dy-spec exactly when the job carries a specLabel (see
  // CLOUD_RUN_SPEC_LABEL_KEY: a patch without one removes the label).
  const labels: Record<string, string> = { [CLOUD_RUN_MANAGED_BY_LABEL_KEY]: CLOUD_RUN_MANAGED_BY_LABEL_VALUE };
  if (params.specLabel !== undefined) {
    labels[CLOUD_RUN_SPEC_LABEL_KEY] = params.specLabel;
  }

  // INGRESS_TRAFFIC_ALL + invoker IAM explicitly ON + no allUsers binding = reachable from the edge
  // gate, callable only with a Google ID token (review M1: `invokerIamDisabled: false` on purpose).
  return {
    labels,
    ingress: "INGRESS_TRAFFIC_ALL",
    invokerIamDisabled: false,
    template,
  };
}

/**
 * The reason an EXISTING service must not be patched, or null when it may be. Review M1 + L5: the
 * service must carry the managed-by label, must not be reconciling (a create still in flight), and
 * must hold no public IAM binding.
 */
async function existingServicePatchRefusal(input: {
  service: CloudRunService;
  serviceUrl: string;
  accessToken: string;
  serviceName: string;
  project: string;
}): Promise<string | null> {
  const { service, serviceName } = input;
  if (!isManagedByPlatform(service)) {
    return (
      `Cloud Run service "${serviceName}" exists but does not carry the ${CLOUD_RUN_MANAGED_BY_LABEL_KEY}=` +
      `${CLOUD_RUN_MANAGED_BY_LABEL_VALUE} label, so this platform did not create it. It is left alone, not taken over.`
    );
  }
  if (service.reconciling === true) {
    return `Cloud Run service "${serviceName}" is still reconciling (an earlier deploy is in flight). Re-run once it settles.`;
  }
  const iam = await readCloudRunPublicMembers(input);
  if (!iam.ok) {
    return iam.detail;
  }
  if (iam.publicMembers.length > 0) {
    return (
      `Cloud Run service "${serviceName}" has a public IAM binding (${iam.publicMembers.join(", ")}). This platform never ` +
      "updates a public service. Remove the binding first."
    );
  }
  return null;
}

/**
 * The reason a SESSION upsert must not run, or null when its subnet is this site's (hub#93 §2, D7).
 * The subnet must exist on the job's network (planning/49 Phase 3: the network is a registry name now,
 * so the subnet must be checked to sit on it), its range must be the one derived from the slot, and its
 * description must bind it to the slug the service name carries. A failed read refuses too: an
 * unconfirmed binding is never treated as a good one.
 */
async function sessionSubnetBindRefusal(input: {
  params: CloudRunServiceUpsertParams;
  accessToken: string;
}): Promise<string | null> {
  const { params, accessToken } = input;
  if (params.slot === undefined) {
    return "a session service must carry its site's Run slot";
  }
  const sessionName = splitCloudRunSessionServiceName(params.serviceName);
  if (sessionName === null) {
    return `"${params.serviceName}" is not a session service name`;
  }
  const expectedRange = siteRunSubnetCidrForSlot(params.slot);

  const read = await readComputeSubnetRaw({
    project: params.project,
    region: params.region,
    subnetName: params.subnet,
    accessToken,
  });
  if (read.kind === "failed") {
    return `could not confirm that subnetwork "${params.subnet}" belongs to "${sessionName.slug}": ${read.detail}`;
  }
  if (read.kind === "absent") {
    return `subnetwork "${params.subnet}" does not exist — create the site's subnet before its session service`;
  }
  if (!subnetIsOnNetwork(read.subnet, params.network)) {
    const foundNetwork = lastUrlSegment(read.subnet.network) ?? "(none)";
    return `subnetwork "${params.subnet}" is on the network "${foundNetwork}", not "${params.network}" — refusing to deploy onto it`;
  }
  if (read.subnet.ipCidrRange !== expectedRange) {
    const foundRange = nonEmptyStringOrNull(read.subnet.ipCidrRange) ?? "(none)";
    return `subnetwork "${params.subnet}" has the range ${foundRange}, not ${expectedRange} for slot ${params.slot} — refusing to deploy onto it`;
  }
  const boundSlug = siteSlugFromSubnetDescription(read.subnet.description);
  if (boundSlug !== sessionName.slug) {
    const foundDescription = nonEmptyStringOrNull(read.subnet.description) ?? "(none)";
    return (
      `subnetwork "${params.subnet}" is described "${foundDescription}", which does not bind it to "${sessionName.slug}" — ` +
      "refusing to deploy one site's session onto another site's subnet"
    );
  }
  return null;
}

export async function actuateCloudRunServiceUpsert(params: CloudRunServiceUpsertParams, env: Env): Promise<CloudRunServiceUpsertResult> {
  const { project, region, serviceName } = params;
  const failure = (detail: string): CloudRunServiceUpsertResult => ({ ok: false, op: "cloudrun-service-upsert", serviceName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const accessToken = token.accessToken;
  const collectionUrl = cloudRunServicesUrl(project, region);
  const serviceUrl = `${collectionUrl}/${encodeURIComponent(serviceName)}`;
  const what = `Cloud Run service "${serviceName}"`;

  // hub#93 D7: a SESSION service is bound to its site's subnet on THIS side too, because the Worker
  // cannot see the platform's database. Read the subnet and refuse, before any Cloud Run call, unless
  // it exists with the range derived from the job's slot AND a description naming the SAME slug as the
  // service. One extra read per upsert.
  if (params.slot !== undefined) {
    const bindRefusal = await sessionSubnetBindRefusal({ params, accessToken });
    if (bindRefusal !== null) {
      return failure(bindRefusal);
    }
  }

  // CREATE or PATCH is decided by a read, not by trying one and reading the error.
  const existing = await readCloudRunServiceRaw({ url: serviceUrl, accessToken, serviceName, project });
  if (existing.kind === "failed") {
    return failure(existing.detail);
  }

  let status: "created" | "updated" = "created";
  let writeUrl = `${collectionUrl}?${new URLSearchParams({ serviceId: serviceName }).toString()}`;
  let method = "POST";
  let verb = "create";
  if (existing.kind === "found") {
    const refusal = await existingServicePatchRefusal({ service: existing.service, serviceUrl, accessToken, serviceName, project });
    if (refusal !== null) {
      return failure(refusal);
    }
    status = "updated";
    writeUrl = serviceUrl;
    method = "PATCH";
    verb = "update";
  }

  let response: Response;
  try {
    response = await fetch(writeUrl, { method, headers: gcpHeaders(accessToken), body: JSON.stringify(buildCloudRunServiceBody(params)) });
  } catch (err) {
    return failure(`could not reach Cloud Run to ${verb} ${what}: ${errorMessage(err)}`);
  }
  const writeBody = (await response.json().catch(() => null)) as CloudRunOperation | null;

  if (response.status === 401 || response.status === 403) {
    return failure(
      `Google Cloud denied the ${what} ${verb} (HTTP ${response.status})${cloudRunErrorMessage(writeBody)} — the service ` +
        `account needs run.services.${verb} (e.g. roles/run.admin) on project "${project}", and iam.serviceAccounts.actAs ` +
        `on "${params.runServiceAccount}".`,
    );
  }
  if (!response.ok) {
    return failure(`${what} ${verb} failed with HTTP ${response.status}${cloudRunErrorMessage(writeBody)}.`);
  }
  // A 2xx must carry an Operation. Without one, the deploy cannot be confirmed.
  const operationName = writeBody?.name;
  if (!operationName) {
    return failure(`Cloud Run returned HTTP ${response.status} but no operation — cannot confirm the ${what} ${verb} was accepted.`);
  }
  const waited = await waitForCloudRunOperation({ operationName, accessToken, what, verb });
  if (waited.kind === "unconfirmed") {
    return { ok: false, op: "cloudrun-service-upsert", serviceName, detail: waited.detail, unconfirmed: true };
  }
  if (waited.kind === "failed") {
    return failure(waited.detail);
  }

  // Re-READ the service rather than parse the operation's embedded response. `uri` and `urls` are
  // load-bearing (planning/49 §3.2), so they come from the service's own current state.
  const settled = await readCloudRunServiceRaw({ url: serviceUrl, accessToken, serviceName, project });
  if (settled.kind === "failed") {
    return failure(settled.detail);
  }
  if (settled.kind === "absent") {
    return failure(`${what} reported a finished ${verb} but is not present on read-back — re-run to resume.`);
  }
  const uri = settled.service.uri;
  if (typeof uri !== "string" || uri.length === 0) {
    return failure(`${what} was deployed but Cloud Run reported no uri for it — re-run to resume.`);
  }

  return {
    ok: true,
    op: "cloudrun-service-upsert",
    serviceName,
    status,
    uri,
    urls: cloudRunServiceUrls(settled.service),
    revision: cloudRunShortName(settled.service.latestCreatedRevision),
  };
}

export async function readCloudRunService(params: CloudRunServiceGetParams, env: Env): Promise<CloudRunServiceGetResult> {
  const { project, region, serviceName } = params;
  const failure = (detail: string): CloudRunServiceGetResult => ({ ok: false, op: "cloudrun-service-get", serviceName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const serviceUrl = `${cloudRunServicesUrl(project, region)}/${encodeURIComponent(serviceName)}`;

  const outcome = await readCloudRunServiceRaw({ url: serviceUrl, accessToken: token.accessToken, serviceName, project });
  if (outcome.kind === "failed") {
    return failure(outcome.detail);
  }
  if (outcome.kind === "absent") {
    return {
      ok: true,
      op: "cloudrun-service-get",
      serviceName,
      found: false,
      uri: null,
      urls: [],
      ready: false,
      managedByPlatform: false,
      reconciling: false,
      network: null,
      subnet: null,
      image: null,
      specLabel: null,
    };
  }

  // "exists" and "serving" are different questions. `ready` answers the second, off the TERMINAL
  // condition Cloud Run settles on.
  const service = outcome.service;
  const condition = service.terminalCondition;
  const ready = condition?.type === "Ready" && condition?.state === "CONDITION_SUCCEEDED";
  let uri: string | null = null;
  if (typeof service.uri === "string" && service.uri.length > 0) {
    uri = service.uri;
  }
  const egress = cloudRunEgressNames(service);
  return {
    ok: true,
    op: "cloudrun-service-get",
    serviceName,
    found: true,
    uri,
    urls: cloudRunServiceUrls(service),
    ready,
    managedByPlatform: isManagedByPlatform(service),
    reconciling: service.reconciling === true,
    network: egress.network,
    subnet: egress.subnet,
    image: cloudRunServiceImage(service),
    specLabel: nonEmptyStringOrNull(service.labels?.[CLOUD_RUN_SPEC_LABEL_KEY]),
  };
}

/**
 * The SHORT network and subnet names of a service's Direct VPC egress interface (the first one: the
 * upsert writes exactly one). Cloud Run may answer with a short name or a full resource path, so the
 * last path segment is taken either way. Null for a name the service does not carry.
 */
function cloudRunEgressNames(service: CloudRunService): { network: string | null; subnet: string | null } {
  const interfaces = service.template?.vpcAccess?.networkInterfaces;
  if (!Array.isArray(interfaces) || interfaces.length === 0) {
    return { network: null, subnet: null };
  }
  const firstInterface = interfaces[0];
  return { network: lastUrlSegment(firstInterface?.network), subnet: lastUrlSegment(firstInterface?.subnetwork) };
}

/** The image of a service's first container (the upsert writes exactly one), or null. */
function cloudRunServiceImage(service: CloudRunService): string | null {
  const containers = service.template?.containers;
  if (!Array.isArray(containers) || containers.length === 0) {
    return null;
  }
  return nonEmptyStringOrNull(containers[0]?.image);
}

export async function actuateCloudRunServiceDelete(params: CloudRunServiceDeleteParams, env: Env): Promise<CloudRunServiceDeleteResult> {
  const { project, region, serviceName } = params;
  const failure = (detail: string): CloudRunServiceDeleteResult => ({ ok: false, op: "cloudrun-service-delete", serviceName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const accessToken = token.accessToken;
  const serviceUrl = `${cloudRunServicesUrl(project, region)}/${encodeURIComponent(serviceName)}`;
  const what = `Cloud Run service "${serviceName}"`;

  // Read first (review M1): delete ONLY a service this platform labelled. Absent already = success.
  const existing = await readCloudRunServiceRaw({ url: serviceUrl, accessToken, serviceName, project });
  if (existing.kind === "failed") {
    return failure(existing.detail);
  }
  if (existing.kind === "absent") {
    return { ok: true, op: "cloudrun-service-delete", serviceName, status: "already-absent" };
  }
  if (!isManagedByPlatform(existing.service)) {
    return failure(
      `${what} does not carry the ${CLOUD_RUN_MANAGED_BY_LABEL_KEY}=${CLOUD_RUN_MANAGED_BY_LABEL_VALUE} label, so this ` +
        "platform did not create it. It is left in place.",
    );
  }

  let response: Response;
  try {
    response = await fetch(serviceUrl, { method: "DELETE", headers: gcpHeaders(accessToken) });
  } catch (err) {
    return failure(`could not reach Cloud Run to delete ${what}: ${errorMessage(err)}`);
  }
  const body = (await response.json().catch(() => null)) as CloudRunOperation | null;

  // A delete CONVERGES: gone between the read and the delete is still the desired state.
  if (response.status === 404) {
    return { ok: true, op: "cloudrun-service-delete", serviceName, status: "already-absent" };
  }
  if (response.status === 401 || response.status === 403) {
    return failure(
      `Google Cloud denied the ${what} delete (HTTP ${response.status})${cloudRunErrorMessage(body)} — the service account ` +
        `needs run.services.delete (e.g. roles/run.admin) on project "${project}".`,
    );
  }
  if (!response.ok) {
    return failure(`${what} delete failed with HTTP ${response.status}${cloudRunErrorMessage(body)}.`);
  }
  const operationName = body?.name;
  if (!operationName) {
    return failure(`Cloud Run returned HTTP ${response.status} but no operation — cannot confirm the ${what} delete was accepted.`);
  }
  const waited = await waitForCloudRunOperation({ operationName, accessToken, what, verb: "delete" });
  if (waited.kind !== "done") {
    return failure(waited.detail);
  }
  return { ok: true, op: "cloudrun-service-delete", serviceName, status: "deleted" };
}

/** Wait `ms` milliseconds (the probe invoke's retry gap). */
function sleepMilliseconds(ms: number): Promise<void> {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

/** Drop a response body we do not read, so the connection is released. */
async function discardBody(response: Response): Promise<void> {
  if (response.body !== null) {
    await response.body.cancel().catch(() => undefined);
  }
}

/**
 * The probe targets the Worker ITSELF deployed: DY_PROBE_TARGETS from the service's own spec. The
 * answer is checked against these (review L3), not against anything the job or the probe says.
 * Returns the "ip:port" keys, or null when the spec carries no well-formed targets.
 */
function deployedProbeTargets(service: CloudRunService): Set<string> | null {
  const containers = service.template?.containers;
  if (!Array.isArray(containers) || containers.length === 0) {
    return null;
  }
  const envList = containers[0]?.env;
  if (!Array.isArray(envList)) {
    return null;
  }
  let raw: string | null = null;
  for (const entry of envList) {
    if (entry?.name === CLOUD_RUN_PROBE_TARGETS_ENV && typeof entry.value === "string") {
      raw = entry.value;
    }
  }
  if (raw === null) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    return null;
  }
  const keys = new Set<string>();
  for (const target of parsed) {
    if (typeof target !== "object" || target === null) {
      return null;
    }
    const { ip, port } = target as { ip?: unknown; port?: unknown };
    if (typeof ip !== "string" || typeof port !== "string") {
      return null;
    }
    keys.add(`${ip}:${port}`);
  }
  return keys;
}

/**
 * Parse and CHECK the probe's answer. Every entry must have the exact shape the program writes, and
 * the set of ip:port pairs must EQUAL the deployed targets: none missing, none extra, none repeated,
 * not empty (review L3). Returns null on any mismatch.
 */
function parseProbeResults(text: string, expectedTargets: Set<string>): CloudRunProbeResultEntry[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return null;
  }
  const results = (parsed as { results?: unknown }).results;
  if (!Array.isArray(results) || results.length === 0 || results.length !== expectedTargets.size) {
    return null;
  }
  const clean: CloudRunProbeResultEntry[] = [];
  const seen = new Set<string>();
  for (const entry of results) {
    if (typeof entry !== "object" || entry === null) {
      return null;
    }
    const { ip, port, result } = entry as { ip?: unknown; port?: unknown; result?: unknown };
    if (typeof ip !== "string" || typeof port !== "string" || typeof result !== "string") {
      return null;
    }
    if (!CLOUD_RUN_PROBE_RESULT_RE.test(result)) {
      return null;
    }
    const key = `${ip}:${port}`;
    if (!expectedTargets.has(key) || seen.has(key)) {
      return null;
    }
    seen.add(key);
    clean.push({ ip, port, result });
  }
  return clean;
}

/**
 * planning/49 Phase 2 — invoke the premise PROBE service (that name only) twice:
 *   1. WITHOUT a token. Cloud Run must refuse it (401 or 403). That proves no allUsers binding.
 *   2. WITH a Google ID token minted from the agency's OWN key, audience = the service URL. That
 *      proves the Worker's identity holds run.invoker and that IAM-only ingress works.
 * Then it returns the probe's TCP results. A READ in effect: the probe opens connections and sends
 * nothing. The ID token is never returned or logged.
 */
export async function actuateCloudRunProbeInvoke(params: CloudRunProbeInvokeParams, env: Env): Promise<CloudRunProbeInvokeResult> {
  const { project, region, serviceName } = params;
  const failure = (detail: string): CloudRunProbeInvokeResult => ({ ok: false, op: "cloudrun-probe-invoke", serviceName, detail });

  const token = await mintPinnedGcpAccessToken(env, project);
  if (!token.ok) {
    return failure(token.detail);
  }
  const serviceUrl = `${cloudRunServicesUrl(project, region)}/${encodeURIComponent(serviceName)}`;
  const existing = await readCloudRunServiceRaw({ url: serviceUrl, accessToken: token.accessToken, serviceName, project });
  if (existing.kind === "failed") {
    return failure(existing.detail);
  }
  if (existing.kind === "absent") {
    return failure(`the probe service "${serviceName}" does not exist — deploy it with cloudrun-service-upsert first`);
  }
  if (!isManagedByPlatform(existing.service)) {
    return failure(`"${serviceName}" does not carry this platform's managed-by label, so it is not our probe`);
  }
  const uri = existing.service.uri;
  if (typeof uri !== "string" || !uri.startsWith("https://")) {
    return failure(`the probe service "${serviceName}" has no https uri yet`);
  }

  const expectedTargets = deployedProbeTargets(existing.service);
  if (expectedTargets === null) {
    return failure(`the probe service "${serviceName}" carries no well-formed ${CLOUD_RUN_PROBE_TARGETS_ENV}, so its answer cannot be checked`);
  }

  // 1. NO token. Cloud Run must refuse it (401 or 403). The other answers are of two kinds:
  //    - 2xx or 3xx: the service ANSWERED a request with no token, so it may be PUBLIC (review L1).
  //      That is a failure HERE, so no caller can read it as a pass.
  //    - anything else (404, 429, 5xx): the call failed and proves nothing either way (re-review L1).
  //      That is a plain failure. It is NOT reported as public.
  //    redirect:"manual" keeps a 3xx as a 3xx instead of following it to some other answer. A runtime
  //    that gives an opaque-redirect response for it reports status 0, which is a redirect too
  //    (the same rule as validators.ts).
  let unauthenticated: Response;
  try {
    unauthenticated = await fetch(uri, { method: "GET", redirect: "manual" });
  } catch (err) {
    return failure(`could not reach the probe at ${uri} (no token): ${errorMessage(err)}`);
  }
  const unauthenticatedStatus = unauthenticated.status;
  await discardBody(unauthenticated);
  const refused = unauthenticatedStatus === 401 || unauthenticatedStatus === 403;
  const answered = unauthenticatedStatus === 0 || (unauthenticatedStatus >= 200 && unauthenticatedStatus < 400);
  if (answered) {
    return {
      ok: false,
      op: "cloudrun-probe-invoke",
      serviceName,
      detail:
        `the probe answered HTTP ${unauthenticatedStatus} to a request with NO token. It must refuse (401 or 403). ` +
        "The service may be PUBLIC: delete it now.",
      public: true,
      unauthenticatedStatus,
    };
  }
  if (!refused) {
    return {
      ok: false,
      op: "cloudrun-probe-invoke",
      serviceName,
      detail:
        `the request with NO token got HTTP ${unauthenticatedStatus}: not a refusal (401 or 403) and not an answer. ` +
        "The check did not complete, so it proves nothing about public access. Try again later.",
      unauthenticatedStatus,
    };
  }

  // 2. WITH an ID token from the agency's own key.
  const idToken = await mintPinnedGcpIdToken(env, project, uri);
  if (!idToken.ok) {
    return failure(idToken.detail);
  }
  let authenticatedStatus = 0;
  // The probe's answer, read with the shared STREAMING byte cap (review L3): never buffered whole.
  let capped: { ok: true; text: string } | { ok: false; detail: string } = { ok: false, detail: "no answer was read" };
  for (let attempt = 1; attempt <= CLOUD_RUN_PROBE_INVOKE_ATTEMPTS; attempt += 1) {
    let response: Response;
    try {
      response = await fetch(uri, { method: "GET", headers: { authorization: `Bearer ${idToken.idToken}` } });
    } catch (err) {
      return failure(`could not reach the probe at ${uri} (with an ID token): ${errorMessage(err)}`);
    }
    authenticatedStatus = response.status;
    // A cold start can answer 429 or 503 (see CLOUD_RUN_PROBE_INVOKE_ATTEMPTS). Anything else is final.
    if (authenticatedStatus === 429 || authenticatedStatus === 503) {
      await discardBody(response);
      if (attempt < CLOUD_RUN_PROBE_INVOKE_ATTEMPTS) {
        await sleepMilliseconds(cloudRunProbeInvokeTuning.retryDelayMs);
      }
      continue;
    }
    if (authenticatedStatus !== 200) {
      await discardBody(response);
      break;
    }
    capped = await readBodyCapped(response, CLOUD_RUN_PROBE_BODY_MAX_LENGTH);
    break;
  }

  if (authenticatedStatus !== 200) {
    return failure(
      `the probe answered HTTP ${authenticatedStatus} to a request with an ID token from the agency's own key ` +
        `(the request without a token got HTTP ${unauthenticatedStatus}). The Worker's service account needs run.invoker on ` +
        `project "${project}".`,
    );
  }
  if (!capped.ok) {
    return failure(`the probe's answer could not be read within ${CLOUD_RUN_PROBE_BODY_MAX_LENGTH} bytes: ${capped.detail}`);
  }
  const results = parseProbeResults(capped.text, expectedTargets);
  if (results === null) {
    return failure("the probe answered HTTP 200, but the body is not the probe's results for exactly the targets it was deployed with");
  }
  return { ok: true, op: "cloudrun-probe-invoke", serviceName, uri, unauthenticatedStatus, authenticatedStatus, results };
}

// ── planning/49 §8 + hub#93: workers-route-upsert / workers-route-delete ─────────────────────────
// The edge gate's Workers route for ONE exact session host in the agency's OWN zone, with the agency's
// own CF_DNS_API_TOKEN (which gains Zone → Workers Routes: Edit — a scope add, not a new secret). The
// pattern is DERIVED from the validated host (`<host>/*`) and the script is ALWAYS the cell's edge gate,
// DERIVED from the job's project and region (edgeGateScriptNameFor: `dy-gate-<project>-<region>`), so a
// signed job can neither widen a route nor point one at another script. The project is PINNED to this
// Worker's service-account key's own project first (no Cloudflare call before that), so a job can only
// name the cell this Worker serves. A route with the same pattern that points ELSEWHERE is not ours:
// the upsert never repoints it and the delete never removes it (the same "never take over" rule as the
// Cloud Run managed-by label).
//   0. PIN `project` to GCP_SERVICE_ACCOUNT_KEY's project_id (no network call)
//   1. GET  /zones?name=<zone>                    -> exactly one zone id (resolveZoneId)
//   2. GET  /zones/:zid/workers/routes            -> the routes with this EXACT pattern
//   3. upsert: none -> POST {pattern, script}; one on the gate -> unchanged; one elsewhere -> refused
//      delete: none -> already-absent; one on the gate -> DELETE; one elsewhere -> refused
// Two or more routes with one pattern is ambiguous and refused (Cloudflare should not allow it).

/** A Workers route row (only the fields these ops read). */
interface CloudflareWorkerRoute {
  id?: string;
  pattern?: string;
  script?: string;
}

const WORKERS_ROUTE_UNAUTHORIZED_HINT =
  "Cloudflare denied the Workers route call — CF_DNS_API_TOKEN needs Zone → Workers Routes: Edit on this zone.";

/** The routes in a zone whose pattern is EXACTLY `pattern`, or the reason the list failed. */
async function findWorkerRoutesByPattern(
  token: string,
  zoneId: string,
  pattern: string,
): Promise<{ routes: CloudflareWorkerRoute[] } | { error: string }> {
  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zoneId)}/workers/routes`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { error: `could not reach Cloudflare to list Workers routes: ${errorMessage(err)}` };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return { error: WORKERS_ROUTE_UNAUTHORIZED_HINT };
  }
  if (!body?.success || !Array.isArray(body.result)) {
    return { error: `Workers route lookup failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.` };
  }
  // Exact pattern only: a route like `*.<zone>/*` or `<host>/admin*` is a DIFFERENT route.
  const routes = (body.result as CloudflareWorkerRoute[]).filter((route) => route.id && route.pattern === pattern);
  return { routes };
}

export async function actuateWorkersRouteUpsert(params: WorkersRouteUpsertParams, env: Env): Promise<WorkersRouteUpsertResult> {
  const pattern = workersRoutePatternFor(params.host);
  const script = edgeGateScriptNameFor(params.project, params.region);
  const failure = (detail: string): WorkersRouteUpsertResult => ({ ok: false, op: "workers-route-upsert", pattern, script, detail });

  const pin = readPinnedServiceAccountKey(env, params.project);
  if (!pin.ok) {
    return failure(pin.detail);
  }
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return failure("CF_DNS_API_TOKEN is not configured on this Worker.");
  }
  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) {
    return failure(zone.error);
  }
  const existing = await findWorkerRoutesByPattern(token, zone.id, pattern);
  if ("error" in existing) {
    return failure(existing.error);
  }
  if (existing.routes.length > 1) {
    return failure(`${existing.routes.length} Workers routes already match "${pattern}" — ambiguous, refusing to change any of them.`);
  }

  const existingRoute = existing.routes[0];
  if (existingRoute) {
    if (existingRoute.script === script) {
      return { ok: true, op: "workers-route-upsert", pattern, script, routeId: existingRoute.id as string, status: "unchanged" };
    }
    const otherScript = existingRoute.script ?? "(no script)";
    return {
      ok: false,
      op: "workers-route-upsert",
      pattern,
      script,
      detail: `a Workers route for "${pattern}" already points at "${otherScript}", not "${script}". It was left unchanged.`,
      foreign: true,
    };
  }

  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zone.id)}/workers/routes`, {
      method: "POST",
      headers: cloudflareHeaders(token),
      body: JSON.stringify({ pattern, script }),
    });
  } catch (err) {
    return failure(`could not reach Cloudflare to create the Workers route: ${errorMessage(err)}`);
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return failure(WORKERS_ROUTE_UNAUTHORIZED_HINT);
  }
  const created = body?.success ? (body.result as CloudflareWorkerRoute | undefined) : undefined;
  if (!created?.id) {
    return failure(`Workers route create failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`);
  }
  return { ok: true, op: "workers-route-upsert", pattern, script, routeId: created.id, status: "created" };
}

export async function actuateWorkersRouteDelete(params: WorkersRouteDeleteParams, env: Env): Promise<WorkersRouteDeleteResult> {
  const pattern = workersRoutePatternFor(params.host);
  const script = edgeGateScriptNameFor(params.project, params.region);
  const failure = (detail: string): WorkersRouteDeleteResult => ({ ok: false, op: "workers-route-delete", pattern, script, detail });

  const pin = readPinnedServiceAccountKey(env, params.project);
  if (!pin.ok) {
    return failure(pin.detail);
  }
  const token = env.CF_DNS_API_TOKEN;
  if (!token) {
    return failure("CF_DNS_API_TOKEN is not configured on this Worker.");
  }
  const zone = await resolveZoneId(token, params.zone);
  if ("error" in zone) {
    return failure(zone.error);
  }
  const existing = await findWorkerRoutesByPattern(token, zone.id, pattern);
  if ("error" in existing) {
    return failure(existing.error);
  }
  if (existing.routes.length === 0) {
    return { ok: true, op: "workers-route-delete", pattern, script, status: "already-absent" };
  }
  if (existing.routes.length > 1) {
    return failure(`${existing.routes.length} Workers routes match "${pattern}" — ambiguous, refusing to delete one.`);
  }

  const route = existing.routes[0];
  if (route.script !== script) {
    const otherScript = route.script ?? "(no script)";
    return {
      ok: false,
      op: "workers-route-delete",
      pattern,
      script,
      detail: `the Workers route for "${pattern}" points at "${otherScript}", not "${script}", so this platform did not make it. It was left in place.`,
      foreign: true,
    };
  }

  let response: Response;
  try {
    response = await fetch(`${CF_API}/zones/${encodeURIComponent(zone.id)}/workers/routes/${encodeURIComponent(route.id as string)}`, {
      method: "DELETE",
      headers: cloudflareHeaders(token),
    });
  } catch (err) {
    return failure(`could not reach Cloudflare to delete the Workers route: ${errorMessage(err)}`);
  }
  // A delete CONVERGES: gone between the list and the delete is still the desired state.
  if (response.status === 404) {
    return { ok: true, op: "workers-route-delete", pattern, script, status: "already-absent" };
  }
  const body = (await response.json().catch(() => null)) as CloudflareEnvelope | null;
  if (response.status === 401 || response.status === 403) {
    return failure(WORKERS_ROUTE_UNAUTHORIZED_HINT);
  }
  if (!body?.success) {
    return failure(`Workers route delete failed with HTTP ${response.status}${cloudflareErrorMessage(body)}.`);
  }
  return { ok: true, op: "workers-route-delete", pattern, script, status: "deleted" };
}
