// Direction-B ACTUATION (agency Worker side). Runs a verified job using the AGENCY's
// OWN credentials — here, creating an R2 bucket with R2_PROVISION_API_TOKEN (the
// account-owned Cloudflare token the agency set at onboarding). There is deliberately
// NO platform credential anywhere in this Worker to fall back to: if the agency's token
// is missing or unauthorized, actuation fails cleanly rather than reaching for ours.
//
// This runs ONLY after dispatch-verify.ts::verifyDispatch returns ok:true.
//
// Worker-native only: fetch. Mirrors the orchestrator's own ensureR2Bucket
// (orchestrator/src/cloudflare.ts): POST /accounts/{id}/r2/buckets, treating a 409
// (bucket already exists) as idempotent success.

import type { Env } from "./env.js";
import { errorMessage } from "./util.js";

const CF_API = "https://api.cloudflare.com/client/v4";

export type ActuateResult =
  | { ok: true; op: "provision-r2"; bucket: string; status: "created" | "already-existed"; accountId: string }
  | { ok: false; op: "provision-r2"; bucket: string; detail: string };

interface CloudflareEnvelope {
  success?: boolean;
  errors?: Array<{ code?: number; message?: string }>;
  result?: unknown;
}

/**
 * Resolve the account id the R2_PROVISION_API_TOKEN belongs to. An account-owned token is
 * scoped to exactly one account, so GET /accounts?per_page=1 returns it — the same cheap,
 * account-scoped read the R2 validator already uses. Avoids a separate account-id secret.
 */
async function resolveAccountId(token: string): Promise<{ id: string } | { error: string }> {
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
export async function actuateProvisionR2(bucketName: string, env: Env): Promise<ActuateResult> {
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
    response = await fetch(`${CF_API}/accounts/${account.id}/r2/buckets`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json",
      },
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
