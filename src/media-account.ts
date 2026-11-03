// hub#133 part 2 — WHICH Cloudflare account holds the agency media Worker's HOSTMAP namespace.
//
// CF_DNS_API_TOKEN is a zone token. Nothing forces it to see only ONE account: an agency can give it
// zones of two accounts. "The first account the token lists" would then be a guess, and a wrong guess
// writes another account's HOSTMAP and reports success while the real media host stays broken. So:
//   - MEDIA_ACCOUNT_ID set   -> that account (trusted agency configuration), and nothing else;
//   - unset, one account     -> the token's only account (the usual single-account agency);
//   - unset, two or more     -> refused, naming MEDIA_ACCOUNT_ID. Never a guess.
//
// SELF-CONTAINED ON PURPOSE: the HOSTMAP ops (actuate-branded-media.ts) and the /validate probe
// (validators.ts) both call this, and validators.ts can not import actuate*.ts without an import cycle.

import type { Env } from "./env.js";
import { errorMessage } from "./util.js";

// A Cloudflare account id is 32 lowercase hex characters.
const CLOUDFLARE_ACCOUNT_ID_RE = /^[0-9a-f]{32}$/;

// Five is Cloudflare's smallest page for /accounts. Two rows are already enough to know "more than one".
const ACCOUNT_LIST_PAGE_SIZE = 5;

export type MediaAccountResolution =
  | { ok: true; id: string; source: "pinned" | "only-account" }
  | { ok: false; reason: "denied" | "ambiguous" | "invalid" | "unresolved"; error: string };

export async function resolveMediaAccountId(token: string, env: Env, deniedHint: string): Promise<MediaAccountResolution> {
  const pinned = env.MEDIA_ACCOUNT_ID;
  if (pinned !== undefined && pinned !== "") {
    if (!CLOUDFLARE_ACCOUNT_ID_RE.test(pinned)) {
      return { ok: false, reason: "invalid", error: "MEDIA_ACCOUNT_ID is not a Cloudflare account id (32 lowercase hex characters)." };
    }
    return { ok: true, id: pinned, source: "pinned" };
  }

  let response: Response;
  try {
    response = await fetch(`https://api.cloudflare.com/client/v4/accounts?per_page=${ACCOUNT_LIST_PAGE_SIZE}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    });
  } catch (err) {
    return { ok: false, reason: "unresolved", error: `could not reach Cloudflare to resolve the account: ${errorMessage(err)}` };
  }
  if (response.status === 401 || response.status === 403) {
    await response.text().catch(() => "");
    return { ok: false, reason: "denied", error: deniedHint };
  }
  const body = (await response.json().catch(() => null)) as { success?: boolean; result?: Array<{ id?: unknown }> } | null;
  if (!body?.success || !Array.isArray(body.result)) {
    return { ok: false, reason: "unresolved", error: `could not list the token's Cloudflare accounts (HTTP ${response.status}).` };
  }
  const accountIds: string[] = [];
  for (const account of body.result) {
    if (typeof account.id === "string" && account.id.length > 0) {
      accountIds.push(account.id);
    }
  }
  if (accountIds.length === 0) {
    return { ok: false, reason: "unresolved", error: "CF_DNS_API_TOKEN sees no Cloudflare account." };
  }
  if (accountIds.length > 1) {
    return {
      ok: false,
      reason: "ambiguous",
      error:
        "CF_DNS_API_TOKEN sees more than one Cloudflare account — set MEDIA_ACCOUNT_ID to the account of your media Worker. Refusing to guess.",
    };
  }
  return { ok: true, id: accountIds[0] as string, source: "only-account" };
}
