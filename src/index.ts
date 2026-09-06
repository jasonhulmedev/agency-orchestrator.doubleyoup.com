// agency-orchestrator — the agency-side glue Worker for the doubleyoup
// agency-cloud pivot. PHASE 1 = onboarding + credential self-validation only;
// NO infrastructure provisioning (see doubleyoup-agency-cloud-pivot-answers.md
// Q4 and the repo README).
//
// This Worker is thin, always-on glue (answers Q1): it validates the agency's
// own service credentials (which live as Cloudflare secrets in the agency's
// account) and talks back to our control-plane app over Direction-A OAuth2.
//
// Routes:
//   GET  /health    — liveness.
//   POST /validate  — run every credential validator; the agency iterates until green.
//   GET  /whoami     — exercise the Direction-A round-trip against our app.
//   POST /complete  — if all green, tell our app onboarding is complete.
//   POST /actuate   — Direction-B: run a SIGNED job (ed25519) the platform dispatched
//                     through us, using the AGENCY's own credentials. First op:
//                     provision-r2 (create an R2 bucket). Verified before any side effect.
//
// NOTE on inbound auth: /validate and /complete are Phase-1 endpoints the agency
// triggers themselves, so they are intentionally open. /actuate is the Direction-B
// (platform → Worker) surface: it is NOT open — every request must carry a valid
// ed25519 signature over the canonical job, verified with the agency's own public key
// (DY_SIGNING_PUBLIC_KEY). An unverified request actuates NOTHING.

import type { Env } from "./env.js";
import { callApp } from "./app-client.js";
import { validateAll, type AllValidations } from "./validators.js";
import { renderSetupPage } from "./setup-page.js";
import { errorMessage } from "./util.js";
import { verifyDispatch, isValidR2BucketName, signingPublicKey } from "./dispatch-verify.js";
import { actuateProvisionR2 } from "./actuate.js";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

// GET / — the guided, browser-only setup page. Instructs a non-terminal agency
// owner how to generate each credential and add it as a Cloudflare secret via
// the dashboard, and lets them validate live (the page's button calls /validate).
function handleSetupPage(env: Env): Response {
  return new Response(renderSetupPage(env), {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function allGreen(results: AllValidations): boolean {
  return (
    results.gcp.ok && results.s3.ok && results.stripe.ok && results.ai.ok && results.r2Provision.ok
  );
}

// POST /validate — run all validators and return each {ok, detail} plus an
// aggregate. This is the endpoint the agency polls while fixing red items.
async function handleValidate(env: Env): Promise<Response> {
  const results = await validateAll(env);
  return json({ ok: allGreen(results), ...results });
}

// GET /whoami — proves the Direction-A token exchange end-to-end by calling our
// app's /api/agency/me with the bearer token and returning the resolved account.
async function handleWhoami(env: Env): Promise<Response> {
  try {
    const response = await callApp(env, "/api/agency/me", { method: "GET" });
    if (!response.ok) {
      const body = (await response.text()).slice(0, 300);
      return json(
        { ok: false, detail: `app /api/agency/me returned HTTP ${response.status}`, body },
        502,
      );
    }
    const data = (await response.json()) as { accountId?: string; account_id?: string };
    return json({ ok: true, accountId: data.accountId ?? data.account_id ?? null });
  } catch (err) {
    return json(
      { ok: false, detail: `Direction-A token exchange or app call failed: ${errorMessage(err)}` },
      502,
    );
  }
}

// POST /complete — re-validate; only if ALL green, call our app's
// onboarding-complete route (Slice E). That route may not exist yet, so a
// 404/non-200 is handled gracefully and reported — this Worker is
// forward-compatible: the callback simply flips to ok once the app route ships.
async function handleComplete(env: Env): Promise<Response> {
  const results = await validateAll(env);
  if (!allGreen(results)) {
    return json(
      {
        ok: false,
        validation: results,
        callback: null,
        detail: "Not all credentials validated — fix the red items and retry.",
      },
      409,
    );
  }

  try {
    const response = await callApp(env, "/api/agency/onboarding-complete", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ validated: true }),
    });

    if (response.ok) {
      const data = await response.json().catch(() => ({}));
      return json({
        ok: true,
        validation: results,
        callback: { ok: true, status: response.status, response: data },
      });
    }

    if (response.status === 404) {
      // Slice E hasn't shipped the app route yet. Credentials are all green;
      // report clearly so the wizard can retry once the callback exists.
      return json({
        ok: true,
        validation: results,
        callback: {
          ok: false,
          status: 404,
          detail:
            "app onboarding-complete callback not yet available (Slice E) — credentials are all green; retry once the app route ships.",
        },
      });
    }

    const body = (await response.text()).slice(0, 300);
    return json({
      ok: true,
      validation: results,
      callback: {
        ok: false,
        status: response.status,
        detail: `app onboarding-complete callback returned HTTP ${response.status}: ${body}`,
      },
    });
  } catch (err) {
    return json({
      ok: true,
      validation: results,
      callback: { ok: false, detail: `app onboarding-complete callback failed: ${errorMessage(err)}` },
    });
  }
}

// POST /actuate — Direction-B signed dispatch. Body: { job, signature }. The job is
// verified (ed25519 over the canonical bytes with the agency's own public key, a fresh
// timestamp, an allowlisted op) BEFORE anything happens; a failed verification returns
// 401 and does NOTHING. Only provision-r2 is wired today. The actuator uses the agency's
// OWN R2_PROVISION_API_TOKEN — never a platform credential (there is none here).
async function handleActuate(request: Request, env: Env): Promise<Response> {
  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return json({ ok: false, error: "body must be JSON" }, 400);
  }
  if (!payload || typeof payload !== "object") {
    return json({ ok: false, error: "body must be a JSON object { job, signature }" }, 400);
  }
  const { job, signature } = payload as { job?: unknown; signature?: unknown };

  const verdict = await verifyDispatch({
    rawJob: job,
    signatureB64: signature,
    publicKeyPem: signingPublicKey(env),
  });
  if (!verdict.ok) {
    // Fail closed: nothing is actuated. 401 for any verification failure (bad signature,
    // stale timestamp, disallowed op, missing key) — the reason is a non-secret code.
    return json({ ok: false, error: "unverified dispatch", reason: verdict.reason }, 401);
  }

  // Verified. Dispatch on the (already allowlisted) op.
  if (verdict.job.op === "provision-r2") {
    if (!isValidR2BucketName(verdict.job.bucketName)) {
      return json({ ok: false, error: "invalid bucket name", bucket: verdict.job.bucketName }, 400);
    }
    const result = await actuateProvisionR2(verdict.job.bucketName, env);
    // Always 200 with a structured result: a CF failure is reported in ok:false + detail,
    // not as a transport error, so the orchestrator classifies it (not the HTTP layer).
    return json(result, 200);
  }

  // Unreachable: verifyDispatch already rejects any non-allowlisted op. Belt-and-braces.
  return json({ ok: false, error: `unsupported op "${verdict.job.op}"` }, 400);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    // Normalize a trailing slash so "/validate/" matches "/validate"; keep "/".
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method;

    if (method === "GET" && path === "/") {
      return handleSetupPage(env);
    }
    if (method === "GET" && path === "/health") {
      return json({ ok: true, service: "agency-orchestrator" });
    }
    if (method === "POST" && path === "/validate") {
      return handleValidate(env);
    }
    if (method === "GET" && path === "/whoami") {
      return handleWhoami(env);
    }
    if (method === "POST" && path === "/complete") {
      return handleComplete(env);
    }
    if (method === "POST" && path === "/actuate") {
      return handleActuate(request, env);
    }

    return json({ ok: false, error: "not found" }, 404);
  },
};
