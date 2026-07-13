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
//
// NOTE on inbound auth: the direction OUR app → this Worker (so the wizard can
// display live status) is the Direction-B signed handshake, which is PHASE 2.
// In Phase 1 the agency triggers /validate and /complete themselves, so these
// routes are intentionally left open (no Direction-B signature verification yet).

import type { Env } from "./env.js";
import { callApp } from "./app-client.js";
import { validateAll, type AllValidations } from "./validators.js";
import { renderSetupPage } from "./setup-page.js";
import { errorMessage } from "./util.js";

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
  return results.gcp.ok && results.s3.ok && results.stripe.ok && results.ai.ok;
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

    return json({ ok: false, error: "not found" }, 404);
  },
};
