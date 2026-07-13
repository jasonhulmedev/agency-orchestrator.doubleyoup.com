// The thin landing page served at GET /.
//
// The full per-credential "how to generate + how to add a secret" instructions
// live in the APP onboarding wizard (Step 2) — one central, instantly-updatable
// source of truth — NOT here. This page is deliberately thin: a short intro, the
// Worker's one genuinely-standalone feature (a live self-check of its own
// secrets, which needs no app login), and a prominent link into the app wizard.
//
// Worker-native: this module returns a single self-contained HTML string with
// inline CSS + inline JS only — no external assets, CDNs or fonts. The router
// wraps it in `new Response(html, { headers: { "content-type": "text/html" } })`.

import type { Env } from "./env.js";
import { stripTrailingSlash } from "./util.js";

// Escape a value for safe interpolation into HTML text or a double-quoted
// attribute. APP_BASE_URL is agency-controlled config rather than untrusted
// input, but escaping keeps the page well-formed regardless of what's set.
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// The inline browser script. Kept as a plain string (NOT a template literal) so
// it never needs `${...}` — that would collide with the outer template literal
// this file returns. It wires the "Check my setup" button to POST /validate and
// renders each credential's {ok, detail}. It never displays secret VALUES.
const INLINE_SCRIPT = `
(function () {
  var button = document.getElementById("check-button");
  var resultsPanel = document.getElementById("results");
  var overallLine = document.getElementById("overall");

  // Human labels for each validator key returned by POST /validate.
  var labels = {
    gcp: "Google Cloud",
    s3: "S3 / object storage",
    stripe: "Stripe",
    ai: "AI providers"
  };
  var orderedKeys = ["gcp", "s3", "stripe", "ai"];

  function renderResult(key, result) {
    var ok = !!(result && result.ok === true);
    var detail = (result && result.detail) ? result.detail : "No detail returned.";

    var row = document.createElement("div");
    row.className = "result-row " + (ok ? "result-ok" : "result-bad");

    var icon = document.createElement("span");
    icon.className = "result-icon";
    icon.textContent = ok ? "✓" : "✗"; // green tick / red cross

    var text = document.createElement("div");
    text.className = "result-text";

    var name = document.createElement("strong");
    name.textContent = labels[key] || key;

    var desc = document.createElement("div");
    desc.className = "result-detail";
    desc.textContent = detail; // textContent, never innerHTML — no value leakage

    text.appendChild(name);
    text.appendChild(desc);
    row.appendChild(icon);
    row.appendChild(text);
    return row;
  }

  async function check() {
    button.disabled = true;
    button.textContent = "Checking\\u2026";
    resultsPanel.innerHTML = "";
    overallLine.textContent = "";
    overallLine.className = "overall";

    try {
      var response = await fetch("/validate", { method: "POST" });
      var data = await response.json();

      for (var i = 0; i < orderedKeys.length; i++) {
        var key = orderedKeys[i];
        resultsPanel.appendChild(renderResult(key, data[key]));
      }

      if (data && data.ok === true) {
        overallLine.textContent = "All credentials validated \\u2014 you're ready to finish onboarding in doubleyoup.";
        overallLine.className = "overall overall-ok";
      } else {
        overallLine.textContent = "Some credentials still need attention \\u2014 set them up in the doubleyoup onboarding wizard, then check again here.";
        overallLine.className = "overall overall-bad";
      }
    } catch (err) {
      overallLine.textContent = "Couldn't reach the validation endpoint. Check your connection and try again.";
      overallLine.className = "overall overall-bad";
    } finally {
      button.disabled = false;
      button.textContent = "Check my setup";
    }
  }

  button.addEventListener("click", check);
})();
`;

// Build the whole self-contained HTML page. `env` supplies APP_BASE_URL (the
// onboarding link); we fall back to the public app host if it's unset.
export function renderSetupPage(env: Env): string {
  const appBaseUrl = stripTrailingSlash(env.APP_BASE_URL || "https://app.doubleyoup.com");
  const onboardingUrl = escapeHtml(`${appBaseUrl}/onboarding`);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>doubleyoup agency-orchestrator</title>
  <style>
    :root {
      --ink: #1a1a2e;
      --muted: #5a5a72;
      --line: #e2e2ec;
      --bg: #f6f7fb;
      --card: #ffffff;
      --accent: #4338ca;
      --accent-ink: #ffffff;
      --ok: #15803d;
      --ok-bg: #e8f6ec;
      --bad: #b91c1c;
      --bad-bg: #fdecec;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      color: var(--ink);
      background: var(--bg);
      line-height: 1.55;
    }
    .wrap { max-width: 640px; margin: 0 auto; padding: 48px 20px 72px; }
    header h1 { font-size: 1.6rem; margin: 0 0 8px; }
    header p.lead { color: var(--muted); margin: 0; }
    h2 { font-size: 1.1rem; margin: 36px 0 6px; }
    a { color: var(--accent); }
    /* Primary call-to-action into the app onboarding wizard. */
    a.cta {
      display: inline-block;
      margin-top: 12px;
      padding: 13px 24px;
      background: var(--accent);
      color: var(--accent-ink);
      border-radius: 10px;
      text-decoration: none;
      font-weight: 700;
    }
    a.cta:hover { opacity: 0.92; }
    /* Self-check panel. */
    .check-block { margin-top: 40px; }
    p.check-lead { color: var(--muted); margin: 0 0 12px; }
    button#check-button {
      appearance: none;
      border: 2px solid var(--accent);
      background: var(--card);
      color: var(--accent);
      font-size: 1rem;
      font-weight: 700;
      padding: 11px 22px;
      border-radius: 10px;
      cursor: pointer;
    }
    button#check-button:hover { background: #eef0fb; }
    button#check-button:disabled { opacity: 0.6; cursor: default; }
    #results { margin-top: 16px; }
    .result-row {
      display: flex;
      gap: 12px;
      align-items: flex-start;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 12px 14px;
      margin: 8px 0;
      background: var(--card);
    }
    .result-row.result-ok { border-color: #bfe6ca; background: var(--ok-bg); }
    .result-row.result-bad { border-color: #f3c4c4; background: var(--bad-bg); }
    .result-icon { font-size: 1.2rem; font-weight: 700; line-height: 1.4; }
    .result-ok .result-icon { color: var(--ok); }
    .result-bad .result-icon { color: var(--bad); }
    .result-text strong { display: block; }
    .result-detail { color: var(--muted); font-size: 0.92rem; }
    .overall { margin-top: 14px; font-weight: 600; }
    .overall-ok { color: var(--ok); }
    .overall-bad { color: var(--bad); }
    footer { margin-top: 44px; color: var(--muted); font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>Your doubleyoup agency-orchestrator</h1>
      <p class="lead">
        This is the always-on glue Worker running in your own Cloudflare account.
        Set up and connect your credentials in the doubleyoup onboarding wizard;
        this page lets you self-check that they work.
      </p>
    </header>

    <h2>Set up your credentials</h2>
    <p class="lead">
      All the step-by-step instructions &mdash; how to generate each credential
      and add it as a secret &mdash; live in the doubleyoup onboarding wizard, so
      they're always current.
    </p>
    <a class="cta" href="${onboardingUrl}" target="_blank" rel="noopener noreferrer">Set up credentials &amp; finish onboarding &rarr;</a>

    <div class="check-block">
      <h2>Check my setup</h2>
      <p class="check-lead">
        Runs a live, read-only test of each credential this Worker holds. Secret
        values are never shown &mdash; only whether each one works.
      </p>
      <button id="check-button" type="button">Check my setup</button>
      <div id="results"></div>
      <div id="overall" class="overall"></div>
    </div>

    <footer>
      doubleyoup agency-orchestrator &middot; Phase 1 (onboarding &amp; credential
      self-validation). This Worker stores no credentials of its own.
    </footer>
  </div>
  <script>${INLINE_SCRIPT}</script>
</body>
</html>`;
}
