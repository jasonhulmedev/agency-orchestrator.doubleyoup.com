import { describe, it, expect } from "vitest";
import worker from "../src/index.js";
import type { Env } from "../src/env.js";

// Only the always-required fields; the setup page and /validate work with no
// service credentials configured (validators report "not configured").
const baseEnv: Env = {
  APP_BASE_URL: "https://app.example.test",
  DY_CLIENT_ID: "client-abc",
  DY_CLIENT_SECRET: "secret-xyz",
};

function request(method: string, path: string): Request {
  return new Request(`http://localhost${path}`, { method });
}

describe("GET / setup page", () => {
  it("returns 200 text/html with the expected markers", async () => {
    const response = await worker.fetch(request("GET", "/"), baseEnv);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/text\/html/);

    const html = await response.text();
    // The self-check button + the onboarding CTA are both present.
    expect(html).toContain("Check my setup");
    expect(html).toContain("/onboarding");
    expect(html).toContain("finish onboarding");
    // The inline script wires the button to POST /validate.
    expect(html).toContain('fetch("/validate", { method: "POST" })');
    // No unresolved template-literal placeholders leaked into the output.
    expect(html).not.toContain("${");
    expect(html).not.toContain("undefined");
  });

  it("builds the onboarding link from APP_BASE_URL", async () => {
    const response = await worker.fetch(request("GET", "/"), baseEnv);
    const html = await response.text();
    expect(html).toContain("https://app.example.test/onboarding");
  });

  it("falls back to the public app host when APP_BASE_URL is empty", async () => {
    const response = await worker.fetch(request("GET", "/"), { ...baseEnv, APP_BASE_URL: "" });
    const html = await response.text();
    expect(html).toContain("https://app.doubleyoup.com/onboarding");
  });
});

describe("existing endpoints still work", () => {
  it("GET /health returns the liveness JSON", async () => {
    const response = await worker.fetch(request("GET", "/health"), baseEnv);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/application\/json/);
    const body = await response.json();
    expect(body).toEqual({ ok: true, service: "agency-orchestrator" });
  });

  it("POST /validate returns each credential result (all not-configured here)", async () => {
    const response = await worker.fetch(request("POST", "/validate"), baseEnv);
    expect(response.status).toBe(200);

    const body = (await response.json()) as {
      ok: boolean;
      gcp: { ok: boolean };
      s3: { ok: boolean };
      stripe: { ok: boolean };
      ai: { ok: boolean };
    };
    expect(body.ok).toBe(false);
    expect(body.gcp.ok).toBe(false);
    expect(body.s3.ok).toBe(false);
    expect(body.stripe.ok).toBe(false);
    expect(body.ai.ok).toBe(false);
  });

  it("returns 404 for an unknown path", async () => {
    const response = await worker.fetch(request("GET", "/nope"), baseEnv);
    expect(response.status).toBe(404);
  });
});
