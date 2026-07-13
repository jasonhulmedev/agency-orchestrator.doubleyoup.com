// Small shared helpers used across the validators, the app client, and the
// router. Kept dependency-free (Worker runtime = fetch + Web Crypto only).

// Turn an unknown thrown value into a human-readable string for a `detail`
// field. `fetch()` and `crypto.subtle` reject with `Error`s, but a `throw`
// anywhere can be any value, so guard rather than assume `.message` exists.
export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

// Pull the text content of a simple, non-nested XML tag (e.g. S3's `<Code>` in
// an error body). Returns null when absent. Deliberately naive — S3 error
// bodies are flat and we only want a short, actionable hint, not a parser.
export function extractXmlTag(xml: string, tag: string): string | null {
  const match = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(xml);
  return match ? match[1] : null;
}

// Normalize a base URL so path concatenation (`${base}${path}`) never produces
// a double slash. APP_BASE_URL and S3_ENDPOINT are agency-typed config, so a
// trailing slash is a realistic input.
export function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
