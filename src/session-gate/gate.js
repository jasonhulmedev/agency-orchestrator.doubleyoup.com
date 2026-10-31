// dy-session-gate v2
// The FIRST LINE above is the gate's marker and version. edge-gate-deploy (src/actuate-edge-gate.ts)
// reads it back from the deployed script: a script whose source does not start with "// dy-session-gate v"
// was not made by this platform, so it is never replaced. Raise the version whenever this file changes
// (test/session-gate.test.ts pins this file's sha256 to the version and fails until you do), so every cell
// takes the new gate on its next deploy.
//
// THE PER-CELL SESSION EDGE GATE (planning/49 §3.2, §5.1; Phase 3 increment I4). It is the ingress of the
// IAM-only Cloud Run session services of ONE cell (term-<slug>, and in Phase 4 pma-, staging-, sterm- and
// spma-<slug>), in the agency's own Cloudflare account. Ported from the platform's syd gate (infra
// cell-run/edge-gate/worker.js). The agency Worker uploads this file as the script
// dy-gate-<project>-<region>, and a Workers route per session host sends `<label>.<zone>` here.
//
//   browser -> https://<label>.<zone>/...?token=<session token>
//           -> this gate: verify the token AT THE EDGE. Invalid or absent: 401, NO origin fetch, so a
//              bot never wakes the scale-to-zero container, and no minter call.
//           -> fetch https://<label><DY_RUN_URL_SUFFIX>/... (same method, path, query and body; on a pma-,
//              spma- or staging- host the query loses the session token, see X-DY-Session-Token) with
//              X-Serverless-Authorization: Bearer <Google ID token for that URL>
//           -> Cloud Run (ingress all, IAM-authenticated, no allUsers). The container verifies the
//              session token AGAIN (infra cell-run/terminal-image/server/token.js).
//
// BINDINGS (set by edge-gate-deploy; a missing or malformed one is a 500 config error, never a proxy):
//   DY_SESSION_SECRET   secret_text  the cell's session secret, 64 lowercase hex. Its only copy.
//   DY_ZONE_SUFFIX      plain_text   "." + the cell's Cloudflare zone, e.g. ".sbmstudio.com.au".
//   DY_RUN_URL_SUFFIX   plain_text   "-<projectNumber>.<region>.run.app". The Cloud Run service name IS the
//                                    host label, so origin = "https://" + label + this suffix: no per-session
//                                    state, nothing to clean up but the route.
//   DY_MINTER           service      the agency Worker's SessionGateMinter entrypoint. This gate holds NO
//                                    Google key (planning/49 decision A): it asks the agency's own Worker for
//                                    an ID token, and the minter signs only for this project's session URLs.
//   DY_MINTER_CALLER_KEY secret_text this gate's minter caller key, 64 lowercase hex (v2, see below).
//   DY_SESSION_KEY_VERSION, DY_SESSION_KEY_FINGERPRINT, DY_MINTER_CALLER_FINGERPRINT  plain_text, read by
//                                    edge-gate-deploy only.
//
// THE MINTER CALLER PROOF (v2; planning/49 Phase 4, decision D1 A). A service binding carries no caller
// identity, so the minter cannot tell this gate from any other script in the account that binds it. So
// every mint call carries a proof made with DY_MINTER_CALLER_KEY: the HKDF of the agency Worker's
// DY_CLIENT_SECRET, bound to this gate's script name. A Worker script cannot read another script's secrets,
// so no other script in the account can make the proof:
//   DY_MINTER.mintIdToken({ audience, ts, mac })
//   ts  = Unix seconds now
//   mac = base64url(HMAC_SHA256("v1|" + audience + "|" + ts, the 32 bytes of DY_MINTER_CALLER_KEY)), no padding
// The minter refuses a proof more than 60 s from its clock. A v1 gate sent the bare audience string with no
// proof; the minter serves that only for term- and sterm- (whose container checks the session token again).
// VERSION SKEW (review M1): an agency Worker rolled back below this gate's release reads only the bare
// string, and answers the object with "audience-refused". For a term- or sterm- host ONLY, the gate then
// asks once more with the bare string (see idTokenFor). pma-, spma- and staging- never ask without the proof.
//
// TOKEN FORMAT (v1, unchanged from syd; MUST match the orchestrator's mintSessionToken, app's
// mintEphemeralSessionToken and the container's verifier byte for byte):
//   token       = base64url(payloadJson) + "." + base64url(HMAC_SHA256(base64url(payloadJson), hostKey))
//   payloadJson = {"siteId":"<cuid>","slug":"<slug>","purpose":"terminal|pma|staging","uid":<int>,"exp":<unixSeconds>}
//
// THE KEY (hub#76, planning/49 §5.2): hostKey = HKDF-SHA256(ikm = the UTF-8 TEXT of DY_SESSION_SECRET, empty
// salt, info = "doubleyoup-ephemeral-session-v1/host:" + the full lower-cased host, 32 bytes). Each session
// container holds only its own host's key, so a key read from one container signs for that host only.
// There is NO fallback to the secret itself (syd's EPHEMERAL_SESSION_ACCEPT_MASTER is not carried over).
//
// WHAT THE CONTAINER NEEDS, and so what forwarding keeps: the terminal reads the token ONLY from the
// `token` query parameter, on GET / and on the WebSocket upgrade /ws?token=... (infra terminal-image/server
// index.js). It reads no cookie and no Authorization header, and its page inlines every asset, so the real
// page makes exactly two requests: GET /?token=T, then the WebSocket /ws?token=T to location.host. So on a
// terminal host (term-, sterm-) the path and query pass unchanged, and NO Cookie header is forwarded. The
// other session hosts forward their cookies without the gate's own. The ID token goes in
// X-Serverless-Authorization: when both headers are present, Cloud Run checks only that one, so the client's
// own Authorization header still reaches the container (a session image that does its own HTTP auth keeps
// working).
//
// X-DY-Session-Token (v2): the session token this gate just verified, for a container that checks it again
// from a header. The gate ALWAYS deletes any X-DY-Session-Token the client sent, so the container never
// sees a header the gate did not write. It sets the header on pma-, spma- and staging- hosts (phpMyAdmin
// and the staging image check it before any of their own code runs, planning/49 Phase 4 decision D1 C and
// DS3). On those hosts a verified ?token= is also REMOVED from the query the origin gets: the container
// has the token in the header, Cloud Run and the web server do not log it, and phpMyAdmin does not read it
// as its own CSRF `token`. A terminal host (term-, sterm-) keeps its own token path (the query) and gets no
// header.
//
// WHICH TOKEN COUNTS. A ?token= that verifies for this host is the session token, and wins over the cookie
// (a fresh token over a stale one). A ?token= that does NOT verify is not a session token: phpMyAdmin's GET
// forms and links send their own CSRF `token`. That request is then a COOKIE-ONLY request, under the rule
// below, and the gate sets no cookie from it. So a cross-site link with ?token=<anything> gets no further
// than a cross-site link with no token.
//
// COOKIE-ONLY REQUESTS (no verified ?token=) are the ones a cross-site page could cause the browser to send
// with the gate's cookie attached, so they must come from this host's own pages: Sec-Fetch-Site must be
// "same-origin" or "none" (typed into the address bar). Every WebSocket upgrade, with or without ?token=,
// must carry Origin: https://<this host> (the real page opens it from this host). Otherwise 401, no fetch.
//
// THE TOKEN-STRIP PAGE (planning/49 Phase 4: decision DS5 for staging-, and Jason's 2026-10-31 decision for
// pma- and spma-, which replaces D4). A GET or HEAD on a pma-, spma- or staging- host with a verified
// ?token= does not reach the origin. The gate sets its cookie and answers a small page of its own (no-store,
// no external resources, a CSP that allows only the page's one inline script, no Referer). The script calls
// location.replace() with the same URL without the session token. The browser then asks again from this
// host's own page (Sec-Fetch-Site: same-origin) with the cookie. So:
//   - the token is not left in the address bar, the history or a Referer;
//   - a redirect from the origin (for example a 3xx on the first phpMyAdmin request) is followed from a
//     same-origin request, so the cookie-only rule lets it through.
// A 302 from the gate cannot do this: the browser keeps Sec-Fetch-Site "cross-site" across a redirect from
// the app's navigation, and the cookie-only rule would refuse the next request. Any other method, and a
// WebSocket upgrade, goes to the origin with the token removed from the query. term- and sterm- hosts never
// get the page: the terminal container reads the token from the query of GET / and of /ws, so it stays in
// the URL there.

// The gate's httpOnly session cookie (set below, read only by this gate). The __Host- prefix makes the
// browser accept it only with Secure, Path=/ and no Domain, so it is bound to this exact host and no
// sibling host of the zone can set or overwrite it.
const COOKIE_NAME = "__Host-dy_egt";
const KEY_INFO_PREFIX = "doubleyoup-ephemeral-session-v1/host:";
const HOST_KEY_BITS = 256;
// A cached ID token is used until this many seconds before its exp, then minted again.
const ID_TOKEN_REFRESH_MARGIN_SECONDS = 300;
// The version tag at the start of every minter caller proof message (see THE MINTER CALLER PROOF above).
const MINTER_CALLER_PROOF_VERSION = "v1";
// The header that carries the verified session token to a pma-, spma- or staging- container (see
// X-DY-Session-Token).
const SESSION_TOKEN_HEADER = "x-dy-session-token";
// The query parameter that carries the session token in the URL the app opens.
const TOKEN_QUERY_PARAMETER = "token";
// The purposes whose container reads the session token from X-DY-Session-Token: "pma" (pma-, spma-) and
// "staging" (staging-). The token is not needed in their URL, so these hosts also get the token-strip page
// and a forwarded query without the token. A "terminal" container (term-, sterm-) reads the token from the
// query only.
const HEADER_TOKEN_PURPOSES = ["pma", "staging"];
// The one inline script of the token-strip page. Constant, so the page's CSP pins its hash. It reads the
// target from the page's own link, so no request data is ever script text.
const TOKEN_STRIP_SCRIPT = 'location.replace(document.getElementById("next").href);';

// Binding grammars. Checked on every request, so a mis-set binding is a config error and can never turn the
// gate into a proxy to some other host.
const SESSION_SECRET_RE = /^[0-9a-f]{64}$/;
const MINTER_CALLER_KEY_RE = /^[0-9a-f]{64}$/;
const ZONE_SUFFIX_RE = /^(?:\.(?!-)[a-z0-9_-]{1,63}(?<!-)){2,}$/;
const RUN_URL_SUFFIX_RE = /^-[1-9][0-9]{0,19}\.[a-z]+-[a-z0-9]+\.run\.app$/;

// The session service name grammar of the twin (agency Worker src/dispatch-params.ts,
// splitCloudRunSessionServiceName): a Cloud Run service name (at most 49 characters) that is one session
// prefix + "-" + a site slug (at most 46 characters, alphanumeric at both ends). A copy, because this file
// is uploaded alone and imports nothing; test/session-gate.test.ts checks the two agree.
const SESSION_LABEL_RE = /^[a-z]([-a-z0-9]{0,47}[a-z0-9])?$/;
const SITE_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,44}[a-z0-9])?$/;

// The host PREFIX is the authority for the token's purpose (syd's mapping, unchanged): `term-` and `sterm-`
// need a "terminal" token, `pma-` and `spma-` a "pma" token, `staging-` a "staging" token. The staging-scoped
// sessions (hub#37) reuse the stock purposes; only the host tells them apart, and each host has its own key.
// No two prefixes overlap once the hyphen is included ("term-" is not a prefix of "sterm-"), so at most one
// prefix matches a label.
const SESSION_PREFIXES = [
  { prefix: "term-", purpose: "terminal" },
  { prefix: "pma-", purpose: "pma" },
  { prefix: "sterm-", purpose: "terminal" },
  { prefix: "spma-", purpose: "pma" },
  { prefix: "staging-", purpose: "staging" },
];

// Per-isolate ID token cache: audience -> { idToken, expiresAt }. An entry exists only after a request with
// a valid session token for that host, so nothing unauthenticated can grow it.
const idTokenCache = new Map();

// The reason the bindings cannot serve a request, or null. Names a binding, never a value.
export function configurationProblem(env) {
  if (typeof env.DY_SESSION_SECRET !== "string" || !SESSION_SECRET_RE.test(env.DY_SESSION_SECRET)) {
    return "DY_SESSION_SECRET is not set to 64 lowercase hex characters";
  }
  if (typeof env.DY_ZONE_SUFFIX !== "string" || !ZONE_SUFFIX_RE.test(env.DY_ZONE_SUFFIX)) {
    return "DY_ZONE_SUFFIX is not set to \".<zone>\"";
  }
  if (typeof env.DY_RUN_URL_SUFFIX !== "string" || !RUN_URL_SUFFIX_RE.test(env.DY_RUN_URL_SUFFIX)) {
    return "DY_RUN_URL_SUFFIX is not set to \"-<projectNumber>.<region>.run.app\"";
  }
  if (!env.DY_MINTER) {
    return "DY_MINTER (the service binding to the agency Worker's SessionGateMinter) is not set";
  }
  if (typeof env.DY_MINTER_CALLER_KEY !== "string" || !MINTER_CALLER_KEY_RE.test(env.DY_MINTER_CALLER_KEY)) {
    return "DY_MINTER_CALLER_KEY is not set to 64 lowercase hex characters";
  }
  return null;
}

// Map a request host to the claims its token must carry, or null when the host is not EXACTLY
// `<session service name><zoneSuffix>`: one label, a session prefix, a site slug. `host` (the full
// lower-cased hostname) is what the signing key is derived from; `label` is the Cloud Run service name.
export function resolveHostTarget(hostname, zoneSuffix) {
  const host = hostname.toLowerCase();
  if (!host.endsWith(zoneSuffix)) {
    return null;
  }
  const label = host.slice(0, host.length - zoneSuffix.length);
  if (!SESSION_LABEL_RE.test(label)) {
    return null;
  }
  for (const entry of SESSION_PREFIXES) {
    if (!label.startsWith(entry.prefix)) {
      continue;
    }
    const slug = label.slice(entry.prefix.length);
    if (!SITE_SLUG_RE.test(slug)) {
      return null;
    }
    return { expectedPurpose: entry.purpose, slug, host, label };
  }
  return null;
}

// Derive one host's signing key from the cell's session secret (hub#76 recipe, see THE KEY above). MUST
// match the orchestrator's deriveSessionHostKey and app's deriveEphemeralHostKey byte for byte.
export async function deriveHostKey(sessionSecret, hostname) {
  const ikm = await crypto.subtle.importKey("raw", new TextEncoder().encode(sessionSecret), "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(KEY_INFO_PREFIX + hostname.toLowerCase()),
    },
    ikm,
    HOST_KEY_BITS,
  );
  return new Uint8Array(bits);
}

// base64url(bytes) with NO padding, as Node's digest("base64url").
function bytesToBase64url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Decode a base64url string to its UTF-8 text, or null on a malformed input (a hostile token must never
// crash the gate).
function base64urlToUtf8(value) {
  let standard = value.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = standard.length % 4;
  if (remainder === 1) {
    return null; // impossible for valid base64
  }
  if (remainder === 2) {
    standard += "==";
  } else if (remainder === 3) {
    standard += "=";
  }
  let binary;
  try {
    binary = atob(standard);
  } catch (decodeError) {
    return null;
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

// Constant-time comparison of two ASCII strings (the two base64url signatures), so timing does not leak
// signature bytes.
function timingSafeEqualStrings(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return difference === 0;
}

// Verify a v1 session token with ONE host key (no fallback key). The HMAC is recomputed over the RECEIVED
// base64url payload, never over re-serialized JSON, then the claims are checked: purpose from the host
// prefix, slug from the host, exp in the future. Returns the claims, or null.
export async function verifyToken(token, hostKey, expectedPurpose, expectedSlug) {
  if (typeof token !== "string" || token.length === 0) {
    return null;
  }
  const dot = token.indexOf(".");
  if (dot <= 0 || dot === token.length - 1) {
    return null;
  }
  const payloadB64 = token.slice(0, dot);
  const signatureB64 = token.slice(dot + 1);
  // A well-formed v1 token has exactly one dot.
  if (signatureB64.indexOf(".") !== -1) {
    return null;
  }

  const key = await crypto.subtle.importKey("raw", hostKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signatureBytes = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64)));
  if (!timingSafeEqualStrings(signatureB64, bytesToBase64url(signatureBytes))) {
    return null;
  }

  // The signature is authentic: decode and check the claims.
  const payloadJson = base64urlToUtf8(payloadB64);
  if (payloadJson === null) {
    return null;
  }
  let payload;
  try {
    payload = JSON.parse(payloadJson);
  } catch (parseError) {
    return null;
  }
  if (payload === null || typeof payload !== "object") {
    return null;
  }
  if (payload.purpose !== expectedPurpose) {
    return null;
  }
  if (payload.slug !== expectedSlug) {
    return null;
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(payload.exp) || payload.exp <= nowSeconds) {
    return null;
  }
  return payload;
}

// Read one cookie value from the request's Cookie header, or null.
function readCookie(request, name) {
  const header = request.headers.get("Cookie");
  if (!header) {
    return null;
  }
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) {
      continue;
    }
    if (part.slice(0, eq).trim() === name) {
      return part.slice(eq + 1).trim();
    }
  }
  return null;
}

// The Cookie header without the gate's own cookie. The container never reads it, and the session token
// in it should not travel past the gate.
function cookieHeaderWithoutGateCookie(header) {
  const kept = [];
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (trimmed === "") {
      continue;
    }
    let name = trimmed;
    const eq = trimmed.indexOf("=");
    if (eq !== -1) {
      name = trimmed.slice(0, eq).trim();
    }
    if (name === COOKIE_NAME) {
      continue;
    }
    kept.push(trimmed);
  }
  return kept.join("; ");
}

// Decode lowercase hex to bytes. Only ever called on DY_MINTER_CALLER_KEY, which configurationProblem has
// already checked against MINTER_CALLER_KEY_RE.
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// The minter call for `audience` with its caller proof (see THE MINTER CALLER PROOF above):
// { audience, ts, mac }. MUST match the agency Worker's src/session-gate/caller-key.ts byte for byte:
// test/session-gate.test.ts pins it to an independent vector, and test/session-gate-minter.test.ts runs this
// gate against the minter.
async function minterRequestFor(env, audience) {
  const ts = Math.floor(Date.now() / 1000);
  const message = MINTER_CALLER_PROOF_VERSION + "|" + audience + "|" + ts;
  const key = await crypto.subtle.importKey("raw", hexToBytes(env.DY_MINTER_CALLER_KEY), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const macBytes = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
  return { audience, ts, mac: bytesToBase64url(macBytes) };
}

// One call to the minter. Its answer, or null when the call itself fails.
async function callMinter(env, mintRequest) {
  try {
    return await env.DY_MINTER.mintIdToken(mintRequest);
  } catch (mintError) {
    // A dropped RPC, or an agency Worker without the SessionGateMinter entrypoint (a fork that has not
    // synced): fail closed, and say nothing about why to the browser.
    return null;
  }
}

// True when the minter refused the audience itself (not the caller, and not for lack of a key).
function isAudienceRefusal(minted) {
  return Boolean(minted) && minted.ok === false && minted.reason === "audience-refused";
}

// An ID token for `audience` from the agency Worker's minter, cached per isolate until
// ID_TOKEN_REFRESH_MARGIN_SECONDS before its exp. Null when the minter refuses, fails or answers garbage.
// `expectedPurpose` is the host's purpose (resolveHostTarget).
async function idTokenFor(env, audience, expectedPurpose) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const cached = idTokenCache.get(audience);
  if (cached !== undefined && nowSeconds < cached.expiresAt - ID_TOKEN_REFRESH_MARGIN_SECONDS) {
    return cached.idToken;
  }
  // A fresh proof for every mint call: the minter refuses one older than 60 s, so a cached proof is no use.
  const mintRequest = await minterRequestFor(env, audience);
  let minted = await callMinter(env, mintRequest);

  // VERSION SKEW (review M1). An agency Worker rolled back below this gate's release reads only a bare
  // audience string, so it answers the object with "audience-refused". Its edge-gate-deploy refuses to put
  // an older gate back, so without this step such a rollback would break every terminal on the cell. So a
  // terminal host (term-, sterm-) asks ONCE more, the v1 way: the bare audience, no proof. The minter serves
  // that keyless form only for the terminal hosts, whose container checks the session token itself. Never
  // for pma-, spma- or staging-: they need the proof on every call, so the gate never asks for their ID
  // token without it. "caller-refused" (a wrong caller key) and "unavailable" are never asked again.
  if (expectedPurpose === "terminal" && isAudienceRefusal(minted)) {
    minted = await callMinter(env, audience);
  }

  if (!minted || minted.ok !== true || typeof minted.idToken !== "string" || typeof minted.expiresAt !== "number") {
    return null;
  }
  idTokenCache.set(audience, { idToken: minted.idToken, expiresAt: minted.expiresAt });
  return minted.idToken;
}

// `search` (URL.search: "" or "?...") without its FIRST `token` parameter, the one
// url.searchParams.get("token") reads. Every other parameter keeps its bytes and its order, so a later
// `token` (phpMyAdmin's own) stays. Empty parts ("&&", a trailing "&") may be dropped: no query parser
// reads them as a parameter, so this is harmless. "" when nothing is left.
function searchWithoutSessionToken(search) {
  const kept = [];
  let removed = false;
  for (const part of search.slice(1).split("&")) {
    if (part === "") {
      continue;
    }
    // The name exactly as url.searchParams decodes it. A part holds no "&", so it is one parameter. The
    // URLSearchParams constructor removes ONE leading "?", so the "?" put in front keeps a "?" that is part
    // of the name: "?token=X" is the parameter "?token", which get("token") never returns (review L1).
    const name = new URLSearchParams("?" + part).keys().next().value;
    if (!removed && name === TOKEN_QUERY_PARAMETER) {
      removed = true;
      continue;
    }
    kept.push(part);
  }
  if (kept.length === 0) {
    return "";
  }
  return "?" + kept.join("&");
}

// The request to the Cloud Run origin: the same method, headers and body as the browser's, to `originUrl`
// (the same path; the query as the fetch handler chose it). The gate's ID token REPLACES any
// X-Serverless-Authorization the client sent, and Cloud Run checks only that header when it is present, so
// only the gate's ID token decides Cloud Run's IAM check. The client's Authorization header passes to the container unchanged. Host
// is dropped so the runtime sets it from the URL: Cloud Run routes by Host. A terminal host forwards no
// Cookie header (the terminal reads none); another session host forwards its cookies minus the gate's.
// X-DY-Session-Token: the client's is always deleted; a pma-, spma- or staging- host gets `verifiedToken`,
// the session token this gate has just verified for this host (from the query or the gate cookie).
function originRequestFor(request, originUrl, idToken, target, verifiedToken) {
  const originRequest = new Request(originUrl, request);
  originRequest.headers.delete("host");
  originRequest.headers.set("x-serverless-authorization", "Bearer " + idToken);
  // Deleted on EVERY host: a container that reads this header must only ever see the value this gate wrote.
  originRequest.headers.delete(SESSION_TOKEN_HEADER);
  if (HEADER_TOKEN_PURPOSES.includes(target.expectedPurpose)) {
    originRequest.headers.set(SESSION_TOKEN_HEADER, verifiedToken);
  }
  if (target.expectedPurpose === "terminal") {
    originRequest.headers.delete("cookie");
    return originRequest;
  }
  const cookieHeader = originRequest.headers.get("cookie");
  if (cookieHeader !== null) {
    const keptCookies = cookieHeaderWithoutGateCookie(cookieHeader);
    if (keptCookies === "") {
      originRequest.headers.delete("cookie");
    } else {
      originRequest.headers.set("cookie", keptCookies);
    }
  }
  return originRequest;
}

const UNAUTHORIZED_HTML =
  "<!doctype html><meta charset=utf-8><title>401 Unauthorized</title>" +
  '<body style="font-family:monospace;background:#0b0e14;color:#e6e6e6;padding:2rem">' +
  "<h1>401 Unauthorized</h1><p>A valid session token is required.</p>";

function unauthorized() {
  return new Response(UNAUTHORIZED_HTML, {
    status: 401,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

// True for a WebSocket upgrade request.
function isWebSocketUpgrade(request) {
  const upgradeHeader = request.headers.get("Upgrade");
  if (!upgradeHeader) {
    return false;
  }
  return upgradeHeader.toLowerCase() === "websocket";
}

// True when the request may be served from what it carries, by where it came from (see COOKIE-ONLY
// REQUESTS above). `hasVerifiedQueryToken`: the URL carries this host's session token, verified.
function requestContextAllowed(request, host, hasVerifiedQueryToken) {
  if (isWebSocketUpgrade(request)) {
    return request.headers.get("Origin") === "https://" + host;
  }
  if (hasVerifiedQueryToken) {
    return true;
  }
  const fetchSite = request.headers.get("Sec-Fetch-Site");
  return fetchSite === "same-origin" || fetchSite === "none";
}

function plainResponse(status, text) {
  return new Response(text, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
}

// The gate's Set-Cookie value for a session token that came in the URL. It lives no longer than the token,
// and the gate re-checks exp on every request anyway.
function gateCookieFor(session) {
  const remainingSeconds = Math.max(0, session.claims.exp - Math.floor(Date.now() / 1000));
  return `${COOKIE_NAME}=${session.token}; Path=/; Max-Age=${remainingSeconds}; HttpOnly; Secure; SameSite=Lax`;
}

// Escape text for a double-quoted HTML attribute value.
function escapeHtmlAttribute(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// The CSP source of a script: 'sha256-' + base64(SHA-256(the script text)), standard base64 with padding.
async function cspScriptHashSource(scriptText) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(scriptText)));
  let binary = "";
  for (let i = 0; i < digest.length; i++) {
    binary += String.fromCharCode(digest[i]);
  }
  return "'sha256-" + btoa(binary) + "'";
}

// The token-strip page (see THE TOKEN-STRIP PAGE above). `nextUrl` is ABSOLUTE, on this
// host, so no path (for example "//elsewhere.example/") can make it leave this host. The link is also the
// way on for a browser without script.
async function tokenStripPage(nextUrl, session) {
  const html =
    "<!doctype html><meta charset=utf-8><title>Opening the session</title>" +
    '<a id="next" href="' +
    escapeHtmlAttribute(nextUrl) +
    '">Continue</a><script>' +
    TOKEN_STRIP_SCRIPT +
    "</script>";
  const contentSecurityPolicy =
    "default-src 'none'; script-src " +
    (await cspScriptHashSource(TOKEN_STRIP_SCRIPT)) +
    "; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": contentSecurityPolicy,
    // The page's URL holds the token: no Referer may carry it to the next request.
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  });
  headers.append("Set-Cookie", gateCookieFor(session));
  return new Response(html, { status: 200, headers });
}

// True for a request that gets the token-strip page instead of the origin.
function getsTokenStripPage(request, target, session) {
  if (!session.fromQuery || !HEADER_TOKEN_PURPOSES.includes(target.expectedPurpose)) {
    return false;
  }
  if (isWebSocketUpgrade(request)) {
    return false;
  }
  // A page load. Any other method goes to the origin (without the token): a page must not drop its body.
  return request.method === "GET" || request.method === "HEAD";
}

export default {
  async fetch(request, env) {
    const problem = configurationProblem(env);
    if (problem !== null) {
      // Fail closed and loud: without its bindings the gate can validate nothing and must NOT proxy.
      // 500, not 401, so an operator can tell a config error from an auth failure.
      return plainResponse(500, "edge gate misconfigured: " + problem);
    }

    const url = new URL(request.url);
    const target = resolveHostTarget(url.hostname, env.DY_ZONE_SUFFIX);
    if (target === null) {
      // Not one of this cell's session hosts (the exact-host routes should make this unreachable; a
      // workers.dev or preview hostname lands here too). Never proxy an unexpected host.
      return plainResponse(404, "not found");
    }

    // The session token comes from ?token= (minted into the URL) or, on follow-up requests, the gate's
    // cookie (see WHICH TOKEN COUNTS above).
    const hostKey = await deriveHostKey(env.DY_SESSION_SECRET, target.host);
    let session = null;
    const queryToken = url.searchParams.get(TOKEN_QUERY_PARAMETER);
    if (queryToken !== null) {
      const queryClaims = await verifyToken(queryToken, hostKey, target.expectedPurpose, target.slug);
      if (queryClaims !== null) {
        session = { token: queryToken, claims: queryClaims, fromQuery: true };
      }
    }

    if (!requestContextAllowed(request, target.host, session !== null)) {
      // A cookie-only request from another site, or a WebSocket from another origin: 401 at the edge, with
      // no minter call and no origin fetch.
      return unauthorized();
    }

    if (session === null) {
      const cookieToken = readCookie(request, COOKIE_NAME);
      const cookieClaims = await verifyToken(cookieToken, hostKey, target.expectedPurpose, target.slug);
      if (cookieClaims === null) {
        // Invalid or absent token: 401 at the edge, and DELIBERATELY no origin fetch and no minter call.
        return unauthorized();
      }
      session = { token: cookieToken, claims: cookieClaims, fromQuery: false };
    }

    // On a pma-, spma- or staging- host the container reads the token from X-DY-Session-Token, so a verified
    // ?token= leaves the query. A terminal reads it from the query, so its query passes unchanged.
    let originSearch = url.search;
    if (session.fromQuery && HEADER_TOKEN_PURPOSES.includes(target.expectedPurpose)) {
      originSearch = searchWithoutSessionToken(url.search);
    }

    if (getsTokenStripPage(request, target, session)) {
      // No minter call and no origin fetch: the next request, from this page, rides on the cookie.
      return tokenStripPage("https://" + target.host + url.pathname + originSearch, session);
    }

    const audience = "https://" + target.label + env.DY_RUN_URL_SUFFIX;
    const idToken = await idTokenFor(env, audience, target.expectedPurpose);
    if (idToken === null) {
      return plainResponse(503, "session gateway unavailable");
    }
    const originUrl = audience + url.pathname + originSearch;
    const originRequest = originRequestFor(request, originUrl, idToken, target, session.token);

    // Both origin fetches say redirect: "manual" EXPLICITLY: a redirect from the origin goes back to the
    // browser as it is and is never followed here, so this gate never fetches a URL the origin chose, with
    // or without the ID token on it.

    // WebSocket upgrade (the terminal's PTY over WS): return the origin's 101 verbatim (it carries the
    // WebSocket). Never wrap it in a new Response and never set a cookie on a handshake.
    if (isWebSocketUpgrade(request)) {
      return fetch(originRequest, { redirect: "manual" });
    }

    // Normal HTTP. When the token came in the URL (and verified), set a short-lived httpOnly cookie so
    // follow-up requests and redirects that drop ?token= re-authenticate off it. A cookie is never set from
    // a ?token= that did not verify.
    const originResponse = await fetch(originRequest, { redirect: "manual" });
    if (!session.fromQuery) {
      return originResponse;
    }
    const response = new Response(originResponse.body, originResponse);
    response.headers.append("Set-Cookie", gateCookieFor(session));
    return response;
  },
};
