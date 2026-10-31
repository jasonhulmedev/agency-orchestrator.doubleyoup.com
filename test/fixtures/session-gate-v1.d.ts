// Types for test/fixtures/session-gate-v1.js: the RELEASED session gate v1, byte for byte (its sha256 is the
// v1 pin in test/session-gate.test.ts). It is live on cells until edge-gate-deploy updates them to v2, so
// test/session-gate-minter.test.ts runs it against the current minter. v1 sends the bare audience string.

declare const gateV1: {
  fetch(request: Request, env: Record<string, unknown>): Promise<Response>;
};
export default gateV1;
