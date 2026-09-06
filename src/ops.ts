// Direction-B OP REGISTRY (agency Worker side): `op` -> { validateParams, actuate }.
//
// index.ts::handleActuate is op-agnostic. After a job verifies (dispatch-verify.ts) and
// its nonce is consumed (nonce-store.ts), it looks the op up here, hands the PARSED
// params to `validateParams`, and — only on ok — runs `actuate` with the typed result.
// Adding an op = one entry here + the op name in dispatch-verify.ts::DISPATCH_OPS (the
// record type below is keyed on that tuple, so the compiler enforces the pairing) + the
// twin validator in the app (which refuses to sign what this side would reject).
//
// Only IDEMPOTENT ops belong here for now: the nonce is burned before actuation, so a
// transient failure needs a re-signed job, which is only safe when re-running converges
// (see the F1 note in actuate.ts).

import type { Env } from "./env.js";
import type { DispatchOp } from "./dispatch-verify.js";
import {
  type ParamsVerdict,
  type ProvisionR2Params,
  type DnsRecordUpsertParams,
  validateProvisionR2Params,
  validateDnsRecordUpsertParams,
} from "./dispatch-params.js";
import { type ActuateResult, actuateProvisionR2, actuateDnsRecordUpsert } from "./actuate.js";

/** A fully-typed op definition: validate/actuate agree on the params type P. */
interface OpDefinition<P> {
  validateParams(raw: unknown): ParamsVerdict<P>;
  actuate(params: P, env: Env): Promise<ActuateResult>;
}

/**
 * The type-erased entry the registry stores. `actuate` here MUST only ever be called with
 * the `params` returned by the SAME entry's `validateParams` (handleActuate does exactly
 * that) — defineOp is what makes the erased cast below sound.
 */
export interface RegisteredOp {
  validateParams(raw: unknown): ParamsVerdict<unknown>;
  actuate(params: unknown, env: Env): Promise<ActuateResult>;
}

function defineOp<P>(definition: OpDefinition<P>): RegisteredOp {
  return {
    validateParams: definition.validateParams,
    // Sound because handleActuate only passes this entry's own validated params (see above).
    actuate: (params, env) => definition.actuate(params as P, env),
  };
}

export const DISPATCH_OP_REGISTRY: Record<DispatchOp, RegisteredOp> = {
  "provision-r2": defineOp<ProvisionR2Params>({
    validateParams: validateProvisionR2Params,
    actuate: (params, env) => actuateProvisionR2(params.bucketName, env),
  }),
  "dns-record-upsert": defineOp<DnsRecordUpsertParams>({
    validateParams: validateDnsRecordUpsertParams,
    actuate: (params, env) => actuateDnsRecordUpsert(params, env),
  }),
};

/**
 * JSON.parse the signed `params` string, fail-closed. Called ONLY after the signature has
 * verified (the string's exact bytes are what was signed). A malformed string yields
 * ok:false so the caller answers 400 and actuates nothing — never a thrown 500.
 */
export function parseDispatchParams(paramsString: string): ParamsVerdict<unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(paramsString);
  } catch {
    return { ok: false, reason: "params is not valid JSON" };
  }
  return { ok: true, params: parsed };
}
