// The limits of ONE waf-edge-sync run: its wall time and its subrequests (hub#44 phase 2).
//
// WALL TIME. The orchestrator gives one dispatch 120 s (EDGE_SYNC_DISPATCH_TIMEOUT_MS in actuate.ts)
// and the per-zone lease lasts 5 minutes. Cloudflare only says a request's tasks "may be canceled"
// when the client disconnects, so the run bounds itself: every Cloudflare call gets a timeout
// (AbortSignal.timeout), and a call starts only when that timeout ends before the run's deadline.
// So no call of a run outlives the deadline, and the deadline sits below the dispatch timeout.
//
// SUBREQUESTS. An agency Worker may be on the Workers Free plan: 50 subrequests per invocation, and
// Durable Object calls count (developers.cloudflare.com/workers/platform/limits/). The budget counts
// every subrequest of the invocation in this one object: the nonce consume before the actuator runs,
// the two lease calls, and every Cloudflare API call of the run.
//
// Past either limit the run stops BEFORE the next call and reports `writeFailed` with what landed.
// The op is idempotent and re-reads the zone, so the next run continues from the zone's real state.

/** The run's own ceiling: Workers Free allows 50 subrequests per invocation; 5 stay spare. */
export const EDGE_SYNC_SUBREQUEST_BUDGET = 45;

/** Subrequests /actuate makes before the actuator runs: the nonce consume (index.ts, handleActuate). */
export const EDGE_SYNC_SUBREQUESTS_BEFORE_ACTUATION = 1;

/** The lease's two Durable Object calls: the acquire, and the release in `finally`. */
export const EDGE_SYNC_LEASE_SUBREQUESTS = 2;

/**
 * Subrequests the custom part may not use, so the rate-limit part (and its off switch) can still
 * run after it: the rate-limit read and up to two writes.
 */
export const EDGE_SYNC_RATE_LIMIT_RESERVE = 3;

/** The run's wall-time limit, from the start of the actuator. Below the 120 s dispatch timeout. */
export const EDGE_SYNC_RUN_DEADLINE_MS = 100 * 1000;

/** The timeout of one Cloudflare API call. */
export const EDGE_SYNC_REQUEST_TIMEOUT_MS = 15 * 1000;

/** The stop reasons, as the result's detail begins. */
export const EDGE_SYNC_BUDGET_REACHED = "subrequest budget reached; the next run continues";
export const EDGE_SYNC_DEADLINE_REACHED = "run time limit reached; the next run continues";

export interface EdgeSyncRunLimits {
  subrequestBudget: number;
  runDeadlineMs: number;
  requestTimeoutMs: number;
  /** The clock, in milliseconds. Tests pass their own. */
  now: () => number;
}

export const EDGE_SYNC_RUN_LIMITS: EdgeSyncRunLimits = {
  subrequestBudget: EDGE_SYNC_SUBREQUEST_BUDGET,
  runDeadlineMs: EDGE_SYNC_RUN_DEADLINE_MS,
  requestTimeoutMs: EDGE_SYNC_REQUEST_TIMEOUT_MS,
  now: () => Date.now(),
};

/** The answer to "may the next Cloudflare call go?": its timeout signal, or why the run stops. */
export type EdgeSyncCallPermit = { ok: true; signal: AbortSignal } | { ok: false; reason: string };

/** Asked before every Cloudflare call of a run (see EdgeSyncRunBudget.beginCall). */
export type EdgeSyncCallGate = () => EdgeSyncCallPermit;

export class EdgeSyncRunBudget {
  private readonly limits: EdgeSyncRunLimits;
  private readonly deadlineAtMs: number;
  private used: number;
  private held = 0;
  private refusal: string | null = null;

  /** Created when the actuator starts; the nonce and lease subrequests are counted at once. */
  constructor(limits: EdgeSyncRunLimits) {
    this.limits = limits;
    this.deadlineAtMs = limits.now() + limits.runDeadlineMs;
    this.used = EDGE_SYNC_SUBREQUESTS_BEFORE_ACTUATION + EDGE_SYNC_LEASE_SUBREQUESTS;
  }

  /** Every subrequest of the invocation counted so far. */
  get subrequestsUsed(): number {
    return this.used;
  }

  /** Why the budget refused a call, once it has (the run is stopping); null before. */
  get stopReason(): string | null {
    return this.refusal;
  }

  /** Keep `count` subrequests for a later step: calls made before `releaseHold` cannot use them. */
  hold(count: number): void {
    this.held += count;
  }

  releaseHold(count: number): void {
    this.held -= count;
  }

  /**
   * Called before every Cloudflare call. Counts the call and gives it a timeout signal, or refuses
   * it: when it would pass the budget (less what is held), or when its timeout would end after the
   * deadline (so no call can outlive the run).
   */
  beginCall(): EdgeSyncCallPermit {
    if (this.used + 1 > this.limits.subrequestBudget - this.held) {
      this.refusal = EDGE_SYNC_BUDGET_REACHED;
      return { ok: false, reason: EDGE_SYNC_BUDGET_REACHED };
    }
    if (this.limits.now() + this.limits.requestTimeoutMs > this.deadlineAtMs) {
      this.refusal = EDGE_SYNC_DEADLINE_REACHED;
      return { ok: false, reason: EDGE_SYNC_DEADLINE_REACHED };
    }
    this.used += 1;
    return { ok: true, signal: AbortSignal.timeout(this.limits.requestTimeoutMs) };
  }
}
