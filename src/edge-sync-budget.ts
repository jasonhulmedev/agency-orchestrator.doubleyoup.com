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
// THE RATE-LIMIT RESERVE. The rate-limit part runs after the custom part and must still be able to
// switch rate limiting off, however slow or large the custom part was (A10). So while the custom part
// runs, three calls are held for it: three subrequests AND three full call timeouts, plus 5 s of
// slack for the work between calls. The custom part's calls therefore end by 50 s
// (100 − 3 × 15 − 5), and the rate-limit part has 50 s of its own.
//
// Past either limit the run stops BEFORE the next call and reports `writeFailed` with what landed.
// The op is idempotent and re-reads the zone, so the next run continues from the zone's real state.
//
// UNKNOWN WRITES. A write whose timeout fired got no answer, and Cloudflare may still apply it later
// (EdgeSyncRunBudget.settleWrite). `landed` leaves it out, and the budget remembers it: the actuator
// then keeps the zone's lease until it expires instead of releasing it, so no newer run can read the
// zone, write, and report ok before that late write lands and undoes its work.

/** The run's own ceiling: Workers Free allows 50 subrequests per invocation; 5 stay spare. */
export const EDGE_SYNC_SUBREQUEST_BUDGET = 45;

/** Subrequests /actuate makes before the actuator runs: the nonce consume (index.ts, handleActuate). */
export const EDGE_SYNC_SUBREQUESTS_BEFORE_ACTUATION = 1;

/** The lease's two Durable Object calls: the acquire, and the release in `finally`. */
export const EDGE_SYNC_LEASE_SUBREQUESTS = 2;

/**
 * Calls held for the rate-limit part while the custom part runs, so its off switch can still run
 * after it: the rate-limit read and up to two writes. Each held call keeps its subrequest and its
 * full timeout (EdgeSyncRunBudget.beginCall).
 */
export const EDGE_SYNC_RATE_LIMIT_RESERVE = 3;

/** The run's wall-time limit, from the start of the actuator. Below the 120 s dispatch timeout. */
export const EDGE_SYNC_RUN_DEADLINE_MS = 100 * 1000;

/** The timeout of one Cloudflare API call. */
export const EDGE_SYNC_REQUEST_TIMEOUT_MS = 15 * 1000;

/**
 * Time held on top of the held calls' timeouts: the run's own work between calls (parsing, planning,
 * the lease call) takes a little time too, and must not cost the rate-limit part its last call.
 */
export const EDGE_SYNC_RESERVE_SLACK_MS = 5 * 1000;

/** The stop reasons, as the result's detail begins. */
export const EDGE_SYNC_BUDGET_REACHED = "subrequest budget reached; the next run continues";
export const EDGE_SYNC_DEADLINE_REACHED = "run time limit reached; the next run continues";

/**
 * The error of a write whose timeout fired: it got no answer, so it may or may not have landed. The
 * actuator keeps the lease (EDGE_SYNC_LEASE_TTL_MS in actuate.ts, 5 minutes) whenever this is reported.
 */
export const EDGE_SYNC_WRITE_UNKNOWN =
  "UNKNOWN: Cloudflare did not answer in time; the write may or may not have landed. The zone's lease " +
  "is kept until it expires (5 minutes after the run began), so a late landing cannot undo a newer run; " +
  "the next run then re-reads the zone.";

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

export class EdgeSyncRunBudget {
  private readonly limits: EdgeSyncRunLimits;
  private readonly deadlineAtMs: number;
  private used: number;
  private heldCalls = 0;
  private heldTimeMs = 0;
  private refusal: string | null = null;
  private unknownWrite = false;

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

  /** True once a write of this run ended UNKNOWN (settleWrite): the lease must not be released. */
  get hadUnknownWrite(): boolean {
    return this.unknownWrite;
  }

  /**
   * Keep `count` calls for a later step until `releaseHold(count)`: their subrequests, and their full
   * timeouts plus EDGE_SYNC_RESERVE_SLACK_MS before the deadline. Calls made in between cannot use
   * either.
   */
  hold(count: number): void {
    this.heldCalls += count;
    this.heldTimeMs += this.timeHeldFor(count);
  }

  releaseHold(count: number): void {
    this.heldCalls -= count;
    this.heldTimeMs -= this.timeHeldFor(count);
  }

  private timeHeldFor(count: number): number {
    return count * this.limits.requestTimeoutMs + EDGE_SYNC_RESERVE_SLACK_MS;
  }

  /**
   * Called before every Cloudflare call. Counts the call and gives it a timeout signal, or refuses
   * it: when it would pass the budget (less the held calls), or when its timeout, followed by the time
   * held, would end after the deadline. So no call can outlive the run, and a held call always has its
   * full timeout left when its turn comes.
   */
  beginCall(): EdgeSyncCallPermit {
    if (this.used + 1 > this.limits.subrequestBudget - this.heldCalls) {
      this.refusal = EDGE_SYNC_BUDGET_REACHED;
      return { ok: false, reason: EDGE_SYNC_BUDGET_REACHED };
    }
    const timeThisCallAndHeldTimeMayTakeMs = this.limits.requestTimeoutMs + this.heldTimeMs;
    if (this.limits.now() + timeThisCallAndHeldTimeMayTakeMs > this.deadlineAtMs) {
      this.refusal = EDGE_SYNC_DEADLINE_REACHED;
      return { ok: false, reason: EDGE_SYNC_DEADLINE_REACHED };
    }
    this.used += 1;
    return { ok: true, signal: AbortSignal.timeout(this.limits.requestTimeoutMs) };
  }

  /**
   * Called with the reply of every write, and the signal its permit gave. A failed write whose timeout
   * fired got no answer, so Cloudflare may or may not apply it, even later: its error becomes
   * EDGE_SYNC_WRITE_UNKNOWN, and the run remembers it (hadUnknownWrite). The caller keeps it out of
   * `landed`. Any other reply passes unchanged.
   */
  settleWrite<Reply extends object>(reply: Reply, signal: AbortSignal): Reply | { error: string } {
    if (!("error" in reply)) {
      return reply;
    }
    if (!signal.aborted) {
      return reply;
    }
    this.unknownWrite = true;
    return { error: EDGE_SYNC_WRITE_UNKNOWN };
  }
}
