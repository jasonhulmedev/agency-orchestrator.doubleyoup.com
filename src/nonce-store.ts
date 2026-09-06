// Direction-B REPLAY PROTECTION — a single-use nonce store (agency Worker side).
//
// dispatch-verify.ts proves an inbound /actuate job is AUTHENTIC (ed25519) and FRESH
// (±FRESHNESS_WINDOW_SECONDS). But the freshness window ALONE admits replay: a captured
// {job, signature} can be re-POSTed any number of times inside that window and each copy
// re-verifies identically. This Durable Object closes that hole by remembering every nonce
// it has already accepted, so the SECOND POST of the same signed job is rejected before any
// side effect ever runs.
//
// WHY A DURABLE OBJECT (not module scope / KV): the spent-nonce set must be shared and
// strongly consistent across every edge isolate and request. Module scope is per-isolate
// and evaporates on eviction — useless as a replay guard. KV is eventually consistent, so a
// racing replay could slip through before a write propagates. A DO gives a single-threaded,
// strongly-consistent home, and its SQLite storage (state.storage.sql) persists the set
// across DO restarts/evictions so a spent nonce is never forgotten while it could still be
// replayed.
//
// THROUGHPUT TRADEOFF: /actuate addresses ONE singleton instance (idFromName("dirb-nonce")),
// so every actuation serializes through it. Actuation is low-QPS / admin-triggered, so a
// single instance is deliberately fine here. If actuation ever becomes high-QPS, shard by
// hashing the nonce across N named instances — each nonce still lands on exactly one
// instance, preserving the single-use guarantee.
//
// Worker-native only: DO SQLite is native to workerd, so this needs no nodejs_compat.

import { DurableObject } from "cloudflare:workers";
import { FRESHNESS_WINDOW_SECONDS } from "./dispatch-verify.js";

// Extra seconds a consumed nonce is retained BEYOND the freshness window's far edge, to
// absorb clock skew between the signer (our control-plane app) and this Worker. A replay
// arriving right at the window boundary under a little skew must still be caught, so we keep
// the nonce slightly longer than strictly required. Kept small: a nonce older than the
// window is already rejected by the timestamp check, so it need not outlive the window by
// much.
const NONCE_RETENTION_SKEW_SECONDS = 30;

/**
 * The wall-clock time (ms since epoch) until which a consumed nonce MUST be retained.
 *
 * A job with timestamp T passes dispatch-verify's window check only while
 * now <= T + FRESHNESS_WINDOW_SECONDS, so the LAST instant a replay of that job could still
 * verify is T + FRESHNESS_WINDOW_SECONDS. We retain the nonce until then, plus a skew
 * margin. Deriving the expiry from the JOB TIMESTAMP — not "now + window" — guarantees the
 * nonce lives for the entire span in which its job is replayable, regardless of when we
 * first saw it. Beyond that instant the timestamp check rejects the job on its own, so the
 * row can be pruned without weakening the guarantee.
 */
export function nonceExpiresAtMs(jobTimestampMs: number): number {
  return jobTimestampMs + (FRESHNESS_WINDOW_SECONDS + NONCE_RETENTION_SKEW_SECONDS) * 1000;
}

export type ConsumeOutcome = "fresh" | "replay";

export class NonceStore extends DurableObject {
  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, env);
    // Idempotent, synchronous, cheap. The DO input gate holds inbound requests until the
    // constructor returns, and sql.exec here is synchronous, so the table always exists by
    // the time consume() runs — no blockConcurrencyWhile needed.
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)",
    );
  }

  /**
   * Record `nonce` as spent, atomically. Returns "fresh" the FIRST time a nonce is seen and
   * "replay" for every subsequent time until it expires and is pruned.
   *
   * ATOMICITY: a DO instance is single-threaded — only one invocation runs at a time — and
   * this method contains NO `await`, so the prune -> existence-check -> insert sequence runs
   * as one uninterruptible synchronous turn. Nothing can interleave between the SELECT and
   * the INSERT. The PRIMARY KEY on `nonce` is a hard backstop: even a logic slip could not
   * create a duplicate. Because /actuate routes every request to the SAME singleton
   * instance, this single-use guarantee holds globally, not merely per-isolate.
   *
   * @param notAfterMs wall-clock ms after which this nonce may be pruned — pass
   *                   nonceExpiresAtMs(Date.parse(job.timestamp)).
   */
  consume(nonce: string, notAfterMs: number): ConsumeOutcome {
    const sql = this.ctx.storage.sql;
    const now = Date.now();

    // (a) Drop anything past its retention horizon. An expired nonce belongs to a job the
    // timestamp check already rejects, so removing it cannot admit a replay.
    sql.exec("DELETE FROM nonces WHERE expires_at <= ?", now);

    // (b) Already spent (and still within retention) => replay.
    const existing = sql
      .exec("SELECT 1 AS present FROM nonces WHERE nonce = ? LIMIT 1", nonce)
      .toArray();
    if (existing.length > 0) {
      return "replay";
    }

    // (c) First sighting => record and accept. There is no await since (b), so this cannot
    // race with a concurrent consume of the same nonce.
    sql.exec("INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)", nonce, notAfterMs);
    return "fresh";
  }
}
