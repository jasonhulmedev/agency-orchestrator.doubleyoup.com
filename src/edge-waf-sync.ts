// The Worker's OWN builder for the `waf-edge-sync` op (hub#44 phase 2, specs/edge-security-via-worker.md):
// the xmlrpc baseline rule, the ban CLAUSES, and the sticky first-fit PACKING of those clauses into
// "chunk" rules. PURE: no fetch, no Node APIs. The actuator (actuate.ts::actuateWafEdgeSync) reads the
// zone, calls this module to plan, and does the writes.
//
// WHAT THE OP OWNS in a zone's firewall-custom phase, matched by EXACT description:
//   - the six baseline rules: the five of waf-rule-upsert (edge-waf-rule.ts, same descriptions, so a
//     baseline that op wrote is patched in place) plus `doubleyoup-xmlrpc`;
//   - the chunk rules `doubleyoup-edge-block:<n>` (action block) and `doubleyoup-edge-challenge:<n>`
//     (action managed_challenge), n = 1, 2, 3, ...
// LEGACY rules (`doubleyoup-ban:*`, `doubleyoup-geo:*`, written by the platform's own token before this
// op) are deleted only on request (`retireLegacy`). Every other rule is FOREIGN: reported, never touched.
//
// WHY CHUNKS. A Pro zone allows 20 custom rules. One rule per ban would run out after a handful of
// bans, so bans are CLAUSES OR-ed together inside a few rules of up to 4,000 characters each.
//
// CLAUSE TEXT IS CANONICAL (sorted, de-duplicated, fixed spacing), so one ban always renders exactly
// one text, and a later run finds the clause again by that text:
//   site ip   (ip.src in {1.2.3.4 10.0.0.0/8} and http.host in {"a.example.com" "b.example.com"})
//   site ua   (http.user_agent contains "BadBot/1.0" and http.host in {"a.example.com"})
//   site all  (http.host in {"a.example.com"} and not http.request.uri.path.extension in {"png" ...})
//   global    the host test becomes `not http.host in {<excludedHosts>}` (hosts: [] in the job)
// AN `all` CLAUSE LEAVES STATIC FILES ALONE (Amendment A9). An image, a stylesheet or a font cannot
// pass a challenge, so "challenge everything" on a host broke a live site's logo and images when its
// pages loaded them from that host. `http.request.uri.path.extension` is the extension after the
// last dot, LOWERCASED by Cloudflare (`/LOGO.PNG` gives "png"), so no upper-case forms are needed.
// The exemption is on `all` clauses only: an ip or ua ban still covers static files.
// A chunk's expression is its clauses, sorted, joined with " or ". `not` binds tighter than `and` and
// `or`, and every clause with an `and` is in parentheses, so a chunk needs no further parentheses.
//
// STICKY FIRST-FIT. A clause already in a chunk STAYS in that chunk while it is still wanted. A new
// clause goes to the lowest-numbered chunk with room, else to a new chunk (the smallest unused
// number). So an unchanged ban never moves, and a run that adds one ban patches one rule.
//
// ADDITIONS BEFORE REMOVALS. The room check counts the clauses a chunk is about to LOSE, so every new
// clause can be written while every old clause is still in place. A chunk that both gains and loses
// clauses therefore gets two writes (gain, then lose). The actuator writes: creates, then gain
// patches, then lose patches, then deletes. A changed ban (a site that gained a domain) is in force
// on its old hosts until its new clause has landed — there is never a gap.

import { WAF_RULE_DESCRIPTIONS, type WafRule } from "./edge-waf-rule.js";

/** The stable identity of the sixth baseline rule: block /xmlrpc.php zone-wide (spec decision D1). */
export const WAF_XMLRPC_DESCRIPTION = "doubleyoup-xmlrpc";

/** All six baseline descriptions. The op never deletes a rule carrying one of them (Amendment A2). */
export const WAF_SYNC_BASELINE_DESCRIPTIONS: readonly string[] = [...WAF_RULE_DESCRIPTIONS, WAF_XMLRPC_DESCRIPTION];

/** Chunk rule descriptions are this prefix + the chunk number. */
export const EDGE_BLOCK_CHUNK_PREFIX = "doubleyoup-edge-block:";
export const EDGE_CHALLENGE_CHUNK_PREFIX = "doubleyoup-edge-challenge:";

/** Rules the platform wrote with its own token before this op. Deleted only when retireLegacy is true. */
export const LEGACY_WAF_RULE_PREFIXES: readonly string[] = ["doubleyoup-ban:", "doubleyoup-geo:"];

/**
 * The most characters one chunk expression may hold. Cloudflare's limit is 4,096
 * (WAF_EXPRESSION_MAX_LENGTH); the 96 spare characters are a margin, not a budget anything uses.
 */
export const EDGE_CHUNK_MAX_LENGTH = 4000;

/** Joins two clauses inside a chunk expression. */
const CLAUSE_SEPARATOR = " or ";

export type EdgeChunkKind = "block" | "challenge";

/** The Cloudflare action of each chunk kind. */
export function edgeChunkAction(kind: EdgeChunkKind): "block" | "managed_challenge" {
  if (kind === "block") {
    return "block";
  }
  return "managed_challenge";
}

/** `doubleyoup-edge-block:3`, `doubleyoup-edge-challenge:1`. */
export function edgeChunkDescription(kind: EdgeChunkKind, chunkNumber: number): string {
  if (kind === "block") {
    return `${EDGE_BLOCK_CHUNK_PREFIX}${chunkNumber}`;
  }
  return `${EDGE_CHALLENGE_CHUNK_PREFIX}${chunkNumber}`;
}

// A chunk number: a positive integer without a leading zero, at most six digits. Anything else after
// the prefix (`doubleyoup-edge-block:01`, `...:x`) is not one of ours, so it is FOREIGN and untouched.
const CHUNK_NUMBER_RE = /^[1-9][0-9]{0,5}$/;

/** Which part of the zone's custom rules a rule belongs to, by its description. */
export type WafRuleOwnership =
  | { owner: "baseline" }
  | { owner: "chunk"; kind: EdgeChunkKind; chunkNumber: number }
  | { owner: "legacy" }
  | { owner: "foreign" };

/** Sort one rule by its description. Exact matches only: a near-miss is foreign, never ours. */
export function classifyWafRuleDescription(description: string | undefined): WafRuleOwnership {
  if (description === undefined) {
    return { owner: "foreign" };
  }
  if (WAF_SYNC_BASELINE_DESCRIPTIONS.includes(description)) {
    return { owner: "baseline" };
  }
  const chunkPrefixes: Array<{ kind: EdgeChunkKind; prefix: string }> = [
    { kind: "block", prefix: EDGE_BLOCK_CHUNK_PREFIX },
    { kind: "challenge", prefix: EDGE_CHALLENGE_CHUNK_PREFIX },
  ];
  for (const { kind, prefix } of chunkPrefixes) {
    if (!description.startsWith(prefix)) {
      continue;
    }
    const numberText = description.slice(prefix.length);
    if (CHUNK_NUMBER_RE.test(numberText)) {
      return { owner: "chunk", kind, chunkNumber: Number(numberText) };
    }
  }
  for (const prefix of LEGACY_WAF_RULE_PREFIXES) {
    if (description.startsWith(prefix)) {
      return { owner: "legacy" };
    }
  }
  return { owner: "foreign" };
}

/**
 * The xmlrpc expression: the path itself. A cell's nginx runs PHP only for a path that ENDS in `.php`
 * (`location ~ \.php$`), so `/xmlrpc.php/anything` never reaches xmlrpc.php and needs no clause.
 * Blocking it breaks Jetpack and the WordPress mobile apps (spec decision D1).
 */
export function wafXmlrpcExpression(): string {
  return 'http.request.uri.path eq "/xmlrpc.php"';
}

/** The xmlrpc rule. `enabled` = baseline.enabled AND xmlrpc "block"; otherwise present but disabled. */
export function buildXmlrpcRule(enabled: boolean): WafRule {
  return {
    description: WAF_XMLRPC_DESCRIPTION,
    expression: wafXmlrpcExpression(),
    action: "block",
    enabled,
  };
}

/** A chunk rule body. Chunk rules are always enabled: `baseline.enabled` switches only the baseline. */
export function buildEdgeChunkRule(kind: EdgeChunkKind, chunkNumber: number, clauses: readonly string[]): WafRule {
  return {
    description: edgeChunkDescription(kind, chunkNumber),
    expression: joinChunkClauses(clauses),
    action: edgeChunkAction(kind),
    enabled: true,
  };
}

// ── clauses ───────────────────────────────────────────────────────────────────────────

/** One validated block or challenge entry, as the clause builder needs it. */
export interface EdgeClauseEntry {
  /** Sorted or not; the builder sorts. [] = the whole zone except excludedHosts. */
  hosts: readonly string[];
  ips: readonly string[];
  uas: readonly string[];
  all: boolean;
}

export type EdgeClausesVerdict = { ok: true; clauses: string[] } | { ok: false; reason: string };

/** The extensions an `all` clause exempts (Amendment A9), in the amendment's order. */
export const EDGE_STATIC_EXTENSIONS: readonly string[] = [
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "avif",
  "svg",
  "ico",
  "css",
  "js",
  "woff",
  "woff2",
  "ttf",
  "map",
];

/** `not http.request.uri.path.extension in {"png" ...}` — appended to every `all` clause. */
const STATIC_FILE_EXEMPTION = `not http.request.uri.path.extension in {${EDGE_STATIC_EXTENSIONS.map((extension) => `"${extension}"`).join(" ")}}`;

/** Sorted by UTF-16 code unit (the default sort) and de-duplicated. Never locale-dependent. */
function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

/** `{"a.example.com" "b.example.com"}` — a set of quoted hosts, in the order given. */
function quotedHostSet(hosts: readonly string[]): string {
  // Hosts passed the FQDN grammar ([a-z0-9.-]), so none can carry a quote or a backslash.
  const quoted = hosts.map((host) => `"${host}"`);
  return `{${quoted.join(" ")}}`;
}

/** The length quotedHostSet would have for `hosts`, without building it. */
function quotedHostSetLength(hosts: readonly string[]): number {
  if (hosts.length === 0) {
    return 2;
  }
  let length = 2 + (hosts.length - 1);
  for (const host of hosts) {
    length += host.length + 2;
  }
  return length;
}

/** The host test of a site entry: `http.host in {...}`. */
function siteHostTest(hosts: readonly string[]): string {
  return `http.host in ${quotedHostSet(hosts)}`;
}

/** The host test of a global entry: every host of the zone except its infrastructure. */
function globalHostTest(excludedHosts: readonly string[]): string {
  return `not http.host in ${quotedHostSet(sortedUnique(excludedHosts))}`;
}

/**
 * The clause makers of one entry, each turning a host test into one clause: one for the IP set (when
 * there are IPs), one per User-Agent, and for `all` the host test minus static files (A9). Splitting
 * measures every clause through its maker, so the longer `all` clause is counted with no extra step.
 */
function clauseMakersFor(entry: EdgeClauseEntry): Array<(hostTest: string) => string> {
  const makers: Array<(hostTest: string) => string> = [];
  const ips = sortedUnique(entry.ips);
  if (ips.length > 0) {
    makers.push((hostTest) => `(ip.src in {${ips.join(" ")}} and ${hostTest})`);
  }
  for (const userAgent of sortedUnique(entry.uas)) {
    // The validator allows no `"` and no `\` in a User-Agent, so it cannot leave the quoted string.
    makers.push((hostTest) => `(http.user_agent contains "${userAgent}" and ${hostTest})`);
  }
  if (entry.all) {
    makers.push((hostTest) => `(${hostTest} and ${STATIC_FILE_EXEMPTION})`);
  }
  return makers;
}

/**
 * The largest group size G for which every group of `sortedHosts` (cut in order, G at a time, the last
 * group shorter) makes a clause of at most `maxLength` characters, or 0 when even one host per clause
 * is too long. `fixedLength` is the clause's length with an EMPTY host set `{}`.
 *
 * The scan goes from the largest size down because fitting is not monotonic in G: groups of 3 can fit
 * where groups of 2 do not (different cut points). Lengths are summed, not built, so a 500-host entry
 * costs arithmetic, not 500 rounds of string building.
 */
function largestFittingGroupSize(sortedHosts: readonly string[], fixedLength: number, maxLength: number): number {
  for (let groupSize = sortedHosts.length - 1; groupSize >= 1; groupSize -= 1) {
    let everyGroupFits = true;
    for (let start = 0; start < sortedHosts.length; start += groupSize) {
      const group = sortedHosts.slice(start, start + groupSize);
      const clauseLength = fixedLength - 2 + quotedHostSetLength(group);
      if (clauseLength > maxLength) {
        everyGroupFits = false;
        break;
      }
    }
    if (everyGroupFits) {
      return groupSize;
    }
  }
  return 0;
}

/**
 * Every canonical clause for a list of entries, sorted and de-duplicated (two bans that render the
 * same text are one clause). A clause longer than EDGE_CHUNK_MAX_LENGTH would never fit in a chunk:
 *   - a SITE clause is split into host-subset clauses — the hosts sorted and cut into groups of the
 *     largest size G that fits, so the split depends only on the entry (deterministic);
 *   - a GLOBAL clause cannot be split (its host test is a NEGATED set: splitting it would widen it),
 *     and neither can an IP list too long for even one host. Both are refused, before any write.
 */
export function buildEdgeClauses(
  entries: readonly EdgeClauseEntry[],
  excludedHosts: readonly string[],
  maxLength: number = EDGE_CHUNK_MAX_LENGTH,
): EdgeClausesVerdict {
  const clauses = new Set<string>();
  for (const entry of entries) {
    const makers = clauseMakersFor(entry);
    if (entry.hosts.length === 0) {
      const hostTest = globalHostTest(excludedHosts);
      for (const makeClause of makers) {
        const clause = makeClause(hostTest);
        if (clause.length > maxLength) {
          return {
            ok: false,
            reason:
              `a global (hosts: []) clause would be ${clause.length} characters, over the ${maxLength}-character ` +
              "chunk budget, and a negated host set cannot be split — shorten baseline.excludedHosts or the entry's IP list",
          };
        }
        clauses.add(clause);
      }
      continue;
    }

    const sortedHosts = sortedUnique(entry.hosts);
    for (const makeClause of makers) {
      const wholeClause = makeClause(siteHostTest(sortedHosts));
      if (wholeClause.length <= maxLength) {
        clauses.add(wholeClause);
        continue;
      }
      const fixedLength = makeClause(siteHostTest([])).length;
      const groupSize = largestFittingGroupSize(sortedHosts, fixedLength, maxLength);
      if (groupSize === 0) {
        return {
          ok: false,
          reason:
            `a clause would be over the ${maxLength}-character chunk budget even with one host — the entry's IP ` +
            "list is too long for one clause",
        };
      }
      for (let start = 0; start < sortedHosts.length; start += groupSize) {
        clauses.add(makeClause(siteHostTest(sortedHosts.slice(start, start + groupSize))));
      }
    }
  }
  return { ok: true, clauses: [...clauses].sort() };
}

/** A chunk expression: the clauses sorted, de-duplicated, joined with " or ". */
export function joinChunkClauses(clauses: readonly string[]): string {
  return sortedUnique(clauses).join(CLAUSE_SEPARATOR);
}

/** The length joinChunkClauses would give a set of DISTINCT clauses, without building it. */
function joinedLength(distinctClauses: Iterable<string>): number {
  let length = 0;
  let count = 0;
  for (const clause of distinctClauses) {
    length += clause.length;
    count += 1;
  }
  if (count === 0) {
    return 0;
  }
  return length + CLAUSE_SEPARATOR.length * (count - 1);
}

/**
 * Split a chunk expression back into its top-level clauses: cut at every " or " that is outside a
 * quoted string, a `{...}` set and a `(...)` group. Our own clauses come back byte for byte. A chunk an
 * agency edited by hand comes back as fragments that match no wanted clause, so the next write
 * replaces them with the canonical text. Inside a quoted string a backslash escapes the next
 * character (the Rules language's escaping), though no clause of ours contains one.
 */
export function splitChunkExpression(expression: string): string[] {
  const clauses: string[] = [];
  let depth = 0;
  let inQuotedString = false;
  let clauseStart = 0;
  let index = 0;
  while (index < expression.length) {
    const character = expression[index];
    if (inQuotedString) {
      if (character === "\\") {
        index += 2;
        continue;
      }
      if (character === '"') {
        inQuotedString = false;
      }
      index += 1;
      continue;
    }
    if (character === '"') {
      inQuotedString = true;
    } else if (character === "(" || character === "{") {
      depth += 1;
    } else if (character === ")" || character === "}") {
      depth -= 1;
    } else if (depth === 0 && expression.startsWith(CLAUSE_SEPARATOR, index)) {
      clauses.push(expression.slice(clauseStart, index));
      index += CLAUSE_SEPARATOR.length;
      clauseStart = index;
      continue;
    }
    index += 1;
  }
  if (expression.length > 0) {
    clauses.push(expression.slice(clauseStart));
  }
  return clauses;
}

// ── sticky first-fit packing ──────────────────────────────────────────────────────────

/** One existing chunk rule of one kind, as read from the zone. */
export interface ExistingEdgeChunk {
  chunkNumber: number;
  /** splitChunkExpression of its expression, in the order found. */
  clauses: readonly string[];
}

/** What the run does to one chunk. */
export interface EdgeChunkPlan {
  chunkNumber: number;
  /** true = the chunk does not exist yet and is created with `finalClauses`. */
  isNew: boolean;
  /** The distinct clauses the chunk holds now (empty for a new chunk). */
  currentClauses: string[];
  /** Still-wanted clauses already in this chunk. They stay here (sticky). */
  keptClauses: string[];
  /** New clauses placed in this chunk by first-fit. */
  gainedClauses: string[];
  /** Clauses (or hand-edited fragments) that leave this chunk: unwanted, or a duplicate kept elsewhere. */
  lostClauses: string[];
  /** The chunk after the run: kept + gained. Empty = the chunk is deleted. */
  finalClauses: string[];
  /**
   * The clauses of the GAIN write of an existing chunk that gains: everything it holds now plus what it
   * gains, so nothing leaves before every addition has landed. null when the chunk gains nothing (or is new).
   */
  gainClauses: string[] | null;
}

/**
 * Plan one chunk kind: keep every still-wanted clause where it is, then place each new clause (in
 * sorted order) in the lowest-numbered chunk whose GAIN text — its current clauses (the ones it is
 * about to lose included) plus what it has gained so far plus this clause — fits in `maxLength`.
 * When none has room, a new chunk takes the smallest number no existing chunk uses (a chunk about to
 * be deleted still exists while the creates run, so its number is not reused in the same run).
 *
 * A wanted clause found in two chunks (only a hand edit or an interrupted run can do that) stays in
 * the lowest-numbered one and leaves the other.
 *
 * `wantedClauses` must already fit one per chunk (buildEdgeClauses guarantees it).
 */
export function planStickyChunks(
  existingChunks: readonly ExistingEdgeChunk[],
  wantedClauses: readonly string[],
  maxLength: number = EDGE_CHUNK_MAX_LENGTH,
): EdgeChunkPlan[] {
  const wanted = new Set(wantedClauses);
  const placedClauses = new Set<string>();
  const plans: EdgeChunkPlan[] = [];

  const existingInNumberOrder = [...existingChunks].sort((left, right) => left.chunkNumber - right.chunkNumber);
  for (const chunk of existingInNumberOrder) {
    const currentClauses = [...new Set(chunk.clauses)];
    const keptClauses: string[] = [];
    const lostClauses: string[] = [];
    for (const clause of currentClauses) {
      if (wanted.has(clause) && !placedClauses.has(clause)) {
        keptClauses.push(clause);
        placedClauses.add(clause);
      } else {
        lostClauses.push(clause);
      }
    }
    plans.push({
      chunkNumber: chunk.chunkNumber,
      isNew: false,
      currentClauses,
      keptClauses,
      gainedClauses: [],
      lostClauses,
      finalClauses: [],
      gainClauses: null,
    });
  }

  const usedNumbers = new Set(plans.map((plan) => plan.chunkNumber));
  const newClauses = [...wanted].filter((clause) => !placedClauses.has(clause)).sort();
  for (const clause of newClauses) {
    let home: EdgeChunkPlan | undefined;
    for (const plan of plans) {
      const occupancy = new Set([...plan.currentClauses, ...plan.gainedClauses, clause]);
      if (joinedLength(occupancy) <= maxLength) {
        home = plan;
        break;
      }
    }
    if (home === undefined) {
      let chunkNumber = 1;
      while (usedNumbers.has(chunkNumber)) {
        chunkNumber += 1;
      }
      usedNumbers.add(chunkNumber);
      home = {
        chunkNumber,
        isNew: true,
        currentClauses: [],
        keptClauses: [],
        gainedClauses: [],
        lostClauses: [],
        finalClauses: [],
        gainClauses: null,
      };
      plans.push(home);
      // Keep number order, so "the first chunk with room" is always the lowest-numbered one.
      plans.sort((left, right) => left.chunkNumber - right.chunkNumber);
    }
    home.gainedClauses.push(clause);
  }

  for (const plan of plans) {
    plan.finalClauses = sortedUnique([...plan.keptClauses, ...plan.gainedClauses]);
    if (!plan.isNew && plan.gainedClauses.length > 0) {
      plan.gainClauses = sortedUnique([...plan.currentClauses, ...plan.gainedClauses]);
    }
  }
  return plans;
}
