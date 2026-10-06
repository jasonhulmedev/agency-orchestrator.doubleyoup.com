// Fixture for gcp-placeholder-value-echo-allowlist.yaml.
//
// Each case is in its own block so the file stays valid TypeScript while re-declaring the same
// constant name — the name is half of what the rule matches on, so every case has to use it.

// The approved value, as it stands in the agency Worker's src/actuate.ts. The orchestrator's twin in
// src/agency-dispatch.ts (GCP_PLACEHOLDER_VALUES_SAFE_TO_ECHO) carries the same four names.
// ok: dy-gcp-placeholder-value-echo-allowlist-pinned
export const PLACEHOLDER_VALUES_SAFE_TO_ECHO = [
  "@@DY_T1_S3_BUCKET@@",
  "@@DY_T2_S3_BUCKET@@",
  "@@DY_T2_S3_ENDPOINT@@",
  "@@DY_T2_S3_REGION@@",
] as const;

{
  // The orchestrator's name for the same list, also at its approved value.
  // ok: dy-gcp-placeholder-value-echo-allowlist-pinned
  const GCP_PLACEHOLDER_VALUES_SAFE_TO_ECHO = [
    "@@DY_T1_S3_BUCKET@@",
    "@@DY_T2_S3_BUCKET@@",
    "@@DY_T2_S3_ENDPOINT@@",
    "@@DY_T2_S3_REGION@@",
  ] as const;
}

{
  // An access key id added to the echo list. It is half of the agency's object-store credential and
  // a long-lived name for their store — exactly what Direction-B says the platform never holds.
  // ruleid: dy-gcp-placeholder-value-echo-allowlist-pinned
  const PLACEHOLDER_VALUES_SAFE_TO_ECHO = [
    "@@DY_T1_S3_BUCKET@@",
    "@@DY_T2_S3_BUCKET@@",
    "@@DY_T2_S3_ENDPOINT@@",
    "@@DY_T2_S3_REGION@@",
    "@@DY_T2_S3_ACCESS_KEY_ID@@",
  ] as const;
}

{
  // The secret key itself, on the orchestrator side — the platform would then print it.
  // ruleid: dy-gcp-placeholder-value-echo-allowlist-pinned
  const GCP_PLACEHOLDER_VALUES_SAFE_TO_ECHO = [
    "@@DY_T1_S3_BUCKET@@",
    "@@DY_T2_S3_BUCKET@@",
    "@@DY_T2_S3_ENDPOINT@@",
    "@@DY_T2_S3_REGION@@",
    "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
  ] as const;
}

{
  // Dropping Tier-1's bucket puts the report back to where hub#64 started: a run that says a
  // placeholder was substituted and never says which bucket it resolved to.
  // ruleid: dy-gcp-placeholder-value-echo-allowlist-pinned
  const PLACEHOLDER_VALUES_SAFE_TO_ECHO = [
    "@@DY_T2_S3_BUCKET@@",
    "@@DY_T2_S3_ENDPOINT@@",
    "@@DY_T2_S3_REGION@@",
  ] as const;
}

{
  // A renamed token: the substitution would refuse it, but the drift should be caught in review.
  // ruleid: dy-gcp-placeholder-value-echo-allowlist-pinned
  const GCP_PLACEHOLDER_VALUES_SAFE_TO_ECHO = [
    "@@DY_T1_BUCKET@@",
    "@@DY_T2_S3_BUCKET@@",
    "@@DY_T2_S3_ENDPOINT@@",
    "@@DY_T2_S3_REGION@@",
  ] as const;
}

// A different constant is a different policy.
// ok: dy-gcp-placeholder-value-echo-allowlist-pinned
const ECHO_DOC_EXAMPLES = ["@@DY_T1_S3_BUCKET@@", "@@DY_ANYTHING@@"] as const;
