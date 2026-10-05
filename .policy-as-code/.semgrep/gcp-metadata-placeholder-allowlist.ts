// Fixture for gcp-metadata-placeholder-allowlist.yaml.
//
// Each case is in its own block so the file stays valid TypeScript while re-declaring the same
// constant name — the name is half of what the rule matches on, so every case has to use it.

// The approved value, as it stands in the orchestrator's src/agency-dispatch.ts. This is the
// only form the rule accepts, and the agency Worker's twin list in src/actuate.ts
// (METADATA_PLACEHOLDER_NAMES) carries the same five names.
// ok: dy-gcp-metadata-placeholder-allowlist-pinned
export const GCP_METADATA_PLACEHOLDERS = [
  "@@DY_T2_S3_ACCESS_KEY_ID@@",
  "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
  "@@DY_T2_S3_ENDPOINT@@",
  "@@DY_T2_S3_BUCKET@@",
  "@@DY_T2_S3_REGION@@",
] as const;

{
  // The Worker's name for the same list, also at its approved value.
  // ok: dy-gcp-metadata-placeholder-allowlist-pinned
  const METADATA_PLACEHOLDER_NAMES = [
    "@@DY_T2_S3_ACCESS_KEY_ID@@",
    "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
    "@@DY_T2_S3_ENDPOINT@@",
    "@@DY_T2_S3_BUCKET@@",
    "@@DY_T2_S3_REGION@@",
  ] as const;
}

{
  // A sixth agency secret spliced into a root-run boot script.
  // ruleid: dy-gcp-metadata-placeholder-allowlist-pinned
  const GCP_METADATA_PLACEHOLDERS = [
    "@@DY_T2_S3_ACCESS_KEY_ID@@",
    "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
    "@@DY_T2_S3_ENDPOINT@@",
    "@@DY_T2_S3_BUCKET@@",
    "@@DY_T2_S3_REGION@@",
    "@@DY_CF_API_TOKEN@@",
  ] as const;
}

{
  // The same widening on the Worker side.
  // ruleid: dy-gcp-metadata-placeholder-allowlist-pinned
  const METADATA_PLACEHOLDER_NAMES = [
    "@@DY_T2_S3_ACCESS_KEY_ID@@",
    "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
    "@@DY_T2_S3_ENDPOINT@@",
    "@@DY_T2_S3_BUCKET@@",
    "@@DY_T2_S3_REGION@@",
    "@@DY_RESTIC_PASSWORD@@",
  ] as const;
}

{
  // Dropping one half of a pair, which would leave the Worker and the renderer disagreeing.
  // ruleid: dy-gcp-metadata-placeholder-allowlist-pinned
  const GCP_METADATA_PLACEHOLDERS = [
    "@@DY_T2_S3_ACCESS_KEY_ID@@",
    "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
  ] as const;
}

{
  // A renamed token: the Worker would refuse it, but the drift should be caught in review first.
  // ruleid: dy-gcp-metadata-placeholder-allowlist-pinned
  const GCP_METADATA_PLACEHOLDERS = [
    "@@DY_T2_S3_ACCESS_KEY@@",
    "@@DY_T2_S3_SECRET_ACCESS_KEY@@",
    "@@DY_T2_S3_ENDPOINT@@",
    "@@DY_T2_S3_BUCKET@@",
    "@@DY_T2_S3_REGION@@",
  ] as const;
}

// A different constant is a different policy.
// ok: dy-gcp-metadata-placeholder-allowlist-pinned
const BOOT_PLACEHOLDER_DOC_EXAMPLES = ["@@DY_T2_S3_ACCESS_KEY_ID@@", "@@DY_ANYTHING@@"] as const;
