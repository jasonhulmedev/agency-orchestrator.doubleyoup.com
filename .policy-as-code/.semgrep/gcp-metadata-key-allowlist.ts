// Fixture for gcp-metadata-key-allowlist.yaml.
//
// Each case is in its own block so the file stays valid TypeScript while re-declaring the same
// constant name — the name is half of what the rule matches on, so every case has to use it.

// The approved value, as it stands in all three twins (app src/server/services/
// agency-dispatch-params.ts, orchestrator src/agency-dispatch.ts, agency Worker
// src/dispatch-params.ts). This is the only form the rule accepts.
// ok: dy-gcp-metadata-key-allowlist-pinned
export const GCP_METADATA_KEYS = ["startup-script"] as const;

{
  // Dropping `as const` widens the TYPE, not the list. Not what this rule is for.
  // ok: dy-gcp-metadata-key-allowlist-pinned
  const GCP_METADATA_KEYS = ["startup-script"];
}

{
  // A type annotation does not change which keys may be set.
  // ok: dy-gcp-metadata-key-allowlist-pinned
  const GCP_METADATA_KEYS: readonly string[] = ["startup-script"] as const;
}

{
  // The capability the allowlist exists to withhold: a persistent interactive login.
  // ruleid: dy-gcp-metadata-key-allowlist-pinned
  const GCP_METADATA_KEYS = ["startup-script", "ssh-keys"] as const;
}

{
  // Access paths of their own, added quietly alongside the approved key.
  // ruleid: dy-gcp-metadata-key-allowlist-pinned
  const GCP_METADATA_KEYS = ["startup-script", "enable-oslogin", "serial-port-enable"] as const;
}

{
  // Swapped rather than widened — still not the approved value.
  // ruleid: dy-gcp-metadata-key-allowlist-pinned
  const GCP_METADATA_KEYS = ["ssh-keys"] as const;
}

{
  // Emptied, which would make the op's own validator accept nothing — still a deliberate edit.
  // ruleid: dy-gcp-metadata-key-allowlist-pinned
  const GCP_METADATA_KEYS = [] as const;
}

// A different constant is a different policy; other rules cover those.
// ok: dy-gcp-metadata-key-allowlist-pinned
const GCP_METADATA_PLACEHOLDER_KEYS = ["startup-script", "ssh-keys"] as const;
