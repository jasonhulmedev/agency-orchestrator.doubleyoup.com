# agency-orchestrator.doubleyoup.com — agent working guide

The agency-side Cloudflare Worker of doubleyoup. Each agency forks this repo and deploys the Worker into its own Cloudflare account. Read `README.md` first.

## ⚠️ READ FIRST — one Worker for every agency

doubleyoup is a hosting platform for the WordPress sites of many agencies. Hundreds of agencies will run this same Worker. Every change must work for an agency that does not exist yet.

- **Do not hard-code an agency or a cell.** Code, config defaults and `wrangler.toml` must not contain the account ID, zone, domain, GCP project, region, VM name or IP address of one agency. Read these values from the agency's own Worker variables and secrets. Test fixtures can use example values.
- **Do not change one agency's fork by hand.** Put the fix in this repo. An agency gets the fix when its fork takes the change.
- **Every cell gets the same releases, through three channels:** `alpha` first (the cell of our own agency, used for tests). Then `beta` (our first customer and a partner) after the release works on alpha. Then `stable` (every other agency) after it works on beta.
- **The agency owns its infrastructure.** This Worker acts with the agency's own credentials. The platform holds no account in the agency's Cloudflare or Google Cloud.
