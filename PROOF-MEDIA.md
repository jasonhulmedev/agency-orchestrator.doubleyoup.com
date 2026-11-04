# Media soft delete (hub#222) — live proof steps

`npm run proof:media` proves, against ONE scratch R2 bucket, the R2
behaviours the Worker's media soft delete depends on. It runs the Worker's own
code (`src/media-store.ts`, `src/actuate-media.ts`, `src/sigv4.ts`) in Node with
the agency's `R2_PROVISION_API_TOKEN`. It does not need a deployed Worker.

| Step | Proves |
| --- | --- |
| a1, a2 | A presigned PUT that signs `if-none-match: *` creates a new key (200), and the same PUT onto that existing key answers **412** |
| b | The trash move (CopyObject with `x-amz-metadata-directive: COPY`) keeps the content type |
| b2 | A Worker copy onto an existing key is refused (**412**): R2 honours `cf-copy-destination-if-none-match: *` (an R2 beta extension). Rename, restore and the trash move rely on it to never replace an object |
| c1, c2 | `media-bucket-protect` writes the `trash/` lifecycle rule and bucket lock; a second run writes nothing |
| c3, c4 | A DELETE of the `trash/` object is refused (**409** expected) and the object is still there |
| d | With `--check-bucket <name>`: each named bucket exists in the token's account |

The script never prints the token, the derived S3 secret or a presigned URL.
Exit code 0 means every check passed.

## Warning: the scratch bucket stays locked for 30 days

Step c leaves a `trash/` object under a 30-day bucket lock. Until it expires,
the scratch bucket cannot be emptied or deleted. Use a bucket made only for
this proof, never a site's media bucket.

## Prereqs

- Node 22.18 or newer (the script loads the TypeScript sources directly), and
  `npm ci` in this repo.
- The agency's `R2_PROVISION_API_TOKEN`: an account-owned token with Workers R2
  Storage: Edit. Read it from wherever the agency keeps it; do not paste it
  into a file in the repo.
- A scratch bucket named `doubleyoup-media-<something>` in the same account,
  for example `doubleyoup-media-proof222`. Create it in the dashboard (R2 →
  Create bucket) or with the existing `provision-r2` op.

## Run

```sh
read -rs R2_PROVISION_API_TOKEN && export R2_PROVISION_API_TOKEN
npm run proof:media -- doubleyoup-media-proof222
```

Optional: set `R2_EXPECTED_ACCOUNT_ID` to make the script refuse a token of
another account.

## The account check (planning/51, planning/52 D8)

hub#222 needs the media buckets of a cell to live in the same Cloudflare
account as the agency Worker that writes them. To check this for a cell, use
that agency Worker's `R2_PROVISION_API_TOKEN` and name the cell's media buckets:

```sh
npm run proof:media -- doubleyoup-media-proof222 \
  --check-bucket doubleyoup-media-<site prefix> \
  --check-bucket doubleyoup-media-<another site prefix>
```

A `[PASS] d` line means the bucket is in the token's account. A `[FAIL] d`
line (HTTP 404 or 403) means it is not, or the token cannot see it. In that case
the Worker cannot be the writer of that bucket, and the site must not switch to
Worker mode until its media moves (planning/52 relocate) into the agency's
account.

## Expected output

```text
account <account id>, bucket doubleyoup-media-proof222
[PASS] a1 presigned create-once PUT of a new key: HTTP 200 (want 200)
[PASS] a2 the same PUT onto the existing key: HTTP 412 (want 412)
[PASS] b  copy into trash/ keeps the content type: source "text/plain; charset=utf-8", trash "text/plain; charset=utf-8" (trash/<day>/proof222/proof-222/<run>.txt)
[PASS] b2 create-once CopyObject onto an existing key: HTTP 412 (want 412)
[PASS] c1 media-bucket-protect: lifecycle created, lock created
[PASS] c2 media-bucket-protect again writes nothing: lifecycle unchanged, lock unchanged
[PASS] c3 DELETE of the trash/ object: HTTP 409 ... (want 409)
[PASS] c4 the trash/ object is still there: present
```

A second run against the same bucket reports `lifecycle unchanged, lock
unchanged` in c1. If c3 answers a refusal status other than 409 (for example
403), the lock still works, but record the status: the docs name 409. The
Worker itself never deletes anything under `trash/`.
