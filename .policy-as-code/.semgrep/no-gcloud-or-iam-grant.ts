// Fixture for no-gcloud-or-iam-grant.yaml.
//
// The quiet cases below matter as much as the matching ones. Two of those shapes are real code
// in the tree today — the role-name diagnostics in the agency Worker, and the migration prose in
// orchestrator's cell-run.ts — and the rule is only usable if it stays silent on both. See the
// yaml header, "WHAT IS DELIBERATELY NOT MATCHED".

// ── The shell-out half ──────────────────────────────────────────────────────────────────────

// ruleid: dy-no-gcloud-or-iam-grant-in-service-code
const listInstances = "gcloud compute instances list --project dy-prod";

// ruleid: dy-no-gcloud-or-iam-grant-in-service-code
const cleanupHint = `gcloud compute instances delete ${instanceName} --zone ${zone}`;

// ruleid: dy-no-gcloud-or-iam-grant-in-service-code
const sshArgs = ["compute", "ssh", "dy-file-syd-1", "--tunnel-through-iap"];

// ruleid: dy-no-gcloud-or-iam-grant-in-service-code
const iapFlag = "--tunnel-through-iap";

// ── The IAM half ────────────────────────────────────────────────────────────────────────────

// ruleid: dy-no-gcloud-or-iam-grant-in-service-code
const grantCommand = "gcloud projects add-iam-policy-binding dy-agency --member=serviceAccount:platform@dy.iam.gserviceaccount.com --role=roles/compute.instanceAdmin.v1";

// ruleid: dy-no-gcloud-or-iam-grant-in-service-code
const grantIap = `setIamPolicy adding roles/iap.tunnelResourceAccessor for ${member}`;

// ── Deliberately quiet ──────────────────────────────────────────────────────────────────────

// A role named in a diagnostic that asks the AGENCY to grant it on the AGENCY's own project.
// This is the shape of all 20 permissionHint strings in the agency Worker's actuate.ts.
// ok: dy-no-gcloud-or-iam-grant-in-service-code
const permissionHint = "compute.instances.create (e.g. roles/compute.instanceAdmin.v1)";

// ok: dy-no-gcloud-or-iam-grant-in-service-code
const missingPermission = `the service account is missing ${count} permission(s). Grant it "roles/compute.admin" on the project.`;

// The GCP REST API the Worker actually calls. Not the CLI, not an SSH session.
// ok: dy-no-gcloud-or-iam-grant-in-service-code
const computeApi = "https://compute.googleapis.com/compute/v1/projects";

// The sanctioned path: a Worker op name.
// ok: dy-no-gcloud-or-iam-grant-in-service-code
const op = "gcp-instance-set-metadata";

// The local Docker exec path, which is not a cell at all.
// ok: dy-no-gcloud-or-iam-grant-in-service-code
const composeExec = ["exec", "-T", "php", "sh", "-lc", script];

// A comment, not a literal: cell-run.ts and cells.ts both record the migration away from
// `gcloud compute ssh` into the cell VMs (planning/31 mechanism-B). The rule must not argue
// with its own documentation. --tunnel-through-iap, roles/compute.admin, add-iam-policy-binding.
// ok: dy-no-gcloud-or-iam-grant-in-service-code
const unrelated = "the cell-agent /run-site-info endpoint";
