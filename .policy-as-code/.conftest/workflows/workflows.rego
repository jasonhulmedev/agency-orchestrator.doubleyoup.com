# GitHub Actions workflow policy, ported from orchestrator.doubleyoup.com (agency-orchestrator#26).
# The rules and their messages are the orchestrator's; the messages name its deploy.yml as the
# model shape, which this repo does not have yet. The message is still the right advice: a
# workflow job that needs to reach a cloud declares the minimum scopes it needs and no more.
#
# The trigger block does NOT arrive under the key "on". The YAML parser resolves the bare word
# `on` to the boolean true, so it lands under the key "true" — confirmed with
# `conftest parse .github/workflows/policy.yml`. Read triggers through the helper below rather
# than reaching for input.on, which is always undefined.
#
# WHY IT MATTERS. A workflow's token scopes and the values it pastes into a shell are the
# security story of the workflow. Every agency forks this repo, so a workflow here is the same
# code running in hundreds of agencies' own Cloudflare accounts.
#
# Unpinned `uses:` refs are checked in supply_chain.rego next to this file, not here.
package main

import rego.v1

triggers := object.get(input, "true", {})

# `on:` accepts a map (on: {push: {...}}) or a sequence (on: [push]); cover both.
trigger_names contains name if {
	some name, _ in triggers
}

trigger_names contains name if {
	some name in triggers
	is_string(name)
}

# A run script that interpolates attacker-influenced context is a shell-injection sink: the
# value is pasted into the script before the shell sees it. Passing it through `env:` and
# referencing "$VAR" is the safe form, which is what deploy.yml already does for the repository
# name. `github.sha` is deliberately not in this set — it is a 40-character hex id, not text a
# contributor can author.
injectable_context_pattern := `\$\{\{\s*github\.(event|head_ref)`

deny contains msg if {
	"pull_request_target" in trigger_names
	msg := "Workflow: the pull_request_target trigger runs with the base repository's secrets while checking out a fork's code. In a repo whose deploy job can reach the production VM, that is the one trigger to never use. Use pull_request, and gate anything privileged behind a separate approved job."
}

deny contains msg if {
	some job_name, job in input.jobs
	not job.permissions
	not input.permissions
	msg := sprintf("Workflow job %q declares no `permissions:`, so it inherits the repository default token scopes rather than the minimum it needs. deploy.yml's own job declares contents:read + id-token:write — match that shape.", [job_name])
}

deny contains msg if {
	some job_name, job in input.jobs
	some step in job.steps
	regex.match(injectable_context_pattern, step.run)
	msg := sprintf("Workflow job %q has a `run:` script that interpolates a github.event value directly. That is a shell-injection sink: pass it through `env:` and reference it as a shell variable instead.", [job_name])
}

# GCP auth here is keyless Workload Identity Federation (deploy.yml, docs/DEPLOY-ON-MERGE.md).
# A `credentials_json:` input is the other way to do it: a long-lived service-account private
# key, held in a repo secret, that keeps working after it leaks.
deny contains msg if {
	some job_name, job in input.jobs
	some step in job.steps
	object.get(step, "with", {})["credentials_json"]
	msg := sprintf("Workflow job %q authenticates to Google Cloud with `credentials_json`, a long-lived service-account key. This repo's deploy uses keyless Workload Identity Federation (workload_identity_provider + service_account), whose credential is minted per run and expires on its own.", [job_name])
}

# Canary. A workflow always has jobs, so finding none means the parsed shape changed and the
# rules above are matching nothing.
deny contains msg if {
	not input.jobs
	msg := "Workflow policy is inert: the parsed document has no `jobs` key, so the rules in workflows.rego cannot match. Check the shape with a probe policy before trusting a pass."
}
