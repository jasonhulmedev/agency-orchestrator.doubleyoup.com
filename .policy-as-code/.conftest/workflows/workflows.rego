# GitHub Actions workflow policy, ported from orchestrator.doubleyoup.com (agency-orchestrator#26).
# The rules and their messages are the orchestrator's; the messages name its deploy.yml as the
# model shape, which this repo does not have yet. The message is still the right advice: a
# workflow job that needs to reach a cloud declares the minimum scopes it needs and no more.
#
# The trigger block arrives under one of two keys, depending on how the workflow author quoted it.
# Read triggers through the helpers below, which cover both keys and all three value shapes, rather
# than reaching for input.on or input["true"] directly.
#
# WHY IT MATTERS. A workflow's token scopes and the values it pastes into a shell are the
# security story of the workflow. Every agency forks this repo, so a workflow here is the same
# code running in hundreds of agencies' own Cloudflare accounts.
#
# Unpinned `uses:` refs are checked in supply_chain.rego next to this file, not here.
package main

import rego.v1

# The YAML parser resolves the bare word `on` to the boolean true, so an unquoted `on:` lands under
# the key "true", while a quoted `"on":` keeps the string key "on". Both spellings are valid
# workflow YAML — confirmed with `conftest parse` on both forms, and on the other YAML boolean
# spellings (`On:`, `ON:`, `yes:`), which also resolve to "true". A policy that read only one key
# would be a bypass rather than a gate.
trigger_keys := {"true", "on"}

trigger_block(key) := object.get(input, key, {})

# `on:` accepts a map (on: {push: {...}}), a sequence (on: [push]) or a bare scalar
# (on: pull_request_target); cover all three.
trigger_names contains name if {
	some key in trigger_keys
	block := trigger_block(key)
	is_object(block)
	some name, _ in block
}

trigger_names contains name if {
	some key in trigger_keys
	block := trigger_block(key)
	is_array(block)
	some name in block
	is_string(name)
}

trigger_names contains name if {
	some key in trigger_keys
	block := trigger_block(key)
	is_string(block)
	name := block
}

# A run script that interpolates attacker-influenced context is a shell-injection sink: the
# value is pasted into the script before the shell sees it. Passing it through `env:` and
# referencing "$VAR" is the safe form, which is what deploy.yml already does for the repository
# name.
#
# This is an ALLOWLIST, not a blocklist. Earlier versions looked for the spellings of
# `github.event` and `github.head_ref` (dot, bracket, wrapped in a function, upper case, ...),
# and each fix left the next spelling open: `toJSON(github)` dumps the whole context including
# the pull request title, `github.*.pull_request.title` filters it out of the context, and
# `github[format('{0}', 'event')]` builds the property name at run time. So the rule works the
# other way round: inside a `${{ }}` expression of a `run:` script, every reference to the
# `github` context must be `github.<property>` where <property> is on the list below. Anything
# else (a bare `github`, `github.*`, `github[...]`, or an unlisted property) is denied. Passing
# the value through `env:` stays allowed because only `run:` scripts are inspected.
#
# The list holds only properties whose value a contributor cannot author. `ref`, `ref_name` and
# `head_ref` are not on it: a branch name can carry shell syntax. `github.sha` is a 40-character
# hex id. `actor` is a login name (letters, digits, hyphens). `event_name` is one of GitHub's
# fixed trigger names, unlike `github.event`, which holds the payload.
safe_github_properties := {
	"sha",
	"repository",
	"repository_owner",
	"run_id",
	"run_number",
	"run_attempt",
	"actor",
	"event_name",
	"workflow",
	"job",
	"server_url",
}

# A single-quoted expression string. `''` is the only escape GitHub knows for a quote inside the
# string; a backslash is an ordinary character. The string may span lines, as GitHub allows.
quoted_expression_string := `'(?:''|[^'])*'`

# One `${{ ... }}` expression. Outside a quoted string the body cannot contain a quote or a
# doubled `}}`, so a `}}` inside a quoted string (`format('}}{0}', ...)`) does not end the
# expression, which matches how GitHub reads it. A lone `}` is allowed (`format('{0}', ...)`
# keeps its brace inside the string anyway). An expression with an unbalanced quote does not
# match; GitHub rejects such a workflow when it parses it, so it never runs.
expression_pattern := sprintf(`(?s)\$\{\{(?:[^}']|\}[^}']|%s)*\}\}`, [quoted_expression_string])

# A reference to the `github` context, as one of three shapes: `github.<property>`, `github[`, or
# a `github` with anything else after it (a bare `github`, as in `toJSON(github)`). Only the first
# shape can be safe, and only for a listed property; `github.*` has `*` as its "property", which no
# list entry matches. Case is folded because GitHub resolves context and property names
# case-insensitively. The word must not be the tail of a longer path (`steps.github.outputs`), so
# the match takes one leading character that is not part of a name; Go regexp has no lookbehind.
github_reference_pattern := `(?i)(?:^|[^a-z0-9_.-])github(?:\s*\.\s*[a-z0-9_*-]+|\s*\[|[^a-z0-9_]|$)`

github_property_pattern := `(?i)^[^a-z0-9_.-]?github\s*\.\s*([a-z0-9_-]+)$`

is_safe_github_reference(reference) if {
	matches := regex.find_all_string_submatch_n(github_property_pattern, reference, 1)
	property := lower(matches[0][1])
	property in safe_github_properties
}

script_reads_unsafe_github_context(script) if {
	some expression in regex.find_n(expression_pattern, script, -1)

	# Text inside a quoted string is data, not a reference. Blank it so `'github.com'` is not a
	# finding, while `github['event']` still leaves a bare `github` behind.
	code_only := regex.replace(expression, quoted_expression_string, "''")
	some reference in regex.find_n(github_reference_pattern, code_only, -1)
	not is_safe_github_reference(reference)
}

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
	script_reads_unsafe_github_context(step.run)
	msg := sprintf("Workflow job %q has a `run:` script whose ${{ }} expression reads the github context beyond a short allowlist of safe properties (sha, repository, run_id, actor, ...). github.event, github.head_ref, github.ref_name, toJSON(github) and github[...] can carry text a contributor wrote, so this is a shell-injection sink: pass the value through `env:` and reference it as a shell variable instead.", [job_name])
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
