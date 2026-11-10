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
# name. `github.sha` is deliberately not in this set — it is a 40-character hex id, not text a
# contributor can author.
#
# Bracket notation (`github['event']['pull_request']['title']`) reads the same value as dot
# notation, and a function wrapper (`toJSON(github.event)`, `format('{0}', github.event.body)`)
# passes it on just as directly. All of these are the same sink, so the pattern allows anything
# between `${{` and the reference and accepts either notation. Requiring the literal prefix
# `github.event` right after `${{` would be a bypass that any PR could write by hand.
#
# The `(?i)` flag on the assembled pattern matters for the same reason: GitHub resolves expression
# context and property names case-insensitively, so `${{ GITHUB.EVENT.pull_request.title }}` reads
# exactly the attacker-authored title that the lowercase spelling does. A case-sensitive pattern
# would be a bypass that any PR could write by holding down the shift key.

# A reference to an injectable context, in dot or in bracket notation. Case is folded by the flag
# on the assembled pattern below.
injectable_context_reference := `github\s*(\.\s*|\[\s*['"]\s*)(event|head_ref)`

# A single-quoted expression string, consumed whole. `''` is the escape for one quote inside the
# string and `\[^\n]` allows the backslash form; either way the run of characters between the two
# outer quotes is opaque.
#
# The string cannot cross a newline. A `run:` block is usually multi-line, and prose on one line
# often carries an apostrophe (`don't`, `it's`). Without the `\n` exclusion, two such apostrophes on
# different lines would pair up into one quoted string, and any `}}` between them would stop
# terminating an expression — which then reports a real injection as absent. Restricting the string
# to one line keeps those apostrophes separate, and matches how a shell heredoc reads them anyway.
quoted_expression_string := `'(?:''|[^'\\\n]|\\[^\n])*'`

# The body of a `${{ ... }}` expression, up to the `}}` that closes it. A single `}` is allowed
# because a wrapper such as `format('{0}', ...)` puts one between `${{` and the reference; only the
# doubled `}}` ends the expression.
#
# A quoted string is consumed by the third branch before the other two can see its characters, so a
# `}}` inside quotes does not end the expression — which is what GitHub does too. Without that
# branch, `${{ format('}}{0}', github.event.pull_request.title) }}` stops the body at the quoted
# `}}` and the reference past it goes unreported, while GitHub still substitutes the attacker's
# title into the shell. A `}}` outside a quoted string still cannot be crossed, so a mention of
# `github.event` in the text after a closed expression is not a finding.
expression_body := sprintf(`(?:[^}]|\}[^}]|%s)*`, [quoted_expression_string])

injectable_context_pattern := sprintf(`(?i)\$\{\{%s%s`, [expression_body, injectable_context_reference])

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
	msg := sprintf("Workflow job %q has a `run:` script that interpolates a github.event or github.head_ref value directly, in dot or bracket notation. That is a shell-injection sink: pass it through `env:` and reference it as a shell variable instead.", [job_name])
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
