# Unit tests for workflows.rego. Run with: npm run conftest:test
#
# Note the "true" key: that is where the YAML parser puts an unquoted `on:` block. A quoted
# `"on":` keeps the string key, so the trigger tests below cover both keys and all three value
# shapes (map, sequence, bare scalar).
#
# Ported from orchestrator. The deploy fixture pins google-github-actions/auth to a commit SHA
# (orchestrator has @v2): supply_chain.rego shares package main and denies a tag-pinned action
# in a job with id-token: write.
package main

import rego.v1

current_deploy_workflow := {
	"name": "Deploy on merge",
	"true": {"push": {"branches": ["main"]}},
	"jobs": {"deploy": {
		"permissions": {"contents": "read", "id-token": "write"},
		"steps": [
			{
				"name": "Authenticate to Google Cloud (keyless WIF)",
				"uses": "google-github-actions/auth@6fc4af4b145ae7821d527454aa9bd537d1f2dc5f",
				"with": {
					"workload_identity_provider": "${{ secrets.GCP_WIF_PROVIDER }}",
					"service_account": "${{ secrets.GCP_DEPLOY_SA }}",
				},
			},
			{
				"name": "Pull + hot-reload on the prod VM",
				"env": {"SERVICE_DIR": "${{ github.event.repository.name }}"},
				"run": "gcloud compute ssh \"$GCP_VM\" --command=\"... ${DEPLOY_ROOT}/${SERVICE_DIR} ...\"",
			},
			{"name": "Summary", "run": "echo \"Merged ${{ github.sha }} → pulled on ${GCP_VM}.\" >> \"$GITHUB_STEP_SUMMARY\""},
		],
	}},
}

test_current_deploy_workflow_has_no_denials if {
	count(deny) == 0 with input as current_deploy_workflow
}

test_denies_pull_request_target if {
	msgs := deny with input as {"true": {"pull_request_target": null}, "jobs": {}}
	some msg in msgs
	contains(msg, "pull_request_target")
}

test_denies_pull_request_target_in_sequence_form if {
	msgs := deny with input as {"true": ["push", "pull_request_target"], "jobs": {}}
	some msg in msgs
	contains(msg, "pull_request_target")
}

# A workflow author may quote the trigger key. `"on":` parses to the string key, not the boolean
# key, so the denial has to read both spellings or the quoted one becomes a bypass.
test_denies_pull_request_target_under_the_quoted_on_key if {
	msgs := deny with input as {"on": {"pull_request_target": null}, "jobs": {}}
	some msg in msgs
	contains(msg, "pull_request_target")
}

test_denies_pull_request_target_under_the_quoted_on_key_in_sequence_form if {
	msgs := deny with input as {"on": ["push", "pull_request_target"], "jobs": {}}
	some msg in msgs
	contains(msg, "pull_request_target")
}

# `on:` also accepts one bare event name with no map and no list.
test_denies_pull_request_target_in_scalar_form if {
	msgs := deny with input as {"true": "pull_request_target", "jobs": {}}
	some msg in msgs
	contains(msg, "pull_request_target")
}

test_denies_pull_request_target_in_scalar_form_under_the_quoted_on_key if {
	msgs := deny with input as {"on": "pull_request_target", "jobs": {}}
	some msg in msgs
	contains(msg, "pull_request_target")
}

test_allows_a_workflow_with_no_pull_request_target_trigger if {
	count(deny) == 0 with input as {
		"on": ["pull_request"],
		"jobs": {"build": {"permissions": {"contents": "read"}, "steps": [{"run": "echo ok"}]}},
	}
}

test_denies_a_job_with_no_permissions if {
	msgs := deny with input as {"jobs": {"build": {"steps": []}}}
	some msg in msgs
	contains(msg, "declares no `permissions:`")
}

test_allows_a_job_covered_by_workflow_level_permissions if {
	covered := {
		"permissions": {"contents": "read"},
		"jobs": {"build": {"steps": []}},
	}
	count(deny) == 0 with input as covered
}

test_denies_github_event_interpolated_into_a_run_script if {
	injected := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo ${{ github.event.pull_request.title }}"}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_denies_head_ref_interpolated_into_a_run_script if {
	injected := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "git checkout ${{ github.head_ref }}"}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

# Bracket notation reads the same context value as dot notation, so it is the same sink. A pattern
# that matched only the dotted form would be a bypass any PR could write by hand.
test_denies_github_event_in_bracket_notation_interpolated_into_a_run_script if {
	injected := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ github['event']['pull_request']['title'] }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_denies_head_ref_in_bracket_notation_interpolated_into_a_run_script if {
	injected := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "git checkout ${{ github[\"head_ref\"] }}"}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_allows_an_unrelated_bracket_expression_in_a_run_script if {
	safe := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ matrix['node-version'] }}\""}],
	}}}
	count(deny) == 0 with input as safe
}

# A function wrapper passes the same value on just as directly, so requiring `github.event` to sit
# right after `${{` would be the same bypass with a different shape.
test_denies_github_event_inside_a_function_wrapper if {
	injected := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ toJSON(github.event.pull_request.title) }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_denies_github_event_inside_a_format_wrapper if {
	injected := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ format('{0}', github.event.issue.body) }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

# GitHub resolves context and property names case-insensitively, so an uppercase spelling reaches
# the same attacker-authored value as the lowercase one.
test_denies_uppercase_github_event_interpolated_into_a_run_script if {
	injected := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ GITHUB.EVENT.pull_request.title }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_denies_mixed_case_github_event_interpolated_into_a_run_script if {
	injected := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ GitHub.Event.pull_request.title }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_denies_uppercase_github_event_in_bracket_notation if {
	injected := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ GITHUB['EVENT']['pull_request']['title'] }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_denies_uppercase_github_head_ref_interpolated_into_a_run_script if {
	injected := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "git checkout ${{ GITHUB.HEAD_REF }}"}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_denies_uppercase_github_event_inside_a_function_wrapper if {
	injected := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ toJSON(GITHUB.EVENT.pull_request.title) }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

# A `}}` inside a quoted expression string does not end the expression, so the reference past it is
# still substituted by GitHub and has to be a finding here too.
test_denies_github_event_after_a_quoted_double_brace_in_the_format_pattern if {
	injected := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ format('}}{0}', github.event.pull_request.title) }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

# The doubled quote is the expression language's own escape for one literal quote, so it does not
# close the string either.
test_denies_github_event_after_a_quoted_double_brace_with_a_doubled_quote if {
	injected := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ format('it''s }}{0}', github.event.issue.body) }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_denies_github_event_after_a_quoted_double_brace_with_a_backslash_escape if {
	injected := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ format('a\\'}}b{0}', github.event.issue.body) }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_denies_uppercase_github_event_after_a_quoted_double_brace if {
	injected := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ format('}}{0}', GITHUB.EVENT.pull_request.title) }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_allows_a_run_script_that_mentions_github_event_only_in_a_variable_name if {
	safe := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ steps.build.outputs.github_event_summary }}\""}],
	}}}
	count(deny) == 0 with input as safe
}

# The case-insensitive match folds the context name only, not the whole script, so an uppercase
# output name that merely contains the words is still safe.
test_allows_an_uppercase_output_name_that_mentions_github_event if {
	safe := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ steps.build.outputs.GITHUB_EVENT_SUMMARY }}\""}],
	}}}
	count(deny) == 0 with input as safe
}

# The quoted-string branch has to stop at the `}}` that really closes the expression, otherwise a
# mention of github.event in the shell text after a closed expression would be reported as an
# interpolation of it.
test_allows_a_github_event_mention_in_the_shell_text_after_a_closed_expression if {
	safe := {"jobs": {"build": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ github.sha }}\" # don't interpolate github.event.title here"}],
	}}}
	count(deny) == 0 with input as safe
}

# A multi-line `run:` script often carries prose apostrophes (`don't`, `it's`). If a quoted string
# could cross a newline, the apostrophe on the earlier line would pair with the one on the later
# line, the `}}` between them would stop terminating an expression, and the real injection past it
# would go unreported. The newline exclusion in the pattern keeps the two separate.
test_denies_github_event_after_an_apostrophe_on_an_earlier_line_of_the_script if {
	injected := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"${{ steps.a.outputs.don't }}\"\necho \"${{ github.event.pull_request.title }}\""}],
	}}}
	msgs := deny with input as injected
	some msg in msgs
	contains(msg, "shell-injection sink")
}

test_allows_github_event_passed_through_env if {
	safe := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{
			"env": {"TITLE": "${{ github.event.pull_request.title }}"},
			"run": "echo \"$TITLE\"",
		}],
	}}}
	count(deny) == 0 with input as safe
}

# The safe form stays safe whichever notation carries it into `env:`, because the policy reads the
# `run:` script and not the env mapping.
test_allows_github_event_passed_through_env_in_bracket_notation if {
	safe := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{
			"env": {"TITLE": "${{ github['event']['pull_request']['title'] }}"},
			"run": "echo \"$TITLE\"",
		}],
	}}}
	count(deny) == 0 with input as safe
}

# github.sha is a commit id, not authored text, so it must not be treated as an injection sink.
test_allows_github_sha_in_a_run_script if {
	safe := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{"run": "echo \"Merged ${{ github.sha }}\""}],
	}}}
	count(deny) == 0 with input as safe
}

test_denies_a_long_lived_gcp_service_account_key if {
	keyed := {"jobs": {"deploy": {
		"permissions": {"contents": "read"},
		"steps": [{
			"uses": "google-github-actions/auth@6fc4af4b145ae7821d527454aa9bd537d1f2dc5f",
			"with": {"credentials_json": "${{ secrets.GCP_SA_KEY }}"},
		}],
	}}}
	msgs := deny with input as keyed
	some msg in msgs
	contains(msg, "long-lived service-account key")
}

test_canary_fires_when_there_are_no_jobs if {
	msgs := deny with input as {"name": "Deploy on merge"}
	some msg in msgs
	contains(msg, "policy is inert")
}
