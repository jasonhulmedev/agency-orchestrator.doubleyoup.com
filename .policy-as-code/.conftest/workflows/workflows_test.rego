# Unit tests for workflows.rego. Run with: npm run conftest:test
#
# Note the "true" key: that is where the YAML parser puts the `on:` block.
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
