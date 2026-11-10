package main

import rego.v1

deploy_job_with(reference) := {"jobs": {"deploy": {
	"permissions": {"contents": "read", "id-token": "write"},
	"steps": [{"uses": reference}],
}}}

test_tag_pinned_action_in_id_token_job_is_denied if {
	count(deny) > 0 with input as deploy_job_with("google-github-actions/auth@v2")
}

test_sha_pinned_action_in_id_token_job_passes if {
	count(deny) == 0 with input as deploy_job_with("google-github-actions/auth@6fc4af4b145ae7821d527454aa9bd537d1f2dc5f")
}

test_workflow_level_id_token_counts if {
	count(deny) > 0 with input as {
		"permissions": {"id-token": "write"},
		"jobs": {"deploy": {"steps": [{"uses": "google-github-actions/setup-gcloud@v2"}]}},
	}
}

test_tag_pinned_action_without_id_token_only_warns if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"uses": "actions/checkout@v4"}]}}}
	count(deny) == 0 with input as policy_input
	count(warn) > 0 with input as policy_input
}

test_local_action_is_not_flagged if {
	policy_input := {"jobs": {"build": {"permissions": {"id-token": "write"}, "steps": [{"uses": "./.github/actions/setup"}]}}}
	count(deny) == 0 with input as policy_input
	count(warn) == 0 with input as policy_input
}

test_unpinned_pip_install_warns if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"run": "python -m pip install --disable-pip-version-check semgrep"}]}}}
	count(warn) > 0 with input as policy_input
}

test_pinned_pip_install_passes if {
	policy_input := {"jobs": {"policy": {"permissions": {"contents": "read"}, "steps": [{"run": "python -m pip install --disable-pip-version-check semgrep==1.97.0\npip install -r requirements.txt"}]}}}
	count(warn) == 0 with input as policy_input
}
