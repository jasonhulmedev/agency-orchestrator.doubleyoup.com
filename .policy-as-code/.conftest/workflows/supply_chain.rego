# Rule dy-workflow-unpinned-supply-chain (conftest, workflows). Ported from app and infra,
# where it answers the security review of infra#160.
package main

import rego.v1

# Security review infra#160 (low): the policy workflow installs semgrep from pip with no
# version pin, and pins actions by tag (@v4), not by commit SHA. A tag can be moved by the
# action's publisher; a 40-hex commit SHA cannot. The risk is highest in a job that can mint
# a cloud credential (`id-token: write`): there a moved tag runs with the deploy identity.

full_sha_pattern := `@[0-9a-f]{40}$`

is_sha_pinned(reference) if {
	regex.match(full_sha_pattern, reference)
}

# A local action or a docker:// image is not a tag reference to a third-party repo.
is_local_or_docker(reference) if {
	startswith(reference, "./")
}

is_local_or_docker(reference) if {
	startswith(reference, "docker://")
}

grants_id_token(permissions) if {
	permissions == "write-all"
}

grants_id_token(permissions) if {
	is_object(permissions)
	object.get(permissions, "id-token", "") == "write"
}

job_can_mint_cloud_token(job) if {
	grants_id_token(object.get(job, "permissions", {}))
}

job_can_mint_cloud_token(job) if {
	not job.permissions
	grants_id_token(object.get(input, "permissions", {}))
}

tag_pinned_steps contains [job_name, reference] if {
	some job_name, job in input.jobs
	some step in object.get(job, "steps", [])
	reference := step.uses
	not is_sha_pinned(reference)
	not is_local_or_docker(reference)
}

deny contains msg if {
	some [job_name, reference] in tag_pinned_steps
	job_can_mint_cloud_token(input.jobs[job_name])
	msg := sprintf("Workflow job %q can mint a cloud credential (id-token: write) and runs %q, which is not pinned to a commit SHA. The action's publisher can move that tag, and the moved code then runs with the deploy identity. Pin it as owner/action@<40-hex sha> # vX.", [job_name, reference])
}

warn contains msg if {
	some [job_name, reference] in tag_pinned_steps
	not job_can_mint_cloud_token(input.jobs[job_name])
	msg := sprintf("Workflow job %q runs %q, which is not pinned to a commit SHA. Pin it as owner/action@<40-hex sha> # vX.", [job_name, reference])
}

# pip install <package> with no ==version. `-r file`, `-c file` and options are left out.
pip_install_words contains [job_name, words] if {
	some job_name, job in input.jobs
	some step in object.get(job, "steps", [])
	some line in split(object.get(step, "run", ""), "\n")
	contains(line, "pip install")
	after := split(line, "pip install")[1]
	words := [word | some word in split(trim_space(after), " "); word != ""]
}

unpinned_pip_packages contains [job_name, word] if {
	some [job_name, words] in pip_install_words
	some index, word in words
	not startswith(word, "-")
	not follows_file_option(words, index)
	not contains(word, "==")
	not contains(word, "@")
}

follows_file_option(words, index) if {
	index > 0
	words[index - 1] in {"-r", "--requirement", "-c", "--constraint"}
}

warn contains msg if {
	some [job_name, package_name] in unpinned_pip_packages
	msg := sprintf("Workflow job %q runs `pip install %s` with no version pin. A new release (or a compromised one) changes what CI runs without a PR. Pin it: %s==<version>.", [job_name, package_name, package_name])
}
