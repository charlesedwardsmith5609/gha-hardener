# Rules

Source of truth for behavior is `REQUIREMENTS.md`. This page is the short list.

1. **unpinned-action** (warning). `owner/repo@v4`, `owner/repo/path@main`, and `owner/repo` with no ref. Not a 40-hex SHA. Not `./local` and not `docker://`.
2. **permissions-missing** (warning). Job inherits nothing because neither the job nor the workflow sets `permissions`.
3. **permissions-write-all** (error). Effective value is `write-all`.
4. **pull-request-target-checkout** (error). `pull_request_target` plus a checkout of the PR head or `refs/pull/`.
5. **secrets-untrusted-trigger** (error). Any `secrets` context access under an untrusted trigger, except an access that is exactly `secrets.GITHUB_TOKEN` (dot or quoted brackets).
6. **unscoped-pat** (error). Classic `ghp_` literal in `env`, or a PAT-named env var pointing at a non-`GITHUB_TOKEN` secret.
7. **script-injection** (error). `run` reads `github.event` via dot or `github['event']` / `github["event"]`. Passing the value through `env` is the safe pattern and is not a finding.

`findings-truncated` (note) is appended last when rule findings would exceed 999, so the report stays within 1000 results. It is not a workflow rule.
