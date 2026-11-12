# Step 5: CI and README

## Files

- `.github/workflows/ci.yml` (new). `on: push` and `pull_request`. `permissions: contents: read`. Job `check` on `ubuntu-latest`. Steps: `actions/checkout` and `actions/setup-go` pinned to SHAs from `resolve` against `https://api.github.com`, then `bash scripts/check.sh`. `go-version-file: go.mod`. No secrets, no `github.event` in `run`.
- `gha-pins.json` (new) only if resolve is used to record those two refs. Committed so the workflow pins are reproducible.
- `README.md` (new). Usage for scan, `--fail-on`, formats, `resolve`, and `--fix`. Rule ids and severities. Threat model and non-goals copied from the requirements, short. A sample findings section from a real checkout of a public platform-templates workflow directory. If no repository with that name is reachable, say which repository was scanned and do not invent lines.
- `DECISIONS.md`. Log the toolchain vulnerability (already D-20) and the sample-repo choice.
- `plans/step-5.md` (this file).

## Types

No new Go types. The workflow is data. `gha-pins.json` uses lock version 1.

## Shared state

None. `resolve` for the two CI refs runs on the calling process, one request at a time, and writes the lockfile only after both SHAs return. The workflow file is written by this step, not by `--fix`, so its `uses` lines are plain scalars pinned before commit.

## Tests

No new Go tests. After the workflow exists, `go run ./cmd/gha-hardener --dir .github/workflows --fail-on warning` must exit 0. `bash scripts/check.sh` is run and the govulncheck stage is reported as it is: GO-2026-6859 on Go 1.26.10. This step does not bump the Go version.

## Out of scope

A release workflow and pinning every action in an external sample repository.

## Review outcomes

Plan review (cursor, gpt-5.6-sol-high):

- Disagree with upgrading to Go 1.26.11 in this step. `AGENTS.md` says not to upgrade when govulncheck reports a vulnerability until the human approves. CI runs the check and will fail that stage. D-20.
- Agree: install `govulncheck` v1.9.0 in CI, the version already used locally. `actions/setup-go` puts `GOPATH/bin` on `PATH`.
- Agree: `actions/checkout` uses `persist-credentials: false`.
- Agree: do not substitute another repository for sample findings. `github/platform-templates` returns 404 and repository search has no repo whose name is `platform-templates`. The README says that and includes no invented lines.
- Agree: resolve `actions/checkout@v4` and `actions/setup-go@v5` and commit `gha-pins.json`.
