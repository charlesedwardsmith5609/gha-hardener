# gha-hardener

Scans `.github/workflows/*.yml` and `*.yaml` for supply-chain risks. `--fix` pins action tags to commit SHAs from a local lockfile. `resolve` is the only command that uses the network.

The parser uses `gopkg.in/yaml.v3` v3.0.1. That is the only non-stdlib module.

## Usage

```sh
go run ./cmd/gha-hardener
go run ./cmd/gha-hardener --format sarif --fail-on error
go run ./cmd/gha-hardener resolve --timeout 10s
go run ./cmd/gha-hardener --fix
```

Scan flags: `--dir` (default `.github/workflows`), `--format` (`text`, `json`, `sarif`), `--fail-on`, `--fix`, `--lockfile` (default `gha-pins.json`). `resolve` flags: `--dir`, `--lockfile`, `--timeout` (default 10s, allowed 1s to 30s), `--api-base` (only `https://api.github.com` or `http://127.0.0.1`, for tests). Any other host, a bad flag value, an unknown command, or an unreadable directory exits 2. The directory is not searched recursively.

Text lines look like `file:line:column: severity: rule-id: message`. JSON is `{"findings":[...]}`. SARIF is 2.1.0. `--fail-on` is `none`, `note`, `warning` (default), or `error`. Exit 1 means a finding is at or above that level. Exit 2 means the invocation itself failed.

`resolve` writes `gha-pins.json`. It sends one GET per `owner/repo@ref` to `https://api.github.com` and does not send a token. `--fix` reads that file and does not call the network. It rewrites plain and single-quoted `uses` values. Double-quoted, block, and folded values stay as they are.

## Rules

| id | severity | what it reports |
|---|---|---|
| `unpinned-action` | warning | `uses` is not a 40-character SHA |
| `permissions-missing` | warning | no effective permissions block |
| `permissions-write-all` | error | `permissions: write-all` |
| `pull-request-target-checkout` | error | `pull_request_target` checks out a pull request head |
| `secrets-untrusted-trigger` | error | a secret other than `GITHUB_TOKEN` reaches an untrusted trigger |
| `unscoped-pat` | error | an env value is a classic PAT or a PAT-named secret |
| `script-injection` | error | a `run` step reads `github.event` |
| `remote-script` | error | a `run` step executes `curl` or `wget` output that is not pinned to a commit on `github.com` |

## Threat model

Workflow files are untrusted input. The scanner does not execute them, render expressions, or follow `uses`. Each file is capped at 1 MiB, a directory at 200 files and 8 MiB, and the YAML tree at 100000 nodes and depth 32. Directory walks reject symlink components and `..`.

## Non-goals

It does not verify action source, signatures, or attestations. It does not call GitHub with write scopes or read private actions. `contents: write` is not `write-all`. `github_pat_` tokens are out of scope.

## Sample findings

[platform-templates](https://github.com/charlesedwardsmith5609/platform-templates) at `c05f37ed6c665c4dd75af01cb4b0162a34c1e855` (`ci.yml`, `secrets-injection.yml`, `service-onboarding.yml`):

```text
ci.yml:103:14: error: remote-script: run script executes a remote script that is not pinned to a commit SHA
```

Exit code 1. That step is `bash <(curl …/rhysd/actionlint/main/scripts/download-actionlint.bash)`. The other two files produced no findings.

At `7f5678977743bec4c062aafd00d5db100cddf3cc` the same URL uses commit `3795ba2f6cb243eeca54c9d22e5c531cb9dcfb4a`. Those three files produce no findings and exit 0.

## CI

`.github/workflows/ci.yml` pins `actions/checkout@v4` and `actions/setup-go@v5` to the SHAs in `gha-pins.json`, sets `permissions: contents: read`, installs `govulncheck` v1.9.0, and runs `bash scripts/check.sh`. `go.mod` requires Go 1.26.11, which fixes GO-2026-6859 in `net/http` (see `DECISIONS.md`, D-20 and D-22). Running the scanner on this repository's own workflows prints nothing and exits 0.

## Pairing and review scripts

`scripts/` holds the agent-pairing-kit helpers this project was built with (kit commit 2ccbb85). `scripts/check.sh` is the completion gate: misbehavior and assertion heuristics, then gofmt, `go vet`, `govulncheck`, and `go test -race -count=1`. `scripts/cross-review.sh` (and `cross-review.ps1`) sends a diff to another AI provider for review after a `gitleaks` scan. It fails closed: a missing `gitleaks`, a scanner error, or a finding sends nothing. Only tracked changes are sent; name an untracked file with `--include PATH`. Files such as `.env*` and keys are never sent. Output goes to `.reviews/`, which is gitignored. `plan-review.sh` does the same for a plan in `plans/`.
