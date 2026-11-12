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

## Threat model

Workflow files are untrusted input. The scanner does not execute them, render expressions, or follow `uses`. Each file is capped at 1 MiB, a directory at 200 files and 8 MiB, and the YAML tree at 100000 nodes and depth 32. Directory walks reject symlink components and `..`.

## Non-goals

It does not verify action source, signatures, or attestations. It does not call GitHub with write scopes or read private actions. `contents: write` is not `write-all`. `github_pat_` tokens are out of scope.

## Sample findings

No public repository is named `platform-templates`. `github/platform-templates` returns 404, and repository search returns no repository with that name. This README does not include findings from a different repository.

## CI

`.github/workflows/ci.yml` pins `actions/checkout@v4` and `actions/setup-go@v5` to the SHAs in `gha-pins.json`, sets `permissions: contents: read`, and runs `bash scripts/check.sh`. On Go 1.26.10 that check fails `govulncheck` with GO-2026-6859 in `net/http`, fixed in Go 1.26.11. The toolchain was not upgraded.
