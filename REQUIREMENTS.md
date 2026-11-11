# Requirements

Go CLI that scans GitHub Actions workflow files for supply-chain risks and can pin action tags to commit SHAs from a local lockfile.

## Commands

- `gha-hardener` and `gha-hardener scan` scan workflow files. Default directory: `.github/workflows`.
- `gha-hardener resolve` is the only command that opens a network connection. It writes `gha-pins.json`.
- `scan --fix` rewrites tags to SHAs using that lockfile. `--fix` never contacts the network.

## Rules

Each rule has a good and a bad fixture. Severities: `note` < `warning` < `error`.

| ID | Severity | Reports when |
|----|----------|----------------|
| `unpinned-action` | warning | `uses` refers to a GitHub action or reusable workflow whose ref is not a 40-hex-char commit SHA. Local `./` actions and `docker://` images are out of scope. |
| `permissions-missing` | warning | A job's effective permissions are unset. Effective permissions are the job `permissions` block, or the workflow block when the job omits one. A workflow with no jobs is reported when the workflow block is absent. `permissions: {}` and `permissions: read-all` are set, not missing. |
| `permissions-write-all` | error | Effective permissions are the scalar `write-all` (any case). Individual `contents: write` grants are not this rule. |
| `pull-request-target-checkout` | error | `on` includes `pull_request_target` and a step checks out untrusted PR head. Checkout means `uses: actions/checkout` with `with.ref` or `with.repository` containing `github.event.pull_request.head`, `github.event.pull_request.merge_commit_sha`, or `refs/pull/`, or a `run` script containing `github.event.pull_request.head` or `refs/pull/`. The `github.event` needles are case-insensitive. `refs/pull/` is case-sensitive. A checkout with neither an unsafe `with.ref` nor an unsafe `with.repository` is not a finding. `with.repository` alone is enough. |
| `secrets-untrusted-trigger` | error | The workflow `on` includes an untrusted trigger and a workflow, job, or step `env`, `with`, or `run` expression reads the `secrets` context, unless every such access is exactly `secrets.GITHUB_TOKEN`, `secrets['GITHUB_TOKEN']`, or `secrets["GITHUB_TOKEN"]`. `toJSON(secrets)`, `secrets[github.event.issue.title]`, and any other secret name are findings. `github.token` is not a secrets access. |
| `unscoped-pat` | error | An `env` entry (workflow, job, or step) contains a classic PAT literal `ghp_` plus at least 20 alphanumerics, or an env name equal (any case) to `PAT`, `GH_PAT`, `GITHUB_PAT`, `PERSONAL_ACCESS_TOKEN`, `GH_TOKEN`, or `GITHUB_PERSONAL_ACCESS_TOKEN` whose value reads `secrets` and any of those reads is not exactly `secrets.GITHUB_TOKEN` (dot or quoted brackets, any case, ending on an identifier boundary). A reserved name with no `secrets` access, including `GH_TOKEN: generated-at-runtime` and `GH_TOKEN: ${{ github.token }}`, is not a finding. A value that reads both `GITHUB_TOKEN` and another secret is a finding. `PATH` is not a PAT name. |
| `script-injection` | error | A `run` scalar's `${{ ... }}` expression reads the `event` property of `github`, written as `github.event` (not followed by an identifier character) or `github['event']` / `github["event"]`, with optional whitespace around `.` and brackets. The names `github` and `event` are matched case-insensitively. `github.event_name`, `github.event_path`, and `github['event_name']` do not match. The same expression placed only in `env` is not a finding. |

Untrusted triggers: `pull_request`, `pull_request_target`, `issue_comment`, `issues`, `pull_request_review`, `pull_request_review_comment`, `discussion`, `discussion_comment`, `workflow_run`.

`on` must be recognized when it is a scalar (`on: push`), a list, or a mapping. The YAML 1.1 boolean value `on` must still be read as the trigger key.

## Output and exit codes

- Formats: `text` (default), `json`, `sarif`. SARIF is 2.1.0. Findings are ordered by file, line, column, rule id, message.
- Text lines: `file:line:column: severity: rule-id: message`. No findings writes nothing.
- JSON: `{"findings":[...]}` with fields `ruleId`, `severity`, `file`, `line`, `column`, `message`. Empty array when clean.
- `--fail-on` is `none`, `note`, `warning`, or `error`. Default `warning`. Exit 1 when any finding's severity is greater than or equal to the threshold. `none` never exits 1 because of findings.
- Exit 2 on usage errors, unreadable paths, rejected input, parse errors, a bad lockfile, or resolve failures. Exit 2 wins over exit 1. Files that parsed are still reported on stdout. File errors go to stderr.
- A run lists at most 1000 results. When there are more rule findings than fit, the first 999 in sort order are kept and a `findings-truncated` note is appended last. The note does not go through the sort.

## resolve and --fix

- Lockfile path defaults to `gha-pins.json`. Schema: `{"version":1,"pins":{"owner/repo@ref":{"sha":"<40 lowercase hex>","repository":"owner/repo","ref":"ref"}}}`. The key is `repository + "@" + ref`, where `repository` is the first two path segments of `uses` (`actions/checkout`, `github/codeql-action`). A subpath such as `github/codeql-action/init@v3` uses the key `github/codeql-action@v3` and `--fix` rewrites only the `@ref` suffix, leaving the subpath in place. A `uses` with no `@` uses ref `HEAD`. Keys are sorted. Unknown top-level or pin fields are rejected. Version must be 1. `repository` and `ref` in the object must match the key.
- `resolve` skips `./` local actions and `docker://` images. It collects unique `repository@ref` pairs, at most 128. More than 128 is exit 2 and no request is sent. `owner` and `repo` match `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$` and must not be `.` or `..`. For each remaining pair it sends exactly one `GET` to `https://api.github.com/repos/{owner}/{repo}/commits/{ref}`. The path is built from escaped segments and is rejected if it is not `/repos/{owner}/{repo}/commits/{ref}` with those three segments. No second request, no `Authorization` header, and no other method. One ref at a time on the calling goroutine. The calling goroutine owns the `http.Transport`, disables keep-alives, and calls `CloseIdleConnections` before returning. A parent context deadline of `min(2 minutes, timeout × ref count)` covers every dial, header wait, and body read.
- Host allowlist: `https://api.github.com`, and `http://127.0.0.1` (any port) so tests can run a local server. Redirects to any other host are refused. Userinfo, query, and fragment on the base URL are refused.
- `--timeout` is the per-request deadline (default 10s, allowed range 1s to 30s). It cannot extend the parent deadline above. The body is read up to 1 MiB plus one byte. That extra byte, or any trailing non-whitespace after the JSON value, rejects the response. A non-200, a non-JSON body, or a `sha` that is not 40 lowercase hex fails the command. On any failure, no lockfile is written.
- `--fix` rewrites a `uses` scalar only when the raw bytes at that node's line and column are exactly the plain value or the single-quoted value with no escaped quote. Double-quoted, block, and folded scalars are left unchanged and the finding remains. Replacement uses that byte span, so two `uses` values on one line are rewritten independently. The `@ref` suffix becomes `@` plus the lockfile SHA. A value with no `@` gains `@sha`. The subpath is unchanged. Missing pins are left in place. The new file is written to a temp file created with `O_EXCL` in the same directory and renamed over the destination (rename replaces a symlink; it does not write through one). `--fix` does not call the network.

## YAML dependency

Ask before adding `gopkg.in/yaml.v3`. It is the only non-stdlib dependency candidate, already used by agent-guard. Nothing else may be added to `go.mod`.

## Threat model

Workflow files are untrusted. The scanner does not execute them, does not render expressions, and does not follow `uses`. Caps: 1 MiB per file (`Parse` enforces this on its byte slice), 200 files, 8 MiB total, 100000 YAML nodes, nesting depth 32. Bytes read from a rejected oversized file count toward the 8 MiB total, and reading stops when that total is exhausted. Reject a second YAML document, alias nodes, and a `<<` merge key. Directory walk is not recursive and keeps at most 201 matching names. Names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml$`. Every component of the directory path is opened with `openat` and `O_NOFOLLOW|O_DIRECTORY` starting from `/` or `.`; a `..` component is rejected. Each file is opened with `openat` and `O_NOFOLLOW|O_NONBLOCK` on that directory descriptor. The descriptor must be a regular file. Invalid UTF-8 is rejected.

## Non-goals

- Does not verify action source code, signatures, or immutable-action attestations.
- Does not call GitHub with a token or any write scope.
- Does not resolve private actions.
- Does not treat `contents: write` as `write-all`.
- Does not flag `${{ github.head_ref }}` (only `github.event.*` in `run`).
- Does not flag fine-grained `github_pat_` tokens.

## Tests

- Table test per rule: one good fixture and one bad fixture.
- Parser rejection tests: merge key, alias, second document, invalid UTF-8, symlink, per-file size cap, node cap, total byte cap, too many files.
- `resolve` talks to `httptest` on a real `127.0.0.1:0` listener. Every read has a deadline. The slow handler blocks on the request context and then returns. The test runs `resolve` on a worker goroutine and the test goroutine selects on that result and a 2s timer. No `time.Sleep` for synchronization. A redirect off the allowlist is refused, and a body over 1 MiB is refused.
- Golden SARIF file checked byte-for-byte against a fixture that triggers every rule.
- `bash scripts/check.sh` is the completion gate (gofmt, go vet, govulncheck, `go test -race -count=1`).

## Phases

1. Design doc and this rules list.
2. Parser plus `unpinned-action`, `permissions-missing`, `permissions-write-all`, and `script-injection`.
3. Remaining rules, text/JSON/SARIF, `--fail-on`, golden SARIF.
4. `resolve` and `--fix`.
5. CI workflow and README. README includes sample findings from a scan of platform-templates.

## Process

Plan review before each phase's code. Cross-model review at the end of each phase. Assess every finding (agree or disagree, with a reason). Apply fixes that were agreed. Log decisions in `DECISIONS.md`.
