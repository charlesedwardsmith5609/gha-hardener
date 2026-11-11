# Step 3: remaining rules, reports, scan CLI

Adds the three remaining rules, text/JSON/SARIF output, `--fail-on`, and the scan command. No `resolve`, no `--fix`, no network.

## Files

- `internal/workflow/parse.go`: store `env` and `with`.
- `internal/rules/checkout.go`, `secrets.go`, `pat.go`, `all.go`.
- `internal/rules/rules_test.go`: tables for the three rules and the 1000 cap.
- `internal/report/report.go`: text, JSON, SARIF.
- `internal/report/report_test.go`: golden SARIF.
- `internal/cli/cli.go`, `internal/cli/cli_test.go`.
- `cmd/gha-hardener/main.go`: `os.Exit(cli.Run(...))`.
- `testdata/fixtures/{pull-request-target-checkout,secrets-untrusted-trigger,unscoped-pat}/{good,bad}.yml`
- `testdata/fixtures/golden/workflow.yml`
- `testdata/golden/all.sarif`

## Types

```go
type Env struct { Name, Value string; Line, Column int }
type Input struct { Name, Value string; Line, Column int } // one with entry
```

`Workflow.Env`, `Job.Env`, `Step.Env` are `[]Env`. `Step.With` is `[]Input`. A non-scalar env or with value is a parse error. `rules.All` concatenates every rule, sorts by file, line, column, rule id, message, and if more than 999 rule findings remain, keeps the first 999 and appends one `findings-truncated` note after the sort.

## Rules

- `pull-request-target-checkout` (error). Fires when `On` contains `pull_request_target` (case-sensitive event name) and a step either (a) `uses` is `actions/checkout` with any ref and `with.ref` or `with.repository` contains `github.event.pull_request.head`, `github.event.pull_request.merge_commit_sha`, or `refs/pull/`, or (b) `run` contains `github.event.pull_request.head` or `refs/pull/`. The `github.event...` needles are case-insensitive. `refs/pull/` is case-sensitive. A checkout with no ref is not a finding. Test that.
- `secrets-untrusted-trigger` (error). Fires when any untrusted event is present and an expression in workflow/job/step `env`, step `with`, or `run` reads `secrets` other than exactly `secrets.GITHUB_TOKEN` or `secrets['GITHUB_TOKEN']` / `secrets["GITHUB_TOKEN"]`. Comparison is case-insensitive. The property access must end at an identifier boundary (not `secrets.GITHUB_TOKEN_EXTRA`). `toJSON(secrets)` and `secrets[github.event.issue.title]` are findings. `github.token` is not. The expression lexer from step 2 skips quoted strings. The finding names the untrusted events, sorted and comma-separated.
- `unscoped-pat` (error). An env value matching `ghp_[A-Za-z0-9]{20,}` is a finding. An env name equal, case-insensitively, to `PAT`, `GH_PAT`, `GITHUB_PAT`, `PERSONAL_ACCESS_TOKEN`, `GH_TOKEN`, or `GITHUB_PERSONAL_ACCESS_TOKEN` is a finding when its value's secret access is not exactly `GITHUB_TOKEN` and is not `github.token`. `PATH` is not a match. `GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}` is clean.

Each rule has a good and a bad fixture file, plus the extra cases above in the same table.

## Reports

- Text: `file:line:column: severity: rule-id: message` and a trailing newline per finding. Empty input writes nothing.
- JSON: `{"findings":[...]}` with `ruleId`, `severity`, `file`, `line`, `column`, `message`. Indent of two spaces. Empty slice, not null.
- SARIF 2.1.0. Driver name `gha-hardener`, version `0.1.0`. Every rule id is listed, sorted, with `defaultConfiguration.level`. Results follow finding order. No timestamps, no absolute paths, no `$schema` URL that would differ by environment. `json.MarshalIndent` plus a trailing newline. The golden file is the SARIF of `testdata/fixtures/golden/workflow.yml` reported as `.github/workflows/ci.yml`. The test compares bytes.

## CLI

`cli.Run(args, stdout, stderr) int`. The calling goroutine owns the buffers. No goroutines and no network.

- Default command and `scan`. Flags: `--dir` (default `.github/workflows`), `--format` (`text`, `json`, `sarif`), `--fail-on` (`none`, `note`, `warning`, `error`, default `warning`).
- Exit 1 when a finding severity is greater than or equal to the threshold. `none` never exits 1 for findings.
- Per-file `LoadDir` errors go to stderr. Exit 2 if the directory cannot be opened or any file error is present. Exit 2 wins over exit 1. Findings for files that parsed are still written to stdout.
- Unknown flags or an unknown format exit 2. `resolve` and `--fix` are rejected with exit 2 in this step (step 4 implements them).

## Ownership

No shared state. `All` and the reporters allocate their output and do not retain the workflow.

## Tests

- Rule tables described above.
- `All` with 1000 direct `Job.Steps` unpinned uses yields 999 `unpinned-action` findings plus one trailing `findings-truncated` note.
- Golden SARIF byte compare.
- CLI on a temp directory: warning-only workflow exits 1 by default and 0 with `--fail-on error`; a workflow with an error exits 0 with `--fail-on none`; JSON contains `ruleId`; a symlink workflow plus a parsed workflow exits 2 and still writes the parsed finding. No `time.Sleep`.

## Review outcomes (plan review, cursor / gpt-5.6-sol-high)

- Disagree that depth 32 and component-wise `O_NOFOLLOW` are missing. Step 2 already enforces both (`TestParseRejectsDepth`, `TestLoadDirRejectsSymlinkComponent`). This step does not reimplement them. It does add a CLI test that `--dir` through an intermediate symlink exits 2.
- Agreed: a reserved PAT name with no `secrets` access is clean (`GH_TOKEN: generated-at-runtime`). A mix of `GITHUB_TOKEN` and another secret is a finding. `ghp_` literals still count on their own.
- Agreed: `with.repository` pointing at the PR head is a finding even when `with.ref` is absent. "No finding" means neither ref nor repository is unsafe.
- Agreed: `findings-truncated` is `note`, file `.`, line 1, column 1, message `%d findings omitted`, and SARIF includes that physical location.
- Agreed: reporters return write errors. The CLI exits 2 on a write error. A test uses a writer that always fails.
- Agreed: the golden workflow produces all seven rule ids, and the test checks that set before comparing bytes.
- Agreed: an unknown `--fail-on` value exits 2.

## Deferred

`resolve`, `--fix`, lockfile, CI, README, platform-templates sample.
