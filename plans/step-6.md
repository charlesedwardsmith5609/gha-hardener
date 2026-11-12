# Step 6: remote-script rule

Flag a `run` step that executes a script fetched by `curl` or `wget` when that URL is not pinned to a 40-character commit SHA. This is the `bash <(curl …/main/…)` pattern in platform-templates `ci.yml`. Download-only `curl` stays clean.

## Files

- `REQUIREMENTS.md`, `docs/rules.md`, `docs/design.md`, `README.md`, `DECISIONS.md`. Add rule `remote-script`.
- `internal/rules/remote.go` (new). `Remote(wf) []Finding`. No I/O. Calling goroutine owns the string it scans.
- `internal/rules/all.go`. Call `Remote` next to the other rules.
- `internal/report/report.go`. SARIF driver entry, level error, placed after `pull-request-target-checkout`.
- `testdata/fixtures/remote-script/good.yml` and `bad.yml`.
- `internal/rules/rules_test.go`. Table: good, bad, pipe to `bash`, `curl -o` then unzip, quoted echo of the pattern, `#` comment, SHA-pinned `raw.githubusercontent.com` URL, URL in a shell variable, backslash line continuation into `| bash`.
- `testdata/fixtures/golden/workflow.yml`. One extra `run` that trips this rule, appended so existing finding lines stay put.
- `testdata/golden/all.sarif`. Regenerated once; byte compare stays.
- `internal/report/report_test.go`. The golden assertion includes `remote-script`.

## Behavior

Severity `error`. One finding per `run` step. Location is the `run` scalar's line and column. Message: `run script executes a remote script that is not pinned to a commit SHA`.

Outside single quotes, double quotes, and `#` comments (quotes suppress comments):

- A shell word `bash`, `sh`, `dash`, `zsh`, `ksh`, or `ash` followed by `<(curl` or `<(wget`, optional whitespace.
- Or a command word `curl` or `wget` whose pipeline (`|`, optional `sudo`) reaches one of those shells.
- Or `eval` of `$(curl` / `$(wget`.

A backslash-newline is whitespace. A URL argument is pinned when a `/` segment is exactly 40 hex digits, either case. Every URL argument must be pinned. No URL argument is a finding. `curl -o` that is not executed by a shell is not a finding. The match is on the command word, so `mycurl` does not match.

## Shared state

None. `Remote` does not start goroutines and does not take a lock.

## Tests

Table tests above, through `workflow.Parse`. No sleeps. Golden SARIF still lists every rule id, including `remote-script`, before the byte compare. After the code exists, rescan platform-templates `c05f37ed` or newer `main` and put the real text finding for `ci.yml` in the README. The other two workflows stay clean. `gha-hardener`'s own `.github/workflows/ci.yml` stays clean.

## Out of scope

Pinning the remote script with `--fix`, fetching the URL, flagging `actions/github-script`, and flagging a download that is executed later as a file (`curl -o /tmp/x && bash /tmp/x`). The rule is streaming, process substitution, `eval`, and `shell -c` only.

## Review outcomes

Plan review (cursor, gpt-5.6-sol-high):

- Disagree with dropping the step. The user said to go ahead on this pattern. The requirement is added to `REQUIREMENTS.md` before the code.
- Agree: `eval "$(curl …)"` runs inside double quotes. Command substitutions in double quotes count. Single-quoted text is rescanned only when it is the script given to `eval` or `shell -c`.
- Agree: a 40-hex segment pins a URL only for `https://raw.githubusercontent.com` and `https://github.com`, with no userinfo and no port. Any other host stays unpinned.
- Agree: a backslash-newline is deleted, including inside a command name (`cu\` + newline + `rl`).
- Agree: tests cover `wget`, `eval`, `sudo` with a flag, and shells other than `bash`.
- Agree: a URL is `--url=`, the word after `--url`, a word containing `://`, or a variable word. One unpinned URL among several is a finding. No URL is a finding.
- Agree: `#` starts a comment only at a word boundary. `x=foo#bar; curl … | bash` is a finding.
- Agree with the stated boundary: `curl -o` followed by executing the file is out of scope and has a test that expects no finding.
