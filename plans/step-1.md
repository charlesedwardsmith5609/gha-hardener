# Step 1: design and rules list

No Go code in this step. Deliverables: `REQUIREMENTS.md`, `docs/design.md`, `docs/rules.md`, `DECISIONS.md`, this plan.

## Behavior this step locks

The scanner is a single-process CLI. Scan and `--fix` do not use the network. `resolve` is the only networked command.

Rules, severities, untrusted triggers, exit codes, lockfile schema, allowlist, and caps are those in `REQUIREMENTS.md`. This step does not change them.

## Files

- `REQUIREMENTS.md`: agreed behavior, threat model, non-goals, phases.
- `docs/design.md`: packages, parser, resolve, fix, ownership.
- `docs/rules.md`: the seven rules in short form.
- `DECISIONS.md`: D-01 through D-08.
- `plans/step-1.md`: this file.

No `go.mod` change. `gopkg.in/yaml.v3` is not added until step 2 (D-02).

## Types

None. Step 2 will add `workflow.Workflow`, `rules.Finding`, and the report types described in `docs/design.md`.

## Ownership

No shared state. The future `resolve` command will run GETs on the calling goroutine and will not share an `http.Client` across goroutines (D-06, design doc).

## Tests

None in this step. Step 2 adds table tests for the first rules. Step 3 adds the golden SARIF file. Step 4 adds the `127.0.0.1:0` resolve tests.

## Explicitly deferred

- Parser and the first four rule ids (step 2). `permissions-missing` and `permissions-write-all` both land in step 2 because they share effective-permission logic.
- Remaining rules, formats, `--fail-on` (step 3).
- `resolve` and `--fix` (step 4).
- CI, README, platform-templates sample (step 5).

## Risks the reviewer should press on

- YAML 1.1 may parse the `on` key as a boolean. Step 2 must recover it from the raw line and test `on: push`, a list, and a mapping.
- Alias nodes, `<<` merge keys, and node count must be rejected before expansion.
- `pull_request` is classified as untrusted (D-07). That will flag secrets on ordinary PR workflows.

## Review outcomes (plan review, cursor / gpt-5.6-sol-high)

Agreed and folded into `REQUIREMENTS.md` and `docs/design.md`:

- Lockfile keys are `owner/repo@ref`. Subpaths share that pin. `--fix` rewrites only the `@ref` suffix.
- A missing ref is `HEAD` and still one `GET .../commits/HEAD`. No repository-metadata request.
- Opens use `O_NOFOLLOW` on the descriptor that is read. No `Lstat` then `Open`.
- A parent context deadline covers every resolve request and body read.
- Bodies of 1 MiB + 1 byte are rejected, and trailing JSON is rejected.
- The 1000 cap reserves the last slot for `findings-truncated`, appended after sort.
- Step 2 tests parser rejections: merge key, alias, second document, invalid UTF-8, symlink, and the size caps.

Disagreed:

- Do not change D-01 to block on another human approval, and do not leave D-02 as a stop. The user asked for this run to self-approve review fixes and to implement the parser. D-02 stays a logged, reversible assumption that `gopkg.in/yaml.v3` v3.0.1 is added in step 2. No other module is added.
