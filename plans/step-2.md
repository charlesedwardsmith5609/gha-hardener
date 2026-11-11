# Step 2: parser and first rules

Implements parsing and four rule ids: `unpinned-action`, `permissions-missing`, `permissions-write-all`, `script-injection`. No CLI, no SARIF, no `resolve`, no `--fix`. Those stay in later steps.

Dependency: `gopkg.in/yaml.v3` v3.0.1 only (D-02). No other `go.mod` requirement.

## Files

- `go.mod`, `go.sum`: add `gopkg.in/yaml.v3` v3.0.1.
- `internal/workflow/parse.go`: `Parse`, `LoadDir`, caps, `O_NOFOLLOW` read.
- `internal/workflow/parse_test.go`: `on` shapes, rejection tests.
- `internal/rules/finding.go`: `Finding`, severities.
- `internal/rules/unpinned.go`, `permissions.go`, `injection.go`.
- `internal/rules/rules_test.go`: table tests from fixtures.
- `testdata/fixtures/unpinned-action/{good,bad}.yml`
- `testdata/fixtures/permissions-missing/{good,bad}.yml`
- `testdata/fixtures/permissions-write-all/{good,bad}.yml`
- `testdata/fixtures/script-injection/{good,bad}.yml`

## Types

```go
type Workflow struct {
    Path        string
    On          []Event
    Permissions *Permissions // nil when the key is absent
    Jobs        []Job
}
type Event struct { Name string; Line, Column int }
type Permissions struct { WriteAll bool; Line, Column int }
type Job struct {
    ID          string
    Line, Column int
    Permissions *Permissions // nil when the job omits the key
    Steps       []Step
}
type Step struct {
    Uses, Run string
    UsesLine, UsesColumn int
    RunLine, RunColumn int
}
type Finding struct {
    RuleID, Severity, File, Message string
    Line, Column int
}
```

`Severity` is `note`, `warning`, or `error`. Step 2 does not sort across rules or apply the 1000 cap; `rules.All` lands in step 3. Each rule function returns findings for one workflow.

## Parser

- `Parse(displayPath string, data []byte) (*Workflow, error)`. `displayPath` must be relative, slash-separated, with no `..` segment.
- Reject invalid UTF-8, a second document, more than 100000 nodes, any alias node, and any mapping key `<<`.
- Count every node, including aliases, before interpreting. Alias rejection does not follow the alias.
- Scalars we require: trigger names, the `permissions` scalar when it is not a mapping, `uses`, `run`. Other keys are ignored. A non-scalar `uses` or `run` is a parse error.
- `on` as a scalar, a sequence, or a mapping. When the key node is tagged `!!bool`, recover the key from the raw line at `Line`/`Column`. Accept it only when that slice is `on`. Covered by tests for `on: push`, `on: [push, pull_request]`, and a mapping.
- Effective permissions are not computed here. The struct records workflow-level and job-level blocks separately, including a present empty mapping (`WriteAll == false`).

## LoadDir

- Open `dir` with `syscall.O_RDONLY|syscall.O_NOFOLLOW`, `fstat` a directory, `ReadDir` on that descriptor.
- Entry names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml$`.
- Open `filepath.Join(dir, name)` with `O_RDONLY|O_NOFOLLOW`, `fstat` a regular file, read at most 1 MiB + 1 byte from that descriptor. The extra byte is an error.
- Stop at 200 files or 8 MiB total, before reading a file that would exceed the total.
- No recursion. The calling goroutine owns the descriptors and closes them on every return. No mutex and no extra goroutine.

## Rules

- `unpinned-action` (warning): skip empty, `./`, and `docker://`. A ref matching `(?i)^[0-9a-f]{40}$` is pinned. Anything else, including a missing ref, is a finding. Message includes the `uses` value.
- Permissions: for each job, use the job block when present, otherwise the workflow block. Nil means `permissions-missing` (warning) at the job key, or at line 1 when the workflow has no jobs and no block. `WriteAll` means `permissions-write-all` (error). A job that sets `contents: read` under a workflow `write-all` is clean. A second job that omits `permissions` is `permissions-write-all`.
- `script-injection` (error): scan each `run` for `${{` … `}}` (no nesting; a missing close is not a finding). Inside, an identifier is `[A-Za-z_][A-Za-z0-9_-]*`. A finding requires identifier `github`, optional whitespace, then either `.` + optional whitespace + `event` not continued by an identifier character, or `[` + optional whitespace + a single- or double-quoted `event` + `]`. `github.event_name` and `github['event_name']` do not match. Expressions only in `env` are not visible to this rule because `Step` does not store them yet (step 3 adds `env` and `with`).

## Ownership

No shared state. `Parse` and the rule functions allocate their results and do not retain the input buffer. `LoadDir` does not start goroutines.

## Tests

Table per rule, good and bad fixture files, plus these extra cases in the same tables:

- unpinned: 40-hex upper case is good; `./.github/actions/build` and `docker://alpine:3.20` are good; `actions/checkout@v4` and `actions/checkout` are bad.
- permissions: workflow `write-all` with one job overriding to `contents: read` (good for that job) and one job inheriting (bad).
- script injection: `github['event']['issue']['title']` and `github["event"]` are bad; `github.event_name` and an `env` indirection (`run` uses `$TITLE` only) are good.

Parser tests: three `on` shapes; merge key `<<: {x: 1}` with no alias; alias node; second document; invalid UTF-8; symlink inside the directory; file of 1 MiB + 1; directory whose files exceed 8 MiB; 201 files; a mapping that exceeds 100000 nodes (about 50000 short keys, under 1 MiB). Symlink and cap tests use a temp directory. No `time.Sleep`.

## Review outcomes (plan review, cursor / gpt-5.6-sol-high)

Agreed with all 7 and this plan is the version to implement:

- `Job` stores `Uses`, `UsesLine`, and `UsesColumn`. `unpinned-action` checks job-level `uses` and step `uses`. Fixtures cover a reusable workflow pinned to a SHA and one pinned to `@v1`.
- Directory open uses `O_RDONLY|O_NOFOLLOW|O_DIRECTORY`. Each entry is opened with `openat` on that directory descriptor (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`). `fstat` must show a regular file before any read. A FIFO test runs `LoadDir` on a worker and the test goroutine selects with a 2s timer.
- `LoadDir` returns `([]*Workflow, []FileError, error)`. `error` is only the directory itself (missing, not a directory, symlink). Per-file parse failures, symlinks, FIFOs, and oversize files are `FileError`s and scanning continues. The 201st matching name produces one too-many-files error and is not opened. Byte caps count bytes actually read: each read is `min(1 MiB, remaining total) + 1` bytes, and the extra byte rejects that file.
- Expression scan skips quoted strings. A quote is interpreted only as a bracket property name after `[`. `${{ contains('github.event.issue.title', 'x') }}` is not a finding. The `${{` closer is also string-aware.
- `WriteAll` is `strings.EqualFold(scalar, "write-all")`. Tests cover `WRITE-ALL`.

## Deferred

CLI, JSON, SARIF, `--fail-on`, the other three rules, `env`/`with` storage, `resolve`, `--fix`.
