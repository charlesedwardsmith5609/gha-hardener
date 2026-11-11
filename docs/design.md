# Design

`gha-hardener` is a single-process CLI. Scan and fix are pure functions over file bytes. `resolve` performs HTTP GETs one at a time on the calling goroutine. There is no shared mutable state, no mutex, and no long-lived goroutine.

## Layout

- `cmd/gha-hardener`: `main` calls `cli.Run` and exits with its code.
- `internal/workflow`: load a directory, parse one file, enforce caps.
- `internal/rules`: one file per rule, plus `All` which sorts and caps findings.
- `internal/report`: text, JSON, SARIF.
- `internal/pin`: lockfile, `resolve`, `--fix` line rewrite.
- `testdata/fixtures`: good/bad workflows and the golden SARIF input.
- `testdata/golden/all.sarif`: expected SARIF.

## Parser

`gopkg.in/yaml.v3` node decoder (line and column come from the node). See `DECISIONS.md` for the dependency assumption.

`Parse` rejects a buffer larger than 1 MiB before decoding. The walker rejects alias nodes, a mapping key `<<`, depth over 32, and more than 100000 nodes. yaml.v3 builds the node tree inside `Decode`, so the byte cap is what bounds that allocation; the node and depth checks run on the tree before it is interpreted. Keys and the values we interpret (`on`, `permissions`, `env`, `jobs`, `steps`, `uses`, `run`, `with`, `if`) must be scalars where GitHub requires scalars. Other keys are ignored. A second document is an error.

The key `on` is special-cased because YAML 1.1 treats `on` as a boolean. The parser recovers it from the raw line when the node tag is `!!bool`.

Reported paths use forward slashes, are relative, and are rejected when they contain `..` or are absolute. `LoadDir` walks every component of the directory from `/` (absolute) or `.` (relative) with `openat`, `O_NOFOLLOW`, and `O_DIRECTORY`. A symlink component or a `..` component fails the open. Directory entries are read in batches. Only names that match the workflow pattern are kept, and at most 201 of them. Each file is opened with `openat` on that directory descriptor (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`). `fstat` must show a regular file before the read. A FIFO cannot block the open. Bytes consumed by a rejected oversized read count toward the 8 MiB total, and the walk stops when the total is exhausted. `LoadDir` returns workflows parsed so far plus one error per rejected file; only a failure to open the directory itself is a hard error.

## Rules

Rules are functions from `*workflow.Workflow` to findings. They do not read the filesystem and do not call the network. `All` concatenates and sorts. When more than 999 rule findings exist, it keeps the first 999 and appends one `findings-truncated` note after the sort, so the total stays at 1000 and the note stays last.

Effective permissions and the untrusted-trigger set are defined in `REQUIREMENTS.md`.

## Reports

SARIF lists every rule on the driver, including rules with no results, so consumers can see the default level. No timestamps and no absolute paths. The golden file is produced from `testdata/fixtures/golden/workflow.yml` with the reported path `.github/workflows/ci.yml`.

## resolve

```text
Base URL (allowlisted)
  -> one GET /repos/{owner}/{repo}/commits/{ref}
  -> JSON field sha, then EOF
  -> lockfile, or nothing if any ref fails
```

Local `./` actions and `docker://` images are skipped before any pin is derived. At most 128 unique pairs are accepted; the command stops before the first request otherwise.

`owner` and `repo` each match `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$` and are not `.` or `..`. `ref` matches `^[A-Za-z0-9_./+-]{1,256}$`, must not contain `..` or an empty segment, and is path-escaped. The URL path is three escaped segments and is rejected unless it equals `/repos/{owner}/{repo}/commits/{ref}`. A `uses` value with no `@` uses ref `HEAD` (still one commits request). The lockfile key ignores any subpath: `github/codeql-action/init@v3` and `github/codeql-action/analyze@v3` share `github/codeql-action@v3`.

One parent `context.WithTimeout` of `min(2 minutes, timeout × ref count)` is created before the first request. Every dial, header wait, and body read uses that context (each request also has its own `--timeout` deadline). The calling goroutine owns one `http.Transport` with keep-alives disabled and calls `CloseIdleConnections` on the way out. `CheckRedirect` re-checks the allowlist and allows at most two redirects. The body is read up to 1 MiB + 1 byte; the extra byte rejects the response. `json.Decoder` must then return `io.EOF` on a second decode. The body is always closed.

Tests replace the base URL with `http://127.0.0.1:<port>` from `net.Listen("tcp", "127.0.0.1:0")`. Production default is `https://api.github.com`.

## --fix

For each parsed `uses` value that is not local or Docker, derive `repository@ref` (first two segments, ref `HEAD` when there is no `@`). When that key is in the lockfile, rewrite only if the raw file bytes at the node's line and column are exactly the plain scalar or a single-quoted scalar with no escaped quote. That span is replaced in place (`@ref` becomes `@sha`; a missing `@` gains `@sha`). Any other scalar style is skipped. The subpath is unchanged. The new bytes go to a temp file in the same directory (created with `O_EXCL`) and `rename` replaces the destination, including when the destination is a symlink. Rename does not follow it.

## Ownership

The calling goroutine owns the file bytes, the lockfile struct, the `http.Client`, and its `Transport`. Keep-alives are off, and `CloseIdleConnections` runs before `resolve` returns. `resolve` does not start its own goroutines. The timeout test runs `resolve` on one worker goroutine; the test goroutine selects between that result and a 2s timer. The slow handler returns when the request context is canceled, so the worker can finish. The worker does not share scanner state.
