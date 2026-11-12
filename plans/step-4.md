# Step 4: resolve and --fix

Implements the only networked command and the local pin rewrite. No CI and no README.

## Files

- `internal/pin/pin.go`: lockfile types, key parsing, read, atomic write.
- `internal/pin/resolve.go`: allowlisted GET client.
- `internal/pin/fix.go`: byte-span rewrite.
- `internal/pin/pin_test.go`: httptest on `127.0.0.1:0`, fix fixtures.
- `internal/cli/cli.go`: `resolve` and `--fix`. Remove the "not available" stubs.
- `internal/workflow/parse.go`: `Workflow.AbsPath` set by `LoadDir` so `--fix` writes the file it opened.

## Types

```go
type Pin struct {
    SHA, Repository, Ref string
}
type Lock struct {
    Version int
    Pins    map[string]Pin // key is repository + "@" + ref
}
```

`AbsPath` is the cleaned `dir/name` `LoadDir` opened. `Parse` leaves it empty. The calling goroutine owns the lock struct, the file bytes, the `http.Client`, and its `Transport`.

## Key parsing

Skip `./` and `docker://`. `repository` is the first two segments. `ref` is the text after the last `@`, or `HEAD` when there is no `@`. `owner` and `repo` match `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$` and are not `.` or `..`. `ref` matches `^[A-Za-z0-9_./+-]{1,256}$` with no empty segment and no `..`. The subpath is not part of the key. More than 128 unique keys is an error and no request is sent.

## resolve

`Resolve(dir, apiBase string, timeout time.Duration) (*Lock, error)`.

- `timeout` must be from 1s to 30s.
- `apiBase` defaults to `https://api.github.com`. Allowed: `https://api.github.com` and `http://127.0.0.1` with any port. No userinfo, query, or fragment. Any other host, including `localhost`, is refused.
- One parent context of `min(2 minutes, timeout × ref count)` wraps every dial, header wait, and body read. Each request also has its own `timeout` deadline.
- One `GET /repos/{owner}/{repo}/commits/{ref}` per key, in sorted key order, on the calling goroutine. The path is built from escaped segments and rejected unless it is exactly those four segments (`repos`, owner, repo, `commits` + escaped ref as one segment).
- No `Authorization` header. Keep-alives disabled. `CloseIdleConnections` runs before return. `CheckRedirect` re-checks the allowlist and stops after two redirects (`len(via) >= 3`).
- Read at most 1 MiB + 1 byte. The extra byte rejects the body. `json.Decoder` must return `io.EOF` on a second value. `sha` must match `^[0-9a-f]{40}$`. Non-200 fails. Any failure returns an error and the caller writes no lockfile.
- The `Transport.DialContext` sets the connection deadline from the request context.

## Lockfile

`{"version":1,"pins":{...}}`. `DisallowUnknownFields` on the top level and on each pin. `repository` and `ref` must reproduce the key. SHA is 40 lowercase hex. Read cap 1 MiB. Write is a temp file in the destination directory (`O_EXCL` via `CreateTemp`) then `rename`. Keys sort because `encoding/json` sorts map keys.

## --fix

For each parsed `uses` with a lockfile key, rewrite only when the raw bytes at the node's line and column are exactly the plain value, or a single-quoted value whose content has no apostrophe. Any other style is left unchanged. The span's trailing `@ref` (or the whole value, when the ref is `HEAD` and the source has no `@`) becomes `@` plus the SHA. The subpath stays. Replacements are applied from the end of the file so earlier columns stay valid. Missing keys are left in place. The new bytes go to a temp file and `rename` replaces the destination. Then the directory is scanned again and that scan is what is reported. `--fix` does not open a network connection.

## CLI

- `resolve --dir --lockfile gha-pins.json --timeout 10s --api-base URL`. Success prints `pinned N refs` and exits 0. Failure exits 2 and leaves any existing lockfile untouched.
- `scan --fix --lockfile`. A missing or invalid lockfile exits 2 before any rewrite.

## Tests

- Success: listener `net.Listen("tcp", "127.0.0.1:0")`, handler checks `GET` and the absence of `Authorization`, returns a 40-hex `sha`. Lockfile key is `actions/checkout@v4`.
- Slow handler blocks on `r.Context().Done()` and returns. `Resolve` runs on a worker. The test goroutine selects on that result and a 2s timer. The request timeout is the 1s minimum. No `time.Sleep`.
- Redirect to `http://192.0.2.1/` is an error and returns within the 2s select.
- Body of 1 MiB + 1 and a second JSON value are errors, and no lockfile is written.
- 129 distinct refs do not open a connection (handler fails the test if called).
- `--fix` rewrites a plain `uses` and a subpath `github/codeql-action/init@v3` to the same SHA, leaves a double-quoted `uses` unchanged, and does not dial.
- CLI `--fix` on a temp dir with a lockfile exits 0 when the only finding was the unpinned tag.

## Ownership

No mutex and no long-lived goroutine. The timeout test's worker does not touch scanner state. The `Transport` is local to `Resolve` and closed before return.

## Review outcomes (plan review, cursor / gpt-5.6-sol-high)

Agreed with all 7:

- `CheckRedirect` follows nothing. An off-allowlist target is a distinct error.
- `--fix` keeps the directory descriptor from `openat`/`O_NOFOLLOW` and does the read, temp create, and `renameat` on it.
- The commits URL has five segments. `feature/foo` is one escaped segment, `feature%2Ffoo`.
- Lock JSON uses lowercase tags. Keys are checked case-sensitively. A second JSON value is rejected.
- A ref may contain `!` and `/`. It still cannot contain an empty, `.`, or `..` segment, controls, or more than 256 characters. Those limits stay because `..` was an earlier agreed path check.
- Every response body is closed and its request context is canceled on every return.
- Tests cover two `uses` values on one line, a single-quoted scalar, a value with no `@`, a double-quoted scalar left in place, and `feature/foo`.

## Deferred

CI workflow, README, platform-templates sample.
