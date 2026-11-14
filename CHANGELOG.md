# Changelog

Format follows Keep a Changelog. Dates are UTC.

## [Unreleased] - 2026-11-14

### Changed

- `go.mod` requires Go 1.26.11 (GO-2026-6859 in `net/http`).
- Refreshed the agent-pairing-kit install to kit commit 2ccbb85: fail-closed `cross-review.sh`/`.ps1` (tracked changes only, `--include` for untracked files), `misbehavior-check.sh` and `assertion-check.sh` stages in `check.sh`, test-first and tool-call rules in `CLAUDE.md`/`AGENTS.md`, permission denies in `.claude/settings.json`.

### Documentation

- README lists every flag, the `--api-base` limits, the CI toolchain state, and the review scripts.
- `docs/design.md` and `REQUIREMENTS.md` describe the ref rules the code enforces (no whitespace, backslash, `?` or `#`).
- `REQUIREMENTS.md` no longer says to ask before adding `gopkg.in/yaml.v3`.

## 2026-11-11

- Initial scanner: eight rules, text/JSON/SARIF output, `resolve`, `--fix`, pinned CI workflow, `remote-script` rule.
