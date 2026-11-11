package rules

import (
	"sort"
	"strings"

	"gha-hardener/internal/workflow"
)

// untrustedEvents are triggers a user without write access can fire,
// including same-repo pull_request where secrets are still populated.
var untrustedEvents = map[string]struct{}{
	"pull_request":                {},
	"pull_request_target":         {},
	"issue_comment":               {},
	"issues":                      {},
	"pull_request_review":         {},
	"pull_request_review_comment": {},
	"discussion":                  {},
	"discussion_comment":          {},
	"workflow_run":                {},
}

// Secrets reports a secrets context read under an untrusted trigger,
// other than an access that is exactly secrets.GITHUB_TOKEN.
func Secrets(wf *workflow.Workflow) []Finding {
	events := untrustedList(wf)
	if len(events) == 0 {
		return nil
	}
	msg := "secret is passed to untrusted trigger " + strings.Join(events, ", ")
	var out []Finding
	add := func(line, col int) {
		out = append(out, at(wf.Path, line, col, Finding{
			RuleID:   "secrets-untrusted-trigger",
			Severity: Error,
			Message:  msg,
		}))
	}
	for _, env := range wf.Env {
		if secretUnsafe(env.Value) {
			add(env.Line, env.Column)
		}
	}
	for _, job := range wf.Jobs {
		for _, env := range job.Env {
			if secretUnsafe(env.Value) {
				add(env.Line, env.Column)
			}
		}
		for _, step := range job.Steps {
			for _, env := range step.Env {
				if secretUnsafe(env.Value) {
					add(env.Line, env.Column)
				}
			}
			for _, in := range step.With {
				if secretUnsafe(in.Value) {
					add(in.Line, in.Column)
				}
			}
			if secretUnsafe(step.Run) {
				add(step.RunLine, step.RunColumn)
			}
		}
	}
	return out
}

func untrustedList(wf *workflow.Workflow) []string {
	seen := map[string]struct{}{}
	var names []string
	for _, ev := range wf.On {
		if _, ok := untrustedEvents[ev.Name]; !ok {
			continue
		}
		if _, ok := seen[ev.Name]; ok {
			continue
		}
		seen[ev.Name] = struct{}{}
		names = append(names, ev.Name)
	}
	sort.Strings(names)
	return names
}

func secretUnsafe(s string) bool {
	for _, body := range expressions(s) {
		if _, unsafe := analyzeSecrets(body); unsafe {
			return true
		}
	}
	return false
}

// analyzeSecrets reports whether body reads secrets, and whether any
// read is not exactly the GITHUB_TOKEN property.
func analyzeSecrets(body string) (saw, unsafe bool) {
	for i := 0; i < len(body); {
		if body[i] == '\'' || body[i] == '"' {
			i = skipString(body, i)
			continue
		}
		if isIdentStart(body[i]) {
			ident, next := readIdent(body, i)
			if strings.EqualFold(ident, "secrets") && !isProperty(body, i) {
				saw = true
				safe, n := githubTokenProperty(body, next)
				if !safe {
					unsafe = true
				}
				if n < next {
					n = next
				}
				i = n
				continue
			}
			i = next
			continue
		}
		i++
	}
	return saw, unsafe
}

func githubTokenProperty(s string, i int) (bool, int) {
	i = skipSpace(s, i)
	if i >= len(s) {
		return false, i
	}
	if s[i] == '.' {
		i = skipSpace(s, i+1)
		ident, next := readIdent(s, i)
		if ident == "" {
			return false, next
		}
		return strings.EqualFold(ident, "GITHUB_TOKEN"), next
	}
	if s[i] != '[' {
		return false, i
	}
	i = skipSpace(s, i+1)
	lit, next, ok := readQuoted(s, i)
	if !ok {
		return false, next
	}
	next = skipSpace(s, next)
	if next >= len(s) || s[next] != ']' {
		return false, next
	}
	return strings.EqualFold(lit, "GITHUB_TOKEN"), next + 1
}
