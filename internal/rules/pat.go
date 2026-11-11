package rules

import (
	"fmt"
	"regexp"
	"strings"

	"gha-hardener/internal/workflow"
)

var classicPAT = regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`)

var patNames = map[string]struct{}{
	"pat":                          {},
	"gh_pat":                       {},
	"github_pat":                   {},
	"personal_access_token":        {},
	"gh_token":                     {},
	"github_personal_access_token": {},
}

// PAT reports a classic ghp_ literal in env, or a PAT-named env var
// that reads a secret other than GITHUB_TOKEN.
func PAT(wf *workflow.Workflow) []Finding {
	var out []Finding
	check := func(env workflow.Env) {
		if env.Value == "" {
			return
		}
		if classicPAT.MatchString(env.Value) || reservedSecret(env.Name, env.Value) {
			out = append(out, at(wf.Path, env.Line, env.Column, Finding{
				RuleID:   "unscoped-pat",
				Severity: Error,
				Message:  fmt.Sprintf("env %q holds an unscoped personal access token", env.Name),
			}))
		}
	}
	for _, env := range wf.Env {
		check(env)
	}
	for _, job := range wf.Jobs {
		for _, env := range job.Env {
			check(env)
		}
		for _, step := range job.Steps {
			for _, env := range step.Env {
				check(env)
			}
		}
	}
	return out
}

func reservedSecret(name, value string) bool {
	if _, ok := patNames[strings.ToLower(name)]; !ok {
		return false
	}
	saw, unsafe := false, false
	for _, body := range expressions(value) {
		s, u := analyzeSecrets(body)
		if s {
			saw = true
		}
		if u {
			unsafe = true
		}
	}
	return saw && unsafe
}
