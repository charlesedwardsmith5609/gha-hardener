package rules

import (
	"strings"

	"gha-hardener/internal/workflow"
)

// Checkout reports a pull_request_target workflow that checks out
// untrusted pull request head code.
func Checkout(wf *workflow.Workflow) []Finding {
	if !hasEvent(wf, "pull_request_target") {
		return nil
	}
	var out []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if checkoutHead(step) {
				line, col := step.UsesLine, step.UsesColumn
				if line < 1 {
					line, col = step.RunLine, step.RunColumn
				}
				out = append(out, at(wf.Path, line, col, Finding{
					RuleID:   "pull-request-target-checkout",
					Severity: Error,
					Message:  "pull_request_target workflow checks out pull request head ref",
				}))
			}
		}
	}
	return out
}

func hasEvent(wf *workflow.Workflow, name string) bool {
	for _, ev := range wf.On {
		if ev.Name == name {
			return true
		}
	}
	return false
}

func checkoutHead(step workflow.Step) bool {
	if isActionsCheckout(step.Uses) {
		for _, in := range step.With {
			if !strings.EqualFold(in.Name, "ref") && !strings.EqualFold(in.Name, "repository") {
				continue
			}
			if unsafeCheckoutValue(in.Value) {
				return true
			}
		}
	}
	return unsafeRunCheckout(step.Run)
}

func isActionsCheckout(uses string) bool {
	repo := uses
	if i := strings.LastIndex(uses, "@"); i >= 0 {
		repo = uses[:i]
	}
	return strings.EqualFold(repo, "actions/checkout")
}

func unsafeCheckoutValue(v string) bool {
	low := strings.ToLower(v)
	if strings.Contains(low, "github.event.pull_request.head") {
		return true
	}
	if strings.Contains(low, "github.event.pull_request.merge_commit_sha") {
		return true
	}
	return strings.Contains(v, "refs/pull/")
}

func unsafeRunCheckout(run string) bool {
	if strings.Contains(strings.ToLower(run), "github.event.pull_request.head") {
		return true
	}
	return strings.Contains(run, "refs/pull/")
}

func at(file string, line, col int, f Finding) Finding {
	if line < 1 {
		line = 1
	}
	if col < 1 {
		col = 1
	}
	f.File = file
	f.Line = line
	f.Column = col
	return f
}
