package rules

import (
	"fmt"
	"regexp"
	"strings"

	"gha-hardener/internal/workflow"
)

var shaRef = regexp.MustCompile(`(?i)^[0-9a-f]{40}$`)

// Unpinned reports actions and reusable workflows whose ref is not a
// 40-hex-character commit SHA. Local ./ actions and docker:// images
// are skipped.
func Unpinned(wf *workflow.Workflow) []Finding {
	var out []Finding
	for _, job := range wf.Jobs {
		if f, ok := unpinnedUses(wf.Path, job.Uses, job.UsesLine, job.UsesColumn); ok {
			out = append(out, f)
		}
		for _, step := range job.Steps {
			if f, ok := unpinnedUses(wf.Path, step.Uses, step.UsesLine, step.UsesColumn); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

func unpinnedUses(file, uses string, line, col int) (Finding, bool) {
	if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return Finding{}, false
	}
	ref := ""
	if i := strings.LastIndex(uses, "@"); i >= 0 {
		ref = uses[i+1:]
	}
	if shaRef.MatchString(ref) {
		return Finding{}, false
	}
	if line < 1 {
		line = 1
	}
	if col < 1 {
		col = 1
	}
	return Finding{
		RuleID:   "unpinned-action",
		Severity: Warning,
		File:     file,
		Line:     line,
		Column:   col,
		Message:  fmt.Sprintf("action %q is not pinned to a 40-character commit SHA", uses),
	}, true
}
