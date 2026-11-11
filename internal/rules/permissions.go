package rules

import (
	"fmt"

	"gha-hardener/internal/workflow"
)

// Permissions reports a job whose effective permissions are unset or write-all.
// Effective permissions are the job block when present, otherwise the workflow block.
func Permissions(wf *workflow.Workflow) []Finding {
	var out []Finding
	if len(wf.Jobs) == 0 {
		return append(out, permFinding(wf.Path, "", 1, 1, wf.Permissions)...)
	}
	for _, job := range wf.Jobs {
		eff := job.Permissions
		if eff == nil {
			eff = wf.Permissions
		}
		line, col := job.Line, job.Column
		if eff != nil && eff.WriteAll {
			line, col = eff.Line, eff.Column
		}
		out = append(out, permFinding(wf.Path, job.ID, line, col, eff)...)
	}
	return out
}

func permFinding(file, jobID string, line, col int, eff *workflow.Permissions) []Finding {
	if line < 1 {
		line = 1
	}
	if col < 1 {
		col = 1
	}
	if eff == nil {
		msg := "workflow has no permissions block"
		if jobID != "" {
			msg = fmt.Sprintf("job %q has no permissions block", jobID)
		}
		return []Finding{{
			RuleID:   "permissions-missing",
			Severity: Warning,
			File:     file,
			Line:     line,
			Column:   col,
			Message:  msg,
		}}
	}
	if eff.WriteAll {
		msg := "workflow grants permissions: write-all"
		if jobID != "" {
			msg = fmt.Sprintf("job %q grants permissions: write-all", jobID)
		}
		return []Finding{{
			RuleID:   "permissions-write-all",
			Severity: Error,
			File:     file,
			Line:     line,
			Column:   col,
			Message:  msg,
		}}
	}
	return nil
}
