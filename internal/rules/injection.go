package rules

import (
	"strings"

	"gha-hardener/internal/workflow"
)

// Injection reports run scripts that read github.event, including bracket form.
// Quoted strings are not reads. github.event_name does not match.
func Injection(wf *workflow.Workflow) []Finding {
	var out []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" || !readsGitHubEvent(step.Run) {
				continue
			}
			line, col := step.RunLine, step.RunColumn
			if line < 1 {
				line = 1
			}
			if col < 1 {
				col = 1
			}
			out = append(out, Finding{
				RuleID:   "script-injection",
				Severity: Error,
				File:     wf.Path,
				Line:     line,
				Column:   col,
				Message:  "run script reads github.event (script injection)",
			})
		}
	}
	return out
}

func readsGitHubEvent(run string) bool {
	for i := 0; i < len(run); {
		if strings.HasPrefix(run[i:], "${{") {
			body, next, ok := scanExpr(run, i+3)
			if !ok {
				return false
			}
			if exprReadsEvent(body) {
				return true
			}
			i = next
			continue
		}
		i++
	}
	return false
}

func scanExpr(s string, i int) (string, int, bool) {
	start := i
	for i < len(s) {
		if s[i] == '\'' || s[i] == '"' {
			i = skipString(s, i)
			continue
		}
		if strings.HasPrefix(s[i:], "}}") {
			return s[start:i], i + 2, true
		}
		i++
	}
	return "", 0, false
}

func exprReadsEvent(s string) bool {
	for i := 0; i < len(s); {
		if s[i] == '\'' || s[i] == '"' {
			i = skipString(s, i)
			continue
		}
		if isIdentStart(s[i]) {
			ident, next := readIdent(s, i)
			if strings.EqualFold(ident, "github") && followedByEvent(s, next) {
				return true
			}
			i = next
			continue
		}
		i++
	}
	return false
}

func followedByEvent(s string, i int) bool {
	i = skipSpace(s, i)
	if i >= len(s) {
		return false
	}
	if s[i] == '.' {
		i = skipSpace(s, i+1)
		ident, _ := readIdent(s, i)
		return strings.EqualFold(ident, "event")
	}
	if s[i] != '[' {
		return false
	}
	i = skipSpace(s, i+1)
	lit, next, ok := readQuoted(s, i)
	if !ok || !strings.EqualFold(lit, "event") {
		return false
	}
	next = skipSpace(s, next)
	return next < len(s) && s[next] == ']'
}

func readIdent(s string, i int) (string, int) {
	if i >= len(s) || !isIdentStart(s[i]) {
		return "", i
	}
	j := i + 1
	for j < len(s) && isIdentCont(s[j]) {
		j++
	}
	return s[i:j], j
}

func readQuoted(s string, i int) (string, int, bool) {
	if i >= len(s) || (s[i] != '\'' && s[i] != '"') {
		return "", i, false
	}
	q := s[i]
	i++
	var b strings.Builder
	for i < len(s) {
		if q == '\'' && strings.HasPrefix(s[i:], "''") {
			b.WriteByte('\'')
			i += 2
			continue
		}
		if q == '"' && s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i += 2
			continue
		}
		if s[i] == q {
			return b.String(), i + 1, true
		}
		b.WriteByte(s[i])
		i++
	}
	return "", len(s), false
}

func skipString(s string, i int) int {
	_, next, ok := readQuoted(s, i)
	if !ok {
		return len(s)
	}
	return next
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isIdentCont(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9') || b == '-'
}
