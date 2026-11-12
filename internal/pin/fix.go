package pin

import (
	"errors"
	"sort"
	"strings"

	"gha-hardener/internal/workflow"
)

type span struct {
	start, end int
	text       string
}

// Rewrite returns data with pinned uses values substituted.
// Scalars that are not plain or single-quoted are left unchanged.
func Rewrite(data []byte, wf *workflow.Workflow, lock *Lock) ([]byte, error) {
	var spans []span
	add := func(uses string, line, col int) {
		if uses == "" || lock == nil {
			return
		}
		_, _, ref, key, ok := splitUses(uses)
		if !ok {
			return
		}
		p, found := lock.Pins[key]
		if !found || !shaPattern.MatchString(p.SHA) {
			return
		}
		start, end, kind, ok := valueSpan(data, line, col, uses)
		if !ok {
			return
		}
		next := pinned(uses, ref, p.SHA)
		if next == uses {
			return
		}
		repl := next
		if kind == '\'' {
			repl = "'" + next + "'"
		}
		spans = append(spans, span{start: start, end: end, text: repl})
	}
	for _, job := range wf.Jobs {
		add(job.Uses, job.UsesLine, job.UsesColumn)
		for _, step := range job.Steps {
			add(step.Uses, step.UsesLine, step.UsesColumn)
		}
	}
	if len(spans) == 0 {
		return data, nil
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b strings.Builder
	b.Grow(len(data))
	pos := 0
	for _, sp := range spans {
		if sp.start < pos || sp.end > len(data) || sp.start > sp.end {
			return nil, errors.New("overlapping uses span")
		}
		b.Write(data[pos:sp.start])
		b.WriteString(sp.text)
		pos = sp.end
	}
	b.Write(data[pos:])
	return []byte(b.String()), nil
}

func pinned(uses, ref, sha string) string {
	if ref == "HEAD" && !strings.Contains(uses, "@") {
		return uses + "@" + sha
	}
	suffix := "@" + ref
	if strings.HasSuffix(uses, suffix) {
		return strings.TrimSuffix(uses, suffix) + "@" + sha
	}
	return uses
}

// valueSpan finds the raw scalar. kind is 0 for plain and '\” for single quotes.
func valueSpan(data []byte, line, col int, value string) (start, end int, kind byte, ok bool) {
	off := lineOffset(data, line)
	if off < 0 || col < 1 {
		return 0, 0, 0, false
	}
	idx := off + col - 1
	if idx < 0 || idx > len(data) {
		return 0, 0, 0, false
	}
	if hasPrefix(data, idx, value) && boundary(data, idx+len(value)) {
		return idx, idx + len(value), 0, true
	}
	if strings.Contains(value, "'") {
		return 0, 0, 0, false
	}
	quoted := "'" + value + "'"
	if hasPrefix(data, idx, quoted) {
		return idx, idx + len(quoted), '\'', true
	}
	if idx > 0 && data[idx-1] == '\'' && hasPrefix(data, idx-1, quoted) {
		return idx - 1, idx - 1 + len(quoted), '\'', true
	}
	return 0, 0, 0, false
}

func hasPrefix(data []byte, idx int, s string) bool {
	if idx < 0 || idx+len(s) > len(data) {
		return false
	}
	return string(data[idx:idx+len(s)]) == s
}

func boundary(data []byte, idx int) bool {
	if idx >= len(data) {
		return true
	}
	switch data[idx] {
	case ' ', '\t', '\n', '\r', '#', ',', '}', ']':
		return true
	default:
		return false
	}
}

func lineOffset(data []byte, line int) int {
	if line < 1 {
		return -1
	}
	if line == 1 {
		return 0
	}
	cur := 1
	for i, c := range data {
		if c == '\n' {
			cur++
			if cur == line {
				return i + 1
			}
		}
	}
	return -1
}
