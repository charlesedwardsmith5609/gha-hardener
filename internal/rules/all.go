package rules

import (
	"container/heap"
	"fmt"
	"sort"

	"gha-hardener/internal/workflow"
)

// All runs every rule. The calling goroutine owns the result.
// At most 999 rule findings are retained, the ones that sort first.
// A findings-truncated note is appended after that sort when any were dropped.
func All(wfs []*workflow.Workflow) []Finding {
	kept := &findingHeap{}
	omitted := 0
	add := func(list []Finding) {
		for _, f := range list {
			if kept.Len() < 999 {
				heap.Push(kept, f)
				continue
			}
			if before(f, kept.items[0]) {
				heap.Pop(kept)
				heap.Push(kept, f)
			}
			omitted++
		}
	}
	for _, wf := range wfs {
		if wf == nil {
			continue
		}
		add(Unpinned(wf))
		add(Permissions(wf))
		add(Checkout(wf))
		add(Secrets(wf))
		add(PAT(wf))
		add(Injection(wf))
		add(Remote(wf))
	}
	out := append([]Finding(nil), kept.items...)
	sort.SliceStable(out, func(i, j int) bool {
		return before(out[i], out[j])
	})
	if omitted == 0 {
		return out
	}
	return append(out, Finding{
		RuleID:   "findings-truncated",
		Severity: Note,
		File:     ".",
		Line:     1,
		Column:   1,
		Message:  fmt.Sprintf("%d findings omitted", omitted),
	})
}

// findingHeap is a min-heap of the latest finding, so the root is the
// first one to drop when a better finding arrives.
type findingHeap struct {
	items []Finding
}

func (h findingHeap) Len() int { return len(h.items) }
func (h findingHeap) Less(i, j int) bool {
	return before(h.items[j], h.items[i])
}
func (h findingHeap) Swap(i, j int) { h.items[i], h.items[j] = h.items[j], h.items[i] }
func (h *findingHeap) Push(x any)   { h.items = append(h.items, x.(Finding)) }
func (h *findingHeap) Pop() any {
	n := len(h.items)
	item := h.items[n-1]
	h.items = h.items[:n-1]
	return item
}

func before(a, b Finding) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.Column != b.Column {
		return a.Column < b.Column
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	return a.Message < b.Message
}
