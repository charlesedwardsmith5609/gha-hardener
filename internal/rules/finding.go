// Package rules reports supply-chain findings for a parsed workflow.
// Rule functions do not read files or share state.
package rules

const (
	Note    = "note"
	Warning = "warning"
	Error   = "error"
)

// Finding is one rule result. Line and Column are 1-based.
type Finding struct {
	RuleID   string
	Severity string
	File     string
	Line     int
	Column   int
	Message  string
}
