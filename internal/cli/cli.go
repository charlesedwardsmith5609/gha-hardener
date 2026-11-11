// Package cli is the gha-hardener command line.
// Run uses the calling goroutine only. It does not open network connections.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"gha-hardener/internal/report"
	"gha-hardener/internal/rules"
	"gha-hardener/internal/workflow"
)

// Run executes one invocation. It returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "resolve" {
		fmt.Fprintln(stderr, "resolve is not available")
		return 2
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if args[0] != "scan" {
			fmt.Fprintf(stderr, "unknown command %q\n", args[0])
			return 2
		}
		args = args[1:]
	}
	fs := flag.NewFlagSet("gha-hardener", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".github/workflows", "workflow directory")
	format := fs.String("format", "text", "text, json, or sarif")
	failOn := fs.String("fail-on", "warning", "none, note, warning, or error")
	fix := fs.Bool("fix", false, "pin tags from the lockfile")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *fix {
		fmt.Fprintln(stderr, "--fix is not available")
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	threshold, ok := thresholdRank(*failOn)
	if !ok {
		fmt.Fprintf(stderr, "unknown --fail-on %q\n", *failOn)
		return 2
	}
	switch *format {
	case "text", "json", "sarif":
	default:
		fmt.Fprintf(stderr, "unknown --format %q\n", *format)
		return 2
	}

	wfs, ferrs, err := workflow.LoadDir(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	findings := rules.All(wfs)
	writeErr := report.Write(stdout, *format, findings)
	for _, fe := range ferrs {
		fmt.Fprintf(stderr, "%v\n", fe)
	}
	if writeErr != nil {
		fmt.Fprintf(stderr, "write report: %v\n", writeErr)
		return 2
	}
	if len(ferrs) > 0 {
		return 2
	}
	if threshold >= 0 && anyAtLeast(findings, threshold) {
		return 1
	}
	return 0
}

func thresholdRank(name string) (int, bool) {
	switch name {
	case "none":
		return -1, true
	case "note":
		return 0, true
	case "warning":
		return 1, true
	case "error":
		return 2, true
	default:
		return 0, false
	}
}

func anyAtLeast(findings []rules.Finding, threshold int) bool {
	for _, f := range findings {
		if rank(f.Severity) >= threshold {
			return true
		}
	}
	return false
}

func rank(severity string) int {
	switch severity {
	case rules.Note:
		return 0
	case rules.Warning:
		return 1
	case rules.Error:
		return 2
	default:
		return 2
	}
}
