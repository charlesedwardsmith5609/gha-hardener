// Package report writes findings as text, JSON, or SARIF.
// Writers do not share state. The caller owns the Writer.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"gha-hardener/internal/rules"
)

// Version is the tool version written into SARIF.
const Version = "0.1.0"

type ruleMeta struct {
	ID    string
	Short string
	Level string
}

var meta = []ruleMeta{
	{"findings-truncated", "The finding list was capped", "note"},
	{"permissions-missing", "Job has no permissions block", "warning"},
	{"permissions-write-all", "Job grants write-all", "error"},
	{"pull-request-target-checkout", "pull_request_target checks out pull request head", "error"},
	{"script-injection", "run script reads github.event", "error"},
	{"secrets-untrusted-trigger", "Secret passed to an untrusted trigger", "error"},
	{"unpinned-action", "Action is not pinned to a commit SHA", "warning"},
	{"unscoped-pat", "Env holds an unscoped personal access token", "error"},
}

// Write encodes findings. format is text, json, or sarif.
func Write(w io.Writer, format string, findings []rules.Finding) error {
	switch format {
	case "text":
		return writeText(w, findings)
	case "json":
		return writeJSON(w, findings)
	case "sarif":
		return writeSARIF(w, findings)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}

func writeText(w io.Writer, findings []rules.Finding) error {
	for _, f := range findings {
		if _, err := fmt.Fprintf(w, "%s:%d:%d: %s: %s: %s\n", f.File, f.Line, f.Column, f.Severity, f.RuleID, f.Message); err != nil {
			return err
		}
	}
	return nil
}

type jsonFinding struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Message  string `json:"message"`
}

func writeJSON(w io.Writer, findings []rules.Finding) error {
	doc := struct {
		Findings []jsonFinding `json:"findings"`
	}{Findings: make([]jsonFinding, 0, len(findings))}
	for _, f := range findings {
		doc.Findings = append(doc.Findings, jsonFinding{
			RuleID: f.RuleID, Severity: f.Severity, File: f.File,
			Line: f.Line, Column: f.Column, Message: f.Message,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	return nil
}

func sarifURI(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func writeSARIF(w io.Writer, findings []rules.Finding) error {
	rulesOut := make([]sarifRule, len(meta))
	order := append([]ruleMeta(nil), meta...)
	sort.Slice(order, func(i, j int) bool { return order[i].ID < order[j].ID })
	for i, m := range order {
		rulesOut[i] = sarifRule{
			ID:                   m.ID,
			ShortDescription:     sarifText{Text: m.Short},
			DefaultConfiguration: sarifConfig{Level: m.Level},
		}
	}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   f.Severity,
			Message: sarifText{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: sarifURI(f.File)},
					Region:           sarifRegion{StartLine: f.Line, StartColumn: f.Column},
				},
			}},
		})
	}
	doc := sarifLog{
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    "gha-hardener",
				Version: Version,
				Rules:   rulesOut,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string      `json:"id"`
	ShortDescription     sarifText   `json:"shortDescription"`
	DefaultConfiguration sarifConfig `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}
