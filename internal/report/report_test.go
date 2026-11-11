package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gha-hardener/internal/rules"
	"gha-hardener/internal/workflow"
)

func TestGoldenSARIF(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "golden", "workflow.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf, err := workflow.Parse(".github/workflows/ci.yml", src)
	if err != nil {
		t.Fatal(err)
	}
	findings := rules.All([]*workflow.Workflow{wf})
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.RuleID] = true
	}
	for _, id := range []string{
		"unpinned-action",
		"permissions-missing",
		"permissions-write-all",
		"pull-request-target-checkout",
		"secrets-untrusted-trigger",
		"unscoped-pat",
		"script-injection",
	} {
		if !seen[id] {
			t.Fatalf("golden fixture missing %s in %#v", id, findings)
		}
	}
	var buf bytes.Buffer
	if err := Write(&buf, "sarif", findings); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "all.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("sarif mismatch\n%s", buf.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestSARIFEscapesURI(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, "sarif", []rules.Finding{{
		RuleID: "unpinned-action", Severity: "warning",
		File: "my dir/ci.yml", Line: 1, Column: 1, Message: "x",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"uri": "my%20dir/ci.yml"`)) {
		t.Fatalf("uri not escaped: %s", buf.String())
	}
}

func TestTextAndJSON(t *testing.T) {
	in := []rules.Finding{{
		RuleID: "unpinned-action", Severity: "warning",
		File: "ci.yml", Line: 2, Column: 3,
		Message: `action "actions/checkout@v4" is not pinned to a 40-character commit SHA`,
	}}
	var text bytes.Buffer
	if err := Write(&text, "text", in); err != nil {
		t.Fatal(err)
	}
	const wantText = "ci.yml:2:3: warning: unpinned-action: action \"actions/checkout@v4\" is not pinned to a 40-character commit SHA\n"
	if text.String() != wantText {
		t.Fatalf("text %q", text.String())
	}
	var js bytes.Buffer
	if err := Write(&js, "json", nil); err != nil {
		t.Fatal(err)
	}
	if js.String() != "{\n  \"findings\": []\n}\n" {
		t.Fatalf("empty json %q", js.String())
	}
}
