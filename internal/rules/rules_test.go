package rules

import (
	"os"
	"path/filepath"
	"testing"

	"gha-hardener/internal/workflow"
)

func TestUnpinned(t *testing.T) {
	cases := []struct {
		name string
		src  string
		file string
		want int
	}{
		{"good", "", "unpinned-action/good.yml", 0},
		{"bad", "", "unpinned-action/bad.yml", 1},
		{"reusable good", "", "unpinned-action/reusable-good.yml", 0},
		{"reusable bad", "", "unpinned-action/reusable-bad.yml", 1},
		{"upper sha", "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@0123456789ABCDEF0123456789ABCDEF01234567\n", "", 0},
		{"local", "on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/build\n", "", 0},
		{"docker", "on: push\njobs:\n  build:\n    steps:\n      - uses: docker://alpine:3.20\n", "", 0},
		{"no ref", "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout\n", "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf := loadWorkflow(t, tc.file, tc.src)
			got := Unpinned(wf)
			if len(got) != tc.want {
				t.Fatalf("findings %#v", got)
			}
			if tc.want == 1 && got[0].RuleID != "unpinned-action" {
				t.Fatalf("rule %s", got[0].RuleID)
			}
		})
	}
}

func TestPermissionsMissing(t *testing.T) {
	cases := []struct {
		name string
		src  string
		file string
		want int
	}{
		{"good", "", "permissions-missing/good.yml", 0},
		{"bad", "", "permissions-missing/bad.yml", 1},
		{"empty mapping is set", "on: push\npermissions: {}\njobs:\n  build:\n    steps:\n      - run: echo ok\n", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf := loadWorkflow(t, tc.file, tc.src)
			got := filter(Permissions(wf), "permissions-missing")
			if len(got) != tc.want {
				t.Fatalf("findings %#v", Permissions(wf))
			}
		})
	}
}

func TestPermissionsWriteAll(t *testing.T) {
	cases := []struct {
		name string
		src  string
		file string
		want int
	}{
		{"good", "", "permissions-write-all/good.yml", 0},
		{"bad", "", "permissions-write-all/bad.yml", 1},
		{"upper case", "on: push\npermissions: WRITE-ALL\njobs:\n  build:\n    steps:\n      - run: echo ok\n", "", 1},
		{"job override", "on: push\npermissions: write-all\njobs:\n  safe:\n    permissions:\n      contents: read\n    steps:\n      - run: echo ok\n  loose:\n    steps:\n      - run: echo ok\n", "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf := loadWorkflow(t, tc.file, tc.src)
			got := filter(Permissions(wf), "permissions-write-all")
			if len(got) != tc.want {
				t.Fatalf("findings %#v", got)
			}
			if tc.name == "job override" && got[0].Message != `job "loose" grants permissions: write-all` {
				t.Fatalf("message %q", got[0].Message)
			}
		})
	}
}

func TestScriptInjection(t *testing.T) {
	cases := []struct {
		name string
		src  string
		file string
		want int
	}{
		{"good", "", "script-injection/good.yml", 0},
		{"bad", "", "script-injection/bad.yml", 1},
		{"brackets", "on: push\njobs:\n  build:\n    steps:\n      - run: echo ${{ github['event']['issue']['title'] }}\n", "", 1},
		{"double quotes", "on: push\njobs:\n  build:\n    steps:\n      - run: echo ${{ github[\"event\"] }}\n", "", 1},
		{"event name", "on: push\njobs:\n  build:\n    steps:\n      - run: echo ${{ github.event_name }}\n", "", 0},
		{"event name brackets", "on: push\njobs:\n  build:\n    steps:\n      - run: echo ${{ github['event_name'] }}\n", "", 0},
		{"string literal", "on: push\njobs:\n  build:\n    steps:\n      - run: echo ${{ contains('github.event.issue.title', 'x') }}\n", "", 0},
		{"mixed case", "on: push\njobs:\n  build:\n    steps:\n      - run: echo ${{ GitHub.Event.issue.title }}\n", "", 1},
		{"mixed case brackets", "on: push\njobs:\n  build:\n    steps:\n      - run: echo ${{ GitHub['Event'] }}\n", "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf := loadWorkflow(t, tc.file, tc.src)
			got := Injection(wf)
			if len(got) != tc.want {
				t.Fatalf("findings %#v", got)
			}
		})
	}
}

func loadWorkflow(t *testing.T, file, src string) *workflow.Workflow {
	t.Helper()
	if file != "" {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", file))
		if err != nil {
			t.Fatal(err)
		}
		src = string(b)
	}
	wf, err := workflow.Parse(".github/workflows/ci.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return wf
}

func filter(in []Finding, rule string) []Finding {
	var out []Finding
	for _, f := range in {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}
