package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFailOn(t *testing.T) {
	dir := t.TempDir()
	body := []byte("on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"--dir", dir}, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("default exit %d", code)
	}
	if code := Run([]string{"--dir", dir, "--fail-on", "error"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("fail-on error exit %d", code)
	}
	var out bytes.Buffer
	if code := Run([]string{"--dir", dir, "--format", "json"}, &out, &bytes.Buffer{}); code != 1 {
		t.Fatalf("json exit %d", code)
	}
	if !strings.Contains(out.String(), `"ruleId": "unpinned-action"`) {
		t.Fatalf("json %s", out.String())
	}
}

func TestFailOnNone(t *testing.T) {
	dir := t.TempDir()
	body := []byte("on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n")
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"--dir", dir, "--fail-on", "none"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestBadFailOn(t *testing.T) {
	var errb bytes.Buffer
	if code := Run([]string{"--fail-on", "critical"}, &bytes.Buffer{}, &errb); code != 2 {
		t.Fatalf("exit %d stderr %s", code, errb.String())
	}
}

func TestFileErrorStillReports(t *testing.T) {
	dir := t.TempDir()
	good := []byte("on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "ci.yml"), filepath.Join(dir, "link.yml")); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := Run([]string{"--dir", dir}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "unpinned-action") {
		t.Fatalf("stdout %s", out.String())
	}
	if !strings.Contains(errb.String(), "link.yml") {
		t.Fatalf("stderr %s", errb.String())
	}
}

func TestSymlinkDirComponent(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	code := Run([]string{"--dir", filepath.Join(root, "link", "workflows")}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestFixPinsAndLeavesDoubleQuoted(t *testing.T) {
	dir := t.TempDir()
	body := []byte("on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: \"actions/checkout@v4\"\n")
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	lock := `{"version":1,"pins":{"actions/checkout@v4":{"sha":"0123456789abcdef0123456789abcdef01234567","repository":"actions/checkout","ref":"v4"}}}`
	lockPath := filepath.Join(dir, "pins.json")
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	code := Run([]string{"--dir", dir, "--fix", "--lockfile", lockPath}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dir, "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("file changed\n%s", got)
	}

	plain := []byte("on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), plain, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"--dir", dir, "--fix", "--lockfile", lockPath}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("pinned exit %d", code)
	}
	got, err = os.ReadFile(filepath.Join(dir, "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "actions/checkout@0123456789abcdef0123456789abcdef01234567") {
		t.Fatalf("file\n%s", got)
	}
}

func TestWriteError(t *testing.T) {
	dir := t.TempDir()
	body := []byte("on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	if err := os.Symlink(filepath.Join(dir, "ci.yml"), filepath.Join(dir, "link.yml")); err != nil {
		t.Fatal(err)
	}
	code := Run([]string{"--dir", dir}, errWriter{}, &errb)
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "link.yml") || !strings.Contains(errb.String(), "write report") {
		t.Fatalf("stderr %s", errb.String())
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }
