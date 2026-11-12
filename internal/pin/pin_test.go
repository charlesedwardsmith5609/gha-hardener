package pin

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gha-hardener/internal/workflow"
)

const testSHA = "0123456789abcdef0123456789abcdef01234567"

func TestResolveSuccessAndSlashRef(t *testing.T) {
	var hits atomic.Int32
	ln, srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("authorization header was set")
		}
		if r.URL.EscapedPath() != "/repos/acme/demo/commits/feature%2Ffoo" &&
			r.URL.RequestURI() != "/repos/acme/demo/commits/feature%2Ffoo" {
			t.Errorf("path %s uri %s", r.URL.EscapedPath(), r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sha":"` + testSHA + `","commit":{"message":"x"}}`))
	})
	defer srv.Close()
	dir := t.TempDir()
	body := []byte("on: push\njobs:\n  build:\n    steps:\n      - uses: acme/demo@feature/foo\n")
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := Resolve(dir, "http://"+ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := lock.Pins["acme/demo@feature/foo"]
	if !ok || p.SHA != testSHA || p.Ref != "feature/foo" {
		t.Fatalf("pin %#v", lock.Pins)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	path := filepath.Join(dir, "gha-pins.json")
	if err := Write(path, lock); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil || got.Pins["acme/demo@feature/foo"].SHA != testSHA {
		t.Fatalf("read %#v %v", got, err)
	}
}

func TestResolveTimeout(t *testing.T) {
	ln, srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	defer srv.Close()
	dir := workflowDir(t, "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	done := make(chan error, 1)
	go func() {
		_, err := Resolve(dir, "http://"+ln.Addr().String(), time.Second)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolve did not return before the deadline")
	}
}

func TestResolveRejectsRedirect(t *testing.T) {
	ln, srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.0.2.1/stolen", http.StatusFound)
	})
	defer srv.Close()
	dir := workflowDir(t, "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	done := make(chan error, 1)
	go func() {
		_, err := Resolve(dir, "http://"+ln.Addr().String(), time.Second)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
			t.Fatalf("err %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("redirect was followed or resolve hung")
	}
}

func TestResolveRejectsHugeBody(t *testing.T) {
	ln, srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 1<<20+1)
		for i := range buf {
			buf[i] = 'a'
		}
		_, _ = w.Write(buf)
	})
	defer srv.Close()
	dir := workflowDir(t, "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	if _, err := Resolve(dir, "http://"+ln.Addr().String(), time.Second); err == nil {
		t.Fatal("expected oversized body to fail")
	}
}

func TestResolveRejectsTrailingJSON(t *testing.T) {
	ln, srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sha":"` + testSHA + `"}{"x":1}`))
	})
	defer srv.Close()
	dir := workflowDir(t, "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	if _, err := Resolve(dir, "http://"+ln.Addr().String(), time.Second); err == nil {
		t.Fatal("expected trailing JSON to fail")
	}
}

func TestResolveCapsRefsBeforeDial(t *testing.T) {
	var hits atomic.Int32
	ln, srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	})
	defer srv.Close()
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  build:\n    steps:\n")
	for i := 0; i < 129; i++ {
		b.WriteString("      - uses: actions/checkout@v")
		b.WriteString(itoa(i))
		b.WriteString("\n")
	}
	dir := workflowDir(t, b.String())
	_, err := Resolve(dir, "http://"+ln.Addr().String(), time.Second)
	if err == nil {
		t.Fatal("expected cap")
	}
	if hits.Load() != 0 {
		t.Fatalf("hits %d", hits.Load())
	}
}

func TestLockfileRejects(t *testing.T) {
	cases := []string{
		`{"Version":1,"pins":{}}`,
		`{"version":1,"pins":{},"extra":1}`,
		`{"version":2,"pins":{}}`,
		`{"version":1,"pins":{"actions/checkout@v4":{"SHA":"` + testSHA + `","repository":"actions/checkout","ref":"v4"}}}`,
		`{"version":1,"pins":{"actions/checkout@v4":{"sha":"` + testSHA + `","repository":"actions/checkout","ref":"v4"}}}{"x":1}`,
	}
	for _, src := range cases {
		if _, err := parseLock([]byte(src)); err == nil {
			t.Fatalf("accepted %s", src)
		}
	}
	good := `{"version":1,"pins":{"actions/checkout@v4":{"sha":"` + testSHA + `","repository":"actions/checkout","ref":"v4"}}}`
	got, err := parseLock([]byte(good))
	if err != nil || got.Pins["actions/checkout@v4"].SHA != testSHA {
		t.Fatal(err)
	}
}

func TestRewriteShapes(t *testing.T) {
	lock := &Lock{Version: 1, Pins: map[string]Pin{
		"actions/checkout@v4":     {SHA: testSHA, Repository: "actions/checkout", Ref: "v4"},
		"actions/setup-go@v5":     {SHA: testSHA, Repository: "actions/setup-go", Ref: "v5"},
		"actions/checkout@HEAD":   {SHA: testSHA, Repository: "actions/checkout", Ref: "HEAD"},
		"github/codeql-action@v3": {SHA: testSHA, Repository: "github/codeql-action", Ref: "v3"},
	}}
	cases := []struct {
		name string
		src  string
		want string
		same bool
	}{
		{
			"plain",
			"on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
			"actions/checkout@" + testSHA,
			false,
		},
		{
			"single quoted",
			"on: push\njobs:\n  build:\n    steps:\n      - uses: 'actions/checkout@v4'\n",
			"'actions/checkout@" + testSHA + "'",
			false,
		},
		{
			"two on one line",
			"on: push\njobs:\n  build:\n    steps: [{uses: actions/checkout@v4}, {uses: actions/setup-go@v5}]\n",
			"actions/checkout@" + testSHA,
			false,
		},
		{
			"no at",
			"on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout\n",
			"actions/checkout@" + testSHA,
			false,
		},
		{
			"subpath",
			"on: push\njobs:\n  build:\n    steps:\n      - uses: github/codeql-action/init@v3\n",
			"github/codeql-action/init@" + testSHA,
			false,
		},
		{
			"double quoted",
			"on: push\njobs:\n  build:\n    steps:\n      - uses: \"actions/checkout@v4\"\n",
			"\"actions/checkout@v4\"",
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, err := workflow.Parse("ci.yml", []byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Rewrite([]byte(tc.src), wf, lock)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), tc.want) {
				t.Fatalf("got\n%s", got)
			}
			if tc.name == "two on one line" && !strings.Contains(string(got), "actions/setup-go@"+testSHA) {
				t.Fatalf("second uses not rewritten\n%s", got)
			}
			if tc.same && string(got) != tc.src {
				t.Fatalf("changed\n%s", got)
			}
		})
	}
}

func TestApplyDoesNotDial(t *testing.T) {
	dir := workflowDir(t, "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	lock := &Lock{Version: 1, Pins: map[string]Pin{
		"actions/checkout@v4": {SHA: testSHA, Repository: "actions/checkout", Ref: "v4"},
	}}
	if err := Apply(dir, lock); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "actions/checkout@"+testSHA) {
		t.Fatalf("file\n%s", got)
	}
}

func serve(t *testing.T, h http.HandlerFunc) (net.Listener, *httptest.Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	old := srv.Listener
	srv.Listener = ln
	_ = old.Close()
	srv.Start()
	t.Cleanup(func() { srv.Close() })
	return ln, srv
}

func workflowDir(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestResolveRejectsMalformedUsesBeforeDial(t *testing.T) {
	dir := workflowDir(t, "on: push\njobs:\n  build:\n    steps:\n      - uses: acme/bad repo@v1\n")
	_, err := Resolve(dir, "http://127.0.0.1:1", time.Second)
	if err == nil || !strings.Contains(err.Error(), "not a pinnable") {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatal("error contains a raw control character")
	}
}

func TestResolveSkipsLocalAndPinned(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    steps:\n      - uses: ./local\n      - uses: docker://alpine\n      - uses: actions/checkout@" + testSHA + "\n"
	dir := workflowDir(t, src)
	lock, err := Resolve(dir, "http://127.0.0.1:1", time.Second)
	if err != nil || len(lock.Pins) != 0 {
		t.Fatalf("%v %#v", err, lock)
	}
}

func TestLockfileRejectsControlKey(t *testing.T) {
	src := `{"version":1,"pins":{"acme/\u001bb@v1":{"sha":"` + testSHA + `","repository":"acme/\u001bb","ref":"v1"}}}`
	_, err := parseLock([]byte(src))
	if err == nil {
		t.Fatal("accepted control character in key")
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("unquoted control in error: %q", err.Error())
	}
}

func TestApplyIsAtomicAndKeepsMode(t *testing.T) {
	dir := t.TempDir()
	plain := []byte("on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
	if err := os.WriteFile(filepath.Join(dir, "a.yml"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "z.yml"), []byte(":\n["), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := &Lock{Version: 1, Pins: map[string]Pin{
		"actions/checkout@v4": {SHA: testSHA, Repository: "actions/checkout", Ref: "v4"},
	}}
	if err := Apply(dir, lock); err == nil {
		t.Fatal("expected the bad file to fail the rewrite")
	}
	got, err := os.ReadFile(filepath.Join(dir, "a.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("partial rewrite\n%s", got)
	}

	if err := os.Remove(filepath.Join(dir, "z.yml")); err != nil {
		t.Fatal(err)
	}
	if err := Apply(dir, lock); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "a.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestApplyTotalCap(t *testing.T) {
	dir := t.TempDir()
	body := make([]byte, workflow.MaxFileBytes)
	copy(body, []byte("on: push\njobs: {}\n"))
	for i := 0; i < 9; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+itoa(i)+".yml"), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := Apply(dir, &Lock{Version: 1, Pins: map[string]Pin{}})
	if !errors.Is(err, workflow.ErrTotal) {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
