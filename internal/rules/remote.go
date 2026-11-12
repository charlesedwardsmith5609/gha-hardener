package rules

import (
	"net/url"
	"regexp"
	"strings"

	"gha-hardener/internal/workflow"
)

const remoteMessage = "run script executes a remote script that is not pinned to a commit SHA"

var shaSegment = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// Remote reports run steps that execute curl or wget output without a
// pinned GitHub commit URL. It does not fetch the URL. The calling
// goroutine owns the script string.
func Remote(wf *workflow.Workflow) []Finding {
	var out []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" || !remoteUnpinned(step.Run, 0) {
				continue
			}
			line, col := step.RunLine, step.RunColumn
			if line < 1 {
				line = 1
			}
			if col < 1 {
				col = 1
			}
			out = append(out, Finding{
				RuleID:   "remote-script",
				Severity: Error,
				File:     wf.Path,
				Line:     line,
				Column:   col,
				Message:  remoteMessage,
			})
		}
	}
	return out
}

type token struct {
	kind byte // 'w' word, 'o' operator
	text string
	sub  []string
}

func remoteUnpinned(script string, depth int) bool {
	if depth > 8 || script == "" {
		return false
	}
	toks := lex(stripContinuations(script))
	for _, t := range toks {
		for _, body := range t.sub {
			if remoteUnpinned(body, depth+1) {
				return true
			}
		}
	}
	for i := 0; i < len(toks); i++ {
		idx, ok := commandIndex(toks, i)
		if !ok {
			continue
		}
		name := toks[idx].text
		switch {
		case isShell(name) && idx+1 < len(toks) && toks[idx+1].text == "<(":
			if args, found := fetchArgs(toks, idx+2); found && !allPinned(args) {
				return true
			}
		case isFetch(name):
			args, next := argsUntil(toks, idx+1)
			if pipeShell(toks, next) && !allPinned(args) {
				return true
			}
		case name == "eval":
			words := wordsUntil(toks, idx+1)
			if executedUnpinned(words, depth) {
				return true
			}
		case isShell(name):
			if arg, found := dashC(toks, idx+1); found && executedUnpinned([]token{arg}, depth) {
				return true
			}
		}
	}
	return false
}

func executedUnpinned(words []token, depth int) bool {
	if len(words) == 0 {
		return false
	}
	for _, w := range words {
		if fetchBodyUnpinned(w) {
			return true
		}
	}
	var b strings.Builder
	for n, w := range words {
		if n > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(w.text)
	}
	return remoteUnpinned(b.String(), depth+1)
}

func commandIndex(toks []token, i int) (int, bool) {
	if i >= len(toks) || toks[i].kind != 'w' || !cmdPos(toks, i) {
		return 0, false
	}
	for i < len(toks) && toks[i].kind == 'w' && isAssign(toks[i].text) {
		i++
	}
	if i >= len(toks) || toks[i].kind != 'w' {
		return 0, false
	}
	return i, true
}

func isAssign(text string) bool {
	eq := strings.IndexByte(text, '=')
	if eq <= 0 {
		return false
	}
	for n, r := range text[:eq] {
		ok := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (n > 0 && r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func wordsUntil(toks []token, i int) []token {
	words, _ := argsUntil(toks, i)
	return words
}

func fetchBodyUnpinned(w token) bool {
	for _, body := range w.sub {
		toks := lex(body)
		for i := 0; i < len(toks); i++ {
			if toks[i].kind == 'w' && cmdPos(toks, i) && isFetch(toks[i].text) {
				args, _ := argsUntil(toks, i+1)
				if !allPinned(args) {
					return true
				}
			}
		}
	}
	return false
}

func fetchArgs(toks []token, i int) ([]token, bool) {
	if i >= len(toks) || toks[i].kind != 'w' || !isFetch(toks[i].text) {
		return nil, false
	}
	args, _ := argsUntil(toks, i+1)
	return args, true
}

func argsUntil(toks []token, i int) ([]token, int) {
	var args []token
	for i < len(toks) {
		t := toks[i]
		if t.kind == 'o' {
			return args, i
		}
		args = append(args, t)
		i++
	}
	return args, i
}

func pipeShell(toks []token, i int) bool {
	if i >= len(toks) || (toks[i].text != "|" && toks[i].text != "|&") {
		return false
	}
	i++
	if i < len(toks) && toks[i].kind == 'w' && toks[i].text == "sudo" {
		i++
		for i < len(toks) && toks[i].kind == 'w' && strings.HasPrefix(toks[i].text, "-") {
			flag := toks[i].text
			i++
			if sudoTakesArg(flag) && i < len(toks) && toks[i].kind == 'w' && !strings.HasPrefix(toks[i].text, "-") {
				i++
			}
		}
	}
	return i < len(toks) && toks[i].kind == 'w' && isShell(toks[i].text)
}

func sudoTakesArg(flag string) bool {
	if strings.Contains(flag, "=") {
		return false
	}
	switch flag {
	case "--user", "--group", "--host", "--prompt", "--chdir", "--role", "--type", "--command-timeout", "--close-from":
		return true
	}
	if len(flag) < 2 || flag[0] != '-' || flag[1] == '-' {
		return false
	}
	switch flag[len(flag)-1] {
	case 'u', 'g', 'h', 'p', 'C', 'T', 'r', 't':
		return true
	default:
		return false
	}
}

func dashC(toks []token, i int) (token, bool) {
	for i < len(toks) && toks[i].kind == 'w' && strings.HasPrefix(toks[i].text, "-") {
		flag := toks[i].text
		i++
		if shortC(flag) {
			if i < len(toks) && toks[i].kind == 'w' {
				return toks[i], true
			}
			return token{}, false
		}
		if shellOptTakesArg(flag) && i < len(toks) && toks[i].kind == 'w' {
			i++
		}
	}
	return token{}, false
}

func shortC(flag string) bool {
	return len(flag) >= 2 && flag[0] == '-' && flag[1] != '-' && strings.Contains(flag[1:], "c")
}

func shellOptTakesArg(flag string) bool {
	switch flag {
	case "-o", "-O", "--rcfile", "--init-file":
		return true
	default:
		return false
	}
}

func allPinned(args []token) bool {
	urls := urlArgs(args)
	if len(urls) == 0 {
		return false
	}
	for _, raw := range urls {
		if !pinnedGitHub(raw) {
			return false
		}
	}
	return true
}

func urlArgs(args []token) []string {
	var urls []string
	for i := 0; i < len(args); i++ {
		text := args[i].text
		if text == "--url" && i+1 < len(args) {
			urls = append(urls, args[i+1].text)
			i++
			continue
		}
		if rest, ok := strings.CutPrefix(text, "--url="); ok {
			urls = append(urls, rest)
			continue
		}
		if strings.HasPrefix(text, "$") {
			urls = append(urls, "")
			continue
		}
		if strings.Contains(text, "://") {
			urls = append(urls, text)
		}
	}
	return urls
}

func pinnedGitHub(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Port() != "" || !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	var segs []string
	for _, seg := range strings.Split(u.Path, "/") {
		if seg != "" {
			segs = append(segs, seg)
		}
	}
	switch strings.ToLower(u.Hostname()) {
	case "raw.githubusercontent.com":
		return len(segs) >= 3 && shaSegment.MatchString(segs[2])
	case "github.com":
		return len(segs) >= 4 && (segs[2] == "raw" || segs[2] == "blob") && shaSegment.MatchString(segs[3])
	default:
		return false
	}
}

func isShell(name string) bool {
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh", "ash":
		return true
	default:
		return false
	}
}

func isFetch(name string) bool {
	return name == "curl" || name == "wget"
}

func cmdPos(toks []token, i int) bool {
	if i == 0 {
		return true
	}
	if toks[i-1].kind != 'o' {
		return false
	}
	switch toks[i-1].text {
	case ";", "|", "|&", "||", "&&", "(", "<(":
		return true
	default:
		return false
	}
}

func stripContinuations(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '\n' || s[i+1] == '\r') {
			i++
			if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func lex(s string) []token {
	var toks []token
	boundary := true
	for i := 0; i < len(s); {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' {
			boundary = true
			i++
			continue
		}
		if c == '\n' {
			if n := len(toks); n > 0 && (toks[n-1].text == "|" || toks[n-1].text == "|&") {
				boundary = true
				i++
				continue
			}
			toks = append(toks, token{kind: 'o', text: ";"})
			boundary = true
			i++
			continue
		}
		if boundary && c == '#' {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		if strings.HasPrefix(s[i:], "<(") {
			toks = append(toks, token{kind: 'o', text: "<("})
			boundary = true
			i += 2
			continue
		}
		if c == '|' || c == '&' || c == ';' || c == '(' || c == ')' {
			if c == '|' && i+1 < len(s) && s[i+1] == '&' {
				toks = append(toks, token{kind: 'o', text: "|&"})
				i += 2
			} else if (c == '|' || c == '&') && i+1 < len(s) && s[i+1] == c {
				toks = append(toks, token{kind: 'o', text: s[i : i+2]})
				i += 2
			} else {
				toks = append(toks, token{kind: 'o', text: s[i : i+1]})
				i++
			}
			boundary = true
			continue
		}
		w, next := readWord(s, i)
		toks = append(toks, w)
		i = next
		boundary = false
	}
	return toks
}

func readWord(s string, i int) (token, int) {
	var b strings.Builder
	var subs []string
	for i < len(s) {
		if strings.HasPrefix(s[i:], "$(") {
			body, n := commandSubst(s, i+2)
			subs = append(subs, body)
			b.WriteString("$(")
			b.WriteString(body)
			b.WriteByte(')')
			i = n
			continue
		}
		if strings.HasPrefix(s[i:], "<(") {
			break
		}
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '|' || c == '&' || c == ';' || c == '(' || c == ')' {
			break
		}
		if c == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i += 2
			continue
		}
		if c == '\'' {
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++
			}
			continue
		}
		if c == '"' {
			i++
			for i < len(s) && s[i] != '"' {
				if strings.HasPrefix(s[i:], "$(") {
					body, n := commandSubst(s, i+2)
					subs = append(subs, body)
					b.WriteString("$(")
					b.WriteString(body)
					b.WriteByte(')')
					i = n
					continue
				}
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++
			}
			continue
		}
		b.WriteByte(c)
		i++
	}
	return token{kind: 'w', text: b.String(), sub: subs}, i
}

func commandSubst(s string, i int) (string, int) {
	start := i
	depth := 1
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '\'' {
			i++
			for i < len(s) && s[i] != '\'' {
				i++
			}
			if i < len(s) {
				i++
			}
			continue
		}
		if s[i] == '"' {
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
			if i < len(s) {
				i++
			}
			continue
		}
		if s[i] == '(' {
			depth++
			i++
			continue
		}
		if s[i] == ')' {
			depth--
			if depth == 0 {
				return s[start:i], i + 1
			}
			i++
			continue
		}
		i++
	}
	return s[start:], len(s)
}
