// Package workflow loads GitHub Actions workflow files.
// The calling goroutine owns every descriptor LoadDir opens and closes
// them before returning. LoadDir does not start goroutines.
package workflow

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	MaxFileBytes  = 1 << 20
	MaxFiles      = 200
	MaxTotalBytes = 8 << 20
	MaxNodes      = 100_000
	MaxDepth      = 32
)

var (
	ErrSymlink    = errors.New("refusing symlink")
	ErrNotRegular = errors.New("not a regular file")
	ErrTooBig     = errors.New("file exceeds 1 MiB")
	ErrTotal      = errors.New("workflow inputs exceed 8 MiB")
	ErrTooMany    = errors.New("more than 200 workflow files")
	ErrAlias      = errors.New("YAML aliases are not allowed")
	ErrMerge      = errors.New("YAML merge keys are not allowed")
	ErrMultiDoc   = errors.New("multiple YAML documents are not allowed")
	ErrUTF8       = errors.New("workflow is not valid UTF-8")
	ErrNodes      = errors.New("workflow exceeds node limit")
	ErrDepth      = errors.New("workflow exceeds nesting depth")
)

// FileError is a problem with one workflow file. LoadDir keeps scanning
// the other files.
type FileError struct {
	Path string
	Err  error
}

func (e FileError) Error() string { return e.Path + ": " + e.Err.Error() }
func (e FileError) Unwrap() error { return e.Err }

// Event is one trigger name from on.
type Event struct {
	Name         string
	Line, Column int
}

// Permissions is a present permissions block. A nil pointer means the
// key was absent. WriteAll is true only for the scalar write-all, in any case.
type Permissions struct {
	WriteAll     bool
	Line, Column int
}

// Step is one job step. Env and with are intentionally not stored yet.
type Step struct {
	Uses                 string
	UsesLine, UsesColumn int
	Run                  string
	RunLine, RunColumn   int
}

// Job is one entry under jobs. Uses is set for a reusable-workflow job.
type Job struct {
	ID                   string
	Line, Column         int
	Permissions          *Permissions
	Uses                 string
	UsesLine, UsesColumn int
	Steps                []Step
}

// Workflow is a parsed workflow file. Path is the display path, not a
// path this package opens.
type Workflow struct {
	Path        string
	On          []Event
	Permissions *Permissions
	Jobs        []Job
}

var workflowName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml$`)

// Parse decodes one workflow document. displayPath is stored as-is after
// it is checked for traversal; Parse does not read it.
func Parse(displayPath string, data []byte) (*Workflow, error) {
	if err := validDisplay(displayPath); err != nil {
		return nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, ErrTooBig
	}
	if !utf8.Valid(data) {
		return nil, ErrUTF8
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, ErrMultiDoc
		}
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	seen := 0
	if err := checkTree(&doc, &seen, 0); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("workflow root must be a mapping")
	}
	wf := &Workflow{Path: displayPath}
	root := doc.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		key, err := mappingKey(root.Content[i], data)
		if err != nil {
			return nil, err
		}
		val := root.Content[i+1]
		switch key {
		case "on":
			ev, err := parseOn(val, data)
			if err != nil {
				return nil, err
			}
			wf.On = ev
		case "permissions":
			p, err := parsePerm(val)
			if err != nil {
				return nil, err
			}
			wf.Permissions = p
		case "jobs":
			jobs, err := parseJobs(val, data)
			if err != nil {
				return nil, err
			}
			wf.Jobs = jobs
		}
	}
	return wf, nil
}

// LoadDir reads workflow files in dir, one level deep.
// The hard error is only a failure to open dir itself. Per-file problems
// are returned alongside any workflows that parsed.
func LoadDir(dir string) ([]*Workflow, []FileError, error) {
	dirfd, err := openDirNoFollow(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("open workflow directory: %w", err)
	}
	defer syscall.Close(dirfd)

	names, err := matchingNames(dirfd)
	if err != nil {
		return nil, nil, err
	}

	var (
		out   []*Workflow
		errs  []FileError
		total int
	)
	for i, name := range names {
		if i >= MaxFiles {
			errs = append(errs, FileError{Path: name, Err: ErrTooMany})
			break
		}
		remaining := MaxTotalBytes - total
		if remaining <= 0 {
			errs = append(errs, FileError{Path: name, Err: ErrTotal})
			break
		}
		limit := MaxFileBytes
		if remaining < limit {
			limit = remaining
		}
		display := displayPath(dir, name)
		body, err := readEntry(dirfd, name, limit)
		if err != nil {
			if errors.Is(err, ErrTooBig) {
				total += limit
				if limit < MaxFileBytes {
					err = ErrTotal
				}
			}
			errs = append(errs, FileError{Path: display, Err: err})
			if total >= MaxTotalBytes {
				break
			}
			continue
		}
		total += len(body)
		wf, err := Parse(display, body)
		if err != nil {
			errs = append(errs, FileError{Path: display, Err: err})
			continue
		}
		out = append(out, wf)
	}
	return out, errs, nil
}

func readEntry(dirfd int, name string, max int) ([]byte, error) {
	fd, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrSymlink
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	return readLimited(f, max)
}

func readLimited(f *os.File, max int) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > max {
		return nil, ErrTooBig
	}
	return buf, nil
}

// openDirNoFollow walks every component of dir from a root descriptor.
// A symlink component fails the open. ".." is rejected so the walk cannot leave the root.
func openDirNoFollow(dir string) (int, error) {
	clean := filepath.Clean(dir)
	var (
		dirfd int
		err   error
		rest  string
	)
	if filepath.IsAbs(clean) {
		dirfd, err = syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		rest = strings.TrimPrefix(clean, string(os.PathSeparator))
	} else {
		dirfd, err = syscall.Open(".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		rest = clean
	}
	if err != nil {
		return -1, err
	}
	if rest == "." || rest == "" {
		return dirfd, nil
	}
	for _, part := range strings.Split(rest, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			syscall.Close(dirfd)
			return -1, errors.New("workflow directory must not contain ..")
		}
		next, err := syscall.Openat(dirfd, part, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		syscall.Close(dirfd)
		if err != nil {
			return -1, err
		}
		dirfd = next
	}
	return dirfd, nil
}

// matchingNames keeps at most MaxFiles+1 workflow file names. Other directory entries are discarded.
func matchingNames(dirfd int) ([]string, error) {
	dupfd, err := syscall.Dup(dirfd)
	if err != nil {
		return nil, fmt.Errorf("read workflow directory: %w", err)
	}
	df := os.NewFile(uintptr(dupfd), ".")
	defer df.Close()

	var names []string
	for {
		batch, err := df.ReadDir(64)
		for _, ent := range batch {
			name := ent.Name()
			if !workflowName.MatchString(name) {
				continue
			}
			names = append(names, name)
			if len(names) > MaxFiles {
				break
			}
		}
		if len(names) > MaxFiles || err != nil {
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("read workflow directory: %w", err)
			}
			break
		}
	}
	sort.Strings(names)
	return names, nil
}

func displayPath(dir, name string) string {
	abs, err := filepath.Abs(filepath.Join(dir, name))
	if err != nil {
		return name
	}
	cwd, err := os.Getwd()
	if err != nil {
		return name
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return name
	}
	rel = filepath.ToSlash(rel)
	if validDisplay(rel) != nil {
		return name
	}
	return rel
}

func validDisplay(p string) error {
	if p == "" || strings.Contains(p, "\\") || strings.Contains(p, "\x00") {
		return fmt.Errorf("invalid workflow path %q", p)
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return fmt.Errorf("invalid workflow path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == ".." {
			return fmt.Errorf("invalid workflow path %q", p)
		}
	}
	return nil
}

func checkTree(n *yaml.Node, seen *int, depth int) error {
	if n == nil {
		return nil
	}
	if depth > MaxDepth {
		return ErrDepth
	}
	*seen++
	if *seen > MaxNodes {
		return ErrNodes
	}
	if n.Kind == yaml.AliasNode {
		return ErrAlias
	}
	if n.Kind == yaml.MappingNode {
		if len(n.Content)%2 != 0 {
			return errors.New("malformed mapping")
		}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Value == "<<" || k.Tag == "!!merge" {
				return ErrMerge
			}
			if err := checkTree(k, seen, depth+1); err != nil {
				return err
			}
			if err := checkTree(n.Content[i+1], seen, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, c := range n.Content {
		if err := checkTree(c, seen, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func mappingKey(k *yaml.Node, raw []byte) (string, error) {
	if k.Kind != yaml.ScalarNode {
		return "", errors.New("mapping key is not a scalar")
	}
	if k.Value == "<<" || k.Tag == "!!merge" {
		return "", ErrMerge
	}
	if k.Tag == "!!bool" {
		tok, err := rawToken(raw, k.Line, k.Column)
		if err != nil {
			return "", err
		}
		if tok == "on" {
			return "on", nil
		}
		return "", fmt.Errorf("boolean mapping key %q", tok)
	}
	return k.Value, nil
}

func rawToken(raw []byte, line, col int) (string, error) {
	if line < 1 || col < 1 {
		return "", errors.New("missing key position")
	}
	cur := 1
	start := 0
	found := false
	for i, c := range raw {
		if cur == line {
			start = i
			found = true
			break
		}
		if c == '\n' {
			cur++
		}
	}
	if !found || cur != line {
		return "", fmt.Errorf("key line %d not found", line)
	}
	endLine := start
	for endLine < len(raw) && raw[endLine] != '\n' {
		endLine++
	}
	lineBytes := raw[start:endLine]
	idx := col - 1
	if idx > len(lineBytes) {
		return "", errors.New("key column out of range")
	}
	rest := lineBytes[idx:]
	n := 0
	for n < len(rest) && rest[n] != ':' && rest[n] != ' ' && rest[n] != '\t' && rest[n] != '#' {
		n++
	}
	if n == 0 {
		return "", errors.New("empty mapping key")
	}
	return string(rest[:n]), nil
}

func parseOn(n *yaml.Node, raw []byte) ([]Event, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!null" || n.Value == "" {
			return nil, nil
		}
		return []Event{{Name: n.Value, Line: lineOf(n), Column: colOf(n)}}, nil
	case yaml.SequenceNode:
		var ev []Event
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode || c.Tag == "!!null" {
				return nil, errors.New("trigger name must be a scalar")
			}
			ev = append(ev, Event{Name: c.Value, Line: lineOf(c), Column: colOf(c)})
		}
		return ev, nil
	case yaml.MappingNode:
		var ev []Event
		for i := 0; i < len(n.Content); i += 2 {
			name, err := mappingKey(n.Content[i], raw)
			if err != nil {
				return nil, err
			}
			ev = append(ev, Event{Name: name, Line: lineOf(n.Content[i]), Column: colOf(n.Content[i])})
		}
		return ev, nil
	default:
		return nil, errors.New("on must be a scalar, list, or mapping")
	}
}

func parsePerm(n *yaml.Node) (*Permissions, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		return &Permissions{
			WriteAll: strings.EqualFold(strings.TrimSpace(n.Value), "write-all"),
			Line:     lineOf(n),
			Column:   colOf(n),
		}, nil
	case yaml.MappingNode:
		return &Permissions{Line: lineOf(n), Column: colOf(n)}, nil
	default:
		return nil, errors.New("permissions must be a scalar or a mapping")
	}
}

func parseJobs(n *yaml.Node, raw []byte) ([]Job, error) {
	if n.Kind != yaml.MappingNode {
		return nil, errors.New("jobs must be a mapping")
	}
	var jobs []Job
	for i := 0; i < len(n.Content); i += 2 {
		id, err := mappingKey(n.Content[i], raw)
		if err != nil {
			return nil, err
		}
		v := n.Content[i+1]
		if v.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("job %q must be a mapping", id)
		}
		job := Job{ID: id, Line: lineOf(n.Content[i]), Column: colOf(n.Content[i])}
		for j := 0; j < len(v.Content); j += 2 {
			key, err := mappingKey(v.Content[j], raw)
			if err != nil {
				return nil, err
			}
			val := v.Content[j+1]
			switch key {
			case "permissions":
				p, err := parsePerm(val)
				if err != nil {
					return nil, err
				}
				job.Permissions = p
			case "uses":
				s, err := scalar(val, "uses")
				if err != nil {
					return nil, err
				}
				job.Uses = s
				job.UsesLine, job.UsesColumn = lineOf(val), colOf(val)
			case "steps":
				steps, err := parseSteps(val)
				if err != nil {
					return nil, err
				}
				job.Steps = steps
			}
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func parseSteps(n *yaml.Node) ([]Step, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, errors.New("steps must be a list")
	}
	var steps []Step
	for _, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			return nil, errors.New("step must be a mapping")
		}
		var step Step
		for i := 0; i < len(item.Content); i += 2 {
			k := item.Content[i]
			if k.Kind != yaml.ScalarNode {
				return nil, errors.New("step key must be a scalar")
			}
			if k.Value == "<<" || k.Tag == "!!merge" {
				return nil, ErrMerge
			}
			val := item.Content[i+1]
			switch k.Value {
			case "uses":
				s, err := scalar(val, "uses")
				if err != nil {
					return nil, err
				}
				step.Uses = s
				step.UsesLine, step.UsesColumn = lineOf(val), colOf(val)
			case "run":
				s, err := scalar(val, "run")
				if err != nil {
					return nil, err
				}
				step.Run = s
				step.RunLine, step.RunColumn = lineOf(val), colOf(val)
			}
		}
		steps = append(steps, step)
	}
	return steps, nil
}

func scalar(n *yaml.Node, what string) (string, error) {
	if n.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("%s must be a scalar", what)
	}
	if n.Tag == "!!null" {
		return "", nil
	}
	return n.Value, nil
}

func lineOf(n *yaml.Node) int {
	if n.Line < 1 {
		return 1
	}
	return n.Line
}

func colOf(n *yaml.Node) int {
	if n.Column < 1 {
		return 1
	}
	return n.Column
}
