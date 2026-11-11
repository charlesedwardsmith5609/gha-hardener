package workflow

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestOnShapes(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"scalar", "on: push\njobs: {}\n", []string{"push"}},
		{"list", "on: [push, pull_request]\njobs: {}\n", []string{"push", "pull_request"}},
		{"mapping", "on:\n  push:\n  pull_request:\njobs: {}\n", []string{"push", "pull_request"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, err := Parse("ci.yml", []byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			if len(wf.On) != len(tc.want) {
				t.Fatalf("events %#v", wf.On)
			}
			for i, name := range tc.want {
				if wf.On[i].Name != name {
					t.Fatalf("event %d = %q, want %q", i, wf.On[i].Name, name)
				}
			}
		})
	}
}

func TestBoolKeyRecoveredAsOn(t *testing.T) {
	raw := []byte("on: push\n")
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true", Line: 1, Column: 1}
	got, err := mappingKey(k, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != "on" {
		t.Fatalf("key %q", got)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want error
	}{
		{"merge", "b:\n  <<: {x: 1}\n", ErrMerge},
		{"alias", "a: &a {x: 1}\nb: *a\n", ErrAlias},
		{"second document", "a: 1\n---\nb: 2\n", ErrMultiDoc},
		{"utf-8", string([]byte("on: push\n\xff\n")), ErrUTF8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("ci.yml", []byte(tc.src))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNodeCap(t *testing.T) {
	var b bytes.Buffer
	for i := 0; i < 50000; i++ {
		b.WriteString("k")
		b.WriteString(itoa(i))
		b.WriteString(": 1\n")
	}
	if b.Len() > MaxFileBytes {
		t.Fatalf("fixture is %d bytes", b.Len())
	}
	_, err := Parse("ci.yml", b.Bytes())
	if !errors.Is(err, ErrNodes) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadDirRejectsSymlinkAndKeepsSibling(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.yml")
	if err := os.WriteFile(outside, []byte("on: push\njobs: {hidden: {steps: [{run: echo pwn}]}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.yml"), []byte("on: push\njobs: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.yml")); err != nil {
		t.Fatal(err)
	}
	got, errs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Jobs) != 0 {
		t.Fatalf("workflows %#v", got)
	}
	if len(errs) != 1 || !errors.Is(errs[0], ErrSymlink) {
		t.Fatalf("errs %#v", errs)
	}
}

func TestLoadDirRejectsSymlinkDirectory(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "workflows")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDir(link); err == nil {
		t.Fatal("expected symlink directory to fail")
	}
}

func TestLoadDirFIFODoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "hang.yml"), 0o644); err != nil {
		t.Fatal(err)
	}
	type result struct {
		errs []FileError
		err  error
	}
	done := make(chan result, 1)
	go func() {
		_, errs, err := LoadDir(dir)
		done <- result{errs, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if len(r.errs) != 1 || !errors.Is(r.errs[0], ErrNotRegular) {
			t.Fatalf("errs %#v", r.errs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LoadDir blocked on a FIFO")
	}
}

func TestLoadDirFileCap(t *testing.T) {
	dir := t.TempDir()
	body := bytes.Repeat([]byte("a"), MaxFileBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "big.yml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	_, errs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 1 || !errors.Is(errs[0], ErrTooBig) {
		t.Fatalf("errs %#v", errs)
	}
}

func TestLoadDirTotalCap(t *testing.T) {
	dir := t.TempDir()
	head := []byte("on: push\njobs: {}\n# ")
	pad := append(append([]byte{}, head...), bytes.Repeat([]byte("a"), MaxFileBytes-len(head))...)
	if len(pad) != MaxFileBytes {
		t.Fatalf("pad %d", len(pad))
	}
	for i := 0; i < 8; i++ {
		name := "t" + itoa(i) + ".yml"
		if err := os.WriteFile(filepath.Join(dir, name), pad, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "z.yml"), []byte("on: push\njobs: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, errs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 {
		t.Fatalf("parsed %d", len(got))
	}
	if len(errs) != 1 || !errors.Is(errs[0], ErrTotal) {
		t.Fatalf("errs %#v", errs)
	}
}

func TestLoadDirTooManyFiles(t *testing.T) {
	dir := t.TempDir()
	body := []byte("on: push\njobs: {}\n")
	for i := 0; i < MaxFiles+1; i++ {
		name := "a" + pad3(i) + ".yml"
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, errs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxFiles {
		t.Fatalf("parsed %d", len(got))
	}
	if len(errs) != 1 || !errors.Is(errs[0], ErrTooMany) {
		t.Fatalf("errs %#v", errs)
	}
}

func TestParseRejectsOversizedBuffer(t *testing.T) {
	_, err := Parse("ci.yml", bytes.Repeat([]byte("a"), MaxFileBytes+1))
	if !errors.Is(err, ErrTooBig) {
		t.Fatalf("got %v", err)
	}
}

func TestParseRejectsDepth(t *testing.T) {
	src := "1"
	for i := 0; i < MaxDepth+8; i++ {
		src = "a: {" + src + "}"
	}
	_, err := Parse("ci.yml", []byte(src+"\n"))
	if !errors.Is(err, ErrDepth) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadDirRejectsSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "workflows", "ci.yml"), []byte("on: push\njobs: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDir(filepath.Join(root, "link", "workflows")); err == nil {
		t.Fatal("expected a symlink path component to fail")
	}
}

func TestLoadDirStopsAfterTotalBudgetOfOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	body := bytes.Repeat([]byte("a"), MaxFileBytes+1)
	for i := 0; i < 12; i++ {
		name := "b" + pad3(i) + ".yml"
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, errs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != MaxTotalBytes/MaxFileBytes {
		t.Fatalf("errs %d, want %d", len(errs), MaxTotalBytes/MaxFileBytes)
	}
	for _, fe := range errs {
		if !errors.Is(fe, ErrTooBig) {
			t.Fatalf("err %v", fe)
		}
	}
}

func TestDisplayPathRejectsControlCharacter(t *testing.T) {
	if _, err := Parse("ci\n.yml", []byte("on: push\njobs: {}\n")); err == nil {
		t.Fatal("expected a newline in the path to fail")
	}
}

func TestDisplayPathRejectsTraversal(t *testing.T) {
	if _, err := Parse("../ci.yml", []byte("on: push\n")); err == nil {
		t.Fatal("expected traversal path to fail")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func pad3(n int) string {
	s := itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}
