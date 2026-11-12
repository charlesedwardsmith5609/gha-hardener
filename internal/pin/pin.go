// Package pin resolves action tags and rewrites workflow files to commit SHAs.
// The calling goroutine owns the lockfile value and any HTTP client.
package pin

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gha-hardener/internal/workflow"
)

const DefaultAPI = "https://api.github.com"

// Pin is one repository ref pinned to a commit.
type Pin struct {
	SHA        string `json:"sha"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
}

// Lock is a gha-pins.json document.
type Lock struct {
	Version int            `json:"version"`
	Pins    map[string]Pin `json:"pins"`
}

// Read parses a lockfile. Keys must be the exact lowercase schema.
func Read(path string) (*Lock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	if len(buf) > 1<<20 {
		return nil, errors.New("lockfile exceeds 1 MiB")
	}
	return parseLock(buf)
}

func parseLock(buf []byte) (*Lock, error) {
	dec := json.NewDecoder(bytes.NewReader(buf))
	var top map[string]json.RawMessage
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("lockfile has trailing JSON")
	}
	if err := exactKeys(top, "version", "pins"); err != nil {
		return nil, err
	}
	var version int
	if err := json.Unmarshal(top["version"], &version); err != nil {
		return nil, fmt.Errorf("parse lockfile version: %w", err)
	}
	if version != 1 {
		return nil, fmt.Errorf("lockfile version %d", version)
	}
	var rawPins map[string]json.RawMessage
	if err := json.Unmarshal(top["pins"], &rawPins); err != nil {
		return nil, fmt.Errorf("parse lockfile pins: %w", err)
	}
	lock := &Lock{Version: 1, Pins: make(map[string]Pin, len(rawPins))}
	for key, raw := range rawPins {
		var fields map[string]json.RawMessage
		if _, _, _, got, ok := splitUses(key); !ok || got != key {
			return nil, fmt.Errorf("pin key %q is not a repository ref", key)
		}
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, fmt.Errorf("pin %q: %w", key, err)
		}
		if err := exactKeys(fields, "sha", "repository", "ref"); err != nil {
			return nil, fmt.Errorf("pin %q: %w", key, err)
		}
		var p Pin
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("pin %q: %w", key, err)
		}
		if p.Repository+"@"+p.Ref != key {
			return nil, fmt.Errorf("pin key %q does not match repository and ref", key)
		}
		if !shaPattern.MatchString(p.SHA) {
			return nil, fmt.Errorf("pin %q has a bad sha", key)
		}
		lock.Pins[key] = p
	}
	return lock, nil
}

func exactKeys(m map[string]json.RawMessage, want ...string) error {
	if len(m) != len(want) {
		return errors.New("lockfile has unexpected fields")
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("lockfile missing %q", k)
		}
	}
	return nil
}

// Write stores the lockfile atomically. An existing file is replaced only
// after the new bytes are complete.
func Write(path string, lock *Lock) error {
	if lock.Version != 1 {
		return errors.New("lockfile version must be 1")
	}
	body, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	dir := "."
	if i := strings.LastIndex(path, string(os.PathSeparator)); i >= 0 {
		dir = path[:i]
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, fmt.Sprintf(".gha-pins-%x-*", rnd))
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// Apply rewrites workflow files in dir using lock. It does not use the network.
func Apply(dir string, lock *Lock) error {
	return workflow.Visit(dir, func(name string, data []byte) ([]byte, error) {
		wf, err := workflow.Parse(name, data)
		if err != nil {
			return nil, err
		}
		return Rewrite(data, wf, lock)
	})
}
