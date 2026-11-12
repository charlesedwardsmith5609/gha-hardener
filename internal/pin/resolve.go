package pin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"time"

	"gha-hardener/internal/workflow"
)

const maxBody = 1 << 20

// Resolve looks up every unpinned action ref. It performs one GET per ref
// on the calling goroutine and returns the lockfile to write. It does not
// write the file itself.
func Resolve(dir, apiBase string, timeout time.Duration) (*Lock, error) {
	if timeout < time.Second || timeout > 30*time.Second {
		return nil, errors.New("timeout must be from 1s to 30s")
	}
	base, err := parseBase(apiBase)
	if err != nil {
		return nil, err
	}
	wfs, ferrs, err := workflow.LoadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(ferrs) > 0 {
		return nil, ferrs[0]
	}
	type item struct {
		owner, repo, ref, key string
	}
	seen := map[string]struct{}{}
	var items []item
	var bad error
	consider := func(uses string) {
		if bad != nil || skippedUses(uses) {
			return
		}
		owner, repo, ref, key, ok := splitUses(uses)
		if !ok {
			bad = fmt.Errorf("uses %q is not a pinnable action ref", uses)
			return
		}
		if shaPattern.MatchString(ref) {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		items = append(items, item{owner, repo, ref, key})
	}
	for _, wf := range wfs {
		for _, job := range wf.Jobs {
			consider(job.Uses)
			for _, step := range job.Steps {
				consider(step.Uses)
			}
		}
	}
	if bad != nil {
		return nil, bad
	}
	if len(items) > 128 {
		return nil, errors.New("more than 128 action refs")
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
	if len(items) == 0 {
		return &Lock{Version: 1, Pins: map[string]Pin{}}, nil
	}

	budget := timeout * time.Duration(len(items))
	if budget > 2*time.Minute {
		budget = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if dl, ok := ctx.Deadline(); ok {
				_ = c.SetDeadline(dl)
			}
			return c, nil
		},
		// CheckRedirect is set on the client.
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := validateBase(req.URL); err != nil {
				return err
			}
			return errors.New("redirects are not followed")
		},
	}

	lock := &Lock{Version: 1, Pins: make(map[string]Pin, len(items))}
	for _, it := range items {
		u, err := commitURL(base, it.owner, it.repo, it.ref)
		if err != nil {
			return nil, err
		}
		sha, err := getSHA(ctx, client, u, timeout)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", it.key, err)
		}
		lock.Pins[it.key] = Pin{SHA: sha, Repository: it.owner + "/" + it.repo, Ref: it.ref}
	}
	return lock, nil
}

func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("api base: %w", err)
	}
	if err := validateBase(u); err != nil {
		return nil, err
	}
	return u, nil
}

func validateBase(u *url.URL) error {
	if u == nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("api URL must not include userinfo, a query, or a fragment")
	}
	host := u.Hostname()
	if host == "api.github.com" && u.Scheme == "https" && u.Port() == "" {
		return nil
	}
	if host == "127.0.0.1" && u.Scheme == "http" {
		return nil
	}
	return fmt.Errorf("api host %q is not allowlisted", host)
}

func commitURL(base *url.URL, owner, repo, ref string) (*url.URL, error) {
	escOwner := url.PathEscape(owner)
	escRepo := url.PathEscape(repo)
	escRef := url.PathEscape(ref)
	rawPath := "/repos/" + escOwner + "/" + escRepo + "/commits/" + escRef
	u := *base
	u.Path = "/repos/" + owner + "/" + repo + "/commits/" + ref
	u.RawPath = rawPath
	u.RawQuery = ""
	u.Fragment = ""
	if u.EscapedPath() != rawPath {
		return nil, errors.New("refused to build commit URL")
	}
	parts := splitPath(u.EscapedPath())
	if len(parts) != 5 || parts[0] != "repos" || parts[1] != escOwner || parts[2] != escRepo || parts[3] != "commits" || parts[4] != escRef {
		return nil, errors.New("refused to build commit URL")
	}
	return &u, nil
}

func splitPath(p string) []string {
	if len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	if p == "" {
		return nil
	}
	return splitSlash(p)
}

func splitSlash(p string) []string {
	var out []string
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			out = append(out, p[start:i])
			start = i + 1
		}
	}
	out = append(out, p[start:])
	return out
}

func getSHA(parent context.Context, client *http.Client, u *url.URL, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.Scheme+"://"+u.Host+"/", nil)
	if err != nil {
		return "", err
	}
	clone := *u
	req.URL = &clone
	req.Host = clone.Host
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "gha-hardener")
	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api status %d", resp.StatusCode)
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return "", err
	}
	if len(buf) > maxBody {
		return "", errors.New("response exceeds 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	var payload struct {
		SHA string `json:"sha"`
	}
	if err := dec.Decode(&payload); err != nil {
		return "", fmt.Errorf("response json: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return "", errors.New("response has trailing JSON")
	}
	if !shaPattern.MatchString(payload.SHA) {
		return "", errors.New("response sha is not 40 lowercase hex characters")
	}
	return payload.SHA, nil
}
