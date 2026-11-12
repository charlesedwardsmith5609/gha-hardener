package pin

import (
	"regexp"
	"strings"
	"unicode"
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var segPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)

// skippedUses reports local actions and Docker images, which are not pinned.
func skippedUses(uses string) bool {
	return uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://")
}

// splitUses returns the pin key for a uses value.
// ok is false for local actions, docker images, and values that are not
// a GitHub repository ref.
func splitUses(uses string) (owner, repo, ref, key string, ok bool) {
	if skippedUses(uses) {
		return "", "", "", "", false
	}
	ref = "HEAD"
	repoPath := uses
	if i := strings.LastIndex(uses, "@"); i >= 0 {
		repoPath = uses[:i]
		ref = uses[i+1:]
	}
	parts := strings.Split(repoPath, "/")
	if len(parts) < 2 {
		return "", "", "", "", false
	}
	owner, repo = parts[0], parts[1]
	if !segPattern.MatchString(owner) || !segPattern.MatchString(repo) {
		return "", "", "", "", false
	}
	if owner == "." || owner == ".." || repo == "." || repo == ".." {
		return "", "", "", "", false
	}
	if !validRef(ref) {
		return "", "", "", "", false
	}
	return owner, repo, ref, owner + "/" + repo + "@" + ref, true
}

func validRef(ref string) bool {
	if ref == "" || len(ref) > 256 {
		return false
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f || r == '\\' || r == '?' || r == '#' || unicode.IsSpace(r) {
			return false
		}
	}
	for _, seg := range strings.Split(ref, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
