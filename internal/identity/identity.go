// Package identity resolves which App (login) and which installation owner
// a token is minted for.
package identity

import (
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

// Marker is a harness environment marker.
type Marker struct {
	Env     string // environment variable whose presence identifies the harness
	Harness string // key looked up in the config's harnesses map
}

// Markers are checked in this order.
var Markers = []Marker{
	{"CLAUDECODE", "claude"},
	{"CODEX_THREAD_ID", "codex"},
	{"CURSOR_AGENT", "cursor"},
	{"PI_CODING_AGENT", "pi"},
	{"COPILOT_CLI", "copilot"},
	{"ANTIGRAVITY_AGENT", "antigravity"},
}

var ErrNoIdentity = errors.New("no agent identity (set GH_LOGIN or --login)")

// ResolveLogin picks the login: flag, GH_LOGIN, then harness markers mapped
// through harnesses (harness name → login).
func ResolveLogin(flagLogin string, getenv func(string) string, harnesses map[string]string) (string, error) {
	if flagLogin != "" {
		return flagLogin, nil
	}
	if l := getenv("GH_LOGIN"); l != "" {
		return l, nil
	}
	for _, m := range Markers {
		if getenv(m.Env) == "" {
			continue
		}
		if l := harnesses[m.Harness]; l != "" {
			return l, nil
		}
		return "", fmt.Errorf("%s is set but no login is mapped for harness '%s' (set harnesses.%s in config, GH_LOGIN, or --login)", m.Env, m.Harness, m.Harness)
	}
	return "", ErrNoIdentity
}

var ErrNoOwner = errors.New("can't determine target org (use --owner, --repo, or set GH_OWNER)")

// Target is the installation owner and the GitHub host it lives on.
type Target struct {
	Host  string // "" for github.com, else a GitHub Enterprise Server host
	Owner string
}

// NormalizeHost lowercases host and maps github.com to "".
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "github.com" || h == "api.github.com" {
		return ""
	}
	return h
}

// ParseRepo splits OWNER/REPO or HOST/OWNER/REPO. Host is "" when absent.
func ParseRepo(repo string) (host, owner string, err error) {
	parts := strings.Split(strings.Trim(repo, "/"), "/")
	switch {
	case len(parts) == 2 && parts[0] != "" && parts[1] != "":
		return "", parts[0], nil
	case len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != "":
		return parts[0], parts[1], nil
	}
	return "", "", fmt.Errorf("invalid repository %q (want [HOST/]OWNER/REPO)", repo)
}

// ResolveTarget picks the installation owner: flag, --repo, GH_REPO,
// GH_OWNER, GH_ORG, then the origin remote of the git repo containing cwd.
// The host is flagHost (a command's --hostname) if set, else the host of a
// host-qualified --repo or GH_REPO, else GH_HOST.
func ResolveTarget(flagOwner, flagRepo, flagHost string, getenv func(string) string, originURL func() string) (Target, error) {
	t, err := resolveTarget(flagOwner, flagRepo, flagHost, getenv, originURL)
	if err == nil && flagHost != "" {
		t.Host = NormalizeHost(flagHost)
	}
	return t, err
}

func resolveTarget(flagOwner, flagRepo, flagHost string, getenv func(string) string, originURL func() string) (Target, error) {
	ghHost := NormalizeHost(getenv("GH_HOST"))
	if flagHost != "" {
		ghHost = NormalizeHost(flagHost)
	}
	if flagOwner != "" {
		return Target{ghHost, flagOwner}, nil
	}
	for _, r := range []struct{ name, val string }{{"--repo", flagRepo}, {"GH_REPO", getenv("GH_REPO")}} {
		if r.val == "" {
			continue
		}
		host, owner, err := ParseRepo(r.val)
		if err != nil {
			return Target{}, fmt.Errorf("%s: %w", r.name, err)
		}
		if host == "" {
			host = ghHost
		}
		return Target{NormalizeHost(host), owner}, nil
	}
	for _, k := range []string{"GH_OWNER", "GH_ORG"} {
		if v := getenv(k); v != "" {
			return Target{ghHost, v}, nil
		}
	}
	if originURL != nil {
		if u := originURL(); u != "" {
			if o, ok := OwnerFromRemote(u, ghHost); ok {
				return Target{ghHost, o}, nil
			}
		}
	}
	return Target{}, ErrNoOwner
}

// GitOrigin returns the origin remote URL of the repo containing dir, or "".
func GitOrigin(dir string) string {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// OwnerFromRemote parses a GitHub remote URL (https, ssh://, scp-style) and
// returns its owner. Only github.com (and ssh.github.com) or ghHost match.
func OwnerFromRemote(remote, ghHost string) (string, bool) {
	remote = strings.TrimSpace(remote)
	var host, path string
	if strings.Contains(remote, "://") {
		u, err := url.Parse(remote)
		if err != nil {
			return "", false
		}
		switch u.Scheme {
		case "https", "http", "ssh", "git", "git+ssh", "ssh+git":
		default:
			return "", false
		}
		host, path = u.Hostname(), u.Path
	} else {
		// scp-like: [user@]host:owner/repo
		at := strings.LastIndex(remote, "@")
		rest := remote[at+1:]
		colon := strings.Index(rest, ":")
		if colon <= 0 {
			return "", false
		}
		host, path = rest[:colon], rest[colon+1:]
	}
	if !hostMatches(host, ghHost) {
		return "", false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || strings.TrimSuffix(parts[1], ".git") == "" {
		return "", false
	}
	return parts[0], true
}

func hostMatches(host, ghHost string) bool {
	host = strings.ToLower(host)
	if host == "github.com" || host == "ssh.github.com" || host == "www.github.com" {
		return true
	}
	if ghHost == "" {
		return false
	}
	ghHost = strings.ToLower(ghHost)
	if i := strings.Index(ghHost, ":"); i >= 0 {
		ghHost = ghHost[:i]
	}
	return host == ghHost
}
