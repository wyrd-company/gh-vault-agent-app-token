package identity

import (
	"errors"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolveLoginOrder(t *testing.T) {
	harnesses := map[string]string{
		"claude": "example-claude[bot]",
		"codex":  "example-codex[bot]",
		"cursor": "example-cursor[bot]",
		"pi":     "example-pi[bot]",
	}
	allMarkers := map[string]string{"CLAUDECODE": "1", "CODEX_THREAD_ID": "t", "CURSOR_AGENT": "1", "PI_CODING_AGENT": "1"}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range allMarkers {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name string
		flag string
		env  map[string]string
		want string
	}{
		{"flag wins", "flag[bot]", with(map[string]string{"GH_LOGIN": "env[bot]"}), "flag[bot]"},
		{"GH_LOGIN beats markers", "", with(map[string]string{"GH_LOGIN": "env[bot]"}), "env[bot]"},
		{"CLAUDECODE first", "", allMarkers, "example-claude[bot]"},
		{"codex", "", map[string]string{"CODEX_THREAD_ID": "x", "CURSOR_AGENT": "1", "PI_CODING_AGENT": "1"}, "example-codex[bot]"},
		{"cursor", "", map[string]string{"CURSOR_AGENT": "1", "PI_CODING_AGENT": "1"}, "example-cursor[bot]"},
		{"pi", "", map[string]string{"PI_CODING_AGENT": "1"}, "example-pi[bot]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveLogin(tc.flag, envMap(tc.env), harnesses)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestResolveLoginErrors(t *testing.T) {
	if _, err := ResolveLogin("", envMap(nil), nil); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("want ErrNoIdentity, got %v", err)
	}
	_, err := ResolveLogin("", envMap(map[string]string{"CURSOR_AGENT": "1"}), map[string]string{"claude": "x"})
	if err == nil || !strings.Contains(err.Error(), "harnesses.cursor") {
		t.Fatalf("want unmapped-harness error, got %v", err)
	}
}

func TestResolveOwnerOrder(t *testing.T) {
	origin := func() string { return "git@github.com:from-git/repo.git" }
	tests := []struct {
		name        string
		owner, repo string
		env         map[string]string
		origin      func() string
		want        string
	}{
		{"flag", "flag-o", "repo-o/r", map[string]string{"GH_OWNER": "e"}, origin, "flag-o"},
		{"repo", "", "repo-o/r", map[string]string{"GH_OWNER": "e"}, origin, "repo-o"},
		{"repo with host", "", "ghe.example.com/repo-o/r", nil, origin, "repo-o"},
		{"GH_OWNER", "", "", map[string]string{"GH_OWNER": "owner-env", "GH_ORG": "org-env"}, origin, "owner-env"},
		{"GH_ORG", "", "", map[string]string{"GH_ORG": "org-env"}, origin, "org-env"},
		{"git origin", "", "", nil, origin, "from-git"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveOwner(tc.owner, tc.repo, envMap(tc.env), tc.origin)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	if _, err := ResolveOwner("", "", envMap(nil), func() string { return "" }); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("want ErrNoOwner, got %v", err)
	}
	if _, err := ResolveOwner("", "", envMap(nil), func() string { return "https://gitlab.com/a/b.git" }); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("non-GitHub remote: want ErrNoOwner, got %v", err)
	}
	if _, err := ResolveOwner("", "noslash", envMap(nil), nil); err == nil {
		t.Fatal("want error for malformed --repo")
	}
}

func TestOwnerFromRemote(t *testing.T) {
	tests := []struct {
		url, ghHost, want string
		ok                bool
	}{
		{"https://github.com/acme/widgets.git", "", "acme", true},
		{"https://github.com/acme/widgets", "", "acme", true},
		{"https://github.com/acme/widgets/", "", "acme", true},
		{"https://user:pw@github.com/acme/widgets.git", "", "acme", true},
		{"http://github.com/acme/widgets", "", "acme", true},
		{"git@github.com:acme/widgets.git", "", "acme", true},
		{"github.com:acme/widgets", "", "acme", true},
		{"ssh://git@github.com/acme/widgets.git", "", "acme", true},
		{"ssh://git@ssh.github.com:443/acme/widgets.git", "", "acme", true},
		{"git://github.com/acme/widgets.git", "", "acme", true},
		{"https://GitHub.com/Acme/widgets.git", "", "Acme", true},
		{"https://ghe.example.com/corp/svc.git", "ghe.example.com", "corp", true},
		{"git@ghe.example.com:corp/svc.git", "ghe.example.com", "corp", true},
		{"https://ghe.example.com/corp/svc.git", "", "", false},
		{"https://gitlab.com/acme/widgets.git", "", "", false},
		{"https://github.com/acme", "", "", false},
		{"/local/path/repo", "", "", false},
		{"file:///srv/repo.git", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range tests {
		got, ok := OwnerFromRemote(tc.url, tc.ghHost)
		if ok != tc.ok || got != tc.want {
			t.Errorf("OwnerFromRemote(%q, %q) = %q, %v; want %q, %v", tc.url, tc.ghHost, got, ok, tc.want, tc.ok)
		}
	}
}
