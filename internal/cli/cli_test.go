package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/gh-vault-agent-app-token/internal/testutil"
)

const testLogin = "test-app[bot]"

type harness struct {
	t       *testing.T
	env     map[string]string
	transit *testutil.FakeTransit
	gh      *testutil.FakeGitHub
	origin  string
}

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func newHarness(t *testing.T, extraConfig string) *harness {
	t.Helper()
	keyOnce.Do(func() { testKey, _ = rsa.GenerateKey(rand.Reader, 2048) })
	dir := t.TempDir()
	cfg := fmt.Sprintf(`harnesses:
  claude: %[1]s
apps:
  %[1]s:
    app_id: 1001
    transit_key: gh-app-test
%[2]s`, testLogin, extraConfig)
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t}
	h.transit = testutil.NewFakeTransit(t, "transit", map[string]*rsa.PrivateKey{"gh-app-test": testKey})
	h.gh = testutil.NewFakeGitHub(t, &testKey.PublicKey, 1001, map[string]int64{"other-org": 5, "Acme": 77, "third": 9})
	h.env = map[string]string{
		"HOME":                          dir,
		"XDG_CACHE_HOME":                filepath.Join(dir, "cache"),
		"GH_VAULT_APP_TOKEN_CONFIG":     cfgPath,
		"GH_VAULT_APP_TOKEN_AGENT_ADDR": h.transit.URL,
	}
	return h
}

func (h *harness) run(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = Run(Env{
		Args:          args,
		Getenv:        func(k string) string { return h.env[k] },
		Stdout:        &out,
		Stderr:        &errb,
		OriginURL:     func() string { return h.origin },
		GitHubBaseURL: h.gh.URL,
	})
	return code, out.String(), errb.String()
}

func TestMintAndCache(t *testing.T) {
	h := newHarness(t, "")
	h.env["CLAUDECODE"] = "1"
	code, out, errs := h.run("--owner", "acme")
	if code != 0 || out != "ghs_fake_77_1" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
	if h.gh.LastIID != 77 {
		t.Fatalf("picked installation %d, want 77 (matched by login, not index)", h.gh.LastIID)
	}
	// Cached: no new token, no Transit call.
	signs := h.transit.Calls.Load()
	code, out, _ = h.run("--owner", "ACME")
	if code != 0 || out != "ghs_fake_77_1" || h.gh.TokenCalls != 1 || h.transit.Calls.Load() != signs {
		t.Fatalf("cache not used: out=%q tokenCalls=%d", out, h.gh.TokenCalls)
	}
	// --force re-mints.
	code, out, _ = h.run("--owner", "acme", "--force")
	if code != 0 || out != "ghs_fake_77_2" {
		t.Fatalf("force: code=%d out=%q", code, out)
	}
	// Cache file content and permissions.
	p := filepath.Join(h.env["XDG_CACHE_HOME"], "gh-vault-agent-app-token", "test-app_bot___acme")
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "\tghs_fake_77_2\t77\t1001\n") {
		t.Fatalf("cache file %q %v", b, err)
	}
}

func TestExpiredCacheRemints(t *testing.T) {
	h := newHarness(t, "")
	h.env["GH_LOGIN"] = testLogin
	h.gh.TokenTTL = 4 * time.Minute // under the 300 s skew
	h.run("--owner", "acme")
	code, out, _ := h.run("--owner", "acme")
	if code != 0 || out != "ghs_fake_77_2" {
		t.Fatalf("expected re-mint inside skew window, got %d %q", code, out)
	}
}

func TestCacheScopedByHostAndApp(t *testing.T) {
	h := newHarness(t, "")
	h.env["GH_LOGIN"] = testLogin
	if code, out, _ := h.run("--owner", "acme"); code != 0 || out != "ghs_fake_77_1" {
		t.Fatalf("code=%d out=%q", code, out)
	}
	// Same login/owner on another host must not reuse the github.com token.
	h.env["GH_HOST"] = "ghe.example.com"
	if code, out, _ := h.run("--owner", "acme"); code != 0 || out != "ghs_fake_77_2" {
		t.Fatalf("GHES reused github.com token: code=%d out=%q", code, out)
	}
	if code, out, _ := h.run("--repo", "github.com/acme/x"); code != 0 || out != "ghs_fake_77_1" {
		t.Fatalf("host-qualified --repo should select the github.com entry: code=%d out=%q", code, out)
	}
	// An entry minted by a different App is not reused.
	delete(h.env, "GH_HOST")
	p := filepath.Join(h.env["XDG_CACHE_HOME"], "gh-vault-agent-app-token", "test-app_bot___acme")
	exp := time.Now().Add(time.Hour).Unix()
	if err := os.WriteFile(p, []byte(fmt.Sprintf("%d\tghs_other_app\t77\t999\n", exp)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := h.run("--owner", "acme"); code != 0 || out != "ghs_fake_77_3" {
		t.Fatalf("token from another App reused: code=%d out=%q", code, out)
	}
}

func TestGHRepo(t *testing.T) {
	h := newHarness(t, "")
	h.env["GH_LOGIN"] = testLogin
	h.env["GH_REPO"] = "third/widgets"
	h.origin = "git@github.com:acme/widgets.git"
	if code, out, errs := h.run(); code != 0 || out != "ghs_fake_9_1" {
		t.Fatalf("GH_REPO must beat origin: code=%d out=%q err=%s", code, out, errs)
	}
}

func TestJSON(t *testing.T) {
	h := newHarness(t, "")
	h.env["GH_LOGIN"] = testLogin
	h.origin = "git@github.com:third/repo.git"
	for i := 0; i < 2; i++ { // fresh, then cached
		code, out, errs := h.run("--json")
		if code != 0 {
			t.Fatalf("code=%d err=%s", code, errs)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatal(err)
		}
		if _, err := time.Parse(time.RFC3339, m["expires_at"].(string)); err != nil {
			t.Fatal(err)
		}
		if m["token"] != "ghs_fake_9_1" || m["login"] != testLogin || m["owner"] != "third" || m["installation_id"] != float64(9) {
			t.Fatalf("json = %s", out)
		}
	}
}

func TestStaticInstallationSkipsLookup(t *testing.T) {
	h := newHarness(t, "    installations:\n      Acme: 4242\n")
	h.env["GH_LOGIN"] = testLogin
	code, out, errs := h.run("--repo", "acme/widgets")
	if code != 0 || out != "ghs_fake_4242_1" || h.gh.ListCalls != 0 {
		t.Fatalf("code=%d out=%q err=%q list=%d", code, out, errs, h.gh.ListCalls)
	}
}

func TestPaginatedLookup(t *testing.T) {
	h := newHarness(t, "")
	h.env["GH_LOGIN"] = testLogin
	h.gh.PageSize = 1
	code, out, _ := h.run("--owner", "acme") // id 77 is on page 3 of 3
	if code != 0 || out != "ghs_fake_77_1" || h.gh.ListCalls != 3 {
		t.Fatalf("code=%d out=%q list=%d", code, out, h.gh.ListCalls)
	}
}

func TestPrintJWT(t *testing.T) {
	h := newHarness(t, "")
	code, out, _ := h.run("--print-jwt", "--login", testLogin)
	if code != 0 || strings.Count(out, ".") != 2 || strings.HasSuffix(out, "\n") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if err := testutil.VerifyJWT(&testKey.PublicKey, 1001, out); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(h.env["XDG_CACHE_HOME"], "gh-vault-agent-app-token"))
	if len(entries) != 0 {
		t.Fatalf("JWT must not be cached; found %d entries", len(entries))
	}
}

func TestList(t *testing.T) {
	h := newHarness(t, "")
	code, out, _ := h.run("--list")
	if code != 0 || !strings.Contains(out, testLogin) || !strings.Contains(out, "transit/gh-app-test") || !strings.Contains(out, "claude") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestErrors(t *testing.T) {
	cases := []struct {
		name  string
		setup func(h *harness)
		args  []string
		code  int
		msg   string
	}{
		{"no identity", nil, []string{"--owner", "acme"}, 2, "no agent identity (set GH_LOGIN or --login)"},
		{"unknown login", func(h *harness) { h.env["GH_LOGIN"] = "nobody[bot]" }, []string{"--owner", "acme"}, 2, "no app configured for 'nobody[bot]'"},
		{"marker unmapped", func(h *harness) { h.env["CODEX_THREAD_ID"] = "x" }, []string{"--owner", "acme"}, 2, "harnesses.codex"},
		{"no owner", func(h *harness) { h.env["GH_LOGIN"] = testLogin }, nil, 2, "can't determine target org (use --owner, --repo, or set GH_OWNER)"},
		{"not installed", func(h *harness) { h.env["GH_LOGIN"] = testLogin }, []string{"--owner", "nope"}, 2, "app for 'test-app[bot]' not installed on 'nope'"},
		{"bad flag", nil, []string{"--bogus"}, 2, "flag provided but not defined"},
		{"transit denied", func(h *harness) { h.env["GH_LOGIN"] = testLogin; h.transit.RequireToken = "s.x" }, []string{"--owner", "acme"}, 3, "HTTP 403: permission denied"},
		{"transit down", func(h *harness) {
			h.env["GH_LOGIN"] = testLogin
			h.env["GH_VAULT_APP_TOKEN_AGENT_ADDR"] = "http://127.0.0.1:1"
		}, []string{"--owner", "acme"}, 3, "unreachable"},
		{"github error", func(h *harness) { h.env["GH_LOGIN"] = testLogin; h.gh.FailToken = 404 }, []string{"--owner", "acme"}, 4, "HTTP 404: Integration not found"},
		{"no config", func(h *harness) { h.env["GH_VAULT_APP_TOKEN_CONFIG"] = "/nonexistent.yml" }, []string{"--list"}, 2, "config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "")
			if tc.setup != nil {
				tc.setup(h)
			}
			code, out, errs := h.run(tc.args...)
			if code != tc.code || out != "" || !strings.HasPrefix(errs, "gh vault-agent-app-token: ") || !strings.Contains(errs, tc.msg) {
				t.Fatalf("code=%d out=%q err=%q", code, out, errs)
			}
			if strings.Contains(errs, "ghs_") {
				t.Fatal("token leaked on error path")
			}
		})
	}
}

func TestBaoTokenSent(t *testing.T) {
	h := newHarness(t, "")
	h.env["GH_LOGIN"] = testLogin
	h.env["BAO_TOKEN"] = "s.direct"
	h.transit.RequireToken = "s.direct"
	if code, _, errs := h.run("--owner", "acme"); code != 0 {
		t.Fatalf("code=%d err=%s", code, errs)
	}
}

func TestVerboseRedacts(t *testing.T) {
	h := newHarness(t, "")
	h.env["GH_LOGIN"] = testLogin
	h.env["GH_DEBUG"] = "1"
	h.env["VAULT_TOKEN"] = "s.supersecret"
	h.transit.RequireToken = "s.supersecret"
	code, out, errs := h.run("--owner", "acme")
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errs)
	}
	if !strings.Contains(errs, "/app/installations") || !strings.Contains(errs, "[REDACTED]") {
		t.Fatalf("expected request log, got %q", errs)
	}
	if strings.Contains(errs, out) || strings.Contains(errs, "s.supersecret") || strings.Contains(errs, "eyJ") {
		t.Fatalf("secret in debug log: %q", errs)
	}
}
