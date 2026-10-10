package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `
agent_addr: http://127.0.0.1:9200
harnesses:
  claude: one-app[bot]
apps:
  one-app[bot]:
    app_id: 111
    transit_key: gh-app-one
    installations:
      Acme: 999
  two-app[bot]:
    app_id: 222
    transit_key: gh-app-two
`

func TestParse(t *testing.T) {
	c, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentAddr != "http://127.0.0.1:9200" || c.TransitMount != "transit" {
		t.Fatalf("got %+v", c)
	}
	a, ok := c.App("one-app[bot]")
	if !ok || a.AppID != 111 || a.TransitKey != "gh-app-one" {
		t.Fatalf("app = %+v", a)
	}
	if id, ok := a.Installation("acme"); !ok || id != 999 {
		t.Fatalf("installation lookup must be case-insensitive: %d %v", id, ok)
	}
	if _, ok := a.Installation("other"); ok {
		t.Fatal("unexpected installation")
	}
	if got := strings.Join(c.Logins(), ","); got != "one-app[bot],two-app[bot]" {
		t.Fatalf("logins = %s", got)
	}
	if c.Harnesses["claude"] != "one-app[bot]" {
		t.Fatalf("harnesses = %v", c.Harnesses)
	}
}

func TestParseMount(t *testing.T) {
	c, err := Parse([]byte("transit_mount: /sec/transit/\napps: {}\n"))
	if err != nil || c.TransitMount != "sec/transit" {
		t.Fatalf("%v %q", err, c.TransitMount)
	}
}

func TestParseValidation(t *testing.T) {
	for _, doc := range []string{
		"apps:\n  a[bot]:\n    transit_key: k\n",
		"apps:\n  a[bot]:\n    app_id: 1\n",
		"apps:\n  a[bot]:\n",
		"apps: [",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("expected error for %q", doc)
		}
	}
}

func TestLoadOrder(t *testing.T) {
	dir := t.TempDir()
	write := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	explicit := filepath.Join(dir, "explicit.yml")
	xdg := filepath.Join(dir, "xdg")
	home := filepath.Join(dir, "home")
	write(explicit, "agent_addr: explicit\n")
	write(filepath.Join(xdg, "gh-vault-agent-app-token", "config.yml"), "agent_addr: xdg\n")
	write(filepath.Join(home, ".config", "gh-vault-agent-app-token", "config.yml"), "agent_addr: home\n")

	env := map[string]string{"GH_VAULT_APP_TOKEN_CONFIG": explicit, "XDG_CONFIG_HOME": xdg, "HOME": home}
	get := func(k string) string { return env[k] }
	for _, want := range []string{"explicit", "xdg", "home"} {
		c, err := Load(get)
		if err != nil || c.AgentAddr != want {
			t.Fatalf("want %s, got %+v %v", want, c, err)
		}
		switch want {
		case "explicit":
			delete(env, "GH_VAULT_APP_TOKEN_CONFIG")
		case "xdg":
			delete(env, "XDG_CONFIG_HOME")
		}
	}

	env = map[string]string{"GH_VAULT_APP_TOKEN_CONFIG": filepath.Join(dir, "missing.yml"), "HOME": home}
	if _, err := Load(get); err == nil {
		t.Fatal("missing explicit config must be an error")
	}
	env = map[string]string{"HOME": filepath.Join(dir, "nohome")}
	if _, err := Load(get); err == nil || !strings.Contains(err.Error(), "no config file found") {
		t.Fatalf("got %v", err)
	}
}
