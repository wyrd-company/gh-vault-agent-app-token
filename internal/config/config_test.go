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
	if c.Apps["one-app[bot]"].Signer != SignerTransit {
		t.Fatal("existing configs must default to Transit")
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

func TestAzureKeyVaultConfig(t *testing.T) {
	const doc = `apps:
  a[bot]:
    app_id: 1
    signer: azure-key-vault
    azure_key_vault:
      vault_url: https://example.vault.azure.net
      key_name: github-app
      key_version: abc123
      credential: managed-identity
`
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	a := c.Apps["a[bot]"]
	if a.Signer != SignerAzureKeyVault || a.AzureKeyVault.KeyVersion != "abc123" || a.AzureKeyVault.Credential != "managed-identity" {
		t.Fatalf("app = %+v", a)
	}
	for _, tc := range []struct{ old, replacement string }{
		{"signer: azure-key-vault", "signer: unknown"},
		{"signer: azure-key-vault", "signer: transit\n    transit_key: test"},
		{"https://example.vault.azure.net", "http://example.vault.azure.net"},
		{"https://example.vault.azure.net", "https://user:password@example.vault.azure.net"},
		{"https://example.vault.azure.net", "https://example.vault.azure.net/keys/key"},
		{"https://example.vault.azure.net", "https://example.vault.azure.net?secret=value"},
		{"key_name: github-app", "key_name: key/name"},
		{"key_name: github-app", "key_name: ''"},
		{"key_version: abc123", "key_version: a/b"},
		{"credential: managed-identity", "credential: unknown"},
		{"signer: azure-key-vault", "transit_key: old\n    signer: azure-key-vault"},
	} {
		bad := strings.Replace(doc, tc.old, tc.replacement, 1)
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("expected error for %s", bad)
		}
	}
	if _, err := Parse([]byte("apps:\n  a[bot]:\n    app_id: 1\n    signer: azure-key-vault\n")); err == nil {
		t.Fatal("expected missing Azure config error")
	}
	for _, kind := range []string{"default", "azure-cli", "workload-identity", "''"} {
		if _, err := Parse([]byte(strings.Replace(doc, "credential: managed-identity", "credential: "+kind, 1))); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	if _, err := Parse([]byte(strings.ReplaceAll(strings.Replace(doc, "      key_version: abc123\n", "", 1), "https://example.vault.azure.net", "https://example.vault.azure.net/"))); err != nil {
		t.Fatal(err)
	}
}
