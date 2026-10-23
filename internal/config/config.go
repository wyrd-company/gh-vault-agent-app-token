// Package config loads the login → GitHub App mapping.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultTransitMount = "transit"
	SignerTransit       = "transit"
	SignerAzureKeyVault = "azure-key-vault"
)

// AzureKeyVault configures remote signing with an imported RSA key.
type AzureKeyVault struct {
	VaultURL   string `yaml:"vault_url"`
	KeyName    string `yaml:"key_name"`
	KeyVersion string `yaml:"key_version"`
	Credential string `yaml:"credential"`
}

var keyNamePattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,127}$`)
var keyVersionPattern = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

func (a *AzureKeyVault) validate() error {
	u, err := url.Parse(a.VaultURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("vault_url must be an HTTPS vault URL without credentials, a path, query, or fragment")
	}
	if !keyNamePattern.MatchString(a.KeyName) {
		return fmt.Errorf("key_name must contain 1-127 letters, digits, or hyphens")
	}
	if a.KeyVersion != "" && !keyVersionPattern.MatchString(a.KeyVersion) {
		return fmt.Errorf("key_version must contain only letters and digits")
	}
	switch a.Credential {
	case "", "default", "azure-cli", "managed-identity", "workload-identity":
	default:
		return fmt.Errorf("credential must be default, azure-cli, managed-identity, or workload-identity")
	}
	return nil
}

// App describes one GitHub App whose private key lives in a remote signing backend.
type App struct {
	Signer        string           `yaml:"signer"`
	AzureKeyVault *AzureKeyVault   `yaml:"azure_key_vault"`
	AppID         int64            `yaml:"app_id"`
	TransitKey    string           `yaml:"transit_key"`
	Installations map[string]int64 `yaml:"installations"`
}

// Config is the on-disk configuration file.
type Config struct {
	AgentAddr    string `yaml:"agent_addr"`
	TransitMount string `yaml:"transit_mount"`
	// Harnesses maps a harness name (claude, codex, cursor, pi) to the login
	// used when that harness's environment marker is set.
	Harnesses map[string]string `yaml:"harnesses"`
	Apps      map[string]*App   `yaml:"apps"`

	// Path is the file the config was loaded from.
	Path string `yaml:"-"`
}

// Candidates returns the config file locations in lookup order.
func Candidates(getenv func(string) string) []string {
	var out []string
	if p := getenv("GH_VAULT_APP_TOKEN_CONFIG"); p != "" {
		out = append(out, p)
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		out = append(out, filepath.Join(x, "gh-vault-agent-app-token", "config.yml"))
	}
	if h := homeDir(getenv); h != "" {
		out = append(out, filepath.Join(h, ".config", "gh-vault-agent-app-token", "config.yml"))
	}
	return out
}

func homeDir(getenv func(string) string) string {
	if h := getenv("HOME"); h != "" {
		return h
	}
	if h := getenv("USERPROFILE"); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

// Load reads the first config file that exists. An explicitly named
// $GH_VAULT_APP_TOKEN_CONFIG that does not exist is an error rather than
// silently falling through.
func Load(getenv func(string) string) (*Config, error) {
	explicit := getenv("GH_VAULT_APP_TOKEN_CONFIG")
	cands := Candidates(getenv)
	for _, p := range cands {
		data, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p != explicit {
				continue
			}
			return nil, fmt.Errorf("reading config %s: %w", p, err)
		}
		c, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("parsing config %s: %w", p, err)
		}
		c.Path = p
		return c, nil
	}
	return nil, fmt.Errorf("no config file found (looked in %s)", strings.Join(cands, ", "))
}

// Parse decodes and validates a config document.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.TransitMount == "" {
		c.TransitMount = DefaultTransitMount
	}
	c.TransitMount = strings.Trim(c.TransitMount, "/")
	for login, a := range c.Apps {
		if a == nil {
			return nil, fmt.Errorf("apps.%s: empty entry", login)
		}
		if a.AppID <= 0 {
			return nil, fmt.Errorf("apps.%s: app_id is required", login)
		}
		if a.Signer == "" {
			a.Signer = SignerTransit
		}
		switch a.Signer {
		case SignerTransit:
			if a.TransitKey == "" {
				return nil, fmt.Errorf("apps.%s: transit_key is required", login)
			}
			if a.AzureKeyVault != nil {
				return nil, fmt.Errorf("apps.%s: azure_key_vault requires signer: azure-key-vault", login)
			}
		case SignerAzureKeyVault:
			if a.AzureKeyVault == nil {
				return nil, fmt.Errorf("apps.%s: azure_key_vault is required", login)
			}
			if a.TransitKey != "" {
				return nil, fmt.Errorf("apps.%s: transit_key cannot be used with signer: azure-key-vault", login)
			}
			if err := a.AzureKeyVault.validate(); err != nil {
				return nil, fmt.Errorf("apps.%s.azure_key_vault: %w", login, err)
			}
		default:
			return nil, fmt.Errorf("apps.%s: unknown signer %q", login, a.Signer)
		}
	}
	return &c, nil
}

// App returns the app configured for login.
func (c *Config) App(login string) (*App, bool) {
	a, ok := c.Apps[login]
	return a, ok
}

// Logins returns the configured logins, sorted.
func (c *Config) Logins() []string {
	out := make([]string, 0, len(c.Apps))
	for l := range c.Apps {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Installation returns the static installation id for owner, matched
// case-insensitively.
func (a *App) Installation(owner string) (int64, bool) {
	for o, id := range a.Installations {
		if strings.EqualFold(o, owner) {
			return id, true
		}
	}
	return 0, false
}
