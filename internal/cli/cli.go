/*
---
relationships:
  references: README
---
*/
// Package cli implements the gh vault-agent-app-token command.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/wyrd-company/gh-vault-agent-app-token/internal/azurekeyvault"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/cache"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/config"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/github"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/identity"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/jwt"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/transit"
)

const prog = "gh vault-agent-app-token"

// Exit codes.
const (
	ExitOK      = 0
	ExitUsage   = 2
	ExitSigner  = 3
	ExitTransit = ExitSigner // retained for compatibility
	ExitGitHub  = 4
)

// Env is everything Run needs from the outside world; tests replace parts.
type Env struct {
	Args   []string // without the program name
	Getenv func(string) string
	Stdout io.Writer
	Stderr io.Writer
	Now    func() time.Time
	// OriginURL returns the origin remote of the git repo containing the cwd.
	OriginURL func() string
	// GitHubBaseURL overrides the API root derived from the target host.
	GitHubBaseURL string
	// NewAzureSigner overrides Azure signer construction in tests.
	NewAzureSigner func(*config.AzureKeyVault) (jwt.Signer, error)
}

// Main runs with the real process environment.
func Main() int {
	return Run(Env{
		Args:   os.Args[1:],
		Getenv: os.Getenv,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Now:    time.Now,
		OriginURL: func() string {
			wd, err := os.Getwd()
			if err != nil {
				return ""
			}
			return identity.GitOrigin(wd)
		},
	})
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }

func fail(code int, format string, a ...any) error {
	return &exitError{code, fmt.Errorf(format, a...)}
}

type options struct {
	owner, login, repo, hostname, agentAddr string
	force, json, printJWT, list             bool
	verbose                                 bool
}

const usage = `Usage:
  gh vault-agent-app-token [--owner OWNER] [--login LOGIN] [--repo [HOST/]OWNER/REPO] [--hostname HOST] [--force] [--json]
  gh vault-agent-app-token --print-jwt [--login LOGIN]
  gh vault-agent-app-token --list

Mint a GitHub App installation token, signing the App JWT with a
remote OpenBao/Vault Transit or Azure Key Vault key.

Flags:
`

func parseFlags(args []string, stderr io.Writer) (*options, error) {
	var o options
	fs := flag.NewFlagSet(prog, flag.ContinueOnError)
	// Errors are reported once, prefixed, by Run; usage only on -h.
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.owner, "owner", "", "installation owner (user or org)")
	fs.StringVar(&o.login, "login", "", "App bot login to mint for, e.g. my-app[bot]")
	fs.StringVar(&o.repo, "repo", "", "OWNER/REPO; its owner selects the installation")
	fs.StringVar(&o.repo, "R", "", "shorthand for --repo")
	fs.StringVar(&o.hostname, "hostname", "", "GitHub host to mint for (overrides --repo host and GH_HOST)")
	fs.StringVar(&o.agentAddr, "agent-addr", "", "OpenBao/Vault Agent address")
	fs.BoolVar(&o.force, "force", false, "ignore the token cache")
	fs.BoolVar(&o.json, "json", false, "print token details as JSON")
	fs.BoolVar(&o.printJWT, "print-jwt", false, "print the signed App JWT and exit")
	fs.BoolVar(&o.list, "list", false, "list configured logins and keys")
	fs.BoolVar(&o.verbose, "verbose", false, "log requests to stderr (tokens redacted)")
	fs.Usage = func() {}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stderr, usage)
			fs.SetOutput(stderr)
			fs.PrintDefaults()
			return nil, err
		}
		return nil, &exitError{ExitUsage, err}
	}
	if fs.NArg() > 0 {
		return nil, fail(ExitUsage, "unexpected argument %q", fs.Arg(0))
	}
	return &o, nil
}

// Run executes the command and returns the exit code.
func Run(env Env) int {
	if env.Now == nil {
		env.Now = time.Now
	}
	err := run(env)
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	code := ExitUsage
	var ee *exitError
	if errors.As(err, &ee) {
		code = ee.code
	}
	fmt.Fprintf(env.Stderr, "%s: %v\n", prog, err)
	return code
}

func run(env Env) error {
	o, err := parseFlags(env.Args, env.Stderr)
	if err != nil {
		return err
	}
	o.verbose = o.verbose || debugEnabled(env.Getenv("GH_DEBUG"))

	cfg, err := config.Load(env.Getenv)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}

	if o.list {
		return list(env.Stdout, cfg)
	}

	login, err := identity.ResolveLogin(o.login, env.Getenv, cfg.Harnesses)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	app, ok := cfg.App(login)
	if !ok {
		return fail(ExitUsage, "no app configured for '%s'", login)
	}

	var wrap func(http.RoundTripper) http.RoundTripper
	if o.verbose {
		wrap = func(rt http.RoundTripper) http.RoundTripper { return &logTransport{rt: rt, w: env.Stderr} }
	}

	var appJWT string
	signJWT := func() (string, error) {
		if appJWT != "" {
			return appJWT, nil
		}
		signer, err := newSigner(env, cfg, app, o, wrap)
		if err != nil {
			return "", fail(ExitUsage, "%v", err)
		}
		in := jwt.SigningInput(app.AppID, env.Now())
		sig, err := signer.SignRS256([]byte(in))
		if err != nil {
			return "", &exitError{ExitSigner, err}
		}
		appJWT = jwt.Assemble(in, sig)
		return appJWT, nil
	}

	if o.printJWT {
		t, err := signJWT()
		if err != nil {
			return err
		}
		_, err = io.WriteString(env.Stdout, t)
		return err
	}

	target, err := identity.ResolveTarget(o.owner, o.repo, o.hostname, env.Getenv, env.OriginURL)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	owner := target.Owner
	scope := cache.Scope{Login: login, Owner: owner, Host: target.Host}

	ghBase := env.GitHubBaseURL
	if ghBase == "" {
		ghBase = github.BaseURL(target.Host)
	}
	gh := &github.Client{BaseURL: ghBase, HTTP: &http.Client{Transport: wrapRT(http.DefaultTransport, wrap), Timeout: 30 * time.Second}}

	var store *cache.Store
	if dir, err := cache.Dir(env.Getenv); err != nil {
		fmt.Fprintf(env.Stderr, "%s: warning: token cache disabled: %v\n", prog, err)
	} else if store, err = cache.Open(dir); err != nil {
		fmt.Fprintf(env.Stderr, "%s: warning: token cache disabled: %v\n", prog, err)
		store = nil
	}
	if store != nil {
		unlock, err := store.Lock(scope)
		if err != nil {
			fmt.Fprintf(env.Stderr, "%s: warning: token cache disabled: %v\n", prog, err)
			store = nil
		} else {
			defer unlock()
		}
	}

	iid, static := app.Installation(owner)
	if store != nil && !o.force {
		if e := store.Get(scope); e.Valid(env.Now()) && e.AppID == app.AppID && (!static || e.InstallationID == iid) {
			return output(env.Stdout, o.json, e, login, owner)
		}
	}

	if !static {
		t, err := signJWT()
		if err != nil {
			return err
		}
		iid, err = gh.FindInstallation(t, owner)
		var ni *github.ErrNotInstalled
		if errors.As(err, &ni) {
			return fail(ExitUsage, "app for '%s' not installed on '%s'", login, owner)
		}
		if err != nil {
			return &exitError{ExitGitHub, err}
		}
	}
	t, err := signJWT()
	if err != nil {
		return err
	}
	tok, err := gh.CreateToken(t, iid)
	if err != nil {
		return &exitError{ExitGitHub, err}
	}
	e := &cache.Entry{Expires: tok.ExpiresAt, Token: tok.Token, InstallationID: iid, AppID: app.AppID}
	if store != nil {
		if err := store.Put(scope, e); err != nil {
			fmt.Fprintf(env.Stderr, "%s: warning: writing token cache: %v\n", prog, err)
		}
	}
	return output(env.Stdout, o.json, e, login, owner)
}

// transitSigner binds a Transit client to the selected App key.
type transitSigner struct {
	client *transit.Client
	key    string
}

func (s *transitSigner) SignRS256(input []byte) (string, error) {
	return s.client.SignRS256(s.key, input)
}

func newSigner(env Env, cfg *config.Config, app *config.App, o *options, wrap func(http.RoundTripper) http.RoundTripper) (jwt.Signer, error) {
	if app.Signer == config.SignerAzureKeyVault {
		a := app.AzureKeyVault
		if env.NewAzureSigner != nil {
			return env.NewAzureSigner(a)
		}
		credential, err := azurekeyvault.Credential(a.Credential)
		if err != nil {
			return nil, err
		}
		return azurekeyvault.New(a.VaultURL, a.KeyName, a.KeyVersion, credential, &azkeys.ClientOptions{
			ClientOptions: policy.ClientOptions{
				Transport: &http.Client{Transport: wrapRT(http.DefaultTransport, wrap), Timeout: 30 * time.Second},
			},
		})
	}
	addr := transit.ResolveAddr(o.agentAddr, cfg.AgentAddr, env.Getenv)
	httpc, err := transit.NewHTTPClient(addr, env.Getenv, wrap)
	if err != nil {
		return nil, err
	}
	return &transitSigner{client: &transit.Client{
		Addr: addr, Mount: cfg.TransitMount,
		Token: transit.TokenFromEnv(env.Getenv), HTTP: httpc,
	}, key: app.TransitKey}, nil
}

func wrapRT(rt http.RoundTripper, wrap func(http.RoundTripper) http.RoundTripper) http.RoundTripper {
	if wrap == nil {
		return rt
	}
	return wrap(rt)
}

type jsonOut struct {
	Token          string `json:"token"`
	ExpiresAt      string `json:"expires_at"`
	Login          string `json:"login"`
	Owner          string `json:"owner"`
	InstallationID int64  `json:"installation_id"`
}

func output(w io.Writer, asJSON bool, e *cache.Entry, login, owner string) error {
	if !asJSON {
		_, err := io.WriteString(w, e.Token)
		return err
	}
	b, err := json.Marshal(jsonOut{
		Token:          e.Token,
		ExpiresAt:      e.Expires.UTC().Format(time.RFC3339),
		Login:          login,
		Owner:          owner,
		InstallationID: e.InstallationID,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

func list(w io.Writer, cfg *config.Config) error {
	harnessOf := map[string][]string{}
	for h, l := range cfg.Harnesses {
		harnessOf[l] = append(harnessOf[l], h)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LOGIN\tAPP_ID\tSIGNER\tKEY\tHARNESS")
	for _, l := range cfg.Logins() {
		a := cfg.Apps[l]
		h := strings.Join(harnessOf[l], ",")
		if h == "" {
			h = "-"
		}
		key := cfg.TransitMount + "/" + a.TransitKey
		if a.Signer == config.SignerAzureKeyVault {
			az := a.AzureKeyVault
			key = strings.TrimRight(az.VaultURL, "/") + "/keys/" + az.KeyName
			if az.KeyVersion != "" {
				key += "/" + az.KeyVersion
			}
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", l, a.AppID, a.Signer, key, h)
	}
	return tw.Flush()
}

func debugEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}

// logTransport logs method, URL and status. Bodies are never logged and
// credential headers are redacted, so tokens and JWTs cannot leak.
type logTransport struct {
	rt http.RoundTripper
	w  io.Writer
}

var sensitiveHeaders = []string{"Authorization", "X-Vault-Token"}

func (t *logTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Fprintf(t.w, "* %s %s\n", req.Method, req.URL.Redacted())
	for _, h := range sensitiveHeaders {
		if v := req.Header.Get(h); v != "" {
			scheme := ""
			if i := strings.IndexByte(v, ' '); i > 0 {
				scheme = v[:i+1]
			}
			fmt.Fprintf(t.w, "* > %s: %s[REDACTED]\n", h, scheme)
		}
	}
	start := time.Now()
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		fmt.Fprintf(t.w, "* < error: %v\n", err)
		return resp, err
	}
	fmt.Fprintf(t.w, "* < %s (%s)\n", resp.Status, time.Since(start).Round(time.Millisecond))
	return resp, nil
}
