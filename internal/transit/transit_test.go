/*
---
relationships:

	tests: internal/transit/transit

---
*/
package transit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wyrd-company/gh-vault-agent-app-token/internal/testutil"
)

func TestParseSignature(t *testing.T) {
	raw := []byte{0xfb, 0xff, 0xfe, 0x01, 0x02} // exercises '+', '/' and padding
	std := base64.StdEncoding.EncodeToString(raw)
	url := base64.RawURLEncoding.EncodeToString(raw)
	if !strings.ContainsAny(std, "+/=") {
		t.Fatalf("test vector should contain +/=: %s", std)
	}
	for name, in := range map[string]string{
		"jws":  "vault:v1:" + url,
		"asn1": "vault:v1:" + std,
		"v12":  "vault:v12:" + url,
	} {
		got, err := ParseSignature(in)
		if err != nil || got != url {
			t.Errorf("%s: got %q, %v; want %q", name, got, err, url)
		}
	}
	for _, bad := range []string{"", "v1:abc", "vault:1:abc", "vault:v:abc", "vault:vx:abc", "vault:v1:", "bao:v1:abc", "vault:v1:a"} {
		if _, err := ParseSignature(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestResolveAddr(t *testing.T) {
	order := []string{"GH_VAULT_APP_TOKEN_AGENT_ADDR", "config", "BAO_AGENT_ADDR", "VAULT_AGENT_ADDR", "BAO_ADDR", "VAULT_ADDR"}
	env := map[string]string{}
	for _, k := range order {
		env[k] = k
	}
	get := func(k string) string { return env[k] }
	if got := ResolveAddr("flag", env["config"], get); got != "flag" {
		t.Fatalf("got %s", got)
	}
	for _, k := range order {
		if got := ResolveAddr("", env["config"], get); got != k {
			t.Fatalf("want %s, got %s", k, got)
		}
		delete(env, k)
	}
	if got := ResolveAddr("", "", get); got != DefaultAddr {
		t.Fatalf("got %s", got)
	}
}

func TestTokenFromEnv(t *testing.T) {
	env := map[string]string{"BAO_TOKEN": "b", "VAULT_TOKEN": "v"}
	get := func(k string) string { return env[k] }
	if TokenFromEnv(get) != "b" {
		t.Fatal("BAO_TOKEN first")
	}
	delete(env, "BAO_TOKEN")
	if TokenFromEnv(get) != "v" {
		t.Fatal("VAULT_TOKEN second")
	}
}

func verify(t *testing.T, pub *rsa.PublicKey, input []byte, sig string) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(input)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], b); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignRS256(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	input := []byte("header.claims")
	for _, mode := range []string{"jws", "ignored", "rejected"} {
		t.Run(mode, func(t *testing.T) {
			f := testutil.NewFakeTransit(t, "transit", map[string]*rsa.PrivateKey{"k": key})
			f.IgnoreMarshaling = mode == "ignored"
			f.LegacyNoMarshaling = mode == "rejected"
			c := &Client{Addr: f.URL, Mount: "transit"}
			sig, err := c.SignRS256("k", input)
			if err != nil {
				t.Fatal(err)
			}
			verify(t, &key.PublicKey, input, sig)
			if tok := f.LastToken.Load(); tok != "" {
				t.Fatalf("no token header expected by default, got %q", tok)
			}
		})
	}
}

func TestSignErrors(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := testutil.NewFakeTransit(t, "transit", map[string]*rsa.PrivateKey{"k": key})
	f.RequireToken = "s.secret"
	c := &Client{Addr: f.URL, Mount: "transit"}
	_, err := c.SignRS256("k", []byte("x"))
	e, ok := err.(*Error)
	if !ok || e.Status != 403 || !strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("got %v", err)
	}
	c.Token = "s.secret"
	if _, err := c.SignRS256("k", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SignRS256("missing", []byte("x")); err == nil || !strings.Contains(err.Error(), "signing key not found") {
		t.Fatalf("got %v", err)
	}
	c.Addr = "http://127.0.0.1:1"
	_, err = c.SignRS256("k", []byte("x"))
	if e, ok := err.(*Error); !ok || e.Status != 0 || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("got %v", err)
	}
}

func TestResolveUnixAddr(t *testing.T) {
	const addr = "unix:///x"
	for _, source := range []string{"flag", "config", "GH_VAULT_APP_TOKEN_AGENT_ADDR", "BAO_AGENT_ADDR", "VAULT_AGENT_ADDR", "BAO_ADDR", "VAULT_ADDR"} {
		t.Run(source, func(t *testing.T) {
			flag, config := "", ""
			if source == "flag" {
				flag = addr
			}
			if source == "config" {
				config = addr
			}
			got := ResolveAddr(flag, config, func(k string) string {
				if k == source {
					return addr
				}
				return ""
			})
			if got != addr {
				t.Fatalf("got %q, want %q", got, addr)
			}
		})
	}
}

func socketPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket test requires a Unix host")
	}
	// Keep the path short enough for macOS sockaddr_un, including under CI.
	dir, err := os.MkdirTemp("", "transit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "agent.sock")
}

func TestSignUnixSocket(t *testing.T) {
	path := socketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/custom/sign/example-key" || r.Host != "localhost" {
			t.Errorf("unexpected request: %s %s host=%s", r.Method, r.URL.Path, r.Host)
		}
		if got := r.Header.Get("X-Vault-Token"); got != r.Header.Get("Expected-Token") {
			t.Errorf("token: %q", got)
		}
		var body signRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Input != "aGVhZGVyLmNsYWltcw==" || body.SignatureAlgorithm != "pkcs1v15" || body.HashAlgorithm != "sha2-256" || body.MarshalingAlg != "jws" {
			t.Errorf("unexpected body: %+v", body)
		}
		w.Write([]byte(`{"data":{"signature":"vault:v1:c2lnbmF0dXJl"}}`))
	}))
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	// A configured proxy must never intercept local socket requests.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	for _, mode := range []string{"default", "configured", "token"} {
		t.Run(mode, func(t *testing.T) {
			c := &Client{Addr: "unix://" + path, Mount: "custom"}
			if mode != "default" {
				if mode == "token" {
					c.Token = "example-token"
				}
				hc, err := NewHTTPClient(c.Addr, func(k string) string {
					if strings.HasSuffix(k, "CACERT") {
						return "/missing/example-ca.pem"
					}
					if strings.HasSuffix(k, "SKIP_VERIFY") {
						return "true"
					}
					return ""
				}, func(rt http.RoundTripper) http.RoundTripper {
					transport := rt.(*http.Transport)
					if transport.Proxy != nil || (transport.TLSClientConfig != nil && (transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.RootCAs != nil)) {
						t.Error("Unix socket transport must bypass proxies and TLS")
					}
					return tokenExpectation{rt: rt, token: c.Token}
				})
				if err != nil {
					t.Fatal(err)
				}
				defer hc.CloseIdleConnections()
				c.HTTP = hc
			}
			sig, err := c.SignRS256("example-key", []byte("header.claims"))
			if err != nil || sig != "c2lnbmF0dXJl" {
				t.Fatalf("sig=%q err=%v", sig, err)
			}
		})
	}
}

type tokenExpectation struct {
	rt    http.RoundTripper
	token string
}

func (e tokenExpectation) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Expected-Token", e.token)
	return e.rt.RoundTrip(r)
}

func TestUnixSocketConnectionErrors(t *testing.T) {
	for _, kind := range []string{"missing", "refused"} {
		t.Run(kind, func(t *testing.T) {
			path := socketPath(t)
			if kind == "refused" {
				l, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				l.(*net.UnixListener).SetUnlinkOnClose(false)
				l.Close()
			}
			c := &Client{Addr: "unix://" + path, Mount: "transit"}
			_, err := c.SignRS256("example-key", []byte("input"))
			e, ok := err.(*Error)
			if !ok || e.Status != 0 || !strings.Contains(e.Error(), path) || !strings.Contains(e.Error(), "unreachable") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestUnixSocketRequiresAbsolutePath(t *testing.T) {
	for _, addr := range []string{"unix://", "unix://relative/agent.sock"} {
		if _, err := NewHTTPClient(addr, func(string) string { return "" }, nil); err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("addr=%s err=%v", addr, err)
		}
	}
}

func TestHTTPClientTLSSettings(t *testing.T) {
	for _, scheme := range []string{"http://localhost", "https://localhost"} {
		if _, err := NewHTTPClient(scheme, func(k string) string {
			if k == "VAULT_CACERT" {
				return "/missing/example-ca.pem"
			}
			return ""
		}, nil); err == nil {
			t.Fatalf("%s must still load configured CA", scheme)
		}
	}
}
