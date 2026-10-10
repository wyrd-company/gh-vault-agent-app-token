package transit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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
