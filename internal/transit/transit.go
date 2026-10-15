/*
---
relationships:
  references: README
---
*/
// Package transit signs data with the Transit secrets engine of OpenBao or
// HashiCorp Vault, normally through a local Agent listener.
package transit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const DefaultAddr = "http://127.0.0.1:8100"

// Client talks to the Transit sign endpoint.
type Client struct {
	Addr  string // e.g. http://127.0.0.1:8100 or unix:///run/agent.sock
	Mount string // e.g. transit
	// Token is sent as X-Vault-Token when non-empty. Leave empty when going
	// through an Agent listener that injects its auto-auth token.
	Token string
	HTTP  *http.Client
}

// Error is a failed request: unreachable server, bad status or bad response.
type Error struct {
	Status int      // 0 when the server was unreachable
	Errors []string // the server's errors[]
	Msg    string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Msg)
	if e.Status != 0 {
		fmt.Fprintf(&b, ": HTTP %d", e.Status)
	}
	if len(e.Errors) > 0 {
		b.WriteString(": ")
		b.WriteString(strings.Join(e.Errors, "; "))
	}
	return b.String()
}

// ResolveAddr picks the agent address: flag, GH_VAULT_APP_TOKEN_AGENT_ADDR,
// config, BAO_AGENT_ADDR, VAULT_AGENT_ADDR, BAO_ADDR, VAULT_ADDR, default.
func ResolveAddr(flagAddr, configAddr string, getenv func(string) string) string {
	cands := []string{
		flagAddr,
		getenv("GH_VAULT_APP_TOKEN_AGENT_ADDR"),
		configAddr,
		getenv("BAO_AGENT_ADDR"),
		getenv("VAULT_AGENT_ADDR"),
		getenv("BAO_ADDR"),
		getenv("VAULT_ADDR"),
	}
	for _, c := range cands {
		if c != "" {
			return c
		}
	}
	return DefaultAddr
}

// TokenFromEnv returns BAO_TOKEN, else VAULT_TOKEN.
func TokenFromEnv(getenv func(string) string) string {
	if t := getenv("BAO_TOKEN"); t != "" {
		return t
	}
	return getenv("VAULT_TOKEN")
}

// NewHTTPClient builds a client honouring BAO_CACERT/VAULT_CACERT and
// BAO_SKIP_VERIFY/VAULT_SKIP_VERIFY. Unix socket addresses bypass TLS settings
// and HTTP proxies.
func NewHTTPClient(addr string, getenv func(string) string, rt func(http.RoundTripper) http.RoundTripper) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if strings.HasPrefix(addr, "unix://") {
		path := strings.TrimPrefix(addr, "unix://")
		if !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("bad agent address %q: Unix socket path must be absolute", addr)
		}
		// The HTTP host is a placeholder; connect directly to the socket.
		tr.Proxy = nil
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}
		var transport http.RoundTripper = tr
		if rt != nil {
			transport = rt(transport)
		}
		return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	caFile := getenv("BAO_CACERT")
	if caFile == "" {
		caFile = getenv("VAULT_CACERT")
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	skip := getenv("BAO_SKIP_VERIFY")
	if skip == "" {
		skip = getenv("VAULT_SKIP_VERIFY")
	}
	if truthy(skip) {
		tlsCfg.InsecureSkipVerify = true
	}
	tr.TLSClientConfig = tlsCfg
	var t http.RoundTripper = tr
	if rt != nil {
		t = rt(t)
	}
	return &http.Client{Transport: t, Timeout: 30 * time.Second}, nil
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	}
	return false
}

type signRequest struct {
	Input              string `json:"input"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	HashAlgorithm      string `json:"hash_algorithm"`
	MarshalingAlg      string `json:"marshaling_algorithm,omitempty"`
}

type signResponse struct {
	Data struct {
		Signature string `json:"signature"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// SignRS256 signs input with key using PKCS#1 v1.5 / SHA-256 and returns the
// signature as base64url without padding, ready for a JWS.
func (c *Client) SignRS256(key string, input []byte) (string, error) {
	sig, err := c.sign(key, input, "jws")
	if e, ok := err.(*Error); ok && e.Status == http.StatusBadRequest && mentionsMarshaling(e.Errors) {
		// Older servers do not know marshaling_algorithm.
		sig, err = c.sign(key, input, "")
	}
	if err != nil {
		return "", err
	}
	return ParseSignature(sig)
}

func mentionsMarshaling(errs []string) bool {
	for _, e := range errs {
		if strings.Contains(strings.ToLower(e), "marshal") {
			return true
		}
	}
	return false
}

func (c *Client) sign(key string, input []byte, marshaling string) (string, error) {
	body, _ := json.Marshal(signRequest{
		Input:              base64.StdEncoding.EncodeToString(input),
		SignatureAlgorithm: "pkcs1v15",
		HashAlgorithm:      "sha2-256",
		MarshalingAlg:      marshaling,
	})
	addr := c.Addr
	if strings.HasPrefix(addr, "unix://") {
		addr = "http://localhost"
	}
	u := strings.TrimRight(addr, "/") + "/v1/" + strings.Trim(c.Mount, "/") + "/sign/" + url.PathEscape(key)
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", &Error{Msg: fmt.Sprintf("bad agent address %q: %v", c.Addr, err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Request", "true")
	if c.Token != "" {
		req.Header.Set("X-Vault-Token", c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		if strings.HasPrefix(c.Addr, "unix://") {
			hc, err = NewHTTPClient(c.Addr, func(string) string { return "" }, nil)
			if err != nil {
				return "", &Error{Msg: err.Error()}
			}
			defer hc.CloseIdleConnections()
		} else {
			hc = http.DefaultClient
		}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", &Error{Msg: fmt.Sprintf("transit sign via %s unreachable: %v", c.Addr, err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var sr signResponse
	jsonErr := json.Unmarshal(raw, &sr)
	if resp.StatusCode/100 != 2 {
		e := &Error{Status: resp.StatusCode, Errors: sr.Errors, Msg: fmt.Sprintf("transit sign with key '%s' failed", key)}
		if jsonErr != nil && len(raw) > 0 {
			e.Errors = []string{strings.TrimSpace(string(truncate(raw, 200)))}
		}
		return "", e
	}
	if jsonErr != nil {
		return "", &Error{Status: resp.StatusCode, Msg: fmt.Sprintf("transit sign: invalid JSON response: %v", jsonErr)}
	}
	if sr.Data.Signature == "" {
		return "", &Error{Status: resp.StatusCode, Msg: "transit sign: response has no data.signature"}
	}
	return sr.Data.Signature, nil
}

func truncate(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// ParseSignature strips the "vault:v<N>:" prefix and returns the signature as
// unpadded base64url. It accepts both jws (already base64url) and standard
// base64 encodings; the two alphabets differ only in '+', '/' and padding.
func ParseSignature(s string) (string, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || len(parts[1]) < 2 || parts[1][0] != 'v' {
		return "", fmt.Errorf("unexpected signature format %q", truncate([]byte(s), 20))
	}
	for _, r := range parts[1][1:] {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("unexpected key version in signature prefix %q", parts[1])
		}
	}
	sig := strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(parts[2], "="))
	if sig == "" {
		return "", fmt.Errorf("empty signature")
	}
	if _, err := base64.RawURLEncoding.DecodeString(sig); err != nil {
		return "", fmt.Errorf("signature is not base64: %v", err)
	}
	return sig, nil
}
