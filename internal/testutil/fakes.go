// Package testutil provides fake Transit and GitHub servers for tests.
package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// FakeTransit emulates POST /v1/<mount>/sign/<key> with local RSA keys.
type FakeTransit struct {
	*httptest.Server
	Keys map[string]*rsa.PrivateKey
	// LegacyNoMarshaling makes the server reject marshaling_algorithm with
	// 400, as a server predating the parameter might.
	LegacyNoMarshaling bool
	// IgnoreMarshaling makes the server ignore marshaling_algorithm and
	// return standard base64, as older Vault versions do.
	IgnoreMarshaling bool
	// RequireToken, when set, must arrive as X-Vault-Token.
	RequireToken string
	Calls        atomic.Int32
	LastToken    atomic.Value
}

func NewFakeTransit(t *testing.T, mount string, keys map[string]*rsa.PrivateKey) *FakeTransit {
	f := &FakeTransit{Keys: keys}
	prefix := "/v1/" + mount + "/sign/"
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.Calls.Add(1)
		f.LastToken.Store(r.Header.Get("X-Vault-Token"))
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, prefix) {
			writeErr(w, 404, "no handler for route")
			return
		}
		if f.RequireToken != "" && r.Header.Get("X-Vault-Token") != f.RequireToken {
			writeErr(w, 403, "permission denied")
			return
		}
		key := f.Keys[strings.TrimPrefix(r.URL.Path, prefix)]
		if key == nil {
			writeErr(w, 400, "signing key not found")
			return
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, "bad json")
			return
		}
		if req["signature_algorithm"] != "pkcs1v15" || req["hash_algorithm"] != "sha2-256" {
			writeErr(w, 400, "unexpected algorithms")
			return
		}
		m, hasM := req["marshaling_algorithm"]
		if hasM && f.LegacyNoMarshaling {
			writeErr(w, 400, "unknown marshaling_algorithm")
			return
		}
		in, err := base64.StdEncoding.DecodeString(req["input"])
		if err != nil {
			writeErr(w, 400, "input not base64")
			return
		}
		h := sha256.Sum256(in)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
		enc := base64.StdEncoding.EncodeToString(sig)
		if m == "jws" && !f.IgnoreMarshaling {
			enc = base64.RawURLEncoding.EncodeToString(sig)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": "vault:v1:" + enc, "key_version": 1}})
	}))
	t.Cleanup(f.Close)
	return f
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}

// FakeGitHub emulates the App installation endpoints and verifies JWTs.
type FakeGitHub struct {
	*httptest.Server
	Pub           *rsa.PublicKey
	AppID         int64
	Installations map[string]int64 // account login → id
	PageSize      int
	TokenTTL      time.Duration

	mu         sync.Mutex
	TokenCalls int
	ListCalls  int
	LastIID    int64
	FailToken  int // non-zero → status for access_tokens
}

func NewFakeGitHub(t *testing.T, pub *rsa.PublicKey, appID int64, inst map[string]int64) *FakeGitHub {
	f := &FakeGitHub{Pub: pub, AppID: appID, Installations: inst, PageSize: 100, TokenTTL: time.Hour}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *FakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
		ghErr(w, 415, "missing headers")
		return
	}
	if err := f.verify(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); err != nil {
		ghErr(w, 401, "A JSON web token could not be decoded: "+err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/app/installations":
		f.ListCalls++
		// Stable order, deliberately not keyed to the owner.
		type acct struct {
			Login string `json:"login"`
		}
		type inst struct {
			ID      int64 `json:"id"`
			Account acct  `json:"account"`
		}
		var all []inst
		for l, id := range f.Installations {
			all = append(all, inst{id, acct{l}})
		}
		for i := range all {
			for j := i + 1; j < len(all); j++ {
				if all[j].ID < all[i].ID {
					all[i], all[j] = all[j], all[i]
				}
			}
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		lo, hi := (page-1)*f.PageSize, page*f.PageSize
		if lo > len(all) {
			lo = len(all)
		}
		if hi >= len(all) {
			hi = len(all)
		} else {
			w.Header().Set("Link", fmt.Sprintf(`<%s/app/installations?per_page=%d&page=%d>; rel="next"`, f.URL, f.PageSize, page+1))
		}
		json.NewEncoder(w).Encode(all[lo:hi])
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/app/installations/") && strings.HasSuffix(r.URL.Path, "/access_tokens"):
		f.TokenCalls++
		if f.FailToken != 0 {
			ghErr(w, f.FailToken, "Integration not found")
			return
		}
		id, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/app/installations/"), "/access_tokens"), 10, 64)
		f.LastIID = id
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      fmt.Sprintf("ghs_fake_%d_%d", id, f.TokenCalls),
			"expires_at": time.Now().Add(f.TokenTTL).UTC().Format(time.RFC3339),
		})
	default:
		ghErr(w, 404, "Not Found")
	}
}

func ghErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"message": msg})
}

func (f *FakeGitHub) verify(tok string) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(f.Pub, crypto.SHA256, h[:], sig); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var c struct {
		Iat, Exp int64
		Iss      string
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	now := time.Now().Unix()
	if c.Iss != strconv.FormatInt(f.AppID, 10) {
		return fmt.Errorf("wrong iss %q", c.Iss)
	}
	if c.Iat > now || c.Exp <= now || c.Exp-c.Iat > 600 {
		return fmt.Errorf("bad iat/exp")
	}
	return nil
}

// VerifyJWT checks an App JWT's RS256 signature and claims.
func VerifyJWT(pub *rsa.PublicKey, appID int64, tok string) error {
	f := &FakeGitHub{Pub: pub, AppID: appID}
	return f.verify(tok)
}
