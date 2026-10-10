package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJWTRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	in := SigningInput(12345, now)

	// Sign locally, the way Transit would with pkcs1v15 + sha2-256.
	h := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	tok := Assemble(in, base64.RawURLEncoding.EncodeToString(sig))

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 parts, got %d", len(parts))
	}
	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	h2 := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h2[:], gotSig); err != nil {
		t.Fatalf("verify: %v", err)
	}

	var hdr map[string]any
	decodeSeg(t, parts[0], &hdr)
	if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" || len(hdr) != 2 {
		t.Fatalf("header = %v", hdr)
	}
	var cl map[string]any
	decodeSeg(t, parts[1], &cl)
	if cl["iss"] != "12345" {
		t.Fatalf("iss must be the app id as a string, got %#v", cl["iss"])
	}
	if cl["iat"].(float64) != float64(now.Unix()-60) || cl["exp"].(float64) != float64(now.Unix()+540) {
		t.Fatalf("claims = %v", cl)
	}
}

func decodeSeg(t *testing.T, s string, v any) {
	t.Helper()
	if strings.ContainsAny(s, "+/=") {
		t.Fatalf("segment not base64url: %q", s)
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}
