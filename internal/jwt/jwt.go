// Package jwt assembles a GitHub App RS256 JWT around an external signer.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"
)

// Signer signs a JWT signing input remotely and returns an unpadded base64url signature.
type Signer interface {
	SignRS256(input []byte) (string, error)
}

const (
	// Backdate iat to tolerate clock drift, as GitHub recommends.
	IssuedAtSkew = 60 * time.Second
	// GitHub rejects exp more than 10 minutes out; keep 9.
	Lifetime = 540 * time.Second
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type claims struct {
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
}

// SigningInput returns base64url(header) + "." + base64url(claims).
func SigningInput(appID int64, now time.Time) string {
	h, _ := json.Marshal(header{Alg: "RS256", Typ: "JWT"})
	c, _ := json.Marshal(claims{
		Iat: now.Add(-IssuedAtSkew).Unix(),
		Exp: now.Add(Lifetime).Unix(),
		Iss: strconv.FormatInt(appID, 10),
	})
	enc := base64.RawURLEncoding
	return enc.EncodeToString(h) + "." + enc.EncodeToString(c)
}

// Assemble joins the signing input with a base64url (unpadded) signature.
func Assemble(signingInput, sigB64URL string) string {
	return signingInput + "." + sigB64URL
}
