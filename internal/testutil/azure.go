package testutil

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// FakeAzureKeyVault implements an in-memory Key Vault transport and credential.
// It accepts sign requests only; fetching private key material is never allowed.
type FakeAzureKeyVault struct {
	TokenError          error
	Key                 *rsa.PrivateKey
	KeyName, KeyVersion string
	SignCalls           atomic.Int32
	TokenCalls          atomic.Int32
	Status              int
	Body                *string
}

const FakeVaultURL = "https://test-vault.vault.azure.net"
const FakeAzureToken = "fake-azure-access-token"

func (f *FakeAzureKeyVault) Options() *azkeys.ClientOptions {
	return &azkeys.ClientOptions{ClientOptions: policy.ClientOptions{Transport: f, Retry: policy.RetryOptions{MaxRetries: -1}}}
}

func (f *FakeAzureKeyVault) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.TokenCalls.Add(1)
	if f.TokenError != nil {
		return azcore.AccessToken{}, f.TokenError
	}
	if len(opts.Scopes) != 1 || opts.Scopes[0] != "https://vault.azure.net/.default" {
		return azcore.AccessToken{}, fmt.Errorf("unexpected token scopes %v", opts.Scopes)
	}
	return azcore.AccessToken{Token: FakeAzureToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func (f *FakeAzureKeyVault) Do(r *http.Request) (*http.Response, error) {
	response := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
	}
	if r.Header.Get("Authorization") == "" {
		resp := response(401, "")
		resp.Header.Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/test-tenant", resource="https://vault.azure.net"`)
		return resp, nil
	}
	if r.Header.Get("Authorization") != "Bearer "+FakeAzureToken {
		return nil, fmt.Errorf("unexpected Azure authorization")
	}
	if r.Header.Get("X-Vault-Token") != "" {
		return nil, fmt.Errorf("Vault token sent to Azure")
	}
	wantPath := path.Clean("/keys/" + f.KeyName + "/" + f.KeyVersion + "/sign")
	if r.Method != http.MethodPost || path.Clean(r.URL.Path) != wantPath {
		return nil, fmt.Errorf("unexpected Key Vault operation: %s %s", r.Method, r.URL.Path)
	}
	f.SignCalls.Add(1)
	if f.Status != 0 {
		return response(f.Status, `{"error":{"code":"Forbidden","message":"sign denied"}}`), nil
	}
	if f.Body != nil {
		return response(200, *f.Body), nil
	}
	var req struct{ Alg, Value string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}
	if req.Alg != "RS256" {
		return nil, fmt.Errorf("unexpected algorithm %s", req.Alg)
	}
	digest, err := base64.RawURLEncoding.DecodeString(req.Value)
	if err != nil {
		return nil, err
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.Key, crypto.SHA256, digest)
	if err != nil {
		return nil, err
	}
	return response(200, `{"value":"`+base64.RawURLEncoding.EncodeToString(sig)+`"}`), nil
}
