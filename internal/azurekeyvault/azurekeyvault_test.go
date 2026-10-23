package azurekeyvault_test

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/gh-vault-agent-app-token/internal/azurekeyvault"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/jwt"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/testutil"
)

func TestSignRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"", "abc123"} {
		t.Run("version="+version, func(t *testing.T) {
			f := &testutil.FakeAzureKeyVault{Key: key, KeyName: "github-app", KeyVersion: version}
			signer, err := azurekeyvault.New(testutil.FakeVaultURL, f.KeyName, version, f, f.Options())
			if err != nil {
				t.Fatal(err)
			}
			input := jwt.SigningInput(1001, time.Now())
			sig, err := signer.SignRS256([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			if err := testutil.VerifyJWT(&key.PublicKey, 1001, jwt.Assemble(input, sig)); err != nil {
				t.Fatal(err)
			}
			if f.SignCalls.Load() != 1 || f.TokenCalls.Load() != 1 {
				t.Fatalf("signCalls=%d tokenCalls=%d", f.SignCalls.Load(), f.TokenCalls.Load())
			}
		})
	}
}

func TestSignErrors(t *testing.T) {
	empty := `{}`
	malformed := `not json`
	invalidBase64 := `{"value":"%%%"}`
	for _, tc := range []struct {
		name   string
		status int
		body   *string
		want   string
	}{
		{"forbidden", 403, nil, "Forbidden"},
		{"missing signature", 0, &empty, "no signature"},
		{"malformed response", 0, &malformed, "invalid character"},
		{"invalid signature encoding", 0, &invalidBase64, "illegal base64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &testutil.FakeAzureKeyVault{KeyName: "github-app", Status: tc.status, Body: tc.body}
			signer, err := azurekeyvault.New(testutil.FakeVaultURL, f.KeyName, "", f, f.Options())
			if err != nil {
				t.Fatal(err)
			}
			sig, err := signer.SignRS256([]byte("input"))
			if sig != "" || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("sig=%q err=%v", sig, err)
			}
		})
	}
}

func TestCredentialSelection(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "test-client")
	t.Setenv("AZURE_TENANT_ID", "test-tenant")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/unused-token-file")
	for _, kind := range []string{"", "default", "azure-cli", "managed-identity", "workload-identity"} {
		if c, err := azurekeyvault.Credential(kind); c == nil || err != nil {
			t.Fatalf("%q: credential=%v err=%v", kind, c, err)
		}
	}
	if _, err := azurekeyvault.Credential("unknown"); err == nil {
		t.Fatal("expected unknown credential error")
	}
}
