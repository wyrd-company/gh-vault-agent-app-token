// Package azurekeyvault signs JWT inputs with RSA keys in Azure Key Vault.
package azurekeyvault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// Credential selects the Azure authentication method. Hosted agents can select
// one identity explicitly instead of falling through to a developer login.
func Credential(kind string) (azcore.TokenCredential, error) {
	switch kind {
	case "", "default":
		return azidentity.NewDefaultAzureCredential(nil)
	case "azure-cli":
		return azidentity.NewAzureCLICredential(nil)
	case "managed-identity":
		opts := &azidentity.ManagedIdentityCredentialOptions{}
		if id := os.Getenv("AZURE_CLIENT_ID"); id != "" {
			opts.ID = azidentity.ClientID(id)
		}
		return azidentity.NewManagedIdentityCredential(opts)
	case "workload-identity":
		return azidentity.NewWorkloadIdentityCredential(nil)
	default:
		return nil, fmt.Errorf("unknown Azure credential %q", kind)
	}
}

// Signer uses a specific Key Vault key, optionally pinned to a version.
type Signer struct {
	client              *azkeys.Client
	keyName, keyVersion string
}

// New constructs a signer without fetching key material or calling Azure.
func New(vaultURL, keyName, keyVersion string, credential azcore.TokenCredential, options *azkeys.ClientOptions) (*Signer, error) {
	client, err := azkeys.NewClient(vaultURL, credential, options)
	if err != nil {
		return nil, fmt.Errorf("creating Azure Key Vault client: %w", err)
	}
	return &Signer{client: client, keyName: keyName, keyVersion: keyVersion}, nil
}

// SignRS256 hashes the JWT signing input once, then sends only that digest to
// Key Vault. The private key is never retrieved. The result is ready for a JWS.
func (s *Signer) SignRS256(input []byte) (string, error) {
	digest := sha256.Sum256(input)
	alg := azkeys.SignatureAlgorithmRS256
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := s.client.Sign(ctx, s.keyName, s.keyVersion, azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest[:],
	}, nil)
	if err != nil {
		return "", fmt.Errorf("Azure Key Vault sign with key %q: %w", s.keyName, err)
	}
	if len(result.Result) == 0 {
		return "", fmt.Errorf("Azure Key Vault sign: response has no signature")
	}
	return base64.RawURLEncoding.EncodeToString(result.Result), nil
}
