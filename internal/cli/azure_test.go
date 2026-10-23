package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wyrd-company/gh-vault-agent-app-token/internal/azurekeyvault"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/config"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/jwt"
	"github.com/wyrd-company/gh-vault-agent-app-token/internal/testutil"
)

func azureHarness(t *testing.T) (*harness, *testutil.FakeAzureKeyVault, *int) {
	t.Helper()
	h := newHarness(t, "")
	h.env["GH_LOGIN"] = testLogin
	p := h.env["GH_VAULT_APP_TOKEN_CONFIG"]
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(raw), "    transit_key: gh-app-test", `    signer: azure-key-vault
    azure_key_vault:
      vault_url: https://test-vault.vault.azure.net
      key_name: github-app
      key_version: abc123
      credential: azure-cli`, 1)
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &testutil.FakeAzureKeyVault{Key: testKey, KeyName: "github-app", KeyVersion: "abc123"}
	constructions := 0
	h.newAzureSigner = func(a *config.AzureKeyVault) (jwt.Signer, error) {
		constructions++
		if a.VaultURL != testutil.FakeVaultURL || a.KeyName != f.KeyName || a.KeyVersion != f.KeyVersion || a.Credential != "azure-cli" {
			return nil, fmt.Errorf("unexpected Azure config: %+v", a)
		}
		return azurekeyvault.New(a.VaultURL, a.KeyName, a.KeyVersion, f, f.Options())
	}
	// Transit-only settings must not affect the Azure backend.
	h.env["BAO_CACERT"] = "/nonexistent-ca.pem"
	h.env["VAULT_TOKEN"] = "fake-vault-token"
	return h, f, &constructions
}

func TestAzureMintAndCache(t *testing.T) {
	h, f, constructions := azureHarness(t)
	for i := 0; i < 2; i++ {
		code, out, errs := h.run("--owner", "acme", "--verbose")
		if code != 0 || out != "ghs_fake_77_1" {
			t.Fatalf("code=%d out=%q err=%s", code, out, errs)
		}
		for _, secret := range []string{testutil.FakeAzureToken, "fake-vault-token", out} {
			if strings.Contains(errs, secret) {
				t.Fatalf("stderr leaked %q", secret)
			}
		}
	}
	if *constructions != 1 || f.SignCalls.Load() != 1 || h.transit.Calls.Load() != 0 {
		t.Fatalf("constructions=%d Azure=%d Transit=%d", *constructions, f.SignCalls.Load(), h.transit.Calls.Load())
	}
	code, out, errs := h.run("--owner", "acme", "--force")
	if code != 0 || out != "ghs_fake_77_2" || f.SignCalls.Load() != 2 {
		t.Fatalf("force: code=%d out=%q err=%s", code, out, errs)
	}
	code, out, errs = h.run("--print-jwt")
	if code != 0 {
		t.Fatalf("print JWT: code=%d err=%s", code, errs)
	}
	if err := testutil.VerifyJWT(&testKey.PublicKey, 1001, out); err != nil {
		t.Fatal(err)
	}
}

func TestAzureErrors(t *testing.T) {
	t.Run("authentication", func(t *testing.T) {
		h, f, _ := azureHarness(t)
		f.TokenError = fmt.Errorf("Azure authentication denied")
		code, out, errs := h.run("--owner", "acme")
		if code != ExitSigner || out != "" || !strings.Contains(errs, "authentication denied") {
			t.Fatalf("code=%d out=%q err=%s", code, out, errs)
		}
	})
	t.Run("signing", func(t *testing.T) {
		h, f, _ := azureHarness(t)
		f.Status = 403
		code, out, errs := h.run("--owner", "acme")
		if code != ExitSigner || out != "" || !strings.Contains(errs, "Forbidden") {
			t.Fatalf("code=%d out=%q err=%s", code, out, errs)
		}
	})
	t.Run("initialization", func(t *testing.T) {
		h, _, _ := azureHarness(t)
		h.newAzureSigner = func(*config.AzureKeyVault) (jwt.Signer, error) { return nil, fmt.Errorf("credential unavailable") }
		code, out, errs := h.run("--owner", "acme")
		if code != ExitUsage || out != "" || !strings.Contains(errs, "credential unavailable") {
			t.Fatalf("code=%d out=%q err=%s", code, out, errs)
		}
	})
	t.Run("GitHub", func(t *testing.T) {
		h, _, _ := azureHarness(t)
		h.gh.FailToken = 403
		code, out, errs := h.run("--owner", "acme")
		if code != ExitGitHub || out != "" || !strings.Contains(errs, "HTTP 403") {
			t.Fatalf("code=%d out=%q err=%s", code, out, errs)
		}
	})
}

func TestListAzureKey(t *testing.T) {
	h, _, constructions := azureHarness(t)
	code, out, errs := h.run("--list")
	if code != 0 || !strings.Contains(out, "azure-key-vault") || !strings.Contains(out, "/keys/github-app/abc123") || *constructions != 0 {
		t.Fatalf("code=%d out=%q err=%s", code, out, errs)
	}
}
