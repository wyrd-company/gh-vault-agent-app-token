//go:build integration

// Integration test against a real OpenBao dev server with Transit enabled.
// Requires the bao binary on PATH or in $BAO_BIN:
//
//	go test -tags integration ./internal/cli/
package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitHTTP(t *testing.T, url string) {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s did not come up", url)
}

func startProc(t *testing.T, bin string, env []string, args ...string) {
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	logf, _ := os.Create(filepath.Join(t.TempDir(), "log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(logf.Name())
			t.Logf("%s %s output:\n%s", filepath.Base(bin), args[0], b)
		}
	})
}

func TestIntegrationOpenBao(t *testing.T) {
	bin := os.Getenv("BAO_BIN")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("bao"); err != nil {
			t.Skip("bao binary not found (set BAO_BIN)")
		}
	}
	const root = "integration-root"
	addr := "http://" + freeAddr(t)
	baseEnv := append(os.Environ(), "BAO_ADDR="+addr, "BAO_TOKEN="+root)
	startProc(t, bin, baseEnv, "server", "-dev", "-dev-root-token-id="+root, "-dev-listen-address="+strings.TrimPrefix(addr, "http://"))
	waitHTTP(t, addr+"/v1/sys/health")

	bao := func(args ...string) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = baseEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bao %v: %v\n%s", args, err, out)
		}
	}
	bao("secrets", "enable", "transit")
	keyGen, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyOnce.Do(func() {}) // keep newHarness from replacing the imported key
	testKey = keyGen
	der, err := x509.MarshalPKCS8PrivateKey(keyGen)
	if err != nil {
		t.Fatal(err)
	}
	bao("transit", "import", "transit/keys/gh-app-test", base64.StdEncoding.EncodeToString(der), "type=rsa-2048")

	// An Agent listener that injects its auto-auth token.
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	os.WriteFile(tokenFile, []byte(root), 0o600)
	agentAddr := "http://" + freeAddr(t)
	agentCfg := filepath.Join(dir, "agent.hcl")
	os.WriteFile(agentCfg, []byte(fmt.Sprintf(`
auto_auth {
  method "token_file" {
    config = { token_file_path = %q }
  }
}
api_proxy { use_auto_auth_token = true }
listener "tcp" {
  address     = %q
  tls_disable = true
}
`, tokenFile, strings.TrimPrefix(agentAddr, "http://"))), 0o600)
	startProc(t, bin, append(os.Environ(), "BAO_ADDR="+addr), "agent", "-config="+agentCfg)
	waitHTTP(t, agentAddr+"/v1/sys/health")

	t.Run("direct with BAO_TOKEN", func(t *testing.T) {
		h := newHarness(t, "")
		h.env["GH_LOGIN"] = testLogin
		h.env["GH_VAULT_APP_TOKEN_AGENT_ADDR"] = addr
		h.env["BAO_TOKEN"] = root
		code, out, errs := h.run("--owner", "acme", "--force")
		if code != 0 || out != "ghs_fake_77_1" {
			t.Fatalf("code=%d out=%q err=%s", code, out, errs)
		}
	})
	t.Run("via agent, no token", func(t *testing.T) {
		h := newHarness(t, "")
		h.env["GH_LOGIN"] = testLogin
		h.env["GH_VAULT_APP_TOKEN_AGENT_ADDR"] = agentAddr
		code, out, errs := h.run("--owner", "acme")
		if code != 0 || out != "ghs_fake_77_1" {
			t.Fatalf("code=%d out=%q err=%s", code, out, errs)
		}
		code, out, errs = h.run("--print-jwt")
		if code != 0 || strings.Count(out, ".") != 2 {
			t.Fatalf("code=%d out=%q err=%s", code, out, errs)
		}
	})
	t.Run("missing key", func(t *testing.T) {
		h := newHarness(t, "")
		h.env["GH_LOGIN"] = testLogin
		h.env["GH_VAULT_APP_TOKEN_AGENT_ADDR"] = agentAddr
		h.env["GH_VAULT_APP_TOKEN_CONFIG"] = writeConfig(t, "apps:\n  "+testLogin+":\n    app_id: 1001\n    transit_key: absent\n")
		code, _, errs := h.run("--owner", "acme")
		if code != 3 || !strings.Contains(errs, "HTTP 400") {
			t.Fatalf("code=%d err=%s", code, errs)
		}
	})
}

func writeConfig(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
