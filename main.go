// Command gh-vault-agent-app-token is a GitHub CLI extension that mints a
// GitHub App installation token whose JWT is signed by OpenBao/Vault Transit.
package main

import (
	"os"

	"github.com/wyrd-company/gh-vault-agent-app-token/internal/cli"
)

func main() { os.Exit(cli.Main()) }
