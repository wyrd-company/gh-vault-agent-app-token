---
relationships:
  references: internal/transit/transit
---
# gh-vault-agent-app-token

A GitHub CLI extension that mints a GitHub App **installation token** for an
agent harness. The App's private key never touches disk or this process: the
RS256 App JWT is signed remotely by the Transit secrets engine of
[OpenBao](https://openbao.org) or HashiCorp Vault, or by Azure Key Vault.
Transit normally uses a local Agent listener that injects its auto-auth token.

```sh
gh extension install wyrd-company/gh-vault-agent-app-token
GH_TOKEN="$(gh vault-agent-app-token)" gh pr list
```

## Usage

```
gh vault-agent-app-token [--owner OWNER] [--login LOGIN] [--repo [HOST/]OWNER/REPO] [--hostname HOST] [--force] [--json]
gh vault-agent-app-token --print-jwt            # debugging: emit the signed App JWT only
gh vault-agent-app-token --list                 # print known logins and their configured keys
```

Other flags: `--agent-addr URL`, `--verbose` (or `GH_DEBUG=1`) to log requests
to stderr with credentials redacted.

By default the token is written to stdout with no trailing newline. `--json`
prints `{"token","expires_at","login","owner","installation_id"}`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 2 | usage, identity, owner or config error; App not installed on the owner |
| 3 | Signing backend unreachable, authentication denied, or signing failed (backend error included) |
| 4 | GitHub API error (HTTP status and message included) |

## Configuration

The first file found of `$GH_VAULT_APP_TOKEN_CONFIG`,
`$XDG_CONFIG_HOME/gh-vault-agent-app-token/config.yml`,
`~/.config/gh-vault-agent-app-token/config.yml`:

```yaml
agent_addr: http://127.0.0.1:8100   # optional
transit_mount: transit               # optional, default "transit"

# Which login to use when a harness's environment marker is set.
harnesses:
  claude: example-claude[bot]        # CLAUDECODE
  codex: example-codex[bot]          # CODEX_THREAD_ID
  cursor: example-cursor[bot]        # CURSOR_AGENT
  pi: example-pi[bot]                # PI_CODING_AGENT
  copilot: example-copilot[bot]      # COPILOT_CLI
  antigravity: example-antigravity[bot] # ANTIGRAVITY_AGENT

apps:
  example-claude[bot]:
    app_id: 123456
    transit_key: gh-app-example-claude
    installations:                   # optional; skips GET /app/installations
      example-org: 11111111
  example-codex[bot]:
    app_id: 234567
    transit_key: gh-app-example-codex
```

Each App defaults to `signer: transit`, so existing configurations work without
changes. To sign with Azure Key Vault, use this App configuration instead:

```yaml
apps:
  example-codex[bot]:
    app_id: 234567
    signer: azure-key-vault
    azure_key_vault:
      vault_url: https://example.vault.azure.net
      key_name: gh-app-example-codex
      key_version: abc123                    # optional; omit for the latest version
      credential: azure-cli                  # optional, default "default"
```

`transit_key` and `azure_key_vault` are mutually exclusive. A single config may
contain Apps using different backends. `--list` shows each App's signer and key.
Azure signing ignores the Transit address, token, and TLS settings below.

### Which App (login)

1. `--login`
2. `GH_LOGIN`
3. Harness markers, checked in order `CLAUDECODE`, `CODEX_THREAD_ID`,
   `CURSOR_AGENT`, `PI_CODING_AGENT`, `COPILOT_CLI`, `ANTIGRAVITY_AGENT`, mapped
   to a login through `harnesses:`.
4. Otherwise exit 2.

Copilot CLI exports `COPILOT_CLI` (observed as `true`), and the Antigravity local
harness exports `ANTIGRAVITY_AGENT` (observed as `1`). As with the existing
markers, a non-empty value selects the corresponding `harnesses:` mapping.
Shared editor/SDK variables such as `CLAUDE_AGENT_SDK_VERSION` do not select a
harness. If a wrapper strips the marker, set `GH_LOGIN` or use `--login`.

Multiple harnesses can map to the same configured App login. A detected harness
without a mapping exits 2 rather than falling through to another identity.

A resolved login without an `apps:` entry is exit 2 `no app configured for '<login>'`.

### Which installation (owner)

`--owner`; the owner of `--repo` (`OWNER/REPO` or `HOST/OWNER/REPO`); the owner
of `GH_REPO`; `GH_OWNER`; `GH_ORG`; the owner of the `origin` remote of the
current git repo (https or ssh GitHub URLs, or `GH_HOST`). A static
`installations:` entry wins; otherwise the App's installations are listed and
matched on `account.login`, case-insensitively.

The GitHub host is `--hostname`, else the one in a host-qualified `--repo` or
`GH_REPO`, else `GH_HOST`, else github.com. GitHub Enterprise Server hosts use
`https://HOST/api/v3`; `*.ghe.com` hosts use `https://api.HOST`.

### Agent address and credentials

First set wins: `--agent-addr`, `GH_VAULT_APP_TOKEN_AGENT_ADDR`, config
`agent_addr`, `BAO_AGENT_ADDR`, `VAULT_AGENT_ADDR`, `BAO_ADDR`, `VAULT_ADDR`,
`http://127.0.0.1:8100`.

Addresses can use `http://`, `https://`, or `unix://<absolute socket path>`.
For example, Wyrwood exposes the OpenBao API through a Unix socket:

```sh
export VAULT_ADDR=unix:///run/wyrwood/vault.sock
export BAO_ADDR=unix:///run/wyrwood/vault.sock
gh vault-agent-app-token --print-jwt
```

Wyrwood adds the container's token to each request. Unix socket requests use
HTTP over the socket and ignore HTTP proxy and TLS settings
(`BAO_CACERT`/`VAULT_CACERT`, `BAO_SKIP_VERIFY`/`VAULT_SKIP_VERIFY`).

No token header is sent unless `BAO_TOKEN` or `VAULT_TOKEN` is set, in which
case it is sent as `X-Vault-Token` (useful for talking to a server directly).
For `https://`, `BAO_CACERT`/`VAULT_CACERT` and
`BAO_SKIP_VERIFY`/`VAULT_SKIP_VERIFY` are honoured.

## Transit setup

Import each App's private key once, then delete the PEM:

```sh
bao secrets enable transit
openssl pkcs8 -topk8 -nocrypt -in app.pem -outform DER | base64 -w0 > key.b64
bao transit import transit/keys/gh-app-example-claude "$(cat key.b64)" type=rsa-2048
shred -u app.pem key.b64
```

The Agent's token needs only:

```hcl
path "transit/sign/gh-app-example-claude" { capabilities = ["update"] }
```

and an Agent config exposing the API proxy:

```hcl
api_proxy { use_auto_auth_token = true }
listener "tcp" {
  address     = "127.0.0.1:8100"
  tls_disable = true
}
```

## Azure Key Vault setup

Import the RSA private key generated by GitHub as a Key Vault **key**, rather
than storing the PEM as a secret. The extension only requests signatures; it
does not download keys or read secrets. A Standard vault with a software-backed
RSA key is sufficient.

Using a separate setup identity with permission to import keys:

```sh
az keyvault key import --vault-name <vault-name> \
  --name gh-app-example-codex --pem-file app.pem --ops sign
```

Remove the local PEM after verifying the import. See the
[Azure CLI import reference](https://learn.microsoft.com/en-us/cli/azure/keyvault/key#az-keyvault-key-import).

The runtime Azure identity needs the `keys/sign` data-plane permission for this
key. With Azure RBAC, `Key Vault Crypto User` permits signing and other crypto
operations; a custom role with only
`Microsoft.KeyVault/vaults/keys/sign/action` provides narrower access. Keep the
setup identity's import/management permissions separate from the agent. See
[Key Vault access control](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide).

Supported `credential` values:

- `azure-cli`: uses the identity selected by `az login` on this machine.
- `managed-identity`: uses the hosting Azure resource's managed identity;
  set `AZURE_CLIENT_ID` to select a user-assigned identity.
- `workload-identity`: uses `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
  `AZURE_FEDERATED_TOKEN_FILE` for federated authentication.
- `default` (or omitted): uses the SDK's `DefaultAzureCredential` chain,
  including environment, workload identity, managed identity, and developer
  credentials. For hosted agents, select an explicit credential to avoid
  falling through to a developer login.

See [Azure authentication](https://learn.microsoft.com/en-us/azure/developer/go/sdk/authentication/credential-chains).
The agent also needs network access to the vault and the authentication
endpoints required by its selected credential.

Key Vault signs the SHA-256 digest of the JWT input using RS256. Each signing
attempt, including authentication and SDK retries, has a 30-second deadline.
`--verbose` logs Key Vault requests through the same credential-redacting logger
used for Transit and GitHub; request/response bodies are not logged.

For rotation, generate a new private key in GitHub, import it as a new Key Vault
key version, update `key_version` when pinned, and verify signing before revoking
the old GitHub key. Do not use Key Vault's automatic key generation/rotation for
this imported key: GitHub will not recognize the newly generated public key.
[GitHub's private-key guidance](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)
explains the overlapping-key rotation process.

Signing permission grants the ability to authenticate as the App across its
installations. Harness mappings select an App; enforce identity separation in
Azure permissions. `--repo` selects an installation owner, without narrowing the
installation token to that single repository. Installation tokens are still
cached locally and passed to `gh` through its environment.

## Token cache

Installation tokens (never JWTs) are cached in
`$XDG_CACHE_HOME/gh-vault-agent-app-token` (else `~/.cache/...`, mode 0700),
one file per `<login>__<owner>` (plus `__<host>` for hosts other than
github.com; mode 0600, content
`<expires_epoch>\t<token>\t<installation_id>\t<app_id>\n`), and reused while
more than 300 s remain and the entry was minted by the configured App. A per-entry lock file serialises concurrent invocations.
`--force` skips the cache.

## gh shim

[`contrib/gh-shim.sh`](contrib/gh-shim.sh) is a drop-in `gh` wrapper for agent
containers and shared shell setups. Put it on `PATH` ahead of the real `gh` as
`gh`. It uses App authentication only when `GH_LOGIN` or a supported harness
marker (`CLAUDECODE`, `CODEX_THREAD_ID`, `CURSOR_AGENT`, `PI_CODING_AGENT`,
`COPILOT_CLI`, or `ANTIGRAVITY_AGENT`) is nonempty. Otherwise it passes the call
straight through to the real `gh`, leaving authentication and configuration
unchanged. This works independently of which shell launches the command.

For calls using App authentication, it obtains a token (reusing the extension's
cache when valid, and passing `--repo`/`-R` and `--hostname`, or `-h` for `gh auth`,
through so owner and host match), drops any inherited `GH_TOKEN`,
`GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN` and `GITHUB_ENTERPRISE_TOKEN`, sets
`GH_TOKEN` (or `GH_ENTERPRISE_TOKEN` when the target is a GitHub Enterprise
Server host) and execs the real `gh`. `gh auth status` runs against a temporary
`GH_CONFIG_DIR`. If an agent is detected but its identity is not configured, or
token acquisition fails, the shim exits with the extension's code; it never
falls back to a user login for that call. Unsupported harnesses can opt in with
`GH_LOGIN`. Direct `gh vault-agent-app-token` calls always reach the extension.

## Development

Go 1.25 or later is required by the Azure SDK dependencies.

```sh
go test ./...
bash contrib/test-shim.sh
# Azure signing tests use a fake Key Vault transport and credential (no Azure account needed).
# integration test against a real OpenBao dev server (bao on PATH or BAO_BIN)
go test -tags integration -run Integration -v ./internal/cli/
```

Releases: push a version tag without a `v` prefix (e.g. `1.2.0`; a tag
containing `-` becomes a prerelease); the workflow publishes
`gh-vault-agent-app-token_<tag>_<os>-<arch>` binaries for linux/amd64,
linux/arm64, darwin/arm64 and windows/amd64.
