# gh-vault-agent-app-token

A GitHub CLI extension that mints a GitHub App **installation token** for an
agent harness. The App's private key never touches disk or this process: the
RS256 App JWT is signed by the Transit secrets engine of
[OpenBao](https://openbao.org) or HashiCorp Vault, normally through a local
Agent listener that injects its auto-auth token.

```sh
gh extension install wyrd-company/gh-vault-agent-app-token
GH_TOKEN="$(gh vault-agent-app-token)" gh pr list
```

## Usage

```
gh vault-agent-app-token [--owner OWNER] [--login LOGIN] [--repo OWNER/REPO] [--force] [--json]
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
| 3 | Agent/Transit unreachable or signing failed (HTTP status and `errors[]` included) |
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

### Which App (login)

1. `--login`
2. `GH_LOGIN`
3. Harness markers, checked in order `CLAUDECODE`, `CODEX_THREAD_ID`,
   `CURSOR_AGENT`, `PI_CODING_AGENT`, mapped to a login through `harnesses:`.
4. Otherwise exit 2.

A resolved login without an `apps:` entry is exit 2 `no app configured for '<login>'`.

### Which installation (owner)

`--owner`; the owner of `--repo` (`OWNER/REPO` or `HOST/OWNER/REPO`); the owner
of `GH_REPO`; `GH_OWNER`; `GH_ORG`; the owner of the `origin` remote of the
current git repo (https or ssh GitHub URLs, or `GH_HOST`). A static
`installations:` entry wins; otherwise the App's installations are listed and
matched on `account.login`, case-insensitively.

The GitHub host is the one in a host-qualified `--repo` or `GH_REPO`, else
`GH_HOST`, else github.com. GitHub Enterprise Server hosts use
`https://HOST/api/v3`; `*.ghe.com` hosts use `https://api.HOST`.

### Agent address and credentials

First set wins: `--agent-addr`, `GH_VAULT_APP_TOKEN_AGENT_ADDR`, config
`agent_addr`, `BAO_AGENT_ADDR`, `VAULT_AGENT_ADDR`, `BAO_ADDR`, `VAULT_ADDR`,
`http://127.0.0.1:8100`.

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
containers. Put it on `PATH` ahead of the real `gh` as `gh`. It mints a token
for every call (passing `--repo`/`-R` through so the owner matches), sets
`GH_TOKEN` (or `GH_ENTERPRISE_TOKEN` when the target is a GitHub Enterprise
Server host) and execs the real `gh`. `gh auth status` runs against a temporary
`GH_CONFIG_DIR`. If minting fails the shim exits with the extension's code;
it never falls back to a user login.

## Development

```sh
go test ./...
bash contrib/test-shim.sh
# integration test against a real OpenBao dev server (bao on PATH or BAO_BIN)
go test -tags integration -run Integration -v ./internal/cli/
```

Releases: push a version tag without a `v` prefix (e.g. `1.2.0`; a tag
containing `-` becomes a prerelease); the workflow publishes
`gh-vault-agent-app-token_<tag>_<os>-<arch>` binaries for linux/amd64,
linux/arm64, darwin/arm64 and windows/amd64.
