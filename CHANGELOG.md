# Changelog

## 0.4.0

Released 2026-10-23.

### Features

- Use `gh --as-user <command>` to skip App authentication for one command and use the stored GitHub CLI login for the target host.

## 0.3.1

Released 2026-10-23.

### Fixes

- The `gh` shim only mints an App token for recognized agent calls or an explicit `GH_LOGIN`. Unmarked calls keep their existing GitHub CLI authentication and configuration.

## 0.3.0

Released 2026-10-23.

### Features

- Detect GitHub Copilot CLI and Antigravity and select their configured GitHub App logins.

## 0.2.0

Released 2026-10-23.

### Features

- Sign GitHub App JWTs with Azure Key Vault as an alternative to OpenBao or Vault Transit.

### Fixes

- Invalidate cached tokens when the configured GitHub App installation changes.
- Initialize Transit only when signing is needed, so cached tokens remain usable without contacting the signing backend.

## 0.1.1

Released 2026-10-16.

### Fixes

- Connect to an OpenBao or Vault Agent over a Unix socket using a `unix://` agent address.

## 0.1.0

Released 2026-10-10.

### Features

- Mint GitHub App installation tokens with JWTs signed by OpenBao or Vault Transit, without loading the App's private key into the extension.
- Choose an App from the environment or CLI and resolve its installation on GitHub.com or GitHub Enterprise. Cache tokens until shortly before they expire.
- Use the optional `gh` shim to authenticate GitHub CLI commands with the minted token.
