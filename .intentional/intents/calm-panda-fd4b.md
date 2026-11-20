---
gh-vault-agent-app-token: minor
---

Support Grok Build in the token command and `gh` shim. Map `harnesses.grok` to a configured GitHub App login before upgrading if you already use the shim in Grok. Grok shell calls, including commands you type in `!` mode, use that App by default; use `!gh --as-user …` to use your stored GitHub CLI login for one command.
