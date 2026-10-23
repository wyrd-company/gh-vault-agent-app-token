#!/usr/bin/env bash
# gh shim: install as `gh` early on PATH. Calls with a known agent marker or
# explicit GH_LOGIN run with GH_TOKEN (GH_ENTERPRISE_TOKEN for GHES) set to
# a GitHub App installation token minted by `gh vault-agent-app-token` for the
# current agent identity. Other calls pass through with authentication unchanged.
#
# If minting fails, its stderr is shown and the shim exits with its code;
# there is no fallback to a user login.
set -euo pipefail

# Real gh = first gh on PATH that is not this shim (avoid self-recursion).
self="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
real_gh=""
IFS=: read -r -a path_dirs <<<"$PATH"
for d in "${path_dirs[@]}"; do
  c="${d:-.}/gh"
  [ -f "$c" ] && [ -x "$c" ] || continue
  [ "$(readlink -f "$c" 2>/dev/null || printf '%s' "$c")" = "$self" ] && continue
  real_gh="$c"
  break
done
[ -n "$real_gh" ] || { echo "gh-shim: no real gh found on PATH" >&2; exit 127; }

# Nothing to authenticate, or the extension itself: pass straight through.
case "${1:-}" in
  "" | vault-agent-app-token) exec "$real_gh" "$@" ;;
esac

# Only intercept calls that request an App identity. Keep the harness marker
# list in sync with internal/identity.Markers; empty values do not opt in.
agent=0
for marker in GH_LOGIN CLAUDECODE CODEX_THREAD_ID CURSOR_AGENT PI_CODING_AGENT COPILOT_CLI ANTIGRAVITY_AGENT; do
  if [ -n "${!marker:-}" ]; then
    agent=1
    break
  fi
done
[ "$agent" -eq 1 ] || exec "$real_gh" "$@"

# An explicit --repo/-R selects the installation owner, and --hostname (-h
# for `gh auth`) the host, as gh would use them. (GH_REPO is read by the
# extension itself.)
repo=""
hostname=""
prev=""
for a in "$@"; do
  case "$prev" in
    --repo | -R) repo="$a" ;;
    --hostname) hostname="$a" ;;
    -h) [ "${1:-}" = auth ] && hostname="$a" ;;
  esac
  case "$a" in
    --) break ;;
    --repo=* | -R=*) repo="${a#*=}" ;;
    -R?*) repo="${a#-R}" ;;
    --hostname=*) hostname="${a#*=}" ;;
    -h=*) [ "${1:-}" = auth ] && hostname="${a#*=}" ;;
  esac
  prev="$a"
done
mint_args=()
[ -n "$repo" ] && mint_args+=(--repo "$repo")
[ -n "$hostname" ] && mint_args+=(--hostname "$hostname")

token="$("$real_gh" vault-agent-app-token ${mint_args[@]+"${mint_args[@]}"})" || exit $?

# gh reads GH_TOKEN for github.com (and *.ghe.com) but GH_ENTERPRISE_TOKEN for
# GitHub Enterprise Server hosts. Resolve the target host the same way the
# extension does: --hostname, host-qualified --repo, GH_REPO, then GH_HOST.
# Inherited credentials are dropped so none can stand in for the App token.
target="${repo:-${GH_REPO:-}}"
host="${GH_HOST:-github.com}"
case "$target" in */*/*) host="${target%%/*}" ;; esac
[ -n "$hostname" ] && host="$hostname"
host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
case "$host" in
  github.com | *.ghe.com) token_var=GH_TOKEN ;;
  *) token_var=GH_ENTERPRISE_TOKEN ;;
esac
unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN
export "$token_var=$token"

if [ "${1:-}" = "auth" ] && [ "${2:-}" = "status" ]; then
  # Isolated config dir so status reports the token, not a stored login.
  tmp_config="$(mktemp -d)"
  trap 'rm -rf "$tmp_config"' EXIT
  rc=0
  GH_CONFIG_DIR="$tmp_config" "$real_gh" "$@" || rc=$?
  exit "$rc"
fi

exec "$real_gh" "$@"
