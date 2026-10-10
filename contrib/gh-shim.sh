#!/usr/bin/env bash
# gh shim for agent containers: install as `gh` early on PATH. Every gh call
# runs with GH_TOKEN (GH_ENTERPRISE_TOKEN for GitHub Enterprise Server) set to
# a GitHub App installation token minted by `gh vault-agent-app-token` for the
# current agent identity.
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

# An explicit --repo/-R selects the installation owner, as gh would use it.
# (GH_REPO is read by the extension itself.)
repo=""
prev=""
for a in "$@"; do
  case "$prev" in --repo | -R) repo="$a"; break ;; esac
  case "$a" in
    --) break ;;
    --repo=* | -R=*) repo="${a#*=}"; break ;;
    -R?*) repo="${a#-R}"; break ;;
  esac
  prev="$a"
done
mint_args=()
[ -n "$repo" ] && mint_args=(--repo "$repo")

token="$("$real_gh" vault-agent-app-token ${mint_args[@]+"${mint_args[@]}"})" || exit $?

# gh reads GH_TOKEN for github.com (and *.ghe.com) but GH_ENTERPRISE_TOKEN for
# GitHub Enterprise Server hosts. Resolve the target host the same way the
# extension does: host-qualified --repo, then GH_REPO, then GH_HOST.
target="${repo:-${GH_REPO:-}}"
host="${GH_HOST:-github.com}"
case "$target" in */*/*) host="${target%%/*}" ;; esac
host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
case "$host" in
  github.com | *.ghe.com) token_var=GH_TOKEN ;;
  *) token_var=GH_ENTERPRISE_TOKEN ;;
esac
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
