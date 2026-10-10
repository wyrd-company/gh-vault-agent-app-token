#!/usr/bin/env bash
# gh shim for agent containers: install as `gh` early on PATH. Every gh call
# runs with GH_TOKEN set to a GitHub App installation token minted by
# `gh vault-agent-app-token` for the current agent identity.
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
mint_args=()
prev=""
for a in "$@"; do
  case "$prev" in --repo | -R) mint_args=(--repo "$a"); break ;; esac
  case "$a" in
    --) break ;;
    --repo=* | -R=*) mint_args=(--repo "${a#*=}"); break ;;
    -R?*) mint_args=(--repo "${a#-R}"); break ;;
  esac
  prev="$a"
done

token="$("$real_gh" vault-agent-app-token ${mint_args[@]+"${mint_args[@]}"})" || exit $?

if [ "${1:-}" = "auth" ] && [ "${2:-}" = "status" ]; then
  # Isolated config dir so status reports the token, not a stored login.
  tmp_config="$(mktemp -d)"
  trap 'rm -rf "$tmp_config"' EXIT
  rc=0
  GH_TOKEN="$token" GH_CONFIG_DIR="$tmp_config" "$real_gh" "$@" || rc=$?
  exit "$rc"
fi

GH_TOKEN="$token" exec "$real_gh" "$@"
