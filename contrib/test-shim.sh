#!/usr/bin/env bash
# Tests for contrib/gh-shim.sh against a fake "real" gh.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/shim" "$work/real"
ln -s "$here/gh-shim.sh" "$work/shim/gh"

cat >"$work/real/gh" <<'FAKE'
#!/usr/bin/env bash
if [ "${1:-}" = vault-agent-app-token ]; then
  shift
  [ -n "${FAKE_MINT_FAIL:-}" ] && { echo "gh vault-agent-app-token: transit down" >&2; exit 3; }
  printf 'tok[%s]' "$*"
  exit 0
fi
printf 'token=%s config=%s args=%s\n' "${GH_TOKEN:-}" "${GH_CONFIG_DIR:-unset}" "$*"
FAKE
chmod +x "$work/real/gh"

export PATH="$work/shim:$work/real:$PATH"
unset GH_TOKEN GH_CONFIG_DIR
fails=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want [$2] got [$3]"; fails=$((fails + 1)); fi
}

check "plain" "token=tok[] config=unset args=pr list" "$(gh pr list)"
check "--repo X" "token=tok[--repo o/r] config=unset args=pr list --repo o/r" "$(gh pr list --repo o/r)"
check "-R X" "token=tok[--repo o/r] config=unset args=pr list -R o/r" "$(gh pr list -R o/r)"
check "--repo=X" "token=tok[--repo o/r] config=unset args=pr list --repo=o/r" "$(gh pr list --repo=o/r)"
check "-RX" "token=tok[--repo o/r] config=unset args=pr list -Ro/r" "$(gh pr list -Ro/r)"
check "after --" "token=tok[] config=unset args=api -- --repo o/r" "$(gh api -- --repo o/r)"

out="$(gh auth status)"
case "$out" in "token=tok[] config=/"*" args=auth status") r=ok ;; *) r="$out" ;; esac
check "auth status uses temp config" ok "$r"

rc=0
err="$(FAKE_MINT_FAIL=1 gh pr list 2>&1 >/dev/null)" || rc=$?
check "mint failure exit code" 3 "$rc"
check "mint failure stderr" "gh vault-agent-app-token: transit down" "$err"

check "extension passthrough" "tok[--json]" "$(gh vault-agent-app-token --json)"

[ "$fails" -eq 0 ] || { echo "$fails failure(s)"; exit 1; }
