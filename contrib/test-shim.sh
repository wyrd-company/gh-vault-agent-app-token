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
if [ -n "${GH_ENTERPRISE_TOKEN:-}" ]; then
  printf 'enterprise=%s token=%s args=%s\n' "$GH_ENTERPRISE_TOKEN" "${GH_TOKEN:-}" "$*"
  exit 0
fi
printf 'token=%s config=%s args=%s\n' "${GH_TOKEN:-}" "${GH_CONFIG_DIR:-unset}" "$*"
FAKE
chmod +x "$work/real/gh"

export PATH="$work/shim:$work/real:$PATH"
unset GH_TOKEN GH_CONFIG_DIR GH_ENTERPRISE_TOKEN GH_HOST GH_REPO
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

check "GHES via GH_HOST" "enterprise=tok[] token=user args=pr list" "$(GH_HOST=ghe.example.com GH_TOKEN=user GH_ENTERPRISE_TOKEN=user-ghes gh pr list)"
check "GHES via --repo" "enterprise=tok[--repo GHE.example.com/o/r] token= args=pr list -R GHE.example.com/o/r" "$(gh pr list -R GHE.example.com/o/r)"
check "GHES via GH_REPO" "enterprise=tok[] token= args=pr list" "$(GH_REPO=ghe.example.com/o/r gh pr list)"
check "github.com --repo beats GH_HOST" "token=tok[--repo github.com/o/r] config=unset args=pr list --repo github.com/o/r" "$(GH_HOST=ghe.example.com gh pr list --repo github.com/o/r)"
check "ghe.com uses GH_TOKEN" "token=tok[] config=unset args=pr list" "$(GH_HOST=acme.ghe.com gh pr list)"
out="$(GH_HOST=ghe.example.com gh auth status)"
case "$out" in "enterprise=tok[] token= args=auth status") r=ok ;; *) r="$out" ;; esac
check "GHES auth status" ok "$r"

out="$(gh auth status)"
case "$out" in "token=tok[] config=/"*" args=auth status") r=ok ;; *) r="$out" ;; esac
check "auth status uses temp config" ok "$r"

rc=0
err="$(FAKE_MINT_FAIL=1 gh pr list 2>&1 >/dev/null)" || rc=$?
check "mint failure exit code" 3 "$rc"
check "mint failure stderr" "gh vault-agent-app-token: transit down" "$err"

check "extension passthrough" "tok[--json]" "$(gh vault-agent-app-token --json)"

[ "$fails" -eq 0 ] || { echo "$fails failure(s)"; exit 1; }
