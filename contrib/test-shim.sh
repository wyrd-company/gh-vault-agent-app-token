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

check "GHES via GH_HOST" "enterprise=tok[] token= args=pr list" "$(GH_HOST=ghe.example.com GH_TOKEN=user GH_ENTERPRISE_TOKEN=user-ghes gh pr list)"
check "GHES via --repo" "enterprise=tok[--repo GHE.example.com/o/r] token= args=pr list -R GHE.example.com/o/r" "$(gh pr list -R GHE.example.com/o/r)"
check "GHES via GH_REPO" "enterprise=tok[] token= args=pr list" "$(GH_REPO=ghe.example.com/o/r gh pr list)"
check "github.com --repo beats GH_HOST" "token=tok[--repo github.com/o/r] config=unset args=pr list --repo github.com/o/r" "$(GH_HOST=ghe.example.com gh pr list --repo github.com/o/r)"
check "ghe.com uses GH_TOKEN" "token=tok[] config=unset args=pr list" "$(GH_HOST=acme.ghe.com gh pr list)"
check "--hostname GHES" "enterprise=tok[--hostname ghe.example.com] token= args=api --hostname ghe.example.com /meta" "$(GH_HOST=github.com GH_ENTERPRISE_TOKEN=user gh api --hostname ghe.example.com /meta)"
check "--hostname= github.com" "token=tok[--hostname github.com] config=unset args=api --hostname=github.com /meta" "$(GH_HOST=ghe.example.com gh api --hostname=github.com /meta)"
check "auth -h GHES" "enterprise=tok[--hostname ghe.example.com] token= args=auth token -h ghe.example.com" "$(gh auth token -h ghe.example.com)"
check "-h is not hostname outside auth" "token=tok[] config=unset args=pr list -h x" "$(gh pr list -h x)"
check "inherited GITHUB_TOKEN dropped" "token=tok[] config=unset args=pr list" "$(GITHUB_TOKEN=user GITHUB_ENTERPRISE_TOKEN=user gh pr list)"
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

# With the real gh: its own credential selection must yield the App token for
# the target host even when user tokens are inherited.
real="$(PATH="${PATH#"$work/shim:$work/real:"}" command -v gh || true)"
if [ -n "$real" ]; then
  mkdir -p "$work/data/gh/extensions/gh-vault-agent-app-token" "$work/config"
  mkdir -p "$work/realshim" && ln -s "$here/gh-shim.sh" "$work/realshim/gh"
  ext="$work/data/gh/extensions/gh-vault-agent-app-token/gh-vault-agent-app-token"
  printf '#!/usr/bin/env bash\nprintf fake-app-token\n' >"$ext"
  chmod +x "$ext"
  run_real() {
    env PATH="$work/realshim:$(dirname "$real"):/usr/bin:/bin" XDG_DATA_HOME="$work/data" GH_CONFIG_DIR="$work/config" \
      GH_TOKEN=fake-user-token GITHUB_TOKEN=fake-user-token \
      GH_ENTERPRISE_TOKEN=fake-user-token GITHUB_ENTERPRISE_TOKEN=fake-user-token "$@"
  }
  check "real gh: github.com" fake-app-token "$(run_real gh auth token --hostname github.com 2>&1)"
  check "real gh: --hostname GHES" fake-app-token "$(run_real env GH_HOST=github.com gh auth token --hostname ghe.example.com 2>&1)"
  check "real gh: -h GHES" fake-app-token "$(run_real gh auth token -h ghe.example.com 2>&1)"
  check "real gh: GH_HOST GHES" fake-app-token "$(run_real env GH_HOST=ghe.example.com gh auth token 2>&1)"
else
  echo "skip real gh checks (gh not found)"
fi

[ "$fails" -eq 0 ] || { echo "$fails failure(s)"; exit 1; }
