#!/usr/bin/env bash
# Build release binaries in the gh extension asset layout:
#   dist/gh-vault-agent-app-token_<tag>_<os>-<arch>[.exe]
# Invoked by cli/gh-extension-precompile with the release tag as $1.
set -euo pipefail

tag="${1:?usage: script/build.sh TAG}"
name="gh-vault-agent-app-token"
platforms=(linux-amd64 linux-arm64 darwin-arm64 windows-amd64)

mkdir -p dist
for p in "${platforms[@]}"; do
  goos="${p%-*}"
  goarch="${p#*-}"
  ext=""
  [ "$goos" = windows ] && ext=".exe"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "dist/${name}_${tag}_${p}${ext}" .
done
