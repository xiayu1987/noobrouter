#!/bin/sh
# Maintainer one-step release: bump version -> commit -> tag -> push.
# The tag triggers .github/workflows/release.yml, which tests, builds, packs and publishes the Release.
# Usage: sh deploy/release.sh <version>      e.g. sh deploy/release.sh 0.1.1
# Needs git, npm; gh is optional (only used to follow the workflow run). Works in Git Bash, WSL, Linux, macOS.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VER=${1:-}
case "$VER" in -h|--help|'') sed -n '2,5p' "$0"; exit 0 ;; esac
echo "$VER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "version must be X.Y.Z: $VER"; exit 2; }
TAG=v$VER
cd "$ROOT"
die() { echo "ABORT: $*"; exit 1; }

[ -z "$(git status --porcelain)" ] || die "uncommitted changes"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "not on main"
git fetch -q origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main differs from origin/main; pull/push first"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG already exists"

INIT=agent/noobrouter_agent/__init__.py
CUR=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$INIT")
[ "$CUR" != "$VER" ] || die "already at $VER"
echo "==> $CUR -> $VER"
sed -i.bak "s/^__version__ = \".*\"/__version__ = \"$VER\"/" "$INIT" && rm -f "$INIT.bak"
(cd web && npm version "$VER" --no-git-tag-version --allow-same-version >/dev/null)

git add "$INIT" web/package.json web/package-lock.json
git commit -q -m "Release $TAG"
git tag -a "$TAG" -m "$TAG"
git push -q origin main "$TAG"
echo "==> pushed $TAG; workflow: https://github.com/xiayu1987/noobrouter/actions/workflows/release.yml"
if command -v gh >/dev/null 2>&1; then
  sleep 5
  RUN=$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)
  [ -n "$RUN" ] && gh run watch "$RUN" --exit-status
fi
