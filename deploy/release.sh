#!/bin/sh
# Publish a GitHub Release: test -> build web -> pack -> gh release create.
# Nothing is pushed to any router; routers install themselves with deploy/get.sh.
# Usage: sh deploy/release.sh [--skip-build] [--skip-tests] [--dry]
#   --dry  build dist/ only, do not create the release
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=1; TESTS=1; DRY=0
for a in "$@"; do
  case "$a" in
    --skip-build) BUILD=0 ;;
    --skip-tests) TESTS=0 ;;
    --dry) DRY=1 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done
step() { printf '\n==> %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1"; exit 1; }; }
need python3; need tar; need sha256sum

if [ $TESTS = 1 ]; then step "unit tests"; (cd "$ROOT/agent" && python3 -m unittest discover -s tests -q); fi
if [ $BUILD = 1 ]; then
  step "build web"; need npm
  (cd "$ROOT/web" && { [ -d node_modules ] || npm ci; } && npm run build)
fi
step "pack"; sh "$ROOT/deploy/pack.sh"
cat "$ROOT/dist/noobrouter-agent.tar.gz.sha256"
[ $DRY = 1 ] && { step "dry: dist/ ready, no release created"; exit 0; }

need gh; need git
VER=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/agent/noobrouter_agent/__init__.py")
[ -z "$(git -C "$ROOT" status --porcelain)" ] || { echo "ABORT: uncommitted changes; commit first"; exit 1; }
step "release v$VER"
(cd "$ROOT" && gh release create "v$VER" --target "$(git rev-parse HEAD)" --title "v$VER" --generate-notes \
  dist/noobrouter-agent.tar.gz dist/noobrouter-agent.tar.gz.sha256 dist/get.sh)
step "done. on the router: curl -fsSL <release-url>/get.sh | sh -s -- --start"
