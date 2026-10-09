#!/bin/sh
# Build a release tarball: dist/noobrouter-agent-<ver>.tar.gz
# Requires web/dist (run `npm run build` in web/ first). Run in WSL/Linux.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$ROOT/web/dist/index.html" ] || { echo "web/dist missing: cd web && npm run build"; exit 1; }
VER=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/agent/noobrouter_agent/__init__.py")
VER=${VER:-0.1.0}
STAGE=$(mktemp -d); N=noobrouter-agent-$VER
mkdir -p "$STAGE/$N"
cp -R "$ROOT/agent/noobrouter_agent" "$STAGE/$N/"
cp -R "$ROOT/web/dist" "$STAGE/$N/web"
cp "$ROOT/deploy/install.sh" "$ROOT/deploy/noobrouter-agent.service" "$ROOT/deploy/noobrouter-agent.example.json" "$STAGE/$N/"
find "$STAGE" -name __pycache__ -type d -prune -exec rm -rf {} +
mkdir -p "$ROOT/dist"
tar -C "$STAGE" -czf "$ROOT/dist/$N.tar.gz" "$N"
rm -rf "$STAGE"
echo "$ROOT/dist/$N.tar.gz"
