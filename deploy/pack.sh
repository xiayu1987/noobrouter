#!/bin/sh
# Build the release files into dist/:
#   noobrouter-agent.tar.gz          (contains noobrouter-agent-<ver>/)
#   noobrouter-agent.tar.gz.sha256
#   get.sh                           (router-side one-step installer)
# Stable file names so get.sh can use .../releases/latest/download/<name>.
# Requires web/dist (run `npm run build` in web/ first). Run in WSL/Linux.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$ROOT/web/dist/index.html" ] || { echo "web/dist missing: cd web && npm run build"; exit 1; }
VER=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/agent/noobrouter_agent/__init__.py")
[ -n "$VER" ] || { echo "__version__ not found in agent/noobrouter_agent/__init__.py"; exit 1; }
STAGE=$(mktemp -d); N=noobrouter-agent-$VER
mkdir -p "$STAGE/$N"
cp -R "$ROOT/agent/noobrouter_agent" "$STAGE/$N/"
cp -R "$ROOT/web/dist" "$STAGE/$N/web"
cp "$ROOT/deploy/install.sh" "$ROOT/deploy/noobrouter-agent.service" "$ROOT/deploy/noobrouter-agent.example.json" "$STAGE/$N/"
find "$STAGE" -name __pycache__ -type d -prune -exec rm -rf {} +
OUT=$ROOT/dist; mkdir -p "$OUT"
rm -f "$OUT"/noobrouter-agent-*.tar.gz  # old versioned name
tar -C "$STAGE" -czf "$OUT/noobrouter-agent.tar.gz" "$N"
rm -rf "$STAGE"
(cd "$OUT" && sha256sum noobrouter-agent.tar.gz > noobrouter-agent.tar.gz.sha256)
cp "$ROOT/deploy/get.sh" "$OUT/get.sh"
echo "$OUT/noobrouter-agent.tar.gz"
