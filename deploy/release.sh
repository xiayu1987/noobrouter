#!/bin/sh
# One-step release: test -> build web -> pack -> upload -> install.sh --start -> health check.
# Runs on a Linux/macOS build machine. Never edits the target's config (dry_run stays as it is).
# Usage: sh deploy/release.sh [options] <[user@]host>
set -eu

usage() {
  cat <<'EOF'
Usage: sh deploy/release.sh [options] <[user@]host>

  -p PORT        SSH port
  -i FILE        SSH identity file
  -F FILE        SSH config file
  --skip-build   reuse existing web/dist (no npm build)
  --skip-tests   skip agent unit tests
  --with-deps    pass --with-deps to install.sh (apt install router packages)
  --no-start     install only, do not restart the service
  --force        deploy even if an unconfirmed firewall/init change is pending
  -h, --help     show this help

Remote user must be root or have passwordless sudo.
EOF
}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SSH_OPTS=""; HOST=""; BUILD=1; TESTS=1; DEPS=0; START=1; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -p) SSH_OPTS="$SSH_OPTS -P $2"; shift 2 ;;
    -i) SSH_OPTS="$SSH_OPTS -i $2"; shift 2 ;;
    -F) SSH_OPTS="$SSH_OPTS -F $2"; shift 2 ;;
    --skip-build) BUILD=0; shift ;;
    --skip-tests) TESTS=0; shift ;;
    --with-deps) DEPS=1; shift ;;
    --no-start) START=0; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $1"; usage; exit 2 ;;
    *) [ -z "$HOST" ] || { echo "only one host allowed"; exit 2; }; HOST=$1; shift ;;
  esac
done
[ -n "$HOST" ] || { usage; exit 2; }
# scp takes -P for the port, ssh takes -p
SCP_OPTS=$SSH_OPTS
SSH_OPTS=$(printf '%s' "$SSH_OPTS" | sed 's/ -P / -p /g')

step() { printf '\n==> %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1"; exit 1; }; }
need ssh; need scp; need tar; need python3

if [ $TESTS = 1 ]; then
  step "unit tests"
  (cd "$ROOT/agent" && python3 -m unittest discover -s tests -q)
fi

if [ $BUILD = 1 ]; then
  step "build web"
  need npm
  (cd "$ROOT/web" && { [ -d node_modules ] || npm ci; } && npm run build)
fi

step "pack"
TGZ=$(sh "$ROOT/deploy/pack.sh" | tail -n 1)
if command -v sha256sum >/dev/null 2>&1; then SUM=$(sha256sum "$TGZ" | cut -d' ' -f1)
else SUM=$(shasum -a 256 "$TGZ" | cut -d' ' -f1); fi
echo "$TGZ  sha256=$SUM"

step "upload to $HOST"
# shellcheck disable=SC2086
RTMP=$(ssh $SSH_OPTS "$HOST" "mktemp -d /tmp/noobrouter-release.XXXXXX")
case "$RTMP" in /tmp/noobrouter-release.*) ;; *) echo "remote mktemp failed: $RTMP"; exit 1 ;; esac
# shellcheck disable=SC2086
scp -q $SCP_OPTS "$TGZ" "$HOST:$RTMP/release.tgz" || { ssh $SSH_OPTS "$HOST" "rm -rf $RTMP"; exit 1; }

step "install on $HOST"
# ssh joins remote args with spaces, so every arg must be non-empty (flags are 0/1)
# shellcheck disable=SC2086
ssh $SSH_OPTS "$HOST" sh -s -- "$RTMP" "$SUM" "$FORCE" "$DEPS" "$START" <<'REMOTE'
set -eu
RTMP=$1
trap 'rm -rf "$RTMP"' EXIT
SUM=$2; FORCE=$3; DEPS=$4; START=$5
ARGS=""
[ "$START" = 1 ] && ARGS="$ARGS --start"
[ "$DEPS" = 1 ] && ARGS="$ARGS --with-deps"
if [ "$(id -u)" = 0 ]; then SUDO=""
elif sudo -n true 2>/dev/null; then SUDO="sudo -n"
else echo "remote user is not root and has no passwordless sudo"; exit 1; fi
[ "$(sha256sum "$RTMP/release.tgz" | cut -d' ' -f1)" = "$SUM" ] || { echo "sha256 mismatch after upload"; exit 1; }
DATA=/var/lib/noobrouter-agent
# a restart in the middle of an unconfirmed change would race the rollback timer
if [ "$FORCE" != 1 ]; then
  if $SUDO test -f "$DATA/fw/pending.json" || systemctl list-units --all --no-legend 'noobrouter-rollback*' 2>/dev/null | grep -q .; then
    echo "ABORT: unconfirmed change pending (fw/pending.json or noobrouter-rollback timer); confirm or roll back first, or use --force"; exit 1
  fi
fi
# this script itself arrives on stdin: keep child commands (apt-get etc.) from eating it
tar -xzf "$RTMP/release.tgz" -C "$RTMP" </dev/null
# shellcheck disable=SC2086
$SUDO sh "$RTMP"/noobrouter-agent-*/install.sh $ARGS </dev/null
[ "$START" = 1 ] || exit 0
# health check from the router itself, against the configured listen address
$SUDO python3 - <<'PY'
import json, sys, time, urllib.request
cfg = json.load(open("/etc/noobrouter-agent.json"))
url = "http://%s:%s/" % (cfg.get("listen", "127.0.0.1"), cfg.get("port", 8090))
for _ in range(10):
    try:
        code = urllib.request.urlopen(url, timeout=3).status
        break
    except Exception as e:
        code, err = None, e
        time.sleep(1)
if code != 200:
    print("FAIL health check %s: %s" % (url, err)); sys.exit(1)
print("OK  %s -> HTTP 200, dry_run=%s" % (url, cfg.get("dry_run", True)))
PY
REMOTE

step "done"
