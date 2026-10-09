#!/bin/sh
# One-step install / upgrade, run ON THE ROUTER as root:
#   curl -fsSL <release-url>/get.sh | sh -s -- --start
# Downloads the release package, verifies sha256, then runs install.sh (same options).
# install.sh refuses to run while a firewall/init change is unconfirmed and health-checks after --start.
#
#   NOOBROUTER_URL   where the release files live (default: latest GitHub Release)
#   PREFIX           dry install into a directory (see install.sh); skips the root check
set -eu
URL=${NOOBROUTER_URL:-https://github.com/xiayu1987/noobrouter/releases/latest/download}
PKG=noobrouter-agent.tar.gz

for a in "$@"; do
  case "$a" in
    --start|--with-deps|--force) ;;
    -h|--help) echo "usage: sh get.sh [--start] [--with-deps] [--force]   (NOOBROUTER_URL=... to override source)"; exit 0 ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done
if [ -z "${PREFIX:-}" ] && [ "$(id -u)" != 0 ]; then echo "run as root"; exit 1; fi
for c in sha256sum tar python3; do command -v $c >/dev/null 2>&1 || { echo "missing command: $c"; exit 1; }; done

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 --connect-timeout 10 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -T 10 -t 3 -O "$2" "$1"
  else python3 -c 'import sys, urllib.request; open(sys.argv[2], "wb").write(urllib.request.urlopen(sys.argv[1], timeout=30).read())' "$1" "$2"; fi
}

T=$(mktemp -d /tmp/noobrouter-get.XXXXXX)
trap 'rm -rf "$T"' EXIT
echo "==> download $URL/$PKG"
fetch "$URL/$PKG" "$T/$PKG"
fetch "$URL/$PKG.sha256" "$T/$PKG.sha256"
WANT=$(cut -d' ' -f1 "$T/$PKG.sha256")
GOT=$(sha256sum "$T/$PKG" | cut -d' ' -f1)
[ ${#WANT} = 64 ] && [ "$WANT" = "$GOT" ] || { echo "ABORT: sha256 mismatch (want $WANT, got $GOT)"; exit 1; }
echo "==> sha256 ok $GOT"
tar -xzf "$T/$PKG" -C "$T"
D=$(ls -d "$T"/noobrouter-agent-*/ 2>/dev/null | head -n 1)
[ -n "$D" ] && [ -f "$D/install.sh" ] || { echo "ABORT: package has no install.sh"; exit 1; }
# piped via `curl | sh`: stdin is this script, keep install.sh (apt etc.) from reading it
sh "$D/install.sh" "$@" </dev/null
