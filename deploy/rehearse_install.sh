#!/bin/sh
# WSL rehearsal: pack -> get.sh from a local HTTP source -> PREFIX install twice; guard + boot checks.
# Host untouched (PREFIX install). Needs only python3, tar, sha256sum.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# dash has no $'\r'; build the CR byte portably
CR=$(printf '\r')
grep -l "$CR" "$ROOT"/deploy/*.sh "$ROOT"/deploy/*.service 2>/dev/null && { echo "FAIL CRLF found"; exit 1; } || echo "PASS no CRLF"
TGZ=$(sh "$ROOT/deploy/pack.sh" | tail -n 1); echo "PASS packed $TGZ"
(cd "$ROOT/dist" && sha256sum -c --quiet noobrouter-agent.tar.gz.sha256) && echo "PASS sha256 file matches"
W=$(mktemp -d); P=$W/root; PID=; HPID=
trap 'kill $PID $HPID 2>/dev/null || true; rm -rf "$W"' EXIT
# http status code via stdlib (no curl needed)
code() { python3 - "$@" <<'PY'
import sys, urllib.request, urllib.error
req = urllib.request.Request(sys.argv[1], headers={"Authorization": "Bearer " + sys.argv[2]} if len(sys.argv) > 2 else {})
try:
    r = urllib.request.urlopen(req, timeout=5); body = r.read(); c = r.status
except urllib.error.HTTPError as e:
    body = e.read(); c = e.code
if len(sys.argv) > 3: open(sys.argv[3], "wb").write(body)
print(c)
PY
}
tar -tzf "$TGZ" | grep -q __pycache__ && { echo "FAIL pycache in tarball"; exit 1; } || echo "PASS no pycache"

# ---- get.sh against a local release source (same path a router uses) ----
(cd "$ROOT/dist" && exec python3 -m http.server 18765 --bind 127.0.0.1 >/dev/null 2>&1) & HPID=$!
sleep 1
NOOBROUTER_URL=http://127.0.0.1:18765 PREFIX=$P sh "$ROOT/dist/get.sh" | tee "$W/o1"
grep -q 'sha256 ok' "$W/o1" && grep -q 'created' "$W/o1" && grep -q WARNING "$W/o1" && echo "PASS get.sh first install (CHECK_ME -> warning)"
mkdir -p "$W/bad"; cp "$ROOT/dist/noobrouter-agent.tar.gz" "$W/bad/"; echo "0000  noobrouter-agent.tar.gz" > "$W/bad/noobrouter-agent.tar.gz.sha256"
kill $HPID; (cd "$W/bad" && exec python3 -m http.server 18765 --bind 127.0.0.1 >/dev/null 2>&1) & HPID=$!; sleep 1
rc=0; NOOBROUTER_URL=http://127.0.0.1:18765 PREFIX=$P sh "$ROOT/dist/get.sh" > "$W/ob" 2>&1 || rc=$?
[ $rc != 0 ] && grep -q 'sha256 mismatch' "$W/ob" && echo "PASS get.sh rejects bad sha256"
kill $HPID; HPID=
rc=0; NOOBROUTER_URL=http://127.0.0.1:18765 PREFIX=$P sh "$ROOT/dist/get.sh" > /dev/null 2>&1 || rc=$?
[ $rc != 0 ] && echo "PASS get.sh fails when source unreachable"

R=$(mktemp -d -p "$W"); tar -C "$R" -xzf "$TGZ"; R=$(ls -d "$R"/noobrouter-agent-*)
[ "$(stat -c %a "$P/etc/noobrouter-agent.json")" = 600 ] && echo "PASS cfg 0600"
[ "$(stat -c %a "$P/var/lib/noobrouter-agent")" = 700 ] && echo "PASS data dir 0700"
[ -f "$P/opt/noobrouter-agent/web/index.html" ] && [ -f "$P/opt/noobrouter-agent/noobrouter_agent/server.py" ] && echo "PASS layout"
sed -i 's/"port": 8090/"port": 18092/' "$P/etc/noobrouter-agent.json"
PREFIX=$P sh "$R/install.sh" > "$W/o2"
grep -q 'keep existing' "$W/o2" && grep -q 18092 "$P/etc/noobrouter-agent.json" && echo "PASS re-install keeps config"
PREFIX=$P sh "$R/install.sh" --with-deps > "$W/o3"
grep -q 'skip apt' "$W/o3" && echo "PASS --with-deps skips apt under PREFIX"
rc=0; PREFIX=$P sh "$R/install.sh" --bogus > /dev/null 2>&1 || rc=$?
[ $rc = 2 ] && echo "PASS unknown option -> exit 2"
# unconfirmed change guard
mkdir -p "$P/var/lib/noobrouter-agent/fw"; echo '{}' > "$P/var/lib/noobrouter-agent/fw/pending.json"
rc=0; PREFIX=$P sh "$R/install.sh" > "$W/o4" 2>&1 || rc=$?
[ $rc = 1 ] && grep -q 'ABORT: unconfirmed change' "$W/o4" && echo "PASS pending change blocks install"
PREFIX=$P sh "$R/install.sh" --force > /dev/null && echo "PASS --force overrides guard"
rm -f "$P/var/lib/noobrouter-agent/fw/pending.json"

# Boot installed copy on loopback with installed web root
cat > "$W/run.json" <<EOF
{"listen":"127.0.0.1","port":18093,"dry_run":true,"data_dir":"$W/data","web_root":"$P/opt/noobrouter-agent/web"}
EOF
(cd "$P/opt/noobrouter-agent" && exec python3 -m noobrouter_agent.server -c "$W/run.json" > "$W/log" 2>&1) & PID=$!
sleep 1.5
[ "$(stat -c %a "$W/data/token")" = 600 ] && echo "PASS token autogen 0600"
TOK=$(cat "$W/data/token")
[ "$(code http://127.0.0.1:18093/)" = 200 ] && echo "PASS installed web served"
[ "$(code http://127.0.0.1:18093/api/status)" = 401 ] && echo "PASS api needs token"
[ "$(code http://127.0.0.1:18093/api/status "$TOK")" = 200 ] && echo "PASS installed api"
# /api/init reads the live ruleset (iptables-save): needs root, so non-root runs report SKIP instead of silently dropping
c=$(code http://127.0.0.1:18093/api/init "$TOK" "$W/init")
if [ "$c" = 200 ]; then echo "PASS installed init api"
elif [ "$(id -u)" != 0 ] && grep -q 'must be root' "$W/init"; then echo "SKIP installed init api (needs root)"
else echo "FAIL installed init api (HTTP $c)"; exit 1; fi
echo INSTALL_REHEARSAL_DONE
