#!/bin/sh
# WSL rehearsal: pack -> unpack -> PREFIX install twice; also boots the installed copy (dry_run, loopback).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# dash has no $'\r'; build the CR byte portably
CR=$(printf '\r')
grep -l "$CR" "$ROOT"/deploy/*.sh "$ROOT"/deploy/*.service 2>/dev/null && { echo "FAIL CRLF found"; exit 1; } || echo "PASS no CRLF"
TGZ=$(sh "$ROOT/deploy/pack.sh" | tail -n 1); echo "PASS packed $TGZ"
W=$(mktemp -d); P=$W/root; trap 'kill $PID 2>/dev/null || true; rm -rf "$W"' EXIT; PID=
tar -C "$W" -xzf "$TGZ"; R=$(ls -d "$W"/noobrouter-agent-*)
tar -tzf "$TGZ" | grep -q __pycache__ && { echo "FAIL pycache in tarball"; exit 1; } || echo "PASS no pycache"
PREFIX=$P sh "$R/install.sh" | tee "$W/o1"
grep -q 'created' "$W/o1" && grep -q WARNING "$W/o1" && echo "PASS first install (CHECK_ME placeholders -> warning)"
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
# Boot installed copy on loopback with installed web root
cat > "$W/run.json" <<EOF
{"listen":"127.0.0.1","port":18093,"dry_run":true,"data_dir":"$W/data","web_root":"$P/opt/noobrouter-agent/web"}
EOF
(cd "$P/opt/noobrouter-agent" && python3 -m noobrouter_agent.server -c "$W/run.json" > "$W/log" 2>&1) & PID=$!
sleep 1.5
[ "$(stat -c %a "$W/data/token")" = 600 ] && echo "PASS token autogen 0600"
TOK=$(cat "$W/data/token")
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18093/)" = 200 ] && echo "PASS installed web served"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" http://127.0.0.1:18093/api/status)" = 200 ] && echo "PASS installed api"
# /api/init reads the live ruleset (iptables-save): needs root, so non-root runs report SKIP instead of silently dropping
code=$(curl -s -o "$W/init" -w '%{http_code}' -H "Authorization: Bearer $TOK" http://127.0.0.1:18093/api/init)
if [ "$code" = 200 ]; then echo "PASS installed init api"
elif [ "$(id -u)" != 0 ] && grep -q 'must be root' "$W/init"; then echo "SKIP installed init api (needs root)"
else echo "FAIL installed init api (HTTP $code)"; exit 1; fi
echo INSTALL_REHEARSAL_DONE
