#!/bin/sh
# Local dev helper: compile, unit test, then HTTP smoke test (dry_run, temp data_dir). Never touches live config.
set -e
cd "$(dirname "$0")/.." || exit 1
python3 -m py_compile noobrouter_agent/*.py
python3 -m unittest discover -s tests 2>&1 | tail -n 3

D=$(mktemp -d)
mkdir -p "$D/web/assets"
echo '<html>INDEX</html>' > "$D/web/index.html"
echo 'console.log(1)' > "$D/web/assets/a.js"
echo secret-in-data > "$D/secret.txt"
cat > "$D/cfg.json" <<EOF
{"listen":"127.0.0.1","port":18090,"token":"tok123","data_dir":"$D/data","web_root":"$D/web","dry_run":true}
EOF
python3 -m noobrouter_agent.server -c "$D/cfg.json" > "$D/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$D"' EXIT
sleep 1
U=http://127.0.0.1:18090
A="Authorization: Bearer tok123"
J="Content-Type: application/json"
code() { curl -s -o /tmp/sr_body -w '%{http_code}' "$@"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS $1 ($3)"; else echo "FAIL $1 expected $2 got $3: $(head -c 300 /tmp/sr_body)"; FAILS=1; fi
}
FAILS=0
check "no token"            401 "$(code $U/api/status)"
check "bad token"           401 "$(code -H 'Authorization: Bearer nope' $U/api/status)"
check "status"              200 "$(code -H "$A" $U/api/status)"
grep -q '"dry_run": true' /tmp/sr_body && echo "PASS status dry_run=true" || { echo "FAIL dry_run flag"; FAILS=1; }
check "traffic"             200 "$(code -H "$A" $U/api/traffic)"
check "interfaces"          200 "$(code -H "$A" $U/api/interfaces)"
check "devices"             200 "$(code -H "$A" $U/api/devices)"
check "connections bad int" 400 "$(code -H "$A" "$U/api/connections?limit=abc")"
check "connections"         200 "$(code -H "$A" "$U/api/connections?limit=5")"
check "services"            200 "$(code -H "$A" $U/api/services)"
check "logs bad unit"       400 "$(code -H "$A" "$U/api/logs?unit=x")"
check "unknown api"         404 "$(code -H "$A" $U/api/nope)"
check "bad json"            400 "$(code -H "$A" -H "$J" -d '{bad' $U/api/firewall/save)"
check "non-object json"     400 "$(code -H "$A" -H "$J" -d '[1]' $U/api/firewall/save)"
check "wrong content-type"  415 "$(code -H "$A" -H 'Content-Type: text/plain' -d '{}' $U/api/firewall/save)"
check "diag inject"         400 "$(code -H "$A" -H "$J" -d '{"tool":"ping","host":"-f;id"}' $U/api/diag)"
check "firewall get"        200 "$(code -H "$A" $U/api/firewall)"
check "fw save empty"       400 "$(code -H "$A" -H "$J" -d '{}' $U/api/firewall/save)"
check "fw apply dry_run"    409 "$(code -H "$A" -H "$J" -d '{}' $U/api/firewall/apply)"
check "fw confirm none"     409 "$(code -H "$A" -H "$J" -d '{}' $U/api/firewall/confirm)"
check "dhcp get"            200 "$(code -H "$A" $U/api/dhcp)"
check "dhcp apply empty"    400 "$(code -H "$A" -H "$J" -d '{}' $U/api/dhcp/apply)"
check "dhcp apply bad mac"  400 "$(code -H "$A" -H "$J" -d '{"model":{"static":[{"mac":"zz","ip":"192.168.50.9"}]}}' $U/api/dhcp/apply)"
check "init get"            200 "$(code -H "$A" $U/api/init)"
grep -q '"probe"' /tmp/sr_body && echo "PASS init probe present" || { echo "FAIL init probe"; FAILS=1; }
check "init preview no plan" 400 "$(code -H "$A" -H "$J" -d '{}' $U/api/init/preview)"
check "init preview bad plan" 400 "$(code -H "$A" -H "$J" -d '{"plan":{"wan":{"type":"x"}}}' $U/api/init/preview)"
check "init apply dry_run"  409 "$(code -H "$A" -H "$J" -d '{"plan":{"wan":{"type":"dhcp","if":"nope0"},"lan":{"if":"nope1","address":"10.9.0.1/24"},"dhcp":{"enabled":false}}}' $U/api/init/apply)"
check "init confirm none"   409 "$(code -H "$A" -H "$J" -d '{}' $U/api/init/confirm)"
check "init rollback none"  409 "$(code -H "$A" -H "$J" -d '{}' $U/api/init/rollback)"
check "static index"        200 "$(code $U/)"
check "static asset"        200 "$(code $U/assets/a.js)"
check "spa fallback"        200 "$(code $U/devices)"
grep -q INDEX /tmp/sr_body && echo "PASS spa body" || { echo "FAIL spa body"; FAILS=1; }
code --path-as-is $U/../secret.txt >/dev/null
grep -q secret-in-data /tmp/sr_body && { echo "FAIL traversal leaked"; FAILS=1; } || echo "PASS traversal blocked"
code --path-as-is $U/assets/../../secret.txt >/dev/null
grep -q secret-in-data /tmp/sr_body && { echo "FAIL traversal2 leaked"; FAILS=1; } || echo "PASS traversal2 blocked"
check "post static"         405 "$(code -X POST $U/)"
echo "--- server log tail"; tail -n 5 "$D/server.log"
[ $FAILS = 0 ] && echo SMOKE_ALL_PASS || { echo SMOKE_FAILED; exit 1; }
