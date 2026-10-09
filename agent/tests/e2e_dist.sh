#!/bin/sh
# Local integration (Linux): dry_run agent serving the built web/dist; exercises every
# endpoint the frontend calls in read/preview mode. Never touches the real router.
cd "$(dirname "$0")/.." || exit 1
D=$(mktemp -d); P=18091; U=http://127.0.0.1:$P; T=e2etok
cat > "$D/cfg.json" <<EOF
{"listen":"127.0.0.1","port":$P,"token":"$T","data_dir":"$D/data","web_root":"$(pwd)/../web/dist","dry_run":true}
EOF
python3 -m noobrouter_agent.server -c "$D/cfg.json" > "$D/log" 2>&1 & PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$D"' EXIT
for i in 1 2 3 4 5 6 7 8 9 10; do curl -s -o /dev/null $U/ && break; sleep 0.3; done
FAILS=0
hit() { # name expected method path [json]
  if [ -n "$5" ]; then c=$(curl -s -o /tmp/e2e_body -w '%{http_code}' -X "$3" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d "$5" "$U$4")
  else c=$(curl -s -o /tmp/e2e_body -w '%{http_code}' -X "$3" -H "Authorization: Bearer $T" "$U$4"); fi
  if [ "$c" = "$2" ]; then echo "PASS $1 ($c)"; else echo "FAIL $1 got $c want $2: $(head -c 300 /tmp/e2e_body)"; FAILS=1; fi
}
c=$(curl -s -o /tmp/e2e_body -w '%{http_code}' $U/); grep -q 'id="app"' /tmp/e2e_body && [ "$c" = 200 ] && echo "PASS index" || { echo "FAIL index $c"; FAILS=1; }
A=$(grep -o '/assets/index-[^"]*\.js' /tmp/e2e_body | head -1)
[ "$(curl -s -o /dev/null -w '%{http_code}' $U$A)" = 200 ] && echo "PASS asset $A" || { echo "FAIL asset $A"; FAILS=1; }
c=$(curl -s -o /dev/null -w '%{http_code}' $U/api/status); [ "$c" = 401 ] && echo "PASS noauth 401" || { echo "FAIL noauth got $c"; FAILS=1; }
c=$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer wrong' $U/api/status); [ "$c" = 401 ] && echo "PASS badtoken 401" || { echo "FAIL badtoken got $c"; FAILS=1; }
for p in status traffic interfaces devices "connections?limit=50" services "logs?unit=dnsmasq&lines=20" firewall dhcp; do hit "get $p" 200 GET "/api/$p"; done
python3 - "$D" <<'PY'
import json,sys,urllib.request
d=sys.argv[1]
def get(p):
    r=urllib.request.Request("http://127.0.0.1:18091"+p,headers={"Authorization":"Bearer e2etok"})
    return json.load(urllib.request.urlopen(r))
fw=get("/api/firewall"); dh=get("/api/dhcp")
json.dump({"model":fw.get("model")},open(d+"/fw.json","w"))
json.dump({"model":dh.get("model")},open(d+"/dh.json","w"))
print("INFO guard.rollback_seconds =", (fw.get("guard") or {}).get("rollback_seconds"))
PY
hit "fw preview" 200 POST /api/firewall/preview "$(cat $D/fw.json)"
grep -q '\*filter' /tmp/e2e_body && echo "PASS fw preview has *filter" || { echo "FAIL fw preview body"; FAILS=1; }
hit "fw apply blocked in dry_run" 409 POST /api/firewall/apply "$(cat $D/fw.json)"
hit "dhcp preview" 200 POST /api/dhcp/apply "$(sed 's/}$/,"preview":true,"allow_empty":true}/' $D/dh.json)"
grep -q '"applied": false' /tmp/e2e_body && echo "PASS dhcp not applied" || { echo "FAIL dhcp body: $(head -c 300 /tmp/e2e_body)"; FAILS=1; }
hit "diag ping" 200 POST /api/diag '{"tool":"ping","host":"127.0.0.1"}'
hit "diag injection rejected" 400 POST /api/diag '{"tool":"ping","host":"127.0.0.1;id"}'
echo "--- agent log tail"; tail -n 3 "$D/log"
[ $FAILS = 0 ] && echo E2E_ALL_PASS || { echo E2E_FAILED; exit 1; }
