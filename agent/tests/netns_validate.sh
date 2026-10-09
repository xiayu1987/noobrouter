#!/bin/sh
# Validate rendered rules against the real kernel inside a throwaway netns (Linux, run as root).
set -e
cd "$(dirname "$0")/.."
NS=srtest$$
export NS
ip netns add $NS
trap 'ip netns del $NS' EXIT
python3 - <<'EOF'
from noobrouter_agent import config, firewall
cfg = dict(config.DEFAULTS)
m, _ = firewall.import_iptables_save(open("tests/fixtures/router_iptables_save.txt").read(), cfg)
full = firewall.normalize(dict(firewall.EMPTY_MODEL, ipv6_filter=True), cfg)  # every option on
import os
ns = os.environ["NS"]
open(f"/tmp/{ns}.v4", "w").write(firewall.render_v4(firewall.normalize(m, cfg), cfg))
open(f"/tmp/{ns}.full4", "w").write(firewall.render_v4(full, cfg))
open(f"/tmp/{ns}.v6", "w").write(firewall.render_v6(full, cfg))
EOF
ip netns exec $NS iptables-restore --test < /tmp/$NS.v4 && echo "v4 (imported fixture) --test OK"
ip netns exec $NS iptables-restore --test < /tmp/$NS.full4 && echo "v4 (all options) --test OK"
ip netns exec $NS ip6tables-restore --test < /tmp/$NS.v6 && echo "v6 --test OK"
ip netns exec $NS iptables-restore < /tmp/$NS.v4
echo "nat PREROUTING DNAT rules from fixture: $(ip netns exec $NS iptables -t nat -S PREROUTING | grep -c DNAT)"
ip netns exec $NS iptables-restore < /tmp/$NS.full4
ip netns exec $NS ip6tables-restore < /tmp/$NS.v6
# what the kernel stored must round-trip through the importer with nothing skipped
ip netns exec $NS iptables-save > /tmp/$NS.s4
ip netns exec $NS ip6tables-save > /tmp/$NS.s6
python3 - <<'EOF'
import os
from noobrouter_agent import config, firewall
cfg, ns = dict(config.DEFAULTS), os.environ["NS"]
m, sk = firewall.import_iptables_save(open(f"/tmp/{ns}.s4").read(), cfg)
f6, sk6 = firewall.import_ip6tables_save(open(f"/tmp/{ns}.s6").read(), cfg, m)
m.update(f6)
want = firewall.normalize(dict(firewall.EMPTY_MODEL, ipv6_filter=True), cfg)
diff = [k for k in firewall.BOOL_KEYS if m[k] != want[k]]
print("kernel round-trip:", "OK" if not (sk or sk6 or diff) else f"FAIL skipped={sk + sk6} diff={diff}")
EOF
rm -f /tmp/$NS.v4 /tmp/$NS.full4 /tmp/$NS.v6 /tmp/$NS.s4 /tmp/$NS.s6
