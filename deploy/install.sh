#!/bin/sh
# Install noobrouter-agent from an unpacked release dir. Safe by design:
#  - never touches iptables / nftables / dnsmasq / ppp / network config
#  - never overwrites an existing /etc/noobrouter-agent.json
#  - does NOT enable or start the service unless --start is given
#  - --with-deps installs the router packages (ppp, dnsmasq, iptables...) for a blank Debian, but
#    leaves them unconfigured/stopped: the web init wizard configures them in one rollback transaction
# Usage: sh install.sh [--start] [--with-deps]     (PREFIX=/tmp/x sh install.sh for a dry install)
#  - upgrades a legacy softroute-agent install in place (config, data dir + token, unit); see migrate_legacy
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PREFIX=${PREFIX:-}
START=0; DEPS=0
for a in "$@"; do
  case "$a" in
    --start) START=1 ;;
    --with-deps) DEPS=1 ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done
OPT=$PREFIX/opt/noobrouter-agent
CFG=$PREFIX/etc/noobrouter-agent.json
UNIT=$PREFIX/etc/systemd/system/noobrouter-agent.service

command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }
[ -d "$HERE/noobrouter_agent" ] && [ -f "$HERE/web/index.html" ] || { echo "release incomplete (noobrouter_agent/ or web/ missing)"; exit 1; }

# ---- legacy softroute-agent -> noobrouter-agent (agent only; never touches network config) ----
OLD_CFG=$PREFIX/etc/softroute-agent.json
OLD_DATA=$PREFIX/var/lib/softroute-agent
OLD_OPT=$PREFIX/opt/softroute-agent
OLD_UNIT=$PREFIX/etc/systemd/system/softroute-agent.service
NEW_DATA=$PREFIX/var/lib/noobrouter-agent
if [ -f "$OLD_CFG" ] || [ -d "$OLD_DATA" ] || [ -f "$OLD_UNIT" ]; then
  echo "legacy softroute-agent install found: migrating"
  # an unconfirmed transaction of the old agent references the old data dir: never migrate under it
  if [ -f "$OLD_DATA/fw/pending.json" ]; then
    echo "ABORT: legacy agent has an unconfirmed change ($OLD_DATA/fw/pending.json); confirm or roll back first"; exit 1
  fi
  if [ -z "$PREFIX" ]; then
    if systemctl list-units --all --no-legend 'softroute-rollback*' 2>/dev/null | grep -q .; then
      echo "ABORT: softroute-rollback timer pending; confirm or let it roll back first"; exit 1
    fi
    if systemctl is-active --quiet softroute-agent; then START=1; fi  # keep the console up
    systemctl disable --now softroute-agent 2>/dev/null || true
  fi
  if [ -d "$OLD_DATA" ]; then
    if [ -e "$NEW_DATA" ]; then echo "ABORT: both $OLD_DATA and $NEW_DATA exist"; exit 1; fi
    mkdir -p "$(dirname "$NEW_DATA")"; mv "$OLD_DATA" "$NEW_DATA"
  fi
  if [ -f "$OLD_CFG" ]; then
    if [ -f "$CFG" ]; then
      echo "keep existing $CFG (legacy $OLD_CFG left as is)"
    else
      sed -e 's#/opt/softroute-agent#/opt/noobrouter-agent#g' -e 's#/var/lib/softroute-agent#/var/lib/noobrouter-agent#g' \
        "$OLD_CFG" > "$CFG.tmp"
      chmod 600 "$CFG.tmp"; mv "$CFG.tmp" "$CFG"; mv "$OLD_CFG" "$OLD_CFG.migrated"
      echo "migrated $OLD_CFG -> $CFG (old copy: $OLD_CFG.migrated)"
    fi
  fi
  rm -f "$OLD_UNIT"; rm -rf "$OLD_OPT"
  if [ -z "$PREFIX" ]; then systemctl daemon-reload; fi
fi

# ---- legacy system artifacts written by the old agent's init wizard: rename in place ----
# Contents are identical; only names change, so nothing is reloaded (dnsmasq/sysctl/.link/cloud-init
# read them by directory). The PPPoE provider name is also the ifupdown iface name, so it is renamed
# only while that link is down; otherwise it stays legacy and init preview reports the conflict.
E=$PREFIX/etc
mvl() { if [ -e "$1" ] && [ ! -e "$2" ]; then mv "$1" "$2"; echo "renamed $1 -> $2"; fi; }
mvl "$E/network/interfaces.d/softroute" "$E/network/interfaces.d/noobrouter"
mvl "$E/dnsmasq.d/softroute.conf" "$E/dnsmasq.d/noobrouter.conf"
mvl "$E/dnsmasq.d/00-softroute-base.conf" "$E/dnsmasq.d/00-noobrouter-base.conf"
mvl "$E/sysctl.d/90-softroute.conf" "$E/sysctl.d/90-noobrouter.conf"
mvl "$E/modules-load.d/softroute.conf" "$E/modules-load.d/noobrouter.conf"
mvl "$E/cloud/cloud.cfg.d/99-softroute-disable-network.cfg" "$E/cloud/cloud.cfg.d/99-noobrouter-disable-network.cfg"
mvl "$E/iptables/rules.v4.softroute.bak" "$E/iptables/rules.v4.noobrouter.bak"
mvl "$E/iptables/rules.v6.softroute.bak" "$E/iptables/rules.v6.noobrouter.bak"
for f in "$E"/systemd/network/10-softroute-*.link; do
  if [ -e "$f" ]; then mvl "$f" "$(dirname "$f")/$(basename "$f" | sed 's/softroute/noobrouter/')"; fi
done
for f in "$E"/network/interfaces.d/noobrouter "$E"/dnsmasq.d/noobrouter.conf "$E"/dnsmasq.d/00-noobrouter-base.conf \
         "$E"/sysctl.d/90-noobrouter.conf "$E"/modules-load.d/noobrouter.conf "$E"/cloud/cloud.cfg.d/99-noobrouter-disable-network.cfg \
         "$E"/systemd/network/10-noobrouter-*.link; do
  if [ -f "$f" ]; then sed -i 's/softroute-agent/noobrouter-agent/' "$f"; fi   # header comment only
done
if [ -e "$E/ppp/peers/softroute" ]; then
  ppp_up=0
  if [ -z "$PREFIX" ]; then
    if pgrep -f 'pppd.*(call|provider) softroute' >/dev/null 2>&1; then ppp_up=1; fi
    if grep -qs '^softroute=' /run/network/ifstate*; then ppp_up=1; fi
  fi
  if [ $ppp_up = 1 ]; then
    echo "WARNING: legacy PPPoE provider 'softroute' is up; left as is (rename after: ifdown softroute)"
  else
    mvl "$E/ppp/peers/softroute" "$E/ppp/peers/noobrouter"
    if [ -f "$E/network/interfaces.d/noobrouter" ]; then
      sed -i -e 's/^auto softroute$/auto noobrouter/' -e 's/^iface softroute inet ppp$/iface noobrouter inet ppp/' \
             -e 's/^\(\s*provider\) softroute$/\1 noobrouter/' "$E/network/interfaces.d/noobrouter"
    fi
  fi
fi
for f in "$E/ppp/chap-secrets" "$E/ppp/pap-secrets"; do
  if [ -f "$f" ] && grep -q '# softroute-agent$' "$f"; then sed -i 's/# softroute-agent$/# noobrouter-agent/' "$f"; fi
done

if [ $DEPS = 1 ]; then
  if [ -n "$PREFIX" ]; then
    echo "PREFIX set: skip apt (--with-deps)"
  else
    PKGS="iptables iptables-persistent dnsmasq ppp ifupdown iproute2 isc-dhcp-client"
    # don't let iptables-persistent snapshot the current rules or prompt
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections
    had_dnsmasq=0; dpkg-query -W -f='${Status}' dnsmasq 2>/dev/null | grep -q "ok installed" && had_dnsmasq=1
    # block service auto-start during apt: stock dnsmasq would grab 0.0.0.0:53 and collide with
    # systemd-resolved (cloud images), leaving a failed unit. Only if no policy-rc.d exists already.
    POLICY=/usr/sbin/policy-rc.d; own_policy=0
    if [ ! -e "$POLICY" ]; then
      printf '#!/bin/sh\nexit 101\n' > "$POLICY"; chmod 755 "$POLICY"; own_policy=1
      trap 'rm -f "$POLICY"' EXIT
    fi
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS
    if [ $own_policy = 1 ]; then rm -f "$POLICY"; trap - EXIT; fi
    if [ $had_dnsmasq = 0 ]; then
      # keep it stopped until the init wizard writes a LAN-bound config and enables it
      systemctl disable --now dnsmasq 2>/dev/null || true
      systemctl reset-failed dnsmasq 2>/dev/null || true
      echo "dnsmasq installed but left stopped (the init wizard enables it)"
    fi
  fi
fi

mkdir -p "$OPT" "$PREFIX/etc/systemd/system" "$PREFIX/var/lib/noobrouter-agent"
chmod 700 "$PREFIX/var/lib/noobrouter-agent"
# Replace code + web atomically-ish: stage then swap.
rm -rf "$OPT/.new"; mkdir -p "$OPT/.new"
cp -R "$HERE/noobrouter_agent" "$HERE/web" "$OPT/.new/"
rm -rf "$OPT/noobrouter_agent" "$OPT/web"
mv "$OPT/.new/noobrouter_agent" "$OPT/.new/web" "$OPT/"; rmdir "$OPT/.new"
find "$OPT" -name __pycache__ -type d -prune -exec rm -rf {} +
python3 -m py_compile "$OPT"/noobrouter_agent/*.py

if [ -f "$CFG" ]; then
  echo "keep existing $CFG"
else
  install -m 600 "$HERE/noobrouter-agent.example.json" "$CFG"
  echo "created $CFG (dry_run=true)"
fi
grep -q CHECK_ME "$CFG" && echo "WARNING: edit $CFG and set wan_phy_if (see: ip -br link) before using"
install -m 644 "$HERE/noobrouter-agent.service" "$UNIT"

if [ -z "$PREFIX" ]; then
  systemctl daemon-reload
  if [ $START = 1 ]; then
    # enable --now is a no-op for a running unit: restart so an upgrade actually loads the new code
    systemctl enable noobrouter-agent
    systemctl restart noobrouter-agent
    sleep 1; systemctl --no-pager status noobrouter-agent | head -n 5
  else
    if systemctl is-active --quiet noobrouter-agent; then
      echo "installed. agent is running OLD code until: systemctl restart noobrouter-agent"
    else
      echo "installed. start with: systemctl enable --now noobrouter-agent"
    fi
  fi
fi
echo "token file: /var/lib/noobrouter-agent/token (created on first start if token is empty)"
