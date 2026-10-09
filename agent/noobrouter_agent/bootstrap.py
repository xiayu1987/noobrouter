"""Blank Debian -> soft router initialisation (plan -> render -> one rollback transaction).

Plan (data_dir/bootstrap.json, password kept only in /etc/ppp/chap-secrets):
{
  "wan":  {"type": "pppoe|dhcp|static", "if": "wan0", "user": "", "password": "",
           "address": "", "gateway": "", "mtu": 1492},
  "lan":  {"if": "lan0", "address": "192.168.50.1/24"},
  "dhcp": {"enabled": true, "start": "192.168.50.100", "end": "192.168.50.200", "lease": "12h"},
  "dns":  {"upstream": ["223.5.5.5", "119.29.29.29"]},
  "ipv6": {"enabled": true},
  "tuning": {"conntrack_max": true, "bbr": false, ...},   # optional TUNING keys (missing = off)
  "ssh_port": 22
}
Managed files (all new, never edits hand-written ones; cfg["sysroot"] prefixes them for tests):
  /etc/network/interfaces.d/noobrouter  /etc/ppp/peers/noobrouter  /etc/ppp/chap-secrets
  /etc/ppp/pap-secrets  /etc/sysctl.d/90-noobrouter.conf  /etc/dnsmasq.d/00-noobrouter-base.conf
  /etc/modules-load.d/noobrouter.conf (only when a tuning item needs a kernel module)
Safety:
  - LAN address is *added* first (ip addr replace), existing addresses are never flushed, so an
    SSH session over the current LAN IP keeps working; old IPs disappear only after reboot.
  - Everything goes through applier.apply: unconfirmed changes roll back automatically.
  - WAN is brought up last; if dial-up fails the LAN side stays reachable.
"""
import ipaddress
import json
import os
import re
import shlex

from . import applier, config, dhcp, firewall, store
from .shell import CmdError, has, read, try_run

IF_RE = firewall.IF_RE
CRED_RE = re.compile(r'^[^\s"\\#]{1,128}$')  # no whitespace/quotes/backslash: chap-secrets syntax
LEASE_RE = re.compile(r"^\d{1,6}[mhd]?$|^infinite$")
PROVIDER = "noobrouter"
SECRET_MARK = "# noobrouter-agent"
PKGS = {"base": ["iptables", "iptables-persistent", "dnsmasq", "ifupdown", "iproute2"],
        "pppoe": ["ppp"], "dhcp": ["isc-dhcp-client"]}

PATHS = {"ifaces": "/etc/network/interfaces.d/noobrouter", "ifaces_main": "/etc/network/interfaces",
         "peers": f"/etc/ppp/peers/{PROVIDER}", "chap": "/etc/ppp/chap-secrets",
         "pap": "/etc/ppp/pap-secrets", "sysctl": "/etc/sysctl.d/90-noobrouter.conf",
         "dnsmasq": "/etc/dnsmasq.d/00-noobrouter-base.conf", "modules": "/etc/modules-load.d/noobrouter.conf"}

# Kernel tuning catalogue (single source for render + UI). mandatory = always applied, UI locks it on.
# sysctl: lines written to 90-noobrouter.conf; modules: loaded before `sysctl -p` (the keys only exist
# once the module is in) and listed in modules-load.d so they are there again after reboot.
TUNING = [
    {"key": "forwarding", "group": "基础", "mandatory": True, "default": True,
     "label": "开启 IPv4 转发、宽松反向路径校验",
     "desc": "ip_forward=1，rp_filter=2（多出口/策略路由下不误丢包）。软路由必需",
     "sysctl": ["net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2"], "modules": []},
    {"key": "conntrack_max", "group": "连接跟踪", "mandatory": False, "default": True,
     "label": "连接跟踪表扩容到 65536 条",
     "desc": "内核按内存估算默认值（实测 1GB 内存的 Debian 12 只有 7680 条），多设备/P2P 下会报 table full 丢包；"
             "哈希桶同步加到 16384。表满时约占 20MB 内存",
     "sysctl": ["net.netfilter.nf_conntrack_max=65536", "net.netfilter.nf_conntrack_buckets=16384"],
     "modules": ["nf_conntrack"]},
    {"key": "conntrack_timeout", "group": "连接跟踪", "mandatory": False, "default": True,
     "label": "缩短已建立 TCP 连接的空闲超时（同 OpenWrt）",
     "desc": "内核默认 432000 秒（5 天）改为 7440 秒：断开不发 FIN 的设备留下的表项约 2 小时后释放",
     "sysctl": ["net.netfilter.nf_conntrack_tcp_timeout_established=7440"], "modules": ["nf_conntrack"]},
    {"key": "bbr", "group": "TCP 与队列", "mandatory": False, "default": False,
     "label": "BBR 拥塞控制 + fq 队列",
     "desc": "只影响路由器自身发起的 TCP（控制台、代理、下载），转发流量不受拥塞算法影响；"
             "fq 只对之后新建的网卡队列生效。需内核 4.9+",
     "sysctl": ["net.core.default_qdisc=fq", "net.ipv4.tcp_congestion_control=bbr"], "modules": ["tcp_bbr"]},
    {"key": "mtu_probing", "group": "TCP 与队列", "mandatory": False, "default": True,
     "label": "TCP MTU 探测",
     "desc": "tcp_mtu_probing=1：路径上 ICMP 被丢时自动降 MSS，避免 PPPoE 下本机连接卡死",
     "sysctl": ["net.ipv4.tcp_mtu_probing=1"], "modules": []},
]
TUNING_KEYS = [t["key"] for t in TUNING if not t["mandatory"]]


class PlanError(ValueError):
    pass


def path(cfg, key):
    if key == "dnsmasq":  # same directory dnsmasq actually loads (and dhcp.py writes noobrouter.conf to)
        return os.path.join(cfg["dnsmasq_conf_dir"], "00-noobrouter-base.conf")
    return (cfg.get("sysroot") or "").rstrip("/") + PATHS[key]


def _ip(v, what):
    try:
        return ipaddress.ip_address(str(v).strip())
    except ValueError:
        raise PlanError(f"非法 {what}: {v}")


def normalize(plan):
    """Validate the wizard input. Returns a normalized copy (password included)."""
    wan, lan = dict(plan.get("wan") or {}), dict(plan.get("lan") or {})
    out = {"wan": {}, "lan": {}, "dhcp": {}, "dns": {}, "ipv6": {}}
    t = wan.get("type")
    if t not in ("pppoe", "dhcp", "static"):
        raise PlanError("WAN 类型必须是 pppoe / dhcp / static")
    for side, d in (("WAN", wan), ("LAN", lan)):
        if not IF_RE.match(str(d.get("if", ""))):
            raise PlanError(f"{side} 网卡名非法: {d.get('if')}")
    if wan["if"] == lan["if"]:
        raise PlanError("WAN 与 LAN 不能是同一块网卡")
    w = {"type": t, "if": wan["if"]}
    if t == "pppoe":
        for k in ("user", "password"):
            if not CRED_RE.match(str(wan.get(k, ""))):
                raise PlanError(f"PPPoE {k} 为空或含空白/引号/反斜杠/#")
        w.update(user=wan["user"], password=wan["password"])
        mtu = int(wan.get("mtu") or 1492)
        if not 576 <= mtu <= 1500:
            raise PlanError("PPPoE MTU 应在 576-1500")
        w["mtu"] = mtu
    if t == "static":
        try:
            w["address"] = str(ipaddress.ip_interface(str(wan.get("address", "")).strip()))
        except ValueError:
            raise PlanError(f"WAN 地址需为 CIDR，如 203.0.113.2/24: {wan.get('address')}")
        w["gateway"] = str(_ip(wan.get("gateway", ""), "WAN 网关"))
    out["wan"] = w

    try:
        li = ipaddress.ip_interface(str(lan.get("address", "")).strip())
    except ValueError:
        raise PlanError(f"LAN 地址需为 CIDR，如 192.168.50.1/24: {lan.get('address')}")
    if li.version != 4 or li.network.prefixlen > 30 or not li.ip.is_private:
        raise PlanError("LAN 地址需为私有 IPv4，前缀 /8-/30")
    if li.ip in (li.network.network_address, li.network.broadcast_address):
        raise PlanError("LAN 地址不能是网络号或广播地址")
    if t == "static" and ipaddress.ip_interface(w["address"]).network.overlaps(li.network):
        raise PlanError("WAN 与 LAN 网段重叠")
    out["lan"] = {"if": lan["if"], "address": str(li), "ip": str(li.ip), "cidr": str(li.network),
                  "netmask": str(li.netmask)}

    d = dict(plan.get("dhcp") or {})
    out["dhcp"] = {"enabled": bool(d.get("enabled", True))}
    if out["dhcp"]["enabled"]:
        s, e = _ip(d.get("start", ""), "DHCP 起始"), _ip(d.get("end", ""), "DHCP 结束")
        if s not in li.network or e not in li.network or int(s) > int(e):
            raise PlanError(f"DHCP 地址池需在 {li.network} 内且起始<=结束")
        if int(s) <= int(li.ip) <= int(e):
            raise PlanError("DHCP 地址池不能包含路由器自身 IP")
        lease = str(d.get("lease") or "12h")
        if not LEASE_RE.match(lease):
            raise PlanError(f"租期格式如 12h / 30m / infinite: {lease}")
        out["dhcp"].update(start=str(s), end=str(e), lease=lease)

    ups = [str(_ip(u, "上游 DNS")) for u in ((plan.get("dns") or {}).get("upstream") or [])]
    out["dns"] = {"upstream": ups or ["223.5.5.5", "119.29.29.29"]}
    out["ipv6"] = {"enabled": bool((plan.get("ipv6") or {}).get("enabled", True))}
    # tuning: plans saved before the catalogue existed carry no "tuning" -> nothing optional is added
    tn = plan.get("tuning") or {}
    if not isinstance(tn, dict):
        raise PlanError("tuning 需为对象")
    out["tuning"] = {k: bool(tn.get(k, False)) for k in TUNING_KEYS}
    port = int(plan.get("ssh_port") or 22)
    if not 1 <= port <= 65535:
        raise PlanError("SSH 端口非法")
    out["ssh_port"] = port
    return out


def public(plan):
    """Plan without the password (safe to store / return to the UI)."""
    p = {k: (dict(v) if isinstance(v, dict) else v) for k, v in plan.items()}
    if "password" in p.get("wan", {}):
        p["wan"]["password"] = "********"
    return p


def wan_if(plan):
    return "ppp0" if plan["wan"]["type"] == "pppoe" else plan["wan"]["if"]


def agent_cfg(cfg, plan):
    """cfg overrides the firewall/dhcp modules need after initialisation."""
    return dict(cfg, wan_if=wan_if(plan), wan_phy_if=plan["wan"]["if"], lan_if=plan["lan"]["if"],
                lan_cidr=plan["lan"]["cidr"], guard_ssh_port=plan["ssh_port"],
                # the old management IP may disappear on reboot; the new LAN IP is always there
                listen=plan["lan"]["ip"])


AGENT_KEYS = ("wan_if", "wan_phy_if", "lan_if", "lan_cidr", "guard_ssh_port", "listen")
SERVICES = ("dnsmasq", "netfilter-persistent")
# cloud images manage NICs via netplan -> systemd-networkd; ifupdown takes over during init
NETWORKD_UNITS = ("systemd-networkd.socket", "systemd-networkd", "systemd-networkd-wait-online")
CLOUD_NET_OFF = "/etc/cloud/cloud.cfg.d/99-noobrouter-disable-network.cfg"
WAN_UP_TIMEOUT = 30  # seconds; must stay well below applier's 60s post-step limit


# ---------------- probe (read-only) ----------------

def _pkg_installed(name):
    return "install ok installed" in try_run(["dpkg-query", "-W", "-f=${Status}", name])


def ppp_plugin():
    """Debian ppp 2.4.9 ships pppoe.so (rp-pppoe.so on older builds); 2.5 keeps pppoe.so."""
    found = []
    for base in ("/usr/lib/pppd", "/usr/lib/x86_64-linux-gnu/pppd", "/usr/lib/aarch64-linux-gnu/pppd"):
        for ver in sorted(os.listdir(base)) if os.path.isdir(base) else []:
            for name in ("pppoe.so", "rp-pppoe.so"):
                if os.path.exists(os.path.join(base, ver, name)):
                    found.append(name)
    return "pppoe.so" if "pppoe.so" in found else (found[0] if found else "")


def _stanzas(text):
    """Parse ifupdown text into stanzas: [{"kind", "names", "method", "lines": [idx...]}]."""
    out, cur = [], None
    for i, raw in enumerate(text.splitlines()):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        word = line.split()
        if word[0] in ("iface", "mapping", "auto", "source", "source-directory") or word[0].startswith("allow-"):
            cur = {"kind": word[0], "names": word[1:2] if word[0] in ("iface", "mapping") else word[1:],
                   "method": word[3] if word[0] == "iface" and len(word) > 3 else "", "lines": [i], "body": []}
            out.append(cur)
            if word[0] not in ("iface", "mapping"):
                cur = None
        elif cur is not None:
            cur["lines"].append(i)
            cur["body"].append(line)
    return out


def conflicts(text, plan):
    """Stanzas in a hand-written interfaces file that would fight with ours."""
    mine = {plan["wan"]["if"], plan["lan"]["if"]}
    res = []
    for s in _stanzas(text):
        hit = set(s["names"]) & mine
        if s["kind"] == "iface" and s["method"] == "ppp" and plan["wan"]["type"] == "pppoe":
            hit = hit or {s["names"][0]}  # a second pppd on the same NIC would fight ours
        if s["kind"] == "iface" and any(n in " ".join(s["body"]).split() for n in mine):
            hit = hit or {s["names"][0]}
        if hit and s["kind"] not in ("source", "source-directory"):
            res.append({"kind": s["kind"], "names": s["names"], "lines": s["lines"], "hit": sorted(hit)})
    return res


def _sources_dir(text, d):
    for s in _stanzas(text):
        for n in s["names"]:
            if (s["kind"] == "source" and n.rstrip("*").rstrip("/") == d.rstrip("/")) or \
               (s["kind"] == "source-directory" and n.rstrip("/") == d.rstrip("/")):
                return True
    return False


def nics(cfg):
    """Physical-ish NICs from /sys/class/net (skip lo, ppp, bridges, veth, docker...)."""
    base = (cfg.get("sysroot") or "") + "/sys/class/net"
    skip = ("lo", "ppp", "veth", "docker", "br-", "virbr", "tun", "tap", "wg", "tailscale", "dummy")
    res = []
    for n in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        if n.startswith(skip):
            continue
        rd = lambda f: read(os.path.join(base, n, f)).strip()  # noqa: E731
        res.append({"name": n, "mac": rd("address"), "carrier": rd("carrier") == "1",
                    "state": rd("operstate"), "speed": rd("speed")})
    return res


def probe(cfg):
    """Read-only environment check for the wizard."""
    return _probe(cfg)


def nm_devices():
    """NetworkManager-managed ethernet NICs: [{"if", "uuid", "method", "addresses"}].
    Connections are referenced by UUID: names may be localised ("有线连接 1") and garbled in -t output."""
    out = []
    for ln in try_run(["nmcli", "-t", "-e", "no", "-f", "DEVICE,TYPE,STATE,CON-UUID", "device"]).splitlines():
        f = ln.split(":")
        if len(f) < 4 or f[1] != "ethernet" or f[2] in ("unmanaged", "unavailable") or not f[3]:
            continue
        if not IF_RE.match(f[0]) or not re.match(r"^[0-9a-fA-F-]{36}$", f[3]):
            continue
        v = try_run(["nmcli", "-g", "ipv4.method,ipv4.addresses", "connection", "show", f[3]]).splitlines()
        out.append({"if": f[0], "uuid": f[3], "method": v[0].strip() if v else "",
                    "addresses": [a.strip() for a in (v[1] if len(v) > 1 else "").split(",") if a.strip()]})
    return out


def parse_peers(text):
    """pppd peers file -> {"user", "nic", "plugin", "mtu"}. Passwords never live here (chap/pap-secrets)."""
    res = {}
    for raw in text.splitlines():
        w = raw.split("#", 1)[0].split()
        if not w:
            continue
        if w[0] == "user" and len(w) > 1:
            res["user"] = " ".join(w[1:]).strip('"')
            continue
        if w[0] == "plugin" and len(w) > 1:
            res["plugin"] = os.path.basename(w[1])
        # pppoeconf may write "plugin rp-pppoe.so nic-wan0" on one line, or nic-xxx on its own
        nic = next((x[4:] for x in w if x.startswith("nic-") and IF_RE.match(x[4:])), None)
        if nic:
            res["nic"] = nic
        elif w[0] == "mtu" and len(w) > 1 and w[1].isdigit():
            res["mtu"] = int(w[1])
    return res


def read_secret(texts, user):
    """chap/pap-secrets texts -> password of `user` (first match, server * or any), or "".
    Lines are "client server secret [ip...]", tokens may be quoted; # starts a comment."""
    for text in texts:
        for raw in text.splitlines():
            try:
                w = shlex.split(raw, comments=True)
            except ValueError:
                continue
            if len(w) >= 3 and w[0] == user and CRED_RE.match(w[2]):
                return w[2]
    return ""


def detect_existing(cfg, main, frag, nic_list, nm):
    """Hand-built router config -> wizard pre-fill + who manages what. Read-only.
    The PPPoE password is read from chap/pap-secrets so the wizard can keep the existing account.
    {"wan": {...}|None, "lan": {...}|None, "providers": [{"name", "file", "nic", "user"}]}"""
    root = cfg.get("sysroot") or ""
    providers = []
    for fn, text in [(path(cfg, "ifaces_main"), main)] + list(frag.items()):
        for s in _stanzas(text):
            if s["kind"] != "iface" or s["method"] != "ppp" or s["names"][0] == PROVIDER:
                continue
            prov = next((ln.split()[1] for ln in s["body"] if ln.split()[0] == "provider" and len(ln.split()) > 1),
                        s["names"][0])
            if not re.match(r"^[A-Za-z0-9_.-]{1,64}$", prov):
                continue
            peer = parse_peers(read(f"{root}/etc/ppp/peers/{prov}"))
            providers.append(dict(peer, name=prov, file=fn, stanza=s["names"][0]))
    names = {n["name"] for n in nic_list}
    wan = None
    for p in providers:
        if p.get("nic") in names and p.get("user"):
            wan = {"type": "pppoe", "if": p["nic"], "user": p["user"], "mtu": p.get("mtu") or 1492,
                   "password": read_secret([read(path(cfg, k)) for k in ("chap", "pap")], p["user"]),
                   "source": f"/etc/ppp/peers/{p['name']}"}
            break
    lan = None
    for d in nm:
        v4 = [a for a in d["addresses"] if _private_cidr(a)]
        if d["method"] == "manual" and v4 and (not wan or d["if"] != wan["if"]):
            lan = {"if": d["if"], "address": v4[0], "source": f"NetworkManager 连接 {d['uuid']}", "nm_uuid": d["uuid"]}
            break
    if lan is None:
        for s in [x for t in [main] + list(frag.values()) for x in _stanzas(t)]:
            if s["kind"] == "iface" and s["method"] == "static" and s["names"][0] in names:
                addr = next((ln.split()[1] for ln in s["body"] if ln.split()[0] == "address" and len(ln.split()) > 1), "")
                if _private_cidr(addr) and (not wan or s["names"][0] != wan["if"]):
                    lan = {"if": s["names"][0], "address": addr, "source": "/etc/network/interfaces"}
                    break
    return {"wan": wan, "lan": lan, "providers": providers}


def _private_cidr(a):
    try:
        i = ipaddress.ip_interface(a)
    except ValueError:
        return False
    return i.version == 4 and i.ip.is_private and "/" in a


def _probe(cfg):
    osr = dict(line.split("=", 1) for line in read("/etc/os-release").splitlines() if "=" in line)
    pk = {p: _pkg_installed(p) for p in sorted({x for v in PKGS.values() for x in v})}
    main = read(path(cfg, "ifaces_main"))
    nm_active = try_run(["systemctl", "is-active", "NetworkManager"]).strip() == "active"
    root = cfg.get("sysroot") or ""
    own = os.path.basename(PATHS["ifaces"])
    nm = nm_devices() if nm_active else []
    nic_list = nics(cfg)
    frag = _read_dir(root + "/etc/network/interfaces.d", skip={own})
    return {"os": osr.get("PRETTY_NAME", "").strip('"'), "debian": osr.get("ID", "").strip('"') == "debian",
            "nics": nic_list, "packages": pk, "ppp_plugin": ppp_plugin(),
            "has": {c: has(c) for c in ("ifup", "pppd", "dnsmasq", "iptables-restore", "dhclient", "systemd-run")},
            "ip_forward": read("/proc/sys/net/ipv4/ip_forward").strip() == "1",
            "sources_interfaces_d": _sources_dir(main, "/etc/network/interfaces.d"),
            "network_manager": nm_active,
            "nm_devices": nm,
            # what this machine already runs (hand-made router): pre-fills the wizard, never a password
            "detected": detect_existing(cfg, main, frag, nic_list, nm),
            "networkd": try_run(["systemctl", "is-active", "systemd-networkd"]).strip() == "active",
            # other ifupdown fragments (cloud-init writes 50-cloud-init here) and netplan configs
            "interfaces_d": frag,
            "netplan": _read_dir(root + "/etc/netplan", suffix=".yaml"),
            "managed_exists": {k: os.path.exists(path(cfg, k))
                               for k in ("ifaces", "peers", "sysctl", "dnsmasq", "modules")},
            # original enablement, so rollback can undo our `systemctl enable`
            "svc_enabled": {s: try_run(["systemctl", "is-enabled", cfg.get("dnsmasq_service", s)
                                        if s == "dnsmasq" else s]).strip() for s in SERVICES},
            "networkd_enabled": {u: try_run(["systemctl", "is-enabled", u]).strip() for u in NETWORKD_UNITS},
            "cloud_init": os.path.isdir(root + "/etc/cloud/cloud.cfg.d"),
            "interfaces_main": main}


def _read_dir(d, skip=(), suffix=""):
    if not os.path.isdir(d):
        return {}
    return {f"{d}/{n}": read(os.path.join(d, n)) for n in sorted(os.listdir(d))
            if n not in skip and n.endswith(suffix) and not n.startswith(".")
            and os.path.isfile(os.path.join(d, n))}


def nm_issues(env, plan):
    """NetworkManager still owning a WAN/LAN NIC would re-apply its own profile and fight ifupdown.
    Returns (blockers, warnings)."""
    mine = (plan["wan"]["if"], plan["lan"]["if"])
    hit = [d for d in env.get("nm_devices") or [] if d["if"] in mine]
    blockers = [f"网卡 {d['if']} 由 NetworkManager 管理（连接 UUID {d['uuid']}），初始化后会争抢配置；"
                f"请先在 /etc/NetworkManager/conf.d/ 写入 [keyfile] unmanaged-devices=interface-name:{d['if']} "
                "并 systemctl reload NetworkManager（该口会短暂断开，请在控制台旁操作）" for d in hit]
    warnings = ["NetworkManager 正在运行，但未管理所选 WAN/LAN 网卡"] if env.get("network_manager") and not hit else []
    return blockers, warnings


def fragment_issues(env, plan):
    """Other network config sources (cloud-init ifupdown fragments, netplan, networkd) that would
    fight with our managed interfaces file. Returns (blockers, warnings).
    netplan/networkd are not blockers: build() takes them over inside the rollback transaction."""
    blockers, warnings = [], []
    for fn, text in (env.get("interfaces_d") or {}).items():
        for c in conflicts(text, plan):
            blockers.append(f"{fn} 已定义 {c['kind']} {' '.join(c['names'])}"
                            f"（涉及 {','.join(c['hit'])}；若为 cloud-init 生成，还需在 /etc/cloud/cloud.cfg.d/ 中"
                            f"写 'network: {{config: disabled}}'），请先移走该文件再初始化")
    for fn, hit in netplan_takeover(env, plan).items():
        warnings.append(f"netplan 配置 {fn} 管理了 {','.join(hit)}：初始化将移除它（回滚时恢复）")
    if env.get("networkd"):
        warnings.append("systemd-networkd 正在运行：初始化将停用它并改由 ifupdown 管理网卡（回滚时恢复）；"
                        "停用瞬间 WAN 的 DHCP 地址会重新获取")
    return blockers, warnings


def netplan_takeover(env, plan):
    """netplan files naming our WAN/LAN NICs -> {path: [nics]}."""
    mine = {plan["wan"]["if"], plan["lan"]["if"]}
    out = {}
    for fn, text in (env.get("netplan") or {}).items():
        hit = sorted(n for n in mine if n in text.replace(":", " ").split())
        if hit:
            out[fn] = hit
    return out


def netplan_renames(text):
    """{set-name: macaddress} from a netplan file (match.macaddress + set-name per ethernets entry).
    Minimal indentation parser: netplan YAML written by cloud-init/installers is block style."""
    out, block, base = {}, {}, None

    def flush():
        if block.get("name") and block.get("mac"):
            out[block["name"]] = block["mac"].lower()

    for ln in text.splitlines():
        s = ln.split("#", 1)[0].rstrip()
        if not s.strip():
            continue
        ind = len(s) - len(s.lstrip())
        if s.strip() == "ethernets:":
            base = None
            block = {}
            continue
        m = re.match(r"^\s*(\S+):\s*(\S*)$", s)
        if not m:
            continue
        if base is None or ind <= base:
            if base is not None and ind < base:
                flush()
                block, base = {}, None
                continue
            flush()
            block, base = {}, ind
            continue
        k, v = m.group(1), m.group(2).strip("'\"")
        if k == "macaddress" and v:
            block["mac"] = v
        elif k == "set-name" and v:
            block["name"] = v
    flush()
    return out


def render_link(name, mac):
    return (f"# noobrouter-agent: keeps the name netplan used to set (removed with netplan)\n"
            f"[Match]\nPermanentMACAddress={mac}\n\n[Link]\nName={name}\n")


def missing_packages(plan, pk):
    need = PKGS["base"] + (PKGS["pppoe"] if plan["wan"]["type"] == "pppoe" else [])
    if plan["wan"]["type"] == "dhcp" and not (has("dhclient") or has("dhcpcd") or has("udhcpc")):
        need += PKGS["dhcp"]
    return [p for p in need if not pk.get(p)]


# ---------------- render (pure) ----------------

HEAD = "# managed by noobrouter-agent bootstrap - edits will be overwritten\n"


def render_ifaces(plan):
    w, lan = plan["wan"], plan["lan"]
    out = [HEAD.rstrip(), "", f"auto {lan['if']}", f"iface {lan['if']} inet static",
           f"    address {lan['address']}"]
    if plan["ipv6"]["enabled"]:
        out += [f"iface {lan['if']} inet6 manual"]  # dnsmasq RA advertises the delegated/ULA prefix
    out.append("")
    if w["type"] == "pppoe":
        out += [f"auto {w['if']}", f"iface {w['if']} inet manual", f"    pre-up /sbin/ip link set {w['if']} up", "",
                f"auto {PROVIDER}", f"iface {PROVIDER} inet ppp", f"    pre-up /sbin/ip link set {w['if']} up",
                f"    provider {PROVIDER}"]
    elif w["type"] == "dhcp":
        # link may be DOWN after networkd stops; dhclient then retries ~60s on "Network is down"
        out += [f"auto {w['if']}", f"iface {w['if']} inet dhcp", f"    pre-up /sbin/ip link set {w['if']} up"]
        if plan["ipv6"]["enabled"]:
            out += [f"iface {w['if']} inet6 auto", "    accept_ra 2"]
    else:
        out += [f"auto {w['if']}", f"iface {w['if']} inet static", f"    address {w['address']}",
                f"    gateway {w['gateway']}", f"    pre-up /sbin/ip link set {w['if']} up"]
    return "\n".join(out) + "\n"


def render_peers(plan, plugin):
    w = plan["wan"]
    lines = [HEAD.rstrip(), "noipdefault", "defaultroute", "replacedefaultroute", "hide-password",
             "noauth", "persist", "maxfail 0", "holdoff 5", "lcp-echo-interval 20", "lcp-echo-failure 3",
             f"plugin {plugin or 'pppoe.so'}", f"nic-{w['if']}", f"user \"{w['user']}\"", "usepeerdns",
             f"mtu {w['mtu']}", f"mru {w['mtu']}"]
    if plan["ipv6"]["enabled"]:
        lines.append("+ipv6")
    return "\n".join(lines) + "\n"


def merge_secrets(text, plan):
    """Replace only our marked line; every other credential is kept verbatim."""
    keep = [ln for ln in text.splitlines() if not ln.rstrip().endswith(SECRET_MARK)]
    if plan["wan"]["type"] == "pppoe":
        w = plan["wan"]
        keep.append(f"\"{w['user']}\" * \"{w['password']}\" *  {SECRET_MARK}")
    return "\n".join(keep).rstrip("\n") + "\n" if keep else ""


def tuning_items(plan):
    """Catalogue entries in effect: mandatory ones plus the optional ones ticked in the plan."""
    on = plan.get("tuning") or {}
    return [t for t in TUNING if t["mandatory"] or on.get(t["key"])]


def tuning_modules(plan):
    return sorted({m for t in tuning_items(plan) for m in t["modules"]})


def render_modules(plan):
    mods = tuning_modules(plan)
    return (HEAD + "\n".join(mods) + "\n") if mods else None


def render_sysctl(plan):
    lines = [HEAD.rstrip()]
    for t in tuning_items(plan):
        lines += [f"# {t['key']}: {t['label']}", *t["sysctl"]]
    if plan["ipv6"]["enabled"]:
        wi = wan_if(plan)
        lines += ["net.ipv6.conf.all.forwarding=1", "net.ipv6.conf.default.forwarding=1",
                  "net.ipv6.conf.all.accept_ra=2", "net.ipv6.conf.default.accept_ra=2"]
        if wi != "ppp0":
            lines.append(f"net.ipv6.conf.{wi}.accept_ra=2")
    return "\n".join(lines) + "\n"


def render_dnsmasq(plan):
    """Base DHCP/RA settings. Upstream DNS lives only in the dhcp model (noobrouter.conf)."""
    lan, d = plan["lan"], plan["dhcp"]
    lines = [HEAD.rstrip(), f"interface={lan['if']}", "bind-dynamic", "domain-needed", "bogus-priv",
             "cache-size=2000"]
    if d["enabled"]:
        lines += [f"dhcp-range={d['start']},{d['end']},{lan['netmask']},{d['lease']}",
                  f"dhcp-option=option:router,{lan['ip']}", f"dhcp-option=option:dns-server,{lan['ip']}",
                  "dhcp-authoritative"]
    if plan["ipv6"]["enabled"]:
        # only advertises once the LAN NIC holds a global/ULA IPv6 prefix (e.g. from DHCPv6-PD)
        lines += [f"dhcp-range=::,constructor:{lan['if']},ra-stateless,ra-names,12h", "enable-ra"]
    return "\n".join(lines) + "\n"


# ---------------- transaction ----------------

def _sh(cmd):
    """Best-effort shell step: never fails the transaction (WAN dial-up may legitimately be slow).
    The whole group is detached from our pipes: daemons it spawns (dhclient, pppd) inherit fds,
    and an inherited stdout pipe would keep run() waiting until its timeout."""
    return ["/bin/sh", "-c", f"( {cmd} ) </dev/null >/dev/null 2>&1 || true"]


def _outside(env, cmd):
    """Run a WAN step outside the agent unit via a transient systemd service:
    - the agent's NoNewPrivileges blocks AppArmor's dhclient -> dhclient-script transition (no lease
      is ever configured), and
    - daemons left in the agent's cgroup (dhclient, pppd) die whenever the agent restarts.
    KillMode=process lets the daemons outlive the oneshot unit; TimeoutStartSec bounds the step."""
    if not env.get("has", {}).get("systemd-run"):
        return cmd
    return ("systemd-run --wait --collect --quiet -p Type=oneshot -p KillMode=process "
            f"-p TimeoutStartSec={WAN_UP_TIMEOUT + 10} /bin/sh -c {shlex.quote(cmd)}")


def _managed(iface):
    """Shell test: does the (restored) ifupdown config still bring up `iface` automatically?"""
    return f"ifquery --list 2>/dev/null | grep -qx {iface}"


def conflict_blockers(clash):
    """One blocker per distinct stanza head (inet + inet6 stanzas of one NIC read the same)."""
    out = []
    for c in clash:
        msg = (f"/etc/network/interfaces 已定义 {c['kind']} {' '.join(c['names'])}"
               f"（涉及 {','.join(c['hit'])}），请先注释掉该段再初始化")
        if msg not in out:
            out.append(msg)
    return out


def build(cfg, plan, env=None):
    """Pure-ish: everything apply() would do, for preview and apply alike."""
    env = env if env is not None else probe(cfg)
    acfg = agent_cfg(cfg, plan)
    w, lan = plan["wan"], plan["lan"]
    blockers, warnings = [], []
    if not env["sources_interfaces_d"]:
        blockers.append("/etc/network/interfaces 未包含 'source /etc/network/interfaces.d/*'，受管片段不会生效")
    clash = conflicts(env["interfaces_main"], plan)
    blockers += conflict_blockers(clash)
    fb, fwarn = fragment_issues(env, plan)
    blockers += fb
    warnings += fwarn
    names = {n["name"] for n in env["nics"]}
    for side, n in (("WAN", w["if"]), ("LAN", lan["if"])):
        if names and n not in names:
            blockers.append(f"{side} 网卡 {n} 不存在（可用: {', '.join(sorted(names))}）")
    miss = missing_packages(plan, env["packages"])
    if miss:
        blockers.append("缺少软件包: " + " ".join(miss) + "（先运行 install.sh --with-deps 或 apt-get install）")
    main_dm = [ln.strip() for ln in read(cfg["dnsmasq_main_conf"]).splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    dup = [ln for ln in main_dm if ln.split("=", 1)[0] in ("interface", "dhcp-range", "dhcp-option", "enable-ra")]
    if dup:
        blockers.append(f"{cfg['dnsmasq_main_conf']} 已有手写的 DHCP 设置（{'; '.join(dup[:4])}），"
                        "与初始化生成的基础配置重复；请先注释掉这些行")
    nb, nw = nm_issues(env, plan)
    blockers += nb
    warnings += nw
    if plan["ipv6"]["enabled"]:
        warnings.append("IPv6：LAN 的 RA 仅在 LAN 口获得公网/ULA 前缀后生效；本向导不配置 DHCPv6-PD")
    for m in env.get("modules_missing", []):
        names = "、".join(t["label"] for t in tuning_items(plan) if m in t["modules"])
        blockers.append(f"内核没有模块 {m}，请取消勾选“{names}”（否则 sysctl 会失败并整体回滚）")

    # existing machine: keep its forwards (imported from live rules on first use); blank: empty model
    fw = store.firewall_model(acfg)
    if not store.import_report(cfg)["acknowledged"]:
        blockers.append("现有防火墙含导入器未识别的规则，初始化整表替换会删除它们；请先在防火墙页确认")
    # a router built by the wizard always filters WAN->LAN forwarding (existing forwards keep working via DNAT)
    fw = firewall.normalize(dict(fw, ipv6_filter=plan["ipv6"]["enabled"] or fw.get("ipv6_filter"),
                                 forward_filter=True), acfg)
    v4, v6 = firewall.render_v4(fw, acfg), firewall.render_v6(fw, acfg)
    dm = dict(store.dhcp_model(cfg), upstream=plan["dns"]["upstream"])
    dm = dhcp.normalize(dm, acfg)

    secrets_old = {k: read(path(cfg, k)) for k in ("chap", "pap")}
    files = [{"path": path(cfg, "ifaces"), "content": render_ifaces(plan), "mode": 0o644},
             {"path": path(cfg, "sysctl"), "content": render_sysctl(plan), "mode": 0o644},
             {"path": path(cfg, "dnsmasq"), "content": render_dnsmasq(plan), "mode": 0o644},
             {"path": os.path.join(cfg["dnsmasq_conf_dir"], "noobrouter.conf"), "content": dhcp.render(dm),
              "mode": 0o644}]
    mods = tuning_modules(plan)
    # no module needed any more but a previous init left the list: remove it (snapshot restores it)
    if mods or env.get("managed_exists", {}).get("modules"):
        files.append({"path": path(cfg, "modules"), "content": render_modules(plan), "mode": 0o644})
    if w["type"] == "pppoe" or any(SECRET_MARK in t for t in secrets_old.values()):
        for k in ("chap", "pap"):
            files.append({"path": path(cfg, k), "content": merge_secrets(secrets_old[k], plan), "mode": 0o600})
    if w["type"] == "pppoe":
        files.append({"path": path(cfg, "peers"), "content": render_peers(plan, env["ppp_plugin"]), "mode": 0o644})
    if cfg.get("config_path"):
        upd = {k: acfg[k] for k in AGENT_KEYS}
        files.append({"path": cfg["config_path"], "content": config.file_text(cfg["config_path"], upd),
                      "mode": 0o600})
    # netplan files for our NICs are removed (snapshot restores them on rollback); stop cloud-init
    # from regenerating them on the next boot
    root = (cfg.get("sysroot") or "").rstrip("/")
    takeover = netplan_takeover(env, plan)
    for fn in takeover:
        files.append({"path": fn, "content": None, "mode": 0o600})
        for name, mac in netplan_renames(env["netplan"][fn]).items():
            if name in (w["if"], lan["if"]):
                files.append({"path": f"{root}/etc/systemd/network/10-noobrouter-{name}.link",
                              "content": render_link(name, mac), "mode": 0o644})
    if takeover and env.get("cloud_init"):
        files.append({"path": root + CLOUD_NET_OFF, "mode": 0o644,
                      "content": "# noobrouter-agent: NICs are managed by ifupdown\nnetwork: {config: disabled}\n"})

    ns = applier._ns(cfg)
    # modules are global (not per netns): load them first, the nf_conntrack/bbr keys only exist after
    post = ([["modprobe", "-a", *mods]] if mods else []) + [
            ns + ["sysctl", "-q", "-p", path(cfg, "sysctl")],
            # add the new LAN IP next to whatever is there now: an SSH session on the old IP survives
            ns + ["ip", "link", "set", lan["if"], "up"],
            ns + ["ip", "addr", "replace", lan["address"], "dev", lan["if"]]]
    # rollback restores runtime sysctl values too (removing the file alone changes nothing until reboot)
    undo = [ns + ["sysctl", "-q", "-w", f"{k}={v}"] for k, v in env.get("sysctl_now", {}).items()]
    if lan["ip"] not in env.get("lan_current_ips", []):
        undo.append(ns + ["ip", "addr", "del", lan["address"], "dev", lan["if"]])
    if not cfg.get("sysroot"):
        pre, more, back = service_steps(cfg, plan, env, bool(takeover))
        post = pre + post + more
        undo += back
    return {"plan": public(plan), "agent": {k: acfg[k] for k in AGENT_KEYS}, "blockers": blockers,
            "warnings": warnings, "missing_packages": miss,
            "files": [{"path": f["path"], "mode": f"{f['mode']:04o}",
                       "content": "(将删除，回滚时恢复)" if f["content"] is None
                       else "(含密码或 token，已隐藏)" if f["mode"] == 0o600 else f["content"]}
                      for f in files],
            "v4": v4, "v6": v6, "post": post, "undo": undo, "_files": files, "_fw": fw, "_dm": dm}


def service_steps(cfg, plan, env, takeover):
    """Host service steps (skipped when sysroot is set). Returns (post_first, post_last, undo).
    undo runs after files are restored, so each service goes back to its original state."""
    w = plan["wan"]
    pre, post, undo = [], [], []
    post += [["dnsmasq", "--test", f"--conf-file={cfg['dnsmasq_main_conf']}",
              f"--conf-dir={cfg['dnsmasq_conf_dir']},.dpkg-dist,.dpkg-old,.dpkg-new"],
             ["systemctl", "enable", cfg["dnsmasq_service"]],
             ["systemctl", "restart", cfg["dnsmasq_service"]],
             ["systemctl", "enable", "netfilter-persistent"]]
    was = env.get("svc_enabled", {})
    if was.get("dnsmasq") == "enabled":
        undo.append(["systemctl", "restart", cfg["dnsmasq_service"]])
    else:
        undo.append(["systemctl", "disable", "--now", cfg["dnsmasq_service"]])
    if was.get("netfilter-persistent") != "enabled":
        undo.append(["systemctl", "disable", "netfilter-persistent"])  # no stop: it may flush rules
    # WAN before networkd in undo: release our lease before networkd takes the NIC back
    if w["type"] == "pppoe":
        post.append(_sh(_outside(env, f"ip link set {w['if']} up; poff {PROVIDER}; pon {PROVIDER}")))
        # re-init rollback: restored files may still define our provider -> dial it again
        undo.append(_sh(_outside(env, f"poff {PROVIDER}; if {_managed(PROVIDER)}; then "
                                      f"ip link set {w['if']} up; pon {PROVIDER}; fi")))
    else:
        # best effort (never rolls back the LAN side); apply() reports the result via wan_status()
        # link up first; bounded so post never hits the 60s run() limit. If ifup fails or times out
        # fall back to a backgrounded dhclient with ifupdown's pidfile/leasefile paths.
        pid = f"/run/dhclient.{w['if']}.pid"
        bg = (f"dhclient -4 -nw -pf {pid} -lf /var/lib/dhcp/dhclient.{w['if']}.leases {w['if']}"
              if w["type"] == "dhcp" else "true")
        post.append(_sh(_outside(env, f"ifdown --force {w['if']}; /sbin/ip link set {w['if']} up; "
                                      f"timeout {WAN_UP_TIMEOUT} ifup --force {w['if']} || {bg}")))
        # files are already restored when undo runs, so ifdown may not know the NIC any more:
        # also stop the dhclient ifup started (pidfile path used by ifupdown)
        # re-init rollback: if the restored files still manage the WAN (previous init), bring it back
        # up; on a fresh machine our fragment is gone and networkd (restarted below) takes it back
        undo.append(_sh(_outside(env, f"ifdown --force {w['if']}; [ -f {pid} ] && kill $(cat {pid}); "
                                      f"rm -f {pid}; if {_managed(w['if'])}; then "
                                      f"/sbin/ip link set {w['if']} up; "
                                      f"timeout {WAN_UP_TIMEOUT} ifup --force {w['if']} || {bg}; fi")))
    # networkd: stopped first so it can't fight ifupdown; undo restores enablement and running state
    nd = env.get("networkd_enabled", {})
    on = [u for u in NETWORKD_UNITS if nd.get(u) == "enabled"]
    if env.get("networkd") or on:
        pre.append(["systemctl", "disable", "--now", *NETWORKD_UNITS])
        if takeover:
            undo.append(_sh("netplan generate"))  # regenerate /run/systemd/network from restored yaml
        if on:
            undo.append(["systemctl", "enable", *on])
        if env.get("networkd"):
            undo.append(["systemctl", "start", "systemd-networkd"])
    return pre, post, undo


def _strip(tx):
    return {k: v for k, v in tx.items() if not k.startswith("_")}


def preview(cfg, raw):
    plan = normalize(raw)
    tx = build(cfg, plan, _env(cfg, plan))
    applier.test_rules(tx["v4"], tx["v6"], cfg)
    return _strip(tx)


def module_available(m):
    """Loaded / built in (/sys/module) or installable (modinfo finds a .ko)."""
    return os.path.isdir(f"/sys/module/{m}") or bool(try_run(["modinfo", "-F", "filename", m]).strip())


def _env(cfg, plan, load=False):
    """load=True (apply only, never preview): load tuning modules first, so the original values of keys
    that exist only with the module (nf_conntrack_*) are captured and a rollback restores them."""
    env = probe(cfg)
    mods = tuning_modules(plan)
    env["modules_missing"] = [m for m in mods if not module_available(m)]
    if load and mods and not env["modules_missing"]:
        try_run(["modprobe", "-a", *mods])
    out = try_run(applier._ns(cfg) + ["ip", "-j", "addr", "show", "dev", plan["lan"]["if"]])
    try:
        env["lan_current_ips"] = [a["local"] for i in json.loads(out or "[]") for a in i.get("addr_info", [])]
    except ValueError:
        env["lan_current_ips"] = []
    keys = [ln.split("=", 1)[0].strip() for ln in render_sysctl(plan).splitlines() if "=" in ln]
    env["sysctl_now"] = {}
    for k in keys:
        v = try_run(applier._ns(cfg) + ["sysctl", "-n", k]).strip()
        if v:
            env["sysctl_now"][k] = v
    return env


def apply(cfg, raw, force=False):
    """One rollback transaction. Unconfirmed -> files, rules, LAN IP all revert automatically."""
    plan = normalize(raw)
    tx = build(cfg, plan, _env(cfg, plan, load=True))
    if tx["blockers"]:
        # one blocker per line: blockers contain "；" themselves, and the UI/i18n work per line
        raise CmdError("存在阻塞项:\n" + "\n".join(tx["blockers"]), 409)
    if tx["warnings"] and not force:
        return dict(_strip(tx), applied=False)
    # written before the transaction so a crash in between can't lose it; txid links it to the pending tx
    store.save(cfg, "bootstrap_pending", {"plan": public(plan), "agent": tx["agent"], "fw": tx["_fw"],
                                          "dhcp": tx["_dm"], "txid": None})
    try:
        info = applier.apply(tx["v4"], tx["v6"], cfg,
                             summary=f"初始化 WAN={plan['wan']['type']} LAN={plan['lan']['address']}",
                             kind="init", files=tx["_files"], post=tx["post"], undo=tx["undo"])
    except Exception:
        _drop_pending(cfg)
        raise
    st = _load_pending(cfg)
    st["txid"] = info["txid"]
    store.save(cfg, "bootstrap_pending", st)
    return dict(_strip(tx), applied=True, pending=info, wan=wan_status(cfg, plan))


def wan_status(cfg, plan):
    """Post-apply WAN check (WAN failure never rolls back: LAN stays reachable to fix it)."""
    dev = wan_if(plan)
    out = try_run(applier._ns(cfg) + ["ip", "-j", "-4", "addr", "show", "dev", dev])
    try:
        addrs = [a["local"] for i in json.loads(out or "[]") for a in i.get("addr_info", [])]
    except ValueError:
        addrs = []
    res = {"if": dev, "ipv4": addrs, "ok": bool(addrs)}
    if not addrs:
        res["hint"] = ("PPPoE 仍在拨号或认证失败，稍后在状态页查看 ppp0；日志: journalctl -t pppd"
                       if plan["wan"]["type"] == "pppoe" else
                       f"{dev} 未获得 IPv4 地址：检查网线/上游，或执行 ifup --force {dev} 查看报错")
    return res


def _pending_path(cfg):
    return os.path.join(cfg["data_dir"], "bootstrap_pending.json")


def _load_pending(cfg):
    p = _pending_path(cfg)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _drop_pending(cfg):
    p = _pending_path(cfg)
    if os.path.exists(p):
        os.remove(p)


def confirm(cfg):
    """Persist models + live cfg only after the user confirmed connectivity."""
    info = applier.pending(cfg)
    if not info or info.get("kind") != "init":
        raise CmdError("没有待确认的初始化", 409)
    st = _load_pending(cfg)
    res = applier.confirm(cfg)
    res["restart"] = False
    if st and st.get("txid") == info["txid"]:
        moved = st["agent"].get("listen") and st["agent"]["listen"] != cfg.get("listen")
        cfg.update(st["agent"])  # running agent switches to the new interfaces immediately
        store.save(cfg, "firewall", st["fw"])
        store.save(cfg, "firewall_import", {"skipped": [], "acknowledged": True})
        store.save(cfg, "dhcp", st["dhcp"])
        store.save(cfg, "bootstrap", {"plan": st["plan"], "txid": st["txid"]})
        if moved:  # the socket is bound once at startup: rebind on the new LAN IP
            res["restart"] = schedule_restart(cfg)
            res["listen"] = cfg["listen"]
    _drop_pending(cfg)
    return res


def schedule_restart(cfg, delay=2):
    """Restart the agent unit a moment later so the confirm response reaches the browser first.
    Only under systemd (INVOCATION_ID is set for service processes); never in netns drills."""
    unit = cfg.get("service_unit", "noobrouter-agent")
    if cfg.get("netns") or not os.environ.get("INVOCATION_ID") or not has("systemd-run"):
        return False
    if not re.match(r"^[A-Za-z0-9@._-]{1,64}$", unit):
        return False
    try:  # systemd-run reports on stderr; success = exit 0
        applier.run(["systemd-run", f"--on-active={int(delay)}", "--timer-property=AccuracySec=100ms",
                     "systemctl", "restart", f"{unit}.service"])
        ok = True
    except CmdError:
        ok = False
    applier.log(cfg, f"agent restart scheduled for new listen {cfg.get('listen')}: {'ok' if ok else 'failed'}")
    return ok


def rollback(cfg):
    info = applier.pending(cfg)
    if not info or info.get("kind") != "init":
        raise CmdError("没有待回滚的初始化", 409)
    res = applier.rollback(cfg)
    _drop_pending(cfg)
    return res


def state(cfg):
    p = os.path.join(cfg["data_dir"], "bootstrap.json")
    done = None
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            done = json.load(f)
    pend = applier.pending(cfg)
    st = _load_pending(cfg)
    # timer-driven rollback runs outside the agent: drop the stale plan once its tx is gone
    # txid None = apply() is between writing the plan and opening the tx: leave it alone
    if st and st.get("txid") and not (pend and pend.get("kind") == "init" and pend.get("txid") == st["txid"]):
        _drop_pending(cfg)
    return {"initialized": done, "pending": pend, "last_rollback": applier.last_rollback(cfg)}
