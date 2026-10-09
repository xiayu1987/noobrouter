"""Read-only network collectors: interfaces, routes, traffic, devices, conntrack."""
import json
import time

from .shell import read, try_run


def interfaces():
    out = try_run(["ip", "-j", "addr"])
    data = json.loads(out) if out.strip() else []
    stats = netdev()
    res = []
    for i in data:
        name = i.get("ifname")
        res.append({
            "name": name,
            "state": i.get("operstate"),
            "mtu": i.get("mtu"),
            "mac": i.get("address"),
            "type": i.get("link_type"),
            "addrs": [f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", [])],
            "rx_bytes": stats.get(name, {}).get("rx_bytes", 0),
            "tx_bytes": stats.get(name, {}).get("tx_bytes", 0),
            "rx_drop": stats.get(name, {}).get("rx_drop", 0),
        })
    return res


def netdev():
    res = {}
    for line in read("/proc/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) >= 9:
            res[name.strip()] = {"rx_bytes": int(f[0]), "rx_drop": int(f[3]), "tx_bytes": int(f[8])}
    return res


def routes():
    out = try_run(["ip", "-j", "route"])
    out6 = try_run(["ip", "-6", "-j", "route"])
    return {"v4": json.loads(out) if out.strip() else [], "v6": json.loads(out6) if out6.strip() else []}


def leases(path):
    """Parse dnsmasq leases: '<expiry> <mac> <ip> <hostname> <clientid>'."""
    res = []
    for line in read(path).splitlines():
        f = line.split()
        if len(f) >= 4 and f[0] != "duid":
            res.append({"expiry": int(f[0]), "mac": f[1].lower(), "ip": f[2],
                        "hostname": "" if f[3] == "*" else f[3]})
    return res


def arp():
    res = []
    for line in read("/proc/net/arp").splitlines()[1:]:
        f = line.split()
        if len(f) >= 6:
            # flags 0x2 = complete (reachable), 0x0 = incomplete
            res.append({"ip": f[0], "mac": f[3].lower(), "online": f[2] == "0x2", "dev": f[5]})
    return res


def devices(leases_path, static_hosts=()):
    """Merge ARP + DHCP leases + static bindings into one list keyed by MAC."""
    now = int(time.time())
    by_mac = {}
    for l in leases(leases_path):
        by_mac[l["mac"]] = {"mac": l["mac"], "ip": l["ip"], "hostname": l["hostname"],
                            "lease_left": max(l["expiry"] - now, 0), "online": False, "static": False}
    for s in static_hosts:
        d = by_mac.setdefault(s["mac"], {"mac": s["mac"], "ip": s["ip"], "hostname": "",
                                          "lease_left": None, "online": False})
        d.update({"static": True, "ip": s["ip"], "hostname": s.get("name") or d["hostname"]})
    for a in arp():
        if a["mac"] == "00:00:00:00:00:00":
            continue
        d = by_mac.setdefault(a["mac"], {"mac": a["mac"], "ip": a["ip"], "hostname": "",
                                          "lease_left": None, "static": False, "online": False})
        d["online"] = d["online"] or a["online"]
        d["ip"] = a["ip"] if a["online"] else d["ip"]
    return sorted(by_mac.values(), key=lambda d: tuple(int(x) for x in d["ip"].split(".")) if d["ip"].count(".") == 3 else (999,))


def connections(limit=500):
    """Parse /proc/net/nf_conntrack (first tuple = original direction)."""
    res, per_src = [], {}
    for line in read("/proc/net/nf_conntrack").splitlines():
        f = line.split()
        if len(f) < 6:
            continue
        kv = {}
        for tok in f:
            k, eq, v = tok.partition("=")
            if eq and k not in kv:
                kv[k] = v
        proto = f[2]
        state = f[5] if proto == "tcp" else ""
        src = kv.get("src", "")
        per_src[src] = per_src.get(src, 0) + 1
        if len(res) < limit:
            res.append({"family": f[0], "proto": proto, "state": state, "src": src, "dst": kv.get("dst", ""),
                        "sport": kv.get("sport", ""), "dport": kv.get("dport", "")})
    top = sorted(per_src.items(), key=lambda x: -x[1])[:10]
    return {"items": res, "top_sources": [{"ip": k, "count": v} for k, v in top]}
