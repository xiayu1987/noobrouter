"""dnsmasq management. Only owns <conf_dir>/noobrouter.conf; the main dnsmasq.conf is read-only.

Model (data_dir/dhcp.json): {"static": [{"mac","ip","name"}], "records": [{"domain","ip"}],
                             "upstream": ["223.5.5.5"]}
"""
import ipaddress
import os
import re

from .shell import CmdError, read, run

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9-]{1,63}$")
EMPTY = {"static": [], "records": [], "upstream": []}


def main_settings(cfg):
    """Parse the hand-written main config for display (never modified)."""
    res = {"dhcp_range": [], "dhcp_option": [], "interface": [], "other": []}
    for line in read(cfg["dnsmasq_main_conf"]).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        key = k.replace("-", "_")
        (res[key] if key in res else res["other"]).append(v if key in res else line)
    return res


def normalize(model, cfg):
    lan = ipaddress.ip_network(cfg["lan_cidr"], strict=False)
    out = {"static": [], "records": [], "upstream": []}
    macs, ips = set(), set()
    for s in model.get("static", []):
        mac = str(s.get("mac", "")).lower().replace("-", ":")
        if not MAC_RE.match(mac):
            raise ValueError(f"非法 MAC: {s.get('mac')}")
        ip = ipaddress.ip_address(s.get("ip", ""))
        if ip not in lan:
            raise ValueError(f"{ip} 不在 LAN 网段内")
        name = str(s.get("name") or "")
        if name and not NAME_RE.match(name):
            raise ValueError(f"非法主机名: {name}（字母数字和-）")
        if mac in macs or str(ip) in ips:
            raise ValueError(f"静态绑定重复: {mac} / {ip}")
        macs.add(mac), ips.add(str(ip))
        out["static"].append({"mac": mac, "ip": str(ip), "name": name})
    for r in model.get("records", []):
        dom = str(r.get("domain", "")).strip(".")
        if not DOMAIN_RE.match(dom):
            raise ValueError(f"非法域名: {dom}")
        out["records"].append({"domain": dom, "ip": str(ipaddress.ip_address(r.get("ip", "")))})
    for u in model.get("upstream", []):
        out["upstream"].append(str(ipaddress.ip_address(str(u).strip())))
    return out


def render(model):
    lines = ["# managed by noobrouter-agent - edits will be overwritten"]
    lines += [f"dhcp-host={s['mac']},{s['ip']}" + (f",{s['name']}" if s["name"] else "") for s in model["static"]]
    lines += [f"address=/{r['domain']}/{r['ip']}" for r in model["records"]]
    if model["upstream"]:
        lines.append("no-resolv")
        lines += [f"server={u}" for u in model["upstream"]]
    return "\n".join(lines) + "\n"


def _managed_path(cfg):
    return os.path.join(cfg["dnsmasq_conf_dir"], "noobrouter.conf")


def test_config(cfg):
    """dnsmasq --test over main conf + conf dir, using the same exclusions as /etc/default/dnsmasq.
    Never leave extra files in conf_dir: dnsmasq loads everything except .dpkg-* and dotfiles."""
    run(["dnsmasq", "--test", f"--conf-file={cfg['dnsmasq_main_conf']}",
         f"--conf-dir={cfg['dnsmasq_conf_dir']},.dpkg-dist,.dpkg-old,.dpkg-new"])


def _restore(path, old):
    if old is None:
        if os.path.exists(path):
            os.remove(path)
    else:
        _atomic_write(path, old)


def _atomic_write(path, text):
    d, base = os.path.split(path)
    tmp = os.path.join(d, f".{base}.tmp")  # dotfile: ignored by dnsmasq conf-dir
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def apply(model, cfg):
    """Write managed conf -> dnsmasq --test -> restart. Any failure restores the previous file.
    Note: restart briefly interrupts LAN DNS/DHCP (~1s); leases survive in the lease file."""
    if cfg.get("dry_run"):
        raise CmdError("dry_run 模式：不会写入 dnsmasq 配置", 409)
    path = _managed_path(cfg)
    old = read(path, None) if os.path.exists(path) else None
    if old is not None:
        _atomic_write(os.path.join(cfg["data_dir"], "noobrouter.conf.bak"), old)
    _atomic_write(path, render(model))
    try:
        test_config(cfg)
        if cfg.get("dnsmasq_service"):
            run(["systemctl", "restart", cfg["dnsmasq_service"]], timeout=30)
            run(["systemctl", "is-active", "--quiet", cfg["dnsmasq_service"]])
    except CmdError:
        _restore(path, old)
        if cfg.get("dnsmasq_service"):
            run(["systemctl", "restart", cfg["dnsmasq_service"]], check=False, timeout=30)
        raise
    return {"path": path, "lines": len(render(model).splitlines())}
