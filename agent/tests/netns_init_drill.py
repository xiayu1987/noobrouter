"""Init (bootstrap) drill in a throwaway netns + temp sysroot (Linux, root).
Usage: python3 tests/netns_init_drill.py [sleep|systemd]
Never touches host services: sysroot set -> no systemctl/pon/ifup; ip/sysctl run inside the netns."""
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from noobrouter_agent import api, applier, bootstrap, config  # noqa: E402

timer = sys.argv[1] if len(sys.argv) > 1 else "sleep"
ns = f"srinit{os.getpid()}"
tmp = tempfile.mkdtemp()
root, data = os.path.join(tmp, "root"), os.path.join(tmp, "data")
os.makedirs(os.path.join(root, "etc/network/interfaces.d"))
os.makedirs(os.path.join(root, "etc/dnsmasq.d"))
os.makedirs(data)
with open(os.path.join(root, "etc/network/interfaces"), "w") as f:
    f.write("source /etc/network/interfaces.d/*\nauto lo\niface lo inet loopback\n")
open(os.path.join(root, "etc/dnsmasq.conf"), "w").close()
cfg = dict(config.DEFAULTS, netns=ns, sysroot=root, data_dir=data, dry_run=False, rollback_seconds=3,
           rollback_timer=timer, token="x", dnsmasq_conf_dir=os.path.join(root, "etc/dnsmasq.d"),
           dnsmasq_main_conf=os.path.join(root, "etc/dnsmasq.conf"), config_path="")
WAN, LAN = "srwan0", "srlan0"
PLAN = {"wan": {"type": "dhcp", "if": WAN}, "lan": {"if": LAN, "address": "10.99.0.1/24"},
        "dhcp": {"enabled": True, "start": "10.99.0.100", "end": "10.99.0.200", "lease": "12h"},
        "dns": {"upstream": ["223.5.5.5"]}, "ipv6": {"enabled": False}, "ssh_port": 22}

# probe reads host dpkg/NM/sysfs; the drill pins those facts to the netns test bed
_real_probe = bootstrap.probe


def fake_probe(c):
    env = _real_probe(c)
    env["packages"] = {p: True for p in env["packages"]}
    env["nics"] = [{"name": n, "mac": "", "carrier": True, "state": "up", "speed": ""} for n in (WAN, LAN)]
    env["network_manager"] = False
    env["networkd"] = False
    env["interfaces_d"], env["netplan"] = {}, {}
    return env


bootstrap.probe = fake_probe


def sh(*a):
    return subprocess.run(["ip", "netns", "exec", ns, *a], capture_output=True, text=True).stdout


def lan_ips():
    return sh("ip", "-4", "-o", "addr", "show", "dev", LAN)


def fwd():
    return sh("sysctl", "-n", "net.ipv4.ip_forward").strip()


def managed():
    return os.path.exists(bootstrap.path(cfg, "ifaces"))


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        raise SystemExit(1)


def expect_409(fn, msg):
    try:
        fn()
        check(False, msg)
    except (api.ApiError, applier.CmdError) as e:
        check(getattr(e, "status", None) == 409, msg)


subprocess.run(["ip", "netns", "add", ns], check=True)
try:
    sh("ip", "link", "add", WAN, "type", "veth", "peer", "name", "srwanp")
    sh("ip", "link", "add", LAN, "type", "veth", "peer", "name", "srlanp")
    base_fwd = fwd()
    check(not managed() and "10.99.0.1" not in lan_ips(), f"baseline: no managed files, ip_forward={base_fwd}")

    pv = bootstrap.preview(cfg, PLAN)
    check(not pv["blockers"] and not pv["warnings"], f"preview clean ({len(pv['files'])} files)")
    check(not managed(), "preview writes nothing")
    expect_409(lambda: bootstrap.apply(dict(cfg, dry_run=True), PLAN), "dry_run apply -> 409")

    # round 1: apply, never confirm -> files, LAN IP, sysctl all revert
    r = bootstrap.apply(cfg, PLAN)
    check(r["applied"] and managed() and "10.99.0.1/24" in lan_ips() and fwd() == "1",
          "applied: files written, LAN IP added, ip_forward=1")
    expect_409(lambda: api.fw_confirm(cfg, {}, {}), "firewall confirm refuses init tx")
    expect_409(lambda: api.fw_rollback(cfg, {}, {}), "firewall rollback refuses init tx")
    time.sleep(cfg["rollback_seconds"] + 3)
    st = bootstrap.state(cfg)
    check(not managed() and "10.99.0.1" not in lan_ips() and fwd() == base_fwd, "timeout -> fully reverted")
    check(st["pending"] is None and st["last_rollback"]["kind"] == "init"
          and st["last_rollback"]["reason"] == "timeout", "last_rollback=init/timeout")
    check(not os.path.exists(os.path.join(data, "bootstrap_pending.json")), "stale plan cleaned by state()")

    # round 2: apply + confirm -> kept past the deadline, models persisted
    bootstrap.apply(cfg, PLAN)
    api.init_confirm(cfg, {}, {})
    time.sleep(cfg["rollback_seconds"] + 3)
    st = bootstrap.state(cfg)
    check(managed() and "10.99.0.1/24" in lan_ips() and st["initialized"], "confirmed -> kept, bootstrap.json saved")
    check(cfg["lan_if"] == LAN and cfg["wan_if"] == WAN, "running cfg switched to new interfaces")
    first = open(bootstrap.path(cfg, "ifaces")).read()

    # round 3: change LAN, manual rollback -> back to round-2 state
    p3 = dict(PLAN, lan={"if": LAN, "address": "10.99.1.1/24"},
              dhcp={"enabled": True, "start": "10.99.1.100", "end": "10.99.1.200"})
    bootstrap.apply(cfg, p3)
    check("10.99.1.1/24" in lan_ips() and "10.99.0.1/24" in lan_ips(), "new LAN IP added, old kept (no lockout)")
    api.init_rollback(cfg, {}, {})
    check("10.99.1.1" not in lan_ips() and "10.99.0.1/24" in lan_ips(), "manual rollback removed only the new IP")
    check(open(bootstrap.path(cfg, "ifaces")).read() == first, "managed file restored to confirmed version")
    expect_409(lambda: api.init_confirm(cfg, {}, {}), "confirm with nothing pending -> 409")
    print("ALL PASS")
finally:
    subprocess.run(["ip", "netns", "del", ns])
    shutil.rmtree(tmp, ignore_errors=True)
