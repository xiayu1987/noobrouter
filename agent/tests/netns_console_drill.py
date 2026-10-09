"""Console-port auto-open drill (Linux, root). Usage: python3 tests/netns_console_drill.py

Two throwaway netns joined by a veth: "router" runs the real agent with INPUT policy DROP,
"client" plays another LAN machine. Covers dry_run (warn only), auto-insert, port change + restart,
no duplicate on restart, and that the importer treats the inserted rule as the built-in guard.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

AGENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, AGENT)
from noobrouter_agent import config, firewall  # noqa: E402

tag = os.getpid() % 10000
RT, CL = f"crt{tag}", f"ccl{tag}"
RIP, CIP, NET = "192.168.77.1", "192.168.77.2", "192.168.77.0/24"
tmp = tempfile.mkdtemp()
cfg_path = os.path.join(tmp, "agent.json")
proc = None


def sh(*argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True, check=check).stdout


def ns(n, *argv, check=True):
    return sh("ip", "netns", "exec", n, *argv, check=check)


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg, flush=True)
    if not cond:
        raise SystemExit(1)


def start(port, dry_run):
    global proc
    stop()
    with open(cfg_path, "w") as f:
        json.dump({"listen": RIP, "port": port, "lan_if": "lan0", "wan_if": "wan0", "lan_cidr": NET,
                   "data_dir": os.path.join(tmp, "data"), "dry_run": dry_run, "token": "drill"}, f)
    proc = subprocess.Popen(["ip", "netns", "exec", RT, sys.executable, "-m", "noobrouter_agent.server",
                             "-c", cfg_path], cwd=AGENT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    lines = []
    # reader thread: the firewall line (if any) comes after "listening on", and "ok" prints nothing
    threading.Thread(target=lambda p=proc: [lines.append(l.strip()) for l in p.stdout], daemon=True).start()
    deadline = time.time() + 5
    while time.time() < deadline and not any("listening on" in l for l in lines):
        time.sleep(0.1)
    time.sleep(1.5)  # ensure_console_access runs right after the listening line
    return list(lines) or [""]


def stop():
    global proc
    if proc:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc = None


def reachable(port):
    code = ("import urllib.request,urllib.error\n"
            "try:\n urllib.request.urlopen('http://%s:%d/', timeout=2); print('HTTP')\n"
            "except urllib.error.HTTPError: print('HTTP')\n"
            "except Exception as e: print('NO', e)\n") % (RIP, port)
    return ns(CL, sys.executable, "-c", code).startswith("HTTP")


def console_rules(port):
    return [l for l in ns(RT, "iptables", "-S", "INPUT").splitlines() if f"--dport {port} " in l + " "]


try:
    for n in (RT, CL):
        sh("ip", "netns", "add", n)
    sh("ip", "link", "add", "lan0", "netns", RT, "type", "veth", "peer", "name", "eth0", "netns", CL)
    ns(RT, "ip", "addr", "add", f"{RIP}/24", "dev", "lan0")
    ns(CL, "ip", "addr", "add", f"{CIP}/24", "dev", "eth0")
    for n, d in ((RT, "lan0"), (CL, "eth0")):
        ns(n, "ip", "link", "set", d, "up")
        ns(n, "ip", "link", "set", "lo", "up")
    # a router hardened before install: only lo, established and SSH get in
    for r in (["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
              ["-A", "INPUT", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
              ["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"], ["-P", "INPUT", "DROP"]):
        ns(RT, "iptables", *r)
    pong = subprocess.run(["ip", "netns", "exec", CL, "ping", "-c1", "-W1", RIP], capture_output=True)
    check(pong.returncode != 0, "baseline: INPUT policy DROP is live (client ping dropped)")

    out = start(18090, dry_run=True)
    check(any("WARNING firewall drops port 18090" in l for l in out), "dry_run: startup warns (%s)" % out[-1])
    check(not reachable(18090) and not console_rules(18090), "dry_run: no rule added, LAN client blocked")

    out = start(18090, dry_run=False)
    check(any("added a LAN-only accept" in l for l in out), "auto: startup reports the inserted rule")
    check(reachable(18090), "auto: LAN client reaches the console on 18090")
    check(console_rules(18090) == ["-A INPUT -i lan0 -p tcp -m tcp --dport 18090 -j ACCEPT"], "auto: one LAN-only rule")

    out = start(18090, dry_run=False)
    check(len(console_rules(18090)) == 1 and not any("added" in l for l in out), "restart: no duplicate rule")

    out = start(18555, dry_run=False)  # port edited in the config file by hand
    check(reachable(18555), "port change + restart: LAN client reaches the new port 18555")
    check(not reachable(18090), "port change: old port no longer answers")

    cfg = dict(config.DEFAULTS, lan_if="lan0", wan_if="wan0", lan_cidr=NET, listen=RIP, port=18555)
    model, skipped = firewall.import_iptables_save(ns(RT, "iptables-save"), cfg)
    check(not any(o["port"] == "18555" for o in model["wan_open"]), "import: 18555 rule recognised as built-in guard")
    check(firewall.console_insert_pos(ns(RT, "iptables-save", "-t", "filter"), cfg) is None, "health check sees it open")

    # the same netns is reachable from a WAN-ish source? (rule is -i lan0 only)
    check(all("-i lan0" in l for l in console_rules(18555) + console_rules(18090)), "rules are LAN-interface only")
    print("CONSOLE_DRILL_OK")
finally:
    stop()
    for n in (RT, CL):
        subprocess.run(["ip", "netns", "del", n], capture_output=True)
    shutil.rmtree(tmp, ignore_errors=True)
