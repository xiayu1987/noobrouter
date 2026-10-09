"""Rollback drill inside a throwaway netns (Linux, root). Usage: python3 tests/netns_rollback_drill.py [sleep|systemd]"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from noobrouter_agent import applier, config, firewall  # noqa: E402

timer = sys.argv[1] if len(sys.argv) > 1 else "sleep"
ns = f"srdrill{os.getpid()}"
tmp = tempfile.mkdtemp()
cfg = dict(config.DEFAULTS, netns=ns, dry_run=False, rollback_seconds=3, data_dir=tmp, rollback_timer=timer,
           token="x")
subprocess.run(["ip", "netns", "add", ns], check=True)


def dnat_count():
    out = subprocess.run(["ip", "netns", "exec", ns, "iptables", "-t", "nat", "-S", "PREROUTING"],
                         capture_output=True, text=True).stdout
    return out.count("DNAT")


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        raise SystemExit(1)


try:
    saved = open(os.path.join(os.path.dirname(__file__), "fixtures", "router_iptables_save.txt")).read()
    model, _ = firewall.import_iptables_save(saved, cfg)
    model = firewall.normalize(model, cfg)
    v4, v6 = firewall.render_v4(model, cfg), firewall.render_v6(model, cfg)
    check(dnat_count() == 0, "baseline: empty netns")

    # round 1: apply, do NOT confirm -> must auto-restore to baseline
    info = applier.apply(v4, v6, cfg, "drill-1")
    check(dnat_count() == 10 and info["timer"]["kind"] == timer, f"applied 10 DNAT, timer={info['timer']['kind']}")
    time.sleep(cfg["rollback_seconds"] + 3)
    check(dnat_count() == 0, "timeout -> rules restored automatically")
    check(applier.pending(cfg) is None and applier.last_rollback(cfg)["reason"] == "timeout", "last_rollback=timeout")

    # round 2: apply + confirm -> timer disarmed, rules stay
    applier.apply(v4, v6, cfg, "drill-2")
    applier.confirm(cfg)
    time.sleep(cfg["rollback_seconds"] + 3)
    check(dnat_count() == 10, "confirmed -> rules kept after deadline")

    # round 3: manual rollback restores previous (confirmed) state
    m2 = dict(model, forwards=model["forwards"][:3])
    applier.apply(firewall.render_v4(m2, cfg), v6, cfg, "drill-3")
    check(dnat_count() == 3, "applied reduced ruleset (3)")
    applier.rollback(cfg)
    check(dnat_count() == 10, "manual rollback -> 10 again")

    # round 4: invalid rules never touch the kernel
    try:
        applier.apply("*filter\n-A INPUT -j NOPE\nCOMMIT\n", v6, cfg)
        check(False, "invalid rules rejected")
    except applier.CmdError:
        check(dnat_count() == 10 and applier.pending(cfg) is None, "invalid rules rejected before apply")
    print("ALL PASS")
finally:
    subprocess.run(["ip", "netns", "del", ns])
    shutil.rmtree(tmp, ignore_errors=True)
