"""Safe apply for iptables: test -> backup -> arm rollback timer -> apply -> wait for confirm.

If the user does not confirm within rollback_seconds (e.g. because the change cut off the
console), the armed timer restores the backup on its own, independent of this agent process.
"""
import json
import os
import re
import shlex
import signal
import subprocess
import time
import uuid

from .shell import CmdError, has, run

UNIT = "noobrouter-rollback"
LOG_MAX = 256 * 1024  # last_rollback.json.log cap; trimmed to the newest half when exceeded
KEEP_BACKUPS = 20  # transactions whose iptables/file snapshots are kept under fw/backup


def _ns(cfg):
    ns = cfg.get("netns")  # test only: run everything inside a network namespace
    return ["ip", "netns", "exec", ns] if ns else []


def _paths(cfg):
    d = os.path.join(cfg["data_dir"], "fw")
    os.makedirs(os.path.join(d, "backup"), mode=0o700, exist_ok=True)
    for x in (d, os.path.join(d, "backup")):  # makedirs mode is umask-filtered and skips existing dirs
        if os.stat(x).st_mode & 0o077:
            os.chmod(x, 0o700)
    return {"dir": d, "pending": os.path.join(d, "pending.json"), "script": os.path.join(d, "rollback.sh"),
            "last": os.path.join(d, "last_rollback.json")}


def _write(path, text, mode=0o600):
    d, base = os.path.split(path)
    tmp = os.path.join(d, f".{base}.tmp{os.getpid()}")  # dotfile: ignored by dnsmasq/ifupdown/sysctl dirs
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)  # umask-independent
    os.replace(tmp, path)  # atomic on the same filesystem


def pending(cfg):
    p = _paths(cfg)["pending"]
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        info = json.load(f)
    info["remaining"] = max(0, int(info["deadline"] - time.time()))
    return info


def last_rollback(cfg):
    p = _paths(cfg)["last"]
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _trim_log(path, limit=LOG_MAX):
    """Keep the newest limit/2 bytes once the file grows past limit (cut at a line boundary)."""
    try:
        if os.path.getsize(path) <= limit:
            return
        with open(path, "rb") as f:
            f.seek(-(limit // 2), os.SEEK_END)
            tail = f.read()
        nl = tail.find(b"\n")
        _write_bytes(path, tail[nl + 1:] if nl >= 0 else tail)
    except OSError:
        pass


def _write_bytes(path, data, mode=0o600):
    d, base = os.path.split(path)
    tmp = os.path.join(d, f".{base}.tmp{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def log(cfg, msg):
    """Append one line to fw/last_rollback.json.log (0600, size-capped). Shared with the timer script."""
    path = _paths(cfg)["last"] + ".log"
    _trim_log(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg.rstrip("\n") + "\n")
    os.chmod(path, 0o600)


def _prune_backups(bdir, keep=KEEP_BACKUPS):
    """Snapshots are named <txid>.v4/.v6/.files; txid starts with a timestamp so names sort by age."""
    if not os.path.isdir(bdir):
        return
    txids = sorted({n.split(".")[0] for n in os.listdir(bdir) if re.match(r"^\d{8}-\d{6}-[0-9a-f]{6}\.", n)})
    for t in txids[:-keep] if keep > 0 else txids:
        for suffix in (".v4", ".v6"):
            p = os.path.join(bdir, t + suffix)
            if os.path.exists(p):
                os.remove(p)
        fdir = os.path.join(bdir, t + ".files")
        if os.path.isdir(fdir):
            for n in os.listdir(fdir):
                os.remove(os.path.join(fdir, n))
            os.rmdir(fdir)


def test_rules(v4, v6, cfg):
    ns = _ns(cfg)
    run(ns + ["iptables-restore", "--test"], input=v4)
    run(ns + ["ip6tables-restore", "--test"], input=v6)


def current(cfg):
    ns = _ns(cfg)
    return run(ns + ["iptables-save"]), run(ns + ["ip6tables-save"])


def ensure_console_access(cfg):
    """Agent start: if the live IPv4 INPUT chain would drop new LAN connections to the console port
    (port changed by hand, or a DROP policy from before install), insert the LAN-only accept the
    firewall guard renders anyway. Never raises: the server must start regardless.
    Returns one of "loopback", "ok", "dry_run", "added", "error: ...". Not persisted: the next
    firewall apply renders the same rule and confirm() saves it."""
    from . import firewall  # local import: firewall stays a pure module without applier deps
    if not firewall.console_lan_facing(cfg):
        return "loopback"
    try:
        pos = firewall.console_insert_pos(run(_ns(cfg) + ["iptables-save", "-t", "filter"]), cfg)
        if pos is None:
            return "ok"
        rule = firewall.console_rule(cfg)
        if cfg.get("dry_run", True):
            return "dry_run"
        argv = ["iptables", "-I", "INPUT", str(pos)] + shlex.split(rule)[2:]
        run(_ns(cfg) + argv)
        log(cfg, f"console port {cfg['port']} was blocked on {cfg['lan_if']}: inserted '{rule}' at INPUT #{pos}")
        return "added"
    except Exception as e:  # noqa: BLE001 - startup must not fail on a firewall probe
        return f"error: {e}"


def _rollback_script(cfg, b4, b6, pend, last, txid, files=(), undo=(), kind="firewall"):
    """files: [{"path", "backup"|None, "mode"}]; undo: argv lists run after restore (best effort)."""
    ns = " ".join(shlex.quote(x) for x in _ns(cfg))
    q = shlex.quote
    lg = q(last + ".log")
    lines = [f"#!/bin/sh",
             f"# auto-generated by noobrouter-agent tx {txid}: restore pre-change state",
             "umask 077",
             f"[ -f {q(pend)} ] || exit 0",
             f"grep -q '\"{txid}\"' {q(pend)} || exit 0",
             # same cap as applier.log(): keep the newest half once the log exceeds LOG_MAX
             f"if [ -f {lg} ] && [ \"$(wc -c < {lg})\" -gt {LOG_MAX} ]; then"
             f" tail -c {LOG_MAX // 2} {lg} | sed 1d > {lg}.tmp && mv -f {lg}.tmp {lg}; fi",
             f"exec >> {lg} 2>&1",
             f"chmod 600 {lg}",
             f"echo \"$(date '+%Y-%m-%d %H:%M:%S') tx {txid} kind={kind}: rollback reason=timeout\""]
    for f in files:
        if f["backup"]:
            lines.append(f"cp -p {q(f['backup'])} {q(f['path'])} || echo \"$(date) restore {f['path']} failed\"")
        else:
            lines.append(f"rm -f {q(f['path'])}")
    lines += [f"{ns} iptables-restore < {q(b4)} || echo \"$(date) tx {txid}: iptables-restore failed\"",
              f"{ns} ip6tables-restore < {q(b6)} || echo \"$(date) tx {txid}: ip6tables-restore failed\""]
    for argv in undo:
        lines.append(" ".join(q(a) for a in argv) + " || true")
    lines += [f"rm -f {q(pend)}",
              f"echo '{{\"txid\": \"{txid}\", \"kind\": \"{kind}\", \"at\": '$(date +%s)', \"reason\": \"timeout\"}}' > {q(last)}"]
    return "\n".join(lines) + "\n"


def _arm_timer(cfg, script, seconds, txid):
    """Prefer a transient systemd timer (survives agent crash/restart); fall back to a detached sleeper.
    cfg["rollback_timer"]: auto | systemd | sleep (tests use this to exercise both paths)."""
    unit = f"{UNIT}-{txid}"
    mode = cfg.get("rollback_timer", "auto")
    systemd_ok = has("systemd-run") and os.path.isdir("/run/systemd/system")
    if mode == "systemd" and not systemd_ok:
        raise CmdError("systemd 不可用")
    if mode in ("auto", "systemd") and systemd_ok:
        run(["systemd-run", f"--unit={unit}", f"--on-active={int(seconds)}", "--timer-property=AccuracySec=1s",
             "/bin/sh", script])
        return {"kind": "systemd", "unit": unit}
    p = subprocess.Popen(["/bin/sh", "-c", f"sleep {int(seconds)}; exec /bin/sh {shlex.quote(script)}"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    return {"kind": "sleep", "pid": p.pid}


def _disarm(timer):
    try:
        if timer["kind"] == "systemd":
            subprocess.run(["systemctl", "stop", f"{timer['unit']}.timer"], capture_output=True, timeout=10)
        else:
            os.killpg(timer["pid"], signal.SIGTERM)
    except (OSError, subprocess.SubprocessError):
        pass  # the script itself is a no-op once pending.json is gone


def _snapshot(files, bdir):
    """Back up every target file before writing. Returns rollback entries."""
    out = []
    os.makedirs(bdir, mode=0o700, exist_ok=True)
    os.chmod(bdir, 0o700)  # snapshots may contain chap-secrets
    for i, f in enumerate(files):
        path = f["path"]
        entry = {"path": path, "backup": None, "mode": f.get("mode", 0o644)}
        if os.path.exists(path):
            entry["backup"] = os.path.join(bdir, f"{i}_{os.path.basename(path)}")
            fd = os.open(entry["backup"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # may hold secrets
            with open(path, "rb") as src, os.fdopen(fd, "wb") as dst:
                dst.write(src.read())
            st = os.stat(path)
            os.chmod(entry["backup"], st.st_mode & 0o7777)
        out.append(entry)
    return out


def _restore_files(entries):
    for f in entries:
        if f["backup"]:
            with open(f["backup"], "rb") as src:
                data = src.read()
            tmp = os.path.join(os.path.dirname(f["path"]), f".{os.path.basename(f['path'])}.srtmp")
            with open(tmp, "wb") as dst:
                dst.write(data)
            os.chmod(tmp, os.stat(f["backup"]).st_mode & 0o7777)
            os.replace(tmp, f["path"])
        elif os.path.exists(f["path"]):
            os.remove(f["path"])


def apply(v4, v6, cfg, summary="", kind="firewall", files=(), post=(), undo=()):
    """One transaction with auto-rollback: file writes + iptables-restore + post commands.
    files: [{"path", "content", "mode"}], content None = remove the file (snapshot restores it);
    post: argv lists run after writing (failure -> rollback);
    undo: argv lists run after restoring on rollback. Single pending slot for every kind."""
    if cfg.get("dry_run"):
        raise CmdError("dry_run 模式：只允许预览与 --test 校验，不会写入防火墙", 409)
    if pending(cfg):
        raise CmdError("已有待确认的变更，请先确认或回滚", 409)
    test_rules(v4, v6, cfg)
    p = _paths(cfg)
    txid = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    _prune_backups(os.path.join(p["dir"], "backup"), KEEP_BACKUPS - 1)  # room for this tx
    old4, old6 = current(cfg)
    b4, b6 = os.path.join(p["dir"], "backup", f"{txid}.v4"), os.path.join(p["dir"], "backup", f"{txid}.v6")
    _write(b4, complete_tables(old4, ("filter", "nat", "mangle")))
    _write(b6, complete_tables(old6, ("filter", "mangle")))  # = tables render_v6 replaces
    entries = _snapshot(files, os.path.join(p["dir"], "backup", f"{txid}.files"))
    undo = [list(a) for a in undo]
    if not re.match(r"^[a-z]{1,16}$", kind):
        raise CmdError(f"非法事务类型: {kind}")
    _write(p["script"], _rollback_script(cfg, b4, b6, p["pending"], p["last"], txid, entries, undo, kind), 0o700)
    seconds = int(cfg["rollback_seconds"])
    info = {"txid": txid, "kind": kind, "deadline": time.time() + seconds, "seconds": seconds,
            "summary": summary, "backup_v4": b4, "backup_v6": b6, "files": entries, "undo": undo}
    _write(p["pending"], json.dumps(info))
    info["timer"] = _arm_timer(cfg, p["script"], seconds, txid)
    _write(p["pending"], json.dumps(info))
    ns = _ns(cfg)
    try:
        for f, e in zip(files, entries):
            if f["content"] is None:
                if os.path.exists(f["path"]):
                    os.remove(f["path"])
                continue
            os.makedirs(os.path.dirname(f["path"]) or ".", exist_ok=True)
            _write(f["path"], f["content"], e["mode"])
        run(ns + ["iptables-restore"], input=v4)
        run(ns + ["ip6tables-restore"], input=v6)
        for argv in post:
            run(list(argv), timeout=60)
    except (CmdError, OSError):
        rollback(cfg, reason="apply_failed")
        raise
    log(cfg, f"tx {txid} kind={kind}: applied, auto-rollback in {seconds}s")
    return pending(cfg)


# Builtin chains per table. A table missing from iptables-save output (never loaded) must still be
# present in the backup, otherwise iptables-restore leaves the newly applied rules in place.
BUILTIN = {
    "filter": ["INPUT", "FORWARD", "OUTPUT"],
    "nat": ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"],
    "mangle": ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"],
}


def complete_tables(save_text, tables):
    """Keep only `tables` from save_text, adding empty ACCEPT tables for any that are missing."""
    blocks, cur = {}, None
    for line in save_text.splitlines():
        if line.startswith("*"):
            cur = line[1:].strip()
            blocks[cur] = []
        if cur is not None and not line.startswith("#"):
            blocks[cur].append(line)
        if line.strip() == "COMMIT":
            cur = None
    out = []
    for t in tables:
        out += blocks.get(t) or ([f"*{t}"] + [f":{c} ACCEPT [0:0]" for c in BUILTIN[t]] + ["COMMIT"])
    return "\n".join(out) + "\n"


def confirm(cfg, persist=True):
    """User confirmed connectivity: disarm timer and persist to rules.v4/v6."""
    info = pending(cfg)
    if not info:
        raise CmdError("没有待确认的变更", 409)
    _disarm(info.get("timer", {}))
    os.remove(_paths(cfg)["pending"])
    v4, v6 = current(cfg)
    persist = bool(persist and cfg.get("persist_v4") and not cfg.get("netns"))  # netns drills never persist
    if persist:
        for path, text in ((cfg["persist_v4"], v4), (cfg["persist_v6"], v6)):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.exists(path):
                _write(path + ".noobrouter.bak", open(path, encoding="utf-8").read(), 0o640)
            _write(path, text, 0o640)
    log(cfg, f"tx {info['txid']} kind={info.get('kind', 'firewall')}: confirmed persisted={persist}")
    return {"txid": info["txid"], "kind": info.get("kind", "firewall"), "persisted": persist}


def rollback(cfg, reason="manual"):
    info = pending(cfg)
    if not info:
        raise CmdError("没有待确认的变更", 409)
    _disarm(info.get("timer", {}))
    ns = _ns(cfg)
    _restore_files(info.get("files", []))
    errs = []
    for tool, b in (("iptables-restore", info["backup_v4"]), ("ip6tables-restore", info["backup_v6"])):
        try:
            run(ns + [tool], input=open(b, encoding="utf-8").read())
        except CmdError as e:
            errs.append(f"{tool}: {e}")
    for argv in info.get("undo", []):
        try:
            run(argv, check=False, timeout=60)
        except CmdError as e:  # timeout: keep undoing the rest
            errs.append(f"{argv[0]}: {e}")
    os.remove(_paths(cfg)["pending"])
    last = {"txid": info["txid"], "kind": info.get("kind", "firewall"), "at": int(time.time()), "reason": reason}
    if errs:
        last["errors"] = errs  # reported, not raised: callers must still finish their own cleanup
    _write(_paths(cfg)["last"], json.dumps(last))
    log(cfg, f"tx {info['txid']} kind={last['kind']}: rollback reason={reason}"
             + (" errors: " + "; ".join(errs) if errs else ""))
    return last
