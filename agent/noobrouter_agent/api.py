"""API handlers: (method, path) -> fn(cfg, body, query). Returns JSON-serialisable data."""
import re
import time

from . import __version__, applier, bootstrap, dhcp, firewall, netinfo, store, sysinfo
from .shell import read, try_run

HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
LOG_UNITS = {"dnsmasq": ["-u", "dnsmasq"], "pppd": ["-t", "pppd"], "ssh": ["-u", "ssh"],
             "kernel": ["-k"], "agent": ["-u", "noobrouter-agent"]}
SERVICES = ["dnsmasq", "ssh", "netfilter-persistent", "NetworkManager", "noobrouter-agent"]


class ApiError(Exception):
    def __init__(self, msg, status=400, code=None):
        super().__init__(msg)
        self.status = status
        self.code = code  # machine-readable reason for the UI (e.g. "allow_empty")


def _int(q, key, default, lo, hi):
    try:
        return max(lo, min(int(q.get(key, default)), hi))
    except (TypeError, ValueError):
        raise ApiError(f"参数 {key} 必须是整数")


def _require_model(body, current, list_keys):
    """Write endpoints must receive an explicit model object. Removing every entry of a
    non-empty list (e.g. all DNAT forwards / all static leases) needs allow_empty=true,
    so an empty or truncated request body can never wipe existing config."""
    m = body.get("model")
    if not isinstance(m, dict) or not m:
        raise ApiError("缺少 model 对象")
    if not body.get("allow_empty"):
        for k in list_keys:
            if current.get(k) and not m.get(k):
                raise ApiError(f"将清空全部 {k}（当前 {len(current[k])} 条），如确认请传 allow_empty=true", 409,
                               code="allow_empty")
    return m


def status(cfg, body, q):
    return {"version": __version__, "dry_run": cfg["dry_run"], "time": int(time.time()),
            "hostname": read("/proc/sys/kernel/hostname").strip(),
            "kernel": read("/proc/sys/kernel/osrelease").strip(),
            "uptime": float(read("/proc/uptime", "0 0").split()[0]),
            "load": read("/proc/loadavg", "0 0 0").split()[:3],
            "cpu": sysinfo.cpu_percent(), "mem": sysinfo.meminfo(), "disk": sysinfo.disk(),
            "temp": sysinfo.temperature(), "conntrack": sysinfo.conntrack(),
            "wan": _wan(cfg), "lan_if": cfg["lan_if"], "pending": applier.pending(cfg)}


def _wan(cfg):
    for i in netinfo.interfaces():
        if i["name"] == cfg["wan_if"]:
            v4 = [a for a in i["addrs"] if "." in a]
            v6 = [a for a in i["addrs"] if ":" in a and not a.startswith("fe80")]
            return {"if": i["name"], "up": True, "ipv4": v4, "ipv6": v6}
    return {"if": cfg["wan_if"], "up": False, "ipv4": [], "ipv6": []}


def traffic(cfg, body, q):
    """Raw byte counters; the UI derives rates from successive samples."""
    return {"time": time.time(), "dev": netinfo.netdev()}


def interfaces(cfg, body, q):
    return {"interfaces": netinfo.interfaces(), "routes": netinfo.routes()}


def devices(cfg, body, q):
    return netinfo.devices(cfg["dnsmasq_leases"], store.dhcp_model(cfg)["static"])


def connections(cfg, body, q):
    return netinfo.connections(limit=_int(q, "limit", 500, 1, 5000))


def services(cfg, body, q):
    return [{"name": s, "state": try_run(["systemctl", "is-active", s]).strip() or "unknown"} for s in SERVICES]


def logs(cfg, body, q):
    unit = q.get("unit", "dnsmasq")
    if unit not in LOG_UNITS:
        raise ApiError("不支持的日志来源")
    n = _int(q, "lines", 200, 1, 2000)
    return {"lines": try_run(["journalctl", "--no-pager", "-o", "short-iso", "-n", str(n)] + LOG_UNITS[unit]).splitlines()}


def diag(cfg, body, q):
    tool, host = body.get("tool"), str(body.get("host", ""))
    if not HOST_RE.match(host) or host.startswith("-"):
        raise ApiError("非法主机名")
    cmds = {"ping": ["ping", "-c", "4", "-W", "2", host], "traceroute": ["traceroute", "-n", "-w", "2", "-m", "20", host],
            "nslookup": ["nslookup", host]}
    if tool not in cmds:
        raise ApiError("不支持的工具")
    return {"output": try_run(cmds[tool], timeout=60)}


# ---------------- firewall ----------------

def fw_get(cfg, body, q):
    m = store.firewall_model(cfg)
    # return what would actually be rendered: mandatory keys forced on, missing option keys filled
    try:
        m = firewall.normalize(m, cfg)
    except firewall.ValidationError:
        pass  # keep raw model so the UI can still show/fix it; lint reports the problem
    return {"model": m, "lint": firewall.lint(m, cfg), "import": store.import_report(cfg),
            "pending": applier.pending(cfg), "last_rollback": applier.last_rollback(cfg),
            # option catalogue: UI renders one checkbox per entry, mandatory ones locked on
            "options": firewall.OPTIONS, "unsupported": firewall.UNSUPPORTED,
            "guard": {"ssh_port": cfg["guard_ssh_port"], "lan_if": cfg["lan_if"], "console_port": cfg["port"],
                      "rollback_seconds": cfg["rollback_seconds"]}}


def _fw_render(cfg, body):
    """Preview/apply use the request model when given, otherwise the stored model."""
    cur = store.firewall_model(cfg)
    m = _require_model(body, cur, ("forwards", "wan_open")) if "model" in body else cur
    m = firewall.normalize(m, cfg)
    return m, firewall.render_v4(m, cfg), firewall.render_v6(m, cfg)


def fw_preview(cfg, body, q):
    """Validate + render + kernel --test. Never changes live rules (allowed in dry_run)."""
    m, v4, v6 = _fw_render(cfg, body)
    applier.test_rules(v4, v6, cfg)
    live4, _ = applier.current(cfg)
    return {"model": m, "v4": v4, "v6": v6, "live_v4": live4, "lint": firewall.lint(m, cfg)}


def fw_save(cfg, body, q):
    """Save the model only (not applied)."""
    m = _require_model(body, store.firewall_model(cfg), ("forwards", "wan_open"))
    m = firewall.normalize(m, cfg)
    store.save(cfg, "firewall", m)
    return {"model": m}


def fw_apply(cfg, body, q):
    rep = store.import_report(cfg)
    if not rep["acknowledged"]:
        raise ApiError("存在导入器未识别的规则，整表应用会删除它们。请先在页面确认", 409)
    m, v4, v6 = _fw_render(cfg, body)
    store.save(cfg, "firewall", m)
    return applier.apply(v4, v6, cfg, summary=body.get("summary", ""))


def _require_kind(cfg, kind):
    """confirm/rollback endpoints only act on their own transaction type."""
    p = applier.pending(cfg)
    if not p:
        raise ApiError("没有待确认的变更", 409)
    if p.get("kind", "firewall") != kind:
        raise ApiError(f"当前待确认的是 {p.get('kind')} 事务，请到对应页面处理", 409)


def fw_confirm(cfg, body, q):
    _require_kind(cfg, "firewall")
    return applier.confirm(cfg)


def fw_rollback(cfg, body, q):
    _require_kind(cfg, "firewall")
    return applier.rollback(cfg)


def fw_ack_import(cfg, body, q):
    return store.acknowledge_import(cfg)


# ---------------- dhcp / dns ----------------

def _conflicts(cfg, model):
    """Warn when a static IP is currently used by another MAC (lease or ARP)."""
    tips = []
    seen = netinfo.devices(cfg["dnsmasq_leases"])
    for s in model["static"]:
        for d in seen:
            if d["ip"] == s["ip"] and d["mac"].lower().replace("-", ":") != s["mac"]:
                tips.append(f"{s['ip']} 当前被 {d['mac']} {d['hostname']} 占用")
    return tips


def dhcp_get(cfg, body, q):
    m = store.dhcp_model(cfg)
    try:
        rendered = dhcp.render(dhcp.normalize(m, cfg))
    except ValueError as e:
        rendered = f"# 已保存的模型无效: {e}"
    return {"model": m, "main": dhcp.main_settings(cfg), "render": rendered,
            "leases": netinfo.leases(cfg["dnsmasq_leases"])}


def dhcp_apply(cfg, body, q):
    raw = _require_model(body, store.dhcp_model(cfg), ("static", "records"))
    try:
        m = dhcp.normalize(raw, cfg)
    except ValueError as e:
        raise ApiError(str(e))
    warnings = _conflicts(cfg, m)
    if warnings and not body.get("force"):
        return {"applied": False, "warnings": warnings}
    if body.get("preview") or cfg["dry_run"]:
        return {"applied": False, "render": dhcp.render(m), "warnings": warnings, "dry_run": cfg["dry_run"]}
    dhcp.apply(m, cfg)
    store.save(cfg, "dhcp", m)
    return {"applied": True, "render": dhcp.render(m), "warnings": warnings}


# ---------------- init (blank machine -> router) ----------------

def _plan(body):
    p = body.get("plan")
    if not isinstance(p, dict) or not p:
        raise ApiError("缺少 plan 对象")
    return p


def init_get(cfg, body, q):
    # tuning catalogue: UI renders one checkbox per entry, mandatory ones locked on
    return {"probe": bootstrap.probe(cfg), "state": bootstrap.state(cfg), "dry_run": cfg["dry_run"],
            # existing port forwards (imported from the live ruleset); kept as-is by init
            "forwards": store.firewall_model(cfg).get("forwards", []),
            "tuning": [{k: t[k] for k in ("key", "group", "mandatory", "default", "label", "desc", "sysctl")}
                       for t in bootstrap.TUNING]}


def init_preview(cfg, body, q):
    return bootstrap.preview(cfg, _plan(body))


def init_apply(cfg, body, q):
    if cfg["dry_run"]:  # refuse before probing/rendering anything
        raise ApiError("dry_run 模式下不能应用初始化，只能预览", 409)
    return bootstrap.apply(cfg, _plan(body), force=bool(body.get("force")))


def init_confirm(cfg, body, q):
    return bootstrap.confirm(cfg)


def init_rollback(cfg, body, q):
    return bootstrap.rollback(cfg)


ROUTES = {
    ("GET", "/api/status"): status, ("GET", "/api/traffic"): traffic,
    ("GET", "/api/interfaces"): interfaces, ("GET", "/api/devices"): devices,
    ("GET", "/api/connections"): connections, ("GET", "/api/services"): services,
    ("GET", "/api/logs"): logs, ("POST", "/api/diag"): diag,
    ("GET", "/api/firewall"): fw_get, ("POST", "/api/firewall/preview"): fw_preview,
    ("POST", "/api/firewall/save"): fw_save, ("POST", "/api/firewall/apply"): fw_apply,
    ("POST", "/api/firewall/confirm"): fw_confirm, ("POST", "/api/firewall/rollback"): fw_rollback,
    ("POST", "/api/firewall/ack-import"): fw_ack_import,
    ("GET", "/api/dhcp"): dhcp_get, ("POST", "/api/dhcp/apply"): dhcp_apply,
    ("GET", "/api/init"): init_get, ("POST", "/api/init/preview"): init_preview,
    ("POST", "/api/init/apply"): init_apply, ("POST", "/api/init/confirm"): init_confirm,
    ("POST", "/api/init/rollback"): init_rollback,
}
