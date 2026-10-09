"""Firewall model -> iptables-restore text. Pure functions (no side effects).

Model (single source of truth, data_dir/firewall.json):
{
  "wan_open":  [{"proto": "tcp", "port": "51820", "comment": "wg", "iface": "", "src": ""}],
               # iface/src optional ("" = any): "-s 192.168.50.0/24 -i lan0" style restricted accepts
  "forwards":  [{"name": "smb", "proto": "tcp", "ext": "21005", "ip": "192.168.50.30",
                 "int": "445", "enabled": true}],
  <one bool per OPTIONS key>   # see OPTIONS below (single source for UI + renderer)
}
Mandatory OPTIONS (guard rules, drop_invalid) are always rendered; normalize() forces them on.

Adapted (not copied) from the legacy softroute.sh, cross-checked with OpenWrt firewall4:
  * sanity drops live in filter INPUT/FORWARD (fw4 does the same), not in a mangle chain; the
    legacy mangle "ESTABLISHED / -i br_lan ... -j ACCEPT" rules are no-ops (ACCEPT only ends the
    mangle chain) and its mt_rtr_4_m_rtr chain was never hooked - the importer treats both as no-ops.
  * XMAS/NULL flag combos are already INVALID to conntrack; they get an explicit opt-in rule
    anyway (cheap, and also catches them on untracked paths).
  * hairpin MASQUERADE is limited to LAN->LAN (-s lan -d lan): port-forward servers keep seeing
    the real WAN client address (the legacy "-o lan -j MASQUERADE" hid it).
  * IPv6 gets MSS clamping but no MASQUERADE (prefix-delegated LANs route natively).
  * iptables-restore replaces whole tables, so re-applying never stacks duplicate rules.
  * fw4 flow offloading needs nftables flowtables; iptables has no FLOWOFFLOAD on Debian -> not offered.
"""
import ipaddress
import re
import shlex

PORT_RE = re.compile(r"^\d{1,5}([:-]\d{1,5})?$")
IF_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
COMMENT_RE = re.compile(r"[^\w .:/-]")
PROTOS = ("tcp", "udp")

# Optimisation / hardening catalogue. mandatory=True -> always on, shown locked in the UI.
# default = value for a fresh install; imported routers start from what is live (see importer).
OPTIONS = [
    {"key": "guard_rules", "group": "基础", "mandatory": True, "default": True,
     "label": "保底放行（lo / 已建立连接 / LAN 管理端口）",
     "desc": "防止规则把自己锁在门外，始终生成"},
    {"key": "lan_accept_all", "group": "基础", "mandatory": False, "default": True,
     "label": "LAN 可访问路由器全部端口",
     "desc": "关闭后 LAN 只能访问 SSH、控制台、DNS、DHCP、ping 和下方显式放行的端口"},
    {"key": "ssh_wan", "group": "安全", "mandatory": False, "default": False,
     "label": "SSH 对 WAN 开放", "desc": "关闭时 SSH 只对 LAN 放行；需要远程管理时建议改用 VPN"},
    {"key": "drop_invalid", "group": "安全", "mandatory": True, "default": True,
     "label": "丢弃 INVALID 状态包", "desc": "conntrack 无法归属的包（含畸形 TCP 标志）在 INPUT/FORWARD 直接丢弃"},
    {"key": "drop_new_not_syn", "group": "安全", "mandatory": False, "default": True,
     "label": "丢弃首包非 SYN 的新 TCP 连接", "desc": "挡住 ACK 扫描；路由器重启后已有长连接需客户端重连"},
    {"key": "drop_bad_flags", "group": "安全", "mandatory": False, "default": True,
     "label": "丢弃 XMAS / NULL 扫描包", "desc": "TCP 标志位全置或全空，正常协议栈不会发出"},
    {"key": "syn_flood", "group": "安全", "mandatory": False, "default": True,
     "label": "WAN 入站 SYN 限速（25/s，突发 50）", "desc": "只限发往路由器本机的新连接，不影响转发流量（同 OpenWrt synflood_protect）"},
    {"key": "forward_filter", "group": "安全", "mandatory": False, "default": True,
     "label": "过滤 WAN→LAN 转发", "desc": "只放行回包和端口转发，防止 WAN 侧把 LAN 网段设为路由直连内网"},
    {"key": "ipv6_filter", "group": "安全", "mandatory": False, "default": False,
     "label": "IPv6 基础防火墙", "desc": "有公网 IPv6 时建议开启；ICMPv6 与 DHCPv6\u2011PD 自动放行"},
    {"key": "mss_clamp", "group": "转发优化", "mandatory": False, "default": True,
     "label": "IPv4 TCP MSS 钳制", "desc": "按出口 MTU 修正 MSS，PPPoE 下避免大包黑洞（网页打不开/卡住）"},
    {"key": "mss_clamp_v6", "group": "转发优化", "mandatory": False, "default": True,
     "label": "IPv6 TCP MSS 钳制", "desc": "同上，作用于 IPv6 转发"},
    {"key": "lan_masquerade", "group": "转发优化", "mandatory": False, "default": True,
     "label": "LAN 回流 NAT", "desc": "内网用公网 IP/域名访问端口转发；仅对 LAN→LAN 生效，外部访问保留真实来源 IP"},
    {"key": "dnat_local_only", "group": "转发优化", "mandatory": False, "default": False,
     "label": "仅对发往本机的流量做 DNAT", "desc": "避免转发规则误伤经过路由器去往其它地址的流量"},
]
UNSUPPORTED = [{"key": "flow_offload", "label": "流量卸载（flowtable）",
                "desc": "需要 nftables flowtable，当前 iptables 后端不支持"}]
BOOL_KEYS = tuple(o["key"] for o in OPTIONS)
MANDATORY = frozenset(o["key"] for o in OPTIONS if o["mandatory"])
EMPTY_MODEL = dict({"wan_open": [], "forwards": []}, **{o["key"]: o["default"] for o in OPTIONS})
# options whose absence in a stored model meant "on" (the renderer used to always emit them):
# upgrading keeps the old behaviour until the user unticks them
LEGACY_ON = frozenset({"lan_accept_all", "ssh_wan"})
# what LAN keeps reaching when lan_accept_all is off (DHCP server needs udp 67, dnsmasq 53)
LAN_SERVICE_PORTS = ((("udp",), "53"), (("tcp",), "53"), (("udp",), "67"))

INVALID_BODY = "-m conntrack --ctstate INVALID -j DROP"
NEW_NOT_SYN_BODY = "-p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP"
BAD_FLAGS_BODIES = ("-p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP",
                    "-p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP")
SYN_LIMIT = "25/sec"
SYN_BURST = 50


def _sanity(model, chain):
    """Sanity drops for one chain, in render order (INVALID first)."""
    out = [f"-A {chain} {INVALID_BODY}"]
    if model.get("drop_new_not_syn"):
        out.append(f"-A {chain} {NEW_NOT_SYN_BODY}")
    if model.get("drop_bad_flags"):
        out += [f"-A {chain} {b}" for b in BAD_FLAGS_BODIES]
    return out


def _syn_flood(wan):
    """syn_flood chain + jump (INPUT only, after ESTABLISHED, before port accepts)."""
    return ([f"-A INPUT -i {wan} -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j syn_flood"],
            [f"-A syn_flood -m limit --limit {SYN_LIMIT} --limit-burst {SYN_BURST} -j RETURN",
             "-A syn_flood -j DROP"])


def _mss_rule(wan):
    return f"-A FORWARD -o {wan} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"


def _hairpin_rule(cfg):
    lan = str(ipaddress.ip_network(cfg["lan_cidr"], strict=False))
    return f"-A POSTROUTING -s {lan} -d {lan} -o {cfg['lan_if']} -j MASQUERADE"


def _forward_guard(wan):
    """IPv4 FORWARD rules rendered when forward_filter is on (also recognised by the importer)."""
    return [f"-A FORWARD -i {wan} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            f"-A FORWARD -i {wan} -m conntrack --ctstate DNAT -j ACCEPT",
            f"-A FORWARD -i {wan} -j DROP"]


def _accept(p, port, iface="", src=""):
    """One INPUT accept in iptables-save's canonical order (-s, -i, -p) so imports round-trip."""
    s = f" -s {src}" if src else ""
    i = f" -i {iface}" if iface else ""
    return f"-A INPUT{s}{i} -p {p} -m {p} --dport {port} -j ACCEPT"


def _input_guard(model, cfg, ver):
    """Lock-out guard: SSH (WAN too when ssh_wan) + LAN management/services. Console port is LAN-only:
    the agent itself only listens on the LAN IP. ver=6 swaps ICMP / DHCP for their v6 forms."""
    lan, ssh = cfg["lan_if"], int(cfg["guard_ssh_port"])
    out = [_accept("tcp", ssh)] if model["ssh_wan"] else []
    if model["lan_accept_all"]:
        return out + [f"-A INPUT -i {lan} -j ACCEPT"]
    ports = sorted({int(cfg["port"])} | (set() if model["ssh_wan"] else {ssh}))
    out += [_accept("tcp", p, lan) for p in ports]
    for protos, port in LAN_SERVICE_PORTS:
        if ver == 6 and port == "67":
            port = "547"  # DHCPv6 server
        out += [_accept(p, port, lan) for p in protos]
    if ver == 4:
        out.append(f"-A INPUT -i {lan} -p icmp -j ACCEPT")
    return out


# ---------------- console reachability (live INPUT check, used at agent start) ----------------

def console_rule(cfg):
    """LAN-only console accept, same text the guard renders (so the importer treats it as ours)."""
    return _accept("tcp", int(cfg["port"]), cfg["lan_if"])


def console_lan_facing(cfg):
    """True when the agent's listen address is meant to be reached from the LAN (0.0.0.0 or a LAN IP)."""
    try:
        ip = ipaddress.ip_address(cfg.get("listen") or "0.0.0.0")
    except ValueError:
        return False
    return ip.version == 4 and (ip.is_unspecified or ip in ipaddress.ip_network(cfg["lan_cidr"], strict=False))


def _filter_chains(save_text):
    """iptables-save text -> ({chain: [rule tokens]}, {builtin chain: policy}) for the filter table."""
    chains, policy, cur = {}, {}, None
    for line in save_text.splitlines():
        line = line.strip()
        if line.startswith("*"):
            cur = line[1:]
        elif cur == "filter" and line.startswith(":"):
            name, pol = line[1:].split()[:2]
            chains.setdefault(name, [])
            if pol != "-":
                policy[name] = pol
        elif cur == "filter" and line.startswith("-A "):
            tok = shlex.split(line)
            chains.setdefault(tok[1], []).append(tok[2:])
    return chains, policy


ALL_TCP_FLAGS = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"}
NON_TERMINAL = {"LOG", "NFLOG", "MARK", "CONNMARK", "TCPMSS", "AUDIT"}


def _flagset(s):
    return ALL_TCP_FLAGS if s == "ALL" else set() if s == "NONE" else set(s.split(","))


def _port_in(spec, port):
    for part in spec.split(","):
        a, _, b = part.partition(":")
        if int(a or 0) <= port <= int(b or a or 65535):
            return True
    return False


def _options(tok):
    """Rule tokens -> [(negated, option, [values])] up to the target (-j/-g)."""
    out, neg = [], False
    for t in tok:
        if t == "!":
            neg = True
        elif t.startswith("-") and not t.lstrip("-").isdigit():
            if t in ("-j", "-g"):
                break
            out.append((neg, t, []))
            neg = False
        elif out:
            out[-1][2].append(t)
    return out


def _match(tok, pkt):
    """Does a new LAN TCP SYN to the console match these matchers? True / False / None (can't tell)."""
    results = []
    for neg, t, vals in _options(tok):
        val = vals[0] if vals else ""
        r = None
        if t == "-m":
            continue  # module name; its options are judged one by one
        if t == "-i":
            r = pkt["iface"].startswith(val[:-1]) if val.endswith("+") else pkt["iface"] == val
        elif t == "-p":
            r = val in ("tcp", "6", "all")
        elif t == "-s":
            net = ipaddress.ip_network(val, strict=False)
            r = True if pkt["src"].subnet_of(net) else (None if pkt["src"].overlaps(net) else False)
        elif t == "-d":
            r = None if pkt["dst"] is None else pkt["dst"] in ipaddress.ip_network(val, strict=False)
        elif t in ("--dport", "--destination-port", "--dports", "--destination-ports"):
            r = _port_in(val, pkt["port"])
        elif t == "--tcp-flags":
            r = len(vals) == 2 and (_flagset(vals[0]) & {"SYN"}) == _flagset(vals[1])
        elif t == "--syn":
            r = True
        elif t in ("--ctstate", "--state"):
            r = "NEW" in val.split(",")
        elif t == "--comment":
            r = True
        elif t == "--dst-type":
            r = "LOCAL" in val.split(",")
        elif t in ("--sport", "--source-port", "--sports", "--source-ports", "--limit", "--limit-burst"):
            r = None  # client port / rate limit: may or may not match this connection
        results.append((not r) if (neg and r is not None) else r)
    if False in results:
        return False
    return None if None in results else True


def _target(tok):
    for k in ("-j", "-g"):
        if k in tok:
            return tok[tok.index(k) + 1]
    return ""


def _walk(chain, chains, pkt, certain, depth):
    """Verdict of a user/builtin chain body: 'accept' / 'drop' / 'return' / None (fell off the end)."""
    for tok in chains.get(chain, []):
        v = _rule_verdict(tok, chains, pkt, certain, depth)
        if v:
            return v
    return None


def _rule_verdict(tok, chains, pkt, certain, depth):
    m = _match(tok, pkt)
    if m is False:
        return None
    sure = certain and m is True
    tgt = _target(tok)
    if tgt == "ACCEPT":
        return "accept" if sure else None  # an accept we can't prove never counts
    if tgt in ("DROP", "REJECT"):
        return "drop"  # an uncertain drop counts: worst case is one redundant accept
    if tgt == "RETURN":
        return "return" if sure else None
    if tgt in NON_TERMINAL or not tgt:
        return None
    if tgt in chains and depth < 8:
        v = _walk(tgt, chains, pkt, sure, depth + 1)
        return None if v == "return" else v
    return "drop"  # NFQUEUE / unknown target: assume it may block


def console_insert_pos(save_text, cfg):
    """Live IPv4 `iptables-save` -> 1-based INPUT position where console_rule() must be inserted so a
    new LAN connection to the console port gets through, or None when it already does."""
    chains, policy = _filter_chains(save_text)
    dst = ipaddress.ip_address(cfg.get("listen") or "0.0.0.0")
    pkt = {"iface": cfg["lan_if"], "src": ipaddress.ip_network(cfg["lan_cidr"], strict=False),
           "dst": None if dst.is_unspecified else dst, "port": int(cfg["port"])}
    rules = chains.get("INPUT", [])
    for pos, tok in enumerate(rules, 1):
        v = _rule_verdict(tok, chains, pkt, True, 0)
        if v == "accept":
            return None
        if v == "drop":
            return pos
    return None if policy.get("INPUT", "ACCEPT") == "ACCEPT" else len(rules) + 1


def _open_rules(model, ver):
    out = []
    for r in model["wan_open"]:
        if ver == 6 and r.get("src"):
            continue  # IPv4 source network: no v6 counterpart
        for p in _protos(r["proto"]):
            out.append(_accept(p, r["port"], r.get("iface", ""), r.get("src", "")))
    return out


class ValidationError(ValueError):
    pass


def _port(p):
    p = str(p).strip()
    if not PORT_RE.match(p):
        raise ValidationError(f"非法端口: {p}")
    parts = [int(x) for x in re.split(r"[:-]", p)]
    if not all(1 <= x <= 65535 for x in parts) or (len(parts) == 2 and parts[0] > parts[1]):
        raise ValidationError(f"端口超出范围: {p}")
    return parts


def _protos(proto):
    if proto == "both":
        return list(PROTOS)
    if proto not in PROTOS:
        raise ValidationError(f"非法协议: {proto}")
    return [proto]


def _comment(s):
    return COMMENT_RE.sub("", str(s or ""))[:60]


def normalize(model, cfg):
    """Validate and return a normalized copy. Raises ValidationError."""
    for k in ("wan_if", "lan_if"):
        if not IF_RE.match(cfg[k]):
            raise ValidationError(f"非法网卡名: {cfg[k]}")
    lan = ipaddress.ip_network(cfg["lan_cidr"], strict=False)
    out = dict(EMPTY_MODEL)
    # a stored model from before an option existed: the new option stays off until the user ticks it,
    # so upgrading the agent never adds rules nobody confirmed. A brand-new model ({}) gets defaults.
    stored = any(k in model for k in BOOL_KEYS)
    for k in BOOL_KEYS:
        miss = (k in LEGACY_ON) if stored else EMPTY_MODEL[k]
        out[k] = True if k in MANDATORY else bool(model.get(k, miss))
    out["wan_open"] = []
    for r in model.get("wan_open", []):
        _protos(r.get("proto")), _port(r.get("port"))
        iface, src = str(r.get("iface") or ""), str(r.get("src") or "")
        if iface and not IF_RE.match(iface):
            raise ValidationError(f"非法网卡名: {iface}")
        if src:
            try:
                src = str(ipaddress.ip_network(src, strict=False))
            except ValueError:
                raise ValidationError(f"非法来源网段: {src}")
            if ipaddress.ip_network(src).version != 4:
                raise ValidationError(f"来源网段需为 IPv4: {src}")
        out["wan_open"].append({"proto": r["proto"], "port": str(r["port"]).replace("-", ":"),
                                "comment": _comment(r.get("comment")), "iface": iface, "src": src})
    out["forwards"] = []
    seen = set()
    for f in model.get("forwards", []):
        _protos(f.get("proto"))
        ext, inner = _port(f.get("ext")), _port(f.get("int") or f.get("ext"))
        if len(ext) != len(inner) or (len(ext) == 2 and ext[1] - ext[0] != inner[1] - inner[0]):
            raise ValidationError(f"外部/内部端口范围长度不一致: {f.get('ext')} -> {f.get('int')}")
        try:
            ip = ipaddress.ip_address(f.get("ip", ""))
        except ValueError:
            raise ValidationError(f"非法内网 IP: {f.get('ip')}")
        if ip not in lan:
            raise ValidationError(f"{ip} 不在 LAN 网段 {lan} 内")
        enabled = bool(f.get("enabled", True))
        if enabled and "tcp" in _protos(f["proto"]):
            for guard in _guard_ports(cfg):
                if ext[0] <= guard <= ext[-1]:
                    raise ValidationError(f"外部端口 {f['ext']} 覆盖了保底端口 {guard}（SSH/控制台），禁止转发")
        for p in _protos(f["proto"]):
            key = (p, str(f["ext"]))
            if enabled and key in seen:
                raise ValidationError(f"外部端口重复: {p}/{f['ext']}")
            if enabled:
                seen.add(key)
        out["forwards"].append({"name": _comment(f.get("name")), "proto": f["proto"],
                                "ext": "-".join(map(str, ext)), "int": "-".join(map(str, inner)),
                                "ip": str(ip), "enabled": enabled})
    return out


def _guard_ports(cfg):
    return sorted({int(cfg["guard_ssh_port"]), int(cfg["port"])})


# ---------------- import (live iptables-save -> model) ----------------

_INPUT_RE = re.compile(r"^-A INPUT(?: -s (\S+))?(?: -i (\S+))? -p (tcp|udp) -m \3 --dport (\S+) -j ACCEPT$")
_DNAT_RE = re.compile(r"^-A PREROUTING -p (tcp|udp) -m \1 --dport (\S+)(?: -m addrtype --dst-type LOCAL)?"
                      r" -j DNAT --to-destination ([\d.]+)(?::(\S+))?$")
# legacy rules carry "-m tcpmss --mss 1400:65495" (only clamp when above the PPPoE MSS) - same intent
_MSS_RE = re.compile(r"^-A FORWARD -o (\S+) -p tcp -m tcp --tcp-flags SYN,RST SYN(?: -m tcpmss --mss \S+)?"
                     r" -j TCPMSS --clamp-mss-to-pmtu$")
_MANGLE_NOOP_RE = re.compile(r"^-A \S+(?: -[io] \S+)*(?: -m conntrack --ctstate RELATED,ESTABLISHED)? -j ACCEPT$")
BUILTIN = {"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}


def _canon(raw):
    """Whitespace + legacy `-m state --state` -> `-m conntrack --ctstate` (same match)."""
    return re.sub(r"\s+", " ", raw.strip()).replace("-m state --state ", "-m conntrack --ctstate ")


def _parse(text):
    """iptables-save text -> {table: [(chain, line)]} keeping only rules reachable from built-in chains.
    A user chain entered by exactly one unconditional `-A <BUILTIN> -j <chain>` is flattened into that
    built-in chain (legacy mt_rtr_* chains); other user chains keep their own name."""
    tables, cur = {}, None
    for raw in text.splitlines():
        line = _canon(raw)
        if line.startswith("*"):
            cur = tables.setdefault(line[1:], [])
        elif cur is not None and line.startswith("-A "):
            cur.append((line.split(" ")[1], line))
    out, dead = {}, []
    for table, rules in tables.items():
        reach, grew = set(BUILTIN), True
        while grew:  # chains jumped to from a reachable chain are reachable (dead chains never ran)
            grew = False
            for chain, line in rules:
                m = re.search(r" -[jg] (\S+)", line)
                if chain in reach and m and m.group(1) not in reach and m.group(1) not in ("ACCEPT", "DROP"):
                    reach.add(m.group(1))
                    grew = True
        parent = {}
        for chain, line in rules:
            m = re.match(r"^-A (\S+) -j (\S+)$", line)
            if m and m.group(1) in BUILTIN and m.group(2) not in BUILTIN:
                parent[m.group(2)] = None if m.group(2) in parent else m.group(1)
        res = []
        for chain, line in rules:
            if chain not in reach:
                dead.append(line)
                continue
            m = re.match(r"^-A (\S+) -j (\S+)$", line)
            if m and parent.get(m.group(2)) == chain:
                continue  # the jump itself: its target's rules are flattened below
            if parent.get(chain):
                line, chain = line.replace(f"-A {chain} ", f"-A {parent[chain]} ", 1), parent[chain]
            res.append((chain, line))
        out[table] = res
    return out, dead


def _flags_from(line, flags):
    """Sanity rules in any chain/table -> option flags. Returns True when recognised."""
    body = line.split(" ", 2)[2] if line.count(" ") >= 2 else ""
    if body == INVALID_BODY:
        flags["drop_invalid"] = True
    elif body == NEW_NOT_SYN_BODY:
        flags["drop_new_not_syn"] = True
    elif body in BAD_FLAGS_BODIES:
        flags["drop_bad_flags"] = True
    else:
        return False
    return True


def _syn_jump(wan):
    return f"-A INPUT -i {wan} -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j syn_flood"


def import_iptables_save(text, cfg):
    """Live `iptables-save` -> (model, skipped). Every option key is set explicitly from what is live
    (an option not found live stays off), except on a blank machine (no rules) which gets defaults.
    `skipped` lists rules a full-table replace would remove: apply stays blocked until acknowledged."""
    tables, dead = _parse(text)
    if not any(tables.values()) and not dead:
        return dict(EMPTY_MODEL, wan_open=[], forwards=[]), []
    wan, lan = cfg["wan_if"], cfg["lan_if"]
    model = dict({k: k in MANDATORY for k in BOOL_KEYS}, wan_open=[], forwards=[])
    skipped = [f"{l}    # 未挂载到内置链，从未生效" for l in dead]
    ssh = str(int(cfg["guard_ssh_port"]))
    # our own LAN-only guard lines (lan_accept_all off) are recognised, not imported as entries
    own = set(_input_guard(dict(model, ssh_wan=False, lan_accept_all=False), cfg, 4))
    known_input = {"-A INPUT -i lo -j ACCEPT", "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                   "-A INPUT -j DROP"}
    _, syn_chain = _syn_flood(wan)
    fwd_guard, fwd_seen = set(_forward_guard(wan)), set()
    seen_open, fwd_index = set(), {}
    for chain, line in tables.get("filter", []):
        if chain == "INPUT":
            m = _INPUT_RE.match(line)
            if line == f"-A INPUT -i {lan} -j ACCEPT":
                model["lan_accept_all"] = True
            elif line in own:
                pass
            elif m:
                src, iface, proto, port = m.group(1) or "", m.group(2) or "", m.group(3), m.group(4)
                if proto == "tcp" and port == ssh and not src and not iface:
                    model["ssh_wan"] = True  # unrestricted SSH accept = what the ssh_wan guard renders
                elif (proto, port, iface, src) not in seen_open:
                    seen_open.add((proto, port, iface, src))
                    model["wan_open"].append({"proto": proto, "port": port, "comment": "",
                                              "iface": iface, "src": src})
            elif line == _syn_jump(wan):
                model["syn_flood"] = True
            elif line not in known_input and not _flags_from(line, model):
                skipped.append(line)
        elif chain == "FORWARD":
            if line in fwd_guard:
                fwd_seen.add(line)
            elif not _flags_from(line, model):
                skipped.append(line)
        elif not (chain == "syn_flood" and line in syn_chain):
            skipped.append(line)
    model["forward_filter"] = fwd_seen == fwd_guard
    hairpin = {f"-A POSTROUTING -o {lan} -j MASQUERADE", _hairpin_rule(cfg)}
    for chain, line in tables.get("nat", []):
        if chain == "PREROUTING":
            m = _DNAT_RE.match(line)
            if not m:
                skipped.append(line)
                continue
            if "addrtype" in line:
                model["dnat_local_only"] = True
            ext = m.group(2).replace(":", "-")
            key = (ext, m.group(3), m.group(4) or ext)
            if key in fwd_index:  # same mapping for tcp+udp -> merge into "both"
                fwd_index[key]["proto"] = "both"
                continue
            fwd = {"name": "", "proto": m.group(1), "ext": ext, "ip": m.group(3),
                   "int": m.group(4) or ext, "enabled": True}
            fwd_index[key] = fwd
            model["forwards"].append(fwd)
        elif line in hairpin:
            model["lan_masquerade"] = True
        elif line != f"-A POSTROUTING -o {wan} -j MASQUERADE":
            skipped.append(line)
    for chain, line in tables.get("mangle", []):
        m = _MSS_RE.match(line)
        if m and m.group(1) == wan:
            model["mss_clamp"] = True  # duplicates collapse into one rendered rule
        elif not _MANGLE_NOOP_RE.match(line):  # ACCEPT in mangle only ends the mangle chain
            skipped.append(line)
    return model, skipped


def import_ip6tables_save(text, cfg, v4_model):
    """Live `ip6tables-save` -> (option overrides, skipped). Empty ruleset -> ({}, [])."""
    tables, dead = _parse(text)
    if not any(tables.values()) and not dead:
        return {}, []
    flags = {"ipv6_filter": False, "mss_clamp_v6": False}
    full = dict(v4_model, **{k: True for k in BOOL_KEYS})
    known = set(render_v6(full, cfg).splitlines()) | set(
        render_v6(dict(full, lan_accept_all=False, ssh_wan=False), cfg).splitlines())
    skipped = [f"{l}    # 未挂载到内置链，从未生效" for l in dead]
    for chain, line in tables.get("filter", []):
        if line == "-A INPUT -j DROP":
            flags["ipv6_filter"] = True
        elif chain in ("INPUT", "FORWARD") and _flags_from(line, flags):
            pass
        elif line not in known:
            skipped.append(line)
    for chain, line in tables.get("mangle", []):
        m = _MSS_RE.match(line)
        if m and m.group(1) == cfg["wan_if"]:
            flags["mss_clamp_v6"] = True
        elif chain == "FORWARD" and _flags_from(line, flags):
            pass  # legacy mt_rtr_6_m_rtr keeps sanity drops in mangle; we render them in filter FORWARD
        elif not _MANGLE_NOOP_RE.match(line):
            skipped.append(line)
    for table in ("nat",):  # v6 nat is not managed: left untouched, nothing lost
        tables.pop(table, None)
    flags.pop("drop_invalid", None)  # mandatory anyway
    return flags, skipped


def lint(model, cfg):
    """Security advisories shown in the UI (informational, never auto-fixed)."""
    tips = []
    risky = {"53": "DNS（公网开放 = 开放解析器，可被用于反射攻击）",
             "67": "DHCP 服务端", "68": "DHCP 客户端"}
    for r in model["wan_open"]:
        if r.get("iface") == cfg["lan_if"]:
            continue  # LAN-only accept: not exposed to WAN
        if r["port"] in risky:
            tips.append({"level": "warning", "msg": f"{r['proto']}/{r['port']} {risky[r['port']]} 对 WAN 开放；"
                         "LAN 已由保底规则放行，建议删除"})
    if model.get("ssh_wan"):
        tips.append({"level": "warning", "msg": f"SSH {cfg['guard_ssh_port']} 对 WAN 开放：公网会持续被扫描爆破，"
                                                "建议只用密钥登录，或取消勾选“SSH 对 WAN 开放”"})
    for fw in model["forwards"]:
        if fw["enabled"] and fw["int"] in ("445", "139", "3389", "23"):
            tips.append({"level": "warning", "msg": f"端口转发 {fw['ext']} -> {fw['ip']}:{fw['int']} 将高危服务暴露到公网"})
    if not model["ipv6_filter"]:
        tips.append({"level": "warning", "msg": "IPv6 未启用防火墙：WAN 侧有公网 IPv6 时路由器与 LAN 设备可能被直接访问"})
    if not model["forward_filter"]:
        tips.append({"level": "warning", "msg": "未启用 WAN 转发过滤：WAN 侧主机可把 LAN 网段设为路由直接访问内网设备，"
                                                "建议勾选“过滤 WAN→LAN 转发”"})
    return tips


# ---------------- render (model -> iptables-restore text) ----------------

def render_v4(model, cfg):
    """Render full filter/nat/mangle tables for iptables-restore (replaces these 3 tables)."""
    wan, lan = cfg["wan_if"], cfg["lan_if"]
    jump, syn_chain = _syn_flood(wan)
    f = ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]"]
    if model["syn_flood"]:
        f.append(":syn_flood - [0:0]")
    # guard rules first; sanity drops right after ESTABLISHED (as fw4), SSH guard is never rate-limited
    f += ["-A INPUT -i lo -j ACCEPT", "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]
    f += _sanity(model, "INPUT")
    f += _input_guard(model, cfg, 4)
    if model["syn_flood"]:
        f += jump
    f += _open_rules(model, 4)
    f.append("-A INPUT -j DROP")
    f += _sanity(model, "FORWARD")
    if model["forward_filter"]:
        f += _forward_guard(wan)
    if model["syn_flood"]:
        f += syn_chain
    f.append("COMMIT")

    n = ["*nat", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]",
         ":POSTROUTING ACCEPT [0:0]"]
    local = " -m addrtype --dst-type LOCAL" if model["dnat_local_only"] else ""
    for fw in model["forwards"]:
        if not fw["enabled"]:
            continue
        ext = fw["ext"].replace("-", ":")
        for p in _protos(fw["proto"]):
            n.append(f"-A PREROUTING -p {p} -m {p} --dport {ext}{local} -j DNAT --to-destination {fw['ip']}:{fw['int']}")
    if model["lan_masquerade"]:
        n.append(_hairpin_rule(cfg))
    n += [f"-A POSTROUTING -o {wan} -j MASQUERADE", "COMMIT"]

    m = ["*mangle", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]",
         ":OUTPUT ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]"]
    if model["mss_clamp"]:
        m.append(_mss_rule(wan))
    m.append("COMMIT")
    return "\n".join(f + n + m) + "\n"


def render_v6(model, cfg):
    """v6 filter + mangle are managed (nat is left untouched: no MASQUERADE for IPv6).
    ICMPv6 is accepted before the INVALID drop: some kernels classify ND/RA as INVALID."""
    lan = cfg["lan_if"]
    lines = ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]"]
    if model["ipv6_filter"]:
        lines += ["-A INPUT -i lo -j ACCEPT",
                  "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                  "-A INPUT -p ipv6-icmp -j ACCEPT"]  # RA/ND from ISP over ppp0 must pass
        lines += _sanity(model, "INPUT")
        lines += _input_guard(model, cfg, 6)
        lines.append("-A INPUT -p udp -m udp --dport 546 -j ACCEPT")  # DHCPv6-PD client
        lines += _open_rules(model, 6)
        lines += ["-A INPUT -j DROP", "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]
    lines.append("-A FORWARD -p ipv6-icmp -j ACCEPT")
    lines += _sanity(model, "FORWARD")
    if model["ipv6_filter"]:
        lines += [f"-A FORWARD -i {lan} -j ACCEPT", "-A FORWARD -j DROP"]
    lines += ["COMMIT", "*mangle", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]",
              ":OUTPUT ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]"]
    if model["mss_clamp_v6"]:
        lines.append(_mss_rule(cfg["wan_if"]))
    return "\n".join(lines + ["COMMIT"]) + "\n"

