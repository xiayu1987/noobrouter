"""UI language for agent messages. Messages are authored in Chinese at their source; for an
English client the response is translated here, in one place, by whole-string templates.

Only system-generated fields are touched (TEXT_KEYS) and only whole-string matches are
replaced, so user data (remarks, hostnames, file contents) passes through unchanged.
A string with no template stays Chinese - never wrong, only untranslated."""
import re

# keys whose values (str or list of str) are agent-generated text
TEXT_KEYS = {"error", "msg", "label", "desc", "group", "hint", "summary", "content",
             "blockers", "warnings", "tips", "skipped"}

# (zh template, en template). {name} = parameter, matched non-greedily.
TEMPLATES = [
    # --- server / api / applier / dhcp
    ("请求体过大", "Request body too large"),
    ("需要 application/json", "application/json required"),
    ("请求体必须是 JSON 对象", "Request body must be a JSON object"),
    ("未授权", "Unauthorized"),
    ("接口不存在", "No such endpoint"),
    ("web_root 未配置", "web_root is not configured"),
    ("参数 {k} 必须是整数", "Parameter {k} must be an integer"),
    ("缺少 model 对象", "Missing model object"),
    ("将清空全部 {k}（当前 {n} 条），如确认请传 allow_empty=true",
     "This would remove all {k} ({n} now); pass allow_empty=true to confirm"),
    ("不支持的日志来源", "Unsupported log source"),
    ("非法主机名", "Invalid host name"),
    ("不支持的工具", "Unsupported tool"),
    ("存在导入器未识别的规则，整表应用会删除它们。请先在页面确认",
     "Some rules were not recognised by the importer and a full apply would delete them. Acknowledge them on the page first"),
    ("没有待确认的变更", "No change awaiting confirmation"),
    ("当前待确认的是 {k} 事务，请到对应页面处理", "The pending change is a {k} transaction; handle it on its page"),
    ("{ip} 当前被 {mac} {host} 占用", "{ip} is currently used by {mac} {host}"),
    ("缺少 plan 对象", "Missing plan object"),
    ("dry_run 模式下不能应用初始化，只能预览", "Setup cannot be applied in dry_run mode, preview only"),
    ("systemd 不可用", "systemd is not available"),
    ("dry_run 模式：只允许预览与 --test 校验，不会写入防火墙",
     "dry_run mode: preview and --test only, the firewall is not written"),
    ("已有待确认的变更，请先确认或回滚", "A change is already awaiting confirmation; confirm or roll it back first"),
    ("非法事务类型: {k}", "Invalid transaction kind: {k}"),
    ("非法 MAC: {v}", "Invalid MAC: {v}"),
    ("{ip} 不在 LAN 网段内", "{ip} is not inside the LAN subnet"),
    ("非法主机名: {v}（字母数字和-）", "Invalid host name: {v} (letters, digits and -)"),
    ("静态绑定重复: {a} / {b}", "Duplicate static lease: {a} / {b}"),
    ("非法域名: {v}", "Invalid domain: {v}"),
    ("dry_run 模式：不会写入 dnsmasq 配置", "dry_run mode: dnsmasq config is not written"),
    # --- firewall: validation / import / lint
    ("非法端口: {v}", "Invalid port: {v}"),
    ("端口超出范围: {v}", "Port out of range: {v}"),
    ("非法协议: {v}", "Invalid protocol: {v}"),
    ("非法网卡名: {v}", "Invalid interface name: {v}"),
    ("非法来源网段: {v}", "Invalid source subnet: {v}"),
    ("来源网段需为 IPv4: {v}", "Source subnet must be IPv4: {v}"),
    ("外部/内部端口范围长度不一致: {a} -> {b}", "External/internal port ranges differ in length: {a} -> {b}"),
    ("非法内网 IP: {v}", "Invalid LAN IP: {v}"),
    ("{ip} 不在 LAN 网段 {lan} 内", "{ip} is not inside the LAN subnet {lan}"),
    ("外部端口 {p} 覆盖了保底端口 {g}（SSH/控制台），禁止转发",
     "External port {p} covers the guard port {g} (SSH/console); forwarding it is not allowed"),
    ("外部端口重复: {v}", "Duplicate external port: {v}"),
    ("{rule}    # 未挂载到内置链，从未生效", "{rule}    # not hooked into a built-in chain, never took effect"),
    ("{port} DNS（公网开放 = 开放解析器，可被用于反射攻击） 对 WAN 开放；LAN 已由保底规则放行，建议删除",
     "{port} DNS (open to the internet = open resolver, usable for reflection attacks) is open to WAN; "
     "LAN is already allowed by the guard rules, consider removing it"),
    ("{port} DHCP 服务端 对 WAN 开放；LAN 已由保底规则放行，建议删除",
     "{port} DHCP server is open to WAN; LAN is already allowed by the guard rules, consider removing it"),
    ("{port} DHCP 客户端 对 WAN 开放；LAN 已由保底规则放行，建议删除",
     "{port} DHCP client is open to WAN; LAN is already allowed by the guard rules, consider removing it"),
    ("SSH {p} 对 WAN 开放：公网会持续被扫描爆破，建议只用密钥登录，或取消勾选“SSH 对 WAN 开放”",
     "SSH {p} is open to WAN: it will be scanned and brute-forced constantly. Use key-only login, "
     "or untick \"SSH open to WAN\""),
    ("端口转发 {a} -> {b} 将高危服务暴露到公网", "Port forward {a} -> {b} exposes a high-risk service to the internet"),
    ("IPv6 未启用防火墙：WAN 侧有公网 IPv6 时路由器与 LAN 设备可能被直接访问",
     "IPv6 firewall is off: with public IPv6 on WAN, the router and LAN devices may be reachable directly"),
    ("未启用 WAN 转发过滤：WAN 侧主机可把 LAN 网段设为路由直接访问内网设备，建议勾选“过滤 WAN→LAN 转发”",
     "WAN forward filtering is off: a WAN host can route to the LAN subnet and reach LAN devices. "
     "Consider ticking \"Filter WAN→LAN forwarding\""),
    # --- option / tuning catalogues (firewall.OPTIONS, UNSUPPORTED, bootstrap.TUNING)
    ("基础", "Basics"), ("安全", "Security"), ("转发优化", "Forwarding"),
    ("连接跟踪", "Connection tracking"), ("TCP 与队列", "TCP & queueing"),
    ("保底放行（lo / 已建立连接 / LAN 管理端口）", "Guard rules (lo / established / LAN management ports)"),
    ("防止规则把自己锁在门外，始终生成", "Keeps you from locking yourself out; always generated"),
    ("LAN 可访问路由器全部端口", "LAN may reach every port on the router"),
    ("关闭后 LAN 只能访问 SSH、控制台、DNS、DHCP、ping 和下方显式放行的端口",
     "When off, LAN can only reach SSH, the console, DNS, DHCP, ping and the ports allowed below"),
    ("SSH 对 WAN 开放", "SSH open to WAN"),
    ("关闭时 SSH 只对 LAN 放行；需要远程管理时建议改用 VPN", "When off, SSH is LAN-only; use a VPN for remote management"),
    ("丢弃 INVALID 状态包", "Drop INVALID packets"),
    ("conntrack 无法归属的包（含畸形 TCP 标志）在 INPUT/FORWARD 直接丢弃",
     "Packets conntrack cannot classify (incl. malformed TCP flags) are dropped in INPUT/FORWARD"),
    ("丢弃首包非 SYN 的新 TCP 连接", "Drop new TCP connections that do not start with SYN"),
    ("挡住 ACK 扫描；路由器重启后已有长连接需客户端重连",
     "Blocks ACK scans; after a router restart, long-lived connections must reconnect"),
    ("丢弃 XMAS / NULL 扫描包", "Drop XMAS / NULL scan packets"),
    ("TCP 标志位全置或全空，正常协议栈不会发出", "All or no TCP flags set; normal stacks never send these"),
    ("WAN 入站 SYN 限速（25/s，突发 50）", "Rate-limit inbound WAN SYN (25/s, burst 50)"),
    ("只限发往路由器本机的新连接，不影响转发流量（同 OpenWrt synflood_protect）",
     "Only new connections to the router itself; forwarded traffic is unaffected (like OpenWrt synflood_protect)"),
    ("过滤 WAN→LAN 转发", "Filter WAN→LAN forwarding"),
    ("只放行回包和端口转发，防止 WAN 侧把 LAN 网段设为路由直连内网",
     "Only replies and port forwards pass, so a WAN host cannot route straight into the LAN subnet"),
    ("IPv6 基础防火墙", "Basic IPv6 firewall"),
    ("有公网 IPv6 时建议开启；ICMPv6 与 DHCPv6\u2011PD 自动放行",
     "Recommended with public IPv6; ICMPv6 and DHCPv6\u2011PD are allowed automatically"),
    ("IPv4 TCP MSS 钳制", "IPv4 TCP MSS clamping"),
    ("按出口 MTU 修正 MSS，PPPoE 下避免大包黑洞（网页打不开/卡住）",
     "Fixes MSS to the egress MTU so large packets are not black-holed on PPPoE (pages hang)"),
    ("IPv6 TCP MSS 钳制", "IPv6 TCP MSS clamping"),
    ("同上，作用于 IPv6 转发", "Same as above, for IPv6 forwarding"),
    ("LAN 回流 NAT", "LAN hairpin NAT"),
    ("内网用公网 IP/域名访问端口转发；仅对 LAN→LAN 生效，外部访问保留真实来源 IP",
     "Lets LAN reach port forwards via the public IP/domain; only LAN→LAN, outside clients keep their real source IP"),
    ("仅对发往本机的流量做 DNAT", "DNAT only traffic addressed to the router"),
    ("避免转发规则误伤经过路由器去往其它地址的流量",
     "Keeps forward rules from catching traffic that passes through to other addresses"),
    ("流量卸载（flowtable）", "Flow offload (flowtable)"),
    ("需要 nftables flowtable，当前 iptables 后端不支持", "Needs nftables flowtable; the iptables backend does not support it"),
    ("开启 IPv4 转发、宽松反向路径校验", "Enable IPv4 forwarding, loose reverse-path filter"),
    ("ip_forward=1，rp_filter=2（多出口/策略路由下不误丢包）。软路由必需",
     "ip_forward=1, rp_filter=2 (no false drops with multiple uplinks/policy routing). Required for a router"),
    ("连接跟踪表扩容到 65536 条", "Grow the conntrack table to 65536 entries"),
    ("内核按内存估算默认值（实测 1GB 内存的 Debian 12 只有 7680 条），多设备/P2P 下会报 table full 丢包；"
     "哈希桶同步加到 16384。表满时约占 20MB 内存",
     "The kernel sizes it from RAM (Debian 12 with 1 GB gets only 7680), so many devices/P2P hit \"table full\" "
     "and drop packets; buckets go to 16384 too. About 20 MB of RAM when full"),
    ("缩短已建立 TCP 连接的空闲超时（同 OpenWrt）", "Shorter idle timeout for established TCP (like OpenWrt)"),
    ("内核默认 432000 秒（5 天）改为 7440 秒：断开不发 FIN 的设备留下的表项约 2 小时后释放",
     "Kernel default 432000 s (5 days) becomes 7440 s: entries left by devices that vanish without FIN are freed after about 2 h"),
    ("BBR 拥塞控制 + fq 队列", "BBR congestion control + fq qdisc"),
    ("只影响路由器自身发起的 TCP（控制台、代理、下载），转发流量不受拥塞算法影响；"
     "fq 只对之后新建的网卡队列生效。需内核 4.9+",
     "Only affects TCP started by the router itself (console, proxy, downloads); forwarded traffic is unaffected. "
     "fq applies to queues created afterwards. Needs kernel 4.9+"),
    ("TCP MTU 探测", "TCP MTU probing"),
    ("tcp_mtu_probing=1：路径上 ICMP 被丢时自动降 MSS，避免 PPPoE 下本机连接卡死",
     "tcp_mtu_probing=1: lowers MSS when ICMP is dropped on the path, so local connections do not stall on PPPoE"),
    # --- bootstrap: plan validation
    ("WAN 网关", "WAN gateway"), ("DHCP 起始", "DHCP start"), ("DHCP 结束", "DHCP end"), ("上游 DNS", "upstream DNS"),
    ("非法 {what}: {v}", "Invalid {what}: {v}"),
    ("WAN 类型必须是 pppoe / dhcp / static", "WAN type must be pppoe / dhcp / static"),
    ("{side} 网卡名非法: {v}", "{side} interface name is invalid: {v}"),
    ("WAN 与 LAN 不能是同一块网卡", "WAN and LAN cannot be the same NIC"),
    ("PPPoE {k} 为空或含空白/引号/反斜杠/#", "PPPoE {k} is empty or contains whitespace/quotes/backslash/#"),
    ("PPPoE MTU 应在 576-1500", "PPPoE MTU must be 576-1500"),
    ("WAN 地址需为 CIDR，如 203.0.113.2/24: {v}", "WAN address must be CIDR, e.g. 203.0.113.2/24: {v}"),
    ("LAN 地址需为 CIDR，如 192.168.50.1/24: {v}", "LAN address must be CIDR, e.g. 192.168.50.1/24: {v}"),
    ("LAN 地址需为私有 IPv4，前缀 /8-/30", "LAN address must be private IPv4 with prefix /8-/30"),
    ("LAN 地址不能是网络号或广播地址", "LAN address cannot be the network or broadcast address"),
    ("WAN 与 LAN 网段重叠", "WAN and LAN subnets overlap"),
    ("DHCP 地址池需在 {net} 内且起始<=结束", "DHCP pool must be inside {net} with start <= end"),
    ("DHCP 地址池不能包含路由器自身 IP", "DHCP pool cannot include the router's own IP"),
    ("租期格式如 12h / 30m / infinite: {v}", "Lease must look like 12h / 30m / infinite: {v}"),
    ("tuning 需为对象", "tuning must be an object"),
    ("SSH 端口非法", "Invalid SSH port"),
    # --- bootstrap: environment conflicts (blockers / warnings), apply result, preview placeholders
    ("网卡 {a} 由 NetworkManager 管理（连接 UUID {uuid}），初始化后会争抢配置；请先在 /etc/NetworkManager/conf.d/ 写入 "
     "[keyfile] unmanaged-devices=interface-name:{b} 并 systemctl reload NetworkManager（该口会短暂断开，请在控制台旁操作）",
     "NIC {a} is managed by NetworkManager (connection UUID {uuid}) and would fight over the config after setup. "
     "First write [keyfile] unmanaged-devices=interface-name:{b} to /etc/NetworkManager/conf.d/ and run "
     "systemctl reload NetworkManager (the port drops briefly; do it next to a console)"),
    ("NetworkManager 正在运行，但未管理所选 WAN/LAN 网卡", "NetworkManager is running but does not manage the chosen WAN/LAN NICs"),
    ("{fn} 已定义 {kind} {names}（涉及 {hit}；若为 cloud-init 生成，还需在 /etc/cloud/cloud.cfg.d/ 中"
     "写 'network: {config: disabled}'），请先移走该文件再初始化",
     "{fn} defines {kind} {names} (affects {hit}; if cloud-init generated it, also write "
     "'network: {config: disabled}' under /etc/cloud/cloud.cfg.d/). Move the file away before setup"),
    ("netplan 配置 {fn} 管理了 {hit}：初始化将移除它（回滚时恢复）",
     "netplan config {fn} manages {hit}: setup removes it (restored on rollback)"),
    ("systemd-networkd 正在运行：初始化将停用它并改由 ifupdown 管理网卡（回滚时恢复）；停用瞬间 WAN 的 DHCP 地址会重新获取",
     "systemd-networkd is running: setup stops it and hands the NICs to ifupdown (restored on rollback); "
     "the WAN DHCP lease is renewed at that moment"),
    ("/etc/network/interfaces 已定义 {kind} {names}（涉及 {hit}），请先注释掉该段再初始化",
     "/etc/network/interfaces defines {kind} {names} (affects {hit}); comment that stanza out before setup"),
    ("/etc/network/interfaces 未包含 'source /etc/network/interfaces.d/*'，受管片段不会生效",
     "/etc/network/interfaces lacks 'source /etc/network/interfaces.d/*', so the managed snippets would not load"),
    ("{side} 网卡 {n} 不存在（可用: {names}）", "{side} NIC {n} does not exist (available: {names})"),
    ("缺少软件包: {pk}（先运行 install.sh --with-deps 或 apt-get install）",
     "Missing packages: {pk} (run install.sh --with-deps or apt-get install first)"),
    ("{fn} 已有手写的 DHCP 设置（{lines}），与初始化生成的基础配置重复；请先注释掉这些行",
     "{fn} already has hand-written DHCP settings ({lines}) that duplicate the generated base config; comment them out first"),
    ("IPv6：LAN 的 RA 仅在 LAN 口获得公网/ULA 前缀后生效；本向导不配置 DHCPv6-PD",
     "IPv6: LAN RA only works once the LAN port has a public/ULA prefix; this wizard does not configure DHCPv6-PD"),
    ("内核没有模块 {m}，请取消勾选“{names}”（否则 sysctl 会失败并整体回滚）",
     "The kernel lacks module {m}; untick \"{names}\" (otherwise sysctl fails and everything rolls back)"),
    ("现有防火墙含导入器未识别的规则，初始化整表替换会删除它们；请先在防火墙页确认",
     "The current firewall has rules the importer did not recognise and setup's full replace would delete them; "
     "acknowledge them on the firewall page first"),
    ("NetworkManager 连接 {uuid}", "NetworkManager connection {uuid}"),
    ("(将删除，回滚时恢复)", "(will be deleted, restored on rollback)"),
    ("(含密码或 token，已隐藏)", "(contains a password or token, hidden)"),
    ("存在阻塞项:", "Blockers present:"),
    ("初始化 WAN={t} LAN={a}", "Setup WAN={t} LAN={a}"),
    ("PPPoE 仍在拨号或认证失败，稍后在状态页查看 ppp0；日志: journalctl -t pppd",
     "PPPoE is still dialling or authentication failed; check ppp0 on the status page later. Logs: journalctl -t pppd"),
    ("{a} 未获得 IPv4 地址：检查网线/上游，或执行 ifup --force {b} 查看报错",
     "{a} got no IPv4 address: check the cable/upstream, or run ifup --force {b} to see the error"),
    ("没有待确认的初始化", "No setup awaiting confirmation"),
    ("没有待回滚的初始化", "No setup to roll back"),
]
TEXT_KEYS.add("source")  # probe results: "NetworkManager 连接 <uuid>"; file paths never match a template

_PARAM = re.compile(r"\{(\w+)\}")


def _compile(zh, en):
    parts = _PARAM.split(zh)  # literal, name, literal, name, ...
    names = parts[1::2]
    assert len(set(names)) == len(names) and set(_PARAM.findall(en)) == set(names), zh
    rx = "".join(re.escape(p) if i % 2 == 0 else f"(?P<{p}>.+?)" for i, p in enumerate(parts))
    return re.compile(rx + r"\Z"), max(parts[::2], key=len), en


_COMPILED = [_compile(zh, en) for zh, en in TEMPLATES]
MAX_LEN = 4000  # messages are short; never scan file contents with the regexes


def _line(s):
    for rx, lit, en in _COMPILED:
        if lit in s:
            m = rx.match(s)
            if m:  # parameters may themselves be messages (option labels, joined blockers)
                vals = {k: _str(v) for k, v in m.groupdict().items()}
                return _PARAM.sub(lambda x: vals[x.group(1)], en)
    return s


def _str(s):
    if len(s) > MAX_LEN or not any("\u4e00" <= c <= "\u9fff" for c in s):
        return s
    return "\n".join(_line(x) for x in s.split("\n"))


def lang_of(header):
    """'en' when the client's first preference is English, else 'zh' (messages' source language)."""
    first = (header or "").split(",")[0].strip().lower()
    return "en" if first.startswith("en") else "zh"


def translate(data, lang, _text=False):
    if lang != "en":
        return data
    if isinstance(data, dict):
        return {k: translate(v, lang, k in TEXT_KEYS) for k, v in data.items()}
    if isinstance(data, list):
        return [translate(x, lang, _text) for x in data]
    if _text and isinstance(data, str):
        return _str(data)
    return data
