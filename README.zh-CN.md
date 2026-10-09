# NoobRouter

[English](README.md) | 简体中文

NoobRouter 把一台普通 Linux 机器直接做成软路由。不用刷 OpenWrt 之类的专用固件，系统还是你熟悉的 Debian：装上之后，用初始化向导配好拨号上网、内网 DHCP/DNS 和防火墙，日常的端口转发、设备管理、流量监控和故障诊断都在浏览器里完成。改防火墙时超时会自动回滚，不怕把自己锁在外面。

## 功能

- 初始化向导：把一台空白机器配置成软路由，WAN 支持 PPPoE、DHCP、静态地址
- 概览：CPU、内存、WAN 状态，实时流量曲线
- 网络：接口、路由表、在线设备（DHCP 租约 + ARP）、连接跟踪
- 防火墙：端口转发（DNAT）、WAN 开放端口、安全与转发优化选项、导入现有规则、预览，应用时带超时自动回滚
- DHCP / DNS：静态绑定、本地 DNS 记录，带冲突检测和预览
- 服务状态与日志，网络诊断（ping、traceroute、DNS 查询）

## 支持的系统

| 系统 | 状态 |
| --- | --- |
| Debian 12 / 13 | 支持，已测试 |
| Ubuntu 22.04 及以上等 Debian 系发行版 | 应该可用，未测试 |
| RHEL / CentOS / Fedora / Arch / Alpine 等 | 不支持初始化和应用配置 |

完整功能依赖以下组件：

- systemd：服务管理和回滚定时器（`systemd-run`）
- ifupdown：`/etc/network/interfaces`
- pppd，按 pppoeconf 方式配置（`/etc/ppp/peers/*`）
- dnsmasq：DHCP 和 DNS
- iptables / ip6tables 命令（`iptables-restore`），已测试 nf_tables 后端（Debian 默认）
- apt：只有 `install.sh --with-deps` 用到

限制：

- 只有 nftables、没有 iptables 命令的系统不能应用防火墙。flowtable 等 nftables 专有功能在界面中显示为不可用。
- 网卡由 NetworkManager、netplan 或 systemd-networkd 管理时：
  - 防火墙、DHCP 等页面可以正常使用。
  - 初始化向导会给出阻塞项或警告，需要先按提示处理。
- 状态、设备、连接等监控页只读取 `/proc` 和 `ip` 命令，在其他发行版上大概率可用，但没有验证过。
- 没有 HTTPS，只适合在可信内网使用。

## 环境要求

- 目标机：Python 3（Debian 12 自带的 3.11 或 Debian 13 的 3.13）、root 权限
- 目标机下载工具：curl、wget 或 python3 任一即可，另需 sha256sum、tar
- 从源码构建（可选）：Linux 或 macOS，Node.js ≥ 20.19，Python 3、tar、sha256sum

## 快速开始：在路由器上一键安装

以 root 身份在路由器上执行：

```sh
curl -fsSL https://github.com/xiayu1987/noobrouter/releases/latest/download/get.sh | sh -s -- --start
```

`get.sh` 按顺序执行以下步骤，任一步失败都会停止：

1. 下载 `noobrouter-agent.tar.gz` 和 `.sha256`。
2. 校验 sha256，不一致就中止。
3. 解压并运行 `install.sh`，参数原样传入。
4. 带 `--start` 时做健康检查：服务为 active，并在配置的地址上监听。

它不会改动已有的配置，`dry_run` 保持原值。有未确认的防火墙或初始化变更时，`install.sh` 会中止。

| 参数 | 说明 |
| --- | --- |
| `--start` | 安装后启动或重启服务，并做健康检查 |
| `--with-deps` | 用 apt 安装路由所需软件包，见下文 |
| `--force` | 有未确认的变更时也继续安装 |
| `NOOBROUTER_URL`（环境变量） | 下载地址，默认是 GitHub 最新 Release，可指向镜像 |

## 从源码安装

```sh
cd web && npm ci && npm run build && cd ..
sh deploy/pack.sh          # 生成 dist/noobrouter-agent.tar.gz、.sha256、get.sh
# 把 noobrouter-agent.tar.gz 复制到路由器，然后在路由器上执行：
tar xzf noobrouter-agent.tar.gz && sh noobrouter-agent-*/install.sh --start
```

`install.sh` 的行为：

- 代码安装到 `/opt/noobrouter-agent`，并注册 systemd 服务 `noobrouter-agent`。
- 第一次安装会生成 `/etc/noobrouter-agent.json`（权限 0600），已有配置不会被覆盖。
- 不会改动防火墙、网络和 dnsmasq。不加 `--start` 时不会启动或重启服务。
- 有未确认的变更（`fw/pending.json` 或 `noobrouter-rollback` 定时器）时中止，需要先确认或回滚，或者加 `--force`。
- `--with-deps`：安装 `iptables iptables-persistent dnsmasq ppp ifupdown iproute2 isc-dhcp-client`。新装的 dnsmasq 保持停止状态，等初始化向导配置。

## 配置

配置文件是 `/etc/noobrouter-agent.json`，修改后执行 `systemctl restart noobrouter-agent` 生效。

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `listen` | `127.0.0.1` | 监听地址。改成 LAN IP 才能在局域网访问，不要填 WAN 地址 |
| `port` | `8090` | 监听端口 |
| `token` | 空 | 登录令牌。留空时自动生成并保存到 `/var/lib/noobrouter-agent/token` |
| `dry_run` | `true` | 为 true 时只预览和校验，不改动系统 |
| `wan_if` | `ppp0` | WAN 三层接口，PPPoE 时为 `ppp0` |
| `wan_phy_if` | `CHECK_ME` | WAN 物理网卡，用 `ip -br link` 查看 |
| `lan_if` | `CHECK_ME` | LAN 网卡 |
| `lan_cidr` | `192.168.1.0/24` | LAN 网段 |
| `rollback_seconds` | `90` | 应用变更后，在这个时间内不确认就自动回滚 |
| `guard_ssh_port` | `22` | 保底规则始终放行的 SSH 端口 |

首次使用：

1. 填好 `wan_phy_if`、`lan_if`、`lan_cidr`。
2. 把 `listen` 改为 LAN IP，然后重启服务；或者不改，通过 SSH 隧道访问：`ssh -L 8090:127.0.0.1:8090 root@<路由器>`。
3. 浏览器打开 `http://<listen>:<port>`，用 token 登录。
4. 在 `dry_run: true` 下确认各页面显示正常后，再改为 `false` 并重启服务。

## 安全说明

- 访问需要 Bearer token。只应监听 LAN 地址或 127.0.0.1。
- 防火墙规则用 `iptables-restore` 整表原子替换。内置保底链始终放行已建立的连接、LAN 和 SSH。
- 每次应用都会用 `systemd-run` 设置回滚定时器。超时未确认时，防火墙和受管配置文件自动恢复。
- 第一次真正应用前，建议另开一个 SSH 会话保持连接，最好在本地控制台或另一条链路上操作。
- 已在运行的路由器不要执行初始化向导，它会接管网卡、拨号和 dnsmasq，执行时会断网。日常管理用防火墙、DHCP 等页面即可。

## 初始化向导的阻塞项

预览出现以下情况时不能应用，需要先手动处理：

- `/etc/network/interfaces` 没有 `source /etc/network/interfaces.d/*`
- 要用的网卡已在 `/etc/network/interfaces` 或 `interfaces.d/` 的其他片段中定义，例如 cloud-init 生成的 `50-cloud-init`
- 要用的网卡由 NetworkManager 管理，需要在 `/etc/NetworkManager/conf.d/` 中设置 `unmanaged-devices`
- 选择的网卡不存在，或缺少软件包（运行 `install.sh --with-deps`）
- 主配置 `dnsmasq.conf` 中有手写的 DHCP 设置
- 现有防火墙中有导入器无法识别的规则，需要先在防火墙页确认导入

netplan / systemd-networkd 只会给出警告。初始化时会备份并移走它们的配置，回滚时恢复。

## 升级

在路由器上重新执行快速开始里的 `get.sh` 命令，或手动安装新包时带上 `install.sh --start`。配置和 token 会保留。

从旧版 softroute-agent 升级时，`install.sh` 会自动迁移：

- 配置、数据目录和 token 迁移到新路径，旧配置保留为 `/etc/softroute-agent.json.migrated`。
- 旧版初始化向导写过的系统文件只改名，内容不变，也不会重载网络或 dnsmasq。
- 旧版有未确认的变更时会中止升级，需要先确认或回滚。
- 浏览器中已打开的页面需要重新登录一次。

## 卸载

```sh
systemctl disable --now noobrouter-agent
rm -rf /opt/noobrouter-agent /etc/systemd/system/noobrouter-agent.service
systemctl daemon-reload
# 如果不再需要配置和数据，再删除：
rm -rf /etc/noobrouter-agent.json /var/lib/noobrouter-agent
```

卸载不会还原 agent 已应用的防火墙规则和 dnsmasq 配置，它们仍保存在 `/etc/iptables/` 和 `/etc/dnsmasq.d/` 中。

## 开发

```sh
cd web && npm ci && npm run dev                       # 开发服务器，/api 代理到 127.0.0.1:18090
cd agent && python3 -m unittest discover -s tests    # 单元测试
sudo sh agent/tests/smoke_http.sh                     # HTTP 冒烟测试（读取 iptables 需要 root）
sudo sh agent/tests/e2e_dist.sh                       # 基于 web/dist 的端到端测试（需要 root）
sh deploy/rehearse_install.sh                         # 打包 + 安装演练（PREFIX 安装，不改动本机系统；非 root 时跳过 init 接口检查）
```

用自己路由器的数据做本地测试（不进仓库）：

```sh
cp agent/tests/local.example.json agent/tests/local.json      # 按自己的网卡、网段修改 cfg
mkdir -p agent/tests/fixtures/local
ssh root@<路由器> iptables-save > agent/tests/fixtures/local/iptables_save.txt
cd agent && python3 -m unittest tests.test_local -v
```

- `local.json` 和 `fixtures/local/` 已在 `.gitignore` 中排除。
- `expect` 里可以填期望的端口转发条数和跳过条数，用来做断言。
- 没有 `local.json` 时，`test_local` 自动跳过，不影响其他测试。

目录结构：

- `agent/noobrouter_agent/`：后端，提供 HTTP API 并托管静态资源
- `web/`：前端
- `deploy/`：systemd unit、示例配置、打包和安装脚本

## 许可证

[MIT](LICENSE)
