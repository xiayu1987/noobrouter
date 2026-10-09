# NoobRouter

English | [简体中文](README.zh-CN.md)

NoobRouter is a lightweight web console for Linux soft routers. The backend is an agent that depends only on the Python 3 standard library; the frontend is Vue 3 + Element Plus. The UI is available in English and Chinese.

## Features

- Overview: CPU, memory, WAN status, live traffic chart
- Network: interfaces, routing table, online devices (DHCP leases + ARP), connection tracking
- Firewall: port forwarding (DNAT), WAN open ports, security and forwarding options, import of existing rules, preview, and automatic rollback on timeout when applying
- DHCP / DNS: static leases and local DNS records, with conflict detection and preview
- Service status and logs, network diagnostics (ping, traceroute, DNS lookup)
- Setup wizard: turns a blank machine into a soft router; WAN supports PPPoE, DHCP and static addressing

## Supported systems

| System | Status |
| --- | --- |
| Debian 12 / 13 | Supported, tested |
| Ubuntu 22.04+ and other Debian-based distributions | Expected to work, untested |
| RHEL / CentOS / Fedora / Arch / Alpine, etc. | Setup and apply are not supported |

Full functionality depends on:

- systemd: service management and rollback timers (`systemd-run`)
- ifupdown: `/etc/network/interfaces`
- pppd, configured the pppoeconf way (`/etc/ppp/peers/*`)
- dnsmasq: DHCP and DNS
- iptables / ip6tables commands (`iptables-restore`); tested with the nf_tables backend (Debian default)
- apt: only used by `install.sh --with-deps`

Limitations:

- Systems with nftables only and no iptables commands cannot apply firewall rules. nftables-only features such as flowtable are shown as unavailable in the UI.
- When interfaces are managed by NetworkManager, netplan or systemd-networkd:
  - Firewall, DHCP and other pages work normally.
  - The setup wizard reports blockers or warnings that must be resolved first.
- Monitoring pages (status, devices, connections) only read `/proc` and the `ip` command. They likely work on other distributions but have not been verified.
- No HTTPS. Use only on a trusted LAN.

## Requirements

- Target: Python 3 (3.11 on Debian 12, 3.13 on Debian 13), root privileges
- Target download tools: any of curl, wget or python3, plus sha256sum and tar
- Building from source (optional): Linux or macOS, Node.js ≥ 20.19, Python 3, tar, sha256sum

## Quick start: one-step install on the router

Run as root on the router:

```sh
curl -fsSL https://github.com/xiayu1987/noobrouter/releases/latest/download/get.sh | sh -s -- --start
```

`get.sh` runs these steps in order and stops at the first failure:

1. Download `noobrouter-agent.tar.gz` and its `.sha256`.
2. Verify sha256; abort on mismatch.
3. Extract and run `install.sh` with the same options.
4. With `--start`, health check: the service is active and listening on the configured address.

It does not change existing configuration; `dry_run` keeps its current value. `install.sh` aborts if there are unconfirmed firewall or setup changes.

| Option | Description |
| --- | --- |
| `--start` | Start or restart the service after install, then health check |
| `--with-deps` | Install router packages with apt, see below |
| `--force` | Install even when unconfirmed changes exist |
| `NOOBROUTER_URL` (env var) | Download URL; defaults to the latest GitHub Release, can point to a mirror |

## Installing from source

```sh
cd web && npm ci && npm run build && cd ..
sh deploy/pack.sh          # produces dist/noobrouter-agent.tar.gz, .sha256, get.sh
# Copy noobrouter-agent.tar.gz to the router, then on the router:
tar xzf noobrouter-agent.tar.gz && sh noobrouter-agent-*/install.sh --start
```

What `install.sh` does:

- Installs the code to `/opt/noobrouter-agent` and registers the systemd service `noobrouter-agent`.
- Creates `/etc/noobrouter-agent.json` (mode 0600) on first install; an existing config is never overwritten.
- Does not touch the firewall, network or dnsmasq. Without `--start` it does not start or restart the service.
- Aborts while a change is unconfirmed (`fw/pending.json` or a `noobrouter-rollback` timer); confirm or roll back first, or pass `--force`.
- `--with-deps`: installs `iptables iptables-persistent dnsmasq ppp ifupdown iproute2 isc-dhcp-client`. A newly installed dnsmasq is left stopped until the setup wizard configures it.

## Configuration

The config file is `/etc/noobrouter-agent.json`. Run `systemctl restart noobrouter-agent` after editing.

| Key | Default | Description |
| --- | --- | --- |
| `listen` | `127.0.0.1` | Listen address. Set to the LAN IP for LAN access; never use a WAN address |
| `port` | `8090` | Listen port |
| `token` | empty | Login token. If empty, one is generated and saved to `/var/lib/noobrouter-agent/token` |
| `dry_run` | `true` | When true, only preview and validate; the system is not modified |
| `wan_if` | `ppp0` | WAN layer-3 interface; `ppp0` for PPPoE |
| `wan_phy_if` | `CHECK_ME` | WAN physical NIC, see `ip -br link` |
| `lan_if` | `CHECK_ME` | LAN NIC |
| `lan_cidr` | `192.168.1.0/24` | LAN subnet |
| `rollback_seconds` | `90` | Changes are rolled back automatically if not confirmed within this time |
| `guard_ssh_port` | `22` | SSH port always allowed by the guard rules |

First use:

1. Set `wan_phy_if`, `lan_if` and `lan_cidr`.
2. Change `listen` to the LAN IP and restart the service, or keep it and use an SSH tunnel: `ssh -L 8090:127.0.0.1:8090 root@<router>`.
3. Open `http://<listen>:<port>` in a browser and log in with the token.
4. With `dry_run: true`, check that every page looks right, then set it to `false` and restart the service.

## Security

- Access requires a Bearer token. Listen only on a LAN address or 127.0.0.1.
- Firewall rules are replaced atomically per table with `iptables-restore`. Built-in guard chains always allow established connections, the LAN and SSH.
- Every apply schedules a rollback timer with `systemd-run`. If not confirmed in time, the firewall and managed config files are restored.
- Before the first real apply, keep a second SSH session open, preferably from a local console or another link.
- Do not run the setup wizard on a router already in service. It takes over interfaces, dial-up and dnsmasq, and the network goes down while it runs. Use the Firewall, DHCP and other pages for day-to-day management.

## Setup wizard blockers

The wizard cannot apply while the preview reports any of the following; resolve them manually first:

- `/etc/network/interfaces` lacks `source /etc/network/interfaces.d/*`
- A selected NIC is already defined in `/etc/network/interfaces` or another `interfaces.d/` snippet, e.g. `50-cloud-init` generated by cloud-init
- A selected NIC is managed by NetworkManager; set `unmanaged-devices` in `/etc/NetworkManager/conf.d/`
- A selected NIC does not exist, or packages are missing (run `install.sh --with-deps`)
- The main `dnsmasq.conf` contains hand-written DHCP settings
- The existing firewall has rules the importer cannot recognize; confirm the import on the Firewall page first

netplan / systemd-networkd only produce warnings. Their config is backed up and moved aside during setup, and restored on rollback.

## Upgrading

Run the `get.sh` command from Quick start again on the router, or install the new package manually with `install.sh --start`. Config and token are preserved.

When upgrading from the old softroute-agent, `install.sh` migrates automatically:

- Config, data directory and token move to the new paths; the old config is kept as `/etc/softroute-agent.json.migrated`.
- System files written by the old setup wizard are only renamed, not modified, and network and dnsmasq are not reloaded.
- The upgrade aborts if the old version has unconfirmed changes; confirm or roll them back first.
- Pages already open in a browser need to log in again.

## Uninstalling

```sh
systemctl disable --now noobrouter-agent
rm -rf /opt/noobrouter-agent /etc/systemd/system/noobrouter-agent.service
systemctl daemon-reload
# If config and data are no longer needed:
rm -rf /etc/noobrouter-agent.json /var/lib/noobrouter-agent
```

Uninstalling does not revert firewall rules or dnsmasq config applied by the agent; they remain in `/etc/iptables/` and `/etc/dnsmasq.d/`.

## Development

```sh
cd web && npm ci && npm run dev                       # dev server, /api proxied to 127.0.0.1:18090
cd agent && python3 -m unittest discover -s tests    # unit tests
sudo sh agent/tests/smoke_http.sh                     # HTTP smoke test (reading iptables needs root)
sudo sh agent/tests/e2e_dist.sh                       # end-to-end test against web/dist (needs root)
sh deploy/rehearse_install.sh                         # pack + install rehearsal (PREFIX install, host untouched; init API check skipped when not root)
```

Local tests against your own router's data (never committed):

```sh
cp agent/tests/local.example.json agent/tests/local.json      # edit cfg for your NICs and subnet
mkdir -p agent/tests/fixtures/local
ssh root@<router> iptables-save > agent/tests/fixtures/local/iptables_save.txt
cd agent && python3 -m unittest tests.test_local -v
```

- `local.json` and `fixtures/local/` are excluded in `.gitignore`.
- `expect` can hold the expected forward and skipped counts to assert on.
- Without `local.json`, `test_local` is skipped and other tests are unaffected.

Layout:

- `agent/noobrouter_agent/`: backend, serves the HTTP API and static assets
- `web/`: frontend
- `deploy/`: systemd unit, example config, packaging and install scripts

## License

[MIT](LICENSE)
