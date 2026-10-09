"""Agent configuration: JSON file merged over defaults."""
import json
import os
import secrets

DEFAULTS = {
    "listen": "127.0.0.1",
    "port": 8090,
    "token": "",
    "wan_if": "ppp0",
    "wan_phy_if": "wan0",
    "lan_if": "lan0",
    "lan_cidr": "192.168.50.0/24",
    "data_dir": "/var/lib/noobrouter-agent",
    "web_root": "",
    # dry_run=True: never touches iptables/dnsmasq/ppp, only renders and validates
    "dry_run": True,
    "rollback_seconds": 90,
    "guard_ssh_port": 22,
    "dnsmasq_main_conf": "/etc/dnsmasq.conf",
    "dnsmasq_conf_dir": "/etc/dnsmasq.d",
    "dnsmasq_leases": "/var/lib/misc/dnsmasq.leases",
    "dnsmasq_service": "dnsmasq",
    "persist_v4": "/etc/iptables/rules.v4",
    "persist_v6": "/etc/iptables/rules.v6",
    "ppp_provider": "dsl-provider",
}


def load(path=None):
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    cfg["config_path"] = path or ""  # bootstrap rewrites the network keys here (same transaction)
    os.makedirs(cfg["data_dir"], exist_ok=True)
    if not cfg["token"]:
        cfg["token"] = _load_or_create_token(cfg["data_dir"])
    return cfg


def file_text(path, updates):
    """Config file content with `updates` merged over what is on disk (unknown keys kept)."""
    data = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    data.update(updates)
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def _load_or_create_token(data_dir):
    """Persist a random token in data_dir/token (0600) when none is configured."""
    path = os.path.join(data_dir, "token")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    token = secrets.token_urlsafe(24)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token)
    return token
