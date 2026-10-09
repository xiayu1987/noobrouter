"""JSON model storage in data_dir (single source of truth for managed config)."""
import json
import os

from . import applier, dhcp, firewall


def _path(cfg, name):
    return os.path.join(cfg["data_dir"], f"{name}.json")


def _load(cfg, name):
    p = _path(cfg, name)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save(cfg, name, model):
    # 0600: models carry LAN layout/forwards; pending init state also carries agent cfg
    applier._write(_path(cfg, name), json.dumps(model, ensure_ascii=False, indent=2), 0o600)


def firewall_model(cfg):
    """First run: import from the live ruleset (read-only) so nothing existing gets lost.
    Lines the importer does not understand are kept in firewall_import.json; apply is blocked
    while that list is non-empty, so a full-table replace can never silently drop them."""
    m = _load(cfg, "firewall")
    if m is None:
        live4, live6 = applier.current(cfg)
        m, skipped = firewall.import_iptables_save(live4, cfg)
        flags6, skipped6 = firewall.import_ip6tables_save(live6, cfg, m)
        m.update(flags6)
        skipped += [f"[IPv6] {s}" for s in skipped6]
        m = firewall.normalize(m, cfg)
        save(cfg, "firewall", m)
        save(cfg, "firewall_import", {"skipped": skipped, "acknowledged": not skipped})
    return m


def import_report(cfg):
    return _load(cfg, "firewall_import") or {"skipped": [], "acknowledged": True}


def acknowledge_import(cfg):
    r = import_report(cfg)
    r["acknowledged"] = True
    save(cfg, "firewall_import", r)
    return r


def dhcp_model(cfg):
    return _load(cfg, "dhcp") or dict(dhcp.EMPTY)
