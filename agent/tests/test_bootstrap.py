import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from noobrouter_agent import bootstrap  # noqa: E402
from noobrouter_agent.bootstrap import PlanError  # noqa: E402

BASE = {"wan": {"type": "pppoe", "if": "wan0", "user": "u123", "password": "p@ss"},
        "lan": {"if": "lan0", "address": "192.168.50.1/24"},
        "dhcp": {"enabled": True, "start": "192.168.50.100", "end": "192.168.50.200"}}


def plan(**over):
    p = {k: dict(v) for k, v in BASE.items()}
    for k, v in over.items():
        p[k] = v
    return p


class NormalizeTest(unittest.TestCase):
    def test_ok_defaults(self):
        n = bootstrap.normalize(plan())
        self.assertEqual(n["lan"]["cidr"], "192.168.50.0/24")
        self.assertEqual(n["wan"]["mtu"], 1492)
        self.assertEqual(n["dhcp"]["lease"], "12h")
        self.assertEqual(n["ssh_port"], 22)
        self.assertEqual(bootstrap.wan_if(n), "ppp0")

    def test_rejects(self):
        bad = [plan(wan={"type": "x", "if": "wan0"}),
               plan(wan={"type": "dhcp", "if": "lan0"}),                       # same NIC
               plan(wan={"type": "dhcp", "if": "en p1"}),                        # bad name
               plan(wan={"type": "pppoe", "if": "wan0", "user": "a b", "password": "x"}),
               plan(wan={"type": "pppoe", "if": "wan0", "user": "a", "password": 'x"y'}),
               plan(lan={"if": "lan0", "address": "8.8.8.1/24"}),              # public LAN
               plan(lan={"if": "lan0", "address": "192.168.50.0/24"}),         # network addr
               plan(dhcp={"enabled": True, "start": "192.168.50.1", "end": "192.168.50.9"}),  # router IP
               plan(dhcp={"enabled": True, "start": "10.0.0.2", "end": "10.0.0.9"}),
               plan(wan={"type": "static", "if": "wan0", "address": "192.168.50.9/24",
                         "gateway": "192.168.50.254"})]                        # overlap
        for p in bad:
            with self.assertRaises(PlanError, msg=p):
                bootstrap.normalize(p)

    def test_public_hides_password(self):
        n = bootstrap.normalize(plan())
        self.assertEqual(bootstrap.public(n)["wan"]["password"], "********")
        self.assertEqual(n["wan"]["password"], "p@ss")  # original untouched

    def test_agent_cfg_moves_listen_to_lan_ip(self):
        a = bootstrap.agent_cfg({"listen": "172.16.77.10"}, bootstrap.normalize(plan()))
        self.assertEqual(a["listen"], "192.168.50.1")
        self.assertIn("listen", bootstrap.AGENT_KEYS)


class RenderTest(unittest.TestCase):
    def test_ifaces_pppoe(self):
        t = bootstrap.render_ifaces(bootstrap.normalize(plan()))
        self.assertIn("iface lan0 inet static", t)
        self.assertIn("provider noobrouter", t)

    def test_sysctl_ipv6_toggle(self):
        on = bootstrap.render_sysctl(bootstrap.normalize(plan()))
        off = bootstrap.render_sysctl(bootstrap.normalize(plan(ipv6={"enabled": False})))
        self.assertIn("net.ipv4.ip_forward=1", off)
        self.assertIn("net.ipv6.conf.all.forwarding=1", on)
        self.assertNotIn("ipv6", off)

    def test_tuning_catalogue_and_old_plans(self):
        keys = [t["key"] for t in bootstrap.TUNING]
        self.assertEqual(len(keys), len(set(keys)))
        for t in bootstrap.TUNING:
            self.assertTrue(all("=" in s and " " not in s for s in t["sysctl"]), t["key"])
            if t["mandatory"]:
                self.assertTrue(t["default"], t["key"])
        # plan stored before the catalogue: no optional item, mandatory forwarding still there
        old = bootstrap.normalize(plan())
        self.assertEqual(set(old["tuning"]), set(bootstrap.TUNING_KEYS))
        self.assertFalse(any(old["tuning"].values()))
        t = bootstrap.render_sysctl(old)
        self.assertIn("net.ipv4.ip_forward=1", t)
        self.assertIn("net.ipv4.conf.all.rp_filter=2", t)
        self.assertNotIn("nf_conntrack", t)
        self.assertIsNone(bootstrap.render_modules(old))
        # mandatory keys can't be switched off from the plan, unknown keys are dropped
        n = bootstrap.normalize(plan(tuning={"forwarding": False, "evil": True}))
        self.assertNotIn("forwarding", n["tuning"])
        self.assertNotIn("evil", n["tuning"])
        self.assertIn("net.ipv4.ip_forward=1", bootstrap.render_sysctl(n))
        with self.assertRaises(PlanError):
            bootstrap.normalize(plan(tuning=["bbr"]))

    def test_tuning_selected_items(self):
        n = bootstrap.normalize(plan(tuning={"conntrack_max": True, "conntrack_timeout": True,
                                             "bbr": True, "mtu_probing": False}))
        t = bootstrap.render_sysctl(n)
        self.assertIn("net.netfilter.nf_conntrack_max=65536", t)
        self.assertIn("net.netfilter.nf_conntrack_tcp_timeout_established=7440", t)
        self.assertIn("net.ipv4.tcp_congestion_control=bbr", t)
        self.assertNotIn("tcp_mtu_probing", t)
        self.assertEqual(bootstrap.tuning_modules(n), ["nf_conntrack", "tcp_bbr"])
        self.assertEqual(bootstrap.render_modules(n).splitlines()[1:], ["nf_conntrack", "tcp_bbr"])
        only = bootstrap.normalize(plan(tuning={"mtu_probing": True}))
        self.assertIn("net.ipv4.tcp_mtu_probing=1", bootstrap.render_sysctl(only))
        self.assertEqual(bootstrap.tuning_modules(only), [])

    def test_dnsmasq(self):
        t = bootstrap.render_dnsmasq(bootstrap.normalize(plan()))
        self.assertIn("interface=lan0", t)
        self.assertIn("dhcp-range=192.168.50.100,192.168.50.200,255.255.255.0,12h", t)
        self.assertNotIn("server=", t)  # upstream lives only in noobrouter.conf

    def test_merge_secrets_keeps_others(self):
        old = '"other" * "secret" *\n"u0" * "old" *  # noobrouter-agent\n'
        t = bootstrap.merge_secrets(old, bootstrap.normalize(plan()))
        self.assertIn('"other" * "secret" *', t)
        self.assertNotIn('"old"', t)
        self.assertEqual(t.count("# noobrouter-agent"), 1)
        self.assertEqual(bootstrap.merge_secrets(old, bootstrap.normalize(
            plan(wan={"type": "dhcp", "if": "wan0"}))), '"other" * "secret" *\n')


class ConflictTest(unittest.TestCase):
    MAIN = ("source /etc/network/interfaces.d/*\nauto lo\niface lo inet loopback\n"
            "auto lan0\niface lan0 inet static\n    address 192.168.1.1/24\n")

    def test_detects_handwritten_lan(self):
        c = bootstrap.conflicts(self.MAIN, bootstrap.normalize(plan()))
        self.assertEqual([x["names"] for x in c if x["kind"] == "iface"], [["lan0"]])
        self.assertTrue(bootstrap._sources_dir(self.MAIN, "/etc/network/interfaces.d"))

    def test_clean_and_missing_source(self):
        clean = "auto lo\niface lo inet loopback\n"
        self.assertEqual(bootstrap.conflicts(clean, bootstrap.normalize(plan())), [])
        self.assertFalse(bootstrap._sources_dir(clean, "/etc/network/interfaces.d"))

    def test_cloud_init_fragment_blocks(self):
        env = {"interfaces_d": {"/etc/network/interfaces.d/50-cloud-init":
                                "auto lan0\niface lan0 inet dhcp\n"}}
        b, w = bootstrap.fragment_issues(env, bootstrap.normalize(plan()))
        self.assertEqual(len(b), 2)  # "auto lan0" and "iface lan0" stanzas
        self.assertTrue(all("50-cloud-init" in x for x in b))
        self.assertEqual(w, [])

    def test_netplan_and_networkd(self):
        env = {"netplan": {"/etc/netplan/50-cloud-init.yaml":
                           "network:\n  ethernets:\n    wan0:\n      dhcp4: true\n"},
               "networkd": True}
        b, w = bootstrap.fragment_issues(env, bootstrap.normalize(plan()))
        self.assertEqual(b, [])  # taken over inside the transaction, not a blocker any more
        self.assertEqual(len(w), 2)
        self.assertIn("wan0", w[0])
        clean = {"netplan": {"/etc/netplan/x.yaml": "network:\n  ethernets:\n    eth9: {}\n"}}
        self.assertEqual(bootstrap.fragment_issues(clean, bootstrap.normalize(plan())), ([], []))


class DetectExistingTest(unittest.TestCase):
    """Typical layout: pppoeconf dsl-provider on wan0, LAN lan0 owned by NetworkManager."""
    MAIN = ("source /etc/network/interfaces.d/*\nauto lo\niface lo inet loopback\n"
            "auto dsl-provider\niface dsl-provider inet ppp\n"
            "pre-up /bin/ip link set wan0 up # line maintained by pppoeconf\n"
            "provider dsl-provider\n\nauto wan0\niface wan0 inet manual\niface wan0 inet6 auto\n")
    PEERS = ('# pppoeconf\nnoipdefault\ndefaultroute\nhide-password\nnoauth\npersist\nmaxfail 0\n'
             'plugin rp-pppoe.so nic-wan0\nuser "pppoe-user01"\nusepeerdns\n')
    NICS = [{"name": "wan0"}, {"name": "lan0"}]
    NM = [{"if": "lan0", "uuid": "00000000-0000-4000-8000-000000000001", "method": "manual",
           "addresses": ["192.168.50.1/24"]}]

    def test_parse_peers(self):
        self.assertEqual(bootstrap.parse_peers(self.PEERS),
                         {"plugin": "rp-pppoe.so", "nic": "wan0", "user": "pppoe-user01"})
        p = bootstrap.parse_peers("plugin /usr/lib/pppd/2.4.9/pppoe.so\nnic-eth0\nmtu 1480\nuser u1\n")
        self.assertEqual(p, {"plugin": "pppoe.so", "nic": "eth0", "mtu": 1480, "user": "u1"})

    def _detect(self, nm, main=None, chap=""):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(root + "/etc/ppp/peers")
            with open(root + "/etc/ppp/peers/dsl-provider", "w") as f:
                f.write(self.PEERS)
            with open(root + "/etc/ppp/chap-secrets", "w") as f:
                f.write(chap)
            return bootstrap.detect_existing({"sysroot": root}, main or self.MAIN, {}, self.NICS, nm)

    def test_legacy_router_layout(self):
        d = self._detect(self.NM)
        self.assertEqual(d["wan"], {"type": "pppoe", "if": "wan0", "user": "pppoe-user01", "mtu": 1492,
                                    "password": "", "source": "/etc/ppp/peers/dsl-provider"})
        self.assertEqual((d["lan"]["if"], d["lan"]["address"], d["lan"]["nm_uuid"]),
                         ("lan0", "192.168.50.1/24", self.NM[0]["uuid"]))
        self.assertEqual([p["name"] for p in d["providers"]], ["dsl-provider"])
        chap = '# Secrets\n"other" * "x1"\n"pppoe-user01" * "s3cr-et" # pppoeconf\n'
        self.assertEqual(self._detect(self.NM, chap=chap)["wan"]["password"], "s3cr-et")

    def test_read_secret(self):
        rs = bootstrap.read_secret
        self.assertEqual(rs(['u1 * p1\n'], "u1"), "p1")
        self.assertEqual(rs(['# u1 * p1\nu2 * p2 *\n'], "u1"), "")  # commented out / other user
        self.assertEqual(rs(['', '"u1" * "p 2"\nu1 * p3\n'], "u1"), "p3")  # pap fallback; bad cred skipped
        self.assertEqual(rs(['u1 * "unterminated\n'], "u1"), "")

    def test_ifupdown_lan_fallback(self):
        main = self.MAIN + "auto lan0\niface lan0 inet static\n    address 192.168.5.1/24\n"
        self.assertEqual(self._detect([], main)["lan"]["address"], "192.168.5.1/24")
        self.assertIsNone(self._detect([])["lan"])

    def test_nm_and_ppp_conflicts(self):
        p = bootstrap.normalize(plan())
        b, w = bootstrap.nm_issues({"network_manager": True, "nm_devices": self.NM}, p)
        self.assertEqual(len(b), 1)
        self.assertIn("lan0", b[0])
        self.assertIn(self.NM[0]["uuid"], b[0])
        self.assertEqual(w, [])
        b, w = bootstrap.nm_issues({"network_manager": True, "nm_devices": []}, p)
        self.assertEqual((b, len(w)), ([], 1))
        self.assertEqual(bootstrap.nm_issues({"network_manager": False}, p), ([], []))
        hits = {tuple(c["names"]) for c in bootstrap.conflicts(self.MAIN, p)}
        self.assertIn(("dsl-provider",), hits)  # a second pppd on wan0
        self.assertIn(("wan0",), hits)
        # "iface wan0 inet manual" + "iface wan0 inet6 auto" -> one blocker, not two
        msgs = bootstrap.conflict_blockers(bootstrap.conflicts(self.MAIN, p))
        self.assertEqual(len(msgs), len(set(msgs)))
        self.assertEqual(sum("iface wan0" in m for m in msgs), 1)


class ServiceStepsTest(unittest.TestCase):
    def test_netplan_renames(self):
        y = ("# generated\nnetwork:\n    ethernets:\n        lan:\n            addresses:\n"
             "            - 172.16.77.10/24\n            match:\n                macaddress: 00:15:5D:77:00:02\n"
             "            set-name: eth1\n        wan:\n            dhcp4: true\n            match:\n"
             "                macaddress: 00:15:5d:77:00:01\n            set-name: eth0\n        plain:\n"
             "            dhcp4: true\n    version: 2\n")
        self.assertEqual(bootstrap.netplan_renames(y), {"eth1": "00:15:5d:77:00:02", "eth0": "00:15:5d:77:00:01"})
        self.assertIn("Name=eth0", bootstrap.render_link("eth0", "00:15:5d:77:00:01"))

    CFG = {"dnsmasq_main_conf": "/etc/dnsmasq.conf", "dnsmasq_conf_dir": "/etc/dnsmasq.d",
           "dnsmasq_service": "dnsmasq"}

    def test_restores_original_enablement(self):
        p = bootstrap.normalize(plan(wan={"type": "dhcp", "if": "wan0"}))
        env = {"svc_enabled": {"dnsmasq": "enabled", "netfilter-persistent": "enabled"}}
        pre, post, undo = bootstrap.service_steps(self.CFG, p, env, False)
        self.assertEqual(pre, [])  # networkd absent: never touched
        self.assertIn(["systemctl", "restart", "dnsmasq"], undo)
        self.assertNotIn(["systemctl", "disable", "netfilter-persistent"], undo)
        wan = post[-1][2]
        self.assertIn("ifdown --force wan0; /sbin/ip link set wan0 up;", wan)
        self.assertIn(f"timeout {bootstrap.WAN_UP_TIMEOUT} ifup --force wan0 || dhclient -4 -nw", wan)
        self.assertLess(bootstrap.WAN_UP_TIMEOUT, 60)  # applier runs post steps with a 60s limit
        env = {"svc_enabled": {"dnsmasq": "disabled", "netfilter-persistent": "disabled"}}
        _, _, undo = bootstrap.service_steps(self.CFG, p, env, False)
        self.assertIn(["systemctl", "disable", "--now", "dnsmasq"], undo)
        self.assertIn(["systemctl", "disable", "netfilter-persistent"], undo)

    def test_networkd_taken_over_and_restored(self):
        p = bootstrap.normalize(plan(wan={"type": "dhcp", "if": "wan0"}))
        env = {"networkd": True, "networkd_enabled": {"systemd-networkd": "enabled",
                                                       "systemd-networkd.socket": "enabled",
                                                       "systemd-networkd-wait-online": "disabled"}}
        pre, _, undo = bootstrap.service_steps(self.CFG, p, env, True)
        self.assertEqual(pre, [["systemctl", "disable", "--now", *bootstrap.NETWORKD_UNITS]])
        flat = [" ".join(a) for a in undo]
        i_wan = next(i for i, s in enumerate(flat) if "ifdown --force wan0" in s)
        i_gen = next(i for i, s in enumerate(flat) if "netplan generate" in s)
        self.assertLess(i_wan, i_gen)  # our lease released before networkd comes back
        self.assertIn(["systemctl", "enable", "systemd-networkd.socket", "systemd-networkd"], undo)
        self.assertEqual(undo[-1], ["systemctl", "start", "systemd-networkd"])

    def test_netplan_takeover_files(self):
        env = {"netplan": {"/etc/netplan/50-cloud-init.yaml": "ethernets:\n  lan0:\n    dhcp4: true\n",
                           "/etc/netplan/90-other.yaml": "ethernets:\n  eth9: {}\n"}}
        self.assertEqual(bootstrap.netplan_takeover(env, bootstrap.normalize(plan())),
                         {"/etc/netplan/50-cloud-init.yaml": ["lan0"]})

    def test_static_wan_no_dhclient_fallback(self):
        p = bootstrap.normalize(plan(wan={"type": "static", "if": "wan0",
                                          "address": "203.0.113.2/24", "gateway": "203.0.113.1"}))
        _, post, _ = bootstrap.service_steps(self.CFG, p, {}, False)
        self.assertIn("ifup --force wan0 || true", post[-1][2])
        self.assertNotIn("dhclient", post[-1][2])

    def test_wan_steps_run_outside_agent_unit(self):
        p = bootstrap.normalize(plan(wan={"type": "dhcp", "if": "wan0"}))
        env = {"has": {"systemd-run": True}}
        _, post, undo = bootstrap.service_steps(self.CFG, p, env, False)
        wan = post[-1][2]
        self.assertIn("systemd-run --wait --collect --quiet -p Type=oneshot -p KillMode=process", wan)
        self.assertIn("/bin/sh -c 'ifdown --force wan0;", wan)
        self.assertTrue(any("systemd-run" in a[2] and "kill $(cat /run/dhclient.wan0.pid)" in a[2]
                            for a in undo if a[0] == "/bin/sh"))
        pp = bootstrap.normalize(plan())
        _, post, _ = bootstrap.service_steps(self.CFG, pp, env, False)
        self.assertIn("systemd-run", post[-1][2])
        self.assertIn("pon noobrouter", post[-1][2])

    def test_reinit_undo_brings_previous_wan_back(self):
        p = bootstrap.normalize(plan(wan={"type": "dhcp", "if": "wan0"}))
        _, _, undo = bootstrap.service_steps(self.CFG, p, {}, False)
        wan = next(a[2] for a in undo if a[0] == "/bin/sh" and "ifdown --force wan0" in a[2])
        # stop ours first, then re-up only if the restored config still manages the NIC
        self.assertLess(wan.index("kill $(cat"), wan.index("ifquery --list"))
        self.assertIn("grep -qx wan0; then /sbin/ip link set wan0 up; timeout", wan)
        _, _, undo = bootstrap.service_steps(self.CFG, bootstrap.normalize(plan()), {}, False)
        ppp = next(a[2] for a in undo if a[0] == "/bin/sh" and "poff noobrouter" in a[2])
        self.assertIn("grep -qx noobrouter; then ip link set wan0 up; pon noobrouter; fi", ppp)


class WanLinkUpTest(unittest.TestCase):
    def test_pre_up_for_dhcp_and_static(self):
        dh = bootstrap.render_ifaces(bootstrap.normalize(plan(wan={"type": "dhcp", "if": "wan0"})))
        self.assertIn("iface wan0 inet dhcp\n    pre-up /sbin/ip link set wan0 up\n", dh)
        st = bootstrap.render_ifaces(bootstrap.normalize(plan(wan={
            "type": "static", "if": "wan0", "address": "203.0.113.2/24", "gateway": "203.0.113.1"})))
        self.assertIn("    pre-up /sbin/ip link set wan0 up\n", st)


if __name__ == "__main__":
    unittest.main()
