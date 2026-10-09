import os
import re
import unittest

from noobrouter_agent import config, firewall
from noobrouter_agent.firewall import ValidationError

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "router_iptables_save.txt")
CFG = dict(config.DEFAULTS)


def dnat_set(text):
    """Semantic DNAT set: (proto, dport, target) ignoring order/whitespace."""
    out = set()
    for m in re.finditer(r"-A PREROUTING -p (\w+) -m \w+ --dport (\S+).*?--to-destination (\S+)", text):
        out.add(m.groups())
    return out


def input_accept_set(text):
    return set(re.findall(r"-A INPUT -p (\w+) -m \w+ --dport (\S+) -j ACCEPT", text))


class FirewallTest(unittest.TestCase):
    def setUp(self):
        with open(FIX, encoding="utf-8") as f:
            self.saved = f.read()
        self.model, self.skipped = firewall.import_iptables_save(self.saved, CFG)

    def test_forward_filter_render_and_import(self):
        # fixture router has no FORWARD filter: importing keeps it off (no behaviour change)
        self.assertFalse(self.model["forward_filter"])
        on = firewall.normalize(dict(self.model, forward_filter=True), CFG)
        v4 = firewall.render_v4(on, CFG)
        self.assertIn(f"-A FORWARD -i {CFG['wan_if']} -m conntrack --ctstate DNAT -j ACCEPT", v4)
        self.assertIn(f"-A FORWARD -i {CFG['wan_if']} -j DROP", v4)
        self.assertNotIn(f"-A FORWARD -i {CFG['wan_if']}", firewall.render_v4(self.model, CFG).split("*nat")[0])
        # our own guard round-trips; foreign FORWARD rules are reported, not silently dropped
        m2, sk = firewall.import_iptables_save(v4, CFG)
        self.assertTrue(m2["forward_filter"])
        self.assertEqual(sk, [])
        _, sk = firewall.import_iptables_save(
            "*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -i wg0 -j ACCEPT\nCOMMIT\n", CFG)
        self.assertEqual(sk, ["-A FORWARD -i wg0 -j ACCEPT"])
        self.assertTrue(firewall.normalize({}, CFG)["forward_filter"])  # new model: on

    def test_import_keeps_all_forwards(self):
        self.assertEqual(len(self.model["forwards"]), 10)
        # the legacy mt_rtr_4_m_rtr chain is never jumped to: reported (apply needs ack), not kept
        self.assertEqual(len(self.skipped), 4)
        self.assertTrue(all(s.startswith("-A mt_rtr_4_m_rtr") and "从未生效" in s for s in self.skipped))
        self.assertTrue(self.model["lan_masquerade"] and self.model["mss_clamp"])

    def test_import_only_enables_what_is_live(self):
        # fixture router: only MSS clamp + hairpin; new optimisations must not appear unconfirmed
        for k in ("drop_new_not_syn", "drop_bad_flags", "syn_flood", "forward_filter", "mss_clamp_v6"):
            self.assertFalse(self.model[k], k)
        self.assertTrue(self.model["drop_invalid"])  # mandatory
        self.assertEqual(firewall.import_iptables_save("", CFG)[0], firewall.EMPTY_MODEL)  # blank box

    def test_import_v6_legacy_mangle_sanity(self):
        # legacy router: ip6tables-save has no *filter; sanity drops live in mangle via mt_rtr_6_m_rtr
        live6 = ("*mangle\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n"
                 ":OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n:mt_rtr_6_m_rtr - [0:0]\n"
                 "-A FORWARD -j mt_rtr_6_m_rtr\n"
                 "-A mt_rtr_6_m_rtr -o ppp0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n"
                 "-A mt_rtr_6_m_rtr -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
                 "-A mt_rtr_6_m_rtr -m conntrack --ctstate INVALID -j DROP\n"
                 "-A mt_rtr_6_m_rtr -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j DROP\n"
                 "-A mt_rtr_6_m_rtr -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP\n"
                 "-A mt_rtr_6_m_rtr -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP\n"
                 "-A mt_rtr_6_m_rtr -i br_lan -o ppp0 -j ACCEPT\nCOMMIT\n"
                 "*nat\n:POSTROUTING ACCEPT [0:0]\n:mt_rtr_6_n_rtr - [0:0]\n-A POSTROUTING -j mt_rtr_6_n_rtr\n"
                 "-A mt_rtr_6_n_rtr -o ppp0 -j MASQUERADE\nCOMMIT\n")
        flags, sk = firewall.import_ip6tables_save(live6, CFG, self.model)
        self.assertEqual(sk, [])
        self.assertTrue(flags["drop_new_not_syn"] and flags["drop_bad_flags"] and flags["mss_clamp_v6"])
        self.assertFalse(flags["ipv6_filter"])
        # the protection survives a full-table replace: rendered into v6 filter FORWARD
        m = firewall.normalize(dict(self.model, **flags), CFG)
        fwd = [l for l in firewall.render_v6(m, CFG).splitlines() if l.startswith("-A FORWARD")]
        for body in (firewall.INVALID_BODY, firewall.NEW_NOT_SYN_BODY) + firewall.BAD_FLAGS_BODIES:
            self.assertIn(f"-A FORWARD {body}", fwd)

    def test_mandatory_and_legacy_model(self):
        n = firewall.normalize({"drop_invalid": False, "guard_rules": False, "forwards": []}, CFG)
        self.assertTrue(n["drop_invalid"] and n["guard_rules"])
        # model saved before syn_flood existed: stays off until the user ticks it
        old = firewall.normalize({"mss_clamp": True, "lan_masquerade": True, "forward_filter": True}, CFG)
        self.assertFalse(old["syn_flood"] or old["drop_new_not_syn"] or old["mss_clamp_v6"])
        self.assertTrue(firewall.normalize({}, CFG)["syn_flood"])  # fresh model gets defaults
        self.assertEqual({o["key"] for o in firewall.OPTIONS if o["mandatory"]}, firewall.MANDATORY)

    def test_legacy_state_match_and_dup_mss(self):
        txt = ("*filter\n-A FORWARD -m state --state INVALID -j DROP\nCOMMIT\n*mangle\n"
               "-A FORWARD -o ppp0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1400:65495 -j TCPMSS --clamp-mss-to-pmtu\n"
               "-A FORWARD -o ppp0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1400:65495 -j TCPMSS --clamp-mss-to-pmtu\n"
               "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\nCOMMIT\n")
        m, sk = firewall.import_iptables_save(txt, CFG)
        self.assertEqual(sk, [])
        self.assertTrue(m["mss_clamp"])
        self.assertEqual(firewall.render_v4(firewall.normalize(m, CFG), CFG).count("TCPMSS"), 1)

    def test_render_options(self):
        full = firewall.normalize({}, CFG)
        v4 = firewall.render_v4(full, CFG)
        inp = [l for l in v4.splitlines() if l.startswith("-A INPUT")]
        self.assertLess(inp.index("-A INPUT -m conntrack --ctstate INVALID -j DROP"),
                        inp.index(f"-A INPUT -i {CFG['lan_if']} -j ACCEPT"))
        self.assertIn(":syn_flood - [0:0]", v4)
        self.assertNotIn("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", inp)  # new model: SSH LAN-only
        wan_ssh = [l for l in firewall.render_v4(dict(full, ssh_wan=True), CFG).splitlines() if l.startswith("-A INPUT")]
        self.assertLess(wan_ssh.index("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"),
                        next(i for i, l in enumerate(wan_ssh) if "syn_flood" in l))  # SSH guard never rate-limited
        self.assertIn(f"-s {CFG['lan_cidr']} -d {CFG['lan_cidr']} -o {CFG['lan_if']} -j MASQUERADE", v4)
        off = firewall.normalize({k: False for k in firewall.BOOL_KEYS}, CFG)
        r = firewall.render_v4(off, CFG)
        for s in ("syn_flood", "TCPMSS", "--tcp-flags FIN,SYN,RST,PSH,ACK,URG", "! --tcp-flags"):
            self.assertNotIn(s, r)
        self.assertIn("--ctstate INVALID -j DROP", r)  # mandatory survives "all off"
        m6, sk6 = firewall.import_ip6tables_save(firewall.render_v6(full, CFG), CFG, full)
        self.assertEqual(sk6, [])
        self.assertTrue(m6["mss_clamp_v6"])

    def test_roundtrip_preserves_dnat_and_open_ports(self):
        rendered = firewall.render_v4(firewall.normalize(self.model, CFG), CFG)
        self.assertEqual(dnat_set(rendered), dnat_set(self.saved))
        # every port open before is still open after (SSH via guard rule)
        self.assertTrue(input_accept_set(self.saved) <= input_accept_set(rendered))

    def test_guard_rules_first_and_drop_last(self):
        rendered = firewall.render_v4(firewall.normalize(self.model, CFG), CFG)
        inp = [l for l in rendered.splitlines() if l.startswith("-A INPUT")]
        self.assertEqual(inp[0], "-A INPUT -i lo -j ACCEPT")
        self.assertIn("--ctstate RELATED,ESTABLISHED", inp[1])
        self.assertEqual(inp[2], "-A INPUT -m conntrack --ctstate INVALID -j DROP")  # mandatory
        # fixture router: SSH open on every NIC, no blanket LAN accept -> kept as is, LAN keeps its services
        self.assertTrue(self.model["ssh_wan"])
        self.assertFalse(self.model["lan_accept_all"])
        self.assertEqual(inp[3], "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT")
        self.assertEqual(inp[4], f"-A INPUT -i lan0 -p tcp -m tcp --dport {CFG['port']} -j ACCEPT")
        self.assertIn("-A INPUT -i lan0 -p udp -m udp --dport 67 -j ACCEPT", inp)
        self.assertNotIn("-A INPUT -i lan0 -j ACCEPT", inp)
        self.assertEqual(inp[-1], "-A INPUT -j DROP")
        self.assertEqual(rendered.count("TCPMSS"), 1)
        self.assertNotIn("br_lan", rendered)

    def test_restricted_accept_roundtrip(self):
        # the rule added by hand on 192.168.50.1 (iptables-save canonical order)
        rule = "-A INPUT -s 192.168.50.0/24 -i lan0 -p tcp -m tcp --dport 11111 -j ACCEPT"
        saved = self.saved.replace("-A INPUT -j DROP", rule + "\n-A INPUT -j DROP")
        m, sk = firewall.import_iptables_save(saved, dict(CFG, port=11111))
        self.assertNotIn(rule, sk)
        self.assertIn({"proto": "tcp", "port": "11111", "comment": "", "iface": "lan0",
                       "src": "192.168.50.0/24"}, m["wan_open"])
        r = firewall.render_v4(firewall.normalize(m, dict(CFG, port=11111)), dict(CFG, port=11111))
        self.assertIn(rule, r)
        self.assertNotIn("-A INPUT -p tcp -m tcp --dport 11111 -j ACCEPT", r)  # never widened
        self.assertNotIn("11111", firewall.render_v6(dict(firewall.normalize(m, CFG), ipv6_filter=True), CFG)
                         .split("--dport 546")[1])  # v4 source net has no v6 rule
        # our own render round-trips in both guard modes, nothing skipped
        for la, sw in ((True, True), (False, False), (False, True), (True, False)):
            full = firewall.normalize(dict(m, lan_accept_all=la, ssh_wan=sw), CFG)
            m2, sk2 = firewall.import_iptables_save(firewall.render_v4(full, CFG), CFG)
            self.assertEqual(sk2, [], (la, sw))
            self.assertEqual((m2["lan_accept_all"], m2["ssh_wan"]), (la, sw))
            self.assertEqual(len(m2["wan_open"]), len(full["wan_open"]))
            _, sk6 = firewall.import_ip6tables_save(firewall.render_v6(dict(full, ipv6_filter=True), CFG), CFG, m2)
            self.assertEqual(sk6, [], (la, sw))
        # stored model from before these options: old behaviour (LAN all + SSH everywhere) kept
        old = firewall.normalize({"mss_clamp": True, "forwards": []}, CFG)
        self.assertTrue(old["lan_accept_all"] and old["ssh_wan"])
        for bad in ({"iface": "eth0;x"}, {"src": "nope"}, {"src": "fd00::/8"}):
            with self.assertRaises(ValidationError):
                firewall.normalize({"wan_open": [dict({"proto": "tcp", "port": "80"}, **bad)]}, CFG)

    def test_validation(self):
        bad = [
            {"proto": "tcp", "ext": "20022", "ip": "10.0.0.5", "int": "22"},          # outside LAN
            {"proto": "tcp", "ext": "21:23", "ip": "192.168.50.5", "int": "21:23"},   # covers SSH
            {"proto": "tcp", "ext": "100-200", "ip": "192.168.50.5", "int": "100-150"},
            {"proto": "icmp", "ext": "1", "ip": "192.168.50.5"},
            {"proto": "tcp", "ext": "1; rm -rf /", "ip": "192.168.50.5"},
        ]
        for f in bad:
            with self.assertRaises(ValidationError, msg=f):
                firewall.normalize({"forwards": [f]}, CFG)
        with self.assertRaises(ValidationError):
            firewall.normalize({"forwards": [
                {"proto": "both", "ext": "80", "ip": "192.168.50.5"},
                {"proto": "tcp", "ext": "80", "ip": "192.168.50.6"}]}, CFG)

    def test_both_proto_and_lint(self):
        m = firewall.normalize({"forwards": [{"proto": "both", "ext": "8080", "ip": "192.168.50.5", "int": "80"}]}, CFG)
        r = firewall.render_v4(m, CFG)
        self.assertIn("-p tcp -m tcp --dport 8080 -j DNAT --to-destination 192.168.50.5:80", r)
        self.assertIn("-p udp -m udp --dport 8080 -j DNAT --to-destination 192.168.50.5:80", r)
        msgs = " ".join(t["msg"] for t in firewall.lint(self.model, CFG))
        self.assertIn("53", msgs)
        self.assertIn("445", msgs)

    def test_v6_filter_allows_icmpv6(self):
        r = firewall.render_v6(dict(firewall.EMPTY_MODEL, ipv6_filter=True), CFG)
        self.assertLess(r.index("ipv6-icmp"), r.index("-A INPUT -j DROP"))
        self.assertLess(r.index("-A INPUT -p ipv6-icmp"), r.index("--ctstate INVALID"))  # ND/RA before INVALID
        off = firewall.render_v6(firewall.EMPTY_MODEL, CFG)
        self.assertNotIn("-A INPUT", off)
        self.assertNotIn("-j DROP\n-A FORWARD -i", off)
        self.assertIn("TCPMSS", off.split("*mangle")[1])


if __name__ == "__main__":
    unittest.main()
