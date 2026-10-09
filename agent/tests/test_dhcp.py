import os
import shutil
import tempfile
import unittest

from noobrouter_agent import config, dhcp
from noobrouter_agent.shell import CmdError, has

CFG = dict(config.DEFAULTS)


class DhcpModelTest(unittest.TestCase):
    def test_reject_bad_input(self):
        bad = [
            {"static": [{"mac": "zz:00:00:00:00:00", "ip": "192.168.50.10"}]},
            {"static": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1"}]},
            {"static": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.50.10", "name": "bad name\nx"}]},
            {"static": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.50.10"},
                        {"mac": "AA-BB-CC-DD-EE-FF", "ip": "192.168.50.11"}]},
            {"records": [{"domain": "a/b", "ip": "1.1.1.1"}]},
            {"upstream": ["1.1.1.1\nport=0"]},
        ]
        for m in bad:
            with self.assertRaises(ValueError, msg=m):
                dhcp.normalize(m, CFG)

    def test_render(self):
        m = dhcp.normalize({"static": [{"mac": "AA-BB-CC-DD-EE-FF", "ip": "192.168.50.10", "name": "nas"}],
                            "records": [{"domain": "nas.lan.", "ip": "192.168.50.10"}],
                            "upstream": ["223.5.5.5"]}, CFG)
        out = dhcp.render(m)
        self.assertIn("dhcp-host=aa:bb:cc:dd:ee:ff,192.168.50.10,nas", out)
        self.assertIn("address=/nas.lan/192.168.50.10", out)
        self.assertIn("no-resolv\nserver=223.5.5.5", out)
        self.assertNotIn("no-resolv", dhcp.render(dhcp.normalize({}, CFG)))


@unittest.skipUnless(has("dnsmasq"), "dnsmasq not installed")
class DhcpApplyTest(unittest.TestCase):
    @staticmethod
    def _read(path):
        with open(path) as f:
            return f.read()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.confdir = os.path.join(self.tmp, "dnsmasq.d")
        os.makedirs(self.confdir)
        main = os.path.join(self.tmp, "dnsmasq.conf")
        with open(main, "w") as f:
            f.write("port=0\ndhcp-range=192.168.50.100,192.168.50.200,255.255.255.0,12h\n")
        self.cfg = dict(CFG, dry_run=False, data_dir=self.tmp, dnsmasq_main_conf=main,
                        dnsmasq_conf_dir=self.confdir, dnsmasq_service="")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_apply_then_bad_config_restores(self):
        good = dhcp.normalize({"static": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.50.10"}]}, self.cfg)
        dhcp.apply(good, self.cfg)
        path = os.path.join(self.confdir, "noobrouter.conf")
        before = self._read(path)
        bad = dict(good, records=[{"domain": "x", "ip": "not-an-ip"}])  # bypass normalize on purpose
        with self.assertRaises(CmdError):
            dhcp.apply(bad, self.cfg)
        self.assertEqual(self._read(path), before)
        self.assertEqual(sorted(os.listdir(self.confdir)), ["noobrouter.conf"])  # no stray files

    def test_dry_run_blocks(self):
        with self.assertRaises(CmdError):
            dhcp.apply(dhcp.normalize({}, CFG), dict(self.cfg, dry_run=True))


if __name__ == "__main__":
    unittest.main()
