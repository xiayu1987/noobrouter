"""API write-endpoint guards. No live iptables/dnsmasq: live state is stubbed."""
import shutil
import tempfile
import unittest
from unittest import mock

from noobrouter_agent import api, applier, config, netinfo, store

FWD = {"name": "smb", "proto": "tcp", "ext": "21005", "ip": "192.168.50.30", "int": "445", "enabled": True}
STATIC = {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.50.10", "name": "nas"}


class ApiWriteGuardTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = dict(config.DEFAULTS, data_dir=self.dir, token="t", dry_run=True)
        store.save(self.cfg, "firewall", {"forwards": [FWD], "wan_open": []})
        store.save(self.cfg, "dhcp", {"static": [STATIC], "records": [], "upstream": []})
        self.p = [mock.patch.object(applier, "current", return_value=("", "")),
                  mock.patch.object(netinfo, "devices", return_value=[])]
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()
        shutil.rmtree(self.dir)

    def assertApiError(self, fn, body, status):
        with self.assertRaises(api.ApiError) as cm:
            fn(self.cfg, body, {})
        self.assertEqual(cm.exception.status, status)
        return cm.exception

    def test_fw_save_rejects_missing_or_empty_model(self):
        self.assertApiError(api.fw_save, {}, 400)
        self.assertApiError(api.fw_save, {"model": {}}, 400)
        self.assertApiError(api.fw_save, {"model": "x"}, 400)
        self.assertEqual(store.firewall_model(self.cfg)["forwards"][0]["ext"], "21005")

    def test_fw_save_wiping_forwards_needs_allow_empty(self):
        e = self.assertApiError(api.fw_save, {"model": {"forwards": []}}, 409)
        self.assertEqual(e.code, "allow_empty")  # the UI keys its "confirm wipe" dialog on this
        self.assertEqual(len(store.firewall_model(self.cfg)["forwards"]), 1)
        api.fw_save(self.cfg, {"model": {"forwards": []}, "allow_empty": True}, {})
        self.assertEqual(store.firewall_model(self.cfg)["forwards"], [])

    def test_fw_get_returns_normalized_model(self):
        from noobrouter_agent import firewall
        # legacy stored model: predates the option catalogue
        store.save(self.cfg, "firewall", {"forwards": [FWD], "wan_open": [], "mss_clamp": True})
        r = api.fw_get(self.cfg, {}, {})
        m = r["model"]
        for k in firewall.BOOL_KEYS:
            self.assertIsInstance(m[k], bool, k)
        self.assertTrue(m["guard_rules"] and m["drop_invalid"])
        self.assertTrue(m["mss_clamp"])
        self.assertFalse(m["syn_flood"])  # new option stays off on upgrade
        self.assertEqual([o["key"] for o in r["options"]], list(firewall.BOOL_KEYS))

    def test_fw_save_ok(self):
        f2 = dict(FWD, ext="20006")
        r = api.fw_save(self.cfg, {"model": {"forwards": [FWD, f2]}}, {})
        self.assertEqual(len(r["model"]["forwards"]), 2)

    def test_fw_apply_blocked_until_import_acknowledged(self):
        store.save(self.cfg, "firewall_import", {"skipped": ["-A X -j Y"], "acknowledged": False})
        self.assertApiError(api.fw_apply, {}, 409)
        api.fw_ack_import(self.cfg, {}, {})
        self.assertTrue(store.import_report(self.cfg)["acknowledged"])

    def test_fw_apply_empty_model_guard_before_dry_run(self):
        self.assertApiError(api.fw_apply, {"model": {}}, 400)
        self.assertApiError(api.fw_apply, {"model": {"forwards": []}}, 409)

    def test_dhcp_apply_guards(self):
        self.assertApiError(api.dhcp_apply, {}, 400)
        self.assertApiError(api.dhcp_apply, {"model": {"upstream": ["223.5.5.5"]}}, 409)
        self.assertApiError(api.dhcp_apply, {"model": {"static": [dict(STATIC, mac="zz")]}}, 400)
        r = api.dhcp_apply(self.cfg, {"model": {"static": [STATIC], "upstream": ["223.5.5.5"]}}, {})
        self.assertFalse(r["applied"])  # dry_run: render only
        self.assertIn("223.5.5.5", r["render"])
        self.assertEqual(store.dhcp_model(self.cfg)["upstream"], [])  # not saved in dry_run

    def test_dhcp_conflict_normalizes_mac(self):
        with mock.patch.object(netinfo, "devices", return_value=[
                {"ip": "192.168.50.10", "mac": "AA:BB:CC:DD:EE:01", "hostname": "nas"},
                {"ip": "192.168.50.11", "mac": "aa:bb:cc:dd:ee:99", "hostname": "pc"}]):
            m = {"static": [STATIC, {"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.50.11"}]}
            r = api.dhcp_apply(self.cfg, {"model": m}, {})
        self.assertFalse(r["applied"])
        self.assertEqual(len(r["warnings"]), 1)
        self.assertIn("192.168.50.11", r["warnings"][0])

    def test_int_param(self):
        with self.assertRaises(api.ApiError):
            api._int({"limit": "abc"}, "limit", 1, 1, 10)
        self.assertEqual(api._int({"limit": "99"}, "limit", 1, 1, 10), 10)


if __name__ == "__main__":
    unittest.main()
