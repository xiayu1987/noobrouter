import os
import tempfile
import time
import unittest
from unittest import mock

from noobrouter_agent import netinfo

LEASES = """1791331076 02:00:00:00:00:A1 192.168.50.186 tv 01:7c
1791344110 02:00:00:00:00:a2 192.168.50.137 * *
duid 00:01:00:01
"""
ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.50.186   0x1         0x0         02:00:00:00:00:a1     *        lan0
192.168.50.102   0x1         0x2         02:00:00:00:00:a3     *        lan0
192.168.50.9     0x1         0x2         00:00:00:00:00:00     *        lan0
"""
CT = ("ipv4     2 tcp      6 431991 ESTABLISHED src=192.168.50.157 dst=1.2.3.4 sport=46822 dport=443 "
      "src=1.2.3.4 dst=203.0.113.7 sport=443 dport=46822 [ASSURED] mark=0 zone=0 use=2\n"
      "ipv4     2 udp      17 4 src=192.168.50.157 dst=5.6.7.8 sport=8567 dport=53 "
      "src=5.6.7.8 dst=203.0.113.7 sport=53 dport=8567 [UNREPLIED] mark=0 zone=0 use=2\n")


def fake_read(files):
    return lambda path, default="": files.get(path, default)


class NetinfoTest(unittest.TestCase):
    def test_leases_skip_duid_and_star(self):
        with mock.patch.object(netinfo, "read", fake_read({"L": LEASES})):
            ls = netinfo.leases("L")
        self.assertEqual(len(ls), 2)
        self.assertEqual(ls[0]["mac"], "02:00:00:00:00:a1")
        self.assertEqual(ls[1]["hostname"], "")

    def test_devices_merge_and_sort(self):
        files = {"L": LEASES, "/proc/net/arp": ARP}
        with mock.patch.object(netinfo, "read", fake_read(files)):
            devs = netinfo.devices("L", [{"mac": "02:00:00:00:00:a2", "ip": "192.168.50.50", "name": "router2"}])
        self.assertEqual([d["ip"] for d in devs], ["192.168.50.50", "192.168.50.102", "192.168.50.186"])
        self.assertTrue(devs[0]["static"] and devs[0]["hostname"] == "router2")
        self.assertTrue(devs[1]["online"])
        self.assertFalse(devs[2]["online"])  # arp flag 0x0

    def test_connections(self):
        with mock.patch.object(netinfo, "read", fake_read({"/proc/net/nf_conntrack": CT})):
            c = netinfo.connections()
        self.assertEqual(c["items"][0]["state"], "ESTABLISHED")
        self.assertEqual(c["items"][0]["dport"], "443")
        self.assertEqual(c["items"][1]["state"], "")
        self.assertEqual(c["top_sources"], [{"ip": "192.168.50.157", "count": 2}])


if __name__ == "__main__":
    unittest.main()
