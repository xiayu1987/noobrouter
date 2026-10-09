"""Optional tests against YOUR router's real data. Skipped unless agent/tests/local.json exists.

local.json and fixtures/local/ are git-ignored: real interfaces, subnets and port forwards never
reach the repo. Copy local.example.json to local.json and fill it in (see the comments there).
"""
import json
import os
import unittest

from noobrouter_agent import config, firewall

HERE = os.path.dirname(__file__)
LOCAL = os.path.join(HERE, "local.json")


def _load():
    with open(LOCAL, encoding="utf-8") as f:
        data = json.load(f)
    data.pop("_comment", None)
    cfg = dict(config.DEFAULTS, **data.get("cfg", {}))
    path = os.path.join(HERE, data["iptables_save"])
    with open(path, encoding="utf-8") as f:
        return cfg, f.read(), data.get("expect", {})


@unittest.skipUnless(os.path.exists(LOCAL), "no agent/tests/local.json (private router data)")
class LocalRouterTest(unittest.TestCase):
    def setUp(self):
        self.cfg, self.saved, self.expect = _load()
        self.model, self.skipped = firewall.import_iptables_save(self.saved, self.cfg)

    def test_import_counts(self):
        if "forwards" in self.expect:
            self.assertEqual(len(self.model["forwards"]), self.expect["forwards"])
        if "skipped" in self.expect:
            self.assertEqual(len(self.skipped), self.expect["skipped"], self.skipped)

    def test_render_round_trip(self):
        # what the agent would apply validates against this router's config and re-imports cleanly
        norm = firewall.normalize(self.model, self.cfg)
        v4 = firewall.render_v4(norm, self.cfg)
        m2, sk = firewall.import_iptables_save(v4, self.cfg)
        self.assertEqual(sk, [])
        key = lambda f: (f["proto"], str(f["ext"]), f["ip"], str(f.get("int", "")))
        self.assertEqual(sorted(map(key, m2["forwards"])), sorted(map(key, norm["forwards"])))


if __name__ == "__main__":
    unittest.main()
