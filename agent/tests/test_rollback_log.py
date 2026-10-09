"""Rollback log cap, snapshot pruning and confirm-time agent restart. No live iptables needed."""
import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from noobrouter_agent import applier, bootstrap, config


class LogCapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = dict(config.DEFAULTS, data_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_log_is_0600_and_capped_at_line_boundary(self):
        path = applier._paths(self.cfg)["last"] + ".log"
        with mock.patch.object(applier, "LOG_MAX", 1000):
            for i in range(200):
                applier.log(self.cfg, f"line {i:04d} " + "x" * 20)
                # _trim_log default arg is bound at def time: call with the patched cap explicitly
                applier._trim_log(path, 1000)
        self.assertLessEqual(os.path.getsize(path), 1000)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertTrue(all(" line " in x and x.endswith("x" * 20) for x in lines), "no partial lines kept")
        self.assertIn("line 0199", lines[-1])

    def test_trim_keeps_newest_half(self):
        path = os.path.join(self.tmp, "t.log")
        with open(path, "w") as f:
            f.write("".join(f"{i:05d}\n" for i in range(1000)))  # 6000 bytes
        applier._trim_log(path, 3000)
        with open(path) as f:
            data = f.read().splitlines()
        self.assertEqual(data[-1], "00999")
        self.assertLessEqual(len(data) * 6, 1500)

    def test_prune_keeps_newest_transactions(self):
        b = os.path.join(self.tmp, "backup")
        os.makedirs(b)
        ids = [f"20261007-0{i}0000-abcde{i}" for i in range(6)]
        for t in ids:
            for s in (".v4", ".v6"):
                open(os.path.join(b, t + s), "w").close()
            os.makedirs(os.path.join(b, t + ".files"))
            open(os.path.join(b, t + ".files", "0_x"), "w").close()
        open(os.path.join(b, "unrelated.txt"), "w").close()
        applier._prune_backups(b, 2)
        left = sorted(os.listdir(b))
        self.assertEqual({n.split(".")[0] for n in left if n != "unrelated.txt"}, set(ids[-2:]))
        self.assertIn("unrelated.txt", left)

    def test_rollback_script_caps_log_and_records_timeout(self):
        s = applier._rollback_script(self.cfg, "/b4", "/b6", "/p.json", "/d/last_rollback.json", "TX1")
        self.assertIn(f"-gt {applier.LOG_MAX} ]", s)
        self.assertIn(f"tail -c {applier.LOG_MAX // 2}", s)
        self.assertIn("rollback reason=timeout", s)
        # the cap check must run before stdout is redirected into the log
        self.assertLess(s.index("tail -c"), s.index("exec >>"))


class ScheduleRestartTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = dict(config.DEFAULTS, data_dir=self.tmp, listen="172.16.77.1")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _go(self, env, **cfg):
        calls = []
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(bootstrap, "has", return_value=True), \
                mock.patch.object(applier, "run", side_effect=lambda a, **k: calls.append(a) or ""):
            ok = bootstrap.schedule_restart(dict(self.cfg, **cfg))
        return ok, calls

    def test_under_systemd(self):
        ok, calls = self._go({"INVOCATION_ID": "abc"})
        self.assertTrue(ok)
        self.assertEqual(calls[0][0], "systemd-run")
        self.assertEqual(calls[0][-3:], ["systemctl", "restart", "noobrouter-agent.service"])

    def test_not_systemd_or_netns(self):
        self.assertEqual(self._go({}), (False, []))
        self.assertEqual(self._go({"INVOCATION_ID": "abc"}, netns="t")[1], [])

    def test_bad_unit_name_refused(self):
        self.assertEqual(self._go({"INVOCATION_ID": "abc"}, service_unit="x; reboot")[1], [])


if __name__ == "__main__":
    unittest.main()
