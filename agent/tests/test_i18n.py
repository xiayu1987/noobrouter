import os
import re
import unittest

from noobrouter_agent import bootstrap, config, firewall, i18n

CJK = re.compile(r"[\u4e00-\u9fff]")
CFG = dict(config.DEFAULTS)
FIX = os.path.join(os.path.dirname(__file__), "fixtures", "router_iptables_save.txt")


def en(data):
    return i18n.translate(data, "en")


class LangTest(unittest.TestCase):
    def test_lang_of(self):
        self.assertEqual(i18n.lang_of("en"), "en")
        self.assertEqual(i18n.lang_of("en-US,en;q=0.9"), "en")
        self.assertEqual(i18n.lang_of("zh-CN"), "zh")
        self.assertEqual(i18n.lang_of(None), "zh")

    def test_zh_is_untouched(self):
        d = {"error": "缺少 model 对象"}
        self.assertIs(i18n.translate(d, "zh"), d)


class TranslateTest(unittest.TestCase):
    def test_parameters(self):
        self.assertEqual(en({"error": "非法端口: 7x"})["error"], "Invalid port: 7x")
        self.assertEqual(en({"error": "将清空全部 forwards（当前 10 条），如确认请传 allow_empty=true"})["error"],
                         "This would remove all forwards (10 now); pass allow_empty=true to confirm")

    def test_nested_parameter_is_translated(self):
        self.assertEqual(en({"error": "非法 WAN 网关: x"})["error"], "Invalid WAN gateway: x")
        msg = "内核没有模块 tcp_bbr，请取消勾选“BBR 拥塞控制 + fq 队列”（否则 sysctl 会失败并整体回滚）"
        self.assertEqual(en({"blockers": [msg]})["blockers"][0],
                         'The kernel lacks module tcp_bbr; untick "BBR congestion control + fq qdisc" '
                         "(otherwise sysctl fails and everything rolls back)")

    def test_multiline_blockers(self):
        out = en({"error": "存在阻塞项:\nWAN 与 LAN 网段重叠\n缺少软件包: ppp dnsmasq（先运行 install.sh --with-deps 或 apt-get install）"})
        self.assertEqual(out["error"].split("\n"), [
            "Blockers present:", "WAN and LAN subnets overlap",
            "Missing packages: ppp dnsmasq (run install.sh --with-deps or apt-get install first)"])

    def test_lint_messages(self):
        out = en({"lint": [{"level": "warning", "msg": "udp/53 DNS（公网开放 = 开放解析器，可被用于反射攻击） 对 WAN 开放；"
                                                         "LAN 已由保底规则放行，建议删除"}]})
        self.assertFalse(CJK.search(out["lint"][0]["msg"]), out)
        self.assertEqual(out["lint"][0]["level"], "warning")

    def test_real_lint_output_is_translated(self):
        # the fixture ruleset: DNS/445 open to WAN, high-risk forwards, SSH on WAN, no v6/forward filter
        with open(FIX, encoding="utf-8") as f:
            m, skipped = firewall.import_iptables_save(f.read(), CFG)
        m.update(ssh_wan=True, ipv6_filter=False, forward_filter=False)  # flat model: options are top-level
        tips = firewall.lint(m, CFG)
        self.assertGreaterEqual(len(tips), 4)
        for x in en({"lint": tips, "skipped": skipped})["lint"]:
            self.assertFalse(CJK.search(x["msg"]), x["msg"])

    def test_real_validation_errors_are_translated(self):
        bad = [{"proto": "tcp", "ext": "20022", "ip": "10.0.0.5", "int": "22"},
               {"proto": "tcp", "ext": "21:23", "ip": "192.168.50.5", "int": "21:23"},
               {"proto": "tcp", "ext": "100-200", "ip": "192.168.50.5", "int": "100-150"},
               {"proto": "icmp", "ext": "1", "ip": "192.168.50.5"},
               {"proto": "tcp", "ext": "1; rm -rf /", "ip": "192.168.50.5"}]
        for f in bad:
            with self.assertRaises(firewall.ValidationError) as cm:
                firewall.normalize({"forwards": [f]}, CFG)
            msg = en({"error": str(cm.exception)})["error"]
            self.assertFalse(CJK.search(msg), msg)

    def test_real_plan_errors_are_translated(self):
        plans = [{"wan": {"type": "x"}}, {"wan": {"type": "dhcp", "if": "eth0"}, "lan": {"if": "eth0"}},
                 {"wan": {"type": "dhcp", "if": "eth0"}, "lan": {"if": "eth1", "address": "8.8.8.8/24"}}]
        for p in plans:
            with self.assertRaises(bootstrap.PlanError) as cm:
                bootstrap.normalize(p)
            msg = en({"error": str(cm.exception)})["error"]
            self.assertFalse(CJK.search(msg), msg)

    def test_catalogues_fully_translated(self):
        items = firewall.OPTIONS + firewall.UNSUPPORTED + bootstrap.TUNING
        for o in en({"options": items})["options"]:
            for k in ("label", "desc", "group"):
                if k in o:
                    self.assertFalse(CJK.search(o[k]), f"{o['key']}.{k}: {o[k]}")

    def test_user_data_and_other_keys_untouched(self):
        d = {"forwards": [{"remark": "非法端口: 1", "name": "基础"}], "label": "我的设备", "hostname": "基础",
             "content": "# 非法端口: 1\n"}
        out = en(d)
        self.assertEqual(out["forwards"], d["forwards"])  # remark/name are not TEXT_KEYS
        self.assertEqual(out["hostname"], "基础")
        self.assertEqual(out["label"], "我的设备")  # no template -> stays Chinese
        self.assertEqual(out["content"], "# 非法端口: 1\n")  # whole-line anchored: comment prefix blocks it

    def test_non_strings_pass_through(self):
        d = {"error": None, "blockers": [], "msg": 3, "ok": True}
        self.assertEqual(en(d), d)


if __name__ == "__main__":
    unittest.main()
