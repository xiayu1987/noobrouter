"""HTTP server (stdlib only). Usage: python3 -m noobrouter_agent.server [-c /etc/noobrouter-agent.json]

- Listens on cfg.listen (default 127.0.0.1); put it on the LAN IP only, never on the WAN.
- Every /api/* request needs "Authorization: Bearer <token>" (token in data_dir/token).
- Other paths serve the built web UI from cfg.web_root (SPA fallback to index.html).
"""
import argparse
import hmac
import json
import mimetypes
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

from . import api, applier, config, i18n
from .shell import CmdError

MAX_BODY = 1 << 20

CONSOLE_FW_MSG = {
    "ok": None, "loopback": None,
    "added": "firewall: console port {port} was blocked on {lan_if}; added a LAN-only accept "
             "(kept until the next firewall apply, which renders the same rule)",
    "dry_run": "WARNING firewall drops port {port} on {lan_if}: LAN clients cannot reach the console "
               "(dry_run=true, rule not added; apply the firewall or open the port by hand)",
}


def error_status(e):
    """Map exceptions to HTTP status codes (single place)."""
    if isinstance(e, api.ApiError):
        return e.status
    if isinstance(e, CmdError):
        return e.status
    if isinstance(e, ValueError):  # ValidationError, JSONDecodeError, bad ip_address(...)
        return 400
    return 500  # KeyError/TypeError etc. are bugs: logged with traceback


def make_handler(cfg):
    token = cfg["token"].encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = "noobrouter-agent"
        sys_version = ""

        def log_message(self, fmt, *a):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

        def _send(self, status, data, ctype="application/json; charset=utf-8"):
            raw = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _authed(self):
            h = self.headers.get("Authorization", "")
            return h.startswith("Bearer ") and hmac.compare_digest(h[7:].strip().encode(), token)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise api.ApiError("请求体过大", 413)
            if not n:
                return {}
            if "application/json" not in self.headers.get("Content-Type", ""):
                raise api.ApiError("需要 application/json", 415)
            body = json.loads(self.rfile.read(n))
            if not isinstance(body, dict):
                raise api.ApiError("请求体必须是 JSON 对象")
            return body

        def _api(self, method):
            url = urlsplit(self.path)
            lang = i18n.lang_of(self.headers.get("Accept-Language"))
            send = lambda st, data: self._send(st, i18n.translate(data, lang))  # noqa: E731
            if not self._authed():
                return send(401, {"error": "未授权"})
            fn = api.ROUTES.get((method, url.path))
            if not fn:
                return send(404, {"error": "接口不存在"})
            try:
                body = self._body() if method == "POST" else {}
                send(200, fn(cfg, body, dict(parse_qsl(url.query))))
            except Exception as e:  # noqa: BLE001 - mapped to a status code
                st = error_status(e)
                if st >= 500:
                    traceback.print_exc()
                out = {"error": str(e)}
                if getattr(e, "code", None):
                    out["code"] = e.code
                send(st, out)

        def _static(self):
            root = cfg.get("web_root")
            if not root:
                return self._send(404, {"error": "web_root 未配置"})
            root = os.path.realpath(root)
            rel = urlsplit(self.path).path.lstrip("/") or "index.html"
            p = os.path.realpath(os.path.join(root, rel))
            if not p.startswith(root + os.sep) or not os.path.isfile(p):
                p = os.path.join(root, "index.html")  # SPA fallback, also blocks traversal
            if not os.path.isfile(p):
                return self._send(404, {"error": "not found"})
            with open(p, "rb") as f:
                self._send(200, f.read(), mimetypes.guess_type(p)[0] or "application/octet-stream")

        def do_GET(self):
            self._api("GET") if self.path.startswith("/api/") else self._static()

        def do_POST(self):
            if self.path.startswith("/api/"):
                self._api("POST")
            else:
                self._send(405, {"error": "method not allowed"})

    return Handler


def main(argv=None):
    ap = argparse.ArgumentParser(prog="noobrouter-agent")
    ap.add_argument("-c", "--config", default="/etc/noobrouter-agent.json")
    args = ap.parse_args(argv)
    cfg = config.load(args.config)
    srv = ThreadingHTTPServer((cfg["listen"], int(cfg["port"])), make_handler(cfg))
    print(f"noobrouter-agent listening on {cfg['listen']}:{cfg['port']} dry_run={cfg['dry_run']}", flush=True)
    res = applier.ensure_console_access(cfg)
    msg = CONSOLE_FW_MSG.get(res, "WARNING console firewall check failed ({res}); "
                                  "LAN clients may not reach port {port}")
    if msg:
        print(msg.format(port=cfg["port"], lan_if=cfg["lan_if"], res=res), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
