#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""运行：python tools/test_admin_ui.py；仅使用项目内临时卡库。"""
import hashlib
import html
import http.cookiejar
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from admin import admin_web as web


def main():
    # 覆盖内存配置，绝不加载线上账号或现有卡库。
    web.STATE["conf"] = {
        "site": "界面隔离检查",
        "secret": "isolated-ui-check-secret",
        "password_sha256": hashlib.sha256(b"isolated-ui-check").hexdigest(),
    }
    artifacts = ROOT / "artifacts" / "ui"
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="check-", dir=artifacts) as folder:
        web.DB = str(Path(folder) / "cards.db")
        original_db = web.db

        # SQLite 的事务上下文不会关闭连接；检查结束即关闭，便于 Windows 清理临时目录。
        @contextmanager
        def isolated_db():
            conn = original_db()
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

        web.db = isolated_db

        def row(card):
            with web.db() as conn:
                return conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()

        def count():
            with web.db() as conn:
                return conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0]

        for page in (web.view_login(), web.view_dashboard(), web.view_cards(),
                     web.view_new(), web.view_logs(), web.view_card_detail("不存在")):
            assert "<!doctype html>" in page.lower() and "/assets/admin.css" in page
        attack = '<script>alert("界面检查")</script>'
        cards = {
            kind: web.create_cards(1, kind, 30, 1, attack)[0]
            for kind in ("时间卡", "永久卡", "点数卡")
        }
        assert count() == 3
        assert "首次使用后计时" in web.view_card_detail(cards["时间卡"])
        assert "永久有效" in web.view_card_detail(cards["永久卡"])
        assert "按验证次数扣点" in web.view_card_detail(cards["点数卡"])
        for page in (web.view_cards(), web.view_card_detail(cards["时间卡"]),
                     web.view_login(attack), web.view_new(attack, {"note": attack}),
                     web.view_created([attack])):
            assert attack not in page and html.escape(attack) in page
        form = web.view_new()
        for name in ("num", "kind", "days", "points", "note"):
            assert f'name="{name}"' in form

        card = cards["时间卡"]
        now = int(time.time())
        with patch.object(web.time, "time", return_value=now):
            assert web.verify_card(card, "测试设备甲")[0]
        expiry = row(card)["expire_ts"]
        assert expiry == now + 30 * 86400
        with patch.object(web.time, "time", return_value=now + 60):
            assert web.verify_card(card, "测试设备甲")[0]
            assert not web.verify_card(card, "测试设备乙")[0]
        assert row(card)["expire_ts"] == expiry and row(card)["bind_count"] == 1
        assert web.verify_card(cards["点数卡"], "测试设备甲")[0]
        assert row(cards["点数卡"])["points"] == 0
        assert "点数耗尽" in web.badge(row(cards["点数卡"]))
        assert not web.verify_card(cards["点数卡"], "测试设备甲")[0]
        web.do_action(card, "ban")
        assert row(card)["status"] == "banned" and not web.verify_card(card, "测试设备甲")[0]
        web.do_action(card, "unban")
        assert row(card)["status"] == "ok" and web.verify_card(card, "测试设备甲")[0]
        web.do_action(card, "renew:30")
        assert row(card)["expire_ts"] == expiry + 30 * 86400
        web.do_action(card, "unbind")
        assert row(card)["bound_machine"] is None
        assert web.verify_card(card, "测试设备乙")[0]
        assert row(card)["bound_machine"] == "测试设备乙"
        with web.db() as conn:
            conn.execute("INSERT INTO logs(ts,card,machine,action,detail) VALUES(?,?,?,?,?)",
                         (now, card, attack, "检查", attack))
        assert attack not in web.view_logs() and html.escape(attack) in web.view_logs()

        # 真实 HTTP 流程，禁止自动跳转以便断言登录和访问控制。
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                return None

        server = ThreadingHTTPServer(("127.0.0.1", 0), web.H)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:%d" % server.server_port
        cookies = http.cookiejar.CookieJar()
        client = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(cookies))
        anonymous = urllib.request.build_opener(NoRedirect())

        def request(path, data=None, opener=client):
            encoded = None if data is None else urllib.parse.urlencode(data).encode("utf-8")
            path = urllib.parse.quote(path, safe="/?=&%")
            try:
                response = opener.open(base + path, encoded, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.code, response.headers, response.read()

        try:
            status, headers, _ = request("/", opener=anonymous)
            assert status == 302 and headers["Location"] == "/login"
            assert request("/new", {"num": "1"}, anonymous)[0] == 302
            assert "账号或密码不对" in request("/login", {"user": "admin", "pass": "wrong"})[2].decode()
            assert not list(cookies)
            status, headers, _ = request("/login", {"user": "admin", "pass": "isolated-ui-check"})
            assert status == 302 and headers["Location"] == "/"
            assert "HttpOnly" in headers["Set-Cookie"] and any(c.name == "sess" for c in cookies)
            for path in ("/", "/cards", "/new", "/logs", "/card/" + card, "/cards?p=非数字"):
                assert request(path)[0] == 200, path
            for path, content_type in (("/assets/admin.css", "text/css"), ("/assets/admin.js", "text/javascript")):
                status, headers, body = request(path, opener=anonymous)
                assert status == 200 and content_type in headers["Content-Type"] and body
            for path in ("/assets/config.json", "/assets/../config.json", "/assets/%2e%2e/config.json", "/assets/admin.py"):
                assert request(path)[0] == 404, path
            valid = {"num": "1", "kind": "时间卡", "days": "7", "points": "2", "note": "隔离检查"}
            for kind in cards:
                before = count()
                assert request("/new", dict(valid, kind=kind))[0] == 200
                assert count() == before + 1
                with web.db() as conn:
                    latest = conn.execute("SELECT * FROM cards WHERE note=? AND kind=?", ("隔离检查", kind)).fetchone()
                    assert latest and latest["days"] == (7 if kind == "时间卡" else 0)
                    assert latest["points"] == (2 if kind == "点数卡" else 0)
            invalid = [dict(valid, **change) for change in (
                {"num": "abc"}, {"num": "0"}, {"num": "501"}, {"kind": "未知类型"},
                {"days": "0"}, {"days": "abc"}, {"days": "36501"},
                {"kind": "点数卡", "points": "0"}, {"kind": "点数卡", "points": "abc"},
                {"kind": "点数卡", "points": "100000001"}, {"note": "长" * 201},
            )]
            for data in invalid:
                before = count()
                assert request("/new", data)[0] == 400, data.keys()
                assert count() == before
            status, headers, body = request("/export.csv")
            assert status == 200 and body.startswith(b"\xef\xbb\xbf")
            assert "text/csv" in headers["Content-Type"] and "attachment" in headers["Content-Disposition"]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print("通过：页面、转义、授权状态、登录 Cookie、输入校验、静态资源、分页与 CSV 导出；未使用真实卡库。")


if __name__ == "__main__":
    main()
