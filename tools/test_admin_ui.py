#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""运行：python tools/test_admin_ui.py；配置、卡库和日志均在项目内临时目录。"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
import hashlib
import html
import http.cookiejar
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import re
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
    artifacts = ROOT / "artifacts" / "ui"
    artifacts.mkdir(parents=True, exist_ok=True)
    # 只记录原路径，不读取真实配置；所有登录和密码迁移都必须在覆盖路径后执行。
    original_conf = Path(web.CONF).resolve()
    original_db, original_state = web.db, web.STATE
    with tempfile.TemporaryDirectory(prefix="check-", dir=artifacts) as folder, ExitStack() as isolated:
        folder = Path(folder)
        conf = folder / "config.json"
        assert conf.resolve() != original_conf
        conf.write_text(json.dumps({
            "site": "界面隔离检查",
            "secret": "isolated-ui-check-secret",
            "password_sha256": hashlib.sha256(b"isolated-ui-check").hexdigest(),
        }, ensure_ascii=False), encoding="utf-8")
        isolated.enter_context(patch.multiple(web, DB=str(folder / "cards.db"),
                                             CONF=str(conf), STATE={"conf": None}))
        isolated.enter_context(patch.multiple(web.config, DB_PATH=str(folder / "cards.db"),
                                             PUBLIC_DIR=str(folder / "public")))

        # SQLite 的事务上下文不会关闭连接，显式关闭以便 Windows 清理临时目录。
        @contextmanager
        def isolated_db():
            conn = original_db()
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

        isolated.enter_context(patch.object(web, "db", isolated_db))
        from server import vps_server as tcp
        isolated.enter_context(patch.object(tcp, "db", isolated_db))
        isolated.enter_context(patch.object(tcp, "LOG_PATH", str(folder / "server.log")))

        def row(card):
            with web.db() as conn:
                return conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()

        def count(table="cards"):
            assert table in ("cards", "logs")
            with web.db() as conn:
                return conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]

        def snapshot(card):
            return dict(row(card)), count("logs")

        def rejects(call):
            try:
                call()
            except ValueError:
                return
            raise AssertionError("非法操作应拒绝执行")

        for page in (web.view_login(), web.view_dashboard(), web.view_cards(),
                     web.view_new(), web.view_logs(), web.view_settings(),
                     web.view_card_detail("不存在")):
            assert "<!doctype html>" in page.lower() and "/assets/admin.css" in page
        assert "password_pbkdf2" not in json.loads(conf.read_text(encoding="utf-8"))
        attack = '<script>alert("界面检查")</script>'
        cards = {kind: web.create_cards(1, kind, 30, 1, attack)[0]
                 for kind in ("时间卡", "永久卡", "点数卡")}
        assert count() == 3
        assert "首次使用后计时" in web.view_card_detail(cards["时间卡"])
        assert "永久有效" in web.view_card_detail(cards["永久卡"])
        assert "按验证次数扣点" in web.view_card_detail(cards["点数卡"])
        for page in (web.view_cards(), web.view_cards(notice=attack),
                     web.view_card_detail(cards["时间卡"], attack), web.view_login(attack),
                     web.view_new(attack, {"note": attack}), web.view_created([attack]),
                     web.view_settings(attack, attack)):
            assert attack not in page and html.escape(attack) in page
        for name in ("num", "kind", "days", "points", "note", "csrf"):
            assert f'name="{name}"' in web.view_new()
        batch_form = re.search(r'<form\b[^>]*id="batch-form"[^>]*>', web.view_cards())
        assert batch_form and "data-confirm=" in batch_form.group()

        card = cards["时间卡"]
        now = int(time.time())
        for machine in (None, "", " \t\n"):
            before = snapshot(card)
            assert not web.verify_card(card, machine)[0]
            assert not tcp.handle_login(card, machine, "1").startswith("验证成功|")
            assert snapshot(card) == before
        with patch.object(web.time, "time", return_value=now):
            assert web.verify_card(card, "测试设备甲")[0]
        expiry = row(card)["expire_ts"]
        assert expiry == now + 30 * 86400
        with patch.object(web.time, "time", return_value=now + 60):
            assert web.verify_card(card, "测试设备甲")[0]
            assert not web.verify_card(card, "测试设备乙")[0]
        assert row(card)["expire_ts"] == expiry and row(card)["bind_count"] == 1
        before = snapshot(card)
        assert not web.verify_card(card, "")[0]
        assert snapshot(card) == before
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

        # 两种入口争用同一卡库：最后一点只能用一次，首次绑定只允许一个设备。
        def concurrent_verify(target, machines):
            barrier = threading.Barrier(len(machines))

            def verify(index):
                barrier.wait(timeout=10)
                if index % 2:
                    return tcp.handle_login(target, machines[index], "1").startswith("验证成功|")
                return web.verify_card(target, machines[index])[0]

            with ThreadPoolExecutor(max_workers=len(machines)) as workers:
                return list(workers.map(verify, range(len(machines))))

        point_card = web.create_cards(1, "点数卡", 0, 1, "并发扣点")[0]
        assert sum(concurrent_verify(point_card, ["并发同设备"] * 8)) == 1
        assert row(point_card)["points"] == 0 and row(point_card)["bind_count"] == 1
        bind_card = web.create_cards(1, "时间卡", 7, 0, "并发绑定")[0]
        machines = ["并发设备%d" % index for index in range(8)]
        results = concurrent_verify(bind_card, machines)
        assert sum(results) == 1
        assert row(bind_card)["bound_machine"] == machines[results.index(True)]
        assert row(bind_card)["bind_count"] == 1 and row(bind_card)["expire_ts"] > now

        for act in ("", "未知操作", "renew:0", "renew:-30", "renew:1", "renew:abc"):
            before = snapshot(card)
            rejects(lambda: web.do_action(card, act))
            rejects(lambda: web.do_batch([card], act))
            assert snapshot(card) == before
        expiry = row(card)["expire_ts"]
        done, skipped, notice = web.do_batch([card, " " + card + " ", card], "renew:30")
        assert done == 1 and skipped == 0 and "成功 1 张" in notice
        assert row(card)["expire_ts"] == expiry + 30 * 86400
        assert notice in web.view_cards(notice=notice)
        before = snapshot(card)
        rejects(lambda: web.do_batch([card] * 2001, "renew:30"))
        assert snapshot(card) == before
        done, skipped, _ = web.do_batch(["", "短卡号", "?" * web.config.CARD_LEN], "ban")
        assert done == 0 and skipped == 3

        # 真实 HTTP 流程；不自动跳转，以检查登录、CSRF 和操作结果。
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

        def request(path, data=None, opener=client, headers=None):
            encoded = None if data is None else urllib.parse.urlencode(data, doseq=True).encode("utf-8")
            path = urllib.parse.quote(path, safe="/?=&%+")
            req = urllib.request.Request(base + path, encoded, headers or {})
            try:
                response = opener.open(req, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.code, response.headers, response.read()

        def get_csrf():
            status, _, body = request("/login")
            match = re.search(r'name="csrf" value="([^"]+)"', body.decode("utf-8"))
            assert status == 200 and match
            token = match.group(1)
            assert any(c.name == "csrf" and c.value == token for c in cookies)
            return token

        def post(path, data, opener=client, headers=None):
            return request(path, dict(data, csrf=token), opener, headers)

        try:
            token = get_csrf()
            status, headers, _ = request("/", opener=anonymous)
            assert status == 302 and headers["Location"] == "/login"
            assert request("/new", {"num": "1"}, anonymous)[0] == 403
            assert post("/new", {"num": "1"}, anonymous)[0] == 302
            before = count()
            assert request("/login", {"user": "admin", "pass": "isolated-ui-check"})[0] == 403
            assert request("/login", {"csrf": "wrong", "user": "admin", "pass": "isolated-ui-check"})[0] == 403
            assert post("/login", {"user": "admin", "pass": "isolated-ui-check"},
                        headers={"Origin": "https://other.invalid"})[0] == 403
            assert count() == before and not any(c.name == "sess" for c in cookies)
            assert "账号或密码不对" in post("/login", {"user": "admin", "pass": "wrong"})[2].decode("utf-8")
            assert not any(c.name == "sess" for c in cookies)
            assert "password_pbkdf2" not in json.loads(conf.read_text(encoding="utf-8"))
            status, headers, _ = post("/login", {"user": "admin", "pass": "isolated-ui-check"},
                                      headers={"Origin": base})
            assert status == 302 and headers["Location"] == "/"
            session_headers = headers.get_all("Set-Cookie")
            assert any("sess=" in h and "HttpOnly" in h and "SameSite=Strict" in h for h in session_headers)
            old_session = next(c.value for c in cookies if c.name == "sess")
            stored = json.loads(conf.read_text(encoding="utf-8"))
            assert "password_sha256" not in stored and "password_sha256_legacy" not in stored
            assert stored["password_pbkdf2"].startswith("pbkdf2_sha256$")
            assert web._verify_pbkdf2(stored["password_pbkdf2"], "isolated-ui-check")
            assert not web._verify_pbkdf2(stored["password_pbkdf2"], "wrong")
            assert not web._verify_pbkdf2("malformed", "isolated-ui-check")
            for path in ("/", "/cards", "/new", "/logs", "/settings", "/card/" + card, "/cards?p=非数字"):
                assert request(path)[0] == 200, path
            for path, content_type in (("/assets/admin.css", "text/css"), ("/assets/admin.js", "text/javascript")):
                status, headers, body = request(path, opener=anonymous)
                assert status == 200 and content_type in headers["Content-Type"] and body
            for path in ("/assets/config.json", "/assets/../config.json", "/assets/%2e%2e/config.json", "/assets/admin.py"):
                assert request(path)[0] == 404, path
            valid = {"num": "1", "kind": "时间卡", "days": "7", "points": "2", "note": "隔离检查"}
            for kind in cards:
                before = count()
                assert post("/new", dict(valid, kind=kind))[0] == 200
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
                before = count(), count("logs")
                assert post("/new", data)[0] == 400, data.keys()
                assert (count(), count("logs")) == before
            for headers in ({}, {"Origin": "https://other.invalid"}, {"Referer": "https://other.invalid/form"}):
                before = snapshot(card)
                data = {"act": "delete", "sel": [card]}
                status = request("/cards/batch", data, headers=headers)[0] if not headers else post("/cards/batch", data, headers=headers)[0]
                assert status == 403 and snapshot(card) == before
            before = snapshot(card)
            assert request("/cards/batch", {"act": "delete", "sel": [card], "csrf": "wrong"})[0] == 403
            assert snapshot(card) == before
            for act in ("unknown", "renew:1", "renew:-30"):
                before = snapshot(card)
                assert post("/cards/batch", {"act": act, "sel": [card]})[0] == 400
                assert post("/card/" + card + "/act", {"act": act})[0] == 400
                assert snapshot(card) == before
            before = snapshot(card)
            assert post("/cards/batch", {"act": "delete", "sel": [card] * 2001})[0] == 400
            assert snapshot(card) == before
            expiry = row(card)["expire_ts"]
            status, headers, _ = post("/cards/batch", {"act": "renew:365", "sel": [card, card]})
            assert status == 302 and row(card)["expire_ts"] == expiry + 365 * 86400
            notice = urllib.parse.parse_qs(urllib.parse.urlparse(headers["Location"]).query)["notice"][0]
            assert "成功 1 张" in notice and notice in request(headers["Location"])[2].decode("utf-8")
            status, headers, _ = post("/cards/batch", {"act": "ban"})
            assert status == 302 and "没有选中任何卡密" in request(headers["Location"])[2].decode("utf-8")
            before = snapshot(card)
            for machine in (None, "", " \t"):
                query = {"card": card}
                if machine is not None:
                    query["machine"] = machine
                status, _, body = request("/api/verify?" + urllib.parse.urlencode(query), opener=anonymous)
                assert status == 400 and not json.loads(body)["ok"], (machine, status, body[:100])
                assert snapshot(card) == before
            for path in ("/export.csv", "/logs.csv"):
                status, headers, body = request(path)
                assert status == 200 and body.startswith(b"\xef\xbb\xbf")
                assert "text/csv" in headers["Content-Type"] and "attachment" in headers["Content-Disposition"]

            old_secret = web.load_conf()["secret"]
            for changes in ({"cur": "wrong"}, {"new": "short", "new2": "short"},
                            {"new2": "different"}, {"new": "isolated-ui-check", "new2": "isolated-ui-check"}):
                data = dict({"cur": "isolated-ui-check", "new": "isolated-ui-check-new", "new2": "isolated-ui-check-new"}, **changes)
                assert post("/settings", data)[0] == 400
                assert web.load_conf()["secret"] == old_secret and web.token_ok(old_session)
            status, headers, _ = post("/settings", {"cur": "isolated-ui-check", "new": "isolated-ui-check-new", "new2": "isolated-ui-check-new"})
            assert status == 302 and headers["Location"] == "/login"
            assert web.load_conf()["secret"] != old_secret and not web.token_ok(old_session)
            assert not any(c.name == "sess" for c in cookies)
            assert not web.check_password("isolated-ui-check") and web.check_password("isolated-ui-check-new")
            assert request("/", opener=anonymous, headers={"Cookie": "sess=" + old_session})[0] == 302
            assert post("/new", valid)[0] == 403
            token = get_csrf()
            assert post("/login", {"user": "admin", "pass": "isolated-ui-check-new"})[0] == 302
            assert request("/settings")[0] == 200
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    assert Path(web.CONF).resolve() == original_conf and web.db is original_db and web.STATE is original_state
    print("通过：隔离配置与卡库、CSRF、密码迁移与会话轮换、跨协议并发、批量操作、页面转义、输入校验及 CSV；未访问真实配置或卡库。")


if __name__ == "__main__":
    main()
