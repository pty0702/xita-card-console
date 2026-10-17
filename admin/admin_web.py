#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
西塔验证壳 · 卡密管理平台（Web 后台）

只做"管理"，不做"售卖"：
  * 批量生成卡密（天数卡 / 永久卡 / 点数卡）
  * 搜索、筛选、翻页
  * 单卡详情：绑定机器码、到期、登录/绑定/解绑日志
  * 操作：续期 / 封禁 / 解封 / 解绑机器 / 删除
  * 统计：总数、已绑定、已过期、登录次数
  * HTTP 校验接口：/api/verify?card=&machine=  （方便别的程序接入）
  * 导出 CSV

纯标准库（http.server + sqlite3 + hmac），不需要 Flask、不需要 pip。

启动：
  python3 admin/admin_web.py            # 默认 0.0.0.0:8080
  python3 admin/admin_web.py --port 8081 --host 127.0.0.1

首次启动会生成 admin/config.json，并打印默认密码（务必改）。
"""
import argparse
import csv
import hashlib
import hmac
import html
import io
import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from common import config  # noqa: E402

CONF = os.path.join(HERE, "config.json")
DB = config.DB_PATH

STATE = {"conf": None}


# ---------------- 配置 ----------------
def load_conf():
    if STATE["conf"]:
        return STATE["conf"]
    if os.path.isfile(CONF):
        c = json.load(open(CONF, "r", encoding="utf-8"))
    else:
        pwd = "xita2026"
        c = {
            "password_sha256": hashlib.sha256(pwd.encode()).hexdigest(),
            "secret": secrets.token_hex(32),
            "site": "西塔验证壳 · 卡密管理平台",
        }
        json.dump(c, open(CONF, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("=" * 60)
        print(" 首次启动，已生成管理后台账号")
        print(" 用户名：admin")
        print(" 密码  ：%s" % pwd)
        print(" 配置文件：%s （改完重启生效）" % CONF)
        print("=" * 60, flush=True)
    STATE["conf"] = c
    return c


def check_password(pwd: str) -> bool:
    c = load_conf()
    return hmac.compare_digest(hashlib.sha256(pwd.encode()).hexdigest(), c["password_sha256"])


def make_token() -> str:
    c = load_conf()
    return hmac.new(c["secret"].encode(), b"admin", hashlib.sha256).hexdigest()


def token_ok(tok: str) -> bool:
    return bool(tok) and hmac.compare_digest(tok, make_token())


# ---------------- 数据库 ----------------
def db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS cards (
        card          TEXT PRIMARY KEY,
        kind          TEXT NOT NULL DEFAULT '时间卡',
        days          INTEGER NOT NULL DEFAULT 30,
        points        INTEGER NOT NULL DEFAULT 0,
        created_at    INTEGER NOT NULL,
        expire_ts     INTEGER NOT NULL DEFAULT 0,
        bound_machine TEXT,
        bound_at      INTEGER,
        bind_count    INTEGER NOT NULL DEFAULT 0,
        status        TEXT NOT NULL DEFAULT 'ok',
        note          TEXT
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, card TEXT,
        machine TEXT, action TEXT, detail TEXT
    );
    """)
    return conn


def gen_card() -> str:
    body_len = config.CARD_LEN - len(config.CARD_PREFIX)
    body = ""
    while len(body) < body_len:
        body += secrets.token_hex(16).upper()
    return config.CARD_PREFIX + body[:body_len]


def fmt_ts(ts):
    if not ts:
        return "永久"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def card_state(r):
    now = int(time.time())
    if r["status"] != "ok":
        return "已封禁"
    if r["expire_ts"] and now > r["expire_ts"]:
        return "已过期"
    if r["bound_machine"]:
        return "已绑定"
    return "未使用"


# ---------------- 业务 ----------------
def create_cards(num, kind, days, points, note):
    now = int(time.time())
    made = []
    with db() as conn:
        for _ in range(max(1, min(num, 500))):
            card = gen_card()
            conn.execute(
                "INSERT OR IGNORE INTO cards(card,kind,days,points,created_at,expire_ts,status,note)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (card, kind, days, points, now, 0, "ok", note or ""))
            made.append(card)
        conn.execute("INSERT INTO logs(ts,card,machine,action,detail) VALUES(?,?,?,?,?)",
                     (now, "", "", "admin", "生成 %d 张 %s" % (len(made), kind)))
    return made


def do_action(card, act):
    now = int(time.time())
    with db() as conn:
        r = conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
        if not r:
            return "卡不存在"
        if act == "ban":
            conn.execute("UPDATE cards SET status='banned' WHERE card=?", (card,))
            msg = "已封禁"
        elif act == "unban":
            conn.execute("UPDATE cards SET status='ok' WHERE card=?", (card,))
            msg = "已解封"
        elif act == "unbind":
            conn.execute("UPDATE cards SET bound_machine=NULL, bound_at=NULL WHERE card=?", (card,))
            msg = "已解绑机器"
        elif act.startswith("renew:"):
            d = int(act.split(":")[1])
            base = max(r["expire_ts"] or now, now)
            conn.execute("UPDATE cards SET expire_ts=?, status='ok' WHERE card=?",
                         (base + d * 86400, card))
            msg = "已续期 %d 天" % d
        elif act == "reset":
            conn.execute("UPDATE cards SET expire_ts=0, bound_machine=NULL, bound_at=NULL,"
                         " bind_count=0, status='ok', points=points WHERE card=?", (card,))
            msg = "已重置为未使用"
        elif act == "delete":
            conn.execute("DELETE FROM cards WHERE card=?", (card,))
            msg = "已删除"
        else:
            msg = "未知操作"
        conn.execute("INSERT INTO logs(ts,card,machine,action,detail) VALUES(?,?,?,?,?)",
                     (now, card, "", "admin", msg))
    return msg


def verify_card(card, machine):
    """给 HTTP 校验接口用：返回 (ok, message, extra)"""
    now = int(time.time())
    with db() as conn:
        r = conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
        if not r:
            return False, "卡号不存在.", {}
        if r["status"] != "ok":
            return False, "该卡号已被禁用.", {}
        if r["expire_ts"] and now > r["expire_ts"]:
            return False, "卡号未登录或已经到期.", {}
        if r["kind"] == "点数卡" and r["points"] <= 0:
            return False, "卡号点数已用完.", {}
        if r["bound_machine"] and machine and r["bound_machine"] != machine:
            return False, "当前用户已登录到其他设备.", {}
        if not r["bound_machine"] and machine:
            conn.execute("UPDATE cards SET bound_machine=?, bound_at=?, bind_count=bind_count+1 WHERE card=?",
                         (machine, now, card))
        if r["kind"] == "点数卡":
            conn.execute("UPDATE cards SET points=points-1 WHERE card=?", (card,))
        exp = r["expire_ts"]
        if r["kind"] == "时间卡" and exp == 0:
            exp = now + r["days"] * 86400
            conn.execute("UPDATE cards SET expire_ts=? WHERE card=?", (exp, card))
        conn.execute("INSERT INTO logs(ts,card,machine,action,detail) VALUES(?,?,?,?,?)",
                     (now, card, machine or "", "api", "HTTP 校验通过"))
        return True, "验证成功", {"expire": fmt_ts(exp), "kind": r["kind"]}


# ---------------- 页面 ----------------
CSS = """
<style>
*{box-sizing:border-box}
body{font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;margin:0;background:#f5f6f8;color:#222}
a{color:#0a6cff;text-decoration:none}
.top{background:#1f2b3a;color:#fff;padding:12px 18px;display:flex;align-items:center;gap:18px}
.top b{font-size:16px}
.top .sp{flex:1}
.top a{color:#cfe0ff}
.wrap{max-width:1180px;margin:18px auto;padding:0 14px}
.card{background:#fff;border-radius:10px;padding:16px 18px;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid #eef0f3;text-align:left;white-space:nowrap}
th{background:#fafbfc;color:#555;font-weight:600}
tr:hover td{background:#fafcff}
input,select,button,textarea{font:inherit;padding:7px 10px;border:1px solid #d7dbe0;border-radius:6px;background:#fff}
button{cursor:pointer;background:#0a6cff;color:#fff;border-color:#0a6cff}
button.gray{background:#fff;color:#333;border-color:#d7dbe0}
button.red{background:#e5484d;border-color:#e5484d}
.k{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px}
.k.ok{background:#e7f7ee;color:#18794e}
.k.bind{background:#e7f0ff;color:#0a56c2}
.k.exp{background:#fff4e5;color:#a15c00}
.k.ban{background:#ffe9e9;color:#c22}
.stat{display:flex;gap:14px;flex-wrap:wrap}
.stat div{background:#fff;border-radius:10px;padding:14px 20px;min-width:150px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.stat b{font-size:22px;display:block}
.mono{font-family:ui-monospace,Consolas,monospace}
.muted{color:#888}
.pill{background:#eef2f7;border-radius:6px;padding:2px 8px;font-size:12px}
</style>
"""


def page(title, body, user=None):
    cfg = load_conf()
    nav = ""
    if user:
        nav = """
        <div class="top">
          <b>%s</b>
          <span class="muted" style="color:#9db4d0">%s</span>
          <span class="sp"></span>
          <a href="/">概览</a>
          <a href="/cards">卡密</a>
          <a href="/new">生成</a>
          <a href="/logs">日志</a>
          <a href="/logout">退出</a>
        </div>""" % (html.escape(cfg["site"]), html.escape(user))
    return ("<!doctype html><html lang=zh><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title>%s</head><body>%s<div class=wrap>%s</div></body></html>"
            % (html.escape(title), CSS, nav, body))


def view_login(err=""):
    body = """
    <div class=card style="max-width:380px;margin:80px auto">
      <h3 style="margin-top:0">卡密管理平台 · 登录</h3>
      %s
      <form method=post action=/login>
        <p><input name=user placeholder=用户名 value=admin style="width:100%%"></p>
        <p><input name=pass type=password placeholder=密码 style="width:100%%"></p>
        <p><button style="width:100%%">登 录</button></p>
      </form>
      <p class=muted style="font-size:12px">默认账号 admin / xita2026（首次启动时生成，见 config.json）</p>
    </div>""" % (("<div class=k exp style='padding:6px 10px'>%s</div>" % html.escape(err)) if err else "")
    return page("登录", body)


def view_dashboard():
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM cards").fetchone()["c"]
        ok = conn.execute("SELECT COUNT(*) c FROM cards WHERE status='ok'").fetchone()["c"]
        bound = conn.execute("SELECT COUNT(*) c FROM cards WHERE bound_machine IS NOT NULL").fetchone()["c"]
        now = int(time.time())
        expired = conn.execute("SELECT COUNT(*) c FROM cards WHERE expire_ts>0 AND expire_ts<?", (now,)).fetchone()["c"]
        logins = conn.execute("SELECT COUNT(*) c FROM logs WHERE action IN ('login','api')").fetchone()["c"]
        recent = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 12").fetchall()
    rows = ""
    for r in recent:
        rows += ("<tr><td>%s</td><td class=mono>%s</td><td class=mono>%s</td><td>%s</td><td>%s</td></tr>"
                 % (time.strftime("%m-%d %H:%M:%S", time.localtime(r["ts"])),
                    html.escape(r["card"] or "-"), html.escape(r["machine"] or "-"),
                    html.escape(r["action"] or ""), html.escape(r["detail"] or "")))
    body = """
    <div class=stat>
      <div>总卡数<b>%d</b></div>
      <div>可用<b>%d</b></div>
      <div>已绑定<b>%d</b></div>
      <div>已过期<b>%d</b></div>
      <div>验证次数<b>%d</b></div>
    </div>
    <div class=card style="margin-top:16px">
      <h4 style="margin-top:0">最近动态</h4>
      <table><tr><th>时间</th><th>卡密</th><th>机器码</th><th>动作</th><th>说明</th></tr>%s</table>
    </div>""" % (total, ok, bound, expired, logins, rows or "<tr><td colspan=5 class=muted>暂无</td></tr>")
    return page("概览", body, "admin")


def view_cards(q="", st="", page_no=1):
    per = 20
    where, args = [], []
    if q:
        where.append("(card LIKE ? OR bound_machine LIKE ? OR note LIKE ?)")
        like = "%" + q + "%"
        args += [like, like, like]
    if st == "ok":
        where.append("status='ok' AND (expire_ts=0 OR expire_ts>cast(strftime('%s','now') as integer))")
    elif st == "bound":
        where.append("bound_machine IS NOT NULL")
    elif st == "expired":
        where.append("expire_ts>0 AND expire_ts<cast(strftime('%s','now') as integer)")
    elif st == "banned":
        where.append("status='banned'")
    w = ("WHERE " + " AND ".join(where)) if where else ""
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM cards " + w, args).fetchone()["c"]
        rows = conn.execute("SELECT * FROM cards %s ORDER BY created_at DESC LIMIT %d OFFSET %d"
                            % (w, per, (page_no - 1) * per), args).fetchall()
    trs = ""
    badge = {"未使用": "ok", "已绑定": "bind", "已过期": "exp", "已封禁": "ban"}
    for r in rows:
        s = card_state(r)
        trs += """
        <tr>
          <td class=mono><a href="/card/%s">%s</a></td>
          <td>%s</td>
          <td><span class="k %s">%s</span></td>
          <td>%s</td>
          <td class=mono>%s</td>
          <td>%s</td>
          <td class=mono>%s</td>
          <td>
            <form method=post action=/card/%s/act style=display:inline>
              <input type=hidden name=act value=renew:30><button class=gray>+30天</button></form>
            <form method=post action=/card/%s/act style=display:inline>
              <input type=hidden name=act value=unbind><button class=gray>解绑</button></form>
            <form method=post action=/card/%s/act style=display:inline>
              <input type=hidden name=act value=%s><button class="%s">%s</button></form>
          </td>
        </tr>""" % (
            html.escape(r["card"]), html.escape(r["card"]), html.escape(r["kind"]),
            badge.get(s, "ok"), s, fmt_ts(r["expire_ts"]),
            html.escape(r["bound_machine"] or "-"),
            time.strftime("%m-%d %H:%M", time.localtime(r["created_at"])),
            html.escape(r["note"] or ""),
            html.escape(r["card"]), html.escape(r["card"]), html.escape(r["card"]),
            "unban" if r["status"] != "ok" else "ban",
            "gray" if r["status"] != "ok" else "red",
            "解封" if r["status"] != "ok" else "封禁")
    pages = max(1, (total + per - 1) // per)
    pager = []
    for p in range(1, min(pages, 12) + 1):
        style = "background:#0a6cff;color:#fff" if p == page_no else ""
        pager.append("<a href='/cards?q=%s&st=%s&p=%d' style='padding:3px 9px;border-radius:5px;%s'>%d</a>"
                     % (urllib.parse.quote(q), st, p, style, p))
    body = """
    <div class=card>
      <form method=get action=/cards style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
        <input name=q value="%s" placeholder="卡密 / 机器码 / 备注" style="min-width:240px">
        <select name=st>
          <option value="" %s>全部</option>
          <option value="ok" %s>可用</option>
          <option value="bound" %s>已绑定</option>
          <option value="expired" %s>已过期</option>
          <option value="banned" %s>已封禁</option>
        </select>
        <button>搜索</button>
        <a href=/new><button type=button class=gray>生成卡密</button></a>
        <a href=/export.csv><button type=button class=gray>导出 CSV</button></a>
      </form>
      <table>
        <tr><th>卡密</th><th>类型</th><th>状态</th><th>到期</th><th>绑定机器</th><th>建卡</th><th>备注</th><th>操作</th></tr>
        %s
      </table>
      <p class=muted>共 %d 张 · %s</p>
    </div>""" % (
        html.escape(q),
        "selected" if st == "" else "", "selected" if st == "ok" else "",
        "selected" if st == "bound" else "", "selected" if st == "expired" else "",
        "selected" if st == "banned" else "",
        trs or "<tr><td colspan=8 class=muted>没有数据</td></tr>",
        total, " ".join(pager))
    return page("卡密列表", body, "admin")


def view_new(msg=""):
    body = """
    <div class=card style="max-width:760px">
      <h4 style="margin-top:0">批量生成卡密</h4>
      <div class=muted style="font-size:13px;line-height:1.9;background:#fafbfc;border:1px solid #eef0f3;border-radius:8px;padding:10px 14px;margin-bottom:14px">
        <b>三种卡怎么选：</b><br>
        · <b>时间卡</b>：首次登录开始倒计时 N 天，到期失效（最常用：月卡/年卡）<br>
        · <b>永久卡</b>：不过期，验证多少次都行（买断制/内部使用）<br>
        · <b>点数卡</b>：卡里带 N 个点，<b>每验证一次扣 1 点</b>，扣光失效（按次收费：一次激活=1点）<br>
        <span class=muted>提示：客户端有「自动登录」，每开一次程序算一次验证；点数卡点数别给太少。</span>
      </div>
      %s
      <form method=post action=/new>
        <p>数量 <input name=num value=10 type=number min=1 max=500></p>
        <p>类型
          <select name=kind>
            <option value=时间卡>时间卡（首次登录开始计时）</option>
            <option value=永久卡>永久卡（不过期）</option>
            <option value=点数卡>点数卡（每验证扣 1 点）</option>
          </select>
        </p>
        <p>天数（时间卡用） <input name=days value=365 type=number min=0></p>
        <p>点数（点数卡用） <input name=points value=0 type=number min=0></p>
        <p>备注 <input name=note value="" placeholder="例如 双十一活动" style="width:60%%"></p>
        <p><button>生成</button></p>
      </form>
    </div>""" % (("<div class=k ok style='padding:6px 10px'>%s</div>" % html.escape(msg)) if msg else "")
    return page("生成卡密", body, "admin")


def view_card_detail(card):
    with db() as conn:
        r = conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
        if not r:
            return page("不存在", "<div class=card>没有这张卡</div>", "admin")
        logs = conn.execute("SELECT * FROM logs WHERE card=? ORDER BY id DESC LIMIT 50", (card,)).fetchall()
    trs = "".join(
        "<tr><td>%s</td><td class=mono>%s</td><td>%s</td><td>%s</td></tr>"
        % (time.strftime("%m-%d %H:%M:%S", time.localtime(l["ts"])),
           html.escape(l["machine"] or "-"), html.escape(l["action"] or ""),
           html.escape(l["detail"] or "")) for l in logs)
    body = """
    <div class=card>
      <h3 style="margin-top:0" class=mono>%s</h3>
      <table style="width:auto">
        <tr><th>类型</th><td>%s</td><th>状态</th><td>%s</td></tr>
        <tr><th>到期</th><td>%s</td><th>剩余点数</th><td>%d</td></tr>
        <tr><th>绑定机器</th><td class=mono>%s</td><th>绑定次数</th><td>%d</td></tr>
        <tr><th>建卡时间</th><td>%s</td><th>备注</th><td>%s</td></tr>
      </table>
      <p style="margin-top:14px">
        <form method=post action=/card/%s/act style=display:inline>
          <input type=hidden name=act value=renew:30><button class=gray>续期 30 天</button></form>
        <form method=post action=/card/%s/act style=display:inline>
          <input type=hidden name=act value=renew:365><button class=gray>续期 365 天</button></form>
        <form method=post action=/card/%s/act style=display:inline>
          <input type=hidden name=act value=unbind><button class=gray>解绑机器</button></form>
        <form method=post action=/card/%s/act style=display:inline>
          <input type=hidden name=act value=reset><button class=gray>重置为未使用</button></form>
        <form method=post action=/card/%s/act style=display:inline>
          <input type=hidden name=act value=%s><button class=%s>%s</button></form>
        <form method=post action=/card/%s/act style=display:inline
              onsubmit="return confirm('确定删除这张卡？不可恢复')">
          <input type=hidden name=act value=delete><button class=red>删除</button></form>
      </p>
    </div>
    <div class=card>
      <h4 style="margin-top:0">这张卡的日志</h4>
      <table><tr><th>时间</th><th>机器码</th><th>动作</th><th>说明</th></tr>%s</table>
    </div>""" % (
        html.escape(r["card"]), html.escape(r["kind"]), card_state(r), fmt_ts(r["expire_ts"]),
        r["points"], html.escape(r["bound_machine"] or "-"), r["bind_count"],
        fmt_ts(r["created_at"]), html.escape(r["note"] or ""),
        html.escape(card), html.escape(card), html.escape(card), html.escape(card),
        html.escape(card), "unban" if r["status"] != "ok" else "ban",
        "gray" if r["status"] != "ok" else "red", "解封" if r["status"] != "ok" else "封禁",
        html.escape(card),
        trs or "<tr><td colspan=4 class=muted>暂无</td></tr>")
    return page("卡密详情", body, "admin")


def view_logs():
    with db() as conn:
        rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    trs = "".join(
        "<tr><td>%s</td><td class=mono>%s</td><td class=mono>%s</td><td>%s</td><td>%s</td></tr>"
        % (time.strftime("%m-%d %H:%M:%S", time.localtime(l["ts"])),
           html.escape(l["card"] or "-"), html.escape(l["machine"] or "-"),
           html.escape(l["action"] or ""), html.escape(l["detail"] or "")) for l in rows)
    body = "<div class=card><h4 style='margin-top:0'>最近 200 条日志</h4><table>" \
           "<tr><th>时间</th><th>卡密</th><th>机器码</th><th>动作</th><th>说明</th></tr>%s</table></div>" % (
               trs or "<tr><td colspan=5 class=muted>暂无</td></tr>")
    return page("日志", body, "admin")


# ---------------- HTTP ----------------
class H(BaseHTTPRequestHandler):
    server_version = "XitaAdmin/1.0"

    def log_message(self, fmt, *a):
        pass

    # --- 工具 ---
    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _redirect(self, to, extra=None):
        body = ("<!doctype html><meta charset=utf-8><a href='%s'>跳转中…</a>" % to).encode("utf-8")
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _cookie_ok(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        m = c.get("sess")
        return bool(m) and token_ok(m.value)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return urllib.parse.parse_qs(raw)

    # --- 路由 ---
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p, qs = u.path, urllib.parse.parse_qs(u.query)
        if p.startswith("/api/verify"):
            return self.api_verify(qs)
        if p == "/login":
            return self._send(200, view_login())
        if not self._cookie_ok():
            return self._redirect("/login")
        if p in ("/", ""):
            return self._send(200, view_dashboard())
        if p == "/cards":
            return self._send(200, view_cards(qs.get("q", [""])[0], qs.get("st", [""])[0],
                                              int(qs.get("p", ["1"])[0] or 1)))
        if p == "/new":
            return self._send(200, view_new())
        if p == "/logs":
            return self._send(200, view_logs())
        if p == "/export.csv":
            return self.export_csv()
        if p.startswith("/card/"):
            card = urllib.parse.unquote(p[len("/card/"):])
            return self._send(200, view_card_detail(card))
        if p == "/logout":
            return self._redirect("/login", [("Set-Cookie", "sess=; Path=/; Max-Age=0")])
        self._send(404, page("404", "<div class=card>页面不存在</div>", "admin"))

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        p = u.path
        f = self._body()
        if p == "/login":
            if check_password(f.get("pass", [""])[0]) and f.get("user", ["admin"])[0] == "admin":
                return self._redirect("/", [("Set-Cookie", "sess=%s; Path=/; HttpOnly" % make_token())])
            return self._send(200, view_login("账号或密码不对"))
        if not self._cookie_ok():
            return self._redirect("/login")
        if p == "/new":
            num = int(f.get("num", ["10"])[0] or 10)
            kind = f.get("kind", ["时间卡"])[0]
            days = int(f.get("days", ["365"])[0] or 0)
            points = int(f.get("points", ["0"])[0] or 0)
            note = f.get("note", [""])[0]
            made = create_cards(num, kind, days, points, note)
            rows = "".join("<li class=mono>%s</li>" % html.escape(c) for c in made)
            body = "<div class=card><h4 style='margin-top:0'>已生成 %d 张</h4><ul>%s</ul>" \
                   "<p><a href=/cards><button type=button>去卡密列表</button></a></p></div>" % (len(made), rows)
            return self._send(200, page("生成结果", body, "admin"))
        if p.startswith("/card/") and p.endswith("/act"):
            card = urllib.parse.unquote(p[len("/card/"):-len("/act")])
            act = f.get("act", [""])[0]
            do_action(card, act)
            return self._redirect("/card/" + urllib.parse.quote(card))
        self._send(404, page("404", "<div class=card>页面不存在</div>", "admin"))

    # --- 接口 ---
    def api_verify(self, qs):
        card = qs.get("card", [""])[0]
        machine = qs.get("machine", [""])[0]
        if not card:
            return self._send(400, json.dumps({"ok": False, "msg": "缺少 card"}, ensure_ascii=False),
                              "application/json; charset=utf-8")
        ok, msg, extra = verify_card(card, machine)
        out = {"ok": ok, "msg": msg}
        out.update(extra)
        self._send(200, json.dumps(out, ensure_ascii=False), "application/json; charset=utf-8")

    def export_csv(self):
        with db() as conn:
            rows = conn.execute("SELECT * FROM cards ORDER BY created_at DESC").fetchall()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["卡密", "类型", "状态", "到期", "绑定机器码", "建卡时间", "备注"])
        for r in rows:
            w.writerow([r["card"], r["kind"], card_state(r), fmt_ts(r["expire_ts"]),
                        r["bound_machine"] or "", fmt_ts(r["created_at"]), r["note"] or ""])
        data = buf.getvalue().encode("utf-8-sig")
        self._send(200, data, "text/csv; charset=utf-8",
                   [("Content-Disposition", 'attachment; filename="cards.csv"')])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    load_conf()
    db()
    srv = ThreadingHTTPServer((a.host, a.port), H)
    print("卡密管理平台启动 http://%s:%d  （数据库 %s）" % (a.host, a.port, DB), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
