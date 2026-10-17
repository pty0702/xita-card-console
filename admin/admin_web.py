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
PBKDF2_ROUNDS = 260000


def _hash_pbkdf2(pwd: str, salt: str = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), PBKDF2_ROUNDS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ROUNDS, salt, dk.hex())


def _verify_pbkdf2(stored: str, pwd: str) -> bool:
    try:
        algo, rounds, salt, expect = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), int(rounds))
        return hmac.compare_digest(dk.hex(), expect)
    except Exception:
        return False


def save_conf(c):
    json.dump(c, open(CONF, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    try:
        os.chmod(CONF, 0o600)
    except Exception:
        pass
    STATE["conf"] = c
    return c


def load_conf():
    if STATE["conf"]:
        return STATE["conf"]
    if os.path.isfile(CONF):
        c = json.load(open(CONF, "r", encoding="utf-8"))
        # 老配置只有 password_sha256：保留原样，等下次登录成功时再原地升级成 PBKDF2
        if "password_pbkdf2" not in c and c.get("password_sha256"):
            c["password_sha256_legacy"] = c.pop("password_sha256")
            save_conf(c)
    else:
        pwd = "xita2026"
        c = {
            "password_pbkdf2": _hash_pbkdf2(pwd),
            "secret": secrets.token_hex(32),
            "site": "西塔验证壳 · 卡密管理平台",
        }
        save_conf(c)
        print("=" * 60)
        print(" 首次启动，已生成管理后台账号")
        print(" 用户名：admin")
        print(" 密码  ：%s" % pwd)
        print(" 配置文件：%s （改完重启生效）" % CONF)
        print("=" * 60, flush=True)
    STATE["conf"] = c
    return c


def check_password(pwd: str) -> bool:
    """PBKDF2 优先；老 sha256 命中则自动升级存储格式"""
    c = load_conf()
    if c.get("password_pbkdf2"):
        return _verify_pbkdf2(c["password_pbkdf2"], pwd)
    legacy = c.get("password_sha256_legacy") or c.get("password_sha256")
    if legacy and hmac.compare_digest(hashlib.sha256(pwd.encode()).hexdigest(), legacy):
        c["password_pbkdf2"] = _hash_pbkdf2(pwd)
        c.pop("password_sha256_legacy", None)
        c.pop("password_sha256", None)
        save_conf(c)
        return True
    return False


def set_password(pwd: str):
    c = load_conf()
    c["password_pbkdf2"] = _hash_pbkdf2(pwd)
    c.pop("password_sha256_legacy", None)
    c.pop("password_sha256", None)
    c["secret"] = secrets.token_hex(32)      # 换密码同时轮换 secret，旧会话全部失效
    return save_conf(c)


def make_token() -> str:
    c = load_conf()
    return hmac.new(c["secret"].encode(), b"admin", hashlib.sha256).hexdigest()


def token_ok(tok: str) -> bool:
    return bool(tok) and hmac.compare_digest(tok, make_token())


def csrf_token() -> str:
    c = load_conf()
    return hmac.new(c["secret"].encode(), b"csrf", hashlib.sha256).hexdigest()


def csrf_field() -> str:
    return '<input type="hidden" name="csrf" value="%s">' % csrf_token()


# ---- 登录失败限制 ----
LOGIN_MAX_FAIL = 5
LOGIN_LOCK_SECONDS = 600


def login_locked(ip: str):
    now = int(time.time())
    with db() as conn:
        conn.execute("DELETE FROM auth_fails WHERE ts<?", (now - LOGIN_LOCK_SECONDS,))
        n = conn.execute("SELECT COUNT(*) FROM auth_fails WHERE ip=?", (ip,)).fetchone()[0]
    return n >= LOGIN_MAX_FAIL


def login_fail(ip: str):
    with db() as conn:
        conn.execute("INSERT INTO auth_fails(ip,ts) VALUES(?,?)", (ip, int(time.time())))


def login_reset(ip: str):
    with db() as conn:
        conn.execute("DELETE FROM auth_fails WHERE ip=?", (ip,))


# ---- 校验接口限流（每 IP 每分钟 120 次）----
API_MAX_PER_MIN = 120


def api_allowed(ip: str) -> bool:
    now = int(time.time())
    with db() as conn:
        conn.execute("DELETE FROM api_hits WHERE ts<?", (now - 60,))
        n = conn.execute("SELECT COUNT(*) FROM api_hits WHERE ip=?", (ip,)).fetchone()[0]
        if n >= API_MAX_PER_MIN:
            return False
        conn.execute("INSERT INTO api_hits(ip,ts) VALUES(?,?)", (ip, now))
    return True


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
    CREATE TABLE IF NOT EXISTS auth_fails (ip TEXT, ts INTEGER);
    CREATE TABLE IF NOT EXISTS api_hits (ip TEXT, ts INTEGER);
    CREATE INDEX IF NOT EXISTS idx_auth_fails ON auth_fails(ip, ts);
    CREATE INDEX IF NOT EXISTS idx_api_hits ON api_hits(ip, ts);
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


CARD_ACTIONS = {
    "ban": "封禁", "unban": "解封", "unbind": "解绑", "reset": "重置",
    "delete": "删除", "renew:30": "续期 30 天", "renew:365": "续期 365 天",
}


def do_action(card, act):
    if act not in CARD_ACTIONS:
        raise ValueError("不支持的卡密操作")
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        now = int(time.time())
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


def do_batch(cards, act):
    """同批次卡号去重，返回成功数、跳过数与结果说明。"""
    if act not in CARD_ACTIONS:
        raise ValueError("不支持的批量操作")
    if len(cards) > 2000:
        raise ValueError("一次最多处理 2000 张卡密，请分批操作")
    done, skipped = 0, 0
    for c in dict.fromkeys((card or "").strip() for card in cards):
        if not c or len(c) != config.CARD_LEN:
            skipped += 1
            continue
        try:
            msg = do_action(c, act)
            if msg in ("卡不存在", "未知操作"):
                skipped += 1
            else:
                done += 1
        except sqlite3.Error:
            skipped += 1
    return done, skipped, "批量%s：成功 %d 张，跳过 %d 张" % (CARD_ACTIONS[act], done, skipped)


def verify_card(card, machine):
    """给 HTTP 校验接口用：返回 (ok, message, extra)"""
    if not machine or not machine.strip():
        return False, "缺少设备标识.", {}
    with db() as conn:
        # 在读取前取得写事务，HTTP 与 TCP 验证共享同一数据库锁。
        conn.execute("BEGIN IMMEDIATE")
        now = int(time.time())
        r = conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
        if not r:
            return False, "卡号不存在.", {}
        if r["status"] != "ok":
            return False, "该卡号已被禁用.", {}
        if r["expire_ts"] and now > r["expire_ts"]:
            return False, "卡号未登录或已经到期.", {}
        if r["kind"] == "点数卡" and r["points"] <= 0:
            return False, "卡号点数已用完.", {}
        if r["bound_machine"] and r["bound_machine"] != machine:
            return False, "当前用户已登录到其他设备.", {}
        if not r["bound_machine"]:
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
def icon(name):
    paths = {
        "grid": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        "card": '<rect x="3" y="5" width="18" height="14" rx="3"/><path d="M3 10h18M7 15h4"/>',
        "plus": '<path d="M12 5v14M5 12h14"/>',
        "logs": '<path d="M8 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-3M9 7h11M9 12h11M9 17h5"/><path d="M5 7h.01M5 12h.01M5 17h.01"/>',
        "arrow": '<path d="M5 12h14m-5-5 5 5-5 5"/>',
        "shield": '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
        "link": '<path d="m10 13 4-4m-6 6-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m2 3 1-1a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0"/>',
        "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        "activity": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
        "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
        "copy": '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
        "download": '<path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/>',
        "logout": '<path d="M9 4H4v16h5m6-13 5 5-5 5M8 12h12"/>',
        "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
        "eye": '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
        "check": '<path d="m5 12 4 4L19 6"/>',
    }
    return '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + paths.get(name, paths["card"]) + '</svg>'


def page(title, body, user=None):
    site = html.escape(load_conf()["site"])
    nav = ""
    if user:
        links = [("/", "grid", "数据概览", "概览"), ("/cards", "card", "卡密管理", "卡密列表"),
                 ("/new", "plus", "生成卡密", "生成卡密"), ("/logs", "logs", "操作日志", "日志"),
                 ("/settings", "shield", "设置与安全", "设置")]
        items = "".join('<a class="nav-link %s" href="%s" %s>%s<span>%s</span></a>' % (
            "active" if title == key or (href == "/cards" and title == "卡密详情") or (href == "/new" and title == "生成结果") else "",
            href, 'aria-current="page"' if title == key else "", icon(symbol), label)
            for href, symbol, label, key in links)
        nav = f'''<aside class="sidebar" id="sidebar" aria-label="主导航">
          <a class="brand" href="/"><span class="brand-mark">X</span><span class="brand-name">西塔 <small>授权管理工作台</small></span></a>
          <div class="nav-label">工作空间</div><nav>{items}</nav>
          <div class="sidebar-foot"><span class="sidebar-shield">{icon("shield")}</span><strong>每一份授权，都有迹可循</strong><p>发卡、绑定与使用记录<br>在一个工作台里掌握。</p><span class="sidebar-version">XITA CONSOLE · v2.0</span></div>
        </aside><button class="mobile-backdrop" id="mobile-backdrop" aria-label="关闭导航" tabindex="-1"></button>'''
        shell = f'''<div class="app-shell">{nav}<div class="workspace"><header class="topbar">
          <button class="button ghost icon-only mobile-menu" type="button" data-menu-toggle aria-label="打开导航" aria-expanded="false" aria-controls="sidebar">{icon("menu")}</button>
          <div class="breadcrumbs">工作空间 <span>/</span> <strong>{html.escape(title)}</strong></div>
          <div class="topbar-right"><span class="muted topbar-date">{time.strftime("%Y.%m.%d")}</span><span class="avatar">A</span><span class="admin-name">管理员</span><a class="button ghost icon-only" href="/logout" aria-label="退出登录" title="退出登录">{icon("logout")}</a></div></header>
          <main id="main" class="main-content">{body}</main><footer class="workspace-footer">{site}<span>让授权管理更从容</span></footer></div></div>'''
    else:
        shell = body
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light">
      <title>{html.escape(title)} · 西塔工作台</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='16' fill='%235367f2'/%3E%3Cpath d='m19 18 26 28m0-28L19 46' stroke='white' stroke-width='7'/%3E%3C/svg%3E">
      <link rel="stylesheet" href="/assets/admin.css?v=20261017"><script defer src="/assets/admin.js?v=20261017"></script></head>
      <body><a class="skip-link" href="#main">跳转到主要内容</a>{shell}
      <div id="toast" class="toast" role="status" aria-live="polite"></div>
      <dialog id="confirm-dialog" class="confirm-dialog" aria-labelledby="confirm-title"><div class="dialog-icon">{icon("shield")}</div><h2 id="confirm-title">确认执行此操作？</h2><p class="dialog-message"></p><div class="dialog-actions"><button type="button" class="button secondary" data-dialog-cancel>取消</button><button type="button" class="button primary" data-dialog-accept>确认操作</button></div></dialog></body></html>'''


def heading(title, description, actions="", eyebrow="工作空间 / WORKSPACE"):
    return f'<div class="page-heading"><div><div class="eyebrow">{eyebrow}</div><h1>{title}</h1><p class="page-description">{description}</p></div><div class="heading-actions">{actions}</div></div>'


def empty_row(columns, text="暂无记录", note="有新的动态时，会显示在这里。"):
    return f'<tr><td colspan="{columns}"><div class="empty-state">{icon("card")}<strong>{text}</strong><span>{note}</span></div></td></tr>'


def badge(r):
    state = card_state(r)
    if r["kind"] == "点数卡" and r["points"] <= 0 and r["status"] == "ok":
        state = "点数耗尽"
    tone = {"未使用": "ok", "已绑定": "bind", "已过期": "exp", "已封禁": "ban", "点数耗尽": "exp"}[state]
    return f'<span class="badge {tone}"><i></i>{state}</span>'


def card_expiry(r):
    if r["expire_ts"]:
        return fmt_ts(r["expire_ts"])
    return {"时间卡": "首次使用后计时", "永久卡": "永久有效", "点数卡": "按验证次数扣点"}.get(r["kind"], "—")


def copy_button(value):
    return '<button class="copy-button" type="button" data-copy="%s" aria-label="复制卡密" title="复制卡密">%s</button>' % (html.escape(value, quote=True), icon("copy"))


def action_form(card, action, label, tone="secondary", message=""):
    url = "/card/" + urllib.parse.quote(card, safe="") + "/act"
    confirm = f' data-confirm="{html.escape(message, quote=True)}"' if message else ""
    return f'<form method="post" action="{url}"{confirm}>{csrf_field()}<input type="hidden" name="act" value="{action}"><button class="button {tone} small" type="submit">{label}</button></form>'


def log_rows(rows, with_card=True):
    result = []
    names = {"admin": "管理操作", "login": "客户端验证", "api": "接口验证", "bind": "设备绑定", "unbind": "设备解绑"}
    for r in rows:
        card = '<td><span class="mono card-code">%s</span></td>' % html.escape(r["card"] or "—") if with_card else ""
        result.append('<tr data-log-row><td class="log-time">%s</td>%s<td><span class="mono machine-code">%s</span></td><td><span class="badge neutral">%s</span></td><td class="log-detail">%s</td></tr>' % (
            time.strftime("%m-%d %H:%M:%S", time.localtime(r["ts"] or 0)), card,
            html.escape(r["machine"] or "—"), html.escape(names.get(r["action"], r["action"] or "—")), html.escape(r["detail"] or "—")))
    return "".join(result) or empty_row(5 if with_card else 4)


def view_login(err=""):
    error = f'<div class="notice error" role="alert">{html.escape(err)}</div>' if err else ""
    return page("登录", f'''<div class="login-page"><section class="login-story" aria-label="西塔工作台">
      <a class="login-logo brand" href="/login"><span class="brand-mark">X</span><span class="brand-name">西塔 <small>XITA CONSOLE</small></span></a>
      <div class="login-story-content"><span class="login-tag">让每一份授权井然有序</span><h2>授权有序，<br>管理从容<span>。</span></h2><p>从第一张卡密，到每一次验证。<br>把繁琐交给工作台，把时间留给业务。</p>
      <div class="login-visual" aria-hidden="true"><div class="visual-orbit"></div><div class="visual-card visual-card-back"></div><div class="visual-card"><div class="visual-card-top"><span>XITA / ACCESS</span>{icon("shield")}</div><div class="visual-card-chip">{icon("card")}</div><div class="visual-card-code">•••• &nbsp; •••• &nbsp; •••• &nbsp; 2026</div><div class="visual-card-bottom"><span>每一份信任，皆有凭证</span><span>AUTHORIZED</span></div></div><div class="visual-status">{icon("check")} 统一管理 · 清晰可控</div></div>
      <div class="login-features"><span>{icon("card")} 灵活发卡</span><span>{icon("link")} 设备绑定</span><span>{icon("logs")} 全程留痕</span></div></div><div class="login-copyright">西塔 · 授权管理工作台</div></section>
      <main id="main" class="login-main"><div class="login-card"><span class="login-eyebrow">WELCOME BACK</span><h1>欢迎回来</h1><p class="login-subtitle">登录西塔工作台，开始今天的管理。</p>{error}
      <form method="post" action="/login">{csrf_field()}<div class="field"><label class="field-label" for="username">管理员账号</label><input id="username" name="user" value="admin" autocomplete="username" required placeholder="请输入管理员账号"></div>
      <div class="field"><label class="field-label" for="password">登录密码</label><div class="password-field"><input id="password" name="pass" type="password" autocomplete="current-password" required placeholder="请输入管理密码"><button type="button" class="password-toggle" data-toggle-password="#password" aria-label="显示密码" aria-pressed="false">{icon("eye")}</button></div></div>
      <button class="button primary login-submit" type="submit">登录工作台 {icon("arrow")}</button></form><div class="login-footer">{icon("shield")} 仅限授权管理员访问</div></div><span class="login-bottom">XITA CONSOLE / 授权管理</span></main></div>''')


def view_dashboard():
    now = int(time.time())
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0]
        available = conn.execute("SELECT COUNT(*) FROM cards WHERE status='ok' AND (expire_ts=0 OR expire_ts>=?) AND (kind!='点数卡' OR points>0)", (now,)).fetchone()[0]
        bound = conn.execute("SELECT COUNT(*) FROM cards WHERE bound_machine IS NOT NULL").fetchone()[0]
        expired = conn.execute("SELECT COUNT(*) FROM cards WHERE expire_ts>0 AND expire_ts<?", (now,)).fetchone()[0]
        logins = conn.execute("SELECT COUNT(*) FROM logs WHERE action IN ('login','api')").fetchone()[0]
        recent = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 6").fetchall()
        days = []
        today = time.mktime(time.localtime(now)[:3] + (0, 0, 0, 0, 0, -1))
        for offset in range(6, -1, -1):
            start = int(today - offset * 86400)
            count = conn.execute("SELECT COUNT(*) FROM logs WHERE action IN ('login','api') AND ts>=? AND ts<?", (start, start + 86400)).fetchone()[0]
            days.append((time.strftime("%m/%d", time.localtime(start)), count))
    actions = f'<a class="button secondary" href="/export.csv">{icon("download")} 导出卡密</a><a class="button primary" href="/new">{icon("plus")} 生成卡密</a>'
    stats = ""
    for name, value, symbol, color, note in [("卡密总量", total, "card", "blue", "已创建的全部卡密"), ("可用卡密", available, "shield", "green", "有效且未被封禁"), ("已绑定设备", bound, "link", "purple", "已完成设备绑定的卡密"), ("已过期卡密", expired, "clock", "amber", "可前往卡密管理续期"), ("累计验证", logins, "activity", "slate", "客户端与接口验证次数")]:
        stats += f'<div class="stat-card"><div class="stat-card-top"><span class="stat-label">{name}</span><span class="stat-icon {color}">{icon(symbol)}</span></div><div class="stat-value">{value:,}</div><div class="stat-note">{note}</div></div>'
    peak = max(1, max(n for _, n in days))
    bars = "".join(f'<div class="chart-day"><span class="chart-count">{n}</span><div class="chart-track"><div class="chart-bar {"is-today" if i == 6 else ""}" style="height:{n / peak * 100:.2f}%"></div></div><span class="chart-label">{day}</span></div>' for i, (day, n) in enumerate(days))
    body = heading("数据概览", "所有授权动态，一目了然。", actions)
    body += f'''<section class="welcome-banner"><div class="welcome-copy"><span>管理有序，业务从容</span><h2>每一份授权，都在掌握之中。</h2><p>集中管理卡密、设备与使用记录，让日常操作更简单。</p></div><div class="banner-mark" aria-hidden="true">{icon("shield")}</div></section>
      <section class="stats-grid" aria-label="授权统计">{stats}</section><div class="dashboard-grid"><section class="panel"><div class="panel-head"><div><h2 class="panel-title">验证趋势</h2><p class="panel-description">最近 7 天的成功验证次数</p></div><span class="badge neutral">近 7 天 · {sum(n for _, n in days):,} 次</span></div><div class="chart-bars" role="img" aria-label="{html.escape('；'.join(day + '：' + str(n) + '次' for day, n in days))}">{bars}</div></section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">快捷操作</h2><p class="panel-description">常用功能，随手可达</p></div></div><div class="quick-links"><a class="quick-link" href="/new"><span class="quick-icon blue">{icon("plus")}</span><span><strong>批量生成卡密</strong><small>时间卡、永久卡与点数卡</small></span>{icon("arrow")}</a><a class="quick-link" href="/cards"><span class="quick-icon purple">{icon("card")}</span><span><strong>管理现有卡密</strong><small>查询、续期与设备解绑</small></span>{icon("arrow")}</a><a class="quick-link" href="/logs"><span class="quick-icon green">{icon("logs")}</span><span><strong>查看操作日志</strong><small>追踪验证与管理记录</small></span>{icon("arrow")}</a></div></section></div>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">最近动态</h2><p class="panel-description">最新的授权验证与管理记录</p></div><a class="text-link" href="/logs">查看全部 {icon("arrow")}</a></div><div class="table-scroll"><table><thead><tr><th>发生时间</th><th>关联卡密</th><th>设备标识</th><th>动作</th><th>说明</th></tr></thead><tbody>{log_rows(recent)}</tbody></table></div></section>'''
    return page("概览", body, "admin")


def view_cards(q="", st="", page_no=1, notice=""):
    per = 20
    where, args = [], []
    if q:
        where.append("(card LIKE ? OR bound_machine LIKE ? OR note LIKE ?)")
        args.extend(["%" + q + "%"] * 3)
    filters = {"ok": "status='ok' AND (expire_ts=0 OR expire_ts>=cast(strftime('%s','now') as integer)) AND (kind!='点数卡' OR points>0)", "bound": "bound_machine IS NOT NULL", "expired": "expire_ts>0 AND expire_ts<cast(strftime('%s','now') as integer)", "banned": "status='banned'"}
    if st in filters:
        where.append(filters[st])
    else:
        st = ""
    clause = " WHERE " + " AND ".join(where) if where else ""
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM cards" + clause, args).fetchone()[0]
        pages = max(1, (total + per - 1) // per)
        try:
            page_no = max(1, min(int(page_no), pages))
        except (TypeError, ValueError):
            page_no = 1
        rows = conn.execute("SELECT * FROM cards" + clause + " ORDER BY created_at DESC, card LIMIT ? OFFSET ?", args + [per, (page_no - 1) * per]).fetchall()
    def list_url(p=1, state=st):
        return "/cards?" + urllib.parse.urlencode({"q": q, "st": state, "p": p})
    tabs = "".join('<a class="tab %s" href="%s" %s>%s</a>' % ("active" if key == st else "", html.escape(list_url(state=key), quote=True), 'aria-current="page"' if key == st else "", label) for key, label in [("", "全部卡密"), ("ok", "可用"), ("bound", "已绑定"), ("expired", "已过期"), ("banned", "已封禁")])
    trs = ""
    for r in rows:
        card = html.escape(r["card"])
        url = "/card/" + urllib.parse.quote(r["card"], safe="")
        controls = action_form(r["card"], "renew:30", "+30 天", message="将这张卡密续期 30 天，确认继续？")
        controls += action_form(r["card"], "unbind", "解绑", message="解绑后，此卡密可在其他设备使用。确认解绑？")
        controls += action_form(r["card"], "unban" if r["status"] != "ok" else "ban", "解封" if r["status"] != "ok" else "封禁", "secondary" if r["status"] != "ok" else "danger", "确认调整这张卡密的封禁状态？")
        trs += f'<tr><td><input type="checkbox" class="row-check" name="sel" value="{card}" form="batch-form" aria-label="选择 {card}"></td><td><div class="card-cell"><a class="mono card-code" href="{url}">{card}</a>{copy_button(r["card"])}</div></td><td><span class="card-kind">{html.escape(r["kind"])}</span></td><td>{badge(r)}</td><td class="expiry-cell">{card_expiry(r)}</td><td><span class="mono machine-code">{html.escape(r["bound_machine"] or "未绑定")}</span></td><td class="log-time">{time.strftime("%m-%d %H:%M", time.localtime(r["created_at"]))}</td><td class="note-cell">{html.escape(r["note"] or "—")}</td><td><div class="table-actions">{controls}<a class="button ghost small" href="{url}">详情</a></div></td></tr>'
    shown = sorted({1, pages, *range(max(1, page_no - 2), min(pages, page_no + 2) + 1)})
    pager = []
    previous = 0
    for p in shown:
        if previous and p - previous > 1:
            pager.append('<span class="muted">…</span>')
        pager.append('<a class="page-link %s" href="%s" %s>%d</a>' % ("active" if p == page_no else "", html.escape(list_url(p), quote=True), 'aria-current="page"' if p == page_no else "", p))
        previous = p
    batch = f'''<form id="batch-form" class="toolbar batch-toolbar" method="post" action="/cards/batch" data-confirm="确认对所选卡密执行批量操作？">{csrf_field()}<label class="batch-check-all"><input type="checkbox" id="check-all" aria-label="全选本页"> 全选</label><span class="muted" id="batch-count">已选 0 张</span><select name="act" aria-label="批量操作"><option value="ban">批量封禁</option><option value="unban">批量解封</option><option value="unbind">批量解绑</option><option value="renew:30">批量续期 30 天</option><option value="renew:365">批量续期 365 天</option><option value="delete">批量删除</option></select><button class="button secondary small" type="submit">执行</button></form>'''
    body = heading("卡密管理", "查询与维护每一张卡密，掌握完整授权状态。", f'<a class="button secondary" href="/export.csv">{icon("download")} 导出全部</a><a class="button primary" href="/new">{icon("plus")} 生成卡密</a>')
    if notice:
        body += f'<div class="notice" role="status">{html.escape(notice)}</div>'
    body += f'''<section class="panel"><div class="tabs" aria-label="卡密状态">{tabs}</div><form class="toolbar" method="get" action="/cards"><div class="search-field"><span class="search-icon">{icon("search")}</span><input name="q" aria-label="搜索卡密、设备或备注" value="{html.escape(q, quote=True)}" placeholder="搜索卡密、设备标识或备注…"></div><input type="hidden" name="st" value="{st}"><button class="button primary" type="submit">搜索</button>{'<a class="button ghost" href="/cards">清空条件</a>' if q or st else ''}<span class="toolbar-count">共 <strong>{total:,}</strong> 张卡密</span></form>
      {batch}
      <div class="table-scroll"><table><thead><tr><th style="width:36px"></th><th>卡密 / 点击查看详情</th><th>授权类型</th><th>当前状态</th><th>有效期限</th><th>绑定设备</th><th>创建时间</th><th>备注</th><th>操作</th></tr></thead><tbody>{trs or empty_row(9, "没有找到匹配的卡密", "试试其他搜索条件，或生成你的第一批卡密。")}</tbody></table></div>
      <div class="panel-footer"><span class="muted">第 {page_no} / {pages} 页 · 每页 {per} 条</span><nav class="pagination" aria-label="卡密分页">{'<a class="page-link" href="' + html.escape(list_url(page_no - 1), quote=True) + '">上一页</a>' if page_no > 1 else ''}{''.join(pager)}{'<a class="page-link" href="' + html.escape(list_url(page_no + 1), quote=True) + '">下一页</a>' if page_no < pages else ''}</nav></div></section>'''
    return page("卡密列表", body, "admin")


def view_new(msg="", values=None):
    values = values or {}
    selected = values.get("kind", "时间卡")
    value = lambda key, default: html.escape(str(values.get(key, default)), quote=True)
    types = ""
    for kind, symbol, text in [("时间卡", "clock", "首次使用开始计时"), ("永久卡", "shield", "长期有效，无需续期"), ("点数卡", "activity", "每次验证消耗 1 点")]:
        types += f'<label class="type-option"><input type="radio" name="kind" value="{kind}" {"checked" if selected == kind else ""}><span class="type-icon">{icon(symbol)}</span><strong>{kind}</strong><small>{text}</small></label>'
    error = f'<div class="notice error" role="alert">{html.escape(msg)}</div>' if msg else ""
    body = heading("生成卡密", "选好授权方式，轻松创建新的一批卡密。", '<a class="button secondary" href="/cards">返回卡密列表</a>')
    body += f'''<div class="form-layout"><section class="panel form-panel"><div class="panel-head"><div><h2 class="panel-title">配置授权</h2><p class="panel-description">一次最多生成 500 张，生成后可复制或下载。</p></div><span class="step-label">01 / 创建</span></div><form id="create-form" class="panel-body" method="post" action="/new">{csrf_field()}{error}
      <fieldset class="field type-field"><legend class="field-label">授权类型</legend><div class="type-options">{types}</div></fieldset>
      <div class="field-row"><div class="field"><label class="field-label" for="quantity">生成数量 <span class="required-mark">*</span></label><input id="quantity" name="num" type="number" min="1" max="500" step="1" value="{value('num', 10)}" required><span class="field-help">支持 1–500 张卡密</span></div>
      <div class="field" data-kind-field="时间卡" {'hidden' if selected != '时间卡' else ''}><label class="field-label" for="days">授权天数 <span class="required-mark">*</span></label><input id="days" name="days" type="number" min="1" max="36500" step="1" value="{value('days', 30)}" {'required' if selected == '时间卡' else 'disabled'}><div class="preset-row"><button class="preset" type="button" data-days="7">7 天</button><button class="preset" type="button" data-days="30">30 天</button><button class="preset" type="button" data-days="90">90 天</button><button class="preset" type="button" data-days="365">365 天</button></div></div>
      <div class="field" data-kind-field="点数卡" {'hidden' if selected != '点数卡' else ''}><label class="field-label" for="points">初始点数 <span class="required-mark">*</span></label><input id="points" name="points" type="number" min="1" max="100000000" step="1" value="{value('points', 100)}" {'required' if selected == '点数卡' else 'disabled'}><span class="field-help">每验证一次扣除 1 点，扣完即失效。</span></div></div>
      <div class="field"><label class="field-label" for="note">批次备注 <span class="muted">选填</span></label><input id="note" name="note" maxlength="200" value="{value('note', '')}" placeholder="例如：10 月客户续费 / 内部测试"><span class="field-help">备注会出现在卡密列表，方便后续检索。</span></div><div class="notice warning">{icon("clock")} 时间卡在首次验证成功后开始计时；点数卡每次验证都会扣点。</div>
      <div class="form-submit"><button class="button primary" type="submit">{icon("plus")} 生成卡密</button><span class="muted">生成后可立即分发使用</span></div></form></section>
      <aside class="help-panel"><section class="panel"><div class="panel-head"><h2 class="panel-title">本次生成预览</h2>{icon("card")}</div><div class="panel-body"><div class="preview-card"><span>XITA / ACCESS</span><strong id="summary-kind">{html.escape(selected)}</strong><div>•••• &nbsp; •••• &nbsp; •••• &nbsp; ••••</div><small>西塔授权卡密</small></div><dl class="form-summary"><div><dt>生成数量</dt><dd><span id="summary-quantity">{value('num', 10)}</span> 张</dd></div><div><dt>授权期限</dt><dd id="summary-validity">{value('days', 30)} 天</dd></div><div><dt>初始状态</dt><dd><span class="badge ok">未使用</span></dd></div></dl></div></section><div class="help-note">{icon("shield")}<div><strong>按业务选择合适的授权</strong><p>周期订阅用时间卡，长期授权用永久卡，按次服务用点数卡。</p></div></div></aside></div>'''
    return page("生成卡密", body, "admin")


def view_created(made):
    codes = html.escape("\n".join(made))
    body = heading("卡密已就绪", "复制或下载本次结果，即可分发给用户。", '<a class="button secondary" href="/new">继续生成</a>')
    body += f'''<section class="panel result-panel"><div class="panel-head"><div><h2 class="panel-title">已成功生成 {len(made)} 张卡密</h2><p class="panel-description">本批次卡密已保存，也可在卡密管理中查询。</p></div><span class="badge ok">生成成功</span></div><div class="panel-body"><label class="field-label" for="generated-cards">本次生成结果</label><textarea id="generated-cards" class="mono result-list" rows="12" readonly spellcheck="false">{codes}</textarea><div class="action-group"><button class="button primary" type="button" data-copy-target="#generated-cards">{icon("copy")} 复制全部</button><button id="download-cards" class="button secondary" type="button">{icon("download")} 下载 TXT</button><a class="button ghost" href="/cards">前往卡密管理 {icon("arrow")}</a></div></div></section>'''
    return page("生成结果", body, "admin")


def view_card_detail(card, notice=""):
    with db() as conn:
        r = conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
        if not r:
            return page("卡密详情", heading("卡密不存在", "卡密可能已被删除，请返回列表查询。", '<a class="button secondary" href="/cards">返回卡密列表</a>'), "admin")
        logs = conn.execute("SELECT * FROM logs WHERE card=? ORDER BY id DESC LIMIT 50", (card,)).fetchall()
    body = heading("卡密详情", "查看授权信息、绑定设备与完整使用记录。", '<a class="button secondary" href="/cards">返回卡密列表</a>')
    if notice:
        body += f'<div class="notice success" role="status">{icon("check")}{html.escape(notice)}</div>'
    details = ""
    for label, content in [("授权类型", html.escape(r["kind"])), ("当前状态", badge(r)), ("有效期限", card_expiry(r)), ("剩余点数", str(r["points"]) if r["kind"] == "点数卡" else "不适用"), ("绑定设备", html.escape(r["bound_machine"] or "尚未绑定")), ("绑定次数", str(r["bind_count"])), ("创建时间", fmt_ts(r["created_at"])), ("备注", html.escape(r["note"] or "未填写"))]:
        details += f'<div class="detail-item"><dt>{label}</dt><dd>{content}</dd></div>'
    controls = action_form(card, "renew:30", "续期 30 天", message="将此卡密续期 30 天，确认继续？") + action_form(card, "renew:365", "续期 365 天", message="将此卡密续期 365 天，确认继续？")
    controls += action_form(card, "unbind", "解绑设备", message="解绑后，此卡密可在其他设备使用。确认解绑？")
    controls += action_form(card, "reset", "重置为未使用", message="重置会清空绑定设备、到期时间与绑定次数。确认重置？")
    controls += action_form(card, "unban" if r["status"] != "ok" else "ban", "解除封禁" if r["status"] != "ok" else "封禁卡密", "secondary" if r["status"] != "ok" else "danger", "确认调整这张卡密的封禁状态？")
    controls += action_form(card, "delete", "删除卡密", "danger", "删除后无法恢复这张卡密，关联日志将保留。确认删除？")
    body += f'''<section class="panel"><div class="panel-head"><div><span class="eyebrow">LICENSE / 授权凭证</span><div class="detail-card-code mono">{html.escape(card)} {copy_button(card)}</div></div>{badge(r)}</div><dl class="detail-grid">{details}</dl><div class="panel-footer action-group">{controls}</div></section><section class="panel"><div class="panel-head"><div><h2 class="panel-title">此卡密的最近记录</h2><p class="panel-description">最多显示最近 50 条验证与管理操作。</p></div><span class="badge neutral">{len(logs)} 条记录</span></div><div class="table-scroll"><table><thead><tr><th>发生时间</th><th>设备标识</th><th>动作</th><th>说明</th></tr></thead><tbody>{log_rows(logs, False)}</tbody></table></div></section>'''
    return page("卡密详情", body, "admin")


def view_settings(msg="", err=""):
    conf = load_conf()
    body = heading("设置与安全", "修改管理密码，查看当前安全状态。", '<a class="button secondary" href="/">返回概览</a>')
    if msg:
        body += f'<div class="notice success" role="status">{icon("check")}{html.escape(msg)}</div>'
    if err:
        body += f'<div class="notice error" role="alert">{html.escape(err)}</div>'
    rows = [
        ("密码哈希算法", "PBKDF2-HMAC-SHA256（%d 轮 + 随机盐）" % PBKDF2_ROUNDS),
        ("登录失败限制", "%d 次失败锁定 %d 分钟" % (LOGIN_MAX_FAIL, LOGIN_LOCK_SECONDS // 60)),
        ("CSRF 防护", "同源自检 + 双提交 Token（表单隐藏域 csrf）"),
        ("会话 Cookie", "HttpOnly + SameSite=Strict"),
        ("校验接口限流", "每 IP 每分钟 %d 次" % API_MAX_PER_MIN),
        ("配置文件权限", "config.json 已设为 600" if os.path.isfile(CONF) else "未生成"),
    ]
    info = "".join(f'<div class="detail-item"><dt>{k}</dt><dd>{v}</dd></div>' for k, v in rows)
    body += f'''<div class="form-layout"><section class="panel form-panel"><div class="panel-head"><div><h2 class="panel-title">修改管理密码</h2><p class="panel-description">修改成功后所有会话立即失效，需要用新密码重新登录。</p></div><span class="step-label">SECURITY</span></div>
      <form class="panel-body" method="post" action="/settings">{csrf_field()}
      <div class="field"><label class="field-label" for="cur">当前密码 <span class="required-mark">*</span></label><input id="cur" name="cur" type="password" autocomplete="current-password" required></div>
      <div class="field"><label class="field-label" for="new1">新密码 <span class="required-mark">*</span></label><input id="new1" name="new" type="password" autocomplete="new-password" minlength="8" required><span class="field-help">至少 8 位，建议 12 位以上混合大小写与数字。</span></div>
      <div class="field"><label class="field-label" for="new2">确认新密码 <span class="required-mark">*</span></label><input id="new2" name="new2" type="password" autocomplete="new-password" minlength="8" required></div>
      <div class="form-submit"><button class="button primary" type="submit">{icon("shield")} 保存并重新登录</button></div></form></section>
      <aside class="help-panel"><section class="panel"><div class="panel-head"><h2 class="panel-title">当前安全状态</h2>{icon("shield")}</div><dl class="detail-grid">{info}</dl></section>
      <div class="help-note">{icon("logs")}<div><strong>公网访问提示</strong><p>后台走 HTTP 明文时，建议只在云安全组放行自己的 IP，或改用 SSH 隧道访问。</p></div></div></aside></div>'''
    return page("设置", body, "admin")


def view_logs():
    with db() as conn:
        rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    body = heading("操作日志", "每一次验证与变更，都有记录可查。", f'<a class="button secondary" href="/logs.csv">{icon("download")} 导出日志</a><a class="button secondary" href="/logs">刷新记录</a>')
    body += f'''<section class="panel"><div class="panel-head"><div><h2 class="panel-title">最近活动记录</h2><p class="panel-description">显示最近 200 条记录；搜索仅筛选当前记录。</p></div><span class="badge neutral"><span id="log-count">{len(rows)}</span> 条记录</span></div><div class="toolbar"><div class="search-field"><span class="search-icon">{icon("search")}</span><input type="search" data-filter-log aria-label="筛选当前日志" placeholder="搜索卡密、设备或操作说明…"></div></div><div class="table-scroll"><table><thead><tr><th>发生时间</th><th>关联卡密</th><th>设备标识</th><th>动作</th><th>说明</th></tr></thead><tbody>{log_rows(rows)}<tr data-log-empty hidden><td colspan="5"><div class="empty-state"><strong>没有匹配的记录</strong><span>试试其他关键词。</span></div></td></tr></tbody></table></div></section>'''
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

    def _csrf_cookie(self):
        return ("Set-Cookie", "csrf=%s; Path=/; SameSite=Strict" % csrf_token())

    def _same_origin(self):
        """同源校验：浏览器跨站 POST 必带 Origin/Referer，不同源直接拒"""
        host = (self.headers.get("Host") or "").lower()
        for h in ("Origin", "Referer"):
            v = self.headers.get(h)
            if v:
                netloc = urllib.parse.urlparse(v).netloc.lower()
                return netloc == host
        return True   # 没有 Origin/Referer 的（命令行/脚本）放行，靠 CSRF token 兜底

    def _csrf_ok(self, f):
        got = f.get("csrf", [""])[0]
        return bool(got) and hmac.compare_digest(got, csrf_token())

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return urllib.parse.parse_qs(raw)

    # --- 路由 ---
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p, qs = u.path, urllib.parse.parse_qs(u.query)
        if p in ("/assets/admin.css", "/assets/admin.js"):
            filename = os.path.basename(p)
            ctype = "text/css; charset=utf-8" if filename.endswith(".css") else "text/javascript; charset=utf-8"
            with open(os.path.join(HERE, "assets", filename), "rb") as asset:
                return self._send(200, asset.read(), ctype, [("Cache-Control", "no-cache")])
        if p.startswith("/api/verify"):
            return self.api_verify(qs)
        if p == "/login":
            return self._send(200, view_login(), extra=[self._csrf_cookie()])
        if not self._cookie_ok():
            return self._redirect("/login")
        if p in ("/", ""):
            return self._send(200, view_dashboard(), extra=[self._csrf_cookie()])
        if p == "/cards":
            return self._send(200, view_cards(qs.get("q", [""])[0], qs.get("st", [""])[0],
                                              qs.get("p", ["1"])[0], qs.get("notice", [""])[0]), extra=[self._csrf_cookie()])
        if p == "/new":
            return self._send(200, view_new(), extra=[self._csrf_cookie()])
        if p == "/logs":
            return self._send(200, view_logs(), extra=[self._csrf_cookie()])
        if p == "/logs.csv":
            return self.export_logs_csv()
        if p == "/settings":
            return self._send(200, view_settings(qs.get("msg", [""])[0]), extra=[self._csrf_cookie()])
        if p == "/export.csv":
            return self.export_csv()
        if p.startswith("/card/"):
            card = urllib.parse.unquote(p[len("/card/"):])
            return self._send(200, view_card_detail(card, qs.get("notice", [""])[0]), extra=[self._csrf_cookie()])
        if p == "/logout":
            return self._redirect("/login", [("Set-Cookie", "sess=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")])
        self._send(404, page("404", "<div class=card>页面不存在</div>", "admin"))

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        p = u.path
        ip = self.client_address[0]
        f = self._body()
        # ① 同源校验（CSRF 第一道）
        if not self._same_origin():
            return self._send(403, page("403", '<div class="panel" style="margin:40px auto;max-width:520px"><h2>拒绝跨站请求</h2><p class="muted">来源与本站不一致，操作已被拦截。</p></div>', None))
        # ② CSRF token（第二道）
        if not self._csrf_ok(f):
            return self._send(403, page("403", '<div class="panel" style="margin:40px auto;max-width:520px"><h2>校验失败</h2><p class="muted">缺少或错误的 CSRF token，请刷新页面重试。</p></div>', None))
        if p == "/login":
            if login_locked(ip):
                return self._send(429, view_login("尝试次数过多，请 %d 分钟后再试。" % (LOGIN_LOCK_SECONDS // 60)),
                                  extra=[self._csrf_cookie()])
            if check_password(f.get("pass", [""])[0]) and f.get("user", ["admin"])[0] == "admin":
                login_reset(ip)
                return self._redirect("/", [("Set-Cookie", "sess=%s; Path=/; HttpOnly; SameSite=Strict" % make_token()),
                                            self._csrf_cookie()])
            login_fail(ip)
            return self._send(200, view_login("账号或密码不对"), extra=[self._csrf_cookie()])
        if not self._cookie_ok():
            return self._redirect("/login")
        if p == "/new":
            values = {key: f.get(key, [""])[0] for key in ("num", "kind", "days", "points", "note")}
            kind, note = values["kind"], values["note"]
            try:
                num = int(values["num"])
                days = int(values["days"]) if kind == "时间卡" else 0
                points = int(values["points"]) if kind == "点数卡" else 0
                if kind not in ("时间卡", "永久卡", "点数卡") or not 1 <= num <= 500:
                    raise ValueError
                if kind == "时间卡" and not 1 <= days <= 36500:
                    raise ValueError
                if kind == "点数卡" and not 1 <= points <= 100000000:
                    raise ValueError
                if len(note) > 200:
                    raise ValueError
            except ValueError:
                res = self._send(400, view_new("请检查输入：数量为 1–500；时间卡天数、点数卡点数须为正整数，备注最多 200 字。", values),
                                 extra=[self._csrf_cookie()])
                return res
            made = create_cards(num, kind, days, points, note)
            return self._send(200, view_created(made), extra=[self._csrf_cookie()])
        if p == "/cards/batch":
            act = f.get("act", [""])[0]
            sel = f.get("sel", [])
            if not sel:
                return self._redirect("/cards?notice=" + urllib.parse.quote("没有选中任何卡密"))
            try:
                done, skipped, msg = do_batch(sel, act)
            except ValueError as exc:
                return self._send(400, view_cards(notice=str(exc)), extra=[self._csrf_cookie()])
            return self._redirect("/cards?notice=" + urllib.parse.quote(msg))
        if p == "/settings":
            cur = f.get("cur", [""])[0]
            new = f.get("new", [""])[0]
            new2 = f.get("new2", [""])[0]
            if not check_password(cur):
                return self._send(400, view_settings(err="当前密码不正确。"), extra=[self._csrf_cookie()])
            if len(new) < 8:
                return self._send(400, view_settings(err="新密码至少 8 位。"), extra=[self._csrf_cookie()])
            if new != new2:
                return self._send(400, view_settings(err="两次输入的新密码不一致。"), extra=[self._csrf_cookie()])
            if new == cur:
                return self._send(400, view_settings(err="新密码不能与当前密码相同。"), extra=[self._csrf_cookie()])
            set_password(new)
            return self._redirect("/login", [("Set-Cookie", "sess=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
                                             self._csrf_cookie()])
        if p.startswith("/card/") and p.endswith("/act"):
            card = urllib.parse.unquote(p[len("/card/"):-len("/act")])
            act = f.get("act", [""])[0]
            try:
                message = do_action(card, act)
            except ValueError as exc:
                return self._send(400, view_card_detail(card, str(exc)), extra=[self._csrf_cookie()])
            return self._redirect("/card/" + urllib.parse.quote(card, safe="") + "?notice=" + urllib.parse.quote(message))
        self._send(404, page("404", "<div class=card>页面不存在</div>", "admin"))

    # --- 接口 ---
    def api_verify(self, qs):
        ip = self.client_address[0]
        if not api_allowed(ip):
            return self._send(429, json.dumps({"ok": False, "msg": "请求过于频繁，请稍后再试."}, ensure_ascii=False),
                              "application/json; charset=utf-8")
        card = qs.get("card", [""])[0]
        machine = qs.get("machine", [""])[0]
        if not card:
            return self._send(400, json.dumps({"ok": False, "msg": "缺少 card"}, ensure_ascii=False),
                              "application/json; charset=utf-8")
        if not machine or not machine.strip():
            return self._send(400, json.dumps({"ok": False, "msg": "缺少 machine"}, ensure_ascii=False),
                              "application/json; charset=utf-8")
        ok, msg, extra = verify_card(card, machine)
        out = {"ok": ok, "msg": msg}
        out.update(extra)
        self._send(200, json.dumps(out, ensure_ascii=False), "application/json; charset=utf-8")

    def export_logs_csv(self):
        with db() as conn:
            rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 5000").fetchall()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["时间", "卡密", "设备标识", "动作", "说明"])
        for r in rows:
            w.writerow([fmt_ts(r["ts"]), r["card"] or "", r["machine"] or "", r["action"] or "", r["detail"] or ""])
        data = buf.getvalue().encode("utf-8-sig")
        self._send(200, data, "text/csv; charset=utf-8",
                   [("Content-Disposition", 'attachment; filename="logs.csv"')])

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
