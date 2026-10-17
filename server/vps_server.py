#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
西塔验证壳 · 服务端（授权服务器）

协议与云之盾同款骨架：
  请求：01 02 04 02 05 04 | u32 总长(LE) | u32 命令号(LE) | payload
  应答：01 02 04 02 05 04 | u32 总长(LE) | payload

payload 一律是 D1 FC | nonce | 密文（见 common/crypto.py）
命令号固定 666，真正的命令放在明文里，形如：
  验证33|<卡密>|<机器码>|<版本>
  验证频率|<卡密>|<机器码>
  是否异地登陆|<卡密>|<机器码>
  返回服务器文件|公告.txt
  解绑By卡号|<卡密>
  试用|<机器码>

启动：
  python server/vps_server.py            # 默认 0.0.0.0:9000
"""
import os
import socket
import socketserver
import sqlite3
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from common import crypto, config, ed25519  # noqa: E402

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

MAGIC = crypto.MAGIC
CMD_TEXT = 666
LOG_PATH = os.path.join(HERE, "server.log")
_lock = threading.Lock()


def log(msg: str):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        print(line, flush=True)
    except Exception:
        print(line.encode("utf-8", "replace").decode("utf-8", "replace"), flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ---------------- 数据库 ----------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS cards (
    card          TEXT PRIMARY KEY,
    kind          TEXT NOT NULL DEFAULT '时间卡',   -- 时间卡 / 点数卡 / 永久卡
    days          INTEGER NOT NULL DEFAULT 30,
    points        INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    expire_ts     INTEGER NOT NULL DEFAULT 0,       -- 0 = 永久
    bound_machine TEXT,
    bound_at      INTEGER,
    bind_count    INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'ok',       -- ok / banned
    note          TEXT
);
CREATE TABLE IF NOT EXISTS logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    card      TEXT,
    machine   TEXT,
    action    TEXT,
    detail    TEXT
);
"""


def db():
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    os.makedirs(config.PUBLIC_DIR, exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)
    pub = os.path.join(config.PUBLIC_DIR, "公告.txt")
    if not os.path.exists(pub):
        open(pub, "w", encoding="gbk").write("欢迎使用西塔验证壳，这是服务器里存放的公告！")


def add_log(conn, card, machine, action, detail=""):
    conn.execute("INSERT INTO logs(ts,card,machine,action,detail) VALUES(?,?,?,?,?)",
                 (int(time.time()), card, machine, action, detail))


# ---------------- 业务逻辑 ----------------
def fmt_time(ts):
    if not ts:
        return "永久"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def handle_login(card: str, machine: str, ver: str) -> str:
    if not machine or not machine.strip():
        return "机器码不能为空."
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        now = int(time.time())
        row = conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
        if row is None:
            add_log(conn, card, machine, "login", "卡号不存在")
            return "卡号不存在."
        if row["status"] != "ok":
            return "该卡号已被禁用."
        if row["expire_ts"] and now > row["expire_ts"]:
            return "卡号未登录或已经到期."
        if row["kind"] == "点数卡" and row["points"] <= 0:
            return "卡号点数已用完."
        bound = row["bound_machine"]
        if not bound:
            conn.execute("UPDATE cards SET bound_machine=?, bound_at=?, bind_count=bind_count+1 WHERE card=?",
                         (machine, now, card))
            bound = machine
            add_log(conn, card, machine, "bind", "首次绑定")
        elif bound != machine:
            add_log(conn, card, machine, "login", "异地/他机登录被拒 bound=%s" % bound)
            return "当前用户已登录到其他设备."
        if row["kind"] == "点数卡":
            conn.execute("UPDATE cards SET points=points-1 WHERE card=?", (card,))
        if row["kind"] == "时间卡" and row["expire_ts"] == 0:
            exp = now + row["days"] * 86400
            conn.execute("UPDATE cards SET expire_ts=? WHERE card=?", (exp, card))
        else:
            exp = row["expire_ts"]
        pts = row["points"] - (1 if row["kind"] == "点数卡" else 0)
        add_log(conn, card, machine, "login", "成功")
        return "验证成功|到期时间:%s|剩余点数:%d|授权类型:%s" % (fmt_time(exp), max(pts, 0), row["kind"])


def handle_heartbeat(card: str, machine: str) -> str:
    if not machine or not machine.strip():
        return "机器码不能为空."
    with db() as conn:
        row = conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
        if not row or row["status"] != "ok":
            return "卡号未登录或已经到期."
        if row["bound_machine"] and row["bound_machine"] != machine:
            return "当前用户已登录到其他设备."
        if row["expire_ts"] and int(time.time()) > row["expire_ts"]:
            return "卡号未登录或已经到期."
        return "1"


def handle_unbind(card: str, machine: str) -> str:
    with db() as conn:
        row = conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
        if not row:
            return "卡号不正确."
        conn.execute("UPDATE cards SET bound_machine=NULL, bound_at=NULL WHERE card=?", (card,))
        add_log(conn, card, machine, "unbind", "手动解绑")
        return "解绑成功."


def handle_trial(machine: str) -> str:
    """试用：按机器码发一张 1 天卡（每机只能领一次）"""
    now = int(time.time())
    with db() as conn:
        row = conn.execute("SELECT card FROM cards WHERE note=? AND kind='试用'",
                           ("machine:" + machine,)).fetchone()
        if row:
            return "该设备已领取过试用."
        card = "TR" + crypto.hashlib.sha256((machine + str(now)).encode()).hexdigest()[:30].upper()
        conn.execute(
            "INSERT INTO cards(card,kind,days,points,created_at,expire_ts,bound_machine,bound_at,bind_count,status,note) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (card, "试用", 1, 0, now, now + 86400, machine, now, 1, "ok", "machine:" + machine))
        add_log(conn, card, machine, "trial", "发放试用")
        return "验证成功|到期时间:%s|剩余点数:0|授权类型:试用" % fmt_time(now + 86400)


def handle_file(name: str) -> str:
    safe = os.path.basename(name)
    path = os.path.join(config.PUBLIC_DIR, safe)
    if not os.path.isfile(path):
        return "文件不存在:%s" % safe
    for enc in ("utf-8-sig", "utf-8", "gbk"):
        try:
            return open(path, "r", encoding=enc).read()
        except Exception:
            continue
    return open(path, "rb").read().decode("gbk", "replace")


def dispatch(text: str, peer: str):
    parts = text.split("|")
    cmd = parts[0]
    log("请求 %s cmd=%r args=%r" % (peer, cmd, parts[1:]))
    if cmd == "验证33":
        card = parts[1] if len(parts) > 1 else ""
        machine = parts[2] if len(parts) > 2 else ""
        ver = parts[3] if len(parts) > 3 else "1"
        return handle_login(card, machine, ver)
    if cmd == "验证频率":
        return handle_heartbeat(parts[1] if len(parts) > 1 else "",
                                parts[2] if len(parts) > 2 else "")
    if cmd == "是否异地登陆":
        return handle_heartbeat(parts[1] if len(parts) > 1 else "",
                                parts[2] if len(parts) > 2 else "")
    if cmd == "返回服务器文件":
        return handle_file(parts[1] if len(parts) > 1 else "")
    if cmd == "解绑By卡号":
        return handle_unbind(parts[1] if len(parts) > 1 else "",
                             parts[2] if len(parts) > 2 else "")
    if cmd == "试用":
        return handle_trial(parts[1] if len(parts) > 1 else "")
    return "非法命令."


# ---------------- 通讯 ----------------
def recv_exact(sock, n, buf):
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            return None, buf
        buf += chunk
    return buf[:n], buf[n:]


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = "%s:%d" % self.client_address
        buf = b""
        sock = self.request
        sock.settimeout(60)
        try:
            while True:
                head, buf = recv_exact(sock, 10, buf)
                if head is None:
                    return
                if head[:6] != MAGIC:
                    log("魔数不符 %s" % peer)
                    buf = b""
                    continue
                total = struct.unpack_from("<I", head, 6)[0]
                if total < 10 or total > 0x100000:
                    return
                rest, buf = recv_exact(sock, total - 10, buf)
                if rest is None:
                    return
                packet = head + rest
                cmd = struct.unpack_from("<I", packet, 10)[0]
                sealed = packet[14:]
                challenge = ""
                try:
                    plain = crypto.unseal(config.KEY, sealed)
                    text = plain.decode("gbk", "replace")
                except Exception as e:
                    log("解密失败 %s: %r" % (peer, e))
                    text = ""
                if cmd != CMD_TEXT:
                    reply_text = "非法命令."
                elif not text:
                    reply_text = "非法数据001"
                else:
                    base, challenge, client_ts = crypto.split_challenge(text)
                    if challenge:
                        now = int(time.time())
                        if abs(now - client_ts) > config.TS_WINDOW:
                            reply_text = "非法数据012"      # 请求时间戳过期
                        else:
                            reply_text = dispatch(base, peer)
                            # 验证成功时，附带一个「服务器签名过的本地授权」
                            # 客户端离线只验公钥签名 → 拿对称 KEY 也造不出可用的 license.dat
                            if reply_text.startswith("验证成功") and base.startswith("验证33|"):
                                parts = base.split("|")
                                card_ = parts[1] if len(parts) > 1 else ""
                                machine_ = parts[2] if len(parts) > 2 else ""
                                exp_, kind_ = "", ""
                                for seg in reply_text.split("|")[1:]:
                                    if seg.startswith("到期时间:"):
                                        exp_ = seg.split(":", 1)[1]
                                    elif seg.startswith("授权类型:"):
                                        kind_ = seg.split(":", 1)[1]
                                # 点数卡必须逐次在线扣点；SIG2 把类型纳入签名，禁止改成永久卡。
                                if kind_ in ("时间卡", "永久卡", "试用") and exp_:
                                    lic_msg = ("%s|%s|%s|%s" % (card_, machine_, exp_, kind_)).encode("gbk")
                                    lic_sig = ed25519.sign(PRIVATE_KEY, lic_msg)
                                    reply_text += "|授权=" + lic_sig.hex()
                    else:
                        reply_text = "非法数据013"           # 协议版本过旧（没带挑战值）
                # 回包带上签名：文本 | 挑战值 | 时间戳 | Ed25519 签名
                signed = crypto.sign_reply(PRIVATE_KEY, reply_text, challenge or "0" * 32)
                reply = crypto.pack_reply(crypto.seal(config.KEY, signed))
                sock.sendall(reply)
                log("应答 %s -> %s" % (peer, reply_text[:80]))
        except Exception as e:
            log("异常 %s: %r" % (peer, e))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    ssl_context = None
    handshake_timeout = 10

    def finish_request(self, request, client_address):
        if self.ssl_context is None:
            return super().finish_request(request, client_address)
        # 握手属于工作线程，慢连接不能阻塞主线程接收其他客户端。
        request.settimeout(self.handshake_timeout)
        try:
            with self.ssl_context.wrap_socket(request, server_side=True) as secured:
                self.RequestHandlerClass(secured, client_address, self)
        except OSError as exc:
            log("TLS 连接失败 %s:%d: %r" % (*client_address, exc))
        finally:
            request.close()


def load_private_key() -> bytes:
    path = os.path.join(config.KEY_DIR, "server_ed25519.key")
    if not os.path.isfile(path):
        raise SystemExit("缺少签名私钥：%s（先跑 tools/gen_keys.py）" % path)
    raw = open(path, "rb").read().strip()
    try:
        key = bytes.fromhex(raw.decode("ascii"))
    except Exception:
        key = raw
    if len(key) != 32:
        raise SystemExit("签名私钥长度不对（要 32 字节）")
    return key


def build_ssl_context():
    import ssl
    cert = os.path.join(config.KEY_DIR, "server.crt")
    key = os.path.join(config.KEY_DIR, "server.key")
    if not (os.path.isfile(cert) and os.path.isfile(key)):
        raise SystemExit("缺少 TLS 证书：%s" % cert)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


PRIVATE_KEY = b"\x00" * 32


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=config.HOST)
    ap.add_argument("--port", type=int, default=config.PORT)
    ap.add_argument("--no-tls", action="store_true")
    args = ap.parse_args()
    init_db()
    PRIVATE_KEY = load_private_key()
    log("西塔验证壳服务端启动 %s:%d（TLS=%s，签名公钥 %s…）数据库 %s"
        % (args.host, args.port, (config.USE_TLS and not args.no_tls),
           config.PUBLIC_KEY_HEX[:16], config.DB_PATH))
    with Server((args.host, args.port), Handler) as srv:
        if config.USE_TLS and not args.no_tls:
            srv.ssl_context = build_ssl_context()
        srv.serve_forever()
