#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""隔离检查授权签名和 TLS 慢握手；仅使用项目内临时文件与随机回环端口。"""
from contextlib import contextmanager, redirect_stdout
import io
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import sys
import tempfile
import threading
import time
from types import ModuleType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import common
from common import crypto, ed25519
from tools import gen_keys


def main():
    artifacts = ROOT / "artifacts" / "server-security"
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=artifacts) as folder:
        folder = Path(folder)
        config = ModuleType("common.config")
        config.KEY = bytes(range(32))
        config.DB_PATH = str(folder / "cards.db")
        config.PUBLIC_DIR = str(folder / "public")
        config.KEY_DIR = str(folder / "keys")
        config.TS_WINDOW = 60
        # 导入前注入配置，禁止加载本机真实配置、密钥和卡库。
        with patch.dict(sys.modules, {"common.config": config}), \
                patch.object(common, "config", config, create=True):
            from server import vps_server as tcp
            from common import tls
        original_db = tcp.db

        @contextmanager
        def isolated_db():
            conn = original_db()
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

        secret, public = ed25519.gen_keypair()
        with patch.object(tcp, "config", config), patch.object(tls, "config", config), \
                patch.object(tcp, "db", isolated_db), patch.object(tcp, "PRIVATE_KEY", secret), \
                patch.object(tcp, "log", lambda message: None):
            with tcp.db() as conn:
                conn.executescript(tcp.SCHEMA)
                now = int(time.time())
                conn.executemany(
                    "INSERT INTO cards(card,kind,days,points,created_at,expire_ts) VALUES(?,?,?,?,?,?)",
                    [("point-last", "点数卡", 0, 1, now, 0),
                     ("point-two", "点数卡", 0, 2, now, 0),
                     ("timed", "时间卡", 3, 0, now, 0),
                     ("permanent", "永久卡", 0, 0, now, 0),
                     ("trial", "试用", 1, 0, now, now + 86400),
                     ("expired", "时间卡", 1, 0, now, now - 1)])

            def request(card, machine="test-machine"):
                challenge = crypto.new_challenge()
                text = crypto.with_challenge("验证33|%s|%s|1" % (card, machine), challenge)
                packet = crypto.pack_request(tcp.CMD_TEXT, crypto.seal(config.KEY, text.encode("gbk")))

                class MessageSocket:
                    def __init__(self):
                        self.data, self.reply = packet, b""

                    def settimeout(self, value):
                        pass

                    def recv(self, size):
                        data, self.data = self.data[:size], self.data[size:]
                        return data

                    def sendall(self, data):
                        self.reply += data

                sock = MessageSocket()
                tcp.Handler(sock, ("127.0.0.1", 12345), None)
                assert sock.reply[:6] == crypto.MAGIC
                assert struct.unpack_from("<I", sock.reply, 6)[0] == len(sock.reply)
                text, valid, reason = crypto.open_reply(
                    public, crypto.unseal(config.KEY, sock.reply[10:]), challenge)
                assert valid, reason
                return text

            for card, count in (("point-last", 1), ("point-two", 2)):
                for remaining in reversed(range(count)):
                    reply = request(card)
                    assert reply.startswith("验证成功") and "授权类型:点数卡" in reply
                    assert "剩余点数:%d" % remaining in reply and "|授权=" not in reply
                    with tcp.db() as conn:
                        assert conn.execute("SELECT points FROM cards WHERE card=?", (card,)).fetchone()[0] == remaining
                assert request(card) == "卡号点数已用完."

            for card, kind in (("timed", "时间卡"), ("permanent", "永久卡"), ("trial", "试用")):
                reply = request(card)
                fields = dict(part.split(":", 1) for part in reply.split("|")[1:] if ":" in part)
                signature = bytes.fromhex(reply.rsplit("|授权=", 1)[1])
                message = "%s|test-machine|%s" % (card, fields["到期时间"])
                assert ed25519.verify(public, (message + "|" + kind).encode("gbk"), signature)
                assert not ed25519.verify(public, message.encode("gbk"), signature), "旧三字段格式不得验过"
                assert not ed25519.verify(public, (message + "|点数卡").encode("gbk"), signature)
                assert "|授权=" not in request(card, "other-machine")
            for card in ("expired", "missing"):
                assert "|授权=" not in request(card)

            # 动态证书只写入临时目录；真实 TLS 检查不依赖线上证书。
            Path(config.KEY_DIR).mkdir()
            with patch.object(gen_keys, "KEY_DIR", config.KEY_DIR), redirect_stdout(io.StringIO()):
                config.CERT_SHA256 = gen_keys.gen_cert("127.0.0.1", days=1)
            config.USE_TLS = True
            context = tcp.build_ssl_context()
            accepted = threading.Event()

            class Probe(socketserver.BaseRequestHandler):
                def handle(self):
                    self.request.sendall(b"ready")

            class TestServer(tcp.Server):
                def finish_request(self, sock, address):
                    accepted.set()
                    return super().finish_request(sock, address)

            with TestServer(("127.0.0.1", 0), Probe) as server:
                server.ssl_context, server.handshake_timeout = context, 0.8
                worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
                worker.start()
                try:
                    address = server.server_address
                    with socket.create_connection(address, timeout=3) as slow:
                        assert accepted.wait(2), "慢连接未进入工作线程"
                        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        client_context.check_hostname = False
                        client_context.verify_mode = ssl.CERT_NONE
                        client_context.minimum_version = client_context.maximum_version = ssl.TLSVersion.TLSv1_2

                        def normal_client():
                            with socket.create_connection(address, timeout=3) as raw:
                                with client_context.wrap_socket(raw, server_hostname="localhost") as secured:
                                    assert secured.version() == "TLSv1.2"
                                    assert secured.recv(5) == b"ready"

                        normal_client()
                        slow.settimeout(3)
                        try:
                            assert slow.recv(1) == b"", "超时握手连接必须关闭"
                        except ConnectionResetError:
                            pass
                    # 非 TLS 流量也必须拒绝，且不得影响下一条正常连接。
                    with socket.create_connection(address, timeout=3) as invalid:
                        invalid.sendall(b"invalid TLS request")
                        try:
                            assert invalid.recv(1) == b""
                        except ConnectionResetError:
                            pass
                    normal_client()
                    with tls.connect(address[0], address[1], 3) as secured:
                        assert secured.recv(5) == b"ready", "正确指纹必须允许真实 TLS 连接"
                    with patch.object(config, "CERT_SHA256", "0" * 64):
                        try:
                            tls.connect(address[0], address[1], 3)
                        except OSError as exc:
                            assert "指纹不匹配" in str(exc)
                        else:
                            raise AssertionError("错误指纹必须拒绝真实 TLS 连接")
                finally:
                    server.shutdown()
                    worker.join(timeout=3)
                    assert not worker.is_alive()
    print("服务端隔离检查通过：点数在线扣点、SIG2 签名、TLS 慢握手超时与真实证书指纹校验。")


if __name__ == "__main__":
    main()
