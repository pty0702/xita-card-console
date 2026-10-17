"""客户端共用的 TLS 连接和证书指纹校验。"""
import hashlib
import socket
import ssl

from . import config


def connect(host, port, timeout):
    if not config.USE_TLS:
        return socket.create_connection((host, port), timeout)
    pin = config.CERT_SHA256
    if not isinstance(pin, str) or len(pin) != 64 or any(
            char not in "0123456789abcdefABCDEF" for char in pin):
        raise IOError("必须配置有效的服务器证书 SHA-256 指纹（64 位十六进制）")
    raw = socket.create_connection((host, port), timeout)
    secured = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # 信任配置的指纹，不使用 CA。
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        secured = ctx.wrap_socket(raw, server_hostname=host)
        got = hashlib.sha256(secured.getpeercert(binary_form=True) or b"").hexdigest()
        if got != pin.lower():
            raise IOError("服务器证书指纹不匹配（疑似中间人）")
        return secured
    except Exception:
        (secured if secured is not None else raw).close()
        raise
