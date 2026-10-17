#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""隔离检查两个客户端的 TLS 身份校验；不读实际配置、不联网。"""
import hashlib
from pathlib import Path
import ssl
import sys
import types
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
config = types.ModuleType("common.config")
config.KEY = b"isolated-tls-check-key"
config.PORT = 9000
config.USE_TLS = True
config.CERT_SHA256 = ""
sys.modules["common.config"] = config
from client import shell, tester


def rejects(call):
    try:
        call()
    except (OSError, ValueError, TypeError):
        return
    raise AssertionError("不安全的 TLS 配置或连接应被拒绝")


def main():
    cert = b"isolated-certificate-bytes"
    pin = hashlib.sha256(cert).hexdigest()
    for client in (shell, tester):
        for invalid in (None, "", " " * 64, "a" * 63, "g" * 64, 123):
            config.CERT_SHA256 = invalid
            with patch("socket.create_connection") as connect, patch("ssl.SSLContext"):
                rejects(lambda: client._tls_connect("unused.invalid", 9000, 1))
                connect.assert_not_called()

        for valid in (pin, pin.upper()):
            config.CERT_SHA256 = valid
            raw, wrapped, context = MagicMock(), MagicMock(), MagicMock()
            wrapped.getpeercert.return_value = cert
            context.wrap_socket.return_value = wrapped
            with patch("socket.create_connection", return_value=raw), \
                    patch("ssl.SSLContext", return_value=context):
                assert client._tls_connect("unused.invalid", 9000, 1) is wrapped
                assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
                assert context.check_hostname is False
                context.wrap_socket.assert_called_once_with(raw, server_hostname="unused.invalid")
                wrapped.getpeercert.assert_called_once_with(binary_form=True)
                wrapped.close.assert_not_called()

        config.CERT_SHA256 = "0" * 64
        raw, wrapped, context = MagicMock(), MagicMock(), MagicMock()
        wrapped.getpeercert.return_value = cert
        context.wrap_socket.return_value = wrapped
        with patch("socket.create_connection", return_value=raw), \
                patch("ssl.SSLContext", return_value=context):
            rejects(lambda: client._tls_connect("unused.invalid", 9000, 1))
            wrapped.close.assert_called()

        config.CERT_SHA256 = pin
        raw, context = MagicMock(), MagicMock()
        context.wrap_socket.side_effect = ssl.SSLError("隔离模拟握手失败")
        with patch("socket.create_connection", return_value=raw), \
                patch("ssl.SSLContext", return_value=context):
            rejects(lambda: client._tls_connect("unused.invalid", 9000, 1))
            raw.close.assert_called()

        config.USE_TLS = False
        config.CERT_SHA256 = ""
        raw = MagicMock()
        try:
            with patch("socket.create_connection", return_value=raw), patch("ssl.SSLContext") as context:
                assert client._tls_connect("unused.invalid", 9000, 1) is raw
                context.assert_not_called()
        finally:
            config.USE_TLS = True
    print("两个客户端的 pin 必填、指纹匹配、握手失败清理与开发开关检查通过")


if __name__ == "__main__":
    main()
