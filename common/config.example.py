#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""首次部署时复制为 config.py；实际配置与密钥不进入版本库。"""
import os

# 服务端和客户端使用同一传输密钥，通过本机环境提供，不要提交真实值。
KEY = bytes.fromhex(os.environ["XITA_TRANSPORT_KEY_HEX"])
if len(KEY) < 32:
    raise ValueError("XITA_TRANSPORT_KEY_HEX 至少需要 32 字节的十六进制密钥")

PORT = 9000
HOST = "0.0.0.0"
PROTO_VER = "1"

# 初始化工具会把服务器验签公钥和证书指纹写入本机 config.py。
PUBLIC_KEY_HEX = ""
CERT_SHA256 = ""
USE_TLS = True
TS_WINDOW = 60

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE, "server", "cards.db")
PUBLIC_DIR = os.path.join(BASE, "server", "public")
KEY_DIR = os.path.join(BASE, "keys")
CARD_PREFIX = "VIPFFF"
CARD_LEN = 32
