#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成西塔验证壳需要的密钥与证书：

  1. Ed25519 签名密钥对
       keys/server_ed25519.key   私钥（32 字节 hex，只放服务器，权限 600）
       keys/server_ed25519.pub   公钥（hex，写进客户端 config.py）

  2. TLS 自签证书（10 年）
       keys/server.crt / keys/server.key
       证书 sha256 指纹写进 config.py 的 CERT_SHA256（客户端 pin）

  3. 自动把 PUBLIC_KEY_HEX / CERT_SHA256 写回 common/config.py

用法：
  python tools/gen_keys.py                    # 本机生成
  python tools/gen_keys.py --host 39.106.250.97   # 证书 SAN 里写服务器 IP
"""
import argparse
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from common import ed25519  # noqa: E402

CONFIG_PY = os.path.join(ROOT, "common", "config.py")
KEY_DIR = os.path.join(ROOT, "keys")


def find_openssl() -> str:
    for cand in (
        os.environ.get("OPENSSL_BIN"),
        "openssl",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    ):
        if not cand:
            continue
        try:
            subprocess.run([cand, "version"], capture_output=True, check=True)
            return cand
        except Exception:
            continue
    raise SystemExit("找不到 openssl，请先安装（Git for Windows 自带）或设置 OPENSSL_BIN")


def gen_ed25519():
    os.makedirs(KEY_DIR, exist_ok=True)
    sk, pk = ed25519.gen_keypair()
    key_path = os.path.join(KEY_DIR, "server_ed25519.key")
    pub_path = os.path.join(KEY_DIR, "server_ed25519.pub")
    with open(key_path, "wb") as f:
        f.write(sk.hex().encode() + b"\n")
    with open(pub_path, "wb") as f:
        f.write(pk.hex().encode() + b"\n")
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    print("签名私钥:", key_path)
    print("签名公钥:", pub_path)
    print("  公钥:", pk.hex())
    return sk, pk


def gen_cert(host: str, days: int = 3650):
    openssl = find_openssl()
    crt = os.path.join(KEY_DIR, "server.crt")
    key = os.path.join(KEY_DIR, "server.key")
    cfg = os.path.join(KEY_DIR, "openssl-san.cnf")
    san = "DNS:xita-verify,IP:%s" % host
    with open(cfg, "w", encoding="utf-8") as f:
        f.write("[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n\n"
                "[dn]\nCN=xita-verify\n\n"
                "[v3]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\nsubjectAltName=%s\n" % san)
    cmd = [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", key, "-out", crt, "-days", str(days),
           "-config", cfg]
    subprocess.run(cmd, check=True, capture_output=True)
    # 指纹 = DER 的 sha256
    der = subprocess.run([openssl, "x509", "-in", crt, "-outform", "DER"],
                         check=True, capture_output=True).stdout
    pin = hashlib.sha256(der).hexdigest()
    print("证书    :", crt)
    print("证书私钥:", key)
    print("指纹pin :", pin)
    return pin


def patch_config(pub_hex: str, pin: str):
    src = open(CONFIG_PY, "r", encoding="utf-8").read()
    src = re.sub(r'PUBLIC_KEY_HEX = "[0-9a-f]*"',
                 'PUBLIC_KEY_HEX = "%s"' % pub_hex, src)
    src = re.sub(r'CERT_SHA256 = "[0-9a-f]*"',
                 'CERT_SHA256 = "%s"' % pin, src)
    open(CONFIG_PY, "w", encoding="utf-8", newline="\n").write(src)
    print("已写回:", CONFIG_PY)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="39.106.250.97", help="证书 SAN 里的服务器 IP")
    ap.add_argument("--days", type=int, default=3650)
    a = ap.parse_args()
    sk, pk = gen_ed25519()
    pin = gen_cert(a.host, a.days)
    patch_config(pk.hex(), pin)
    print("\n完成。别忘了：")
    print("  1) 把 keys/server_ed25519.key、server.crt、server.key 上传到服务器 /opt/xita_shield/keys/")
    print("  2) 重新打包客户端（公钥和指纹已经写进 common/config.py）")


if __name__ == "__main__":
    main()
