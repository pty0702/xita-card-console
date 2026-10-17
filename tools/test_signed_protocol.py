#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""隔离检查签名报文与密钥初始化工具，不读取实际密钥、不联网。"""
from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common import crypto, ed25519
from tools import gen_keys


def main():
    secret, public = ed25519.gen_keypair()
    text, challenge, now = "验证成功|授权类型:时间卡", crypto.new_challenge(), 1700000000
    signed = crypto.sign_reply(secret, text, challenge, now)
    assert crypto.open_reply(public, signed, challenge, now=now) == (text, True, "")
    assert not crypto.open_reply(public, signed, "0" * 32, now=now)[1]
    assert not crypto.open_reply(public, signed, challenge, now=now + 61)[1]
    tampered = bytes([signed[0] ^ 1]) + signed[1:]
    assert not crypto.open_reply(public, tampered, challenge, now=now)[1]
    assert not crypto.open_reply(ed25519.gen_keypair()[1], signed, challenge, now=now)[1]
    for malformed in (b"", b"plain", signed[:-1], b"a\x1fb\x1fc\x1fd"):
        assert not crypto.open_reply(public, malformed, challenge, now=now)[1]
    assert crypto.split_challenge(crypto.with_challenge(text, challenge, now)) == (text, challenge, now)

    artifacts = ROOT / "artifacts" / "signed-protocol"
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=artifacts) as folder:
        folder = Path(folder)
        conf = folder / "config.py"
        conf.write_text((ROOT / "common/config.example.py").read_text(encoding="utf-8-sig"), encoding="utf-8-sig")
        output = io.StringIO()
        with patch.multiple(gen_keys, KEY_DIR=str(folder / "keys"), CONFIG_PY=str(conf)), redirect_stdout(output):
            sk, pk = gen_keys.gen_ed25519()
            pin = gen_keys.gen_cert("127.0.0.1", days=1)
            gen_keys.patch_config(pk.hex(), pin)
        assert sk.hex() not in output.getvalue(), "初始化日志不得输出私钥"
        assert pk.hex() in conf.read_text(encoding="utf-8-sig")
        assert pin in conf.read_text(encoding="utf-8-sig")
        san = subprocess.check_output([gen_keys.find_openssl(), "x509", "-in",
                                       str(folder / "keys/server.crt"), "-noout", "-ext", "subjectAltName"])
        assert b"IP Address:127.0.0.1" in san
    print("签名报文、防重放检查与隔离证书初始化通过；未读取实际密钥。")


if __name__ == "__main__":
    main()
