#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
西塔验证壳 · 打包器（把要保护的程序加密成 payload.bin）

用法：
  python tools/pack.py --in  "C:\\path\\你的程序.exe" --out client/payload.bin
  python tools/pack.py --in  "C:\\path\\你的程序.exe"      # 默认输出到 client/payload.bin

壳运行时：验证通过 -> 解密 payload.bin -> 释放到 %TEMP% -> 启动。
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from common import crypto, config  # noqa: E402

DEFAULT_OUT = os.path.join(ROOT, "client", "payload.bin")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", required=True, help="要加密的程序（exe）")
    ap.add_argument("--out", dest="dst", default=DEFAULT_OUT)
    a = ap.parse_args()

    if not os.path.isfile(a.src):
        print("[!] 找不到 %s" % a.src)
        sys.exit(1)
    data = open(a.src, "rb").read()
    sealed = crypto.seal(config.KEY, data)
    blob = b"FJPK" + sealed
    os.makedirs(os.path.dirname(os.path.abspath(a.dst)), exist_ok=True)
    open(a.dst, "wb").write(blob)
    print("已加密：%s (%d 字节)" % (a.src, len(data)))
    print("输出  ：%s (%d 字节)" % (a.dst, len(blob)))
    print("把下面这些一起发给用户：")
    print("  client/shell.exe   （壳，登录界面）")
    print("  client/payload.bin （加密后的程序体）")
    print("  client/_internal/  （如果壳是 PyInstaller 打包的）")


if __name__ == "__main__":
    main()
