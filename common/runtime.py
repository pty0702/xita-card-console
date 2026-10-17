#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
西塔验证壳 · 运行时小工具
  * app_dir()      程序所在目录（打包成 exe 后就是 exe 所在目录）
  * load_server()  读取 server.ini / 环境变量，决定连哪台服务器
"""
import os
import sys

from . import config


def app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(sys.argv[0]))


def ini_path() -> str:
    return os.path.join(app_dir(), "server.ini")


def load_server(default_host="127.0.0.1", default_port=None):
    """
    优先级：环境变量 FJ_HOST / FJ_PORT  >  server.ini  >  默认值
    server.ini 格式：
        host=192.168.0.100
        port=9000
    """
    host = os.environ.get("FJ_HOST", "").strip()
    port = os.environ.get("FJ_PORT", "").strip()
    p = ini_path()
    if os.path.isfile(p):
        try:
            for line in open(p, "r", encoding="utf-8", errors="replace"):
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip().lower(), v.strip()
                if k == "host" and not host:
                    host = v
                elif k == "port" and not port:
                    port = v
        except Exception:
            pass
    return (host or default_host, int(port) if port else (default_port or config.PORT))


def write_server_ini(host, port, path=None):
    p = path or ini_path()
    with open(p, "w", encoding="utf-8") as f:
        f.write("# 西塔验证壳 · 服务器地址\n")
        f.write("host=%s\n" % host)
        f.write("port=%s\n" % port)
    return p
