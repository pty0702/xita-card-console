#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
西塔验证壳 · 客户端壳（登录界面 + 加密通讯 + 释放并启动被保护程序）

特点（和"origin2026激活补丁"同款体验）：
  * 卡密框 / 公告栏 / 记住卡密 / 自动登录 / 换绑
  * 机器码取 C: 卷序列号
  * 时间/永久/试用卡登录成功写服务器签名的 SIG2 授权，点数卡每次在线验证
  * 真正的程序是加密的 payload.bin，验证通过才解密释放并启动

用法：
  python client/shell.py                # 图形界面
  python client/shell.py --cli --card VIPFFFxxxx --verify-only  # 只验证，不启动程序
"""
import argparse
import ctypes
from datetime import datetime
import hashlib
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from common import crypto, config, runtime, tls  # noqa: E402

APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
INI = os.path.join(APP_DIR, "用户配置.ini")
LIC = os.path.join(APP_DIR, "license.dat")
PAYLOAD = os.path.join(APP_DIR, "payload.bin")


# ---------------- 机器码 ----------------
def machine_code() -> str:
    kernel32 = ctypes.windll.kernel32
    serial = ctypes.c_ulong()
    ok = kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p("C:\\"), None, 0,
        ctypes.byref(serial), None, None, None, 0)
    if ok:
        v = "%08X" % serial.value
        return "-".join(v[i:i + 4] for i in range(0, 8, 4)) + "-" + \
               hashlib.md5(("fj" + v).encode()).hexdigest()[:8].upper()
    return hashlib.md5(os.environ.get("COMPUTERNAME", "pc").encode()).hexdigest()[:19].upper()


# ---------------- 通讯 ----------------
_tls_connect = tls.connect


class Client:
    def __init__(self, host=None, port=None, timeout=8):
        h, p = runtime.load_server()
        self.host = host or h
        self.port = port or p
        self.timeout = timeout

    def call(self, text: str) -> str:
        challenge = crypto.new_challenge()
        req_text = crypto.with_challenge(text, challenge)
        s = _tls_connect(self.host, self.port, self.timeout)
        try:
            req = crypto.pack_request(crypto.CMD_TEXT if hasattr(crypto, "CMD_TEXT") else 666,
                                      crypto.seal(config.KEY, req_text.encode("gbk")))
            s.sendall(req)
            buf = b""
            while len(buf) < 10:
                chunk = s.recv(65536)
                if not chunk:
                    raise IOError("连接被关闭")
                buf += chunk
            total = struct.unpack_from("<I", buf, 6)[0]
            while len(buf) < total:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            plain = crypto.unseal(config.KEY, buf[10:])
            pk = bytes.fromhex(config.PUBLIC_KEY_HEX)
            reply, ok, why = crypto.open_reply(pk, plain, challenge, config.TS_WINDOW)
            if not ok:
                raise IOError(why)
            return reply
        finally:
            s.close()


# ---------------- 本地配置 / 授权缓存 ----------------
def read_ini():
    cfg = {"记住用户": "假", "自动登录": "假", "卡号": ""}
    if not os.path.isfile(INI):
        return cfg
    try:
        for line in open(INI, "r", encoding="gbk", errors="replace"):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                cfg[k] = v
    except Exception:
        pass
    return cfg


def write_ini(cfg):
    with open(INI, "w", encoding="gbk") as f:
        f.write("[程序配置]\n")
        for k in ("记住用户", "自动登录", "卡号"):
            f.write("%s=%s\n" % (k, cfg.get(k, "")))


def _license_message(card, machine, expire_text, kind):
    """严格限定离线卡种及到期字段，签名同时绑定卡种。"""
    fields = (card, machine, expire_text, kind)
    if any(not isinstance(value, str) or not value or "|" in value for value in fields):
        raise ValueError("授权字段缺失或无效")
    if kind == "永久卡":
        if expire_text != "永久":
            raise ValueError("永久卡授权到期字段无效")
    elif kind in ("时间卡", "试用"):
        fmt = "%Y-%m-%d %H:%M:%S"
        expires = datetime.strptime(expire_text, fmt)
        if expires.strftime(fmt) != expire_text or time.time() > expires.timestamp():
            raise ValueError("授权已过期或到期字段无效")
    else:
        raise ValueError("此卡种不支持离线授权")
    return "|".join(fields).encode("gbk")


def save_license(card, machine, expire_text, server_sig_hex="", kind=""):
    """只保存公钥验证通过的 SIG2 授权；缺少或损坏签名时拒绝。"""
    try:
        msg = _license_message(card, machine, expire_text, kind)
        sig = bytes.fromhex(server_sig_hex)
        if not crypto.ed25519.verify(bytes.fromhex(config.PUBLIC_KEY_HEX), msg, sig):
            return False
    except (ValueError, TypeError, OverflowError):
        return False
    with open(LIC, "wb") as f:
        f.write(b"SIG2" + len(msg).to_bytes(4, "little") + msg + sig)
    return True


def load_license(machine):
    if not os.path.isfile(LIC):
        return None
    try:
        with open(LIC, "rb") as f:
            raw = f.read()
        if raw[:4] != b"SIG2":
            return None
        n = int.from_bytes(raw[4:8], "little")
        if len(raw) != 8 + n + 64:
            return None
        msg, sig = raw[8:8 + n], raw[8 + n:]
        if not crypto.ed25519.verify(bytes.fromhex(config.PUBLIC_KEY_HEX), msg, sig):
            return None
        card, m, expire_text, kind = msg.decode("gbk").split("|")
        if m != machine:
            return None
        _license_message(card, m, expire_text, kind)
        return (card, expire_text)
    except Exception:
        return None


def accept_online_license(text, card, machine):
    """GUI/CLI 共用：在线成功后验证授权；点数卡只允许本次在线启动。"""
    parts = dict(p.split(":", 1) for p in text.split("|")[1:] if ":" in p)
    if parts.get("授权类型") == "点数卡":
        if os.path.isfile(LIC):
            os.remove(LIC)
        return True, "点数卡本次在线验证通过，不保存离线授权"
    signature = next((seg.split("=", 1)[1] for seg in text.split("|")
                      if seg.startswith("授权=")), "")
    if not save_license(card, machine, parts.get("到期时间", ""), signature,
                        parts.get("授权类型", "")):
        return False, "服务器授权签名缺失或无效，请重新在线验证"
    return True, "已保存本地授权 license.dat"


# ---------------- 释放并启动被保护程序 ----------------
def launch_payload():
    if not os.path.isfile(PAYLOAD):
        return False, "没有找到加密的程序体 payload.bin（先用 tools/pack.py 打包）"
    try:
        with open(PAYLOAD, "rb") as f:
            raw = f.read()
        if not raw.startswith(b"FJPK"):
            return False, "payload.bin 格式不对"
        body = crypto.unseal(config.KEY, raw[4:])
        tmp = os.path.join(tempfile.gettempdir(), "fj_%08x.exe" % random.getrandbits(32))
        with open(tmp, "wb") as f:
            f.write(body)
        subprocess.Popen([tmp], close_fds=True)
    except (OSError, ValueError) as e:
        return False, "启动被保护程序失败：%s" % e
    return True, tmp


def hide_console():
    """双击 exe 时不弹黑框（打包成 exe 后生效）"""
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


# ---------------- 图形界面 ----------------
def drop_icon(root):
    """去掉窗口左上角图标：Tk 层 + Win32 层双保险（见 common/winui.py）"""
    try:
        from common.winui import drop_icon as _drop
        if _drop(root):
            return
    except Exception:
        pass
    try:
        import tkinter as tk
        BLANK_PNG = (
            "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAE0lEQVR4nGNgGAWjYBSMAgYwAAAEEAAB"
            "sax5zAAAAABJRU5ErkJggg=="
        )
        img = tk.PhotoImage(data=BLANK_PNG)
        root.iconphoto(True, img)
        root._fj_icon = img
    except Exception:
        pass


def run_gui():
    import tkinter as tk
    from tkinter import messagebox, scrolledtext

    mc = machine_code()
    cfg = read_ini()

    root = tk.Tk()
    drop_icon(root)
    root.title("西塔验证壳")
    root.geometry("420x300")
    root.resizable(False, False)

    tk.Label(root, text="公告").place(x=10, y=8)
    notice = scrolledtext.ScrolledText(root, width=48, height=6)
    notice.place(x=10, y=30)
    notice.insert("1.0", "正在获取公告…")
    notice.config(state="disabled")

    tk.Label(root, text="卡密：").place(x=10, y=168)
    var_card = tk.StringVar(value=cfg.get("卡号", ""))
    entry = tk.Entry(root, textvariable=var_card, width=40)
    entry.place(x=50, y=168)

    var_remember = tk.BooleanVar(value=cfg.get("记住用户") == "真")
    var_auto = tk.BooleanVar(value=cfg.get("自动登录") == "真")
    tk.Checkbutton(root, text="记住卡密", variable=var_remember).place(x=20, y=200)
    tk.Checkbutton(root, text="自动登录", variable=var_auto).place(x=200, y=200)

    status = tk.StringVar(value="机器码：" + mc)
    tk.Label(root, textvariable=status, fg="#666").place(x=10, y=275)

    def set_notice(txt):
        notice.config(state="normal")
        notice.delete("1.0", "end")
        notice.insert("1.0", txt)
        notice.config(state="disabled")

    def do_login(card=None, silent=False):
        card = (card or var_card.get()).strip()
        if len(card) != config.CARD_LEN:
            if not silent:
                messagebox.showerror("错误", "卡密长度错误!")
            return False
        status.set("正在验证…")
        root.update()

        def work():
            try:
                txt = Client().call("验证33|%s|%s|1" % (card, mc))
            except Exception as e:
                txt = "连接服务器失败,请稍后重试.(%s)" % e
            root.after(0, lambda: done(txt, card))
        threading.Thread(target=work, daemon=True).start()
        return True

    result = {}

    def done(txt, card):
        result["txt"] = txt
        if txt.startswith("验证成功"):
            try:
                accepted, info = accept_online_license(txt, card, mc)
            except OSError as e:
                accepted, info = False, "保存授权失败：%s" % e
            if not accepted:
                messagebox.showerror("【网络验证提示】", info)
                status.set(info)
                return
            cfg2 = {"记住用户": "真" if var_remember.get() else "假",
                    "自动登录": "真" if var_auto.get() else "假",
                    "卡号": card if var_remember.get() else ""}
            write_ini(cfg2)
            messagebox.showinfo("信息：", txt.replace("|", "\n"))
            ok, info = launch_payload()
            status.set(info if not ok else "已启动被保护程序")
            if ok:
                root.after(1200, root.destroy)
        else:
            messagebox.showerror("【网络验证提示】", txt)
            status.set("机器码：" + mc)

    def fetch_notice():
        try:
            txt = Client().call("返回服务器文件|公告.txt")
        except Exception as e:
            txt = "获取公告失败：%s" % e
        set_notice(txt)

    threading.Thread(target=fetch_notice, daemon=True).start()

    btn_login = tk.Button(root, text="登 录", width=36, command=lambda: do_login())
    btn_login.place(x=40, y=232)
    btn_unbind = tk.Button(root, text="换 绑", width=8,
                           command=lambda: unbind())
    btn_unbind.place(x=330, y=232)

    def unbind():
        card = var_card.get().strip()
        if not card:
            messagebox.showwarning("提示", "先填卡密")
            return
        try:
            txt = Client().call("解绑By卡号|%s|%s" % (card, mc))
        except Exception as e:
            txt = "失败：%s" % e
        messagebox.showinfo("信息：", txt)

    # 自动登录 / 离线启动
    lic = load_license(mc)
    if var_auto.get() and var_card.get():
        root.after(800, lambda: do_login(var_card.get(), silent=True))
    elif lic:
        def start_offline():
            status.set("检测到本地授权：%s 到期" % lic[1])
            ok, info = launch_payload()
            if ok:
                root.destroy()
            else:
                status.set(info)
        root.after(600, start_offline)

    root.mainloop()


# ---------------- 命令行模式（测试/脚本用） ----------------
def run_cli(card, offline=False, host=None, port=None, verify_only=False):
    mc = machine_code()
    print("机器码：%s" % mc)
    if offline:
        lic = load_license(mc)
        print("本地授权：%r" % (lic,))
        if not lic:
            return 2
        if verify_only:
            print("离线验证通过，未启动被保护程序")
            return 0
        ok, info = launch_payload()
        print("离线启动：", (ok, info))
        return 0 if ok else 3
    try:
        txt = Client(host=host, port=port).call("验证33|%s|%s|1" % (card, mc))
    except Exception as e:
        print("连接服务器失败：%r" % (e,))
        return 1
    print("服务器回复：%s" % txt)
    if txt.startswith("验证成功"):
        try:
            accepted, info = accept_online_license(txt, card, mc)
        except OSError as e:
            accepted, info = False, "保存授权失败：%s" % e
        print(info)
        if not accepted:
            return 2
        write_ini({"记住用户": "真", "自动登录": "真", "卡号": card})
        if verify_only:
            print("在线验证通过，未启动被保护程序")
            return 0
        ok, info = launch_payload()
        print("启动被保护程序：", (ok, info))
        return 0 if ok else 3
    return 2


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--card", default="")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--verify-only", action="store_true", help="仅命令行验证授权，不释放或启动程序")
    ap.add_argument("--no-hide", action="store_true")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    a = ap.parse_args()
    if a.verify_only and not a.cli:
        ap.error("--verify-only 必须与 --cli 一起使用")
    if a.cli:
        sys.exit(run_cli(a.card, a.offline, a.host, a.port, a.verify_only))
    if not a.no_hide:
        hide_console()
    run_gui()
