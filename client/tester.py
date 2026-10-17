#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
西塔验证壳 · 客户测试工具（发给客户，验证卡密/服务器通不通）

界面：
  服务器地址（自动读 server.ini）  机器码
  [测试连接]  ← 拉公告，确认服务器可达
  卡密 [______________]  [验证卡密]
  结果区（显示 验证成功/到期时间/失败原因）
  [换绑]

用法：
  测试工具.exe                        # 图形界面
  测试工具.exe --host 1.2.3.4 --port 9000
  python client/tester.py --cli --host 127.0.0.1 --card VIPFFF...
"""
import argparse
import ctypes
import hashlib
import os
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from common import crypto, config, runtime, tls  # noqa: E402


def machine_code() -> str:
    try:
        kernel32 = ctypes.windll.kernel32
        serial = ctypes.c_ulong()
        ok = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p("C:\\"), None, 0, ctypes.byref(serial), None, None, None, 0)
        if ok:
            v = "%08X" % serial.value
            return "-".join(v[i:i + 4] for i in range(0, 8, 4)) + "-" + \
                   hashlib.md5(("fj" + v).encode()).hexdigest()[:8].upper()
    except Exception:
        pass
    return hashlib.md5(os.environ.get("COMPUTERNAME", "pc").encode()).hexdigest()[:19].upper()


_tls_connect = tls.connect


def rpc(host, port, text, timeout=6.0) -> str:
    challenge = crypto.new_challenge()
    req_text = crypto.with_challenge(text, challenge)
    s = _tls_connect(host, port, timeout)
    try:
        s.sendall(crypto.pack_request(666, crypto.seal(config.KEY, req_text.encode("gbk"))))
        buf = b""
        while len(buf) < 10:
            c = s.recv(4096)
            if not c:
                raise IOError("连接被关闭")
            buf += c
        total = struct.unpack_from("<I", buf, 6)[0]
        while len(buf) < total:
            c = s.recv(4096)
            if not c:
                break
            buf += c
        plain = crypto.unseal(config.KEY, buf[10:])
        pk = bytes.fromhex(config.PUBLIC_KEY_HEX)
        reply, ok, why = crypto.open_reply(pk, plain, challenge, config.TS_WINDOW)
        if not ok:
            raise IOError(why)
        return reply
    finally:
        s.close()


def hide_console():
    try:
        h = ctypes.windll.kernel32.GetConsoleWindow()
        if h:
            ctypes.windll.user32.ShowWindow(h, 0)
    except Exception:
        pass


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


def run_gui(host, port):
    import tkinter as tk
    from tkinter import messagebox, scrolledtext

    mc = machine_code()
    root = tk.Tk()
    drop_icon(root)
    root.title("卡密测试工具 · 西塔验证壳")
    root.geometry("460x360")
    root.resizable(False, False)

    tk.Label(root, text="服务器：", fg="#444").place(x=10, y=10)
    var_srv = tk.StringVar(value="%s:%d" % (host, port))
    tk.Entry(root, textvariable=var_srv, width=24).place(x=70, y=10)
    tk.Label(root, text="机器码：" + mc, fg="#666").place(x=250, y=10)

    tk.Label(root, text="公告").place(x=10, y=40)
    notice = scrolledtext.ScrolledText(root, width=54, height=5)
    notice.place(x=10, y=62)
    notice.insert("1.0", "点【测试连接】拉取公告…")
    notice.config(state="disabled")

    tk.Label(root, text="卡密：").place(x=10, y=180)
    var_card = tk.StringVar()
    tk.Entry(root, textvariable=var_card, width=42).place(x=50, y=180)

    out = tk.StringVar(value="")
    lbl = tk.Label(root, textvariable=out, fg="#0a7", justify="left", wraplength=440)
    lbl.place(x=10, y=250)

    def set_notice(t):
        notice.config(state="normal"); notice.delete("1.0", "end")
        notice.insert("1.0", t); notice.config(state="disabled")

    def parse_srv():
        s = var_srv.get().strip()
        if ":" in s:
            h, p = s.rsplit(":", 1)
            return h, int(p)
        return s, 9000

    def test_conn():
        h, p = parse_srv()
        out.set("正在连接 %s:%d …" % (h, p)); root.update()
        try:
            txt = rpc(h, p, "返回服务器文件|公告.txt")
            set_notice(txt)
            out.set("✔ 服务器可达")
        except Exception as e:
            out.set("✘ 连不上：%r\n（检查服务器是否启动 / 防火墙 / 端口映射）" % (e,))

    def do_login():
        h, p = parse_srv()
        card = var_card.get().strip()
        if len(card) != config.CARD_LEN:
            messagebox.showerror("错误", "卡密长度错误!（应为 %d 位）" % config.CARD_LEN)
            return
        out.set("验证中…"); root.update()
        try:
            txt = rpc(h, p, "验证33|%s|%s|1" % (card, mc))
        except Exception as e:
            out.set("✘ 连接服务器失败：%r" % (e,))
            return
        if txt.startswith("验证成功"):
            parts = dict(x.split(":", 1) for x in txt.split("|")[1:] if ":" in x)
            out.set("✔ 验证成功\n到期时间：%s\n剩余点数：%s\n授权类型：%s" % (
                parts.get("到期时间", "?"), parts.get("剩余点数", "?"), parts.get("授权类型", "?")))
        else:
            out.set("✘ " + txt)
            messagebox.showerror("【网络验证提示】", txt)

    def do_unbind():
        h, p = parse_srv()
        card = var_card.get().strip()
        if not card:
            messagebox.showwarning("提示", "先填卡密")
            return
        try:
            out.set(rpc(h, p, "解绑By卡号|%s|%s" % (card, mc)))
        except Exception as e:
            out.set("失败：%r" % (e,))

    tk.Button(root, text="测试连接", width=12, command=test_conn).place(x=10, y=212)
    tk.Button(root, text="验证卡密", width=16, command=do_login).place(x=330, y=178)
    tk.Button(root, text="换 绑", width=10, command=do_unbind).place(x=340, y=212)

    root.after(400, test_conn)
    root.mainloop()


def run_cli(host, port, card):
    mc = machine_code()
    print("服务器：%s:%d" % (host, port))
    print("机器码：%s" % mc)
    try:
        print("公告  ：%s" % rpc(host, port, "返回服务器文件|公告.txt")[:60])
    except Exception as e:
        print("公告  ：连接失败 %r" % (e,))
        return 1
    if card:
        txt = rpc(host, port, "验证33|%s|%s|1" % (card, mc))
        print("验证  ：%s" % txt)
        return 0 if txt.startswith("验证成功") else 2
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--card", default="")
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--no-hide", action="store_true")
    a = ap.parse_args()
    h0, p0 = runtime.load_server()
    h = a.host or h0            # 命令行 --host 优先
    p = a.port or p0
    if a.cli:
        sys.exit(run_cli(h, p, a.card))
    if not a.no_hide:
        hide_console()
    run_gui(h, p)
