#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
西塔验证壳 · Windows 窗口小工具
  clear_window_icon(root) —— 把窗口左上角（标题栏）图标换成全透明

原理：Windows 的标题栏图标来自窗口类图标（GCLP_HICON / GCLP_HICONSM）和 WM_SETICON。
      Tk 的 iconphoto 在这台机器上盖不住，所以直接用 ctypes 造一个「全透明单色图标」，
      通过 WM_SETICON + SetClassLongPtr 硬塞进去 —— 系统照样画，但画出来是全透明的。
"""
import ctypes
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

WM_SETICON = 0x0080
ICON_SMALL = 0
ICON_BIG = 1
GCLP_HICON = -14
GCLP_HICONSM = -34
GA_ROOT = 2


class ICONINFO(ctypes.Structure):
    _fields_ = [("fIcon", wintypes.BOOL),
                ("xHotspot", wintypes.DWORD),
                ("yHotspot", wintypes.DWORD),
                ("hbmMask", wintypes.HBITMAP),
                ("hbmColor", wintypes.HBITMAP)]


def _make_blank_icon(size=32):
    """造一个全透明图标：mask 全 1（透明），color 全 0"""
    row_bytes = ((size + 15) // 16) * 2          # 1bpp 每行字节数，按 WORD 对齐
    mask = b"\xff" * (row_bytes * size)          # 1 = 透明
    color = b"\x00" * (row_bytes * size)
    hbm_mask = gdi32.CreateBitmap(size, size, 1, 1, mask)
    hbm_color = gdi32.CreateBitmap(size, size, 1, 1, color)
    ii = ICONINFO(True, 0, 0, hbm_mask, hbm_color)
    hicon = user32.CreateIconIndirect(ctypes.byref(ii))
    return hicon, (hbm_mask, hbm_color)


def clear_window_icon(root):
    """把 Tk 窗口标题栏图标换成全透明；返回 True/False 方便排查"""
    try:
        root.update_idletasks()
    except Exception:
        pass
    try:
        hwnd = int(root.winfo_id())
    except Exception:
        return False
    try:
        top = user32.GetAncestor(wintypes.HWND(hwnd), GA_ROOT) or hwnd
    except Exception:
        top = hwnd
    ok = False
    for size in (16, 32):
        try:
            hicon, bmps = _make_blank_icon(size)
            if not hicon:
                continue
            user32.SendMessageW(wintypes.HWND(top), WM_SETICON, ICON_SMALL, hicon)
            user32.SendMessageW(wintypes.HWND(top), WM_SETICON, ICON_BIG, hicon)
            user32.SetClassLongPtrW(wintypes.HWND(top), GCLP_HICON, hicon)
            user32.SetClassLongPtrW(wintypes.HWND(top), GCLP_HICONSM, hicon)
            root._fj_hicon = hicon          # 防止被回收
            root._fj_bmps = bmps
            ok = True
        except Exception:
            continue
    return ok


def drop_icon(root):
    """给客户端用的统一入口：Tk 层 + Win32 层双保险"""
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
    try:
        root.iconbitmap(default="")
    except Exception:
        pass
    try:
        clear_window_icon(root)
    except Exception:
        pass
