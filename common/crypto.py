#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
西塔 · 加密与协议工具（纯标准库，无需 pip）

三层保护：
  ① 报文加密：每个报文带 8 字节随机 nonce，密钥流 = SHA256(key || nonce || counter)
     报文格式：D1 FC | nonce(8) | 密文
  ② 回包签名：服务器用 Ed25519 私钥对「明文 + 客户端挑战值 + 时间戳」签名
     客户端只放公钥 —— 拿不到私钥就签不出「验证成功」
  ③ 防重放：回包必须回显本次请求的挑战值，且时间戳在 60 秒内

所以就算别人反编译拿到 KEY（对称密钥），也伪造不了服务器：
他只能加密，不能签名。
"""
import hashlib
import hmac
import os
import struct
import time

try:                      # 作为包导入（正常情况）
    from . import ed25519
except ImportError:       # 直接运行本文件 / 打包时的兜底
    import ed25519  # type: ignore

MAGIC = bytes([0x01, 0x02, 0x04, 0x02, 0x05, 0x04])
SEP = b"\x1f"          # 回包内部分隔符（单元分隔符，正常文本里不会出现）


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + struct.pack(">Q", ctr)).digest()
        ctr += 1
    return bytes(out[:n])


def seal(key: bytes, data: bytes) -> bytes:
    """带随机 nonce 的加密封装：D1 FC | nonce | 密文"""
    nonce = os.urandom(8)
    return b"\xd1\xfc" + nonce + _xor(data, keystream(key, nonce, len(data)))


def unseal(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 10 or blob[:2] != b"\xd1\xfc":
        raise ValueError("bad sealed blob")
    nonce = blob[2:10]
    ct = blob[10:]
    return _xor(ct, keystream(key, nonce, len(ct)))


# --------- 和云之盾一模一样的静态流（想复刻老味道就用这个） ---------
def static_keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(key + struct.pack(">Q", ctr)).digest()
        ctr += 1
    return bytes(out[:n])


def seal_static(key: bytes, data: bytes) -> bytes:
    return b"\xd1\xfc" + _xor(data, static_keystream(key, len(data)))


def open_static(key: bytes, blob: bytes) -> bytes:
    if blob[:2] != b"\xd1\xfc":
        raise ValueError("bad blob")
    ct = blob[2:]
    return _xor(ct, static_keystream(key, len(ct)))


# --------- 包封装 ---------
def pack_request(cmd: int, payload: bytes) -> bytes:
    body = struct.pack("<I", cmd) + payload
    return MAGIC + struct.pack("<I", 10 + len(body)) + body


def pack_reply(payload: bytes) -> bytes:
    return MAGIC + struct.pack("<I", 10 + len(payload)) + payload


# --------- HMAC（本地授权文件用，仍保留） ---------
def sign(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def verify(key: bytes, msg: bytes, sig: bytes) -> bool:
    return hmac.compare_digest(sign(key, msg), sig)


# ================= 签名层（防伪造 / 防重放） =================
def new_challenge() -> str:
    """客户端每次请求一个新挑战值（32 位 hex）"""
    return os.urandom(16).hex()


def build_signed_text(text: str, challenge: str, ts: int = None) -> bytes:
    """服务器侧：把明文 + 挑战值 + 时间戳拼成待签名内容"""
    ts = int(ts if ts is not None else time.time())
    return text.encode("gbk") + SEP + challenge.encode() + SEP + str(ts).encode()


def sign_reply(sk: bytes, text: str, challenge: str, ts: int = None) -> bytes:
    """服务器侧：生成带签名的回包明文 = 文本 | 挑战值 | 时间戳 | 签名hex"""
    ts = int(ts if ts is not None else time.time())
    msg = build_signed_text(text, challenge, ts)
    sig = ed25519.sign(sk, msg)
    return msg + SEP + sig.hex().encode()


def open_reply(pk: bytes, plain: bytes, expect_challenge: str,
               ts_window: int = 60, now: int = None) -> tuple:
    """客户端侧：拆包 + 验签 + 查挑战值 + 查时间戳

    返回 (text, ok, reason)
    """
    try:
        parts = plain.split(SEP)
        if len(parts) != 4:
            return "", False, "报文结构不对（签名缺失）"
        text_b, ch_b, ts_b, sig_b = parts
        if not ch_b or not ts_b or not sig_b:
            return "", False, "报文结构不对（字段为空）"
        challenge = ch_b.decode("ascii", "replace")
        ts = int(ts_b.decode("ascii", "replace"))
        sig = bytes.fromhex(sig_b.decode("ascii", "replace"))
    except Exception:
        return "", False, "报文解析失败"
    # ① 挑战值必须是本次发的那个
    if not hmac.compare_digest(challenge, expect_challenge):
        return "", False, "挑战值不匹配（疑似重放）"
    # ② 时间戳窗口
    now = int(now if now is not None else time.time())
    if abs(now - ts) > ts_window:
        return "", False, "回包时间戳过期（疑似重放）"
    # ③ 验签（最关键的一步）
    msg = build_signed_text(text_b.decode("gbk", "replace"), challenge, ts)
    if not ed25519.verify(pk, msg, sig):
        return "", False, "签名验证失败（不是官方服务器）"
    return text_b.decode("gbk", "replace"), True, ""


def with_challenge(text: str, challenge: str, ts: int = None) -> str:
    """客户端侧：把挑战值/时间戳附加到请求文本后面"""
    ts = int(ts if ts is not None else time.time())
    return "%s|%s|%d" % (text, challenge, ts)


def split_challenge(payload_text: str) -> tuple:
    """服务器侧：从请求文本里拆出 (原文本, 挑战值, 时间戳)

    兼容不带挑战值的老请求（challenge 返回空串）
    """
    parts = payload_text.rsplit("|", 2)
    if len(parts) == 3 and len(parts[1]) == 32 and parts[2].isdigit():
        return parts[0], parts[1], int(parts[2])
    return payload_text, "", int(time.time())
