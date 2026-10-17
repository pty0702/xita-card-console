#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
纯标准库 Ed25519（RFC 8032）实现 —— 用于西塔验证壳的「回包签名」。

为什么不用现成库：
  * 服务器是 Ubuntu（有 openssl 但没有 pyca/cryptography 保证）
  * 客户端是 PyInstaller 打的单文件 exe，多一个依赖就多一份体积和风险
  * 这里只用到 ed25519，纯 hashlib + 大整数运算，零依赖

用法：
  sk, pk = gen_keypair()            # sk/pk 都是 32 字节
  sig = sign(sk, b"message")        # 64 字节
  verify(pk, b"message", sig) -> bool

自测：
  python3 ed25519.py                # 跑 RFC 8032 官方向量
"""
import hashlib

# ---------- 曲线参数 ----------
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _recover_x(y: int) -> int:
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


_BY = 4 * _inv(5) % P
_BX = _recover_x(_BY)
B = (_BX % P, _BY % P, 1, (_BX * _BY) % P)


def _add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _double(p1):
    x1, y1, z1, _ = p1
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    h = a + b
    e = h - (x1 + y1) * (x1 + y1) % P
    g = a - b
    f = c + g
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(p, e: int):
    if e == 0:
        return (0, 1, 1, 0)
    q = _mul(p, e // 2)
    q = _double(q)
    if e & 1:
        q = _add(q, p)
    return q


def _encode_point(p) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % P, y * zi % P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    out = bytearray(32)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def _decode_point(s: bytes):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _recover_x(y)
    if x & 1 != (s[31] >> 7) & 1:
        x = P - x
    return (x, y, 1, x * y % P)


def _hint(m: bytes) -> int:
    return int.from_bytes(_sha512(m), "little") % L


def _expand(sk: bytes):
    h = _sha512(sk)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(sk: bytes) -> bytes:
    """由 32 字节私钥推导公钥"""
    if len(sk) != 32:
        raise ValueError("私钥必须 32 字节")
    a, _ = _expand(sk)
    return _encode_point(_mul(B, a))


def sign(sk: bytes, msg: bytes) -> bytes:
    """签名，返回 64 字节（R || S）"""
    if len(sk) != 32:
        raise ValueError("私钥必须 32 字节")
    a, prefix = _expand(sk)
    pk = _encode_point(_mul(B, a))
    r = _hint(prefix + msg)
    R = _encode_point(_mul(B, r))
    k = _hint(R + pk + msg)
    S = (r + k * a) % L
    return R + S.to_bytes(32, "little")


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """验签；任何异常都当作失败"""
    try:
        if len(pk) != 32 or len(sig) != 64:
            return False
        A = _decode_point(pk)
        R = _decode_point(sig[:32])
        S = int.from_bytes(sig[32:], "little")
        if S >= L:
            return False
        k = _hint(sig[:32] + pk + msg)
        left = _mul(B, S)
        right = _add(R, _mul(A, k))
        return _encode_point(left) == _encode_point(right)
    except Exception:
        return False


def gen_keypair(seed: bytes = None):
    """生成 (sk, pk)；seed 给定时按 RFC 8032 直接当私钥"""
    import os
    sk = seed if seed is not None else os.urandom(32)
    return sk, public_key(sk)


# ---------- 自测：RFC 8032 §7.1 测试向量 ----------
_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


def _selftest() -> bool:
    ok = True
    for sk_hex, pk_hex, msg_hex, sig_hex in _VECTORS:
        sk = bytes.fromhex(sk_hex)
        pk = bytes.fromhex(pk_hex)
        msg = bytes.fromhex(msg_hex)
        want = bytes.fromhex(sig_hex)
        got = sign(sk, msg)
        v_ok = verify(pk, msg, got)
        print("sk=%s… 公钥 %s  签名 %s  验签 %s"
              % (sk_hex[:8], "OK" if public_key(sk) == pk else "FAIL",
                 "OK" if got == want else "FAIL", "OK" if v_ok else "FAIL"))
        ok = ok and public_key(sk) == pk and got == want and v_ok
    # 篡改必须失败
    sk = bytes.fromhex(_VECTORS[0][0])
    pk = public_key(sk)
    sig = sign(sk, b"hello")
    print("正常消息验签:", verify(pk, b"hello", sig))
    print("改 1 字节消息:", verify(pk, b"hellp", sig))
    bad = bytearray(sig)
    bad[0] ^= 1
    print("改签名 1 字节:", verify(pk, b"hello", bytes(bad)))
    print("换公钥:", verify(public_key(bytes(32)), b"hello", sig))
    return ok


if __name__ == "__main__":
    print("=== RFC 8032 官方向量 ===")
    allok = _selftest()
    print("\n自测结果:", "全部通过" if allok else "有失败")
