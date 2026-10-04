"""
vprs/_secp256k1.py
==================================================================
纯标准库实现的 secp256k1 签名/验签子集（用于可携带声誉的签发方签名）。

来源：Vouched 项目 evm_crypto.py 中已被审计库（pycryptodome + python-ecdsa）
逐字节比对验证过的原语（见 Vouched 的 test_evm_crypto_oracle.py）。
本文件是那份已验证代码的精炼副本，仅保留声誉签名所需的最小集合，不引入任何
第三方依赖。

为什么不用 HMAC / 共享密钥：可携带声誉要"第三方无需信任签发方即可验真"，
所以必须用非对称签名——签发方持私钥签名，任何人用其公开公钥验签，无需密钥。

⚠️ 任何改动都必须先过本仓库 tests/test_vprs.py 的签名/验签向量，否则禁止用于真钱。
（声誉签名本身不转移资金，但它是信任锚，正确性同样不能含糊。）
"""

import hashlib
import hmac

# ---------------------------------------------------------------------------
# secp256k1 曲线参数
# ---------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
A_CURVE = 0
B_CURVE = 7


def inv(a, m):
    """模逆（扩展欧几里得）。"""
    a %= m
    if a == 0:
        raise ZeroDivisionError("modular inverse of zero")
    old_r, r = a, m
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError("no inverse exists")
    return old_s % m


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if x1 == x2 and y1 == y2:
        m = (3 * x1 * x1 + A_CURVE) * inv(2 * y1, P) % P
    else:
        m = (y2 - y1) * inv((x2 - x1) % P, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    if k % N == 0 or point is None:
        return None
    k = k % N
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def priv_to_pub(priv_int):
    """私钥（int）→ 非压缩公钥坐标 (x, y)。priv=1 必须得到生成元 G（已知向量）。"""
    if not (1 <= priv_int < N):
        raise ValueError("private key out of range")
    return scalar_mult(priv_int, G)


def pub_to_address(pub_point):
    """(x,y) → 0x 校验和前 40 hex 的小写以太坊式地址（仅作签发方身份展示用）。"""
    x, y = pub_point
    pub_bytes = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    h = hashlib.sha256(pub_bytes[1:]).digest()  # 与 evm_crypto 保持一致：去掉 0x04 后 sha256
    return "0x" + h[-20:].hex()


def sha256(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hashlib.sha256(b).digest()


def _rfc6979_k(priv_int, digest, extra=b""):
    """RFC6979 确定性 nonce（可复现、无随机数源隐患）。"""
    v = b"\x01" * 32
    k = b"\x00" * 32
    priv_b = priv_int.to_bytes(32, "big")
    k = hmac.new(k, v + b"\x00" + priv_b + digest + extra, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + priv_b + digest + extra, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 1 <= t < N:
            return t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(priv_int, digest):
    """ECDSA 签名（digest 为 32 字节哈希）。返回 (r, s, v)，s 已低 s 规范化。"""
    if isinstance(digest, bytes):
        z = int.from_bytes(digest, "big")
    else:
        z = digest % N
    while True:
        k = _rfc6979_k(priv_int, digest)
        R = scalar_mult(k, G)
        r = R[0] % N
        if r == 0:
            continue
        s = (inv(k, N) * (z + r * priv_int)) % N
        if s == 0:
            continue
        y_parity = R[1] & 1
        if s > N // 2:
            s = N - s
            y_parity = 1 - y_parity
        v = 27 + y_parity
        return (r, s, v)


def verify_digest(pub_point, digest, r, s):
    """ECDSA 验签。pub_point=(x,y)；digest 为 32 字节哈希。返回布尔。"""
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(digest, "big") if isinstance(digest, bytes) else digest % N
    w = inv(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    X = point_add(scalar_mult(u1, G), scalar_mult(u2, pub_point))
    if X is None:
        return False
    return (X[0] % N) == r
