"""
vprs/crypto.py
==================================================================
签发方签名 / 验签的算法分发层。

VPRS 支持两种 alg（详见 SPEC.md）：
  - "secp256k1"：纯标准库实现（见 _secp256k1.py），零依赖，且与链上出金同源，
    便于把"声誉"和"支付"锚定到同一套密钥/链上身份。本仓库参考实现默认用它。
  - "ed25519"：更轻量（32 字节密钥/签名），由 cryptography 库提供（可选依赖，
    仅当 alg=ed25519 时才需要 import）。

两种算法都只签名 signed_digest（32 字节 sha256），验签方用签发方发布的公钥即可，
无需任何签发方密钥。
"""

from . import _secp256k1 as k1


def _int_to_bytes32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _strip0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


# ---------------------------------------------------------------------------
# secp256k1
# ---------------------------------------------------------------------------
def sign_secp256k1(priv_hex, digest: bytes) -> str:
    priv = int(priv_hex, 16) if isinstance(priv_hex, str) else int(priv_hex)
    r, s, _v = k1.sign_digest(priv, digest)
    return "0x" + _int_to_bytes32(r).hex() + _int_to_bytes32(s).hex()


def verify_secp256k1(pub_hex: str, digest: bytes, sig_hex: str) -> bool:
    pub = _strip0x(pub_hex)
    # 接受非压缩公钥 0x04+x(32)+y(32) 或裸 128 hex
    if pub.startswith("04") and len(pub) == 130:
        pub = pub[2:]
    if len(pub) != 128:
        return False
    x = int(pub[:64], 16)
    y = int(pub[64:], 16)
    sig = _strip0x(sig_hex)
    if len(sig) != 128:
        return False
    r = int(sig[:64], 16)
    s = int(sig[64:], 16)
    return k1.verify_digest((x, y), digest, r, s)


# ---------------------------------------------------------------------------
# ed25519（可选；需要 cryptography）
# ---------------------------------------------------------------------------
def sign_ed25519(priv_hex, digest: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_strip0x(priv_hex)))
    return "0x" + key.sign(digest).hex()


def verify_ed25519(pub_hex: str, digest: bytes, sig_hex: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(_strip0x(pub_hex)))
    try:
        key.verify(bytes.fromhex(_strip0x(sig_hex)), digest)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 分发
# ---------------------------------------------------------------------------
def sign(alg: str, priv_hex, digest: bytes) -> str:
    if alg == "secp256k1":
        return sign_secp256k1(priv_hex, digest)
    if alg == "ed25519":
        return sign_ed25519(priv_hex, digest)
    raise ValueError(f"unsupported alg: {alg}")


def verify(alg: str, pub_hex: str, digest: bytes, sig_hex: str) -> bool:
    if alg == "secp256k1":
        return verify_secp256k1(pub_hex, digest, sig_hex)
    if alg == "ed25519":
        return verify_ed25519(pub_hex, digest, sig_hex)
    raise ValueError(f"unsupported alg: {alg}")
