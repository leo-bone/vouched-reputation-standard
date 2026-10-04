"""
VPRS — Vouched Portable Reputation Standard（可携带声誉开放标准）参考实现。

零三方依赖（默认 secp256k1 路径）；ed25519 路径可选需要 cryptography。

核心能力：
  - build_credential / verify_credential：签发与第三方验真
  - commitment.proof_hash / root_hash：不可篡改回执与聚合根
  - crypto.sign / verify：算法分发（secp256k1 / ed25519）

详见 SPEC.md 与 README.md。
"""

from .commitment import proof_hash, root_hash, signed_digest, canonical_settlement
from .crypto import sign, verify, sign_secp256k1, verify_secp256k1
from .credential import (
    build_credential,
    verify_credential,
    import_decisions,
    SCHEMA,
)

__all__ = [
    "proof_hash",
    "root_hash",
    "signed_digest",
    "canonical_settlement",
    "sign",
    "verify",
    "sign_secp256k1",
    "verify_secp256k1",
    "build_credential",
    "verify_credential",
    "import_decisions",
    "SCHEMA",
]
