"""
vprs/commitment.py
==================================================================
VPRS 的"承诺"层：把一笔结算绑定成不可篡改的回执（proof_hash），再把一批回执
聚合成根（root_hash），并定义签发方签名所覆盖的规范化摘要（signed_digest）。

设计原则（为什么这样设计，详见 SPEC.md）：
  - proof_hash 是"纯承诺"：只用 sha256 对结算事实做规范化哈希，**不含任何密钥**。
    任何人（含第三方）都能从结算字段重算 proof_hash 来检测篡改——这是可携带声誉
    的 tamper-evidence 来源。真正的所有权/签发权威来自签发方的非对称签名，而不是
    共享秘密。
  - root_hash 是全部 proof_hash 的聚合，用于一次性校验"结算集合是否被改动"。
  - signed_digest 是签发方签名所覆盖的字节：根 + 身份 + 时间 + key_id。
"""

import hashlib


def _fmt_amount(v):
    return f"{float(v):.2f}"


def _fmt_rating(v):
    return f"{float(v):.2f}"


def _fmt_ts(v):
    return f"{int(float(v))}"


def canonical_settlement(s: dict) -> str:
    """结算事实的规范化字符串（用于 proof_hash）。

    字段顺序固定，且数值按固定小数位格式化，避免 80.0 / 80.00 之类浮点表示差异
    导致哈希失配。任何对结算事实的改动都会改变此字符串 → 改变 proof_hash。
    """
    return "|".join([
        str(s.get("origin_agent_id", s.get("agent_id", ""))),
        str(s.get("task_id", "")),
        str(s.get("issuer_id", "")),
        _fmt_amount(s.get("amount_usd", 0)),
        str(s.get("category", "")),
        str(s.get("outcome", "")),
        _fmt_rating(s.get("rating", 0)),
        _fmt_ts(s.get("ts", 0)),
    ])


def proof_hash(s: dict) -> str:
    """一笔结算的承诺回执。返回 "0x" + sha256(规范化字符串) 前 40 hex。"""
    h = hashlib.sha256(canonical_settlement(s).encode("utf-8")).hexdigest()
    return "0x" + h[:40]


def root_hash(settlements: list) -> str:
    """一批结算 proof_hash 的聚合根。返回 "0x" + sha256(拼接) 前 48 hex。

    顺序由调用方保证（建议按 ts 升序），本函数只负责聚合。
    """
    joined = "".join(str(s.get("proof_hash", "")) for s in settlements)
    h = hashlib.sha256(joined.encode("utf-8")).hexdigest()
    return "0x" + h[:48]


def canonical_signed_string(cred: dict) -> str:
    """签发方签名覆盖的规范化字符串。"""
    return "|".join([
        str(cred.get("root_hash", "")),
        str(cred.get("agent_id", "")),
        str(cred.get("issuer_id", "")),
        _fmt_ts(cred.get("issued_at", 0)),
        str(cred.get("key_id", "")),
    ])


def signed_digest(cred: dict) -> bytes:
    """签发方签名所签的 32 字节摘要 = sha256(canonical_signed_string)。"""
    return hashlib.sha256(canonical_signed_string(cred).encode("utf-8")).digest()
