"""
vprs/credential.py
==================================================================
VPRS 凭证的构建、验证、导入。

凭证 = 一个 Agent 在某签发方（issuer）的全部结算（Settlement）的签名聚合包。
第三方拿到的不是"数据库里的评分"，而是一份可独立验真的密码学回执：
  1) 每条结算带 proof_hash（自身 tamper-evident）
  2) 全部 proof_hash 聚合成 root_hash
  3) 签发方用私钥对 (root_hash + 身份 + 时间 + key_id) 签名 → issuer_sig
验证方只需签发方公布的公钥，即可在不信任签发方数据库的前提下采信声誉。
"""

import time

from . import commitment as C
from . import crypto as K

SCHEMA = "vprs/v1"


def build_credential(agent_id: str, issuer_id: str, settlements: list,
                     summary: dict, priv_hex, alg: str = "secp256k1",
                     key_id: str = None) -> dict:
    """签发一份 VPRS 凭证。

    settlements: 原始结算列表（每条为 dict，含 task_id/amount_usd/category/outcome/
                 rating/ts/issuer_id/origin_agent_id 等；无需预先带 proof_hash）。
    summary: 由签发方计算的声誉画像（settled_count/failed_count/total_earned_usd/
             avg_rating/success_rate/reputation/score/tier/tier_label/portable）。
    priv_hex: 签发方私钥（secp256k1 或 ed25519，取决于 alg）。
    """
    items = []
    for s in sorted(settlements, key=lambda x: int(float(x.get("ts", 0)))):
        ss = dict(s)
        ss["proof_hash"] = C.proof_hash(ss)
        items.append(ss)

    root = C.root_hash(items)
    cred = {
        "schema": SCHEMA,
        "agent_id": agent_id,
        "issuer_id": issuer_id,
        "issued_at": int(time.time()),
        "key_id": key_id or (issuer_id + "-default"),
        "alg": alg,
        "settlements": items,
        "summary": summary,
        "root_hash": root,
    }
    digest = C.signed_digest(cred)
    cred["issuer_sig"] = K.sign(alg, priv_hex, digest)
    return cred


def verify_credential(cred: dict, pub_hex: str) -> dict:
    """第三方验证凭证。无需签发方密钥，只需签发方公布的公钥 pub_hex。

    返回 {valid, issues}。valid=True 表示：每条结算自洽 + 集合未被改 + 签发方签名有效。
    """
    issues = []
    items = cred.get("settlements", [])

    for it in items:
        exp = C.proof_hash(it)
        if exp != it.get("proof_hash"):
            issues.append(f"settlement {it.get('id')} proof_hash mismatch (tampered)")

    root = C.root_hash(items)
    if root != cred.get("root_hash"):
        issues.append("root_hash mismatch (settlement set altered)")

    digest = C.signed_digest(cred)
    try:
        ok = K.verify(cred.get("alg", "secp256k1"), pub_hex, digest, cred.get("issuer_sig", ""))
    except Exception as e:
        ok = False
        issues.append(f"signature verification error: {e}")
    if not ok:
        issues.append("issuer_sig invalid (not signed by issuer or tampered)")

    return {"valid": len(issues) == 0, "issues": issues}


def import_decisions(cred: dict, existing: set) -> dict:
    """计算把凭证导入某 Agent 时的去重结果（不修改任何外部状态）。

    existing: 已存在的 {(issuer_id, proof_hash)} 集合。
    返回 {imported, skipped, added_keys}。按 (issuer_id, proof_hash) 去重，避免同一笔
    结算被重复计入；origin_agent_id 被保留，使结算仍归属原发平台身份。
    """
    imported = 0
    skipped = 0
    added = []
    for it in cred.get("settlements", []):
        key = (cred.get("issuer_id", ""), it.get("proof_hash"))
        if key in existing:
            skipped += 1
            continue
        existing.add(key)
        added.append(key)
        imported += 1
    return {"imported": imported, "skipped": skipped, "added_keys": added}
